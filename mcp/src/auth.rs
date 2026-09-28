//! Reusable axum middleware that verifies inbound bearer / DPoP-bound
//! access tokens against an [`AuthplaneResource`].
//!
//! Builds a per-request DPoP context (RFC 9449 §4.3) and runs it
//! through `verify_with_context`, then stashes the resulting
//! [`VerifiedClaims`] on the request so downstream handlers don't
//! re-verify.
//!
//! `htu` reconstruction uses the **configured resource origin** rather
//! than the request's `Host`/scheme. A misconfigured reverse proxy can
//! forge `Host`; the resource owner knows their own canonical origin and
//! must supply it via [`AuthplaneMcpAuth::new`].

use std::sync::Arc;

use authplane_sdk::{
    AuthplaneResource, DpopRequestContext, VerifierError, http_status,
    www_authenticate_for_missing_credentials,
};
use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use url::Url;

use crate::RawAccessToken;

/// State handle bundling the verifier and the canonical resource origin
/// used to reconstruct `htu` for DPoP-bound requests.
///
/// Cheap to clone: the verifier is held behind `Arc`, and [`Url`] is a
/// small owned wrapper. Pass it to
/// [`axum::middleware::from_fn_with_state`] alongside
/// [`authplane_mcp_auth_middleware`].
#[derive(Clone)]
#[non_exhaustive]
pub struct AuthplaneMcpAuth {
    verifier: Arc<AuthplaneResource>,
    resource_origin: Url,
    realm: String,
}

impl AuthplaneMcpAuth {
    /// Build with the standard configuration.
    ///
    /// `resource_origin` must be the canonical origin the resource
    /// advertises in its Protected Resource Metadata (RFC 9728) — DPoP
    /// proofs are validated against this origin rather than the
    /// request's `Host` header to avoid trust in upstream proxies.
    pub fn new(verifier: Arc<AuthplaneResource>, resource_origin: Url) -> Self {
        Self {
            verifier,
            resource_origin,
            realm: String::new(),
        }
    }

    /// Set the `realm` parameter emitted in the `WWW-Authenticate`
    /// challenge on auth failures.
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = realm.into();
        self
    }

    pub fn verifier(&self) -> &Arc<AuthplaneResource> {
        &self.verifier
    }

    pub fn resource_origin(&self) -> &Url {
        &self.resource_origin
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }
}

/// Build a [`DpopRequestContext`] from an axum request.
///
/// * `method` — the HTTP method (uppercased).
/// * `url` — the request URI re-anchored on `resource_origin` and stripped
///   of query + fragment, matching RFC 9449 §4.3 #5 `htu`.
/// * `proof` — the single `DPoP` header value, or `None` if absent.
///   Multiple headers are rejected upfront per RFC 9449 §4.3 #1 by
///   `DpopRequestContext::from_header_values` (this helper is axum
///   header extraction plus that call); the resulting `WWW-Authenticate`
///   challenge uses the `DPoP` scheme with `error="invalid_dpop_proof"`
///   per RFC 9449 §7.1.
/// * `nonce` — the `DPoP-Nonce` header value when present.
pub fn dpop_request_context_from_axum<B>(
    req: &axum::http::Request<B>,
    resource_origin: &Url,
) -> Result<DpopRequestContext, VerifierError> {
    let method = req.method().as_str().to_ascii_uppercase();

    let mut htu = resource_origin.clone();
    htu.set_path(req.uri().path());
    htu.set_query(None);
    htu.set_fragment(None);

    // Header extraction only — the RFC 9449 §4.3 #1 cardinality check
    // (exactly one `DPoP` header; zero is the Mode 2 bearer-only path)
    // lives in `DpopRequestContext::from_header_values`, so every
    // integration shares it. A non-ASCII header value cannot be a DPoP
    // proof (a base64url-encoded JWT) and rejects upfront.
    let mut proofs = Vec::new();
    for value in req.headers().get_all("dpop") {
        proofs.push(
            value
                .to_str()
                .map_err(|_| VerifierError::DpopBindingMismatch {
                    message: "DPoP header value is not valid ASCII".to_string(),
                })?,
        );
    }

    let nonce = req
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok());

    DpopRequestContext::from_header_values(&method, htu.as_str(), proofs, nonce)
}

/// axum middleware that verifies the inbound token.
///
/// Wire it with:
///
/// ```ignore
/// use axum::{Router, middleware, routing::post};
/// use authplane_mcp::{AuthplaneMcpAuth, authplane_mcp_auth_middleware};
///
/// let auth = AuthplaneMcpAuth::new(verifier, "https://mcp.example.com".parse()?)
///     .with_realm("authplane-rmcp-demo");
///
/// let app = Router::new()
///     .route("/mcp", post(handler))
///     .layer(middleware::from_fn_with_state(
///         auth,
///         authplane_mcp_auth_middleware,
///     ));
/// ```
///
/// On success: [`VerifiedClaims`], [`RawAccessToken`], and the
/// [`AuthplaneMcpAuth`] handle are inserted into request extensions.
///
/// On failure: a `401`/`403`/`503` response is returned with the
/// `WWW-Authenticate` challenge string emitted by
/// [`AuthplaneResource::www_authenticate`]. The scheme follows RFC 9449
/// §7.1 (Bearer for plain failures, DPoP for proof-validation
/// failures); the `error=` parameter follows core's mapping. Every
/// challenge carries the RFC 9728 §5.1 `resource_metadata` parameter
/// (the verifier's [`AuthplaneResource::resource_metadata_url`]) so an
/// MCP client can discover the authorization server from the `401`
/// alone; a request with no credentials gets `realm` and
/// `resource_metadata` only (RFC 6750 §3.1).
pub async fn authplane_mcp_auth_middleware(
    State(auth): State<AuthplaneMcpAuth>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = match extract_access_token(req.headers()) {
        Ok(token) => token,
        Err(message) => return missing_bearer_response(&auth, message),
    };

    let context = match dpop_request_context_from_axum(&req, &auth.resource_origin) {
        Ok(ctx) => ctx,
        Err(error) => return verifier_error_response(&auth, &error),
    };

    match auth.verifier.verify_with_context(&token, &context).await {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            req.extensions_mut().insert(RawAccessToken(token));
            req.extensions_mut().insert(auth.clone());
            next.run(req).await
        }
        Err(error) => verifier_error_response(&auth, &error),
    }
}

fn extract_access_token(headers: &axum::http::HeaderMap) -> Result<String, &'static str> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .ok_or("missing Authorization header")?;
    let text = raw.to_str().map_err(|_| "invalid Authorization header")?;
    // RFC 9449 §7 — clients MAY present a DPoP-bound access token under
    // either the `Bearer` or `DPoP` scheme. Both are accepted; the proof
    // check itself enforces sender-binding.
    let stripped = text
        .strip_prefix("Bearer ")
        .or_else(|| text.strip_prefix("DPoP "))
        .ok_or("expected Bearer or DPoP scheme")?
        .trim();
    if stripped.is_empty() {
        return Err("empty access token");
    }
    Ok(stripped.to_string())
}

fn missing_bearer_response(auth: &AuthplaneMcpAuth, message: &'static str) -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, message).into_response();
    let challenge = www_authenticate_for_missing_credentials(
        &auth.realm,
        auth.verifier.resource_metadata_url(),
    );
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn verifier_error_response(auth: &AuthplaneMcpAuth, error: &VerifierError) -> Response {
    let status =
        StatusCode::from_u16(http_status(error)).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let challenge = auth.verifier.www_authenticate(error, &auth.realm);
    let mut response = (status, error.to_string()).into_response();
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use authplane_sdk::{AuthorizationServerMetadata, FetchSettings, ResourceOptions};
    use axum::http::Request;
    use jsonwebtoken::jwk::JwkSet;

    const PRM_URL: &str = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";

    fn auth_state() -> AuthplaneMcpAuth {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            token_endpoint: None,
            introspection_endpoint: None,
            revocation_endpoint: None,
        };
        let verifier = AuthplaneResource::from_prefetched_metadata(
            "https://auth.example.com",
            "https://mcp.example.com/mcp",
            &["tools/read".to_string()],
            metadata,
            FetchSettings::from_dev_mode(true),
            ResourceOptions::default(),
            JwkSet { keys: Vec::new() },
        )
        .expect("prefetched resource");
        AuthplaneMcpAuth::new(Arc::new(verifier), origin()).with_realm("api")
    }

    fn www_authenticate_of(response: &Response) -> &str {
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("WWW-Authenticate header")
            .to_str()
            .expect("ascii header")
    }

    /// RFC 6750 §3.1 + RFC 9728 §5.1 — a request with no credentials gets
    /// no error code, but does get told where the resource metadata is.
    #[test]
    fn missing_credentials_challenge_carries_resource_metadata_without_error_code() {
        let response = missing_bearer_response(&auth_state(), "missing Authorization header");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            www_authenticate_of(&response),
            format!("Bearer realm=\"api\", resource_metadata=\"{PRM_URL}\"")
        );
    }

    #[test]
    fn verifier_failure_challenge_carries_resource_metadata_after_the_error() {
        let response = verifier_error_response(&auth_state(), &VerifierError::TokenExpired);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            www_authenticate_of(&response),
            format!(
                "Bearer realm=\"api\", error=\"invalid_token\", \
                 error_description=\"token has expired\", resource_metadata=\"{PRM_URL}\""
            )
        );
    }

    #[test]
    fn dpop_failure_challenge_keeps_the_dpop_scheme_and_resource_metadata() {
        let response = verifier_error_response(&auth_state(), &VerifierError::DpopMultipleProofs);
        let header = www_authenticate_of(&response);
        assert!(header.starts_with("DPoP realm=\"api\", error=\"invalid_dpop_proof\""));
        assert!(header.ends_with(&format!("resource_metadata=\"{PRM_URL}\"")));
    }

    fn req(method: &str, path: &str) -> Request<()> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(())
            .expect("request")
    }

    fn origin() -> Url {
        Url::parse("https://mcp.example.com").expect("origin")
    }

    #[test]
    fn htu_anchors_on_resource_origin_not_host_header() {
        let mut request = req("post", "/tools/call?session=abc#frag");
        request
            .headers_mut()
            .insert("host", HeaderValue::from_static("attacker.example.net"));
        let ctx = dpop_request_context_from_axum(&request, &origin()).expect("context");
        assert_eq!(ctx.method(), "POST");
        assert_eq!(ctx.url(), "https://mcp.example.com/tools/call");
        assert!(ctx.proof().is_none());
        assert!(ctx.nonce().is_none());
    }

    #[test]
    fn dpop_proof_passed_through_when_single_header_present() {
        let mut request = req("POST", "/tools/call");
        request
            .headers_mut()
            .insert("dpop", HeaderValue::from_static("eyJhbGciOi..."));
        let ctx = dpop_request_context_from_axum(&request, &origin()).expect("context");
        assert_eq!(ctx.proof(), Some("eyJhbGciOi..."));
    }

    #[test]
    fn multiple_dpop_headers_rejected_with_multiple_proofs() {
        let mut request = req("POST", "/tools/call");
        request
            .headers_mut()
            .append("dpop", HeaderValue::from_static("first"));
        request
            .headers_mut()
            .append("dpop", HeaderValue::from_static("second"));
        let err =
            dpop_request_context_from_axum(&request, &origin()).expect_err("two headers rejected");
        assert!(
            matches!(err, VerifierError::DpopMultipleProofs),
            "expected DpopMultipleProofs, got {err:?}"
        );
        let message = err.to_string();
        assert!(message.contains("multiple DPoP headers"));
        assert!(message.contains("RFC 9449"));
        assert!(message.is_ascii(), "challenge text must stay ASCII");
    }

    #[test]
    fn dpop_nonce_header_propagated() {
        let mut request = req("POST", "/tools/call");
        request
            .headers_mut()
            .insert("dpop-nonce", HeaderValue::from_static("nonce-123"));
        let ctx = dpop_request_context_from_axum(&request, &origin()).expect("context");
        assert_eq!(ctx.nonce(), Some("nonce-123"));
    }
}
