//! Reusable `TokenVerifier` for `fastmcp-rust` 0.3.x.
//!
//! `fastmcp-rust` 0.3 ships its own TCP accept loop (not axum) and
//! parses JSON-RPC requests by reading only the HTTP **body** —
//! [`HttpRequest::headers`] is discarded before reaching the
//! [`TokenVerifier::verify`] hook, which only sees JSON-RPC method /
//! params / request_id. There is no upstream extension point for
//! per-request HTTP context.
//!
//! Consequence: the rust fastmcp adapter currently supports **bearer-only**
//! inbound verification (RFC 6750 §2.1). DPoP-bound tokens
//! (RFC 9449 §6) cannot be verified end-to-end because the proof header
//! and the `htu`-relevant request URL never make it to this layer.
//!
//! A DPoP-bound token is therefore **rejected here, not downgraded**. That
//! distinction is the security-relevant half of the limitation and is worth
//! stating outright: `cnf` on an access token means the authorization server
//! issued it sender-constrained, and that binding is the whole reason a
//! stolen token is useless to a thief. Verifying it as a bearer token would
//! discard the constraint silently — the token would work for whoever holds
//! the bytes, which is precisely what DPoP exists to prevent. So
//! [`AuthplaneResource::verify`] refuses it: `DpopNotSupported` when the
//! resource has not opted into inbound DPoP, `DpopBindingMismatch` when it
//! has. An operator who configures a DPoP-bound flow against this adapter
//! gets a JSON-RPC `ResourceForbidden` (-32002) — the closest code this
//! framework exposes, see [`verifier_error_to_mcp_error`] — rather than a
//! request that quietly succeeds without the guarantee they configured.
//!
//! This limitation persists until the upstream framework exposes
//! inbound HTTP context. For DPoP-aware MCP servers in Rust today,
//! use the `authplane-mcp` adapter (rmcp / axum native) — it ships
//! the full
//! [`verify_with_context`](authplane_sdk::AuthplaneResource::verify_with_context)
//! pipeline.
//!
//! The same constraint applies on the way out: there is no
//! `WWW-Authenticate` header to put the RFC 9728 §5.1 `resource_metadata`
//! parameter in, so a rejected token carries the verifier's
//! [`resource_metadata_url`](authplane_sdk::AuthplaneResource::resource_metadata_url)
//! in the JSON-RPC error `data` (`{"resource_metadata": "<url>"}`)
//! instead. Serve the PRM document at that URL as usual.
//!
//! ## Wiring
//!
//! ```ignore
//! use std::sync::Arc;
//! use authplane_fastmcp::AuthplaneFastMcpTokenVerifier;
//! use fastmcp_rust::TokenAuthProvider;
//!
//! let verifier = client.resource(&resource, &scopes).await?;
//! let provider = TokenAuthProvider::new(
//!     AuthplaneFastMcpTokenVerifier::new(Arc::new(verifier))?,
//! );
//! ```

use std::sync::{Arc, Mutex};

use authplane_sdk::{AuthplaneResource, VerifiedClaims, VerifierError};
use fastmcp_rust::{
    AccessToken, AuthContext, AuthRequest, McpContext, McpError, McpErrorCode, McpResult,
    TokenVerifier,
};
use serde_json::json;

/// Synchronous `TokenVerifier` adapter that drives an
/// [`AuthplaneResource`] through fastmcp-rust's auth hook.
///
/// Owns a dedicated single-threaded tokio runtime so the synchronous
/// `verify` call can `block_on` the async verifier without depending on
/// — or fighting with — an ambient runtime owned by fastmcp's accept
/// loop. The runtime is created at construction time and reused for the
/// lifetime of the verifier; each `verify` call locks the runtime
/// mutex, so a single verifier instance serializes verification.
/// Construct one per server in normal usage.
pub struct AuthplaneFastMcpTokenVerifier {
    verifier: Arc<AuthplaneResource>,
    runtime: Mutex<tokio::runtime::Runtime>,
}

impl AuthplaneFastMcpTokenVerifier {
    pub fn new(verifier: Arc<AuthplaneResource>) -> McpResult<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                McpError::tool_error(format!(
                    "failed to build authplane verifier runtime: {error}"
                ))
            })?;
        Ok(Self {
            verifier,
            runtime: Mutex::new(runtime),
        })
    }
}

impl std::fmt::Debug for AuthplaneFastMcpTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthplaneFastMcpTokenVerifier")
            .finish_non_exhaustive()
    }
}

impl TokenVerifier for AuthplaneFastMcpTokenVerifier {
    fn verify(
        &self,
        _ctx: &McpContext,
        _request: AuthRequest<'_>,
        token: &AccessToken,
    ) -> McpResult<AuthContext> {
        // RFC 6750 §2.1 — only the Bearer scheme is honored on this
        // path. DPoP-scheme presentation requires the proof header and
        // request URL, which fastmcp-rust 0.3 strips before reaching
        // this hook (see module docs).
        if !token.scheme.eq_ignore_ascii_case("Bearer") {
            return Err(McpError::new(
                McpErrorCode::ResourceForbidden,
                format!(
                    "Unsupported access token scheme {scheme:?}; \
                     fastmcp-rust 0.3 adapter only honors Bearer",
                    scheme = token.scheme
                ),
            ));
        }

        let runtime = self
            .runtime
            .lock()
            .map_err(|_| McpError::tool_error("authplane verifier runtime mutex poisoned"))?;
        let token_str = token.token.clone();
        let verifier = self.verifier.clone();
        let claims = runtime
            .block_on(async move { verifier.verify(&token_str).await })
            .map_err(|error| {
                verifier_error_to_mcp_error(&error, self.verifier.resource_metadata_url())
            })?;

        Ok(claims_to_auth_context(&claims, token.clone()))
    }
}

fn claims_to_auth_context(claims: &VerifiedClaims, token: AccessToken) -> AuthContext {
    AuthContext {
        subject: Some(claims.sub.clone()),
        scopes: claims.scopes.clone(),
        token: Some(token),
        claims: Some(json!({
            "iss": claims.issuer,
            "sub": claims.sub,
            "aud": claims.audience,
            "scope": claims.scopes.join(" "),
            "jti": claims.jti,
            "exp": claims.expires_at,
            "iat": claims.issued_at,
            "nbf": claims.not_before,
        })),
    }
}

fn verifier_error_to_mcp_error(error: &VerifierError, resource_metadata_url: &str) -> McpError {
    // `McpErrorCode` (fastmcp-core 0.3) does not expose an unauthorized
    // / 401-style variant — `ResourceForbidden` (-32002) is the closest
    // available code for both authentication failures (expired / invalid
    // signature / revoked / missing token) and authorization failures
    // (insufficient scope). HTTP-level callers that need the 401-vs-403
    // distinction should consult [`VerifierError`] directly via the
    // `mcp` adapter, where the `WWW-Authenticate` challenge carries the
    // RFC 6750 / RFC 9449 scheme + error code.
    let code = match error {
        VerifierError::InsufficientScope { .. } => McpErrorCode::ResourceForbidden,
        VerifierError::MetadataUnavailable { .. } | VerifierError::JwksUnavailable { .. } => {
            McpErrorCode::InternalError
        }
        _ => McpErrorCode::ResourceForbidden,
    };
    // No HTTP headers reach this hook, so the RFC 9728 §5.1
    // `resource_metadata` discovery hint that the `mcp` adapter puts in
    // `WWW-Authenticate` rides in the JSON-RPC error `data` instead. It is
    // the same URL under the same name; a client that knows the header
    // parameter knows what to do with it. `ResourceForbidden` survives
    // fastmcp's error masking, so the hint reaches the client on every
    // rejected token.
    McpError::with_data(
        code,
        error.to_string(),
        json!({ "resource_metadata": resource_metadata_url }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRM_URL: &str = "https://api.example.com/.well-known/oauth-protected-resource/mcp";

    #[test]
    fn rejected_token_carries_resource_metadata_in_error_data() {
        let error = verifier_error_to_mcp_error(&VerifierError::TokenExpired, PRM_URL);
        assert_eq!(error.code, McpErrorCode::ResourceForbidden);
        assert_eq!(error.data, Some(json!({ "resource_metadata": PRM_URL })));
        // The hint must survive the masking fastmcp applies before an
        // error leaves the server.
        assert_eq!(error.masked(true).data, error.data);
    }

    #[test]
    fn service_side_failure_maps_to_internal_error() {
        let error = verifier_error_to_mcp_error(
            &VerifierError::JwksUnavailable {
                message: "down".to_string(),
            },
            PRM_URL,
        );
        assert_eq!(error.code, McpErrorCode::InternalError);
    }
}
