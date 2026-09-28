//! End-to-end coverage for `authplane_mcp_auth_middleware`.
//!
//! Builds a real `AuthplaneResource` against prefetched metadata + a
//! fixed RSA JWKS so the middleware exercises the full
//! `verify_with_context` path (signature → claims → mode dispatch).
//! Drives requests through the middleware via `tower::ServiceExt`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use authplane_mcp::{AuthplaneMcpAuth, RawAccessToken, authplane_mcp_auth_middleware};
use authplane_sdk::{
    AuthorizationServerMetadata, AuthplaneResource, FetchSettings, InboundDPoPOptions,
    ResourceOptions, VerifiedClaims,
};
use axum::Router;
use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, StatusCode, header};
use axum::middleware::from_fn_with_state;
use axum::response::IntoResponse;
use axum::routing::post;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use tower::ServiceExt;
use url::Url;

const TEST_PRIVATE_PEM: &str = include_str!("../../core/tests/fixtures/test-private.pem");
const TEST_RSA_N: &str = "pza1Jk6AXrea2P-TlgPStQO4PJ8H4mCz3qaW-PqscKygy31-_T-XNpYlH948O-hS3eN0bKLLKJetWx8bSWxBlMMW4DlV-vv32kO-phwPGE0BbQ2rMfZXfEKwKbcU_hTQv3_yfo6eugv3g_9bZR16MaNOWL0fWTmmcYoD7j8mODWoTgwGnHoriRE9wLgHOkXSJ-lnV4gR3Wa0HdI1Th91kve4mMC4DxxpzZ37xh5d0wyExHSb9bssowS70hts0JD-TX46MSpgVoCcZfBefyJ9JKoVgxVZ2aYGsdR8pwVRSRYUf2CYDvKyUZ8HfoWBv4JwBO0AVqT5Eb5F-X375fULQQ";
const TEST_RSA_E: &str = "AQAB";

fn resource(inbound: Option<InboundDPoPOptions>) -> Arc<AuthplaneResource> {
    let metadata = AuthorizationServerMetadata {
        issuer: "https://auth.example.com".to_string(),
        jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
        token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
        introspection_endpoint: None,
        revocation_endpoint: None,
    };
    let jwks: JwkSet = serde_json::from_value(json!({
        "keys": [{
            "kty": "RSA",
            "kid": "at-kid",
            "alg": "RS256",
            "use": "sig",
            "n": TEST_RSA_N,
            "e": TEST_RSA_E
        }]
    }))
    .expect("valid jwks");
    let mut options = ResourceOptions::default();
    if let Some(inbound) = inbound {
        options = options.with_inbound_dpop(inbound);
    }
    Arc::new(
        AuthplaneResource::from_prefetched_metadata(
            "https://auth.example.com",
            "https://mcp.example.com/mcp",
            &["tools/read".to_string()],
            metadata,
            FetchSettings::from_dev_mode(true),
            options,
            jwks,
        )
        .expect("build resource"),
    )
}

fn signed_token(extra: serde_json::Value) -> String {
    let mut claims = json!({
        "iss": "https://auth.example.com",
        "sub": "user-1",
        "client_id": "client-1",
        "aud": "https://mcp.example.com/mcp",
        "exp": unix_now() + 600,
        "iat": unix_now(),
        "jti": "token-1",
        "scope": "tools/read"
    });
    if let Some(map) = extra.as_object() {
        for (k, v) in map {
            claims[k] = v.clone();
        }
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("at-kid".to_string());
    header.typ = Some("at+jwt".to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).expect("signer"),
    )
    .expect("signed jwt")
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn protected_handler(
    Extension(claims): Extension<VerifiedClaims>,
    Extension(raw): Extension<RawAccessToken>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        format!("sub={}; token_prefix={}", claims.sub, &raw.0[..8]),
    )
}

fn router(auth: AuthplaneMcpAuth) -> Router {
    Router::new()
        .route("/mcp", post(protected_handler))
        .layer(from_fn_with_state(auth, authplane_mcp_auth_middleware))
}

fn origin() -> Url {
    Url::parse("https://mcp.example.com").expect("origin")
}

#[tokio::test]
async fn missing_authorization_header_returns_401_bearer_challenge() {
    let auth = AuthplaneMcpAuth::new(resource(None), origin()).with_realm("test");
    let app = router(auth);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("challenge present")
        .to_str()
        .expect("challenge ascii");
    assert!(
        challenge.starts_with("Bearer"),
        "expected Bearer-scheme challenge, got {challenge:?}"
    );
    // RFC 6750 §3.1: no error code when the request carried no
    // credentials. RFC 9728 §5.1: the discovery hint is always there,
    // derived from the resource identifier per §3.1.
    assert!(
        !challenge.contains("error="),
        "no error code expected on a credential-less request, got {challenge:?}"
    );
    assert!(
        challenge.contains(
            "resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/mcp\""
        ),
        "expected resource_metadata on the 401, got {challenge:?}"
    );
}

#[tokio::test]
async fn valid_bearer_token_invokes_handler_with_claims_extension() {
    let auth = AuthplaneMcpAuth::new(resource(None), origin());
    let app = router(auth);
    let token = signed_token(json!({}));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("body");
    let text = String::from_utf8(body.to_vec()).expect("utf-8");
    assert!(text.contains("sub=user-1"));
    assert!(text.contains("token_prefix="));
}

#[tokio::test]
async fn multiple_dpop_headers_rejected_with_dpop_scheme_challenge() {
    // Resource is in Mode 2 (inbound DPoP enabled). Two DPoP headers
    // arriving on the same request must be rejected per RFC 9449 §4.3 —
    // the middleware surfaces the failure on the DPoP-scheme
    // `WWW-Authenticate` challenge with `error="invalid_dpop_proof"`
    // (RFC 9449 §7.1).
    let auth = AuthplaneMcpAuth::new(resource(Some(InboundDPoPOptions::default())), origin());
    let app = router(auth);
    let token = signed_token(json!({}));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("dpop", "proof-a")
                .header("dpop", "proof-b")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("challenge present")
        .to_str()
        .expect("challenge ascii");
    assert!(
        challenge.starts_with("DPoP"),
        "expected DPoP-scheme challenge for proof-validation failure, got {challenge:?}"
    );
    assert!(
        challenge.contains("error=\"invalid_dpop_proof\""),
        "expected invalid_dpop_proof on the RFC 9449 section 4.3 multi-header rejection, got {challenge:?}"
    );
}

#[tokio::test]
async fn dpop_signal_rejected_when_resource_is_mode_3() {
    // Resource has not opted into inbound DPoP. A stray DPoP header
    // (even with a plain bearer token) must be rejected — silent
    // downgrade would drop the binding the client believed it set up.
    let auth = AuthplaneMcpAuth::new(resource(None), origin());
    let app = router(auth);
    let token = signed_token(json!({}));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("dpop", "any-proof-value-here")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // Mode-3 rejection: the client offered a DPoP signal against a
    // resource that has not opted into DPoP (`DpopNotSupported`). The
    // scheme is `Bearer` because the resource has no DPoP path the
    // client could retry against; the error code stays `invalid_token`
    // per the shared conformance catalog's `dpop_error → invalid_token`
    // mapping.
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("challenge present")
        .to_str()
        .expect("challenge ascii");
    assert!(
        challenge.starts_with("Bearer"),
        "expected Bearer-scheme challenge for Mode-3 DPoP signal, got {challenge:?}"
    );
    assert!(
        challenge.contains("error=\"invalid_token\""),
        "expected invalid_token error code on Mode-3 rejection, got {challenge:?}"
    );
}
