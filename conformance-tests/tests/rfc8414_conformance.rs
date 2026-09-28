//! RFC 8414 conformance cases.
//!
//! Each test body traces back to its catalog case. Assertions check the
//! behavior described in the case's `expected` block — nothing is
//! weakened to make a test pass. If the SDK ever diverges here, stop and
//! escalate (see `conformance-tests/README.md`).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use authplane_conformance_tests::conformance_case;
use authplane_sdk::{
    AuthError, AuthorizationServerMetadata, AuthplaneClient, AuthplaneError, FetchSettings,
    build_metadata_url,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

// Reuse the keypairs shipped with the core crate so the rotation case is
// driven by the same signing path as the rest of the suite. The retired
// key is RSA, the rotated one EC — distinct key material, not just a
// distinct `kid`, so nothing but a fetch from the new `jwks_uri` can make
// the post-rotation token verify.
const RETIRED_PRIVATE_PEM: &str = include_str!("../../core/tests/fixtures/test-private.pem");
const ROTATED_PRIVATE_PEM: &str = include_str!("../../core/tests/fixtures/test-ec-private.pem");
const RETIRED_RSA_N: &str = "pza1Jk6AXrea2P-TlgPStQO4PJ8H4mCz3qaW-PqscKygy31-_T-XNpYlH948O-hS3eN0bKLLKJetWx8bSWxBlMMW4DlV-vv32kO-phwPGE0BbQ2rMfZXfEKwKbcU_hTQv3_yfo6eugv3g_9bZR16MaNOWL0fWTmmcYoD7j8mODWoTgwGnHoriRE9wLgHOkXSJ-lnV4gR3Wa0HdI1Th91kve4mMC4DxxpzZ37xh5d0wyExHSb9bssowS70hts0JD-TX46MSpgVoCcZfBefyJ9JKoVgxVZ2aYGsdR8pwVRSRYUf2CYDvKyUZ8HfoWBv4JwBO0AVqT5Eb5F-X375fULQQ";
const RETIRED_RSA_E: &str = "AQAB";
const ROTATED_EC_X: &str = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";
const ROTATED_EC_Y: &str = "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4";
const RETIRED_KID: &str = "jwks-v1-key";
const ROTATED_KID: &str = "jwks-v2-key";

/// Metadata refresh interval for this test, shortened so ordinary
/// traffic crosses it. One second is the floor
/// `with_metadata_refresh_seconds` clamps to.
const METADATA_REFRESH_SECONDS: u64 = 1;
const POLL_INTERVAL: Duration = Duration::from_millis(100);

fn metadata_with(
    issuer: &str,
    jwks_uri: &str,
    token_endpoint: Option<&str>,
    introspection_endpoint: Option<&str>,
    revocation_endpoint: Option<&str>,
) -> AuthorizationServerMetadata {
    AuthorizationServerMetadata {
        issuer: issuer.to_string(),
        jwks_uri: jwks_uri.to_string(),
        token_endpoint: token_endpoint.map(str::to_string),
        introspection_endpoint: introspection_endpoint.map(str::to_string),
        revocation_endpoint: revocation_endpoint.map(str::to_string),
    }
}

fn expect_auth_error(err: AuthplaneError) -> AuthError {
    match err {
        AuthplaneError::Auth(auth) => auth,
        other => panic!("expected AuthplaneError::Auth, got {other:?}"),
    }
}

#[test]
fn rfc8414_metadata_issuer_must_match_configured_issuer() {
    conformance_case!("rfc8414-metadata-issuer-must-match-configured-issuer");

    let metadata = metadata_with(
        "https://evil.example.com",
        "https://auth.example.com/jwks.json",
        None,
        None,
        None,
    );
    let err = metadata
        .validate("https://auth.example.com", &FetchSettings::default())
        .expect_err("issuer mismatch must be rejected");
    let auth = expect_auth_error(err);
    assert_eq!(auth.code, "metadata_fetch_error");
    assert!(
        auth.message.contains("issuer mismatch"),
        "expected 'issuer mismatch' in error: {}",
        auth.message
    );
}

#[test]
fn rfc8414_jwks_uri_required_for_jwt_validation() {
    conformance_case!("rfc8414-jwks-uri-required-for-jwt-validation");

    // An empty jwks_uri means the SDK has no way to fetch signing keys —
    // validation must reject before a JWT verification attempt is ever
    // made. RFC 8414 §2 requires `jwks_uri` for JWT-based token issuers.
    let metadata = metadata_with("https://auth.example.com", "", None, None, None);
    let err = metadata
        .validate("https://auth.example.com", &FetchSettings::default())
        .expect_err("empty jwks_uri must be rejected");
    let auth = expect_auth_error(err);
    assert_eq!(auth.code, "metadata_fetch_error");
    assert!(
        auth.message.contains("jwks_uri"),
        "error should mention jwks_uri: {}",
        auth.message
    );
}

#[test]
fn rfc8414_metadata_must_contain_issuer() {
    conformance_case!("rfc8414-metadata-must-contain-issuer");

    let metadata = metadata_with("", "https://auth.example.com/jwks.json", None, None, None);
    let err = metadata
        .validate("https://auth.example.com", &FetchSettings::default())
        .expect_err("missing issuer must be rejected");
    let auth = expect_auth_error(err);
    assert_eq!(auth.code, "metadata_fetch_error");
    assert!(
        auth.message.contains("issuer"),
        "error should mention issuer: {}",
        auth.message
    );
}

#[test]
fn rfc8414_jwks_uri_must_be_absolute_https_url() {
    conformance_case!("rfc8414-jwks-uri-must-be-absolute-https-url");

    let metadata = metadata_with(
        "https://auth.example.com",
        "/relative-jwks",
        None,
        None,
        None,
    );
    let err = metadata
        .validate("https://auth.example.com", &FetchSettings::default())
        .expect_err("relative jwks_uri must be rejected");
    let auth = expect_auth_error(err);
    assert_eq!(auth.code, "metadata_fetch_error");
    assert!(
        auth.message.contains("jwks_uri"),
        "error should mention jwks_uri: {}",
        auth.message
    );
}

#[test]
fn rfc8414_token_endpoint_required_when_token_operation_is_used() {
    conformance_case!("rfc8414-token-endpoint-required-when-token-operation-is-used");

    let metadata = metadata_with(
        "https://auth.example.com",
        "https://auth.example.com/jwks.json",
        None,
        None,
        None,
    );
    let err = metadata
        .token_endpoint()
        .expect_err("token_endpoint must be required when missing");
    let auth = expect_auth_error(err);
    assert_eq!(auth.code, "missing_metadata_endpoint");
    assert!(
        auth.message.contains("token_endpoint"),
        "error should mention token_endpoint: {}",
        auth.message
    );
}

#[test]
fn rfc8414_token_endpoint_must_be_absolute_https_url() {
    conformance_case!("rfc8414-token-endpoint-must-be-absolute-https-url");

    let metadata = metadata_with(
        "https://auth.example.com",
        "https://auth.example.com/jwks.json",
        Some("http://auth.example.com/oauth/token"),
        None,
        None,
    );
    let err = metadata
        .validate("https://auth.example.com", &FetchSettings::default())
        .expect_err("http token_endpoint must be rejected in prod mode");
    let auth = expect_auth_error(err);
    assert_eq!(auth.code, "metadata_fetch_error");
    assert!(
        auth.message.contains("token_endpoint"),
        "error should mention token_endpoint: {}",
        auth.message
    );
}

#[test]
fn rfc8414_introspection_endpoint_required_when_introspection_is_used() {
    conformance_case!("rfc8414-introspection-endpoint-required-when-introspection-is-used");

    let metadata = metadata_with(
        "https://auth.example.com",
        "https://auth.example.com/jwks.json",
        Some("https://auth.example.com/oauth/token"),
        None,
        None,
    );
    let err = metadata
        .introspection_endpoint()
        .expect_err("introspection_endpoint must be required when missing");
    let auth = expect_auth_error(err);
    assert_eq!(auth.code, "missing_metadata_endpoint");
    assert!(
        auth.message.contains("introspection_endpoint"),
        "error should mention introspection_endpoint: {}",
        auth.message
    );
}

#[test]
fn rfc8414_introspection_endpoint_must_be_absolute_https_url() {
    conformance_case!("rfc8414-introspection-endpoint-must-be-absolute-https-url");

    let metadata = metadata_with(
        "https://auth.example.com",
        "https://auth.example.com/jwks.json",
        None,
        Some("http://auth.example.com/oauth/introspect"),
        None,
    );
    let err = metadata
        .validate("https://auth.example.com", &FetchSettings::default())
        .expect_err("http introspection_endpoint must be rejected in prod mode");
    let auth = expect_auth_error(err);
    assert_eq!(auth.code, "metadata_fetch_error");
    assert!(
        auth.message.contains("introspection_endpoint"),
        "error should mention introspection_endpoint: {}",
        auth.message
    );
}

#[test]
fn rfc8414_revocation_endpoint_required_when_revocation_is_used() {
    conformance_case!("rfc8414-revocation-endpoint-required-when-revocation-is-used");

    let metadata = metadata_with(
        "https://auth.example.com",
        "https://auth.example.com/jwks.json",
        Some("https://auth.example.com/oauth/token"),
        None,
        None,
    );
    let err = metadata
        .revocation_endpoint()
        .expect_err("revocation_endpoint must be required when missing");
    let auth = expect_auth_error(err);
    assert_eq!(auth.code, "missing_metadata_endpoint");
    assert!(
        auth.message.contains("revocation_endpoint"),
        "error should mention revocation_endpoint: {}",
        auth.message
    );
}

#[test]
fn rfc8414_revocation_endpoint_must_be_absolute_https_url() {
    conformance_case!("rfc8414-revocation-endpoint-must-be-absolute-https-url");

    let metadata = metadata_with(
        "https://auth.example.com",
        "https://auth.example.com/jwks.json",
        None,
        None,
        Some("http://auth.example.com/oauth/revoke"),
    );
    let err = metadata
        .validate("https://auth.example.com", &FetchSettings::default())
        .expect_err("http revocation_endpoint must be rejected in prod mode");
    let auth = expect_auth_error(err);
    assert_eq!(auth.code, "metadata_fetch_error");
    assert!(
        auth.message.contains("revocation_endpoint"),
        "error should mention revocation_endpoint: {}",
        auth.message
    );
}

#[test]
fn rfc8414_discovery_url_must_insert_well_known_before_issuer_path() {
    conformance_case!("rfc8414-discovery-url-must-insert-well-known-before-issuer-path");

    // RFC 8414 §3: for a path-suffixed issuer, the metadata URL must
    // inject `/.well-known/oauth-authorization-server` BEFORE the path —
    // not after. `https://auth.example.com/tenant-a` resolves to
    // `https://auth.example.com/.well-known/oauth-authorization-server/tenant-a`.
    let issuer = "https://auth.example.com/tenant-a";
    let expected = "https://auth.example.com/.well-known/oauth-authorization-server/tenant-a";
    let wrong = "https://auth.example.com/tenant-a/.well-known/oauth-authorization-server";

    let url = build_metadata_url(issuer).expect("build_metadata_url must accept https issuer");
    assert_eq!(url, expected);
    assert_ne!(url, wrong);

    // Root issuer (no path) follows the canonical form.
    let root = build_metadata_url("https://auth.example.com").expect("root issuer");
    assert_eq!(
        root,
        "https://auth.example.com/.well-known/oauth-authorization-server"
    );
}

fn retired_rsa_jwk() -> Value {
    json!({
        "kty": "RSA",
        "kid": RETIRED_KID,
        "alg": "RS256",
        "use": "sig",
        "n": RETIRED_RSA_N,
        "e": RETIRED_RSA_E
    })
}

fn rotated_ec_jwk() -> Value {
    json!({
        "kty": "EC",
        "kid": ROTATED_KID,
        "alg": "ES256",
        "use": "sig",
        "crv": "P-256",
        "x": ROTATED_EC_X,
        "y": ROTATED_EC_Y
    })
}

fn access_token_claims(issuer: &str, audience: &str, jti: &str) -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after the epoch")
        .as_secs() as i64;
    json!({
        "iss": issuer,
        "sub": "user-1",
        "client_id": "client-1",
        "aud": audience,
        "jti": jti,
        "iat": now,
        "exp": now + 300,
        "scope": "tools/read"
    })
}

fn sign(alg: Algorithm, kid: &str, pem: &str, claims: &Value) -> String {
    let header = Header {
        alg,
        kid: Some(kid.to_string()),
        typ: Some("at+jwt".to_string()),
        ..Header::new(alg)
    };
    let key = match alg {
        Algorithm::ES256 => EncodingKey::from_ec_pem(pem.as_bytes()),
        _ => EncodingKey::from_rsa_pem(pem.as_bytes()),
    }
    .expect("access-token signer");
    encode(&header, claims, &key).expect("signed access token")
}

/// Token signed by the key published at the pre-rotation `jwks_uri`.
fn signed_retired_token(issuer: &str, audience: &str) -> String {
    sign(
        Algorithm::RS256,
        RETIRED_KID,
        RETIRED_PRIVATE_PEM,
        &access_token_claims(issuer, audience, "jti-retired"),
    )
}

/// Token signed by the key published only at the post-rotation `jwks_uri`.
fn signed_rotated_token(issuer: &str, audience: &str) -> String {
    sign(
        Algorithm::ES256,
        ROTATED_KID,
        ROTATED_PRIVATE_PEM,
        &access_token_claims(issuer, audience, "jti-rotated"),
    )
}

#[tokio::test]
async fn rfc8414_jwks_uri_rotation_must_reconfigure_jwks_cache() {
    conformance_case!("rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache");

    // The catalog names one side effect — `jwks_uri` updated to the new
    // metadata value — under a stimulus this SDK has no equivalent of (an
    // `_on_metadata_changed` entry point). Driving the real client end to
    // end against a mock AS, with ordinary `verify` traffic as the only
    // stimulus, satisfies that the harder way: nothing below reaches for a
    // force-refresh argument, a test-only hook, or cache internals.
    let mut server = mockito::Server::new_async().await;
    let issuer = server.url();
    let audience = "https://api.example.com/mcp";

    let rotated = Arc::new(AtomicBool::new(false));
    let metadata_hits = Arc::new(AtomicUsize::new(0));
    let jwks_v1_hits = Arc::new(AtomicUsize::new(0));
    let jwks_v2_hits = Arc::new(AtomicUsize::new(0));

    // One metadata endpoint that starts publishing `jwks-v2.json` the
    // moment `rotated` flips — the AS-side rotation, invisible to the SDK
    // until it re-reads the document.
    let metadata_issuer = issuer.clone();
    let metadata_rotated = rotated.clone();
    let metadata_counter = metadata_hits.clone();
    let _metadata_mock = server
        .mock("GET", "/.well-known/oauth-authorization-server")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body_from_request(move |_request| {
            metadata_counter.fetch_add(1, Ordering::SeqCst);
            let jwks_uri = if metadata_rotated.load(Ordering::SeqCst) {
                format!("{metadata_issuer}/jwks-v2.json")
            } else {
                format!("{metadata_issuer}/jwks-v1.json")
            };
            json!({ "issuer": metadata_issuer, "jwks_uri": jwks_uri })
                .to_string()
                .into_bytes()
        })
        .create_async()
        .await;

    // The withdrawn document keeps serving the retired key forever, which
    // is the harsher of the two ways to retire it: a verifier that never
    // rebinds still gets a well-formed JWKS back, so the only thing that
    // can make the v2-signed token verify is the rebind itself.
    let v1_counter = jwks_v1_hits.clone();
    let _jwks_v1_mock = server
        .mock("GET", "/jwks-v1.json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body_from_request(move |_request| {
            v1_counter.fetch_add(1, Ordering::SeqCst);
            json!({ "keys": [retired_rsa_jwk()] })
                .to_string()
                .into_bytes()
        })
        .create_async()
        .await;

    let v2_counter = jwks_v2_hits.clone();
    let _jwks_v2_mock = server
        .mock("GET", "/jwks-v2.json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body_from_request(move |_request| {
            v2_counter.fetch_add(1, Ordering::SeqCst);
            json!({ "keys": [rotated_ec_jwk()] })
                .to_string()
                .into_bytes()
        })
        .create_async()
        .await;

    // `with_metadata_refresh_seconds` is the public knob that brings the
    // re-read within the test's reach. The JWKS interval stays long on
    // purpose: if the keys were simply expiring on their own TTL, the test
    // would pass without any metadata re-read at all.
    let client = AuthplaneClient::builder(&issuer)
        .with_fetch_settings(FetchSettings::from_dev_mode(true))
        .with_metadata_refresh_seconds(METADATA_REFRESH_SECONDS)
        .with_jwks_refresh_seconds(3600)
        .build()
        .await
        .expect("client discovers the pre-rotation metadata");
    let resource = client
        .resource(audience, &["tools/read".to_string()])
        .await
        .expect("resource built through the public API");

    // Pre-rotation: a token signed by the jwks-v1 key verifies.
    let retired_token = signed_retired_token(&issuer, audience);
    resource
        .verify(&retired_token)
        .await
        .expect("token signed by the jwks-v1 key must verify before rotation");
    assert_eq!(
        jwks_v1_hits.load(Ordering::SeqCst),
        1,
        "the pre-rotation verify must fetch jwks-v1.json exactly once",
    );
    assert_eq!(
        jwks_v2_hits.load(Ordering::SeqCst),
        0,
        "jwks-v2.json must not be touched before the rotation",
    );

    // The AS rotates. Nothing tells the SDK.
    rotated.store(true, Ordering::SeqCst);

    // Ordinary traffic only: repeat the same `verify` call the resource
    // server would already be making. The catalog sets no latency bound;
    // two refresh intervals is this test's own deadline, wide enough to
    // cover the gate firing and the fetch it triggers.
    let rotated_token = signed_rotated_token(&issuer, audience);
    let deadline =
        Instant::now() + Duration::from_secs(METADATA_REFRESH_SECONDS * 2) + POLL_INTERVAL;
    let mut verified = None;
    while Instant::now() < deadline {
        if let Ok(claims) = resource.verify(&rotated_token).await {
            verified = Some(claims);
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    let claims = verified.expect(
        "a token signed by the jwks-v2-only key must verify within two metadata refresh intervals",
    );
    assert_eq!(claims.kid, ROTATED_KID);

    assert!(
        metadata_hits.load(Ordering::SeqCst) >= 2,
        "metadata must be re-fetched after the refresh interval without an explicit refresh call",
    );
    assert!(
        jwks_v2_hits.load(Ordering::SeqCst) >= 1,
        "JWKS must be fetched from the rotated jwks_uri",
    );

    // Once the rebind has happened the withdrawn URI must go quiet, even
    // under continued traffic.
    let v1_hits_at_rebind = jwks_v1_hits.load(Ordering::SeqCst);
    for _ in 0..3 {
        resource
            .verify(&rotated_token)
            .await
            .expect("post-rebind traffic keeps verifying against the rotated JWKS");
    }
    assert_eq!(
        jwks_v1_hits.load(Ordering::SeqCst),
        v1_hits_at_rebind,
        "the withdrawn jwks-v1.json must not be fetched again after the rebind",
    );

    client.aclose().await;
}
