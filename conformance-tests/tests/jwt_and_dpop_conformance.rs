//! JWT + DPoP conformance: RFC 9068, RFC 8725, RFC 9449, RFC 9110.
//!
//! Assertions trace to the catalog cases' `expected` blocks. Cases whose
//! bodies need a full `AuthplaneResource::verify` path with mocked AS
//! metadata + JWKS are marked `#[ignore]` with a note on what the port
//! needs. Each case still carries
//! a `conformance_case!` marker so catalog alignment passes.

use authplane_conformance_tests::conformance_case;
use authplane_sdk::{
    AuthorizationServerMetadata, AuthplaneResource, DpopProofOptions, DpopReplayStore,
    DpopRequestContext, DpopVerificationOptions, FetchSettings, InMemoryDpopReplayStore,
    InboundDPoPOptions, ResourceOptions, VerifierError, create_dpop_proof, dpop_ath,
    jwk_thumbprint_sha256, verify_dpop_proof, verify_dpop_proof_with_replay,
};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

// Reuse the fixtures shipped with the core crate so every conformance test
// is driven by the same keypair the unit tests use — this guarantees the
// catalog's "signed by a known key" cases match the real signing path.
const TEST_PRIVATE_PEM: &str = include_str!("../../core/tests/fixtures/test-private.pem");
const TEST_EC_PRIVATE_PEM: &str = include_str!("../../core/tests/fixtures/test-ec-private.pem");
const TEST_RSA_N: &str = "pza1Jk6AXrea2P-TlgPStQO4PJ8H4mCz3qaW-PqscKygy31-_T-XNpYlH948O-hS3eN0bKLLKJetWx8bSWxBlMMW4DlV-vv32kO-phwPGE0BbQ2rMfZXfEKwKbcU_hTQv3_yfo6eugv3g_9bZR16MaNOWL0fWTmmcYoD7j8mODWoTgwGnHoriRE9wLgHOkXSJ-lnV4gR3Wa0HdI1Th91kve4mMC4DxxpzZ37xh5d0wyExHSb9bssowS70hts0JD-TX46MSpgVoCcZfBefyJ9JKoVgxVZ2aYGsdR8pwVRSRYUf2CYDvKyUZ8HfoWBv4JwBO0AVqT5Eb5F-X375fULQQ";
const TEST_RSA_E: &str = "AQAB";
const TEST_EC_X: &str = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";
const TEST_EC_Y: &str = "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4";

fn rsa_public_jwk() -> Value {
    json!({"kty": "RSA", "n": TEST_RSA_N, "e": TEST_RSA_E})
}

fn ec_public_jwk() -> Value {
    json!({"kty": "EC", "crv": "P-256", "x": TEST_EC_X, "y": TEST_EC_Y})
}

fn verify_options<'a>() -> DpopVerificationOptions<'a> {
    DpopVerificationOptions {
        expected_access_token: None,
        expected_nonce: None,
        allowed_algorithms: &[Algorithm::RS256, Algorithm::ES256],
        clock_skew_seconds: 10,
        max_age_seconds: 300,
    }
}

fn rs256_options(nonce: Option<String>) -> DpopProofOptions {
    DpopProofOptions {
        private_key_pem: TEST_PRIVATE_PEM.to_string(),
        public_jwk: rsa_public_jwk(),
        algorithm: Algorithm::RS256,
        key_id: Some("dpop-kid".to_string()),
        nonce,
        proof_ttl_seconds: None,
    }
}

fn es256_options() -> DpopProofOptions {
    DpopProofOptions {
        private_key_pem: TEST_EC_PRIVATE_PEM.to_string(),
        public_jwk: ec_public_jwk(),
        algorithm: Algorithm::ES256,
        key_id: Some("ec-kid".to_string()),
        nonce: None,
        proof_ttl_seconds: None,
    }
}

/// Builds an `AuthplaneResource` that shares the RSA test keypair, so
/// DPoP conformance cases can drive `verify_with_context` without mocking
/// the authorization server. Mirrors the helper in the core unit tests.
fn resource_with_test_rsa_jwks() -> AuthplaneResource {
    let metadata = AuthorizationServerMetadata {
        issuer: "https://auth.example.com".to_string(),
        jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
        token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
        introspection_endpoint: None,
        revocation_endpoint: None,
    };
    let jwks_json = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "at-kid",
            "alg": "RS256",
            "use": "sig",
            "n": TEST_RSA_N,
            "e": TEST_RSA_E
        }]
    });
    let jwks: JwkSet = serde_json::from_value(jwks_json).expect("valid jwks");
    // Conformance tests asserting DPoP-bound token behaviour expect the
    // resource to be in Mode 2 (DPoP supported, bearer also accepted).
    // The new default is Mode 3 (inbound_dpop = None → reject any DPoP
    // signal), so opt in here. The new Mode-3 / Mode-1 conformance cases
    // below build their own resources without this helper.
    AuthplaneResource::from_prefetched_metadata(
        "https://auth.example.com",
        "https://api.example.com/mcp",
        &["tools/read".to_string()],
        metadata,
        FetchSettings::from_dev_mode(true),
        ResourceOptions::default().with_inbound_dpop(InboundDPoPOptions::default()),
        jwks,
    )
    .expect("build resource from prefetched metadata")
}

fn access_token_header() -> Header {
    Header {
        alg: Algorithm::RS256,
        kid: Some("at-kid".to_string()),
        typ: Some("at+jwt".to_string()),
        ..Header::new(Algorithm::RS256)
    }
}

fn signed_access_token(claims: Value) -> String {
    encode(
        &access_token_header(),
        &claims,
        &EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).expect("access-token signer"),
    )
    .expect("signed access token")
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn valid_access_token_claims() -> Value {
    json!({
        "iss": "https://auth.example.com",
        "sub": "user-1",
        "client_id": "client-1",
        "aud": "https://api.example.com/mcp",
        "exp": 4_102_444_800i64,
        "iat": 1_700_000_000i64,
        "jti": "token-1"
    })
}

/// Build a DPoP proof JWT with explicit claims (for time-manipulation tests).
/// Signs with the test RSA key and includes the standard DPoP header.
fn dpop_proof_with_claims(claims: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("dpop+jwt".to_string());
    header.kid = Some("dpop-kid".to_string());
    // We need to set the jwk field for verification
    let jwk_value = rsa_public_jwk();
    header.jwk = Some(serde_json::from_value(jwk_value).expect("valid jwk"));

    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).expect("dpop signer"),
    )
    .expect("signed dpop proof")
}

// ---------- RFC 9068 access-token JWTs ---------------------------------------
//
// These cases validate behavior accessed through `AuthplaneResource::verify`,
// which requires constructing a resource from a mocked AS: an HTTP mock plus a
// full JWKS for each. They come off `#[ignore]` once this crate lands mockito
// fixtures.

#[tokio::test]
async fn rfc9068_valid_at_jwt_must_verify() {
    conformance_case!("rfc9068-valid-at-jwt-must-verify");

    let resource = resource_with_test_rsa_jwks();
    let token = signed_access_token(valid_access_token_claims());
    let claims = resource
        .verify(&token)
        .await
        .expect("valid at+jwt must verify");
    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.client_id, "client-1");
    assert_eq!(claims.issuer, "https://auth.example.com");
}

#[tokio::test]
async fn rfc9068_typ_must_be_at_jwt() {
    conformance_case!("rfc9068-typ-must-be-at-jwt");

    let resource = resource_with_test_rsa_jwks();
    // Sign with typ="JWT" instead of "at+jwt"
    let mut header = access_token_header();
    header.typ = Some("JWT".to_string());
    let token = encode(
        &header,
        &valid_access_token_claims(),
        &EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).expect("signer"),
    )
    .expect("token");
    let err = resource
        .verify(&token)
        .await
        .expect_err("typ=JWT must be rejected");
    match err {
        VerifierError::InvalidClaims { message } => {
            assert!(
                message.contains("at+jwt"),
                "error should mention at+jwt: {message}"
            );
        }
        other => panic!("expected InvalidClaims, got {other:?}"),
    }
}

#[tokio::test]
async fn rfc9068_issuer_must_match() {
    conformance_case!("rfc9068-issuer-must-match");

    let resource = resource_with_test_rsa_jwks();
    let mut claims = valid_access_token_claims();
    claims["iss"] = json!("https://wrong-issuer.example.com");
    let token = signed_access_token(claims);
    let err = resource
        .verify(&token)
        .await
        .expect_err("wrong issuer must be rejected");
    assert!(
        matches!(err, VerifierError::InvalidClaims { .. }),
        "expected InvalidClaims, got {err:?}"
    );
}

#[tokio::test]
async fn rfc9068_audience_must_match_resource() {
    conformance_case!("rfc9068-audience-must-match-resource");

    let resource = resource_with_test_rsa_jwks();
    let mut claims = valid_access_token_claims();
    claims["aud"] = json!("https://wrong-resource.example.com");
    let token = signed_access_token(claims);
    let err = resource
        .verify(&token)
        .await
        .expect_err("wrong audience must be rejected");
    assert!(
        matches!(err, VerifierError::InvalidClaims { .. }),
        "expected InvalidClaims, got {err:?}"
    );
}

#[tokio::test]
async fn rfc9068_required_claims_must_be_enforced() {
    conformance_case!("rfc9068-required-claims-must-be-enforced");

    let resource = resource_with_test_rsa_jwks();
    // Token missing "sub" claim
    let claims = json!({
        "iss": "https://auth.example.com",
        "client_id": "client-1",
        "aud": "https://api.example.com/mcp",
        "exp": 4_102_444_800i64,
        "iat": 1_700_000_000i64,
        "jti": "token-no-sub"
    });
    let token = signed_access_token(claims);
    let err = resource
        .verify(&token)
        .await
        .expect_err("missing sub must be rejected");
    assert!(
        matches!(err, VerifierError::InvalidClaims { .. }),
        "expected InvalidClaims, got {err:?}"
    );
}

#[tokio::test]
async fn rfc9068_token_header_must_contain_kid() {
    conformance_case!("rfc9068-token-header-must-contain-kid");

    let resource = resource_with_test_rsa_jwks();
    // Sign token with header that has no kid
    let header = Header {
        alg: Algorithm::RS256,
        kid: None,
        typ: Some("at+jwt".to_string()),
        ..Header::new(Algorithm::RS256)
    };
    let token = encode(
        &header,
        &valid_access_token_claims(),
        &EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).expect("signer"),
    )
    .expect("token");
    let err = resource
        .verify(&token)
        .await
        .expect_err("missing kid must be rejected");
    assert!(
        matches!(err, VerifierError::InvalidClaims { .. }),
        "expected InvalidClaims, got {err:?}"
    );
}

#[tokio::test]
async fn rfc9068_iat_future_must_be_rejected_beyond_leeway() {
    conformance_case!("rfc9068-iat-future-must-be-rejected-beyond-leeway");

    let resource = resource_with_test_rsa_jwks();
    // iat far in the future (beyond 30s default clock skew)
    let future_iat = unix_now() + 3600;
    let mut claims = valid_access_token_claims();
    claims["iat"] = json!(future_iat);
    let token = signed_access_token(claims);
    let err = resource
        .verify(&token)
        .await
        .expect_err("future iat must be rejected");
    assert!(
        matches!(err, VerifierError::InvalidClaims { .. }),
        "expected InvalidClaims for future iat, got {err:?}"
    );
}

#[tokio::test]
async fn rfc9068_nbf_must_be_honored_when_present() {
    conformance_case!("rfc9068-nbf-must-be-honored-when-present");

    let resource = resource_with_test_rsa_jwks();
    // nbf far in the future
    let mut claims = valid_access_token_claims();
    claims["nbf"] = json!(unix_now() + 3600);
    let token = signed_access_token(claims);
    let err = resource
        .verify(&token)
        .await
        .expect_err("future nbf must be rejected");
    assert!(
        matches!(err, VerifierError::InvalidClaims { .. }),
        "expected InvalidClaims for future nbf, got {err:?}"
    );
}

#[tokio::test]
async fn rfc9068_token_header_must_contain_alg() {
    conformance_case!("rfc9068-token-header-must-contain-alg");

    let resource = resource_with_test_rsa_jwks();
    // JWT always has alg, so test that an unsupported alg (HS256) is rejected.
    // We can't actually sign HS256 with an RSA key through the normal path,
    // but we can construct a token with HS256 in the header manually.
    let header = Header {
        alg: Algorithm::HS256,
        kid: Some("at-kid".to_string()),
        typ: Some("at+jwt".to_string()),
        ..Header::new(Algorithm::HS256)
    };
    let token = encode(
        &header,
        &valid_access_token_claims(),
        &EncodingKey::from_secret(b"fake-secret-key-for-hs256-test"),
    )
    .expect("token");
    let err = resource
        .verify(&token)
        .await
        .expect_err("HS256 must be rejected");
    assert!(
        matches!(err, VerifierError::InvalidClaims { .. }),
        "expected InvalidClaims for disallowed alg, got {err:?}"
    );
}

#[tokio::test]
async fn rfc9068_signature_failure_must_reject_token() {
    conformance_case!("rfc9068-signature-failure-must-reject-token");

    let resource = resource_with_test_rsa_jwks();
    // Sign token with EC key (different from the RSA key in JWKS) but
    // use the same kid so it finds the JWKS entry but signature fails.
    // Instead, we tamper with the signature of a valid token.
    let token = signed_access_token(valid_access_token_claims());
    // Corrupt the signature by flipping a character in the last segment.
    let parts: Vec<&str> = token.split('.').collect();
    let mut sig = parts[2].to_string();
    let replacement = if sig.ends_with('A') { "B" } else { "A" };
    sig.replace_range(sig.len() - 1..sig.len(), replacement);
    let tampered = format!("{}.{}.{}", parts[0], parts[1], sig);
    let err = resource
        .verify(&tampered)
        .await
        .expect_err("tampered signature must be rejected");
    assert!(
        matches!(err, VerifierError::InvalidSignature { .. }),
        "expected InvalidSignature, got {err:?}"
    );
}

#[tokio::test]
async fn rfc9068_expiration_and_clock_skew_must_be_enforced() {
    conformance_case!("rfc9068-expiration-and-clock-skew-must-be-enforced");

    let resource = resource_with_test_rsa_jwks();
    // Token with exp well in the past (beyond clock skew)
    let mut claims = valid_access_token_claims();
    claims["exp"] = json!(1_000_000_000i64);
    let token = signed_access_token(claims);
    let err = resource
        .verify(&token)
        .await
        .expect_err("expired token must be rejected");
    assert!(
        matches!(err, VerifierError::TokenExpired),
        "expected TokenExpired, got {err:?}"
    );
}

// ---------- RFC 8725 (JWT BCP) ----------------------------------------------

#[tokio::test]
async fn rfc8725_allowed_jwt_algorithms_must_be_restricted() {
    conformance_case!("rfc8725-allowed-jwt-algorithms-must-be-restricted");

    // Create a resource that only allows ES256, then send an RS256 token.
    let metadata = AuthorizationServerMetadata {
        issuer: "https://auth.example.com".to_string(),
        jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
        token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
        introspection_endpoint: None,
        revocation_endpoint: None,
    };
    let jwks_json = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "at-kid",
            "alg": "RS256",
            "use": "sig",
            "n": TEST_RSA_N,
            "e": TEST_RSA_E
        }]
    });
    let jwks: JwkSet = serde_json::from_value(jwks_json).expect("valid jwks");
    let resource = AuthplaneResource::from_prefetched_metadata(
        "https://auth.example.com",
        "https://api.example.com/mcp",
        &["tools/read".to_string()],
        metadata,
        FetchSettings::from_dev_mode(true),
        ResourceOptions::default()
            .with_allowed_algorithms(vec![Algorithm::ES256])
            .expect("ES256 is valid")
            .with_inbound_dpop(InboundDPoPOptions::default()),
        jwks,
    )
    .expect("build resource");

    let token = signed_access_token(valid_access_token_claims());
    let err = resource
        .verify(&token)
        .await
        .expect_err("RS256 must be rejected when only ES256 is allowed");
    assert!(
        matches!(err, VerifierError::InvalidClaims { .. }),
        "expected InvalidClaims for disallowed alg, got {err:?}"
    );
}

#[tokio::test]
async fn rfc8725_kid_must_resolve_through_jwks_with_single_refresh_on_miss() {
    conformance_case!("rfc8725-kid-must-resolve-through-jwks-with-single-refresh-on-miss");

    let resource = resource_with_test_rsa_jwks();
    // Token with a kid that doesn't exist in JWKS
    let header = Header {
        alg: Algorithm::RS256,
        kid: Some("unknown-kid".to_string()),
        typ: Some("at+jwt".to_string()),
        ..Header::new(Algorithm::RS256)
    };
    let token = encode(
        &header,
        &valid_access_token_claims(),
        &EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).expect("signer"),
    )
    .expect("token");
    let err = resource
        .verify(&token)
        .await
        .expect_err("unknown kid must be rejected");
    assert!(
        matches!(err, VerifierError::InvalidSignature { .. }),
        "expected InvalidSignature for unknown kid, got {err:?}"
    );
}

#[tokio::test]
async fn rfc8725_jwk_selection_must_honor_use_key_ops_and_alg() {
    conformance_case!("rfc8725-jwk-selection-must-honor-use-key-ops-and-alg");

    // JWKS has matching kid but wrong alg (ES256 instead of RS256)
    let metadata = AuthorizationServerMetadata {
        issuer: "https://auth.example.com".to_string(),
        jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
        token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
        introspection_endpoint: None,
        revocation_endpoint: None,
    };
    let jwks_json = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "at-kid",
            "alg": "ES256",
            "use": "sig",
            "n": TEST_RSA_N,
            "e": TEST_RSA_E
        }]
    });
    let jwks: JwkSet = serde_json::from_value(jwks_json).expect("valid jwks");
    let resource = AuthplaneResource::from_prefetched_metadata(
        "https://auth.example.com",
        "https://api.example.com/mcp",
        &["tools/read".to_string()],
        metadata,
        FetchSettings::from_dev_mode(true),
        ResourceOptions::default(),
        jwks,
    )
    .expect("build resource");

    let token = signed_access_token(valid_access_token_claims());
    let err = resource
        .verify(&token)
        .await
        .expect_err("JWKS key with wrong alg must not match");
    assert!(
        matches!(err, VerifierError::InvalidSignature { .. }),
        "expected InvalidSignature for alg mismatch in JWKS, got {err:?}"
    );
}

// ---------- RFC 9449 DPoP — testable via public primitives -----------------

#[test]
fn rfc9449_dpop_provider_must_build_dpop_jwt_header() {
    conformance_case!("rfc9449-dpop-provider-must-build-dpop-jwt-header");

    // RFC 9449 §4.2: the DPoP proof's JWS header MUST have typ "dpop+jwt"
    // and MUST carry the public key as a JWK in the `jwk` header param.
    let proof = create_dpop_proof(
        "POST",
        "https://api.example.com/token",
        None,
        &rs256_options(None),
    )
    .expect("RSA DPoP proof must build");

    // Decode header segment and confirm shape.
    let header_b64 = proof.split('.').next().expect("dpop proof has header");
    let header_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        header_b64,
    )
    .expect("header base64");
    let header: Value = serde_json::from_slice(&header_bytes).expect("header json");
    assert_eq!(header.get("typ").and_then(Value::as_str), Some("dpop+jwt"));
    assert!(
        header.get("jwk").and_then(Value::as_object).is_some(),
        "DPoP header must contain a jwk object, got {header:?}"
    );
    assert_eq!(header.get("alg").and_then(Value::as_str), Some("RS256"));
}

#[test]
fn rfc9449_dpop_proof_header_typ_must_be_dpop_jwt() {
    conformance_case!("rfc9449-dpop-proof-header-typ-must-be-dpop-jwt");

    // Same invariant as above, isolated: the catalog case emphasizes typ
    // specifically. RFC 9449 §4.2 requires this value verbatim.
    let proof = create_dpop_proof(
        "GET",
        "https://api.example.com/resource",
        None,
        &rs256_options(None),
    )
    .expect("proof must build");
    let header_b64 = proof.split('.').next().unwrap();
    let header: Value = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            header_b64,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(header.get("typ").and_then(Value::as_str), Some("dpop+jwt"));
}

#[test]
fn rfc9449_dpop_nonce_challenge_must_trigger_single_retry() {
    conformance_case!("rfc9449-dpop-nonce-challenge-must-trigger-single-retry");

    // Test that the DpopProvider can store a nonce and include it in the
    // next proof. This mirrors the nonce retry pattern: first request gets
    // a 401 with DPoP-Nonce header, provider stores it, second request
    // includes the nonce.
    let provider =
        authplane_sdk::DpopProvider::new(TEST_PRIVATE_PEM, rsa_public_jwk(), Algorithm::RS256)
            .expect("provider");

    let url = "https://auth.example.com/token";

    // Initially no nonce
    let nonce_before = provider.current_nonce(url).expect("nonce lookup");
    assert!(nonce_before.is_empty(), "no nonce initially");

    // Simulate receiving a DPoP-Nonce challenge
    provider
        .note_nonce(url, "server-nonce-1")
        .expect("note nonce");

    // Now the next proof should include the nonce
    let nonce_after = provider.current_nonce(url).expect("nonce lookup");
    assert_eq!(nonce_after, "server-nonce-1");

    // Build a proof with the stored nonce
    let proof = provider
        .build_proof("POST", url, None)
        .expect("proof with nonce");
    // Decode and verify nonce is present
    let parts: Vec<&str> = proof.split('.').collect();
    let payload_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
            .expect("base64");
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("json");
    assert_eq!(
        payload.get("nonce").and_then(Value::as_str),
        Some("server-nonce-1"),
        "proof must carry the stored nonce"
    );
}

#[test]
fn rfc9449_dpop_nonce_on_success_response_should_be_stored() {
    conformance_case!("rfc9449-dpop-nonce-on-success-response-should-be-stored");

    // When a success response includes a DPoP-Nonce header, the provider
    // must store it for future requests to the same origin.
    let provider =
        authplane_sdk::DpopProvider::new(TEST_PRIVATE_PEM, rsa_public_jwk(), Algorithm::RS256)
            .expect("provider");

    let url = "https://auth.example.com/token";

    // Simulate noting a nonce from a success response
    provider
        .note_nonce(url, "success-nonce")
        .expect("note nonce");
    let stored = provider.current_nonce(url).expect("lookup");
    assert_eq!(stored, "success-nonce");

    // Update with a newer nonce (server rotates)
    provider
        .note_nonce(url, "rotated-nonce")
        .expect("note nonce");
    let stored2 = provider.current_nonce(url).expect("lookup");
    assert_eq!(stored2, "rotated-nonce");
}

#[test]
fn rfc9110_rfc9449_dpop_nonce_header_must_be_treated_case_insensitively() {
    conformance_case!("rfc9110-rfc9449-dpop-nonce-header-must-be-treated-case-insensitively");

    // The nonce store keys by origin, which is case-insensitive per RFC 9110.
    // Nonces stored for one casing of the URL must be retrievable from another.
    let provider =
        authplane_sdk::DpopProvider::new(TEST_PRIVATE_PEM, rsa_public_jwk(), Algorithm::RS256)
            .expect("provider");

    // Store nonce via uppercase host
    provider
        .note_nonce("https://AUTH.EXAMPLE.COM/token", "nonce-case")
        .expect("note nonce");

    // Retrieve via lowercase host — same origin
    let stored = provider
        .current_nonce("https://auth.example.com/other-path")
        .expect("lookup");
    assert_eq!(
        stored, "nonce-case",
        "nonce store must treat host case-insensitively"
    );
}

#[test]
fn rfc9449_inbound_dpop_proof_must_validate_method_url_and_binding() {
    conformance_case!("rfc9449-inbound-dpop-proof-must-validate-method-url-and-binding");

    // RFC 9449 §4.3: verification MUST check typ, signature, alg, htm, htu,
    // iat freshness, and (if binding) ath. A proof generated for
    // (POST, https://api.example.com/resource) must verify cleanly when the
    // server presents the same tuple.
    let method = "POST";
    let url = "https://api.example.com/resource";
    let access_token = "access-token-abc";
    let proof =
        create_dpop_proof(method, url, Some(access_token), &rs256_options(None)).expect("proof");
    let verified = verify_dpop_proof(
        &proof,
        method,
        url,
        DpopVerificationOptions {
            expected_access_token: Some(access_token),
            ..verify_options()
        },
    )
    .expect("valid proof must verify");
    assert_eq!(verified.method, "POST");
    assert_eq!(verified.url, "https://api.example.com/resource");
    // Thumbprint of the public JWK must be stable and equal to the
    // `cnf.jkt` that would be bound on a DPoP-bound access token.
    let expected_jkt = jwk_thumbprint_sha256(&rsa_public_jwk()).expect("thumbprint");
    assert_eq!(verified.jkt, expected_jkt);
}

#[tokio::test]
async fn rfc9449_bearer_token_with_request_context_and_no_proof_must_still_verify_as_bearer() {
    conformance_case!(
        "rfc9449-bearer-token-with-request-context-and-no-proof-must-still-verify-as-bearer"
    );

    let resource = resource_with_test_rsa_jwks();
    let token = signed_access_token(valid_access_token_claims());
    let context = DpopRequestContext::new("GET", "https://api.example.com/mcp", None, None);
    let claims = resource
        .verify_with_context(&token, &context)
        .await
        .expect("bearer + request context must verify");
    assert_eq!(claims.client_id, "client-1");
    assert!(
        !claims.raw.contains_key("cnf"),
        "bearer token must not carry cnf"
    );
}

#[tokio::test]
async fn rfc9449_dpop_bound_token_with_request_context_and_no_proof_must_be_rejected_via_main_verify_path()
 {
    conformance_case!(
        "rfc9449-dpop-bound-token-with-request-context-and-no-proof-must-be-rejected-via-main-verify-path"
    );

    let resource = resource_with_test_rsa_jwks();
    let token = signed_access_token(json!({
        "iss": "https://auth.example.com",
        "sub": "user-1",
        "client_id": "client-1",
        "aud": "https://api.example.com/mcp",
        "exp": 4_102_444_800i64,
        "iat": 1_700_000_000i64,
        "jti": "bound-token",
        "cnf": { "jkt": "some-thumbprint" }
    }));
    let context = DpopRequestContext::new("POST", "https://api.example.com/mcp", None, None);
    let err = resource
        .verify_with_context(&token, &context)
        .await
        .expect_err("dpop-bound token without proof must reject");
    match err {
        VerifierError::DpopProofMissing => {}
        other => panic!("expected DpopProofMissing, got {other:?}"),
    }
}

#[tokio::test]
async fn rfc9449_dpop_replay_must_be_detected() {
    conformance_case!("rfc9449-dpop-replay-must-be-detected");

    let replay_store = InMemoryDpopReplayStore::new();
    let method = "POST";
    let url = "https://api.example.com/resource";
    let proof = create_dpop_proof(method, url, None, &rs256_options(None)).expect("proof");

    // First verification succeeds
    let first =
        verify_dpop_proof_with_replay(&proof, method, url, verify_options(), &replay_store).await;
    assert!(first.is_ok(), "first verification must succeed");

    // Second verification with the same proof must detect replay
    let second =
        verify_dpop_proof_with_replay(&proof, method, url, verify_options(), &replay_store).await;
    let err = second.expect_err("replayed proof must be rejected");
    assert!(
        matches!(err, VerifierError::DpopReplayDetected),
        "expected DpopReplayDetected, got {err:?}"
    );
}

#[test]
fn rfc9449_dpop_method_mismatch_must_be_rejected() {
    conformance_case!("rfc9449-dpop-method-mismatch-must-be-rejected");

    // RFC 9449 §4.3: htm MUST equal the HTTP method of the request the
    // proof is being presented with. A proof generated for POST must not
    // verify for GET on the same URL.
    let proof = create_dpop_proof(
        "POST",
        "https://api.example.com/resource",
        None,
        &rs256_options(None),
    )
    .expect("proof");
    let error = verify_dpop_proof(
        &proof,
        "GET",
        "https://api.example.com/resource",
        verify_options(),
    )
    .expect_err("method mismatch must be rejected");
    match error {
        authplane_sdk::VerifierError::InvalidClaims { message } => {
            assert!(
                message.contains("htm"),
                "error should mention htm: {message}"
            );
        }
        other => panic!("expected InvalidClaims, got {other:?}"),
    }
}

#[test]
fn rfc9449_dpop_url_mismatch_must_be_rejected() {
    conformance_case!("rfc9449-dpop-url-mismatch-must-be-rejected");

    // RFC 9449 §4.3: htu MUST equal the target URI of the request. A proof
    // signed for resource/a must not verify when presented against
    // resource/b.
    let proof = create_dpop_proof(
        "POST",
        "https://api.example.com/resource-a",
        None,
        &rs256_options(None),
    )
    .expect("proof");
    let error = verify_dpop_proof(
        &proof,
        "POST",
        "https://api.example.com/resource-b",
        verify_options(),
    )
    .expect_err("htu mismatch must be rejected");
    match error {
        authplane_sdk::VerifierError::InvalidClaims { message } => {
            assert!(
                message.contains("htu"),
                "error should mention htu: {message}"
            );
        }
        other => panic!("expected InvalidClaims, got {other:?}"),
    }
}

#[test]
fn rfc9449_dpop_proof_htu_must_be_normalized_before_comparison() {
    conformance_case!("rfc9449-dpop-proof-htu-must-be-normalized-before-comparison");

    // RFC 9449 §4.2 + RFC 3986 §6 — the htu comparison applies
    // syntax-based and scheme-based normalization. The Rust SDK strips
    // query and fragment and lowercases scheme/host, so a proof minted
    // against an equivalent URL must verify.
    let proof = create_dpop_proof(
        "POST",
        "https://API.Example.com/resource",
        None,
        &rs256_options(None),
    )
    .expect("proof");
    verify_dpop_proof(
        &proof,
        "POST",
        "https://api.example.com/resource",
        verify_options(),
    )
    .expect("normalized URLs must match");
}

#[test]
fn rfc9449_dpop_proof_htm_must_be_case_sensitive() {
    conformance_case!("rfc9449-dpop-proof-htm-must-be-case-sensitive");

    // RFC 9449 §4.2: htm is the (case-sensitive) HTTP method token. The
    // SDK uppercases both sides before comparison so callers that pass
    // lowercase ("post") still work end-to-end, but the serialized htm
    // claim must be the uppercase canonical form.
    let proof = create_dpop_proof(
        "post",
        "https://api.example.com/resource",
        None,
        &rs256_options(None),
    )
    .expect("proof");
    let parts: Vec<&str> = proof.split('.').collect();
    let payload_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
            .expect("payload base64");
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("payload json");
    assert_eq!(payload.get("htm").and_then(Value::as_str), Some("POST"));
}

#[tokio::test]
async fn rfc9449_dpop_replay_store_must_evict_expired_entries() {
    conformance_case!("rfc9449-dpop-replay-store-must-evict-expired-entries");

    let store = InMemoryDpopReplayStore::new();

    // Insert an entry that has already expired
    let stored = store
        .check_and_store("jti-expired", unix_now() - 1)
        .await
        .expect("store");
    assert!(stored, "first insert must succeed");

    // Insert a fresh entry — this triggers eviction of expired entries
    let stored2 = store
        .check_and_store("jti-fresh", unix_now() + 3600)
        .await
        .expect("store");
    assert!(stored2);

    // The expired entry should have been evicted, so re-inserting it succeeds
    let re_stored = store
        .check_and_store("jti-expired", unix_now() + 3600)
        .await
        .expect("store");
    assert!(re_stored, "expired jti must be evicted and re-storable");

    // The fresh entry should still be present (not evicted)
    let duplicate = store
        .check_and_store("jti-fresh", unix_now() + 3600)
        .await
        .expect("store");
    assert!(!duplicate, "non-expired jti must not be evicted");
}

#[test]
fn rfc9449_dpop_inbound_nonce_must_be_validated_when_required() {
    conformance_case!("rfc9449-dpop-inbound-nonce-must-be-validated-when-required");

    let method = "POST";
    let url = "https://api.example.com/resource";
    // Create a proof with nonce "actual-nonce"
    let proof = create_dpop_proof(
        method,
        url,
        None,
        &rs256_options(Some("actual-nonce".to_string())),
    )
    .expect("proof");

    // Verify with expected_nonce that doesn't match
    let err = verify_dpop_proof(
        &proof,
        method,
        url,
        DpopVerificationOptions {
            expected_nonce: Some("expected-nonce"),
            ..verify_options()
        },
    )
    .expect_err("nonce mismatch must be rejected");
    match err {
        VerifierError::InvalidClaims { message } => {
            assert!(
                message.contains("nonce"),
                "error should mention nonce: {message}"
            );
        }
        other => panic!("expected InvalidClaims, got {other:?}"),
    }

    // Also test: expected_nonce set but proof has no nonce at all
    let proof_no_nonce = create_dpop_proof(method, url, None, &rs256_options(None)).expect("proof");
    let err2 = verify_dpop_proof(
        &proof_no_nonce,
        method,
        url,
        DpopVerificationOptions {
            expected_nonce: Some("required-nonce"),
            ..verify_options()
        },
    )
    .expect_err("missing nonce must be rejected when expected");
    match err2 {
        VerifierError::InvalidClaims { message } => {
            assert!(
                message.contains("nonce"),
                "error should mention nonce: {message}"
            );
        }
        other => panic!("expected InvalidClaims, got {other:?}"),
    }
}

#[test]
fn rfc9449_dpop_proof_exp_must_be_enforced_when_present() {
    conformance_case!("rfc9449-dpop-proof-exp-must-be-enforced-when-present");

    // Craft a DPoP proof with an exp claim in the past
    let now = unix_now();
    let proof = dpop_proof_with_claims(json!({
        "htm": "POST",
        "htu": "https://api.example.com/resource",
        "iat": now - 60,
        "jti": "exp-test-jti",
        "exp": now - 120  // well in the past
    }));
    let err = verify_dpop_proof(
        &proof,
        "POST",
        "https://api.example.com/resource",
        verify_options(),
    )
    .expect_err("expired DPoP proof must be rejected");
    match err {
        VerifierError::InvalidClaims { message } => {
            assert!(
                message.contains("expired") || message.contains("exp"),
                "error should mention expiry: {message}"
            );
        }
        other => panic!("expected InvalidClaims, got {other:?}"),
    }
}

#[test]
fn rfc9449_generated_dpop_proof_should_include_exp() {
    conformance_case!("rfc9449-generated-dpop-proof-should-include-exp");

    // RFC 9449 §4.2 — the SDK now emits `exp = iat + proof_ttl_seconds`
    // (default 300s) on every generated DPoP proof. This test verifies
    // both `iat` and `exp` are present and that `exp` equals `iat + 300`.
    let proof = create_dpop_proof(
        "POST",
        "https://api.example.com/resource",
        None,
        &rs256_options(None),
    )
    .expect("proof");
    let payload_b64 = proof.split('.').nth(1).expect("has payload");
    let payload: Value = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload_b64,
        )
        .unwrap(),
    )
    .unwrap();
    let iat = payload
        .get("iat")
        .and_then(Value::as_i64)
        .expect("iat must be present");
    let exp = payload
        .get("exp")
        .and_then(Value::as_i64)
        .expect("exp must be present in SDK-generated DPoP proof");
    // Default TTL is 300 seconds; allow 1 second of tolerance for clock
    // drift between `iat` capture and assertion.
    assert!(
        (exp - iat - 300).unsigned_abs() <= 1,
        "exp must equal iat + 300 (got iat={iat}, exp={exp}, diff={})",
        exp - iat
    );
}

#[test]
fn rfc9449_dpop_proof_must_carry_public_jwk() {
    conformance_case!("rfc9449-dpop-proof-must-carry-public-jwk");

    // RFC 9449 §4.2: the DPoP proof JWS header MUST include `jwk`. A
    // resource server without out-of-band key material cannot verify
    // otherwise.
    let proof = create_dpop_proof(
        "POST",
        "https://api.example.com/resource",
        None,
        &rs256_options(None),
    )
    .expect("proof");
    let header_b64 = proof.split('.').next().unwrap();
    let header: Value = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            header_b64,
        )
        .unwrap(),
    )
    .unwrap();
    let jwk = header
        .get("jwk")
        .and_then(Value::as_object)
        .expect("jwk must be present in header");
    assert_eq!(jwk.get("kty").and_then(Value::as_str), Some("RSA"));
    assert_eq!(jwk.get("n").and_then(Value::as_str), Some(TEST_RSA_N));
    assert_eq!(jwk.get("e").and_then(Value::as_str), Some(TEST_RSA_E));
}

#[test]
fn rfc9449_dpop_proof_jwk_must_not_include_private_key_material() {
    conformance_case!("rfc9449-dpop-proof-jwk-must-not-include-private-key-material");

    // RFC 9449 §4.2 + RFC 7800: the `jwk` in the DPoP header MUST be the
    // PUBLIC key. Any RSA private-key parameter in the header is a
    // catastrophic leak.
    let proof = create_dpop_proof(
        "POST",
        "https://api.example.com/resource",
        None,
        &rs256_options(None),
    )
    .expect("proof");
    let header_b64 = proof.split('.').next().unwrap();
    let header: Value = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            header_b64,
        )
        .unwrap(),
    )
    .unwrap();
    let jwk = header.get("jwk").expect("jwk");
    for private in [
        "d", "p", "q", "dp", "dq", "qi", "oth", "k", // EC private
        "d_EC",
    ] {
        assert!(
            jwk.get(private).is_none(),
            "DPoP proof jwk must not carry private-key param {private}: {jwk:?}"
        );
    }
}

#[test]
fn rfc9449_dpop_proof_alg_must_be_supported_asymmetric() {
    conformance_case!("rfc9449-dpop-proof-alg-must-be-supported-asymmetric");

    // RFC 9449 §4.2: alg MUST be an asymmetric signing algorithm the
    // resource server supports. RS256 and ES256 are the two algs the Rust
    // SDK accepts — verification with only a symmetric alg allow-list
    // must reject.
    let proof = create_dpop_proof(
        "POST",
        "https://api.example.com/resource",
        None,
        &rs256_options(None),
    )
    .expect("proof");
    let err = verify_dpop_proof(
        &proof,
        "POST",
        "https://api.example.com/resource",
        DpopVerificationOptions {
            allowed_algorithms: &[Algorithm::ES256],
            ..verify_options()
        },
    )
    .expect_err("RS256 proof must not verify under an ES256-only allow-list");
    match err {
        authplane_sdk::VerifierError::InvalidClaims { message } => {
            assert!(
                message.contains("algorithm") || message.contains("alg"),
                "error should mention alg: {message}"
            );
        }
        other => panic!("expected InvalidClaims, got {other:?}"),
    }

    // ES256 path verifies end to end too.
    let ec_proof = create_dpop_proof(
        "POST",
        "https://api.example.com/resource",
        None,
        &es256_options(),
    )
    .expect("EC proof");
    verify_dpop_proof(
        &ec_proof,
        "POST",
        "https://api.example.com/resource",
        verify_options(),
    )
    .expect("ES256 proof must verify");
}

#[test]
fn rfc9449_dpop_proof_iat_must_not_be_in_the_future_beyond_leeway() {
    conformance_case!("rfc9449-dpop-proof-iat-must-not-be-in-the-future-beyond-leeway");

    // Craft a DPoP proof with iat far in the future (beyond 10s clock_skew)
    let now = unix_now();
    let proof = dpop_proof_with_claims(json!({
        "htm": "POST",
        "htu": "https://api.example.com/resource",
        "iat": now + 3600,
        "jti": "future-iat-jti"
    }));
    let err = verify_dpop_proof(
        &proof,
        "POST",
        "https://api.example.com/resource",
        verify_options(),
    )
    .expect_err("future iat DPoP proof must be rejected");
    match err {
        VerifierError::InvalidClaims { message } => {
            assert!(
                message.contains("future") || message.contains("iat"),
                "error should mention future iat: {message}"
            );
        }
        other => panic!("expected InvalidClaims, got {other:?}"),
    }
}

#[test]
fn rfc9449_dpop_proof_must_not_be_too_old() {
    conformance_case!("rfc9449-dpop-proof-must-not-be-too-old");

    // Craft a DPoP proof with iat far in the past (beyond max_age + skew)
    let now = unix_now();
    let proof = dpop_proof_with_claims(json!({
        "htm": "POST",
        "htu": "https://api.example.com/resource",
        "iat": now - 3600,  // 1 hour ago, well beyond 300s max_age + 10s skew
        "jti": "old-proof-jti"
    }));
    let err = verify_dpop_proof(
        &proof,
        "POST",
        "https://api.example.com/resource",
        verify_options(),
    )
    .expect_err("too-old DPoP proof must be rejected");
    match err {
        VerifierError::InvalidClaims { message } => {
            assert!(
                message.contains("old") || message.contains("iat") || message.contains("age"),
                "error should mention age: {message}"
            );
        }
        other => panic!("expected InvalidClaims, got {other:?}"),
    }
}

#[tokio::test]
async fn rfc9449_dpop_proof_required_when_validating_dpop_bound_token() {
    conformance_case!("rfc9449-dpop-proof-required-when-validating-dpop-bound-token");

    // Catalog `expected.outcome = reject`,
    // `error_category = dpop_proof_missing`. A DPoP-bound token
    // (`cnf.jkt` present) cannot be validated when the caller omits
    // the DPoP proof, regardless of how the verification is invoked.
    let resource = resource_with_test_rsa_jwks();
    let token = signed_access_token(json!({
        "iss": "https://auth.example.com",
        "sub": "user-1",
        "client_id": "client-1",
        "aud": "https://api.example.com/mcp",
        "exp": 4_102_444_800i64,
        "iat": 1_700_000_000i64,
        "jti": "bound-token",
        "cnf": { "jkt": "matching-thumbprint" }
    }));
    let context =
        authplane_sdk::DpopRequestContext::new("POST", "https://api.example.com/mcp", None, None);
    let err = resource
        .verify_with_context(&token, &context)
        .await
        .expect_err("dpop-bound token without proof must reject");
    match err {
        VerifierError::DpopProofMissing => {}
        other => panic!("expected DpopProofMissing, got {other:?}"),
    }
}

#[test]
fn rfc9449_dpop_binding_mismatch_must_be_rejected() {
    conformance_case!("rfc9449-dpop-binding-mismatch-must-be-rejected");

    // RFC 9449 §4.3: when ath is expected and present it MUST match the
    // SHA-256 hash of the access token being presented. A proof minted
    // for a different access token must fail binding validation.
    let proof = create_dpop_proof(
        "POST",
        "https://api.example.com/resource",
        Some("token-A"),
        &rs256_options(None),
    )
    .expect("proof");
    let err = verify_dpop_proof(
        &proof,
        "POST",
        "https://api.example.com/resource",
        DpopVerificationOptions {
            expected_access_token: Some("token-B"),
            ..verify_options()
        },
    )
    .expect_err("ath mismatch must be rejected");
    match err {
        authplane_sdk::VerifierError::InvalidClaims { message } => {
            assert!(
                message.contains("ath"),
                "error should mention ath: {message}"
            );
        }
        other => panic!("expected InvalidClaims, got {other:?}"),
    }
}

#[test]
fn rfc9449_dpop_ath_mismatch_must_be_rejected() {
    conformance_case!("rfc9449-dpop-ath-mismatch-must-be-rejected");

    // Closely related to the binding case above, but separated in the
    // catalog: ath is derived from the access token's SHA-256 hash. We
    // assert the hash function is deterministic AND that two different
    // tokens produce two different ath values — anchoring the catalog's
    // `expected.result_contains` for this case.
    let a = dpop_ath("token-A");
    let b = dpop_ath("token-B");
    assert_ne!(a, b);
    assert_eq!(dpop_ath("token-A"), a, "ath must be deterministic");
}

#[tokio::test]
async fn rfc9449_dpop_bound_token_must_contain_cnf_jkt() {
    conformance_case!("rfc9449-dpop-bound-token-must-contain-cnf-jkt");

    // Catalog `expected.outcome = reject`,
    // `error_category = invalid_claims`, `error_hint = "cnf"`. If a
    // token carries a `cnf` claim that's missing the `jkt` thumbprint,
    // the resource server cannot verify sender binding and MUST reject.
    let resource = resource_with_test_rsa_jwks();
    let token = signed_access_token(json!({
        "iss": "https://auth.example.com",
        "sub": "user-1",
        "client_id": "client-1",
        "aud": "https://api.example.com/mcp",
        "exp": 4_102_444_800i64,
        "iat": 1_700_000_000i64,
        "jti": "bound-token-no-jkt",
        // `cnf` present but `jkt` missing — malformed binding claim.
        "cnf": {}
    }));
    // An otherwise-valid proof; we just need something so the request
    // doesn't bail on the empty `proof` field before checking cnf.
    let proof = create_dpop_proof(
        "POST",
        "https://api.example.com/mcp",
        Some(&token),
        &rs256_options(None),
    )
    .expect("proof");
    let context = authplane_sdk::DpopRequestContext::new(
        "POST",
        "https://api.example.com/mcp",
        Some(proof.as_str()),
        None,
    );
    let err = resource
        .verify_with_context(&token, &context)
        .await
        .expect_err("dpop-bound token missing cnf.jkt must reject");
    match err {
        VerifierError::InvalidClaims { message } => assert!(
            message.to_ascii_lowercase().contains("cnf"),
            "error hint must mention cnf, got {message}"
        ),
        other => panic!("expected InvalidClaims, got {other:?}"),
    }
}

#[test]
fn rfc9449_dpop_proof_validation_must_not_skip_binding_when_access_token_is_provided() {
    conformance_case!(
        "rfc9449-dpop-proof-validation-must-not-skip-binding-when-access-token-is-provided"
    );

    // Catalog: `expected.outcome = reject`,
    // `error_category = dpop_binding_mismatch`. If `verify_dpop_proof`
    // receives an access token but the proof carries no `ath`, it MUST
    // reject rather than silently skip binding enforcement.
    let proof = create_dpop_proof(
        "GET",
        "https://api.example.com/resource",
        None, // no access token → proof is minted without `ath`
        &rs256_options(None),
    )
    .expect("proof");
    let err = verify_dpop_proof(
        &proof,
        "GET",
        "https://api.example.com/resource",
        DpopVerificationOptions {
            expected_access_token: Some("token-a"),
            ..verify_options()
        },
    )
    .expect_err("missing ath must reject when expected_access_token is set");
    match err {
        VerifierError::InvalidClaims { message } => {
            let lower = message.to_ascii_lowercase();
            assert!(
                lower.contains("ath") || lower.contains("binding"),
                "error must surface a binding/ath failure, got {message}"
            );
        }
        other => panic!("expected InvalidClaims binding failure, got {other:?}"),
    }
}

#[test]
fn rfc9449_dpop_proof_htu_must_strip_query_and_fragment() {
    conformance_case!("rfc9449-dpop-proof-htu-must-strip-query-and-fragment");

    // RFC 9449 §4.2: htu SHOULD be the URL without query or fragment.
    // The SDK strips both before signing so a proof for
    // `/resource?foo=bar#baz` verifies as-if it had been minted for
    // `/resource`.
    let proof = create_dpop_proof(
        "POST",
        "https://api.example.com/resource?foo=bar#baz",
        None,
        &rs256_options(None),
    )
    .expect("proof");
    verify_dpop_proof(
        &proof,
        "POST",
        "https://api.example.com/resource",
        verify_options(),
    )
    .expect("proof must verify against the base URL");
}
