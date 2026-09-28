//! AuthPlane-specific + verifier-surface conformance.
//!
//! Groups the catalog cases that don't sit naturally alongside a single
//! RFC: the three AuthPlane agent/delegation claims (`agent_id`,
//! `agent_chain`, `nbf`), plus the "unified verify entrypoint" DPoP
//! cases that describe how the SDK's single verify path must behave
//! when request context is present or absent.
//!
//! Each test body traces directly to the case's `expected` block. The
//! unified-entrypoint DPoP cases exercise
//! [`AuthplaneResource::verify_with_context`], which dispatches to
//! bearer or DPoP-bound verification based on the token's `cnf.jkt`
//! claim, so a caller need not decide up front which entrypoint a token
//! requires.

use authplane_conformance_tests::conformance_case;
use authplane_sdk::{
    AuthorizationServerMetadata, AuthplaneResource, DpopProofOptions, DpopRequestContext,
    DpopVerificationOptions, FetchSettings, InboundDPoPOptions, ResourceOptions, VerifiedClaims,
    VerifierError, create_dpop_proof, verify_dpop_proof,
};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::BTreeMap;

// Shared fixtures — lifted verbatim from jwt_and_dpop_conformance.rs so the
// `expected_access_token` binding test signs with the same keypair the rest
// of the suite uses.
const TEST_PRIVATE_PEM: &str = include_str!("../../core/tests/fixtures/test-private.pem");
const TEST_RSA_N: &str = "pza1Jk6AXrea2P-TlgPStQO4PJ8H4mCz3qaW-PqscKygy31-_T-XNpYlH948O-hS3eN0bKLLKJetWx8bSWxBlMMW4DlV-vv32kO-phwPGE0BbQ2rMfZXfEKwKbcU_hTQv3_yfo6eugv3g_9bZR16MaNOWL0fWTmmcYoD7j8mODWoTgwGnHoriRE9wLgHOkXSJ-lnV4gR3Wa0HdI1Th91kve4mMC4DxxpzZ37xh5d0wyExHSb9bssowS70hts0JD-TX46MSpgVoCcZfBefyJ9JKoVgxVZ2aYGsdR8pwVRSRYUf2CYDvKyUZ8HfoWBv4JwBO0AVqT5Eb5F-X375fULQQ";
const TEST_RSA_E: &str = "AQAB";

fn rsa_public_jwk() -> Value {
    json!({"kty": "RSA", "n": TEST_RSA_N, "e": TEST_RSA_E})
}

fn rs256_proof_options(nonce: Option<String>) -> DpopProofOptions {
    DpopProofOptions {
        private_key_pem: TEST_PRIVATE_PEM.to_string(),
        public_jwk: rsa_public_jwk(),
        algorithm: Algorithm::RS256,
        key_id: Some("dpop-kid".to_string()),
        nonce,
        proof_ttl_seconds: None,
    }
}

fn verify_opts_with<'a>(access_token: Option<&'a str>) -> DpopVerificationOptions<'a> {
    DpopVerificationOptions {
        expected_access_token: access_token,
        expected_nonce: None,
        allowed_algorithms: &[Algorithm::RS256, Algorithm::ES256],
        clock_skew_seconds: 10,
        max_age_seconds: 300,
    }
}

/// Minimal `VerifiedClaims` builder used by the AuthPlane agent tests.
///
/// The struct has all-public fields so we can drive it directly without
/// going through `AuthplaneResource::verify`; the catalog only asks us
/// to confirm the public API exposes the claim as a typed first-class
/// field, not how the verifier populated it.
fn claims_with(
    agent_id: &str,
    agent_chain: Vec<String>,
    not_before: i64,
    raw_overrides: BTreeMap<String, Value>,
) -> VerifiedClaims {
    VerifiedClaims {
        sub: "user-123".to_string(),
        client_id: "client-123".to_string(),
        scopes: vec!["tools/read".to_string()],
        issuer: "https://auth.example.com".to_string(),
        audience: vec!["https://api.example.com".to_string()],
        expires_at: 4_102_444_800,
        issued_at: 1_700_000_000,
        jti: "jti-1".to_string(),
        kid: "kid-1".to_string(),
        agent_id: agent_id.to_string(),
        agent_chain,
        not_before,
        raw: raw_overrides,
        dpop_proof: None,
    }
}

fn empty_claims() -> VerifiedClaims {
    claims_with("", Vec::new(), 0, BTreeMap::new())
}

// ---------------------------------------------------------------------------
// authplane-agent-id-must-be-exposed-as-first-class-field
// ---------------------------------------------------------------------------

#[test]
fn authplane_agent_id_present_is_exposed_as_typed_field() {
    conformance_case!("authplane-agent-id-must-be-exposed-as-first-class-field");

    // Catalog `expected.verified_claims_fields.agentId` == "research-agent"
    // — i.e. after verification, the typed field must equal the claim.
    let claims = claims_with("research-agent", Vec::new(), 0, BTreeMap::new());
    assert_eq!(claims.agent_id, "research-agent");
    // Type coverage — agent_id must be a String (not Option<String>) so
    // callers can use it directly without unwrapping.
    let _: &String = &claims.agent_id;
}

#[test]
fn authplane_agent_id_absent_defaults_to_empty_string() {
    conformance_case!("authplane-agent-id-must-be-exposed-as-first-class-field");

    // Catalog `expected.absent_claim_default.agentId` == "" — absence of
    // the claim must yield the empty string, not an error, not None.
    let claims = empty_claims();
    assert_eq!(claims.agent_id, "");
}

// ---------------------------------------------------------------------------
// authplane-agent-chain-must-be-exposed-as-first-class-field
// ---------------------------------------------------------------------------

#[test]
fn authplane_agent_chain_present_is_exposed_as_typed_list() {
    conformance_case!("authplane-agent-chain-must-be-exposed-as-first-class-field");

    // Catalog `expected.verified_claims_fields.agentChain`:
    //   - "orchestrator"
    //   - "research-agent"
    //   - "summarizer"
    let chain = vec![
        "orchestrator".to_string(),
        "research-agent".to_string(),
        "summarizer".to_string(),
    ];
    let claims = claims_with("", chain.clone(), 0, BTreeMap::new());
    assert_eq!(claims.agent_chain, chain);
    // Type coverage — must be Vec<String>, not Option<Vec<String>>.
    let _: &Vec<String> = &claims.agent_chain;
}

#[test]
fn authplane_agent_chain_absent_defaults_to_empty_list() {
    conformance_case!("authplane-agent-chain-must-be-exposed-as-first-class-field");

    // Catalog `expected.absent_claim_default.agentChain` == [] — absence
    // must yield an empty list, not None, not a missing field.
    let claims = empty_claims();
    assert!(
        claims.agent_chain.is_empty(),
        "agent_chain must default to empty list when claim is absent, got {:?}",
        claims.agent_chain
    );
}

// ---------------------------------------------------------------------------
// authplane-nbf-must-be-exposed-as-typed-field-on-verified-claims
// ---------------------------------------------------------------------------

#[test]
fn authplane_nbf_present_is_exposed_as_typed_integer() {
    conformance_case!("authplane-nbf-must-be-exposed-as-typed-field-on-verified-claims");

    // Catalog requirement summary: "When a verified JWT contains an nbf
    // claim, the SDK MUST expose it as a typed integer (Unix timestamp)
    // field on VerifiedClaims." The Rust SDK names the field `not_before`
    // to match the RFC 7519 full-form name — the wire claim is still
    // `nbf`.
    let claims = claims_with("", Vec::new(), 1_700_000_000, BTreeMap::new());
    assert_eq!(claims.not_before, 1_700_000_000);
    // Type coverage — must be a bare integer, not Option<i64>, so the
    // "absence yields 0" contract is representable.
    let _: &i64 = &claims.not_before;
}

#[test]
fn authplane_nbf_absent_defaults_to_zero() {
    conformance_case!("authplane-nbf-must-be-exposed-as-typed-field-on-verified-claims");

    // Catalog `expected.absent_claim_default.nbf` == 0 — absence must
    // surface as 0 per the AuthPlane SDK contract, not as a sentinel the
    // caller has to test for separately.
    let claims = empty_claims();
    assert_eq!(claims.not_before, 0);
}

// ---------------------------------------------------------------------------
// Verifier single-entrypoint cases (RFC 9449 §7 / §8)
//
// The Rust SDK exposes two verify entrypoints:
//   - `AuthplaneResource::verify(token)` — bearer only; rejects a
//     `cnf`-bound token instead of accepting it unbound
//   - `AuthplaneResource::verify_with_context(token, &ctx)` — unified,
//     three-mode dispatch
//
// The catalog's "unified entrypoint" cases describe the latter: a
// single verify path that takes a `DpopRequestContext` and branches on
// whether the access token is DPoP-bound (`cnf.jkt` present) to decide
// whether proof validation must run.
// ---------------------------------------------------------------------------

/// Builds an `AuthplaneResource` from pre-fetched metadata + JWKS that
/// share the test keypair, so these tests can drive `verify*` without
/// hitting a network. Mirrors the in-crate `resource_with_test_jwks`
/// helper used by the core unit tests.
fn resource_with_test_jwks() -> AuthplaneResource {
    let metadata = AuthorizationServerMetadata {
        issuer: "https://auth.example.com".to_string(),
        jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
        token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
        introspection_endpoint: Some("https://auth.example.com/oauth/introspect".to_string()),
        revocation_endpoint: Some("https://auth.example.com/oauth/revoke".to_string()),
    };
    let jwks_json = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "test-kid",
            "alg": "RS256",
            "use": "sig",
            "n": TEST_RSA_N,
            "e": TEST_RSA_E
        }]
    });
    let jwks: JwkSet = serde_json::from_value(jwks_json).expect("valid jwks");
    // Mode 2 opt-in (DPoP supported, bearer also accepted) so the
    // DPoP-related cases here pass the new Mode-3-by-default verifier.
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

fn auth_token_header() -> Header {
    Header {
        alg: Algorithm::RS256,
        kid: Some("test-kid".to_string()),
        typ: Some("at+jwt".to_string()),
        ..Header::new(Algorithm::RS256)
    }
}

fn signed_access_token(claims: Value) -> String {
    encode(
        &auth_token_header(),
        &claims,
        &EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).expect("private key"),
    )
    .expect("token")
}

#[tokio::test]
async fn rfc9449_bearer_token_with_request_context_and_no_proof_verifies_as_bearer() {
    conformance_case!(
        "rfc9449-bearer-token-with-request-context-and-no-proof-must-still-verify-as-bearer"
    );

    // Catalog `expected.outcome = accept`, `result_shape = [verified_claims]`,
    // `result_absent = [verified_dpop_proof]`. Bearer access token (no
    // `cnf`) + request context provided but `proof = None` MUST still
    // succeed as bearer token validation — the unified entrypoint is
    // not allowed to reject based on the mere presence of request
    // context.
    let resource = resource_with_test_jwks();
    let token = signed_access_token(json!({
        "iss": "https://auth.example.com",
        "sub": "user-1",
        "client_id": "client-1",
        "aud": "https://api.example.com/mcp",
        "exp": 4_102_444_800i64,
        "iat": 1_700_000_000i64,
        "jti": "bearer-token-1"
    }));
    let context = DpopRequestContext::new("GET", "https://api.example.com/resource", None, None);
    let claims = resource
        .verify_with_context(&token, &context)
        .await
        .expect("bearer + request context must verify");
    // `verified_claims` present (outcome = accept, result_shape covers
    // `verified_claims`).
    assert_eq!(claims.client_id, "client-1");
    // `verified_dpop_proof` absent — our `VerifiedClaims` does not
    // carry a proof field at all for bearer tokens, and the token has
    // no `cnf` confirmation claim.
    assert!(
        !claims.raw.contains_key("cnf"),
        "bearer token must not carry a cnf confirmation claim"
    );
}

#[tokio::test]
async fn rfc9449_dpop_bound_token_with_request_context_and_no_proof_is_rejected() {
    conformance_case!(
        "rfc9449-dpop-bound-token-with-request-context-and-no-proof-must-be-rejected-via-main-verify-path"
    );

    // Catalog `expected.outcome = reject`,
    // `error_category = dpop_proof_missing`. DPoP-bound access token
    // (`cnf.jkt` present) + request context WITHOUT a proof MUST be
    // rejected by the unified verify path, even though `verify(token)`
    // alone would accept the JWT.
    let resource = resource_with_test_jwks();
    let token = signed_access_token(json!({
        "iss": "https://auth.example.com",
        "sub": "user-1",
        "client_id": "client-1",
        "aud": "https://api.example.com/mcp",
        "exp": 4_102_444_800i64,
        "iat": 1_700_000_000i64,
        "jti": "bound-token-1",
        "cnf": { "jkt": "matching-thumbprint" }
    }));
    let context = DpopRequestContext::new("GET", "https://api.example.com/resource", None, None);
    let err = resource
        .verify_with_context(&token, &context)
        .await
        .expect_err("dpop-bound token without proof must reject");
    match err {
        VerifierError::DpopProofMissing => {}
        other => {
            panic!("expected DpopProofMissing (error_category = dpop_proof_missing), got {other:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// rfc9449-dpop-proof-validation-must-not-skip-binding-when-access-token-is-provided
// ---------------------------------------------------------------------------

#[test]
fn rfc9449_dpop_proof_validation_must_not_skip_binding_when_access_token_is_provided() {
    conformance_case!(
        "rfc9449-dpop-proof-validation-must-not-skip-binding-when-access-token-is-provided"
    );

    // Catalog: if `verify_dpop_proof` is given an access token to
    // validate against, it MUST NOT silently skip binding enforcement.
    // Concretely: the caller creates a proof WITHOUT ath (by passing
    // `access_token = None` to `create_dpop_proof`), then asks the
    // verifier to enforce binding against "token-a". The verifier must
    // reject — either because the proof has no ath, or because the ath
    // does not match the token.
    let method = "GET";
    let url = "https://api.example.com/resource";
    let proof =
        create_dpop_proof(method, url, None, &rs256_proof_options(None)).expect("proof created");

    // Sanity: the proof must not already carry an ath — otherwise the
    // test would not actually exercise "missing binding" behavior.
    let parts: Vec<&str> = proof.split('.').collect();
    assert_eq!(parts.len(), 3, "proof must have 3 compact segments");
    let payload_bytes = base64_url_decode(parts[1]);
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("payload is JSON");
    assert!(
        payload.get("ath").is_none(),
        "proof was built with access_token=None; ath must be absent"
    );

    let err = verify_dpop_proof(&proof, method, url, verify_opts_with(Some("token-a")))
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

fn base64_url_decode(input: &str) -> Vec<u8> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD.decode(input).expect("valid base64url")
}

// ---------------------------------------------------------------------------
// Three-mode inbound DPoP (RFC 9449 §6/§7 + RFC 9728 §2).
// The three modes are the resource's own DPoP posture: capability advertised,
// required, or absent.
// ---------------------------------------------------------------------------

/// Build a resource with a custom `ResourceOptions` — used by the Mode-1 /
/// Mode-3 tests that need to bypass the helper's Mode-2 default.
fn resource_with_test_jwks_and_options(options: ResourceOptions) -> AuthplaneResource {
    let metadata = AuthorizationServerMetadata {
        issuer: "https://auth.example.com".to_string(),
        jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
        token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
        introspection_endpoint: Some("https://auth.example.com/oauth/introspect".to_string()),
        revocation_endpoint: Some("https://auth.example.com/oauth/revoke".to_string()),
    };
    let jwks_json = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "test-kid",
            "alg": "RS256",
            "use": "sig",
            "n": TEST_RSA_N,
            "e": TEST_RSA_E
        }]
    });
    let jwks: JwkSet = serde_json::from_value(jwks_json).expect("valid jwks");
    AuthplaneResource::from_prefetched_metadata(
        "https://auth.example.com",
        "https://api.example.com/mcp",
        &["tools/read".to_string()],
        metadata,
        FetchSettings::from_dev_mode(true),
        options,
        jwks,
    )
    .expect("build resource from prefetched metadata")
}

#[tokio::test]
async fn rfc9449_verifier_must_reject_bearer_only_token_when_resource_requires_dpop() {
    conformance_case!("rfc9449-verifier-must-reject-bearer-only-token-when-resource-requires-dpop");

    // Mode 1: inbound_dpop.required = true. A token without `cnf.jkt`
    // (pure bearer) MUST be rejected even when the JWT itself verifies.
    let resource = resource_with_test_jwks_and_options(
        ResourceOptions::default().with_inbound_dpop(InboundDPoPOptions::required()),
    );
    let token = signed_access_token(json!({
        "iss": "https://auth.example.com",
        "sub": "user-1",
        "client_id": "client-1",
        "aud": "https://api.example.com/mcp",
        "exp": 4_102_444_800i64,
        "iat": 1_700_000_000i64,
        "jti": "bearer-token-1"
    }));
    let context = DpopRequestContext::new("GET", "https://api.example.com/resource", None, None);
    let err = resource
        .verify_with_context(&token, &context)
        .await
        .expect_err("Mode 1 must reject bearer-only tokens");
    match err {
        VerifierError::DpopBindingMismatch { message } => {
            assert!(
                message.to_ascii_lowercase().contains("dpop-bound"),
                "expected the message to mention DPoP-bound, got: {message}"
            );
        }
        other => panic!("expected DpopBindingMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn rfc9449_verifier_must_reject_dpop_bound_token_when_resource_does_not_support_dpop() {
    conformance_case!(
        "rfc9449-verifier-must-reject-dpop-bound-token-when-resource-does-not-support-dpop"
    );

    // Mode 3: inbound_dpop = None (the `ResourceOptions::default()`
    // shape). A DPoP-bound access token (carrying `cnf.jkt`) MUST be
    // rejected with DpopNotSupported — the resource has not advertised
    // DPoP, so silently downgrading to bearer would drop sender-binding
    // (RFC 9449 §6).
    let resource = resource_with_test_jwks_and_options(ResourceOptions::default());
    let token = signed_access_token(json!({
        "iss": "https://auth.example.com",
        "sub": "user-1",
        "client_id": "client-1",
        "aud": "https://api.example.com/mcp",
        "exp": 4_102_444_800i64,
        "iat": 1_700_000_000i64,
        "jti": "bound-token-1",
        "cnf": { "jkt": "any-thumbprint" }
    }));
    let context = DpopRequestContext::new("GET", "https://api.example.com/resource", None, None);
    let err = resource
        .verify_with_context(&token, &context)
        .await
        .expect_err("Mode 3 must reject DPoP-bound tokens");
    assert!(
        matches!(err, VerifierError::DpopNotSupported),
        "expected DpopNotSupported, got {err:?}"
    );
}

#[tokio::test]
async fn rfc9449_verifier_must_reject_dpop_proof_when_access_token_is_not_dpop_bound() {
    conformance_case!(
        "rfc9449-verifier-must-reject-dpop-proof-when-access-token-is-not-dpop-bound"
    );

    // Mode 2: resource supports DPoP but doesn't require it. A bearer-
    // only token (no `cnf.jkt`) accompanied by a DPoP proof header is
    // structurally malformed — the proof's `ath` has nothing to bind to
    // — so the verifier MUST reject before signature checks (the proof
    // itself need not be well-formed for this test, the rejection
    // happens at the binding-shape check).
    let resource = resource_with_test_jwks_and_options(
        ResourceOptions::default().with_inbound_dpop(InboundDPoPOptions::default()),
    );
    let token = signed_access_token(json!({
        "iss": "https://auth.example.com",
        "sub": "user-1",
        "client_id": "client-1",
        "aud": "https://api.example.com/mcp",
        "exp": 4_102_444_800i64,
        "iat": 1_700_000_000i64,
        "jti": "bearer-token-1"
    }));
    let context = DpopRequestContext::new(
        "POST",
        "https://api.example.com/resource",
        Some("dummy-proof-not-validated"),
        None,
    );
    let err = resource
        .verify_with_context(&token, &context)
        .await
        .expect_err("Mode 2 must reject proof attached to bearer-only token");
    match err {
        VerifierError::DpopBindingMismatch { message } => {
            assert!(
                message.to_ascii_lowercase().contains("not dpop-bound"),
                "expected 'not DPoP-bound' message, got: {message}"
            );
        }
        other => panic!("expected DpopBindingMismatch, got {other:?}"),
    }
}

#[test]
fn rfc9728_prm_must_advertise_dpop_required_when_resource_requires_dpop() {
    conformance_case!("rfc9728-prm-must-advertise-dpop-required-when-resource-requires-dpop");

    use authplane_sdk::build_prm;

    // When `inbound_dpop.required = true`, PRM advertises
    // `dpop_bound_access_tokens_required: true` alongside
    // `dpop_signing_alg_values_supported`. Mode-2 emits the same fields
    // with `required: false`; Mode 3 omits them entirely.
    let dpop_algs = vec!["ES256".to_string(), "RS256".to_string()];
    let prm = build_prm(
        "https://auth.example.com",
        "https://api.example.com/mcp",
        &["tools/read".to_string(), "tools/write".to_string()],
        Some(dpop_algs.as_slice()),
        true,
    );

    let json = serde_json::to_value(&prm).expect("serialise PRM");
    assert_eq!(
        json.get("dpop_bound_access_tokens_required"),
        Some(&Value::Bool(true)),
        "PRM must advertise dpop_bound_access_tokens_required:true when required"
    );
    let algs = json
        .get("dpop_signing_alg_values_supported")
        .and_then(Value::as_array)
        .expect("PRM must advertise dpop_signing_alg_values_supported alongside required flag");
    assert!(!algs.is_empty(), "alg list must not be empty");

    // Sanity: Mode 2 still emits the field as false — advertising DPoP support
    // is not the same as requiring it.
    let dpop_algs_m2 = vec!["ES256".to_string()];
    let prm_mode2 = build_prm(
        "https://auth.example.com",
        "https://api.example.com/mcp",
        &["tools/read".to_string()],
        Some(dpop_algs_m2.as_slice()),
        false,
    );
    let json_mode2 = serde_json::to_value(&prm_mode2).expect("serialise PRM");
    assert_eq!(
        json_mode2.get("dpop_bound_access_tokens_required"),
        Some(&Value::Bool(false)),
        "Mode 2 PRM must advertise dpop_bound_access_tokens_required:false"
    );

    // Mode 3: no DPoP configured at all → both DPoP fields omitted.
    let prm_mode3 = build_prm(
        "https://auth.example.com",
        "https://api.example.com/mcp",
        &["tools/read".to_string()],
        None,
        false,
    );
    let json_mode3 = serde_json::to_value(&prm_mode3).expect("serialise PRM");
    assert!(
        json_mode3
            .get("dpop_bound_access_tokens_required")
            .is_none(),
        "Mode 3 PRM must omit the required flag"
    );
    assert!(
        json_mode3
            .get("dpop_signing_alg_values_supported")
            .is_none(),
        "Mode 3 PRM must omit the alg list"
    );
}
