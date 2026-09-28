//! In-process DPoP roundtrip — mints a proof, verifies it, and confirms the
//! JWK thumbprint matches what a resource server would enforce via the
//! `cnf.jkt` claim of a DPoP-bound access token.
//!
//! Runs with no network: uses the same RSA test key pair the unit tests ship
//! with under `core/tests/fixtures/`.
//!
//! Run with:
//!   cargo run -p authplane-sdk --example dpop_roundtrip

use std::error::Error;

use authplane_sdk::{
    DpopProofOptions, DpopVerificationOptions, create_dpop_proof, dpop_ath, jwk_thumbprint_sha256,
    verify_dpop_proof,
};
use jsonwebtoken::Algorithm;
use serde_json::json;

const TEST_PRIVATE_PEM: &str = include_str!("../tests/fixtures/test-private.pem");
const TEST_RSA_N: &str = "pza1Jk6AXrea2P-TlgPStQO4PJ8H4mCz3qaW-PqscKygy31-_T-XNpYlH948O-hS3eN0bKLLKJetWx8bSWxBlMMW4DlV-vv32kO-phwPGE0BbQ2rMfZXfEKwKbcU_hTQv3_yfo6eugv3g_9bZR16MaNOWL0fWTmmcYoD7j8mODWoTgwGnHoriRE9wLgHOkXSJ-lnV4gR3Wa0HdI1Th91kve4mMC4DxxpzZ37xh5d0wyExHSb9bssowS70hts0JD-TX46MSpgVoCcZfBefyJ9JKoVgxVZ2aYGsdR8pwVRSRYUf2CYDvKyUZ8HfoWBv4JwBO0AVqT5Eb5F-X375fULQQ";
const TEST_RSA_E: &str = "AQAB";

fn main() -> Result<(), Box<dyn Error>> {
    // 1. Describe the public key the AS and resource server see.
    let public_jwk = json!({
        "kty": "RSA",
        "kid": "dpop-demo-kid",
        "use": "sig",
        "alg": "RS256",
        "n": TEST_RSA_N,
        "e": TEST_RSA_E
    });

    // 2. Compute the thumbprint (`cnf.jkt`) of the DPoP key. The AS embeds this
    //    in the issued access token; the resource server compares it to the
    //    thumbprint of the DPoP proof's header jwk on every request.
    let cnf_jkt = jwk_thumbprint_sha256(&public_jwk)?;
    println!("cnf_jkt = {cnf_jkt}");

    // 3. Mint a DPoP proof bound to the access token the client intends to use.
    let access_token = "bearer-or-dpop-access-token";
    let method = "POST";
    let target_url = "https://api.example.com/mcp";
    let nonce = Some("server-nonce");

    let proof = create_dpop_proof(
        method,
        target_url,
        Some(access_token),
        &DpopProofOptions {
            private_key_pem: TEST_PRIVATE_PEM.to_string(),
            public_jwk: public_jwk.clone(),
            algorithm: Algorithm::RS256,
            key_id: Some("dpop-demo-kid".to_string()),
            nonce: nonce.map(ToString::to_string),
            proof_ttl_seconds: None,
        },
    )?;
    println!(
        "dpop_proof header.claim.signature ({} segments, {} bytes)",
        proof.split('.').count(),
        proof.len()
    );
    println!("ath      = {}", dpop_ath(access_token));

    // 4. Verify the proof exactly as the resource server would (RFC 9449 §4.3).
    let verified = verify_dpop_proof(
        &proof,
        method,
        target_url,
        DpopVerificationOptions {
            expected_access_token: Some(access_token),
            expected_nonce: nonce,
            allowed_algorithms: &[Algorithm::RS256],
            clock_skew_seconds: 30,
            max_age_seconds: 300,
        },
    )?;

    // 5. Close the loop: the proof's jwk thumbprint must equal the access
    //    token's `cnf.jkt` claim. If they differ, the resource server MUST
    //    reject the request per RFC 9449 §6.1.
    assert_eq!(verified.jkt, cnf_jkt, "cnf.jkt binding failed");
    println!("verified: jti={} jkt={}", verified.jti, verified.jkt);

    // 6. Demonstrate rejection of a tampered proof: change the target URL and
    //    re-verify. The server must refuse replayed proofs on different
    //    endpoints.
    let replay_err = verify_dpop_proof(
        &proof,
        method,
        "https://api.example.com/other",
        DpopVerificationOptions {
            expected_access_token: Some(access_token),
            expected_nonce: nonce,
            allowed_algorithms: &[Algorithm::RS256],
            clock_skew_seconds: 30,
            max_age_seconds: 300,
        },
    )
    .expect_err("replay across URLs must fail");
    println!("replay across URL correctly rejected: {replay_err}");

    println!("dpop_roundtrip_ok");
    Ok(())
}
