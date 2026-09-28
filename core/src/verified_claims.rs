use std::collections::BTreeMap;

use serde_json::Value;
use thiserror::Error;

use crate::dpop::VerifiedDpopProof;

#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    pub sub: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub issuer: String,
    pub audience: Vec<String>,
    pub expires_at: i64,
    pub issued_at: i64,
    pub jti: String,
    pub kid: String,
    pub agent_id: String,
    pub agent_chain: Vec<String>,
    pub not_before: i64,
    pub raw: BTreeMap<String, Value>,
    /// The verified DPoP proof, if the token was DPoP-bound and
    /// `verify_with_context` was used. `None` for bearer tokens.
    pub dpop_proof: Option<VerifiedDpopProof>,
}

/// Manual `PartialEq` that excludes `dpop_proof`: the verified proof is
/// attached to the claims for the caller's use, but two sets of claims are
/// equal on their claim values, not on which request carried them.
impl PartialEq for VerifiedClaims {
    fn eq(&self, other: &Self) -> bool {
        self.sub == other.sub
            && self.client_id == other.client_id
            && self.scopes == other.scopes
            && self.issuer == other.issuer
            && self.audience == other.audience
            && self.expires_at == other.expires_at
            && self.issued_at == other.issued_at
            && self.jti == other.jti
            && self.kid == other.kid
            && self.agent_id == other.agent_id
            && self.agent_chain == other.agent_chain
            && self.not_before == other.not_before
            && self.raw == other.raw
    }
}

impl VerifiedClaims {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|candidate| candidate == scope)
    }

    pub fn require_scope(&self, scope: &str) -> Result<(), VerifierError> {
        if self.has_scope(scope) {
            return Ok(());
        }

        Err(VerifierError::InsufficientScope {
            required: scope.to_string(),
            available: self.scopes.clone(),
        })
    }

    pub fn has_claim(&self, key: &str, expected: Option<&Value>) -> bool {
        match self.raw.get(key) {
            Some(value) => expected.is_none_or(|candidate| candidate == value),
            None => false,
        }
    }

    /// RFC 8693 §4.1 — the `act` (actor) claim, if present.
    ///
    /// Returns the nested actor claim object describing who is acting on
    /// behalf of the subject.
    pub fn act(&self) -> Option<&Value> {
        self.raw.get("act")
    }

    /// RFC 8693 §4.4 — the `may_act` claim, if present.
    ///
    /// Returns the authorization claim describing who is allowed to act
    /// on behalf of the subject.
    #[deprecated(note = "authserver 0.2.0 no longer issues may_act; removed in the next minor")]
    pub fn may_act(&self) -> Option<&Value> {
        self.raw.get("may_act")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum VerifierError {
    #[error("access token is missing")]
    TokenMissing,
    #[error("token has expired")]
    TokenExpired,
    #[error("token signature verification failed: {message}")]
    InvalidSignature { message: String },
    #[error("token claims validation failed: {message}")]
    InvalidClaims { message: String },
    #[error("failed to fetch or use metadata: {message}")]
    MetadataUnavailable { message: String },
    #[error("failed to fetch or use JWKS: {message}")]
    JwksUnavailable { message: String },
    /// RFC 7662 §2.2 — introspection answered `active: false` for a token
    /// that had already passed local JWT verification.
    ///
    /// RFC 7662 defines `active: false` broadly and authserver does not
    /// say why, so the token may be revoked — or the AS may not recognise
    /// this resource server as the token's owner. Since authserver 0.1.2
    /// only the issuing client or a runtime-client of the Resource named
    /// in `aud` gets a real answer; any other caller, including a public
    /// (secret-less) client, gets `active: false` for every token. If every
    /// token is rejected with this error, register the resource server's
    /// client on the Resource:
    /// `authserver admin resource runtime-client add --client-id <rs-client-id> --slug <resource-slug>`.
    ///
    /// The Display is deliberately bare: `www_authenticate*` copies
    /// `error.to_string()` into `error_description` and the mcp adapter copies
    /// it into the 401 body, so anything said here reaches an unauthenticated
    /// caller. The operator guidance above stays in the docs.
    #[error("token is not active")]
    TokenRevoked,
    #[error("token missing required scope {required:?}; available scopes: {available:?}")]
    InsufficientScope {
        required: String,
        available: Vec<String>,
    },
    /// RFC 9449 §7 — the `verify_with_context` entrypoint received a
    /// DPoP-bound access token (one with `cnf.jkt`) but the request
    /// context carried no DPoP proof. Maps to the catalog's
    /// `error_category = "dpop_proof_missing"` bucket.
    ///
    /// A context that was never supplied is a different failure and is
    /// reported as [`Self::DpopBindingMismatch`]: `verify` takes no
    /// request context by construction, so "the caller passed one and it
    /// held no proof" is a claim only this entrypoint can make.
    #[error("DPoP-bound access token rejected: no DPoP proof supplied in request context")]
    DpopProofMissing,
    /// RFC 9449 §11.1 — the proof's `jti` had already been observed by
    /// the configured replay store.
    #[error("DPoP proof replay detected (duplicate jti)")]
    DpopReplayDetected,
    /// RFC 9449 §4.3 #1 — the request carried more than one `DPoP` header,
    /// so there is no way to know which proof binds the request. Unlike the
    /// other DPoP failures this maps to `error="invalid_dpop_proof"`
    /// (RFC 9449 §7.1) rather than the generic `invalid_token`.
    #[error("multiple DPoP headers received; exactly one required (RFC 9449 section 4.3)")]
    DpopMultipleProofs,
    #[error("DPoP binding mismatch: {message}")]
    DpopBindingMismatch { message: String },
    /// RFC 9449 §6 — the resource has NOT opted into inbound DPoP
    /// (`ResourceOptions::inbound_dpop` is `None`), but the request carried
    /// a DPoP signal (a `cnf.jkt`-bound access token or a `DPoP` proof
    /// header). The verifier rejects rather than silently downgrading to
    /// bearer or applying ad-hoc defaults never advertised in PRM.
    #[error(
        "DPoP-bound request rejected: resource is not configured for inbound DPoP. \
         Set ResourceOptions::inbound_dpop to enable."
    )]
    DpopNotSupported,
}

impl VerifierError {
    /// `true` for any DPoP-specific variant. Currently `DpopProofMissing`,
    /// `DpopReplayDetected`, `DpopMultipleProofs`, `DpopBindingMismatch`,
    /// and `DpopNotSupported`.
    ///
    /// Membership only — does NOT decide the `WWW-Authenticate` scheme.
    /// `DpopNotSupported` is a DPoP-flavoured error but the spec-correct
    /// retry scheme is `Bearer` (see [`Self::www_authenticate_scheme_is_dpop`]).
    pub fn is_dpop(&self) -> bool {
        matches!(
            self,
            VerifierError::DpopProofMissing
                | VerifierError::DpopReplayDetected
                | VerifierError::DpopMultipleProofs
                | VerifierError::DpopBindingMismatch { .. }
                | VerifierError::DpopNotSupported
        )
    }

    /// `true` when the spec-correct `WWW-Authenticate` challenge for this
    /// error uses the `DPoP` scheme (RFC 9449 §7.1) rather than the default
    /// `Bearer` (RFC 6750 §3).
    ///
    /// All DPoP-bound failures map to `DPoP` **except** [`Self::DpopNotSupported`],
    /// which is the carve-out: the client presented a DPoP signal against a
    /// resource that has not opted into DPoP, so there is no `DPoP` retry
    /// path on this resource — the correct challenge tells the client to
    /// retry as `Bearer`. Conformance fixtures assert this scheme
    /// byte-for-byte.
    pub fn www_authenticate_scheme_is_dpop(&self) -> bool {
        matches!(
            self,
            VerifierError::DpopProofMissing
                | VerifierError::DpopReplayDetected
                | VerifierError::DpopMultipleProofs
                | VerifierError::DpopBindingMismatch { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{VerifiedClaims, VerifierError};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn sample_claims() -> VerifiedClaims {
        let mut raw = BTreeMap::new();
        raw.insert("sub".to_string(), json!("user-123"));
        raw.insert("tenant".to_string(), json!("acme"));
        VerifiedClaims {
            sub: "user-123".to_string(),
            client_id: "client-123".to_string(),
            scopes: vec!["tools/read".to_string(), "tools/write".to_string()],
            issuer: "https://auth.example.com".to_string(),
            audience: vec!["https://api.example.com".to_string()],
            expires_at: 4_102_444_800,
            issued_at: 1_700_000_000,
            jti: "jti-1".to_string(),
            kid: "kid-1".to_string(),
            agent_id: "agent-1".to_string(),
            agent_chain: vec!["agent-0".to_string(), "agent-1".to_string()],
            not_before: 1_700_000_000,
            raw,
            dpop_proof: None,
        }
    }

    #[test]
    fn has_scope_returns_true_when_present() {
        let claims = sample_claims();
        assert!(claims.has_scope("tools/read"));
    }

    #[test]
    fn has_scope_returns_false_when_absent() {
        let claims = sample_claims();
        assert!(!claims.has_scope("tools/delete"));
    }

    #[test]
    fn require_scope_succeeds_when_present() {
        let claims = sample_claims();
        assert!(claims.require_scope("tools/write").is_ok());
    }

    #[test]
    fn require_scope_fails_when_missing() {
        let claims = sample_claims();
        let error = claims
            .require_scope("tools/admin")
            .expect_err("missing scope must fail");
        let VerifierError::InsufficientScope {
            required,
            available,
        } = error
        else {
            panic!("expected insufficient scope")
        };
        assert_eq!(required, "tools/admin");
        assert_eq!(available, vec!["tools/read", "tools/write"]);
    }

    #[test]
    fn has_claim_true_without_expected_when_key_exists() {
        let claims = sample_claims();
        assert!(claims.has_claim("tenant", None));
    }

    #[test]
    fn has_claim_true_with_expected_when_value_matches() {
        let claims = sample_claims();
        assert!(claims.has_claim("tenant", Some(&json!("acme"))));
    }

    #[test]
    fn has_claim_false_when_value_mismatch() {
        let claims = sample_claims();
        assert!(!claims.has_claim("tenant", Some(&json!("other"))));
    }

    #[test]
    fn has_claim_false_when_key_missing() {
        let claims = sample_claims();
        assert!(!claims.has_claim("missing", None));
    }

    /// `is_dpop` is part of the public API — downstream consumers use it
    /// to bucket DPoP-flavoured failures. Pin its membership exhaustively
    /// so a new `VerifierError` variant added in the future does not
    /// silently miss the predicate.
    #[test]
    fn is_dpop_covers_every_dpop_variant_and_nothing_else() {
        // DPoP-flavoured: must return true.
        assert!(VerifierError::DpopProofMissing.is_dpop());
        assert!(VerifierError::DpopReplayDetected.is_dpop());
        assert!(VerifierError::DpopMultipleProofs.is_dpop());
        assert!(
            VerifierError::DpopBindingMismatch {
                message: "x".to_string()
            }
            .is_dpop()
        );
        assert!(VerifierError::DpopNotSupported.is_dpop());

        // Non-DPoP: must return false.
        assert!(!VerifierError::TokenMissing.is_dpop());
        assert!(!VerifierError::TokenExpired.is_dpop());
        assert!(
            !VerifierError::InvalidSignature {
                message: "x".to_string()
            }
            .is_dpop()
        );
        assert!(
            !VerifierError::InvalidClaims {
                message: "x".to_string()
            }
            .is_dpop()
        );
        assert!(
            !VerifierError::MetadataUnavailable {
                message: "x".to_string()
            }
            .is_dpop()
        );
        assert!(
            !VerifierError::JwksUnavailable {
                message: "x".to_string()
            }
            .is_dpop()
        );
        assert!(!VerifierError::TokenRevoked.is_dpop());
        assert!(
            !VerifierError::InsufficientScope {
                required: "x".to_string(),
                available: vec![]
            }
            .is_dpop()
        );
    }

    /// `www_authenticate*` copies `error.to_string()` into `error_description`
    /// and the mcp adapter copies it into the 401 body, so this Display reaches
    /// unauthenticated callers. It must not describe the deployment.
    #[test]
    fn token_revoked_display_carries_no_deployment_detail() {
        let rendered = VerifierError::TokenRevoked.to_string();
        assert_eq!(rendered, "token is not active");
        for leaked in [
            "introspection",
            "runtime-client",
            "issuing client",
            "active=false",
        ] {
            assert!(
                !rendered.contains(leaked),
                "TokenRevoked Display leaked {leaked:?} onto the wire"
            );
        }
    }
}
