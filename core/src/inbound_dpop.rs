//! Per-resource inbound DPoP validation configuration.
//!
//! Passing any instance — even [`InboundDPoPOptions::default`] — into
//! [`ResourceOptions`] is the on/off switch for PRM advertising of
//! `dpop_signing_alg_values_supported` and
//! `dpop_bound_access_tokens_required`, **and** for the verifier accepting
//! any inbound DPoP signal. Omitting it (`None`) causes the verifier to
//! reject any inbound DPoP signal with [`VerifierError::DpopNotSupported`]
//! (RFC 9449 §6).
//!
//! [`ResourceOptions`]: crate::resource::ResourceOptions
//! [`VerifierError::DpopNotSupported`]: crate::verified_claims::VerifierError::DpopNotSupported

use std::borrow::Cow;
use std::sync::Arc;

use jsonwebtoken::Algorithm;

use crate::dpop_replay::{DpopReplayStore, InMemoryDpopReplayStore};

/// Per-resource inbound DPoP validation configuration (RFC 9449 §7.1 +
/// RFC 9728 §2).
///
/// Fields are private so the type-system enforces the validation that
/// [`Self::with_allowed_proof_algorithms`] performs. Construct with
/// [`Self::default`] (Mode 2 — DPoP optional) or [`Self::required`]
/// (Mode 1 — DPoP mandatory) and refine with the `with_*` setters.
#[derive(Clone, Debug)]
pub struct InboundDPoPOptions {
    required: bool,
    allowed_proof_algorithms: Option<Vec<Algorithm>>,
    max_proof_age_seconds: Option<u64>,
    clock_skew_seconds: Option<u64>,
    /// Always populated. [`Self::default`] allocates a fresh
    /// [`InMemoryDpopReplayStore`] so the RFC 9449 §11.1 `jti` guarantee
    /// holds without callers having to remember to install one. Multi-
    /// process deployments override via [`Self::with_replay_store`].
    /// Cloning [`InboundDPoPOptions`] clones the `Arc`, so two resources
    /// built from the same options instance share replay state — pass
    /// distinct `InboundDPoPOptions::default()` values when independent
    /// per-resource deduplication is required.
    replay_store: Arc<dyn DpopReplayStore>,
}

impl Default for InboundDPoPOptions {
    fn default() -> Self {
        Self {
            required: false,
            allowed_proof_algorithms: None,
            max_proof_age_seconds: None,
            clock_skew_seconds: None,
            replay_store: Arc::new(InMemoryDpopReplayStore::new()),
        }
    }
}

impl InboundDPoPOptions {
    /// Mode 1 (DPoP required) with defaults for everything else. Equivalent
    /// to `InboundDPoPOptions::default().with_required(true)` but reads
    /// closer to intent at call sites.
    pub fn required() -> Self {
        Self {
            required: true,
            ..Self::default()
        }
    }

    /// Set whether DPoP binding is required. When `true`, bearer-only
    /// tokens (no `cnf.jkt`) are rejected with `DpopBindingMismatch` and
    /// the PRM advertises `dpop_bound_access_tokens_required: true`.
    pub fn with_required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    /// Restrict accepted DPoP proof algorithms to a non-empty subset of
    /// [`crate::dpop::SUPPORTED_DPOP_ALGORITHMS`]. Returns an error on
    /// empty or unsupported entries so callers cannot install
    /// asymmetric-only-bypass values like `HS256` through this setter
    /// (or any other path — the field is private).
    pub fn with_allowed_proof_algorithms(
        mut self,
        algorithms: Vec<Algorithm>,
    ) -> Result<Self, InboundDPoPOptionsError> {
        if algorithms.is_empty() {
            return Err(InboundDPoPOptionsError::EmptyAlgorithmList);
        }
        for alg in &algorithms {
            if !crate::dpop::SUPPORTED_DPOP_ALGORITHMS.contains(alg) {
                return Err(InboundDPoPOptionsError::UnsupportedAlgorithm(*alg));
            }
        }
        self.allowed_proof_algorithms = Some(algorithms);
        Ok(self)
    }

    /// Override the maximum accepted proof age (seconds from `iat`).
    /// Unset means inherit `ResourceOptions::dpop_proof_max_age_seconds`.
    pub fn with_max_proof_age_seconds(mut self, seconds: u64) -> Self {
        self.max_proof_age_seconds = Some(seconds);
        self
    }

    /// Override the clock skew (seconds) tolerated on proof time claims.
    /// Unset means inherit `ResourceOptions::clock_skew_seconds`.
    pub fn with_clock_skew_seconds(mut self, seconds: u64) -> Self {
        self.clock_skew_seconds = Some(seconds);
        self
    }

    /// Install a custom replay store. Defaults to a fresh
    /// [`InMemoryDpopReplayStore`] per [`InboundDPoPOptions::default`]
    /// allocation — sufficient for single-process deployments. Multi-
    /// process and distributed deployments MUST pass a shared store
    /// (Redis, database) so the RFC 9449 §11.1 `jti` guarantee holds
    /// across replicas.
    pub fn with_replay_store(mut self, store: Arc<dyn DpopReplayStore>) -> Self {
        self.replay_store = store;
        self
    }

    /// Whether the resource requires DPoP-bound tokens (Mode 1).
    pub fn is_required(&self) -> bool {
        self.required
    }

    /// Replay store the resource will use for proof-`jti` deduplication.
    /// Always non-`None` — see [`Self::with_replay_store`] for the
    /// default and override semantics.
    pub fn replay_store(&self) -> &Arc<dyn DpopReplayStore> {
        &self.replay_store
    }

    /// Effective allowed proof algorithms: borrows the configured slice
    /// when set, or the SDK default otherwise. Borrowed in both cases —
    /// callers iterating or `contains`-checking pay no allocation.
    pub fn resolved_allowed_proof_algorithms(&self) -> Cow<'_, [Algorithm]> {
        match self.allowed_proof_algorithms.as_deref() {
            Some(algs) => Cow::Borrowed(algs),
            None => Cow::Borrowed(crate::dpop::SUPPORTED_DPOP_ALGORITHMS),
        }
    }

    /// Effective max proof age, falling through to `resource_default` when
    /// the caller didn't set one explicitly. `ResourceOptions` carries the
    /// SDK-wide default of 300s; this method only resolves the override
    /// layer.
    pub fn resolved_max_proof_age_seconds(&self, resource_default: u64) -> u64 {
        self.max_proof_age_seconds.unwrap_or(resource_default)
    }

    /// Effective clock skew, falling through to `resource_default` when
    /// the caller didn't set one explicitly. The SDK-wide default of 30s
    /// lives on `ResourceOptions`.
    pub fn resolved_clock_skew_seconds(&self, resource_default: u64) -> u64 {
        self.clock_skew_seconds.unwrap_or(resource_default)
    }
}

/// Configuration error surfaced by [`InboundDPoPOptions::with_allowed_proof_algorithms`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InboundDPoPOptionsError {
    #[error(
        "allowed_proof_algorithms must be non-empty; omit the setter to accept the default set"
    )]
    EmptyAlgorithmList,

    #[error("DPoP proof algorithm {0:?} is not supported; supported algorithms are ES256, RS256")]
    UnsupportedAlgorithm(Algorithm),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn defaults_to_mode_2() {
        let opts = InboundDPoPOptions::default();
        assert!(!opts.is_required());
        // Defaults inherit from the resource-level setting.
        assert_eq!(opts.resolved_max_proof_age_seconds(600), 600);
        assert_eq!(opts.resolved_clock_skew_seconds(60), 60);
        // Replay store is auto-allocated, so `jti` deduplication is on by
        // default without the
        // caller having to remember to install a store. Smoke-check the
        // store works by recording a `jti`.
        let stored = opts
            .replay_store()
            .check_and_store("jti-default-test", 4102444800)
            .await
            .expect("default replay store must be usable");
        assert!(stored, "first observation of jti must succeed");
    }

    #[tokio::test]
    async fn each_default_allocates_an_independent_replay_store() {
        // Two `InboundDPoPOptions::default()` calls must NOT share state —
        // otherwise a duplicate `jti` from resource B would falsely look
        // like a replay of resource A's earlier proof.
        let opts_a = InboundDPoPOptions::default();
        let opts_b = InboundDPoPOptions::default();
        opts_a
            .replay_store()
            .check_and_store("jti-shared", 4102444800)
            .await
            .expect("store A accepts");
        let stored_in_b = opts_b
            .replay_store()
            .check_and_store("jti-shared", 4102444800)
            .await
            .expect("store B accepts");
        assert!(stored_in_b, "distinct defaults must not share replay state");
    }

    #[test]
    fn required_shortcut_sets_only_the_flag() {
        let opts = InboundDPoPOptions::required();
        assert!(opts.is_required());
        // Other inheritance points still inherit from the resource.
        assert_eq!(opts.resolved_clock_skew_seconds(60), 60);
    }

    #[test]
    fn with_allowed_proof_algorithms_rejects_empty() {
        let res = InboundDPoPOptions::default().with_allowed_proof_algorithms(vec![]);
        assert!(matches!(
            res,
            Err(InboundDPoPOptionsError::EmptyAlgorithmList)
        ));
    }

    #[test]
    fn with_allowed_proof_algorithms_rejects_unsupported() {
        let res =
            InboundDPoPOptions::default().with_allowed_proof_algorithms(vec![Algorithm::HS256]);
        assert!(matches!(
            res,
            Err(InboundDPoPOptionsError::UnsupportedAlgorithm(
                Algorithm::HS256
            ))
        ));
    }

    #[test]
    fn with_allowed_proof_algorithms_accepts_es256_subset() {
        let opts = InboundDPoPOptions::default()
            .with_allowed_proof_algorithms(vec![Algorithm::ES256])
            .expect("valid");
        match opts.resolved_allowed_proof_algorithms() {
            Cow::Borrowed(slice) => assert_eq!(slice, &[Algorithm::ES256]),
            Cow::Owned(_) => panic!("setter slice should be borrowed"),
        }
    }

    #[test]
    fn resolved_allowed_proof_algorithms_borrows_default_when_unset() {
        let opts = InboundDPoPOptions::default();
        let resolved = opts.resolved_allowed_proof_algorithms();
        // Hot-path-friendly: no allocation when the caller didn't override.
        assert!(matches!(resolved, Cow::Borrowed(_)));
        assert_eq!(&*resolved, crate::dpop::SUPPORTED_DPOP_ALGORITHMS);
    }

    #[test]
    fn resolved_clock_skew_inherits_resource_default() {
        let opts = InboundDPoPOptions::default();
        assert_eq!(opts.resolved_clock_skew_seconds(60), 60);
        let opts = opts.with_clock_skew_seconds(10);
        assert_eq!(opts.resolved_clock_skew_seconds(60), 10);
    }

    #[test]
    fn resolved_max_proof_age_inherits_resource_default() {
        let opts = InboundDPoPOptions::default();
        assert_eq!(opts.resolved_max_proof_age_seconds(600), 600);
        let opts = opts.with_max_proof_age_seconds(120);
        assert_eq!(opts.resolved_max_proof_age_seconds(600), 120);
    }
}
