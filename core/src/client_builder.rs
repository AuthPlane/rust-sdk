//! Builder for [`crate::AuthplaneClient`] that exposes the runtime knobs
//! [`crate::AuthplaneClient::create`] configures: cache refresh
//! intervals, circuit-breaker thresholds, token-cache buffer, optional
//! outbound DPoP provider, and a metadata `on_change` hook.
//!
//! Use [`AuthplaneClient::builder`] to obtain a builder pre-seeded with
//! the SDK defaults.

use std::sync::Arc;

use crate::auth_provider::AuthProvider;
use crate::cache::MetadataChangeCallback;
use crate::circuit_breaker::CircuitBreaker;
use crate::client::{AuthplaneClient, ClientRuntimeConfig};
use crate::dpop_provider::DpopProvider;
use crate::{AuthplaneError, FetchSettings};

/// Builder for [`AuthplaneClient`].
///
/// Every knob defaults to the value [`AuthplaneClient::create`] uses, so a
/// builder built without further configuration produces a client identical to
/// one obtained from that constructor.
#[derive(Clone)]
pub struct AuthplaneClientBuilder {
    issuer: String,
    fetch_settings: FetchSettings,
    jwks_refresh_seconds: u64,
    metadata_refresh_seconds: u64,
    cache_ttl_buffer_seconds: f64,
    default_token_ttl_seconds: f64,
    circuit_breaker_threshold: u32,
    circuit_breaker_cooldown_seconds: f64,
    dpop_provider: Option<Arc<DpopProvider>>,
    auth_provider: Option<Arc<dyn AuthProvider>>,
    on_metadata_change: Option<MetadataChangeCallback>,
}

impl AuthplaneClientBuilder {
    /// Default JWKS refresh interval.
    pub const DEFAULT_JWKS_REFRESH_SECONDS: u64 = 300;
    /// Default AS-metadata refresh interval.
    pub const DEFAULT_METADATA_REFRESH_SECONDS: u64 = 3600;

    /// Build a builder seeded with SDK defaults.
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            fetch_settings: FetchSettings::default(),
            jwks_refresh_seconds: Self::DEFAULT_JWKS_REFRESH_SECONDS,
            metadata_refresh_seconds: Self::DEFAULT_METADATA_REFRESH_SECONDS,
            cache_ttl_buffer_seconds: crate::cache::TokenCache::DEFAULT_TTL_BUFFER_SECONDS,
            default_token_ttl_seconds: crate::cache::TokenCache::DEFAULT_TTL_SECONDS,
            circuit_breaker_threshold: CircuitBreaker::DEFAULT_THRESHOLD,
            circuit_breaker_cooldown_seconds: CircuitBreaker::DEFAULT_COOLDOWN_SECONDS,
            dpop_provider: None,
            auth_provider: None,
            on_metadata_change: None,
        }
    }

    /// Outbound HTTP / SSRF policy. Applied to both AS metadata and JWKS
    /// document fetches — RFC 8414 / RFC 7517 share the same threat profile,
    /// so a single setting governs both.
    pub fn with_fetch_settings(mut self, fetch_settings: FetchSettings) -> Self {
        self.fetch_settings = fetch_settings;
        self
    }

    /// Override the JWKS refresh interval (seconds).
    pub fn with_jwks_refresh_seconds(mut self, seconds: u64) -> Self {
        self.jwks_refresh_seconds = seconds.max(1);
        self
    }

    /// Override the AS-metadata refresh interval (seconds).
    pub fn with_metadata_refresh_seconds(mut self, seconds: u64) -> Self {
        self.metadata_refresh_seconds = seconds.max(1);
        self
    }

    /// Override the token-cache TTL buffer.
    pub fn with_token_cache_ttl_buffer_seconds(mut self, buffer_seconds: f64) -> Self {
        self.cache_ttl_buffer_seconds = buffer_seconds.max(0.0);
        self
    }

    /// Override the fallback token TTL used when the AS does not return one.
    pub fn with_default_token_ttl_seconds(mut self, seconds: f64) -> Self {
        self.default_token_ttl_seconds = seconds.max(0.0);
        self
    }

    /// Override the circuit-breaker threshold.
    pub fn with_circuit_breaker_threshold(mut self, threshold: u32) -> Self {
        self.circuit_breaker_threshold = threshold.max(1);
        self
    }

    /// Override the circuit-breaker cooldown (seconds).
    pub fn with_circuit_breaker_cooldown_seconds(mut self, cooldown_seconds: f64) -> Self {
        self.circuit_breaker_cooldown_seconds = cooldown_seconds.max(0.0);
        self
    }

    /// Store a default auth provider (e.g., [`ClientCredentialsProvider`])
    /// so callers can use methods without passing credentials each time.
    ///
    /// [`ClientCredentialsProvider`]: crate::auth_provider::ClientCredentialsProvider
    pub fn with_auth(mut self, provider: Arc<dyn AuthProvider>) -> Self {
        self.auth_provider = Some(provider);
        self
    }

    /// Wire an outbound DPoP provider so `client_credentials` /
    /// `exchange_token` / `introspect` / `revoke` use a shared signing
    /// key + nonce store when callers pass `Some(&proof_options)`.
    pub fn with_dpop_provider(mut self, provider: Arc<DpopProvider>) -> Self {
        self.dpop_provider = Some(provider);
        self
    }

    /// Register an async callback fired when AS metadata changes (e.g.
    /// `jwks_uri` rotation).
    pub fn with_metadata_change_callback(mut self, callback: MetadataChangeCallback) -> Self {
        self.on_metadata_change = Some(callback);
        self
    }

    /// Build and initialize the [`AuthplaneClient`].
    ///
    /// Performs AS metadata discovery, validates the issuer, primes the
    /// JWKS cache, and returns a fully wired client ready to use.
    pub async fn build(self) -> Result<AuthplaneClient, AuthplaneError> {
        let runtime = ClientRuntimeConfig {
            jwks_refresh_seconds: self.jwks_refresh_seconds,
            metadata_refresh_seconds: self.metadata_refresh_seconds,
            cache_ttl_buffer_seconds: self.cache_ttl_buffer_seconds,
            default_token_ttl_seconds: self.default_token_ttl_seconds,
            circuit_breaker_threshold: self.circuit_breaker_threshold,
            circuit_breaker_cooldown_seconds: self.circuit_breaker_cooldown_seconds,
            dpop_provider: self.dpop_provider,
            auth_provider: self.auth_provider,
            on_metadata_change: self.on_metadata_change,
        };
        AuthplaneClient::build(self.issuer, self.fetch_settings, runtime).await
    }
}
