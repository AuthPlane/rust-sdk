use std::sync::Arc;

use reqwest::Client;

use crate::auth::AuthplaneAuth;
use crate::cache::DocumentFetcherFn;
use crate::cache::{
    DocumentFetcher, FetchResult, JwksCache, MetadataCache, MetadataChangeCallback, TokenCache,
};
use crate::circuit_breaker::CircuitBreaker;
use crate::client_builder::AuthplaneClientBuilder;
use crate::dpop_provider::DpopProvider;
use crate::errors::transport_error;
use crate::metadata::{AuthorizationServerMetadata, build_metadata_url};
use crate::metadata_binding::{JwksUriCell, MetadataBinding};
use crate::oauth::{IntrospectionResponse, TokenExchangeOptions, TokenResponse};
use crate::prm::{ProtectedResourceMetadata, build_prm};
use crate::resource::{AuthplaneResource, ResourceOptions};
use crate::transport::{build_http_client, validate_fetch_url};
use crate::{AuthplaneError, FetchSettings};

/// Internal runtime configuration assembled by [`AuthplaneClientBuilder`].
#[derive(Clone)]
pub(crate) struct ClientRuntimeConfig {
    pub jwks_refresh_seconds: u64,
    pub metadata_refresh_seconds: u64,
    pub cache_ttl_buffer_seconds: f64,
    pub default_token_ttl_seconds: f64,
    pub circuit_breaker_threshold: u32,
    pub circuit_breaker_cooldown_seconds: f64,
    pub dpop_provider: Option<Arc<DpopProvider>>,
    pub auth_provider: Option<Arc<dyn crate::auth_provider::AuthProvider>>,
    pub on_metadata_change: Option<MetadataChangeCallback>,
}

impl ClientRuntimeConfig {
    fn defaults() -> Self {
        Self {
            jwks_refresh_seconds: AuthplaneClientBuilder::DEFAULT_JWKS_REFRESH_SECONDS,
            metadata_refresh_seconds: AuthplaneClientBuilder::DEFAULT_METADATA_REFRESH_SECONDS,
            cache_ttl_buffer_seconds: TokenCache::DEFAULT_TTL_BUFFER_SECONDS,
            default_token_ttl_seconds: TokenCache::DEFAULT_TTL_SECONDS,
            circuit_breaker_threshold: CircuitBreaker::DEFAULT_THRESHOLD,
            circuit_breaker_cooldown_seconds: CircuitBreaker::DEFAULT_COOLDOWN_SECONDS,
            dpop_provider: None,
            auth_provider: None,
            on_metadata_change: None,
        }
    }
}

/// Authplane client — the entry point for AS discovery, token operations,
/// and resource creation.
///
/// `AuthplaneClient` wires the production-ready runtime the SDK exposes by
/// default:
/// * [`MetadataCache`] backing AS-metadata discovery, with `on_change`
///   callbacks fired on rotation.
/// * [`JwksCache`] with background refresh and `kid`-miss force-refresh
///   semantics, shared with every [`AuthplaneResource`] obtained via
///   [`AuthplaneClient::resource`]. Its fetch target follows the
///   `jwks_uri` published by the AS: once `metadata_refresh_seconds` has
///   elapsed, ordinary verification traffic re-reads the metadata
///   document and rebinds JWKS fetching to the rotated URL (RFC 8414 §2).
/// * [`TokenCache`] caching `client_credentials` results with a TTL buffer.
/// * [`CircuitBreaker`] guarding every outbound AS call.
/// * Optional [`DpopProvider`] supplying outbound DPoP proofs when an
///   operation is called with `Some(&DpopProofOptions)`.
#[derive(Clone)]
pub struct AuthplaneClient {
    issuer: String,
    metadata: AuthorizationServerMetadata,
    metadata_cache: MetadataCache,
    fetch_settings: FetchSettings,
    http: Arc<Client>,
    jwks_cache: Arc<JwksCache>,
    metadata_binding: Arc<MetadataBinding>,
    circuit_breaker: Arc<CircuitBreaker>,
    token_cache: Arc<TokenCache>,
    dpop_provider: Option<Arc<DpopProvider>>,
    auth_provider: Option<Arc<dyn crate::auth_provider::AuthProvider>>,
}

impl std::fmt::Debug for AuthplaneClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthplaneClient")
            .field("issuer", &self.issuer)
            .finish()
    }
}

impl AuthplaneClient {
    /// Build a builder seeded with SDK defaults.
    pub fn builder(issuer: impl Into<String>) -> AuthplaneClientBuilder {
        AuthplaneClientBuilder::new(issuer)
    }

    /// Backwards-compatible constructor.
    ///
    /// Mirrors the previous signature so existing callers keep compiling.
    /// Wires the same defaults as [`AuthplaneClient::builder`].
    pub async fn create(
        issuer: &str,
        fetch_settings: FetchSettings,
    ) -> Result<Self, AuthplaneError> {
        Self::build(
            issuer.to_string(),
            fetch_settings,
            ClientRuntimeConfig::defaults(),
        )
        .await
    }

    /// Convenience constructor using `FetchSettings::default()`.
    pub async fn discover(issuer: &str) -> Result<Self, AuthplaneError> {
        Self::create(issuer, FetchSettings::default()).await
    }

    /// Build path used by the public constructors and the builder.
    pub(crate) async fn build(
        issuer: String,
        fetch_settings: FetchSettings,
        runtime: ClientRuntimeConfig,
    ) -> Result<Self, AuthplaneError> {
        let http = Arc::new(build_http_client(&fetch_settings)?);
        let normalized_issuer = crate::errors::normalize_issuer(&issuer).to_string();

        // Metadata cache (one fetch happens during validation below; the
        // returned document is then reused so we do not re-hit the AS).
        let metadata_url = build_metadata_url(&normalized_issuer)?;
        validate_fetch_url(
            &metadata_url,
            &fetch_settings,
            "authorization server metadata URL",
        )?;
        let metadata_fetcher = DocumentFetcher::with_client(
            metadata_url.clone(),
            "metadata",
            fetch_settings.clone(),
            DocumentFetcher::DEFAULT_METADATA_MAX_BYTES,
            http.clone(),
        );
        let metadata_fetcher_fn = fetcher_to_fn(metadata_fetcher);
        let metadata_cache = MetadataCache::new(
            metadata_fetcher_fn,
            normalized_issuer.clone(),
            fetch_settings.clone(),
            runtime.metadata_refresh_seconds,
            runtime.on_metadata_change.clone(),
        );

        let metadata_value = metadata_cache.get_metadata().await?;
        let metadata: AuthorizationServerMetadata = serde_json::from_value(metadata_value.clone())
            .map_err(|error| transport_error(&error.to_string()))?;
        metadata.validate(&normalized_issuer, &fetch_settings)?;

        // JWKS cache (primed lazily on first verifier use). The unified
        // `fetch_settings` governs both metadata and JWKS document fetches
        // (RFC 8414 / RFC 7517 — same threat profile).
        //
        // The fetch target is held in a shared cell instead of being baked
        // into the fetcher, so `MetadataBinding` can follow a `jwks_uri`
        // rotation without rebuilding a cache that resources already hold.
        let jwks_uri: JwksUriCell = Arc::new(std::sync::RwLock::new(metadata.jwks_uri.clone()));
        let jwks_fetcher_fn =
            rebindable_jwks_fetcher(jwks_uri.clone(), fetch_settings.clone(), http.clone());
        let jwks_cache = Arc::new(JwksCache::new(
            jwks_fetcher_fn,
            runtime.jwks_refresh_seconds,
        ));
        let metadata_binding = Arc::new(MetadataBinding::new(
            metadata_cache.clone(),
            jwks_cache.clone(),
            jwks_uri,
            normalized_issuer.clone(),
            fetch_settings.clone(),
            runtime.metadata_refresh_seconds,
        ));

        let circuit_breaker = Arc::new(CircuitBreaker::with_config(
            runtime.circuit_breaker_threshold,
            runtime.circuit_breaker_cooldown_seconds,
        ));
        let token_cache = Arc::new(TokenCache::with_config(
            runtime.cache_ttl_buffer_seconds,
            runtime.default_token_ttl_seconds,
        ));

        Ok(Self {
            issuer: normalized_issuer,
            metadata,
            metadata_cache,
            fetch_settings,
            http,
            jwks_cache,
            metadata_binding,
            circuit_breaker,
            token_cache,
            dpop_provider: runtime.dpop_provider,
            auth_provider: runtime.auth_provider,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// AS metadata as discovered when this client was built.
    ///
    /// This is a snapshot, not a live view: it returns a borrow, so it
    /// cannot hand out a document that a background rotation may replace.
    /// The JWKS fetch target is *not* read from here — it follows the
    /// rotating document (see [`MetadataCache`] and
    /// `metadata_refresh_seconds`). Callers that need the current
    /// endpoints should read them from
    /// [`AuthplaneClient::metadata_cache`], which re-fetches on its own
    /// TTL.
    pub fn metadata(&self) -> &AuthorizationServerMetadata {
        &self.metadata
    }

    /// Shared JWKS cache; passed into [`AuthplaneResource`] so token
    /// verification benefits from background refresh + stale fallback.
    pub fn jwks_cache(&self) -> Arc<JwksCache> {
        self.jwks_cache.clone()
    }

    /// Shared metadata cache.
    pub fn metadata_cache(&self) -> MetadataCache {
        self.metadata_cache.clone()
    }

    /// Token cache for `client_credentials` results.
    pub fn token_cache(&self) -> Arc<TokenCache> {
        self.token_cache.clone()
    }

    /// Circuit breaker guarding outbound AS calls.
    pub fn circuit_breaker(&self) -> Arc<CircuitBreaker> {
        self.circuit_breaker.clone()
    }

    /// Outbound DPoP provider, if configured via the builder.
    pub fn dpop_provider(&self) -> Option<Arc<DpopProvider>> {
        self.dpop_provider.clone()
    }

    /// Stored auth provider, if configured via the builder.
    pub fn auth_provider(&self) -> Option<Arc<dyn crate::auth_provider::AuthProvider>> {
        self.auth_provider.clone()
    }

    /// Fetch settings (HTTPS-only / SSRF / dev-mode policy).
    pub fn fetch_settings(&self) -> &FetchSettings {
        &self.fetch_settings
    }

    pub fn auth(&self) -> AuthplaneAuth {
        AuthplaneAuth::new(
            self.metadata.clone(),
            self.fetch_settings.clone(),
            (*self.http).clone(),
        )
    }

    /// Client-level PRM convenience: emits a Mode-3 (DPoP-unconfigured) document.
    /// Inbound DPoP advertising is per-resource state, so use
    /// [`AuthplaneResource::prm_response`](crate::AuthplaneResource::prm_response)
    /// when serving PRM for a resource that may have `inbound_dpop` configured.
    pub fn prm_response(&self, resource: &str, scopes: &[String]) -> ProtectedResourceMetadata {
        build_prm(&self.issuer, resource, scopes, None, false)
    }

    /// `client_credentials` grant with circuit-breaker + token-cache.
    ///
    /// Pass `Some(&proof_options)` to attach an outbound DPoP proof; `None`
    /// for the plain bearer path. DPoP-bound results bypass the token cache
    /// (each call mints a fresh proof bound to the token endpoint).
    pub async fn client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
        scopes: &[String],
        resources: &[String],
        dpop: Option<&DpopProvider>,
    ) -> Result<TokenResponse, AuthplaneError> {
        self.guarded_client_credentials(client_id, client_secret, scopes, resources, dpop)
            .await
    }

    /// `client_credentials` grant using the stored [`AuthProvider`].
    ///
    /// Returns `Err` if no auth provider was configured via the builder.
    /// The provider's `auth_header()` value is used as the `Authorization`
    /// header for the token request.
    ///
    /// Pass `Some(&proof_options)` to attach an outbound DPoP proof; `None`
    /// for the plain bearer path. DPoP-bound results bypass the token
    /// cache (mirrors [`AuthplaneClient::client_credentials`]).
    ///
    /// [`AuthProvider`]: crate::auth_provider::AuthProvider
    pub async fn client_credentials_stored(
        &self,
        scopes: &[String],
        resources: &[String],
        dpop: Option<&DpopProvider>,
    ) -> Result<TokenResponse, AuthplaneError> {
        let provider = self.auth_provider.as_ref().ok_or_else(|| {
            crate::errors::auth_error(
                "auth_provider_not_configured",
                "no auth provider configured on this client",
            )
        })?;
        let auth_header = provider.auth_header();

        let scope_key = scopes.join(" ");
        let resource_key = resources.join(",");
        let cache_key = format!(
            "cc_stored:{}",
            TokenCache::cache_key(&scope_key, &resource_key)
        );
        if dpop.is_none()
            && let Some(cached) = self.token_cache.get(&cache_key)
        {
            return Ok(cached.into());
        }

        let result = self
            .run_guarded(|| async {
                self.auth()
                    .client_credentials_with_header(&auth_header, scopes, resources, dpop)
                    .await
            })
            .await?;

        if dpop.is_none() {
            self.token_cache.set(
                &cache_key,
                &result.access_token,
                &result.token_type,
                result.expires_in,
                &result.scope,
                result.cnf.as_ref(),
                &result.cnf_jkt,
            );
        }
        Ok(result)
    }

    /// RFC 8693 token exchange (guarded by the circuit breaker).
    /// Pass `Some(&proof_options)` to attach an outbound DPoP proof.
    pub async fn exchange_token(
        &self,
        client_id: &str,
        client_secret: &str,
        options: &TokenExchangeOptions,
        dpop: Option<&DpopProvider>,
    ) -> Result<TokenResponse, AuthplaneError> {
        self.run_guarded(|| async {
            self.auth()
                .exchange_token(client_id, client_secret, options, dpop)
                .await
        })
        .await
    }

    /// RFC 7662 introspection (guarded by the circuit breaker).
    /// Pass `Some(&proof_options)` to attach an outbound DPoP proof.
    pub async fn introspect(
        &self,
        client_id: &str,
        client_secret: &str,
        token: &str,
        dpop: Option<&DpopProvider>,
    ) -> Result<IntrospectionResponse, AuthplaneError> {
        self.run_guarded(|| async {
            self.auth()
                .introspect(client_id, client_secret, token, dpop)
                .await
        })
        .await
    }

    /// RFC 7009 revocation (guarded by the circuit breaker).
    /// Pass `Some(&proof_options)` to attach an outbound DPoP proof.
    pub async fn revoke(
        &self,
        client_id: &str,
        client_secret: &str,
        token: &str,
        dpop: Option<&DpopProvider>,
    ) -> Result<(), AuthplaneError> {
        self.run_guarded(|| async {
            self.auth()
                .revoke(client_id, client_secret, token, dpop)
                .await
        })
        .await
    }

    pub async fn resource(
        &self,
        resource: &str,
        scopes: &[String],
    ) -> Result<AuthplaneResource, crate::VerifierError> {
        self.resource_with_options(resource, scopes, ResourceOptions::default())
            .await
    }

    pub async fn resource_with_options(
        &self,
        resource: &str,
        scopes: &[String],
        options: ResourceOptions,
    ) -> Result<AuthplaneResource, crate::VerifierError> {
        AuthplaneResource::from_parts(
            self.issuer.clone(),
            resource.to_string(),
            scopes.to_vec(),
            self.metadata.clone(),
            self.fetch_settings.clone(),
            options,
            (*self.http).clone(),
            Some(self.jwks_cache.clone()),
            Some(self.metadata_binding.clone()),
            Some(self.circuit_breaker.clone()),
        )
        .await
    }

    /// Build DPoP proof headers for downstream API calls.
    ///
    /// Exposes the configured [`DpopProvider`]'s `build_headers` so
    /// callers can attach a DPoP proof to outbound resource requests.
    /// Returns `Err` if no DPoP provider was configured.
    pub fn dpop_headers(
        &self,
        method: &str,
        url: &str,
        access_token: Option<&str>,
    ) -> Result<Vec<(String, String)>, AuthplaneError> {
        let provider = self.dpop_provider.as_ref().ok_or_else(|| {
            crate::errors::auth_error(
                "dpop_not_configured",
                "no DPoP provider configured on this client",
            )
        })?;
        provider.build_headers(method, url, access_token)
    }

    /// Cancel background refresh tasks held by the metadata + JWKS caches.
    /// Idempotent.
    pub async fn aclose(&self) {
        self.metadata_cache.aclose().await;
        self.jwks_cache.aclose().await;
    }

    async fn guarded_client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
        scopes: &[String],
        resources: &[String],
        dpop: Option<&DpopProvider>,
    ) -> Result<TokenResponse, AuthplaneError> {
        // Cache is keyed by sorted scopes + comma-joined resources.
        let scope_key = scopes.join(" ");
        let resource_key = resources.join(",");
        let cache_key = format!("cc:{}", TokenCache::cache_key(&scope_key, &resource_key));
        if dpop.is_none()
            && let Some(cached) = self.token_cache.get(&cache_key)
        {
            return Ok(cached.into());
        }

        let result = self
            .run_guarded(|| async {
                self.auth()
                    .client_credentials(client_id, client_secret, scopes, resources, dpop)
                    .await
            })
            .await?;

        if dpop.is_none() {
            self.token_cache.set(
                &cache_key,
                &result.access_token,
                &result.token_type,
                result.expires_in,
                &result.scope,
                result.cnf.as_ref(),
                &result.cnf_jkt,
            );
        }
        Ok(result)
    }

    async fn run_guarded<F, Fut, T>(&self, op: F) -> Result<T, AuthplaneError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, AuthplaneError>>,
    {
        if !self.circuit_breaker.allow() {
            return Err(AuthplaneError::CircuitOpen);
        }
        match op().await {
            Ok(value) => {
                self.circuit_breaker.record_success();
                Ok(value)
            }
            Err(error) => {
                if crate::circuit_policy::should_count_failure(&error) {
                    self.circuit_breaker.record_failure();
                }
                Err(error)
            }
        }
    }
}

/// JWKS fetcher that reads its target URL from `jwks_uri` on every fetch.
///
/// [`DocumentFetcher`] pins one URL for its lifetime and [`JwksCache`]
/// owns its fetcher immutably, so following an RFC 8414 `jwks_uri`
/// rotation means resolving the URL per fetch rather than at wiring time.
/// Building the fetcher here is cheap — it clones the settings and the
/// shared HTTP client, and performs no I/O until `fetch()` runs.
fn rebindable_jwks_fetcher(
    jwks_uri: JwksUriCell,
    fetch_settings: FetchSettings,
    http: Arc<Client>,
) -> DocumentFetcherFn {
    Arc::new(move || {
        let url = jwks_uri.read().expect("jwks_uri lock poisoned").clone();
        let fetcher = DocumentFetcher::with_client(
            url,
            "jwks",
            fetch_settings.clone(),
            DocumentFetcher::DEFAULT_JWKS_MAX_BYTES,
            http.clone(),
        );
        Box::pin(async move {
            let result = fetcher.fetch().await?;
            Ok(FetchResult {
                document: result.document,
                expires_at: result.expires_at,
            })
        })
    })
}

fn fetcher_to_fn(fetcher: DocumentFetcher) -> DocumentFetcherFn {
    let fetcher = Arc::new(fetcher);
    Arc::new(move || {
        let fetcher = fetcher.clone();
        Box::pin(async move {
            let result = fetcher.fetch().await?;
            Ok(FetchResult {
                document: result.document,
                expires_at: result.expires_at,
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::AuthplaneClient;
    use crate::transport::build_basic_auth_header;
    use crate::{AuthorizationServerMetadata, FetchSettings};
    use mockito::Server;
    use serde_json::json;

    fn dummy_metadata(issuer: &str) -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: issuer.to_string(),
            jwks_uri: format!("{issuer}/jwks"),
            token_endpoint: Some(format!("{issuer}/token")),
            introspection_endpoint: None,
            revocation_endpoint: None,
        }
    }

    #[test]
    fn basic_auth_percent_encodes_credentials_before_base64() {
        let header = build_basic_auth_header("http://localhost:8080/mcp", "s3cret");
        assert_eq!(
            header,
            "Basic aHR0cCUzQSUyRiUyRmxvY2FsaG9zdCUzQTgwODAlMkZtY3A6czNjcmV0"
        );
    }

    #[test]
    fn discover_uses_secure_default_fetch_settings() {
        let settings = FetchSettings::default();
        assert!(settings.ssrf_protection);
        assert!(!settings.allow_http);
    }

    #[test]
    fn dummy_metadata_round_trip() {
        let meta = dummy_metadata("https://auth.example.com");
        assert_eq!(meta.issuer, "https://auth.example.com");
    }

    #[tokio::test]
    async fn create_loads_metadata_and_normalizes_issuer() {
        let mut server = Server::new_async().await;
        let issuer = server.url();
        let metadata_body = json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
            "token_endpoint": format!("{issuer}/oauth/token"),
            "introspection_endpoint": format!("{issuer}/oauth/introspect"),
            "revocation_endpoint": format!("{issuer}/oauth/revoke")
        });
        let _mock = server
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(metadata_body.to_string())
            .create();

        let client =
            AuthplaneClient::create(&(issuer.clone() + "/"), FetchSettings::from_dev_mode(true))
                .await
                .expect("client should be created");

        assert_eq!(client.issuer(), issuer);
        assert_eq!(
            client.metadata().token_endpoint.as_deref(),
            Some(format!("{issuer}/oauth/token").as_str())
        );
    }

    #[tokio::test]
    async fn create_fails_when_metadata_fetch_returns_error_status() {
        let mut server = Server::new_async().await;
        let _mock = server
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"server_error","error_description":"boom"}"#)
            .create();

        let error = AuthplaneClient::create(&server.url(), FetchSettings::from_dev_mode(true))
            .await
            .expect_err("must fail");
        assert!(
            error.to_string().to_lowercase().contains("metadata")
                || error.to_string().contains("HTTP")
        );
    }

    #[tokio::test]
    async fn token_cache_short_circuits_repeated_client_credentials_calls() {
        let mut server = Server::new_async().await;
        let issuer = server.url();
        let _metadata = server
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "issuer": issuer,
                    "jwks_uri": format!("{issuer}/jwks"),
                    "token_endpoint": format!("{issuer}/oauth/token")
                })
                .to_string(),
            )
            .create();
        // Token endpoint should be hit exactly once even after two calls.
        let token_mock = server
            .mock("POST", "/oauth/token")
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "access_token":"t1",
                    "token_type":"Bearer",
                    "expires_in":3600,
                    "scope":"tools/read"
                })
                .to_string(),
            )
            .create();

        let client = AuthplaneClient::create(&issuer, FetchSettings::from_dev_mode(true))
            .await
            .expect("client");
        let first = client
            .client_credentials(
                "cid",
                "csecret",
                &["tools/read".into()],
                &["https://api".into()],
                None,
            )
            .await
            .expect("first");
        let second = client
            .client_credentials(
                "cid",
                "csecret",
                &["tools/read".into()],
                &["https://api".into()],
                None,
            )
            .await
            .expect("second");
        assert_eq!(first.access_token, second.access_token);
        token_mock.assert();
    }

    #[tokio::test]
    async fn dpop_use_dpop_nonce_retry_is_transparent_to_callers() {
        // RFC 9449 §6.1: a server may return `use_dpop_nonce` plus a
        // `DPoP-Nonce` header on the first DPoP-authenticated request.
        // The SDK must rebuild the proof with the supplied nonce and
        // retry transparently. Previously the four `pub async fn` callers
        // in `oauth.rs` discarded the nonce (`let (_, _, _nonce)`) and
        // surfaced the error to the caller; this test pins the new contract.
        use crate::dpop_provider::DpopProvider;
        use jsonwebtoken::Algorithm;

        let mut server = Server::new_async().await;
        let issuer = server.url();
        let _metadata = server
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "issuer": issuer,
                    "jwks_uri": format!("{issuer}/jwks"),
                    "token_endpoint": format!("{issuer}/oauth/token")
                })
                .to_string(),
            )
            .create();

        // First POST: 400 + DPoP-Nonce header (RFC 9449 §6.1).
        let nonce_mock = server
            .mock("POST", "/oauth/token")
            .expect(1)
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_header("dpop-nonce", "as-issued-nonce")
            .with_body(r#"{"error":"use_dpop_nonce"}"#)
            .create();
        // Second POST (retry with the supplied nonce): 200 success.
        let success_mock = server
            .mock("POST", "/oauth/token")
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "access_token": "dpop-bound-token",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "scope": "tools/read"
                })
                .to_string(),
            )
            .create();

        let client = AuthplaneClient::create(&issuer, FetchSettings::from_dev_mode(true))
            .await
            .expect("client");

        let pem = include_str!("../tests/fixtures/test-private.pem");
        let provider = DpopProvider::from_pem(pem, Algorithm::RS256).expect("provider");

        let response = client
            .client_credentials(
                "cid",
                "csecret",
                &["tools/read".into()],
                &[],
                Some(&provider),
            )
            .await
            .expect("retry should succeed");

        assert_eq!(response.access_token, "dpop-bound-token");
        assert_eq!(response.token_type, "DPoP");
        // Both endpoints must have been hit exactly once — proves the
        // retry happened (not just a silent success on first call).
        nonce_mock.assert();
        success_mock.assert();
        // Provider must have noted the AS-supplied nonce so subsequent
        // requests reuse it (the whole point of `note_nonce`).
        assert_eq!(
            provider
                .current_nonce(&format!("{issuer}/oauth/token"))
                .expect("current_nonce"),
            "as-issued-nonce"
        );
    }

    #[tokio::test]
    async fn revoke_succeeds_on_empty_response_body() {
        // RFC 7009 §2.2: a successful revocation returns 200 with no body.
        // `do_form_post` previously called `response.json()` unconditionally,
        // mapping the resulting EOF/parse error to `transport_error` — so a
        // spec-conformant revoke surfaced as `Err`. Treat an empty body as
        // `{}` so the 2xx path through `revoke_token` returns `Ok(())`.
        let mut server = Server::new_async().await;
        let issuer = server.url();
        let _metadata = server
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "issuer": issuer,
                    "jwks_uri": format!("{issuer}/jwks"),
                    "token_endpoint": format!("{issuer}/oauth/token"),
                    "revocation_endpoint": format!("{issuer}/oauth/revoke")
                })
                .to_string(),
            )
            .create();
        // RFC 7009-conformant revoke response: 200 with no body and no
        // content-type. Pre-fix, `response.json()` rejected this.
        let revoke_mock = server
            .mock("POST", "/oauth/revoke")
            .expect(1)
            .with_status(200)
            .create();

        let client = AuthplaneClient::create(&issuer, FetchSettings::from_dev_mode(true))
            .await
            .expect("client");
        client
            .revoke("cid", "csecret", "tok", None)
            .await
            .expect("revoke must succeed on empty 200 body");
        revoke_mock.assert();
    }

    #[tokio::test]
    async fn circuit_breaker_short_circuits_after_threshold_failures() {
        let mut server = Server::new_async().await;
        let issuer = server.url();
        let _metadata = server
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "issuer": issuer,
                    "jwks_uri": format!("{issuer}/jwks"),
                    "token_endpoint": format!("{issuer}/oauth/token")
                })
                .to_string(),
            )
            .create();
        // Repeated 500s from token endpoint should trip the breaker after
        // threshold=5 failures, then short-circuit subsequent calls.
        let _token = server
            .mock("POST", "/oauth/token")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"server_error"}"#)
            .expect_at_most(5)
            .create();

        let client = AuthplaneClient::builder(&issuer)
            .with_fetch_settings(FetchSettings::from_dev_mode(true))
            .with_circuit_breaker_threshold(5)
            .with_circuit_breaker_cooldown_seconds(60.0)
            .build()
            .await
            .expect("client");

        for _ in 0..5 {
            let _ = client
                .client_credentials("cid", "csecret", &["s".into()], &["r".into()], None)
                .await;
        }
        // 6th call: must short-circuit BEFORE hitting the AS.
        let error = client
            .client_credentials("cid", "csecret", &["s".into()], &["r".into()], None)
            .await
            .expect_err("circuit must short-circuit");
        let msg = error.to_string().to_lowercase();
        assert!(
            msg.contains("circuit"),
            "expected circuit-open error, got {msg}"
        );
    }
}
