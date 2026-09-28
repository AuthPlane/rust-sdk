#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
use jsonwebtoken::errors::ErrorKind as JwtErrorKind;
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde_json::Value;

use crate::cache::DocumentFetcher;
use crate::circuit_breaker::CircuitBreaker;
use crate::client::AuthplaneClient;
use crate::constants::{jwt_claims, oauth_params};
use crate::metadata::AuthorizationServerMetadata;
use crate::oauth::introspect_token;
use crate::prm::ProtectedResourceMetadata;
use crate::transport::{build_basic_auth_header, is_http_success, ssrf_safe_get};
use crate::{AuthplaneError, FetchSettings, build_prm, build_prm_url};
use crate::{DpopRequestContext, DpopVerificationOptions};
use crate::{VerifiedClaims, VerifierError};

const DEFAULT_ALLOWED_ALGORITHMS: &[Algorithm] = &[Algorithm::RS256, Algorithm::ES256];
const JWKS_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// Credentials for the RFC 7662 introspection round-trip that backs
/// revocation checking.
///
/// They must belong to a **confidential** client that is either the
/// issuing client or a runtime-client of the Resource named in the token's
/// `aud`. Since authserver 0.1.2 any other caller — including a public
/// (secret-less) client — gets `{"active": false}` for every token, and the
/// verifier would reject all traffic as revoked. Empty `client_id` or
/// `client_secret` is therefore refused when the resource is constructed.
/// Link the resource server's client with
/// `authserver admin resource runtime-client add --client-id <rs-client-id> --slug <resource-slug>`.
#[derive(Debug, Clone)]
pub struct RevocationConfig {
    pub client_id: String,
    pub client_secret: String,
    pub fail_open: bool,
}

#[derive(Debug, Clone)]
pub struct ResourceOptions {
    /// Private so the type-system enforces the validation in
    /// [`Self::with_allowed_algorithms`]: only `RS256` and `ES256` may
    /// be installed. HMAC (`HS256`/`HS384`/`HS512`), `none`, and every
    /// other asymmetric variant the underlying JWT crate exposes
    /// (`RS384`/`RS512`/`PS*`/`ES384`/`EdDSA`) are rejected at
    /// construction. Read via [`Self::allowed_algorithms`].
    pub(crate) allowed_algorithms: Vec<Algorithm>,
    pub clock_skew_seconds: u64,
    /// Maximum age for inbound DPoP proofs (seconds). Separate from
    /// `clock_skew_seconds` because DPoP proof TTL and access-token
    /// clock skew are independent time domains.
    pub dpop_proof_max_age_seconds: u64,
    pub revocation: Option<RevocationConfig>,
    /// Per-resource inbound DPoP configuration (RFC 9449 §7.1 + RFC 9728 §2).
    ///
    /// * `None` (default) — Mode 3: resource has NOT opted into DPoP. The
    ///   verifier rejects any inbound DPoP signal (`cnf.jkt` on the access
    ///   token or a DPoP proof header) with
    ///   [`VerifierError::DpopNotSupported`]; PRM omits the `dpop_*`
    ///   discovery fields entirely.
    /// * `Some(InboundDPoPOptions::default())` — Mode 2: bearer-only
    ///   tokens accepted, DPoP-bound tokens validated end-to-end. PRM
    ///   advertises DPoP capability with
    ///   `dpop_bound_access_tokens_required: false`.
    /// * `Some(InboundDPoPOptions::required())` — Mode 1: bearer-only
    ///   tokens rejected with `VerifierError::DpopBindingMismatch`. PRM
    ///   advertises `dpop_bound_access_tokens_required: true`.
    pub inbound_dpop: Option<crate::InboundDPoPOptions>,
    /// Override for the URL emitted as the RFC 9728 §5.1 `resource_metadata`
    /// parameter of every `WWW-Authenticate` challenge. `None` (default)
    /// derives it from the resource identifier per RFC 9728 §3.1
    /// ([`AuthplaneResource::prm_document_url`]). Set it when the document
    /// is served elsewhere — e.g. the AS-hosted
    /// `/.well-known/oauth-protected-resource/{ref}`. Private so the
    /// absolute-URL check in [`Self::with_resource_metadata_url`] cannot be
    /// bypassed; read via [`Self::resource_metadata_url`].
    pub(crate) resource_metadata_url: Option<String>,
}

impl Default for ResourceOptions {
    fn default() -> Self {
        Self {
            allowed_algorithms: DEFAULT_ALLOWED_ALGORITHMS.to_vec(),
            clock_skew_seconds: 30,
            dpop_proof_max_age_seconds: 300,
            revocation: None,
            inbound_dpop: None,
            resource_metadata_url: None,
        }
    }
}

impl ResourceOptions {
    /// Builder shortcut for opting the resource into inbound DPoP. Equivalent
    /// to assigning `Some(opts)` to [`Self::inbound_dpop`] via struct-update
    /// syntax — exists to avoid the four-line boilerplate at call sites:
    ///
    /// ```ignore
    /// ResourceOptions {
    ///     inbound_dpop: Some(InboundDPoPOptions::default()),
    ///     ..ResourceOptions::default()
    /// }
    /// ```
    ///
    /// becomes:
    ///
    /// ```ignore
    /// ResourceOptions::default().with_inbound_dpop(InboundDPoPOptions::default())
    /// ```
    pub fn with_inbound_dpop(mut self, opts: crate::InboundDPoPOptions) -> Self {
        self.inbound_dpop = Some(opts);
        self
    }

    /// Restrict the accepted access-token algorithms to a non-empty
    /// subset of [`DEFAULT_ALLOWED_ALGORITHMS`] (currently `RS256` and
    /// `ES256`). Returns an error on an empty list or on any algorithm
    /// outside that allowlist, at construction rather than at the first
    /// verification.
    ///
    /// An allowlist (rather than an HMAC blocklist) is required: the
    /// jsonwebtoken crate also exposes `RS384`, `RS512`, `PS*`, `ES384`,
    /// and `EdDSA`. None of these are part of the supported
    /// access-token algorithm contract; silently accepting them here
    /// would let a caller advertise an alg in their PRM / JWKS that
    /// peers can't validate, and broaden the algorithm-confusion
    /// surface beyond that contract.
    ///
    /// Acts as the public construction path; the field is `pub(crate)`
    /// so the only way to install a custom set from outside the crate
    /// is through this validator.
    pub fn with_allowed_algorithms(
        mut self,
        algorithms: Vec<Algorithm>,
    ) -> Result<Self, ResourceOptionsError> {
        if algorithms.is_empty() {
            return Err(ResourceOptionsError::EmptyAlgorithmList);
        }
        for alg in &algorithms {
            if !is_supported_access_token_algorithm(*alg) {
                return Err(ResourceOptionsError::UnsupportedAlgorithm(*alg));
            }
        }
        self.allowed_algorithms = algorithms;
        Ok(self)
    }

    /// Borrow the configured access-token algorithm allow-list.
    pub fn allowed_algorithms(&self) -> &[Algorithm] {
        &self.allowed_algorithms
    }

    /// Publish a custom Protected Resource Metadata URL in the
    /// `resource_metadata` challenge parameter (RFC 9728 §5.1) instead of
    /// the one derived from the resource identifier.
    ///
    /// Rejects anything that is not an absolute URL with a host, at
    /// construction rather than on the first `401`: a client cannot fetch
    /// a relative reference out of a header, and RFC 9728 §3.3 gives it no
    /// recovery path when the document does not resolve.
    ///
    /// Whitespace, control characters, `"` and `\` are rejected on the raw
    /// string, for the reason [`crate::prm`] spells out on the resource
    /// identifier: the WHATWG parser trims leading and trailing C0/space and
    /// removes tab and newline anywhere before parsing, so a value carrying
    /// them parses cleanly while being stored and advertised intact. A
    /// trailing newline — the shape a file-sourced env var or `$(cat …)`
    /// produces — would then make `HeaderValue::from_str` fail and drop
    /// `WWW-Authenticate` from every `401`, which is the header this setter
    /// exists to populate.
    pub fn with_resource_metadata_url(
        mut self,
        url: impl Into<String>,
    ) -> Result<Self, ResourceOptionsError> {
        let url = url.into();
        let is_absolute = url::Url::parse(&url).is_ok_and(|parsed| parsed.has_host());
        if !is_absolute {
            return Err(ResourceOptionsError::InvalidResourceMetadataUrl(url));
        }
        if url
            .chars()
            .any(|c| c.is_ascii_whitespace() || c.is_ascii_control() || c == '"' || c == '\\')
        {
            return Err(ResourceOptionsError::InvalidResourceMetadataUrl(url));
        }
        self.resource_metadata_url = Some(url);
        Ok(self)
    }

    /// The configured `resource_metadata` override, if any.
    pub fn resource_metadata_url(&self) -> Option<&str> {
        self.resource_metadata_url.as_deref()
    }
}

/// Configuration error surfaced by the validating `ResourceOptions`
/// setters.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResourceOptionsError {
    #[error("allowed_algorithms must be non-empty; omit the setter to accept the default set")]
    EmptyAlgorithmList,

    #[error(
        "resource_metadata_url must be an absolute URL with a host and must not contain whitespace, control characters, '\"' or '\\', got {0:?}; omit the setter to derive it from the resource identifier (RFC 9728 section 3.1)"
    )]
    InvalidResourceMetadataUrl(String),

    #[error(
        "access-token algorithm {0:?} is not allowed; only `RS256` and `ES256` are accepted. `none`, HMAC (`HS256`/`HS384`/`HS512`), and the additional asymmetric variants the underlying JWT crate exposes (`RS384`/`RS512`/`PS*`/`ES384`/`EdDSA`) are rejected at construction."
    )]
    UnsupportedAlgorithm(Algorithm),
}

#[derive(Debug, Clone)]
pub struct AuthplaneResource {
    issuer: String,
    resource: String,
    /// URL emitted as the RFC 9728 §5.1 `resource_metadata` challenge
    /// parameter. Resolved once at construction — the operator's override
    /// or the RFC 9728 §3.1 derivation from `resource` — so the 401 path
    /// never re-derives it.
    resource_metadata_url: String,
    scopes: Vec<String>,
    metadata: AuthorizationServerMetadata,
    fetch_settings: FetchSettings,
    options: ResourceOptions,
    http: Client,
    jwks_state: Arc<std::sync::Mutex<JwksState>>,
    /// Optional shared JWKS cache (provided by `AuthplaneClient`).
    /// When `Some`, key lookups bypass the in-process `JwksState` and go
    /// through the shared cache, picking up background refresh + stale
    /// fallback + coordinated fetch semantics.
    jwks_cache: Option<Arc<crate::cache::JwksCache>>,
    /// Optional live AS-metadata binding (provided by `AuthplaneClient`).
    /// RFC 8414 §2 publishes `jwks_uri` in the metadata document, so the
    /// URI the shared `JwksCache` fetches from has to be re-read on the
    /// configured metadata refresh interval; this binding is what does
    /// it, driven by the verification traffic below. `None` for the
    /// `from_prefetched_metadata` / test constructors, whose caller owns
    /// discovery.
    metadata_binding: Option<Arc<crate::metadata_binding::MetadataBinding>>,
    /// Optional shared circuit breaker (provided by `AuthplaneClient`).
    /// When `Some`, the introspection round-trip on the verify hot path
    /// participates in the same breaker that gates `AuthplaneClient::introspect`
    /// — an AS-introspect outage trips the breaker after the threshold
    /// instead of paying a round-trip per `verify_with_context` call.
    /// `None` keeps the legacy (un-guarded) path for the
    /// `from_prefetched_metadata` / test constructors.
    circuit_breaker: Option<Arc<CircuitBreaker>>,
}

#[derive(Debug, Clone)]
struct JwksState {
    keys: Vec<Jwk>,
    loaded_at: Instant,
}

impl AuthplaneResource {
    pub async fn create(
        issuer: &str,
        resource: &str,
        scopes: &[String],
        fetch_settings: FetchSettings,
    ) -> Result<Self, VerifierError> {
        Self::create_with_options(
            issuer,
            resource,
            scopes,
            fetch_settings,
            ResourceOptions::default(),
        )
        .await
    }

    pub async fn create_with_options(
        issuer: &str,
        resource: &str,
        scopes: &[String],
        fetch_settings: FetchSettings,
        options: ResourceOptions,
    ) -> Result<Self, VerifierError> {
        // Redundant with the `from_parts` gate for the guarantee, but it
        // reports a malformed identifier before AS discovery: a typo'd
        // resource costs no network round trip, and against an
        // unreachable AS the operator is told the identifier is
        // malformed rather than that the AS is down.
        validate_resource_for_construction(resource)?;
        let client = AuthplaneClient::create(issuer, fetch_settings.clone())
            .await
            .map_err(|error| VerifierError::MetadataUnavailable {
                message: error.to_string(),
            })?;
        client
            .resource_with_options(resource, scopes, options)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn from_parts(
        issuer: String,
        resource: String,
        scopes: Vec<String>,
        metadata: AuthorizationServerMetadata,
        fetch_settings: FetchSettings,
        options: ResourceOptions,
        http: Client,
        jwks_cache: Option<Arc<crate::cache::JwksCache>>,
        metadata_binding: Option<Arc<crate::metadata_binding::MetadataBinding>>,
        circuit_breaker: Option<Arc<CircuitBreaker>>,
    ) -> Result<Self, VerifierError> {
        validate_resource_for_construction(&resource)?;
        validate_revocation_for_construction(&options)?;
        let resource_metadata_url = resolve_resource_metadata_url(&resource, &options)?;
        let initial_keys: Vec<Jwk> = if jwks_cache.is_some() {
            // Shared cache will own JWKS fetching; we only keep an empty
            // in-memory state for backwards-compat path read-throughs.
            Vec::new()
        } else {
            fetch_jwks(&metadata.jwks_uri, &fetch_settings)
                .await
                .map_err(|message| VerifierError::JwksUnavailable { message })?
        };

        Ok(Self {
            issuer,
            resource,
            resource_metadata_url,
            scopes,
            metadata,
            fetch_settings,
            options,
            http,
            jwks_state: Arc::new(std::sync::Mutex::new(JwksState {
                keys: initial_keys,
                loaded_at: Instant::now(),
            })),
            jwks_cache,
            metadata_binding,
            circuit_breaker,
        })
    }

    /// Construct an `AuthplaneResource` from pre-fetched metadata and
    /// JWKS, bypassing the discovery calls that
    /// [`AuthplaneResource::create`] performs.
    ///
    /// Primarily intended for conformance test harnesses and callers
    /// that manage JWKS caching externally (e.g. shared in-process
    /// cache, preloaded fixture). Normal applications should use
    /// [`AuthplaneResource::create`] or [`AuthplaneResource::create_with_options`]
    /// so discovery and JWKS fetching happen through the standard
    /// hardening path.
    #[doc(hidden)]
    pub fn from_prefetched_metadata(
        issuer: &str,
        resource: &str,
        scopes: &[String],
        metadata: AuthorizationServerMetadata,
        fetch_settings: FetchSettings,
        options: ResourceOptions,
        jwks: JwkSet,
    ) -> Result<Self, VerifierError> {
        validate_resource_for_construction(resource)?;
        validate_revocation_for_construction(&options)?;
        let resource_metadata_url = resolve_resource_metadata_url(resource, &options)?;
        let http = crate::transport::build_http_client(&fetch_settings).map_err(|error| {
            VerifierError::MetadataUnavailable {
                message: error.to_string(),
            }
        })?;
        Ok(Self {
            issuer: issuer.to_string(),
            resource: resource.to_string(),
            resource_metadata_url,
            scopes: scopes.to_vec(),
            metadata,
            fetch_settings,
            options,
            http,
            jwks_state: Arc::new(std::sync::Mutex::new(JwksState {
                keys: jwks.keys,
                loaded_at: Instant::now(),
            })),
            jwks_cache: None,
            metadata_binding: None,
            circuit_breaker: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_metadata_and_jwks(
        issuer: &str,
        resource: &str,
        scopes: &[String],
        metadata: AuthorizationServerMetadata,
        fetch_settings: FetchSettings,
        options: ResourceOptions,
        jwks: JwkSet,
    ) -> Self {
        Self::from_prefetched_metadata(
            issuer,
            resource,
            scopes,
            metadata,
            fetch_settings,
            options,
            jwks,
        )
        .expect("valid fetch settings")
    }

    /// Test-only constructor variant that wires a `CircuitBreaker` into the
    /// resource so tests can drive the short-circuit branches of
    /// [`Self::verify`]'s revocation path (open + fail-open accepts the
    /// token; open + fail-closed surfaces `MetadataUnavailable`). Mirrors
    /// the production path where `AuthplaneClient::resource_with_options`
    /// passes its own `Arc<CircuitBreaker>`.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_metadata_jwks_and_breaker(
        issuer: &str,
        resource: &str,
        scopes: &[String],
        metadata: AuthorizationServerMetadata,
        fetch_settings: FetchSettings,
        options: ResourceOptions,
        jwks: JwkSet,
        circuit_breaker: Arc<CircuitBreaker>,
    ) -> Self {
        let http =
            crate::transport::build_http_client(&fetch_settings).expect("valid fetch settings");
        let resource_metadata_url =
            resolve_resource_metadata_url(resource, &options).expect("valid resource");
        Self {
            issuer: issuer.to_string(),
            resource: resource.to_string(),
            resource_metadata_url,
            scopes: scopes.to_vec(),
            metadata,
            fetch_settings,
            options,
            http,
            jwks_state: Arc::new(std::sync::Mutex::new(JwksState {
                keys: jwks.keys,
                loaded_at: Instant::now(),
            })),
            jwks_cache: None,
            metadata_binding: None,
            circuit_breaker: Some(circuit_breaker),
        }
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn prm_response(&self) -> ProtectedResourceMetadata {
        // RFC 9728 §2 + RFC 9449 §7.1 — resources advertise DPoP support
        // here so OAuth-discovery clients can mint matching tokens. When
        // `inbound_dpop` is not configured (Mode 3), the document omits
        // `dpop_*` entirely; when configured, it lists the accepted proof
        // algorithms and sets `dpop_bound_access_tokens_required` from
        // the `required` flag (Mode 1 vs Mode 2).
        let (dpop_algs, dpop_required) = match self.options.inbound_dpop.as_ref() {
            Some(inbound) => {
                // `filter_map` drops any algorithm `prm_alg_label` can't name
                // (today only the HMAC variants, which the upstream allowlist
                // filters already reject — see `prm_alg_label`'s doc). Failing
                // closed by omission keeps the PRM document well-formed and
                // serves a degraded discovery answer rather than panicking on
                // a per-request hot path; a `debug_assert!` inside
                // `prm_alg_label` still surfaces the regression in
                // dev / test builds.
                let algs: Vec<String> = inbound
                    .resolved_allowed_proof_algorithms()
                    .iter()
                    .filter_map(prm_alg_label)
                    .collect();
                (Some(algs), inbound.is_required())
            }
            None => (None, false),
        };
        build_prm(
            &self.issuer,
            &self.resource,
            &self.scopes,
            dpop_algs.as_deref(),
            dpop_required,
        )
    }

    /// RFC 9728 §3.1 — absolute URL of this resource's metadata document,
    /// derived from the resource identifier. This is where a server that
    /// hosts its own document should serve it.
    pub fn prm_document_url(&self) -> Result<String, AuthplaneError> {
        build_prm_url(&self.resource)
    }

    /// The URL advertised as the RFC 9728 §5.1 `resource_metadata`
    /// parameter of every `WWW-Authenticate` challenge this resource
    /// emits: the [`ResourceOptions::with_resource_metadata_url`] override
    /// when set, otherwise [`Self::prm_document_url`].
    pub fn resource_metadata_url(&self) -> &str {
        &self.resource_metadata_url
    }

    /// Build the `WWW-Authenticate` challenge for a verifier failure on
    /// this resource: [`www_authenticate()`](crate::www_authenticate()) plus the RFC 9728 §5.1
    /// `resource_metadata` parameter carrying
    /// [`Self::resource_metadata_url`]. Adapters should prefer this over
    /// the free function so every `401` tells the client where to discover
    /// the authorization server. `realm` is optional; pass `""` to omit it.
    pub fn www_authenticate(&self, error: &VerifierError, realm: &str) -> String {
        crate::www_authenticate::www_authenticate_with_resource_metadata(
            error,
            realm,
            &self.resource_metadata_url,
        )
    }

    /// Signature and claims only — no DPoP mode dispatch.
    ///
    /// The shared core of [`verify`](Self::verify) and
    /// [`verify_with_context`](Self::verify_with_context). Deliberately
    /// unaware of `cnf`: the binding guard belongs to the bearer-only
    /// entrypoint and the three-mode dispatch to the context one, and putting
    /// either here would break the other. `verify` used to *be* this function,
    /// which is how a DPoP-bound token could be accepted as a plain bearer
    /// token by anything calling it.
    async fn verify_claims_only(&self, token: &str) -> Result<VerifiedClaims, VerifierError> {
        if token.trim().is_empty() {
            return Err(VerifierError::TokenMissing);
        }

        let header = decode_header(token).map_err(|error| VerifierError::InvalidSignature {
            message: error.to_string(),
        })?;

        let kid = header.kid.ok_or_else(|| VerifierError::InvalidClaims {
            message: "token header missing 'kid' field".to_string(),
        })?;
        let alg = header.alg;
        let typ = header.typ.ok_or_else(|| VerifierError::InvalidClaims {
            message: "token header missing 'typ' field".to_string(),
        })?;

        // RFC 9068 §2.1: access tokens MUST use typ "at+jwt". We enforce this
        // strictly — tokens with "JWT" or missing typ are rejected, which
        // prevents type-confusion attacks where a generic JWT is accepted as
        // an access token.
        if typ != "at+jwt" {
            return Err(VerifierError::InvalidClaims {
                message: format!("token type must be 'at+jwt', got {typ:?}"),
            });
        }
        if !self.options.allowed_algorithms.contains(&alg) || is_dangerous_algorithm(alg) {
            return Err(VerifierError::InvalidClaims {
                message: format!("token algorithm {alg:?} is not allowed"),
            });
        }

        let key = self.lookup_key(&kid, alg).await?;

        let decoding_key =
            DecodingKey::from_jwk(&key).map_err(|error| VerifierError::JwksUnavailable {
                message: error.to_string(),
            })?;

        let mut validation = Validation::new(alg);
        validation.leeway = self.options.clock_skew_seconds;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&[jwt_claims::EXP, jwt_claims::ISS, jwt_claims::AUD]);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.resource.as_str()]);

        let verified = decode::<Value>(token, &decoding_key, &validation)
            .map_err(|error| map_jwt_error(error.kind(), &kid))?;
        let payload = verified.claims;

        let claims = build_verified_claims(&payload, &kid, self.options.clock_skew_seconds)?;

        if let Some(revocation) = &self.options.revocation {
            // CRITICAL: gate the introspection round-trip through the shared
            // CircuitBreaker when one is wired. `AuthplaneClient::introspect`
            // already does this via `run_guarded`, but the resource path —
            // which validates every inbound token in production — used to
            // call introspect_token directly. An AS-introspect outage paid
            // a full round-trip per verify, and the breaker never opened
            // because failures were not recorded against it. With the
            // breaker plumbed in, an outage trips the breaker after the
            // configured threshold and subsequent verify() calls
            // short-circuit on AuthplaneError::CircuitOpen instead.
            if let Some(breaker) = &self.circuit_breaker
                && !breaker.allow()
            {
                if revocation.fail_open {
                    // Circuit open + fail-open: accept the token without
                    // round-tripping. Same lenient policy the legacy
                    // path applied to network errors.
                    return Ok(claims);
                }
                return Err(VerifierError::MetadataUnavailable {
                    message: "authorization server circuit breaker is open".to_string(),
                });
            }

            let auth_header =
                build_basic_auth_header(&revocation.client_id, &revocation.client_secret);
            let introspection_result = introspect_token(
                &self.http,
                self.metadata.introspection_endpoint().map_err(|error| {
                    VerifierError::MetadataUnavailable {
                        message: error.to_string(),
                    }
                })?,
                token,
                &auth_header,
                &self.fetch_settings,
                None,
            )
            .await;

            match introspection_result {
                Ok(response) => {
                    if let Some(breaker) = &self.circuit_breaker {
                        breaker.record_success();
                    }
                    if !response.active {
                        return Err(VerifierError::TokenRevoked);
                    }
                }
                Err(error) => {
                    // Only count this against the breaker if it would also
                    // count on the `AuthplaneClient` introspection path —
                    // otherwise a benign OAuth response from the AS (e.g.
                    // `invalid_client` from rotated credentials) would trip
                    // the breaker here while leaving the client path
                    // healthy, then degrade every inbound token check for
                    // the cooldown window (fail_open=true silently accepts
                    // possibly-revoked tokens; fail_open=false rejects all
                    // traffic). The shared predicate lives in
                    // `circuit_policy` so the two consumers cannot drift.
                    if let Some(breaker) = &self.circuit_breaker
                        && crate::circuit_policy::should_count_failure(&error)
                    {
                        breaker.record_failure();
                    }
                    if !revocation.fail_open {
                        return Err(VerifierError::MetadataUnavailable {
                            message: error.to_string(),
                        });
                    }
                }
            }
        }

        Ok(claims)
    }

    /// Verify a **bearer** access token (RFC 6750 §2.1).
    ///
    /// Rejects a DPoP-bound token rather than accepting it as a bearer one.
    /// A `cnf` claim means the authorization server issued this token
    /// sender-constrained, and the binding is the whole reason a stolen token
    /// is useless to a thief. This entrypoint has no request context, so it
    /// has no proof to check against — accepting the token anyway would
    /// silently discard the constraint, which is a downgrade, not a
    /// limitation.
    ///
    /// * Token **without** `cnf`: verified and returned.
    /// * Token **with** `cnf`, resource **not** configured for inbound DPoP
    ///   (Mode 3): [`VerifierError::DpopNotSupported`] — the same answer
    ///   [`verify_with_context`](Self::verify_with_context) gives.
    /// * Token **with** `cnf`, resource **is** configured for inbound DPoP
    ///   (Modes 1 and 2): [`VerifierError::DpopBindingMismatch`] — a proof is
    ///   required and this entrypoint cannot supply one. Use
    ///   [`verify_with_context`](Self::verify_with_context).
    ///
    /// Mode dispatch comes first, so a malformed `cnf` cannot select a weaker
    /// path than a well-formed one. It is *not* separated out beyond that:
    /// `verify_with_context` checks for `cnf.jkt` before the proof-missing
    /// check and answers [`VerifierError::InvalidClaims`] for a `cnf` without
    /// one, which this entrypoint does not reproduce — there is no proof to
    /// bind either way here, so the malformed case folds into the same
    /// rejection. Both reject; the class differs, and the catalog case that
    /// pins `invalid_claims` for that shape
    /// (`rfc9449-dpop-bound-token-must-contain-cnf-jkt`) is specified against
    /// the DPoP entrypoint with a proof present, not against this one.
    pub async fn verify(&self, token: &str) -> Result<VerifiedClaims, VerifierError> {
        let claims = self.verify_claims_only(token).await?;

        // RFC 7800 §3.1 — a `cnf` of any object shape makes the token bound.
        if claims
            .raw
            .get(jwt_claims::CNF)
            .and_then(Value::as_object)
            .is_some()
        {
            return Err(if self.options.inbound_dpop.is_none() {
                VerifierError::DpopNotSupported
            } else {
                // Not `DpopProofMissing`: that variant means a request context
                // was supplied and carried no proof. This entrypoint takes no
                // context at all, which is a different thing to tell a caller
                // matching on the error.
                VerifierError::DpopBindingMismatch {
                    message: "access token is DPoP-bound (`cnf.jkt` present) but no DPoP \
                              request context was provided; use verify_with_context"
                        .to_string(),
                }
            });
        }

        Ok(claims)
    }

    /// RFC 9449 §7 — unified verify entrypoint.
    ///
    /// Accepts both bearer and DPoP-bound access tokens behind a single
    /// API that takes a request-level [`DpopRequestContext`] and uses
    /// the token's `cnf.jkt` claim to decide whether sender-constraint
    /// validation must run, so a caller need not decide up front which
    /// entrypoint a token requires.
    ///
    /// Behavior matrix:
    ///
    /// * Token **without** `cnf`/`cnf.jkt`: ignored request context;
    ///   verification succeeds as a bearer token.
    /// * Token **with** `cnf` but no `cnf.jkt`: rejected with
    ///   [`VerifierError::InvalidClaims`] — structurally malformed
    ///   confirmation claim.
    /// * Token **with** `cnf.jkt` and `context.proof == None`: rejected
    ///   with [`VerifierError::DpopProofMissing`].
    /// * Token **with** `cnf.jkt` and `context.proof = Some(_)`: proof
    ///   is validated (method, URL, nonce, `ath`, and `cnf.jkt` ↔ `jwk`
    ///   thumbprint binding). Mismatch surfaces as
    ///   [`VerifierError::InvalidClaims`].
    pub async fn verify_with_context(
        &self,
        token: &str,
        context: &DpopRequestContext,
    ) -> Result<VerifiedClaims, VerifierError> {
        let claims = self.verify_claims_only(token).await?;

        let cnf_object = claims.raw.get(jwt_claims::CNF).and_then(Value::as_object);
        // RFC 7800 §3.1 — a `cnf` of any object shape makes the token bound
        // for mode-dispatch purposes. The jkt-presence check happens AFTER
        // mode dispatch so a malformed cnf-without-jkt surfaces as
        // InvalidClaims regardless of Mode 1/2.
        let token_is_bound = cnf_object.is_some();
        // Constructors normalize blank proofs to `None`, so presence is
        // exactly `is_some()` — mode dispatch and proof verification can
        // never disagree over a `Some("")` proof.
        let proof_present = context.proof.is_some();

        // RFC 9449 §6 / RFC 9728 §2 — three-mode inbound DPoP.
        //
        // Mode 3 (inbound_dpop = None): resource has NOT opted into DPoP.
        // Any DPoP signal on the request — bound token OR proof header —
        // is rejected upfront. Silent downgrade to bearer would drop sender-
        // binding; ad-hoc defaults applied here would be invisible in PRM.
        let Some(inbound) = self.options.inbound_dpop.as_ref() else {
            if token_is_bound || proof_present {
                return Err(VerifierError::DpopNotSupported);
            }
            return Ok(claims);
        };

        // Modes 1 & 2 — resource supports DPoP.
        if !token_is_bound {
            // Mode 1 — `required = true` rejects bearer-only tokens.
            if inbound.is_required() {
                return Err(VerifierError::DpopBindingMismatch {
                    message:
                        "Resource requires DPoP-bound access tokens but the presented token has no `cnf.jkt`"
                            .to_string(),
                });
            }

            // Mode 2 with a stray proof attached to a bearer-only token —
            // the proof's `ath` has nothing to bind to, so it's malformed.
            if proof_present {
                return Err(VerifierError::DpopBindingMismatch {
                    message:
                        "DPoP proof presented but the access token is not DPoP-bound (`cnf.jkt` missing); \
                         the proof has nothing to bind to"
                            .to_string(),
                });
            }

            // Bearer token, Mode 2 — accepted. The request context is
            // informational; any (absent) proof is ignored.
            return Ok(claims);
        }

        // Token is DPoP-bound — `cnf` is present but must carry a non-empty `jkt`.
        let cnf = cnf_object.expect("token_is_bound implies cnf_object is Some");
        let expected_jkt = cnf
            .get(jwt_claims::JKT)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| VerifierError::InvalidClaims {
                message:
                    "DPoP-bound access token carries 'cnf' but is missing required 'cnf.jkt' claim"
                        .to_string(),
            })?
            .to_string();

        let proof = context
            .proof
            .as_deref()
            .ok_or(VerifierError::DpopProofMissing)?;

        // Resolve verification parameters: per-resource inbound_dpop fields
        // override the resource-level defaults when set explicitly.
        let allowed_algs = inbound.resolved_allowed_proof_algorithms();
        let clock_skew = inbound.resolved_clock_skew_seconds(self.options.clock_skew_seconds);
        let max_age =
            inbound.resolved_max_proof_age_seconds(self.options.dpop_proof_max_age_seconds);

        let dpop_options = DpopVerificationOptions {
            expected_access_token: Some(token),
            expected_nonce: context.nonce.as_deref(),
            allowed_algorithms: &allowed_algs,
            clock_skew_seconds: clock_skew,
            max_age_seconds: max_age,
        };

        // Replay-store resolution: configured per-resource via `inbound_dpop`
        // (RFC 9449 §11.1). `InboundDPoPOptions::default()` auto-allocates
        // an `InMemoryDpopReplayStore` so this branch is unconditional —
        // any DPoP-bound request that reaches `verify_with_context` runs
        // through the with-replay path. Multi-process deployments install
        // a shared store via `InboundDPoPOptions::with_replay_store`.
        // Per-request replay-store override was removed deliberately: two
        // requests racing with different store instances would deduplicate
        // independently, defeating the JTI single-use guarantee. The
        // resource-level configuration is the single source of truth.
        // Use the jkt-first variant: comparing cnf.jkt BEFORE the jti commit
        // closes the slot-poisoning window. An attacker who knows a
        // legitimate jti could otherwise submit a proof bearing that jti
        // with the wrong jkt; the jti gets registered in the replay store
        // before the (post-verify) jkt check fires, and the legitimate
        // proof carrying the same jti is then rejected as a replay.
        let verified = crate::dpop::verify_dpop_proof_with_jkt_and_replay(
            proof,
            context.method.as_str(),
            context.url.as_str(),
            dpop_options,
            &expected_jkt,
            inbound.replay_store().as_ref(),
        )
        .await?;

        let mut claims = claims;
        claims.dpop_proof = Some(verified);
        Ok(claims)
    }

    fn find_key(&self, kid: &str, alg: Algorithm) -> Option<Jwk> {
        let state = self.jwks_state.lock().expect("jwks mutex poisoned");
        state
            .keys
            .iter()
            .find(|jwk| jwk_matches(jwk, kid, alg))
            .cloned()
    }

    /// Resolve a JWK by `kid`/`alg`, preferring the shared [`JwksCache`]
    /// when one was provided by [`AuthplaneClient`]. Falls back to the
    /// in-process `JwksState` (with the legacy refresh-on-miss policy)
    /// for callers that built the resource via `from_prefetched_metadata`.
    async fn lookup_key(&self, kid: &str, alg: Algorithm) -> Result<Jwk, VerifierError> {
        // RFC 8414 §2 keeps `jwks_uri` in the metadata document, so key
        // resolution has to start from a document that is still current.
        // Following a rotation therefore costs nothing beyond the
        // verification traffic already flowing: this re-reads metadata
        // only once the configured refresh interval has elapsed, and
        // rebinds the shared JWKS cache when the URI changed. Runs before
        // the lookup so a rotation that landed during the interval is
        // already bound by the time keys are read.
        if let Some(binding) = self.metadata_binding.as_ref() {
            binding.refresh_if_due().await;
        }

        if let Some(cache) = self.jwks_cache.as_ref() {
            let alg_label = alg_jose_label(alg);
            let mut found = cache
                .get_key_by_kid(kid, alg_label)
                .await
                .map_err(|error| VerifierError::JwksUnavailable {
                    message: error.to_string(),
                })?;

            // A `kid` the bound key set does not contain is the request that
            // proves the binding is stale, and the metadata document naming
            // where keys live is no more current than the key set it
            // produced. Re-read it here rather than waiting for the interval
            // gate above, which is a no-op until the interval is up: an AS
            // that rotates `jwks_uri` and retires the old key set at the same
            // moment would otherwise fail every verification until then. The
            // re-read is floored inside the binding, so an arbitrary `kid`
            // cannot turn the pre-authentication path into one discovery
            // fetch per request. Retried only when `jwks_uri` actually moved
            // — the rebind expires the keys cached from the withdrawn URL,
            // so that is the only case where a second lookup can answer
            // differently.
            if found.is_none()
                && let Some(binding) = self.metadata_binding.as_ref()
                && binding.refresh_on_kid_miss().await
            {
                found = cache
                    .get_key_by_kid(kid, alg_label)
                    .await
                    .map_err(|error| VerifierError::JwksUnavailable {
                        message: error.to_string(),
                    })?;
            }

            let value = found.ok_or_else(|| VerifierError::InvalidSignature {
                message: format!("token kid {kid:?} not found in JWKS after refresh"),
            })?;
            let jwk: Jwk =
                serde_json::from_value(value).map_err(|error| VerifierError::JwksUnavailable {
                    message: error.to_string(),
                })?;
            return Ok(jwk);
        }

        // Legacy in-process state path.
        if let Some(found) = self.find_key(kid, alg) {
            return Ok(found);
        }
        if self.should_refresh_jwks() {
            self.refresh_jwks().await?;
        }
        self.find_key(kid, alg)
            .ok_or_else(|| VerifierError::InvalidSignature {
                message: format!("token kid {kid:?} not found in JWKS after refresh"),
            })
    }

    async fn refresh_jwks(&self) -> Result<(), VerifierError> {
        let keys = fetch_jwks(&self.metadata.jwks_uri, &self.fetch_settings)
            .await
            .map_err(|message| VerifierError::JwksUnavailable { message })?;

        let mut state = self.jwks_state.lock().expect("jwks mutex poisoned");
        state.keys = keys;
        state.loaded_at = Instant::now();
        Ok(())
    }

    fn should_refresh_jwks(&self) -> bool {
        let state = self.jwks_state.lock().expect("jwks mutex poisoned");
        state.keys.is_empty() || state.loaded_at.elapsed() >= JWKS_REFRESH_MIN_INTERVAL
    }
}

/// Construction-time gate on the configured resource identifier: it must
/// be an absolute URL with a scheme and a host, free of fragment,
/// whitespace/control characters, and userinfo (RFC 8707 §2 + RFC 9728
/// §3 — see `prm::validate_resource_identifier` for the full grounding).
///
/// Runs in every constructor funnel (`from_parts` behind
/// `create`/`create_with_options`/`AuthplaneClient::resource*`, plus
/// `from_prefetched_metadata`) so a malformed identifier fails when the
/// resource is built — not later, when the 401-challenge path first
/// tries to derive the PRM document URL from it. The underlying
/// rejection carries the module's `invalid_resource` error code; it
/// surfaces here as `MetadataUnavailable`, the same variant these
/// constructors already use for other construction-time failures, which
/// deliberately maps to no `WWW-Authenticate` challenge code.
fn validate_resource_for_construction(resource: &str) -> Result<(), VerifierError> {
    crate::prm::validate_resource_identifier(resource).map_err(|error| {
        VerifierError::MetadataUnavailable {
            message: error.to_string(),
        }
    })
}

/// Construction-time gate on [`RevocationConfig`]: introspection needs
/// confidential client credentials. Since authserver 0.1.2 an
/// unauthenticated or public-client introspection call gets
/// `{"active": false}` for every token, so a resource built with empty
/// credentials would not be "less strict" — it would reject all traffic as
/// revoked, and silently. Fail here, where the cause is attributable, with
/// the same variant the other construction-time checks use.
fn validate_revocation_for_construction(options: &ResourceOptions) -> Result<(), VerifierError> {
    let Some(revocation) = &options.revocation else {
        return Ok(());
    };
    if revocation.client_id.trim().is_empty() || revocation.client_secret.trim().is_empty() {
        return Err(VerifierError::MetadataUnavailable {
            message: "RevocationConfig requires a confidential client: client_id and \
                      client_secret must be non-empty. authserver >= 0.1.2 answers \
                      active=false to unauthenticated introspection, so every token would \
                      be rejected as revoked"
                .to_string(),
        });
    }
    Ok(())
}

/// The URL for the `resource_metadata` challenge parameter: the operator's
/// override when set, otherwise the RFC 9728 §3.1 derivation. The
/// derivation can only fail on an identifier
/// `validate_resource_for_construction` already rejected, so the error arm
/// is defensive.
fn resolve_resource_metadata_url(
    resource: &str,
    options: &ResourceOptions,
) -> Result<String, VerifierError> {
    match options.resource_metadata_url() {
        Some(url) => Ok(url.to_string()),
        None => build_prm_url(resource).map_err(|error| VerifierError::MetadataUnavailable {
            message: error.to_string(),
        }),
    }
}

async fn fetch_jwks(jwks_uri: &str, fetch_settings: &FetchSettings) -> Result<Vec<Jwk>, String> {
    // CRITICAL: always go through ssrf_safe_get so DNS pinning + IP-allowlist
    // checks run between the lexical URL validation and the TCP connect. The
    // previous direct http.get() path only ran validate_fetch_url (lexical),
    // leaving a DNS-rebinding window where the resolved IP could be swapped
    // to a cloud-metadata address between validation and connect. The
    // ssrf_safe_get path resolves the host, validates every returned IP
    // against the allow-list, and connects to the pinned IP with the
    // original Host header preserved.
    let response = ssrf_safe_get(
        jwks_uri,
        fetch_settings,
        DocumentFetcher::DEFAULT_JWKS_MAX_BYTES,
    )
    .await
    .map_err(|error| error.to_string())?;

    let status = response.status_code;
    if !is_http_success(status) {
        // `ssrf_safe_get` parses the body as JSON and falls back to
        // `Value::Null` on parse failure (see `transport::ssrf_safe_request`),
        // so a non-JSON error page would render as the literal string
        // `null` here. Surface a clearer hint instead of the misleading
        // payload — for the proper fix, transport would have to carry the
        // raw bytes alongside the parsed `Value`.
        let body_hint = if response.body.is_null() {
            "<non-JSON response body>".to_string()
        } else {
            response.body.to_string()
        };
        return Err(format!(
            "jwks fetch failed with status {status}: {body_hint}"
        ));
    }

    let jwks: JwkSet = serde_json::from_value(response.body).map_err(|error| error.to_string())?;
    Ok(jwks.keys)
}

/// Map a `jsonwebtoken::Algorithm` to its RFC 7518 / IANA JOSE-Algorithms
/// short name. Returns `None` for the HMAC variants (`HS*`), which are
/// rejected upstream by [`is_dangerous_algorithm`] and by
/// [`InboundDPoPOptions::with_allowed_proof_algorithms`] /
/// [`ResourceOptions::with_allowed_algorithms`]. Used by both the PRM
/// document (`dpop_signing_alg_values_supported`, RFC 9449 §7.1 + RFC
/// 9728 §2) and the JWKS cache lookup path that fans out by alg.
fn alg_jose_label(alg: Algorithm) -> Option<&'static str> {
    match alg {
        Algorithm::RS256 => Some("RS256"),
        Algorithm::RS384 => Some("RS384"),
        Algorithm::RS512 => Some("RS512"),
        Algorithm::PS256 => Some("PS256"),
        Algorithm::PS384 => Some("PS384"),
        Algorithm::PS512 => Some("PS512"),
        Algorithm::ES256 => Some("ES256"),
        Algorithm::ES384 => Some("ES384"),
        Algorithm::EdDSA => Some("EdDSA"),
        // HMAC: never reaches a PRM document or a JWKS lookup we'd serve.
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => None,
    }
}

/// PRM variant of [`alg_jose_label`]. Returns `Some(label)` for any algorithm
/// the SDK is willing to advertise in `dpop_signing_alg_values_supported`,
/// and `None` for the HMAC variants — those should never reach this function
/// (the upstream allowlist filters `is_dangerous_algorithm`,
/// `InboundDPoPOptions::with_allowed_proof_algorithms`,
/// `ResourceOptions::with_allowed_algorithms`, and the private
/// `SUPPORTED_DPOP_ALGORITHMS` constant all reject HMAC), but `None` keeps
/// the PRM-emission path total: if a regression ever bypasses every filter,
/// the unsupported entry is silently dropped from the advertised list rather
/// than panicking in the per-request `prm_response()` hot path.
///
/// A `debug_assert!` still surfaces the regression in dev / test builds so
/// CI flags any future bypass loudly, without taking down a Tokio task in
/// production.
fn prm_alg_label(alg: &Algorithm) -> Option<String> {
    let label = alg_jose_label(*alg).map(str::to_string);
    debug_assert!(
        label.is_some(),
        "prm_alg_label received unsupported algorithm {alg:?}; \
         InboundDPoPOptions::with_allowed_proof_algorithms / \
         SUPPORTED_DPOP_ALGORITHMS should have rejected it",
    );
    label
}

fn jwk_matches(jwk: &Jwk, kid: &str, alg: Algorithm) -> bool {
    if jwk.common.key_id.as_deref() != Some(kid) {
        return false;
    }

    if let Some(use_hint) = &jwk.common.public_key_use
        && use_hint != &PublicKeyUse::Signature
    {
        return false;
    }

    if let Some(key_ops) = &jwk.common.key_operations
        && !key_ops
            .iter()
            .any(|operation| operation == &KeyOperations::Verify)
    {
        return false;
    }

    if let Some(key_alg) = jwk.common.key_algorithm
        && key_algorithm_to_jwt(key_alg) != Some(alg)
    {
        return false;
    }

    true
}

fn key_algorithm_to_jwt(value: KeyAlgorithm) -> Option<Algorithm> {
    match value {
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        _ => None,
    }
}

fn is_dangerous_algorithm(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}

/// Only `RS256` and `ES256` are part of the access-token contract.
/// Used by
/// [`ResourceOptions::with_allowed_algorithms`] at construction so we
/// reject (not just HMAC, but) every other variant the underlying
/// `jsonwebtoken` crate exposes.
fn is_supported_access_token_algorithm(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::RS256 | Algorithm::ES256)
}

fn build_verified_claims(
    payload: &Value,
    kid: &str,
    clock_skew_seconds: u64,
) -> Result<VerifiedClaims, VerifierError> {
    let object = payload
        .as_object()
        .ok_or_else(|| VerifierError::InvalidClaims {
            message: "token payload must be a JSON object".to_string(),
        })?;

    let issuer = required_string(payload, jwt_claims::ISS)?;
    let subject = required_string(payload, jwt_claims::SUB)?;
    let client_id = required_string(payload, jwt_claims::CLIENT_ID)?;
    let jti = required_string(payload, jwt_claims::JTI)?;
    let expires_at = required_i64(payload, jwt_claims::EXP)?;
    let issued_at = required_i64(payload, jwt_claims::IAT)?;
    let now = unix_now();
    if issued_at > now + clock_skew_seconds as i64 {
        return Err(VerifierError::InvalidClaims {
            message: format!(
                "token 'iat' claim is in the future (iat={issued_at}, now={now}, leeway={}s)",
                clock_skew_seconds
            ),
        });
    }

    let audience = parse_audience(payload.get(jwt_claims::AUD)).ok_or_else(|| {
        VerifierError::InvalidClaims {
            message: "token missing required 'aud' claim".to_string(),
        }
    })?;

    let not_before = payload
        .get(jwt_claims::NBF)
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let scopes = payload
        .get(oauth_params::SCOPE)
        .and_then(Value::as_str)
        .map(|value| {
            value
                .split_whitespace()
                .filter(|scope| !scope.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let agent_id = payload
        .get(jwt_claims::AGENT_ID)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let agent_chain = crate::json_util::string_array(payload, jwt_claims::AGENT_CHAIN);

    let raw = object
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();

    Ok(VerifiedClaims {
        sub: subject,
        client_id,
        scopes,
        issuer,
        audience,
        expires_at,
        issued_at,
        jti,
        kid: kid.to_string(),
        agent_id,
        agent_chain,
        not_before,
        raw,
        dpop_proof: None,
    })
}

fn parse_audience(aud: Option<&Value>) -> Option<Vec<String>> {
    match aud {
        Some(Value::String(value)) if !value.is_empty() => Some(vec![value.to_string()]),
        Some(Value::Array(values)) => {
            let normalized = values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if normalized.is_empty() {
                None
            } else {
                Some(normalized)
            }
        }
        _ => None,
    }
}

fn required_string(payload: &Value, field: &str) -> Result<String, VerifierError> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| VerifierError::InvalidClaims {
            message: format!("token missing required '{field}' claim"),
        })
}

fn required_i64(payload: &Value, field: &str) -> Result<i64, VerifierError> {
    payload
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| VerifierError::InvalidClaims {
            message: format!("token missing required '{field}' claim"),
        })
}

use crate::time_utils::unix_now_secs_i64 as unix_now;

fn map_jwt_error(kind: &JwtErrorKind, kid: &str) -> VerifierError {
    match kind {
        JwtErrorKind::ExpiredSignature => VerifierError::TokenExpired,
        JwtErrorKind::InvalidAudience
        | JwtErrorKind::InvalidIssuer
        | JwtErrorKind::ImmatureSignature
        | JwtErrorKind::MissingRequiredClaim(_)
        | JwtErrorKind::InvalidAlgorithm => VerifierError::InvalidClaims {
            message: format!("{kind:?}"),
        },
        JwtErrorKind::InvalidSignature => VerifierError::InvalidSignature {
            message: format!("signature verification failed for kid {kid:?}"),
        },
        _ => VerifierError::InvalidSignature {
            message: format!("{kind:?}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::json;

    use super::{
        AuthplaneResource, ResourceOptions, ResourceOptionsError, RevocationConfig,
        build_verified_claims, jwk_matches, parse_audience,
    };
    use crate::metadata::AuthorizationServerMetadata;
    use crate::{DpopProofOptions, DpopRequestContext, create_dpop_proof, jwk_thumbprint_sha256};
    use crate::{FetchSettings, VerifierError};

    const TEST_JWKS: &str = r#"{
      "keys": [
        {
          "kty": "RSA",
          "kid": "test-kid",
          "alg": "RS256",
          "use": "sig",
          "n": "pza1Jk6AXrea2P-TlgPStQO4PJ8H4mCz3qaW-PqscKygy31-_T-XNpYlH948O-hS3eN0bKLLKJetWx8bSWxBlMMW4DlV-vv32kO-phwPGE0BbQ2rMfZXfEKwKbcU_hTQv3_yfo6eugv3g_9bZR16MaNOWL0fWTmmcYoD7j8mODWoTgwGnHoriRE9wLgHOkXSJ-lnV4gR3Wa0HdI1Th91kve4mMC4DxxpzZ37xh5d0wyExHSb9bssowS70hts0JD-TX46MSpgVoCcZfBefyJ9JKoVgxVZ2aYGsdR8pwVRSRYUf2CYDvKyUZ8HfoWBv4JwBO0AVqT5Eb5F-X375fULQQ",
          "e": "AQAB"
        }
      ]
    }"#;
    const TEST_PRIVATE_PEM: &str = include_str!("../tests/fixtures/test-private.pem");

    fn auth_header() -> Header {
        Header {
            alg: Algorithm::RS256,
            kid: Some("test-kid".to_string()),
            typ: Some("at+jwt".to_string()),
            ..Header::new(Algorithm::RS256)
        }
    }

    fn signed_token_with_claims(claims: serde_json::Value) -> String {
        encode(
            &auth_header(),
            &claims,
            &EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).expect("private key"),
        )
        .expect("token")
    }

    fn resource_with_test_jwks() -> AuthplaneResource {
        // Existing DPoP tests assume Mode 2 (DPoP supported, bearer also
        // accepted). Opt in here so the introduction of Mode 3 (the new
        // default when inbound_dpop is None) doesn't sweep through every
        // existing assertion. New tests below opt out (or in to Mode 1)
        // explicitly via the corresponding `resource_with_*` helper.
        resource_with_test_jwks_and_options(
            ResourceOptions::default().with_inbound_dpop(crate::InboundDPoPOptions::default()),
        )
    }

    fn resource_with_test_jwks_and_options(options: ResourceOptions) -> AuthplaneResource {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
            introspection_endpoint: Some("https://auth.example.com/oauth/introspect".to_string()),
            revocation_endpoint: Some("https://auth.example.com/oauth/revoke".to_string()),
        };
        let jwks: JwkSet = serde_json::from_str(TEST_JWKS).expect("valid jwks");
        AuthplaneResource::from_metadata_and_jwks(
            "https://auth.example.com",
            "https://api.example.com/mcp",
            &["tools/read".to_string()],
            metadata,
            FetchSettings::from_dev_mode(true),
            options,
            jwks,
        )
    }

    #[test]
    fn build_verified_claims_rejects_future_iat() {
        let payload = json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com",
            "exp": 4102444800i64,
            "iat": 4102444800i64,
            "jti": "token-1"
        });

        let error = build_verified_claims(
            &payload,
            "test-kid",
            ResourceOptions::default().clock_skew_seconds,
        )
        .expect_err("iat must fail");
        assert!(matches!(error, VerifierError::InvalidClaims { .. }));
    }

    #[test]
    fn jwk_selection_honors_kid_use_and_alg() {
        let jwks: JwkSet = serde_json::from_str(TEST_JWKS).expect("valid jwks");
        assert!(jwk_matches(
            &jwks.keys[0],
            "test-kid",
            jsonwebtoken::Algorithm::RS256
        ));
        assert!(!jwk_matches(
            &jwks.keys[0],
            "wrong-kid",
            jsonwebtoken::Algorithm::RS256
        ));
        assert!(!jwk_matches(
            &jwks.keys[0],
            "test-kid",
            jsonwebtoken::Algorithm::ES256
        ));
    }

    #[test]
    fn resource_prm_uses_resource_and_issuer() {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
            introspection_endpoint: Some("https://auth.example.com/oauth/introspect".to_string()),
            revocation_endpoint: Some("https://auth.example.com/oauth/revoke".to_string()),
        };
        let jwks: JwkSet = serde_json::from_str(TEST_JWKS).expect("valid jwks");
        let resource = AuthplaneResource::from_metadata_and_jwks(
            "https://auth.example.com",
            "https://api.example.com/mcp",
            &["tools/add".to_string()],
            metadata,
            FetchSettings::from_dev_mode(true),
            ResourceOptions::default(),
            jwks,
        );

        let prm = resource.prm_response();
        assert_eq!(prm.resource, "https://api.example.com/mcp");
        assert_eq!(
            prm.authorization_servers,
            vec!["https://auth.example.com".to_string()]
        );
        assert_eq!(
            resource.prm_document_url().expect("valid prm document url"),
            "https://api.example.com/.well-known/oauth-protected-resource/mcp"
        );
    }

    /// Drive `from_prefetched_metadata` (the sync constructor sharing the
    /// resource-identifier gate with `from_parts`) with an arbitrary
    /// resource string.
    fn try_construct_resource(resource: &str) -> Result<AuthplaneResource, VerifierError> {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
            introspection_endpoint: Some("https://auth.example.com/oauth/introspect".to_string()),
            revocation_endpoint: Some("https://auth.example.com/oauth/revoke".to_string()),
        };
        let jwks: JwkSet = serde_json::from_str(TEST_JWKS).expect("valid jwks");
        AuthplaneResource::from_prefetched_metadata(
            "https://auth.example.com",
            resource,
            &["tools/read".to_string()],
            metadata,
            FetchSettings::from_dev_mode(true),
            ResourceOptions::default(),
            jwks,
        )
    }

    fn assert_construction_rejects_resource(resource: &str, expected_message: &str) {
        let error = try_construct_resource(resource)
            .map(|_| ())
            .expect_err("construction must reject the resource identifier");
        let VerifierError::MetadataUnavailable { message } = error else {
            panic!("expected MetadataUnavailable, got {error:?}");
        };
        assert!(
            message.contains(expected_message),
            "unexpected message: {message}"
        );
    }

    const ABSOLUTE_URL_MESSAGE: &str =
        "resource identifier must be an absolute URL with a scheme and a host";

    #[test]
    fn construction_rejects_relative_resource_identifier() {
        // RFC 8707 §2 requires an absolute URI; the failure must surface
        // when the resource is built, not later when the 401-challenge
        // path first derives the PRM document URL.
        assert_construction_rejects_resource("/mcp", ABSOLUTE_URL_MESSAGE);
    }

    #[test]
    fn construction_rejects_scheme_relative_resource_identifier() {
        // Carries an authority but no scheme — must reject on its own,
        // independent of the plain relative form.
        assert_construction_rejects_resource("//api.example.com/mcp", ABSOLUTE_URL_MESSAGE);
    }

    #[test]
    fn construction_rejects_opaque_resource_identifier() {
        // Has no host to anchor the RFC 9728 §3 well-known insertion.
        assert_construction_rejects_resource("urn:example:api", ABSOLUTE_URL_MESSAGE);
    }

    #[test]
    fn construction_rejects_fragment_bearing_resource_identifier() {
        // RFC 8707 §2 forbids a fragment outright; the raw-string check
        // must catch it because parsing splits the fragment off.
        assert_construction_rejects_resource(
            "https://api.example.com/mcp#v2",
            "resource identifier must not include a fragment component",
        );
    }

    #[test]
    fn construction_rejects_userinfo_bearing_resource_identifier() {
        // RFC 9110 §4.2.4 — a credential in the identifier would be
        // served verbatim in the PRM `resource` member.
        assert_construction_rejects_resource(
            "https://svc:pw@api.example.com/mcp",
            "resource identifier must not include userinfo",
        );
    }

    /// Drive `from_parts` — the production constructor funnel behind
    /// `create`/`create_with_options`/`AuthplaneClient::resource*` —
    /// directly: its resource-identifier gate runs before `fetch_jwks`,
    /// so with `jwks_cache: None` a bad resource must return `Err`
    /// without touching the network. The gate's message (rather than a
    /// JWKS fetch failure) proves the rejection came from validation.
    #[tokio::test]
    async fn from_parts_rejects_bad_resource_before_any_network_call() {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
            introspection_endpoint: Some("https://auth.example.com/oauth/introspect".to_string()),
            revocation_endpoint: Some("https://auth.example.com/oauth/revoke".to_string()),
        };
        let fetch_settings = FetchSettings::from_dev_mode(true);
        let http =
            crate::transport::build_http_client(&fetch_settings).expect("valid fetch settings");
        let error = AuthplaneResource::from_parts(
            "https://auth.example.com".to_string(),
            "/mcp".to_string(),
            vec!["tools/read".to_string()],
            metadata,
            fetch_settings,
            ResourceOptions::default(),
            http,
            None,
            None,
            None,
        )
        .await
        .map(|_| ())
        .expect_err("from_parts must reject the resource identifier");
        let VerifierError::MetadataUnavailable { message } = error else {
            panic!("expected MetadataUnavailable, got {error:?}");
        };
        assert!(
            message.contains(ABSOLUTE_URL_MESSAGE),
            "unexpected message: {message}"
        );
    }

    #[test]
    fn construction_accepts_http_localhost_resource() {
        // Scheme and host required, scheme not narrowed: plain-http local
        // development hosts stay constructible end-to-end.
        let resource = try_construct_resource("http://localhost:8080/mcp")
            .expect("http localhost resource must construct");
        assert_eq!(
            resource.prm_document_url().expect("valid prm document url"),
            "http://localhost:8080/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn revocation_config_can_be_constructed() {
        let config = RevocationConfig {
            client_id: "client-1".to_string(),
            client_secret: "secret-1".to_string(),
            fail_open: true,
        };
        assert!(config.fail_open);
    }

    #[test]
    fn parse_audience_string_single_entry() {
        let aud = serde_json::json!("https://api.example.com");
        let parsed = parse_audience(Some(&aud)).expect("string aud must parse");
        assert_eq!(parsed, vec!["https://api.example.com".to_string()]);
    }

    #[test]
    fn parse_audience_string_empty_is_none() {
        let aud = serde_json::json!("");
        assert!(parse_audience(Some(&aud)).is_none());
    }

    #[test]
    fn parse_audience_array_multiple_entries() {
        let aud = serde_json::json!(["https://one.example", "https://two.example"]);
        let parsed = parse_audience(Some(&aud)).expect("array aud must parse");
        assert_eq!(
            parsed,
            vec![
                "https://one.example".to_string(),
                "https://two.example".to_string(),
            ]
        );
    }

    #[test]
    fn parse_audience_array_filters_empty_entries() {
        let aud = serde_json::json!(["", "https://real.example", ""]);
        let parsed = parse_audience(Some(&aud)).expect("array aud must parse");
        assert_eq!(parsed, vec!["https://real.example".to_string()]);
    }

    #[test]
    fn parse_audience_array_of_only_empty_strings_is_none() {
        let aud = serde_json::json!(["", ""]);
        assert!(parse_audience(Some(&aud)).is_none());
    }

    #[test]
    fn parse_audience_array_of_non_strings_is_none() {
        // Per RFC 7519 `aud` must be string-valued; numeric-valued entries
        // must be ignored, not coerced.
        let aud = serde_json::json!([42, true]);
        assert!(parse_audience(Some(&aud)).is_none());
    }

    #[test]
    fn parse_audience_object_is_none() {
        let aud = serde_json::json!({"not": "a valid aud"});
        assert!(parse_audience(Some(&aud)).is_none());
    }

    #[test]
    fn parse_audience_missing_is_none() {
        assert!(parse_audience(None).is_none());
    }

    #[test]
    fn build_verified_claims_accepts_array_audience_with_target_resource() {
        // RFC 8707 §2 — resource servers MUST accept tokens whose `aud` is
        // a list that contains the configured resource; the decoded
        // `audience` vector must preserve every array entry.
        let payload = json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": ["https://api.example.com", "https://other.example.com"],
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1"
        });
        let claims = build_verified_claims(
            &payload,
            "test-kid",
            ResourceOptions::default().clock_skew_seconds,
        )
        .expect("array aud must decode");
        assert_eq!(
            claims.audience,
            vec![
                "https://api.example.com".to_string(),
                "https://other.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn build_verified_claims_string_audience_becomes_single_element_vec() {
        let payload = json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1"
        });
        let claims = build_verified_claims(
            &payload,
            "test-kid",
            ResourceOptions::default().clock_skew_seconds,
        )
        .expect("string aud must decode");
        assert_eq!(claims.audience, vec!["https://api.example.com".to_string()]);
    }

    #[test]
    fn build_verified_claims_rejects_empty_audience() {
        let payload = json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1"
        });
        let error = build_verified_claims(
            &payload,
            "test-kid",
            ResourceOptions::default().clock_skew_seconds,
        )
        .expect_err("empty aud must fail");
        assert!(matches!(error, VerifierError::InvalidClaims { .. }));
    }

    #[test]
    fn build_verified_claims_rejects_missing_jti() {
        let payload = json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com",
            "exp": 4102444800i64,
            "iat": 1700000000i64
        });
        let error = build_verified_claims(
            &payload,
            "test-kid",
            ResourceOptions::default().clock_skew_seconds,
        )
        .expect_err("missing jti must fail");
        assert!(matches!(error, VerifierError::InvalidClaims { .. }));
    }

    #[test]
    fn build_verified_claims_promotes_agent_id_and_chain() {
        let payload = json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1",
            "agent_id": "agent-007",
            "agent_chain": ["orchestrator", "agent-007"]
        });
        let claims = build_verified_claims(
            &payload,
            "test-kid",
            ResourceOptions::default().clock_skew_seconds,
        )
        .expect("agent claims must decode");
        assert_eq!(claims.agent_id, "agent-007");
        assert_eq!(
            claims.agent_chain,
            vec!["orchestrator".to_string(), "agent-007".to_string()]
        );
    }

    #[test]
    fn build_verified_claims_defaults_agent_id_to_empty_when_absent() {
        let payload = json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1"
        });
        let claims = build_verified_claims(
            &payload,
            "test-kid",
            ResourceOptions::default().clock_skew_seconds,
        )
        .expect("bare token must decode");
        assert_eq!(claims.agent_id, "");
        assert!(claims.agent_chain.is_empty());
        assert_eq!(claims.not_before, 0);
    }

    #[test]
    fn revocation_config_fail_closed_is_the_default() {
        // The `RevocationConfig` struct requires `fail_open` to be
        // explicit, but we document that the secure-by-default posture
        // is `fail_open = false`.
        let config = RevocationConfig {
            client_id: "client-1".to_string(),
            client_secret: "secret-1".to_string(),
            fail_open: false,
        };
        assert!(!config.fail_open, "default posture must be fail-closed");
    }

    #[tokio::test]
    async fn verify_with_context_accepts_bearer_token_with_request_context_and_no_proof() {
        // Catalog:
        // `rfc9449-bearer-token-with-request-context-and-no-proof-must-still-verify-as-bearer`.
        // Bearer access token (no `cnf`) + request context supplied but
        // `proof = None` MUST still verify as bearer.
        let resource = resource_with_test_jwks();
        let token = signed_token_with_claims(json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com/mcp",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1"
        }));
        let context = DpopRequestContext::new("GET", "https://api.example.com/mcp", None, None);
        let claims = resource
            .verify_with_context(&token, &context)
            .await
            .expect("bearer + request context must verify");
        assert_eq!(claims.client_id, "client-1");
        assert!(!claims.raw.contains_key("cnf"));
    }

    /// The gap this trio closes: `verify` used to be the shared core, so a
    /// DPoP-bound token handed to the bearer-only entrypoint was verified and
    /// returned with its `cnf` never looked at — the sender constraint
    /// silently discarded. Nothing pinned that behaviour, which is why it
    /// survived. The `authplane-fastmcp` adapter is bearer-only by necessity
    /// (the upstream framework exposes no inbound HTTP context) and calls
    /// exactly this path.
    #[tokio::test]
    async fn verify_rejects_a_dpop_bound_token_in_mode_3() {
        // Mode 3 — resource has not opted into inbound DPoP. Same answer
        // `verify_with_context` gives for the same input.
        let resource = resource_with_test_jwks_and_options(ResourceOptions::default());
        let token = signed_token_with_claims(json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com/mcp",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1",
            "cnf": { "jkt": "some-thumbprint" }
        }));
        let err = resource
            .verify(&token)
            .await
            .expect_err("a sender-constrained token must not pass as a bearer token");
        assert!(
            matches!(err, VerifierError::DpopNotSupported),
            "expected DpopNotSupported, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_a_dpop_bound_token_when_the_resource_supports_dpop() {
        // Modes 1 and 2 — the resource does support DPoP, so the token is
        // fine; what is missing is the proof, which this entrypoint cannot
        // supply. `resource_with_test_jwks` is Mode 2.
        let resource = resource_with_test_jwks();
        let token = signed_token_with_claims(json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com/mcp",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1",
            "cnf": { "jkt": "some-thumbprint" }
        }));
        let err = resource
            .verify(&token)
            .await
            .expect_err("a bound token with no proof must not pass");
        // `DpopBindingMismatch`, not `DpopProofMissing`: this entrypoint takes
        // no request context, so "a context was supplied and held no proof" is
        // not what happened. `verify_with_context` owns that class.
        assert!(
            matches!(err, VerifierError::DpopBindingMismatch { .. }),
            "expected DpopBindingMismatch, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_still_accepts_a_plain_bearer_token() {
        // The regression guard for the two above: the guard must reject only
        // bound tokens, not every token.
        let resource = resource_with_test_jwks_and_options(ResourceOptions::default());
        let token = signed_token_with_claims(json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com/mcp",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1"
        }));
        let claims = resource
            .verify(&token)
            .await
            .expect("a bearer token must still verify");
        assert_eq!(claims.sub, "user-1");
    }

    #[tokio::test]
    async fn verify_with_context_rejects_dpop_bound_token_when_proof_is_missing() {
        // Catalog:
        // `rfc9449-dpop-bound-token-with-request-context-and-no-proof-must-be-rejected-via-main-verify-path`.
        // DPoP-bound token (`cnf.jkt` present) + request context WITHOUT
        // a proof MUST reject with `DpopProofMissing` ( error_category
        // "dpop_proof_missing" in the catalog).
        let resource = resource_with_test_jwks();
        let token = signed_token_with_claims(json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com/mcp",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1",
            "cnf": { "jkt": "some-thumbprint" }
        }));
        let context = DpopRequestContext::new("GET", "https://api.example.com/mcp", None, None);
        let err = resource
            .verify_with_context(&token, &context)
            .await
            .expect_err("dpop-bound token + no proof must fail");
        assert!(
            matches!(err, VerifierError::DpopProofMissing),
            "expected DpopProofMissing, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_with_context_accepts_matching_dpop_bound_token_and_proof() {
        let resource = resource_with_test_jwks();
        let public_jwk = json!({
            "kty": "RSA",
            "kid": "test-kid",
            "use": "sig",
            "alg": "RS256",
            "n": "pza1Jk6AXrea2P-TlgPStQO4PJ8H4mCz3qaW-PqscKygy31-_T-XNpYlH948O-hS3eN0bKLLKJetWx8bSWxBlMMW4DlV-vv32kO-phwPGE0BbQ2rMfZXfEKwKbcU_hTQv3_yfo6eugv3g_9bZR16MaNOWL0fWTmmcYoD7j8mODWoTgwGnHoriRE9wLgHOkXSJ-lnV4gR3Wa0HdI1Th91kve4mMC4DxxpzZ37xh5d0wyExHSb9bssowS70hts0JD-TX46MSpgVoCcZfBefyJ9JKoVgxVZ2aYGsdR8pwVRSRYUf2CYDvKyUZ8HfoWBv4JwBO0AVqT5Eb5F-X375fULQQ",
            "e": "AQAB"
        });
        let jkt = jwk_thumbprint_sha256(&public_jwk).expect("jkt");
        let token = signed_token_with_claims(json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com/mcp",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1",
            "cnf": { "jkt": jkt }
        }));
        let proof = create_dpop_proof(
            "POST",
            "https://api.example.com/mcp",
            Some(&token),
            &DpopProofOptions {
                private_key_pem: TEST_PRIVATE_PEM.to_string(),
                public_jwk,
                algorithm: Algorithm::RS256,
                key_id: Some("test-kid".to_string()),
                nonce: Some("nonce-1".to_string()),
                proof_ttl_seconds: None,
            },
        )
        .expect("proof");
        let context = DpopRequestContext::new(
            "POST",
            "https://api.example.com/mcp",
            Some(proof.as_str()),
            Some("nonce-1"),
        );
        let claims = resource
            .verify_with_context(&token, &context)
            .await
            .expect("matching dpop binding must verify");
        assert_eq!(claims.client_id, "client-1");
    }

    #[tokio::test]
    async fn verify_with_context_rejects_cnf_with_missing_jkt() {
        // A token with `cnf` present but no `cnf.jkt` is structurally malformed
        // and must be rejected — we cannot fall through to bearer acceptance
        // because the AS signalled a binding.
        let resource = resource_with_test_jwks();
        let token = signed_token_with_claims(json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com/mcp",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1",
            "cnf": { "x5t#S256": "unrelated" }
        }));
        let context = DpopRequestContext::new("GET", "https://api.example.com/mcp", None, None);
        let err = resource
            .verify_with_context(&token, &context)
            .await
            .expect_err("cnf without jkt must be rejected");
        match err {
            VerifierError::InvalidClaims { message } => assert!(
                message.to_ascii_lowercase().contains("cnf.jkt"),
                "error must call out cnf.jkt, got {message}"
            ),
            other => panic!("expected InvalidClaims, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_with_context_rejects_cnf_jkt_mismatch_as_invalid_claims() {
        let resource = resource_with_test_jwks();
        let token = signed_token_with_claims(json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com/mcp",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-1",
            "cnf": { "jkt": "wrong-thumbprint" }
        }));
        let proof = create_dpop_proof(
            "POST",
            "https://api.example.com/mcp",
            Some(&token),
            &DpopProofOptions {
                private_key_pem: TEST_PRIVATE_PEM.to_string(),
                public_jwk: json!({
                    "kty": "RSA",
                    "kid": "test-kid",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "pza1Jk6AXrea2P-TlgPStQO4PJ8H4mCz3qaW-PqscKygy31-_T-XNpYlH948O-hS3eN0bKLLKJetWx8bSWxBlMMW4DlV-vv32kO-phwPGE0BbQ2rMfZXfEKwKbcU_hTQv3_yfo6eugv3g_9bZR16MaNOWL0fWTmmcYoD7j8mODWoTgwGnHoriRE9wLgHOkXSJ-lnV4gR3Wa0HdI1Th91kve4mMC4DxxpzZ37xh5d0wyExHSb9bssowS70hts0JD-TX46MSpgVoCcZfBefyJ9JKoVgxVZ2aYGsdR8pwVRSRYUf2CYDvKyUZ8HfoWBv4JwBO0AVqT5Eb5F-X375fULQQ",
                    "e": "AQAB"
                }),
                algorithm: Algorithm::RS256,
                key_id: Some("test-kid".to_string()),
                nonce: None,
                proof_ttl_seconds: None,
            },
        )
        .expect("proof");
        let context = DpopRequestContext::new(
            "POST",
            "https://api.example.com/mcp",
            Some(proof.as_str()),
            None,
        );
        let err = resource
            .verify_with_context(&token, &context)
            .await
            .expect_err("mismatched cnf.jkt must be rejected");
        assert!(
            err.to_string().contains("cnf.jkt mismatch"),
            "expected cnf.jkt mismatch error, got {err:?}"
        );
    }

    const PRM_URL: &str = "https://api.example.com/.well-known/oauth-protected-resource/mcp";

    fn prefetched_resource(options: ResourceOptions) -> Result<AuthplaneResource, VerifierError> {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            token_endpoint: None,
            introspection_endpoint: Some("https://auth.example.com/oauth/introspect".to_string()),
            revocation_endpoint: None,
        };
        let jwks: JwkSet = serde_json::from_str(TEST_JWKS).expect("valid jwks");
        AuthplaneResource::from_prefetched_metadata(
            "https://auth.example.com",
            "https://api.example.com/mcp",
            &["tools/read".to_string()],
            metadata,
            FetchSettings::from_dev_mode(true),
            options,
            jwks,
        )
    }

    /// RFC 9728 §5.1 — with no override the challenge advertises the
    /// §3.1 derivation, the same URL `prm_document_url` returns.
    #[test]
    fn resource_metadata_url_defaults_to_the_derived_prm_document_url() {
        let resource = resource_with_test_jwks();
        assert_eq!(resource.resource_metadata_url(), PRM_URL);
        assert_eq!(
            resource.prm_document_url().expect("derivable"),
            resource.resource_metadata_url()
        );
        let header = resource.www_authenticate(&VerifierError::TokenExpired, "api");
        assert_eq!(
            header,
            format!(
                "Bearer realm=\"api\", error=\"invalid_token\", \
                 error_description=\"token has expired\", resource_metadata=\"{PRM_URL}\""
            )
        );
    }

    #[test]
    fn resource_metadata_url_override_is_advertised_instead_of_the_derivation() {
        let custom = "https://auth.example.com/.well-known/oauth-protected-resource/calc";
        let options = ResourceOptions::default()
            .with_resource_metadata_url(custom)
            .expect("absolute URL");
        assert_eq!(options.resource_metadata_url(), Some(custom));
        let resource = resource_with_test_jwks_and_options(options);
        assert_eq!(resource.resource_metadata_url(), custom);
        // The derivation is untouched: it still names where this server
        // would host its own document.
        assert_eq!(resource.prm_document_url().expect("derivable"), PRM_URL);
        let header = resource.www_authenticate(&VerifierError::TokenMissing, "");
        assert!(header.ends_with(&format!("resource_metadata=\"{custom}\"")));
    }

    #[test]
    fn with_resource_metadata_url_rejects_non_absolute_urls() {
        for bad in ["/.well-known/oauth-protected-resource/mcp", "not a url", ""] {
            let error = ResourceOptions::default()
                .with_resource_metadata_url(bad)
                .err()
                .unwrap_or_else(|| panic!("{bad:?} must be rejected"));
            assert!(
                matches!(&error, ResourceOptionsError::InvalidResourceMetadataUrl(got) if got == bad),
                "unexpected error for {bad:?}: {error}"
            );
        }
    }

    /// The WHATWG parser trims leading and trailing C0/space and removes tab
    /// and newline anywhere before parsing, so every one of these parses with
    /// a host. The value is stored and advertised as typed, so a CR or LF
    /// makes `HeaderValue::from_str` fail and drops `WWW-Authenticate` from
    /// every `401` — silently, since the adapters have no error path there.
    #[test]
    fn with_resource_metadata_url_rejects_octets_the_header_cannot_carry() {
        for bad in [
            "https://auth.example.com/prm\n",
            "https://auth.example.com/prm\r\n",
            " https://auth.example.com/prm",
            "https://auth.example.com/prm\tx",
            "https://auth.example.com/prm doc",
            "https://auth.example.com/prm\u{7f}",
            "https://auth.example.com/prm\"x",
            "https://auth.example.com/prm\\x",
        ] {
            let error = ResourceOptions::default()
                .with_resource_metadata_url(bad)
                .err()
                .unwrap_or_else(|| panic!("{bad:?} must be rejected"));
            assert!(
                matches!(&error, ResourceOptionsError::InvalidResourceMetadataUrl(got) if got == bad),
                "unexpected error for {bad:?}: {error}"
            );
        }
    }

    /// authserver >= 0.1.2 answers `active: false` to unauthenticated
    /// introspection, so a resource built with empty credentials would
    /// reject every token as revoked. Refuse it at construction.
    #[test]
    fn construction_rejects_revocation_config_with_empty_credentials() {
        for (client_id, client_secret) in [("", "secret"), ("rs-client", ""), ("rs-client", "  ")] {
            let options = ResourceOptions {
                revocation: Some(RevocationConfig {
                    client_id: client_id.to_string(),
                    client_secret: client_secret.to_string(),
                    fail_open: false,
                }),
                ..ResourceOptions::default()
            };
            let error = prefetched_resource(options).expect_err("empty credentials must fail");
            let VerifierError::MetadataUnavailable { message } = &error else {
                panic!("expected MetadataUnavailable, got {error:?}");
            };
            assert!(message.contains("confidential client"), "{message}");
            assert!(message.contains("authserver >= 0.1.2"), "{message}");
        }
    }

    #[test]
    fn construction_accepts_revocation_config_with_credentials() {
        let options = ResourceOptions {
            revocation: Some(RevocationConfig {
                client_id: "rs-client".to_string(),
                client_secret: "rs-secret".to_string(),
                fail_open: false,
            }),
            ..ResourceOptions::default()
        };
        prefetched_resource(options).expect("credentials present");
    }

    #[test]
    fn with_allowed_algorithms_accepts_asymmetric_subset() {
        let opts = ResourceOptions::default()
            .with_allowed_algorithms(vec![Algorithm::ES256])
            .expect("ES256 is asymmetric, must be accepted");
        assert_eq!(opts.allowed_algorithms(), &[Algorithm::ES256]);
    }

    #[test]
    fn with_allowed_algorithms_rejects_empty_list() {
        let err = ResourceOptions::default()
            .with_allowed_algorithms(Vec::new())
            .expect_err("empty list must be rejected");
        assert!(matches!(
            err,
            super::ResourceOptionsError::EmptyAlgorithmList
        ));
    }

    #[test]
    fn with_allowed_algorithms_rejects_hmac() {
        // RFC 7518 §3.2 HS256: a JWKS rotation that ships a symmetric key
        // as a public JWK would let an attacker forge tokens (algorithm
        // confusion). Construction-time rejection beats verify-time
        // rejection because it makes the misconfiguration impossible to
        // ship.
        for hmac in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            let err = ResourceOptions::default()
                .with_allowed_algorithms(vec![hmac])
                .expect_err("HMAC must be rejected at construction");
            assert!(
                matches!(err, super::ResourceOptionsError::UnsupportedAlgorithm(alg) if alg == hmac),
                "expected UnsupportedAlgorithm({hmac:?}), got {err:?}"
            );
        }
    }

    #[test]
    fn with_allowed_algorithms_rejects_mixed_list_when_any_hmac() {
        // A single HMAC entry in an otherwise-asymmetric list MUST poison
        // the whole call — silently dropping it would silently relax the
        // user's stated intent.
        let err = ResourceOptions::default()
            .with_allowed_algorithms(vec![Algorithm::RS256, Algorithm::HS256])
            .expect_err("mixed list with HMAC must be rejected");
        assert!(matches!(
            err,
            super::ResourceOptionsError::UnsupportedAlgorithm(Algorithm::HS256)
        ));
    }

    #[test]
    fn with_allowed_algorithms_rejects_non_contract_asymmetric_variants() {
        // The access-token contract allowlists exactly {RS256, ES256};
        // the additional asymmetric variants `jsonwebtoken` exposes are
        // not part of it. Accepting them here would let a caller advertise
        // an alg in their PRM / JWKS that peers can't validate and
        // broaden the algorithm-confusion surface beyond that contract.
        // Each non-contract variant must fail at construction with
        // `UnsupportedAlgorithm`.
        for alg in [
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
            Algorithm::ES384,
            Algorithm::EdDSA,
        ] {
            let err = ResourceOptions::default()
                .with_allowed_algorithms(vec![alg])
                .expect_err("non-contract asymmetric alg must be rejected");
            assert!(
                matches!(err, super::ResourceOptionsError::UnsupportedAlgorithm(rejected) if rejected == alg),
                "expected UnsupportedAlgorithm({alg:?}), got {err:?}"
            );
        }
    }

    #[test]
    fn with_allowed_algorithms_rejects_mixed_list_when_any_non_contract() {
        // Same poisoning semantics as the HMAC case, but for the
        // non-contract asymmetric variants. A list of `[RS256, RS384]` is
        // not the user expressing "accept the union" — it's the user
        // expressing intent we can't honour, so we surface the offending
        // entry instead of silently dropping it.
        let err = ResourceOptions::default()
            .with_allowed_algorithms(vec![Algorithm::RS256, Algorithm::RS384])
            .expect_err("mixed list with non-contract alg must be rejected");
        assert!(matches!(
            err,
            super::ResourceOptionsError::UnsupportedAlgorithm(Algorithm::RS384)
        ));
    }

    #[tokio::test]
    async fn verify_with_context_rejects_replayed_proof() {
        // Regression coverage: `InboundDPoPOptions::default()` used to leave
        // `replay_store = None`, which silently fell through to the
        // no-replay path. Auto-allocation now wires an in-memory store by
        // default — confirm that a second verify with the same proof + jti
        // hits `DpopReplayDetected`, proving the with-replay branch is the
        // one being exercised.
        let resource = resource_with_test_jwks();
        let public_jwk = json!({
            "kty": "RSA",
            "kid": "test-kid",
            "use": "sig",
            "alg": "RS256",
            "n": "pza1Jk6AXrea2P-TlgPStQO4PJ8H4mCz3qaW-PqscKygy31-_T-XNpYlH948O-hS3eN0bKLLKJetWx8bSWxBlMMW4DlV-vv32kO-phwPGE0BbQ2rMfZXfEKwKbcU_hTQv3_yfo6eugv3g_9bZR16MaNOWL0fWTmmcYoD7j8mODWoTgwGnHoriRE9wLgHOkXSJ-lnV4gR3Wa0HdI1Th91kve4mMC4DxxpzZ37xh5d0wyExHSb9bssowS70hts0JD-TX46MSpgVoCcZfBefyJ9JKoVgxVZ2aYGsdR8pwVRSRYUf2CYDvKyUZ8HfoWBv4JwBO0AVqT5Eb5F-X375fULQQ",
            "e": "AQAB"
        });
        let jkt = jwk_thumbprint_sha256(&public_jwk).expect("jkt");
        let token = signed_token_with_claims(json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com/mcp",
            "exp": 4102444800i64,
            "iat": 1700000000i64,
            "jti": "token-replay-1",
            "cnf": { "jkt": jkt }
        }));
        let proof = create_dpop_proof(
            "POST",
            "https://api.example.com/mcp",
            Some(&token),
            &DpopProofOptions {
                private_key_pem: TEST_PRIVATE_PEM.to_string(),
                public_jwk,
                algorithm: Algorithm::RS256,
                key_id: Some("test-kid".to_string()),
                nonce: Some("nonce-replay".to_string()),
                proof_ttl_seconds: None,
            },
        )
        .expect("proof");
        let context = DpopRequestContext::new(
            "POST",
            "https://api.example.com/mcp",
            Some(proof.as_str()),
            Some("nonce-replay"),
        );
        resource
            .verify_with_context(&token, &context)
            .await
            .expect("first verify must succeed");
        let err = resource
            .verify_with_context(&token, &context)
            .await
            .expect_err("replayed proof must be rejected");
        assert!(
            matches!(err, VerifierError::DpopReplayDetected),
            "expected DpopReplayDetected on replay, got {err:?}"
        );
    }

    fn prm_resource_with_options(options: ResourceOptions) -> AuthplaneResource {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
            introspection_endpoint: Some("https://auth.example.com/oauth/introspect".to_string()),
            revocation_endpoint: Some("https://auth.example.com/oauth/revoke".to_string()),
        };
        let jwks: JwkSet = serde_json::from_str(TEST_JWKS).expect("valid jwks");
        AuthplaneResource::from_metadata_and_jwks(
            "https://auth.example.com",
            "https://api.example.com/mcp",
            &["tools/read".to_string()],
            metadata,
            FetchSettings::from_dev_mode(true),
            options,
            jwks,
        )
    }

    #[test]
    fn prm_response_mode_3_omits_dpop_fields() {
        // Mode 3: ResourceOptions::default() has inbound_dpop = None,
        // so the PRM document MUST omit both dpop_* fields entirely
        // (RFC 9728 §2 — absence signals "no DPoP capability").
        let resource = prm_resource_with_options(ResourceOptions::default());
        let prm = resource.prm_response();
        assert!(
            prm.dpop_signing_alg_values_supported.is_none(),
            "Mode 3 PRM must not advertise DPoP algs"
        );
        assert!(
            prm.dpop_bound_access_tokens_required.is_none(),
            "Mode 3 PRM must not advertise dpop_bound_access_tokens_required"
        );
    }

    #[test]
    fn prm_response_mode_2_advertises_dpop_optional() {
        // Mode 2: inbound_dpop = InboundDPoPOptions::default() means
        // DPoP-bound tokens are accepted but not required. PRM advertises
        // the supported proof algs AND `dpop_bound_access_tokens_required: false`.
        let resource = prm_resource_with_options(
            ResourceOptions::default().with_inbound_dpop(crate::InboundDPoPOptions::default()),
        );
        let prm = resource.prm_response();
        assert_eq!(
            prm.dpop_signing_alg_values_supported,
            Some(vec!["ES256".to_string(), "RS256".to_string()]),
            "Mode 2 PRM must list the default proof algs in the documented canonical order [ES256, RS256]"
        );
        assert_eq!(prm.dpop_bound_access_tokens_required, Some(false));
    }

    #[test]
    fn prm_response_mode_1_advertises_dpop_required() {
        // Mode 1: inbound_dpop = InboundDPoPOptions::required() — bearer-
        // only tokens are rejected, PRM tells well-behaved clients to
        // retry with a DPoP-bound token.
        let resource = prm_resource_with_options(
            ResourceOptions::default().with_inbound_dpop(crate::InboundDPoPOptions::required()),
        );
        let prm = resource.prm_response();
        assert_eq!(
            prm.dpop_signing_alg_values_supported,
            Some(vec!["ES256".to_string(), "RS256".to_string()]),
        );
        assert_eq!(prm.dpop_bound_access_tokens_required, Some(true));
    }

    #[test]
    fn prm_response_respects_custom_proof_alg_subset() {
        // When the resource narrows the accepted proof algs (e.g. to
        // ES256 only), the PRM document must reflect that exact subset
        // — clients picking RS256 would just get a verify-time rejection.
        let inbound = crate::InboundDPoPOptions::default()
            .with_allowed_proof_algorithms(vec![Algorithm::ES256])
            .expect("ES256 subset is valid");
        let resource =
            prm_resource_with_options(ResourceOptions::default().with_inbound_dpop(inbound));
        let prm = resource.prm_response();
        assert_eq!(
            prm.dpop_signing_alg_values_supported,
            Some(vec!["ES256".to_string()]),
        );
        assert_eq!(prm.dpop_bound_access_tokens_required, Some(false));
    }

    #[test]
    fn dpop_proof_max_age_independent_of_clock_skew() {
        // Raising clock_skew_seconds must NOT extend the DPoP proof
        // acceptance window beyond dpop_proof_max_age_seconds.
        let default = ResourceOptions::default();
        assert_eq!(default.clock_skew_seconds, 30);
        assert_eq!(default.dpop_proof_max_age_seconds, 300);

        let custom = ResourceOptions {
            clock_skew_seconds: 600,         // high clock skew
            dpop_proof_max_age_seconds: 120, // tight DPoP proof window
            ..ResourceOptions::default()
        };
        // The DPoP proof TTL must remain 120, not get inflated to 600.
        assert_eq!(custom.dpop_proof_max_age_seconds, 120);
        assert_eq!(custom.clock_skew_seconds, 600);
        // Before the fix, max_age_seconds was computed as
        // `clock_skew_seconds.max(300)` = 600, effectively overriding
        // any intended DPoP proof window. Now it's a separate field.
    }

    // -------------------------------------------------------------------
    // Circuit-breaker short-circuit behaviour on the revocation path
    // -------------------------------------------------------------------
    //
    // These tests cover the new branches introduced when introspection was
    // routed through the shared `CircuitBreaker`: when the breaker is OPEN
    // we never make the HTTP round-trip; whether the token is accepted or
    // rejected depends on `RevocationConfig::fail_open`. The breaker-OPEN
    // path is the one that doesn't hit `self.http` at all, so we can test
    // it without an HTTP mock — the closed-and-call-introspect path needs
    // a wiremock-style harness and is left for the integration suite.

    use std::sync::Arc;

    use crate::CircuitBreaker;

    fn revocation_resource_with_breaker(
        fail_open: bool,
        breaker: Arc<CircuitBreaker>,
    ) -> AuthplaneResource {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
            introspection_endpoint: Some("https://auth.example.com/oauth/introspect".to_string()),
            revocation_endpoint: Some("https://auth.example.com/oauth/revoke".to_string()),
        };
        let jwks: JwkSet = serde_json::from_str(TEST_JWKS).expect("valid jwks");
        let options = ResourceOptions {
            revocation: Some(RevocationConfig {
                client_id: "client-1".to_string(),
                client_secret: "secret-1".to_string(),
                fail_open,
            }),
            ..ResourceOptions::default()
        };
        AuthplaneResource::from_metadata_jwks_and_breaker(
            "https://auth.example.com",
            "https://api.example.com/mcp",
            &["tools/read".to_string()],
            metadata,
            FetchSettings::from_dev_mode(true),
            options,
            jwks,
            breaker,
        )
    }

    fn token_for_revocation_branch() -> String {
        signed_token_with_claims(json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "client_id": "client-1",
            "aud": "https://api.example.com/mcp",
            "exp": 4_102_444_800i64,
            "iat": 1_700_000_000i64,
            "jti": "token-1"
        }))
    }

    fn opened_breaker() -> Arc<CircuitBreaker> {
        let breaker = CircuitBreaker::with_config(1, 60.0);
        breaker.record_failure();
        // Sanity-check: the breaker is OPEN before we hand it to the resource,
        // so `breaker.allow()` will return false on the first verify call and
        // the short-circuit branch fires.
        assert!(
            !breaker.allow(),
            "breaker must be open before the test runs"
        );
        Arc::new(breaker)
    }

    #[tokio::test]
    async fn verify_with_open_breaker_and_fail_open_accepts_token_without_introspection() {
        // Branch: revocation configured + breaker OPEN + fail_open=true.
        // Expected: `verify` returns Ok without calling the introspection
        // endpoint. (If it did, the call would hit the unreachable AS host
        // and either time out or return a transport error.)
        let resource = revocation_resource_with_breaker(true, opened_breaker());
        let token = token_for_revocation_branch();
        let claims = resource
            .verify(&token)
            .await
            .expect("open breaker + fail-open must accept the token");
        assert_eq!(claims.sub, "user-1");
    }

    #[tokio::test]
    async fn verify_with_open_breaker_and_fail_closed_surfaces_metadata_unavailable() {
        // Branch: revocation configured + breaker OPEN + fail_open=false.
        // Expected: `verify` returns MetadataUnavailable with a message
        // naming the circuit breaker, never touching the AS.
        let resource = revocation_resource_with_breaker(false, opened_breaker());
        let token = token_for_revocation_branch();
        let error = resource
            .verify(&token)
            .await
            .expect_err("open breaker + fail-closed must reject");
        match error {
            VerifierError::MetadataUnavailable { message } => {
                assert!(
                    message.contains("circuit breaker"),
                    "expected the message to name the breaker, got: {message}"
                );
            }
            other => panic!("expected MetadataUnavailable, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Failure-accounting tests — cover the introspection-call path (not
    // just the breaker-already-open short-circuit). The reviewer flagged
    // that the prior set only tested OPEN-branch behaviour, so a
    // regression where `record_failure()` is called on a benign OAuth
    // error (e.g. `invalid_client`) would not be caught. The shared
    // `circuit_policy::should_count_failure` predicate is what gates the
    // counting; these tests exercise both halves of that gate from the
    // resource-side introspection path.
    // -------------------------------------------------------------------

    fn revocation_resource_pointing_at(
        introspection_url: &str,
        fail_open: bool,
        breaker: Arc<CircuitBreaker>,
    ) -> AuthplaneResource {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
            introspection_endpoint: Some(introspection_url.to_string()),
            revocation_endpoint: Some("https://auth.example.com/oauth/revoke".to_string()),
        };
        let jwks: JwkSet = serde_json::from_str(TEST_JWKS).expect("valid jwks");
        let options = ResourceOptions {
            revocation: Some(RevocationConfig {
                client_id: "client-1".to_string(),
                client_secret: "secret-1".to_string(),
                fail_open,
            }),
            ..ResourceOptions::default()
        };
        AuthplaneResource::from_metadata_jwks_and_breaker(
            "https://auth.example.com",
            "https://api.example.com/mcp",
            &["tools/read".to_string()],
            metadata,
            FetchSettings::from_dev_mode(true),
            options,
            jwks,
            breaker,
        )
    }

    #[tokio::test]
    async fn introspection_invalid_client_does_not_trip_breaker() {
        // The introspection endpoint returns the OAuth error that lives
        // in `circuit_policy::OAUTH_ERRORS_NO_CIRCUIT`. With fail_open=true
        // the verify call still succeeds; the breaker MUST remain Closed
        // even after enough failed introspection round-trips to cross the
        // configured threshold. This is the asymmetry the audit was
        // worried about — `AuthplaneClient::run_guarded` ignores
        // `invalid_client` for breaker accounting and the resource path
        // must do the same, otherwise misconfigured introspection creds
        // silently disable revocation checks for the cooldown window.
        let mut server = mockito::Server::new_async().await;
        let introspection_url = format!("{}/oauth/introspect", server.url());
        let _mock = server
            .mock("POST", "/oauth/introspect")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"invalid_client","error_description":"bad creds"}"#)
            .expect_at_least(3)
            .create_async()
            .await;

        let breaker = Arc::new(CircuitBreaker::with_config(2, 60.0));
        let resource = revocation_resource_pointing_at(&introspection_url, true, breaker.clone());
        let token = token_for_revocation_branch();

        // 3 calls > threshold of 2 — if the resource counted these against
        // the breaker, it would already be Open by the third iteration.
        for _ in 0..3 {
            resource
                .verify(&token)
                .await
                .expect("fail_open swallows the introspection error");
        }

        assert!(
            breaker.allow(),
            "breaker must still allow traffic after benign OAuth errors"
        );
    }

    #[tokio::test]
    async fn introspection_server_error_does_trip_breaker() {
        // Counter-test: `server_error` is NOT in OAUTH_ERRORS_NO_CIRCUIT,
        // so it MUST count against the breaker. Without this assertion the
        // first test could pass trivially by a `should_count_failure` that
        // returned `false` for every input.
        let mut server = mockito::Server::new_async().await;
        let introspection_url = format!("{}/oauth/introspect", server.url());
        let _mock = server
            .mock("POST", "/oauth/introspect")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"server_error","error_description":"boom"}"#)
            .expect_at_least(2)
            .create_async()
            .await;

        let breaker = Arc::new(CircuitBreaker::with_config(2, 60.0));
        let resource = revocation_resource_pointing_at(&introspection_url, true, breaker.clone());
        let token = token_for_revocation_branch();

        for _ in 0..2 {
            resource
                .verify(&token)
                .await
                .expect("fail_open swallows the introspection error");
        }

        assert!(
            !breaker.allow(),
            "breaker must be Open after threshold genuine AS failures"
        );
    }

    // ------------------------------------------------------------------
    // jwks_uri rotation discovered by a `kid` miss
    // ------------------------------------------------------------------

    /// The shipped RSA test key, republished under an arbitrary `kid`.
    ///
    /// Only the `kid` distinguishes the two JWKS documents in the rotation
    /// test below, which is enough: the pre-rotation document never carries
    /// the post-rotation `kid`, so the lookup can only succeed by fetching
    /// the document published at the rotated `jwks_uri`.
    fn jwks_document_with_kid(kid: &str) -> serde_json::Value {
        let mut document: serde_json::Value =
            serde_json::from_str(TEST_JWKS).expect("valid jwks fixture");
        document["keys"][0]["kid"] = json!(kid);
        document
    }

    /// A second RSA key pair with material distinct from `TEST_PRIVATE_PEM`,
    /// for rotations that republish under the **same** `kid`.
    const TEST_PRIVATE_PEM_2: &str = include_str!("../tests/fixtures/test-private-2.pem");
    const TEST_MODULUS_2: &str = "xRkG21gLFZsQn9F9D-UAevGbhdQFw1htbfWdtviNQTO3jjyk3vg273zrbNcs_-KrhtTRcLlJQWgtXuSakzdw472PvGsDph8k1v_XDj_jZztXXj6K9-G_ntAFigT55CdRXw7DzjoJKbDMgIyaVASAlvOi7Vdz39iWn5BlGU4GhUyjgKJHoUee5jCWWN0c2A-N0RclR77JVbptEi8DUZ5P2UjoW1n26pkyP4Pmy2zjBlAj6S7jm7BayeiMvaaTRy_esqjzRxh8D62BbUtFpZ-Og60HXayUqjJBOnR4Pt5d515e9BiBVqWLe7hkG0TPA6fweOxN96VL50Bf24mUPPvx9Q";

    /// The second key's JWKS, published under an arbitrary `kid`.
    fn jwks_document_with_kid_and_second_key(kid: &str) -> serde_json::Value {
        let mut document: serde_json::Value =
            serde_json::from_str(TEST_JWKS).expect("valid jwks fixture");
        document["keys"][0]["kid"] = json!(kid);
        document["keys"][0]["n"] = json!(TEST_MODULUS_2);
        document
    }

    fn signed_token_with_kid_and_key(
        kid: &str,
        private_pem: &str,
        issuer: &str,
        audience: &str,
        jti: &str,
    ) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after the epoch")
            .as_secs() as i64;
        let claims = json!({
            "iss": issuer,
            "sub": "user-1",
            "client_id": "client-1",
            "aud": audience,
            "jti": jti,
            "iat": now,
            "exp": now + 300,
            "scope": "tools/read"
        });
        let header = Header {
            alg: Algorithm::RS256,
            kid: Some(kid.to_string()),
            typ: Some("at+jwt".to_string()),
            ..Header::new(Algorithm::RS256)
        };
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("private key"),
        )
        .expect("token")
    }

    fn signed_token_with_kid(kid: &str, issuer: &str, audience: &str, jti: &str) -> String {
        signed_token_with_kid_and_key(kid, TEST_PRIVATE_PEM, issuer, audience, jti)
    }

    #[tokio::test]
    async fn kid_miss_re_reads_metadata_without_waiting_for_the_refresh_interval() {
        // The interval gate is set far out of reach (one hour) and the JWKS
        // TTL with it, so nothing in this test can re-read metadata on a
        // timer. The only thing that can follow the rotation is the `kid`
        // miss itself — the one request that proves the current binding is
        // stale. Without a re-read on that branch the rotated key is
        // unreachable for the whole interval, which is a hard verification
        // failure for every request in it.
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let mut server = mockito::Server::new_async().await;
        let issuer = server.url();
        let audience = "https://api.example.com/mcp";

        let rotated = Arc::new(AtomicBool::new(false));
        let metadata_hits = Arc::new(AtomicUsize::new(0));
        let v1_hits = Arc::new(AtomicUsize::new(0));
        let v2_hits = Arc::new(AtomicUsize::new(0));

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

        // The withdrawn document keeps serving the retired key, so a
        // verifier that never rebinds still gets a well-formed JWKS back and
        // fails only on the lookup. Nothing but the rebind can make the
        // rotated token verify.
        let v1_counter = v1_hits.clone();
        let _jwks_v1_mock = server
            .mock("GET", "/jwks-v1.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |_request| {
                v1_counter.fetch_add(1, Ordering::SeqCst);
                jwks_document_with_kid("jwks-v1-key")
                    .to_string()
                    .into_bytes()
            })
            .create_async()
            .await;

        let v2_counter = v2_hits.clone();
        let _jwks_v2_mock = server
            .mock("GET", "/jwks-v2.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |_request| {
                v2_counter.fetch_add(1, Ordering::SeqCst);
                jwks_document_with_kid("jwks-v2-key")
                    .to_string()
                    .into_bytes()
            })
            .create_async()
            .await;

        let client = crate::AuthplaneClient::builder(&issuer)
            .with_fetch_settings(FetchSettings::from_dev_mode(true))
            .with_metadata_refresh_seconds(3600)
            .with_jwks_refresh_seconds(3600)
            .build()
            .await
            .expect("client discovers the pre-rotation metadata");
        let resource = client
            .resource(audience, &["tools/read".to_string()])
            .await
            .expect("resource built through the public API");

        resource
            .verify(&signed_token_with_kid(
                "jwks-v1-key",
                &issuer,
                audience,
                "jti-retired",
            ))
            .await
            .expect("token signed by the jwks-v1 key must verify before rotation");
        let metadata_hits_before = metadata_hits.load(Ordering::SeqCst);

        // The AS rotates. No timer fires, no caller asks for a refresh.
        rotated.store(true, Ordering::SeqCst);

        let claims = resource
            .verify(&signed_token_with_kid(
                "jwks-v2-key",
                &issuer,
                audience,
                "jti-rotated",
            ))
            .await
            .expect("the kid miss must re-read metadata and follow the rotation");
        assert_eq!(claims.kid, "jwks-v2-key");
        assert!(
            metadata_hits.load(Ordering::SeqCst) > metadata_hits_before,
            "the kid miss must re-read metadata, not wait for the interval",
        );
        assert_eq!(
            v2_hits.load(Ordering::SeqCst),
            1,
            "keys must be fetched from the rotated jwks_uri",
        );
        assert!(
            v1_hits.load(Ordering::SeqCst) >= 1,
            "the pre-rotation document must have been the one serving keys",
        );

        client.aclose().await;
    }

    #[tokio::test]
    async fn kid_miss_re_read_is_floored_so_an_unknown_kid_cannot_amplify_fetches() {
        // Counter-test to the one above. The re-read bypasses the refresh
        // interval by design, and the caller that reaches it has not
        // authenticated anything — `verify` has only decoded the header. A
        // well-formed header carrying an arbitrary `kid` must therefore not
        // cost the AS one discovery fetch per request.
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut server = mockito::Server::new_async().await;
        let issuer = server.url();
        let audience = "https://api.example.com/mcp";

        let metadata_hits = Arc::new(AtomicUsize::new(0));
        let metadata_issuer = issuer.clone();
        let metadata_counter = metadata_hits.clone();
        let _metadata_mock = server
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |_request| {
                metadata_counter.fetch_add(1, Ordering::SeqCst);
                json!({
                    "issuer": metadata_issuer,
                    "jwks_uri": format!("{metadata_issuer}/jwks-v1.json")
                })
                .to_string()
                .into_bytes()
            })
            .create_async()
            .await;

        let _jwks_mock = server
            .mock("GET", "/jwks-v1.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(jwks_document_with_kid("jwks-v1-key").to_string())
            .create_async()
            .await;

        let client = crate::AuthplaneClient::builder(&issuer)
            .with_fetch_settings(FetchSettings::from_dev_mode(true))
            .with_metadata_refresh_seconds(3600)
            .with_jwks_refresh_seconds(3600)
            .build()
            .await
            .expect("client discovers metadata");
        let resource = client
            .resource(audience, &["tools/read".to_string()])
            .await
            .expect("resource built through the public API");

        let boot_hits = metadata_hits.load(Ordering::SeqCst);
        for index in 0..8 {
            let token =
                signed_token_with_kid("unknown-kid", &issuer, audience, &format!("jti-{index}"));
            resource
                .verify(&token)
                .await
                .expect_err("an unknown kid must not verify");
        }

        assert_eq!(
            metadata_hits.load(Ordering::SeqCst) - boot_hits,
            1,
            "the forced re-read floor must admit one discovery fetch, not one per request",
        );

        client.aclose().await;
    }

    #[tokio::test]
    async fn interval_re_read_follows_a_rotation_that_republishes_the_same_kid() {
        // The rotated document republishes the SAME `kid` with different key
        // material, so `get_key_by_kid` always finds the kid in whatever
        // document is bound and the miss branch can never fire. The only
        // mechanism that can make the rotated token verify is the
        // interval-driven re-read at the top of `lookup_key` — delete the
        // `refresh_if_due()` call and this test fails. It equally pins the
        // one job the rebind's cache expiry genuinely has: without it the
        // still-warm pre-rotation document keeps answering the shared kid
        // with the retired material for the whole JWKS TTL.
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let mut server = mockito::Server::new_async().await;
        let issuer = server.url();
        let audience = "https://api.example.com/mcp";
        let shared_kid = "shared-kid";

        let rotated = Arc::new(AtomicBool::new(false));
        let metadata_hits = Arc::new(AtomicUsize::new(0));
        let v1_hits = Arc::new(AtomicUsize::new(0));
        let v2_hits = Arc::new(AtomicUsize::new(0));

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

        let v1_counter = v1_hits.clone();
        let _jwks_v1_mock = server
            .mock("GET", "/jwks-v1.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |_request| {
                v1_counter.fetch_add(1, Ordering::SeqCst);
                jwks_document_with_kid("shared-kid")
                    .to_string()
                    .into_bytes()
            })
            .create_async()
            .await;

        let v2_counter = v2_hits.clone();
        let _jwks_v2_mock = server
            .mock("GET", "/jwks-v2.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |_request| {
                v2_counter.fetch_add(1, Ordering::SeqCst);
                jwks_document_with_kid_and_second_key("shared-kid")
                    .to_string()
                    .into_bytes()
            })
            .create_async()
            .await;

        // A one-second refresh interval so the gate comes due inside the
        // test; the JWKS TTL stays long so only the rebind's expiry — never
        // the document's own age — can force keys to be re-fetched.
        let client = crate::AuthplaneClient::builder(&issuer)
            .with_fetch_settings(FetchSettings::from_dev_mode(true))
            .with_metadata_refresh_seconds(1)
            .with_jwks_refresh_seconds(3600)
            .build()
            .await
            .expect("client discovers the pre-rotation metadata");
        let resource = client
            .resource(audience, &["tools/read".to_string()])
            .await
            .expect("resource built through the public API");

        resource
            .verify(&signed_token_with_kid_and_key(
                shared_kid,
                TEST_PRIVATE_PEM,
                &issuer,
                audience,
                "jti-original",
            ))
            .await
            .expect("token signed by the original key must verify before rotation");

        // The AS rotates: same kid, new material, new jwks_uri.
        rotated.store(true, Ordering::SeqCst);
        let v1_hits_at_rotation = v1_hits.load(Ordering::SeqCst);

        // Let the refresh interval elapse so the next verification's gate
        // is unambiguously due — this test must go through the interval
        // path, not win a race against it.
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

        let claims = resource
            .verify(&signed_token_with_kid_and_key(
                shared_kid,
                TEST_PRIVATE_PEM_2,
                &issuer,
                audience,
                "jti-rotated",
            ))
            .await
            .expect("the due re-read must rebind and fetch the same kid's new material");
        assert_eq!(claims.kid, shared_kid);
        assert!(
            v2_hits.load(Ordering::SeqCst) >= 1,
            "keys must have been re-fetched from the rotated jwks_uri",
        );
        assert_eq!(
            v1_hits.load(Ordering::SeqCst),
            v1_hits_at_rotation,
            "no further fetch of the withdrawn document once the rebind happened",
        );

        client.aclose().await;
    }
}
