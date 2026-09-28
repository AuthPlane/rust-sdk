pub mod auth;
pub mod auth_provider;
pub mod cache;
pub mod circuit_breaker;
pub mod circuit_policy;
pub mod client;
pub mod client_builder;
pub mod consent_elicitation;
pub mod constants;
pub mod dpop;
pub mod dpop_provider;
pub mod dpop_replay;
pub mod errors;
pub mod fetch_settings;
pub mod inbound_dpop;
mod json_util;
pub mod metadata;
mod metadata_binding;
pub mod oauth;
pub mod prm;
pub mod resource;
#[doc(hidden)]
pub mod three_mode_dpop_docs;
mod time_utils;
pub mod transport;
pub mod verified_claims;
pub mod www_authenticate;

pub use auth::AuthplaneAuth;
pub use auth_provider::{AuthProvider, ClientCredentialsProvider};
pub use cache::{
    CachedToken, DocumentFetcher, JwksCache, MetadataCache, MetadataChangeCallback, TokenCache,
};
pub use circuit_breaker::{CircuitBreaker, CircuitState};
pub use circuit_policy::should_open_circuit_for_oauth_error;
pub use client::AuthplaneClient;
pub use client_builder::AuthplaneClientBuilder;
pub use consent_elicitation::{
    DEFAULT_CONSENT_MESSAGE, UNKNOWN_SERVICE_ID, UrlElicitationPayload,
    build_url_elicitation_payload,
};
pub use dpop::{
    DpopProofOptions, DpopRequestContext, DpopVerificationOptions, DpopVerificationOptionsOwned,
    SUPPORTED_DPOP_ALGORITHMS, VerifiedDpopProof, create_dpop_proof, dpop_ath,
    jwk_thumbprint_sha256, verify_dpop_proof, verify_dpop_proof_with_jkt_and_replay,
    verify_dpop_proof_with_replay,
};
pub use dpop_provider::{DpopNonceStore, DpopProvider, InMemoryDpopNonceStore};
pub use dpop_replay::{DpopReplayStore, InMemoryDpopReplayStore};
pub use errors::{AuthError, AuthplaneError, ConsentRequiredError, map_oauth_error};
pub use fetch_settings::FetchSettings;
pub use inbound_dpop::{InboundDPoPOptions, InboundDPoPOptionsError};
pub use metadata::{AuthorizationServerMetadata, build_metadata_url};
pub use oauth::{
    GRANT_TYPE_TOKEN_EXCHANGE, IntrospectionResponse, TOKEN_TYPE_ACCESS_TOKEN,
    TokenExchangeOptions, TokenResponse, parse_token_exchange_error, parse_token_response_dpop,
};
pub use prm::{ProtectedResourceMetadata, build_prm, build_prm_url};
pub use resource::{AuthplaneResource, ResourceOptions, ResourceOptionsError, RevocationConfig};
pub use verified_claims::{VerifiedClaims, VerifierError};
pub use www_authenticate::{
    http_status, http_status_for_auth_error, is_dpop_error, www_authenticate,
    www_authenticate_for_missing_credentials, www_authenticate_with_resource_metadata,
};
