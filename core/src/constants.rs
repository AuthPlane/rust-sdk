//! Well-known string constants used across the SDK.
//!
//! Previously these literals (OAuth parameter names, RFC 6750 / 9449
//! error codes, HTTP header names, MIME types, JWT / DPoP / JWK claim
//! names, `.well-known/*` paths, JOSE algorithm identifiers) lived
//! inline in 30+ sites across `core/src/oauth`, `core/src/dpop`,
//! `core/src/errors`, `core/src/www_authenticate`, `core/src/resource`,
//! `core/src/cache`, `core/src/metadata`, `core/src/prm`, and the two
//! adapters. Drift between any two copies — a typo in one site, a
//! missing entry in another — silently breaks OAuth / DPoP interop.
//!
//! New entries land here the first time the same literal is needed in
//! a second site. Existing constants (`GRANT_TYPE_TOKEN_EXCHANGE`,
//! `TOKEN_TYPE_ACCESS_TOKEN` in `oauth`, `SUPPORTED_DPOP_ALGORITHMS`
//! in `dpop`) stay where they are for now to avoid churn; they may
//! migrate here over time.

/// OAuth 2.0 / RFC 8693 form-body parameter names.
pub mod oauth_params {
    pub const GRANT_TYPE: &str = "grant_type";
    pub const SCOPE: &str = "scope";
    pub const RESOURCE: &str = "resource";
    pub const AUDIENCE: &str = "audience";
    pub const TOKEN: &str = "token";
    pub const TOKEN_TYPE_HINT: &str = "token_type_hint";
    pub const SUBJECT_TOKEN: &str = "subject_token";
    pub const SUBJECT_TOKEN_TYPE: &str = "subject_token_type";
    pub const ACTOR_TOKEN: &str = "actor_token";
    pub const ACTOR_TOKEN_TYPE: &str = "actor_token_type";
    pub const REQUESTED_TOKEN_TYPE: &str = "requested_token_type";

    pub const GRANT_TYPE_CLIENT_CREDENTIALS: &str = "client_credentials";
}

/// OAuth 2.0 / RFC 6750 / RFC 7009 / RFC 9449 error codes.
pub mod oauth_errors {
    pub const INVALID_TOKEN: &str = "invalid_token";
    pub const INSUFFICIENT_SCOPE: &str = "insufficient_scope";
    pub const INVALID_DPOP_PROOF: &str = "invalid_dpop_proof";
    pub const USE_DPOP_NONCE: &str = "use_dpop_nonce";
    pub const CONSENT_REQUIRED: &str = "consent_required";
    pub const INTERACTION_REQUIRED: &str = "interaction_required";
    pub const INVALID_GRANT: &str = "invalid_grant";
    pub const INVALID_SCOPE: &str = "invalid_scope";
    pub const INVALID_REQUEST: &str = "invalid_request";
    pub const INVALID_CLIENT: &str = "invalid_client";
    pub const UNAUTHORIZED_CLIENT: &str = "unauthorized_client";
    /// RFC 6749 §4.1.2.1 — the AS refused the request on policy grounds.
    /// authserver 0.2.0 answers it (HTTP 403) to a cross-client token
    /// exchange whose client is not allowlisted on the target Resource.
    /// Unlike `consent_required`, no user interaction can clear it.
    pub const ACCESS_DENIED: &str = "access_denied";
    /// RFC 8707 §2.2 — returned by the AS when a `resource` parameter is
    /// rejected. authserver compares the value byte for byte against the
    /// granted resources, so a trailing slash is enough to trigger it.
    pub const INVALID_TARGET: &str = "invalid_target";
    pub const SERVER_ERROR: &str = "server_error";
    pub const UNSUPPORTED_GRANT_TYPE: &str = "unsupported_grant_type";
    pub const UNSUPPORTED_TOKEN_TYPE: &str = "unsupported_token_type";
    pub const INVALID_RESPONSE: &str = "invalid_response";
    pub const TOKEN_TYPE_HINT_ACCESS_TOKEN: &str = "access_token";
    pub const TOKEN_TYPE_HINT_REFRESH_TOKEN: &str = "refresh_token";
}

/// HTTP header names this SDK reads or writes.
pub mod http_headers {
    pub const AUTHORIZATION: &str = "authorization";
    pub const ACCEPT: &str = "accept";
    pub const CONTENT_TYPE: &str = "content-type";
    pub const HOST: &str = "Host";
    pub const DPOP: &str = "dpop";
    pub const DPOP_NONCE: &str = "dpop-nonce";
    pub const WWW_AUTHENTICATE: &str = "WWW-Authenticate";
    pub const CACHE_CONTROL: &str = "cache-control";
}

/// MIME types this SDK reads or writes.
pub mod media_types {
    pub const APPLICATION_JSON: &str = "application/json";
    pub const APPLICATION_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
}

/// Authorization scheme prefixes (RFC 6750 / RFC 9449 / RFC 7617).
pub mod auth_schemes {
    pub const BEARER: &str = "Bearer";
    pub const DPOP: &str = "DPoP";
    pub const BASIC: &str = "Basic";
}

/// `.well-known/*` document paths.
pub mod well_known {
    pub const OAUTH_AUTHORIZATION_SERVER: &str = "/.well-known/oauth-authorization-server";
    pub const OPENID_CONFIGURATION: &str = "/.well-known/openid-configuration";
    pub const OAUTH_PROTECTED_RESOURCE: &str = "/.well-known/oauth-protected-resource";
}

/// Standard JWT claim names (RFC 7519, RFC 7800, RFC 9068).
///
/// Confined to claims that are spec-defined for JWT payloads. OAuth /
/// introspection fields that happen to also appear inside JWTs (`scope`,
/// `client_id` per RFC 9068, `active` / `token_type` from RFC 7662
/// introspection responses) live in [`oauth_params`] and
/// [`introspection_fields`] respectively so the module taxonomy reflects the
/// spec each constant comes from. The constants module is brand-new this
/// release cycle so moving these is not a downstream break.
pub mod jwt_claims {
    pub const ISS: &str = "iss";
    pub const SUB: &str = "sub";
    pub const AUD: &str = "aud";
    pub const EXP: &str = "exp";
    pub const IAT: &str = "iat";
    pub const NBF: &str = "nbf";
    pub const JTI: &str = "jti";
    /// RFC 7800 §3.1 confirmation claim, carrying the sender-constrained
    /// binding (e.g. `cnf.jkt` per RFC 9449 §6).
    pub const CNF: &str = "cnf";
    /// RFC 9449 §6.1 — JWK SHA-256 thumbprint inside `cnf`.
    pub const JKT: &str = "jkt";
    /// RFC 9068 §2.2.3.1 — client identifier, mirrored into the access-token
    /// JWT (also an OAuth response field; kept here because the JWT-payload
    /// usage is the one this SDK reads).
    pub const CLIENT_ID: &str = "client_id";

    // Authplane-specific (custom claims used by the AS).
    pub const AGENT_ID: &str = "agent_id";
    pub const AGENT_CHAIN: &str = "agent_chain";
}

/// RFC 7662 token-introspection response fields.
pub mod introspection_fields {
    pub const ACTIVE: &str = "active";
    pub const TOKEN_TYPE: &str = "token_type";
    pub const SCOPE: &str = "scope";
}

/// RFC 9449 DPoP-proof claim names + JWS `typ` header value.
pub mod dpop_claims {
    pub const HTM: &str = "htm";
    pub const HTU: &str = "htu";
    pub const ATH: &str = "ath";
    pub const NONCE: &str = "nonce";

    /// `typ` header value for a DPoP proof JWS (RFC 9449 §4.2).
    pub const TYP_DPOP_JWT: &str = "dpop+jwt";

    /// `typ` header value for an access-token JWT (RFC 9068).
    pub const TYP_AT_JWT: &str = "at+jwt";
}

/// RFC 7517 JWK parameter names + RFC 7518 / RFC 8037 algorithm values.
pub mod jwk_params {
    pub const KTY: &str = "kty";
    pub const CRV: &str = "crv";
    pub const X: &str = "x";
    pub const Y: &str = "y";
    pub const E: &str = "e";
    pub const N: &str = "n";

    pub const KTY_EC: &str = "EC";
    pub const KTY_RSA: &str = "RSA";
    pub const KTY_OKP: &str = "OKP";

    pub const CRV_P256: &str = "P-256";

    pub const USE: &str = "use";
    pub const USE_SIG: &str = "sig";

    pub const KEY_OPS: &str = "key_ops";
    pub const KEY_OPS_VERIFY: &str = "verify";

    /// RFC 7517 §4.4 — JOSE algorithm identifier on the JWK.
    pub const ALG: &str = "alg";
    /// RFC 7517 §4.5 — key identifier on the JWK.
    pub const KID: &str = "kid";
}

/// HTTP request methods written by this SDK.
///
/// Currently only `POST` is constructed in DPoP-proof HTU/HTM binding; other
/// methods reach this SDK only via inbound parsing where `http::Method` already
/// owns the canonical spelling.
pub mod http_methods {
    pub const POST: &str = "POST";
}

/// JOSE algorithm identifiers (RFC 7518).
pub mod algorithms {
    pub const ES256: &str = "ES256";
    pub const RS256: &str = "RS256";
}
