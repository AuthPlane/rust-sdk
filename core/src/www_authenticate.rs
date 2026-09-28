//! RFC 6750 §3 `WWW-Authenticate` header builders and HTTP status mapping.
//!
//! These helpers give resource servers a consistent, spec-compliant way to
//! convert [`VerifierError`] and [`AuthplaneError`] values into HTTP
//! challenge headers and status codes.

use crate::constants::{auth_schemes, oauth_errors};
use crate::{AuthplaneError, VerifierError};

/// HTTP status codes this module emits. Centralised so the bearer/DPoP
/// challenge mapping documented in the module preamble stays aligned with
/// the actual values returned by [`http_status`] and
/// [`http_status_for_auth_error`].
const HTTP_STATUS_BAD_REQUEST: u16 = 400;
const HTTP_STATUS_UNAUTHORIZED: u16 = 401;
const HTTP_STATUS_FORBIDDEN: u16 = 403;
const HTTP_STATUS_SERVICE_UNAVAILABLE: u16 = 503;

/// Build an RFC 6750 §3 / RFC 9449 §7.1 `WWW-Authenticate` header value
/// for a verifier failure.
///
/// The scheme is `Bearer` for plain-token failures and `DPoP` for any
/// DPoP proof-validation failure (see [`is_dpop_error`]). The `error`
/// parameter is one of:
///
/// - `insufficient_scope` — token is valid but missing a required scope.
/// - `invalid_token` — token is expired, has an invalid signature, has
///   invalid claims, was revoked, simply wasn't supplied, or failed
///   DPoP proof validation (missing proof against a bound token,
///   replay, binding mismatch, or DPoP signal against a Mode-3
///   resource). RFC 6750 §3.1 groups these under `invalid_token`; the
///   shared conformance catalog's `dpop_error → invalid_token` mapping
///   keeps the DPoP cases on the same code.
/// - `invalid_dpop_proof` — the request carried more than one `DPoP`
///   header (RFC 9449 §4.3 #1). RFC 9449 §7.1 prescribes this code for
///   proof-validation rejections; only the multi-header case carries it.
/// - no `error` — server-side issue (metadata or JWKS unavailable);
///   RFC 6750 §3 only requires the scheme in that case.
///
/// The `realm` is optional; pass `""` to omit it.
///
/// Emits no `resource_metadata` parameter. A resource server that knows
/// its RFC 9728 document URL should use
/// [`AuthplaneResource::www_authenticate`](crate::AuthplaneResource::www_authenticate)
/// or [`www_authenticate_with_resource_metadata`] instead, so clients can
/// discover the authorization server from the challenge.
pub fn www_authenticate(error: &VerifierError, realm: &str) -> String {
    www_authenticate_with_resource_metadata(error, realm, "")
}

/// [`www_authenticate`] plus the RFC 9728 §5.1 `resource_metadata`
/// parameter: the absolute URL of the resource's Protected Resource
/// Metadata document, which a client fetches to learn the authorization
/// server it must obtain a token from. The MCP authorization spec requires
/// it on every `401`.
///
/// `resource_metadata_url` is emitted verbatim as a quoted-string; pass
/// `""` to omit it. It is appended after the RFC 6750 parameters so the
/// `<scheme> error="…", error_description="…"` shape the shared
/// conformance catalog pins is unchanged.
pub fn www_authenticate_with_resource_metadata(
    error: &VerifierError,
    realm: &str,
    resource_metadata_url: &str,
) -> String {
    let scheme = if is_dpop_error(error) {
        auth_schemes::DPOP
    } else {
        auth_schemes::BEARER
    };
    // Service-side failures (metadata/JWKS) intentionally omit the
    // `error` parameter per RFC 6750 §3 — the caller isn't at fault.
    let error_params = challenge_error_for(error).map(|code| (code, error.to_string()));
    build_challenge(
        scheme,
        realm,
        error_params
            .as_ref()
            .map(|(code, description)| (*code, description.as_str())),
        resource_metadata_url,
    )
}

/// Challenge for a request that carried no credentials at all.
///
/// RFC 6750 §3.1: when "the request lacks any authentication information
/// […] the resource server SHOULD NOT include an error code or other error
/// information", so this emits only `realm` and `resource_metadata`
/// (RFC 9728 §5.1) — the two parameters a client that did not know
/// authentication was required needs in order to go and get a token. The
/// scheme is `Bearer`: with no token there is no DPoP binding to fail.
///
/// Both parameters are optional; pass `""` to omit either.
pub fn www_authenticate_for_missing_credentials(
    realm: &str,
    resource_metadata_url: &str,
) -> String {
    build_challenge(auth_schemes::BEARER, realm, None, resource_metadata_url)
}

fn build_challenge(
    scheme: &str,
    realm: &str,
    error: Option<(&str, &str)>,
    resource_metadata_url: &str,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !realm.is_empty() {
        parts.push(format!("realm=\"{}\"", escape_quoted(realm)));
    }
    if let Some((code, description)) = error {
        parts.push(format!("error=\"{code}\""));
        parts.push(format!(
            "error_description=\"{}\"",
            escape_quoted(description)
        ));
    }
    if !resource_metadata_url.is_empty() {
        parts.push(format!(
            "resource_metadata=\"{}\"",
            escape_quoted(resource_metadata_url)
        ));
    }

    if parts.is_empty() {
        scheme.to_string()
    } else {
        format!("{scheme} {}", parts.join(", "))
    }
}

/// Returns `true` when the `WWW-Authenticate` header for this error
/// should use the `DPoP` scheme instead of `Bearer` (RFC 9449 §7.1).
///
/// Delegates to [`VerifierError::www_authenticate_scheme_is_dpop`] so the
/// scheme decision is owned by the error type and cannot drift from
/// [`challenge_error_for`]'s `invalid_token` mapping. Note that
/// `DpopNotSupported` is intentionally NOT in this set: the request reached
/// a resource that has not opted into DPoP, so the spec-correct retry
/// scheme is `Bearer`, not `DPoP`.
pub fn is_dpop_error(error: &VerifierError) -> bool {
    error.www_authenticate_scheme_is_dpop()
}

/// Map a [`VerifierError`] to the HTTP status code a resource server should
/// return.
///
/// - `401 Unauthorized` — authentication failed (missing, expired, invalid
///   signature, invalid claims, revoked).
/// - `403 Forbidden` — authentication succeeded but the token is missing
///   a required scope.
/// - `503 Service Unavailable` — the resource server cannot validate because
///   metadata or JWKS cannot be fetched.
pub fn http_status(error: &VerifierError) -> u16 {
    match error {
        VerifierError::InsufficientScope { .. } => HTTP_STATUS_FORBIDDEN,
        VerifierError::MetadataUnavailable { .. } | VerifierError::JwksUnavailable { .. } => {
            HTTP_STATUS_SERVICE_UNAVAILABLE
        }
        _ => HTTP_STATUS_UNAUTHORIZED,
    }
}

/// Map an [`AuthplaneError`] (client-side OAuth error) to an HTTP status code
/// a proxy or MCP adapter should surface to its own caller. Consent-required
/// errors map to `401` so the caller knows to re-authenticate; other OAuth
/// errors preserve the status the AS returned when present and fall back to
/// `400` otherwise.
pub fn http_status_for_auth_error(error: &AuthplaneError) -> u16 {
    match error {
        AuthplaneError::ConsentRequired(_) => HTTP_STATUS_UNAUTHORIZED,
        AuthplaneError::CircuitOpen => HTTP_STATUS_SERVICE_UNAVAILABLE,
        AuthplaneError::Auth(inner) => inner.status_code.unwrap_or(HTTP_STATUS_BAD_REQUEST),
    }
}

fn challenge_error_for(error: &VerifierError) -> Option<&'static str> {
    match error {
        VerifierError::InsufficientScope { .. } => Some(oauth_errors::INSUFFICIENT_SCOPE),
        VerifierError::TokenMissing
        | VerifierError::TokenExpired
        | VerifierError::InvalidSignature { .. }
        | VerifierError::InvalidClaims { .. }
        | VerifierError::TokenRevoked => Some(oauth_errors::INVALID_TOKEN),
        VerifierError::MetadataUnavailable { .. } | VerifierError::JwksUnavailable { .. } => None,
        // DPoP failures share the `invalid_token` code — they're invalid-
        // token failures, just with a different scheme (`DPoP` vs
        // `Bearer`). The shared conformance catalog's
        // `rfc6750-error-response-must-map-error-codes` case pins this
        // mapping (`dpop_error → invalid_token`).
        VerifierError::DpopProofMissing
        | VerifierError::DpopReplayDetected
        | VerifierError::DpopBindingMismatch { .. }
        | VerifierError::DpopNotSupported => Some(oauth_errors::INVALID_TOKEN),
        // Carve-out: RFC 9449 §4.3 #1 (more than one `DPoP` header) is a
        // proof-validation failure with no way to tell which proof binds
        // the request, so RFC 9449 §7.1's `invalid_dpop_proof` applies.
        // Only this case carries the code; the other DPoP failures above
        // stay on `invalid_token`.
        VerifierError::DpopMultipleProofs => Some(oauth_errors::INVALID_DPOP_PROOF),
    }
}

fn escape_quoted(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthError, AuthplaneError, ConsentRequiredError};

    #[test]
    fn www_authenticate_token_missing_is_invalid_token() {
        let header = www_authenticate(&VerifierError::TokenMissing, "api");
        assert!(header.starts_with("Bearer "));
        assert!(header.contains("realm=\"api\""));
        assert!(header.contains("error=\"invalid_token\""));
        assert!(header.contains("error_description=\""));
    }

    #[test]
    fn www_authenticate_insufficient_scope_uses_that_code() {
        let header = www_authenticate(
            &VerifierError::InsufficientScope {
                required: "tools/admin".to_string(),
                available: vec!["tools/read".to_string()],
            },
            "",
        );
        assert!(header.contains("error=\"insufficient_scope\""));
        assert!(!header.contains("realm="));
    }

    #[test]
    fn www_authenticate_jwks_unavailable_omits_error() {
        let header = www_authenticate(
            &VerifierError::JwksUnavailable {
                message: "boom".to_string(),
            },
            "api",
        );
        assert!(header.contains("realm=\"api\""));
        assert!(!header.contains("error="));
    }

    #[test]
    fn www_authenticate_escapes_quotes_in_description() {
        let header = www_authenticate(
            &VerifierError::InvalidClaims {
                message: "token \"bad\"".to_string(),
            },
            "",
        );
        assert!(header.contains("\\\""));
    }

    #[test]
    fn http_status_maps_insufficient_scope_to_403() {
        assert_eq!(
            http_status(&VerifierError::InsufficientScope {
                required: "x".to_string(),
                available: vec![],
            }),
            403
        );
    }

    #[test]
    fn http_status_maps_metadata_unavailable_to_503() {
        assert_eq!(
            http_status(&VerifierError::MetadataUnavailable {
                message: "n/a".to_string(),
            }),
            503
        );
        assert_eq!(
            http_status(&VerifierError::JwksUnavailable {
                message: "n/a".to_string(),
            }),
            503
        );
    }

    #[test]
    fn http_status_maps_auth_failures_to_401() {
        assert_eq!(http_status(&VerifierError::TokenMissing), 401);
        assert_eq!(http_status(&VerifierError::TokenExpired), 401);
        assert_eq!(http_status(&VerifierError::TokenRevoked), 401);
        assert_eq!(
            http_status(&VerifierError::InvalidSignature {
                message: "x".to_string(),
            }),
            401
        );
        assert_eq!(
            http_status(&VerifierError::InvalidClaims {
                message: "x".to_string(),
            }),
            401
        );
    }

    #[test]
    fn http_status_for_auth_error_prefers_consent_required_to_401() {
        let err = AuthplaneError::from(ConsentRequiredError {
            message: "need consent".to_string(),
            code: "consent_required".to_string(),
            status_code: Some(403),
            service_id: "drive".to_string(),
            cause_detail: "approval".to_string(),
            consent_url: None,
        });
        assert_eq!(http_status_for_auth_error(&err), 401);
    }

    #[test]
    fn http_status_for_auth_error_preserves_upstream_status() {
        let err = AuthplaneError::Auth(AuthError {
            message: "bad".to_string(),
            code: "invalid_grant".to_string(),
            status_code: Some(400),
        });
        assert_eq!(http_status_for_auth_error(&err), 400);
    }

    /// RFC 9449 §7.1 — DPoP-bound failures emit the `DPoP` scheme so the
    /// client knows to retry with a proof, EXCEPT `DpopNotSupported` which
    /// uses `Bearer` because the resource has no DPoP path the client could
    /// retry against.
    #[test]
    fn www_authenticate_dpop_bound_failures_use_dpop_scheme() {
        for err in [
            VerifierError::DpopProofMissing,
            VerifierError::DpopReplayDetected,
            VerifierError::DpopBindingMismatch {
                message: "mismatch".to_string(),
            },
        ] {
            let header = www_authenticate(&err, "api");
            assert!(
                header.starts_with("DPoP "),
                "expected DPoP scheme for {err:?}, got {header:?}"
            );
        }
    }

    #[test]
    fn www_authenticate_dpop_not_supported_uses_bearer_scheme_with_invalid_token() {
        // Mode-3 rejection: the client offered a DPoP signal against a
        // resource that has not opted into DPoP. The scheme is `Bearer`
        // because the resource has no DPoP path the client could retry
        // against; the error code stays `invalid_token` per the shared
        // conformance catalog's `dpop_error → invalid_token` mapping.
        let header = www_authenticate(&VerifierError::DpopNotSupported, "api");
        assert!(
            header.starts_with("Bearer "),
            "DpopNotSupported must retry as Bearer, got {header:?}"
        );
        assert!(header.contains("error=\"invalid_token\""));
    }

    #[test]
    fn www_authenticate_dpop_proof_missing_uses_dpop_scheme_and_invalid_token() {
        let header = www_authenticate(&VerifierError::DpopProofMissing, "api");
        assert!(
            header.starts_with("DPoP "),
            "expected DPoP scheme, got {header:?}"
        );
        assert!(header.contains("error=\"invalid_token\""));
    }

    #[test]
    fn www_authenticate_dpop_binding_mismatch_uses_dpop_scheme_and_invalid_token() {
        let header = www_authenticate(
            &VerifierError::DpopBindingMismatch {
                message: "cnf.jkt mismatch".to_string(),
            },
            "",
        );
        assert!(header.starts_with("DPoP"));
        assert!(header.contains("error=\"invalid_token\""));
    }

    #[test]
    fn www_authenticate_dpop_replay_uses_dpop_scheme_and_invalid_token() {
        let header = www_authenticate(&VerifierError::DpopReplayDetected, "");
        assert!(header.starts_with("DPoP"));
        assert!(header.contains("error=\"invalid_token\""));
    }

    #[test]
    fn www_authenticate_dpop_multiple_proofs_uses_dpop_scheme_and_invalid_dpop_proof() {
        let header = www_authenticate(&VerifierError::DpopMultipleProofs, "");
        assert!(header.starts_with("DPoP"));
        assert!(header.contains("error=\"invalid_dpop_proof\""));
        assert_eq!(http_status(&VerifierError::DpopMultipleProofs), 401);
    }

    const PRM_URL: &str = "https://api.example.com/.well-known/oauth-protected-resource/mcp";

    /// RFC 9728 §5.1 — the parameter is a quoted-string appended after
    /// the RFC 6750 parameters. Asserted byte for byte so nothing else
    /// (scheme, order, spacing, an extra parameter) can slip in.
    #[test]
    fn www_authenticate_with_resource_metadata_appends_a_quoted_string() {
        let header =
            www_authenticate_with_resource_metadata(&VerifierError::TokenExpired, "api", PRM_URL);
        assert_eq!(
            header,
            format!(
                "Bearer realm=\"api\", error=\"invalid_token\", \
                 error_description=\"token has expired\", resource_metadata=\"{PRM_URL}\""
            )
        );
    }

    #[test]
    fn www_authenticate_with_resource_metadata_keeps_the_dpop_scheme() {
        let header =
            www_authenticate_with_resource_metadata(&VerifierError::DpopProofMissing, "", PRM_URL);
        assert!(header.starts_with("DPoP error=\"invalid_token\""));
        assert!(header.ends_with(&format!("resource_metadata=\"{PRM_URL}\"")));
    }

    #[test]
    fn www_authenticate_with_resource_metadata_survives_a_service_side_failure() {
        // No `error` parameter (RFC 6750 §3), but the discovery hint is
        // still worth sending: the client is not at fault and can retry.
        let header = www_authenticate_with_resource_metadata(
            &VerifierError::JwksUnavailable {
                message: "boom".to_string(),
            },
            "",
            PRM_URL,
        );
        assert_eq!(header, format!("Bearer resource_metadata=\"{PRM_URL}\""));
    }

    #[test]
    fn www_authenticate_without_resource_metadata_emits_no_such_parameter() {
        let header = www_authenticate(&VerifierError::TokenExpired, "api");
        assert!(!header.contains("resource_metadata"));
        let header = www_authenticate_with_resource_metadata(&VerifierError::TokenExpired, "", "");
        assert_eq!(
            header,
            "Bearer error=\"invalid_token\", error_description=\"token has expired\""
        );
    }

    #[test]
    fn www_authenticate_escapes_quotes_in_resource_metadata() {
        let header = www_authenticate_with_resource_metadata(
            &VerifierError::TokenMissing,
            "",
            "https://api.example.com/.well-known/oauth-protected-resource/a\"b",
        );
        assert!(header.ends_with(
            "resource_metadata=\"https://api.example.com/.well-known/oauth-protected-resource/a\\\"b\""
        ));
    }

    /// RFC 6750 §3.1 — a request with no credentials gets no error code;
    /// it does get the RFC 9728 §5.1 discovery hint.
    #[test]
    fn www_authenticate_for_missing_credentials_has_realm_and_resource_metadata_only() {
        assert_eq!(
            www_authenticate_for_missing_credentials("api", PRM_URL),
            format!("Bearer realm=\"api\", resource_metadata=\"{PRM_URL}\"")
        );
        assert_eq!(
            www_authenticate_for_missing_credentials("", PRM_URL),
            format!("Bearer resource_metadata=\"{PRM_URL}\"")
        );
        assert_eq!(
            www_authenticate_for_missing_credentials("api", ""),
            "Bearer realm=\"api\""
        );
        assert_eq!(www_authenticate_for_missing_credentials("", ""), "Bearer");
    }

    #[test]
    fn http_status_for_auth_error_defaults_to_400_when_status_missing() {
        let err = AuthplaneError::Auth(AuthError {
            message: "bad".to_string(),
            code: "invalid_grant".to_string(),
            status_code: None,
        });
        assert_eq!(http_status_for_auth_error(&err), 400);
    }
}
