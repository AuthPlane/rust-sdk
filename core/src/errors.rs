use serde_json::Value;
use thiserror::Error;

use crate::constants::oauth_errors;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct AuthError {
    pub message: String,
    pub code: String,
    pub status_code: Option<u16>,
}

/// Convenience predicates for the common error categories.
/// These check the `code` field so callers can pattern-match on OAuth error
/// codes without string comparisons.
impl AuthError {
    pub fn is_invalid_client(&self) -> bool {
        self.code == oauth_errors::INVALID_CLIENT
    }
    pub fn is_unauthorized_client(&self) -> bool {
        self.code == oauth_errors::UNAUTHORIZED_CLIENT
    }
    pub fn is_invalid_scope(&self) -> bool {
        self.code == oauth_errors::INVALID_SCOPE
    }
    pub fn is_invalid_grant(&self) -> bool {
        self.code == oauth_errors::INVALID_GRANT
    }
    pub fn is_unsupported_grant_type(&self) -> bool {
        self.code == oauth_errors::UNSUPPORTED_GRANT_TYPE
    }
    pub fn is_invalid_request(&self) -> bool {
        self.code == oauth_errors::INVALID_REQUEST
    }
    /// `access_denied` — the AS refused the request on policy grounds.
    /// On a cross-client token exchange this means the exchanging client
    /// is not allowlisted on the target Resource; the operator has to add
    /// it (`PATCH /admin/resources/{id}` with
    /// `policy.exchange.allowed_client_ids`). Re-prompting the user does
    /// not help, which is what separates it from `consent_required`.
    pub fn is_access_denied(&self) -> bool {
        self.code == oauth_errors::ACCESS_DENIED
    }
    /// `invalid_target` (RFC 8707 §2.2) — the `resource` parameter does
    /// not match a granted resource byte for byte (a trailing slash is
    /// enough).
    pub fn is_invalid_target(&self) -> bool {
        self.code == oauth_errors::INVALID_TARGET
    }
    pub fn is_server_error(&self) -> bool {
        self.code == oauth_errors::SERVER_ERROR
            || self
                .status_code
                .is_some_and(|status| (500..600).contains(&(status as u32)))
    }
    pub fn is_circuit_open(&self) -> bool {
        self.code == "circuit_open"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct ConsentRequiredError {
    pub message: String,
    pub code: String,
    pub status_code: Option<u16>,
    pub service_id: String,
    pub cause_detail: String,
    pub consent_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuthplaneError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    /// The payload is boxed. `ConsentRequiredError` carries six fields
    /// (128 bytes) against `AuthError`'s three (56), so leaving it inline
    /// makes every `Result<_, AuthplaneError>` in the crate — overwhelmingly
    /// the success path — as wide as the rarest error. Boxing keeps the enum
    /// at 64 bytes.
    ///
    /// Construct with `AuthplaneError::from(consent)` or `consent.into()`;
    /// `match` arms bind a `Box<ConsentRequiredError>` and reach the fields
    /// through `Deref`, so patterns need no change.
    #[error(transparent)]
    ConsentRequired(#[from] Box<ConsentRequiredError>),
    /// Circuit breaker is open — the authorization server is considered
    /// unavailable.
    #[error("circuit breaker open: AS unavailable")]
    CircuitOpen,
}

/// Boxing companion for the derived `From<Box<ConsentRequiredError>>`, so
/// call sites and `?` keep converting an unboxed `ConsentRequiredError`.
impl From<ConsentRequiredError> for AuthplaneError {
    fn from(error: ConsentRequiredError) -> Self {
        AuthplaneError::ConsentRequired(Box::new(error))
    }
}

/// Convenience predicates on `AuthplaneError` for common error categories.
impl AuthplaneError {
    pub fn is_circuit_open(&self) -> bool {
        matches!(self, AuthplaneError::CircuitOpen)
    }
    pub fn is_consent_required(&self) -> bool {
        matches!(self, AuthplaneError::ConsentRequired(_))
    }
}

pub fn map_oauth_error(status_code: Option<u16>, payload: &Value) -> AuthplaneError {
    let body_error_code = payload.get("error").and_then(Value::as_str);

    let description = payload
        .get("error_description")
        .and_then(Value::as_str)
        .unwrap_or("OAuth request failed");
    let message = description.to_string();

    // Two structural cases are checked BEFORE the RFC 6749 §5.2
    // `error`-code switch (status-first classifier):
    //   • status >= 500 → server-side regardless of the (often-missing)
    //     error body. Surface as `code = "server_error"` so callers'
    //     `AuthError::is_server_error()` predicate fires correctly and
    //     circuit-breaker policy can react.
    //   • status == 401 with no error body → AS rejected client
    //     authentication; the typed handle is invalid_client.
    let resolved_code = if status_code.is_some_and(|status| status >= 500) {
        oauth_errors::SERVER_ERROR.to_string()
    } else if status_code == Some(401) && body_error_code.is_none_or(|code| code.trim().is_empty())
    {
        oauth_errors::INVALID_CLIENT.to_string()
    } else {
        body_error_code
            .unwrap_or(oauth_errors::INVALID_REQUEST)
            .to_string()
    };

    let oauth_code = resolved_code;

    if oauth_code == oauth_errors::CONSENT_REQUIRED
        || oauth_code == oauth_errors::INTERACTION_REQUIRED
    {
        let consent_url = payload
            .get("consent_url")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let service_id = first_non_empty_string(payload, &["service_id", "service", "resource"])
            .unwrap_or("unknown_service")
            .to_string();
        let cause_detail = payload
            .get("cause")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or(description)
            .to_string();

        return AuthplaneError::from(ConsentRequiredError {
            message,
            code: oauth_code,
            status_code,
            service_id,
            cause_detail,
            consent_url,
        });
    }

    AuthplaneError::Auth(AuthError {
        message,
        code: oauth_code,
        status_code,
    })
}

pub(crate) fn transport_error(message: &str) -> AuthplaneError {
    AuthplaneError::Auth(AuthError {
        message: message.to_string(),
        code: "transport_error".to_string(),
        status_code: None,
    })
}

/// Build an `AuthplaneError::Auth(AuthError {...})` with the
/// `metadata_fetch_error` code. Centralises the construction that was
/// duplicated between `metadata.rs` and `cache/metadata_cache.rs`; new
/// metadata-fetch failure paths should route through here so the
/// `code` token never drifts.
pub(crate) fn metadata_error(message: &str) -> AuthplaneError {
    AuthplaneError::Auth(AuthError {
        message: message.to_string(),
        code: "metadata_fetch_error".to_string(),
        status_code: None,
    })
}

/// Build a generic `AuthplaneError::Auth(AuthError {...})` from a free-form
/// code + message pair. Replaces hand-written struct literals at the
/// call sites that don't have a more specific helper. Use this only when
/// a specific helper (`transport_error`, `metadata_error`,
/// `validation_error`, `protocol_error`) doesn't apply — those carry
/// the canonical code strings and should remain the first-choice paths.
pub(crate) fn auth_error(code: &str, message: &str) -> AuthplaneError {
    AuthplaneError::Auth(AuthError {
        message: message.to_string(),
        code: code.to_string(),
        status_code: None,
    })
}

/// Trim a single trailing `/` from an issuer string. RFC 8414 §2
/// treats `https://example.com` and `https://example.com/` as equivalent;
/// every call site that compares or stores an issuer should funnel
/// through here so the comparison shape stays uniform.
pub(crate) fn normalize_issuer(issuer: &str) -> &str {
    issuer.trim_end_matches('/')
}

/// How [`build_well_known_url`] treats the base URL's query component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueryComponent {
    /// RFC 9728 §3 inserts the well-known suffix "between the host
    /// component and the path and/or query components, if any" — a query
    /// on the resource identifier survives into the derived PRM URL.
    /// The query is a legal part of the identifier: RFC 8707 §2 states
    /// the SHOULD NOT and its scoping exception in the same sentence,
    /// and RFC 9728 §1.2 carries that carve-out forward.
    ///
    /// Two caveats. A bare trailing `?` (empty query) is treated as no
    /// query — the empty string identifies nothing, so it resolves to
    /// the query-less document URL. And the query rides through
    /// `url::Url`'s serializer rather than being spliced from the
    /// configured bytes, so legal-but-normalizable octets (a raw space,
    /// `'` on a special scheme) surface percent-encoded in the derived
    /// URL while `ProtectedResourceMetadata::resource` keeps the
    /// operator's original bytes.
    Preserve,
    /// RFC 8414 §2 defines the issuer identifier with no query or
    /// fragment components, so the AS-metadata derivation drops a query
    /// rather than propagating an out-of-spec issuer shape.
    Strip,
}

/// Build the absolute URL for a `/.well-known/<suffix>` document scoped
/// to a base URL's path. Shared between `build_metadata_url`
/// (RFC 8414 §3) and `build_prm_url` (RFC 9728 §3) — both apply the
/// same template (parse → remove the terminating slash → splice the
/// well-known prefix → clear the fragment); the suffix and the query
/// handling differ per caller (see [`QueryComponent`]).
///
/// `suffix` is the well-known segment without leading or trailing
/// slashes (e.g. `"oauth-authorization-server"`,
/// `"oauth-protected-resource"`).
///
/// `invalid_url_message` is invoked only on the error path so callers
/// can embed the offending input via `format!` without paying for the
/// allocation on every successful parse.
pub(crate) fn build_well_known_url<F>(
    base: &str,
    suffix: &str,
    query: QueryComponent,
    invalid_url_code: &str,
    invalid_url_message: F,
) -> Result<String, AuthplaneError>
where
    F: FnOnce() -> String,
{
    let parsed =
        url::Url::parse(base).map_err(|_| auth_error(invalid_url_code, &invalid_url_message()))?;
    // RFC 8414 §3.1 / RFC 9728 §3.1 remove the *terminating* "/" from
    // the path before inserting the well-known suffix after the host.
    // Only trailing slashes come off: the previous `trim_matches('/')`
    // stripped leading slashes too, collapsing `//mcp` onto `/mcp` —
    // two distinct identifiers deriving one metadata document URL.
    let path = parsed.path().trim_end_matches('/');
    let well_known_path = if path.is_empty() {
        format!("/.well-known/{suffix}")
    } else if path.starts_with('/') {
        // A URL with an authority always exposes a '/'-prefixed path,
        // so plain concatenation keeps exactly one separator and
        // preserves any leading empty segment.
        format!("/.well-known/{suffix}{path}")
    } else {
        // Cannot-be-a-base URLs (e.g. `urn:`) expose a slash-less path;
        // re-add a separator between suffix and path. The derivation is
        // not meaningful for such identifiers — RFC 9728 §3 presumes a
        // host component — and the construction path does not yet
        // reject them.
        format!("/.well-known/{suffix}/{path}")
    };

    let mut rebuilt = parsed;
    rebuilt.set_path(&well_known_path);
    // In Preserve mode an *empty* query (a bare trailing `?`) is still
    // dropped: `url::Url` parses it as `Some("")` and would re-serialize
    // the lone `?` into a document URL no client re-derives.
    if query == QueryComponent::Strip || rebuilt.query() == Some("") {
        rebuilt.set_query(None);
    }
    rebuilt.set_fragment(None);
    Ok(rebuilt.to_string())
}

pub(crate) fn validation_error(message: &str) -> AuthplaneError {
    AuthplaneError::Auth(AuthError {
        message: format!("authplane: {message}"),
        code: "validation_error".to_string(),
        status_code: None,
    })
}

pub(crate) fn protocol_error(message: &str) -> AuthplaneError {
    AuthplaneError::Auth(AuthError {
        message: format!("authplane: {message}"),
        code: "protocol_error".to_string(),
        status_code: None,
    })
}

fn first_non_empty_string<'a>(payload: &'a Value, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(value) = payload.get(key).and_then(Value::as_str)
            && !value.is_empty()
        {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{AuthplaneError, map_oauth_error};

    /// Guards the boxing on `ConsentRequired`. 128 bytes is clippy's
    /// `result_large_err` threshold; crossing it makes the lint fire on
    /// every `Result<_, AuthplaneError>` in the crate, which is what the
    /// module-wide `#![allow]`s used to paper over.
    #[test]
    fn error_enum_stays_under_the_result_large_err_threshold() {
        assert!(
            size_of::<AuthplaneError>() < 128,
            "AuthplaneError grew to {} bytes; box the new payload instead of \
             allowing clippy::result_large_err",
            size_of::<AuthplaneError>()
        );
    }

    #[test]
    fn consent_required_uses_unknown_service_fallback() {
        let payload = json!({
            "error": "consent_required",
            "error_description": "Consent required"
        });

        let mapped = map_oauth_error(Some(400), &payload);
        let AuthplaneError::ConsentRequired(consent) = mapped else {
            panic!("expected consent required");
        };

        assert_eq!(consent.service_id, "unknown_service");
        assert_eq!(consent.cause_detail, "Consent required");
    }

    #[test]
    fn other_errors_map_to_auth_error() {
        let payload = json!({
            "error": "invalid_scope",
            "error_description": "scope missing"
        });

        let mapped = map_oauth_error(Some(400), &payload);
        let AuthplaneError::Auth(auth_error) = mapped else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "invalid_scope");
        assert_eq!(auth_error.message, "scope missing");
    }

    #[test]
    fn interaction_required_uses_resource_and_description_fallbacks() {
        let payload = json!({
            "error": "interaction_required",
            "error_description": "User action needed",
            "resource": "calendar"
        });

        let mapped = map_oauth_error(Some(400), &payload);
        let AuthplaneError::ConsentRequired(consent) = mapped else {
            panic!("expected consent required");
        };
        assert_eq!(consent.service_id, "calendar");
        assert_eq!(consent.cause_detail, "User action needed");
        assert_eq!(consent.consent_url, None);
    }

    #[test]
    fn consent_required_uses_default_message_when_description_missing() {
        let payload = json!({
            "error": "consent_required",
            "service_id": "drive"
        });

        let mapped = map_oauth_error(Some(400), &payload);
        let AuthplaneError::ConsentRequired(consent) = mapped else {
            panic!("expected consent required");
        };
        assert_eq!(consent.message, "OAuth request failed");
        assert_eq!(consent.cause_detail, "OAuth request failed");
    }

    #[test]
    fn http_5xx_maps_to_server_error_regardless_of_body_code() {
        // The mapping short-circuits on status >= 500 before reaching the
        // error-code switch — a 503 with no usable body still
        // surfaces as ServerError so circuit-breaker policy can trip.
        let payload = json!({});
        let mapped = map_oauth_error(Some(503), &payload);
        let AuthplaneError::Auth(auth_error) = mapped else {
            panic!("expected auth error variant");
        };
        assert_eq!(auth_error.code, "server_error");
        assert!(auth_error.is_server_error());

        // Even if the AS returned a misleading `error=invalid_grant` on
        // a 502, the status code wins — server-side outage trumps the
        // wire error code.
        let misleading = json!({ "error": "invalid_grant" });
        let mapped = map_oauth_error(Some(502), &misleading);
        let AuthplaneError::Auth(auth_error) = mapped else {
            panic!("expected auth error variant");
        };
        assert_eq!(auth_error.code, "server_error");
    }

    #[test]
    fn bare_401_with_no_body_error_maps_to_invalid_client() {
        // A bodyless 401 is the AS rejecting client authentication;
        // the typed `invalid_client` code is the catch handle.
        let payload = json!({});
        let mapped = map_oauth_error(Some(401), &payload);
        let AuthplaneError::Auth(auth_error) = mapped else {
            panic!("expected auth error variant");
        };
        assert_eq!(auth_error.code, "invalid_client");
        assert!(auth_error.is_invalid_client());
    }

    #[test]
    fn populated_401_with_body_error_uses_body_code() {
        // When the body DOES carry an error code, that wins over the
        // 401-bare-fallback. Only the bodyless case dispatches to
        // invalid_client.
        let payload = json!({
            "error": "invalid_grant",
            "error_description": "Refresh token expired"
        });
        let mapped = map_oauth_error(Some(401), &payload);
        let AuthplaneError::Auth(auth_error) = mapped else {
            panic!("expected auth error variant");
        };
        assert_eq!(auth_error.code, "invalid_grant");
    }

    // --- helpers added in the audit-followup sweep ---

    use super::{QueryComponent, build_well_known_url, normalize_issuer};

    #[test]
    fn normalize_issuer_strips_single_trailing_slash() {
        assert_eq!(
            normalize_issuer("https://auth.example.com/"),
            "https://auth.example.com"
        );
    }

    #[test]
    fn normalize_issuer_is_idempotent_without_trailing_slash() {
        assert_eq!(
            normalize_issuer("https://auth.example.com"),
            "https://auth.example.com"
        );
    }

    #[test]
    fn normalize_issuer_treats_pre_and_post_trim_forms_as_equal() {
        // RFC 8414 §2 equivalence: the two forms must collapse to the
        // same comparison key. This pins the property the validator
        // depends on.
        assert_eq!(
            normalize_issuer("https://auth.example.com/"),
            normalize_issuer("https://auth.example.com")
        );
    }

    #[test]
    fn build_well_known_url_appends_suffix_without_issuer_path() {
        let url = build_well_known_url(
            "https://auth.example.com",
            "oauth-authorization-server",
            QueryComponent::Strip,
            "metadata_fetch_error",
            || "issuer must be an absolute URL".to_string(),
        )
        .expect("valid base");
        assert_eq!(
            url,
            "https://auth.example.com/.well-known/oauth-authorization-server"
        );
    }

    #[test]
    fn build_well_known_url_splices_suffix_before_issuer_path() {
        let url = build_well_known_url(
            "https://auth.example.com/tenant-a",
            "oauth-authorization-server",
            QueryComponent::Strip,
            "metadata_fetch_error",
            || "issuer must be an absolute URL".to_string(),
        )
        .expect("valid base");
        assert_eq!(
            url,
            "https://auth.example.com/.well-known/oauth-authorization-server/tenant-a"
        );
    }

    #[test]
    fn build_well_known_url_preserves_query_and_strips_fragment() {
        // RFC 9728 §3: the well-known suffix goes between the host and
        // "the path and/or query components, if any" — the query is part
        // of the derived URL, not noise to normalize away.
        let url = build_well_known_url(
            "https://api.example.com/v1/mcp?token=abc#frag",
            "oauth-protected-resource",
            QueryComponent::Preserve,
            "invalid_resource",
            || "invalid resource URL".to_string(),
        )
        .expect("valid base");
        assert_eq!(
            url,
            "https://api.example.com/.well-known/oauth-protected-resource/v1/mcp?token=abc"
        );
    }

    #[test]
    fn build_well_known_url_strip_mode_drops_query() {
        // RFC 8414 §2 gives the issuer identifier no query component;
        // the AS-metadata caller opts into stripping.
        let url = build_well_known_url(
            "https://auth.example.com/tenant-a?q=1#frag",
            "oauth-authorization-server",
            QueryComponent::Strip,
            "metadata_fetch_error",
            || "issuer must be an absolute URL".to_string(),
        )
        .expect("valid base");
        assert_eq!(
            url,
            "https://auth.example.com/.well-known/oauth-authorization-server/tenant-a"
        );
    }

    #[test]
    fn build_well_known_url_preserve_mode_drops_empty_query() {
        // A bare trailing `?` parses as `query() == Some("")`; carrying
        // it forward would serialize a lone `?` into the document URL.
        // Preserve mode still resolves the empty query to the query-less
        // URL.
        let url = build_well_known_url(
            "https://api.example.com/mcp?",
            "oauth-protected-resource",
            QueryComponent::Preserve,
            "invalid_resource",
            || "invalid resource URL".to_string(),
        )
        .expect("valid base");
        assert_eq!(
            url,
            "https://api.example.com/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn build_well_known_url_keeps_leading_empty_path_segment() {
        // §3.1 removes only the *terminating* slash. `//mcp` and `/mcp`
        // are distinct identifiers and must derive distinct documents.
        let doubled = build_well_known_url(
            "https://api.example.com//mcp",
            "oauth-protected-resource",
            QueryComponent::Preserve,
            "invalid_resource",
            || "invalid resource URL".to_string(),
        )
        .expect("valid base");
        let single = build_well_known_url(
            "https://api.example.com/mcp",
            "oauth-protected-resource",
            QueryComponent::Preserve,
            "invalid_resource",
            || "invalid resource URL".to_string(),
        )
        .expect("valid base");
        assert_eq!(
            doubled,
            "https://api.example.com/.well-known/oauth-protected-resource//mcp"
        );
        assert_eq!(
            single,
            "https://api.example.com/.well-known/oauth-protected-resource/mcp"
        );
        assert_ne!(doubled, single);
    }

    #[test]
    fn build_well_known_url_rejects_relative_base_with_supplied_code() {
        let error = build_well_known_url(
            "/relative/path",
            "oauth-authorization-server",
            QueryComponent::Strip,
            "metadata_fetch_error",
            || "issuer must be an absolute URL".to_string(),
        )
        .expect_err("relative base must be rejected");
        let AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "metadata_fetch_error");
        assert_eq!(auth_error.message, "issuer must be an absolute URL");
    }

    #[test]
    fn build_well_known_url_does_not_invoke_message_thunk_on_success() {
        // The lazy-message contract: callers can embed expensive
        // formatting (URL interpolation, etc.) in the error message
        // without paying for it on every successful parse.
        use std::cell::Cell;
        let invoked = Cell::new(false);
        let _ = build_well_known_url(
            "https://api.example.com/mcp",
            "oauth-protected-resource",
            QueryComponent::Preserve,
            "invalid_resource",
            || {
                invoked.set(true);
                "should not be called".to_string()
            },
        )
        .expect("valid base");
        assert!(
            !invoked.get(),
            "message thunk must not run on successful parse"
        );
    }
}
