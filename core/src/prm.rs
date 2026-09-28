use serde::{Deserialize, Serialize};

use crate::AuthplaneError;
use crate::errors::{QueryComponent, auth_error, build_well_known_url};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens_required: Option<bool>,
}

pub fn build_prm(
    issuer: &str,
    resource: &str,
    scopes: &[String],
    dpop_algs: Option<&[String]>,
    dpop_required: bool,
) -> ProtectedResourceMetadata {
    // Three documented modes:
    //   * Mode 1 — DPoP required: `dpop_algs = Some([..]), dpop_required = true`
    //     ⇒ both fields emitted.
    //   * Mode 2 — DPoP accepted: `dpop_algs = Some([..]), dpop_required = false`
    //     ⇒ algs emitted, required=false emitted explicitly.
    //   * Mode 3 — Bearer-only: `dpop_algs = None, dpop_required = false`
    //     ⇒ both fields omitted from the PRM JSON.
    //
    // The original `dpop_algs.map(|_| dpop_required)` silently collapsed
    // a `(None, true)` mis-call to `None` — a Bearer-permissive PRM
    // emitted on a resource that the verifier was treating as
    // DPoP-required. We surface the (None, true) case as an explicit
    // `dpop_bound_access_tokens_required: true` so the misconfiguration
    // is visible to clients even when the operator forgot to also
    // declare an algorithm list. This diverges on the safer side from
    // the prior gate-both-on-algs-present shape; aligning the rest of
    // the surface is a separate follow-up.
    let dpop_required_field = if dpop_algs.is_some() || dpop_required {
        Some(dpop_required)
    } else {
        None
    };

    ProtectedResourceMetadata {
        resource: resource.to_string(),
        authorization_servers: vec![issuer.to_string()],
        bearer_methods_supported: vec!["header".to_string()],
        scopes_supported: scopes.to_vec(),
        dpop_signing_alg_values_supported: dpop_algs.map(|items| items.to_vec()),
        dpop_bound_access_tokens_required: dpop_required_field,
    }
}

/// Require the resource identifier to be an absolute URL with both a
/// scheme and a host, and free of the components RFC 8707 §2 forbids.
///
/// The scheme comes from RFC 8707 §2: the value "MUST be an absolute
/// URI, as specified by Section 4.3 of [RFC3986]", whose grammar makes
/// the scheme mandatory and excludes a fragment. The host comes from
/// RFC 9728 §3, which derives the metadata document URL by inserting
/// the well-known suffix after the host component — an identifier
/// without a host gives that insertion nowhere to anchor and previously
/// produced a malformed document URL instead of an error.
///
/// Every check runs on the **raw string**, before any parse, because
/// the WHATWG parser behind `url::Url::parse` judges a *cleaned* value,
/// not the identifier that is stored verbatim and served in the PRM
/// `resource` member:
///
/// * it splits the fragment off, so a parse-based check never sees it;
/// * it synthesizes an authority for a special scheme written without
///   `//` (`https:example.com/mcp` parses with `host = example.com`,
///   an identifier RFC 3986 gives no authority at all);
/// * it strips ASCII tab/CR/LF anywhere in the input and trims leading
///   C0-or-space before parsing, so a whitespace-bearing identifier
///   would pass a parse-based gate while being stored with the
///   whitespace.
///
/// Any such divergence between the stored identifier and the derived
/// document URL is exactly the byte-for-byte mismatch RFC 9728 §3.3
/// obliges a conformant client to discard. The checks run in a fixed
/// order — fragment first — so an identifier wrong in more than one way
/// reports deterministically.
///
/// The scheme is required but not narrowed: `http://localhost:8080/mcp`
/// stays accepted as a deliberate profile relaxation so local
/// development loops keep working — this gate is not an https-only
/// check.
pub(crate) fn validate_resource_identifier(resource: &str) -> Result<(), AuthplaneError> {
    // The rejected value is not echoed in any of these messages: a
    // malformed identifier can carry userinfo (`//user:pass@host/path`),
    // and the messages reach startup logs.
    let reject = |message| auth_error("invalid_resource", message);

    // Fragment first — RFC 8707 §2 forbids it outright ("The URI MUST
    // NOT include a fragment component"; RFC 9728 §1.2 repeats it for
    // the resource identifier). Checked on the raw string because
    // `Url::parse` splits the fragment off.
    if resource.contains('#') {
        return Err(reject(
            "resource identifier must not include a fragment component (RFC 8707 section 2; RFC 9728 section 1.2)",
        ));
    }

    // Whitespace or control characters anywhere in the identifier: the
    // parser would strip or trim them and validate the cleaned string,
    // while the identifier is stored and advertised with them intact.
    if resource
        .chars()
        .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
    {
        return Err(reject(
            "resource identifier must not contain whitespace or control characters",
        ));
    }

    // Anchored `scheme://authority` shape on the raw string. This is
    // what rejects a relative reference (`/mcp`), a scheme-relative one
    // (`//api.example.com/mcp`), an opaque identifier (`urn:example:api`
    // — no authority for RFC 9728 §3 to anchor the well-known suffix
    // to), and the authority-less special-scheme form
    // (`https:example.com/mcp`) the parser would silently repair.
    let Some(authority) = explicit_authority(resource) else {
        return Err(reject(
            "resource identifier must be an absolute URL with a scheme and a host",
        ));
    };

    // Userinfo — RFC 9110 section 4.2.4 deprecates it and tells
    // recipients to treat its presence as an error; letting it through
    // would carry the credential verbatim into the PRM `resource`
    // member served to unauthenticated callers.
    if authority.contains('@') {
        return Err(reject(
            "resource identifier must not include userinfo in its authority (RFC 9110 section 4.2.4)",
        ));
    }

    // Defensive backstop: the identifier must still parse and expose a
    // host. This catches what the raw-string shape cannot express, e.g.
    // an empty authority (`foo:///path`).
    let parsed = url::Url::parse(resource).map_err(|_| {
        reject("resource identifier must be an absolute URL with a scheme and a host")
    })?;
    if !parsed.has_host() {
        return Err(reject(
            "resource identifier must be an absolute URL with a scheme and a host",
        ));
    }
    Ok(())
}

/// Split off the authority component of an identifier written in the
/// explicit `scheme://authority[/path][?query]` form. Returns `None`
/// when the `://` marker is missing or the scheme violates the RFC 3986
/// §3.1 grammar (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`).
fn explicit_authority(resource: &str) -> Option<&str> {
    let (scheme, rest) = resource.split_once("://")?;
    let mut scheme_chars = scheme.chars();
    if !scheme_chars.next()?.is_ascii_alphabetic() {
        return None;
    }
    if !scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&rest[..authority_end])
}

/// RFC 9728 §3 — derive the well-known PRM document URL from the
/// resource identifier by inserting the suffix "between the host
/// component and the path and/or query components, if any". The
/// identifier's query, when present, survives into the derived URL:
/// RFC 8707 §2 states the SHOULD NOT and its scoping exception in the
/// same sentence, and RFC 9728 §1.2 carries that carve-out forward, so
/// two identifiers differing only by query must not collapse onto one
/// document URL. A bare trailing `?` (empty query) is the exception:
/// it identifies nothing and derives the query-less URL.
pub fn build_prm_url(resource: &str) -> Result<String, AuthplaneError> {
    // Defensive backstop for direct callers. The authoritative gate runs
    // at construction time in `AuthplaneResource::from_parts` /
    // `from_prefetched_metadata`, so a resource that exists at all can
    // always derive its document URL.
    validate_resource_identifier(resource)?;
    build_well_known_url(
        resource,
        "oauth-protected-resource",
        QueryComponent::Preserve,
        "invalid_resource",
        || format!("invalid resource URL: {resource}"),
    )
}

#[cfg(test)]
mod tests {
    use super::{build_prm, build_prm_url};

    #[test]
    fn prm_builder_keeps_expected_fields() {
        let prm = build_prm(
            "https://auth.example.com",
            "https://api.example.com/mcp",
            &["tools/read".to_string()],
            Some(&["ES256".to_string()]),
            true,
        );

        assert_eq!(prm.resource, "https://api.example.com/mcp");
        assert_eq!(
            prm.authorization_servers,
            vec!["https://auth.example.com".to_string()]
        );
        assert_eq!(prm.bearer_methods_supported, vec!["header".to_string()]);
        assert_eq!(
            prm.dpop_signing_alg_values_supported,
            Some(vec!["ES256".to_string()])
        );
        assert_eq!(prm.dpop_bound_access_tokens_required, Some(true));
    }

    #[test]
    fn prm_url_inserts_well_known_before_path() {
        let url = build_prm_url("https://api.example.com/v1/mcp").expect("valid prm url");
        assert_eq!(
            url,
            "https://api.example.com/.well-known/oauth-protected-resource/v1/mcp"
        );
    }

    #[test]
    fn prm_url_preserves_resource_query() {
        // RFC 9728 §3: the suffix goes between the host and "the path
        // and/or query components, if any" — the query is part of the
        // derived document URL.
        let url = build_prm_url("https://api.example.com/mcp?tenant=a").expect("valid prm url");
        assert_eq!(
            url,
            "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a"
        );
    }

    #[test]
    fn prm_url_query_only_resource_appends_suffix_directly_after_host() {
        // No path and no terminating slash: §3.1 has no slash to remove,
        // the suffix follows the host directly, and the query follows it.
        let url = build_prm_url("https://api.example.com?x=1").expect("valid prm url");
        assert_eq!(
            url,
            "https://api.example.com/.well-known/oauth-protected-resource?x=1"
        );
    }

    #[test]
    fn prm_url_removes_terminating_slash_before_query() {
        // §3.1 removes the terminating "/", so this derives the same URL
        // as the slash-less form above.
        let url = build_prm_url("https://api.example.com/?x=1").expect("valid prm url");
        assert_eq!(
            url,
            "https://api.example.com/.well-known/oauth-protected-resource?x=1"
        );
    }

    #[test]
    fn prm_url_treats_bare_trailing_question_mark_as_no_query() {
        // An empty query identifies nothing: `?` alone resolves to the
        // same document URL as the query-less identifier, not to a URL
        // ending in a lone `?` that no client would re-derive.
        let url = build_prm_url("https://api.example.com/mcp?").expect("valid prm url");
        assert_eq!(
            url,
            "https://api.example.com/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn prm_url_removes_terminating_slash_from_path() {
        // §3.1 removes the terminating "/" from a non-root path too —
        // the trailing-slash and slash-less forms derive one document.
        let url = build_prm_url("https://api.example.com/mcp/").expect("valid prm url");
        assert_eq!(
            url,
            "https://api.example.com/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn prm_url_removes_all_terminating_slashes_from_path() {
        // Only *trailing* slashes come off; doubled ones at the end are
        // normalization noise, unlike the leading `//mcp` case below.
        let url = build_prm_url("https://api.example.com/mcp//").expect("valid prm url");
        assert_eq!(
            url,
            "https://api.example.com/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn prm_url_keeps_query_distinct_identifiers_distinct() {
        // Two identifiers differing only by query must not collapse onto
        // one metadata document URL (the multi-tenant case RFC 8707 §2
        // names as the reason a query can be necessary).
        let tenant_a = build_prm_url("https://api.example.com/mcp?tenant=a").expect("valid");
        let tenant_b = build_prm_url("https://api.example.com/mcp?tenant=b").expect("valid");
        assert_ne!(tenant_a, tenant_b);
    }

    const ABSOLUTE_URL_MESSAGE: &str =
        "resource identifier must be an absolute URL with a scheme and a host";
    const FRAGMENT_MESSAGE: &str = "resource identifier must not include a fragment component";
    const WHITESPACE_MESSAGE: &str =
        "resource identifier must not contain whitespace or control characters";
    const USERINFO_MESSAGE: &str = "resource identifier must not include userinfo";

    fn assert_rejects_as_invalid_resource(resource: &str, expected_message: &str) {
        let error = build_prm_url(resource).expect_err("resource must be rejected");
        let crate::AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "invalid_resource");
        assert!(
            auth_error.message.contains(expected_message),
            "unexpected message: {}",
            auth_error.message
        );
    }

    #[test]
    fn prm_url_rejects_relative_resource() {
        // RFC 8707 §2: the value MUST be an absolute URI (RFC 3986 §4.3),
        // so a relative reference has no scheme to satisfy the grammar.
        assert_rejects_as_invalid_resource("/mcp", ABSOLUTE_URL_MESSAGE);
    }

    #[test]
    fn prm_url_rejects_scheme_relative_resource() {
        // A scheme-relative reference carries an authority, so a guard
        // asking only "opaque or authority-less?" would admit it — the
        // missing component is the scheme, and it must reject on its
        // own.
        assert_rejects_as_invalid_resource("//api.example.com/mcp", ABSOLUTE_URL_MESSAGE);
    }

    #[test]
    fn prm_url_rejects_opaque_resource_without_host() {
        // No authority at all, so RFC 9728 §3 has no insertion point for
        // the well-known suffix. Previously this derived a garbled
        // document URL instead of erroring.
        assert_rejects_as_invalid_resource("urn:example:api", ABSOLUTE_URL_MESSAGE);
    }

    #[test]
    fn prm_url_rejects_fragment_bearing_resource() {
        // RFC 8707 §2: "The URI MUST NOT include a fragment component";
        // RFC 9728 §1.2 repeats it. The WHATWG parser splits the
        // fragment off, so this must be caught on the raw string — a
        // parse-based gate accepted it while `build_well_known_url`
        // stripped the fragment from the derived document URL, leaving
        // the stored identifier and the document URL to disagree
        // byte-for-byte.
        assert_rejects_as_invalid_resource("https://api.example.com/mcp#v2", FRAGMENT_MESSAGE);
    }

    #[test]
    fn prm_url_reports_fragment_first_on_doubly_invalid_resource() {
        // Wrong in two ways (no scheme, fragment present): the fragment
        // check runs first, so the report is deterministic.
        assert_rejects_as_invalid_resource("//api.example.com/mcp#v2", FRAGMENT_MESSAGE);
    }

    #[test]
    fn prm_url_rejects_authority_less_special_scheme_form() {
        // RFC 3986 gives `https:example.com/mcp` no authority
        // (`hier-part = path-rootless`), but the WHATWG parser
        // synthesizes one: `Url::parse` yields `host = example.com` and
        // serializes as `https://example.com/mcp`. A parse-based gate
        // therefore accepted an identifier its own message claims to
        // reject, and the stored-verbatim identifier differed from the
        // derived document URL. The anchored `scheme://` check on the
        // raw string closes this.
        assert_rejects_as_invalid_resource("https:example.com/mcp", ABSOLUTE_URL_MESSAGE);
    }

    #[test]
    fn prm_url_rejects_whitespace_in_resource() {
        // The WHATWG parser strips ASCII tab/CR/LF anywhere in the input
        // (`https://api.exa\tmple.com/mcp` parses to
        // `https://api.example.com/mcp`) and trims leading C0-or-space,
        // so a parse-based gate accepted identifiers that are stored and
        // advertised with the whitespace intact.
        assert_rejects_as_invalid_resource("https://api.exa\tmple.com/mcp", WHITESPACE_MESSAGE);
        assert_rejects_as_invalid_resource(" https://api.example.com/mcp", WHITESPACE_MESSAGE);
    }

    #[test]
    fn prm_url_rejects_userinfo_in_authority() {
        // RFC 9110 §4.2.4 deprecates userinfo and tells recipients to
        // treat its presence as an error. The `url` crate preserves
        // userinfo across `set_path` + `to_string`, so before this gate
        // the credential reached both the derived document URL and —
        // verbatim — the `resource` member of the PRM document served to
        // unauthenticated callers.
        assert_rejects_as_invalid_resource("https://svc:pw@api.example.com/mcp", USERINFO_MESSAGE);
    }

    #[test]
    fn prm_url_rejects_empty_authority() {
        // Passes the `scheme://` shape check but parses with no host —
        // the defensive `has_host` backstop still rejects it.
        assert_rejects_as_invalid_resource("foo:///mcp", ABSOLUTE_URL_MESSAGE);
    }

    #[test]
    fn prm_url_accepts_http_localhost() {
        // Scheme and host are required but the scheme is not narrowed:
        // plain-http local development hosts stay accepted.
        let url = build_prm_url("http://localhost:8080/mcp").expect("http localhost accepted");
        assert_eq!(
            url,
            "http://localhost:8080/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn prm_url_keeps_doubled_leading_slash_distinct() {
        // §3.1 only removes the *terminating* slash; `//mcp` and `/mcp`
        // are distinct identifiers and must derive distinct documents.
        let doubled = build_prm_url("https://api.example.com//mcp").expect("valid prm url");
        let single = build_prm_url("https://api.example.com/mcp").expect("valid prm url");
        assert_eq!(
            doubled,
            "https://api.example.com/.well-known/oauth-protected-resource//mcp"
        );
        assert_ne!(doubled, single);
    }

    /// Regression: `dpop_bound_access_tokens_required` MUST NOT depend on
    /// `dpop_algs` being `Some`. The previous `dpop_algs.map(|_| required)`
    /// silently dropped the `required = true` flag when the caller passed
    /// no algorithms — the PRM then advertised neither algorithms nor a
    /// requirement, leaving a Bearer-permissive document on a
    /// DPoP-required resource. The (None, true) case is now emitted
    /// explicitly so the misconfiguration is visible to clients.
    #[test]
    fn prm_required_flag_survives_when_no_algs_given() {
        let prm = build_prm(
            "https://auth.example.com",
            "https://api.example.com/mcp",
            &[],
            None,
            true,
        );
        assert_eq!(prm.dpop_signing_alg_values_supported, None);
        assert_eq!(prm.dpop_bound_access_tokens_required, Some(true));
    }

    /// Mode 3 — Bearer-only resource omits both DPoP fields from the
    /// PRM JSON. This stays the same as the original behaviour and is
    /// covered by `rfc9728_prm_must_advertise_dpop_required_when_resource_requires_dpop`
    /// in the conformance suite; the regression here is just locking in
    /// the local invariant alongside the Mode-1 fix above.
    #[test]
    fn prm_omits_both_fields_for_bearer_only_mode() {
        let prm = build_prm(
            "https://auth.example.com",
            "https://api.example.com/mcp",
            &[],
            None,
            false,
        );
        assert_eq!(prm.dpop_signing_alg_values_supported, None);
        assert_eq!(prm.dpop_bound_access_tokens_required, None);
    }
}
