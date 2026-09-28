use serde::{Deserialize, Serialize};

use crate::errors::{QueryComponent, build_well_known_url, metadata_error, normalize_issuer};
use crate::transport::validate_fetch_url;
use crate::{AuthplaneError, FetchSettings};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub introspection_endpoint: Option<String>,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
}

impl AuthorizationServerMetadata {
    pub fn validate(
        &self,
        expected_issuer: &str,
        settings: &FetchSettings,
    ) -> Result<(), AuthplaneError> {
        let normalized_expected = normalize_issuer(expected_issuer);
        let normalized_actual = normalize_issuer(&self.issuer);

        if normalized_actual.is_empty() {
            return Err(metadata_error(
                "AS metadata missing required 'issuer' field",
            ));
        }
        if !normalized_expected.is_empty() && normalized_actual != normalized_expected {
            return Err(metadata_error(&format!(
                "AS metadata issuer mismatch: expected {normalized_expected:?}, got {normalized_actual:?}"
            )));
        }

        validate_endpoint_url("jwks_uri", &self.jwks_uri, settings)?;
        if let Some(value) = self.token_endpoint.as_deref() {
            validate_endpoint_url("token_endpoint", value, settings)?;
        }
        if let Some(value) = self.introspection_endpoint.as_deref() {
            validate_endpoint_url("introspection_endpoint", value, settings)?;
        }
        if let Some(value) = self.revocation_endpoint.as_deref() {
            validate_endpoint_url("revocation_endpoint", value, settings)?;
        }
        Ok(())
    }

    pub fn token_endpoint(&self) -> Result<&str, AuthplaneError> {
        self.token_endpoint
            .as_deref()
            .ok_or_else(|| missing_endpoint_error("token_endpoint"))
    }

    pub fn introspection_endpoint(&self) -> Result<&str, AuthplaneError> {
        self.introspection_endpoint
            .as_deref()
            .ok_or_else(|| missing_endpoint_error("introspection_endpoint"))
    }

    pub fn revocation_endpoint(&self) -> Result<&str, AuthplaneError> {
        self.revocation_endpoint
            .as_deref()
            .ok_or_else(|| missing_endpoint_error("revocation_endpoint"))
    }
}

pub fn build_metadata_url(issuer: &str) -> Result<String, AuthplaneError> {
    // RFC 8414 §2 gives the issuer identifier no query or fragment
    // components, so a query on the input is out-of-spec noise and is
    // dropped rather than carried into the metadata URL.
    build_well_known_url(
        issuer,
        "oauth-authorization-server",
        QueryComponent::Strip,
        "metadata_fetch_error",
        || "issuer must be an absolute URL".to_string(),
    )
}

fn validate_endpoint_url(
    field: &str,
    value: &str,
    settings: &FetchSettings,
) -> Result<(), AuthplaneError> {
    validate_fetch_url(value, settings, &format!("AS metadata field {field:?}")).map_err(|_| {
        metadata_error(&format!(
            "AS metadata field {field:?} failed fetch validation: {value:?}"
        ))
    })
}

fn missing_endpoint_error(field: &str) -> AuthplaneError {
    crate::errors::auth_error(
        "missing_metadata_endpoint",
        &format!("AS metadata missing required '{field}' field"),
    )
}

#[cfg(test)]
mod tests {
    use super::{AuthorizationServerMetadata, build_metadata_url};
    use crate::FetchSettings;

    #[test]
    fn metadata_url_inserts_well_known_before_issuer_path() {
        let url =
            build_metadata_url("https://auth.example.com/team-a").expect("valid metadata url");
        assert_eq!(
            url,
            "https://auth.example.com/.well-known/oauth-authorization-server/team-a"
        );
    }

    #[test]
    fn validation_rejects_non_https_endpoints_in_prod_mode() {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "http://auth.example.com/jwks".to_string(),
            token_endpoint: None,
            introspection_endpoint: None,
            revocation_endpoint: None,
        };

        let error = metadata
            .validate("https://auth.example.com", &FetchSettings::default())
            .expect_err("http jwks should fail");
        let crate::AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "metadata_fetch_error");
    }

    #[test]
    fn token_endpoint_accessor_requires_field() {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/jwks".to_string(),
            token_endpoint: None,
            introspection_endpoint: None,
            revocation_endpoint: None,
        };
        let error = metadata
            .token_endpoint()
            .expect_err("missing token endpoint");
        let crate::AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "missing_metadata_endpoint");
    }

    #[test]
    fn metadata_url_for_root_issuer_has_no_suffix_path() {
        let url = build_metadata_url("https://auth.example.com").expect("valid metadata url");
        assert_eq!(
            url,
            "https://auth.example.com/.well-known/oauth-authorization-server"
        );
    }

    #[test]
    fn metadata_url_strips_trailing_slash_before_injecting_well_known() {
        let url =
            build_metadata_url("https://auth.example.com/tenant-a/").expect("valid metadata url");
        assert_eq!(
            url,
            "https://auth.example.com/.well-known/oauth-authorization-server/tenant-a"
        );
    }

    #[test]
    fn metadata_url_drops_query_and_fragment() {
        let url = build_metadata_url("https://auth.example.com/tenant-a?q=1#frag")
            .expect("valid metadata url");
        assert_eq!(
            url,
            "https://auth.example.com/.well-known/oauth-authorization-server/tenant-a"
        );
    }

    #[test]
    fn metadata_url_rejects_non_absolute_issuer() {
        let error = build_metadata_url("/relative/path").expect_err("relative issuer rejected");
        let crate::AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "metadata_fetch_error");
    }

    #[test]
    fn validate_accepts_issuer_with_equivalent_trailing_slash() {
        // RFC 8414 §2 issuer normalization: a trailing `/` on the
        // configured issuer must match metadata whose `issuer` field
        // does not include one (and vice versa).
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com/".to_string(),
            jwks_uri: "https://auth.example.com/jwks.json".to_string(),
            token_endpoint: None,
            introspection_endpoint: None,
            revocation_endpoint: None,
        };
        metadata
            .validate("https://auth.example.com", &FetchSettings::default())
            .expect("trailing-slash issuer must be treated as equal");
    }

    #[test]
    fn validate_accepts_expected_issuer_with_trailing_slash() {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/jwks.json".to_string(),
            token_endpoint: None,
            introspection_endpoint: None,
            revocation_endpoint: None,
        };
        metadata
            .validate("https://auth.example.com/", &FetchSettings::default())
            .expect("trailing-slash on expected issuer must be treated as equal");
    }

    #[test]
    fn validate_rejects_completely_different_issuer() {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://attacker.example.net".to_string(),
            jwks_uri: "https://auth.example.com/jwks.json".to_string(),
            token_endpoint: None,
            introspection_endpoint: None,
            revocation_endpoint: None,
        };
        let error = metadata
            .validate("https://auth.example.com", &FetchSettings::default())
            .expect_err("issuer mismatch must be rejected");
        let crate::AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "metadata_fetch_error");
        assert!(auth_error.message.contains("issuer mismatch"));
    }

    #[test]
    fn validate_happy_path_accepts_full_metadata() {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/jwks.json".to_string(),
            token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
            introspection_endpoint: Some("https://auth.example.com/oauth/introspect".to_string()),
            revocation_endpoint: Some("https://auth.example.com/oauth/revoke".to_string()),
        };
        metadata
            .validate("https://auth.example.com", &FetchSettings::default())
            .expect("fully populated https metadata must validate");
    }

    #[test]
    fn introspection_endpoint_accessor_requires_field() {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/jwks.json".to_string(),
            token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
            introspection_endpoint: None,
            revocation_endpoint: None,
        };
        let error = metadata
            .introspection_endpoint()
            .expect_err("missing introspection endpoint must fail");
        let crate::AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "missing_metadata_endpoint");
    }

    #[test]
    fn revocation_endpoint_accessor_requires_field() {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            jwks_uri: "https://auth.example.com/jwks.json".to_string(),
            token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
            introspection_endpoint: None,
            revocation_endpoint: None,
        };
        let error = metadata
            .revocation_endpoint()
            .expect_err("missing revocation endpoint must fail");
        let crate::AuthplaneError::Auth(auth_error) = error else {
            panic!("expected auth error");
        };
        assert_eq!(auth_error.code, "missing_metadata_endpoint");
    }
}
