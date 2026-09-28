mod auth;

pub use auth::{AuthplaneMcpAuth, authplane_mcp_auth_middleware, dpop_request_context_from_axum};

use authplane_sdk::{AuthplaneError, build_url_elicitation_payload};
use rmcp::model::ErrorData;

/// Newtype wrapping the raw access-token JWT presented by the caller.
///
/// MCP tool handlers that delegate to AuthPlane's token-exchange flow need
/// the original JWT for the `subject_token` field. The verified-claims
/// extension (`VerifiedClaims`) intentionally drops the raw token, so
/// middleware that authenticates a request should stash it alongside the
/// claims as `RawAccessToken` for downstream extraction.
///
/// Transparent wrapper per the API convention documented in
/// [`CONTRIBUTING.md`]: the inner `String` is `pub` because there are no
/// invariants to enforce — the JWT shape is enforced by the verifier, not
/// by this wrapper. Compare with `InboundDPoPOptions`, which carries
/// validation invariants and keeps its fields private.
///
/// Exported here so consumers don't reinvent the newtype in each codebase.
/// See `demo/http_calculator_demo.rs` for the wiring pattern.
///
/// [`CONTRIBUTING.md`]: https://github.com/AuthPlane/rust-sdk/blob/main/CONTRIBUTING.md
#[derive(Clone, Debug)]
pub struct RawAccessToken(pub String);

impl RawAccessToken {
    /// View the underlying JWT string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the owned JWT string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for RawAccessToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

pub fn to_url_elicitation_required_error(
    error: AuthplaneError,
) -> Result<AuthplaneError, ErrorData> {
    let AuthplaneError::ConsentRequired(consent) = &error else {
        return Ok(error);
    };

    match build_url_elicitation_payload(consent) {
        Some(payload) => Err(ErrorData::url_elicitation_required(
            payload.message,
            Some(payload.data),
        )),
        None => Ok(error),
    }
}

pub async fn wrap_tool_with_url_elicitation<F, Fut, T>(handler: F) -> Result<T, ErrorData>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, AuthplaneError>>,
{
    match handler().await {
        Ok(value) => Ok(value),
        Err(error) => match to_url_elicitation_required_error(error) {
            Ok(unmapped) => Err(ErrorData::internal_error(unmapped.to_string(), None)),
            Err(mapped) => Err(mapped),
        },
    }
}

#[cfg(test)]
mod tests {
    use authplane_sdk::{AuthplaneError, ConsentRequiredError, parse_token_exchange_error};
    use rmcp::model::ErrorCode;

    use crate::{to_url_elicitation_required_error, wrap_tool_with_url_elicitation};

    #[test]
    fn maps_consent_error_to_url_elicitation() {
        let input = AuthplaneError::from(ConsentRequiredError {
            message: "Consent required".to_string(),
            code: "consent_required".to_string(),
            status_code: Some(400),
            service_id: "drive".to_string(),
            cause_detail: "approval_pending".to_string(),
            consent_url: Some("https://example.com/consent".to_string()),
        });

        let mapped = to_url_elicitation_required_error(input);
        let err = mapped.expect_err("must map to MCP url elicitation");

        assert_eq!(err.code, ErrorCode::URL_ELICITATION_REQUIRED);
        let data = err.data.expect("data should exist");
        assert!(data["elicitations"][0]["url"] == "https://example.com/consent");
    }

    #[tokio::test]
    async fn wrapper_passes_success() {
        let result = wrap_tool_with_url_elicitation(|| async { Ok::<_, AuthplaneError>(42_u32) })
            .await
            .expect("must succeed");
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn end_to_end_token_exchange_to_url_elicitation() {
        let payload = r#"{
            "error":"consent_required",
            "error_description":"Consent needed",
            "service_id":"calendar",
            "cause":"approval_pending",
            "consent_url":"https://example.com/consent"
        }"#;

        let result = wrap_tool_with_url_elicitation(|| async {
            Err::<(), _>(parse_token_exchange_error(Some(400), payload))
        })
        .await;

        let err = result.expect_err("must map to url elicitation");
        assert_eq!(err.code, ErrorCode::URL_ELICITATION_REQUIRED);
        assert_eq!(
            err.data.expect("must include data")["elicitations"][0]["mode"],
            "url"
        );
    }

    #[test]
    fn non_consent_error_is_passthrough() {
        let input = AuthplaneError::Auth(authplane_sdk::AuthError {
            message: "scope denied".to_string(),
            code: "invalid_scope".to_string(),
            status_code: Some(400),
        });
        let passthrough =
            to_url_elicitation_required_error(input).expect("non-consent errors must pass through");
        let AuthplaneError::Auth(auth_error) = passthrough else {
            panic!("expected auth error passthrough")
        };
        assert_eq!(auth_error.code, "invalid_scope");
    }

    #[test]
    fn consent_without_url_is_passthrough() {
        let input = AuthplaneError::from(ConsentRequiredError {
            message: "Consent required".to_string(),
            code: "consent_required".to_string(),
            status_code: Some(400),
            service_id: "drive".to_string(),
            cause_detail: "approval_pending".to_string(),
            consent_url: None,
        });
        assert!(to_url_elicitation_required_error(input).is_ok());
    }

    #[test]
    fn missing_fields_use_defaults() {
        let input = AuthplaneError::from(ConsentRequiredError {
            message: String::new(),
            code: "consent_required".to_string(),
            status_code: Some(400),
            service_id: String::new(),
            cause_detail: String::new(),
            consent_url: Some("https://example.com/consent".to_string()),
        });
        let mapped = to_url_elicitation_required_error(input).expect_err("must map");
        let data = mapped.data.expect("must include data");
        let message = data["elicitations"][0]["message"]
            .as_str()
            .expect("message string");
        assert!(message.contains("unknown_service"));
        assert!(message.contains("Consent is required to proceed"));
    }
}
