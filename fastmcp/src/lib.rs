mod auth;

pub use auth::AuthplaneFastMcpTokenVerifier;

use authplane_sdk::{AuthplaneError, build_url_elicitation_payload};
use fastmcp_rust::{McpError, McpErrorCode};

/// MCP wire constant for the "URL elicitation required" error code.
/// Defined here because `fastmcp_rust` exposes the generic
/// `McpErrorCode::Custom(i32)` constructor but does not name this
/// specific code. The value (-32042) matches the MCP authorization
/// spec and `rmcp::model::ErrorCode::URL_ELICITATION_REQUIRED`.
const URL_ELICITATION_REQUIRED: i32 = -32042;

pub fn to_url_elicitation_required_error(
    error: AuthplaneError,
) -> Result<AuthplaneError, McpError> {
    let AuthplaneError::ConsentRequired(consent) = &error else {
        return Ok(error);
    };

    match build_url_elicitation_payload(consent) {
        Some(payload) => Err(McpError::with_data(
            McpErrorCode::Custom(URL_ELICITATION_REQUIRED),
            payload.message,
            payload.data,
        )),
        None => Ok(error),
    }
}

pub async fn wrap_tool_with_url_elicitation<F, Fut, T>(handler: F) -> Result<T, McpError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, AuthplaneError>>,
{
    match handler().await {
        Ok(value) => Ok(value),
        Err(error) => match to_url_elicitation_required_error(error) {
            Ok(unmapped) => Err(McpError::tool_error(unmapped.to_string())),
            Err(mapped) => Err(mapped),
        },
    }
}

#[cfg(test)]
mod tests {
    use authplane_sdk::{AuthplaneError, ConsentRequiredError, parse_token_exchange_error};

    use crate::{to_url_elicitation_required_error, wrap_tool_with_url_elicitation};

    #[test]
    fn maps_consent_error_to_url_elicitation() {
        let input = AuthplaneError::from(ConsentRequiredError {
            message: "Consent required".to_string(),
            code: "consent_required".to_string(),
            status_code: Some(400),
            service_id: "calendar".to_string(),
            cause_detail: "approval_pending".to_string(),
            consent_url: Some("https://example.com/consent".to_string()),
        });

        let mapped = to_url_elicitation_required_error(input);
        let err = mapped.expect_err("must map to MCP url elicitation");

        assert_eq!(i32::from(err.code), -32042);
        let data = err.data.expect("data should exist");
        assert!(data["elicitations"][0]["mode"] == "url");
    }

    #[tokio::test]
    async fn wrapper_maps_non_consent_errors_to_tool_error() {
        let result = wrap_tool_with_url_elicitation(|| async {
            Err::<u32, _>(AuthplaneError::Auth(authplane_sdk::AuthError {
                message: "nope".to_string(),
                code: "invalid_request".to_string(),
                status_code: Some(400),
            }))
        })
        .await;

        let err = result.expect_err("must map to mcp error");
        assert_eq!(i32::from(err.code), -32000);
    }

    #[tokio::test]
    async fn end_to_end_token_exchange_to_url_elicitation() {
        let payload = r#"{
            "error":"interaction_required",
            "error_description":"User action required",
            "service":"drive",
            "consent_url":"https://example.com/consent"
        }"#;

        let result = wrap_tool_with_url_elicitation(|| async {
            Err::<(), _>(parse_token_exchange_error(Some(400), payload))
        })
        .await;

        let err = result.expect_err("must map to url elicitation");
        assert_eq!(i32::from(err.code), -32042);
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
