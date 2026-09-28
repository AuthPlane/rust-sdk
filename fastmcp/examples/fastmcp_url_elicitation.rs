use authplane_fastmcp::wrap_tool_with_url_elicitation;
use authplane_sdk::{AuthplaneError, ConsentRequiredError};

#[tokio::main]
async fn main() {
    let result = wrap_tool_with_url_elicitation(|| async {
        Err::<(), _>(AuthplaneError::from(ConsentRequiredError {
            message: "Consent needed".to_string(),
            code: "consent_required".to_string(),
            status_code: Some(400),
            service_id: "calendar".to_string(),
            cause_detail: "approval_pending".to_string(),
            consent_url: Some("https://example.com/consent".to_string()),
        }))
    })
    .await;

    println!("{result:?}");
}
