use authplane_sdk::{AuthplaneError, parse_token_exchange_error};

fn main() {
    let payload = r#"{
      "error":"consent_required",
      "error_description":"Consent required for this service",
      "service_id":"drive",
      "cause":"approval_pending",
      "consent_url":"https://example.com/consent"
    }"#;

    match parse_token_exchange_error(Some(400), payload) {
        AuthplaneError::ConsentRequired(err) => {
            println!("consent_url={:?}", err.consent_url);
        }
        AuthplaneError::Auth(err) => {
            println!("oauth error {}: {}", err.code, err.message);
        }
        AuthplaneError::CircuitOpen => {
            println!("circuit breaker open");
        }
        // `AuthplaneError` is `#[non_exhaustive]`: consumers must leave room
        // for variants a future release may add.
        other => {
            println!("unhandled error: {other}");
        }
    }
}
