//! MCP "URL elicitation" payload builder.
//!
//! Both `authplane-mcp` and `authplane-fastmcp` need to convert an
//! [`AuthplaneError::ConsentRequired`] into an MCP "URL elicitation"
//! response that asks the caller to visit a consent URL and retry.
//! The two adapters used to ship byte-for-byte duplicates of the
//! payload-construction logic; the only thing they disagreed on was
//! the final MCP error type to wrap the payload in.
//!
//! This module owns the payload shape so both adapters consume the
//! same source of truth. A future protocol-level change (additional
//! elicitation fields, multi-step flows) lands here and the adapters
//! pick it up automatically.

use serde_json::{Value, json};
use uuid::Uuid;

use crate::errors::ConsentRequiredError;

/// Default user-facing message when the AS did not supply one.
pub const DEFAULT_CONSENT_MESSAGE: &str = "Consent is required to proceed";

/// Fallback `service_id` placeholder when the AS did not name a service.
pub const UNKNOWN_SERVICE_ID: &str = "unknown_service";

/// Payload returned by [`build_url_elicitation_payload`].
///
/// `message` is the human-readable string to set as the MCP error
/// message; `data` is the structured `elicitations` envelope.
///
/// `#[non_exhaustive]` so a future protocol update (multi-step flows, a
/// `kind` discriminant for non-URL elicitation modes) can add fields
/// without a major-version break for downstream crates. Today's adapters
/// destructure by name (not exhaustively), so this is forward-compatible.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UrlElicitationPayload {
    pub message: String,
    pub data: Value,
}

/// Build the MCP "URL elicitation" payload from a `ConsentRequiredError`.
///
/// Returns `None` when the consent error does not carry a `consent_url`
/// (the adapter should pass the error through unchanged so the caller
/// sees the original `ConsentRequiredError`).
///
/// The returned `data` matches the MCP wire shape:
///
/// ```json
/// {
///   "elicitations": [{
///     "mode": "url",
///     "url": "<consent_url>",
///     "elicitationId": "<uuid v4>",
///     "message": "<message> (<service_id>: <cause_detail>)"
///   }]
/// }
/// ```
///
/// Each call produces a fresh `elicitationId` (UUID v4) so retried
/// consent prompts are distinguishable on the client side.
pub fn build_url_elicitation_payload(
    consent: &ConsentRequiredError,
) -> Option<UrlElicitationPayload> {
    let consent_url = consent.consent_url.as_ref()?;

    let message = if consent.message.is_empty() {
        DEFAULT_CONSENT_MESSAGE.to_string()
    } else {
        consent.message.clone()
    };
    let service_id = if consent.service_id.is_empty() {
        UNKNOWN_SERVICE_ID.to_string()
    } else {
        consent.service_id.clone()
    };
    let cause_detail = if consent.cause_detail.is_empty() {
        message.clone()
    } else {
        consent.cause_detail.clone()
    };

    let data = json!({
        "elicitations": [{
            "mode": "url",
            "url": consent_url,
            "elicitationId": Uuid::new_v4().to_string(),
            "message": format!("{message} ({service_id}: {cause_detail})"),
        }]
    });

    Some(UrlElicitationPayload { message, data })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consent(
        url: Option<&str>,
        message: &str,
        service_id: &str,
        cause: &str,
    ) -> ConsentRequiredError {
        ConsentRequiredError {
            message: message.to_string(),
            code: "consent_required".to_string(),
            status_code: Some(400),
            service_id: service_id.to_string(),
            cause_detail: cause.to_string(),
            consent_url: url.map(ToString::to_string),
        }
    }

    #[test]
    fn returns_none_when_consent_url_missing() {
        let result = build_url_elicitation_payload(&consent(None, "msg", "svc", "cause"));
        assert!(result.is_none());
    }

    #[test]
    fn populates_payload_with_supplied_fields() {
        let payload = build_url_elicitation_payload(&consent(
            Some("https://example.com/consent"),
            "Approve to continue",
            "drive",
            "approval_pending",
        ))
        .expect("payload");

        assert_eq!(payload.message, "Approve to continue");
        let data = payload.data;
        assert_eq!(data["elicitations"][0]["mode"], "url");
        assert_eq!(
            data["elicitations"][0]["url"],
            "https://example.com/consent"
        );
        let msg = data["elicitations"][0]["message"]
            .as_str()
            .expect("message");
        assert!(msg.contains("Approve to continue"));
        assert!(msg.contains("drive"));
        assert!(msg.contains("approval_pending"));
        // elicitationId is a UUID v4 — non-empty and parseable.
        let id = data["elicitations"][0]["elicitationId"]
            .as_str()
            .expect("elicitationId");
        Uuid::parse_str(id).expect("valid uuid");
    }

    #[test]
    fn applies_defaults_for_blank_fields() {
        let payload = build_url_elicitation_payload(&consent(
            Some("https://example.com/consent"),
            "",
            "",
            "",
        ))
        .expect("payload");

        assert_eq!(payload.message, DEFAULT_CONSENT_MESSAGE);
        let msg = payload.data["elicitations"][0]["message"]
            .as_str()
            .expect("message");
        assert!(msg.contains(UNKNOWN_SERVICE_ID));
        assert!(msg.contains(DEFAULT_CONSENT_MESSAGE));
    }
}
