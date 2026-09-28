//! Small JSON-shape parsing helpers shared across the SDK.
//!
//! Centralises patterns that were inlined at multiple call sites. Keeping
//! them in one module makes drift surface visible — if a new
//! agent-related JWT claim ships, there's exactly one place to harden the
//! parse policy.

use serde_json::Value;

/// Pull a `Vec<String>` from a JSON object's array field. Returns an
/// empty vec when the field is missing, `null`, or not an array; ignores
/// non-string entries inside an otherwise-valid array.
///
/// Mirrors the inline pattern that lived in
/// `oauth::introspect_token` (parsing the `agent_chain` claim out of an
/// RFC 7662 introspection response) and `resource::parse_claims`
/// (parsing the same claim out of a verified JWT payload). Centralising
/// the relaxed-parse policy here ensures the two paths agree on which
/// shapes are tolerated.
pub(crate) fn string_array(payload: &Value, key: &str) -> Vec<String> {
    payload
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::string_array;
    use serde_json::json;

    #[test]
    fn extracts_string_array_when_field_is_array_of_strings() {
        let payload = json!({ "agent_chain": ["orchestrator", "agent-007"] });
        assert_eq!(
            string_array(&payload, "agent_chain"),
            vec!["orchestrator".to_string(), "agent-007".to_string()]
        );
    }

    #[test]
    fn missing_field_returns_empty_vec() {
        let payload = json!({});
        assert!(string_array(&payload, "agent_chain").is_empty());
    }

    #[test]
    fn null_field_returns_empty_vec() {
        let payload = json!({ "agent_chain": null });
        assert!(string_array(&payload, "agent_chain").is_empty());
    }

    #[test]
    fn non_array_field_returns_empty_vec() {
        let payload = json!({ "agent_chain": "not-an-array" });
        assert!(string_array(&payload, "agent_chain").is_empty());
    }

    #[test]
    fn non_string_entries_are_filtered_out() {
        // Tolerate a mixed array rather than failing parse — the
        // introspection response is operator-facing JSON; one stray
        // numeric entry shouldn't drop the whole agent chain.
        let payload = json!({ "agent_chain": ["orchestrator", 42, "agent-007", null] });
        assert_eq!(
            string_array(&payload, "agent_chain"),
            vec!["orchestrator".to_string(), "agent-007".to_string()]
        );
    }
}
