use crate::AuthplaneError;
use crate::constants::oauth_errors::*;

/// OAuth error codes that describe the request, not the AS. Every one of
/// them is a deliberate answer from a healthy server — `access_denied` is
/// an exchange-policy refusal and `invalid_target` a resource-indicator
/// mismatch (RFC 8707 §2.2) — so none may count toward opening the
/// breaker.
const OAUTH_ERRORS_NO_CIRCUIT: &[&str] = &[
    INVALID_GRANT,
    INVALID_CLIENT,
    UNAUTHORIZED_CLIENT,
    INVALID_SCOPE,
    INVALID_TARGET,
    ACCESS_DENIED,
    CONSENT_REQUIRED,
    INTERACTION_REQUIRED,
];

pub fn should_open_circuit_for_oauth_error(code: &str) -> bool {
    !OAUTH_ERRORS_NO_CIRCUIT.contains(&code)
}

/// Shared `AuthplaneError`-level predicate used by every breaker consumer
/// (`AuthplaneClient::run_guarded` and `AuthplaneResource`'s introspection
/// path). Centralising this here keeps the two consumers in lockstep: a
/// benign OAuth error such as `invalid_client` must NOT trip either
/// breaker, otherwise a misconfigured client silently disables revocation
/// checks during the cooldown window (with `fail_open=true`) or rejects
/// all traffic (with `fail_open=false`).
pub(crate) fn should_count_failure(error: &AuthplaneError) -> bool {
    let code = match error {
        AuthplaneError::Auth(auth) => auth.code.as_str(),
        AuthplaneError::ConsentRequired(consent) => consent.code.as_str(),
        AuthplaneError::CircuitOpen => return false,
    };
    should_open_circuit_for_oauth_error(code)
}

#[cfg(test)]
mod tests {
    use super::{should_count_failure, should_open_circuit_for_oauth_error};
    use crate::{AuthError, AuthplaneError};

    #[test]
    fn consent_required_does_not_open_circuit() {
        assert!(!should_open_circuit_for_oauth_error("consent_required"));
        assert!(!should_open_circuit_for_oauth_error("interaction_required"));
    }

    #[test]
    fn server_error_opens_circuit() {
        assert!(should_open_circuit_for_oauth_error("server_error"));
    }

    /// A refused cross-client exchange (`access_denied`, 403) and a
    /// resource indicator that does not match a granted resource
    /// (`invalid_target`, 400) are policy answers from a healthy AS, not
    /// outages.
    #[test]
    fn access_denied_and_invalid_target_do_not_open_circuit() {
        assert!(!should_open_circuit_for_oauth_error("access_denied"));
        assert!(!should_open_circuit_for_oauth_error("invalid_target"));
    }

    fn auth_err(code: &str) -> AuthplaneError {
        AuthplaneError::Auth(AuthError {
            message: code.to_string(),
            code: code.to_string(),
            status_code: None,
        })
    }

    #[test]
    fn should_count_failure_agrees_with_code_predicate() {
        assert!(!should_count_failure(&auth_err("invalid_client")));
        assert!(!should_count_failure(&auth_err("consent_required")));
        assert!(!should_count_failure(&auth_err("access_denied")));
        assert!(!should_count_failure(&auth_err("invalid_target")));
        assert!(should_count_failure(&auth_err("server_error")));
        assert!(!should_count_failure(&AuthplaneError::CircuitOpen));
    }
}
