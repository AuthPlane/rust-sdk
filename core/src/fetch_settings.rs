#[derive(Debug, Clone, PartialEq)]
pub struct FetchSettings {
    pub ssrf_protection: bool,
    pub allow_http: bool,
    pub allow_localhost: bool,
    pub allow_private_networks: bool,
    pub timeout_seconds: f64,
}

impl Default for FetchSettings {
    fn default() -> Self {
        Self {
            ssrf_protection: true,
            allow_http: false,
            allow_localhost: false,
            allow_private_networks: false,
            timeout_seconds: 10.0,
        }
    }
}

impl FetchSettings {
    pub fn from_dev_mode(dev_mode: bool) -> Self {
        if dev_mode {
            Self {
                ssrf_protection: true,
                allow_http: true,
                allow_localhost: true,
                allow_private_networks: true,
                timeout_seconds: 10.0,
            }
        } else {
            Self::default()
        }
    }

    /// Resolve dev-mode from the environment variable `AUTHPLANE_DEV_MODE`.
    ///
    /// Truthy values: `"true"`, `"1"`, `"yes"` (case-insensitive).
    /// Falls back to `from_dev_mode(false)` when the variable is absent or
    /// not truthy.
    pub fn from_dev_mode_env() -> Self {
        let dev_mode = std::env::var("AUTHPLANE_DEV_MODE")
            .ok()
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);
        Self::from_dev_mode(dev_mode)
    }
}

#[cfg(test)]
mod tests {
    use super::FetchSettings;

    #[test]
    fn dev_mode_relaxes_fetch_restrictions() {
        let settings = FetchSettings::from_dev_mode(true);
        assert!(settings.allow_http);
        assert!(settings.allow_localhost);
        assert!(settings.allow_private_networks);
        assert!(settings.ssrf_protection);
    }

    #[test]
    fn prod_mode_uses_secure_defaults() {
        let settings = FetchSettings::from_dev_mode(false);
        assert!(!settings.allow_http);
        assert!(!settings.allow_localhost);
        assert!(!settings.allow_private_networks);
        assert!(settings.ssrf_protection);
        assert_eq!(settings.timeout_seconds, 10.0);
    }

    #[test]
    fn default_matches_prod_mode() {
        // Callers who construct FetchSettings::default() should not end up
        // with dev-mode permissions — this guards against a refactor that
        // silently flips the default to `allow_http = true`.
        assert_eq!(
            FetchSettings::default(),
            FetchSettings::from_dev_mode(false)
        );
    }

    #[test]
    fn timeout_can_be_overridden_without_touching_ssrf() {
        let settings = FetchSettings {
            timeout_seconds: 45.0,
            ..FetchSettings::default()
        };
        assert_eq!(settings.timeout_seconds, 45.0);
        assert!(settings.ssrf_protection);
        assert!(!settings.allow_http);
    }

    #[test]
    fn fractional_timeout_is_preserved() {
        // Reqwest's Duration::from_secs_f64 handles sub-second timeouts —
        // make sure the struct carries them verbatim.
        let settings = FetchSettings {
            timeout_seconds: 0.25,
            ..FetchSettings::default()
        };
        assert_eq!(settings.timeout_seconds, 0.25);
    }

    #[test]
    fn clone_and_eq_are_reflexive() {
        let a = FetchSettings::from_dev_mode(true);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
