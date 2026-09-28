//! HTTP cache header parsing utilities (RFC 7234).

use chrono::{DateTime, FixedOffset};

/// Extract an absolute Unix expiry timestamp from HTTP response headers.
///
/// Precedence (per RFC 7234 §4.2.2):
/// 1. `Cache-Control: no-store` / `no-cache` → `Some(0.0)` (already expired).
/// 2. `Cache-Control: max-age=N` → `Some(now + N)`.
/// 3. `Expires: <RFC 7231 date>` → parsed to a Unix timestamp.
/// 4. None — caller falls back to the configured refresh interval.
pub fn parse_expires_at<I, K, V>(headers: I) -> Option<f64>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut cache_control: Option<String> = None;
    let mut expires: Option<String> = None;
    for (name, value) in headers {
        let lower = name.as_ref().to_ascii_lowercase();
        if lower == "cache-control" {
            cache_control.get_or_insert_with(|| value.as_ref().to_string());
        } else if lower == "expires" {
            expires.get_or_insert_with(|| value.as_ref().to_string());
        }
    }

    if let Some(cc) = cache_control {
        let lower_cc = cc.to_ascii_lowercase();
        if lower_cc.contains("no-store") || lower_cc.contains("no-cache") {
            return Some(0.0);
        }
        for directive in lower_cc.split(',') {
            let directive = directive.trim();
            if let Some(rest) = directive.strip_prefix("max-age=")
                && let Ok(max_age) = rest.trim().parse::<f64>()
                && max_age >= 0.0
            {
                return Some(now_unix() + max_age);
            }
        }
    }

    if let Some(expires_value) = expires {
        if let Ok(parsed) = DateTime::<FixedOffset>::parse_from_rfc2822(&expires_value) {
            return Some(parsed.timestamp() as f64);
        }
        if let Ok(parsed) = DateTime::parse_from_rfc3339(&expires_value) {
            return Some(parsed.timestamp() as f64);
        }
    }

    None
}

use crate::time_utils::unix_now_secs_f64 as now_unix;

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, eps: f64) -> bool {
        (a - b).abs() < eps
    }

    #[test]
    fn no_store_marks_already_expired() {
        let result = parse_expires_at([("Cache-Control", "no-store")]);
        assert_eq!(result, Some(0.0));
    }

    #[test]
    fn no_cache_marks_already_expired() {
        let result = parse_expires_at([("Cache-Control", "no-cache, public")]);
        assert_eq!(result, Some(0.0));
    }

    #[test]
    fn max_age_returns_future_timestamp() {
        let now = now_unix();
        let result = parse_expires_at([("Cache-Control", "max-age=120, public")]);
        let exp = result.expect("max-age should produce expires_at");
        assert!(approx_eq(exp - now, 120.0, 5.0));
    }

    #[test]
    fn negative_max_age_is_ignored() {
        let result = parse_expires_at([("Cache-Control", "max-age=-1")]);
        assert!(result.is_none());
    }

    #[test]
    fn expires_header_is_parsed_when_no_cache_control() {
        let result = parse_expires_at([("Expires", "Tue, 01 Jan 2030 00:00:00 GMT")]);
        let exp = result.expect("Expires must parse");
        // Jan 1 2030 = 1893456000
        assert!(approx_eq(exp, 1893456000.0, 1.0));
    }

    #[test]
    fn missing_headers_return_none() {
        let result = parse_expires_at(std::iter::empty::<(&str, &str)>());
        assert!(result.is_none());
    }

    #[test]
    fn cache_control_case_insensitive() {
        let result = parse_expires_at([("CACHE-CONTROL", "Max-Age=60")]);
        assert!(result.is_some());
    }
}
