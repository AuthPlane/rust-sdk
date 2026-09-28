//! Wall-clock helpers shared across the SDK.
//!
//! Five copies of this idiom used to live across `dpop`, `dpop_replay`,
//! `resource`, `cache/cache_headers`, and `cache/document_cache`, each
//! with subtly different error handling
//! (`unwrap_or(Duration::from_secs(0))` vs `unwrap_or_default()` — the
//! same default in practice, but drift-prone). Centralised here so a
//! single change (switching to a monotonic clock, propagating an error
//! when the system clock is broken, etc.) lands once.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds elapsed since the Unix epoch, as an `i64`.
///
/// Returns 0 if the system clock is set before 1970-01-01. The DPoP
/// proof verifier treats "now" as the lower bound when comparing
/// against proof claims, so a forward-shift of the clock cannot make
/// a stale proof appear fresh — a backward-shift past the epoch is
/// the only failure mode this fallback masks, and that scenario is
/// not realistic on production hosts.
pub(crate) fn unix_now_secs_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() as i64
}

/// Seconds elapsed since the Unix epoch, as an `f64` (sub-second
/// precision). Used by the cache TTL math where fractional seconds
/// matter for short refresh intervals.
pub(crate) fn unix_now_secs_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
