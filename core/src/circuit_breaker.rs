//! Circuit breaker for authorization-server resilience.
//!
//! A failing AS trips the breaker after `threshold` failures; subsequent calls
//! short-circuit until `cooldown_seconds` elapse, after which a single probe
//! is admitted (HALF_OPEN). A successful probe restores normal traffic; a
//! failed probe re-opens the breaker without rewalking the failure counter.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Logical state of a [`CircuitBreaker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — every request is admitted.
    Closed,
    /// Tripped — every request is shed without contacting the AS.
    Open,
    /// Cooldown elapsed; one probe is admitted to test recovery.
    HalfOpen,
}

impl CircuitState {
    /// Lower-case label, for log lines and any API that surfaces the state.
    pub fn as_str(self) -> &'static str {
        match self {
            CircuitState::Closed => "closed",
            CircuitState::Open => "open",
            CircuitState::HalfOpen => "half_open",
        }
    }
}

#[derive(Debug)]
struct Inner {
    state: CircuitState,
    failure_count: u32,
    opened_at: Option<Instant>,
    probe_in_flight: bool,
}

/// Circuit breaker that protects the SDK from cascading AS failures.
///
/// The contract:
/// * `threshold` consecutive failures move CLOSED → OPEN.
/// * After `cooldown_seconds`, the next [`CircuitBreaker::allow`] call moves
///   the breaker to HALF_OPEN and admits **one** probe; concurrent callers
///   keep seeing the breaker as unavailable.
/// * Any [`CircuitBreaker::record_success`] (including the half-open probe)
///   fully closes the breaker and resets the failure counter.
/// * A failure during a half-open probe re-opens the breaker without
///   rewalking the failure counter.
#[derive(Debug)]
pub struct CircuitBreaker {
    threshold: u32,
    cooldown: Duration,
    inner: Mutex<Inner>,
}

impl CircuitBreaker {
    /// Default failure threshold.
    pub const DEFAULT_THRESHOLD: u32 = 5;
    /// Default cooldown.
    pub const DEFAULT_COOLDOWN_SECONDS: f64 = 30.0;

    /// Create a breaker with the SDK defaults (threshold=5, cooldown=30s).
    pub fn new() -> Self {
        Self::with_config(Self::DEFAULT_THRESHOLD, Self::DEFAULT_COOLDOWN_SECONDS)
    }

    /// Create a breaker with custom configuration.
    ///
    /// `threshold` must be at least 1; values below 1 are clamped up.
    /// `cooldown_seconds` must be non-negative; negative values are clamped to 0.
    pub fn with_config(threshold: u32, cooldown_seconds: f64) -> Self {
        let cooldown = Duration::from_secs_f64(cooldown_seconds.max(0.0));
        Self {
            threshold: threshold.max(1),
            cooldown,
            inner: Mutex::new(Inner {
                state: CircuitState::Closed,
                failure_count: 0,
                opened_at: None,
                probe_in_flight: false,
            }),
        }
    }

    /// Return the effective state right now.
    pub fn state(&self) -> CircuitState {
        let inner = self.inner.lock().expect("poisoned");
        Self::effective_state(&inner, self.cooldown, Instant::now())
    }

    /// Return `true` if a request should be attempted, `false` if shed.
    ///
    /// Side effect: the first caller to observe HALF_OPEN gets the probe
    /// permit; subsequent callers keep seeing the breaker as unavailable
    /// until the probe records its outcome.
    pub fn allow(&self) -> bool {
        let mut inner = self.inner.lock().expect("poisoned");
        let now = Instant::now();
        let effective = Self::effective_state(&inner, self.cooldown, now);
        match effective {
            CircuitState::Closed => true,
            CircuitState::Open => false,
            CircuitState::HalfOpen => {
                if inner.state != CircuitState::HalfOpen {
                    inner.state = CircuitState::HalfOpen;
                }
                if inner.probe_in_flight {
                    return false;
                }
                inner.probe_in_flight = true;
                true
            }
        }
    }

    /// Record a successful request. Closes the breaker and resets the counter.
    pub fn record_success(&self) {
        let mut inner = self.inner.lock().expect("poisoned");
        inner.state = CircuitState::Closed;
        inner.failure_count = 0;
        inner.opened_at = None;
        inner.probe_in_flight = false;
    }

    /// Record a failed request.
    ///
    /// * If a probe was in flight (HALF_OPEN), the breaker re-opens.
    /// * If the cooldown has elapsed but no probe has been admitted, the
    ///   failure is ignored — it would only push the cooldown timer
    ///   forward unnecessarily.
    /// * Otherwise the failure counter increments and, on reaching
    ///   `threshold`, the breaker opens.
    pub fn record_failure(&self) {
        let mut inner = self.inner.lock().expect("poisoned");
        let now = Instant::now();
        let effective = Self::effective_state(&inner, self.cooldown, now);

        if inner.probe_in_flight
            && (effective == CircuitState::HalfOpen || inner.state == CircuitState::HalfOpen)
        {
            inner.state = CircuitState::Open;
            inner.opened_at = Some(now);
            inner.probe_in_flight = false;
            inner.failure_count = self.threshold;
            return;
        }

        if effective == CircuitState::HalfOpen && inner.state == CircuitState::Open {
            // Cooldown elapsed but no probe was admitted yet; do not reset the timer.
            return;
        }

        inner.failure_count = inner.failure_count.saturating_add(1);
        if inner.failure_count >= self.threshold {
            inner.state = CircuitState::Open;
            inner.opened_at = Some(now);
        }
        inner.probe_in_flight = false;
    }

    /// Reset the breaker to CLOSED unconditionally (test / admin helper).
    pub fn reset(&self) {
        self.record_success();
    }

    fn effective_state(inner: &Inner, cooldown: Duration, now: Instant) -> CircuitState {
        if inner.state == CircuitState::Open
            && let Some(opened_at) = inner.opened_at
            && now.saturating_duration_since(opened_at) >= cooldown
        {
            return CircuitState::HalfOpen;
        }
        inner.state
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker(threshold: u32, cooldown_secs: f64) -> CircuitBreaker {
        CircuitBreaker::with_config(threshold, cooldown_secs)
    }

    #[test]
    fn closed_admits_traffic() {
        let cb = breaker(3, 30.0);
        assert!(cb.allow());
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn opens_after_threshold_failures() {
        let cb = breaker(3, 30.0);
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow());
    }

    #[test]
    fn success_resets_counter() {
        let cb = breaker(3, 30.0);
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn cooldown_transitions_to_half_open() {
        let cb = breaker(1, 0.0); // cooldown=0 means immediately HALF_OPEN
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        // First allow() admits the probe.
        assert!(cb.allow());
        // Second allow() is shed because the probe is in flight.
        assert!(!cb.allow());
    }

    #[test]
    fn half_open_probe_success_closes_breaker() {
        let cb = breaker(1, 0.0);
        cb.record_failure();
        assert!(cb.allow()); // probe admitted
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow());
    }

    #[test]
    fn half_open_probe_failure_reopens_breaker() {
        // Use zero cooldown so we can reach HalfOpen, but after a probe
        // failure the breaker re-opens. With cooldown=0 state() shows
        // HalfOpen immediately, so we verify the re-open indirectly: a
        // second allow() should admit a new probe (confirming the old
        // probe_in_flight flag was cleared).
        let cb = breaker(3, 0.0);
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        assert!(cb.allow()); // probe admitted
        cb.record_failure(); // probe fails → re-opens → instant HalfOpen
        // The breaker re-opened and cleared probe_in_flight, so a new
        // probe should be admitted.
        assert!(cb.allow());
        // counter must not double-count: it is set to threshold so the next
        // cooldown still produces a HALF_OPEN attempt rather than locking us out.
    }

    #[test]
    fn failure_after_cooldown_without_probe_does_not_reset_timer() {
        let cb = breaker(1, 0.0);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        // No allow() yet — record a failure; this should NOT reset cooldown.
        cb.record_failure();
        // Underlying state stays OPEN, effective HALF_OPEN.
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn reset_helper_closes_breaker() {
        let cb = breaker(2, 30.0);
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn state_strings_are_the_documented_lower_case_labels() {
        assert_eq!(CircuitState::Closed.as_str(), "closed");
        assert_eq!(CircuitState::Open.as_str(), "open");
        assert_eq!(CircuitState::HalfOpen.as_str(), "half_open");
    }

    #[test]
    fn threshold_is_clamped_to_one() {
        let cb = CircuitBreaker::with_config(0, 1.0);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn defaults_are_the_documented_values() {
        assert_eq!(CircuitBreaker::DEFAULT_THRESHOLD, 5);
        assert!((CircuitBreaker::DEFAULT_COOLDOWN_SECONDS - 30.0).abs() < f64::EPSILON);
        let cb = CircuitBreaker::default();
        for _ in 0..4 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }
}
