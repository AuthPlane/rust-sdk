//! In-memory token cache with TTL buffer for `client_credentials` results.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

/// A cached access-token entry.
#[derive(Debug, Clone)]
pub struct CachedToken {
    pub access_token: String,
    pub token_type: String,
    /// AS-supplied lifetime hint, preserved across the cache boundary so a
    /// caller that schedules its own refresh off `TokenResponse.expires_in`
    /// sees the same `None` / `Some(N)` distinction it would have gotten
    /// from a fresh AS round-trip. Positive values are clamped to
    /// [`TokenCache::MAX_CACHE_TTL_SECONDS`] before storage, matching the
    /// clamp applied to the live TTL — so a caller scheduling its own
    /// refresh sees the same upper bound the cache will honour.
    pub expires_in: Option<i64>,
    pub scope: String,
    /// Raw `cnf` confirmation object from the AS token response (RFC 9449
    /// §6.1). Preserved verbatim so a token that was issued as
    /// DPoP-bound still looks DPoP-bound on cache hits — without this,
    /// downstream code gating on `cnf` / `cnf_jkt` sees the wrong shape
    /// the moment a token round-trips through the cache and silently
    /// loses its sender-constrained guarantee.
    pub cnf: Option<Value>,
    /// DPoP key thumbprint at `cnf.jkt`, mirrored from the source
    /// `TokenResponse`. Empty string when the cached token is not
    /// DPoP-bound.
    pub cnf_jkt: String,
}

impl From<CachedToken> for crate::oauth::TokenResponse {
    /// Rehydrate a `TokenResponse` from a cached entry. `refresh_token` and
    /// `issued_token_type` default to empty — `client_credentials` responses
    /// never carry them. `cnf` and `cnf_jkt` are preserved verbatim from the
    /// cache so a DPoP-bound token still looks DPoP-bound on cache hits.
    fn from(cached: CachedToken) -> Self {
        crate::oauth::TokenResponse {
            access_token: cached.access_token,
            token_type: cached.token_type,
            expires_in: cached.expires_in,
            scope: cached.scope,
            refresh_token: String::new(),
            issued_token_type: String::new(),
            cnf: cached.cnf,
            cnf_jkt: cached.cnf_jkt,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    token: CachedToken,
    expires_at: Instant,
}

/// In-memory cache for AS-issued machine tokens.
///
/// Tokens are evicted `ttl_buffer_seconds` before their actual expiry so the
/// SDK never returns a token that is about to die mid-request.
#[derive(Debug)]
pub struct TokenCache {
    ttl_buffer: Duration,
    default_ttl: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

impl TokenCache {
    /// Default TTL buffer applied before token expiry on every `get`.
    pub const DEFAULT_TTL_BUFFER_SECONDS: f64 = 30.0;
    /// Default fallback TTL when the AS does not supply `expires_in`.
    pub const DEFAULT_TTL_SECONDS: f64 = 3600.0;
    /// Upper bound clamp for AS-supplied `expires_in` values, in seconds.
    /// `Instant + Duration` panics on overflow, so an absurd AS reply
    /// (e.g. `i64::MAX`) cannot flow through unchecked. 30 days is well
    /// above any realistic access-token lifetime.
    pub const MAX_CACHE_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

    pub fn new() -> Self {
        Self::with_config(Self::DEFAULT_TTL_BUFFER_SECONDS, Self::DEFAULT_TTL_SECONDS)
    }

    pub fn with_config(ttl_buffer_seconds: f64, default_ttl_seconds: f64) -> Self {
        Self {
            ttl_buffer: Duration::from_secs_f64(ttl_buffer_seconds.max(0.0)),
            default_ttl: Duration::from_secs_f64(default_ttl_seconds.max(0.0)),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Get a cached token if it exists and has not expired (after applying the buffer).
    pub fn get(&self, key: &str) -> Option<CachedToken> {
        let mut entries = self.entries.lock().expect("poisoned");
        let now = Instant::now();
        if let Some(entry) = entries.get(key) {
            if now < entry.expires_at {
                return Some(entry.token.clone());
            }
            entries.remove(key);
        }
        None
    }

    /// Insert a token into the cache. Skips caching if the effective TTL
    /// (after buffer) would be non-positive.
    ///
    /// `expires_in` follows the [`TokenResponse::expires_in`] semantics:
    ///
    /// * `None` — the AS omitted the hint; the cache applies its configured
    ///   `default_ttl` (then the buffer).
    /// * `Some(0)` — the AS asked for immediate expiry (RFC 6749 §5.1
    ///   permits this for one-shot flows). The entry is not stored, since
    ///   it would be born expired.
    /// * `Some(n)` with `n > 0` — use `n` seconds, then apply the buffer.
    ///   Clamped to [`MAX_CACHE_TTL_SECONDS`] both for the live TTL and
    ///   for the hint preserved on [`CachedToken::expires_in`], so the
    ///   stored value never advertises a lifetime the cache will not
    ///   actually honour. The clamp also keeps `Instant + Duration`
    ///   from overflowing on an absurd AS reply.
    ///
    /// `cnf` / `cnf_jkt` preserve the DPoP confirmation binding through
    /// cache round-trips (RFC 9449 §6.1). Pass `None` / `""` for plain
    /// bearer tokens.
    ///
    /// [`TokenResponse::expires_in`]: crate::oauth::TokenResponse::expires_in
    /// [`MAX_CACHE_TTL_SECONDS`]: Self::MAX_CACHE_TTL_SECONDS
    /// [`CachedToken::expires_in`]: CachedToken::expires_in
    #[allow(clippy::too_many_arguments)] // mirrors the TokenResponse fields we need to cache verbatim
    pub fn set(
        &self,
        key: &str,
        access_token: &str,
        token_type: &str,
        expires_in: Option<i64>,
        scope: &str,
        cnf: Option<&Value>,
        cnf_jkt: &str,
    ) {
        let (raw_ttl, stored_expires_in) = match expires_in {
            None => (self.default_ttl, None),
            // RFC 6749 §5.1 explicit `expires_in: 0` ⇒ token is born expired;
            // skip caching rather than apply the default fallback (which
            // would silently extend a deliberately-zero lifetime to an hour).
            Some(0) => return,
            // `optional_non_negative_i64` rejects negative `expires_in` at
            // parse time, so the only reachable `Some(_)` branch is `n > 0`.
            // Defend anyway in case a future direct-deserialize path skips
            // that validation.
            Some(n) if n < 0 => return,
            Some(n) => {
                let clamped = n.min(Self::MAX_CACHE_TTL_SECONDS);
                (Duration::from_secs(clamped as u64), Some(clamped))
            }
        };
        let effective_ttl = raw_ttl.saturating_sub(self.ttl_buffer);
        if effective_ttl.is_zero() {
            return;
        }
        let entry = Entry {
            token: CachedToken {
                access_token: access_token.to_string(),
                token_type: token_type.to_string(),
                expires_in: stored_expires_in,
                scope: scope.to_string(),
                cnf: cnf.cloned(),
                cnf_jkt: cnf_jkt.to_string(),
            },
            expires_at: Instant::now() + effective_ttl,
        };
        let mut entries = self.entries.lock().expect("poisoned");
        entries.insert(key.to_string(), entry);
    }

    /// Remove a cached entry.
    pub fn delete(&self, key: &str) {
        let mut entries = self.entries.lock().expect("poisoned");
        entries.remove(key);
    }

    /// Number of currently-stored entries (test/admin helper).
    pub fn len(&self) -> usize {
        self.entries.lock().expect("poisoned").len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Build a deterministic cache key from scope + resource.
    ///
    /// Scope tokens are sorted so the key is order-independent.
    pub fn cache_key(scope: &str, resource: &str) -> String {
        let mut parts: Vec<&str> = if scope.is_empty() {
            Vec::new()
        } else {
            scope.split_whitespace().collect()
        };
        parts.sort_unstable();
        let scope_part = parts.join(" ");
        if !resource.is_empty() {
            if scope_part.is_empty() {
                return format!("|{resource}");
            }
            return format!("{scope_part}|{resource}");
        }
        if scope_part.is_empty() {
            "_default".to_string()
        } else {
            scope_part
        }
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn cache_key_sorts_scopes_and_appends_resource() {
        assert_eq!(
            TokenCache::cache_key("read write", "https://api"),
            "read write|https://api"
        );
        assert_eq!(
            TokenCache::cache_key("write read", "https://api"),
            "read write|https://api"
        );
        assert_eq!(TokenCache::cache_key("", "https://api"), "|https://api");
        assert_eq!(TokenCache::cache_key("read", ""), "read");
        assert_eq!(TokenCache::cache_key("", ""), "_default");
    }

    #[test]
    fn set_and_get_round_trip() {
        let cache = TokenCache::with_config(0.0, 60.0);
        cache.set("k", "tok", "Bearer", Some(60), "read", None, "");
        let entry = cache.get("k").expect("entry should exist");
        assert_eq!(entry.access_token, "tok");
        assert_eq!(entry.token_type, "Bearer");
        assert_eq!(entry.scope, "read");
        assert_eq!(entry.expires_in, Some(60));
        assert!(entry.cnf.is_none());
        assert_eq!(entry.cnf_jkt, "");
    }

    #[test]
    fn set_skips_when_buffer_consumes_ttl() {
        let cache = TokenCache::with_config(60.0, 3600.0);
        cache.set("k", "tok", "Bearer", Some(30), "read", None, "");
        assert!(cache.get("k").is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn entry_expires_after_buffer_adjusted_ttl() {
        let cache = TokenCache::with_config(0.0, 3600.0);
        cache.set("k", "tok", "Bearer", Some(1), "read", None, "");
        // Sleep slightly longer than 1s; entry should be evicted on next get.
        thread::sleep(Duration::from_millis(1100));
        assert!(cache.get("k").is_none());
    }

    #[test]
    fn delete_removes_entry() {
        let cache = TokenCache::new();
        cache.set("k", "tok", "Bearer", Some(60), "", None, "");
        cache.delete("k");
        assert!(cache.get("k").is_none());
    }

    #[test]
    fn missing_expires_in_falls_back_to_default_ttl() {
        // `None` means the AS omitted `expires_in`; the cache must apply
        // its configured `default_ttl` rather than treat it as immediate
        // expiry.
        let cache = TokenCache::with_config(0.0, 60.0);
        cache.set("k", "tok", "Bearer", None, "read", None, "");
        let entry = cache.get("k").expect("default-TTL fallback should store");
        assert_eq!(entry.expires_in, None);
    }

    #[test]
    fn explicit_zero_expires_in_does_not_extend_to_default_ttl() {
        // RFC 6749 §5.1 permits `expires_in: 0` for one-shot flows.
        // Previously the cache collapsed Some(0) to default_ttl (3600s) —
        // a token meant to die immediately was kept for an hour. Now an
        // explicit zero refuses to store at all.
        let cache = TokenCache::with_config(0.0, 3600.0);
        cache.set("k", "tok", "Bearer", Some(0), "read", None, "");
        assert!(cache.get("k").is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn dpop_binding_survives_cache_round_trip() {
        // RFC 9449 §6.1: a DPoP-bound access token carries its key
        // thumbprint at `cnf.jkt`. The cache used to drop both `cnf`
        // and `cnf_jkt`, so a token issued as sender-constrained
        // looked bearer-only on every cache hit. Pin the fix here so
        // any future refactor that re-introduces the asymmetry fails
        // loudly.
        let cache = TokenCache::with_config(0.0, 60.0);
        let cnf = serde_json::json!({"jkt": "thumbprint-xyz"});
        cache.set(
            "k",
            "dpop-tok",
            "DPoP",
            Some(60),
            "read",
            Some(&cnf),
            "thumbprint-xyz",
        );
        let entry = cache.get("k").expect("entry should exist");
        assert_eq!(entry.token_type, "DPoP");
        assert_eq!(entry.cnf_jkt, "thumbprint-xyz");
        assert_eq!(
            entry
                .cnf
                .as_ref()
                .and_then(|c| c.get("jkt"))
                .and_then(|v| v.as_str()),
            Some("thumbprint-xyz"),
        );
    }

    #[test]
    fn defaults_match_documented_constants() {
        assert!((TokenCache::DEFAULT_TTL_BUFFER_SECONDS - 30.0).abs() < f64::EPSILON);
        assert!((TokenCache::DEFAULT_TTL_SECONDS - 3600.0).abs() < f64::EPSILON);
    }

    #[test]
    fn huge_expires_in_is_clamped_to_max_ttl() {
        // `Instant + Duration` panics on overflow. An AS that replies with
        // `expires_in: i64::MAX` (or any value larger than
        // `MAX_CACHE_TTL_SECONDS`) must be clamped so the cache stores a
        // sane entry rather than crashing — or storing nothing — silently.
        // The stored hint is clamped too, so a caller scheduling its own
        // refresh sees the same upper bound the cache will honour.
        let cache = TokenCache::with_config(0.0, 60.0);
        cache.set("k", "tok", "Bearer", Some(i64::MAX), "read", None, "");
        let entry = cache
            .get("k")
            .expect("clamped entry should store, not crash, not skip");
        assert_eq!(entry.expires_in, Some(TokenCache::MAX_CACHE_TTL_SECONDS));
    }
}
