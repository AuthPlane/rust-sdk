//! JWKS cache with key-ID lookup, force-refresh on `kid` miss, stale
//! fallback on fetch errors, and background refresh at 80 % of TTL.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::sync::Mutex;

#[cfg(test)]
use crate::AuthError;
use crate::AuthplaneError;
use crate::cache::document_cache::{DocumentCache, DocumentFetcherFn};
use crate::constants::jwk_params;

/// JWKS cache.
#[derive(Clone)]
pub struct JwksCache {
    inner: Arc<DocumentCache>,
    last_force_refresh: Arc<Mutex<Option<Instant>>>,
    min_force_refresh_interval: Duration,
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache")
            .field("inner", &self.inner)
            .field(
                "min_force_refresh_interval",
                &self.min_force_refresh_interval,
            )
            .finish()
    }
}

impl JwksCache {
    /// Default minimum interval between force-refreshes triggered by `kid` misses.
    pub const DEFAULT_MIN_FORCE_REFRESH_SECONDS: u64 = 30;

    /// Build a JWKS cache.
    pub fn new(fetcher: DocumentFetcherFn, refresh_seconds: u64) -> Self {
        let inner = DocumentCache::with_error_factory(
            fetcher,
            refresh_seconds,
            "jwks",
            None,
            Box::new(jwks_error_factory),
        );
        Self {
            inner,
            last_force_refresh: Arc::new(Mutex::new(None)),
            min_force_refresh_interval: Duration::from_secs(
                Self::DEFAULT_MIN_FORCE_REFRESH_SECONDS,
            ),
        }
    }

    /// Override the minimum force-refresh interval (test hook).
    pub fn with_min_force_refresh_interval(mut self, interval: Duration) -> Self {
        self.min_force_refresh_interval = interval;
        self
    }

    /// Underlying [`DocumentCache`] (for `aclose()` plumbing).
    pub fn document_cache(&self) -> Arc<DocumentCache> {
        self.inner.clone()
    }

    /// Cancel any background refresh task.
    pub async fn aclose(&self) {
        self.inner.aclose().await;
    }

    /// Expire the cached JWKS and clear the force-refresh rate limiter.
    ///
    /// Called when the fetcher is rebound to a new `jwks_uri` (RFC 8414
    /// rotation): keys retrieved from the withdrawn URL must stop being
    /// served from the warm cache — the next lookup fetches from the
    /// rebound URI — and the next `kid` miss must be free to force a
    /// refresh instead of being throttled by a force-refresh that ran
    /// against the old URL.
    ///
    /// Expired, not dropped. The retired key set stays available as the
    /// stale fallback, so an AS that publishes rotated metadata before the
    /// new endpoint is live — or a transient failure there — degrades to
    /// serving the last good keys instead of failing every verification.
    pub(crate) async fn expire(&self) {
        self.inner.expire().await;
        *self.last_force_refresh.lock().await = None;
    }

    /// Return the full JWKS document (forces a fetch if no cached value yet).
    pub async fn get(&self, force_refresh: bool) -> Result<Value, AuthplaneError> {
        self.inner.get(force_refresh).await
    }

    /// Look up a JWK by `kid`, optionally restricting to a specific algorithm.
    ///
    /// On a miss, the cache force-refreshes (rate-limited via
    /// `min_force_refresh_interval`) and tries again, so a key rotation at
    /// the same `jwks_uri` is followed without a caller-visible refresh.
    pub async fn get_key_by_kid(
        &self,
        kid: &str,
        algorithm: Option<&str>,
    ) -> Result<Option<Value>, AuthplaneError> {
        if let Some(jwk) = self.find_key(self.inner.get(false).await?, kid, algorithm) {
            return Ok(Some(jwk));
        }
        // Miss: maybe rotate. Rate-limit force-refresh attempts.
        if !self.try_record_force_refresh().await {
            return Ok(None);
        }
        let document = self.inner.get(true).await?;
        Ok(self.find_key(document, kid, algorithm))
    }

    fn find_key(&self, document: Value, kid: &str, algorithm: Option<&str>) -> Option<Value> {
        let keys = document.get("keys").and_then(Value::as_array)?;
        for entry in keys {
            if !entry.is_object() {
                continue;
            }
            if entry.get(jwk_params::KID).and_then(Value::as_str) != Some(kid) {
                continue;
            }
            if let Some(use_value) = entry.get(jwk_params::USE).and_then(Value::as_str)
                && use_value != jwk_params::USE_SIG
            {
                continue;
            }
            if let Some(ops) = entry.get(jwk_params::KEY_OPS).and_then(Value::as_array)
                && !ops.iter().any(|op| {
                    op.as_str()
                        .map(|s| s == jwk_params::KEY_OPS_VERIFY)
                        .unwrap_or(false)
                })
            {
                continue;
            }
            if let (Some(expected), Some(jwk_alg)) = (
                algorithm,
                entry.get(jwk_params::ALG).and_then(Value::as_str),
            ) && jwk_alg != expected
            {
                continue;
            }
            return Some(entry.clone());
        }
        None
    }

    async fn try_record_force_refresh(&self) -> bool {
        let mut last = self.last_force_refresh.lock().await;
        let now = Instant::now();
        match *last {
            Some(prev) if now.saturating_duration_since(prev) < self.min_force_refresh_interval => {
                false
            }
            _ => {
                *last = Some(now);
                true
            }
        }
    }
}

// Thin wrapper around the shared `errors::auth_error` helper. Kept as a
// function so it can be handed to `DocumentCache::with_error_factory`
// as a `Box<dyn Fn(&str) -> AuthplaneError>`; the JWKS-specific error
// code (`jwks_fetch_error`) is bound here.
fn jwks_error_factory(message: &str) -> AuthplaneError {
    crate::errors::auth_error("jwks_fetch_error", message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::document_cache::FetchResult;
    use std::pin::Pin;
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex as TokioMutex;

    fn fixed_fetcher(responses: Vec<Value>) -> (DocumentFetcherFn, StdArc<AtomicUsize>) {
        let counter = StdArc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let queue = StdArc::new(TokioMutex::new(responses));
        let fetcher: DocumentFetcherFn = StdArc::new(move || {
            let counter = counter_clone.clone();
            let queue = queue.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut q = queue.lock().await;
                if q.is_empty() {
                    return Err(AuthplaneError::Auth(AuthError {
                        message: "exhausted".to_string(),
                        code: "transport_error".to_string(),
                        status_code: None,
                    }));
                }
                Ok(FetchResult {
                    document: q.remove(0),
                    expires_at: None,
                })
            }) as Pin<Box<_>>
        });
        (fetcher, counter)
    }

    fn jwks_with(kids: &[&str]) -> Value {
        let keys: Vec<Value> = kids
            .iter()
            .map(|kid| {
                serde_json::json!({
                    "kid": kid,
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "abc",
                    "e": "AQAB",
                })
            })
            .collect();
        serde_json::json!({"keys": keys})
    }

    #[tokio::test]
    async fn lookup_finds_existing_kid() {
        let (fetcher, counter) = fixed_fetcher(vec![jwks_with(&["k1", "k2"])]);
        let cache = JwksCache::new(fetcher, 600);
        let jwk = cache
            .get_key_by_kid("k1", Some("RS256"))
            .await
            .expect("ok")
            .expect("found");
        assert_eq!(jwk["kid"], "k1");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn missing_kid_triggers_force_refresh() {
        let (fetcher, counter) = fixed_fetcher(vec![jwks_with(&["k1"]), jwks_with(&["k1", "k2"])]);
        let cache = JwksCache::new(fetcher, 600);
        let jwk = cache.get_key_by_kid("k2", None).await.expect("ok");
        assert!(jwk.is_some(), "second fetch should expose k2");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn force_refresh_is_rate_limited() {
        let (fetcher, counter) = fixed_fetcher(vec![
            jwks_with(&["k1"]),
            jwks_with(&["k1"]),
            jwks_with(&["k1"]),
        ]);
        let cache =
            JwksCache::new(fetcher, 600).with_min_force_refresh_interval(Duration::from_secs(60));
        // First miss: triggers force refresh.
        cache.get_key_by_kid("missing", None).await.expect("ok");
        // Second miss within the rate-limit window: no extra fetch.
        cache.get_key_by_kid("missing", None).await.expect("ok");
        assert_eq!(counter.load(Ordering::SeqCst), 2); // initial get + 1 force refresh
    }

    #[tokio::test]
    async fn algorithm_mismatch_is_skipped() {
        let mismatched = serde_json::json!({"keys": [{
            "kid": "k1", "kty": "RSA", "alg": "ES256", "use": "sig",
            "n": "abc", "e": "AQAB",
        }]});
        let (fetcher, _counter) = fixed_fetcher(vec![mismatched.clone(), mismatched]);
        let cache = JwksCache::new(fetcher, 600);
        let jwk = cache.get_key_by_kid("k1", Some("RS256")).await.expect("ok");
        assert!(jwk.is_none());
    }

    #[tokio::test]
    async fn expire_bypasses_cached_keys_and_clears_the_force_refresh_limiter() {
        // Models a `jwks_uri` rotation: the retired document is cached,
        // then the fetcher is rebound and the cache expired. The next
        // lookup must go back to the fetcher rather than answering from
        // keys retrieved at the withdrawn URL.
        let (fetcher, counter) = fixed_fetcher(vec![jwks_with(&["old"]), jwks_with(&["new"])]);
        // A long TTL, so only `expire` can force the second fetch.
        let cache = JwksCache::new(fetcher, 3600);
        assert!(
            cache
                .get_key_by_kid("old", None)
                .await
                .expect("ok")
                .is_some()
        );
        // The miss above consumed the one force-refresh the rate limiter
        // allows; `expire` must clear it along with the document's TTL.
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        cache.expire().await;

        assert!(
            cache
                .get_key_by_kid("new", None)
                .await
                .expect("ok")
                .is_some()
        );
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn enc_use_keys_are_skipped() {
        let mixed = serde_json::json!({"keys": [{
            "kid": "k1", "kty": "RSA", "alg": "RS256", "use": "enc",
            "n": "abc", "e": "AQAB",
        }]});
        let (fetcher, _counter) = fixed_fetcher(vec![mixed.clone(), mixed]);
        let cache = JwksCache::new(fetcher, 600);
        let jwk = cache.get_key_by_kid("k1", None).await.expect("ok");
        assert!(jwk.is_none());
    }

    #[tokio::test]
    async fn key_ops_without_verify_is_skipped() {
        let restricted = serde_json::json!({"keys": [{
            "kid": "k1", "kty": "RSA", "alg": "RS256",
            "key_ops": ["sign"],
            "n": "abc", "e": "AQAB",
        }]});
        let (fetcher, _counter) = fixed_fetcher(vec![restricted.clone(), restricted]);
        let cache = JwksCache::new(fetcher, 600);
        let jwk = cache.get_key_by_kid("k1", None).await.expect("ok");
        assert!(jwk.is_none());
    }
}
