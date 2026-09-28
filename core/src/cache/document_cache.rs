//! Generic JSON document cache: TTL with HTTP cache-header awareness,
//! background refresh at 80 % of effective TTL, stale fallback on fetch
//! errors, lock-coordinated fetching, and an optional change callback.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::sync::{Mutex, OnceCell};
use tokio::task::JoinHandle;

#[cfg(test)]
use crate::AuthError;
use crate::AuthplaneError;

/// Result returned by a [`DocumentFetcherFn`].
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// The parsed JSON body.
    pub document: Value,
    /// Absolute Unix expiry timestamp derived from cache headers, if any.
    pub expires_at: Option<f64>,
}

/// Type alias for the boxed async fetcher closure used by [`DocumentCache`].
pub type DocumentFetcherFn = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<FetchResult, AuthplaneError>> + Send>>
        + Send
        + Sync,
>;

/// Type alias for the on_change callback used by [`DocumentCache`].
pub type DocumentChangeCallback =
    Arc<dyn Fn(Value, Value) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

#[derive(Debug)]
struct CachedDocument {
    body: Value,
    cache_time: Instant,
    server_expires_at_unix: Option<f64>,
    /// Set by [`DocumentCache::expire`]: the next `get` must re-fetch no
    /// matter how warm the TTL says this entry is, but the body stays
    /// available as the stale fallback should that fetch fail.
    expired: bool,
}

#[derive(Debug, Default)]
struct State {
    cached: Option<CachedDocument>,
    refresh_task: Option<JoinHandle<()>>,
}

/// Generic JSON document cache shared by metadata and JWKS layers.
pub struct DocumentCache {
    fetcher: DocumentFetcherFn,
    refresh_seconds: u64,
    document_type: String,
    on_change: Option<DocumentChangeCallback>,
    error_factory: Box<dyn Fn(&str) -> AuthplaneError + Send + Sync>,
    state: Arc<Mutex<State>>,
    fetch_lock: Arc<Mutex<()>>,
    /// Weak self-pointer used to spawn a background-refresh task without
    /// creating an `Arc<Self>` cycle that would leak the cache.
    self_handle: OnceCell<Weak<DocumentCache>>,
}

impl std::fmt::Debug for DocumentCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentCache")
            .field("document_type", &self.document_type)
            .field("refresh_seconds", &self.refresh_seconds)
            .finish()
    }
}

impl DocumentCache {
    /// Build a new cache with default error factory (`transport_error`).
    pub fn new(
        fetcher: DocumentFetcherFn,
        refresh_seconds: u64,
        document_type: impl Into<String>,
        on_change: Option<DocumentChangeCallback>,
    ) -> Arc<Self> {
        Self::with_error_factory(
            fetcher,
            refresh_seconds,
            document_type,
            on_change,
            Box::new(default_error_factory),
        )
    }

    /// Build a cache with a custom error factory (e.g. `JwksFetchError`).
    pub fn with_error_factory(
        fetcher: DocumentFetcherFn,
        refresh_seconds: u64,
        document_type: impl Into<String>,
        on_change: Option<DocumentChangeCallback>,
        error_factory: Box<dyn Fn(&str) -> AuthplaneError + Send + Sync>,
    ) -> Arc<Self> {
        let cache = Arc::new(Self {
            fetcher,
            refresh_seconds: refresh_seconds.max(1),
            document_type: document_type.into(),
            on_change,
            error_factory,
            state: Arc::new(Mutex::new(State::default())),
            fetch_lock: Arc::new(Mutex::new(())),
            self_handle: OnceCell::new(),
        });
        // Store a Weak handle so background tasks do not keep the cache
        // alive past the user's last Arc drop.
        let _ = cache.self_handle.set(Arc::downgrade(&cache));
        cache
    }

    /// Document type label.
    pub fn document_type(&self) -> &str {
        &self.document_type
    }

    /// Configured refresh interval in seconds.
    pub fn refresh_seconds(&self) -> u64 {
        self.refresh_seconds
    }

    fn effective_expires_at(&self, doc: &CachedDocument, now: Instant) -> Instant {
        if doc.expired {
            // `cache_time` is never later than any `now` a caller compares
            // against, so an expired entry always misses the warm path.
            return doc.cache_time;
        }
        let configured = doc.cache_time + Duration::from_secs(self.refresh_seconds);
        if let Some(server_unix) = doc.server_expires_at_unix {
            // Translate the server's absolute Unix expiry into a monotonic
            // Instant relative to "now" so it can be compared cleanly.
            let now_unix = now_unix_seconds();
            if server_unix <= now_unix {
                return doc.cache_time;
            }
            let delta = Duration::from_secs_f64((server_unix - now_unix).max(0.0));
            let server_instant = now + delta;
            return std::cmp::min(configured, server_instant);
        }
        configured
    }

    /// Return the cached document, fetching or refreshing as needed.
    ///
    /// Concurrent callers serialise behind an internal mutex so only one
    /// fetch is in flight at a time. On fetch errors a stale cache is
    /// served, silently — the crate carries no logging facility, so the
    /// failed refresh leaves no trace; if no cache existed yet, the error
    /// factory is invoked.
    pub async fn get(&self, force_refresh: bool) -> Result<Value, AuthplaneError> {
        self.get_inner(force_refresh, true).await
    }

    /// Force a refresh and report a failed fetch instead of falling back to
    /// the cached document.
    ///
    /// [`Self::get`] answers a failed refresh with the last good body, which
    /// is the right posture for a caller that only wants *a* document. A
    /// caller whose next decision depends on the document being current —
    /// rebinding a rotated `jwks_uri`, say — needs to know the refresh did
    /// not happen, otherwise it treats the previous interval's body as a
    /// fresh answer and schedules its next attempt as if it had one. The
    /// cached body is left in place either way, so other readers keep being
    /// served through the failure.
    pub(crate) async fn refresh_strict(&self) -> Result<Value, AuthplaneError> {
        self.get_inner(true, false).await
    }

    async fn get_inner(
        &self,
        force_refresh: bool,
        stale_fallback: bool,
    ) -> Result<Value, AuthplaneError> {
        let now = Instant::now();
        // Fast path: cached value still warm.
        {
            let mut state = self.state.lock().await;
            if !force_refresh && let Some(doc) = state.cached.as_ref() {
                let expires = self.effective_expires_at(doc, now);
                if now < expires {
                    let body = doc.body.clone();
                    let ttl = expires.saturating_duration_since(doc.cache_time);
                    let elapsed = now.saturating_duration_since(doc.cache_time);
                    let needs_bg_refresh = !ttl.is_zero() && elapsed >= ttl.mul_f64(0.8);
                    let task_idle = state
                        .refresh_task
                        .as_ref()
                        .map(|task| task.is_finished())
                        .unwrap_or(true);
                    if needs_bg_refresh && task_idle {
                        self.do_spawn_background_refresh(&mut state);
                    }
                    drop(state);
                    return Ok(body);
                }
            }
        }

        // Slow path: fetch under fetch_lock to coordinate with concurrent callers.
        let _guard = self.fetch_lock.lock().await;

        // Re-check after acquiring the lock — another caller may have refreshed.
        {
            let state = self.state.lock().await;
            if !force_refresh && let Some(doc) = state.cached.as_ref() {
                let expires = self.effective_expires_at(doc, Instant::now());
                if Instant::now() < expires {
                    return Ok(doc.body.clone());
                }
            }
        }

        match (self.fetcher)().await {
            Ok(result) => {
                let mut state = self.state.lock().await;
                let old_body = state.cached.as_ref().map(|doc| doc.body.clone());
                let new_body = result.document.clone();
                state.cached = Some(CachedDocument {
                    body: new_body.clone(),
                    cache_time: Instant::now(),
                    server_expires_at_unix: result.expires_at,
                    expired: false,
                });
                drop(state);
                if let (Some(callback), Some(old)) = (self.on_change.as_ref(), old_body)
                    && old != new_body
                {
                    let cb = callback.clone();
                    let old_clone = old;
                    let new_clone = new_body.clone();
                    tokio::spawn(async move {
                        (cb)(old_clone, new_clone).await;
                    });
                }
                Ok(new_body)
            }
            Err(error) => {
                if stale_fallback {
                    let state = self.state.lock().await;
                    if let Some(doc) = state.cached.as_ref() {
                        return Ok(doc.body.clone());
                    }
                }
                Err((self.error_factory)(&format!(
                    "Failed to fetch {}: {error}",
                    self.document_type
                )))
            }
        }
    }

    /// Expire the cached document so the next [`Self::get`] re-fetches,
    /// while keeping the body available as the stale fallback.
    ///
    /// Needed when the fetch target itself changes rather than expiring —
    /// an RFC 8414 `jwks_uri` rotation, for instance. The cached body came
    /// from the withdrawn URL, so the TTL that would normally govern it no
    /// longer says anything about its freshness.
    ///
    /// Expired, not dropped: dropping would leave the fallback branch with
    /// nothing to serve, so one transient failure at the new target would
    /// fail every caller — including ones the retired document was
    /// answering a moment earlier. Keeping the body preserves the cache's
    /// last-known-good posture; retired content is served only while a
    /// fetch of the new target is failing.
    ///
    /// Takes `fetch_lock` first, so a fetch already in flight against the
    /// old target commits before the expiry lands and cannot resurrect a
    /// warm entry for a full TTL afterwards. Safe to await from callers
    /// holding no cache locks; nothing here is held across the fetcher.
    pub(crate) async fn expire(&self) {
        let _guard = self.fetch_lock.lock().await;
        let mut state = self.state.lock().await;
        if let Some(doc) = state.cached.as_mut() {
            doc.expired = true;
        }
    }

    /// Cancel the background refresh task (if any). Safe to call multiple times.
    pub async fn aclose(&self) {
        let mut state = self.state.lock().await;
        if let Some(task) = state.refresh_task.take() {
            task.abort();
        }
    }

    fn do_spawn_background_refresh(&self, state: &mut State) {
        if state
            .refresh_task
            .as_ref()
            .map(|task| !task.is_finished())
            .unwrap_or(false)
        {
            return;
        }
        let weak = match self.self_handle.get() {
            Some(handle) => handle.clone(),
            None => return,
        };
        let task = tokio::spawn(async move {
            if let Some(cache) = weak.upgrade() {
                let _ = cache.get(true).await;
            }
        });
        state.refresh_task = Some(task);
    }
}

// Thin wrapper around the shared `errors::transport_error` helper, kept
// as a function so it can be passed as a `Box<dyn Fn(&str) -> AuthplaneError>`
// default. New transport-error sites should call the helper directly
// rather than going through this thunk.
fn default_error_factory(message: &str) -> AuthplaneError {
    crate::errors::transport_error(message)
}

use crate::time_utils::unix_now_secs_f64 as now_unix_seconds;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex as TokioMutex;

    fn make_fetcher(
        responses: Vec<Result<FetchResult, AuthplaneError>>,
    ) -> (DocumentFetcherFn, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let queue = Arc::new(TokioMutex::new(responses));
        let fetcher: DocumentFetcherFn = Arc::new(move || {
            let counter = counter_clone.clone();
            let queue = queue.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut q = queue.lock().await;
                if q.is_empty() {
                    return Err(AuthplaneError::Auth(AuthError {
                        message: "no more responses".to_string(),
                        code: "test".to_string(),
                        status_code: None,
                    }));
                }
                q.remove(0)
            })
        });
        (fetcher, counter)
    }

    #[tokio::test]
    async fn first_get_invokes_fetcher_and_caches_result() {
        let (fetcher, counter) = make_fetcher(vec![Ok(FetchResult {
            document: serde_json::json!({"a": 1}),
            expires_at: None,
        })]);
        let cache = DocumentCache::new(fetcher, 60, "test", None);
        let body = cache.get(false).await.expect("ok");
        assert_eq!(body, serde_json::json!({"a": 1}));
        // Subsequent get returns cache without re-fetching.
        let body2 = cache.get(false).await.expect("ok");
        assert_eq!(body2, serde_json::json!({"a": 1}));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn force_refresh_bypasses_cache() {
        let (fetcher, counter) = make_fetcher(vec![
            Ok(FetchResult {
                document: serde_json::json!({"v": 1}),
                expires_at: None,
            }),
            Ok(FetchResult {
                document: serde_json::json!({"v": 2}),
                expires_at: None,
            }),
        ]);
        let cache = DocumentCache::new(fetcher, 600, "test", None);
        let v1 = cache.get(false).await.expect("ok");
        assert_eq!(v1["v"], 1);
        let v2 = cache.get(true).await.expect("ok");
        assert_eq!(v2["v"], 2);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn fetch_failure_falls_back_to_stale() {
        let (fetcher, _counter) = make_fetcher(vec![
            Ok(FetchResult {
                document: serde_json::json!({"k": "first"}),
                expires_at: None,
            }),
            Err(AuthplaneError::Auth(AuthError {
                message: "boom".to_string(),
                code: "transport_error".to_string(),
                status_code: None,
            })),
        ]);
        let cache = DocumentCache::new(fetcher, 600, "test", None);
        let _ = cache.get(false).await.expect("first ok");
        // Force refresh fails; stale cache must be returned.
        let stale = cache.get(true).await.expect("stale");
        assert_eq!(stale["k"], "first");
    }

    #[tokio::test]
    async fn first_fetch_failure_propagates_error() {
        let (fetcher, _counter) = make_fetcher(vec![Err(AuthplaneError::Auth(AuthError {
            message: "boom".to_string(),
            code: "transport_error".to_string(),
            status_code: None,
        }))]);
        let cache = DocumentCache::new(fetcher, 60, "test", None);
        let result = cache.get(false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn expire_forces_the_next_get_to_refetch() {
        let (fetcher, counter) = make_fetcher(vec![
            Ok(FetchResult {
                document: serde_json::json!({"v": 1}),
                expires_at: None,
            }),
            Ok(FetchResult {
                document: serde_json::json!({"v": 2}),
                expires_at: None,
            }),
        ]);
        // A long TTL would normally keep serving the first document.
        let cache = DocumentCache::new(fetcher, 3600, "test", None);
        assert_eq!(cache.get(false).await.expect("first")["v"], 1);
        cache.expire().await;
        assert_eq!(cache.get(false).await.expect("second")["v"], 2);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn expire_keeps_the_stale_body_as_fallback_when_the_refetch_fails() {
        // The expiry must not strip the cache of its last-known-good
        // posture: if the re-fetch it forces fails, callers are served the
        // retired body rather than an error. This is the difference between
        // expiring and dropping — a dropped entry would fail every caller
        // for as long as the new target is unreachable.
        let (fetcher, counter) = make_fetcher(vec![
            Ok(FetchResult {
                document: serde_json::json!({"v": 1}),
                expires_at: None,
            }),
            Err(AuthplaneError::Auth(AuthError {
                message: "new target unreachable".to_string(),
                code: "transport_error".to_string(),
                status_code: None,
            })),
            Ok(FetchResult {
                document: serde_json::json!({"v": 2}),
                expires_at: None,
            }),
        ]);
        let cache = DocumentCache::new(fetcher, 3600, "test", None);
        assert_eq!(cache.get(false).await.expect("first")["v"], 1);

        cache.expire().await;

        // The forced re-fetch fails; the retired body must still answer.
        assert_eq!(cache.get(false).await.expect("stale fallback")["v"], 1);
        // The entry stays expired, so the next get retries the fetch
        // rather than settling back onto the retired body.
        assert_eq!(cache.get(false).await.expect("recovered")["v"], 2);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn on_change_callback_fires_when_document_changes() {
        let (fetcher, _counter) = make_fetcher(vec![
            Ok(FetchResult {
                document: serde_json::json!({"v": 1}),
                expires_at: None,
            }),
            Ok(FetchResult {
                document: serde_json::json!({"v": 2}),
                expires_at: None,
            }),
        ]);
        let invoked = Arc::new(AtomicUsize::new(0));
        let invoked_cb = invoked.clone();
        let on_change: DocumentChangeCallback = Arc::new(move |_old, _new| {
            let invoked_cb = invoked_cb.clone();
            Box::pin(async move {
                invoked_cb.fetch_add(1, Ordering::SeqCst);
            })
        });
        let cache = DocumentCache::new(fetcher, 600, "test", Some(on_change));
        cache.get(false).await.expect("first");
        cache.get(true).await.expect("second");
        // The callback runs on a tokio task; give it a moment.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(invoked.load(Ordering::SeqCst), 1);
    }
}
