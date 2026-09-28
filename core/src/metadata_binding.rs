//! Live binding between the AS-metadata cache and the JWKS cache.
//!
//! RFC 8414 §2 publishes `jwks_uri` inside the AS metadata document and
//! specifies no refresh cadence; `metadata_refresh_seconds` supplies it.
//! A verifier that captures `jwks_uri` once at construction can never
//! follow a rotation — it keeps fetching keys from the withdrawn URL.
//!
//! This type closes that gap without a caller-visible refresh call. The
//! URL the JWKS fetcher targets lives in a shared cell rather than being
//! baked into the fetcher, and ordinary verification traffic drives the
//! re-read: once the configured interval has elapsed, the next key
//! lookup re-reads metadata through [`MetadataCache`] and, if `jwks_uri`
//! changed, swaps the cell and expires the keys cached from the old URL
//! (kept as stale fallback should the new URL not answer).
//!
//! The interval is not the only trigger. A `kid` the bound key set does
//! not contain is itself evidence that the binding is stale, so that
//! lookup re-reads immediately rather than waiting out the interval —
//! floored, since it runs before anything has been authenticated. See
//! [`MetadataBinding::refresh_on_kid_miss`].

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::cache::{JwksCache, MetadataCache};
use crate::errors::metadata_error;
use crate::metadata::AuthorizationServerMetadata;
use crate::{AuthplaneError, FetchSettings};

/// Shared cell holding the `jwks_uri` the JWKS fetcher currently targets.
///
/// Read once per fetch (see `client::rebindable_jwks_fetcher`) so a
/// rotation applied here takes effect on the next JWKS fetch without
/// rebuilding the [`JwksCache`] — which every already-created
/// [`AuthplaneResource`](crate::AuthplaneResource) holds by `Arc` and so
/// could not be swapped out from under them anyway.
pub(crate) type JwksUriCell = Arc<RwLock<String>>;

/// Keeps JWKS fetching bound to the `jwks_uri` currently published by the
/// authorization server.
pub(crate) struct MetadataBinding {
    metadata_cache: MetadataCache,
    jwks_cache: Arc<JwksCache>,
    jwks_uri: JwksUriCell,
    expected_issuer: String,
    fetch_settings: FetchSettings,
    refresh_interval: Duration,
    /// Earliest instant at which the next metadata re-read may run. Kept
    /// separate from the [`MetadataCache`]'s own TTL so the hot path pays
    /// a single uncontended mutex rather than a document clone + parse on
    /// every verification.
    next_check: Mutex<Instant>,
    /// Minimum spacing between forced re-reads driven by a `kid` miss.
    forced_read_floor: Duration,
    /// When the last forced re-read was admitted, `None` until the first.
    last_forced_read: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for MetadataBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `try_read`, not `current_jwks_uri`: a Debug impl runs inside
        // tracing and panic-handler paths, where a panic on a poisoned or
        // contended lock is worse than printing `None`.
        f.debug_struct("MetadataBinding")
            .field("expected_issuer", &self.expected_issuer)
            .field("refresh_interval", &self.refresh_interval)
            .field("jwks_uri", &self.jwks_uri.try_read().ok().as_deref())
            .finish()
    }
}

impl MetadataBinding {
    /// Ceiling on how far apart forced re-reads are spaced. The floor
    /// itself is `min(refresh_seconds, this)`, so a deployment that asks
    /// for fresher metadata than a minute still gets it.
    const FORCED_READ_FLOOR_CEILING: Duration = Duration::from_secs(60);

    /// Ceiling on how long a failed re-read may defer the next attempt.
    /// The retry is `min(refresh_interval, this)`, so it never stretches
    /// the configured cadence — only shortens it after a failure.
    pub(crate) const FAILED_RELOAD_RETRY_CEILING: Duration = Duration::from_secs(60);

    /// Wire a binding over an already-primed metadata cache and JWKS cache.
    ///
    /// `refresh_seconds` is the client's `metadata_refresh_seconds`; the
    /// first re-read becomes due one interval after construction, which is
    /// also when the metadata cache's own boot entry expires.
    pub(crate) fn new(
        metadata_cache: MetadataCache,
        jwks_cache: Arc<JwksCache>,
        jwks_uri: JwksUriCell,
        expected_issuer: String,
        fetch_settings: FetchSettings,
        refresh_seconds: u64,
    ) -> Self {
        let refresh_interval = Duration::from_secs(refresh_seconds.max(1));
        Self {
            metadata_cache,
            jwks_cache,
            jwks_uri,
            expected_issuer,
            fetch_settings,
            refresh_interval,
            next_check: Mutex::new(Instant::now() + refresh_interval),
            forced_read_floor: std::cmp::min(refresh_interval, Self::FORCED_READ_FLOOR_CEILING),
            last_forced_read: Mutex::new(None),
        }
    }

    /// Re-read AS metadata if the refresh interval has elapsed, rebinding
    /// JWKS fetching when `jwks_uri` rotated.
    ///
    /// Called from the verification path, so following a rotation costs
    /// the caller nothing beyond the traffic it was already serving.
    /// Errors are deliberately swallowed: an unreachable or malformed
    /// metadata document must not fail tokens that the currently bound
    /// keys can still verify — the same last-known-good posture the
    /// document cache takes on a failed refresh. Swallowed, but not
    /// forgotten: a failed re-read brings the next attempt forward
    /// instead of leaving the gate parked a full interval out.
    ///
    /// Cancellation caveat, accepted: the gate advances before the fetch
    /// (deliberately — see [`Self::claim_due_check`]), so a caller dropped
    /// mid-reload (an HTTP server dropping the handler future on client
    /// disconnect, say) performs no read and schedules no retry, deferring
    /// the next timed read until the advanced gate — up to one interval.
    /// The same holds for the forced-read floor in
    /// [`Self::refresh_on_kid_miss`], bounded there by
    /// `min(interval, 60s)`. A rotation is still followed meanwhile: the
    /// next surviving verification that misses on `kid` re-reads through
    /// the floored miss path, so a dropped read defers discovery by at
    /// most the floor, not the interval. A gate restored on drop would
    /// reopen the pile-up and amplification that stamping before the
    /// fetch exists to prevent.
    pub(crate) async fn refresh_if_due(&self) {
        if !self.claim_due_check() {
            return;
        }
        if self.reload().await.is_err() {
            self.schedule_retry_after_failure();
        }
    }

    /// Re-read metadata now, ignoring the interval gate, because a `kid`
    /// miss says the current binding is stale. Returns whether `jwks_uri`
    /// moved, i.e. whether retrying the key lookup can produce a different
    /// answer.
    ///
    /// The one request that proves the binding is wrong — a `kid` the
    /// bound key set does not contain — is otherwise the one request that
    /// cannot correct it: the gate is a no-op until the interval is up, so
    /// an AS that rotates `jwks_uri` and retires the old key set at the
    /// same moment takes the whole interval to recover.
    ///
    /// Floored, because bypassing the interval is on its own no rate
    /// limit. The caller that reaches here has authenticated nothing —
    /// `verify` has only decoded the header — so a well-formed header
    /// carrying an arbitrary `kid` would otherwise cost the AS one
    /// discovery fetch per request, forever, on top of the JWKS fetch the
    /// miss already triggers. The floor still follows a real rotation
    /// promptly: the first miss after it elapses re-reads immediately.
    pub(crate) async fn refresh_on_kid_miss(&self) -> bool {
        if !self.admit_forced_read() {
            return false;
        }
        self.reload().await.unwrap_or(false)
    }

    /// Returns `true` for exactly one caller per interval; that caller
    /// owns the re-read and the interval is advanced before the fetch so
    /// concurrent verifications do not pile up behind it.
    fn claim_due_check(&self) -> bool {
        let mut next = self.next_check.lock().expect("refresh clock poisoned");
        let now = Instant::now();
        if now < *next {
            return false;
        }
        *next = now + self.refresh_interval;
        true
    }

    /// Whether a forced re-read may run now, recording it if so.
    ///
    /// Recorded before the fetch, not after: a metadata endpoint that is
    /// slow or failing must not become a way to hold the floor open.
    fn admit_forced_read(&self) -> bool {
        let mut last = self
            .last_forced_read
            .lock()
            .expect("forced-read clock poisoned");
        let now = Instant::now();
        if let Some(previous) = *last
            && now.saturating_duration_since(previous) < self.forced_read_floor
        {
            return false;
        }
        *last = Some(now);
        true
    }

    /// Bring the next check forward after a failed re-read.
    ///
    /// `claim_due_check` advances the gate before the fetch, so without
    /// this one unreachable metadata endpoint, one malformed document or
    /// one rotated `jwks_uri` rejected by the fetch policy would cost a
    /// full interval — an hour at the defaults — before anything tried
    /// again. Only ever moves the gate earlier, so a caller that lost the
    /// race and set a later check is not pushed back.
    fn schedule_retry_after_failure(&self) {
        let retry = std::cmp::min(self.refresh_interval, Self::FAILED_RELOAD_RETRY_CEILING);
        let candidate = Instant::now() + retry;
        let mut next = self.next_check.lock().expect("refresh clock poisoned");
        if candidate < *next {
            *next = candidate;
        }
    }

    /// Re-read metadata and rebind if `jwks_uri` moved. Returns whether a
    /// rebind happened.
    ///
    /// The read is forced. A TTL-gated read would not do: the gate above
    /// and the [`MetadataCache`]'s own TTL are both
    /// `metadata_refresh_seconds`, but the gate advances before the fetch
    /// while the cache stamps its TTL after it, so from the second gate
    /// fire onwards the gate always comes due while the cached document is
    /// still warm. A non-forced read at that moment takes the cache's fast
    /// path and hands back the previous interval's body — the rebind would
    /// run off a document up to one interval old, putting worst-case
    /// rotation latency at twice the configured interval.
    ///
    /// `refresh_strict` rather than `refresh`: the cache answers a failed
    /// fetch with the last good document, which would report success here
    /// and let the caller schedule its next attempt a full interval away
    /// on the strength of a read that never happened.
    async fn reload(&self) -> Result<bool, AuthplaneError> {
        let document = self.metadata_cache.refresh_strict().await?;
        let metadata: AuthorizationServerMetadata = serde_json::from_value(document)
            .map_err(|error| metadata_error(&format!("AS metadata is not well-formed: {error}")))?;
        // Same validation the boot path applies: a rotated `jwks_uri` is
        // an outbound fetch target and must clear the HTTPS / SSRF policy
        // before anything binds to it.
        metadata.validate(&self.expected_issuer, &self.fetch_settings)?;
        Ok(self.rebind_jwks(metadata.jwks_uri).await)
    }

    async fn rebind_jwks(&self, jwks_uri: String) -> bool {
        {
            let current = self.jwks_uri.read().expect("jwks_uri lock poisoned");
            if *current == jwks_uri {
                return false;
            }
        }
        {
            let mut current = self.jwks_uri.write().expect("jwks_uri lock poisoned");
            if *current == jwks_uri {
                return false;
            }
            *current = jwks_uri;
        }
        // The cached JWKS was fetched from the withdrawn URL. Leaving it
        // warm would keep retired keys answering lookups until the JWKS
        // TTL expired, and would hide the rebind from any token whose
        // `kid` happened to still be present there. Expired rather than
        // dropped: if the rebound URI cannot be fetched, the retired key
        // set keeps verifying as the stale fallback — last-known-good,
        // not an outage — until a fetch of the new target succeeds.
        self.jwks_cache.expire().await;
        true
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::{Value, json};

    use super::*;
    use crate::cache::{DocumentFetcherFn, FetchResult};

    const ISSUER: &str = "https://auth.example.com";
    const JWKS_V1: &str = "https://auth.example.com/jwks-v1.json";
    const JWKS_V2: &str = "https://auth.example.com/jwks-v2.json";

    fn metadata_document(jwks_uri: &str) -> Value {
        json!({ "issuer": ISSUER, "jwks_uri": jwks_uri })
    }

    /// Fetcher that walks a scripted list of responses and then repeats the
    /// last one, counting every upstream call.
    fn scripted_fetcher(
        responses: Vec<Result<Value, &'static str>>,
    ) -> (DocumentFetcherFn, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let script = Arc::new(responses);
        let fetcher: DocumentFetcherFn = Arc::new(move || {
            let index = counter.fetch_add(1, Ordering::SeqCst);
            let script = script.clone();
            Box::pin(async move {
                let slot = std::cmp::min(index, script.len().saturating_sub(1));
                match &script[slot] {
                    Ok(document) => Ok(FetchResult {
                        document: document.clone(),
                        expires_at: None,
                    }),
                    Err(message) => Err(crate::errors::metadata_error(message)),
                }
            }) as Pin<Box<_>>
        });
        (fetcher, calls)
    }

    fn dead_jwks_fetcher() -> DocumentFetcherFn {
        Arc::new(|| {
            Box::pin(async { Err(crate::errors::auth_error("jwks_fetch_error", "unused")) })
                as Pin<Box<_>>
        })
    }

    /// Wire a binding the way `AuthplaneClient::build` does, except that the
    /// metadata cache's own TTL is passed separately so a test can hold the
    /// document warm while the binding's gate is due.
    fn binding_with(
        fetcher: DocumentFetcherFn,
        cache_ttl_seconds: u64,
        refresh_seconds: u64,
    ) -> (Arc<MetadataBinding>, JwksUriCell) {
        let metadata_cache = MetadataCache::new(
            fetcher,
            ISSUER,
            FetchSettings::default(),
            cache_ttl_seconds,
            None,
        );
        let jwks_uri: JwksUriCell = Arc::new(RwLock::new(JWKS_V1.to_string()));
        let jwks_cache = Arc::new(JwksCache::new(dead_jwks_fetcher(), 3600));
        let binding = Arc::new(MetadataBinding::new(
            metadata_cache,
            jwks_cache,
            jwks_uri.clone(),
            ISSUER.to_string(),
            FetchSettings::default(),
            refresh_seconds,
        ));
        (binding, jwks_uri)
    }

    /// Bring the gate forward instead of sleeping through the interval.
    fn make_check_due(binding: &MetadataBinding) {
        *binding.next_check.lock().expect("refresh clock") = Instant::now();
    }

    #[tokio::test]
    async fn due_reload_reads_a_fresh_document_rather_than_the_cached_one() {
        // The cache's TTL and the binding's gate are both
        // `metadata_refresh_seconds` in production, and the gate advances
        // before the fetch while the cache stamps its TTL after it — so the
        // gate always comes due while the cached document is still warm by
        // roughly one fetch duration. A non-forced read at that moment hands
        // back the previous interval's document, and the rebind runs off a
        // document that is up to a full interval old.
        //
        // The long cache TTL here is that skew taken to its limit: the read
        // the gate performs has to be authoritative, not a cache hit.
        let (fetcher, calls) = scripted_fetcher(vec![
            Ok(metadata_document(JWKS_V1)),
            Ok(metadata_document(JWKS_V2)),
        ]);
        let (binding, jwks_uri) = binding_with(fetcher, 3600, 3600);

        // Prime the cache the way the boot fetch does.
        binding
            .metadata_cache
            .get_metadata()
            .await
            .expect("boot document");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        make_check_due(&binding);
        binding.refresh_if_due().await;

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the due re-read must reach the AS, not answer from the cached document",
        );
        assert_eq!(
            *jwks_uri.read().expect("jwks_uri lock"),
            JWKS_V2,
            "the rotated jwks_uri must be bound off the document the re-read fetched",
        );
    }

    #[tokio::test]
    async fn a_failed_reload_retries_within_a_bounded_window_not_a_full_interval() {
        // The gate advances before the fetch, so a failed re-read used to
        // cost the whole interval — an hour at the default — before anything
        // tried again. It must come back inside a bounded window instead.
        //
        // The failure here is a 503 at the metadata endpoint with a warm
        // cache behind it, which is the case that has to reach the retry
        // branch at all: `DocumentCache` serves the last good document on a
        // failed fetch, so the caller only learns the read failed if it asks
        // for one that does not fall back.
        let (fetcher, calls) = scripted_fetcher(vec![
            Ok(metadata_document(JWKS_V1)),
            Err("metadata endpoint returned HTTP 503"),
        ]);
        let (binding, _jwks_uri) = binding_with(fetcher, 3600, 3600);

        binding
            .metadata_cache
            .get_metadata()
            .await
            .expect("boot document");

        make_check_due(&binding);
        let before = Instant::now();
        binding.refresh_if_due().await;

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the due re-read must have attempted an upstream fetch",
        );
        let next_check = *binding.next_check.lock().expect("refresh clock");
        let wait = next_check.saturating_duration_since(before);
        assert!(
            wait <= MetadataBinding::FAILED_RELOAD_RETRY_CEILING + Duration::from_secs(1),
            "a failed re-read must retry within a bounded window, not a full interval (waits {wait:?})",
        );
    }

    #[tokio::test]
    async fn a_successful_reload_keeps_the_full_interval() {
        // Counter-test: the bounded retry must not shorten the ordinary
        // cadence, otherwise every verifier would re-read metadata once a
        // minute regardless of its configuration.
        let (fetcher, _calls) = scripted_fetcher(vec![Ok(metadata_document(JWKS_V1))]);
        let (binding, _jwks_uri) = binding_with(fetcher, 3600, 3600);

        binding
            .metadata_cache
            .get_metadata()
            .await
            .expect("boot document");

        make_check_due(&binding);
        let before = Instant::now();
        binding.refresh_if_due().await;

        let next_check = *binding.next_check.lock().expect("refresh clock");
        assert!(
            next_check.saturating_duration_since(before)
                > MetadataBinding::FAILED_RELOAD_RETRY_CEILING,
            "a successful re-read must keep the configured interval",
        );
    }

    #[tokio::test]
    async fn a_kid_miss_re_read_bypasses_the_gate_but_is_floored() {
        // The gate is nowhere near due, so only the forced path can follow
        // the rotation; and a second miss straight afterwards must not buy a
        // second discovery fetch.
        let (fetcher, calls) = scripted_fetcher(vec![
            Ok(metadata_document(JWKS_V1)),
            Ok(metadata_document(JWKS_V2)),
        ]);
        let (binding, jwks_uri) = binding_with(fetcher, 3600, 3600);

        binding
            .metadata_cache
            .get_metadata()
            .await
            .expect("boot document");

        assert!(
            binding.refresh_on_kid_miss().await,
            "the forced re-read must report the rebind it performed",
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(*jwks_uri.read().expect("jwks_uri lock"), JWKS_V2);

        assert!(
            !binding.refresh_on_kid_miss().await,
            "a second miss inside the floor must not re-read",
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the floor must hold the AS to one forced discovery fetch",
        );
    }
}
