//! Inbound DPoP proof replay protection.
//!
//! The store atomically records a freshly-validated `jti`/`exp` pair, returning
//! `false` if the same `jti` had already been seen.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::VerifierError;
use crate::time_utils::unix_now_secs_i64 as unix_now;

/// Atomic replay store used by inbound DPoP verification.
///
/// Implementations MUST guarantee that concurrent calls with the same
/// `jti` produce exactly one `Ok(true)` result; every other call MUST
/// return `Ok(false)`.
///
/// The `Debug` bound lets `InboundDPoPOptions` derive `Debug` without a
/// hand-rolled impl. An opaque `#[derive(Debug)]` suffices for store
/// implementations that don't want to leak internals.
#[async_trait::async_trait]
pub trait DpopReplayStore: Debug + Send + Sync {
    /// Record `jti` if it has not been observed before.
    ///
    /// Returns `Ok(true)` when the `jti` was newly stored, `Ok(false)`
    /// when it had already been seen, or `Err` if the underlying
    /// storage is unreachable.
    async fn check_and_store(&self, jti: &str, expires_at: i64) -> Result<bool, VerifierError>;
}

/// In-memory replay store with eviction on every write.
///
/// Suitable for single-process deployments. For multi-process or
/// distributed deployments, implement [`DpopReplayStore`] on top of
/// Redis or a shared database.
#[derive(Debug, Default, Clone)]
pub struct InMemoryDpopReplayStore {
    inner: Arc<Mutex<HashMap<String, i64>>>,
}

impl InMemoryDpopReplayStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of currently-stored entries (after eviction). Test helper.
    pub async fn len(&self) -> usize {
        let entries = self.inner.lock().await;
        let now = unix_now();
        entries.values().filter(|expires| **expires > now).count()
    }

    /// Whether the store is empty (post-eviction). Test helper.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

#[async_trait::async_trait]
impl DpopReplayStore for InMemoryDpopReplayStore {
    async fn check_and_store(&self, jti: &str, expires_at: i64) -> Result<bool, VerifierError> {
        let mut entries = self.inner.lock().await;
        let now = unix_now();
        // Evict expired entries on every write to bound memory usage.
        entries.retain(|_, exp| *exp > now);
        if entries.contains_key(jti) {
            return Ok(false);
        }
        entries.insert(jti.to_string(), expires_at);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_seen_jti_is_stored() {
        let store = InMemoryDpopReplayStore::new();
        let stored = store
            .check_and_store("jti-1", unix_now() + 60)
            .await
            .unwrap();
        assert!(stored);
    }

    #[tokio::test]
    async fn duplicate_jti_is_rejected() {
        let store = InMemoryDpopReplayStore::new();
        let first = store
            .check_and_store("jti-1", unix_now() + 60)
            .await
            .unwrap();
        let second = store
            .check_and_store("jti-1", unix_now() + 60)
            .await
            .unwrap();
        assert!(first);
        assert!(!second);
    }

    #[tokio::test]
    async fn expired_entries_are_evicted() {
        let store = InMemoryDpopReplayStore::new();
        store
            .check_and_store("jti-old", unix_now() - 1)
            .await
            .unwrap();
        // Triggering another write evicts expired entries.
        store
            .check_and_store("jti-new", unix_now() + 60)
            .await
            .unwrap();
        // The expired jti must be re-acceptable now.
        let stored_again = store
            .check_and_store("jti-old", unix_now() + 60)
            .await
            .unwrap();
        assert!(stored_again);
    }

    #[tokio::test]
    async fn distinct_jtis_coexist() {
        let store = InMemoryDpopReplayStore::new();
        store.check_and_store("a", unix_now() + 60).await.unwrap();
        store.check_and_store("b", unix_now() + 60).await.unwrap();
        assert_eq!(store.len().await, 2);
    }
}
