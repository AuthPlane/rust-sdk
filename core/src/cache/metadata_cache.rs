//! AS metadata cache (RFC 8414) with `on_change` notifications.
//!
//! Discovers the AS metadata document, validates the discovered `issuer`
//! against the configured one, exposes typed accessors for individual
//! endpoints, and notifies a callback when the cached document changes
//! (e.g. when `jwks_uri` rotates).

use std::sync::Arc;

use serde_json::Value;

use crate::cache::document_cache::{DocumentCache, DocumentChangeCallback, DocumentFetcherFn};
use crate::transport::validate_fetch_url;
use crate::{AuthplaneError, FetchSettings};

/// Convenience alias for the metadata `on_change` callback shape.
pub type MetadataChangeCallback = DocumentChangeCallback;

/// AS metadata cache.
#[derive(Clone)]
pub struct MetadataCache {
    inner: Arc<DocumentCache>,
    expected_issuer: String,
    fetch_settings: FetchSettings,
}

impl std::fmt::Debug for MetadataCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetadataCache")
            .field("expected_issuer", &self.expected_issuer)
            .field("inner", &self.inner)
            .finish()
    }
}

impl MetadataCache {
    /// Create a new metadata cache.
    ///
    /// `fetcher` MUST GET the AS metadata document. `expected_issuer` is
    /// the issuer the application configured; the discovered document
    /// is rejected if its `issuer` field does not match exactly (RFC 8414).
    pub fn new(
        fetcher: DocumentFetcherFn,
        expected_issuer: impl Into<String>,
        fetch_settings: FetchSettings,
        refresh_seconds: u64,
        on_change: Option<MetadataChangeCallback>,
    ) -> Self {
        let inner = DocumentCache::with_error_factory(
            fetcher,
            refresh_seconds,
            "metadata",
            on_change,
            Box::new(metadata_error_factory),
        );
        Self {
            inner,
            expected_issuer: crate::errors::normalize_issuer(&expected_issuer.into()).to_string(),
            fetch_settings,
        }
    }

    /// Underlying [`DocumentCache`] (for `aclose()` plumbing).
    pub fn document_cache(&self) -> Arc<DocumentCache> {
        self.inner.clone()
    }

    /// Cancel any background refresh task.
    pub async fn aclose(&self) {
        self.inner.aclose().await;
    }

    /// Return the cached metadata document, refreshing if expired.
    pub async fn get_metadata(&self) -> Result<Value, AuthplaneError> {
        let document = self.inner.get(false).await?;
        self.validate_issuer(&document)?;
        Ok(document)
    }

    /// Force-refresh and return the metadata document.
    pub async fn refresh(&self) -> Result<Value, AuthplaneError> {
        let document = self.inner.get(true).await?;
        self.validate_issuer(&document)?;
        Ok(document)
    }

    /// Force-refresh, surfacing a failed fetch rather than falling back to
    /// the cached document. See [`DocumentCache::refresh_strict`].
    pub(crate) async fn refresh_strict(&self) -> Result<Value, AuthplaneError> {
        let document = self.inner.refresh_strict().await?;
        self.validate_issuer(&document)?;
        Ok(document)
    }

    /// Read a specific endpoint URL out of the cached metadata.
    pub async fn endpoint(&self, key: &str) -> Result<String, AuthplaneError> {
        let metadata = self.get_metadata().await?;
        let value = metadata
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                metadata_error_factory(&format!("AS metadata missing required '{key}' endpoint"))
            })?
            .to_string();
        validate_fetch_url(&value, &self.fetch_settings, &format!("{key} URL"))?;
        Ok(value)
    }

    /// Convenience accessor for `jwks_uri`. The URL is validated through
    /// the fetch settings (HTTPS-only, SSRF, …).
    pub async fn get_jwks_uri(&self) -> Result<String, AuthplaneError> {
        self.endpoint("jwks_uri").await
    }

    /// Convenience accessor for `token_endpoint`.
    pub async fn get_token_endpoint(&self) -> Result<String, AuthplaneError> {
        self.endpoint("token_endpoint").await
    }

    /// Convenience accessor for `introspection_endpoint`.
    pub async fn get_introspection_endpoint(&self) -> Result<String, AuthplaneError> {
        self.endpoint("introspection_endpoint").await
    }

    /// Convenience accessor for `revocation_endpoint`.
    pub async fn get_revocation_endpoint(&self) -> Result<String, AuthplaneError> {
        self.endpoint("revocation_endpoint").await
    }

    fn validate_issuer(&self, document: &Value) -> Result<(), AuthplaneError> {
        let discovered = document
            .get("issuer")
            .and_then(Value::as_str)
            .map(crate::errors::normalize_issuer)
            .ok_or_else(|| metadata_error_factory("AS metadata missing 'issuer' field"))?;
        if discovered != self.expected_issuer {
            return Err(metadata_error_factory(&format!(
                "AS metadata issuer mismatch: configured {:?}, discovered {:?}",
                self.expected_issuer, discovered
            )));
        }
        Ok(())
    }
}

// Local thin wrapper around the shared `errors::metadata_error` helper.
// Keeps the `Box<dyn Fn(&str) -> AuthplaneError>` shape `DocumentCache`
// expects without re-stating the `AuthError { code: ... }` literal,
// matching `prm.rs` and `metadata.rs` which call the shared helper
// directly.
fn metadata_error_factory(message: &str) -> AuthplaneError {
    crate::errors::metadata_error(message)
}
