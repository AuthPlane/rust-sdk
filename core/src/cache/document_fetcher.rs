//! SSRF-protected JSON document fetcher used by the metadata and JWKS caches.

use std::sync::Arc;

use reqwest::Client;
use serde_json::Value;

use crate::cache::cache_headers::parse_expires_at;
use crate::cache::document_cache::FetchResult;
use crate::errors::transport_error;
use crate::transport::{build_http_client, ssrf_safe_get, validate_fetch_url};
use crate::{AuthplaneError, FetchSettings};

/// Fetcher for JSON documents (AS metadata, JWKS, …).
///
/// Validates the URL through [`crate::transport::validate_fetch_url`], honours
/// the configured timeout / SSRF policy, enforces a `max_size` body limit, and
/// parses the response body as JSON.
#[derive(Debug, Clone)]
pub struct DocumentFetcher {
    url: String,
    document_type: String,
    settings: FetchSettings,
    max_size: u64,
    http: Arc<Client>,
}

impl DocumentFetcher {
    /// Default size cap for AS metadata documents (128 KB).
    pub const DEFAULT_METADATA_MAX_BYTES: u64 = 131_072;
    /// Default size cap for JWKS documents (64 KB).
    pub const DEFAULT_JWKS_MAX_BYTES: u64 = 65_536;

    /// Build a fetcher from a brand new HTTP client.
    pub fn new(
        url: impl Into<String>,
        document_type: impl Into<String>,
        settings: FetchSettings,
        max_size: u64,
    ) -> Result<Self, AuthplaneError> {
        let http = Arc::new(build_http_client(&settings)?);
        Ok(Self {
            url: url.into(),
            document_type: document_type.into(),
            settings,
            max_size,
            http,
        })
    }

    /// Build a fetcher reusing an existing HTTP client (e.g. shared with
    /// `AuthplaneClient`).
    pub fn with_client(
        url: impl Into<String>,
        document_type: impl Into<String>,
        settings: FetchSettings,
        max_size: u64,
        http: Arc<Client>,
    ) -> Self {
        Self {
            url: url.into(),
            document_type: document_type.into(),
            settings,
            max_size,
            http,
        }
    }

    /// Target URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Document type label (used in errors / logs).
    pub fn document_type(&self) -> &str {
        &self.document_type
    }

    /// Perform a fetch, returning the parsed JSON body and the absolute
    /// expiry timestamp derived from cache headers (if any).
    pub async fn fetch(&self) -> Result<FetchResult, AuthplaneError> {
        validate_fetch_url(
            &self.url,
            &self.settings,
            &format!("{} URL", self.document_type),
        )?;

        if self.settings.ssrf_protection {
            // DNS-pinned SSRF-safe fetch path.
            let ssrf_response = ssrf_safe_get(&self.url, &self.settings, self.max_size).await?;

            if !crate::transport::is_http_success(ssrf_response.status_code) {
                return Err(transport_error(&format!(
                    "{} fetch returned HTTP {}",
                    self.document_type, ssrf_response.status_code
                )));
            }

            let expires_at = parse_expires_at(
                ssrf_response
                    .headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str())),
            );

            Ok(FetchResult {
                document: ssrf_response.body,
                expires_at,
            })
        } else {
            // Plain reqwest path (no SSRF protection).
            let response = self.http.get(&self.url).send().await.map_err(|error| {
                transport_error(&format!("{} fetch failed: {error}", self.document_type))
            })?;

            let status = response.status().as_u16();
            if !crate::transport::is_http_success(status) {
                return Err(transport_error(&format!(
                    "{} fetch returned HTTP {status}",
                    self.document_type
                )));
            }

            // Header snapshot for cache parsing (consumes nothing).
            let header_snapshot: Vec<(String, String)> = response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|v| (name.to_string(), v.to_string()))
                })
                .collect();

            let bytes = response.bytes().await.map_err(|error| {
                transport_error(&format!("{} body read failed: {error}", self.document_type))
            })?;

            if bytes.len() as u64 > self.max_size {
                return Err(transport_error(&format!(
                    "{} document exceeds {} bytes",
                    self.document_type, self.max_size
                )));
            }

            let document: Value = serde_json::from_slice(&bytes).map_err(|error| {
                transport_error(&format!(
                    "{} body is not valid JSON: {error}",
                    self.document_type
                ))
            })?;

            let expires_at = parse_expires_at(
                header_snapshot
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str())),
            );

            Ok(FetchResult {
                document,
                expires_at,
            })
        }
    }
}
