//! Outbound DPoP provider with per-origin nonce store and helper to build
//! the `DPoP` request header.
//!
//! The provider is intentionally synchronous around proof generation (it does
//! not perform network I/O); nonce retry on 401 `use_dpop_nonce` is implemented
//! at the call site by:
//!
//! 1. building a proof with the current nonce,
//! 2. sending the request,
//! 3. on `use_dpop_nonce`, calling [`DpopProvider::note_nonce`] with the
//!    server-supplied `DPoP-Nonce` header value, and
//! 4. retrying once with the freshly-stored nonce.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::Algorithm;
use serde_json::{Value, json};
use url::Url;

use crate::AuthplaneError;
use crate::dpop::{
    DpopProofOptions, SUPPORTED_DPOP_ALGORITHMS, create_dpop_proof, ensure_supported_dpop_alg,
};
use crate::errors::validation_error;

/// Trait used by [`DpopProvider`] to remember per-origin DPoP nonces.
pub trait DpopNonceStore: Send + Sync {
    /// Return the nonce currently stored for `key`, or empty.
    fn get(&self, key: &str) -> String;
    /// Insert (or replace) the nonce for `key`.
    fn put(&self, key: &str, nonce: &str);
}

/// Bounded LRU-style in-memory nonce store. Single-process default.
#[derive(Debug)]
pub struct InMemoryDpopNonceStore {
    max_entries: usize,
    inner: Mutex<NonceInner>,
}

#[derive(Debug, Default)]
struct NonceInner {
    keys: VecDeque<String>,
    values: std::collections::HashMap<String, String>,
}

impl InMemoryDpopNonceStore {
    /// Default cap.
    pub const DEFAULT_MAX_ENTRIES: usize = 128;

    pub fn new() -> Self {
        Self::with_max_entries(Self::DEFAULT_MAX_ENTRIES)
    }

    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            inner: Mutex::new(NonceInner::default()),
        }
    }
}

impl Default for InMemoryDpopNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DpopNonceStore for InMemoryDpopNonceStore {
    fn get(&self, key: &str) -> String {
        let mut inner = self.inner.lock().expect("poisoned");
        if let Some(value) = inner.values.get(key).cloned() {
            // Move-to-end semantics for LRU.
            inner.keys.retain(|k| k != key);
            inner.keys.push_back(key.to_string());
            return value;
        }
        String::new()
    }

    fn put(&self, key: &str, nonce: &str) {
        let mut inner = self.inner.lock().expect("poisoned");
        if inner.values.contains_key(key) {
            inner.keys.retain(|k| k != key);
        }
        inner.keys.push_back(key.to_string());
        inner.values.insert(key.to_string(), nonce.to_string());
        while inner.keys.len() > self.max_entries {
            if let Some(oldest) = inner.keys.pop_front() {
                inner.values.remove(&oldest);
            }
        }
    }
}

/// Outbound DPoP provider.
#[derive(Clone)]
pub struct DpopProvider {
    private_key_pem: String,
    public_jwk: Value,
    algorithm: Algorithm,
    key_id: Option<String>,
    proof_ttl_seconds: u64,
    nonce_store: Arc<dyn DpopNonceStore>,
}

impl std::fmt::Debug for DpopProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopProvider")
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("proof_ttl_seconds", &self.proof_ttl_seconds)
            .finish()
    }
}

impl DpopProvider {
    /// Default proof TTL.
    pub const DEFAULT_PROOF_TTL_SECONDS: u64 = 300;

    /// Build a provider by importing a PEM-encoded private key.
    ///
    /// Extracts the public JWK parameters automatically. Supports ES256
    /// (P-256 EC) and RS256 (RSA) algorithms.
    pub fn from_pem(pem_str: &str, algorithm: Algorithm) -> Result<Self, AuthplaneError> {
        let public_jwk = extract_public_jwk(pem_str, algorithm)?;
        Self::new(pem_str, public_jwk, algorithm)
    }

    /// Build a provider with an in-memory nonce store.
    pub fn new(
        private_key_pem: impl Into<String>,
        public_jwk: Value,
        algorithm: Algorithm,
    ) -> Result<Self, AuthplaneError> {
        Self::with_options(
            private_key_pem,
            public_jwk,
            algorithm,
            None,
            Self::DEFAULT_PROOF_TTL_SECONDS,
            Arc::new(InMemoryDpopNonceStore::new()),
        )
    }

    /// Build a provider with all knobs exposed.
    pub fn with_options(
        private_key_pem: impl Into<String>,
        public_jwk: Value,
        algorithm: Algorithm,
        key_id: Option<String>,
        proof_ttl_seconds: u64,
        nonce_store: Arc<dyn DpopNonceStore>,
    ) -> Result<Self, AuthplaneError> {
        if proof_ttl_seconds == 0 {
            return Err(validation_error("DPoP proof_ttl_seconds must be positive"));
        }
        ensure_supported_dpop_alg(algorithm)?;
        Ok(Self {
            private_key_pem: private_key_pem.into(),
            public_jwk,
            algorithm,
            key_id,
            proof_ttl_seconds,
            nonce_store,
        })
    }

    /// RFC 7638 SHA-256 thumbprint of the configured public JWK.
    ///
    /// This is the value that appears as `cnf.jkt` in DPoP-bound tokens.
    pub fn thumbprint(&self) -> Result<String, AuthplaneError> {
        crate::dpop::jwk_thumbprint_sha256(&self.public_jwk).map_err(|msg| validation_error(&msg))
    }

    /// Algorithm of the configured signing key.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Configured proof TTL in seconds.
    pub fn proof_ttl_seconds(&self) -> u64 {
        self.proof_ttl_seconds
    }

    /// Public JWK shipped in the proof header (clone).
    pub fn public_jwk(&self) -> Value {
        self.public_jwk.clone()
    }

    /// Build a DPoP proof JWT for the given HTTP method/URL/access token.
    ///
    /// The current per-origin nonce (if any) is automatically added to the
    /// proof claims. Callers can override the nonce or leave the provider
    /// to fetch one from its store.
    pub fn build_proof(
        &self,
        method: &str,
        target_url: &str,
        access_token: Option<&str>,
    ) -> Result<String, AuthplaneError> {
        let nonce = self.current_nonce(target_url)?;
        let options = DpopProofOptions {
            private_key_pem: self.private_key_pem.clone(),
            public_jwk: self.public_jwk.clone(),
            algorithm: self.algorithm,
            key_id: self.key_id.clone(),
            nonce: if nonce.is_empty() { None } else { Some(nonce) },
            proof_ttl_seconds: Some(self.proof_ttl_seconds),
        };
        create_dpop_proof(method, target_url, access_token, &options)
    }

    /// Convenience: build proof + return `{ "DPoP": <proof> }` headers map.
    pub fn build_headers(
        &self,
        method: &str,
        target_url: &str,
        access_token: Option<&str>,
    ) -> Result<Vec<(String, String)>, AuthplaneError> {
        let proof = self.build_proof(method, target_url, access_token)?;
        Ok(vec![("DPoP".to_string(), proof)])
    }

    /// Record a server-issued `DPoP-Nonce` for the URL's origin so the next
    /// outbound request reuses it.
    pub fn note_nonce(&self, target_url: &str, nonce: &str) -> Result<(), AuthplaneError> {
        let key = nonce_key(target_url)?;
        self.nonce_store.put(&key, nonce);
        Ok(())
    }

    /// Look up the current nonce for the URL's origin (empty string if none).
    pub fn current_nonce(&self, target_url: &str) -> Result<String, AuthplaneError> {
        let key = nonce_key(target_url)?;
        Ok(self.nonce_store.get(&key))
    }
}

fn nonce_key(target_url: &str) -> Result<String, AuthplaneError> {
    let parsed = Url::parse(target_url)
        .map_err(|error| validation_error(&format!("DPoP URL must be absolute: {error}")))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let host = parsed
        .host_str()
        .ok_or_else(|| validation_error("DPoP URL is missing host"))?
        .to_ascii_lowercase();
    let port = parsed
        .port()
        .unwrap_or_else(|| if scheme == "https" { 443 } else { 80 });
    Ok(format!("{scheme}://{host}:{port}"))
}

/// Extract the public JWK (as `serde_json::Value`) from a PEM-encoded
/// private key. Supports ES256 (P-256) and RS256 (RSA).
fn extract_public_jwk(pem_str: &str, algorithm: Algorithm) -> Result<Value, AuthplaneError> {
    match algorithm {
        Algorithm::ES256 => extract_ec_p256_jwk(pem_str),
        Algorithm::RS256 => extract_rsa_jwk(pem_str),
        _ => Err(validation_error(&format!(
            "from_pem: unsupported algorithm {algorithm:?}; must be one of {:?}",
            SUPPORTED_DPOP_ALGORITHMS
        ))),
    }
}

fn extract_ec_p256_jwk(pem_str: &str) -> Result<Value, AuthplaneError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::DecodePrivateKey;

    let secret_key = p256::SecretKey::from_pkcs8_pem(pem_str)
        .or_else(|_| {
            // Also try SEC1 format (-----BEGIN EC PRIVATE KEY-----)
            p256::SecretKey::from_sec1_pem(pem_str)
        })
        .map_err(|e| validation_error(&format!("from_pem: failed to parse EC P-256 key: {e}")))?;
    let public_key = secret_key.public_key();
    let point = public_key.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| validation_error("from_pem: EC key missing x coordinate"))?;
    let y = point
        .y()
        .ok_or_else(|| validation_error("from_pem: EC key missing y coordinate"))?;

    Ok(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y),
    }))
}

fn extract_rsa_jwk(pem_str: &str) -> Result<Value, AuthplaneError> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;

    let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(pem_str)
        .map_err(|e| validation_error(&format!("from_pem: failed to parse RSA key: {e}")))?;
    let public_key = private_key.to_public_key();

    let n = public_key.n().to_bytes_be();
    let e = public_key.e().to_bytes_be();

    Ok(json!({
        "kty": "RSA",
        "n": URL_SAFE_NO_PAD.encode(&n),
        "e": URL_SAFE_NO_PAD.encode(&e),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_store_round_trip() {
        let store = InMemoryDpopNonceStore::new();
        store.put("https://auth.example.com:443", "abc");
        assert_eq!(store.get("https://auth.example.com:443"), "abc");
        assert_eq!(store.get("https://other.example.com:443"), "");
    }

    #[test]
    fn nonce_store_is_lru_bounded() {
        let store = InMemoryDpopNonceStore::with_max_entries(2);
        store.put("a", "1");
        store.put("b", "2");
        store.put("c", "3");
        // "a" should have been evicted (oldest).
        assert_eq!(store.get("a"), "");
        assert_eq!(store.get("b"), "2");
        assert_eq!(store.get("c"), "3");
    }

    #[test]
    fn nonce_key_normalizes_origin() {
        assert_eq!(
            nonce_key("https://AUTH.example.com/oauth/token").unwrap(),
            "https://auth.example.com:443"
        );
        assert_eq!(
            nonce_key("http://localhost:9000/path").unwrap(),
            "http://localhost:9000"
        );
    }

    #[test]
    fn rejects_invalid_url() {
        assert!(nonce_key("not-a-url").is_err());
    }

    #[test]
    fn rejects_zero_ttl() {
        let result = DpopProvider::with_options(
            "pem",
            serde_json::json!({"kty":"RSA"}),
            Algorithm::RS256,
            None,
            0,
            Arc::new(InMemoryDpopNonceStore::new()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_disallowed_algorithm() {
        let result = DpopProvider::with_options(
            "pem",
            serde_json::json!({"kty":"oct"}),
            Algorithm::HS256,
            None,
            300,
            Arc::new(InMemoryDpopNonceStore::new()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn note_nonce_persists_per_origin() {
        let store = Arc::new(InMemoryDpopNonceStore::new());
        let provider = DpopProvider::with_options(
            include_str!("../tests/fixtures/test-private.pem").to_string(),
            serde_json::json!({"kty":"RSA","alg":"RS256","use":"sig","n":"x","e":"AQAB"}),
            Algorithm::RS256,
            Some("kid".to_string()),
            300,
            store.clone(),
        )
        .expect("provider");
        provider
            .note_nonce("https://auth.example.com/token", "n-1")
            .unwrap();
        assert_eq!(
            provider
                .current_nonce("https://auth.example.com/oauth/token")
                .unwrap(),
            "n-1"
        );
        assert_eq!(
            provider.current_nonce("https://other.example.com").unwrap(),
            ""
        );
    }
}
