//! Pluggable authentication providers for AS credentials.
//!
//! Defines the `AuthProvider` trait and
//! `ClientCredentialsProvider` implementation.

use crate::transport::build_basic_auth_header;

/// Trait for providing HTTP authentication headers to the AS.
///
/// Implement this trait to plug in custom authentication strategies
/// (e.g., mTLS, JWT client assertion). The default implementation
/// [`ClientCredentialsProvider`] uses HTTP Basic authentication with
/// percent-encoded client credentials.
pub trait AuthProvider: Send + Sync {
    /// Return the `Authorization` header value (e.g., `"Basic ..."`)
    /// to include in outbound AS requests.
    fn auth_header(&self) -> String;
}

/// HTTP Basic authentication provider that pre-computes the header
/// from `client_id` and `client_secret`.
///
/// Client-credentials provider.
#[derive(Debug, Clone)]
pub struct ClientCredentialsProvider {
    header: String,
    client_id: String,
}

impl ClientCredentialsProvider {
    pub fn new(client_id: impl Into<String>, client_secret: &str) -> Self {
        let client_id = client_id.into();
        let header = build_basic_auth_header(&client_id, client_secret);
        Self { header, client_id }
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}

impl AuthProvider for ClientCredentialsProvider {
    fn auth_header(&self) -> String {
        self.header.clone()
    }
}

/// Convenience wrapper: treat a pair of `(client_id, client_secret)` as
/// an ad-hoc auth provider without constructing one explicitly.
pub struct InlineCredentials {
    header: String,
}

impl InlineCredentials {
    pub fn new(client_id: &str, client_secret: &str) -> Self {
        Self {
            header: build_basic_auth_header(client_id, client_secret),
        }
    }
}

impl AuthProvider for InlineCredentials {
    fn auth_header(&self) -> String {
        self.header.clone()
    }
}
