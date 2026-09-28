use reqwest::Client;

use crate::dpop_provider::DpopProvider;
use crate::metadata::AuthorizationServerMetadata;
use crate::oauth::{
    IntrospectionResponse, TokenExchangeOptions, TokenResponse, client_credentials_grant,
    exchange_token, introspect_token, revoke_token,
};
use crate::transport::build_basic_auth_header;
use crate::{AuthplaneError, FetchSettings};

#[derive(Debug, Clone)]
pub struct AuthplaneAuth {
    metadata: AuthorizationServerMetadata,
    fetch_settings: FetchSettings,
    http: Client,
}

impl AuthplaneAuth {
    pub fn new(
        metadata: AuthorizationServerMetadata,
        fetch_settings: FetchSettings,
        http: Client,
    ) -> Self {
        Self {
            metadata,
            fetch_settings,
            http,
        }
    }

    pub fn metadata(&self) -> &AuthorizationServerMetadata {
        &self.metadata
    }

    /// `client_credentials` grant (RFC 6749 §4.4). Pass `Some(&provider)`
    /// to attach a DPoP-bound exchange; `None` for the plain bearer path.
    /// The provider owns the per-origin nonce store, so the RFC 9449 §6.1
    /// `use_dpop_nonce` retry is transparent across calls.
    pub async fn client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
        scopes: &[String],
        resources: &[String],
        dpop: Option<&DpopProvider>,
    ) -> Result<TokenResponse, AuthplaneError> {
        let token_endpoint = self.metadata.token_endpoint()?;
        client_credentials_grant(
            &self.http,
            token_endpoint,
            &build_basic_auth_header(client_id, client_secret),
            &self.fetch_settings,
            scopes,
            resources,
            dpop,
        )
        .await
    }

    /// `client_credentials` grant using a pre-built `Authorization` header
    /// value (e.g. from an [`AuthProvider`](crate::auth_provider::AuthProvider)).
    /// Pass `Some(&provider)` to attach a DPoP-bound exchange; `None` otherwise.
    pub async fn client_credentials_with_header(
        &self,
        auth_header: &str,
        scopes: &[String],
        resources: &[String],
        dpop: Option<&DpopProvider>,
    ) -> Result<TokenResponse, AuthplaneError> {
        let token_endpoint = self.metadata.token_endpoint()?;
        client_credentials_grant(
            &self.http,
            token_endpoint,
            auth_header,
            &self.fetch_settings,
            scopes,
            resources,
            dpop,
        )
        .await
    }

    /// RFC 8693 token exchange. Pass `Some(&provider)` to attach a DPoP-bound
    /// exchange at the token endpoint; `None` for the plain bearer path.
    pub async fn exchange_token(
        &self,
        client_id: &str,
        client_secret: &str,
        options: &TokenExchangeOptions,
        dpop: Option<&DpopProvider>,
    ) -> Result<TokenResponse, AuthplaneError> {
        let token_endpoint = self.metadata.token_endpoint()?;
        exchange_token(
            &self.http,
            token_endpoint,
            options,
            &build_basic_auth_header(client_id, client_secret),
            &self.fetch_settings,
            dpop,
        )
        .await
    }

    /// RFC 7662 token introspection. Pass `Some(&provider)` to attach a
    /// DPoP-bound exchange at the introspection endpoint; `None` otherwise.
    pub async fn introspect(
        &self,
        client_id: &str,
        client_secret: &str,
        token: &str,
        dpop: Option<&DpopProvider>,
    ) -> Result<IntrospectionResponse, AuthplaneError> {
        let introspection_endpoint = self.metadata.introspection_endpoint()?;
        introspect_token(
            &self.http,
            introspection_endpoint,
            token,
            &build_basic_auth_header(client_id, client_secret),
            &self.fetch_settings,
            dpop,
        )
        .await
    }

    /// RFC 7009 token revocation. Pass `Some(&provider)` to attach a DPoP-bound
    /// exchange at the revocation endpoint; `None` otherwise.
    pub async fn revoke(
        &self,
        client_id: &str,
        client_secret: &str,
        token: &str,
        dpop: Option<&DpopProvider>,
    ) -> Result<(), AuthplaneError> {
        let revocation_endpoint = self.metadata.revocation_endpoint()?;
        revoke_token(
            &self.http,
            revocation_endpoint,
            token,
            &build_basic_auth_header(client_id, client_secret),
            &self.fetch_settings,
            dpop,
        )
        .await
    }
}
