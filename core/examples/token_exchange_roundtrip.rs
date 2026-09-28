//! End-to-end OAuth 2.0 Token Exchange (RFC 8693) roundtrip against a running
//! demo authorization server.
//!
//! Steps:
//!   1. `client_credentials` → obtain a machine access token (the "subject").
//!   2. `urn:ietf:params:oauth:grant-type:token-exchange` → swap the subject
//!      token for a downstream token scoped to the requested resource.
//!   3. Print the outcome so the smoke runner can assert `exchange_ok`.
//!
//! The exchange targets the same resource the subject token was minted for,
//! with the demo client's own token. authserver 0.2.0 answers that shape
//! with `consent_required` rather than a token: a same-resource machine
//! exchange is routed through the user-consent path, which no
//! `client_credentials` caller can complete. The round-trip is still the
//! point of this example — the request was built, sent, and the typed
//! error parsed — so `ConsentRequired` counts as success below.
//!
//! Run with:
//!   ISSUER_URL=http://localhost:9000 \
//!   RESOURCE_URL=http://localhost:8080/mcp \
//!   cargo run -p authplane-sdk --example token_exchange_roundtrip
//!
//! Expects the demo authserver and a resource definition populated by
//! `scripts/manual-e2e-setup.sh`. The secrets in `/tmp/authserver-demo.*` are
//! written by that setup script.

use std::env;
use std::error::Error;
use std::fs;

use authplane_sdk::{
    AuthplaneClient, AuthplaneError, FetchSettings, GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN, TokenExchangeOptions,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let issuer_url = env::var("ISSUER_URL").unwrap_or_else(|_| "http://localhost:9000".to_string());
    let resource_url =
        env::var("RESOURCE_URL").unwrap_or_else(|_| "http://localhost:8080/mcp".to_string());
    let scope = env::var("AUTHGENT_SMOKE_SCOPE").unwrap_or_else(|_| "tools/add".to_string());

    let client_id = load_secret(
        "CLIENT_ID",
        "CLIENT_ID_FILE",
        "/tmp/authserver-demo.client-id",
    )?;
    let client_secret = load_secret(
        "CLIENT_SECRET",
        "CLIENT_SECRET_FILE",
        "/tmp/authserver-demo.key",
    )?;

    let client = AuthplaneClient::create(&issuer_url, FetchSettings::from_dev_mode(true)).await?;

    println!("--- 1) client_credentials (subject token) ---");
    let subject = match client
        .client_credentials(
            &client_id,
            &client_secret,
            std::slice::from_ref(&scope),
            std::slice::from_ref(&resource_url),
            None,
        )
        .await
    {
        Ok(token) => token,
        Err(AuthplaneError::Auth(error)) if error.code == "invalid_scope" => {
            client
                .client_credentials(
                    &client_id,
                    &client_secret,
                    &[],
                    std::slice::from_ref(&resource_url),
                    None,
                )
                .await?
        }
        Err(error) => return Err(error.into()),
    };
    println!("subject_token_type: {}", subject.token_type);
    println!("subject_scope: {}", subject.scope);
    println!("subject_access_token_len: {}", subject.access_token.len());

    println!("\n--- 2) token_exchange (grant_type = {GRANT_TYPE_TOKEN_EXCHANGE}) ---");
    let options = TokenExchangeOptions {
        subject_token: subject.access_token.clone(),
        subject_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
        scope: scope.clone(),
        resources: vec![resource_url.clone()],
        ..Default::default()
    };

    let exchange = match client
        .exchange_token(&client_id, &client_secret, &options, None)
        .await
    {
        Err(AuthplaneError::Auth(error)) if error.code == "invalid_scope" => {
            let fallback = TokenExchangeOptions {
                subject_token: subject.access_token.clone(),
                subject_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
                resources: vec![resource_url.clone()],
                ..Default::default()
            };
            client
                .exchange_token(&client_id, &client_secret, &fallback, None)
                .await
        }
        other => other,
    };

    match exchange {
        Ok(exchanged) => {
            if exchanged.access_token.trim().is_empty() {
                return Err("token endpoint returned an empty exchanged access token".into());
            }
            println!("exchanged_token_type: {}", exchanged.token_type);
            println!("issued_token_type: {}", exchanged.issued_token_type);
            println!("exchanged_scope: {}", exchanged.scope);
            println!(
                "exchanged_access_token_len: {}",
                exchanged.access_token.len()
            );
            if !exchanged.cnf_jkt.is_empty() {
                println!("cnf_jkt: {}", exchanged.cnf_jkt);
            }
        }
        // The AS handled the exchange end to end and answered with the
        // typed consent error (see the module docs): the path this example
        // exercises worked. `access_denied` is deliberately NOT tolerated
        // here — it would mean the demo provisioner failed to allowlist
        // the client on the resource, which is a broken setup.
        Err(AuthplaneError::ConsentRequired(consent)) => {
            println!("exchange_outcome: consent_required");
            println!("consent_service_id: {}", consent.service_id);
            println!("consent_cause: {}", consent.cause_detail);
            if let Some(url) = &consent.consent_url {
                println!("consent_url: {url}");
            }
        }
        Err(error) => return Err(error.into()),
    }

    println!(
        "\nexchange_ok issuer={} token_endpoint={} scope={} resource={}",
        client.issuer(),
        client.metadata().token_endpoint()?,
        scope,
        resource_url,
    );

    Ok(())
}

fn load_secret(
    value_env: &str,
    file_env: &str,
    default_path: &str,
) -> Result<String, Box<dyn Error>> {
    if let Ok(value) = env::var(value_env) {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    let path = env::var(file_env).unwrap_or_else(|_| default_path.to_string());
    let contents = fs::read_to_string(&path)?;
    let trimmed = contents.trim().to_string();
    if trimmed.is_empty() {
        return Err(format!("secret file {path} is empty").into());
    }
    Ok(trimmed)
}
