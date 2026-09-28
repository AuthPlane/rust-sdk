use std::env;
use std::error::Error;
use std::fs;

use authplane_sdk::{AuthplaneClient, AuthplaneError, FetchSettings};

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
    let token = match client
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

    if token.access_token.trim().is_empty() {
        return Err("token endpoint returned an empty access token".into());
    }

    println!(
        "smoke_ok issuer={} token_endpoint={} scope={} resource={} token_type={} expires_in={:?}",
        client.issuer(),
        client.metadata().token_endpoint()?,
        scope,
        resource_url,
        token.token_type,
        token.expires_in
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
