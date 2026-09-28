use authplane_fastmcp::{AuthplaneFastMcpTokenVerifier, wrap_tool_with_url_elicitation};
use authplane_sdk::{
    AuthplaneClient, AuthplaneError, ConsentRequiredError, FetchSettings, ResourceOptions,
};
use fastmcp_rust::HttpServerConfig;
use fastmcp_rust::prelude::*;
use std::path::Path;
use std::sync::Arc;

const DEMO_SCOPES: &[&str] = &["tools/add", "tools/multiply", "tools/consent_demo"];

#[tool(description = "Add two numbers")]
async fn add(ctx: &McpContext, a: f64, b: f64) -> McpResult<String> {
    require_scope(ctx, "tools/add")?;
    Ok((a + b).to_string())
}

#[tool(description = "Multiply two numbers")]
async fn multiply(ctx: &McpContext, a: f64, b: f64) -> McpResult<String> {
    require_scope(ctx, "tools/multiply")?;
    Ok((a * b).to_string())
}

#[tool(description = "Show the current auth context")]
async fn whoami(ctx: &McpContext) -> McpResult<String> {
    let auth = ctx
        .auth()
        .ok_or_else(|| McpError::tool_error("missing auth context"))?;
    Ok(format!(
        "subject={} scopes={}",
        auth.subject.as_deref().unwrap_or("anonymous"),
        auth.scopes.join(",")
    ))
}

#[tool(description = "Demonstrate consent-required mapping into URL elicitation")]
async fn consent_demo(ctx: &McpContext) -> Result<String, McpError> {
    // Real demo wiring would require this scope to drive a token exchange
    // against the authserver's `google-calendar` Broker resource; the
    // simulated path below is enough for the URL-elicitation surface
    // smoke. This file shows the SDK shape; the http_calculator_demo in
    // mcp/demo uses the live exchange directly.
    require_scope(ctx, "tools/consent_demo")?;
    wrap_tool_with_url_elicitation(|| async {
        Err::<String, AuthplaneError>(AuthplaneError::from(ConsentRequiredError {
            message: "Consent is required to continue".to_string(),
            code: "consent_required".to_string(),
            status_code: Some(400),
            service_id: "google-calendar".to_string(),
            cause_detail: "consent_missing".to_string(),
            consent_url: Some(
                "http://localhost:9000/oauth/authorize?resource=calculator-mcp-demo".to_string(),
            ),
        }))
    })
    .await
}

fn require_scope(ctx: &McpContext, scope: &str) -> McpResult<()> {
    let auth = ctx
        .auth()
        .ok_or_else(|| McpError::tool_error("missing auth context"))?;
    if auth.scopes.iter().any(|candidate| candidate == scope) {
        return Ok(());
    }
    Err(McpError::tool_error(format!(
        "missing required scope {scope}; available scopes: {}",
        auth.scopes.join(",")
    )))
}

fn env(name: &str, legacy_name: &str, fallback: &str) -> String {
    std::env::var(name)
        .or_else(|_| std::env::var(legacy_name))
        .unwrap_or_else(|_| fallback.to_string())
}

fn read_trimmed_file(path: &str) -> Option<String> {
    if !Path::new(path).exists() {
        return None;
    }
    std::fs::read_to_string(path)
        .ok()
        .map(|content| content.trim().to_string())
        .filter(|content| !content.is_empty())
}

fn main() {
    let issuer = env("AUTHPLANE_ISSUER", "ISSUER_URL", "http://localhost:9000");
    let resource = env(
        "AUTHPLANE_RESOURCE",
        "RESOURCE_URL",
        "http://localhost:8080/mcp",
    );
    let bind_addr = env("BIND_ADDR", "BIND_ADDR", "127.0.0.1:8080");
    let transport = env("TRANSPORT", "TRANSPORT", "http");
    let scopes = DEMO_SCOPES
        .iter()
        .map(|scope| (*scope).to_string())
        .collect::<Vec<_>>();

    // Credential discovery — env first, then /tmp files written by the
    // authserver demo provisioner. Logged below for visibility; not used
    // by the simulated consent_demo (the http_calculator_demo in the
    // mcp/ crate runs the live token-exchange against these credentials).
    let client_id = std::env::var("AUTHPLANE_CLIENT_ID")
        .or_else(|_| std::env::var("CLIENT_ID"))
        .ok()
        .or_else(|| read_trimmed_file("/tmp/authserver-demo.client-id"));
    let client_secret_present = std::env::var("AUTHPLANE_CLIENT_SECRET")
        .or_else(|_| std::env::var("CLIENT_SECRET"))
        .ok()
        .or_else(|| read_trimmed_file("/tmp/authserver-demo.key"))
        .is_some();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to initialize async runtime for demo startup");
    let client = runtime
        .block_on(AuthplaneClient::create(
            &issuer,
            FetchSettings::from_dev_mode(true),
        ))
        .expect("failed to create authplane client");

    // fastmcp-rust 0.3 strips HTTP headers before reaching TokenVerifier,
    // so this adapter runs in bearer-only mode (Mode 3 default — no
    // InboundDPoPOptions). DPoP-aware MCP servers in Rust should use the
    // `authplane-mcp` adapter, which is axum-native and ships the full
    // verify_with_context pipeline. See `authplane_fastmcp::auth` module
    // docs for the upstream constraint.
    let resource_options = ResourceOptions::default();
    let verifier = runtime
        .block_on(client.resource_with_options(&resource, &scopes, resource_options))
        .expect("failed to create authplane resource verifier");
    let provider = TokenAuthProvider::new(
        AuthplaneFastMcpTokenVerifier::new(Arc::new(verifier))
            .expect("failed to create token verifier"),
    );

    println!("Authplane FastMCP demo starting");
    println!("  transport:  {transport}");
    println!("  issuer:     {issuer}");
    println!("  resource:   {resource}");
    println!("  scopes:     {}", DEMO_SCOPES.join(", "));
    println!(
        "  client_id:  {}",
        client_id.as_deref().unwrap_or("<unset>")
    );
    println!(
        "  client_secret: {}",
        if client_secret_present {
            "present"
        } else {
            "<unset>"
        }
    );

    let server = Server::new("authplane-fastmcp-demo", "0.1.0")
        .instructions(
            "A calculator FastMCP demo showing tool scope checks and consent URL elicitation.",
        )
        .http_config(HttpServerConfig::default())
        .auth_provider(provider)
        .tool(Add)
        .tool(Multiply)
        .tool(Whoami)
        .tool(ConsentDemo)
        .build();

    match transport.as_str() {
        "stdio" => {
            println!("  listening:  stdio");
            server.run_stdio();
        }
        _ => {
            println!("  listening:  http://{bind_addr}/mcp");
            server.run_http(&bind_addr);
        }
    }
}
