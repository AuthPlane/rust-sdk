use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use authplane_mcp::{
    AuthplaneMcpAuth, RawAccessToken, authplane_mcp_auth_middleware,
    to_url_elicitation_required_error,
};
use authplane_sdk::{
    AuthorizationServerMetadata, AuthplaneAuth, AuthplaneClient, FetchSettings, InboundDPoPOptions,
    ResourceOptions, TokenExchangeOptions, VerifiedClaims,
};
use axum::extract::{Request, State};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ErrorData, ServerCapabilities, ServerInfo};
use rmcp::schemars::JsonSchema;
use rmcp::service::RequestContext;
use rmcp::transport::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::StreamableHttpService;
use rmcp::{RoleServer, ServerHandler, tool, tool_handler, tool_router};
use serde::Deserialize;
use url::Url;

const DEMO_SCOPES: &[&str] = &["tools/add", "tools/multiply", "tools/consent_demo"];

// The authserver demo provisioner registers `google-calendar` as a Broker
// resource with fake upstream credentials. Token-exchange targeting it
// always returns `consent_required` + a `consent_url`; the consent_demo
// tool below surfaces that URL to the MCP client.
const GOOGLE_CALENDAR_RESOURCE_URI: &str = "https://www.googleapis.com/calendar/v3";
const GOOGLE_CALENDAR_SCOPE: &str = "https://www.googleapis.com/auth/calendar";

#[derive(Clone)]
struct DemoState {
    verifier: authplane_sdk::AuthplaneResource,
    prm: authplane_sdk::ProtectedResourceMetadata,
    auth: Option<DemoAuth>,
}

/// Credentials + outbound auth client used by the `consent_demo` tool.
/// `None` when the operator didn't provide a `client_secret` — the bearer
/// tools still work, but `consent_demo` will surface a clear error.
#[derive(Clone)]
struct DemoAuth {
    client_id: String,
    client_secret: String,
    auth: AuthplaneAuth,
}

#[derive(Debug, Clone)]
struct DemoConfig {
    issuer: String,
    resource: String,
    port: u16,
    mcp_path: String,
    client_id: Option<String>,
    client_secret: Option<String>,
}

impl DemoConfig {
    fn from_env() -> Result<Self, String> {
        let issuer = std::env::var("AUTHPLANE_ISSUER")
            .or_else(|_| std::env::var("ISSUER_URL"))
            .unwrap_or_else(|_| "http://localhost:9000".to_string());
        let resource = std::env::var("AUTHPLANE_RESOURCE")
            .or_else(|_| std::env::var("RESOURCE_URL"))
            .unwrap_or_else(|_| "http://localhost:8080/mcp".to_string());
        let resource_url = Url::parse(&resource)
            .map_err(|error| format!("invalid AUTHPLANE_RESOURCE/RESOURCE_URL: {error}"))?;
        let port = resource_url.port_or_known_default().ok_or_else(|| {
            format!("resource URL is missing a port and has no known default: {resource}")
        })?;
        let mcp_path = resource_url.path().to_string();

        // Credential fallback chain:
        //   env AUTHPLANE_CLIENT_ID / CLIENT_ID → /tmp/authserver-demo.client-id
        //   env AUTHPLANE_CLIENT_SECRET / CLIENT_SECRET → /tmp/authserver-demo.key
        // The authserver demo provisioner writes those files; SDK demos
        // pick them up automatically.
        let client_id = std::env::var("AUTHPLANE_CLIENT_ID")
            .or_else(|_| std::env::var("CLIENT_ID"))
            .ok()
            .or_else(|| read_trimmed_file("/tmp/authserver-demo.client-id"));
        let client_secret = std::env::var("AUTHPLANE_CLIENT_SECRET")
            .or_else(|_| std::env::var("CLIENT_SECRET"))
            .ok()
            .or_else(|| read_trimmed_file("/tmp/authserver-demo.key"));

        Ok(Self {
            issuer,
            resource,
            port,
            mcp_path,
            client_id,
            client_secret,
        })
    }
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

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct BinaryOp {
    a: f64,
    b: f64,
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for CalculatorServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "A calculator MCP demo protected by authplane-sdk bearer verification.",
        )
    }
}

#[derive(Debug, Clone)]
struct CalculatorServer {
    tool_router: ToolRouter<Self>,
}

impl CalculatorServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router(router = tool_router)]
impl CalculatorServer {
    #[tool(name = "add", description = "Add two numbers")]
    async fn add(
        &self,
        params: Parameters<BinaryOp>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<String, ErrorData> {
        require_scope(&ctx, "tools/add")?;
        Ok((params.0.a + params.0.b).to_string())
    }

    #[tool(name = "multiply", description = "Multiply two numbers")]
    async fn multiply(
        &self,
        params: Parameters<BinaryOp>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<String, ErrorData> {
        require_scope(&ctx, "tools/multiply")?;
        Ok((params.0.a * params.0.b).to_string())
    }

    #[tool(
        name = "whoami",
        description = "Return the verified subject and scopes from the bearer token"
    )]
    async fn whoami(
        &self,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, ErrorData> {
        let claims = parts.extensions.get::<VerifiedClaims>().ok_or_else(|| {
            ErrorData::internal_error("verified claims missing from request", None)
        })?;
        Ok(format!(
            "sub={} scopes={}",
            claims.sub,
            claims.scopes.join(",")
        ))
    }

    /// Exchange the inbound user token for a Google Calendar token via
    /// RFC 8693. The authserver demo registers `google-calendar` as a
    /// Broker resource with fake upstream credentials, so the exchange
    /// returns `consent_required` + a `consent_url` — the surface MCP
    /// clients use to drive URL elicitation.
    #[tool(
        name = "consent_demo",
        description = "Exchange the inbound token for a Google Calendar token to surface a consent_url."
    )]
    async fn consent_demo(
        &self,
        ctx: RequestContext<RoleServer>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<String, ErrorData> {
        require_scope(&ctx, "tools/consent_demo")?;

        let auth_state = parts.extensions.get::<Option<DemoAuth>>().ok_or_else(|| {
            ErrorData::internal_error("demo auth state missing from request", None)
        })?;
        let auth = auth_state.as_ref().ok_or_else(|| {
            ErrorData::invalid_request(
                "consent_demo requires CLIENT_ID + CLIENT_SECRET. Start the authserver demo provisioner first (./demo/mcp-demo-server-start.sh).",
                None,
            )
        })?;

        let subject_token = parts
            .extensions
            .get::<RawAccessToken>()
            .map(|t| t.0.clone())
            .ok_or_else(|| {
                ErrorData::internal_error("raw access token missing from request context", None)
            })?;

        let options = TokenExchangeOptions {
            subject_token,
            subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
            actor_token: String::new(),
            actor_token_type: String::new(),
            scope: GOOGLE_CALENDAR_SCOPE.to_string(),
            resources: vec![GOOGLE_CALENDAR_RESOURCE_URI.to_string()],
            audiences: vec![],
        };

        match auth
            .auth
            .exchange_token(&auth.client_id, &auth.client_secret, &options, None)
            .await
        {
            Ok(response) => Ok(format!(
                "exchanged: token_type={} scope={}",
                response.token_type, response.scope
            )),
            // Structured URL-elicitation (MCP `-32042`) rather than a
            // substring inside an `invalid_request` message — the latter
            // forces clients to regex-parse the URL out. The helper lives
            // in `authplane-mcp::to_url_elicitation_required_error`.
            Err(error) => match to_url_elicitation_required_error(error) {
                Ok(unmapped) => Err(ErrorData::internal_error(unmapped.to_string(), None)),
                Err(elicitation) => Err(elicitation),
            },
        }
    }
}

fn require_scope(ctx: &RequestContext<RoleServer>, scope: &str) -> Result<(), ErrorData> {
    let parts = ctx
        .extensions
        .get::<axum::http::request::Parts>()
        .ok_or_else(|| ErrorData::internal_error("http request context unavailable", None))?;
    let claims = parts
        .extensions
        .get::<VerifiedClaims>()
        .ok_or_else(|| ErrorData::internal_error("verified claims missing from request", None))?;
    claims
        .require_scope(scope)
        .map_err(|error| ErrorData::invalid_request(error.to_string(), None))
}

async fn protected_resource_metadata(
    State(state): State<DemoState>,
) -> Json<authplane_sdk::ProtectedResourceMetadata> {
    Json(state.prm.clone())
}

/// Tail-end middleware that copies the demo-specific `DemoAuth` handle
/// from the router state into the request extensions, so `consent_demo`
/// can pull it from `RequestContext::extensions`. Runs *after* the
/// reusable `authplane_mcp_auth_middleware` injected the verified
/// claims + raw token, so we never overwrite them.
async fn inject_demo_auth(
    State(state): State<DemoState>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(state.auth.clone());
    next.run(request).await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = DemoConfig::from_env()?;
    let fetch_settings = FetchSettings::from_dev_mode(true);
    let client = AuthplaneClient::create(&config.issuer, fetch_settings.clone()).await?;
    let scopes = DEMO_SCOPES
        .iter()
        .map(|scope| (*scope).to_string())
        .collect::<Vec<_>>();
    // Mode 2 opt-in: this demo accepts both bearer and DPoP-bound tokens
    // (defaults of InboundDPoPOptions). Passing `None` instead would put
    // the resource in Mode 3 — any DPoP signal would be rejected. See
    // `core/src/inbound_dpop.rs` for the full mode dispatch.
    let resource_options =
        ResourceOptions::default().with_inbound_dpop(InboundDPoPOptions::default());
    let verifier = client
        .resource_with_options(&config.resource, &scopes, resource_options)
        .await?;
    let prm_url = verifier
        .prm_document_url()
        .map_err(|error| format!("invalid PRM URL for resource: {error}"))?;
    let prm_path = Url::parse(&prm_url)
        .map_err(|error| format!("invalid PRM URL {prm_url}: {error}"))?
        .path()
        .to_string();
    let prm = verifier.prm_response();

    // Outbound auth client for the consent_demo tool. We construct a fresh
    // reqwest::Client because AuthplaneAuth keeps its own copy independent
    // of AuthplaneClient's internal one: verification and the OAuth client
    // are deliberately separate clients.
    let demo_auth = match (&config.client_id, &config.client_secret) {
        (Some(id), Some(secret)) => Some(DemoAuth {
            client_id: id.clone(),
            client_secret: secret.clone(),
            auth: AuthplaneAuth::new(
                AuthorizationServerMetadata::clone(client.metadata()),
                fetch_settings,
                reqwest::Client::new(),
            ),
        }),
        _ => None,
    };

    let state = DemoState {
        verifier,
        prm,
        auth: demo_auth,
    };

    let service: StreamableHttpService<CalculatorServer, LocalSessionManager> =
        StreamableHttpService::new(
            || Ok(CalculatorServer::new()),
            Default::default(),
            StreamableHttpServerConfig::default(),
        );

    // Reusable adapter middleware: extracts the bearer (or DPoP-scheme)
    // access token, builds an RFC 9449 §4.3 request context anchored on
    // the configured resource origin, and verifies before stashing
    // VerifiedClaims + RawAccessToken in the request extensions. The
    // demo-specific `inject_demo_auth` runs after it to thread the
    // optional outbound-auth handle through to `consent_demo`.
    let resource_origin = {
        let mut url = Url::parse(&config.resource)?;
        url.set_path("");
        url.set_query(None);
        url.set_fragment(None);
        url
    };
    let auth_state = AuthplaneMcpAuth::new(Arc::new(state.verifier.clone()), resource_origin)
        .with_realm("authplane-rmcp-demo");

    let mcp_service = tower::ServiceBuilder::new()
        .layer(from_fn_with_state(
            auth_state,
            authplane_mcp_auth_middleware,
        ))
        .layer(from_fn_with_state(state.clone(), inject_demo_auth))
        .service(service);

    // Serve PRM at BOTH the per-resource path (RFC 9728 §3.1 canonical
    // form) AND the host root `/.well-known/oauth-protected-resource`
    // (MCP authorization spec discovery convention). MCP clients
    // (Claude Code, Inspector) probe the root regardless of the resource
    // path; without the duplicate route their probe 404s and they fall
    // back to the pre-auth `authenticate` handshake.
    let mut app = Router::new()
        .route(&prm_path, get(protected_resource_metadata))
        .route("/healthz", get(|| async { "ok" }));
    if prm_path != "/.well-known/oauth-protected-resource" {
        app = app.route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        );
    }
    let app = app
        .nest_service(&config.mcp_path, mcp_service)
        .with_state(state);

    let bind = SocketAddr::from(([127, 0, 0, 1], config.port));
    let listener = tokio::net::TcpListener::bind(bind).await?;

    println!(
        "Authplane RMCP demo listening on http://{}{}",
        bind, config.mcp_path
    );
    println!("  issuer:   {}", config.issuer);
    println!("  resource: {}", config.resource);
    println!("  prm:      {prm_url}  (also served at /.well-known/oauth-protected-resource)");
    println!("  scopes:   {}", DEMO_SCOPES.join(", "));
    println!(
        "  consent_demo: {}",
        if config.client_id.is_some() && config.client_secret.is_some() {
            "armed (token-exchange will surface consent_required)"
        } else {
            "disabled — set CLIENT_ID + CLIENT_SECRET to enable"
        }
    );

    axum::serve(listener, app).await?;
    Ok(())
}
