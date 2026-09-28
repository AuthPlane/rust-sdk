# authplane-fastmcp User Guide

OAuth 2.1 JWT authentication for [`fastmcp-rust`](https://crates.io/crates/fastmcp-rust), powered by the [Authplane Rust SDK (`authplane-sdk`)](../../core).

`authplane-fastmcp` is a thin layer on top of `authplane-sdk`. All JWT validation, PRM, revocation, and DPoP work lives in the core crate. This crate adds a `TokenVerifier` pattern that plugs into `fastmcp-rust`'s `AuthProvider`, plus the MCP URL-elicitation mapping (`-32042`) for consent-required errors.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Transports: HTTP and Stdio](#transports-http-and-stdio)
- [Token Verifier](#token-verifier)
- [Scope Enforcement](#scope-enforcement)
- [Accessing Token Claims](#accessing-token-claims)
- [Protected Resource Metadata (PRM)](#protected-resource-metadata-prm)
- [Token Revocation Checking](#token-revocation-checking)
- [Token Exchange (RFC 8693)](#token-exchange-rfc-8693)
- [URL Elicitation for Consent](#url-elicitation-for-consent)
- [DPoP (RFC 9449)](#dpop-rfc-9449)
- [Development Mode and SSRF](#development-mode-and-ssrf)
- [Error Handling](#error-handling)
- [API Reference](#api-reference)
- [Security Properties](#security-properties)

---

## Installation

```toml
[dependencies]
authplane-sdk = "0.1"
authplane-fastmcp = "0.1"
fastmcp-rust = "0.3"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Requires Rust **1.91** (edition 2024) or newer.

## Quick Start

`fastmcp-rust` 0.3+ supports both HTTP and stdio transports. The adapter plugs into `Server::auth_provider(...)`:

```rust
use authplane_fastmcp::wrap_tool_with_url_elicitation;
use authplane_sdk::{AuthplaneClient, AuthplaneError, FetchSettings, VerifiedClaims};
use fastmcp_rust::prelude::*;
use fastmcp_rust::{AuthRequest, HttpServerConfig, McpErrorCode};
use std::sync::{Arc, Mutex};

const SCOPES: &[&str] = &["tools/add", "tools/multiply"];

#[tool(description = "Add two numbers")]
async fn add(ctx: &McpContext, a: f64, b: f64) -> McpResult<String> {
    require_scope(ctx, "tools/add")?;
    Ok((a + b).to_string())
}

fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let client = runtime
        .block_on(AuthplaneClient::create(
            "https://auth.company.com",
            FetchSettings::default(),
        ))
        .expect("client");

    let scopes: Vec<String> = SCOPES.iter().map(|s| (*s).to_string()).collect();
    let verifier = runtime
        .block_on(client.resource("https://mcp.company.com", &scopes))
        .expect("verifier");

    let provider = TokenAuthProvider::new(
        AuthplaneTokenVerifier::new(verifier).expect("verifier"),
    );

    Server::new("authplane-fastmcp-demo", "0.1.0")
        .auth_provider(provider)
        .http_config(HttpServerConfig::default())
        .tool(Add)
        .build()
        .run_http("0.0.0.0:8080");
}
```

The full working example lives at `fastmcp/demo/calculator_demo.rs`.

## Transports: HTTP and Stdio

`fastmcp-rust` 0.3 added `Server::run_http()` alongside the original `Server::run_stdio()`. This is the key difference from earlier versions that only supported stdio.

### HTTP (recommended for authenticated servers)

```rust
Server::new("my-server", "1.0.0")
    .auth_provider(provider)
    .http_config(
        HttpServerConfig::new()
            .mcp_path("/mcp")
            .max_connections(128),
    )
    .tool(MyTool)
    .build()
    .run_http("0.0.0.0:8080");
```

HTTP is the natural fit for authenticated MCP servers because:
- Bearer tokens travel in HTTP headers.
- PRM documents can be served from the same process.
- DPoP proofs require HTTP method and URL binding.

### Stdio (subprocess transport)

```rust
Server::new("my-server", "1.0.0")
    .auth_provider(provider)
    .tool(MyTool)
    .build()
    .run_stdio();
```

Stdio remains useful for local MCP clients that launch the server as a subprocess. Auth still works via the `TokenVerifier` trait, but DPoP is not available (no HTTP request context).

### Choosing at runtime

The calculator demo supports both via `TRANSPORT=http|stdio`:

```rust
match transport.as_str() {
    "stdio" => server.run_stdio(),
    _ => server.run_http(&bind_addr),
}
```

## Token Verifier

The crate ships `AuthplaneFastMcpTokenVerifier`, a reusable bridge
between fastmcp-rust's synchronous `TokenVerifier` trait and
`AuthplaneResource`'s async API. It owns a dedicated single-threaded
tokio runtime so `verify` can `block_on` the async call without
fighting the outer accept loop:

```rust
use std::sync::Arc;
use authplane_fastmcp::AuthplaneFastMcpTokenVerifier;
use fastmcp_rust::TokenAuthProvider;

let verifier = client
    .resource(&resource_url, &scopes)
    .await?;
let provider = TokenAuthProvider::new(
    AuthplaneFastMcpTokenVerifier::new(Arc::new(verifier))?,
);
```

The `AuthContext` returned is what tool handlers see via `ctx.auth()`.

### Bearer-only constraint

`fastmcp-rust` 0.3 owns its own TCP accept loop and parses JSON-RPC
requests by reading only the HTTP **body** — the
`HttpRequest::headers` map is discarded before the request reaches
`TokenVerifier::verify`, which only sees JSON-RPC method / params /
request_id. Without inbound HTTP context, DPoP proof validation
(RFC 9449 §6.1) cannot run end-to-end. This adapter therefore accepts
only the `Bearer` scheme; DPoP-bound tokens are rejected with
`ResourceForbidden`.

For DPoP-aware MCP servers in Rust today, use the rmcp-native
`authplane-mcp` adapter — it mounts as an axum middleware and ships
the full `verify_with_context` pipeline.

## Scope Enforcement

`AuthContext::scopes` is the canonical source of truth inside a tool handler. The pattern mirrors `authplane-mcp`:

```rust
fn require_scope(ctx: &McpContext, scope: &str) -> McpResult<()> {
    let auth = ctx
        .auth()
        .ok_or_else(|| McpError::tool_error("missing auth context"))?;
    if auth.scopes.iter().any(|s| s == scope) {
        return Ok(());
    }
    Err(McpError::tool_error(format!(
        "missing required scope {scope}; available scopes: {}",
        auth.scopes.join(",")
    )))
}
```

For tools that need richer scope semantics (hierarchical scopes, regex matching), inspect `auth.claims` directly and branch on the raw `scope` claim.

## Accessing Token Claims

The `claims` JSON object built inside the verifier carries the validated RFC 9068 payload. Any tool handler can reach for it:

```rust
#[tool(description = "Return the current auth context")]
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
```

Claim fields exposed through `AuthContext`:

| Field | Source |
| --- | --- |
| `auth.subject` | `sub` from the JWT. |
| `auth.scopes` | Parsed `scope` claim. |
| `auth.token` | The original `AccessToken` (scheme + raw string). |
| `auth.claims` | `serde_json::Value` carrying `iss`, `aud`, `exp`, `jti`, `iat`, `nbf`, and any vendor claims you add. |

## Protected Resource Metadata (PRM)

`AuthplaneResource` always knows how to produce the RFC 9728 discovery document — same API as the `authplane-mcp` guide:

```rust
let prm_url = verifier.prm_document_url()?;
let prm     = verifier.prm_response();
```

When running over HTTP, serve `prm_response()` from the same process that hosts the MCP endpoint — unauthenticated, exactly like the `authplane-mcp` example. For stdio, the client discovers the AS out-of-band (the MCP handshake itself) rather than via PRM.

## Token Revocation Checking

Revocation is configured on the `AuthplaneResource`, not on the adapter. Pass `ResourceOptions::revocation` into `resource_with_options`:

```rust
use authplane_sdk::{ResourceOptions, RevocationConfig};

let options = ResourceOptions {
    revocation: Some(RevocationConfig {
        client_id: "my-resource-server".to_string(),
        client_secret: std::env::var("AS_CLIENT_SECRET")?,
        fail_open: false,
    }),
    ..ResourceOptions::default()
};
let verifier = client
    .resource_with_options("https://mcp.company.com", &scopes, options)
    .await?;
```

`fail_open: true` accepts tokens when the introspection endpoint is unreachable; `false` rejects them. An `active: false` response always fails closed with `VerifierError::TokenRevoked`.

The credentials must belong to a **confidential** client that is either the issuing client or a runtime-client of the Resource named in the token's `aud`. Since authserver 0.1.2 any other caller gets `{"active": false}` for every token — a public (secret-less) client cannot introspect at all — so a resource server with the wrong credentials would reject all traffic as revoked. Empty credentials are refused when the resource is constructed. Link the resource server's client with:

```bash
authserver admin resource runtime-client add --client-id <rs-client-id> --slug <resource-slug>
```

## Token Exchange (RFC 8693)

A tool handler that needs to call a downstream service on behalf of the caller:

```rust
use authplane_sdk::{TokenExchangeOptions, TOKEN_TYPE_ACCESS_TOKEN};

#[tool(description = "Look up the caller's calendar")]
async fn calendar(ctx: &McpContext) -> McpResult<String> {
    let auth = ctx.auth().ok_or_else(|| McpError::tool_error("no auth"))?;
    let subject_token = auth
        .token
        .as_ref()
        .map(|t| t.token.clone())
        .ok_or_else(|| McpError::tool_error("no inbound token"))?;

    let downstream = wrap_tool_with_url_elicitation(|| async {
        client
            .exchange_token(
                &client_id,
                &client_secret,
                &TokenExchangeOptions {
                    subject_token,
                    subject_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
                    scope: "calendar.read".to_string(),
                    resources: vec!["https://calendar.example".to_string()],
                    ..Default::default()
                },
            )
            .await
    })
    .await?;

    fetch_calendar(&downstream.access_token).await
}
```

The wrapper translates any consent-required error into the `-32042` URL elicitation the MCP client knows how to handle (see the next section).

**Operator step.** Token exchange is on by default since authserver 0.2.0, but a cross-client exchange is allowlisted per Resource. For each MCP server that exchanges for a downstream resource it does not act as, register the exchanging client on that Resource:

```http
PATCH /admin/resources/{id}
{"policy": {"exchange": {"allowed_client_ids": ["<exchanging-client-id>"]}}}
```

A client exchanging a token issued to itself, fronted exchanges, and Broker resources need nothing.

Two `AuthplaneError::Auth` codes the wrapper does not translate deserve their own handling:

- `access_denied` (HTTP 403, `AuthError::is_access_denied()`) — the operator has not allowlisted the exchanging client on the target Resource. Unlike `consent_required`, re-prompting the user will not fix it; the `PATCH` above will.
- `invalid_target` (HTTP 400, `AuthError::is_invalid_target()`) — the `resource` string does not match a granted resource byte for byte (a trailing slash is enough).

Neither counts toward the circuit breaker.

`TokenExchangeOptions` fields:

| Field | Purpose |
| --- | --- |
| `subject_token` | Required. Token being exchanged. |
| `subject_token_type` | RFC 8693 token-type URI. Defaults to `...:access_token`. |
| `actor_token` / `actor_token_type` | Optional delegation token. |
| `scope` | Space-separated scopes for the downstream token. |
| `resources` | RFC 8707 audience binding. |
| `audiences` | Explicit audiences when `resources` is not a fit. |

## URL Elicitation for Consent

MCP defines error code `-32042` (`URL_ELICITATION_REQUIRED`) to signal that the user must visit a URL to finish authorization. `authplane-fastmcp` translates `AuthplaneError::ConsentRequired` payloads that carry a `consent_url` into a `fastmcp_rust::McpError` with that code.

**Wrapper form** — handles consent and non-consent errors in one line:

```rust
use authplane_fastmcp::wrap_tool_with_url_elicitation;
use authplane_sdk::AuthplaneError;

#[tool(description = "Demonstrate consent-required mapping")]
async fn consent_demo(ctx: &McpContext) -> Result<String, McpError> {
    wrap_tool_with_url_elicitation(|| async {
        Err::<String, AuthplaneError>(AuthplaneError::from(
            authplane_sdk::ConsentRequiredError {
                message: "Consent is required to continue".into(),
                code: "consent_required".into(),
                status_code: Some(400),
                service_id: "calendar".into(),
                cause_detail: "approval_pending".into(),
                consent_url: Some("https://example.com/consent".into()),
            },
        ))
    })
    .await
}
```

**Explicit form** — map manually when you want to re-raise non-consent errors with different `tool_error` messages:

```rust
use authplane_fastmcp::to_url_elicitation_required_error;

match client.exchange_token(...).await {
    Ok(token) => Ok(/* ... */),
    Err(error) => match to_url_elicitation_required_error(error) {
        Err(mcp) => Err(mcp),                                             // -32042
        Ok(other) => Err(McpError::tool_error(other.to_string())),        // non-consent
    },
}
```

The produced error carries:

```json
{
  "code": -32042,
  "message": "Consent is required to proceed",
  "data": {
    "elicitations": [
      {
        "mode": "url",
        "url": "https://auth.company.com/consent?service=calendar&...",
        "elicitationId": "...uuid...",
        "message": "Consent is required to proceed (calendar: approval_pending)"
      }
    ]
  }
}
```

Consent errors without a `consent_url` pass through unchanged; non-consent `AuthplaneError`s become `McpError::tool_error` so the client sees a normal tool failure.

## DPoP (RFC 9449)

The unified `AuthplaneResource::verify_with_context(token, ctx)` dispatcher — and the three-mode `ResourceOptions::inbound_dpop` config it dispatches on — are documented in the core SDK guide: [Three-mode inbound DPoP dispatch](../../core/docs/user-guide.md#three-mode-inbound-dpop-dispatch). The fastmcp adapter wires the dispatcher into either an HTTP middleware (path 1 below) or rejects DPoP-bound tokens at the transport layer (path 2 below).

If the inbound token is DPoP-bound, the verifier must also check the `DPoP` header. Because `fastmcp-rust`'s `TokenVerifier` signature doesn't expose the full HTTP request, you have two options:

1. **HTTP transport:** when running with `run_http`, inject middleware before FastMCP that calls `AuthplaneResource::verify_with_context` and strips the header before the request reaches the MCP layer — the same pattern as the `authplane-mcp` bearer middleware.
2. **Stdio transport:** require `Bearer` tokens and rely on the AS to only issue bearer tokens to stdio clients. DPoP-bound tokens are rejected by the stdio transport because no `DPoP` header can be transmitted.

The same DPoP primitives used server-side power the DPoP-capable client: `AuthplaneClient::client_credentials`, `exchange_token`, `introspect`, and `revoke` all take a final `Option<&DpopProofOptions>` — pass `Some(&opts)` to attach a proof on the same call. See the in-process `core/examples/dpop_roundtrip.rs` example:

```bash
cargo run -p authplane-sdk --example dpop_roundtrip
```

## Development Mode and SSRF

`FetchSettings::default()` is production-safe. For local development where the AS runs over HTTP on `localhost`, use `FetchSettings::from_dev_mode(true)`:

| Check | Default | Dev mode | Notes |
| --- | --- | --- | --- |
| HTTPS required | Yes | No | Plain HTTP allowed. |
| Localhost | Blocked | Allowed | `127.0.0.0/8`. |
| Private networks | Blocked | Allowed | `10.x`, `172.16-31.x`, `192.168.x`. |
| Cloud metadata | **Always blocked** | Always blocked | `169.254.x` — cannot be disabled. |
| Redirect follow | Blocked | Blocked | Prevents open-redirect attacks. |
| Timeout | 10 s | 10 s | Applied per fetch. |

Enabling dev mode from the environment:

```bash
AUTHPLANE_DEV_MODE=true cargo run -p authplane-fastmcp --example calculator_demo
```

## Error Handling

Error types produced by this adapter and the core SDK, and how fastmcp surfaces each:

| Error | Produced by | Fastmcp surface |
| --- | --- | --- |
| `McpError::with_data(McpErrorCode::ResourceForbidden, ..., {"resource_metadata": url})` | Token verifier on invalid/expired/revoked JWTs. The `data` carries the verifier's `resource_metadata_url()` — the RFC 9728 §5.1 hint the HTTP adapter puts in `WWW-Authenticate`, which this transport has no header for. | `403` to the MCP client. |
| `McpError::tool_error(msg)` | Scope checks, missing auth context, non-consent `AuthplaneError` via `wrap_tool_with_url_elicitation`. | JSON-RPC tool error result. |
| `McpError::with_data(Custom(-32042), ...)` | `to_url_elicitation_required_error` on consent-required errors with URL. | MCP URL elicitation prompt to the user. |

Core-SDK error types to match on:

| Error | When to expect it |
| --- | --- |
| `VerifierError::TokenMissing` | `Authorization` absent or wrong scheme. |
| `VerifierError::TokenExpired` | JWT `exp` passed. |
| `VerifierError::InvalidSignature { message }` | Signature / key mismatch. |
| `VerifierError::InvalidClaims { message }` | RFC 9068 claim violation. |
| `VerifierError::TokenRevoked` | Introspection returned `active=false`: revoked, or the AS does not recognise this resource server as the token's owner (see [Token Revocation Checking](#token-revocation-checking)). |
| `VerifierError::InsufficientScope { required, available }` | Valid token, scope absent. |
| `VerifierError::MetadataUnavailable { message }` | AS metadata fetch failed. |
| `VerifierError::JwksUnavailable { message }` | JWKS fetch failed. |
| `AuthplaneError::Auth { code, status_code, message }` | Token-endpoint / admin-API error. |
| `AuthplaneError::ConsentRequired(_)` | AS asks the user to complete interactive consent. |

`authplane_sdk::http_status(&err)` and `verifier.www_authenticate(&err, realm)` return the RFC 6750 §3 status + challenge header (with the RFC 9728 §5.1 `resource_metadata` parameter) when you front the fastmcp server with HTTP middleware.

## API Reference

### `to_url_elicitation_required_error`

```rust
pub fn to_url_elicitation_required_error(
    error: AuthplaneError,
) -> Result<AuthplaneError, McpError>
```

- Input: an `authplane_sdk::AuthplaneError`.
- Output:
  - `Err(McpError)` — the error carried a `consent_url`; mapped to MCP code `-32042`.
  - `Ok(AuthplaneError)` — the error was not a URL-elicitation candidate; caller handles it.

### `wrap_tool_with_url_elicitation`

```rust
pub async fn wrap_tool_with_url_elicitation<F, Fut, T>(
    handler: F,
) -> Result<T, McpError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, AuthplaneError>>,
```

- Runs the handler, maps consent errors to `-32042`, wraps every other `AuthplaneError` as `McpError::tool_error(msg)`.

### Re-exports from `authplane-sdk`

The types below are reachable through `authplane_sdk::...`. The adapter does not re-export them, but they form the stable surface any fastmcp integration uses:

| Type | Purpose |
| --- | --- |
| `AuthplaneClient` | AS discovery + factory for verifiers. |
| `AuthplaneResource` | Per-resource verifier (`verify`, `verify_with_context`, PRM). |
| `VerifiedClaims` | Validated JWT payload (RFC 9068). |
| `VerifierError`, `AuthplaneError` | Failure enums. |
| `ConsentRequiredError` | Payload for `AuthplaneError::ConsentRequired`. |
| `TokenExchangeOptions`, `TokenResponse` | RFC 8693 shapes. |
| `FetchSettings` | SSRF/timeout/redirect controls. |
| `ResourceOptions`, `RevocationConfig` | Verifier tuning + revocation. |
| `ProtectedResourceMetadata` | RFC 9728 PRM document. |
| `www_authenticate`, `http_status`, `http_status_for_auth_error` | RFC 6750 §3 challenge + status mapping. |

## Security Properties

Through `authplane-sdk`, this adapter enforces:

- **RFC 9068 JWT validation** — `iss`, `aud`, `sub`, `client_id`, `exp`, `nbf`, `iat`, `jti`, `typ`.
- **`typ: "at+jwt"`** — other JWT profiles are rejected.
- **Asymmetric algorithms only** — `HS*` and `none` rejected; default is `RS256` + `ES256`.
- **SSRF-safe fetches** — DNS pinning, IP blocklists, protocol allowlist, redirect block, 64 KB size cap.
- **JWKS auto-refresh** — re-fetches after a cache miss with a minimum 30 s interval; stale cache fallback on refresh failure.
- **DPoP cnf.jkt binding** — `verify_with_context` checks both the proof signature and the `cnf.jkt` thumbprint match (RFC 9449 §6.1).
- **RFC 6750 §3 challenges** — via `www_authenticate`.
