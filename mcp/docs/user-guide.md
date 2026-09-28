# authplane-mcp User Guide

OAuth 2.1 JWT authentication for the [official Rust MCP SDK (`rmcp`)](https://github.com/modelcontextprotocol/rust-sdk), powered by the [Authplane Rust SDK (`authplane-sdk`)](../../core).

`authplane-mcp` is intentionally small: the heavy lifting — JWKS discovery, JWT validation, DPoP proof verification, revocation — lives in `authplane-sdk`. This crate adds the MCP-specific glue: translating `AuthplaneError::ConsentRequired` into the JSON-RPC URL-elicitation error (`-32042`) that MCP clients understand.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Server Shape](#server-shape)
- [Bearer Middleware](#bearer-middleware)
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
authplane-mcp = "0.1"
rmcp = "0.8"                 # official Rust MCP SDK
axum = "0.8"                 # transport for streamable-http
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Requires Rust **1.91** (edition 2024) or newer.

## Quick Start

The end-to-end example below mirrors `mcp/demo/http_calculator_demo.rs` in the repo:

```rust
use authplane_sdk::{AuthplaneClient, FetchSettings, VerifiedClaims};
use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rmcp::model::ErrorData;
use rmcp::service::RequestContext;
use rmcp::RoleServer;

const SCOPES: &[&str] = &["tools/add", "tools/multiply"];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AuthplaneClient::create(
        "https://auth.company.com",
        FetchSettings::default(),
    )
    .await?;
    let scopes: Vec<String> = SCOPES.iter().map(|s| (*s).to_string()).collect();
    let verifier = client
        .resource("https://mcp.company.com/mcp", &scopes)
        .await?;
    let prm = verifier.prm_response();
    let state = DemoState { verifier, prm };

    let app = Router::new()
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource_metadata),
        )
        .route("/healthz", get(|| async { "ok" }))
        .nest_service(
            "/mcp",
            tower::ServiceBuilder::new()
                .layer(from_fn_with_state(state.clone(), bearer_auth))
                .service(build_mcp_service()),
        )
        .with_state(state);

    axum::serve(
        tokio::net::TcpListener::bind("127.0.0.1:8080").await?,
        app,
    )
    .await?;
    Ok(())
}
```

The three things to notice:

1. `AuthplaneClient::create` discovers the AS metadata (`RFC 8414`) and is the factory for per-resource verifiers.
2. `client.resource(resource_url, &scopes)` returns an `AuthplaneResource` that can `verify(token)` incoming JWTs.
3. The `bearer_auth` middleware rejects unauthorised requests with a `WWW-Authenticate: Bearer` challenge (RFC 6750 §3) that carries the `resource_metadata` URL (RFC 9728 §5.1) MCP clients use to find the authorization server.

## Server Shape

Rust MCP servers are built out of three layers:

| Layer | Role |
| --- | --- |
| `rmcp::ServerHandler` | The MCP protocol state machine and tool dispatch. |
| `StreamableHttpService` | Streams JSON-RPC over HTTP chunked responses. |
| `axum::Router` | HTTP routing (healthchecks, PRM document, the `/mcp` endpoint). |

The adapter attaches to the `axum::Router` as middleware on the `/mcp` nested service — not inside the MCP handler — so that unauthenticated requests never reach `ServerHandler` code.

## Bearer / DPoP Middleware

The crate ships a reusable axum middleware that drives the full
`verify_with_context` pipeline (RFC 6750 bearer + RFC 9449 DPoP) and
stashes the verified claims on the request extensions:

```rust
use std::sync::Arc;
use axum::{Router, middleware::from_fn_with_state, routing::post};
use authplane_mcp::{AuthplaneMcpAuth, authplane_mcp_auth_middleware};

let auth = AuthplaneMcpAuth::new(
    Arc::new(verifier),
    "https://mcp.example.com".parse()?,
)
.with_realm("authplane-rmcp-demo");

let app = Router::new()
    .route("/mcp", post(handler))
    .layer(from_fn_with_state(auth, authplane_mcp_auth_middleware));
```

On success the middleware inserts:

* `VerifiedClaims` — the validated JWT payload
* `RawAccessToken` — the original JWT (for downstream RFC 8693 token
  exchange)
* `AuthplaneMcpAuth` — the verifier handle itself, in case nested code
  needs it

On failure it returns the appropriate `401` / `403` / `503` plus the
spec-compliant `WWW-Authenticate` challenge — `Bearer error="invalid_token"`
for plain failures, `DPoP error="invalid_token"` for proof-validation
failures (RFC 9449 §7.1 names `invalid_dpop_proof`, but the shared
conformance catalog pins `dpop_error → invalid_token`, so that is the
code core emits), etc. Every challenge ends with
`resource_metadata="<url>"` (RFC 9728 §5.1) — the verifier's
`resource_metadata_url()`, derived from the resource identifier unless
you set `ResourceOptions::with_resource_metadata_url` — so a client can
discover the AS from the `401` alone. A request with no credentials gets
`realm` and `resource_metadata` only, per RFC 6750 §3.1.

### Why `resource_origin` is required

`htu` reconstruction reads from the `resource_origin` you pass to
`AuthplaneMcpAuth::new`, **not** the inbound `Host`/scheme. A
misconfigured reverse proxy can let an attacker forge the `Host` header
and shift `htu` to a different origin; binding `htu` to the operator-
declared canonical origin closes that gap. The value must match what
the resource advertises in its PRM (RFC 9728).

### Three-mode dispatch

The middleware delegates mode selection to `verify_with_context`:

| `ResourceOptions::inbound_dpop` | Bearer-only request          | Bearer-only with stray `DPoP` header | DPoP-bound token + proof |
| ------------------------------- | ---------------------------- | ------------------------------------ | ------------------------ |
| `None` (Mode 3, default)        | accepted                     | rejected (`DpopNotSupported`)        | rejected                 |
| `Some(InboundDPoPOptions::default())` (Mode 2) | accepted          | rejected (`DpopBindingMismatch`)     | accepted                 |
| `Some(InboundDPoPOptions::required())` (Mode 1) | rejected (`DpopBindingMismatch`) | rejected             | accepted                 |

See `mcp/demo/http_calculator_demo.rs` for a complete wiring example.

## Scope Enforcement

Tool handlers pull the `VerifiedClaims` out of the request extensions and call `require_scope`:

```rust
use authplane_sdk::VerifiedClaims;

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

#[tool(name = "delete_all", description = "Drop every row")]
async fn delete_all(
    &self,
    ctx: RequestContext<RoleServer>,
) -> Result<String, ErrorData> {
    require_scope(&ctx, "tools/admin")?;
    Ok("cleared".to_string())
}
```

`VerifiedClaims::require_scope` returns `VerifierError::InsufficientScope` when the token is valid but missing the scope — which maps to HTTP 403 via `http_status`.

## Accessing Token Claims

`VerifiedClaims` exposes the RFC 9068 fields:

| Field | Type | Description |
| --- | --- | --- |
| `issuer` | `String` | `iss` claim. |
| `sub` | `String` | Subject (often the end-user id). |
| `audience` | `Vec<String>` | `aud` claim, always parsed as a list. |
| `client_id` | `String` | OAuth client that obtained the token. |
| `scopes` | `Vec<String>` | Parsed `scope` claim. |
| `expires_at` | `i64` | Unix timestamp of expiry. |
| `issued_at` | `i64` | Unix timestamp of issuance. |
| `not_before` | `Option<i64>` | `nbf` if present. |
| `jti` | `String` | JWT ID. |
| `raw` | `serde_json::Value` | Full payload for vendor claims. |

```rust
#[tool(name = "whoami", description = "Return the verified subject")]
async fn whoami(
    &self,
    Extension(parts): Extension<axum::http::request::Parts>,
) -> Result<String, ErrorData> {
    let claims = parts
        .extensions
        .get::<VerifiedClaims>()
        .ok_or_else(|| ErrorData::internal_error("verified claims missing", None))?;
    Ok(format!("sub={} scopes={}", claims.sub, claims.scopes.join(",")))
}
```

## Protected Resource Metadata (PRM)

RFC 9728 defines a discovery document at `/.well-known/oauth-protected-resource/{path}` that MCP clients use to find the authorization server. `AuthplaneResource` produces both the URL and the document:

```rust
let prm_url = verifier.prm_document_url()?;     // "https://mcp.company.com/.well-known/oauth-protected-resource/mcp"
let prm     = verifier.prm_response();          // ProtectedResourceMetadata struct
```

Serve the document from a plain `axum` route — no auth middleware, since PRM must be discoverable without a token:

```rust
async fn protected_resource_metadata(
    State(state): State<DemoState>,
) -> Json<ProtectedResourceMetadata> {
    Json(state.prm.clone())
}

Router::new().route("/.well-known/oauth-protected-resource/mcp",
                    get(protected_resource_metadata))
```

The document includes the `issuer`, supported `scopes`, and `bearer_methods_supported = ["header"]`.

## Token Revocation Checking

`AuthplaneResource::create` defaults to offline validation (signature + claims). To enable RFC 7662 introspection, pass `ResourceOptions::revocation`:

```rust
use authplane_sdk::{ResourceOptions, RevocationConfig};

let options = ResourceOptions {
    revocation: Some(RevocationConfig {
        client_id: "my-resource-server".to_string(),
        client_secret: std::env::var("AS_CLIENT_SECRET")?,
        fail_open: false, // strict: reject when AS is unreachable
    }),
    ..ResourceOptions::default()
};
let verifier = client
    .resource_with_options("https://mcp.company.com/mcp", &scopes, options)
    .await?;
```

- `fail_open: true` — the token is accepted when introspection is unreachable (availability over strictness).
- `fail_open: false` — the token is rejected when introspection fails (strictness over availability).
- When introspection responds with `active: false`, the verifier returns `VerifierError::TokenRevoked`.

The credentials must belong to a **confidential** client that is either the issuing client or a runtime-client of the Resource named in the token's `aud`. Since authserver 0.1.2 any other caller gets `{"active": false}` for every token — a public (secret-less) client cannot introspect at all — so a resource server with the wrong credentials would reject all traffic as revoked. Empty credentials are refused when the resource is constructed. Link the resource server's client with:

```bash
authserver admin resource runtime-client add --client-id <rs-client-id> --slug <resource-slug>
```

## Token Exchange (RFC 8693)

Use `AuthplaneClient::exchange_token` to swap an inbound token for a narrowly-scoped downstream token, typically from inside a tool handler that needs to call another service on behalf of the user:

```rust
use authplane_sdk::{TokenExchangeOptions, TOKEN_TYPE_ACCESS_TOKEN};

let exchanged = client
    .exchange_token(
        "my-resource-server",
        &as_client_secret,
        &TokenExchangeOptions {
            subject_token: inbound_token.to_string(),
            subject_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
            scope: "downstream/write".to_string(),
            resources: vec!["https://downstream.example".to_string()],
            ..Default::default()
        },
    )
    .await?;
// exchanged.access_token    — present to the downstream service
// exchanged.expires_in      — lifetime in seconds
// exchanged.token_type      — "Bearer" or "DPoP"
// exchanged.issued_token_type — the RFC 8693 URI returned by the AS
```

`TokenExchangeOptions` fields:

| Field | Purpose |
| --- | --- |
| `subject_token` | Required. Token being exchanged (usually the inbound caller's token). |
| `subject_token_type` | RFC 8693 token-type URI; default `urn:ietf:params:oauth:token-type:access_token`. |
| `actor_token` / `actor_token_type` | Optional delegation token. |
| `scope` | Space-separated scopes to request on the downstream token. |
| `resources` | RFC 8707 resource indicators. Binds the downstream token's audience. |
| `audiences` | Explicit audiences when resources are not appropriate. |

**Operator step.** Token exchange is on by default since authserver 0.2.0, but a cross-client exchange is allowlisted per Resource. For each MCP server that exchanges for a downstream resource it does not act as, register the exchanging client on that Resource:

```http
PATCH /admin/resources/{id}
{"policy": {"exchange": {"allowed_client_ids": ["<exchanging-client-id>"]}}}
```

A client exchanging a token issued to itself, fronted exchanges, and Broker resources need nothing.

Errors from the AS come back as `AuthplaneError::Auth { code, message, status_code }` (generic OAuth errors) or `AuthplaneError::ConsentRequired` (when the user must complete interactive consent — see the next section). Two `Auth` codes deserve their own handling:

- `access_denied` (HTTP 403, `AuthError::is_access_denied()`) — the operator has not allowlisted the exchanging client on the target Resource. Unlike `consent_required`, re-prompting the user will not fix it; the `PATCH` above will.
- `invalid_target` (HTTP 400, `AuthError::is_invalid_target()`) — the `resource` string does not match a granted resource byte for byte (a trailing slash is enough).

Neither counts toward the circuit breaker.

## URL Elicitation for Consent

Some exchanges require the user to complete interactive consent at the AS before a downstream token can be issued. MCP defines a dedicated JSON-RPC error code (`-32042`, `URL_ELICITATION_REQUIRED`) for this case. `authplane-mcp` translates a `ConsentRequiredError` with a `consent_url` into that error transparently.

**Wrapper form** — most concise; wrap the part of your handler that might produce a consent error:

```rust
use authplane_mcp::wrap_tool_with_url_elicitation;

#[tool(name = "call_downstream")]
async fn call_downstream(
    &self,
    Parameters(body): Parameters<Payload>,
    ctx: RequestContext<RoleServer>,
) -> Result<String, ErrorData> {
    wrap_tool_with_url_elicitation(|| async {
        let subject_token = extract_token(&ctx)?;
        let exchanged = self
            .client
            .exchange_token(&client_id, &client_secret, &TokenExchangeOptions {
                subject_token,
                scope: "downstream/write".into(),
                resources: vec!["https://downstream.example".into()],
                ..Default::default()
            })
            .await?;
        call_downstream_api(&exchanged.access_token, &body).await
    })
    .await
}
```

**Explicit form** — call `to_url_elicitation_required_error` after catching the error:

```rust
use authplane_mcp::to_url_elicitation_required_error;

match client.exchange_token(...).await {
    Ok(token) => Ok(/* ... */),
    Err(error) => match to_url_elicitation_required_error(error) {
        Err(mcp_error) => Err(mcp_error),             // -32042 URL elicitation
        Ok(other) => Err(ErrorData::internal_error(other.to_string(), None)),
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
        "url": "https://auth.company.com/consent?service=drive&...",
        "elicitationId": "…uuid…",
        "message": "Consent is required to proceed (drive: approval_pending)"
      }
    ]
  }
}
```

Consent errors **without** a `consent_url` pass through unchanged — the resource can't point the user anywhere, so MCP treats it as a generic auth failure. Non-consent errors (expired tokens, invalid scope) are wrapped as `internal_error`.

## DPoP (RFC 9449)

`authplane-sdk` ships full DPoP primitives — `create_dpop_proof`, `verify_dpop_proof`, `AuthplaneResource::verify_with_context`. When the inbound token is DPoP-bound (carries `cnf.jkt`), the resource server must also verify the `DPoP` header.

The unified dispatcher `AuthplaneResource::verify_with_context(token, ctx)` — Mode 1 (DPoP required), Mode 2 (DPoP supported), Mode 3 (no DPoP) — is documented in the core SDK guide: [Three-mode inbound DPoP dispatch](../../core/docs/user-guide.md#three-mode-inbound-dpop-dispatch). The adapter already drives it for you: wire `authplane_mcp_auth_middleware` with `AuthplaneMcpAuth::new(verifier, resource_origin)` as shown under [Bearer / DPoP Middleware](#bearer--dpop-middleware), and the `ResourceOptions::inbound_dpop` builder decides which mode the resource runs in.

If you must hand-roll the middleware instead, it looks like this. `AuthplaneMcpAuth` carries both pieces the context needs — the verifier and the canonical origin `htu` is rebuilt from:

```rust
use authplane_mcp::{AuthplaneMcpAuth, dpop_request_context_from_axum};
use authplane_sdk::VerifierError;

async fn bearer_auth_with_dpop(
    State(auth): State<AuthplaneMcpAuth>,
    mut request: Request,
    next: Next,
) -> Response {
    let token = match bearer_token(&request) {
        Some(token) => token,
        None => return unauthorized_err(&VerifierError::TokenMissing),
    };
    // Build the RFC 9449 §4.3 request context once and let the verifier
    // dispatch. Do NOT branch on the DPoP header and fall back to
    // `verify`: `verify` does not enforce `InboundDPoPOptions::required()`,
    // so a bearer-only token would pass a DPoP-required resource.
    // `verify_with_context` applies the resource's configured mode, and
    // answers `DpopProofMissing` for a bound token that arrives without a
    // proof.
    let ctx = match dpop_request_context_from_axum(&request, auth.resource_origin()) {
        Ok(ctx) => ctx,
        Err(err) => return unauthorized_err(&err),
    };

    let result = auth.verifier().verify_with_context(token, &ctx).await;

    match result {
        Ok(claims) => {
            request.extensions_mut().insert(claims);
            next.run(request).await
        }
        Err(error) => unauthorized_err(&error),
    }
}
```

When you exchange tokens from a DPoP-capable client, pass `Some(&DpopProofOptions { ... })` as the final argument to `exchange_token` — it attaches a fresh proof to the token-endpoint call. Bearer-only callers pass `None`.

A fully in-process DPoP example lives at `core/examples/dpop_roundtrip.rs`:

```bash
cargo run -p authplane-sdk --example dpop_roundtrip
```

## Development Mode and SSRF

`FetchSettings::default()` enforces SSRF protections that are correct for production:

| Check | Default | Description |
| --- | --- | --- |
| HTTPS required | Yes | Blocks plain HTTP. |
| Localhost blocked | Yes | Blocks `127.0.0.0/8`. |
| Private networks blocked | Yes | Blocks `10.x`, `172.16-31.x`, `192.168.x`. |
| Cloud metadata blocked | **Always** | Blocks `169.254.x` (cannot be disabled). |
| Redirect blocking | Yes | Prevents open-redirect attacks on metadata/JWKS fetches. |
| Request timeout | 10 s | Applied to every outbound fetch. |

For local dev, relax HTTP + localhost + private networks with `FetchSettings::from_dev_mode(true)`. Cloud-metadata addresses remain blocked.

```rust
let client = AuthplaneClient::create(
    "http://localhost:9000",
    FetchSettings::from_dev_mode(true),
)
.await?;
```

Or drive it from an env var:

```bash
AUTHPLANE_DEV_MODE=true cargo run -p authplane-mcp --example http_calculator_demo
```

## Error Handling

`authplane-mcp` itself can produce two shapes of `ErrorData`:

| Origin | Shape |
| --- | --- |
| `ConsentRequiredError` with `consent_url` | `ErrorData::url_elicitation_required(message, Some(data))` (code `-32042`). |
| Any other `AuthplaneError` (inside `wrap_tool_with_url_elicitation`) | `ErrorData::internal_error(error.to_string(), None)`. |

`authplane-sdk` produces two error enums you should expect to surface:

| Error | When to expect it | Spec HTTP status |
| --- | --- | --- |
| `VerifierError::TokenMissing` | No `Authorization: Bearer …` header. | 401 |
| `VerifierError::TokenExpired` | JWT `exp` passed. | 401 |
| `VerifierError::InvalidSignature { message }` | Signature or key failure. | 401 |
| `VerifierError::InvalidClaims { message }` | RFC 9068 claim violation, `typ` mismatch, etc. | 401 |
| `VerifierError::TokenRevoked` | Introspection returned `active=false`: revoked, or the AS does not recognise this resource server as the token's owner (see [Token Revocation Checking](#token-revocation-checking)). | 401 |
| `VerifierError::InsufficientScope { required, available }` | Valid token, missing scope. | 403 |
| `VerifierError::MetadataUnavailable { message }` | AS metadata not reachable. | 503 |
| `VerifierError::JwksUnavailable { message }` | JWKS not reachable. | 503 |
| `AuthplaneError::Auth { code, status_code, message }` | Token-endpoint or admin-call error. | `status_code` if present, else 400. |
| `AuthplaneError::ConsentRequired(_)` | AS requested interactive consent. | 401 (or `-32042` for MCP). |

`authplane_sdk::http_status(&err)` and `verifier.www_authenticate(&err, realm)` produce the canonical status + challenge header for `VerifierError` (the free `authplane_sdk::www_authenticate` is the same without the `resource_metadata` parameter); `http_status_for_auth_error` covers `AuthplaneError`.

## API Reference

### `to_url_elicitation_required_error`

```rust
pub fn to_url_elicitation_required_error(
    error: AuthplaneError,
) -> Result<AuthplaneError, ErrorData>
```

- Input: an `authplane_sdk::AuthplaneError`.
- Output:
  - `Err(ErrorData)` — the error carried a `consent_url`, mapped to `-32042`.
  - `Ok(AuthplaneError)` — the error did not qualify for URL elicitation; the caller should handle it.

### `wrap_tool_with_url_elicitation`

```rust
pub async fn wrap_tool_with_url_elicitation<F, Fut, T>(
    handler: F,
) -> Result<T, ErrorData>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, AuthplaneError>>,
```

- Runs `handler`, maps consent errors to `-32042`, wraps every other `AuthplaneError` as `ErrorData::internal_error`. Works for any `Fn` that returns `AuthplaneError`.

### Re-exports from `authplane-sdk`

These types are used throughout the guide and are stable public API:

| Type | Purpose |
| --- | --- |
| `AuthplaneClient` | AS discovery + factory for `AuthplaneResource`. |
| `AuthplaneResource` | Per-resource verifier (`verify`, `verify_with_context`, `prm_response`). |
| `VerifiedClaims` | Validated JWT payload (RFC 9068). |
| `VerifierError` | Verifier failure enum; maps to HTTP status via `http_status`. |
| `AuthplaneError` | Client-side OAuth error enum. |
| `ConsentRequiredError` | Payload delivered with `AuthplaneError::ConsentRequired`. |
| `TokenExchangeOptions` | RFC 8693 exchange parameters. |
| `TokenResponse` | AS token-endpoint response. |
| `FetchSettings` | SSRF, timeout, and redirect controls. |
| `ResourceOptions` | `allowed_algorithms`, `clock_skew_seconds`, `revocation`. |
| `RevocationConfig` | Revocation credentials + fail-open flag. |
| `ProtectedResourceMetadata` | RFC 9728 PRM document. |
| `www_authenticate` / `http_status` | RFC 6750 §3 challenge + status helpers. |

## Security Properties

Through `authplane-sdk`, this adapter enforces:

- **RFC 9068 compliance** — validates `iss`, `aud`, `sub`, `client_id`, `exp`, `nbf`, `iat`, `jti`, `typ`.
- **Type header enforcement** — only accepts `typ: "at+jwt"`.
- **Asymmetric algorithms only** — `HS*` and `none` are rejected; default allow-list is `RS256` and `ES256`.
- **JWKS refresh** — re-fetches on cache miss with a minimum 30 s interval.
- **SSRF-safe fetches** — DNS pinning, IP blocklists, protocol allowlists, redirect blocking.
- **DPoP cnf.jkt binding** — `verify_with_context` checks both the proof signature and the `cnf.jkt` thumbprint match (RFC 9449 §6.1).
- **RFC 6750 §3 challenges** — `www_authenticate` emits the correct `error=…` parameter per failure class.
