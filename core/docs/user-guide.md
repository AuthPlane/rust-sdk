# authplane-sdk User Guide

## Install

```bash
cargo add authplane-sdk
```

## Quickstart

The smallest useful entry point is typed OAuth error parsing:

```rust
use authplane_sdk::parse_token_exchange_error;

let err = parse_token_exchange_error(
    Some(400),
    r#"{"error":"interaction_required","error_description":"User action needed"}"#,
);

println!("{err}");
```

## Core concepts

`authplane-sdk` is split into three main roles:

- `AuthplaneClient`: discovers authorization-server metadata and exposes token, introspection, revocation, and verifier helpers.
- `AuthplaneAuth`: performs OAuth client operations once you already have metadata loaded.
- `AuthplaneResource`: verifies JWT access tokens for a protected resource and can optionally require DPoP proof binding.

The crate also exposes:

- typed OAuth errors (`AuthplaneError`, `ConsentRequiredError`)
- `FetchSettings` for outbound HTTP policy
- DPoP helpers (`create_dpop_proof`, `verify_dpop_proof`)
- PRM helpers (`build_prm`, `build_prm_url`)
- `VerifiedClaims` and `VerifierError`

## Basic usage

### Discover metadata and build a client

```rust
use authplane_sdk::{AuthplaneClient, FetchSettings};

# async fn demo() -> Result<(), authplane_sdk::AuthplaneError> {
let client = AuthplaneClient::create(
    "https://auth.example.com",
    FetchSettings::default(),
)
.await?;

assert_eq!(client.issuer(), "https://auth.example.com");
# Ok(())
# }
```

Use `FetchSettings::default()` for production-style HTTPS-only behavior, or `FetchSettings::from_dev_mode(true)` when working against local demos.

### Call the token endpoint

```rust
use authplane_sdk::{AuthplaneClient, FetchSettings};

# async fn demo() -> Result<(), authplane_sdk::AuthplaneError> {
let client = AuthplaneClient::create(
    "https://auth.example.com",
    FetchSettings::default(),
)
.await?;

let token = client
    .client_credentials(
        "client-id",
        "client-secret",
        &["tools/read".to_string()],
        &["https://api.example.com/mcp".to_string()],
    )
    .await?;

println!("{}", token.access_token);
# Ok(())
# }
```

### Build a verifier for a protected resource

```rust
use authplane_sdk::{AuthplaneClient, FetchSettings};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let client = AuthplaneClient::create(
    "https://auth.example.com",
    FetchSettings::default(),
)
.await?;

let verifier = client
    .resource(
        "https://api.example.com/mcp",
        &["tools/read".to_string()],
    )
    .await?;

let claims = verifier.verify("<access-token>").await?;
claims.require_scope("tools/read")?;
# Ok(())
# }
```

## Main API reference

### `AuthplaneClient`

- `AuthplaneClient::create(issuer, fetch_settings) -> Result<AuthplaneClient, AuthplaneError>`
  Loads and validates authorization-server metadata.
- `AuthplaneClient::discover(issuer) -> Result<AuthplaneClient, AuthplaneError>`
  Convenience wrapper that uses `FetchSettings::default()`.
- `client.client_credentials(...)`
  Sends a `client_credentials` token request.
- `client.exchange_token(...)`
  Sends a token-exchange request.
- `client.introspect(...)`
  Calls the introspection endpoint.
- `client.revoke(...)`
  Calls the revocation endpoint.
- `client.resource(resource, scopes)`
  Builds an `AuthplaneResource` verifier for a protected resource.
- `client.prm_response(resource, scopes)`
  Builds Protected Resource Metadata JSON for an exposed resource.

### `AuthplaneAuth`

Use `client.auth()` if you want to keep metadata discovery separate from repeated OAuth calls. `AuthplaneAuth` exposes the same token/introspection/revocation operations as `AuthplaneClient` — `client_credentials`, `exchange_token`, `introspect`, `revoke`. Each takes a final `dpop: Option<&DpopProofOptions>`: pass `None` for the plain bearer path, or `Some(&opts)` to attach a DPoP proof on the same call.

### `AuthplaneResource`

- `AuthplaneResource::create(...)`
  Creates a verifier directly from an issuer and resource.
- `verify(token) -> Result<VerifiedClaims, VerifierError>`
  Validates JWT signature, issuer, audience, expiration, algorithm, and time-based claims.
  **Bearer only:** a DPoP-bound token (one carrying `cnf`) is rejected here rather than
  accepted with its binding discarded — `DpopNotSupported` if the resource has not opted
  into inbound DPoP, `DpopBindingMismatch` if it has. Use `verify_with_context` for those.
- `verify_with_context(token, ctx) -> Result<VerifiedClaims, VerifierError>`
  The unified entrypoint. Takes a request-level `DpopRequestContext` and dispatches on the
  three inbound-DPoP modes, requiring a matching proof bound through `cnf.jkt` where the
  mode calls for one.
- `prm_response()`
  Builds PRM for the configured resource and scopes.
- `resource_metadata_url()`
  The URL advertised in the `resource_metadata` challenge parameter (RFC 9728 §5.1): the
  `ResourceOptions::with_resource_metadata_url` override, or the RFC 9728 §3.1 derivation
  (`prm_document_url()`) by default.
- `www_authenticate(error, realm)`
  The `WWW-Authenticate` challenge for a `VerifierError` on this resource — the free
  `www_authenticate` helper plus `resource_metadata`. Prefer it in HTTP adapters so every
  `401` tells the client where to discover the authorization server.

### `VerifiedClaims`

- `has_scope(scope) -> bool`
- `require_scope(scope) -> Result<(), VerifierError>`
- `has_claim(key, expected) -> bool`

`VerifiedClaims` also exposes parsed `sub`, `client_id`, `issuer`, `audience`, `scopes`, `jti`, `kid`, `issued_at`, `expires_at`, `not_before`, and the raw claim map.

## Configuration options

### `FetchSettings`

```rust
use authplane_sdk::FetchSettings;

let settings = FetchSettings {
    ssrf_protection: true,
    allow_http: false,
    allow_localhost: false,
    allow_private_networks: false,
    timeout_seconds: 10.0,
};
```

- `ssrf_protection`
  Enables outbound URL checks and disables redirects in the shared HTTP client.
- `allow_http`
  Allows `http://` endpoints. Disabled by default.
- `allow_localhost`
  Allows literal localhost and loopback targets.
- `allow_private_networks`
  Allows literal private-network IP targets.
- `timeout_seconds`
  Sets the reqwest timeout used by metadata, JWKS, and OAuth requests.

`FetchSettings::from_dev_mode(true)` is the easiest way to opt into local development behavior.

### `ResourceOptions`

```rust
use authplane_sdk::ResourceOptions;
use jsonwebtoken::Algorithm;

# fn demo() -> Result<(), authplane_sdk::ResourceOptionsError> {
let options = ResourceOptions::default()
    .with_allowed_algorithms(vec![Algorithm::RS256, Algorithm::ES256])?;
# Ok(())
# }
```

- `with_allowed_algorithms`
  Sets the access-token algorithms accepted by the verifier. Only `RS256` and `ES256` are accepted. Every other variant the underlying `jsonwebtoken` crate exposes (HMAC `HS256`/`HS384`/`HS512`, plus the additional asymmetric `RS384`/`RS512`/`PS*`/`ES384`/`EdDSA`) is rejected at construction with `Err(ResourceOptionsError::UnsupportedAlgorithm)`. The JWS `none` algorithm isn't reachable here because `jsonwebtoken` doesn't expose it. The field itself is `pub(crate)`; this builder is the only public construction path.
- `clock_skew_seconds`
  Shared leeway for JWT time validation and DPoP future-`iat` tolerance.
- `revocation`
  Optional introspection-backed revocation check. The `RevocationConfig` credentials must belong to a confidential client that is the issuing client or a runtime-client of the resource; empty credentials are rejected when the resource is constructed. See [Token exchange, introspection, and revocation](#token-exchange-introspection-and-revocation).
- `with_resource_metadata_url`
  Overrides the URL emitted as the `resource_metadata` parameter of every `WWW-Authenticate` challenge (RFC 9728 §5.1). Defaults to the RFC 9728 §3.1 derivation from the resource identifier; set it when the document is served elsewhere, e.g. the AS-hosted `/.well-known/oauth-protected-resource/{ref}`. Anything but an absolute URL with a host — or any value carrying whitespace, a control character, `"` or `\`, which the URL parser would trim or strip while the value is advertised intact — is rejected with `Err(ResourceOptionsError::InvalidResourceMetadataUrl)`.

## Intermediate features

### Protected Resource Metadata

Use PRM helpers when your server exposes OAuth-protected MCP endpoints:

```rust
use authplane_sdk::build_prm;

let prm = build_prm(
    "https://auth.example.com",
    "https://api.example.com/mcp",
    &["tools/read".to_string()],
    None,
    false,
);
```

### Circuit policy

Use `should_open_circuit_for_oauth_error(code)` when you distinguish expected OAuth client errors from real upstream outages:

```rust
use authplane_sdk::should_open_circuit_for_oauth_error;

assert!(!should_open_circuit_for_oauth_error("invalid_scope"));
assert!(should_open_circuit_for_oauth_error("server_error"));
```

## Advanced features

### DPoP proof creation

```rust
use authplane_sdk::{DpopProofOptions, create_dpop_proof};
use jsonwebtoken::Algorithm;
use serde_json::json;

let proof = create_dpop_proof(
    "POST",
    "https://api.example.com/mcp",
    Some("<access-token>"),
    &DpopProofOptions {
        private_key_pem: "<private-key-pem>".to_string(),
        public_jwk: json!({
            "kty": "EC",
            "kid": "key-1",
            "use": "sig",
            "alg": "ES256",
            "crv": "P-256",
            "x": "<x>",
            "y": "<y>"
        }),
        algorithm: Algorithm::ES256,
        key_id: Some("key-1".to_string()),
        nonce: None,
    },
)?;
```

`create_dpop_proof` currently supports asymmetric signing keys compatible with the selected `jsonwebtoken::Algorithm`.

### DPoP verification and token binding

`AuthplaneResource::verify_with_context(...)` is stricter than plain bearer verification:

- it validates the DPoP proof signature and claims
- it requires `ath` when a token is supplied
- it requires the access token to contain `cnf.jkt`
- it rejects proofs whose thumbprint does not match the token binding

If you only have a proof and want to validate it independently, use `verify_dpop_proof(...)`.

### Three-mode inbound DPoP dispatch

`AuthplaneResource::verify_with_context(token, context)` is the unified entrypoint adapters use. The behaviour is driven by `ResourceOptions::inbound_dpop` and has three modes — required, supported, and not-configured — with distinct error mappings to `WWW-Authenticate` challenges.

The full reference (mode table, builder pattern, runnable examples for `create_with_options` and `DpopRequestContext`, error class list, and PRM-advertising semantics) lives in **[three_mode_dpop.md](three_mode_dpop.md)**. That file is the single source of truth and is pulled into rustdoc via `include_str!`, so its `rust` fences are compiled by `cargo test --doc -p authplane-sdk` and stay in sync with the live API automatically.

### Token exchange, introspection, and revocation

Use `TokenExchangeOptions` for token exchange:

```rust
use authplane_sdk::{AuthplaneClient, FetchSettings, TokenExchangeOptions};

# async fn demo() -> Result<(), authplane_sdk::AuthplaneError> {
let client = AuthplaneClient::create(
    "https://auth.example.com",
    FetchSettings::default(),
)
.await?;

let token = client
    .exchange_token(
        "client-id",
        "client-secret",
        &TokenExchangeOptions {
            subject_token: "<subject-token>".to_string(),
            subject_token_type:
                "urn:ietf:params:oauth:token-type:access_token".to_string(),
            actor_token: String::new(),
            actor_token_type: String::new(),
            scope: "tools/read".to_string(),
            resources: vec!["https://api.example.com/mcp".to_string()],
            audiences: Vec::new(),
        },
    )
    .await?;

println!("{}", token.issued_token_type);
# Ok(())
# }
```

For DPoP-bound endpoints, pass `Some(&DpopProofOptions { ... })` as the final argument on the same `client_credentials` / `exchange_token` / `introspect` / `revoke` call on `AuthplaneClient` or `AuthplaneAuth`. Callers that don't need DPoP pass `None`.

**Operator step.** Token exchange is on by default since authserver 0.2.0, but a cross-client exchange is allowlisted per Resource. For each MCP server that exchanges for a downstream resource it does not act as, register the exchanging client on that Resource:

```http
PATCH /admin/resources/{id}
{"policy": {"exchange": {"allowed_client_ids": ["<exchanging-client-id>"]}}}
```

A client exchanging a token issued to itself, fronted exchanges, and Broker resources need nothing.

Three token-endpoint answers are worth telling apart:

- `AuthplaneError::ConsentRequired` — the user must complete consent at the AS; surface the `consent_url` (the MCP adapters do this for you).
- `access_denied` (HTTP 403, `AuthError::is_access_denied()`) — the operator has not allowlisted the exchanging client on the target Resource. Re-prompting the user will not fix it; the `PATCH` above will.
- `invalid_target` (HTTP 400, `AuthError::is_invalid_target()`) — the `resource` string does not match a granted resource byte for byte. A trailing slash is enough.

None of the three counts toward the circuit breaker.

**Introspection.** `client.introspect(...)` and `ResourceOptions::revocation` need a confidential client that is either the issuing client or a runtime-client of the Resource named in the token's `aud`. Since authserver 0.1.2 every other caller — a public (secret-less) client cannot introspect at all — receives `{"active": false}` for every token, and a resource server introspecting with the wrong credentials rejects all traffic as revoked. Link the resource server's client with:

```bash
authserver admin resource runtime-client add --client-id <rs-client-id> --slug <resource-slug>
```

## Error handling

### OAuth client errors

`AuthplaneError` is the main error type for metadata loading and OAuth calls:

- `AuthplaneError::Auth(AuthError)`
  Standard OAuth or transport errors. `AuthError` exposes predicates for the common codes — `is_invalid_client`, `is_invalid_scope`, `is_access_denied`, `is_invalid_target`, `is_server_error`, … — so callers need not compare strings.
- `AuthplaneError::ConsentRequired(Box<ConsentRequiredError>)`
  `consent_required` and `interaction_required` responses, including optional `consent_url`.

`parse_token_exchange_error(status, body)` is useful when another library performed the HTTP call and you still want the typed error mapping.

### Verifier errors

`VerifierError` covers:

- `TokenMissing`
- `TokenExpired`
- `InvalidSignature`
- `InvalidClaims`
- `MetadataUnavailable`
- `JwksUnavailable`
- `TokenRevoked` — introspection answered `active: false`. Either the token is revoked or the AS does not recognise this resource server as the token's owner; if every token fails this way, see the runtime-client requirement above.
- `InsufficientScope`

## Cross-feature integration

Consent and interaction errors are designed to flow into the MCP adapter crate. If `parse_token_exchange_error(...)` returns `AuthplaneError::ConsentRequired`, pass that error to:

- [`authplane-mcp`](../../mcp/docs/user-guide.md) for `rmcp`
- [`authplane-fastmcp`](../../fastmcp/docs/user-guide.md) for `fastmcp-rust` (stdio + HTTP)

The adapter translates the typed error into MCP URL elicitation.

## Lifecycle

The crate does not spawn background tasks. `AuthplaneClient`, `AuthplaneAuth`, and `AuthplaneResource` are regular Rust values backed by a shared reqwest client and can be dropped normally when no longer needed.
