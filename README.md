# Authplane Rust SDK

[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](LICENSE)

Rust crates for OAuth 2.1 client flows, token verification, and MCP consent propagation with Authplane.

This repository is a Cargo workspace with a framework-agnostic core crate plus adapters for both the official Rust MCP SDK and FastMCP.

## Packages

| Crate | Install command | Purpose |
| --- | --- | --- |
| `authplane-sdk` | `cargo add authplane-sdk` | Core OAuth 2.1 client helpers, token verification, DPoP helpers, and PRM generation. |
| `authplane-mcp` | `cargo add authplane-mcp` | Adapter helpers for `rmcp`, including URL-elicitation mapping for consent flows. |
| `authplane-fastmcp` | `cargo add authplane-fastmcp` | Adapter helpers for `fastmcp-rust` (stdio + HTTP), including URL-elicitation mapping. |
| `authplane-conformance-tests` | _(internal)_ | Shared OAuth SDK conformance test suite |

## Capabilities

### Standards and RFCs

- OAuth 2.1 draft: authorization-server discovery, token endpoint helpers, and secure-by-default fetch settings.
- RFC 8414: authorization server metadata discovery via `AuthplaneClient` with a `MetadataCache` that fires an `on_change` hook on rotation.
- RFC 8693: token exchange request helpers and typed token-exchange error parsing.
- RFC 7662: token introspection helpers and optional revocation checks during verification.
- RFC 7009: token revocation helpers.
- RFC 9068: JWT Profile for OAuth 2.0 Access Tokens (`typ = at+jwt` enforcement, required claims `sub` / `client_id` / `exp` / `iat` / `jti`).
- RFC 9728: Protected Resource Metadata generation, and the `resource_metadata` parameter on every `WWW-Authenticate` challenge.
- RFC 9449: outbound DPoP proof generation with per-origin nonce store and inbound DPoP verification with optional replay protection.
- RFC 8707: repeated `resource` indicators in token and token-exchange requests.
- RFC 7234: HTTP caching semantics on metadata and JWKS discovery responses (`max-age`, `Expires`, stale-cache fallback).
- RFC 6750 / RFC 7519 / RFC 7517: bearer access-token verification over JWT/JWKS with typed claims access.

### Security

- HTTPS-only by default for outbound metadata, JWKS, token, introspection, and revocation requests.
- Development-mode fetch settings that explicitly allow `http://localhost` and private networks when needed.
- Outbound fetch hardening for literal localhost and private-network targets, plus redirect disabling when SSRF protection is enabled.
- JWT validation with issuer, audience, signature, `exp`, `nbf`, future-`iat`, `typ = at+jwt`, and allowed-algorithm checks.
- Algorithm-confusion defenses: only `RS256` and `ES256` (asymmetric) are accepted; `none`, `HS256`, `HS384`, and `HS512` are always rejected at construction.
- DPoP verification with `htm`, `htu`, `ath`, nonce, age, and `cnf.jkt` binding checks; optional `DpopReplayStore` for `jti` replay protection.
- JWKS resilience: background refresh at 80% of TTL, force-refresh on `kid` miss with a minimum refresh interval, stale-cache fallback on transient fetch errors.
- Token caching with TTL buffer for `client_credentials` results.
- Stateful circuit breaker (closed/open/half-open) wrapping every outbound AS call.

### Framework Integrations

- [`authplane-sdk`](core/README.md): framework-agnostic primitives.
- [`authplane-mcp`](mcp/README.md): `rmcp` adapter.
- [`authplane-fastmcp`](fastmcp/README.md): `fastmcp-rust` adapter (stdio + HTTP).

## Requirements

- Rust 1.91 or newer (edition 2024)
- A Tokio runtime for async client and verifier flows

## Compatibility

Tested against authserver 0.2.0. Introspection-based revocation requires authserver 0.1.2 or newer, and a confidential client that is the issuing client or a runtime-client of the resource — older releases and other callers answer `active: false` for every token.

## Documentation

- [`core/README.md`](core/README.md) and [`core/docs/user-guide.md`](core/docs/user-guide.md)
- [`mcp/README.md`](mcp/README.md) and [`mcp/docs/user-guide.md`](mcp/docs/user-guide.md)
- [`fastmcp/README.md`](fastmcp/README.md) and [`fastmcp/docs/user-guide.md`](fastmcp/docs/user-guide.md)
- [`CHANGELOG.md`](CHANGELOG.md)
- [`SECURITY.md`](SECURITY.md)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`RELEASE_POLICY.md`](RELEASE_POLICY.md)

## Status

| Crate | crates.io | docs.rs |
| --- | --- | --- |
| Core SDK | [![crates.io](https://img.shields.io/crates/v/authplane-sdk?style=flat-square&label=authplane-sdk)](https://crates.io/crates/authplane-sdk) | [![docs.rs](https://img.shields.io/docsrs/authplane-sdk?style=flat-square&label=docs.rs)](https://docs.rs/authplane-sdk) |
| MCP adapter | [![crates.io](https://img.shields.io/crates/v/authplane-mcp?style=flat-square&label=authplane-mcp)](https://crates.io/crates/authplane-mcp) | [![docs.rs](https://img.shields.io/docsrs/authplane-mcp?style=flat-square&label=docs.rs)](https://docs.rs/authplane-mcp) |
| FastMCP adapter | [![crates.io](https://img.shields.io/crates/v/authplane-fastmcp?style=flat-square&label=authplane-fastmcp)](https://crates.io/crates/authplane-fastmcp) | [![docs.rs](https://img.shields.io/docsrs/authplane-fastmcp?style=flat-square&label=docs.rs)](https://docs.rs/authplane-fastmcp) |

## License

Apache 2.0. See [LICENSE](LICENSE).
