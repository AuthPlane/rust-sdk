# Calculator Service Example

A minimal MCP server demonstrating Authplane JWT authentication with per-tool scope enforcement.

The server exposes two tools:

| Tool       | Required scope    |
| ---------- | ----------------- |
| `add`      | `tools/add`       |
| `multiply` | `tools/multiply`  |

Tokens must carry the scope for the specific tool being called. A token with only `tools/add` can call `add` but not `multiply`.

## Prerequisites

- `rustup`. The compiler is pinned in `rust-toolchain.toml` at the
  repository root and selected automatically inside the workspace.
- The **authserver authorization server** running locally

## Setup

1. Copy the environment file:

   ```bash
   cp demo/.env.example demo/.env
   ```

2. Run the MCP server:

   ```bash
   cd mcp
   ./demo/run.sh
   ```

Once the demo is up:

- PRM: `http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp`
- MCP endpoint: `http://127.0.0.1:8080/mcp`

## How it works

- Discovers AS metadata and JWKS from `AUTHPLANE_ISSUER` (RFC 8414).
- Verifies bearer JWT (`iss`, `aud`, signature, expiry).
- Enforces per-tool scopes (`tools/add`, `tools/multiply`) in handlers.
