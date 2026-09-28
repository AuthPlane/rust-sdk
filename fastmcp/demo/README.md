# Calculator Service Example

A minimal FastMCP server demonstrating Authplane JWT authentication with per-tool scope enforcement, supporting both HTTP and stdio transports.

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

2. Run the FastMCP server over HTTP (default):

   ```bash
   cd fastmcp
   ./demo/run.sh
   ```

   Or over stdio:

   ```bash
   TRANSPORT=stdio ./demo/run.sh
   ```

The demo registers:

- `add`
- `multiply`
- `whoami`
- `consent_demo`

## How it works

- Verifies bearer JWTs via `authplane-sdk` against `AUTHPLANE_ISSUER`/`AUTHPLANE_RESOURCE`.
- Exposes verified subject and scopes in FastMCP auth context.
- Demonstrates URL elicitation mapping for consent-required token-exchange errors.
- Defaults to HTTP transport (`Server::run_http`); set `TRANSPORT=stdio` for stdio.
