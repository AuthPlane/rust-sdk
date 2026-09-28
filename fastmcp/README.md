# authplane-fastmcp

[![crates.io](https://img.shields.io/crates/v/authplane-fastmcp?style=flat-square&label=authplane-fastmcp)](https://crates.io/crates/authplane-fastmcp)
[![docs.rs](https://img.shields.io/docsrs/authplane-fastmcp?style=flat-square&label=docs.rs)](https://docs.rs/authplane-fastmcp)

Consent-to-URL-elicitation helpers for `fastmcp-rust`, with support for both stdio and HTTP transports.

## Install

```bash
cargo add authplane-fastmcp
```

## Quickstart

```rust
use authplane_fastmcp::wrap_tool_with_url_elicitation;

# async fn demo() {
let result = wrap_tool_with_url_elicitation(|| async {
    Ok::<_, authplane_sdk::AuthplaneError>("ok")
})
.await;

assert!(result.is_ok());
# }
```

## Transports

`fastmcp-rust` 0.3+ supports both stdio and HTTP:

```rust
// HTTP (default for authenticated servers)
server.run_http("127.0.0.1:8080");

// stdio (for subprocess-based MCP clients)
server.run_stdio();
```

See the [user guide](docs/user-guide.md) for consent mapping details and the exact `fastmcp-rust` error shape.
