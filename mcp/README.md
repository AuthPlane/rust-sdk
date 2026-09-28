# authplane-mcp

[![crates.io](https://img.shields.io/crates/v/authplane-mcp?style=flat-square&label=authplane-mcp)](https://crates.io/crates/authplane-mcp)
[![docs.rs](https://img.shields.io/docsrs/authplane-mcp?style=flat-square&label=docs.rs)](https://docs.rs/authplane-mcp)

Consent-to-URL-elicitation helpers for the official Rust `rmcp` SDK.

## Install

```bash
cargo add authplane-mcp
```

## Quickstart

```rust
use authplane_mcp::wrap_tool_with_url_elicitation;

# async fn demo() {
let result = wrap_tool_with_url_elicitation(|| async {
    Ok::<_, authplane_sdk::AuthplaneError>("ok")
})
.await;

assert!(result.is_ok());
# }
```

See the [user guide](docs/user-guide.md) for consent mapping details and the exact `rmcp` error shape.
