# authplane-sdk

[![crates.io](https://img.shields.io/crates/v/authplane-sdk?style=flat-square&label=authplane-sdk)](https://crates.io/crates/authplane-sdk)
[![docs.rs](https://img.shields.io/docsrs/authplane-sdk?style=flat-square&label=docs.rs)](https://docs.rs/authplane-sdk)

Framework-agnostic Rust primitives for Authplane OAuth flows, token verification, and DPoP.

## What is included

- Typed OAuth errors, including `ConsentRequiredError`.
- OAuth error mapping utility from token responses.
- Circuit policy helper with shared defaults (5 failures, 30s cooldown).

## Install

```bash
cargo add authplane-sdk
```

## Quickstart

```rust
use authplane_sdk::parse_token_exchange_error;

let err = parse_token_exchange_error(
    Some(400),
    r#"{
        "error":"consent_required",
        "error_description":"Consent is required",
        "service_id":"drive",
        "consent_url":"https://example.com/consent"
    }"#,
);

println!("{err}");
```

See the [user guide](docs/user-guide.md) for `AuthplaneClient`, token verification, DPoP, fetch settings, and error handling.
