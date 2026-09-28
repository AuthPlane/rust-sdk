<!--
  Canonical doc for the "Three-mode inbound DPoP dispatch" topic. This file
  is pulled into rustdoc via `#![doc = include_str!("../docs/three_mode_dpop.md")]`
  in `core/src/three_mode_dpop_docs.rs`, so its `rust` fences run under
  `cargo test --doc -p authplane-sdk` and any drift from the live API
  surfaces as a CI failure.

  `core/docs/user-guide.md` links here and does NOT duplicate the content —
  this is the single source of truth.
-->

# Three-mode inbound DPoP dispatch

`AuthplaneResource::verify_with_context(token, context)` is the unified entrypoint adapters use. The behaviour it picks at runtime is driven by `ResourceOptions::inbound_dpop` (an `Option<InboundDPoPOptions>`):

| Mode | `inbound_dpop` value | Bearer-only token | DPoP-bound token (proof attached) | DPoP signal on a non-bound token |
|---|---|---|---|---|
| **1 — Required** | `Some(InboundDPoPOptions::required())` | rejected — `DpopBindingMismatch` | accepted | rejected |
| **2 — Supported** | `Some(InboundDPoPOptions::default())` | accepted | accepted | rejected as malformed |
| **3 — Not configured** | `None` | accepted | rejected — `DpopNotSupported` (RFC 9449 §6) | rejected — `DpopNotSupported` |

`ResourceOptions` is a plain struct (no `new` constructor); the idiomatic builders are `ResourceOptions::default()` for Modes 2/3 and the `.with_inbound_dpop(...)` chain helper for Modes 1/2. The resource URL is passed to `AuthplaneResource::create_with_options(...)` (or `AuthplaneClient::resource_with_options(...)` if you already hold a client), not to `ResourceOptions` itself.

> **PRM advertising.** `AuthplaneResource::prm_response()` reflects the configured mode automatically (RFC 9449 §7.1 + RFC 9728 §2). Mode 2 / Mode 1 emit `dpop_signing_alg_values_supported` from `InboundDPoPOptions::resolved_allowed_proof_algorithms()`; Mode 1 additionally sets `dpop_bound_access_tokens_required: true`. Mode 3 omits both fields entirely.

```rust
use authplane_sdk::{
    AuthplaneResource, FetchSettings, InboundDPoPOptions, ResourceOptions,
};

# async fn demo() -> Result<(), authplane_sdk::VerifierError> {
let issuer = "https://auth.example.com";
let resource_url = "https://api.example.com/mcp";
let scopes: Vec<String> = vec!["tools/echo".into()];

// Mode 2 — Supported. Bearer and DPoP-bound tokens both accepted.
let mode_2 = AuthplaneResource::create_with_options(
    issuer,
    resource_url,
    &scopes,
    FetchSettings::default(),
    ResourceOptions::default().with_inbound_dpop(InboundDPoPOptions::default()),
)
.await?;

// Mode 1 — Required. Bearer-only tokens rejected.
let mode_1 = AuthplaneResource::create_with_options(
    issuer,
    resource_url,
    &scopes,
    FetchSettings::default(),
    ResourceOptions::default().with_inbound_dpop(InboundDPoPOptions::required()),
)
.await?;

// Mode 3 — No DPoP semantics. Inbound proofs rejected.
let mode_3 = AuthplaneResource::create_with_options(
    issuer,
    resource_url,
    &scopes,
    FetchSettings::default(),
    ResourceOptions::default(),
)
.await?;
# let _ = (mode_1, mode_2, mode_3);
# Ok(())
# }
```

`verify_with_context` takes a `DpopRequestContext`. The struct carries the request shape only — `method`, `url`, `proof`, `nonce`. Replay store and other DPoP policy knobs live on the resource via `InboundDPoPOptions`, applied automatically by the verifier. Construct it with `DpopRequestContext::new` (single, already-extracted proof) or `DpopRequestContext::from_header_values` (raw header values; also enforces the RFC 9449 §4.3 #1 one-proof-per-request rule):

```rust
use authplane_sdk::{AuthplaneResource, DpopRequestContext, VerifierError};

# async fn demo(
#     resource: &AuthplaneResource,
#     token: &str,
#     proof: Option<&str>,
# ) -> Result<(), VerifierError> {
let context = DpopRequestContext::new("POST", "https://api.example.com/mcp", proof, None);
let claims = resource.verify_with_context(token, &context).await?;
# let _ = claims;
# Ok(())
# }
```

`verify_with_context` returns `VerifierError`, not `AuthplaneError`; the three error classes a caller can map onto `WWW-Authenticate` challenges:

- `VerifierError::DpopBindingMismatch` — Mode 1 received a bearer-only token. Map to `WWW-Authenticate: Bearer error="invalid_token"`. The retry hint comes from the resource's PRM document, which advertises `dpop_bound_access_tokens_required: true` automatically whenever `InboundDPoPOptions::required()` is installed (RFC 9449 §7.1 + RFC 9728 §2).
- `VerifierError::DpopProofMissing` — DPoP-bound token (`cnf.jkt` present) presented without a proof.
- `VerifierError::DpopNotSupported` — Mode 3 received a DPoP signal. The retry challenge must be `Bearer`, not `DPoP`, because the client should fall back to bearer (the resource never opted into DPoP).
