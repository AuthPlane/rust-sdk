# authplane-conformance-tests

Conformance test harness that drives the shared OAuth SDK conformance
catalog against the Rust `authplane-sdk` crate: every test here traces
back to a single case in `oauth-sdk-conformance-catalog.yaml`, which is
the **sole source of truth** for what the test must assert.

## Ground rule

Never modify, weaken, or delete a conformance assertion to make a test
pass. If the implementation disagrees with the catalog, stop and
escalate to a human — only humans decide whether the catalog is wrong
or the implementation is. See the `conformance-testing` skill for the
red-flag table.

## Layout

| File                                      | Scope                                                |
| ----------------------------------------- | ---------------------------------------------------- |
| `src/lib.rs`                              | `conformance_case!` marker + catalog loader          |
| `src/bin/conformance-case-ids.rs`         | Writes the registered case ids as JSON, for the drift check |
| `tests/catalog_alignment.rs`              | Fails the build if any catalog case lacks a marker   |
| `tests/catalog_path_guard.rs`             | Pins the catalog-path explicitness contract          |
| `tests/rfc8414_conformance.rs`            | RFC 8414 authorization-server metadata               |
| `tests/oauth_protocol_conformance.rs`     | RFC 6749 / 7009 / 7662 / 8693 / 8707 / 9728          |
| `tests/jwt_and_dpop_conformance.rs`       | RFC 9068 / 8725 / 9449 / 9110                        |
| `tests/authplane_specific_conformance.rs` | AuthPlane agent claims + unified verify contract     |

## Writing a conformance test

1. Find the case in `oauth-sdk-conformance-catalog.yaml`.
2. Read its `expected` block — note every key in `result_contains`,
   `result_shape`, `outcome`, `error_category`, and any SDK-specific
   subkeys.
3. Write one or more `#[test]` bodies whose assertions cover every item
   in `expected`. Multiple tests per case id are fine — split accept
   vs. reject paths if that's clearer.
4. Place the case id at the top of each test body via
   `conformance_case!("<case-id>")`. The catalog alignment test scans
   these markers statically, so the string **must be a literal** —
   `rustfmt` is free to split the call across lines, which the scan
   handles by collapsing whitespace before it matches.

```rust
#[test]
fn rfc8414_metadata_issuer_must_match_configured_issuer() {
    conformance_case!("rfc8414-metadata-issuer-must-match-configured-issuer");
    // body with real assertions
}
```

## `#[ignore]` convention

Some catalog cases describe behavior that is not yet reachable through
the Rust SDK's stable API — either because the required surface is only
available behind `#[doc(hidden)]`, or because no mockito fixture is
wired up yet. Those tests still carry a `conformance_case!` marker (so
catalog alignment passes) but are annotated `#[ignore = "..."]` naming
the missing fixture. Do not remove the marker — it is the contract that
the Rust SDK owes the case a real implementation.

## Catalog discovery

The harness resolves the catalog file in this order:

1. `$CONFORMANCE_CATALOG_PATH` (absolute path to the YAML).
2. `$AUTHPLANE_CONFORMANCE_CATALOG` (legacy).
3. `<rust-sdk-repo>/../conformance/oauth-sdk-conformance-catalog.yaml`
   — a sibling checkout of `AuthPlane/conformance`, for working
   against only this repo.

If (1) or (2) is set but names a file that is not there,
`catalog_alignment.rs` fails: something configured the catalog
explicitly and it is missing, which is a broken harness rather than an
absent one. Only the fallback (3) skips, so a solo `rust-sdk` checkout
still works offline.

CI never relies on (3). `ci.yml`, `release.yml` and
`conformance-catalog-drift.yml` all fetch the catalog into the runner
temp directory and set `$CONFORMANCE_CATALOG_PATH`, so the assertion
always runs there.

## Catalog pinning

`ci.yml` and `release.yml` fetch the catalog at the revision recorded in
the tracked [`.conformance-catalog-ref`](../.conformance-catalog-ref) at
the repo root, via `.github/scripts/fetch-conformance-catalog.sh`. The
ref is guarded by a `^[0-9a-f]{40}$` shape check before the fetch, so a
branch or tag name cannot silently un-pin CI.

Pinning means a case added to the catalog cannot turn an unrelated PR
red here. Adopt new cases deliberately: add the `conformance_case!`
coverage and bump `.conformance-catalog-ref` in the same change.

The trade-off is that new cases are invisible until someone bumps the
pin. `conformance-catalog-drift.yml` closes that gap — weekly, it runs
this same alignment assertion against the catalog's unpinned tip as an
early warning.

## Running

```bash
# All crates, including conformance tests
cargo test --workspace --all-features --locked

# Just the conformance crate
cargo test -p authplane-conformance-tests

# One test file
cargo test -p authplane-conformance-tests --test rfc8414_conformance
```

## Known gaps

The Rust SDK exposes two verify entrypoints —
`AuthplaneResource::verify` (bearer-only; rejects `cnf`-bound tokens) and the
unified `AuthplaneResource::verify_with_context(token, &DpopRequestContext)`
(three-mode dispatch) that branches automatically on the token's `cnf.jkt`
claim. All RFC 9449 unified-entrypoint cases are now active tests.

The catalog's 107 cases at the pinned revision all have real test bodies
**except** the RFC 9068 access-token cases that need a full-JWKS/metadata
fixture.
Those are annotated `#[ignore = "requires mockito JWKS fixture"]`; when
someone wires up the mockito AS harness, remove `#[ignore]` and
implement against
`AuthplaneResource::from_prefetched_metadata` (which now accepts a
pre-built `JwkSet` and skips the network call).
