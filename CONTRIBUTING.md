# Contributing

Thanks for helping improve the Authplane Rust SDK.

## Reporting issues

- Bugs and feature requests should go through the repository issue tracker.
- Security reports should follow the process in [SECURITY.md](SECURITY.md) instead of public issues.

## Development setup

### Prerequisites

- `rustup`. The exact compiler CI builds with is pinned in
  `rust-toolchain.toml`; rustup installs and selects it automatically for any
  cargo command run inside the repository, so a local `fmt`/`clippy`/`test`
  run uses the same toolchain CI does. Run `rustup toolchain install` from the
  repository root to fetch it up front.

  The pin is bumped deliberately, as part of cutting a release: a new rustc
  brings new `clippy` findings, and the point of pinning is that they arrive in
  one reviewable commit instead of turning every open PR red on the day Rust
  ships. Nothing bumps it automatically — dependabot has no
  `rust-toolchain.toml` ecosystem — so if it is not done at release time it
  does not get done, and the first bump after a long gap carries a year of
  lints at once.
- Cargo

### Clone and build

```bash
git clone https://github.com/AuthPlane/rust-sdk.git
cd rust-sdk
cargo build
```

## Local verification

Run these from the repository root unless a package-specific change needs a narrower run:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

For focused iteration on the core crate:

```bash
cd core
cargo test
```

## Pull requests

- Keep changes focused and explain the user-facing impact in the PR description.
- Use Conventional Commit-style subjects when possible.
- Update docs and examples in the same PR when public behavior changes.
- Add or update tests for bug fixes and new functionality.
- If release notes matter, update [`CHANGELOG.md`](CHANGELOG.md) under `Unreleased`.
- Open pull requests against the default branch.
- Every commit that lands here stands on its own: no work-in-progress state, and a
  message that explains the change without pointing at a tracker or a repository a
  reader of this one cannot open. Citing a spec — an RFC section, a linked standard —
  is the opposite of that and is encouraged.

## API conventions

When adding a new public type, pick the visibility shape by the type's role:

- **Transparent newtype** — a thin wrapper around a single inner value with no
  invariants to enforce (e.g. `RawAccessToken(pub String)`). The inner field is
  `pub` so callers can construct, destructure, and read without going through
  ceremony. Add `as_str()` / `into_inner()` / `AsRef<_>` only when they read
  more naturally than the field.
- **Invariant-carrying config** — a struct whose validity depends on cross-field
  rules or whose setters perform validation (e.g. `InboundDPoPOptions`). All
  fields are private; expose typed setters that enforce the invariants and
  getters where the verifier or PRM emitter needs to read state. Public fields
  here would let callers bypass validation and the type system wouldn't catch
  it.

If you find a type that fits neither bucket cleanly, default to private and
revisit when a concrete consumer needs more access.

## CI expectations

- Format and test commands should pass locally before opening a PR.
- Keep dependency and automation changes reviewable; avoid mixing large vendoring churn with behavioral changes when possible.


## Code of conduct

Be respectful, assume good intent, and help keep reviews constructive.
