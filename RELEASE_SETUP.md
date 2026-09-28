# Release setup

One-time operator steps required before the release pipeline can publish to crates.io. All three crates (`authplane-sdk`, `authplane-mcp`, `authplane-fastmcp`) must be configured independently.

## 1. First publish of each crate — manual, with a token

**crates.io has no pending publishers.** A trusted publisher can only be
configured on a crate that already exists, so the first version of each crate
name has to be uploaded by hand. RFC 3691, which defines the feature, is
explicit: *"A Trusted Publisher Configuration can only be created after an
initial manual publishing of a crate."* Configuring one ahead of the first
publish is listed there as a future possibility and is not implemented.

This is where crates.io differs from PyPI, whose pending-publisher flow does
let you register a publisher for a name you do not own yet. `publish-crates.yml`
is tag-triggered and authenticates only via OIDC, so with no trusted publisher
in place the token exchange has nothing to exchange against, for all three
crates at once.

### Cut the release first, then publish from the tag

The tag `vX.Y.Z` is not created by hand. It comes from `release.yml`, which a
maintainer dispatches from the `release/v*` (or `hotfix/v*`) branch and which
pushes the release branch and the tag together in one atomic push. Run it as
usual for the first release: the version bump, the release commit, the tag and
the GitHub Release all come out of that run and none of them depend on
crates.io.

The tag push then starts `publish-crates.yml`, and on the first release that
run will go red at **Exchange OIDC for a crates.io publish token**. That is
expected — no trusted publisher exists yet, so there is nothing to exchange
against — and it is harmless: the step runs after packaging and after the
packed `.crate` files have been uploaded as the `dist-vX.Y.Z` artifact, so the
run fails before it has published anything. Do not follow §5. Nothing was
partially uploaded and there is nothing to recover; §5 is only for a run that
published one crate and then failed. If the `crates-io` environment has
required reviewers, reject the deployment instead of letting the run reach the
failing step.

Then publish from the tag, locally, in the §4 order — the adapters declare
`authplane-sdk` by version and cannot resolve until the core crate is on the
index:

```bash
cargo login                          # scoped crates.io token, entered interactively
git checkout vX.Y.Z
cargo publish -p authplane-sdk      --locked
# wait for authplane-sdk X.Y.Z to appear on the index before continuing
cargo publish -p authplane-mcp      --locked --no-verify
cargo publish -p authplane-fastmcp  --locked --no-verify
```

Before uploading, download the `dist-vX.Y.Z` artifact from the failed
`publish-crates.yml` run and compare each local `.crate` hash against it, the
same check §5 describes, so what reaches crates.io is exactly what CI packed
from the tag.

Scope the token before you create it. crates.io derives the endpoint scope it
demands from whether the crate already exists, so creating a name needs
**`publish-new`**; `publish-update` alone is rejected for a name that is not on
the index yet, and §1 is by definition the new-name case. Create the token with
both `publish-new` and `publish-update` — the second scope is what the §5
recovery path needs, and §2 says to keep this token for it — restricted to the
crate pattern `authplane-*` and to a short expiry.

Two things are permanent from this point and worth checking before running it:
a published version can never be deleted (only yanked, which leaves it
resolvable), and `rust-version` and the rendered documentation both travel in
the package metadata. Publish from a tag whose declared MSRV is true and whose
docs are current.

### Add a second owner before configuring trusted publishing

A manual `cargo publish` leaves the account that ran it as the only owner of
all three crates, and only an owner can add the trusted publisher in §2 or yank
a bad version later. Add a second maintainer to each crate before moving on:

```bash
cargo owner --add <login> authplane-sdk
cargo owner --add <login> authplane-mcp
cargo owner --add <login> authplane-fastmcp
```

The invitation has to be accepted before it takes effect. A GitHub team
(`cargo owner --add github:<org>:<team> <crate>`) can be added the same way and
is worth adding for yanks and ownership changes, but it does not replace the
individual: crates.io only accepts the §2 trusted-publishing form from an
individual account that owns the crate, with a verified email address and a
linked GitHub account. Team membership alone does not satisfy that check.

## 2. crates.io trusted publishing — after the first publish

Once a crate exists, on its own page — `crates.io/crates/<crate>` →
**Settings → Trusted Publishing → GitHub → Add**. Per crate, so three times.

- **Repository owner**: `AuthPlane`
- **Repository name**: `rust-sdk`
- **Workflow filename**: `publish-crates.yml` — the workflow that exchanges
  OIDC for a publish token and runs `cargo publish`, not `release.yml`, which
  only pushes the tag.
- **Environment**: `crates-io`

From the second release of each crate onward, `publish-crates.yml` runs
unattended and no registry token is stored in GitHub: authentication is a
short-lived OIDC token scoped to that workflow and environment. Keep the
operator token only for the recovery path in §5.

### GitHub Environment

Needed before the first OIDC-authenticated release, and its name has to match
the **Environment** field above exactly.

1. **Settings → Environments → New environment → `crates-io`**.
2. (Optional) Add **required reviewers** so every release waits for a human
   approval before uploading to crates.io.
3. (Optional) Restrict the environment to tags matching `v*.*.*` so only the
   tag-triggered `publish-crates.yml` workflow can deploy. The release tag is
   pushed directly onto the `release/v*` / `hotfix/v*` source branch (no merge
   to the default branch); `publish-crates.yml` runs on the tag push and
   publishes to crates.io via OIDC.

## 3. CHANGELOG

The release workflow reads `CHANGELOG.md` for notes. Ensure:

- Every release has a `## [X.Y.Z]` heading on the source branch (`release/v*` or `hotfix/v*`) before running the release workflow.
- The default branch always carries `## [Unreleased]` between releases. The `cut-release` workflow enforces this on `release/v*` cuts (refuses to cut if missing); `hotfix/v*` cuts skip the check because they branch off an older tag.

## 4. Publish order

crates.io does not support atomic multi-crate uploads, and both adapters depend on `authplane-sdk`. The `publish-crates.yml` workflow publishes in this fixed order, waiting for the core crate to appear on the index before publishing the adapters:

1. `authplane-sdk` (workspace member `core`)
2. `authplane-mcp` (workspace member `mcp`)
3. `authplane-fastmcp` (workspace member `fastmcp`)

The adapters declare the core dependency as `authplane-sdk = { path = "../core", version = "X.Y.Z" }`. `cargo publish` strips the `path` key from the published manifests, so the published adapters resolve `authplane-sdk` from the registry, while every local/CI step before publication resolves it from the workspace. Do not replace the dep with a bare version string before the release is on crates.io — `cargo update`/`package`/`publish --dry-run` would all fail to resolve it.

## 5. Recovery: partial crates.io upload

If the publish workflow publishes one crate then fails (e.g. a network blip during the wait-for-index step, or an unexpected verification error on a later crate):

1. Download the `dist-vX.Y.Z` artifact from the failed workflow run. It contains the packed `.crate` files flat: `authplane-sdk-X.Y.Z.crate`, `authplane-mcp-X.Y.Z.crate`, `authplane-fastmcp-X.Y.Z.crate`.
2. `publish-crates.yml` is tag-triggered only (no manual dispatch or inputs), so a partial publish is finished by hand. `cargo publish` does not skip already-uploaded versions — it exits non-zero — so check the index first and run only the commands for crates still missing, in the §4 order:
   ```bash
   # Requires a scoped crates.io token in the local `cargo login` session
   git checkout vX.Y.Z
   cargo publish -p authplane-sdk      --locked  # run only if this version is not yet on the index
   cargo publish -p authplane-mcp      --locked --no-verify
   cargo publish -p authplane-fastmcp  --locked --no-verify
   ```
   (The workflow publishes all three crates with `--no-verify` — the tarballs were already validated by the workspace-mode package step. Manually, verifying the core crate is safe to keep; the adapters need `--no-verify` because per-crate verification would try to resolve the core crate from the registry mid-flight. Before pushing anything, compare each local `.crate` hash against the artifact from the failed run so you ship exactly what CI built.)
3. Manually create the GitHub Release if that step was also skipped:
   ```bash
   gh release create vX.Y.Z --title vX.Y.Z --notes-file <path-to-notes>
   ```
   No `--target` — the tag already points at the correct commit on the (now deleted) source branch.
4. If any commits on the source branch need to reach the default branch, dispatch the **Backport fixes** workflow with `fromBranch=vX.Y.Z` (the tag, not the branch — the branch was deleted after the atomic push).

The git tag is already live, so the release cannot be re-run end to end against the same version (`release.yml`'s tag-exists pre-flight will refuse, and re-pushing the tag would not change what crates.io already holds). Finish the publish manually as above.

## 6. Pre-release checks performed by CI

Every pull request runs `ci.yml`: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features`, per publishable crate and workspace-wide, plus an MSRV build/test and a package + publish dry-run of `authplane-sdk` (the adapters cannot be dry-run individually until the core crate is on the index — see §4).

`release.yml` re-runs the workspace tests on the release branch and validates all three crates with `cargo package --workspace` and `cargo publish --workspace --dry-run` before tagging; a failure there aborts before the tag exists. `publish-crates.yml` re-packages the workspace from the tag and aborts before upload if packaging fails.
