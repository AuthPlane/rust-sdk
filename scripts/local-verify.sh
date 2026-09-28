#!/usr/bin/env bash
#
# Local-verify pipeline for rust-sdk.
#
# Mirrors the gates that .github/workflows/ci.yml runs in CI, plus a coverage
# step.  Run from any directory; the script resolves its own location.
#
# Usage:
#   scripts/local-verify.sh                # fmt + clippy + tests
#   scripts/local-verify.sh --with-coverage  # adds cargo-llvm-cov
#   scripts/local-verify.sh --with-conformance  # adds conformance suite
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WITH_COVERAGE=0
WITH_CONFORMANCE=0

while [ "${#}" -gt 0 ]; do
  case "$1" in
    --with-coverage) WITH_COVERAGE=1 ;;
    --with-conformance) WITH_CONFORMANCE=1 ;;
    -h|--help)
      grep '^# ' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
  shift
done

cd "$REPO_ROOT"

echo "==> cargo fmt --all -- --check"
cargo fmt --all -- --check

echo "==> cargo clippy --workspace --all-targets --all-features -- -D warnings"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> cargo test --workspace --all-features"
cargo test --workspace --all-features

if [ "$WITH_CONFORMANCE" = "1" ]; then
  # Arm the fail-loud guard when the sibling checkout is present: with the
  # path set explicitly, a missing/broken catalog fails the alignment test
  # instead of skipping it, so "green locally" means "aligned". Without the
  # checkout the suite skips alignment — say so, so a green run is not read
  # as an alignment pass.
  SIBLING_CATALOG="$REPO_ROOT/../conformance/oauth-sdk-conformance-catalog.yaml"
  if [ -z "${CONFORMANCE_CATALOG_PATH:-}" ] && [ -f "$SIBLING_CATALOG" ]; then
    export CONFORMANCE_CATALOG_PATH="$SIBLING_CATALOG"
  fi
  if [ -z "${CONFORMANCE_CATALOG_PATH:-}" ]; then
    echo "==> conformance catalog not found; catalog alignment will be SKIPPED" >&2
    echo "    (set CONFORMANCE_CATALOG_PATH or check out AuthPlane/conformance alongside this repo)" >&2
  fi
  echo "==> cargo test -p authplane-conformance-tests"
  cargo test -p authplane-conformance-tests
fi

if [ "$WITH_COVERAGE" = "1" ]; then
  if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo "cargo-llvm-cov not installed; running: cargo install cargo-llvm-cov" >&2
    cargo install cargo-llvm-cov
  fi
  echo "==> cargo llvm-cov --workspace --all-features --html"
  cargo llvm-cov --workspace --all-features --html
  echo "    report: target/llvm-cov/html/index.html"
fi

echo "All gates passed."
