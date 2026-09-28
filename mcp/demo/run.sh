#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Check .env exists
if [ ! -f "$SCRIPT_DIR/.env" ]; then
  echo "ERROR: $SCRIPT_DIR/.env not found."
  echo "Copy the example:"
  echo "  cp $SCRIPT_DIR/.env.example $SCRIPT_DIR/.env"
  exit 1
fi

# shellcheck disable=SC1090
set -a
source "$SCRIPT_DIR/.env"
set +a

AUTHPLANE_ISSUER="${AUTHPLANE_ISSUER:-${ISSUER_URL:-http://localhost:9000}}"
METADATA_URL="${AUTHPLANE_ISSUER%/}/.well-known/oauth-authorization-server"

if command -v curl >/dev/null 2>&1; then
  if ! curl -fsS "$METADATA_URL" >/dev/null 2>&1; then
    echo "ERROR: cannot reach authorization server metadata at:"
    echo "  $METADATA_URL"
    echo
    echo "Start authserver first, or fix AUTHPLANE_ISSUER in demo/.env."
    exit 1
  fi
fi

cd "$PROJECT_DIR"
cargo run --example http_calculator_demo
