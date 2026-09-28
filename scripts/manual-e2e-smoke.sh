#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ADAPTER="mcp"
RUN_SETUP=1
SKIP_ADAPTER=0
export ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
export RESOURCE_URL="${RESOURCE_URL:-http://localhost:8080/mcp}"

usage() {
  cat <<'EOF'
Usage:
  manual-e2e-smoke.sh [--adapter mcp|fastmcp] [--skip-setup] [--skip-adapter]

Modes:
  --adapter      Which MCP adapter demo to exercise (default: mcp).
                 Use --adapter fastmcp to drive the FastMCP demo instead.
  --skip-setup   Do not rebuild/start the authserver demo (assume it's already up).
  --skip-adapter Only run the core client_credentials smoke example; do NOT start
                 any MCP demo server. Useful in minimal CI.

Environment overrides:
  ISSUER_URL     Authorization server issuer (default: http://localhost:9000)
  RESOURCE_URL   MCP resource URL (default: http://localhost:8080/mcp)
EOF
}

while [ "${#}" -gt 0 ]; do
  case "$1" in
    --adapter)
      ADAPTER="${2:-}"
      shift
      ;;
    --skip-setup)
      RUN_SETUP=0
      ;;
    --skip-adapter)
      SKIP_ADAPTER=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [ "${ADAPTER}" != "mcp" ] && [ "${ADAPTER}" != "fastmcp" ]; then
  echo "Invalid adapter: ${ADAPTER}" >&2
  exit 1
fi

ADAPTER_DIR="${REPO_ROOT}/${ADAPTER}"
RUN_CMD="${ADAPTER_DIR}/demo/run.sh"
SERVER_LOG="/tmp/rust-sdk-manual-e2e-smoke-${ADAPTER}.log"

RESOURCE_BASE="${RESOURCE_URL%/mcp}"
if [ "${RESOURCE_BASE}" = "${RESOURCE_URL}" ]; then
  echo "ERROR: RESOURCE_URL must end with /mcp, got ${RESOURCE_URL}" >&2
  exit 1
fi
PRM_URL="${RESOURCE_BASE}/.well-known/oauth-protected-resource/mcp"

SERVER_PID=""
cleanup() {
  if [ -n "${SERVER_PID}" ]; then
    pkill -P "${SERVER_PID}" >/dev/null 2>&1 || true
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  pkill -f "authplane-sdk --example client_credentials_smoke" >/dev/null 2>&1 || true
  pkill -f "authplane-sdk --example token_exchange_roundtrip" >/dev/null 2>&1 || true
  pkill -f "authplane-sdk --example dpop_roundtrip" >/dev/null 2>&1 || true
  pkill -f "cargo run --example http_calculator_demo" >/dev/null 2>&1 || true
  pkill -f "cargo run --example calculator_demo" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ "${RUN_SETUP}" -eq 1 ]; then
  bash "${SCRIPT_DIR}/manual-e2e-setup.sh"
fi

echo "==> Waiting for issuer metadata: ${ISSUER_URL}/.well-known/oauth-authorization-server"
for _ in $(seq 1 45); do
  status="$(curl -sS -o /dev/null -w "%{http_code}" "${ISSUER_URL}/.well-known/oauth-authorization-server" || true)"
  if [ "${status}" = "200" ]; then
    break
  fi
  sleep 1
done

status="$(curl -sS -o /dev/null -w "%{http_code}" "${ISSUER_URL}/.well-known/oauth-authorization-server" || true)"
if [ "${status}" != "200" ]; then
  echo "ERROR: issuer metadata endpoint not ready (status=${status})" >&2
  exit 1
fi

if [ ! -f /tmp/authserver-demo.client-id ] || [ ! -f /tmp/authserver-demo.key ]; then
  echo "ERROR: missing /tmp/authserver-demo.client-id or /tmp/authserver-demo.key" >&2
  exit 1
fi

echo "==> Running Rust SDK client_credentials smoke example"
OUTPUT="$(
  cd "${REPO_ROOT}" &&
  ISSUER_URL="${ISSUER_URL}" \
  RESOURCE_URL="${RESOURCE_URL}" \
  cargo run -p authplane-sdk --example client_credentials_smoke
)"
echo "${OUTPUT}"
if [[ "${OUTPUT}" != *"smoke_ok"* ]]; then
  echo "ERROR: smoke example did not report success" >&2
  exit 1
fi

echo ""
echo "==> Running Rust SDK token_exchange_roundtrip example"
OUTPUT="$(
  cd "${REPO_ROOT}" &&
  ISSUER_URL="${ISSUER_URL}" \
  RESOURCE_URL="${RESOURCE_URL}" \
  cargo run -p authplane-sdk --example token_exchange_roundtrip
)"
echo "${OUTPUT}"
if [[ "${OUTPUT}" != *"exchange_ok"* ]]; then
  echo "ERROR: token_exchange_roundtrip example did not report success" >&2
  exit 1
fi

echo ""
echo "==> Running Rust SDK dpop_roundtrip example (in-process)"
OUTPUT="$(
  cd "${REPO_ROOT}" &&
  cargo run -p authplane-sdk --example dpop_roundtrip
)"
echo "${OUTPUT}"
if [[ "${OUTPUT}" != *"dpop_roundtrip_ok"* ]]; then
  echo "ERROR: dpop_roundtrip example did not report success" >&2
  exit 1
fi

if [ "${SKIP_ADAPTER}" -eq 1 ]; then
  echo ""
  echo "Smoke check passed (rust-sdk, core only, adapter stage skipped)"
  exit 0
fi

if [ ! -x "${RUN_CMD}" ]; then
  echo "ERROR: adapter run script not found or not executable: ${RUN_CMD}" >&2
  exit 1
fi

if [ ! -f "${ADAPTER_DIR}/demo/.env" ]; then
  cp "${ADAPTER_DIR}/demo/.env.example" "${ADAPTER_DIR}/demo/.env"
fi

echo "==> Starting Rust demo (${ADAPTER})"
(
  cd "${REPO_ROOT}"
  "${RUN_CMD}" >"${SERVER_LOG}" 2>&1
) &
SERVER_PID=$!

if [ "${ADAPTER}" = "mcp" ]; then
  echo "==> Waiting for PRM: ${PRM_URL}"
  for _ in $(seq 1 180); do
    status="$(curl -sS -o /dev/null -w "%{http_code}" "${PRM_URL}" || true)"
    if [ "${status}" = "200" ] || [ "${status}" = "401" ]; then
      break
    fi
    sleep 1
  done
  status="$(curl -sS -o /dev/null -w "%{http_code}" "${PRM_URL}" || true)"
  if [ "${status}" != "200" ] && [ "${status}" != "401" ]; then
    echo "ERROR: PRM endpoint not ready (status=${status})" >&2
    echo "Server log: ${SERVER_LOG}" >&2
    exit 1
  fi

  echo "==> Checking unauthenticated /mcp is blocked"
  mcp_status="$(
    curl -sS -o /dev/null -w "%{http_code}" -X POST "${RESOURCE_URL}" \
      -H "Content-Type: application/json" \
      -d '{}' || true
  )"
  if [ "${mcp_status}" = "200" ]; then
    echo "ERROR: unauthenticated /mcp request unexpectedly returned 200" >&2
    exit 1
  fi
  if [ "${mcp_status}" = "000" ]; then
    echo "ERROR: unauthenticated /mcp check could not reach server" >&2
    exit 1
  fi
else
  # FastMCP demo runs over stdio; we just confirm the process started without
  # immediately exiting.
  sleep 3
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "ERROR: fastmcp demo exited early" >&2
    echo "Server log: ${SERVER_LOG}" >&2
    exit 1
  fi
fi

echo ""
echo "Smoke check passed (rust-sdk, adapter=${ADAPTER})"
echo "PRM: ${PRM_URL}"
echo "Server log: ${SERVER_LOG}"
