#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

HELPER="scripts/cosmos_bridge_local_stack.sh"

if [[ ! -f "${HELPER}" ]]; then
  echo "missing helper script: ${HELPER}"
  exit 1
fi

require_contains() {
  local haystack="$1"
  local needle="$2"
  local message="$3"
  if ! grep -Fq -- "${needle}" <<<"${haystack}"; then
    echo "${message}"
    echo "--- output ---"
    printf '%s\n' "${haystack}"
    exit 1
  fi
}

require_not_contains() {
  local haystack="$1"
  local needle="$2"
  local message="$3"
  if grep -Fq -- "${needle}" <<<"${haystack}"; then
    echo "${message}"
    echo "--- output ---"
    printf '%s\n' "${haystack}"
    exit 1
  fi
}

echo "[cosmos-bridge-local-stack-contract] dry-run with auth + grpc wiring"
OUTPUT_WITH_AUTH="$(
  bash "${HELPER}" \
    --dry-run \
    --settlement-http-listen "127.0.0.1:18080" \
    --grpc-listen "127.0.0.1:19090" \
    --auth-token "bridge-contract-token"
)"

require_contains "${OUTPUT_WITH_AUTH}" "export SETTLEMENT_CHAIN_ADAPTER=cosmos" \
  "contract failed: missing SETTLEMENT_CHAIN_ADAPTER export"
require_contains "${OUTPUT_WITH_AUTH}" "export COSMOS_SETTLEMENT_ENDPOINT=http://127.0.0.1:18080" \
  "contract failed: missing COSMOS_SETTLEMENT_ENDPOINT export"
require_contains "${OUTPUT_WITH_AUTH}" "export COSMOS_SETTLEMENT_API_KEY=bridge-contract-token" \
  "contract failed: missing COSMOS_SETTLEMENT_API_KEY export in auth mode"
require_contains "${OUTPUT_WITH_AUTH}" "go run ./blockchain/tdpn-chain/cmd/tdpnd --settlement-http-listen 127.0.0.1:18080 --grpc-listen 127.0.0.1:19090 --settlement-http-auth-token bridge-contract-token" \
  "contract failed: missing expected tdpnd command wiring in auth+grpc mode"
require_contains "${OUTPUT_WITH_AUTH}" "dry-run mode: command not started." \
  "contract failed: helper did not report dry-run mode"

echo "[cosmos-bridge-local-stack-contract] dry-run without auth"
OUTPUT_NO_AUTH="$(
  bash "${HELPER}" \
    --dry-run \
    --settlement-http-listen "127.0.0.1:28080"
)"

require_contains "${OUTPUT_NO_AUTH}" "export SETTLEMENT_CHAIN_ADAPTER=cosmos" \
  "contract failed: missing SETTLEMENT_CHAIN_ADAPTER export (no-auth mode)"
require_contains "${OUTPUT_NO_AUTH}" "export COSMOS_SETTLEMENT_ENDPOINT=http://127.0.0.1:28080" \
  "contract failed: missing COSMOS_SETTLEMENT_ENDPOINT export (no-auth mode)"
require_contains "${OUTPUT_NO_AUTH}" "go run ./blockchain/tdpn-chain/cmd/tdpnd --settlement-http-listen 127.0.0.1:28080" \
  "contract failed: missing tdpnd command in no-auth mode"
require_not_contains "${OUTPUT_NO_AUTH}" "export COSMOS_SETTLEMENT_API_KEY=" \
  "contract failed: COSMOS_SETTLEMENT_API_KEY should not be exported without auth token"
require_not_contains "${OUTPUT_NO_AUTH}" "--settlement-http-auth-token" \
  "contract failed: no-auth dry-run should not include settlement auth runtime flag"

echo "[cosmos-bridge-local-stack-contract] dry-run with state-dir wiring"
OUTPUT_STATE_DIR="$(
  bash "${HELPER}" \
    --dry-run \
    --settlement-http-listen "127.0.0.1:38080" \
    --state-dir "/tmp/tdpn-chain-state-contract"
)"

require_contains "${OUTPUT_STATE_DIR}" "export TDPN_CHAIN_STATE_DIR=/tmp/tdpn-chain-state-contract" \
  "contract failed: missing TDPN_CHAIN_STATE_DIR export in state-dir mode"
require_contains "${OUTPUT_STATE_DIR}" "--state-dir /tmp/tdpn-chain-state-contract" \
  "contract failed: missing --state-dir flag wiring in command"

echo "cosmos bridge local stack contract integration check ok"
