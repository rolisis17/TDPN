#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_expect_fail() {
  local name="$1"
  local expected_pattern="$2"
  shift 2

  local log_file="/tmp/integration_wg_only_${name}.log"
  if "$@" >"$log_file" 2>&1; then
    echo "expected ${name} to fail under WG-only guardrails"
    cat "$log_file"
    exit 1
  fi
  if ! rg -q "$expected_pattern" "$log_file"; then
    echo "missing expected ${name} validation signal"
    cat "$log_file"
    exit 1
  fi
}

run_expect_fail \
  "client_default" \
  "WG_ONLY_MODE requires DATA_PLANE_MODE=opaque" \
  env WG_ONLY_MODE=1 timeout 12s go run ./cmd/node --client

run_expect_fail \
  "entry_default" \
  "WG_ONLY_MODE requires ENTRY_LIVE_WG_MODE=1" \
  env WG_ONLY_MODE=1 timeout 12s go run ./cmd/node --entry

run_expect_fail \
  "exit_default" \
  "WG_ONLY_MODE requires DATA_PLANE_MODE=opaque" \
  env WG_ONLY_MODE=1 timeout 12s go run ./cmd/node --exit

run_expect_fail \
  "client_prod_implicit" \
  "WG_ONLY_MODE requires DATA_PLANE_MODE=opaque" \
  env PROD_STRICT_MODE=1 BETA_STRICT_MODE=1 timeout 12s go run ./cmd/node --client

echo "wg-only mode integration check ok"
