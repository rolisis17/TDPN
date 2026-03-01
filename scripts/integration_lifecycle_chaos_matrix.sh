#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_profile() {
  local name="$1"
  shift
  local out="/tmp/integration_lifecycle_chaos_matrix_${name}.log"
  rm -f "$out"
  echo "[lifecycle-chaos-matrix] running profile=${name}"
  if ! env "$@" ./scripts/integration_lifecycle_chaos.sh >"$out" 2>&1; then
    echo "[lifecycle-chaos-matrix] profile=${name} failed"
    cat "$out"
    exit 1
  fi
  if ! rg -q "lifecycle chaos integration check ok" "$out"; then
    echo "[lifecycle-chaos-matrix] profile=${name} missing success marker"
    cat "$out"
    exit 1
  fi
  echo "[lifecycle-chaos-matrix] profile=${name} ok"
}

run_profile base \
  LIFECYCLE_CHAOS_TAG=base \
  DIR_PORT=8381 \
  ISSUER_PORT=8382 \
  ENTRY_PORT=8383 \
  EXIT_PORT=8384 \
  ENTRY_DATA_PORT=53820 \
  EXIT_DATA_PORT=53821 \
  RACE_LOOPS=20 \
  DISPUTE_LOOPS=14 \
  FRESH_LOOPS=18

run_profile higher_churn \
  LIFECYCLE_CHAOS_TAG=higher_churn \
  DIR_PORT=8391 \
  ISSUER_PORT=8392 \
  ENTRY_PORT=8393 \
  EXIT_PORT=8394 \
  ENTRY_DATA_PORT=53920 \
  EXIT_DATA_PORT=53921 \
  RACE_LOOPS=28 \
  DISPUTE_LOOPS=20 \
  DISPUTE_SLEEP_SEC=0.1 \
  FRESH_LOOPS=24 \
  FRESH_SLEEP_SEC=0.12

run_profile slower_control \
  LIFECYCLE_CHAOS_TAG=slower_control \
  DIR_PORT=8401 \
  ISSUER_PORT=8402 \
  ENTRY_PORT=8403 \
  EXIT_PORT=8404 \
  ENTRY_DATA_PORT=54020 \
  EXIT_DATA_PORT=54021 \
  RACE_LOOPS=16 \
  RACE_SLEEP_SEC=0.25 \
  DISPUTE_LOOPS=10 \
  DISPUTE_SLEEP_SEC=0.18 \
  FRESH_LOOPS=14 \
  FRESH_SLEEP_SEC=0.2

echo "lifecycle chaos matrix integration check ok"
