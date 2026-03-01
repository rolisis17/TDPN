#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_profile() {
  local name="$1"
  shift
  local out="/tmp/integration_client_bootstrap_recovery_matrix_${name}.log"
  rm -f "$out"
  echo "[bootstrap-recovery-matrix] running profile=${name}"
  if ! env "$@" ./scripts/integration_client_bootstrap_recovery.sh >"$out" 2>&1; then
    echo "[bootstrap-recovery-matrix] profile=${name} failed"
    cat "$out"
    exit 1
  fi
  if ! rg -q "client bootstrap recovery integration check ok" "$out"; then
    echo "[bootstrap-recovery-matrix] profile=${name} missing success marker"
    cat "$out"
    exit 1
  fi
  echo "[bootstrap-recovery-matrix] profile=${name} ok"
}

run_profile base \
  DIR_PORT=8481 \
  ISSUER_PORT=8482 \
  ENTRY_PORT=8483 \
  EXIT_PORT=8484 \
  ENTRY_DATA_PORT=54820 \
  EXIT_DATA_PORT=54821 \
  INFRA_START_DELAY_SEC=2 \
  CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
  CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC=4 \
  CLIENT_BOOTSTRAP_JITTER_PCT=0 \
  SCRIPT_TIMEOUT_SEC=80

run_profile fast_retry \
  DIR_PORT=8491 \
  ISSUER_PORT=8492 \
  ENTRY_PORT=8493 \
  EXIT_PORT=8494 \
  ENTRY_DATA_PORT=54920 \
  EXIT_DATA_PORT=54921 \
  INFRA_START_DELAY_SEC=1 \
  CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
  CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC=2 \
  CLIENT_BOOTSTRAP_JITTER_PCT=10 \
  SCRIPT_TIMEOUT_SEC=80

run_profile longer_outage \
  DIR_PORT=8501 \
  ISSUER_PORT=8502 \
  ENTRY_PORT=8503 \
  EXIT_PORT=8504 \
  ENTRY_DATA_PORT=55020 \
  EXIT_DATA_PORT=55021 \
  INFRA_START_DELAY_SEC=4 \
  CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
  CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC=8 \
  CLIENT_BOOTSTRAP_JITTER_PCT=20 \
  SCRIPT_TIMEOUT_SEC=90

run_profile startup_sync_gate \
  DIR_PORT=8511 \
  ISSUER_PORT=8512 \
  ENTRY_PORT=8513 \
  EXIT_PORT=8514 \
  ENTRY_DATA_PORT=55120 \
  EXIT_DATA_PORT=55121 \
  INFRA_START_DELAY_SEC=2 \
  CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
  CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC=4 \
  CLIENT_BOOTSTRAP_JITTER_PCT=0 \
  CLIENT_STARTUP_SYNC_TIMEOUT_SEC=8 \
  EXPECT_INITIAL_FAILURE=0 \
  SCRIPT_TIMEOUT_SEC=90

echo "client bootstrap recovery matrix integration check ok"
