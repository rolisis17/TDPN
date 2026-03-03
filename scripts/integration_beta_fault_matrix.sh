#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in bash rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

run_profile() {
  local name="$1"
  local success_marker="$2"
  shift 2
  local out="/tmp/integration_beta_fault_matrix_${name}.log"
  rm -f "$out"
  echo "[beta-fault-matrix] running profile=${name}"
  if ! "$@" >"$out" 2>&1; then
    echo "[beta-fault-matrix] profile=${name} failed"
    cat "$out"
    exit 1
  fi
  if ! rg -q "$success_marker" "$out"; then
    echo "[beta-fault-matrix] profile=${name} missing success marker"
    cat "$out"
    exit 1
  fi
  echo "[beta-fault-matrix] profile=${name} ok"
}

run_profile startup_race_client_sync \
  "client startup sync integration check ok" \
  ./scripts/integration_client_startup_sync.sh

run_profile startup_race_exit_sync \
  "exit startup sync integration check ok" \
  ./scripts/integration_exit_startup_sync.sh

run_profile sync_loss_recovery_client_bootstrap \
  "client bootstrap recovery matrix integration check ok" \
  ./scripts/integration_client_bootstrap_recovery_matrix.sh

run_profile sync_loss_recovery_directory_status \
  "sync-status chaos integration check ok" \
  ./scripts/integration_sync_status_chaos.sh

echo "beta fault matrix integration check ok"
