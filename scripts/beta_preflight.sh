#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in go rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

run_step() {
  local label="$1"
  shift
  echo "[beta-preflight] ${label}"
  "$@"
}

run_step "unit tests" go test ./...
run_step "directory strict governance" ./scripts/integration_directory_beta_strict.sh
run_step "cross-role strict guardrails" ./scripts/integration_beta_strict_roles.sh
run_step "distinct-operator anti-collusion" ./scripts/integration_distinct_operators.sh
run_step "peer discovery operator cap" ./scripts/integration_peer_discovery_operator_cap.sh
run_step "anonymous credential dispute" ./scripts/integration_anon_credential_dispute.sh
run_step "client bootstrap recovery matrix" ./scripts/integration_client_bootstrap_recovery_matrix.sh
run_step "client startup sync" ./scripts/integration_client_startup_sync.sh
run_step "beta fault matrix" ./scripts/integration_beta_fault_matrix.sh
run_step "strict live-wg full path" ./scripts/integration_live_wg_full_path_strict.sh
run_step "wg-only mode guardrails" ./scripts/integration_wg_only_mode.sh
run_step "load chaos matrix" ./scripts/integration_load_chaos_matrix.sh
run_step "lifecycle chaos matrix" ./scripts/integration_lifecycle_chaos_matrix.sh

if [[ "${BETA_PREFLIGHT_PRIVILEGED:-0}" == "1" ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[beta-preflight] privileged checks requested but not running as root"
    echo "[beta-preflight] re-run with sudo and BETA_PREFLIGHT_PRIVILEGED=1"
    exit 1
  fi
  run_step "real wireguard privileged matrix" ./scripts/integration_real_wg_privileged_matrix.sh
  if [[ "${BETA_PREFLIGHT_INCLUDE_WG_ONLY_STACK_SELFTEST:-0}" == "1" ]]; then
    run_step "wg-only stack lifecycle selftest" ./scripts/integration_wg_only_stack_selftest.sh
  fi
  if [[ "${BETA_PREFLIGHT_INCLUDE_STOP_ALL_WG_ONLY_CLEANUP:-0}" == "1" ]]; then
    run_step "stop-all wg-only cleanup" ./scripts/integration_stop_all_wg_only_cleanup.sh
  fi
fi

echo "[beta-preflight] ok"
