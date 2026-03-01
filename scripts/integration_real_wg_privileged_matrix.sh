#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this script requires Linux (wireguard kernel interface support)"
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: sudo ./scripts/integration_real_wg_privileged_matrix.sh"
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_profile() {
  local name="$1"
  shift
  local out="/tmp/integration_real_wg_matrix_${name}.log"
  rm -f "$out"
  echo "[real-wg-matrix] running profile=${name}"
  if ! env "$@" ./scripts/integration_real_wg_privileged.sh >"$out" 2>&1; then
    echo "[real-wg-matrix] profile=${name} failed"
    cat "$out"
    exit 1
  fi
  if ! rg -q "real wg privileged integration check ok" "$out"; then
    echo "[real-wg-matrix] profile=${name} missing success marker"
    cat "$out"
    exit 1
  fi
  echo "[real-wg-matrix] profile=${name} ok"
}

run_profile base \
  CLIENT_IFACE=wgcint0 \
  EXIT_IFACE=wgeint0 \
  CLIENT_PROXY_ADDR=127.0.0.1:57960 \
  ENTRY_DATA_ADDR=127.0.0.1:51980 \
  EXIT_DATA_ADDR=127.0.0.1:51981 \
  EXIT_WG_PORT=51982 \
  CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC=2 \
  SCRIPT_TIMEOUT_SEC=120

run_profile alt_ports \
  CLIENT_IFACE=wgcint1 \
  EXIT_IFACE=wgeint1 \
  CLIENT_PROXY_ADDR=127.0.0.1:57961 \
  ENTRY_DATA_ADDR=127.0.0.1:51990 \
  EXIT_DATA_ADDR=127.0.0.1:51991 \
  EXIT_WG_PORT=51992 \
  CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC=1 \
  SCRIPT_TIMEOUT_SEC=120

run_profile startup_race \
  CLIENT_IFACE=wgcint2 \
  EXIT_IFACE=wgeint2 \
  CLIENT_PROXY_ADDR=127.0.0.1:57962 \
  ENTRY_DATA_ADDR=127.0.0.1:52000 \
  EXIT_DATA_ADDR=127.0.0.1:52001 \
  EXIT_WG_PORT=52002 \
  CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC=0 \
  CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
  SCRIPT_TIMEOUT_SEC=140

run_profile strict_beta_roles \
  CLIENT_IFACE=wgcint3 \
  EXIT_IFACE=wgeint3 \
  CLIENT_PROXY_ADDR=127.0.0.1:57963 \
  ENTRY_DATA_ADDR=127.0.0.1:52010 \
  EXIT_DATA_ADDR=127.0.0.1:52011 \
  EXIT_WG_PORT=52012 \
  STRICT_BETA_PROFILE=1 \
  CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC=1 \
  CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
  CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC=2 \
  CLIENT_BOOTSTRAP_JITTER_PCT=0 \
  SCRIPT_TIMEOUT_SEC=150

echo "real wg privileged matrix integration check ok"
