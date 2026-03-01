#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_profile() {
  local name="$1"
  shift
  local out="/tmp/integration_load_chaos_matrix_${name}.log"
  rm -f "$out"
  echo "[load-chaos-matrix] running profile=${name}"
  if ! env "$@" ./scripts/integration_load_chaos.sh >"$out" 2>&1; then
    echo "[load-chaos-matrix] profile=${name} failed"
    cat "$out"
    exit 1
  fi
  if ! rg -q "load/chaos integration check ok" "$out"; then
    echo "[load-chaos-matrix] profile=${name} missing success marker"
    cat "$out"
    exit 1
  fi
  echo "[load-chaos-matrix] profile=${name} ok"
}

run_profile base \
  LOAD_CHAOS_TAG=base \
  MAIN_DIR_PORT=8781 \
  PEER_DIR_PORT=8785 \
  CORE_ISSUER_PORT=8782 \
  CORE_ENTRY_PORT=8783 \
  CORE_EXIT_PORT=8784 \
  ENTRY_DATA_PORT=57820 \
  EXIT_DATA_PORT=57821 \
  ENTRY_OPEN_RPS=2 \
  ENTRY_PUZZLE_DIFFICULTY=1 \
  ENTRY_BAN_THRESHOLD=2 \
  ENTRY_BAN_SEC=6 \
  LOAD_OPEN_REQUESTS=12 \
  LOAD_OPEN_PARALLEL=6

run_profile high_pressure \
  LOAD_CHAOS_TAG=high_pressure \
  MAIN_DIR_PORT=8791 \
  PEER_DIR_PORT=8795 \
  CORE_ISSUER_PORT=8792 \
  CORE_ENTRY_PORT=8793 \
  CORE_EXIT_PORT=8794 \
  ENTRY_DATA_PORT=57920 \
  EXIT_DATA_PORT=57921 \
  ENTRY_OPEN_RPS=1 \
  ENTRY_PUZZLE_DIFFICULTY=2 \
  ENTRY_BAN_THRESHOLD=2 \
  ENTRY_BAN_SEC=8 \
  LOAD_OPEN_REQUESTS=16 \
  LOAD_OPEN_PARALLEL=8

run_profile milder_limits \
  LOAD_CHAOS_TAG=milder_limits \
  MAIN_DIR_PORT=8801 \
  PEER_DIR_PORT=8805 \
  CORE_ISSUER_PORT=8802 \
  CORE_ENTRY_PORT=8803 \
  CORE_EXIT_PORT=8804 \
  ENTRY_DATA_PORT=58020 \
  EXIT_DATA_PORT=58021 \
  ENTRY_OPEN_RPS=3 \
  ENTRY_PUZZLE_DIFFICULTY=1 \
  ENTRY_BAN_THRESHOLD=3 \
  ENTRY_BAN_SEC=5 \
  LOAD_OPEN_REQUESTS=10 \
  LOAD_OPEN_PARALLEL=5

echo "load/chaos matrix integration check ok"
