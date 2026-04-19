#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

CLIENTS="${CLIENTS:-24}"
CONCURRENCY="${CONCURRENCY:-8}"
MIN_SUCCESS="${MIN_SUCCESS:-12}"

ENTRY_OPEN_RPS="${ENTRY_OPEN_RPS:-250}"
ENTRY_PUZZLE_DIFFICULTY="${ENTRY_PUZZLE_DIFFICULTY:-0}"
ENTRY_BAN_THRESHOLD="${ENTRY_BAN_THRESHOLD:-8}"

require_uint() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an unsigned integer (got: $value)"
    exit 2
  fi
}

for var_name in CLIENTS CONCURRENCY MIN_SUCCESS ENTRY_OPEN_RPS ENTRY_PUZZLE_DIFFICULTY ENTRY_BAN_THRESHOLD; do
  require_uint "$var_name" "${!var_name}"
done

old_umask="$(umask)"
umask 077
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stress_bootstrap.XXXXXX")"
umask "$old_umask"
NODE_LOG="$TMP_DIR/node.log"
export TMP_DIR

ENTRY_OPEN_RPS="$ENTRY_OPEN_RPS" \
ENTRY_PUZZLE_DIFFICULTY="$ENTRY_PUZZLE_DIFFICULTY" \
ENTRY_BAN_THRESHOLD="$ENTRY_BAN_THRESHOLD" \
timeout 50s go run ./cmd/node --directory --issuer --entry --exit >"$NODE_LOG" 2>&1 &
node_pid=$!
trap 'kill "$node_pid" >/dev/null 2>&1 || true; rm -rf "$TMP_DIR"' EXIT

sleep 3

run_client_bootstrap_once() {
  local client_idx="$1"
  timeout 10s go run ./cmd/node --client >"${TMP_DIR}/client_${client_idx}.log" 2>&1 || true
}

active_jobs=0
for client_idx in $(seq "$CLIENTS"); do
  run_client_bootstrap_once "$client_idx" &
  active_jobs=$((active_jobs + 1))
  if (( active_jobs >= CONCURRENCY )); then
    wait -n || true
    active_jobs=$((active_jobs - 1))
  fi
done
wait || true

success_count=$(rg -l 'client selected entry=' "$TMP_DIR"/client_*.log 2>/dev/null | wc -l | tr -d ' ')
if [[ "$success_count" -lt "$MIN_SUCCESS" ]]; then
  echo "expected at least ${MIN_SUCCESS} successful client bootstraps, got ${success_count}/${CLIENTS}"
  cat "$NODE_LOG"
  exit 1
fi

if rg -q 'panic:' "$NODE_LOG"; then
  echo "unexpected panic in stress bootstrap run"
  cat "$NODE_LOG"
  exit 1
fi

metrics=$(curl -sS http://127.0.0.1:8084/v1/metrics)
accepted=$(echo "$metrics" | sed -n 's/.*"accepted_packets":\([0-9][0-9]*\).*/\1/p')
if [[ -z "$accepted" || "$accepted" -le 0 ]]; then
  echo "expected accepted packet metrics after stress run"
  echo "$metrics"
  cat "$NODE_LOG"
  exit 1
fi

echo "stress bootstrap integration check ok (success=${success_count}/${CLIENTS}, accepted_packets=${accepted})"
