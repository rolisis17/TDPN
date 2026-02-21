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

ENTRY_OPEN_RPS="$ENTRY_OPEN_RPS" \
ENTRY_PUZZLE_DIFFICULTY="$ENTRY_PUZZLE_DIFFICULTY" \
ENTRY_BAN_THRESHOLD="$ENTRY_BAN_THRESHOLD" \
timeout 50s go run ./cmd/node --directory --issuer --entry --exit >/tmp/stress_bootstrap_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 3

rm -f /tmp/stress_client_*.log

seq "$CLIENTS" | xargs -P "$CONCURRENCY" -I{} sh -c '
  timeout 10s go run ./cmd/node --client >/tmp/stress_client_{}.log 2>&1 || true
'

success_count=$(rg -l 'client selected entry=' /tmp/stress_client_*.log 2>/dev/null | wc -l | tr -d ' ')
if [[ "$success_count" -lt "$MIN_SUCCESS" ]]; then
  echo "expected at least ${MIN_SUCCESS} successful client bootstraps, got ${success_count}/${CLIENTS}"
  cat /tmp/stress_bootstrap_node.log
  exit 1
fi

if rg -q 'panic:' /tmp/stress_bootstrap_node.log; then
  echo "unexpected panic in stress bootstrap run"
  cat /tmp/stress_bootstrap_node.log
  exit 1
fi

metrics=$(curl -sS http://127.0.0.1:8084/v1/metrics)
accepted=$(echo "$metrics" | sed -n 's/.*"accepted_packets":\([0-9][0-9]*\).*/\1/p')
if [[ -z "$accepted" || "$accepted" -le 0 ]]; then
  echo "expected accepted packet metrics after stress run"
  echo "$metrics"
  cat /tmp/stress_bootstrap_node.log
  exit 1
fi

echo "stress bootstrap integration check ok (success=${success_count}/${CLIENTS}, accepted_packets=${accepted})"

