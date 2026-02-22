#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE=/tmp/session_reuse.log
rm -f "$LOG_FILE"

CLIENT_SESSION_REUSE=1 \
CLIENT_SESSION_REFRESH_LEAD_SEC=20 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=2 \
timeout 20s go run ./cmd/node --directory --issuer --entry --exit --client >"$LOG_FILE" 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

selected_ok=0
for _ in $(seq 1 80); do
  if rg -q "client selected entry=" "$LOG_FILE"; then
    selected_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$selected_ok" -ne 1 ]]; then
  echo "expected initial client selection log"
  cat "$LOG_FILE"
  exit 1
fi

if ! rg -q "client keeping active session session=" "$LOG_FILE"; then
  echo "expected client to keep active session"
  cat "$LOG_FILE"
  exit 1
fi

reuse_ok=0
for _ in $(seq 1 80); do
  if rg -q "client reused active session session=" "$LOG_FILE"; then
    reuse_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$reuse_ok" -ne 1 ]]; then
  echo "expected active session reuse log on subsequent bootstrap cycles"
  cat "$LOG_FILE"
  exit 1
fi

echo "session reuse integration check ok"
