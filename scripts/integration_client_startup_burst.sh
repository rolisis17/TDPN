#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

DIR_PORT=8581
ISSUER_PORT=8582
ENTRY_PORT=8583
EXIT_PORT=8584
ENTRY_DATA_PORT=55820
EXIT_DATA_PORT=55821

CLIENTS="${CLIENTS:-12}"
CONCURRENCY="${CONCURRENCY:-6}"
MIN_SUCCESS="${MIN_SUCCESS:-10}"
CLIENT_BOOTSTRAP_INTERVAL_SEC="${CLIENT_BOOTSTRAP_INTERVAL_SEC:-1}"
CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC="${CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC:-4}"
CLIENT_BOOTSTRAP_JITTER_PCT="${CLIENT_BOOTSTRAP_JITTER_PCT:-30}"

INFRA_LOG=/tmp/client_startup_burst_infra.log
rm -f "$INFRA_LOG" /tmp/client_startup_burst_client_*.log

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ENTRY_ADDR="127.0.0.1:${ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${EXIT_PORT}" \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}" \
EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}" \
timeout 70s go run ./cmd/node --directory --issuer --entry --exit >"$INFRA_LOG" 2>&1 &
infra_pid=$!

cleanup() {
  kill "$infra_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ready=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${ENTRY_PORT}/v1/health" >/dev/null 2>&1 && \
    curl -fsS "http://127.0.0.1:${ISSUER_PORT}/v1/pubkey" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.25
done
if [[ "$ready" -ne 1 ]]; then
  echo "startup burst infrastructure did not become ready"
  cat "$INFRA_LOG"
  exit 1
fi

seq "$CLIENTS" | xargs -P "$CONCURRENCY" -I{} sh -c '
  DIRECTORY_URL="http://127.0.0.1:'"${DIR_PORT}"'" \
  ISSUER_URL="http://127.0.0.1:'"${ISSUER_PORT}"'" \
  ENTRY_URL="http://127.0.0.1:'"${ENTRY_PORT}"'" \
  EXIT_CONTROL_URL="http://127.0.0.1:'"${EXIT_PORT}"'" \
  CLIENT_BOOTSTRAP_INTERVAL_SEC="'"${CLIENT_BOOTSTRAP_INTERVAL_SEC}"'" \
  CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC="'"${CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC}"'" \
  CLIENT_BOOTSTRAP_JITTER_PCT="'"${CLIENT_BOOTSTRAP_JITTER_PCT}"'" \
  timeout 14s go run ./cmd/node --client >/tmp/client_startup_burst_client_{}.log 2>&1 || true
'

success_count=$(rg -l 'client selected entry=' /tmp/client_startup_burst_client_*.log 2>/dev/null | wc -l | tr -d ' ')
if [[ "$success_count" -lt "$MIN_SUCCESS" ]]; then
  echo "expected at least ${MIN_SUCCESS} successful client bootstraps, got ${success_count}/${CLIENTS}"
  cat "$INFRA_LOG"
  exit 1
fi

if rg -q 'panic:' "$INFRA_LOG" || rg -q 'panic:' /tmp/client_startup_burst_client_*.log 2>/dev/null; then
  echo "unexpected panic during client startup burst run"
  cat "$INFRA_LOG"
  exit 1
fi

metrics=$(curl -sS "http://127.0.0.1:${EXIT_PORT}/v1/metrics")
accepted=$(echo "$metrics" | sed -n 's/.*"accepted_packets":\([0-9][0-9]*\).*/\1/p')
if [[ -z "$accepted" || "$accepted" -lt "$MIN_SUCCESS" ]]; then
  echo "expected accepted_packets >= ${MIN_SUCCESS} after startup burst"
  echo "$metrics"
  cat "$INFRA_LOG"
  exit 1
fi

echo "client startup burst integration check ok (success=${success_count}/${CLIENTS}, accepted_packets=${accepted})"
