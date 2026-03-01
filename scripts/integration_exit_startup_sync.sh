#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in go curl rg timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

FAIL_LOG="/tmp/integration_exit_startup_sync_fail.log"
EXIT_LOG="/tmp/integration_exit_startup_sync_exit.log"
ISSUER_LOG="/tmp/integration_exit_startup_sync_issuer.log"

ISSUER_ADDR="127.0.0.1:18082"
EXIT_ADDR="127.0.0.1:18084"
EXIT_DATA_ADDR="127.0.0.1:15981"
ISSUER_URL="http://${ISSUER_ADDR}"
EXIT_HEALTH_URL="http://${EXIT_ADDR}/v1/health"

rm -f "$FAIL_LOG" "$EXIT_LOG" "$ISSUER_LOG"

cleanup() {
  kill "${exit_pid:-}" >/dev/null 2>&1 || true
  kill "${issuer_pid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if DATA_PLANE_MODE=opaque \
  WG_BACKEND=noop \
  EXIT_ADDR="$EXIT_ADDR" \
  EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
  ISSUER_URL="$ISSUER_URL" \
  ISSUER_REVOCATIONS_URL="${ISSUER_URL}/v1/revocations" \
  EXIT_STARTUP_SYNC_TIMEOUT_SEC=1 \
  timeout 15s go run ./cmd/node --exit >"$FAIL_LOG" 2>&1; then
  echo "expected exit startup sync timeout failure when issuer is unavailable"
  cat "$FAIL_LOG"
  exit 1
fi

if ! rg -q "exit startup issuer sync timeout" "$FAIL_LOG"; then
  echo "missing startup sync timeout signal in failure log"
  cat "$FAIL_LOG"
  exit 1
fi

DATA_PLANE_MODE=opaque \
WG_BACKEND=noop \
EXIT_ADDR="$EXIT_ADDR" \
EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
ISSUER_URL="$ISSUER_URL" \
ISSUER_REVOCATIONS_URL="${ISSUER_URL}/v1/revocations" \
EXIT_STARTUP_SYNC_TIMEOUT_SEC=8 \
timeout 35s go run ./cmd/node --exit >"$EXIT_LOG" 2>&1 &
exit_pid=$!

sleep 1
if ! kill -0 "$exit_pid" >/dev/null 2>&1; then
  echo "exit process exited before issuer startup"
  cat "$EXIT_LOG"
  exit 1
fi

if curl -fsS "$EXIT_HEALTH_URL" >/dev/null 2>&1; then
  echo "exit became healthy before issuer was available"
  cat "$EXIT_LOG"
  exit 1
fi

ISSUER_ADDR="$ISSUER_ADDR" \
timeout 35s go run ./cmd/node --issuer >"$ISSUER_LOG" 2>&1 &
issuer_pid=$!

ready=0
for _ in $(seq 1 150); do
  if curl -fsS "$EXIT_HEALTH_URL" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$exit_pid" >/dev/null 2>&1; then
    echo "exit process exited before startup sync completed"
    cat "$EXIT_LOG"
    cat "$ISSUER_LOG"
    exit 1
  fi
  sleep 0.2
done

if [[ "$ready" -ne 1 ]]; then
  echo "exit did not become healthy after issuer startup"
  cat "$EXIT_LOG"
  cat "$ISSUER_LOG"
  exit 1
fi

if ! rg -q "exit startup issuer sync ready attempts=" "$EXIT_LOG"; then
  echo "missing startup sync success signal"
  cat "$EXIT_LOG"
  exit 1
fi

echo "exit startup sync integration check ok"
