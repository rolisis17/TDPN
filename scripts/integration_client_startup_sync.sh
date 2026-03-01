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

FAIL_LOG="/tmp/integration_client_startup_sync_fail.log"
CLIENT_LOG="/tmp/integration_client_startup_sync_client.log"
INFRA_LOG="/tmp/integration_client_startup_sync_infra.log"

DIR_PORT=18981
ISSUER_PORT=18982
ENTRY_PORT=18983
EXIT_PORT=18984
ENTRY_DATA_PORT=15980
EXIT_DATA_PORT=15981

DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}"
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}"
ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}"
EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}"

rm -f "$FAIL_LOG" "$CLIENT_LOG" "$INFRA_LOG"

cleanup() {
  kill "${client_pid:-}" >/dev/null 2>&1 || true
  kill "${infra_pid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if DIRECTORY_URL="$DIRECTORY_URL" \
  ISSUER_URL="$ISSUER_URL" \
  ENTRY_URL="$ENTRY_URL" \
  EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
  CLIENT_STARTUP_SYNC_TIMEOUT_SEC=1 \
  timeout 15s go run ./cmd/node --client >"$FAIL_LOG" 2>&1; then
  echo "expected client startup sync timeout failure when control plane is unavailable"
  cat "$FAIL_LOG"
  exit 1
fi

if ! rg -q "client startup control-plane sync timeout" "$FAIL_LOG"; then
  echo "missing startup sync timeout signal in failure log"
  cat "$FAIL_LOG"
  exit 1
fi

DIRECTORY_URL="$DIRECTORY_URL" \
ISSUER_URL="$ISSUER_URL" \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
CLIENT_STARTUP_SYNC_TIMEOUT_SEC=8 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
timeout 35s go run ./cmd/node --client >"$CLIENT_LOG" 2>&1 &
client_pid=$!

sleep 1
if ! kill -0 "$client_pid" >/dev/null 2>&1; then
  echo "client process exited before infrastructure startup"
  cat "$CLIENT_LOG"
  exit 1
fi

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ENTRY_ADDR="127.0.0.1:${ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${EXIT_PORT}" \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
DIRECTORY_URL="$DIRECTORY_URL" \
ISSUER_URL="$ISSUER_URL" \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
timeout 35s go run ./cmd/node --directory --issuer --entry --exit >"$INFRA_LOG" 2>&1 &
infra_pid=$!

selected=0
for _ in $(seq 1 180); do
  if rg -q "client selected entry=.* exit=.* token_exp=" "$CLIENT_LOG"; then
    selected=1
    break
  fi
  if ! kill -0 "$client_pid" >/dev/null 2>&1; then
    echo "client process exited before startup sync completed"
    cat "$CLIENT_LOG"
    cat "$INFRA_LOG"
    exit 1
  fi
  sleep 0.2
done

if [[ "$selected" -ne 1 ]]; then
  echo "client did not become ready after infrastructure startup"
  cat "$CLIENT_LOG"
  cat "$INFRA_LOG"
  exit 1
fi

if ! rg -q "client startup control-plane sync ready attempts=" "$CLIENT_LOG"; then
  echo "missing startup sync success signal"
  cat "$CLIENT_LOG"
  exit 1
fi

if rg -q "client bootstrap failed|client bootstrap retry failed" "$CLIENT_LOG"; then
  echo "unexpected bootstrap failures while startup sync gate was configured"
  cat "$CLIENT_LOG"
  cat "$INFRA_LOG"
  exit 1
fi

echo "client startup sync integration check ok"
