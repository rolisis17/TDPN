#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

timeout 25s go run ./cmd/node --issuer --entry --exit >/tmp/dsync_core.log 2>&1 &
core_pid=$!

DIRECTORY_ADDR=127.0.0.1:8085 \
DIRECTORY_PRIVATE_KEY_FILE=data/directory_peer.key \
DIRECTORY_OPERATOR_ID=op-peer-de \
ENTRY_RELAY_ID=entry-de-1 \
EXIT_RELAY_ID=exit-de-1 \
ENTRY_COUNTRY_CODE=DE \
EXIT_COUNTRY_CODE=DE \
timeout 25s go run ./cmd/node --directory >/tmp/dsync_peer.log 2>&1 &
peer_pid=$!

DIRECTORY_ADDR=127.0.0.1:8081 \
DIRECTORY_PRIVATE_KEY_FILE=data/directory_main.key \
DIRECTORY_OPERATOR_ID=op-main \
DIRECTORY_PEERS=http://127.0.0.1:8085 \
DIRECTORY_SYNC_SEC=1 \
ENTRY_RELAY_ID=entry-us-1 \
EXIT_RELAY_ID=exit-us-1 \
ENTRY_COUNTRY_CODE=US \
EXIT_COUNTRY_CODE=US \
timeout 25s go run ./cmd/node --directory >/tmp/dsync_main.log 2>&1 &
main_pid=$!

cleanup() {
  kill "$core_pid" "$peer_pid" "$main_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 4

if ! curl -sS http://127.0.0.1:8081/v1/relays | rg -q '"relay_id":"exit-de-1"'; then
  echo "expected synced peer relay in main directory output"
  cat /tmp/dsync_main.log
  cat /tmp/dsync_peer.log
  exit 1
fi

DIRECTORY_URL=http://127.0.0.1:8081 \
CLIENT_EXIT_COUNTRY=DE \
CLIENT_EXIT_STRICT_LOCALITY=1 \
timeout 10s go run ./cmd/node --client >/tmp/dsync_client.log 2>&1 || true

if ! rg -q 'client selected entry=' /tmp/dsync_client.log; then
  echo "expected client bootstrap through synced directory view"
  cat /tmp/dsync_client.log
  cat /tmp/dsync_main.log
  cat /tmp/dsync_peer.log
  cat /tmp/dsync_core.log
  exit 1
fi

if ! rg -q 'exit=exit-de-1' /tmp/dsync_client.log; then
  echo "expected strict DE locality to pick synced peer exit"
  cat /tmp/dsync_client.log
  exit 1
fi

echo "directory sync integration check ok"
