#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

PORT_SEED=8135
PORT_LOOSE=8136
PORT_STRICT=8137
PORT_DOWN=8138
DOWN_URL="http://127.0.0.1:${PORT_DOWN}"

DIRECTORY_ADDR="127.0.0.1:${PORT_SEED}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_SEED}" \
DIRECTORY_PRIVATE_KEY_FILE="data/discovery_hint_seed.key" \
DIRECTORY_OPERATOR_ID="op-discovery-hint-seed" \
ENTRY_RELAY_ID="entry-discovery-hint-seed" \
EXIT_RELAY_ID="exit-discovery-hint-seed" \
DIRECTORY_PEERS="${DOWN_URL}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_hint_seed.log 2>&1 &
seed_pid=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_LOOSE}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_LOOSE}" \
DIRECTORY_PRIVATE_KEY_FILE="data/discovery_hint_loose.key" \
DIRECTORY_OPERATOR_ID="op-discovery-hint-loose" \
ENTRY_RELAY_ID="entry-discovery-hint-loose" \
EXIT_RELAY_ID="exit-discovery-hint-loose" \
DIRECTORY_PEERS="http://127.0.0.1:${PORT_SEED}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=0 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_hint_loose.log 2>&1 &
loose_pid=$!

strict_pid=""
cleanup() {
  kill "${strict_pid:-}" "${loose_pid:-}" "${seed_pid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 3

loose_discovered=0
for _ in $(seq 1 40); do
  peers_loose="$(curl -fsS "http://127.0.0.1:${PORT_LOOSE}/v1/peers" || true)"
  if echo "$peers_loose" | rg -Fq "\"${DOWN_URL}\""; then
    loose_discovered=1
    break
  fi
  sleep 0.25
done
if [[ "${loose_discovered}" -ne 1 ]]; then
  echo "expected loose discovery mode to admit peer without signed hint metadata"
  curl -sS "http://127.0.0.1:${PORT_LOOSE}/v1/peers" || true
  cat /tmp/discovery_hint_seed.log
  cat /tmp/discovery_hint_loose.log
  exit 1
fi

kill "${loose_pid}" >/dev/null 2>&1 || true
unset loose_pid
sleep 1

DIRECTORY_ADDR="127.0.0.1:${PORT_STRICT}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_STRICT}" \
DIRECTORY_PRIVATE_KEY_FILE="data/discovery_hint_strict.key" \
DIRECTORY_OPERATOR_ID="op-discovery-hint-strict" \
ENTRY_RELAY_ID="entry-discovery-hint-strict" \
EXIT_RELAY_ID="exit-discovery-hint-strict" \
DIRECTORY_PEERS="http://127.0.0.1:${PORT_SEED}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_hint_strict.log 2>&1 &
strict_pid=$!

sleep 3

for _ in $(seq 1 40); do
  peers_strict="$(curl -fsS "http://127.0.0.1:${PORT_STRICT}/v1/peers" || true)"
  if echo "$peers_strict" | rg -Fq "\"${DOWN_URL}\""; then
    echo "expected strict discovery mode to block peer without signed hint metadata"
    echo "$peers_strict"
    cat /tmp/discovery_hint_seed.log
    cat /tmp/discovery_hint_strict.log
    exit 1
  fi
  sleep 0.25
done

echo "peer discovery require-hint integration check ok"
