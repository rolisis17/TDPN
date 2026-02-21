#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

PORT_A=8097
PORT_B=8098
PORT_C=8099

DIRECTORY_ADDR="127.0.0.1:${PORT_A}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_A}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_a.key \
DIRECTORY_OPERATOR_ID=op-discovery-a \
ENTRY_RELAY_ID=entry-discovery-a \
EXIT_RELAY_ID=exit-discovery-a \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 40s go run ./cmd/node --directory >/tmp/discovery_a.log 2>&1 &
pid_a=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_B}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_B}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_b.key \
DIRECTORY_OPERATOR_ID=op-discovery-b \
ENTRY_RELAY_ID=entry-discovery-b \
EXIT_RELAY_ID=exit-discovery-b \
DIRECTORY_PEERS="http://127.0.0.1:${PORT_A}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 40s go run ./cmd/node --directory >/tmp/discovery_b.log 2>&1 &
pid_b=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_C}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_C}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_c.key \
DIRECTORY_OPERATOR_ID=op-discovery-c \
ENTRY_RELAY_ID=entry-discovery-c \
EXIT_RELAY_ID=exit-discovery-c \
DIRECTORY_PEERS="http://127.0.0.1:${PORT_B}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
DIRECTORY_PEER_DISCOVERY_MAX=16 \
timeout 40s go run ./cmd/node --directory >/tmp/discovery_c.log 2>&1 &
pid_c=$!

cleanup() {
  kill "$pid_a" "$pid_b" "$pid_c" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 3

peer_ok=0
for _ in $(seq 1 30); do
  peers=$(curl -fsS "http://127.0.0.1:${PORT_C}/v1/peers" || true)
  if echo "$peers" | rg -q "\"http://127.0.0.1:${PORT_A}\""; then
    peer_ok=1
    break
  fi
  sleep 0.3
done
if [[ "$peer_ok" -ne 1 ]]; then
  echo "expected directory C to discover directory A in /v1/peers feed"
  curl -sS "http://127.0.0.1:${PORT_C}/v1/peers" || true
  cat /tmp/discovery_a.log
  cat /tmp/discovery_b.log
  cat /tmp/discovery_c.log
  exit 1
fi

relay_ok=0
for _ in $(seq 1 40); do
  relays=$(curl -fsS "http://127.0.0.1:${PORT_C}/v1/relays" || true)
  if echo "$relays" | rg -q '"relay_id":"exit-discovery-a"'; then
    relay_ok=1
    break
  fi
  sleep 0.3
done
if [[ "$relay_ok" -ne 1 ]]; then
  echo "expected directory C to import relay from newly discovered peer A"
  curl -sS "http://127.0.0.1:${PORT_C}/v1/relays" || true
  cat /tmp/discovery_a.log
  cat /tmp/discovery_b.log
  cat /tmp/discovery_c.log
  exit 1
fi

echo "peer discovery integration check ok"
