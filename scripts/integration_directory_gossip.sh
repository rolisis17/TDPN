#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

SENDER_PORT=8095
RECV_PORT=8096

DIRECTORY_ADDR="127.0.0.1:${SENDER_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE=data/gossip_sender.key \
DIRECTORY_OPERATOR_ID=op-gossip-sender \
ENTRY_RELAY_ID=entry-gossip-src \
EXIT_RELAY_ID=exit-gossip-src \
ENTRY_COUNTRY_CODE=DE \
EXIT_COUNTRY_CODE=DE \
timeout 35s go run ./cmd/node --directory >/tmp/gossip_sender.log 2>&1 &
sender_pid=$!

DIRECTORY_ADDR="127.0.0.1:${RECV_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE=data/gossip_recv.key \
DIRECTORY_OPERATOR_ID=op-gossip-recv \
DIRECTORY_PEERS="http://127.0.0.1:${SENDER_PORT}" \
DIRECTORY_SYNC_SEC=60 \
timeout 35s go run ./cmd/node --directory >/tmp/gossip_recv.log 2>&1 &
recv_pid=$!

cleanup() {
  kill "$sender_pid" "$recv_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 2

curl -fsS "http://127.0.0.1:${SENDER_PORT}/v1/relays" >/tmp/gossip_sender_relays.json
one_line=$(tr -d '\n' </tmp/gossip_sender_relays.json)
relays_array=$(echo "$one_line" | sed -n 's/^{"relays":\(\[.*\]\)}$/\1/p')
if [[ -z "$relays_array" ]]; then
  echo "failed to parse sender relays payload"
  cat /tmp/gossip_sender_relays.json
  cat /tmp/gossip_sender.log
  exit 1
fi

payload=$(cat <<JSON
{"peer_url":"http://127.0.0.1:${SENDER_PORT}","relays":${relays_array}}
JSON
)

resp=$(curl -fsS -X POST "http://127.0.0.1:${RECV_PORT}/v1/gossip/relays" \
  -H 'Content-Type: application/json' \
  --data "$payload")

if ! echo "$resp" | rg -q '"imported":[1-9]'; then
  echo "expected gossip import count > 0"
  echo "$resp"
  cat /tmp/gossip_recv.log
  exit 1
fi

recv_relays=$(curl -fsS "http://127.0.0.1:${RECV_PORT}/v1/relays")
if ! echo "$recv_relays" | rg -q '"relay_id":"exit-gossip-src"'; then
  echo "expected receiver to publish gossiped exit relay"
  echo "$recv_relays"
  cat /tmp/gossip_recv.log
  exit 1
fi

echo "directory gossip integration check ok"
