#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

PORT_A=8110
PORT_B=8111
PORT_D=8112
PORT_C1=8113
PORT_C2=8114

DIRECTORY_ADDR="127.0.0.1:${PORT_A}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_A}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_q_a.key \
DIRECTORY_OPERATOR_ID=op-discovery-q-a \
ENTRY_RELAY_ID=entry-discovery-q-a \
EXIT_RELAY_ID=exit-discovery-q-a \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 70s go run ./cmd/node --directory >/tmp/discovery_q_a.log 2>&1 &
pid_a=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_B}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_B}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_q_b.key \
DIRECTORY_OPERATOR_ID=op-discovery-q-b \
ENTRY_RELAY_ID=entry-discovery-q-b \
EXIT_RELAY_ID=exit-discovery-q-b \
DIRECTORY_PEERS="http://127.0.0.1:${PORT_A}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 70s go run ./cmd/node --directory >/tmp/discovery_q_b.log 2>&1 &
pid_b=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_C1}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_C1}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_q_c1.key \
DIRECTORY_OPERATOR_ID=op-discovery-q-c1 \
ENTRY_RELAY_ID=entry-discovery-q-c1 \
EXIT_RELAY_ID=exit-discovery-q-c1 \
DIRECTORY_PEERS="http://127.0.0.1:${PORT_B}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
DIRECTORY_PEER_DISCOVERY_MIN_VOTES=2 \
timeout 70s go run ./cmd/node --directory >/tmp/discovery_q_c1.log 2>&1 &
pid_c1=$!

cleanup() {
  kill "${pid_a:-}" "${pid_b:-}" "${pid_d:-}" "${pid_c1:-}" "${pid_c2:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 3

for _ in $(seq 1 15); do
  peers_c1=$(curl -fsS "http://127.0.0.1:${PORT_C1}/v1/peers" || true)
  if echo "$peers_c1" | rg -q "\"http://127.0.0.1:${PORT_A}\""; then
    echo "expected discovery quorum to block single-source discovery of A on C1"
    echo "$peers_c1"
    cat /tmp/discovery_q_a.log
    cat /tmp/discovery_q_b.log
    cat /tmp/discovery_q_c1.log
    exit 1
  fi
  sleep 0.2
done

kill "$pid_c1" >/dev/null 2>&1 || true
unset pid_c1
sleep 1

DIRECTORY_ADDR="127.0.0.1:${PORT_D}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_D}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_q_d.key \
DIRECTORY_OPERATOR_ID=op-discovery-q-d \
ENTRY_RELAY_ID=entry-discovery-q-d \
EXIT_RELAY_ID=exit-discovery-q-d \
DIRECTORY_PEERS="http://127.0.0.1:${PORT_A}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 70s go run ./cmd/node --directory >/tmp/discovery_q_d.log 2>&1 &
pid_d=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_C2}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_C2}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_q_c2.key \
DIRECTORY_OPERATOR_ID=op-discovery-q-c2 \
ENTRY_RELAY_ID=entry-discovery-q-c2 \
EXIT_RELAY_ID=exit-discovery-q-c2 \
DIRECTORY_PEERS="http://127.0.0.1:${PORT_B},http://127.0.0.1:${PORT_D}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
DIRECTORY_PEER_DISCOVERY_MIN_VOTES=2 \
DIRECTORY_PEER_DISCOVERY_MAX=16 \
timeout 70s go run ./cmd/node --directory >/tmp/discovery_q_c2.log 2>&1 &
pid_c2=$!

sleep 3

peer_ok=0
for _ in $(seq 1 35); do
  peers_c2=$(curl -fsS "http://127.0.0.1:${PORT_C2}/v1/peers" || true)
  if echo "$peers_c2" | rg -q "\"http://127.0.0.1:${PORT_A}\""; then
    peer_ok=1
    break
  fi
  sleep 0.3
done
if [[ "$peer_ok" -ne 1 ]]; then
  echo "expected directory C2 to discover A after two-source quorum"
  curl -sS "http://127.0.0.1:${PORT_C2}/v1/peers" || true
  cat /tmp/discovery_q_a.log
  cat /tmp/discovery_q_b.log
  cat /tmp/discovery_q_d.log
  cat /tmp/discovery_q_c2.log
  exit 1
fi

relay_ok=0
for _ in $(seq 1 40); do
  relays_c2=$(curl -fsS "http://127.0.0.1:${PORT_C2}/v1/relays" || true)
  if echo "$relays_c2" | rg -q '"relay_id":"exit-discovery-q-a"'; then
    relay_ok=1
    break
  fi
  sleep 0.3
done
if [[ "$relay_ok" -ne 1 ]]; then
  echo "expected directory C2 to import relay from discovered peer A after quorum"
  curl -sS "http://127.0.0.1:${PORT_C2}/v1/relays" || true
  cat /tmp/discovery_q_a.log
  cat /tmp/discovery_q_b.log
  cat /tmp/discovery_q_d.log
  cat /tmp/discovery_q_c2.log
  exit 1
fi

echo "peer discovery quorum integration check ok"
