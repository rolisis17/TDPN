#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

PORT_A=8130
PORT_X=8131
PORT_B=8132
PORT_D=8133
PORT_C1=8134
PORT_C2=8135

URL_A="http://127.0.0.1:${PORT_A}"
URL_X="http://127.0.0.1:${PORT_X}"
URL_B="http://127.0.0.1:${PORT_B}"
URL_D="http://127.0.0.1:${PORT_D}"
URL_C1="http://127.0.0.1:${PORT_C1}"
URL_C2="http://127.0.0.1:${PORT_C2}"

cleanup() {
  kill "${pid_a:-}" "${pid_x:-}" "${pid_b:-}" "${pid_d:-}" "${pid_c1:-}" "${pid_c2:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

DIRECTORY_ADDR="127.0.0.1:${PORT_A}" \
DIRECTORY_PUBLIC_URL="${URL_A}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_cap_a.key \
DIRECTORY_OPERATOR_ID=op-discovery-cap-a \
ENTRY_RELAY_ID=entry-discovery-cap-a \
EXIT_RELAY_ID=exit-discovery-cap-a \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_cap_a.log 2>&1 &
pid_a=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_X}" \
DIRECTORY_PUBLIC_URL="${URL_X}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_cap_x.key \
DIRECTORY_OPERATOR_ID=op-discovery-cap-x \
ENTRY_RELAY_ID=entry-discovery-cap-x \
EXIT_RELAY_ID=exit-discovery-cap-x \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_cap_x.log 2>&1 &
pid_x=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_B}" \
DIRECTORY_PUBLIC_URL="${URL_B}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_cap_b.key \
DIRECTORY_OPERATOR_ID=op-discovery-cap-b \
ENTRY_RELAY_ID=entry-discovery-cap-b \
EXIT_RELAY_ID=exit-discovery-cap-b \
DIRECTORY_PEERS="${URL_A},${URL_X}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_cap_b.log 2>&1 &
pid_b=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_C1}" \
DIRECTORY_PUBLIC_URL="${URL_C1}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_cap_c1.key \
DIRECTORY_OPERATOR_ID=op-discovery-cap-c1 \
ENTRY_RELAY_ID=entry-discovery-cap-c1 \
EXIT_RELAY_ID=exit-discovery-cap-c1 \
DIRECTORY_PEERS="${URL_B}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE=1 \
DIRECTORY_PEER_DISCOVERY_MAX=16 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_cap_c1.log 2>&1 &
pid_c1=$!

sleep 4

single_source_ok=0
for _ in $(seq 1 50); do
  peers_c1="$(curl -fsS "${URL_C1}/v1/peers" || true)"
  has_a=0
  has_x=0
  if echo "$peers_c1" | rg -q "\"${URL_A}\""; then
    has_a=1
  fi
  if echo "$peers_c1" | rg -q "\"${URL_X}\""; then
    has_x=1
  fi
  if [[ "$has_a" -eq 1 && "$has_x" -eq 1 ]]; then
    echo "expected per-source cap to prevent one source from admitting both discovered peers"
    echo "$peers_c1"
    cat /tmp/discovery_cap_b.log
    cat /tmp/discovery_cap_c1.log
    exit 1
  fi
  if [[ "$has_a" -eq 1 || "$has_x" -eq 1 ]]; then
    single_source_ok=1
    break
  fi
  sleep 0.25
done
if [[ "$single_source_ok" -ne 1 ]]; then
  echo "expected capped source to admit one discovered peer on C1"
  curl -sS "${URL_C1}/v1/peers" || true
  cat /tmp/discovery_cap_a.log
  cat /tmp/discovery_cap_x.log
  cat /tmp/discovery_cap_b.log
  cat /tmp/discovery_cap_c1.log
  exit 1
fi

kill "$pid_c1" >/dev/null 2>&1 || true
unset pid_c1
sleep 1

DIRECTORY_ADDR="127.0.0.1:${PORT_D}" \
DIRECTORY_PUBLIC_URL="${URL_D}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_cap_d.key \
DIRECTORY_OPERATOR_ID=op-discovery-cap-d \
ENTRY_RELAY_ID=entry-discovery-cap-d \
EXIT_RELAY_ID=exit-discovery-cap-d \
DIRECTORY_PEERS="${URL_X}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_cap_d.log 2>&1 &
pid_d=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_C2}" \
DIRECTORY_PUBLIC_URL="${URL_C2}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_cap_c2.key \
DIRECTORY_OPERATOR_ID=op-discovery-cap-c2 \
ENTRY_RELAY_ID=entry-discovery-cap-c2 \
EXIT_RELAY_ID=exit-discovery-cap-c2 \
DIRECTORY_PEERS="${URL_B},${URL_D}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE=1 \
DIRECTORY_PEER_DISCOVERY_MAX=16 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_cap_c2.log 2>&1 &
pid_c2=$!

sleep 4

both_sources_ok=0
for _ in $(seq 1 60); do
  peers_c2="$(curl -fsS "${URL_C2}/v1/peers" || true)"
  if echo "$peers_c2" | rg -q "\"${URL_A}\"" && echo "$peers_c2" | rg -q "\"${URL_X}\""; then
    both_sources_ok=1
    break
  fi
  sleep 0.25
done
if [[ "$both_sources_ok" -ne 1 ]]; then
  echo "expected C2 to discover both peers when they come from different source operators"
  curl -sS "${URL_C2}/v1/peers" || true
  cat /tmp/discovery_cap_a.log
  cat /tmp/discovery_cap_x.log
  cat /tmp/discovery_cap_b.log
  cat /tmp/discovery_cap_d.log
  cat /tmp/discovery_cap_c2.log
  exit 1
fi

relay_ok=0
for _ in $(seq 1 70); do
  relays_c2="$(curl -fsS "${URL_C2}/v1/relays" || true)"
  if echo "$relays_c2" | rg -q '"relay_id":"exit-discovery-cap-a"' &&
     echo "$relays_c2" | rg -q '"relay_id":"exit-discovery-cap-x"'; then
    relay_ok=1
    break
  fi
  sleep 0.25
done
if [[ "$relay_ok" -ne 1 ]]; then
  echo "expected C2 relay import from both discovered peers after per-source capped discovery"
  curl -sS "${URL_C2}/v1/relays" || true
  cat /tmp/discovery_cap_a.log
  cat /tmp/discovery_cap_x.log
  cat /tmp/discovery_cap_b.log
  cat /tmp/discovery_cap_d.log
  cat /tmp/discovery_cap_c2.log
  exit 1
fi

echo "peer discovery source-cap integration check ok"
