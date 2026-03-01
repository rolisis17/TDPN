#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

PORT_A=8140
PORT_X=8141
PORT_D=8142
PORT_B=8143
PORT_C=8144

URL_A="http://127.0.0.1:${PORT_A}"
URL_X="http://127.0.0.1:${PORT_X}"
URL_D="http://127.0.0.1:${PORT_D}"
URL_B="http://127.0.0.1:${PORT_B}"
URL_C="http://127.0.0.1:${PORT_C}"

cleanup() {
  kill "${pid_a:-}" "${pid_x:-}" "${pid_d:-}" "${pid_b:-}" "${pid_c:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

DIRECTORY_ADDR="127.0.0.1:${PORT_A}" \
DIRECTORY_PUBLIC_URL="${URL_A}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_op_cap_a.key \
DIRECTORY_OPERATOR_ID=op-discovery-shared \
ENTRY_RELAY_ID=entry-discovery-opcap-a \
EXIT_RELAY_ID=exit-discovery-opcap-a \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_op_cap_a.log 2>&1 &
pid_a=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_X}" \
DIRECTORY_PUBLIC_URL="${URL_X}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_op_cap_x.key \
DIRECTORY_OPERATOR_ID=op-discovery-shared \
ENTRY_RELAY_ID=entry-discovery-opcap-x \
EXIT_RELAY_ID=exit-discovery-opcap-x \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_op_cap_x.log 2>&1 &
pid_x=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_D}" \
DIRECTORY_PUBLIC_URL="${URL_D}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_op_cap_d.key \
DIRECTORY_OPERATOR_ID=op-discovery-other \
ENTRY_RELAY_ID=entry-discovery-opcap-d \
EXIT_RELAY_ID=exit-discovery-opcap-d \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_op_cap_d.log 2>&1 &
pid_d=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_B}" \
DIRECTORY_PUBLIC_URL="${URL_B}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_op_cap_b.key \
DIRECTORY_OPERATOR_ID=op-discovery-seed \
ENTRY_RELAY_ID=entry-discovery-opcap-b \
EXIT_RELAY_ID=exit-discovery-opcap-b \
DIRECTORY_PEERS="${URL_A},${URL_X},${URL_D}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_op_cap_b.log 2>&1 &
pid_b=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_C}" \
DIRECTORY_PUBLIC_URL="${URL_C}" \
DIRECTORY_PRIVATE_KEY_FILE=data/discovery_op_cap_c.key \
DIRECTORY_OPERATOR_ID=op-discovery-client \
ENTRY_RELAY_ID=entry-discovery-opcap-c \
EXIT_RELAY_ID=exit-discovery-opcap-c \
DIRECTORY_PEERS="${URL_B}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
DIRECTORY_PEER_DISCOVERY_MAX=16 \
DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR=1 \
DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1 \
timeout 90s go run ./cmd/node --directory >/tmp/discovery_op_cap_c.log 2>&1 &
pid_c=$!

sleep 4

discovery_ok=0
for _ in $(seq 1 70); do
  peers_c="$(curl -fsS "${URL_C}/v1/peers" || true)"
  has_a=0
  has_x=0
  has_d=0
  if echo "$peers_c" | rg -q "\"${URL_A}\""; then
    has_a=1
  fi
  if echo "$peers_c" | rg -q "\"${URL_X}\""; then
    has_x=1
  fi
  if echo "$peers_c" | rg -q "\"${URL_D}\""; then
    has_d=1
  fi
  if [[ "$has_a" -eq 1 && "$has_x" -eq 1 ]]; then
    echo "expected per-operator cap to prevent admitting both shared-operator peers"
    echo "$peers_c"
    cat /tmp/discovery_op_cap_b.log
    cat /tmp/discovery_op_cap_c.log
    exit 1
  fi
  if [[ "$has_d" -eq 1 && ( "$has_a" -eq 1 || "$has_x" -eq 1 ) ]]; then
    discovery_ok=1
    break
  fi
  sleep 0.25
done
if [[ "$discovery_ok" -ne 1 ]]; then
  echo "expected one shared-operator discovered peer plus one different-operator peer"
  curl -sS "${URL_C}/v1/peers" || true
  cat /tmp/discovery_op_cap_a.log
  cat /tmp/discovery_op_cap_x.log
  cat /tmp/discovery_op_cap_d.log
  cat /tmp/discovery_op_cap_b.log
  cat /tmp/discovery_op_cap_c.log
  exit 1
fi

echo "peer discovery operator-cap integration check ok"
