#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

ADMIN_TOKEN="scale-admin-token"

PORT_A=8461
PORT_B=8462
PORT_C=8463
PORT_TX=8464
PORT_TY=8465
PORT_MAIN=8466

URL_A="http://127.0.0.1:${PORT_A}"
URL_B="http://127.0.0.1:${PORT_B}"
URL_C="http://127.0.0.1:${PORT_C}"
URL_TX="http://127.0.0.1:${PORT_TX}"
URL_TY="http://127.0.0.1:${PORT_TY}"
URL_MAIN="http://127.0.0.1:${PORT_MAIN}"

cleanup() {
  kill "${pid_a:-}" "${pid_b:-}" "${pid_c:-}" "${pid_tx:-}" "${pid_ty:-}" "${pid_main:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

DIRECTORY_ADDR="127.0.0.1:${PORT_A}" \
DIRECTORY_PUBLIC_URL="${URL_A}" \
DIRECTORY_PRIVATE_KEY_FILE=data/scale_dir_a.key \
DIRECTORY_OPERATOR_ID=op-scale-a \
ENTRY_RELAY_ID=entry-scale-a \
EXIT_RELAY_ID=exit-scale-a \
timeout 120s go run ./cmd/node --directory >/tmp/scale_dir_a.log 2>&1 &
pid_a=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_B}" \
DIRECTORY_PUBLIC_URL="${URL_B}" \
DIRECTORY_PRIVATE_KEY_FILE=data/scale_dir_b.key \
DIRECTORY_OPERATOR_ID=op-scale-b \
ENTRY_RELAY_ID=entry-scale-b \
EXIT_RELAY_ID=exit-scale-b \
timeout 120s go run ./cmd/node --directory >/tmp/scale_dir_b.log 2>&1 &
pid_b=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_C}" \
DIRECTORY_PUBLIC_URL="${URL_C}" \
DIRECTORY_PRIVATE_KEY_FILE=data/scale_dir_c.key \
DIRECTORY_OPERATOR_ID=op-scale-c \
ENTRY_RELAY_ID=entry-scale-c \
EXIT_RELAY_ID=exit-scale-c \
timeout 120s go run ./cmd/node --directory >/tmp/scale_dir_c.log 2>&1 &
pid_c=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_TX}" \
DIRECTORY_PUBLIC_URL="${URL_TX}" \
DIRECTORY_PRIVATE_KEY_FILE=data/scale_dir_tx.key \
DIRECTORY_OPERATOR_ID=op-scale-transit-x \
ENTRY_RELAY_ID=entry-scale-tx \
EXIT_RELAY_ID=exit-scale-tx \
DIRECTORY_PEERS="${URL_A},${URL_B},${URL_C}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 120s go run ./cmd/node --directory >/tmp/scale_dir_tx.log 2>&1 &
pid_tx=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_TY}" \
DIRECTORY_PUBLIC_URL="${URL_TY}" \
DIRECTORY_PRIVATE_KEY_FILE=data/scale_dir_ty.key \
DIRECTORY_OPERATOR_ID=op-scale-transit-y \
ENTRY_RELAY_ID=entry-scale-ty \
EXIT_RELAY_ID=exit-scale-ty \
DIRECTORY_PEERS="${URL_A},${URL_B},${URL_C}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 120s go run ./cmd/node --directory >/tmp/scale_dir_ty.log 2>&1 &
pid_ty=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_MAIN}" \
DIRECTORY_PUBLIC_URL="${URL_MAIN}" \
DIRECTORY_PRIVATE_KEY_FILE=data/scale_dir_main.key \
DIRECTORY_OPERATOR_ID=op-scale-main \
ENTRY_RELAY_ID=entry-scale-main \
EXIT_RELAY_ID=exit-scale-main \
DIRECTORY_PEERS="${URL_TX},${URL_TY}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_MIN_OPERATORS=2 \
DIRECTORY_PEER_DISCOVERY=1 \
DIRECTORY_PEER_DISCOVERY_MIN_VOTES=2 \
DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1 \
DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE=2 \
DIRECTORY_ADMIN_TOKEN="${ADMIN_TOKEN}" \
timeout 120s go run ./cmd/node --directory >/tmp/scale_dir_main.log 2>&1 &
pid_main=$!

sleep 4

relays_ready=0
for _ in $(seq 1 80); do
  relays="$(curl -fsS "${URL_MAIN}/v1/relays" || true)"
  if echo "$relays" | rg -q '"relay_id":"exit-scale-a"' && \
     echo "$relays" | rg -q '"relay_id":"exit-scale-b"' && \
     echo "$relays" | rg -q '"relay_id":"exit-scale-c"'; then
    relays_ready=1
    break
  fi
  sleep 0.25
done
if [[ "$relays_ready" -ne 1 ]]; then
  echo "expected main directory to import exit relays from three seed operators"
  curl -sS "${URL_MAIN}/v1/relays" || true
  cat /tmp/scale_dir_main.log
  cat /tmp/scale_dir_tx.log
  cat /tmp/scale_dir_ty.log
  exit 1
fi

status_up=""
for _ in $(seq 1 60); do
  status_up="$(curl -fsS "${URL_MAIN}/v1/admin/sync-status" -H "X-Admin-Token: ${ADMIN_TOKEN}" || true)"
  if echo "$status_up" | rg -q '"peer":\{[^}]*"success":true' && \
     echo "$status_up" | rg -q '"peer":\{[^}]*"required_operators":2' && \
     echo "$status_up" | rg -q '"peer":\{[^}]*"quorum_met":true' && \
     echo "$status_up" | rg -q 'op-scale-transit-x' && \
     echo "$status_up" | rg -q 'op-scale-transit-y'; then
    break
  fi
  sleep 0.25
done
if ! echo "$status_up" | rg -q '"peer":\{[^}]*"quorum_met":true'; then
  echo "expected main directory peer sync quorum up-state with two transit operators"
  echo "$status_up"
  cat /tmp/scale_dir_main.log
  exit 1
fi

kill "${pid_tx:-}" >/dev/null 2>&1 || true
unset pid_tx

status_down=""
for _ in $(seq 1 80); do
  status_down="$(curl -fsS "${URL_MAIN}/v1/admin/sync-status" -H "X-Admin-Token: ${ADMIN_TOKEN}" || true)"
  if echo "$status_down" | rg -q '"peer":\{[^}]*"success":false' && \
     echo "$status_down" | rg -q '"peer":\{[^}]*"required_operators":2' && \
     echo "$status_down" | rg -q '"peer":\{[^}]*"quorum_met":false'; then
    break
  fi
  sleep 0.25
done
if ! echo "$status_down" | rg -q '"peer":\{[^}]*"quorum_met":false'; then
  echo "expected peer quorum drop after transit-x shutdown"
  echo "$status_down"
  cat /tmp/scale_dir_main.log
  cat /tmp/scale_dir_ty.log
  exit 1
fi

continuity_relays="$(curl -fsS "${URL_MAIN}/v1/relays" || true)"
if ! echo "$continuity_relays" | rg -q '"relay_id":"exit-scale-a"' && \
   ! echo "$continuity_relays" | rg -q '"relay_id":"exit-scale-b"' && \
   ! echo "$continuity_relays" | rg -q '"relay_id":"exit-scale-c"'; then
  echo "expected cached relay continuity while one transit source is down"
  echo "$continuity_relays"
  cat /tmp/scale_dir_main.log
  exit 1
fi

DIRECTORY_ADDR="127.0.0.1:${PORT_TX}" \
DIRECTORY_PUBLIC_URL="${URL_TX}" \
DIRECTORY_PRIVATE_KEY_FILE=data/scale_dir_tx.key \
DIRECTORY_OPERATOR_ID=op-scale-transit-x \
ENTRY_RELAY_ID=entry-scale-tx \
EXIT_RELAY_ID=exit-scale-tx \
DIRECTORY_PEERS="${URL_A},${URL_B},${URL_C}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 120s go run ./cmd/node --directory >/tmp/scale_dir_tx_restart.log 2>&1 &
pid_tx=$!

status_recovered=""
for _ in $(seq 1 80); do
  status_recovered="$(curl -fsS "${URL_MAIN}/v1/admin/sync-status" -H "X-Admin-Token: ${ADMIN_TOKEN}" || true)"
  if echo "$status_recovered" | rg -q '"peer":\{[^}]*"success":true' && \
     echo "$status_recovered" | rg -q '"peer":\{[^}]*"quorum_met":true' && \
     echo "$status_recovered" | rg -q 'op-scale-transit-x' && \
     echo "$status_recovered" | rg -q 'op-scale-transit-y'; then
    break
  fi
  sleep 0.25
done
if ! echo "$status_recovered" | rg -q '"peer":\{[^}]*"quorum_met":true'; then
  echo "expected peer quorum recovery after transit-x restart"
  echo "$status_recovered"
  cat /tmp/scale_dir_main.log
  cat /tmp/scale_dir_tx_restart.log
  cat /tmp/scale_dir_ty.log
  exit 1
fi

kill "${pid_c:-}" >/dev/null 2>&1 || true
unset pid_c

degraded_relays_ok=0
for _ in $(seq 1 80); do
  degraded_relays="$(curl -fsS "${URL_MAIN}/v1/relays" || true)"
  if echo "$degraded_relays" | rg -q '"relay_id":"exit-scale-a"' && \
     echo "$degraded_relays" | rg -q '"relay_id":"exit-scale-b"'; then
    degraded_relays_ok=1
    break
  fi
  sleep 0.25
done
if [[ "$degraded_relays_ok" -ne 1 ]]; then
  echo "expected main directory to keep at least two seed exits under seed-c loss"
  curl -sS "${URL_MAIN}/v1/relays" || true
  cat /tmp/scale_dir_main.log
  cat /tmp/scale_dir_tx_restart.log
  cat /tmp/scale_dir_ty.log
  exit 1
fi

if rg -q 'panic:' /tmp/scale_dir_main.log; then
  echo "unexpected panic in main directory during churn scale test"
  cat /tmp/scale_dir_main.log
  exit 1
fi

echo "directory operator churn-scale integration check ok"
