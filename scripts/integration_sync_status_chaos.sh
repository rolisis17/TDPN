#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

PORT_MAIN=8130
PORT_PEER=8131

DIRECTORY_ADDR="127.0.0.1:${PORT_MAIN}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_MAIN}" \
DIRECTORY_PRIVATE_KEY_FILE="data/sync_status_main.key" \
DIRECTORY_OPERATOR_ID="op-sync-main" \
DIRECTORY_PEERS="http://127.0.0.1:${PORT_PEER}" \
DIRECTORY_SYNC_SEC=1 \
timeout 90s go run ./cmd/node --directory >/tmp/sync_status_main.log 2>&1 &
main_pid=$!

peer_pid=""
cleanup() {
  kill "${peer_pid:-}" >/dev/null 2>&1 || true
  kill "${main_pid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 3

status_down="$(curl -fsS "http://127.0.0.1:${PORT_MAIN}/v1/admin/sync-status" -H 'X-Admin-Token: dev-admin-token' || true)"
if ! echo "$status_down" | rg -q '"peer":\{[^}]*"success":false'; then
  echo "expected sync status to report no successful peer sources while peer is down"
  echo "$status_down"
  cat /tmp/sync_status_main.log
  exit 1
fi
if ! echo "$status_down" | rg -q '"error":"'; then
  echo "expected sync status to carry failure reason while peer is down"
  echo "$status_down"
  cat /tmp/sync_status_main.log
  exit 1
fi

DIRECTORY_ADDR="127.0.0.1:${PORT_PEER}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_PEER}" \
DIRECTORY_PRIVATE_KEY_FILE="data/sync_status_peer.key" \
DIRECTORY_OPERATOR_ID="op-sync-peer" \
timeout 90s go run ./cmd/node --directory >/tmp/sync_status_peer.log 2>&1 &
peer_pid=$!

status_up=""
for _ in $(seq 1 40); do
  status_up="$(curl -fsS "http://127.0.0.1:${PORT_MAIN}/v1/admin/sync-status" -H 'X-Admin-Token: dev-admin-token' || true)"
  if echo "$status_up" | rg -q '"peer":\{[^}]*"success":true' && \
     echo "$status_up" | rg -q '"source_operators":\["op-sync-peer"\]' && \
     echo "$status_up" | rg -q '"success_sources":1' && \
     echo "$status_up" | rg -q '"quorum_met":true'; then
    break
  fi
  sleep 0.25
done
if ! echo "$status_up" | rg -q '"source_operators":\["op-sync-peer"\]'; then
  echo "expected sync status to track successful peer operator after recovery"
  echo "$status_up"
  cat /tmp/sync_status_main.log
  cat /tmp/sync_status_peer.log
  exit 1
fi

kill "${peer_pid:-}" >/dev/null 2>&1 || true
unset peer_pid

status_recover=""
for _ in $(seq 1 40); do
  status_recover="$(curl -fsS "http://127.0.0.1:${PORT_MAIN}/v1/admin/sync-status" -H 'X-Admin-Token: dev-admin-token' || true)"
  if echo "$status_recover" | rg -q '"peer":\{[^}]*"success":false' && echo "$status_recover" | rg -q '"error":"'; then
    break
  fi
  sleep 0.25
done
if ! echo "$status_recover" | rg -q '"peer":\{[^}]*"success":false'; then
  echo "expected sync status to return to no-success state after peer shutdown"
  echo "$status_recover"
  cat /tmp/sync_status_main.log
  exit 1
fi
if ! echo "$status_recover" | rg -q '"error":"'; then
  echo "expected sync status failure reason after peer shutdown"
  echo "$status_recover"
  cat /tmp/sync_status_main.log
  exit 1
fi

if rg -q 'panic:' /tmp/sync_status_main.log; then
  echo "unexpected panic in sync-status chaos main directory"
  cat /tmp/sync_status_main.log
  exit 1
fi

echo "sync-status chaos integration check ok"
