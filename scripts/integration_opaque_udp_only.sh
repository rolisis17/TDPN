#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

DATA_PLANE_MODE=opaque \
timeout 45s go run ./cmd/node --directory --issuer --entry --exit >/tmp/opaque_udp_only_node.log 2>&1 &
node_pid=$!

inject_pid=""
cleanup() {
  kill "${inject_pid:-}" >/dev/null 2>&1 || true
  kill "${node_pid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 2

(
  while true; do
    printf '\x01\x00\x00\x00udp-only-test' > /dev/udp/127.0.0.1/51900 || true
    sleep 0.05
  done
) >/dev/null 2>&1 &
inject_pid=$!

DATA_PLANE_MODE=opaque \
CLIENT_INNER_SOURCE=udp \
CLIENT_DISABLE_SYNTHETIC_FALLBACK=1 \
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS=2500 \
timeout 10s go run ./cmd/node --client >/tmp/opaque_udp_only_client_ok.log 2>&1 || true

kill "${inject_pid:-}" >/dev/null 2>&1 || true
unset inject_pid

if ! rg -q 'client selected entry=' /tmp/opaque_udp_only_client_ok.log; then
  echo "expected client bootstrap success with UDP-only opaque source"
  cat /tmp/opaque_udp_only_client_ok.log
  cat /tmp/opaque_udp_only_node.log
  exit 1
fi
if ! rg -q 'client forwarded opaque udp packets count=' /tmp/opaque_udp_only_client_ok.log; then
  echo "expected UDP opaque packets to be forwarded"
  cat /tmp/opaque_udp_only_client_ok.log
  cat /tmp/opaque_udp_only_node.log
  exit 1
fi

DATA_PLANE_MODE=opaque \
CLIENT_INNER_SOURCE=synthetic \
CLIENT_DISABLE_SYNTHETIC_FALLBACK=1 \
timeout 8s go run ./cmd/node --client >/tmp/opaque_udp_only_client_fail.log 2>&1 || true

if ! rg -q 'CLIENT_INNER_SOURCE=udp required when synthetic fallback is disabled' /tmp/opaque_udp_only_client_fail.log; then
  echo "expected strict UDP-source validation failure when synthetic source is configured"
  cat /tmp/opaque_udp_only_client_fail.log
  cat /tmp/opaque_udp_only_node.log
  exit 1
fi

echo "opaque udp-only integration check ok"
