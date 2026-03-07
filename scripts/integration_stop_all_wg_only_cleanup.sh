#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "stop-all wg-only cleanup integration requires Linux"
  exit 2
fi
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "stop-all wg-only cleanup integration requires root privileges"
  echo "re-run with sudo ./scripts/integration_stop_all_wg_only_cleanup.sh"
  exit 2
fi

for cmd in docker go rg ip wg timeout curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing dependency for stop-all wg-only cleanup integration: $cmd"
    exit 2
  fi
done

state_file="$ROOT_DIR/deploy/data/wg_only_stack.state"
client_iface="wgcstackstop0"
exit_iface="wgestackstop0"
log_file="$(mktemp)"
cleanup() {
  ./scripts/easy_node.sh wg-only-stack-down --force-iface-cleanup 1 >/dev/null 2>&1 || true
  rm -f "$log_file"
}
trap cleanup EXIT INT TERM

./scripts/easy_node.sh wg-only-stack-down --force-iface-cleanup 1 >/dev/null 2>&1 || true

./scripts/easy_node.sh wg-only-stack-up \
  --strict-beta 1 \
  --detach 1 \
  --base-port 19380 \
  --client-iface "$client_iface" \
  --exit-iface "$exit_iface" \
  --force-iface-reset 1 \
  --cleanup-ifaces 1 >/dev/null

if ! ./scripts/easy_node.sh wg-only-stack-status | rg -q 'running: 1'; then
  echo "expected wg-only stack to be running before stop-all"
  ./scripts/easy_node.sh wg-only-stack-status || true
  exit 1
fi

if ! ./scripts/easy_node.sh stop-all --with-wg-only 1 --force-iface-cleanup 1 >"$log_file" 2>&1; then
  echo "stop-all failed during wg-only cleanup integration"
  cat "$log_file"
  exit 1
fi

if [[ -f "$state_file" ]]; then
  echo "wg-only state file still present after stop-all: $state_file"
  cat "$log_file"
  exit 1
fi
if ip link show dev "$client_iface" >/dev/null 2>&1; then
  echo "client interface still present after stop-all: $client_iface"
  cat "$log_file"
  exit 1
fi
if ip link show dev "$exit_iface" >/dev/null 2>&1; then
  echo "exit interface still present after stop-all: $exit_iface"
  cat "$log_file"
  exit 1
fi

if ! rg -q "wg-only stack cleanup: done|all local Privacynode docker resources are stopped" "$log_file"; then
  echo "missing expected stop-all cleanup log signals"
  cat "$log_file"
  exit 1
fi

echo "stop-all wg-only cleanup integration check ok"
