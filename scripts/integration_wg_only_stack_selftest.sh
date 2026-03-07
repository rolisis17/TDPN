#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "wg-only stack selftest integration requires Linux"
  exit 2
fi
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "wg-only stack selftest integration requires root privileges"
  echo "re-run with sudo ./scripts/integration_wg_only_stack_selftest.sh"
  exit 2
fi

for cmd in docker go rg ip wg timeout curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing dependency for wg-only stack selftest integration: $cmd"
    exit 2
  fi
done

log_file="$(mktemp)"
state_file="$ROOT_DIR/deploy/data/wg_only_stack.state"
cleanup() {
  ./scripts/easy_node.sh wg-only-stack-down --force-iface-cleanup 1 >/dev/null 2>&1 || true
  rm -f "$log_file"
}
trap cleanup EXIT INT TERM

./scripts/easy_node.sh wg-only-stack-down --force-iface-cleanup 1 >/dev/null 2>&1 || true

if ! ./scripts/easy_node.sh wg-only-stack-selftest \
  --strict-beta 1 \
  --base-port 19280 \
  --timeout-sec 80 \
  --min-selection-lines 8 \
  --force-iface-reset 1 \
  --cleanup-ifaces 1 >"$log_file" 2>&1; then
  echo "wg-only stack selftest integration failed"
  cat "$log_file"
  exit 1
fi

if ! rg -q "wg-only stack selftest: ok" "$log_file"; then
  echo "missing expected wg-only stack selftest success signal"
  cat "$log_file"
  exit 1
fi

if [[ -f "$state_file" ]]; then
  echo "wg-only stack state file still present after selftest: $state_file"
  cat "$log_file"
  exit 1
fi

echo "wg-only stack selftest integration check ok"
