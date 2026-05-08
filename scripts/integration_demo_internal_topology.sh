#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in mktemp rg timeout go; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

LOG_FILE="$(mktemp "${TMPDIR:-/tmp}/integration_demo_internal_topology.XXXXXX.log")"
trap 'rm -f "$LOG_FILE"' EXIT

set +e
DEMO_DURATION_SEC="${DEMO_DURATION_SEC:-8}" ./scripts/demo_internal_topology.sh >"$LOG_FILE" 2>&1
demo_rc=$?
set -e

if [[ "$demo_rc" -ne 124 && "$demo_rc" -ne 137 ]]; then
  echo "internal topology demo returned unexpected exit code: $demo_rc"
  cat "$LOG_FILE"
  exit "$demo_rc"
fi
if rg -q "route assertion incomplete|directory key is not trusted" "$LOG_FILE"; then
  echo "internal topology demo hit route assertion or trust-state setup failure"
  cat "$LOG_FILE"
  exit 1
fi
if ! rg -q "exit accepted opaque packet" "$LOG_FILE"; then
  echo "internal topology demo missing expected packet acceptance log"
  cat "$LOG_FILE"
  exit 1
fi
if ! rg -q "wgiotap packets=" "$LOG_FILE"; then
  echo "internal topology demo missing expected tap stats log"
  cat "$LOG_FILE"
  exit 1
fi
if ! rg -q "(client downlink opaque packets|client forwarded opaque udp packets count=)" "$LOG_FILE"; then
  echo "internal topology demo missing expected client relay/downlink log"
  cat "$LOG_FILE"
  exit 1
fi

echo "internal topology demo integration check ok"
