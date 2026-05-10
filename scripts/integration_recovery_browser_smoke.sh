#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in go; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "recovery browser smoke failed: missing required command: $cmd"
    exit 2
  fi
done

if command -v node >/dev/null 2>&1; then
  NODE_BIN="node"
elif command -v node.exe >/dev/null 2>&1; then
  NODE_BIN="node.exe"
else
  echo "recovery browser smoke failed: missing required command: node/node.exe"
  exit 2
fi

"$NODE_BIN" --check scripts/integration_recovery_browser_smoke.js
"$NODE_BIN" scripts/integration_recovery_browser_smoke.js

echo "recovery browser smoke integration check ok"
