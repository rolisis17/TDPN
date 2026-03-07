#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"
backup_mode_file=""

restore_mode_file() {
  if [[ -n "$backup_mode_file" && -f "$backup_mode_file" ]]; then
    cp "$backup_mode_file" "$MODE_FILE"
    rm -f "$backup_mode_file"
    return
  fi
  rm -f "$MODE_FILE"
}
trap restore_mode_file EXIT

mkdir -p "$ROOT_DIR/deploy/data"
if [[ -f "$MODE_FILE" ]]; then
  backup_mode_file="$(mktemp)"
  cp "$MODE_FILE" "$backup_mode_file"
fi

printf 'EASY_NODE_SERVER_MODE=provider\n' >"$MODE_FILE"
provider_out="$(./scripts/easy_node.sh invite-generate --count 1 2>&1 || true)"
if ! printf '%s\n' "$provider_out" | rg -q "allowed only on authority nodes"; then
  echo "expected provider mode to block invite-generate"
  echo "$provider_out"
  exit 1
fi

printf 'EASY_NODE_SERVER_MODE=authority\n' >"$MODE_FILE"
authority_out="$(./scripts/easy_node.sh invite-generate --count 1 --issuer-url http://127.0.0.1:1 --admin-token test 2>&1 || true)"
if printf '%s\n' "$authority_out" | rg -q "allowed only on authority nodes"; then
  echo "expected authority mode to pass role guard"
  echo "$authority_out"
  exit 1
fi

echo "easy-node role guard integration check ok"
