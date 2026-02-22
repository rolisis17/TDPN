#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

DIR_KEY_FILE=/tmp/dir_auto_rotation_ed25519.key
DIR_PREV_FILE=/tmp/dir_auto_rotation_previous_pubkeys.txt
DIR_PORT=8130
ISSUER_PORT=8131
ENTRY_CTRL_PORT=8132
EXIT_CTRL_PORT=8133
ENTRY_DATA_PORT=51960
EXIT_DATA_PORT=51961
rm -f "$DIR_KEY_FILE" "$DIR_PREV_FILE"

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ENTRY_ADDR="127.0.0.1:${ENTRY_CTRL_PORT}" \
EXIT_ADDR="127.0.0.1:${EXIT_CTRL_PORT}" \
DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ENTRY_URL="http://127.0.0.1:${ENTRY_CTRL_PORT}" \
EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_CTRL_PORT}" \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE="$DIR_KEY_FILE" \
DIRECTORY_PREVIOUS_PUBKEYS_FILE="$DIR_PREV_FILE" \
DIRECTORY_KEY_ROTATE_SEC=2 \
DIRECTORY_KEY_HISTORY=2 \
DIRECTORY_ADMIN_TOKEN=dev-admin-token \
timeout 55s go run ./cmd/node --directory --issuer --entry --exit >/tmp/dir_auto_rotation_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 3

rotated=0
for _ in $(seq 1 10); do
  sleep 1
  prev_count=$(rg -vc '^\s*(#|$)' "$DIR_PREV_FILE" 2>/dev/null || true)
  if [[ "$prev_count" -ge 1 ]]; then
    rotated=1
    break
  fi
done
if [[ "$rotated" -ne 1 ]]; then
  echo "expected automatic directory key rotation to append previous pubkeys"
  cat "$DIR_PREV_FILE" || true
  cat /tmp/dir_auto_rotation_node.log
  exit 1
fi

prev_count=$(rg -vc '^\s*(#|$)' "$DIR_PREV_FILE" 2>/dev/null || true)
if [[ "$prev_count" -gt 2 ]]; then
  echo "expected previous pubkey history trimmed to 2"
  cat "$DIR_PREV_FILE"
  exit 1
fi

echo "directory auto key-rotation integration check ok"
