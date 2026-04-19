#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

old_umask="$(umask)"
umask 077
TRUST_FILE="$(mktemp /tmp/dir_rotation_trusted_keys.XXXXXX.txt)"
DIR_KEY_FILE="$(mktemp /tmp/dir_rotation_ed25519.XXXXXX.key)"
DIR_PREV_FILE="$(mktemp /tmp/dir_rotation_previous_pubkeys.XXXXXX.txt)"
NODE_LOG="$(mktemp /tmp/dir_rotation_node.XXXXXX.log)"
CLIENT_LOG="$(mktemp /tmp/dir_rotation_client.XXXXXX.log)"
ROTATE_RESP_FILE="$(mktemp /tmp/dir_rotation_rotate.XXXXXX.json)"
umask "$old_umask"
DIR_PORT=8120
ISSUER_PORT=8121
ENTRY_CTRL_PORT=8122
EXIT_CTRL_PORT=8123
ENTRY_DATA_PORT=51950
EXIT_DATA_PORT=51951

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
DIRECTORY_ADMIN_TOKEN=dev-admin-token \
timeout 30s go run ./cmd/node --directory --issuer --entry --exit >"$NODE_LOG" 2>&1 &
node_pid=$!
cleanup() {
  kill "$node_pid" >/dev/null 2>&1 || true
  rm -f \
    "$TRUST_FILE" \
    "$DIR_KEY_FILE" \
    "$DIR_PREV_FILE" \
    "$NODE_LOG" \
    "$CLIENT_LOG" \
    "$ROTATE_RESP_FILE"
}
trap cleanup EXIT

sleep 3

run_strict_client() {
  DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
  ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
  ENTRY_URL="http://127.0.0.1:${ENTRY_CTRL_PORT}" \
  EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_CTRL_PORT}" \
  DIRECTORY_TRUST_STRICT=1 \
  DIRECTORY_TRUST_TOFU=1 \
  DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
  timeout 10s go run ./cmd/node --client >"$CLIENT_LOG" 2>&1 || true
}

run_strict_client
if ! rg -q 'client selected entry=' "$CLIENT_LOG"; then
  echo "expected initial strict-trust bootstrap success"
  cat "$CLIENT_LOG"
  cat "$NODE_LOG"
  exit 1
fi

before_count=$(wc -l < "$TRUST_FILE" | tr -d ' ')

curl -sS -X POST "http://127.0.0.1:${DIR_PORT}/v1/admin/rotate-key" \
  -H 'X-Admin-Token: dev-admin-token' >"$ROTATE_RESP_FILE"

sleep 2

run_strict_client
if ! rg -q 'client selected entry=' "$CLIENT_LOG"; then
  echo "expected strict-trust bootstrap success after directory key rotation"
  cat "$CLIENT_LOG"
  cat "$NODE_LOG"
  exit 1
fi

after_count=$(wc -l < "$TRUST_FILE" | tr -d ' ')
if [[ "$after_count" -le "$before_count" ]]; then
  echo "expected trust file to auto-pin rotated key"
  echo "before=$before_count after=$after_count"
  cat "$TRUST_FILE"
  exit 1
fi

echo "directory key-rotation integration check ok"
