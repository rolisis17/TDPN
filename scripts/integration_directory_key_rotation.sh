#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

old_umask="$(umask)"
umask 077
TMP_DIR="$(mktemp -d /tmp/dir_rotation.XXXXXX)"
TRUST_FILE="$TMP_DIR/trusted_keys.txt"
DIR_KEY_FILE="$TMP_DIR/directory_ed25519.key"
DIR_PREV_FILE="$TMP_DIR/directory_previous_pubkeys.txt"
NODE_LOG="$TMP_DIR/node.log"
CLIENT_LOG="$TMP_DIR/client.log"
ROTATE_RESP_FILE="$TMP_DIR/rotate.json"
umask "$old_umask"
DIR_PORT="${DIR_KEY_ROTATION_DIR_PORT:-18320}"
ISSUER_PORT="${DIR_KEY_ROTATION_ISSUER_PORT:-18321}"
ENTRY_CTRL_PORT="${DIR_KEY_ROTATION_ENTRY_CTRL_PORT:-18322}"
EXIT_CTRL_PORT="${DIR_KEY_ROTATION_EXIT_CTRL_PORT:-18323}"
ENTRY_DATA_PORT="${DIR_KEY_ROTATION_ENTRY_DATA_PORT:-53350}"
EXIT_DATA_PORT="${DIR_KEY_ROTATION_EXIT_DATA_PORT:-53351}"
route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion keypair"
  exit 1
fi

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
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE="$DIR_KEY_FILE" \
DIRECTORY_PREVIOUS_PUBKEYS_FILE="$DIR_PREV_FILE" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_token_proof_replay.json" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/exit_token_proof_replay.json" \
ENTRY_DIRECTORY_TRUST_STRICT=1 \
ENTRY_DIRECTORY_TRUST_TOFU=1 \
ENTRY_DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
ENTRY_RELAY_ID=entry-local-1 \
EXIT_RELAY_ID=exit-local-1 \
DIRECTORY_ADMIN_TOKEN=dev-admin-token \
timeout 30s go run ./cmd/node --directory --issuer --entry --exit >"$NODE_LOG" 2>&1 &
node_pid=$!
cleanup() {
  kill "$node_pid" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
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
rotated_pub="$(sed -n 's/.*"pub_key":"\([^"]*\)".*/\1/p' "$ROTATE_RESP_FILE")"
if [[ -z "$rotated_pub" ]]; then
  echo "expected rotate-key response to include rotated pub_key"
  cat "$ROTATE_RESP_FILE"
  exit 1
fi
printf '%s\n' "$rotated_pub" >>"$TRUST_FILE"

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
  echo "expected trust file to include rotated key"
  echo "before=$before_count after=$after_count"
  cat "$TRUST_FILE"
  exit 1
fi

echo "directory key-rotation integration check ok"
