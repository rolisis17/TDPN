#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

old_umask="$(umask)"
umask 077
TMP_DIR="$(mktemp -d /tmp/dir_auto_rotation.XXXXXX)"
DIR_KEY_FILE="$TMP_DIR/directory_ed25519.key"
DIR_PREV_FILE="$TMP_DIR/directory_previous_pubkeys.txt"
NODE_LOG="$TMP_DIR/node.log"
umask "$old_umask"
DIR_PORT="${DIR_AUTO_ROTATION_DIR_PORT:-18330}"
ISSUER_PORT="${DIR_AUTO_ROTATION_ISSUER_PORT:-18331}"
ENTRY_CTRL_PORT="${DIR_AUTO_ROTATION_ENTRY_CTRL_PORT:-18332}"
EXIT_CTRL_PORT="${DIR_AUTO_ROTATION_EXIT_CTRL_PORT:-18333}"
ENTRY_DATA_PORT="${DIR_AUTO_ROTATION_ENTRY_DATA_PORT:-53360}"
EXIT_DATA_PORT="${DIR_AUTO_ROTATION_EXIT_DATA_PORT:-53361}"

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
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_token_proof_replay.json" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/exit_token_proof_replay.json" \
DIRECTORY_KEY_ROTATE_SEC=2 \
DIRECTORY_KEY_HISTORY=2 \
DIRECTORY_ADMIN_TOKEN=dev-admin-token \
timeout 55s go run ./cmd/node --directory --issuer --entry --exit >"$NODE_LOG" 2>&1 &
node_pid=$!
cleanup() {
  kill "$node_pid" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

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
  cat "$NODE_LOG"
  exit 1
fi

prev_count=$(rg -vc '^\s*(#|$)' "$DIR_PREV_FILE" 2>/dev/null || true)
if [[ "$prev_count" -gt 2 ]]; then
  echo "expected previous pubkey history trimmed to 2"
  cat "$DIR_PREV_FILE"
  exit 1
fi

echo "directory auto key-rotation integration check ok"
