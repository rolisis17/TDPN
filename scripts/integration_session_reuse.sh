#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

TMP_DIR="$(mktemp -d)"
LOG_FILE="$TMP_DIR/session_reuse.log"
TRUST_FILE="$TMP_DIR/directory_trust.txt"

DIR_PORT=19081
ISSUER_PORT=19082
ENTRY_PORT=19083
EXIT_PORT=19084
ENTRY_DATA_PORT=20080
EXIT_DATA_PORT=20081
EXIT_WG_PORT=20082

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  exit 1
fi

cleanup() {
  kill "${node_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
DIRECTORY_PRIVATE_KEY_FILE="$TMP_DIR/directory.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_replay.json" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ISSUER_URLS="http://127.0.0.1:${ISSUER_PORT}" \
CORE_ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ISSUER_PRIVATE_KEY_FILE="$TMP_DIR/issuer.key" \
ISSUER_SUBJECTS_FILE="$TMP_DIR/issuer_subjects.json" \
ISSUER_REVOCATIONS_FILE="$TMP_DIR/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$TMP_DIR/issuer_anon_revocations.json" \
ENTRY_ADDR="127.0.0.1:${ENTRY_PORT}" \
ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}" \
ENTRY_RELAY_ID=entry-local-1 \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_ADDR="127.0.0.1:${EXIT_PORT}" \
EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}" \
EXIT_RELAY_ID=exit-local-1 \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
EXIT_WG_LISTEN_PORT="${EXIT_WG_PORT}" \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/exit_token_replay.json" \
CLIENT_SESSION_REUSE=1 \
CLIENT_SESSION_REFRESH_LEAD_SEC=20 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=2 \
timeout 20s go run ./cmd/node --directory --issuer --entry --exit --client >"$LOG_FILE" 2>&1 &
node_pid=$!

selected_ok=0
for _ in $(seq 1 80); do
  if rg -q "client selected entry=" "$LOG_FILE"; then
    selected_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$selected_ok" -ne 1 ]]; then
  echo "expected initial client selection log"
  cat "$LOG_FILE"
  exit 1
fi

if ! rg -q "client keeping active session session=" "$LOG_FILE"; then
  echo "expected client to keep active session"
  cat "$LOG_FILE"
  exit 1
fi

reuse_ok=0
for _ in $(seq 1 80); do
  if rg -q "client reused active session session=" "$LOG_FILE"; then
    reuse_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$reuse_ok" -ne 1 ]]; then
  echo "expected active session reuse log on subsequent bootstrap cycles"
  cat "$LOG_FILE"
  exit 1
fi

echo "session reuse integration check ok"
