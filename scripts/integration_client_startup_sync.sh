#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in go curl rg timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

FAIL_LOG="/tmp/integration_client_startup_sync_fail.log"
CLIENT_LOG="/tmp/integration_client_startup_sync_client.log"
INFRA_LOG="/tmp/integration_client_startup_sync_infra.log"

DIR_PORT=18981
ISSUER_PORT=18982
ENTRY_PORT=18983
EXIT_PORT=18984
ENTRY_DATA_PORT=15980
EXIT_DATA_PORT=15981

DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}"
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}"
ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}"
EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}"

rm -f "$FAIL_LOG" "$CLIENT_LOG" "$INFRA_LOG"
TMP_DIR="$(mktemp -d)"
TRUST_FILE="$TMP_DIR/directory_trust.txt"
DIRECTORY_KEY_FILE="$TMP_DIR/directory.key"

directory_key_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
directory_private_key="$(echo "$directory_key_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
directory_pubkey="$(echo "$directory_key_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$directory_private_key" || -z "$directory_pubkey" || -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate startup sync key material"
  exit 1
fi
printf '%s\n' "$directory_private_key" >"$DIRECTORY_KEY_FILE"
printf '%s\n' "$directory_pubkey" >"$TRUST_FILE"
chmod 600 "$DIRECTORY_KEY_FILE"

cleanup() {
  kill "${client_pid:-}" >/dev/null 2>&1 || true
  kill "${infra_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if DIRECTORY_URL="$DIRECTORY_URL" \
  DIRECTORY_TRUST_TOFU=0 \
  DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
  ISSUER_URL="$ISSUER_URL" \
  ENTRY_URL="$ENTRY_URL" \
  EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
  CLIENT_STARTUP_SYNC_TIMEOUT_SEC=1 \
  timeout 15s go run ./cmd/node --client >"$FAIL_LOG" 2>&1; then
  echo "expected client startup sync timeout failure when control plane is unavailable"
  cat "$FAIL_LOG"
  exit 1
fi

if ! rg -q "client startup control-plane sync timeout" "$FAIL_LOG"; then
  echo "missing startup sync timeout signal in failure log"
  cat "$FAIL_LOG"
  exit 1
fi

DIRECTORY_URL="$DIRECTORY_URL" \
DIRECTORY_TRUST_TOFU=0 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
ISSUER_URL="$ISSUER_URL" \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
CLIENT_STARTUP_SYNC_TIMEOUT_SEC=8 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
timeout 35s go run ./cmd/node --client >"$CLIENT_LOG" 2>&1 &
client_pid=$!

sleep 1
if ! kill -0 "$client_pid" >/dev/null 2>&1; then
  echo "client process exited before infrastructure startup"
  cat "$CLIENT_LOG"
  exit 1
fi

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
DIRECTORY_PUBLIC_URL="$DIRECTORY_URL" \
DIRECTORY_PRIVATE_KEY_FILE="$DIRECTORY_KEY_FILE" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_replay.json" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_PRIVATE_KEY_FILE="$TMP_DIR/issuer.key" \
ISSUER_SUBJECTS_FILE="$TMP_DIR/issuer_subjects.json" \
ISSUER_REVOCATIONS_FILE="$TMP_DIR/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$TMP_DIR/issuer_anon_revocations.json" \
ENTRY_ADDR="127.0.0.1:${ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${EXIT_PORT}" \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_RELAY_ID=entry-local-1 \
EXIT_RELAY_ID=exit-local-1 \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
ENTRY_DIRECTORY_TRUST_TOFU=0 \
ENTRY_DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
EXIT_WG_LISTEN_PORT="$((EXIT_DATA_PORT + 10))" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/exit_token_replay.json" \
DIRECTORY_URL="$DIRECTORY_URL" \
ISSUER_URL="$ISSUER_URL" \
ISSUER_URLS="$ISSUER_URL" \
CORE_ISSUER_URL="$ISSUER_URL" \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
timeout 35s go run ./cmd/node --directory --issuer --entry --exit >"$INFRA_LOG" 2>&1 &
infra_pid=$!

selected=0
for _ in $(seq 1 180); do
  if rg -q "client selected entry=.* exit=.* token_exp=" "$CLIENT_LOG"; then
    selected=1
    break
  fi
  if ! kill -0 "$client_pid" >/dev/null 2>&1; then
    echo "client process exited before startup sync completed"
    cat "$CLIENT_LOG"
    cat "$INFRA_LOG"
    exit 1
  fi
  sleep 0.2
done

if [[ "$selected" -ne 1 ]]; then
  echo "client did not become ready after infrastructure startup"
  cat "$CLIENT_LOG"
  cat "$INFRA_LOG"
  exit 1
fi

if ! rg -q "client startup control-plane sync ready attempts=" "$CLIENT_LOG"; then
  echo "missing startup sync success signal"
  cat "$CLIENT_LOG"
  exit 1
fi

if rg -q "client bootstrap failed|client bootstrap retry failed" "$CLIENT_LOG"; then
  echo "unexpected bootstrap failures while startup sync gate was configured"
  cat "$CLIENT_LOG"
  cat "$INFRA_LOG"
  exit 1
fi

echo "client startup sync integration check ok"
