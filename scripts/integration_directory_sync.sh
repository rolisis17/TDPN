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

BASE_PORT="${INTEGRATION_DIRECTORY_SYNC_BASE_PORT:-26580}"
MAIN_DIRECTORY_ADDR="${INTEGRATION_DIRECTORY_SYNC_MAIN_DIRECTORY_ADDR:-127.0.0.1:$((BASE_PORT + 1))}"
ISSUER_ADDR="${INTEGRATION_DIRECTORY_SYNC_ISSUER_ADDR:-127.0.0.1:$((BASE_PORT + 2))}"
ENTRY_ADDR="${INTEGRATION_DIRECTORY_SYNC_ENTRY_ADDR:-127.0.0.1:$((BASE_PORT + 3))}"
EXIT_ADDR="${INTEGRATION_DIRECTORY_SYNC_EXIT_ADDR:-127.0.0.1:$((BASE_PORT + 4))}"
PEER_DIRECTORY_ADDR="${INTEGRATION_DIRECTORY_SYNC_PEER_DIRECTORY_ADDR:-127.0.0.1:$((BASE_PORT + 5))}"
ENTRY_DATA_ADDR="${INTEGRATION_DIRECTORY_SYNC_ENTRY_DATA_ADDR:-127.0.0.1:$((BASE_PORT + 20))}"
EXIT_DATA_ADDR="${INTEGRATION_DIRECTORY_SYNC_EXIT_DATA_ADDR:-127.0.0.1:$((BASE_PORT + 21))}"
MAIN_DIRECTORY_URL="http://${MAIN_DIRECTORY_ADDR}"
PEER_DIRECTORY_URL="http://${PEER_DIRECTORY_ADDR}"
ISSUER_URL="http://${ISSUER_ADDR}"
ENTRY_URL="http://${ENTRY_ADDR}"
EXIT_URL="http://${EXIT_ADDR}"
NODE_TIMEOUT_SEC="${INTEGRATION_DIRECTORY_SYNC_NODE_TIMEOUT_SEC:-60}"

old_umask="$(umask)"
umask 077
tmp_dir="$(mktemp -d /tmp/integration_directory_sync.XXXXXX)"
umask "$old_umask"

core_log="$tmp_dir/dsync_core.log"
peer_log="$tmp_dir/dsync_peer.log"
main_log="$tmp_dir/dsync_main.log"
client_log="$tmp_dir/dsync_client.log"

cleanup() {
  kill "$core_pid" "$peer_pid" "$main_pid" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

wait_for_http_ready() {
  local url="$1"
  local label="$2"
  local pid="$3"
  local log_file="$4"
  local deadline=$((SECONDS + 25))
  while ((SECONDS < deadline)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "${label} exited before becoming ready"
      cat "$log_file"
      return 1
    fi
    sleep 0.2
  done
  echo "timed out waiting for ${label} (${url})"
  cat "$log_file"
  return 1
}

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  exit 1
fi

DIRECTORY_URL="$MAIN_DIRECTORY_URL" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$tmp_dir/core_trusted_directory_keys.txt" \
ISSUER_ADDR="$ISSUER_ADDR" \
ISSUER_PRIVATE_KEY_FILE="$tmp_dir/issuer.key" \
ISSUER_PREVIOUS_PUBKEYS_FILE="$tmp_dir/issuer_previous_pubkeys.txt" \
ISSUER_EPOCHS_FILE="$tmp_dir/issuer_epochs.json" \
ISSUER_REVOCATIONS_FILE="$tmp_dir/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$tmp_dir/issuer_anon_revocations.json" \
ENTRY_ADDR="$ENTRY_ADDR" \
ENTRY_URL="$ENTRY_URL" \
ENTRY_DATA_ADDR="$ENTRY_DATA_ADDR" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
ENTRY_RELAY_ID=entry-de-1 \
ENTRY_COUNTRY_CODE=DE \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_ADDR="$EXIT_ADDR" \
EXIT_CONTROL_URL="$EXIT_URL" \
EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
EXIT_RELAY_ID=exit-de-1 \
EXIT_COUNTRY_CODE=DE \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
ISSUER_URL="$ISSUER_URL" \
ISSUER_URLS="$ISSUER_URL" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/exit_token_replay.json" \
  timeout "${NODE_TIMEOUT_SEC}s" go run ./cmd/node --issuer --entry --exit >"$core_log" 2>&1 &
core_pid=$!

DIRECTORY_ADDR="$PEER_DIRECTORY_ADDR" \
DIRECTORY_PRIVATE_KEY_FILE="$tmp_dir/directory_peer.key" \
DIRECTORY_PREVIOUS_PUBKEYS_FILE="$tmp_dir/directory_peer_previous_pubkeys.txt" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/directory_peer_provider_replay.json" \
DIRECTORY_OPERATOR_ID=op-peer-de \
ENTRY_URL="$ENTRY_URL" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
ENTRY_RELAY_ID=entry-de-1 \
ENTRY_COUNTRY_CODE=DE \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_CONTROL_URL="$EXIT_URL" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
EXIT_RELAY_ID=exit-de-1 \
EXIT_COUNTRY_CODE=DE \
  timeout "${NODE_TIMEOUT_SEC}s" go run ./cmd/node --directory >"$peer_log" 2>&1 &
peer_pid=$!

DIRECTORY_ADDR="$MAIN_DIRECTORY_ADDR" \
DIRECTORY_PRIVATE_KEY_FILE="$tmp_dir/directory_main.key" \
DIRECTORY_PREVIOUS_PUBKEYS_FILE="$tmp_dir/directory_main_previous_pubkeys.txt" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/directory_main_provider_replay.json" \
DIRECTORY_OPERATOR_ID=op-main \
DIRECTORY_PEERS="$PEER_DIRECTORY_URL" \
DIRECTORY_PEER_TRUST_TOFU=1 \
DIRECTORY_PEER_TRUSTED_KEYS_FILE="$tmp_dir/directory_main_peer_trusted_keys.txt" \
DIRECTORY_SYNC_SEC=1 \
ENTRY_URL="$ENTRY_URL" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
ENTRY_RELAY_ID=entry-us-1 \
ENTRY_COUNTRY_CODE=US \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_CONTROL_URL="$EXIT_URL" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
EXIT_RELAY_ID=exit-us-1 \
EXIT_COUNTRY_CODE=US \
  timeout "${NODE_TIMEOUT_SEC}s" go run ./cmd/node --directory >"$main_log" 2>&1 &
main_pid=$!

wait_for_http_ready "$ISSUER_URL/v1/pubkeys" "issuer" "$core_pid" "$core_log"
wait_for_http_ready "$ENTRY_URL/v1/health" "entry" "$core_pid" "$core_log"
wait_for_http_ready "$EXIT_URL/v1/health" "exit" "$core_pid" "$core_log"
wait_for_http_ready "$PEER_DIRECTORY_URL/v1/pubkey" "peer directory" "$peer_pid" "$peer_log"
wait_for_http_ready "$MAIN_DIRECTORY_URL/v1/pubkey" "main directory" "$main_pid" "$main_log"

synced=0
for _ in $(seq 1 30); do
  if curl -fsS "$MAIN_DIRECTORY_URL/v1/relays" | rg -q '"relay_id":"exit-de-1"'; then
    synced=1
    break
  fi
  sleep 1
done

if [[ "$synced" != "1" ]]; then
  echo "expected synced peer relay in main directory output"
  cat "$main_log"
  cat "$peer_log"
  exit 1
fi

DIRECTORY_URL="$MAIN_DIRECTORY_URL" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$tmp_dir/client_trusted_directory_keys.txt" \
ISSUER_URL="$ISSUER_URL" \
ISSUER_URLS="$ISSUER_URL" \
CLIENT_EXIT_COUNTRY=DE \
CLIENT_EXIT_STRICT_LOCALITY=1 \
  timeout 20s go run ./cmd/node --client >"$client_log" 2>&1 || true

if ! rg -q 'client selected entry=' "$client_log"; then
  echo "expected client bootstrap through synced directory view"
  cat "$client_log"
  cat "$main_log"
  cat "$peer_log"
  cat "$core_log"
  exit 1
fi

if ! rg -q 'exit=exit-de-1' "$client_log"; then
  echo "expected strict DE locality to pick synced peer exit"
  cat "$client_log"
  exit 1
fi

echo "directory sync integration check ok"
