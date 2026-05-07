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

BASE_PORT="${INTEGRATION_FEDERATION_BASE_PORT:-26680}"
DIR_A_ADDR="${INTEGRATION_FEDERATION_DIR_A_ADDR:-127.0.0.1:$((BASE_PORT + 1))}"
ISSUER_ADDR="${INTEGRATION_FEDERATION_ISSUER_ADDR:-127.0.0.1:$((BASE_PORT + 2))}"
ENTRY_ADDR="${INTEGRATION_FEDERATION_ENTRY_ADDR:-127.0.0.1:$((BASE_PORT + 3))}"
EXIT_ADDR="${INTEGRATION_FEDERATION_EXIT_ADDR:-127.0.0.1:$((BASE_PORT + 4))}"
DIR_B_ADDR="${INTEGRATION_FEDERATION_DIR_B_ADDR:-127.0.0.1:$((BASE_PORT + 5))}"
ENTRY_DATA_ADDR="${INTEGRATION_FEDERATION_ENTRY_DATA_ADDR:-127.0.0.1:$((BASE_PORT + 20))}"
EXIT_DATA_ADDR="${INTEGRATION_FEDERATION_EXIT_DATA_ADDR:-127.0.0.1:$((BASE_PORT + 21))}"
DIR_A_URL="http://${DIR_A_ADDR}"
DIR_B_URL="http://${DIR_B_ADDR}"
ISSUER_URL="http://${ISSUER_ADDR}"
ENTRY_URL="http://${ENTRY_ADDR}"
EXIT_URL="http://${EXIT_ADDR}"
NODE_TIMEOUT_SEC="${INTEGRATION_FEDERATION_NODE_TIMEOUT_SEC:-60}"

old_umask="$(umask)"
umask 077
tmp_dir="$(mktemp -d /tmp/integration_federation.XXXXXX)"
umask "$old_umask"

core_log="$tmp_dir/federation_core.log"
dir_a_log="$tmp_dir/federation_dir_a.log"
dir_b_log="$tmp_dir/federation_dir_b.log"
client_log="$tmp_dir/federation_client.log"
client_trust_file="$tmp_dir/client_trusted_directory_keys.txt"

cleanup() {
  kill "$core_pid" "$dir_a_pid" "$dir_b_pid" >/dev/null 2>&1 || true
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

directory_pubkey() {
  local url="$1"
  curl -fsS "$url/v1/pubkey" | sed -n 's/.*"pub_key":"\([^"]*\)".*/\1/p'
}

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  exit 1
fi

DIRECTORY_URLS="$DIR_A_URL,$DIR_B_URL" \
ENTRY_DIRECTORY_TRUST_STRICT=0 \
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
ENTRY_RELAY_ID=entry-fed-1 \
ENTRY_OPERATOR_ID=op-fed-relay \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_ADDR="$EXIT_ADDR" \
EXIT_CONTROL_URL="$EXIT_URL" \
EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
EXIT_RELAY_ID=exit-fed-1 \
EXIT_OPERATOR_ID=op-fed-relay \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
ISSUER_URL="$ISSUER_URL" \
ISSUER_URLS="$ISSUER_URL" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/exit_token_replay.json" \
  timeout "${NODE_TIMEOUT_SEC}s" go run ./cmd/node --issuer --entry --exit >"$core_log" 2>&1 &
core_pid=$!

DIRECTORY_ADDR="$DIR_A_ADDR" \
DIRECTORY_PRIVATE_KEY_FILE="$tmp_dir/directory_a.key" \
DIRECTORY_PREVIOUS_PUBKEYS_FILE="$tmp_dir/directory_a_previous_pubkeys.txt" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/directory_a_provider_replay.json" \
DIRECTORY_OPERATOR_ID=op-fed-a \
ENTRY_URL="$ENTRY_URL" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
RELAY_PUBKEY="$route_assertion_pubkey" \
ENTRY_RELAY_ID=entry-fed-1 \
ENTRY_OPERATOR_ID=op-fed-relay \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_CONTROL_URL="$EXIT_URL" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
EXIT_RELAY_ID=exit-fed-1 \
EXIT_OPERATOR_ID=op-fed-relay \
  timeout "${NODE_TIMEOUT_SEC}s" go run ./cmd/node --directory >"$dir_a_log" 2>&1 &
dir_a_pid=$!

DIRECTORY_ADDR="$DIR_B_ADDR" \
DIRECTORY_PRIVATE_KEY_FILE="$tmp_dir/directory_b.key" \
DIRECTORY_PREVIOUS_PUBKEYS_FILE="$tmp_dir/directory_b_previous_pubkeys.txt" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/directory_b_provider_replay.json" \
DIRECTORY_OPERATOR_ID=op-fed-b \
ENTRY_URL="$ENTRY_URL" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
RELAY_PUBKEY="$route_assertion_pubkey" \
ENTRY_RELAY_ID=entry-fed-1 \
ENTRY_OPERATOR_ID=op-fed-relay \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_CONTROL_URL="$EXIT_URL" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
EXIT_RELAY_ID=exit-fed-1 \
EXIT_OPERATOR_ID=op-fed-relay \
  timeout "${NODE_TIMEOUT_SEC}s" go run ./cmd/node --directory >"$dir_b_log" 2>&1 &
dir_b_pid=$!

wait_for_http_ready "$ISSUER_URL/v1/pubkeys" "issuer" "$core_pid" "$core_log"
wait_for_http_ready "$ENTRY_URL/v1/health" "entry" "$core_pid" "$core_log"
wait_for_http_ready "$EXIT_URL/v1/health" "exit" "$core_pid" "$core_log"
wait_for_http_ready "$DIR_A_URL/v1/pubkey" "directory-a" "$dir_a_pid" "$dir_a_log"
wait_for_http_ready "$DIR_B_URL/v1/pubkey" "directory-b" "$dir_b_pid" "$dir_b_log"

: >"$client_trust_file"
directory_pubkey "$DIR_A_URL" >>"$client_trust_file"
directory_pubkey "$DIR_B_URL" >>"$client_trust_file"

DIRECTORY_URLS="$DIR_A_URL,$DIR_B_URL" \
DIRECTORY_TRUST_TOFU=0 \
DIRECTORY_TRUSTED_KEYS_FILE="$client_trust_file" \
DIRECTORY_MIN_SOURCES=2 \
DIRECTORY_MIN_OPERATORS=2 \
DIRECTORY_MIN_RELAY_VOTES=2 \
ISSUER_URL="$ISSUER_URL" \
ISSUER_URLS="$ISSUER_URL" \
  timeout 20s go run ./cmd/node --client >"$client_log" 2>&1 || true

if ! rg -q 'client selected entry=' "$client_log"; then
  echo "expected successful federated client bootstrap"
  cat "$client_log"
  cat "$core_log"
  cat "$dir_a_log"
  cat "$dir_b_log"
  exit 1
fi

echo "federation integration check ok"
