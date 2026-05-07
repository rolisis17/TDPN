#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

EXIT_REPUTATION_SCORE="${EXIT_REPUTATION_SCORE:-0.9}"
EXIT_UPTIME_SCORE="${EXIT_UPTIME_SCORE:-0.85}"
EXIT_CAPACITY_SCORE="${EXIT_CAPACITY_SCORE:-0.8}"
EXIT_ABUSE_PENALTY="${EXIT_ABUSE_PENALTY:-0.1}"
BASE_PORT="${INTEGRATION_SELECTION_FEED_BASE_PORT:-23480}"
DIRECTORY_ADDR="${INTEGRATION_SELECTION_FEED_DIRECTORY_ADDR:-127.0.0.1:$((BASE_PORT + 1))}"
ISSUER_ADDR="${INTEGRATION_SELECTION_FEED_ISSUER_ADDR:-127.0.0.1:$((BASE_PORT + 2))}"
ENTRY_ADDR="${INTEGRATION_SELECTION_FEED_ENTRY_ADDR:-127.0.0.1:$((BASE_PORT + 3))}"
EXIT_ADDR="${INTEGRATION_SELECTION_FEED_EXIT_ADDR:-127.0.0.1:$((BASE_PORT + 4))}"
ENTRY_DATA_ADDR="${INTEGRATION_SELECTION_FEED_ENTRY_DATA_ADDR:-127.0.0.1:$((BASE_PORT + 20))}"
EXIT_DATA_ADDR="${INTEGRATION_SELECTION_FEED_EXIT_DATA_ADDR:-127.0.0.1:$((BASE_PORT + 21))}"
DIRECTORY_URL="http://${DIRECTORY_ADDR}"
ISSUER_URL="http://${ISSUER_ADDR}"
ENTRY_URL="http://${ENTRY_ADDR}"
EXIT_URL="http://${EXIT_ADDR}"

old_umask="$(umask)"
umask 077
tmp_dir="$(mktemp -d /tmp/integration_selection_feed.XXXXXX)"
umask "$old_umask"
node_log="$tmp_dir/selection_feed_node.log"
client_log="$tmp_dir/selection_feed_client.log"

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  exit 1
fi

wait_for_http_ready() {
  local url="$1"
  local label="$2"
  local deadline=$((SECONDS + 20))
  while ((SECONDS < deadline)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$node_pid" >/dev/null 2>&1; then
      echo "node exited before ${label} became ready"
      cat "$node_log"
      return 1
    fi
    sleep 0.2
  done
  echo "timed out waiting for ${label} (${url})"
  cat "$node_log"
  return 1
}

DIRECTORY_ADDR="$DIRECTORY_ADDR" \
DIRECTORY_PRIVATE_KEY_FILE="$tmp_dir/directory.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/directory_provider_replay.json" \
ISSUER_ADDR="$ISSUER_ADDR" \
ISSUER_PRIVATE_KEY_FILE="$tmp_dir/issuer.key" \
ISSUER_REVOCATIONS_FILE="$tmp_dir/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$tmp_dir/issuer_anon_revocations.json" \
ENTRY_ADDR="$ENTRY_ADDR" \
ENTRY_URL="$ENTRY_URL" \
ENTRY_DATA_ADDR="$ENTRY_DATA_ADDR" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
ENTRY_RELAY_ID=entry-local-1 \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_ADDR="$EXIT_ADDR" \
EXIT_CONTROL_URL="$EXIT_URL" \
EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
EXIT_RELAY_ID=exit-local-1 \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
DIRECTORY_URL="$DIRECTORY_URL" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$tmp_dir/entry_trusted_directory_keys.txt" \
ISSUER_URL="$ISSUER_URL" \
ISSUER_URLS="$ISSUER_URL" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/exit_token_replay.json" \
EXIT_REPUTATION_SCORE="$EXIT_REPUTATION_SCORE" \
EXIT_UPTIME_SCORE="$EXIT_UPTIME_SCORE" \
EXIT_CAPACITY_SCORE="$EXIT_CAPACITY_SCORE" \
EXIT_ABUSE_PENALTY="$EXIT_ABUSE_PENALTY" \
timeout 20s go run ./cmd/node --directory --issuer --entry --exit >"$node_log" 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true; rm -rf "$tmp_dir"' EXIT

wait_for_http_ready "$DIRECTORY_URL/v1/health" "directory"
wait_for_http_ready "$ISSUER_URL/v1/health" "issuer"
wait_for_http_ready "$ENTRY_URL/v1/health" "entry"

DIRECTORY_URL="$DIRECTORY_URL" \
ISSUER_URL="$ISSUER_URL" \
ENTRY_URL="$ENTRY_URL" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$tmp_dir/trusted_directory_keys.txt" \
CLIENT_SELECTION_FEED_REQUIRE=1 \
timeout 10s go run ./cmd/node --client >"$client_log" 2>&1 || true

if ! rg -q 'client selected entry=' "$client_log"; then
  echo "expected successful client bootstrap with required selection feed"
  cat "$client_log"
  cat "$node_log"
  exit 1
fi

echo "selection feed integration check ok"
