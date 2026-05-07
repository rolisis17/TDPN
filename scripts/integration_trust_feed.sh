#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

MIDDLE_BOND_SCORE="${MIDDLE_BOND_SCORE:-0.95}"
MIDDLE_STAKE_SCORE="${MIDDLE_STAKE_SCORE:-0.75}"

TMP_DIR="$(mktemp -d)"
TRUST_FILE="$TMP_DIR/directory_trust.txt"
NODE_LOG="$TMP_DIR/trust_feed_node.log"
CLIENT_LOG="$TMP_DIR/trust_feed_client.log"
RESPONSE_JSON="$TMP_DIR/trust_feed_response.json"

DIR_PORT=19281
ISSUER_PORT=19282
ENTRY_PORT=19283
EXIT_PORT=19284
ENTRY_DATA_PORT=20280
EXIT_DATA_PORT=20281
EXIT_WG_PORT=20282
MIDDLE_DATA_PORT=20283

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
MIDDLE_RELAY_ENABLED=1 \
MIDDLE_RELAY_ID=middle-local-1 \
MIDDLE_OPERATOR_ID=operator-middle \
MIDDLE_DATA_ADDR="127.0.0.1:${MIDDLE_DATA_PORT}" \
MIDDLE_ENDPOINT_PUBLIC="127.0.0.1:${MIDDLE_DATA_PORT}" \
MIDDLE_BOND_SCORE="$MIDDLE_BOND_SCORE" \
MIDDLE_STAKE_SCORE="$MIDDLE_STAKE_SCORE" \
timeout 20s go run ./cmd/node --directory --issuer --entry --exit >"$NODE_LOG" 2>&1 &
node_pid=$!

sleep 2

curl -fsS "http://127.0.0.1:${DIR_PORT}/v1/trust-attestations" >"$RESPONSE_JSON"
if ! rg -q "\"bond_score\":${MIDDLE_BOND_SCORE}" "$RESPONSE_JSON"; then
  echo "expected trust feed to include configured bond score"
  cat "$RESPONSE_JSON"
  cat "$NODE_LOG"
  exit 1
fi
if ! rg -q "\"stake_score\":${MIDDLE_STAKE_SCORE}" "$RESPONSE_JSON"; then
  echo "expected trust feed to include configured stake score"
  cat "$RESPONSE_JSON"
  cat "$NODE_LOG"
  exit 1
fi

DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}" \
CLIENT_TRUST_FEED_REQUIRE=1 \
timeout 10s go run ./cmd/node --client >"$CLIENT_LOG" 2>&1 || true

if ! rg -q 'client selected entry=' "$CLIENT_LOG"; then
  echo "expected successful client bootstrap with required trust feed"
  cat "$CLIENT_LOG"
  cat "$NODE_LOG"
  exit 1
fi

echo "trust feed integration check ok"
