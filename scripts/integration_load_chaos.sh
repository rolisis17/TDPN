#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOAD_CHAOS_TAG="${LOAD_CHAOS_TAG:-base}"
CORE_TIMEOUT_SEC="${CORE_TIMEOUT_SEC:-90}"
CLIENT_TIMEOUT_SEC="${CLIENT_TIMEOUT_SEC:-10}"
MAIN_DIR_PORT="${MAIN_DIR_PORT:-8781}"
PEER_DIR_PORT="${PEER_DIR_PORT:-8785}"
CORE_ISSUER_PORT="${CORE_ISSUER_PORT:-8782}"
CORE_ENTRY_PORT="${CORE_ENTRY_PORT:-8783}"
CORE_EXIT_PORT="${CORE_EXIT_PORT:-8784}"
CORE_ENTRY_URL="${CORE_ENTRY_URL:-http://127.0.0.1:${CORE_ENTRY_PORT}}"
CORE_EXIT_CONTROL_URL="${CORE_EXIT_CONTROL_URL:-http://127.0.0.1:${CORE_EXIT_PORT}}"
ENTRY_DATA_PORT="${ENTRY_DATA_PORT:-57820}"
EXIT_DATA_PORT="${EXIT_DATA_PORT:-57821}"
ENTRY_OPEN_RPS="${ENTRY_OPEN_RPS:-2}"
ENTRY_PUZZLE_DIFFICULTY="${ENTRY_PUZZLE_DIFFICULTY:-1}"
ENTRY_BAN_THRESHOLD="${ENTRY_BAN_THRESHOLD:-2}"
ENTRY_BAN_SEC="${ENTRY_BAN_SEC:-6}"
EXIT_STARTUP_SYNC_TIMEOUT_SEC="${EXIT_STARTUP_SYNC_TIMEOUT_SEC:-5}"
LOAD_OPEN_REQUESTS="${LOAD_OPEN_REQUESTS:-12}"
LOAD_OPEN_PARALLEL="${LOAD_OPEN_PARALLEL:-6}"
LOAD_COUNTRY_CODE="${LOAD_COUNTRY_CODE:-DE}"
MAIN_OPERATOR_ID="${MAIN_OPERATOR_ID:-op-main}"
PEER_OPERATOR_ID="${PEER_OPERATOR_ID:-op-peer-${LOAD_COUNTRY_CODE,,}}"
PEER_SYNC_SEC="${PEER_SYNC_SEC:-1}"

CORE_LOG="/tmp/load_chaos_core_${LOAD_CHAOS_TAG}.log"
PEER_LOG="/tmp/load_chaos_peer_${LOAD_CHAOS_TAG}.log"
MAIN_LOG="/tmp/load_chaos_main_${LOAD_CHAOS_TAG}.log"
RESPONSES_LOG="/tmp/load_chaos_responses_${LOAD_CHAOS_TAG}.log"
PAYLOAD_FILE="/tmp/load_chaos_path_open_${LOAD_CHAOS_TAG}.json"
CLIENT_DOWN_LOG="/tmp/load_chaos_client_down_${LOAD_CHAOS_TAG}.log"
PEER_RESTART_LOG="/tmp/load_chaos_peer_restart_${LOAD_CHAOS_TAG}.log"
CLIENT_RECOVER_LOG="/tmp/load_chaos_client_recover_${LOAD_CHAOS_TAG}.log"

ENTRY_OPEN_RPS="$ENTRY_OPEN_RPS" \
ENTRY_PUZZLE_DIFFICULTY="$ENTRY_PUZZLE_DIFFICULTY" \
ENTRY_BAN_THRESHOLD="$ENTRY_BAN_THRESHOLD" \
ENTRY_BAN_SEC="$ENTRY_BAN_SEC" \
EXIT_STARTUP_SYNC_TIMEOUT_SEC="$EXIT_STARTUP_SYNC_TIMEOUT_SEC" \
ISSUER_ADDR="127.0.0.1:${CORE_ISSUER_PORT}" \
ISSUER_URL="http://127.0.0.1:${CORE_ISSUER_PORT}" \
ENTRY_ADDR="127.0.0.1:${CORE_ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${CORE_EXIT_PORT}" \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_URL="${CORE_ENTRY_URL}" \
EXIT_CONTROL_URL="${CORE_EXIT_CONTROL_URL}" \
DIRECTORY_URL="http://127.0.0.1:${MAIN_DIR_PORT}" \
timeout "${CORE_TIMEOUT_SEC}s" go run ./cmd/node --issuer --entry --exit >"${CORE_LOG}" 2>&1 &
core_pid=$!

DIRECTORY_ADDR="127.0.0.1:${PEER_DIR_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE=data/load_chaos_peer.key \
DIRECTORY_OPERATOR_ID="${PEER_OPERATOR_ID}" \
ENTRY_ADDR="127.0.0.1:${CORE_ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${CORE_EXIT_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_URL="${CORE_ENTRY_URL}" \
EXIT_CONTROL_URL="${CORE_EXIT_CONTROL_URL}" \
ENTRY_RELAY_ID="entry-${LOAD_COUNTRY_CODE,,}-1" \
EXIT_RELAY_ID="exit-${LOAD_COUNTRY_CODE,,}-1" \
ENTRY_COUNTRY_CODE="${LOAD_COUNTRY_CODE}" \
EXIT_COUNTRY_CODE="${LOAD_COUNTRY_CODE}" \
timeout "${CORE_TIMEOUT_SEC}s" go run ./cmd/node --directory >"${PEER_LOG}" 2>&1 &
peer_pid=$!

DIRECTORY_ADDR="127.0.0.1:${MAIN_DIR_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE=data/load_chaos_main.key \
DIRECTORY_OPERATOR_ID="${MAIN_OPERATOR_ID}" \
DIRECTORY_PEERS="http://127.0.0.1:${PEER_DIR_PORT}" \
DIRECTORY_SYNC_SEC="${PEER_SYNC_SEC}" \
DIRECTORY_PEER_MIN_VOTES=1 \
ENTRY_ADDR="127.0.0.1:${CORE_ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${CORE_EXIT_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_URL="${CORE_ENTRY_URL}" \
EXIT_CONTROL_URL="${CORE_EXIT_CONTROL_URL}" \
timeout "${CORE_TIMEOUT_SEC}s" go run ./cmd/node --directory >"${MAIN_LOG}" 2>&1 &
main_pid=$!

cleanup() {
  kill "$core_pid" "$peer_pid" "$main_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 4

local_relays_json=$(curl -sS "http://127.0.0.1:${MAIN_DIR_PORT}/v1/relays" || true)
if ! echo "$local_relays_json" | rg -q "\"control_url\":\"${CORE_ENTRY_URL}\""; then
  echo "expected main directory to publish entry control url ${CORE_ENTRY_URL}"
  echo "$local_relays_json"
  cat "$MAIN_LOG"
  exit 1
fi
if ! echo "$local_relays_json" | rg -q "\"control_url\":\"${CORE_EXIT_CONTROL_URL}\""; then
  echo "expected main directory to publish exit control url ${CORE_EXIT_CONTROL_URL}"
  echo "$local_relays_json"
  cat "$MAIN_LOG"
  exit 1
fi

pop_json=$(go run ./cmd/tokenpop gen)
pop_pub=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
pop_priv=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$pop_pub" || -z "$pop_priv" ]]; then
  echo "failed to generate token PoP keypair"
  echo "$pop_json"
  exit 1
fi

token_json=$(curl -sS -X POST "http://127.0.0.1:${CORE_ISSUER_PORT}/v1/token" -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-load-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")
token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$token" ]]; then
  echo "failed to issue token for load segment"
  echo "$token_json"
  cat "$CORE_LOG"
  exit 1
fi

client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
token_proof_nonce="$(date +%s%N)-load-chaos"
token_proof=$(go run ./cmd/tokenpop sign \
  --private-key "$pop_priv" \
  --token "$token" \
  --exit-id "exit-local-1" \
  --proof-nonce "$token_proof_nonce" \
  --client-inner-pub "$client_pub" \
  --transport "policy-json" \
  --requested-mtu 1280 \
  --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
if [[ -z "$token_proof" ]]; then
  echo "failed to sign token proof"
  exit 1
fi

cat >"$PAYLOAD_FILE" <<JSON
{"exit_id":"exit-local-1","token":"$token","token_proof":"$token_proof","token_proof_nonce":"$token_proof_nonce","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON

: >"$RESPONSES_LOG"
export RESPONSES_LOG
export PAYLOAD_FILE
export CORE_ENTRY_PORT

seq "$LOAD_OPEN_REQUESTS" | xargs -P "$LOAD_OPEN_PARALLEL" -I{} sh -c '
  curl -sS -X POST "http://127.0.0.1:${CORE_ENTRY_PORT}/v1/path/open" \
    -H "Content-Type: application/json" \
    --data @"${PAYLOAD_FILE}" >>"${RESPONSES_LOG}"
  printf "\n" >>"${RESPONSES_LOG}"
'

challenge_count=$(rg -c 'challenge-required' "$RESPONSES_LOG" || true)
blocked_count=$(rg -c 'source-temporarily-blocked|entry-overloaded' "$RESPONSES_LOG" || true)

if [[ "$challenge_count" -lt 1 ]]; then
  echo "note: challenge-required response not observed; continuing because temporary block/overload responses are present"
fi
if [[ "$blocked_count" -lt 1 ]]; then
  echo "expected temporary block or overload response under load"
  cat "$RESPONSES_LOG"
  cat "$CORE_LOG"
  exit 1
fi

synced=0
for _ in $(seq 1 10); do
  if curl -sS "http://127.0.0.1:${MAIN_DIR_PORT}/v1/relays" | rg -q "\"relay_id\":\"exit-${LOAD_COUNTRY_CODE,,}-1\""; then
    synced=1
    break
  fi
  sleep 1
done
if [[ "$synced" -ne 1 ]]; then
  echo "expected synced DE relay before chaos step"
  cat "$MAIN_LOG"
  cat "$PEER_LOG"
  exit 1
fi

kill "$peer_pid" >/dev/null 2>&1 || true
sleep 2
sleep $((ENTRY_BAN_SEC + 1))

DIRECTORY_URL="http://127.0.0.1:${MAIN_DIR_PORT}" \
ISSUER_URL="http://127.0.0.1:${CORE_ISSUER_PORT}" \
CLIENT_EXIT_COUNTRY="${LOAD_COUNTRY_CODE}" \
CLIENT_EXIT_STRICT_LOCALITY=1 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC=1 \
CLIENT_BOOTSTRAP_JITTER_PCT=0 \
timeout "${CLIENT_TIMEOUT_SEC}s" go run ./cmd/node --client >"${CLIENT_DOWN_LOG}" 2>&1 || true

if ! rg -q 'client selected entry=' "${CLIENT_DOWN_LOG}"; then
  echo "expected client bootstrap to continue with cached synced relay while peer is down"
  cat "${CLIENT_DOWN_LOG}"
  cat "$MAIN_LOG"
  exit 1
fi

DIRECTORY_ADDR="127.0.0.1:${PEER_DIR_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE=data/load_chaos_peer.key \
DIRECTORY_OPERATOR_ID="${PEER_OPERATOR_ID}" \
ENTRY_ADDR="127.0.0.1:${CORE_ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${CORE_EXIT_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_URL="${CORE_ENTRY_URL}" \
EXIT_CONTROL_URL="${CORE_EXIT_CONTROL_URL}" \
ENTRY_RELAY_ID="entry-${LOAD_COUNTRY_CODE,,}-1" \
EXIT_RELAY_ID="exit-${LOAD_COUNTRY_CODE,,}-1" \
ENTRY_COUNTRY_CODE="${LOAD_COUNTRY_CODE}" \
EXIT_COUNTRY_CODE="${LOAD_COUNTRY_CODE}" \
timeout "${CORE_TIMEOUT_SEC}s" go run ./cmd/node --directory >"${PEER_RESTART_LOG}" 2>&1 &
peer_pid=$!

sleep 3

DIRECTORY_URL="http://127.0.0.1:${MAIN_DIR_PORT}" \
ISSUER_URL="http://127.0.0.1:${CORE_ISSUER_PORT}" \
CLIENT_EXIT_COUNTRY="${LOAD_COUNTRY_CODE}" \
CLIENT_EXIT_STRICT_LOCALITY=1 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC=1 \
CLIENT_BOOTSTRAP_JITTER_PCT=0 \
timeout "${CLIENT_TIMEOUT_SEC}s" go run ./cmd/node --client >"${CLIENT_RECOVER_LOG}" 2>&1 || true

if ! rg -q 'client selected entry=' "${CLIENT_RECOVER_LOG}"; then
  echo "expected client bootstrap after peer restart"
  cat "${CLIENT_RECOVER_LOG}"
  cat "$MAIN_LOG"
  cat "${PEER_RESTART_LOG}"
  exit 1
fi

echo "load/chaos integration check ok"
