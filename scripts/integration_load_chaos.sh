#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOAD_CHAOS_TAG="${LOAD_CHAOS_TAG:-base}"
LOAD_CHAOS_TAG_SAFE="$(printf '%s' "$LOAD_CHAOS_TAG" | tr -cd 'A-Za-z0-9._-')"
if [[ -z "$LOAD_CHAOS_TAG_SAFE" ]]; then
  LOAD_CHAOS_TAG_SAFE="base"
fi
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
EXIT_WG_PORT="${EXIT_WG_PORT:-57822}"
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
PEER_ENTRY_RELAY_ID="entry-${LOAD_COUNTRY_CODE,,}-1"
PEER_EXIT_RELAY_ID="exit-${LOAD_COUNTRY_CODE,,}-1"
PEER_SYNC_SEC="${PEER_SYNC_SEC:-1}"

make_temp_file() {
  mktemp "$1"
}

make_private_temp_file() {
  local old_umask
  local file_path
  old_umask="$(umask)"
  umask 077
  file_path="$(mktemp "$1")"
  umask "$old_umask"
  printf '%s\n' "$file_path"
}

redact_token_json() {
  local payload="$1"
  if command -v jq >/dev/null 2>&1 && printf '%s' "$payload" | jq -e . >/dev/null 2>&1; then
    printf '%s' "$payload" | jq -c '
      if type == "object" then
        (if has("token") then .token = "[redacted]" else . end)
        | (if has("private_key") then .private_key = "[redacted]" else . end)
        | (if has("credential") then .credential = "[redacted]" else . end)
      else
        .
      end
    '
    return
  fi
  printf '%s\n' "$payload" | sed -E \
    -e 's/"token":"[^"]*"/"token":"[redacted]"/g' \
    -e 's/"private_key":"[^"]*"/"private_key":"[redacted]"/g' \
    -e 's/"credential":"[^"]*"/"credential":"[redacted]"/g'
}

CORE_LOG="$(make_temp_file "/tmp/load_chaos_core_${LOAD_CHAOS_TAG_SAFE}.XXXXXX.log")"
PEER_LOG="$(make_temp_file "/tmp/load_chaos_peer_${LOAD_CHAOS_TAG_SAFE}.XXXXXX.log")"
MAIN_LOG="$(make_temp_file "/tmp/load_chaos_main_${LOAD_CHAOS_TAG_SAFE}.XXXXXX.log")"
RESPONSES_LOG="$(make_temp_file "/tmp/load_chaos_responses_${LOAD_CHAOS_TAG_SAFE}.XXXXXX.log")"
STATE_DIR="$(mktemp -d "/tmp/load_chaos_state_${LOAD_CHAOS_TAG_SAFE}.XXXXXX")"
TRUST_FILE="$STATE_DIR/directory_trust.txt"
PEER_TRUST_FILE="$STATE_DIR/peer_trust.txt"
PAYLOAD_FILE="$(make_private_temp_file "/tmp/load_chaos_path_open_${LOAD_CHAOS_TAG_SAFE}.XXXXXX.json")"
CLIENT_DOWN_LOG="$(make_temp_file "/tmp/load_chaos_client_down_${LOAD_CHAOS_TAG_SAFE}.XXXXXX.log")"
PEER_RESTART_LOG="$(make_temp_file "/tmp/load_chaos_peer_restart_${LOAD_CHAOS_TAG_SAFE}.XXXXXX.log")"
CLIENT_RECOVER_LOG="$(make_temp_file "/tmp/load_chaos_client_recover_${LOAD_CHAOS_TAG_SAFE}.XXXXXX.log")"
POP_PRIV_FILE=""
TOKEN_FILE=""

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  exit 1
fi

ENTRY_OPEN_RPS="$ENTRY_OPEN_RPS" \
ENTRY_PUZZLE_DIFFICULTY="$ENTRY_PUZZLE_DIFFICULTY" \
ENTRY_BAN_THRESHOLD="$ENTRY_BAN_THRESHOLD" \
ENTRY_BAN_SEC="$ENTRY_BAN_SEC" \
EXIT_STARTUP_SYNC_TIMEOUT_SEC="$EXIT_STARTUP_SYNC_TIMEOUT_SEC" \
ISSUER_ADDR="127.0.0.1:${CORE_ISSUER_PORT}" \
ISSUER_URL="http://127.0.0.1:${CORE_ISSUER_PORT}" \
ISSUER_PRIVATE_KEY_FILE="$STATE_DIR/issuer.key" \
ISSUER_SUBJECTS_FILE="$STATE_DIR/issuer_subjects.json" \
ISSUER_REVOCATIONS_FILE="$STATE_DIR/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$STATE_DIR/issuer_anon_revocations.json" \
ENTRY_ADDR="127.0.0.1:${CORE_ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${CORE_EXIT_PORT}" \
ENTRY_RELAY_ID="$PEER_ENTRY_RELAY_ID" \
EXIT_RELAY_ID="$PEER_EXIT_RELAY_ID" \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_URL="${CORE_ENTRY_URL}" \
EXIT_CONTROL_URL="${CORE_EXIT_CONTROL_URL}" \
DIRECTORY_URL="http://127.0.0.1:${MAIN_DIR_PORT}" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
ENTRY_LIVE_WG_MODE=0 \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_WG_LISTEN_PORT="$EXIT_WG_PORT" \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$STATE_DIR/exit_token_replay.json" \
timeout "${CORE_TIMEOUT_SEC}s" go run ./cmd/node --issuer --entry --exit >"${CORE_LOG}" 2>&1 &
core_pid=$!

DIRECTORY_ADDR="127.0.0.1:${PEER_DIR_PORT}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PEER_DIR_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE="$STATE_DIR/load_chaos_peer.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$STATE_DIR/peer_provider_replay.json" \
DIRECTORY_OPERATOR_ID="${PEER_OPERATOR_ID}" \
ENTRY_ADDR="127.0.0.1:${CORE_ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${CORE_EXIT_PORT}" \
ENTRY_RELAY_ID="$PEER_ENTRY_RELAY_ID" \
EXIT_RELAY_ID="$PEER_EXIT_RELAY_ID" \
ENTRY_COUNTRY_CODE="${LOAD_COUNTRY_CODE}" \
EXIT_COUNTRY_CODE="${LOAD_COUNTRY_CODE}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_URL="${CORE_ENTRY_URL}" \
EXIT_CONTROL_URL="${CORE_EXIT_CONTROL_URL}" \
ENTRY_RELAY_ID="$PEER_ENTRY_RELAY_ID" \
EXIT_RELAY_ID="$PEER_EXIT_RELAY_ID" \
ENTRY_COUNTRY_CODE="${LOAD_COUNTRY_CODE}" \
EXIT_COUNTRY_CODE="${LOAD_COUNTRY_CODE}" \
timeout "${CORE_TIMEOUT_SEC}s" go run ./cmd/node --directory >"${PEER_LOG}" 2>&1 &
peer_pid=$!

DIRECTORY_ADDR="127.0.0.1:${MAIN_DIR_PORT}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${MAIN_DIR_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE="$STATE_DIR/load_chaos_main.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$STATE_DIR/main_provider_replay.json" \
DIRECTORY_OPERATOR_ID="${MAIN_OPERATOR_ID}" \
DIRECTORY_PEERS="http://127.0.0.1:${PEER_DIR_PORT}" \
DIRECTORY_PEER_TRUST_TOFU=1 \
DIRECTORY_PEER_TRUSTED_KEYS_FILE="$PEER_TRUST_FILE" \
DIRECTORY_ALLOW_DANGEROUS_DISCOVERED_PRIVATE_PEERS=1 \
DIRECTORY_SYNC_SEC="${PEER_SYNC_SEC}" \
DIRECTORY_PEER_MIN_VOTES=1 \
ENTRY_ADDR="127.0.0.1:${CORE_ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${CORE_EXIT_PORT}" \
ENTRY_RELAY_ID="$PEER_ENTRY_RELAY_ID" \
EXIT_RELAY_ID="$PEER_EXIT_RELAY_ID" \
ENTRY_COUNTRY_CODE="${LOAD_COUNTRY_CODE}" \
EXIT_COUNTRY_CODE="${LOAD_COUNTRY_CODE}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_URL="${CORE_ENTRY_URL}" \
EXIT_CONTROL_URL="${CORE_EXIT_CONTROL_URL}" \
timeout "${CORE_TIMEOUT_SEC}s" go run ./cmd/node --directory >"${MAIN_LOG}" 2>&1 &
main_pid=$!

cleanup() {
  kill "$core_pid" "$peer_pid" "$main_pid" >/dev/null 2>&1 || true
  if [[ -n "$POP_PRIV_FILE" ]]; then
    rm -f "$POP_PRIV_FILE"
  fi
  if [[ -n "$TOKEN_FILE" ]]; then
    rm -f "$TOKEN_FILE"
  fi
  rm -f \
    "$CORE_LOG" \
    "$PEER_LOG" \
    "$MAIN_LOG" \
    "$RESPONSES_LOG" \
    "$PAYLOAD_FILE" \
	    "$CLIENT_DOWN_LOG" \
	    "$PEER_RESTART_LOG" \
	    "$CLIENT_RECOVER_LOG"
  rm -rf "$STATE_DIR"
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

pop_json=$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)
pop_pub=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
pop_priv=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$pop_pub" || -z "$pop_priv" ]]; then
  echo "failed to generate token PoP keypair"
  redact_token_json "$pop_json"
  exit 1
fi

token_json=$(curl -sS -X POST "http://127.0.0.1:${CORE_ISSUER_PORT}/v1/token" -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-load-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"$PEER_EXIT_RELAY_ID\"]}")
token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$token" ]]; then
  echo "failed to issue token for load segment"
  redact_token_json "$token_json"
  cat "$CORE_LOG"
  exit 1
fi

client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
token_proof_nonce="$(date +%s%N)-load-chaos"
session_id="load-chaos-session-$(date +%s%N)"
POP_PRIV_FILE="$(make_private_temp_file "/tmp/load_chaos_tokenpop_private_${LOAD_CHAOS_TAG_SAFE}.XXXXXX.key")"
printf '%s' "$pop_priv" >"$POP_PRIV_FILE"
chmod 600 "$POP_PRIV_FILE"
TOKEN_FILE="$(make_private_temp_file "/tmp/load_chaos_token_${LOAD_CHAOS_TAG_SAFE}.XXXXXX.jwt")"
printf '%s' "$token" >"$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
token_proof=$(go run ./cmd/tokenpop sign \
  --private-key-file "$POP_PRIV_FILE" \
  --token-file "$TOKEN_FILE" \
  --exit-id "$PEER_EXIT_RELAY_ID" \
  --session-id "$session_id" \
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
{"exit_id":"$PEER_EXIT_RELAY_ID","session_id":"$session_id","token":"$token","token_proof":"$token_proof","token_proof_nonce":"$token_proof_nonce","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON

: >"$RESPONSES_LOG"
export RESPONSES_LOG
export PAYLOAD_FILE
export CORE_ENTRY_PORT

send_path_open_once() {
  curl -sS -X POST "http://127.0.0.1:${CORE_ENTRY_PORT}/v1/path/open" \
    -H "Content-Type: application/json" \
    --data @"${PAYLOAD_FILE}" >>"${RESPONSES_LOG}" || true
  printf "\n" >>"${RESPONSES_LOG}"
}

active_jobs=0
open_pids=()
for _request_idx in $(seq "$LOAD_OPEN_REQUESTS"); do
  send_path_open_once &
  open_pids+=("$!")
  active_jobs=$((active_jobs + 1))
  if (( active_jobs >= LOAD_OPEN_PARALLEL )); then
    wait "${open_pids[0]}" || true
    open_pids=("${open_pids[@]:1}")
    active_jobs=$((active_jobs - 1))
  fi
done
for open_pid in "${open_pids[@]}"; do
  wait "$open_pid" || true
done

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
  if curl -sS "http://127.0.0.1:${MAIN_DIR_PORT}/v1/relays" | rg -q "\"relay_id\":\"${PEER_EXIT_RELAY_ID}\""; then
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
sleep $((ENTRY_BAN_SEC * 2 + 2))

DIRECTORY_URL="http://127.0.0.1:${MAIN_DIR_PORT}" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
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
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PEER_DIR_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE="$STATE_DIR/load_chaos_peer.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$STATE_DIR/peer_provider_replay_restart.json" \
DIRECTORY_OPERATOR_ID="${PEER_OPERATOR_ID}" \
ENTRY_ADDR="127.0.0.1:${CORE_ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${CORE_EXIT_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_URL="${CORE_ENTRY_URL}" \
EXIT_CONTROL_URL="${CORE_EXIT_CONTROL_URL}" \
ENTRY_RELAY_ID="$PEER_ENTRY_RELAY_ID" \
EXIT_RELAY_ID="$PEER_EXIT_RELAY_ID" \
ENTRY_COUNTRY_CODE="${LOAD_COUNTRY_CODE}" \
EXIT_COUNTRY_CODE="${LOAD_COUNTRY_CODE}" \
timeout "${CORE_TIMEOUT_SEC}s" go run ./cmd/node --directory >"${PEER_RESTART_LOG}" 2>&1 &
peer_pid=$!

sleep 3
sleep $((ENTRY_BAN_SEC * 2 + 2))

DIRECTORY_URL="http://127.0.0.1:${MAIN_DIR_PORT}" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
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
