#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LIFECYCLE_CHAOS_TAG="${LIFECYCLE_CHAOS_TAG:-base}"
LIFECYCLE_CHAOS_TAG_SAFE="$(printf '%s' "$LIFECYCLE_CHAOS_TAG" | tr -cd 'A-Za-z0-9._-')"
if [[ -z "$LIFECYCLE_CHAOS_TAG_SAFE" ]]; then
  LIFECYCLE_CHAOS_TAG_SAFE="base"
fi
DIR_PORT="${DIR_PORT:-8381}"
ISSUER_PORT="${ISSUER_PORT:-8382}"
ENTRY_PORT="${ENTRY_PORT:-8383}"
EXIT_PORT="${EXIT_PORT:-8384}"
ENTRY_DATA_PORT="${ENTRY_DATA_PORT:-53820}"
EXIT_DATA_PORT="${EXIT_DATA_PORT:-53821}"
CHAOS_TIMEOUT_SEC="${CHAOS_TIMEOUT_SEC:-60}"
READY_ATTEMPTS="${READY_ATTEMPTS:-40}"
READY_SLEEP_SEC="${READY_SLEEP_SEC:-0.25}"
RACE_LOOPS="${RACE_LOOPS:-20}"
RACE_SLEEP_SEC="${RACE_SLEEP_SEC:-0.2}"
DISPUTE_LOOPS="${DISPUTE_LOOPS:-14}"
DISPUTE_SLEEP_SEC="${DISPUTE_SLEEP_SEC:-0.12}"
FRESH_LOOPS="${FRESH_LOOPS:-18}"
FRESH_SLEEP_SEC="${FRESH_SLEEP_SEC:-0.15}"

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

emit_redacted_tokenpop_error() {
  local message="$1"
  local rc="${2:-0}"
  local payload="${3:-}"
  local bytes
  local parse_hint="unknown"
  bytes="$(printf '%s' "$payload" | wc -c | tr -d '[:space:]')"
  if command -v jq >/dev/null 2>&1; then
    if printf '%s' "$payload" | jq -e . >/dev/null 2>&1; then
      parse_hint="json_missing_required_fields"
    else
      parse_hint="non_json_output"
    fi
  fi
  echo "${message} (tokenpop output redacted; rc=${rc}, bytes=${bytes:-0}, parse_hint=${parse_hint})"
}

read_tokenpop_keypair() {
  local tokenpop_output=""
  if tokenpop_output="$(go run ./cmd/tokenpop gen --show-private-key 2>&1)"; then
    :
  else
    local rc=$?
    emit_redacted_tokenpop_error "failed to generate seed token PoP keypair" "$rc" "$tokenpop_output"
    return 1
  fi

  local parsed_pub=""
  local parsed_priv=""
  if command -v jq >/dev/null 2>&1; then
    parsed_pub="$(printf '%s' "$tokenpop_output" | jq -er '.public_key // empty' 2>/dev/null || true)"
    parsed_priv="$(printf '%s' "$tokenpop_output" | jq -er '.private_key // empty' 2>/dev/null || true)"
  else
    parsed_pub="$(printf '%s' "$tokenpop_output" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
    parsed_priv="$(printf '%s' "$tokenpop_output" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
  fi
  if [[ -z "$parsed_pub" || -z "$parsed_priv" ]]; then
    emit_redacted_tokenpop_error "failed to parse seed token PoP keypair output" 0 "$tokenpop_output"
    return 1
  fi

  TOKENPOP_PUBLIC_KEY="$parsed_pub"
  TOKENPOP_PRIVATE_KEY="$parsed_priv"
  return 0
}

NODE_LOG="$(make_temp_file "/tmp/lifecycle_chaos_node_${LIFECYCLE_CHAOS_TAG_SAFE}.XXXXXX.log")"
REVOKE_LOG="$(make_temp_file "/tmp/lifecycle_chaos_revoke_${LIFECYCLE_CHAOS_TAG_SAFE}.XXXXXX.json")"
DISPUTE_LOG="$(make_temp_file "/tmp/lifecycle_chaos_dispute_${LIFECYCLE_CHAOS_TAG_SAFE}.XXXXXX.log")"
RACE_LOG="$(make_temp_file "/tmp/lifecycle_chaos_race_${LIFECYCLE_CHAOS_TAG_SAFE}.XXXXXX.log")"
FRESH_LOG="$(make_temp_file "/tmp/lifecycle_chaos_fresh_${LIFECYCLE_CHAOS_TAG_SAFE}.XXXXXX.log")"
PAYLOAD_FILE="$(make_private_temp_file "/tmp/lifecycle_chaos_payload_${LIFECYCLE_CHAOS_TAG_SAFE}.XXXXXX.json")"
POP_PRIV_FILE="$(make_private_temp_file "/tmp/lifecycle_chaos_pop_priv_${LIFECYCLE_CHAOS_TAG_SAFE}.XXXXXX.key")"
POP_PRIV_ITER_FILE="$(make_private_temp_file "/tmp/lifecycle_chaos_pop_priv_iter_${LIFECYCLE_CHAOS_TAG_SAFE}.XXXXXX.key")"
TOKEN_FILE="$(make_private_temp_file "/tmp/lifecycle_chaos_token_${LIFECYCLE_CHAOS_TAG_SAFE}.XXXXXX.jwt")"
TOKEN_ITER_FILE="$(make_private_temp_file "/tmp/lifecycle_chaos_token_iter_${LIFECYCLE_CHAOS_TAG_SAFE}.XXXXXX.jwt")"

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ENTRY_ADDR="127.0.0.1:${ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${EXIT_PORT}" \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}" \
EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}" \
DIRECTORY_ISSUER_TRUST_URLS="http://127.0.0.1:${ISSUER_PORT}" \
DIRECTORY_ISSUER_SYNC_SEC=1 \
EXIT_REVOCATION_REFRESH_SEC=1 \
timeout "${CHAOS_TIMEOUT_SEC}s" go run ./cmd/node --directory --issuer --entry --exit >"${NODE_LOG}" 2>&1 &
node_pid=$!

cleanup() {
  kill "$node_pid" >/dev/null 2>&1 || true
  rm -f \
    "$NODE_LOG" \
    "$REVOKE_LOG" \
    "$DISPUTE_LOG" \
    "$RACE_LOG" \
    "$FRESH_LOG" \
    "$PAYLOAD_FILE" \
    "$POP_PRIV_FILE" \
    "$POP_PRIV_ITER_FILE" \
    "$TOKEN_FILE" \
    "$TOKEN_ITER_FILE"
}
trap cleanup EXIT

ready=0
for _ in $(seq 1 "${READY_ATTEMPTS}"); do
  if curl -fsS "http://127.0.0.1:${ENTRY_PORT}/v1/health" >/dev/null 2>&1 && \
    curl -fsS "http://127.0.0.1:${ISSUER_PORT}/v1/pubkey" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep "${READY_SLEEP_SEC}"
done
if [[ "$ready" -ne 1 ]]; then
  echo "lifecycle chaos stack did not become ready"
  cat "${NODE_LOG}"
  exit 1
fi

client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
if ! read_tokenpop_keypair; then
  exit 1
fi
pop_pub="$TOKENPOP_PUBLIC_KEY"
pop_priv="$TOKENPOP_PRIVATE_KEY"

token_json=$(curl -sS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/token" -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-chaos-seed\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")
token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
jti=$(echo "$token_json" | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p')

if [[ -z "$token" || -z "$jti" ]]; then
  echo "failed to parse token/jti for lifecycle chaos seed token"
  redact_token_json "$token_json"
  cat "${NODE_LOG}"
  exit 1
fi

printf '%s' "$pop_priv" >"$POP_PRIV_FILE"
printf '%s' "$token" >"$TOKEN_FILE"

token_proof=$(go run ./cmd/tokenpop sign \
  --private-key-file "$POP_PRIV_FILE" \
  --token-file "$TOKEN_FILE" \
  --exit-id "exit-local-1" \
  --proof-nonce "seed-${jti}" \
  --client-inner-pub "$client_pub" \
  --transport "policy-json" \
  --requested-mtu 1280 \
  --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
if [[ -z "$token_proof" ]]; then
  echo "failed to sign seed token proof"
  exit 1
fi

cat >"$PAYLOAD_FILE" <<JSON
{"exit_id":"exit-local-1","token":"$token","token_proof":"$token_proof","token_proof_nonce":"seed-${jti}","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON

: >"${RACE_LOG}"

(
  for _ in $(seq 1 "${RACE_LOOPS}"); do
    curl -sS -X POST "http://127.0.0.1:${ENTRY_PORT}/v1/path/open" \
      -H 'Content-Type: application/json' \
      --data @"${PAYLOAD_FILE}" >>"${RACE_LOG}" || true
    printf "\n" >>"${RACE_LOG}"
    sleep "${RACE_SLEEP_SEC}"
  done
) &
race_pid=$!

sleep 1
until_ts=$(( $(date +%s) + 180 ))
curl -sS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/revoke-token" \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"jti\":\"$jti\",\"until\":$until_ts}" >"${REVOKE_LOG}"

(
  for _ in $(seq 1 "${DISPUTE_LOOPS}"); do
    du=$(( $(date +%s) + 180 ))
    curl -sS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/subject/dispute" \
      -H 'X-Admin-Token: dev-admin-token' \
      -H 'Content-Type: application/json' \
      --data "{\"subject\":\"exit-local-1\",\"tier_cap\":1,\"until\":$du,\"reason\":\"chaos-cycle\"}" >/dev/null || true
    sleep "${DISPUTE_SLEEP_SEC}"
    curl -sS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/subject/dispute/clear" \
      -H 'X-Admin-Token: dev-admin-token' \
      -H 'Content-Type: application/json' \
      --data '{"subject":"exit-local-1","reason":"chaos-cycle-clear"}' >/dev/null || true
    sleep "${DISPUTE_SLEEP_SEC}"
  done
) >"${DISPUTE_LOG}" 2>&1 &
dispute_pid=$!

: >"${FRESH_LOG}"
(
  for _ in $(seq 1 "${FRESH_LOOPS}"); do
    popj="$(go run ./cmd/tokenpop gen --show-private-key 2>&1 || true)"
    if command -v jq >/dev/null 2>&1; then
      pop_pub_iter="$(printf '%s' "$popj" | jq -er '.public_key // empty' 2>/dev/null || true)"
      pop_priv_iter="$(printf '%s' "$popj" | jq -er '.private_key // empty' 2>/dev/null || true)"
    else
      pop_pub_iter="$(printf '%s' "$popj" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
      pop_priv_iter="$(printf '%s' "$popj" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
    fi
    if [[ -z "$pop_pub_iter" || -z "$pop_priv_iter" ]]; then
      sleep "${FRESH_SLEEP_SEC}"
      continue
    fi
    tj=$(curl -sS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/token" -H 'Content-Type: application/json' \
      --data "{\"tier\":1,\"subject\":\"client-chaos-fresh\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub_iter\",\"exit_scope\":[\"exit-local-1\"]}" || true)
    tk=$(echo "$tj" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    if [[ -n "$tk" ]]; then
      fresh_nonce="fresh-$RANDOM-$(date +%s%N)"
      printf '%s' "$pop_priv_iter" >"$POP_PRIV_ITER_FILE"
      printf '%s' "$tk" >"$TOKEN_ITER_FILE"
      tp=$(go run ./cmd/tokenpop sign \
        --private-key-file "$POP_PRIV_ITER_FILE" \
        --token-file "$TOKEN_ITER_FILE" \
        --exit-id "exit-local-1" \
        --proof-nonce "$fresh_nonce" \
        --client-inner-pub "$client_pub" \
        --transport "policy-json" \
        --requested-mtu 1280 \
        --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
      if [[ -z "$tp" ]]; then
        sleep "${FRESH_SLEEP_SEC}"
        continue
      fi
      pl=$(cat <<JSON
{"exit_id":"exit-local-1","token":"$tk","token_proof":"$tp","token_proof_nonce":"$fresh_nonce","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)
      curl -sS -X POST "http://127.0.0.1:${ENTRY_PORT}/v1/path/open" -H 'Content-Type: application/json' --data "$pl" >>"${FRESH_LOG}" || true
      printf "\n" >>"${FRESH_LOG}"
    fi
    sleep "${FRESH_SLEEP_SEC}"
  done
) &
fresh_pid=$!

wait "$race_pid"
wait "$dispute_pid"
wait "$fresh_pid"

accepted_seed=$(rg -c '"accepted":true' "${RACE_LOG}" || true)
revoked_seed=$(rg -c 'token revoked' "${RACE_LOG}" || true)
if [[ "$accepted_seed" -lt 1 ]]; then
  echo "expected at least one accepted open before revocation in race loop"
  cat "${RACE_LOG}"
  cat "${NODE_LOG}"
  exit 1
fi
if [[ "$revoked_seed" -lt 1 ]]; then
  echo "expected revoked-token denial during race loop"
  cat "${RACE_LOG}"
  cat "${NODE_LOG}"
  exit 1
fi

accepted_fresh=$(rg -c '"accepted":true' "${FRESH_LOG}" || true)
if [[ "$accepted_fresh" -lt 3 ]]; then
  echo "expected fresh token opens to continue under dispute/revocation churn"
  cat "${FRESH_LOG}"
  cat "${NODE_LOG}"
  exit 1
fi

if rg -q 'panic:' "${NODE_LOG}"; then
  echo "unexpected panic during lifecycle chaos run"
  cat "${NODE_LOG}"
  exit 1
fi

metrics=$(curl -sS "http://127.0.0.1:${EXIT_PORT}/v1/metrics")
revoked_drops=$(echo "$metrics" | sed -n 's/.*"dropped_token_revoked":\([0-9][0-9]*\).*/\1/p')
if [[ -z "$revoked_drops" || "$revoked_drops" -lt 1 ]]; then
  echo "expected dropped_token_revoked metrics > 0 after chaos race"
  echo "$metrics"
  cat "${NODE_LOG}"
  exit 1
fi

audit=$(curl -sS "http://127.0.0.1:${ISSUER_PORT}/v1/admin/audit?limit=40" -H 'X-Admin-Token: dev-admin-token')
if ! echo "$audit" | rg -q 'subject-dispute-apply'; then
  echo "expected dispute apply events in issuer audit"
  echo "$audit"
  cat "${NODE_LOG}"
  exit 1
fi

echo "lifecycle chaos integration check ok (accepted_seed=${accepted_seed}, revoked_seed=${revoked_seed}, accepted_fresh=${accepted_fresh})"
