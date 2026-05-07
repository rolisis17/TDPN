#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

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
  if tokenpop_output="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key 2>&1)"; then
    :
  else
    local rc=$?
    emit_redacted_tokenpop_error "failed to generate token PoP keypair" "$rc" "$tokenpop_output"
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
    emit_redacted_tokenpop_error "failed to parse token PoP keypair output" 0 "$tokenpop_output"
    return 1
  fi

  TOKENPOP_PUBLIC_KEY="$parsed_pub"
  TOKENPOP_PRIVATE_KEY="$parsed_priv"
  return 0
}

BASE_PORT="${INTEGRATION_REVOCATION_BASE_PORT:-23280}"
DIRECTORY_ADDR="${INTEGRATION_REVOCATION_DIRECTORY_ADDR:-127.0.0.1:$((BASE_PORT + 1))}"
ISSUER_ADDR="${INTEGRATION_REVOCATION_ISSUER_ADDR:-127.0.0.1:$((BASE_PORT + 2))}"
ENTRY_ADDR="${INTEGRATION_REVOCATION_ENTRY_ADDR:-127.0.0.1:$((BASE_PORT + 3))}"
EXIT_ADDR="${INTEGRATION_REVOCATION_EXIT_ADDR:-127.0.0.1:$((BASE_PORT + 4))}"
ENTRY_DATA_ADDR="${INTEGRATION_REVOCATION_ENTRY_DATA_ADDR:-127.0.0.1:$((BASE_PORT + 20))}"
EXIT_DATA_ADDR="${INTEGRATION_REVOCATION_EXIT_DATA_ADDR:-127.0.0.1:$((BASE_PORT + 21))}"
DIRECTORY_URL="http://${DIRECTORY_ADDR}"
ISSUER_URL="http://${ISSUER_ADDR}"
ENTRY_URL="http://${ENTRY_ADDR}"
EXIT_URL="http://${EXIT_ADDR}"
ADMIN_TOKEN="${INTEGRATION_REVOCATION_ADMIN_TOKEN:-integration-revocation-admin-token}"

wait_for_http_ready() {
  local url="$1"
  local label="$2"
  local pid="$3"
  local log_file="$4"
  local deadline=$((SECONDS + 20))
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

old_umask="$(umask)"
umask 077
tmp_dir="$(mktemp -d /tmp/integration_revocation.XXXXXX)"
umask "$old_umask"
node_log="$tmp_dir/revoke_node.log"
admin_resp="$tmp_dir/revoke_admin.json"

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  redact_token_json "$route_assertion_json"
  exit 1
fi

EXIT_REVOCATION_REFRESH_SEC="${EXIT_REVOCATION_REFRESH_SEC:-1}"
NODE_TIMEOUT_SEC="${INTEGRATION_REVOCATION_NODE_TIMEOUT_SEC:-60}"
DIRECTORY_ADDR="$DIRECTORY_ADDR" \
DIRECTORY_PRIVATE_KEY_FILE="$tmp_dir/directory.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/directory_provider_replay.json" \
ISSUER_ADDR="$ISSUER_ADDR" \
ISSUER_PRIVATE_KEY_FILE="$tmp_dir/issuer.key" \
ISSUER_PREVIOUS_PUBKEYS_FILE="$tmp_dir/issuer_previous_pubkeys.txt" \
ISSUER_EPOCHS_FILE="$tmp_dir/issuer_epochs.json" \
ISSUER_ADMIN_TOKEN="$ADMIN_TOKEN" \
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
DIRECTORY_TRUSTED_KEYS_FILE="$tmp_dir/trusted_directory_keys.txt" \
ISSUER_URL="$ISSUER_URL" \
ISSUER_URLS="$ISSUER_URL" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/exit_token_replay.json" \
EXIT_STARTUP_SYNC_TIMEOUT_SEC=5 \
EXIT_REVOCATION_REFRESH_SEC="$EXIT_REVOCATION_REFRESH_SEC" \
  timeout "${NODE_TIMEOUT_SEC}s" go run ./cmd/node --directory --issuer --entry --exit >"$node_log" 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true; rm -rf "$tmp_dir"' EXIT

wait_for_http_ready "$DIRECTORY_URL/v1/health" "directory" "$node_pid" "$node_log"
wait_for_http_ready "$ISSUER_URL/v1/health" "issuer" "$node_pid" "$node_log"
wait_for_http_ready "$ISSUER_URL/v1/pubkeys" "issuer pubkeys" "$node_pid" "$node_log"
wait_for_http_ready "$ENTRY_URL/v1/health" "entry" "$node_pid" "$node_log"

if ! read_tokenpop_keypair; then
  exit 1
fi
pop_pub="$TOKENPOP_PUBLIC_KEY"
pop_priv="$TOKENPOP_PRIVATE_KEY"

token_json=$(curl -sS -X POST "$ISSUER_URL/v1/token" -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-revoke-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")

token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
jti=$(echo "$token_json" | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p')

if [[ -z "$token" || -z "$jti" ]]; then
  echo "failed to parse token/jti"
  redact_token_json "$token_json"
  cat "$node_log"
  exit 1
fi

pop_priv_file="$(mktemp)"
token_file="$(mktemp)"
chmod 600 "$pop_priv_file"
chmod 600 "$token_file"
printf '%s' "$pop_priv" >"$pop_priv_file"
printf '%s' "$token" >"$token_file"
trap 'kill $node_pid >/dev/null 2>&1 || true; rm -f "$pop_priv_file" "$token_file"; rm -rf "$tmp_dir"' EXIT

client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

build_path_open_payload() {
  local path_session_id="$1"
  local proof_nonce="$2"
  local proof
  proof=$(go run ./cmd/tokenpop sign \
    --private-key-file "$pop_priv_file" \
    --token-file "$token_file" \
    --exit-id "exit-local-1" \
    --session-id "$path_session_id" \
    --proof-nonce "$proof_nonce" \
    --client-inner-pub "$client_pub" \
    --transport "policy-json" \
    --requested-mtu 1280 \
    --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
  if [[ -z "$proof" ]]; then
    return 1
  fi
  cat <<JSON
{"exit_id":"exit-local-1","session_id":"$path_session_id","token":"$token","token_proof":"$proof","token_proof_nonce":"$proof_nonce","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
}

token_proof_nonce="$(date +%s%N)-revoke"
session_id="revoke-session-$(date +%s%N)"
if ! payload="$(build_path_open_payload "$session_id" "$token_proof_nonce")"; then
  echo "failed to sign token proof"
  exit 1
fi

first=$(curl -sS -X POST "$ENTRY_URL/v1/path/open" -H 'Content-Type: application/json' --data "$payload" 2>&1 || true)
if ! echo "$first" | rg -q '"accepted":true'; then
  echo "expected first path open accepted"
  echo "$first"
  cat "$node_log"
  exit 1
fi

until=$(( $(date +%s) + 120 ))
if ! curl -fsS -X POST "$ISSUER_URL/v1/admin/revoke-token" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "{\"jti\":\"$jti\",\"until\":$until}" >"$admin_resp"; then
  echo "failed to revoke token through issuer admin API"
  cat "$admin_resp" 2>/dev/null || true
  cat "$node_log"
  exit 1
fi
if ! rg -q "\"jti\":\"$jti\"" "$admin_resp"; then
  echo "issuer admin revoke response did not contain expected jti"
  cat "$admin_resp"
  cat "$node_log"
  exit 1
fi

second=""
revoked_seen=0
for attempt in $(seq 1 15); do
  second_token_proof_nonce="$(date +%s%N)-revoke-after-${attempt}"
  second_session_id="revoke-session-after-${attempt}-$(date +%s%N)"
  if ! second_payload="$(build_path_open_payload "$second_session_id" "$second_token_proof_nonce")"; then
    echo "failed to sign second token proof"
    exit 1
  fi
  second=$(curl -sS -X POST "$ENTRY_URL/v1/path/open" -H 'Content-Type: application/json' --data "$second_payload" 2>&1 || true)
  if echo "$second" | rg -q 'token revoked'; then
    revoked_seen=1
    break
  fi
  sleep 1
done
if [[ "$revoked_seen" != "1" ]]; then
  echo "expected revoked token denial"
  echo "$second"
  cat "$node_log"
  exit 1
fi

echo "revocation integration check ok"
