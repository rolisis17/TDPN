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

BASE_PORT="${INTEGRATION_MULTI_ISSUER_BASE_PORT:-23380}"
DIRECTORY_ADDR="${INTEGRATION_MULTI_ISSUER_DIRECTORY_ADDR:-127.0.0.1:$((BASE_PORT + 1))}"
ISSUER_A_ADDR="${INTEGRATION_MULTI_ISSUER_ISSUER_A_ADDR:-127.0.0.1:$((BASE_PORT + 2))}"
ENTRY_ADDR="${INTEGRATION_MULTI_ISSUER_ENTRY_ADDR:-127.0.0.1:$((BASE_PORT + 3))}"
EXIT_ADDR="${INTEGRATION_MULTI_ISSUER_EXIT_ADDR:-127.0.0.1:$((BASE_PORT + 4))}"
ISSUER_B_ADDR="${INTEGRATION_MULTI_ISSUER_ISSUER_B_ADDR:-127.0.0.1:$((BASE_PORT + 6))}"
ENTRY_DATA_ADDR="${INTEGRATION_MULTI_ISSUER_ENTRY_DATA_ADDR:-127.0.0.1:$((BASE_PORT + 20))}"
EXIT_DATA_ADDR="${INTEGRATION_MULTI_ISSUER_EXIT_DATA_ADDR:-127.0.0.1:$((BASE_PORT + 21))}"
DIRECTORY_URL="http://${DIRECTORY_ADDR}"
ISSUER_A_URL="http://${ISSUER_A_ADDR}"
ISSUER_B_URL="http://${ISSUER_B_ADDR}"
ENTRY_URL="http://${ENTRY_ADDR}"
EXIT_URL="http://${EXIT_ADDR}"
ADMIN_TOKEN="${INTEGRATION_MULTI_ISSUER_ADMIN_TOKEN:-integration-multi-issuer-admin-token}"

old_umask="$(umask)"
umask 077
tmp_dir="$(mktemp -d /tmp/integration_multi_issuer.XXXXXX)"
umask "$old_umask"
directory_log="$tmp_dir/multi_issuer_directory.log"
issuer_a_log="$tmp_dir/multi_issuer_a.log"
issuer_b_log="$tmp_dir/multi_issuer_b.log"
entry_exit_log="$tmp_dir/multi_issuer_entry_exit.log"
revoke_resp="$tmp_dir/multi_issuer_revoke.json"
NODE_TIMEOUT_SEC="${INTEGRATION_MULTI_ISSUER_NODE_TIMEOUT_SEC:-60}"

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  redact_token_json "$route_assertion_json"
  exit 1
fi

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

decode_b64url() {
  local raw="${1//-/+}"
  raw="${raw//_/\/}"
  case $((${#raw} % 4)) in
    2) raw="${raw}==" ;;
    3) raw="${raw}=" ;;
  esac
  printf '%s' "$raw" | base64 -d 2>/dev/null
}

print_path_open_debug() {
  echo "issuer-a pubkeys:"
  curl -sS "$ISSUER_A_URL/v1/pubkeys" 2>&1 || true
  echo
  echo "issuer-b pubkeys:"
  curl -sS "$ISSUER_B_URL/v1/pubkeys" 2>&1 || true
  echo
  echo "token claims:"
  decode_b64url "${token%%.*}" || true
  echo
  echo "entry-exit log:"
  cat "$entry_exit_log"
  echo "issuer-a log:"
  cat "$issuer_a_log"
  echo "issuer-b log:"
  cat "$issuer_b_log"
}

DIRECTORY_ADDR="$DIRECTORY_ADDR" \
DIRECTORY_PRIVATE_KEY_FILE="$tmp_dir/directory.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/directory_provider_replay.json" \
ENTRY_URL="$ENTRY_URL" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
ENTRY_RELAY_ID=entry-local-1 \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_CONTROL_URL="$EXIT_URL" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
EXIT_RELAY_ID=exit-local-1 \
  timeout "${NODE_TIMEOUT_SEC}s" go run ./cmd/node --directory >"$directory_log" 2>&1 &
dir_pid=$!

ISSUER_ADDR="$ISSUER_A_ADDR" \
ISSUER_ID=issuer-a \
ISSUER_PRIVATE_KEY_FILE="$tmp_dir/issuer_a.key" \
ISSUER_PREVIOUS_PUBKEYS_FILE="$tmp_dir/issuer_a_previous_pubkeys.txt" \
ISSUER_EPOCHS_FILE="$tmp_dir/issuer_a_epochs.json" \
ISSUER_ADMIN_TOKEN="$ADMIN_TOKEN" \
ISSUER_REVOCATIONS_FILE="$tmp_dir/issuer_a_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$tmp_dir/issuer_a_anon_revocations.json" \
  timeout "${NODE_TIMEOUT_SEC}s" go run ./cmd/node --issuer >"$issuer_a_log" 2>&1 &
issuer_a_pid=$!

ISSUER_ADDR="$ISSUER_B_ADDR" \
ISSUER_ID=issuer-b \
ISSUER_PRIVATE_KEY_FILE="$tmp_dir/issuer_b.key" \
ISSUER_PREVIOUS_PUBKEYS_FILE="$tmp_dir/issuer_b_previous_pubkeys.txt" \
ISSUER_EPOCHS_FILE="$tmp_dir/issuer_b_epochs.json" \
ISSUER_ADMIN_TOKEN="$ADMIN_TOKEN" \
ISSUER_REVOCATIONS_FILE="$tmp_dir/issuer_b_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$tmp_dir/issuer_b_anon_revocations.json" \
  timeout "${NODE_TIMEOUT_SEC}s" go run ./cmd/node --issuer >"$issuer_b_log" 2>&1 &
issuer_b_pid=$!

wait_for_http_ready "$DIRECTORY_URL/v1/health" "directory" "$dir_pid" "$directory_log"
wait_for_http_ready "$ISSUER_A_URL/v1/health" "issuer-a" "$issuer_a_pid" "$issuer_a_log"
wait_for_http_ready "$ISSUER_B_URL/v1/health" "issuer-b" "$issuer_b_pid" "$issuer_b_log"
wait_for_http_ready "$ISSUER_A_URL/v1/pubkeys" "issuer-a pubkeys" "$issuer_a_pid" "$issuer_a_log"
wait_for_http_ready "$ISSUER_B_URL/v1/pubkeys" "issuer-b pubkeys" "$issuer_b_pid" "$issuer_b_log"

DIRECTORY_URL="$DIRECTORY_URL" \
ISSUER_URLS="$ISSUER_A_URL,$ISSUER_B_URL" \
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
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$tmp_dir/trusted_directory_keys.txt" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/exit_token_replay.json" \
EXIT_STARTUP_SYNC_TIMEOUT_SEC=5 \
EXIT_VERIFY_ISSUER_REFRESH_MIN_INTERVAL_MS=0 \
EXIT_REVOCATION_REFRESH_SEC=1 \
  timeout "${NODE_TIMEOUT_SEC}s" go run ./cmd/node --entry --exit >"$entry_exit_log" 2>&1 &
relay_pid=$!

cleanup() {
  kill "$dir_pid" "$issuer_a_pid" "$issuer_b_pid" "$relay_pid" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

wait_for_http_ready "$ENTRY_URL/v1/health" "entry-exit" "$relay_pid" "$entry_exit_log"

if ! read_tokenpop_keypair; then
  exit 1
fi
pop_pub="$TOKENPOP_PUBLIC_KEY"
pop_priv="$TOKENPOP_PRIVATE_KEY"

token_json=$(curl -sS -X POST "$ISSUER_B_URL/v1/token" -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-multi-issuer-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")
token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
jti=$(echo "$token_json" | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p')

if [[ -z "$token" || -z "$jti" ]]; then
  echo "failed to parse issuer-b token/jti"
  redact_token_json "$token_json"
  cat "$issuer_b_log"
  exit 1
fi

pop_priv_file="$(mktemp)"
token_file="$(mktemp)"
chmod 600 "$pop_priv_file"
chmod 600 "$token_file"
printf '%s' "$pop_priv" >"$pop_priv_file"
printf '%s' "$token" >"$token_file"
trap 'kill "$dir_pid" "$issuer_a_pid" "$issuer_b_pid" "$relay_pid" >/dev/null 2>&1 || true; rm -f "$pop_priv_file" "$token_file"; rm -rf "$tmp_dir"' EXIT

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

first=""
first_seen=0
for attempt in $(seq 1 12); do
  token_proof_nonce="$(date +%s%N)-multi-issuer-${attempt}"
  session_id="multi-issuer-session-${attempt}-$(date +%s%N)"
  if ! payload="$(build_path_open_payload "$session_id" "$token_proof_nonce")"; then
    echo "failed to sign token proof"
    exit 1
  fi
  first=$(curl -sS -X POST "$ENTRY_URL/v1/path/open" -H 'Content-Type: application/json' --data "$payload" 2>&1 || true)
  if echo "$first" | rg -q '"accepted":true'; then
    first_seen=1
    break
  fi
  sleep 1
done
if [[ "$first_seen" != "1" ]]; then
  echo "expected path open accepted with issuer-b token"
  echo "$first"
  print_path_open_debug
  exit 1
fi

until=$(( $(date +%s) + 120 ))
if ! curl -fsS -X POST "$ISSUER_B_URL/v1/admin/revoke-token" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "{\"jti\":\"$jti\",\"until\":$until}" >"$revoke_resp"; then
  echo "failed to revoke issuer-b token through issuer admin API"
  cat "$revoke_resp" 2>/dev/null || true
  cat "$issuer_b_log"
  exit 1
fi
if ! rg -q "\"jti\":\"$jti\"" "$revoke_resp"; then
  echo "issuer-b revoke response did not contain expected jti"
  cat "$revoke_resp"
  cat "$issuer_b_log"
  exit 1
fi

second=""
revoked_seen=0
for attempt in $(seq 1 15); do
  second_token_proof_nonce="$(date +%s%N)-multi-issuer-after-${attempt}"
  second_session_id="multi-issuer-session-after-${attempt}-$(date +%s%N)"
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
  echo "expected issuer-b revoked token denial"
  echo "$second"
  print_path_open_debug
  exit 1
fi

echo "multi-issuer integration check ok"
