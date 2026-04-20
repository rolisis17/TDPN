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
  if tokenpop_output="$(go run ./cmd/tokenpop gen --show-private-key 2>&1)"; then
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

EXIT_REVOCATION_REFRESH_SEC="${EXIT_REVOCATION_REFRESH_SEC:-1}"
EXIT_REVOCATION_REFRESH_SEC="$EXIT_REVOCATION_REFRESH_SEC" \
  timeout 20s go run ./cmd/node --directory --issuer --entry --exit >/tmp/revoke_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 2

if ! read_tokenpop_keypair; then
  exit 1
fi
pop_pub="$TOKENPOP_PUBLIC_KEY"
pop_priv="$TOKENPOP_PRIVATE_KEY"

token_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-revoke-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")

token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
jti=$(echo "$token_json" | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p')

if [[ -z "$token" || -z "$jti" ]]; then
  echo "failed to parse token/jti"
  redact_token_json "$token_json"
  cat /tmp/revoke_node.log
  exit 1
fi

pop_priv_file="$(mktemp)"
token_file="$(mktemp)"
chmod 600 "$pop_priv_file"
chmod 600 "$token_file"
printf '%s' "$pop_priv" >"$pop_priv_file"
printf '%s' "$token" >"$token_file"
trap 'kill $node_pid >/dev/null 2>&1 || true; rm -f "$pop_priv_file" "$token_file"' EXIT

client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
token_proof_nonce="$(date +%s%N)-revoke"
token_proof=$(go run ./cmd/tokenpop sign \
  --private-key-file "$pop_priv_file" \
  --token-file "$token_file" \
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

payload=$(cat <<JSON
{"exit_id":"exit-local-1","token":"$token","token_proof":"$token_proof","token_proof_nonce":"$token_proof_nonce","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)

first=$(curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$payload")
if ! echo "$first" | rg -q '"accepted":true'; then
  echo "expected first path open accepted"
  echo "$first"
  cat /tmp/revoke_node.log
  exit 1
fi

until=$(( $(date +%s) + 120 ))
curl -sS -X POST http://127.0.0.1:8082/v1/admin/revoke-token \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"jti\":\"$jti\",\"until\":$until}" >/tmp/revoke_admin.json

sleep 2
second=$(curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$payload")
if ! echo "$second" | rg -q 'token revoked'; then
  echo "expected revoked token denial"
  echo "$second"
  cat /tmp/revoke_node.log
  exit 1
fi

echo "revocation integration check ok"
