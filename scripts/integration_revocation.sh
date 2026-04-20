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

EXIT_REVOCATION_REFRESH_SEC="${EXIT_REVOCATION_REFRESH_SEC:-1}"
EXIT_REVOCATION_REFRESH_SEC="$EXIT_REVOCATION_REFRESH_SEC" \
  timeout 20s go run ./cmd/node --directory --issuer --entry --exit >/tmp/revoke_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 2

pop_json=$(go run ./cmd/tokenpop gen --show-private-key)
pop_pub=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
pop_priv=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$pop_pub" || -z "$pop_priv" ]]; then
  echo "failed to generate token PoP keypair"
  redact_token_json "$pop_json"
  exit 1
fi

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
