#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in go curl rg sed timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

LOG_FILE="/tmp/integration_anon_credential.log"
rm -f "$LOG_FILE"

timeout 25s go run ./cmd/node --directory --issuer --entry --exit >"$LOG_FILE" 2>&1 &
node_pid=$!
trap 'kill "$node_pid" >/dev/null 2>&1 || true' EXIT

sleep 2

credential_id="anon-integration-1"
issue_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/admin/anon-credential/issue \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"credential_id\":\"$credential_id\",\"tier\":2,\"reason\":\"integration-test\"}")
anon_cred=$(echo "$issue_json" | sed -n 's/.*"credential":"\([^"]*\)".*/\1/p')
if [[ -z "$anon_cred" ]]; then
  echo "failed to issue anonymous credential"
  echo "$issue_json"
  cat "$LOG_FILE"
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

token_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":2,\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"],\"anon_cred\":\"$anon_cred\"}")
token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$token" ]]; then
  echo "failed to issue token with anonymous credential"
  echo "$token_json"
  cat "$LOG_FILE"
  exit 1
fi

client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
token_proof_nonce="$(date +%s%N)-anon"
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

path_payload=$(cat <<JSON
{"exit_id":"exit-local-1","token":"$token","token_proof":"$token_proof","token_proof_nonce":"$token_proof_nonce","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)

open_resp=$(curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$path_payload")
if ! echo "$open_resp" | rg -q '"accepted":true'; then
  echo "expected path open accepted for anonymous-credential token"
  echo "$open_resp"
  cat "$LOG_FILE"
  exit 1
fi

until=$(( $(date +%s) + 120 ))
revoke_resp=$(curl -sS -X POST http://127.0.0.1:8082/v1/admin/anon-credential/revoke \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"credential_id\":\"$credential_id\",\"until\":$until,\"reason\":\"integration-test\"}")
if ! echo "$revoke_resp" | rg -q "\"credential_id\":\"$credential_id\""; then
  echo "failed to revoke anonymous credential"
  echo "$revoke_resp"
  cat "$LOG_FILE"
  exit 1
fi

status_code=$(curl -sS -o /tmp/integration_anon_credential_denied.txt -w '%{http_code}' \
  -X POST http://127.0.0.1:8082/v1/token \
  -H 'Content-Type: application/json' \
  --data "{\"tier\":2,\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"],\"anon_cred\":\"$anon_cred\"}")
if [[ "$status_code" != "403" ]]; then
  echo "expected token issuance denial with revoked anonymous credential"
  echo "status_code=$status_code body=$(cat /tmp/integration_anon_credential_denied.txt)"
  cat "$LOG_FILE"
  exit 1
fi
if ! rg -q "anonymous credential revoked" /tmp/integration_anon_credential_denied.txt; then
  echo "missing revoked anonymous credential denial reason"
  cat /tmp/integration_anon_credential_denied.txt
  cat "$LOG_FILE"
  exit 1
fi

echo "anonymous credential integration check ok"
