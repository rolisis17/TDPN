#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

timeout 25s go run ./cmd/node --directory >/tmp/multi_issuer_directory.log 2>&1 &
dir_pid=$!

ISSUER_ADDR=127.0.0.1:8082 \
ISSUER_ID=issuer-a \
timeout 25s go run ./cmd/node --issuer >/tmp/multi_issuer_a.log 2>&1 &
issuer_a_pid=$!

ISSUER_ADDR=127.0.0.1:8086 \
ISSUER_ID=issuer-b \
timeout 25s go run ./cmd/node --issuer >/tmp/multi_issuer_b.log 2>&1 &
issuer_b_pid=$!

ISSUER_URLS="http://127.0.0.1:8082,http://127.0.0.1:8086" \
EXIT_REVOCATION_REFRESH_SEC=1 \
timeout 25s go run ./cmd/node --entry --exit >/tmp/multi_issuer_entry_exit.log 2>&1 &
relay_pid=$!

cleanup() {
  kill "$dir_pid" "$issuer_a_pid" "$issuer_b_pid" "$relay_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 3

pop_json=$(go run ./cmd/tokenpop gen)
pop_pub=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
pop_priv=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$pop_pub" || -z "$pop_priv" ]]; then
  echo "failed to generate token PoP keypair"
  echo "$pop_json"
  exit 1
fi

token_json=$(curl -sS -X POST http://127.0.0.1:8086/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-multi-issuer-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")
token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
jti=$(echo "$token_json" | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p')

if [[ -z "$token" || -z "$jti" ]]; then
  echo "failed to parse issuer-b token/jti"
  echo "$token_json"
  cat /tmp/multi_issuer_b.log
  exit 1
fi

client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
token_proof_nonce="$(date +%s%N)-multi-issuer"
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

payload=$(cat <<JSON
{"exit_id":"exit-local-1","token":"$token","token_proof":"$token_proof","token_proof_nonce":"$token_proof_nonce","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)

first=$(curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$payload")
if ! echo "$first" | rg -q '"accepted":true'; then
  echo "expected path open accepted with issuer-b token"
  echo "$first"
  cat /tmp/multi_issuer_entry_exit.log
  exit 1
fi

until=$(( $(date +%s) + 120 ))
curl -sS -X POST http://127.0.0.1:8086/v1/admin/revoke-token \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"jti\":\"$jti\",\"until\":$until}" >/tmp/multi_issuer_revoke.json

sleep 2
second=$(curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$payload")
if ! echo "$second" | rg -q 'token revoked'; then
  echo "expected issuer-b revoked token denial"
  echo "$second"
  cat /tmp/multi_issuer_entry_exit.log
  cat /tmp/multi_issuer_b.log
  exit 1
fi

echo "multi-issuer integration check ok"
