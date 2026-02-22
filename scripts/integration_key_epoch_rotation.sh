#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

ISSUER_KEY_ROTATE_SEC="${ISSUER_KEY_ROTATE_SEC:-2}"
EXIT_REVOCATION_REFRESH_SEC="${EXIT_REVOCATION_REFRESH_SEC:-1}"
ISSUER_KEY_HISTORY="${ISSUER_KEY_HISTORY:-4}"

ISSUER_KEY_ROTATE_SEC="$ISSUER_KEY_ROTATE_SEC" \
EXIT_REVOCATION_REFRESH_SEC="$EXIT_REVOCATION_REFRESH_SEC" \
ISSUER_KEY_HISTORY="$ISSUER_KEY_HISTORY" \
timeout 45s go run ./cmd/node --directory --issuer --entry --exit >/tmp/key_epoch_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 3

TOKEN_POP_PRIVATE_KEY=""
ISSUE_TOKEN_JSON=""
issue_token() {
  local pop_json pop_pub pop_priv
  pop_json=$(go run ./cmd/tokenpop gen)
  pop_pub=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
  pop_priv=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
  if [[ -z "$pop_pub" || -z "$pop_priv" ]]; then
    echo "failed to generate PoP keypair for token" >&2
    echo "$pop_json" >&2
    return 1
  fi
  TOKEN_POP_PRIVATE_KEY="$pop_priv"
  ISSUE_TOKEN_JSON=$(curl -sS -X POST http://127.0.0.1:8082/v1/token \
    -H 'Content-Type: application/json' \
    --data "{\"tier\":1,\"subject\":\"client-key-epoch-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")
}

path_open() {
  local token="$1"
  local pop_priv="$2"
  local client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  local token_proof_nonce
  token_proof_nonce="$(date +%s%N)-key-epoch-$RANDOM"
  local token_proof
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
    echo '{"accepted":false,"reason":"failed-token-proof"}'
    return 1
  fi
  local payload
  payload=$(cat <<JSON
{"exit_id":"exit-local-1","token":"$token","token_proof":"$token_proof","token_proof_nonce":"$token_proof_nonce","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)
  curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$payload"
}

issue_token
token_json_1="$ISSUE_TOKEN_JSON"
token_1=$(echo "$token_json_1" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
token_1_pop_priv="$TOKEN_POP_PRIVATE_KEY"
if [[ -z "$token_1" ]]; then
  echo "failed to issue initial token"
  echo "$token_json_1"
  cat /tmp/key_epoch_node.log
  exit 1
fi

first=$(path_open "$token_1" "$token_1_pop_priv")
if ! echo "$first" | rg -q '"accepted":true'; then
  echo "expected initial token accepted"
  echo "$first"
  cat /tmp/key_epoch_node.log
  exit 1
fi

stale_denied=0
for _ in $(seq 1 20); do
  sleep 1
  probe=$(path_open "$token_1" "$token_1_pop_priv")
  if echo "$probe" | rg -q 'token key epoch expired'; then
    stale_denied=1
    break
  fi
done

if [[ "$stale_denied" -ne 1 ]]; then
  echo "expected old token denied after issuer key epoch rotation"
  cat /tmp/key_epoch_node.log
  exit 1
fi

issue_token
token_json_2="$ISSUE_TOKEN_JSON"
token_2=$(echo "$token_json_2" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
token_2_pop_priv="$TOKEN_POP_PRIVATE_KEY"
if [[ -z "$token_2" ]]; then
  echo "failed to issue rotated-epoch token"
  echo "$token_json_2"
  cat /tmp/key_epoch_node.log
  exit 1
fi

second=$(path_open "$token_2" "$token_2_pop_priv")
if ! echo "$second" | rg -q '"accepted":true'; then
  echo "expected fresh token accepted after rotation"
  echo "$second"
  cat /tmp/key_epoch_node.log
  exit 1
fi

echo "key-epoch rotation integration check ok"
