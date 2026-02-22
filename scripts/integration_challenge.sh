#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

ENTRY_OPEN_RPS="${ENTRY_OPEN_RPS:-1}"
ENTRY_PUZZLE_DIFFICULTY="${ENTRY_PUZZLE_DIFFICULTY:-1}"

ENTRY_OPEN_RPS="$ENTRY_OPEN_RPS" ENTRY_PUZZLE_DIFFICULTY="$ENTRY_PUZZLE_DIFFICULTY" \
  timeout 15s go run ./cmd/node --directory --issuer --entry --exit >/tmp/challenge_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 2

pop_json=$(go run ./cmd/tokenpop gen)
POP_PUBLIC_KEY=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
POP_PRIVATE_KEY=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$POP_PUBLIC_KEY" || -z "$POP_PRIVATE_KEY" ]]; then
  echo "failed to generate token PoP keypair"
  echo "$pop_json"
  exit 1
fi

TOKEN=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-challenge-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$POP_PUBLIC_KEY\",\"exit_scope\":[\"exit-local-1\"]}" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

if [[ -z "$TOKEN" ]]; then
  echo "failed to fetch token"
  cat /tmp/challenge_node.log
  exit 1
fi

CLIENT_PUB="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
TOKEN_PROOF_NONCE="$(date +%s%N)-challenge"
TOKEN_PROOF=$(go run ./cmd/tokenpop sign \
  --private-key "$POP_PRIVATE_KEY" \
  --token "$TOKEN" \
  --exit-id "exit-local-1" \
  --proof-nonce "$TOKEN_PROOF_NONCE" \
  --client-inner-pub "$CLIENT_PUB" \
  --transport "policy-json" \
  --requested-mtu 1280 \
  --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
if [[ -z "$TOKEN_PROOF" ]]; then
  echo "failed to sign token proof"
  cat /tmp/challenge_node.log
  exit 1
fi

PAYLOAD=$(cat <<JSON
{"exit_id":"exit-local-1","token":"$TOKEN","token_proof":"$TOKEN_PROOF","token_proof_nonce":"$TOKEN_PROOF_NONCE","client_inner_pub":"$CLIENT_PUB","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)

curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$PAYLOAD" >/tmp/challenge_first.json
curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$PAYLOAD" >/tmp/challenge_second.json

if ! rg -q 'challenge-required' /tmp/challenge_second.json; then
  echo "expected challenge-required response"
  cat /tmp/challenge_second.json
  cat /tmp/challenge_node.log
  exit 1
fi

echo "challenge integration check ok"
