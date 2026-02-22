#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

EXIT_TOKEN_PROOF_REPLAY_GUARD=1 \
timeout 20s go run ./cmd/node --directory --issuer --entry --exit >/tmp/token_proof_replay_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 2

pop_json=$(go run ./cmd/tokenpop gen)
pop_pub=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
pop_priv=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$pop_pub" || -z "$pop_priv" ]]; then
  echo "failed to generate token PoP keypair"
  echo "$pop_json"
  exit 1
fi

token_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-proof-replay-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")
token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$token" ]]; then
  echo "failed to parse token"
  echo "$token_json"
  cat /tmp/token_proof_replay_node.log
  exit 1
fi

client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
nonce_1="replay-nonce-1"
proof_1=$(go run ./cmd/tokenpop sign \
  --private-key "$pop_priv" \
  --token "$token" \
  --exit-id "exit-local-1" \
  --proof-nonce "$nonce_1" \
  --client-inner-pub "$client_pub" \
  --transport "policy-json" \
  --requested-mtu 1280 \
  --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
if [[ -z "$proof_1" ]]; then
  echo "failed to sign first proof"
  cat /tmp/token_proof_replay_node.log
  exit 1
fi

payload_1=$(cat <<JSON
{"exit_id":"exit-local-1","token":"$token","token_proof":"$proof_1","token_proof_nonce":"$nonce_1","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)

first=$(curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$payload_1")
if ! echo "$first" | rg -q '"accepted":true'; then
  echo "expected first path open accepted"
  echo "$first"
  cat /tmp/token_proof_replay_node.log
  exit 1
fi

second=$(curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$payload_1")
if ! echo "$second" | rg -q 'token proof replay'; then
  echo "expected replay denial on second path open"
  echo "$second"
  cat /tmp/token_proof_replay_node.log
  exit 1
fi

nonce_2="replay-nonce-2"
proof_2=$(go run ./cmd/tokenpop sign \
  --private-key "$pop_priv" \
  --token "$token" \
  --exit-id "exit-local-1" \
  --proof-nonce "$nonce_2" \
  --client-inner-pub "$client_pub" \
  --transport "policy-json" \
  --requested-mtu 1280 \
  --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
if [[ -z "$proof_2" ]]; then
  echo "failed to sign second proof"
  cat /tmp/token_proof_replay_node.log
  exit 1
fi

payload_2=$(cat <<JSON
{"exit_id":"exit-local-1","token":"$token","token_proof":"$proof_2","token_proof_nonce":"$nonce_2","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)

third=$(curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$payload_2")
if ! echo "$third" | rg -q '"accepted":true'; then
  echo "expected third path open accepted with new nonce"
  echo "$third"
  cat /tmp/token_proof_replay_node.log
  exit 1
fi

echo "token proof replay integration check ok"
