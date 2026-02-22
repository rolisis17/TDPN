#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

ENTRY_OPEN_RPS=2 \
ENTRY_PUZZLE_DIFFICULTY=1 \
ENTRY_BAN_THRESHOLD=2 \
ENTRY_BAN_SEC=6 \
timeout 45s go run ./cmd/node --issuer --entry --exit >/tmp/load_chaos_core.log 2>&1 &
core_pid=$!

DIRECTORY_ADDR=127.0.0.1:8085 \
DIRECTORY_PRIVATE_KEY_FILE=data/load_chaos_peer.key \
DIRECTORY_OPERATOR_ID=op-peer-de \
ENTRY_RELAY_ID=entry-de-1 \
EXIT_RELAY_ID=exit-de-1 \
ENTRY_COUNTRY_CODE=DE \
EXIT_COUNTRY_CODE=DE \
timeout 45s go run ./cmd/node --directory >/tmp/load_chaos_peer.log 2>&1 &
peer_pid=$!

DIRECTORY_ADDR=127.0.0.1:8081 \
DIRECTORY_PRIVATE_KEY_FILE=data/load_chaos_main.key \
DIRECTORY_OPERATOR_ID=op-main \
DIRECTORY_PEERS=http://127.0.0.1:8085 \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_MIN_VOTES=1 \
timeout 45s go run ./cmd/node --directory >/tmp/load_chaos_main.log 2>&1 &
main_pid=$!

cleanup() {
  kill "$core_pid" "$peer_pid" "$main_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 4

pop_json=$(go run ./cmd/tokenpop gen)
pop_pub=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
pop_priv=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$pop_pub" || -z "$pop_priv" ]]; then
  echo "failed to generate token PoP keypair"
  echo "$pop_json"
  exit 1
fi

token_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-load-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")
token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$token" ]]; then
  echo "failed to issue token for load segment"
  echo "$token_json"
  cat /tmp/load_chaos_core.log
  exit 1
fi

client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
token_proof_nonce="$(date +%s%N)-load-chaos"
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

payload_file=/tmp/load_chaos_path_open.json
cat >"$payload_file" <<JSON
{"exit_id":"exit-local-1","token":"$token","token_proof":"$token_proof","token_proof_nonce":"$token_proof_nonce","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON

responses=/tmp/load_chaos_responses.log
: >"$responses"
export responses

seq 12 | xargs -P 6 -I{} sh -c '
  curl -sS -X POST http://127.0.0.1:8083/v1/path/open \
    -H "Content-Type: application/json" \
    --data @"'"$payload_file"'" >>"'"$responses"'"
  printf "\n" >>"'"$responses"'"
'

challenge_count=$(rg -c 'challenge-required' "$responses" || true)
blocked_count=$(rg -c 'source-temporarily-blocked|entry-overloaded' "$responses" || true)

if [[ "$challenge_count" -lt 1 ]]; then
  echo "expected challenge-required under load"
  cat "$responses"
  cat /tmp/load_chaos_core.log
  exit 1
fi
if [[ "$blocked_count" -lt 1 ]]; then
  echo "expected temporary block or overload response under load"
  cat "$responses"
  cat /tmp/load_chaos_core.log
  exit 1
fi

synced=0
for _ in $(seq 1 10); do
  if curl -sS http://127.0.0.1:8081/v1/relays | rg -q '"relay_id":"exit-de-1"'; then
    synced=1
    break
  fi
  sleep 1
done
if [[ "$synced" -ne 1 ]]; then
  echo "expected synced DE relay before chaos step"
  cat /tmp/load_chaos_main.log
  cat /tmp/load_chaos_peer.log
  exit 1
fi

kill "$peer_pid" >/dev/null 2>&1 || true
sleep 2

DIRECTORY_URL=http://127.0.0.1:8081 \
CLIENT_EXIT_COUNTRY=DE \
CLIENT_EXIT_STRICT_LOCALITY=1 \
timeout 10s go run ./cmd/node --client >/tmp/load_chaos_client_down.log 2>&1 || true

if ! rg -q 'client selected entry=' /tmp/load_chaos_client_down.log; then
  echo "expected client bootstrap to continue with cached synced relay while peer is down"
  cat /tmp/load_chaos_client_down.log
  cat /tmp/load_chaos_main.log
  exit 1
fi

DIRECTORY_ADDR=127.0.0.1:8085 \
DIRECTORY_PRIVATE_KEY_FILE=data/load_chaos_peer.key \
DIRECTORY_OPERATOR_ID=op-peer-de \
ENTRY_RELAY_ID=entry-de-1 \
EXIT_RELAY_ID=exit-de-1 \
ENTRY_COUNTRY_CODE=DE \
EXIT_COUNTRY_CODE=DE \
timeout 45s go run ./cmd/node --directory >/tmp/load_chaos_peer_restart.log 2>&1 &
peer_pid=$!

sleep 3

DIRECTORY_URL=http://127.0.0.1:8081 \
CLIENT_EXIT_COUNTRY=DE \
CLIENT_EXIT_STRICT_LOCALITY=1 \
timeout 10s go run ./cmd/node --client >/tmp/load_chaos_client_recover.log 2>&1 || true

if ! rg -q 'client selected entry=' /tmp/load_chaos_client_recover.log; then
  echo "expected client bootstrap after peer restart"
  cat /tmp/load_chaos_client_recover.log
  cat /tmp/load_chaos_main.log
  cat /tmp/load_chaos_peer_restart.log
  exit 1
fi

echo "load/chaos integration check ok"
