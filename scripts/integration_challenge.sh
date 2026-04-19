#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

redact_sensitive_json() {
  local payload="$1"
  printf '%s\n' "$payload" | sed -E \
    -e 's/("token"[[:space:]]*:[[:space:]]*")[^"]+/\1[redacted]/g' \
    -e 's/("private_key"[[:space:]]*:[[:space:]]*")[^"]+/\1[redacted]/g'
}

ENTRY_OPEN_RPS="${ENTRY_OPEN_RPS:-1}"
ENTRY_PUZZLE_DIFFICULTY="${ENTRY_PUZZLE_DIFFICULTY:-1}"

old_umask="$(umask)"
umask 077
tmp_dir="$(mktemp -d /tmp/integration_challenge.XXXXXX)"
umask "$old_umask"
pop_priv_file=""
token_file=""
node_log="$tmp_dir/challenge_node.log"
first_resp="$tmp_dir/challenge_first.json"
second_resp="$tmp_dir/challenge_second.json"

ENTRY_OPEN_RPS="$ENTRY_OPEN_RPS" ENTRY_PUZZLE_DIFFICULTY="$ENTRY_PUZZLE_DIFFICULTY" \
  timeout 15s go run ./cmd/node --directory --issuer --entry --exit >"$node_log" 2>&1 &
node_pid=$!
cleanup() {
  kill "$node_pid" >/dev/null 2>&1 || true
  if [[ -n "$pop_priv_file" ]]; then
    rm -f "$pop_priv_file"
  fi
  if [[ -n "$token_file" ]]; then
    rm -f "$token_file"
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

sleep 2

pop_json=$(go run ./cmd/tokenpop gen)
POP_PUBLIC_KEY=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
POP_PRIVATE_KEY=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$POP_PUBLIC_KEY" || -z "$POP_PRIVATE_KEY" ]]; then
  echo "failed to generate token PoP keypair"
  redact_sensitive_json "$pop_json"
  exit 1
fi

TOKEN=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-challenge-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$POP_PUBLIC_KEY\",\"exit_scope\":[\"exit-local-1\"]}" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

if [[ -z "$TOKEN" ]]; then
  echo "failed to fetch token"
  cat "$node_log"
  exit 1
fi

CLIENT_PUB="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
TOKEN_PROOF_NONCE="$(date +%s%N)-challenge"
pop_priv_file="$tmp_dir/tokenpop_private.key"
printf '%s' "$POP_PRIVATE_KEY" >"$pop_priv_file"
chmod 600 "$pop_priv_file"
token_file="$tmp_dir/token.jwt"
printf '%s' "$TOKEN" >"$token_file"
chmod 600 "$token_file"
TOKEN_PROOF=$(go run ./cmd/tokenpop sign \
  --private-key-file "$pop_priv_file" \
  --token-file "$token_file" \
  --exit-id "exit-local-1" \
  --proof-nonce "$TOKEN_PROOF_NONCE" \
  --client-inner-pub "$CLIENT_PUB" \
  --transport "policy-json" \
  --requested-mtu 1280 \
  --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
if [[ -z "$TOKEN_PROOF" ]]; then
  echo "failed to sign token proof"
  cat "$node_log"
  exit 1
fi

PAYLOAD=$(cat <<JSON
{"exit_id":"exit-local-1","token":"$TOKEN","token_proof":"$TOKEN_PROOF","token_proof_nonce":"$TOKEN_PROOF_NONCE","client_inner_pub":"$CLIENT_PUB","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)

curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$PAYLOAD" >"$first_resp"
curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$PAYLOAD" >"$second_resp"

if ! rg -q 'challenge-required' "$second_resp"; then
  echo "expected challenge-required response"
  cat "$second_resp"
  cat "$node_log"
  exit 1
fi

echo "challenge integration check ok"
