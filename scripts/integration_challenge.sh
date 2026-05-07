#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

redact_sensitive_json() {
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

ENTRY_OPEN_RPS="${ENTRY_OPEN_RPS:-1}"
ENTRY_PUZZLE_DIFFICULTY="${ENTRY_PUZZLE_DIFFICULTY:-1}"
BASE_PORT="${INTEGRATION_CHALLENGE_BASE_PORT:-23180}"
DIRECTORY_ADDR="${INTEGRATION_CHALLENGE_DIRECTORY_ADDR:-127.0.0.1:$((BASE_PORT + 1))}"
ISSUER_ADDR="${INTEGRATION_CHALLENGE_ISSUER_ADDR:-127.0.0.1:$((BASE_PORT + 2))}"
ENTRY_ADDR="${INTEGRATION_CHALLENGE_ENTRY_ADDR:-127.0.0.1:$((BASE_PORT + 3))}"
EXIT_ADDR="${INTEGRATION_CHALLENGE_EXIT_ADDR:-127.0.0.1:$((BASE_PORT + 4))}"
ENTRY_DATA_ADDR="${INTEGRATION_CHALLENGE_ENTRY_DATA_ADDR:-127.0.0.1:$((BASE_PORT + 20))}"
EXIT_DATA_ADDR="${INTEGRATION_CHALLENGE_EXIT_DATA_ADDR:-127.0.0.1:$((BASE_PORT + 21))}"
DIRECTORY_URL="http://${DIRECTORY_ADDR}"
ISSUER_URL="http://${ISSUER_ADDR}"
ENTRY_URL="http://${ENTRY_ADDR}"
EXIT_URL="http://${EXIT_ADDR}"

old_umask="$(umask)"
umask 077
tmp_dir="$(mktemp -d /tmp/integration_challenge.XXXXXX)"
umask "$old_umask"
pop_priv_file=""
token_file=""
node_log="$tmp_dir/challenge_node.log"
first_resp="$tmp_dir/challenge_first.json"
second_resp="$tmp_dir/challenge_second.json"

wait_for_http_ready() {
  local url="$1"
  local label="$2"
  local deadline=$((SECONDS + 20))
  while ((SECONDS < deadline)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$node_pid" >/dev/null 2>&1; then
      echo "node exited before ${label} became ready"
      cat "$node_log"
      return 1
    fi
    sleep 0.2
  done
  echo "timed out waiting for ${label} (${url})"
  cat "$node_log"
  return 1
}

DIRECTORY_ADDR="$DIRECTORY_ADDR" \
DIRECTORY_PRIVATE_KEY_FILE="$tmp_dir/directory.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/directory_provider_replay.json" \
ISSUER_ADDR="$ISSUER_ADDR" \
ISSUER_PRIVATE_KEY_FILE="$tmp_dir/issuer.key" \
ISSUER_REVOCATIONS_FILE="$tmp_dir/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$tmp_dir/issuer_anon_revocations.json" \
ENTRY_ADDR="$ENTRY_ADDR" \
ENTRY_URL="$ENTRY_URL" \
ENTRY_DATA_ADDR="$ENTRY_DATA_ADDR" \
EXIT_ADDR="$EXIT_ADDR" \
EXIT_CONTROL_URL="$EXIT_URL" \
EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
DIRECTORY_URL="$DIRECTORY_URL" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$tmp_dir/trusted_directory_keys.txt" \
ISSUER_URL="$ISSUER_URL" \
ISSUER_URLS="$ISSUER_URL" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/exit_token_replay.json" \
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

wait_for_http_ready "$ISSUER_URL/v1/health" "issuer"
wait_for_http_ready "$ENTRY_URL/v1/health" "entry"

pop_json=$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)
POP_PUBLIC_KEY=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
POP_PRIVATE_KEY=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$POP_PUBLIC_KEY" || -z "$POP_PRIVATE_KEY" ]]; then
  echo "failed to generate token PoP keypair"
  redact_sensitive_json "$pop_json"
  exit 1
fi

TOKEN=$(curl -sS -X POST "$ISSUER_URL/v1/token" -H 'Content-Type: application/json' \
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

curl -sS -X POST "$ENTRY_URL/v1/path/open" -H 'Content-Type: application/json' --data "$PAYLOAD" >"$first_resp"
curl -sS -X POST "$ENTRY_URL/v1/path/open" -H 'Content-Type: application/json' --data "$PAYLOAD" >"$second_resp"

if ! rg -q 'challenge-required' "$second_resp"; then
  echo "expected challenge-required response"
  cat "$second_resp"
  cat "$node_log"
  exit 1
fi

echo "challenge integration check ok"
