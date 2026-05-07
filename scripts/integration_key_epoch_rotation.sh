#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

ISSUER_KEY_ROTATE_SEC="${ISSUER_KEY_ROTATE_SEC:-2}"
EXIT_REVOCATION_REFRESH_SEC="${EXIT_REVOCATION_REFRESH_SEC:-1}"
ISSUER_KEY_HISTORY="${ISSUER_KEY_HISTORY:-4}"
DIRECTORY_ADDR="${KEY_EPOCH_DIRECTORY_ADDR:-127.0.0.1:18101}"
ISSUER_ADDR="${KEY_EPOCH_ISSUER_ADDR:-127.0.0.1:18102}"
ENTRY_ADDR="${KEY_EPOCH_ENTRY_ADDR:-127.0.0.1:18103}"
EXIT_ADDR="${KEY_EPOCH_EXIT_ADDR:-127.0.0.1:18104}"
DIRECTORY_URL="http://${DIRECTORY_ADDR}"
ISSUER_URL_KEY_EPOCH="http://${ISSUER_ADDR}"
ENTRY_URL="http://${ENTRY_ADDR}"
EXIT_CONTROL_URL="http://${EXIT_ADDR}"
ENTRY_DATA_ADDR="${KEY_EPOCH_ENTRY_DATA_ADDR:-127.0.0.1:53120}"
EXIT_DATA_ADDR="${KEY_EPOCH_EXIT_DATA_ADDR:-127.0.0.1:53121}"
TMP_DIR="$(mktemp -d)"
NODE_LOG="$TMP_DIR/key_epoch_node.log"

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

ISSUER_KEY_ROTATE_SEC="$ISSUER_KEY_ROTATE_SEC" \
EXIT_REVOCATION_REFRESH_SEC="$EXIT_REVOCATION_REFRESH_SEC" \
ISSUER_KEY_HISTORY="$ISSUER_KEY_HISTORY" \
DIRECTORY_ADDR="$DIRECTORY_ADDR" \
ISSUER_ADDR="$ISSUER_ADDR" \
ENTRY_ADDR="$ENTRY_ADDR" \
EXIT_ADDR="$EXIT_ADDR" \
DIRECTORY_URL="$DIRECTORY_URL" \
ISSUER_URL="$ISSUER_URL_KEY_EPOCH" \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
DIRECTORY_ISSUER_TRUST_URLS="$ISSUER_URL_KEY_EPOCH" \
DIRECTORY_TRUST_STRICT=0 \
ENTRY_DIRECTORY_TRUST_STRICT=0 \
ENTRY_LIVE_WG_MODE=0 \
DATA_PLANE_MODE=json \
ENTRY_DATA_ADDR="$ENTRY_DATA_ADDR" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
timeout 45s go run ./cmd/node --directory --issuer --entry --exit >"$NODE_LOG" 2>&1 &
node_pid=$!
TOKEN_POP_PRIVATE_KEY_FILE=""
TOKEN_POP_FILE=""
trap 'kill $node_pid >/dev/null 2>&1 || true; rm -f "${TOKEN_POP_PRIVATE_KEY_FILE:-}" "${TOKEN_POP_FILE:-}"; rm -rf "$TMP_DIR"' EXIT

sleep 3

TOKEN_POP_PRIVATE_KEY_FILE="$(mktemp)"
TOKEN_POP_FILE="$(mktemp)"
chmod 600 "$TOKEN_POP_PRIVATE_KEY_FILE" "$TOKEN_POP_FILE"

TOKEN_POP_PRIVATE_KEY=""
ISSUE_TOKEN_JSON=""
issue_token() {
  local pop_json pop_pub pop_priv
  pop_json=$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)
  pop_pub=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
  pop_priv=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
  if [[ -z "$pop_pub" || -z "$pop_priv" ]]; then
    echo "failed to generate PoP keypair for token" >&2
    redact_token_json "$pop_json" >&2
    return 1
  fi
  TOKEN_POP_PRIVATE_KEY="$pop_priv"
  ISSUE_TOKEN_JSON=$(curl -sS -X POST "$ISSUER_URL_KEY_EPOCH/v1/token" \
    -H 'Content-Type: application/json' \
    --data "{\"tier\":1,\"subject\":\"client-key-epoch-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"],\"transport\":\"policy-json\"}")
}

path_open() {
  local token="$1"
  local pop_priv="$2"
  local client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  local token_proof_nonce
  token_proof_nonce="$(date +%s%N)-key-epoch-$RANDOM"
  local session_id="key-epoch-${token_proof_nonce}"
  printf '%s' "$pop_priv" >"$TOKEN_POP_PRIVATE_KEY_FILE"
  printf '%s' "$token" >"$TOKEN_POP_FILE"
  local token_proof
  token_proof=$(go run ./cmd/tokenpop sign \
    --private-key-file "$TOKEN_POP_PRIVATE_KEY_FILE" \
    --token-file "$TOKEN_POP_FILE" \
    --exit-id "exit-local-1" \
    --session-id "$session_id" \
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
{"exit_id":"exit-local-1","session_id":"$session_id","token":"$token","token_proof":"$token_proof","token_proof_nonce":"$token_proof_nonce","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)
  curl -sS -X POST "$ENTRY_URL/v1/path/open" -H 'Content-Type: application/json' --data "$payload"
}

issue_token
token_json_1="$ISSUE_TOKEN_JSON"
token_1=$(echo "$token_json_1" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
token_1_pop_priv="$TOKEN_POP_PRIVATE_KEY"
if [[ -z "$token_1" ]]; then
  echo "failed to issue initial token"
  redact_token_json "$token_json_1"
  cat "$NODE_LOG"
  exit 1
fi

first=$(path_open "$token_1" "$token_1_pop_priv")
if ! echo "$first" | rg -q '"accepted":true'; then
  echo "expected initial token accepted"
  echo "$first"
  cat "$NODE_LOG"
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
  cat "$NODE_LOG"
  exit 1
fi

issue_token
token_json_2="$ISSUE_TOKEN_JSON"
token_2=$(echo "$token_json_2" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
token_2_pop_priv="$TOKEN_POP_PRIVATE_KEY"
if [[ -z "$token_2" ]]; then
  echo "failed to issue rotated-epoch token"
  redact_token_json "$token_json_2"
  cat "$NODE_LOG"
  exit 1
fi

second=$(path_open "$token_2" "$token_2_pop_priv")
if ! echo "$second" | rg -q '"accepted":true'; then
  echo "expected fresh token accepted after rotation"
  echo "$second"
  cat "$NODE_LOG"
  exit 1
fi

echo "key-epoch rotation integration check ok"
