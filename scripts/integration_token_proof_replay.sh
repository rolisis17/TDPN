#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

umask 077
DIRECTORY_ADDR="${TOKEN_PROOF_REPLAY_DIRECTORY_ADDR:-127.0.0.1:18201}"
ISSUER_ADDR="${TOKEN_PROOF_REPLAY_ISSUER_ADDR:-127.0.0.1:18202}"
ENTRY_ADDR="${TOKEN_PROOF_REPLAY_ENTRY_ADDR:-127.0.0.1:18203}"
EXIT_ADDR="${TOKEN_PROOF_REPLAY_EXIT_ADDR:-127.0.0.1:18204}"
DIRECTORY_URL="http://${DIRECTORY_ADDR}"
ISSUER_URL="http://${ISSUER_ADDR}"
ENTRY_URL="http://${ENTRY_ADDR}"
EXIT_CONTROL_URL="http://${EXIT_ADDR}"
ENTRY_DATA_ADDR="${TOKEN_PROOF_REPLAY_ENTRY_DATA_ADDR:-127.0.0.1:53220}"
EXIT_DATA_ADDR="${TOKEN_PROOF_REPLAY_EXIT_DATA_ADDR:-127.0.0.1:53221}"
node_log="$(mktemp "${TMPDIR:-/tmp}/token_proof_replay_node.XXXXXX.log")"
pop_priv_file=""
token_file=""
node_pid=""

cleanup() {
  kill "${node_pid:-}" >/dev/null 2>&1 || true
  rm -f "$node_log" "${pop_priv_file:-}" "${token_file:-}"
}
trap cleanup EXIT

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

wait_for_http_ok() {
  local label="$1"
  local url="$2"
  local code=""
  for _ in $(seq 1 80); do
    if [[ -n "${node_pid:-}" ]] && ! kill -0 "$node_pid" >/dev/null 2>&1; then
      echo "node exited before $label became ready"
      cat "$node_log"
      exit 1
    fi
    code="$(curl -sS --max-time 1 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)"
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    sleep 0.25
  done
  echo "timed out waiting for $label at $url"
  cat "$node_log"
  exit 1
}

EXIT_TOKEN_PROOF_REPLAY_GUARD=1 \
DIRECTORY_ADDR="$DIRECTORY_ADDR" \
ISSUER_ADDR="$ISSUER_ADDR" \
ENTRY_ADDR="$ENTRY_ADDR" \
EXIT_ADDR="$EXIT_ADDR" \
DIRECTORY_URL="$DIRECTORY_URL" \
ISSUER_URL="$ISSUER_URL" \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
DIRECTORY_ISSUER_TRUST_URLS="$ISSUER_URL" \
DIRECTORY_TRUST_STRICT=0 \
ENTRY_DIRECTORY_TRUST_STRICT=0 \
ENTRY_LIVE_WG_MODE=0 \
DATA_PLANE_MODE=json \
ENTRY_DATA_ADDR="$ENTRY_DATA_ADDR" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
timeout 35s go run ./cmd/node --directory --issuer --entry --exit >"$node_log" 2>&1 &
node_pid=$!

wait_for_http_ok "issuer" "$ISSUER_URL/v1/health"
wait_for_http_ok "entry" "$ENTRY_URL/v1/health"

pop_json=$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)
pop_pub=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
pop_priv=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$pop_pub" || -z "$pop_priv" ]]; then
  echo "failed to generate token PoP keypair"
  redact_token_json "$pop_json"
  exit 1
fi

token_json=$(curl -sS -X POST "$ISSUER_URL/v1/token" -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-proof-replay-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"],\"transport\":\"policy-json\"}")
token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$token" ]]; then
  echo "failed to parse token"
  redact_token_json "$token_json"
  cat "$node_log"
  exit 1
fi

pop_priv_file="$(mktemp "${TMPDIR:-/tmp}/token_proof_replay_priv.XXXXXX.key")"
token_file="$(mktemp "${TMPDIR:-/tmp}/token_proof_replay_token.XXXXXX.txt")"
chmod 600 "$pop_priv_file" "$token_file"
printf '%s' "$pop_priv" >"$pop_priv_file"
printf '%s' "$token" >"$token_file"

client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
nonce_1="replay-nonce-1"
session_id_1="token-proof-replay-session-1"
proof_1=$(go run ./cmd/tokenpop sign \
  --private-key-file "$pop_priv_file" \
  --token-file "$token_file" \
  --exit-id "exit-local-1" \
  --session-id "$session_id_1" \
  --proof-nonce "$nonce_1" \
  --client-inner-pub "$client_pub" \
  --transport "policy-json" \
  --requested-mtu 1280 \
  --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
if [[ -z "$proof_1" ]]; then
  echo "failed to sign first proof"
  cat "$node_log"
  exit 1
fi

payload_1=$(cat <<JSON
{"exit_id":"exit-local-1","session_id":"$session_id_1","token":"$token","token_proof":"$proof_1","token_proof_nonce":"$nonce_1","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)

first=$(curl -sS -X POST "$ENTRY_URL/v1/path/open" -H 'Content-Type: application/json' --data "$payload_1")
if ! echo "$first" | rg -q '"accepted":true'; then
  echo "expected first path open accepted"
  echo "$first"
  cat "$node_log"
  exit 1
fi

second=$(curl -sS -X POST "$ENTRY_URL/v1/path/open" -H 'Content-Type: application/json' --data "$payload_1")
if ! echo "$second" | rg -q 'token proof replay'; then
  echo "expected replay denial on second path open"
  echo "$second"
  cat "$node_log"
  exit 1
fi

nonce_2="replay-nonce-2"
session_id_2="token-proof-replay-session-2"
proof_2=$(go run ./cmd/tokenpop sign \
  --private-key-file "$pop_priv_file" \
  --token-file "$token_file" \
  --exit-id "exit-local-1" \
  --session-id "$session_id_2" \
  --proof-nonce "$nonce_2" \
  --client-inner-pub "$client_pub" \
  --transport "policy-json" \
  --requested-mtu 1280 \
  --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
if [[ -z "$proof_2" ]]; then
  echo "failed to sign second proof"
  cat "$node_log"
  exit 1
fi

payload_2=$(cat <<JSON
{"exit_id":"exit-local-1","session_id":"$session_id_2","token":"$token","token_proof":"$proof_2","token_proof_nonce":"$nonce_2","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)

third=$(curl -sS -X POST "$ENTRY_URL/v1/path/open" -H 'Content-Type: application/json' --data "$payload_2")
if ! echo "$third" | rg -q '"accepted":true'; then
  echo "expected third path open accepted with new nonce"
  echo "$third"
  cat "$node_log"
  exit 1
fi

echo "token proof replay integration check ok"
