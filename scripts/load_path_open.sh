#!/usr/bin/env bash
set -euo pipefail

ENTRY_URL="${ENTRY_URL:-http://127.0.0.1:8083}"
TOKEN="${TOKEN:-}"
TOKEN_PROOF="${TOKEN_PROOF:-}"
TOKEN_PROOF_NONCE="${TOKEN_PROOF_NONCE:-}"
EXIT_ID="${EXIT_ID:-exit-local-1}"
CLIENT_PUB="${CLIENT_WG_PUBLIC_KEY:-}"
REQS="${REQS:-200}"
CONCURRENCY="${CONCURRENCY:-20}"

if [[ -z "$TOKEN" ]]; then
  echo "TOKEN is required"
  exit 1
fi
if [[ -z "$TOKEN_PROOF" ]]; then
  echo "TOKEN_PROOF is required"
  exit 1
fi
if [[ -z "$TOKEN_PROOF_NONCE" ]]; then
  echo "TOKEN_PROOF_NONCE is required"
  exit 1
fi
if [[ -z "$CLIENT_PUB" ]]; then
  echo "CLIENT_WG_PUBLIC_KEY is required"
  exit 1
fi

PAYLOAD_FILE=/tmp/path_open_payload.json
cat >"$PAYLOAD_FILE" <<JSON
{"exit_id":"$EXIT_ID","token":"$TOKEN","token_proof":"$TOKEN_PROOF","token_proof_nonce":"$TOKEN_PROOF_NONCE","client_inner_pub":"$CLIENT_PUB","transport":"wireguard-udp","requested_mtu":1280,"requested_region":"local"}
JSON

export ENTRY_URL PAYLOAD_FILE

seq "$REQS" | xargs -P "$CONCURRENCY" -I{} sh -c '
  curl -sS -o /tmp/path_open_{}.json -w "%{http_code}\n" \
    -H "Content-Type: application/json" \
    -X POST "$ENTRY_URL/v1/path/open" \
    --data @"$PAYLOAD_FILE" >/tmp/path_open_status_{}.txt
'

ok=$(rg -l "200" /tmp/path_open_status_* | wc -l | tr -d ' ')
echo "completed requests=$REQS http200=$ok"
