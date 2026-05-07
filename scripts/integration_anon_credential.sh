#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in go curl rg sed timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

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

umask 077
tmp_dir="$(mktemp -d)"
LOG_FILE="$tmp_dir/integration_anon_credential.log"
DENIED_FILE="$tmp_dir/integration_anon_credential_denied.txt"
TRUST_FILE="$tmp_dir/directory_trust.txt"
ADMIN_TOKEN="integration-admin-token"
DIR_PORT=19321
ISSUER_PORT=19322
ENTRY_PORT=19323
EXIT_PORT=19324
ENTRY_DATA_PORT=20321
EXIT_DATA_PORT=20322
EXIT_WG_PORT=20323
DIR_URL="http://127.0.0.1:${DIR_PORT}"
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}"
ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}"
EXIT_URL="http://127.0.0.1:${EXIT_PORT}"
pop_priv_file=""
token_file=""
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

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  exit 1
fi

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
DIRECTORY_PUBLIC_URL="$DIR_URL" \
DIRECTORY_URL="$DIR_URL" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
DIRECTORY_PRIVATE_KEY_FILE="$tmp_dir/directory.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/directory_provider_replay.json" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_URL="$ISSUER_URL" \
ISSUER_ADMIN_TOKEN="$ADMIN_TOKEN" \
ISSUER_PRIVATE_KEY_FILE="$tmp_dir/issuer.key" \
ISSUER_SUBJECTS_FILE="$tmp_dir/issuer_subjects.json" \
ISSUER_REVOCATIONS_FILE="$tmp_dir/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$tmp_dir/issuer_anon_revocations.json" \
ISSUER_ANON_DISPUTES_FILE="$tmp_dir/issuer_anon_disputes.json" \
ISSUER_AUDIT_FILE="$tmp_dir/issuer_audit.json" \
ENTRY_ADDR="127.0.0.1:${ENTRY_PORT}" \
ENTRY_URL="$ENTRY_URL" \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
ENTRY_LIVE_WG_MODE=0 \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_ADDR="127.0.0.1:${EXIT_PORT}" \
EXIT_CONTROL_URL="$EXIT_URL" \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
EXIT_WG_LISTEN_PORT="$EXIT_WG_PORT" \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$tmp_dir/exit_token_replay.json" \
timeout 25s go run ./cmd/node --directory --issuer --entry --exit >"$LOG_FILE" 2>&1 &
node_pid=$!
trap cleanup EXIT

wait_http_ready() {
  local url="$1"
  local tries="${2:-50}"
  for _ in $(seq 1 "$tries"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

if ! wait_http_ready "${DIR_URL}/v1/relays" 60 || \
   ! wait_http_ready "${ISSUER_URL}/v1/pubkeys" 60 || \
   ! wait_http_ready "${ENTRY_URL}/v1/health" 60 || \
   ! wait_http_ready "${EXIT_URL}/v1/health" 60; then
  echo "node services did not become ready before anon-credential checks"
  cat "$LOG_FILE"
  exit 1
fi

credential_id="anon-integration-$(date +%s%N)"
issue_json=$(curl -sS -X POST "${ISSUER_URL}/v1/admin/anon-credential/issue" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data "{\"credential_id\":\"$credential_id\",\"tier\":2,\"reason\":\"integration-test\"}")
anon_cred=$(echo "$issue_json" | sed -n 's/.*"credential":"\([^"]*\)".*/\1/p')
if [[ -z "$anon_cred" ]]; then
  echo "failed to issue anonymous credential"
  redact_sensitive_json "$issue_json"
  cat "$LOG_FILE"
  exit 1
fi

pop_json=$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)
pop_pub=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
pop_priv=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$pop_pub" || -z "$pop_priv" ]]; then
  echo "failed to generate token PoP keypair"
  redact_sensitive_json "$pop_json"
  exit 1
fi

token_json=$(curl -sS -X POST "${ISSUER_URL}/v1/token" -H 'Content-Type: application/json' \
  --data "{\"tier\":2,\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"],\"anon_cred\":\"$anon_cred\"}")
token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$token" ]]; then
  echo "failed to issue token with anonymous credential"
  redact_sensitive_json "$token_json"
  cat "$LOG_FILE"
  exit 1
fi

pop_priv_file="$tmp_dir/tokenpop_priv.key"
printf '%s' "$pop_priv" >"$pop_priv_file"
chmod 600 "$pop_priv_file"
token_file="$tmp_dir/token.jwt"
printf '%s' "$token" >"$token_file"
chmod 600 "$token_file"

client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
token_proof_nonce="$(date +%s%N)-anon"
session_id="anon-session-$(date +%s%N)"
token_proof=$(go run ./cmd/tokenpop sign \
  --private-key-file "$pop_priv_file" \
  --token-file "$token_file" \
  --exit-id "exit-local-1" \
  --session-id "$session_id" \
  --proof-nonce "$token_proof_nonce" \
  --client-inner-pub "$client_pub" \
  --transport "policy-json" \
  --requested-mtu 1280 \
  --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
if [[ -z "$token_proof" ]]; then
  echo "failed to sign token proof"
  exit 1
fi

path_payload=$(cat <<JSON
{"exit_id":"exit-local-1","session_id":"$session_id","token":"$token","token_proof":"$token_proof","token_proof_nonce":"$token_proof_nonce","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)

open_resp=$(curl -sS -X POST "${ENTRY_URL}/v1/path/open" -H 'Content-Type: application/json' --data "$path_payload")
if ! echo "$open_resp" | rg -q '"accepted":true'; then
  echo "expected path open accepted for anonymous-credential token"
  echo "$open_resp"
  cat "$LOG_FILE"
  exit 1
fi

until=$(( $(date +%s) + 120 ))
revoke_resp=$(curl -sS -X POST "${ISSUER_URL}/v1/admin/anon-credential/revoke" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data "{\"credential_id\":\"$credential_id\",\"until\":$until,\"reason\":\"integration-test\"}")
if ! echo "$revoke_resp" | rg -q "\"credential_id\":\"$credential_id\""; then
  echo "failed to revoke anonymous credential"
  echo "$revoke_resp"
  cat "$LOG_FILE"
  exit 1
fi

status_code=$(curl -sS -o "$DENIED_FILE" -w '%{http_code}' \
  -X POST "${ISSUER_URL}/v1/token" \
  -H 'Content-Type: application/json' \
  --data "{\"tier\":2,\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"],\"anon_cred\":\"$anon_cred\"}")
if [[ "$status_code" != "403" ]]; then
  echo "expected token issuance denial with revoked anonymous credential"
  echo "status_code=$status_code body=$(cat "$DENIED_FILE")"
  cat "$LOG_FILE"
  exit 1
fi
if ! rg -q "anonymous credential revoked" "$DENIED_FILE"; then
  echo "missing revoked anonymous credential denial reason"
  cat "$DENIED_FILE"
  cat "$LOG_FILE"
  exit 1
fi

echo "anonymous credential integration check ok"
