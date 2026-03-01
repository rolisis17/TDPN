#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in go curl rg sed timeout base64; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

LOG_FILE="/tmp/integration_anon_credential_dispute.log"
PAYLOAD_TMP="/tmp/integration_anon_credential_dispute_payload.json"
rm -f "$LOG_FILE"

timeout 25s go run ./cmd/node --directory --issuer --entry --exit >"$LOG_FILE" 2>&1 &
node_pid=$!
trap 'kill "$node_pid" >/dev/null 2>&1 || true; rm -f "$PAYLOAD_TMP"' EXIT

sleep 2

credential_id="anon-dispute-integration-1"
issue_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/admin/anon-credential/issue \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"credential_id\":\"$credential_id\",\"tier\":3,\"reason\":\"integration-test\"}")
anon_cred=$(echo "$issue_json" | sed -n 's/.*"credential":"\([^"]*\)".*/\1/p')
if [[ -z "$anon_cred" ]]; then
  echo "failed to issue anonymous credential"
  echo "$issue_json"
  cat "$LOG_FILE"
  exit 1
fi

pop_json=$(go run ./cmd/tokenpop gen)
pop_pub=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
if [[ -z "$pop_pub" ]]; then
  echo "failed to generate token PoP keypair"
  echo "$pop_json"
  exit 1
fi

decode_token_tier() {
  local token="$1"
  local payload
  payload="${token%%.*}"
  payload="${payload//-/+}"
  payload="${payload//_/\/}"
  case $(( ${#payload} % 4 )) in
    2) payload="${payload}==" ;;
    3) payload="${payload}=" ;;
    1) payload="${payload}===" ;;
  esac
  if printf '%s' "$payload" | base64 -d >"$PAYLOAD_TMP" 2>/dev/null; then
    sed -n 's/.*"tier":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$PAYLOAD_TMP"
    return
  fi
  if printf '%s' "$payload" | base64 --decode >"$PAYLOAD_TMP" 2>/dev/null; then
    sed -n 's/.*"tier":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$PAYLOAD_TMP"
    return
  fi
  if printf '%s' "$payload" | base64 -D >"$PAYLOAD_TMP" 2>/dev/null; then
    sed -n 's/.*"tier":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$PAYLOAD_TMP"
    return
  fi
  return 1
}

issue_client_token() {
  local requested_tier="$1"
  curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
    --data "{\"tier\":$requested_tier,\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"],\"anon_cred\":\"$anon_cred\"}"
}

token_json=$(issue_client_token 3)
token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$token" ]]; then
  echo "failed to issue baseline token with anonymous credential"
  echo "$token_json"
  cat "$LOG_FILE"
  exit 1
fi
baseline_tier="$(decode_token_tier "$token")"
if [[ "$baseline_tier" != "3" ]]; then
  echo "expected baseline anonymous credential token tier 3, got $baseline_tier"
  echo "$token_json"
  cat "$LOG_FILE"
  exit 1
fi

dispute_until=$(( $(date +%s) + 180 ))
dispute_resp=$(curl -sS -X POST http://127.0.0.1:8082/v1/admin/anon-credential/dispute \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"credential_id\":\"$credential_id\",\"tier_cap\":1,\"until\":$dispute_until,\"case_id\":\"case-anon-dispute-1\",\"evidence_ref\":\"evidence://anon-dispute-1\",\"reason\":\"integration-test\"}")
if ! echo "$dispute_resp" | rg -q "\"credential_id\":\"$credential_id\""; then
  echo "failed to apply anonymous credential dispute cap"
  echo "$dispute_resp"
  cat "$LOG_FILE"
  exit 1
fi
status_disputed=$(curl -sS -G http://127.0.0.1:8082/v1/admin/anon-credential/get \
  -H 'X-Admin-Token: dev-admin-token' \
  --data-urlencode "credential_id=$credential_id")
if ! echo "$status_disputed" | rg -q '"disputed":true'; then
  echo "expected disputed status after anonymous credential dispute apply"
  echo "$status_disputed"
  cat "$LOG_FILE"
  exit 1
fi
if ! echo "$status_disputed" | rg -q '"dispute_tier_cap":1'; then
  echo "expected dispute_tier_cap=1 in anonymous credential status"
  echo "$status_disputed"
  cat "$LOG_FILE"
  exit 1
fi

token_json_capped=$(issue_client_token 3)
token_capped=$(echo "$token_json_capped" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$token_capped" ]]; then
  echo "failed to issue token after anonymous credential dispute cap"
  echo "$token_json_capped"
  cat "$LOG_FILE"
  exit 1
fi
capped_tier="$(decode_token_tier "$token_capped")"
if [[ "$capped_tier" != "1" ]]; then
  echo "expected disputed anonymous credential token tier 1, got $capped_tier"
  echo "$token_json_capped"
  cat "$LOG_FILE"
  exit 1
fi

clear_resp=$(curl -sS -X POST http://127.0.0.1:8082/v1/admin/anon-credential/dispute/clear \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"credential_id\":\"$credential_id\",\"reason\":\"resolved\"}")
if ! echo "$clear_resp" | rg -q '"cleared":true'; then
  echo "failed to clear anonymous credential dispute cap"
  echo "$clear_resp"
  cat "$LOG_FILE"
  exit 1
fi
status_cleared=$(curl -sS -G http://127.0.0.1:8082/v1/admin/anon-credential/get \
  -H 'X-Admin-Token: dev-admin-token' \
  --data-urlencode "credential_id=$credential_id")
if ! echo "$status_cleared" | rg -q '"disputed":false'; then
  echo "expected disputed=false after anonymous credential dispute clear"
  echo "$status_cleared"
  cat "$LOG_FILE"
  exit 1
fi

token_json_restored=$(issue_client_token 3)
token_restored=$(echo "$token_json_restored" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$token_restored" ]]; then
  echo "failed to issue token after anonymous credential dispute clear"
  echo "$token_json_restored"
  cat "$LOG_FILE"
  exit 1
fi
restored_tier="$(decode_token_tier "$token_restored")"
if [[ "$restored_tier" != "3" ]]; then
  echo "expected restored anonymous credential token tier 3, got $restored_tier"
  echo "$token_json_restored"
  cat "$LOG_FILE"
  exit 1
fi

echo "anonymous credential dispute integration check ok"
