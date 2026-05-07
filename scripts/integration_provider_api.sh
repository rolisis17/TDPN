#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

umask 077
tmp_dir="$(mktemp -d)"
node_log="$tmp_dir/provider_api_node.log"
low_exit_resp="$tmp_dir/provider_api_low_exit.json"
cap_resp="$tmp_dir/provider_api_cap.json"
reject_resp="$tmp_dir/provider_api_reject.json"
issuer_subjects_file="$tmp_dir/issuer_subjects.json"
sponsor_token="integration-provider-api-sponsor-token"
DIRECTORY_ADDR="${PROVIDER_API_DIRECTORY_ADDR:-127.0.0.1:18081}"
ISSUER_ADDR="${PROVIDER_API_ISSUER_ADDR:-127.0.0.1:18082}"
DIRECTORY_URL="http://${DIRECTORY_ADDR}"
ISSUER_URL_PROVIDER="http://${ISSUER_ADDR}"

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

validate_bearer_token_or_die() {
  local token="$1"
  if [[ -z "$token" ]]; then
    echo "refusing empty bearer token for curl auth config" >&2
    return 1
  fi
  if ((${#token} > 4096)); then
    echo "refusing oversized bearer token for curl auth config" >&2
    return 1
  fi
  if printf '%s' "$token" | LC_ALL=C grep -q '[[:cntrl:][:space:]]'; then
    echo "refusing bearer token with whitespace/control characters for curl auth config" >&2
    return 1
  fi
  if [[ "$token" == *\"* || "$token" == *\\* ]]; then
    echo "refusing bearer token with unsafe quote/backslash characters for curl auth config" >&2
    return 1
  fi
}

write_bearer_curl_config() {
  local token="$1"
  local cfg_file
  validate_bearer_token_or_die "$token"
  cfg_file="$(mktemp "$tmp_dir/curl_auth.XXXXXX.cfg")"
  printf 'header = "Authorization: Bearer %s"\n' "$token" >"$cfg_file"
  printf '%s\n' "$cfg_file"
}

curl_with_bearer_config() {
  local token="$1"
  shift
  local cfg_file
  local rc
  cfg_file="$(write_bearer_curl_config "$token")"
  if curl --config "$cfg_file" "$@"; then
    rc=0
  else
    rc=$?
  fi
  rm -f "$cfg_file"
  return "$rc"
}

cleanup() {
  kill "$node_pid" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}

wait_for_http_ready() {
  local url="$1"
  local label="$2"
  local timeout_sec="${3:-20}"
  local deadline=$((SECONDS + timeout_sec))
  while ((SECONDS < deadline)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for ${label} (${url})"
  cat "$node_log"
  return 1
}

write_sign_provider_upsert_proof_tool() {
  cat >"$tmp_dir/sign_provider_upsert_proof.go" <<'GO'
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	privateKey := flag.String("private-key", "", "base64url-encoded ed25519 private key")
	tokenID := flag.String("token-id", "", "provider token id")
	subject := flag.String("subject", "", "provider operator subject")
	relayID := flag.String("relay-id", "", "relay id")
	role := flag.String("role", "", "relay role")
	pubKey := flag.String("pub-key", "", "relay pub key")
	endpoint := flag.String("endpoint", "", "relay endpoint")
	controlURL := flag.String("control-url", "", "relay control url")
	nonce := flag.String("nonce", "", "proof nonce")
	flag.Parse()

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(*privateKey))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		exitf("invalid private key")
	}
	normalizedRole := strings.TrimSpace(strings.ToLower(*role))
	switch normalizedRole {
	case "micro_relay", "middle", "relay", "transit", "three-hop-middle":
		normalizedRole = "micro-relay"
	case "micro_exit", "client-exit", "contribution-exit":
		normalizedRole = "micro-exit"
	}
	payload := struct {
		Context    string `json:"context"`
		TokenID    string `json:"token_id"`
		Subject    string `json:"subject"`
		RelayID    string `json:"relay_id"`
		Role       string `json:"role"`
		PubKey     string `json:"pub_key"`
		Endpoint   string `json:"endpoint"`
		ControlURL string `json:"control_url"`
		Nonce      string `json:"nonce"`
	}{
		Context:    "provider_relay_upsert_v1",
		TokenID:    strings.TrimSpace(*tokenID),
		Subject:    strings.ToLower(strings.TrimSpace(*subject)),
		RelayID:    strings.TrimSpace(*relayID),
		Role:       normalizedRole,
		PubKey:     strings.TrimSpace(*pubKey),
		Endpoint:   strings.TrimSpace(*endpoint),
		ControlURL: strings.TrimSpace(*controlURL),
		Nonce:      strings.TrimSpace(*nonce),
	}
	msg, err := json.Marshal(payload)
	if err != nil {
		exitf("marshal proof payload: %v", err)
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(raw), msg)))
}

func exitf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
GO
}

sign_provider_upsert_proof() {
  go run "$tmp_dir/sign_provider_upsert_proof.go" "$@"
}

cat >"$issuer_subjects_file" <<'JSON'
{
  "provider-op-1": {
    "subject": "provider-op-1",
    "kind": "relay-exit",
    "tier": 2,
    "reputation": 1,
    "bond": 500
  },
  "provider-op-micro": {
    "subject": "provider-op-micro",
    "kind": "relay-exit",
    "tier": 1,
    "reputation": 1,
    "bond": 500
  }
}
JSON

timeout 25s env \
  DIRECTORY_ADDR="$DIRECTORY_ADDR" \
  ISSUER_ADDR="$ISSUER_ADDR" \
  DIRECTORY_PROVIDER_ISSUER_URLS="$ISSUER_URL_PROVIDER" \
  DIRECTORY_ISSUER_TRUST_URLS="$ISSUER_URL_PROVIDER" \
  DIRECTORY_PROVIDER_MIN_EXIT_TIER=2 \
  DIRECTORY_PROVIDER_MIN_MICRO_RELAY_TIER=1 \
  DIRECTORY_PROVIDER_MIN_ENTRY_TIER=1 \
  DIRECTORY_PROVIDER_MAX_RELAYS_PER_OPERATOR=2 \
  ISSUER_SPONSOR_API_TOKEN="$sponsor_token" \
  ISSUER_SUBJECTS_FILE="$issuer_subjects_file" \
  ISSUER_URL="$ISSUER_URL_PROVIDER" \
  go run ./cmd/node --directory --issuer >"$node_log" 2>&1 &
node_pid=$!
trap cleanup EXIT

wait_for_http_ready "$DIRECTORY_URL/v1/health" "directory health"
wait_for_http_ready "$ISSUER_URL_PROVIDER/v1/health" "issuer health"

write_sign_provider_upsert_proof_tool

provider_pop_json=$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)
provider_pop_pub=$(echo "$provider_pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
provider_pop_priv=$(echo "$provider_pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_pop_pub" || -z "$provider_pop_priv" ]]; then
  echo "failed to generate provider pop key"
  redact_token_json "$provider_pop_json"
  exit 1
fi

provider_token_t1_json=$(curl -sS -X POST "$ISSUER_URL_PROVIDER/v1/sponsor/token" -H 'Content-Type: application/json' -H "X-Sponsor-Token: $sponsor_token" \
  --data "{\"tier\":1,\"subject\":\"provider-op-1\",\"token_type\":\"provider_role\",\"pop_pub_key\":\"$provider_pop_pub\"}")
provider_token_t1=$(echo "$provider_token_t1_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
provider_token_t1_id=$(echo "$provider_token_t1_json" | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_token_t1" || -z "$provider_token_t1_id" ]]; then
  echo "failed to issue provider token"
  redact_token_json "$provider_token_t1_json"
  cat "$node_log"
  exit 1
fi

relay_key_json="$provider_pop_json"
relay_pub=$(echo "$relay_key_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
if [[ -z "$relay_pub" ]]; then
  echo "failed to generate relay pubkey"
  redact_token_json "$relay_key_json"
  exit 1
fi

low_exit_payload=$(cat <<JSON
{"relay_id":"exit-provider-1","role":"exit","pub_key":"$relay_pub","endpoint":"127.0.0.1:52821","control_url":"http://127.0.0.1:9284","country_code":"US","region":"us-east","capabilities":["wg","tiered-policy"],"valid_for_sec":120}
JSON
)

status_low_exit=$(curl_with_bearer_config "$provider_token_t1" -sS -o "$low_exit_resp" -w '%{http_code}' \
  -X POST "$DIRECTORY_URL/v1/provider/relay/upsert" \
  -H 'Content-Type: application/json' \
  --data "$low_exit_payload")
if [[ "$status_low_exit" != "400" ]]; then
  echo "expected tier1 provider token rejected for exit relay with min exit tier=2"
  echo "status=$status_low_exit body=$(cat "$low_exit_resp")"
  cat "$node_log"
  exit 1
fi

entry_nonce="provider-api-entry-$(date +%s%N)-$$"
entry_proof=$(sign_provider_upsert_proof \
  --private-key "$provider_pop_priv" \
  --token-id "$provider_token_t1_id" \
  --subject "provider-op-1" \
  --relay-id "entry-provider-1" \
  --role "entry" \
  --pub-key "$relay_pub" \
  --endpoint "127.0.0.1:52820" \
  --control-url "http://127.0.0.1:9283" \
  --nonce "$entry_nonce")
if [[ -z "$entry_proof" ]]; then
  echo "failed to sign entry provider upsert proof"
  exit 1
fi

entry_payload=$(cat <<JSON
{"relay_id":"entry-provider-1","role":"entry","pub_key":"$relay_pub","endpoint":"127.0.0.1:52820","control_url":"http://127.0.0.1:9283","country_code":"US","region":"us-east","capabilities":["wg","tiered-policy"],"valid_for_sec":120,"token_proof":"$entry_proof","token_proof_nonce":"$entry_nonce"}
JSON
)

entry_resp=$(curl_with_bearer_config "$provider_token_t1" -sS -X POST "$DIRECTORY_URL/v1/provider/relay/upsert" \
  -H 'Content-Type: application/json' \
  --data "$entry_payload")
if ! echo "$entry_resp" | rg -q '"accepted":true'; then
  echo "expected tier1 provider relay upsert accepted for entry role"
  echo "$entry_resp"
  cat "$node_log"
  exit 1
fi

provider_pop_micro_json=$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)
provider_pop_micro_pub=$(echo "$provider_pop_micro_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
provider_pop_micro_priv=$(echo "$provider_pop_micro_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_pop_micro_pub" || -z "$provider_pop_micro_priv" ]]; then
  echo "failed to generate provider micro-relay pop key"
  redact_token_json "$provider_pop_micro_json"
  exit 1
fi

provider_token_micro_json=$(curl -sS -X POST "$ISSUER_URL_PROVIDER/v1/sponsor/token" -H 'Content-Type: application/json' -H "X-Sponsor-Token: $sponsor_token" \
  --data "{\"tier\":1,\"subject\":\"provider-op-micro\",\"token_type\":\"provider_role\",\"pop_pub_key\":\"$provider_pop_micro_pub\"}")
provider_token_micro=$(echo "$provider_token_micro_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
provider_token_micro_id=$(echo "$provider_token_micro_json" | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_token_micro" || -z "$provider_token_micro_id" ]]; then
  echo "failed to issue provider micro-relay token"
  redact_token_json "$provider_token_micro_json"
  cat "$node_log"
  exit 1
fi

relay_key_micro_json="$provider_pop_micro_json"
relay_micro_pub=$(echo "$relay_key_micro_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
if [[ -z "$relay_micro_pub" ]]; then
  echo "failed to generate micro-relay pubkey"
  redact_token_json "$relay_key_micro_json"
  exit 1
fi

micro_nonce="provider-api-micro-$(date +%s%N)-$$"
micro_proof=$(sign_provider_upsert_proof \
  --private-key "$provider_pop_micro_priv" \
  --token-id "$provider_token_micro_id" \
  --subject "provider-op-micro" \
  --relay-id "micro-provider-1" \
  --role "middle" \
  --pub-key "$relay_micro_pub" \
  --endpoint "127.0.0.1:52830" \
  --control-url "http://127.0.0.1:9290" \
  --nonce "$micro_nonce")
if [[ -z "$micro_proof" ]]; then
  echo "failed to sign micro provider upsert proof"
  exit 1
fi

micro_payload=$(cat <<JSON
{"relay_id":"micro-provider-1","role":"middle","pub_key":"$relay_micro_pub","endpoint":"127.0.0.1:52830","control_url":"http://127.0.0.1:9290","country_code":"US","region":"us-east","capabilities":["wg"],"reputation_score":1,"uptime_score":1,"capacity_score":1,"valid_for_sec":120,"token_proof":"$micro_proof","token_proof_nonce":"$micro_nonce"}
JSON
)

micro_resp=$(curl_with_bearer_config "$provider_token_micro" -sS -X POST "$DIRECTORY_URL/v1/provider/relay/upsert" \
  -H 'Content-Type: application/json' \
  --data "$micro_payload")
if ! echo "$micro_resp" | rg -q '"accepted":true'; then
  echo "expected tier1 provider relay upsert accepted for middle alias role"
  echo "$micro_resp"
  cat "$node_log"
  exit 1
fi
if ! echo "$micro_resp" | rg -q '"role":"micro-relay"'; then
  echo "expected middle alias to canonicalize to micro-relay role"
  echo "$micro_resp"
  cat "$node_log"
  exit 1
fi

provider_token_t2_json=$(curl -sS -X POST "$ISSUER_URL_PROVIDER/v1/sponsor/token" -H 'Content-Type: application/json' -H "X-Sponsor-Token: $sponsor_token" \
  --data "{\"tier\":2,\"subject\":\"provider-op-1\",\"token_type\":\"provider_role\",\"pop_pub_key\":\"$provider_pop_pub\"}")
provider_token_t2=$(echo "$provider_token_t2_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
provider_token_t2_id=$(echo "$provider_token_t2_json" | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_token_t2" || -z "$provider_token_t2_id" ]]; then
  echo "failed to issue provider tier2 token"
  redact_token_json "$provider_token_t2_json"
  cat "$node_log"
  exit 1
fi

exit_nonce="provider-api-exit-$(date +%s%N)-$$"
exit_proof=$(sign_provider_upsert_proof \
  --private-key "$provider_pop_priv" \
  --token-id "$provider_token_t2_id" \
  --subject "provider-op-1" \
  --relay-id "exit-provider-1" \
  --role "exit" \
  --pub-key "$relay_pub" \
  --endpoint "127.0.0.1:52821" \
  --control-url "http://127.0.0.1:9284" \
  --nonce "$exit_nonce")
if [[ -z "$exit_proof" ]]; then
  echo "failed to sign exit provider upsert proof"
  exit 1
fi

exit_payload_t2=$(cat <<JSON
{"relay_id":"exit-provider-1","role":"exit","pub_key":"$relay_pub","endpoint":"127.0.0.1:52821","control_url":"http://127.0.0.1:9284","country_code":"US","region":"us-east","capabilities":["wg","tiered-policy"],"valid_for_sec":120,"token_proof":"$exit_proof","token_proof_nonce":"$exit_nonce"}
JSON
)

upsert_resp=$(curl_with_bearer_config "$provider_token_t2" -sS -X POST "$DIRECTORY_URL/v1/provider/relay/upsert" \
  -H 'Content-Type: application/json' \
  --data "$exit_payload_t2")
if ! echo "$upsert_resp" | rg -q '"accepted":true'; then
  echo "expected tier2 provider relay upsert accepted for exit role"
  echo "$upsert_resp"
  cat "$node_log"
  exit 1
fi

third_nonce="provider-api-third-$(date +%s%N)-$$"
third_proof=$(sign_provider_upsert_proof \
  --private-key "$provider_pop_priv" \
  --token-id "$provider_token_t2_id" \
  --subject "provider-op-1" \
  --relay-id "entry-provider-2" \
  --role "entry" \
  --pub-key "$relay_pub" \
  --endpoint "127.0.0.1:52822" \
  --control-url "http://127.0.0.1:9285" \
  --nonce "$third_nonce")
if [[ -z "$third_proof" ]]; then
  echo "failed to sign third provider upsert proof"
  exit 1
fi

third_payload=$(cat <<JSON
{"relay_id":"entry-provider-2","role":"entry","pub_key":"$relay_pub","endpoint":"127.0.0.1:52822","control_url":"http://127.0.0.1:9285","country_code":"US","region":"us-east","capabilities":["wg","tiered-policy"],"valid_for_sec":120,"token_proof":"$third_proof","token_proof_nonce":"$third_nonce"}
JSON
)

status_cap=$(curl_with_bearer_config "$provider_token_t2" -sS -o "$cap_resp" -w '%{http_code}' \
  -X POST "$DIRECTORY_URL/v1/provider/relay/upsert" \
  -H 'Content-Type: application/json' \
  --data "$third_payload")
if [[ "$status_cap" != "429" ]]; then
  echo "expected provider operator relay cap to reject third advertised relay"
  echo "status=$status_cap body=$(cat "$cap_resp")"
  cat "$node_log"
  exit 1
fi

if ! curl -sS "$DIRECTORY_URL/v1/relays" | rg -q '"relay_id":"exit-provider-1"'; then
  echo "expected provider relay in directory relays list"
  cat "$node_log"
  exit 1
fi

client_pop_json=$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)
client_pop_pub=$(echo "$client_pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
if [[ -z "$client_pop_pub" ]]; then
  echo "failed to generate client pop key"
  redact_token_json "$client_pop_json"
  exit 1
fi

client_token_json=$(curl -sS -X POST "$ISSUER_URL_PROVIDER/v1/token" -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-user-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$client_pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")
client_token=$(echo "$client_token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$client_token" ]]; then
  echo "failed to issue client token"
  redact_token_json "$client_token_json"
  cat "$node_log"
  exit 1
fi

status_code=$(curl_with_bearer_config "$client_token" -sS -o "$reject_resp" -w '%{http_code}' \
  -X POST "$DIRECTORY_URL/v1/provider/relay/upsert" \
  -H 'Content-Type: application/json' \
  --data "$low_exit_payload")
if [[ "$status_code" != "401" ]]; then
  echo "expected client_access token rejected by provider api"
  echo "status=$status_code body=$(cat "$reject_resp")"
  cat "$node_log"
  exit 1
fi

echo "provider api integration check ok"
