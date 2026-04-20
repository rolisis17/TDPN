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

redact_token_json() {
  local payload="$1"
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

timeout 25s env \
  DIRECTORY_PROVIDER_ISSUER_URLS=http://127.0.0.1:8082 \
  DIRECTORY_ISSUER_TRUST_URLS=http://127.0.0.1:8082 \
  DIRECTORY_PROVIDER_MIN_EXIT_TIER=2 \
  DIRECTORY_PROVIDER_MIN_ENTRY_TIER=1 \
  DIRECTORY_PROVIDER_MAX_RELAYS_PER_OPERATOR=2 \
  ISSUER_URL=http://127.0.0.1:8082 \
  go run ./cmd/node --directory --issuer >"$node_log" 2>&1 &
node_pid=$!
trap cleanup EXIT

sleep 2

provider_pop_json=$(go run ./cmd/tokenpop gen --show-private-key)
provider_pop_pub=$(echo "$provider_pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_pop_pub" ]]; then
  echo "failed to generate provider pop key"
  redact_token_json "$provider_pop_json"
  exit 1
fi

provider_token_t1_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"provider-op-1\",\"token_type\":\"provider_role\",\"pop_pub_key\":\"$provider_pop_pub\"}")
provider_token_t1=$(echo "$provider_token_t1_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_token_t1" ]]; then
  echo "failed to issue provider token"
  redact_token_json "$provider_token_t1_json"
  cat "$node_log"
  exit 1
fi

relay_key_json=$(go run ./cmd/tokenpop gen --show-private-key)
relay_pub=$(echo "$relay_key_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
if [[ -z "$relay_pub" ]]; then
  echo "failed to generate relay pubkey"
  redact_token_json "$relay_key_json"
  exit 1
fi

upsert_payload=$(cat <<JSON
{"relay_id":"exit-provider-1","role":"exit","pub_key":"$relay_pub","endpoint":"127.0.0.1:52821","control_url":"http://127.0.0.1:9284","country_code":"US","region":"us-east","capabilities":["wg","tiered-policy"],"valid_for_sec":120}
JSON
)

status_low_exit=$(curl_with_bearer_config "$provider_token_t1" -sS -o "$low_exit_resp" -w '%{http_code}' \
  -X POST http://127.0.0.1:8081/v1/provider/relay/upsert \
  -H 'Content-Type: application/json' \
  --data "$upsert_payload")
if [[ "$status_low_exit" != "400" ]]; then
  echo "expected tier1 provider token rejected for exit relay with min exit tier=2"
  echo "status=$status_low_exit body=$(cat "$low_exit_resp")"
  cat "$node_log"
  exit 1
fi

entry_payload=$(cat <<JSON
{"relay_id":"entry-provider-1","role":"entry","pub_key":"$relay_pub","endpoint":"127.0.0.1:52820","control_url":"http://127.0.0.1:9283","country_code":"US","region":"us-east","capabilities":["wg","tiered-policy"],"valid_for_sec":120}
JSON
)

entry_resp=$(curl_with_bearer_config "$provider_token_t1" -sS -X POST http://127.0.0.1:8081/v1/provider/relay/upsert \
  -H 'Content-Type: application/json' \
  --data "$entry_payload")
if ! echo "$entry_resp" | rg -q '"accepted":true'; then
  echo "expected tier1 provider relay upsert accepted for entry role"
  echo "$entry_resp"
  cat "$node_log"
  exit 1
fi

provider_pop_t2_json=$(go run ./cmd/tokenpop gen --show-private-key)
provider_pop_t2_pub=$(echo "$provider_pop_t2_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_pop_t2_pub" ]]; then
  echo "failed to generate provider tier2 pop key"
  redact_token_json "$provider_pop_t2_json"
  exit 1
fi

provider_token_t2_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":2,\"subject\":\"provider-op-1\",\"token_type\":\"provider_role\",\"pop_pub_key\":\"$provider_pop_t2_pub\"}")
provider_token_t2=$(echo "$provider_token_t2_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_token_t2" ]]; then
  echo "failed to issue provider tier2 token"
  redact_token_json "$provider_token_t2_json"
  cat "$node_log"
  exit 1
fi

upsert_resp=$(curl_with_bearer_config "$provider_token_t2" -sS -X POST http://127.0.0.1:8081/v1/provider/relay/upsert \
  -H 'Content-Type: application/json' \
  --data "$upsert_payload")
if ! echo "$upsert_resp" | rg -q '"accepted":true'; then
  echo "expected tier2 provider relay upsert accepted for exit role"
  echo "$upsert_resp"
  cat "$node_log"
  exit 1
fi

third_payload=$(cat <<JSON
{"relay_id":"entry-provider-2","role":"entry","pub_key":"$relay_pub","endpoint":"127.0.0.1:52822","control_url":"http://127.0.0.1:9285","country_code":"US","region":"us-east","capabilities":["wg","tiered-policy"],"valid_for_sec":120}
JSON
)

status_cap=$(curl_with_bearer_config "$provider_token_t2" -sS -o "$cap_resp" -w '%{http_code}' \
  -X POST http://127.0.0.1:8081/v1/provider/relay/upsert \
  -H 'Content-Type: application/json' \
  --data "$third_payload")
if [[ "$status_cap" != "429" ]]; then
  echo "expected provider operator relay cap to reject third advertised relay"
  echo "status=$status_cap body=$(cat "$cap_resp")"
  cat "$node_log"
  exit 1
fi

if ! curl -sS http://127.0.0.1:8081/v1/relays | rg -q '"relay_id":"exit-provider-1"'; then
  echo "expected provider relay in directory relays list"
  cat "$node_log"
  exit 1
fi

client_pop_json=$(go run ./cmd/tokenpop gen --show-private-key)
client_pop_pub=$(echo "$client_pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
if [[ -z "$client_pop_pub" ]]; then
  echo "failed to generate client pop key"
  redact_token_json "$client_pop_json"
  exit 1
fi

client_token_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-user-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$client_pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")
client_token=$(echo "$client_token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$client_token" ]]; then
  echo "failed to issue client token"
  redact_token_json "$client_token_json"
  cat "$node_log"
  exit 1
fi

status_code=$(curl_with_bearer_config "$client_token" -sS -o "$reject_resp" -w '%{http_code}' \
  -X POST http://127.0.0.1:8081/v1/provider/relay/upsert \
  -H 'Content-Type: application/json' \
  --data "$upsert_payload")
if [[ "$status_code" != "401" ]]; then
  echo "expected client_access token rejected by provider api"
  echo "status=$status_code body=$(cat "$reject_resp")"
  cat "$node_log"
  exit 1
fi

echo "provider api integration check ok"
