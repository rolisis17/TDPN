#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

timeout 25s env \
  DIRECTORY_PROVIDER_ISSUER_URLS=http://127.0.0.1:8082 \
  DIRECTORY_ISSUER_TRUST_URLS=http://127.0.0.1:8082 \
  DIRECTORY_PROVIDER_MIN_EXIT_TIER=2 \
  DIRECTORY_PROVIDER_MIN_ENTRY_TIER=1 \
  DIRECTORY_PROVIDER_MAX_RELAYS_PER_OPERATOR=2 \
  ISSUER_URL=http://127.0.0.1:8082 \
  go run ./cmd/node --directory --issuer >/tmp/provider_api_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 2

provider_pop_json=$(go run ./cmd/tokenpop gen)
provider_pop_pub=$(echo "$provider_pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_pop_pub" ]]; then
  echo "failed to generate provider pop key"
  echo "$provider_pop_json"
  exit 1
fi

provider_token_t1_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"provider-op-1\",\"token_type\":\"provider_role\",\"pop_pub_key\":\"$provider_pop_pub\"}")
provider_token_t1=$(echo "$provider_token_t1_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_token_t1" ]]; then
  echo "failed to issue provider token"
  echo "$provider_token_t1_json"
  cat /tmp/provider_api_node.log
  exit 1
fi

relay_key_json=$(go run ./cmd/tokenpop gen)
relay_pub=$(echo "$relay_key_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
if [[ -z "$relay_pub" ]]; then
  echo "failed to generate relay pubkey"
  echo "$relay_key_json"
  exit 1
fi

upsert_payload=$(cat <<JSON
{"relay_id":"exit-provider-1","role":"exit","pub_key":"$relay_pub","endpoint":"127.0.0.1:52821","control_url":"http://127.0.0.1:9284","country_code":"US","region":"us-east","capabilities":["wg","tiered-policy"],"valid_for_sec":120}
JSON
)

status_low_exit=$(curl -sS -o /tmp/provider_api_low_exit.json -w '%{http_code}' \
  -X POST http://127.0.0.1:8081/v1/provider/relay/upsert \
  -H "Authorization: Bearer $provider_token_t1" \
  -H 'Content-Type: application/json' \
  --data "$upsert_payload")
if [[ "$status_low_exit" != "400" ]]; then
  echo "expected tier1 provider token rejected for exit relay with min exit tier=2"
  echo "status=$status_low_exit body=$(cat /tmp/provider_api_low_exit.json)"
  cat /tmp/provider_api_node.log
  exit 1
fi

entry_payload=$(cat <<JSON
{"relay_id":"entry-provider-1","role":"entry","pub_key":"$relay_pub","endpoint":"127.0.0.1:52820","control_url":"http://127.0.0.1:9283","country_code":"US","region":"us-east","capabilities":["wg","tiered-policy"],"valid_for_sec":120}
JSON
)

entry_resp=$(curl -sS -X POST http://127.0.0.1:8081/v1/provider/relay/upsert \
  -H "Authorization: Bearer $provider_token_t1" \
  -H 'Content-Type: application/json' \
  --data "$entry_payload")
if ! echo "$entry_resp" | rg -q '"accepted":true'; then
  echo "expected tier1 provider relay upsert accepted for entry role"
  echo "$entry_resp"
  cat /tmp/provider_api_node.log
  exit 1
fi

provider_pop_t2_json=$(go run ./cmd/tokenpop gen)
provider_pop_t2_pub=$(echo "$provider_pop_t2_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_pop_t2_pub" ]]; then
  echo "failed to generate provider tier2 pop key"
  echo "$provider_pop_t2_json"
  exit 1
fi

provider_token_t2_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":2,\"subject\":\"provider-op-1\",\"token_type\":\"provider_role\",\"pop_pub_key\":\"$provider_pop_t2_pub\"}")
provider_token_t2=$(echo "$provider_token_t2_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$provider_token_t2" ]]; then
  echo "failed to issue provider tier2 token"
  echo "$provider_token_t2_json"
  cat /tmp/provider_api_node.log
  exit 1
fi

upsert_resp=$(curl -sS -X POST http://127.0.0.1:8081/v1/provider/relay/upsert \
  -H "Authorization: Bearer $provider_token_t2" \
  -H 'Content-Type: application/json' \
  --data "$upsert_payload")
if ! echo "$upsert_resp" | rg -q '"accepted":true'; then
  echo "expected tier2 provider relay upsert accepted for exit role"
  echo "$upsert_resp"
  cat /tmp/provider_api_node.log
  exit 1
fi

third_payload=$(cat <<JSON
{"relay_id":"entry-provider-2","role":"entry","pub_key":"$relay_pub","endpoint":"127.0.0.1:52822","control_url":"http://127.0.0.1:9285","country_code":"US","region":"us-east","capabilities":["wg","tiered-policy"],"valid_for_sec":120}
JSON
)

status_cap=$(curl -sS -o /tmp/provider_api_cap.json -w '%{http_code}' \
  -X POST http://127.0.0.1:8081/v1/provider/relay/upsert \
  -H "Authorization: Bearer $provider_token_t2" \
  -H 'Content-Type: application/json' \
  --data "$third_payload")
if [[ "$status_cap" != "429" ]]; then
  echo "expected provider operator relay cap to reject third advertised relay"
  echo "status=$status_cap body=$(cat /tmp/provider_api_cap.json)"
  cat /tmp/provider_api_node.log
  exit 1
fi

if ! curl -sS http://127.0.0.1:8081/v1/relays | rg -q '"relay_id":"exit-provider-1"'; then
  echo "expected provider relay in directory relays list"
  cat /tmp/provider_api_node.log
  exit 1
fi

client_pop_json=$(go run ./cmd/tokenpop gen)
client_pop_pub=$(echo "$client_pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
if [[ -z "$client_pop_pub" ]]; then
  echo "failed to generate client pop key"
  echo "$client_pop_json"
  exit 1
fi

client_token_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-user-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$client_pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")
client_token=$(echo "$client_token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$client_token" ]]; then
  echo "failed to issue client token"
  echo "$client_token_json"
  cat /tmp/provider_api_node.log
  exit 1
fi

status_code=$(curl -sS -o /tmp/provider_api_reject.json -w '%{http_code}' \
  -X POST http://127.0.0.1:8081/v1/provider/relay/upsert \
  -H "Authorization: Bearer $client_token" \
  -H 'Content-Type: application/json' \
  --data "$upsert_payload")
if [[ "$status_code" != "401" ]]; then
  echo "expected client_access token rejected by provider api"
  echo "status=$status_code body=$(cat /tmp/provider_api_reject.json)"
  cat /tmp/provider_api_node.log
  exit 1
fi

echo "provider api integration check ok"
