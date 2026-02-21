#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

EXIT_REVOCATION_REFRESH_SEC="${EXIT_REVOCATION_REFRESH_SEC:-1}"
EXIT_REVOCATION_REFRESH_SEC="$EXIT_REVOCATION_REFRESH_SEC" \
  timeout 20s go run ./cmd/node --directory --issuer --entry --exit >/tmp/revoke_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 2

token_json=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data '{"tier":1,"subject":"client-revoke-1","exit_scope":["exit-local-1"]}')

token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
jti=$(echo "$token_json" | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p')

if [[ -z "$token" || -z "$jti" ]]; then
  echo "failed to parse token/jti"
  echo "$token_json"
  cat /tmp/revoke_node.log
  exit 1
fi

payload=$(cat <<JSON
{"exit_id":"exit-local-1","token":"$token","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)

first=$(curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$payload")
if ! echo "$first" | rg -q '"accepted":true'; then
  echo "expected first path open accepted"
  echo "$first"
  cat /tmp/revoke_node.log
  exit 1
fi

until=$(( $(date +%s) + 120 ))
curl -sS -X POST http://127.0.0.1:8082/v1/admin/revoke-token \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"jti\":\"$jti\",\"until\":$until}" >/tmp/revoke_admin.json

sleep 2
second=$(curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$payload")
if ! echo "$second" | rg -q 'token revoked'; then
  echo "expected revoked token denial"
  echo "$second"
  cat /tmp/revoke_node.log
  exit 1
fi

echo "revocation integration check ok"
