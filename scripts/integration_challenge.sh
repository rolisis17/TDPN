#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

ENTRY_OPEN_RPS="${ENTRY_OPEN_RPS:-1}"
ENTRY_PUZZLE_DIFFICULTY="${ENTRY_PUZZLE_DIFFICULTY:-1}"

ENTRY_OPEN_RPS="$ENTRY_OPEN_RPS" ENTRY_PUZZLE_DIFFICULTY="$ENTRY_PUZZLE_DIFFICULTY" \
  timeout 15s go run ./cmd/node --directory --issuer --entry --exit >/tmp/challenge_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 2

TOKEN=$(curl -sS -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' \
  --data '{"tier":1,"subject":"client-challenge-1","exit_scope":["exit-local-1"]}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

if [[ -z "$TOKEN" ]]; then
  echo "failed to fetch token"
  cat /tmp/challenge_node.log
  exit 1
fi

CLIENT_PUB="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
PAYLOAD=$(cat <<JSON
{"exit_id":"exit-local-1","token":"$TOKEN","client_inner_pub":"$CLIENT_PUB","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)

curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$PAYLOAD" >/tmp/challenge_first.json
curl -sS -X POST http://127.0.0.1:8083/v1/path/open -H 'Content-Type: application/json' --data "$PAYLOAD" >/tmp/challenge_second.json

if ! rg -q 'challenge-required' /tmp/challenge_second.json; then
  echo "expected challenge-required response"
  cat /tmp/challenge_second.json
  cat /tmp/challenge_node.log
  exit 1
fi

echo "challenge integration check ok"
