#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

DIRECTORY_DESCRIPTOR_EPOCH_SEC="${DIRECTORY_DESCRIPTOR_EPOCH_SEC:-15}"
DIRECTORY_SELECTION_FEED_EPOCH_SEC="${DIRECTORY_SELECTION_FEED_EPOCH_SEC:-15}"
DIRECTORY_ADDR="${HTTP_CACHE_DIRECTORY_ADDR:-127.0.0.1:18581}"
DIRECTORY_URL="http://${DIRECTORY_ADDR}"
TMP_DIR="$(mktemp -d /tmp/http_cache.XXXXXX)"
NODE_LOG="$TMP_DIR/node.log"

DIRECTORY_DESCRIPTOR_EPOCH_SEC="$DIRECTORY_DESCRIPTOR_EPOCH_SEC" \
DIRECTORY_SELECTION_FEED_EPOCH_SEC="$DIRECTORY_SELECTION_FEED_EPOCH_SEC" \
DIRECTORY_ADDR="$DIRECTORY_ADDR" \
DIRECTORY_PRIVATE_KEY_FILE="$TMP_DIR/directory_ed25519.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_token_proof_replay.json" \
timeout 25s go run ./cmd/node --directory >"$NODE_LOG" 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true; rm -rf "$TMP_DIR"' EXIT

sleep 2

ready=0
for _ in $(seq 1 20); do
  if curl -sS -X GET "$DIRECTORY_URL/v1/relays" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then
  echo "directory did not become ready for cache test"
  cat "$NODE_LOG"
  exit 1
fi

extract_etag() {
  awk 'BEGIN{IGNORECASE=1}/^Etag:/{gsub("\r","",$2); print $2}'
}

extract_code() {
  awk 'NR==1{print $2}'
}

check_endpoint() {
  local endpoint="$1"
  local first second etag code

  first=$(curl -sS -D - -o /dev/null -X GET "${DIRECTORY_URL}${endpoint}")
  etag=$(echo "$first" | extract_etag)
  if [[ -z "$etag" ]]; then
    echo "expected etag on ${endpoint}"
    echo "$first"
    cat "$NODE_LOG"
    exit 1
  fi

  second=$(curl -sS -D - -o /dev/null -X GET -H "If-None-Match: $etag" "${DIRECTORY_URL}${endpoint}")
  code=$(echo "$second" | extract_code)
  if [[ "$code" != "304" ]]; then
    echo "expected 304 Not Modified for ${endpoint}, got ${code}"
    echo "etag=${etag}"
    echo "$second"
    cat "$NODE_LOG"
    exit 1
  fi
}

check_endpoint "/v1/relays"
check_endpoint "/v1/selection-feed"

echo "http cache integration check ok"
