#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

timeout 20s go run ./cmd/node --issuer --entry --exit >/tmp/federation_core.log 2>&1 &
core_pid=$!

DIRECTORY_ADDR=127.0.0.1:8081 DIRECTORY_PRIVATE_KEY_FILE=data/directory_a.key DIRECTORY_OPERATOR_ID=op-fed-a \
  timeout 20s go run ./cmd/node --directory >/tmp/federation_dir_a.log 2>&1 &
dir_a_pid=$!

DIRECTORY_ADDR=127.0.0.1:8085 DIRECTORY_PRIVATE_KEY_FILE=data/directory_b.key DIRECTORY_OPERATOR_ID=op-fed-b \
  timeout 20s go run ./cmd/node --directory >/tmp/federation_dir_b.log 2>&1 &
dir_b_pid=$!

cleanup() {
  kill "$core_pid" "$dir_a_pid" "$dir_b_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 3

DIRECTORY_URLS="http://127.0.0.1:8081,http://127.0.0.1:8085" \
DIRECTORY_MIN_SOURCES=2 \
DIRECTORY_MIN_OPERATORS=2 \
DIRECTORY_MIN_RELAY_VOTES=2 \
timeout 10s go run ./cmd/node --client >/tmp/federation_client.log 2>&1 || true

if ! rg -q 'client selected entry=' /tmp/federation_client.log; then
  echo "expected successful federated client bootstrap"
  cat /tmp/federation_client.log
  cat /tmp/federation_core.log
  cat /tmp/federation_dir_a.log
  cat /tmp/federation_dir_b.log
  exit 1
fi

echo "federation integration check ok"
