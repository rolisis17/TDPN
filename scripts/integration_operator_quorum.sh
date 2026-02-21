#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

timeout 25s go run ./cmd/node --issuer --entry --exit >/tmp/operator_quorum_core.log 2>&1 &
core_pid=$!

DIRECTORY_ADDR=127.0.0.1:8081 \
DIRECTORY_PRIVATE_KEY_FILE=data/operator_quorum_a.key \
DIRECTORY_OPERATOR_ID=op-fed-same \
timeout 25s go run ./cmd/node --directory >/tmp/operator_quorum_dir_a.log 2>&1 &
dir_a_pid=$!

DIRECTORY_ADDR=127.0.0.1:8085 \
DIRECTORY_PRIVATE_KEY_FILE=data/operator_quorum_b.key \
DIRECTORY_OPERATOR_ID=op-fed-same \
timeout 25s go run ./cmd/node --directory >/tmp/operator_quorum_dir_b.log 2>&1 &
dir_b_pid=$!

cleanup() {
  for pid in "$core_pid" "$dir_a_pid" "${dir_b_pid:-}"; do
    if [[ -n "${pid}" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

sleep 3

DIRECTORY_URLS="http://127.0.0.1:8081,http://127.0.0.1:8085" \
DIRECTORY_MIN_SOURCES=2 \
DIRECTORY_MIN_OPERATORS=2 \
DIRECTORY_MIN_RELAY_VOTES=2 \
timeout 10s go run ./cmd/node --client >/tmp/operator_quorum_fail.log 2>&1 || true

if rg -q 'client selected entry=' /tmp/operator_quorum_fail.log; then
  echo "expected operator-quorum bootstrap failure with same-operator directories"
  cat /tmp/operator_quorum_fail.log
  cat /tmp/operator_quorum_dir_a.log
  cat /tmp/operator_quorum_dir_b.log
  exit 1
fi
if ! rg -q 'operator quorum not met' /tmp/operator_quorum_fail.log; then
  echo "expected operator quorum failure reason in client log"
  cat /tmp/operator_quorum_fail.log
  exit 1
fi

kill "$dir_b_pid" >/dev/null 2>&1 || true

DIRECTORY_ADDR=127.0.0.1:8085 \
DIRECTORY_PRIVATE_KEY_FILE=data/operator_quorum_b.key \
DIRECTORY_OPERATOR_ID=op-fed-b \
timeout 25s go run ./cmd/node --directory >/tmp/operator_quorum_dir_b.log 2>&1 &
dir_b_pid=$!

sleep 2

DIRECTORY_URLS="http://127.0.0.1:8081,http://127.0.0.1:8085" \
DIRECTORY_MIN_SOURCES=2 \
DIRECTORY_MIN_OPERATORS=2 \
DIRECTORY_MIN_RELAY_VOTES=2 \
timeout 10s go run ./cmd/node --client >/tmp/operator_quorum_pass.log 2>&1 || true

if ! rg -q 'client selected entry=' /tmp/operator_quorum_pass.log; then
  echo "expected operator-quorum bootstrap success with distinct operators"
  cat /tmp/operator_quorum_pass.log
  cat /tmp/operator_quorum_dir_a.log
  cat /tmp/operator_quorum_dir_b.log
  cat /tmp/operator_quorum_core.log
  exit 1
fi

echo "operator quorum integration check ok"
