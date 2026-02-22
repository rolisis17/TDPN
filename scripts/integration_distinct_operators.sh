#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

core_pid=""

start_core() {
  local entry_operator="$1"
  local exit_operator="$2"
  DIRECTORY_PRIVATE_KEY_FILE=data/distinct_ops_directory.key \
  ISSUER_PRIVATE_KEY_FILE=data/distinct_ops_issuer.key \
  DIRECTORY_OPERATOR_ID=op-distinct-dir \
  ENTRY_OPERATOR_ID="$entry_operator" \
  EXIT_OPERATOR_ID="$exit_operator" \
  timeout 25s go run ./cmd/node --directory --issuer --entry --exit >/tmp/distinct_ops_core.log 2>&1 &
  core_pid=$!
  sleep 3
}

stop_core() {
  if [[ -n "${core_pid}" ]]; then
    kill "$core_pid" >/dev/null 2>&1 || true
    wait "$core_pid" >/dev/null 2>&1 || true
    core_pid=""
  fi
}

cleanup() {
  stop_core
}
trap cleanup EXIT

# Case 1: entry and exit share the same operator; distinct-operator mode should fail selection.
start_core "op-shared" "op-shared"
CLIENT_REQUIRE_DISTINCT_OPERATORS=1 \
timeout 10s go run ./cmd/node --client >/tmp/distinct_ops_fail.log 2>&1 || true
if rg -q 'client selected entry=' /tmp/distinct_ops_fail.log; then
  echo "expected distinct-operator mode to reject same-operator entry/exit pair"
  cat /tmp/distinct_ops_fail.log
  cat /tmp/distinct_ops_core.log
  exit 1
fi
if ! rg -q 'distinct-operator filter applied' /tmp/distinct_ops_fail.log; then
  echo "expected distinct-operator filter log in failure case"
  cat /tmp/distinct_ops_fail.log
  cat /tmp/distinct_ops_core.log
  exit 1
fi
if ! rg -q 'no suitable entry/exit relays found' /tmp/distinct_ops_fail.log; then
  echo "expected no-suitable-relays failure in same-operator case"
  cat /tmp/distinct_ops_fail.log
  cat /tmp/distinct_ops_core.log
  exit 1
fi
stop_core

# Case 2: entry and exit use distinct operators; distinct-operator mode should succeed.
start_core "op-entry" "op-exit"
CLIENT_REQUIRE_DISTINCT_OPERATORS=1 \
timeout 10s go run ./cmd/node --client >/tmp/distinct_ops_pass.log 2>&1 || true
if ! rg -q 'client selected entry=' /tmp/distinct_ops_pass.log; then
  echo "expected distinct-operator mode bootstrap success with distinct operators"
  cat /tmp/distinct_ops_pass.log
  cat /tmp/distinct_ops_core.log
  exit 1
fi

echo "distinct-operator integration check ok"
