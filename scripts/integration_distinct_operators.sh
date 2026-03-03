#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

core_pid=""
DIR_ADDR="127.0.0.1:18081"
ISSUER_ADDR="127.0.0.1:18082"
ENTRY_ADDR="127.0.0.1:18083"
EXIT_ADDR="127.0.0.1:18084"
ENTRY_DATA_ADDR="127.0.0.1:61980"
EXIT_DATA_ADDR="127.0.0.1:61981"

start_core() {
  local entry_operator="$1"
  local exit_operator="$2"
  local entry_enforce_distinct="${3:-0}"
  rm -f /tmp/distinct_ops_core.log
  DIRECTORY_PRIVATE_KEY_FILE=data/distinct_ops_directory.key \
  ISSUER_PRIVATE_KEY_FILE=data/distinct_ops_issuer.key \
  DIRECTORY_OPERATOR_ID=op-distinct-dir \
  DIRECTORY_URL="http://$DIR_ADDR" \
  DIRECTORY_URLS="http://$DIR_ADDR" \
  DIRECTORY_ADDR="$DIR_ADDR" \
  ISSUER_ADDR="$ISSUER_ADDR" \
  ENTRY_ADDR="$ENTRY_ADDR" \
  EXIT_ADDR="$EXIT_ADDR" \
  ENTRY_DATA_ADDR="$ENTRY_DATA_ADDR" \
  EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
  ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
  EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
  ENTRY_URL="http://$ENTRY_ADDR" \
  EXIT_CONTROL_URL="http://$EXIT_ADDR" \
  ENTRY_OPERATOR_ID="$entry_operator" \
  EXIT_OPERATOR_ID="$exit_operator" \
  ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR="$entry_enforce_distinct" \
  timeout 25s go run ./cmd/node --directory --issuer --entry --exit >/tmp/distinct_ops_core.log 2>&1 &
  core_pid=$!
  for _ in $(seq 1 40); do
    if ! kill -0 "$core_pid" >/dev/null 2>&1; then
      echo "distinct_ops core exited unexpectedly"
      cat /tmp/distinct_ops_core.log
      exit 1
    fi
    if curl -fsS "http://$DIR_ADDR/v1/health" >/dev/null 2>&1; then
      return
    fi
    sleep 0.1
  done
  echo "distinct_ops core did not become ready"
  cat /tmp/distinct_ops_core.log
  exit 1
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
DIRECTORY_URL="http://$DIR_ADDR" \
ISSUER_URL="http://$ISSUER_ADDR" \
ENTRY_URL="http://$ENTRY_ADDR" \
EXIT_CONTROL_URL="http://$EXIT_ADDR" \
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

# Case 2: same-operator relays but entry enforces distinct-operator path policy.
start_core "op-shared" "op-shared" "1"
DIRECTORY_URL="http://$DIR_ADDR" \
ISSUER_URL="http://$ISSUER_ADDR" \
ENTRY_URL="http://$ENTRY_ADDR" \
EXIT_CONTROL_URL="http://$EXIT_ADDR" \
CLIENT_REQUIRE_DISTINCT_OPERATORS=0 \
timeout 10s go run ./cmd/node --client >/tmp/distinct_ops_entry_enforced.log 2>&1 || true
if rg -q 'client selected entry=' /tmp/distinct_ops_entry_enforced.log; then
  echo "expected entry-side distinct-operator policy to reject same-operator path-open"
  cat /tmp/distinct_ops_entry_enforced.log
  cat /tmp/distinct_ops_core.log
  exit 1
fi
if ! rg -q 'entry-exit-operator-collision' /tmp/distinct_ops_entry_enforced.log; then
  echo "expected entry-exit-operator-collision reason when entry policy is enabled"
  cat /tmp/distinct_ops_entry_enforced.log
  cat /tmp/distinct_ops_core.log
  exit 1
fi
stop_core

# Case 3: entry and exit use distinct operators; distinct-operator mode should succeed.
start_core "op-entry" "op-exit"
DIRECTORY_URL="http://$DIR_ADDR" \
ISSUER_URL="http://$ISSUER_ADDR" \
ENTRY_URL="http://$ENTRY_ADDR" \
EXIT_CONTROL_URL="http://$EXIT_ADDR" \
CLIENT_REQUIRE_DISTINCT_OPERATORS=1 \
timeout 10s go run ./cmd/node --client >/tmp/distinct_ops_pass.log 2>&1 || true
if ! rg -q 'client selected entry=' /tmp/distinct_ops_pass.log; then
  echo "expected distinct-operator mode bootstrap success with distinct operators"
  cat /tmp/distinct_ops_pass.log
  cat /tmp/distinct_ops_core.log
  exit 1
fi

echo "distinct-operator integration check ok"
