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
TMP_DIR="$(mktemp -d /tmp/distinct_ops.XXXXXX)"
CORE_LOG="$TMP_DIR/core.log"
FAIL_LOG="$TMP_DIR/fail.log"
ENTRY_ENFORCED_LOG="$TMP_DIR/entry_enforced.log"
PASS_LOG="$TMP_DIR/pass.log"
TRUST_FILE="$TMP_DIR/trusted_directory_keys.txt"
route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion keypair"
  exit 1
fi

pin_directory_key() {
  local payload pub
  payload="$(curl -fsS "http://$DIR_ADDR/v1/pubkeys")"
  pub="$(printf '%s' "$payload" | sed -n 's/.*"pub_keys":\["\([^"]*\)".*/\1/p')"
  if [[ -z "$pub" ]]; then
    echo "failed to parse directory pubkey"
    echo "$payload"
    cat "$CORE_LOG" 2>/dev/null || true
    exit 1
  fi
  printf '%s\n' "$pub" >"$TRUST_FILE"
}

start_core() {
  local entry_operator="$1"
  local exit_operator="$2"
  local entry_enforce_distinct="${3:-0}"
  rm -f "$CORE_LOG"
  DIRECTORY_PRIVATE_KEY_FILE="$TMP_DIR/distinct_ops_directory.key" \
  ISSUER_PRIVATE_KEY_FILE="$TMP_DIR/distinct_ops_issuer.key" \
  DIRECTORY_OPERATOR_ID=op-distinct-dir \
  DIRECTORY_URL="http://$DIR_ADDR" \
  DIRECTORY_URLS="http://$DIR_ADDR" \
  DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
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
  ENTRY_RELAY_ID=entry-local-1 \
  EXIT_RELAY_ID=exit-local-1 \
  ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
  ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
  EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
  DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_token_proof_replay.json" \
  EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/exit_token_proof_replay.json" \
  ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR="$entry_enforce_distinct" \
  timeout 25s go run ./cmd/node --directory --issuer --entry --exit >"$CORE_LOG" 2>&1 &
  core_pid=$!
  for _ in $(seq 1 40); do
    if ! kill -0 "$core_pid" >/dev/null 2>&1; then
      echo "distinct_ops core exited unexpectedly"
      cat "$CORE_LOG"
      exit 1
    fi
    if curl -fsS "http://$DIR_ADDR/v1/health" >/dev/null 2>&1; then
      pin_directory_key
      return
    fi
    sleep 0.1
  done
  echo "distinct_ops core did not become ready"
  cat "$CORE_LOG"
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
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Case 1: entry and exit share the same operator; distinct-operator mode should fail selection.
start_core "op-shared" "op-shared"
DIRECTORY_URL="http://$DIR_ADDR" \
DIRECTORY_TRUST_STRICT=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
ISSUER_URL="http://$ISSUER_ADDR" \
ENTRY_URL="http://$ENTRY_ADDR" \
EXIT_CONTROL_URL="http://$EXIT_ADDR" \
CLIENT_REQUIRE_DISTINCT_OPERATORS=1 \
timeout 10s go run ./cmd/node --client >"$FAIL_LOG" 2>&1 || true
if rg -q 'client selected entry=' "$FAIL_LOG"; then
  echo "expected distinct-operator mode to reject same-operator entry/exit pair"
  cat "$FAIL_LOG"
  cat "$CORE_LOG"
  exit 1
fi
if ! rg -q 'distinct-operator filter applied' "$FAIL_LOG"; then
  echo "expected distinct-operator filter log in failure case"
  cat "$FAIL_LOG"
  cat "$CORE_LOG"
  exit 1
fi
if ! rg -q 'no suitable entry/exit relays found' "$FAIL_LOG"; then
  echo "expected no-suitable-relays failure in same-operator case"
  cat "$FAIL_LOG"
  cat "$CORE_LOG"
  exit 1
fi
stop_core

# Case 2: same-operator relays but entry enforces distinct-operator path policy.
start_core "op-shared" "op-shared" "1"
DIRECTORY_URL="http://$DIR_ADDR" \
DIRECTORY_TRUST_STRICT=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
ISSUER_URL="http://$ISSUER_ADDR" \
ENTRY_URL="http://$ENTRY_ADDR" \
EXIT_CONTROL_URL="http://$EXIT_ADDR" \
CLIENT_REQUIRE_DISTINCT_OPERATORS=0 \
timeout 10s go run ./cmd/node --client >"$ENTRY_ENFORCED_LOG" 2>&1 || true
if rg -q 'client selected entry=' "$ENTRY_ENFORCED_LOG"; then
  echo "expected entry-side distinct-operator policy to reject same-operator path-open"
  cat "$ENTRY_ENFORCED_LOG"
  cat "$CORE_LOG"
  exit 1
fi
if ! rg -q 'entry-exit-operator-collision' "$ENTRY_ENFORCED_LOG"; then
  echo "expected entry-exit-operator-collision reason when entry policy is enabled"
  cat "$ENTRY_ENFORCED_LOG"
  cat "$CORE_LOG"
  exit 1
fi
stop_core

# Case 3: entry and exit use distinct operators; distinct-operator mode should succeed.
start_core "op-entry" "op-exit"
DIRECTORY_URL="http://$DIR_ADDR" \
DIRECTORY_TRUST_STRICT=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
ISSUER_URL="http://$ISSUER_ADDR" \
ENTRY_URL="http://$ENTRY_ADDR" \
EXIT_CONTROL_URL="http://$EXIT_ADDR" \
CLIENT_REQUIRE_DISTINCT_OPERATORS=1 \
timeout 10s go run ./cmd/node --client >"$PASS_LOG" 2>&1 || true
if ! rg -q 'client selected entry=' "$PASS_LOG"; then
  echo "expected distinct-operator mode bootstrap success with distinct operators"
  cat "$PASS_LOG"
  cat "$CORE_LOG"
  exit 1
fi

echo "distinct-operator integration check ok"
