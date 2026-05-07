#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

DIR_PORT="${DIR_PORT:-8481}"
ISSUER_PORT="${ISSUER_PORT:-8482}"
ENTRY_PORT="${ENTRY_PORT:-8483}"
EXIT_PORT="${EXIT_PORT:-8484}"
ENTRY_DATA_PORT="${ENTRY_DATA_PORT:-54820}"
EXIT_DATA_PORT="${EXIT_DATA_PORT:-54821}"
SCRIPT_TIMEOUT_SEC="${SCRIPT_TIMEOUT_SEC:-80}"
INFRA_START_DELAY_SEC="${INFRA_START_DELAY_SEC:-2}"
CLIENT_BOOTSTRAP_INTERVAL_SEC="${CLIENT_BOOTSTRAP_INTERVAL_SEC:-1}"
CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC="${CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC:-4}"
CLIENT_BOOTSTRAP_JITTER_PCT="${CLIENT_BOOTSTRAP_JITTER_PCT:-0}"
CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC="${CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC:-0}"
CLIENT_STARTUP_SYNC_TIMEOUT_SEC="${CLIENT_STARTUP_SYNC_TIMEOUT_SEC:-0}"
EXPECT_INITIAL_FAILURE="${EXPECT_INITIAL_FAILURE:-1}"

CLIENT_LOG=/tmp/client_bootstrap_recovery_client.log
INFRA_LOG=/tmp/client_bootstrap_recovery_infra.log
rm -f "$CLIENT_LOG" "$INFRA_LOG"
TMP_DIR="$(mktemp -d)"
TRUST_FILE="$TMP_DIR/directory_trust.txt"
DIRECTORY_KEY_FILE="$TMP_DIR/directory.key"

directory_key_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
directory_private_key="$(echo "$directory_key_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
directory_pubkey="$(echo "$directory_key_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$directory_private_key" || -z "$directory_pubkey" || -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate bootstrap recovery key material"
  exit 1
fi
printf '%s\n' "$directory_private_key" >"$DIRECTORY_KEY_FILE"
printf '%s\n' "$directory_pubkey" >"$TRUST_FILE"
chmod 600 "$DIRECTORY_KEY_FILE"

DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_TRUST_TOFU=0 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}" \
EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}" \
CLIENT_BOOTSTRAP_INTERVAL_SEC="$CLIENT_BOOTSTRAP_INTERVAL_SEC" \
CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC="$CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC" \
CLIENT_BOOTSTRAP_JITTER_PCT="$CLIENT_BOOTSTRAP_JITTER_PCT" \
CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC="$CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC" \
CLIENT_STARTUP_SYNC_TIMEOUT_SEC="$CLIENT_STARTUP_SYNC_TIMEOUT_SEC" \
timeout "${SCRIPT_TIMEOUT_SEC}s" go run ./cmd/node --client >"$CLIENT_LOG" 2>&1 &
client_pid=$!

infra_pid=""
cleanup() {
  kill "$client_pid" >/dev/null 2>&1 || true
  if [[ -n "$infra_pid" ]]; then
    kill "$infra_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

sleep "$INFRA_START_DELAY_SEC"

if [[ "$EXPECT_INITIAL_FAILURE" == "1" ]]; then
  bootstrap_fail_seen=0
  for _ in $(seq 1 30); do
    if rg -q "client bootstrap failed|client bootstrap retry failed" "$CLIENT_LOG"; then
      bootstrap_fail_seen=1
      break
    fi
    sleep 0.2
  done
  if [[ "$bootstrap_fail_seen" -ne 1 ]]; then
    echo "expected client bootstrap failure before infrastructure start"
    cat "$CLIENT_LOG"
    exit 1
  fi
fi

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE="$DIRECTORY_KEY_FILE" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_replay.json" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_PRIVATE_KEY_FILE="$TMP_DIR/issuer.key" \
ISSUER_SUBJECTS_FILE="$TMP_DIR/issuer_subjects.json" \
ISSUER_REVOCATIONS_FILE="$TMP_DIR/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$TMP_DIR/issuer_anon_revocations.json" \
ENTRY_ADDR="127.0.0.1:${ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${EXIT_PORT}" \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
ENTRY_RELAY_ID=entry-local-1 \
EXIT_RELAY_ID=exit-local-1 \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
ENTRY_DIRECTORY_TRUST_TOFU=0 \
ENTRY_DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
EXIT_WG_LISTEN_PORT="$((EXIT_DATA_PORT + 10))" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/exit_token_replay.json" \
DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ISSUER_URLS="http://127.0.0.1:${ISSUER_PORT}" \
CORE_ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}" \
EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}" \
timeout "${SCRIPT_TIMEOUT_SEC}s" go run ./cmd/node --directory --issuer --entry --exit >"$INFRA_LOG" 2>&1 &
infra_pid=$!

selected=0
for _ in $(seq 1 180); do
  if rg -q "client selected entry=.* exit=.* token_exp=" "$CLIENT_LOG"; then
    selected=1
    break
  fi
  sleep 0.2
done
if [[ "$selected" -ne 1 ]]; then
  echo "client did not recover and establish a path"
  cat "$CLIENT_LOG"
  cat "$INFRA_LOG"
  exit 1
fi

if [[ "$EXPECT_INITIAL_FAILURE" == "1" ]]; then
  recovered=0
  for _ in $(seq 1 30); do
    if rg -q "client bootstrap recovered after failures=" "$CLIENT_LOG"; then
      recovered=1
      break
    fi
    sleep 0.1
  done
  if [[ "$recovered" -ne 1 ]]; then
    echo "expected recovery log after initial bootstrap failures"
    cat "$CLIENT_LOG"
    cat "$INFRA_LOG"
    exit 1
  fi
else
  if rg -q "client bootstrap failed|client bootstrap retry failed" "$CLIENT_LOG"; then
    echo "unexpected bootstrap failure logs while startup sync gating was enabled"
    cat "$CLIENT_LOG"
    cat "$INFRA_LOG"
    exit 1
  fi
fi

metrics_ok=0
for _ in $(seq 1 40); do
  metrics=$(curl -fsS "http://127.0.0.1:${EXIT_PORT}/v1/metrics" 2>/dev/null || true)
  accepted=$(echo "$metrics" | sed -n 's/.*"accepted_packets":\([0-9][0-9]*\).*/\1/p')
  if [[ -n "$accepted" && "$accepted" -gt 0 ]]; then
    metrics_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$metrics_ok" -ne 1 ]]; then
  echo "expected accepted_packets > 0 after client recovery"
  curl -sS "http://127.0.0.1:${EXIT_PORT}/v1/metrics" || true
  cat "$CLIENT_LOG"
  cat "$INFRA_LOG"
  exit 1
fi

if rg -q "panic:" "$CLIENT_LOG" || rg -q "panic:" "$INFRA_LOG"; then
  echo "unexpected panic detected during bootstrap recovery integration"
  cat "$CLIENT_LOG"
  cat "$INFRA_LOG"
  exit 1
fi

echo "client bootstrap recovery integration check ok"
