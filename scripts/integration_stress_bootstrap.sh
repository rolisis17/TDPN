#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

CLIENTS="${CLIENTS:-24}"
CONCURRENCY="${CONCURRENCY:-8}"
MIN_SUCCESS="${MIN_SUCCESS:-12}"
DIR_PORT="${DIR_PORT:-19381}"
ISSUER_PORT="${ISSUER_PORT:-19382}"
ENTRY_PORT="${ENTRY_PORT:-19383}"
EXIT_PORT="${EXIT_PORT:-19384}"
ENTRY_DATA_PORT="${ENTRY_DATA_PORT:-20381}"
EXIT_DATA_PORT="${EXIT_DATA_PORT:-20382}"
EXIT_WG_PORT="${EXIT_WG_PORT:-20383}"
NODE_TIMEOUT_SEC="${NODE_TIMEOUT_SEC:-180}"
CLIENT_TIMEOUT_SEC="${CLIENT_TIMEOUT_SEC:-20}"

ENTRY_OPEN_RPS="${ENTRY_OPEN_RPS:-250}"
ENTRY_PUZZLE_DIFFICULTY="${ENTRY_PUZZLE_DIFFICULTY:-0}"
ENTRY_BAN_THRESHOLD="${ENTRY_BAN_THRESHOLD:-8}"

require_uint() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an unsigned integer (got: $value)"
    exit 2
  fi
}

for var_name in CLIENTS CONCURRENCY MIN_SUCCESS DIR_PORT ISSUER_PORT ENTRY_PORT EXIT_PORT ENTRY_DATA_PORT EXIT_DATA_PORT EXIT_WG_PORT NODE_TIMEOUT_SEC CLIENT_TIMEOUT_SEC ENTRY_OPEN_RPS ENTRY_PUZZLE_DIFFICULTY ENTRY_BAN_THRESHOLD; do
  require_uint "$var_name" "${!var_name}"
done

old_umask="$(umask)"
umask 077
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stress_bootstrap.XXXXXX")"
umask "$old_umask"
NODE_LOG="$TMP_DIR/node.log"
TRUST_FILE="$TMP_DIR/directory_trust.txt"
export TMP_DIR

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  exit 1
fi

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE="$TMP_DIR/directory.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_replay.json" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ISSUER_PRIVATE_KEY_FILE="$TMP_DIR/issuer.key" \
ISSUER_SUBJECTS_FILE="$TMP_DIR/issuer_subjects.json" \
ISSUER_REVOCATIONS_FILE="$TMP_DIR/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$TMP_DIR/issuer_anon_revocations.json" \
ENTRY_ADDR="127.0.0.1:${ENTRY_PORT}" \
ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}" \
ENTRY_RELAY_ID=entry-local-1 \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
ENTRY_LIVE_WG_MODE=0 \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_ADDR="127.0.0.1:${EXIT_PORT}" \
EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}" \
EXIT_RELAY_ID=exit-local-1 \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
EXIT_WG_LISTEN_PORT="$EXIT_WG_PORT" \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/exit_token_replay.json" \
ENTRY_OPEN_RPS="$ENTRY_OPEN_RPS" \
ENTRY_PUZZLE_DIFFICULTY="$ENTRY_PUZZLE_DIFFICULTY" \
ENTRY_BAN_THRESHOLD="$ENTRY_BAN_THRESHOLD" \
timeout "${NODE_TIMEOUT_SEC}s" go run ./cmd/node --directory --issuer --entry --exit >"$NODE_LOG" 2>&1 &
node_pid=$!
trap 'kill "$node_pid" >/dev/null 2>&1 || true; rm -rf "$TMP_DIR"' EXIT

sleep 3

run_client_bootstrap_once() {
  local client_idx="$1"
  DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
  DIRECTORY_TRUST_TOFU=1 \
  DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
  ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
  ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}" \
  EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}" \
  timeout "${CLIENT_TIMEOUT_SEC}s" go run ./cmd/node --client >"${TMP_DIR}/client_${client_idx}.log" 2>&1 || true
}

active_jobs=0
client_pids=()
for client_idx in $(seq "$CLIENTS"); do
  run_client_bootstrap_once "$client_idx" &
  client_pids+=("$!")
  active_jobs=$((active_jobs + 1))
  if (( active_jobs >= CONCURRENCY )); then
    wait "${client_pids[0]}" || true
    client_pids=("${client_pids[@]:1}")
    active_jobs=$((active_jobs - 1))
  fi
done
for client_pid in "${client_pids[@]}"; do
  wait "$client_pid" || true
done

success_count=$({ rg -l 'client selected entry=' "$TMP_DIR"/client_*.log 2>/dev/null || true; } | wc -l | tr -d ' ')
if [[ "$success_count" -lt "$MIN_SUCCESS" ]]; then
  echo "expected at least ${MIN_SUCCESS} successful client bootstraps, got ${success_count}/${CLIENTS}"
  tail -n 30 "$TMP_DIR"/client_*.log 2>/dev/null || true
  cat "$NODE_LOG"
  exit 1
fi

if rg -q 'panic:' "$NODE_LOG"; then
  echo "unexpected panic in stress bootstrap run"
  cat "$NODE_LOG"
  exit 1
fi

metrics=$(curl -sS "http://127.0.0.1:${EXIT_PORT}/v1/metrics")
accepted=$(echo "$metrics" | sed -n 's/.*"accepted_packets":\([0-9][0-9]*\).*/\1/p')
if [[ -z "$accepted" || "$accepted" -le 0 ]]; then
  echo "expected accepted packet metrics after stress run"
  echo "$metrics"
  cat "$NODE_LOG"
  exit 1
fi

echo "stress bootstrap integration check ok (success=${success_count}/${CLIENTS}, accepted_packets=${accepted})"
