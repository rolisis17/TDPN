#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

old_umask="$(umask)"
umask 077
TMP_DIR="$(mktemp -d /tmp/operator_quorum.XXXXXX)"
umask "$old_umask"

CORE_LOG="$TMP_DIR/core.log"
DIR_A_LOG="$TMP_DIR/dir_a.log"
DIR_B_LOG="$TMP_DIR/dir_b.log"
FAIL_LOG="$TMP_DIR/fail.log"
PASS_LOG="$TMP_DIR/pass.log"
TRUST_FILE="$TMP_DIR/trusted_directory_keys.txt"
DIR_A_KEY_FILE="$TMP_DIR/operator_quorum_a.key"
DIR_B_KEY_FILE="$TMP_DIR/operator_quorum_b.key"

DIR_A_ADDR="${OPERATOR_QUORUM_DIR_A_ADDR:-127.0.0.1:18481}"
DIR_B_ADDR="${OPERATOR_QUORUM_DIR_B_ADDR:-127.0.0.1:18485}"
ISSUER_ADDR="${OPERATOR_QUORUM_ISSUER_ADDR:-127.0.0.1:18482}"
ENTRY_ADDR="${OPERATOR_QUORUM_ENTRY_ADDR:-127.0.0.1:18483}"
EXIT_ADDR="${OPERATOR_QUORUM_EXIT_ADDR:-127.0.0.1:18484}"
ENTRY_DATA_ADDR="${OPERATOR_QUORUM_ENTRY_DATA_ADDR:-127.0.0.1:53480}"
EXIT_DATA_ADDR="${OPERATOR_QUORUM_EXIT_DATA_ADDR:-127.0.0.1:53481}"
DIR_A_URL="http://${DIR_A_ADDR}"
DIR_B_URL="http://${DIR_B_ADDR}"
DIRECTORY_URLS_VALUE="${DIR_A_URL},${DIR_B_URL}"
ISSUER_URL="http://${ISSUER_ADDR}"
ENTRY_URL="http://${ENTRY_ADDR}"
EXIT_CONTROL_URL="http://${EXIT_ADDR}"

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion keypair"
  exit 1
fi
relay_identity_json="$(go run ./cmd/tokenpop gen)"
relay_pubkey="$(echo "$relay_identity_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$relay_pubkey" ]]; then
  echo "failed to generate relay identity pubkey"
  exit 1
fi

DIRECTORY_URLS="$DIRECTORY_URLS_VALUE" \
DIRECTORY_URL="$DIR_A_URL" \
ISSUER_ADDR="$ISSUER_ADDR" \
ENTRY_ADDR="$ENTRY_ADDR" \
EXIT_ADDR="$EXIT_ADDR" \
ISSUER_URL="$ISSUER_URL" \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
ENTRY_DATA_ADDR="$ENTRY_DATA_ADDR" \
EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
ENTRY_DIRECTORY_TRUST_STRICT=1 \
ENTRY_DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
ENTRY_RELAY_ID=entry-local-1 \
EXIT_RELAY_ID=exit-local-1 \
ENTRY_OPERATOR_ID=op-relay \
EXIT_OPERATOR_ID=op-relay \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/exit_token_proof_replay.json" \
timeout 25s go run ./cmd/node --issuer --entry --exit >"$CORE_LOG" 2>&1 &
core_pid=$!

DIRECTORY_ADDR="$DIR_A_ADDR" \
DIRECTORY_PRIVATE_KEY_FILE="$DIR_A_KEY_FILE" \
DIRECTORY_OPERATOR_ID=op-fed-same \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
RELAY_PUBKEY="$relay_pubkey" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
ENTRY_RELAY_ID=entry-local-1 \
EXIT_RELAY_ID=exit-local-1 \
ENTRY_OPERATOR_ID=op-relay \
EXIT_OPERATOR_ID=op-relay \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_token_proof_replay_a.json" \
timeout 25s go run ./cmd/node --directory >"$DIR_A_LOG" 2>&1 &
dir_a_pid=$!

DIRECTORY_ADDR="$DIR_B_ADDR" \
DIRECTORY_PRIVATE_KEY_FILE="$DIR_B_KEY_FILE" \
DIRECTORY_OPERATOR_ID=op-fed-same \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
RELAY_PUBKEY="$relay_pubkey" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
ENTRY_RELAY_ID=entry-local-1 \
EXIT_RELAY_ID=exit-local-1 \
ENTRY_OPERATOR_ID=op-relay \
EXIT_OPERATOR_ID=op-relay \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_token_proof_replay_b.json" \
timeout 25s go run ./cmd/node --directory >"$DIR_B_LOG" 2>&1 &
dir_b_pid=$!

cleanup() {
  for pid in "$core_pid" "$dir_a_pid" "${dir_b_pid:-}"; do
    if [[ -n "${pid}" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

sleep 3

pin_directory_key() {
  local url="$1"
  local payload pub
  payload=""
  for _ in $(seq 1 30); do
    if payload="$(curl -fsS "$url/v1/pubkeys" 2>/dev/null)"; then
      break
    fi
    sleep 0.5
  done
  pub="$(printf '%s' "$payload" | sed -n 's/.*"pub_keys":\["\([^"]*\)".*/\1/p')"
  if [[ -z "$pub" ]]; then
    echo "failed to fetch directory pubkey from $url"
    echo "$payload"
    cat "$DIR_A_LOG" "$DIR_B_LOG" 2>/dev/null || true
    exit 1
  fi
  printf '%s\n' "$pub" >>"$TRUST_FILE"
}

pin_directory_key "$DIR_A_URL"
pin_directory_key "$DIR_B_URL"

DIRECTORY_URLS="$DIRECTORY_URLS_VALUE" \
DIRECTORY_MIN_SOURCES=2 \
DIRECTORY_MIN_OPERATORS=2 \
DIRECTORY_MIN_RELAY_VOTES=1 \
DIRECTORY_TRUST_STRICT=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
ISSUER_URL="$ISSUER_URL" \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
timeout 10s go run ./cmd/node --client >"$FAIL_LOG" 2>&1 || true

if rg -q 'client selected entry=' "$FAIL_LOG"; then
  echo "expected operator-quorum bootstrap failure with same-operator directories"
  cat "$FAIL_LOG"
  cat "$DIR_A_LOG"
  cat "$DIR_B_LOG"
  exit 1
fi
if ! rg -q 'operator quorum not met' "$FAIL_LOG"; then
  echo "expected operator quorum failure reason in client log"
  cat "$FAIL_LOG"
  exit 1
fi

kill "$dir_b_pid" >/dev/null 2>&1 || true

DIRECTORY_ADDR="$DIR_B_ADDR" \
DIRECTORY_PRIVATE_KEY_FILE="$DIR_B_KEY_FILE" \
DIRECTORY_OPERATOR_ID=op-fed-b \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
RELAY_PUBKEY="$relay_pubkey" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
ENTRY_RELAY_ID=entry-local-1 \
EXIT_RELAY_ID=exit-local-1 \
ENTRY_OPERATOR_ID=op-relay \
EXIT_OPERATOR_ID=op-relay \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_token_proof_replay_b.json" \
timeout 25s go run ./cmd/node --directory >"$DIR_B_LOG" 2>&1 &
dir_b_pid=$!

sleep 2

DIRECTORY_URLS="$DIRECTORY_URLS_VALUE" \
DIRECTORY_MIN_SOURCES=2 \
DIRECTORY_MIN_OPERATORS=2 \
DIRECTORY_MIN_RELAY_VOTES=1 \
DIRECTORY_TRUST_STRICT=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
ISSUER_URL="$ISSUER_URL" \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
timeout 10s go run ./cmd/node --client >"$PASS_LOG" 2>&1 || true

if ! rg -q 'client selected entry=' "$PASS_LOG"; then
  echo "expected operator-quorum bootstrap success with distinct operators"
  cat "$PASS_LOG"
  cat "$DIR_A_LOG"
  cat "$DIR_B_LOG"
  cat "$CORE_LOG"
  exit 1
fi

echo "operator quorum integration check ok"
