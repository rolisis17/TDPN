#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

TMP_DIR="$(mktemp -d)"
TRUST_FILE="$TMP_DIR/directory_trust.txt"

DIR_PORT=18581
ISSUER_PORT=18582
ENTRY_PORT=18583
EXIT_PORT=18584
ENTRY_DATA_PORT=19580
EXIT_DATA_PORT=19581
EXIT_WG_PORT=19582
CLIENT_INNER_PORT=19590

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  exit 1
fi

export DATA_PLANE_MODE=opaque
export DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}"
export DIRECTORY_PUBLIC_URL="http://127.0.0.1:${DIR_PORT}"
export DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}"
export DIRECTORY_TRUST_TOFU=1
export DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE"
export DIRECTORY_PRIVATE_KEY_FILE="$TMP_DIR/directory.key"
export DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_replay.json"
export ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}"
export ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}"
export ISSUER_URLS="http://127.0.0.1:${ISSUER_PORT}"
export CORE_ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}"
export ISSUER_PRIVATE_KEY_FILE="$TMP_DIR/issuer.key"
export ISSUER_SUBJECTS_FILE="$TMP_DIR/issuer_subjects.json"
export ISSUER_REVOCATIONS_FILE="$TMP_DIR/issuer_revocations.json"
export ISSUER_ANON_REVOCATIONS_FILE="$TMP_DIR/issuer_anon_revocations.json"
export ENTRY_ADDR="127.0.0.1:${ENTRY_PORT}"
export ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}"
export ENTRY_RELAY_ID="entry-local-1"
export ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}"
export ENTRY_PUBLIC_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}"
export ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}"
export ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key"
export ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey"
export EXIT_ADDR="127.0.0.1:${EXIT_PORT}"
export EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}"
export EXIT_RELAY_ID="exit-local-1"
export EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}"
export EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}"
export EXIT_WG_LISTEN_PORT="${EXIT_WG_PORT}"
export EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey"
export EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/exit_token_replay.json"

timeout 45s go run ./cmd/node --directory --issuer --entry --exit >/tmp/opaque_udp_only_node.log 2>&1 &
node_pid=$!

inject_pid=""
cleanup() {
  kill "${inject_pid:-}" >/dev/null 2>&1 || true
  kill "${node_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

sleep 2

(
  while true; do
    printf '\x01\x00\x00\x00udp-only-test' > /dev/udp/127.0.0.1/"${CLIENT_INNER_PORT}" || true
    sleep 0.05
  done
) >/dev/null 2>&1 &
inject_pid=$!

CLIENT_INNER_SOURCE=udp \
CLIENT_INNER_UDP_ADDR="127.0.0.1:${CLIENT_INNER_PORT}" \
CLIENT_DISABLE_SYNTHETIC_FALLBACK=1 \
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS=2500 \
timeout 10s go run ./cmd/node --client >/tmp/opaque_udp_only_client_ok.log 2>&1 || true

kill "${inject_pid:-}" >/dev/null 2>&1 || true
unset inject_pid

if ! rg -q 'client selected entry=' /tmp/opaque_udp_only_client_ok.log; then
  echo "expected client bootstrap success with UDP-only opaque source"
  cat /tmp/opaque_udp_only_client_ok.log
  cat /tmp/opaque_udp_only_node.log
  exit 1
fi
if ! rg -q 'client forwarded opaque udp packets count=' /tmp/opaque_udp_only_client_ok.log; then
  echo "expected UDP opaque packets to be forwarded"
  cat /tmp/opaque_udp_only_client_ok.log
  cat /tmp/opaque_udp_only_node.log
  exit 1
fi

CLIENT_INNER_SOURCE=synthetic \
CLIENT_DISABLE_SYNTHETIC_FALLBACK=1 \
timeout 8s go run ./cmd/node --client >/tmp/opaque_udp_only_client_fail.log 2>&1 || true

if ! rg -q 'CLIENT_INNER_SOURCE=udp required when synthetic fallback is disabled' /tmp/opaque_udp_only_client_fail.log; then
  echo "expected strict UDP-source validation failure when synthetic source is configured"
  cat /tmp/opaque_udp_only_client_fail.log
  cat /tmp/opaque_udp_only_node.log
  exit 1
fi

echo "opaque udp-only integration check ok"
