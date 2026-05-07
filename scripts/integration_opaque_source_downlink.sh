#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

TMP_DIR="$(mktemp -d)"
LOG_FILE="$TMP_DIR/opaque_source_downlink.log"
TRUST_FILE="$TMP_DIR/directory_trust.txt"

DIR_PORT=18481
ISSUER_PORT=18482
ENTRY_PORT=18483
EXIT_PORT=18484
ENTRY_DATA_PORT=19480
EXIT_DATA_PORT=19481
EXIT_WG_PORT=19482
CLIENT_INNER_PORT=19490
CLIENT_SINK_PORT=19491
EXIT_SINK_PORT=19492
EXIT_SOURCE_PORT=19493
WGIO_FROM_WG_PORT=19500
WGIO_TO_WG_PORT=19501

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  exit 1
fi

cleanup() {
  kill "${node_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
DIRECTORY_PRIVATE_KEY_FILE="$TMP_DIR/directory.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_replay.json" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ISSUER_URLS="http://127.0.0.1:${ISSUER_PORT}" \
CORE_ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ISSUER_PRIVATE_KEY_FILE="$TMP_DIR/issuer.key" \
ISSUER_SUBJECTS_FILE="$TMP_DIR/issuer_subjects.json" \
ISSUER_REVOCATIONS_FILE="$TMP_DIR/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$TMP_DIR/issuer_anon_revocations.json" \
ENTRY_ADDR="127.0.0.1:${ENTRY_PORT}" \
ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}" \
ENTRY_RELAY_ID="entry-local-1" \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
ENTRY_PUBLIC_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
ENTRY_ENDPOINT="127.0.0.1:${ENTRY_DATA_PORT}" \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_ADDR="127.0.0.1:${EXIT_PORT}" \
EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}" \
EXIT_RELAY_ID="exit-local-1" \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
EXIT_WG_LISTEN_PORT="${EXIT_WG_PORT}" \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/exit_token_replay.json" \
DATA_PLANE_MODE=opaque \
CLIENT_INNER_SOURCE=udp \
CLIENT_INNER_UDP_ADDR="127.0.0.1:${CLIENT_INNER_PORT}" \
CLIENT_OPAQUE_SINK_ADDR="127.0.0.1:${CLIENT_SINK_PORT}" \
CLIENT_OPAQUE_DRAIN_MS=5000 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=2 \
WG_BACKEND=noop \
CLIENT_WG_BACKEND=noop \
EXIT_OPAQUE_ECHO=0 \
EXIT_OPAQUE_SINK_ADDR="127.0.0.1:${EXIT_SINK_PORT}" \
EXIT_OPAQUE_SOURCE_ADDR="127.0.0.1:${EXIT_SOURCE_PORT}" \
WGIO_FROM_WG_ADDR="127.0.0.1:${WGIO_FROM_WG_PORT}" \
WGIO_TO_CLIENT_ADDR="127.0.0.1:${CLIENT_INNER_PORT}" \
WGIO_FROM_EXIT_ADDR="127.0.0.1:${CLIENT_SINK_PORT}" \
WGIO_TO_WG_ADDR="127.0.0.1:${WGIO_TO_WG_PORT}" \
WGIOTAP_ADDR="127.0.0.1:${WGIO_TO_WG_PORT}" \
WGIOINJECT_TARGET_ADDR="127.0.0.1:${WGIO_FROM_WG_PORT}" \
WGIOINJECT_INTERVAL_MS=80 \
WGIOINJECT_WG_LIKE_PCT=100 \
timeout 35s go run ./cmd/node \
  --directory --issuer --entry --exit --client --wgio --wgiotap --wgioinject \
  >"$LOG_FILE" 2>&1 &
node_pid=$!

ready=0
for _ in $(seq 1 120); do
  if rg -q "exit accepted opaque packet session=" "$LOG_FILE"; then
    ready=1
    break
  fi
  sleep 0.25
done
if [[ "$ready" -ne 1 ]]; then
  echo "exit did not accept opaque uplink traffic"
  cat "$LOG_FILE"
  exit 1
fi

for i in $(seq 1 30); do
  session_id=$(rg -No "exit accepted opaque packet session=[0-9a-f]+" "$LOG_FILE" | tail -n1 | sed -E 's/.*session=//')
  if [[ -n "${session_id}" ]]; then
    printf "%s\ndownlink-probe-%02d" "$session_id" "$i" >/dev/udp/127.0.0.1/"${EXIT_SOURCE_PORT}" || true
  fi
  sleep 0.1
done

metric_ok=0
for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${EXIT_PORT}/v1/metrics" 2>/dev/null | rg -q '"forwarded_downlink_packets":[1-9][0-9]*'; then
    metric_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$metric_ok" -ne 1 ]]; then
  echo "expected forwarded_downlink_packets > 0"
  curl -sS "http://127.0.0.1:${EXIT_PORT}/v1/metrics" || true
  cat "$LOG_FILE"
  exit 1
fi

client_ok=0
for _ in $(seq 1 50); do
  if rg -q "client downlink opaque packets count=[1-9][0-9]*" "$LOG_FILE"; then
    client_ok=1
    break
  fi
  sleep 0.1
done
if [[ "$client_ok" -ne 1 ]]; then
  echo "expected client downlink opaque packets log entry"
  cat "$LOG_FILE"
  exit 1
fi

echo "opaque source downlink integration check ok"
