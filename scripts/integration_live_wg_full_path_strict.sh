#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE=/tmp/live_wg_full_path_strict.log
rm -f "$LOG_FILE"

TMP_DIR="$(mktemp -d)"
TMP_BIN_DIR="$TMP_DIR/bin"
mkdir -p "$TMP_BIN_DIR"
KEY_EXIT="$TMP_DIR/exit.key"
KEY_CLIENT="$TMP_DIR/client.key"
TRUSTED_KEYS_FILE="$TMP_DIR/trusted_directory_keys.txt"
DIRECTORY_KEY_FILE="$TMP_DIR/directory.key"

cleanup() {
  kill "${node_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat >"$TMP_BIN_DIR/wg" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "pubkey" ]]; then
  cat >/dev/null || true
  echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  exit 0
fi
exit 0
EOS

cat >"$TMP_BIN_DIR/ip" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOS

cat >"$TMP_BIN_DIR/iptables" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOS

cat >"$TMP_BIN_DIR/ip6tables" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOS

chmod +x "$TMP_BIN_DIR/wg" "$TMP_BIN_DIR/ip" "$TMP_BIN_DIR/iptables" "$TMP_BIN_DIR/ip6tables"
printf "fake-exit-key\n" >"$KEY_EXIT"
printf "fake-client-key\n" >"$KEY_CLIENT"
chmod 600 "$KEY_EXIT" "$KEY_CLIENT"
directory_key_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
directory_private_key="$(echo "$directory_key_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
directory_pubkey="$(echo "$directory_key_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$directory_private_key" || -z "$directory_pubkey" ]]; then
  echo "failed to generate directory key material"
  exit 1
fi
printf '%s\n' "$directory_private_key" >"$DIRECTORY_KEY_FILE"
printf '%s\n' "$directory_pubkey" >"$TRUSTED_KEYS_FILE"
chmod 600 "$DIRECTORY_KEY_FILE"
FIXED_WG_PUB="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
CLIENT_PROXY_ADDR="127.0.0.1:59240"
route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  exit 1
fi

DATA_PLANE_MODE=opaque \
DIRECTORY_TRUST_STRICT=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUSTED_KEYS_FILE" \
DIRECTORY_TRUST_TOFU=0 \
DIRECTORY_PRIVATE_KEY_FILE="$DIRECTORY_KEY_FILE" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_replay.json" \
CLIENT_BETA_STRICT=1 \
ENTRY_BETA_STRICT=0 \
EXIT_BETA_STRICT=1 \
WG_BACKEND=command \
WG_ALLOW_UNTRUSTED_BINARY_PATH=1 \
CLIENT_WG_BACKEND=command \
CLIENT_WG_PRIVATE_KEY_PATH="$KEY_CLIENT" \
CLIENT_WG_PUBLIC_KEY="$FIXED_WG_PUB" \
CLIENT_WG_KERNEL_PROXY=1 \
CLIENT_WG_PROXY_ADDR="$CLIENT_PROXY_ADDR" \
CLIENT_LIVE_WG_MODE=1 \
CLIENT_INNER_SOURCE=udp \
CLIENT_DISABLE_SYNTHETIC_FALLBACK=1 \
CLIENT_REQUIRE_DISTINCT_OPERATORS=1 \
CLIENT_OPAQUE_SESSION_SEC=14 \
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS=5000 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC=0 \
CLIENT_STARTUP_SYNC_TIMEOUT_SEC=8 \
ENTRY_LIVE_WG_MODE=1 \
ENTRY_DIRECTORY_TRUST_STRICT=1 \
ENTRY_DIRECTORY_TRUSTED_KEYS_FILE="$TRUSTED_KEYS_FILE" \
ENTRY_DIRECTORY_TRUST_TOFU=0 \
ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1 \
ENTRY_PUZZLE_SECRET=integration-entry-secret-0001 \
ENTRY_PUZZLE_DIFFICULTY=1 \
ENTRY_OPERATOR_ID=op-entry \
ENTRY_RELAY_ID=entry-local-1 \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY="$route_assertion_private_key" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$route_assertion_pubkey" \
EXIT_OPERATOR_ID=op-exit \
EXIT_RELAY_ID=exit-local-1 \
EXIT_WG_PRIVATE_KEY_PATH="$KEY_EXIT" \
EXIT_WG_PUBKEY="$FIXED_WG_PUB" \
EXIT_WG_KERNEL_PROXY=1 \
EXIT_WG_LISTEN_PORT=53631 \
EXIT_LIVE_WG_MODE=1 \
EXIT_EGRESS_BACKEND=command \
EXIT_OPAQUE_ECHO=0 \
EXIT_TOKEN_PROOF_REPLAY_GUARD=1 \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/exit_token_replay.json" \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$route_assertion_pubkey" \
EXIT_STARTUP_SYNC_TIMEOUT_SEC=8 \
EXIT_OPAQUE_SINK_ADDR=127.0.0.1:53612 \
EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:53611 \
ENTRY_DATA_ADDR=127.0.0.1:53620 \
ENTRY_ENDPOINT=127.0.0.1:53620 \
EXIT_DATA_ADDR=127.0.0.1:53621 \
EXIT_ENDPOINT=127.0.0.1:53621 \
ENTRY_ADDR=127.0.0.1:8363 \
EXIT_ADDR=127.0.0.1:8364 \
DIRECTORY_ADDR=127.0.0.1:8361 \
DIRECTORY_PUBLIC_URL=http://127.0.0.1:8361 \
ISSUER_ADDR=127.0.0.1:8362 \
ISSUER_URL=http://127.0.0.1:8362 \
ISSUER_URLS=http://127.0.0.1:8362 \
CORE_ISSUER_URL=http://127.0.0.1:8362 \
ISSUER_PRIVATE_KEY_FILE="$TMP_DIR/issuer.key" \
ISSUER_SUBJECTS_FILE="$TMP_DIR/issuer_subjects.json" \
ISSUER_REVOCATIONS_FILE="$TMP_DIR/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$TMP_DIR/issuer_anon_revocations.json" \
ENTRY_URL=http://127.0.0.1:8363 \
EXIT_CONTROL_URL=http://127.0.0.1:8364 \
DIRECTORY_URL=http://127.0.0.1:8361 \
PATH="$TMP_BIN_DIR:$PATH" \
timeout 95s go run ./cmd/node --directory --issuer --entry --exit --client >"$LOG_FILE" 2>&1 &
node_pid=$!

ready=0
for _ in $(seq 1 240); do
  if rg -q "client wireguard runtime ready:|client wg-kernel proxy listening:" "$LOG_FILE"; then
    ready=1
    break
  fi
  if ! kill -0 "$node_pid" >/dev/null 2>&1; then
    echo "strict live-wg stack exited before client session config"
    cat "$LOG_FILE"
    exit 1
  fi
  sleep 0.2
done
if [[ "$ready" -ne 1 ]]; then
  echo "client did not receive wg-session config in strict live-wg profile"
  cat "$LOG_FILE"
  exit 1
fi

relay_json="$(curl -fsS http://127.0.0.1:8361/v1/relays || true)"
if ! echo "$relay_json" | rg -q '"role":"entry"[^\}]*"operator_id":"op-entry"'; then
  echo "strict live-wg profile missing expected entry operator metadata"
  echo "$relay_json"
  cat "$LOG_FILE"
  exit 1
fi
if ! echo "$relay_json" | rg -q '"role":"exit"[^\}]*"operator_id":"op-exit"'; then
  echo "strict live-wg profile missing expected exit operator metadata"
  echo "$relay_json"
  cat "$LOG_FILE"
  exit 1
fi

# non-WG payload should be dropped at client ingress in live mode
printf 'not-wireguard-live' >/dev/udp/127.0.0.1/59240 || true

# plausible WG-like traffic should still traverse full path
for _ in $(seq 1 6); do
  perl -MIO::Socket::INET -e '
    my $target = shift @ARGV;
    my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or exit 1;
    my $pkt = pack("C4", 4, 0, 0, 0) . ("\0" x 28);
    print {$sock} $pkt or exit 1;
  ' "$CLIENT_PROXY_ADDR"
  sleep 0.12
done

strict_log_ok=0
client_drop_ok=0
exit_accept_ok=0
metrics_ok=0
for _ in $(seq 1 140); do
  if rg -q "client role enabled: .*beta_strict=true" "$LOG_FILE" &&
     rg -q "entry route discovery: .*distinct_exit_operator=true .*operator_id=op-entry" "$LOG_FILE" &&
     rg -q "exit wg backend=.*beta_strict=true" "$LOG_FILE"; then
    strict_log_ok=1
  fi
  if rg -q "client dropped wg-kernel uplink reason=non-wireguard-live" "$LOG_FILE"; then
    client_drop_ok=1
  fi
  if rg -q "exit accepted opaque packet session=.*wg_like=true" "$LOG_FILE"; then
    exit_accept_ok=1
  fi
  m="$(curl -fsS http://127.0.0.1:8364/v1/metrics || true)"
  if echo "$m" | rg -q '"accepted_packets"[[:space:]]*:[[:space:]]*[1-9][0-9]*' &&
     echo "$m" | rg -q '"wg_proxy_created"[[:space:]]*:[[:space:]]*[1-9][0-9]*'; then
    metrics_ok=1
  fi
  if [[ "$strict_log_ok" -eq 1 && "$client_drop_ok" -eq 1 && "$exit_accept_ok" -eq 1 && "$metrics_ok" -eq 1 ]]; then
    break
  fi
  sleep 0.2
done

if [[ "$strict_log_ok" -ne 1 ]]; then
  echo "missing expected strict-mode startup log signals"
  cat "$LOG_FILE"
  exit 1
fi
if [[ "$client_drop_ok" -ne 1 ]]; then
  echo "missing client live-wg ingress drop log for non-wireguard payload"
  cat "$LOG_FILE"
  exit 1
fi
if [[ "$exit_accept_ok" -ne 1 && "$metrics_ok" -ne 1 ]]; then
  echo "missing strict full-path live-wg acceptance signals"
  echo "latest exit metrics: $(curl -fsS http://127.0.0.1:8364/v1/metrics || true)"
  cat "$LOG_FILE"
  exit 1
fi
echo "strict live wg full-path integration check ok"
