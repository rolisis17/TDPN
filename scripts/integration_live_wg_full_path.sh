#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE=/tmp/live_wg_full_path.log
rm -f "$LOG_FILE"

TMP_DIR="$(mktemp -d)"
TMP_BIN_DIR="$TMP_DIR/bin"
mkdir -p "$TMP_BIN_DIR"
KEY_EXIT="$TMP_DIR/exit.key"
KEY_CLIENT="$TMP_DIR/client.key"

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

chmod +x "$TMP_BIN_DIR/wg" "$TMP_BIN_DIR/ip"
printf "fake-exit-key\n" >"$KEY_EXIT"
printf "fake-client-key\n" >"$KEY_CLIENT"
FIXED_WG_PUB="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
CLIENT_PROXY_ADDR="127.0.0.1:59140"

DATA_PLANE_MODE=opaque \
WG_BACKEND=command \
CLIENT_WG_BACKEND=command \
CLIENT_WG_PRIVATE_KEY_PATH="$KEY_CLIENT" \
CLIENT_WG_PUBLIC_KEY="$FIXED_WG_PUB" \
CLIENT_WG_KERNEL_PROXY=1 \
CLIENT_WG_PROXY_ADDR="$CLIENT_PROXY_ADDR" \
CLIENT_LIVE_WG_MODE=1 \
CLIENT_INNER_SOURCE=udp \
CLIENT_DISABLE_SYNTHETIC_FALLBACK=1 \
CLIENT_OPAQUE_SESSION_SEC=12 \
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS=5000 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC=2 \
EXIT_WG_PRIVATE_KEY_PATH="$KEY_EXIT" \
EXIT_WG_PUBKEY="$FIXED_WG_PUB" \
EXIT_WG_KERNEL_PROXY=1 \
EXIT_WG_LISTEN_PORT=53531 \
EXIT_LIVE_WG_MODE=1 \
EXIT_OPAQUE_ECHO=0 \
EXIT_OPAQUE_SINK_ADDR=127.0.0.1:53512 \
EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:53511 \
ENTRY_DATA_ADDR=127.0.0.1:53520 \
ENTRY_ENDPOINT=127.0.0.1:53520 \
EXIT_DATA_ADDR=127.0.0.1:53521 \
EXIT_ENDPOINT=127.0.0.1:53521 \
ENTRY_ADDR=127.0.0.1:8353 \
EXIT_ADDR=127.0.0.1:8354 \
DIRECTORY_ADDR=127.0.0.1:8351 \
ISSUER_ADDR=127.0.0.1:8352 \
ISSUER_URL=http://127.0.0.1:8352 \
ENTRY_URL=http://127.0.0.1:8353 \
EXIT_CONTROL_URL=http://127.0.0.1:8354 \
DIRECTORY_URL=http://127.0.0.1:8351 \
PATH="$TMP_BIN_DIR:$PATH" \
timeout 90s go run ./cmd/node --directory --issuer --entry --exit --client >"$LOG_FILE" 2>&1 &
node_pid=$!

ready=0
for _ in $(seq 1 220); do
  if rg -q "client received wg-session config:" "$LOG_FILE"; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ "$ready" -ne 1 ]]; then
  echo "client did not receive wg-session config"
  cat "$LOG_FILE"
  exit 1
fi

# non-WG payload should be dropped at client ingress in live mode
printf 'not-wireguard-live' >/dev/udp/127.0.0.1/59140 || true

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

client_drop_ok=0
exit_accept_ok=0
metrics_ok=0
for _ in $(seq 1 120); do
  if rg -q "client dropped wg-kernel uplink reason=non-wireguard-live" "$LOG_FILE"; then
    client_drop_ok=1
  fi
  if rg -q "exit accepted opaque packet session=.*wg_like=true" "$LOG_FILE"; then
    exit_accept_ok=1
  fi
  m="$(curl -fsS http://127.0.0.1:8354/v1/metrics || true)"
  if echo "$m" | rg -q '"accepted_packets"[[:space:]]*:[[:space:]]*[1-9][0-9]*' &&
     echo "$m" | rg -q '"wg_proxy_created"[[:space:]]*:[[:space:]]*[1-9][0-9]*'; then
    metrics_ok=1
  fi
  if [[ "$client_drop_ok" -eq 1 && "$exit_accept_ok" -eq 1 && "$metrics_ok" -eq 1 ]]; then
    break
  fi
  sleep 0.2
done

if [[ "$client_drop_ok" -ne 1 ]]; then
  echo "missing client live-wg ingress drop log for non-wireguard payload"
  cat "$LOG_FILE"
  exit 1
fi
if [[ "$exit_accept_ok" -ne 1 && "$metrics_ok" -ne 1 ]]; then
  echo "missing full-path live-wg acceptance signals"
  echo "latest exit metrics: $(curl -fsS http://127.0.0.1:8354/v1/metrics || true)"
  cat "$LOG_FILE"
  exit 1
fi

echo "live wg full-path integration check ok"
