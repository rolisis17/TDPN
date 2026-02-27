#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE=/tmp/exit_live_wg_mode.log
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

DATA_PLANE_MODE=opaque \
WG_BACKEND=command \
CLIENT_WG_BACKEND=command \
CLIENT_WG_PRIVATE_KEY_PATH="$KEY_CLIENT" \
CLIENT_WG_PUBLIC_KEY="$FIXED_WG_PUB" \
CLIENT_WG_KERNEL_PROXY=1 \
CLIENT_WG_PROXY_ADDR=127.0.0.1:59040 \
CLIENT_INNER_SOURCE=synthetic \
CLIENT_OPAQUE_SESSION_SEC=10 \
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS=4000 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
EXIT_WG_PRIVATE_KEY_PATH="$KEY_EXIT" \
EXIT_WG_PUBKEY="$FIXED_WG_PUB" \
EXIT_WG_KERNEL_PROXY=1 \
EXIT_WG_LISTEN_PORT=53431 \
EXIT_LIVE_WG_MODE=1 \
EXIT_OPAQUE_ECHO=0 \
EXIT_OPAQUE_SINK_ADDR=127.0.0.1:53412 \
EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:53411 \
ENTRY_DATA_ADDR=127.0.0.1:53420 \
ENTRY_ENDPOINT=127.0.0.1:53420 \
EXIT_DATA_ADDR=127.0.0.1:53421 \
EXIT_ENDPOINT=127.0.0.1:53421 \
ENTRY_ADDR=127.0.0.1:8343 \
EXIT_ADDR=127.0.0.1:8344 \
DIRECTORY_ADDR=127.0.0.1:8341 \
ISSUER_ADDR=127.0.0.1:8342 \
ISSUER_URL=http://127.0.0.1:8342 \
ENTRY_URL=http://127.0.0.1:8343 \
EXIT_CONTROL_URL=http://127.0.0.1:8344 \
DIRECTORY_URL=http://127.0.0.1:8341 \
PATH="$TMP_BIN_DIR:$PATH" \
timeout 80s go run ./cmd/node --directory --issuer --entry --exit --client >"$LOG_FILE" 2>&1 &
node_pid=$!

ready=0
for _ in $(seq 1 180); do
  if rg -q "client received wg-session config:" "$LOG_FILE"; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ "$ready" -ne 1 ]]; then
  echo "client did not receive wg session config"
  cat "$LOG_FILE"
  exit 1
fi

# Send one non-WG packet through client proxy. Exit live mode should drop it.
printf 'not-wireguard-live' >/dev/udp/127.0.0.1/59040 || true

# Send a few WG-like packets so accepted packet metrics also advance.
for _ in $(seq 1 6); do
  perl -MIO::Socket::INET -e '
    my $target = shift @ARGV;
    my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or exit 1;
    my $pkt = pack("C4", 4, 0, 0, 0) . ("\0" x 28);
    print {$sock} $pkt or exit 1;
  ' "127.0.0.1:59040"
  sleep 0.12
done

metrics_ok=0
for _ in $(seq 1 100); do
  m="$(curl -fsS http://127.0.0.1:8344/v1/metrics || true)"
  if echo "$m" | rg -q '"dropped_non_wg_live"[[:space:]]*:[[:space:]]*[1-9][0-9]*' &&
     echo "$m" | rg -q '"accepted_packets"[[:space:]]*:[[:space:]]*[1-9][0-9]*' &&
     echo "$m" | rg -q '"wg_proxy_created"[[:space:]]*:[[:space:]]*[1-9][0-9]*'; then
    metrics_ok=1
    break
  fi
  sleep 0.2
done

if [[ "$metrics_ok" -ne 1 ]]; then
  echo "expected live-WG exit metrics were not observed"
  echo "latest metrics: $(curl -fsS http://127.0.0.1:8344/v1/metrics || true)"
  cat "$LOG_FILE"
  exit 1
fi

if ! rg -q "exit dropped opaque packet session=.*reason=non-wireguard-live" "$LOG_FILE"; then
  echo "expected exit live-mode non-wireguard drop log"
  cat "$LOG_FILE"
  exit 1
fi

echo "exit live-wg mode integration check ok"
