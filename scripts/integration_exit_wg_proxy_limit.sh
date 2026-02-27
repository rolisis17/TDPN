#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_NODE=/tmp/exit_wg_proxy_limit_node.log
LOG_CLIENT1=/tmp/exit_wg_proxy_limit_client1.log
LOG_CLIENT2=/tmp/exit_wg_proxy_limit_client2.log
rm -f "$LOG_NODE" "$LOG_CLIENT1" "$LOG_CLIENT2"

TMP_DIR="$(mktemp -d)"
TMP_BIN_DIR="$TMP_DIR/bin"
mkdir -p "$TMP_BIN_DIR"
KEY_EXIT="$TMP_DIR/exit.key"
KEY_C1="$TMP_DIR/client1.key"
KEY_C2="$TMP_DIR/client2.key"

cleanup() {
  kill "${node_pid:-}" "${client1_pid:-}" "${client2_pid:-}" >/dev/null 2>&1 || true
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
printf "fake-client1-key\n" >"$KEY_C1"
printf "fake-client2-key\n" >"$KEY_C2"
FIXED_WG_PUB="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

DATA_PLANE_MODE=opaque \
WG_BACKEND=command \
EXIT_WG_PRIVATE_KEY_PATH="$KEY_EXIT" \
EXIT_WG_PUBKEY="$FIXED_WG_PUB" \
EXIT_WG_KERNEL_PROXY=1 \
EXIT_WG_KERNEL_PROXY_MAX_SESSIONS=1 \
EXIT_WG_KERNEL_PROXY_IDLE_SEC=60 \
EXIT_SESSION_CLEANUP_SEC=1 \
EXIT_WG_LISTEN_PORT=53131 \
ENTRY_DATA_ADDR=127.0.0.1:53120 \
ENTRY_ENDPOINT=127.0.0.1:53120 \
EXIT_DATA_ADDR=127.0.0.1:53121 \
EXIT_ENDPOINT=127.0.0.1:53121 \
ENTRY_ADDR=127.0.0.1:8313 \
EXIT_ADDR=127.0.0.1:8314 \
DIRECTORY_ADDR=127.0.0.1:8311 \
ISSUER_ADDR=127.0.0.1:8312 \
ISSUER_URL=http://127.0.0.1:8312 \
ENTRY_URL=http://127.0.0.1:8313 \
EXIT_CONTROL_URL=http://127.0.0.1:8314 \
DIRECTORY_URL=http://127.0.0.1:8311 \
PATH="$TMP_BIN_DIR:$PATH" \
timeout 80s go run ./cmd/node --directory --issuer --entry --exit >"$LOG_NODE" 2>&1 &
node_pid=$!

wait_http_ok() {
  local url="$1"
  local timeout_sec="${2:-20}"
  local start
  start="$(date +%s)"
  while true; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    if (( $(date +%s) - start >= timeout_sec )); then
      return 1
    fi
    sleep 0.2
  done
}

if ! wait_http_ok "http://127.0.0.1:8311/v1/relays" 30; then
  echo "infra node did not become healthy"
  cat "$LOG_NODE"
  exit 1
fi

CLIENT_COMMON=(
  DATA_PLANE_MODE=opaque
  CLIENT_WG_BACKEND=command
  CLIENT_WG_PUBLIC_KEY=$FIXED_WG_PUB
  CLIENT_WG_KERNEL_PROXY=1
  CLIENT_INNER_SOURCE=synthetic
  CLIENT_OPAQUE_SESSION_SEC=14
  CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS=5000
  CLIENT_BOOTSTRAP_INTERVAL_SEC=1
  DIRECTORY_URL=http://127.0.0.1:8311
  ISSUER_URL=http://127.0.0.1:8312
  ENTRY_URL=http://127.0.0.1:8313
)

env "${CLIENT_COMMON[@]}" \
  CLIENT_WG_PRIVATE_KEY_PATH="$KEY_C1" \
  CLIENT_WG_PROXY_ADDR=127.0.0.1:58920 \
  CLIENT_WG_INTERFACE=wgc-limit1 \
  PATH="$TMP_BIN_DIR:$PATH" \
  timeout 50s go run ./cmd/node --client >"$LOG_CLIENT1" 2>&1 &
client1_pid=$!

env "${CLIENT_COMMON[@]}" \
  CLIENT_WG_PRIVATE_KEY_PATH="$KEY_C2" \
  CLIENT_WG_PROXY_ADDR=127.0.0.1:58921 \
  CLIENT_WG_INTERFACE=wgc-limit2 \
  PATH="$TMP_BIN_DIR:$PATH" \
  timeout 50s go run ./cmd/node --client >"$LOG_CLIENT2" 2>&1 &
client2_pid=$!

wait_client_cfg() {
  local log="$1"
  local timeout_sec="${2:-30}"
  local start
  start="$(date +%s)"
  while true; do
    if rg -q "client received wg-session config:" "$log"; then
      return 0
    fi
    if (( $(date +%s) - start >= timeout_sec )); then
      return 1
    fi
    sleep 0.2
  done
}

if ! wait_client_cfg "$LOG_CLIENT1" 35; then
  echo "client1 did not receive session config"
  cat "$LOG_CLIENT1"
  cat "$LOG_NODE"
  exit 1
fi
if ! wait_client_cfg "$LOG_CLIENT2" 35; then
  echo "client2 did not receive session config"
  cat "$LOG_CLIENT2"
  cat "$LOG_NODE"
  exit 1
fi

for _ in $(seq 1 8); do
  perl -MIO::Socket::INET -e '
    my $target = shift @ARGV;
    my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or exit 1;
    my $pkt = pack("C4", 4, 0, 0, 0) . ("\0" x 28);
    print {$sock} $pkt or exit 1;
  ' "127.0.0.1:58920"
  perl -MIO::Socket::INET -e '
    my $target = shift @ARGV;
    my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or exit 1;
    my $pkt = pack("C4", 4, 0, 0, 0) . ("\0" x 28);
    print {$sock} $pkt or exit 1;
  ' "127.0.0.1:58921"
  sleep 0.15
done

metrics_ok=0
for _ in $(seq 1 80); do
  m="$(curl -fsS http://127.0.0.1:8314/v1/metrics || true)"
  if echo "$m" | rg -q '"wg_proxy_created"[[:space:]]*:[[:space:]]*1' &&
     echo "$m" | rg -q '"wg_proxy_limit_drops"[[:space:]]*:[[:space:]]*[1-9][0-9]*' &&
     echo "$m" | rg -q '"accepted_packets"[[:space:]]*:[[:space:]]*[1-9][0-9]*'; then
    metrics_ok=1
    break
  fi
  sleep 0.2
done

if [[ "$metrics_ok" -ne 1 ]]; then
  echo "expected exit wg proxy limit metrics not observed"
  echo "latest metrics: $(curl -fsS http://127.0.0.1:8314/v1/metrics || true)"
  cat "$LOG_NODE"
  cat "$LOG_CLIENT1"
  cat "$LOG_CLIENT2"
  exit 1
fi

echo "exit wg proxy limit integration check ok"
