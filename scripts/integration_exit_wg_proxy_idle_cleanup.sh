#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_NODE=/tmp/exit_wg_proxy_idle_node.log
LOG_CLIENT=/tmp/exit_wg_proxy_idle_client.log
rm -f "$LOG_NODE" "$LOG_CLIENT"

TMP_DIR="$(mktemp -d)"
TMP_BIN_DIR="$TMP_DIR/bin"
mkdir -p "$TMP_BIN_DIR"
KEY_EXIT="$TMP_DIR/exit.key"
KEY_CLIENT="$TMP_DIR/client.key"

cleanup() {
  kill "${node_pid:-}" "${client_pid:-}" >/dev/null 2>&1 || true
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
EXIT_WG_PRIVATE_KEY_PATH="$KEY_EXIT" \
EXIT_WG_PUBKEY="$FIXED_WG_PUB" \
EXIT_WG_KERNEL_PROXY=1 \
EXIT_WG_KERNEL_PROXY_MAX_SESSIONS=8 \
EXIT_WG_KERNEL_PROXY_IDLE_SEC=2 \
EXIT_SESSION_CLEANUP_SEC=1 \
EXIT_WG_LISTEN_PORT=53231 \
ENTRY_DATA_ADDR=127.0.0.1:53220 \
ENTRY_ENDPOINT=127.0.0.1:53220 \
EXIT_DATA_ADDR=127.0.0.1:53221 \
EXIT_ENDPOINT=127.0.0.1:53221 \
ENTRY_ADDR=127.0.0.1:8323 \
EXIT_ADDR=127.0.0.1:8324 \
DIRECTORY_ADDR=127.0.0.1:8321 \
ISSUER_ADDR=127.0.0.1:8322 \
ISSUER_URL=http://127.0.0.1:8322 \
ENTRY_URL=http://127.0.0.1:8323 \
EXIT_CONTROL_URL=http://127.0.0.1:8324 \
DIRECTORY_URL=http://127.0.0.1:8321 \
PATH="$TMP_BIN_DIR:$PATH" \
timeout 70s go run ./cmd/node --directory --issuer --entry --exit >"$LOG_NODE" 2>&1 &
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

if ! wait_http_ok "http://127.0.0.1:8321/v1/relays" 30; then
  echo "infra node did not become healthy"
  cat "$LOG_NODE"
  exit 1
fi

DATA_PLANE_MODE=opaque \
CLIENT_WG_BACKEND=command \
CLIENT_WG_PRIVATE_KEY_PATH="$KEY_CLIENT" \
CLIENT_WG_PUBLIC_KEY="$FIXED_WG_PUB" \
CLIENT_WG_KERNEL_PROXY=1 \
CLIENT_WG_PROXY_ADDR=127.0.0.1:59020 \
CLIENT_WG_INTERFACE=wgc-idle1 \
CLIENT_INNER_SOURCE=synthetic \
CLIENT_OPAQUE_SESSION_SEC=16 \
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS=5000 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
DIRECTORY_URL=http://127.0.0.1:8321 \
ISSUER_URL=http://127.0.0.1:8322 \
ENTRY_URL=http://127.0.0.1:8323 \
PATH="$TMP_BIN_DIR:$PATH" \
timeout 40s go run ./cmd/node --client >"$LOG_CLIENT" 2>&1 &
client_pid=$!

ready=0
for _ in $(seq 1 180); do
  if rg -q "client received wg-session config:" "$LOG_CLIENT"; then
    ready=1
    break
  fi
  sleep 0.15
done
if [[ "$ready" -ne 1 ]]; then
  echo "client did not receive session config"
  cat "$LOG_CLIENT"
  cat "$LOG_NODE"
  exit 1
fi

for _ in $(seq 1 4); do
  perl -MIO::Socket::INET -e '
    my $target = shift @ARGV;
    my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or exit 1;
    my $pkt = pack("C4", 4, 0, 0, 0) . ("\0" x 28);
    print {$sock} $pkt or exit 1;
  ' "127.0.0.1:59020"
  sleep 0.1
done

created_ok=0
for _ in $(seq 1 100); do
  m="$(curl -fsS http://127.0.0.1:8324/v1/metrics || true)"
  if echo "$m" | rg -q '"wg_proxy_created"[[:space:]]*:[[:space:]]*[1-9][0-9]*' &&
     echo "$m" | rg -q '"active_wg_proxy_sessions"[[:space:]]*:[[:space:]]*[1-9][0-9]*'; then
    created_ok=1
    break
  fi
  sleep 0.1
done
if [[ "$created_ok" -ne 1 ]]; then
  echo "expected wg proxy creation not observed"
  echo "latest metrics: $(curl -fsS http://127.0.0.1:8324/v1/metrics || true)"
  cat "$LOG_NODE"
  cat "$LOG_CLIENT"
  exit 1
fi

idle_ok=0
for _ in $(seq 1 140); do
  m="$(curl -fsS http://127.0.0.1:8324/v1/metrics || true)"
  if echo "$m" | rg -q '"wg_proxy_idle_closed"[[:space:]]*:[[:space:]]*[1-9][0-9]*' &&
     echo "$m" | rg -q '"active_wg_proxy_sessions"[[:space:]]*:[[:space:]]*0'; then
    idle_ok=1
    break
  fi
  sleep 0.15
done
if [[ "$idle_ok" -ne 1 ]]; then
  echo "expected wg proxy idle cleanup not observed"
  echo "latest metrics: $(curl -fsS http://127.0.0.1:8324/v1/metrics || true)"
  cat "$LOG_NODE"
  cat "$LOG_CLIENT"
  exit 1
fi

echo "exit wg proxy idle cleanup integration check ok"
