#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this script requires Linux (wireguard kernel interface support)"
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: sudo ./scripts/integration_real_wg_privileged.sh"
  exit 2
fi
for cmd in go wg ip curl rg perl timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

CLIENT_IFACE="${CLIENT_IFACE:-wgcint0}"
EXIT_IFACE="${EXIT_IFACE:-wgeint0}"
CLIENT_PROXY_ADDR="${CLIENT_PROXY_ADDR:-127.0.0.1:57960}"
ENTRY_DATA_ADDR="${ENTRY_DATA_ADDR:-127.0.0.1:51980}"
EXIT_DATA_ADDR="${EXIT_DATA_ADDR:-127.0.0.1:51981}"
EXIT_WG_PORT="${EXIT_WG_PORT:-51982}"
SCRIPT_TIMEOUT_SEC="${SCRIPT_TIMEOUT_SEC:-120}"
CLIENT_OPAQUE_SESSION_SEC="${CLIENT_OPAQUE_SESSION_SEC:-30}"
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS="${CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS:-5000}"
CLIENT_BOOTSTRAP_INTERVAL_SEC="${CLIENT_BOOTSTRAP_INTERVAL_SEC:-1}"
CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC="${CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC:-2}"
LOG_FILE="${LOG_FILE:-/tmp/integration_real_wg_privileged.log}"
KEY_DIR="$(mktemp -d)"
CLIENT_KEY_FILE="$KEY_DIR/client.key"
EXIT_KEY_FILE="$KEY_DIR/exit.key"

cleanup() {
  kill "${node_pid:-}" >/dev/null 2>&1 || true
  ip link delete "$CLIENT_IFACE" >/dev/null 2>&1 || true
  ip link delete "$EXIT_IFACE" >/dev/null 2>&1 || true
  rm -rf "$KEY_DIR"
}
trap cleanup EXIT

ip link delete "$CLIENT_IFACE" >/dev/null 2>&1 || true
ip link delete "$EXIT_IFACE" >/dev/null 2>&1 || true

if ! ip link add dev "$CLIENT_IFACE" type wireguard >/dev/null 2>&1; then
  echo "failed to create wireguard interface $CLIENT_IFACE (is wireguard kernel support available?)"
  exit 2
fi
if ! ip link add dev "$EXIT_IFACE" type wireguard >/dev/null 2>&1; then
  echo "failed to create wireguard interface $EXIT_IFACE (is wireguard kernel support available?)"
  exit 2
fi

wg genkey >"$CLIENT_KEY_FILE"
wg genkey >"$EXIT_KEY_FILE"
chmod 600 "$CLIENT_KEY_FILE" "$EXIT_KEY_FILE"
CLIENT_WG_PUB="$(wg pubkey <"$CLIENT_KEY_FILE")"
EXIT_WG_PUB="$(wg pubkey <"$EXIT_KEY_FILE")"

rm -f "$LOG_FILE"

DATA_PLANE_MODE=opaque \
CLIENT_WG_BACKEND=command \
WG_BACKEND=command \
CLIENT_WG_PRIVATE_KEY_PATH="$CLIENT_KEY_FILE" \
CLIENT_WG_PUBLIC_KEY="$CLIENT_WG_PUB" \
EXIT_WG_PRIVATE_KEY_PATH="$EXIT_KEY_FILE" \
EXIT_WG_PUBKEY="$EXIT_WG_PUB" \
CLIENT_WG_INTERFACE="$CLIENT_IFACE" \
EXIT_WG_INTERFACE="$EXIT_IFACE" \
CLIENT_WG_INSTALL_ROUTE=0 \
CLIENT_WG_KERNEL_PROXY=1 \
CLIENT_WG_PROXY_ADDR="$CLIENT_PROXY_ADDR" \
CLIENT_INNER_SOURCE=synthetic \
CLIENT_OPAQUE_SESSION_SEC="$CLIENT_OPAQUE_SESSION_SEC" \
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS="$CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS" \
CLIENT_BOOTSTRAP_INTERVAL_SEC="$CLIENT_BOOTSTRAP_INTERVAL_SEC" \
CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC="$CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC" \
ENTRY_DATA_ADDR="$ENTRY_DATA_ADDR" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
EXIT_WG_LISTEN_PORT="$EXIT_WG_PORT" \
EXIT_WG_KERNEL_PROXY=1 \
timeout "${SCRIPT_TIMEOUT_SEC}s" go run ./cmd/node --directory --issuer --entry --exit --client >"$LOG_FILE" 2>&1 &
node_pid=$!

ready=0
for _ in $(seq 1 200); do
  if ! kill -0 "$node_pid" >/dev/null 2>&1; then
    echo "node exited before client session config"
    cat "$LOG_FILE"
    exit 1
  fi
  if rg -q "client received wg-session config:" "$LOG_FILE"; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ "$ready" -ne 1 ]]; then
  echo "client did not reach wg session config stage"
  cat "$LOG_FILE"
  exit 1
fi

relay_json="$(curl -fsS "http://127.0.0.1:8081/v1/relays" || true)"
if ! echo "$relay_json" | rg -q "\"endpoint\":\"$ENTRY_DATA_ADDR\""; then
  echo "directory entry endpoint mismatch (expected $ENTRY_DATA_ADDR)"
  echo "$relay_json"
  cat "$LOG_FILE"
  exit 1
fi
if ! echo "$relay_json" | rg -q "\"endpoint\":\"$EXIT_DATA_ADDR\""; then
  echo "directory exit endpoint mismatch (expected $EXIT_DATA_ADDR)"
  echo "$relay_json"
  cat "$LOG_FILE"
  exit 1
fi

iface_ready=0
for _ in $(seq 1 60); do
  if wg show "$CLIENT_IFACE" >/dev/null 2>&1 && wg show "$EXIT_IFACE" >/dev/null 2>&1; then
    iface_ready=1
    break
  fi
  sleep 0.2
done
if [[ "$iface_ready" -ne 1 ]]; then
  echo "wireguard interfaces were not configured"
  ip link show "$CLIENT_IFACE" >/dev/null 2>&1 && ip link show "$CLIENT_IFACE" || true
  ip link show "$EXIT_IFACE" >/dev/null 2>&1 && ip link show "$EXIT_IFACE" || true
  cat "$LOG_FILE"
  exit 1
fi

client_peer_ok=0
for _ in $(seq 1 80); do
  if wg show "$CLIENT_IFACE" peers | grep -Fqx -- "$EXIT_WG_PUB"; then
    client_peer_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$client_peer_ok" -ne 1 ]]; then
  echo "client wireguard interface missing expected exit peer ${EXIT_WG_PUB}"
  wg show "$CLIENT_IFACE" || true
  cat "$LOG_FILE"
  exit 1
fi

client_ep_ok=0
for _ in $(seq 1 80); do
  if wg show "$CLIENT_IFACE" endpoints | awk -v key="$EXIT_WG_PUB" -v endpoint="$CLIENT_PROXY_ADDR" '
    $1 == key && $2 == endpoint { found = 1 }
    END { exit(found ? 0 : 1) }
  '; then
    client_ep_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$client_ep_ok" -ne 1 ]]; then
  echo "client wireguard endpoint not set to kernel proxy address ${CLIENT_PROXY_ADDR}"
  wg show "$CLIENT_IFACE" endpoints || true
  cat "$LOG_FILE"
  exit 1
fi

exit_port="$(wg show "$EXIT_IFACE" listen-port || true)"
if [[ "$exit_port" != "$EXIT_WG_PORT" ]]; then
  echo "exit wireguard listen-port mismatch: got=${exit_port} expected=${EXIT_WG_PORT}"
  wg show "$EXIT_IFACE" || true
  cat "$LOG_FILE"
  exit 1
fi

session_active=0
for _ in $(seq 1 100); do
  metrics_json="$(curl -fsS "http://127.0.0.1:8084/v1/metrics" 2>/dev/null || true)"
  if echo "$metrics_json" | rg -q '"active_sessions"[[:space:]]*:[[:space:]]*[1-9][0-9]*'; then
    session_active=1
    break
  fi
  sleep 0.1
done
if [[ "$session_active" -ne 1 ]]; then
  echo "exit never reported an active session before packet injection"
  if [[ -n "${metrics_json:-}" ]]; then
    echo "latest exit metrics: $metrics_json"
  fi
  cat "$LOG_FILE"
  exit 1
fi

exit_peer_ok=0
for _ in $(seq 1 80); do
  if wg show "$EXIT_IFACE" peers | grep -Fqx -- "$CLIENT_WG_PUB"; then
    exit_peer_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$exit_peer_ok" -ne 1 ]]; then
  echo "exit wireguard interface missing expected client peer ${CLIENT_WG_PUB}"
  wg show "$EXIT_IFACE" || true
  cat "$LOG_FILE"
  exit 1
fi

up_ok=0
exit_ok=0
metrics_ok=0
for _ in $(seq 1 8); do
  if ! perl -MIO::Socket::INET -e '
    my $target = shift @ARGV;
    my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or exit 1;
    my $pkt = pack("C4", 4, 0, 0, 0) . ("\0" x 28);
    print {$sock} $pkt or exit 1;
  ' "$CLIENT_PROXY_ADDR"; then
    echo "failed to inject wg-like packet into client proxy"
    cat "$LOG_FILE"
    exit 1
  fi
  sleep 0.1
done

hs_ok=0
for _ in $(seq 1 80); do
  client_hs="$(wg show "$CLIENT_IFACE" latest-handshakes | awk -v key="$EXIT_WG_PUB" '$1==key {print $2}')"
  exit_hs="$(wg show "$EXIT_IFACE" latest-handshakes | awk -v key="$CLIENT_WG_PUB" '$1==key {print $2}')"
  if [[ "${client_hs:-0}" -gt 0 && "${exit_hs:-0}" -gt 0 ]]; then
    hs_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$hs_ok" -ne 1 ]]; then
  echo "wireguard latest-handshakes did not become active on both interfaces"
  wg show "$CLIENT_IFACE" latest-handshakes || true
  wg show "$EXIT_IFACE" latest-handshakes || true
  cat "$LOG_FILE"
  exit 1
fi

transfer_ok=0
for _ in $(seq 1 80); do
  client_tx="$(wg show "$CLIENT_IFACE" transfer | awk -v key="$EXIT_WG_PUB" '$1==key {print $3}')"
  exit_rx="$(wg show "$EXIT_IFACE" transfer | awk -v key="$CLIENT_WG_PUB" '$1==key {print $2}')"
  if [[ "${client_tx:-0}" -gt 0 && "${exit_rx:-0}" -gt 0 ]]; then
    transfer_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$transfer_ok" -ne 1 ]]; then
  echo "wireguard transfer counters did not advance on client->exit path"
  wg show "$CLIENT_IFACE" transfer || true
  wg show "$EXIT_IFACE" transfer || true
  cat "$LOG_FILE"
  exit 1
fi

for _ in $(seq 1 80); do
  if rg -q "client wg-kernel proxy uplink packets=[1-9][0-9]*" "$LOG_FILE"; then
    up_ok=1
  fi
  if rg -q "exit accepted opaque packet session=.*wg_like=(true|false)" "$LOG_FILE"; then
    exit_ok=1
  fi
  metrics_json="$(curl -fsS "http://127.0.0.1:8084/v1/metrics" 2>/dev/null || true)"
  if echo "$metrics_json" | rg -q '"accepted_packets"[[:space:]]*:[[:space:]]*[1-9][0-9]*' &&
    echo "$metrics_json" | rg -q '"wg_proxy_created"[[:space:]]*:[[:space:]]*[1-9][0-9]*'; then
    metrics_ok=1
  fi
  if [[ "$exit_ok" -eq 1 || "$metrics_ok" -eq 1 ]]; then
    break
  fi
  sleep 0.25
done

if [[ "$exit_ok" -ne 1 && "$metrics_ok" -ne 1 ]]; then
  echo "missing expected real wg integration log signals"
  if [[ -n "${metrics_json:-}" ]]; then
    echo "latest exit metrics: $metrics_json"
  fi
  cat "$LOG_FILE"
  exit 1
fi

if [[ "$up_ok" -ne 1 ]]; then
  echo "note: client uplink summary log not observed before script completion (traffic still verified via exit metrics/logs)"
fi

echo "real wg privileged integration check ok"
