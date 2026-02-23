#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE=/tmp/entry_live_wg_filter.log

DATA_PLANE_MODE=opaque \
ENTRY_LIVE_WG_MODE=1 \
CLIENT_INNER_SOURCE=udp \
CLIENT_INNER_UDP_ADDR=127.0.0.1:57900 \
CLIENT_DISABLE_SYNTHETIC_FALLBACK=1 \
CLIENT_OPAQUE_SESSION_SEC=3 \
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS=2500 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=2 \
EXIT_OPAQUE_ECHO=0 \
timeout 50s go run ./cmd/node --directory --issuer --entry --exit --client >"${LOG_FILE}" 2>&1 &
node_pid=$!

cleanup() {
  kill "${node_pid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 3

wait_for_log() {
  local pattern="$1"
  local timeout_sec="${2:-15}"
  local start
  start="$(date +%s)"
  while true; do
    if rg -q "$pattern" "${LOG_FILE}"; then
      return 0
    fi
    if (( $(date +%s) - start >= timeout_sec )); then
      return 1
    fi
    sleep 0.2
  done
}

send_udp_literal() {
  local payload="$1"
  perl -MIO::Socket::INET -e '
    my ($target, $data) = @ARGV;
    my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or die $!;
    print {$sock} $data or die $!;
  ' "127.0.0.1:57900" "$payload"
}

send_udp_wg_transport() {
  perl -MIO::Socket::INET -e '
    my $target = shift @ARGV;
    my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or die $!;
    my $pkt = pack("C4", 4, 0, 0, 0) . ("\0" x 28); # transport-data, 32-byte minimum
    print {$sock} $pkt or die $!;
  ' "127.0.0.1:57900"
}

if ! wait_for_log 'client received wg-session config:' 20; then
  echo "timed out waiting for client session bootstrap"
  cat "${LOG_FILE}"
  exit 1
fi

saw_drop=0
saw_forward=0
for _ in $(seq 1 40); do
  send_udp_literal 'non-wireguard'
  send_udp_wg_transport
  sleep 0.15
  if rg -q 'entry dropped packet session=.*reason=non-wireguard-live' "${LOG_FILE}"; then
    saw_drop=1
  fi
  if rg -q 'exit accepted opaque packet session=' "${LOG_FILE}"; then
    saw_forward=1
  fi
  if [[ "${saw_drop}" -eq 1 && "${saw_forward}" -eq 1 ]]; then
    break
  fi
done

if [[ "${saw_drop}" -ne 1 ]]; then
  echo "expected entry live-mode drop for non-WG packet"
  cat "${LOG_FILE}"
  exit 1
fi

if [[ "${saw_forward}" -ne 1 ]]; then
  echo "expected exit to receive at least one forwarded plausible WG packet"
  cat "${LOG_FILE}"
  exit 1
fi

echo "entry live-wg filter integration check ok"
