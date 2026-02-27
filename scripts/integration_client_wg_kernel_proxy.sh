#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE=/tmp/client_wg_kernel_proxy.log
rm -f "$LOG_FILE"

TMP_BIN_DIR="$(mktemp -d)"
KEY_FILE="$(mktemp)"
cleanup() {
  kill "${node_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP_BIN_DIR"
  rm -f "$KEY_FILE"
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
printf "fake-private-key\n" >"$KEY_FILE"

DATA_PLANE_MODE=opaque \
CLIENT_WG_BACKEND=command \
CLIENT_WG_PRIVATE_KEY_PATH="$KEY_FILE" \
CLIENT_WG_PUBLIC_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
CLIENT_WG_KERNEL_PROXY=1 \
CLIENT_WG_PROXY_ADDR=127.0.0.1:57920 \
CLIENT_INNER_SOURCE=synthetic \
CLIENT_OPAQUE_SESSION_SEC=2 \
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS=2200 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=2 \
EXIT_OPAQUE_ECHO=1 \
PATH="$TMP_BIN_DIR:$PATH" \
timeout 45s go run ./cmd/node --directory --issuer --entry --exit --client >"$LOG_FILE" 2>&1 &
node_pid=$!

ready=0
for _ in $(seq 1 140); do
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

sent=0
for _ in $(seq 1 40); do
  if perl -MIO::Socket::INET -MIO::Select -e '
    my $target = shift @ARGV;
    my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or exit 1;
    my $pkt = pack("C4", 4, 0, 0, 0) . ("\0" x 28);
    print {$sock} $pkt or exit 1;
    my $sel = IO::Select->new($sock);
    if ($sel->can_read(1.5)) {
      my $buf = "";
      $sock->recv($buf, 4096);
      exit(length($buf) > 0 ? 0 : 1);
    }
    exit 1;
  ' "127.0.0.1:57920"; then
    sent=1
    break
  fi
  sleep 0.1
done
if [[ "$sent" -ne 1 ]]; then
  echo "failed to send/receive packet through client wg kernel proxy"
  cat "$LOG_FILE"
  exit 1
fi

up_ok=0
down_ok=0
for _ in $(seq 1 40); do
  if rg -q "client wg-kernel proxy uplink packets=[1-9][0-9]*" "$LOG_FILE"; then
    up_ok=1
  fi
  if rg -q "client wg-kernel proxy downlink packets=[1-9][0-9]*" "$LOG_FILE"; then
    down_ok=1
  fi
  if [[ "$up_ok" -eq 1 && "$down_ok" -eq 1 ]]; then
    break
  fi
  sleep 0.1
done

if [[ "$up_ok" -ne 1 || "$down_ok" -ne 1 ]]; then
  echo "missing client wg kernel proxy packet counters in log"
  cat "$LOG_FILE"
  exit 1
fi

echo "client wg-kernel proxy integration check ok"
