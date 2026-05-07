#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE=/tmp/client_wg_kernel_proxy.log
rm -f "$LOG_FILE"

TMP_BIN_DIR="$(mktemp -d)"
TMP_STATE_DIR="$(mktemp -d)"
KEY_FILE="$(mktemp)"
TRUST_FILE="$(mktemp)"

DIR_PORT=18681
ISSUER_PORT=18682
ENTRY_PORT=18683
EXIT_PORT=18684
ENTRY_DATA_PORT=19680
EXIT_DATA_PORT=19681
EXIT_WG_PORT=19682
CLIENT_WG_PROXY_PORT=57920

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  exit 1
fi

cleanup() {
  kill "${node_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP_BIN_DIR"
  rm -rf "$TMP_STATE_DIR"
  rm -f "$KEY_FILE"
  rm -f "$TRUST_FILE"
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
DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE="$TMP_STATE_DIR/directory.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_STATE_DIR/directory_provider_replay.json" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ISSUER_URLS="http://127.0.0.1:${ISSUER_PORT}" \
CORE_ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ISSUER_PRIVATE_KEY_FILE="$TMP_STATE_DIR/issuer.key" \
ISSUER_SUBJECTS_FILE="$TMP_STATE_DIR/issuer_subjects.json" \
ISSUER_REVOCATIONS_FILE="$TMP_STATE_DIR/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$TMP_STATE_DIR/issuer_anon_revocations.json" \
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
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_STATE_DIR/exit_token_replay.json" \
CLIENT_WG_BACKEND=command \
CLIENT_WG_PRIVATE_KEY_PATH="$KEY_FILE" \
CLIENT_WG_PUBLIC_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
CLIENT_WG_KERNEL_PROXY=1 \
CLIENT_WG_PROXY_ADDR="127.0.0.1:${CLIENT_WG_PROXY_PORT}" \
WG_ALLOW_UNTRUSTED_BINARY_PATH=1 \
CLIENT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=1 \
ENTRY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=1 \
EXIT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=1 \
DIRECTORY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=1 \
DIRECTORY_TRUST_TOFU=1 \
DIRECTORY_TRUSTED_KEYS_FILE="$TRUST_FILE" \
CLIENT_INNER_SOURCE=udp \
CLIENT_DISABLE_SYNTHETIC_FALLBACK=1 \
CLIENT_OPAQUE_SESSION_SEC=2 \
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS=2200 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=2 \
EXIT_OPAQUE_ECHO=1 \
PATH="$TMP_BIN_DIR:$PATH" \
timeout 45s go run ./cmd/node --directory --issuer --entry --exit --client >"$LOG_FILE" 2>&1 &
node_pid=$!

ready=0
for _ in $(seq 1 140); do
  if rg -q "client wg-kernel proxy listening:" "$LOG_FILE"; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ "$ready" -ne 1 ]]; then
  echo "client did not reach wg kernel proxy listening stage"
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
  ' "127.0.0.1:${CLIENT_WG_PROXY_PORT}"; then
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
