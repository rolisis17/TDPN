#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

TMP_DIR="$(mktemp -d)"
LOG_FILE="$TMP_DIR/entry_live_wg_filter.log"
TRUST_FILE="$TMP_DIR/directory_trust.txt"

DIR_PORT=18781
ISSUER_PORT=18782
ENTRY_PORT=18783
EXIT_PORT=18784
ENTRY_DATA_PORT=19780
EXIT_DATA_PORT=19781
EXIT_WG_PORT=19782
CLIENT_INNER_PORT=19790

route_assertion_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
route_assertion_private_key="$(echo "$route_assertion_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
route_assertion_pubkey="$(echo "$route_assertion_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$route_assertion_private_key" || -z "$route_assertion_pubkey" ]]; then
  echo "failed to generate entry route assertion key material"
  exit 1
fi

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
ENTRY_LIVE_WG_MODE=1 \
CLIENT_INNER_SOURCE=udp \
CLIENT_INNER_UDP_ADDR="127.0.0.1:${CLIENT_INNER_PORT}" \
CLIENT_DISABLE_SYNTHETIC_FALLBACK=1 \
CLIENT_OPAQUE_SESSION_SEC=3 \
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS=2500 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=2 \
EXIT_OPAQUE_ECHO=0 \
timeout 50s go run ./cmd/node --directory --issuer --entry --exit --client >"${LOG_FILE}" 2>&1 &
node_pid=$!

cleanup() {
  kill "${node_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
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
  ' "127.0.0.1:${CLIENT_INNER_PORT}" "$payload"
}

send_udp_wg_transport() {
  perl -MIO::Socket::INET -e '
    my $target = shift @ARGV;
    my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or die $!;
    my $pkt = pack("C4", 4, 0, 0, 0) . ("\0" x 28); # transport-data, 32-byte minimum
    print {$sock} $pkt or die $!;
  ' "127.0.0.1:${CLIENT_INNER_PORT}"
}

if ! wait_for_log 'client wireguard runtime ready:' 20; then
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
