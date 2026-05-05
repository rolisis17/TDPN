#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash curl go grep mktemp python3 timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

TMP_DIR="$(mktemp -d)"
MIDDLE_PID=""

cleanup() {
  if [[ -n "${MIDDLE_PID}" ]]; then
    kill "$MIDDLE_PID" >/dev/null 2>&1 || true
    wait "$MIDDLE_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

free_tcp_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

free_udp_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

wait_http_ok() {
  local url="$1"
  local label="$2"
  local deadline_sec="${3:-45}"
  local start
  start="$(date +%s)"
  while true; do
    if curl --silent --show-error --fail --max-time 2 "$url" >/dev/null 2>&1; then
      return 0
    fi
    if (( $(date +%s) - start >= deadline_sec )); then
      echo "timed out waiting for $label at $url"
      cat "$MIDDLE_LOG" || true
      return 1
    fi
    sleep 0.25
  done
}

echo "[middle-service-contract] fail-closed without explicit static route peers"
FAIL_LOG="$TMP_DIR/fail_closed.log"
FAIL_CONTROL_PORT="$(free_tcp_port)"
FAIL_DATA_PORT="$(free_udp_port)"
set +e
env -u MIDDLE_ENTRY_DATA_ADDR -u MIDDLE_EXIT_DATA_ADDR \
  MIDDLE_ADDR="127.0.0.1:${FAIL_CONTROL_PORT}" \
  MIDDLE_DATA_ADDR="127.0.0.1:${FAIL_DATA_PORT}" \
  timeout 60s go run ./cmd/node --middle >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -eq 0 ]]; then
  echo "expected middle service to fail closed without explicit MIDDLE_ENTRY_DATA_ADDR/MIDDLE_EXIT_DATA_ADDR"
  cat "$FAIL_LOG"
  exit 1
fi
if ! grep -F "MIDDLE_ENTRY_DATA_ADDR is required" "$FAIL_LOG" >/dev/null 2>&1; then
  echo "missing fail-closed error for absent MIDDLE_ENTRY_DATA_ADDR"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[middle-service-contract] configured health, readiness, UDP forwarding, and source drop"
CONTROL_PORT="$(free_tcp_port)"
MIDDLE_DATA_PORT="$(free_udp_port)"
ENTRY_DATA_PORT="$(free_udp_port)"
EXIT_DATA_PORT="$(free_udp_port)"
MIDDLE_LOG="$TMP_DIR/middle.log"
READY_FILE="$TMP_DIR/middle.ready"
OBSERVED_FILE="$TMP_DIR/middle.observed"

MIDDLE_ADDR="127.0.0.1:${CONTROL_PORT}" \
MIDDLE_DATA_ADDR="127.0.0.1:${MIDDLE_DATA_PORT}" \
MIDDLE_ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
MIDDLE_EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
MIDDLE_READY_FILE="$READY_FILE" \
MIDDLE_OBSERVED_FILE="$OBSERVED_FILE" \
timeout 90s go run ./cmd/node --middle >"$MIDDLE_LOG" 2>&1 &
MIDDLE_PID=$!

wait_http_ok "http://127.0.0.1:${CONTROL_PORT}/v1/health" "middle health"
wait_http_ok "http://127.0.0.1:${CONTROL_PORT}/v1/ready" "middle readiness"

python3 - "$MIDDLE_DATA_PORT" "$ENTRY_DATA_PORT" "$EXIT_DATA_PORT" <<'PY'
import socket
import sys
import threading
import time

middle_port = int(sys.argv[1])
entry_port = int(sys.argv[2])
exit_port = int(sys.argv[3])
middle_addr = ("127.0.0.1", middle_port)

exit_received = []
exit_errors = []

exit_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
entry_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rogue_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    exit_sock.bind(("127.0.0.1", exit_port))
    entry_sock.bind(("127.0.0.1", entry_port))
    rogue_sock.bind(("127.0.0.1", 0))
    exit_sock.settimeout(5)
    entry_sock.settimeout(5)

    def exit_responder():
        try:
            data, peer = exit_sock.recvfrom(2048)
            exit_received.append(data)
            exit_sock.sendto(b"exit-response", peer)
        except Exception as exc:
            exit_errors.append(str(exc))

    responder = threading.Thread(target=exit_responder)
    responder.start()

    entry_sock.sendto(b"entry-probe", middle_addr)
    data, _ = entry_sock.recvfrom(2048)
    responder.join(timeout=5)
    if responder.is_alive():
        raise SystemExit("exit responder did not finish")
    if exit_errors:
        raise SystemExit("exit responder failed: " + "; ".join(exit_errors))
    if exit_received != [b"entry-probe"]:
        raise SystemExit(f"expected exit to receive entry-probe, got {exit_received!r}")
    if data != b"exit-response":
        raise SystemExit(f"expected entry to receive exit-response, got {data!r}")

    rogue_sock.sendto(b"rogue-probe", middle_addr)
    exit_sock.settimeout(0.75)
    try:
        dropped, _ = exit_sock.recvfrom(2048)
    except socket.timeout:
        dropped = None
    if dropped is not None:
        raise SystemExit(f"expected rogue source to be dropped, exit received {dropped!r}")
finally:
    exit_sock.close()
    entry_sock.close()
    rogue_sock.close()
PY

STATS_FILE="$TMP_DIR/stats.json"
curl --silent --show-error --fail --max-time 3 "http://127.0.0.1:${CONTROL_PORT}/v1/stats" >"$STATS_FILE"
grep -E '"entry_to_exit"[[:space:]]*:[[:space:]]*1' "$STATS_FILE" >/dev/null 2>&1 || {
  echo "expected entry_to_exit counter to be 1"
  cat "$STATS_FILE"
  cat "$MIDDLE_LOG"
  exit 1
}
grep -E '"exit_to_entry"[[:space:]]*:[[:space:]]*1' "$STATS_FILE" >/dev/null 2>&1 || {
  echo "expected exit_to_entry counter to be 1"
  cat "$STATS_FILE"
  cat "$MIDDLE_LOG"
  exit 1
}

echo "middle service contract integration ok"
