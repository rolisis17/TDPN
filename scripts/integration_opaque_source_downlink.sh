#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE=/tmp/opaque_source_downlink.log
rm -f "$LOG_FILE"

DATA_PLANE_MODE=opaque \
CLIENT_INNER_SOURCE=udp \
CLIENT_INNER_UDP_ADDR=127.0.0.1:52900 \
CLIENT_OPAQUE_SINK_ADDR=127.0.0.1:52910 \
CLIENT_OPAQUE_DRAIN_MS=5000 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=2 \
WG_BACKEND=noop \
CLIENT_WG_BACKEND=noop \
EXIT_OPAQUE_ECHO=0 \
EXIT_OPAQUE_SINK_ADDR=127.0.0.1:52912 \
EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:52911 \
WGIO_FROM_WG_ADDR=127.0.0.1:53000 \
WGIO_TO_CLIENT_ADDR=127.0.0.1:52900 \
WGIO_FROM_EXIT_ADDR=127.0.0.1:52910 \
WGIO_TO_WG_ADDR=127.0.0.1:53001 \
WGIOTAP_ADDR=127.0.0.1:53001 \
WGIOINJECT_TARGET_ADDR=127.0.0.1:53000 \
WGIOINJECT_INTERVAL_MS=80 \
WGIOINJECT_WG_LIKE_PCT=100 \
timeout 35s go run ./cmd/node \
  --directory --issuer --entry --exit --client --wgio --wgiotap --wgioinject \
  >"$LOG_FILE" 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

ready=0
for _ in $(seq 1 120); do
  if rg -q "exit accepted opaque packet session=" "$LOG_FILE"; then
    ready=1
    break
  fi
  sleep 0.25
done
if [[ "$ready" -ne 1 ]]; then
  echo "exit did not accept opaque uplink traffic"
  cat "$LOG_FILE"
  exit 1
fi

for i in $(seq 1 30); do
  session_id=$(rg -No "exit accepted opaque packet session=[0-9a-f]+" "$LOG_FILE" | tail -n1 | sed -E 's/.*session=//')
  if [[ -n "${session_id}" ]]; then
    printf "%s\ndownlink-probe-%02d" "$session_id" "$i" >/dev/udp/127.0.0.1/52911 || true
  fi
  sleep 0.1
done

metric_ok=0
for _ in $(seq 1 40); do
  if curl -fsS http://127.0.0.1:8084/v1/metrics 2>/dev/null | rg -q '"forwarded_downlink_packets":[1-9][0-9]*'; then
    metric_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$metric_ok" -ne 1 ]]; then
  echo "expected forwarded_downlink_packets > 0"
  curl -sS http://127.0.0.1:8084/v1/metrics || true
  cat "$LOG_FILE"
  exit 1
fi

client_ok=0
for _ in $(seq 1 50); do
  if rg -q "client downlink opaque packets count=[1-9][0-9]*" "$LOG_FILE"; then
    client_ok=1
    break
  fi
  sleep 0.1
done
if [[ "$client_ok" -ne 1 ]]; then
  echo "expected client downlink opaque packets log entry"
  cat "$LOG_FILE"
  exit 1
fi

echo "opaque source downlink integration check ok"
