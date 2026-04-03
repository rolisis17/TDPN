#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export DATA_PLANE_MODE="${DATA_PLANE_MODE:-opaque}"
export CLIENT_INNER_SOURCE="${CLIENT_INNER_SOURCE:-udp}"
export CLIENT_OPAQUE_DRAIN_MS="${CLIENT_OPAQUE_DRAIN_MS:-1800}"
export CLIENT_BOOTSTRAP_INTERVAL_SEC="${CLIENT_BOOTSTRAP_INTERVAL_SEC:-2}"
export EXIT_OPAQUE_ECHO="${EXIT_OPAQUE_ECHO:-1}"
export EXIT_OPAQUE_SINK_ADDR="${EXIT_OPAQUE_SINK_ADDR:-}"

export WG_BACKEND="${WG_BACKEND:-noop}"
export CLIENT_WG_BACKEND="${CLIENT_WG_BACKEND:-noop}"

port_in_use_01() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    if ss -H -ltnu 2>/dev/null | awk '{print $5}' | grep -Eq "(^|[:.])${port}$"; then
      return 0
    fi
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN -iUDP:"$port" >/dev/null 2>&1; then
      return 0
    fi
  fi
  return 1
}

demo_assign_auto_ports_01() {
  local control_base="${DEMO_CONTROL_BASE_PORT:-8081}"
  local data_base="${DEMO_DATA_BASE_PORT:-51820}"
  local step="${DEMO_PORT_BLOCK_STEP:-20}"
  local attempts="${DEMO_PORT_BLOCK_ATTEMPTS:-32}"
  local attempt=0
  local control_port=0
  local data_port=0
  local port=0
  local busy=0
  local -a required_ports=()

  for ((attempt = 0; attempt < attempts; attempt++)); do
    control_port=$((control_base + attempt * step))
    data_port=$((data_base + attempt * step))
    required_ports=(
      "$control_port"
      "$((control_port + 1))"
      "$((control_port + 2))"
      "$((control_port + 3))"
      "$data_port"
      "$((data_port + 1))"
      "$((data_port + 80))"
      "$((data_port + 81))"
      "$((data_port + 100))"
      "$((data_port + 101))"
    )

    busy=0
    for port in "${required_ports[@]}"; do
      if port_in_use_01 "$port"; then
        busy=1
        break
      fi
    done
    if ((busy == 0)); then
      DIRECTORY_ADDR="127.0.0.1:${control_port}"
      ISSUER_ADDR="127.0.0.1:$((control_port + 1))"
      ENTRY_ADDR="127.0.0.1:$((control_port + 2))"
      EXIT_ADDR="127.0.0.1:$((control_port + 3))"
      ENTRY_DATA_ADDR="127.0.0.1:${data_port}"
      EXIT_DATA_ADDR="127.0.0.1:$((data_port + 1))"
      ENTRY_ENDPOINT="$ENTRY_DATA_ADDR"
      EXIT_ENDPOINT="$EXIT_DATA_ADDR"
      CLIENT_INNER_UDP_ADDR="127.0.0.1:$((data_port + 80))"
      CLIENT_OPAQUE_SINK_ADDR="127.0.0.1:$((data_port + 81))"
      WGIO_FROM_WG_ADDR="127.0.0.1:$((data_port + 100))"
      WGIO_TO_CLIENT_ADDR="$CLIENT_INNER_UDP_ADDR"
      WGIO_FROM_EXIT_ADDR="$CLIENT_OPAQUE_SINK_ADDR"
      WGIO_TO_WG_ADDR="127.0.0.1:$((data_port + 101))"
      WGIOTAP_ADDR="$WGIO_TO_WG_ADDR"
      WGIOINJECT_TARGET_ADDR="$WGIO_FROM_WG_ADDR"
      export DIRECTORY_ADDR ISSUER_ADDR ENTRY_ADDR EXIT_ADDR ENTRY_DATA_ADDR EXIT_DATA_ADDR ENTRY_ENDPOINT EXIT_ENDPOINT
      export CLIENT_INNER_UDP_ADDR CLIENT_OPAQUE_SINK_ADDR WGIO_FROM_WG_ADDR WGIO_TO_CLIENT_ADDR WGIO_FROM_EXIT_ADDR WGIO_TO_WG_ADDR WGIOTAP_ADDR WGIOINJECT_TARGET_ADDR
      export DEMO_SELECTED_PORT_OFFSET="$((attempt * step))"
      return 0
    fi
  done
  return 1
}

demo_ports_preconfigured=0
for name in \
  DIRECTORY_ADDR ISSUER_ADDR ENTRY_ADDR EXIT_ADDR ENTRY_DATA_ADDR EXIT_DATA_ADDR ENTRY_ENDPOINT EXIT_ENDPOINT \
  CLIENT_INNER_UDP_ADDR CLIENT_OPAQUE_SINK_ADDR WGIO_FROM_WG_ADDR WGIO_TO_CLIENT_ADDR WGIO_FROM_EXIT_ADDR WGIO_TO_WG_ADDR WGIOTAP_ADDR WGIOINJECT_TARGET_ADDR; do
  if [[ -n "${!name:-}" ]]; then
    demo_ports_preconfigured=1
    break
  fi
done
if [[ "${DEMO_AUTO_PORT_SELECT:-1}" == "1" && "$demo_ports_preconfigured" == "0" ]]; then
  if ! demo_assign_auto_ports_01; then
    echo "[demo] unable to find a free local port block for internal topology demo" >&2
    exit 1
  fi
fi

export DIRECTORY_ADDR="${DIRECTORY_ADDR:-127.0.0.1:8081}"
export ISSUER_ADDR="${ISSUER_ADDR:-127.0.0.1:8082}"
export ENTRY_ADDR="${ENTRY_ADDR:-127.0.0.1:8083}"
export EXIT_ADDR="${EXIT_ADDR:-127.0.0.1:8084}"
export ENTRY_DATA_ADDR="${ENTRY_DATA_ADDR:-127.0.0.1:51820}"
export EXIT_DATA_ADDR="${EXIT_DATA_ADDR:-127.0.0.1:51821}"
export ENTRY_ENDPOINT="${ENTRY_ENDPOINT:-$ENTRY_DATA_ADDR}"
export EXIT_ENDPOINT="${EXIT_ENDPOINT:-$EXIT_DATA_ADDR}"

export CLIENT_INNER_UDP_ADDR="${CLIENT_INNER_UDP_ADDR:-127.0.0.1:51900}"
export CLIENT_OPAQUE_SINK_ADDR="${CLIENT_OPAQUE_SINK_ADDR:-127.0.0.1:51910}"

export WGIO_FROM_WG_ADDR="${WGIO_FROM_WG_ADDR:-127.0.0.1:52000}"
export WGIO_TO_CLIENT_ADDR="${WGIO_TO_CLIENT_ADDR:-$CLIENT_INNER_UDP_ADDR}"
export WGIO_FROM_EXIT_ADDR="${WGIO_FROM_EXIT_ADDR:-$CLIENT_OPAQUE_SINK_ADDR}"
export WGIO_TO_WG_ADDR="${WGIO_TO_WG_ADDR:-127.0.0.1:52001}"

export WGIOTAP_ADDR="${WGIOTAP_ADDR:-$WGIO_TO_WG_ADDR}"

export WGIOINJECT_TARGET_ADDR="${WGIOINJECT_TARGET_ADDR:-$WGIO_FROM_WG_ADDR}"
export WGIOINJECT_INTERVAL_MS="${WGIOINJECT_INTERVAL_MS:-120}"
export WGIOINJECT_WG_LIKE_PCT="${WGIOINJECT_WG_LIKE_PCT:-90}"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

DURATION="${DEMO_DURATION_SEC:-15}"
DEMO_BIN="$(mktemp "${TMPDIR:-/tmp}/privacynode-demo-internal-topology.XXXXXX")"

cleanup() {
  rm -f "$DEMO_BIN"
}
trap cleanup EXIT

echo "[demo] running internal topology for ${DURATION}s"
echo "[demo] mode=${DATA_PLANE_MODE} source=${CLIENT_INNER_SOURCE} wg_backend=${WG_BACKEND} client_wg_backend=${CLIENT_WG_BACKEND}"
echo "[demo] control_addrs directory=${DIRECTORY_ADDR} issuer=${ISSUER_ADDR} entry=${ENTRY_ADDR} exit=${EXIT_ADDR}"
echo "[demo] data_addrs entry_data=${ENTRY_DATA_ADDR} exit_data=${EXIT_DATA_ADDR} client_inner=${CLIENT_INNER_UDP_ADDR} client_sink=${CLIENT_OPAQUE_SINK_ADDR}"
if [[ -n "${DEMO_SELECTED_PORT_OFFSET:-}" ]]; then
  echo "[demo] auto-port-select offset=${DEMO_SELECTED_PORT_OFFSET}"
fi

go build -o "$DEMO_BIN" ./cmd/node

timeout "${DURATION}s" "$DEMO_BIN" \
  --directory --issuer --entry --exit --client --wgio --wgiotap --wgioinject
