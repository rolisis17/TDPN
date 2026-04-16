#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHAIN_DIR="$ROOT_DIR/blockchain/tdpn-chain"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

TMP_ROOT="$(mktemp -d -t tdpnd-comet-runtime-smoke.XXXXXX)"
LOG_FILE="$TMP_ROOT/tdpnd-comet-runtime.log"
STATUS_FILE="$TMP_ROOT/comet-status.json"
TDPND_PID=""

HOST="${COMET_RUNTIME_SMOKE_HOST:-127.0.0.1}"
PROBE_HOST="${COMET_RUNTIME_SMOKE_PROBE_HOST:-127.0.0.1}"
MONIKER="${COMET_RUNTIME_SMOKE_MONIKER:-tdpn-comet-smoke}"
PROXY_APP="${COMET_RUNTIME_SMOKE_PROXY_APP:-tdpn-comet-smoke}"
WAIT_SECONDS="${COMET_RUNTIME_SMOKE_WAIT_SECONDS:-45}"
STOP_WAIT_SECONDS="${COMET_RUNTIME_SMOKE_STOP_WAIT_SECONDS:-15}"
P2P_PORT_INPUT="${COMET_RUNTIME_SMOKE_P2P_PORT:-}"
RPC_PORT_INPUT="${COMET_RUNTIME_SMOKE_RPC_PORT:-}"

usage() {
  cat <<'EOF'
Usage: scripts/integration_cosmos_tdpnd_comet_runtime_smoke.sh

Environment overrides:
  COMET_RUNTIME_SMOKE_HOST
  COMET_RUNTIME_SMOKE_PROBE_HOST
  COMET_RUNTIME_SMOKE_MONIKER
  COMET_RUNTIME_SMOKE_PROXY_APP
  COMET_RUNTIME_SMOKE_WAIT_SECONDS
  COMET_RUNTIME_SMOKE_STOP_WAIT_SECONDS
  COMET_RUNTIME_SMOKE_P2P_PORT
  COMET_RUNTIME_SMOKE_RPC_PORT
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

validate_port() {
  local label="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || (( value < 1 || value > 65535 )); then
    echo "${label} must be an integer in [1,65535] (got: ${value})" >&2
    exit 2
  fi
}

validate_seconds() {
  local label="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || (( value < 1 )); then
    echo "${label} must be an integer >= 1 (got: ${value})" >&2
    exit 2
  fi
}

pick_port() {
  for _ in $(seq 1 40); do
    local port
    port=$((32000 + RANDOM % 10000))
    if ! (echo >/dev/tcp/"${PROBE_HOST}"/"${port}") >/dev/null 2>&1; then
      echo "${port}"
      return 0
    fi
  done
  return 1
}

signal_runtime() {
  local sig="$1"
  if [[ -n "${TDPND_PID}" ]]; then
    kill "-${sig}" "${TDPND_PID}" 2>/dev/null || true
    if command -v pkill >/dev/null 2>&1; then
      pkill "-${sig}" -P "${TDPND_PID}" 2>/dev/null || true
    fi
  fi
}

wait_for_runtime_exit() {
  local attempts="$1"
  for _ in $(seq 1 "${attempts}"); do
    if ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

dump_log() {
  if [[ -f "${LOG_FILE}" ]]; then
    echo "--- tdpnd comet runtime log ---"
    cat "${LOG_FILE}"
  fi
}

cleanup() {
  set +e
  if [[ -n "${TDPND_PID}" ]] && kill -0 "${TDPND_PID}" 2>/dev/null; then
    signal_runtime INT
    wait_for_runtime_exit $((STOP_WAIT_SECONDS * 10)) || true
    if kill -0 "${TDPND_PID}" 2>/dev/null; then
      signal_runtime TERM
      wait_for_runtime_exit $((STOP_WAIT_SECONDS * 10)) || true
    fi
    if kill -0 "${TDPND_PID}" 2>/dev/null; then
      signal_runtime KILL
    fi
    wait "${TDPND_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP_ROOT}"
  set -e
}
trap cleanup EXIT

wait_for_tcp_port() {
  local port="$1"
  local label="$2"
  for _ in $(seq 1 $((WAIT_SECONDS * 10))); do
    if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      echo "tdpnd exited before ${label} port became ready"
      dump_log
      exit 1
    fi
    if (echo >/dev/tcp/"${PROBE_HOST}"/"${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for ${label} port ${HOST}:${port}"
  dump_log
  exit 1
}

wait_for_rpc_status() {
  local url="$1"
  for _ in $(seq 1 $((WAIT_SECONDS * 10))); do
    if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      echo "tdpnd exited before comet RPC status became ready"
      dump_log
      exit 1
    fi
    local code
    code="$(curl -sS -m 2 -o "${STATUS_FILE}" -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "200" ]] && grep -q '"node_info"' "${STATUS_FILE}" && grep -q '"sync_info"' "${STATUS_FILE}"; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for comet RPC status at ${url}"
  dump_log
  if [[ -f "${STATUS_FILE}" ]]; then
    echo "--- comet RPC status response ---"
    cat "${STATUS_FILE}"
  fi
  exit 1
}

validate_seconds "COMET_RUNTIME_SMOKE_WAIT_SECONDS" "${WAIT_SECONDS}"
validate_seconds "COMET_RUNTIME_SMOKE_STOP_WAIT_SECONDS" "${STOP_WAIT_SECONDS}"

if [[ -n "${P2P_PORT_INPUT}" ]]; then
  validate_port "COMET_RUNTIME_SMOKE_P2P_PORT" "${P2P_PORT_INPUT}"
  P2P_PORT="${P2P_PORT_INPUT}"
else
  P2P_PORT="$(pick_port)"
fi

if [[ -n "${RPC_PORT_INPUT}" ]]; then
  validate_port "COMET_RUNTIME_SMOKE_RPC_PORT" "${RPC_PORT_INPUT}"
  RPC_PORT="${RPC_PORT_INPUT}"
else
  RPC_PORT="$(pick_port)"
fi

if [[ -z "${P2P_PORT}" || -z "${RPC_PORT}" ]]; then
  echo "failed to allocate comet runtime smoke ports" >&2
  exit 1
fi
if [[ "${P2P_PORT}" == "${RPC_PORT}" ]]; then
  echo "comet runtime smoke requires distinct p2p/rpc ports (got: ${P2P_PORT})" >&2
  exit 2
fi

COMET_HOME_DIR="$TMP_ROOT/comet-home"
mkdir -p "${COMET_HOME_DIR}"

(
  cd "${CHAIN_DIR}"
  go run ./cmd/tdpnd \
    --comet-home "${COMET_HOME_DIR}" \
    --comet-moniker "${MONIKER}" \
    --comet-p2p-laddr "tcp://${HOST}:${P2P_PORT}" \
    --comet-rpc-laddr "tcp://${HOST}:${RPC_PORT}" \
    --comet-proxy-app "${PROXY_APP}"
) >"${LOG_FILE}" 2>&1 &
TDPND_PID=$!

wait_for_tcp_port "${P2P_PORT}" "comet p2p"
wait_for_tcp_port "${RPC_PORT}" "comet rpc"
wait_for_rpc_status "http://${PROBE_HOST}:${RPC_PORT}/status"

if ! grep -q '"network":"tdpn-comet-chain"' "${STATUS_FILE}"; then
  echo "expected comet RPC status to report chain id tdpn-comet-chain"
  echo "--- comet RPC status response ---"
  cat "${STATUS_FILE}"
  dump_log
  exit 1
fi

signal_runtime INT
if ! wait_for_runtime_exit $((STOP_WAIT_SECONDS * 10)); then
  signal_runtime TERM
  if ! wait_for_runtime_exit $((STOP_WAIT_SECONDS * 10)); then
    echo "tdpnd did not exit after INT/TERM shutdown sequence"
    dump_log
    signal_runtime KILL
    wait_for_runtime_exit 20 || true
    exit 1
  fi
fi

set +e
wait "${TDPND_PID}" 2>/dev/null
WAIT_RC=$?
set -e
TDPND_PID=""

echo "cosmos tdpnd comet runtime smoke integration check ok (exit=${WAIT_RC})"
