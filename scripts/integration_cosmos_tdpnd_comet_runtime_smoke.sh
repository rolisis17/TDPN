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
START_ATTEMPTS="${COMET_RUNTIME_SMOKE_START_ATTEMPTS:-6}"
GRPC_AUTH_TOKEN="${COMET_RUNTIME_SMOKE_GRPC_AUTH_TOKEN:-tdpn-comet-grpc-smoke-token}"
P2P_PORT_INPUT="${COMET_RUNTIME_SMOKE_P2P_PORT:-}"
RPC_PORT_INPUT="${COMET_RUNTIME_SMOKE_RPC_PORT:-}"
GRPC_PORT_INPUT="${COMET_RUNTIME_SMOKE_GRPC_PORT:-}"

usage() {
  cat <<'EOF'
Usage: scripts/integration_cosmos_tdpnd_comet_runtime_smoke.sh

Environment overrides:
  COMET_RUNTIME_SMOKE_HOST
  COMET_RUNTIME_SMOKE_PROBE_HOST
  COMET_RUNTIME_SMOKE_MONIKER
  COMET_RUNTIME_SMOKE_PROXY_APP
  COMET_RUNTIME_SMOKE_GRPC_AUTH_TOKEN
  COMET_RUNTIME_SMOKE_WAIT_SECONDS
  COMET_RUNTIME_SMOKE_STOP_WAIT_SECONDS
  COMET_RUNTIME_SMOKE_START_ATTEMPTS
  COMET_RUNTIME_SMOKE_P2P_PORT
  COMET_RUNTIME_SMOKE_RPC_PORT
  COMET_RUNTIME_SMOKE_GRPC_PORT
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

wait_for_grpcurl_health() {
  local port="$1"
  for _ in $(seq 1 $((WAIT_SECONDS * 10))); do
    if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      echo "tdpnd exited before grpc health became ready"
      dump_log
      exit 1
    fi
    if grpcurl -plaintext -max-time 2 -d '{}' "${PROBE_HOST}:${port}" grpc.health.v1.Health/Check >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for grpc health on ${PROBE_HOST}:${port}"
  dump_log
  exit 1
}

assert_grpc_query_dispatch() {
  local port="$1"
  local method="$2"
  local expected_field="$3"
  local payload="${4:-{}}"
  local output
  local rc

  set +e
  output="$(grpcurl -plaintext -max-time 2 -d "${payload}" "${PROBE_HOST}:${port}" "${method}" 2>&1)"
  rc=$?
  set -e
  if (( rc != 0 )); then
    echo "expected grpc query dispatch for ${method} to succeed (rc=${rc})"
    echo "grpc query output:"
    echo "${output}"
    dump_log
    exit 1
  fi
  if ! grep -Eq "\"${expected_field}\"[[:space:]]*:" <<<"${output}"; then
    echo "expected grpc query ${method} response to include ${expected_field} field"
    echo "grpc query output:"
    echo "${output}"
    dump_log
    exit 1
  fi
}

assert_grpc_query_unauthenticated() {
  local port="$1"
  local method="$2"
  local payload="${3:-{}}"
  local output
  local rc

  set +e
  output="$(grpcurl -plaintext -max-time 2 -d "${payload}" "${PROBE_HOST}:${port}" "${method}" 2>&1)"
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "expected grpc query ${method} without bearer token to fail, but it succeeded"
    echo "grpc query output:"
    echo "${output}"
    dump_log
    exit 1
  fi
  if ! grep -Eq 'Unauthenticated|missing or invalid bearer token' <<<"${output}"; then
    echo "expected unauthenticated signal for grpc query ${method} without token"
    echo "grpc query output:"
    echo "${output}"
    dump_log
    exit 1
  fi
}

assert_grpc_query_dispatch_with_token() {
  local port="$1"
  local method="$2"
  local expected_field="$3"
  local payload="${4:-{}}"
  local output
  local rc

  set +e
  output="$(grpcurl -plaintext -max-time 2 -H "authorization: Bearer ${GRPC_AUTH_TOKEN}" -d "${payload}" "${PROBE_HOST}:${port}" "${method}" 2>&1)"
  rc=$?
  set -e
  if (( rc != 0 )); then
    echo "expected grpc query dispatch for ${method} with bearer token to succeed (rc=${rc})"
    echo "grpc query output:"
    echo "${output}"
    dump_log
    exit 1
  fi
  if ! grep -Eq "\"${expected_field}\"[[:space:]]*:" <<<"${output}"; then
    echo "expected grpc query ${method} response with bearer token to include ${expected_field} field"
    echo "grpc query output:"
    echo "${output}"
    dump_log
    exit 1
  fi
}

assert_grpc_reflection_disabled() {
  local port="$1"
  local output
  local rc

  set +e
  output="$(grpcurl -plaintext -max-time 2 -H "authorization: Bearer ${GRPC_AUTH_TOKEN}" "${PROBE_HOST}:${port}" list 2>&1)"
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "expected grpc reflection/list to be disabled in auth mode, but grpcurl list succeeded"
    echo "grpc reflection output:"
    echo "${output}"
    dump_log
    exit 1
  fi
  if ! grep -Eqi 'does not support the reflection API|unimplemented|unknown service|not implemented' <<<"${output}"; then
    echo "expected reflection-disabled signal for grpcurl list in auth mode"
    echo "grpc reflection output:"
    echo "${output}"
    dump_log
    exit 1
  fi
}

validate_seconds "COMET_RUNTIME_SMOKE_WAIT_SECONDS" "${WAIT_SECONDS}"
validate_seconds "COMET_RUNTIME_SMOKE_STOP_WAIT_SECONDS" "${STOP_WAIT_SECONDS}"
validate_seconds "COMET_RUNTIME_SMOKE_START_ATTEMPTS" "${START_ATTEMPTS}"

has_auto_ports=0
if [[ -z "${P2P_PORT_INPUT}" || -z "${RPC_PORT_INPUT}" || -z "${GRPC_PORT_INPUT}" ]]; then
  has_auto_ports=1
fi

if [[ -n "${P2P_PORT_INPUT}" ]]; then
  validate_port "COMET_RUNTIME_SMOKE_P2P_PORT" "${P2P_PORT_INPUT}"
fi

if [[ -n "${RPC_PORT_INPUT}" ]]; then
  validate_port "COMET_RUNTIME_SMOKE_RPC_PORT" "${RPC_PORT_INPUT}"
fi

if [[ -n "${GRPC_PORT_INPUT}" ]]; then
  validate_port "COMET_RUNTIME_SMOKE_GRPC_PORT" "${GRPC_PORT_INPUT}"
fi

assign_ports() {
  local p2p rpc grpc
  local attempt
  for attempt in $(seq 1 40); do
    if [[ -n "${P2P_PORT_INPUT}" ]]; then
      p2p="${P2P_PORT_INPUT}"
    else
      p2p="$(pick_port || true)"
    fi

    if [[ -n "${RPC_PORT_INPUT}" ]]; then
      rpc="${RPC_PORT_INPUT}"
    else
      rpc="$(pick_port || true)"
    fi

    if [[ -n "${GRPC_PORT_INPUT}" ]]; then
      grpc="${GRPC_PORT_INPUT}"
    else
      grpc="$(pick_port || true)"
    fi

    if [[ -z "${p2p}" || -z "${rpc}" || -z "${grpc}" ]]; then
      continue
    fi
    if [[ "${p2p}" == "${rpc}" || "${p2p}" == "${grpc}" || "${rpc}" == "${grpc}" ]]; then
      if [[ -n "${P2P_PORT_INPUT}" && -n "${RPC_PORT_INPUT}" && -n "${GRPC_PORT_INPUT}" ]]; then
        break
      fi
      continue
    fi

    P2P_PORT="${p2p}"
    RPC_PORT="${rpc}"
    GRPC_PORT="${grpc}"
    return 0
  done
  return 1
}

is_port_conflict_log() {
  grep -Eqi 'address already in use|bind: address already in use|failed to listen on .* bind: address already in use' "${LOG_FILE}"
}

COMET_HOME_DIR="$TMP_ROOT/comet-home"
mkdir -p "${COMET_HOME_DIR}"

wait_for_tcp_port() {
  local port="$1"
  local label="$2"
  for _ in $(seq 1 $((WAIT_SECONDS * 10))); do
    if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      echo "tdpnd exited before ${label} port became ready"
      return 1
    fi
    if (echo >/dev/tcp/"${PROBE_HOST}"/"${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for ${label} port ${HOST}:${port}"
  return 1
}

wait_for_rpc_status() {
  local url="$1"
  for _ in $(seq 1 $((WAIT_SECONDS * 10))); do
    if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      echo "tdpnd exited before comet RPC status became ready"
      return 1
    fi
    local code
    code="$(curl -sS -m 2 -o "${STATUS_FILE}" -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "200" ]] && grep -q '"node_info"' "${STATUS_FILE}" && grep -q '"sync_info"' "${STATUS_FILE}"; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for comet RPC status at ${url}"
  return 1
}

started=0
for start_attempt in $(seq 1 "${START_ATTEMPTS}"); do
  if ! assign_ports; then
    echo "failed to allocate distinct comet runtime smoke ports" >&2
    exit 1
  fi

  : >"${LOG_FILE}"
  : >"${STATUS_FILE}"

  (
    cd "${CHAIN_DIR}"
    go run ./cmd/tdpnd \
      --comet-home "${COMET_HOME_DIR}" \
      --comet-moniker "${MONIKER}" \
      --comet-p2p-laddr "tcp://${HOST}:${P2P_PORT}" \
      --comet-rpc-laddr "tcp://${HOST}:${RPC_PORT}" \
      --comet-proxy-app "${PROXY_APP}" \
      --grpc-listen "${HOST}:${GRPC_PORT}" \
      --grpc-auth-token "${GRPC_AUTH_TOKEN}"
  ) >"${LOG_FILE}" 2>&1 &
  TDPND_PID=$!

  if wait_for_tcp_port "${P2P_PORT}" "comet p2p" \
    && wait_for_tcp_port "${RPC_PORT}" "comet rpc" \
    && wait_for_tcp_port "${GRPC_PORT}" "grpc" \
    && wait_for_rpc_status "http://${PROBE_HOST}:${RPC_PORT}/status"; then
    started=1
    break
  fi

  signal_runtime TERM
  wait_for_runtime_exit $((STOP_WAIT_SECONDS * 10)) || true
  if [[ -n "${TDPND_PID}" ]]; then
    wait "${TDPND_PID}" 2>/dev/null || true
  fi
  TDPND_PID=""

  if (( start_attempt < START_ATTEMPTS )) && (( has_auto_ports == 1 )) && is_port_conflict_log; then
    continue
  fi

  echo "tdpnd comet runtime failed to become ready (attempt ${start_attempt}/${START_ATTEMPTS})"
  dump_log
  if [[ -f "${STATUS_FILE}" ]]; then
    echo "--- comet RPC status response ---"
    cat "${STATUS_FILE}"
  fi
  exit 1
done

if (( started != 1 )); then
  echo "tdpnd comet runtime failed to start after ${START_ATTEMPTS} attempts"
  dump_log
  exit 1
fi

if ! grep -q '"network":"tdpn-comet-chain"' "${STATUS_FILE}"; then
  echo "expected comet RPC status to report chain id tdpn-comet-chain"
  echo "--- comet RPC status response ---"
  cat "${STATUS_FILE}"
  dump_log
  exit 1
fi

if command -v grpcurl >/dev/null 2>&1; then
  # Health remains open even when gRPC auth token mode is enabled.
  wait_for_grpcurl_health "${GRPC_PORT}"
  # Module query RPCs require bearer auth in token mode.
  assert_grpc_query_unauthenticated "${GRPC_PORT}" "tdpn.vpnbilling.v1.Query/ListCreditReservations"
  assert_grpc_query_dispatch_with_token "${GRPC_PORT}" "tdpn.vpnbilling.v1.Query/ListCreditReservations" "reservations"
  # Reflection/list remains disabled when auth token mode is enabled.
  assert_grpc_reflection_disabled "${GRPC_PORT}"
else
  (
    cd "${CHAIN_DIR}"
    timeout 60s go test ./cmd/tdpnd -count=1 -run '^(TestRunTDPNDMixedCometGRPCSettlementLifecycle|TestRunTDPNDMixedCometGRPCQueryDispatchAvailability|TestRunTDPNDMixedCometGRPCAuth.*)$'
  )
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
