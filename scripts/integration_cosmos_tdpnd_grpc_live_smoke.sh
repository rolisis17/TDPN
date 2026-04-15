#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE="$(mktemp -t tdpnd-grpc-live-smoke.XXXXXX.log)"
TDPND_PID=""

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

cleanup() {
  set +e
  if [[ -n "${TDPND_PID}" ]] && kill -0 "${TDPND_PID}" 2>/dev/null; then
    signal_runtime INT
    wait_for_runtime_exit 20 || true
    if kill -0 "${TDPND_PID}" 2>/dev/null; then
      signal_runtime TERM
      wait_for_runtime_exit 20 || true
    fi
    if kill -0 "${TDPND_PID}" 2>/dev/null; then
      signal_runtime KILL
    fi
    wait "${TDPND_PID}" 2>/dev/null || true
  fi
  rm -f "${LOG_FILE}"
  set -e
}
trap cleanup EXIT

pick_port() {
  for _ in $(seq 1 40); do
    local port
    port=$((32000 + RANDOM % 10000))
    if ! (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1; then
      echo "${port}"
      return 0
    fi
  done
  return 1
}

wait_for_tcp_ready() {
  local port="$1"
  for _ in $(seq 1 60); do
    if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      echo "tdpnd exited before becoming ready"
      cat "${LOG_FILE}"
      return 1
    fi
    if (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for tdpnd TCP readiness on ${port}"
  cat "${LOG_FILE}"
  return 1
}

wait_for_grpcurl_health() {
  local port="$1"
  for _ in $(seq 1 40); do
    if grpcurl -plaintext -max-time 2 -d '{}' "127.0.0.1:${port}" grpc.health.v1.Health/Check >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.15
  done
  echo "timed out waiting for grpc health check on ${port}"
  cat "${LOG_FILE}"
  return 1
}

wait_for_grpcurl_reflection() {
  local port="$1"
  for _ in $(seq 1 40); do
    local services
    services="$(grpcurl -plaintext -max-time 2 "127.0.0.1:${port}" list 2>/dev/null || true)"
    if [[ -n "${services}" ]] && grep -q '^grpc\.health\.v1\.Health$' <<<"${services}" && grep -q '^grpc\.reflection\.' <<<"${services}"; then
      return 0
    fi
    sleep 0.15
  done
  echo "timed out waiting for grpc reflection services on ${port}"
  cat "${LOG_FILE}"
  return 1
}

PORT="$(pick_port)"
if [[ -z "${PORT}" ]]; then
  echo "failed to allocate smoke-test grpc port"
  exit 1
fi

(
  cd blockchain/tdpn-chain
  go run ./cmd/tdpnd --grpc-listen "127.0.0.1:${PORT}"
) >"${LOG_FILE}" 2>&1 &
TDPND_PID=$!

if command -v grpcurl >/dev/null 2>&1; then
  wait_for_grpcurl_health "${PORT}"
  wait_for_grpcurl_reflection "${PORT}"
else
  wait_for_tcp_ready "${PORT}"
  sleep 0.15
  wait_for_tcp_ready "${PORT}"
  if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
    echo "tdpnd exited unexpectedly after TCP fallback readiness checks"
    cat "${LOG_FILE}"
    exit 1
  fi
fi

signal_runtime INT
if ! wait_for_runtime_exit 30; then
  signal_runtime TERM
fi
if ! wait_for_runtime_exit 20; then
  signal_runtime KILL
  wait_for_runtime_exit 20 || true
fi
if kill -0 "${TDPND_PID}" 2>/dev/null; then
  echo "tdpnd did not exit after INT/TERM/KILL sequence"
  cat "${LOG_FILE}"
  exit 1
fi
wait "${TDPND_PID}" 2>/dev/null || true
TDPND_PID=""

echo "cosmos tdpnd grpc live smoke integration check ok"
