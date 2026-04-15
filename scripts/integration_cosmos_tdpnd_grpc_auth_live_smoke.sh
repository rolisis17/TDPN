#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

if ! command -v grpcurl >/dev/null 2>&1; then
  (
    cd blockchain/tdpn-chain
    timeout 60s go test ./cmd/tdpnd -count=1 -run '^TestRunTDPNDGRPCModeAuthEnforcementAndHealth$'
  )
  echo "cosmos tdpnd grpc auth live smoke integration check ok (runtime test fallback)"
  exit 0
fi

LOG_FILE="$(mktemp -t tdpnd-grpc-auth-live-smoke.XXXXXX.log)"
TDPND_PID=""
AUTH_TOKEN="${TDPND_GRPC_AUTH_LIVE_SMOKE_TOKEN:-tdpn-live-smoke-token}"
MODULE_QUERY_CHECKS=(
  "tdpn.vpnbilling.v1.Query/ListCreditReservations|reservations"
  "tdpn.vpnrewards.v1.Query/ListRewardAccruals|accruals"
  "tdpn.vpnslashing.v1.Query/ListSlashEvidence|evidence"
  "tdpn.vpnsponsor.v1.Query/ListSponsorAuthorizations|authorizations"
  "tdpn.vpnvalidator.v1.Query/ListValidatorEligibilities|eligibilities"
  "tdpn.vpngovernance.v1.Query/ListGovernancePolicies|policies"
)

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

wait_for_grpcurl_health_ready() {
  local port="$1"
  for _ in $(seq 1 60); do
    if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      echo "tdpnd exited before becoming ready"
      cat "${LOG_FILE}"
      return 1
    fi
    if grpcurl -plaintext -max-time 2 -d '{}' "127.0.0.1:${port}" grpc.health.v1.Health/Check >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for grpc health readiness on ${port}"
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
  go run ./cmd/tdpnd --grpc-listen "127.0.0.1:${PORT}" --grpc-auth-token "${AUTH_TOKEN}"
) >"${LOG_FILE}" 2>&1 &
TDPND_PID=$!

wait_for_grpcurl_health_ready "${PORT}"

# 1) Health must stay open without bearer token.
HEALTH_OUTPUT="$(grpcurl -plaintext -max-time 2 -d '{}' "127.0.0.1:${PORT}" grpc.health.v1.Health/Check 2>&1 || true)"
if ! grep -q 'SERVING' <<<"${HEALTH_OUTPUT}"; then
  echo "expected unauthenticated health check to succeed and report SERVING"
  echo "health output:"
  echo "${HEALTH_OUTPUT}"
  cat "${LOG_FILE}"
  exit 1
fi

# 2) Query RPCs must fail without auth token and succeed with token.
for module_spec in "${MODULE_QUERY_CHECKS[@]}"; do
  IFS='|' read -r module_rpc expected_field <<<"${module_spec}"

  set +e
  unauth_output="$(grpcurl -plaintext -max-time 2 -d '{}' "127.0.0.1:${PORT}" "${module_rpc}" 2>&1)"
  unauth_rc=$?
  set -e
  if (( unauth_rc == 0 )); then
    echo "expected module RPC ${module_rpc} to fail without token, but it succeeded"
    echo "module output:"
    echo "${unauth_output}"
    cat "${LOG_FILE}"
    exit 1
  fi
  if ! grep -Eq 'Unauthenticated|missing or invalid bearer token' <<<"${unauth_output}"; then
    echo "expected unauthenticated signal for module RPC ${module_rpc} without token"
    echo "module unauth output:"
    echo "${unauth_output}"
    cat "${LOG_FILE}"
    exit 1
  fi

  set +e
  auth_output="$(grpcurl -plaintext -max-time 2 -H "authorization: Bearer ${AUTH_TOKEN}" -d '{}' "127.0.0.1:${PORT}" "${module_rpc}" 2>&1)"
  auth_rc=$?
  set -e
  if (( auth_rc != 0 )); then
    echo "expected module RPC ${module_rpc} to succeed with bearer token (rc=${auth_rc})"
    echo "module auth output:"
    echo "${auth_output}"
    cat "${LOG_FILE}"
    exit 1
  fi
  if ! grep -Eq "\"${expected_field}\"[[:space:]]*:" <<<"${auth_output}"; then
    echo "expected authorized module RPC ${module_rpc} response to include ${expected_field} field"
    echo "module auth output:"
    echo "${auth_output}"
    cat "${LOG_FILE}"
    exit 1
  fi
done

# 3) Reflection must be disabled in auth-token mode.
set +e
REFLECTION_OUTPUT="$(grpcurl -plaintext -max-time 2 "127.0.0.1:${PORT}" list 2>&1)"
REFLECTION_RC=$?
set -e
if (( REFLECTION_RC == 0 )); then
  echo "expected grpc reflection/list to be disabled in auth mode, but list succeeded"
  echo "reflection output:"
  echo "${REFLECTION_OUTPUT}"
  cat "${LOG_FILE}"
  exit 1
fi
if ! grep -Eqi 'does not support the reflection API|unimplemented|unknown service|not implemented' <<<"${REFLECTION_OUTPUT}"; then
  echo "expected reflection-disabled signal from grpcurl list in auth mode"
  echo "reflection output:"
  echo "${REFLECTION_OUTPUT}"
  cat "${LOG_FILE}"
  exit 1
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

echo "cosmos tdpnd grpc auth live smoke integration check ok"
