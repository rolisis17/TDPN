#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE="$(mktemp -t tdpnd-settlement-bridge-live.XXXXXX.log)"
RESP_FILE="$(mktemp -t tdpnd-settlement-bridge-resp.XXXXXX.json)"
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
  rm -f "${LOG_FILE}" "${RESP_FILE}"
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

wait_for_health_ready() {
  local url="$1"
  for _ in $(seq 1 60); do
    if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      echo "tdpnd exited before settlement bridge health became ready"
      cat "${LOG_FILE}"
      return 1
    fi
    local code
    code="$(curl -s -m 2 -o "${RESP_FILE}" -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for settlement bridge health at ${url}"
  cat "${LOG_FILE}"
  return 1
}

post_expect_status() {
  local url="$1"
  local payload="$2"
  local expected="$3"
  local token="${4:-}"
  local code
  if [[ -n "${token}" ]]; then
    code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" -H "Content-Type: application/json" -H "Authorization: Bearer ${token}" -d "${payload}" "${url}" || true)"
  else
    code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" -H "Content-Type: application/json" -d "${payload}" "${url}" || true)"
  fi
  if [[ "${code}" != "${expected}" ]]; then
    echo "unexpected status for ${url}: expected ${expected}, got ${code}"
    echo "response:"
    cat "${RESP_FILE}"
    echo
    echo "tdpnd log:"
    cat "${LOG_FILE}"
    return 1
  fi
}

get_expect_status() {
  local url="$1"
  local expected="$2"
  local token="${3:-}"
  local code
  if [[ -n "${token}" ]]; then
    code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" -H "Authorization: Bearer ${token}" "${url}" || true)"
  else
    code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" "${url}" || true)"
  fi
  if [[ "${code}" != "${expected}" ]]; then
    echo "unexpected status for ${url}: expected ${expected}, got ${code}"
    echo "response:"
    cat "${RESP_FILE}"
    echo
    echo "tdpnd log:"
    cat "${LOG_FILE}"
    return 1
  fi
}

TOKEN="bridge-smoke-token"
PORT="$(pick_port)"
if [[ -z "${PORT}" ]]; then
  echo "failed to allocate settlement bridge smoke-test port"
  exit 1
fi

(
  cd blockchain/tdpn-chain
  go run ./cmd/tdpnd --settlement-http-listen "127.0.0.1:${PORT}" --settlement-http-auth-token "${TOKEN}"
) >"${LOG_FILE}" 2>&1 &
TDPND_PID=$!

BASE_URL="http://127.0.0.1:${PORT}"
wait_for_health_ready "${BASE_URL}/health"

post_expect_status "${BASE_URL}/x/vpnslashing/evidence" '{"EvidenceID":"ev-unauth-1","SubjectID":"provider-1","SessionID":"sess-1","ViolationType":"double-sign","EvidenceRef":"sha256:abc","ObservedAt":"2026-01-01T00:00:00Z"}' "401"
post_expect_status "${BASE_URL}/x/vpnvalidator/eligibilities" '{"ValidatorID":"val-unauth-1","OperatorAddress":"op-unauth-1","Eligible":true,"PolicyReason":"auth smoke","UpdatedAt":"2026-01-01T00:00:00Z","Status":"submitted"}' "401"
post_expect_status "${BASE_URL}/x/vpngovernance/policies" '{"PolicyID":"policy-unauth-1","Title":"unauth-policy","Description":"auth smoke policy","Version":1,"ActivatedAt":"2026-01-01T00:00:00Z","Status":"submitted"}' "401"

post_expect_status "${BASE_URL}/x/vpnslashing/evidence" '{"EvidenceID":"ev-invalid-ref-1","SubjectID":"provider-1","SessionID":"sess-1","ViolationType":"double-sign","EvidenceRef":"proof-invalid-ref-1","ObservedAt":"2026-01-01T00:00:00Z"}' "400" "${TOKEN}"
grep -q 'objective format' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnbilling/settlements" '{"SettlementID":"set-live-1","SessionID":"sess-live-1","SubjectID":"subject-live-1","ChargedMicros":250,"Currency":"TDPNC","SettledAt":"2026-01-01T00:00:00Z"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnrewards/issues" '{"RewardID":"reward-live-1","ProviderSubjectID":"provider-live-1","SessionID":"sess-live-1","RewardMicros":100,"Currency":"TDPNC","IssuedAt":"2026-01-01T00:00:00Z"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnsponsor/reservations" '{"ReservationID":"res-live-1","SponsorID":"sponsor-live-1","SubjectID":"app-live-1","SessionID":"sess-live-1","AmountMicros":500,"Currency":"TDPNC","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnslashing/evidence" '{"EvidenceID":"ev-live-1","SubjectID":"provider-live-1","SessionID":"sess-live-1","ViolationType":"double-sign","EvidenceRef":"sha256:abc123","ObservedAt":"2026-01-01T00:00:00Z"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnvalidator/eligibilities" '{"ValidatorID":"val-live-1","OperatorAddress":"op-live-1","Eligible":true,"PolicyReason":"bootstrap policy","UpdatedAt":"2026-01-01T00:00:00Z","Status":"confirmed"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnvalidator/status-records" '{"StatusID":"status-live-1","ValidatorID":"val-live-1","ConsensusAddress":"cons-live-1","LifecycleStatus":"active","EvidenceHeight":7,"EvidenceRef":"sha256:status-live-1","RecordedAt":"2026-01-01T00:00:01Z","Status":"submitted"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpngovernance/policies" '{"PolicyID":"policy-live-1","Title":"policy-live-title","Description":"policy-live-description","Version":1,"ActivatedAt":"2026-01-01T00:00:00Z","Status":"submitted"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpngovernance/decisions" '{"DecisionID":"decision-live-1","PolicyID":"policy-live-1","ProposalID":"proposal-live-1","Outcome":"approve","Decider":"bootstrap-multisig","Reason":"smoke decision","DecidedAt":"2026-01-01T00:00:02Z","Status":"confirmed"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpngovernance/audit-actions" '{"ActionID":"action-live-1","Action":"policy.bootstrap","Actor":"bootstrap-multisig","Reason":"smoke audit","EvidencePointer":"obj://audit/action-live-1","Timestamp":"2026-01-01T00:00:03Z"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

# Query-by-id coverage for validator/governance plus an existing module path.
get_expect_status "${BASE_URL}/x/vpnbilling/settlements/set-live-1" "200"
grep -q '"settlement"' "${RESP_FILE}"
grep -q '"SettlementID"[[:space:]]*:[[:space:]]*"set-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnvalidator/eligibilities/val-live-1" "200"
grep -q '"eligibility"' "${RESP_FILE}"
grep -q '"ValidatorID"[[:space:]]*:[[:space:]]*"val-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnvalidator/status-records/status-live-1" "200"
grep -q '"status"' "${RESP_FILE}"
grep -q '"StatusID"[[:space:]]*:[[:space:]]*"status-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/policies/policy-live-1" "200"
grep -q '"policy"' "${RESP_FILE}"
grep -q '"PolicyID"[[:space:]]*:[[:space:]]*"policy-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/decisions/decision-live-1" "200"
grep -q '"decision"' "${RESP_FILE}"
grep -q '"DecisionID"[[:space:]]*:[[:space:]]*"decision-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/audit-actions/action-live-1" "200"
grep -q '"action"' "${RESP_FILE}"
grep -q '"ActionID"[[:space:]]*:[[:space:]]*"action-live-1"' "${RESP_FILE}"

# List coverage for validator/governance plus an existing module path.
get_expect_status "${BASE_URL}/x/vpnbilling/settlements" "200"
grep -q '"settlements"' "${RESP_FILE}"
grep -q '"SettlementID"[[:space:]]*:[[:space:]]*"set-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnvalidator/eligibilities" "200"
grep -q '"eligibilities"' "${RESP_FILE}"
grep -q '"ValidatorID"[[:space:]]*:[[:space:]]*"val-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnvalidator/status-records" "200"
grep -q '"records"' "${RESP_FILE}"
grep -q '"StatusID"[[:space:]]*:[[:space:]]*"status-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/policies" "200"
grep -q '"policies"' "${RESP_FILE}"
grep -q '"PolicyID"[[:space:]]*:[[:space:]]*"policy-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/decisions" "200"
grep -q '"decisions"' "${RESP_FILE}"
grep -q '"DecisionID"[[:space:]]*:[[:space:]]*"decision-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/audit-actions" "200"
grep -q '"actions"' "${RESP_FILE}"
grep -q '"ActionID"[[:space:]]*:[[:space:]]*"action-live-1"' "${RESP_FILE}"

# Replay/id behavior check: duplicate write should surface replay=true and preserve id.
post_expect_status "${BASE_URL}/x/vpnvalidator/status-records" '{"StatusID":"status-live-1","ValidatorID":"val-live-1","ConsensusAddress":"cons-live-1","LifecycleStatus":"active","EvidenceHeight":7,"EvidenceRef":"sha256:status-live-1","RecordedAt":"2026-01-01T00:00:01Z","Status":"submitted"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"
grep -q '"replay"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"
grep -q '"id"[[:space:]]*:[[:space:]]*"status-live-1"' "${RESP_FILE}"

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

echo "cosmos tdpnd settlement bridge live smoke integration check ok"
