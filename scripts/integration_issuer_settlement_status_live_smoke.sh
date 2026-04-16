#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in go curl jq mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

TMP_DIR="$(mktemp -d -t issuer-settlement-status-live-smoke.XXXXXX)"
LOG_FILE="$TMP_DIR/issuer.log"
RESP_FILE="$TMP_DIR/response.json"
ISSUER_PID=""

signal_runtime() {
  local sig="$1"
  if [[ -n "${ISSUER_PID}" ]]; then
    kill "-${sig}" "${ISSUER_PID}" 2>/dev/null || true
    if command -v pkill >/dev/null 2>&1; then
      pkill "-${sig}" -P "${ISSUER_PID}" 2>/dev/null || true
    fi
  fi
}

wait_for_runtime_exit() {
  local attempts="$1"
  for _ in $(seq 1 "${attempts}"); do
    if ! kill -0 "${ISSUER_PID}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

cleanup() {
  set +e
  if [[ -n "${ISSUER_PID}" ]] && kill -0 "${ISSUER_PID}" 2>/dev/null; then
    signal_runtime INT
    wait_for_runtime_exit 20 || true
    if kill -0 "${ISSUER_PID}" 2>/dev/null; then
      signal_runtime TERM
      wait_for_runtime_exit 20 || true
    fi
    if kill -0 "${ISSUER_PID}" 2>/dev/null; then
      signal_runtime KILL
    fi
    wait "${ISSUER_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}"
  set -e
}
trap cleanup EXIT

pick_port() {
  for _ in $(seq 1 40); do
    local port
    port=$((33000 + RANDOM % 9000))
    if ! (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1; then
      echo "${port}"
      return 0
    fi
  done
  return 1
}

wait_for_health_ready() {
  local url="$1"
  for _ in $(seq 1 80); do
    if [[ -n "${ISSUER_PID}" ]] && ! kill -0 "${ISSUER_PID}" 2>/dev/null; then
      echo "issuer exited before settlement status smoke health became ready"
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
  echo "timed out waiting for issuer health at ${url}"
  cat "${LOG_FILE}"
  return 1
}

start_issuer_runtime() {
  local port="$1"
  local cosmos_endpoint="$2"
  : >"${LOG_FILE}"
  (
    ISSUER_ADDR="127.0.0.1:${port}" \
    ISSUER_PRIVATE_KEY_FILE="${TMP_DIR}/issuer_ed25519.key" \
    ISSUER_PREVIOUS_PUBKEYS_FILE="${TMP_DIR}/issuer_previous_pubkeys.txt" \
    ISSUER_EPOCHS_FILE="${TMP_DIR}/issuer_epochs.json" \
    ISSUER_SUBJECTS_FILE="${TMP_DIR}/issuer_subjects.json" \
    ISSUER_REVOCATIONS_FILE="${TMP_DIR}/issuer_revocations.json" \
    ISSUER_ANON_REVOCATIONS_FILE="${TMP_DIR}/issuer_anon_revocations.json" \
    ISSUER_ANON_DISPUTES_FILE="${TMP_DIR}/issuer_anon_disputes.json" \
    ISSUER_AUDIT_FILE="${TMP_DIR}/issuer_audit.json" \
    ISSUER_SETTLEMENT_RECONCILE_SEC=0 \
    ISSUER_ADMIN_TOKEN="${ADMIN_TOKEN}" \
    ISSUER_ADMIN_ALLOW_TOKEN=1 \
    ISSUER_SPONSOR_API_TOKEN="${SPONSOR_TOKEN}" \
    SETTLEMENT_CHAIN_ADAPTER=cosmos \
    COSMOS_SETTLEMENT_ENDPOINT="${cosmos_endpoint}" \
    COSMOS_SETTLEMENT_API_KEY="issuer-settlement-smoke" \
    COSMOS_SETTLEMENT_QUEUE_SIZE=8 \
    COSMOS_SETTLEMENT_MAX_RETRIES=1 \
    COSMOS_SETTLEMENT_BASE_BACKOFF_MS=20 \
    COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS=120 \
    go run ./cmd/node --issuer
  ) >"${LOG_FILE}" 2>&1 &
  ISSUER_PID=$!
}

post_expect_status() {
  local url="$1"
  local payload="$2"
  local expected="$3"
  local header_name="${4:-}"
  local token="${5:-}"
  local code
  if [[ -n "${header_name}" && -n "${token}" ]]; then
    code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" -H "Content-Type: application/json" -H "${header_name}: ${token}" -d "${payload}" "${url}" || true)"
  else
    code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" -H "Content-Type: application/json" -d "${payload}" "${url}" || true)"
  fi
  if [[ "${code}" != "${expected}" ]]; then
    echo "unexpected status for ${url}: expected ${expected}, got ${code}"
    echo "response:"
    cat "${RESP_FILE}"
    echo
    echo "issuer log:"
    cat "${LOG_FILE}"
    return 1
  fi
}

get_expect_status() {
  local url="$1"
  local expected="$2"
  local header_name="${3:-}"
  local token="${4:-}"
  local code
  if [[ -n "${header_name}" && -n "${token}" ]]; then
    code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" -H "${header_name}: ${token}" "${url}" || true)"
  else
    code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" "${url}" || true)"
  fi
  if [[ "${code}" != "${expected}" ]]; then
    echo "unexpected status for ${url}: expected ${expected}, got ${code}"
    echo "response:"
    cat "${RESP_FILE}"
    echo
    echo "issuer log:"
    cat "${LOG_FILE}"
    return 1
  fi
}

wait_for_backlog_status() {
  local url="$1"
  for _ in $(seq 1 80); do
    get_expect_status "${url}" "200" "X-Admin-Token" "${ADMIN_TOKEN}"
    if jq -e '
      .status == "backlog" and
      (.pending_adapter_operations | type == "number" and . >= 1) and
      (
        (.submitted_operations | type == "number" and . >= 2) or
        ((.pending_operations + .submitted_operations + .failed_operations) | type == "number" and . >= 2)
      )
    ' "${RESP_FILE}" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done

  echo "timed out waiting for settlement backlog status contract"
  echo "last response:"
  cat "${RESP_FILE}"
  echo
  echo "issuer log:"
  cat "${LOG_FILE}"
  return 1
}

ADMIN_TOKEN="issuer-admin-settlement-live-012345"
SPONSOR_TOKEN="issuer-sponsor-settlement-live-012345"
SUBJECT_ID="client-settlement-live-1"
SPONSOR_ID="dapp-settlement-live-1"
RESERVATION_ID="sres-settlement-live-${RANDOM}-$(date +%s)"
SESSION_ID="sess-settlement-live-${RANDOM}-$(date +%s)"
EVIDENCE_ID="ev-settlement-live-${RANDOM}-$(date +%s)"
EVIDENCE_ID_INVALID="ev-settlement-live-invalid-${RANDOM}-$(date +%s)"
EVIDENCE_ID_MISSING="ev-settlement-live-missing-${RANDOM}-$(date +%s)"
COSMOS_PORT="$(pick_port)"
if [[ -z "${COSMOS_PORT}" ]]; then
  echo "failed to allocate closed cosmos endpoint port"
  exit 1
fi
COSMOS_ENDPOINT="http://127.0.0.1:${COSMOS_PORT}"

started="0"
BASE_URL=""
for _ in $(seq 1 12); do
  PORT="$(pick_port)"
  if [[ -z "${PORT}" ]]; then
    continue
  fi
  BASE_URL="http://127.0.0.1:${PORT}"
  start_issuer_runtime "${PORT}" "${COSMOS_ENDPOINT}"
  if wait_for_health_ready "${BASE_URL}/v1/health"; then
    started="1"
    break
  fi
  if [[ -n "${ISSUER_PID}" ]]; then
    wait "${ISSUER_PID}" 2>/dev/null || true
    ISSUER_PID=""
  fi
  if ! grep -Fq "address already in use" "${LOG_FILE}"; then
    echo "issuer failed to start for non-bind-conflict reason"
    cat "${LOG_FILE}"
    exit 1
  fi
done
if [[ "${started}" != "1" ]]; then
  echo "failed to start issuer settlement status live-smoke runtime after bind-conflict retries"
  cat "${LOG_FILE}"
  exit 1
fi

# Negative auth check: admin endpoint must reject unauthenticated callers.
get_expect_status "${BASE_URL}/v1/settlement/status" "401"

reserve_payload="$(jq -n \
  --arg reservation_id "${RESERVATION_ID}" \
  --arg sponsor_id "${SPONSOR_ID}" \
  --arg subject "${SUBJECT_ID}" \
  --arg session_id "${SESSION_ID}" \
  '{reservation_id:$reservation_id,sponsor_id:$sponsor_id,subject:$subject,session_id:$session_id,amount_micros:150000,currency:"TDPNC"}')"
post_expect_status "${BASE_URL}/v1/sponsor/reserve" "${reserve_payload}" "200" "X-Sponsor-Token" "${SPONSOR_TOKEN}"
jq -e --arg reservation_id "${RESERVATION_ID}" '
  .accepted == true and
  .reservation_id == $reservation_id and
  (.status | type == "string" and length > 0)
' "${RESP_FILE}" >/dev/null

slash_payload="$(jq -n \
  --arg evidence_id "${EVIDENCE_ID}" \
  --arg subject "${SUBJECT_ID}" \
  --arg session_id "${SESSION_ID}" \
  '{evidence_id:$evidence_id,subject:$subject,session_id:$session_id,violation_type:"double-sign",evidence_ref:"sha256:6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",slash_micros:42000,currency:"TDPNC",reason:"live-smoke objective evidence"}')"
post_expect_status "${BASE_URL}/v1/admin/slash/evidence" "${slash_payload}" "200" "X-Admin-Token" "${ADMIN_TOKEN}"
jq -e --arg evidence_id "${EVIDENCE_ID}" '
  .accepted == true and
  .evidence_id == $evidence_id and
  (.status | type == "string" and length > 0)
' "${RESP_FILE}" >/dev/null

invalid_violation_payload="$(jq -n \
  --arg evidence_id "${EVIDENCE_ID_INVALID}" \
  --arg subject "${SUBJECT_ID}" \
  --arg session_id "${SESSION_ID}" \
  '{evidence_id:$evidence_id,subject:$subject,session_id:$session_id,violation_type:"manual-review-only",evidence_ref:"sha256:6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",slash_micros:42000,currency:"TDPNC",reason:"live-smoke invalid violation type check"}')"
post_expect_status "${BASE_URL}/v1/admin/slash/evidence" "${invalid_violation_payload}" "400" "X-Admin-Token" "${ADMIN_TOKEN}"

missing_required_payload="$(jq -n \
  --arg evidence_id "${EVIDENCE_ID_MISSING}" \
  --arg subject "${SUBJECT_ID}" \
  --arg session_id "${SESSION_ID}" \
  '{evidence_id:$evidence_id,subject:$subject,session_id:$session_id,violation_type:"double-sign",slash_micros:42000,currency:"TDPNC",reason:"live-smoke missing required field check"}')"
post_expect_status "${BASE_URL}/v1/admin/slash/evidence" "${missing_required_payload}" "400" "X-Admin-Token" "${ADMIN_TOKEN}"

wait_for_backlog_status "${BASE_URL}/v1/settlement/status"

signal_runtime INT
if ! wait_for_runtime_exit 30; then
  signal_runtime TERM
fi
if ! wait_for_runtime_exit 20; then
  signal_runtime KILL
  wait_for_runtime_exit 20 || true
fi
if kill -0 "${ISSUER_PID}" 2>/dev/null; then
  echo "issuer did not exit after INT/TERM/KILL sequence"
  cat "${LOG_FILE}"
  exit 1
fi
wait "${ISSUER_PID}" 2>/dev/null || true
ISSUER_PID=""

echo "issuer settlement status live smoke integration check ok"
