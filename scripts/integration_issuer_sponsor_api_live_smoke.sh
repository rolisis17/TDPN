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

TMP_DIR="$(mktemp -d -t issuer-sponsor-live-smoke.XXXXXX)"
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
      echo "issuer exited before sponsor API health became ready"
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
  echo "timed out waiting for issuer sponsor API health at ${url}"
  cat "${LOG_FILE}"
  return 1
}

start_issuer_runtime() {
  local port="$1"
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
    ISSUER_SPONSOR_API_TOKEN="${SPONSOR_TOKEN}" \
    go run ./cmd/node --issuer
  ) >"${LOG_FILE}" 2>&1 &
  ISSUER_PID=$!
}

post_expect_status() {
  local url="$1"
  local payload="$2"
  local expected="$3"
  local token="${4:-}"
  local code
  if [[ -n "${token}" ]]; then
    code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" -H "Content-Type: application/json" -H "X-Sponsor-Token: ${token}" -d "${payload}" "${url}" || true)"
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
  local token="${3:-}"
  local code
  if [[ -n "${token}" ]]; then
    code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" -H "X-Sponsor-Token: ${token}" "${url}" || true)"
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

assert_response_contains() {
  local needle="$1"
  local context="$2"
  local body
  body="$(cat "${RESP_FILE}" 2>/dev/null || true)"
  if [[ "${body}" != *"${needle}"* ]]; then
    echo "unexpected response body for ${context}: expected to contain '${needle}'"
    echo "response:"
    printf '%s\n' "${body}"
    echo
    echo "issuer log:"
    cat "${LOG_FILE}"
    return 1
  fi
}

PORT="$(pick_port)"
if [[ -z "${PORT}" ]]; then
  echo "failed to allocate issuer sponsor live-smoke port"
  exit 1
fi

SPONSOR_TOKEN="sponsor-live-smoke-token"
SUBJECT_ID="client-live-1"
SPONSOR_ID="dapp-operator-live-1"
RESERVATION_ID="sres-live-${RANDOM}-$(date +%s)"
SESSION_ID="sess-live-${RANDOM}-$(date +%s)"
BASE_URL=""
started="0"
for _ in $(seq 1 12); do
  PORT="$(pick_port)"
  if [[ -z "${PORT}" ]]; then
    continue
  fi
  BASE_URL="http://127.0.0.1:${PORT}"
  start_issuer_runtime "${PORT}"
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
  echo "failed to start issuer sponsor live-smoke runtime after bind-conflict retries"
  cat "${LOG_FILE}"
  exit 1
fi

quote_payload="$(jq -n --arg subject "${SUBJECT_ID}" --arg currency "TDPNC" '{subject:$subject,currency:$currency}')"
post_expect_status "${BASE_URL}/v1/sponsor/quote" "${quote_payload}" "200" "${SPONSOR_TOKEN}"
jq -e --arg subject "${SUBJECT_ID}" '
  .subject == $subject and
  .currency == "TDPNC" and
  (.price_per_mib_micros | type == "number" and . > 0) and
  (.quoted_at | type == "number" and . > 0) and
  (.expires_at | type == "number" and . > 0)
' "${RESP_FILE}" >/dev/null

reserve_payload="$(jq -n \
  --arg reservation_id "${RESERVATION_ID}" \
  --arg sponsor_id "${SPONSOR_ID}" \
  --arg subject "${SUBJECT_ID}" \
  --arg session_id "${SESSION_ID}" \
  --arg currency "TDPNC" \
  '{reservation_id:$reservation_id,sponsor_id:$sponsor_id,subject:$subject,session_id:$session_id,amount_micros:200000,currency:$currency}')"
post_expect_status "${BASE_URL}/v1/sponsor/reserve" "${reserve_payload}" "200" "${SPONSOR_TOKEN}"
jq -e --arg reservation_id "${RESERVATION_ID}" --arg sponsor_id "${SPONSOR_ID}" --arg subject "${SUBJECT_ID}" --arg session_id "${SESSION_ID}" '
  .accepted == true and
  .reservation_id == $reservation_id and
  .sponsor_id == $sponsor_id and
  .subject == $subject and
  .session_id == $session_id and
  .amount_micros == 200000 and
  .currency == "TDPNC" and
  (.status | type == "string" and length > 0) and
  (.created_at | type == "number" and . > 0) and
  (.expires_at | type == "number" and . > 0)
' "${RESP_FILE}" >/dev/null

pop_pub_key="$(go run ./cmd/tokenpop gen | jq -r '.public_key // empty')"
if [[ -z "${pop_pub_key}" ]]; then
  echo "failed to generate pop public key for sponsor token request"
  cat "${LOG_FILE}"
  exit 1
fi

token_missing_proof_payload="$(jq -n \
  --arg subject "${SUBJECT_ID}" \
  --arg pop_pub_key "${pop_pub_key}" \
  '{tier:1,subject:$subject,token_type:"client_access",pop_pub_key:$pop_pub_key}')"
echo "[issuer-sponsor-live-smoke] payment-proof negative path invalid proof (missing payment_proof)"
post_expect_status "${BASE_URL}/v1/sponsor/token" "${token_missing_proof_payload}" "402" "${SPONSOR_TOKEN}"
assert_response_contains "payment proof required" "missing sponsor token payment_proof"

token_blank_reservation_id_payload="$(jq -n \
  --arg subject "${SUBJECT_ID}" \
  --arg pop_pub_key "${pop_pub_key}" \
  --arg sponsor_id "${SPONSOR_ID}" \
  --arg session_id "${SESSION_ID}" \
  '{tier:1,subject:$subject,token_type:"client_access",pop_pub_key:$pop_pub_key,payment_proof:{reservation_id:"",sponsor_id:$sponsor_id,subject:$subject,session_id:$session_id}}')"
echo "[issuer-sponsor-live-smoke] payment-proof negative path invalid proof (blank reservation_id)"
post_expect_status "${BASE_URL}/v1/sponsor/token" "${token_blank_reservation_id_payload}" "402" "${SPONSOR_TOKEN}"
assert_response_contains "authorize payment requires reservation_id" "blank reservation_id token payment_proof"

token_mismatched_proof_payload="$(jq -n \
  --arg subject "${SUBJECT_ID}" \
  --arg pop_pub_key "${pop_pub_key}" \
  --arg reservation_id "${RESERVATION_ID}" \
  --arg sponsor_id "mismatched-sponsor-live-smoke" \
  --arg session_id "${SESSION_ID}" \
  '{tier:1,subject:$subject,token_type:"client_access",pop_pub_key:$pop_pub_key,payment_proof:{reservation_id:$reservation_id,sponsor_id:$sponsor_id,subject:$subject,session_id:$session_id}}')"
post_expect_status "${BASE_URL}/v1/sponsor/token" "${token_mismatched_proof_payload}" "402" "${SPONSOR_TOKEN}"
assert_response_contains "reservation sponsor mismatch" "mismatched sponsor token payment_proof"
echo "[issuer-sponsor-live-smoke] payment-proof negative path invalid proof (mismatched sponsor)"

token_subject_mismatch_payload="$(jq -n \
  --arg subject "${SUBJECT_ID}" \
  --arg pop_pub_key "${pop_pub_key}" \
  --arg reservation_id "${RESERVATION_ID}" \
  --arg sponsor_id "${SPONSOR_ID}" \
  --arg mismatched_subject "client-live-mismatch-subject" \
  --arg session_id "${SESSION_ID}" \
  '{tier:1,subject:$subject,token_type:"client_access",pop_pub_key:$pop_pub_key,payment_proof:{reservation_id:$reservation_id,sponsor_id:$sponsor_id,subject:$mismatched_subject,session_id:$session_id}}')"
post_expect_status "${BASE_URL}/v1/sponsor/token" "${token_subject_mismatch_payload}" "402" "${SPONSOR_TOKEN}"
assert_response_contains "subject mismatch" "mismatched subject token payment_proof"
echo "[issuer-sponsor-live-smoke] payment-proof negative path invalid proof (mismatched subject)"

token_session_mismatch_payload="$(jq -n \
  --arg subject "${SUBJECT_ID}" \
  --arg pop_pub_key "${pop_pub_key}" \
  --arg reservation_id "${RESERVATION_ID}" \
  --arg sponsor_id "${SPONSOR_ID}" \
  --arg subject_proof "${SUBJECT_ID}" \
  --arg mismatched_session "sess-live-mismatch-${RANDOM}-$(date +%s)" \
  '{tier:1,subject:$subject,token_type:"client_access",pop_pub_key:$pop_pub_key,payment_proof:{reservation_id:$reservation_id,sponsor_id:$sponsor_id,subject:$subject_proof,session_id:$mismatched_session}}')"
post_expect_status "${BASE_URL}/v1/sponsor/token" "${token_session_mismatch_payload}" "402" "${SPONSOR_TOKEN}"
assert_response_contains "session mismatch" "mismatched session token payment_proof"
echo "[issuer-sponsor-live-smoke] payment-proof negative path invalid proof (mismatched session)"

unknown_reservation_id="sres-live-missing-${RANDOM}-$(date +%s)"
token_unknown_reservation_payload="$(jq -n \
  --arg subject "${SUBJECT_ID}" \
  --arg pop_pub_key "${pop_pub_key}" \
  --arg reservation_id "${unknown_reservation_id}" \
  --arg sponsor_id "${SPONSOR_ID}" \
  --arg session_id "${SESSION_ID}" \
  '{tier:1,subject:$subject,token_type:"client_access",pop_pub_key:$pop_pub_key,payment_proof:{reservation_id:$reservation_id,sponsor_id:$sponsor_id,subject:$subject,session_id:$session_id}}')"
post_expect_status "${BASE_URL}/v1/sponsor/token" "${token_unknown_reservation_payload}" "402" "${SPONSOR_TOKEN}"
assert_response_contains "payment proof invalid: reservation not found:" "unknown reservation token payment_proof"
echo "[issuer-sponsor-live-smoke] payment-proof negative path invalid proof (unknown reservation)"

token_payload="$(jq -n \
  --arg subject "${SUBJECT_ID}" \
  --arg pop_pub_key "${pop_pub_key}" \
  --arg reservation_id "${RESERVATION_ID}" \
  --arg sponsor_id "${SPONSOR_ID}" \
  --arg session_id "${SESSION_ID}" \
  '{tier:1,subject:$subject,token_type:"client_access",pop_pub_key:$pop_pub_key,payment_proof:{reservation_id:$reservation_id,sponsor_id:$sponsor_id,subject:$subject,session_id:$session_id}}')"
echo "[issuer-sponsor-live-smoke] payment-proof happy path token issuance"
post_expect_status "${BASE_URL}/v1/sponsor/token" "${token_payload}" "200" "${SPONSOR_TOKEN}"
jq -e '
  (.token | type == "string" and length > 0) and
  (.expires | type == "number" and . > 0) and
  (.jti | type == "string" and length > 0)
' "${RESP_FILE}" >/dev/null

get_expect_status "${BASE_URL}/v1/sponsor/status?reservation_id=${RESERVATION_ID}" "200" "${SPONSOR_TOKEN}"
jq -e --arg reservation_id "${RESERVATION_ID}" --arg sponsor_id "${SPONSOR_ID}" --arg subject "${SUBJECT_ID}" --arg session_id "${SESSION_ID}" '
  .accepted == true and
  .reservation_id == $reservation_id and
  .sponsor_id == $sponsor_id and
  .subject == $subject and
  .session_id == $session_id and
  (.status | type == "string" and length > 0) and
  (.consumed_at | type == "number" and . > 0)
' "${RESP_FILE}" >/dev/null
consumed_at_after_first_issue="$(jq -r '.consumed_at // empty' "${RESP_FILE}")"
if [[ -z "${consumed_at_after_first_issue}" || "${consumed_at_after_first_issue}" == "null" ]]; then
  echo "expected consumed_at after first payment-proof success"
  cat "${RESP_FILE}"
  exit 1
fi

echo "[issuer-sponsor-live-smoke] payment-proof negative path duplicate proof replay"
post_expect_status "${BASE_URL}/v1/sponsor/token" "${token_payload}" "200" "${SPONSOR_TOKEN}"
jq -e '
  (.token | type == "string" and length > 0) and
  (.expires | type == "number" and . > 0) and
  (.jti | type == "string" and length > 0)
' "${RESP_FILE}" >/dev/null

get_expect_status "${BASE_URL}/v1/sponsor/status?reservation_id=${RESERVATION_ID}" "200" "${SPONSOR_TOKEN}"
jq -e --arg reservation_id "${RESERVATION_ID}" --arg sponsor_id "${SPONSOR_ID}" --arg subject "${SUBJECT_ID}" --arg session_id "${SESSION_ID}" '
  .accepted == true and
  .reservation_id == $reservation_id and
  .sponsor_id == $sponsor_id and
  .subject == $subject and
  .session_id == $session_id and
  (.status | type == "string" and length > 0) and
  (.consumed_at | type == "number" and . > 0)
' "${RESP_FILE}" >/dev/null
consumed_at_after_replay="$(jq -r '.consumed_at // empty' "${RESP_FILE}")"
if [[ "${consumed_at_after_replay}" != "${consumed_at_after_first_issue}" ]]; then
  echo "duplicate payment-proof replay must be idempotent for consumed_at"
  echo "first consumed_at=${consumed_at_after_first_issue} replay consumed_at=${consumed_at_after_replay}"
  cat "${RESP_FILE}"
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
if kill -0 "${ISSUER_PID}" 2>/dev/null; then
  echo "issuer did not exit after INT/TERM/KILL sequence"
  cat "${LOG_FILE}"
  exit 1
fi
wait "${ISSUER_PID}" 2>/dev/null || true
ISSUER_PID=""

echo "issuer sponsor api live smoke integration check ok"
