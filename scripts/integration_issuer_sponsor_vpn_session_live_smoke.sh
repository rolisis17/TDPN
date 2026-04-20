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

TMP_DIR="$(mktemp -d -t issuer-sponsor-vpn-session-live-smoke.XXXXXX)"
RESP_FILE=""
ISSUER_LOG_FILE=""
EXIT_LOG_FILE=""
MOCK_LOG_FILE=""
MOCK_GO_FILE=""
ISSUER_PID=""
EXIT_PID=""
MOCK_PID=""

ADMIN_TOKEN="issuer-admin-sponsor-vpn-live-012345"
SPONSOR_TOKEN="issuer-sponsor-vpn-live-012345"

configure_scenario_paths() {
  local mode="$1"
  local sanitized_mode
  sanitized_mode="$(printf '%s' "${mode}" | tr -c '[:alnum:]_-' '_')"
  RESP_FILE="$TMP_DIR/response_${sanitized_mode}.json"
  ISSUER_LOG_FILE="$TMP_DIR/issuer_${sanitized_mode}.log"
  EXIT_LOG_FILE="$TMP_DIR/exit_${sanitized_mode}.log"
  MOCK_LOG_FILE="$TMP_DIR/mock_cosmos_${sanitized_mode}.log"
  MOCK_GO_FILE="$TMP_DIR/mock_cosmos_${sanitized_mode}.go"
}

signal_process() {
  local sig="$1"
  local pid="${2:-}"
  if [[ -n "${pid}" ]]; then
    kill "-${sig}" "${pid}" 2>/dev/null || true
    if command -v pkill >/dev/null 2>&1; then
      pkill "-${sig}" -P "${pid}" 2>/dev/null || true
    fi
  fi
}

wait_for_pid_exit() {
  local pid="$1"
  local attempts="$2"
  for _ in $(seq 1 "${attempts}"); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

stop_mock_runtime() {
  if [[ -n "${MOCK_PID}" ]] && kill -0 "${MOCK_PID}" 2>/dev/null; then
    signal_process INT "${MOCK_PID}"
    wait_for_pid_exit "${MOCK_PID}" 20 || true
    if kill -0 "${MOCK_PID}" 2>/dev/null; then
      signal_process TERM "${MOCK_PID}"
      wait_for_pid_exit "${MOCK_PID}" 20 || true
    fi
    if kill -0 "${MOCK_PID}" 2>/dev/null; then
      signal_process KILL "${MOCK_PID}"
    fi
    wait "${MOCK_PID}" 2>/dev/null || true
  fi
  MOCK_PID=""
}

stop_exit_runtime() {
  if [[ -n "${EXIT_PID}" ]] && kill -0 "${EXIT_PID}" 2>/dev/null; then
    signal_process INT "${EXIT_PID}"
    wait_for_pid_exit "${EXIT_PID}" 20 || true
    if kill -0 "${EXIT_PID}" 2>/dev/null; then
      signal_process TERM "${EXIT_PID}"
      wait_for_pid_exit "${EXIT_PID}" 20 || true
    fi
    if kill -0 "${EXIT_PID}" 2>/dev/null; then
      signal_process KILL "${EXIT_PID}"
    fi
    wait "${EXIT_PID}" 2>/dev/null || true
  fi
  EXIT_PID=""
}

stop_issuer_runtime() {
  if [[ -n "${ISSUER_PID}" ]] && kill -0 "${ISSUER_PID}" 2>/dev/null; then
    signal_process INT "${ISSUER_PID}"
    wait_for_pid_exit "${ISSUER_PID}" 20 || true
    if kill -0 "${ISSUER_PID}" 2>/dev/null; then
      signal_process TERM "${ISSUER_PID}"
      wait_for_pid_exit "${ISSUER_PID}" 20 || true
    fi
    if kill -0 "${ISSUER_PID}" 2>/dev/null; then
      signal_process KILL "${ISSUER_PID}"
    fi
    wait "${ISSUER_PID}" 2>/dev/null || true
  fi
  ISSUER_PID=""
}

cleanup() {
  set +e
  stop_mock_runtime
  stop_exit_runtime
  stop_issuer_runtime
  rm -rf "${TMP_DIR}"
  set -e
}
trap cleanup EXIT

pick_port() {
  for _ in $(seq 1 40); do
    local port
    port=$((61000 + RANDOM % 4000))
    if ! (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1; then
      echo "${port}"
      return 0
    fi
  done
  return 1
}

dump_logs() {
  echo "issuer log:"
  if [[ -f "${ISSUER_LOG_FILE}" ]]; then
    cat "${ISSUER_LOG_FILE}"
  fi
  echo
  echo "exit log:"
  if [[ -f "${EXIT_LOG_FILE}" ]]; then
    cat "${EXIT_LOG_FILE}"
  fi
  echo
  echo "mock cosmos log:"
  if [[ -f "${MOCK_LOG_FILE}" ]]; then
    cat "${MOCK_LOG_FILE}"
  fi
}

write_secret_file() {
  local secret_value="$1"
  local prefix="$2"
  local secret_path
  secret_path="$(mktemp "${TMP_DIR}/${prefix}.XXXXXX")"
  chmod 600 "${secret_path}"
  printf '%s' "${secret_value}" >"${secret_path}"
  printf '%s\n' "${secret_path}"
}

redact_sensitive_json() {
  local payload="$1"
  if command -v jq >/dev/null 2>&1 && printf '%s' "${payload}" | jq -e . >/dev/null 2>&1; then
    printf '%s' "${payload}" | jq -c '
      if type == "object" then
        (if has("token") then .token = "[redacted]" else . end)
        | (if has("private_key") then .private_key = "[redacted]" else . end)
        | (if has("credential") then .credential = "[redacted]" else . end)
      else
        .
      end
    '
    return
  fi
  printf '%s\n' "${payload}" | sed -E \
    -e 's/"token":"[^"]*"/"token":"[redacted]"/g' \
    -e 's/"private_key":"[^"]*"/"private_key":"[redacted]"/g' \
    -e 's/"credential":"[^"]*"/"credential":"[redacted]"/g'
}

wait_for_health_ready() {
  local url="$1"
  local pid="$2"
  local label="$3"
  local log_file="$4"
  for _ in $(seq 1 80); do
    if [[ -n "${pid}" ]] && ! kill -0 "${pid}" 2>/dev/null; then
      echo "${label} exited before health became ready"
      cat "${log_file}"
      return 1
    fi
    local code
    code="$(curl -s -m 2 -o "${RESP_FILE}" -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for ${label} health at ${url}"
  cat "${log_file}"
  return 1
}

start_mock_cosmos_runtime() {
  local port="$1"
  cat >"${MOCK_GO_FILE}" <<'EOF'
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	addr := "127.0.0.1:0"
	if len(os.Args) > 1 && strings.TrimSpace(os.Args[1]) != "" {
		addr = strings.TrimSpace(os.Args[1])
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		case r.URL.Path == "/cosmos/tx/v1beta1/txs":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"tx_response":{"code":0,"txhash":"MOCK_SPONSOR_VPN_SESSION_TX"}}`))
		case strings.HasPrefix(r.URL.Path, "/x/"):
			switch r.Method {
			case http.MethodPost:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":true}`))
			case http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"found":true}`))
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		default:
			http.NotFound(w, r)
		}
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	log.Printf("mock cosmos listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}
EOF
  : >"${MOCK_LOG_FILE}"
  (
    go run "${MOCK_GO_FILE}" "127.0.0.1:${port}"
  ) >"${MOCK_LOG_FILE}" 2>&1 &
  MOCK_PID=$!
}

start_issuer_runtime() {
  local port="$1"
  local cosmos_endpoint="$2"
  local submit_mode="$3"
  : >"${ISSUER_LOG_FILE}"
  (
    ISSUER_ADDR="127.0.0.1:${port}" \
    ISSUER_PRIVATE_KEY_FILE="${TMP_DIR}/issuer_ed25519_${port}.key" \
    ISSUER_PREVIOUS_PUBKEYS_FILE="${TMP_DIR}/issuer_previous_pubkeys_${port}.txt" \
    ISSUER_EPOCHS_FILE="${TMP_DIR}/issuer_epochs_${port}.json" \
    ISSUER_SUBJECTS_FILE="${TMP_DIR}/issuer_subjects_${port}.json" \
    ISSUER_REVOCATIONS_FILE="${TMP_DIR}/issuer_revocations_${port}.json" \
    ISSUER_ANON_REVOCATIONS_FILE="${TMP_DIR}/issuer_anon_revocations_${port}.json" \
    ISSUER_ANON_DISPUTES_FILE="${TMP_DIR}/issuer_anon_disputes_${port}.json" \
    ISSUER_AUDIT_FILE="${TMP_DIR}/issuer_audit_${port}.json" \
    ISSUER_SETTLEMENT_RECONCILE_SEC=0 \
    ISSUER_ADMIN_TOKEN="${ADMIN_TOKEN}" \
    ISSUER_ADMIN_ALLOW_TOKEN=1 \
    ISSUER_SPONSOR_API_TOKEN="${SPONSOR_TOKEN}" \
    SETTLEMENT_CHAIN_ADAPTER=cosmos \
    COSMOS_SETTLEMENT_ENDPOINT="${cosmos_endpoint}" \
    COSMOS_SETTLEMENT_API_KEY="issuer-sponsor-vpn-live-smoke" \
    COSMOS_SETTLEMENT_SUBMIT_MODE="${submit_mode}" \
    COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID="tdpn-settlement-smoke-1" \
    COSMOS_SETTLEMENT_SIGNED_TX_SIGNER="issuer-sponsor-vpn-live-smoke-signer" \
    COSMOS_SETTLEMENT_SIGNED_TX_SECRET="issuer-sponsor-vpn-live-smoke-secret" \
    COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID="issuer-sponsor-vpn-live-smoke-key" \
    COSMOS_SETTLEMENT_QUEUE_SIZE=8 \
    COSMOS_SETTLEMENT_MAX_RETRIES=1 \
    COSMOS_SETTLEMENT_BASE_BACKOFF_MS=20 \
    COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS=120 \
    go run ./cmd/node --issuer
  ) >"${ISSUER_LOG_FILE}" 2>&1 &
  ISSUER_PID=$!
}

start_exit_runtime() {
  local exit_port="$1"
  local data_port="$2"
  local issuer_url="$3"
  local cosmos_endpoint="$4"
  local submit_mode="$5"
  : >"${EXIT_LOG_FILE}"
  (
    DATA_PLANE_MODE=json \
    WG_BACKEND=noop \
    EXIT_ADDR="127.0.0.1:${exit_port}" \
    EXIT_DATA_ADDR="127.0.0.1:${data_port}" \
    ISSUER_URL="${issuer_url}" \
    ISSUER_REVOCATIONS_URL="${issuer_url}/v1/revocations" \
    EXIT_STARTUP_SYNC_TIMEOUT_SEC=8 \
    EXIT_SETTLEMENT_RECONCILE_SEC=0 \
    SETTLEMENT_CHAIN_ADAPTER=cosmos \
    COSMOS_SETTLEMENT_ENDPOINT="${cosmos_endpoint}" \
    COSMOS_SETTLEMENT_API_KEY="exit-sponsor-vpn-live-smoke" \
    COSMOS_SETTLEMENT_SUBMIT_MODE="${submit_mode}" \
    COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID="tdpn-settlement-smoke-1" \
    COSMOS_SETTLEMENT_SIGNED_TX_SIGNER="exit-sponsor-vpn-live-smoke-signer" \
    COSMOS_SETTLEMENT_SIGNED_TX_SECRET="exit-sponsor-vpn-live-smoke-secret" \
    COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID="exit-sponsor-vpn-live-smoke-key" \
    COSMOS_SETTLEMENT_QUEUE_SIZE=8 \
    COSMOS_SETTLEMENT_MAX_RETRIES=1 \
    COSMOS_SETTLEMENT_BASE_BACKOFF_MS=20 \
    COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS=120 \
    go run ./cmd/node --exit
  ) >"${EXIT_LOG_FILE}" 2>&1 &
  EXIT_PID=$!
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
    dump_logs
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
    dump_logs
    return 1
  fi
}

assert_response_jq() {
  local context="$1"
  shift
  if ! jq -e "$@" "${RESP_FILE}" >/dev/null; then
    echo "response assertion failed: ${context}"
    echo "response:"
    cat "${RESP_FILE}"
    echo
    dump_logs
    return 1
  fi
}

wait_for_settlement_status_available() {
  local url="$1"
  local header_name="${2:-}"
  local token="${3:-}"
  local runtime_pid="${4:-}"
  local runtime_name="${5:-runtime}"
  for _ in $(seq 1 120); do
    if [[ -n "${runtime_pid}" ]] && ! kill -0 "${runtime_pid}" 2>/dev/null; then
      echo "${runtime_name} exited before settlement status became available"
      dump_logs
      return 1
    fi
    local code
    if [[ -n "${header_name}" && -n "${token}" ]]; then
      code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" -H "${header_name}: ${token}" "${url}" || true)"
    else
      code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" "${url}" || true)"
    fi
    if [[ "${code}" == "200" ]] && jq -e '
      .enabled == true and
      (
        ((.status? | type) == "string" and ((.status // "") | length) > 0) or
        (
          (.checked_at | type == "string" and length > 0) and
          (.report_generated_at | type == "string" and length > 0)
        ) or
        (
          (.checked_at | type == "number" and . >= 0) and
          (.generated_at | type == "number" and . >= 0)
        )
      )
    ' "${RESP_FILE}" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for settlement status availability at ${url}"
  echo "last response:"
  cat "${RESP_FILE}"
  echo
  dump_logs
  return 1
}

wait_for_sponsor_consumed_status() {
  local url="$1"
  local token="$2"
  local reservation_id="$3"
  local sponsor_id="$4"
  local subject_id="$5"
  local session_id="$6"
  local amount_micros="$7"
  local currency="$8"
  for _ in $(seq 1 80); do
    get_expect_status "${url}" "200" "X-Sponsor-Token" "${token}"
    if jq -e \
      --arg reservation_id "${reservation_id}" \
      --arg sponsor_id "${sponsor_id}" \
      --arg subject_id "${subject_id}" \
      --arg session_id "${session_id}" \
      --argjson amount_micros "${amount_micros}" \
      --arg currency "${currency}" '
      .accepted == true and
      .reservation_id == $reservation_id and
      .sponsor_id == $sponsor_id and
      .subject == $subject_id and
      .session_id == $session_id and
      .amount_micros == $amount_micros and
      .currency == $currency and
      (.status | type == "string" and length > 0) and
      (.created_at | type == "number" and . > 0) and
      (.expires_at | type == "number" and . > 0) and
      (.consumed_at | type == "number" and . > 0) and
      (.expires_at >= .created_at) and
      (.consumed_at >= .created_at)
    ' "${RESP_FILE}" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for sponsor reservation consumed metadata"
  echo "last response:"
  cat "${RESP_FILE}"
  echo
  dump_logs
  return 1
}

extract_token_proof() {
  local sign_output="$1"
  local proof
  proof="$(printf '%s' "${sign_output}" | jq -r '.proof // empty' 2>/dev/null || true)"
  if [[ -n "${proof}" ]]; then
    printf '%s' "${proof}"
    return 0
  fi
  proof="$(printf '%s' "${sign_output}" | tr -d '\r\n')"
  if [[ -n "${proof}" ]]; then
    printf '%s' "${proof}"
    return 0
  fi
  return 1
}

run_mode_scenario() {
  local mode="$1"
  case "${mode}" in
    http|signed-tx)
      ;;
    *)
      echo "unsupported sponsor vpn session smoke mode: ${mode}"
      return 1
      ;;
  esac

  configure_scenario_paths "${mode}"
  : >"${RESP_FILE}"
  stop_mock_runtime
  stop_exit_runtime
  stop_issuer_runtime

  local mode_tag
  mode_tag="$(printf '%s' "${mode}" | tr -c '[:alnum:]' '-')"
  local unique_suffix
  unique_suffix="${RANDOM}-$(date +%s)-${mode_tag}"

  local subject_id="client-sponsor-vpn-live-${mode_tag}"
  local sponsor_id="dapp-sponsor-vpn-live-${mode_tag}"
  local reservation_id="sres-sponsor-vpn-live-${unique_suffix}"
  local session_id="sess-sponsor-vpn-live-${unique_suffix}"
  local exit_id="exit-sponsor-vpn-live-${mode_tag}"
  local token_nonce="proof-sponsor-vpn-live-${unique_suffix}"
  local reserve_amount_micros=250000
  local reserve_currency="TDPNC"

  local cosmos_started="0"
  local cosmos_endpoint=""
  for _ in $(seq 1 12); do
    local cosmos_port
    cosmos_port="$(pick_port)"
    if [[ -z "${cosmos_port}" ]]; then
      continue
    fi
    cosmos_endpoint="http://127.0.0.1:${cosmos_port}"
    start_mock_cosmos_runtime "${cosmos_port}"
    if wait_for_health_ready "${cosmos_endpoint}/health" "${MOCK_PID}" "mock cosmos" "${MOCK_LOG_FILE}"; then
      cosmos_started="1"
      break
    fi
    stop_mock_runtime
    if ! grep -Fq "address already in use" "${MOCK_LOG_FILE}"; then
      echo "mock cosmos failed to start for non-bind-conflict reason (mode=${mode})"
      cat "${MOCK_LOG_FILE}"
      return 1
    fi
  done
  if [[ "${cosmos_started}" != "1" ]]; then
    echo "failed to start mock cosmos runtime after bind-conflict retries (mode=${mode})"
    if [[ -f "${MOCK_LOG_FILE}" ]]; then
      cat "${MOCK_LOG_FILE}"
    fi
    return 1
  fi

  local issuer_url=""
  local issuer_started="0"
  for _ in $(seq 1 12); do
    local issuer_port
    issuer_port="$(pick_port)"
    if [[ -z "${issuer_port}" ]]; then
      continue
    fi
    issuer_url="http://127.0.0.1:${issuer_port}"
    start_issuer_runtime "${issuer_port}" "${cosmos_endpoint}" "${mode}"
    if wait_for_health_ready "${issuer_url}/v1/health" "${ISSUER_PID}" "issuer" "${ISSUER_LOG_FILE}"; then
      issuer_started="1"
      break
    fi
    stop_issuer_runtime
    if ! grep -Fq "address already in use" "${ISSUER_LOG_FILE}"; then
      echo "issuer failed to start for non-bind-conflict reason (mode=${mode})"
      cat "${ISSUER_LOG_FILE}"
      return 1
    fi
  done
  if [[ "${issuer_started}" != "1" ]]; then
    echo "failed to start issuer runtime after bind-conflict retries (mode=${mode})"
    cat "${ISSUER_LOG_FILE}"
    return 1
  fi

  local exit_base_url=""
  local exit_started="0"
  for _ in $(seq 1 12); do
    local exit_port
    exit_port="$(pick_port)"
    local exit_data_port
    exit_data_port="$(pick_port)"
    if [[ -z "${exit_port}" || -z "${exit_data_port}" || "${exit_port}" == "${exit_data_port}" ]]; then
      continue
    fi
    exit_base_url="http://127.0.0.1:${exit_port}"
    start_exit_runtime "${exit_port}" "${exit_data_port}" "${issuer_url}" "${cosmos_endpoint}" "${mode}"
    if wait_for_health_ready "${exit_base_url}/v1/health" "${EXIT_PID}" "exit" "${EXIT_LOG_FILE}"; then
      exit_started="1"
      break
    fi
    stop_exit_runtime
    if ! grep -Fq "address already in use" "${EXIT_LOG_FILE}"; then
      echo "exit failed to start for non-bind-conflict reason (mode=${mode})"
      cat "${EXIT_LOG_FILE}"
      return 1
    fi
  done
  if [[ "${exit_started}" != "1" ]]; then
    echo "failed to start exit runtime after bind-conflict retries (mode=${mode})"
    cat "${EXIT_LOG_FILE}"
    return 1
  fi

  wait_for_settlement_status_available "${issuer_url}/v1/settlement/status" "X-Admin-Token" "${ADMIN_TOKEN}" "${ISSUER_PID}" "issuer"
  wait_for_settlement_status_available "${exit_base_url}/v1/settlement/status" "" "" "${EXIT_PID}" "exit"

  local quote_payload
  quote_payload="$(jq -n --arg subject "${subject_id}" --arg currency "${reserve_currency}" '{subject:$subject,currency:$currency}')"
  post_expect_status "${issuer_url}/v1/sponsor/quote" "${quote_payload}" "200" "X-Sponsor-Token" "${SPONSOR_TOKEN}"
  assert_response_jq "mode=${mode} sponsor quote response contract" --arg subject_id "${subject_id}" --arg reserve_currency "${reserve_currency}" '
    .subject == $subject_id and
    .currency == $reserve_currency and
    (.price_per_mib_micros | type == "number" and . > 0) and
    (.quoted_at | type == "number" and . > 0) and
    (.expires_at | type == "number" and . > 0) and
    (.expires_at >= .quoted_at)
  '

  local reserve_payload
  reserve_payload="$(jq -n \
    --arg reservation_id "${reservation_id}" \
    --arg sponsor_id "${sponsor_id}" \
    --arg subject_id "${subject_id}" \
    --arg session_id "${session_id}" \
    --arg reserve_currency "${reserve_currency}" \
    --argjson reserve_amount_micros "${reserve_amount_micros}" \
    '{reservation_id:$reservation_id,sponsor_id:$sponsor_id,subject:$subject_id,session_id:$session_id,amount_micros:$reserve_amount_micros,currency:$reserve_currency}')"
  post_expect_status "${issuer_url}/v1/sponsor/reserve" "${reserve_payload}" "200" "X-Sponsor-Token" "${SPONSOR_TOKEN}"
  assert_response_jq "mode=${mode} sponsor reserve accepted contract" \
    --arg reservation_id "${reservation_id}" \
    --arg sponsor_id "${sponsor_id}" \
    --arg subject_id "${subject_id}" \
    --arg session_id "${session_id}" \
    --arg reserve_currency "${reserve_currency}" \
    --argjson reserve_amount_micros "${reserve_amount_micros}" '
    .accepted == true and
    .reservation_id == $reservation_id and
    .sponsor_id == $sponsor_id and
    .subject == $subject_id and
    .session_id == $session_id and
    .amount_micros == $reserve_amount_micros and
    .currency == $reserve_currency and
    (.status | type == "string" and length > 0) and
    (.created_at | type == "number" and . > 0) and
    (.expires_at | type == "number" and . > 0) and
    (.expires_at >= .created_at)
  '

  local pop_json
  pop_json="$(go run ./cmd/tokenpop gen --show-private-key)"
  local pop_pub_key
  pop_pub_key="$(printf '%s' "${pop_json}" | jq -r '.public_key // empty')"
  local pop_priv_key
  pop_priv_key="$(printf '%s' "${pop_json}" | jq -r '.private_key // empty')"
  if [[ -z "${pop_pub_key}" || -z "${pop_priv_key}" ]]; then
    echo "failed to generate token proof keypair for mode=${mode}"
    redact_sensitive_json "${pop_json}"
    dump_logs
    return 1
  fi

  local sponsor_token_payload
  sponsor_token_payload="$(jq -n \
    --arg subject_id "${subject_id}" \
    --arg pop_pub_key "${pop_pub_key}" \
    --arg exit_id "${exit_id}" \
    --arg reservation_id "${reservation_id}" \
    --arg sponsor_id "${sponsor_id}" \
    --arg session_id "${session_id}" \
    '{
      tier:1,
      subject:$subject_id,
      token_type:"client_access",
      pop_pub_key:$pop_pub_key,
      exit_scope:[$exit_id],
      payment_proof:{
        reservation_id:$reservation_id,
        sponsor_id:$sponsor_id,
        subject:$subject_id,
        session_id:$session_id
      }
    }')"
  post_expect_status "${issuer_url}/v1/sponsor/token" "${sponsor_token_payload}" "200" "X-Sponsor-Token" "${SPONSOR_TOKEN}"
  assert_response_jq "mode=${mode} sponsor payment-proof token issuance contract" '
    (.token | type == "string" and length > 0) and
    (.expires | type == "number" and . > 0) and
    (.jti | type == "string" and length > 0)
  '
  local token
  token="$(jq -r '.token // empty' "${RESP_FILE}")"
  if [[ -z "${token}" ]]; then
    echo "sponsor token response missing token for mode=${mode}"
    cat "${RESP_FILE}"
    dump_logs
    return 1
  fi

  local client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  local pop_priv_file
  pop_priv_file="$(write_secret_file "${pop_priv_key}" "tokenpop_private_${mode_tag}")"
  local token_file
  token_file="$(write_secret_file "${token}" "token_${mode_tag}")"
  local token_proof_json
  token_proof_json="$(go run ./cmd/tokenpop sign \
    --private-key-file "${pop_priv_file}" \
    --token-file "${token_file}" \
    --exit-id "${exit_id}" \
    --proof-nonce "${token_nonce}" \
    --client-inner-pub "${client_pub}" \
    --transport "policy-json" \
    --requested-mtu 1280 \
    --requested-region "local")"
  rm -f "${pop_priv_file}" "${token_file}"
  local token_proof
  token_proof="$(extract_token_proof "${token_proof_json}")"
  if [[ -z "${token_proof}" ]]; then
    echo "failed to sign token proof for mode=${mode}"
    redact_sensitive_json "${token_proof_json}"
    dump_logs
    return 1
  fi

  local open_payload
  open_payload="$(jq -n \
    --arg exit_id "${exit_id}" \
    --arg token "${token}" \
    --arg token_proof "${token_proof}" \
    --arg token_nonce "${token_nonce}" \
    --arg client_pub "${client_pub}" \
    --arg session_id "${session_id}" \
    '{
      exit_id:$exit_id,
      token:$token,
      token_proof:$token_proof,
      token_proof_nonce:$token_nonce,
      client_inner_pub:$client_pub,
      transport:"policy-json",
      requested_mtu:1280,
      requested_region:"local",
      session_id:$session_id
    }')"
  post_expect_status "${exit_base_url}/v1/path/open" "${open_payload}" "200"
  assert_response_jq "mode=${mode} path open accepted contract" '
    .accepted == true and
    (.reason | type == "string") and
    (
      ((.session_exp | type == "number") and .session_exp > 0) or
      true
    )
  '

  local close_payload
  close_payload="$(jq -n --arg session_id "${session_id}" '{session_id:$session_id}')"
  post_expect_status "${exit_base_url}/v1/path/close" "${close_payload}" "200"
  assert_response_jq "mode=${mode} path close accepted contract" '
    .closed == true
  '

  wait_for_sponsor_consumed_status \
    "${issuer_url}/v1/sponsor/status?reservation_id=${reservation_id}" \
    "${SPONSOR_TOKEN}" \
    "${reservation_id}" \
    "${sponsor_id}" \
    "${subject_id}" \
    "${session_id}" \
    "${reserve_amount_micros}" \
    "${reserve_currency}"

  wait_for_settlement_status_available "${issuer_url}/v1/settlement/status" "X-Admin-Token" "${ADMIN_TOKEN}" "${ISSUER_PID}" "issuer"
  wait_for_settlement_status_available "${exit_base_url}/v1/settlement/status" "" "" "${EXIT_PID}" "exit"

  stop_exit_runtime
  stop_issuer_runtime
  stop_mock_runtime
  echo "issuer sponsor vpn session live smoke scenario ok mode=${mode}"
}

SPONSOR_VPN_SESSION_SMOKE_MODES="${SPONSOR_VPN_SESSION_SMOKE_MODES:-http,signed-tx}"

trimmed_mode_values=()
IFS=',' read -r -a raw_modes <<<"${SPONSOR_VPN_SESSION_SMOKE_MODES}"
for raw_mode in "${raw_modes[@]}"; do
  mode="${raw_mode#"${raw_mode%%[![:space:]]*}"}"
  mode="${mode%"${mode##*[![:space:]]}"}"
  if [[ -n "${mode}" ]]; then
    trimmed_mode_values+=("${mode}")
  fi
done

if [[ "${#trimmed_mode_values[@]}" -eq 0 ]]; then
  echo "no sponsor vpn session smoke modes requested via SPONSOR_VPN_SESSION_SMOKE_MODES"
  exit 1
fi

for mode in "${trimmed_mode_values[@]}"; do
  run_mode_scenario "${mode}"
done

echo "issuer sponsor vpn session live smoke integration check ok (modes: ${trimmed_mode_values[*]})"
