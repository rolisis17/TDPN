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

TMP_DIR="$(mktemp -d -t exit-settlement-status-live-smoke.XXXXXX)"
RESP_FILE=""
ISSUER_LOG_FILE=""
EXIT_LOG_FILE=""
MOCK_LOG_FILE=""
MOCK_GO_FILE=""
ISSUER_PID=""
EXIT_PID=""
MOCK_PID=""

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
  if printf '%s' "${payload}" | jq -e . >/dev/null 2>&1; then
    printf '%s' "${payload}" | jq -c '
      if type == "object" then
        (if has("token") then .token = "[redacted]" else . end)
        | (if has("private_key") then .private_key = "[redacted]" else . end)
      else
        .
      end
    '
    return
  fi
  printf '%s\n' "${payload}" | sed -E \
    -e 's/("token"[[:space:]]*:[[:space:]]*")[^"]+/\1[redacted]/g' \
    -e 's/("private_key"[[:space:]]*:[[:space:]]*")[^"]+/\1[redacted]/g'
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

start_issuer_runtime() {
  local port="$1"
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
    COSMOS_SETTLEMENT_API_KEY="exit-settlement-smoke" \
    COSMOS_SETTLEMENT_SUBMIT_MODE="${submit_mode}" \
    COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID="tdpn-settlement-smoke-1" \
    COSMOS_SETTLEMENT_SIGNED_TX_SIGNER="exit-settlement-smoke-signer" \
    COSMOS_SETTLEMENT_SIGNED_TX_SECRET="exit-settlement-smoke-secret" \
    COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID="exit-settlement-smoke-key" \
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
  local code
  code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" -H "Content-Type: application/json" -d "${payload}" "${url}" || true)"
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
  local code
  code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" "${url}" || true)"
  if [[ "${code}" != "${expected}" ]]; then
    echo "unexpected status for ${url}: expected ${expected}, got ${code}"
    echo "response:"
    cat "${RESP_FILE}"
    echo
    dump_logs
    return 1
  fi
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
			_, _ = w.Write([]byte(`{"tx_response":{"code":0,"txhash":"MOCK_EXIT_SETTLEMENT_TX"}}`))
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

wait_for_mock_ready() {
  local url="$1"
  for _ in $(seq 1 80); do
    if [[ -n "${MOCK_PID}" ]] && ! kill -0 "${MOCK_PID}" 2>/dev/null; then
      echo "mock cosmos exited before it became ready"
      dump_logs
      return 1
    fi
    local code
    code="$(curl -s -m 2 -o "${RESP_FILE}" -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for mock cosmos at ${url}"
  dump_logs
  return 1
}

wait_for_backlog_status() {
  local url="$1"
  for _ in $(seq 1 120); do
    if [[ -n "${EXIT_PID}" ]] && ! kill -0 "${EXIT_PID}" 2>/dev/null; then
      echo "exit exited before settlement backlog status became ready"
      dump_logs
      return 1
    fi
    get_expect_status "${url}" "200"
    if jq -e '
      .enabled == true and
      (
        ((((.last_error // "") | length) > 0) and .stale == true) or
        ((((.last_error // "") | length) == 0) and .stale == false)
      ) and
      (.pending_adapter_operations | type == "number" and . >= 1) and
      (
        (.pending_operations + .submitted_operations + .confirmed_operations + .failed_operations)
        | type == "number" and . >= 1
      )
    ' "${RESP_FILE}" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for exit settlement backlog status contract"
  echo "last response:"
  cat "${RESP_FILE}"
  echo
  dump_logs
  return 1
}

wait_for_recovery_status() {
  local url="$1"
  for _ in $(seq 1 160); do
    if [[ -n "${EXIT_PID}" ]] && ! kill -0 "${EXIT_PID}" 2>/dev/null; then
      echo "exit exited before settlement recovery status became ready"
      dump_logs
      return 1
    fi
    get_expect_status "${url}" "200"
    if jq -e '
      .enabled == true and
      .stale == false and
      (.pending_adapter_operations | type == "number" and . == 0) and
      (.failed_operations | type == "number" and . == 0) and
      ((.submitted_operations + .confirmed_operations) | type == "number" and . >= 1)
    ' "${RESP_FILE}" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for exit settlement recovery status contract"
  echo "last response:"
  cat "${RESP_FILE}"
  echo
  dump_logs
  return 1
}

assert_status_timestamps_not_older() {
  local min_checked_at="$1"
  local min_report_generated_at="$2"
  local phase_label="$3"
  if ! jq -e --arg min_checked_at "${min_checked_at}" --arg min_report_generated_at "${min_report_generated_at}" '
    (.checked_at | type == "string" and length > 0) and
    (.report_generated_at | type == "string" and length > 0) and
    (.checked_at >= $min_checked_at) and
    (.report_generated_at >= $min_report_generated_at)
  ' "${RESP_FILE}" >/dev/null; then
    echo "exit settlement status timestamp progression contract failed (${phase_label})"
    echo "last response:"
    cat "${RESP_FILE}"
    echo
    dump_logs
    return 1
  fi
}

run_mode_scenario() {
  local mode="$1"
  case "${mode}" in
    http|signed-tx)
      ;;
    *)
      echo "unsupported exit settlement smoke mode: ${mode}"
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
  local exit_id="exit-settlement-live-${mode_tag}"
  local subject_id="client-settlement-live-${mode_tag}"
  local session_id="sess-exit-settlement-live-${unique_suffix}"
  local token_nonce="proof-${unique_suffix}"

  local cosmos_port
  cosmos_port="$(pick_port)"
  if [[ -z "${cosmos_port}" ]]; then
    echo "failed to allocate closed cosmos endpoint port for mode=${mode}"
    return 1
  fi
  local cosmos_endpoint="http://127.0.0.1:${cosmos_port}"

  local issuer_url=""
  local issuer_started="0"
  for _ in $(seq 1 12); do
    local issuer_port
    issuer_port="$(pick_port)"
    if [[ -z "${issuer_port}" ]]; then
      continue
    fi
    issuer_url="http://127.0.0.1:${issuer_port}"
    start_issuer_runtime "${issuer_port}"
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
    if [[ -z "${exit_port}" || -z "${exit_data_port}" ]]; then
      continue
    fi
    if [[ "${exit_port}" == "${exit_data_port}" ]]; then
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

  get_expect_status "${exit_base_url}/v1/settlement/status" "200"
  jq -e '.enabled == true' "${RESP_FILE}" >/dev/null
  local initial_checked_at
  initial_checked_at="$(jq -r '.checked_at // empty' "${RESP_FILE}")"
  local initial_report_generated_at
  initial_report_generated_at="$(jq -r '.report_generated_at // empty' "${RESP_FILE}")"
  if [[ -z "${initial_checked_at}" || -z "${initial_report_generated_at}" ]]; then
    echo "initial exit settlement status missing checked/report timestamps"
    cat "${RESP_FILE}"
    dump_logs
    return 1
  fi

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

  local issue_payload
  issue_payload="$(jq -n \
    --arg subject "${subject_id}" \
    --arg pop_pub_key "${pop_pub_key}" \
    --arg exit_id "${exit_id}" \
    '{tier:1,subject:$subject,token_type:"client_access",pop_pub_key:$pop_pub_key,exit_scope:[$exit_id]}')"
  post_expect_status "${issuer_url}/v1/token" "${issue_payload}" "200"
  local token
  token="$(jq -r '.token // empty' "${RESP_FILE}")"
  if [[ -z "${token}" ]]; then
    echo "issuer token response missing token for mode=${mode}"
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
  token_proof="$(printf '%s' "${token_proof_json}" | jq -r '.proof // empty')"
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
  jq -e '.accepted == true' "${RESP_FILE}" >/dev/null

  local close_payload
  close_payload="$(jq -n --arg session_id "${session_id}" '{session_id:$session_id}')"
  post_expect_status "${exit_base_url}/v1/path/close" "${close_payload}" "200"
  jq -e '.closed == true' "${RESP_FILE}" >/dev/null

  wait_for_backlog_status "${exit_base_url}/v1/settlement/status"
  assert_status_timestamps_not_older "${initial_checked_at}" "${initial_report_generated_at}" "outage-backlog"
  local backlog_checked_at
  backlog_checked_at="$(jq -r '.checked_at // empty' "${RESP_FILE}")"
  local backlog_report_generated_at
  backlog_report_generated_at="$(jq -r '.report_generated_at // empty' "${RESP_FILE}")"
  if [[ -z "${backlog_checked_at}" || -z "${backlog_report_generated_at}" ]]; then
    echo "backlog exit settlement status missing checked/report timestamps"
    cat "${RESP_FILE}"
    dump_logs
    return 1
  fi

  start_mock_cosmos_runtime "${cosmos_port}"
  if ! wait_for_mock_ready "${cosmos_endpoint}/health"; then
    return 1
  fi

  wait_for_recovery_status "${exit_base_url}/v1/settlement/status"
  assert_status_timestamps_not_older "${backlog_checked_at}" "${backlog_report_generated_at}" "recovery"

  stop_mock_runtime
  stop_exit_runtime
  stop_issuer_runtime
  echo "exit settlement status live smoke scenario ok mode=${mode}"
}

SETTLEMENT_STATUS_SMOKE_MODES="${EXIT_SETTLEMENT_STATUS_SMOKE_MODES:-${SETTLEMENT_STATUS_SMOKE_MODES:-http,signed-tx}}"

trimmed_mode_values=()
IFS=',' read -r -a raw_modes <<<"${SETTLEMENT_STATUS_SMOKE_MODES}"
for raw_mode in "${raw_modes[@]}"; do
  mode="${raw_mode#"${raw_mode%%[![:space:]]*}"}"
  mode="${mode%"${mode##*[![:space:]]}"}"
  if [[ -n "${mode}" ]]; then
    trimmed_mode_values+=("${mode}")
  fi
done

if [[ "${#trimmed_mode_values[@]}" -eq 0 ]]; then
  echo "no exit settlement smoke modes requested via EXIT_SETTLEMENT_STATUS_SMOKE_MODES/SETTLEMENT_STATUS_SMOKE_MODES"
  exit 1
fi

for mode in "${trimmed_mode_values[@]}"; do
  run_mode_scenario "${mode}"
done

echo "exit settlement status live smoke integration check ok (modes: ${trimmed_mode_values[*]})"
