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
LOG_FILE=""
RESP_FILE=""
MOCK_LOG_FILE=""
MOCK_GO_FILE=""
ISSUER_PID=""
MOCK_PID=""

configure_scenario_paths() {
  local mode="$1"
  local sanitized_mode
  sanitized_mode="$(printf '%s' "${mode}" | tr -c '[:alnum:]_-' '_')"
  LOG_FILE="$TMP_DIR/issuer_${sanitized_mode}.log"
  RESP_FILE="$TMP_DIR/response_${sanitized_mode}.json"
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
  local submit_mode="$3"
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
    COSMOS_SETTLEMENT_SUBMIT_MODE="${submit_mode}" \
    COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID="tdpn-settlement-smoke-1" \
    COSMOS_SETTLEMENT_SIGNED_TX_SIGNER="issuer-settlement-smoke-signer" \
    COSMOS_SETTLEMENT_SIGNED_TX_SECRET="issuer-settlement-smoke-secret" \
    COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID="issuer-settlement-smoke-key" \
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

wait_for_backlog_status() {
  local url="$1"
  for _ in $(seq 1 80); do
    get_expect_status "${url}" "200" "X-Admin-Token" "${ADMIN_TOKEN}"
    if jq -e '
      .status == "backlog" and
      (
        ((((.last_error // "") | length) > 0) and .stale == true) or
        ((((.last_error // "") | length) == 0) and .stale == false)
      ) and
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

dump_logs() {
  echo "issuer log:"
  cat "${LOG_FILE}"
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
			_, _ = w.Write([]byte(`{"tx_response":{"code":0,"txhash":"MOCK_SETTLEMENT_TX"}}`))
		case strings.HasPrefix(r.URL.Path, "/x/"):
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
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

wait_for_recovery_status() {
  local url="$1"
  for _ in $(seq 1 120); do
    if [[ -n "${ISSUER_PID}" ]] && ! kill -0 "${ISSUER_PID}" 2>/dev/null; then
      echo "issuer exited before settlement status recovery became ready"
      dump_logs
      return 1
    fi
    get_expect_status "${url}" "200" "X-Admin-Token" "${ADMIN_TOKEN}"
    if jq -e '
      .status == "ok" and
      .stale == false and
      ((.last_error // "") | length == 0) and
      (.pending_adapter_operations | type == "number" and . == 0) and
      (.failed_operations | type == "number" and . == 0)
    ' "${RESP_FILE}" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done

  echo "timed out waiting for settlement recovery status contract"
  echo "last response:"
  cat "${RESP_FILE}"
  echo
  dump_logs
  return 1
}

ADMIN_TOKEN="issuer-admin-settlement-live-012345"
SPONSOR_TOKEN="issuer-sponsor-settlement-live-012345"
SETTLEMENT_STATUS_SMOKE_MODES="${SETTLEMENT_STATUS_SMOKE_MODES:-http,signed-tx}"

run_mode_scenario() {
  local mode="$1"
  case "${mode}" in
    http|signed-tx)
      ;;
    *)
      echo "unsupported settlement smoke mode: ${mode}"
      return 1
      ;;
  esac

  configure_scenario_paths "${mode}"
  : >"${RESP_FILE}"
  stop_mock_runtime
  stop_issuer_runtime

  local mode_tag
  mode_tag="$(printf '%s' "${mode}" | tr -c '[:alnum:]' '-')"
  local unique_suffix
  unique_suffix="${RANDOM}-$(date +%s)-${mode_tag}"
  local subject_id="client-settlement-live-${mode_tag}"
  local sponsor_id="dapp-settlement-live-${mode_tag}"
  local reservation_id="sres-settlement-live-${unique_suffix}"
  local session_id="sess-settlement-live-${unique_suffix}"
  local evidence_id="ev-settlement-live-${unique_suffix}"
  local evidence_id_invalid="ev-settlement-live-invalid-${unique_suffix}"
  local evidence_id_missing="ev-settlement-live-missing-${unique_suffix}"

  local cosmos_port
  cosmos_port="$(pick_port)"
  if [[ -z "${cosmos_port}" ]]; then
    echo "failed to allocate closed cosmos endpoint port for mode=${mode}"
    return 1
  fi
  local cosmos_endpoint="http://127.0.0.1:${cosmos_port}"

  local started="0"
  local base_url=""
  for _ in $(seq 1 12); do
    local port
    port="$(pick_port)"
    if [[ -z "${port}" ]]; then
      continue
    fi
    base_url="http://127.0.0.1:${port}"
    start_issuer_runtime "${port}" "${cosmos_endpoint}" "${mode}"
    if wait_for_health_ready "${base_url}/v1/health"; then
      started="1"
      break
    fi
    stop_issuer_runtime
    if ! grep -Fq "address already in use" "${LOG_FILE}"; then
      echo "issuer failed to start for non-bind-conflict reason (mode=${mode})"
      cat "${LOG_FILE}"
      return 1
    fi
  done
  if [[ "${started}" != "1" ]]; then
    echo "failed to start issuer settlement status live-smoke runtime after bind-conflict retries (mode=${mode})"
    cat "${LOG_FILE}"
    return 1
  fi

  # Negative auth check: admin endpoint must reject unauthenticated callers.
  get_expect_status "${base_url}/v1/settlement/status" "401"

  local reserve_payload
  reserve_payload="$(jq -n \
    --arg reservation_id "${reservation_id}" \
    --arg sponsor_id "${sponsor_id}" \
    --arg subject "${subject_id}" \
    --arg session_id "${session_id}" \
    '{reservation_id:$reservation_id,sponsor_id:$sponsor_id,subject:$subject,session_id:$session_id,amount_micros:150000,currency:"TDPNC"}')"
  post_expect_status "${base_url}/v1/sponsor/reserve" "${reserve_payload}" "200" "X-Sponsor-Token" "${SPONSOR_TOKEN}"
  assert_response_jq "mode=${mode} sponsor reserve accepted while cosmos endpoint is down" --arg reservation_id "${reservation_id}" --arg sponsor_id "${sponsor_id}" --arg subject "${subject_id}" --arg session_id "${session_id}" '
    . as $r |
    $r.accepted == true and
    $r.reservation_id == $reservation_id and
    $r.sponsor_id == $sponsor_id and
    $r.subject == $subject and
    $r.session_id == $session_id and
    $r.amount_micros == 150000 and
    $r.currency == "TDPNC" and
    ($r.status | type == "string" and length > 0) and
    ($r.created_at | type == "number" and . > 0) and
    ($r.expires_at | type == "number" and . > 0) and
    ($r.expires_at > $r.created_at)
  '

  local slash_payload
  slash_payload="$(jq -n \
    --arg evidence_id "${evidence_id}" \
    --arg subject "${subject_id}" \
    --arg session_id "${session_id}" \
    '{evidence_id:$evidence_id,subject:$subject,session_id:$session_id,violation_type:"double-sign",evidence_ref:"sha256:6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",slash_micros:42000,currency:"TDPNC",reason:"live-smoke objective evidence"}')"
  post_expect_status "${base_url}/v1/admin/slash/evidence" "${slash_payload}" "200" "X-Admin-Token" "${ADMIN_TOKEN}"
  jq -e --arg evidence_id "${evidence_id}" '
    .accepted == true and
    .evidence_id == $evidence_id and
    (.status | type == "string" and length > 0)
  ' "${RESP_FILE}" >/dev/null

  local invalid_violation_payload
  invalid_violation_payload="$(jq -n \
    --arg evidence_id "${evidence_id_invalid}" \
    --arg subject "${subject_id}" \
    --arg session_id "${session_id}" \
    '{evidence_id:$evidence_id,subject:$subject,session_id:$session_id,violation_type:"manual-review-only",evidence_ref:"sha256:6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",slash_micros:42000,currency:"TDPNC",reason:"live-smoke invalid violation type check"}')"
  post_expect_status "${base_url}/v1/admin/slash/evidence" "${invalid_violation_payload}" "400" "X-Admin-Token" "${ADMIN_TOKEN}"

  local missing_required_payload
  missing_required_payload="$(jq -n \
    --arg evidence_id "${evidence_id_missing}" \
    --arg subject "${subject_id}" \
    --arg session_id "${session_id}" \
    '{evidence_id:$evidence_id,subject:$subject,session_id:$session_id,violation_type:"double-sign",slash_micros:42000,currency:"TDPNC",reason:"live-smoke missing required field check"}')"
  post_expect_status "${base_url}/v1/admin/slash/evidence" "${missing_required_payload}" "400" "X-Admin-Token" "${ADMIN_TOKEN}"

  wait_for_backlog_status "${base_url}/v1/settlement/status"

  local pop_pub_key
  pop_pub_key="$(go run ./cmd/tokenpop gen --show-private-key | jq -r '.public_key // empty')"
  if [[ -z "${pop_pub_key}" || "${pop_pub_key}" == "null" ]]; then
    echo "failed to generate pop public key for sponsor token outage check (mode=${mode})"
    dump_logs
    return 1
  fi

  local sponsor_token_payload
  sponsor_token_payload="$(jq -n \
    --arg subject "${subject_id}" \
    --arg pop_pub_key "${pop_pub_key}" \
    --arg reservation_id "${reservation_id}" \
    --arg sponsor_id "${sponsor_id}" \
    --arg session_id "${session_id}" \
    '{tier:1,subject:$subject,token_type:"client_access",pop_pub_key:$pop_pub_key,payment_proof:{reservation_id:$reservation_id,sponsor_id:$sponsor_id,subject:$subject,session_id:$session_id}}')"

  echo "[issuer-settlement-status-live-smoke] sponsor payment-proof happy path during outage mode=${mode}"
  post_expect_status "${base_url}/v1/sponsor/token" "${sponsor_token_payload}" "200" "X-Sponsor-Token" "${SPONSOR_TOKEN}"
  assert_response_jq "mode=${mode} sponsor token issuance remains available while cosmos endpoint is down" '
    (.token | type == "string" and length > 0) and
    (.expires | type == "number" and . > 0) and
    (.jti | type == "string" and length > 0)
  '

  get_expect_status "${base_url}/v1/sponsor/status?reservation_id=${reservation_id}" "200" "X-Sponsor-Token" "${SPONSOR_TOKEN}"
  assert_response_jq "mode=${mode} sponsor reservation consumed metadata while cosmos endpoint is down" --arg reservation_id "${reservation_id}" --arg sponsor_id "${sponsor_id}" --arg subject "${subject_id}" --arg session_id "${session_id}" '
    . as $r |
    $r.accepted == true and
    $r.reservation_id == $reservation_id and
    $r.sponsor_id == $sponsor_id and
    $r.subject == $subject and
    $r.session_id == $session_id and
    $r.amount_micros == 150000 and
    $r.currency == "TDPNC" and
    ($r.status | type == "string" and length > 0) and
    ($r.created_at | type == "number" and . > 0) and
    ($r.expires_at | type == "number" and . > 0) and
    ($r.consumed_at | type == "number" and . >= 0) and
    ($r.expires_at > $r.created_at) and
    ($r.consumed_at >= $r.created_at)
  '

  start_mock_cosmos_runtime "${cosmos_port}"
  if ! wait_for_mock_ready "${cosmos_endpoint}/health"; then
    return 1
  fi

  wait_for_recovery_status "${base_url}/v1/settlement/status"
  stop_mock_runtime
  stop_issuer_runtime
  echo "issuer settlement status live smoke scenario ok mode=${mode}"
}

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
  echo "no settlement smoke modes requested via SETTLEMENT_STATUS_SMOKE_MODES"
  exit 1
fi

for mode in "${trimmed_mode_values[@]}"; do
  run_mode_scenario "${mode}"
done

echo "issuer settlement status live smoke integration check ok (modes: ${trimmed_mode_values[*]})"
