#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp rg chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/easy_node_calls.log"
FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"

cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_EASY_CAPTURE_FILE:?}"
cmd="${1:-}"
shift || true
case "$cmd" in
  real-wg-privileged-matrix)
    if [[ "${FAKE_REAL_WG_MATRIX_SLEEP_SEC:-0}" =~ ^[0-9]+$ ]] && [[ "${FAKE_REAL_WG_MATRIX_SLEEP_SEC:-0}" -gt 0 ]]; then
      sleep "${FAKE_REAL_WG_MATRIX_SLEEP_SEC}"
    fi
    if [[ -n "${FAKE_REAL_WG_MATRIX_OUTPUT+x}" || -n "${FAKE_REAL_WG_MATRIX_RC:-}" ]]; then
      if [[ -n "${FAKE_REAL_WG_MATRIX_OUTPUT+x}" ]]; then
        printf '%s\n' "$FAKE_REAL_WG_MATRIX_OUTPUT"
      fi
      exit "${FAKE_REAL_WG_MATRIX_RC:-0}"
    fi
    if [[ "${FAKE_SECRET_OUTPUT:-0}" == "1" ]]; then
      echo "TOKEN=secret-auth-123"
      echo "Authorization: Bearer secret-bearer-789"
      echo "ADMIN_TOKEN=secret-admin-000"
      echo "subject inv-secret-leak"
    fi
    if [[ "${FAKE_REAL_WG_MATRIX_FAIL:-0}" == "1" ]]; then
      echo "real wg privileged matrix integration failed"
      exit 1
    fi
    echo "real wg privileged matrix integration check ok"
    exit 0
    ;;
  manual-validation-report)
    summary_json=""
    report_md=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --summary-json)
          summary_json="${2:-}"
          shift 2
          ;;
        --report-md)
          report_md="${2:-}"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
    cat >"$summary_json" <<'EOF_REPORT_JSON'
{"report":{"readiness_status":"NOT_READY"},"summary":{"next_action_check_id":"machine_c_vpn_smoke"}}
EOF_REPORT_JSON
    printf '# Manual Validation Readiness Report\n' >"$report_md"
    echo "[manual-validation-report] readiness_status=NOT_READY total=5 pass=2 warn=0 fail=0 pending=3"
    echo "[manual-validation-report] summary_json=$summary_json"
    echo "[manual-validation-report] report_md=$report_md"
    echo "[manual-validation-report] next_action_check_id=machine_c_vpn_smoke"
    echo "[manual-validation-report] summary_json_payload:"
    cat "$summary_json"
    exit 0
    ;;
  manual-validation-record)
    echo "manual-validation-record ok"
    exit 0
    ;;
esac

echo "unexpected command: $cmd" >&2
exit 1
EOF_FAKE_EASY
chmod +x "$FAKE_EASY_NODE"

echo "[real-wg-privileged-matrix-record] success path"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
FAKE_SECRET_OUTPUT="1" \
REAL_WG_PRIVILEGED_MATRIX_RECORD_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/real_wg_privileged_matrix_record.sh \
  --print-summary-json 1 >/tmp/integration_real_wg_privileged_matrix_record_ok.log 2>&1

if ! rg -q 'real-wg-privileged-matrix-record: status=pass' /tmp/integration_real_wg_privileged_matrix_record_ok.log; then
  echo "expected pass status for real-wg-privileged-matrix-record success path"
  cat /tmp/integration_real_wg_privileged_matrix_record_ok.log
  exit 1
fi
if ! rg -q '^real-wg-privileged-matrix$' "$CAPTURE"; then
  echo "expected real-wg-privileged-matrix forwarding missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id real_wg_privileged_matrix --status pass ' "$CAPTURE"; then
  echo "expected manual-validation-record pass call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-report --overlay-check-id real_wg_privileged_matrix --overlay-status pass ' "$CAPTURE"; then
  echo "expected manual-validation-report overlay call missing"
  cat "$CAPTURE"
  exit 1
fi

summary_json_path="$(sed -n 's/^summary_json: //p' /tmp/integration_real_wg_privileged_matrix_record_ok.log | tail -n 1)"
if [[ -z "$summary_json_path" || ! -f "$summary_json_path" ]]; then
  echo "expected success summary JSON missing"
  cat /tmp/integration_real_wg_privileged_matrix_record_ok.log
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .matrix.status == "pass"
  and .matrix.rc == 0
  and .matrix.blocker == null
  and .blocker == null
  and .matrix.timed_out == false
  and .matrix.timeout_sec == 900
  and .manual_validation_report.status == "ok"
  and .manual_validation_report.readiness_status == "NOT_READY"
  and .manual_validation_report.next_action_check_id == "machine_c_vpn_smoke"
' "$summary_json_path" >/dev/null; then
  echo "success summary JSON missing expected fields"
  cat "$summary_json_path"
  exit 1
fi
summary_log_path="$(jq -r '.artifacts.summary_log // ""' "$summary_json_path")"
if [[ -z "$summary_log_path" || ! -f "$summary_log_path" ]]; then
  echo "expected success summary log missing"
  cat "$summary_json_path"
  exit 1
fi
if rg -q 'secret-auth-123|secret-bearer-789|secret-admin-000|inv-secret-leak' "$summary_log_path"; then
  echo "real-wg-privileged-matrix-record summary log leaked sensitive output"
  cat "$summary_log_path"
  exit 1
fi
if ! rg -q '\[REDACTED\]|\[REDACTED_INVITE\]' "$summary_log_path"; then
  echo "real-wg-privileged-matrix-record summary log missing redaction markers"
  cat "$summary_log_path"
  exit 1
fi

: >"$CAPTURE"

echo "[real-wg-privileged-matrix-record] failure path"
if env \
  FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
  FAKE_REAL_WG_MATRIX_FAIL="1" \
  REAL_WG_PRIVILEGED_MATRIX_RECORD_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
  ./scripts/real_wg_privileged_matrix_record.sh >/tmp/integration_real_wg_privileged_matrix_record_fail.log 2>&1; then
  echo "expected failure path to return non-zero"
  cat /tmp/integration_real_wg_privileged_matrix_record_fail.log
  exit 1
fi

if ! rg -q 'real-wg-privileged-matrix-record: status=fail' /tmp/integration_real_wg_privileged_matrix_record_fail.log; then
  echo "expected fail status for real-wg-privileged-matrix-record failure path"
  cat /tmp/integration_real_wg_privileged_matrix_record_fail.log
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id real_wg_privileged_matrix --status fail ' "$CAPTURE"; then
  echo "expected manual-validation-record fail call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-report --overlay-check-id real_wg_privileged_matrix --overlay-status fail ' "$CAPTURE"; then
  echo "expected manual-validation-report fail overlay call missing"
  cat "$CAPTURE"
  exit 1
fi

fail_summary_json_path="$(sed -n 's/^summary_json: //p' /tmp/integration_real_wg_privileged_matrix_record_fail.log | tail -n 1)"
if [[ -z "$fail_summary_json_path" || ! -f "$fail_summary_json_path" ]]; then
  echo "expected failure summary JSON missing"
  cat /tmp/integration_real_wg_privileged_matrix_record_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .matrix.status == "fail"
  and .matrix.rc == 1
  and .matrix.blocker.code == "unknown"
  and .blocker.code == "unknown"
  and .matrix.timed_out == false
  and .manual_validation_report.status == "ok"
' "$fail_summary_json_path" >/dev/null; then
  echo "failure summary JSON missing expected fields"
  cat "$fail_summary_json_path"
  exit 1
fi

run_blocker_case() {
  local name="$1"
  local output="$2"
  local rc="$3"
  local jq_filter="$4"
  local log_file="/tmp/integration_real_wg_privileged_matrix_record_${name}.log"
  local summary_path=""

  : >"$CAPTURE"
  echo "[real-wg-privileged-matrix-record] blocker case: $name"
  if env \
    FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
    FAKE_REAL_WG_MATRIX_OUTPUT="$output" \
    FAKE_REAL_WG_MATRIX_RC="$rc" \
    REAL_WG_PRIVILEGED_MATRIX_RECORD_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
    ./scripts/real_wg_privileged_matrix_record.sh >"$log_file" 2>&1; then
    echo "expected blocker case $name to return non-zero"
    cat "$log_file"
    exit 1
  fi

  summary_path="$(sed -n 's/^summary_json: //p' "$log_file" | tail -n 1)"
  if [[ -z "$summary_path" || ! -f "$summary_path" ]]; then
    echo "expected blocker summary JSON missing for $name"
    cat "$log_file"
    exit 1
  fi
  if ! jq -e "$jq_filter" "$summary_path" >/dev/null; then
    echo "blocker summary JSON mismatch for $name"
    cat "$summary_path"
    exit 1
  fi
}

run_blocker_case \
  "root_required" \
  "run as root: sudo ./scripts/integration_real_wg_privileged_matrix.sh" \
  "2" \
  '.matrix.blocker.code == "root_required" and .matrix.blocker.category == "privilege" and .blocker.code == "root_required" and (.notes | test("root"))'

run_blocker_case \
  "missing_wg" \
  "missing required command: wg" \
  "2" \
  '.matrix.blocker.code == "missing_command" and .matrix.blocker.category == "tooling" and .matrix.blocker.details.command == "wg" and .blocker.code == "missing_command"'

run_blocker_case \
  "missing_ip" \
  "missing required command: ip" \
  "2" \
  '.matrix.blocker.code == "missing_command" and .matrix.blocker.details.command == "ip" and .blocker.code == "missing_command"'

run_blocker_case \
  "kernel_missing" \
  "failed to create wireguard interface wgcint0 (is wireguard kernel support available?)" \
  "2" \
  '.matrix.blocker.code == "kernel_missing" and .matrix.blocker.category == "kernel" and .blocker.code == "kernel_missing"'

run_blocker_case \
  "port_occupied" \
  "preflight failed: EXIT_WG_PORT port 51982/udp already in use" \
  "1" \
  '.matrix.blocker.code == "port_occupied" and .matrix.blocker.category == "network" and .matrix.blocker.details.label == "EXIT_WG_PORT" and .matrix.blocker.details.port == 51982 and .matrix.blocker.details.proto == "udp" and .blocker.code == "port_occupied"'

if command -v timeout >/dev/null 2>&1; then
  : >"$CAPTURE"
  echo "[real-wg-privileged-matrix-record] timeout path"
  if env \
    FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
    FAKE_REAL_WG_MATRIX_SLEEP_SEC="2" \
    REAL_WG_PRIVILEGED_MATRIX_RECORD_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
    ./scripts/real_wg_privileged_matrix_record.sh \
      --matrix-timeout-sec 1 >/tmp/integration_real_wg_privileged_matrix_record_timeout.log 2>&1; then
    echo "expected timeout path to return non-zero"
    cat /tmp/integration_real_wg_privileged_matrix_record_timeout.log
    exit 1
  fi

  if ! rg -q 'real-wg-privileged-matrix-record: status=fail' /tmp/integration_real_wg_privileged_matrix_record_timeout.log; then
    echo "expected fail status for timeout path"
    cat /tmp/integration_real_wg_privileged_matrix_record_timeout.log
    exit 1
  fi
  if ! rg -q '^manual-validation-record --check-id real_wg_privileged_matrix --status fail ' "$CAPTURE"; then
    echo "expected manual-validation-record fail call missing for timeout path"
    cat "$CAPTURE"
    exit 1
  fi

  timeout_summary_json_path="$(sed -n 's/^summary_json: //p' /tmp/integration_real_wg_privileged_matrix_record_timeout.log | tail -n 1)"
  if [[ -z "$timeout_summary_json_path" || ! -f "$timeout_summary_json_path" ]]; then
    echo "expected timeout summary JSON missing"
    cat /tmp/integration_real_wg_privileged_matrix_record_timeout.log
    exit 1
  fi
  if ! jq -e '
    .status == "fail"
    and .rc == 124
    and .notes == "Linux root real-WG privileged matrix timed out after 1s"
    and .matrix.status == "fail"
    and .matrix.rc == 124
    and .matrix.blocker.code == "timeout"
    and .matrix.blocker.category == "timeout"
    and .blocker.code == "timeout"
    and .matrix.timed_out == true
    and .matrix.timeout_sec == 1
    and .manual_validation_report.status == "ok"
  ' "$timeout_summary_json_path" >/dev/null; then
    echo "timeout summary JSON missing expected fields"
    cat "$timeout_summary_json_path"
    exit 1
  fi
fi

echo "real wg privileged matrix record integration ok"
