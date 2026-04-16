#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp rg chmod; do
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
  wg-only-stack-selftest)
    if [[ "${FAKE_WG_ONLY_SELFTEST_FAIL:-0}" == "1" ]]; then
      echo "wg-only selftest failed"
      exit 1
    fi
    echo "wg-only selftest passed"
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
    report_payload='{"version":1,"summary":{"next_action_check_id":"machine_c_vpn_smoke"},"report":{"readiness_status":"NOT_READY"}}'
    if [[ "${FAKE_MANUAL_REPORT_INVALID_SCHEMA:-0}" == "1" ]]; then
      report_payload='{"version":1,"schema":{"id":"manual_validation_readiness_summary","major":2,"minor":0},"summary":{"next_action_check_id":"machine_c_vpn_smoke"},"report":{"readiness_status":"NOT_READY"}}'
    fi
    printf '%s\n' "$report_payload" >"$summary_json"
    printf '# Manual Validation Readiness Report\n' >"$report_md"
    echo "[manual-validation-report] readiness_status=NOT_READY total=3 pass=1 warn=1 fail=1 pending=0"
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

echo "[wg-only-stack-selftest-record] success path"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
WG_ONLY_STACK_SELFTEST_RECORD_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/wg_only_stack_selftest_record.sh \
  --strict-beta 1 \
  --base-port 19290 \
  --client-iface wgctest0 \
  --exit-iface wgestest0 \
  --print-summary-json 1 >/tmp/integration_wg_only_stack_selftest_record_ok.log 2>&1

if ! rg -q 'wg-only-stack-selftest-record: status=pass' /tmp/integration_wg_only_stack_selftest_record_ok.log; then
  echo "expected pass status for wg-only-stack-selftest-record success path"
  cat /tmp/integration_wg_only_stack_selftest_record_ok.log
  exit 1
fi
if ! rg -q '^wg-only-stack-selftest --strict-beta 1 --base-port 19290 --client-iface wgctest0 --exit-iface wgestest0$' "$CAPTURE"; then
  echo "expected wg-only-stack-selftest forwarding missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-report --base-port 19290 --client-iface wgctest0 --exit-iface wgestest0 --overlay-check-id wg_only_stack_selftest --overlay-status pass ' "$CAPTURE"; then
  echo "expected manual-validation-report overlay call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id wg_only_stack_selftest --status pass ' "$CAPTURE"; then
  echo "expected manual-validation-record pass call missing"
  cat "$CAPTURE"
  exit 1
fi

summary_json_path="$(sed -n 's/^summary_json: //p' /tmp/integration_wg_only_stack_selftest_record_ok.log | tail -n 1)"
if [[ -z "$summary_json_path" || ! -f "$summary_json_path" ]]; then
  echo "expected success summary JSON missing"
  cat /tmp/integration_wg_only_stack_selftest_record_ok.log
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .schema.id == "wg_only_stack_selftest_record_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and .rc == 0
  and .selftest.strict_beta == true
  and .selftest.base_port == 19290
  and .selftest.client_iface == "wgctest0"
  and .selftest.exit_iface == "wgestest0"
  and .manual_validation_report.status == "ok"
  and .manual_validation_report.readiness_status == "NOT_READY"
  and .manual_validation_report.next_action_check_id == "machine_c_vpn_smoke"
' "$summary_json_path" >/dev/null; then
  echo "success summary JSON missing expected fields"
  cat "$summary_json_path"
  exit 1
fi

: >"$CAPTURE"

echo "[wg-only-stack-selftest-record] defer-no-root skip path"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
WG_ONLY_STACK_SELFTEST_RECORD_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
WG_ONLY_STACK_SELFTEST_RECORD_EFFECTIVE_UID_OVERRIDE="1000" \
./scripts/wg_only_stack_selftest_record.sh \
  --defer-no-root 1 \
  --strict-beta 1 \
  --base-port 19293 \
  --client-iface wgcnoroot0 \
  --exit-iface wgenoroot0 \
  --print-summary-json 1 >/tmp/integration_wg_only_stack_selftest_record_noroot.log 2>&1

if ! rg -q 'wg-only-stack-selftest-record: status=skip' /tmp/integration_wg_only_stack_selftest_record_noroot.log; then
  echo "expected skip status in defer-no-root path"
  cat /tmp/integration_wg_only_stack_selftest_record_noroot.log
  exit 1
fi
if rg -q '^wg-only-stack-selftest ' "$CAPTURE"; then
  echo "wg-only selftest must not run in defer-no-root path"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-report --base-port 19293 --client-iface wgcnoroot0 --exit-iface wgenoroot0 --overlay-check-id wg_only_stack_selftest --overlay-status skip ' "$CAPTURE"; then
  echo "expected manual-validation-report skip overlay call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id wg_only_stack_selftest --status skip ' "$CAPTURE"; then
  echo "expected manual-validation-record skip call missing"
  cat "$CAPTURE"
  exit 1
fi

no_root_summary_json_path="$(sed -n 's/^summary_json: //p' /tmp/integration_wg_only_stack_selftest_record_noroot.log | tail -n 1)"
if [[ -z "$no_root_summary_json_path" || ! -f "$no_root_summary_json_path" ]]; then
  echo "expected defer-no-root summary JSON missing"
  cat /tmp/integration_wg_only_stack_selftest_record_noroot.log
  exit 1
fi
if ! jq -e '
  .status == "skip"
  and .rc == 0
  and .selftest.defer_no_root == true
  and .selftest.effective_uid == 1000
  and .selftest.deferred_no_root == true
  and .manual_validation_report.status == "ok"
' "$no_root_summary_json_path" >/dev/null; then
  echo "defer-no-root summary JSON missing expected fields"
  cat "$no_root_summary_json_path"
  exit 1
fi

: >"$CAPTURE"

echo "[wg-only-stack-selftest-record] manual validation malformed payload path"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
FAKE_MANUAL_REPORT_INVALID_SCHEMA="1" \
WG_ONLY_STACK_SELFTEST_RECORD_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/wg_only_stack_selftest_record.sh \
  --strict-beta 1 \
  --base-port 19292 \
  --client-iface wgcbad0 \
  --exit-iface wgebad0 \
  --print-summary-json 1 >/tmp/integration_wg_only_stack_selftest_record_manual_invalid.log 2>&1

if ! rg -q 'wg-only-stack-selftest-record: status=pass' /tmp/integration_wg_only_stack_selftest_record_manual_invalid.log; then
  echo "expected pass status in manual-validation malformed payload path"
  cat /tmp/integration_wg_only_stack_selftest_record_manual_invalid.log
  exit 1
fi
manual_invalid_summary_json_path="$(sed -n 's/^summary_json: //p' /tmp/integration_wg_only_stack_selftest_record_manual_invalid.log | tail -n 1)"
if [[ -z "$manual_invalid_summary_json_path" || ! -f "$manual_invalid_summary_json_path" ]]; then
  echo "expected malformed-payload summary JSON missing"
  cat /tmp/integration_wg_only_stack_selftest_record_manual_invalid.log
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .manual_validation_report.status == "fail"
  and .manual_validation_report.readiness_status == ""
  and .manual_validation_report.next_action_check_id == ""
' "$manual_invalid_summary_json_path" >/dev/null; then
  echo "malformed manual-validation payload path did not fail-close manual report status"
  cat "$manual_invalid_summary_json_path"
  exit 1
fi
if ! rg -q '^manual-validation-report --base-port 19292 --client-iface wgcbad0 --exit-iface wgebad0 --overlay-check-id wg_only_stack_selftest --overlay-status pass ' "$CAPTURE"; then
  echo "expected manual-validation-report call missing in malformed payload path"
  cat "$CAPTURE"
  exit 1
fi

: >"$CAPTURE"

echo "[wg-only-stack-selftest-record] failure path"
if env \
  FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
  FAKE_WG_ONLY_SELFTEST_FAIL="1" \
  WG_ONLY_STACK_SELFTEST_RECORD_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
  ./scripts/wg_only_stack_selftest_record.sh \
    --strict-beta 0 \
    --base-port 19291 \
    --client-iface wgcfail0 \
    --exit-iface wgesfail0 >/tmp/integration_wg_only_stack_selftest_record_fail.log 2>&1; then
  echo "expected failure path to return non-zero"
  cat /tmp/integration_wg_only_stack_selftest_record_fail.log
  exit 1
fi

if ! rg -q 'wg-only-stack-selftest-record: status=fail' /tmp/integration_wg_only_stack_selftest_record_fail.log; then
  echo "expected fail status for wg-only-stack-selftest-record failure path"
  cat /tmp/integration_wg_only_stack_selftest_record_fail.log
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id wg_only_stack_selftest --status fail ' "$CAPTURE"; then
  echo "expected manual-validation-record fail call missing"
  cat "$CAPTURE"
  exit 1
fi

fail_summary_json_path="$(sed -n 's/^summary_json: //p' /tmp/integration_wg_only_stack_selftest_record_fail.log | tail -n 1)"
if [[ -z "$fail_summary_json_path" || ! -f "$fail_summary_json_path" ]]; then
  echo "expected failure summary JSON missing"
  cat /tmp/integration_wg_only_stack_selftest_record_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .schema.id == "wg_only_stack_selftest_record_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and .rc == 1
  and .selftest.strict_beta == false
  and .selftest.base_port == 19291
  and .manual_validation_report.status == "ok"
' "$fail_summary_json_path" >/dev/null; then
  echo "failure summary JSON missing expected fields"
  cat "$fail_summary_json_path"
  exit 1
fi

echo "wg-only stack selftest record integration ok"
