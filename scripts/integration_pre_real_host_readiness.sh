#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 1
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.log"
FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"

cat >"$FAKE_EASY_NODE" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
CAPTURE_FILE="${FAKE_CAPTURE_FILE:?}"
MODE="${FAKE_MODE:-success}"
printf '%s\n' "$*" >>"$CAPTURE_FILE"

cmd="${1:-}"
shift || true

write_file_if_requested() {
  local flag="$1"
  local content="$2"
  shift 2
  local path=""
  local prev=""
  local arg=""
  for arg in "$@"; do
    if [[ "$prev" == "$flag" ]]; then
      path="$arg"
      break
    fi
    prev="$arg"
  done
  if [[ -n "$path" ]]; then
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$content" >"$path"
  fi
}

arg_value_or_default() {
  local flag="$1"
  local default_value="$2"
  shift 2
  local prev=""
  local arg=""
  for arg in "$@"; do
    if [[ "$prev" == "$flag" ]]; then
      printf '%s\n' "$arg"
      return 0
    fi
    prev="$arg"
  done
  printf '%s\n' "$default_value"
}

case "$cmd" in
  runtime-fix-record)
    summary_payload='{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "notes": "Runtime hygiene clean after runtime-fix",
  "runtime_fix": {
    "after_status": "OK",
    "actions_taken_count": 1,
    "actions_failed_count": 0
  },
  "manual_validation_report": {
    "status": "ok",
    "readiness_status": "NOT_READY",
    "next_action_check_id": "machine_c_vpn_smoke"
  }
}'
    if [[ "$MODE" == "runtime-fail" ]]; then
      summary_payload='{
  "version": 1,
  "status": "warn",
  "rc": 0,
  "notes": "Runtime hygiene still has warnings after runtime-fix",
  "runtime_fix": {
    "after_status": "WARN",
    "actions_taken_count": 1,
    "actions_failed_count": 0
  },
  "manual_validation_report": {
    "status": "ok",
    "readiness_status": "NOT_READY",
    "next_action_check_id": "machine_c_vpn_smoke"
  }
}'
    fi
    write_file_if_requested "--summary-json" "$summary_payload" "$@"
    echo "runtime-fix-record: status=$(printf '%s\n' "$summary_payload" | jq -r '.status')"
    echo "summary_log: /tmp/fake-runtime-fix-record.log"
    echo "summary_json: $(printf '%s\n' "$@" | awk 'prev == \"--summary-json\" {print; exit} {prev=$0}')"
    if printf '%s\n' "$*" | rg -q -- '--print-summary-json( |$)'; then
      printf '%s\n' "$summary_payload"
    fi
    ;;
  wg-only-stack-selftest-record)
    defer_no_root_value="$(arg_value_or_default "--defer-no-root" "0" "$@")"
    summary_payload='{
  "version": 1,
  "schema": {
    "id": "wg_only_stack_selftest_record_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "recorded_at_utc": "2026-03-15T12:00:00Z",
  "notes": "Linux root host rerun passed",
  "selftest": {
    "strict_beta": false,
    "base_port": 19290,
    "client_iface": "wgctest0",
    "exit_iface": "wgestest0"
  }
}'
    rc=0
    if [[ "$MODE" == "wg-schema-incompatible" ]]; then
      summary_payload='{
  "version": 1,
  "schema": {
    "id": "wg_only_stack_selftest_record_summary",
    "major": 2,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "recorded_at_utc": "2026-03-15T12:00:00Z",
  "notes": "WG-only validation passed with unsupported schema major",
  "selftest": {
    "strict_beta": false,
    "base_port": 19290,
    "client_iface": "wgctest0",
    "exit_iface": "wgestest0"
  }
}'
    fi
    if [[ "$MODE" == "wg-fail" ]]; then
      summary_payload='{
  "version": 1,
  "schema": {
    "id": "wg_only_stack_selftest_record_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 1,
  "recorded_at_utc": "2026-03-15T12:00:00Z",
  "notes": "WG-only validation failed",
  "selftest": {
    "strict_beta": false,
    "base_port": 19290,
    "client_iface": "wgctest0",
    "exit_iface": "wgestest0"
  }
}'
      rc=1
    fi
    if [[ "$MODE" == "wg-root-required" ]]; then
      if [[ "$defer_no_root_value" == "1" ]]; then
        summary_payload='{
  "version": 1,
  "schema": {
    "id": "wg_only_stack_selftest_record_summary",
    "major": 1,
    "minor": 0
  },
  "status": "skip",
  "rc": 0,
  "recorded_at_utc": "2026-03-15T12:00:00Z",
  "notes": "WG-only stack selftest deferred: requires root privileges",
  "selftest": {
    "strict_beta": false,
    "defer_no_root": true,
    "deferred_no_root": true,
    "base_port": 19290,
    "client_iface": "wgctest0",
    "exit_iface": "wgestest0"
  }
}'
        rc=0
      else
        summary_payload='{
  "version": 1,
  "schema": {
    "id": "wg_only_stack_selftest_record_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 1,
  "recorded_at_utc": "2026-03-15T12:00:00Z",
  "notes": "WG-only stack selftest failed: requires root privileges",
  "selftest": {
    "strict_beta": false,
    "defer_no_root": false,
    "deferred_no_root": false,
    "base_port": 19290,
    "client_iface": "wgctest0",
    "exit_iface": "wgestest0"
  }
}'
        rc=1
      fi
    fi
    write_file_if_requested "--summary-json" "$summary_payload" "$@"
    echo "[wg-only-stack-selftest-record] summary_json_payload:"
    printf '%s\n' "$summary_payload"
    exit "$rc"
    ;;
  manual-validation-report)
    summary_payload='{
  "report": {
    "readiness_status": "NOT_READY"
  },
  "summary": {
    "next_action_check_id": "machine_c_vpn_smoke",
    "next_action_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
  }
}'
    if [[ "$MODE" == "manual-report-invalid" ]]; then
      summary_payload='{
  "report": {
    "readiness_status": 123
  },
  "summary": {
    "next_action_check_id": "machine_c_vpn_smoke"
  }
}'
    fi
    if [[ "$MODE" == "manual-report-schema-incompatible" ]]; then
      summary_payload='{
  "schema": {
    "id": "manual_validation_readiness_summary",
    "major": 2,
    "minor": 0
  },
  "report": {
    "readiness_status": "NOT_READY"
  },
  "summary": {
    "next_action_check_id": "machine_c_vpn_smoke"
  }
}'
    fi
    write_file_if_requested "--summary-json" "$summary_payload" "$@"
    write_file_if_requested "--report-md" "# Manual Validation Report" "$@"
    echo "[manual-validation-report] summary_json_payload:"
    printf '%s\n' "$summary_payload"
    ;;
  *)
    echo "unexpected fake easy_node command: $cmd" >&2
    exit 2
    ;;
esac
FAKE
chmod +x "$FAKE_EASY_NODE"

SUCCESS_SUMMARY_JSON="$TMP_DIR/pre_real_host_readiness_success.json"
SUCCESS_REPORT_JSON="$TMP_DIR/manual_validation_readiness_summary.json"
SUCCESS_REPORT_MD="$TMP_DIR/manual_validation_readiness_report.md"

FAKE_CAPTURE_FILE="$CAPTURE" \
PRE_REAL_HOST_READINESS_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/pre_real_host_readiness.sh \
  --base-port 19290 \
  --client-iface wgctest0 \
  --exit-iface wgestest0 \
  --vpn-iface wgvpntest0 \
  --runtime-fix-prune-wg-only-dir 1 \
  --strict-beta 0 \
  --summary-json "$SUCCESS_SUMMARY_JSON" \
  --manual-validation-report-summary-json "$SUCCESS_REPORT_JSON" \
  --manual-validation-report-md "$SUCCESS_REPORT_MD" \
  --print-summary-json 1 >/tmp/integration_pre_real_host_readiness_success.log

if ! rg -q '\[pre-real-host-readiness\] machine_c_smoke_ready=true' /tmp/integration_pre_real_host_readiness_success.log; then
  echo "pre-real-host readiness success run missing ready=true line"
  cat /tmp/integration_pre_real_host_readiness_success.log
  exit 1
fi
if [[ ! -f "$SUCCESS_SUMMARY_JSON" ]]; then
  echo "pre-real-host readiness success run missing summary JSON"
  exit 1
fi
if ! jq -e --arg report_json "$SUCCESS_REPORT_JSON" --arg report_md "$SUCCESS_REPORT_MD" '
  .status == "pass"
  and .stage == "complete"
  and .machine_c_smoke_gate.ready == true
  and (.machine_c_smoke_gate.blockers | length) == 0
  and .machine_c_smoke_gate.blocker_class == "none"
  and .runtime_fix.status == "ok"
  and .runtime_fix.after_status == "OK"
  and .wg_only_stack_selftest.status == "pass"
  and .wg_only_stack_selftest.blocker_class == "none"
  and .wg_only_stack_selftest.root_required == false
  and .manual_validation_report.status == "ok"
  and .manual_validation_report.readiness_status == "NOT_READY"
  and .manual_validation_report.next_action_check_id == "machine_c_vpn_smoke"
  and .manual_validation_report.summary_json == $report_json
  and .manual_validation_report.report_md == $report_md
' "$SUCCESS_SUMMARY_JSON" >/dev/null; then
  echo "pre-real-host readiness success summary missing expected fields"
  cat "$SUCCESS_SUMMARY_JSON"
  exit 1
fi
if ! rg -q '^runtime-fix-record .*--base-port 19290 .*--prune-wg-only-dir 1 .*--record-result 1 .*--summary-json .*/pre_real_host_readiness_.*_runtime_fix\.json .*--print-summary-json 1' "$CAPTURE"; then
  echo "pre-real-host readiness success run missing runtime-fix-record forwarding"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^wg-only-stack-selftest-record .*--client-iface wgctest0 .*--exit-iface wgestest0 .*--strict-beta 0 .*--manual-validation-report 0 ' "$CAPTURE"; then
  echo "pre-real-host readiness success run missing wg-only forwarding"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^wg-only-stack-selftest-record .*--defer-no-root 0 ' "$CAPTURE"; then
  echo "pre-real-host readiness success run missing default defer-no-root forwarding"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^\[pre-real-host-readiness\] wg_only_stack_selftest_blocker_class=none$' /tmp/integration_pre_real_host_readiness_success.log; then
  echo "pre-real-host readiness success run missing blocker class console line"
  cat /tmp/integration_pre_real_host_readiness_success.log
  exit 1
fi
if ! rg -q '^manual-validation-report .*--summary-json .*/manual_validation_readiness_summary\.json .*--report-md .*/manual_validation_readiness_report\.md .*--print-summary-json 1' "$CAPTURE"; then
  echo "pre-real-host readiness success run missing manual-validation-report forwarding"
  cat "$CAPTURE"
  exit 1
fi

: >"$CAPTURE"
WG_DEFER_ROOT_SUMMARY_JSON="$TMP_DIR/pre_real_host_readiness_wg_defer_root.json"
WG_DEFER_ROOT_REPORT_JSON="$TMP_DIR/manual_validation_readiness_wg_defer_root_summary.json"
WG_DEFER_ROOT_REPORT_MD="$TMP_DIR/manual_validation_readiness_wg_defer_root_report.md"

set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_MODE="wg-root-required" \
PRE_REAL_HOST_READINESS_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/pre_real_host_readiness.sh \
  --base-port 19295 \
  --client-iface wgcrootdefer0 \
  --exit-iface wgerootdefer0 \
  --vpn-iface wgvpnrootdefer0 \
  --defer-no-root 1 \
  --summary-json "$WG_DEFER_ROOT_SUMMARY_JSON" \
  --manual-validation-report-summary-json "$WG_DEFER_ROOT_REPORT_JSON" \
  --manual-validation-report-md "$WG_DEFER_ROOT_REPORT_MD" \
  --print-summary-json 0 >/tmp/integration_pre_real_host_readiness_wg_defer_root.log 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "pre-real-host readiness should remain fail-closed when wg-only is deferred for root requirement"
  cat /tmp/integration_pre_real_host_readiness_wg_defer_root.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .stage == "wg_only_stack_selftest"
  and .machine_c_smoke_gate.ready == false
  and (.machine_c_smoke_gate.blockers | index("wg_only_stack_selftest") != null)
  and .wg_only_stack_selftest.status == "skip"
  and .wg_only_stack_selftest.root_required == true
  and .wg_only_stack_selftest.blocker_class == "root_required_deferred_blocker"
  and .wg_only_stack_selftest.deferred_root_required_blocker == true
  and .wg_only_stack_selftest.root_required_failure == false
  and (.wg_only_stack_selftest.notes | test("requires root"; "i"))
  and (.wg_only_stack_selftest.next_step_note | test("rerun with sudo"; "i"))
  and .machine_c_smoke_gate.blocker_class == "root_required_deferred_blocker"
  and .manual_validation_report.status == "ok"
' "$WG_DEFER_ROOT_SUMMARY_JSON" >/dev/null; then
  echo "pre-real-host readiness defer root-required summary missing expected fields"
  cat "$WG_DEFER_ROOT_SUMMARY_JSON"
  exit 1
fi
if ! rg -q '^wg-only-stack-selftest-record .*--defer-no-root 1 ' "$CAPTURE"; then
  echo "pre-real-host readiness defer root-required run missing defer-no-root forwarding"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^\[pre-real-host-readiness\] wg_only_stack_selftest_blocker_class=root_required_deferred_blocker$' /tmp/integration_pre_real_host_readiness_wg_defer_root.log; then
  echo "pre-real-host readiness defer root-required run missing blocker class console line"
  cat /tmp/integration_pre_real_host_readiness_wg_defer_root.log
  exit 1
fi
if ! rg -q '^\[pre-real-host-readiness\] wg_only_stack_selftest_note=WG-only stack selftest was deferred because root is required; rerun with sudo: sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpnrootdefer0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country$' /tmp/integration_pre_real_host_readiness_wg_defer_root.log; then
  echo "pre-real-host readiness defer root-required run missing deferred note console line"
  cat /tmp/integration_pre_real_host_readiness_wg_defer_root.log
  exit 1
fi
if ! rg -q '^manual-validation-report ' "$CAPTURE"; then
  echo "pre-real-host readiness defer root-required run should still refresh manual-validation-report"
  cat "$CAPTURE"
  exit 1
fi

: >"$CAPTURE"
WG_STRICT_ROOT_SUMMARY_JSON="$TMP_DIR/pre_real_host_readiness_wg_strict_root.json"
WG_STRICT_ROOT_REPORT_JSON="$TMP_DIR/manual_validation_readiness_wg_strict_root_summary.json"
WG_STRICT_ROOT_REPORT_MD="$TMP_DIR/manual_validation_readiness_wg_strict_root_report.md"

set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_MODE="wg-root-required" \
PRE_REAL_HOST_READINESS_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/pre_real_host_readiness.sh \
  --base-port 19296 \
  --client-iface wgcrootstrict0 \
  --exit-iface wgerootstrict0 \
  --vpn-iface wgvpnrootstrict0 \
  --defer-no-root 0 \
  --summary-json "$WG_STRICT_ROOT_SUMMARY_JSON" \
  --manual-validation-report-summary-json "$WG_STRICT_ROOT_REPORT_JSON" \
  --manual-validation-report-md "$WG_STRICT_ROOT_REPORT_MD" \
  --print-summary-json 0 >/tmp/integration_pre_real_host_readiness_wg_strict_root.log 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "pre-real-host readiness strict root-required run should fail"
  cat /tmp/integration_pre_real_host_readiness_wg_strict_root.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .stage == "wg_only_stack_selftest"
  and .machine_c_smoke_gate.ready == false
  and (.machine_c_smoke_gate.blockers | index("wg_only_stack_selftest") != null)
  and .wg_only_stack_selftest.status == "fail"
  and .wg_only_stack_selftest.root_required == true
  and .wg_only_stack_selftest.blocker_class == "root_required_real_failure"
  and .wg_only_stack_selftest.deferred_root_required_blocker == false
  and .wg_only_stack_selftest.root_required_failure == true
  and (.wg_only_stack_selftest.notes | test("requires root"; "i"))
  and (.wg_only_stack_selftest.next_step_note | test("rerun with sudo"; "i"))
  and .machine_c_smoke_gate.blocker_class == "root_required_real_failure"
  and .manual_validation_report.status == "ok"
' "$WG_STRICT_ROOT_SUMMARY_JSON" >/dev/null; then
  echo "pre-real-host readiness strict root-required summary missing expected fields"
  cat "$WG_STRICT_ROOT_SUMMARY_JSON"
  exit 1
fi
if ! rg -q '^wg-only-stack-selftest-record .*--defer-no-root 0 ' "$CAPTURE"; then
  echo "pre-real-host readiness strict root-required run missing defer-no-root strict forwarding"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^\[pre-real-host-readiness\] wg_only_stack_selftest_blocker_class=root_required_real_failure$' /tmp/integration_pre_real_host_readiness_wg_strict_root.log; then
  echo "pre-real-host readiness strict root-required run missing blocker class console line"
  cat /tmp/integration_pre_real_host_readiness_wg_strict_root.log
  exit 1
fi
if ! rg -q '^\[pre-real-host-readiness\] wg_only_stack_selftest_note=WG-only stack selftest requires root privileges; rerun with sudo: sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpnrootstrict0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country$' /tmp/integration_pre_real_host_readiness_wg_strict_root.log; then
  echo "pre-real-host readiness strict root-required run missing failure note console line"
  cat /tmp/integration_pre_real_host_readiness_wg_strict_root.log
  exit 1
fi
if ! rg -q '^manual-validation-report ' "$CAPTURE"; then
  echo "pre-real-host readiness strict root-required run should still refresh manual-validation-report"
  cat "$CAPTURE"
  exit 1
fi

: >"$CAPTURE"
FAIL_SUMMARY_JSON="$TMP_DIR/pre_real_host_readiness_runtime_fail.json"
FAIL_REPORT_JSON="$TMP_DIR/manual_validation_readiness_fail_summary.json"
FAIL_REPORT_MD="$TMP_DIR/manual_validation_readiness_fail_report.md"

set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_MODE="runtime-fail" \
PRE_REAL_HOST_READINESS_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/pre_real_host_readiness.sh \
  --base-port 19291 \
  --client-iface wgcfail0 \
  --exit-iface wgefail0 \
  --vpn-iface wgvpnfail0 \
  --summary-json "$FAIL_SUMMARY_JSON" \
  --manual-validation-report-summary-json "$FAIL_REPORT_JSON" \
  --manual-validation-report-md "$FAIL_REPORT_MD" \
  --print-summary-json 0 >/tmp/integration_pre_real_host_readiness_fail.log 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "pre-real-host readiness runtime-fail run should have returned non-zero"
  cat /tmp/integration_pre_real_host_readiness_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .stage == "runtime_fix"
  and .machine_c_smoke_gate.ready == false
  and (.machine_c_smoke_gate.blockers | index("runtime_hygiene") != null)
  and .runtime_fix.status == "fail"
  and .runtime_fix.after_status == "WARN"
  and .manual_validation_report.status == "ok"
' "$FAIL_SUMMARY_JSON" >/dev/null; then
  echo "pre-real-host readiness runtime-fail summary missing expected fields"
  cat "$FAIL_SUMMARY_JSON"
  exit 1
fi
if rg -q '^wg-only-stack-selftest-record ' "$CAPTURE"; then
  echo "pre-real-host readiness runtime-fail run should not invoke wg-only-stack-selftest-record"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-report ' "$CAPTURE"; then
  echo "pre-real-host readiness runtime-fail run should still refresh manual-validation-report"
  cat "$CAPTURE"
  exit 1
fi

: >"$CAPTURE"
WG_SCHEMA_FAIL_SUMMARY_JSON="$TMP_DIR/pre_real_host_readiness_wg_schema_fail.json"
WG_SCHEMA_FAIL_REPORT_JSON="$TMP_DIR/manual_validation_readiness_wg_schema_fail_summary.json"
WG_SCHEMA_FAIL_REPORT_MD="$TMP_DIR/manual_validation_readiness_wg_schema_fail_report.md"

set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_MODE="wg-schema-incompatible" \
PRE_REAL_HOST_READINESS_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/pre_real_host_readiness.sh \
  --base-port 19292 \
  --client-iface wgcschema0 \
  --exit-iface wgeschema0 \
  --vpn-iface wgvpnschema0 \
  --summary-json "$WG_SCHEMA_FAIL_SUMMARY_JSON" \
  --manual-validation-report-summary-json "$WG_SCHEMA_FAIL_REPORT_JSON" \
  --manual-validation-report-md "$WG_SCHEMA_FAIL_REPORT_MD" \
  --print-summary-json 0 >/tmp/integration_pre_real_host_readiness_wg_schema_fail.log 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "pre-real-host readiness should fail when wg-only summary schema is incompatible"
  cat /tmp/integration_pre_real_host_readiness_wg_schema_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .stage == "wg_only_stack_selftest"
  and .machine_c_smoke_gate.ready == false
  and (.machine_c_smoke_gate.blockers | index("wg_only_stack_selftest") != null)
  and .wg_only_stack_selftest.status == "fail"
  and (.wg_only_stack_selftest.notes | contains("incompatible or malformed"))
  and .manual_validation_report.status == "ok"
' "$WG_SCHEMA_FAIL_SUMMARY_JSON" >/dev/null; then
  echo "pre-real-host readiness schema-fail summary missing expected fields"
  cat "$WG_SCHEMA_FAIL_SUMMARY_JSON"
  exit 1
fi
if ! rg -q '^wg-only-stack-selftest-record .*--client-iface wgcschema0 .*--exit-iface wgeschema0 ' "$CAPTURE"; then
  echo "pre-real-host readiness schema-fail run missing wg-only forwarding"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-report ' "$CAPTURE"; then
  echo "pre-real-host readiness schema-fail run should still refresh manual-validation-report"
  cat "$CAPTURE"
  exit 1
fi

: >"$CAPTURE"
MANUAL_SCHEMA_FAIL_SUMMARY_JSON="$TMP_DIR/pre_real_host_readiness_manual_schema_fail.json"
MANUAL_SCHEMA_FAIL_REPORT_JSON="$TMP_DIR/manual_validation_readiness_manual_schema_fail_summary.json"
MANUAL_SCHEMA_FAIL_REPORT_MD="$TMP_DIR/manual_validation_readiness_manual_schema_fail_report.md"

set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_MODE="manual-report-invalid" \
PRE_REAL_HOST_READINESS_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/pre_real_host_readiness.sh \
  --base-port 19293 \
  --client-iface wgcmanual0 \
  --exit-iface wgemanual0 \
  --vpn-iface wgvpnmanual0 \
  --summary-json "$MANUAL_SCHEMA_FAIL_SUMMARY_JSON" \
  --manual-validation-report-summary-json "$MANUAL_SCHEMA_FAIL_REPORT_JSON" \
  --manual-validation-report-md "$MANUAL_SCHEMA_FAIL_REPORT_MD" \
  --print-summary-json 0 >/tmp/integration_pre_real_host_readiness_manual_schema_fail.log 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "pre-real-host readiness should fail when manual-validation-report summary payload is incompatible"
  cat /tmp/integration_pre_real_host_readiness_manual_schema_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .stage == "manual_validation_report"
  and .machine_c_smoke_gate.ready == false
  and (.machine_c_smoke_gate.blockers | index("manual_validation_report") != null)
  and .runtime_fix.status == "ok"
  and .wg_only_stack_selftest.status == "pass"
  and .manual_validation_report.status == "fail"
  and .manual_validation_report.readiness_status == ""
' "$MANUAL_SCHEMA_FAIL_SUMMARY_JSON" >/dev/null; then
  echo "pre-real-host readiness manual-validation schema-fail summary missing expected fields"
  cat "$MANUAL_SCHEMA_FAIL_SUMMARY_JSON"
  exit 1
fi
if ! rg -q '^manual-validation-report ' "$CAPTURE"; then
  echo "pre-real-host readiness manual-validation schema-fail run missing manual-validation-report call"
  cat "$CAPTURE"
  exit 1
fi

: >"$CAPTURE"
MANUAL_SCHEMA_VERSION_FAIL_SUMMARY_JSON="$TMP_DIR/pre_real_host_readiness_manual_schema_version_fail.json"
MANUAL_SCHEMA_VERSION_FAIL_REPORT_JSON="$TMP_DIR/manual_validation_readiness_manual_schema_version_fail_summary.json"
MANUAL_SCHEMA_VERSION_FAIL_REPORT_MD="$TMP_DIR/manual_validation_readiness_manual_schema_version_fail_report.md"

set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_MODE="manual-report-schema-incompatible" \
PRE_REAL_HOST_READINESS_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/pre_real_host_readiness.sh \
  --base-port 19294 \
  --client-iface wgcmanual1 \
  --exit-iface wgemanual1 \
  --vpn-iface wgvpnmanual1 \
  --summary-json "$MANUAL_SCHEMA_VERSION_FAIL_SUMMARY_JSON" \
  --manual-validation-report-summary-json "$MANUAL_SCHEMA_VERSION_FAIL_REPORT_JSON" \
  --manual-validation-report-md "$MANUAL_SCHEMA_VERSION_FAIL_REPORT_MD" \
  --print-summary-json 0 >/tmp/integration_pre_real_host_readiness_manual_schema_version_fail.log 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "pre-real-host readiness should fail when manual-validation-report schema major is incompatible"
  cat /tmp/integration_pre_real_host_readiness_manual_schema_version_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .stage == "manual_validation_report"
  and .machine_c_smoke_gate.ready == false
  and (.machine_c_smoke_gate.blockers | index("manual_validation_report") != null)
  and .runtime_fix.status == "ok"
  and .wg_only_stack_selftest.status == "pass"
  and .manual_validation_report.status == "fail"
  and .manual_validation_report.readiness_status == ""
' "$MANUAL_SCHEMA_VERSION_FAIL_SUMMARY_JSON" >/dev/null; then
  echo "pre-real-host readiness manual-validation schema-version fail summary missing expected fields"
  cat "$MANUAL_SCHEMA_VERSION_FAIL_SUMMARY_JSON"
  exit 1
fi
if ! rg -q '^manual-validation-report ' "$CAPTURE"; then
  echo "pre-real-host readiness manual-validation schema-version fail run missing manual-validation-report call"
  cat "$CAPTURE"
  exit 1
fi

echo "pre-real-host readiness integration check ok"
