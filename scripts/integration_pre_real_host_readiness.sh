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
    summary_payload='{
  "version": 1,
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
    if [[ "$MODE" == "wg-fail" ]]; then
      summary_payload='{
  "version": 1,
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
  and .runtime_fix.status == "ok"
  and .runtime_fix.after_status == "OK"
  and .wg_only_stack_selftest.status == "pass"
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
if ! rg -q '^manual-validation-report .*--summary-json .*/manual_validation_readiness_summary\.json .*--report-md .*/manual_validation_readiness_report\.md .*--print-summary-json 1' "$CAPTURE"; then
  echo "pre-real-host readiness success run missing manual-validation-report forwarding"
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

echo "pre-real-host readiness integration check ok"
