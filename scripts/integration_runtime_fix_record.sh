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
  runtime-fix)
    summary_json=""
    report_md=""
    report_log=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --manual-validation-report-summary-json)
          summary_json="${2:-}"
          shift 2
          ;;
        --manual-validation-report-md)
          report_md="${2:-}"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ -z "$summary_json" ]]; then
      summary_json=".easy-node-logs/manual_validation_readiness_summary.json"
    fi
    if [[ -z "$report_md" ]]; then
      report_md=".easy-node-logs/manual_validation_readiness_report.md"
    fi
    summary_json="${summary_json/#./${PRIVACYNODE_ROOT:?}}"
    report_md="${report_md/#./${PRIVACYNODE_ROOT:?}}"
    report_log="${report_md%.md}.log"
    mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
    printf '%s\n' '{"report":{"readiness_status":"NOT_READY"},"summary":{"next_action_check_id":"machine_c_vpn_smoke"}}' >"$summary_json"
    printf '# fake readiness report\n' >"$report_md"
    printf 'fake report log\n' >"$report_log"
    if [[ "${FAKE_RUNTIME_FIX_FAIL:-0}" == "1" ]]; then
      cat <<EOF_RUNTIME_FAIL
[runtime-fix] before_status=WARN findings=1
[runtime-fix] after_status=FAIL findings=1 actions_taken=0 actions_skipped=0 actions_failed=1
[runtime-fix] manual_validation_report_status=ok
[runtime-fix] manual_validation_report_summary_json=$summary_json
[runtime-fix] manual_validation_report_md=$report_md
[runtime-fix] manual_validation_report_log=$report_log
[runtime-fix] summary_json_payload:
{
  "doctor": {
    "before": {"status": "WARN", "summary": {"findings_total": 1}},
    "after": {"status": "FAIL", "summary": {"findings_total": 1}}
  },
  "manual_validation_report": {
    "status": "ok",
    "summary_json": "$summary_json",
    "report_md": "$report_md",
    "log": "$report_log",
    "summary": {
      "report": {"readiness_status": "NOT_READY"},
      "summary": {"next_action_check_id": "machine_c_vpn_smoke"}
    }
  },
  "actions": {
    "taken": [],
    "skipped": [],
    "failed": ["wg-only runtime dir prune"]
  }
}
EOF_RUNTIME_FAIL
      exit 1
    fi
    cat <<EOF_RUNTIME_OK
[runtime-fix] before_status=WARN findings=1
[runtime-fix] after_status=OK findings=0 actions_taken=1 actions_skipped=0 actions_failed=0
[runtime-fix] manual_validation_report_status=ok
[runtime-fix] manual_validation_report_summary_json=$summary_json
[runtime-fix] manual_validation_report_md=$report_md
[runtime-fix] manual_validation_report_log=$report_log
[runtime-fix] summary_json_payload:
{
  "doctor": {
    "before": {"status": "WARN", "summary": {"findings_total": 1}},
    "after": {"status": "OK", "summary": {"findings_total": 0}}
  },
  "manual_validation_report": {
    "status": "ok",
    "summary_json": "$summary_json",
    "report_md": "$report_md",
    "log": "$report_log",
    "summary": {
      "report": {"readiness_status": "NOT_READY"},
      "summary": {"next_action_check_id": "machine_c_vpn_smoke"}
    }
  },
  "actions": {
    "taken": ["wg-only runtime dir prune"],
    "skipped": [],
    "failed": []
  }
}
EOF_RUNTIME_OK
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

echo "[runtime-fix-record] success path"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
PRIVACYNODE_ROOT="$ROOT_DIR" \
RUNTIME_FIX_RECORD_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/runtime_fix_record.sh \
  --base-port 19290 \
  --client-iface wgcfix0 \
  --exit-iface wgefix0 \
  --vpn-iface wgvpnfix0 \
  --prune-wg-only-dir 1 \
  --print-summary-json 1 >/tmp/integration_runtime_fix_record_ok.log 2>&1

if ! rg -q 'runtime-fix-record: status=pass' /tmp/integration_runtime_fix_record_ok.log; then
  echo "expected pass status for runtime-fix-record success path"
  cat /tmp/integration_runtime_fix_record_ok.log
  exit 1
fi
if ! rg -q '^runtime-fix --base-port 19290 --client-iface wgcfix0 --exit-iface wgefix0 --vpn-iface wgvpnfix0 --prune-wg-only-dir 1 --manual-validation-report 1 --show-json 1$' "$CAPTURE"; then
  echo "expected runtime-fix forwarding missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id runtime_hygiene --status pass ' "$CAPTURE"; then
  echo "expected manual-validation-record pass call missing"
  cat "$CAPTURE"
  exit 1
fi

summary_json_path="$(sed -n 's/^summary_json: //p' /tmp/integration_runtime_fix_record_ok.log | tail -n 1)"
if [[ -z "$summary_json_path" || ! -f "$summary_json_path" ]]; then
  echo "expected success summary JSON missing"
  cat /tmp/integration_runtime_fix_record_ok.log
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .runtime_fix.base_port == 19290
  and .runtime_fix.client_iface == "wgcfix0"
  and .runtime_fix.exit_iface == "wgefix0"
  and .runtime_fix.vpn_iface == "wgvpnfix0"
  and .runtime_fix.prune_wg_only_dir == true
  and .runtime_fix.after_status == "OK"
  and .manual_validation_report.status == "ok"
  and .manual_validation_report.readiness_status == "NOT_READY"
  and .manual_validation_report.next_action_check_id == "machine_c_vpn_smoke"
' "$summary_json_path" >/dev/null; then
  echo "success summary JSON missing expected fields"
  cat "$summary_json_path"
  exit 1
fi

: >"$CAPTURE"

echo "[runtime-fix-record] failure path"
if env \
  FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
  PRIVACYNODE_ROOT="$ROOT_DIR" \
  FAKE_RUNTIME_FIX_FAIL="1" \
  RUNTIME_FIX_RECORD_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
  ./scripts/runtime_fix_record.sh \
    --base-port 19291 \
    --client-iface wgcfixfail0 \
    --exit-iface wgefixfail0 \
    --vpn-iface wgvpnfixfail0 >/tmp/integration_runtime_fix_record_fail.log 2>&1; then
  echo "expected failure path to return non-zero"
  cat /tmp/integration_runtime_fix_record_fail.log
  exit 1
fi

if ! rg -q 'runtime-fix-record: status=fail' /tmp/integration_runtime_fix_record_fail.log; then
  echo "expected fail status for runtime-fix-record failure path"
  cat /tmp/integration_runtime_fix_record_fail.log
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id runtime_hygiene --status fail ' "$CAPTURE"; then
  echo "expected manual-validation-record fail call missing"
  cat "$CAPTURE"
  exit 1
fi

fail_summary_json_path="$(sed -n 's/^summary_json: //p' /tmp/integration_runtime_fix_record_fail.log | tail -n 1)"
if [[ -z "$fail_summary_json_path" || ! -f "$fail_summary_json_path" ]]; then
  echo "expected failure summary JSON missing"
  cat /tmp/integration_runtime_fix_record_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .runtime_fix.base_port == 19291
  and .runtime_fix.after_status == "FAIL"
  and .manual_validation_report.status == "ok"
' "$fail_summary_json_path" >/dev/null; then
  echo "failure summary JSON missing expected fields"
  cat "$fail_summary_json_path"
  exit 1
fi

echo "runtime fix record integration ok"
