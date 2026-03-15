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

STATE_DIR="$TMP_DIR/state"
FAKE_DOCTOR="$TMP_DIR/fake_runtime_doctor.sh"
SUMMARY_JSON="$TMP_DIR/manual_validation_readiness_summary.json"
REPORT_MD="$TMP_DIR/manual_validation_readiness_report.md"

cat >"$FAKE_DOCTOR" <<'EOF_DOCTOR'
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[runtime-doctor] status=WARN findings=1 warnings=1 failures=0
[runtime-doctor] summary_json_payload:
{
  "version": 1,
  "generated_at_utc": "2026-03-15T10:00:00Z",
  "status": "WARN",
  "summary": {
    "findings_total": 1,
    "warnings_total": 1,
    "failures_total": 0
  },
  "findings": [
    {
      "severity": "WARN",
      "code": "client_env_file_not_writable",
      "message": "client env file not writable",
      "remediation": "sudo chown user:user deploy/.env.easy.client"
    }
  ]
}
OUT
EOF_DOCTOR
chmod +x "$FAKE_DOCTOR"

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
./scripts/manual_validation_record.sh \
  --check-id wg_only_stack_selftest \
  --status pass \
  --notes "Linux root host rerun passed" \
  --artifact "$ROOT_DIR/scripts/easy_node.sh" \
  --command "sudo ./scripts/integration_wg_only_stack_selftest.sh" \
  --show-json 0 >/tmp/integration_manual_validation_report_record_pass.log

SMOKE_INCIDENT_DIR="$TMP_DIR/client_vpn_smoke_incident"
mkdir -p "$SMOKE_INCIDENT_DIR/attachments"
SMOKE_INCIDENT_SUMMARY_JSON="$SMOKE_INCIDENT_DIR/incident_summary.json"
SMOKE_INCIDENT_REPORT_MD="$SMOKE_INCIDENT_DIR/incident_report.md"
SMOKE_INCIDENT_ATTACH_MANIFEST="$SMOKE_INCIDENT_DIR/attachments/manifest.tsv"
SMOKE_INCIDENT_ATTACH_SKIPPED="$SMOKE_INCIDENT_DIR/attachments/skipped.tsv"
SMOKE_INCIDENT_LOG="$SMOKE_INCIDENT_DIR/incident_snapshot.log"
SMOKE_INCIDENT_BUNDLE_TAR="${SMOKE_INCIDENT_DIR}.tar.gz"
SMOKE_RUN_SUMMARY_JSON="$TMP_DIR/client_vpn_smoke_fail_summary.json"
SMOKE_READY_SUMMARY_SOURCE="$TMP_DIR/source_manual_validation_readiness_summary.json"
SMOKE_READY_REPORT_SOURCE="$TMP_DIR/source_manual_validation_readiness_report.md"
SMOKE_READY_LOG_SOURCE="$TMP_DIR/source_client_vpn_manual_validation_report.log"
SMOKE_READY_SUMMARY_ATTACHMENT="$SMOKE_INCIDENT_DIR/attachments/02_manual_validation_readiness_summary.json"
SMOKE_READY_REPORT_ATTACHMENT="$SMOKE_INCIDENT_DIR/attachments/03_manual_validation_readiness_report.md"
SMOKE_READY_LOG_ATTACHMENT="$SMOKE_INCIDENT_DIR/attachments/04_client_vpn_manual_validation_report.log"

cat <<'EOF_INCIDENT_SUMMARY' >"$SMOKE_INCIDENT_SUMMARY_JSON"
{"status":"ok"}
EOF_INCIDENT_SUMMARY
cat <<'EOF_INCIDENT_REPORT' >"$SMOKE_INCIDENT_REPORT_MD"
# Client VPN Incident Report
EOF_INCIDENT_REPORT
printf '%s\n' '{"readiness_status":"NOT_READY"}' >"$SMOKE_READY_SUMMARY_SOURCE"
printf '%s\n' '# Readiness Report Attachment' >"$SMOKE_READY_REPORT_SOURCE"
printf '%s\n' 'manual validation report log' >"$SMOKE_READY_LOG_SOURCE"
printf '%s\n' '{"readiness_status":"NOT_READY"}' >"$SMOKE_READY_SUMMARY_ATTACHMENT"
printf '%s\n' '# Readiness Report Attachment' >"$SMOKE_READY_REPORT_ATTACHMENT"
printf '%s\n' 'manual validation report log' >"$SMOKE_READY_LOG_ATTACHMENT"
cat >"$SMOKE_INCIDENT_ATTACH_MANIFEST" <<EOF_INCIDENT_MANIFEST
attachments/01_runtime_doctor_before.json	file	/tmp/runtime_doctor_before.json
attachments/02_manual_validation_readiness_summary.json	file	$SMOKE_READY_SUMMARY_SOURCE
attachments/03_manual_validation_readiness_report.md	file	$SMOKE_READY_REPORT_SOURCE
attachments/04_client_vpn_manual_validation_report.log	file	$SMOKE_READY_LOG_SOURCE
EOF_INCIDENT_MANIFEST
: >"$SMOKE_INCIDENT_ATTACH_SKIPPED"
printf 'incident snapshot log\n' >"$SMOKE_INCIDENT_LOG"
: >"$SMOKE_INCIDENT_BUNDLE_TAR"
cat >"$SMOKE_RUN_SUMMARY_JSON" <<EOF_SMOKE_SUMMARY
{
  "version": 1,
  "status": "fail",
  "stage": "up",
  "incident_snapshot": {
    "enabled_on_fail": true,
    "status": "ok",
    "bundle_dir": "$SMOKE_INCIDENT_DIR",
    "bundle_tar": "$SMOKE_INCIDENT_BUNDLE_TAR",
    "summary_json": "$SMOKE_INCIDENT_SUMMARY_JSON",
    "report_md": "$SMOKE_INCIDENT_REPORT_MD",
    "attachment_manifest": "$SMOKE_INCIDENT_ATTACH_MANIFEST",
    "attachment_skipped": "$SMOKE_INCIDENT_ATTACH_SKIPPED",
    "attachment_count": 1,
    "log": "$SMOKE_INCIDENT_LOG"
  }
}
EOF_SMOKE_SUMMARY

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
./scripts/manual_validation_record.sh \
  --check-id machine_c_vpn_smoke \
  --status fail \
  --notes "Machine C smoke failed with captured incident bundle" \
  --artifact "$SMOKE_RUN_SUMMARY_JSON" \
  --artifact "$SMOKE_INCIDENT_DIR" \
  --artifact "$SMOKE_INCIDENT_SUMMARY_JSON" \
  --artifact "$SMOKE_INCIDENT_REPORT_MD" \
  --artifact "$SMOKE_INCIDENT_ATTACH_MANIFEST" \
  --artifact "$SMOKE_INCIDENT_ATTACH_SKIPPED" \
  --artifact "$SMOKE_INCIDENT_LOG" \
  --command "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country" \
  --show-json 0 >/tmp/integration_manual_validation_report_record_fail.log

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --print-report 0 \
  --print-summary-json 1 >/tmp/integration_manual_validation_report.log

if ! rg -q '\[manual-validation-report\] readiness_status=NOT_READY' /tmp/integration_manual_validation_report.log; then
  echo "manual validation report missing readiness summary line"
  cat /tmp/integration_manual_validation_report.log
  exit 1
fi
if ! rg -q '\[manual-validation-report\] machine_c_smoke_ready=false' /tmp/integration_manual_validation_report.log; then
  echo "manual validation report missing machine_c_smoke_ready=false line"
  cat /tmp/integration_manual_validation_report.log
  exit 1
fi
if ! rg -q '\[manual-validation-report\] machine_c_smoke_blockers=runtime_hygiene' /tmp/integration_manual_validation_report.log; then
  echo "manual validation report missing machine_c_smoke_blockers line"
  cat /tmp/integration_manual_validation_report.log
  exit 1
fi
if ! rg -q '\[manual-validation-report\] machine_c_smoke_next_command=sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country' /tmp/integration_manual_validation_report.log; then
  echo "manual validation report missing machine_c_smoke_next_command line"
  cat /tmp/integration_manual_validation_report.log
  exit 1
fi
if ! rg -q "\[manual-validation-report\] summary_json=${SUMMARY_JSON}" /tmp/integration_manual_validation_report.log; then
  echo "manual validation report missing summary_json path"
  cat /tmp/integration_manual_validation_report.log
  exit 1
fi
if ! rg -q "\[manual-validation-report\] report_md=${REPORT_MD}" /tmp/integration_manual_validation_report.log; then
  echo "manual validation report missing report_md path"
  cat /tmp/integration_manual_validation_report.log
  exit 1
fi
if [[ ! -f "$SUMMARY_JSON" || ! -f "$REPORT_MD" ]]; then
  echo "manual validation report did not create expected artifacts"
  ls -la "$TMP_DIR"
  exit 1
fi

report_json_payload="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' /tmp/integration_manual_validation_report.log)"
if [[ -z "$report_json_payload" ]]; then
  echo "manual validation report missing JSON payload"
  cat /tmp/integration_manual_validation_report.log
  exit 1
fi
if ! jq -e . "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "manual validation report wrote invalid summary JSON"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! printf '%s\n' "$report_json_payload" | jq -e --arg summary_json "$SUMMARY_JSON" --arg report_md "$REPORT_MD" --arg incident_summary "$SMOKE_INCIDENT_SUMMARY_JSON" --arg incident_report "$SMOKE_INCIDENT_REPORT_MD" --arg ready_summary_attachment "$SMOKE_READY_SUMMARY_ATTACHMENT" --arg ready_report_attachment "$SMOKE_READY_REPORT_ATTACHMENT" --arg ready_log_attachment "$SMOKE_READY_LOG_ATTACHMENT" '
  .report.readiness_status == "NOT_READY"
  and .report.ready == false
  and .report.summary_json == $summary_json
  and .report.report_md == $report_md
  and .summary.next_action_check_id == "runtime_hygiene"
  and .summary.pre_machine_c_gate.ready == false
  and .summary.pre_machine_c_gate.blockers == ["runtime_hygiene"]
  and .summary.pre_machine_c_gate.next_check_id == "machine_c_vpn_smoke"
  and .summary.pre_machine_c_gate.next_command == "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
  and .summary.latest_failed_incident.check_id == "machine_c_vpn_smoke"
  and .summary.latest_failed_incident.summary_json.path == $incident_summary
  and .summary.latest_failed_incident.report_md.path == $incident_report
  and .summary.latest_failed_incident.readiness_report_summary_attachment.bundle_path == $ready_summary_attachment
  and .summary.latest_failed_incident.readiness_report_md_attachment.bundle_path == $ready_report_attachment
  and .summary.latest_failed_incident.readiness_report_log_attachment.bundle_path == $ready_log_attachment
' >/dev/null; then
  echo "manual validation report JSON missing expected fields"
  printf '%s\n' "$report_json_payload"
  exit 1
fi

if ! rg -q '^# Manual Validation Readiness Report' "$REPORT_MD"; then
  echo "manual validation report markdown missing title"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q '^## Next Action' "$REPORT_MD"; then
  echo "manual validation report markdown missing next action section"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q '^## Pre-Machine-C Gate' "$REPORT_MD"; then
  echo "manual validation report markdown missing pre-machine-c gate section"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Machine C smoke ready: `false`' "$REPORT_MD"; then
  echo "manual validation report markdown missing machine_c_smoke_ready value"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Blockers: `runtime_hygiene`' "$REPORT_MD"; then
  echo "manual validation report markdown missing machine_c_smoke_blockers value"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Next machine-C smoke command: `sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country`' "$REPORT_MD"; then
  echo "manual validation report markdown missing machine_c_smoke_next_command"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Runtime hygiene doctor' "$REPORT_MD"; then
  echo "manual validation report markdown missing runtime hygiene entry"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Machine C VPN smoke test' "$REPORT_MD"; then
  echo "manual validation report markdown missing machine C entry"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q '^## Latest Failed Incident' "$REPORT_MD"; then
  echo "manual validation report markdown missing latest incident section"
  cat "$REPORT_MD"
  exit 1
fi
if ! grep -F -- "$SMOKE_READY_SUMMARY_ATTACHMENT" "$REPORT_MD" >/dev/null; then
  echo "manual validation report markdown missing readiness summary attachment path"
  cat "$REPORT_MD"
  exit 1
fi
if ! grep -F -- "$SMOKE_READY_REPORT_ATTACHMENT" "$REPORT_MD" >/dev/null; then
  echo "manual validation report markdown missing readiness report attachment path"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q "$(printf '%s' "$SMOKE_INCIDENT_REPORT_MD" | sed 's/[.[\*^$()+?{|]/\\&/g')" "$REPORT_MD"; then
  echo "manual validation report markdown missing incident report path"
  cat "$REPORT_MD"
  exit 1
fi

set +e
EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/fail_close_summary.json" \
  --report-md "$TMP_DIR/fail_close_report.md" \
  --print-report 0 \
  --print-summary-json 0 \
  --fail-on-not-ready 1 >/tmp/integration_manual_validation_report_fail_close.log 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "manual validation report fail-close should have returned non-zero"
  cat /tmp/integration_manual_validation_report_fail_close.log
  exit 1
fi
if ! rg -q 'manual-validation-report: readiness is NOT_READY' /tmp/integration_manual_validation_report_fail_close.log; then
  echo "manual validation report fail-close missing expected message"
  cat /tmp/integration_manual_validation_report_fail_close.log
  exit 1
fi

echo "manual validation report integration check ok"
