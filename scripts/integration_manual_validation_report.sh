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
PROFILE_SIGNOFF_SUMMARY_JSON="$TMP_DIR/profile_compare_campaign_signoff_summary.json"
FAKE_DOCTOR="$TMP_DIR/fake_runtime_doctor.sh"
SUMMARY_JSON="$TMP_DIR/manual_validation_readiness_summary.json"
REPORT_MD="$TMP_DIR/manual_validation_readiness_report.md"
RECORD_PASS_LOG="$TMP_DIR/integration_manual_validation_report_record_pass.log"
RECORD_FAIL_LOG="$TMP_DIR/integration_manual_validation_report_record_fail.log"
REPORT_LOG="$TMP_DIR/integration_manual_validation_report.log"
FAIL_CLOSE_LOG="$TMP_DIR/integration_manual_validation_report_fail_close.log"
PROFILE_BLOCKED_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_profile_blocked.log"
PROFILE_STALE_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_profile_stale.log"
INVALID_STATUS_PAYLOAD_LOG="$TMP_DIR/integration_manual_validation_report_invalid_status_payload.log"
CAPTURE="$TMP_DIR/capture.log"
FAKE_REPORT="$TMP_DIR/fake_manual_validation_report.sh"
FAKE_STATUS_INVALID="$TMP_DIR/fake_manual_validation_status_invalid_json.sh"

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
  --show-json 0 >$RECORD_PASS_LOG

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
  --command "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country" \
  --show-json 0 >$RECORD_FAIL_LOG

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --print-report 0 \
  --print-summary-json 1 >$REPORT_LOG

if ! rg -q '\[manual-validation-report\] readiness_status=NOT_READY' $REPORT_LOG; then
  echo "manual validation report missing readiness summary line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] machine_c_smoke_ready=false' $REPORT_LOG; then
  echo "manual validation report missing machine_c_smoke_ready=false line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] machine_c_smoke_blockers=runtime_hygiene' $REPORT_LOG; then
  echo "manual validation report missing machine_c_smoke_blockers line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] machine_c_smoke_next_command=sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country' $REPORT_LOG; then
  echo "manual validation report missing machine_c_smoke_next_command line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] single_machine_ready=false' $REPORT_LOG; then
  echo "manual validation report missing single_machine_ready=false line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] roadmap_stage=BLOCKED_LOCAL' $REPORT_LOG; then
  echo "manual validation report missing roadmap_stage=BLOCKED_LOCAL line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] real_host_gate_ready=false' $REPORT_LOG; then
  echo "manual validation report missing real_host_gate_ready=false line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] real_host_gate_blockers=machine_c_vpn_smoke,three_machine_prod_signoff' $REPORT_LOG; then
  echo "manual validation report missing real_host_gate_blockers line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] real_host_gate_next_command=sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country' $REPORT_LOG; then
  echo "manual validation report missing real_host_gate_next_command line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] profile_default_gate_status=pending' $REPORT_LOG; then
  echo "manual validation report missing profile_default_gate_status=pending line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] profile_default_gate_available=false' $REPORT_LOG; then
  echo "manual validation report missing profile_default_gate_available=false line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] docker_rehearsal_status=pending' $REPORT_LOG; then
  echo "manual validation report missing docker_rehearsal_status=pending line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] docker_rehearsal_ready=false' $REPORT_LOG; then
  echo "manual validation report missing docker_rehearsal_ready=false line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] real_wg_privileged_status=pending' $REPORT_LOG; then
  echo "manual validation report missing real_wg_privileged_status=pending line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] real_wg_privileged_ready=false' $REPORT_LOG; then
  echo "manual validation report missing real_wg_privileged_ready=false line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] next_action_command=sudo \./scripts/easy_node\.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1' $REPORT_LOG; then
  echo "manual validation report missing next_action_command line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] next_action_remediations=sudo chown user:user deploy/\.env\.easy\.client' $REPORT_LOG; then
  echo "manual validation report missing next_action_remediations line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q "\[manual-validation-report\] summary_json=${SUMMARY_JSON}" $REPORT_LOG; then
  echo "manual validation report missing summary_json path"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q "\[manual-validation-report\] report_md=${REPORT_MD}" $REPORT_LOG; then
  echo "manual validation report missing report_md path"
  cat $REPORT_LOG
  exit 1
fi
if [[ ! -f "$SUMMARY_JSON" || ! -f "$REPORT_MD" ]]; then
  echo "manual validation report did not create expected artifacts"
  ls -la "$TMP_DIR"
  exit 1
fi

report_json_payload="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' $REPORT_LOG)"
if [[ -z "$report_json_payload" ]]; then
  echo "manual validation report missing JSON payload"
  cat $REPORT_LOG
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
  and .summary.next_action_command == "sudo ./scripts/easy_node.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1"
  and .summary.next_action_remediations == ["sudo chown user:user deploy/.env.easy.client"]
  and .summary.pre_machine_c_gate.ready == false
  and .summary.pre_machine_c_gate.blockers == ["runtime_hygiene"]
  and .summary.pre_machine_c_gate.next_check_id == "machine_c_vpn_smoke"
  and .summary.pre_machine_c_gate.next_command == "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
  and .summary.local_gate.ready == false
  and .summary.local_gate.blockers == ["runtime_hygiene"]
  and .summary.local_gate.next_check_id == "runtime_hygiene"
  and .summary.real_host_gate.ready == false
  and .summary.real_host_gate.blockers == ["machine_c_vpn_smoke","three_machine_prod_signoff"]
  and .summary.real_host_gate.next_check_id == "machine_c_vpn_smoke"
  and .summary.real_host_gate.next_command == "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
  and .summary.profile_default_gate.status == "pending"
  and .summary.profile_default_gate.available == false
  and .summary.profile_default_gate.valid_json == false
  and .summary.profile_default_gate.summary_json == "'"$PROFILE_SIGNOFF_SUMMARY_JSON"'"
  and .summary.docker_rehearsal_gate.status == "pending"
  and .summary.docker_rehearsal_gate.ready == false
  and .summary.docker_rehearsal_gate.check_id == "three_machine_docker_readiness"
  and .summary.docker_rehearsal_gate.next_command == "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
  and .summary.real_wg_privileged_gate.status == "pending"
  and .summary.real_wg_privileged_gate.ready == false
  and .summary.real_wg_privileged_gate.check_id == "real_wg_privileged_matrix"
  and .summary.real_wg_privileged_gate.next_command == "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
  and (.summary.real_wg_privileged_gate.host.eligible | type == "boolean")
  and ((.summary.real_wg_privileged_gate.host.hint // "") | length > 0)
  and .summary.single_machine_ready == false
  and .summary.roadmap_stage == "BLOCKED_LOCAL"
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
if ! rg -q '^## Profile Default Gate' "$REPORT_MD"; then
  echo "manual validation report markdown missing profile default gate section"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q '^## Docker Rehearsal \(Optional\)' "$REPORT_MD"; then
  echo "manual validation report markdown missing docker rehearsal section"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q '^## Real-WG Matrix \(Optional\)' "$REPORT_MD"; then
  echo "manual validation report markdown missing real-wg matrix section"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q '^## Roadmap Stage' "$REPORT_MD"; then
  echo "manual validation report markdown missing roadmap stage section"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Stage: `BLOCKED_LOCAL`' "$REPORT_MD"; then
  echo "manual validation report markdown missing roadmap stage value"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Single-machine gate ready: `false`' "$REPORT_MD"; then
  echo "manual validation report markdown missing single-machine gate value"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Real-host gate ready: `false`' "$REPORT_MD"; then
  echo "manual validation report markdown missing real-host gate value"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Real-host blockers: `machine_c_vpn_smoke,three_machine_prod_signoff`' "$REPORT_MD"; then
  echo "manual validation report markdown missing real-host blockers value"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Machine C smoke ready: `false`' "$REPORT_MD"; then
  echo "manual validation report markdown missing machine_c_smoke_ready value"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Status: `pending`' "$REPORT_MD"; then
  echo "manual validation report markdown missing profile default gate status value"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Ready: `false`' "$REPORT_MD"; then
  echo "manual validation report markdown missing docker rehearsal ready value"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Command: `sudo \./scripts/easy_node\.sh real-wg-privileged-matrix-record --print-summary-json 1`' "$REPORT_MD"; then
  echo "manual validation report markdown missing real-wg matrix command"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Summary available: `false`' "$REPORT_MD"; then
  echo "manual validation report markdown missing profile default gate availability value"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Blockers: `runtime_hygiene`' "$REPORT_MD"; then
  echo "manual validation report markdown missing machine_c_smoke_blockers value"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Next machine-C smoke command: `sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country`' "$REPORT_MD"; then
  echo "manual validation report markdown missing machine_c_smoke_next_command"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Command: `sudo \./scripts/easy_node\.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1`' "$REPORT_MD"; then
  echo "manual validation report markdown missing next_action_command"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Remediation: `sudo chown user:user deploy/\.env\.easy\.client`' "$REPORT_MD"; then
  echo "manual validation report markdown missing next_action remediation"
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

PROFILE_SIGNOFF_CAMPAIGN_LOG="$TMP_DIR/profile_compare_campaign_signoff_campaign.log"
PROFILE_SIGNOFF_RUN_LOG="$TMP_DIR/profile_compare_local_run_01.log"
cat >"$PROFILE_SIGNOFF_RUN_LOG" <<'EOF_PROFILE_SIGNOFF_RUN'
--start-local-stack=1 requires root (run with sudo)
EOF_PROFILE_SIGNOFF_RUN
cat >"$PROFILE_SIGNOFF_CAMPAIGN_LOG" <<EOF_PROFILE_SIGNOFF_CAMPAIGN
[profile-compare-campaign] run=01 status=fail rc=2 duration_sec=0 summary_json=$TMP_DIR/profile_compare_local_run_01.json log=$PROFILE_SIGNOFF_RUN_LOG
profile-compare-campaign: no valid compare summaries were produced
EOF_PROFILE_SIGNOFF_CAMPAIGN
cat >"$PROFILE_SIGNOFF_SUMMARY_JSON" <<EOF_PROFILE_SIGNOFF_SUMMARY
{
  "version": 1,
  "status": "fail",
  "final_rc": 1,
  "failure_stage": "campaign",
  "inputs": {
    "refresh_campaign": true
  },
  "stages": {
    "campaign": {
      "status": "fail",
      "log": "$PROFILE_SIGNOFF_CAMPAIGN_LOG"
    }
  },
  "decision": {
    "decision": "unknown"
  }
}
EOF_PROFILE_SIGNOFF_SUMMARY

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/profile_blocked_summary.json" \
  --report-md "$TMP_DIR/profile_blocked_report.md" \
  --print-report 0 \
  --print-summary-json 1 >$PROFILE_BLOCKED_REPORT_LOG

if ! rg -q '\[manual-validation-report\] profile_default_gate_status=pending' $PROFILE_BLOCKED_REPORT_LOG; then
  echo "manual validation report profile-blocked run missing profile_default_gate_status=pending line"
  cat $PROFILE_BLOCKED_REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] profile_default_gate_available=true' $PROFILE_BLOCKED_REPORT_LOG; then
  echo "manual validation report profile-blocked run missing profile_default_gate_available=true line"
  cat $PROFILE_BLOCKED_REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] profile_default_gate_next_command=sudo \./scripts/easy_node\.sh profile-compare-campaign-signoff' $PROFILE_BLOCKED_REPORT_LOG; then
  echo "manual validation report profile-blocked run missing sudo profile-default next command"
  cat $PROFILE_BLOCKED_REPORT_LOG
  exit 1
fi
profile_blocked_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' $PROFILE_BLOCKED_REPORT_LOG)"
if [[ -z "$profile_blocked_report_json" ]]; then
  echo "manual validation report profile-blocked run missing JSON payload"
  cat $PROFILE_BLOCKED_REPORT_LOG
  exit 1
fi
if ! printf '%s\n' "$profile_blocked_report_json" | jq -e '
  .summary.profile_default_gate.status == "pending"
  and .summary.profile_default_gate.available == true
  and .summary.profile_default_gate.valid_json == true
  and .summary.profile_default_gate.failure_stage == "campaign"
  and .summary.profile_default_gate.non_root_refresh_blocked == true
  and (.summary.profile_default_gate.next_command | startswith("sudo ./scripts/easy_node.sh profile-compare-campaign-signoff"))
' >/dev/null; then
  echo "manual validation report profile-blocked JSON missing expected profile_default_gate fields"
  printf '%s\n' "$profile_blocked_report_json"
  exit 1
fi

cat >"$PROFILE_SIGNOFF_SUMMARY_JSON" <<'EOF_PROFILE_SIGNOFF_STALE'
{
  "version": 1,
  "status": "fail",
  "final_rc": 1,
  "failure_stage": "campaign_check",
  "inputs": {
    "refresh_campaign": false
  },
  "decision": {
    "decision": "NO-GO",
    "recommended_profile": "balanced"
  }
}
EOF_PROFILE_SIGNOFF_STALE

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/profile_stale_summary.json" \
  --report-md "$TMP_DIR/profile_stale_report.md" \
  --print-report 0 \
  --print-summary-json 1 >$PROFILE_STALE_REPORT_LOG

if ! rg -q '\[manual-validation-report\] profile_default_gate_status=pending' $PROFILE_STALE_REPORT_LOG; then
  echo "manual validation report profile-stale run missing profile_default_gate_status=pending line"
  cat $PROFILE_STALE_REPORT_LOG
  exit 1
fi
profile_stale_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' $PROFILE_STALE_REPORT_LOG)"
if [[ -z "$profile_stale_report_json" ]]; then
  echo "manual validation report profile-stale run missing JSON payload"
  cat $PROFILE_STALE_REPORT_LOG
  exit 1
fi
if ! printf '%s\n' "$profile_stale_report_json" | jq -e '
  .summary.profile_default_gate.status == "pending"
  and .summary.profile_default_gate.available == true
  and .summary.profile_default_gate.valid_json == true
  and .summary.profile_default_gate.failure_stage == "campaign_check"
  and .summary.profile_default_gate.non_root_refresh_blocked == false
  and .summary.profile_default_gate.stale_non_refreshed == true
  and .summary.profile_default_gate.refresh_campaign == false
  and (.summary.profile_default_gate.next_command | startswith("sudo ./scripts/easy_node.sh profile-compare-campaign-signoff"))
' >/dev/null; then
  echo "manual validation report profile-stale JSON missing expected profile_default_gate fields"
  printf '%s\n' "$profile_stale_report_json"
  exit 1
fi

set +e
EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/fail_close_summary.json" \
  --report-md "$TMP_DIR/fail_close_report.md" \
  --print-report 0 \
  --print-summary-json 0 \
  --fail-on-not-ready 1 >$FAIL_CLOSE_LOG 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "manual validation report fail-close should have returned non-zero"
  cat $FAIL_CLOSE_LOG
  exit 1
fi
if ! rg -q 'manual-validation-report: readiness is NOT_READY' $FAIL_CLOSE_LOG; then
  echo "manual validation report fail-close missing expected message"
  cat $FAIL_CLOSE_LOG
  exit 1
fi

cat >"$FAKE_STATUS_INVALID" <<'EOF_STATUS_INVALID'
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[manual-validation-status] summary_json_payload:
{"version":1,"checks":
OUT
EOF_STATUS_INVALID
chmod +x "$FAKE_STATUS_INVALID"

set +e
EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS_INVALID" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/invalid_status_summary.json" \
  --report-md "$TMP_DIR/invalid_status_report.md" \
  --print-report 0 \
  --print-summary-json 0 >$INVALID_STATUS_PAYLOAD_LOG 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "manual validation report should fail when status payload is invalid JSON"
  cat $INVALID_STATUS_PAYLOAD_LOG
  exit 1
fi
if ! rg -q 'manual-validation-report failed: manual-validation-status emitted invalid JSON summary' $INVALID_STATUS_PAYLOAD_LOG; then
  echo "manual validation report missing invalid-status-payload error"
  cat $INVALID_STATUS_PAYLOAD_LOG
  exit 1
fi

echo "[manual-validation-report] easy_node forwarding"
cat >"$FAKE_REPORT" <<'EOF_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf 'manual-validation-report %s\n' "$*" >>"$CAPTURE"
EOF_FORWARD
chmod +x "$FAKE_REPORT"
: >"$CAPTURE"

CAPTURE="$CAPTURE" \
MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_REPORT" \
./scripts/easy_node.sh manual-validation-report \
  --base-port 19400 \
  --client-iface wgctest0 \
  --exit-iface wgestest0 \
  --vpn-iface wgvpntest0 \
  --profile-compare-signoff-summary-json /tmp/profile_signoff_override.json \
  --summary-json /tmp/manual_validation_readiness_summary.json \
  --report-md /tmp/manual_validation_readiness_report.md \
  --print-report 0 \
  --print-summary-json 1 \
  --fail-on-not-ready 1

line_report="$(rg '^manual-validation-report ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line_report" ]]; then
  echo "easy_node manual-validation-report forwarding failed"
  cat "$CAPTURE"
  exit 1
fi
for expected in \
  '--base-port 19400' \
  '--client-iface wgctest0' \
  '--exit-iface wgestest0' \
  '--vpn-iface wgvpntest0' \
  '--profile-compare-signoff-summary-json /tmp/profile_signoff_override.json' \
  '--summary-json /tmp/manual_validation_readiness_summary.json' \
  '--report-md /tmp/manual_validation_readiness_report.md' \
  '--print-report 0' \
  '--print-summary-json 1' \
  '--fail-on-not-ready 1'; do
  if ! grep -F -- "$expected" <<<"$line_report" >/dev/null; then
    echo "easy_node manual-validation-report forwarding missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

echo "manual validation report integration check ok"
