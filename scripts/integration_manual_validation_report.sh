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

TEST_LOG_DIR="$TMP_DIR/easy-node-logs"
STATE_DIR="$TMP_DIR/manual-validation-state"
mkdir -p "$TEST_LOG_DIR" "$STATE_DIR"
export EASY_NODE_LOG_DIR="$TEST_LOG_DIR"
export EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR"

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
PROFILE_INVALID_SUMMARY_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_profile_invalid_summary.log"
INVALID_STATUS_PAYLOAD_LOG="$TMP_DIR/integration_manual_validation_report_invalid_status_payload.log"
TIMEOUT_STATUS_PAYLOAD_LOG="$TMP_DIR/integration_manual_validation_report_timeout_status.log"
STABILITY_VALID_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_stability_valid.log"
STABILITY_INVALID_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_stability_invalid.log"
STABILITY_DEFAULT_MISSING_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_stability_default_missing.log"
CYCLE_VALID_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_cycle_valid.log"
CYCLE_INVALID_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_cycle_invalid.log"
CYCLE_DEFAULT_MISSING_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_cycle_default_missing.log"
MULTI_VM_STABILITY_VALID_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_multi_vm_stability_valid.log"
MULTI_VM_STABILITY_CYCLE_FALLBACK_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_multi_vm_stability_cycle_fallback.log"
MULTI_VM_STABILITY_DEFAULT_MISSING_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_multi_vm_stability_default_missing.log"
CAPTURE="$TMP_DIR/capture.log"
FAKE_REPORT="$TMP_DIR/fake_manual_validation_report.sh"
FAKE_STATUS_INVALID="$TMP_DIR/fake_manual_validation_status_invalid_json.sh"
FAKE_STATUS_TIMEOUT="$TMP_DIR/fake_manual_validation_status_timeout.sh"
FAKE_STATUS_ROOT_DEFER="$TMP_DIR/fake_manual_validation_status_root_defer.sh"
FAKE_STATUS_STABILITY_VALID="$TMP_DIR/fake_manual_validation_status_stability_valid.sh"
FAKE_STATUS_STABILITY_INVALID="$TMP_DIR/fake_manual_validation_status_stability_invalid.sh"
FAKE_STATUS_STABILITY_DEFAULT_MISSING="$TMP_DIR/fake_manual_validation_status_stability_default_missing.sh"
FAKE_STATUS_CYCLE_VALID="$TMP_DIR/fake_manual_validation_status_cycle_valid.sh"
FAKE_STATUS_CYCLE_INVALID="$TMP_DIR/fake_manual_validation_status_cycle_invalid.sh"
FAKE_STATUS_CYCLE_DEFAULT_MISSING="$TMP_DIR/fake_manual_validation_status_cycle_default_missing.sh"
FAKE_STATUS_MULTI_VM_STABILITY_VALID="$TMP_DIR/fake_manual_validation_status_multi_vm_stability_valid.sh"
FAKE_STATUS_MULTI_VM_STABILITY_CYCLE_FALLBACK="$TMP_DIR/fake_manual_validation_status_multi_vm_stability_cycle_fallback.sh"
FAKE_STATUS_MULTI_VM_STABILITY_DEFAULT_MISSING="$TMP_DIR/fake_manual_validation_status_multi_vm_stability_default_missing.sh"
STABILITY_VALID_SUMMARY_JSON="$TMP_DIR/profile_default_gate_stability_check_summary_valid.json"
STABILITY_INVALID_SUMMARY_JSON="$TMP_DIR/profile_default_gate_stability_check_summary_invalid.json"
STABILITY_DEFAULT_SIGNOFF_SUMMARY_JSON="$TMP_DIR/profile_compare_campaign_signoff_summary_default.json"
STABILITY_DEFAULT_EXPECTED_SUMMARY_JSON="$TMP_DIR/profile_default_gate_stability_check_summary.json"
CYCLE_VALID_SUMMARY_JSON="$TMP_DIR/profile_default_gate_stability_cycle_summary_valid.json"
CYCLE_INVALID_SUMMARY_JSON="$TMP_DIR/profile_default_gate_stability_cycle_summary_invalid.json"
CYCLE_DEFAULT_SIGNOFF_SUMMARY_JSON="$TMP_DIR/profile_compare_campaign_signoff_cycle_default.json"
CYCLE_DEFAULT_EXPECTED_SUMMARY_JSON="$TMP_DIR/profile_default_gate_stability_cycle_summary.json"
MULTI_VM_STABILITY_CHECK_VALID_SUMMARY_JSON="$TMP_DIR/profile_compare_multi_vm_stability_check_summary_valid.json"
MULTI_VM_STABILITY_CHECK_INVALID_SUMMARY_JSON="$TMP_DIR/profile_compare_multi_vm_stability_check_summary_invalid.json"
MULTI_VM_STABILITY_CHECK_DEFAULT_EXPECTED_SUMMARY_JSON="$TMP_DIR/profile_compare_multi_vm_stability_check_summary.json"
MULTI_VM_STABILITY_CYCLE_VALID_SUMMARY_JSON="$TMP_DIR/profile_compare_multi_vm_stability_cycle_summary_valid.json"
MULTI_VM_STABILITY_CYCLE_DEFAULT_EXPECTED_SUMMARY_JSON="$TMP_DIR/profile_compare_multi_vm_stability_cycle_summary.json"

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

cat >"$FAKE_STATUS_ROOT_DEFER" <<'EOF_STATUS_ROOT_DEFER'
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[manual-validation-status] summary_json_payload:
{
  "version": 1,
  "state_dir": "/tmp/manual-validation-state",
  "status_json": "/tmp/manual-validation-status.json",
  "runtime_doctor_exit_code": 0,
  "runtime_doctor": {
    "version": 1,
    "generated_at_utc": "2026-03-15T11:00:00Z",
    "status": "OK",
    "summary": {
      "findings_total": 0,
      "warnings_total": 0,
      "failures_total": 0
    },
    "findings": []
  },
  "checks": [],
  "summary": {
    "total_checks": 1,
    "pass_checks": 0,
    "warn_checks": 0,
    "fail_checks": 1,
    "pending_checks": 0,
    "next_action_check_id": "machine_c_vpn_smoke",
    "next_action_label": "Machine C VPN smoke test",
    "next_action_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country",
    "next_action_remediations": ["rerun with sudo"],
    "pre_machine_c_gate": {
      "ready": false,
      "blockers": ["wg_only_stack_selftest"],
      "next_check_id": "machine_c_vpn_smoke",
      "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country",
      "blocker_class": "root_required_deferred_blocker",
      "next_sudo_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    "local_gate": {
      "ready": false,
      "check_ids": [],
      "blockers": ["wg_only_stack_selftest"],
      "next_check_id": "machine_c_vpn_smoke"
    },
    "real_host_gate": {
      "ready": false,
      "check_ids": ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
      "blockers": ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
      "next_check_id": "machine_c_vpn_smoke",
      "next_label": "Machine C VPN smoke test",
      "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    "profile_default_gate": {
      "enabled": true,
      "available": false,
      "valid_json": false,
      "status": "pending",
      "notes": "profile compare campaign signoff unavailable",
      "next_command": ""
    },
    "profile_default_ready": false,
    "docker_rehearsal_gate": {
      "check_id": "three_machine_docker_readiness",
      "status": "pending",
      "notes": "status unavailable",
      "command": "",
      "next_command": "",
      "ready": false
    },
    "real_wg_privileged_gate": {
      "check_id": "real_wg_privileged_matrix",
      "status": "skip",
      "notes": "status unavailable",
      "command": "",
      "next_command": "",
      "ready": true
    },
    "single_machine_ready": false,
    "roadmap_stage": "BLOCKED_LOCAL",
    "latest_failed_incident": null
  }
}
OUT
EOF_STATUS_ROOT_DEFER
chmod +x "$FAKE_STATUS_ROOT_DEFER"

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
if ! rg -q '\[manual-validation-report\] real_wg_privileged_status=(pending|skip)' $REPORT_LOG; then
  echo "manual validation report missing real_wg_privileged_status=(pending|skip) line"
  cat $REPORT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-report\] real_wg_privileged_ready=(false|true)' $REPORT_LOG; then
  echo "manual validation report missing real_wg_privileged_ready=(false|true) line"
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
  .schema.id == "manual_validation_readiness_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and
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
  and (
    if .summary.real_wg_privileged_gate.host.eligible then
      .summary.real_wg_privileged_gate.status == "pending"
      and .summary.real_wg_privileged_gate.ready == false
      and .summary.real_wg_privileged_gate.next_command == "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    else
      .summary.real_wg_privileged_gate.status == "skip"
      and .summary.real_wg_privileged_gate.ready == true
      and .summary.real_wg_privileged_gate.next_command == ""
    end
  )
  and .summary.real_wg_privileged_gate.check_id == "real_wg_privileged_matrix"
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
  and (.summary.profile_default_gate.next_command | contains("--campaign-subject INVITE_KEY"))
  and ((.summary.profile_default_gate.next_command | split("--campaign-subject") | length) == 2)
  and (.summary.profile_default_gate.next_command | contains("--summary-json '"$PROFILE_SIGNOFF_SUMMARY_JSON"'"))
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
  and (.summary.profile_default_gate.next_command | contains("--campaign-subject INVITE_KEY"))
  and ((.summary.profile_default_gate.next_command | split("--campaign-subject") | length) == 2)
  and (.summary.profile_default_gate.next_command | contains("--summary-json '"$PROFILE_SIGNOFF_SUMMARY_JSON"'"))
' >/dev/null; then
  echo "manual validation report profile-stale JSON missing expected profile_default_gate fields"
  printf '%s\n' "$profile_stale_report_json"
  exit 1
fi

echo "[manual-validation-report] profile-default pending/no-go guidance prefers docker no-sudo path when rehearsal artifacts exist"
PROFILE_DOCKER_HINT_MATRIX_SUMMARY_JSON="$TMP_DIR/three_machine_docker_profile_matrix_record_hint_matrix.json"
PROFILE_DOCKER_HINT_PROFILE_SUMMARY_JSON="$TMP_DIR/three_machine_docker_readiness_hint_2hop.json"
PROFILE_NO_GO_INSUFFICIENT_CHECK_SUMMARY_JSON="$TMP_DIR/profile_compare_campaign_check_insufficient.json"
cat >"$PROFILE_DOCKER_HINT_PROFILE_SUMMARY_JSON" <<'EOF_PROFILE_DOCKER_HINT_PROFILE'
{
  "version": 1,
  "status": "pass",
  "endpoints": {
    "directory_a": "http://127.0.0.1:18081",
    "directory_b": "http://127.0.0.1:28081",
    "issuer_a": "http://127.0.0.1:18082",
    "entry": "http://127.0.0.1:18083",
    "exit": "http://127.0.0.1:18084"
  }
}
EOF_PROFILE_DOCKER_HINT_PROFILE
cat >"$PROFILE_DOCKER_HINT_MATRIX_SUMMARY_JSON" <<EOF_PROFILE_DOCKER_HINT_MATRIX
{
  "version": 1,
  "status": "pass",
  "profiles": [
    {
      "profile": "2hop",
      "status": "pass",
      "artifacts": {
        "summary_json": "$(basename "$PROFILE_DOCKER_HINT_PROFILE_SUMMARY_JSON")"
      }
    }
  ]
}
EOF_PROFILE_DOCKER_HINT_MATRIX
cat >"$PROFILE_NO_GO_INSUFFICIENT_CHECK_SUMMARY_JSON" <<'EOF_PROFILE_NO_GO_INSUFFICIENT_CHECK'
{
  "version": 1,
  "status": "fail",
  "decision": "NO-GO",
  "inputs": {
    "policy": {
      "require_min_runs_total": 3,
      "require_min_runs_with_summary": 3
    }
  },
  "observed": {
    "campaign_status": "pass",
    "trend_status": "warn",
    "runs_total": 2,
    "runs_with_summary": 2
  }
}
EOF_PROFILE_NO_GO_INSUFFICIENT_CHECK
cat >"$PROFILE_SIGNOFF_SUMMARY_JSON" <<EOF_PROFILE_SIGNOFF_NO_GO_INSUFFICIENT
{
  "version": 1,
  "status": "fail",
  "final_rc": 1,
  "failure_stage": "campaign_check",
  "inputs": {
    "refresh_campaign": true
  },
  "decision": {
    "decision": "NO-GO",
    "recommended_profile": "balanced"
  },
  "artifacts": {
    "campaign_check_summary_json": "$(basename "$PROFILE_NO_GO_INSUFFICIENT_CHECK_SUMMARY_JSON")"
  }
}
EOF_PROFILE_SIGNOFF_NO_GO_INSUFFICIENT
EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
./scripts/manual_validation_record.sh \
  --check-id three_machine_docker_readiness \
  --status pass \
  --notes "docker rehearsal endpoints available" \
  --artifact "$PROFILE_DOCKER_HINT_MATRIX_SUMMARY_JSON" \
  --artifact "$PROFILE_DOCKER_HINT_PROFILE_SUMMARY_JSON" \
  --command "./scripts/three_machine_docker_profile_matrix_record.sh --print-summary-json 1" \
  --show-json 0 >/dev/null

PROFILE_NO_GO_INSUFFICIENT_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_profile_no_go_insufficient.log"
EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/profile_no_go_insufficient_summary.json" \
  --report-md "$TMP_DIR/profile_no_go_insufficient_report.md" \
  --print-report 0 \
  --print-summary-json 1 >$PROFILE_NO_GO_INSUFFICIENT_REPORT_LOG

if ! rg -q '\[manual-validation-report\] profile_default_gate_next_command_sudo=sudo \./scripts/easy_node\.sh profile-default-gate-run' $PROFILE_NO_GO_INSUFFICIENT_REPORT_LOG; then
  echo "manual validation report no-go-insufficient run missing profile_default_gate_next_command_sudo line"
  cat $PROFILE_NO_GO_INSUFFICIENT_REPORT_LOG
  exit 1
fi
profile_no_go_insufficient_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' $PROFILE_NO_GO_INSUFFICIENT_REPORT_LOG)"
if [[ -z "$profile_no_go_insufficient_report_json" ]]; then
  echo "manual validation report no-go-insufficient run missing JSON payload"
  cat $PROFILE_NO_GO_INSUFFICIENT_REPORT_LOG
  exit 1
fi
if ! printf '%s\n' "$profile_no_go_insufficient_report_json" | jq -e --arg matrix "$PROFILE_DOCKER_HINT_MATRIX_SUMMARY_JSON" --arg profile "$PROFILE_DOCKER_HINT_PROFILE_SUMMARY_JSON" --arg check_summary "$PROFILE_NO_GO_INSUFFICIENT_CHECK_SUMMARY_JSON" '
  .summary.profile_default_gate.status == "pending"
  and .summary.profile_default_gate.insufficient_evidence == true
  and .summary.profile_default_gate.docker_rehearsal_hint_available == true
  and (.summary.profile_default_gate.next_command | startswith("./scripts/easy_node.sh profile-default-gate-run"))
  and (.summary.profile_default_gate.next_command | contains("--campaign-execution-mode docker") | not)
  and (.summary.profile_default_gate.next_command | contains("--campaign-start-local-stack") | not)
  and (.summary.profile_default_gate.next_command | contains("--campaign-directory-urls") | not)
  and (.summary.profile_default_gate.next_command | contains("--refresh-campaign") | not)
  and (.summary.profile_default_gate.next_command | contains("--fail-on-no-go") | not)
  and (.summary.profile_default_gate.next_command | contains("18081"))
  and (.summary.profile_default_gate.next_command | contains("28081"))
  and (.summary.profile_default_gate.next_command | contains("--campaign-timeout-sec 2400"))
  and (.summary.profile_default_gate.next_command | contains("--campaign-issuer-url http://127.0.0.1:18082"))
  and (.summary.profile_default_gate.next_command | contains("--campaign-entry-url http://127.0.0.1:18083"))
  and (.summary.profile_default_gate.next_command | contains("--campaign-exit-url http://127.0.0.1:18084"))
  and (.summary.profile_default_gate.next_command | contains("--campaign-subject INVITE_KEY"))
  and ((.summary.profile_default_gate.next_command | split("--campaign-subject") | length) == 2)
  and (.summary.profile_default_gate.next_command_sudo | startswith("sudo ./scripts/easy_node.sh profile-default-gate-run"))
  and (.summary.profile_default_gate.next_command_sudo | contains("--campaign-execution-mode docker") | not)
  and (.summary.profile_default_gate.next_command_sudo | contains("--campaign-start-local-stack") | not)
  and (.summary.profile_default_gate.next_command_sudo | contains("--campaign-directory-urls") | not)
  and (.summary.profile_default_gate.next_command_sudo | contains("--refresh-campaign") | not)
  and (.summary.profile_default_gate.next_command_sudo | contains("--fail-on-no-go") | not)
  and (.summary.profile_default_gate.next_command_sudo | contains("--campaign-timeout-sec 2400"))
  and (.summary.profile_default_gate.next_command_sudo | contains("--campaign-subject INVITE_KEY"))
  and ((.summary.profile_default_gate.next_command_sudo | split("--campaign-subject") | length) == 2)
  and (.summary.profile_default_gate.next_command_source | test("docker"))
  and .summary.profile_default_gate.artifacts.docker_rehearsal_matrix_summary_json == $matrix
  and .summary.profile_default_gate.artifacts.docker_rehearsal_profile_summary_json == $profile
  and .summary.profile_default_gate.artifacts.campaign_check_summary_json_resolved == $check_summary
' >/dev/null; then
  echo "manual validation report no-go-insufficient JSON missing docker-hint guidance fields"
  printf '%s\n' "$profile_no_go_insufficient_report_json"
  exit 1
fi

printf '{"version":1,"status":"fail",' >"$PROFILE_SIGNOFF_SUMMARY_JSON"
EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/profile_invalid_summary_summary.json" \
  --report-md "$TMP_DIR/profile_invalid_summary_report.md" \
  --print-report 0 \
  --print-summary-json 1 >$PROFILE_INVALID_SUMMARY_REPORT_LOG

if ! rg -q '\[manual-validation-report\] profile_default_gate_status=pending' $PROFILE_INVALID_SUMMARY_REPORT_LOG; then
  echo "manual validation report profile-invalid-summary run missing profile_default_gate_status=pending line"
  cat $PROFILE_INVALID_SUMMARY_REPORT_LOG
  exit 1
fi
profile_invalid_summary_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' $PROFILE_INVALID_SUMMARY_REPORT_LOG)"
if [[ -z "$profile_invalid_summary_report_json" ]]; then
  echo "manual validation report profile-invalid-summary run missing JSON payload"
  cat $PROFILE_INVALID_SUMMARY_REPORT_LOG
  exit 1
fi
if ! printf '%s\n' "$profile_invalid_summary_report_json" | jq -e '
  .summary.profile_default_gate.status == "pending"
  and .summary.profile_default_gate.available == true
  and .summary.profile_default_gate.valid_json == false
  and (.summary.profile_default_gate.notes | contains("summary JSON is invalid"))
  and (
    (.summary.profile_default_gate.next_command | startswith("./scripts/easy_node.sh profile-default-gate-run"))
    or
    (.summary.profile_default_gate.next_command | startswith("sudo ./scripts/easy_node.sh profile-default-gate-run"))
  )
  and (.summary.profile_default_gate.next_command | contains("--directory-a http://127.0.0.1:18081"))
  and (.summary.profile_default_gate.next_command | contains("--directory-b http://127.0.0.1:28081"))
  and (.summary.profile_default_gate.next_command | contains("--campaign-timeout-sec 2400"))
  and (.summary.profile_default_gate.next_command | contains("--campaign-subject INVITE_KEY"))
  and ((.summary.profile_default_gate.next_command | split("--campaign-subject") | length) == 2)
  and (.summary.profile_default_gate.next_command_sudo | startswith("sudo ./scripts/easy_node.sh profile-default-gate-run"))
  and (.summary.profile_default_gate.next_command_sudo | contains("--directory-a http://127.0.0.1:18081"))
  and (.summary.profile_default_gate.next_command_sudo | contains("--directory-b http://127.0.0.1:28081"))
  and (.summary.profile_default_gate.next_command_sudo | contains("--campaign-timeout-sec 2400"))
  and (.summary.profile_default_gate.next_command_sudo | contains("--campaign-subject INVITE_KEY"))
  and ((.summary.profile_default_gate.next_command_sudo | split("--campaign-subject") | length) == 2)
  and (.summary.profile_default_gate.next_command | contains("--summary-json '"$PROFILE_SIGNOFF_SUMMARY_JSON"'"))
' >/dev/null; then
  echo "manual validation report profile-invalid-summary JSON missing expected profile_default_gate fields"
  printf '%s\n' "$profile_invalid_summary_report_json"
  exit 1
fi

echo "[manual-validation-report] profile-default stability-check fields (valid summary)"
cat >"$STABILITY_VALID_SUMMARY_JSON" <<'EOF_STABILITY_VALID_SUMMARY'
{
  "version": 1,
  "decision": "GO",
  "status": "pass",
  "rc": 0,
  "observed": {
    "modal_recommended_profile": "balanced",
    "modal_support_rate_pct": 66.67
  }
}
EOF_STABILITY_VALID_SUMMARY
cat >"$FAKE_STATUS_STABILITY_VALID" <<EOF_STATUS_STABILITY_VALID
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[manual-validation-status] summary_json_payload:
{
  "version": 1,
  "state_dir": "$STATE_DIR",
  "status_json": "$TMP_DIR/manual_validation_status_stability_valid.json",
  "runtime_doctor": {
    "status": "OK",
    "summary": { "findings_total": 0, "warnings_total": 0, "failures_total": 0 },
    "findings": []
  },
  "checks": [],
  "summary": {
    "total_checks": 0,
    "pass_checks": 0,
    "warn_checks": 0,
    "fail_checks": 0,
    "pending_checks": 0,
    "next_action_check_id": "",
    "next_action_label": "",
    "next_action_command": "",
    "next_action_remediations": [],
    "pre_machine_c_gate": { "ready": true, "blockers": [], "next_check_id": "", "next_command": "" },
    "local_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "" },
    "real_host_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "", "next_label": "", "next_command": "" },
    "profile_default_gate": {
      "enabled": true,
      "available": true,
      "valid_json": true,
      "status": "pass",
      "summary_json": "$PROFILE_SIGNOFF_SUMMARY_JSON",
      "decision": "GO",
      "recommended_profile": "balanced",
      "notes": "",
      "next_command": "",
      "next_command_sudo": "",
      "next_command_source": "default_non_sudo",
      "artifacts": {
        "profile_default_gate_stability_check_summary_json": "$STABILITY_VALID_SUMMARY_JSON"
      }
    },
    "profile_default_ready": true,
    "docker_rehearsal_gate": { "check_id": "three_machine_docker_readiness", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "real_wg_privileged_gate": { "check_id": "real_wg_privileged_matrix", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "single_machine_ready": true,
    "roadmap_stage": "PRODUCTION_SIGNOFF_COMPLETE",
    "latest_failed_incident": null
  }
}
OUT
EOF_STATUS_STABILITY_VALID
chmod +x "$FAKE_STATUS_STABILITY_VALID"

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS_STABILITY_VALID" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/stability_valid_summary.json" \
  --report-md "$TMP_DIR/stability_valid_report.md" \
  --print-report 0 \
  --print-summary-json 1 >"$STABILITY_VALID_REPORT_LOG"

if ! rg -q '\[manual-validation-report\] profile_default_gate_stability_check_summary_available=true' "$STABILITY_VALID_REPORT_LOG"; then
  echo "manual validation report valid-stability run missing stability available=true line"
  cat "$STABILITY_VALID_REPORT_LOG"
  exit 1
fi
stability_valid_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' "$STABILITY_VALID_REPORT_LOG")"
if [[ -z "$stability_valid_report_json" ]]; then
  echo "manual validation report valid-stability run missing JSON payload"
  cat "$STABILITY_VALID_REPORT_LOG"
  exit 1
fi
if ! printf '%s\n' "$stability_valid_report_json" | jq -e --arg stability "$STABILITY_VALID_SUMMARY_JSON" '
  .summary.profile_default_gate.stability_check_summary_json == $stability
  and .summary.profile_default_gate.artifacts.profile_default_gate_stability_check_summary_json == $stability
  and .summary.profile_default_gate.stability_check_summary_available == true
  and .summary.profile_default_gate.stability_check_decision == "GO"
  and .summary.profile_default_gate.stability_check_status == "pass"
  and .summary.profile_default_gate.stability_check_rc == 0
  and .summary.profile_default_gate.stability_check_modal_recommended_profile == "balanced"
  and .summary.profile_default_gate.stability_check_modal_support_rate_pct == 66.67
' >/dev/null; then
  echo "manual validation report valid-stability JSON missing expected fields"
  printf '%s\n' "$stability_valid_report_json"
  exit 1
fi
if ! rg -q 'Stability-check summary available: `true`' "$TMP_DIR/stability_valid_report.md"; then
  echo "manual validation report valid-stability markdown missing availability line"
  cat "$TMP_DIR/stability_valid_report.md"
  exit 1
fi
if ! rg -q 'Stability-check decision/status: decision=`GO`, status=`pass`' "$TMP_DIR/stability_valid_report.md"; then
  echo "manual validation report valid-stability markdown missing decision/status line"
  cat "$TMP_DIR/stability_valid_report.md"
  exit 1
fi
if ! rg -q 'Stability-check rc/modal: rc=`0`, modal_profile=`balanced`, modal_support_rate_pct=`66.67`' "$TMP_DIR/stability_valid_report.md"; then
  echo "manual validation report valid-stability markdown missing rc/modal line"
  cat "$TMP_DIR/stability_valid_report.md"
  exit 1
fi

echo "[manual-validation-report] profile-default stability-check fields (invalid summary fail-closed)"
cat >"$STABILITY_INVALID_SUMMARY_JSON" <<'EOF_STABILITY_INVALID_SUMMARY'
{
  "version": 1,
  "decision": "GO",
  "status": "pass",
  "rc": "0",
  "observed": {
    "modal_recommended_profile": "balanced",
    "modal_support_rate_pct": "66.67"
  }
}
EOF_STABILITY_INVALID_SUMMARY
cat >"$FAKE_STATUS_STABILITY_INVALID" <<EOF_STATUS_STABILITY_INVALID
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[manual-validation-status] summary_json_payload:
{
  "version": 1,
  "state_dir": "$STATE_DIR",
  "status_json": "$TMP_DIR/manual_validation_status_stability_invalid.json",
  "runtime_doctor": {
    "status": "OK",
    "summary": { "findings_total": 0, "warnings_total": 0, "failures_total": 0 },
    "findings": []
  },
  "checks": [],
  "summary": {
    "total_checks": 0,
    "pass_checks": 0,
    "warn_checks": 0,
    "fail_checks": 0,
    "pending_checks": 0,
    "next_action_check_id": "",
    "next_action_label": "",
    "next_action_command": "",
    "next_action_remediations": [],
    "pre_machine_c_gate": { "ready": true, "blockers": [], "next_check_id": "", "next_command": "" },
    "local_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "" },
    "real_host_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "", "next_label": "", "next_command": "" },
    "profile_default_gate": {
      "enabled": true,
      "available": true,
      "valid_json": true,
      "status": "pass",
      "summary_json": "$PROFILE_SIGNOFF_SUMMARY_JSON",
      "decision": "GO",
      "recommended_profile": "balanced",
      "notes": "",
      "next_command": "",
      "next_command_sudo": "",
      "next_command_source": "default_non_sudo",
      "artifacts": {
        "profile_default_gate_stability_check_summary_json": "$STABILITY_INVALID_SUMMARY_JSON"
      }
    },
    "profile_default_ready": true,
    "docker_rehearsal_gate": { "check_id": "three_machine_docker_readiness", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "real_wg_privileged_gate": { "check_id": "real_wg_privileged_matrix", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "single_machine_ready": true,
    "roadmap_stage": "PRODUCTION_SIGNOFF_COMPLETE",
    "latest_failed_incident": null
  }
}
OUT
EOF_STATUS_STABILITY_INVALID
chmod +x "$FAKE_STATUS_STABILITY_INVALID"

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS_STABILITY_INVALID" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/stability_invalid_summary.json" \
  --report-md "$TMP_DIR/stability_invalid_report.md" \
  --print-report 0 \
  --print-summary-json 1 >"$STABILITY_INVALID_REPORT_LOG"

if ! rg -q '\[manual-validation-report\] profile_default_gate_stability_check_summary_available=false' "$STABILITY_INVALID_REPORT_LOG"; then
  echo "manual validation report invalid-stability run missing stability available=false line"
  cat "$STABILITY_INVALID_REPORT_LOG"
  exit 1
fi
stability_invalid_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' "$STABILITY_INVALID_REPORT_LOG")"
if [[ -z "$stability_invalid_report_json" ]]; then
  echo "manual validation report invalid-stability run missing JSON payload"
  cat "$STABILITY_INVALID_REPORT_LOG"
  exit 1
fi
if ! printf '%s\n' "$stability_invalid_report_json" | jq -e --arg stability "$STABILITY_INVALID_SUMMARY_JSON" '
  .summary.profile_default_gate.stability_check_summary_json == $stability
  and .summary.profile_default_gate.artifacts.profile_default_gate_stability_check_summary_json == $stability
  and .summary.profile_default_gate.stability_check_summary_available == false
  and .summary.profile_default_gate.stability_check_decision == null
  and .summary.profile_default_gate.stability_check_status == null
  and .summary.profile_default_gate.stability_check_rc == null
  and .summary.profile_default_gate.stability_check_modal_recommended_profile == null
  and .summary.profile_default_gate.stability_check_modal_support_rate_pct == null
' >/dev/null; then
  echo "manual validation report invalid-stability JSON missing expected fail-closed fields"
  printf '%s\n' "$stability_invalid_report_json"
  exit 1
fi

echo "[manual-validation-report] profile-default stability-check fields (missing default artifact path)"
printf '%s\n' '{"version":1,"status":"ok"}' >"$STABILITY_DEFAULT_SIGNOFF_SUMMARY_JSON"
rm -f "$STABILITY_DEFAULT_EXPECTED_SUMMARY_JSON"
cat >"$FAKE_STATUS_STABILITY_DEFAULT_MISSING" <<EOF_STATUS_STABILITY_DEFAULT_MISSING
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[manual-validation-status] summary_json_payload:
{
  "version": 1,
  "state_dir": "$STATE_DIR",
  "status_json": "$TMP_DIR/manual_validation_status_stability_default_missing.json",
  "runtime_doctor": {
    "status": "OK",
    "summary": { "findings_total": 0, "warnings_total": 0, "failures_total": 0 },
    "findings": []
  },
  "checks": [],
  "summary": {
    "total_checks": 0,
    "pass_checks": 0,
    "warn_checks": 0,
    "fail_checks": 0,
    "pending_checks": 0,
    "next_action_check_id": "",
    "next_action_label": "",
    "next_action_command": "",
    "next_action_remediations": [],
    "pre_machine_c_gate": { "ready": true, "blockers": [], "next_check_id": "", "next_command": "" },
    "local_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "" },
    "real_host_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "", "next_label": "", "next_command": "" },
    "profile_default_gate": {
      "enabled": true,
      "available": true,
      "valid_json": true,
      "status": "pass",
      "summary_json": "$STABILITY_DEFAULT_SIGNOFF_SUMMARY_JSON",
      "decision": "GO",
      "recommended_profile": "balanced",
      "notes": "",
      "next_command": "",
      "next_command_sudo": "",
      "next_command_source": "default_non_sudo",
      "artifacts": {}
    },
    "profile_default_ready": true,
    "docker_rehearsal_gate": { "check_id": "three_machine_docker_readiness", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "real_wg_privileged_gate": { "check_id": "real_wg_privileged_matrix", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "single_machine_ready": true,
    "roadmap_stage": "PRODUCTION_SIGNOFF_COMPLETE",
    "latest_failed_incident": null
  }
}
OUT
EOF_STATUS_STABILITY_DEFAULT_MISSING
chmod +x "$FAKE_STATUS_STABILITY_DEFAULT_MISSING"

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS_STABILITY_DEFAULT_MISSING" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/stability_default_missing_summary.json" \
  --report-md "$TMP_DIR/stability_default_missing_report.md" \
  --print-report 0 \
  --print-summary-json 1 >"$STABILITY_DEFAULT_MISSING_REPORT_LOG"

if ! rg -q '\[manual-validation-report\] profile_default_gate_stability_check_summary_available=false' "$STABILITY_DEFAULT_MISSING_REPORT_LOG"; then
  echo "manual validation report missing-default-stability run missing stability available=false line"
  cat "$STABILITY_DEFAULT_MISSING_REPORT_LOG"
  exit 1
fi
if ! rg -q "\[manual-validation-report\] profile_default_gate_stability_check_summary_json=${STABILITY_DEFAULT_EXPECTED_SUMMARY_JSON}" "$STABILITY_DEFAULT_MISSING_REPORT_LOG"; then
  echo "manual validation report missing-default-stability run missing default summary path line"
  cat "$STABILITY_DEFAULT_MISSING_REPORT_LOG"
  exit 1
fi
stability_default_missing_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' "$STABILITY_DEFAULT_MISSING_REPORT_LOG")"
if [[ -z "$stability_default_missing_report_json" ]]; then
  echo "manual validation report missing-default-stability run missing JSON payload"
  cat "$STABILITY_DEFAULT_MISSING_REPORT_LOG"
  exit 1
fi
if ! printf '%s\n' "$stability_default_missing_report_json" | jq -e --arg expected "$STABILITY_DEFAULT_EXPECTED_SUMMARY_JSON" '
  .summary.profile_default_gate.stability_check_summary_json == $expected
  and .summary.profile_default_gate.artifacts.profile_default_gate_stability_check_summary_json == $expected
  and .summary.profile_default_gate.stability_check_summary_available == false
  and .summary.profile_default_gate.stability_check_decision == null
  and .summary.profile_default_gate.stability_check_status == null
  and .summary.profile_default_gate.stability_check_rc == null
  and .summary.profile_default_gate.stability_check_modal_recommended_profile == null
  and .summary.profile_default_gate.stability_check_modal_support_rate_pct == null
' >/dev/null; then
  echo "manual validation report missing-default-stability JSON missing expected fail-closed fields"
  printf '%s\n' "$stability_default_missing_report_json"
  exit 1
fi

echo "[manual-validation-report] profile-default stability-cycle fields (valid summary)"
cat >"$CYCLE_VALID_SUMMARY_JSON" <<'EOF_CYCLE_VALID_SUMMARY'
{
  "version": 1,
  "status": "pass",
  "decision": "GO",
  "rc": 0,
  "failure_stage": null,
  "failure_reason": null
}
EOF_CYCLE_VALID_SUMMARY
cat >"$FAKE_STATUS_CYCLE_VALID" <<EOF_STATUS_CYCLE_VALID
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[manual-validation-status] summary_json_payload:
{
  "version": 1,
  "state_dir": "$STATE_DIR",
  "status_json": "$TMP_DIR/manual_validation_status_cycle_valid.json",
  "runtime_doctor": {
    "status": "OK",
    "summary": { "findings_total": 0, "warnings_total": 0, "failures_total": 0 },
    "findings": []
  },
  "checks": [],
  "summary": {
    "total_checks": 0,
    "pass_checks": 0,
    "warn_checks": 0,
    "fail_checks": 0,
    "pending_checks": 0,
    "next_action_check_id": "",
    "next_action_label": "",
    "next_action_command": "",
    "next_action_remediations": [],
    "pre_machine_c_gate": { "ready": true, "blockers": [], "next_check_id": "", "next_command": "" },
    "local_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "" },
    "real_host_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "", "next_label": "", "next_command": "" },
    "profile_default_gate": {
      "enabled": true,
      "available": true,
      "valid_json": true,
      "status": "pass",
      "summary_json": "$PROFILE_SIGNOFF_SUMMARY_JSON",
      "decision": "GO",
      "recommended_profile": "balanced",
      "notes": "",
      "next_command": "",
      "next_command_sudo": "",
      "next_command_source": "default_non_sudo",
      "artifacts": {
        "profile_default_gate_stability_cycle_summary_json": "$CYCLE_VALID_SUMMARY_JSON"
      }
    },
    "profile_default_ready": true,
    "docker_rehearsal_gate": { "check_id": "three_machine_docker_readiness", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "real_wg_privileged_gate": { "check_id": "real_wg_privileged_matrix", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "single_machine_ready": true,
    "roadmap_stage": "PRODUCTION_SIGNOFF_COMPLETE",
    "latest_failed_incident": null
  }
}
OUT
EOF_STATUS_CYCLE_VALID
chmod +x "$FAKE_STATUS_CYCLE_VALID"

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS_CYCLE_VALID" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/cycle_valid_summary.json" \
  --report-md "$TMP_DIR/cycle_valid_report.md" \
  --print-report 0 \
  --print-summary-json 1 >"$CYCLE_VALID_REPORT_LOG"

if ! rg -q '\[manual-validation-report\] profile_default_gate_stability_cycle_summary_available=true' "$CYCLE_VALID_REPORT_LOG"; then
  echo "manual validation report valid-cycle run missing cycle available=true line"
  cat "$CYCLE_VALID_REPORT_LOG"
  exit 1
fi
cycle_valid_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' "$CYCLE_VALID_REPORT_LOG")"
if [[ -z "$cycle_valid_report_json" ]]; then
  echo "manual validation report valid-cycle run missing JSON payload"
  cat "$CYCLE_VALID_REPORT_LOG"
  exit 1
fi
if ! printf '%s\n' "$cycle_valid_report_json" | jq -e --arg cycle "$CYCLE_VALID_SUMMARY_JSON" '
  .summary.profile_default_gate.cycle_summary_json == $cycle
  and .summary.profile_default_gate.artifacts.profile_default_gate_stability_cycle_summary_json == $cycle
  and .summary.profile_default_gate.cycle_summary_available == true
  and .summary.profile_default_gate.cycle_decision == "GO"
  and .summary.profile_default_gate.cycle_status == "pass"
  and .summary.profile_default_gate.cycle_rc == 0
  and .summary.profile_default_gate.cycle_failure_stage == null
  and .summary.profile_default_gate.cycle_failure_reason == null
' >/dev/null; then
  echo "manual validation report valid-cycle JSON missing expected fields"
  printf '%s\n' "$cycle_valid_report_json"
  exit 1
fi
if ! rg -q 'Stability-cycle summary available: `true`' "$TMP_DIR/cycle_valid_report.md"; then
  echo "manual validation report valid-cycle markdown missing availability line"
  cat "$TMP_DIR/cycle_valid_report.md"
  exit 1
fi
if ! rg -q 'Stability-cycle decision/status: decision=`GO`, status=`pass`' "$TMP_DIR/cycle_valid_report.md"; then
  echo "manual validation report valid-cycle markdown missing decision/status line"
  cat "$TMP_DIR/cycle_valid_report.md"
  exit 1
fi

echo "[manual-validation-report] profile-default stability-cycle fields (invalid summary fail-closed)"
cat >"$CYCLE_INVALID_SUMMARY_JSON" <<'EOF_CYCLE_INVALID_SUMMARY'
{
  "version": 1,
  "status": "pass",
  "decision": "GO",
  "rc": "0"
}
EOF_CYCLE_INVALID_SUMMARY
cat >"$FAKE_STATUS_CYCLE_INVALID" <<EOF_STATUS_CYCLE_INVALID
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[manual-validation-status] summary_json_payload:
{
  "version": 1,
  "state_dir": "$STATE_DIR",
  "status_json": "$TMP_DIR/manual_validation_status_cycle_invalid.json",
  "runtime_doctor": {
    "status": "OK",
    "summary": { "findings_total": 0, "warnings_total": 0, "failures_total": 0 },
    "findings": []
  },
  "checks": [],
  "summary": {
    "total_checks": 0,
    "pass_checks": 0,
    "warn_checks": 0,
    "fail_checks": 0,
    "pending_checks": 0,
    "next_action_check_id": "",
    "next_action_label": "",
    "next_action_command": "",
    "next_action_remediations": [],
    "pre_machine_c_gate": { "ready": true, "blockers": [], "next_check_id": "", "next_command": "" },
    "local_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "" },
    "real_host_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "", "next_label": "", "next_command": "" },
    "profile_default_gate": {
      "enabled": true,
      "available": true,
      "valid_json": true,
      "status": "pass",
      "summary_json": "$PROFILE_SIGNOFF_SUMMARY_JSON",
      "decision": "GO",
      "recommended_profile": "balanced",
      "notes": "",
      "next_command": "",
      "next_command_sudo": "",
      "next_command_source": "default_non_sudo",
      "artifacts": {
        "profile_default_gate_stability_cycle_summary_json": "$CYCLE_INVALID_SUMMARY_JSON"
      }
    },
    "profile_default_ready": true,
    "docker_rehearsal_gate": { "check_id": "three_machine_docker_readiness", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "real_wg_privileged_gate": { "check_id": "real_wg_privileged_matrix", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "single_machine_ready": true,
    "roadmap_stage": "PRODUCTION_SIGNOFF_COMPLETE",
    "latest_failed_incident": null
  }
}
OUT
EOF_STATUS_CYCLE_INVALID
chmod +x "$FAKE_STATUS_CYCLE_INVALID"

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS_CYCLE_INVALID" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/cycle_invalid_summary.json" \
  --report-md "$TMP_DIR/cycle_invalid_report.md" \
  --print-report 0 \
  --print-summary-json 1 >"$CYCLE_INVALID_REPORT_LOG"

if ! rg -q '\[manual-validation-report\] profile_default_gate_stability_cycle_summary_available=false' "$CYCLE_INVALID_REPORT_LOG"; then
  echo "manual validation report invalid-cycle run missing cycle available=false line"
  cat "$CYCLE_INVALID_REPORT_LOG"
  exit 1
fi
cycle_invalid_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' "$CYCLE_INVALID_REPORT_LOG")"
if [[ -z "$cycle_invalid_report_json" ]]; then
  echo "manual validation report invalid-cycle run missing JSON payload"
  cat "$CYCLE_INVALID_REPORT_LOG"
  exit 1
fi
if ! printf '%s\n' "$cycle_invalid_report_json" | jq -e --arg cycle "$CYCLE_INVALID_SUMMARY_JSON" '
  .summary.profile_default_gate.cycle_summary_json == $cycle
  and .summary.profile_default_gate.artifacts.profile_default_gate_stability_cycle_summary_json == $cycle
  and .summary.profile_default_gate.cycle_summary_available == false
  and .summary.profile_default_gate.cycle_decision == null
  and .summary.profile_default_gate.cycle_status == null
  and .summary.profile_default_gate.cycle_rc == null
  and .summary.profile_default_gate.cycle_failure_stage == null
  and .summary.profile_default_gate.cycle_failure_reason == null
' >/dev/null; then
  echo "manual validation report invalid-cycle JSON missing expected fail-closed fields"
  printf '%s\n' "$cycle_invalid_report_json"
  exit 1
fi

echo "[manual-validation-report] profile-default stability-cycle fields (missing default artifact path)"
printf '%s\n' '{"version":1,"status":"ok"}' >"$CYCLE_DEFAULT_SIGNOFF_SUMMARY_JSON"
rm -f "$CYCLE_DEFAULT_EXPECTED_SUMMARY_JSON"
cat >"$FAKE_STATUS_CYCLE_DEFAULT_MISSING" <<EOF_STATUS_CYCLE_DEFAULT_MISSING
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[manual-validation-status] summary_json_payload:
{
  "version": 1,
  "state_dir": "$STATE_DIR",
  "status_json": "$TMP_DIR/manual_validation_status_cycle_default_missing.json",
  "runtime_doctor": {
    "status": "OK",
    "summary": { "findings_total": 0, "warnings_total": 0, "failures_total": 0 },
    "findings": []
  },
  "checks": [],
  "summary": {
    "total_checks": 0,
    "pass_checks": 0,
    "warn_checks": 0,
    "fail_checks": 0,
    "pending_checks": 0,
    "next_action_check_id": "",
    "next_action_label": "",
    "next_action_command": "",
    "next_action_remediations": [],
    "pre_machine_c_gate": { "ready": true, "blockers": [], "next_check_id": "", "next_command": "" },
    "local_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "" },
    "real_host_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "", "next_label": "", "next_command": "" },
    "profile_default_gate": {
      "enabled": true,
      "available": true,
      "valid_json": true,
      "status": "pass",
      "summary_json": "$CYCLE_DEFAULT_SIGNOFF_SUMMARY_JSON",
      "decision": "GO",
      "recommended_profile": "balanced",
      "notes": "",
      "next_command": "",
      "next_command_sudo": "",
      "next_command_source": "default_non_sudo",
      "artifacts": {}
    },
    "profile_default_ready": true,
    "docker_rehearsal_gate": { "check_id": "three_machine_docker_readiness", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "real_wg_privileged_gate": { "check_id": "real_wg_privileged_matrix", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "single_machine_ready": true,
    "roadmap_stage": "PRODUCTION_SIGNOFF_COMPLETE",
    "latest_failed_incident": null
  }
}
OUT
EOF_STATUS_CYCLE_DEFAULT_MISSING
chmod +x "$FAKE_STATUS_CYCLE_DEFAULT_MISSING"

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS_CYCLE_DEFAULT_MISSING" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/cycle_default_missing_summary.json" \
  --report-md "$TMP_DIR/cycle_default_missing_report.md" \
  --print-report 0 \
  --print-summary-json 1 >"$CYCLE_DEFAULT_MISSING_REPORT_LOG"

if ! rg -q '\[manual-validation-report\] profile_default_gate_stability_cycle_summary_available=false' "$CYCLE_DEFAULT_MISSING_REPORT_LOG"; then
  echo "manual validation report missing-default-cycle run missing cycle available=false line"
  cat "$CYCLE_DEFAULT_MISSING_REPORT_LOG"
  exit 1
fi
if ! rg -q "\[manual-validation-report\] profile_default_gate_stability_cycle_summary_json=${CYCLE_DEFAULT_EXPECTED_SUMMARY_JSON}" "$CYCLE_DEFAULT_MISSING_REPORT_LOG"; then
  echo "manual validation report missing-default-cycle run missing default summary path line"
  cat "$CYCLE_DEFAULT_MISSING_REPORT_LOG"
  exit 1
fi
cycle_default_missing_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' "$CYCLE_DEFAULT_MISSING_REPORT_LOG")"
if [[ -z "$cycle_default_missing_report_json" ]]; then
  echo "manual validation report missing-default-cycle run missing JSON payload"
  cat "$CYCLE_DEFAULT_MISSING_REPORT_LOG"
  exit 1
fi
if ! printf '%s\n' "$cycle_default_missing_report_json" | jq -e --arg expected "$CYCLE_DEFAULT_EXPECTED_SUMMARY_JSON" '
  .summary.profile_default_gate.cycle_summary_json == $expected
  and .summary.profile_default_gate.artifacts.profile_default_gate_stability_cycle_summary_json == $expected
  and .summary.profile_default_gate.cycle_summary_available == false
  and .summary.profile_default_gate.cycle_decision == null
  and .summary.profile_default_gate.cycle_status == null
  and .summary.profile_default_gate.cycle_rc == null
  and .summary.profile_default_gate.cycle_failure_stage == null
  and .summary.profile_default_gate.cycle_failure_reason == null
' >/dev/null; then
  echo "manual validation report missing-default-cycle JSON missing expected fail-closed fields"
  printf '%s\n' "$cycle_default_missing_report_json"
  exit 1
fi

echo "[manual-validation-report] profile-default multi-vm stability fields (valid check summary)"
cat >"$MULTI_VM_STABILITY_CHECK_VALID_SUMMARY_JSON" <<'EOF_MULTI_VM_STABILITY_CHECK_VALID_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_check_summary"
  },
  "status": "ok",
  "decision": "GO",
  "rc": 0,
  "observed": {
    "modal_recommended_profile": "balanced",
    "modal_support_rate_pct": 73.5
  }
}
EOF_MULTI_VM_STABILITY_CHECK_VALID_SUMMARY
cat >"$FAKE_STATUS_MULTI_VM_STABILITY_VALID" <<EOF_STATUS_MULTI_VM_STABILITY_VALID
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[manual-validation-status] summary_json_payload:
{
  "version": 1,
  "state_dir": "$STATE_DIR",
  "status_json": "$TMP_DIR/manual_validation_status_multi_vm_stability_valid.json",
  "runtime_doctor": {
    "status": "OK",
    "summary": { "findings_total": 0, "warnings_total": 0, "failures_total": 0 },
    "findings": []
  },
  "checks": [],
  "summary": {
    "total_checks": 0,
    "pass_checks": 0,
    "warn_checks": 0,
    "fail_checks": 0,
    "pending_checks": 0,
    "next_action_check_id": "",
    "next_action_label": "",
    "next_action_command": "",
    "next_action_remediations": [],
    "pre_machine_c_gate": { "ready": true, "blockers": [], "next_check_id": "", "next_command": "" },
    "local_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "" },
    "real_host_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "", "next_label": "", "next_command": "" },
    "profile_default_gate": {
      "enabled": true,
      "available": true,
      "valid_json": true,
      "status": "pass",
      "summary_json": "$PROFILE_SIGNOFF_SUMMARY_JSON",
      "decision": "GO",
      "recommended_profile": "balanced",
      "notes": "",
      "next_command": "",
      "next_command_sudo": "",
      "next_command_source": "default_non_sudo",
      "artifacts": {
        "profile_compare_multi_vm_stability_check_summary_json": "$MULTI_VM_STABILITY_CHECK_VALID_SUMMARY_JSON"
      }
    },
    "profile_default_ready": true,
    "docker_rehearsal_gate": { "check_id": "three_machine_docker_readiness", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "real_wg_privileged_gate": { "check_id": "real_wg_privileged_matrix", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "single_machine_ready": true,
    "roadmap_stage": "PRODUCTION_SIGNOFF_COMPLETE",
    "latest_failed_incident": null
  }
}
OUT
EOF_STATUS_MULTI_VM_STABILITY_VALID
chmod +x "$FAKE_STATUS_MULTI_VM_STABILITY_VALID"

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS_MULTI_VM_STABILITY_VALID" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/multi_vm_stability_valid_summary.json" \
  --report-md "$TMP_DIR/multi_vm_stability_valid_report.md" \
  --print-report 0 \
  --print-summary-json 1 >"$MULTI_VM_STABILITY_VALID_REPORT_LOG"

if ! rg -q '\[manual-validation-report\] profile_default_gate_multi_vm_stability_available=true' "$MULTI_VM_STABILITY_VALID_REPORT_LOG"; then
  echo "manual validation report multi-vm valid run missing availability=true line"
  cat "$MULTI_VM_STABILITY_VALID_REPORT_LOG"
  exit 1
fi
if ! rg -q '\[manual-validation-report\] profile_default_gate_multi_vm_stability_source=check_summary' "$MULTI_VM_STABILITY_VALID_REPORT_LOG"; then
  echo "manual validation report multi-vm valid run missing source=check_summary line"
  cat "$MULTI_VM_STABILITY_VALID_REPORT_LOG"
  exit 1
fi
multi_vm_stability_valid_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' "$MULTI_VM_STABILITY_VALID_REPORT_LOG")"
if [[ -z "$multi_vm_stability_valid_report_json" ]]; then
  echo "manual validation report multi-vm valid run missing JSON payload"
  cat "$MULTI_VM_STABILITY_VALID_REPORT_LOG"
  exit 1
fi
if ! printf '%s\n' "$multi_vm_stability_valid_report_json" | jq -e --arg check "$MULTI_VM_STABILITY_CHECK_VALID_SUMMARY_JSON" '
  .summary.profile_default_gate.artifacts.profile_compare_multi_vm_stability_check_summary_json == $check
  and .summary.profile_default_gate.multi_vm_stability_check_summary_json == $check
  and .summary.profile_default_gate.multi_vm_stability_check_summary_available == true
  and .summary.profile_default_gate.multi_vm_stability_check_status == "ok"
  and .summary.profile_default_gate.multi_vm_stability_check_decision == "GO"
  and .summary.profile_default_gate.multi_vm_stability_check_go == true
  and .summary.profile_default_gate.multi_vm_stability_check_no_go == false
  and .summary.profile_default_gate.multi_vm_stability_check_modal_recommended_profile == "balanced"
  and .summary.profile_default_gate.multi_vm_stability_check_modal_support_rate_pct == 73.5
  and .summary.profile_default_gate.multi_vm_stability_summary_json == $check
  and .summary.profile_default_gate.multi_vm_stability_source == "check_summary"
  and .summary.profile_default_gate.multi_vm_stability_available == true
  and .summary.profile_default_gate.multi_vm_stability_status == "ok"
  and .summary.profile_default_gate.multi_vm_stability_decision == "GO"
  and .summary.profile_default_gate.multi_vm_stability_go == true
  and .summary.profile_default_gate.multi_vm_stability_no_go == false
  and .summary.profile_default_gate.multi_vm_stability_modal_recommended_profile == "balanced"
  and .summary.profile_default_gate.multi_vm_stability_modal_support_rate_pct == 73.5
' >/dev/null; then
  echo "manual validation report multi-vm valid JSON missing expected fields"
  printf '%s\n' "$multi_vm_stability_valid_report_json"
  exit 1
fi
if ! rg -q 'Multi-VM stability source: `check_summary`' "$TMP_DIR/multi_vm_stability_valid_report.md"; then
  echo "manual validation report multi-vm valid markdown missing source line"
  cat "$TMP_DIR/multi_vm_stability_valid_report.md"
  exit 1
fi

echo "[manual-validation-report] profile-default multi-vm stability fields (cycle fallback)"
cat >"$MULTI_VM_STABILITY_CHECK_INVALID_SUMMARY_JSON" <<'EOF_MULTI_VM_STABILITY_CHECK_INVALID_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_check_summary"
  },
  "status": "ok",
  "decision": "GO",
  "rc": "0",
  "observed": {
    "modal_recommended_profile": "balanced"
  }
}
EOF_MULTI_VM_STABILITY_CHECK_INVALID_SUMMARY
cat >"$MULTI_VM_STABILITY_CYCLE_VALID_SUMMARY_JSON" <<'EOF_MULTI_VM_STABILITY_CYCLE_VALID_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_cycle_summary"
  },
  "status": "warn",
  "decision": "NO-GO",
  "rc": 0,
  "failure_stage": null,
  "failure_reason": null,
  "check": {
    "modal_recommended_profile": "private",
    "modal_support_rate_pct": 61.2
  }
}
EOF_MULTI_VM_STABILITY_CYCLE_VALID_SUMMARY
cat >"$FAKE_STATUS_MULTI_VM_STABILITY_CYCLE_FALLBACK" <<EOF_STATUS_MULTI_VM_STABILITY_CYCLE_FALLBACK
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[manual-validation-status] summary_json_payload:
{
  "version": 1,
  "state_dir": "$STATE_DIR",
  "status_json": "$TMP_DIR/manual_validation_status_multi_vm_stability_cycle_fallback.json",
  "runtime_doctor": {
    "status": "OK",
    "summary": { "findings_total": 0, "warnings_total": 0, "failures_total": 0 },
    "findings": []
  },
  "checks": [],
  "summary": {
    "total_checks": 0,
    "pass_checks": 0,
    "warn_checks": 0,
    "fail_checks": 0,
    "pending_checks": 0,
    "next_action_check_id": "",
    "next_action_label": "",
    "next_action_command": "",
    "next_action_remediations": [],
    "pre_machine_c_gate": { "ready": true, "blockers": [], "next_check_id": "", "next_command": "" },
    "local_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "" },
    "real_host_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "", "next_label": "", "next_command": "" },
    "profile_default_gate": {
      "enabled": true,
      "available": true,
      "valid_json": true,
      "status": "pass",
      "summary_json": "$PROFILE_SIGNOFF_SUMMARY_JSON",
      "decision": "GO",
      "recommended_profile": "balanced",
      "notes": "",
      "next_command": "",
      "next_command_sudo": "",
      "next_command_source": "default_non_sudo",
      "artifacts": {
        "profile_compare_multi_vm_stability_check_summary_json": "$MULTI_VM_STABILITY_CHECK_INVALID_SUMMARY_JSON",
        "profile_compare_multi_vm_stability_cycle_summary_json": "$MULTI_VM_STABILITY_CYCLE_VALID_SUMMARY_JSON"
      }
    },
    "profile_default_ready": true,
    "docker_rehearsal_gate": { "check_id": "three_machine_docker_readiness", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "real_wg_privileged_gate": { "check_id": "real_wg_privileged_matrix", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "single_machine_ready": true,
    "roadmap_stage": "PRODUCTION_SIGNOFF_COMPLETE",
    "latest_failed_incident": null
  }
}
OUT
EOF_STATUS_MULTI_VM_STABILITY_CYCLE_FALLBACK
chmod +x "$FAKE_STATUS_MULTI_VM_STABILITY_CYCLE_FALLBACK"

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS_MULTI_VM_STABILITY_CYCLE_FALLBACK" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/multi_vm_stability_cycle_fallback_summary.json" \
  --report-md "$TMP_DIR/multi_vm_stability_cycle_fallback_report.md" \
  --print-report 0 \
  --print-summary-json 1 >"$MULTI_VM_STABILITY_CYCLE_FALLBACK_REPORT_LOG"

if ! rg -q '\[manual-validation-report\] profile_default_gate_multi_vm_stability_source=cycle_summary' "$MULTI_VM_STABILITY_CYCLE_FALLBACK_REPORT_LOG"; then
  echo "manual validation report multi-vm cycle-fallback run missing source=cycle_summary line"
  cat "$MULTI_VM_STABILITY_CYCLE_FALLBACK_REPORT_LOG"
  exit 1
fi
multi_vm_stability_cycle_fallback_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' "$MULTI_VM_STABILITY_CYCLE_FALLBACK_REPORT_LOG")"
if [[ -z "$multi_vm_stability_cycle_fallback_report_json" ]]; then
  echo "manual validation report multi-vm cycle-fallback run missing JSON payload"
  cat "$MULTI_VM_STABILITY_CYCLE_FALLBACK_REPORT_LOG"
  exit 1
fi
if ! printf '%s\n' "$multi_vm_stability_cycle_fallback_report_json" | jq -e --arg check "$MULTI_VM_STABILITY_CHECK_INVALID_SUMMARY_JSON" --arg cycle "$MULTI_VM_STABILITY_CYCLE_VALID_SUMMARY_JSON" '
  .summary.profile_default_gate.artifacts.profile_compare_multi_vm_stability_check_summary_json == $check
  and .summary.profile_default_gate.artifacts.profile_compare_multi_vm_stability_cycle_summary_json == $cycle
  and .summary.profile_default_gate.multi_vm_stability_check_summary_json == $check
  and .summary.profile_default_gate.multi_vm_stability_check_summary_available == false
  and .summary.profile_default_gate.multi_vm_stability_cycle_summary_json == $cycle
  and .summary.profile_default_gate.multi_vm_stability_cycle_summary_available == true
  and .summary.profile_default_gate.multi_vm_stability_cycle_decision == "NO-GO"
  and .summary.profile_default_gate.multi_vm_stability_cycle_status == "warn"
  and .summary.profile_default_gate.multi_vm_stability_cycle_go == false
  and .summary.profile_default_gate.multi_vm_stability_cycle_no_go == true
  and .summary.profile_default_gate.multi_vm_stability_cycle_modal_recommended_profile == "private"
  and .summary.profile_default_gate.multi_vm_stability_cycle_modal_support_rate_pct == 61.2
  and .summary.profile_default_gate.multi_vm_stability_summary_json == $cycle
  and .summary.profile_default_gate.multi_vm_stability_source == "cycle_summary"
  and .summary.profile_default_gate.multi_vm_stability_available == true
  and .summary.profile_default_gate.multi_vm_stability_decision == "NO-GO"
  and .summary.profile_default_gate.multi_vm_stability_status == "warn"
  and .summary.profile_default_gate.multi_vm_stability_go == false
  and .summary.profile_default_gate.multi_vm_stability_no_go == true
  and .summary.profile_default_gate.multi_vm_stability_modal_recommended_profile == "private"
  and .summary.profile_default_gate.multi_vm_stability_modal_support_rate_pct == 61.2
' >/dev/null; then
  echo "manual validation report multi-vm cycle-fallback JSON missing expected fields"
  printf '%s\n' "$multi_vm_stability_cycle_fallback_report_json"
  exit 1
fi

echo "[manual-validation-report] profile-default multi-vm stability fields (missing default artifact paths)"
printf '%s\n' '{"version":1,"status":"ok"}' >"$PROFILE_SIGNOFF_SUMMARY_JSON"
rm -f "$MULTI_VM_STABILITY_CHECK_DEFAULT_EXPECTED_SUMMARY_JSON" "$MULTI_VM_STABILITY_CYCLE_DEFAULT_EXPECTED_SUMMARY_JSON"
cat >"$FAKE_STATUS_MULTI_VM_STABILITY_DEFAULT_MISSING" <<EOF_STATUS_MULTI_VM_STABILITY_DEFAULT_MISSING
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[manual-validation-status] summary_json_payload:
{
  "version": 1,
  "state_dir": "$STATE_DIR",
  "status_json": "$TMP_DIR/manual_validation_status_multi_vm_stability_default_missing.json",
  "runtime_doctor": {
    "status": "OK",
    "summary": { "findings_total": 0, "warnings_total": 0, "failures_total": 0 },
    "findings": []
  },
  "checks": [],
  "summary": {
    "total_checks": 0,
    "pass_checks": 0,
    "warn_checks": 0,
    "fail_checks": 0,
    "pending_checks": 0,
    "next_action_check_id": "",
    "next_action_label": "",
    "next_action_command": "",
    "next_action_remediations": [],
    "pre_machine_c_gate": { "ready": true, "blockers": [], "next_check_id": "", "next_command": "" },
    "local_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "" },
    "real_host_gate": { "ready": true, "check_ids": [], "blockers": [], "next_check_id": "", "next_label": "", "next_command": "" },
    "profile_default_gate": {
      "enabled": true,
      "available": true,
      "valid_json": true,
      "status": "pass",
      "summary_json": "$PROFILE_SIGNOFF_SUMMARY_JSON",
      "decision": "GO",
      "recommended_profile": "balanced",
      "notes": "",
      "next_command": "",
      "next_command_sudo": "",
      "next_command_source": "default_non_sudo",
      "artifacts": {}
    },
    "profile_default_ready": true,
    "docker_rehearsal_gate": { "check_id": "three_machine_docker_readiness", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "real_wg_privileged_gate": { "check_id": "real_wg_privileged_matrix", "status": "pass", "notes": "", "command": "", "next_command": "", "ready": true },
    "single_machine_ready": true,
    "roadmap_stage": "PRODUCTION_SIGNOFF_COMPLETE",
    "latest_failed_incident": null
  }
}
OUT
EOF_STATUS_MULTI_VM_STABILITY_DEFAULT_MISSING
chmod +x "$FAKE_STATUS_MULTI_VM_STABILITY_DEFAULT_MISSING"

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS_MULTI_VM_STABILITY_DEFAULT_MISSING" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_report.sh \
  --summary-json "$TMP_DIR/multi_vm_stability_default_missing_summary.json" \
  --report-md "$TMP_DIR/multi_vm_stability_default_missing_report.md" \
  --print-report 0 \
  --print-summary-json 1 >"$MULTI_VM_STABILITY_DEFAULT_MISSING_REPORT_LOG"

if ! rg -q '\[manual-validation-report\] profile_default_gate_multi_vm_stability_available=false' "$MULTI_VM_STABILITY_DEFAULT_MISSING_REPORT_LOG"; then
  echo "manual validation report multi-vm missing-default run missing availability=false line"
  cat "$MULTI_VM_STABILITY_DEFAULT_MISSING_REPORT_LOG"
  exit 1
fi
if ! rg -q "\[manual-validation-report\] profile_default_gate_multi_vm_stability_check_summary_json=${MULTI_VM_STABILITY_CHECK_DEFAULT_EXPECTED_SUMMARY_JSON}" "$MULTI_VM_STABILITY_DEFAULT_MISSING_REPORT_LOG"; then
  echo "manual validation report multi-vm missing-default run missing default check summary path line"
  cat "$MULTI_VM_STABILITY_DEFAULT_MISSING_REPORT_LOG"
  exit 1
fi
if ! rg -q "\[manual-validation-report\] profile_default_gate_multi_vm_stability_cycle_summary_json=${MULTI_VM_STABILITY_CYCLE_DEFAULT_EXPECTED_SUMMARY_JSON}" "$MULTI_VM_STABILITY_DEFAULT_MISSING_REPORT_LOG"; then
  echo "manual validation report multi-vm missing-default run missing default cycle summary path line"
  cat "$MULTI_VM_STABILITY_DEFAULT_MISSING_REPORT_LOG"
  exit 1
fi
multi_vm_stability_default_missing_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' "$MULTI_VM_STABILITY_DEFAULT_MISSING_REPORT_LOG")"
if [[ -z "$multi_vm_stability_default_missing_report_json" ]]; then
  echo "manual validation report multi-vm missing-default run missing JSON payload"
  cat "$MULTI_VM_STABILITY_DEFAULT_MISSING_REPORT_LOG"
  exit 1
fi
if ! printf '%s\n' "$multi_vm_stability_default_missing_report_json" | jq -e --arg check "$MULTI_VM_STABILITY_CHECK_DEFAULT_EXPECTED_SUMMARY_JSON" --arg cycle "$MULTI_VM_STABILITY_CYCLE_DEFAULT_EXPECTED_SUMMARY_JSON" '
  .summary.profile_default_gate.artifacts.profile_compare_multi_vm_stability_check_summary_json == $check
  and .summary.profile_default_gate.artifacts.profile_compare_multi_vm_stability_cycle_summary_json == $cycle
  and .summary.profile_default_gate.multi_vm_stability_check_summary_json == $check
  and .summary.profile_default_gate.multi_vm_stability_check_summary_available == false
  and .summary.profile_default_gate.multi_vm_stability_cycle_summary_json == $cycle
  and .summary.profile_default_gate.multi_vm_stability_cycle_summary_available == false
  and .summary.profile_default_gate.multi_vm_stability_summary_json == null
  and .summary.profile_default_gate.multi_vm_stability_source == null
  and .summary.profile_default_gate.multi_vm_stability_available == false
  and .summary.profile_default_gate.multi_vm_stability_status == null
  and .summary.profile_default_gate.multi_vm_stability_decision == null
  and .summary.profile_default_gate.multi_vm_stability_go == null
  and .summary.profile_default_gate.multi_vm_stability_no_go == null
  and .summary.profile_default_gate.multi_vm_stability_modal_recommended_profile == null
  and .summary.profile_default_gate.multi_vm_stability_modal_support_rate_pct == null
' >/dev/null; then
  echo "manual validation report multi-vm missing-default JSON missing expected fail-closed fields"
  printf '%s\n' "$multi_vm_stability_default_missing_report_json"
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

if command -v timeout >/dev/null 2>&1; then
  cat >"$FAKE_STATUS_TIMEOUT" <<'EOF_STATUS_TIMEOUT'
#!/usr/bin/env bash
set -euo pipefail
sleep 30
EOF_STATUS_TIMEOUT
  chmod +x "$FAKE_STATUS_TIMEOUT"

  set +e
  EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
  MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
  RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
  MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS_TIMEOUT" \
  ./scripts/manual_validation_report.sh \
    --status-timeout-sec 1 \
    --summary-json "$TMP_DIR/timeout_status_summary.json" \
    --report-md "$TMP_DIR/timeout_status_report.md" \
    --print-report 0 \
    --print-summary-json 1 >$TIMEOUT_STATUS_PAYLOAD_LOG 2>&1
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "manual validation report should fail-closed when status script times out"
    cat $TIMEOUT_STATUS_PAYLOAD_LOG
    exit 1
  fi
  if ! rg -q '\[manual-validation-report\] source_status_timed_out=true' $TIMEOUT_STATUS_PAYLOAD_LOG; then
    echo "manual validation report timeout run missing source_status_timed_out=true line"
    cat $TIMEOUT_STATUS_PAYLOAD_LOG
    exit 1
  fi
  if ! rg -q '\[manual-validation-report\] source_status_payload_synthesized=true' $TIMEOUT_STATUS_PAYLOAD_LOG; then
    echo "manual validation report timeout run missing source_status_payload_synthesized=true line"
    cat $TIMEOUT_STATUS_PAYLOAD_LOG
    exit 1
  fi
  if ! rg -q 'manual-validation-report: manual-validation-status timed out after 1s' $TIMEOUT_STATUS_PAYLOAD_LOG; then
    echo "manual validation report timeout run missing fail-closed timeout message"
    cat $TIMEOUT_STATUS_PAYLOAD_LOG
    exit 1
  fi
  if [[ ! -f "$TMP_DIR/timeout_status_summary.json" ]]; then
    echo "manual validation report timeout run did not create timeout summary JSON"
    cat $TIMEOUT_STATUS_PAYLOAD_LOG
    exit 1
  fi
  if ! jq -e '
    .report.source_status_timed_out == true
    and .report.source_status_timeout_sec == 1
    and .report.source_status_timeout_guard_available == true
    and .report.source_status_payload_synthesized == true
    and .summary.next_action_check_id == "manual_validation_status_timeout"
    and .summary.local_gate.next_check_id == "manual_validation_status_timeout"
    and .summary.roadmap_stage == "BLOCKED_LOCAL"
    and (.summary.profile_default_gate.next_command | contains("--campaign-subject INVITE_KEY"))
    and ((.summary.profile_default_gate.next_command | split("--campaign-subject") | length) == 2)
    and (.summary.profile_default_gate.next_command_sudo | contains("--campaign-subject INVITE_KEY"))
    and ((.summary.profile_default_gate.next_command_sudo | split("--campaign-subject") | length) == 2)
    and ((.runtime_doctor.findings[0].code // "") == "manual_validation_status_timeout")
  ' "$TMP_DIR/timeout_status_summary.json" >/dev/null; then
    echo "manual validation report timeout run JSON missing expected timeout fallback fields"
    cat "$TMP_DIR/timeout_status_summary.json"
    exit 1
  fi
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
  --status-timeout-sec 99 \
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
  '--status-timeout-sec 99' \
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

ROOT_DEFER_REPORT_LOG="$TMP_DIR/integration_manual_validation_report_root_defer.log"
ROOT_DEFER_REPORT_MD="$TMP_DIR/manual_validation_readiness_root_defer_report.md"
ROOT_DEFER_REPORT_JSON="$TMP_DIR/manual_validation_readiness_root_defer_summary.json"
MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS_ROOT_DEFER" \
./scripts/manual_validation_report.sh \
  --summary-json "$ROOT_DEFER_REPORT_JSON" \
  --report-md "$ROOT_DEFER_REPORT_MD" \
  --print-report 0 \
  --print-summary-json 1 >"$ROOT_DEFER_REPORT_LOG"

if ! rg -q '\[manual-validation-report\] machine_c_smoke_blocker_class=root_required_deferred_blocker' "$ROOT_DEFER_REPORT_LOG"; then
  echo "manual validation report missing blocker class line"
  cat "$ROOT_DEFER_REPORT_LOG"
  exit 1
fi
if ! rg -q '\[manual-validation-report\] machine_c_smoke_next_sudo_command=sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country' "$ROOT_DEFER_REPORT_LOG"; then
  echo "manual validation report missing next sudo command line"
  cat "$ROOT_DEFER_REPORT_LOG"
  exit 1
fi
if ! rg -q '^## Pre-Machine-C Gate$' "$ROOT_DEFER_REPORT_MD"; then
  echo "manual validation report root-defer markdown missing pre-machine-c gate section"
  cat "$ROOT_DEFER_REPORT_MD"
  exit 1
fi
if ! rg -q 'Blocker class: `root_required_deferred_blocker`' "$ROOT_DEFER_REPORT_MD"; then
  echo "manual validation report root-defer markdown missing blocker class entry"
  cat "$ROOT_DEFER_REPORT_MD"
  exit 1
fi
if ! rg -q 'Next sudo command: `sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country`' "$ROOT_DEFER_REPORT_MD"; then
  echo "manual validation report root-defer markdown missing next sudo command entry"
  cat "$ROOT_DEFER_REPORT_MD"
  exit 1
fi

echo "manual validation report integration check ok"
