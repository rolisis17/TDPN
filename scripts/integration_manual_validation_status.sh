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
FAKE_STATUS="$TMP_DIR/fake_manual_validation_status.sh"
FAKE_RECORD="$TMP_DIR/fake_manual_validation_record.sh"
CAPTURE="$TMP_DIR/capture.log"
BASELINE_LOG="$TMP_DIR/integration_manual_validation_status_baseline.log"
RECORD_LOG="$TMP_DIR/integration_manual_validation_record.log"
RECORDED_LOG="$TMP_DIR/integration_manual_validation_status_recorded.log"
INCIDENT_RECORD_LOG="$TMP_DIR/integration_manual_validation_record_smoke_fail.log"
INCIDENT_LOG="$TMP_DIR/integration_manual_validation_status_incident.log"
PROFILE_BLOCKED_LOG="$TMP_DIR/integration_manual_validation_status_profile_blocked.log"
PROFILE_STALE_LOG="$TMP_DIR/integration_manual_validation_status_profile_stale.log"
INVALID_STATUS_LOG="$TMP_DIR/integration_manual_validation_status_invalid_status_json.log"
LOCK_RECOVER_LOG="$TMP_DIR/integration_manual_validation_record_lock_recover.log"
LOCK_TIMEOUT_LOG="$TMP_DIR/integration_manual_validation_record_lock_timeout.log"
INVALID_DOCTOR_JSON_LOG="$TMP_DIR/integration_manual_validation_status_invalid_runtime_doctor_json.log"

cat >"$FAKE_DOCTOR" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[runtime-doctor] status=WARN findings=2 warnings=2 failures=0
[runtime-doctor] summary_json_payload:
{
  "version": 1,
  "generated_at_utc": "2026-03-14T15:00:00Z",
  "status": "WARN",
  "summary": {
    "findings_total": 2,
    "warnings_total": 2,
    "failures_total": 0
  },
  "findings": [
    {
      "severity": "WARN",
      "code": "client_env_file_not_writable",
      "message": "client env file not writable",
      "remediation": "sudo chown user:user deploy/.env.easy.client"
    },
    {
      "severity": "WARN",
      "code": "wg_only_dir_not_writable",
      "message": "wg-only runtime dir not writable",
      "remediation": "sudo rm -rf deploy/data/wg_only"
    }
  ]
}
OUT
EOF
chmod +x "$FAKE_DOCTOR"

FAKE_DOCTOR_INVALID="$TMP_DIR/fake_runtime_doctor_invalid_json.sh"
cat >"$FAKE_DOCTOR_INVALID" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[runtime-doctor] status=WARN findings=1 warnings=1 failures=0
[runtime-doctor] summary_json_payload:
{"version":1,"status":"WARN",
OUT
EOF
chmod +x "$FAKE_DOCTOR_INVALID"

echo "[manual-validation] baseline status"
EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_status.sh --show-json 1 >$BASELINE_LOG

if ! rg -q '\[manual-validation-status\] runtime_hygiene=WARN' $BASELINE_LOG; then
  echo "baseline status missing runtime_hygiene WARN line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] wg_only_stack_selftest=PENDING' $BASELINE_LOG; then
  echo "baseline status missing pending wg_only_stack_selftest"
  cat $BASELINE_LOG
  exit 1
fi
baseline_json="$(awk '/^\[manual-validation-status\] summary_json_payload:/{flag=1; next} flag{print}' $BASELINE_LOG)"
if [[ -z "$baseline_json" ]]; then
  echo "baseline status missing JSON payload"
  cat $BASELINE_LOG
  exit 1
fi
if ! printf '%s\n' "$baseline_json" | jq -e '.summary.next_action_check_id == "runtime_hygiene"' >/dev/null; then
  echo "baseline status JSON missing expected next_action_check_id"
  printf '%s\n' "$baseline_json"
  exit 1
fi
if ! printf '%s\n' "$baseline_json" | jq -e '.summary.next_action_command == "sudo ./scripts/easy_node.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1"' >/dev/null; then
  echo "baseline status JSON missing expected next_action_command"
  printf '%s\n' "$baseline_json"
  exit 1
fi
if ! rg -q '\[manual-validation-status\] next_action_command=sudo \./scripts/easy_node\.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1' $BASELINE_LOG; then
  echo "baseline status missing next_action_command output line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] next_action_remediation=sudo chown user:user deploy/\.env\.easy\.client' $BASELINE_LOG; then
  echo "baseline status missing next_action_remediation client env line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] next_action_remediation=sudo rm -rf deploy/data/wg_only' $BASELINE_LOG; then
  echo "baseline status missing next_action_remediation wg-only line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] machine_c_smoke_ready=false' $BASELINE_LOG; then
  echo "baseline status missing machine_c_smoke_ready=false line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] machine_c_smoke_blockers=runtime_hygiene,wg_only_stack_selftest' $BASELINE_LOG; then
  echo "baseline status missing machine_c_smoke_blockers line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] machine_c_smoke_next_command=sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country' $BASELINE_LOG; then
  echo "baseline status missing machine_c_smoke_next_command line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] single_machine_ready=false' $BASELINE_LOG; then
  echo "baseline status missing single_machine_ready=false line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] roadmap_stage=BLOCKED_LOCAL' $BASELINE_LOG; then
  echo "baseline status missing roadmap_stage=BLOCKED_LOCAL line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_host_gate_ready=false' $BASELINE_LOG; then
  echo "baseline status missing real_host_gate_ready=false line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_host_gate_blockers=machine_c_vpn_smoke,three_machine_prod_signoff' $BASELINE_LOG; then
  echo "baseline status missing real_host_gate_blockers line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_host_gate_next_command=sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country' $BASELINE_LOG; then
  echo "baseline status missing real_host_gate_next_command line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] profile_default_gate_status=pending' $BASELINE_LOG; then
  echo "baseline status missing profile_default_gate_status=pending line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] profile_default_gate_available=false' $BASELINE_LOG; then
  echo "baseline status missing profile_default_gate_available=false line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] docker_rehearsal_status=pending' $BASELINE_LOG; then
  echo "baseline status missing docker_rehearsal_status=pending line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] docker_rehearsal_ready=false' $BASELINE_LOG; then
  echo "baseline status missing docker_rehearsal_ready=false line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_wg_privileged_status=pending' $BASELINE_LOG; then
  echo "baseline status missing real_wg_privileged_status=pending line"
  cat $BASELINE_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_wg_privileged_ready=false' $BASELINE_LOG; then
  echo "baseline status missing real_wg_privileged_ready=false line"
  cat $BASELINE_LOG
  exit 1
fi
if ! printf '%s\n' "$baseline_json" | jq -e '
  .summary.pre_machine_c_gate.ready == false
  and .summary.pre_machine_c_gate.blockers == ["runtime_hygiene","wg_only_stack_selftest"]
  and .summary.pre_machine_c_gate.next_check_id == "machine_c_vpn_smoke"
  and .summary.pre_machine_c_gate.next_command == "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
  and .summary.local_gate.ready == false
  and .summary.local_gate.blockers == ["runtime_hygiene","wg_only_stack_selftest"]
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
  and .summary.real_wg_privileged_gate.status == "pending"
  and .summary.real_wg_privileged_gate.ready == false
  and .summary.real_wg_privileged_gate.check_id == "real_wg_privileged_matrix"
  and .summary.single_machine_ready == false
  and .summary.roadmap_stage == "BLOCKED_LOCAL"
  and .summary.next_action_remediations == ["sudo chown user:user deploy/.env.easy.client","sudo rm -rf deploy/data/wg_only"]
' >/dev/null; then
  echo "baseline status JSON missing expected pre_machine_c_gate fields"
  printf '%s\n' "$baseline_json"
  exit 1
fi

echo "[manual-validation] invalid runtime-doctor JSON"
set +e
EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR_INVALID" \
./scripts/manual_validation_status.sh --show-json 0 >$INVALID_DOCTOR_JSON_LOG 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "invalid runtime-doctor JSON path should have failed"
  cat $INVALID_DOCTOR_JSON_LOG
  exit 1
fi
if ! rg -q 'manual-validation-status failed: runtime-doctor emitted invalid JSON summary' $INVALID_DOCTOR_JSON_LOG; then
  echo "invalid runtime-doctor JSON path missing expected message"
  cat $INVALID_DOCTOR_JSON_LOG
  exit 1
fi

echo "[manual-validation] invalid status.json fallback"
mkdir -p "$STATE_DIR"
printf '%s\n' '{"version":1,"checks":' >"$STATE_DIR/status.json"
EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_status.sh --show-json 1 >$INVALID_STATUS_LOG

if ! rg -q '\[manual-validation-status\] warn=manual-validation status file is invalid JSON; falling back to empty checks:' $INVALID_STATUS_LOG; then
  echo "invalid status fallback missing warning line"
  cat $INVALID_STATUS_LOG
  exit 1
fi
invalid_status_json="$(awk '/^\[manual-validation-status\] summary_json_payload:/{flag=1; next} flag{print}' $INVALID_STATUS_LOG)"
if [[ -z "$invalid_status_json" ]]; then
  echo "invalid status fallback missing JSON payload"
  cat $INVALID_STATUS_LOG
  exit 1
fi
if ! printf '%s\n' "$invalid_status_json" | jq -e '
  .recorded_status.file_exists == true
  and .recorded_status.valid_json == false
  and .recorded_status.fallback_used == true
  and ((.recorded_status.warning // "") | length > 0)
  and .summary.next_action_check_id == "runtime_hygiene"
' >/dev/null; then
  echo "invalid status fallback JSON missing recorded_status fields"
  printf '%s\n' "$invalid_status_json"
  exit 1
fi

echo "[manual-validation] stale status lock recovery"
LOCK_STATE_DIR="$TMP_DIR/lock_state"
mkdir -p "$LOCK_STATE_DIR/status.lock"
printf '%s\n' "999999" >"$LOCK_STATE_DIR/status.lock/pid"
EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$LOCK_STATE_DIR" \
./scripts/manual_validation_record.sh \
  --check-id runtime_hygiene \
  --status pass \
  --notes "lock recovery path" \
  --show-json 0 >"$LOCK_RECOVER_LOG"

if ! rg -q '\[manual-validation-record\] check_id=runtime_hygiene status=pass' $LOCK_RECOVER_LOG; then
  echo "manual-validation-record lock recovery path missing success line"
  cat $LOCK_RECOVER_LOG
  exit 1
fi
if [[ -d "$LOCK_STATE_DIR/status.lock" ]]; then
  echo "manual-validation-record lock recovery path left stale lock directory"
  ls -la "$LOCK_STATE_DIR/status.lock"
  exit 1
fi
if ! jq -e '.checks.runtime_hygiene.status == "pass"' "$LOCK_STATE_DIR/status.json" >/dev/null; then
  echo "manual-validation-record lock recovery path did not update status ledger"
  cat "$LOCK_STATE_DIR/status.json"
  exit 1
fi

echo "[manual-validation] status lock timeout"
mkdir -p "$LOCK_STATE_DIR/status.lock"
printf '%s\n' "$$" >"$LOCK_STATE_DIR/status.lock/pid"
if EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$LOCK_STATE_DIR" \
  MANUAL_VALIDATION_RECORD_LOCK_TIMEOUT_SEC=0 \
  ./scripts/manual_validation_record.sh \
    --check-id machine_c_vpn_smoke \
    --status pending \
    --show-json 0 >"$LOCK_TIMEOUT_LOG" 2>&1; then
  echo "manual-validation-record should fail fast when lock is held"
  cat "$LOCK_TIMEOUT_LOG"
  exit 1
fi
if ! rg -q '^timed out acquiring manual-validation state lock:' $LOCK_TIMEOUT_LOG; then
  echo "manual-validation-record lock timeout path missing expected error"
  cat "$LOCK_TIMEOUT_LOG"
  exit 1
fi
rm -rf "$LOCK_STATE_DIR/status.lock"

echo "[manual-validation] record pass receipt"
artifact_path="$ROOT_DIR/scripts/easy_node.sh"
EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
./scripts/manual_validation_record.sh \
  --check-id wg_only_stack_selftest \
  --status pass \
  --notes "Linux root host rerun passed" \
  --artifact "$artifact_path" \
  --command "sudo ./scripts/integration_wg_only_stack_selftest.sh" \
  --show-json 1 >$RECORD_LOG

if ! rg -q '\[manual-validation-record\] check_id=wg_only_stack_selftest status=pass' $RECORD_LOG; then
  echo "manual-validation-record missing expected summary line"
  cat $RECORD_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-record\] warn=existing status JSON invalid; resetting status ledger before recording new check' $RECORD_LOG; then
  echo "manual-validation-record missing invalid status fallback warning"
  cat $RECORD_LOG
  exit 1
fi
receipt_json_path="$(sed -n 's/^\[manual-validation-record\] receipt_json=//p' $RECORD_LOG | tail -n 1)"
if [[ -z "$receipt_json_path" || ! -f "$receipt_json_path" ]]; then
  echo "manual-validation-record missing receipt artifact"
  cat $RECORD_LOG
  exit 1
fi
if ! jq -e --arg artifact "$artifact_path" '.check_id == "wg_only_stack_selftest" and .status == "pass" and (.artifacts | index($artifact) != null)' "$receipt_json_path" >/dev/null; then
  echo "manual-validation-record receipt JSON missing expected fields"
  cat "$receipt_json_path"
  exit 1
fi
if ! jq -e '.checks.wg_only_stack_selftest.status == "pass"' "$STATE_DIR/status.json" >/dev/null; then
  echo "manual-validation-record did not recover invalid status.json into valid ledger"
  cat "$STATE_DIR/status.json"
  exit 1
fi

echo "[manual-validation] updated status"
EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_status.sh --show-json 1 >$RECORDED_LOG

if ! rg -q '\[manual-validation-status\] wg_only_stack_selftest=PASS' $RECORDED_LOG; then
  echo "recorded status missing wg_only_stack_selftest PASS line"
  cat $RECORDED_LOG
  exit 1
fi
if ! rg -q "artifacts: ${ROOT_DIR}/scripts/easy_node.sh" $RECORDED_LOG; then
  echo "recorded status missing artifact path"
  cat $RECORDED_LOG
  exit 1
fi
recorded_json="$(awk '/^\[manual-validation-status\] summary_json_payload:/{flag=1; next} flag{print}' $RECORDED_LOG)"
if [[ -z "$recorded_json" ]]; then
  echo "recorded status missing JSON payload"
  cat $RECORDED_LOG
  exit 1
fi
if ! printf '%s\n' "$recorded_json" | jq -e '
  .summary.warn_checks == 1
  and .summary.pass_checks == 1
  and .summary.next_action_command == "sudo ./scripts/easy_node.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1"
  and .summary.next_action_remediations == ["sudo chown user:user deploy/.env.easy.client","sudo rm -rf deploy/data/wg_only"]
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
  and .summary.docker_rehearsal_gate.status == "pending"
  and .summary.docker_rehearsal_gate.ready == false
  and .summary.real_wg_privileged_gate.status == "pending"
  and .summary.real_wg_privileged_gate.ready == false
  and .summary.real_wg_privileged_gate.check_id == "real_wg_privileged_matrix"
  and .summary.single_machine_ready == false
  and .summary.roadmap_stage == "BLOCKED_LOCAL"
  and (.checks[] | select(.check_id == "machine_c_vpn_smoke") | .command == "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country")
  and (.checks[] | select(.check_id == "three_machine_prod_signoff") | .command == "sudo ./scripts/easy_node.sh three-machine-prod-signoff --bundle-dir .easy-node-logs/prod_gate_bundle --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084 --pre-real-host-readiness 1 --runtime-fix 1 --print-summary-json 1")
  and (.checks[] | select(.check_id == "wg_only_stack_selftest") | .status == "pass")
' >/dev/null; then
  echo "recorded status JSON missing expected summary counts"
  printf '%s\n' "$recorded_json"
  exit 1
fi
if ! rg -q '\[manual-validation-status\] machine_c_smoke_ready=false' $RECORDED_LOG; then
  echo "recorded status missing machine_c_smoke_ready=false line"
  cat $RECORDED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] machine_c_smoke_blockers=runtime_hygiene' $RECORDED_LOG; then
  echo "recorded status missing machine_c_smoke_blockers line"
  cat $RECORDED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] machine_c_smoke_next_command=sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country' $RECORDED_LOG; then
  echo "recorded status missing machine_c_smoke_next_command line"
  cat $RECORDED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] single_machine_ready=false' $RECORDED_LOG; then
  echo "recorded status missing single_machine_ready=false line"
  cat $RECORDED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] roadmap_stage=BLOCKED_LOCAL' $RECORDED_LOG; then
  echo "recorded status missing roadmap_stage=BLOCKED_LOCAL line"
  cat $RECORDED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_host_gate_ready=false' $RECORDED_LOG; then
  echo "recorded status missing real_host_gate_ready=false line"
  cat $RECORDED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_host_gate_blockers=machine_c_vpn_smoke,three_machine_prod_signoff' $RECORDED_LOG; then
  echo "recorded status missing real_host_gate_blockers line"
  cat $RECORDED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] profile_default_gate_status=pending' $RECORDED_LOG; then
  echo "recorded status missing profile_default_gate_status=pending line"
  cat $RECORDED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] docker_rehearsal_status=pending' $RECORDED_LOG; then
  echo "recorded status missing docker_rehearsal_status=pending line"
  cat $RECORDED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] docker_rehearsal_ready=false' $RECORDED_LOG; then
  echo "recorded status missing docker_rehearsal_ready=false line"
  cat $RECORDED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_wg_privileged_status=pending' $RECORDED_LOG; then
  echo "recorded status missing real_wg_privileged_status=pending line"
  cat $RECORDED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_wg_privileged_ready=false' $RECORDED_LOG; then
  echo "recorded status missing real_wg_privileged_ready=false line"
  cat $RECORDED_LOG
  exit 1
fi

echo "[manual-validation] failed smoke incident handoff"
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
  --show-json 0 >$INCIDENT_RECORD_LOG

EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$STATE_DIR" \
MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON="$PROFILE_SIGNOFF_SUMMARY_JSON" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/manual_validation_status.sh --show-json 1 >$INCIDENT_LOG

if ! rg -q '\[manual-validation-status\] machine_c_vpn_smoke=FAIL' $INCIDENT_LOG; then
  echo "incident status missing machine_c_vpn_smoke FAIL line"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q "incident_handoff source_summary_json=${SMOKE_RUN_SUMMARY_JSON}" $INCIDENT_LOG; then
  echo "incident status missing incident_handoff source summary path"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q "readiness_report_summary_attachment=${SMOKE_READY_SUMMARY_ATTACHMENT}" $INCIDENT_LOG; then
  echo "incident status missing readiness summary attachment path"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q "readiness_report_md_attachment=${SMOKE_READY_REPORT_ATTACHMENT}" $INCIDENT_LOG; then
  echo "incident status missing readiness report attachment path"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q "summary_json=${SMOKE_INCIDENT_SUMMARY_JSON}" $INCIDENT_LOG; then
  echo "incident status missing incident summary path"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q "\\[manual-validation-status\\] latest_failed_incident_check_id=machine_c_vpn_smoke" $INCIDENT_LOG; then
  echo "incident status missing latest failed incident check id"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q "\\[manual-validation-status\\] latest_failed_incident_summary_json=${SMOKE_INCIDENT_SUMMARY_JSON}" $INCIDENT_LOG; then
  echo "incident status missing latest failed incident summary path"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q "\\[manual-validation-status\\] latest_failed_incident_readiness_report_summary_attachment=${SMOKE_READY_SUMMARY_ATTACHMENT}" $INCIDENT_LOG; then
  echo "incident status missing latest failed readiness summary attachment path"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q "\\[manual-validation-status\\] latest_failed_incident_readiness_report_md_attachment=${SMOKE_READY_REPORT_ATTACHMENT}" $INCIDENT_LOG; then
  echo "incident status missing latest failed readiness report attachment path"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] machine_c_smoke_ready=false' $INCIDENT_LOG; then
  echo "incident status missing machine_c_smoke_ready=false line"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] machine_c_smoke_blockers=runtime_hygiene' $INCIDENT_LOG; then
  echo "incident status missing machine_c_smoke_blockers line"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] machine_c_smoke_next_command=sudo \./scripts/easy_node\.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api\.ipify\.org --country-url https://ipinfo\.io/country' $INCIDENT_LOG; then
  echo "incident status missing machine_c_smoke_next_command line"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] single_machine_ready=false' $INCIDENT_LOG; then
  echo "incident status missing single_machine_ready=false line"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] roadmap_stage=BLOCKED_LOCAL' $INCIDENT_LOG; then
  echo "incident status missing roadmap_stage=BLOCKED_LOCAL line"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_host_gate_ready=false' $INCIDENT_LOG; then
  echo "incident status missing real_host_gate_ready=false line"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_host_gate_blockers=machine_c_vpn_smoke,three_machine_prod_signoff' $INCIDENT_LOG; then
  echo "incident status missing real_host_gate_blockers line"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] profile_default_gate_status=pending' $INCIDENT_LOG; then
  echo "incident status missing profile_default_gate_status=pending line"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] docker_rehearsal_status=pending' $INCIDENT_LOG; then
  echo "incident status missing docker_rehearsal_status=pending line"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] docker_rehearsal_ready=false' $INCIDENT_LOG; then
  echo "incident status missing docker_rehearsal_ready=false line"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_wg_privileged_status=pending' $INCIDENT_LOG; then
  echo "incident status missing real_wg_privileged_status=pending line"
  cat $INCIDENT_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] real_wg_privileged_ready=false' $INCIDENT_LOG; then
  echo "incident status missing real_wg_privileged_ready=false line"
  cat $INCIDENT_LOG
  exit 1
fi
incident_json="$(awk '/^\[manual-validation-status\] summary_json_payload:/{flag=1; next} flag{print}' $INCIDENT_LOG)"
if [[ -z "$incident_json" ]]; then
  echo "incident status missing JSON payload"
  cat $INCIDENT_LOG
  exit 1
fi
if ! printf '%s\n' "$incident_json" | jq -e --arg smoke_summary "$SMOKE_RUN_SUMMARY_JSON" --arg incident_summary "$SMOKE_INCIDENT_SUMMARY_JSON" --arg incident_report "$SMOKE_INCIDENT_REPORT_MD" --arg ready_summary_attachment "$SMOKE_READY_SUMMARY_ATTACHMENT" --arg ready_report_attachment "$SMOKE_READY_REPORT_ATTACHMENT" --arg ready_log_attachment "$SMOKE_READY_LOG_ATTACHMENT" '
  .summary.warn_checks == 1
  and .summary.pass_checks == 1
  and .summary.fail_checks == 1
  and .summary.next_action_check_id == "runtime_hygiene"
  and .summary.next_action_command == "sudo ./scripts/easy_node.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1"
  and .summary.next_action_remediations == ["sudo chown user:user deploy/.env.easy.client","sudo rm -rf deploy/data/wg_only"]
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
  and .summary.docker_rehearsal_gate.status == "pending"
  and .summary.docker_rehearsal_gate.ready == false
  and .summary.real_wg_privileged_gate.status == "pending"
  and .summary.real_wg_privileged_gate.ready == false
  and .summary.real_wg_privileged_gate.check_id == "real_wg_privileged_matrix"
  and .summary.single_machine_ready == false
  and .summary.roadmap_stage == "BLOCKED_LOCAL"
  and .summary.latest_failed_incident.check_id == "machine_c_vpn_smoke"
  and .summary.latest_failed_incident.summary_json.path == $incident_summary
  and .summary.latest_failed_incident.readiness_report_summary_attachment.bundle_path == $ready_summary_attachment
  and .summary.latest_failed_incident.readiness_report_md_attachment.bundle_path == $ready_report_attachment
  and .summary.latest_failed_incident.readiness_report_log_attachment.bundle_path == $ready_log_attachment
  and ([.checks[]
    | select(.check_id == "machine_c_vpn_smoke")
    | (
        .incident_handoff.available == true
        and .incident_handoff.source_summary_json.path == $smoke_summary
        and .incident_handoff.summary_json.path == $incident_summary
        and .incident_handoff.report_md.path == $incident_report
        and .incident_handoff.attachment_count == 1
        and .incident_handoff.readiness_report_summary_attachment.bundle_path == $ready_summary_attachment
        and .incident_handoff.readiness_report_md_attachment.bundle_path == $ready_report_attachment
        and .incident_handoff.readiness_report_log_attachment.bundle_path == $ready_log_attachment
      )
  ] | any)
' >/dev/null; then
  echo "incident status JSON missing expected incident handoff fields"
  printf '%s\n' "$incident_json"
  exit 1
fi

echo "[manual-validation] profile-default gate non-root refresh block"
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
./scripts/manual_validation_status.sh --show-json 1 >$PROFILE_BLOCKED_LOG

if ! rg -q '\[manual-validation-status\] profile_default_gate_status=pending' $PROFILE_BLOCKED_LOG; then
  echo "profile-blocked status missing profile_default_gate_status=pending line"
  cat $PROFILE_BLOCKED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] profile_default_gate_available=true' $PROFILE_BLOCKED_LOG; then
  echo "profile-blocked status missing profile_default_gate_available=true line"
  cat $PROFILE_BLOCKED_LOG
  exit 1
fi
if ! rg -q '\[manual-validation-status\] profile_default_gate_next_command=sudo \./scripts/easy_node\.sh profile-compare-campaign-signoff' $PROFILE_BLOCKED_LOG; then
  echo "profile-blocked status missing sudo profile-default gate next command"
  cat $PROFILE_BLOCKED_LOG
  exit 1
fi
profile_blocked_json="$(awk '/^\[manual-validation-status\] summary_json_payload:/{flag=1; next} flag{print}' $PROFILE_BLOCKED_LOG)"
if [[ -z "$profile_blocked_json" ]]; then
  echo "profile-blocked status missing JSON payload"
  cat $PROFILE_BLOCKED_LOG
  exit 1
fi
if ! printf '%s\n' "$profile_blocked_json" | jq -e '
  .summary.profile_default_gate.status == "pending"
  and .summary.profile_default_gate.available == true
  and .summary.profile_default_gate.valid_json == true
  and .summary.profile_default_gate.failure_stage == "campaign"
  and .summary.profile_default_gate.non_root_refresh_blocked == true
  and (.summary.profile_default_gate.next_command | startswith("sudo ./scripts/easy_node.sh profile-compare-campaign-signoff"))
' >/dev/null; then
  echo "profile-blocked status JSON missing expected profile_default_gate fields"
  printf '%s\n' "$profile_blocked_json"
  exit 1
fi

echo "[manual-validation] profile-default stale non-refreshed summary"
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
./scripts/manual_validation_status.sh --show-json 1 >$PROFILE_STALE_LOG

if ! rg -q '\[manual-validation-status\] profile_default_gate_status=pending' $PROFILE_STALE_LOG; then
  echo "profile-stale status missing profile_default_gate_status=pending line"
  cat $PROFILE_STALE_LOG
  exit 1
fi
profile_stale_json="$(awk '/^\[manual-validation-status\] summary_json_payload:/{flag=1; next} flag{print}' $PROFILE_STALE_LOG)"
if [[ -z "$profile_stale_json" ]]; then
  echo "profile-stale status missing JSON payload"
  cat $PROFILE_STALE_LOG
  exit 1
fi
if ! printf '%s\n' "$profile_stale_json" | jq -e '
  .summary.profile_default_gate.status == "pending"
  and .summary.profile_default_gate.available == true
  and .summary.profile_default_gate.valid_json == true
  and .summary.profile_default_gate.failure_stage == "campaign_check"
  and .summary.profile_default_gate.non_root_refresh_blocked == false
  and .summary.profile_default_gate.stale_non_refreshed == true
  and .summary.profile_default_gate.refresh_campaign == false
  and (.summary.profile_default_gate.next_command | startswith("sudo ./scripts/easy_node.sh profile-compare-campaign-signoff"))
' >/dev/null; then
  echo "profile-stale status JSON missing expected stale profile_default_gate fields"
  printf '%s\n' "$profile_stale_json"
  exit 1
fi

echo "[manual-validation] easy_node forwarding"
cat >"$FAKE_STATUS" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'manual-validation-status %s\n' "\$*" >>"$CAPTURE"
EOF
cat >"$FAKE_RECORD" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'manual-validation-record %s\n' "\$*" >>"$CAPTURE"
EOF
chmod +x "$FAKE_STATUS" "$FAKE_RECORD"
: >"$CAPTURE"

MANUAL_VALIDATION_STATUS_SCRIPT="$FAKE_STATUS" \
./scripts/easy_node.sh manual-validation-status \
  --base-port 19400 \
  --client-iface wgctest0 \
  --exit-iface wgestest0 \
  --vpn-iface wgvpntest0 \
  --profile-compare-signoff-summary-json /tmp/profile_signoff_override.json \
  --show-json 1

line_status="$(rg '^manual-validation-status ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line_status" ]]; then
  echo "easy_node manual-validation-status forwarding failed"
  cat "$CAPTURE"
  exit 1
fi
for expected in '--base-port 19400' '--client-iface wgctest0' '--exit-iface wgestest0' '--vpn-iface wgvpntest0' '--profile-compare-signoff-summary-json /tmp/profile_signoff_override.json' '--show-json 1'; do
  if ! grep -F -- "$expected" <<<"$line_status" >/dev/null; then
    echo "easy_node manual-validation-status forwarding missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

MANUAL_VALIDATION_RECORD_SCRIPT="$FAKE_RECORD" \
./scripts/easy_node.sh manual-validation-record \
  --check-id machine_c_vpn_smoke \
  --status fail \
  --notes "test note" \
  --artifact scripts/easy_node.sh \
  --command "sudo ./scripts/easy_node.sh client-vpn-up" \
  --show-json 1

line_record="$(rg '^manual-validation-record ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line_record" ]]; then
  echo "easy_node manual-validation-record forwarding failed"
  cat "$CAPTURE"
  exit 1
fi
for expected in '--check-id machine_c_vpn_smoke' '--status fail' '--notes test note' '--artifact scripts/easy_node.sh' '--command sudo ./scripts/easy_node.sh client-vpn-up' '--show-json 1'; do
  if ! grep -F -- "$expected" <<<"$line_record" >/dev/null; then
    echo "easy_node manual-validation-record forwarding missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

echo "manual validation status integration ok"
