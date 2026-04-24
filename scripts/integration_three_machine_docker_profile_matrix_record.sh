#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp chmod grep sed tail cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

if [[ ! -x ./scripts/three_machine_docker_profile_matrix_record.sh ]]; then
  echo "missing executable script under test: ./scripts/three_machine_docker_profile_matrix_record.sh"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/helper_calls.log"
FAKE_MATRIX="$TMP_DIR/fake_three_machine_docker_profile_matrix.sh"
FAKE_MANUAL_RECORD="$TMP_DIR/fake_manual_validation_record.sh"
FAKE_MANUAL_REPORT="$TMP_DIR/fake_manual_validation_report.sh"

cat >"$FAKE_MATRIX" <<'EOF_FAKE_MATRIX'
#!/usr/bin/env bash
set -euo pipefail

capture="${FAKE_HELPER_CAPTURE_FILE:?}"
printf '%s\n' "three-machine-docker-profile-matrix $*" >>"$capture"

summary_json=""
dry_run="0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --dry-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dry_run="${2:-}"
        shift 2
      else
        dry_run="1"
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

status="${FAKE_MATRIX_STATUS:-pass}"
rc="${FAKE_MATRIX_RC:-0}"
notes="${FAKE_MATRIX_NOTES:-Docker profile matrix rehearsal passed}"
if [[ "${FAKE_MATRIX_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_MATRIX_RC:-1}"
  notes="${FAKE_MATRIX_NOTES:-Docker profile matrix rehearsal failed}"
fi

reduction_available="false"
failed_profiles_json='[]'
failed_profiles_count=0
failed_profiles_csv=""
failed_profiles_csv_json="null"
rerun_failed_profiles_command_json="null"
if [[ "$status" == "fail" ]]; then
  reduction_available="true"
  failed_profiles_json="${FAKE_MATRIX_FAILED_PROFILES_JSON:-[\"balanced\"]}"
  failed_profiles_count="$(printf '%s\n' "$failed_profiles_json" | jq -r 'if type == "array" then length else 0 end' 2>/dev/null || printf '0')"
  failed_profiles_csv="$(printf '%s\n' "$failed_profiles_json" | jq -r 'if type == "array" then join(",") else "" end' 2>/dev/null || printf '')"
  if [[ -n "$failed_profiles_csv" ]]; then
    failed_profiles_csv_json="$(printf '%s' "$failed_profiles_csv" | jq -R '.')"
  fi
  rerun_failed_profiles_command_json="$(printf '%s' "${FAKE_MATRIX_RERUN_FAILED_PROFILES_COMMAND:-./scripts/three_machine_docker_profile_matrix.sh --profiles ${failed_profiles_csv:-balanced} --print-summary-json 1}" | jq -R '.')"
fi

if [[ "$dry_run" == "1" ]]; then
  echo "three-machine-docker-profile-matrix: dry-run"
fi

emit_summary="1"
if [[ "$dry_run" == "1" || "${FAKE_MATRIX_OMIT_SUMMARY:-0}" == "1" ]]; then
  emit_summary="0"
fi

if [[ -n "$summary_json" && "$emit_summary" == "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  matrix_log="${summary_json%.json}.log"
  : >"$matrix_log"
  cat >"$summary_json" <<EOF_MATRIX_JSON
{
  "version": 1,
  "status": "$status",
  "rc": $rc,
  "notes": "$notes",
  "summary": {
    "profiles_total": 3,
    "profiles_pass": $(if [[ "$status" == "pass" ]]; then echo 3; else echo 2; fi),
    "profiles_fail": $(if [[ "$status" == "pass" ]]; then echo 0; else echo 1; fi)
  },
  "reduction": {
    "available": $reduction_available,
    "failed_profiles": $failed_profiles_json,
    "failed_profiles_count": $failed_profiles_count,
    "failed_profiles_csv": $failed_profiles_csv_json,
    "rerun_failed_profiles_command": $rerun_failed_profiles_command_json
  },
  "artifacts": {
    "matrix_log": "$matrix_log"
  }
}
EOF_MATRIX_JSON
fi

if [[ "${FAKE_MATRIX_FAIL:-0}" == "1" ]]; then
  exit 1
fi
exit 0
EOF_FAKE_MATRIX
chmod +x "$FAKE_MATRIX"

cat >"$FAKE_MANUAL_RECORD" <<'EOF_FAKE_MANUAL_RECORD'
#!/usr/bin/env bash
set -euo pipefail

capture="${FAKE_HELPER_CAPTURE_FILE:?}"
receipt_json="${FAKE_MANUAL_VALIDATION_RECEIPT_JSON:?}"
printf '%s\n' "manual-validation-record $*" >>"$capture"
mkdir -p "$(dirname "$receipt_json")"
printf '%s\n' '{"status":"ok"}' >"$receipt_json"
echo "[manual-validation-record] receipt_json=$receipt_json"
echo "manual-validation-record ok"
exit 0
EOF_FAKE_MANUAL_RECORD
chmod +x "$FAKE_MANUAL_RECORD"

cat >"$FAKE_MANUAL_REPORT" <<'EOF_FAKE_MANUAL_REPORT'
#!/usr/bin/env bash
set -euo pipefail

capture="${FAKE_HELPER_CAPTURE_FILE:?}"
printf '%s\n' "manual-validation-report $*" >>"$capture"

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
printf '%s\n' '{"report":{"readiness_status":"NOT_READY"},"summary":{"next_action_check_id":"machine_c_vpn_smoke"}}' >"$summary_json"
printf '# Manual Validation Readiness Report\n' >"$report_md"

echo "[manual-validation-report] summary_json_payload:"
cat "$summary_json"
exit 0
EOF_FAKE_MANUAL_REPORT
chmod +x "$FAKE_MANUAL_REPORT"

echo "[three-machine-docker-profile-matrix-record] success path"
: >"$CAPTURE"
FAKE_HELPER_CAPTURE_FILE="$CAPTURE" \
FAKE_MANUAL_VALIDATION_RECEIPT_JSON="$TMP_DIR/manual_validation_receipt_success.json" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MATRIX_SCRIPT="$FAKE_MATRIX" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MANUAL_VALIDATION_RECORD_SCRIPT="$FAKE_MANUAL_RECORD" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
./scripts/three_machine_docker_profile_matrix_record.sh \
  --path-profiles speed,balanced \
  --soak-rounds 3 \
  --soak-pause-sec 1 \
  --summary-json "$TMP_DIR/summary_success.json" \
  --matrix-summary-json "$TMP_DIR/matrix_summary_success.json" \
  --manual-validation-report-summary-json "$TMP_DIR/manual_validation_report_success.json" \
  --manual-validation-report-md "$TMP_DIR/manual_validation_report_success.md" \
  --record-result 1 \
  --print-summary-json 1 >"$TMP_DIR/integration_three_machine_docker_profile_matrix_record_ok.log" 2>&1

if ! grep -q 'three-machine-docker-profile-matrix-record: status=pass' "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_ok.log"; then
  echo "expected pass status for three-machine-docker-profile-matrix-record success path"
  cat "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_ok.log"
  exit 1
fi
if ! grep -Eq '^three-machine-docker-profile-matrix( |$)' "$CAPTURE"; then
  echo "expected matrix stage invocation missing"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -Eq '^manual-validation-record --check-id three_machine_docker_readiness --status pass ' "$CAPTURE"; then
  echo "expected manual-validation-record pass call missing"
  cat "$CAPTURE"
  exit 1
fi

summary_json_path="$(sed -n 's/^summary_json: //p' "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_ok.log" | tail -n 1)"
if [[ -z "$summary_json_path" || ! -f "$summary_json_path" ]]; then
  echo "expected success summary JSON missing"
  cat "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_ok.log"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .schema.id == "three_machine_docker_profile_matrix_record_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and .inputs.run_matrix == true
  and .rc == 0
  and .stages.matrix.ran == true
  and .stages.matrix.status == "pass"
  and .stages.matrix.rc == 0
  and .stages.matrix.summary.status == "pass"
  and .stages.matrix.summary.summary.profiles_total == 3
  and .stages.matrix.reduction.available == false
  and .stages.matrix.reduction.failed_profiles == []
  and .stages.matrix.reduction.failed_profiles_count == 0
  and .stages.matrix.reduction.rerun_failed_profiles_command == null
  and .stages.manual_validation_record.ran == true
  and .stages.manual_validation_record.status == "ok"
  and .stages.manual_validation_record.check_id == "three_machine_docker_readiness"
  and .stages.manual_validation_record.written_receipt == true
  and .stages.manual_validation_report.status == "ok"
  and .stages.manual_validation_report.readiness_status == "NOT_READY"
  and .stages.manual_validation_report.next_action_check_id == "machine_c_vpn_smoke"
' "$summary_json_path" >/dev/null; then
  echo "success summary JSON missing expected contract fields"
  cat "$summary_json_path"
  exit 1
fi

echo "[three-machine-docker-profile-matrix-record] run-matrix=0 reuse summary path"
: >"$CAPTURE"
mkdir -p "$TMP_DIR/reuse"
cat >"$TMP_DIR/reuse/matrix_summary_reuse.json" <<EOF_REUSE_SUMMARY
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "notes": "Reused matrix summary artifact",
  "summary": {
    "profiles_total": 3,
    "profiles_pass": 3,
    "profiles_fail": 0
  },
  "reduction": {
    "available": false,
    "failed_profiles": [],
    "failed_profiles_count": 0,
    "failed_profiles_csv": null,
    "rerun_failed_profiles_command": null
  },
  "artifacts": {
    "matrix_log": "$TMP_DIR/reuse/matrix_reuse.log"
  }
}
EOF_REUSE_SUMMARY
: >"$TMP_DIR/reuse/matrix_reuse.log"

FAKE_HELPER_CAPTURE_FILE="$CAPTURE" \
FAKE_MANUAL_VALIDATION_RECEIPT_JSON="$TMP_DIR/manual_validation_receipt_reuse.json" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MATRIX_SCRIPT="$FAKE_MATRIX" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MANUAL_VALIDATION_RECORD_SCRIPT="$FAKE_MANUAL_RECORD" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
./scripts/three_machine_docker_profile_matrix_record.sh \
  --run-matrix 0 \
  --summary-json "$TMP_DIR/summary_reuse.json" \
  --matrix-summary-json "$TMP_DIR/reuse/matrix_summary_reuse.json" \
  --manual-validation-report-summary-json "$TMP_DIR/manual_validation_report_reuse.json" \
  --manual-validation-report-md "$TMP_DIR/manual_validation_report_reuse.md" \
  --record-result 1 \
  --print-summary-json 1 >"$TMP_DIR/integration_three_machine_docker_profile_matrix_record_reuse.log" 2>&1

if ! grep -q 'three-machine-docker-profile-matrix-record: status=pass' "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_reuse.log"; then
  echo "expected pass status for run-matrix=0 reuse path"
  cat "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_reuse.log"
  exit 1
fi
if grep -Eq '^three-machine-docker-profile-matrix( |$)' "$CAPTURE"; then
  echo "matrix helper should not be invoked when --run-matrix 0"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -Eq '^manual-validation-record --check-id three_machine_docker_readiness --status pass ' "$CAPTURE"; then
  echo "expected manual-validation-record pass call missing in run-matrix=0 reuse path"
  cat "$CAPTURE"
  exit 1
fi

reuse_summary_json_path="$(sed -n 's/^summary_json: //p' "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_reuse.log" | tail -n 1)"
if [[ -z "$reuse_summary_json_path" || ! -f "$reuse_summary_json_path" ]]; then
  echo "expected run-matrix=0 reuse summary JSON missing"
  cat "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_reuse.log"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .schema.id == "three_machine_docker_profile_matrix_record_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and .inputs.run_matrix == false
  and .rc == 0
  and .stages.matrix.ran == false
  and .stages.matrix.status == "pass"
  and .stages.matrix.rc == 0
  and .stages.matrix.command_rc == 0
  and .stages.matrix.summary_valid == true
  and .stages.matrix.summary_status == "pass"
  and .stages.matrix.summary.summary.profiles_total == 3
  and .stages.matrix.reduction.available == false
  and .stages.matrix.reduction.failed_profiles == []
  and .stages.matrix.reduction.failed_profiles_count == 0
  and .stages.matrix.reduction.rerun_failed_profiles_command == null
  and .notes == "Reused matrix summary artifact"
  and .stages.manual_validation_record.ran == true
  and .stages.manual_validation_record.status == "ok"
  and .stages.manual_validation_report.status == "ok"
  and .stages.manual_validation_report.readiness_status == "NOT_READY"
' "$reuse_summary_json_path" >/dev/null; then
  echo "run-matrix=0 reuse summary JSON missing expected contract fields"
  cat "$reuse_summary_json_path"
  exit 1
fi

echo "[three-machine-docker-profile-matrix-record] dry-run success path (no matrix summary)"
: >"$CAPTURE"
FAKE_HELPER_CAPTURE_FILE="$CAPTURE" \
FAKE_MANUAL_VALIDATION_RECEIPT_JSON="$TMP_DIR/manual_validation_receipt_dry_run.json" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MATRIX_SCRIPT="$FAKE_MATRIX" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MANUAL_VALIDATION_RECORD_SCRIPT="$FAKE_MANUAL_RECORD" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
./scripts/three_machine_docker_profile_matrix_record.sh \
  --path-profiles speed,balanced \
  --dry-run 1 \
  --summary-json "$TMP_DIR/summary_dry_run.json" \
  --matrix-summary-json "$TMP_DIR/matrix_summary_dry_run.json" \
  --manual-validation-report-summary-json "$TMP_DIR/manual_validation_report_dry_run.json" \
  --manual-validation-report-md "$TMP_DIR/manual_validation_report_dry_run.md" \
  --record-result 1 \
  --print-summary-json 1 >"$TMP_DIR/integration_three_machine_docker_profile_matrix_record_dry_run.log" 2>&1

if ! grep -q 'three-machine-docker-profile-matrix-record: status=pass' "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_dry_run.log"; then
  echo "expected pass status for three-machine-docker-profile-matrix-record dry-run path"
  cat "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_dry_run.log"
  exit 1
fi
if ! grep -Eq '^three-machine-docker-profile-matrix .*--dry-run 1( |$)' "$CAPTURE"; then
  echo "expected dry-run matrix invocation missing"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -Eq '^manual-validation-record --check-id three_machine_docker_readiness --status pass ' "$CAPTURE"; then
  echo "expected manual-validation-record pass call missing in dry-run path"
  cat "$CAPTURE"
  exit 1
fi

dry_run_summary_json_path="$(sed -n 's/^summary_json: //p' "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_dry_run.log" | tail -n 1)"
if [[ -z "$dry_run_summary_json_path" || ! -f "$dry_run_summary_json_path" ]]; then
  echo "expected dry-run summary JSON missing"
  cat "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_dry_run.log"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .schema.id == "three_machine_docker_profile_matrix_record_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and .inputs.run_matrix == true
  and .rc == 0
  and .stages.matrix.ran == true
  and .stages.matrix.status == "pass"
  and .stages.matrix.rc == 0
  and .stages.matrix.command_rc == 0
  and .stages.matrix.summary_valid == false
  and .stages.matrix.dry_run == true
  and .stages.matrix.summary_status == "dry-run-no-summary"
  and .stages.matrix.reduction.available == false
  and .stages.matrix.reduction.failed_profiles == []
  and .stages.matrix.reduction.failed_profiles_count == 0
  and .stages.matrix.reduction.rerun_failed_profiles_command == null
  and (.notes | test("dry-run"))
  and .stages.manual_validation_record.ran == true
  and .stages.manual_validation_record.status == "ok"
  and .stages.manual_validation_record.check_id == "three_machine_docker_readiness"
  and .stages.manual_validation_report.status == "ok"
  and .stages.manual_validation_report.readiness_status == "NOT_READY"
' "$dry_run_summary_json_path" >/dev/null; then
  echo "dry-run summary JSON missing expected contract fields"
  cat "$dry_run_summary_json_path"
  exit 1
fi

echo "[three-machine-docker-profile-matrix-record] non-dry-run missing summary fails closed"
: >"$CAPTURE"
if env \
  FAKE_HELPER_CAPTURE_FILE="$CAPTURE" \
  FAKE_MANUAL_VALIDATION_RECEIPT_JSON="$TMP_DIR/manual_validation_receipt_missing_summary.json" \
  FAKE_MATRIX_OMIT_SUMMARY="1" \
  THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MATRIX_SCRIPT="$FAKE_MATRIX" \
  THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MANUAL_VALIDATION_RECORD_SCRIPT="$FAKE_MANUAL_RECORD" \
  THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
  ./scripts/three_machine_docker_profile_matrix_record.sh \
    --path-profiles speed,balanced \
    --summary-json "$TMP_DIR/summary_missing_summary.json" \
    --matrix-summary-json "$TMP_DIR/matrix_summary_missing_summary.json" \
    --manual-validation-report-summary-json "$TMP_DIR/manual_validation_report_missing_summary.json" \
    --manual-validation-report-md "$TMP_DIR/manual_validation_report_missing_summary.md" \
    --record-result 1 \
    --print-summary-json 1 >"$TMP_DIR/integration_three_machine_docker_profile_matrix_record_missing_summary.log" 2>&1; then
  echo "expected non-dry-run missing-summary path to return non-zero"
  cat "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_missing_summary.log"
  exit 1
fi

if ! grep -q 'three-machine-docker-profile-matrix-record: status=fail' "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_missing_summary.log"; then
  echo "expected fail status for non-dry-run missing-summary path"
  cat "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_missing_summary.log"
  exit 1
fi
if ! grep -Eq '^manual-validation-record --check-id three_machine_docker_readiness --status fail ' "$CAPTURE"; then
  echo "expected manual-validation-record fail call missing in non-dry-run missing-summary path"
  cat "$CAPTURE"
  exit 1
fi

missing_summary_json_path="$(sed -n 's/^summary_json: //p' "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_missing_summary.log" | tail -n 1)"
if [[ -z "$missing_summary_json_path" || ! -f "$missing_summary_json_path" ]]; then
  echo "expected non-dry-run missing-summary summary JSON missing"
  cat "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_missing_summary.log"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .schema.id == "three_machine_docker_profile_matrix_record_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and .inputs.run_matrix == true
  and .rc == 1
  and .stages.matrix.ran == true
  and .stages.matrix.status == "fail"
  and .stages.matrix.rc == 1
  and .stages.matrix.command_rc == 0
  and .stages.matrix.summary_valid == false
  and .stages.matrix.dry_run == false
  and .stages.matrix.summary_status == "missing"
  and .stages.matrix.reduction.available == false
  and .stages.matrix.reduction.failed_profiles == []
  and .stages.matrix.reduction.failed_profiles_count == 0
  and .stages.matrix.reduction.rerun_failed_profiles_command == null
  and (.notes | test("did not emit a usable JSON summary"))
  and .stages.manual_validation_record.ran == true
  and .stages.manual_validation_record.status == "ok"
  and .stages.manual_validation_record.check_id == "three_machine_docker_readiness"
  and .stages.manual_validation_report.status == "ok"
  and .stages.manual_validation_report.readiness_status == "NOT_READY"
' "$missing_summary_json_path" >/dev/null; then
  echo "non-dry-run missing-summary JSON missing expected strict contract fields"
  cat "$missing_summary_json_path"
  exit 1
fi

echo "[three-machine-docker-profile-matrix-record] failure path"
: >"$CAPTURE"
if env \
  FAKE_HELPER_CAPTURE_FILE="$CAPTURE" \
  FAKE_MANUAL_VALIDATION_RECEIPT_JSON="$TMP_DIR/manual_validation_receipt_fail.json" \
  FAKE_MATRIX_FAIL="1" \
  FAKE_MATRIX_STATUS="fail" \
  FAKE_MATRIX_RC=1 \
  FAKE_MATRIX_NOTES="Docker profile matrix rehearsal failed" \
  THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MATRIX_SCRIPT="$FAKE_MATRIX" \
  THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MANUAL_VALIDATION_RECORD_SCRIPT="$FAKE_MANUAL_RECORD" \
  THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
  ./scripts/three_machine_docker_profile_matrix_record.sh \
    --path-profiles speed,balanced,private \
    --summary-json "$TMP_DIR/summary_failure.json" \
    --matrix-summary-json "$TMP_DIR/matrix_summary_failure.json" \
    --manual-validation-report-summary-json "$TMP_DIR/manual_validation_report_failure.json" \
    --manual-validation-report-md "$TMP_DIR/manual_validation_report_failure.md" \
    --record-result 1 \
    --print-summary-json 1 >"$TMP_DIR/integration_three_machine_docker_profile_matrix_record_fail.log" 2>&1; then
  echo "expected failure path to return non-zero"
  cat "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_fail.log"
  exit 1
fi

if ! grep -q 'three-machine-docker-profile-matrix-record: status=fail' "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_fail.log"; then
  echo "expected fail status for three-machine-docker-profile-matrix-record failure path"
  cat "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_fail.log"
  exit 1
fi
if ! grep -Eq '^three-machine-docker-profile-matrix( |$)' "$CAPTURE"; then
  echo "expected matrix stage invocation missing in failure path"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -Eq '^manual-validation-record --check-id three_machine_docker_readiness --status fail ' "$CAPTURE"; then
  echo "expected manual-validation-record fail call missing"
  cat "$CAPTURE"
  exit 1
fi

fail_summary_json_path="$(sed -n 's/^summary_json: //p' "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_fail.log" | tail -n 1)"
if [[ -z "$fail_summary_json_path" || ! -f "$fail_summary_json_path" ]]; then
  echo "expected failure summary JSON missing"
  cat "$TMP_DIR/integration_three_machine_docker_profile_matrix_record_fail.log"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .schema.id == "three_machine_docker_profile_matrix_record_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and .inputs.run_matrix == true
  and .rc == 1
  and .stages.matrix.ran == true
  and .stages.matrix.status == "fail"
  and .stages.matrix.rc == 1
  and .stages.matrix.command_rc == 1
  and .stages.matrix.reduction.available == true
  and .stages.matrix.reduction.failed_profiles == ["balanced"]
  and .stages.matrix.reduction.failed_profiles_count == 1
  and (.stages.matrix.reduction.rerun_failed_profiles_command | contains("--profiles balanced"))
  and .stages.manual_validation_record.ran == true
  and .stages.manual_validation_record.status == "ok"
  and .stages.manual_validation_record.check_id == "three_machine_docker_readiness"
  and .stages.manual_validation_report.status == "ok"
  and .stages.manual_validation_report.readiness_status == "NOT_READY"
' "$fail_summary_json_path" >/dev/null; then
  echo "failure summary JSON missing expected contract fields"
  cat "$fail_summary_json_path"
  exit 1
fi

echo "three machine docker profile matrix record integration check ok"
