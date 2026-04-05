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
FAKE_SIGNOFF="$TMP_DIR/fake_three_machine_prod_signoff.sh"

cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_EASY_CAPTURE_FILE:?}"
cmd="${1:-}"
shift || true
case "$cmd" in
  runtime-doctor)
    count_file="${FAKE_RUNTIME_DOCTOR_COUNT_FILE:-}"
    sequence="${FAKE_RUNTIME_DOCTOR_STATUS_SEQUENCE:-OK}"
    call_index=1
    if [[ -n "$count_file" ]]; then
      if [[ -f "$count_file" ]]; then
        call_index="$(cat "$count_file")"
      fi
      printf '%s\n' $((call_index + 1)) >"$count_file"
    fi
    status="$(printf '%s\n' "$sequence" | cut -d, -f"$call_index")"
    if [[ -z "$status" ]]; then
      status="$(printf '%s\n' "$sequence" | awk -F, '{print $NF}')"
    fi
    findings_total=0
    if [[ "$status" != "OK" ]]; then
      findings_total=1
    fi
    echo "[runtime-doctor] status=$status findings=$findings_total warnings=$findings_total failures=0"
    echo "[runtime-doctor] summary_json_payload:"
    cat <<EOF_DOCTOR
{"version":1,"status":"$status","summary":{"findings_total":$findings_total},"findings":[{"code":"test_runtime"}]}
EOF_DOCTOR
    if [[ "$status" == "FAIL" ]]; then
      exit 1
    fi
    exit 0
    ;;
  runtime-fix)
    echo "[runtime-fix] before_status=WARN findings=1"
    echo "[runtime-fix] after_status=OK findings=0 actions_taken=1 actions_skipped=0 actions_failed=0"
    echo "[runtime-fix] summary_json_payload:"
    cat <<'EOF_FIX'
{"version":1,"doctor":{"before":{"status":"WARN","summary":{"findings_total":1}},"after":{"status":"OK","summary":{"findings_total":0}}},"actions":{"taken":["cleanup"],"failed":[]}}
EOF_FIX
    exit 0
    ;;
  pre-real-host-readiness)
    summary_json=""
    readiness_summary_json=""
    readiness_report_md=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --summary-json)
          summary_json="${2:-}"
          shift 2
          ;;
        --manual-validation-report-summary-json)
          readiness_summary_json="${2:-}"
          shift 2
          ;;
        --manual-validation-report-md)
          readiness_report_md="${2:-}"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ -n "$readiness_summary_json" ]]; then
      mkdir -p "$(dirname "$readiness_summary_json")"
      cat >"$readiness_summary_json" <<'EOF_PRE_READY_JSON'
{"report":{"readiness_status":"NOT_READY"}}
EOF_PRE_READY_JSON
    fi
    if [[ -n "$readiness_report_md" ]]; then
      mkdir -p "$(dirname "$readiness_report_md")"
      cat >"$readiness_report_md" <<'EOF_PRE_READY_MD'
# Manual Validation Readiness Report
EOF_PRE_READY_MD
    fi
    if [[ -z "$summary_json" ]]; then
      echo "missing pre-real-host summary json" >&2
      exit 1
    fi
    mkdir -p "$(dirname "$summary_json")"
    if [[ "${FAKE_PRE_REAL_HOST_FAIL:-0}" == "1" ]]; then
      cat >"$summary_json" <<EOF_PRE_REAL_FAIL
{"status":"fail","machine_c_smoke_gate":{"ready":false,"blockers":["runtime_hygiene"],"next_command":"sudo ./scripts/easy_node.sh client-vpn-smoke --runtime-fix 1"},"manual_validation_report":{"summary_json":"$readiness_summary_json","report_md":"$readiness_report_md","readiness_status":"NOT_READY"}}
EOF_PRE_REAL_FAIL
      echo "[pre-real-host-readiness] status=FAIL stage=runtime-fix"
      echo "[pre-real-host-readiness] machine_c_smoke_ready=false"
      echo "[pre-real-host-readiness] blockers=runtime_hygiene"
      echo "[pre-real-host-readiness] manual_validation_readiness_status=NOT_READY"
      echo "[pre-real-host-readiness] next_machine_c_command=sudo ./scripts/easy_node.sh client-vpn-smoke --runtime-fix 1"
      echo "[pre-real-host-readiness] summary_json=$summary_json"
      echo "[pre-real-host-readiness] summary_log=${summary_json%.json}.log"
      if [[ -n "$readiness_summary_json" ]]; then
        echo "[pre-real-host-readiness] readiness_report_json=$readiness_summary_json"
      fi
      if [[ -n "$readiness_report_md" ]]; then
        echo "[pre-real-host-readiness] readiness_report_md=$readiness_report_md"
      fi
      echo "[pre-real-host-readiness] summary_json_payload:"
      cat "$summary_json"
      exit 1
    fi
    cat >"$summary_json" <<EOF_PRE_REAL_OK
{"status":"pass","machine_c_smoke_gate":{"ready":true,"blockers":[],"next_command":"sudo ./scripts/easy_node.sh client-vpn-smoke --runtime-fix 1"},"manual_validation_report":{"summary_json":"$readiness_summary_json","report_md":"$readiness_report_md","readiness_status":"NOT_READY"}}
EOF_PRE_REAL_OK
    echo "[pre-real-host-readiness] status=PASS stage=complete"
    echo "[pre-real-host-readiness] machine_c_smoke_ready=true"
    echo "[pre-real-host-readiness] blockers=none"
    echo "[pre-real-host-readiness] manual_validation_readiness_status=NOT_READY"
    echo "[pre-real-host-readiness] next_machine_c_command=sudo ./scripts/easy_node.sh client-vpn-smoke --runtime-fix 1"
    echo "[pre-real-host-readiness] summary_json=$summary_json"
    echo "[pre-real-host-readiness] summary_log=${summary_json%.json}.log"
    if [[ -n "$readiness_summary_json" ]]; then
      echo "[pre-real-host-readiness] readiness_report_json=$readiness_summary_json"
    fi
    if [[ -n "$readiness_report_md" ]]; then
      echo "[pre-real-host-readiness] readiness_report_md=$readiness_report_md"
    fi
    echo "[pre-real-host-readiness] summary_json_payload:"
    cat "$summary_json"
    exit 0
    ;;
  three-machine-prod-bundle)
    bundle_dir=""
    run_report_json=""
    signoff_check=""
    declare -a attach_artifacts=()
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --bundle-dir)
          bundle_dir="${2:-}"
          shift 2
          ;;
        --run-report-json)
          run_report_json="${2:-}"
          shift 2
          ;;
        --signoff-check)
          signoff_check="${2:-}"
          shift 2
          ;;
        --incident-snapshot-attach-artifact)
          attach_artifacts+=("${2:-}")
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ -z "$bundle_dir" || -z "$run_report_json" ]]; then
      echo "missing expected bundle outputs" >&2
      exit 2
    fi
    mkdir -p "$bundle_dir"
    bundle_tar="${bundle_dir}.tar.gz"
    gate_summary_json="${bundle_dir}/prod_gate_summary.json"
    wg_validate_summary_json="${bundle_dir}/prod_wg_validate_summary.json"
    wg_soak_summary_json="${bundle_dir}/prod_wg_soak_summary.json"
    touch "$bundle_tar" "$gate_summary_json" "$wg_validate_summary_json" "$wg_soak_summary_json"
    if [[ "${FAKE_PROD_SIGNOFF_FAIL:-0}" == "1" ]]; then
      incident_dir="${bundle_dir}/incident_snapshot"
      mkdir -p "$incident_dir"
      cat >"$incident_dir/metadata.txt" <<'EOF_INCIDENT_META'
generated_at_utc=2026-03-15T00:00:00Z
host=test-signoff
mode=server
directory_url=https://198.51.100.10:8081
issuer_url=https://198.51.100.10:8082
entry_url=https://198.51.100.10:8083
exit_url=https://203.0.113.20:8084
EOF_INCIDENT_META
      incident_summary_json="${incident_dir}/incident_summary.json"
      incident_report_md="${incident_dir}/incident_report.md"
      incident_tar="${incident_dir}.tar.gz"
      attachment_manifest="${incident_dir}/attachments/manifest.tsv"
      mkdir -p "${incident_dir}/attachments"
      : >"$attachment_manifest"
      attach_index=0
      for artifact in "${attach_artifacts[@]}"; do
        [[ -f "$artifact" ]] || continue
        attach_index=$((attach_index + 1))
        dest_rel="attachments/$(printf '%02d' "$attach_index")_$(basename "$artifact")"
        cp "$artifact" "${incident_dir}/${dest_rel}"
        printf '%s\tfile\t%s\n' "$dest_rel" "$artifact" >>"$attachment_manifest"
      done
      touch "$incident_summary_json" "$incident_report_md" "$incident_tar"
      cat >"$run_report_json" <<EOF_FAIL
{
  "version": 1,
  "status": "fail",
  "final_rc": 1,
  "bundle_dir": "$bundle_dir",
  "bundle_tar": "$bundle_tar",
  "gate_summary_json": "$gate_summary_json",
  "wg_validate_summary_json": "$wg_validate_summary_json",
  "wg_soak_summary_json": "$wg_soak_summary_json",
  "incident_snapshot": {
    "status": "ok",
    "summary_json": "$incident_summary_json",
    "report_md": "$incident_report_md",
    "bundle_dir": "$incident_dir",
    "bundle_tar": "$incident_tar",
    "attachment_manifest": "$attachment_manifest",
    "attachment_skipped": "",
    "attachment_count": $attach_index
  },
  "signoff": {
    "enabled": true,
    "rc": 1
  }
}
EOF_FAIL
      echo "three-machine-prod-bundle failed"
      exit 1
    fi
    cat >"$run_report_json" <<EOF_OK
{
  "version": 1,
  "status": "ok",
  "final_rc": 0,
  "bundle_dir": "$bundle_dir",
  "bundle_tar": "$bundle_tar",
  "gate_summary_json": "$gate_summary_json",
  "wg_validate_summary_json": "$wg_validate_summary_json",
  "wg_soak_summary_json": "$wg_soak_summary_json",
  "incident_snapshot": {
    "status": "skipped",
    "summary_json": "",
    "report_md": "",
    "bundle_dir": "",
    "bundle_tar": ""
  },
  "signoff": {
    "enabled": true,
    "rc": 0
  }
}
EOF_OK
    if [[ "$signoff_check" != "1" ]]; then
      echo "expected signoff-check=1" >&2
      exit 2
    fi
    echo "three-machine-prod-bundle ok"
    exit 0
    ;;
  manual-validation-record)
    echo "manual-validation-record ok"
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
    if [[ -z "$summary_json" || -z "$report_md" ]]; then
      echo "missing manual validation report outputs" >&2
      exit 1
    fi
    mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
    if [[ "${FAKE_MANUAL_REPORT_INVALID:-0}" == "1" ]]; then
      cat >"$summary_json" <<'EOF_REPORT_JSON_INVALID'
{"version":1,"summary":{"next_action_check_id":"machine_c_vpn_smoke"},"report":{"readiness_status":123}}
EOF_REPORT_JSON_INVALID
    else
      cat >"$summary_json" <<'EOF_REPORT_JSON'
{"version":1,"summary":{"next_action_check_id":"machine_c_vpn_smoke"},"report":{"readiness_status":"NOT_READY"}}
EOF_REPORT_JSON
    fi
    cat >"$report_md" <<'EOF_REPORT_MD'
# Manual Validation Readiness Report
EOF_REPORT_MD
    echo "[manual-validation-report] readiness_status=NOT_READY total=4 pass=2 warn=1 fail=1 pending=0"
    echo "[manual-validation-report] summary_json=$summary_json"
    echo "[manual-validation-report] report_md=$report_md"
    echo "[manual-validation-report] next_action_check_id=machine_c_vpn_smoke"
    echo "[manual-validation-report] summary_json_payload:"
    cat "$summary_json"
    exit 0
    ;;
esac
echo "unexpected command: $cmd" >&2
exit 1
EOF_FAKE_EASY
chmod +x "$FAKE_EASY_NODE"

echo "[three-machine-prod-signoff] success path"
runtime_doctor_count="$TMP_DIR/runtime_doctor_count.txt"
printf '1\n' >"$runtime_doctor_count"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
FAKE_RUNTIME_DOCTOR_COUNT_FILE="$runtime_doctor_count" \
THREE_MACHINE_PROD_SIGNOFF_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/three_machine_prod_signoff.sh \
  --directory-a https://198.51.100.10:8081 \
  --directory-b https://203.0.113.20:8081 \
  --issuer-url https://198.51.100.10:8082 \
  --entry-url https://198.51.100.10:8083 \
  --exit-url https://203.0.113.20:8084 \
  --pre-real-host-readiness 1 \
  --print-summary-json 1 >/tmp/integration_three_machine_prod_signoff_ok.log 2>&1

if ! rg -q 'three-machine-prod-signoff: status=pass stage=bundle' /tmp/integration_three_machine_prod_signoff_ok.log; then
  echo "expected pass status for three-machine-prod-signoff success path"
  cat /tmp/integration_three_machine_prod_signoff_ok.log
  exit 1
fi
line_success="$(rg '^three-machine-prod-bundle ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line_success" ]]; then
  echo "expected three-machine-prod-bundle call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^runtime-doctor ' "$CAPTURE"; then
  echo "expected runtime-doctor call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^pre-real-host-readiness ' "$CAPTURE"; then
  echo "expected pre-real-host-readiness call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -F -- '--signoff-check 1' <<<"$line_success" >/dev/null; then
  echo "expected wrapper to force --signoff-check 1"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id three_machine_prod_signoff --status pass ' "$CAPTURE"; then
  echo "expected manual-validation-record pass call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -F -- '--incident-snapshot-attach-artifact' <<<"$line_success" >/dev/null; then
  echo "expected wrapper to forward incident snapshot attachments into bundle command"
  cat "$CAPTURE"
  exit 1
fi
success_summary_json="$(sed -n 's/^summary_json: //p' /tmp/integration_three_machine_prod_signoff_ok.log | tail -n 1)"
if [[ -z "$success_summary_json" || ! -f "$success_summary_json" ]]; then
  echo "expected success summary json file missing"
  cat /tmp/integration_three_machine_prod_signoff_ok.log
  exit 1
fi
if ! jq -e '.status == "pass" and .outputs.run_report_status == "ok" and .incident_snapshot.status == "skipped"' "$success_summary_json" >/dev/null 2>&1; then
  echo "success summary JSON missing expected values"
  cat "$success_summary_json"
  exit 1
fi
if ! jq -e '.pre_real_host_readiness.enabled == true and .pre_real_host_readiness.status == "pass" and .pre_real_host_readiness.machine_c_smoke_ready == true and (.pre_real_host_readiness.summary_json | length) > 0' "$success_summary_json" >/dev/null 2>&1; then
  echo "success summary JSON missing pre-real-host readiness data"
  cat "$success_summary_json"
  exit 1
fi
if ! jq -e '.runtime_gate.enabled == true and .runtime_gate.doctor_status_before == "OK"' "$success_summary_json" >/dev/null 2>&1; then
  echo "success summary JSON missing runtime gate data"
  cat "$success_summary_json"
  exit 1
fi
if ! jq -e '.manual_validation_report.status == "ok" and .manual_validation_report.readiness_status == "NOT_READY" and (.manual_validation_report.summary_json | length) > 0 and (.manual_validation_report.report_md | length) > 0' "$success_summary_json" >/dev/null 2>&1; then
  echo "success summary JSON missing manual validation report data"
  cat "$success_summary_json"
  exit 1
fi
success_runtime_doctor_json="$(jq -r '.runtime_gate.artifacts.doctor_before_json // ""' "$success_summary_json")"
if [[ -z "$success_runtime_doctor_json" || ! -f "$success_runtime_doctor_json" ]]; then
  echo "expected success runtime doctor json artifact missing"
  cat "$success_summary_json"
  exit 1
fi
if ! rg -q '^manual-validation-report ' "$CAPTURE"; then
  echo "expected manual-validation-report call missing on success path"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q 'manual_validation_readiness_report\.md' "$CAPTURE"; then
  echo "expected success receipt artifacts to include manual validation report"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q 'pre_real_host_readiness' "$CAPTURE"; then
  echo "expected success receipt artifacts to include pre-real-host readiness evidence"
  cat "$CAPTURE"
  exit 1
fi

echo "[three-machine-prod-signoff] manual validation malformed payload path"
: >"$CAPTURE"
printf '1\n' >"$runtime_doctor_count"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
FAKE_RUNTIME_DOCTOR_COUNT_FILE="$runtime_doctor_count" \
THREE_MACHINE_PROD_SIGNOFF_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
FAKE_MANUAL_REPORT_INVALID=1 \
./scripts/three_machine_prod_signoff.sh \
  --directory-a https://198.51.100.10:8081 \
  --directory-b https://203.0.113.20:8081 \
  --issuer-url https://198.51.100.10:8082 \
  --entry-url https://198.51.100.10:8083 \
  --exit-url https://203.0.113.20:8084 \
  --pre-real-host-readiness 1 >/tmp/integration_three_machine_prod_signoff_manual_invalid.log 2>&1

if ! rg -q 'three-machine-prod-signoff: status=pass stage=bundle' /tmp/integration_three_machine_prod_signoff_manual_invalid.log; then
  echo "expected pass status when manual-validation payload is malformed"
  cat /tmp/integration_three_machine_prod_signoff_manual_invalid.log
  exit 1
fi
manual_invalid_summary_json="$(sed -n 's/^summary_json: //p' /tmp/integration_three_machine_prod_signoff_manual_invalid.log | tail -n 1)"
if [[ -z "$manual_invalid_summary_json" || ! -f "$manual_invalid_summary_json" ]]; then
  echo "expected manual-invalid summary json file missing"
  cat /tmp/integration_three_machine_prod_signoff_manual_invalid.log
  exit 1
fi
if ! jq -e '.status == "pass" and .manual_validation_report.status == "fail" and .manual_validation_report.readiness_status == "" and .manual_validation_report.next_action_check_id == ""' "$manual_invalid_summary_json" >/dev/null 2>&1; then
  echo "manual-invalid summary JSON missing fail-closed manual-validation status"
  cat "$manual_invalid_summary_json"
  exit 1
fi
if ! rg -q '^manual-validation-report ' "$CAPTURE"; then
  echo "expected manual-validation-report call missing in malformed payload path"
  cat "$CAPTURE"
  exit 1
fi

echo "[three-machine-prod-signoff] failure path"
: >"$CAPTURE"
printf '1\n' >"$runtime_doctor_count"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
FAKE_RUNTIME_DOCTOR_COUNT_FILE="$runtime_doctor_count" \
THREE_MACHINE_PROD_SIGNOFF_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
FAKE_PROD_SIGNOFF_FAIL=1 \
./scripts/three_machine_prod_signoff.sh \
  --directory-a https://198.51.100.10:8081 \
  --directory-b https://203.0.113.20:8081 \
  --issuer-url https://198.51.100.10:8082 \
  --entry-url https://198.51.100.10:8083 \
  --exit-url https://203.0.113.20:8084 \
  --pre-real-host-readiness 1 >/tmp/integration_three_machine_prod_signoff_fail.log 2>&1 && {
    echo "expected three-machine-prod-signoff failure to return non-zero"
    cat /tmp/integration_three_machine_prod_signoff_fail.log
    exit 1
  }

if ! rg -q 'three-machine-prod-signoff: status=fail stage=bundle' /tmp/integration_three_machine_prod_signoff_fail.log; then
  echo "expected fail status for three-machine-prod-signoff failure path"
  cat /tmp/integration_three_machine_prod_signoff_fail.log
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id three_machine_prod_signoff --status fail ' "$CAPTURE"; then
  echo "expected manual-validation-record fail call missing"
  cat "$CAPTURE"
  exit 1
fi
line_fail="$(rg '^three-machine-prod-bundle ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line_fail" ]]; then
  echo "expected three-machine-prod-bundle fail call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -F -- '--incident-snapshot-attach-artifact' <<<"$line_fail" >/dev/null; then
  echo "expected fail bundle command to include incident snapshot attachments"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q 'incident_report\.md' "$CAPTURE"; then
  echo "expected fail receipt artifacts to include incident report"
  cat "$CAPTURE"
  exit 1
fi
fail_summary_json="$(sed -n 's/^summary_json: //p' /tmp/integration_three_machine_prod_signoff_fail.log | tail -n 1)"
if [[ -z "$fail_summary_json" || ! -f "$fail_summary_json" ]]; then
  echo "expected fail summary json file missing"
  cat /tmp/integration_three_machine_prod_signoff_fail.log
  exit 1
fi
if ! jq -e '.status == "fail" and .incident_snapshot.status == "ok" and (.incident_snapshot.report_md | endswith("incident_report.md")) and (.incident_snapshot.attachment_manifest | endswith("attachments/manifest.tsv")) and .incident_snapshot.attachment_count >= 1' "$fail_summary_json" >/dev/null 2>&1; then
  echo "failure summary JSON missing expected incident snapshot values"
  cat "$fail_summary_json"
  exit 1
fi
if ! jq -e '.pre_real_host_readiness.enabled == true and .pre_real_host_readiness.status == "pass"' "$fail_summary_json" >/dev/null 2>&1; then
  echo "failure summary JSON missing pre-real-host readiness pass data"
  cat "$fail_summary_json"
  exit 1
fi
if ! jq -e '.incident_snapshot.refresh_status == "ok" and (.incident_snapshot.refresh_log | length) > 0' "$fail_summary_json" >/dev/null 2>&1; then
  echo "failure summary JSON missing incident refresh metadata"
  cat "$fail_summary_json"
  exit 1
fi
if ! jq -e '.manual_validation_report.status == "ok" and .manual_validation_report.readiness_status == "NOT_READY"' "$fail_summary_json" >/dev/null 2>&1; then
  echo "failure summary JSON missing manual validation report data"
  cat "$fail_summary_json"
  exit 1
fi
if ! rg -q 'manual_validation_readiness_summary\.json' "$CAPTURE"; then
  echo "expected failure receipt artifacts to include manual validation readiness summary"
  cat "$CAPTURE"
  exit 1
fi
if ! jq -e '(.runtime_gate.artifacts.doctor_before_json | length) > 0' "$fail_summary_json" >/dev/null 2>&1; then
  echo "failure summary JSON missing runtime doctor artifact path"
  cat "$fail_summary_json"
  exit 1
fi
fail_attachment_manifest="$(jq -r '.incident_snapshot.attachment_manifest // ""' "$fail_summary_json")"
if [[ -z "$fail_attachment_manifest" || ! -f "$fail_attachment_manifest" ]]; then
  echo "expected failure attachment manifest missing"
  cat "$fail_summary_json"
  exit 1
fi
if ! rg -q 'manual_validation_readiness_summary\.json' "$fail_attachment_manifest"; then
  echo "expected failure attachment manifest to include readiness summary"
  cat "$fail_attachment_manifest"
  exit 1
fi
if ! rg -q 'manual_validation_readiness_report\.md' "$fail_attachment_manifest"; then
  echo "expected failure attachment manifest to include readiness report"
  cat "$fail_attachment_manifest"
  exit 1
fi

echo "[three-machine-prod-signoff] runtime hygiene failure path"
: >"$CAPTURE"
printf '1\n' >"$runtime_doctor_count"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
FAKE_RUNTIME_DOCTOR_COUNT_FILE="$runtime_doctor_count" \
FAKE_RUNTIME_DOCTOR_STATUS_SEQUENCE="WARN" \
THREE_MACHINE_PROD_SIGNOFF_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/three_machine_prod_signoff.sh \
  --directory-a https://198.51.100.10:8081 \
  --directory-b https://203.0.113.20:8081 \
  --issuer-url https://198.51.100.10:8082 \
  --entry-url https://198.51.100.10:8083 \
  --exit-url https://203.0.113.20:8084 \
  --pre-real-host-readiness 1 >/tmp/integration_three_machine_prod_signoff_runtime_fail.log 2>&1 && {
    echo "expected three-machine-prod-signoff runtime hygiene failure to return non-zero"
    cat /tmp/integration_three_machine_prod_signoff_runtime_fail.log
    exit 1
  }

if rg -q '^three-machine-prod-bundle ' "$CAPTURE"; then
  echo "did not expect bundle command when runtime hygiene gate failed"
  cat "$CAPTURE"
  exit 1
fi
runtime_fail_summary_json="$(sed -n 's/^summary_json: //p' /tmp/integration_three_machine_prod_signoff_runtime_fail.log | tail -n 1)"
if [[ -z "$runtime_fail_summary_json" || ! -f "$runtime_fail_summary_json" ]]; then
  echo "expected runtime failure summary json file missing"
  cat /tmp/integration_three_machine_prod_signoff_runtime_fail.log
  exit 1
fi
if ! jq -e '.status == "fail" and .stage == "runtime-doctor" and .runtime_gate.doctor_status_before == "WARN"' "$runtime_fail_summary_json" >/dev/null 2>&1; then
  echo "runtime failure summary JSON missing expected runtime gate values"
  cat "$runtime_fail_summary_json"
  exit 1
fi
if ! jq -e '.pre_real_host_readiness.enabled == true and .pre_real_host_readiness.status == "pass"' "$runtime_fail_summary_json" >/dev/null 2>&1; then
  echo "runtime failure summary JSON missing pre-real-host readiness data"
  cat "$runtime_fail_summary_json"
  exit 1
fi
if ! jq -e '.manual_validation_report.status == "ok" and (.manual_validation_report.log | length) > 0' "$runtime_fail_summary_json" >/dev/null 2>&1; then
  echo "runtime failure summary JSON missing manual validation report data"
  cat "$runtime_fail_summary_json"
  exit 1
fi
if ! rg -q 'manual_validation_readiness_report\.md' "$CAPTURE"; then
  echo "expected runtime failure receipt artifacts to include manual validation report"
  cat "$CAPTURE"
  exit 1
fi
runtime_fail_doctor_json="$(jq -r '.runtime_gate.artifacts.doctor_before_json // ""' "$runtime_fail_summary_json")"
if [[ -z "$runtime_fail_doctor_json" || ! -f "$runtime_fail_doctor_json" ]]; then
  echo "expected runtime failure doctor json artifact missing"
  cat "$runtime_fail_summary_json"
  exit 1
fi

echo "[three-machine-prod-signoff] pre-real-host readiness failure path"
: >"$CAPTURE"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
FAKE_RUNTIME_DOCTOR_COUNT_FILE="$runtime_doctor_count" \
FAKE_PRE_REAL_HOST_FAIL=1 \
THREE_MACHINE_PROD_SIGNOFF_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/three_machine_prod_signoff.sh \
  --directory-a https://198.51.100.10:8081 \
  --directory-b https://203.0.113.20:8081 \
  --issuer-url https://198.51.100.10:8082 \
  --entry-url https://198.51.100.10:8083 \
  --exit-url https://203.0.113.20:8084 \
  --pre-real-host-readiness 1 >/tmp/integration_three_machine_prod_signoff_pre_readiness_fail.log 2>&1 && {
    echo "expected three-machine-prod-signoff pre-real-host readiness failure to return non-zero"
    cat /tmp/integration_three_machine_prod_signoff_pre_readiness_fail.log
    exit 1
  }

if rg -q '^three-machine-prod-bundle ' "$CAPTURE"; then
  echo "did not expect bundle command when pre-real-host readiness gate failed"
  cat "$CAPTURE"
  exit 1
fi
if rg -q '^runtime-doctor ' "$CAPTURE"; then
  echo "did not expect runtime-doctor after pre-real-host readiness gate failed"
  cat "$CAPTURE"
  exit 1
fi
pre_ready_fail_summary_json="$(sed -n 's/^summary_json: //p' /tmp/integration_three_machine_prod_signoff_pre_readiness_fail.log | tail -n 1)"
if [[ -z "$pre_ready_fail_summary_json" || ! -f "$pre_ready_fail_summary_json" ]]; then
  echo "expected pre-real-host readiness failure summary json file missing"
  cat /tmp/integration_three_machine_prod_signoff_pre_readiness_fail.log
  exit 1
fi
if ! jq -e '.status == "fail" and .stage == "pre-real-host-readiness" and .pre_real_host_readiness.status == "fail" and .pre_real_host_readiness.machine_c_smoke_ready == false' "$pre_ready_fail_summary_json" >/dev/null 2>&1; then
  echo "pre-real-host readiness failure summary JSON missing expected values"
  cat "$pre_ready_fail_summary_json"
  exit 1
fi
if ! rg -q 'manual_validation_readiness_report\.md' "$CAPTURE"; then
  echo "expected pre-real-host readiness failure receipt artifacts to include manual validation report"
  cat "$CAPTURE"
  exit 1
fi

echo "[three-machine-prod-signoff] easy_node forwarding"
cat >"$FAKE_SIGNOFF" <<'EOF_FAKE_SIGNOFF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_SIGNOFF_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_SIGNOFF
chmod +x "$FAKE_SIGNOFF"

FAKE_SIGNOFF_CAPTURE_FILE="$TMP_DIR/signoff_wrapper_calls.log" \
THREE_MACHINE_PROD_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
./scripts/easy_node.sh three-machine-prod-signoff \
  --directory-a https://198.51.100.10:8081 \
  --directory-b https://203.0.113.20:8081 \
  --issuer-url https://198.51.100.10:8082 \
  --entry-url https://198.51.100.10:8083 \
  --exit-url https://203.0.113.20:8084 \
  --pre-real-host-readiness 1 \
  --print-summary-json 1 >/tmp/integration_three_machine_prod_signoff_wrapper.log 2>&1

if ! rg -q -- '--directory-a https://198\.51\.100\.10:8081' "$TMP_DIR/signoff_wrapper_calls.log"; then
  echo "easy_node three-machine-prod-signoff forwarding missing directory-a"
  cat "$TMP_DIR/signoff_wrapper_calls.log"
  exit 1
fi
if ! rg -q -- '--directory-b https://203\.0\.113\.20:8081' "$TMP_DIR/signoff_wrapper_calls.log"; then
  echo "easy_node three-machine-prod-signoff forwarding missing directory-b"
  cat "$TMP_DIR/signoff_wrapper_calls.log"
  exit 1
fi
if ! rg -q -- '--pre-real-host-readiness 1' "$TMP_DIR/signoff_wrapper_calls.log"; then
  echo "easy_node three-machine-prod-signoff forwarding missing pre-real-host-readiness"
  cat "$TMP_DIR/signoff_wrapper_calls.log"
  exit 1
fi
if ! rg -q -- '--print-summary-json 1' "$TMP_DIR/signoff_wrapper_calls.log"; then
  echo "easy_node three-machine-prod-signoff forwarding missing print-summary-json"
  cat "$TMP_DIR/signoff_wrapper_calls.log"
  exit 1
fi

echo "three machine prod signoff integration check ok"
