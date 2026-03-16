#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

REPORTS_DIR="$TMP_DIR/reports"
mkdir -p "$REPORTS_DIR"

SUMMARY_JSON="$REPORTS_DIR/prod_pilot_campaign_summary.json"
REPORT_MD="$REPORTS_DIR/prod_pilot_campaign_summary.md"
RUNBOOK_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_cohort_quick_runbook_summary.json"
QUICK_RUN_REPORT_JSON="$REPORTS_DIR/prod_pilot_cohort_quick_report.json"
RUN_REPORT_JSON="$REPORTS_DIR/prod_pilot_campaign_run_report.json"
SIGNOFF_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_campaign_signoff_summary.json"
CHECK_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_campaign_check_summary.json"

cat >"$SUMMARY_JSON" <<'EOF_SUMMARY'
{
  "decision": "GO",
  "decision_reason": "all required campaign gates passed",
  "fail_policy": {
    "require_incident_snapshot_on_fail": 1,
    "require_incident_snapshot_artifacts": 1,
    "incident_snapshot_min_attachment_count": 1,
    "incident_snapshot_max_skipped_count": 0
  },
  "incident_policy_errors": []
}
EOF_SUMMARY
cat >"$REPORT_MD" <<'EOF_REPORT'
# Campaign Summary
EOF_REPORT

cat >"$RUNBOOK_SUMMARY_JSON" <<'EOF_RUNBOOK'
{
  "status": "ok",
  "final_rc": 0
}
EOF_RUNBOOK

cat >"$QUICK_RUN_REPORT_JSON" <<'EOF_QUICK_RUN_REPORT'
{
  "status": "ok",
  "runbook_rc": 0,
  "signoff_rc": 0
}
EOF_QUICK_RUN_REPORT

cat >"$SIGNOFF_SUMMARY_JSON" <<'EOF_SIGNOFF_SUMMARY'
{
  "status": "ok",
  "failure_stage": "",
  "final_rc": 0
}
EOF_SIGNOFF_SUMMARY

cat >"$RUN_REPORT_JSON" <<EOF_RUN_REPORT
{
  "status": "ok",
  "failure_step": "",
  "final_rc": 0,
  "stages": {
    "quick_runbook": {"rc": 0},
    "campaign_summary": {"attempted": true, "rc": 0},
    "campaign_signoff": {"enabled": true, "required": true, "attempted": true, "rc": 0}
  },
  "config": {
    "campaign_summary_fail_close": 1,
    "campaign_signoff_check": 1,
    "campaign_run_report_required": 1,
    "campaign_run_report_json_required": 1,
    "require_incident_snapshot_on_fail": 1,
    "require_incident_snapshot_artifacts": 1,
    "incident_snapshot_min_attachment_count": 1,
    "incident_snapshot_max_skipped_count": 0
  },
  "artifacts": {
    "runbook_summary_json": {"path": "$RUNBOOK_SUMMARY_JSON", "exists": true, "valid_json": true},
    "quick_run_report_json": {"path": "$QUICK_RUN_REPORT_JSON", "exists": true, "valid_json": true},
    "campaign_summary_json": {"path": "$SUMMARY_JSON", "exists": true, "valid_json": true},
    "campaign_report_md": {"path": "$REPORT_MD", "exists": true},
    "campaign_signoff_summary_json": {"path": "$SIGNOFF_SUMMARY_JSON", "exists": true, "valid_json": true}
  }
}
EOF_RUN_REPORT

echo "[prod-pilot-cohort-campaign-check] baseline pass"
./scripts/prod_pilot_cohort_campaign_check.sh \
  --campaign-run-report-json "$RUN_REPORT_JSON" \
  --summary-json "$CHECK_SUMMARY_JSON" \
  --print-summary-json 0 >/tmp/integration_prod_pilot_cohort_campaign_check_pass.log 2>&1
if ! rg -q 'decision=GO' /tmp/integration_prod_pilot_cohort_campaign_check_pass.log; then
  echo "campaign-check should report GO on baseline pass"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_pass.log
  exit 1
fi
if [[ ! -f "$CHECK_SUMMARY_JSON" ]]; then
  echo "campaign-check should emit summary JSON when --summary-json is set"
  exit 1
fi
if [[ "$(jq -r '.decision // ""' "$CHECK_SUMMARY_JSON")" != "GO" ]]; then
  echo "campaign-check summary JSON should report GO on baseline pass"
  cat "$CHECK_SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.issues | length' "$CHECK_SUMMARY_JSON")" != "0" ]]; then
  echo "campaign-check summary JSON issues should be empty on baseline pass"
  cat "$CHECK_SUMMARY_JSON"
  exit 1
fi

echo "[prod-pilot-cohort-campaign-check] reports-dir auto-resolve"
./scripts/prod_pilot_cohort_campaign_check.sh \
  --reports-dir "$REPORTS_DIR" >/tmp/integration_prod_pilot_cohort_campaign_check_reports_dir.log 2>&1

echo "[prod-pilot-cohort-campaign-check] campaign decision fail"
BAD_DECISION_SUMMARY="$REPORTS_DIR/prod_pilot_campaign_summary_bad_decision.json"
BAD_DECISION_RUN_REPORT="$REPORTS_DIR/prod_pilot_campaign_run_report_bad_decision.json"
BAD_DECISION_CHECK_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_campaign_check_bad_decision_summary.json"
jq '.decision="NO-GO" | .decision_reason="synthetic no-go"' "$SUMMARY_JSON" >"$BAD_DECISION_SUMMARY"
jq --arg summary "$BAD_DECISION_SUMMARY" '.artifacts.campaign_summary_json.path=$summary' "$RUN_REPORT_JSON" >"$BAD_DECISION_RUN_REPORT"
set +e
./scripts/prod_pilot_cohort_campaign_check.sh \
  --campaign-run-report-json "$BAD_DECISION_RUN_REPORT" \
  --summary-json "$BAD_DECISION_CHECK_SUMMARY_JSON" >/tmp/integration_prod_pilot_cohort_campaign_check_bad_decision.log 2>&1
bad_decision_rc=$?
set -e
if [[ "$bad_decision_rc" -eq 0 ]]; then
  echo "campaign-check should fail when campaign summary decision is NO-GO"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_decision.log
  exit 1
fi
if ! rg -q 'campaign summary decision is not GO' /tmp/integration_prod_pilot_cohort_campaign_check_bad_decision.log; then
  echo "campaign-check missing campaign decision failure signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_decision.log
  exit 1
fi
if [[ ! -f "$BAD_DECISION_CHECK_SUMMARY_JSON" ]]; then
  echo "campaign-check should emit summary JSON on fail path when --summary-json is set"
  exit 1
fi
if [[ "$(jq -r '.decision // ""' "$BAD_DECISION_CHECK_SUMMARY_JSON")" != "NO-GO" ]]; then
  echo "campaign-check summary JSON should report NO-GO on fail path"
  cat "$BAD_DECISION_CHECK_SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.issues | length' "$BAD_DECISION_CHECK_SUMMARY_JSON")" -lt 1 ]]; then
  echo "campaign-check summary JSON should capture failure issues on fail path"
  cat "$BAD_DECISION_CHECK_SUMMARY_JSON"
  exit 1
fi

echo "[prod-pilot-cohort-campaign-check] summary policy mismatch fail"
BAD_POLICY_SUMMARY="$REPORTS_DIR/prod_pilot_campaign_summary_bad_policy.json"
BAD_POLICY_RUN_REPORT="$REPORTS_DIR/prod_pilot_campaign_run_report_bad_policy.json"
jq '.fail_policy.require_incident_snapshot_on_fail=0' "$SUMMARY_JSON" >"$BAD_POLICY_SUMMARY"
jq --arg summary "$BAD_POLICY_SUMMARY" '.artifacts.campaign_summary_json.path=$summary' "$RUN_REPORT_JSON" >"$BAD_POLICY_RUN_REPORT"
set +e
./scripts/prod_pilot_cohort_campaign_check.sh \
  --campaign-run-report-json "$BAD_POLICY_RUN_REPORT" >/tmp/integration_prod_pilot_cohort_campaign_check_bad_policy.log 2>&1
bad_policy_rc=$?
set -e
if [[ "$bad_policy_rc" -eq 0 ]]; then
  echo "campaign-check should fail when summary fail_policy drifts from expected policy"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_policy.log
  exit 1
fi
if ! rg -q 'campaign summary fail_policy.require_incident_snapshot_on_fail mismatch' /tmp/integration_prod_pilot_cohort_campaign_check_bad_policy.log; then
  echo "campaign-check missing summary fail_policy mismatch signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_policy.log
  exit 1
fi

echo "[prod-pilot-cohort-campaign-check] quick run report artifact fail"
BAD_QUICK_RUN_REPORT="$REPORTS_DIR/prod_pilot_campaign_run_report_bad_quick_artifact.json"
MISSING_QUICK_RUN_REPORT="$REPORTS_DIR/quick_run_report_missing.json"
jq --arg quick "$MISSING_QUICK_RUN_REPORT" \
  '.artifacts.quick_run_report_json.path=$quick | .artifacts.quick_run_report_json.exists=true | .artifacts.quick_run_report_json.valid_json=true' \
  "$RUN_REPORT_JSON" >"$BAD_QUICK_RUN_REPORT"
set +e
./scripts/prod_pilot_cohort_campaign_check.sh \
  --campaign-run-report-json "$BAD_QUICK_RUN_REPORT" >/tmp/integration_prod_pilot_cohort_campaign_check_bad_quick_artifact.log 2>&1
bad_quick_artifact_rc=$?
set -e
if [[ "$bad_quick_artifact_rc" -eq 0 ]]; then
  echo "campaign-check should fail when quick run report artifact is missing"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_quick_artifact.log
  exit 1
fi
if ! rg -q 'quick run report JSON file not found' /tmp/integration_prod_pilot_cohort_campaign_check_bad_quick_artifact.log; then
  echo "campaign-check missing quick run report artifact failure signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_quick_artifact.log
  exit 1
fi

echo "[prod-pilot-cohort-campaign-check] campaign signoff stage fail"
BAD_SIGNOFF_RUN_REPORT="$REPORTS_DIR/prod_pilot_campaign_run_report_bad_signoff_stage.json"
jq '.stages.campaign_signoff.attempted=false' "$RUN_REPORT_JSON" >"$BAD_SIGNOFF_RUN_REPORT"
set +e
./scripts/prod_pilot_cohort_campaign_check.sh \
  --campaign-run-report-json "$BAD_SIGNOFF_RUN_REPORT" >/tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_stage.log 2>&1
bad_signoff_stage_rc=$?
set -e
if [[ "$bad_signoff_stage_rc" -eq 0 ]]; then
  echo "campaign-check should fail when campaign signoff stage is not attempted"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_stage.log
  exit 1
fi
if ! rg -q 'campaign signoff stage was not attempted' /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_stage.log; then
  echo "campaign-check missing campaign signoff stage failure signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_stage.log
  exit 1
fi

echo "[prod-pilot-cohort-campaign-check] campaign signoff enabled/required policy fail"
BAD_SIGNOFF_POLICY_RUN_REPORT="$REPORTS_DIR/prod_pilot_campaign_run_report_bad_signoff_policy.json"
jq '.stages.campaign_signoff.enabled=false | .stages.campaign_signoff.required=false' "$RUN_REPORT_JSON" >"$BAD_SIGNOFF_POLICY_RUN_REPORT"
set +e
./scripts/prod_pilot_cohort_campaign_check.sh \
  --campaign-run-report-json "$BAD_SIGNOFF_POLICY_RUN_REPORT" >/tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_policy.log 2>&1
bad_signoff_policy_rc=$?
set -e
if [[ "$bad_signoff_policy_rc" -eq 0 ]]; then
  echo "campaign-check should fail when campaign signoff enabled/required policy is weakened"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_policy.log
  exit 1
fi
if ! rg -q 'campaign signoff stage is not enabled in wrapper run report' /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_policy.log; then
  echo "campaign-check missing campaign signoff enabled policy failure signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_policy.log
  exit 1
fi
if ! rg -q 'campaign signoff stage is not required in wrapper run report' /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_policy.log; then
  echo "campaign-check missing campaign signoff required policy failure signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_policy.log
  exit 1
fi

echo "[prod-pilot-cohort-campaign-check] campaign signoff summary status/final_rc fail"
BAD_SIGNOFF_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_campaign_signoff_summary_bad_status.json"
BAD_SIGNOFF_SUMMARY_RUN_REPORT="$REPORTS_DIR/prod_pilot_campaign_run_report_bad_signoff_summary.json"
jq '.status="fail" | .final_rc=7' "$SIGNOFF_SUMMARY_JSON" >"$BAD_SIGNOFF_SUMMARY_JSON"
jq --arg signoff "$BAD_SIGNOFF_SUMMARY_JSON" \
  '.artifacts.campaign_signoff_summary_json.path=$signoff | .artifacts.campaign_signoff_summary_json.exists=true | .artifacts.campaign_signoff_summary_json.valid_json=true' \
  "$RUN_REPORT_JSON" >"$BAD_SIGNOFF_SUMMARY_RUN_REPORT"
set +e
./scripts/prod_pilot_cohort_campaign_check.sh \
  --campaign-run-report-json "$BAD_SIGNOFF_SUMMARY_RUN_REPORT" >/tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_summary.log 2>&1
bad_signoff_summary_rc=$?
set -e
if [[ "$bad_signoff_summary_rc" -eq 0 ]]; then
  echo "campaign-check should fail when campaign signoff summary status/final_rc are not healthy"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_summary.log
  exit 1
fi
if ! rg -q 'campaign signoff summary status is not ok' /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_summary.log; then
  echo "campaign-check missing campaign signoff summary status failure signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_summary.log
  exit 1
fi
if ! rg -q 'campaign signoff summary final_rc is non-zero' /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_summary.log; then
  echo "campaign-check missing campaign signoff summary final_rc failure signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_signoff_summary.log
  exit 1
fi

echo "[prod-pilot-cohort-campaign-check] campaign wrapper config floor fail"
BAD_CONFIG_RUN_REPORT="$REPORTS_DIR/prod_pilot_campaign_run_report_bad_config_floor.json"
jq '.config.campaign_summary_fail_close=0 | .config.campaign_signoff_check=0 | .config.campaign_run_report_required=0 | .config.campaign_run_report_json_required=0' \
  "$RUN_REPORT_JSON" >"$BAD_CONFIG_RUN_REPORT"
set +e
./scripts/prod_pilot_cohort_campaign_check.sh \
  --campaign-run-report-json "$BAD_CONFIG_RUN_REPORT" >/tmp/integration_prod_pilot_cohort_campaign_check_bad_config_floor.log 2>&1
bad_config_floor_rc=$?
set -e
if [[ "$bad_config_floor_rc" -eq 0 ]]; then
  echo "campaign-check should fail when wrapper fail-close config floors are weakened"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_config_floor.log
  exit 1
fi
if ! rg -q 'config.campaign_summary_fail_close is not enabled' /tmp/integration_prod_pilot_cohort_campaign_check_bad_config_floor.log; then
  echo "campaign-check missing campaign_summary_fail_close floor failure signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_config_floor.log
  exit 1
fi
if ! rg -q 'config.campaign_signoff_check is not enabled' /tmp/integration_prod_pilot_cohort_campaign_check_bad_config_floor.log; then
  echo "campaign-check missing campaign_signoff_check floor failure signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_config_floor.log
  exit 1
fi
if ! rg -q 'config.campaign_run_report_required is not enabled' /tmp/integration_prod_pilot_cohort_campaign_check_bad_config_floor.log; then
  echo "campaign-check missing campaign_run_report_required floor failure signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_config_floor.log
  exit 1
fi
if ! rg -q 'config.campaign_run_report_json_required is not enabled' /tmp/integration_prod_pilot_cohort_campaign_check_bad_config_floor.log; then
  echo "campaign-check missing campaign_run_report_json_required floor failure signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_config_floor.log
  exit 1
fi

echo "[prod-pilot-cohort-campaign-check] artifact path mismatch fail"
MISMATCH_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_campaign_summary_mismatch.json"
BAD_PATH_RUN_REPORT="$REPORTS_DIR/prod_pilot_campaign_run_report_bad_path_match.json"
cp "$SUMMARY_JSON" "$MISMATCH_SUMMARY_JSON"
jq --arg mismatch "$MISMATCH_SUMMARY_JSON" \
  '.artifacts.campaign_summary_json.path=$mismatch | .artifacts.campaign_summary_json.exists=true | .artifacts.campaign_summary_json.valid_json=true' \
  "$RUN_REPORT_JSON" >"$BAD_PATH_RUN_REPORT"
set +e
./scripts/prod_pilot_cohort_campaign_check.sh \
  --campaign-run-report-json "$BAD_PATH_RUN_REPORT" \
  --campaign-summary-json "$SUMMARY_JSON" >/tmp/integration_prod_pilot_cohort_campaign_check_bad_path_match.log 2>&1
bad_path_match_rc=$?
set -e
if [[ "$bad_path_match_rc" -eq 0 ]]; then
  echo "campaign-check should fail when run-report artifact paths drift from resolved inputs"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_path_match.log
  exit 1
fi
if ! rg -q 'run report campaign summary path does not match resolved input' /tmp/integration_prod_pilot_cohort_campaign_check_bad_path_match.log; then
  echo "campaign-check missing artifact path mismatch failure signal"
  cat /tmp/integration_prod_pilot_cohort_campaign_check_bad_path_match.log
  exit 1
fi

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  printf 'Docker Compose version vtest\n'
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  exit 0
fi
if [[ "${1:-}" == "--version" ]]; then
  printf 'Docker version test\n'
  exit 0
fi
if [[ "${1:-}" == "info" ]]; then
  exit 0
fi
exit 0
EOF_DOCKER
chmod +x "$TMP_BIN/docker"

FAKE_CHECK="$TMP_DIR/fake_campaign_check.sh"
DISPATCH_CAPTURE="$TMP_DIR/campaign_check_dispatch.log"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DISPATCH_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

echo "[prod-pilot-cohort-campaign-check] easy-node command dispatch"
PATH="$TMP_BIN:$PATH" \
DISPATCH_CAPTURE_FILE="$DISPATCH_CAPTURE" \
PROD_PILOT_COHORT_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/easy_node.sh prod-pilot-cohort-campaign-check \
  --campaign-run-report-json /tmp/campaign_run_report.json \
  --campaign-summary-json /tmp/campaign_summary.json \
  --campaign-signoff-summary-json /tmp/campaign_signoff_summary.json \
  --require-runbook-summary-json 0 \
  --require-quick-run-report-json 0 \
  --require-campaign-summary-go 0 \
  --require-campaign-signoff-attempted 0 \
  --require-campaign-signoff-enabled 0 \
  --require-campaign-signoff-required 0 \
  --require-campaign-signoff-ok 0 \
  --require-campaign-signoff-summary-json 0 \
  --require-campaign-signoff-summary-json-valid 0 \
  --require-campaign-signoff-summary-status-ok 0 \
  --require-campaign-signoff-summary-final-rc-zero 0 \
  --require-campaign-summary-fail-close 0 \
  --require-campaign-signoff-check 0 \
  --require-campaign-run-report-required 0 \
  --require-campaign-run-report-json-required 0 \
  --require-artifact-path-match 0 \
  --require-summary-policy-match 0 \
  --require-incident-policy-clean 0 \
  --summary-json /tmp/campaign_check_summary.json \
  --print-summary-json 1 \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_campaign_check_dispatch.log 2>&1

if ! rg -q -- '--campaign-run-report-json /tmp/campaign_run_report.json' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --campaign-run-report-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--campaign-summary-json /tmp/campaign_summary.json' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --campaign-summary-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--campaign-signoff-summary-json /tmp/campaign_signoff_summary.json' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --campaign-signoff-summary-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-runbook-summary-json 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-runbook-summary-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-quick-run-report-json 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-quick-run-report-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-summary-go 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-summary-go"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-attempted 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-signoff-attempted"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-enabled 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-signoff-enabled"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-required 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-signoff-required"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-ok 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-signoff-ok"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-summary-json 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-signoff-summary-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-summary-json-valid 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-signoff-summary-json-valid"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-summary-status-ok 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-signoff-summary-status-ok"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-summary-final-rc-zero 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-signoff-summary-final-rc-zero"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-summary-fail-close 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-summary-fail-close"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-check 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-signoff-check"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-run-report-required 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-run-report-required"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-run-report-json-required 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-campaign-run-report-json-required"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-artifact-path-match 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-artifact-path-match"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-summary-policy-match 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-summary-policy-match"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-policy-clean 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --require-incident-policy-clean"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json /tmp/campaign_check_summary.json' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --summary-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-summary-json 1' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --print-summary-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$DISPATCH_CAPTURE"; then
  echo "easy-node campaign-check dispatch missing --show-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi

echo "prod pilot cohort campaign check integration check ok"
