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
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

REPORTS_DIR="$TMP_DIR/reports"
mkdir -p "$REPORTS_DIR"

QUICK_REPORT_JSON="$REPORTS_DIR/prod_pilot_cohort_quick_report.json"
COHORT_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_cohort_summary.json"
SIGNOFF_JSON="$REPORTS_DIR/prod_pilot_quick_signoff.json"
TREND_JSON="$REPORTS_DIR/prod_pilot_quick_signoff_trend.json"
ALERT_JSON="$REPORTS_DIR/prod_pilot_quick_signoff_alert.json"
DASHBOARD_MD="$REPORTS_DIR/prod_pilot_quick_dashboard.md"
RUNBOOK_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_cohort_quick_runbook_summary.json"
PRE_REAL_HOST_READINESS_SUMMARY_JSON="$REPORTS_DIR/pre_real_host_readiness_summary.json"
SUMMARY_JSON="$REPORTS_DIR/prod_pilot_campaign_summary.json"
REPORT_MD="$REPORTS_DIR/prod_pilot_campaign_summary.md"
INCIDENT_BUNDLE_DIR="$REPORTS_DIR/round_2/incident_snapshot"
INCIDENT_SUMMARY_JSON="$INCIDENT_BUNDLE_DIR/incident_summary.json"
INCIDENT_REPORT_MD="$INCIDENT_BUNDLE_DIR/incident_report.md"
INCIDENT_ATTACH_DIR="$INCIDENT_BUNDLE_DIR/attachments"
INCIDENT_ATTACH_MANIFEST="$INCIDENT_ATTACH_DIR/manifest.tsv"
INCIDENT_ATTACH_SKIPPED="$INCIDENT_ATTACH_DIR/skipped.tsv"
FAILED_RUN_REPORT_JSON="$REPORTS_DIR/round_2/prod_bundle_run_report.json"

cat >"$QUICK_REPORT_JSON" <<EOF_QUICK
{
  "status": "ok",
  "failure_step": "",
  "final_rc": 0,
  "signoff": {
    "attempted": true,
    "rc": 0
  },
  "config": {
    "bootstrap_directory": "https://dir-a.example:8081",
    "subject": "pilot-client"
  }
}
EOF_QUICK

cat >"$COHORT_SUMMARY_JSON" <<EOF_COHORT
{
  "status": "ok",
  "final_rc": 0,
  "rounds": {
    "requested": 6,
    "attempted": 6,
    "passed": 6,
    "failed": 0
  },
  "bundle": {
    "created": true,
    "manifest_created": true
  },
  "artifacts": {
    "run_reports": [],
    "bundle_tar": "$REPORTS_DIR/prod_pilot_cohort_bundle.tar.gz",
    "bundle_manifest_json": "$REPORTS_DIR/prod_pilot_cohort_bundle_manifest.json"
  }
}
EOF_COHORT

mkdir -p "$INCIDENT_BUNDLE_DIR"
mkdir -p "$INCIDENT_ATTACH_DIR"
cat >"$INCIDENT_SUMMARY_JSON" <<'EOF_INCIDENT_SUMMARY'
{"status":"ok","findings":[]}
EOF_INCIDENT_SUMMARY
cat >"$INCIDENT_REPORT_MD" <<'EOF_INCIDENT_REPORT'
# Incident Snapshot Summary
EOF_INCIDENT_REPORT
printf 'attachments/01_runtime_doctor_before.json\tfile\t/tmp/runtime_doctor_before.json\n' >"$INCIDENT_ATTACH_MANIFEST"
printf '/tmp/runtime_fix.json\tmissing\n' >"$INCIDENT_ATTACH_SKIPPED"
cat >"$FAILED_RUN_REPORT_JSON" <<EOF_FAILED_RUN_REPORT
{
  "status": "fail",
  "final_rc": 9,
  "incident_snapshot": {
    "enabled": true,
    "enabled_on_fail": true,
    "status": "ok",
    "bundle_dir": "$INCIDENT_BUNDLE_DIR",
    "bundle_tar": "$INCIDENT_BUNDLE_DIR.tar.gz",
    "summary_json": "$INCIDENT_SUMMARY_JSON",
    "report_md": "$INCIDENT_REPORT_MD",
    "attachment_manifest": "$INCIDENT_ATTACH_MANIFEST",
    "attachment_skipped": "$INCIDENT_ATTACH_SKIPPED",
    "attachment_count": 1
  }
}
EOF_FAILED_RUN_REPORT
printf 'tar placeholder\n' >"$INCIDENT_BUNDLE_DIR.tar.gz"

cat >"$COHORT_SUMMARY_JSON" <<EOF_COHORT
{
  "status": "ok",
  "final_rc": 0,
  "rounds": {
    "requested": 6,
    "attempted": 6,
    "passed": 6,
    "failed": 0
  },
  "bundle": {
    "created": true,
    "manifest_created": true
  },
  "artifacts": {
    "run_reports": [
      "$FAILED_RUN_REPORT_JSON"
    ],
    "bundle_tar": "$REPORTS_DIR/prod_pilot_cohort_bundle.tar.gz",
    "bundle_manifest_json": "$REPORTS_DIR/prod_pilot_cohort_bundle_manifest.json"
  }
}
EOF_COHORT

touch "$REPORTS_DIR/prod_pilot_cohort_bundle.tar.gz" "$REPORTS_DIR/prod_pilot_cohort_bundle_manifest.json"

cat >"$SIGNOFF_JSON" <<EOF_SIGNOFF
{
  "status": "ok",
  "failure_step": "",
  "final_rc": 0,
  "observed": {
    "alert_severity": "WARN"
  }
}
EOF_SIGNOFF

cat >"$TREND_JSON" <<'EOF_TREND'
{
  "decision": "GO",
  "go_rate_pct": 100.00,
  "no_go": 0,
  "evaluation_errors": 0,
  "top_no_go_reasons": []
}
EOF_TREND

cat >"$ALERT_JSON" <<'EOF_ALERT'
{
  "severity": "WARN",
  "trigger_reasons": [
    "go_rate_pct 100.00 < warn_go_rate_pct 101.00"
  ]
}
EOF_ALERT

cat >"$DASHBOARD_MD" <<'EOF_DASH'
# Quick Dashboard
EOF_DASH

cat >"$PRE_REAL_HOST_READINESS_SUMMARY_JSON" <<'EOF_PRE_REAL_HOST'
{
  "status": "ok",
  "machine_c_smoke_gate": {
    "ready": true,
    "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke ..."
  }
}
EOF_PRE_REAL_HOST

cat >"$RUNBOOK_SUMMARY_JSON" <<EOF_RUNBOOK
{
  "status": "ok",
  "failure_step": "",
  "final_rc": 0,
  "duration_sec": 321,
  "stages": {
    "quick": {"rc": 0},
    "quick_signoff": {"rc": 0},
    "quick_dashboard": {"rc": 0}
  },
  "config": {
    "rounds": 6,
    "pause_sec": 45,
    "max_alert_severity": "WARN"
  },
  "artifacts": {
    "reports_dir": "$REPORTS_DIR",
    "summary_json": "$COHORT_SUMMARY_JSON",
    "run_report_json": "$QUICK_REPORT_JSON",
    "signoff_json": "$SIGNOFF_JSON",
    "trend_summary_json": "$TREND_JSON",
    "alert_summary_json": "$ALERT_JSON",
    "dashboard_md": "$DASHBOARD_MD",
    "pre_real_host_readiness_summary_json": "$PRE_REAL_HOST_READINESS_SUMMARY_JSON"
  }
}
EOF_RUNBOOK

echo "[prod-pilot-cohort-campaign-summary] standalone GO summary"
./scripts/prod_pilot_cohort_campaign_summary.sh \
  --runbook-summary-json "$RUNBOOK_SUMMARY_JSON" \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_prod_pilot_cohort_campaign_summary_go.log 2>&1

if [[ ! -f "$SUMMARY_JSON" ]]; then
  echo "campaign summary JSON was not created"
  exit 1
fi
if [[ ! -f "$REPORT_MD" ]]; then
  echo "campaign report markdown was not created"
  exit 1
fi
if [[ "$(jq -r '.decision' "$SUMMARY_JSON")" != "GO" ]]; then
  echo "campaign summary JSON decision should be GO"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.signoff.alert_severity' "$SUMMARY_JSON")" != "WARN" ]]; then
  echo "campaign summary JSON missing signoff alert severity"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.summary_json.path' "$SUMMARY_JSON")" != "$INCIDENT_SUMMARY_JSON" ]]; then
  echo "campaign summary JSON missing incident snapshot summary_json path"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.source_runbook_summary_json.path' "$SUMMARY_JSON")" != "$RUNBOOK_SUMMARY_JSON" ]]; then
  echo "campaign summary JSON missing incident snapshot source runbook summary path"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.source_pre_real_host_readiness_summary_json.path' "$SUMMARY_JSON")" != "$PRE_REAL_HOST_READINESS_SUMMARY_JSON" ]]; then
  echo "campaign summary JSON missing incident snapshot source pre-real-host readiness summary path"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.source_quick_run_report_json.path' "$SUMMARY_JSON")" != "$QUICK_REPORT_JSON" ]]; then
  echo "campaign summary JSON missing incident snapshot source quick run report path"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.artifacts.pre_real_host_readiness_summary_json.path' "$SUMMARY_JSON")" != "$PRE_REAL_HOST_READINESS_SUMMARY_JSON" ]]; then
  echo "campaign summary JSON missing pre-real-host readiness summary artifact path"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.artifacts.pre_real_host_readiness_summary_json.valid_json' "$SUMMARY_JSON")" != "1" ]]; then
  echo "campaign summary JSON should mark pre-real-host readiness summary as valid JSON"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.source_summary_json.path' "$SUMMARY_JSON")" != "$COHORT_SUMMARY_JSON" ]]; then
  echo "campaign summary JSON missing incident snapshot source cohort summary path"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.report_md.path' "$SUMMARY_JSON")" != "$INCIDENT_REPORT_MD" ]]; then
  echo "campaign summary JSON missing incident snapshot report_md path"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_manifest.path' "$SUMMARY_JSON")" != "$INCIDENT_ATTACH_MANIFEST" ]]; then
  echo "campaign summary JSON missing incident snapshot attachment manifest path"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_skipped.path' "$SUMMARY_JSON")" != "$INCIDENT_ATTACH_SKIPPED" ]]; then
  echo "campaign summary JSON missing incident snapshot attachment skipped path"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_count' "$SUMMARY_JSON")" != "1" ]]; then
  echo "campaign summary JSON missing incident snapshot attachment count"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_manifest_count' "$SUMMARY_JSON")" != "1" ]]; then
  echo "campaign summary JSON missing incident snapshot attachment manifest count"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_skipped_count' "$SUMMARY_JSON")" != "1" ]]; then
  echo "campaign summary JSON missing incident snapshot attachment skipped count"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.effective_attachment_count' "$SUMMARY_JSON")" != "1" ]]; then
  echo "campaign summary JSON missing incident snapshot effective attachment count"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.fail_policy.require_incident_snapshot_on_fail' "$SUMMARY_JSON")" != "1" ]]; then
  echo "campaign summary JSON missing fail policy require_incident_snapshot_on_fail default"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.fail_policy.require_incident_snapshot_artifacts' "$SUMMARY_JSON")" != "1" ]]; then
  echo "campaign summary JSON missing fail policy require_incident_snapshot_artifacts default"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.fail_policy.incident_snapshot_min_attachment_count' "$SUMMARY_JSON")" != "0" ]]; then
  echo "campaign summary JSON missing fail policy minimum attachment default"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.fail_policy.incident_snapshot_max_skipped_count' "$SUMMARY_JSON")" != "-1" ]]; then
  echo "campaign summary JSON missing fail policy max skipped default"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_policy_errors | length' "$SUMMARY_JSON")" != "0" ]]; then
  echo "campaign summary JSON should not report incident policy errors in baseline GO case"
  cat "$SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.summary_json.valid_json' "$SUMMARY_JSON")" != "1" ]]; then
  echo "campaign summary JSON should mark incident snapshot summary as valid JSON"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! rg -q -- '- Decision: GO' "$REPORT_MD"; then
  echo "campaign markdown missing GO decision line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q -- 'pilot-client' "$REPORT_MD"; then
  echo "campaign markdown missing subject"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q -- 'Trend: decision=GO go_rate_pct=100' "$REPORT_MD"; then
  echo "campaign markdown missing trend summary"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q -- 'Incident snapshot summary JSON' "$REPORT_MD"; then
  echo "campaign markdown missing incident snapshot artifact section"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q -- 'Incident snapshot attachment manifest' "$REPORT_MD"; then
  echo "campaign markdown missing incident snapshot attachment manifest line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q -- 'Incident snapshot source pre-real-host readiness summary' "$REPORT_MD"; then
  echo "campaign markdown missing incident snapshot source pre-real-host readiness summary line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q -- 'Pre-real-host readiness summary JSON' "$REPORT_MD"; then
  echo "campaign markdown missing pre-real-host readiness artifact line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q -- 'Incident snapshot source quick run report' "$REPORT_MD"; then
  echo "campaign markdown missing incident snapshot source quick run report line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'incident_handoff source_runbook_summary_json=' /tmp/integration_prod_pilot_cohort_campaign_summary_go.log; then
  echo "campaign summary output missing normalized incident_handoff line"
  cat /tmp/integration_prod_pilot_cohort_campaign_summary_go.log
  exit 1
fi
if ! rg -q "attachment_manifest=${INCIDENT_ATTACH_MANIFEST}" /tmp/integration_prod_pilot_cohort_campaign_summary_go.log; then
  echo "campaign summary output missing incident attachment manifest"
  cat /tmp/integration_prod_pilot_cohort_campaign_summary_go.log
  exit 1
fi
if ! rg -q "source_pre_real_host_readiness_summary_json=${PRE_REAL_HOST_READINESS_SUMMARY_JSON}" /tmp/integration_prod_pilot_cohort_campaign_summary_go.log; then
  echo "campaign summary output missing pre-real-host readiness source pointer"
  cat /tmp/integration_prod_pilot_cohort_campaign_summary_go.log
  exit 1
fi

POLICY_FAIL_RUNBOOK_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_cohort_quick_runbook_summary_policy_fail.json"
POLICY_FAIL_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_campaign_summary_policy_fail.json"
POLICY_FAIL_REPORT_MD="$REPORTS_DIR/prod_pilot_campaign_summary_policy_fail.md"
cat >"$POLICY_FAIL_RUNBOOK_SUMMARY_JSON" <<EOF_POLICY_FAIL_RUNBOOK
{
  "status": "fail",
  "failure_step": "quick_signoff",
  "final_rc": 9,
  "duration_sec": 321,
  "stages": {
    "quick": {"rc": 0},
    "quick_signoff": {"rc": 9},
    "quick_dashboard": {"rc": 0}
  },
  "config": {
    "rounds": 6,
    "pause_sec": 45,
    "max_alert_severity": "WARN"
  },
  "artifacts": {
    "reports_dir": "$REPORTS_DIR",
    "summary_json": "$COHORT_SUMMARY_JSON",
    "run_report_json": "$QUICK_REPORT_JSON",
    "signoff_json": "$SIGNOFF_JSON",
    "trend_summary_json": "$TREND_JSON",
    "alert_summary_json": "$ALERT_JSON",
    "dashboard_md": "$DASHBOARD_MD",
    "pre_real_host_readiness_summary_json": "$PRE_REAL_HOST_READINESS_SUMMARY_JSON"
  }
}
EOF_POLICY_FAIL_RUNBOOK
echo "[prod-pilot-cohort-campaign-summary] incident policy fail-close (max skipped)"
./scripts/prod_pilot_cohort_campaign_summary.sh \
  --runbook-summary-json "$POLICY_FAIL_RUNBOOK_SUMMARY_JSON" \
  --summary-json "$POLICY_FAIL_SUMMARY_JSON" \
  --report-md "$POLICY_FAIL_REPORT_MD" \
  --incident-snapshot-min-attachment-count 1 \
  --incident-snapshot-max-skipped-count 0 \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_prod_pilot_cohort_campaign_summary_policy.log 2>&1

if [[ "$(jq -r '.decision' "$POLICY_FAIL_SUMMARY_JSON")" != "NO-GO" ]]; then
  echo "campaign summary should be NO-GO when skipped attachments exceed policy cap"
  cat "$POLICY_FAIL_SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.incident_policy_errors[0]' "$POLICY_FAIL_SUMMARY_JSON")" != "incident_snapshot_attachment_skipped_count_above_max" ]]; then
  echo "campaign summary should report skipped attachment policy violation"
  cat "$POLICY_FAIL_SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.fail_policy.incident_snapshot_max_skipped_count' "$POLICY_FAIL_SUMMARY_JSON")" != "0" ]]; then
  echo "campaign summary should preserve max skipped policy threshold"
  cat "$POLICY_FAIL_SUMMARY_JSON"
  exit 1
fi
if ! rg -q -- 'Incident fail policy errors: incident_snapshot_attachment_skipped_count_above_max' "$POLICY_FAIL_REPORT_MD"; then
  echo "campaign markdown missing incident fail policy violation line"
  cat "$POLICY_FAIL_REPORT_MD"
  exit 1
fi

INVALID_SIGNOFF_JSON="$REPORTS_DIR/prod_pilot_quick_signoff_invalid.json"
INVALID_RUNBOOK_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_cohort_quick_runbook_summary_invalid.json"
INVALID_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_campaign_summary_invalid.json"
INVALID_REPORT_MD="$REPORTS_DIR/prod_pilot_campaign_summary_invalid.md"

cat >"$INVALID_SIGNOFF_JSON" <<'EOF_INVALID_SIGNOFF'
{invalid
EOF_INVALID_SIGNOFF

cat >"$INVALID_RUNBOOK_SUMMARY_JSON" <<EOF_INVALID_RUNBOOK
{
  "status": "ok",
  "failure_step": "",
  "final_rc": 0,
  "duration_sec": 321,
  "stages": {
    "quick": {"rc": 0},
    "quick_signoff": {"rc": 0},
    "quick_dashboard": {"rc": 0}
  },
  "config": {
    "rounds": 6,
    "pause_sec": 45,
    "max_alert_severity": "WARN"
  },
  "artifacts": {
    "reports_dir": "$REPORTS_DIR",
    "summary_json": "$COHORT_SUMMARY_JSON",
    "run_report_json": "$QUICK_REPORT_JSON",
    "signoff_json": "$INVALID_SIGNOFF_JSON",
    "trend_summary_json": "$TREND_JSON",
    "alert_summary_json": "$ALERT_JSON",
    "dashboard_md": "$DASHBOARD_MD"
  }
}
EOF_INVALID_RUNBOOK

echo "[prod-pilot-cohort-campaign-summary] invalid required JSON artifact"
./scripts/prod_pilot_cohort_campaign_summary.sh \
  --runbook-summary-json "$INVALID_RUNBOOK_SUMMARY_JSON" \
  --summary-json "$INVALID_SUMMARY_JSON" \
  --report-md "$INVALID_REPORT_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_prod_pilot_cohort_campaign_summary_invalid.log 2>&1

if [[ "$(jq -r '.decision' "$INVALID_SUMMARY_JSON")" != "NO-GO" ]]; then
  echo "campaign summary should be NO-GO when required JSON artifact is invalid"
  cat "$INVALID_SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.invalid_required_artifacts[0]' "$INVALID_SUMMARY_JSON")" != "signoff_json" ]]; then
  echo "campaign summary should report invalid required JSON artifacts"
  cat "$INVALID_SUMMARY_JSON"
  exit 1
fi
if [[ "$(jq -r '.artifacts.signoff_json.valid_json' "$INVALID_SUMMARY_JSON")" != "0" ]]; then
  echo "campaign summary should mark invalid signoff JSON artifact"
  cat "$INVALID_SUMMARY_JSON"
  exit 1
fi
if ! rg -q -- 'Invalid required JSON artifacts: signoff_json' "$INVALID_REPORT_MD"; then
  echo "campaign markdown missing invalid required JSON artifact line"
  cat "$INVALID_REPORT_MD"
  exit 1
fi

FAIL_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_campaign_summary_fail.json"
FAIL_REPORT_MD="$REPORTS_DIR/prod_pilot_campaign_summary_fail.md"
FAIL_RUNBOOK_SUMMARY_JSON="$REPORTS_DIR/prod_pilot_cohort_quick_runbook_summary_fail.json"
cat >"$FAIL_RUNBOOK_SUMMARY_JSON" <<EOF_FAIL_RUNBOOK
{
  "status": "fail",
  "failure_step": "quick_signoff",
  "final_rc": 7,
  "duration_sec": 120,
  "stages": {
    "quick": {"rc": 0},
    "quick_signoff": {"rc": 7},
    "quick_dashboard": {"rc": 0}
  },
  "config": {
    "rounds": 6,
    "pause_sec": 45,
    "max_alert_severity": "WARN"
  },
  "artifacts": {
    "reports_dir": "$REPORTS_DIR",
    "summary_json": "$COHORT_SUMMARY_JSON",
    "run_report_json": "$QUICK_REPORT_JSON",
    "signoff_json": "$SIGNOFF_JSON",
    "trend_summary_json": "$TREND_JSON",
    "alert_summary_json": "$ALERT_JSON",
    "dashboard_md": "$DASHBOARD_MD"
  }
}
EOF_FAIL_RUNBOOK

echo "[prod-pilot-cohort-campaign-summary] fail-on-no-go"
set +e
./scripts/prod_pilot_cohort_campaign_summary.sh \
  --runbook-summary-json "$FAIL_RUNBOOK_SUMMARY_JSON" \
  --summary-json "$FAIL_SUMMARY_JSON" \
  --report-md "$FAIL_REPORT_MD" \
  --print-report 0 \
  --print-summary-json 0 \
  --fail-on-no-go 1 >/tmp/integration_prod_pilot_cohort_campaign_summary_fail.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "campaign summary should fail closed on NO-GO when requested"
  exit 1
fi
if [[ "$(jq -r '.decision' "$FAIL_SUMMARY_JSON")" != "NO-GO" ]]; then
  echo "campaign summary JSON decision should be NO-GO"
  cat "$FAIL_SUMMARY_JSON"
  exit 1
fi

FAKE_SUMMARY_SCRIPT="$TMP_DIR/fake_campaign_summary.sh"
DISPATCH_CAPTURE="$TMP_DIR/prod_pilot_cohort_campaign_summary_dispatch.log"
cat >"$FAKE_SUMMARY_SCRIPT" <<'EOF_FAKE_SUMMARY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DISPATCH_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_SUMMARY
chmod +x "$FAKE_SUMMARY_SCRIPT"

echo "[prod-pilot-cohort-campaign-summary] easy-node command dispatch"
PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_SCRIPT="$FAKE_SUMMARY_SCRIPT" \
DISPATCH_CAPTURE_FILE="$DISPATCH_CAPTURE" \
./scripts/easy_node.sh prod-pilot-cohort-campaign-summary --runbook-summary-json /tmp/runbook.json --fail-on-no-go 1 --require-incident-snapshot-on-fail 0 --require-incident-snapshot-artifacts 0 --incident-snapshot-min-attachment-count 2 --incident-snapshot-max-skipped-count 3 >/tmp/integration_prod_pilot_cohort_campaign_summary_dispatch.log 2>&1

if ! rg -q -- '--runbook-summary-json /tmp/runbook.json' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-campaign-summary did not forward runbook summary path"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fail-on-no-go 1' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-campaign-summary did not forward fail-on-no-go"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-campaign-summary did not forward --require-incident-snapshot-on-fail"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-campaign-summary did not forward --require-incident-snapshot-artifacts"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-min-attachment-count 2' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-campaign-summary did not forward --incident-snapshot-min-attachment-count"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-max-skipped-count 3' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-campaign-summary did not forward --incident-snapshot-max-skipped-count"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi

echo "prod pilot cohort campaign summary integration check ok"
