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
SUMMARY_JSON="$REPORTS_DIR/prod_pilot_campaign_summary.json"
REPORT_MD="$REPORTS_DIR/prod_pilot_campaign_summary.md"

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
    "dashboard_md": "$DASHBOARD_MD"
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
./scripts/easy_node.sh prod-pilot-cohort-campaign-summary --runbook-summary-json /tmp/runbook.json --fail-on-no-go 1 >/tmp/integration_prod_pilot_cohort_campaign_summary_dispatch.log 2>&1

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

echo "prod pilot cohort campaign summary integration check ok"
