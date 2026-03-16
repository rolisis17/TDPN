#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp jq rg; do
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

FAKE_TREND="$TMP_DIR/fake_quick_trend.sh"
FAKE_ALERT="$TMP_DIR/fake_quick_alert.sh"
TREND_CAPTURE="$TMP_DIR/quick_trend_args.log"
ALERT_CAPTURE="$TMP_DIR/quick_alert_args.log"
DASHBOARD_MD="$TMP_DIR/quick_dashboard.md"
TREND_JSON="$TMP_DIR/quick_trend.json"
ALERT_JSON="$TMP_DIR/quick_alert.json"
INCIDENT_DIR="$TMP_DIR/incident_snapshot"
INCIDENT_SUMMARY_JSON="$INCIDENT_DIR/incident_summary.json"
INCIDENT_REPORT_MD="$INCIDENT_DIR/incident_report.md"
INCIDENT_SOURCE_RUN_REPORT="$TMP_DIR/round_2_run_report.json"
INCIDENT_SOURCE_QUICK_RUN_REPORT="$TMP_DIR/prod_pilot_cohort_quick_report.json"
INCIDENT_BUNDLE_TAR="$TMP_DIR/incident_snapshot.tar.gz"

mkdir -p "$INCIDENT_DIR"
cat >"$INCIDENT_SUMMARY_JSON" <<'EOF_INCIDENT_SUMMARY'
{"status":"ok","top_findings":["demo incident"]}
EOF_INCIDENT_SUMMARY
cat >"$INCIDENT_REPORT_MD" <<'EOF_INCIDENT_REPORT'
# Incident Report
EOF_INCIDENT_REPORT
cat >"$INCIDENT_SOURCE_RUN_REPORT" <<'EOF_INCIDENT_SOURCE_RR'
{"status":"fail"}
EOF_INCIDENT_SOURCE_RR
cat >"$INCIDENT_SOURCE_QUICK_RUN_REPORT" <<'EOF_INCIDENT_SOURCE_QUICK_RR'
{"status":"fail"}
EOF_INCIDENT_SOURCE_QUICK_RR
printf 'incident tar placeholder\n' >"$INCIDENT_BUNDLE_TAR"
printf '[]\n' >"$INCIDENT_DIR/attachments_manifest.json"
printf '[]\n' >"$INCIDENT_DIR/attachments_skipped.json"

cat >"$FAKE_TREND" <<'EOF_FAKE_TREND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${TREND_CAPTURE_FILE:?}"
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -z "$summary_json" ]]; then
  echo "fake quick trend missing --summary-json"
  exit 2
fi
mkdir -p "$(dirname "$summary_json")"
cat >"$summary_json" <<'EOF_TREND_JSON'
{
  "version": 1,
  "generated_at_utc": "2026-03-10T00:00:00Z",
  "decision": "NO-GO",
  "reports_total": 8,
  "go": 6,
  "no_go": 2,
  "go_rate_pct": 75.00,
  "evaluation_errors": 1,
  "top_no_go_reasons": [
    {"count": 2, "reason": "signoff rc is non-zero"},
    {"count": 1, "reason": "summary status is not ok"}
  ],
  "incident_snapshot": {
    "latest_failed_run_report": {
      "source_quick_run_report": {"path": "__INCIDENT_SOURCE_QUICK_RUN_REPORT__"},
      "path": "__INCIDENT_SOURCE_RUN_REPORT__",
      "enabled": 1,
      "status": "ok",
      "bundle_dir": {"path": "__INCIDENT_DIR__"},
      "bundle_tar": {"path": "__INCIDENT_BUNDLE_TAR__"},
      "summary_json": {"path": "__INCIDENT_SUMMARY_JSON__"},
      "report_md": {"path": "__INCIDENT_REPORT_MD__"},
      "attachment_manifest": {"path": "__INCIDENT_DIR__/attachments_manifest.json"},
      "attachment_skipped": {"path": "__INCIDENT_DIR__/attachments_skipped.json"},
      "attachment_count": 1
    }
  }
}
EOF_TREND_JSON
sed -i \
  -e "s#__INCIDENT_SOURCE_QUICK_RUN_REPORT__#${INCIDENT_SOURCE_QUICK_RUN_REPORT}#g" \
  -e "s#__INCIDENT_SOURCE_RUN_REPORT__#${INCIDENT_SOURCE_RUN_REPORT}#g" \
  -e "s#__INCIDENT_DIR__#${INCIDENT_DIR}#g" \
  -e "s#__INCIDENT_BUNDLE_TAR__#${INCIDENT_BUNDLE_TAR}#g" \
  -e "s#__INCIDENT_SUMMARY_JSON__#${INCIDENT_SUMMARY_JSON}#g" \
  -e "s#__INCIDENT_REPORT_MD__#${INCIDENT_REPORT_MD}#g" \
  "$summary_json"
exit "${FAKE_TREND_RC:-0}"
EOF_FAKE_TREND
chmod +x "$FAKE_TREND"

cat >"$FAKE_ALERT" <<'EOF_FAKE_ALERT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${ALERT_CAPTURE_FILE:?}"
summary_json=""
trend_summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --trend-summary-json)
      trend_summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -z "$summary_json" ]]; then
  echo "fake quick alert missing --summary-json"
  exit 2
fi
if [[ -z "$trend_summary_json" || ! -f "$trend_summary_json" ]]; then
  echo "fake quick alert missing readable --trend-summary-json"
  exit 2
fi
mkdir -p "$(dirname "$summary_json")"
cat >"$summary_json" <<'EOF_ALERT_JSON'
{
  "version": 1,
  "generated_at_utc": "2026-03-10T00:00:01Z",
  "severity": "WARN",
  "trigger_reasons": [
    "go_rate_pct 75 < warn_go_rate_pct 98",
    "no_go_count 2 >= warn_no_go_count 1"
  ]
}
EOF_ALERT_JSON
exit "${FAKE_ALERT_RC:-0}"
EOF_FAKE_ALERT
chmod +x "$FAKE_ALERT"

echo "[prod-pilot-cohort-quick-dashboard] success path"
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
INCIDENT_SOURCE_QUICK_RUN_REPORT="$INCIDENT_SOURCE_QUICK_RUN_REPORT" \
INCIDENT_SOURCE_RUN_REPORT="$INCIDENT_SOURCE_RUN_REPORT" \
INCIDENT_DIR="$INCIDENT_DIR" \
INCIDENT_BUNDLE_TAR="$INCIDENT_BUNDLE_TAR" \
INCIDENT_SUMMARY_JSON="$INCIDENT_SUMMARY_JSON" \
INCIDENT_REPORT_MD="$INCIDENT_REPORT_MD" \
PROD_PILOT_COHORT_QUICK_TREND_SCRIPT="$FAKE_TREND" \
PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT="$FAKE_ALERT" \
./scripts/prod_pilot_cohort_quick_dashboard.sh \
  --reports-dir /tmp/quick_reports \
  --max-reports 10 \
  --since-hours 24 \
  --require-signoff-ok 1 \
  --require-cohort-signoff-policy 1 \
  --incident-snapshot-min-attachment-count 2 \
  --incident-snapshot-max-skipped-count 0 \
  --min-go-rate-pct 95 \
  --show-top-reasons 3 \
  --warn-go-rate-pct 98 \
  --critical-go-rate-pct 90 \
  --fail-on-warn 0 \
  --fail-on-critical 0 \
  --trend-summary-json "$TREND_JSON" \
  --alert-summary-json "$ALERT_JSON" \
  --dashboard-md "$DASHBOARD_MD" \
  --print-dashboard 0 \
  --print-summary-json 1 >/tmp/integration_prod_pilot_cohort_quick_dashboard_success.log 2>&1

if [[ ! -s "$DASHBOARD_MD" ]]; then
  echo "quick dashboard markdown not generated"
  exit 1
fi
if ! rg -q 'Alert severity: WARN' "$DASHBOARD_MD"; then
  echo "quick dashboard missing alert severity line"
  cat "$DASHBOARD_MD"
  exit 1
fi
if ! rg -q 'count=2 reason=signoff rc is non-zero' "$DASHBOARD_MD"; then
  echo "quick dashboard missing top no-go reason"
  cat "$DASHBOARD_MD"
  exit 1
fi
if ! rg -q '## Incident Handoff' "$DASHBOARD_MD"; then
  echo "quick dashboard missing incident handoff section"
  cat "$DASHBOARD_MD"
  exit 1
fi
if ! rg -q "$INCIDENT_SUMMARY_JSON" "$DASHBOARD_MD"; then
  echo "quick dashboard missing incident summary path"
  cat "$DASHBOARD_MD"
  exit 1
fi
if ! rg -q "$INCIDENT_REPORT_MD" "$DASHBOARD_MD"; then
  echo "quick dashboard missing incident report path"
  cat "$DASHBOARD_MD"
  exit 1
fi
if ! rg -q "$INCIDENT_DIR/attachments_manifest.json" "$DASHBOARD_MD"; then
  echo "quick dashboard missing incident attachment manifest path"
  cat "$DASHBOARD_MD"
  exit 1
fi
if ! rg -q 'Incident attachment count: 1' "$DASHBOARD_MD"; then
  echo "quick dashboard missing incident attachment count"
  cat "$DASHBOARD_MD"
  exit 1
fi
if ! rg -q '\[prod-pilot-cohort-quick-dashboard\] incident_handoff ' /tmp/integration_prod_pilot_cohort_quick_dashboard_success.log; then
  echo "quick dashboard missing incident_handoff output line"
  cat /tmp/integration_prod_pilot_cohort_quick_dashboard_success.log
  exit 1
fi
if ! rg -q "attachment_manifest=${INCIDENT_DIR}/attachments_manifest.json" /tmp/integration_prod_pilot_cohort_quick_dashboard_success.log; then
  echo "quick dashboard missing incident attachment manifest in handoff output"
  cat /tmp/integration_prod_pilot_cohort_quick_dashboard_success.log
  exit 1
fi
if ! rg -q -- '--require-signoff-ok 1' "$TREND_CAPTURE"; then
  echo "quick dashboard did not forward --require-signoff-ok to trend script"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-cohort-signoff-policy 1' "$TREND_CAPTURE"; then
  echo "quick dashboard did not forward --require-cohort-signoff-policy to trend script"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-min-attachment-count 2' "$TREND_CAPTURE"; then
  echo "quick dashboard did not forward --incident-snapshot-min-attachment-count to trend script"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-max-skipped-count 0' "$TREND_CAPTURE"; then
  echo "quick dashboard did not forward --incident-snapshot-max-skipped-count to trend script"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- "--trend-summary-json $TREND_JSON" "$ALERT_CAPTURE"; then
  echo "quick dashboard did not forward trend summary path to alert script"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-cohort-signoff-policy 1' "$ALERT_CAPTURE"; then
  echo "quick dashboard did not forward --require-cohort-signoff-policy to alert script"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-min-attachment-count 2' "$ALERT_CAPTURE"; then
  echo "quick dashboard did not forward --incident-snapshot-min-attachment-count to alert script"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-max-skipped-count 0' "$ALERT_CAPTURE"; then
  echo "quick dashboard did not forward --incident-snapshot-max-skipped-count to alert script"
  cat "$ALERT_CAPTURE"
  exit 1
fi

echo "[prod-pilot-cohort-quick-dashboard] return code: trend fail when alert succeeds"
set +e
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
FAKE_TREND_RC=1 \
FAKE_ALERT_RC=0 \
INCIDENT_SOURCE_QUICK_RUN_REPORT="$INCIDENT_SOURCE_QUICK_RUN_REPORT" \
INCIDENT_SOURCE_RUN_REPORT="$INCIDENT_SOURCE_RUN_REPORT" \
INCIDENT_DIR="$INCIDENT_DIR" \
INCIDENT_BUNDLE_TAR="$INCIDENT_BUNDLE_TAR" \
INCIDENT_SUMMARY_JSON="$INCIDENT_SUMMARY_JSON" \
INCIDENT_REPORT_MD="$INCIDENT_REPORT_MD" \
PROD_PILOT_COHORT_QUICK_TREND_SCRIPT="$FAKE_TREND" \
PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT="$FAKE_ALERT" \
./scripts/prod_pilot_cohort_quick_dashboard.sh \
  --reports-dir /tmp/quick_reports \
  --trend-summary-json "$TREND_JSON" \
  --alert-summary-json "$ALERT_JSON" \
  --dashboard-md "$DASHBOARD_MD" \
  --print-dashboard 0 >/tmp/integration_prod_pilot_cohort_quick_dashboard_trend_fail.log 2>&1
rc=$?
set -e
if [[ "$rc" -ne 1 ]]; then
  echo "expected rc=1 when trend fails and alert succeeds; got rc=$rc"
  cat /tmp/integration_prod_pilot_cohort_quick_dashboard_trend_fail.log
  exit 1
fi

echo "[prod-pilot-cohort-quick-dashboard] return code: alert fail precedence"
set +e
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
FAKE_TREND_RC=1 \
FAKE_ALERT_RC=2 \
INCIDENT_SOURCE_QUICK_RUN_REPORT="$INCIDENT_SOURCE_QUICK_RUN_REPORT" \
INCIDENT_SOURCE_RUN_REPORT="$INCIDENT_SOURCE_RUN_REPORT" \
INCIDENT_DIR="$INCIDENT_DIR" \
INCIDENT_BUNDLE_TAR="$INCIDENT_BUNDLE_TAR" \
INCIDENT_SUMMARY_JSON="$INCIDENT_SUMMARY_JSON" \
INCIDENT_REPORT_MD="$INCIDENT_REPORT_MD" \
PROD_PILOT_COHORT_QUICK_TREND_SCRIPT="$FAKE_TREND" \
PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT="$FAKE_ALERT" \
./scripts/prod_pilot_cohort_quick_dashboard.sh \
  --reports-dir /tmp/quick_reports \
  --trend-summary-json "$TREND_JSON" \
  --alert-summary-json "$ALERT_JSON" \
  --dashboard-md "$DASHBOARD_MD" \
  --print-dashboard 0 >/tmp/integration_prod_pilot_cohort_quick_dashboard_alert_fail.log 2>&1
rc=$?
set -e
if [[ "$rc" -ne 2 ]]; then
  echo "expected rc=2 when alert fails; got rc=$rc"
  cat /tmp/integration_prod_pilot_cohort_quick_dashboard_alert_fail.log
  exit 1
fi

FAKE_EASY_NODE_DASHBOARD="$TMP_DIR/fake_easy_node_quick_dashboard.sh"
EASY_NODE_DASHBOARD_CAPTURE="$TMP_DIR/easy_node_quick_dashboard_args.log"
cat >"$FAKE_EASY_NODE_DASHBOARD" <<'EOF_FAKE_EASY_NODE_DASHBOARD'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${EASY_NODE_DASHBOARD_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_EASY_NODE_DASHBOARD
chmod +x "$FAKE_EASY_NODE_DASHBOARD"

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

echo "[prod-pilot-cohort-quick-dashboard] easy-node forwarding"
PATH="$TMP_BIN:$PATH" \
EASY_NODE_DASHBOARD_CAPTURE_FILE="$EASY_NODE_DASHBOARD_CAPTURE" \
PROD_PILOT_COHORT_QUICK_DASHBOARD_SCRIPT="$FAKE_EASY_NODE_DASHBOARD" \
./scripts/easy_node.sh prod-pilot-cohort-quick-dashboard \
  --reports-dir /tmp/quick_reports \
  --since-hours 12 \
  --require-cohort-signoff-policy 1 \
  --incident-snapshot-min-attachment-count 3 \
  --incident-snapshot-max-skipped-count 1 \
  --dashboard-md /tmp/quick_dashboard.md >/tmp/integration_prod_pilot_cohort_quick_dashboard_easy_node.log 2>&1

if ! rg -q -- '--reports-dir /tmp/quick_reports' "$EASY_NODE_DASHBOARD_CAPTURE"; then
  echo "easy-node quick-dashboard forwarding missing --reports-dir"
  cat "$EASY_NODE_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--since-hours 12' "$EASY_NODE_DASHBOARD_CAPTURE"; then
  echo "easy-node quick-dashboard forwarding missing --since-hours"
  cat "$EASY_NODE_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--dashboard-md /tmp/quick_dashboard.md' "$EASY_NODE_DASHBOARD_CAPTURE"; then
  echo "easy-node quick-dashboard forwarding missing --dashboard-md"
  cat "$EASY_NODE_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-cohort-signoff-policy 1' "$EASY_NODE_DASHBOARD_CAPTURE"; then
  echo "easy-node quick-dashboard forwarding missing --require-cohort-signoff-policy"
  cat "$EASY_NODE_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-min-attachment-count 3' "$EASY_NODE_DASHBOARD_CAPTURE"; then
  echo "easy-node quick-dashboard forwarding missing --incident-snapshot-min-attachment-count"
  cat "$EASY_NODE_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-max-skipped-count 1' "$EASY_NODE_DASHBOARD_CAPTURE"; then
  echo "easy-node quick-dashboard forwarding missing --incident-snapshot-max-skipped-count"
  cat "$EASY_NODE_DASHBOARD_CAPTURE"
  exit 1
fi

echo "prod pilot cohort quick dashboard integration ok"
