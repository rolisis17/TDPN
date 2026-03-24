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

OK_SUMMARY="$TMP_DIR/quick_trend_ok.json"
WARN_SUMMARY="$TMP_DIR/quick_trend_warn.json"
CRIT_SUMMARY="$TMP_DIR/quick_trend_critical.json"

cat >"$OK_SUMMARY" <<'EOF_OK_SUMMARY'
{
  "go_rate_pct": 100,
  "no_go": 0,
  "evaluation_errors": 0,
  "reports_total": 8,
  "top_no_go_reasons": []
}
EOF_OK_SUMMARY

cat >"$WARN_SUMMARY" <<'EOF_WARN_SUMMARY'
{
  "go_rate_pct": 96.5,
  "no_go": 1,
  "evaluation_errors": 0,
  "reports_total": 10,
  "incident_snapshot": {
    "latest_failed_run_report": {
      "source_pre_real_host_readiness_summary_json": {"path": "/tmp/run_b/pre_real_host_readiness_summary.json", "exists": true, "valid_json": true},
      "source_quick_run_report": {"path": "/tmp/run_b/prod_pilot_cohort_quick_report.json", "exists": true},
      "source_summary_json": {"path": "/tmp/run_b/prod_pilot_cohort_summary.json", "exists": true, "valid_json": true},
      "path": "/tmp/run_b/round_2_run_report.json",
      "enabled": true,
      "status": "ok",
      "bundle_dir": {"path": "/tmp/run_b/incident_snapshot", "exists": true},
      "bundle_tar": {"path": "/tmp/run_b/incident_snapshot.tar.gz", "exists": true},
      "summary_json": {"path": "/tmp/run_b/incident_summary.json", "exists": true, "valid_json": true},
      "report_md": {"path": "/tmp/run_b/incident_report.md", "exists": true},
      "attachment_manifest": {"path": "/tmp/run_b/attachments_manifest.json", "exists": true},
      "attachment_skipped": {"path": "/tmp/run_b/attachments_skipped.json", "exists": true},
      "attachment_count": 1
    }
  },
  "top_no_go_reasons": [
    {"count": 1, "reason": "signoff rc is non-zero (signoff_rc=3)"}
  ]
}
EOF_WARN_SUMMARY

cat >"$CRIT_SUMMARY" <<'EOF_CRIT_SUMMARY'
{
  "go_rate_pct": 84.2,
  "no_go": 3,
  "evaluation_errors": 2,
  "reports_total": 12,
  "top_no_go_reasons": [
    {"count": 2, "reason": "quick status is not ok"},
    {"count": 1, "reason": "summary status is not ok"}
  ]
}
EOF_CRIT_SUMMARY

echo "[prod-pilot-cohort-quick-alert] OK severity baseline"
./scripts/prod_pilot_cohort_quick_alert.sh \
  --trend-summary-json "$OK_SUMMARY" \
  --summary-json "$TMP_DIR/quick_alert_ok_out.json" \
  --print-summary-json 1 >${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_ok.log 2>&1

if ! rg -q '\[prod-pilot-cohort-quick-alert\] severity=OK' ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_ok.log; then
  echo "expected OK severity baseline not found"
  cat ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_ok.log
  exit 1
fi
if ! jq -e '.severity == "OK" and .metrics.reports_total == 8' "$TMP_DIR/quick_alert_ok_out.json" >/dev/null 2>&1; then
  echo "quick alert OK summary JSON missing expected fields"
  cat "$TMP_DIR/quick_alert_ok_out.json"
  exit 1
fi

echo "[prod-pilot-cohort-quick-alert] WARN severity baseline"
./scripts/prod_pilot_cohort_quick_alert.sh \
  --trend-summary-json "$WARN_SUMMARY" \
  --warn-go-rate-pct 98 \
  --critical-go-rate-pct 90 \
  --warn-no-go-count 1 \
  --critical-no-go-count 2 \
  --warn-eval-errors 1 \
  --critical-eval-errors 2 >${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_warn.log 2>&1

if ! rg -q '\[prod-pilot-cohort-quick-alert\] severity=WARN' ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_warn.log; then
  echo "expected WARN severity baseline not found"
  cat ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_warn.log
  exit 1
fi
if ! rg -q '\[prod-pilot-cohort-quick-alert\] incident_handoff ' ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_warn.log; then
  echo "expected quick alert incident_handoff output not found"
  cat ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_warn.log
  exit 1
fi
if ! rg -q 'source_pre_real_host_readiness_summary_json=/tmp/run_b/pre_real_host_readiness_summary.json' ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_warn.log; then
  echo "expected quick alert readiness summary pointer in handoff output"
  cat ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_warn.log
  exit 1
fi
if ! rg -q 'attachment_manifest=/tmp/run_b/attachments_manifest.json' ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_warn.log; then
  echo "expected quick alert attachment manifest in handoff output"
  cat ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_warn.log
  exit 1
fi

echo "[prod-pilot-cohort-quick-alert] WARN fail-close"
set +e
./scripts/prod_pilot_cohort_quick_alert.sh \
  --trend-summary-json "$WARN_SUMMARY" \
  --warn-go-rate-pct 98 \
  --critical-go-rate-pct 90 \
  --warn-no-go-count 1 \
  --critical-no-go-count 2 \
  --fail-on-warn 1 >${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_warn_fail.log 2>&1
warn_fail_rc=$?
set -e
if [[ "$warn_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for WARN fail-close (got $warn_fail_rc)"
  cat ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_warn_fail.log
  exit 1
fi
WARN_ALERT_JSON="$TMP_DIR/quick_alert_warn_out.json"
./scripts/prod_pilot_cohort_quick_alert.sh \
  --trend-summary-json "$WARN_SUMMARY" \
  --summary-json "$WARN_ALERT_JSON" >${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_warn_json.log 2>&1
if ! jq -e '.incident_snapshot.latest_failed_run_report.source_pre_real_host_readiness_summary_json.path == "/tmp/run_b/pre_real_host_readiness_summary.json" and .incident_snapshot.latest_failed_run_report.source_quick_run_report.path == "/tmp/run_b/prod_pilot_cohort_quick_report.json" and .incident_snapshot.latest_failed_run_report.source_summary_json.path == "/tmp/run_b/prod_pilot_cohort_summary.json" and .incident_snapshot.latest_failed_run_report.summary_json.path == "/tmp/run_b/incident_summary.json" and .incident_snapshot.latest_failed_run_report.report_md.path == "/tmp/run_b/incident_report.md" and .incident_snapshot.latest_failed_run_report.attachment_manifest.path == "/tmp/run_b/attachments_manifest.json" and .incident_snapshot.latest_failed_run_report.attachment_skipped.path == "/tmp/run_b/attachments_skipped.json" and .incident_snapshot.latest_failed_run_report.attachment_count == 1' "$WARN_ALERT_JSON" >/dev/null 2>&1; then
  echo "quick alert WARN summary JSON missing incident handoff block"
  cat "$WARN_ALERT_JSON"
  exit 1
fi

echo "[prod-pilot-cohort-quick-alert] CRITICAL fail-close"
set +e
./scripts/prod_pilot_cohort_quick_alert.sh \
  --trend-summary-json "$CRIT_SUMMARY" \
  --fail-on-critical 1 >${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_critical_fail.log 2>&1
crit_fail_rc=$?
set -e
if [[ "$crit_fail_rc" -ne 2 ]]; then
  echo "expected rc=2 for CRITICAL fail-close (got $crit_fail_rc)"
  cat ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_critical_fail.log
  exit 1
fi
if ! rg -q '\[prod-pilot-cohort-quick-alert\] severity=CRITICAL' ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_critical_fail.log; then
  echo "expected CRITICAL severity marker not found"
  cat ${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_critical_fail.log
  exit 1
fi

echo "[prod-pilot-cohort-quick-alert] generated trend summary path"
FAKE_TREND="$TMP_DIR/fake_quick_trend.sh"
TREND_CAPTURE="$TMP_DIR/quick_trend_capture.log"
cat >"$FAKE_TREND" <<'EOF_FAKE_TREND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${TREND_CAPTURE_FILE:?}"
summary_file=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_file="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_file" ]]; then
  mkdir -p "$(dirname "$summary_file")"
  cat >"$summary_file" <<'EOF_TREND_SUMMARY'
{
  "go_rate_pct": 99.2,
  "no_go": 0,
  "evaluation_errors": 0,
  "reports_total": 4,
  "top_no_go_reasons": []
}
EOF_TREND_SUMMARY
fi
exit 0
EOF_FAKE_TREND
chmod +x "$FAKE_TREND"

TREND_CAPTURE_FILE="$TREND_CAPTURE" \
PROD_PILOT_COHORT_QUICK_TREND_SCRIPT="$FAKE_TREND" \
./scripts/prod_pilot_cohort_quick_alert.sh \
  --reports-dir ${TMP_DIR}/quick_reports \
  --max-reports 7 \
  --since-hours 24 \
  --require-cohort-signoff-policy 1 \
  --require-signoff-ok 1 \
  --show-top-reasons 3 >${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_generated.log 2>&1

if ! rg -F -q -- "--reports-dir ${TMP_DIR}/quick_reports" "$TREND_CAPTURE"; then
  echo "quick-alert generated trend failed: missing reports-dir forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-reports 7' "$TREND_CAPTURE"; then
  echo "quick-alert generated trend failed: missing max-reports forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--since-hours 24' "$TREND_CAPTURE"; then
  echo "quick-alert generated trend failed: missing since-hours forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json ' "$TREND_CAPTURE"; then
  echo "quick-alert generated trend failed: missing summary-json forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-summary-json 0' "$TREND_CAPTURE"; then
  echo "quick-alert generated trend failed: missing print-summary-json forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-cohort-signoff-policy 1' "$TREND_CAPTURE"; then
  echo "quick-alert generated trend failed: missing --require-cohort-signoff-policy forwarding"
  cat "$TREND_CAPTURE"
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

echo "[prod-pilot-cohort-quick-alert] easy_node forwarding"
FAKE_ALERT="$TMP_DIR/fake_quick_alert.sh"
ALERT_CAPTURE="$TMP_DIR/quick_alert_capture.log"
cat >"$FAKE_ALERT" <<'EOF_FAKE_ALERT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${ALERT_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_ALERT
chmod +x "$FAKE_ALERT"

PATH="$TMP_BIN:$PATH" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT="$FAKE_ALERT" \
./scripts/easy_node.sh prod-pilot-cohort-quick-alert \
  --reports-dir ${TMP_DIR}/quick_reports \
  --since-hours 12 \
  --require-cohort-signoff-policy 1 \
  --warn-go-rate-pct 99 \
  --critical-go-rate-pct 95 \
  --fail-on-warn 1 \
  --summary-json /tmp/quick_alert.json \
  --print-summary-json 1 >${TMP_DIR}/integration_prod_pilot_cohort_quick_alert_easy_node.log 2>&1

if ! rg -F -q -- "--reports-dir ${TMP_DIR}/quick_reports" "$ALERT_CAPTURE"; then
  echo "easy_node quick-alert forwarding failed: missing reports-dir"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--since-hours 12' "$ALERT_CAPTURE"; then
  echo "easy_node quick-alert forwarding failed: missing since-hours"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--warn-go-rate-pct 99' "$ALERT_CAPTURE"; then
  echo "easy_node quick-alert forwarding failed: missing warn-go-rate-pct"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--critical-go-rate-pct 95' "$ALERT_CAPTURE"; then
  echo "easy_node quick-alert forwarding failed: missing critical-go-rate-pct"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-cohort-signoff-policy 1' "$ALERT_CAPTURE"; then
  echo "easy_node quick-alert forwarding failed: missing --require-cohort-signoff-policy"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json /tmp/quick_alert.json' "$ALERT_CAPTURE"; then
  echo "easy_node quick-alert forwarding failed: missing summary-json"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-summary-json 1' "$ALERT_CAPTURE"; then
  echo "easy_node quick-alert forwarding failed: missing print-summary-json"
  cat "$ALERT_CAPTURE"
  exit 1
fi

echo "prod pilot cohort quick alert integration ok"
