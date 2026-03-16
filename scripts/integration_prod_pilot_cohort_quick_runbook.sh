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

FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
CAPTURE="$TMP_DIR/capture.log"

cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY_NODE'
#!/usr/bin/env bash
set -euo pipefail

cmd="${1:-}"
shift || true
printf '%s %s\n' "$cmd" "$*" >>"${CAPTURE_FILE:?}"

arg_value() {
  local key="$1"
  shift
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "$key" ]]; then
      echo "${2:-}"
      return
    fi
    shift
  done
  echo ""
}

touch_parent() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
}

case "$cmd" in
  prod-pilot-cohort-quick)
    quick_rc="${FAKE_QUICK_RC:-0}"
    write_report="${FAKE_QUICK_WRITE_REPORT:-1}"
    summary_json="$(arg_value --summary-json "$@")"
    run_report_json="$(arg_value --run-report-json "$@")"
    if [[ "$write_report" == "1" ]]; then
      if [[ -n "$summary_json" ]]; then
        touch_parent "$summary_json"
        cat >"$summary_json" <<'EOF_SUMMARY'
{"status":"ok"}
EOF_SUMMARY
      fi
      if [[ -n "$run_report_json" ]]; then
        touch_parent "$run_report_json"
        cat >"$run_report_json" <<EOF_RUN
{"status":"ok","runbook":{"rc":0},"signoff":{"attempted":true,"rc":0},"artifacts":{"summary_json":"$summary_json"}}
EOF_RUN
      fi
    fi
    exit "$quick_rc"
    ;;
  prod-pilot-cohort-quick-signoff)
    signoff_rc="${FAKE_SIGNOFF_RC:-0}"
    signoff_json="$(arg_value --signoff-json "$@")"
    trend_json="$(arg_value --trend-summary-json "$@")"
    alert_json="$(arg_value --alert-summary-json "$@")"
    if [[ -n "$trend_json" ]]; then
      touch_parent "$trend_json"
      cat >"$trend_json" <<'EOF_TREND'
{"decision":"GO"}
EOF_TREND
    fi
    if [[ -n "$alert_json" ]]; then
      touch_parent "$alert_json"
      cat >"$alert_json" <<'EOF_ALERT'
{"severity":"WARN"}
EOF_ALERT
    fi
    if [[ -n "$signoff_json" ]]; then
      touch_parent "$signoff_json"
      cat >"$signoff_json" <<EOF_SIGNOFF
{"status":"ok","incident_snapshot":{"source_summary_json":{"path":"${FAKE_SIGNOFF_SOURCE_SUMMARY_JSON:-}","exists":false,"valid_json":false},"source_run_report_json":{"path":"${FAKE_SIGNOFF_SOURCE_RUN_REPORT_JSON:-}","exists":false},"enabled":${FAKE_SIGNOFF_INCIDENT_ENABLED:-false},"status":"${FAKE_SIGNOFF_INCIDENT_STATUS:-}","bundle_dir":{"path":"${FAKE_SIGNOFF_INCIDENT_BUNDLE_DIR:-}","exists":false},"bundle_tar":{"path":"${FAKE_SIGNOFF_INCIDENT_BUNDLE_TAR:-}","exists":false},"summary_json":{"path":"${FAKE_SIGNOFF_INCIDENT_SUMMARY_JSON:-}","exists":false,"valid_json":false},"report_md":{"path":"${FAKE_SIGNOFF_INCIDENT_REPORT_MD:-}","exists":false}}}
EOF_SIGNOFF
    fi
    exit "$signoff_rc"
    ;;
  prod-pilot-cohort-quick-dashboard)
    dashboard_rc="${FAKE_DASHBOARD_RC:-0}"
    dashboard_md="$(arg_value --dashboard-md "$@")"
    if [[ -n "$dashboard_md" ]]; then
      touch_parent "$dashboard_md"
      cat >"$dashboard_md" <<'EOF_DASH'
# quick dashboard
EOF_DASH
    fi
    exit "$dashboard_rc"
    ;;
  *)
    echo "unexpected fake easy-node command: $cmd"
    exit 2
    ;;
esac
EOF_FAKE_EASY_NODE
chmod +x "$FAKE_EASY_NODE"

echo "[prod-pilot-cohort-quick-runbook] success path"
SUCCESS_DIR="$TMP_DIR/success"
CAPTURE_FILE="$CAPTURE" \
PROD_PILOT_COHORT_QUICK_RUNBOOK_EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/prod_pilot_cohort_quick_runbook.sh \
  --bootstrap-directory https://a.example:8081 \
  --subject demo-client \
  --max-round-failures 2 \
  --bundle-outputs 0 \
  --bundle-fail-close 0 \
  --signoff-incident-snapshot-min-attachment-count 3 \
  --signoff-incident-snapshot-max-skipped-count 0 \
  --reports-dir "$SUCCESS_DIR" \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_quick_runbook_success.log 2>&1

if ! rg -q '^prod-pilot-cohort-quick ' "$CAPTURE"; then
  echo "missing quick stage invocation"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^prod-pilot-cohort-quick-signoff ' "$CAPTURE"; then
  echo "missing quick-signoff stage invocation"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^prod-pilot-cohort-quick-dashboard ' "$CAPTURE"; then
  echo "missing quick-dashboard stage invocation"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--require-cohort-signoff-policy 1' "$CAPTURE"; then
  echo "missing strict cohort-signoff policy forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--require-trend-artifact-policy-match 1' "$CAPTURE"; then
  echo "missing strict trend-artifact policy forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--require-trend-wg-validate-udp-source 1' "$CAPTURE"; then
  echo "missing strict trend udp-source policy forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--require-trend-wg-validate-strict-distinct 1' "$CAPTURE"; then
  echo "missing strict trend distinct policy forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--require-trend-wg-soak-diversity-pass 1' "$CAPTURE"; then
  echo "missing strict trend soak-diversity policy forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--min-trend-wg-soak-selection-lines 12' "$CAPTURE"; then
  echo "missing strict trend soak selection-lines forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--min-trend-wg-soak-entry-operators 2' "$CAPTURE"; then
  echo "missing strict trend soak entry-operators forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--min-trend-wg-soak-exit-operators 2' "$CAPTURE"; then
  echo "missing strict trend soak exit-operators forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--min-trend-wg-soak-cross-operator-pairs 2' "$CAPTURE"; then
  echo "missing strict trend soak cross-operator-pairs forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--incident-snapshot-min-attachment-count 3' "$CAPTURE"; then
  echo "missing incident attachment minimum forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--incident-snapshot-max-skipped-count 0' "$CAPTURE"; then
  echo "missing incident skipped-attachment cap forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--signoff-require-trend-artifact-policy-match 1' "$CAPTURE"; then
  echo "missing strict trend-artifact policy forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--signoff-require-trend-wg-validate-udp-source 1' "$CAPTURE"; then
  echo "missing strict trend udp-source policy forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--signoff-require-trend-wg-validate-strict-distinct 1' "$CAPTURE"; then
  echo "missing strict trend distinct policy forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--signoff-require-trend-wg-soak-diversity-pass 1' "$CAPTURE"; then
  echo "missing strict trend soak-diversity policy forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--signoff-min-trend-wg-soak-selection-lines 12' "$CAPTURE"; then
  echo "missing strict trend soak selection-lines forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--signoff-min-trend-wg-soak-entry-operators 2' "$CAPTURE"; then
  echo "missing strict trend soak entry-operators forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--signoff-min-trend-wg-soak-exit-operators 2' "$CAPTURE"; then
  echo "missing strict trend soak exit-operators forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--signoff-min-trend-wg-soak-cross-operator-pairs 2' "$CAPTURE"; then
  echo "missing strict trend soak cross-operator-pairs forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--signoff-incident-snapshot-min-attachment-count 3' "$CAPTURE"; then
  echo "missing incident attachment minimum forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--signoff-incident-snapshot-max-skipped-count 0' "$CAPTURE"; then
  echo "missing incident skipped-attachment cap forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--max-round-failures 2' "$CAPTURE"; then
  echo "missing max-round-failures forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--bundle-outputs 0' "$CAPTURE"; then
  echo "missing bundle-outputs forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--bundle-fail-close 0' "$CAPTURE"; then
  echo "missing bundle-fail-close forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick .*--pre-real-host-readiness 1' "$CAPTURE"; then
  echo "missing default pre-real-host readiness forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- "^prod-pilot-cohort-quick .*--pre-real-host-readiness-summary-json ${SUCCESS_DIR}/pre_real_host_readiness_summary.json" "$CAPTURE"; then
  echo "missing derived pre-real-host readiness summary path forwarding to quick stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-dashboard .*--require-cohort-signoff-policy 0' "$CAPTURE"; then
  echo "missing bundle-compatible cohort-signoff policy forwarding to quick-dashboard stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-dashboard .*--incident-snapshot-min-attachment-count 3' "$CAPTURE"; then
  echo "missing incident attachment minimum forwarding to quick-dashboard stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-dashboard .*--incident-snapshot-max-skipped-count 0' "$CAPTURE"; then
  echo "missing incident skipped-attachment cap forwarding to quick-dashboard stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--require-bundle-created 0' "$CAPTURE"; then
  echo "missing bundle-created policy forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-pilot-cohort-quick-signoff .*--require-bundle-manifest 0' "$CAPTURE"; then
  echo "missing bundle-manifest policy forwarding to quick-signoff stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- "--run-report-json ${SUCCESS_DIR}/prod_pilot_cohort_quick_report.json" "$CAPTURE"; then
  echo "runbook forwarding missing quick run-report path"
  cat "$CAPTURE"
  exit 1
fi
if [[ ! -f "${SUCCESS_DIR}/prod_pilot_cohort_quick_runbook_summary.json" ]]; then
  echo "missing runbook summary artifact on success"
  ls -la "$SUCCESS_DIR"
  exit 1
fi
if ! jq -e --arg pre_summary_json "${SUCCESS_DIR}/pre_real_host_readiness_summary.json" '.status=="ok" and .stages.quick.rc==0 and .stages.quick_signoff.rc==0 and .stages.quick_dashboard.rc==0 and .config.max_round_failures==2 and .config.bundle_outputs==0 and .config.bundle_fail_close==0 and .config.pre_real_host_readiness==1 and .config.signoff_require_cohort_signoff_policy==1 and .config.dashboard_require_cohort_signoff_policy==0 and .config.signoff_require_trend_artifact_policy_match==1 and .config.signoff_min_trend_wg_soak_selection_lines==12 and .config.signoff_incident_snapshot_min_attachment_count==3 and .config.signoff_incident_snapshot_max_skipped_count==0 and .artifacts.pre_real_host_readiness_summary_json==$pre_summary_json' "${SUCCESS_DIR}/prod_pilot_cohort_quick_runbook_summary.json" >/dev/null 2>&1; then
  echo "runbook summary missing expected success stage fields"
  cat "${SUCCESS_DIR}/prod_pilot_cohort_quick_runbook_summary.json"
  exit 1
fi
if ! rg -q -- "\\[prod-pilot-cohort-quick-runbook] pre_real_host_readiness_summary_json=${SUCCESS_DIR}/pre_real_host_readiness_summary.json" /tmp/integration_prod_pilot_cohort_quick_runbook_success.log; then
  echo "runbook output missing pre-real-host readiness summary path"
  cat /tmp/integration_prod_pilot_cohort_quick_runbook_success.log
  exit 1
fi

echo "[prod-pilot-cohort-quick-runbook] incident handoff propagation"
HANDOFF_DIR="$TMP_DIR/handoff"
HANDOFF_SOURCE_SUMMARY="$HANDOFF_DIR/prod_pilot_cohort_summary.json"
HANDOFF_SOURCE_RUN_REPORT="$HANDOFF_DIR/prod_pilot_cohort_quick_report.json"
HANDOFF_INCIDENT_DIR="$HANDOFF_DIR/incident_bundle"
HANDOFF_INCIDENT_TAR="$HANDOFF_DIR/incident_bundle.tar.gz"
HANDOFF_INCIDENT_SUMMARY="$HANDOFF_DIR/incident_summary.json"
HANDOFF_INCIDENT_REPORT="$HANDOFF_DIR/incident_report.md"
mkdir -p "$HANDOFF_INCIDENT_DIR"
cat >"$HANDOFF_SOURCE_SUMMARY" <<'EOF_HANDOFF_SOURCE_SUMMARY'
{"rounds_failed":1}
EOF_HANDOFF_SOURCE_SUMMARY
cat >"$HANDOFF_SOURCE_RUN_REPORT" <<EOF_HANDOFF_SOURCE_RUN_REPORT
{"artifacts":{"summary_json":"$HANDOFF_SOURCE_SUMMARY"}}
EOF_HANDOFF_SOURCE_RUN_REPORT
printf 'incident bundle tar placeholder\n' >"$HANDOFF_INCIDENT_TAR"
cat >"$HANDOFF_INCIDENT_SUMMARY" <<'EOF_HANDOFF_INCIDENT_SUMMARY'
{"status":"ok","top_findings":["demo incident"]}
EOF_HANDOFF_INCIDENT_SUMMARY
cat >"$HANDOFF_INCIDENT_REPORT" <<'EOF_HANDOFF_INCIDENT_REPORT'
# Incident Report
EOF_HANDOFF_INCIDENT_REPORT

CAPTURE_FILE="$CAPTURE" \
FAKE_SIGNOFF_INCIDENT_ENABLED=true \
FAKE_SIGNOFF_INCIDENT_STATUS=ok \
FAKE_SIGNOFF_SOURCE_SUMMARY_JSON="$HANDOFF_SOURCE_SUMMARY" \
FAKE_SIGNOFF_SOURCE_RUN_REPORT_JSON="$HANDOFF_SOURCE_RUN_REPORT" \
FAKE_SIGNOFF_INCIDENT_BUNDLE_DIR="$HANDOFF_INCIDENT_DIR" \
FAKE_SIGNOFF_INCIDENT_BUNDLE_TAR="$HANDOFF_INCIDENT_TAR" \
FAKE_SIGNOFF_INCIDENT_SUMMARY_JSON="$HANDOFF_INCIDENT_SUMMARY" \
FAKE_SIGNOFF_INCIDENT_REPORT_MD="$HANDOFF_INCIDENT_REPORT" \
PROD_PILOT_COHORT_QUICK_RUNBOOK_EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/prod_pilot_cohort_quick_runbook.sh \
  --reports-dir "$HANDOFF_DIR" \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_quick_runbook_handoff.log 2>&1

if ! jq -e --arg summary "$HANDOFF_INCIDENT_SUMMARY" --arg report "$HANDOFF_INCIDENT_REPORT" '.incident_snapshot.enabled==1 and .incident_snapshot.status=="ok" and .incident_snapshot.summary_json.path==$summary and .incident_snapshot.report_md.path==$report' "${HANDOFF_DIR}/prod_pilot_cohort_quick_runbook_summary.json" >/dev/null 2>&1; then
  echo "runbook summary missing incident handoff propagation"
  cat "${HANDOFF_DIR}/prod_pilot_cohort_quick_runbook_summary.json"
  exit 1
fi
if ! rg -q 'incident_handoff' /tmp/integration_prod_pilot_cohort_quick_runbook_handoff.log; then
  echo "expected incident_handoff line in runbook output"
  cat /tmp/integration_prod_pilot_cohort_quick_runbook_handoff.log
  exit 1
fi
if ! rg -q -- "\\[prod-pilot-cohort-quick-runbook] pre_real_host_readiness_summary_json=${HANDOFF_DIR}/pre_real_host_readiness_summary.json" /tmp/integration_prod_pilot_cohort_quick_runbook_handoff.log; then
  echo "handoff output missing pre-real-host readiness summary path"
  cat /tmp/integration_prod_pilot_cohort_quick_runbook_handoff.log
  exit 1
fi

echo "[prod-pilot-cohort-quick-runbook] quick fail but report exists still runs signoff"
FAIL_WITH_REPORT_DIR="$TMP_DIR/fail_with_report"
set +e
CAPTURE_FILE="$CAPTURE" \
FAKE_QUICK_RC=1 \
FAKE_QUICK_WRITE_REPORT=1 \
PROD_PILOT_COHORT_QUICK_RUNBOOK_EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/prod_pilot_cohort_quick_runbook.sh \
  --reports-dir "$FAIL_WITH_REPORT_DIR" >/tmp/integration_prod_pilot_cohort_quick_runbook_quick_fail_with_report.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc when quick stage fails"
  cat /tmp/integration_prod_pilot_cohort_quick_runbook_quick_fail_with_report.log
  exit 1
fi
if ! rg -q -- "--reports-dir ${FAIL_WITH_REPORT_DIR}" "$CAPTURE"; then
  echo "missing capture lines for fail-with-report run"
  cat "$CAPTURE"
  exit 1
fi
if [[ ! -f "${FAIL_WITH_REPORT_DIR}/prod_pilot_cohort_quick_runbook_summary.json" ]]; then
  echo "missing runbook summary artifact for fail-with-report run"
  ls -la "$FAIL_WITH_REPORT_DIR"
  exit 1
fi
if ! jq -e '.status=="fail" and .failure_step=="quick"' "${FAIL_WITH_REPORT_DIR}/prod_pilot_cohort_quick_runbook_summary.json" >/dev/null 2>&1; then
  echo "runbook summary missing expected quick failure classification"
  cat "${FAIL_WITH_REPORT_DIR}/prod_pilot_cohort_quick_runbook_summary.json"
  exit 1
fi

echo "[prod-pilot-cohort-quick-runbook] quick fail without report stops before signoff"
FAIL_NO_REPORT_DIR="$TMP_DIR/fail_no_report"
set +e
CAPTURE_FILE="$CAPTURE" \
FAKE_QUICK_RC=1 \
FAKE_QUICK_WRITE_REPORT=0 \
PROD_PILOT_COHORT_QUICK_RUNBOOK_EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/prod_pilot_cohort_quick_runbook.sh \
  --reports-dir "$FAIL_NO_REPORT_DIR" >/tmp/integration_prod_pilot_cohort_quick_runbook_quick_fail_no_report.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc when quick fails without report artifact"
  cat /tmp/integration_prod_pilot_cohort_quick_runbook_quick_fail_no_report.log
  exit 1
fi
if [[ ! -f "${FAIL_NO_REPORT_DIR}/prod_pilot_cohort_quick_runbook_summary.json" ]]; then
  echo "missing runbook summary artifact for fail-no-report run"
  ls -la "$FAIL_NO_REPORT_DIR"
  exit 1
fi
if ! jq -e '.status=="fail" and .failure_step=="quick_missing_report"' "${FAIL_NO_REPORT_DIR}/prod_pilot_cohort_quick_runbook_summary.json" >/dev/null 2>&1; then
  echo "runbook summary missing expected quick_missing_report failure classification"
  cat "${FAIL_NO_REPORT_DIR}/prod_pilot_cohort_quick_runbook_summary.json"
  exit 1
fi

echo "[prod-pilot-cohort-quick-runbook] dashboard fail does not fail run by default"
DASH_NON_FAIL_DIR="$TMP_DIR/dash_non_fail"
CAPTURE_FILE="$CAPTURE" \
FAKE_DASHBOARD_RC=2 \
PROD_PILOT_COHORT_QUICK_RUNBOOK_EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/prod_pilot_cohort_quick_runbook.sh \
  --reports-dir "$DASH_NON_FAIL_DIR" \
  --dashboard-fail-close 0 >/tmp/integration_prod_pilot_cohort_quick_runbook_dashboard_non_fail.log 2>&1

if ! jq -e '.status=="ok" and .stages.quick_dashboard.rc==2' "${DASH_NON_FAIL_DIR}/prod_pilot_cohort_quick_runbook_summary.json" >/dev/null 2>&1; then
  echo "dashboard non-fail-close behavior not reflected in summary"
  cat "${DASH_NON_FAIL_DIR}/prod_pilot_cohort_quick_runbook_summary.json"
  exit 1
fi

echo "[prod-pilot-cohort-quick-runbook] dashboard fail-close path"
DASH_FAIL_CLOSE_DIR="$TMP_DIR/dash_fail_close"
set +e
CAPTURE_FILE="$CAPTURE" \
FAKE_DASHBOARD_RC=2 \
PROD_PILOT_COHORT_QUICK_RUNBOOK_EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/prod_pilot_cohort_quick_runbook.sh \
  --reports-dir "$DASH_FAIL_CLOSE_DIR" \
  --dashboard-fail-close 1 >/tmp/integration_prod_pilot_cohort_quick_runbook_dashboard_fail_close.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc when dashboard fails with fail-close enabled"
  cat /tmp/integration_prod_pilot_cohort_quick_runbook_dashboard_fail_close.log
  exit 1
fi
if ! jq -e '.status=="fail" and .failure_step=="quick_dashboard"' "${DASH_FAIL_CLOSE_DIR}/prod_pilot_cohort_quick_runbook_summary.json" >/dev/null 2>&1; then
  echo "dashboard fail-close behavior not reflected in summary"
  cat "${DASH_FAIL_CLOSE_DIR}/prod_pilot_cohort_quick_runbook_summary.json"
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

echo "[prod-pilot-cohort-quick-runbook] easy_node forwarding"
FAKE_RUNBOOK="$TMP_DIR/fake_quick_runbook.sh"
RUNBOOK_FORWARD_CAPTURE="$TMP_DIR/runbook_forward_capture.log"
cat >"$FAKE_RUNBOOK" <<'EOF_FAKE_RUNBOOK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${RUNBOOK_FORWARD_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_RUNBOOK
chmod +x "$FAKE_RUNBOOK"

PATH="$TMP_BIN:$PATH" \
RUNBOOK_FORWARD_CAPTURE_FILE="$RUNBOOK_FORWARD_CAPTURE" \
PROD_PILOT_COHORT_QUICK_RUNBOOK_SCRIPT="$FAKE_RUNBOOK" \
./scripts/easy_node.sh prod-pilot-cohort-quick-runbook \
  --bootstrap-directory https://a.example:8081 \
  --subject demo-client \
  --pre-real-host-readiness 0 \
  --pre-real-host-readiness-summary-json /tmp/quick_pre_real_host.json \
  --reports-dir /tmp/quick_runbook \
  --max-round-failures 3 \
  --bundle-outputs 0 \
  --bundle-fail-close 0 \
  --signoff-incident-snapshot-min-attachment-count 4 \
  --signoff-incident-snapshot-max-skipped-count 1 \
  --signoff-require-cohort-signoff-policy 0 \
  --signoff-require-trend-artifact-policy-match 0 \
  --dashboard-fail-close 1 \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_quick_runbook_easy_node.log 2>&1

if ! rg -q -- '--bootstrap-directory https://a.example:8081' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --bootstrap-directory"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--subject demo-client' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --subject"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--pre-real-host-readiness 0' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --pre-real-host-readiness"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--pre-real-host-readiness-summary-json /tmp/quick_pre_real_host.json' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --pre-real-host-readiness-summary-json"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--reports-dir /tmp/quick_runbook' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --reports-dir"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-round-failures 3' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --max-round-failures"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--bundle-outputs 0' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --bundle-outputs"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--bundle-fail-close 0' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --bundle-fail-close"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--dashboard-fail-close 1' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --dashboard-fail-close"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--signoff-require-cohort-signoff-policy 0' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --signoff-require-cohort-signoff-policy"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--signoff-require-trend-artifact-policy-match 0' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --signoff-require-trend-artifact-policy-match"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--signoff-incident-snapshot-min-attachment-count 4' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --signoff-incident-snapshot-min-attachment-count"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--signoff-incident-snapshot-max-skipped-count 1' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --signoff-incident-snapshot-max-skipped-count"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --show-json"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi

echo "prod pilot cohort quick runbook integration ok"
