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
      cat >"$signoff_json" <<'EOF_SIGNOFF'
{"status":"ok"}
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
if ! jq -e '.status=="ok" and .stages.quick.rc==0 and .stages.quick_signoff.rc==0 and .stages.quick_dashboard.rc==0' "${SUCCESS_DIR}/prod_pilot_cohort_quick_runbook_summary.json" >/dev/null 2>&1; then
  echo "runbook summary missing expected success stage fields"
  cat "${SUCCESS_DIR}/prod_pilot_cohort_quick_runbook_summary.json"
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
  --reports-dir /tmp/quick_runbook \
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
if ! rg -q -- '--reports-dir /tmp/quick_runbook' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --reports-dir"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--dashboard-fail-close 1' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --dashboard-fail-close"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$RUNBOOK_FORWARD_CAPTURE"; then
  echo "easy_node quick-runbook forwarding failed: missing --show-json"
  cat "$RUNBOOK_FORWARD_CAPTURE"
  exit 1
fi

echo "prod pilot cohort quick runbook integration ok"
