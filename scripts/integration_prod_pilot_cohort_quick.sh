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
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
CAPTURE="$TMP_DIR/capture.log"
cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY'
#!/usr/bin/env bash
set -euo pipefail
printf 'cmd %s\n' "$*" >>"${CAPTURE_FILE:?}"
cmd="${1:-}"
shift || true
if [[ "$cmd" == "prod-pilot-cohort-runbook" ]]; then
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
  if [[ "${FAKE_SKIP_SUMMARY_CREATE:-0}" != "1" && -n "$summary_json" ]]; then
    mkdir -p "$(dirname "$summary_json")"
    cat >"$summary_json" <<'EOF_SUMMARY'
{"status":"ok"}
EOF_SUMMARY
  fi
  exit "${FAKE_RUNBOOK_RC:-0}"
fi
if [[ "$cmd" == "prod-pilot-cohort-signoff" ]]; then
  exit "${FAKE_SIGNOFF_RC:-0}"
fi
exit 2
EOF_FAKE_EASY
chmod +x "$FAKE_EASY_NODE"

echo "[prod-pilot-cohort-quick] success path forwarding"
SUCCESS_REPORTS="$TMP_DIR/success_reports"
SUCCESS_SUMMARY="$SUCCESS_REPORTS/prod_pilot_cohort_summary.json"
SUCCESS_RUN_REPORT="$SUCCESS_REPORTS/prod_pilot_cohort_quick_report.json"
CAPTURE_FILE="$CAPTURE" \
PROD_PILOT_COHORT_QUICK_EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_RUNBOOK_RC=0 \
FAKE_SIGNOFF_RC=0 \
./scripts/prod_pilot_cohort_quick.sh \
  --bootstrap-directory https://a.example:8081 \
  --subject pilot-alice \
  --rounds 3 \
  --pause-sec 1 \
  --reports-dir "$SUCCESS_REPORTS" \
  --summary-json "$SUCCESS_SUMMARY" \
  --run-report-json "$SUCCESS_RUN_REPORT" \
  --print-run-report 1 \
  --max-alert-severity WARN \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_quick_success.log 2>&1

if ! rg -q 'cmd prod-pilot-cohort-runbook' "$CAPTURE"; then
  echo "expected runbook invocation not observed"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q 'cmd prod-pilot-cohort-signoff' "$CAPTURE"; then
  echo "expected signoff invocation not observed"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--bootstrap-directory https://a.example:8081' "$CAPTURE"; then
  echo "quick forwarding missing bootstrap-directory"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--subject pilot-alice' "$CAPTURE"; then
  echo "quick forwarding missing subject"
  cat "$CAPTURE"
  exit 1
fi
if [[ ! -f "$SUCCESS_RUN_REPORT" ]]; then
  echo "expected quick run report not found"
  exit 1
fi
if ! jq -e '.status == "ok" and .runbook.rc == 0 and .signoff.rc == 0' "$SUCCESS_RUN_REPORT" >/dev/null; then
  echo "unexpected quick run report payload for success path"
  cat "$SUCCESS_RUN_REPORT"
  exit 1
fi

echo "[prod-pilot-cohort-quick] runbook fail with summary still runs signoff"
FAIL_SUMMARY="$TMP_DIR/fail_with_summary/prod_pilot_cohort_summary.json"
FAIL_RUN_REPORT="$TMP_DIR/fail_with_summary/prod_pilot_cohort_quick_report.json"
CAPTURE2="$TMP_DIR/capture2.log"
set +e
CAPTURE_FILE="$CAPTURE2" \
PROD_PILOT_COHORT_QUICK_EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_RUNBOOK_RC=9 \
FAKE_SIGNOFF_RC=0 \
./scripts/prod_pilot_cohort_quick.sh \
  --reports-dir "$TMP_DIR/fail_with_summary" \
  --summary-json "$FAIL_SUMMARY" \
  --run-report-json "$FAIL_RUN_REPORT" >/tmp/integration_prod_pilot_cohort_quick_fail_with_summary.log 2>&1
rc_with_summary=$?
set -e
if [[ "$rc_with_summary" -eq 0 ]]; then
  echo "expected non-zero rc when runbook fails with summary"
  cat /tmp/integration_prod_pilot_cohort_quick_fail_with_summary.log
  exit 1
fi

if ! rg -q 'cmd prod-pilot-cohort-signoff' "$CAPTURE2"; then
  echo "expected signoff invocation when runbook fails with summary"
  cat "$CAPTURE2"
  exit 1
fi
if [[ ! -f "$FAIL_RUN_REPORT" ]]; then
  echo "expected quick run report for runbook-fail-with-summary path not found"
  exit 1
fi
if ! jq -e '.status == "fail" and .failure_step == "runbook" and .runbook.rc == 9 and .signoff.rc == 0' "$FAIL_RUN_REPORT" >/dev/null; then
  echo "unexpected run report payload for runbook-fail-with-summary path"
  cat "$FAIL_RUN_REPORT"
  exit 1
fi

echo "[prod-pilot-cohort-quick] runbook fail without summary stops before signoff"
FAIL_NO_SUMMARY="$TMP_DIR/fail_no_summary/prod_pilot_cohort_summary.json"
FAIL_NO_SUMMARY_REPORT="$TMP_DIR/fail_no_summary/prod_pilot_cohort_quick_report.json"
CAPTURE3="$TMP_DIR/capture3.log"
set +e
CAPTURE_FILE="$CAPTURE3" \
PROD_PILOT_COHORT_QUICK_EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_RUNBOOK_RC=11 \
FAKE_SIGNOFF_RC=0 \
FAKE_SKIP_SUMMARY_CREATE=1 \
./scripts/prod_pilot_cohort_quick.sh \
  --reports-dir "$TMP_DIR/fail_no_summary" \
  --summary-json "$FAIL_NO_SUMMARY" \
  --run-report-json "$FAIL_NO_SUMMARY_REPORT" >/tmp/integration_prod_pilot_cohort_quick_fail_no_summary.log 2>&1
rc_no_summary=$?
set -e
if [[ "$rc_no_summary" -eq 0 ]]; then
  echo "expected non-zero rc when runbook fails without summary"
  cat /tmp/integration_prod_pilot_cohort_quick_fail_no_summary.log
  exit 1
fi
if rg -q 'cmd prod-pilot-cohort-signoff' "$CAPTURE3"; then
  echo "signoff should not run when runbook fails and summary is missing"
  cat "$CAPTURE3"
  exit 1
fi
if [[ ! -f "$FAIL_NO_SUMMARY_REPORT" ]]; then
  echo "expected run report for missing-summary failure path not found"
  exit 1
fi
if ! jq -e '.status == "fail" and .failure_step == "runbook_summary_missing" and .runbook.rc == 11 and .signoff.attempted == false' "$FAIL_NO_SUMMARY_REPORT" >/dev/null; then
  echo "unexpected run report payload for missing-summary failure path"
  cat "$FAIL_NO_SUMMARY_REPORT"
  exit 1
fi

echo "prod pilot cohort quick integration check ok"
