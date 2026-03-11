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

REPORTS_DIR="$TMP_DIR/reports"
mkdir -p "$REPORTS_DIR"
SUMMARY_JSON="$REPORTS_DIR/prod_pilot_cohort_summary.json"
RUN_REPORT_JSON="$REPORTS_DIR/prod_pilot_cohort_quick_report.json"

cat >"$SUMMARY_JSON" <<'EOF_SUMMARY'
{"status":"ok"}
EOF_SUMMARY

cat >"$RUN_REPORT_JSON" <<EOF_RUN_REPORT
{
  "status":"ok",
  "failure_step":"",
  "final_rc":0,
  "duration_sec":12,
  "runbook":{"rc":0},
  "signoff":{"attempted":true,"rc":0},
  "artifacts":{"summary_json":"$SUMMARY_JSON"}
}
EOF_RUN_REPORT

echo "[prod-pilot-cohort-quick-check] baseline pass"
./scripts/prod_pilot_cohort_quick_check.sh \
  --run-report-json "$RUN_REPORT_JSON" >/tmp/integration_prod_pilot_cohort_quick_check_pass.log 2>&1

echo "[prod-pilot-cohort-quick-check] detect signoff rc failure"
BAD_SIGNOFF="$TMP_DIR/bad_signoff.json"
jq '.signoff.rc=3' "$RUN_REPORT_JSON" >"$BAD_SIGNOFF"
set +e
./scripts/prod_pilot_cohort_quick_check.sh \
  --run-report-json "$BAD_SIGNOFF" >/tmp/integration_prod_pilot_cohort_quick_check_bad_signoff.log 2>&1
bad_signoff_rc=$?
set -e
if [[ "$bad_signoff_rc" -eq 0 ]]; then
  echo "expected non-zero rc for signoff rc failure"
  cat /tmp/integration_prod_pilot_cohort_quick_check_bad_signoff.log
  exit 1
fi
if ! rg -q 'signoff rc is non-zero' /tmp/integration_prod_pilot_cohort_quick_check_bad_signoff.log; then
  echo "expected signoff rc failure signal not found"
  cat /tmp/integration_prod_pilot_cohort_quick_check_bad_signoff.log
  exit 1
fi

echo "[prod-pilot-cohort-quick-check] detect summary status failure"
cat >"$SUMMARY_JSON" <<'EOF_SUMMARY_BAD'
{"status":"fail"}
EOF_SUMMARY_BAD
set +e
./scripts/prod_pilot_cohort_quick_check.sh \
  --run-report-json "$RUN_REPORT_JSON" >/tmp/integration_prod_pilot_cohort_quick_check_bad_summary_status.log 2>&1
bad_summary_rc=$?
set -e
if [[ "$bad_summary_rc" -eq 0 ]]; then
  echo "expected non-zero rc for summary status failure"
  cat /tmp/integration_prod_pilot_cohort_quick_check_bad_summary_status.log
  exit 1
fi
if ! rg -q 'summary status is not ok' /tmp/integration_prod_pilot_cohort_quick_check_bad_summary_status.log; then
  echo "expected summary status failure signal not found"
  cat /tmp/integration_prod_pilot_cohort_quick_check_bad_summary_status.log
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

echo "[prod-pilot-cohort-quick-check] easy_node forwarding"
FAKE_CHECK="$TMP_DIR/fake_check.sh"
CHECK_CAPTURE="$TMP_DIR/check_capture.log"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CHECK_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

PATH="$TMP_BIN:$PATH" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
PROD_PILOT_COHORT_QUICK_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/easy_node.sh prod-pilot-cohort-quick-check \
  --run-report-json /tmp/quick/report.json \
  --require-signoff-ok 1 \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_quick_check_easy_node.log 2>&1

if ! rg -q -- '--run-report-json /tmp/quick/report.json' "$CHECK_CAPTURE"; then
  echo "easy_node quick-check forwarding failed: missing --run-report-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-signoff-ok 1' "$CHECK_CAPTURE"; then
  echo "easy_node quick-check forwarding failed: missing --require-signoff-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$CHECK_CAPTURE"; then
  echo "easy_node quick-check forwarding failed: missing --show-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi

echo "prod pilot cohort quick check integration check ok"
