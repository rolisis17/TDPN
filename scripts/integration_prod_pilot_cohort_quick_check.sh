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
PRE_REAL_HOST_READINESS_SUMMARY_JSON="$REPORTS_DIR/pre_real_host_readiness_summary.json"

cat >"$SUMMARY_JSON" <<'EOF_SUMMARY'
{"status":"ok"}
EOF_SUMMARY

cat >"$PRE_REAL_HOST_READINESS_SUMMARY_JSON" <<'EOF_PRE_REAL_HOST'
{"status":"ok","machine_c_smoke_gate":{"ready":true}}
EOF_PRE_REAL_HOST

cat >"$RUN_REPORT_JSON" <<EOF_RUN_REPORT
{
  "status":"ok",
  "failure_step":"",
  "final_rc":0,
  "duration_sec":12,
  "runbook":{"rc":0},
  "signoff":{"attempted":true,"rc":0},
  "artifacts":{
    "summary_json":"$SUMMARY_JSON",
    "pre_real_host_readiness_summary_json":"$PRE_REAL_HOST_READINESS_SUMMARY_JSON"
  }
}
EOF_RUN_REPORT

echo "[prod-pilot-cohort-quick-check] baseline pass"
./scripts/prod_pilot_cohort_quick_check.sh \
  --run-report-json "$RUN_REPORT_JSON" >/tmp/integration_prod_pilot_cohort_quick_check_pass.log 2>&1
if ! rg -q -- "\\[prod-pilot-cohort-quick-check] pre_real_host_readiness_summary_json=$PRE_REAL_HOST_READINESS_SUMMARY_JSON" /tmp/integration_prod_pilot_cohort_quick_check_pass.log; then
  echo "quick-check output missing pre-real-host readiness summary path"
  cat /tmp/integration_prod_pilot_cohort_quick_check_pass.log
  exit 1
fi

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

echo "[prod-pilot-cohort-quick-check] detect numeric signoff attempted=false"
BAD_SIGNOFF_ATTEMPT="$TMP_DIR/bad_signoff_attempt.json"
jq '.signoff.attempted=0 | .signoff.rc=0' "$RUN_REPORT_JSON" >"$BAD_SIGNOFF_ATTEMPT"
set +e
./scripts/prod_pilot_cohort_quick_check.sh \
  --run-report-json "$BAD_SIGNOFF_ATTEMPT" >/tmp/integration_prod_pilot_cohort_quick_check_bad_signoff_attempt.log 2>&1
bad_signoff_attempt_rc=$?
set -e
if [[ "$bad_signoff_attempt_rc" -eq 0 ]]; then
  echo "expected non-zero rc for signoff attempted=false numeric value"
  cat /tmp/integration_prod_pilot_cohort_quick_check_bad_signoff_attempt.log
  exit 1
fi
if ! rg -q 'signoff was not attempted' /tmp/integration_prod_pilot_cohort_quick_check_bad_signoff_attempt.log; then
  echo "expected numeric signoff-attempt failure signal not found"
  cat /tmp/integration_prod_pilot_cohort_quick_check_bad_signoff_attempt.log
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

echo "[prod-pilot-cohort-quick-check] strict cohort signoff policy hook"
cat >"$SUMMARY_JSON" <<'EOF_SUMMARY_OK'
{"status":"ok"}
EOF_SUMMARY_OK
COHORT_POLICY_CAPTURE="$TMP_DIR/cohort_policy_capture.log"
FAKE_COHORT_POLICY="$TMP_DIR/fake_cohort_policy.sh"
cat >"$FAKE_COHORT_POLICY" <<'EOF_FAKE_COHORT_POLICY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${COHORT_POLICY_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_COHORT_POLICY
chmod +x "$FAKE_COHORT_POLICY"

COHORT_POLICY_CAPTURE_FILE="$COHORT_POLICY_CAPTURE" \
PROD_PILOT_COHORT_CHECK_SCRIPT="$FAKE_COHORT_POLICY" \
./scripts/prod_pilot_cohort_quick_check.sh \
  --run-report-json "$RUN_REPORT_JSON" \
  --require-cohort-signoff-policy 1 \
  --require-trend-artifact-policy-match 0 \
  --require-trend-wg-validate-udp-source 0 \
  --require-trend-wg-validate-strict-distinct 0 \
  --require-trend-wg-soak-diversity-pass 0 \
  --min-trend-wg-soak-selection-lines 5 \
  --min-trend-wg-soak-entry-operators 1 \
  --min-trend-wg-soak-exit-operators 1 \
  --min-trend-wg-soak-cross-operator-pairs 1 \
  --min-go-rate-pct 97.5 \
  --max-alert-severity OK \
  --require-bundle-created 0 \
  --require-bundle-manifest 0 \
  --require-incident-snapshot-on-fail 0 \
  --require-incident-snapshot-artifacts 0 \
  --incident-snapshot-min-attachment-count 2 \
  --incident-snapshot-max-skipped-count 0 >/tmp/integration_prod_pilot_cohort_quick_check_cohort_policy.log 2>&1

if ! rg -q -- '--require-trend-artifact-policy-match 0' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward trend artifact policy override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-trend-wg-validate-udp-source 0' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward trend udp-source policy override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-trend-wg-validate-strict-distinct 0' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward trend strict-distinct policy override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-trend-wg-soak-diversity-pass 0' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward trend soak-diversity policy override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-trend-wg-soak-selection-lines 5' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward trend soak selection-lines override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-trend-wg-soak-entry-operators 1' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward trend soak entry-operators override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-trend-wg-soak-exit-operators 1' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward trend soak exit-operators override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-trend-wg-soak-cross-operator-pairs 1' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward trend soak cross-operator-pairs override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-go-rate-pct 97.5' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward min-go-rate override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-alert-severity OK' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward max-alert-severity override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-bundle-created 0' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward bundle-created override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-bundle-manifest 0' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward bundle-manifest override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-min-attachment-count 2' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward incident attachment floor override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-max-skipped-count 0' "$COHORT_POLICY_CAPTURE"; then
  echo "expected cohort policy hook to forward incident skipped-count budget override"
  cat "$COHORT_POLICY_CAPTURE"
  exit 1
fi

echo "[prod-pilot-cohort-quick-check] incident sub-check disables trend artifact policy coupling"
INCIDENT_SUMMARY="$TMP_DIR/incident_summary.json"
INCIDENT_RUN_REPORT="$TMP_DIR/incident_run_report.json"
COHORT_CAPTURE="$TMP_DIR/cohort_check_capture.log"
cat >"$INCIDENT_SUMMARY" <<'EOF_INCIDENT_SUMMARY'
{"status":"fail","rounds":{"failed":1},"run_reports":[]}
EOF_INCIDENT_SUMMARY
cat >"$INCIDENT_RUN_REPORT" <<EOF_INCIDENT_RUN_REPORT
{
  "status":"fail",
  "failure_step":"runbook",
  "final_rc":9,
  "duration_sec":3,
  "runbook":{"rc":9},
  "signoff":{"attempted":0,"rc":0},
  "artifacts":{"summary_json":"$INCIDENT_SUMMARY"}
}
EOF_INCIDENT_RUN_REPORT

FAKE_COHORT_CHECK="$TMP_DIR/fake_cohort_check.sh"
cat >"$FAKE_COHORT_CHECK" <<'EOF_FAKE_COHORT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${COHORT_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_COHORT
chmod +x "$FAKE_COHORT_CHECK"

COHORT_CAPTURE_FILE="$COHORT_CAPTURE" \
PROD_PILOT_COHORT_CHECK_SCRIPT="$FAKE_COHORT_CHECK" \
./scripts/prod_pilot_cohort_quick_check.sh \
  --run-report-json "$INCIDENT_RUN_REPORT" \
  --require-status-ok 0 \
  --require-runbook-ok 0 \
  --require-signoff-attempted 0 \
  --require-signoff-ok 0 \
  --require-summary-status-ok 0 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 0 \
  --incident-snapshot-min-attachment-count 2 \
  --incident-snapshot-max-skipped-count 0 >/tmp/integration_prod_pilot_cohort_quick_check_incident_subcheck.log 2>&1

if ! rg -q -- '--require-trend-artifact-policy-match 0' "$COHORT_CAPTURE"; then
  echo "expected incident sub-check to disable trend artifact policy coupling"
  cat "$COHORT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 1' "$COHORT_CAPTURE"; then
  echo "expected incident sub-check forwarding missing --require-incident-snapshot-on-fail 1"
  cat "$COHORT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-min-attachment-count 2' "$COHORT_CAPTURE"; then
  echo "expected incident sub-check forwarding missing --incident-snapshot-min-attachment-count 2"
  cat "$COHORT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-max-skipped-count 0' "$COHORT_CAPTURE"; then
  echo "expected incident sub-check forwarding missing --incident-snapshot-max-skipped-count 0"
  cat "$COHORT_CAPTURE"
  exit 1
fi

echo "[prod-pilot-cohort-quick-check] incident handoff output"
HANDOFF_SUMMARY="$TMP_DIR/handoff_summary.json"
HANDOFF_REPORT="$TMP_DIR/handoff_report.md"
HANDOFF_BUNDLE_DIR="$TMP_DIR/handoff_bundle"
HANDOFF_BUNDLE_TAR="$TMP_DIR/handoff_bundle.tar.gz"
HANDOFF_RUN_REPORT="$TMP_DIR/handoff_run_report.json"
mkdir -p "$HANDOFF_BUNDLE_DIR"
cat >"$HANDOFF_SUMMARY" <<EOF_HANDOFF_SUMMARY
{
  "status":"ok",
  "incident_snapshot":{
    "latest_failed_run_report":{
      "path":"$TMP_DIR/source_failed_round.json",
      "enabled":true,
      "status":"ok",
      "bundle_dir":{"path":"$HANDOFF_BUNDLE_DIR","exists":true},
      "bundle_tar":{"path":"$HANDOFF_BUNDLE_TAR","exists":true},
      "summary_json":{"path":"$INCIDENT_SUMMARY","exists":true,"valid_json":true},
      "report_md":{"path":"$HANDOFF_REPORT","exists":true}
    }
  }
}
EOF_HANDOFF_SUMMARY
printf 'handoff tar\n' >"$HANDOFF_BUNDLE_TAR"
cat >"$HANDOFF_REPORT" <<'EOF_HANDOFF_REPORT'
# Incident Snapshot Summary
EOF_HANDOFF_REPORT
cat >"$HANDOFF_RUN_REPORT" <<EOF_HANDOFF_RUN_REPORT
{
  "status":"fail",
  "failure_step":"runbook",
  "final_rc":9,
  "duration_sec":3,
  "runbook":{"rc":0},
  "signoff":{"attempted":0,"rc":0},
  "artifacts":{"summary_json":"$HANDOFF_SUMMARY"}
}
EOF_HANDOFF_RUN_REPORT

COHORT_CAPTURE_FILE="$COHORT_CAPTURE" \
PROD_PILOT_COHORT_CHECK_SCRIPT="$FAKE_COHORT_CHECK" \
./scripts/prod_pilot_cohort_quick_check.sh \
  --run-report-json "$HANDOFF_RUN_REPORT" \
  --require-status-ok 0 \
  --require-runbook-ok 0 \
  --require-signoff-attempted 0 \
  --require-signoff-ok 0 \
  --require-summary-status-ok 0 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 >/tmp/integration_prod_pilot_cohort_quick_check_handoff.log 2>&1

if ! rg -q 'incident_handoff' /tmp/integration_prod_pilot_cohort_quick_check_handoff.log; then
  echo "expected quick-check incident handoff line not found"
  cat /tmp/integration_prod_pilot_cohort_quick_check_handoff.log
  exit 1
fi
if ! rg -q -- "$INCIDENT_SUMMARY" /tmp/integration_prod_pilot_cohort_quick_check_handoff.log; then
  echo "expected quick-check incident summary path not surfaced"
  cat /tmp/integration_prod_pilot_cohort_quick_check_handoff.log
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
  --incident-snapshot-min-attachment-count 2 \
  --incident-snapshot-max-skipped-count 0 \
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
if ! rg -q -- '--incident-snapshot-min-attachment-count 2' "$CHECK_CAPTURE"; then
  echo "easy_node quick-check forwarding failed: missing --incident-snapshot-min-attachment-count"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-max-skipped-count 0' "$CHECK_CAPTURE"; then
  echo "easy_node quick-check forwarding failed: missing --incident-snapshot-max-skipped-count"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$CHECK_CAPTURE"; then
  echo "easy_node quick-check forwarding failed: missing --show-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi

echo "prod pilot cohort quick check integration check ok"
