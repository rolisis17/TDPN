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

SIGNOFF_CAPTURE="$TMP_DIR/signoff_capture.log"
CHECK_CAPTURE="$TMP_DIR/check_capture.log"
TREND_CAPTURE="$TMP_DIR/trend_capture.log"
ALERT_CAPTURE="$TMP_DIR/alert_capture.log"

FAKE_CHECK="$TMP_DIR/fake_quick_check.sh"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail
printf 'check %s\n' "$*" >>"${SIGNOFF_CAPTURE_FILE:?}"
printf '%s\n' "$*" >>"${CHECK_CAPTURE_FILE:?}"
exit "${FAKE_CHECK_RC:-0}"
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

FAKE_TREND="$TMP_DIR/fake_quick_trend.sh"
cat >"$FAKE_TREND" <<'EOF_FAKE_TREND'
#!/usr/bin/env bash
set -euo pipefail
printf 'trend %s\n' "$*" >>"${SIGNOFF_CAPTURE_FILE:?}"
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
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_TREND_SUMMARY'
{"decision":"GO","go_rate_pct":100,"no_go":0,"evaluation_errors":0,"reports_total":1}
EOF_TREND_SUMMARY
fi
exit "${FAKE_TREND_RC:-0}"
EOF_FAKE_TREND
chmod +x "$FAKE_TREND"

FAKE_ALERT="$TMP_DIR/fake_quick_alert.sh"
cat >"$FAKE_ALERT" <<'EOF_FAKE_ALERT'
#!/usr/bin/env bash
set -euo pipefail
printf 'alert %s\n' "$*" >>"${SIGNOFF_CAPTURE_FILE:?}"
printf '%s\n' "$*" >>"${ALERT_CAPTURE_FILE:?}"
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
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_ALERT_SUMMARY'
{"severity":"WARN"}
EOF_ALERT_SUMMARY
fi
exit "${FAKE_ALERT_RC:-0}"
EOF_FAKE_ALERT
chmod +x "$FAKE_ALERT"

echo "[prod-pilot-cohort-quick-signoff] script orchestration success path"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
PROD_PILOT_COHORT_QUICK_CHECK_SCRIPT="$FAKE_CHECK" \
PROD_PILOT_COHORT_QUICK_TREND_SCRIPT="$FAKE_TREND" \
PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT="$FAKE_ALERT" \
./scripts/prod_pilot_cohort_quick_signoff.sh \
  --run-report-json /tmp/quick/report.json \
  --reports-dir /tmp/quick/reports \
  --require-cohort-signoff-policy 1 \
  --require-trend-artifact-policy-match 0 \
  --require-trend-wg-validate-udp-source 0 \
  --require-trend-wg-validate-strict-distinct 0 \
  --require-trend-wg-soak-diversity-pass 0 \
  --min-trend-wg-soak-selection-lines 3 \
  --min-trend-wg-soak-entry-operators 1 \
  --min-trend-wg-soak-exit-operators 1 \
  --min-trend-wg-soak-cross-operator-pairs 1 \
  --require-bundle-created 0 \
  --require-bundle-manifest 0 \
  --max-alert-severity WARN \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_quick_signoff_pass.log 2>&1

SIGNOFF_JSON="/tmp/quick/reports/prod_pilot_quick_signoff.json"
if [[ ! -f "$SIGNOFF_JSON" ]]; then
  echo "expected quick-signoff artifact missing: $SIGNOFF_JSON"
  ls -la /tmp/quick/reports 2>/dev/null || true
  cat /tmp/integration_prod_pilot_cohort_quick_signoff_pass.log
  exit 1
fi
if ! jq -e '.status=="ok" and .policy.require_trend_artifact_policy_match==0 and .policy.require_trend_wg_validate_udp_source==0 and .policy.require_trend_wg_validate_strict_distinct==0 and .policy.require_trend_wg_soak_diversity_pass==0 and .policy.min_trend_wg_soak_selection_lines==3 and .policy.min_trend_wg_soak_entry_operators==1 and .policy.min_trend_wg_soak_exit_operators==1 and .policy.min_trend_wg_soak_cross_operator_pairs==1 and .policy.require_bundle_created==0 and .policy.require_bundle_manifest==0 and .policy.max_alert_severity=="WARN"' "$SIGNOFF_JSON" >/dev/null 2>&1; then
  echo "quick-signoff artifact missing expected strict policy fields"
  cat "$SIGNOFF_JSON"
  exit 1
fi

if ! rg -q -- '^check ' "$SIGNOFF_CAPTURE"; then
  echo "expected quick-check step invocation not observed"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q -- '^trend ' "$SIGNOFF_CAPTURE"; then
  echo "expected quick-trend step invocation not observed"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q -- '^alert ' "$SIGNOFF_CAPTURE"; then
  echo "expected quick-alert step invocation not observed"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q -- '--run-report-json /tmp/quick/report.json' "$CHECK_CAPTURE"; then
  echo "quick-signoff forwarding missing --run-report-json to quick-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-cohort-signoff-policy 1' "$CHECK_CAPTURE"; then
  echo "quick-signoff forwarding missing --require-cohort-signoff-policy 1 to quick-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-trend-artifact-policy-match 0' "$CHECK_CAPTURE"; then
  echo "quick-signoff forwarding missing --require-trend-artifact-policy-match 0 to quick-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-trend-wg-validate-udp-source 0' "$CHECK_CAPTURE"; then
  echo "quick-signoff forwarding missing --require-trend-wg-validate-udp-source 0 to quick-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-trend-wg-validate-strict-distinct 0' "$CHECK_CAPTURE"; then
  echo "quick-signoff forwarding missing --require-trend-wg-validate-strict-distinct 0 to quick-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-trend-wg-soak-diversity-pass 0' "$CHECK_CAPTURE"; then
  echo "quick-signoff forwarding missing --require-trend-wg-soak-diversity-pass 0 to quick-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-trend-wg-soak-selection-lines 3' "$CHECK_CAPTURE"; then
  echo "quick-signoff forwarding missing --min-trend-wg-soak-selection-lines 3 to quick-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-trend-wg-soak-entry-operators 1' "$CHECK_CAPTURE"; then
  echo "quick-signoff forwarding missing --min-trend-wg-soak-entry-operators 1 to quick-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-trend-wg-soak-exit-operators 1' "$CHECK_CAPTURE"; then
  echo "quick-signoff forwarding missing --min-trend-wg-soak-exit-operators 1 to quick-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-trend-wg-soak-cross-operator-pairs 1' "$CHECK_CAPTURE"; then
  echo "quick-signoff forwarding missing --min-trend-wg-soak-cross-operator-pairs 1 to quick-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-bundle-created 0' "$CHECK_CAPTURE"; then
  echo "quick-signoff forwarding missing --require-bundle-created 0 to quick-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-bundle-manifest 0' "$CHECK_CAPTURE"; then
  echo "quick-signoff forwarding missing --require-bundle-manifest 0 to quick-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json ' "$TREND_CAPTURE"; then
  echo "quick-signoff forwarding missing --summary-json to quick-trend"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-cohort-signoff-policy 1' "$TREND_CAPTURE"; then
  echo "quick-signoff forwarding missing --require-cohort-signoff-policy 1 to quick-trend"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--trend-summary-json ' "$ALERT_CAPTURE"; then
  echo "quick-signoff forwarding missing --trend-summary-json to quick-alert"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-cohort-signoff-policy 1' "$ALERT_CAPTURE"; then
  echo "quick-signoff forwarding missing --require-cohort-signoff-policy 1 to quick-alert"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fail-on-critical 1' "$ALERT_CAPTURE"; then
  echo "quick-signoff severity policy forwarding missing --fail-on-critical 1 for max-alert-severity=WARN"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fail-on-warn 0' "$ALERT_CAPTURE"; then
  echo "quick-signoff severity policy forwarding missing --fail-on-warn 0 for max-alert-severity=WARN"
  cat "$ALERT_CAPTURE"
  exit 1
fi

echo "[prod-pilot-cohort-quick-signoff] signoff env namespace precedence"
CHECK_CAPTURE_ENV="$TMP_DIR/check_capture_env.log"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE_ENV" \
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_STATUS_OK=0 \
PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_RUNBOOK_OK=0 \
PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_SIGNOFF_ATTEMPTED=0 \
PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_SIGNOFF_OK=0 \
PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_SUMMARY_JSON=0 \
PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_SUMMARY_STATUS_OK=0 \
PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL=0 \
PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS=0 \
PROD_PILOT_COHORT_QUICK_SIGNOFF_MAX_DURATION_SEC=17 \
PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_STATUS_OK=1 \
PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_RUNBOOK_OK=1 \
PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SIGNOFF_ATTEMPTED=1 \
PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SIGNOFF_OK=1 \
PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SUMMARY_JSON=1 \
PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SUMMARY_STATUS_OK=1 \
PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL=1 \
PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS=1 \
PROD_PILOT_COHORT_QUICK_CHECK_MAX_DURATION_SEC=99 \
PROD_PILOT_COHORT_QUICK_CHECK_SCRIPT="$FAKE_CHECK" \
PROD_PILOT_COHORT_QUICK_TREND_SCRIPT="$FAKE_TREND" \
PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT="$FAKE_ALERT" \
./scripts/prod_pilot_cohort_quick_signoff.sh \
  --run-report-json /tmp/quick/report.json \
  --reports-dir /tmp/quick/reports >/tmp/integration_prod_pilot_cohort_quick_signoff_env_namespace.log 2>&1
if ! rg -q -- '--require-status-ok 0' "$CHECK_CAPTURE_ENV"; then
  echo "quick-signoff env precedence failed: missing --require-status-ok 0 from signoff env namespace"
  cat "$CHECK_CAPTURE_ENV"
  exit 1
fi
if ! rg -q -- '--require-runbook-ok 0' "$CHECK_CAPTURE_ENV"; then
  echo "quick-signoff env precedence failed: missing --require-runbook-ok 0 from signoff env namespace"
  cat "$CHECK_CAPTURE_ENV"
  exit 1
fi
if ! rg -q -- '--require-signoff-attempted 0' "$CHECK_CAPTURE_ENV"; then
  echo "quick-signoff env precedence failed: missing --require-signoff-attempted 0 from signoff env namespace"
  cat "$CHECK_CAPTURE_ENV"
  exit 1
fi
if ! rg -q -- '--require-signoff-ok 0' "$CHECK_CAPTURE_ENV"; then
  echo "quick-signoff env precedence failed: missing --require-signoff-ok 0 from signoff env namespace"
  cat "$CHECK_CAPTURE_ENV"
  exit 1
fi
if ! rg -q -- '--require-summary-json 0' "$CHECK_CAPTURE_ENV"; then
  echo "quick-signoff env precedence failed: missing --require-summary-json 0 from signoff env namespace"
  cat "$CHECK_CAPTURE_ENV"
  exit 1
fi
if ! rg -q -- '--require-summary-status-ok 0' "$CHECK_CAPTURE_ENV"; then
  echo "quick-signoff env precedence failed: missing --require-summary-status-ok 0 from signoff env namespace"
  cat "$CHECK_CAPTURE_ENV"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 0' "$CHECK_CAPTURE_ENV"; then
  echo "quick-signoff env precedence failed: missing --require-incident-snapshot-on-fail 0 from signoff env namespace"
  cat "$CHECK_CAPTURE_ENV"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 0' "$CHECK_CAPTURE_ENV"; then
  echo "quick-signoff env precedence failed: missing --require-incident-snapshot-artifacts 0 from signoff env namespace"
  cat "$CHECK_CAPTURE_ENV"
  exit 1
fi
if ! rg -q -- '--max-duration-sec 17' "$CHECK_CAPTURE_ENV"; then
  echo "quick-signoff env precedence failed: missing --max-duration-sec 17 from signoff env namespace"
  cat "$CHECK_CAPTURE_ENV"
  exit 1
fi

echo "[prod-pilot-cohort-quick-signoff] severity matrix: max-alert-severity=OK"
ALERT_CAPTURE_OK="$TMP_DIR/alert_capture_ok.log"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE_OK" \
PROD_PILOT_COHORT_QUICK_CHECK_SCRIPT="$FAKE_CHECK" \
PROD_PILOT_COHORT_QUICK_TREND_SCRIPT="$FAKE_TREND" \
PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT="$FAKE_ALERT" \
./scripts/prod_pilot_cohort_quick_signoff.sh \
  --run-report-json /tmp/quick/report.json \
  --reports-dir /tmp/quick/reports \
  --max-alert-severity OK >/tmp/integration_prod_pilot_cohort_quick_signoff_ok_severity.log 2>&1
if ! rg -q -- '--fail-on-warn 1' "$ALERT_CAPTURE_OK"; then
  echo "quick-signoff severity mapping failed for max-alert-severity=OK: missing --fail-on-warn 1"
  cat "$ALERT_CAPTURE_OK"
  exit 1
fi
if ! rg -q -- '--fail-on-critical 1' "$ALERT_CAPTURE_OK"; then
  echo "quick-signoff severity mapping failed for max-alert-severity=OK: missing --fail-on-critical 1"
  cat "$ALERT_CAPTURE_OK"
  exit 1
fi

echo "[prod-pilot-cohort-quick-signoff] severity matrix: max-alert-severity=CRITICAL"
ALERT_CAPTURE_CRITICAL="$TMP_DIR/alert_capture_critical.log"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE_CRITICAL" \
PROD_PILOT_COHORT_QUICK_CHECK_SCRIPT="$FAKE_CHECK" \
PROD_PILOT_COHORT_QUICK_TREND_SCRIPT="$FAKE_TREND" \
PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT="$FAKE_ALERT" \
./scripts/prod_pilot_cohort_quick_signoff.sh \
  --run-report-json /tmp/quick/report.json \
  --reports-dir /tmp/quick/reports \
  --max-alert-severity CRITICAL >/tmp/integration_prod_pilot_cohort_quick_signoff_critical_severity.log 2>&1
if ! rg -q -- '--fail-on-warn 0' "$ALERT_CAPTURE_CRITICAL"; then
  echo "quick-signoff severity mapping failed for max-alert-severity=CRITICAL: missing --fail-on-warn 0"
  cat "$ALERT_CAPTURE_CRITICAL"
  exit 1
fi
if ! rg -q -- '--fail-on-critical 0' "$ALERT_CAPTURE_CRITICAL"; then
  echo "quick-signoff severity mapping failed for max-alert-severity=CRITICAL: missing --fail-on-critical 0"
  cat "$ALERT_CAPTURE_CRITICAL"
  exit 1
fi

echo "[prod-pilot-cohort-quick-signoff] fail-close when quick-check fails"
TREND_SHOULD_NOT_RUN="$TMP_DIR/trend_should_not_run.log"
ALERT_SHOULD_NOT_RUN="$TMP_DIR/alert_should_not_run.log"

FAKE_TREND_MARK="$TMP_DIR/fake_trend_mark.sh"
cat >"$FAKE_TREND_MARK" <<'EOF_FAKE_TREND_MARK'
#!/usr/bin/env bash
set -euo pipefail
printf 'unexpected-trend %s\n' "$*" >>"${TREND_SHOULD_NOT_RUN_FILE:?}"
exit 0
EOF_FAKE_TREND_MARK
chmod +x "$FAKE_TREND_MARK"

FAKE_ALERT_MARK="$TMP_DIR/fake_alert_mark.sh"
cat >"$FAKE_ALERT_MARK" <<'EOF_FAKE_ALERT_MARK'
#!/usr/bin/env bash
set -euo pipefail
printf 'unexpected-alert %s\n' "$*" >>"${ALERT_SHOULD_NOT_RUN_FILE:?}"
exit 0
EOF_FAKE_ALERT_MARK
chmod +x "$FAKE_ALERT_MARK"

set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
FAKE_CHECK_RC=1 \
TREND_SHOULD_NOT_RUN_FILE="$TREND_SHOULD_NOT_RUN" \
ALERT_SHOULD_NOT_RUN_FILE="$ALERT_SHOULD_NOT_RUN" \
PROD_PILOT_COHORT_QUICK_CHECK_SCRIPT="$FAKE_CHECK" \
PROD_PILOT_COHORT_QUICK_TREND_SCRIPT="$FAKE_TREND_MARK" \
PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT="$FAKE_ALERT_MARK" \
./scripts/prod_pilot_cohort_quick_signoff.sh \
  --run-report-json /tmp/quick/report.json >/tmp/integration_prod_pilot_cohort_quick_signoff_check_fail.log 2>&1
check_fail_rc=$?
set -e
if [[ "$check_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when quick-check step fails"
  cat /tmp/integration_prod_pilot_cohort_quick_signoff_check_fail.log
  exit 1
fi
if [[ -f "$TREND_SHOULD_NOT_RUN" ]]; then
  echo "quick-trend should not run when quick-check fails"
  cat "$TREND_SHOULD_NOT_RUN"
  exit 1
fi
if [[ -f "$ALERT_SHOULD_NOT_RUN" ]]; then
  echo "quick-alert should not run when quick-check fails"
  cat "$ALERT_SHOULD_NOT_RUN"
  exit 1
fi

echo "[prod-pilot-cohort-quick-signoff] fail-close when quick-trend fails"
ALERT_SHOULD_NOT_RUN_2="$TMP_DIR/alert_should_not_run_2.log"
FAKE_ALERT_MARK2="$TMP_DIR/fake_alert_mark2.sh"
cat >"$FAKE_ALERT_MARK2" <<'EOF_FAKE_ALERT_MARK2'
#!/usr/bin/env bash
set -euo pipefail
printf 'unexpected-alert %s\n' "$*" >>"${ALERT_SHOULD_NOT_RUN_FILE2:?}"
exit 0
EOF_FAKE_ALERT_MARK2
chmod +x "$FAKE_ALERT_MARK2"

set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
FAKE_TREND_RC=1 \
ALERT_SHOULD_NOT_RUN_FILE2="$ALERT_SHOULD_NOT_RUN_2" \
PROD_PILOT_COHORT_QUICK_CHECK_SCRIPT="$FAKE_CHECK" \
PROD_PILOT_COHORT_QUICK_TREND_SCRIPT="$FAKE_TREND" \
PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT="$FAKE_ALERT_MARK2" \
./scripts/prod_pilot_cohort_quick_signoff.sh \
  --run-report-json /tmp/quick/report.json >/tmp/integration_prod_pilot_cohort_quick_signoff_trend_fail.log 2>&1
trend_fail_rc=$?
set -e
if [[ "$trend_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when quick-trend step fails"
  cat /tmp/integration_prod_pilot_cohort_quick_signoff_trend_fail.log
  exit 1
fi
if [[ -f "$ALERT_SHOULD_NOT_RUN_2" ]]; then
  echo "quick-alert should not run when quick-trend fails"
  cat "$ALERT_SHOULD_NOT_RUN_2"
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

echo "[prod-pilot-cohort-quick-signoff] easy_node forwarding"
FAKE_SIGNOFF="$TMP_DIR/fake_quick_signoff.sh"
SIGNOFF_FORWARD_CAPTURE="$TMP_DIR/signoff_forward_capture.log"
cat >"$FAKE_SIGNOFF" <<'EOF_FAKE_SIGNOFF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SIGNOFF_FORWARD_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_SIGNOFF
chmod +x "$FAKE_SIGNOFF"

PATH="$TMP_BIN:$PATH" \
SIGNOFF_FORWARD_CAPTURE_FILE="$SIGNOFF_FORWARD_CAPTURE" \
PROD_PILOT_COHORT_QUICK_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
./scripts/easy_node.sh prod-pilot-cohort-quick-signoff \
  --run-report-json /tmp/quick/report.json \
  --require-cohort-signoff-policy 0 \
  --require-trend-artifact-policy-match 0 \
  --max-alert-severity OK \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_quick_signoff_easy_node.log 2>&1

if ! rg -q -- '--run-report-json /tmp/quick/report.json' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node quick-signoff forwarding failed: missing --run-report-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-alert-severity OK' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node quick-signoff forwarding failed: missing --max-alert-severity"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-cohort-signoff-policy 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node quick-signoff forwarding failed: missing --require-cohort-signoff-policy"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-trend-artifact-policy-match 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node quick-signoff forwarding failed: missing --require-trend-artifact-policy-match"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node quick-signoff forwarding failed: missing --show-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi

echo "prod pilot cohort quick signoff integration ok"
