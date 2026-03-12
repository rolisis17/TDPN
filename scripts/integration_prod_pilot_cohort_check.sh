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

REPORTS_DIR="$TMP_DIR/cohort_reports"
mkdir -p "$REPORTS_DIR"

TREND_JSON="$REPORTS_DIR/prod_pilot_cohort_trend.json"
ALERT_JSON="$REPORTS_DIR/prod_pilot_cohort_alert.json"
MANIFEST_JSON="$REPORTS_DIR/prod_pilot_cohort_bundle_manifest.json"
SUMMARY_JSON="$REPORTS_DIR/prod_pilot_cohort_summary.json"

cat >"$TREND_JSON" <<'EOF_TREND'
{
  "decision":"GO",
  "go_rate_pct":100,
  "policy":{
    "require_wg_validate_udp_source":1,
    "require_wg_validate_strict_distinct":1,
    "require_wg_soak_diversity_pass":1,
    "min_wg_soak_selection_lines":12,
    "min_wg_soak_entry_operators":2,
    "min_wg_soak_exit_operators":2,
    "min_wg_soak_cross_operator_pairs":2
  }
}
EOF_TREND
cat >"$ALERT_JSON" <<'EOF_ALERT'
{"severity":"OK"}
EOF_ALERT
cat >"$MANIFEST_JSON" <<'EOF_MANIFEST'
{"generated_at":"2026-03-11T00:00:00Z"}
EOF_MANIFEST
cat >"$SUMMARY_JSON" <<EOF_SUMMARY
{
  "status":"ok",
  "failure_step":"",
  "final_rc":0,
  "rounds":{"requested":3,"attempted":3,"passed":3,"failed":0},
  "trend":{"rc":0,"go_rate_pct":"100.00"},
  "alert":{"rc":0,"severity":"OK","policy_violation":false},
  "bundle":{"created":true,"rc":0,"manifest_created":true},
  "policy":{
    "trend_require_wg_validate_udp_source":true,
    "trend_require_wg_validate_strict_distinct":true,
    "trend_require_wg_soak_diversity_pass":true,
    "trend_min_wg_soak_selection_lines":12,
    "trend_min_wg_soak_entry_operators":2,
    "trend_min_wg_soak_exit_operators":2,
    "trend_min_wg_soak_cross_operator_pairs":2
  },
  "artifacts":{
    "trend_summary_json":"$TREND_JSON",
    "bundle_manifest_json":"$MANIFEST_JSON"
  }
}
EOF_SUMMARY

echo "[prod-pilot-cohort-check] baseline pass"
./scripts/prod_pilot_cohort_check.sh \
  --summary-json "$SUMMARY_JSON" >/tmp/integration_prod_pilot_cohort_check_pass.log 2>&1

echo "[prod-pilot-cohort-check] severity policy fail"
BAD_SEVERITY_SUMMARY="$TMP_DIR/summary_bad_severity.json"
jq '.alert.severity="CRITICAL"' "$SUMMARY_JSON" >"$BAD_SEVERITY_SUMMARY"
set +e
./scripts/prod_pilot_cohort_check.sh \
  --summary-json "$BAD_SEVERITY_SUMMARY" \
  --max-alert-severity WARN >/tmp/integration_prod_pilot_cohort_check_bad_severity.log 2>&1
bad_severity_rc=$?
set -e
if [[ "$bad_severity_rc" -eq 0 ]]; then
  echo "expected non-zero rc for severity policy failure"
  cat /tmp/integration_prod_pilot_cohort_check_bad_severity.log
  exit 1
fi
if ! rg -q 'alert severity exceeds policy' /tmp/integration_prod_pilot_cohort_check_bad_severity.log; then
  echo "expected severity policy signal not found"
  cat /tmp/integration_prod_pilot_cohort_check_bad_severity.log
  exit 1
fi

echo "[prod-pilot-cohort-check] trend decision fail"
cat >"$TREND_JSON" <<'EOF_TREND_FAIL'
{
  "decision":"NO-GO",
  "go_rate_pct":66.67,
  "policy":{
    "require_wg_validate_udp_source":1,
    "require_wg_validate_strict_distinct":1,
    "require_wg_soak_diversity_pass":1,
    "min_wg_soak_selection_lines":12,
    "min_wg_soak_entry_operators":2,
    "min_wg_soak_exit_operators":2,
    "min_wg_soak_cross_operator_pairs":2
  }
}
EOF_TREND_FAIL
set +e
./scripts/prod_pilot_cohort_check.sh \
  --summary-json "$SUMMARY_JSON" >/tmp/integration_prod_pilot_cohort_check_bad_trend.log 2>&1
bad_trend_rc=$?
set -e
if [[ "$bad_trend_rc" -eq 0 ]]; then
  echo "expected non-zero rc for trend decision failure"
  cat /tmp/integration_prod_pilot_cohort_check_bad_trend.log
  exit 1
fi
if ! rg -q 'trend decision is not GO' /tmp/integration_prod_pilot_cohort_check_bad_trend.log; then
  echo "expected trend decision failure signal not found"
  cat /tmp/integration_prod_pilot_cohort_check_bad_trend.log
  exit 1
fi

echo "[prod-pilot-cohort-check] strict trend policy fail"
STRICT_POLICY_FAIL_SUMMARY="$TMP_DIR/summary_strict_policy_fail.json"
jq '.policy.trend_require_wg_validate_udp_source=false' "$SUMMARY_JSON" >"$STRICT_POLICY_FAIL_SUMMARY"
set +e
./scripts/prod_pilot_cohort_check.sh \
  --summary-json "$STRICT_POLICY_FAIL_SUMMARY" >/tmp/integration_prod_pilot_cohort_check_strict_policy_fail.log 2>&1
strict_policy_fail_rc=$?
set -e
if [[ "$strict_policy_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc for strict trend policy failure"
  cat /tmp/integration_prod_pilot_cohort_check_strict_policy_fail.log
  exit 1
fi
if ! rg -q 'missing strict wg validate udp-source requirement' /tmp/integration_prod_pilot_cohort_check_strict_policy_fail.log; then
  echo "expected strict trend policy failure signal not found"
  cat /tmp/integration_prod_pilot_cohort_check_strict_policy_fail.log
  exit 1
fi

echo "[prod-pilot-cohort-check] strict trend artifact policy fail"
cat >"$TREND_JSON" <<'EOF_TREND_ARTIFACT_FAIL'
{
  "decision":"GO",
  "go_rate_pct":100,
  "policy":{
    "require_wg_validate_udp_source":0,
    "require_wg_validate_strict_distinct":1,
    "require_wg_soak_diversity_pass":1,
    "min_wg_soak_selection_lines":12,
    "min_wg_soak_entry_operators":2,
    "min_wg_soak_exit_operators":2,
    "min_wg_soak_cross_operator_pairs":2
  }
}
EOF_TREND_ARTIFACT_FAIL
set +e
./scripts/prod_pilot_cohort_check.sh \
  --summary-json "$SUMMARY_JSON" >/tmp/integration_prod_pilot_cohort_check_strict_artifact_policy_fail.log 2>&1
strict_artifact_policy_fail_rc=$?
set -e
if [[ "$strict_artifact_policy_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc for strict trend artifact policy failure"
  cat /tmp/integration_prod_pilot_cohort_check_strict_artifact_policy_fail.log
  exit 1
fi
if ! rg -q 'trend summary policy missing strict wg validate udp-source requirement' /tmp/integration_prod_pilot_cohort_check_strict_artifact_policy_fail.log; then
  echo "expected strict trend artifact policy failure signal not found"
  cat /tmp/integration_prod_pilot_cohort_check_strict_artifact_policy_fail.log
  exit 1
fi

cat >"$TREND_JSON" <<'EOF_TREND'
{
  "decision":"GO",
  "go_rate_pct":100,
  "policy":{
    "require_wg_validate_udp_source":1,
    "require_wg_validate_strict_distinct":1,
    "require_wg_soak_diversity_pass":1,
    "min_wg_soak_selection_lines":12,
    "min_wg_soak_entry_operators":2,
    "min_wg_soak_exit_operators":2,
    "min_wg_soak_cross_operator_pairs":2
  }
}
EOF_TREND

echo "[prod-pilot-cohort-check] incident snapshot policy fail on failed round"
FAIL_ROUND_REPORT="$REPORTS_DIR/round_1/prod_bundle_run_report.json"
mkdir -p "$(dirname "$FAIL_ROUND_REPORT")"
cat >"$FAIL_ROUND_REPORT" <<'EOF_FAIL_ROUND_REPORT'
{
  "status":"fail",
  "final_rc":7,
  "incident_snapshot":{
    "enabled":false,
    "status":"fail",
    "bundle_dir":"",
    "bundle_tar":""
  }
}
EOF_FAIL_ROUND_REPORT

INCIDENT_FAIL_SUMMARY="$TMP_DIR/summary_incident_fail.json"
jq \
  --arg rr "$FAIL_ROUND_REPORT" \
  '.rounds.failed=1
   | .rounds.passed=2
   | .run_reports=[$rr]' "$SUMMARY_JSON" >"$INCIDENT_FAIL_SUMMARY"

set +e
./scripts/prod_pilot_cohort_check.sh \
  --summary-json "$INCIDENT_FAIL_SUMMARY" \
  --require-all-rounds-ok 0 \
  --max-round-failures 1 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 >/tmp/integration_prod_pilot_cohort_check_incident_fail.log 2>&1
incident_fail_rc=$?
set -e
if [[ "$incident_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc for incident snapshot policy failure"
  cat /tmp/integration_prod_pilot_cohort_check_incident_fail.log
  exit 1
fi
if ! rg -q 'incident snapshot' /tmp/integration_prod_pilot_cohort_check_incident_fail.log; then
  echo "expected incident snapshot policy signal not found"
  cat /tmp/integration_prod_pilot_cohort_check_incident_fail.log
  exit 1
fi

echo "[prod-pilot-cohort-check] incident snapshot policy pass on failed round with artifacts"
INCIDENT_BUNDLE_DIR="$REPORTS_DIR/round_2/incident_snapshot"
INCIDENT_BUNDLE_TAR="$REPORTS_DIR/round_2/incident_snapshot.tar.gz"
mkdir -p "$INCIDENT_BUNDLE_DIR"
printf 'snapshot bundle\n' >"$INCIDENT_BUNDLE_DIR/manifest.txt"
printf 'snapshot tar placeholder\n' >"$INCIDENT_BUNDLE_TAR"

PASS_ROUND_REPORT="$REPORTS_DIR/round_2/prod_bundle_run_report.json"
mkdir -p "$(dirname "$PASS_ROUND_REPORT")"
cat >"$PASS_ROUND_REPORT" <<EOF_PASS_ROUND_REPORT
{
  "status":"fail",
  "final_rc":9,
  "incident_snapshot":{
    "enabled":true,
    "status":"ok",
    "bundle_dir":"$INCIDENT_BUNDLE_DIR",
    "bundle_tar":"$INCIDENT_BUNDLE_TAR"
  }
}
EOF_PASS_ROUND_REPORT

INCIDENT_PASS_SUMMARY="$TMP_DIR/summary_incident_pass.json"
jq \
  --arg rr "$PASS_ROUND_REPORT" \
  '.rounds.failed=1
   | .rounds.passed=2
   | .run_reports=[$rr]' "$SUMMARY_JSON" >"$INCIDENT_PASS_SUMMARY"

./scripts/prod_pilot_cohort_check.sh \
  --summary-json "$INCIDENT_PASS_SUMMARY" \
  --require-all-rounds-ok 0 \
  --max-round-failures 1 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 >/tmp/integration_prod_pilot_cohort_check_incident_pass.log 2>&1

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

echo "[prod-pilot-cohort-check] easy_node forwarding"
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
PROD_PILOT_COHORT_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/easy_node.sh prod-pilot-cohort-check \
  --summary-json /tmp/cohort/summary.json \
  --max-alert-severity OK \
  --require-trend-artifact-policy-match 1 \
  --require-trend-wg-validate-udp-source 1 \
  --min-trend-wg-soak-selection-lines 12 \
  --require-incident-snapshot-on-fail 0 \
  --require-incident-snapshot-artifacts 0 \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_check_easy_node.log 2>&1

if ! rg -q -- '--summary-json /tmp/cohort/summary.json' "$CHECK_CAPTURE"; then
  echo "easy_node cohort check forwarding failed: missing --summary-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-alert-severity OK' "$CHECK_CAPTURE"; then
  echo "easy_node cohort check forwarding failed: missing --max-alert-severity"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-trend-wg-validate-udp-source 1' "$CHECK_CAPTURE"; then
  echo "easy_node cohort check forwarding failed: missing --require-trend-wg-validate-udp-source"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-trend-artifact-policy-match 1' "$CHECK_CAPTURE"; then
  echo "easy_node cohort check forwarding failed: missing --require-trend-artifact-policy-match"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-trend-wg-soak-selection-lines 12' "$CHECK_CAPTURE"; then
  echo "easy_node cohort check forwarding failed: missing --min-trend-wg-soak-selection-lines"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 0' "$CHECK_CAPTURE"; then
  echo "easy_node cohort check forwarding failed: missing --require-incident-snapshot-on-fail"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 0' "$CHECK_CAPTURE"; then
  echo "easy_node cohort check forwarding failed: missing --require-incident-snapshot-artifacts"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$CHECK_CAPTURE"; then
  echo "easy_node cohort check forwarding failed: missing --show-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi

echo "prod pilot cohort check integration check ok"
