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

PILOT_CAPTURE="$TMP_DIR/pilot_capture.log"
TREND_CAPTURE="$TMP_DIR/trend_capture.log"
ALERT_CAPTURE="$TMP_DIR/alert_capture.log"
PRE_READINESS_CAPTURE="$TMP_DIR/pre_readiness_capture.log"
PILOT_COUNTER="$TMP_DIR/pilot_counter.txt"

FAKE_PILOT="$TMP_DIR/fake_prod_pilot_runbook.sh"
cat >"$FAKE_PILOT" <<'EOF_FAKE_PILOT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${PILOT_CAPTURE_FILE:?}"
count=0
if [[ -f "${PILOT_COUNTER_FILE:?}" ]]; then
  count="$(cat "${PILOT_COUNTER_FILE:?}")"
fi
count=$((count + 1))
printf '%s' "$count" >"${PILOT_COUNTER_FILE:?}"

run_report_json=""
for ((i = 1; i <= $#; i++)); do
  arg="${!i}"
  if [[ "$arg" == "--run-report-json" ]]; then
    j=$((i + 1))
    if ((j <= $#)); then
      run_report_json="${!j}"
    fi
    break
  fi
done
if [[ -n "$run_report_json" ]]; then
  mkdir -p "$(dirname "$run_report_json")"
  cat >"$run_report_json" <<'EOF_RUN_REPORT'
{
  "status": "ok",
  "steps": {
    "control_validate": "ok",
    "control_soak": "ok",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "ok"
  }
}
EOF_RUN_REPORT
fi

fail_on_call="${FAKE_PILOT_FAIL_ON_CALL:-0}"
if [[ "$fail_on_call" =~ ^[0-9]+$ ]] && ((fail_on_call > 0)) && ((count == fail_on_call)); then
  exit "${FAKE_PILOT_FAIL_RC:-19}"
fi
exit 0
EOF_FAKE_PILOT
chmod +x "$FAKE_PILOT"

FAKE_TREND="$TMP_DIR/fake_prod_gate_slo_trend.sh"
cat >"$FAKE_TREND" <<'EOF_FAKE_TREND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${TREND_CAPTURE_FILE:?}"
summary_json=""
for ((i = 1; i <= $#; i++)); do
  arg="${!i}"
  if [[ "$arg" == "--summary-json" ]]; then
    j=$((i + 1))
    if ((j <= $#)); then
      summary_json="${!j}"
    fi
    break
  fi
done
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_TREND'
{
  "decision": "go",
  "go_rate_pct": 100,
  "total_reports": 3,
  "go_reports": 3,
  "no_go_reports": 0
}
EOF_TREND
fi
exit "${FAKE_TREND_RC:-0}"
EOF_FAKE_TREND
chmod +x "$FAKE_TREND"

FAKE_ALERT="$TMP_DIR/fake_prod_gate_slo_alert.sh"
cat >"$FAKE_ALERT" <<'EOF_FAKE_ALERT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${ALERT_CAPTURE_FILE:?}"
summary_json=""
for ((i = 1; i <= $#; i++)); do
  arg="${!i}"
  if [[ "$arg" == "--summary-json" ]]; then
    j=$((i + 1))
    if ((j <= $#)); then
      summary_json="${!j}"
    fi
    break
  fi
done
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  severity="${FAKE_ALERT_SEVERITY:-OK}"
  cat >"$summary_json" <<'EOF_ALERT'
{
  "severity": "__SEVERITY__"
}
EOF_ALERT
  sed -i "s/__SEVERITY__/${severity}/g" "$summary_json"
fi
exit "${FAKE_ALERT_RC:-0}"
EOF_FAKE_ALERT
chmod +x "$FAKE_ALERT"

FAKE_PRE_READINESS="$TMP_DIR/fake_pre_real_host_readiness.sh"
cat >"$FAKE_PRE_READINESS" <<'EOF_FAKE_PRE_READINESS'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${PRE_READINESS_CAPTURE_FILE:?}"
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
  echo "missing --summary-json"
  exit 2
fi
mkdir -p "$(dirname "$summary_json")"
status="${FAKE_PRE_READINESS_STATUS:-pass}"
ready="${FAKE_PRE_READINESS_READY:-true}"
cat >"$summary_json" <<EOF_PRE
{
  "status": "$status",
  "machine_c_smoke_gate": {
    "ready": $ready,
    "blockers": [],
    "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --pre-real-host-readiness 1"
  },
  "manual_validation_report": {
    "readiness_status": "NOT_READY",
    "summary_json": "/tmp/fake_manual_validation_readiness_summary.json",
    "report_md": "/tmp/fake_manual_validation_readiness_report.md"
  }
}
EOF_PRE
exit "${FAKE_PRE_READINESS_RC:-0}"
EOF_FAKE_PRE_READINESS
chmod +x "$FAKE_PRE_READINESS"

echo "[prod-pilot-cohort] success path"
SUCCESS_SUMMARY="$TMP_DIR/success_summary.json"
SUCCESS_REPORTS_DIR="$TMP_DIR/success_reports"
: >"$PILOT_CAPTURE"
: >"$TREND_CAPTURE"
: >"$ALERT_CAPTURE"
: >"$PRE_READINESS_CAPTURE"
rm -f "$PILOT_COUNTER"

PILOT_CAPTURE_FILE="$PILOT_CAPTURE" \
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
PRE_READINESS_CAPTURE_FILE="$PRE_READINESS_CAPTURE" \
PILOT_COUNTER_FILE="$PILOT_COUNTER" \
PROD_PILOT_RUNBOOK_SCRIPT="$FAKE_PILOT" \
PROD_GATE_SLO_TREND_SCRIPT="$FAKE_TREND" \
PROD_GATE_SLO_ALERT_SCRIPT="$FAKE_ALERT" \
PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_READINESS" \
./scripts/prod_pilot_cohort_runbook.sh \
  --rounds 3 \
  --pause-sec 0 \
  --continue-on-fail 0 \
  --require-all-rounds-ok 1 \
  --reports-dir "$SUCCESS_REPORTS_DIR" \
  --summary-json "$SUCCESS_SUMMARY" \
  --trend-min-go-rate-pct 95 \
  -- \
  --bootstrap-directory https://dir-a:8081 \
  --subject pilot-client >/tmp/integration_prod_pilot_cohort_runbook_success.log 2>&1

if [[ ! -f "$SUCCESS_SUMMARY" ]]; then
  echo "prod-pilot-cohort success path did not produce summary json"
  cat /tmp/integration_prod_pilot_cohort_runbook_success.log
  exit 1
fi
if [[ "$(jq -r '.status' "$SUCCESS_SUMMARY")" != "ok" ]]; then
  echo "prod-pilot-cohort success summary has unexpected status"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rounds.requested' "$SUCCESS_SUMMARY")" != "3" ]]; then
  echo "prod-pilot-cohort success summary has unexpected rounds.requested"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rounds.passed' "$SUCCESS_SUMMARY")" != "3" ]]; then
  echo "prod-pilot-cohort success summary has unexpected rounds.passed"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rounds.failed' "$SUCCESS_SUMMARY")" != "0" ]]; then
  echo "prod-pilot-cohort success summary has unexpected rounds.failed"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.pre_real_host_readiness.status' "$SUCCESS_SUMMARY")" != "pass" ]]; then
  echo "prod-pilot-cohort success summary expected pre_real_host_readiness.status=pass"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.pre_real_host_readiness.machine_c_smoke_ready' "$SUCCESS_SUMMARY")" != "true" ]]; then
  echo "prod-pilot-cohort success summary expected pre_real_host_readiness.machine_c_smoke_ready=true"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.bundle.created' "$SUCCESS_SUMMARY")" != "true" ]]; then
  echo "prod-pilot-cohort success summary expected bundle.created=true"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
bundle_tar="$(jq -r '.artifacts.bundle_tar' "$SUCCESS_SUMMARY")"
bundle_sha_file="$(jq -r '.artifacts.bundle_sha256_file' "$SUCCESS_SUMMARY")"
bundle_manifest="$(jq -r '.artifacts.bundle_manifest_json' "$SUCCESS_SUMMARY")"
if [[ ! -f "$bundle_tar" ]]; then
  echo "prod-pilot-cohort success summary bundle tar missing: $bundle_tar"
  ls -la "$SUCCESS_REPORTS_DIR" || true
  exit 1
fi
if [[ ! -f "$bundle_sha_file" ]]; then
  echo "prod-pilot-cohort success summary bundle sha256 sidecar missing: $bundle_sha_file"
  ls -la "$(dirname "$bundle_tar")" || true
  exit 1
fi
if [[ ! -f "$bundle_manifest" ]]; then
  echo "prod-pilot-cohort success summary bundle manifest missing: $bundle_manifest"
  ls -la "$SUCCESS_REPORTS_DIR" || true
  exit 1
fi
if [[ "$(rg -c '^--summary-json ' "$PRE_READINESS_CAPTURE")" -ne 1 ]]; then
  echo "prod-pilot-cohort success path expected one pre-real-host readiness invocation"
  cat "$PRE_READINESS_CAPTURE"
  exit 1
fi
if ! rg -q -- '--bootstrap-directory https://dir-a:8081' "$PILOT_CAPTURE"; then
  echo "prod-pilot-cohort success path did not forward pilot args"
  cat "$PILOT_CAPTURE"
  exit 1
fi
if [[ "$(rg -c -- '--pre-real-host-readiness 0' "$PILOT_CAPTURE")" -ne 3 ]]; then
  echo "prod-pilot-cohort success path expected inner pilot rounds to disable duplicate pre-real-host readiness"
  cat "$PILOT_CAPTURE"
  exit 1
fi
if [[ "$(rg -c '^--bundle-dir ' "$PILOT_CAPTURE")" -ne 3 ]]; then
  echo "prod-pilot-cohort success path expected 3 pilot rounds"
  cat "$PILOT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--run-report-list ' "$TREND_CAPTURE"; then
  echo "prod-pilot-cohort success path missing trend run-report list"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-udp-source 1' "$TREND_CAPTURE"; then
  echo "prod-pilot-cohort success path missing trend --require-wg-validate-udp-source 1"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-strict-distinct 1' "$TREND_CAPTURE"; then
  echo "prod-pilot-cohort success path missing trend --require-wg-validate-strict-distinct 1"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-soak-diversity-pass 1' "$TREND_CAPTURE"; then
  echo "prod-pilot-cohort success path missing trend --require-wg-soak-diversity-pass 1"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-selection-lines 12' "$TREND_CAPTURE"; then
  echo "prod-pilot-cohort success path missing trend --min-wg-soak-selection-lines 12"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-entry-operators 2' "$TREND_CAPTURE"; then
  echo "prod-pilot-cohort success path missing trend --min-wg-soak-entry-operators 2"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-exit-operators 2' "$TREND_CAPTURE"; then
  echo "prod-pilot-cohort success path missing trend --min-wg-soak-exit-operators 2"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-cross-operator-pairs 2' "$TREND_CAPTURE"; then
  echo "prod-pilot-cohort success path missing trend --min-wg-soak-cross-operator-pairs 2"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--trend-summary-json ' "$ALERT_CAPTURE"; then
  echo "prod-pilot-cohort success path missing alert trend-summary-json input"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-udp-source 1' "$ALERT_CAPTURE"; then
  echo "prod-pilot-cohort success path missing alert --require-wg-validate-udp-source 1"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-strict-distinct 1' "$ALERT_CAPTURE"; then
  echo "prod-pilot-cohort success path missing alert --require-wg-validate-strict-distinct 1"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-soak-diversity-pass 1' "$ALERT_CAPTURE"; then
  echo "prod-pilot-cohort success path missing alert --require-wg-soak-diversity-pass 1"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-selection-lines 12' "$ALERT_CAPTURE"; then
  echo "prod-pilot-cohort success path missing alert --min-wg-soak-selection-lines 12"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-entry-operators 2' "$ALERT_CAPTURE"; then
  echo "prod-pilot-cohort success path missing alert --min-wg-soak-entry-operators 2"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-exit-operators 2' "$ALERT_CAPTURE"; then
  echo "prod-pilot-cohort success path missing alert --min-wg-soak-exit-operators 2"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-cross-operator-pairs 2' "$ALERT_CAPTURE"; then
  echo "prod-pilot-cohort success path missing alert --min-wg-soak-cross-operator-pairs 2"
  cat "$ALERT_CAPTURE"
  exit 1
fi

echo "[prod-pilot-cohort] alert severity gate fail path"
ALERT_FAIL_SUMMARY="$TMP_DIR/alert_fail_summary.json"
ALERT_FAIL_REPORTS_DIR="$TMP_DIR/alert_fail_reports"
: >"$PILOT_CAPTURE"
: >"$TREND_CAPTURE"
: >"$ALERT_CAPTURE"
: >"$PRE_READINESS_CAPTURE"
rm -f "$PILOT_COUNTER"
set +e
PILOT_CAPTURE_FILE="$PILOT_CAPTURE" \
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
PRE_READINESS_CAPTURE_FILE="$PRE_READINESS_CAPTURE" \
PILOT_COUNTER_FILE="$PILOT_COUNTER" \
PROD_PILOT_RUNBOOK_SCRIPT="$FAKE_PILOT" \
PROD_GATE_SLO_TREND_SCRIPT="$FAKE_TREND" \
PROD_GATE_SLO_ALERT_SCRIPT="$FAKE_ALERT" \
PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_READINESS" \
FAKE_ALERT_SEVERITY=CRITICAL \
./scripts/prod_pilot_cohort_runbook.sh \
  --rounds 2 \
  --pause-sec 0 \
  --continue-on-fail 0 \
  --require-all-rounds-ok 1 \
  --max-alert-severity WARN \
  --reports-dir "$ALERT_FAIL_REPORTS_DIR" \
  --summary-json "$ALERT_FAIL_SUMMARY" >/tmp/integration_prod_pilot_cohort_runbook_alert_fail.log 2>&1
alert_fail_rc=$?
set -e
if [[ "$alert_fail_rc" -ne 24 ]]; then
  echo "prod-pilot-cohort alert severity gate returned unexpected rc=$alert_fail_rc (expected 24)"
  cat /tmp/integration_prod_pilot_cohort_runbook_alert_fail.log
  exit 1
fi
if [[ "$(jq -r '.status' "$ALERT_FAIL_SUMMARY")" != "fail" ]]; then
  echo "prod-pilot-cohort alert fail summary has unexpected status"
  cat "$ALERT_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.failure_step' "$ALERT_FAIL_SUMMARY")" != "alert_severity_policy" ]]; then
  echo "prod-pilot-cohort alert fail summary has unexpected failure_step"
  cat "$ALERT_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.alert.policy_violation' "$ALERT_FAIL_SUMMARY")" != "true" ]]; then
  echo "prod-pilot-cohort alert fail summary expected alert.policy_violation=true"
  cat "$ALERT_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.policy.max_alert_severity' "$ALERT_FAIL_SUMMARY")" != "WARN" ]]; then
  echo "prod-pilot-cohort alert fail summary expected policy.max_alert_severity=WARN"
  cat "$ALERT_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.bundle.created' "$ALERT_FAIL_SUMMARY")" != "true" ]]; then
  echo "prod-pilot-cohort alert fail summary expected bundle.created=true"
  cat "$ALERT_FAIL_SUMMARY"
  exit 1
fi

echo "[prod-pilot-cohort] stop-early fail path"
FAIL_SUMMARY="$TMP_DIR/fail_summary.json"
FAIL_REPORTS_DIR="$TMP_DIR/fail_reports"
: >"$PILOT_CAPTURE"
: >"$TREND_CAPTURE"
: >"$ALERT_CAPTURE"
: >"$PRE_READINESS_CAPTURE"
rm -f "$PILOT_COUNTER"
set +e
PILOT_CAPTURE_FILE="$PILOT_CAPTURE" \
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
PRE_READINESS_CAPTURE_FILE="$PRE_READINESS_CAPTURE" \
PILOT_COUNTER_FILE="$PILOT_COUNTER" \
PROD_PILOT_RUNBOOK_SCRIPT="$FAKE_PILOT" \
FAKE_PILOT_FAIL_ON_CALL=2 \
FAKE_PILOT_FAIL_RC=17 \
PROD_GATE_SLO_TREND_SCRIPT="$FAKE_TREND" \
PROD_GATE_SLO_ALERT_SCRIPT="$FAKE_ALERT" \
PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_READINESS" \
./scripts/prod_pilot_cohort_runbook.sh \
  --rounds 4 \
  --pause-sec 0 \
  --continue-on-fail 0 \
  --require-all-rounds-ok 1 \
  --reports-dir "$FAIL_REPORTS_DIR" \
  --summary-json "$FAIL_SUMMARY" >/tmp/integration_prod_pilot_cohort_runbook_fail.log 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 17 ]]; then
  echo "prod-pilot-cohort fail path returned unexpected rc=$fail_rc (expected 17)"
  cat /tmp/integration_prod_pilot_cohort_runbook_fail.log
  exit 1
fi
if [[ "$(jq -r '.status' "$FAIL_SUMMARY")" != "fail" ]]; then
  echo "prod-pilot-cohort fail summary has unexpected status"
  cat "$FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.failure_step' "$FAIL_SUMMARY")" != "pilot_rounds" ]]; then
  echo "prod-pilot-cohort fail summary has unexpected failure_step"
  cat "$FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rounds.attempted' "$FAIL_SUMMARY")" != "2" ]]; then
  echo "prod-pilot-cohort fail summary has unexpected rounds.attempted"
  cat "$FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rounds.stopped_early' "$FAIL_SUMMARY")" != "true" ]]; then
  echo "prod-pilot-cohort fail summary expected stopped_early=true"
  cat "$FAIL_SUMMARY"
  exit 1
fi

echo "[prod-pilot-cohort] pre-real-host readiness fail path"
PRE_FAIL_SUMMARY="$TMP_DIR/pre_fail_summary.json"
PRE_FAIL_REPORTS_DIR="$TMP_DIR/pre_fail_reports"
: >"$PILOT_CAPTURE"
: >"$TREND_CAPTURE"
: >"$ALERT_CAPTURE"
: >"$PRE_READINESS_CAPTURE"
rm -f "$PILOT_COUNTER"
set +e
PILOT_CAPTURE_FILE="$PILOT_CAPTURE" \
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
PRE_READINESS_CAPTURE_FILE="$PRE_READINESS_CAPTURE" \
PILOT_COUNTER_FILE="$PILOT_COUNTER" \
PROD_PILOT_RUNBOOK_SCRIPT="$FAKE_PILOT" \
PROD_GATE_SLO_TREND_SCRIPT="$FAKE_TREND" \
PROD_GATE_SLO_ALERT_SCRIPT="$FAKE_ALERT" \
PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_READINESS" \
FAKE_PRE_READINESS_STATUS=fail \
FAKE_PRE_READINESS_READY=false \
FAKE_PRE_READINESS_RC=31 \
./scripts/prod_pilot_cohort_runbook.sh \
  --rounds 4 \
  --pause-sec 0 \
  --continue-on-fail 0 \
  --require-all-rounds-ok 1 \
  --reports-dir "$PRE_FAIL_REPORTS_DIR" \
  --summary-json "$PRE_FAIL_SUMMARY" >/tmp/integration_prod_pilot_cohort_runbook_pre_fail.log 2>&1
pre_fail_rc=$?
set -e
if [[ "$pre_fail_rc" -ne 31 ]]; then
  echo "prod-pilot-cohort pre-real-host readiness fail path returned unexpected rc=$pre_fail_rc (expected 31)"
  cat /tmp/integration_prod_pilot_cohort_runbook_pre_fail.log
  exit 1
fi
if [[ "$(jq -r '.failure_step' "$PRE_FAIL_SUMMARY")" != "pre_real_host_readiness" ]]; then
  echo "prod-pilot-cohort pre-real-host readiness fail summary has unexpected failure_step"
  cat "$PRE_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rounds.attempted' "$PRE_FAIL_SUMMARY")" != "0" ]]; then
  echo "prod-pilot-cohort pre-real-host readiness fail summary expected rounds.attempted=0"
  cat "$PRE_FAIL_SUMMARY"
  exit 1
fi
if [[ -s "$PILOT_CAPTURE" ]]; then
  echo "prod-pilot-cohort pre-real-host readiness fail path should not run pilot rounds"
  cat "$PILOT_CAPTURE"
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

FAKE_COHORT_RUNBOOK="$TMP_DIR/fake_prod_pilot_cohort_runbook.sh"
DISPATCH_CAPTURE="$TMP_DIR/dispatch_capture.log"
cat >"$FAKE_COHORT_RUNBOOK" <<'EOF_FAKE_COHORT_RUNBOOK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DISPATCH_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_COHORT_RUNBOOK
chmod +x "$FAKE_COHORT_RUNBOOK"

echo "[prod-pilot-cohort] easy_node dispatch"
PATH="$TMP_BIN:$PATH" \
DISPATCH_CAPTURE_FILE="$DISPATCH_CAPTURE" \
PROD_PILOT_COHORT_RUNBOOK_SCRIPT="$FAKE_COHORT_RUNBOOK" \
./scripts/easy_node.sh prod-pilot-cohort-runbook \
  --rounds 7 \
  --pause-sec 2 \
  --max-alert-severity CRITICAL >/tmp/integration_prod_pilot_cohort_runbook_dispatch.log 2>&1

if ! rg -q -- '--rounds 7' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-runbook did not forward --rounds"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--pause-sec 2' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-runbook did not forward --pause-sec"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-alert-severity CRITICAL' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-runbook did not forward --max-alert-severity"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi

echo "prod pilot cohort runbook integration check ok"
