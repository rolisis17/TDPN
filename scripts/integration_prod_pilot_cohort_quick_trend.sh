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

REPORTS_DIR="$TMP_DIR/reports"
mkdir -p "$REPORTS_DIR/run_a" "$REPORTS_DIR/run_b" "$REPORTS_DIR/run_c"

cat >"$REPORTS_DIR/run_a/prod_pilot_cohort_summary.json" <<'EOF_SUM_A'
{"status":"ok"}
EOF_SUM_A
cat >"$REPORTS_DIR/run_b/prod_pilot_cohort_summary.json" <<'EOF_SUM_B'
{"status":"ok"}
EOF_SUM_B
cat >"$REPORTS_DIR/run_c/prod_pilot_cohort_summary.json" <<'EOF_SUM_C'
{"status":"ok"}
EOF_SUM_C

cat >"$REPORTS_DIR/run_a/prod_pilot_cohort_quick_report.json" <<EOF_RUN_A
{
  "started_at": "2026-03-10T10:00:00Z",
  "finished_at": "2026-03-10T10:01:00Z",
  "duration_sec": 60,
  "status": "ok",
  "failure_step": "",
  "final_rc": 0,
  "runbook": {"rc": 0},
  "signoff": {"attempted": true, "rc": 0},
  "artifacts": {"summary_json": "$REPORTS_DIR/run_a/prod_pilot_cohort_summary.json"}
}
EOF_RUN_A

cat >"$REPORTS_DIR/run_b/prod_pilot_cohort_quick_report.json" <<EOF_RUN_B
{
  "started_at": "2026-03-10T11:00:00Z",
  "finished_at": "2026-03-10T11:01:30Z",
  "duration_sec": 90,
  "status": "fail",
  "failure_step": "signoff",
  "final_rc": 3,
  "runbook": {"rc": 0},
  "signoff": {"attempted": true, "rc": 3},
  "artifacts": {"summary_json": "$REPORTS_DIR/run_b/prod_pilot_cohort_summary.json"}
}
EOF_RUN_B

cat >"$REPORTS_DIR/run_c/prod_pilot_cohort_quick_report.json" <<EOF_RUN_C
{
  "started_at": "2026-03-10T12:00:00Z",
  "finished_at": "2026-03-10T12:00:40Z",
  "duration_sec": 40,
  "status": "ok",
  "failure_step": "",
  "final_rc": 0,
  "runbook": {"rc": 0},
  "signoff": {"attempted": true, "rc": 0},
  "artifacts": {"summary_json": "$REPORTS_DIR/run_c/prod_pilot_cohort_summary.json"}
}
EOF_RUN_C

echo "[prod-pilot-cohort-quick-trend] baseline trend (2 GO, 1 NO-GO)"
SUMMARY_JSON="$TMP_DIR/quick_trend_summary.json"
./scripts/prod_pilot_cohort_quick_trend.sh \
  --reports-dir "$REPORTS_DIR" \
  --max-reports 3 \
  --summary-json "$SUMMARY_JSON" \
  --print-summary-json 1 \
  --show-details 0 \
  --show-top-reasons 3 >/tmp/integration_prod_pilot_cohort_quick_trend_baseline.log 2>&1

if ! rg -q '\[prod-pilot-cohort-quick-trend\] reports_total=3 go=2 no_go=1 go_rate_pct=66.67' /tmp/integration_prod_pilot_cohort_quick_trend_baseline.log; then
  echo "expected baseline quick trend summary not found"
  cat /tmp/integration_prod_pilot_cohort_quick_trend_baseline.log
  exit 1
fi
if ! rg -q 'reason=signoff rc is non-zero' /tmp/integration_prod_pilot_cohort_quick_trend_baseline.log; then
  echo "expected top no-go reason not found"
  cat /tmp/integration_prod_pilot_cohort_quick_trend_baseline.log
  exit 1
fi
if [[ ! -f "$SUMMARY_JSON" ]]; then
  echo "expected quick trend summary JSON output file not found"
  ls -la "$TMP_DIR"
  cat /tmp/integration_prod_pilot_cohort_quick_trend_baseline.log
  exit 1
fi
if ! jq -e '.reports_total == 3 and .go == 2 and .no_go == 1 and .decision == "GO"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "quick trend summary JSON missing expected baseline aggregate fields"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! rg -q '\[prod-pilot-cohort-quick-trend\] summary_json_payload:' /tmp/integration_prod_pilot_cohort_quick_trend_baseline.log; then
  echo "expected printed summary payload marker not found"
  cat /tmp/integration_prod_pilot_cohort_quick_trend_baseline.log
  exit 1
fi

echo "[prod-pilot-cohort-quick-trend] since-hours filter"
touch -t 202001010101 "$REPORTS_DIR/run_a/prod_pilot_cohort_quick_report.json" "$REPORTS_DIR/run_b/prod_pilot_cohort_quick_report.json"
./scripts/prod_pilot_cohort_quick_trend.sh \
  --reports-dir "$REPORTS_DIR" \
  --max-reports 10 \
  --since-hours 1 \
  --show-details 0 >/tmp/integration_prod_pilot_cohort_quick_trend_since_hours.log 2>&1

if ! rg -q '\[prod-pilot-cohort-quick-trend\] reports_total=1 go=1 no_go=0' /tmp/integration_prod_pilot_cohort_quick_trend_since_hours.log; then
  echo "expected since-hours filtered aggregate not found"
  cat /tmp/integration_prod_pilot_cohort_quick_trend_since_hours.log
  exit 1
fi

echo "[prod-pilot-cohort-quick-trend] fail-close on any NO-GO"
set +e
./scripts/prod_pilot_cohort_quick_trend.sh \
  --reports-dir "$REPORTS_DIR" \
  --max-reports 3 \
  --fail-on-any-no-go 1 \
  --show-details 0 >/tmp/integration_prod_pilot_cohort_quick_trend_fail_any.log 2>&1
fail_any_rc=$?
set -e
if [[ "$fail_any_rc" -eq 0 ]]; then
  echo "expected non-zero rc when --fail-on-any-no-go=1 and a NO-GO exists"
  cat /tmp/integration_prod_pilot_cohort_quick_trend_fail_any.log
  exit 1
fi
if ! rg -q '\[prod-pilot-cohort-quick-trend\] trend_decision=NO-GO' /tmp/integration_prod_pilot_cohort_quick_trend_fail_any.log; then
  echo "expected NO-GO trend decision in fail-on-any output"
  cat /tmp/integration_prod_pilot_cohort_quick_trend_fail_any.log
  exit 1
fi

echo "[prod-pilot-cohort-quick-trend] fail-close on minimum GO rate"
set +e
./scripts/prod_pilot_cohort_quick_trend.sh \
  --reports-dir "$REPORTS_DIR" \
  --max-reports 3 \
  --min-go-rate-pct 70 \
  --show-details 0 >/tmp/integration_prod_pilot_cohort_quick_trend_fail_rate.log 2>&1
fail_rate_rc=$?
set -e
if [[ "$fail_rate_rc" -eq 0 ]]; then
  echo "expected non-zero rc when GO rate is below --min-go-rate-pct"
  cat /tmp/integration_prod_pilot_cohort_quick_trend_fail_rate.log
  exit 1
fi
if ! rg -q 'go_rate_pct=66.67' /tmp/integration_prod_pilot_cohort_quick_trend_fail_rate.log; then
  echo "expected GO rate output not found"
  cat /tmp/integration_prod_pilot_cohort_quick_trend_fail_rate.log
  exit 1
fi

echo "[prod-pilot-cohort-quick-trend] strict cohort-signoff policy forwarding"
FAKE_QUICK_CHECK="$TMP_DIR/fake_quick_check_for_trend.sh"
CHECK_CAPTURE="$TMP_DIR/quick_check_trend_capture.log"
cat >"$FAKE_QUICK_CHECK" <<'EOF_FAKE_QUICK_CHECK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CHECK_CAPTURE_FILE:?}"
echo "[prod-pilot-cohort-quick-check] run_report_json=${1:-unknown}"
echo "[prod-pilot-cohort-quick-check] decision=GO status=ok runbook_rc=0 signoff_attempted=true signoff_rc=0 duration_sec=1"
echo "[prod-pilot-cohort-quick-check] ok"
exit 0
EOF_FAKE_QUICK_CHECK
chmod +x "$FAKE_QUICK_CHECK"

CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
PROD_PILOT_COHORT_QUICK_CHECK_SCRIPT="$FAKE_QUICK_CHECK" \
./scripts/prod_pilot_cohort_quick_trend.sh \
  --reports-dir "$REPORTS_DIR" \
  --max-reports 1 \
  --require-cohort-signoff-policy 1 \
  --show-details 0 >/tmp/integration_prod_pilot_cohort_quick_trend_cohort_policy.log 2>&1

if ! rg -q -- '--require-cohort-signoff-policy 1' "$CHECK_CAPTURE"; then
  echo "quick-trend forwarding failed: missing --require-cohort-signoff-policy 1 to quick-check"
  cat "$CHECK_CAPTURE"
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

echo "[prod-pilot-cohort-quick-trend] easy_node forwarding"
FAKE_TREND="$TMP_DIR/fake_quick_trend.sh"
CAPTURE="$TMP_DIR/quick_trend_args.log"
cat >"$FAKE_TREND" <<'EOF_FAKE_TREND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CAPTURE_FILE:?}"
exit 0
EOF_FAKE_TREND
chmod +x "$FAKE_TREND"

PATH="$TMP_BIN:$PATH" \
CAPTURE_FILE="$CAPTURE" \
PROD_PILOT_COHORT_QUICK_TREND_SCRIPT="$FAKE_TREND" \
./scripts/easy_node.sh prod-pilot-cohort-quick-trend \
  --reports-dir /tmp/reports \
  --max-reports 10 \
  --since-hours 24 \
  --require-cohort-signoff-policy 1 \
  --summary-json /tmp/quick_trend.json \
  --print-summary-json 1 \
  --fail-on-any-no-go 1 \
  --min-go-rate-pct 95 \
  --show-top-reasons 7 >/tmp/integration_prod_pilot_cohort_quick_trend_easy_node.log 2>&1

if ! rg -q -- '--reports-dir /tmp/reports' "$CAPTURE"; then
  echo "easy_node quick-trend forwarding failed: missing --reports-dir"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--fail-on-any-no-go 1' "$CAPTURE"; then
  echo "easy_node quick-trend forwarding failed: missing --fail-on-any-no-go"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-go-rate-pct 95' "$CAPTURE"; then
  echo "easy_node quick-trend forwarding failed: missing --min-go-rate-pct"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--since-hours 24' "$CAPTURE"; then
  echo "easy_node quick-trend forwarding failed: missing --since-hours"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json /tmp/quick_trend.json' "$CAPTURE"; then
  echo "easy_node quick-trend forwarding failed: missing --summary-json"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-cohort-signoff-policy 1' "$CAPTURE"; then
  echo "easy_node quick-trend forwarding failed: missing --require-cohort-signoff-policy"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-summary-json 1' "$CAPTURE"; then
  echo "easy_node quick-trend forwarding failed: missing --print-summary-json"
  cat "$CAPTURE"
  exit 1
fi

echo "prod pilot cohort quick trend integration ok"
