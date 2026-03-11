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
  --max-alert-severity WARN \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_quick_signoff_pass.log 2>&1

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
if ! rg -q -- '--summary-json ' "$TREND_CAPTURE"; then
  echo "quick-signoff forwarding missing --summary-json to quick-trend"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--trend-summary-json ' "$ALERT_CAPTURE"; then
  echo "quick-signoff forwarding missing --trend-summary-json to quick-alert"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fail-on-critical 1' "$ALERT_CAPTURE"; then
  echo "quick-signoff severity policy forwarding missing --fail-on-critical 1 for max-alert-severity=WARN"
  cat "$ALERT_CAPTURE"
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
if ! rg -q -- '--show-json 1' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node quick-signoff forwarding failed: missing --show-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi

echo "prod pilot cohort quick signoff integration ok"
