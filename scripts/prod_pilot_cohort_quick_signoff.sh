#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

QUICK_CHECK_SCRIPT="${PROD_PILOT_COHORT_QUICK_CHECK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick_check.sh}"
QUICK_TREND_SCRIPT="${PROD_PILOT_COHORT_QUICK_TREND_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick_trend.sh}"
QUICK_ALERT_SCRIPT="${PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick_alert.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_quick_signoff.sh \
    [--run-report-json PATH] \
    [--reports-dir PATH] \
    [--check-latest [0|1]] \
    [--check-trend [0|1]] \
    [--check-alert [0|1]] \
    [--require-status-ok [0|1]] \
    [--require-runbook-ok [0|1]] \
    [--require-signoff-attempted [0|1]] \
    [--require-signoff-ok [0|1]] \
    [--require-summary-json [0|1]] \
    [--require-summary-status-ok [0|1]] \
    [--max-duration-sec N] \
    [--max-reports N] \
    [--since-hours N] \
    [--fail-on-any-no-go [0|1]] \
    [--min-go-rate-pct N] \
    [--warn-go-rate-pct N] \
    [--critical-go-rate-pct N] \
    [--warn-no-go-count N] \
    [--critical-no-go-count N] \
    [--warn-eval-errors N] \
    [--critical-eval-errors N] \
    [--max-alert-severity OK|WARN|CRITICAL] \
    [--trend-summary-json PATH] \
    [--alert-summary-json PATH] \
    [--signoff-json PATH] \
    [--show-json [0|1]]

Purpose:
  Run quick-mode pilot signoff in one fail-closed command:
    1) latest quick-run report policy check
    2) quick-run trend gate
    3) quick alert severity gate

Notes:
  - Recommended input is --run-report-json from prod-pilot-cohort-quick.
  - --max-alert-severity controls fail-close severity policy:
      OK        => fail on WARN and CRITICAL
      WARN      => fail on CRITICAL only (default)
      CRITICAL  => no severity-based fail-close
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    echo ""
    return
  fi
  if [[ "$path" == /* ]]; then
    echo "$path"
  else
    echo "$ROOT_DIR/$path"
  fi
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

for cmd in bash jq date; do
  need_cmd "$cmd"
done

run_report_json=""
reports_dir=""
check_latest="${PROD_PILOT_COHORT_QUICK_SIGNOFF_CHECK_LATEST:-1}"
check_trend="${PROD_PILOT_COHORT_QUICK_SIGNOFF_CHECK_TREND:-1}"
check_alert="${PROD_PILOT_COHORT_QUICK_SIGNOFF_CHECK_ALERT:-1}"

require_status_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_STATUS_OK:-1}"
require_runbook_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_RUNBOOK_OK:-1}"
require_signoff_attempted="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SIGNOFF_ATTEMPTED:-1}"
require_signoff_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SIGNOFF_OK:-1}"
require_summary_json="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SUMMARY_JSON:-1}"
require_summary_status_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SUMMARY_STATUS_OK:-1}"
max_duration_sec="${PROD_PILOT_COHORT_QUICK_CHECK_MAX_DURATION_SEC:-0}"

max_reports="${PROD_PILOT_COHORT_QUICK_TREND_MAX_REPORTS:-25}"
since_hours="${PROD_PILOT_COHORT_QUICK_TREND_SINCE_HOURS:-24}"
fail_on_any_no_go="${PROD_PILOT_COHORT_QUICK_TREND_FAIL_ON_ANY_NO_GO:-0}"
min_go_rate_pct="${PROD_PILOT_COHORT_QUICK_TREND_MIN_GO_RATE_PCT:-95}"

warn_go_rate_pct="${PROD_PILOT_COHORT_QUICK_ALERT_WARN_GO_RATE_PCT:-98}"
critical_go_rate_pct="${PROD_PILOT_COHORT_QUICK_ALERT_CRITICAL_GO_RATE_PCT:-90}"
warn_no_go_count="${PROD_PILOT_COHORT_QUICK_ALERT_WARN_NO_GO_COUNT:-1}"
critical_no_go_count="${PROD_PILOT_COHORT_QUICK_ALERT_CRITICAL_NO_GO_COUNT:-2}"
warn_eval_errors="${PROD_PILOT_COHORT_QUICK_ALERT_WARN_EVAL_ERRORS:-1}"
critical_eval_errors="${PROD_PILOT_COHORT_QUICK_ALERT_CRITICAL_EVAL_ERRORS:-2}"
max_alert_severity="${PROD_PILOT_COHORT_QUICK_SIGNOFF_MAX_ALERT_SEVERITY:-WARN}"

trend_summary_json=""
alert_summary_json=""
signoff_json=""
show_json="${PROD_PILOT_COHORT_QUICK_SIGNOFF_SHOW_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-report-json)
      run_report_json="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --check-latest)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        check_latest="${2:-}"
        shift 2
      else
        check_latest="1"
        shift
      fi
      ;;
    --check-trend)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        check_trend="${2:-}"
        shift 2
      else
        check_trend="1"
        shift
      fi
      ;;
    --check-alert)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        check_alert="${2:-}"
        shift 2
      else
        check_alert="1"
        shift
      fi
      ;;
    --require-status-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_status_ok="${2:-}"
        shift 2
      else
        require_status_ok="1"
        shift
      fi
      ;;
    --require-runbook-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_runbook_ok="${2:-}"
        shift 2
      else
        require_runbook_ok="1"
        shift
      fi
      ;;
    --require-signoff-attempted)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_signoff_attempted="${2:-}"
        shift 2
      else
        require_signoff_attempted="1"
        shift
      fi
      ;;
    --require-signoff-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_signoff_ok="${2:-}"
        shift 2
      else
        require_signoff_ok="1"
        shift
      fi
      ;;
    --require-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_summary_json="${2:-}"
        shift 2
      else
        require_summary_json="1"
        shift
      fi
      ;;
    --require-summary-status-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_summary_status_ok="${2:-}"
        shift 2
      else
        require_summary_status_ok="1"
        shift
      fi
      ;;
    --max-duration-sec)
      max_duration_sec="${2:-}"
      shift 2
      ;;
    --max-reports)
      max_reports="${2:-}"
      shift 2
      ;;
    --since-hours)
      since_hours="${2:-}"
      shift 2
      ;;
    --fail-on-any-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_any_no_go="${2:-}"
        shift 2
      else
        fail_on_any_no_go="1"
        shift
      fi
      ;;
    --min-go-rate-pct)
      min_go_rate_pct="${2:-}"
      shift 2
      ;;
    --warn-go-rate-pct)
      warn_go_rate_pct="${2:-}"
      shift 2
      ;;
    --critical-go-rate-pct)
      critical_go_rate_pct="${2:-}"
      shift 2
      ;;
    --warn-no-go-count)
      warn_no_go_count="${2:-}"
      shift 2
      ;;
    --critical-no-go-count)
      critical_no_go_count="${2:-}"
      shift 2
      ;;
    --warn-eval-errors)
      warn_eval_errors="${2:-}"
      shift 2
      ;;
    --critical-eval-errors)
      critical_eval_errors="${2:-}"
      shift 2
      ;;
    --max-alert-severity)
      max_alert_severity="${2:-}"
      shift 2
      ;;
    --trend-summary-json)
      trend_summary_json="${2:-}"
      shift 2
      ;;
    --alert-summary-json)
      alert_summary_json="${2:-}"
      shift 2
      ;;
    --signoff-json)
      signoff_json="${2:-}"
      shift 2
      ;;
    --show-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_json="${2:-}"
        shift 2
      else
        show_json="1"
        shift
      fi
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

if [[ ! -x "$QUICK_CHECK_SCRIPT" ]]; then
  echo "missing executable quick-check script: $QUICK_CHECK_SCRIPT"
  exit 2
fi
if [[ ! -x "$QUICK_TREND_SCRIPT" ]]; then
  echo "missing executable quick-trend script: $QUICK_TREND_SCRIPT"
  exit 2
fi
if [[ ! -x "$QUICK_ALERT_SCRIPT" ]]; then
  echo "missing executable quick-alert script: $QUICK_ALERT_SCRIPT"
  exit 2
fi

for pair in \
  "--check-latest:$check_latest" \
  "--check-trend:$check_trend" \
  "--check-alert:$check_alert" \
  "--require-status-ok:$require_status_ok" \
  "--require-runbook-ok:$require_runbook_ok" \
  "--require-signoff-attempted:$require_signoff_attempted" \
  "--require-signoff-ok:$require_signoff_ok" \
  "--require-summary-json:$require_summary_json" \
  "--require-summary-status-ok:$require_summary_status_ok" \
  "--fail-on-any-no-go:$fail_on_any_no_go" \
  "--show-json:$show_json"; do
  key="${pair%%:*}"
  val="${pair##*:}"
  bool_arg_or_die "$key" "$val"
done

if [[ ! "$max_duration_sec" =~ ^[0-9]+$ ]]; then
  echo "--max-duration-sec must be an integer >= 0"
  exit 2
fi
if [[ ! "$max_reports" =~ ^[0-9]+$ ]] || ((max_reports < 1)); then
  echo "--max-reports must be an integer >= 1"
  exit 2
fi
if [[ ! "$since_hours" =~ ^[0-9]+$ ]]; then
  echo "--since-hours must be an integer >= 0"
  exit 2
fi
for int_name in warn_no_go_count critical_no_go_count warn_eval_errors critical_eval_errors; do
  int_val="${!int_name}"
  if [[ ! "$int_val" =~ ^[0-9]+$ ]]; then
    echo "--${int_name//_/-} must be an integer >= 0"
    exit 2
  fi
done
for dec_name in min_go_rate_pct warn_go_rate_pct critical_go_rate_pct; do
  dec_val="${!dec_name}"
  if ! is_non_negative_decimal "$dec_val"; then
    echo "--${dec_name//_/-} must be a number between 0 and 100"
    exit 2
  fi
done

max_alert_severity="$(printf '%s' "$max_alert_severity" | tr '[:lower:]' '[:upper:]')"
if [[ "$max_alert_severity" != "OK" && "$max_alert_severity" != "WARN" && "$max_alert_severity" != "CRITICAL" ]]; then
  echo "--max-alert-severity must be OK, WARN, or CRITICAL"
  exit 2
fi

run_report_json="$(abs_path "$run_report_json")"
reports_dir="$(abs_path "$reports_dir")"
trend_summary_json="$(abs_path "$trend_summary_json")"
alert_summary_json="$(abs_path "$alert_summary_json")"
signoff_json="$(abs_path "$signoff_json")"

if [[ -z "$reports_dir" ]]; then
  if [[ -n "$run_report_json" ]]; then
    reports_dir="$(dirname "$run_report_json")"
  else
    reports_dir="$ROOT_DIR/.easy-node-logs"
  fi
fi
if [[ -z "$run_report_json" ]]; then
  run_report_json="$reports_dir/prod_pilot_cohort_quick_report.json"
fi
if [[ -z "$trend_summary_json" ]]; then
  trend_summary_json="$reports_dir/prod_pilot_quick_signoff_trend.json"
fi
if [[ -z "$alert_summary_json" ]]; then
  alert_summary_json="$reports_dir/prod_pilot_quick_signoff_alert.json"
fi
if [[ -z "$signoff_json" ]]; then
  signoff_json="$reports_dir/prod_pilot_quick_signoff.json"
fi

mkdir -p "$reports_dir" "$(dirname "$trend_summary_json")" "$(dirname "$alert_summary_json")" "$(dirname "$signoff_json")"

fail_on_warn="0"
fail_on_critical="0"
case "$max_alert_severity" in
  OK)
    fail_on_warn="1"
    fail_on_critical="1"
    ;;
  WARN)
    fail_on_warn="0"
    fail_on_critical="1"
    ;;
  CRITICAL)
    fail_on_warn="0"
    fail_on_critical="0"
    ;;
esac

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_epoch="$(date -u +%s)"

status="ok"
failure_step=""
final_rc=0

latest_check_rc=0
trend_rc=0
alert_rc=0
alert_severity=""

if [[ "$check_latest" == "1" ]]; then
  echo "prod-pilot-cohort-quick-signoff: quick-check stage"
  set +e
  "$QUICK_CHECK_SCRIPT" \
    --run-report-json "$run_report_json" \
    --reports-dir "$reports_dir" \
    --require-status-ok "$require_status_ok" \
    --require-runbook-ok "$require_runbook_ok" \
    --require-signoff-attempted "$require_signoff_attempted" \
    --require-signoff-ok "$require_signoff_ok" \
    --require-summary-json "$require_summary_json" \
    --require-summary-status-ok "$require_summary_status_ok" \
    --max-duration-sec "$max_duration_sec" \
    --show-json 0
  latest_check_rc=$?
  set -e
  if [[ "$latest_check_rc" -ne 0 ]]; then
    status="fail"
    failure_step="quick_check"
    final_rc="$latest_check_rc"
  fi
fi

if [[ "$status" == "ok" && "$check_trend" == "1" ]]; then
  echo "prod-pilot-cohort-quick-signoff: quick-trend stage"
  set +e
  "$QUICK_TREND_SCRIPT" \
    --run-report-json "$run_report_json" \
    --reports-dir "$reports_dir" \
    --max-reports "$max_reports" \
    --since-hours "$since_hours" \
    --require-status-ok "$require_status_ok" \
    --require-runbook-ok "$require_runbook_ok" \
    --require-signoff-attempted "$require_signoff_attempted" \
    --require-signoff-ok "$require_signoff_ok" \
    --require-summary-json "$require_summary_json" \
    --require-summary-status-ok "$require_summary_status_ok" \
    --max-duration-sec "$max_duration_sec" \
    --fail-on-any-no-go "$fail_on_any_no_go" \
    --min-go-rate-pct "$min_go_rate_pct" \
    --show-details 0 \
    --show-top-reasons 5 \
    --summary-json "$trend_summary_json" \
    --print-summary-json 0
  trend_rc=$?
  set -e
  if [[ "$trend_rc" -ne 0 ]]; then
    status="fail"
    failure_step="quick_trend"
    final_rc="$trend_rc"
  fi
fi

if [[ "$status" == "ok" && "$check_alert" == "1" ]]; then
  echo "prod-pilot-cohort-quick-signoff: quick-alert stage"
  set +e
  "$QUICK_ALERT_SCRIPT" \
    --trend-summary-json "$trend_summary_json" \
    --reports-dir "$reports_dir" \
    --max-reports "$max_reports" \
    --since-hours "$since_hours" \
    --require-status-ok "$require_status_ok" \
    --require-runbook-ok "$require_runbook_ok" \
    --require-signoff-attempted "$require_signoff_attempted" \
    --require-signoff-ok "$require_signoff_ok" \
    --require-summary-json "$require_summary_json" \
    --require-summary-status-ok "$require_summary_status_ok" \
    --max-duration-sec "$max_duration_sec" \
    --warn-go-rate-pct "$warn_go_rate_pct" \
    --critical-go-rate-pct "$critical_go_rate_pct" \
    --warn-no-go-count "$warn_no_go_count" \
    --critical-no-go-count "$critical_no_go_count" \
    --warn-eval-errors "$warn_eval_errors" \
    --critical-eval-errors "$critical_eval_errors" \
    --fail-on-warn "$fail_on_warn" \
    --fail-on-critical "$fail_on_critical" \
    --show-top-reasons 5 \
    --summary-json "$alert_summary_json" \
    --print-summary-json 0
  alert_rc=$?
  set -e
  if [[ -f "$alert_summary_json" ]]; then
    alert_severity="$(jq -r '.severity // ""' "$alert_summary_json" 2>/dev/null || true)"
  fi
  if [[ "$alert_rc" -ne 0 ]]; then
    status="fail"
    failure_step="quick_alert"
    final_rc="$alert_rc"
  fi
fi

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
finished_epoch="$(date -u +%s)"
duration_sec=$((finished_epoch - started_epoch))
if [[ "$duration_sec" -lt 0 ]]; then
  duration_sec=0
fi

jq -nc \
  --arg started_at "$started_at" \
  --arg finished_at "$finished_at" \
  --arg status "$status" \
  --arg failure_step "$failure_step" \
  --arg run_report_json "$run_report_json" \
  --arg reports_dir "$reports_dir" \
  --arg trend_summary_json "$trend_summary_json" \
  --arg alert_summary_json "$alert_summary_json" \
  --arg signoff_json "$signoff_json" \
  --arg max_alert_severity "$max_alert_severity" \
  --arg alert_severity "${alert_severity:-}" \
  --argjson check_latest "$check_latest" \
  --argjson check_trend "$check_trend" \
  --argjson check_alert "$check_alert" \
  --argjson latest_check_rc "$latest_check_rc" \
  --argjson trend_rc "$trend_rc" \
  --argjson alert_rc "$alert_rc" \
  --argjson final_rc "$final_rc" \
  --argjson duration_sec "$duration_sec" \
  --argjson fail_on_warn "$fail_on_warn" \
  --argjson fail_on_critical "$fail_on_critical" \
  '{
    version: 1,
    started_at: $started_at,
    finished_at: $finished_at,
    duration_sec: $duration_sec,
    status: $status,
    failure_step: ($failure_step // ""),
    final_rc: $final_rc,
    stages: {
      quick_check: {enabled: $check_latest, rc: $latest_check_rc},
      quick_trend: {enabled: $check_trend, rc: $trend_rc},
      quick_alert: {enabled: $check_alert, rc: $alert_rc}
    },
    policy: {
      max_alert_severity: $max_alert_severity,
      fail_on_warn: $fail_on_warn,
      fail_on_critical: $fail_on_critical
    },
    observed: {
      alert_severity: ($alert_severity // "")
    },
    artifacts: {
      run_report_json: $run_report_json,
      reports_dir: $reports_dir,
      trend_summary_json: $trend_summary_json,
      alert_summary_json: $alert_summary_json,
      signoff_json: $signoff_json
    }
  }' >"$signoff_json"

echo "prod-pilot-cohort-quick-signoff: signoff_json=$signoff_json status=$status"
if [[ "$show_json" == "1" ]]; then
  cat "$signoff_json"
fi

if [[ "$status" == "ok" ]]; then
  exit 0
fi
exit "$final_rc"
