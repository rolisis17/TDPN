#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TREND_SCRIPT="${PROD_PILOT_COHORT_QUICK_TREND_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick_trend.sh}"
ALERT_SCRIPT="${PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick_alert.sh}"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_quick_dashboard.sh \
    [--run-report-json PATH]... \
    [--run-report-list FILE] \
    [--reports-dir DIR] \
    [--max-reports N] \
    [--since-hours N] \
    [--require-status-ok [0|1]] \
    [--require-runbook-ok [0|1]] \
    [--require-signoff-attempted [0|1]] \
    [--require-signoff-ok [0|1]] \
    [--require-summary-json [0|1]] \
    [--require-summary-status-ok [0|1]] \
    [--max-duration-sec N] \
    [--fail-on-any-no-go [0|1]] \
    [--min-go-rate-pct N] \
    [--show-top-reasons N] \
    [--warn-go-rate-pct N] \
    [--critical-go-rate-pct N] \
    [--warn-no-go-count N] \
    [--critical-no-go-count N] \
    [--warn-eval-errors N] \
    [--critical-eval-errors N] \
    [--fail-on-warn [0|1]] \
    [--fail-on-critical [0|1]] \
    [--trend-summary-json PATH] \
    [--alert-summary-json PATH] \
    [--dashboard-md PATH] \
    [--print-dashboard [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Produce one quick-mode operator dashboard from quick run reports.
  The command runs quick trend + quick alert evaluation and writes:
    1) trend summary JSON
    2) alert summary JSON
    3) markdown dashboard

Notes:
  - If no report input is supplied, defaults to scanning ./.easy-node-logs.
  - Exit code follows fail-close policy from trend/alert stages.
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

float_gt() {
  local left="$1"
  local right="$2"
  awk -v l="$left" -v r="$right" 'BEGIN { exit (l > r) ? 0 : 1 }'
}

reports_dir=""
run_report_list=""
declare -a run_report_jsons=()

max_reports="${PROD_PILOT_COHORT_QUICK_TREND_MAX_REPORTS:-25}"
since_hours="${PROD_PILOT_COHORT_QUICK_TREND_SINCE_HOURS:-24}"
require_status_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_STATUS_OK:-1}"
require_runbook_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_RUNBOOK_OK:-1}"
require_signoff_attempted="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SIGNOFF_ATTEMPTED:-1}"
require_signoff_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SIGNOFF_OK:-1}"
require_summary_json="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SUMMARY_JSON:-1}"
require_summary_status_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SUMMARY_STATUS_OK:-1}"
max_duration_sec="${PROD_PILOT_COHORT_QUICK_CHECK_MAX_DURATION_SEC:-0}"
fail_on_any_no_go="${PROD_PILOT_COHORT_QUICK_TREND_FAIL_ON_ANY_NO_GO:-0}"
min_go_rate_pct="${PROD_PILOT_COHORT_QUICK_TREND_MIN_GO_RATE_PCT:-95}"
show_top_reasons="${PROD_PILOT_COHORT_QUICK_TREND_SHOW_TOP_REASONS:-5}"

warn_go_rate_pct="${PROD_PILOT_COHORT_QUICK_ALERT_WARN_GO_RATE_PCT:-98}"
critical_go_rate_pct="${PROD_PILOT_COHORT_QUICK_ALERT_CRITICAL_GO_RATE_PCT:-90}"
warn_no_go_count="${PROD_PILOT_COHORT_QUICK_ALERT_WARN_NO_GO_COUNT:-1}"
critical_no_go_count="${PROD_PILOT_COHORT_QUICK_ALERT_CRITICAL_NO_GO_COUNT:-2}"
warn_eval_errors="${PROD_PILOT_COHORT_QUICK_ALERT_WARN_EVAL_ERRORS:-1}"
critical_eval_errors="${PROD_PILOT_COHORT_QUICK_ALERT_CRITICAL_EVAL_ERRORS:-2}"
fail_on_warn="${PROD_PILOT_COHORT_QUICK_ALERT_FAIL_ON_WARN:-0}"
fail_on_critical="${PROD_PILOT_COHORT_QUICK_ALERT_FAIL_ON_CRITICAL:-0}"

trend_summary_json=""
alert_summary_json=""
dashboard_md=""
print_dashboard="${PROD_PILOT_COHORT_QUICK_DASHBOARD_PRINT_DASHBOARD:-1}"
print_summary_json="${PROD_PILOT_COHORT_QUICK_DASHBOARD_PRINT_SUMMARY_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-report-json)
      run_report_jsons+=("${2:-}")
      shift 2
      ;;
    --run-report-list)
      run_report_list="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
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
    --show-top-reasons)
      show_top_reasons="${2:-}"
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
    --fail-on-warn)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_warn="${2:-}"
        shift 2
      else
        fail_on_warn="1"
        shift
      fi
      ;;
    --fail-on-critical)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_critical="${2:-}"
        shift 2
      else
        fail_on_critical="1"
        shift
      fi
      ;;
    --trend-summary-json)
      trend_summary_json="${2:-}"
      shift 2
      ;;
    --alert-summary-json)
      alert_summary_json="${2:-}"
      shift 2
      ;;
    --dashboard-md)
      dashboard_md="${2:-}"
      shift 2
      ;;
    --print-dashboard)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_dashboard="${2:-}"
        shift 2
      else
        print_dashboard="1"
        shift
      fi
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
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

for cmd in bash jq awk date; do
  need_cmd "$cmd"
done
if [[ ! -x "$TREND_SCRIPT" ]]; then
  echo "missing executable trend script: $TREND_SCRIPT"
  exit 2
fi
if [[ ! -x "$ALERT_SCRIPT" ]]; then
  echo "missing executable alert script: $ALERT_SCRIPT"
  exit 2
fi

bool_arg_or_die "--require-status-ok" "$require_status_ok"
bool_arg_or_die "--require-runbook-ok" "$require_runbook_ok"
bool_arg_or_die "--require-signoff-attempted" "$require_signoff_attempted"
bool_arg_or_die "--require-signoff-ok" "$require_signoff_ok"
bool_arg_or_die "--require-summary-json" "$require_summary_json"
bool_arg_or_die "--require-summary-status-ok" "$require_summary_status_ok"
bool_arg_or_die "--fail-on-any-no-go" "$fail_on_any_no_go"
bool_arg_or_die "--fail-on-warn" "$fail_on_warn"
bool_arg_or_die "--fail-on-critical" "$fail_on_critical"
bool_arg_or_die "--print-dashboard" "$print_dashboard"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

for int_name in max_reports since_hours max_duration_sec show_top_reasons warn_no_go_count critical_no_go_count warn_eval_errors critical_eval_errors; do
  value="${!int_name}"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "--${int_name//_/-} must be an integer >= 0"
    exit 2
  fi
done

for decimal_name in min_go_rate_pct warn_go_rate_pct critical_go_rate_pct; do
  value="${!decimal_name}"
  if ! is_non_negative_decimal "$value"; then
    echo "--${decimal_name//_/-} must be a number between 0 and 100"
    exit 2
  fi
  if float_gt "$value" "100"; then
    echo "--${decimal_name//_/-} must be <= 100"
    exit 2
  fi
done
if float_gt "$critical_go_rate_pct" "$warn_go_rate_pct"; then
  echo "--critical-go-rate-pct cannot be greater than --warn-go-rate-pct"
  exit 2
fi
if ((critical_no_go_count < warn_no_go_count)); then
  echo "--critical-no-go-count must be >= --warn-no-go-count"
  exit 2
fi
if ((critical_eval_errors < warn_eval_errors)); then
  echo "--critical-eval-errors must be >= --warn-eval-errors"
  exit 2
fi

reports_dir="$(trim "$reports_dir")"
run_report_list="$(trim "$run_report_list")"
trend_summary_json="$(trim "$trend_summary_json")"
alert_summary_json="$(trim "$alert_summary_json")"
dashboard_md="$(trim "$dashboard_md")"

if [[ -z "$reports_dir" && -z "$run_report_list" && ${#run_report_jsons[@]} -eq 0 ]]; then
  reports_dir="$(default_log_dir)"
fi

timestamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$trend_summary_json" ]]; then
  trend_summary_json="$(default_log_dir)/prod_pilot_quick_trend_${timestamp}.json"
fi
if [[ -z "$alert_summary_json" ]]; then
  alert_summary_json="$(default_log_dir)/prod_pilot_quick_alert_${timestamp}.json"
fi
if [[ -z "$dashboard_md" ]]; then
  dashboard_md="$(default_log_dir)/prod_pilot_quick_dashboard_${timestamp}.md"
fi

if [[ "$trend_summary_json" != /* ]]; then
  trend_summary_json="$ROOT_DIR/$trend_summary_json"
fi
if [[ "$alert_summary_json" != /* ]]; then
  alert_summary_json="$ROOT_DIR/$alert_summary_json"
fi
if [[ "$dashboard_md" != /* ]]; then
  dashboard_md="$ROOT_DIR/$dashboard_md"
fi

trend_args=(
  --max-reports "$max_reports"
  --since-hours "$since_hours"
  --require-status-ok "$require_status_ok"
  --require-runbook-ok "$require_runbook_ok"
  --require-signoff-attempted "$require_signoff_attempted"
  --require-signoff-ok "$require_signoff_ok"
  --require-summary-json "$require_summary_json"
  --require-summary-status-ok "$require_summary_status_ok"
  --max-duration-sec "$max_duration_sec"
  --fail-on-any-no-go "$fail_on_any_no_go"
  --min-go-rate-pct "$min_go_rate_pct"
  --show-details 0
  --show-top-reasons "$show_top_reasons"
  --summary-json "$trend_summary_json"
  --print-summary-json "$print_summary_json"
)
if [[ -n "$reports_dir" ]]; then
  trend_args+=(--reports-dir "$reports_dir")
fi
if [[ -n "$run_report_list" ]]; then
  trend_args+=(--run-report-list "$run_report_list")
fi
for raw in "${run_report_jsons[@]}"; do
  raw="$(trim "$raw")"
  [[ -z "$raw" ]] && continue
  trend_args+=(--run-report-json "$raw")
done

echo "[prod-pilot-cohort-quick-dashboard] running trend summary"
set +e
"$TREND_SCRIPT" "${trend_args[@]}"
trend_rc=$?
set -e

if [[ ! -f "$trend_summary_json" ]]; then
  echo "trend summary JSON file not found after trend run: $trend_summary_json"
  exit 1
fi
if ! jq -e . "$trend_summary_json" >/dev/null 2>&1; then
  echo "trend summary JSON is not valid: $trend_summary_json"
  exit 1
fi

alert_args=(
  --trend-summary-json "$trend_summary_json"
  --warn-go-rate-pct "$warn_go_rate_pct"
  --critical-go-rate-pct "$critical_go_rate_pct"
  --warn-no-go-count "$warn_no_go_count"
  --critical-no-go-count "$critical_no_go_count"
  --warn-eval-errors "$warn_eval_errors"
  --critical-eval-errors "$critical_eval_errors"
  --fail-on-warn "$fail_on_warn"
  --fail-on-critical "$fail_on_critical"
  --show-top-reasons "$show_top_reasons"
  --summary-json "$alert_summary_json"
  --print-summary-json "$print_summary_json"
)

echo "[prod-pilot-cohort-quick-dashboard] running alert classification"
set +e
"$ALERT_SCRIPT" "${alert_args[@]}"
alert_rc=$?
set -e

if [[ ! -f "$alert_summary_json" ]]; then
  echo "alert summary JSON file not found after alert run: $alert_summary_json"
  exit 1
fi
if ! jq -e . "$alert_summary_json" >/dev/null 2>&1; then
  echo "alert summary JSON is not valid: $alert_summary_json"
  exit 1
fi

mkdir -p "$(dirname "$dashboard_md")"

trend_decision="$(jq -r '.decision // "UNKNOWN"' "$trend_summary_json")"
reports_total="$(jq -r '.reports_total // 0' "$trend_summary_json")"
go_count="$(jq -r '.go // 0' "$trend_summary_json")"
no_go_count="$(jq -r '.no_go // 0' "$trend_summary_json")"
go_rate_pct="$(jq -r '.go_rate_pct // 0' "$trend_summary_json")"
evaluation_errors="$(jq -r '.evaluation_errors // 0' "$trend_summary_json")"
alert_severity="$(jq -r '.severity // "UNKNOWN"' "$alert_summary_json")"

action_line="Continue pilot traffic and keep monitoring."
case "$alert_severity" in
  CRITICAL)
    action_line="Pause onboarding and investigate immediate quick-run failures."
    ;;
  WARN)
    action_line="Investigate quick-run regressions before widening traffic."
    ;;
esac

{
  echo "# PROD Pilot Quick Dashboard"
  echo
  echo "- Generated (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Window (hours): $since_hours"
  echo "- Reports evaluated: $reports_total"
  echo "- Trend decision: $trend_decision"
  echo "- Alert severity: $alert_severity"
  echo
  echo "## Key Metrics"
  echo
  echo "- GO runs: $go_count"
  echo "- NO-GO runs: $no_go_count"
  echo "- GO rate (%): $go_rate_pct"
  echo "- Evaluation errors: $evaluation_errors"
  echo
  echo "## Trigger Reasons"
  echo
  trigger_lines="$(jq -r '.trigger_reasons[]? // empty' "$alert_summary_json")"
  if [[ -n "$trigger_lines" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "$line" ]] && continue
      echo "- $line"
    done <<<"$trigger_lines"
  else
    echo "- none"
  fi
  echo
  echo "## Top NO-GO Reasons"
  echo
  top_reason_lines="$(jq -r '.top_no_go_reasons[]? | "- count=\(.count) reason=\(.reason)"' "$trend_summary_json")"
  if [[ -n "$top_reason_lines" ]]; then
    printf '%s\n' "$top_reason_lines"
  else
    echo "- none"
  fi
  echo
  echo "## Artifacts"
  echo
  echo "- Trend summary JSON: $trend_summary_json"
  echo "- Alert summary JSON: $alert_summary_json"
  echo "- Dashboard markdown: $dashboard_md"
  echo
  echo "## Recommended Operator Action"
  echo
  echo "- $action_line"
  echo
  echo "## Execution Status"
  echo
  echo "- trend_rc: $trend_rc"
  echo "- alert_rc: $alert_rc"
} >"$dashboard_md"

echo "[prod-pilot-cohort-quick-dashboard] trend_summary_json=$trend_summary_json"
echo "[prod-pilot-cohort-quick-dashboard] alert_summary_json=$alert_summary_json"
echo "[prod-pilot-cohort-quick-dashboard] dashboard_md=$dashboard_md"

if [[ "$print_dashboard" == "1" ]]; then
  echo "[prod-pilot-cohort-quick-dashboard] dashboard_preview:"
  cat "$dashboard_md"
fi

if [[ "$alert_rc" -ne 0 ]]; then
  exit "$alert_rc"
fi
if [[ "$trend_rc" -ne 0 ]]; then
  exit "$trend_rc"
fi
exit 0
