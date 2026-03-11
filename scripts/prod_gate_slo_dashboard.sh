#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TREND_SCRIPT="${PROD_GATE_SLO_TREND_SCRIPT:-$ROOT_DIR/scripts/prod_gate_slo_trend.sh}"
ALERT_SCRIPT="${PROD_GATE_SLO_ALERT_SCRIPT:-$ROOT_DIR/scripts/prod_gate_slo_alert.sh}"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_gate_slo_dashboard.sh \
    [--run-report-json PATH]... \
    [--run-report-list FILE] \
    [--reports-dir DIR] \
    [--max-reports N] \
    [--since-hours N] \
    [--require-full-sequence [0|1]] \
    [--require-wg-validate-ok [0|1]] \
    [--require-wg-soak-ok [0|1]] \
    [--max-wg-soak-failed-rounds N] \
    [--require-preflight-ok [0|1]] \
    [--require-bundle-ok [0|1]] \
    [--require-integrity-ok [0|1]] \
    [--require-signoff-ok [0|1]] \
    [--require-incident-snapshot-on-fail [0|1]] \
    [--require-incident-snapshot-artifacts [0|1]] \
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
  Produce one operator-facing SLO dashboard from prod gate run reports.
  The command runs trend + alert evaluation and writes:
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
  local v="$1"
  [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

float_gt() {
  local left="$1"
  local right="$2"
  awk -v l="$left" -v r="$right" 'BEGIN { exit (l > r) ? 0 : 1 }'
}

reports_dir=""
run_report_list=""
declare -a run_report_jsons=()

max_reports="${PROD_GATE_SLO_TREND_MAX_REPORTS:-25}"
since_hours="${PROD_GATE_SLO_TREND_SINCE_HOURS:-24}"
require_full_sequence="${PROD_GATE_SLO_REQUIRE_FULL_SEQUENCE:-1}"
require_wg_validate_ok="${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_OK:-1}"
require_wg_soak_ok="${PROD_GATE_SLO_REQUIRE_WG_SOAK_OK:-1}"
max_wg_soak_failed_rounds="${PROD_GATE_SLO_MAX_WG_SOAK_FAILED_ROUNDS:-0}"
require_preflight_ok="${PROD_GATE_SLO_REQUIRE_PREFLIGHT_OK:-0}"
require_bundle_ok="${PROD_GATE_SLO_REQUIRE_BUNDLE_OK:-0}"
require_integrity_ok="${PROD_GATE_SLO_REQUIRE_INTEGRITY_OK:-0}"
require_signoff_ok="${PROD_GATE_SLO_REQUIRE_SIGNOFF_OK:-0}"
require_incident_snapshot_on_fail="${PROD_GATE_SLO_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-0}"
require_incident_snapshot_artifacts="${PROD_GATE_SLO_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-0}"
fail_on_any_no_go="${PROD_GATE_SLO_TREND_FAIL_ON_ANY_NO_GO:-0}"
min_go_rate_pct="${PROD_GATE_SLO_TREND_MIN_GO_RATE_PCT:-95}"
show_top_reasons="${PROD_GATE_SLO_TREND_SHOW_TOP_REASONS:-5}"

warn_go_rate_pct="${PROD_GATE_SLO_ALERT_WARN_GO_RATE_PCT:-98}"
critical_go_rate_pct="${PROD_GATE_SLO_ALERT_CRITICAL_GO_RATE_PCT:-90}"
warn_no_go_count="${PROD_GATE_SLO_ALERT_WARN_NO_GO_COUNT:-1}"
critical_no_go_count="${PROD_GATE_SLO_ALERT_CRITICAL_NO_GO_COUNT:-2}"
warn_eval_errors="${PROD_GATE_SLO_ALERT_WARN_EVAL_ERRORS:-1}"
critical_eval_errors="${PROD_GATE_SLO_ALERT_CRITICAL_EVAL_ERRORS:-2}"
fail_on_warn="${PROD_GATE_SLO_ALERT_FAIL_ON_WARN:-0}"
fail_on_critical="${PROD_GATE_SLO_ALERT_FAIL_ON_CRITICAL:-0}"

trend_summary_json=""
alert_summary_json=""
dashboard_md=""
print_dashboard="${PROD_GATE_SLO_DASHBOARD_PRINT_DASHBOARD:-1}"
print_summary_json="${PROD_GATE_SLO_DASHBOARD_PRINT_SUMMARY_JSON:-0}"

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
    --require-full-sequence)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_full_sequence="${2:-}"
        shift 2
      else
        require_full_sequence="1"
        shift
      fi
      ;;
    --require-wg-validate-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_ok="${2:-}"
        shift 2
      else
        require_wg_validate_ok="1"
        shift
      fi
      ;;
    --require-wg-soak-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_soak_ok="${2:-}"
        shift 2
      else
        require_wg_soak_ok="1"
        shift
      fi
      ;;
    --max-wg-soak-failed-rounds)
      max_wg_soak_failed_rounds="${2:-}"
      shift 2
      ;;
    --require-preflight-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_preflight_ok="${2:-}"
        shift 2
      else
        require_preflight_ok="1"
        shift
      fi
      ;;
    --require-bundle-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_bundle_ok="${2:-}"
        shift 2
      else
        require_bundle_ok="1"
        shift
      fi
      ;;
    --require-integrity-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_integrity_ok="${2:-}"
        shift 2
      else
        require_integrity_ok="1"
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
    --require-incident-snapshot-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_incident_snapshot_on_fail="${2:-}"
        shift 2
      else
        require_incident_snapshot_on_fail="1"
        shift
      fi
      ;;
    --require-incident-snapshot-artifacts)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_incident_snapshot_artifacts="${2:-}"
        shift 2
      else
        require_incident_snapshot_artifacts="1"
        shift
      fi
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

for cmd in bash jq awk date mktemp; do
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

bool_arg_or_die "--require-full-sequence" "$require_full_sequence"
bool_arg_or_die "--require-wg-validate-ok" "$require_wg_validate_ok"
bool_arg_or_die "--require-wg-soak-ok" "$require_wg_soak_ok"
bool_arg_or_die "--require-preflight-ok" "$require_preflight_ok"
bool_arg_or_die "--require-bundle-ok" "$require_bundle_ok"
bool_arg_or_die "--require-integrity-ok" "$require_integrity_ok"
bool_arg_or_die "--require-signoff-ok" "$require_signoff_ok"
bool_arg_or_die "--require-incident-snapshot-on-fail" "$require_incident_snapshot_on_fail"
bool_arg_or_die "--require-incident-snapshot-artifacts" "$require_incident_snapshot_artifacts"
bool_arg_or_die "--fail-on-any-no-go" "$fail_on_any_no_go"
bool_arg_or_die "--fail-on-warn" "$fail_on_warn"
bool_arg_or_die "--fail-on-critical" "$fail_on_critical"
bool_arg_or_die "--print-dashboard" "$print_dashboard"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

for int_name in max_reports since_hours max_wg_soak_failed_rounds show_top_reasons warn_no_go_count critical_no_go_count warn_eval_errors critical_eval_errors; do
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
  trend_summary_json="$(default_log_dir)/prod_slo_trend_${timestamp}.json"
fi
if [[ -z "$alert_summary_json" ]]; then
  alert_summary_json="$(default_log_dir)/prod_slo_alert_${timestamp}.json"
fi
if [[ -z "$dashboard_md" ]]; then
  dashboard_md="$(default_log_dir)/prod_slo_dashboard_${timestamp}.md"
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
  --require-full-sequence "$require_full_sequence"
  --require-wg-validate-ok "$require_wg_validate_ok"
  --require-wg-soak-ok "$require_wg_soak_ok"
  --max-wg-soak-failed-rounds "$max_wg_soak_failed_rounds"
  --require-preflight-ok "$require_preflight_ok"
  --require-bundle-ok "$require_bundle_ok"
  --require-integrity-ok "$require_integrity_ok"
  --require-signoff-ok "$require_signoff_ok"
  --require-incident-snapshot-on-fail "$require_incident_snapshot_on_fail"
  --require-incident-snapshot-artifacts "$require_incident_snapshot_artifacts"
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

echo "[prod-gate-slo-dashboard] running trend summary"
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
  --require-full-sequence "$require_full_sequence"
  --require-wg-validate-ok "$require_wg_validate_ok"
  --require-wg-soak-ok "$require_wg_soak_ok"
  --max-wg-soak-failed-rounds "$max_wg_soak_failed_rounds"
  --require-preflight-ok "$require_preflight_ok"
  --require-bundle-ok "$require_bundle_ok"
  --require-integrity-ok "$require_integrity_ok"
  --require-signoff-ok "$require_signoff_ok"
  --require-incident-snapshot-on-fail "$require_incident_snapshot_on_fail"
  --require-incident-snapshot-artifacts "$require_incident_snapshot_artifacts"
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

echo "[prod-gate-slo-dashboard] running alert classification"
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
    action_line="Pause onboarding and investigate immediately."
    ;;
  WARN)
    action_line="Investigate recent failures and monitor before widening traffic."
    ;;
esac

{
  echo "# PROD SLO Dashboard"
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

echo "[prod-gate-slo-dashboard] trend_summary_json=$trend_summary_json"
echo "[prod-gate-slo-dashboard] alert_summary_json=$alert_summary_json"
echo "[prod-gate-slo-dashboard] dashboard_md=$dashboard_md"

if [[ "$print_dashboard" == "1" ]]; then
  echo "[prod-gate-slo-dashboard] dashboard_preview:"
  cat "$dashboard_md"
fi

if [[ "$alert_rc" -ne 0 ]]; then
  exit "$alert_rc"
fi
if [[ "$trend_rc" -ne 0 ]]; then
  exit "$trend_rc"
fi
exit 0
