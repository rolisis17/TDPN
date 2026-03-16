#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EASY_NODE_SH="${PROD_PILOT_COHORT_QUICK_RUNBOOK_EASY_NODE_SH:-$ROOT_DIR/scripts/easy_node.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_quick_runbook.sh \
    [--bootstrap-directory URL] \
    [--subject ID] \
    [--pre-real-host-readiness [0|1]] \
    [--pre-real-host-readiness-summary-json PATH] \
    [--rounds N] \
    [--pause-sec N] \
    [--continue-on-fail [0|1]] \
    [--require-all-rounds-ok [0|1]] \
    [--max-round-failures N] \
    [--trend-min-go-rate-pct N] \
    [--max-alert-severity OK|WARN|CRITICAL] \
    [--bundle-outputs [0|1]] \
    [--bundle-fail-close [0|1]] \
    [--reports-dir PATH] \
    [--summary-json PATH] \
    [--run-report-json PATH] \
    [--signoff-json PATH] \
    [--trend-summary-json PATH] \
    [--alert-summary-json PATH] \
    [--dashboard-md PATH] \
    [--signoff-max-reports N] \
    [--signoff-since-hours N] \
    [--signoff-fail-on-any-no-go [0|1]] \
    [--signoff-min-go-rate-pct N] \
    [--signoff-require-cohort-signoff-policy [0|1]] \
    [--signoff-require-trend-artifact-policy-match [0|1]] \
    [--signoff-require-trend-wg-validate-udp-source [0|1]] \
    [--signoff-require-trend-wg-validate-strict-distinct [0|1]] \
    [--signoff-require-trend-wg-soak-diversity-pass [0|1]] \
    [--signoff-min-trend-wg-soak-selection-lines N] \
    [--signoff-min-trend-wg-soak-entry-operators N] \
    [--signoff-min-trend-wg-soak-exit-operators N] \
    [--signoff-min-trend-wg-soak-cross-operator-pairs N] \
    [--signoff-require-incident-snapshot-on-fail [0|1]] \
    [--signoff-require-incident-snapshot-artifacts [0|1]] \
    [--signoff-incident-snapshot-min-attachment-count N] \
    [--signoff-incident-snapshot-max-skipped-count N|-1] \
    [--dashboard-enable [0|1]] \
    [--dashboard-fail-close [0|1]] \
    [--dashboard-print [0|1]] \
    [--dashboard-print-summary-json [0|1]] \
    [--show-json [0|1]] \
    [-- <prod-pilot-runbook extra args...>]

Purpose:
  One-command quick pilot operator flow:
    1) run prod-pilot-cohort-quick
    2) run prod-pilot-cohort-quick-signoff (fail-closed)
    3) optionally generate quick dashboard artifacts

Notes:
  - If the quick run fails but still emits a quick run report, signoff still runs
    to produce explicit policy verdict artifacts.
  - Dashboard stage is non-fail-close by default (`--dashboard-fail-close 0`).
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

bool_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

int_or_die() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an integer >= 0"
    exit 2
  fi
}

json_string_runbook() {
  local file="$1"
  local expr="$2"
  if [[ -z "$file" || ! -f "$file" ]]; then
    echo ""
    return
  fi
  jq -er "$expr // empty" "$file" 2>/dev/null || true
}

json_bool01_runbook() {
  local file="$1"
  local expr="$2"
  if [[ -z "$file" || ! -f "$file" ]]; then
    echo "0"
    return
  fi
  if jq -er "$expr == true" "$file" >/dev/null 2>&1; then
    echo "1"
  else
    echo "0"
  fi
}

path_exists01_runbook() {
  local path
  path="$(trim "${1:-}")"
  if [[ -n "$path" && -e "$path" ]]; then
    echo "1"
  else
    echo "0"
  fi
}

json_valid01_runbook() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" || ! -f "$path" ]]; then
    echo "0"
    return
  fi
  if jq -e . "$path" >/dev/null 2>&1; then
    echo "1"
  else
    echo "0"
  fi
}

if [[ $# -gt 0 ]]; then
  case "${1:-}" in
    -h|--help|help)
      usage
      exit 0
      ;;
  esac
fi

for cmd in bash date jq; do
  need_cmd "$cmd"
done

if [[ ! -x "$EASY_NODE_SH" ]]; then
  echo "missing executable easy_node script: $EASY_NODE_SH"
  exit 2
fi

bootstrap_directory="${PROD_PILOT_COHORT_QUICK_BOOTSTRAP_DIRECTORY:-}"
subject="${PROD_PILOT_COHORT_QUICK_SUBJECT:-pilot-client}"
pre_real_host_readiness="${PROD_PILOT_COHORT_QUICK_RUNBOOK_PRE_REAL_HOST_READINESS:-1}"
pre_real_host_readiness_summary_json="${PROD_PILOT_COHORT_QUICK_RUNBOOK_PRE_REAL_HOST_READINESS_SUMMARY_JSON:-}"
rounds="${PROD_PILOT_COHORT_QUICK_ROUNDS:-5}"
pause_sec="${PROD_PILOT_COHORT_QUICK_PAUSE_SEC:-60}"
continue_on_fail="${PROD_PILOT_COHORT_QUICK_CONTINUE_ON_FAIL:-0}"
require_all_rounds_ok="${PROD_PILOT_COHORT_QUICK_REQUIRE_ALL_ROUNDS_OK:-1}"
max_round_failures="${PROD_PILOT_COHORT_QUICK_MAX_ROUND_FAILURES:-0}"
trend_min_go_rate_pct="${PROD_PILOT_COHORT_QUICK_TREND_MIN_GO_RATE_PCT:-95}"
max_alert_severity="${PROD_PILOT_COHORT_QUICK_MAX_ALERT_SEVERITY:-WARN}"
bundle_outputs="${PROD_PILOT_COHORT_QUICK_BUNDLE_OUTPUTS:-1}"
bundle_fail_close="${PROD_PILOT_COHORT_QUICK_BUNDLE_FAIL_CLOSE:-1}"
reports_dir="${PROD_PILOT_COHORT_QUICK_REPORTS_DIR:-}"
summary_json="${PROD_PILOT_COHORT_QUICK_SUMMARY_JSON:-}"
run_report_json="${PROD_PILOT_COHORT_QUICK_RUN_REPORT_JSON:-}"
signoff_json="${PROD_PILOT_COHORT_QUICK_SIGNOFF_JSON:-}"
trend_summary_json="${PROD_PILOT_COHORT_QUICK_SIGNOFF_TREND_SUMMARY_JSON:-}"
alert_summary_json="${PROD_PILOT_COHORT_QUICK_SIGNOFF_ALERT_SUMMARY_JSON:-}"
dashboard_md="${PROD_PILOT_COHORT_QUICK_DASHBOARD_MD:-}"

signoff_max_reports="${PROD_PILOT_COHORT_QUICK_SIGNOFF_MAX_REPORTS:-25}"
signoff_since_hours="${PROD_PILOT_COHORT_QUICK_SIGNOFF_SINCE_HOURS:-24}"
signoff_fail_on_any_no_go="${PROD_PILOT_COHORT_QUICK_SIGNOFF_FAIL_ON_ANY_NO_GO:-0}"
signoff_min_go_rate_pct="${PROD_PILOT_COHORT_QUICK_SIGNOFF_MIN_GO_RATE_PCT:-95}"
signoff_require_cohort_signoff_policy="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_COHORT_SIGNOFF_POLICY:-1}"
signoff_require_trend_artifact_policy_match="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_TREND_ARTIFACT_POLICY_MATCH:-1}"
signoff_require_trend_wg_validate_udp_source="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_TREND_WG_VALIDATE_UDP_SOURCE:-1}"
signoff_require_trend_wg_validate_strict_distinct="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_TREND_WG_VALIDATE_STRICT_DISTINCT:-1}"
signoff_require_trend_wg_soak_diversity_pass="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_TREND_WG_SOAK_DIVERSITY_PASS:-1}"
signoff_min_trend_wg_soak_selection_lines="${PROD_PILOT_COHORT_QUICK_SIGNOFF_MIN_TREND_WG_SOAK_SELECTION_LINES:-12}"
signoff_min_trend_wg_soak_entry_operators="${PROD_PILOT_COHORT_QUICK_SIGNOFF_MIN_TREND_WG_SOAK_ENTRY_OPERATORS:-2}"
signoff_min_trend_wg_soak_exit_operators="${PROD_PILOT_COHORT_QUICK_SIGNOFF_MIN_TREND_WG_SOAK_EXIT_OPERATORS:-2}"
signoff_min_trend_wg_soak_cross_operator_pairs="${PROD_PILOT_COHORT_QUICK_SIGNOFF_MIN_TREND_WG_SOAK_CROSS_OPERATOR_PAIRS:-2}"
signoff_require_incident_snapshot_on_fail="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-1}"
signoff_require_incident_snapshot_artifacts="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-1}"
signoff_incident_snapshot_min_attachment_count="${PROD_PILOT_COHORT_QUICK_SIGNOFF_INCIDENT_SNAPSHOT_MIN_ATTACHMENT_COUNT:-${PROD_PILOT_COHORT_QUICK_CHECK_INCIDENT_SNAPSHOT_MIN_ATTACHMENT_COUNT:-0}}"
signoff_incident_snapshot_max_skipped_count="${PROD_PILOT_COHORT_QUICK_SIGNOFF_INCIDENT_SNAPSHOT_MAX_SKIPPED_COUNT:-${PROD_PILOT_COHORT_QUICK_CHECK_INCIDENT_SNAPSHOT_MAX_SKIPPED_COUNT:--1}}"

dashboard_enable="${PROD_PILOT_COHORT_QUICK_RUNBOOK_DASHBOARD_ENABLE:-1}"
dashboard_fail_close="${PROD_PILOT_COHORT_QUICK_RUNBOOK_DASHBOARD_FAIL_CLOSE:-0}"
dashboard_print="${PROD_PILOT_COHORT_QUICK_RUNBOOK_DASHBOARD_PRINT:-1}"
dashboard_print_summary_json="${PROD_PILOT_COHORT_QUICK_RUNBOOK_DASHBOARD_PRINT_SUMMARY_JSON:-0}"
show_json="${PROD_PILOT_COHORT_QUICK_RUNBOOK_SHOW_JSON:-0}"

declare -a quick_extra_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bootstrap-directory)
      bootstrap_directory="${2:-}"
      shift 2
      ;;
    --subject)
      subject="${2:-}"
      shift 2
      ;;
    --pre-real-host-readiness)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        pre_real_host_readiness="${2:-}"
        shift 2
      else
        pre_real_host_readiness="1"
        shift
      fi
      ;;
    --pre-real-host-readiness-summary-json)
      pre_real_host_readiness_summary_json="${2:-}"
      shift 2
      ;;
    --rounds)
      rounds="${2:-}"
      shift 2
      ;;
    --pause-sec)
      pause_sec="${2:-}"
      shift 2
      ;;
    --continue-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        continue_on_fail="${2:-}"
        shift 2
      else
        continue_on_fail="1"
        shift
      fi
      ;;
    --require-all-rounds-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_all_rounds_ok="${2:-}"
        shift 2
      else
        require_all_rounds_ok="1"
        shift
      fi
      ;;
    --max-round-failures)
      max_round_failures="${2:-}"
      shift 2
      ;;
    --trend-min-go-rate-pct)
      trend_min_go_rate_pct="${2:-}"
      shift 2
      ;;
    --max-alert-severity)
      max_alert_severity="${2:-}"
      shift 2
      ;;
    --bundle-outputs)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        bundle_outputs="${2:-}"
        shift 2
      else
        bundle_outputs="1"
        shift
      fi
      ;;
    --bundle-fail-close)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        bundle_fail_close="${2:-}"
        shift 2
      else
        bundle_fail_close="1"
        shift
      fi
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --run-report-json)
      run_report_json="${2:-}"
      shift 2
      ;;
    --signoff-json)
      signoff_json="${2:-}"
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
    --dashboard-md)
      dashboard_md="${2:-}"
      shift 2
      ;;
    --signoff-max-reports)
      signoff_max_reports="${2:-}"
      shift 2
      ;;
    --signoff-since-hours)
      signoff_since_hours="${2:-}"
      shift 2
      ;;
    --signoff-fail-on-any-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_fail_on_any_no_go="${2:-}"
        shift 2
      else
        signoff_fail_on_any_no_go="1"
        shift
      fi
      ;;
    --signoff-min-go-rate-pct)
      signoff_min_go_rate_pct="${2:-}"
      shift 2
      ;;
    --signoff-require-cohort-signoff-policy)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_cohort_signoff_policy="${2:-}"
        shift 2
      else
        signoff_require_cohort_signoff_policy="1"
        shift
      fi
      ;;
    --signoff-require-trend-artifact-policy-match)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_trend_artifact_policy_match="${2:-}"
        shift 2
      else
        signoff_require_trend_artifact_policy_match="1"
        shift
      fi
      ;;
    --signoff-require-trend-wg-validate-udp-source)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_trend_wg_validate_udp_source="${2:-}"
        shift 2
      else
        signoff_require_trend_wg_validate_udp_source="1"
        shift
      fi
      ;;
    --signoff-require-trend-wg-validate-strict-distinct)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_trend_wg_validate_strict_distinct="${2:-}"
        shift 2
      else
        signoff_require_trend_wg_validate_strict_distinct="1"
        shift
      fi
      ;;
    --signoff-require-trend-wg-soak-diversity-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_trend_wg_soak_diversity_pass="${2:-}"
        shift 2
      else
        signoff_require_trend_wg_soak_diversity_pass="1"
        shift
      fi
      ;;
    --signoff-min-trend-wg-soak-selection-lines)
      signoff_min_trend_wg_soak_selection_lines="${2:-}"
      shift 2
      ;;
    --signoff-min-trend-wg-soak-entry-operators)
      signoff_min_trend_wg_soak_entry_operators="${2:-}"
      shift 2
      ;;
    --signoff-min-trend-wg-soak-exit-operators)
      signoff_min_trend_wg_soak_exit_operators="${2:-}"
      shift 2
      ;;
    --signoff-min-trend-wg-soak-cross-operator-pairs)
      signoff_min_trend_wg_soak_cross_operator_pairs="${2:-}"
      shift 2
      ;;
    --signoff-require-incident-snapshot-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_incident_snapshot_on_fail="${2:-}"
        shift 2
      else
        signoff_require_incident_snapshot_on_fail="1"
        shift
      fi
      ;;
    --signoff-require-incident-snapshot-artifacts)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_incident_snapshot_artifacts="${2:-}"
        shift 2
      else
        signoff_require_incident_snapshot_artifacts="1"
        shift
      fi
      ;;
    --signoff-incident-snapshot-min-attachment-count)
      signoff_incident_snapshot_min_attachment_count="${2:-}"
      shift 2
      ;;
    --signoff-incident-snapshot-max-skipped-count)
      signoff_incident_snapshot_max_skipped_count="${2:-}"
      shift 2
      ;;
    --dashboard-enable)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dashboard_enable="${2:-}"
        shift 2
      else
        dashboard_enable="1"
        shift
      fi
      ;;
    --dashboard-fail-close)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dashboard_fail_close="${2:-}"
        shift 2
      else
        dashboard_fail_close="1"
        shift
      fi
      ;;
    --dashboard-print)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dashboard_print="${2:-}"
        shift 2
      else
        dashboard_print="1"
        shift
      fi
      ;;
    --dashboard-print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dashboard_print_summary_json="${2:-}"
        shift 2
      else
        dashboard_print_summary_json="1"
        shift
      fi
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
    --)
      shift
      if [[ $# -gt 0 ]]; then
        quick_extra_args=("$@")
      fi
      break
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

int_or_die "--rounds" "$rounds"
int_or_die "--pause-sec" "$pause_sec"
int_or_die "--max-round-failures" "$max_round_failures"
int_or_die "--signoff-max-reports" "$signoff_max_reports"
int_or_die "--signoff-since-hours" "$signoff_since_hours"
int_or_die "--signoff-min-trend-wg-soak-selection-lines" "$signoff_min_trend_wg_soak_selection_lines"
int_or_die "--signoff-min-trend-wg-soak-entry-operators" "$signoff_min_trend_wg_soak_entry_operators"
int_or_die "--signoff-min-trend-wg-soak-exit-operators" "$signoff_min_trend_wg_soak_exit_operators"
int_or_die "--signoff-min-trend-wg-soak-cross-operator-pairs" "$signoff_min_trend_wg_soak_cross_operator_pairs"
bool_or_die "--continue-on-fail" "$continue_on_fail"
bool_or_die "--require-all-rounds-ok" "$require_all_rounds_ok"
bool_or_die "--bundle-outputs" "$bundle_outputs"
bool_or_die "--bundle-fail-close" "$bundle_fail_close"
bool_or_die "--signoff-fail-on-any-no-go" "$signoff_fail_on_any_no_go"
bool_or_die "--signoff-require-cohort-signoff-policy" "$signoff_require_cohort_signoff_policy"
bool_or_die "--signoff-require-trend-artifact-policy-match" "$signoff_require_trend_artifact_policy_match"
bool_or_die "--signoff-require-trend-wg-validate-udp-source" "$signoff_require_trend_wg_validate_udp_source"
bool_or_die "--signoff-require-trend-wg-validate-strict-distinct" "$signoff_require_trend_wg_validate_strict_distinct"
bool_or_die "--signoff-require-trend-wg-soak-diversity-pass" "$signoff_require_trend_wg_soak_diversity_pass"
bool_or_die "--signoff-require-incident-snapshot-on-fail" "$signoff_require_incident_snapshot_on_fail"
bool_or_die "--signoff-require-incident-snapshot-artifacts" "$signoff_require_incident_snapshot_artifacts"
if [[ ! "$signoff_incident_snapshot_min_attachment_count" =~ ^[0-9]+$ ]]; then
  echo "--signoff-incident-snapshot-min-attachment-count must be an integer >= 0"
  exit 2
fi
if [[ ! "$signoff_incident_snapshot_max_skipped_count" =~ ^-?[0-9]+$ ]] || ((signoff_incident_snapshot_max_skipped_count < -1)); then
  echo "--signoff-incident-snapshot-max-skipped-count must be an integer >= -1"
  exit 2
fi
bool_or_die "--dashboard-enable" "$dashboard_enable"
bool_or_die "--dashboard-fail-close" "$dashboard_fail_close"
bool_or_die "--dashboard-print" "$dashboard_print"
bool_or_die "--dashboard-print-summary-json" "$dashboard_print_summary_json"
bool_or_die "--show-json" "$show_json"
bool_or_die "--pre-real-host-readiness" "$pre_real_host_readiness"

max_alert_severity="$(printf '%s' "$max_alert_severity" | tr '[:lower:]' '[:upper:]')"
if [[ "$max_alert_severity" != "OK" && "$max_alert_severity" != "WARN" && "$max_alert_severity" != "CRITICAL" ]]; then
  echo "--max-alert-severity must be OK, WARN, or CRITICAL"
  exit 2
fi

timestamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/prod_pilot_cohort_quick_runbook_${timestamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/prod_pilot_cohort_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$run_report_json" ]]; then
  run_report_json="$reports_dir/prod_pilot_cohort_quick_report.json"
else
  run_report_json="$(abs_path "$run_report_json")"
fi
if [[ -z "$signoff_json" ]]; then
  signoff_json="$reports_dir/prod_pilot_quick_signoff.json"
else
  signoff_json="$(abs_path "$signoff_json")"
fi
if [[ -z "$trend_summary_json" ]]; then
  trend_summary_json="$reports_dir/prod_pilot_quick_signoff_trend.json"
else
  trend_summary_json="$(abs_path "$trend_summary_json")"
fi
if [[ -z "$alert_summary_json" ]]; then
  alert_summary_json="$reports_dir/prod_pilot_quick_signoff_alert.json"
else
  alert_summary_json="$(abs_path "$alert_summary_json")"
fi
if [[ -z "$dashboard_md" ]]; then
  dashboard_md="$reports_dir/prod_pilot_quick_dashboard.md"
else
  dashboard_md="$(abs_path "$dashboard_md")"
fi
if [[ -z "$pre_real_host_readiness_summary_json" ]]; then
  pre_real_host_readiness_summary_json="$reports_dir/pre_real_host_readiness_summary.json"
else
  pre_real_host_readiness_summary_json="$(abs_path "$pre_real_host_readiness_summary_json")"
fi

mkdir -p "$reports_dir" "$(dirname "$summary_json")" "$(dirname "$run_report_json")" "$(dirname "$signoff_json")" "$(dirname "$trend_summary_json")" "$(dirname "$alert_summary_json")" "$(dirname "$dashboard_md")" "$(dirname "$pre_real_host_readiness_summary_json")"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_epoch="$(date -u +%s)"
quick_rc=0
quick_signoff_rc=0
quick_dashboard_rc=0
status="ok"
failure_step=""
final_rc=0
dashboard_require_cohort_signoff_policy="$signoff_require_cohort_signoff_policy"

quick_cmd=(
  "$EASY_NODE_SH" "prod-pilot-cohort-quick"
  --pre-real-host-readiness "$pre_real_host_readiness"
  --pre-real-host-readiness-summary-json "$pre_real_host_readiness_summary_json"
  --rounds "$rounds"
  --pause-sec "$pause_sec"
  --continue-on-fail "$continue_on_fail"
  --require-all-rounds-ok "$require_all_rounds_ok"
  --max-round-failures "$max_round_failures"
  --trend-min-go-rate-pct "$trend_min_go_rate_pct"
  --max-alert-severity "$max_alert_severity"
  --bundle-outputs "$bundle_outputs"
  --bundle-fail-close "$bundle_fail_close"
  --reports-dir "$reports_dir"
  --summary-json "$summary_json"
  --run-report-json "$run_report_json"
  --signoff-require-trend-artifact-policy-match "$signoff_require_trend_artifact_policy_match"
  --signoff-require-trend-wg-validate-udp-source "$signoff_require_trend_wg_validate_udp_source"
  --signoff-require-trend-wg-validate-strict-distinct "$signoff_require_trend_wg_validate_strict_distinct"
  --signoff-require-trend-wg-soak-diversity-pass "$signoff_require_trend_wg_soak_diversity_pass"
  --signoff-min-trend-wg-soak-selection-lines "$signoff_min_trend_wg_soak_selection_lines"
  --signoff-min-trend-wg-soak-entry-operators "$signoff_min_trend_wg_soak_entry_operators"
  --signoff-min-trend-wg-soak-exit-operators "$signoff_min_trend_wg_soak_exit_operators"
  --signoff-min-trend-wg-soak-cross-operator-pairs "$signoff_min_trend_wg_soak_cross_operator_pairs"
  --signoff-require-incident-snapshot-on-fail "$signoff_require_incident_snapshot_on_fail"
  --signoff-require-incident-snapshot-artifacts "$signoff_require_incident_snapshot_artifacts"
  --signoff-incident-snapshot-min-attachment-count "$signoff_incident_snapshot_min_attachment_count"
  --signoff-incident-snapshot-max-skipped-count "$signoff_incident_snapshot_max_skipped_count"
  --print-run-report "$show_json"
  --show-json "$show_json"
)
if [[ -n "$bootstrap_directory" ]]; then
  quick_cmd+=(--bootstrap-directory "$bootstrap_directory")
fi
if [[ -n "$subject" ]]; then
  quick_cmd+=(--subject "$subject")
fi
if [[ "${#quick_extra_args[@]}" -gt 0 ]]; then
  quick_cmd+=(-- "${quick_extra_args[@]}")
fi

echo "[prod-pilot-cohort-quick-runbook] stage=quick"
set +e
"${quick_cmd[@]}"
quick_rc=$?
set -e

if [[ "$quick_rc" -ne 0 && ! -f "$run_report_json" ]]; then
  status="fail"
  failure_step="quick_missing_report"
  final_rc="$quick_rc"
fi

if [[ "$status" == "ok" || -f "$run_report_json" ]]; then
  signoff_cmd=(
    "$EASY_NODE_SH" "prod-pilot-cohort-quick-signoff"
    --run-report-json "$run_report_json"
    --reports-dir "$reports_dir"
    --max-reports "$signoff_max_reports"
    --since-hours "$signoff_since_hours"
    --fail-on-any-no-go "$signoff_fail_on_any_no_go"
    --min-go-rate-pct "$signoff_min_go_rate_pct"
    --require-cohort-signoff-policy "$signoff_require_cohort_signoff_policy"
    --require-trend-artifact-policy-match "$signoff_require_trend_artifact_policy_match"
    --require-trend-wg-validate-udp-source "$signoff_require_trend_wg_validate_udp_source"
    --require-trend-wg-validate-strict-distinct "$signoff_require_trend_wg_validate_strict_distinct"
    --require-trend-wg-soak-diversity-pass "$signoff_require_trend_wg_soak_diversity_pass"
    --min-trend-wg-soak-selection-lines "$signoff_min_trend_wg_soak_selection_lines"
    --min-trend-wg-soak-entry-operators "$signoff_min_trend_wg_soak_entry_operators"
    --min-trend-wg-soak-exit-operators "$signoff_min_trend_wg_soak_exit_operators"
    --min-trend-wg-soak-cross-operator-pairs "$signoff_min_trend_wg_soak_cross_operator_pairs"
    --require-bundle-created "$bundle_outputs"
    --require-bundle-manifest "$bundle_outputs"
    --require-incident-snapshot-on-fail "$signoff_require_incident_snapshot_on_fail"
    --require-incident-snapshot-artifacts "$signoff_require_incident_snapshot_artifacts"
    --incident-snapshot-min-attachment-count "$signoff_incident_snapshot_min_attachment_count"
    --incident-snapshot-max-skipped-count "$signoff_incident_snapshot_max_skipped_count"
    --max-alert-severity "$max_alert_severity"
    --trend-summary-json "$trend_summary_json"
    --alert-summary-json "$alert_summary_json"
    --signoff-json "$signoff_json"
    --show-json "$show_json"
  )
  echo "[prod-pilot-cohort-quick-runbook] stage=quick-signoff"
  set +e
  "${signoff_cmd[@]}"
  quick_signoff_rc=$?
  set -e

  if [[ "$quick_signoff_rc" -ne 0 ]]; then
    status="fail"
    failure_step="quick_signoff"
    final_rc="$quick_signoff_rc"
  elif [[ "$quick_rc" -ne 0 ]]; then
    status="fail"
    failure_step="quick"
    final_rc="$quick_rc"
  fi
fi

if [[ "$dashboard_enable" == "1" ]]; then
  if [[ "$bundle_outputs" == "0" && "$dashboard_require_cohort_signoff_policy" == "1" ]]; then
    dashboard_require_cohort_signoff_policy="0"
    echo "[prod-pilot-cohort-quick-runbook] note: bundle-outputs=0; forcing dashboard cohort-policy check off"
  fi
  dashboard_cmd=(
    "$EASY_NODE_SH" "prod-pilot-cohort-quick-dashboard"
    --run-report-json "$run_report_json"
    --reports-dir "$reports_dir"
    --max-reports "$signoff_max_reports"
    --since-hours "$signoff_since_hours"
    --min-go-rate-pct "$signoff_min_go_rate_pct"
    --require-cohort-signoff-policy "$dashboard_require_cohort_signoff_policy"
    --require-incident-snapshot-on-fail "$signoff_require_incident_snapshot_on_fail"
    --require-incident-snapshot-artifacts "$signoff_require_incident_snapshot_artifacts"
    --incident-snapshot-min-attachment-count "$signoff_incident_snapshot_min_attachment_count"
    --incident-snapshot-max-skipped-count "$signoff_incident_snapshot_max_skipped_count"
    --warn-go-rate-pct 98
    --critical-go-rate-pct 90
    --warn-no-go-count 1
    --critical-no-go-count 2
    --warn-eval-errors 1
    --critical-eval-errors 2
    --trend-summary-json "$trend_summary_json"
    --alert-summary-json "$alert_summary_json"
    --dashboard-md "$dashboard_md"
    --print-dashboard "$dashboard_print"
    --print-summary-json "$dashboard_print_summary_json"
  )
  echo "[prod-pilot-cohort-quick-runbook] stage=quick-dashboard"
  set +e
  "${dashboard_cmd[@]}"
  quick_dashboard_rc=$?
  set -e
  if [[ "$quick_dashboard_rc" -ne 0 && "$dashboard_fail_close" == "1" && "$status" == "ok" ]]; then
    status="fail"
    failure_step="quick_dashboard"
    final_rc="$quick_dashboard_rc"
  fi
fi

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
finished_epoch="$(date -u +%s)"
duration_sec=$((finished_epoch - started_epoch))
if [[ "$duration_sec" -lt 0 ]]; then
  duration_sec=0
fi

incident_source_summary_json=""
incident_source_summary_exists=0
incident_source_summary_valid_json=0
incident_source_run_report=""
incident_source_run_report_exists=0
incident_enabled=0
incident_status=""
incident_bundle_dir=""
incident_bundle_dir_exists=0
incident_bundle_tar=""
incident_bundle_tar_exists=0
incident_summary_handoff_json=""
incident_summary_exists=0
incident_summary_valid_json=0
incident_report_md=""
incident_report_exists=0

if [[ "$(path_exists01_runbook "$signoff_json")" == "1" && "$(json_valid01_runbook "$signoff_json")" == "1" ]]; then
  incident_source_summary_json="$(abs_path "$(json_string_runbook "$signoff_json" '.incident_snapshot.source_summary_json.path')")"
  incident_source_summary_exists="$(path_exists01_runbook "$incident_source_summary_json")"
  incident_source_summary_valid_json="$(json_valid01_runbook "$incident_source_summary_json")"
  incident_source_run_report="$(abs_path "$(json_string_runbook "$signoff_json" '.incident_snapshot.source_run_report_json.path')")"
  incident_source_run_report_exists="$(path_exists01_runbook "$incident_source_run_report")"
  incident_enabled="$(json_bool01_runbook "$signoff_json" '.incident_snapshot.enabled')"
  incident_status="$(json_string_runbook "$signoff_json" '.incident_snapshot.status')"
  incident_bundle_dir="$(abs_path "$(json_string_runbook "$signoff_json" '.incident_snapshot.bundle_dir.path')")"
  incident_bundle_dir_exists="$(path_exists01_runbook "$incident_bundle_dir")"
  incident_bundle_tar="$(abs_path "$(json_string_runbook "$signoff_json" '.incident_snapshot.bundle_tar.path')")"
  incident_bundle_tar_exists="$(path_exists01_runbook "$incident_bundle_tar")"
  incident_summary_handoff_json="$(abs_path "$(json_string_runbook "$signoff_json" '.incident_snapshot.summary_json.path')")"
  incident_summary_exists="$(path_exists01_runbook "$incident_summary_handoff_json")"
  incident_summary_valid_json="$(json_valid01_runbook "$incident_summary_handoff_json")"
  incident_report_md="$(abs_path "$(json_string_runbook "$signoff_json" '.incident_snapshot.report_md.path')")"
  incident_report_exists="$(path_exists01_runbook "$incident_report_md")"
fi

summary_json_path="$reports_dir/prod_pilot_cohort_quick_runbook_summary.json"
jq -nc \
  --arg started_at "$started_at" \
  --arg finished_at "$finished_at" \
  --arg status "$status" \
  --arg failure_step "$failure_step" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg run_report_json "$run_report_json" \
  --arg signoff_json "$signoff_json" \
  --arg trend_summary_json "$trend_summary_json" \
  --arg alert_summary_json "$alert_summary_json" \
  --arg dashboard_md "$dashboard_md" \
  --arg pre_real_host_readiness_summary_json "$pre_real_host_readiness_summary_json" \
  --arg runbook_summary_json "$summary_json_path" \
  --arg max_alert_severity "$max_alert_severity" \
  --arg incident_source_summary_json "$incident_source_summary_json" \
  --arg incident_source_run_report "$incident_source_run_report" \
  --arg incident_status "$incident_status" \
  --arg incident_bundle_dir "$incident_bundle_dir" \
  --arg incident_bundle_tar "$incident_bundle_tar" \
  --arg incident_summary_json "$incident_summary_handoff_json" \
  --arg incident_report_md "$incident_report_md" \
  --argjson rounds "$rounds" \
  --argjson pause_sec "$pause_sec" \
  --argjson pre_real_host_readiness "$pre_real_host_readiness" \
  --argjson continue_on_fail "$continue_on_fail" \
  --argjson require_all_rounds_ok "$require_all_rounds_ok" \
  --argjson max_round_failures "$max_round_failures" \
  --argjson trend_min_go_rate_pct "$trend_min_go_rate_pct" \
  --argjson signoff_max_reports "$signoff_max_reports" \
  --argjson signoff_since_hours "$signoff_since_hours" \
  --argjson signoff_fail_on_any_no_go "$signoff_fail_on_any_no_go" \
  --argjson signoff_min_go_rate_pct "$signoff_min_go_rate_pct" \
  --argjson signoff_require_cohort_signoff_policy "$signoff_require_cohort_signoff_policy" \
  --argjson dashboard_require_cohort_signoff_policy "$dashboard_require_cohort_signoff_policy" \
  --argjson signoff_require_trend_artifact_policy_match "$signoff_require_trend_artifact_policy_match" \
  --argjson signoff_require_trend_wg_validate_udp_source "$signoff_require_trend_wg_validate_udp_source" \
  --argjson signoff_require_trend_wg_validate_strict_distinct "$signoff_require_trend_wg_validate_strict_distinct" \
  --argjson signoff_require_trend_wg_soak_diversity_pass "$signoff_require_trend_wg_soak_diversity_pass" \
  --argjson signoff_min_trend_wg_soak_selection_lines "$signoff_min_trend_wg_soak_selection_lines" \
  --argjson signoff_min_trend_wg_soak_entry_operators "$signoff_min_trend_wg_soak_entry_operators" \
  --argjson signoff_min_trend_wg_soak_exit_operators "$signoff_min_trend_wg_soak_exit_operators" \
  --argjson signoff_min_trend_wg_soak_cross_operator_pairs "$signoff_min_trend_wg_soak_cross_operator_pairs" \
  --argjson signoff_require_incident_snapshot_on_fail "$signoff_require_incident_snapshot_on_fail" \
  --argjson signoff_require_incident_snapshot_artifacts "$signoff_require_incident_snapshot_artifacts" \
  --argjson signoff_incident_snapshot_min_attachment_count "$signoff_incident_snapshot_min_attachment_count" \
  --argjson signoff_incident_snapshot_max_skipped_count "$signoff_incident_snapshot_max_skipped_count" \
  --argjson bundle_outputs "$bundle_outputs" \
  --argjson bundle_fail_close "$bundle_fail_close" \
  --argjson dashboard_enable "$dashboard_enable" \
  --argjson dashboard_fail_close "$dashboard_fail_close" \
  --argjson dashboard_print "$dashboard_print" \
  --argjson dashboard_print_summary_json "$dashboard_print_summary_json" \
  --argjson quick_rc "$quick_rc" \
  --argjson quick_signoff_rc "$quick_signoff_rc" \
  --argjson quick_dashboard_rc "$quick_dashboard_rc" \
  --argjson final_rc "$final_rc" \
  --argjson duration_sec "$duration_sec" \
  --argjson incident_source_summary_exists "$incident_source_summary_exists" \
  --argjson incident_source_summary_valid_json "$incident_source_summary_valid_json" \
  --argjson incident_source_run_report_exists "$incident_source_run_report_exists" \
  --argjson incident_enabled "$incident_enabled" \
  --argjson incident_bundle_dir_exists "$incident_bundle_dir_exists" \
  --argjson incident_bundle_tar_exists "$incident_bundle_tar_exists" \
  --argjson incident_summary_exists "$incident_summary_exists" \
  --argjson incident_summary_valid_json "$incident_summary_valid_json" \
  --argjson incident_report_exists "$incident_report_exists" \
  '{
    version: 1,
    started_at: $started_at,
    finished_at: $finished_at,
    duration_sec: $duration_sec,
    status: $status,
    failure_step: ($failure_step // ""),
    final_rc: $final_rc,
    stages: {
      quick: {rc: $quick_rc},
      quick_signoff: {rc: $quick_signoff_rc},
      quick_dashboard: {enabled: $dashboard_enable, rc: $quick_dashboard_rc}
    },
    config: {
      rounds: $rounds,
      pause_sec: $pause_sec,
      pre_real_host_readiness: $pre_real_host_readiness,
      continue_on_fail: $continue_on_fail,
      require_all_rounds_ok: $require_all_rounds_ok,
      max_round_failures: $max_round_failures,
      trend_min_go_rate_pct: $trend_min_go_rate_pct,
      max_alert_severity: $max_alert_severity,
      bundle_outputs: $bundle_outputs,
      bundle_fail_close: $bundle_fail_close,
      signoff_max_reports: $signoff_max_reports,
      signoff_since_hours: $signoff_since_hours,
      signoff_fail_on_any_no_go: $signoff_fail_on_any_no_go,
      signoff_min_go_rate_pct: $signoff_min_go_rate_pct,
      signoff_require_cohort_signoff_policy: $signoff_require_cohort_signoff_policy,
      dashboard_require_cohort_signoff_policy: $dashboard_require_cohort_signoff_policy,
      signoff_require_trend_artifact_policy_match: $signoff_require_trend_artifact_policy_match,
      signoff_require_trend_wg_validate_udp_source: $signoff_require_trend_wg_validate_udp_source,
      signoff_require_trend_wg_validate_strict_distinct: $signoff_require_trend_wg_validate_strict_distinct,
      signoff_require_trend_wg_soak_diversity_pass: $signoff_require_trend_wg_soak_diversity_pass,
      signoff_min_trend_wg_soak_selection_lines: $signoff_min_trend_wg_soak_selection_lines,
      signoff_min_trend_wg_soak_entry_operators: $signoff_min_trend_wg_soak_entry_operators,
      signoff_min_trend_wg_soak_exit_operators: $signoff_min_trend_wg_soak_exit_operators,
      signoff_min_trend_wg_soak_cross_operator_pairs: $signoff_min_trend_wg_soak_cross_operator_pairs,
      signoff_require_incident_snapshot_on_fail: $signoff_require_incident_snapshot_on_fail,
      signoff_require_incident_snapshot_artifacts: $signoff_require_incident_snapshot_artifacts,
      signoff_incident_snapshot_min_attachment_count: $signoff_incident_snapshot_min_attachment_count,
      signoff_incident_snapshot_max_skipped_count: $signoff_incident_snapshot_max_skipped_count,
      dashboard_enable: $dashboard_enable,
      dashboard_fail_close: $dashboard_fail_close,
      dashboard_print: $dashboard_print,
      dashboard_print_summary_json: $dashboard_print_summary_json
    },
    incident_snapshot: {
      source_summary_json: {path: ($incident_source_summary_json // ""), exists: $incident_source_summary_exists, valid_json: $incident_source_summary_valid_json},
      source_run_report_json: {path: ($incident_source_run_report // ""), exists: $incident_source_run_report_exists},
      enabled: $incident_enabled,
      status: ($incident_status // ""),
      bundle_dir: {path: ($incident_bundle_dir // ""), exists: $incident_bundle_dir_exists},
      bundle_tar: {path: ($incident_bundle_tar // ""), exists: $incident_bundle_tar_exists},
      summary_json: {path: ($incident_summary_json // ""), exists: $incident_summary_exists, valid_json: $incident_summary_valid_json},
      report_md: {path: ($incident_report_md // ""), exists: $incident_report_exists}
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      run_report_json: $run_report_json,
      signoff_json: $signoff_json,
      trend_summary_json: $trend_summary_json,
      alert_summary_json: $alert_summary_json,
      dashboard_md: $dashboard_md,
      pre_real_host_readiness_summary_json: $pre_real_host_readiness_summary_json,
      runbook_summary_json: $runbook_summary_json
    }
  }' >"$summary_json_path"

echo "[prod-pilot-cohort-quick-runbook] pre_real_host_readiness_summary_json=$pre_real_host_readiness_summary_json"
echo "[prod-pilot-cohort-quick-runbook] runbook_summary_json=$summary_json_path status=$status"
if [[ -n "$incident_source_run_report" || -n "$incident_summary_handoff_json" || -n "$incident_report_md" ]]; then
  echo "[prod-pilot-cohort-quick-runbook] incident_handoff source_run_report=${incident_source_run_report:-unset} summary_json=${incident_summary_handoff_json:-unset} report_md=${incident_report_md:-unset}"
fi
if [[ "$show_json" == "1" ]]; then
  cat "$summary_json_path"
fi

if [[ "$status" == "ok" ]]; then
  exit 0
fi
exit "$final_rc"
