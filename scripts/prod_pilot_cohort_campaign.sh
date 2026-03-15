#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EASY_NODE_SH="${EASY_NODE_SH:-$ROOT_DIR/scripts/easy_node.sh}"
CAMPAIGN_SUMMARY_SCRIPT="${PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_campaign_summary.sh}"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
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

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_campaign.sh \
    [--pre-real-host-readiness [0|1]] \
    [--pre-real-host-readiness-summary-json PATH] \
    [--campaign-summary-json PATH] \
    [--campaign-report-md PATH] \
    [--campaign-print-report [0|1]] \
    [--campaign-print-summary-json [0|1]] \
    [--campaign-summary-fail-close [0|1]] \
    [prod-pilot-cohort-quick-runbook args...]

Purpose:
  One-command sustained pilot campaign wrapper for machine C.
  Runs easy-node `prod-pilot-cohort-quick-runbook` with operator-safe defaults:
  - sustained multi-round campaign defaults
  - strict signoff trend/WG evidence policy
  - fail-closed bundle artifact generation
  - dashboard artifact generation enabled
  - deterministic campaign artifact paths under one reports directory
  - concise campaign markdown + JSON handoff summary generation

Examples:
  ./scripts/prod_pilot_cohort_campaign.sh \
    --bootstrap-directory https://A_HOST:8081 \
    --subject pilot-client

  ./scripts/prod_pilot_cohort_campaign.sh \
    --bootstrap-directory https://A_HOST:8081 \
    --subject pilot-client \
    --reports-dir .easy-node-logs/prod_campaign_manual \
    --show-json 1

Notes:
  - Quick-runbook flags are appended last and can override defaults.
  - Wrapper-only `--campaign-*` flags control the generated handoff report.
  - Set EASY_NODE_SH to point at a custom easy-node wrapper if needed.
USAGE
}

if [[ $# -gt 0 ]]; then
  case "${1:-}" in
    -h|--help|help)
      usage
      exit 0
      ;;
  esac
fi

if [[ ! -x "$EASY_NODE_SH" ]]; then
  echo "missing executable easy_node script: $EASY_NODE_SH"
  exit 2
fi
if [[ ! -x "$CAMPAIGN_SUMMARY_SCRIPT" ]]; then
  echo "missing executable campaign summary script: $CAMPAIGN_SUMMARY_SCRIPT"
  exit 2
fi

timestamp="$(date +%Y%m%d_%H%M%S)"

declare -a user_args=("$@")
declare -a quick_args=()
user_reports_dir=""
user_summary_json=""
user_run_report_json=""
user_signoff_json=""
user_trend_summary_json=""
user_alert_summary_json=""
user_dashboard_md=""
user_campaign_summary_json=""
user_campaign_report_md=""
user_campaign_print_report=""
user_campaign_print_summary_json=""
user_campaign_summary_fail_close=""
user_pre_real_host_readiness=""
user_pre_real_host_readiness_summary_json=""

idx=0
while ((idx < ${#user_args[@]})); do
  arg="${user_args[idx]}"
  case "$arg" in
    --reports-dir)
      if ((idx + 1 < ${#user_args[@]})); then
        user_reports_dir="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --summary-json)
      if ((idx + 1 < ${#user_args[@]})); then
        user_summary_json="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --run-report-json)
      if ((idx + 1 < ${#user_args[@]})); then
        user_run_report_json="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --signoff-json)
      if ((idx + 1 < ${#user_args[@]})); then
        user_signoff_json="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --trend-summary-json)
      if ((idx + 1 < ${#user_args[@]})); then
        user_trend_summary_json="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --alert-summary-json)
      if ((idx + 1 < ${#user_args[@]})); then
        user_alert_summary_json="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --dashboard-md)
      if ((idx + 1 < ${#user_args[@]})); then
        user_dashboard_md="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --campaign-summary-json)
      if ((idx + 1 < ${#user_args[@]})); then
        user_campaign_summary_json="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --pre-real-host-readiness)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_pre_real_host_readiness="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_pre_real_host_readiness="1"
        idx=$((idx + 1))
      fi
      ;;
    --pre-real-host-readiness-summary-json)
      if ((idx + 1 < ${#user_args[@]})); then
        user_pre_real_host_readiness_summary_json="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --campaign-report-md)
      if ((idx + 1 < ${#user_args[@]})); then
        user_campaign_report_md="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --campaign-print-report)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_print_report="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_print_report="1"
        idx=$((idx + 1))
      fi
      ;;
    --campaign-print-summary-json)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_print_summary_json="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_print_summary_json="1"
        idx=$((idx + 1))
      fi
      ;;
    --campaign-summary-fail-close)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_summary_fail_close="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_summary_fail_close="1"
        idx=$((idx + 1))
      fi
      ;;
    *)
      quick_args+=("$arg")
      if ((idx + 1 < ${#user_args[@]})); then
        next="${user_args[$((idx + 1))]}"
        case "$arg" in
          --reports-dir|--summary-json|--run-report-json|--signoff-json|--trend-summary-json|--alert-summary-json|--dashboard-md|--bootstrap-directory|--subject|--rounds|--pause-sec|--continue-on-fail|--require-all-rounds-ok|--max-round-failures|--trend-min-go-rate-pct|--max-alert-severity|--bundle-outputs|--bundle-fail-close|--signoff-max-reports|--signoff-since-hours|--signoff-fail-on-any-no-go|--signoff-min-go-rate-pct|--signoff-require-cohort-signoff-policy|--signoff-require-trend-artifact-policy-match|--signoff-require-trend-wg-validate-udp-source|--signoff-require-trend-wg-validate-strict-distinct|--signoff-require-trend-wg-soak-diversity-pass|--signoff-min-trend-wg-soak-selection-lines|--signoff-min-trend-wg-soak-entry-operators|--signoff-min-trend-wg-soak-exit-operators|--signoff-min-trend-wg-soak-cross-operator-pairs|--signoff-require-incident-snapshot-on-fail|--signoff-require-incident-snapshot-artifacts|--dashboard-enable|--dashboard-fail-close|--dashboard-print|--dashboard-print-summary-json|--show-json)
            quick_args+=("$next")
            idx=$((idx + 2))
            continue
            ;;
        esac
      fi
      idx=$((idx + 1))
      ;;
  esac
done

rounds="${PROD_PILOT_COHORT_CAMPAIGN_ROUNDS:-6}"
pause_sec="${PROD_PILOT_COHORT_CAMPAIGN_PAUSE_SEC:-45}"
continue_on_fail="${PROD_PILOT_COHORT_CAMPAIGN_CONTINUE_ON_FAIL:-1}"
require_all_rounds_ok="${PROD_PILOT_COHORT_CAMPAIGN_REQUIRE_ALL_ROUNDS_OK:-1}"
max_round_failures="${PROD_PILOT_COHORT_CAMPAIGN_MAX_ROUND_FAILURES:-0}"
trend_min_go_rate_pct="${PROD_PILOT_COHORT_CAMPAIGN_TREND_MIN_GO_RATE_PCT:-95}"
max_alert_severity="${PROD_PILOT_COHORT_CAMPAIGN_MAX_ALERT_SEVERITY:-WARN}"
bundle_outputs="${PROD_PILOT_COHORT_CAMPAIGN_BUNDLE_OUTPUTS:-1}"
bundle_fail_close="${PROD_PILOT_COHORT_CAMPAIGN_BUNDLE_FAIL_CLOSE:-1}"
signoff_max_reports="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_MAX_REPORTS:-25}"
signoff_since_hours="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_SINCE_HOURS:-24}"
signoff_fail_on_any_no_go="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_FAIL_ON_ANY_NO_GO:-0}"
signoff_min_go_rate_pct="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_MIN_GO_RATE_PCT:-95}"
dashboard_enable="${PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_ENABLE:-1}"
dashboard_fail_close="${PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_FAIL_CLOSE:-0}"
dashboard_print="${PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_PRINT:-1}"
dashboard_print_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_PRINT_SUMMARY_JSON:-0}"
show_json="${PROD_PILOT_COHORT_CAMPAIGN_SHOW_JSON:-0}"
pre_real_host_readiness="${user_pre_real_host_readiness:-${PROD_PILOT_COHORT_CAMPAIGN_PRE_REAL_HOST_READINESS:-1}}"
pre_real_host_readiness_summary_json_override="${user_pre_real_host_readiness_summary_json:-${PROD_PILOT_COHORT_CAMPAIGN_PRE_REAL_HOST_READINESS_SUMMARY_JSON:-}}"
campaign_print_report="${user_campaign_print_report:-${PROD_PILOT_COHORT_CAMPAIGN_PRINT_REPORT:-1}}"
campaign_print_summary_json="${user_campaign_print_summary_json:-${PROD_PILOT_COHORT_CAMPAIGN_PRINT_SUMMARY_JSON:-0}}"
campaign_summary_fail_close="${user_campaign_summary_fail_close:-${PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_FAIL_CLOSE:-1}}"
reports_dir_override="${PROD_PILOT_COHORT_CAMPAIGN_REPORTS_DIR:-}"
summary_json_override="${PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_JSON:-}"
run_report_json_override="${PROD_PILOT_COHORT_CAMPAIGN_RUN_REPORT_JSON:-}"
signoff_json_override="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_JSON:-}"
trend_summary_json_override="${PROD_PILOT_COHORT_CAMPAIGN_TREND_SUMMARY_JSON:-}"
alert_summary_json_override="${PROD_PILOT_COHORT_CAMPAIGN_ALERT_SUMMARY_JSON:-}"
dashboard_md_override="${PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_MD:-}"
campaign_summary_json_override="${PROD_PILOT_COHORT_CAMPAIGN_CAMPAIGN_SUMMARY_JSON:-}"
campaign_report_md_override="${PROD_PILOT_COHORT_CAMPAIGN_CAMPAIGN_REPORT_MD:-}"

int_or_die "PROD_PILOT_COHORT_CAMPAIGN_ROUNDS" "$rounds"
int_or_die "PROD_PILOT_COHORT_CAMPAIGN_PAUSE_SEC" "$pause_sec"
int_or_die "PROD_PILOT_COHORT_CAMPAIGN_MAX_ROUND_FAILURES" "$max_round_failures"
int_or_die "PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_MAX_REPORTS" "$signoff_max_reports"
int_or_die "PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_SINCE_HOURS" "$signoff_since_hours"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_CONTINUE_ON_FAIL" "$continue_on_fail"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_REQUIRE_ALL_ROUNDS_OK" "$require_all_rounds_ok"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_BUNDLE_OUTPUTS" "$bundle_outputs"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_BUNDLE_FAIL_CLOSE" "$bundle_fail_close"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_FAIL_ON_ANY_NO_GO" "$signoff_fail_on_any_no_go"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_ENABLE" "$dashboard_enable"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_FAIL_CLOSE" "$dashboard_fail_close"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_PRINT" "$dashboard_print"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_PRINT_SUMMARY_JSON" "$dashboard_print_summary_json"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_SHOW_JSON" "$show_json"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_PRE_REAL_HOST_READINESS" "$pre_real_host_readiness"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_PRINT_REPORT" "$campaign_print_report"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_PRINT_SUMMARY_JSON" "$campaign_print_summary_json"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_FAIL_CLOSE" "$campaign_summary_fail_close"

if [[ -n "$reports_dir_override" ]]; then
  reports_dir="$(abs_path "$reports_dir_override")"
elif [[ -n "$user_reports_dir" ]]; then
  reports_dir="$(abs_path "$user_reports_dir")"
else
  reports_dir="$(default_log_dir)/prod_pilot_cohort_campaign_${timestamp}"
fi

summary_json="$(abs_path "${summary_json_override:-${user_summary_json:-$reports_dir/prod_pilot_cohort_summary.json}}")"
run_report_json="$(abs_path "${run_report_json_override:-${user_run_report_json:-$reports_dir/prod_pilot_cohort_quick_report.json}}")"
signoff_json="$(abs_path "${signoff_json_override:-${user_signoff_json:-$reports_dir/prod_pilot_quick_signoff.json}}")"
trend_summary_json="$(abs_path "${trend_summary_json_override:-${user_trend_summary_json:-$reports_dir/prod_pilot_quick_signoff_trend.json}}")"
alert_summary_json="$(abs_path "${alert_summary_json_override:-${user_alert_summary_json:-$reports_dir/prod_pilot_quick_signoff_alert.json}}")"
dashboard_md="$(abs_path "${dashboard_md_override:-${user_dashboard_md:-$reports_dir/prod_pilot_quick_dashboard.md}}")"
campaign_summary_json="$(abs_path "${campaign_summary_json_override:-${user_campaign_summary_json:-$reports_dir/prod_pilot_campaign_summary.json}}")"
campaign_report_md="$(abs_path "${campaign_report_md_override:-${user_campaign_report_md:-$reports_dir/prod_pilot_campaign_summary.md}}")"
pre_real_host_readiness_summary_json="$(abs_path "${pre_real_host_readiness_summary_json_override:-$reports_dir/pre_real_host_readiness_summary.json}")"
runbook_summary_json="$reports_dir/prod_pilot_cohort_quick_runbook_summary.json"

mkdir -p "$reports_dir"

declare -a cmd=(
  "$EASY_NODE_SH" "prod-pilot-cohort-quick-runbook"
  --rounds "$rounds"
  --pause-sec "$pause_sec"
  --continue-on-fail "$continue_on_fail"
  --require-all-rounds-ok "$require_all_rounds_ok"
  --max-round-failures "$max_round_failures"
  --trend-min-go-rate-pct "$trend_min_go_rate_pct"
  --max-alert-severity "$max_alert_severity"
  --bundle-outputs "$bundle_outputs"
  --bundle-fail-close "$bundle_fail_close"
  --pre-real-host-readiness "$pre_real_host_readiness"
  --pre-real-host-readiness-summary-json "$pre_real_host_readiness_summary_json"
  --reports-dir "$reports_dir"
  --summary-json "$summary_json"
  --run-report-json "$run_report_json"
  --signoff-json "$signoff_json"
  --trend-summary-json "$trend_summary_json"
  --alert-summary-json "$alert_summary_json"
  --dashboard-md "$dashboard_md"
  --signoff-max-reports "$signoff_max_reports"
  --signoff-since-hours "$signoff_since_hours"
  --signoff-fail-on-any-no-go "$signoff_fail_on_any_no_go"
  --signoff-min-go-rate-pct "$signoff_min_go_rate_pct"
  --signoff-require-cohort-signoff-policy 1
  --signoff-require-trend-artifact-policy-match 1
  --signoff-require-trend-wg-validate-udp-source 1
  --signoff-require-trend-wg-validate-strict-distinct 1
  --signoff-require-trend-wg-soak-diversity-pass 1
  --signoff-min-trend-wg-soak-selection-lines 12
  --signoff-min-trend-wg-soak-entry-operators 2
  --signoff-min-trend-wg-soak-exit-operators 2
  --signoff-min-trend-wg-soak-cross-operator-pairs 2
  --signoff-require-incident-snapshot-on-fail 1
  --signoff-require-incident-snapshot-artifacts 1
  --dashboard-enable "$dashboard_enable"
  --dashboard-fail-close "$dashboard_fail_close"
  --dashboard-print "$dashboard_print"
  --dashboard-print-summary-json "$dashboard_print_summary_json"
  --show-json "$show_json"
)

if [[ "${#quick_args[@]}" -gt 0 ]]; then
  cmd+=("${quick_args[@]}")
fi

echo "[prod-pilot-cohort-campaign] running sustained pilot campaign"
echo "[prod-pilot-cohort-campaign] reports_dir=$reports_dir"
echo "[prod-pilot-cohort-campaign] pre_real_host_readiness_summary_json=$pre_real_host_readiness_summary_json"
echo "[prod-pilot-cohort-campaign] summary_json=$summary_json"
echo "[prod-pilot-cohort-campaign] run_report_json=$run_report_json"
echo "[prod-pilot-cohort-campaign] campaign_summary_json=$campaign_summary_json"
echo "[prod-pilot-cohort-campaign] campaign_report_md=$campaign_report_md"

quick_runbook_rc=0
campaign_summary_rc=0
final_rc=0

set +e
"${cmd[@]}"
quick_runbook_rc=$?
set -e
final_rc="$quick_runbook_rc"

if [[ -f "$runbook_summary_json" ]]; then
  summary_cmd=(
    "$CAMPAIGN_SUMMARY_SCRIPT"
    --runbook-summary-json "$runbook_summary_json"
    --summary-json "$campaign_summary_json"
    --report-md "$campaign_report_md"
    --print-report "$campaign_print_report"
    --print-summary-json "$campaign_print_summary_json"
    --fail-on-no-go "$campaign_summary_fail_close"
  )
  echo "[prod-pilot-cohort-campaign] stage=campaign-summary"
  set +e
  "${summary_cmd[@]}"
  campaign_summary_rc=$?
  set -e
  if [[ "$campaign_summary_rc" -ne 0 && "$campaign_summary_fail_close" == "1" && "$final_rc" -eq 0 ]]; then
    final_rc="$campaign_summary_rc"
  fi
elif [[ "$campaign_summary_fail_close" == "1" && "$final_rc" -eq 0 ]]; then
  echo "missing expected runbook summary artifact: $runbook_summary_json"
  final_rc=1
fi

exit "$final_rc"
