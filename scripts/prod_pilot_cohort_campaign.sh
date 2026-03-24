#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EASY_NODE_SH="${EASY_NODE_SH:-$ROOT_DIR/scripts/easy_node.sh}"
CAMPAIGN_SUMMARY_SCRIPT="${PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_campaign_summary.sh}"
CAMPAIGN_SIGNOFF_SCRIPT="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_campaign_signoff.sh}"

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

require_distinct_paths_or_die() {
  local left_label="$1"
  local left_path="$2"
  local right_label="$3"
  local right_path="$4"
  if [[ -n "$left_path" && -n "$right_path" && "$left_path" == "$right_path" ]]; then
    echo "invalid configuration: $left_label and $right_label resolve to the same path: $left_path"
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
    [--campaign-run-report-json PATH] \
    [--campaign-signoff-check [0|1]] \
    [--campaign-signoff-required [0|1]] \
    [--campaign-signoff-summary-json PATH] \
    [--campaign-signoff-print-summary-json [0|1]] \
    [--campaign-signoff-refresh-summary [0|1]] \
    [--campaign-signoff-summary-fail-on-no-go [0|1]] \
    [--campaign-print-report [0|1]] \
    [--campaign-print-run-report [0|1]] \
    [--campaign-print-summary-json [0|1]] \
    [--campaign-summary-fail-close [0|1]] \
    [--campaign-run-report-required [0|1]] \
    [--campaign-run-report-json-required [0|1]] \
    [--campaign-require-incident-snapshot-on-fail [0|1]] \
    [--campaign-require-incident-snapshot-artifacts [0|1]] \
    [--campaign-incident-snapshot-min-attachment-count N] \
    [--campaign-incident-snapshot-max-skipped-count N|-1] \
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
  - optional inline campaign-signoff policy gate with summary artifact output

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
  - Inline campaign signoff is enabled by default (`--campaign-signoff-check 1`).
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

for cmd in bash date jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

if [[ ! -x "$EASY_NODE_SH" ]]; then
  echo "missing executable easy_node script: $EASY_NODE_SH"
  exit 2
fi
if [[ ! -x "$CAMPAIGN_SUMMARY_SCRIPT" ]]; then
  echo "missing executable campaign summary script: $CAMPAIGN_SUMMARY_SCRIPT"
  exit 2
fi
if [[ ! -r "$CAMPAIGN_SIGNOFF_SCRIPT" ]]; then
  echo "missing readable campaign signoff script: $CAMPAIGN_SIGNOFF_SCRIPT"
  exit 2
fi

timestamp="$(date +%Y%m%d_%H%M%S)"
started_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_epoch="$(date -u +%s)"

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
user_campaign_run_report_json=""
user_campaign_signoff_check=""
user_campaign_signoff_required=""
user_campaign_signoff_summary_json=""
user_campaign_signoff_print_summary_json=""
user_campaign_signoff_refresh_summary=""
user_campaign_signoff_summary_fail_on_no_go=""
user_campaign_print_report=""
user_campaign_print_run_report=""
user_campaign_print_summary_json=""
user_campaign_summary_fail_close=""
user_campaign_run_report_required=""
user_campaign_run_report_json_required=""
user_campaign_require_incident_snapshot_on_fail=""
user_campaign_require_incident_snapshot_artifacts=""
user_campaign_incident_snapshot_min_attachment_count=""
user_campaign_incident_snapshot_max_skipped_count=""
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
    --campaign-run-report-json)
      if ((idx + 1 < ${#user_args[@]})); then
        user_campaign_run_report_json="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --campaign-signoff-check)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_signoff_check="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_signoff_check="1"
        idx=$((idx + 1))
      fi
      ;;
    --campaign-signoff-required)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_signoff_required="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_signoff_required="1"
        idx=$((idx + 1))
      fi
      ;;
    --campaign-signoff-summary-json)
      if ((idx + 1 < ${#user_args[@]})); then
        user_campaign_signoff_summary_json="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --campaign-signoff-print-summary-json)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_signoff_print_summary_json="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_signoff_print_summary_json="1"
        idx=$((idx + 1))
      fi
      ;;
    --campaign-signoff-refresh-summary)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_signoff_refresh_summary="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_signoff_refresh_summary="1"
        idx=$((idx + 1))
      fi
      ;;
    --campaign-signoff-summary-fail-on-no-go)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_signoff_summary_fail_on_no_go="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_signoff_summary_fail_on_no_go="1"
        idx=$((idx + 1))
      fi
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
    --campaign-print-run-report)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_print_run_report="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_print_run_report="1"
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
    --campaign-run-report-required)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_run_report_required="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_run_report_required="1"
        idx=$((idx + 1))
      fi
      ;;
    --campaign-run-report-json-required)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_run_report_json_required="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_run_report_json_required="1"
        idx=$((idx + 1))
      fi
      ;;
    --campaign-require-incident-snapshot-on-fail)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_require_incident_snapshot_on_fail="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_require_incident_snapshot_on_fail="1"
        idx=$((idx + 1))
      fi
      ;;
    --campaign-require-incident-snapshot-artifacts)
      if ((idx + 1 < ${#user_args[@]} && ( "${user_args[$((idx + 1))]}" == "0" || "${user_args[$((idx + 1))]}" == "1" ) )); then
        user_campaign_require_incident_snapshot_artifacts="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_campaign_require_incident_snapshot_artifacts="1"
        idx=$((idx + 1))
      fi
      ;;
    --campaign-incident-snapshot-min-attachment-count)
      if ((idx + 1 < ${#user_args[@]})); then
        user_campaign_incident_snapshot_min_attachment_count="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    --campaign-incident-snapshot-max-skipped-count)
      if ((idx + 1 < ${#user_args[@]})); then
        user_campaign_incident_snapshot_max_skipped_count="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    *)
      quick_args+=("$arg")
      if ((idx + 1 < ${#user_args[@]})); then
        next="${user_args[$((idx + 1))]}"
        case "$arg" in
          --reports-dir|--summary-json|--run-report-json|--signoff-json|--trend-summary-json|--alert-summary-json|--dashboard-md|--bootstrap-directory|--subject|--rounds|--pause-sec|--continue-on-fail|--require-all-rounds-ok|--max-round-failures|--trend-min-go-rate-pct|--max-alert-severity|--bundle-outputs|--bundle-fail-close|--signoff-max-reports|--signoff-since-hours|--signoff-fail-on-any-no-go|--signoff-min-go-rate-pct|--signoff-require-cohort-signoff-policy|--signoff-require-trend-artifact-policy-match|--signoff-require-trend-wg-validate-udp-source|--signoff-require-trend-wg-validate-strict-distinct|--signoff-require-trend-wg-soak-diversity-pass|--signoff-min-trend-wg-soak-selection-lines|--signoff-min-trend-wg-soak-entry-operators|--signoff-min-trend-wg-soak-exit-operators|--signoff-min-trend-wg-soak-cross-operator-pairs|--signoff-require-incident-snapshot-on-fail|--signoff-require-incident-snapshot-artifacts|--signoff-incident-snapshot-min-attachment-count|--signoff-incident-snapshot-max-skipped-count|--dashboard-enable|--dashboard-fail-close|--dashboard-print|--dashboard-print-summary-json|--show-json)
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
signoff_incident_snapshot_min_attachment_count="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_INCIDENT_SNAPSHOT_MIN_ATTACHMENT_COUNT:-1}"
signoff_incident_snapshot_max_skipped_count="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_INCIDENT_SNAPSHOT_MAX_SKIPPED_COUNT:-0}"
dashboard_enable="${PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_ENABLE:-1}"
dashboard_fail_close="${PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_FAIL_CLOSE:-0}"
dashboard_print="${PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_PRINT:-1}"
dashboard_print_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_PRINT_SUMMARY_JSON:-0}"
show_json="${PROD_PILOT_COHORT_CAMPAIGN_SHOW_JSON:-0}"
pre_real_host_readiness="${user_pre_real_host_readiness:-${PROD_PILOT_COHORT_CAMPAIGN_PRE_REAL_HOST_READINESS:-1}}"
pre_real_host_readiness_summary_json_override="${user_pre_real_host_readiness_summary_json:-${PROD_PILOT_COHORT_CAMPAIGN_PRE_REAL_HOST_READINESS_SUMMARY_JSON:-}}"
campaign_print_report="${user_campaign_print_report:-${PROD_PILOT_COHORT_CAMPAIGN_PRINT_REPORT:-1}}"
campaign_print_run_report="${user_campaign_print_run_report:-${PROD_PILOT_COHORT_CAMPAIGN_PRINT_RUN_REPORT:-0}}"
campaign_print_summary_json="${user_campaign_print_summary_json:-${PROD_PILOT_COHORT_CAMPAIGN_PRINT_SUMMARY_JSON:-0}}"
campaign_summary_fail_close="${user_campaign_summary_fail_close:-${PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_FAIL_CLOSE:-1}}"
campaign_run_report_required="${user_campaign_run_report_required:-${PROD_PILOT_COHORT_CAMPAIGN_RUN_REPORT_REQUIRED:-1}}"
campaign_run_report_json_required="${user_campaign_run_report_json_required:-${PROD_PILOT_COHORT_CAMPAIGN_RUN_REPORT_JSON_REQUIRED:-1}}"
campaign_require_incident_snapshot_on_fail="${user_campaign_require_incident_snapshot_on_fail:-${PROD_PILOT_COHORT_CAMPAIGN_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-1}}"
campaign_require_incident_snapshot_artifacts="${user_campaign_require_incident_snapshot_artifacts:-${PROD_PILOT_COHORT_CAMPAIGN_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-1}}"
campaign_incident_snapshot_min_attachment_count="${user_campaign_incident_snapshot_min_attachment_count:-${PROD_PILOT_COHORT_CAMPAIGN_INCIDENT_SNAPSHOT_MIN_ATTACHMENT_COUNT:-1}}"
campaign_incident_snapshot_max_skipped_count="${user_campaign_incident_snapshot_max_skipped_count:-${PROD_PILOT_COHORT_CAMPAIGN_INCIDENT_SNAPSHOT_MAX_SKIPPED_COUNT:-0}}"
campaign_signoff_check="${user_campaign_signoff_check:-${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_CHECK:-1}}"
campaign_signoff_required="${user_campaign_signoff_required:-${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRED:-1}}"
campaign_signoff_refresh_summary="${user_campaign_signoff_refresh_summary:-${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REFRESH_SUMMARY:-0}}"
campaign_signoff_summary_fail_on_no_go="${user_campaign_signoff_summary_fail_on_no_go:-${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_SUMMARY_FAIL_ON_NO_GO:-$campaign_summary_fail_close}}"
campaign_signoff_print_summary_json="${user_campaign_signoff_print_summary_json:-${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_PRINT_SUMMARY_JSON:-0}}"
reports_dir_override="${PROD_PILOT_COHORT_CAMPAIGN_REPORTS_DIR:-}"
summary_json_override="${PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_JSON:-}"
run_report_json_override="${PROD_PILOT_COHORT_CAMPAIGN_RUN_REPORT_JSON:-}"
signoff_json_override="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_JSON:-}"
trend_summary_json_override="${PROD_PILOT_COHORT_CAMPAIGN_TREND_SUMMARY_JSON:-}"
alert_summary_json_override="${PROD_PILOT_COHORT_CAMPAIGN_ALERT_SUMMARY_JSON:-}"
dashboard_md_override="${PROD_PILOT_COHORT_CAMPAIGN_DASHBOARD_MD:-}"
campaign_summary_json_override="${PROD_PILOT_COHORT_CAMPAIGN_CAMPAIGN_SUMMARY_JSON:-}"
campaign_report_md_override="${PROD_PILOT_COHORT_CAMPAIGN_CAMPAIGN_REPORT_MD:-}"
campaign_run_report_json_override="${PROD_PILOT_COHORT_CAMPAIGN_CAMPAIGN_RUN_REPORT_JSON:-}"
campaign_signoff_summary_json_override="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_SUMMARY_JSON:-}"

int_or_die "PROD_PILOT_COHORT_CAMPAIGN_ROUNDS" "$rounds"
int_or_die "PROD_PILOT_COHORT_CAMPAIGN_PAUSE_SEC" "$pause_sec"
int_or_die "PROD_PILOT_COHORT_CAMPAIGN_MAX_ROUND_FAILURES" "$max_round_failures"
int_or_die "PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_MAX_REPORTS" "$signoff_max_reports"
int_or_die "PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_SINCE_HOURS" "$signoff_since_hours"
int_or_die "PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_INCIDENT_SNAPSHOT_MIN_ATTACHMENT_COUNT" "$signoff_incident_snapshot_min_attachment_count"
if [[ ! "$signoff_incident_snapshot_max_skipped_count" =~ ^-?[0-9]+$ ]] || ((signoff_incident_snapshot_max_skipped_count < -1)); then
  echo "PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_INCIDENT_SNAPSHOT_MAX_SKIPPED_COUNT must be an integer >= -1"
  exit 2
fi
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
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_PRINT_RUN_REPORT" "$campaign_print_run_report"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_PRINT_SUMMARY_JSON" "$campaign_print_summary_json"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_FAIL_CLOSE" "$campaign_summary_fail_close"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_RUN_REPORT_REQUIRED" "$campaign_run_report_required"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_RUN_REPORT_JSON_REQUIRED" "$campaign_run_report_json_required"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL" "$campaign_require_incident_snapshot_on_fail"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS" "$campaign_require_incident_snapshot_artifacts"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_CHECK" "$campaign_signoff_check"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRED" "$campaign_signoff_required"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REFRESH_SUMMARY" "$campaign_signoff_refresh_summary"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_SUMMARY_FAIL_ON_NO_GO" "$campaign_signoff_summary_fail_on_no_go"
bool_or_die "PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_PRINT_SUMMARY_JSON" "$campaign_signoff_print_summary_json"
int_or_die "PROD_PILOT_COHORT_CAMPAIGN_INCIDENT_SNAPSHOT_MIN_ATTACHMENT_COUNT" "$campaign_incident_snapshot_min_attachment_count"
if [[ ! "$campaign_incident_snapshot_max_skipped_count" =~ ^-?[0-9]+$ ]] || ((campaign_incident_snapshot_max_skipped_count < -1)); then
  echo "PROD_PILOT_COHORT_CAMPAIGN_INCIDENT_SNAPSHOT_MAX_SKIPPED_COUNT must be an integer >= -1"
  exit 2
fi

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
campaign_run_report_json="$(abs_path "${campaign_run_report_json_override:-${user_campaign_run_report_json:-$reports_dir/prod_pilot_campaign_run_report.json}}")"
campaign_signoff_summary_json="$(abs_path "${campaign_signoff_summary_json_override:-${user_campaign_signoff_summary_json:-$reports_dir/prod_pilot_campaign_signoff_summary.json}}")"
pre_real_host_readiness_summary_json="$(abs_path "${pre_real_host_readiness_summary_json_override:-$reports_dir/pre_real_host_readiness_summary.json}")"
runbook_summary_json="$reports_dir/prod_pilot_cohort_quick_runbook_summary.json"

require_distinct_paths_or_die "campaign_run_report_json" "$campaign_run_report_json" "campaign_summary_json" "$campaign_summary_json"
require_distinct_paths_or_die "campaign_run_report_json" "$campaign_run_report_json" "campaign_signoff_summary_json" "$campaign_signoff_summary_json"
require_distinct_paths_or_die "campaign_summary_json" "$campaign_summary_json" "campaign_signoff_summary_json" "$campaign_signoff_summary_json"

mkdir -p "$reports_dir" "$(dirname "$campaign_run_report_json")"

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
  --signoff-incident-snapshot-min-attachment-count "$signoff_incident_snapshot_min_attachment_count"
  --signoff-incident-snapshot-max-skipped-count "$signoff_incident_snapshot_max_skipped_count"
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
echo "[prod-pilot-cohort-campaign] campaign_run_report_json=$campaign_run_report_json"
echo "[prod-pilot-cohort-campaign] campaign_signoff_summary_json=$campaign_signoff_summary_json"

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
    --require-incident-snapshot-on-fail "$campaign_require_incident_snapshot_on_fail"
    --require-incident-snapshot-artifacts "$campaign_require_incident_snapshot_artifacts"
    --incident-snapshot-min-attachment-count "$campaign_incident_snapshot_min_attachment_count"
    --incident-snapshot-max-skipped-count "$campaign_incident_snapshot_max_skipped_count"
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

campaign_signoff_attempted=0
campaign_signoff_rc=0
campaign_summary_attempted=0
if [[ -f "$runbook_summary_json" ]]; then
  campaign_summary_attempted=1
fi

runbook_summary_exists=0
runbook_summary_valid_json=0
pre_real_host_readiness_summary_exists=0
pre_real_host_readiness_summary_valid_json=0
quick_summary_exists=0
quick_summary_valid_json=0
quick_run_report_exists=0
quick_run_report_valid_json=0
signoff_json_exists=0
signoff_json_valid_json=0
trend_summary_exists=0
trend_summary_valid_json=0
alert_summary_exists=0
alert_summary_valid_json=0
dashboard_md_exists=0
campaign_summary_exists=0
campaign_summary_valid_json=0
campaign_report_exists=0
campaign_signoff_summary_exists=0
campaign_signoff_summary_valid_json=0
finished_at_utc=""
duration_sec=0
status=""
failure_step=""

compute_campaign_status_fields() {
  finished_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local finished_epoch
  finished_epoch="$(date -u +%s)"
  duration_sec=$((finished_epoch - started_epoch))
  if [[ "$duration_sec" -lt 0 ]]; then
    duration_sec=0
  fi

  status="ok"
  failure_step=""
  if [[ "$final_rc" -ne 0 ]]; then
    status="fail"
    if [[ "$quick_runbook_rc" -ne 0 ]]; then
      failure_step="quick_runbook"
    elif [[ "$campaign_summary_rc" -ne 0 && "$campaign_summary_fail_close" == "1" ]]; then
      failure_step="campaign_summary"
    elif [[ "$campaign_signoff_check" == "1" && "$campaign_signoff_required" == "1" && "$campaign_signoff_rc" -ne 0 ]]; then
      failure_step="campaign_signoff"
    elif [[ "$campaign_summary_fail_close" == "1" && ! -f "$runbook_summary_json" ]]; then
      failure_step="campaign_summary_prereq"
    elif [[ "$campaign_signoff_check" == "1" && "$campaign_signoff_required" == "1" && "$campaign_signoff_attempted" != "1" ]]; then
      failure_step="campaign_signoff_prereq"
    else
      failure_step="unknown"
    fi
  fi
}

compute_campaign_artifact_flags() {
  runbook_summary_exists=0
  runbook_summary_valid_json=0
  if [[ -f "$runbook_summary_json" ]]; then
    runbook_summary_exists=1
    if jq -e . "$runbook_summary_json" >/dev/null 2>&1; then
      runbook_summary_valid_json=1
    fi
  fi

  pre_real_host_readiness_summary_exists=0
  pre_real_host_readiness_summary_valid_json=0
  if [[ -f "$pre_real_host_readiness_summary_json" ]]; then
    pre_real_host_readiness_summary_exists=1
    if jq -e . "$pre_real_host_readiness_summary_json" >/dev/null 2>&1; then
      pre_real_host_readiness_summary_valid_json=1
    fi
  fi

  quick_summary_exists=0
  quick_summary_valid_json=0
  if [[ -f "$summary_json" ]]; then
    quick_summary_exists=1
    if jq -e . "$summary_json" >/dev/null 2>&1; then
      quick_summary_valid_json=1
    fi
  fi

  quick_run_report_exists=0
  quick_run_report_valid_json=0
  if [[ -f "$run_report_json" ]]; then
    quick_run_report_exists=1
    if jq -e . "$run_report_json" >/dev/null 2>&1; then
      quick_run_report_valid_json=1
    fi
  fi

  signoff_json_exists=0
  signoff_json_valid_json=0
  if [[ -f "$signoff_json" ]]; then
    signoff_json_exists=1
    if jq -e . "$signoff_json" >/dev/null 2>&1; then
      signoff_json_valid_json=1
    fi
  fi

  trend_summary_exists=0
  trend_summary_valid_json=0
  if [[ -f "$trend_summary_json" ]]; then
    trend_summary_exists=1
    if jq -e . "$trend_summary_json" >/dev/null 2>&1; then
      trend_summary_valid_json=1
    fi
  fi

  alert_summary_exists=0
  alert_summary_valid_json=0
  if [[ -f "$alert_summary_json" ]]; then
    alert_summary_exists=1
    if jq -e . "$alert_summary_json" >/dev/null 2>&1; then
      alert_summary_valid_json=1
    fi
  fi

  dashboard_md_exists=0
  if [[ -f "$dashboard_md" ]]; then
    dashboard_md_exists=1
  fi

  campaign_summary_exists=0
  campaign_summary_valid_json=0
  if [[ -f "$campaign_summary_json" ]]; then
    campaign_summary_exists=1
    if jq -e . "$campaign_summary_json" >/dev/null 2>&1; then
      campaign_summary_valid_json=1
    fi
  fi

  campaign_report_exists=0
  if [[ -f "$campaign_report_md" ]]; then
    campaign_report_exists=1
  fi

  campaign_signoff_summary_exists=0
  campaign_signoff_summary_valid_json=0
  if [[ -f "$campaign_signoff_summary_json" ]]; then
    campaign_signoff_summary_exists=1
    if jq -e . "$campaign_signoff_summary_json" >/dev/null 2>&1; then
      campaign_signoff_summary_valid_json=1
    fi
  fi
}

write_campaign_run_report() {
  compute_campaign_status_fields
  compute_campaign_artifact_flags

  jq -nc \
    --arg started_at_utc "$started_at_utc" \
    --arg finished_at_utc "$finished_at_utc" \
    --arg status "$status" \
    --arg failure_step "$failure_step" \
    --arg reports_dir "$reports_dir" \
    --arg runbook_summary_json "$runbook_summary_json" \
    --arg pre_real_host_readiness_summary_json "$pre_real_host_readiness_summary_json" \
    --arg summary_json "$summary_json" \
    --arg run_report_json "$run_report_json" \
    --arg signoff_json "$signoff_json" \
    --arg trend_summary_json "$trend_summary_json" \
    --arg alert_summary_json "$alert_summary_json" \
    --arg dashboard_md "$dashboard_md" \
    --arg campaign_summary_json "$campaign_summary_json" \
    --arg campaign_report_md "$campaign_report_md" \
    --arg campaign_signoff_summary_json "$campaign_signoff_summary_json" \
    --arg campaign_run_report_json "$campaign_run_report_json" \
    --argjson duration_sec "$duration_sec" \
    --argjson final_rc "$final_rc" \
    --argjson quick_runbook_rc "$quick_runbook_rc" \
    --argjson campaign_summary_attempted "$campaign_summary_attempted" \
    --argjson campaign_summary_rc "$campaign_summary_rc" \
    --argjson campaign_signoff_check "$campaign_signoff_check" \
    --argjson campaign_signoff_required "$campaign_signoff_required" \
    --argjson campaign_signoff_attempted "$campaign_signoff_attempted" \
    --argjson campaign_signoff_rc "$campaign_signoff_rc" \
    --argjson campaign_summary_fail_close "$campaign_summary_fail_close" \
    --argjson campaign_signoff_refresh_summary "$campaign_signoff_refresh_summary" \
    --argjson campaign_signoff_summary_fail_on_no_go "$campaign_signoff_summary_fail_on_no_go" \
    --argjson campaign_signoff_print_summary_json "$campaign_signoff_print_summary_json" \
    --argjson campaign_run_report_required "$campaign_run_report_required" \
    --argjson campaign_run_report_json_required "$campaign_run_report_json_required" \
    --argjson campaign_require_incident_snapshot_on_fail "$campaign_require_incident_snapshot_on_fail" \
    --argjson campaign_require_incident_snapshot_artifacts "$campaign_require_incident_snapshot_artifacts" \
    --argjson campaign_incident_snapshot_min_attachment_count "$campaign_incident_snapshot_min_attachment_count" \
    --argjson campaign_incident_snapshot_max_skipped_count "$campaign_incident_snapshot_max_skipped_count" \
    --argjson runbook_summary_exists "$runbook_summary_exists" \
    --argjson runbook_summary_valid_json "$runbook_summary_valid_json" \
    --argjson pre_real_host_readiness_summary_exists "$pre_real_host_readiness_summary_exists" \
    --argjson pre_real_host_readiness_summary_valid_json "$pre_real_host_readiness_summary_valid_json" \
    --argjson quick_summary_exists "$quick_summary_exists" \
    --argjson quick_summary_valid_json "$quick_summary_valid_json" \
    --argjson quick_run_report_exists "$quick_run_report_exists" \
    --argjson quick_run_report_valid_json "$quick_run_report_valid_json" \
    --argjson signoff_json_exists "$signoff_json_exists" \
    --argjson signoff_json_valid_json "$signoff_json_valid_json" \
    --argjson trend_summary_exists "$trend_summary_exists" \
    --argjson trend_summary_valid_json "$trend_summary_valid_json" \
    --argjson alert_summary_exists "$alert_summary_exists" \
    --argjson alert_summary_valid_json "$alert_summary_valid_json" \
    --argjson dashboard_md_exists "$dashboard_md_exists" \
    --argjson campaign_summary_exists "$campaign_summary_exists" \
    --argjson campaign_summary_valid_json "$campaign_summary_valid_json" \
    --argjson campaign_report_exists "$campaign_report_exists" \
    --argjson campaign_signoff_summary_exists "$campaign_signoff_summary_exists" \
    --argjson campaign_signoff_summary_valid_json "$campaign_signoff_summary_valid_json" \
    '{
      version: 1,
      started_at_utc: $started_at_utc,
      finished_at_utc: $finished_at_utc,
      duration_sec: $duration_sec,
      status: $status,
      failure_step: $failure_step,
      final_rc: $final_rc,
      stages: {
        quick_runbook: {rc: $quick_runbook_rc},
        campaign_summary: {attempted: $campaign_summary_attempted, rc: $campaign_summary_rc},
        campaign_signoff: {enabled: $campaign_signoff_check, required: $campaign_signoff_required, attempted: $campaign_signoff_attempted, rc: $campaign_signoff_rc}
      },
      config: {
        campaign_summary_fail_close: $campaign_summary_fail_close,
        campaign_signoff_check: $campaign_signoff_check,
        campaign_signoff_required: $campaign_signoff_required,
        campaign_signoff_refresh_summary: $campaign_signoff_refresh_summary,
        campaign_signoff_summary_fail_on_no_go: $campaign_signoff_summary_fail_on_no_go,
        campaign_signoff_print_summary_json: $campaign_signoff_print_summary_json,
        campaign_run_report_required: $campaign_run_report_required,
        campaign_run_report_json_required: $campaign_run_report_json_required,
        require_incident_snapshot_on_fail: $campaign_require_incident_snapshot_on_fail,
        require_incident_snapshot_artifacts: $campaign_require_incident_snapshot_artifacts,
        incident_snapshot_min_attachment_count: $campaign_incident_snapshot_min_attachment_count,
        incident_snapshot_max_skipped_count: $campaign_incident_snapshot_max_skipped_count
      },
      artifacts: {
        reports_dir: {path: $reports_dir, exists: true},
        runbook_summary_json: {path: $runbook_summary_json, exists: $runbook_summary_exists, valid_json: $runbook_summary_valid_json},
        pre_real_host_readiness_summary_json: {path: $pre_real_host_readiness_summary_json, exists: $pre_real_host_readiness_summary_exists, valid_json: $pre_real_host_readiness_summary_valid_json},
        quick_summary_json: {path: $summary_json, exists: $quick_summary_exists, valid_json: $quick_summary_valid_json},
        quick_run_report_json: {path: $run_report_json, exists: $quick_run_report_exists, valid_json: $quick_run_report_valid_json},
        signoff_json: {path: $signoff_json, exists: $signoff_json_exists, valid_json: $signoff_json_valid_json},
        trend_summary_json: {path: $trend_summary_json, exists: $trend_summary_exists, valid_json: $trend_summary_valid_json},
        alert_summary_json: {path: $alert_summary_json, exists: $alert_summary_exists, valid_json: $alert_summary_valid_json},
        dashboard_md: {path: $dashboard_md, exists: $dashboard_md_exists},
        campaign_summary_json: {path: $campaign_summary_json, exists: $campaign_summary_exists, valid_json: $campaign_summary_valid_json},
        campaign_report_md: {path: $campaign_report_md, exists: $campaign_report_exists},
        campaign_signoff_summary_json: {path: $campaign_signoff_summary_json, exists: $campaign_signoff_summary_exists, valid_json: $campaign_signoff_summary_valid_json},
        campaign_run_report_json: {path: $campaign_run_report_json, exists: true}
      }
    }' >"$campaign_run_report_json"
}

if [[ "$campaign_signoff_check" == "1" ]]; then
  pre_signoff_run_report_rc=0
  set +e
  write_campaign_run_report
  pre_signoff_run_report_rc=$?
  set -e
  if [[ "$pre_signoff_run_report_rc" -ne 0 ]]; then
    echo "[prod-pilot-cohort-campaign] warning: failed to write pre-signoff campaign run report (rc=$pre_signoff_run_report_rc)"
  fi

  signoff_cmd=(
    bash "$CAMPAIGN_SIGNOFF_SCRIPT"
    --runbook-summary-json "$runbook_summary_json"
    --campaign-run-report-json "$campaign_run_report_json"
    --campaign-summary-json "$campaign_summary_json"
    --campaign-report-md "$campaign_report_md"
    --reports-dir "$reports_dir"
    --refresh-summary "$campaign_signoff_refresh_summary"
    --summary-fail-on-no-go "$campaign_signoff_summary_fail_on_no_go"
    --require-campaign-summary-fail-close "$campaign_summary_fail_close"
    --require-campaign-signoff-check "$campaign_signoff_check"
    --require-campaign-signoff-enabled "$campaign_signoff_check"
    --require-campaign-signoff-required "$campaign_signoff_required"
    --require-campaign-run-report-required "$campaign_run_report_required"
    --require-campaign-run-report-json-required "$campaign_run_report_json_required"
    --require-artifact-path-match 1
    --require-distinct-artifact-paths 1
    --require-incident-snapshot-on-fail "$campaign_require_incident_snapshot_on_fail"
    --require-incident-snapshot-artifacts "$campaign_require_incident_snapshot_artifacts"
    --incident-snapshot-min-attachment-count "$campaign_incident_snapshot_min_attachment_count"
    --incident-snapshot-max-skipped-count "$campaign_incident_snapshot_max_skipped_count"
    --summary-json "$campaign_signoff_summary_json"
    --print-summary-json "$campaign_signoff_print_summary_json"
    --show-json "$show_json"
  )
  campaign_signoff_attempted=1
  echo "[prod-pilot-cohort-campaign] stage=campaign-signoff"
  set +e
  "${signoff_cmd[@]}"
  campaign_signoff_rc=$?
  set -e
  if [[ "$campaign_signoff_rc" -ne 0 && "$campaign_signoff_required" == "1" && "$final_rc" -eq 0 ]]; then
    final_rc="$campaign_signoff_rc"
  fi
fi

campaign_run_report_gen_rc=0
set +e
write_campaign_run_report
campaign_run_report_gen_rc=$?
set -e

campaign_run_report_exists=0
campaign_run_report_valid_json=0
if [[ -f "$campaign_run_report_json" ]]; then
  campaign_run_report_exists=1
  if jq -e . "$campaign_run_report_json" >/dev/null 2>&1; then
    campaign_run_report_valid_json=1
  fi
fi

if [[ "$campaign_run_report_gen_rc" -ne 0 ]]; then
  echo "[prod-pilot-cohort-campaign] warning: failed to write campaign run report (rc=$campaign_run_report_gen_rc)"
fi
if [[ "$campaign_run_report_required" == "1" && "$campaign_run_report_exists" != "1" && "$final_rc" -eq 0 ]]; then
  echo "[prod-pilot-cohort-campaign] required campaign run report missing: $campaign_run_report_json"
  final_rc=1
fi
if [[ "$campaign_run_report_json_required" == "1" && "$campaign_run_report_valid_json" != "1" && "$final_rc" -eq 0 ]]; then
  echo "[prod-pilot-cohort-campaign] required campaign run report JSON invalid: $campaign_run_report_json"
  final_rc=1
fi

if [[ "$campaign_print_run_report" == "1" && "$campaign_run_report_exists" == "1" ]]; then
  cat "$campaign_run_report_json"
fi

exit "$final_rc"
