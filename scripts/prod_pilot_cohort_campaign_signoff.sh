#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CAMPAIGN_SUMMARY_SCRIPT="${PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_campaign_summary.sh}"
CAMPAIGN_CHECK_SCRIPT="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_campaign_check.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_campaign_signoff.sh \
    [--runbook-summary-json PATH] \
    [--campaign-run-report-json PATH] \
    [--campaign-summary-json PATH] \
    [--campaign-report-md PATH] \
    [--campaign-signoff-summary-json PATH] \
    [--reports-dir PATH] \
    [--refresh-summary [0|1]] \
    [--summary-fail-on-no-go [0|1]] \
    [--require-status-ok [0|1]] \
    [--require-quick-runbook-ok [0|1]] \
    [--require-runbook-summary-json [0|1]] \
    [--require-quick-run-report-json [0|1]] \
    [--require-campaign-summary-attempted [0|1]] \
    [--require-campaign-summary-ok [0|1]] \
    [--require-campaign-summary-json [0|1]] \
    [--require-campaign-summary-go [0|1]] \
    [--require-campaign-report-md [0|1]] \
    [--require-campaign-signoff-attempted [0|1]] \
    [--require-campaign-signoff-ok [0|1]] \
    [--require-campaign-signoff-enabled [0|1]] \
    [--require-campaign-signoff-required [0|1]] \
    [--require-campaign-signoff-summary-json [0|1]] \
    [--require-campaign-signoff-summary-json-valid [0|1]] \
    [--require-campaign-signoff-summary-status-ok [0|1]] \
    [--require-campaign-signoff-summary-final-rc-zero [0|1]] \
    [--require-campaign-summary-fail-close [0|1]] \
    [--require-campaign-signoff-check [0|1]] \
    [--require-campaign-run-report-required [0|1]] \
    [--require-campaign-run-report-json-required [0|1]] \
    [--require-artifact-path-match [0|1]] \
    [--require-distinct-artifact-paths [0|1]] \
    [--allow-summary-overwrite [0|1]] \
    [--require-summary-policy-match [0|1]] \
    [--require-incident-policy-clean [0|1]] \
    [--require-incident-snapshot-on-fail [0|1]] \
    [--require-incident-snapshot-artifacts [0|1]] \
    [--incident-snapshot-min-attachment-count N] \
    [--incident-snapshot-max-skipped-count N|-1] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--show-json [0|1]]

Purpose:
  Run campaign-summary (optional refresh) and campaign-check in one fail-closed command.
  Recommended input is --reports-dir from prod-pilot-cohort-campaign outputs.
USAGE
}

bool_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
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

runbook_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_RUNBOOK_SUMMARY_JSON:-}"
campaign_run_report_json="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_CAMPAIGN_RUN_REPORT_JSON:-}"
campaign_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_CAMPAIGN_SUMMARY_JSON:-}"
campaign_report_md="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_CAMPAIGN_REPORT_MD:-}"
campaign_signoff_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_CAMPAIGN_SIGNOFF_SUMMARY_JSON:-}"
reports_dir="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REPORTS_DIR:-}"
refresh_summary="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REFRESH_SUMMARY:-0}"
summary_fail_on_no_go="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_SUMMARY_FAIL_ON_NO_GO:-0}"

require_status_ok="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_STATUS_OK:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_STATUS_OK:-1}}"
require_quick_runbook_ok="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_QUICK_RUNBOOK_OK:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_QUICK_RUNBOOK_OK:-1}}"
require_runbook_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_RUNBOOK_SUMMARY_JSON:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_RUNBOOK_SUMMARY_JSON:-1}}"
require_quick_run_report_json="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_QUICK_RUN_REPORT_JSON:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_QUICK_RUN_REPORT_JSON:-1}}"
require_campaign_summary_attempted="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SUMMARY_ATTEMPTED:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SUMMARY_ATTEMPTED:-1}}"
require_campaign_summary_ok="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SUMMARY_OK:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SUMMARY_OK:-1}}"
require_campaign_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SUMMARY_JSON:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SUMMARY_JSON:-1}}"
require_campaign_summary_go="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SUMMARY_GO:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SUMMARY_GO:-1}}"
require_campaign_report_md="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_REPORT_MD:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_REPORT_MD:-1}}"
require_campaign_signoff_attempted="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SIGNOFF_ATTEMPTED:-0}"
require_campaign_signoff_ok="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SIGNOFF_OK:-0}"
require_campaign_signoff_enabled="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SIGNOFF_ENABLED:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_ENABLED:-0}}"
require_campaign_signoff_required="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SIGNOFF_REQUIRED:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_REQUIRED:-0}}"
require_campaign_signoff_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SIGNOFF_SUMMARY_JSON:-0}"
require_campaign_signoff_summary_json_valid="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SIGNOFF_SUMMARY_JSON_VALID:-0}"
require_campaign_signoff_summary_status_ok="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SIGNOFF_SUMMARY_STATUS_OK:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_SUMMARY_STATUS_OK:-0}}"
require_campaign_signoff_summary_final_rc_zero="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SIGNOFF_SUMMARY_FINAL_RC_ZERO:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_SUMMARY_FINAL_RC_ZERO:-0}}"
require_campaign_summary_fail_close="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SUMMARY_FAIL_CLOSE:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SUMMARY_FAIL_CLOSE:-1}}"
require_campaign_signoff_check="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_SIGNOFF_CHECK:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_CHECK:-1}}"
require_campaign_run_report_required="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_RUN_REPORT_REQUIRED:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_RUN_REPORT_REQUIRED:-1}}"
require_campaign_run_report_json_required="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_CAMPAIGN_RUN_REPORT_JSON_REQUIRED:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_RUN_REPORT_JSON_REQUIRED:-1}}"
require_artifact_path_match="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_ARTIFACT_PATH_MATCH:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_ARTIFACT_PATH_MATCH:-1}}"
require_distinct_artifact_paths="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_DISTINCT_ARTIFACT_PATHS:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_DISTINCT_ARTIFACT_PATHS:-1}}"
allow_summary_overwrite="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_ALLOW_SUMMARY_OVERWRITE:-0}"
require_summary_policy_match="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_SUMMARY_POLICY_MATCH:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_SUMMARY_POLICY_MATCH:-1}}"
require_incident_policy_clean="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_INCIDENT_POLICY_CLEAN:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_INCIDENT_POLICY_CLEAN:-1}}"
require_incident_snapshot_on_fail="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-1}}"
require_incident_snapshot_artifacts="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-1}}"
incident_snapshot_min_attachment_count="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_INCIDENT_SNAPSHOT_MIN_ATTACHMENT_COUNT:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_INCIDENT_SNAPSHOT_MIN_ATTACHMENT_COUNT:-1}}"
incident_snapshot_max_skipped_count="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_INCIDENT_SNAPSHOT_MAX_SKIPPED_COUNT:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_INCIDENT_SNAPSHOT_MAX_SKIPPED_COUNT:-0}}"
summary_json="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_SUMMARY_JSON:-}"
print_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_PRINT_SUMMARY_JSON:-0}"
show_json="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_SHOW_JSON:-${PROD_PILOT_COHORT_CAMPAIGN_CHECK_SHOW_JSON:-0}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runbook-summary-json)
      runbook_summary_json="${2:-}"
      shift 2
      ;;
    --campaign-run-report-json)
      campaign_run_report_json="${2:-}"
      shift 2
      ;;
    --campaign-summary-json)
      campaign_summary_json="${2:-}"
      shift 2
      ;;
    --campaign-report-md)
      campaign_report_md="${2:-}"
      shift 2
      ;;
    --campaign-signoff-summary-json)
      campaign_signoff_summary_json="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --refresh-summary)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_summary="${2:-}"
        shift 2
      else
        refresh_summary="1"
        shift
      fi
      ;;
    --summary-fail-on-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        summary_fail_on_no_go="${2:-}"
        shift 2
      else
        summary_fail_on_no_go="1"
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
    --require-quick-runbook-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_quick_runbook_ok="${2:-}"
        shift 2
      else
        require_quick_runbook_ok="1"
        shift
      fi
      ;;
    --require-runbook-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_runbook_summary_json="${2:-}"
        shift 2
      else
        require_runbook_summary_json="1"
        shift
      fi
      ;;
    --require-quick-run-report-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_quick_run_report_json="${2:-}"
        shift 2
      else
        require_quick_run_report_json="1"
        shift
      fi
      ;;
    --require-campaign-summary-attempted)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_summary_attempted="${2:-}"
        shift 2
      else
        require_campaign_summary_attempted="1"
        shift
      fi
      ;;
    --require-campaign-summary-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_summary_ok="${2:-}"
        shift 2
      else
        require_campaign_summary_ok="1"
        shift
      fi
      ;;
    --require-campaign-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_summary_json="${2:-}"
        shift 2
      else
        require_campaign_summary_json="1"
        shift
      fi
      ;;
    --require-campaign-summary-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_summary_go="${2:-}"
        shift 2
      else
        require_campaign_summary_go="1"
        shift
      fi
      ;;
    --require-campaign-report-md)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_report_md="${2:-}"
        shift 2
      else
        require_campaign_report_md="1"
        shift
      fi
      ;;
    --require-campaign-signoff-attempted)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_signoff_attempted="${2:-}"
        shift 2
      else
        require_campaign_signoff_attempted="1"
        shift
      fi
      ;;
    --require-campaign-signoff-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_signoff_ok="${2:-}"
        shift 2
      else
        require_campaign_signoff_ok="1"
        shift
      fi
      ;;
    --require-campaign-signoff-enabled)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_signoff_enabled="${2:-}"
        shift 2
      else
        require_campaign_signoff_enabled="1"
        shift
      fi
      ;;
    --require-campaign-signoff-required)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_signoff_required="${2:-}"
        shift 2
      else
        require_campaign_signoff_required="1"
        shift
      fi
      ;;
    --require-campaign-signoff-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_signoff_summary_json="${2:-}"
        shift 2
      else
        require_campaign_signoff_summary_json="1"
        shift
      fi
      ;;
    --require-campaign-signoff-summary-json-valid)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_signoff_summary_json_valid="${2:-}"
        shift 2
      else
        require_campaign_signoff_summary_json_valid="1"
        shift
      fi
      ;;
    --require-campaign-signoff-summary-status-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_signoff_summary_status_ok="${2:-}"
        shift 2
      else
        require_campaign_signoff_summary_status_ok="1"
        shift
      fi
      ;;
    --require-campaign-signoff-summary-final-rc-zero)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_signoff_summary_final_rc_zero="${2:-}"
        shift 2
      else
        require_campaign_signoff_summary_final_rc_zero="1"
        shift
      fi
      ;;
    --require-campaign-summary-fail-close)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_summary_fail_close="${2:-}"
        shift 2
      else
        require_campaign_summary_fail_close="1"
        shift
      fi
      ;;
    --require-campaign-signoff-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_signoff_check="${2:-}"
        shift 2
      else
        require_campaign_signoff_check="1"
        shift
      fi
      ;;
    --require-campaign-run-report-required)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_run_report_required="${2:-}"
        shift 2
      else
        require_campaign_run_report_required="1"
        shift
      fi
      ;;
    --require-campaign-run-report-json-required)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_campaign_run_report_json_required="${2:-}"
        shift 2
      else
        require_campaign_run_report_json_required="1"
        shift
      fi
      ;;
    --require-artifact-path-match)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_artifact_path_match="${2:-}"
        shift 2
      else
        require_artifact_path_match="1"
        shift
      fi
      ;;
    --require-distinct-artifact-paths)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_distinct_artifact_paths="${2:-}"
        shift 2
      else
        require_distinct_artifact_paths="1"
        shift
      fi
      ;;
    --require-summary-policy-match)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_summary_policy_match="${2:-}"
        shift 2
      else
        require_summary_policy_match="1"
        shift
      fi
      ;;
    --require-incident-policy-clean)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_incident_policy_clean="${2:-}"
        shift 2
      else
        require_incident_policy_clean="1"
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
    --incident-snapshot-min-attachment-count)
      incident_snapshot_min_attachment_count="${2:-}"
      shift 2
      ;;
    --incident-snapshot-max-skipped-count)
      incident_snapshot_max_skipped_count="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
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
    --show-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_json="${2:-}"
        shift 2
      else
        show_json="1"
        shift
      fi
      ;;
    --allow-summary-overwrite)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_summary_overwrite="${2:-}"
        shift 2
      else
        allow_summary_overwrite="1"
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

if [[ ! -r "$CAMPAIGN_SUMMARY_SCRIPT" ]]; then
  echo "missing readable campaign summary script: $CAMPAIGN_SUMMARY_SCRIPT"
  exit 2
fi
if [[ ! -r "$CAMPAIGN_CHECK_SCRIPT" ]]; then
  echo "missing readable campaign check script: $CAMPAIGN_CHECK_SCRIPT"
  exit 2
fi

bool_or_die "--refresh-summary" "$refresh_summary"
bool_or_die "--summary-fail-on-no-go" "$summary_fail_on_no_go"
bool_or_die "--require-status-ok" "$require_status_ok"
bool_or_die "--require-quick-runbook-ok" "$require_quick_runbook_ok"
bool_or_die "--require-runbook-summary-json" "$require_runbook_summary_json"
bool_or_die "--require-quick-run-report-json" "$require_quick_run_report_json"
bool_or_die "--require-campaign-summary-attempted" "$require_campaign_summary_attempted"
bool_or_die "--require-campaign-summary-ok" "$require_campaign_summary_ok"
bool_or_die "--require-campaign-summary-json" "$require_campaign_summary_json"
bool_or_die "--require-campaign-summary-go" "$require_campaign_summary_go"
bool_or_die "--require-campaign-report-md" "$require_campaign_report_md"
bool_or_die "--require-campaign-signoff-attempted" "$require_campaign_signoff_attempted"
bool_or_die "--require-campaign-signoff-ok" "$require_campaign_signoff_ok"
bool_or_die "--require-campaign-signoff-enabled" "$require_campaign_signoff_enabled"
bool_or_die "--require-campaign-signoff-required" "$require_campaign_signoff_required"
bool_or_die "--require-campaign-signoff-summary-json" "$require_campaign_signoff_summary_json"
bool_or_die "--require-campaign-signoff-summary-json-valid" "$require_campaign_signoff_summary_json_valid"
bool_or_die "--require-campaign-signoff-summary-status-ok" "$require_campaign_signoff_summary_status_ok"
bool_or_die "--require-campaign-signoff-summary-final-rc-zero" "$require_campaign_signoff_summary_final_rc_zero"
bool_or_die "--require-campaign-summary-fail-close" "$require_campaign_summary_fail_close"
bool_or_die "--require-campaign-signoff-check" "$require_campaign_signoff_check"
bool_or_die "--require-campaign-run-report-required" "$require_campaign_run_report_required"
bool_or_die "--require-campaign-run-report-json-required" "$require_campaign_run_report_json_required"
bool_or_die "--require-artifact-path-match" "$require_artifact_path_match"
bool_or_die "--require-distinct-artifact-paths" "$require_distinct_artifact_paths"
bool_or_die "--require-summary-policy-match" "$require_summary_policy_match"
bool_or_die "--require-incident-policy-clean" "$require_incident_policy_clean"
bool_or_die "--require-incident-snapshot-on-fail" "$require_incident_snapshot_on_fail"
bool_or_die "--require-incident-snapshot-artifacts" "$require_incident_snapshot_artifacts"
bool_or_die "--print-summary-json" "$print_summary_json"
bool_or_die "--show-json" "$show_json"
bool_or_die "--allow-summary-overwrite" "$allow_summary_overwrite"
if [[ ! "$incident_snapshot_min_attachment_count" =~ ^[0-9]+$ ]]; then
  echo "--incident-snapshot-min-attachment-count must be an integer >= 0"
  exit 2
fi
if [[ ! "$incident_snapshot_max_skipped_count" =~ ^-?[0-9]+$ ]] || ((incident_snapshot_max_skipped_count < -1)); then
  echo "--incident-snapshot-max-skipped-count must be an integer >= -1"
  exit 2
fi

runbook_summary_json="$(abs_path "$runbook_summary_json")"
campaign_run_report_json="$(abs_path "$campaign_run_report_json")"
campaign_summary_json="$(abs_path "$campaign_summary_json")"
campaign_report_md="$(abs_path "$campaign_report_md")"
campaign_signoff_summary_json="$(abs_path "$campaign_signoff_summary_json")"
reports_dir="$(abs_path "$reports_dir")"
summary_json="$(abs_path "$summary_json")"

if [[ "$allow_summary_overwrite" != "1" && -n "$summary_json" ]]; then
  if [[ -n "$campaign_signoff_summary_json" && "$summary_json" == "$campaign_signoff_summary_json" ]]; then
    echo "summary output path must differ from campaign signoff stage summary path (set --allow-summary-overwrite 1 to override)"
    exit 2
  fi
  if [[ -n "$campaign_summary_json" && "$summary_json" == "$campaign_summary_json" ]]; then
    echo "summary output path must differ from campaign summary JSON path (set --allow-summary-overwrite 1 to override)"
    exit 2
  fi
  if [[ -n "$campaign_run_report_json" && "$summary_json" == "$campaign_run_report_json" ]]; then
    echo "summary output path must differ from campaign run report JSON path (set --allow-summary-overwrite 1 to override)"
    exit 2
  fi
fi

declare -a summary_args=(
  --require-incident-snapshot-on-fail "$require_incident_snapshot_on_fail"
  --require-incident-snapshot-artifacts "$require_incident_snapshot_artifacts"
  --incident-snapshot-min-attachment-count "$incident_snapshot_min_attachment_count"
  --incident-snapshot-max-skipped-count "$incident_snapshot_max_skipped_count"
  --print-report 0
  --print-summary-json 0
  --fail-on-no-go "$summary_fail_on_no_go"
)
if [[ -n "$runbook_summary_json" ]]; then
  summary_args+=(--runbook-summary-json "$runbook_summary_json")
fi
if [[ -n "$reports_dir" ]]; then
  summary_args+=(--reports-dir "$reports_dir")
fi
if [[ -n "$campaign_summary_json" ]]; then
  summary_args+=(--summary-json "$campaign_summary_json")
fi
if [[ -n "$campaign_report_md" ]]; then
  summary_args+=(--report-md "$campaign_report_md")
fi

declare -a check_args=(
  --require-status-ok "$require_status_ok"
  --require-quick-runbook-ok "$require_quick_runbook_ok"
  --require-runbook-summary-json "$require_runbook_summary_json"
  --require-quick-run-report-json "$require_quick_run_report_json"
  --require-campaign-summary-attempted "$require_campaign_summary_attempted"
  --require-campaign-summary-ok "$require_campaign_summary_ok"
  --require-campaign-summary-json "$require_campaign_summary_json"
  --require-campaign-summary-go "$require_campaign_summary_go"
  --require-campaign-report-md "$require_campaign_report_md"
  --require-campaign-signoff-attempted "$require_campaign_signoff_attempted"
  --require-campaign-signoff-ok "$require_campaign_signoff_ok"
  --require-campaign-signoff-enabled "$require_campaign_signoff_enabled"
  --require-campaign-signoff-required "$require_campaign_signoff_required"
  --require-campaign-signoff-summary-json "$require_campaign_signoff_summary_json"
  --require-campaign-signoff-summary-json-valid "$require_campaign_signoff_summary_json_valid"
  --require-campaign-signoff-summary-status-ok "$require_campaign_signoff_summary_status_ok"
  --require-campaign-signoff-summary-final-rc-zero "$require_campaign_signoff_summary_final_rc_zero"
  --require-campaign-summary-fail-close "$require_campaign_summary_fail_close"
  --require-campaign-signoff-check "$require_campaign_signoff_check"
  --require-campaign-run-report-required "$require_campaign_run_report_required"
  --require-campaign-run-report-json-required "$require_campaign_run_report_json_required"
  --require-artifact-path-match "$require_artifact_path_match"
  --require-distinct-artifact-paths "$require_distinct_artifact_paths"
  --require-summary-policy-match "$require_summary_policy_match"
  --require-incident-policy-clean "$require_incident_policy_clean"
  --require-incident-snapshot-on-fail "$require_incident_snapshot_on_fail"
  --require-incident-snapshot-artifacts "$require_incident_snapshot_artifacts"
  --incident-snapshot-min-attachment-count "$incident_snapshot_min_attachment_count"
  --incident-snapshot-max-skipped-count "$incident_snapshot_max_skipped_count"
  --show-json "$show_json"
)
if [[ -n "$campaign_run_report_json" ]]; then
  check_args+=(--campaign-run-report-json "$campaign_run_report_json")
fi
if [[ -n "$campaign_summary_json" ]]; then
  check_args+=(--campaign-summary-json "$campaign_summary_json")
fi
if [[ -n "$campaign_report_md" ]]; then
  check_args+=(--campaign-report-md "$campaign_report_md")
fi
if [[ -n "$campaign_signoff_summary_json" ]]; then
  check_args+=(--campaign-signoff-summary-json "$campaign_signoff_summary_json")
fi
if [[ -n "$reports_dir" ]]; then
  check_args+=(--reports-dir "$reports_dir")
fi

summary_stage_attempted=0
summary_stage_rc=0
check_stage_attempted=0
check_stage_rc=0
failure_stage=""
status="ok"
final_rc=0

if [[ "$refresh_summary" == "1" ]]; then
  summary_stage_attempted=1
  echo "prod-pilot-cohort-campaign-signoff: stage=campaign-summary"
  set +e
  bash "$CAMPAIGN_SUMMARY_SCRIPT" "${summary_args[@]}"
  summary_stage_rc=$?
  set -e
  if [[ "$summary_stage_rc" -ne 0 ]]; then
    status="fail"
    failure_stage="campaign-summary"
    final_rc="$summary_stage_rc"
  fi
fi

if [[ "$status" == "ok" ]]; then
  check_stage_attempted=1
  echo "prod-pilot-cohort-campaign-signoff: stage=campaign-check"
  set +e
  bash "$CAMPAIGN_CHECK_SCRIPT" "${check_args[@]}"
  check_stage_rc=$?
  set -e
  if [[ "$check_stage_rc" -ne 0 ]]; then
    status="fail"
    failure_stage="campaign-check"
    final_rc="$check_stage_rc"
  fi
fi

summary_payload="$(
  jq -nc \
    --arg status "$status" \
    --arg failure_stage "$failure_stage" \
    --arg runbook_summary_json "${runbook_summary_json:-}" \
    --arg campaign_run_report_json "${campaign_run_report_json:-}" \
    --arg campaign_summary_json "${campaign_summary_json:-}" \
    --arg campaign_report_md "${campaign_report_md:-}" \
    --arg campaign_signoff_summary_json "${campaign_signoff_summary_json:-}" \
    --arg reports_dir "${reports_dir:-}" \
    --argjson final_rc "$final_rc" \
    --argjson refresh_summary "$refresh_summary" \
    --argjson summary_fail_on_no_go "$summary_fail_on_no_go" \
    --argjson summary_stage_attempted "$summary_stage_attempted" \
    --argjson summary_stage_rc "$summary_stage_rc" \
    --argjson check_stage_attempted "$check_stage_attempted" \
    --argjson check_stage_rc "$check_stage_rc" \
    --argjson require_status_ok "$require_status_ok" \
    --argjson require_quick_runbook_ok "$require_quick_runbook_ok" \
    --argjson require_runbook_summary_json "$require_runbook_summary_json" \
    --argjson require_quick_run_report_json "$require_quick_run_report_json" \
    --argjson require_campaign_summary_attempted "$require_campaign_summary_attempted" \
    --argjson require_campaign_summary_ok "$require_campaign_summary_ok" \
    --argjson require_campaign_summary_json "$require_campaign_summary_json" \
    --argjson require_campaign_summary_go "$require_campaign_summary_go" \
    --argjson require_campaign_report_md "$require_campaign_report_md" \
    --argjson require_campaign_signoff_attempted "$require_campaign_signoff_attempted" \
    --argjson require_campaign_signoff_ok "$require_campaign_signoff_ok" \
    --argjson require_campaign_signoff_enabled "$require_campaign_signoff_enabled" \
    --argjson require_campaign_signoff_required "$require_campaign_signoff_required" \
    --argjson require_campaign_signoff_summary_json "$require_campaign_signoff_summary_json" \
    --argjson require_campaign_signoff_summary_json_valid "$require_campaign_signoff_summary_json_valid" \
    --argjson require_campaign_signoff_summary_status_ok "$require_campaign_signoff_summary_status_ok" \
    --argjson require_campaign_signoff_summary_final_rc_zero "$require_campaign_signoff_summary_final_rc_zero" \
    --argjson require_campaign_summary_fail_close "$require_campaign_summary_fail_close" \
    --argjson require_campaign_signoff_check "$require_campaign_signoff_check" \
    --argjson require_campaign_run_report_required "$require_campaign_run_report_required" \
    --argjson require_campaign_run_report_json_required "$require_campaign_run_report_json_required" \
    --argjson require_artifact_path_match "$require_artifact_path_match" \
    --argjson require_distinct_artifact_paths "$require_distinct_artifact_paths" \
    --argjson allow_summary_overwrite "$allow_summary_overwrite" \
    --argjson require_summary_policy_match "$require_summary_policy_match" \
    --argjson require_incident_policy_clean "$require_incident_policy_clean" \
    --argjson require_incident_snapshot_on_fail "$require_incident_snapshot_on_fail" \
    --argjson require_incident_snapshot_artifacts "$require_incident_snapshot_artifacts" \
    --argjson incident_snapshot_min_attachment_count "$incident_snapshot_min_attachment_count" \
    --argjson incident_snapshot_max_skipped_count "$incident_snapshot_max_skipped_count" \
    --argjson show_json "$show_json" \
    '{
      version: 1,
      status: $status,
      failure_stage: $failure_stage,
      final_rc: $final_rc,
      config: {
        refresh_summary: $refresh_summary,
        summary_fail_on_no_go: $summary_fail_on_no_go,
        require_status_ok: $require_status_ok,
        require_quick_runbook_ok: $require_quick_runbook_ok,
        require_runbook_summary_json: $require_runbook_summary_json,
        require_quick_run_report_json: $require_quick_run_report_json,
        require_campaign_summary_attempted: $require_campaign_summary_attempted,
        require_campaign_summary_ok: $require_campaign_summary_ok,
        require_campaign_summary_json: $require_campaign_summary_json,
        require_campaign_summary_go: $require_campaign_summary_go,
        require_campaign_report_md: $require_campaign_report_md,
        require_campaign_signoff_attempted: $require_campaign_signoff_attempted,
        require_campaign_signoff_ok: $require_campaign_signoff_ok,
        require_campaign_signoff_enabled: $require_campaign_signoff_enabled,
        require_campaign_signoff_required: $require_campaign_signoff_required,
        require_campaign_signoff_summary_json: $require_campaign_signoff_summary_json,
        require_campaign_signoff_summary_json_valid: $require_campaign_signoff_summary_json_valid,
        require_campaign_signoff_summary_status_ok: $require_campaign_signoff_summary_status_ok,
        require_campaign_signoff_summary_final_rc_zero: $require_campaign_signoff_summary_final_rc_zero,
        require_campaign_summary_fail_close: $require_campaign_summary_fail_close,
        require_campaign_signoff_check: $require_campaign_signoff_check,
        require_campaign_run_report_required: $require_campaign_run_report_required,
        require_campaign_run_report_json_required: $require_campaign_run_report_json_required,
        require_artifact_path_match: $require_artifact_path_match,
        require_distinct_artifact_paths: $require_distinct_artifact_paths,
        allow_summary_overwrite: $allow_summary_overwrite,
        require_summary_policy_match: $require_summary_policy_match,
        require_incident_policy_clean: $require_incident_policy_clean,
        require_incident_snapshot_on_fail: $require_incident_snapshot_on_fail,
        require_incident_snapshot_artifacts: $require_incident_snapshot_artifacts,
        incident_snapshot_min_attachment_count: $incident_snapshot_min_attachment_count,
        incident_snapshot_max_skipped_count: $incident_snapshot_max_skipped_count,
        show_json: $show_json
      },
      stages: {
        campaign_summary: {
          attempted: $summary_stage_attempted,
          rc: $summary_stage_rc
        },
        campaign_check: {
          attempted: $check_stage_attempted,
          rc: $check_stage_rc
        }
      },
      inputs: {
        runbook_summary_json: $runbook_summary_json,
        campaign_run_report_json: $campaign_run_report_json,
        campaign_summary_json: $campaign_summary_json,
        campaign_report_md: $campaign_report_md,
        campaign_signoff_summary_json: $campaign_signoff_summary_json,
        reports_dir: $reports_dir
      }
    }'
)"

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  printf '%s\n' "$summary_payload" >"$summary_json"
  echo "prod-pilot-cohort-campaign-signoff: summary_json=$summary_json"
fi

if [[ "$print_summary_json" == "1" ]]; then
  echo "prod-pilot-cohort-campaign-signoff: summary payload:"
  printf '%s\n' "$summary_payload"
fi

exit "$final_rc"
