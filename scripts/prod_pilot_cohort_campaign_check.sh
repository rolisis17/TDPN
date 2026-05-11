#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_campaign_check.sh \
    [--campaign-run-report-json PATH] \
    [--campaign-summary-json PATH] \
    [--campaign-signoff-summary-json PATH] \
    [--reports-dir PATH] \
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
    [--require-summary-policy-match [0|1]] \
    [--require-incident-policy-clean [0|1]] \
    [--require-incident-snapshot-on-fail [0|1]] \
    [--require-incident-snapshot-artifacts [0|1]] \
    [--incident-snapshot-min-attachment-count N] \
    [--incident-snapshot-max-skipped-count N|-1] \
    [--max-evidence-age-sec N] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--show-json [0|1]]

Purpose:
  Verify campaign wrapper run-report + handoff artifacts and enforce fail-closed
  campaign summary policy consistency.

Notes:
  - Recommended input:
      --campaign-run-report-json <reports_dir>/prod_pilot_campaign_run_report.json
  - --reports-dir auto-resolves:
      <reports_dir>/prod_pilot_campaign_run_report.json
      <reports_dir>/prod_pilot_campaign_summary.json
      <reports_dir>/prod_pilot_campaign_summary.md
      <reports_dir>/prod_pilot_campaign_signoff_summary.json
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

json_string() {
  local file="$1"
  local expr="$2"
  jq -r "$expr // \"\"" "$file" 2>/dev/null || true
}

json_int() {
  local file="$1"
  local expr="$2"
  local value
  value="$(jq -r "$expr // 0" "$file" 2>/dev/null || true)"
  if [[ -z "$value" || ! "$value" =~ ^-?[0-9]+$ ]]; then
    echo "0"
    return
  fi
  echo "$value"
}

json_bool_flag() {
  local file="$1"
  local expr="$2"
  local value
  value="$(jq -r "$expr // false | if . == true or . == 1 or . == \"1\" then \"1\" elif . == false or . == 0 or . == \"0\" then \"0\" else \"0\" end" "$file" 2>/dev/null || true)"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "0"
    return
  fi
  echo "$value"
}

json_valid01() {
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

iso8601_utc_to_epoch() {
  local timestamp="$1"
  timestamp="$(trim "$timestamp")"
  if [[ ! "$timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    return 1
  fi
  jq -nr --arg ts "$timestamp" '$ts | fromdateiso8601 | floor' 2>/dev/null
}

check_evidence_timestamp_age() {
  local label="$1"
  local timestamp="$2"
  local now_epoch="$3"
  local timestamp_epoch=""
  timestamp="$(trim "$timestamp")"
  if [[ -z "$timestamp" ]]; then
    errors+=("$label timestamp missing while --max-evidence-age-sec is enabled")
    return
  fi
  if ! timestamp_epoch="$(iso8601_utc_to_epoch "$timestamp" 2>/dev/null)"; then
    errors+=("$label timestamp is invalid (value=$timestamp)")
    return
  fi
  if (( timestamp_epoch > now_epoch + max_evidence_future_skew_sec )); then
    errors+=("$label timestamp is too far in the future (value=$timestamp, future_skew_sec=$((timestamp_epoch - now_epoch)))")
    return
  fi
  if (( now_epoch - timestamp_epoch > max_evidence_age_sec )); then
    errors+=("$label timestamp is stale (value=$timestamp, age_sec=$((now_epoch - timestamp_epoch)), max_evidence_age_sec=$max_evidence_age_sec)")
  fi
}

need_cmd jq

campaign_run_report_json=""
campaign_summary_json=""
campaign_report_md=""
campaign_signoff_summary_json=""
reports_dir=""
require_status_ok="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_STATUS_OK:-1}"
require_quick_runbook_ok="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_QUICK_RUNBOOK_OK:-1}"
require_runbook_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_RUNBOOK_SUMMARY_JSON:-1}"
require_quick_run_report_json="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_QUICK_RUN_REPORT_JSON:-1}"
require_campaign_summary_attempted="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SUMMARY_ATTEMPTED:-1}"
require_campaign_summary_ok="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SUMMARY_OK:-1}"
require_campaign_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SUMMARY_JSON:-1}"
require_campaign_summary_go="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SUMMARY_GO:-1}"
require_campaign_report_md="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_REPORT_MD:-1}"
require_campaign_signoff_attempted="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_ATTEMPTED:-1}"
require_campaign_signoff_ok="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_OK:-1}"
require_campaign_signoff_enabled="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_ENABLED:-1}"
require_campaign_signoff_required="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_REQUIRED:-1}"
require_campaign_signoff_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_SUMMARY_JSON:-1}"
require_campaign_signoff_summary_json_valid="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_SUMMARY_JSON_VALID:-1}"
require_campaign_signoff_summary_status_ok="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_SUMMARY_STATUS_OK:-1}"
require_campaign_signoff_summary_final_rc_zero="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_SUMMARY_FINAL_RC_ZERO:-1}"
require_campaign_summary_fail_close="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SUMMARY_FAIL_CLOSE:-1}"
require_campaign_signoff_check="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_SIGNOFF_CHECK:-1}"
require_campaign_run_report_required="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_RUN_REPORT_REQUIRED:-1}"
require_campaign_run_report_json_required="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_CAMPAIGN_RUN_REPORT_JSON_REQUIRED:-1}"
require_artifact_path_match="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_ARTIFACT_PATH_MATCH:-1}"
require_distinct_artifact_paths="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_DISTINCT_ARTIFACT_PATHS:-1}"
require_summary_policy_match="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_SUMMARY_POLICY_MATCH:-1}"
require_incident_policy_clean="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_INCIDENT_POLICY_CLEAN:-1}"
require_incident_snapshot_on_fail="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-1}"
require_incident_snapshot_artifacts="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-1}"
incident_snapshot_min_attachment_count="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_INCIDENT_SNAPSHOT_MIN_ATTACHMENT_COUNT:-1}"
incident_snapshot_max_skipped_count="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_INCIDENT_SNAPSHOT_MAX_SKIPPED_COUNT:-0}"
max_evidence_age_sec="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_MAX_EVIDENCE_AGE_SEC:-600}"
max_evidence_future_skew_sec="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_MAX_EVIDENCE_FUTURE_SKEW_SEC:-300}"
max_evidence_now_epoch="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_NOW_EPOCH:-}"
show_json="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_SHOW_JSON:-0}"
summary_json="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_SUMMARY_JSON:-}"
print_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_PRINT_SUMMARY_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --campaign-run-report-json)
      campaign_run_report_json="${2:-}"
      shift 2
      ;;
    --campaign-summary-json)
      campaign_summary_json="${2:-}"
      shift 2
      ;;
    --campaign-signoff-summary-json)
      campaign_signoff_summary_json="${2:-}"
      shift 2
      ;;
    --campaign-report-md)
      campaign_report_md="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
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
    --max-evidence-age-sec)
      max_evidence_age_sec="${2:-}"
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

bool_arg_or_die "--require-status-ok" "$require_status_ok"
bool_arg_or_die "--require-quick-runbook-ok" "$require_quick_runbook_ok"
bool_arg_or_die "--require-runbook-summary-json" "$require_runbook_summary_json"
bool_arg_or_die "--require-quick-run-report-json" "$require_quick_run_report_json"
bool_arg_or_die "--require-campaign-summary-attempted" "$require_campaign_summary_attempted"
bool_arg_or_die "--require-campaign-summary-ok" "$require_campaign_summary_ok"
bool_arg_or_die "--require-campaign-summary-json" "$require_campaign_summary_json"
bool_arg_or_die "--require-campaign-summary-go" "$require_campaign_summary_go"
bool_arg_or_die "--require-campaign-report-md" "$require_campaign_report_md"
bool_arg_or_die "--require-campaign-signoff-attempted" "$require_campaign_signoff_attempted"
bool_arg_or_die "--require-campaign-signoff-ok" "$require_campaign_signoff_ok"
bool_arg_or_die "--require-campaign-signoff-enabled" "$require_campaign_signoff_enabled"
bool_arg_or_die "--require-campaign-signoff-required" "$require_campaign_signoff_required"
bool_arg_or_die "--require-campaign-signoff-summary-json" "$require_campaign_signoff_summary_json"
bool_arg_or_die "--require-campaign-signoff-summary-json-valid" "$require_campaign_signoff_summary_json_valid"
bool_arg_or_die "--require-campaign-signoff-summary-status-ok" "$require_campaign_signoff_summary_status_ok"
bool_arg_or_die "--require-campaign-signoff-summary-final-rc-zero" "$require_campaign_signoff_summary_final_rc_zero"
bool_arg_or_die "--require-campaign-summary-fail-close" "$require_campaign_summary_fail_close"
bool_arg_or_die "--require-campaign-signoff-check" "$require_campaign_signoff_check"
bool_arg_or_die "--require-campaign-run-report-required" "$require_campaign_run_report_required"
bool_arg_or_die "--require-campaign-run-report-json-required" "$require_campaign_run_report_json_required"
bool_arg_or_die "--require-artifact-path-match" "$require_artifact_path_match"
bool_arg_or_die "--require-distinct-artifact-paths" "$require_distinct_artifact_paths"
bool_arg_or_die "--require-summary-policy-match" "$require_summary_policy_match"
bool_arg_or_die "--require-incident-policy-clean" "$require_incident_policy_clean"
bool_arg_or_die "--require-incident-snapshot-on-fail" "$require_incident_snapshot_on_fail"
bool_arg_or_die "--require-incident-snapshot-artifacts" "$require_incident_snapshot_artifacts"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--show-json" "$show_json"
if [[ ! "$incident_snapshot_min_attachment_count" =~ ^[0-9]+$ ]]; then
  echo "--incident-snapshot-min-attachment-count must be an integer >= 0"
  exit 2
fi
if [[ ! "$incident_snapshot_max_skipped_count" =~ ^-?[0-9]+$ ]] || ((incident_snapshot_max_skipped_count < -1)); then
  echo "--incident-snapshot-max-skipped-count must be an integer >= -1"
  exit 2
fi
if [[ ! "$max_evidence_age_sec" =~ ^[0-9]+$ ]]; then
  echo "--max-evidence-age-sec must be an integer >= 0"
  exit 2
fi
if [[ ! "$max_evidence_future_skew_sec" =~ ^[0-9]+$ ]]; then
  echo "PROD_PILOT_COHORT_CAMPAIGN_CHECK_MAX_EVIDENCE_FUTURE_SKEW_SEC must be an integer >= 0"
  exit 2
fi

reports_dir="$(abs_path "$reports_dir")"
campaign_run_report_json="$(abs_path "$campaign_run_report_json")"
campaign_summary_json="$(abs_path "$campaign_summary_json")"
campaign_report_md="$(abs_path "$campaign_report_md")"
campaign_signoff_summary_json="$(abs_path "$campaign_signoff_summary_json")"
summary_json="$(abs_path "$summary_json")"

if [[ -z "$campaign_run_report_json" && -n "$reports_dir" ]]; then
  campaign_run_report_json="$reports_dir/prod_pilot_campaign_run_report.json"
fi
if [[ -z "$campaign_run_report_json" ]]; then
  echo "missing required input: set --campaign-run-report-json or --reports-dir"
  exit 2
fi
if [[ ! -f "$campaign_run_report_json" ]]; then
  echo "campaign run report JSON not found: $campaign_run_report_json"
  exit 1
fi
if ! jq -e . "$campaign_run_report_json" >/dev/null 2>&1; then
  echo "campaign run report JSON is not valid JSON: $campaign_run_report_json"
  exit 1
fi

status="$(json_string "$campaign_run_report_json" '.status')"
failure_step="$(json_string "$campaign_run_report_json" '.failure_step')"
final_rc="$(json_int "$campaign_run_report_json" '.final_rc')"
campaign_run_started_at_utc="$(json_string "$campaign_run_report_json" '.started_at_utc')"
campaign_run_finished_at_utc="$(json_string "$campaign_run_report_json" '.finished_at_utc')"
quick_runbook_rc="$(json_int "$campaign_run_report_json" '.stages.quick_runbook.rc')"
campaign_summary_attempted="$(json_bool_flag "$campaign_run_report_json" '.stages.campaign_summary.attempted')"
campaign_summary_rc="$(json_int "$campaign_run_report_json" '.stages.campaign_summary.rc')"
campaign_signoff_enabled="$(json_bool_flag "$campaign_run_report_json" '.stages.campaign_signoff.enabled')"
campaign_signoff_required="$(json_bool_flag "$campaign_run_report_json" '.stages.campaign_signoff.required')"
campaign_signoff_attempted="$(json_bool_flag "$campaign_run_report_json" '.stages.campaign_signoff.attempted')"
campaign_signoff_rc="$(json_int "$campaign_run_report_json" '.stages.campaign_signoff.rc')"

run_report_policy_require_on_fail="$(json_bool_flag "$campaign_run_report_json" '.config.require_incident_snapshot_on_fail')"
run_report_policy_require_artifacts="$(json_bool_flag "$campaign_run_report_json" '.config.require_incident_snapshot_artifacts')"
run_report_policy_min_attachment="$(json_int "$campaign_run_report_json" '.config.incident_snapshot_min_attachment_count')"
run_report_policy_max_skipped="$(json_int "$campaign_run_report_json" '.config.incident_snapshot_max_skipped_count')"
run_report_campaign_summary_fail_close="$(json_bool_flag "$campaign_run_report_json" '.config.campaign_summary_fail_close')"
run_report_campaign_signoff_check="$(json_bool_flag "$campaign_run_report_json" '.config.campaign_signoff_check')"
run_report_campaign_run_report_required="$(json_bool_flag "$campaign_run_report_json" '.config.campaign_run_report_required')"
run_report_campaign_run_report_json_required="$(json_bool_flag "$campaign_run_report_json" '.config.campaign_run_report_json_required')"

run_report_runbook_summary_path="$(abs_path "$(json_string "$campaign_run_report_json" '.artifacts.runbook_summary_json.path')")"
run_report_runbook_summary_exists="$(json_bool_flag "$campaign_run_report_json" '.artifacts.runbook_summary_json.exists')"
run_report_runbook_summary_valid_json="$(json_bool_flag "$campaign_run_report_json" '.artifacts.runbook_summary_json.valid_json')"
run_report_quick_run_report_path="$(abs_path "$(json_string "$campaign_run_report_json" '.artifacts.quick_run_report_json.path')")"
run_report_quick_run_report_exists="$(json_bool_flag "$campaign_run_report_json" '.artifacts.quick_run_report_json.exists')"
run_report_quick_run_report_valid_json="$(json_bool_flag "$campaign_run_report_json" '.artifacts.quick_run_report_json.valid_json')"
run_report_summary_path="$(abs_path "$(json_string "$campaign_run_report_json" '.artifacts.campaign_summary_json.path')")"
run_report_summary_exists="$(json_bool_flag "$campaign_run_report_json" '.artifacts.campaign_summary_json.exists')"
run_report_summary_valid_json="$(json_bool_flag "$campaign_run_report_json" '.artifacts.campaign_summary_json.valid_json')"
run_report_report_md_path="$(abs_path "$(json_string "$campaign_run_report_json" '.artifacts.campaign_report_md.path')")"
run_report_report_md_exists="$(json_bool_flag "$campaign_run_report_json" '.artifacts.campaign_report_md.exists')"
run_report_campaign_signoff_summary_path="$(abs_path "$(json_string "$campaign_run_report_json" '.artifacts.campaign_signoff_summary_json.path')")"
run_report_campaign_signoff_summary_exists="$(json_bool_flag "$campaign_run_report_json" '.artifacts.campaign_signoff_summary_json.exists')"
run_report_campaign_signoff_summary_valid_json="$(json_bool_flag "$campaign_run_report_json" '.artifacts.campaign_signoff_summary_json.valid_json')"

if [[ -z "$campaign_summary_json" ]]; then
  campaign_summary_json="$run_report_summary_path"
fi
if [[ -z "$campaign_summary_json" && -n "$reports_dir" ]]; then
  campaign_summary_json="$reports_dir/prod_pilot_campaign_summary.json"
fi
if [[ -z "$campaign_report_md" ]]; then
  campaign_report_md="$run_report_report_md_path"
fi
if [[ -z "$campaign_report_md" && -n "$reports_dir" ]]; then
  campaign_report_md="$reports_dir/prod_pilot_campaign_summary.md"
fi
if [[ -z "$campaign_signoff_summary_json" ]]; then
  campaign_signoff_summary_json="$run_report_campaign_signoff_summary_path"
fi
if [[ -z "$campaign_signoff_summary_json" && -n "$reports_dir" ]]; then
  campaign_signoff_summary_json="$reports_dir/prod_pilot_campaign_signoff_summary.json"
fi

runbook_summary_json="$run_report_runbook_summary_path"
quick_run_report_json="$run_report_quick_run_report_path"

runbook_summary_exists="0"
runbook_summary_valid_json="0"
runbook_summary_started_at=""
runbook_summary_finished_at=""
runbook_summary_generated_at_utc=""
if [[ -n "$runbook_summary_json" && -f "$runbook_summary_json" ]]; then
  runbook_summary_exists="1"
  runbook_summary_valid_json="$(json_valid01 "$runbook_summary_json")"
  if [[ "$runbook_summary_valid_json" == "1" ]]; then
    runbook_summary_started_at="$(json_string "$runbook_summary_json" '.started_at')"
    runbook_summary_finished_at="$(json_string "$runbook_summary_json" '.finished_at')"
    runbook_summary_generated_at_utc="$(json_string "$runbook_summary_json" '.generated_at_utc')"
  fi
fi

quick_run_report_exists="0"
quick_run_report_valid_json="0"
quick_run_report_started_at=""
quick_run_report_finished_at=""
quick_run_report_generated_at_utc=""
if [[ -n "$quick_run_report_json" && -f "$quick_run_report_json" ]]; then
  quick_run_report_exists="1"
  quick_run_report_valid_json="$(json_valid01 "$quick_run_report_json")"
  if [[ "$quick_run_report_valid_json" == "1" ]]; then
    quick_run_report_started_at="$(json_string "$quick_run_report_json" '.started_at')"
    quick_run_report_finished_at="$(json_string "$quick_run_report_json" '.finished_at')"
    quick_run_report_generated_at_utc="$(json_string "$quick_run_report_json" '.generated_at_utc')"
  fi
fi

summary_exists="0"
summary_valid_json="0"
campaign_summary_generated_at_utc=""
if [[ -n "$campaign_summary_json" && -f "$campaign_summary_json" ]]; then
  summary_exists="1"
  summary_valid_json="$(json_valid01 "$campaign_summary_json")"
  if [[ "$summary_valid_json" == "1" ]]; then
    campaign_summary_generated_at_utc="$(json_string "$campaign_summary_json" '.generated_at_utc')"
  fi
fi

report_md_exists="0"
if [[ -n "$campaign_report_md" && -f "$campaign_report_md" ]]; then
  report_md_exists="1"
fi

campaign_signoff_summary_exists="0"
campaign_signoff_summary_valid_json="0"
campaign_signoff_summary_generated_at_utc=""
if [[ -n "$campaign_signoff_summary_json" && -f "$campaign_signoff_summary_json" ]]; then
  campaign_signoff_summary_exists="1"
  campaign_signoff_summary_valid_json="$(json_valid01 "$campaign_signoff_summary_json")"
  if [[ "$campaign_signoff_summary_valid_json" == "1" ]]; then
    campaign_signoff_summary_generated_at_utc="$(json_string "$campaign_signoff_summary_json" '.generated_at_utc')"
  fi
fi
campaign_signoff_summary_status=""
campaign_signoff_summary_final_rc="0"
if [[ "$campaign_signoff_summary_exists" == "1" && "$campaign_signoff_summary_valid_json" == "1" ]]; then
  campaign_signoff_summary_status="$(json_string "$campaign_signoff_summary_json" '.status')"
  campaign_signoff_summary_final_rc="$(json_int "$campaign_signoff_summary_json" '.final_rc')"
fi

campaign_decision=""
campaign_decision_reason=""
summary_policy_require_on_fail="0"
summary_policy_require_artifacts="0"
summary_policy_min_attachment="0"
summary_policy_max_skipped="0"
summary_incident_policy_errors_count="0"
summary_incident_handoff_summary_json=""
summary_incident_handoff_report_md=""
summary_artifact_runbook_summary_path=""
summary_artifact_quick_run_report_path=""
summary_artifact_campaign_summary_path=""
summary_artifact_campaign_report_md_path=""
if [[ "$summary_exists" == "1" && "$summary_valid_json" == "1" ]]; then
  campaign_decision="$(json_string "$campaign_summary_json" '.decision')"
  campaign_decision_reason="$(json_string "$campaign_summary_json" '.decision_reason')"
  summary_policy_require_on_fail="$(json_bool_flag "$campaign_summary_json" '.fail_policy.require_incident_snapshot_on_fail')"
  summary_policy_require_artifacts="$(json_bool_flag "$campaign_summary_json" '.fail_policy.require_incident_snapshot_artifacts')"
  summary_policy_min_attachment="$(json_int "$campaign_summary_json" '.fail_policy.incident_snapshot_min_attachment_count')"
  summary_policy_max_skipped="$(json_int "$campaign_summary_json" '.fail_policy.incident_snapshot_max_skipped_count')"
  summary_incident_policy_errors_count="$(json_int "$campaign_summary_json" '.incident_policy_errors | length')"
  summary_incident_handoff_summary_json="$(abs_path "$(json_string "$campaign_summary_json" '.incident_snapshot.summary_json.path')")"
  summary_incident_handoff_report_md="$(abs_path "$(json_string "$campaign_summary_json" '.incident_snapshot.report_md.path')")"
  summary_artifact_runbook_summary_path="$(abs_path "$(json_string "$campaign_summary_json" '.artifacts.runbook_summary_json.path')")"
  summary_artifact_quick_run_report_path="$(abs_path "$(json_string "$campaign_summary_json" '.artifacts.quick_run_report_json.path')")"
  summary_artifact_campaign_summary_path="$(abs_path "$(json_string "$campaign_summary_json" '.artifacts.campaign_summary_json.path')")"
  summary_artifact_campaign_report_md_path="$(abs_path "$(json_string "$campaign_summary_json" '.artifacts.campaign_report_md.path')")"
fi

declare -a errors=()
now_epoch=""

if (( max_evidence_age_sec > 0 )); then
  if [[ -n "$max_evidence_now_epoch" ]]; then
    now_epoch="$max_evidence_now_epoch"
  else
    need_cmd date
    now_epoch="$(date -u +%s)"
  fi
  if [[ -z "$now_epoch" || ! "$now_epoch" =~ ^[0-9]+$ ]]; then
    errors+=("could not determine current UTC epoch for evidence freshness check")
  else
    check_evidence_timestamp_age "campaign run report started_at_utc" "$campaign_run_started_at_utc" "$now_epoch"
    check_evidence_timestamp_age "campaign run report finished_at_utc" "$campaign_run_finished_at_utc" "$now_epoch"
    if [[ "$runbook_summary_valid_json" == "1" ]]; then
      runbook_summary_freshness_ts="$runbook_summary_finished_at"
      if [[ -z "$runbook_summary_freshness_ts" ]]; then
        runbook_summary_freshness_ts="$runbook_summary_generated_at_utc"
      fi
      if [[ -z "$runbook_summary_freshness_ts" ]]; then
        runbook_summary_freshness_ts="$runbook_summary_started_at"
      fi
      check_evidence_timestamp_age "runbook summary evidence" "$runbook_summary_freshness_ts" "$now_epoch"
    fi
    if [[ "$quick_run_report_valid_json" == "1" ]]; then
      quick_run_report_freshness_ts="$quick_run_report_finished_at"
      if [[ -z "$quick_run_report_freshness_ts" ]]; then
        quick_run_report_freshness_ts="$quick_run_report_generated_at_utc"
      fi
      if [[ -z "$quick_run_report_freshness_ts" ]]; then
        quick_run_report_freshness_ts="$quick_run_report_started_at"
      fi
      check_evidence_timestamp_age "quick run report evidence" "$quick_run_report_freshness_ts" "$now_epoch"
    fi
    if [[ "$summary_valid_json" == "1" ]]; then
      check_evidence_timestamp_age "campaign summary generated_at_utc" "$campaign_summary_generated_at_utc" "$now_epoch"
    fi
    if [[ "$campaign_signoff_summary_valid_json" == "1" ]]; then
      check_evidence_timestamp_age "campaign signoff summary generated_at_utc" "$campaign_signoff_summary_generated_at_utc" "$now_epoch"
    fi
  fi
fi

check_distinct_path() {
  local path="$1"
  local label="$2"
  local -n seen_paths_ref="$3"
  local -n seen_labels_ref="$4"
  local -n errors_ref="$5"
  local idx

  if [[ -z "$path" ]]; then
    return
  fi
  for idx in "${!seen_paths_ref[@]}"; do
    if [[ "${seen_paths_ref[$idx]}" == "$path" ]]; then
      errors_ref+=("artifact path collision: $label and ${seen_labels_ref[$idx]} both resolve to $path")
      return
    fi
  done
  seen_paths_ref+=("$path")
  seen_labels_ref+=("$label")
}

if [[ "$require_status_ok" == "1" && "$status" != "ok" ]]; then
  errors+=("campaign run status is not ok (status=${status:-unset}, failure_step=${failure_step:-none}, final_rc=$final_rc)")
fi
if [[ "$require_quick_runbook_ok" == "1" && "$quick_runbook_rc" -ne 0 ]]; then
  errors+=("quick runbook rc is non-zero (quick_runbook_rc=$quick_runbook_rc)")
fi
if [[ "$require_campaign_summary_attempted" == "1" && "$campaign_summary_attempted" != "1" ]]; then
  errors+=("campaign summary stage was not attempted")
fi
if [[ "$require_campaign_summary_ok" == "1" && "$campaign_summary_rc" -ne 0 ]]; then
  errors+=("campaign summary stage rc is non-zero (campaign_summary_rc=$campaign_summary_rc)")
fi
if [[ "$require_campaign_signoff_attempted" == "1" && "$campaign_signoff_attempted" != "1" ]]; then
  errors+=("campaign signoff stage was not attempted (enabled=$campaign_signoff_enabled required=$campaign_signoff_required)")
fi
if [[ "$require_campaign_signoff_ok" == "1" && "$campaign_signoff_rc" -ne 0 ]]; then
  errors+=("campaign signoff stage rc is non-zero (campaign_signoff_rc=$campaign_signoff_rc)")
fi
if [[ "$require_campaign_signoff_enabled" == "1" && "$campaign_signoff_enabled" != "1" ]]; then
  errors+=("campaign signoff stage is not enabled in wrapper run report (campaign_signoff_enabled=$campaign_signoff_enabled)")
fi
if [[ "$require_campaign_signoff_required" == "1" && "$campaign_signoff_required" != "1" ]]; then
  errors+=("campaign signoff stage is not required in wrapper run report (campaign_signoff_required=$campaign_signoff_required)")
fi

if [[ "$require_runbook_summary_json" == "1" ]]; then
  if [[ -z "$runbook_summary_json" ]]; then
    errors+=("runbook summary JSON path is missing in campaign run report artifacts")
  elif [[ "$runbook_summary_exists" != "1" ]]; then
    errors+=("runbook summary JSON file not found: $runbook_summary_json")
  elif [[ "$runbook_summary_valid_json" != "1" ]]; then
    errors+=("runbook summary JSON is invalid: $runbook_summary_json")
  fi
fi

if [[ "$require_quick_run_report_json" == "1" ]]; then
  if [[ -z "$quick_run_report_json" ]]; then
    errors+=("quick run report JSON path is missing in campaign run report artifacts")
  elif [[ "$quick_run_report_exists" != "1" ]]; then
    errors+=("quick run report JSON file not found: $quick_run_report_json")
  elif [[ "$quick_run_report_valid_json" != "1" ]]; then
    errors+=("quick run report JSON is invalid: $quick_run_report_json")
  fi
fi

if [[ "$require_campaign_summary_json" == "1" ]]; then
  if [[ -z "$campaign_summary_json" ]]; then
    errors+=("campaign summary JSON path is missing")
  elif [[ "$summary_exists" != "1" ]]; then
    errors+=("campaign summary JSON file not found: $campaign_summary_json")
  elif [[ "$summary_valid_json" != "1" ]]; then
    errors+=("campaign summary JSON is invalid: $campaign_summary_json")
  fi
fi

if [[ "$require_campaign_report_md" == "1" ]]; then
  if [[ -z "$campaign_report_md" ]]; then
    errors+=("campaign report markdown path is missing")
  elif [[ "$report_md_exists" != "1" ]]; then
    errors+=("campaign report markdown file not found: $campaign_report_md")
  fi
fi

if [[ "$require_campaign_signoff_summary_json" == "1" ]]; then
  if [[ -z "$campaign_signoff_summary_json" ]]; then
    errors+=("campaign signoff summary JSON path is missing")
  elif [[ "$campaign_signoff_summary_exists" != "1" ]]; then
    errors+=("campaign signoff summary JSON file not found: $campaign_signoff_summary_json")
  fi
fi

if [[ "$require_campaign_signoff_summary_json_valid" == "1" ]]; then
  if [[ -z "$campaign_signoff_summary_json" ]]; then
    errors+=("campaign signoff summary JSON path is missing")
  elif [[ "$campaign_signoff_summary_exists" != "1" ]]; then
    errors+=("campaign signoff summary JSON file not found: $campaign_signoff_summary_json")
  elif [[ "$campaign_signoff_summary_valid_json" != "1" ]]; then
    errors+=("campaign signoff summary JSON is invalid: $campaign_signoff_summary_json")
  fi
fi
if [[ "$require_campaign_signoff_summary_status_ok" == "1" ]]; then
  if [[ "$campaign_signoff_summary_exists" != "1" || "$campaign_signoff_summary_valid_json" != "1" ]]; then
    errors+=("cannot validate campaign signoff summary status because signoff summary JSON is unavailable")
  elif [[ "$campaign_signoff_summary_status" != "ok" ]]; then
    errors+=("campaign signoff summary status is not ok (status=${campaign_signoff_summary_status:-unset})")
  fi
fi
if [[ "$require_campaign_signoff_summary_final_rc_zero" == "1" ]]; then
  if [[ "$campaign_signoff_summary_exists" != "1" || "$campaign_signoff_summary_valid_json" != "1" ]]; then
    errors+=("cannot validate campaign signoff summary final_rc because signoff summary JSON is unavailable")
  elif [[ "$campaign_signoff_summary_final_rc" -ne 0 ]]; then
    errors+=("campaign signoff summary final_rc is non-zero (final_rc=$campaign_signoff_summary_final_rc)")
  fi
fi
if [[ "$require_campaign_summary_fail_close" == "1" && "$run_report_campaign_summary_fail_close" != "1" ]]; then
  errors+=("campaign run report config.campaign_summary_fail_close is not enabled (observed=$run_report_campaign_summary_fail_close)")
fi
if [[ "$require_campaign_signoff_check" == "1" && "$run_report_campaign_signoff_check" != "1" ]]; then
  errors+=("campaign run report config.campaign_signoff_check is not enabled (observed=$run_report_campaign_signoff_check)")
fi
if [[ "$require_campaign_run_report_required" == "1" && "$run_report_campaign_run_report_required" != "1" ]]; then
  errors+=("campaign run report config.campaign_run_report_required is not enabled (observed=$run_report_campaign_run_report_required)")
fi
if [[ "$require_campaign_run_report_json_required" == "1" && "$run_report_campaign_run_report_json_required" != "1" ]]; then
  errors+=("campaign run report config.campaign_run_report_json_required is not enabled (observed=$run_report_campaign_run_report_json_required)")
fi

if [[ "$require_campaign_summary_go" == "1" ]]; then
  if [[ "$summary_exists" != "1" || "$summary_valid_json" != "1" ]]; then
    errors+=("cannot validate campaign summary decision because summary JSON is unavailable")
  elif [[ "$campaign_decision" != "GO" ]]; then
    errors+=("campaign summary decision is not GO (decision=${campaign_decision:-unset}, reason=${campaign_decision_reason:-unset})")
  fi
fi

if [[ "$require_summary_policy_match" == "1" ]]; then
  if [[ "$summary_exists" != "1" || "$summary_valid_json" != "1" ]]; then
    errors+=("cannot validate campaign summary policy match because summary JSON is unavailable")
  else
    if [[ "$run_report_policy_require_on_fail" != "$require_incident_snapshot_on_fail" ]]; then
      errors+=("campaign run report policy require_incident_snapshot_on_fail mismatch (observed=$run_report_policy_require_on_fail expected=$require_incident_snapshot_on_fail)")
    fi
    if [[ "$run_report_policy_require_artifacts" != "$require_incident_snapshot_artifacts" ]]; then
      errors+=("campaign run report policy require_incident_snapshot_artifacts mismatch (observed=$run_report_policy_require_artifacts expected=$require_incident_snapshot_artifacts)")
    fi
    if [[ "$run_report_policy_min_attachment" -ne "$incident_snapshot_min_attachment_count" ]]; then
      errors+=("campaign run report policy incident_snapshot_min_attachment_count mismatch (observed=$run_report_policy_min_attachment expected=$incident_snapshot_min_attachment_count)")
    fi
    if [[ "$run_report_policy_max_skipped" -ne "$incident_snapshot_max_skipped_count" ]]; then
      errors+=("campaign run report policy incident_snapshot_max_skipped_count mismatch (observed=$run_report_policy_max_skipped expected=$incident_snapshot_max_skipped_count)")
    fi
    if [[ "$summary_policy_require_on_fail" != "$require_incident_snapshot_on_fail" ]]; then
      errors+=("campaign summary fail_policy.require_incident_snapshot_on_fail mismatch (observed=$summary_policy_require_on_fail expected=$require_incident_snapshot_on_fail)")
    fi
    if [[ "$summary_policy_require_artifacts" != "$require_incident_snapshot_artifacts" ]]; then
      errors+=("campaign summary fail_policy.require_incident_snapshot_artifacts mismatch (observed=$summary_policy_require_artifacts expected=$require_incident_snapshot_artifacts)")
    fi
    if [[ "$summary_policy_min_attachment" -ne "$incident_snapshot_min_attachment_count" ]]; then
      errors+=("campaign summary fail_policy.incident_snapshot_min_attachment_count mismatch (observed=$summary_policy_min_attachment expected=$incident_snapshot_min_attachment_count)")
    fi
    if [[ "$summary_policy_max_skipped" -ne "$incident_snapshot_max_skipped_count" ]]; then
      errors+=("campaign summary fail_policy.incident_snapshot_max_skipped_count mismatch (observed=$summary_policy_max_skipped expected=$incident_snapshot_max_skipped_count)")
    fi
  fi
fi

if [[ "$require_artifact_path_match" == "1" ]]; then
  if [[ -n "$run_report_runbook_summary_path" && -n "$runbook_summary_json" && "$run_report_runbook_summary_path" != "$runbook_summary_json" ]]; then
    errors+=("run report runbook summary path does not match resolved input (run_report=$run_report_runbook_summary_path input=$runbook_summary_json)")
  fi
  if [[ -n "$run_report_quick_run_report_path" && -n "$quick_run_report_json" && "$run_report_quick_run_report_path" != "$quick_run_report_json" ]]; then
    errors+=("run report quick run report path does not match resolved input (run_report=$run_report_quick_run_report_path input=$quick_run_report_json)")
  fi
  if [[ -n "$run_report_summary_path" && -n "$campaign_summary_json" && "$run_report_summary_path" != "$campaign_summary_json" ]]; then
    errors+=("run report campaign summary path does not match resolved input (run_report=$run_report_summary_path input=$campaign_summary_json)")
  fi
  if [[ -n "$run_report_report_md_path" && -n "$campaign_report_md" && "$run_report_report_md_path" != "$campaign_report_md" ]]; then
    errors+=("run report campaign report markdown path does not match resolved input (run_report=$run_report_report_md_path input=$campaign_report_md)")
  fi
  if [[ -n "$run_report_campaign_signoff_summary_path" && -n "$campaign_signoff_summary_json" && "$run_report_campaign_signoff_summary_path" != "$campaign_signoff_summary_json" ]]; then
    errors+=("run report campaign signoff summary path does not match resolved input (run_report=$run_report_campaign_signoff_summary_path input=$campaign_signoff_summary_json)")
  fi
  if [[ "$summary_exists" == "1" && "$summary_valid_json" == "1" ]]; then
    if [[ -n "$summary_artifact_runbook_summary_path" && -n "$runbook_summary_json" && "$summary_artifact_runbook_summary_path" != "$runbook_summary_json" ]]; then
      errors+=("campaign summary artifacts.runbook_summary_json.path does not match resolved runbook summary path (summary=$summary_artifact_runbook_summary_path input=$runbook_summary_json)")
    fi
    if [[ -n "$summary_artifact_quick_run_report_path" && -n "$quick_run_report_json" && "$summary_artifact_quick_run_report_path" != "$quick_run_report_json" ]]; then
      errors+=("campaign summary artifacts.quick_run_report_json.path does not match resolved quick run report path (summary=$summary_artifact_quick_run_report_path input=$quick_run_report_json)")
    fi
    if [[ -n "$summary_artifact_campaign_summary_path" && -n "$campaign_summary_json" && "$summary_artifact_campaign_summary_path" != "$campaign_summary_json" ]]; then
      errors+=("campaign summary artifacts.campaign_summary_json.path does not match resolved campaign summary path (summary=$summary_artifact_campaign_summary_path input=$campaign_summary_json)")
    fi
    if [[ -n "$summary_artifact_campaign_report_md_path" && -n "$campaign_report_md" && "$summary_artifact_campaign_report_md_path" != "$campaign_report_md" ]]; then
      errors+=("campaign summary artifacts.campaign_report_md.path does not match resolved campaign report markdown path (summary=$summary_artifact_campaign_report_md_path input=$campaign_report_md)")
    fi
  fi
fi

if [[ "$require_distinct_artifact_paths" == "1" ]]; then
  declare -a seen_paths=()
  declare -a seen_labels=()
  check_distinct_path "$campaign_run_report_json" "campaign_run_report_json" seen_paths seen_labels errors
  check_distinct_path "$campaign_summary_json" "campaign_summary_json" seen_paths seen_labels errors
  check_distinct_path "$campaign_report_md" "campaign_report_md" seen_paths seen_labels errors
  check_distinct_path "$campaign_signoff_summary_json" "campaign_signoff_summary_json" seen_paths seen_labels errors
  check_distinct_path "$runbook_summary_json" "runbook_summary_json" seen_paths seen_labels errors
  check_distinct_path "$quick_run_report_json" "quick_run_report_json" seen_paths seen_labels errors
  if [[ "$summary_exists" == "1" && "$summary_valid_json" == "1" ]]; then
    check_distinct_path "$summary_artifact_runbook_summary_path" "summary.artifacts.runbook_summary_json.path" seen_paths seen_labels errors
    check_distinct_path "$summary_artifact_quick_run_report_path" "summary.artifacts.quick_run_report_json.path" seen_paths seen_labels errors
    check_distinct_path "$summary_artifact_campaign_summary_path" "summary.artifacts.campaign_summary_json.path" seen_paths seen_labels errors
    check_distinct_path "$summary_artifact_campaign_report_md_path" "summary.artifacts.campaign_report_md.path" seen_paths seen_labels errors
  fi
fi

if [[ "$require_incident_policy_clean" == "1" ]]; then
  if [[ "$summary_exists" != "1" || "$summary_valid_json" != "1" ]]; then
    errors+=("cannot validate incident policy error set because summary JSON is unavailable")
  elif [[ "$summary_incident_policy_errors_count" -ne 0 ]]; then
    errors+=("campaign summary incident policy errors are non-empty (count=$summary_incident_policy_errors_count)")
  fi
fi

if [[ "$run_report_summary_exists" != "$summary_exists" ]]; then
  errors+=("run report summary artifact existence metadata does not match filesystem (reported=$run_report_summary_exists actual=$summary_exists)")
fi
if [[ "$run_report_summary_valid_json" != "$summary_valid_json" ]]; then
  errors+=("run report summary artifact valid_json metadata does not match filesystem (reported=$run_report_summary_valid_json actual=$summary_valid_json)")
fi
if [[ "$run_report_report_md_exists" != "$report_md_exists" ]]; then
  errors+=("run report campaign markdown existence metadata does not match filesystem (reported=$run_report_report_md_exists actual=$report_md_exists)")
fi
if [[ "$run_report_campaign_signoff_summary_exists" != "$campaign_signoff_summary_exists" ]]; then
  errors+=("run report campaign signoff summary existence metadata does not match filesystem (reported=$run_report_campaign_signoff_summary_exists actual=$campaign_signoff_summary_exists)")
fi
if [[ "$run_report_campaign_signoff_summary_valid_json" != "$campaign_signoff_summary_valid_json" ]]; then
  errors+=("run report campaign signoff summary valid_json metadata does not match filesystem (reported=$run_report_campaign_signoff_summary_valid_json actual=$campaign_signoff_summary_valid_json)")
fi
if [[ "$run_report_runbook_summary_exists" != "$runbook_summary_exists" ]]; then
  errors+=("run report runbook summary existence metadata does not match filesystem (reported=$run_report_runbook_summary_exists actual=$runbook_summary_exists)")
fi
if [[ "$run_report_runbook_summary_valid_json" != "$runbook_summary_valid_json" ]]; then
  errors+=("run report runbook summary valid_json metadata does not match filesystem (reported=$run_report_runbook_summary_valid_json actual=$runbook_summary_valid_json)")
fi
if [[ "$run_report_quick_run_report_exists" != "$quick_run_report_exists" ]]; then
  errors+=("run report quick run report existence metadata does not match filesystem (reported=$run_report_quick_run_report_exists actual=$quick_run_report_exists)")
fi
if [[ "$run_report_quick_run_report_valid_json" != "$quick_run_report_valid_json" ]]; then
  errors+=("run report quick run report valid_json metadata does not match filesystem (reported=$run_report_quick_run_report_valid_json actual=$quick_run_report_valid_json)")
fi

decision="GO"
if ((${#errors[@]} > 0)); then
  decision="NO-GO"
fi

issues_json='[]'
if ((${#errors[@]} > 0)); then
  issues_json="$(printf '%s\n' "${errors[@]}" | jq -R . | jq -s '.')"
fi
need_cmd date
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
summary_payload="$(
  jq -nc \
    --arg generated_at_utc "$generated_at_utc" \
    --arg decision "$decision" \
    --arg status "$status" \
    --arg failure_step "$failure_step" \
    --arg campaign_decision "$campaign_decision" \
    --arg campaign_decision_reason "$campaign_decision_reason" \
    --arg campaign_run_report_json "$campaign_run_report_json" \
    --arg campaign_summary_json "${campaign_summary_json:-}" \
    --arg campaign_report_md "${campaign_report_md:-}" \
    --arg campaign_signoff_summary_json "${campaign_signoff_summary_json:-}" \
    --arg runbook_summary_json "${runbook_summary_json:-}" \
    --arg quick_run_report_json "${quick_run_report_json:-}" \
    --argjson final_rc "$final_rc" \
    --argjson quick_runbook_rc "$quick_runbook_rc" \
    --argjson campaign_summary_attempted "$campaign_summary_attempted" \
    --argjson campaign_summary_rc "$campaign_summary_rc" \
    --argjson campaign_signoff_enabled "$campaign_signoff_enabled" \
    --argjson campaign_signoff_required "$campaign_signoff_required" \
    --argjson campaign_signoff_attempted "$campaign_signoff_attempted" \
    --argjson campaign_signoff_rc "$campaign_signoff_rc" \
    --arg campaign_signoff_summary_status "${campaign_signoff_summary_status:-}" \
    --argjson campaign_signoff_summary_final_rc "$campaign_signoff_summary_final_rc" \
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
    --argjson require_summary_policy_match "$require_summary_policy_match" \
    --argjson require_incident_policy_clean "$require_incident_policy_clean" \
    --argjson require_incident_snapshot_on_fail "$require_incident_snapshot_on_fail" \
    --argjson require_incident_snapshot_artifacts "$require_incident_snapshot_artifacts" \
    --argjson incident_snapshot_min_attachment_count "$incident_snapshot_min_attachment_count" \
    --argjson incident_snapshot_max_skipped_count "$incident_snapshot_max_skipped_count" \
    --argjson run_report_policy_require_on_fail "$run_report_policy_require_on_fail" \
    --argjson run_report_policy_require_artifacts "$run_report_policy_require_artifacts" \
    --argjson run_report_policy_min_attachment "$run_report_policy_min_attachment" \
    --argjson run_report_policy_max_skipped "$run_report_policy_max_skipped" \
    --argjson run_report_campaign_summary_fail_close "$run_report_campaign_summary_fail_close" \
    --argjson run_report_campaign_signoff_check "$run_report_campaign_signoff_check" \
    --argjson run_report_campaign_run_report_required "$run_report_campaign_run_report_required" \
    --argjson run_report_campaign_run_report_json_required "$run_report_campaign_run_report_json_required" \
    --argjson summary_policy_require_on_fail "$summary_policy_require_on_fail" \
    --argjson summary_policy_require_artifacts "$summary_policy_require_artifacts" \
    --argjson summary_policy_min_attachment "$summary_policy_min_attachment" \
    --argjson summary_policy_max_skipped "$summary_policy_max_skipped" \
    --argjson summary_incident_policy_errors_count "$summary_incident_policy_errors_count" \
    --arg summary_artifact_runbook_summary_path "${summary_artifact_runbook_summary_path:-}" \
    --arg summary_artifact_quick_run_report_path "${summary_artifact_quick_run_report_path:-}" \
    --arg summary_artifact_campaign_summary_path "${summary_artifact_campaign_summary_path:-}" \
    --arg summary_artifact_campaign_report_md_path "${summary_artifact_campaign_report_md_path:-}" \
    --arg run_report_runbook_summary_path "${run_report_runbook_summary_path:-}" \
    --arg run_report_quick_run_report_path "${run_report_quick_run_report_path:-}" \
    --arg run_report_summary_path "${run_report_summary_path:-}" \
    --arg run_report_report_md_path "${run_report_report_md_path:-}" \
    --arg run_report_campaign_signoff_summary_path "${run_report_campaign_signoff_summary_path:-}" \
    --arg campaign_run_started_at_utc "${campaign_run_started_at_utc:-}" \
    --arg campaign_run_finished_at_utc "${campaign_run_finished_at_utc:-}" \
    --arg runbook_summary_started_at "${runbook_summary_started_at:-}" \
    --arg runbook_summary_finished_at "${runbook_summary_finished_at:-}" \
    --arg runbook_summary_generated_at_utc "${runbook_summary_generated_at_utc:-}" \
    --arg quick_run_report_started_at "${quick_run_report_started_at:-}" \
    --arg quick_run_report_finished_at "${quick_run_report_finished_at:-}" \
    --arg quick_run_report_generated_at_utc "${quick_run_report_generated_at_utc:-}" \
    --arg campaign_summary_generated_at_utc "${campaign_summary_generated_at_utc:-}" \
    --arg campaign_signoff_summary_generated_at_utc "${campaign_signoff_summary_generated_at_utc:-}" \
    --arg now_epoch "${now_epoch:-}" \
    --argjson runbook_summary_exists "$runbook_summary_exists" \
    --argjson runbook_summary_valid_json "$runbook_summary_valid_json" \
    --argjson run_report_runbook_summary_exists "$run_report_runbook_summary_exists" \
    --argjson run_report_runbook_summary_valid_json "$run_report_runbook_summary_valid_json" \
    --argjson quick_run_report_exists "$quick_run_report_exists" \
    --argjson quick_run_report_valid_json "$quick_run_report_valid_json" \
    --argjson run_report_quick_run_report_exists "$run_report_quick_run_report_exists" \
    --argjson run_report_quick_run_report_valid_json "$run_report_quick_run_report_valid_json" \
    --argjson summary_exists "$summary_exists" \
    --argjson summary_valid_json "$summary_valid_json" \
    --argjson run_report_summary_exists "$run_report_summary_exists" \
    --argjson run_report_summary_valid_json "$run_report_summary_valid_json" \
    --argjson report_md_exists "$report_md_exists" \
    --argjson run_report_report_md_exists "$run_report_report_md_exists" \
    --argjson campaign_signoff_summary_exists "$campaign_signoff_summary_exists" \
    --argjson campaign_signoff_summary_valid_json "$campaign_signoff_summary_valid_json" \
    --argjson run_report_campaign_signoff_summary_exists "$run_report_campaign_signoff_summary_exists" \
    --argjson run_report_campaign_signoff_summary_valid_json "$run_report_campaign_signoff_summary_valid_json" \
    --argjson max_evidence_age_sec "$max_evidence_age_sec" \
    --argjson max_evidence_future_skew_sec "$max_evidence_future_skew_sec" \
    --argjson issues "$issues_json" \
    '{
      version: 1,
      generated_at_utc: $generated_at_utc,
      decision: $decision,
      status: $status,
      failure_step: $failure_step,
      final_rc: $final_rc,
      quick_runbook_rc: $quick_runbook_rc,
      campaign_summary_attempted: $campaign_summary_attempted,
      campaign_summary_rc: $campaign_summary_rc,
      campaign_signoff_enabled: $campaign_signoff_enabled,
      campaign_signoff_required: $campaign_signoff_required,
      campaign_signoff_attempted: $campaign_signoff_attempted,
      campaign_signoff_rc: $campaign_signoff_rc,
      campaign_signoff_summary_status: $campaign_signoff_summary_status,
      campaign_signoff_summary_final_rc: $campaign_signoff_summary_final_rc,
      campaign_decision: $campaign_decision,
      campaign_decision_reason: $campaign_decision_reason,
      inputs: {
        campaign_run_report_json: $campaign_run_report_json,
        campaign_summary_json: $campaign_summary_json,
        campaign_report_md: $campaign_report_md,
        campaign_signoff_summary_json: $campaign_signoff_summary_json,
        runbook_summary_json: $runbook_summary_json,
        quick_run_report_json: $quick_run_report_json
      },
      policy: {
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
        require_summary_policy_match: $require_summary_policy_match,
        require_incident_policy_clean: $require_incident_policy_clean,
        require_incident_snapshot_on_fail: $require_incident_snapshot_on_fail,
        require_incident_snapshot_artifacts: $require_incident_snapshot_artifacts,
        incident_snapshot_min_attachment_count: $incident_snapshot_min_attachment_count,
        incident_snapshot_max_skipped_count: $incident_snapshot_max_skipped_count,
        max_evidence_age_sec: $max_evidence_age_sec,
        max_evidence_future_skew_sec: $max_evidence_future_skew_sec
      },
      observed: {
        freshness: {
          now_epoch: (if $now_epoch == "" then null else ($now_epoch | tonumber) end),
          campaign_run_started_at_utc: $campaign_run_started_at_utc,
          campaign_run_finished_at_utc: $campaign_run_finished_at_utc,
          runbook_summary_started_at: $runbook_summary_started_at,
          runbook_summary_finished_at: $runbook_summary_finished_at,
          runbook_summary_generated_at_utc: $runbook_summary_generated_at_utc,
          quick_run_report_started_at: $quick_run_report_started_at,
          quick_run_report_finished_at: $quick_run_report_finished_at,
          quick_run_report_generated_at_utc: $quick_run_report_generated_at_utc,
          campaign_summary_generated_at_utc: $campaign_summary_generated_at_utc,
          campaign_signoff_summary_generated_at_utc: $campaign_signoff_summary_generated_at_utc
        },
        campaign_signoff_stage: {
          enabled: $campaign_signoff_enabled,
          required: $campaign_signoff_required,
          attempted: $campaign_signoff_attempted,
          rc: $campaign_signoff_rc
        },
        campaign_signoff_summary: {
          status: $campaign_signoff_summary_status,
          final_rc: $campaign_signoff_summary_final_rc
        },
        run_report_policy: {
          require_incident_snapshot_on_fail: $run_report_policy_require_on_fail,
          require_incident_snapshot_artifacts: $run_report_policy_require_artifacts,
          incident_snapshot_min_attachment_count: $run_report_policy_min_attachment,
          incident_snapshot_max_skipped_count: $run_report_policy_max_skipped
        },
        run_report_config: {
          campaign_summary_fail_close: $run_report_campaign_summary_fail_close,
          campaign_signoff_check: $run_report_campaign_signoff_check,
          campaign_run_report_required: $run_report_campaign_run_report_required,
          campaign_run_report_json_required: $run_report_campaign_run_report_json_required
        },
        summary_policy: {
          require_incident_snapshot_on_fail: $summary_policy_require_on_fail,
          require_incident_snapshot_artifacts: $summary_policy_require_artifacts,
          incident_snapshot_min_attachment_count: $summary_policy_min_attachment,
          incident_snapshot_max_skipped_count: $summary_policy_max_skipped,
          incident_policy_errors_count: $summary_incident_policy_errors_count
        },
        artifact_paths: {
          run_report: {
            runbook_summary_json: $run_report_runbook_summary_path,
            quick_run_report_json: $run_report_quick_run_report_path,
            campaign_summary_json: $run_report_summary_path,
            campaign_report_md: $run_report_report_md_path,
            campaign_signoff_summary_json: $run_report_campaign_signoff_summary_path
          },
          summary: {
            runbook_summary_json: $summary_artifact_runbook_summary_path,
            quick_run_report_json: $summary_artifact_quick_run_report_path,
            campaign_summary_json: $summary_artifact_campaign_summary_path,
            campaign_report_md: $summary_artifact_campaign_report_md_path
          }
        }
      },
      artifacts: {
        runbook_summary_json: {
          exists: $runbook_summary_exists,
          valid_json: $runbook_summary_valid_json,
          run_report_exists: $run_report_runbook_summary_exists,
          run_report_valid_json: $run_report_runbook_summary_valid_json
        },
        quick_run_report_json: {
          exists: $quick_run_report_exists,
          valid_json: $quick_run_report_valid_json,
          run_report_exists: $run_report_quick_run_report_exists,
          run_report_valid_json: $run_report_quick_run_report_valid_json
        },
        campaign_summary_json: {
          exists: $summary_exists,
          valid_json: $summary_valid_json,
          run_report_exists: $run_report_summary_exists,
          run_report_valid_json: $run_report_summary_valid_json
        },
        campaign_report_md: {
          exists: $report_md_exists,
          run_report_exists: $run_report_report_md_exists
        },
        campaign_signoff_summary_json: {
          exists: $campaign_signoff_summary_exists,
          valid_json: $campaign_signoff_summary_valid_json,
          run_report_exists: $run_report_campaign_signoff_summary_exists,
          run_report_valid_json: $run_report_campaign_signoff_summary_valid_json
        }
      },
      issues: $issues
    }'
)"

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  printf '%s\n' "$summary_payload" >"$summary_json"
fi

echo "[prod-pilot-cohort-campaign-check] campaign_run_report_json=$campaign_run_report_json"
echo "[prod-pilot-cohort-campaign-check] campaign_summary_json=${campaign_summary_json:-unset}"
echo "[prod-pilot-cohort-campaign-check] campaign_report_md=${campaign_report_md:-unset}"
echo "[prod-pilot-cohort-campaign-check] campaign_signoff_summary_json=${campaign_signoff_summary_json:-unset}"
if [[ -n "$summary_json" ]]; then
  echo "[prod-pilot-cohort-campaign-check] summary_json=$summary_json"
fi
echo "[prod-pilot-cohort-campaign-check] freshness max_evidence_age_sec=$max_evidence_age_sec campaign_run_started_at_utc=${campaign_run_started_at_utc:-unset} campaign_run_finished_at_utc=${campaign_run_finished_at_utc:-unset} runbook_summary_started_at=${runbook_summary_started_at:-unset} runbook_summary_finished_at=${runbook_summary_finished_at:-unset} runbook_summary_generated_at_utc=${runbook_summary_generated_at_utc:-unset} quick_run_report_started_at=${quick_run_report_started_at:-unset} quick_run_report_finished_at=${quick_run_report_finished_at:-unset} quick_run_report_generated_at_utc=${quick_run_report_generated_at_utc:-unset} campaign_summary_generated_at_utc=${campaign_summary_generated_at_utc:-unset} campaign_signoff_summary_generated_at_utc=${campaign_signoff_summary_generated_at_utc:-unset}"
echo "[prod-pilot-cohort-campaign-check] decision=$decision status=${status:-unset} quick_runbook_rc=$quick_runbook_rc campaign_summary_attempted=$campaign_summary_attempted campaign_summary_rc=$campaign_summary_rc campaign_signoff_attempted=$campaign_signoff_attempted campaign_signoff_rc=$campaign_signoff_rc campaign_decision=${campaign_decision:-unset}"
if [[ -n "$summary_incident_handoff_summary_json" || -n "$summary_incident_handoff_report_md" ]]; then
  echo "[prod-pilot-cohort-campaign-check] incident_handoff summary_json=${summary_incident_handoff_summary_json:-unset} report_md=${summary_incident_handoff_report_md:-unset}"
fi

if ((${#errors[@]} > 0)); then
  echo "[prod-pilot-cohort-campaign-check] failed with ${#errors[@]} issue(s):"
  for err in "${errors[@]}"; do
    echo "  - $err"
  done
  if [[ "$show_json" == "1" ]]; then
    echo "[prod-pilot-cohort-campaign-check] campaign run report payload:"
    cat "$campaign_run_report_json"
    if [[ "$summary_exists" == "1" ]]; then
      echo "[prod-pilot-cohort-campaign-check] campaign summary payload:"
      cat "$campaign_summary_json"
    fi
  fi
  if [[ "$print_summary_json" == "1" ]]; then
    echo "[prod-pilot-cohort-campaign-check] summary payload:"
    printf '%s\n' "$summary_payload"
  fi
  exit 1
fi

if [[ "$print_summary_json" == "1" ]]; then
  echo "[prod-pilot-cohort-campaign-check] summary payload:"
  printf '%s\n' "$summary_payload"
fi
if [[ "$show_json" == "1" ]]; then
  echo "[prod-pilot-cohort-campaign-check] campaign run report payload:"
  cat "$campaign_run_report_json"
fi
echo "[prod-pilot-cohort-campaign-check] ok"
