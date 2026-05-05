#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SWEEP_SCRIPT="${PROFILE_COMPARE_MULTI_VM_SWEEP_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_sweep.sh}"
REDUCER_SCRIPT="${PROFILE_COMPARE_MULTI_VM_REDUCER_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_reducer.sh}"
CHECK_SCRIPT="${PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign_check.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_multi_vm_cycle.sh \
    [--reports-dir DIR] \
    [--sweep-summary-json PATH] \
    [--sweep-canonical-summary-json PATH] \
    [--sweep-report-md PATH] \
    [--sweep-command-timeout-sec N] \
    [--sweep-allow-partial [0|1]] \
    [--sweep-fail-fast [0|1]] \
    [--sweep-reducer-min-successful-vms N] \
    [--sweep-reducer-require-all-success [0|1]] \
    [--sweep-allow-unready-handoff [0|1]] \
    [--vm-command SPEC]... \
    [--vm-command-file PATH]... \
    [--reducer-summary-json PATH] \
    [--reducer-report-md PATH] \
    [--reducer-fail-on-no-go [0|1]] \
    [--reducer-min-support-rate-pct N] \
    [--reducer-campaign-summary-json PATH]... \
    [--reducer-campaign-summary-list FILE] \
    [--check-campaign-summary-json PATH] \
    [--check-trend-summary-json PATH] \
    [--check-summary-json PATH] \
    [--require-status-pass [0|1]] \
    [--require-trend-status-pass [0|1]] \
    [--require-min-runs-total N] \
    [--require-max-runs-fail N] \
    [--require-max-runs-warn N] \
    [--require-min-runs-with-summary N] \
    [--require-recommendation-support-rate-pct N] \
    [--require-recommended-profile PROFILE] \
    [--allow-recommended-profiles CSV] \
    [--disallow-experimental-default [0|1]] \
    [--require-trend-source CSV] \
    [--require-selection-policy-present [0|1]] \
    [--require-selection-policy-valid [0|1]] \
    [--fail-on-no-go [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Run profile-compare multi-VM sweep, reducer, and campaign policy check in one
  command, then emit one cycle summary artifact with per-stage status/artifacts.

Notes:
  - --vm-command and --vm-command-file are passed directly to sweep stage.
  - Check stage input artifacts are derived from reducer output and written to:
    --check-campaign-summary-json and --check-trend-summary-json paths.
  - Stage scripts can be overridden with:
    PROFILE_COMPARE_MULTI_VM_SWEEP_SCRIPT
    PROFILE_COMPARE_MULTI_VM_REDUCER_SCRIPT
    PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

require_value_or_die() {
  local flag="$1"
  local argc="$2"
  if (( argc < 2 )); then
    echo "$flag requires a value"
    exit 2
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

int_arg_or_die() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be a non-negative integer"
    exit 2
  fi
}

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

non_negative_int_or_zero() {
  local value
  value="$(trim "${1:-}")"
  if [[ "$value" =~ ^-?[0-9]+$ ]]; then
    if (( value < 0 )); then
      printf '%s' "0"
    else
      printf '%s' "$value"
    fi
  else
    printf '%s' "0"
  fi
}

non_negative_decimal_or_zero() {
  local value
  value="$(trim "${1:-}")"
  if is_non_negative_decimal "$value"; then
    printf '%s' "$value"
  else
    printf '%s' "0"
  fi
}

normalize_decision() {
  local decision
  decision="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
  case "$decision" in
    GO) printf '%s\n' "GO" ;;
    NO-GO|NOGO|NO_GO) printf '%s\n' "NO-GO" ;;
    *) printf '%s\n' "$decision" ;;
  esac
}

quote_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

redact_text() {
  local value="$1"
  local sensitive_flags sensitive_envs
  sensitive_flags='--campaign-subject|--subject|--key|--invite-key|--campaign-anon-cred|--anon-cred|--token|--auth-token|--admin-token|--authorization|--bearer|--password|--secret|--api-key'
  sensitive_envs='CAMPAIGN_SUBJECT|INVITE_KEY|ANON_CRED|AUTH_TOKEN|ADMIN_TOKEN|API_KEY|PASSWORD|SECRET'
  printf '%s' "$value" | sed -E \
    -e "s/(--vm-command[[:space:]]+)(([^[:space:]]|\\\\[[:space:]])+)/\\1[redacted]/g" \
    -e "s/(--vm-command[[:space:]]*=[[:space:]]*)(([^[:space:]]|\\\\[[:space:]])+)/\\1[redacted]/g" \
    -e "s/(((${sensitive_flags})[[:space:]]+))\"([^\"]*)\"/\\1[redacted]/g" \
    -e "s/(((${sensitive_flags})[[:space:]]+))'([^']*)'/\\1[redacted]/g" \
    -e "s/(((${sensitive_flags})[[:space:]]+))([^[:space:]]+)/\\1[redacted]/g" \
    -e "s/(((${sensitive_flags})[[:space:]]*=[[:space:]]*))\"([^\"]*)\"/\\1[redacted]/g" \
    -e "s/(((${sensitive_flags})[[:space:]]*=[[:space:]]*))'([^']*)'/\\1[redacted]/g" \
    -e "s/(((${sensitive_flags})[[:space:]]*=[[:space:]]*))([^[:space:]]+)/\\1[redacted]/g" \
    -e "s/(((${sensitive_envs})[[:space:]]*=[[:space:]]*))\"([^\"]*)\"/\\1[redacted]/g" \
    -e "s/(((${sensitive_envs})[[:space:]]*=[[:space:]]*))'([^']*)'/\\1[redacted]/g" \
    -e "s/(((${sensitive_envs})[[:space:]]*=[[:space:]]*))([^[:space:]]+)/\\1[redacted]/g" \
    -e "s#([[:alpha:]][[:alnum:]+.-]*://)[^/@[:space:]]+@#\\1[redacted]@#g" \
    -e "s/([?&]([Tt][Oo][Kk][Ee][Nn]|[Aa][Uu][Tt][Hh]_[Tt][Oo][Kk][Ee][Nn]|[Aa][Pp][Ii]_[Kk][Ee][Yy]|[Aa][Pp][Ii][Kk][Ee][Yy]|[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Aa][Nn][Oo][Nn]_[Cc][Rr][Ee][Dd]|[Ii][Nn][Vv][Ii][Tt][Ee]_[Kk][Ee][Yy]|[Cc][Aa][Mm][Pp][Aa][Ii][Gg][Nn]_[Ss][Uu][Bb][Jj][Ee][Cc][Tt])=)[^&#[:space:]]+/\\1[redacted]/g" \
    -e "s/([Aa]uthorization:[[:space:]]*[Bb]earer[[:space:]]+)[^[:space:]\"']+/\\1[redacted]/g" \
    -e "s/(-H[[:space:]]+['\"]?[A-Za-z0-9-]*(authorization|token|key|secret|cookie|auth)[A-Za-z0-9-]*:[[:space:]]*)[^'\"[:space:]]+(['\"]?)/\\1[redacted]\\3/gI" \
    -e "s/(([A-Za-z0-9-]*(authorization|token|key|secret|cookie|auth)[A-Za-z0-9-]*:[[:space:]]*))[^[:space:]\"']+/\\1[redacted]/gI"
}

json_file_valid_01() {
  local path="$1"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '%s' "0"
    return
  fi
  if jq -e 'type == "object"' "$path" >/dev/null 2>&1; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

file_fingerprint_01() {
  local path="$1"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '%s' ""
    return
  fi
  cksum "$path" 2>/dev/null | awk '{print $1 ":" $2}' || true
}

array_to_json() {
  if (( $# == 0 )); then
    printf '%s' "[]"
  else
    printf '%s\n' "$@" | jq -R . | jq -s '.'
  fi
}

need_cmd jq
need_cmd date
need_cmd bash
need_cmd mkdir
need_cmd cksum

reports_dir="${PROFILE_COMPARE_MULTI_VM_CYCLE_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"

sweep_summary_json="${PROFILE_COMPARE_MULTI_VM_CYCLE_SWEEP_SUMMARY_JSON:-}"
sweep_canonical_summary_json="${PROFILE_COMPARE_MULTI_VM_CYCLE_SWEEP_CANONICAL_SUMMARY_JSON:-}"
sweep_report_md="${PROFILE_COMPARE_MULTI_VM_CYCLE_SWEEP_REPORT_MD:-}"
sweep_command_timeout_sec="${PROFILE_COMPARE_MULTI_VM_CYCLE_SWEEP_COMMAND_TIMEOUT_SEC:-2400}"
sweep_allow_partial="${PROFILE_COMPARE_MULTI_VM_CYCLE_SWEEP_ALLOW_PARTIAL:-0}"
sweep_fail_fast="${PROFILE_COMPARE_MULTI_VM_CYCLE_SWEEP_FAIL_FAST:-0}"
sweep_reducer_min_successful_vms="${PROFILE_COMPARE_MULTI_VM_CYCLE_SWEEP_REDUCER_MIN_SUCCESSFUL_VMS:-1}"
sweep_reducer_require_all_success="${PROFILE_COMPARE_MULTI_VM_CYCLE_SWEEP_REDUCER_REQUIRE_ALL_SUCCESS:-0}"
sweep_allow_unready_handoff="${PROFILE_COMPARE_MULTI_VM_CYCLE_SWEEP_ALLOW_UNREADY_HANDOFF:-0}"

reducer_summary_json="${PROFILE_COMPARE_MULTI_VM_CYCLE_REDUCER_SUMMARY_JSON:-}"
reducer_report_md="${PROFILE_COMPARE_MULTI_VM_CYCLE_REDUCER_REPORT_MD:-}"
reducer_fail_on_no_go="${PROFILE_COMPARE_MULTI_VM_CYCLE_REDUCER_FAIL_ON_NO_GO:-0}"
reducer_min_support_rate_pct="${PROFILE_COMPARE_MULTI_VM_CYCLE_REDUCER_MIN_SUPPORT_RATE_PCT:-${PROFILE_COMPARE_MULTI_VM_REDUCER_MIN_SUPPORT_RATE_PCT:-60}}"
reducer_campaign_summary_list="${PROFILE_COMPARE_MULTI_VM_CYCLE_REDUCER_CAMPAIGN_SUMMARY_LIST:-}"

check_campaign_summary_json="${PROFILE_COMPARE_MULTI_VM_CYCLE_CHECK_CAMPAIGN_SUMMARY_JSON:-}"
check_trend_summary_json="${PROFILE_COMPARE_MULTI_VM_CYCLE_CHECK_TREND_SUMMARY_JSON:-}"
check_summary_json="${PROFILE_COMPARE_MULTI_VM_CYCLE_CHECK_SUMMARY_JSON:-}"

require_status_pass="${PROFILE_COMPARE_MULTI_VM_CYCLE_REQUIRE_STATUS_PASS:-${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_STATUS_PASS:-1}}"
require_trend_status_pass="${PROFILE_COMPARE_MULTI_VM_CYCLE_REQUIRE_TREND_STATUS_PASS:-${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_TREND_STATUS_PASS:-1}}"
require_min_runs_total="${PROFILE_COMPARE_MULTI_VM_CYCLE_REQUIRE_MIN_RUNS_TOTAL:-${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MIN_RUNS_TOTAL:-3}}"
require_max_runs_fail="${PROFILE_COMPARE_MULTI_VM_CYCLE_REQUIRE_MAX_RUNS_FAIL:-${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MAX_RUNS_FAIL:-0}}"
require_max_runs_warn="${PROFILE_COMPARE_MULTI_VM_CYCLE_REQUIRE_MAX_RUNS_WARN:-${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MAX_RUNS_WARN:-0}}"
require_min_runs_with_summary="${PROFILE_COMPARE_MULTI_VM_CYCLE_REQUIRE_MIN_RUNS_WITH_SUMMARY:-${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MIN_RUNS_WITH_SUMMARY:-3}}"
require_recommendation_support_rate_pct="${PROFILE_COMPARE_MULTI_VM_CYCLE_REQUIRE_RECOMMENDATION_SUPPORT_RATE_PCT:-${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_RECOMMENDATION_SUPPORT_RATE_PCT:-60}}"
require_recommended_profile="${PROFILE_COMPARE_MULTI_VM_CYCLE_REQUIRE_RECOMMENDED_PROFILE:-${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_RECOMMENDED_PROFILE:-}}"
allow_recommended_profiles="${PROFILE_COMPARE_MULTI_VM_CYCLE_ALLOW_RECOMMENDED_PROFILES:-${PROFILE_COMPARE_CAMPAIGN_CHECK_ALLOW_RECOMMENDED_PROFILES:-balanced,speed,private}}"
disallow_experimental_default="${PROFILE_COMPARE_MULTI_VM_CYCLE_DISALLOW_EXPERIMENTAL_DEFAULT:-${PROFILE_COMPARE_CAMPAIGN_CHECK_DISALLOW_EXPERIMENTAL_DEFAULT:-1}}"
require_trend_source="${PROFILE_COMPARE_MULTI_VM_CYCLE_REQUIRE_TREND_SOURCE:-${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_TREND_SOURCE:-policy_reliability_latency,vote_fallback,safe_default_fallback}}"
require_selection_policy_present="${PROFILE_COMPARE_MULTI_VM_CYCLE_REQUIRE_SELECTION_POLICY_PRESENT:-${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_SELECTION_POLICY_PRESENT:-0}}"
require_selection_policy_valid="${PROFILE_COMPARE_MULTI_VM_CYCLE_REQUIRE_SELECTION_POLICY_VALID:-${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_SELECTION_POLICY_VALID:-0}}"
fail_on_no_go="${PROFILE_COMPARE_MULTI_VM_CYCLE_FAIL_ON_NO_GO:-${PROFILE_COMPARE_CAMPAIGN_CHECK_FAIL_ON_NO_GO:-1}}"

summary_json="${PROFILE_COMPARE_MULTI_VM_CYCLE_SUMMARY_JSON:-}"
show_json="${PROFILE_COMPARE_MULTI_VM_CYCLE_SHOW_JSON:-0}"
print_summary_json="${PROFILE_COMPARE_MULTI_VM_CYCLE_PRINT_SUMMARY_JSON:-0}"

declare -a vm_command_specs=()
declare -a vm_command_files=()
declare -a reducer_campaign_summary_jsons=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      require_value_or_die "$1" "$#"
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --sweep-summary-json)
      require_value_or_die "$1" "$#"
      sweep_summary_json="${2:-}"
      shift 2
      ;;
    --sweep-summary-json=*)
      sweep_summary_json="${1#*=}"
      shift
      ;;
    --sweep-canonical-summary-json)
      require_value_or_die "$1" "$#"
      sweep_canonical_summary_json="${2:-}"
      shift 2
      ;;
    --sweep-canonical-summary-json=*)
      sweep_canonical_summary_json="${1#*=}"
      shift
      ;;
    --sweep-report-md)
      require_value_or_die "$1" "$#"
      sweep_report_md="${2:-}"
      shift 2
      ;;
    --sweep-report-md=*)
      sweep_report_md="${1#*=}"
      shift
      ;;
    --sweep-command-timeout-sec)
      require_value_or_die "$1" "$#"
      sweep_command_timeout_sec="${2:-}"
      shift 2
      ;;
    --sweep-command-timeout-sec=*)
      sweep_command_timeout_sec="${1#*=}"
      shift
      ;;
    --sweep-allow-partial)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        sweep_allow_partial="${2:-}"
        shift 2
      else
        sweep_allow_partial="1"
        shift
      fi
      ;;
    --sweep-allow-partial=*)
      sweep_allow_partial="${1#*=}"
      shift
      ;;
    --sweep-fail-fast)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        sweep_fail_fast="${2:-}"
        shift 2
      else
        sweep_fail_fast="1"
        shift
      fi
      ;;
    --sweep-fail-fast=*)
      sweep_fail_fast="${1#*=}"
      shift
      ;;
    --sweep-reducer-min-successful-vms)
      require_value_or_die "$1" "$#"
      sweep_reducer_min_successful_vms="${2:-}"
      shift 2
      ;;
    --sweep-reducer-min-successful-vms=*)
      sweep_reducer_min_successful_vms="${1#*=}"
      shift
      ;;
    --sweep-reducer-require-all-success)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        sweep_reducer_require_all_success="${2:-}"
        shift 2
      else
        sweep_reducer_require_all_success="1"
        shift
      fi
      ;;
    --sweep-reducer-require-all-success=*)
      sweep_reducer_require_all_success="${1#*=}"
      shift
      ;;
    --sweep-allow-unready-handoff)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        sweep_allow_unready_handoff="${2:-}"
        shift 2
      else
        sweep_allow_unready_handoff="1"
        shift
      fi
      ;;
    --sweep-allow-unready-handoff=*)
      sweep_allow_unready_handoff="${1#*=}"
      shift
      ;;
    --vm-command)
      require_value_or_die "$1" "$#"
      vm_command_specs+=("${2:-}")
      shift 2
      ;;
    --vm-command=*)
      vm_command_specs+=("${1#*=}")
      shift
      ;;
    --vm-command-file)
      require_value_or_die "$1" "$#"
      vm_command_files+=("${2:-}")
      shift 2
      ;;
    --vm-command-file=*)
      vm_command_files+=("${1#*=}")
      shift
      ;;
    --reducer-summary-json)
      require_value_or_die "$1" "$#"
      reducer_summary_json="${2:-}"
      shift 2
      ;;
    --reducer-summary-json=*)
      reducer_summary_json="${1#*=}"
      shift
      ;;
    --reducer-report-md)
      require_value_or_die "$1" "$#"
      reducer_report_md="${2:-}"
      shift 2
      ;;
    --reducer-report-md=*)
      reducer_report_md="${1#*=}"
      shift
      ;;
    --reducer-fail-on-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        reducer_fail_on_no_go="${2:-}"
        shift 2
      else
        reducer_fail_on_no_go="1"
        shift
      fi
      ;;
    --reducer-fail-on-no-go=*)
      reducer_fail_on_no_go="${1#*=}"
      shift
      ;;
    --reducer-min-support-rate-pct)
      require_value_or_die "$1" "$#"
      reducer_min_support_rate_pct="${2:-}"
      shift 2
      ;;
    --reducer-min-support-rate-pct=*)
      reducer_min_support_rate_pct="${1#*=}"
      shift
      ;;
    --reducer-campaign-summary-json)
      require_value_or_die "$1" "$#"
      reducer_campaign_summary_jsons+=("${2:-}")
      shift 2
      ;;
    --reducer-campaign-summary-json=*)
      reducer_campaign_summary_jsons+=("${1#*=}")
      shift
      ;;
    --reducer-campaign-summary-list)
      require_value_or_die "$1" "$#"
      reducer_campaign_summary_list="${2:-}"
      shift 2
      ;;
    --reducer-campaign-summary-list=*)
      reducer_campaign_summary_list="${1#*=}"
      shift
      ;;
    --check-campaign-summary-json)
      require_value_or_die "$1" "$#"
      check_campaign_summary_json="${2:-}"
      shift 2
      ;;
    --check-campaign-summary-json=*)
      check_campaign_summary_json="${1#*=}"
      shift
      ;;
    --check-trend-summary-json)
      require_value_or_die "$1" "$#"
      check_trend_summary_json="${2:-}"
      shift 2
      ;;
    --check-trend-summary-json=*)
      check_trend_summary_json="${1#*=}"
      shift
      ;;
    --check-summary-json)
      require_value_or_die "$1" "$#"
      check_summary_json="${2:-}"
      shift 2
      ;;
    --check-summary-json=*)
      check_summary_json="${1#*=}"
      shift
      ;;
    --require-status-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_status_pass="${2:-}"
        shift 2
      else
        require_status_pass="1"
        shift
      fi
      ;;
    --require-status-pass=*)
      require_status_pass="${1#*=}"
      shift
      ;;
    --require-trend-status-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_trend_status_pass="${2:-}"
        shift 2
      else
        require_trend_status_pass="1"
        shift
      fi
      ;;
    --require-trend-status-pass=*)
      require_trend_status_pass="${1#*=}"
      shift
      ;;
    --require-min-runs-total)
      require_value_or_die "$1" "$#"
      require_min_runs_total="${2:-}"
      shift 2
      ;;
    --require-min-runs-total=*)
      require_min_runs_total="${1#*=}"
      shift
      ;;
    --require-max-runs-fail)
      require_value_or_die "$1" "$#"
      require_max_runs_fail="${2:-}"
      shift 2
      ;;
    --require-max-runs-fail=*)
      require_max_runs_fail="${1#*=}"
      shift
      ;;
    --require-max-runs-warn)
      require_value_or_die "$1" "$#"
      require_max_runs_warn="${2:-}"
      shift 2
      ;;
    --require-max-runs-warn=*)
      require_max_runs_warn="${1#*=}"
      shift
      ;;
    --require-min-runs-with-summary)
      require_value_or_die "$1" "$#"
      require_min_runs_with_summary="${2:-}"
      shift 2
      ;;
    --require-min-runs-with-summary=*)
      require_min_runs_with_summary="${1#*=}"
      shift
      ;;
    --require-recommendation-support-rate-pct)
      require_value_or_die "$1" "$#"
      require_recommendation_support_rate_pct="${2:-}"
      shift 2
      ;;
    --require-recommendation-support-rate-pct=*)
      require_recommendation_support_rate_pct="${1#*=}"
      shift
      ;;
    --require-recommended-profile)
      require_value_or_die "$1" "$#"
      require_recommended_profile="${2:-}"
      shift 2
      ;;
    --require-recommended-profile=*)
      require_recommended_profile="${1#*=}"
      shift
      ;;
    --allow-recommended-profiles)
      require_value_or_die "$1" "$#"
      allow_recommended_profiles="${2:-}"
      shift 2
      ;;
    --allow-recommended-profiles=*)
      allow_recommended_profiles="${1#*=}"
      shift
      ;;
    --disallow-experimental-default)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        disallow_experimental_default="${2:-}"
        shift 2
      else
        disallow_experimental_default="1"
        shift
      fi
      ;;
    --disallow-experimental-default=*)
      disallow_experimental_default="${1#*=}"
      shift
      ;;
    --require-trend-source)
      require_value_or_die "$1" "$#"
      require_trend_source="${2:-}"
      shift 2
      ;;
    --require-trend-source=*)
      require_trend_source="${1#*=}"
      shift
      ;;
    --require-selection-policy-present)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_selection_policy_present="${2:-}"
        shift 2
      else
        require_selection_policy_present="1"
        shift
      fi
      ;;
    --require-selection-policy-present=*)
      require_selection_policy_present="${1#*=}"
      shift
      ;;
    --require-selection-policy-valid)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_selection_policy_valid="${2:-}"
        shift 2
      else
        require_selection_policy_valid="1"
        shift
      fi
      ;;
    --require-selection-policy-valid=*)
      require_selection_policy_valid="${1#*=}"
      shift
      ;;
    --fail-on-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_no_go="${2:-}"
        shift 2
      else
        fail_on_no_go="1"
        shift
      fi
      ;;
    --fail-on-no-go=*)
      fail_on_no_go="${1#*=}"
      shift
      ;;
    --summary-json)
      require_value_or_die "$1" "$#"
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
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
    --show-json=*)
      show_json="${1#*=}"
      shift
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
    --print-summary-json=*)
      print_summary_json="${1#*=}"
      shift
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

reports_dir="$(abs_path "$reports_dir")"
sweep_summary_json="$(abs_path "$sweep_summary_json")"
sweep_canonical_summary_json="$(abs_path "$sweep_canonical_summary_json")"
sweep_report_md="$(abs_path "$sweep_report_md")"
sweep_command_timeout_sec="$(trim "$sweep_command_timeout_sec")"
sweep_allow_partial="$(trim "$sweep_allow_partial")"
sweep_fail_fast="$(trim "$sweep_fail_fast")"
sweep_reducer_min_successful_vms="$(trim "$sweep_reducer_min_successful_vms")"
sweep_reducer_require_all_success="$(trim "$sweep_reducer_require_all_success")"
sweep_allow_unready_handoff="$(trim "$sweep_allow_unready_handoff")"

reducer_summary_json="$(abs_path "$reducer_summary_json")"
reducer_report_md="$(abs_path "$reducer_report_md")"
reducer_fail_on_no_go="$(trim "$reducer_fail_on_no_go")"
reducer_min_support_rate_pct="$(trim "$reducer_min_support_rate_pct")"
reducer_campaign_summary_list="$(abs_path "$reducer_campaign_summary_list")"

check_campaign_summary_json="$(abs_path "$check_campaign_summary_json")"
check_trend_summary_json="$(abs_path "$check_trend_summary_json")"
check_summary_json="$(abs_path "$check_summary_json")"

require_status_pass="$(trim "$require_status_pass")"
require_trend_status_pass="$(trim "$require_trend_status_pass")"
require_min_runs_total="$(trim "$require_min_runs_total")"
require_max_runs_fail="$(trim "$require_max_runs_fail")"
require_max_runs_warn="$(trim "$require_max_runs_warn")"
require_min_runs_with_summary="$(trim "$require_min_runs_with_summary")"
require_recommendation_support_rate_pct="$(trim "$require_recommendation_support_rate_pct")"
require_recommended_profile="$(trim "$require_recommended_profile")"
allow_recommended_profiles="$(trim "$allow_recommended_profiles")"
disallow_experimental_default="$(trim "$disallow_experimental_default")"
require_trend_source="$(trim "$require_trend_source")"
require_selection_policy_present="$(trim "$require_selection_policy_present")"
require_selection_policy_valid="$(trim "$require_selection_policy_valid")"
fail_on_no_go="$(trim "$fail_on_no_go")"

summary_json="$(abs_path "$summary_json")"
show_json="$(trim "$show_json")"
print_summary_json="$(trim "$print_summary_json")"

SWEEP_SCRIPT="$(abs_path "$SWEEP_SCRIPT")"
REDUCER_SCRIPT="$(abs_path "$REDUCER_SCRIPT")"
CHECK_SCRIPT="$(abs_path "$CHECK_SCRIPT")"

if [[ ! -f "$SWEEP_SCRIPT" ]]; then
  echo "multi-vm sweep script not found: $SWEEP_SCRIPT"
  exit 2
fi
if [[ ! -f "$REDUCER_SCRIPT" ]]; then
  echo "multi-vm reducer script not found: $REDUCER_SCRIPT"
  exit 2
fi
if [[ ! -f "$CHECK_SCRIPT" ]]; then
  echo "campaign-check script not found: $CHECK_SCRIPT"
  exit 2
fi

bool_arg_or_die "--sweep-allow-partial" "$sweep_allow_partial"
bool_arg_or_die "--sweep-fail-fast" "$sweep_fail_fast"
bool_arg_or_die "--sweep-reducer-require-all-success" "$sweep_reducer_require_all_success"
bool_arg_or_die "--sweep-allow-unready-handoff" "$sweep_allow_unready_handoff"
bool_arg_or_die "--reducer-fail-on-no-go" "$reducer_fail_on_no_go"
bool_arg_or_die "--require-status-pass" "$require_status_pass"
bool_arg_or_die "--require-trend-status-pass" "$require_trend_status_pass"
bool_arg_or_die "--disallow-experimental-default" "$disallow_experimental_default"
bool_arg_or_die "--require-selection-policy-present" "$require_selection_policy_present"
bool_arg_or_die "--require-selection-policy-valid" "$require_selection_policy_valid"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

int_arg_or_die "--sweep-command-timeout-sec" "$sweep_command_timeout_sec"
int_arg_or_die "--sweep-reducer-min-successful-vms" "$sweep_reducer_min_successful_vms"
int_arg_or_die "--require-min-runs-total" "$require_min_runs_total"
int_arg_or_die "--require-max-runs-fail" "$require_max_runs_fail"
int_arg_or_die "--require-max-runs-warn" "$require_max_runs_warn"
int_arg_or_die "--require-min-runs-with-summary" "$require_min_runs_with_summary"
if (( sweep_reducer_min_successful_vms < 1 )); then
  echo "--sweep-reducer-min-successful-vms must be >= 1"
  exit 2
fi

if ! is_non_negative_decimal "$require_recommendation_support_rate_pct"; then
  echo "--require-recommendation-support-rate-pct must be a non-negative number"
  exit 2
fi
if ! is_non_negative_decimal "$reducer_min_support_rate_pct"; then
  echo "--reducer-min-support-rate-pct must be a non-negative number"
  exit 2
fi
if awk -v raw="$reducer_min_support_rate_pct" 'BEGIN { exit !(raw > 100) }'; then
  echo "--reducer-min-support-rate-pct must be <= 100"
  exit 2
fi
reducer_min_support_rate_pct="$(awk -v raw="$reducer_min_support_rate_pct" 'BEGIN { printf "%.2f", raw + 0 }')"

if [[ ${#vm_command_specs[@]} -eq 0 && ${#vm_command_files[@]} -eq 0 ]]; then
  echo "at least one --vm-command or --vm-command-file is required"
  exit 2
fi

declare -a vm_command_specs_norm=()
for spec in "${vm_command_specs[@]}"; do
  spec="$(trim "$spec")"
  if [[ -z "$spec" ]]; then
    echo "empty --vm-command value is not allowed"
    exit 2
  fi
  vm_command_specs_norm+=("$spec")
done
vm_command_specs=("${vm_command_specs_norm[@]}")

declare -a vm_command_files_norm=()
for vm_file in "${vm_command_files[@]}"; do
  vm_file="$(abs_path "$vm_file")"
  if [[ -z "$vm_file" || ! -f "$vm_file" ]]; then
    echo "--vm-command-file not found: $vm_file"
    exit 2
  fi
  vm_command_files_norm+=("$vm_file")
done
vm_command_files=("${vm_command_files_norm[@]}")

declare -a reducer_campaign_summary_jsons_norm=()
for reducer_input in "${reducer_campaign_summary_jsons[@]}"; do
  reducer_input="$(abs_path "$reducer_input")"
  if [[ -n "$reducer_input" ]]; then
    reducer_campaign_summary_jsons_norm+=("$reducer_input")
  fi
done
reducer_campaign_summary_jsons=("${reducer_campaign_summary_jsons_norm[@]}")

if [[ -n "$reducer_campaign_summary_list" && ! -f "$reducer_campaign_summary_list" ]]; then
  echo "--reducer-campaign-summary-list file not found: $reducer_campaign_summary_list"
  exit 2
fi

mkdir -p "$reports_dir"

if [[ -z "$sweep_summary_json" ]]; then
  sweep_summary_json="$reports_dir/profile_compare_multi_vm_sweep_summary.json"
fi
if [[ -z "$sweep_canonical_summary_json" ]]; then
  sweep_canonical_summary_json="$reports_dir/profile_compare_multi_vm_sweep_canonical_summary.json"
fi
if [[ -z "$sweep_report_md" ]]; then
  sweep_report_md="$reports_dir/profile_compare_multi_vm_sweep_report.md"
fi
if [[ -z "$reducer_summary_json" ]]; then
  reducer_summary_json="$reports_dir/profile_compare_multi_vm_reducer_summary.json"
fi
if [[ -z "$reducer_report_md" ]]; then
  reducer_report_md="$reports_dir/profile_compare_multi_vm_reducer_report.md"
fi
if [[ -z "$check_campaign_summary_json" ]]; then
  check_campaign_summary_json="$reports_dir/profile_compare_multi_vm_campaign_summary_for_check.json"
fi
if [[ -z "$check_trend_summary_json" ]]; then
  check_trend_summary_json="$reports_dir/profile_compare_multi_vm_trend_summary_for_check.json"
fi
if [[ -z "$check_summary_json" ]]; then
  check_summary_json="$reports_dir/profile_compare_multi_vm_check_summary.json"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/profile_compare_multi_vm_cycle_summary.json"
fi

mkdir -p \
  "$(dirname "$sweep_summary_json")" \
  "$(dirname "$sweep_canonical_summary_json")" \
  "$(dirname "$sweep_report_md")" \
  "$(dirname "$reducer_summary_json")" \
  "$(dirname "$reducer_report_md")" \
  "$(dirname "$check_campaign_summary_json")" \
  "$(dirname "$check_trend_summary_json")" \
  "$(dirname "$check_summary_json")" \
  "$(dirname "$summary_json")"

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
sweep_log="$reports_dir/profile_compare_multi_vm_cycle_${run_stamp}_sweep.log"
reducer_log="$reports_dir/profile_compare_multi_vm_cycle_${run_stamp}_reducer.log"
check_log="$reports_dir/profile_compare_multi_vm_cycle_${run_stamp}_check.log"

declare -a sweep_cmd=(
  bash "$SWEEP_SCRIPT"
  --reports-dir "$reports_dir"
  --summary-json "$sweep_summary_json"
  --canonical-summary-json "$sweep_canonical_summary_json"
  --report-md "$sweep_report_md"
  --command-timeout-sec "$sweep_command_timeout_sec"
  --allow-partial "$sweep_allow_partial"
  --fail-fast "$sweep_fail_fast"
  --reducer-min-successful-vms "$sweep_reducer_min_successful_vms"
  --reducer-require-all-success "$sweep_reducer_require_all_success"
  --print-summary-json 0
)
for spec in "${vm_command_specs[@]}"; do
  sweep_cmd+=(--vm-command "$spec")
done
for vm_file in "${vm_command_files[@]}"; do
  sweep_cmd+=(--vm-command-file "$vm_file")
done
sweep_command_display="$(redact_text "$(quote_cmd "${sweep_cmd[@]}")")"

vm_command_count_json="${#vm_command_specs[@]}"
vm_command_file_count_json="${#vm_command_files[@]}"
reducer_campaign_summary_json_count_json="${#reducer_campaign_summary_jsons[@]}"

sweep_stage_status="skip"
sweep_stage_rc=0
sweep_summary_exists="false"
sweep_summary_valid="false"
sweep_summary_fresh="false"
sweep_reducer_handoff_ready="false"
sweep_reducer_handoff_not_ready_reason=""
sweep_reducer_input_vm_count_json="0"
sweep_reducer_input_summary_jsons_json="[]"
sweep_reducer_input_missing_paths=0

reducer_stage_attempted="false"
reducer_stage_status="skip"
reducer_stage_rc=0
reducer_stage_rc_json="null"
reducer_command_display=""
reducer_summary_exists="false"
reducer_summary_valid="false"
reducer_summary_fresh="false"
reducer_decision=""
reducer_status_value=""
reducer_rc_json="null"
reducer_recommended_profile=""
reducer_support_rate_pct_json="null"
reducer_trend_source=""
reducer_errors_json="[]"
reducer_promotion_gate_available="false"
reducer_promotion_gate_decision=""
reducer_promotion_gate_status=""
reducer_promotion_gate_ready_json="false"
reducer_promotion_missing_evidence_json="[]"

check_stage_attempted="false"
check_stage_status="skip"
check_stage_rc=0
check_stage_rc_json="null"
check_command_display=""
check_summary_exists="false"
check_summary_valid="false"
check_summary_fresh="false"
check_decision=""
check_status_value=""
check_rc_json="null"
check_recommended_profile=""
check_support_rate_pct_json="null"
check_trend_source_value=""
check_errors_json="[]"
check_promotion_missing_evidence_json="[]"

failure_stage=""
failure_reason=""
decision=""
status="fail"
final_rc=1

declare -a sweep_reducer_input_summary_jsons=()

echo "[profile-compare-multi-vm-cycle] $(timestamp_utc) sweep-stage start reports_dir=$reports_dir sweep_summary_json=$sweep_summary_json"
pre_sweep_summary_fingerprint="$(file_fingerprint_01 "$sweep_summary_json")"
set +e
"${sweep_cmd[@]}" >"$sweep_log" 2>&1
sweep_stage_rc=$?
set -e

sweep_stage_status="pass"
if [[ "$sweep_stage_rc" -ne 0 ]]; then
  sweep_stage_status="fail"
fi

if [[ -f "$sweep_summary_json" ]]; then
  sweep_summary_exists="true"
fi
if [[ "$(json_file_valid_01 "$sweep_summary_json")" == "1" ]]; then
  sweep_summary_valid="true"
  post_sweep_summary_fingerprint="$(file_fingerprint_01 "$sweep_summary_json")"
  if [[ -z "$pre_sweep_summary_fingerprint" && -n "$post_sweep_summary_fingerprint" ]]; then
    sweep_summary_fresh="true"
  elif [[ -n "$post_sweep_summary_fingerprint" && "$post_sweep_summary_fingerprint" != "$pre_sweep_summary_fingerprint" ]]; then
    sweep_summary_fresh="true"
  fi
  sweep_reducer_handoff_ready="$(jq -r '
    if (.reducer_handoff.ready | type) == "boolean"
    then (.reducer_handoff.ready | tostring)
    else "false"
    end
  ' "$sweep_summary_json" 2>/dev/null || printf '%s' "false")"
  sweep_reducer_handoff_not_ready_reason="$(jq -r '
    if (.reducer_handoff.not_ready_reason | type) == "string"
    then .reducer_handoff.not_ready_reason
    else ""
    end
  ' "$sweep_summary_json" 2>/dev/null || printf '%s' "")"
  sweep_reducer_input_vm_count_json="$(jq -r '
    if (.reducer_handoff.input_vm_count | type) == "number"
    then (.reducer_handoff.input_vm_count | floor)
    else 0
    end
  ' "$sweep_summary_json" 2>/dev/null || printf '%s' "0")"
  sweep_reducer_input_vm_count_json="$(non_negative_int_or_zero "$sweep_reducer_input_vm_count_json")"
  mapfile -t sweep_reducer_input_summary_jsons < <(
    jq -r '
      .reducer_handoff.input_summary_jsons[]?
      | select(type == "string" and length > 0)
    ' "$sweep_summary_json" 2>/dev/null || true
  )
  if [[ ${#sweep_reducer_input_summary_jsons[@]} -gt 0 ]]; then
    declare -a sweep_reducer_input_summary_jsons_norm=()
    for sweep_input_path in "${sweep_reducer_input_summary_jsons[@]}"; do
      sweep_input_path="$(abs_path "$sweep_input_path")"
      if [[ -n "$sweep_input_path" ]]; then
        sweep_reducer_input_summary_jsons_norm+=("$sweep_input_path")
        if [[ ! -f "$sweep_input_path" ]]; then
          sweep_reducer_input_missing_paths=$((sweep_reducer_input_missing_paths + 1))
        fi
      fi
    done
    sweep_reducer_input_summary_jsons=("${sweep_reducer_input_summary_jsons_norm[@]}")
    sweep_reducer_input_summary_jsons_json="$(array_to_json "${sweep_reducer_input_summary_jsons[@]}")"
  fi
fi

proceed_reducer="false"
if [[ "$sweep_stage_rc" -ne 0 ]]; then
  failure_stage="sweep"
  failure_reason="multi-vm sweep failed (rc=$sweep_stage_rc)"
  decision="NO-GO"
  status="fail"
  final_rc="$sweep_stage_rc"
  if [[ "$final_rc" -eq 0 ]]; then
    final_rc=1
  fi
elif [[ "$sweep_summary_valid" != "true" ]]; then
  sweep_stage_status="fail"
  failure_stage="sweep"
  failure_reason="multi-vm sweep summary is missing or invalid"
  decision="NO-GO"
  status="fail"
  final_rc=1
elif [[ "$sweep_summary_fresh" != "true" ]]; then
  sweep_stage_status="fail"
  failure_stage="sweep"
  failure_reason="multi-vm sweep summary is stale (not refreshed by current run)"
  decision="NO-GO"
  status="fail"
  final_rc=1
elif [[ "$sweep_reducer_handoff_ready" != "true" && "$sweep_allow_unready_handoff" != "1" ]]; then
  sweep_stage_status="fail"
  failure_stage="sweep"
  if [[ -n "$sweep_reducer_handoff_not_ready_reason" ]]; then
    failure_reason="multi-vm sweep reducer handoff is not ready: $sweep_reducer_handoff_not_ready_reason"
  else
    failure_reason="multi-vm sweep reducer handoff is not ready"
  fi
  decision="NO-GO"
  status="fail"
  final_rc=1
elif [[ "$sweep_reducer_handoff_ready" == "true" && ${#reducer_campaign_summary_jsons[@]} -eq 0 && -z "$reducer_campaign_summary_list" && "$sweep_reducer_input_vm_count_json" != "${#sweep_reducer_input_summary_jsons[@]}" ]]; then
  sweep_stage_status="fail"
  failure_stage="sweep"
  failure_reason="multi-vm sweep reducer handoff is inconsistent: ready=true but reducer input summary count does not match advertised input_vm_count"
  decision="NO-GO"
  status="fail"
  final_rc=1
elif [[ "$sweep_reducer_handoff_ready" == "true" && ${#reducer_campaign_summary_jsons[@]} -eq 0 && -z "$reducer_campaign_summary_list" && "$sweep_reducer_input_missing_paths" -gt 0 ]]; then
  sweep_stage_status="fail"
  failure_stage="sweep"
  failure_reason="multi-vm sweep reducer handoff is inconsistent: ready=true but one or more reducer input summary paths are missing"
  decision="NO-GO"
  status="fail"
  final_rc=1
else
  proceed_reducer="true"
fi

if [[ "$proceed_reducer" == "true" ]]; then
  reducer_stage_attempted="true"
  declare -a reducer_cmd=(
    bash "$REDUCER_SCRIPT"
    --reports-dir "$reports_dir"
    --fail-on-no-go "$reducer_fail_on_no_go"
    --min-support-rate-pct "$reducer_min_support_rate_pct"
    --summary-json "$reducer_summary_json"
    --report-md "$reducer_report_md"
    --show-json 0
    --print-summary-json 0
  )
  for sweep_input_summary in "${sweep_reducer_input_summary_jsons[@]}"; do
    reducer_cmd+=(--campaign-summary-json "$sweep_input_summary")
  done
  for reducer_input_summary in "${reducer_campaign_summary_jsons[@]}"; do
    reducer_cmd+=(--campaign-summary-json "$reducer_input_summary")
  done
  if [[ -n "$reducer_campaign_summary_list" ]]; then
    reducer_cmd+=(--campaign-summary-list "$reducer_campaign_summary_list")
  fi
  reducer_command_display="$(redact_text "$(quote_cmd "${reducer_cmd[@]}")")"

  echo "[profile-compare-multi-vm-cycle] $(timestamp_utc) reducer-stage start reducer_summary_json=$reducer_summary_json"
  pre_reducer_summary_fingerprint="$(file_fingerprint_01 "$reducer_summary_json")"
  set +e
  "${reducer_cmd[@]}" >"$reducer_log" 2>&1
  reducer_stage_rc=$?
  set -e
  reducer_stage_rc_json="$reducer_stage_rc"

  reducer_stage_status="pass"
  if [[ "$reducer_stage_rc" -ne 0 ]]; then
    reducer_stage_status="fail"
  fi

  if [[ -f "$reducer_summary_json" ]]; then
    reducer_summary_exists="true"
  fi
  if [[ "$(json_file_valid_01 "$reducer_summary_json")" == "1" ]]; then
    reducer_summary_valid="true"
    post_reducer_summary_fingerprint="$(file_fingerprint_01 "$reducer_summary_json")"
    if [[ -z "$pre_reducer_summary_fingerprint" && -n "$post_reducer_summary_fingerprint" ]]; then
      reducer_summary_fresh="true"
    elif [[ -n "$post_reducer_summary_fingerprint" && "$post_reducer_summary_fingerprint" != "$pre_reducer_summary_fingerprint" ]]; then
      reducer_summary_fresh="true"
    fi
    reducer_decision="$(jq -r '
      if (.decision.decision | type) == "string" then .decision.decision else "" end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "")"
    reducer_decision="$(normalize_decision "$reducer_decision")"
    reducer_status_value="$(jq -r '
      if (.status | type) == "string" then .status else "" end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "")"
    reducer_rc_json="$(jq -r '
      if (.rc | type) == "number" then .rc else "null" end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "null")"
    reducer_recommended_profile="$(jq -r '
      if (.decision.recommended_profile | type) == "string"
      then .decision.recommended_profile
      else ""
      end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "")"
    reducer_support_rate_pct_json="$(jq -r '
      (.decision.support_rate_pct // null) as $v
      | if $v == null then "null"
        elif ($v | type) == "number"
        then (if $v < 0 then 0 else $v end)
        elif ($v | type) == "string" and ($v | test("^-?[0-9]+([.][0-9]+)?$"))
        then (($v | tonumber) | if . < 0 then 0 else . end)
        else "null"
        end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "null")"
    reducer_trend_source="$(jq -r '
      if (.decision.trend_source | type) == "string"
      then .decision.trend_source
      else ""
      end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "")"
    reducer_errors_json="$(jq -c '
      if (.errors | type) == "array" then .errors else [] end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "[]")"
    reducer_promotion_gate_available="$(jq -r '
      if (.promotion_gate | type) == "object" then "true" else "false" end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "false")"
    reducer_promotion_gate_decision="$(jq -r '
      if (.promotion_gate.decision | type) == "string" then .promotion_gate.decision else "" end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "")"
    reducer_promotion_gate_decision="$(normalize_decision "$reducer_promotion_gate_decision")"
    reducer_promotion_gate_status="$(jq -r '
      if (.promotion_gate.status | type) == "string" then .promotion_gate.status else "" end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "")"
    reducer_promotion_gate_ready_json="$(jq -r '
      if (.promotion_gate.promotion_ready | type) == "boolean" then (.promotion_gate.promotion_ready | tostring) else "false" end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "false")"
    reducer_promotion_missing_evidence_json="$(jq -c '
      if (.promotion_gate.missing_evidence_reasons | type) == "array" then
        [
          .promotion_gate.missing_evidence_reasons[]?
          | if type == "object" then
              {
                id: (
                  if (.id | type) == "string" and (.id | length) > 0
                  then .id
                  else "reducer_policy_failure"
                  end
                ),
                message: (
                  if (.message | type) == "string"
                  then .message
                  else ""
                  end
                ),
                source: "reducer.promotion_gate"
              }
            elif type == "string" then
              {id: ., message: ., source: "reducer.promotion_gate"}
            else
              empty
            end
        ]
      else
        []
      end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "[]")"
  fi

  if [[ "$reducer_stage_rc" -eq 0 && "$reducer_summary_valid" != "true" ]]; then
    reducer_stage_status="fail"
  elif [[ "$reducer_stage_rc" -eq 0 && "$reducer_summary_fresh" != "true" ]]; then
    reducer_stage_status="fail"
  fi

  proceed_check="false"
  if [[ "$reducer_stage_rc" -ne 0 ]]; then
    failure_stage="reducer"
    failure_reason="$(jq -r '
      if (. | type) == "array" and (. | length) > 0 and (.[0] | type) == "string"
      then .[0]
      else ""
      end
    ' <<<"$reducer_errors_json" 2>/dev/null || printf '%s' "")"
    if [[ -z "$failure_reason" ]]; then
      failure_reason="multi-vm reducer failed (rc=$reducer_stage_rc)"
    fi
    decision="NO-GO"
    status="fail"
    final_rc="$reducer_stage_rc"
    if [[ "$final_rc" -eq 0 ]]; then
      final_rc=1
    fi
  elif [[ "$reducer_summary_valid" != "true" ]]; then
    failure_stage="reducer"
    failure_reason="multi-vm reducer summary is missing or invalid"
    decision="NO-GO"
    status="fail"
    final_rc=1
  elif [[ "$reducer_summary_fresh" != "true" ]]; then
    failure_stage="reducer"
    failure_reason="multi-vm reducer summary is stale (not refreshed by current run)"
    decision="NO-GO"
    status="fail"
    final_rc=1
  else
    projection_ok="true"
    projection_failure_reason=""

    runs_total_json="$(jq -r '
      if (.summary.vm_summaries_valid | type) == "number"
      then (.summary.vm_summaries_valid | floor)
      else ([.vm_summaries[]? | select(.valid == true)] | length)
      end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "0")"
    runs_total_json="$(non_negative_int_or_zero "$runs_total_json")"

    runs_pass_json="$(jq -r '
      if (.summary.status_counts.pass | type) == "number"
      then (.summary.status_counts.pass | floor)
      else ([.vm_summaries[]? | select(.valid == true and .status == "pass")] | length)
      end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "0")"
    runs_pass_json="$(non_negative_int_or_zero "$runs_pass_json")"

    runs_warn_json="$(jq -r '
      if (.summary.status_counts.warn | type) == "number"
      then (.summary.status_counts.warn | floor)
      else ([.vm_summaries[]? | select(.valid == true and .status == "warn")] | length)
      end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "0")"
    runs_warn_json="$(non_negative_int_or_zero "$runs_warn_json")"

    runs_fail_base_json="$(jq -r '
      if (.summary.status_counts.fail | type) == "number"
      then (.summary.status_counts.fail | floor)
      else ([.vm_summaries[]? | select(.valid == true and .status == "fail")] | length)
      end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "0")"
    runs_fail_base_json="$(non_negative_int_or_zero "$runs_fail_base_json")"

    vm_invalid_json="$(jq -r '
      if (.summary.vm_summaries_invalid | type) == "number"
      then (.summary.vm_summaries_invalid | floor)
      else ([.vm_summaries[]? | select(.valid != true)] | length)
      end
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "0")"
    vm_invalid_json="$(non_negative_int_or_zero "$vm_invalid_json")"

    runs_fail_json="$((runs_fail_base_json + vm_invalid_json))"
    runs_with_summary_json="$runs_total_json"
    support_rate_for_projection="$(non_negative_decimal_or_zero "$reducer_support_rate_pct_json")"

    selected_summaries_json="$(jq -c '
      [.vm_summaries[]? | .input_summary_json | select(type == "string" and length > 0)]
    ' "$reducer_summary_json" 2>/dev/null || printf '%s' "[]")"
    if ! jq -e 'type == "array"' <<<"$selected_summaries_json" >/dev/null 2>&1; then
      selected_summaries_json='[]'
    fi

    campaign_status_for_check="pass"
    campaign_rc_for_check=0
    trend_status_for_check="pass"
    trend_rc_for_check=0
    if [[ "$reducer_decision" != "GO" || "$reducer_status_value" == "fail" ]]; then
      campaign_status_for_check="fail"
      campaign_rc_for_check=1
      trend_status_for_check="fail"
      trend_rc_for_check=1
    fi

    if ! jq -n \
      --arg generated_at_utc "$(timestamp_utc)" \
      --arg trend_status "$trend_status_for_check" \
      --argjson trend_rc "$trend_rc_for_check" \
      --arg recommended_profile "$reducer_recommended_profile" \
      --arg trend_source "$reducer_trend_source" \
      --argjson support_rate_pct "$support_rate_for_projection" \
      --argjson reports_total "$runs_total_json" \
      --argjson pass_reports "$runs_pass_json" \
      --argjson warn_reports "$runs_warn_json" \
      --argjson fail_reports "$runs_fail_json" \
      '{
        version: 1,
        status: $trend_status,
        rc: $trend_rc,
        notes: "derived_from_multi_vm_reducer",
        generated_at_utc: $generated_at_utc,
        summary: {
          reports_total: $reports_total,
          pass_reports: $pass_reports,
          warn_reports: $warn_reports,
          fail_reports: $fail_reports
        },
        decision: {
          recommended_default_profile: (if $recommended_profile == "" then null else $recommended_profile end),
          source: (if $trend_source == "" then null else $trend_source end),
          rationale: "derived_from_multi_vm_reducer",
          recommendation_support_rate_pct: $support_rate_pct
        },
        profiles: []
      }' >"$check_trend_summary_json"; then
      projection_ok="false"
      projection_failure_reason="failed to write check trend summary projection"
    fi

    if [[ "$projection_ok" == "true" ]]; then
      if ! jq -n \
        --arg campaign_status "$campaign_status_for_check" \
        --argjson campaign_rc "$campaign_rc_for_check" \
        --arg recommended_profile "$reducer_recommended_profile" \
        --arg trend_source "$reducer_trend_source" \
        --arg trend_status "$trend_status_for_check" \
        --argjson trend_rc "$trend_rc_for_check" \
        --arg check_trend_summary_json "$check_trend_summary_json" \
        --argjson runs_total "$runs_total_json" \
        --argjson runs_pass "$runs_pass_json" \
        --argjson runs_warn "$runs_warn_json" \
        --argjson runs_fail "$runs_fail_json" \
        --argjson runs_with_summary "$runs_with_summary_json" \
        --argjson selected_summaries "$selected_summaries_json" \
        '{
          version: 1,
          status: $campaign_status,
          rc: $campaign_rc,
          notes: "derived_from_multi_vm_reducer",
          summary: {
            runs_total: $runs_total,
            runs_pass: $runs_pass,
            runs_warn: $runs_warn,
            runs_fail: $runs_fail,
            runs_with_summary: $runs_with_summary
          },
          decision: {
            recommended_default_profile: (if $recommended_profile == "" then null else $recommended_profile end),
            source: (if $trend_source == "" then null else $trend_source end),
            rationale: "derived_from_multi_vm_reducer"
          },
          trend: {
            status: $trend_status,
            rc: $trend_rc,
            notes: "derived_from_multi_vm_reducer",
            summary_json: $check_trend_summary_json
          },
          selected_summaries: $selected_summaries,
          runs: []
        }' >"$check_campaign_summary_json"; then
        projection_ok="false"
        projection_failure_reason="failed to write check campaign summary projection"
      fi
    fi

    if [[ "$projection_ok" != "true" ]]; then
      reducer_stage_status="fail"
      failure_stage="reducer"
      failure_reason="$projection_failure_reason"
      decision="NO-GO"
      status="fail"
      final_rc=1
    else
      proceed_check="true"
    fi

    if [[ "$proceed_check" == "true" ]]; then
      check_stage_attempted="true"
      declare -a check_cmd=(
        bash "$CHECK_SCRIPT"
        --campaign-summary-json "$check_campaign_summary_json"
        --trend-summary-json "$check_trend_summary_json"
        --reports-dir "$reports_dir"
        --require-status-pass "$require_status_pass"
        --require-trend-status-pass "$require_trend_status_pass"
        --require-min-runs-total "$require_min_runs_total"
        --require-max-runs-fail "$require_max_runs_fail"
        --require-max-runs-warn "$require_max_runs_warn"
        --require-min-runs-with-summary "$require_min_runs_with_summary"
        --require-recommendation-support-rate-pct "$require_recommendation_support_rate_pct"
        --disallow-experimental-default "$disallow_experimental_default"
        --require-selection-policy-present "$require_selection_policy_present"
        --require-selection-policy-valid "$require_selection_policy_valid"
        --fail-on-no-go "$fail_on_no_go"
        --summary-json "$check_summary_json"
        --show-json 0
        --print-summary-json 0
      )
      if [[ -n "$require_recommended_profile" ]]; then
        check_cmd+=(--require-recommended-profile "$require_recommended_profile")
      fi
      if [[ -n "$allow_recommended_profiles" ]]; then
        check_cmd+=(--allow-recommended-profiles "$allow_recommended_profiles")
      fi
      if [[ -n "$require_trend_source" ]]; then
        check_cmd+=(--require-trend-source "$require_trend_source")
      fi
      check_command_display="$(redact_text "$(quote_cmd "${check_cmd[@]}")")"

      echo "[profile-compare-multi-vm-cycle] $(timestamp_utc) check-stage start check_summary_json=$check_summary_json"
      pre_check_summary_fingerprint="$(file_fingerprint_01 "$check_summary_json")"
      set +e
      "${check_cmd[@]}" >"$check_log" 2>&1
      check_stage_rc=$?
      set -e
      check_stage_rc_json="$check_stage_rc"

      check_stage_status="pass"
      if [[ "$check_stage_rc" -ne 0 ]]; then
        check_stage_status="fail"
      fi

      if [[ -f "$check_summary_json" ]]; then
        check_summary_exists="true"
      fi
      if [[ "$(json_file_valid_01 "$check_summary_json")" == "1" ]]; then
        check_summary_valid="true"
        post_check_summary_fingerprint="$(file_fingerprint_01 "$check_summary_json")"
        if [[ -z "$pre_check_summary_fingerprint" && -n "$post_check_summary_fingerprint" ]]; then
          check_summary_fresh="true"
        elif [[ -n "$post_check_summary_fingerprint" && "$post_check_summary_fingerprint" != "$pre_check_summary_fingerprint" ]]; then
          check_summary_fresh="true"
        fi
        check_decision="$(jq -r '
          if (.decision | type) == "string" then .decision else "" end
        ' "$check_summary_json" 2>/dev/null || printf '%s' "")"
        check_decision="$(normalize_decision "$check_decision")"
        check_status_value="$(jq -r '
          if (.status | type) == "string" then .status else "" end
        ' "$check_summary_json" 2>/dev/null || printf '%s' "")"
        check_rc_json="$(jq -r '
          if (.rc | type) == "number" then .rc else "null" end
        ' "$check_summary_json" 2>/dev/null || printf '%s' "null")"
        check_recommended_profile="$(jq -r '
          if (.observed.recommended_profile | type) == "string"
          then .observed.recommended_profile
          else ""
          end
        ' "$check_summary_json" 2>/dev/null || printf '%s' "")"
        check_support_rate_pct_json="$(jq -r '
          (.observed.recommendation_support_rate_pct // null) as $v
          | if $v == null then "null"
            elif ($v | type) == "number"
            then (if $v < 0 then 0 else $v end)
            elif ($v | type) == "string" and ($v | test("^-?[0-9]+([.][0-9]+)?$"))
            then (($v | tonumber) | if . < 0 then 0 else . end)
            else "null"
            end
        ' "$check_summary_json" 2>/dev/null || printf '%s' "null")"
        check_trend_source_value="$(jq -r '
          if (.observed.trend_source | type) == "string"
          then .observed.trend_source
          else ""
          end
        ' "$check_summary_json" 2>/dev/null || printf '%s' "")"
        check_errors_json="$(jq -c '
          if (.errors | type) == "array" then .errors else [] end
        ' "$check_summary_json" 2>/dev/null || printf '%s' "[]")"
        check_promotion_missing_evidence_json="$(jq -c '
          (.decision_diagnostics.m4_policy.unmet_requirements // []) as $unmet
          | (
              [ $unmet[]? | select(type == "string" and length > 0) | {id: ., message: ., source: "check.m4_policy"} ]
            ) as $unmet_rows
          | if ($unmet_rows | length) > 0 then
              $unmet_rows
            else
              [ (.errors // [])[]? | select(type == "string" and length > 0) | {id: "check_policy_error", message: ., source: "check.errors"} ]
            end
        ' "$check_summary_json" 2>/dev/null || printf '%s' "[]")"
      fi

      if [[ "$check_stage_rc" -eq 0 ]]; then
        if [[ "$check_summary_valid" != "true" ]]; then
          check_stage_status="fail"
        elif [[ "$check_summary_fresh" != "true" ]]; then
          check_stage_status="fail"
        elif [[ "$check_status_value" == "fail" || "$check_decision" == "NO-GO" ]]; then
          check_stage_status="fail"
        elif [[ "$check_status_value" == "ok" || "$check_decision" == "GO" ]]; then
          check_stage_status="pass"
        fi
      fi

      if [[ -n "$check_decision" ]]; then
        decision="$check_decision"
      fi

      if [[ "$check_stage_rc" -ne 0 ]]; then
        if [[ -z "$decision" ]]; then
          decision="NO-GO"
        fi
        status="fail"
        final_rc="$check_stage_rc"
        if [[ "$final_rc" -eq 0 ]]; then
          final_rc=1
        fi
        failure_stage="check"
        failure_reason="$(jq -r '
          if (. | type) == "array" and (. | length) > 0 and (.[0] | type) == "string"
          then .[0]
          else ""
          end
        ' <<<"$check_errors_json" 2>/dev/null || printf '%s' "")"
        if [[ -z "$failure_reason" ]]; then
          failure_reason="campaign check failed (rc=$check_stage_rc)"
        fi
      elif [[ "$check_summary_valid" != "true" ]]; then
        decision="NO-GO"
        status="fail"
        final_rc=1
        failure_stage="check"
        failure_reason="campaign check summary is missing or invalid"
      elif [[ "$check_summary_fresh" != "true" ]]; then
        decision="NO-GO"
        status="fail"
        final_rc=1
        failure_stage="check"
        failure_reason="campaign check summary is stale (not refreshed by current run)"
      elif [[ "$check_decision" == "GO" ]]; then
        decision="GO"
        status="pass"
        final_rc=0
      elif [[ "$check_decision" == "NO-GO" ]]; then
        decision="NO-GO"
        if [[ "$fail_on_no_go" == "1" ]]; then
          status="fail"
          final_rc=1
          failure_stage="check"
          failure_reason="$(jq -r '
            if (. | type) == "array" and (. | length) > 0 and (.[0] | type) == "string"
            then .[0]
            else ""
            end
          ' <<<"$check_errors_json" 2>/dev/null || printf '%s' "")"
          if [[ -z "$failure_reason" ]]; then
            failure_reason="campaign check decision is NO-GO"
          fi
        else
          status="warn"
          final_rc=0
        fi
      else
        decision="NO-GO"
        status="fail"
        final_rc=1
        failure_stage="check"
        failure_reason="campaign check summary is missing a usable decision"
      fi
    fi
  fi
fi

reducer_promotion_gate_decision_effective="$reducer_promotion_gate_decision"
if [[ -z "$reducer_promotion_gate_decision_effective" ]]; then
  reducer_promotion_gate_decision_effective="$reducer_decision"
fi

reducer_promotion_gate_status_effective="$reducer_promotion_gate_status"
if [[ -z "$reducer_promotion_gate_status_effective" ]]; then
  if [[ "$reducer_stage_attempted" != "true" ]]; then
    reducer_promotion_gate_status_effective="skip"
  elif [[ "$reducer_promotion_gate_decision_effective" == "GO" && "$reducer_status_value" != "fail" ]]; then
    reducer_promotion_gate_status_effective="pass"
  else
    reducer_promotion_gate_status_effective="fail"
  fi
fi

if [[ "$reducer_promotion_gate_available" != "true" ]]; then
  if [[ "$reducer_promotion_gate_status_effective" == "pass" ]]; then
    reducer_promotion_gate_ready_json="true"
  else
    reducer_promotion_gate_ready_json="false"
  fi
fi

if [[ "$(jq -r 'length' <<<"$reducer_promotion_missing_evidence_json" 2>/dev/null || printf '0')" == "0" && "$reducer_stage_attempted" == "true" && "$reducer_promotion_gate_status_effective" == "fail" ]]; then
  reducer_primary_reason="$(jq -r '
    if (. | type) == "array" and (. | length) > 0 and (.[0] | type) == "string"
    then .[0]
    else "multi-vm reducer promotion gate not pass"
    end
  ' <<<"$reducer_errors_json" 2>/dev/null || printf '%s' "multi-vm reducer promotion gate not pass")"
  reducer_promotion_missing_evidence_json="$(jq -nc --arg reason "$reducer_primary_reason" '
    [{id: "reducer_gate_not_pass", message: $reason, source: "reducer"}]
  ')"
fi

check_promotion_gate_decision="$check_decision"
check_promotion_gate_status="skip"
check_promotion_gate_ready_json="false"
if [[ "$check_stage_attempted" == "true" ]]; then
  if [[ "$check_promotion_gate_decision" == "GO" && "$check_status_value" == "ok" ]]; then
    check_promotion_gate_status="pass"
    check_promotion_gate_ready_json="true"
  else
    check_promotion_gate_status="fail"
  fi
fi

if [[ "$(jq -r 'length' <<<"$check_promotion_missing_evidence_json" 2>/dev/null || printf '0')" == "0" && "$check_stage_attempted" == "true" && "$check_promotion_gate_status" == "fail" ]]; then
  check_primary_reason="$(jq -r '
    if (. | type) == "array" and (. | length) > 0 and (.[0] | type) == "string"
    then .[0]
    else "campaign check promotion gate not pass"
    end
  ' <<<"$check_errors_json" 2>/dev/null || printf '%s' "campaign check promotion gate not pass")"
  check_promotion_missing_evidence_json="$(jq -nc --arg reason "$check_primary_reason" '
    [{id: "campaign_check_gate_not_pass", message: $reason, source: "check"}]
  ')"
fi

promotion_gate_missing_evidence_json="$(jq -nc \
  --argjson reducer_reasons "$reducer_promotion_missing_evidence_json" \
  --argjson check_reasons "$check_promotion_missing_evidence_json" \
  --arg decision "$decision" \
  --arg failure_stage "$failure_stage" \
  --arg failure_reason "$failure_reason" '
  ($reducer_reasons + $check_reasons) as $base
  | (
      $base
      + (
          if (($base | length) == 0 and $decision == "NO-GO") then
            [
              {
                id: (if $failure_stage == "" then "cycle_no_go" else ($failure_stage + "_stage_failure") end),
                message: (if $failure_reason == "" then "promotion gate failed" else $failure_reason end),
                source: "cycle"
              }
            ]
          else
            []
          end
        )
    )
  | map({
      id: (if (.id // "") == "" then "unspecified" else .id end),
      message: (.message // ""),
      source: (if (.source // "") == "" then "cycle" else .source end)
    })
  | unique_by(.id + "|" + .source + "|" + .message)
')"
promotion_gate_missing_evidence_reason_ids_json="$(jq -c '[.[] | .id]' <<<"$promotion_gate_missing_evidence_json")"

promotion_gate_decision="NO-GO"
promotion_gate_status="fail"
promotion_gate_ready_json="false"
if [[ "$decision" == "GO" ]] && [[ "$(jq -r 'length' <<<"$promotion_gate_missing_evidence_json" 2>/dev/null || printf '0')" == "0" ]]; then
  promotion_gate_decision="GO"
  promotion_gate_status="pass"
  promotion_gate_ready_json="true"
fi

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --arg decision "$decision" \
  --arg promotion_gate_decision "$promotion_gate_decision" \
  --arg promotion_gate_status "$promotion_gate_status" \
  --arg failure_stage "$failure_stage" \
  --arg failure_reason "$failure_reason" \
  --arg reports_dir "$reports_dir" \
  --arg sweep_summary_json "$sweep_summary_json" \
  --arg sweep_canonical_summary_json "$sweep_canonical_summary_json" \
  --arg sweep_report_md "$sweep_report_md" \
  --arg reducer_summary_json "$reducer_summary_json" \
  --arg reducer_report_md "$reducer_report_md" \
  --arg check_campaign_summary_json "$check_campaign_summary_json" \
  --arg check_trend_summary_json "$check_trend_summary_json" \
  --arg check_summary_json "$check_summary_json" \
  --arg summary_json_path "$summary_json" \
  --arg sweep_log "$sweep_log" \
  --arg reducer_log "$reducer_log" \
  --arg check_log "$check_log" \
  --arg sweep_command "$sweep_command_display" \
  --arg reducer_command "$reducer_command_display" \
  --arg check_command "$check_command_display" \
  --arg sweep_stage_status "$sweep_stage_status" \
  --arg reducer_stage_attempted "$reducer_stage_attempted" \
  --arg reducer_stage_status "$reducer_stage_status" \
  --arg check_stage_attempted "$check_stage_attempted" \
  --arg check_stage_status "$check_stage_status" \
  --arg sweep_summary_exists "$sweep_summary_exists" \
  --arg sweep_summary_valid "$sweep_summary_valid" \
  --arg sweep_summary_fresh "$sweep_summary_fresh" \
  --arg sweep_reducer_handoff_ready "$sweep_reducer_handoff_ready" \
  --arg sweep_reducer_handoff_not_ready_reason "$sweep_reducer_handoff_not_ready_reason" \
  --arg reducer_summary_exists "$reducer_summary_exists" \
  --arg reducer_summary_valid "$reducer_summary_valid" \
  --arg reducer_summary_fresh "$reducer_summary_fresh" \
  --arg reducer_decision "$reducer_decision" \
  --arg reducer_status_value "$reducer_status_value" \
  --arg reducer_recommended_profile "$reducer_recommended_profile" \
  --arg reducer_trend_source "$reducer_trend_source" \
  --arg reducer_promotion_gate_available "$reducer_promotion_gate_available" \
  --arg reducer_promotion_gate_decision "$reducer_promotion_gate_decision_effective" \
  --arg reducer_promotion_gate_status "$reducer_promotion_gate_status_effective" \
  --arg reducer_promotion_gate_ready "$reducer_promotion_gate_ready_json" \
  --arg check_summary_exists "$check_summary_exists" \
  --arg check_summary_valid "$check_summary_valid" \
  --arg check_summary_fresh "$check_summary_fresh" \
  --arg check_decision "$check_decision" \
  --arg check_status_value "$check_status_value" \
  --arg check_recommended_profile "$check_recommended_profile" \
  --arg check_trend_source_value "$check_trend_source_value" \
  --arg check_promotion_gate_status "$check_promotion_gate_status" \
  --arg check_promotion_gate_decision "$check_promotion_gate_decision" \
  --arg check_promotion_gate_ready "$check_promotion_gate_ready_json" \
  --argjson rc "$final_rc" \
  --argjson promotion_gate_ready "$promotion_gate_ready_json" \
  --argjson sweep_stage_rc "$sweep_stage_rc" \
  --argjson reducer_stage_rc "$reducer_stage_rc_json" \
  --argjson check_stage_rc "$check_stage_rc_json" \
  --argjson sweep_reducer_input_vm_count "$sweep_reducer_input_vm_count_json" \
  --argjson sweep_reducer_input_summary_jsons "$sweep_reducer_input_summary_jsons_json" \
  --argjson reducer_rc "$reducer_rc_json" \
  --argjson reducer_support_rate_pct "$reducer_support_rate_pct_json" \
  --argjson reducer_errors "$reducer_errors_json" \
  --argjson reducer_promotion_missing_evidence "$reducer_promotion_missing_evidence_json" \
  --argjson check_rc "$check_rc_json" \
  --argjson check_support_rate_pct "$check_support_rate_pct_json" \
  --argjson check_errors "$check_errors_json" \
  --argjson check_promotion_missing_evidence "$check_promotion_missing_evidence_json" \
  --argjson promotion_gate_missing_evidence_reasons "$promotion_gate_missing_evidence_json" \
  --argjson promotion_gate_missing_evidence_reason_ids "$promotion_gate_missing_evidence_reason_ids_json" \
  --argjson vm_command_count "$vm_command_count_json" \
  --argjson vm_command_file_count "$vm_command_file_count_json" \
  --argjson sweep_command_timeout_sec "$sweep_command_timeout_sec" \
  --argjson sweep_allow_partial "$sweep_allow_partial" \
  --argjson sweep_fail_fast "$sweep_fail_fast" \
  --argjson sweep_reducer_min_successful_vms "$sweep_reducer_min_successful_vms" \
  --argjson sweep_reducer_require_all_success "$sweep_reducer_require_all_success" \
  --argjson sweep_allow_unready_handoff "$sweep_allow_unready_handoff" \
  --argjson reducer_fail_on_no_go "$reducer_fail_on_no_go" \
  --argjson reducer_min_support_rate_pct "$reducer_min_support_rate_pct" \
  --arg reducer_campaign_summary_list "$reducer_campaign_summary_list" \
  --argjson reducer_campaign_summary_json_count "$reducer_campaign_summary_json_count_json" \
  --argjson require_status_pass "$require_status_pass" \
  --argjson require_trend_status_pass "$require_trend_status_pass" \
  --argjson require_min_runs_total "$require_min_runs_total" \
  --argjson require_max_runs_fail "$require_max_runs_fail" \
  --argjson require_max_runs_warn "$require_max_runs_warn" \
  --argjson require_min_runs_with_summary "$require_min_runs_with_summary" \
  --argjson require_recommendation_support_rate_pct "$require_recommendation_support_rate_pct" \
  --arg require_recommended_profile "$require_recommended_profile" \
  --arg allow_recommended_profiles "$allow_recommended_profiles" \
  --argjson disallow_experimental_default "$disallow_experimental_default" \
  --arg require_trend_source "$require_trend_source" \
  --argjson require_selection_policy_present "$require_selection_policy_present" \
  --argjson require_selection_policy_valid "$require_selection_policy_valid" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  '{
    version: 1,
    schema: {
      id: "profile_compare_multi_vm_cycle_summary"
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    decision: (if $decision == "" then null else $decision end),
    promotion_gate: {
      decision: $promotion_gate_decision,
      status: $promotion_gate_status,
      promotion_ready: $promotion_gate_ready,
      missing_evidence_reasons: $promotion_gate_missing_evidence_reasons,
      missing_evidence_reason_ids: $promotion_gate_missing_evidence_reason_ids,
      reducer: {
        available: ($reducer_promotion_gate_available == "true"),
        decision: (if $reducer_promotion_gate_decision == "" then null else $reducer_promotion_gate_decision end),
        status: (if $reducer_promotion_gate_status == "" then null else $reducer_promotion_gate_status end),
        promotion_ready: ($reducer_promotion_gate_ready == "true"),
        missing_evidence_reasons: $reducer_promotion_missing_evidence
      },
      check: {
        attempted: ($check_stage_attempted == "true"),
        decision: (if $check_promotion_gate_decision == "" then null else $check_promotion_gate_decision end),
        status: (if $check_promotion_gate_status == "" then null else $check_promotion_gate_status end),
        promotion_ready: ($check_promotion_gate_ready == "true"),
        missing_evidence_reasons: $check_promotion_missing_evidence
      }
    },
    failure_stage: (if $failure_stage == "" then null else $failure_stage end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    inputs: {
      reports_dir: $reports_dir,
      sweep: {
        vm_command_count: $vm_command_count,
        vm_command_file_count: $vm_command_file_count,
        command_timeout_sec: $sweep_command_timeout_sec,
        allow_partial: ($sweep_allow_partial == 1),
        fail_fast: ($sweep_fail_fast == 1),
        reducer_min_successful_vms: $sweep_reducer_min_successful_vms,
        reducer_require_all_success: ($sweep_reducer_require_all_success == 1),
        allow_unready_handoff: ($sweep_allow_unready_handoff == 1)
      },
      reducer: {
        fail_on_no_go: ($reducer_fail_on_no_go == 1),
        min_support_rate_pct: $reducer_min_support_rate_pct,
        campaign_summary_json_count: $reducer_campaign_summary_json_count,
        campaign_summary_list: (
          if $reducer_campaign_summary_list == ""
          then null
          else $reducer_campaign_summary_list
          end
        )
      },
      check: {
        policy: {
          require_status_pass: ($require_status_pass == 1),
          require_trend_status_pass: ($require_trend_status_pass == 1),
          require_min_runs_total: $require_min_runs_total,
          require_max_runs_fail: $require_max_runs_fail,
          require_max_runs_warn: $require_max_runs_warn,
          require_min_runs_with_summary: $require_min_runs_with_summary,
          require_recommendation_support_rate_pct: $require_recommendation_support_rate_pct,
          require_recommended_profile: (
            if $require_recommended_profile == "" then null
            else $require_recommended_profile
            end
          ),
          allow_recommended_profiles: (
            if $allow_recommended_profiles == "" then null
            else $allow_recommended_profiles
            end
          ),
          disallow_experimental_default: ($disallow_experimental_default == 1),
          require_trend_source: (
            if $require_trend_source == "" then null
            else $require_trend_source
            end
          ),
          require_selection_policy_present: ($require_selection_policy_present == 1),
          require_selection_policy_valid: ($require_selection_policy_valid == 1),
          fail_on_no_go: ($fail_on_no_go == 1)
        }
      }
    },
    stages: {
      sweep: {
        attempted: true,
        status: $sweep_stage_status,
        rc: $sweep_stage_rc,
        command: $sweep_command,
        log: $sweep_log,
        summary_json: $sweep_summary_json,
        canonical_summary_json: $sweep_canonical_summary_json,
        report_md: $sweep_report_md
      },
      reducer: {
        attempted: ($reducer_stage_attempted == "true"),
        status: $reducer_stage_status,
        rc: $reducer_stage_rc,
        command: (if $reducer_command == "" then null else $reducer_command end),
        log: $reducer_log,
        summary_json: $reducer_summary_json,
        report_md: $reducer_report_md
      },
      check: {
        attempted: ($check_stage_attempted == "true"),
        status: $check_stage_status,
        rc: $check_stage_rc,
        command: (if $check_command == "" then null else $check_command end),
        log: $check_log,
        campaign_summary_json: $check_campaign_summary_json,
        trend_summary_json: $check_trend_summary_json,
        summary_json: $check_summary_json
      }
    },
    sweep: {
      summary_exists: ($sweep_summary_exists == "true"),
      summary_valid_json: ($sweep_summary_valid == "true"),
      summary_fresh: ($sweep_summary_fresh == "true"),
      reducer_handoff_ready: ($sweep_reducer_handoff_ready == "true"),
      reducer_handoff_not_ready_reason: (
        if $sweep_reducer_handoff_not_ready_reason == "" then null
        else $sweep_reducer_handoff_not_ready_reason
        end
      ),
      reducer_input_vm_count: $sweep_reducer_input_vm_count,
      reducer_input_summary_jsons: $sweep_reducer_input_summary_jsons
    },
    reducer: {
      summary_exists: ($reducer_summary_exists == "true"),
      summary_valid_json: ($reducer_summary_valid == "true"),
      summary_fresh: ($reducer_summary_fresh == "true"),
      decision: (if $reducer_decision == "" then null else $reducer_decision end),
      status: (if $reducer_status_value == "" then null else $reducer_status_value end),
      rc: $reducer_rc,
      recommended_profile: (
        if $reducer_recommended_profile == "" then null
        else $reducer_recommended_profile
        end
      ),
      support_rate_pct: $reducer_support_rate_pct,
      trend_source: (
        if $reducer_trend_source == "" then null
        else $reducer_trend_source
        end
      ),
      errors: $reducer_errors
    },
    check: {
      summary_exists: ($check_summary_exists == "true"),
      summary_valid_json: ($check_summary_valid == "true"),
      summary_fresh: ($check_summary_fresh == "true"),
      decision: (if $check_decision == "" then null else $check_decision end),
      status: (if $check_status_value == "" then null else $check_status_value end),
      rc: $check_rc,
      recommended_profile: (
        if $check_recommended_profile == "" then null
        else $check_recommended_profile
        end
      ),
      recommendation_support_rate_pct: $check_support_rate_pct,
      trend_source: (
        if $check_trend_source_value == "" then null
        else $check_trend_source_value
        end
      ),
      errors: $check_errors
    },
    artifacts: {
      summary_json: $summary_json_path,
      sweep_summary_json: $sweep_summary_json,
      sweep_canonical_summary_json: $sweep_canonical_summary_json,
      sweep_report_md: $sweep_report_md,
      reducer_summary_json: $reducer_summary_json,
      reducer_report_md: $reducer_report_md,
      check_campaign_summary_json: $check_campaign_summary_json,
      check_trend_summary_json: $check_trend_summary_json,
      check_summary_json: $check_summary_json,
      sweep_log: $sweep_log,
      reducer_log: $reducer_log,
      check_log: $check_log
    }
  }' >"$summary_json"

echo "[profile-compare-multi-vm-cycle] status=$status rc=$final_rc decision=${decision:-unset} summary_json=$summary_json"
if [[ -n "$failure_stage" ]]; then
  echo "[profile-compare-multi-vm-cycle] failure_stage=$failure_stage failure_reason=${failure_reason:-}"
fi
if [[ "$show_json" == "1" ]]; then
  echo "[profile-compare-multi-vm-cycle] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
