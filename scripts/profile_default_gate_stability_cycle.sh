#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_SCRIPT="${PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_stability_run.sh}"
CHECK_SCRIPT="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_stability_check.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_default_gate_stability_cycle.sh \
    --host-a HOST \
    --host-b HOST \
    [--campaign-subject ID | --subject ID] \
    [--runs N] \
    [--campaign-timeout-sec N] \
    [--sleep-between-sec N] \
    [--allow-partial [0|1]] \
    [--reports-dir DIR] \
    [--run-summary-json PATH | --stability-summary-json PATH] \
    [--check-summary-json PATH | --stability-check-summary-json PATH] \
    [--require-status-pass [0|1]] \
    [--require-stability-ok [0|1]] \
    [--require-selection-policy-present-all [0|1]] \
    [--require-consistent-selection-policy [0|1]] \
    [--require-decision-consensus [0|1]] \
    [--require-min-runs-requested N] \
    [--require-min-runs-completed N] \
    [--require-max-runs-fail N] \
    [--require-modal-decision GO|NO-GO] \
    [--require-modal-decision-support-rate-pct N] \
    [--require-recommended-profile PROFILE] \
    [--allow-recommended-profiles CSV] \
    [--require-modal-support-rate-pct N] \
    [--fail-on-no-go [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Run profile-default-gate stability evidence collection and policy check in
  one command, then emit a single cycle summary artifact.

Notes:
  - Stage scripts can be overridden with:
    PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT
    PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT
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

require_value_or_die() {
  local flag="$1"
  local argc="$2"
  if (( argc < 2 )); then
    echo "$flag requires a value"
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

normalize_decision() {
  local decision
  decision="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
  case "$decision" in
    GO) printf '%s\n' "GO" ;;
    NO-GO|NOGO|NO_GO) printf '%s\n' "NO-GO" ;;
    *) printf '%s\n' "$decision" ;;
  esac
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

quote_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

json_file_valid_01() {
  local path="$1"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e 'type == "object"' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
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

need_cmd jq
need_cmd date
need_cmd bash
need_cmd mkdir
need_cmd cksum

host_a="${PROFILE_DEFAULT_GATE_STABILITY_HOST_A:-}"
host_b="${PROFILE_DEFAULT_GATE_STABILITY_HOST_B:-}"
campaign_subject="${PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT:-}"
campaign_subject_from_campaign=""
campaign_subject_from_alias=""
runs="${PROFILE_DEFAULT_GATE_STABILITY_RUNS:-3}"
campaign_timeout_sec="${PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_TIMEOUT_SEC:-2400}"
sleep_between_sec="${PROFILE_DEFAULT_GATE_STABILITY_SLEEP_BETWEEN_SEC:-5}"
allow_partial="${PROFILE_DEFAULT_GATE_STABILITY_ALLOW_PARTIAL:-0}"
reports_dir="${PROFILE_DEFAULT_GATE_STABILITY_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"

run_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_RUN_SUMMARY_JSON:-}"
check_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_SUMMARY_JSON:-}"
summary_json="${PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SUMMARY_JSON:-}"

require_status_pass="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_STATUS_PASS:-${REQUIRE_STATUS_PASS:-1}}"
require_stability_ok="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_STABILITY_OK:-${REQUIRE_STABILITY_OK:-1}}"
require_selection_policy_present_all="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_SELECTION_POLICY_PRESENT_ALL:-${REQUIRE_SELECTION_POLICY_PRESENT_ALL:-1}}"
require_consistent_selection_policy="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_CONSISTENT_SELECTION_POLICY:-${REQUIRE_CONSISTENT_SELECTION_POLICY:-1}}"
require_decision_consensus="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_DECISION_CONSENSUS:-${REQUIRE_DECISION_CONSENSUS:-0}}"
require_min_runs_requested="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_MIN_RUNS_REQUESTED:-${REQUIRE_MIN_RUNS_REQUESTED:-3}}"
require_min_runs_completed="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_MIN_RUNS_COMPLETED:-${REQUIRE_MIN_RUNS_COMPLETED:-3}}"
require_max_runs_fail="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_MAX_RUNS_FAIL:-${REQUIRE_MAX_RUNS_FAIL:-0}}"
require_modal_decision="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_MODAL_DECISION:-${REQUIRE_MODAL_DECISION:-GO}}"
require_modal_decision_support_rate_pct="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_MODAL_DECISION_SUPPORT_RATE_PCT:-${REQUIRE_MODAL_DECISION_SUPPORT_RATE_PCT:-0}}"
require_recommended_profile="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_RECOMMENDED_PROFILE:-${REQUIRE_RECOMMENDED_PROFILE:-}}"
allow_recommended_profiles="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_ALLOW_RECOMMENDED_PROFILES:-${ALLOW_RECOMMENDED_PROFILES:-balanced,speed,private}}"
require_modal_support_rate_pct="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_MODAL_SUPPORT_RATE_PCT:-${REQUIRE_MODAL_SUPPORT_RATE_PCT:-60}}"
fail_on_no_go="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_FAIL_ON_NO_GO:-${FAIL_ON_NO_GO:-1}}"

show_json="${PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SHOW_JSON:-0}"
print_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_CYCLE_PRINT_SUMMARY_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host-a)
      require_value_or_die "$1" "$#"
      host_a="${2:-}"
      shift 2
      ;;
    --host-a=*)
      host_a="${1#*=}"
      shift
      ;;
    --host-b)
      require_value_or_die "$1" "$#"
      host_b="${2:-}"
      shift 2
      ;;
    --host-b=*)
      host_b="${1#*=}"
      shift
      ;;
    --campaign-subject)
      require_value_or_die "$1" "$#"
      campaign_subject="${2:-}"
      campaign_subject_from_campaign="${2:-}"
      shift 2
      ;;
    --campaign-subject=*)
      campaign_subject="${1#*=}"
      campaign_subject_from_campaign="${1#*=}"
      shift
      ;;
    --subject)
      require_value_or_die "$1" "$#"
      campaign_subject="${2:-}"
      campaign_subject_from_alias="${2:-}"
      shift 2
      ;;
    --subject=*)
      campaign_subject="${1#*=}"
      campaign_subject_from_alias="${1#*=}"
      shift
      ;;
    --runs)
      require_value_or_die "$1" "$#"
      runs="${2:-}"
      shift 2
      ;;
    --runs=*)
      runs="${1#*=}"
      shift
      ;;
    --campaign-timeout-sec)
      require_value_or_die "$1" "$#"
      campaign_timeout_sec="${2:-}"
      shift 2
      ;;
    --campaign-timeout-sec=*)
      campaign_timeout_sec="${1#*=}"
      shift
      ;;
    --sleep-between-sec)
      require_value_or_die "$1" "$#"
      sleep_between_sec="${2:-}"
      shift 2
      ;;
    --sleep-between-sec=*)
      sleep_between_sec="${1#*=}"
      shift
      ;;
    --allow-partial)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_partial="${2:-}"
        shift 2
      else
        allow_partial="1"
        shift
      fi
      ;;
    --allow-partial=*)
      allow_partial="${1#*=}"
      shift
      ;;
    --reports-dir)
      require_value_or_die "$1" "$#"
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --run-summary-json)
      require_value_or_die "$1" "$#"
      run_summary_json="${2:-}"
      shift 2
      ;;
    --run-summary-json=*)
      run_summary_json="${1#*=}"
      shift
      ;;
    --stability-summary-json)
      require_value_or_die "$1" "$#"
      run_summary_json="${2:-}"
      shift 2
      ;;
    --stability-summary-json=*)
      run_summary_json="${1#*=}"
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
    --stability-check-summary-json)
      require_value_or_die "$1" "$#"
      check_summary_json="${2:-}"
      shift 2
      ;;
    --stability-check-summary-json=*)
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
    --require-stability-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_stability_ok="${2:-}"
        shift 2
      else
        require_stability_ok="1"
        shift
      fi
      ;;
    --require-stability-ok=*)
      require_stability_ok="${1#*=}"
      shift
      ;;
    --require-selection-policy-present-all)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_selection_policy_present_all="${2:-}"
        shift 2
      else
        require_selection_policy_present_all="1"
        shift
      fi
      ;;
    --require-selection-policy-present-all=*)
      require_selection_policy_present_all="${1#*=}"
      shift
      ;;
    --require-consistent-selection-policy)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_consistent_selection_policy="${2:-}"
        shift 2
      else
        require_consistent_selection_policy="1"
        shift
      fi
      ;;
    --require-consistent-selection-policy=*)
      require_consistent_selection_policy="${1#*=}"
      shift
      ;;
    --require-decision-consensus)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_decision_consensus="${2:-}"
        shift 2
      else
        require_decision_consensus="1"
        shift
      fi
      ;;
    --require-decision-consensus=*)
      require_decision_consensus="${1#*=}"
      shift
      ;;
    --require-min-runs-requested)
      require_value_or_die "$1" "$#"
      require_min_runs_requested="${2:-}"
      shift 2
      ;;
    --require-min-runs-requested=*)
      require_min_runs_requested="${1#*=}"
      shift
      ;;
    --require-min-runs-completed)
      require_value_or_die "$1" "$#"
      require_min_runs_completed="${2:-}"
      shift 2
      ;;
    --require-min-runs-completed=*)
      require_min_runs_completed="${1#*=}"
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
    --require-modal-decision)
      require_value_or_die "$1" "$#"
      require_modal_decision="${2:-}"
      shift 2
      ;;
    --require-modal-decision=*)
      require_modal_decision="${1#*=}"
      shift
      ;;
    --require-modal-decision-support-rate-pct)
      require_value_or_die "$1" "$#"
      require_modal_decision_support_rate_pct="${2:-}"
      shift 2
      ;;
    --require-modal-decision-support-rate-pct=*)
      require_modal_decision_support_rate_pct="${1#*=}"
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
    --require-modal-support-rate-pct)
      require_value_or_die "$1" "$#"
      require_modal_support_rate_pct="${2:-}"
      shift 2
      ;;
    --require-modal-support-rate-pct=*)
      require_modal_support_rate_pct="${1#*=}"
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

host_a="$(trim "$host_a")"
host_b="$(trim "$host_b")"
campaign_subject="$(trim "$campaign_subject")"
campaign_subject_from_campaign="$(trim "$campaign_subject_from_campaign")"
campaign_subject_from_alias="$(trim "$campaign_subject_from_alias")"
runs="$(trim "$runs")"
campaign_timeout_sec="$(trim "$campaign_timeout_sec")"
sleep_between_sec="$(trim "$sleep_between_sec")"
allow_partial="$(trim "$allow_partial")"
reports_dir="$(abs_path "$reports_dir")"
run_summary_json="$(abs_path "$run_summary_json")"
check_summary_json="$(abs_path "$check_summary_json")"
summary_json="$(abs_path "$summary_json")"
require_status_pass="$(trim "$require_status_pass")"
require_stability_ok="$(trim "$require_stability_ok")"
require_selection_policy_present_all="$(trim "$require_selection_policy_present_all")"
require_consistent_selection_policy="$(trim "$require_consistent_selection_policy")"
require_decision_consensus="$(trim "$require_decision_consensus")"
require_min_runs_requested="$(trim "$require_min_runs_requested")"
require_min_runs_completed="$(trim "$require_min_runs_completed")"
require_max_runs_fail="$(trim "$require_max_runs_fail")"
require_modal_decision="$(trim "$require_modal_decision")"
require_modal_decision_support_rate_pct="$(trim "$require_modal_decision_support_rate_pct")"
require_recommended_profile="$(trim "$require_recommended_profile")"
allow_recommended_profiles="$(trim "$allow_recommended_profiles")"
require_modal_support_rate_pct="$(trim "$require_modal_support_rate_pct")"
fail_on_no_go="$(trim "$fail_on_no_go")"
show_json="$(trim "$show_json")"
print_summary_json="$(trim "$print_summary_json")"
RUN_SCRIPT="$(abs_path "$RUN_SCRIPT")"
CHECK_SCRIPT="$(abs_path "$CHECK_SCRIPT")"

if [[ -z "$host_a" ]]; then
  echo "--host-a is required"
  exit 2
fi
if [[ -z "$host_b" ]]; then
  echo "--host-b is required"
  exit 2
fi
if [[ -z "$campaign_subject" ]]; then
  echo "--campaign-subject or --subject is required"
  exit 2
fi
if [[ -n "$campaign_subject_from_campaign" && -n "$campaign_subject_from_alias" && "$campaign_subject_from_campaign" != "$campaign_subject_from_alias" ]]; then
  echo "conflicting subject values: --campaign-subject and --subject must match when both are provided"
  exit 2
fi
if [[ ! -f "$RUN_SCRIPT" ]]; then
  echo "stability run script not found: $RUN_SCRIPT"
  exit 2
fi
if [[ ! -f "$CHECK_SCRIPT" ]]; then
  echo "stability check script not found: $CHECK_SCRIPT"
  exit 2
fi

int_arg_or_die "--runs" "$runs"
int_arg_or_die "--campaign-timeout-sec" "$campaign_timeout_sec"
int_arg_or_die "--sleep-between-sec" "$sleep_between_sec"
int_arg_or_die "--require-min-runs-requested" "$require_min_runs_requested"
int_arg_or_die "--require-min-runs-completed" "$require_min_runs_completed"
int_arg_or_die "--require-max-runs-fail" "$require_max_runs_fail"
bool_arg_or_die "--allow-partial" "$allow_partial"
bool_arg_or_die "--require-status-pass" "$require_status_pass"
bool_arg_or_die "--require-stability-ok" "$require_stability_ok"
bool_arg_or_die "--require-selection-policy-present-all" "$require_selection_policy_present_all"
bool_arg_or_die "--require-consistent-selection-policy" "$require_consistent_selection_policy"
bool_arg_or_die "--require-decision-consensus" "$require_decision_consensus"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

if ! is_non_negative_decimal "$require_modal_support_rate_pct"; then
  echo "--require-modal-support-rate-pct must be a non-negative number"
  exit 2
fi
if ! is_non_negative_decimal "$require_modal_decision_support_rate_pct"; then
  echo "--require-modal-decision-support-rate-pct must be a non-negative number"
  exit 2
fi
if [[ -z "$require_modal_decision" ]]; then
  require_modal_decision="GO"
fi
require_modal_decision="$(normalize_decision "$require_modal_decision")"
if [[ "$require_modal_decision" != "GO" && "$require_modal_decision" != "NO-GO" ]]; then
  echo "--require-modal-decision must be GO or NO-GO"
  exit 2
fi

if (( runs < 1 )); then
  echo "--runs must be >= 1"
  exit 2
fi
if (( campaign_timeout_sec < 1 )); then
  echo "--campaign-timeout-sec must be >= 1"
  exit 2
fi

mkdir -p "$reports_dir"
if [[ -z "$run_summary_json" ]]; then
  run_summary_json="$reports_dir/profile_default_gate_stability_summary.json"
fi
if [[ -z "$check_summary_json" ]]; then
  check_summary_json="$reports_dir/profile_default_gate_stability_check_summary.json"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/profile_default_gate_stability_cycle_summary.json"
fi
mkdir -p "$(dirname "$run_summary_json")" "$(dirname "$check_summary_json")" "$(dirname "$summary_json")"

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
run_log="$reports_dir/profile_default_gate_stability_cycle_${run_stamp}_run.log"
check_log="$reports_dir/profile_default_gate_stability_cycle_${run_stamp}_check.log"

declare -a run_cmd
run_cmd=(
  bash "$RUN_SCRIPT"
  --host-a "$host_a"
  --host-b "$host_b"
  --campaign-subject "$campaign_subject"
  --runs "$runs"
  --campaign-timeout-sec "$campaign_timeout_sec"
  --sleep-between-sec "$sleep_between_sec"
  --allow-partial "$allow_partial"
  --reports-dir "$reports_dir"
  --summary-json "$run_summary_json"
  --print-summary-json 0
)
run_command_display="$(quote_cmd "${run_cmd[@]}")"

declare -a check_cmd
check_cmd=(
  bash "$CHECK_SCRIPT"
  --stability-summary-json "$run_summary_json"
  --reports-dir "$reports_dir"
  --require-status-pass "$require_status_pass"
  --require-stability-ok "$require_stability_ok"
  --require-selection-policy-present-all "$require_selection_policy_present_all"
  --require-consistent-selection-policy "$require_consistent_selection_policy"
  --require-decision-consensus "$require_decision_consensus"
  --require-min-runs-requested "$require_min_runs_requested"
  --require-min-runs-completed "$require_min_runs_completed"
  --require-max-runs-fail "$require_max_runs_fail"
  --require-modal-decision "$require_modal_decision"
  --require-modal-decision-support-rate-pct "$require_modal_decision_support_rate_pct"
  --require-modal-support-rate-pct "$require_modal_support_rate_pct"
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
check_command_display="$(quote_cmd "${check_cmd[@]}")"

run_summary_exists="false"
run_summary_valid="false"
run_summary_fresh="false"
run_summary_schema_id=""
run_summary_schema_valid="false"
run_summary_status=""
run_summary_rc_json="null"
run_observed_runs_total_json="null"
run_observed_runs_completed_json="null"
run_observed_runs_fail_json="null"
run_observed_evidence_state=""
run_observed_selection_policy_state=""
run_observed_command_failures_json="null"
run_observed_summary_missing_count_json="null"
run_observed_summary_unreadable_count_json="null"

echo "[profile-default-gate-stability-cycle] $(timestamp_utc) run-stage start reports_dir=$reports_dir run_summary_json=$run_summary_json"
pre_run_summary_fingerprint="$(file_fingerprint_01 "$run_summary_json")"
set +e
"${run_cmd[@]}" >"$run_log" 2>&1
run_stage_rc=$?
set -e

run_stage_status="pass"
if [[ "$run_stage_rc" -ne 0 ]]; then
  run_stage_status="fail"
fi

if [[ -f "$run_summary_json" ]]; then
  run_summary_exists="true"
fi
if [[ "$(json_file_valid_01 "$run_summary_json")" == "1" ]]; then
  run_summary_valid="true"
  post_run_summary_fingerprint="$(file_fingerprint_01 "$run_summary_json")"
  if [[ -z "$pre_run_summary_fingerprint" && -n "$post_run_summary_fingerprint" ]]; then
    run_summary_fresh="true"
  elif [[ -n "$post_run_summary_fingerprint" && "$post_run_summary_fingerprint" != "$pre_run_summary_fingerprint" ]]; then
    run_summary_fresh="true"
  fi
  run_summary_schema_id="$(jq -r '
    if (.schema.id | type) == "string" then .schema.id else "" end
  ' "$run_summary_json" 2>/dev/null || printf '%s' "")"
  if [[ "$run_summary_schema_id" == "profile_default_gate_stability_summary" ]]; then
    run_summary_schema_valid="true"
  fi
  run_summary_status="$(jq -r '
    if (.status | type) == "string" then .status else "" end
  ' "$run_summary_json" 2>/dev/null || printf '%s' "")"
  run_summary_rc_json="$(jq -r '
    if (.rc | type) == "number" then .rc else "null" end
  ' "$run_summary_json" 2>/dev/null || printf '%s' "null")"
  run_observed_runs_total_json="$(jq -r '
    if (.runs_total | type) == "number" then .runs_total
    elif (.runs_total | type) == "string" and (.runs_total | test("^[0-9]+$")) then (.runs_total | tonumber)
    elif (.runs | type) == "array" then (.runs | length)
    else "null"
    end
  ' "$run_summary_json" 2>/dev/null || printf '%s' "null")"
  run_observed_runs_completed_json="$(jq -r '
    if (.runs_completed | type) == "number" then .runs_completed
    elif (.runs_completed | type) == "string" and (.runs_completed | test("^[0-9]+$")) then (.runs_completed | tonumber)
    elif (.runs | type) == "array" then ([.runs[] | select(.completed == true)] | length)
    else "null"
    end
  ' "$run_summary_json" 2>/dev/null || printf '%s' "null")"
  run_observed_runs_fail_json="$(jq -r '
    if (.runs_fail | type) == "number" then .runs_fail
    elif (.runs_fail | type) == "string" and (.runs_fail | test("^[0-9]+$")) then (.runs_fail | tonumber)
    elif (.runs | type) == "array" then ([.runs[] | select(.command_rc != 0 or .summary_exists != true or .completed != true)] | length)
    else "null"
    end
  ' "$run_summary_json" 2>/dev/null || printf '%s' "null")"
  run_observed_command_failures_json="$(jq -r '
    if (.diagnostics.command_failures | type) == "number" then .diagnostics.command_failures
    elif (.diagnostics.command_failures | type) == "string" and (.diagnostics.command_failures | test("^[0-9]+$")) then (.diagnostics.command_failures | tonumber)
    elif (.runs | type) == "array" then ([.runs[] | select(.command_rc != 0)] | length)
    else "null"
    end
  ' "$run_summary_json" 2>/dev/null || printf '%s' "null")"
  run_observed_summary_missing_count_json="$(jq -r '
    if (.diagnostics.summary_missing_count | type) == "number" then .diagnostics.summary_missing_count
    elif (.diagnostics.summary_missing_count | type) == "string" and (.diagnostics.summary_missing_count | test("^[0-9]+$")) then (.diagnostics.summary_missing_count | tonumber)
    elif (.runs | type) == "array" then ([.runs[] | select(.summary_exists != true)] | length)
    else "null"
    end
  ' "$run_summary_json" 2>/dev/null || printf '%s' "null")"
  run_observed_summary_unreadable_count_json="$(jq -r '
    if (.diagnostics.summary_unreadable_count | type) == "number" then .diagnostics.summary_unreadable_count
    elif (.diagnostics.summary_unreadable_count | type) == "string" and (.diagnostics.summary_unreadable_count | test("^[0-9]+$")) then (.diagnostics.summary_unreadable_count | tonumber)
    elif (.runs | type) == "array" then ([.runs[] | select(.summary_exists == true and .completed != true)] | length)
    else "null"
    end
  ' "$run_summary_json" 2>/dev/null || printf '%s' "null")"
  run_observed_evidence_state="$(jq -r '
    if (.diagnostics.evidence_state | type) == "string" and ((.diagnostics.evidence_state | length) > 0) then
      .diagnostics.evidence_state
    else
      ""
    end
  ' "$run_summary_json" 2>/dev/null || printf '%s' "")"
  run_observed_selection_policy_state="$(jq -r '
    if (.diagnostics.selection_policy_state | type) == "string" and ((.diagnostics.selection_policy_state | length) > 0) then
      .diagnostics.selection_policy_state
    else
      ""
    end
  ' "$run_summary_json" 2>/dev/null || printf '%s' "")"
fi

check_stage_attempted="false"
check_stage_status="skip"
check_stage_rc_json="null"
check_stage_rc=0

check_summary_exists="false"
check_summary_valid="false"
check_summary_fresh="false"
check_summary_schema_id=""
check_summary_schema_valid="false"
check_decision=""
check_has_usable_decision="false"
check_status=""
check_rc_json="null"
check_modal_recommended_profile=""
check_modal_support_rate_pct_json="null"
check_enforcement_no_go_enforced=""
check_outcome_action=""
check_errors_json="[]"
check_error_count_json="0"
check_next_operator_action=""

failure_stage=""
failure_reason=""
decision=""
status="fail"
final_rc=1

if [[ "$run_stage_rc" -ne 0 ]]; then
  failure_stage="run"
  failure_reason="stability run failed (rc=$run_stage_rc)"
  decision="NO-GO"
  final_rc="$run_stage_rc"
  if [[ "$final_rc" -eq 0 ]]; then
    final_rc=1
  fi
elif [[ "$run_summary_valid" != "true" ]]; then
  run_stage_status="fail"
  failure_stage="run"
  failure_reason="stability run summary is missing or invalid"
  decision="NO-GO"
  final_rc=1
elif [[ "$run_summary_fresh" != "true" ]]; then
  run_stage_status="fail"
  failure_stage="run"
  failure_reason="stability run summary is stale (not refreshed by current run)"
  decision="NO-GO"
  final_rc=1
elif [[ "$run_summary_schema_valid" != "true" ]]; then
  run_stage_status="fail"
  failure_stage="run"
  failure_reason="stability run summary schema.id mismatch (expected=profile_default_gate_stability_summary actual=${run_summary_schema_id:-unset})"
  decision="NO-GO"
  final_rc=1
elif [[ "$run_summary_rc_json" == "null" ]]; then
  run_stage_status="fail"
  failure_stage="run"
  failure_reason="stability run summary is missing rc"
  decision="NO-GO"
  final_rc=1
elif [[ "$run_summary_rc_json" -ne 0 ]]; then
  run_stage_status="fail"
  failure_stage="run"
  failure_reason="stability run summary reports non-zero rc (rc=$run_summary_rc_json)"
  decision="NO-GO"
  final_rc=1
else
  echo "[profile-default-gate-stability-cycle] $(timestamp_utc) check-stage start check_summary_json=$check_summary_json"
  check_stage_attempted="true"
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

  if [[ "$(json_file_valid_01 "$check_summary_json")" == "1" ]]; then
    check_summary_exists="true"
    check_summary_valid="true"
    post_check_summary_fingerprint="$(file_fingerprint_01 "$check_summary_json")"
    if [[ -z "$pre_check_summary_fingerprint" && -n "$post_check_summary_fingerprint" ]]; then
      check_summary_fresh="true"
    elif [[ -n "$post_check_summary_fingerprint" && "$post_check_summary_fingerprint" != "$pre_check_summary_fingerprint" ]]; then
      check_summary_fresh="true"
    fi
    check_summary_schema_id="$(jq -r '
      if (.schema.id | type) == "string" then .schema.id else "" end
    ' "$check_summary_json" 2>/dev/null || printf '%s' "")"
    if [[ "$check_summary_schema_id" == "profile_default_gate_stability_check_summary" ]]; then
      check_summary_schema_valid="true"
    fi
    check_decision="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$check_summary_json" 2>/dev/null || printf '%s' "")"
    if [[ -n "$check_decision" ]]; then
      check_decision="$(normalize_decision "$check_decision")"
    fi
    if [[ "$check_decision" == "GO" || "$check_decision" == "NO-GO" ]]; then
      check_has_usable_decision="true"
    fi
    check_status="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$check_summary_json" 2>/dev/null || printf '%s' "")"
    check_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else "null" end' "$check_summary_json" 2>/dev/null || printf '%s' "null")"
    check_modal_recommended_profile="$(jq -r '
      if (.observed.modal_recommended_profile | type) == "string"
      then .observed.modal_recommended_profile
      else ""
      end
    ' "$check_summary_json" 2>/dev/null || printf '%s' "")"
    check_modal_support_rate_pct_json="$(jq -r '
      if (.observed.modal_support_rate_pct | type) == "number"
      then .observed.modal_support_rate_pct
      else "null"
      end
    ' "$check_summary_json" 2>/dev/null || printf '%s' "null")"
    check_errors_json="$(jq -c '
      if (.errors | type) == "array" then .errors else [] end
    ' "$check_summary_json" 2>/dev/null || printf '%s' "[]")"
    check_error_count_json="$(jq -r '
      if (.errors | type) == "array" then (.errors | length) else 0 end
    ' "$check_summary_json" 2>/dev/null || printf '%s' "0")"
    check_enforcement_no_go_enforced="$(jq -r '
      if (.enforcement.no_go_enforced | type) == "boolean" then
        if .enforcement.no_go_enforced then "true" else "false" end
      else
        ""
      end
    ' "$check_summary_json" 2>/dev/null || printf '%s' "")"
    check_outcome_action="$(jq -r '
      if (.outcome.action | type) == "string" then .outcome.action else "" end
    ' "$check_summary_json" 2>/dev/null || printf '%s' "")"
    check_next_operator_action="$(jq -r '
      if (.diagnostics.next_operator_action | type) == "string" then .diagnostics.next_operator_action else "" end
    ' "$check_summary_json" 2>/dev/null || printf '%s' "")"
  elif [[ -f "$check_summary_json" ]]; then
    check_summary_exists="true"
    check_summary_valid="false"
  fi

  if [[ "$check_stage_rc" -eq 0 ]]; then
    if [[ "$check_summary_valid" != "true" ]]; then
      check_stage_status="fail"
    elif [[ "$check_summary_fresh" != "true" ]]; then
      check_stage_status="fail"
    elif [[ "$check_summary_schema_valid" != "true" ]]; then
      check_stage_status="fail"
    elif [[ "$check_has_usable_decision" != "true" ]]; then
      check_stage_status="fail"
    elif [[ "$check_status" == "fail" || "$check_decision" == "NO-GO" ]]; then
      check_stage_status="fail"
    elif [[ "$check_status" == "ok" || "$check_decision" == "GO" ]]; then
      check_stage_status="pass"
    else
      check_stage_status="fail"
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
      failure_reason="stability check failed (rc=$check_stage_rc)"
    fi
  elif [[ "$check_summary_valid" != "true" ]]; then
    decision="NO-GO"
    status="fail"
    final_rc=1
    failure_stage="check"
    failure_reason="stability check summary is missing or invalid"
  elif [[ "$check_summary_fresh" != "true" ]]; then
    decision="NO-GO"
    status="fail"
    final_rc=1
    failure_stage="check"
    failure_reason="stability check summary is stale (not refreshed by current run)"
  elif [[ "$check_summary_schema_valid" != "true" ]]; then
    decision="NO-GO"
    status="fail"
    final_rc=1
    failure_stage="check"
    failure_reason="stability check summary schema.id mismatch (expected=profile_default_gate_stability_check_summary actual=${check_summary_schema_id:-unset})"
  elif [[ "$check_has_usable_decision" != "true" ]]; then
    decision="NO-GO"
    status="fail"
    final_rc=1
    failure_stage="check"
    failure_reason="stability check summary is missing a usable decision"
  elif [[ "$check_decision" == "GO" ]]; then
    status="pass"
    final_rc=0
  elif [[ "$check_decision" == "NO-GO" ]]; then
    if [[ "$fail_on_no_go" == "1" ]]; then
      status="fail"
      final_rc=1
      failure_stage="check"
      failure_reason="stability check decision is NO-GO"
    else
      status="warn"
      final_rc=0
    fi
  else
    decision="NO-GO"
    status="fail"
    final_rc=1
    failure_stage="check"
    failure_reason="stability check summary is missing a usable decision"
  fi
fi

cycle_evidence_state="complete"
if [[ "$run_summary_valid" != "true" || "$run_summary_fresh" != "true" || "$run_summary_schema_valid" != "true" ]]; then
  cycle_evidence_state="missing"
elif [[ "$check_stage_attempted" == "false" ]]; then
  cycle_evidence_state="partial"
elif [[ "$check_summary_valid" != "true" || "$check_summary_fresh" != "true" || "$check_summary_schema_valid" != "true" ]]; then
  cycle_evidence_state="partial"
elif [[ "$run_observed_evidence_state" == "partial" ]]; then
  cycle_evidence_state="partial"
elif [[ "$check_decision" == "NO-GO" ]]; then
  cycle_evidence_state="partial"
fi

declare -a cycle_issues=()
if [[ "$run_stage_status" != "pass" ]]; then
  cycle_issues+=("run stage did not pass (rc=$run_stage_rc)")
fi
if [[ "$run_summary_valid" != "true" ]]; then
  cycle_issues+=("run summary missing or unreadable")
fi
if [[ "$run_summary_fresh" != "true" ]]; then
  cycle_issues+=("run summary is stale for this cycle")
fi
if [[ "$run_summary_schema_valid" != "true" ]]; then
  cycle_issues+=("run summary schema mismatch")
fi
if [[ "$check_stage_attempted" == "true" && "$check_stage_status" != "pass" ]]; then
  cycle_issues+=("check stage did not pass (rc=$check_stage_rc)")
fi
if [[ "$check_stage_attempted" == "true" && "$check_summary_valid" != "true" ]]; then
  cycle_issues+=("check summary missing or unreadable")
fi
if [[ "$check_stage_attempted" == "true" && "$check_summary_fresh" != "true" ]]; then
  cycle_issues+=("check summary is stale for this cycle")
fi
if [[ "$check_stage_attempted" == "true" && "$check_summary_schema_valid" != "true" ]]; then
  cycle_issues+=("check summary schema mismatch")
fi
if [[ "$check_decision" == "NO-GO" ]]; then
  cycle_issues+=("check summary decision is NO-GO")
fi

cycle_issues_json='[]'
if ((${#cycle_issues[@]} > 0)); then
  cycle_issues_json="$(printf '%s\n' "${cycle_issues[@]}" | jq -R . | jq -s '.')"
fi

next_operator_action="Cycle evidence is healthy; proceed with stability promotion."
if [[ -n "$check_next_operator_action" ]]; then
  next_operator_action="$check_next_operator_action"
fi
if [[ "$cycle_evidence_state" == "missing" ]]; then
  next_operator_action="Required stability evidence is missing/stale; rerun cycle after verifying real-host availability."
elif [[ "$cycle_evidence_state" == "partial" && "$check_decision" != "NO-GO" ]]; then
  next_operator_action="Cycle evidence is partial; inspect stage logs and rerun cycle before promotion."
fi

rerun_cycle_command_template="./scripts/easy_node.sh profile-default-gate-stability-cycle --host-a ${host_a} --host-b ${host_b} --campaign-subject INVITE_KEY --runs ${runs} --campaign-timeout-sec ${campaign_timeout_sec} --sleep-between-sec ${sleep_between_sec} --allow-partial ${allow_partial} --reports-dir ${reports_dir} --summary-json ${summary_json} --print-summary-json 1"
rerun_run_command_template="./scripts/easy_node.sh profile-default-gate-stability-run --host-a ${host_a} --host-b ${host_b} --campaign-subject INVITE_KEY --runs ${runs} --campaign-timeout-sec ${campaign_timeout_sec} --sleep-between-sec ${sleep_between_sec} --allow-partial ${allow_partial} --reports-dir ${reports_dir} --summary-json ${run_summary_json} --print-summary-json 1"
rerun_check_command_template="./scripts/easy_node.sh profile-default-gate-stability-check --stability-summary-json ${run_summary_json} --summary-json ${check_summary_json} --print-summary-json 1"

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --arg decision "$decision" \
  --arg run_summary_json "$run_summary_json" \
  --arg check_summary_json "$check_summary_json" \
  --arg summary_json_path "$summary_json" \
  --arg run_log "$run_log" \
  --arg check_log "$check_log" \
  --arg run_command "$run_command_display" \
  --arg check_command "$check_command_display" \
  --arg host_a "$host_a" \
  --arg host_b "$host_b" \
  --arg campaign_subject "$campaign_subject" \
  --arg reports_dir "$reports_dir" \
  --arg run_stage_status "$run_stage_status" \
  --arg run_summary_exists "$run_summary_exists" \
  --arg run_summary_valid "$run_summary_valid" \
  --arg run_summary_fresh "$run_summary_fresh" \
  --arg run_summary_schema_id "$run_summary_schema_id" \
  --arg run_summary_schema_valid "$run_summary_schema_valid" \
  --arg run_summary_status "$run_summary_status" \
  --arg run_observed_evidence_state "$run_observed_evidence_state" \
  --arg run_observed_selection_policy_state "$run_observed_selection_policy_state" \
  --arg check_stage_attempted "$check_stage_attempted" \
  --arg check_stage_status "$check_stage_status" \
  --arg failure_stage "$failure_stage" \
  --arg failure_reason "$failure_reason" \
  --arg check_summary_exists "$check_summary_exists" \
  --arg check_summary_valid "$check_summary_valid" \
  --arg check_summary_fresh "$check_summary_fresh" \
  --arg check_summary_schema_id "$check_summary_schema_id" \
  --arg check_summary_schema_valid "$check_summary_schema_valid" \
  --arg check_decision "$check_decision" \
  --arg check_has_usable_decision "$check_has_usable_decision" \
  --arg check_status "$check_status" \
  --arg check_modal_recommended_profile "$check_modal_recommended_profile" \
  --arg check_enforcement_no_go_enforced "$check_enforcement_no_go_enforced" \
  --arg check_outcome_action "$check_outcome_action" \
  --arg check_next_operator_action "$check_next_operator_action" \
  --arg cycle_evidence_state "$cycle_evidence_state" \
  --arg next_operator_action "$next_operator_action" \
  --arg rerun_cycle_command_template "$rerun_cycle_command_template" \
  --arg rerun_run_command_template "$rerun_run_command_template" \
  --arg rerun_check_command_template "$rerun_check_command_template" \
  --argjson rc "$final_rc" \
  --argjson run_stage_rc "$run_stage_rc" \
  --argjson run_summary_rc "$run_summary_rc_json" \
  --argjson run_observed_runs_total "$run_observed_runs_total_json" \
  --argjson run_observed_runs_completed "$run_observed_runs_completed_json" \
  --argjson run_observed_runs_fail "$run_observed_runs_fail_json" \
  --argjson run_observed_command_failures "$run_observed_command_failures_json" \
  --argjson run_observed_summary_missing_count "$run_observed_summary_missing_count_json" \
  --argjson run_observed_summary_unreadable_count "$run_observed_summary_unreadable_count_json" \
  --argjson check_stage_rc "$check_stage_rc_json" \
  --argjson check_rc "$check_rc_json" \
  --argjson check_modal_support_rate_pct "$check_modal_support_rate_pct_json" \
  --argjson check_error_count "$check_error_count_json" \
  --argjson check_errors "$check_errors_json" \
  --argjson cycle_issues "$cycle_issues_json" \
  --argjson runs "$runs" \
  --argjson campaign_timeout_sec "$campaign_timeout_sec" \
  --argjson sleep_between_sec "$sleep_between_sec" \
  --argjson allow_partial "$allow_partial" \
  --argjson require_status_pass "$require_status_pass" \
  --argjson require_stability_ok "$require_stability_ok" \
  --argjson require_selection_policy_present_all "$require_selection_policy_present_all" \
  --argjson require_consistent_selection_policy "$require_consistent_selection_policy" \
  --argjson require_decision_consensus "$require_decision_consensus" \
  --argjson require_min_runs_requested "$require_min_runs_requested" \
  --argjson require_min_runs_completed "$require_min_runs_completed" \
  --argjson require_max_runs_fail "$require_max_runs_fail" \
  --arg require_modal_decision "$require_modal_decision" \
  --argjson require_modal_decision_support_rate_pct "$require_modal_decision_support_rate_pct" \
  --arg require_recommended_profile "$require_recommended_profile" \
  --arg allow_recommended_profiles "$allow_recommended_profiles" \
  --argjson require_modal_support_rate_pct "$require_modal_support_rate_pct" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  '{
    version: 1,
    schema: {
      id: "profile_default_gate_stability_cycle_summary"
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    decision: (if $decision == "" then null else $decision end),
    failure_stage: (if $failure_stage == "" then null else $failure_stage end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    inputs: {
      host_a: $host_a,
      host_b: $host_b,
      campaign_subject: $campaign_subject,
      reports_dir: $reports_dir,
      run: {
        runs: $runs,
        campaign_timeout_sec: $campaign_timeout_sec,
        sleep_between_sec: $sleep_between_sec,
        allow_partial: ($allow_partial == 1)
      },
      check: {
        policy: {
          require_status_pass: ($require_status_pass == 1),
          require_stability_ok: ($require_stability_ok == 1),
          require_selection_policy_present_all: ($require_selection_policy_present_all == 1),
          require_consistent_selection_policy: ($require_consistent_selection_policy == 1),
          require_decision_consensus: ($require_decision_consensus == 1),
          require_min_runs_requested: $require_min_runs_requested,
          require_min_runs_completed: $require_min_runs_completed,
          require_max_runs_fail: $require_max_runs_fail,
          require_modal_decision: (
            if $require_modal_decision == "" then null
            else $require_modal_decision
            end
          ),
          require_modal_decision_support_rate_pct: $require_modal_decision_support_rate_pct,
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
          require_modal_support_rate_pct: $require_modal_support_rate_pct,
          fail_on_no_go: ($fail_on_no_go == 1)
        }
      }
    },
    stages: {
      run: {
        attempted: true,
        status: $run_stage_status,
        rc: $run_stage_rc,
        command: $run_command,
        log: $run_log,
        summary_json: $run_summary_json,
        summary_exists: ($run_summary_exists == "true"),
        summary_valid_json: ($run_summary_valid == "true"),
        summary_fresh: ($run_summary_fresh == "true"),
        summary_schema_id: (
          if $run_summary_schema_id == "" then null
          else $run_summary_schema_id
          end
        ),
        summary_schema_valid: ($run_summary_schema_valid == "true"),
        observed_status: (
          if $run_summary_status == "" then null
          else $run_summary_status
          end
        ),
        observed_rc: $run_summary_rc,
        observed_runs_total: $run_observed_runs_total,
        observed_runs_completed: $run_observed_runs_completed,
        observed_runs_fail: $run_observed_runs_fail,
        observed_command_failures: $run_observed_command_failures,
        observed_summary_missing_count: $run_observed_summary_missing_count,
        observed_summary_unreadable_count: $run_observed_summary_unreadable_count,
        observed_evidence_state: (
          if $run_observed_evidence_state == "" then null
          else $run_observed_evidence_state
          end
        ),
        observed_selection_policy_state: (
          if $run_observed_selection_policy_state == "" then null
          else $run_observed_selection_policy_state
          end
        )
      },
      check: {
        attempted: ($check_stage_attempted == "true"),
        status: $check_stage_status,
        rc: $check_stage_rc,
        command: $check_command,
        log: $check_log,
        summary_json: $check_summary_json
      }
    },
    check: {
      summary_exists: ($check_summary_exists == "true"),
      summary_valid_json: ($check_summary_valid == "true"),
      summary_fresh: ($check_summary_fresh == "true"),
      summary_schema_id: (
        if $check_summary_schema_id == "" then null
        else $check_summary_schema_id
        end
      ),
      summary_schema_valid: ($check_summary_schema_valid == "true"),
      decision: (if $check_decision == "" then null else $check_decision end),
      has_usable_decision: ($check_has_usable_decision == "true"),
      status: (if $check_status == "" then null else $check_status end),
      rc: $check_rc,
      modal_recommended_profile: (
        if $check_modal_recommended_profile == "" then null
        else $check_modal_recommended_profile
        end
      ),
      modal_support_rate_pct: $check_modal_support_rate_pct,
      enforcement_no_go_enforced: (
        if $check_enforcement_no_go_enforced == "true" then true
        elif $check_enforcement_no_go_enforced == "false" then false
        else null
        end
      ),
      outcome_action: (
        if $check_outcome_action == "" then null
        else $check_outcome_action
        end
      ),
      next_operator_action: (
        if $check_next_operator_action == "" then null
        else $check_next_operator_action
        end
      ),
      error_count: $check_error_count,
      errors: $check_errors
    },
    enforcement: {
      fail_on_no_go: ($fail_on_no_go == 1),
      no_go_detected: ($decision == "NO-GO"),
      no_go_enforced: ($decision == "NO-GO" and ($fail_on_no_go == 1)),
      run_summary_schema_enforced: ($run_summary_schema_valid == "true"),
      check_summary_schema_enforced: ($check_summary_schema_valid == "true")
    },
    outcome: {
      run_stage_passed: ($run_stage_status == "pass"),
      check_stage_passed: ($check_stage_status == "pass"),
      check_has_usable_decision: ($check_has_usable_decision == "true"),
      should_promote: ($status == "pass" and $decision == "GO"),
      action: (
        if $status == "pass" and $decision == "GO" then "promote_allowed"
        elif $decision == "NO-GO" and $fail_on_no_go == 1 then "hold_promotion_blocked"
        elif $decision == "NO-GO" then "hold_promotion_warn_only"
        else "investigate_artifacts"
        end
      )
    },
    diagnostics: {
      evidence_state: $cycle_evidence_state,
      issue_count: ($cycle_issues | length),
      issues: $cycle_issues,
      next_operator_action: $next_operator_action,
      rerun_cycle_command_template: $rerun_cycle_command_template,
      rerun_run_command_template: $rerun_run_command_template,
      rerun_check_command_template: $rerun_check_command_template
    },
    artifacts: {
      summary_json: $summary_json_path,
      run_summary_json: $run_summary_json,
      check_summary_json: $check_summary_json,
      run_log: $run_log,
      check_log: $check_log
    }
  }' >"$summary_json"

echo "[profile-default-gate-stability-cycle] status=$status rc=$final_rc decision=${decision:-unset} summary_json=$summary_json"
if [[ -n "$failure_stage" ]]; then
  echo "[profile-default-gate-stability-cycle] failure_stage=$failure_stage failure_reason=${failure_reason:-}"
fi
if [[ "$show_json" == "1" ]]; then
  echo "[profile-default-gate-stability-cycle] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
