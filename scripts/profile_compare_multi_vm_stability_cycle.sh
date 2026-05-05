#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_SCRIPT="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_run.sh}"
CHECK_SCRIPT="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_check.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_multi_vm_stability_cycle.sh \
    [--reports-dir DIR] \
    [--run-summary-json PATH | --stability-summary-json PATH] \
    [--check-summary-json PATH | --stability-check-summary-json PATH] \
    [--runs N] \
    [--sleep-between-sec N] \
    [--allow-partial [0|1]] \
    [--vm-command SPEC]... \
    [--vm-command-file PATH]... \
    [--require-status-pass [0|1]] \
    [--require-min-runs-requested N] \
    [--require-min-runs-completed N] \
    [--require-max-runs-fail N] \
    [--require-decision-consensus [0|1]] \
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
  Run profile-compare multi-VM stability run and policy check in one command,
  then emit a single cycle summary artifact.

Notes:
  - Stage scripts can be overridden with:
    PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SCRIPT
    PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SCRIPT
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

array_to_json() {
  if (( $# == 0 )); then
    printf '%s' "[]"
  else
    printf '%s\n' "$@" | jq -R . | jq -s '.'
  fi
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

json_schema_id() {
  local path="$1"
  jq -r 'if (.schema.id | type) == "string" then .schema.id else "" end' "$path" 2>/dev/null || true
}

run_summary_schema_valid_01() {
  local schema_id
  schema_id="$(trim "${1:-}")"
  case "$schema_id" in
    profile_compare_multi_vm_stability_run_summary|profile_compare_multi_vm_stability_summary)
      printf '1'
      ;;
    *)
      printf '0'
      ;;
  esac
}

check_summary_schema_valid_01() {
  local schema_id
  schema_id="$(trim "${1:-}")"
  if [[ "$schema_id" == "profile_compare_multi_vm_stability_check_summary" ]]; then
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

extract_run_stage_failure_hint() {
  local run_log_path="$1"
  local hint=""
  if [[ -z "$run_log_path" || ! -f "$run_log_path" ]]; then
    printf '%s' ""
    return
  fi
  hint="$(grep -m1 '^operator_next_action:' "$run_log_path" 2>/dev/null || true)"
  if [[ -n "$hint" ]]; then
    printf '%s' "$hint"
    return
  fi
  hint="$(grep -m1 'at least one --vm-command or --vm-command-file is required' "$run_log_path" 2>/dev/null || true)"
  if [[ -n "$hint" ]]; then
    printf '%s' "$hint"
    return
  fi
  printf '%s' ""
}

extract_run_stage_failure_hints_json() {
  local run_log_path="$1"
  local line=""
  local -a hints=()
  if [[ -z "$run_log_path" || ! -f "$run_log_path" ]]; then
    printf '%s' "[]"
    return
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim "$line")"
    if [[ -z "$line" ]]; then
      continue
    fi
    case "$line" in
      operator_next_action:*|preflight_diag:*|fallback\ checks:*|vm-command-file\ preflight\ checks:*|at\ least\ one\ --vm-command\ or\ --vm-command-file\ is\ required|no\ usable\ VM\ command\ fallback\ was\ discovered*|vm\ command\ file\ preflight\ failed:*|vm\ command\ file:*)
        hints+=("$line")
        ;;
      -\ source=*)
        hints+=("${line#- }")
        ;;
      source=*)
        if [[ "$line" == *"reason="* || "$line" == *"result="* ]]; then
          hints+=("$line")
        fi
        ;;
    esac
  done <"$run_log_path"
  array_to_json "${hints[@]}"
}

set_primary_failure() {
  local code="$1"
  local stage="$2"
  local reason="$3"
  local action="$4"
  local action_command="$5"
  local category="${6:-contract}"

  failure_stage="$stage"
  failure_reason="$reason"
  failure_reason_code="$code"
  failure_category="$category"
  next_operator_action="$action"
  next_operator_action_command="$(trim "$action_command")"
  failure_reasons_json="$(jq -n \
    --arg code "$code" \
    --arg stage "$stage" \
    --arg reason "$reason" \
    --arg action "$action" \
    --arg action_command "$next_operator_action_command" \
    --arg category "$category" \
    '[{
      code: $code,
      stage: (if $stage == "" then null else $stage end),
      category: (if $category == "" then null else $category end),
      reason: $reason,
      action: $action,
      action_command: (if $action_command == "" then null else $action_command end)
    }]')"
}

need_cmd jq
need_cmd date
need_cmd bash
need_cmd mkdir
need_cmd cksum
need_cmd grep

reports_dir="${PROFILE_COMPARE_MULTI_VM_STABILITY_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
run_summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SUMMARY_JSON:-}"
check_summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SUMMARY_JSON:-}"
summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_CYCLE_SUMMARY_JSON:-}"

runs=""
sleep_between_sec=""
allow_partial=""
declare -a vm_command_specs=()
declare -a vm_command_files=()

require_status_pass="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_STATUS_PASS:-${REQUIRE_STATUS_PASS:-1}}"
require_min_runs_requested="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_MIN_RUNS_REQUESTED:-${REQUIRE_MIN_RUNS_REQUESTED:-3}}"
require_min_runs_completed="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_MIN_RUNS_COMPLETED:-${REQUIRE_MIN_RUNS_COMPLETED:-3}}"
require_max_runs_fail="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_MAX_RUNS_FAIL:-${REQUIRE_MAX_RUNS_FAIL:-0}}"
require_decision_consensus="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_DECISION_CONSENSUS:-${REQUIRE_DECISION_CONSENSUS:-1}}"
require_modal_decision="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_MODAL_DECISION:-${REQUIRE_MODAL_DECISION:-GO}}"
require_modal_decision_support_rate_pct="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_MODAL_DECISION_SUPPORT_RATE_PCT:-${REQUIRE_MODAL_DECISION_SUPPORT_RATE_PCT:-67}}"
require_recommended_profile="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_RECOMMENDED_PROFILE:-${REQUIRE_RECOMMENDED_PROFILE:-}}"
allow_recommended_profiles="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_ALLOW_RECOMMENDED_PROFILES:-${ALLOW_RECOMMENDED_PROFILES:-balanced,speed,private}}"
require_modal_support_rate_pct="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_MODAL_SUPPORT_RATE_PCT:-${REQUIRE_MODAL_SUPPORT_RATE_PCT:-60}}"
fail_on_no_go="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_FAIL_ON_NO_GO:-${FAIL_ON_NO_GO:-1}}"

show_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_CYCLE_SHOW_JSON:-0}"
print_summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_CYCLE_PRINT_SUMMARY_JSON:-0}"

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
    --runs)
      require_value_or_die "$1" "$#"
      runs="${2:-}"
      shift 2
      ;;
    --runs=*)
      runs="${1#*=}"
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

reports_dir="$(abs_path "$reports_dir")"
run_summary_json="$(abs_path "$run_summary_json")"
check_summary_json="$(abs_path "$check_summary_json")"
summary_json="$(abs_path "$summary_json")"
runs="$(trim "$runs")"
sleep_between_sec="$(trim "$sleep_between_sec")"
allow_partial="$(trim "$allow_partial")"
require_status_pass="$(trim "$require_status_pass")"
require_min_runs_requested="$(trim "$require_min_runs_requested")"
require_min_runs_completed="$(trim "$require_min_runs_completed")"
require_max_runs_fail="$(trim "$require_max_runs_fail")"
require_decision_consensus="$(trim "$require_decision_consensus")"
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
for i in "${!vm_command_specs[@]}"; do
  vm_command_specs[$i]="$(trim "${vm_command_specs[$i]}")"
  if [[ -z "${vm_command_specs[$i]}" ]]; then
    echo "--vm-command cannot be empty"
    exit 2
  fi
done
for i in "${!vm_command_files[@]}"; do
  vm_command_files[$i]="$(abs_path "${vm_command_files[$i]}")"
  if [[ -z "${vm_command_files[$i]}" ]]; then
    echo "--vm-command-file cannot be empty"
    exit 2
  fi
done

if [[ ! -f "$RUN_SCRIPT" ]]; then
  echo "stability run script not found: $RUN_SCRIPT"
  exit 2
fi
if [[ ! -f "$CHECK_SCRIPT" ]]; then
  echo "stability check script not found: $CHECK_SCRIPT"
  exit 2
fi

if [[ -n "$runs" ]]; then
  int_arg_or_die "--runs" "$runs"
  if (( runs < 1 )); then
    echo "--runs must be >= 1"
    exit 2
  fi
fi
if [[ -n "$sleep_between_sec" ]]; then
  int_arg_or_die "--sleep-between-sec" "$sleep_between_sec"
fi
if [[ -n "$allow_partial" ]]; then
  bool_arg_or_die "--allow-partial" "$allow_partial"
fi
bool_arg_or_die "--require-status-pass" "$require_status_pass"
bool_arg_or_die "--require-decision-consensus" "$require_decision_consensus"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

for int_arg in "$require_min_runs_requested" "$require_min_runs_completed" "$require_max_runs_fail"; do
  if ! [[ "$int_arg" =~ ^[0-9]+$ ]]; then
    echo "run count thresholds must be non-negative integers"
    exit 2
  fi
done
if ! is_non_negative_decimal "$require_modal_support_rate_pct"; then
  echo "--require-modal-support-rate-pct must be a non-negative number"
  exit 2
fi
if ! is_non_negative_decimal "$require_modal_decision_support_rate_pct"; then
  echo "--require-modal-decision-support-rate-pct must be a non-negative number"
  exit 2
fi
if [[ -n "$require_modal_decision" ]]; then
  require_modal_decision="$(normalize_decision "$require_modal_decision")"
  if [[ "$require_modal_decision" != "GO" && "$require_modal_decision" != "NO-GO" ]]; then
    echo "--require-modal-decision must be GO or NO-GO"
    exit 2
  fi
fi

mkdir -p "$reports_dir"
if [[ -z "$run_summary_json" ]]; then
  run_summary_json="$reports_dir/profile_compare_multi_vm_stability_summary.json"
fi
if [[ -z "$check_summary_json" ]]; then
  check_summary_json="$reports_dir/profile_compare_multi_vm_stability_check_summary.json"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/profile_compare_multi_vm_stability_cycle_summary.json"
fi
mkdir -p "$(dirname "$run_summary_json")" "$(dirname "$check_summary_json")" "$(dirname "$summary_json")"

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
run_log="$reports_dir/profile_compare_multi_vm_stability_cycle_${run_stamp}_run.log"
check_log="$reports_dir/profile_compare_multi_vm_stability_cycle_${run_stamp}_check.log"

declare -a run_cmd
run_cmd=(
  bash "$RUN_SCRIPT"
  --reports-dir "$reports_dir"
  --summary-json "$run_summary_json"
  --print-summary-json 0
)
if [[ -n "$runs" ]]; then
  run_cmd+=(--runs "$runs")
fi
if [[ -n "$sleep_between_sec" ]]; then
  run_cmd+=(--sleep-between-sec "$sleep_between_sec")
fi
if [[ -n "$allow_partial" ]]; then
  run_cmd+=(--allow-partial "$allow_partial")
fi
for vm_spec in "${vm_command_specs[@]}"; do
  run_cmd+=(--vm-command "$vm_spec")
done
for vm_file in "${vm_command_files[@]}"; do
  run_cmd+=(--vm-command-file "$vm_file")
done
run_command_display="$(quote_cmd "${run_cmd[@]}")"

declare -a check_cmd
check_cmd=(
  bash "$CHECK_SCRIPT"
  --stability-summary-json "$run_summary_json"
  --reports-dir "$reports_dir"
  --require-status-pass "$require_status_pass"
  --require-min-runs-requested "$require_min_runs_requested"
  --require-min-runs-completed "$require_min_runs_completed"
  --require-max-runs-fail "$require_max_runs_fail"
  --require-decision-consensus "$require_decision_consensus"
  --require-modal-decision-support-rate-pct "$require_modal_decision_support_rate_pct"
  --require-modal-support-rate-pct "$require_modal_support_rate_pct"
  --fail-on-no-go "$fail_on_no_go"
  --summary-json "$check_summary_json"
  --show-json 0
  --print-summary-json 0
)
if [[ -n "$require_modal_decision" ]]; then
  check_cmd+=(--require-modal-decision "$require_modal_decision")
fi
if [[ -n "$require_recommended_profile" ]]; then
  check_cmd+=(--require-recommended-profile "$require_recommended_profile")
fi
if [[ -n "$allow_recommended_profiles" ]]; then
  check_cmd+=(--allow-recommended-profiles "$allow_recommended_profiles")
fi
check_command_display="$(quote_cmd "${check_cmd[@]}")"

run_summary_exists="false"
run_summary_valid="false"
run_summary_schema_id=""
run_summary_schema_valid="false"
run_summary_fresh="false"
run_stage_failure_hint=""
run_stage_failure_hints_json="[]"

echo "[profile-compare-multi-vm-stability-cycle] $(timestamp_utc) run-stage start reports_dir=$reports_dir run_summary_json=$run_summary_json"
pre_run_summary_fingerprint="$(file_fingerprint_01 "$run_summary_json")"
set +e
"${run_cmd[@]}" >"$run_log" 2>&1
run_stage_rc=$?
set -e
run_stage_failure_hints_json="$(extract_run_stage_failure_hints_json "$run_log")"

run_stage_status="pass"
if [[ "$run_stage_rc" -ne 0 ]]; then
  run_stage_status="fail"
  run_stage_failure_hint="$(extract_run_stage_failure_hint "$run_log")"
fi

if [[ -f "$run_summary_json" ]]; then
  run_summary_exists="true"
fi
if [[ "$(json_file_valid_01 "$run_summary_json")" == "1" ]]; then
  run_summary_schema_id="$(json_schema_id "$run_summary_json")"
  if [[ "$(run_summary_schema_valid_01 "$run_summary_schema_id")" == "1" ]]; then
    run_summary_valid="true"
    run_summary_schema_valid="true"
    post_run_summary_fingerprint="$(file_fingerprint_01 "$run_summary_json")"
    if [[ -z "$pre_run_summary_fingerprint" && -n "$post_run_summary_fingerprint" ]]; then
      run_summary_fresh="true"
    elif [[ -n "$post_run_summary_fingerprint" && "$post_run_summary_fingerprint" != "$pre_run_summary_fingerprint" ]]; then
      run_summary_fresh="true"
    fi
  else
    run_summary_valid="false"
    run_summary_schema_valid="false"
  fi
fi

check_stage_attempted="false"
check_stage_status="skip"
check_stage_rc_json="null"
check_stage_rc=0

check_summary_exists="false"
check_summary_valid="false"
check_summary_schema_id=""
check_summary_schema_valid="false"
check_summary_fresh="false"
check_decision=""
check_status=""
check_rc_json="null"
check_modal_recommended_profile=""
check_modal_support_rate_pct_json="null"
check_errors_json="[]"
check_primary_violation_code=""
check_primary_violation_message=""
check_primary_violation_action=""

failure_stage=""
failure_reason=""
failure_reason_code=""
failure_category=""
next_operator_action=""
next_operator_action_command=""
failure_reasons_json="[]"
decision=""
status="fail"
final_rc=1

if [[ "$run_stage_rc" -ne 0 ]]; then
  if [[ -n "$run_stage_failure_hint" ]]; then
    set_primary_failure \
      "run_stage_command_failed" \
      "run" \
      "$run_stage_failure_hint" \
      "Inspect run-stage diagnostics and rerun profile_compare_multi_vm_stability_cycle.sh." \
      "$run_command_display" \
      "execution"
  else
    set_primary_failure \
      "run_stage_command_failed" \
      "run" \
      "stability run failed (rc=$run_stage_rc)" \
      "Inspect run-stage diagnostics and rerun profile_compare_multi_vm_stability_cycle.sh." \
      "$run_command_display" \
      "execution"
  fi
  decision="NO-GO"
  status="fail"
  final_rc="$run_stage_rc"
  if [[ "$final_rc" -eq 0 ]]; then
    final_rc=1
  fi
elif [[ "$run_summary_valid" != "true" ]]; then
  run_stage_status="fail"
  if [[ "$run_summary_exists" == "true" && -n "$run_summary_schema_id" && "$run_summary_schema_valid" != "true" ]]; then
    set_primary_failure \
      "run_summary_schema_invalid" \
      "run" \
      "stability run summary schema.id mismatch (expected profile_compare_multi_vm_stability_run_summary)" \
      "Regenerate multi-VM run summary artifacts with profile_compare_multi_vm_stability_run.sh and rerun the cycle." \
      "$run_command_display" \
      "artifact_contract"
  else
    set_primary_failure \
      "run_summary_missing_or_invalid" \
      "run" \
      "stability run summary is missing or invalid" \
      "Ensure run stage writes a valid summary JSON and rerun profile_compare_multi_vm_stability_cycle.sh." \
      "$run_command_display" \
      "artifact_contract"
  fi
  decision="NO-GO"
  status="fail"
  final_rc=1
elif [[ "$run_summary_fresh" != "true" ]]; then
  run_stage_status="fail"
  set_primary_failure \
    "run_summary_stale" \
    "run" \
    "stability run summary is stale (not refreshed by current run)" \
    "Delete stale summary artifacts or force a fresh run-stage execution, then rerun the cycle." \
    "$run_command_display" \
    "artifact_freshness"
  decision="NO-GO"
  status="fail"
  final_rc=1
else
  echo "[profile-compare-multi-vm-stability-cycle] $(timestamp_utc) check-stage start check_summary_json=$check_summary_json"
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
    check_summary_schema_id="$(json_schema_id "$check_summary_json")"
    if [[ "$(check_summary_schema_valid_01 "$check_summary_schema_id")" == "1" ]]; then
      check_summary_valid="true"
      check_summary_schema_valid="true"
      post_check_summary_fingerprint="$(file_fingerprint_01 "$check_summary_json")"
      if [[ -z "$pre_check_summary_fingerprint" && -n "$post_check_summary_fingerprint" ]]; then
        check_summary_fresh="true"
      elif [[ -n "$post_check_summary_fingerprint" && "$post_check_summary_fingerprint" != "$pre_check_summary_fingerprint" ]]; then
        check_summary_fresh="true"
      fi
      check_decision="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$check_summary_json" 2>/dev/null || printf '%s' "")"
      check_decision="$(normalize_decision "$check_decision")"
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
      check_errors_json="$(jq -c 'if (.errors | type) == "array" then .errors else [] end' "$check_summary_json" 2>/dev/null || printf '%s' "[]")"
      check_primary_violation_code="$(jq -r '
        if (.violations | type) == "array"
          and (.violations | length) > 0
          and (.violations[0].code | type) == "string"
        then .violations[0].code
        else ""
        end
      ' "$check_summary_json" 2>/dev/null || printf '%s' "")"
      check_primary_violation_message="$(jq -r '
        if (.violations | type) == "array"
          and (.violations | length) > 0
          and (.violations[0].message | type) == "string"
        then .violations[0].message
        else ""
        end
      ' "$check_summary_json" 2>/dev/null || printf '%s' "")"
      check_primary_violation_action="$(jq -r '
        if (.violations | type) == "array"
          and (.violations | length) > 0
          and (.violations[0].action | type) == "string"
        then .violations[0].action
        else ""
        end
      ' "$check_summary_json" 2>/dev/null || printf '%s' "")"
    else
      check_summary_valid="false"
      check_summary_schema_valid="false"
    fi
  elif [[ -f "$check_summary_json" ]]; then
    check_summary_exists="true"
    check_summary_valid="false"
  fi

  if [[ "$check_stage_rc" -eq 0 ]]; then
    if [[ "$check_summary_valid" != "true" ]]; then
      check_stage_status="fail"
    elif [[ "$check_summary_fresh" != "true" ]]; then
      check_stage_status="fail"
    elif [[ "$check_status" == "fail" || "$check_decision" == "NO-GO" ]]; then
      check_stage_status="fail"
    elif [[ "$check_status" == "ok" || "$check_decision" == "GO" ]]; then
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
    failure_reason="$(jq -r '
      if (. | type) == "array" and (. | length) > 0 and (.[0] | type) == "string"
      then .[0]
      else ""
      end
    ' <<<"$check_errors_json" 2>/dev/null || printf '%s' "")"
    primary_code="$check_primary_violation_code"
    primary_action="$check_primary_violation_action"
    if [[ -z "$failure_reason" && -n "$check_primary_violation_message" ]]; then
      failure_reason="$check_primary_violation_message"
    fi
    if [[ -z "$failure_reason" ]]; then
      failure_reason="stability check failed (rc=$check_stage_rc)"
    fi
    if [[ -z "$primary_code" ]]; then
      primary_code="check_stage_command_failed"
    fi
    if [[ -z "$primary_action" ]]; then
      primary_action="Inspect check-stage diagnostics and rerun profile_compare_multi_vm_stability_cycle.sh."
    fi
    set_primary_failure \
      "$primary_code" \
      "check" \
      "$failure_reason" \
      "$primary_action" \
      "$check_command_display" \
      "execution"
  elif [[ "$check_summary_valid" != "true" ]]; then
    decision="NO-GO"
    status="fail"
    final_rc=1
    if [[ "$check_summary_exists" == "true" && -n "$check_summary_schema_id" && "$check_summary_schema_valid" != "true" ]]; then
      set_primary_failure \
        "check_summary_schema_invalid" \
        "check" \
        "stability check summary schema.id mismatch (expected profile_compare_multi_vm_stability_check_summary)" \
        "Regenerate stability check summary artifacts with profile_compare_multi_vm_stability_check.sh." \
        "$check_command_display" \
        "artifact_contract"
    else
      set_primary_failure \
        "check_summary_missing_or_invalid" \
        "check" \
        "stability check summary is missing or invalid" \
        "Ensure check stage emits a valid check summary JSON and rerun profile_compare_multi_vm_stability_cycle.sh." \
        "$check_command_display" \
        "artifact_contract"
    fi
  elif [[ "$check_summary_fresh" != "true" ]]; then
    decision="NO-GO"
    status="fail"
    final_rc=1
    set_primary_failure \
      "check_summary_stale" \
      "check" \
      "stability check summary is stale (not refreshed by current run)" \
      "Refresh check-stage artifacts by rerunning profile_compare_multi_vm_stability_cycle.sh." \
      "$check_command_display" \
      "artifact_freshness"
  elif [[ "$check_decision" == "GO" ]]; then
    status="pass"
    final_rc=0
    if [[ -z "$next_operator_action" ]]; then
      next_operator_action="Stability cycle passes policy gates. Promotion checks may proceed."
    fi
  elif [[ "$check_decision" == "NO-GO" ]]; then
    primary_code="$check_primary_violation_code"
    primary_message="$check_primary_violation_message"
    primary_action="$check_primary_violation_action"
    if [[ -z "$primary_code" ]]; then
      primary_code="check_decision_no_go"
    fi
    if [[ -z "$primary_message" ]]; then
      primary_message="stability check decision is NO-GO"
    fi
    if [[ -z "$primary_action" ]]; then
      primary_action="Hold promotion, remediate policy violations, and rerun profile_compare_multi_vm_stability_cycle.sh."
    fi
    if [[ "$fail_on_no_go" == "1" ]]; then
      status="fail"
      final_rc=1
      set_primary_failure \
        "$primary_code" \
        "check" \
        "$primary_message" \
        "$primary_action" \
        "$check_command_display" \
        "policy"
    else
      status="warn"
      final_rc=0
      set_primary_failure \
        "$primary_code" \
        "" \
        "$primary_message" \
        "$primary_action" \
        "$check_command_display" \
        "policy"
    fi
  else
    decision="NO-GO"
    status="fail"
    final_rc=1
    set_primary_failure \
      "check_decision_unusable" \
      "check" \
      "stability check summary is missing a usable decision" \
      "Regenerate check summary with a GO/NO-GO decision and rerun profile_compare_multi_vm_stability_cycle.sh." \
      "$check_command_display" \
      "artifact_contract"
  fi
fi

runs_json="null"
sleep_between_sec_json="null"
allow_partial_json="null"
if [[ -n "$runs" ]]; then
  runs_json="$runs"
fi
if [[ -n "$sleep_between_sec" ]]; then
  sleep_between_sec_json="$sleep_between_sec"
fi
if [[ -n "$allow_partial" ]]; then
  allow_partial_json="$allow_partial"
fi

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
  --arg reports_dir "$reports_dir" \
  --arg run_stage_status "$run_stage_status" \
  --arg run_stage_failure_hint "$run_stage_failure_hint" \
  --argjson run_stage_failure_hints "$run_stage_failure_hints_json" \
  --arg check_stage_attempted "$check_stage_attempted" \
  --arg check_stage_status "$check_stage_status" \
  --arg failure_stage "$failure_stage" \
  --arg failure_reason "$failure_reason" \
  --arg failure_reason_code "$failure_reason_code" \
  --arg failure_category "$failure_category" \
  --arg next_operator_action "$next_operator_action" \
  --arg next_operator_action_command "$next_operator_action_command" \
  --arg run_summary_exists "$run_summary_exists" \
  --arg run_summary_valid "$run_summary_valid" \
  --arg run_summary_schema_id "$run_summary_schema_id" \
  --arg run_summary_schema_valid "$run_summary_schema_valid" \
  --arg run_summary_fresh "$run_summary_fresh" \
  --arg check_summary_exists "$check_summary_exists" \
  --arg check_summary_valid "$check_summary_valid" \
  --arg check_summary_schema_id "$check_summary_schema_id" \
  --arg check_summary_schema_valid "$check_summary_schema_valid" \
  --arg check_summary_fresh "$check_summary_fresh" \
  --arg check_decision "$check_decision" \
  --arg check_status "$check_status" \
  --arg check_modal_recommended_profile "$check_modal_recommended_profile" \
  --arg check_primary_violation_code "$check_primary_violation_code" \
  --arg check_primary_violation_message "$check_primary_violation_message" \
  --arg check_primary_violation_action "$check_primary_violation_action" \
  --argjson rc "$final_rc" \
  --argjson run_stage_rc "$run_stage_rc" \
  --argjson check_stage_rc "$check_stage_rc_json" \
  --argjson check_rc "$check_rc_json" \
  --argjson check_modal_support_rate_pct "$check_modal_support_rate_pct_json" \
  --argjson check_errors "$check_errors_json" \
  --argjson failure_reasons "$failure_reasons_json" \
  --argjson runs "$runs_json" \
  --argjson sleep_between_sec "$sleep_between_sec_json" \
  --argjson allow_partial "$allow_partial_json" \
  --argjson require_status_pass "$require_status_pass" \
  --argjson require_min_runs_requested "$require_min_runs_requested" \
  --argjson require_min_runs_completed "$require_min_runs_completed" \
  --argjson require_max_runs_fail "$require_max_runs_fail" \
  --argjson require_decision_consensus "$require_decision_consensus" \
  --arg require_modal_decision "$require_modal_decision" \
  --argjson require_modal_decision_support_rate_pct "$require_modal_decision_support_rate_pct" \
  --arg require_recommended_profile "$require_recommended_profile" \
  --arg allow_recommended_profiles "$allow_recommended_profiles" \
  --argjson require_modal_support_rate_pct "$require_modal_support_rate_pct" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  '{
    version: 1,
    schema: {
      id: "profile_compare_multi_vm_stability_cycle_summary"
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    decision: (if $decision == "" then null else $decision end),
    failure_stage: (if $failure_stage == "" then null else $failure_stage end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    failure_reason_code: (if $failure_reason_code == "" then null else $failure_reason_code end),
    failure_category: (if $failure_category == "" then null else $failure_category end),
    failure_reasons: $failure_reasons,
    operator_next_action: (
      if $next_operator_action == "" then null
      else $next_operator_action
      end
    ),
    operator_next_action_command: (
      if $next_operator_action_command == "" then null
      else $next_operator_action_command
      end
    ),
    inputs: {
      reports_dir: $reports_dir,
      run: {
        runs: (if $runs == null then null else $runs end),
        sleep_between_sec: (if $sleep_between_sec == null then null else $sleep_between_sec end),
        allow_partial: (
          if $allow_partial == null then null
          else ($allow_partial == 1)
          end
        )
      },
      check: {
        policy_profile: "strict-defaults",
        policy: {
          require_status_pass: ($require_status_pass == 1),
          require_min_runs_requested: $require_min_runs_requested,
          require_min_runs_completed: $require_min_runs_completed,
          require_max_runs_fail: $require_max_runs_fail,
          require_decision_consensus: ($require_decision_consensus == 1),
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
        summary_json: $run_summary_json
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
    run: {
      summary_exists: ($run_summary_exists == "true"),
      summary_valid_json: ($run_summary_valid == "true"),
      summary_schema_id: (if $run_summary_schema_id == "" then null else $run_summary_schema_id end),
      summary_schema_valid: ($run_summary_schema_valid == "true"),
      summary_fresh: ($run_summary_fresh == "true"),
      failure_hint: (
        if $run_stage_failure_hint == "" then null
        else $run_stage_failure_hint
        end
      ),
      failure_hints: $run_stage_failure_hints
    },
    check: {
      summary_exists: ($check_summary_exists == "true"),
      summary_valid_json: ($check_summary_valid == "true"),
      summary_schema_id: (if $check_summary_schema_id == "" then null else $check_summary_schema_id end),
      summary_schema_valid: ($check_summary_schema_valid == "true"),
      summary_fresh: ($check_summary_fresh == "true"),
      decision: (if $check_decision == "" then null else $check_decision end),
      status: (if $check_status == "" then null else $check_status end),
      rc: $check_rc,
      modal_recommended_profile: (
        if $check_modal_recommended_profile == "" then null
        else $check_modal_recommended_profile
        end
      ),
      modal_support_rate_pct: $check_modal_support_rate_pct,
      errors: $check_errors
      ,
      primary_violation: (
        if $check_primary_violation_code == "" and $check_primary_violation_message == "" and $check_primary_violation_action == "" then null
        else {
          code: (if $check_primary_violation_code == "" then null else $check_primary_violation_code end),
          message: (if $check_primary_violation_message == "" then null else $check_primary_violation_message end),
          action: (if $check_primary_violation_action == "" then null else $check_primary_violation_action end)
        }
        end
      )
    },
    outcome: {
      gate_pass: ($status == "pass" and $decision == "GO" and $rc == 0),
      action: (
        if $status == "pass" and $decision == "GO" and $rc == 0 then "cycle_gate_pass"
        elif $status == "warn" then "cycle_gate_warn_only"
        else "cycle_gate_blocked"
        end
      ),
      next_operator_action: (
        if $next_operator_action == "" then null
        else $next_operator_action
        end
      )
    },
    artifacts: {
      summary_json: $summary_json_path,
      run_summary_json: $run_summary_json,
      check_summary_json: $check_summary_json,
      run_log: $run_log,
      check_log: $check_log
    }
  }' >"$summary_json"

echo "[profile-compare-multi-vm-stability-cycle] status=$status rc=$final_rc decision=${decision:-unset} summary_json=$summary_json"
if [[ -n "$failure_stage" ]]; then
  echo "[profile-compare-multi-vm-stability-cycle] failure_stage=$failure_stage failure_reason=${failure_reason:-}"
fi
if [[ "$show_json" == "1" ]]; then
  echo "[profile-compare-multi-vm-stability-cycle] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
