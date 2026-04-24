#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CYCLE_SCRIPT="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_STAGE_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_cycle.sh}"
PROMOTION_CHECK_SCRIPT="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_STAGE_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_promotion_check.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_multi_vm_stability_promotion_cycle.sh \
    [--reports-dir DIR] \
    [--cycles N] \
    [--sleep-between-sec N] \
    [--cycle-timeout-sec N] \
    [--cycle-summary-list PATH] \
    [--promotion-summary-json PATH] \
    [--require-min-cycles N] \
    [--require-min-pass-cycles N] \
    [--require-max-fail-cycles N] \
    [--require-max-warn-cycles N] \
    [--require-min-pass-rate-pct N] \
    [--require-min-go-decision-rate-pct N] \
    [--require-cycle-schema-valid [0|1]] \
    [--require-check-modal-decision GO|NO-GO] \
    [--require-check-policy-modal-decision GO|NO-GO] \
    [--fail-on-no-go [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]] \
    [--cycle-arg ARG]...

Purpose:
  Run profile_compare_multi_vm_stability_cycle.sh repeatedly, capture each
  cycle summary path into a deterministic list file, then run
  profile_compare_multi_vm_stability_promotion_check.sh over that list.

Notes:
  - Fail-closed defaults:
    require_min_cycles = cycles
    require_min_pass_cycles = cycles
    require_max_fail_cycles = 0
    require_max_warn_cycles = 0
    require_min_pass_rate_pct = 100
    require_min_go_decision_rate_pct = 100
    require_cycle_schema_valid = 1
    require_check_policy_modal_decision = GO
    fail_on_no_go = 1
  - Stage scripts can be overridden with:
    PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_STAGE_SCRIPT
    PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_STAGE_SCRIPT
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

normalize_status() {
  local status
  status="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$status" in
    pass|ok|success) printf '%s\n' "pass" ;;
    warn|warning) printf '%s\n' "warn" ;;
    fail|failed|error) printf '%s\n' "fail" ;;
    *) printf '%s\n' "$status" ;;
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

append_failure_reason() {
  local code="$1"
  local stage="$2"
  local reason="$3"
  local action="$4"
  local action_command="$5"
  local category="${6:-contract}"
  local entry
  entry="$(jq -n \
    --arg code "$code" \
    --arg stage "$stage" \
    --arg reason "$reason" \
    --arg action "$action" \
    --arg action_command "$action_command" \
    --arg category "$category" \
    '{
      code: $code,
      stage: (if $stage == "" then null else $stage end),
      category: (if $category == "" then null else $category end),
      reason: $reason,
      action: $action,
      action_command: (if $action_command == "" then null else $action_command end)
    }')"
  failure_reasons_json="$(jq -c --argjson entry "$entry" '. + [$entry]' <<<"$failure_reasons_json")"
}

set_promotion_failure() {
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
  failure_reasons_json='[]'
  append_failure_reason "$code" "$stage" "$reason" "$action" "$next_operator_action_command" "$category"
}

need_cmd jq
need_cmd date
need_cmd bash
need_cmd mkdir
need_cmd cksum
need_cmd sleep
need_cmd wc

reports_dir="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
cycles="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_CYCLES:-3}"
sleep_between_sec="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SLEEP_BETWEEN_SEC:-5}"
cycle_timeout_sec="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_TIMEOUT_SEC:-0}"

cycle_summary_list="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SUMMARY_LIST:-}"
promotion_summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_PROMOTION_SUMMARY_JSON:-}"
summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SUMMARY_JSON:-}"

require_min_cycles="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_MIN_CYCLES:-}"
require_min_pass_cycles="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_MIN_PASS_CYCLES:-}"
require_max_fail_cycles="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_MAX_FAIL_CYCLES:-0}"
require_max_warn_cycles="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_MAX_WARN_CYCLES:-0}"
require_min_pass_rate_pct="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_MIN_PASS_RATE_PCT:-100}"
require_min_go_decision_rate_pct="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_MIN_GO_DECISION_RATE_PCT:-100}"
require_cycle_schema_valid="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_CYCLE_SCHEMA_VALID:-1}"
require_check_policy_modal_decision="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_CHECK_POLICY_MODAL_DECISION:-GO}"
fail_on_no_go="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_FAIL_ON_NO_GO:-1}"

show_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SHOW_JSON:-0}"
print_summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_PRINT_SUMMARY_JSON:-0}"

declare -a cycle_args=()

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
    --cycles)
      require_value_or_die "$1" "$#"
      cycles="${2:-}"
      shift 2
      ;;
    --cycles=*)
      cycles="${1#*=}"
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
    --cycle-timeout-sec)
      require_value_or_die "$1" "$#"
      cycle_timeout_sec="${2:-}"
      shift 2
      ;;
    --cycle-timeout-sec=*)
      cycle_timeout_sec="${1#*=}"
      shift
      ;;
    --cycle-summary-list)
      require_value_or_die "$1" "$#"
      cycle_summary_list="${2:-}"
      shift 2
      ;;
    --cycle-summary-list=*)
      cycle_summary_list="${1#*=}"
      shift
      ;;
    --promotion-summary-json)
      require_value_or_die "$1" "$#"
      promotion_summary_json="${2:-}"
      shift 2
      ;;
    --promotion-summary-json=*)
      promotion_summary_json="${1#*=}"
      shift
      ;;
    --require-min-cycles)
      require_value_or_die "$1" "$#"
      require_min_cycles="${2:-}"
      shift 2
      ;;
    --require-min-cycles=*)
      require_min_cycles="${1#*=}"
      shift
      ;;
    --require-min-pass-cycles)
      require_value_or_die "$1" "$#"
      require_min_pass_cycles="${2:-}"
      shift 2
      ;;
    --require-min-pass-cycles=*)
      require_min_pass_cycles="${1#*=}"
      shift
      ;;
    --require-max-fail-cycles)
      require_value_or_die "$1" "$#"
      require_max_fail_cycles="${2:-}"
      shift 2
      ;;
    --require-max-fail-cycles=*)
      require_max_fail_cycles="${1#*=}"
      shift
      ;;
    --require-max-warn-cycles)
      require_value_or_die "$1" "$#"
      require_max_warn_cycles="${2:-}"
      shift 2
      ;;
    --require-max-warn-cycles=*)
      require_max_warn_cycles="${1#*=}"
      shift
      ;;
    --require-min-pass-rate-pct)
      require_value_or_die "$1" "$#"
      require_min_pass_rate_pct="${2:-}"
      shift 2
      ;;
    --require-min-pass-rate-pct=*)
      require_min_pass_rate_pct="${1#*=}"
      shift
      ;;
    --require-min-go-decision-rate-pct)
      require_value_or_die "$1" "$#"
      require_min_go_decision_rate_pct="${2:-}"
      shift 2
      ;;
    --require-min-go-decision-rate-pct=*)
      require_min_go_decision_rate_pct="${1#*=}"
      shift
      ;;
    --require-cycle-schema-valid)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_cycle_schema_valid="${2:-}"
        shift 2
      else
        require_cycle_schema_valid="1"
        shift
      fi
      ;;
    --require-cycle-schema-valid=*)
      require_cycle_schema_valid="${1#*=}"
      shift
      ;;
    --require-check-modal-decision)
      require_value_or_die "$1" "$#"
      require_check_policy_modal_decision="${2:-}"
      shift 2
      ;;
    --require-check-modal-decision=*)
      require_check_policy_modal_decision="${1#*=}"
      shift
      ;;
    --require-check-policy-modal-decision)
      require_value_or_die "$1" "$#"
      require_check_policy_modal_decision="${2:-}"
      shift 2
      ;;
    --require-check-policy-modal-decision=*)
      require_check_policy_modal_decision="${1#*=}"
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
    --cycle-arg)
      require_value_or_die "$1" "$#"
      cycle_args+=("${2:-}")
      shift 2
      ;;
    --cycle-arg=*)
      cycle_args+=("${1#*=}")
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
cycles="$(trim "$cycles")"
sleep_between_sec="$(trim "$sleep_between_sec")"
cycle_timeout_sec="$(trim "$cycle_timeout_sec")"
cycle_summary_list="$(abs_path "$cycle_summary_list")"
promotion_summary_json="$(abs_path "$promotion_summary_json")"
summary_json="$(abs_path "$summary_json")"
require_min_cycles="$(trim "$require_min_cycles")"
require_min_pass_cycles="$(trim "$require_min_pass_cycles")"
require_max_fail_cycles="$(trim "$require_max_fail_cycles")"
require_max_warn_cycles="$(trim "$require_max_warn_cycles")"
require_min_pass_rate_pct="$(trim "$require_min_pass_rate_pct")"
require_min_go_decision_rate_pct="$(trim "$require_min_go_decision_rate_pct")"
require_cycle_schema_valid="$(trim "$require_cycle_schema_valid")"
require_check_policy_modal_decision="$(trim "$require_check_policy_modal_decision")"
fail_on_no_go="$(trim "$fail_on_no_go")"
show_json="$(trim "$show_json")"
print_summary_json="$(trim "$print_summary_json")"
CYCLE_SCRIPT="$(abs_path "$CYCLE_SCRIPT")"
PROMOTION_CHECK_SCRIPT="$(abs_path "$PROMOTION_CHECK_SCRIPT")"

int_arg_or_die "--cycles" "$cycles"
int_arg_or_die "--sleep-between-sec" "$sleep_between_sec"
int_arg_or_die "--cycle-timeout-sec" "$cycle_timeout_sec"
bool_arg_or_die "--require-cycle-schema-valid" "$require_cycle_schema_valid"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

if ! is_non_negative_decimal "$require_min_pass_rate_pct"; then
  echo "--require-min-pass-rate-pct must be a non-negative number"
  exit 2
fi
if ! is_non_negative_decimal "$require_min_go_decision_rate_pct"; then
  echo "--require-min-go-decision-rate-pct must be a non-negative number"
  exit 2
fi

if (( cycles < 1 )); then
  echo "--cycles must be >= 1"
  exit 2
fi

if [[ -z "$require_min_cycles" ]]; then
  require_min_cycles="$cycles"
fi
if [[ -z "$require_min_pass_cycles" ]]; then
  require_min_pass_cycles="$cycles"
fi
int_arg_or_die "--require-min-cycles" "$require_min_cycles"
int_arg_or_die "--require-min-pass-cycles" "$require_min_pass_cycles"
int_arg_or_die "--require-max-fail-cycles" "$require_max_fail_cycles"
int_arg_or_die "--require-max-warn-cycles" "$require_max_warn_cycles"

if (( require_min_cycles < 1 )); then
  echo "--require-min-cycles must be >= 1"
  exit 2
fi
if (( require_min_pass_cycles < 1 )); then
  echo "--require-min-pass-cycles must be >= 1"
  exit 2
fi
if (( require_min_cycles > cycles )); then
  echo "--require-min-cycles must be <= --cycles"
  exit 2
fi
if (( require_min_pass_cycles > cycles )); then
  echo "--require-min-pass-cycles must be <= --cycles"
  exit 2
fi

if [[ -z "$require_check_policy_modal_decision" ]]; then
  require_check_policy_modal_decision="GO"
fi
require_check_policy_modal_decision="$(normalize_decision "$require_check_policy_modal_decision")"
if [[ "$require_check_policy_modal_decision" != "GO" && "$require_check_policy_modal_decision" != "NO-GO" ]]; then
  echo "--require-check-modal-decision must be GO or NO-GO"
  exit 2
fi

if [[ ! -f "$CYCLE_SCRIPT" ]]; then
  echo "stability cycle script not found: $CYCLE_SCRIPT"
  exit 2
fi
if [[ ! -f "$PROMOTION_CHECK_SCRIPT" ]]; then
  echo "stability promotion check script not found: $PROMOTION_CHECK_SCRIPT"
  exit 2
fi
if (( cycle_timeout_sec > 0 )) && ! command -v timeout >/dev/null 2>&1; then
  echo "cycle timeout requested but missing required command: timeout"
  exit 2
fi

mkdir -p "$reports_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"
archive_root="$reports_dir/profile_compare_multi_vm_stability_promotion_cycle_${run_stamp}"
mkdir -p "$archive_root"

if [[ -z "$cycle_summary_list" ]]; then
  cycle_summary_list="$archive_root/profile_compare_multi_vm_stability_promotion_cycle_summary_paths.list"
fi
if [[ -z "$promotion_summary_json" ]]; then
  promotion_summary_json="$archive_root/profile_compare_multi_vm_stability_promotion_check_summary.json"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$archive_root/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
fi
mkdir -p "$(dirname "$cycle_summary_list")" "$(dirname "$promotion_summary_json")" "$(dirname "$summary_json")"

: >"$cycle_summary_list"

cycle_counts_requested="$cycles"
cycle_counts_completed=0
cycle_counts_pass=0
cycle_counts_warn=0
cycle_counts_fail=0
cycle_command_failures=0
cycle_summary_missing_count=0
cycle_summary_invalid_count=0
cycle_summary_stale_count=0

cycles_json='[]'

echo "[profile-compare-multi-vm-stability-promotion-cycle] $(timestamp_utc) start cycles=$cycles sleep_between_sec=$sleep_between_sec reports_dir=$reports_dir"

cycle_index=0
while (( cycle_index < cycles )); do
  cycle_index=$((cycle_index + 1))
  cycle_id="$(printf 'cycle_%03d' "$cycle_index")"
  cycle_dir="$archive_root/$cycle_id"
  mkdir -p "$cycle_dir"

  cycle_summary_json="$cycle_dir/profile_compare_multi_vm_stability_cycle_summary.json"
  cycle_log="$cycle_dir/profile_compare_multi_vm_stability_cycle.log"
  printf '%s\n' "$cycle_summary_json" >>"$cycle_summary_list"

  cycle_cmd=(bash "$CYCLE_SCRIPT" --reports-dir "$cycle_dir" --summary-json "$cycle_summary_json" --show-json 0 --print-summary-json 0)
  if (( ${#cycle_args[@]} > 0 )); then
    cycle_cmd+=("${cycle_args[@]}")
  fi
  cycle_command_display="$(quote_cmd "${cycle_cmd[@]}")"

  cycle_started_at="$(timestamp_utc)"
  pre_cycle_summary_fingerprint="$(file_fingerprint_01 "$cycle_summary_json")"

  echo "[profile-compare-multi-vm-stability-promotion-cycle] $(timestamp_utc) cycle-start cycle_id=$cycle_id cycle_summary_json=$cycle_summary_json"
  set +e
  if (( cycle_timeout_sec > 0 )); then
    timeout "${cycle_timeout_sec}s" "${cycle_cmd[@]}" >"$cycle_log" 2>&1
  else
    "${cycle_cmd[@]}" >"$cycle_log" 2>&1
  fi
  cycle_command_rc=$?
  set -e
  cycle_completed_at="$(timestamp_utc)"

  cycle_summary_exists="false"
  cycle_summary_valid="false"
  cycle_summary_fresh="false"
  cycle_summary_status=""
  cycle_summary_decision=""
  cycle_summary_rc_json="null"
  cycle_summary_failure_reason=""

  if [[ -f "$cycle_summary_json" ]]; then
    cycle_summary_exists="true"
  fi
  if [[ "$(json_file_valid_01 "$cycle_summary_json")" == "1" ]]; then
    cycle_summary_valid="true"
    post_cycle_summary_fingerprint="$(file_fingerprint_01 "$cycle_summary_json")"
    if [[ -z "$pre_cycle_summary_fingerprint" && -n "$post_cycle_summary_fingerprint" ]]; then
      cycle_summary_fresh="true"
    elif [[ -n "$post_cycle_summary_fingerprint" && "$post_cycle_summary_fingerprint" != "$pre_cycle_summary_fingerprint" ]]; then
      cycle_summary_fresh="true"
    fi
    cycle_summary_status="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$cycle_summary_json" 2>/dev/null || printf '%s' "")"
    cycle_summary_status="$(normalize_status "$cycle_summary_status")"
    cycle_summary_decision="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$cycle_summary_json" 2>/dev/null || printf '%s' "")"
    cycle_summary_decision="$(normalize_decision "$cycle_summary_decision")"
    cycle_summary_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else "null" end' "$cycle_summary_json" 2>/dev/null || printf '%s' "null")"
    cycle_summary_failure_reason="$(jq -r 'if (.failure_reason | type) == "string" then .failure_reason else "" end' "$cycle_summary_json" 2>/dev/null || printf '%s' "")"
  fi

  cycle_result_status="fail"
  cycle_result_reason=""
  cycle_result_reason_code=""
  cycle_result_action=""
  if [[ "$cycle_command_rc" -ne 0 ]]; then
    cycle_result_status="fail"
    cycle_result_reason="cycle command failed (rc=$cycle_command_rc)"
    cycle_result_reason_code="cycle_command_failed"
    cycle_result_action="Inspect cycle command log and rerun the cycle."
    cycle_command_failures=$((cycle_command_failures + 1))
  elif [[ "$cycle_summary_exists" != "true" ]]; then
    cycle_result_status="fail"
    cycle_result_reason="cycle summary is missing"
    cycle_result_reason_code="cycle_summary_missing"
    cycle_result_action="Ensure cycle stage writes summary artifacts and rerun the cycle."
    cycle_summary_missing_count=$((cycle_summary_missing_count + 1))
  elif [[ "$cycle_summary_valid" != "true" ]]; then
    cycle_result_status="fail"
    cycle_result_reason="cycle summary is invalid JSON"
    cycle_result_reason_code="cycle_summary_invalid_json"
    cycle_result_action="Regenerate cycle summary JSON and rerun the cycle."
    cycle_summary_invalid_count=$((cycle_summary_invalid_count + 1))
  elif [[ "$cycle_summary_fresh" != "true" ]]; then
    cycle_result_status="fail"
    cycle_result_reason="cycle summary is stale"
    cycle_result_reason_code="cycle_summary_stale"
    cycle_result_action="Refresh stale cycle summary evidence and rerun the cycle."
    cycle_summary_stale_count=$((cycle_summary_stale_count + 1))
  else
    cycle_counts_completed=$((cycle_counts_completed + 1))
    if [[ "$cycle_summary_status" == "pass" && "$cycle_summary_decision" == "GO" && "$cycle_summary_rc_json" == "0" ]]; then
      cycle_result_status="pass"
      cycle_result_reason_code="cycle_pass"
      cycle_result_action="No action required."
    elif [[ "$cycle_summary_status" == "warn" && "$cycle_summary_rc_json" == "0" ]]; then
      cycle_result_status="warn"
      cycle_result_reason_code="cycle_warn"
      cycle_result_action="Review warning diagnostics before promotion."
    elif [[ "$cycle_summary_status" == "fail" ]]; then
      cycle_result_status="fail"
      cycle_result_reason_code="cycle_policy_fail"
      cycle_result_action="Inspect cycle summary failure details and remediate before rerun."
    else
      cycle_result_status="fail"
      cycle_result_reason="cycle summary status/decision contract is invalid"
      cycle_result_reason_code="cycle_summary_contract_invalid"
      cycle_result_action="Fix cycle summary contract fields (status/decision/rc) and rerun."
    fi
  fi

  if [[ -z "$cycle_result_reason" && -n "$cycle_summary_failure_reason" ]]; then
    cycle_result_reason="$cycle_summary_failure_reason"
  fi
  if [[ -z "$cycle_result_reason_code" && "$cycle_result_status" == "fail" ]]; then
    cycle_result_reason_code="cycle_failed"
  fi
  if [[ -z "$cycle_result_action" ]]; then
    cycle_result_action="Inspect cycle artifacts and rerun."
  fi
  if [[ -z "$cycle_result_reason" ]]; then
    case "$cycle_result_status" in
      pass) cycle_result_reason="cycle passed" ;;
      warn) cycle_result_reason="cycle completed with warn status" ;;
      fail) cycle_result_reason="cycle failed policy gates" ;;
      *) cycle_result_reason="cycle status unavailable" ;;
    esac
  fi

  case "$cycle_result_status" in
    pass) cycle_counts_pass=$((cycle_counts_pass + 1)) ;;
    warn) cycle_counts_warn=$((cycle_counts_warn + 1)) ;;
    *) cycle_counts_fail=$((cycle_counts_fail + 1)) ;;
  esac

  cycle_row_json="$(jq -n \
    --arg cycle_id "$cycle_id" \
    --arg cycle_dir "$cycle_dir" \
    --arg cycle_summary_json "$cycle_summary_json" \
    --arg cycle_log "$cycle_log" \
    --arg command "$cycle_command_display" \
    --arg started_at "$cycle_started_at" \
    --arg completed_at "$cycle_completed_at" \
    --arg status "$cycle_result_status" \
    --arg reason "$cycle_result_reason" \
    --arg reason_code "$cycle_result_reason_code" \
    --arg next_action "$cycle_result_action" \
    --arg summary_exists "$cycle_summary_exists" \
    --arg summary_valid_json "$cycle_summary_valid" \
    --arg summary_fresh "$cycle_summary_fresh" \
    --arg observed_status "$cycle_summary_status" \
    --arg observed_decision "$cycle_summary_decision" \
    --argjson cycle_index "$cycle_index" \
    --argjson command_rc "$cycle_command_rc" \
    --argjson observed_rc "$cycle_summary_rc_json" \
    '{
      cycle_index: $cycle_index,
      cycle_id: $cycle_id,
      status: $status,
      reason: $reason,
      reason_code: (if $reason_code == "" then null else $reason_code end),
      next_operator_action: $next_action,
      command: $command,
      command_rc: $command_rc,
      started_at_utc: $started_at,
      completed_at_utc: $completed_at,
      summary_exists: ($summary_exists == "true"),
      summary_valid_json: ($summary_valid_json == "true"),
      summary_fresh: ($summary_fresh == "true"),
      observed_status: (if $observed_status == "" then null else $observed_status end),
      observed_decision: (if $observed_decision == "" then null else $observed_decision end),
      observed_rc: $observed_rc,
      artifacts: {
        cycle_dir: $cycle_dir,
        summary_json: $cycle_summary_json,
        log: $cycle_log
      }
    }')"
  cycles_json="$(jq -c --argjson row "$cycle_row_json" '. + [$row]' <<<"$cycles_json")"

  echo "[profile-compare-multi-vm-stability-promotion-cycle] $(timestamp_utc) cycle-end cycle_id=$cycle_id status=$cycle_result_status command_rc=$cycle_command_rc summary_json=$cycle_summary_json"

  if (( cycle_index < cycles )) && (( sleep_between_sec > 0 )); then
    sleep "$sleep_between_sec"
  fi
done

promotion_log="$archive_root/profile_compare_multi_vm_stability_promotion_check.log"
promotion_cmd=(
  bash "$PROMOTION_CHECK_SCRIPT"
  --cycle-summary-list "$cycle_summary_list"
  --reports-dir "$reports_dir"
  --require-min-cycles "$require_min_cycles"
  --require-min-pass-cycles "$require_min_pass_cycles"
  --require-max-fail-cycles "$require_max_fail_cycles"
  --require-max-warn-cycles "$require_max_warn_cycles"
  --require-min-pass-rate-pct "$require_min_pass_rate_pct"
  --require-min-go-decision-rate-pct "$require_min_go_decision_rate_pct"
  --require-cycle-schema-valid "$require_cycle_schema_valid"
  --require-check-policy-modal-decision "$require_check_policy_modal_decision"
  --fail-on-no-go "$fail_on_no_go"
  --summary-json "$promotion_summary_json"
  --show-json 0
  --print-summary-json 0
)
promotion_command_display="$(quote_cmd "${promotion_cmd[@]}")"

promotion_stage_attempted="true"
promotion_stage_status="fail"
promotion_stage_started_at="$(timestamp_utc)"
pre_promotion_summary_fingerprint="$(file_fingerprint_01 "$promotion_summary_json")"

echo "[profile-compare-multi-vm-stability-promotion-cycle] $(timestamp_utc) promotion-check start cycle_summary_list=$cycle_summary_list"
set +e
"${promotion_cmd[@]}" >"$promotion_log" 2>&1
promotion_stage_rc=$?
set -e
promotion_stage_completed_at="$(timestamp_utc)"

promotion_summary_exists="false"
promotion_summary_valid="false"
promotion_summary_fresh="false"
promotion_decision=""
promotion_status=""
promotion_rc_json="null"
promotion_violations_count=0
promotion_operator_next_action=""
promotion_contract_ok="false"
promotion_primary_violation_code=""
promotion_primary_violation_message=""
promotion_primary_violation_action=""

if [[ -f "$promotion_summary_json" ]]; then
  promotion_summary_exists="true"
fi
if [[ "$(json_file_valid_01 "$promotion_summary_json")" == "1" ]]; then
  promotion_summary_valid="true"
  post_promotion_summary_fingerprint="$(file_fingerprint_01 "$promotion_summary_json")"
  if [[ -z "$pre_promotion_summary_fingerprint" && -n "$post_promotion_summary_fingerprint" ]]; then
    promotion_summary_fresh="true"
  elif [[ -n "$post_promotion_summary_fingerprint" && "$post_promotion_summary_fingerprint" != "$pre_promotion_summary_fingerprint" ]]; then
    promotion_summary_fresh="true"
  fi
  promotion_decision="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_decision="$(normalize_decision "$promotion_decision")"
  promotion_status="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_status="$(normalize_status "$promotion_status")"
  promotion_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else "null" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "null")"
  promotion_violations_count="$(jq -r 'if (.violations | type) == "array" then (.violations | length) else 0 end' "$promotion_summary_json" 2>/dev/null || printf '0')"
  promotion_operator_next_action="$(jq -r '
    if (.operator_next_action | type) == "string" and (.operator_next_action | length) > 0 then .operator_next_action
    elif (.outcome.next_operator_action | type) == "string" and (.outcome.next_operator_action | length) > 0 then .outcome.next_operator_action
    else ""
    end
  ' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_primary_violation_code="$(jq -r '
    if (.violations | type) == "array"
      and (.violations | length) > 0
      and (.violations[0].code | type) == "string"
    then .violations[0].code
    else ""
    end
  ' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_primary_violation_message="$(jq -r '
    if (.violations | type) == "array"
      and (.violations | length) > 0
      and (.violations[0].message | type) == "string"
    then .violations[0].message
    else ""
    end
  ' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_primary_violation_action="$(jq -r '
    if (.violations | type) == "array"
      and (.violations | length) > 0
      and (.violations[0].action | type) == "string"
    then .violations[0].action
    else ""
    end
  ' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
fi

if [[ "$promotion_stage_rc" -ne 0 ]]; then
  promotion_stage_status="fail"
elif [[ "$promotion_summary_valid" != "true" || "$promotion_summary_fresh" != "true" ]]; then
  promotion_stage_status="fail"
elif [[ "$promotion_decision" == "GO" && "$promotion_status" == "pass" && "$promotion_rc_json" == "0" ]]; then
  promotion_stage_status="pass"
elif [[ "$promotion_decision" == "NO-GO" ]]; then
  if [[ "$fail_on_no_go" == "1" ]]; then
    promotion_stage_status="fail"
  else
    promotion_stage_status="warn"
  fi
else
  promotion_stage_status="fail"
fi

if [[ "$promotion_stage_rc" -eq 0 && "$promotion_summary_valid" == "true" && "$promotion_summary_fresh" == "true" && ( "$promotion_decision" == "GO" || "$promotion_decision" == "NO-GO" ) ]]; then
  promotion_contract_ok="true"
fi

failure_stage=""
failure_reason=""
failure_reason_code=""
failure_category=""
failure_reasons_json="[]"
next_operator_action=""
next_operator_action_command=""
final_decision="NO-GO"
final_status="fail"
final_rc=1

cycles_collection_failure_reason=""
if (( cycle_command_failures > 0 || cycle_summary_missing_count > 0 || cycle_summary_invalid_count > 0 || cycle_summary_stale_count > 0 )); then
  cycles_collection_failure_reason="one or more cycle runs failed to execute or produce fresh valid summary artifacts"
fi

if [[ "$promotion_stage_rc" -ne 0 ]]; then
  set_promotion_failure \
    "promotion_check_command_failed" \
    "promotion_check" \
    "promotion check command failed (rc=$promotion_stage_rc)" \
    "Inspect promotion-check logs and rerun profile_compare_multi_vm_stability_promotion_cycle.sh." \
    "$promotion_command_display" \
    "execution"
  final_decision="NO-GO"
  final_status="fail"
  final_rc="$promotion_stage_rc"
  if [[ "$final_rc" -eq 0 ]]; then
    final_rc=1
  fi
elif [[ "$promotion_summary_valid" != "true" ]]; then
  set_promotion_failure \
    "promotion_check_summary_missing_or_invalid" \
    "promotion_check" \
    "promotion check summary is missing or invalid" \
    "Regenerate promotion-check summary artifacts and rerun profile_compare_multi_vm_stability_promotion_cycle.sh." \
    "$promotion_command_display" \
    "artifact_contract"
  final_decision="NO-GO"
  final_status="fail"
  final_rc=1
elif [[ "$promotion_summary_fresh" != "true" ]]; then
  set_promotion_failure \
    "promotion_check_summary_stale" \
    "promotion_check" \
    "promotion check summary is stale (not refreshed by current run)" \
    "Refresh promotion-check evidence and rerun profile_compare_multi_vm_stability_promotion_cycle.sh." \
    "$promotion_command_display" \
    "artifact_freshness"
  final_decision="NO-GO"
  final_status="fail"
  final_rc=1
elif [[ -n "$cycles_collection_failure_reason" ]]; then
  set_promotion_failure \
    "cycles_collection_incomplete" \
    "cycles" \
    "$cycles_collection_failure_reason" \
    "Inspect failed cycle logs/artifacts and rerun profile_compare_multi_vm_stability_promotion_cycle.sh." \
    "$cycle_summary_list" \
    "artifact_contract"
  final_decision="NO-GO"
  final_status="fail"
  final_rc=1
elif [[ "$promotion_decision" == "GO" && "$promotion_status" == "pass" && "$promotion_rc_json" == "0" ]]; then
  final_decision="GO"
  final_status="pass"
  final_rc=0
  if [[ -z "$next_operator_action" ]]; then
    next_operator_action="Promotion may proceed."
  fi
elif [[ "$promotion_decision" == "NO-GO" ]]; then
  final_decision="NO-GO"
  primary_code="$promotion_primary_violation_code"
  primary_message="$promotion_primary_violation_message"
  primary_action="$promotion_primary_violation_action"
  if [[ -z "$primary_code" ]]; then
    primary_code="promotion_decision_no_go"
  fi
  if [[ -z "$primary_message" ]]; then
    primary_message="promotion decision is NO-GO"
  fi
  if [[ -z "$primary_action" ]]; then
    primary_action="Hold promotion, resolve promotion-check violations, and rerun profile_compare_multi_vm_stability_promotion_cycle.sh."
  fi
  if [[ "$fail_on_no_go" == "1" ]]; then
    set_promotion_failure \
      "$primary_code" \
      "promotion_check" \
      "$primary_message" \
      "$primary_action" \
      "$promotion_command_display" \
      "policy"
    final_status="fail"
    final_rc=1
  else
    final_status="warn"
    final_rc=0
    set_promotion_failure \
      "$primary_code" \
      "" \
      "$primary_message" \
      "$primary_action" \
      "$promotion_command_display" \
      "policy"
  fi
else
  set_promotion_failure \
    "promotion_decision_unusable" \
    "promotion_check" \
    "promotion check summary is missing a usable decision" \
    "Regenerate promotion-check summary with a GO/NO-GO decision and rerun promotion cycle." \
    "$promotion_command_display" \
    "artifact_contract"
  final_decision="NO-GO"
  final_status="fail"
  final_rc=1
fi

promotion_effective_decision="$promotion_decision"
promotion_effective_status="$promotion_status"
if [[ "$promotion_contract_ok" != "true" ]]; then
  promotion_effective_decision="NO-GO"
  promotion_effective_status="fail"
fi

if [[ -z "$next_operator_action" ]]; then
  next_operator_action="$promotion_operator_next_action"
fi
if [[ -z "$next_operator_action" && "$failure_stage" == "cycles" ]]; then
  next_operator_action="Inspect failed cycle logs/artifacts under $archive_root and rerun profile_compare_multi_vm_stability_promotion_cycle.sh."
fi
if [[ -z "$next_operator_action" && "$final_decision" == "NO-GO" ]]; then
  next_operator_action="Hold promotion. Resolve cycle/promotion violations, then rerun profile_compare_multi_vm_stability_promotion_cycle.sh."
fi
if [[ -z "$next_operator_action" ]]; then
  next_operator_action="Promotion may proceed."
fi
if [[ -z "$next_operator_action_command" ]]; then
  next_operator_action_command="$(quote_cmd bash ./scripts/profile_compare_multi_vm_stability_promotion_cycle.sh --reports-dir .easy-node-logs --summary-json .easy-node-logs/profile_compare_multi_vm_stability_promotion_cycle_summary.json --print-summary-json 1)"
  next_operator_action_command="$(trim "$next_operator_action_command")"
fi

cycle_summary_list_count="$(wc -l <"$cycle_summary_list" | tr -d '[:space:]')"
if [[ -z "$cycle_summary_list_count" ]]; then
  cycle_summary_list_count="0"
fi

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$final_status" \
  --arg decision "$final_decision" \
  --arg failure_stage "$failure_stage" \
  --arg failure_reason "$failure_reason" \
  --arg failure_reason_code "$failure_reason_code" \
  --arg failure_category "$failure_category" \
  --arg reports_dir "$reports_dir" \
  --arg archive_root "$archive_root" \
  --arg cycle_summary_list "$cycle_summary_list" \
  --arg promotion_summary_json "$promotion_summary_json" \
  --arg summary_json_path "$summary_json" \
  --arg next_operator_action "$next_operator_action" \
  --arg next_operator_action_command "$next_operator_action_command" \
  --arg promotion_stage_attempted "$promotion_stage_attempted" \
  --arg promotion_stage_status "$promotion_stage_status" \
  --arg promotion_decision "$promotion_decision" \
  --arg promotion_effective_decision "$promotion_effective_decision" \
  --arg promotion_status "$promotion_status" \
  --arg promotion_effective_status "$promotion_effective_status" \
  --arg promotion_summary_exists "$promotion_summary_exists" \
  --arg promotion_summary_valid "$promotion_summary_valid" \
  --arg promotion_summary_fresh "$promotion_summary_fresh" \
  --arg promotion_contract_ok "$promotion_contract_ok" \
  --arg promotion_primary_violation_code "$promotion_primary_violation_code" \
  --arg promotion_primary_violation_message "$promotion_primary_violation_message" \
  --arg promotion_primary_violation_action "$promotion_primary_violation_action" \
  --arg promotion_log "$promotion_log" \
  --arg promotion_command "$promotion_command_display" \
  --arg promotion_stage_started_at "$promotion_stage_started_at" \
  --arg promotion_stage_completed_at "$promotion_stage_completed_at" \
  --arg require_check_policy_modal_decision "$require_check_policy_modal_decision" \
  --argjson rc "$final_rc" \
  --argjson cycles_requested "$cycle_counts_requested" \
  --argjson cycles_completed "$cycle_counts_completed" \
  --argjson cycles_pass "$cycle_counts_pass" \
  --argjson cycles_warn "$cycle_counts_warn" \
  --argjson cycles_fail "$cycle_counts_fail" \
  --argjson cycle_command_failures "$cycle_command_failures" \
  --argjson cycle_summary_missing_count "$cycle_summary_missing_count" \
  --argjson cycle_summary_invalid_count "$cycle_summary_invalid_count" \
  --argjson cycle_summary_stale_count "$cycle_summary_stale_count" \
  --argjson cycle_summary_list_count "$cycle_summary_list_count" \
  --argjson promotion_stage_rc "$promotion_stage_rc" \
  --argjson promotion_rc "$promotion_rc_json" \
  --argjson promotion_violations_count "$promotion_violations_count" \
  --argjson failure_reasons "$failure_reasons_json" \
  --argjson cycles "$cycles_json" \
  --argjson sleep_between_sec "$sleep_between_sec" \
  --argjson cycle_timeout_sec "$cycle_timeout_sec" \
  --argjson require_min_cycles "$require_min_cycles" \
  --argjson require_min_pass_cycles "$require_min_pass_cycles" \
  --argjson require_max_fail_cycles "$require_max_fail_cycles" \
  --argjson require_max_warn_cycles "$require_max_warn_cycles" \
  --argjson require_min_pass_rate_pct "$require_min_pass_rate_pct" \
  --argjson require_min_go_decision_rate_pct "$require_min_go_decision_rate_pct" \
  --argjson require_cycle_schema_valid "$require_cycle_schema_valid" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  '{
    version: 1,
    schema: {
      id: "profile_compare_multi_vm_stability_promotion_cycle_summary"
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
    next_operator_action: $next_operator_action,
    operator_next_action_command: (
      if $next_operator_action_command == "" then null
      else $next_operator_action_command
      end
    ),
    inputs: {
      reports_dir: $reports_dir,
      cycle_orchestration: {
        cycles: $cycles_requested,
        sleep_between_sec: $sleep_between_sec,
        cycle_timeout_sec: $cycle_timeout_sec
      },
      promotion_policy: {
        require_min_cycles: $require_min_cycles,
        require_min_pass_cycles: $require_min_pass_cycles,
        require_max_fail_cycles: $require_max_fail_cycles,
        require_max_warn_cycles: $require_max_warn_cycles,
        require_min_pass_rate_pct: $require_min_pass_rate_pct,
        require_min_go_decision_rate_pct: $require_min_go_decision_rate_pct,
        require_cycle_schema_valid: ($require_cycle_schema_valid == 1),
        require_check_policy_modal_decision: $require_check_policy_modal_decision,
        fail_on_no_go: ($fail_on_no_go == 1)
      }
    },
    cycle_counts: {
      requested: $cycles_requested,
      completed: $cycles_completed,
      pass: $cycles_pass,
      warn: $cycles_warn,
      fail: $cycles_fail,
      command_failures: $cycle_command_failures,
      summary_missing: $cycle_summary_missing_count,
      summary_invalid_json: $cycle_summary_invalid_count,
      summary_stale: $cycle_summary_stale_count,
      cycle_summary_list_count: $cycle_summary_list_count
    },
    stages: {
      promotion_check: {
        attempted: ($promotion_stage_attempted == "true"),
        status: $promotion_stage_status,
        rc: $promotion_stage_rc,
        command: $promotion_command,
        log: $promotion_log,
        started_at_utc: $promotion_stage_started_at,
        completed_at_utc: $promotion_stage_completed_at,
        summary_json: $promotion_summary_json
      }
    },
    promotion: {
      contract_ok: ($promotion_contract_ok == "true"),
      summary_exists: ($promotion_summary_exists == "true"),
      summary_valid_json: ($promotion_summary_valid == "true"),
      summary_fresh: ($promotion_summary_fresh == "true"),
      decision: (if $promotion_effective_decision == "" then null else $promotion_effective_decision end),
      status: (if $promotion_effective_status == "" then null else $promotion_effective_status end),
      observed_decision: (if $promotion_decision == "" then null else $promotion_decision end),
      observed_status: (if $promotion_status == "" then null else $promotion_status end),
      rc: $promotion_rc,
      violations_count: $promotion_violations_count,
      primary_violation: (
        if $promotion_primary_violation_code == "" and $promotion_primary_violation_message == "" and $promotion_primary_violation_action == "" then null
        else {
          code: (if $promotion_primary_violation_code == "" then null else $promotion_primary_violation_code end),
          message: (if $promotion_primary_violation_message == "" then null else $promotion_primary_violation_message end),
          action: (if $promotion_primary_violation_action == "" then null else $promotion_primary_violation_action end)
        }
        end
      ),
      operator_next_action: (
        if $next_operator_action == "" then null
        else $next_operator_action
        end
      )
    },
    enforcement: {
      fail_on_no_go: ($fail_on_no_go == 1),
      no_go_detected: ($decision == "NO-GO"),
      no_go_enforced: ($decision == "NO-GO" and ($fail_on_no_go == 1)),
      terminal_outcome: (
        if $decision == "GO" then "pass"
        elif $fail_on_no_go == 1 then "blocked"
        else "warn"
        end
      )
    },
    outcome: {
      should_promote: ($status == "pass" and $decision == "GO" and $rc == 0),
      action: (
        if $status == "pass" and $decision == "GO" and $rc == 0 then "promote_allowed"
        elif $fail_on_no_go == 1 then "hold_promotion_blocked"
        else "hold_promotion_warn_only"
        end
      ),
      next_operator_action: $next_operator_action
    },
    cycles: $cycles,
    artifacts: {
      summary_json: $summary_json_path,
      cycle_summary_list: $cycle_summary_list,
      promotion_summary_json: $promotion_summary_json,
      archive_root: $archive_root,
      promotion_log: $promotion_log
    }
  }' >"$summary_json"

echo "[profile-compare-multi-vm-stability-promotion-cycle] status=$final_status rc=$final_rc decision=${final_decision:-unset} summary_json=$summary_json"
if [[ -n "$failure_stage" ]]; then
  echo "[profile-compare-multi-vm-stability-promotion-cycle] failure_stage=$failure_stage failure_reason=${failure_reason:-}"
fi
if [[ "$show_json" == "1" ]]; then
  echo "[profile-compare-multi-vm-stability-promotion-cycle] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
