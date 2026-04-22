#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STABILITY_CYCLE_SCRIPT="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_stability_cycle.sh}"
PROMOTION_CHECK_SCRIPT="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_stability_promotion_check.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_default_gate_stability_promotion_cycle.sh \
    --host-a HOST \
    --host-b HOST \
    [--campaign-subject ID | --subject ID] \
    [--cycles N] \
    [--sleep-between-cycles-sec N] \
    [--reports-dir DIR] \
    [--cycle-summary-list PATH] \
    [--promotion-summary-json PATH] \
    [--summary-json PATH] \
    [--cycle-runs N] \
    [--cycle-campaign-timeout-sec N] \
    [--cycle-sleep-between-sec N] \
    [--cycle-allow-partial [0|1]] \
    [--require-min-cycles N] \
    [--require-min-pass-cycles N] \
    [--require-max-fail-cycles N] \
    [--require-max-warn-cycles N] \
    [--require-min-pass-rate-pct N] \
    [--require-min-go-decision-rate-pct N] \
    [--require-check-schema-valid [0|1]] \
    [--require-check-usable-decision [0|1]] \
    [--require-check-policy-modal-decision GO|NO-GO] \
    [--fail-on-no-go [0|1]] \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Run repeated profile-default-gate stability cycles, capture deterministic
  cycle-summary paths in one list file, then run promotion gating across the
  collected cycle evidence in one fail-closed command.

Notes:
  - Stage scripts can be overridden with:
    PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT
    PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT
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

need_cmd jq
need_cmd date
need_cmd bash
need_cmd mkdir

host_a="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_HOST_A:-}"
host_b="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_HOST_B:-}"
campaign_subject="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_CAMPAIGN_SUBJECT:-}"
campaign_subject_from_campaign=""
campaign_subject_from_alias=""

cycles="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_CYCLES:-3}"
sleep_between_cycles_sec="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_SLEEP_BETWEEN_CYCLES_SEC:-5}"
reports_dir="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"

cycle_summary_list="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_SUMMARY_LIST:-}"
promotion_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_SUMMARY_JSON:-}"
summary_json="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_SUMMARY_JSON:-}"

cycle_runs="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_RUNS:-}"
cycle_campaign_timeout_sec="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_CAMPAIGN_TIMEOUT_SEC:-}"
cycle_sleep_between_sec="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_SLEEP_BETWEEN_SEC:-}"
cycle_allow_partial="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_ALLOW_PARTIAL:-}"

require_min_cycles="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_REQUIRE_MIN_CYCLES:-${REQUIRE_MIN_CYCLES:-3}}"
require_min_pass_cycles="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_REQUIRE_MIN_PASS_CYCLES:-${REQUIRE_MIN_PASS_CYCLES:-3}}"
require_max_fail_cycles="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_REQUIRE_MAX_FAIL_CYCLES:-${REQUIRE_MAX_FAIL_CYCLES:-0}}"
require_max_warn_cycles="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_REQUIRE_MAX_WARN_CYCLES:-${REQUIRE_MAX_WARN_CYCLES:-0}}"
require_min_pass_rate_pct="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_REQUIRE_MIN_PASS_RATE_PCT:-${REQUIRE_MIN_PASS_RATE_PCT:-100}}"
require_min_go_decision_rate_pct="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_REQUIRE_MIN_GO_DECISION_RATE_PCT:-${REQUIRE_MIN_GO_DECISION_RATE_PCT:-100}}"
require_check_schema_valid="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_REQUIRE_CHECK_SCHEMA_VALID:-${REQUIRE_CHECK_SCHEMA_VALID:-1}}"
require_check_usable_decision="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_REQUIRE_CHECK_USABLE_DECISION:-${REQUIRE_CHECK_USABLE_DECISION:-1}}"
require_check_policy_modal_decision="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_REQUIRE_CHECK_POLICY_MODAL_DECISION:-${REQUIRE_CHECK_POLICY_MODAL_DECISION:-GO}}"
fail_on_no_go="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_FAIL_ON_NO_GO:-${FAIL_ON_NO_GO:-1}}"

show_json="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_SHOW_JSON:-0}"
print_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PRINT_SUMMARY_JSON:-0}"

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
    --cycles)
      require_value_or_die "$1" "$#"
      cycles="${2:-}"
      shift 2
      ;;
    --cycles=*)
      cycles="${1#*=}"
      shift
      ;;
    --sleep-between-cycles-sec)
      require_value_or_die "$1" "$#"
      sleep_between_cycles_sec="${2:-}"
      shift 2
      ;;
    --sleep-between-cycles-sec=*)
      sleep_between_cycles_sec="${1#*=}"
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
    --summary-json)
      require_value_or_die "$1" "$#"
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    --cycle-runs)
      require_value_or_die "$1" "$#"
      cycle_runs="${2:-}"
      shift 2
      ;;
    --cycle-runs=*)
      cycle_runs="${1#*=}"
      shift
      ;;
    --cycle-campaign-timeout-sec)
      require_value_or_die "$1" "$#"
      cycle_campaign_timeout_sec="${2:-}"
      shift 2
      ;;
    --cycle-campaign-timeout-sec=*)
      cycle_campaign_timeout_sec="${1#*=}"
      shift
      ;;
    --cycle-sleep-between-sec)
      require_value_or_die "$1" "$#"
      cycle_sleep_between_sec="${2:-}"
      shift 2
      ;;
    --cycle-sleep-between-sec=*)
      cycle_sleep_between_sec="${1#*=}"
      shift
      ;;
    --cycle-allow-partial)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        cycle_allow_partial="${2:-}"
        shift 2
      else
        cycle_allow_partial="1"
        shift
      fi
      ;;
    --cycle-allow-partial=*)
      cycle_allow_partial="${1#*=}"
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
    --require-check-schema-valid)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_check_schema_valid="${2:-}"
        shift 2
      else
        require_check_schema_valid="1"
        shift
      fi
      ;;
    --require-check-schema-valid=*)
      require_check_schema_valid="${1#*=}"
      shift
      ;;
    --require-check-usable-decision)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_check_usable_decision="${2:-}"
        shift 2
      else
        require_check_usable_decision="1"
        shift
      fi
      ;;
    --require-check-usable-decision=*)
      require_check_usable_decision="${1#*=}"
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
cycles="$(trim "$cycles")"
sleep_between_cycles_sec="$(trim "$sleep_between_cycles_sec")"
reports_dir="$(abs_path "$reports_dir")"
cycle_summary_list="$(abs_path "$cycle_summary_list")"
promotion_summary_json="$(abs_path "$promotion_summary_json")"
summary_json="$(abs_path "$summary_json")"
cycle_runs="$(trim "$cycle_runs")"
cycle_campaign_timeout_sec="$(trim "$cycle_campaign_timeout_sec")"
cycle_sleep_between_sec="$(trim "$cycle_sleep_between_sec")"
cycle_allow_partial="$(trim "$cycle_allow_partial")"
require_min_cycles="$(trim "$require_min_cycles")"
require_min_pass_cycles="$(trim "$require_min_pass_cycles")"
require_max_fail_cycles="$(trim "$require_max_fail_cycles")"
require_max_warn_cycles="$(trim "$require_max_warn_cycles")"
require_min_pass_rate_pct="$(trim "$require_min_pass_rate_pct")"
require_min_go_decision_rate_pct="$(trim "$require_min_go_decision_rate_pct")"
require_check_schema_valid="$(trim "$require_check_schema_valid")"
require_check_usable_decision="$(trim "$require_check_usable_decision")"
require_check_policy_modal_decision="$(trim "$require_check_policy_modal_decision")"
fail_on_no_go="$(trim "$fail_on_no_go")"
show_json="$(trim "$show_json")"
print_summary_json="$(trim "$print_summary_json")"
STABILITY_CYCLE_SCRIPT="$(abs_path "$STABILITY_CYCLE_SCRIPT")"
PROMOTION_CHECK_SCRIPT="$(abs_path "$PROMOTION_CHECK_SCRIPT")"

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
if [[ ! -f "$STABILITY_CYCLE_SCRIPT" ]]; then
  echo "stability cycle script not found: $STABILITY_CYCLE_SCRIPT"
  exit 2
fi
if [[ ! -f "$PROMOTION_CHECK_SCRIPT" ]]; then
  echo "promotion check script not found: $PROMOTION_CHECK_SCRIPT"
  exit 2
fi

int_arg_or_die "--cycles" "$cycles"
int_arg_or_die "--sleep-between-cycles-sec" "$sleep_between_cycles_sec"
for int_arg in "$require_min_cycles" "$require_min_pass_cycles" "$require_max_fail_cycles" "$require_max_warn_cycles"; do
  int_arg_or_die "promotion threshold" "$int_arg"
done
if [[ -n "$cycle_runs" ]]; then
  int_arg_or_die "--cycle-runs" "$cycle_runs"
fi
if [[ -n "$cycle_campaign_timeout_sec" ]]; then
  int_arg_or_die "--cycle-campaign-timeout-sec" "$cycle_campaign_timeout_sec"
fi
if [[ -n "$cycle_sleep_between_sec" ]]; then
  int_arg_or_die "--cycle-sleep-between-sec" "$cycle_sleep_between_sec"
fi
if [[ -n "$cycle_allow_partial" ]]; then
  bool_arg_or_die "--cycle-allow-partial" "$cycle_allow_partial"
fi
bool_arg_or_die "--require-check-schema-valid" "$require_check_schema_valid"
bool_arg_or_die "--require-check-usable-decision" "$require_check_usable_decision"
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
if [[ -z "$require_check_policy_modal_decision" ]]; then
  require_check_policy_modal_decision="GO"
fi
require_check_policy_modal_decision="$(normalize_decision "$require_check_policy_modal_decision")"
if [[ "$require_check_policy_modal_decision" != "GO" && "$require_check_policy_modal_decision" != "NO-GO" ]]; then
  echo "--require-check-policy-modal-decision must be GO or NO-GO"
  exit 2
fi

if (( cycles < 1 )); then
  echo "--cycles must be >= 1"
  exit 2
fi
if [[ -n "$cycle_runs" ]] && (( cycle_runs < 1 )); then
  echo "--cycle-runs must be >= 1"
  exit 2
fi
if [[ -n "$cycle_campaign_timeout_sec" ]] && (( cycle_campaign_timeout_sec < 1 )); then
  echo "--cycle-campaign-timeout-sec must be >= 1"
  exit 2
fi

mkdir -p "$reports_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"
run_dir="$reports_dir/profile_default_gate_stability_promotion_cycle_${run_stamp}_$$"
mkdir -p "$run_dir"

if [[ -z "$cycle_summary_list" ]]; then
  cycle_summary_list="$run_dir/profile_default_gate_stability_cycle_summaries.list"
fi
if [[ -z "$promotion_summary_json" ]]; then
  promotion_summary_json="$run_dir/profile_default_gate_stability_promotion_check_summary.json"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$run_dir/profile_default_gate_stability_promotion_cycle_summary.json"
fi
mkdir -p "$(dirname "$cycle_summary_list")" "$(dirname "$promotion_summary_json")" "$(dirname "$summary_json")"

declare -a cycle_summary_paths=()
cycles_json='[]'
cycle_collection_hard_failures=0

cycle_index=0
while (( cycle_index < cycles )); do
  cycle_index=$((cycle_index + 1))
  cycle_id="$(printf '%02d' "$cycle_index")"

  cycle_summary_json="$run_dir/profile_default_gate_stability_cycle_${cycle_id}_summary.json"
  cycle_run_summary_json="$run_dir/profile_default_gate_stability_run_${cycle_id}_summary.json"
  cycle_check_summary_json="$run_dir/profile_default_gate_stability_check_${cycle_id}_summary.json"
  cycle_log="$run_dir/profile_default_gate_stability_cycle_${cycle_id}.log"

  cycle_summary_paths+=("$cycle_summary_json")

  declare -a cycle_cmd
  cycle_cmd=(
    bash "$STABILITY_CYCLE_SCRIPT"
    --host-a "$host_a"
    --host-b "$host_b"
    --campaign-subject "$campaign_subject"
    --reports-dir "$run_dir"
    --run-summary-json "$cycle_run_summary_json"
    --check-summary-json "$cycle_check_summary_json"
    --summary-json "$cycle_summary_json"
    --fail-on-no-go "$fail_on_no_go"
    --show-json 0
    --print-summary-json 0
  )
  if [[ -n "$cycle_runs" ]]; then
    cycle_cmd+=(--runs "$cycle_runs")
  fi
  if [[ -n "$cycle_campaign_timeout_sec" ]]; then
    cycle_cmd+=(--campaign-timeout-sec "$cycle_campaign_timeout_sec")
  fi
  if [[ -n "$cycle_sleep_between_sec" ]]; then
    cycle_cmd+=(--sleep-between-sec "$cycle_sleep_between_sec")
  fi
  if [[ -n "$cycle_allow_partial" ]]; then
    cycle_cmd+=(--allow-partial "$cycle_allow_partial")
  fi

  cycle_command_display="$(quote_cmd "${cycle_cmd[@]}")"
  echo "[profile-default-gate-stability-promotion-cycle] $(timestamp_utc) cycle-stage start cycle=$cycle_id summary_json=$cycle_summary_json"
  rm -f "$cycle_summary_json" "$cycle_run_summary_json" "$cycle_check_summary_json" "$cycle_log"
  set +e
  "${cycle_cmd[@]}" >"$cycle_log" 2>&1
  cycle_command_rc=$?
  set -e

  cycle_summary_exists="false"
  cycle_summary_valid="false"
  cycle_summary_schema_id=""
  cycle_summary_schema_valid="false"
  cycle_status=""
  cycle_decision=""
  cycle_rc_json="null"
  cycle_failure_reason=""
  cycle_command_contract_ok="true"

  if [[ -f "$cycle_summary_json" ]]; then
    cycle_summary_exists="true"
  else
    cycle_failure_reason="cycle_summary_missing"
    cycle_collection_hard_failures=$((cycle_collection_hard_failures + 1))
  fi

  if [[ "$cycle_summary_exists" == "true" && "$(json_file_valid_01 "$cycle_summary_json")" == "1" ]]; then
    cycle_summary_valid="true"
    cycle_summary_schema_id="$(jq -r 'if (.schema.id | type) == "string" then .schema.id else "" end' "$cycle_summary_json" 2>/dev/null || printf '%s' "")"
    if [[ "$cycle_summary_schema_id" == "profile_default_gate_stability_cycle_summary" ]]; then
      cycle_summary_schema_valid="true"
    else
      cycle_collection_hard_failures=$((cycle_collection_hard_failures + 1))
      cycle_failure_reason="cycle_summary_schema_invalid"
    fi
    cycle_status="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$cycle_summary_json" 2>/dev/null || printf '%s' "")"
    cycle_decision="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$cycle_summary_json" 2>/dev/null || printf '%s' "")"
    if [[ -n "$cycle_decision" ]]; then
      cycle_decision="$(normalize_decision "$cycle_decision")"
    fi
    cycle_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else "null" end' "$cycle_summary_json" 2>/dev/null || printf '%s' "null")"
  elif [[ "$cycle_summary_exists" == "true" ]]; then
    cycle_collection_hard_failures=$((cycle_collection_hard_failures + 1))
    cycle_failure_reason="cycle_summary_invalid_json"
  fi

  if [[ "$cycle_summary_valid" == "true" ]]; then
    if [[ "$cycle_command_rc" -eq 0 ]]; then
      if [[ "$cycle_rc_json" != "0" ]]; then
        cycle_command_contract_ok="false"
      fi
    else
      if [[ "$cycle_rc_json" != "$cycle_command_rc" ]]; then
        cycle_command_contract_ok="false"
      elif [[ "$cycle_decision" != "NO-GO" ]]; then
        cycle_command_contract_ok="false"
      elif [[ "$cycle_status" != "fail" ]]; then
        cycle_command_contract_ok="false"
      fi
    fi
  elif [[ "$cycle_command_rc" -ne 0 ]]; then
    cycle_command_contract_ok="false"
  fi

  if [[ "$cycle_command_contract_ok" != "true" ]]; then
    cycle_collection_hard_failures=$((cycle_collection_hard_failures + 1))
    if [[ -z "$cycle_failure_reason" ]]; then
      cycle_failure_reason="cycle_command_rc_contract_mismatch"
    fi
  fi

  cycle_entry="$(jq -n \
    --arg cycle_id "$cycle_id" \
    --arg command "$cycle_command_display" \
    --arg log "$cycle_log" \
    --arg cycle_summary_json "$cycle_summary_json" \
    --arg cycle_run_summary_json "$cycle_run_summary_json" \
    --arg cycle_check_summary_json "$cycle_check_summary_json" \
    --arg cycle_summary_exists "$cycle_summary_exists" \
    --arg cycle_summary_valid "$cycle_summary_valid" \
    --arg cycle_summary_schema_id "$cycle_summary_schema_id" \
    --arg cycle_summary_schema_valid "$cycle_summary_schema_valid" \
    --arg cycle_status "$cycle_status" \
    --arg cycle_decision "$cycle_decision" \
    --arg cycle_failure_reason "$cycle_failure_reason" \
    --arg cycle_command_contract_ok "$cycle_command_contract_ok" \
    --argjson command_rc "$cycle_command_rc" \
    --argjson cycle_rc "$cycle_rc_json" \
    '{
      cycle_id: $cycle_id,
      command: $command,
      command_rc: $command_rc,
      status: (if $cycle_status == "" then null else $cycle_status end),
      decision: (if $cycle_decision == "" then null else $cycle_decision end),
      rc: $cycle_rc,
      command_contract_ok: ($cycle_command_contract_ok == "true"),
      failure_reason: (if $cycle_failure_reason == "" then null else $cycle_failure_reason end),
      artifacts: {
        cycle_summary_json: $cycle_summary_json,
        cycle_run_summary_json: $cycle_run_summary_json,
        cycle_check_summary_json: $cycle_check_summary_json,
        cycle_log: $log
      },
      summary_exists: ($cycle_summary_exists == "true"),
      summary_valid_json: ($cycle_summary_valid == "true"),
      summary_schema_id: (if $cycle_summary_schema_id == "" then null else $cycle_summary_schema_id end),
      summary_schema_valid: ($cycle_summary_schema_valid == "true")
    }')"
  cycles_json="$(jq -c --argjson entry "$cycle_entry" '. + [$entry]' <<<"$cycles_json")"

  echo "[profile-default-gate-stability-promotion-cycle] $(timestamp_utc) cycle-stage end cycle=$cycle_id command_rc=$cycle_command_rc summary_exists=$cycle_summary_exists summary_valid=$cycle_summary_valid schema_valid=$cycle_summary_schema_valid"

  if (( cycle_index < cycles && sleep_between_cycles_sec > 0 )); then
    sleep "$sleep_between_cycles_sec"
  fi
done

printf '%s\n' "${cycle_summary_paths[@]}" >"$cycle_summary_list"

promotion_stage_attempted="true"
promotion_stage_status="pass"
promotion_stage_rc_json="null"
promotion_decision=""
promotion_has_usable_decision="false"
promotion_status=""
promotion_rc_json="null"
promotion_summary_exists="false"
promotion_summary_valid="false"
promotion_summary_schema_id=""
promotion_summary_schema_valid="false"
promotion_violations_json="[]"
promotion_errors_json="[]"
promotion_outcome_action=""
promotion_enforcement_no_go_enforced=""
promotion_notes=""

declare -a promotion_cmd
promotion_cmd=(
  bash "$PROMOTION_CHECK_SCRIPT"
  --cycle-summary-list "$cycle_summary_list"
  --reports-dir "$run_dir"
  --require-min-cycles "$require_min_cycles"
  --require-min-pass-cycles "$require_min_pass_cycles"
  --require-max-fail-cycles "$require_max_fail_cycles"
  --require-max-warn-cycles "$require_max_warn_cycles"
  --require-min-pass-rate-pct "$require_min_pass_rate_pct"
  --require-min-go-decision-rate-pct "$require_min_go_decision_rate_pct"
  --require-check-schema-valid "$require_check_schema_valid"
  --require-check-usable-decision "$require_check_usable_decision"
  --require-check-policy-modal-decision "$require_check_policy_modal_decision"
  --fail-on-no-go "$fail_on_no_go"
  --summary-json "$promotion_summary_json"
  --show-json 0
  --print-summary-json 0
)
promotion_command_display="$(quote_cmd "${promotion_cmd[@]}")"

echo "[profile-default-gate-stability-promotion-cycle] $(timestamp_utc) promotion-stage start summary_json=$promotion_summary_json"
rm -f "$promotion_summary_json" "$run_dir/profile_default_gate_stability_promotion_check.log"
set +e
"${promotion_cmd[@]}" >"$run_dir/profile_default_gate_stability_promotion_check.log" 2>&1
promotion_stage_rc=$?
set -e
promotion_stage_rc_json="$promotion_stage_rc"
if [[ "$promotion_stage_rc" -ne 0 ]]; then
  promotion_stage_status="fail"
fi

if [[ -f "$promotion_summary_json" ]]; then
  promotion_summary_exists="true"
fi
if [[ "$promotion_summary_exists" == "true" && "$(json_file_valid_01 "$promotion_summary_json")" == "1" ]]; then
  promotion_summary_valid="true"
  promotion_summary_schema_id="$(jq -r 'if (.schema.id | type) == "string" then .schema.id else "" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  if [[ "$promotion_summary_schema_id" == "profile_default_gate_stability_promotion_check_summary" ]]; then
    promotion_summary_schema_valid="true"
  fi
  promotion_decision="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  if [[ -n "$promotion_decision" ]]; then
    promotion_decision="$(normalize_decision "$promotion_decision")"
  fi
  if [[ "$promotion_decision" == "GO" || "$promotion_decision" == "NO-GO" ]]; then
    promotion_has_usable_decision="true"
  fi
  promotion_status="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else "null" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "null")"
  promotion_violations_json="$(jq -c 'if (.violations | type) == "array" then .violations else [] end' "$promotion_summary_json" 2>/dev/null || printf '%s' "[]")"
  promotion_errors_json="$(jq -c 'if (.errors | type) == "array" then .errors else [] end' "$promotion_summary_json" 2>/dev/null || printf '%s' "[]")"
  promotion_outcome_action="$(jq -r 'if (.outcome.action | type) == "string" then .outcome.action else "" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_enforcement_no_go_enforced="$(jq -r '
    if (.enforcement.no_go_enforced | type) == "boolean" then
      if .enforcement.no_go_enforced then "true" else "false" end
    else
      ""
    end
  ' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_notes="$(jq -r 'if (.notes | type) == "string" then .notes else "" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
else
  promotion_stage_status="fail"
fi

hard_failure_count=0
hard_failure_reason=""
if (( cycle_collection_hard_failures > 0 )); then
  hard_failure_count=$((hard_failure_count + 1))
  hard_failure_reason="cycle_collection_artifact_contract_failed"
fi
if [[ "$promotion_summary_exists" != "true" ]]; then
  hard_failure_count=$((hard_failure_count + 1))
  hard_failure_reason="promotion_summary_missing"
elif [[ "$promotion_summary_valid" != "true" ]]; then
  hard_failure_count=$((hard_failure_count + 1))
  hard_failure_reason="promotion_summary_invalid_json"
elif [[ "$promotion_summary_schema_valid" != "true" ]]; then
  hard_failure_count=$((hard_failure_count + 1))
  hard_failure_reason="promotion_summary_schema_invalid"
elif [[ "$promotion_has_usable_decision" != "true" ]]; then
  hard_failure_count=$((hard_failure_count + 1))
  hard_failure_reason="promotion_summary_missing_decision"
fi
if [[ "$promotion_stage_rc" -ne 0 ]]; then
  hard_failure_count=$((hard_failure_count + 1))
  hard_failure_reason="promotion_command_rc_contract_mismatch"
elif [[ "$promotion_summary_valid" == "true" ]]; then
  if [[ "$promotion_rc_json" != "0" ]]; then
    hard_failure_count=$((hard_failure_count + 1))
    hard_failure_reason="promotion_command_rc_contract_mismatch"
  fi
fi

final_decision="$promotion_decision"
if [[ -z "$final_decision" ]]; then
  final_decision="NO-GO"
fi

final_status="pass"
final_rc=0
failure_stage=""
failure_reason=""
final_notes="$promotion_notes"
if [[ -z "$final_notes" ]]; then
  final_notes="profile default gate stability promotion cycle completed"
fi

if (( hard_failure_count > 0 )); then
  final_decision="NO-GO"
  final_status="fail"
  final_rc=1
  failure_stage="cycle_collection"
  if [[ "$hard_failure_reason" == promotion_* ]]; then
    failure_stage="promotion_check"
  fi
  failure_reason="$hard_failure_reason"
  if (( cycle_collection_hard_failures > 0 )); then
    final_notes="fail-closed: cycle artifact contract failed before promotion decision could be trusted"
  else
    final_notes="fail-closed: promotion summary contract failed"
  fi
elif [[ "$final_decision" == "GO" ]]; then
  final_status="pass"
  final_rc=0
else
  if [[ "$fail_on_no_go" == "1" ]]; then
    final_status="fail"
    final_rc=1
    failure_stage="promotion_check"
    failure_reason="promotion_decision_no_go"
  else
    final_status="warn"
    final_rc=0
  fi
fi

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$final_status" \
  --arg decision "$final_decision" \
  --arg notes "$final_notes" \
  --arg host_a "$host_a" \
  --arg host_b "$host_b" \
  --arg campaign_subject "$campaign_subject" \
  --arg reports_dir "$run_dir" \
  --arg cycle_summary_list "$cycle_summary_list" \
  --arg promotion_summary_json "$promotion_summary_json" \
  --arg summary_json_path "$summary_json" \
  --arg stability_cycle_script "$STABILITY_CYCLE_SCRIPT" \
  --arg promotion_check_script "$PROMOTION_CHECK_SCRIPT" \
  --arg promotion_stage_status "$promotion_stage_status" \
  --arg promotion_summary_exists "$promotion_summary_exists" \
  --arg promotion_summary_valid "$promotion_summary_valid" \
  --arg promotion_summary_schema_id "$promotion_summary_schema_id" \
  --arg promotion_summary_schema_valid "$promotion_summary_schema_valid" \
  --arg promotion_decision "$promotion_decision" \
  --arg promotion_has_usable_decision "$promotion_has_usable_decision" \
  --arg promotion_status "$promotion_status" \
  --arg promotion_outcome_action "$promotion_outcome_action" \
  --arg promotion_enforcement_no_go_enforced "$promotion_enforcement_no_go_enforced" \
  --arg failure_stage "$failure_stage" \
  --arg failure_reason "$failure_reason" \
  --arg promotion_command "$promotion_command_display" \
  --argjson rc "$final_rc" \
  --argjson cycles "$cycles" \
  --argjson sleep_between_cycles_sec "$sleep_between_cycles_sec" \
  --argjson cycle_runs "$([ -n "$cycle_runs" ] && printf '%s' "$cycle_runs" || printf '%s' "null")" \
  --argjson cycle_campaign_timeout_sec "$([ -n "$cycle_campaign_timeout_sec" ] && printf '%s' "$cycle_campaign_timeout_sec" || printf '%s' "null")" \
  --argjson cycle_sleep_between_sec "$([ -n "$cycle_sleep_between_sec" ] && printf '%s' "$cycle_sleep_between_sec" || printf '%s' "null")" \
  --argjson cycle_allow_partial "$([ -n "$cycle_allow_partial" ] && printf '%s' "$cycle_allow_partial" || printf '%s' "null")" \
  --argjson require_min_cycles "$require_min_cycles" \
  --argjson require_min_pass_cycles "$require_min_pass_cycles" \
  --argjson require_max_fail_cycles "$require_max_fail_cycles" \
  --argjson require_max_warn_cycles "$require_max_warn_cycles" \
  --argjson require_min_pass_rate_pct "$require_min_pass_rate_pct" \
  --argjson require_min_go_decision_rate_pct "$require_min_go_decision_rate_pct" \
  --argjson require_check_schema_valid "$require_check_schema_valid" \
  --argjson require_check_usable_decision "$require_check_usable_decision" \
  --arg require_check_policy_modal_decision "$require_check_policy_modal_decision" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --argjson cycle_collection_hard_failures "$cycle_collection_hard_failures" \
  --argjson promotion_stage_rc "$promotion_stage_rc_json" \
  --argjson promotion_rc "$promotion_rc_json" \
  --argjson promotion_violations "$promotion_violations_json" \
  --argjson promotion_errors "$promotion_errors_json" \
  --argjson cycles_json "$cycles_json" \
  '{
    version: 1,
    schema: {
      id: "profile_default_gate_stability_promotion_cycle_summary"
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    decision: $decision,
    notes: $notes,
    failure_stage: (if $failure_stage == "" then null else $failure_stage end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    inputs: {
      host_a: $host_a,
      host_b: $host_b,
      campaign_subject: $campaign_subject,
      reports_dir: $reports_dir,
      policy: {
        cycles: $cycles,
        sleep_between_cycles_sec: $sleep_between_cycles_sec,
        cycle_runs: (if $cycle_runs == null then null else $cycle_runs end),
        cycle_campaign_timeout_sec: (if $cycle_campaign_timeout_sec == null then null else $cycle_campaign_timeout_sec end),
        cycle_sleep_between_sec: (if $cycle_sleep_between_sec == null then null else $cycle_sleep_between_sec end),
        cycle_allow_partial: (
          if $cycle_allow_partial == null then null
          else ($cycle_allow_partial == 1)
          end
        ),
        require_min_cycles: $require_min_cycles,
        require_min_pass_cycles: $require_min_pass_cycles,
        require_max_fail_cycles: $require_max_fail_cycles,
        require_max_warn_cycles: $require_max_warn_cycles,
        require_min_pass_rate_pct: $require_min_pass_rate_pct,
        require_min_go_decision_rate_pct: $require_min_go_decision_rate_pct,
        require_check_schema_valid: ($require_check_schema_valid == 1),
        require_check_usable_decision: ($require_check_usable_decision == 1),
        require_check_policy_modal_decision: $require_check_policy_modal_decision,
        fail_on_no_go: ($fail_on_no_go == 1)
      }
    },
    stages: {
      cycle_collection: {
        attempted: true,
        cycles_requested: $cycles,
        hard_failures: $cycle_collection_hard_failures,
        status: (
          if $cycle_collection_hard_failures > 0 then "fail"
          else "pass"
          end
        ),
        cycles: $cycles_json
      },
      promotion_check: {
        attempted: true,
        status: $promotion_stage_status,
        rc: $promotion_stage_rc,
        command: $promotion_command,
        summary_json: $promotion_summary_json,
        summary_exists: ($promotion_summary_exists == "true"),
        summary_valid_json: ($promotion_summary_valid == "true"),
        summary_schema_id: (
          if $promotion_summary_schema_id == "" then null
          else $promotion_summary_schema_id
          end
        ),
        summary_schema_valid: ($promotion_summary_schema_valid == "true")
      }
    },
    promotion: {
      decision: (if $promotion_decision == "" then null else $promotion_decision end),
      has_usable_decision: ($promotion_has_usable_decision == "true"),
      status: (if $promotion_status == "" then null else $promotion_status end),
      rc: $promotion_rc,
      outcome_action: (if $promotion_outcome_action == "" then null else $promotion_outcome_action end),
      enforcement_no_go_enforced: (
        if $promotion_enforcement_no_go_enforced == "true" then true
        elif $promotion_enforcement_no_go_enforced == "false" then false
        else null
        end
      ),
      violations: $promotion_violations,
      errors: $promotion_errors
    },
    enforcement: {
      fail_on_no_go: ($fail_on_no_go == 1),
      no_go_detected: ($decision == "NO-GO"),
      no_go_enforced: ($decision == "NO-GO" and ($fail_on_no_go == 1)),
      fail_closed_hard_failures: ($cycle_collection_hard_failures > 0 or $promotion_summary_valid != "true" or $promotion_summary_schema_valid != "true" or $promotion_has_usable_decision != "true")
    },
    outcome: {
      should_promote: ($status == "pass" and $decision == "GO"),
      action: (
        if $status == "pass" and $decision == "GO" then "promote_allowed"
        elif $status == "fail" then "hold_promotion_blocked"
        elif $decision == "NO-GO" then "hold_promotion_warn_only"
        else "investigate_artifacts"
        end
      )
    },
    artifacts: {
      summary_json: $summary_json_path,
      reports_dir: $reports_dir,
      cycle_summary_list: $cycle_summary_list,
      promotion_summary_json: $promotion_summary_json,
      promotion_log: ($reports_dir + "/profile_default_gate_stability_promotion_check.log")
    }
  }' >"$summary_json"

echo "[profile-default-gate-stability-promotion-cycle] status=$final_status rc=$final_rc decision=$final_decision summary_json=$summary_json"
if [[ -n "$failure_stage" ]]; then
  echo "[profile-default-gate-stability-promotion-cycle] failure_stage=$failure_stage failure_reason=${failure_reason:-}"
fi
if [[ "$show_json" == "1" ]]; then
  echo "[profile-default-gate-stability-promotion-cycle] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
