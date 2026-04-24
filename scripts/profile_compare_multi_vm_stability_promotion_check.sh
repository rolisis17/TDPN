#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_multi_vm_stability_promotion_check.sh \
    [--cycle-summary-json PATH]... \
    [--cycle-summary-list FILE] \
    [--reports-dir DIR] \
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
    [--print-summary-json [0|1]]

Purpose:
  Reduce repeated profile-compare multi-VM stability cycle summaries into a
  deterministic promotion GO/NO-GO decision with fail-closed policy gates and
  actionable operator guidance.
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

quote_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
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
need_cmd sort

reports_dir="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REPORTS_DIR:-${REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}}"
cycle_summary_list="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_CYCLE_SUMMARY_LIST:-}"
cycle_summary_list_missing="0"

require_min_cycles="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_MIN_CYCLES:-${REQUIRE_MIN_CYCLES:-3}}"
require_min_pass_cycles="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_MIN_PASS_CYCLES:-${REQUIRE_MIN_PASS_CYCLES:-3}}"
require_max_fail_cycles="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_MAX_FAIL_CYCLES:-${REQUIRE_MAX_FAIL_CYCLES:-0}}"
require_max_warn_cycles="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_MAX_WARN_CYCLES:-${REQUIRE_MAX_WARN_CYCLES:-0}}"
require_min_pass_rate_pct="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_MIN_PASS_RATE_PCT:-${REQUIRE_MIN_PASS_RATE_PCT:-100}}"
require_min_go_decision_rate_pct="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_MIN_GO_DECISION_RATE_PCT:-${REQUIRE_MIN_GO_DECISION_RATE_PCT:-100}}"
require_cycle_schema_valid="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_CYCLE_SCHEMA_VALID:-${REQUIRE_CYCLE_SCHEMA_VALID:-1}}"
require_check_policy_modal_decision="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_REQUIRE_CHECK_POLICY_MODAL_DECISION:-${REQUIRE_CHECK_POLICY_MODAL_DECISION:-GO}}"
fail_on_no_go="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_FAIL_ON_NO_GO:-${FAIL_ON_NO_GO:-1}}"

show_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_SHOW_JSON:-0}"
print_summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_PRINT_SUMMARY_JSON:-0}"
summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_SUMMARY_JSON:-}"

declare -a cycle_summary_inputs=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cycle-summary-json)
      require_value_or_die "$1" "$#"
      cycle_summary_inputs+=("${2:-}")
      shift 2
      ;;
    --cycle-summary-json=*)
      cycle_summary_inputs+=("${1#*=}")
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
    --reports-dir)
      require_value_or_die "$1" "$#"
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
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
cycle_summary_list="$(abs_path "$cycle_summary_list")"
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

bool_arg_or_die "--require-cycle-schema-valid" "$require_cycle_schema_valid"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

for int_arg in "$require_min_cycles" "$require_min_pass_cycles" "$require_max_fail_cycles" "$require_max_warn_cycles"; do
  if ! [[ "$int_arg" =~ ^[0-9]+$ ]]; then
    echo "cycle count thresholds must be non-negative integers"
    exit 2
  fi
done

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
  echo "--require-check-modal-decision must be GO or NO-GO"
  exit 2
fi

log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/profile_compare_multi_vm_stability_promotion_check_${run_stamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

declare -a cycle_summary_paths_raw=()
for path in "${cycle_summary_inputs[@]}"; do
  cycle_summary_paths_raw+=("$path")
done

if [[ -n "$cycle_summary_list" ]]; then
  if [[ ! -f "$cycle_summary_list" ]]; then
    cycle_summary_list_missing="1"
  else
    while IFS= read -r list_line || [[ -n "$list_line" ]]; do
      list_line="$(trim "$list_line")"
      if [[ -z "$list_line" || "${list_line:0:1}" == "#" ]]; then
        continue
      fi
      cycle_summary_paths_raw+=("$list_line")
    done <"$cycle_summary_list"
  fi
fi

if ((${#cycle_summary_paths_raw[@]} == 0)); then
  shopt -s nullglob
  for candidate in "$reports_dir"/profile_compare_multi_vm_stability_cycle_summary*.json; do
    cycle_summary_paths_raw+=("$candidate")
  done
  shopt -u nullglob
fi

declare -A seen_cycle_paths=()
declare -a cycle_summary_paths=()
for raw_path in "${cycle_summary_paths_raw[@]}"; do
  normalized_path="$(abs_path "$raw_path")"
  if [[ -z "$normalized_path" ]]; then
    continue
  fi
  if [[ -z "${seen_cycle_paths[$normalized_path]+x}" ]]; then
    seen_cycle_paths["$normalized_path"]="1"
    cycle_summary_paths+=("$normalized_path")
  fi
done

if ((${#cycle_summary_paths[@]} > 0)); then
  mapfile -t cycle_summary_paths < <(printf '%s\n' "${cycle_summary_paths[@]}" | sort)
fi

total_cycles="${#cycle_summary_paths[@]}"

status_pass_cycles=0
status_warn_cycles=0
status_fail_cycles=0
promotion_pass_cycles=0
go_decision_cycles=0
no_go_decision_cycles=0
usable_decision_cycles=0
cycle_schema_invalid_cycles=0
check_policy_modal_decision_mismatch_cycles=0
cycle_contract_invalid_cycles=0

cycles_json='[]'

for cycle_path in "${cycle_summary_paths[@]}"; do
  artifact_exists="0"
  artifact_valid_json="0"
  artifact_schema_id=""
  artifact_schema_valid="0"
  artifact_status=""
  artifact_decision=""
  artifact_rc_json="null"
  artifact_check_policy_modal_decision=""
  artifact_contract_valid="0"
  artifact_promotion_candidate="false"
  artifact_reasons='[]'

  if [[ -f "$cycle_path" ]]; then
    artifact_exists="1"
  else
    artifact_reasons="$(jq -c '
      . + [{
        code: "artifact_missing",
        message: "cycle summary artifact is missing",
        action: "regenerate multi-VM stability cycle artifact and rerun promotion check"
      }]
    ' <<<"$artifact_reasons")"
  fi

  if [[ "$artifact_exists" == "1" && "$(json_file_valid_01 "$cycle_path")" == "1" ]]; then
    artifact_valid_json="1"
    artifact_schema_id="$(jq -r '
      if (.schema.id | type) == "string" then .schema.id else "" end
    ' "$cycle_path" 2>/dev/null || printf '%s' "")"
    if [[ "$artifact_schema_id" == "profile_compare_multi_vm_stability_cycle_summary" ]]; then
      artifact_schema_valid="1"
    else
      cycle_schema_invalid_cycles=$((cycle_schema_invalid_cycles + 1))
      artifact_reasons="$(jq -c --arg actual "$artifact_schema_id" '
        . + [{
          code: "cycle_schema_invalid",
          message: ("cycle summary schema.id mismatch (actual=" + (if $actual == "" then "unset" else $actual end) + ")"),
          action: "refresh artifacts with profile_compare_multi_vm_stability_cycle.sh before promotion gating"
        }]
      ' <<<"$artifact_reasons")"
    fi

    artifact_status="$(jq -r '
      if (.status | type) == "string" then .status else "" end
    ' "$cycle_path" 2>/dev/null || printf '%s' "")"
    artifact_decision="$(jq -r '
      if (.decision | type) == "string" then .decision else "" end
    ' "$cycle_path" 2>/dev/null || printf '%s' "")"
    artifact_decision="$(normalize_decision "$artifact_decision")"
    artifact_rc_json="$(jq -r '
      if (.rc | type) == "number" then .rc else "null" end
    ' "$cycle_path" 2>/dev/null || printf '%s' "null")"

    artifact_check_policy_modal_decision="$(jq -r '
      if (.inputs.check.policy.require_modal_decision | type) == "string"
      then .inputs.check.policy.require_modal_decision
      else ""
      end
    ' "$cycle_path" 2>/dev/null || printf '%s' "")"
    artifact_check_policy_modal_decision="$(normalize_decision "$artifact_check_policy_modal_decision")"

    if [[ "$artifact_decision" == "GO" ]]; then
      go_decision_cycles=$((go_decision_cycles + 1))
      usable_decision_cycles=$((usable_decision_cycles + 1))
    elif [[ "$artifact_decision" == "NO-GO" ]]; then
      no_go_decision_cycles=$((no_go_decision_cycles + 1))
      usable_decision_cycles=$((usable_decision_cycles + 1))
    else
      artifact_reasons="$(jq -c --arg decision "$artifact_decision" '
        . + [{
          code: "decision_unusable",
          message: ("cycle decision is missing or invalid (actual=" + (if $decision == "" then "unset" else $decision end) + ")"),
          action: "re-run stability cycle and verify decision fields are populated"
        }]
      ' <<<"$artifact_reasons")"
    fi

    if [[ "$artifact_check_policy_modal_decision" != "$require_check_policy_modal_decision" ]]; then
      check_policy_modal_decision_mismatch_cycles=$((check_policy_modal_decision_mismatch_cycles + 1))
      artifact_reasons="$(jq -c --arg required "$require_check_policy_modal_decision" --arg observed "$artifact_check_policy_modal_decision" '
        . + [{
          code: "check_policy_modal_decision_mismatch",
          message: ("cycle check policy modal decision mismatch (required=" + $required + " observed=" + (if $observed == "" then "unset" else $observed end) + ")"),
          action: "align cycle/check policy modal decision and regenerate evidence"
        }]
      ' <<<"$artifact_reasons")"
    fi
  elif [[ "$artifact_exists" == "1" ]]; then
    artifact_reasons="$(jq -c '
      . + [{
        code: "artifact_invalid_json",
        message: "cycle summary artifact is not a valid JSON object",
        action: "regenerate cycle summary artifact"
      }]
    ' <<<"$artifact_reasons")"
  fi

  if [[ "$artifact_valid_json" == "1" && ( "$artifact_schema_valid" == "1" || "$require_cycle_schema_valid" == "0" ) ]]; then
    if [[ "$artifact_status" == "pass" ]]; then
      status_pass_cycles=$((status_pass_cycles + 1))
    elif [[ "$artifact_status" == "warn" ]]; then
      status_warn_cycles=$((status_warn_cycles + 1))
    else
      status_fail_cycles=$((status_fail_cycles + 1))
      if [[ "$artifact_status" != "fail" ]]; then
        artifact_reasons="$(jq -c --arg status "$artifact_status" '
          . + [{
            code: "status_invalid",
            message: ("cycle status is missing or invalid (actual=" + (if $status == "" then "unset" else $status end) + ")"),
            action: "inspect cycle summary generation and rerun"
          }]
        ' <<<"$artifact_reasons")"
      fi
    fi
  else
    status_fail_cycles=$((status_fail_cycles + 1))
  fi

  if [[ "$artifact_valid_json" == "1" && ( "$artifact_schema_valid" == "1" || "$require_cycle_schema_valid" == "0" ) ]]; then
    artifact_contract_valid="0"
    if [[ "$artifact_decision" == "GO" && "$artifact_status" == "pass" && "$artifact_rc_json" == "0" ]]; then
      artifact_contract_valid="1"
    elif [[ "$artifact_decision" == "NO-GO" && "$artifact_status" == "warn" && "$artifact_rc_json" == "0" ]]; then
      artifact_contract_valid="1"
    elif [[ "$artifact_decision" == "NO-GO" && "$artifact_status" == "fail" && "$artifact_rc_json" != "0" && "$artifact_rc_json" != "null" ]]; then
      artifact_contract_valid="1"
    fi

    if [[ "$artifact_contract_valid" != "1" ]]; then
      cycle_contract_invalid_cycles=$((cycle_contract_invalid_cycles + 1))
      artifact_reasons="$(jq -c --arg decision "$artifact_decision" --arg status "$artifact_status" --arg rc "$artifact_rc_json" '
        . + [{
          code: "cycle_contract_invalid",
          message: (
            "cycle decision/status/rc contract invalid (decision="
            + (if $decision == "" then "unset" else $decision end)
            + " status="
            + (if $status == "" then "unset" else $status end)
            + " rc="
            + $rc
            + ")"
          ),
          action: "regenerate cycle artifact so GO=pass+rc=0 and NO-GO=(warn+rc=0 or fail+rc!=0)"
        }]
      ' <<<"$artifact_reasons")"
    fi
  fi

  if [[ "$artifact_valid_json" == "1" && ( "$artifact_schema_valid" == "1" || "$require_cycle_schema_valid" == "0" ) && "$artifact_contract_valid" == "1" && "$artifact_status" == "pass" && "$artifact_decision" == "GO" ]]; then
    if [[ "$artifact_check_policy_modal_decision" != "$require_check_policy_modal_decision" ]]; then
      artifact_promotion_candidate="false"
    else
      artifact_promotion_candidate="true"
      promotion_pass_cycles=$((promotion_pass_cycles + 1))
    fi
  fi

  cycle_entry="$(jq -n \
    --arg path "$cycle_path" \
    --arg exists "$artifact_exists" \
    --arg valid_json "$artifact_valid_json" \
    --arg schema_id "$artifact_schema_id" \
    --arg schema_valid "$artifact_schema_valid" \
    --arg status "$artifact_status" \
    --arg decision "$artifact_decision" \
    --argjson rc "$artifact_rc_json" \
    --arg check_policy_modal_decision "$artifact_check_policy_modal_decision" \
    --arg promotion_candidate "$artifact_promotion_candidate" \
    --argjson reasons "$artifact_reasons" \
    '{
      path: $path,
      exists: ($exists == "1"),
      valid_json: ($valid_json == "1"),
      schema_id: (if $schema_id == "" then null else $schema_id end),
      schema_valid: ($schema_valid == "1"),
      status: (if $status == "" then null else $status end),
      decision: (if $decision == "" then null else $decision end),
      rc: $rc,
      check_policy_modal_decision: (
        if $check_policy_modal_decision == "" then null
        else $check_policy_modal_decision
        end
      ),
      promotion_candidate: ($promotion_candidate == "true"),
      reasons: $reasons
    }')"
  cycles_json="$(jq -c --argjson entry "$cycle_entry" '. + [$entry]' <<<"$cycles_json")"
done

promotion_pass_rate_pct_json="$(jq -n \
  --argjson pass "$promotion_pass_cycles" \
  --argjson total "$total_cycles" \
  'if $total > 0 then (($pass * 100) / $total) else 0 end')"

go_decision_rate_pct_json="$(jq -n \
  --argjson go_count "$go_decision_cycles" \
  --argjson total "$total_cycles" \
  'if $total > 0 then (($go_count * 100) / $total) else 0 end')"

violations_json='[]'
declare -a errors=()

append_violation() {
  local code="$1"
  local field="$2"
  local message="$3"
  local action="$4"
  local required="$5"
  local observed="$6"
  local entry
  entry="$(jq -n \
    --arg code "$code" \
    --arg field "$field" \
    --arg message "$message" \
    --arg action "$action" \
    --arg required "$required" \
    --arg observed "$observed" \
    '{
      code: $code,
      field: $field,
      severity: "error",
      message: $message,
      action: $action,
      required: $required,
      observed: $observed
    }')"
  violations_json="$(jq -c --argjson entry "$entry" '. + [$entry]' <<<"$violations_json")"
  errors+=("$message")
}

if [[ "$cycle_summary_list_missing" == "1" ]]; then
  append_violation \
    "cycle_summary_list_missing" \
    "inputs.cycle_summary_list" \
    "cycle summary list file is missing" \
    "provide a valid --cycle-summary-list file or rerun promotion cycle to regenerate it" \
    "existing file path" \
    "$cycle_summary_list"
fi

if (( total_cycles < require_min_cycles )); then
  append_violation \
    "min_cycles_not_met" \
    "observed.cycles_total" \
    "insufficient cycle artifacts for promotion gate" \
    "capture additional multi-VM stability cycles and rerun promotion check" \
    ">=${require_min_cycles}" \
    "$total_cycles"
fi

if (( promotion_pass_cycles < require_min_pass_cycles )); then
  append_violation \
    "min_pass_cycles_not_met" \
    "observed.cycles_promotion_pass" \
    "insufficient promotion-pass cycle count" \
    "investigate failed/warn cycles and regenerate multi-VM evidence" \
    ">=${require_min_pass_cycles}" \
    "$promotion_pass_cycles"
fi

if (( status_fail_cycles > require_max_fail_cycles )); then
  append_violation \
    "max_fail_cycles_exceeded" \
    "observed.cycles_status_fail" \
    "cycle failure count exceeds allowed maximum" \
    "resolve failed multi-VM cycles before promotion" \
    "<=${require_max_fail_cycles}" \
    "$status_fail_cycles"
fi

if (( status_warn_cycles > require_max_warn_cycles )); then
  append_violation \
    "max_warn_cycles_exceeded" \
    "observed.cycles_status_warn" \
    "cycle warn count exceeds allowed maximum" \
    "reduce warn outcomes and rerun stability cycle capture" \
    "<=${require_max_warn_cycles}" \
    "$status_warn_cycles"
fi

if awk -v observed="$promotion_pass_rate_pct_json" -v required="$require_min_pass_rate_pct" 'BEGIN { exit !(observed < required) }'; then
  append_violation \
    "pass_rate_below_threshold" \
    "observed.promotion_pass_rate_pct" \
    "promotion-pass rate below threshold" \
    "improve cycle pass consistency before promotion" \
    ">=$require_min_pass_rate_pct%" \
    "${promotion_pass_rate_pct_json}%"
fi

if awk -v observed="$go_decision_rate_pct_json" -v required="$require_min_go_decision_rate_pct" 'BEGIN { exit !(observed < required) }'; then
  append_violation \
    "go_decision_rate_below_threshold" \
    "observed.go_decision_rate_pct" \
    "GO decision rate below threshold" \
    "address NO-GO decisions in stability check before promotion" \
    ">=$require_min_go_decision_rate_pct%" \
    "${go_decision_rate_pct_json}%"
fi

if [[ "$require_cycle_schema_valid" == "1" && "$cycle_schema_invalid_cycles" -gt 0 ]]; then
  append_violation \
    "cycle_schema_invalid" \
    "observed.cycle_schema_invalid_cycles" \
    "one or more cycles do not match the required cycle-summary schema" \
    "regenerate cycle artifacts with profile_compare_multi_vm_stability_cycle.sh" \
    "0" \
    "$cycle_schema_invalid_cycles"
fi

if [[ "$check_policy_modal_decision_mismatch_cycles" -gt 0 ]]; then
  append_violation \
    "check_policy_modal_decision_mismatch" \
    "observed.check_policy_modal_decision_mismatch_cycles" \
    "one or more cycles were produced with a mismatched check modal decision policy" \
    "rerun cycles with the required check modal decision policy" \
    "0 mismatches (required policy=$require_check_policy_modal_decision)" \
    "$check_policy_modal_decision_mismatch_cycles"
fi

if [[ "$cycle_contract_invalid_cycles" -gt 0 ]]; then
  append_violation \
    "cycle_contract_invalid" \
    "observed.cycle_contract_invalid_cycles" \
    "one or more cycles violate the required decision/status/rc contract" \
    "regenerate invalid cycle summaries so GO=pass+rc=0 and NO-GO=(warn+rc=0 or fail+rc!=0)" \
    "0" \
    "$cycle_contract_invalid_cycles"
fi

decision="GO"
status="ok"
notes="repeated multi-VM stability cycle artifacts satisfy promotion policy thresholds"
if [[ "$(jq -r 'length' <<<"$violations_json")" -gt 0 ]]; then
  decision="NO-GO"
  status="fail"
  notes="one or more multi-VM promotion policy thresholds are violated"
fi

failure_reason=""
failure_reason_code=""
if [[ "$decision" == "NO-GO" ]]; then
  failure_reason="$(jq -r 'if (type == "array") and (length > 0) and (.[0].message | type) == "string" then .[0].message else "" end' <<<"$violations_json" 2>/dev/null || printf '%s' "")"
  failure_reason_code="$(jq -r 'if (type == "array") and (length > 0) and (.[0].code | type) == "string" then .[0].code else "" end' <<<"$violations_json" 2>/dev/null || printf '%s' "")"
fi

operator_next_action="$(jq -r '
  if (length > 0) then
    "Hold promotion. " + .[0].action + ". Re-run profile_compare_multi_vm_stability_cycle.sh and this promotion check after remediation."
  else
    "Promotion may proceed. Continue collecting periodic multi-VM stability cycles."
  end
' <<<"$violations_json")"
operator_next_action_command="$(quote_cmd bash ./scripts/profile_compare_multi_vm_stability_promotion_check.sh --reports-dir "$reports_dir" --summary-json "$summary_json" --print-summary-json 1)"
operator_next_action_command="$(trim "$operator_next_action_command")"

rc=0
if [[ "$decision" == "NO-GO" && "$fail_on_no_go" == "1" ]]; then
  rc=1
fi

errors_json='[]'
if ((${#errors[@]} > 0)); then
  errors_json="$(printf '%s\n' "${errors[@]}" | jq -R . | jq -s '.')"
fi

cycle_summary_paths_json='[]'
if ((${#cycle_summary_paths[@]} > 0)); then
  cycle_summary_paths_json="$(printf '%s\n' "${cycle_summary_paths[@]}" | jq -R . | jq -s '.')"
fi

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg decision "$decision" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg failure_reason "$failure_reason" \
  --arg failure_reason_code "$failure_reason_code" \
  --arg operator_next_action "$operator_next_action" \
  --arg operator_next_action_command "$operator_next_action_command" \
  --arg reports_dir "$reports_dir" \
  --arg cycle_summary_list "$cycle_summary_list" \
  --arg cycle_summary_list_missing "$cycle_summary_list_missing" \
  --arg summary_json "$summary_json" \
  --argjson rc "$rc" \
  --argjson cycle_summary_paths "$cycle_summary_paths_json" \
  --argjson require_min_cycles "$require_min_cycles" \
  --argjson require_min_pass_cycles "$require_min_pass_cycles" \
  --argjson require_max_fail_cycles "$require_max_fail_cycles" \
  --argjson require_max_warn_cycles "$require_max_warn_cycles" \
  --argjson require_min_pass_rate_pct "$require_min_pass_rate_pct" \
  --argjson require_min_go_decision_rate_pct "$require_min_go_decision_rate_pct" \
  --argjson require_cycle_schema_valid "$require_cycle_schema_valid" \
  --arg require_check_policy_modal_decision "$require_check_policy_modal_decision" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --argjson cycles_total "$total_cycles" \
  --argjson cycles_status_pass "$status_pass_cycles" \
  --argjson cycles_status_warn "$status_warn_cycles" \
  --argjson cycles_status_fail "$status_fail_cycles" \
  --argjson cycles_promotion_pass "$promotion_pass_cycles" \
  --argjson go_decision_cycles "$go_decision_cycles" \
  --argjson no_go_decision_cycles "$no_go_decision_cycles" \
  --argjson usable_decision_cycles "$usable_decision_cycles" \
  --argjson cycle_schema_invalid_cycles "$cycle_schema_invalid_cycles" \
  --argjson check_policy_modal_decision_mismatch_cycles "$check_policy_modal_decision_mismatch_cycles" \
  --argjson cycle_contract_invalid_cycles "$cycle_contract_invalid_cycles" \
  --argjson promotion_pass_rate_pct "$promotion_pass_rate_pct_json" \
  --argjson go_decision_rate_pct "$go_decision_rate_pct_json" \
  --argjson cycles "$cycles_json" \
  --argjson violations "$violations_json" \
  --argjson errors "$errors_json" \
  '{
    version: 1,
    schema: {
      id: "profile_compare_multi_vm_stability_promotion_check_summary"
    },
    generated_at_utc: $generated_at_utc,
    decision: $decision,
    status: $status,
    rc: $rc,
    notes: $notes,
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    failure_reason_code: (if $failure_reason_code == "" then null else $failure_reason_code end),
    operator_next_action: $operator_next_action,
    operator_next_action_command: (
      if $operator_next_action_command == "" then null
      else $operator_next_action_command
      end
    ),
    inputs: {
      reports_dir: $reports_dir,
      cycle_summary_list: (
        if $cycle_summary_list == "" then null
        else $cycle_summary_list
        end
      ),
      cycle_summary_list_missing: ($cycle_summary_list_missing == "1"),
      cycle_summary_paths: $cycle_summary_paths,
      policy: {
        require_min_cycles: $require_min_cycles,
        require_min_pass_cycles: $require_min_pass_cycles,
        require_max_fail_cycles: $require_max_fail_cycles,
        require_max_warn_cycles: $require_max_warn_cycles,
        require_min_pass_rate_pct: $require_min_pass_rate_pct,
        require_min_go_decision_rate_pct: $require_min_go_decision_rate_pct,
        require_cycle_schema_valid: ($require_cycle_schema_valid == 1),
        require_check_policy_modal_decision: (
          if $require_check_policy_modal_decision == "" then null
          else $require_check_policy_modal_decision
          end
        ),
        fail_on_no_go: ($fail_on_no_go == 1)
      }
    },
    observed: {
      cycles_total: $cycles_total,
      cycles_status_pass: $cycles_status_pass,
      cycles_status_warn: $cycles_status_warn,
      cycles_status_fail: $cycles_status_fail,
      cycles_promotion_pass: $cycles_promotion_pass,
      promotion_pass_rate_pct: $promotion_pass_rate_pct,
      go_decision_cycles: $go_decision_cycles,
      no_go_decision_cycles: $no_go_decision_cycles,
      usable_decision_cycles: $usable_decision_cycles,
      go_decision_rate_pct: $go_decision_rate_pct,
      cycle_schema_invalid_cycles: $cycle_schema_invalid_cycles,
      check_policy_modal_decision_mismatch_cycles: $check_policy_modal_decision_mismatch_cycles,
      cycle_contract_invalid_cycles: $cycle_contract_invalid_cycles,
      cycle_summary_list_missing: ($cycle_summary_list_missing == "1")
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
      should_promote: ($decision == "GO"),
      action: (
        if $decision == "GO" then "promote_allowed"
        elif $fail_on_no_go == 1 then "hold_promotion_blocked"
        else "hold_promotion_warn_only"
        end
      ),
      next_operator_action: $operator_next_action
    },
    violations: $violations,
    errors: $errors,
    cycles: $cycles,
    artifacts: {
      summary_json: $summary_json
    }
  }' >"$summary_json"

echo "[profile-compare-multi-vm-stability-promotion-check] decision=$decision status=$status rc=$rc cycles_total=$total_cycles promotion_pass_cycles=$promotion_pass_cycles pass_rate_pct=$promotion_pass_rate_pct_json go_decision_rate_pct=$go_decision_rate_pct_json"
if [[ "$(jq -r 'length' <<<"$violations_json")" -gt 0 ]]; then
  echo "[profile-compare-multi-vm-stability-promotion-check] failed with $(jq -r 'length' <<<"$violations_json") violation(s):"
  jq -r '.[] | "  - [" + .code + "] " + .message' <<<"$violations_json"
fi

if [[ "$show_json" == "1" ]]; then
  echo "[profile-compare-multi-vm-stability-promotion-check] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
