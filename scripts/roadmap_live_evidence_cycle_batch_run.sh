#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--iterations N] \
    [--continue-on-fail [0|1]] \
    [--parallel [0|1]] \
    [--include-track-id ID] \
    [--exclude-track-id ID] \
    [--print-summary-json [0|1]]

Purpose:
  Run deterministic repeated evidence cycles for roadmap live-evidence tracks.
  Default tracks:
    - profile_default_gate_stability_cycle
    - runtime_actuation_promotion_cycle
    - profile_compare_multi_vm_stability_promotion_cycle

Defaults:
  --iterations 1
  --continue-on-fail 0
  --parallel 0
  --print-summary-json 1

Track path overrides:
  ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT
  ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT
  ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT

Failure diagnostics:
  ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_FAILURE_LOG_TAIL_LINES (default: 20)

Runtime input fallback summary override:
  ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_ROADMAP_PROGRESS_SUMMARY_JSON (default: .easy-node-logs/roadmap_progress_summary.json)

Exit behavior:
  - With --continue-on-fail=0, stop after first failed track result.
  - With --continue-on-fail=1, execute all selected tracks for all iterations.
  - Fails closed when no tracks are selected after filtering.
  - Final rc is the first non-zero track rc in deterministic iteration/track order, else 0.
USAGE
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

strip_optional_wrapping_quotes_01() {
  local value="${1:-}"
  local first_char=""
  local last_char=""
  if (( ${#value} < 2 )); then
    printf '%s' "$value"
    return
  fi
  first_char="${value:0:1}"
  last_char="${value: -1}"
  if [[ "$first_char" == '"' && "$last_char" == '"' ]]; then
    value="${value:1:${#value}-2}"
  elif [[ "$first_char" == "'" && "$last_char" == "'" ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf '%s' "$value"
}

is_runtime_placeholder_token_01() {
  local value=""
  local normalized=""
  value="$(trim "${1:-}")"
  value="$(strip_optional_wrapping_quotes_01 "$value")"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    return 1
  fi
  normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  case "$normalized" in
    INVITE_KEY|CAMPAIGN_SUBJECT|A_HOST|B_HOST|HOST_A|HOST_B|REPLACE_WITH_INVITE_KEY|REPLACE_WITH_INVITE_SUBJECT|REPLACE_WITH_CAMPAIGN_SUBJECT|REPLACE_WITH_HOST_A|REPLACE_WITH_HOST_B|REPLACE_WITH_VM_COMMAND_FILE|"<SET-REAL-INVITE-KEY>"|SET-REAL-INVITE-KEY|"<INVITE_KEY>"|"<CAMPAIGN_SUBJECT>"|"<HOST_A>"|"<HOST_B>"|\$\{INVITE_KEY\}|\$INVITE_KEY|\$\{CAMPAIGN_SUBJECT\}|\$CAMPAIGN_SUBJECT|\$\{A_HOST\}|\$A_HOST|\$\{B_HOST\}|\$B_HOST|%INVITE_KEY%|%CAMPAIGN_SUBJECT%)
      return 0
      ;;
    *)
      ;;
  esac
  if [[ "$normalized" == *"PLACEHOLDER"* || "$normalized" == *"REPLACE_WITH_"* ]]; then
    return 0
  fi
  return 1
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
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
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
    echo "$name must be an integer"
    exit 2
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

parse_id_list_arg() {
  local value="$1"
  local -n out_ref="$2"
  local item
  IFS=',' read -r -a _items <<<"$value"
  for item in "${_items[@]}"; do
    item="$(trim "$item")"
    if [[ -n "$item" ]]; then
      out_ref+=("$item")
    fi
  done
}

log_tail_window_json() {
  local log_path="${1:-}"
  local max_lines="${2:-0}"
  local total_line_count=0
  local -a tail_lines=()
  local line
  if [[ "$max_lines" =~ ^[0-9]+$ ]] && (( max_lines > 0 )) && [[ -f "$log_path" && -r "$log_path" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      total_line_count=$((total_line_count + 1))
      tail_lines+=("$line")
      if (( ${#tail_lines[@]} > max_lines )); then
        tail_lines=("${tail_lines[@]:1}")
      fi
    done < "$log_path"
  fi

  local tail_lines_json='[]'
  if (( ${#tail_lines[@]} > 0 )); then
    tail_lines_json="$(printf '%s\n' "${tail_lines[@]}" | jq -R . | jq -s .)"
  fi
  local line_count="${#tail_lines[@]}"
  local truncated_json="false"
  if (( total_line_count > line_count )); then
    truncated_json="true"
  fi

  jq -cn \
    --argjson lines "$tail_lines_json" \
    --argjson line_count "$line_count" \
    --argjson total_line_count "$total_line_count" \
    --argjson truncated "$truncated_json" \
    '{
      log_tail_lines: $lines,
      log_tail_line_count: $line_count,
      log_total_line_count: $total_line_count,
      log_tail_truncated: $truncated
    }'
}

augment_result_file_with_failure_diagnostics() {
  local result_path="$1"
  if [[ ! -s "$result_path" ]] || ! jq -e . "$result_path" >/dev/null 2>&1; then
    return
  fi
  local status
  status="$(jq -r '.status // ""' "$result_path")"
  if [[ "$status" != "fail" ]]; then
    return
  fi
  local log_path
  log_path="$(jq -r '.log // .artifacts.log // ""' "$result_path")"
  local track_id
  local rc
  track_id="$(jq -r '.track_id // ""' "$result_path")"
  rc="$(jq -r '.rc // 1' "$result_path")"
  if ! [[ "$rc" =~ ^-?[0-9]+$ ]]; then
    rc=1
  fi
  local log_tail_json
  local failure_classification_json
  local failure_diagnostics_json
  log_tail_json="$(log_tail_window_json "$log_path" "$failure_log_tail_lines")"
  failure_classification_json="$(classify_track_failure_json "$track_id" "$rc" "$log_path")"
  failure_diagnostics_json="$(jq -cn --argjson c "$failure_classification_json" --argjson l "$log_tail_json" '$c + $l')"
  local updated_json
  updated_json="$(jq -c --argjson failure_diagnostics "$failure_diagnostics_json" '. + {failure_diagnostics: $failure_diagnostics}' "$result_path")"
  printf '%s\n' "$updated_json" >"$result_path"
}

need_cmd jq
need_cmd bash
need_cmd date
need_cmd mktemp

reports_dir="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_REPORTS_DIR:-}"
summary_json="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_SUMMARY_JSON:-}"
iterations="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_ITERATIONS:-1}"
continue_on_fail="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_CONTINUE_ON_FAIL:-0}"
parallel="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_PARALLEL:-0}"
print_summary_json="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_PRINT_SUMMARY_JSON:-1}"
failure_log_tail_lines="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_FAILURE_LOG_TAIL_LINES:-20}"
roadmap_progress_summary_json="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_ROADMAP_PROGRESS_SUMMARY_JSON:-.easy-node-logs/roadmap_progress_summary.json}"

declare -a include_track_ids=()
declare -a exclude_track_ids=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      require_value_or_die "$1" "${2:-}"
      reports_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      require_value_or_die "$1" "${2:-}"
      summary_json="${2:-}"
      shift 2
      ;;
    --iterations)
      require_value_or_die "$1" "${2:-}"
      iterations="${2:-}"
      shift 2
      ;;
    --continue-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        continue_on_fail="${2:-}"
        shift 2
      else
        continue_on_fail="1"
        shift
      fi
      ;;
    --parallel)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        parallel="${2:-}"
        shift 2
      else
        parallel="1"
        shift
      fi
      ;;
    --include-track-id)
      require_value_or_die "$1" "${2:-}"
      parse_id_list_arg "${2:-}" include_track_ids
      shift 2
      ;;
    --exclude-track-id)
      require_value_or_die "$1" "${2:-}"
      parse_id_list_arg "${2:-}" exclude_track_ids
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
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg: $1"
      usage
      exit 2
      ;;
  esac
done

int_arg_or_die "--iterations" "$iterations"
if (( iterations < 1 )); then
  echo "--iterations must be >= 1"
  exit 2
fi
bool_arg_or_die "--continue-on-fail" "$continue_on_fail"
bool_arg_or_die "--parallel" "$parallel"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
int_arg_or_die "--failure-log-tail-lines" "$failure_log_tail_lines"

include_track_ids_requested_count="${#include_track_ids[@]}"
exclude_track_ids_requested_count="${#exclude_track_ids[@]}"

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/roadmap_live_evidence_cycle_batch_run_${run_stamp}"
fi
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/roadmap_live_evidence_cycle_batch_run_summary.json"
fi
summary_json="$(abs_path "$summary_json")"
mkdir -p "$(dirname "$summary_json")"
roadmap_progress_summary_json="$(abs_path "$roadmap_progress_summary_json")"

default_track_ids_json='[
  "profile_default_gate_stability_cycle",
  "runtime_actuation_promotion_cycle",
  "profile_compare_multi_vm_stability_promotion_cycle"
]'

declare -a default_track_ids=(
  "profile_default_gate_stability_cycle"
  "runtime_actuation_promotion_cycle"
  "profile_compare_multi_vm_stability_promotion_cycle"
)

profile_default_gate_stability_cycle_script="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_stability_cycle.sh}"
runtime_actuation_promotion_cycle_script="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT:-$ROOT_DIR/scripts/runtime_actuation_promotion_cycle.sh}"
profile_compare_multi_vm_stability_promotion_cycle_script="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_promotion_cycle.sh}"

track_id_exists() {
  local id="$1"
  case "$id" in
    profile_default_gate_stability_cycle|runtime_actuation_promotion_cycle|profile_compare_multi_vm_stability_promotion_cycle)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

track_script_for_id() {
  local id="$1"
  case "$id" in
    profile_default_gate_stability_cycle)
      printf '%s' "$profile_default_gate_stability_cycle_script"
      ;;
    runtime_actuation_promotion_cycle)
      printf '%s' "$runtime_actuation_promotion_cycle_script"
      ;;
    profile_compare_multi_vm_stability_promotion_cycle)
      printf '%s' "$profile_compare_multi_vm_stability_promotion_cycle_script"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

append_unique_id() {
  local id="$1"
  local -n out_ref="$2"
  local existing
  for existing in "${out_ref[@]:-}"; do
    if [[ "$existing" == "$id" ]]; then
      return
    fi
  done
  out_ref+=("$id")
}

json_array_from_ref() {
  local -n arr_ref="$1"
  local out='[]'
  local value
  for value in "${arr_ref[@]}"; do
    out="$(jq -c --arg v "$value" '. + [$v]' <<<"$out")"
  done
  printf '%s' "$out"
}

roadmap_summary_next_action_commands_cache_ready="0"
roadmap_summary_next_action_commands_json_cache='[]'
roadmap_runtime_input_fallback_last_value=""
roadmap_runtime_input_fallback_last_source=""
roadmap_runtime_input_fallback_last_placeholder_detected="0"

load_roadmap_summary_next_action_commands_cache_01() {
  local extracted_json="[]"
  if [[ "$roadmap_summary_next_action_commands_cache_ready" == "1" ]]; then
    return
  fi
  roadmap_summary_next_action_commands_cache_ready="1"
  roadmap_summary_next_action_commands_json_cache='[]'

  if [[ -z "$roadmap_progress_summary_json" ]]; then
    return
  fi
  if [[ ! -f "$roadmap_progress_summary_json" || ! -r "$roadmap_progress_summary_json" ]]; then
    return
  fi
  if ! extracted_json="$(jq -c '
    if type == "object" then
      [(.next_actions // [])[] | (.command? // empty) | strings]
    else
      []
    end
  ' "$roadmap_progress_summary_json" 2>/dev/null)"; then
    return
  fi
  if jq -e 'type == "array"' <<<"$extracted_json" >/dev/null 2>&1; then
    roadmap_summary_next_action_commands_json_cache="$extracted_json"
  fi
}

extract_flag_value_from_command_01() {
  local cmd="$1"
  local flag="$2"
  local value=""
  if [[ -z "$cmd" || -z "$flag" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$cmd" =~ (^|[[:space:]])${flag}=([^[:space:]]+) ]]; then
    value="${BASH_REMATCH[2]}"
    value="$(strip_optional_wrapping_quotes_01 "$value")"
    printf '%s' "$(trim "$value")"
    return
  fi
  if [[ "$cmd" =~ (^|[[:space:]])${flag}[[:space:]]+([^[:space:]]+) ]]; then
    value="${BASH_REMATCH[2]}"
    value="$(strip_optional_wrapping_quotes_01 "$value")"
    printf '%s' "$(trim "$value")"
    return
  fi
  printf '%s' ""
}

extract_env_assignment_value_from_command_01() {
  local cmd="$1"
  local env_name="$2"
  local value=""
  if [[ -z "$cmd" || -z "$env_name" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$cmd" =~ (^|[[:space:]])${env_name}=([^[:space:]]+) ]]; then
    value="${BASH_REMATCH[2]}"
    value="$(strip_optional_wrapping_quotes_01 "$value")"
    printf '%s' "$(trim "$value")"
    return
  fi
  printf '%s' ""
}

roadmap_summary_command_matches_track_scope_01() {
  local track_id="$1"
  local cmd="$2"
  case "$track_id" in
    profile_default_gate_stability_cycle)
      if [[ "$cmd" == *"profile-default-gate-stability-cycle"* ]] \
         || [[ "$cmd" == *"profile-default-gate-stability-run"* ]] \
         || [[ "$cmd" == *"profile_default_gate_stability_cycle.sh"* ]] \
         || [[ "$cmd" == *"profile_default_gate_stability_run.sh"* ]]; then
        return 0
      fi
      ;;
    runtime_actuation_promotion_cycle)
      if [[ "$cmd" == *"runtime-actuation-promotion-cycle"* ]] \
         || [[ "$cmd" == *"runtime_actuation_promotion_cycle.sh"* ]]; then
        return 0
      fi
      ;;
    *)
      ;;
  esac
  return 1
}

resolve_runtime_input_from_roadmap_summary_01() {
  local track_id="$1"
  local input_id="$2"
  local cmd=""
  local value=""
  roadmap_runtime_input_fallback_last_value=""
  roadmap_runtime_input_fallback_last_source=""
  roadmap_runtime_input_fallback_last_placeholder_detected="0"

  load_roadmap_summary_next_action_commands_cache_01
  while IFS= read -r cmd || [[ -n "$cmd" ]]; do
    cmd="$(trim "$cmd")"
    if [[ -z "$cmd" ]]; then
      continue
    fi
    if ! roadmap_summary_command_matches_track_scope_01 "$track_id" "$cmd"; then
      continue
    fi

    value=""
    case "$input_id" in
      host_a)
        value="$(extract_flag_value_from_command_01 "$cmd" "--host-a")"
        if [[ -z "$value" ]]; then
          value="$(extract_env_assignment_value_from_command_01 "$cmd" "PROFILE_DEFAULT_GATE_STABILITY_HOST_A")"
        fi
        if [[ -z "$value" ]]; then
          value="$(extract_env_assignment_value_from_command_01 "$cmd" "A_HOST")"
        fi
        ;;
      host_b)
        value="$(extract_flag_value_from_command_01 "$cmd" "--host-b")"
        if [[ -z "$value" ]]; then
          value="$(extract_env_assignment_value_from_command_01 "$cmd" "PROFILE_DEFAULT_GATE_STABILITY_HOST_B")"
        fi
        if [[ -z "$value" ]]; then
          value="$(extract_env_assignment_value_from_command_01 "$cmd" "B_HOST")"
        fi
        ;;
      campaign_subject)
        value="$(extract_flag_value_from_command_01 "$cmd" "--campaign-subject")"
        if [[ -z "$value" ]]; then
          value="$(extract_flag_value_from_command_01 "$cmd" "--subject")"
        fi
        if [[ -z "$value" ]]; then
          value="$(extract_flag_value_from_command_01 "$cmd" "--key")"
        fi
        if [[ -z "$value" ]]; then
          value="$(extract_flag_value_from_command_01 "$cmd" "--invite-key")"
        fi
        if [[ -z "$value" ]]; then
          value="$(extract_env_assignment_value_from_command_01 "$cmd" "PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT")"
        fi
        if [[ -z "$value" ]]; then
          value="$(extract_env_assignment_value_from_command_01 "$cmd" "CAMPAIGN_SUBJECT")"
        fi
        if [[ -z "$value" ]]; then
          value="$(extract_env_assignment_value_from_command_01 "$cmd" "INVITE_KEY")"
        fi
        ;;
      *)
        value=""
        ;;
    esac

    value="$(trim "$value")"
    if [[ -z "$value" ]]; then
      continue
    fi
    if is_runtime_placeholder_token_01 "$value"; then
      roadmap_runtime_input_fallback_last_placeholder_detected="1"
      continue
    fi
    roadmap_runtime_input_fallback_last_value="$value"
    roadmap_runtime_input_fallback_last_source="roadmap_summary:next_actions"
    return 0
  done < <(jq -r '.[]' <<<"$roadmap_summary_next_action_commands_json_cache" 2>/dev/null || true)
  return 1
}

resolve_runtime_input_state_json() {
  local track_id="$1"
  local input_id="$2"
  local required_flag="$3"
  local description="$4"
  local operator_hint="$5"
  shift 5
  local -a env_candidates=("$@")
  local -a placeholder_envs=()
  local env_name=""
  local env_value=""
  local resolved_env=""
  local resolved_fallback_value=""
  local fallback_placeholder_detected="0"
  local state="missing"
  local resolution_source=""

  for env_name in "${env_candidates[@]}"; do
    env_value="$(trim "${!env_name:-}")"
    if [[ -z "$env_value" ]]; then
      continue
    fi
    if is_runtime_placeholder_token_01 "$env_value"; then
      placeholder_envs+=("$env_name")
      continue
    fi
    resolved_env="$env_name"
    break
  done

  if [[ -n "$resolved_env" ]]; then
    state="resolved"
    resolution_source="env:${resolved_env}"
  else
    resolve_runtime_input_from_roadmap_summary_01 "$track_id" "$input_id"
    resolved_fallback_value="$roadmap_runtime_input_fallback_last_value"
    fallback_placeholder_detected="$roadmap_runtime_input_fallback_last_placeholder_detected"
    if [[ -n "$resolved_fallback_value" ]]; then
      state="resolved"
      resolution_source="$roadmap_runtime_input_fallback_last_source"
    elif (( ${#placeholder_envs[@]} > 0 )) || [[ "$fallback_placeholder_detected" == "1" ]]; then
      state="placeholder_unresolved"
    fi
  fi

  local env_candidates_json
  local placeholder_envs_json
  local value_present_json="false"
  env_candidates_json="$(json_array_from_ref env_candidates)"
  placeholder_envs_json="$(json_array_from_ref placeholder_envs)"
  if [[ "$state" != "missing" ]]; then
    value_present_json="true"
  fi

  jq -cn \
    --arg id "$input_id" \
    --argjson required "$required_flag" \
    --arg description "$description" \
    --arg operator_hint "$operator_hint" \
    --arg state "$state" \
    --arg resolution_source "$resolution_source" \
    --argjson env_candidates "$env_candidates_json" \
    --argjson placeholder_envs "$placeholder_envs_json" \
    --argjson value_present "$value_present_json" \
    '{
      id: $id,
      required: $required,
      description: $description,
      state: $state,
      resolution_source: (if $resolution_source == "" then null else $resolution_source end),
      value_present: $value_present,
      env_candidates: $env_candidates,
      placeholder_envs: $placeholder_envs,
      operator_hint: $operator_hint
    }'
}

m5_validate_vm_command_source_file_or_reason_01() {
  local path=""
  local line=""
  local line_number=0
  local vm_id=""
  local vm_command=""
  local vm_id_key=""
  local vm_command_existing=""
  local runnable_specs=0
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s\n' "empty_path"
    return 1
  fi
  if is_runtime_placeholder_token_01 "$path"; then
    printf '%s\n' "placeholder_path"
    return 1
  fi
  if [[ ! -f "$path" ]]; then
    printf '%s\n' "not_found"
    return 1
  fi
  if [[ ! -r "$path" ]]; then
    printf '%s\n' "not_readable"
    return 1
  fi

  declare -A vm_command_by_id=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    line="$(trim "$line")"
    if [[ -z "$line" || "$line" == \#* ]]; then
      continue
    fi
    if [[ "$line" != *"::"* ]]; then
      printf '%s\n' "invalid_vm_command_spec_line_${line_number}_missing_delimiter"
      return 1
    fi
    vm_id="$(trim "${line%%::*}")"
    vm_command="$(trim "${line#*::}")"
    if [[ -z "$vm_id" || -z "$vm_command" ]]; then
      printf '%s\n' "invalid_vm_command_spec_line_${line_number}_empty_vm_or_command"
      return 1
    fi
    if [[ "$vm_id" =~ [[:space:]] ]]; then
      printf '%s\n' "invalid_vm_command_spec_line_${line_number}_vm_id_contains_whitespace"
      return 1
    fi
    vm_id_key="$vm_id"
    if [[ -n "${vm_command_by_id["$vm_id_key"]+present}" ]]; then
      vm_command_existing="${vm_command_by_id["$vm_id_key"]}"
      if [[ "$vm_command_existing" != "$vm_command" ]]; then
        printf '%s\n' "invalid_vm_command_spec_line_${line_number}_duplicate_vm_id_conflict"
        return 1
      fi
      continue
    fi
    vm_command_by_id["$vm_id_key"]="$vm_command"
    runnable_specs=$((runnable_specs + 1))
  done <"$path"
  if (( runnable_specs < 1 )); then
    printf '%s\n' "no_runnable_specs"
    return 1
  fi
  printf '%s\n' "ready"
  return 0
}

collect_m5_vm_command_candidate_dirs_01() {
  local reports_dir_abs=""
  local reports_dir_basename=""
  local parent_dir=""
  local grandparent_dir=""
  declare -A seen_dirs=()
  declare -a candidate_dirs=()

  reports_dir_abs="$(abs_path "$reports_dir")"
  if [[ -n "$reports_dir_abs" && -z "${seen_dirs["$reports_dir_abs"]+present}" ]]; then
    candidate_dirs+=("$reports_dir_abs")
    seen_dirs["$reports_dir_abs"]=1
  fi

  reports_dir_basename="$(basename "$reports_dir_abs")"
  if [[ "$reports_dir_basename" == cycle_* || "$reports_dir_basename" == run_* ||
        "$reports_dir_abs" == *"/profile_compare_multi_vm_stability_run_"*"/"* ||
        "$reports_dir_abs" == *"/profile_compare_multi_vm_stability_promotion_cycle_"*"/"* ]]; then
    parent_dir="$(abs_path "$(dirname "$reports_dir_abs")")"
    if [[ -n "$parent_dir" && "$parent_dir" != "/" && -z "${seen_dirs["$parent_dir"]+present}" ]]; then
      candidate_dirs+=("$parent_dir")
      seen_dirs["$parent_dir"]=1
    fi
    if [[ -n "$parent_dir" && "$parent_dir" != "/" ]]; then
      grandparent_dir="$(abs_path "$(dirname "$parent_dir")")"
      if [[ -n "$grandparent_dir" && "$grandparent_dir" != "/" && -z "${seen_dirs["$grandparent_dir"]+present}" ]]; then
        candidate_dirs+=("$grandparent_dir")
        seen_dirs["$grandparent_dir"]=1
      fi
    fi
  fi

  printf '%s\n' "${candidate_dirs[@]}"
}

resolve_m5_vm_command_source_runtime_input_state_json() {
  local input_id="vm_command_source"
  local required_flag="true"
  local description="Concrete VM command source for multi-VM stability cycle (--vm-command/--vm-command-file fallback)."
  local operator_hint="Provide a readable VM command source via PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE (or related envs) or recognized reports-dir artifacts, then rerun."
  local -a env_candidates=(
    "PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE"
    "PROFILE_COMPARE_MULTI_VM_STABILITY_VM_COMMAND_FILE"
    "PROFILE_COMPARE_MULTI_VM_VM_COMMAND_FILE"
  )
  local -a legacy_artifact_names=(
    "profile_compare_multi_vm_vm_commands.txt"
    "vm_commands.txt"
  )
  local -a candidate_dirs=()
  local -a placeholder_envs=()
  local -a artifact_candidates=()
  local env_name=""
  local env_value=""
  local candidate_dir=""
  local candidate_path=""
  local artifact_name=""
  local validation_reason=""
  local resolution_source=""
  local resolution_path=""
  local state="missing"
  local line=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim "$line")"
    if [[ -n "$line" ]]; then
      candidate_dirs+=("$line")
    fi
  done < <(collect_m5_vm_command_candidate_dirs_01)

  for candidate_dir in "${candidate_dirs[@]}"; do
    candidate_path="$(abs_path "$candidate_dir/profile_compare_multi_vm_stability_vm_commands.txt")"
    append_unique_id "$candidate_path" artifact_candidates
    if validation_reason="$(m5_validate_vm_command_source_file_or_reason_01 "$candidate_path")"; then
      resolution_source="reports-dir-canonical"
      if [[ "$candidate_dir" != "$(abs_path "$reports_dir")" ]]; then
        resolution_source="reports-dir-canonical-candidate"
      fi
      resolution_path="$candidate_path"
      break
    fi
  done

  if [[ -z "$resolution_path" ]]; then
    for env_name in "${env_candidates[@]}"; do
      env_value="$(trim "${!env_name:-}")"
      if [[ -z "$env_value" ]]; then
        continue
      fi
      if is_runtime_placeholder_token_01 "$env_value"; then
        placeholder_envs+=("$env_name")
        continue
      fi
      candidate_path="$(abs_path "$env_value")"
      append_unique_id "$candidate_path" artifact_candidates
      if validation_reason="$(m5_validate_vm_command_source_file_or_reason_01 "$candidate_path")"; then
        resolution_source="env:${env_name}"
        resolution_path="$candidate_path"
        break
      fi
      if [[ "$validation_reason" == "placeholder_path" ]]; then
        placeholder_envs+=("$env_name")
      fi
    done
  fi

  if [[ -z "$resolution_path" ]]; then
    for candidate_dir in "${candidate_dirs[@]}"; do
      for artifact_name in "${legacy_artifact_names[@]}"; do
        candidate_path="$(abs_path "$candidate_dir/$artifact_name")"
        append_unique_id "$candidate_path" artifact_candidates
        if validation_reason="$(m5_validate_vm_command_source_file_or_reason_01 "$candidate_path")"; then
          resolution_source="reports-dir-legacy"
          if [[ "$candidate_dir" != "$(abs_path "$reports_dir")" ]]; then
            resolution_source="reports-dir-legacy-candidate"
          fi
          resolution_path="$candidate_path"
          break
        fi
      done
      if [[ -n "$resolution_path" ]]; then
        break
      fi
    done
  fi

  if [[ -n "$resolution_path" ]]; then
    state="resolved"
  elif (( ${#placeholder_envs[@]} > 0 )); then
    state="placeholder_unresolved"
  fi

  local env_candidates_json
  local placeholder_envs_json
  local artifact_candidates_json
  local value_present_json="false"
  env_candidates_json="$(json_array_from_ref env_candidates)"
  placeholder_envs_json="$(json_array_from_ref placeholder_envs)"
  artifact_candidates_json="$(json_array_from_ref artifact_candidates)"
  if [[ "$state" != "missing" ]]; then
    value_present_json="true"
  fi

  jq -cn \
    --arg id "$input_id" \
    --argjson required "$required_flag" \
    --arg description "$description" \
    --arg operator_hint "$operator_hint" \
    --arg state "$state" \
    --arg resolution_source "$resolution_source" \
    --arg resolution_path "$resolution_path" \
    --argjson env_candidates "$env_candidates_json" \
    --argjson placeholder_envs "$placeholder_envs_json" \
    --argjson artifact_candidates "$artifact_candidates_json" \
    --argjson value_present "$value_present_json" \
    '{
      id: $id,
      required: $required,
      description: $description,
      state: $state,
      resolution_source: (if $resolution_source == "" then null else $resolution_source end),
      resolution_path: (if $resolution_path == "" then null else $resolution_path end),
      value_present: $value_present,
      env_candidates: $env_candidates,
      placeholder_envs: $placeholder_envs,
      artifact_candidates: $artifact_candidates,
      operator_hint: $operator_hint
    }'
}

build_track_runtime_requirements_json() {
  local track_id="$1"
  local track_group="$track_id"
  local track_note=""
  local requirements_json='[]'
  local unresolved_required_inputs_json='[]'
  local unresolved_required_count=0
  local status="ready_or_dynamic"
  local row_json=""

  case "$track_id" in
    profile_default_gate_stability_cycle)
      track_group="m2_profile_default_gate_stability"
      row_json="$(resolve_runtime_input_state_json \
        "profile_default_gate_stability_cycle" \
        "host_a" "true" \
        "Real host/IP for lane A." \
        "Set PROFILE_DEFAULT_GATE_STABILITY_HOST_A or A_HOST to a concrete host." \
        "PROFILE_DEFAULT_GATE_STABILITY_HOST_A" "A_HOST")"
      requirements_json="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$requirements_json")"
      row_json="$(resolve_runtime_input_state_json \
        "profile_default_gate_stability_cycle" \
        "host_b" "true" \
        "Real host/IP for lane B." \
        "Set PROFILE_DEFAULT_GATE_STABILITY_HOST_B or B_HOST to a concrete host." \
        "PROFILE_DEFAULT_GATE_STABILITY_HOST_B" "B_HOST")"
      requirements_json="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$requirements_json")"
      row_json="$(resolve_runtime_input_state_json \
        "profile_default_gate_stability_cycle" \
        "campaign_subject" "true" \
        "Concrete invite/campaign subject for profile-default gate checks." \
        "Set PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT or INVITE_KEY to a real invite subject." \
        "PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT" "INVITE_KEY")"
      requirements_json="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$requirements_json")"
      ;;
    runtime_actuation_promotion_cycle)
      track_group="m4_runtime_actuation_promotion"
      row_json="$(resolve_runtime_input_state_json \
        "runtime_actuation_promotion_cycle" \
        "campaign_subject" "true" \
        "Concrete invite/campaign subject (required when signoff args do not provide a usable subject)." \
        "Set CAMPAIGN_SUBJECT or INVITE_KEY to a real invite subject." \
        "CAMPAIGN_SUBJECT" "INVITE_KEY")"
      requirements_json="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$requirements_json")"
      ;;
    profile_compare_multi_vm_stability_promotion_cycle)
      track_group="m5_multi_vm_stability_promotion"
      track_note="M5 requires a concrete VM command source (env/file fallback or recognized reports-dir artifacts); unresolved inputs are skipped in partial-progress mode."
      row_json="$(resolve_m5_vm_command_source_runtime_input_state_json)"
      requirements_json="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$requirements_json")"
      ;;
    *)
      ;;
  esac

  unresolved_required_inputs_json="$(jq -c '[.[] | select(.required == true and .state != "resolved") | .id]' <<<"$requirements_json")"
  unresolved_required_count="$(jq -r 'length' <<<"$unresolved_required_inputs_json")"
  if (( unresolved_required_count > 0 )); then
    status="unresolved_required_inputs"
  fi

  jq -cn \
    --arg track_id "$track_id" \
    --arg track_group "$track_group" \
    --arg status "$status" \
    --arg track_note "$track_note" \
    --argjson required_runtime_inputs "$requirements_json" \
    --argjson unresolved_required_inputs "$unresolved_required_inputs_json" \
    --argjson unresolved_required_count "$unresolved_required_count" \
    '{
      track_id: $track_id,
      track_group: $track_group,
      status: $status,
      note: (if $track_note == "" then null else $track_note end),
      required_runtime_inputs: $required_runtime_inputs,
      unresolved_required_inputs: $unresolved_required_inputs,
      unresolved_required_count: $unresolved_required_count
    }'
}

first_log_match_line_or_empty() {
  local log_path="$1"
  local pattern="$2"
  if [[ -f "$log_path" && -r "$log_path" ]]; then
    grep -m1 -E -- "$pattern" "$log_path" 2>/dev/null || true
  else
    printf '%s' ""
  fi
}

classify_track_failure_json() {
  local track_id="$1"
  local rc="${2:-1}"
  local log_path="$3"
  local track_group="$track_id"
  local failure_kind="track_execution_failed"
  local failure_code="track_command_failed"
  local operator_next_action="Inspect track logs and rerun this track."
  local operator_next_command=""
  local hint_line=""
  local -a unresolved_inputs=()
  local runtime_requirements_json=""
  local unresolved_required_inputs_json="[]"
  local unresolved_required_count=0

  runtime_requirements_json="$(build_track_runtime_requirements_json "$track_id")"
  unresolved_required_inputs_json="$(jq -c '.unresolved_required_inputs // []' <<<"$runtime_requirements_json")"
  unresolved_required_count="$(jq -r '.unresolved_required_count // 0' <<<"$runtime_requirements_json")"

  case "$track_id" in
    profile_default_gate_stability_cycle)
      track_group="m2_profile_default_gate_stability"
      failure_code="m2_track_failed"
      operator_next_action="Set real host/subject inputs for M2 and rerun the profile-default-gate stability cycle."
      operator_next_command="./scripts/easy_node.sh profile-default-gate-stability-cycle --host-a <host-a> --host-b <host-b> --campaign-subject <invite-key> --reports-dir .easy-node-logs --print-summary-json 1"
      hint_line="$(first_log_match_line_or_empty "$log_path" '--host-a is required|--host-b is required|--campaign-subject or --subject is required|uses placeholder token|conflicting subject values')"
      if [[ -n "$hint_line" ]]; then
        failure_kind="required_runtime_input_unresolved"
        failure_code="m2_required_runtime_input_unresolved"
      fi
      if grep -F -- "--host-a is required" "$log_path" >/dev/null 2>&1 || grep -F -- "set A_HOST/PROFILE_DEFAULT_GATE_STABILITY_HOST_A" "$log_path" >/dev/null 2>&1; then
        append_unique_id "host_a" unresolved_inputs
      fi
      if grep -F -- "--host-b is required" "$log_path" >/dev/null 2>&1 || grep -F -- "set B_HOST/PROFILE_DEFAULT_GATE_STABILITY_HOST_B" "$log_path" >/dev/null 2>&1; then
        append_unique_id "host_b" unresolved_inputs
      fi
      if grep -F -- "--campaign-subject or --subject is required" "$log_path" >/dev/null 2>&1 || grep -F -- "set PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT" "$log_path" >/dev/null 2>&1; then
        append_unique_id "campaign_subject" unresolved_inputs
      fi
      ;;
    runtime_actuation_promotion_cycle)
      track_group="m4_runtime_actuation_promotion"
      failure_code="m4_track_failed"
      operator_next_action="Provide a real invite subject credential for M4 (direct arg or CAMPAIGN_SUBJECT/INVITE_KEY) and rerun the runtime-actuation cycle."
      operator_next_command="CAMPAIGN_SUBJECT='<set-real-invite-key>' ./scripts/easy_node.sh runtime-actuation-promotion-cycle --reports-dir .easy-node-logs --print-summary-json 1"
      hint_line="$(first_log_match_line_or_empty "$log_path" 'placeholder invite subject|set CAMPAIGN_SUBJECT/INVITE_KEY|requires a non-empty value in signoff passthrough args|requires a value in signoff passthrough args')"
      if [[ -n "$hint_line" ]]; then
        failure_kind="required_runtime_input_unresolved"
        failure_code="m4_required_runtime_input_unresolved"
        append_unique_id "campaign_subject" unresolved_inputs
      fi
      ;;
    profile_compare_multi_vm_stability_promotion_cycle)
      track_group="m5_multi_vm_stability_promotion"
      failure_code="m5_track_failed"
      operator_next_action="Ensure M5 has usable VM commands/files and rerun the multi-VM stability promotion cycle."
      operator_next_command="./scripts/profile_compare_multi_vm_stability_promotion_cycle.sh --reports-dir .easy-node-logs --cycle-arg \"--vm-command-file REPLACE_WITH_VM_COMMAND_FILE\" --print-summary-json 1"
      hint_line="$(first_log_match_line_or_empty "$log_path" 'at least one --vm-command or --vm-command-file is required|vm command file preflight failed|no usable VM command fallback was discovered|vm-command-file preflight checks')"
      if [[ -n "$hint_line" ]]; then
        failure_kind="required_runtime_input_unresolved"
        failure_code="m5_required_runtime_input_unresolved"
        append_unique_id "vm_command_or_file" unresolved_inputs
      fi
      ;;
    *)
      ;;
  esac

  if [[ "$failure_kind" == "track_execution_failed" ]] && [[ "$rc" == "2" ]] && (( unresolved_required_count > 0 )); then
    failure_kind="required_runtime_input_unresolved"
    failure_code="${track_group}_required_runtime_input_preflight"
    if [[ -z "$hint_line" ]]; then
      hint_line="required runtime inputs unresolved by preflight"
    fi
  fi

  local unresolved_inputs_json
  local unresolved_inputs_count=0
  unresolved_inputs_json="$(json_array_from_ref unresolved_inputs)"
  unresolved_inputs_count="$(jq -r 'length' <<<"$unresolved_inputs_json")"
  if (( unresolved_inputs_count == 0 )) && [[ "$failure_kind" == "required_runtime_input_unresolved" ]]; then
    unresolved_inputs_json="$unresolved_required_inputs_json"
    unresolved_inputs_count="$(jq -r 'length' <<<"$unresolved_inputs_json")"
  fi

  jq -cn \
    --arg track_group "$track_group" \
    --arg failure_kind "$failure_kind" \
    --arg failure_code "$failure_code" \
    --arg operator_next_action "$operator_next_action" \
    --arg operator_next_command "$operator_next_command" \
    --arg hint_line "$hint_line" \
    --argjson failure_rc "$rc" \
    --argjson unresolved_inputs "$unresolved_inputs_json" \
    --argjson unresolved_inputs_count "$unresolved_inputs_count" \
    --argjson runtime_requirements "$runtime_requirements_json" \
    '{
      track_group: $track_group,
      failure_kind: $failure_kind,
      failure_code: $failure_code,
      failure_rc: $failure_rc,
      deterministic_failure_key: ($track_group + ":" + $failure_code + ":rc=" + ($failure_rc|tostring)),
      operator_next_action: $operator_next_action,
      operator_next_command: (if $operator_next_command == "" then null else $operator_next_command end),
      log_hint_line: (if $hint_line == "" then null else $hint_line end),
      unresolved_required_inputs: $unresolved_inputs,
      unresolved_required_inputs_count: $unresolved_inputs_count,
      runtime_requirements_snapshot: $runtime_requirements
    }'
}

build_runtime_preflight_skip_result_json() {
  local iter_idx="$1"
  local track_id="$2"
  local script_path="$3"
  local log_path="$4"
  local runtime_requirements_json="$5"
  local started_at ended_at diagnostics_json notes next_command_reason
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  ended_at="$started_at"
  notes="required runtime inputs unresolved during preflight; track execution skipped in partial-progress mode"
  next_command_reason="resolve required runtime inputs and rerun this track"

  diagnostics_json="$(classify_track_failure_json "$track_id" "2" "/dev/null")"
  diagnostics_json="$(jq -c \
    --arg notes "$notes" \
    --arg next_command_reason "$next_command_reason" \
    --argjson runtime_requirements "$runtime_requirements_json" \
    '
      .failure_rc = null
      | .runtime_requirements_snapshot = $runtime_requirements
      | .partial_progress_skip = true
      | .skip_reason = $notes
      | .next_command_reason = $next_command_reason
      | .deterministic_failure_key = (.track_group + ":" + .failure_code + ":preflight_skip")
    ' <<<"$diagnostics_json")"

  jq -cn \
    --argjson iteration "$iter_idx" \
    --arg track_id "$track_id" \
    --arg script_path "$script_path" \
    --arg log "$log_path" \
    --arg started_at_utc "$started_at" \
    --arg ended_at_utc "$ended_at" \
    --argjson failure_diagnostics "$diagnostics_json" \
    --arg notes "$notes" \
    '{
      iteration: $iteration,
      track_id: $track_id,
      script_path: $script_path,
      log: $log,
      started_at_utc: $started_at_utc,
      ended_at_utc: $ended_at_utc,
      status: "skipped",
      rc: null,
      duration_sec: 0,
      failure_kind: "skipped_unresolved_runtime_inputs",
      notes: $notes,
      failure_diagnostics: $failure_diagnostics
    }'
}

for id in "${include_track_ids[@]}"; do
  if ! track_id_exists "$id"; then
    echo "unknown --include-track-id: $id"
    exit 2
  fi
done
for id in "${exclude_track_ids[@]}"; do
  if ! track_id_exists "$id"; then
    echo "unknown --exclude-track-id: $id"
    exit 2
  fi
done

declare -a include_unique_ids=()
declare -a exclude_unique_ids=()
for id in "${include_track_ids[@]}"; do
  append_unique_id "$id" include_unique_ids
done
for id in "${exclude_track_ids[@]}"; do
  append_unique_id "$id" exclude_unique_ids
done

include_track_ids_unique_count="${#include_unique_ids[@]}"
exclude_track_ids_unique_count="${#exclude_unique_ids[@]}"

declare -a base_track_ids=()
if (( ${#include_unique_ids[@]} > 0 )); then
  for id in "${default_track_ids[@]}"; do
    for include_id in "${include_unique_ids[@]}"; do
      if [[ "$id" == "$include_id" ]]; then
        base_track_ids+=("$id")
        break
      fi
    done
  done
else
  base_track_ids=("${default_track_ids[@]}")
fi
base_track_count="${#base_track_ids[@]}"

declare -a selected_track_ids=()
for id in "${base_track_ids[@]}"; do
  excluded="0"
  for exclude_id in "${exclude_unique_ids[@]:-}"; do
    if [[ "$id" == "$exclude_id" ]]; then
      excluded="1"
      break
    fi
  done
  if [[ "$excluded" == "0" ]]; then
    selected_track_ids+=("$id")
  fi
done
selected_track_ids_count="${#selected_track_ids[@]}"

declare -a selected_track_scripts=()
for id in "${selected_track_ids[@]}"; do
  script_path="$(track_script_for_id "$id")"
  if [[ -z "$script_path" ]]; then
    echo "track script unresolved for id: $id"
    exit 2
  fi
  if [[ ! -f "$script_path" ]]; then
    echo "track script is missing for id=$id path=$script_path"
    exit 2
  fi
  if [[ ! -r "$script_path" ]]; then
    echo "track script is not readable for id=$id path=$script_path"
    exit 2
  fi
  selected_track_scripts+=("$script_path")
done

selection_error=""
selection_error_rc=0
declare -a conflicting_duplicate_track_ids=()
if [[ "${#selected_track_ids[@]}" -gt 0 ]]; then
  declare -A seen_track_script_by_id=()
  for idx in "${!selected_track_ids[@]}"; do
    id="${selected_track_ids[$idx]}"
    script_path="${selected_track_scripts[$idx]}"
    if [[ -n "${seen_track_script_by_id[$id]+x}" && "${seen_track_script_by_id[$id]}" != "$script_path" ]]; then
      append_unique_id "$id" conflicting_duplicate_track_ids
      continue
    fi
    seen_track_script_by_id["$id"]="$script_path"
  done
fi
if [[ "${#conflicting_duplicate_track_ids[@]}" -gt 0 ]]; then
  selection_error="conflicting_duplicate_track_ids"
  selection_error_rc=3
  conflicting_ids_csv="$(IFS=','; printf '%s' "${conflicting_duplicate_track_ids[*]}")"
  echo "[roadmap-live-evidence-cycle-batch-run] stage=selection status=fail reason=conflicting duplicate track ids ids=$conflicting_ids_csv"
fi
if [[ "${#selected_track_ids[@]}" -eq 0 && -z "$selection_error" ]]; then
  selection_error="no_tracks_selected"
  selection_error_rc=1
  echo "[roadmap-live-evidence-cycle-batch-run] stage=selection status=fail reason=no tracks selected after filtering"
fi
if [[ -z "$selection_error" ]]; then
  selected_track_ids_csv="$(IFS=','; printf '%s' "${selected_track_ids[*]}")"
  echo "[roadmap-live-evidence-cycle-batch-run] stage=selection status=pass selected_track_count=${#selected_track_ids[@]} ids=$selected_track_ids_csv"
fi

selected_track_runtime_requirements_json='[]'
declare -A selected_track_runtime_requirements_by_id=()
declare -A selected_track_unresolved_required_count_by_id=()
if [[ -z "$selection_error" ]]; then
  for id in "${selected_track_ids[@]}"; do
    track_runtime_json="$(build_track_runtime_requirements_json "$id")"
    selected_track_runtime_requirements_by_id["$id"]="$track_runtime_json"
    selected_track_unresolved_required_count_by_id["$id"]="$(jq -r '.unresolved_required_count // 0' <<<"$track_runtime_json")"
    selected_track_runtime_requirements_json="$(jq -c --argjson row "$track_runtime_json" '. + [$row]' <<<"$selected_track_runtime_requirements_json")"
  done
fi
unresolved_required_track_ids_json="$(jq -c '[.[] | select(.unresolved_required_count > 0) | .track_id]' <<<"$selected_track_runtime_requirements_json")"
unresolved_required_track_count="$(jq -r 'length' <<<"$unresolved_required_track_ids_json")"
if [[ -z "$selection_error" ]] && (( unresolved_required_track_count > 0 )); then
  unresolved_required_track_ids_csv="$(jq -r 'join(",")' <<<"$unresolved_required_track_ids_json")"
  echo "[roadmap-live-evidence-cycle-batch-run] stage=runtime-input-preflight status=warn unresolved_required_track_count=$unresolved_required_track_count ids=${unresolved_required_track_ids_csv:-none} mode=partial_progress_skip_unresolved_tracks"
fi

declare -A pass_count_by_track=()
declare -A fail_count_by_track=()
declare -A skipped_count_by_track=()
declare -A total_count_by_track=()
for id in "${selected_track_ids[@]}"; do
  pass_count_by_track["$id"]=0
  fail_count_by_track["$id"]=0
  skipped_count_by_track["$id"]=0
  total_count_by_track["$id"]=0
done

iteration_results_json='[]'
executed_iterations=0
executed_tracks=0
skipped_tracks=0
skipped_unresolved_runtime_input_tracks=0
final_rc=0
first_failure_iteration=0
first_failure_track_id=""

tmp_root="$(mktemp -d "$reports_dir/.roadmap_live_evidence_cycle_batch_run_tmp.XXXXXX")"
trap 'rm -rf "$tmp_root"' EXIT

execute_track_to_result_file() {
  local iter_idx="$1"
  local track_id="$2"
  local script_path="$3"
  local log_path="$4"
  local result_path="$5"

  local started_at ended_at duration_sec rc status
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local start_epoch end_epoch
  start_epoch="$(date +%s)"
  set +e
  bash "$script_path" >"$log_path" 2>&1
  rc=$?
  set -e
  end_epoch="$(date +%s)"
  ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  duration_sec=$((end_epoch - start_epoch))
  if (( rc == 0 )); then
    status="pass"
  else
    status="fail"
  fi

  jq -n \
    --argjson iteration "$iter_idx" \
    --arg track_id "$track_id" \
    --arg script_path "$script_path" \
    --arg log "$log_path" \
    --arg started_at_utc "$started_at" \
    --arg ended_at_utc "$ended_at" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --argjson duration_sec "$duration_sec" \
    '{
      iteration: $iteration,
      track_id: $track_id,
      script_path: $script_path,
      log: $log,
      started_at_utc: $started_at_utc,
      ended_at_utc: $ended_at_utc,
      status: $status,
      rc: $rc,
      duration_sec: $duration_sec
    }' >"$result_path"
  augment_result_file_with_failure_diagnostics "$result_path"
}

halt_after_iteration="0"
if [[ -z "$selection_error" ]]; then
  for ((iter=1; iter<=iterations; iter++)); do
    iter_name="$(printf 'iteration_%03d' "$iter")"
    iter_dir="$reports_dir/iterations/$iter_name"
    mkdir -p "$iter_dir"
    iter_tmp_dir="$tmp_root/$iter_name"
    mkdir -p "$iter_tmp_dir"
    iter_track_results_json='[]'
    iter_rc=0
    iter_status="pass"
    iter_failed_track_id=""
    echo "[roadmap-live-evidence-cycle-batch-run] stage=iteration status=running iteration=$iter selected_track_count=${#selected_track_ids[@]} parallel=$parallel"

    if [[ "$parallel" == "1" && "$continue_on_fail" != "0" && ${#selected_track_ids[@]} -gt 1 ]]; then
      declare -a pids=()
      for idx in "${!selected_track_ids[@]}"; do
        track_id="${selected_track_ids[$idx]}"
        script_path="${selected_track_scripts[$idx]}"
        log_path="$iter_dir/${track_id}.log"
        result_path="$iter_tmp_dir/${idx}_${track_id}.json"
        track_unresolved_required_count="${selected_track_unresolved_required_count_by_id[$track_id]:-0}"
        track_runtime_requirements_json="${selected_track_runtime_requirements_by_id[$track_id]:-}"
        if [[ -z "$track_runtime_requirements_json" ]]; then
          track_runtime_requirements_json="$(jq -cn --arg track_id "$track_id" '{track_id: $track_id, required_runtime_inputs: [], unresolved_required_inputs: [], unresolved_required_count: 0}')"
        fi
        if [[ "$track_unresolved_required_count" =~ ^[0-9]+$ ]] && (( track_unresolved_required_count > 0 )); then
          echo "[roadmap-live-evidence-cycle-batch-run] stage=track status=skipped iteration=$iter track_id=$track_id reason=unresolved_runtime_inputs mode=parallel"
          build_runtime_preflight_skip_result_json "$iter" "$track_id" "$script_path" "$log_path" "$track_runtime_requirements_json" >"$result_path"
          continue
        fi
        echo "[roadmap-live-evidence-cycle-batch-run] stage=track status=running iteration=$iter track_id=$track_id mode=parallel"
        execute_track_to_result_file "$iter" "$track_id" "$script_path" "$log_path" "$result_path" &
        pids+=("$!")
      done
      for pid in "${pids[@]}"; do
        set +e
        wait "$pid"
        wait_rc=$?
        set -e
        if (( wait_rc != 0 )); then
          :
        fi
      done
      for idx in "${!selected_track_ids[@]}"; do
        track_id="${selected_track_ids[$idx]}"
        script_path="${selected_track_scripts[$idx]}"
        log_path="$iter_dir/${track_id}.log"
        result_path="$iter_tmp_dir/${idx}_${track_id}.json"
        if [[ ! -s "$result_path" ]] || ! jq -e . "$result_path" >/dev/null 2>&1; then
          jq -n \
            --argjson iteration "$iter" \
            --arg track_id "$track_id" \
            --arg script_path "$script_path" \
            --arg log "$log_path" \
            --arg started_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg ended_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg status "fail" \
            --argjson rc 125 \
            --argjson duration_sec 0 \
            '{
              iteration: $iteration,
              track_id: $track_id,
              script_path: $script_path,
              log: $log,
              started_at_utc: $started_at_utc,
              ended_at_utc: $ended_at_utc,
              status: $status,
              rc: $rc,
              duration_sec: $duration_sec,
              failure_kind: "runner_error",
              notes: "missing or invalid track result payload"
            }' >"$result_path"
          augment_result_file_with_failure_diagnostics "$result_path"
        fi
        result_json="$(cat "$result_path")"
        iter_track_results_json="$(jq -c --argjson row "$result_json" '. + [$row]' <<<"$iter_track_results_json")"
      done
    else
      for idx in "${!selected_track_ids[@]}"; do
        track_id="${selected_track_ids[$idx]}"
        script_path="${selected_track_scripts[$idx]}"
        log_path="$iter_dir/${track_id}.log"
        result_path="$iter_tmp_dir/${idx}_${track_id}.json"
        track_unresolved_required_count="${selected_track_unresolved_required_count_by_id[$track_id]:-0}"
        track_runtime_requirements_json="${selected_track_runtime_requirements_by_id[$track_id]:-}"
        if [[ -z "$track_runtime_requirements_json" ]]; then
          track_runtime_requirements_json="$(jq -cn --arg track_id "$track_id" '{track_id: $track_id, required_runtime_inputs: [], unresolved_required_inputs: [], unresolved_required_count: 0}')"
        fi
        if [[ "$track_unresolved_required_count" =~ ^[0-9]+$ ]] && (( track_unresolved_required_count > 0 )); then
          echo "[roadmap-live-evidence-cycle-batch-run] stage=track status=skipped iteration=$iter track_id=$track_id reason=unresolved_runtime_inputs mode=sequential"
          result_json="$(build_runtime_preflight_skip_result_json "$iter" "$track_id" "$script_path" "$log_path" "$track_runtime_requirements_json")"
          printf '%s\n' "$result_json" >"$result_path"
          iter_track_results_json="$(jq -c --argjson row "$result_json" '. + [$row]' <<<"$iter_track_results_json")"
          continue
        fi
        echo "[roadmap-live-evidence-cycle-batch-run] stage=track status=running iteration=$iter track_id=$track_id mode=sequential"
        execute_track_to_result_file "$iter" "$track_id" "$script_path" "$log_path" "$result_path"
        if [[ ! -s "$result_path" ]] || ! jq -e . "$result_path" >/dev/null 2>&1; then
          jq -n \
            --argjson iteration "$iter" \
            --arg track_id "$track_id" \
            --arg script_path "$script_path" \
            --arg log "$log_path" \
            --arg started_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg ended_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg status "fail" \
            --argjson rc 125 \
            --argjson duration_sec 0 \
            '{
              iteration: $iteration,
              track_id: $track_id,
              script_path: $script_path,
              log: $log,
              started_at_utc: $started_at_utc,
              ended_at_utc: $ended_at_utc,
              status: $status,
              rc: $rc,
              duration_sec: $duration_sec,
              failure_kind: "runner_error",
              notes: "missing or invalid track result payload"
            }' >"$result_path"
          augment_result_file_with_failure_diagnostics "$result_path"
        fi
        result_json="$(cat "$result_path")"
        iter_track_results_json="$(jq -c --argjson row "$result_json" '. + [$row]' <<<"$iter_track_results_json")"
        row_status="$(jq -r '.status // ""' <<<"$result_json")"
        if [[ "$row_status" == "skipped" ]]; then
          continue
        fi
        row_rc="$(jq -r '.rc' <<<"$result_json")"
        if (( row_rc != 0 )) && [[ "$continue_on_fail" == "0" ]]; then
          if (( idx + 1 < ${#selected_track_ids[@]} )); then
            for ((skipped_idx=idx+1; skipped_idx<${#selected_track_ids[@]}; skipped_idx++)); do
              skipped_track_id="${selected_track_ids[$skipped_idx]}"
              skipped_script_path="${selected_track_scripts[$skipped_idx]}"
              skipped_log_path="$iter_dir/${skipped_track_id}.log"
              skipped_result_json="$(jq -c -n \
                --argjson iteration "$iter" \
                --arg track_id "$skipped_track_id" \
                --arg script_path "$skipped_script_path" \
                --arg log "$skipped_log_path" \
                --arg started_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                --arg ended_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                --arg status "skipped" \
                --argjson rc null \
                --argjson duration_sec 0 \
                '{
                  iteration: $iteration,
                  track_id: $track_id,
                  script_path: $script_path,
                  log: $log,
                  started_at_utc: $started_at_utc,
                  ended_at_utc: $ended_at_utc,
                  status: $status,
                  rc: $rc,
                  duration_sec: $duration_sec,
                  failure_kind: "skipped_due_to_fail_closed",
                  notes: "not executed because a previous track failed and continue_on_fail=0"
                }')"
              iter_track_results_json="$(jq -c --argjson row "$skipped_result_json" '. + [$row]' <<<"$iter_track_results_json")"
            done
          fi
          break
        fi
      done
    fi

    iter_track_count="$(jq -r 'length' <<<"$iter_track_results_json")"
    if (( iter_track_count > 0 )); then
      for idx in $(seq 0 $((iter_track_count - 1))); do
        row_json="$(jq -c ".[$idx]" <<<"$iter_track_results_json")"
        row_id="$(jq -r '.track_id' <<<"$row_json")"
        if [[ -z "${total_count_by_track[$row_id]+x}" ]]; then
          total_count_by_track["$row_id"]=0
          pass_count_by_track["$row_id"]=0
          fail_count_by_track["$row_id"]=0
          skipped_count_by_track["$row_id"]=0
        fi
        row_status="$(jq -r '.status // ""' <<<"$row_json")"
        row_rc_raw="$(jq -r '.rc // empty' <<<"$row_json")"
        if [[ "$row_status" == "skipped" ]]; then
          skipped_count_by_track["$row_id"]=$((skipped_count_by_track["$row_id"] + 1))
          skipped_tracks=$((skipped_tracks + 1))
          row_failure_kind="$(jq -r '.failure_kind // "skipped"' <<<"$row_json")"
          if [[ "$row_failure_kind" == "skipped_unresolved_runtime_inputs" ]]; then
            skipped_unresolved_runtime_input_tracks=$((skipped_unresolved_runtime_input_tracks + 1))
          fi
          echo "[roadmap-live-evidence-cycle-batch-run] stage=track status=skipped iteration=$iter track_id=$row_id reason=$row_failure_kind"
          continue
        fi
        if ! [[ "$row_rc_raw" =~ ^-?[0-9]+$ ]]; then
          row_rc_raw=125
        fi
        row_rc="$row_rc_raw"
        executed_tracks=$((executed_tracks + 1))
        total_count_by_track["$row_id"]=$((total_count_by_track["$row_id"] + 1))
        if (( row_rc == 0 )); then
          pass_count_by_track["$row_id"]=$((pass_count_by_track["$row_id"] + 1))
          echo "[roadmap-live-evidence-cycle-batch-run] stage=track status=pass iteration=$iter track_id=$row_id rc=0"
        else
          fail_count_by_track["$row_id"]=$((fail_count_by_track["$row_id"] + 1))
          echo "[roadmap-live-evidence-cycle-batch-run] stage=track status=fail iteration=$iter track_id=$row_id rc=$row_rc"
          if (( iter_rc == 0 )); then
            iter_rc="$row_rc"
            iter_status="fail"
            iter_failed_track_id="$row_id"
          fi
        fi
      done
    fi

    if (( iter_rc != 0 )) && (( final_rc == 0 )); then
      final_rc="$iter_rc"
      first_failure_iteration="$iter"
      first_failure_track_id="$iter_failed_track_id"
    fi

    iter_failure_substep=""
    if [[ "$iter_status" == "fail" ]]; then
      if [[ -n "$iter_failed_track_id" ]]; then
        iter_failure_substep="track_failed:$iter_failed_track_id"
      else
        iter_failure_substep="track_failed:unknown"
      fi
    fi

    iter_result_json="$(jq -c -n \
      --argjson iteration "$iter" \
      --arg status "$iter_status" \
      --argjson rc "$iter_rc" \
      --arg failed_track_id "$iter_failed_track_id" \
      --arg failure_substep "$iter_failure_substep" \
      --argjson tracks "$iter_track_results_json" \
      '{
        iteration: $iteration,
        status: $status,
        rc: $rc,
        failed_track_id: (if $failed_track_id == "" then null else $failed_track_id end),
        failure_substep: (if $failure_substep == "" then null else $failure_substep end),
        tracks: $tracks
      }')"
    iteration_results_json="$(jq -c --argjson row "$iter_result_json" '. + [$row]' <<<"$iteration_results_json")"
    executed_iterations=$((executed_iterations + 1))
    echo "[roadmap-live-evidence-cycle-batch-run] stage=iteration status=$iter_status iteration=$iter rc=$iter_rc"

    if (( iter_rc != 0 )) && [[ "$continue_on_fail" == "0" ]]; then
      halt_after_iteration="1"
      break
    fi
  done
fi

if [[ -n "$selection_error" ]]; then
  final_status="fail"
  final_rc="$selection_error_rc"
elif (( final_rc == 0 )) && (( executed_tracks == 0 )) && (( ${#selected_track_ids[@]} > 0 )); then
  final_status="fail"
  final_rc=1
elif (( final_rc == 0 )); then
  final_status="pass"
else
  final_status="fail"
fi

failure_substep=""
failure_reason=""
if [[ -n "$selection_error" ]]; then
  failure_substep="selection:$selection_error"
  failure_reason="selection failed before execution"
elif [[ "$final_status" == "fail" ]] && (( executed_tracks == 0 )) && (( ${#selected_track_ids[@]} > 0 )); then
  failure_substep="execution:no_tracks_executed"
  failure_reason="no selected tracks executed; required runtime inputs unresolved across all selected tracks"
elif [[ "$final_status" == "fail" ]]; then
  if (( first_failure_iteration > 0 )) && [[ -n "$first_failure_track_id" ]]; then
    failure_substep="execution:iteration_${first_failure_iteration}:track_${first_failure_track_id}"
    failure_reason="first failing track in deterministic iteration/track order"
  else
    failure_substep="execution:unknown"
    failure_reason="execution failed without first failure metadata"
  fi
fi

per_track_json='[]'
for id in "${selected_track_ids[@]}"; do
  row_json="$(jq -c -n \
    --arg id "$id" \
    --arg script_path "$(track_script_for_id "$id")" \
    --argjson total "${total_count_by_track[$id]}" \
    --argjson pass "${pass_count_by_track[$id]}" \
    --argjson fail "${fail_count_by_track[$id]}" \
    --argjson skipped "${skipped_count_by_track[$id]}" \
    '{
      id: $id,
      script_path: $script_path,
      total_runs: $total,
      pass: $pass,
      fail: $fail,
      skipped: $skipped
    }')"
  per_track_json="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$per_track_json")"
done

include_track_ids_json="$(json_array_from_ref include_unique_ids)"
exclude_track_ids_json="$(json_array_from_ref exclude_unique_ids)"
selected_track_ids_json="$(json_array_from_ref selected_track_ids)"
conflicting_duplicate_track_ids_json="$(json_array_from_ref conflicting_duplicate_track_ids)"

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg failure_substep "$failure_substep" \
  --arg failure_reason "$failure_reason" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg selection_error "$selection_error" \
  --argjson iterations_requested "$iterations" \
  --argjson iterations_completed "$executed_iterations" \
  --argjson continue_on_fail "$continue_on_fail" \
  --argjson parallel "$parallel" \
  --argjson print_summary_json "$print_summary_json" \
  --argjson failure_log_tail_lines "$failure_log_tail_lines" \
  --argjson default_track_ids "$default_track_ids_json" \
  --argjson include_track_ids "$include_track_ids_json" \
  --argjson exclude_track_ids "$exclude_track_ids_json" \
  --argjson selected_track_ids "$selected_track_ids_json" \
  --argjson selected_track_runtime_requirements "$selected_track_runtime_requirements_json" \
  --argjson default_track_count "${#default_track_ids[@]}" \
  --argjson include_track_ids_requested_count "$include_track_ids_requested_count" \
  --argjson include_track_ids_unique_count "$include_track_ids_unique_count" \
  --argjson exclude_track_ids_requested_count "$exclude_track_ids_requested_count" \
  --argjson exclude_track_ids_unique_count "$exclude_track_ids_unique_count" \
  --argjson base_track_count "$base_track_count" \
  --argjson selected_track_ids_count "$selected_track_ids_count" \
  --argjson unresolved_required_track_ids "$unresolved_required_track_ids_json" \
  --argjson unresolved_required_track_count "$unresolved_required_track_count" \
  --argjson conflicting_duplicate_track_ids "$conflicting_duplicate_track_ids_json" \
  --argjson per_track "$per_track_json" \
  --argjson iterations_results "$iteration_results_json" \
  --argjson executed_tracks "$executed_tracks" \
  --argjson skipped_tracks "$skipped_tracks" \
  --argjson skipped_unresolved_runtime_input_tracks "$skipped_unresolved_runtime_input_tracks" \
  --argjson halt_after_iteration "$halt_after_iteration" \
  --argjson first_failure_iteration "$first_failure_iteration" \
  --arg first_failure_track_id "$first_failure_track_id" \
  '{
    version: 1,
    schema: { id: "roadmap_live_evidence_cycle_batch_run_summary", major: 1, minor: 0 },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    failure_substep: (if $failure_substep == "" then null else $failure_substep end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    selection_error: (if $selection_error == "" then null else $selection_error end),
    inputs: {
      iterations: $iterations_requested,
      continue_on_fail: ($continue_on_fail == 1),
      parallel: ($parallel == 1),
      print_summary_json: ($print_summary_json == 1),
      failure_log_tail_lines: $failure_log_tail_lines,
      default_track_ids: $default_track_ids,
      include_track_ids: $include_track_ids,
      exclude_track_ids: $exclude_track_ids,
      selected_track_ids: $selected_track_ids,
      track_runtime_requirements: $selected_track_runtime_requirements
    },
    selection_accounting: {
      default_track_count: $default_track_count,
      include_track_ids_requested_count: $include_track_ids_requested_count,
      include_track_ids_unique_count: $include_track_ids_unique_count,
      exclude_track_ids_requested_count: $exclude_track_ids_requested_count,
      exclude_track_ids_unique_count: $exclude_track_ids_unique_count,
      base_track_count: $base_track_count,
      selected_track_ids_count: $selected_track_ids_count,
      unresolved_required_track_ids: $unresolved_required_track_ids,
      unresolved_required_track_count: $unresolved_required_track_count,
      conflicting_duplicate_track_ids: $conflicting_duplicate_track_ids
    },
    stages: {
      selection: {
        status: (if $selection_error == "" then "pass" else "fail" end),
        reason: (if $selection_error == "" then null else $selection_error end)
      },
      execution: {
        status: (if $selection_error == "" then $status else "skip_due_to_selection_error" end),
        halted_early: ($halt_after_iteration == 1),
        partial_progress_runtime_input_skips: ($skipped_unresolved_runtime_input_tracks > 0)
      }
    },
    summary: {
      iterations_requested: $iterations_requested,
      iterations_completed: $iterations_completed,
      selected_track_count: ($selected_track_ids | length),
      executed_tracks: $executed_tracks,
      skipped_tracks: $skipped_tracks,
      skipped_unresolved_runtime_input_tracks: $skipped_unresolved_runtime_input_tracks,
      halt_after_iteration: ($halt_after_iteration == 1),
      first_failure_iteration: (if $first_failure_iteration == 0 then null else $first_failure_iteration end),
      first_failure_track_id: (if $first_failure_track_id == "" then null else $first_failure_track_id end)
    },
    per_track: $per_track,
    iterations: $iterations_results,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json
    }
  }' >"$summary_json"

echo "[roadmap-live-evidence-cycle-batch-run] status=$final_status rc=$final_rc iterations_completed=$executed_iterations selected_tracks=${#selected_track_ids[@]} failure_substep=${failure_substep:-none}"
if [[ "$final_status" == "fail" && -n "$failure_substep" ]]; then
  echo "[roadmap-live-evidence-cycle-batch-run] fail_substep=$failure_substep reason=${failure_reason:-unknown}"
fi
echo "[roadmap-live-evidence-cycle-batch-run] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
