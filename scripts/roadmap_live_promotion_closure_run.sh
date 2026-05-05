#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_live_promotion_closure_run.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--host-a HOST] \
    [--host-b HOST] \
    [--campaign-subject ID] \
    [--vm-command-file PATH | --m5-vm-command-file PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run the three live promotion closure helpers (M2/M4/M5) in deterministic,
  deconflict-safe sequence, then emit one consolidated machine-readable summary.

Helper order (fixed):
  1) profile_default_gate_stability_live_archive_and_pack.sh                     (M2)
  2) runtime_actuation_promotion_live_archive_and_pack.sh                        (M4)
  3) profile_compare_multi_vm_stability_promotion_live_archive_and_pack.sh       (M5)

Defaults:
  --reports-dir .easy-node-logs/roadmap_live_promotion_closure_run
  --summary-json <reports-dir>/roadmap_live_promotion_closure_run_summary.json
  --print-summary-json 1
  --host-a from ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_A, then
    PROFILE_DEFAULT_GATE_STABILITY_HOST_A, then A_HOST
  --host-b from ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_B, then
    PROFILE_DEFAULT_GATE_STABILITY_HOST_B, then B_HOST
  --campaign-subject from ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_CAMPAIGN_SUBJECT,
    then PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT, then
    CAMPAIGN_SUBJECT/INVITE_KEY
  --vm-command-file from ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_VM_COMMAND_FILE,
    then PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE, then
    PROFILE_COMPARE_MULTI_VM_STABILITY_VM_COMMAND_FILE, then
    PROFILE_COMPARE_MULTI_VM_VM_COMMAND_FILE, then reports-dir artifacts

Helper script override env vars:
  ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M2_SCRIPT
  ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M4_SCRIPT
  ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_SCRIPT

Fail-closed behavior:
  - If any required helper is missing or unreadable, no helper is executed.
  - If any required runtime inputs are missing/unresolved/placeholder, no helper
    is executed.
  - Per-helper summary contract violations (missing/invalid summary JSON, invalid
    status/rc contract) are treated as failures.
  - Final rc is 0 only when all tracks pass.
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
    INVITE_KEY|CAMPAIGN_SUBJECT|A_HOST|B_HOST|HOST_A|HOST_B|VM_COMMAND_FILE|REPLACE_WITH_INVITE_KEY|REPLACE_WITH_INVITE_SUBJECT|REPLACE_WITH_CAMPAIGN_SUBJECT|REPLACE_WITH_HOST_A|REPLACE_WITH_HOST_B|REPLACE_WITH_VM_COMMAND_FILE|"<SET-REAL-INVITE-KEY>"|SET-REAL-INVITE-KEY|"<INVITE_KEY>"|"<CAMPAIGN_SUBJECT>"|"<HOST_A>"|"<HOST_B>"|"<VM_COMMAND_FILE>"|\$\{INVITE_KEY\}|\$INVITE_KEY|\$\{CAMPAIGN_SUBJECT\}|\$CAMPAIGN_SUBJECT|\$\{A_HOST\}|\$A_HOST|\$\{B_HOST\}|\$B_HOST|\$\{HOST_A\}|\$HOST_A|\$\{HOST_B\}|\$HOST_B|\$\{VM_COMMAND_FILE\}|\$VM_COMMAND_FILE|%INVITE_KEY%|%CAMPAIGN_SUBJECT%|%HOST_A%|%HOST_B%|%VM_COMMAND_FILE%)
      return 0
      ;;
    *)
      ;;
  esac
  if [[ "$normalized" == *"PLACEHOLDER"* || "$normalized" == *"REPLACE_WITH_"* || "$normalized" == *"[REDACTED]"* ]]; then
    return 0
  fi
  if [[ "$normalized" =~ \$\{?(INVITE_KEY|CAMPAIGN_SUBJECT|A_HOST|B_HOST|HOST_A|HOST_B|VM_COMMAND_FILE)(:[-?][^}]*)?\}? ]]; then
    return 0
  fi
  if [[ "$normalized" =~ %(INVITE_KEY|CAMPAIGN_SUBJECT|HOST_A|HOST_B|VM_COMMAND_FILE)% ]]; then
    return 0
  fi
  if [[ "$normalized" =~ \{\{[[:space:]]*(INVITE_KEY|CAMPAIGN_SUBJECT|HOST_A|HOST_B|VM_COMMAND_FILE)[[:space:]]*\}\} ]]; then
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

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

render_invocation_command() {
  local rendered=""
  local token=""
  for token in "$@"; do
    if [[ -n "$rendered" ]]; then
      rendered+=" "
    fi
    rendered+="$(printf '%q' "$token")"
  done
  printf '%s' "$rendered"
}

json_array_from_lines() {
  local line=""
  local normalized=""
  local -a lines=()
  for line in "$@"; do
    normalized="$(trim "$line")"
    if [[ -n "$normalized" ]]; then
      lines+=("$normalized")
    fi
  done
  if [[ "${#lines[@]}" -eq 0 ]]; then
    printf '%s' "[]"
    return
  fi
  printf '%s\n' "${lines[@]}" | jq -R . | jq -s .
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
  if [[ "$path" == *$'\n'* || "$path" == *$'\r'* || "$path" == *";"* || "$path" == *"&&"* || "$path" == *"||"* || "$path" == *"|"* || "$path" == *'$('* || "$path" == *'`'* ]]; then
    printf '%s\n' "unsafe_path"
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

collect_m5_vm_command_candidate_paths_01() {
  local reports_dir_abs=""
  local reports_dir_basename=""
  local parent_dir=""
  local grandparent_dir=""
  local base_dir=""
  local artifact_name=""
  local candidate_path=""
  declare -A seen_paths=()
  declare -a base_dirs=()
  declare -a candidate_paths=()

  reports_dir_abs="$(abs_path "$reports_dir")"
  if [[ -n "$reports_dir_abs" ]]; then
    base_dirs+=("$reports_dir_abs")
    reports_dir_basename="$(basename "$reports_dir_abs")"
    if [[ "$reports_dir_basename" == cycle_* || "$reports_dir_basename" == run_* ||
          "$reports_dir_abs" == *"/profile_compare_multi_vm_stability_run_"*"/"* ||
          "$reports_dir_abs" == *"/profile_compare_multi_vm_stability_promotion_cycle_"*"/"* ]]; then
      parent_dir="$(abs_path "$(dirname "$reports_dir_abs")")"
      if [[ -n "$parent_dir" && "$parent_dir" != "/" ]]; then
        base_dirs+=("$parent_dir")
      fi
      if [[ -n "$parent_dir" && "$parent_dir" != "/" ]]; then
        grandparent_dir="$(abs_path "$(dirname "$parent_dir")")"
        if [[ -n "$grandparent_dir" && "$grandparent_dir" != "/" ]]; then
          base_dirs+=("$grandparent_dir")
        fi
      fi
    fi
  fi

  for base_dir in "${base_dirs[@]}"; do
    for artifact_name in "profile_compare_multi_vm_stability_vm_commands.txt" "vm_commands.txt"; do
      candidate_path="$(abs_path "$base_dir/$artifact_name")"
      if [[ -n "$candidate_path" && -z "${seen_paths["$candidate_path"]+present}" ]]; then
        candidate_paths+=("$candidate_path")
        seen_paths["$candidate_path"]=1
      fi
    done
  done

  printf '%s\n' "${candidate_paths[@]}"
}

runtime_input_last_value=""
runtime_input_last_state="missing"
runtime_input_last_resolution_source=""
runtime_input_last_validation_reason=""

resolve_scalar_runtime_input_state_json() {
  local input_id="$1"
  local description="$2"
  local operator_hint="$3"
  local primary_source="$4"
  local primary_value="$5"
  shift 5
  local -a candidate_var_names=("$@")
  local -a env_candidates=()
  local -a placeholder_sources=()
  local -a considered_sources=()
  local var_name=""
  local value=""
  local resolved_value=""
  local resolved_source=""
  local state="missing"
  local value_present_json="false"
  local env_candidates_json='[]'
  local placeholder_sources_json='[]'
  local considered_sources_json='[]'

  considered_sources+=("$primary_source")
  value="$(trim "$primary_value")"
  if [[ -n "$value" ]]; then
    if is_runtime_placeholder_token_01 "$value"; then
      placeholder_sources+=("$primary_source")
    else
      resolved_value="$value"
      resolved_source="$primary_source"
    fi
  fi

  for var_name in "${candidate_var_names[@]}"; do
    env_candidates+=("$var_name")
    considered_sources+=("env:$var_name")
    if [[ -n "$resolved_value" ]]; then
      continue
    fi
    value="$(trim "${!var_name:-}")"
    if [[ -z "$value" ]]; then
      continue
    fi
    if is_runtime_placeholder_token_01 "$value"; then
      placeholder_sources+=("env:$var_name")
      continue
    fi
    resolved_value="$value"
    resolved_source="env:$var_name"
  done

  if [[ -n "$resolved_value" ]]; then
    state="resolved"
    value_present_json="true"
  elif (( ${#placeholder_sources[@]} > 0 )); then
    state="placeholder_unresolved"
    value_present_json="true"
  fi

  env_candidates_json="$(json_array_from_lines "${env_candidates[@]}")"
  placeholder_sources_json="$(json_array_from_lines "${placeholder_sources[@]}")"
  considered_sources_json="$(json_array_from_lines "${considered_sources[@]}")"

  runtime_input_last_value="$resolved_value"
  runtime_input_last_state="$state"
  runtime_input_last_resolution_source="$resolved_source"
  runtime_input_last_validation_reason=""

  jq -cn \
    --arg id "$input_id" \
    --arg description "$description" \
    --arg state "$state" \
    --arg resolution_source "$resolved_source" \
    --arg operator_hint "$operator_hint" \
    --argjson required true \
    --argjson value_present "$value_present_json" \
    --argjson env_candidates "$env_candidates_json" \
    --argjson placeholder_sources "$placeholder_sources_json" \
    --argjson considered_sources "$considered_sources_json" \
    '{
      id: $id,
      required: $required,
      description: $description,
      state: $state,
      resolution_source: (if $resolution_source == "" then null else $resolution_source end),
      value_present: $value_present,
      env_candidates: $env_candidates,
      placeholder_sources: $placeholder_sources,
      considered_sources: $considered_sources,
      validation_reason: null,
      operator_hint: $operator_hint
    }'
}

resolve_m5_vm_command_source_state_json() {
  local primary_source="$1"
  local primary_value="$2"
  local input_id="vm_command_source"
  local description="Concrete VM command source for multi-VM promotion helper."
  local operator_hint="Provide --vm-command-file (or PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE) pointing to a readable vm command spec file."
  local -a env_candidates=(
    "PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE"
    "PROFILE_COMPARE_MULTI_VM_STABILITY_VM_COMMAND_FILE"
    "PROFILE_COMPARE_MULTI_VM_VM_COMMAND_FILE"
  )
  local -a placeholder_sources=()
  local -a considered_sources=()
  local -a artifact_candidates=()
  local -a validation_reasons=()
  local env_name=""
  local value=""
  local candidate_path=""
  local validation_reason=""
  local line=""
  local resolution_source=""
  local resolution_path=""
  local state="missing"
  local value_present_json="false"
  local env_candidates_json='[]'
  local placeholder_sources_json='[]'
  local considered_sources_json='[]'
  local artifact_candidates_json='[]'
  local validation_reasons_json='[]'

  considered_sources+=("$primary_source")
  value="$(trim "$primary_value")"
  if [[ -n "$value" ]]; then
    if is_runtime_placeholder_token_01 "$value"; then
      placeholder_sources+=("$primary_source")
    else
      candidate_path="$(abs_path "$value")"
      artifact_candidates+=("$candidate_path")
      if validation_reason="$(m5_validate_vm_command_source_file_or_reason_01 "$candidate_path")"; then
        resolution_source="$primary_source"
        resolution_path="$candidate_path"
      else
        validation_reasons+=("${primary_source}:${validation_reason}")
      fi
    fi
  fi

  if [[ -z "$resolution_path" ]]; then
    for env_name in "${env_candidates[@]}"; do
      considered_sources+=("env:$env_name")
      value="$(trim "${!env_name:-}")"
      if [[ -z "$value" ]]; then
        continue
      fi
      if is_runtime_placeholder_token_01 "$value"; then
        placeholder_sources+=("env:$env_name")
        continue
      fi
      candidate_path="$(abs_path "$value")"
      artifact_candidates+=("$candidate_path")
      if validation_reason="$(m5_validate_vm_command_source_file_or_reason_01 "$candidate_path")"; then
        resolution_source="env:$env_name"
        resolution_path="$candidate_path"
        break
      fi
      validation_reasons+=("env:$env_name:$validation_reason")
    done
  fi

  if [[ -z "$resolution_path" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="$(trim "$line")"
      if [[ -z "$line" ]]; then
        continue
      fi
      considered_sources+=("reports_dir_candidates")
      artifact_candidates+=("$line")
      if validation_reason="$(m5_validate_vm_command_source_file_or_reason_01 "$line")"; then
        resolution_source="reports_dir_candidates"
        resolution_path="$line"
        break
      fi
      validation_reasons+=("reports_dir_candidates:$validation_reason:$line")
    done < <(collect_m5_vm_command_candidate_paths_01)
  fi

  if [[ -n "$resolution_path" ]]; then
    state="resolved"
    value_present_json="true"
  elif (( ${#placeholder_sources[@]} > 0 )); then
    state="placeholder_unresolved"
    value_present_json="true"
  elif (( ${#validation_reasons[@]} > 0 )); then
    state="unresolved"
  fi

  env_candidates_json="$(json_array_from_lines "${env_candidates[@]}")"
  placeholder_sources_json="$(json_array_from_lines "${placeholder_sources[@]}")"
  considered_sources_json="$(json_array_from_lines "${considered_sources[@]}")"
  artifact_candidates_json="$(json_array_from_lines "${artifact_candidates[@]}")"
  validation_reasons_json="$(json_array_from_lines "${validation_reasons[@]}")"

  runtime_input_last_value="$resolution_path"
  runtime_input_last_state="$state"
  runtime_input_last_resolution_source="$resolution_source"
  runtime_input_last_validation_reason="$(jq -r '.[0] // ""' <<<"$validation_reasons_json")"

  jq -cn \
    --arg id "$input_id" \
    --arg description "$description" \
    --arg state "$state" \
    --arg resolution_source "$resolution_source" \
    --arg resolution_path "$resolution_path" \
    --arg operator_hint "$operator_hint" \
    --argjson required true \
    --argjson value_present "$value_present_json" \
    --argjson env_candidates "$env_candidates_json" \
    --argjson placeholder_sources "$placeholder_sources_json" \
    --argjson considered_sources "$considered_sources_json" \
    --argjson artifact_candidates "$artifact_candidates_json" \
    --argjson validation_reasons "$validation_reasons_json" \
    '{
      id: $id,
      required: $required,
      description: $description,
      state: $state,
      resolution_source: (if $resolution_source == "" then null else $resolution_source end),
      resolution_path: (if $resolution_path == "" then null else $resolution_path end),
      value_present: $value_present,
      env_candidates: $env_candidates,
      placeholder_sources: $placeholder_sources,
      considered_sources: $considered_sources,
      artifact_candidates: $artifact_candidates,
      validation_reason: (if ($validation_reasons | length) == 0 then null else $validation_reasons[0] end),
      validation_reasons: $validation_reasons,
      operator_hint: $operator_hint
    }'
}

need_cmd bash
need_cmd jq
need_cmd mktemp
need_cmd date
need_cmd env

reports_dir="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_REPORTS_DIR:-.easy-node-logs/roadmap_live_promotion_closure_run}"
summary_json="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_SUMMARY_JSON:-}"
host_a="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_A:-}"
host_b="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_B:-}"
campaign_subject="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_CAMPAIGN_SUBJECT:-}"
m5_vm_command_file="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_VM_COMMAND_FILE:-}"
print_summary_json="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_PRINT_SUMMARY_JSON:-1}"

m2_script="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M2_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_stability_live_archive_and_pack.sh}"
m4_script="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M4_SCRIPT:-$ROOT_DIR/scripts/runtime_actuation_promotion_live_archive_and_pack.sh}"
m5_script="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_promotion_live_archive_and_pack.sh}"

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
    --host-a)
      require_value_or_die "$1" "${2:-}"
      host_a="${2:-}"
      shift 2
      ;;
    --host-b)
      require_value_or_die "$1" "${2:-}"
      host_b="${2:-}"
      shift 2
      ;;
    --campaign-subject|--subject)
      require_value_or_die "$1" "${2:-}"
      campaign_subject="${2:-}"
      shift 2
      ;;
    --vm-command-file|--m5-vm-command-file)
      require_value_or_die "$1" "${2:-}"
      m5_vm_command_file="${2:-}"
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
    --help|-h)
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

bool_arg_or_die "--print-summary-json" "$print_summary_json"

host_a="$(trim "$host_a")"
host_b="$(trim "$host_b")"
campaign_subject="$(trim "$campaign_subject")"
m5_vm_command_file="$(trim "$m5_vm_command_file")"
reports_dir="$(abs_path "$reports_dir")"
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/roadmap_live_promotion_closure_run_summary.json"
fi
summary_json="$(abs_path "$summary_json")"
m2_script="$(abs_path "$m2_script")"
m4_script="$(abs_path "$m4_script")"
m5_script="$(abs_path "$m5_script")"
if [[ -n "$m5_vm_command_file" ]] && ! is_runtime_placeholder_token_01 "$m5_vm_command_file"; then
  m5_vm_command_file="$(abs_path "$m5_vm_command_file")"
fi

mkdir -p "$reports_dir" "$(dirname "$summary_json")"
rm -f "$summary_json"

tmp_dir="$(mktemp -d "$reports_dir/.roadmap_live_promotion_closure_run.XXXXXX")"
tracks_jsonl="$tmp_dir/tracks.jsonl"
runtime_input_preflight_failures_jsonl="$tmp_dir/runtime_input_preflight_failures.jsonl"
touch "$tracks_jsonl"
touch "$runtime_input_preflight_failures_jsonl"
trap 'rm -rf "$tmp_dir"' EXIT

started_at="$(timestamp_utc)"

declare -a track_ids=(
  "m2_profile_default_gate_stability_live_archive_and_pack"
  "m4_runtime_actuation_promotion_live_archive_and_pack"
  "m5_profile_compare_multi_vm_stability_promotion_live_archive_and_pack"
)

declare -A track_label
declare -A track_script
declare -A track_reports_dir
declare -A track_summary_json
declare -A track_log
declare -A track_helper_available
declare -A track_helper_readable
declare -A track_status
declare -A track_rc
declare -A track_notes
declare -A track_started_at
declare -A track_completed_at
declare -A track_executed
declare -A track_summary_valid
declare -A track_contract_valid
declare -A track_contract_failure_reason
declare -A track_observed_status
declare -A track_observed_rc
declare -A track_run_rc
declare -A track_command
declare -A track_expected_schema_id
declare -A track_observed_schema_id
declare -A track_schema_valid
declare -A track_preflight_failure_substep
declare -A track_preflight_failure_reason
declare -A track_preflight_failure_codes_json
declare -A track_runtime_required_inputs_json
declare -A track_runtime_unresolved_inputs_json
declare -A track_runtime_unresolved_count
declare -A track_runtime_preflight_ok
declare -A track_runtime_preflight_failure_substep
declare -A track_runtime_preflight_failure_reason
declare -A track_runtime_preflight_failure_codes_json
declare -A track_runtime_input_value

track_label["m2_profile_default_gate_stability_live_archive_and_pack"]="M2 profile-default live archive+pack"
track_label["m4_runtime_actuation_promotion_live_archive_and_pack"]="M4 runtime-actuation live archive+pack"
track_label["m5_profile_compare_multi_vm_stability_promotion_live_archive_and_pack"]="M5 multi-vm promotion live archive+pack"

track_script["m2_profile_default_gate_stability_live_archive_and_pack"]="$m2_script"
track_script["m4_runtime_actuation_promotion_live_archive_and_pack"]="$m4_script"
track_script["m5_profile_compare_multi_vm_stability_promotion_live_archive_and_pack"]="$m5_script"

track_expected_schema_id["m2_profile_default_gate_stability_live_archive_and_pack"]="profile_default_gate_stability_live_archive_and_pack_summary"
track_expected_schema_id["m4_runtime_actuation_promotion_live_archive_and_pack"]="runtime_actuation_promotion_live_archive_and_pack_summary"
track_expected_schema_id["m5_profile_compare_multi_vm_stability_promotion_live_archive_and_pack"]="profile_compare_multi_vm_stability_promotion_live_archive_and_pack_summary"

preflight_failed="0"
helper_preflight_failed="0"
runtime_input_preflight_failed="0"
missing_or_unreadable_helper_count=0
unresolved_runtime_input_track_count=0
unresolved_runtime_input_count=0
preflight_failure_reason=""

for track_id in "${track_ids[@]}"; do
  track_reports_dir["$track_id"]="$reports_dir/$track_id"
  track_summary_json["$track_id"]="$reports_dir/$track_id/${track_id}_summary.json"
  track_log["$track_id"]="$reports_dir/$track_id/${track_id}.log"
  track_helper_available["$track_id"]="1"
  track_helper_readable["$track_id"]="1"
  track_status["$track_id"]="pending"
  track_rc["$track_id"]="null"
  track_notes["$track_id"]=""
  track_started_at["$track_id"]=""
  track_completed_at["$track_id"]=""
  track_executed["$track_id"]="0"
  track_summary_valid["$track_id"]="0"
  track_contract_valid["$track_id"]="0"
  track_contract_failure_reason["$track_id"]=""
  track_observed_status["$track_id"]=""
  track_observed_rc["$track_id"]="null"
  track_run_rc["$track_id"]="null"
  track_observed_schema_id["$track_id"]=""
  track_schema_valid["$track_id"]="0"
  track_command["$track_id"]=""
  track_preflight_failure_substep["$track_id"]=""
  track_preflight_failure_reason["$track_id"]=""
  track_preflight_failure_codes_json["$track_id"]='[]'
  track_runtime_required_inputs_json["$track_id"]='[]'
  track_runtime_unresolved_inputs_json["$track_id"]='[]'
  track_runtime_unresolved_count["$track_id"]="0"
  track_runtime_preflight_ok["$track_id"]="1"
  track_runtime_preflight_failure_substep["$track_id"]=""
  track_runtime_preflight_failure_reason["$track_id"]=""
  track_runtime_preflight_failure_codes_json["$track_id"]='[]'

  helper_path="${track_script[$track_id]}"
  if [[ ! -f "$helper_path" ]]; then
    track_helper_available["$track_id"]="0"
    track_helper_readable["$track_id"]="0"
    track_status["$track_id"]="fail"
    track_rc["$track_id"]="2"
    track_notes["$track_id"]="missing_helper_script"
    preflight_failed="1"
    helper_preflight_failed="1"
    missing_or_unreadable_helper_count=$((missing_or_unreadable_helper_count + 1))
    track_preflight_failure_substep["$track_id"]="preflight:helper_missing_or_unreadable"
    track_preflight_failure_reason["$track_id"]="missing helper script: $helper_path"
    track_preflight_failure_codes_json["$track_id"]='["helper_missing"]'
    if [[ -z "$preflight_failure_reason" ]]; then
      preflight_failure_reason="missing helper script: $helper_path"
    fi
  elif [[ ! -r "$helper_path" ]]; then
    track_helper_available["$track_id"]="1"
    track_helper_readable["$track_id"]="0"
    track_status["$track_id"]="fail"
    track_rc["$track_id"]="2"
    track_notes["$track_id"]="unreadable_helper_script"
    preflight_failed="1"
    helper_preflight_failed="1"
    missing_or_unreadable_helper_count=$((missing_or_unreadable_helper_count + 1))
    track_preflight_failure_substep["$track_id"]="preflight:helper_missing_or_unreadable"
    track_preflight_failure_reason["$track_id"]="unreadable helper script: $helper_path"
    track_preflight_failure_codes_json["$track_id"]='["helper_unreadable"]'
    if [[ -z "$preflight_failure_reason" ]]; then
      preflight_failure_reason="unreadable helper script: $helper_path"
    fi
  fi

  runtime_requirements_json='[]'
  runtime_unresolved_inputs_json='[]'
  runtime_unresolved_count=0
  runtime_failure_reason=""
  runtime_failure_codes_json='[]'

  case "$track_id" in
    m2_profile_default_gate_stability_live_archive_and_pack)
      row_json="$(resolve_scalar_runtime_input_state_json \
        "host_a" \
        "Real host/IP for lane A." \
        "Set --host-a (or PROFILE_DEFAULT_GATE_STABILITY_HOST_A/A_HOST/HOST_A) to a concrete host." \
        "arg_or_env:--host-a|ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_A" \
        "$host_a" \
        "PROFILE_DEFAULT_GATE_STABILITY_HOST_A" "A_HOST" "HOST_A")"
      runtime_requirements_json="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$runtime_requirements_json")"
      if [[ "$runtime_input_last_state" == "resolved" ]]; then
        track_runtime_input_value["$track_id:host_a"]="$runtime_input_last_value"
        if [[ -z "$host_a" ]]; then
          host_a="$runtime_input_last_value"
        fi
      fi

      row_json="$(resolve_scalar_runtime_input_state_json \
        "host_b" \
        "Real host/IP for lane B." \
        "Set --host-b (or PROFILE_DEFAULT_GATE_STABILITY_HOST_B/B_HOST/HOST_B) to a concrete host." \
        "arg_or_env:--host-b|ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_B" \
        "$host_b" \
        "PROFILE_DEFAULT_GATE_STABILITY_HOST_B" "B_HOST" "HOST_B")"
      runtime_requirements_json="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$runtime_requirements_json")"
      if [[ "$runtime_input_last_state" == "resolved" ]]; then
        track_runtime_input_value["$track_id:host_b"]="$runtime_input_last_value"
        if [[ -z "$host_b" ]]; then
          host_b="$runtime_input_last_value"
        fi
      fi

      row_json="$(resolve_scalar_runtime_input_state_json \
        "campaign_subject" \
        "Concrete invite/campaign subject for profile-default gate checks." \
        "Set --campaign-subject (or PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT/CAMPAIGN_SUBJECT/INVITE_KEY) to a real invite subject." \
        "arg_or_env:--campaign-subject|ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_CAMPAIGN_SUBJECT" \
        "$campaign_subject" \
        "PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT" "CAMPAIGN_SUBJECT" "INVITE_KEY")"
      runtime_requirements_json="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$runtime_requirements_json")"
      if [[ "$runtime_input_last_state" == "resolved" ]]; then
        track_runtime_input_value["$track_id:campaign_subject"]="$runtime_input_last_value"
        if [[ -z "$campaign_subject" ]]; then
          campaign_subject="$runtime_input_last_value"
        fi
      fi
      ;;
    m4_runtime_actuation_promotion_live_archive_and_pack)
      row_json="$(resolve_scalar_runtime_input_state_json \
        "campaign_subject" \
        "Concrete invite/campaign subject for runtime-actuation promotion checks." \
        "Set --campaign-subject (or CAMPAIGN_SUBJECT/INVITE_KEY) to a real invite subject." \
        "arg_or_env:--campaign-subject|ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_CAMPAIGN_SUBJECT" \
        "$campaign_subject" \
        "PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT" "CAMPAIGN_SUBJECT" "INVITE_KEY")"
      runtime_requirements_json="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$runtime_requirements_json")"
      if [[ "$runtime_input_last_state" == "resolved" ]]; then
        track_runtime_input_value["$track_id:campaign_subject"]="$runtime_input_last_value"
        if [[ -z "$campaign_subject" ]]; then
          campaign_subject="$runtime_input_last_value"
        fi
      fi
      ;;
    m5_profile_compare_multi_vm_stability_promotion_live_archive_and_pack)
      row_json="$(resolve_m5_vm_command_source_state_json \
        "arg_or_env:--vm-command-file|ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_VM_COMMAND_FILE" \
        "$m5_vm_command_file")"
      runtime_requirements_json="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$runtime_requirements_json")"
      if [[ "$runtime_input_last_state" == "resolved" ]]; then
        track_runtime_input_value["$track_id:vm_command_source"]="$runtime_input_last_value"
        if [[ -z "$m5_vm_command_file" ]]; then
          m5_vm_command_file="$runtime_input_last_value"
        fi
      fi
      ;;
    *)
      ;;
  esac

  runtime_unresolved_inputs_json="$(jq -c '[.[] | select(.required == true and .state != "resolved") | .id]' <<<"$runtime_requirements_json")"
  runtime_unresolved_count="$(jq -r 'length' <<<"$runtime_unresolved_inputs_json")"
  if (( runtime_unresolved_count > 0 )); then
    runtime_failure_reason="$(jq -r '[.[] | select(.required == true and .state != "resolved") | "\(.id)=\(.state)"] | join(", ")' <<<"$runtime_requirements_json")"
    runtime_failure_codes_json="$(jq -c '[.[] | select(.required == true and .state != "resolved") | "runtime_input_unresolved:\(.id):\(.state)"]' <<<"$runtime_requirements_json")"
    track_runtime_preflight_ok["$track_id"]="0"
    track_runtime_preflight_failure_substep["$track_id"]="preflight:runtime_inputs_unresolved_or_placeholder"
    track_runtime_preflight_failure_reason["$track_id"]="$runtime_failure_reason"
    track_runtime_preflight_failure_codes_json["$track_id"]="$runtime_failure_codes_json"
    track_preflight_failure_substep["$track_id"]="preflight:runtime_inputs_unresolved_or_placeholder"
    track_preflight_failure_reason["$track_id"]="$runtime_failure_reason"
    track_preflight_failure_codes_json["$track_id"]="$(jq -c --argjson existing "${track_preflight_failure_codes_json[$track_id]}" --argjson runtime "$runtime_failure_codes_json" '$existing + $runtime')"

    preflight_failed="1"
    runtime_input_preflight_failed="1"
    unresolved_runtime_input_track_count=$((unresolved_runtime_input_track_count + 1))
    unresolved_runtime_input_count=$((unresolved_runtime_input_count + runtime_unresolved_count))
    track_status["$track_id"]="fail"
    track_rc["$track_id"]="2"
    if [[ -n "${track_notes[$track_id]}" ]]; then
      track_notes["$track_id"]="${track_notes[$track_id]};runtime_input_preflight_failed"
    else
      track_notes["$track_id"]="runtime_input_preflight_failed"
    fi
    if [[ -z "$preflight_failure_reason" ]]; then
      preflight_failure_reason="unresolved required runtime inputs for $track_id: ${runtime_failure_reason:-unknown}"
    fi

    jq -n \
      --arg track_id "$track_id" \
      --arg label "${track_label[$track_id]}" \
      --arg failure_substep "preflight:runtime_inputs_unresolved_or_placeholder" \
      --arg failure_reason "$runtime_failure_reason" \
      --argjson unresolved_required_inputs "$runtime_unresolved_inputs_json" \
      --argjson unresolved_required_count "$runtime_unresolved_count" \
      --argjson required_runtime_inputs "$runtime_requirements_json" \
      --argjson failure_codes "$runtime_failure_codes_json" \
      '{
        track_id: $track_id,
        label: $label,
        failure_substep: $failure_substep,
        failure_reason: (if $failure_reason == "" then null else $failure_reason end),
        unresolved_required_inputs: $unresolved_required_inputs,
        unresolved_required_count: $unresolved_required_count,
        failure_codes: $failure_codes,
        required_runtime_inputs: $required_runtime_inputs
      }' >>"$runtime_input_preflight_failures_jsonl"
  fi

  track_runtime_required_inputs_json["$track_id"]="$runtime_requirements_json"
  track_runtime_unresolved_inputs_json["$track_id"]="$runtime_unresolved_inputs_json"
  track_runtime_unresolved_count["$track_id"]="$runtime_unresolved_count"
done

if [[ "$preflight_failed" == "1" ]]; then
  for track_id in "${track_ids[@]}"; do
    if [[ "${track_status[$track_id]}" == "pending" ]]; then
      track_status["$track_id"]="skipped"
      track_rc["$track_id"]="null"
      if [[ "$helper_preflight_failed" == "1" ]]; then
        track_notes["$track_id"]="preflight_aborted_due_to_missing_or_unreadable_helper"
      elif [[ "$runtime_input_preflight_failed" == "1" ]]; then
        track_notes["$track_id"]="preflight_aborted_due_to_unresolved_runtime_inputs"
      else
        track_notes["$track_id"]="preflight_aborted"
      fi
    fi
  done
else
  for track_id in "${track_ids[@]}"; do
    mkdir -p "${track_reports_dir[$track_id]}"
    rm -f "${track_summary_json[$track_id]}" "${track_log[$track_id]}"

    track_started_at["$track_id"]="$(timestamp_utc)"

    declare -a cmd=()
    declare -a cmd_prefix=()
    cmd=(
      bash "${track_script[$track_id]}"
      --reports-dir "${track_reports_dir[$track_id]}"
      --summary-json "${track_summary_json[$track_id]}"
      --fail-on-no-go 1
      --print-summary-json 0
    )

    if [[ "$track_id" == "m2_profile_default_gate_stability_live_archive_and_pack" ]]; then
      m2_host_a="${track_runtime_input_value["$track_id:host_a"]:-$host_a}"
      m2_host_b="${track_runtime_input_value["$track_id:host_b"]:-$host_b}"
      m2_campaign_subject="${track_runtime_input_value["$track_id:campaign_subject"]:-$campaign_subject}"
      if [[ -n "$(trim "$m2_host_a")" ]]; then
        cmd+=(--host-a "$m2_host_a")
      fi
      if [[ -n "$(trim "$m2_host_b")" ]]; then
        cmd+=(--host-b "$m2_host_b")
      fi
      if [[ -n "$(trim "$m2_campaign_subject")" ]]; then
        cmd+=(--campaign-subject "$m2_campaign_subject")
      fi
    elif [[ "$track_id" == "m4_runtime_actuation_promotion_live_archive_and_pack" ]]; then
      m4_campaign_subject="${track_runtime_input_value["$track_id:campaign_subject"]:-$campaign_subject}"
      if [[ -n "$(trim "$m4_campaign_subject")" ]]; then
        cmd+=(--campaign-subject "$m4_campaign_subject")
        cmd_prefix=(
          env
          "CAMPAIGN_SUBJECT=$m4_campaign_subject"
          "INVITE_KEY=$m4_campaign_subject"
        )
      fi
    elif [[ "$track_id" == "m5_profile_compare_multi_vm_stability_promotion_live_archive_and_pack" ]]; then
      m5_vm_command_source="${track_runtime_input_value["$track_id:vm_command_source"]:-$m5_vm_command_file}"
      if [[ -n "$(trim "$m5_vm_command_source")" ]]; then
        cmd_prefix=(
          env
          "PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE=$m5_vm_command_source"
          "PROFILE_COMPARE_MULTI_VM_STABILITY_VM_COMMAND_FILE=$m5_vm_command_source"
          "PROFILE_COMPARE_MULTI_VM_VM_COMMAND_FILE=$m5_vm_command_source"
        )
      fi
    fi

    if (( ${#cmd_prefix[@]} > 0 )); then
      cmd=("${cmd_prefix[@]}" "${cmd[@]}")
    fi

    track_command["$track_id"]="$(render_invocation_command "${cmd[@]}")"

    echo "[roadmap-live-promotion-closure-run] stage=track status=running track_id=$track_id helper=${track_script[$track_id]}"
    set +e
    "${cmd[@]}" >"${track_log[$track_id]}" 2>&1
    run_rc=$?
    set -e
    track_run_rc["$track_id"]="$run_rc"
    track_completed_at["$track_id"]="$(timestamp_utc)"
    track_executed["$track_id"]="1"

    summary_valid="0"
    observed_status=""
    observed_rc="null"
    observed_schema_id=""
    schema_valid="0"
    if [[ -f "${track_summary_json[$track_id]}" ]] && jq -e 'type == "object"' "${track_summary_json[$track_id]}" >/dev/null 2>&1; then
      summary_valid="1"
      observed_status="$(jq -r '.status // "" | tostring | ascii_downcase' "${track_summary_json[$track_id]}")"
      observed_rc_raw="$(jq -r '.rc // empty | tostring' "${track_summary_json[$track_id]}")"
      observed_schema_id="$(jq -r 'if (.schema.id | type) == "string" then .schema.id else "" end' "${track_summary_json[$track_id]}")"
      if [[ "$observed_schema_id" == "${track_expected_schema_id[$track_id]}" ]]; then
        schema_valid="1"
      fi
      if [[ "$observed_rc_raw" =~ ^-?[0-9]+$ ]]; then
        observed_rc="$observed_rc_raw"
      fi
    fi
    track_summary_valid["$track_id"]="$summary_valid"
    track_observed_status["$track_id"]="$observed_status"
    track_observed_rc["$track_id"]="$observed_rc"
    track_observed_schema_id["$track_id"]="$observed_schema_id"
    track_schema_valid["$track_id"]="$schema_valid"

    contract_valid="0"
    contract_failure_reason=""
    effective_status="fail"
    effective_rc="$run_rc"

    if [[ "$run_rc" -ne 0 ]]; then
      contract_failure_reason="helper process exited non-zero (run_rc=$run_rc)"
    elif [[ "$summary_valid" != "1" ]]; then
      contract_failure_reason="summary missing or invalid JSON object"
    elif [[ "$schema_valid" != "1" ]]; then
      contract_failure_reason="summary schema.id mismatch (expected ${track_expected_schema_id[$track_id]})"
    elif [[ "$observed_status" != "pass" && "$observed_status" != "fail" ]]; then
      contract_failure_reason="summary status must be pass or fail"
    elif [[ "$observed_rc" == "null" ]]; then
      contract_failure_reason="summary rc must be an integer"
    elif [[ "$observed_rc" == "0" && "$observed_status" != "pass" ]]; then
      contract_failure_reason="summary contract mismatch: rc=0 requires status=pass"
    elif [[ "$observed_rc" != "0" && "$observed_status" != "fail" ]]; then
      contract_failure_reason="summary contract mismatch: rc!=0 requires status=fail"
    elif [[ "$observed_rc" != "$run_rc" ]]; then
      contract_failure_reason="summary rc mismatch: observed_rc=$observed_rc run_rc=$run_rc"
    else
      contract_valid="1"
      effective_status="$observed_status"
      effective_rc="$observed_rc"
    fi

    if [[ "$contract_valid" != "1" ]]; then
      effective_status="fail"
      if [[ "$run_rc" == "0" ]]; then
        effective_rc="125"
      else
        effective_rc="$run_rc"
      fi
    fi

    track_contract_valid["$track_id"]="$contract_valid"
    track_contract_failure_reason["$track_id"]="$contract_failure_reason"
    track_status["$track_id"]="$effective_status"
    track_rc["$track_id"]="$effective_rc"
    if [[ "$effective_status" == "pass" ]]; then
      track_notes["$track_id"]=""
      echo "[roadmap-live-promotion-closure-run] stage=track status=pass track_id=$track_id rc=0"
    else
      if [[ -n "$contract_failure_reason" ]]; then
        track_notes["$track_id"]="helper_failed_or_summary_contract_violation"
      else
        track_notes["$track_id"]="helper_failed"
      fi
      echo "[roadmap-live-promotion-closure-run] stage=track status=fail track_id=$track_id rc=$effective_rc"
    fi
  done
fi

total_tracks="${#track_ids[@]}"
executed_tracks=0
pass_tracks=0
fail_tracks=0
skipped_tracks=0
first_failure_track_id=""
first_failure_rc="1"

for track_id in "${track_ids[@]}"; do
  status="${track_status[$track_id]}"
  if [[ "${track_executed[$track_id]}" == "1" ]]; then
    executed_tracks=$((executed_tracks + 1))
  fi
  case "$status" in
    pass)
      pass_tracks=$((pass_tracks + 1))
      ;;
    fail)
      fail_tracks=$((fail_tracks + 1))
      if [[ -z "$first_failure_track_id" ]]; then
        first_failure_track_id="$track_id"
        if [[ "${track_rc[$track_id]}" =~ ^-?[0-9]+$ ]]; then
          first_failure_rc="${track_rc[$track_id]}"
        else
          first_failure_rc="1"
        fi
      fi
      ;;
    *)
      skipped_tracks=$((skipped_tracks + 1))
      ;;
  esac
done

final_status="pass"
final_rc="0"
failure_substep=""
failure_reason=""

if [[ "$preflight_failed" == "1" ]]; then
  if [[ "$helper_preflight_failed" == "1" ]]; then
    final_status="fail"
    final_rc="2"
    failure_substep="preflight:helpers_missing_or_unreadable"
    failure_reason="${preflight_failure_reason:-missing or unreadable helper script}"
  else
    final_status="fail"
    final_rc="2"
    failure_substep="preflight:runtime_inputs_unresolved_or_placeholder"
    failure_reason="${preflight_failure_reason:-required runtime inputs unresolved or placeholder}"
  fi
elif (( fail_tracks > 0 )); then
  final_status="fail"
  final_rc="$first_failure_rc"
  failure_substep="track:${first_failure_track_id}"
  failure_reason="first failing track in deterministic M2/M4/M5 order"
fi

preflight_ok="1"
if [[ "$preflight_failed" == "1" ]]; then
  preflight_ok="0"
fi
helper_preflight_ok="1"
if [[ "$helper_preflight_failed" == "1" ]]; then
  helper_preflight_ok="0"
fi
runtime_input_preflight_ok="1"
if [[ "$runtime_input_preflight_failed" == "1" ]]; then
  runtime_input_preflight_ok="0"
fi
runtime_input_preflight_failures_json='[]'
if [[ -s "$runtime_input_preflight_failures_jsonl" ]]; then
  runtime_input_preflight_failures_json="$(jq -s '.' "$runtime_input_preflight_failures_jsonl")"
fi

for track_id in "${track_ids[@]}"; do
  track_rc_json="${track_rc[$track_id]}"
  if [[ "$track_rc_json" != "null" && ! "$track_rc_json" =~ ^-?[0-9]+$ ]]; then
    track_rc_json="null"
  fi
  observed_rc_json="${track_observed_rc[$track_id]}"
  if [[ "$observed_rc_json" != "null" && ! "$observed_rc_json" =~ ^-?[0-9]+$ ]]; then
    observed_rc_json="null"
  fi
  run_rc_json="${track_run_rc[$track_id]}"
  if [[ "$run_rc_json" != "null" && ! "$run_rc_json" =~ ^-?[0-9]+$ ]]; then
    run_rc_json="null"
  fi
  track_preflight_failure_substep_value="${track_preflight_failure_substep[$track_id]}"
  track_preflight_failure_reason_value="${track_preflight_failure_reason[$track_id]}"
  track_preflight_failure_codes_json_value="${track_preflight_failure_codes_json[$track_id]}"
  if [[ -z "$track_preflight_failure_codes_json_value" ]]; then
    track_preflight_failure_codes_json_value='[]'
  fi
  runtime_required_inputs_json="${track_runtime_required_inputs_json[$track_id]}"
  if [[ -z "$runtime_required_inputs_json" ]]; then
    runtime_required_inputs_json='[]'
  fi
  runtime_unresolved_inputs_json="${track_runtime_unresolved_inputs_json[$track_id]}"
  if [[ -z "$runtime_unresolved_inputs_json" ]]; then
    runtime_unresolved_inputs_json='[]'
  fi
  runtime_unresolved_count_json="${track_runtime_unresolved_count[$track_id]}"
  if ! [[ "$runtime_unresolved_count_json" =~ ^[0-9]+$ ]]; then
    runtime_unresolved_count_json="0"
  fi
  runtime_preflight_ok_json="${track_runtime_preflight_ok[$track_id]}"
  if [[ "$runtime_preflight_ok_json" != "0" && "$runtime_preflight_ok_json" != "1" ]]; then
    runtime_preflight_ok_json="0"
  fi
  runtime_preflight_failure_substep_value="${track_runtime_preflight_failure_substep[$track_id]}"
  runtime_preflight_failure_reason_value="${track_runtime_preflight_failure_reason[$track_id]}"
  runtime_preflight_failure_codes_json_value="${track_runtime_preflight_failure_codes_json[$track_id]}"
  if [[ -z "$runtime_preflight_failure_codes_json_value" ]]; then
    runtime_preflight_failure_codes_json_value='[]'
  fi

  jq -n \
    --arg track_id "$track_id" \
    --arg label "${track_label[$track_id]}" \
    --arg status "${track_status[$track_id]}" \
    --argjson rc "$track_rc_json" \
    --arg script_path "${track_script[$track_id]}" \
    --arg reports_dir "${track_reports_dir[$track_id]}" \
    --arg summary_json "${track_summary_json[$track_id]}" \
    --arg log "${track_log[$track_id]}" \
    --arg command "${track_command[$track_id]}" \
    --arg started_at "${track_started_at[$track_id]}" \
    --arg completed_at "${track_completed_at[$track_id]}" \
    --arg notes "${track_notes[$track_id]}" \
    --arg observed_status "${track_observed_status[$track_id]}" \
    --arg observed_schema_id "${track_observed_schema_id[$track_id]}" \
    --arg expected_schema_id "${track_expected_schema_id[$track_id]}" \
    --arg contract_failure_reason "${track_contract_failure_reason[$track_id]}" \
    --argjson run_rc "$run_rc_json" \
    --argjson observed_rc "$observed_rc_json" \
    --argjson helper_available "${track_helper_available[$track_id]}" \
    --argjson helper_readable "${track_helper_readable[$track_id]}" \
    --argjson executed "${track_executed[$track_id]}" \
    --argjson summary_valid "${track_summary_valid[$track_id]}" \
    --argjson schema_valid "${track_schema_valid[$track_id]}" \
    --argjson contract_valid "${track_contract_valid[$track_id]}" \
    --arg preflight_failure_substep "$track_preflight_failure_substep_value" \
    --arg preflight_failure_reason "$track_preflight_failure_reason_value" \
    --argjson preflight_failure_codes "$track_preflight_failure_codes_json_value" \
    --argjson runtime_required_inputs "$runtime_required_inputs_json" \
    --argjson runtime_unresolved_inputs "$runtime_unresolved_inputs_json" \
    --argjson runtime_unresolved_count "$runtime_unresolved_count_json" \
    --argjson runtime_preflight_ok "$runtime_preflight_ok_json" \
    --arg runtime_preflight_failure_substep "$runtime_preflight_failure_substep_value" \
    --arg runtime_preflight_failure_reason "$runtime_preflight_failure_reason_value" \
    --argjson runtime_preflight_failure_codes "$runtime_preflight_failure_codes_json_value" \
    '{
      track_id: $track_id,
      label: $label,
      status: $status,
      rc: $rc,
      executed: ($executed == 1),
      helper: {
        script_path: $script_path,
        available: ($helper_available == 1),
        readable: ($helper_readable == 1)
      },
      preflight: {
        ok: ($helper_available == 1 and $helper_readable == 1 and $runtime_preflight_ok == 1),
        failure_substep: (if $preflight_failure_substep == "" then null else $preflight_failure_substep end),
        failure_reason: (if $preflight_failure_reason == "" then null else $preflight_failure_reason end),
        failure_codes: $preflight_failure_codes
      },
      runtime_preflight: {
        ok: ($runtime_preflight_ok == 1),
        required_runtime_inputs: $runtime_required_inputs,
        unresolved_required_inputs: $runtime_unresolved_inputs,
        unresolved_required_count: $runtime_unresolved_count,
        failure_substep: (if $runtime_preflight_failure_substep == "" then null else $runtime_preflight_failure_substep end),
        failure_reason: (if $runtime_preflight_failure_reason == "" then null else $runtime_preflight_failure_reason end),
        failure_codes: $runtime_preflight_failure_codes
      },
      contract: {
        summary_valid: ($summary_valid == 1),
        expected_schema_id: $expected_schema_id,
        observed_schema_id: (if $observed_schema_id == "" then null else $observed_schema_id end),
        schema_valid: ($schema_valid == 1),
        valid: ($contract_valid == 1),
        failure_reason: (if $contract_failure_reason == "" then null else $contract_failure_reason end),
        run_rc: $run_rc,
        observed_status: (if $observed_status == "" then null else $observed_status end),
        observed_rc: $observed_rc
      },
      artifacts: {
        reports_dir: $reports_dir,
        summary_json: $summary_json,
        log: $log
      },
      command: (if $command == "" then null else $command end),
      started_at: (if $started_at == "" then null else $started_at end),
      completed_at: (if $completed_at == "" then null else $completed_at end),
      notes: (if $notes == "" then null else $notes end)
    }' >>"$tracks_jsonl"
done

tracks_json="$(jq -s '.' "$tracks_jsonl")"

host_a_provided="0"
host_b_provided="0"
campaign_subject_provided="0"
m5_vm_command_file_provided="0"
if [[ -n "$(trim "$host_a")" ]]; then
  host_a_provided="1"
fi
if [[ -n "$(trim "$host_b")" ]]; then
  host_b_provided="1"
fi
if [[ -n "$(trim "$campaign_subject")" ]]; then
  campaign_subject_provided="1"
fi
if [[ -n "$(trim "$m5_vm_command_file")" ]]; then
  m5_vm_command_file_provided="1"
fi

completed_at="$(timestamp_utc)"

jq -n \
  --arg started_at "$started_at" \
  --arg completed_at "$completed_at" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg failure_substep "$failure_substep" \
  --arg failure_reason "$failure_reason" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg m2_script "$m2_script" \
  --arg m4_script "$m4_script" \
  --arg m5_script "$m5_script" \
  --arg first_failure_track_id "$first_failure_track_id" \
  --argjson host_a_provided "$host_a_provided" \
  --argjson host_b_provided "$host_b_provided" \
  --argjson campaign_subject_provided "$campaign_subject_provided" \
  --argjson m5_vm_command_file_provided "$m5_vm_command_file_provided" \
  --argjson print_summary_json "$print_summary_json" \
  --argjson preflight_ok "$preflight_ok" \
  --argjson helper_preflight_ok "$helper_preflight_ok" \
  --argjson runtime_input_preflight_ok "$runtime_input_preflight_ok" \
  --argjson missing_or_unreadable_helper_count "$missing_or_unreadable_helper_count" \
  --argjson unresolved_runtime_input_track_count "$unresolved_runtime_input_track_count" \
  --argjson unresolved_runtime_input_count "$unresolved_runtime_input_count" \
  --argjson runtime_input_preflight_failures "$runtime_input_preflight_failures_json" \
  --argjson total_tracks "$total_tracks" \
  --argjson executed_tracks "$executed_tracks" \
  --argjson pass_tracks "$pass_tracks" \
  --argjson fail_tracks "$fail_tracks" \
  --argjson skipped_tracks "$skipped_tracks" \
  --argjson tracks "$tracks_json" \
  '{
    version: 1,
    schema: { id: "roadmap_live_promotion_closure_run_summary", major: 1, minor: 0 },
    status: $status,
    rc: $rc,
    failure_substep: (if $failure_substep == "" then null else $failure_substep end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    timestamps: {
      started_at: $started_at,
      completed_at: $completed_at
    },
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      host_a_provided: ($host_a_provided == 1),
      host_b_provided: ($host_b_provided == 1),
      campaign_subject_provided: ($campaign_subject_provided == 1),
      m5_vm_command_file_provided: ($m5_vm_command_file_provided == 1),
      print_summary_json: ($print_summary_json == 1)
    },
    preflight: {
      ok: ($preflight_ok == 1),
      helper_scripts_ok: ($helper_preflight_ok == 1),
      runtime_inputs_ok: ($runtime_input_preflight_ok == 1),
      missing_or_unreadable_helper_count: $missing_or_unreadable_helper_count,
      unresolved_runtime_input_track_count: $unresolved_runtime_input_track_count,
      unresolved_runtime_input_count: $unresolved_runtime_input_count,
      runtime_input_failures: $runtime_input_preflight_failures
    },
    helper_scripts: {
      m2: $m2_script,
      m4: $m4_script,
      m5: $m5_script
    },
    summary: {
      total_tracks: $total_tracks,
      executed_tracks: $executed_tracks,
      pass_tracks: $pass_tracks,
      fail_tracks: $fail_tracks,
      skipped_tracks: $skipped_tracks,
      preflight_ok: ($preflight_ok == 1),
      helper_preflight_ok: ($helper_preflight_ok == 1),
      runtime_input_preflight_ok: ($runtime_input_preflight_ok == 1),
      missing_or_unreadable_helper_count: $missing_or_unreadable_helper_count,
      unresolved_runtime_input_track_count: $unresolved_runtime_input_track_count,
      unresolved_runtime_input_count: $unresolved_runtime_input_count,
      first_failure_track_id: (if $first_failure_track_id == "" then null else $first_failure_track_id end)
    },
    tracks: $tracks,
    artifacts: {
      summary_json: $summary_json
    }
  }' >"$summary_json"

echo "[roadmap-live-promotion-closure-run] status=$final_status rc=$final_rc executed_tracks=$executed_tracks pass_tracks=$pass_tracks fail_tracks=$fail_tracks skipped_tracks=$skipped_tracks"
echo "[roadmap-live-promotion-closure-run] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
