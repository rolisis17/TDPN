#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_live_promotion_prepare_env.sh \
    [--reports-dir DIR] \
    [--roadmap-summary-json PATH] \
    [--summary-json PATH] \
    [--host-a HOST] \
    [--host-b HOST] \
    [--campaign-subject ID] \
    [--vm-command-source PATH] \
    [--require-summary [0|1]] \
    [--print-shell [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Resolve required runtime inputs for live promotion closures (M2/M4/M5) from
  roadmap summary commands and/or environment, then print export-ready shell
  commands when all required inputs are concretely resolved.

Resolved runtime inputs:
  - M2: host-a, host-b, campaign-subject
  - M4: no additional runtime input values required by this helper
  - M5: vm-command-source

Fail-closed behavior:
  - Placeholder values are treated as unresolved and skipped.
  - If any required input remains unresolved, no shell exports are emitted and
    rc is non-zero.

Defaults:
  --reports-dir .easy-node-logs
  --roadmap-summary-json <reports-dir>/roadmap_progress_summary.json
  --summary-json <reports-dir>/roadmap_live_promotion_prepare_env_summary.json
  --require-summary 0
  --print-shell 1
  --print-summary-json 0

Env precedence for runtime values:
  host-a:
    ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_HOST_A
    ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_A
    A_HOST
    HOST_A
  host-b:
    ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_HOST_B
    ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_B
    B_HOST
    HOST_B
  campaign-subject:
    ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_CAMPAIGN_SUBJECT
    ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_CAMPAIGN_SUBJECT
    CAMPAIGN_SUBJECT
    INVITE_KEY
  vm-command-source:
    ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_VM_COMMAND_SOURCE
    VM_COMMAND_SOURCE
    VM_COMMAND_FILE
    VM_COMMAND
USAGE
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

path_is_cross_platform_absolute_01() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '0'
    return
  fi
  if [[ "$path" == /* ]]; then
    printf '1'
    return
  fi
  if [[ "$path" =~ ^[A-Za-z]:[\\/].* ]]; then
    printf '1'
    return
  fi
  if [[ "$path" =~ ^\\\\.* ]]; then
    printf '1'
    return
  fi
  if [[ "$path" == //* ]]; then
    printf '1'
    return
  fi
  printf '0'
}

normalize_cross_platform_path_separators() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$path" =~ ^[A-Za-z]:[\\/].* ]] || [[ "$path" =~ ^\\\\.* ]] || [[ "$path" == //* ]]; then
    printf '%s' "${path//\\//}"
    return
  fi
  printf '%s' "$path"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$(path_is_cross_platform_absolute_01 "$path")" == "1" ]]; then
    printf '%s' "$(normalize_cross_platform_path_separators "$path")"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1" >&2
    exit 2
  fi
}

require_value_or_die() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
    echo "$flag requires a value" >&2
    exit 2
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 2
  fi
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

value_matches_placeholder_token_01() {
  local value token normalized
  value="$(trim "${1:-}")"
  token="$(trim "${2:-}")"
  if [[ -z "$value" || -z "$token" ]]; then
    return 1
  fi
  value="$(strip_optional_wrapping_quotes_01 "$value")"
  normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  token="$(printf '%s' "$token" | tr '[:lower:]' '[:upper:]')"
  case "$normalized" in
    "$token"|\$\{"$token"\}|\$"$token"|"<$token>"|"{{$token}}"|YOUR_"$token"|REPLACE_WITH_"$token"|%$token%|\$\{"$token":-*}|\$\{"$token"-*})
      return 0
      ;;
  esac
  return 1
}

host_a_value_looks_placeholder_01() {
  local value
  value="$(trim "${1:-}")"
  for token in A_HOST HOST_A; do
    if value_matches_placeholder_token_01 "$value" "$token"; then
      return 0
    fi
  done
  return 1
}

host_b_value_looks_placeholder_01() {
  local value
  value="$(trim "${1:-}")"
  for token in B_HOST HOST_B; do
    if value_matches_placeholder_token_01 "$value" "$token"; then
      return 0
    fi
  done
  return 1
}

subject_value_looks_placeholder_01() {
  local value
  value="$(trim "${1:-}")"
  for token in INVITE_KEY CAMPAIGN_SUBJECT INVITE_SUBJECT; do
    if value_matches_placeholder_token_01 "$value" "$token"; then
      return 0
    fi
  done
  return 1
}

vm_command_source_value_looks_placeholder_01() {
  local value
  value="$(trim "${1:-}")"
  for token in VM_COMMAND_SOURCE VM_COMMAND_FILE VM_COMMAND; do
    if value_matches_placeholder_token_01 "$value" "$token"; then
      return 0
    fi
  done
  value="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  case "$value" in
    "<VM-COMMAND>"|"<SET-VM-COMMAND-SOURCE>"|REPLACE_WITH_VM_COMMAND_SOURCE|REPLACE_WITH_VM_COMMAND_FILE)
      return 0
      ;;
  esac
  return 1
}

COMMAND_STRING_ARGV=()
command_string_to_argv_01() {
  local command_text="${1:-}"
  local length=0
  local idx=0
  local ch=""
  local token=""
  local quote_mode=""
  local escaped="0"
  local token_started="0"
  COMMAND_STRING_ARGV=()
  length="${#command_text}"

  while (( idx < length )); do
    ch="${command_text:idx:1}"
    if [[ "$quote_mode" == "single" ]]; then
      if [[ "$ch" == "'" ]]; then
        quote_mode=""
      else
        token+="$ch"
      fi
      token_started="1"
      idx=$((idx + 1))
      continue
    fi
    if [[ "$quote_mode" == "double" ]]; then
      if [[ "$escaped" == "1" ]]; then
        token+="$ch"
        escaped="0"
        token_started="1"
        idx=$((idx + 1))
        continue
      fi
      case "$ch" in
        "\\")
          escaped="1"
          ;;
        "\"")
          quote_mode=""
          ;;
        *)
          token+="$ch"
          token_started="1"
          ;;
      esac
      idx=$((idx + 1))
      continue
    fi
    if [[ "$escaped" == "1" ]]; then
      token+="$ch"
      escaped="0"
      token_started="1"
      idx=$((idx + 1))
      continue
    fi
    case "$ch" in
      [[:space:]])
        if [[ "$token_started" == "1" ]]; then
          COMMAND_STRING_ARGV+=("$token")
          token=""
          token_started="0"
        fi
        ;;
      "\\")
        escaped="1"
        token_started="1"
        ;;
      "'")
        quote_mode="single"
        token_started="1"
        ;;
      "\"")
        quote_mode="double"
        token_started="1"
        ;;
      *)
        token+="$ch"
        token_started="1"
        ;;
    esac
    idx=$((idx + 1))
  done

  if [[ "$escaped" == "1" || -n "$quote_mode" ]]; then
    COMMAND_STRING_ARGV=()
    return 1
  fi
  if [[ "$token_started" == "1" ]]; then
    COMMAND_STRING_ARGV+=("$token")
  fi
  [[ "${#COMMAND_STRING_ARGV[@]}" -gt 0 ]]
}

command_extract_first_flag_value_01() {
  local command_text="${1:-}"
  local token=""
  local key=""
  local idx=0
  local token_count=0
  local flag=""
  local -a argv=()
  shift || true
  if [[ -z "$command_text" || $# -eq 0 ]]; then
    printf '%s' ""
    return
  fi
  if ! command_string_to_argv_01 "$command_text"; then
    printf '%s' ""
    return
  fi
  argv=("${COMMAND_STRING_ARGV[@]}")
  token_count="${#argv[@]}"
  while (( idx < token_count )); do
    token="${argv[$idx]}"
    for flag in "$@"; do
      if [[ "$token" == "$flag" ]]; then
        if (( idx + 1 < token_count )); then
          printf '%s' "${argv[$((idx + 1))]}"
        else
          printf '%s' ""
        fi
        return
      fi
      if [[ "$token" == "$flag="* ]]; then
        printf '%s' "${token#"$flag="}"
        return
      fi
    done
    if [[ "$token" == --*=* ]]; then
      key="${token%%=*}"
      for flag in "$@"; do
        if [[ "$key" == "$flag" ]]; then
          printf '%s' "${token#*=}"
          return
        fi
      done
    fi
    idx=$((idx + 1))
  done
  printf '%s' ""
}

extract_host_a_value_from_command_01() {
  local command_text="${1:-}"
  local value
  value="$(command_extract_first_flag_value_01 "$command_text" --host-a --host_a)"
  value="$(trim "$value")"
  if [[ -n "$value" ]] && ! host_a_value_looks_placeholder_01 "$value"; then
    printf '%s' "$value"
    return
  fi
  printf '%s' ""
}

extract_host_b_value_from_command_01() {
  local command_text="${1:-}"
  local value
  value="$(command_extract_first_flag_value_01 "$command_text" --host-b --host_b)"
  value="$(trim "$value")"
  if [[ -n "$value" ]] && ! host_b_value_looks_placeholder_01 "$value"; then
    printf '%s' "$value"
    return
  fi
  printf '%s' ""
}

extract_campaign_subject_value_from_command_01() {
  local command_text="${1:-}"
  local value
  value="$(command_extract_first_flag_value_01 "$command_text" --campaign-subject --campaign_subject --subject)"
  value="$(trim "$value")"
  if [[ -n "$value" ]] && ! subject_value_looks_placeholder_01 "$value"; then
    printf '%s' "$value"
    return
  fi
  printf '%s' ""
}

extract_vm_command_source_value_from_command_01() {
  local command_text="${1:-}"
  local value
  value="$(command_extract_first_flag_value_01 "$command_text" --vm-command-source --vm_command_source --vm-command-file --vm-command)"
  value="$(trim "$value")"
  if [[ -n "$value" ]] && ! vm_command_source_value_looks_placeholder_01 "$value"; then
    printf '%s' "$value"
    return
  fi
  printf '%s' ""
}

extract_first_runtime_value_from_commands_json_01() {
  local commands_json="${1:-[]}"
  local extractor="${2:-}"
  local command_text=""
  local candidate=""
  if [[ -z "$extractor" ]]; then
    printf '%s' ""
    return
  fi
  while IFS= read -r command_text; do
    command_text="$(trim "$command_text")"
    if [[ -z "$command_text" ]]; then
      continue
    fi
    candidate="$("$extractor" "$command_text")"
    candidate="$(trim "$candidate")"
    if [[ -n "$candidate" ]]; then
      printf '%s' "$candidate"
      return
    fi
  done < <(printf '%s' "$commands_json" | jq -r '.[]? // empty')
  printf '%s' ""
}

add_export_line_01() {
  local var_name="$1"
  local value="$2"
  local sensitive="${3:-0}"
  local rendered_value
  rendered_value="$(printf '%q' "$value")"
  export_lines+=("export ${var_name}=${rendered_value}")
  export_vars+=("$var_name")
  if [[ "$sensitive" == "1" ]]; then
    export_lines_redacted+=("export ${var_name}='[redacted]'")
  else
    export_lines_redacted+=("export ${var_name}=${rendered_value}")
  fi
}

append_unresolved_key_01() {
  local key="$1"
  local seen=""
  for seen in "${unresolved_keys[@]}"; do
    if [[ "$seen" == "$key" ]]; then
      return
    fi
  done
  unresolved_keys+=("$key")
}

json_from_array_lines_01() {
  if [[ $# -eq 0 ]]; then
    printf '[]'
    return
  fi
  printf '%s\n' "$@" | jq -R . | jq -sc '.'
}

need_cmd bash
need_cmd jq
need_cmd date
need_cmd mktemp
need_cmd paste

reports_dir="${ROADMAP_LIVE_PROMOTION_PREPARE_ENV_REPORTS_DIR:-.easy-node-logs}"
roadmap_summary_json="${ROADMAP_LIVE_PROMOTION_PREPARE_ENV_ROADMAP_SUMMARY_JSON:-}"
summary_json="${ROADMAP_LIVE_PROMOTION_PREPARE_ENV_SUMMARY_JSON:-}"

host_a_arg=""
host_b_arg=""
campaign_subject_arg=""
vm_command_source_arg=""
host_a_arg_provided="0"
host_b_arg_provided="0"
campaign_subject_arg_provided="0"
vm_command_source_arg_provided="0"

require_summary="${ROADMAP_LIVE_PROMOTION_PREPARE_ENV_REQUIRE_SUMMARY:-0}"
print_shell="${ROADMAP_LIVE_PROMOTION_PREPARE_ENV_PRINT_SHELL:-1}"
print_summary_json="${ROADMAP_LIVE_PROMOTION_PREPARE_ENV_PRINT_SUMMARY_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      require_value_or_die "$1" "${2:-}"
      reports_dir="${2:-}"
      shift 2
      ;;
    --roadmap-summary-json)
      require_value_or_die "$1" "${2:-}"
      roadmap_summary_json="${2:-}"
      shift 2
      ;;
    --summary-json)
      require_value_or_die "$1" "${2:-}"
      summary_json="${2:-}"
      shift 2
      ;;
    --host-a)
      require_value_or_die "$1" "${2:-}"
      host_a_arg="${2:-}"
      host_a_arg_provided="1"
      shift 2
      ;;
    --host-b)
      require_value_or_die "$1" "${2:-}"
      host_b_arg="${2:-}"
      host_b_arg_provided="1"
      shift 2
      ;;
    --campaign-subject|--subject)
      require_value_or_die "$1" "${2:-}"
      campaign_subject_arg="${2:-}"
      campaign_subject_arg_provided="1"
      shift 2
      ;;
    --vm-command-source)
      require_value_or_die "$1" "${2:-}"
      vm_command_source_arg="${2:-}"
      vm_command_source_arg_provided="1"
      shift 2
      ;;
    --require-summary)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_summary="${2:-}"
        shift 2
      else
        require_summary="1"
        shift
      fi
      ;;
    --print-shell)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_shell="${2:-}"
        shift 2
      else
        print_shell="1"
        shift
      fi
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
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

bool_arg_or_die "--require-summary" "$require_summary"
bool_arg_or_die "--print-shell" "$print_shell"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

reports_dir="$(abs_path "$reports_dir")"
if [[ -z "$(trim "$roadmap_summary_json")" ]]; then
  roadmap_summary_json="$reports_dir/roadmap_progress_summary.json"
fi
if [[ -z "$(trim "$summary_json")" ]]; then
  summary_json="$reports_dir/roadmap_live_promotion_prepare_env_summary.json"
fi
roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
summary_json="$(abs_path "$summary_json")"

mkdir -p "$reports_dir" "$(dirname "$summary_json")"

generated_at="$(timestamp_utc)"

roadmap_summary_available="0"
roadmap_summary_valid="0"
roadmap_summary_error=""
if [[ -f "$roadmap_summary_json" ]]; then
  roadmap_summary_available="1"
  if jq -e . "$roadmap_summary_json" >/dev/null 2>&1; then
    roadmap_summary_valid="1"
  else
    roadmap_summary_error="invalid_json"
  fi
else
  roadmap_summary_error="missing_file"
fi

m2_status=""
m4_status=""
m5_status=""
m5_promotion_status=""
m2_required="1"
m4_required="0"
m5_required="1"

m2_commands_json='[]'
m5_commands_json='[]'
vm_command_file_fallback=""
vm_command_file_fallback_usable="0"

if [[ "$roadmap_summary_valid" == "1" ]]; then
  m2_status="$(jq -r '.vpn_track.profile_default_gate.status // "" | tostring | ascii_downcase' "$roadmap_summary_json")"
  m4_status="$(jq -r '.vpn_track.runtime_actuation_promotion.status // "" | tostring | ascii_downcase' "$roadmap_summary_json")"
  m5_status="$(jq -r '.vpn_track.multi_vm_stability.status // "" | tostring | ascii_downcase' "$roadmap_summary_json")"
  m5_promotion_status="$(jq -r '.vpn_track.multi_vm_stability_promotion.status // "" | tostring | ascii_downcase' "$roadmap_summary_json")"

  if [[ "$m2_status" == "pass" ]]; then
    m2_required="0"
  fi
  if [[ "$m5_status" == "pass" && "$m5_promotion_status" == "pass" ]]; then
    m5_required="0"
  fi

  m2_commands_json="$(jq -c '[
      (.vpn_track.profile_default_gate.next_command // empty),
      (.vpn_track.profile_default_gate.next_command_sudo // empty),
      ((.next_actions // [])[]? | select((.id // "") == "profile_default_gate") | (.command // empty))
    ] | map(tostring) | map(select(length > 0))' "$roadmap_summary_json")"

  m5_commands_json="$(jq -c '[
      (.vpn_track.multi_vm_stability.next_command // empty),
      (.vpn_track.multi_vm_stability_promotion.next_command // empty),
      ((.next_actions // [])[]? | select((.id // "") == "profile_compare_multi_vm_stability") | (.command // empty)),
      ((.next_actions // [])[]? | select((.id // "") == "profile_compare_multi_vm_stability_promotion") | (.command // empty))
    ] | map(tostring) | map(select(length > 0))' "$roadmap_summary_json")"

  vm_command_file_fallback="$(jq -r '.vpn_track.multi_vm_stability.vm_command_file_fallback // "" | tostring' "$roadmap_summary_json")"
  vm_command_file_fallback_usable="$(jq -r 'if (.vpn_track.multi_vm_stability.vm_command_file_fallback_usable // false) then "1" else "0" end' "$roadmap_summary_json")"
fi

runtime_host_a=""
runtime_host_a_source="missing"
runtime_host_a_configured="0"

runtime_host_b=""
runtime_host_b_source="missing"
runtime_host_b_configured="0"

runtime_campaign_subject=""
runtime_campaign_subject_source="missing"
runtime_campaign_subject_configured="0"

runtime_vm_command_source=""
runtime_vm_command_source_source="missing"
runtime_vm_command_source_configured="0"

candidate=""
if [[ "$host_a_arg_provided" == "1" ]]; then
  candidate="$(trim "$host_a_arg")"
  if [[ -n "$candidate" ]] && ! host_a_value_looks_placeholder_01 "$candidate"; then
    runtime_host_a="$candidate"
    runtime_host_a_source="cli:--host-a"
    runtime_host_a_configured="1"
  fi
fi
if [[ "$runtime_host_a_configured" != "1" ]]; then
  for env_name in ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_HOST_A ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_A A_HOST HOST_A; do
    candidate="$(trim "${!env_name:-}")"
    if [[ -n "$candidate" ]] && ! host_a_value_looks_placeholder_01 "$candidate"; then
      runtime_host_a="$candidate"
      runtime_host_a_source="env:${env_name}"
      runtime_host_a_configured="1"
      break
    fi
  done
fi
if [[ "$runtime_host_a_configured" != "1" && "$roadmap_summary_valid" == "1" ]]; then
  candidate="$(extract_first_runtime_value_from_commands_json_01 "$m2_commands_json" extract_host_a_value_from_command_01)"
  candidate="$(trim "$candidate")"
  if [[ -n "$candidate" ]]; then
    runtime_host_a="$candidate"
    runtime_host_a_source="summary_command:m2"
    runtime_host_a_configured="1"
  fi
fi

if [[ "$host_b_arg_provided" == "1" ]]; then
  candidate="$(trim "$host_b_arg")"
  if [[ -n "$candidate" ]] && ! host_b_value_looks_placeholder_01 "$candidate"; then
    runtime_host_b="$candidate"
    runtime_host_b_source="cli:--host-b"
    runtime_host_b_configured="1"
  fi
fi
if [[ "$runtime_host_b_configured" != "1" ]]; then
  for env_name in ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_HOST_B ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_B B_HOST HOST_B; do
    candidate="$(trim "${!env_name:-}")"
    if [[ -n "$candidate" ]] && ! host_b_value_looks_placeholder_01 "$candidate"; then
      runtime_host_b="$candidate"
      runtime_host_b_source="env:${env_name}"
      runtime_host_b_configured="1"
      break
    fi
  done
fi
if [[ "$runtime_host_b_configured" != "1" && "$roadmap_summary_valid" == "1" ]]; then
  candidate="$(extract_first_runtime_value_from_commands_json_01 "$m2_commands_json" extract_host_b_value_from_command_01)"
  candidate="$(trim "$candidate")"
  if [[ -n "$candidate" ]]; then
    runtime_host_b="$candidate"
    runtime_host_b_source="summary_command:m2"
    runtime_host_b_configured="1"
  fi
fi

if [[ "$campaign_subject_arg_provided" == "1" ]]; then
  candidate="$(trim "$campaign_subject_arg")"
  if [[ -n "$candidate" ]] && ! subject_value_looks_placeholder_01 "$candidate"; then
    runtime_campaign_subject="$candidate"
    runtime_campaign_subject_source="cli:--campaign-subject"
    runtime_campaign_subject_configured="1"
  fi
fi
if [[ "$runtime_campaign_subject_configured" != "1" ]]; then
  for env_name in ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_CAMPAIGN_SUBJECT ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_CAMPAIGN_SUBJECT CAMPAIGN_SUBJECT INVITE_KEY; do
    candidate="$(trim "${!env_name:-}")"
    if [[ -n "$candidate" ]] && ! subject_value_looks_placeholder_01 "$candidate"; then
      runtime_campaign_subject="$candidate"
      runtime_campaign_subject_source="env:${env_name}"
      runtime_campaign_subject_configured="1"
      break
    fi
  done
fi
if [[ "$runtime_campaign_subject_configured" != "1" && "$roadmap_summary_valid" == "1" ]]; then
  candidate="$(extract_first_runtime_value_from_commands_json_01 "$m2_commands_json" extract_campaign_subject_value_from_command_01)"
  candidate="$(trim "$candidate")"
  if [[ -n "$candidate" ]]; then
    runtime_campaign_subject="$candidate"
    runtime_campaign_subject_source="summary_command:m2"
    runtime_campaign_subject_configured="1"
  fi
fi

if [[ "$vm_command_source_arg_provided" == "1" ]]; then
  candidate="$(trim "$vm_command_source_arg")"
  if [[ -n "$candidate" ]] && ! vm_command_source_value_looks_placeholder_01 "$candidate"; then
    runtime_vm_command_source="$candidate"
    runtime_vm_command_source_source="cli:--vm-command-source"
    runtime_vm_command_source_configured="1"
  fi
fi
if [[ "$runtime_vm_command_source_configured" != "1" ]]; then
  for env_name in ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_VM_COMMAND_SOURCE VM_COMMAND_SOURCE VM_COMMAND_FILE VM_COMMAND; do
    candidate="$(trim "${!env_name:-}")"
    if [[ -n "$candidate" ]] && ! vm_command_source_value_looks_placeholder_01 "$candidate"; then
      runtime_vm_command_source="$candidate"
      runtime_vm_command_source_source="env:${env_name}"
      runtime_vm_command_source_configured="1"
      break
    fi
  done
fi
if [[ "$runtime_vm_command_source_configured" != "1" && "$roadmap_summary_valid" == "1" ]]; then
  candidate="$(trim "$vm_command_file_fallback")"
  if [[ "$vm_command_file_fallback_usable" == "1" ]] && [[ -n "$candidate" ]] && ! vm_command_source_value_looks_placeholder_01 "$candidate"; then
    runtime_vm_command_source="$candidate"
    runtime_vm_command_source_source="summary_field:multi_vm_stability.vm_command_file_fallback"
    runtime_vm_command_source_configured="1"
  fi
fi
if [[ "$runtime_vm_command_source_configured" != "1" && "$roadmap_summary_valid" == "1" ]]; then
  candidate="$(extract_first_runtime_value_from_commands_json_01 "$m5_commands_json" extract_vm_command_source_value_from_command_01)"
  candidate="$(trim "$candidate")"
  if [[ -n "$candidate" ]]; then
    runtime_vm_command_source="$candidate"
    runtime_vm_command_source_source="summary_command:m5"
    runtime_vm_command_source_configured="1"
  fi
fi

declare -a unresolved_keys=()
declare -a unresolved_reasons=()

if [[ "$require_summary" == "1" && "$roadmap_summary_valid" != "1" ]]; then
  append_unresolved_key_01 "roadmap_summary_json"
  unresolved_reasons+=("roadmap summary required but unavailable ($roadmap_summary_error): $roadmap_summary_json")
fi

if [[ "$m2_required" == "1" ]]; then
  if [[ "$runtime_host_a_configured" != "1" ]]; then
    append_unresolved_key_01 "host_a"
    unresolved_reasons+=("M2 requires host-a; unresolved or placeholder")
  fi
  if [[ "$runtime_host_b_configured" != "1" ]]; then
    append_unresolved_key_01 "host_b"
    unresolved_reasons+=("M2 requires host-b; unresolved or placeholder")
  fi
  if [[ "$runtime_campaign_subject_configured" != "1" ]]; then
    append_unresolved_key_01 "campaign_subject"
    unresolved_reasons+=("M2 requires campaign-subject; unresolved or placeholder")
  fi
fi
if [[ "$m5_required" == "1" ]]; then
  if [[ "$runtime_vm_command_source_configured" != "1" ]]; then
    append_unresolved_key_01 "vm_command_source"
    unresolved_reasons+=("M5 requires vm-command-source; unresolved or placeholder")
  fi
fi

unresolved_count="${#unresolved_keys[@]}"

status="pass"
rc=0
if (( unresolved_count > 0 )); then
  status="fail"
  rc=1
fi

declare -a export_lines=()
declare -a export_lines_redacted=()
declare -a export_vars=()

if [[ "$status" == "pass" ]]; then
  if [[ "$runtime_host_a_configured" == "1" ]]; then
    add_export_line_01 "ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_HOST_A" "$runtime_host_a" 0
    add_export_line_01 "ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_A" "$runtime_host_a" 0
    add_export_line_01 "A_HOST" "$runtime_host_a" 0
  fi
  if [[ "$runtime_host_b_configured" == "1" ]]; then
    add_export_line_01 "ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_HOST_B" "$runtime_host_b" 0
    add_export_line_01 "ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_B" "$runtime_host_b" 0
    add_export_line_01 "B_HOST" "$runtime_host_b" 0
  fi
  if [[ "$runtime_campaign_subject_configured" == "1" ]]; then
    add_export_line_01 "ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_CAMPAIGN_SUBJECT" "$runtime_campaign_subject" 1
    add_export_line_01 "ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_CAMPAIGN_SUBJECT" "$runtime_campaign_subject" 1
    add_export_line_01 "CAMPAIGN_SUBJECT" "$runtime_campaign_subject" 1
  fi
  if [[ "$runtime_vm_command_source_configured" == "1" ]]; then
    add_export_line_01 "ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_VM_COMMAND_SOURCE" "$runtime_vm_command_source" 0
    add_export_line_01 "VM_COMMAND_SOURCE" "$runtime_vm_command_source" 0
  fi
fi

unresolved_keys_json="$(json_from_array_lines_01 "${unresolved_keys[@]}")"
unresolved_reasons_json="$(json_from_array_lines_01 "${unresolved_reasons[@]}")"
export_lines_redacted_json="$(json_from_array_lines_01 "${export_lines_redacted[@]}")"
export_vars_json="$(json_from_array_lines_01 "${export_vars[@]}")"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at "$generated_at" \
  --arg status "$status" \
  --argjson rc "$rc" \
  --arg reports_dir "$reports_dir" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg summary_json "$summary_json" \
  --argjson require_summary "$require_summary" \
  --argjson print_shell "$print_shell" \
  --argjson print_summary_json "$print_summary_json" \
  --arg roadmap_summary_error "$roadmap_summary_error" \
  --argjson roadmap_summary_available "$roadmap_summary_available" \
  --argjson roadmap_summary_valid "$roadmap_summary_valid" \
  --arg m2_status "$m2_status" \
  --arg m4_status "$m4_status" \
  --arg m5_status "$m5_status" \
  --arg m5_promotion_status "$m5_promotion_status" \
  --argjson m2_required "$m2_required" \
  --argjson m4_required "$m4_required" \
  --argjson m5_required "$m5_required" \
  --arg runtime_host_a "$runtime_host_a" \
  --arg runtime_host_a_source "$runtime_host_a_source" \
  --argjson runtime_host_a_configured "$runtime_host_a_configured" \
  --arg runtime_host_b "$runtime_host_b" \
  --arg runtime_host_b_source "$runtime_host_b_source" \
  --argjson runtime_host_b_configured "$runtime_host_b_configured" \
  --arg runtime_campaign_subject_source "$runtime_campaign_subject_source" \
  --argjson runtime_campaign_subject_configured "$runtime_campaign_subject_configured" \
  --arg runtime_vm_command_source "$runtime_vm_command_source" \
  --arg runtime_vm_command_source_source "$runtime_vm_command_source_source" \
  --argjson runtime_vm_command_source_configured "$runtime_vm_command_source_configured" \
  --argjson unresolved_count "$unresolved_count" \
  --argjson unresolved_keys "$unresolved_keys_json" \
  --argjson unresolved_reasons "$unresolved_reasons_json" \
  --argjson export_lines_redacted "$export_lines_redacted_json" \
  --argjson export_vars "$export_vars_json" \
  '{
    version: 1,
    schema: {
      id: "roadmap_live_promotion_prepare_env_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at,
    status: $status,
    rc: $rc,
    inputs: {
      reports_dir: $reports_dir,
      roadmap_summary_json: $roadmap_summary_json,
      summary_json: $summary_json,
      require_summary: ($require_summary == 1),
      print_shell: ($print_shell == 1),
      print_summary_json: ($print_summary_json == 1)
    },
    roadmap_summary: {
      available: ($roadmap_summary_available == 1),
      valid_json: ($roadmap_summary_valid == 1),
      error: (if $roadmap_summary_error == "" then null else $roadmap_summary_error end)
    },
    requirements: {
      m2: {
        required: ($m2_required == 1),
        status: (if $m2_status == "" then null else $m2_status end),
        required_runtime_inputs: ["host_a", "host_b", "campaign_subject"]
      },
      m4: {
        required: ($m4_required == 1),
        status: (if $m4_status == "" then null else $m4_status end),
        required_runtime_inputs: []
      },
      m5: {
        required: ($m5_required == 1),
        status: (if $m5_status == "" then null else $m5_status end),
        promotion_status: (if $m5_promotion_status == "" then null else $m5_promotion_status end),
        required_runtime_inputs: ["vm_command_source"]
      }
    },
    runtime: {
      host_a: {
        configured: ($runtime_host_a_configured == 1),
        source: (if $runtime_host_a_source == "" then null else $runtime_host_a_source end),
        value: (if $runtime_host_a_configured == 1 then $runtime_host_a else null end)
      },
      host_b: {
        configured: ($runtime_host_b_configured == 1),
        source: (if $runtime_host_b_source == "" then null else $runtime_host_b_source end),
        value: (if $runtime_host_b_configured == 1 then $runtime_host_b else null end)
      },
      campaign_subject: {
        configured: ($runtime_campaign_subject_configured == 1),
        source: (if $runtime_campaign_subject_source == "" then null else $runtime_campaign_subject_source end),
        value: (if $runtime_campaign_subject_configured == 1 then "[redacted]" else null end)
      },
      vm_command_source: {
        configured: ($runtime_vm_command_source_configured == 1),
        source: (if $runtime_vm_command_source_source == "" then null else $runtime_vm_command_source_source end),
        value: (if $runtime_vm_command_source_configured == 1 then $runtime_vm_command_source else null end)
      }
    },
    unresolved: {
      count: $unresolved_count,
      keys: $unresolved_keys,
      reasons: $unresolved_reasons
    },
    exports: {
      count: ($export_vars | length),
      variables: $export_vars,
      shell_lines_redacted: $export_lines_redacted
    },
    artifacts: {
      summary_json: $summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

if [[ "$status" == "pass" && "$print_shell" == "1" ]]; then
  printf '%s\n' "${export_lines[@]}"
fi

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

echo "[roadmap-live-promotion-prepare-env] status=$status rc=$rc unresolved_count=$unresolved_count summary_json=$summary_json" >&2
if (( unresolved_count > 0 )); then
  echo "[roadmap-live-promotion-prepare-env] unresolved_keys=$(printf '%s\n' "${unresolved_keys[@]}" | paste -sd ',' -)" >&2
fi

exit "$rc"
