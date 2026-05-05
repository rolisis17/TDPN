#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_live_and_pack_actionable_run.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--roadmap-summary-json PATH] \
    [--roadmap-report-md PATH] \
    [--host-a HOST] \
    [--host-b HOST] \
    [--campaign-subject ID] \
    [--vm-command-source PATH] \
    [--run-live-archive [0|1]] \
    [--archive-root DIR] \
    [--action-timeout-sec N] \
    [--allow-unsafe-shell-commands [0|1]] \
    [--refresh-manual-validation [0|1]] \
    [--refresh-single-machine-readiness [0|1]] \
    [--scope auto|all|profile-default|runtime-actuation|multi-vm] \
    [--parallel [0|1]] \
    [--max-actions N] \
    [--continue-on-live-fail [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Execute the roadmap evidence pipeline in one command:
    1) roadmap_live_evidence_actionable_run.sh
    2) optional roadmap_live_evidence_archive_run.sh
    3) roadmap_evidence_pack_actionable_run.sh

Defaults:
  --action-timeout-sec 0   (0 = no per-action timeout)
  --allow-unsafe-shell-commands 0
  --host-a ""   (precedence: CLI --host-a > ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_HOST_A > A_HOST > HOST_A > delegated summary command values)
  --host-b ""   (precedence: CLI --host-b > ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_HOST_B > B_HOST > HOST_B > delegated summary command values)
  --campaign-subject ""   (precedence: CLI --campaign-subject > ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_CAMPAIGN_SUBJECT > CAMPAIGN_SUBJECT > INVITE_KEY > delegated summary command values)
  --vm-command-source ""   (precedence: CLI --vm-command-source > ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_VM_COMMAND_SOURCE > VM_COMMAND_SOURCE > delegated summary command values)
  --refresh-manual-validation 0
  --refresh-single-machine-readiness 0
  --run-live-archive 0
  --archive-root <reports-dir>/live_evidence_archive
  --scope auto
  --parallel 0
  --max-actions 0   (0 = no limit)
  --continue-on-live-fail 0
  --print-summary-json 1

Exit behavior:
  - Runs live-evidence stage first, optional archive stage second, and
    evidence-pack stage last.
  - With --continue-on-live-fail=0 (default), evidence-pack is skipped when live fails.
  - With --continue-on-live-fail=1, evidence-pack still runs even when live fails.
  - When --run-live-archive=1, evidence-pack runs only if archive stage passes.
  - Final rc is first failing stage rc (live first, archive second, pack third), else 0.
USAGE
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
  elif [[ "$(path_is_cross_platform_absolute_01 "$path")" == "1" ]]; then
    printf '%s' "$(normalize_cross_platform_path_separators "$path")"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
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

scope_arg_or_die() {
  local value="$1"
  case "$value" in
    auto|all|profile-default|runtime-actuation|multi-vm) ;;
    *)
      echo "--scope must be one of: auto, all, profile-default, runtime-actuation, multi-vm"
      exit 2
      ;;
  esac
}

require_value_or_die() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
    echo "$flag requires a value"
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

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

render_log_token() {
  local token="${1:-}"
  if [[ "$token" == *[[:space:]]* ]]; then
    token="${token//\'/\'\"\'\"\'}"
    printf "'%s'" "$token"
  else
    printf '%s' "$token"
  fi
}

redact_command_secrets() {
  local line="${1:-}"
  local flag_regex='--campaign-subject|--subject|--key|--invite-key|--campaign-anon-cred|--anon-cred|--token|--auth-token|--admin-token|--authorization|--bearer'
  line="$(printf '%s' "$line" | sed -E \
    -e "s/(${flag_regex})([[:space:]]+)\"[^\"]*\"/\\1\\2[redacted]/g" \
    -e "s/(${flag_regex})([[:space:]]+)'[^']*'/\\1\\2[redacted]/g" \
    -e "s/(${flag_regex})([[:space:]]+)[^[:space:]]+/\\1\\2[redacted]/g" \
    -e "s/(${flag_regex})=[^[:space:]]+/\\1=[redacted]/g")"
  printf '%s' "$line"
}

command_hygiene_default_json() {
  jq -nc '
    {
      checked: false,
      selected_commands: [],
      selected_commands_count: 0,
      unresolved_placeholders: [],
      unresolved_placeholder_count: 0,
      unsafe_tokens: [],
      unsafe_token_count: 0,
      unsafe_tokens_blocked: false,
      contract_valid: true,
      contract_failure_reason: null
    }'
}

evaluate_selected_action_command_hygiene_json() {
  local summary_path="${1:-}"
  local allow_unsafe="${2:-0}"
  if [[ ! -f "$summary_path" ]] || ! jq -e . "$summary_path" >/dev/null 2>&1; then
    command_hygiene_default_json
    return 0
  fi

  jq -c --argjson allow_unsafe "$allow_unsafe" '
    def trim: gsub("^\\s+|\\s+$"; "");
    def has_unresolved_placeholder:
      (ascii_upcase) as $u
      | ($u | test("(^|[^A-Z0-9_])(INVITE_KEY|CAMPAIGN_SUBJECT|REPLACE_WITH_INVITE_SUBJECT|REPLACE_WITH_CAMPAIGN_SUBJECT)($|[^A-Z0-9_])"))
        or ($u | test("\\$\\{?(INVITE_KEY|CAMPAIGN_SUBJECT)\\}?"))
        or ($u | contains("<SET-REAL-INVITE-KEY>"))
        or ($u | contains("<SET-INVITE-SUBJECT>"));
    def has_unsafe_shell_token:
      test("[\\n\\r]")
      or test("[;|&<>`$(){}]")
      or test("^[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]+");

    (.roadmap.selected_action_ids // [] | map(tostring | trim) | map(select(length > 0)) | unique) as $selected_ids
    | ([
        (.actions // [])[]
        | {
            id: ((.id // "") | tostring | trim),
            command: ((.command // "") | tostring | trim)
          }
        | select((.id | length) > 0 and (.command | length) > 0)
        | .id as $action_id
        | select(($selected_ids | index($action_id)) != null)
      ] | sort_by([.id, .command])) as $selected_commands
    | ($selected_commands | map(select(.command | has_unresolved_placeholder))) as $unresolved_placeholders
    | ($selected_commands | map(select(.command | has_unsafe_shell_token))) as $unsafe_tokens
    | {
        checked: true,
        selected_commands: $selected_commands,
        selected_commands_count: ($selected_commands | length),
        unresolved_placeholders: $unresolved_placeholders,
        unresolved_placeholder_count: ($unresolved_placeholders | length),
        unsafe_tokens: $unsafe_tokens,
        unsafe_token_count: ($unsafe_tokens | length),
        unsafe_tokens_blocked: (($unsafe_tokens | length) > 0 and ($allow_unsafe != 1)),
        contract_valid: ((($unresolved_placeholders | length) == 0) and ((($unsafe_tokens | length) == 0) or ($allow_unsafe == 1))),
        contract_failure_reason: (
          [
            (if ($unresolved_placeholders | length) > 0 then
              "selected actionable commands include unresolved placeholder tokens"
             else empty end),
            (if (($unsafe_tokens | length) > 0 and ($allow_unsafe != 1)) then
              "selected actionable commands require unsafe shell parsing while --allow-unsafe-shell-commands=0"
             else empty end)
          ]
          | if length == 0 then null else join("; ") end
        )
      }' "$summary_path"
}

need_cmd jq
need_cmd bash
need_cmd date
need_cmd mktemp

reports_dir="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_REPORTS_DIR:-}"
summary_json="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_SUMMARY_JSON:-}"
roadmap_summary_json="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ROADMAP_SUMMARY_JSON:-}"
roadmap_report_md="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ROADMAP_REPORT_MD:-}"
host_a_override_env="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_HOST_A:-${A_HOST:-${HOST_A:-}}}"
host_b_override_env="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_HOST_B:-${B_HOST:-${HOST_B:-}}}"
campaign_subject_override_env="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_CAMPAIGN_SUBJECT:-${CAMPAIGN_SUBJECT:-${INVITE_KEY:-}}}"
vm_command_source_override_env="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_VM_COMMAND_SOURCE:-${VM_COMMAND_SOURCE:-}}"
refresh_manual_validation="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_REFRESH_MANUAL_VALIDATION:-0}"
refresh_single_machine_readiness="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_REFRESH_SINGLE_MACHINE_READINESS:-0}"
parallel="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PARALLEL:-0}"
max_actions="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_MAX_ACTIONS:-0}"
print_summary_json="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PRINT_SUMMARY_JSON:-1}"
action_timeout_sec="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ACTION_TIMEOUT_SEC:-0}"
allow_unsafe_shell_commands="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ALLOW_UNSAFE_SHELL_COMMANDS:-0}"
continue_on_live_fail="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_CONTINUE_ON_LIVE_FAIL:-0}"
run_live_archive="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_RUN_LIVE_ARCHIVE:-0}"
archive_root="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ARCHIVE_ROOT:-}"
scope="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_SCOPE:-${ROADMAP_LIVE_AND_PACK_ACTIONABLE_SCOPE:-auto}}"
original_args=("$@")
host_a_override_arg=""
host_b_override_arg=""
campaign_subject_override_arg=""
vm_command_source_override_arg=""
host_a_override_arg_provided="0"
host_b_override_arg_provided="0"
campaign_subject_override_arg_provided="0"
vm_command_source_override_arg_provided="0"

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
    --roadmap-summary-json)
      require_value_or_die "$1" "${2:-}"
      roadmap_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-report-md)
      require_value_or_die "$1" "${2:-}"
      roadmap_report_md="${2:-}"
      shift 2
      ;;
    --host-a)
      require_value_or_die "$1" "${2:-}"
      host_a_override_arg="${2:-}"
      host_a_override_arg_provided="1"
      shift 2
      ;;
    --host-b)
      require_value_or_die "$1" "${2:-}"
      host_b_override_arg="${2:-}"
      host_b_override_arg_provided="1"
      shift 2
      ;;
    --campaign-subject)
      require_value_or_die "$1" "${2:-}"
      campaign_subject_override_arg="${2:-}"
      campaign_subject_override_arg_provided="1"
      shift 2
      ;;
    --vm-command-source)
      require_value_or_die "$1" "${2:-}"
      vm_command_source_override_arg="${2:-}"
      vm_command_source_override_arg_provided="1"
      shift 2
      ;;
    --run-live-archive)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_live_archive="${2:-}"
        shift 2
      else
        run_live_archive="1"
        shift
      fi
      ;;
    --archive-root)
      require_value_or_die "$1" "${2:-}"
      archive_root="${2:-}"
      shift 2
      ;;
    --action-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      action_timeout_sec="${2:-}"
      shift 2
      ;;
    --allow-unsafe-shell-commands)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_unsafe_shell_commands="${2:-}"
        shift 2
      else
        allow_unsafe_shell_commands="1"
        shift
      fi
      ;;
    --refresh-manual-validation)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_manual_validation="${2:-}"
        shift 2
      else
        refresh_manual_validation="1"
        shift
      fi
      ;;
    --refresh-single-machine-readiness)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_single_machine_readiness="${2:-}"
        shift 2
      else
        refresh_single_machine_readiness="1"
        shift
      fi
      ;;
    --scope)
      require_value_or_die "$1" "${2:-}"
      scope="${2:-}"
      shift 2
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
    --max-actions)
      require_value_or_die "$1" "${2:-}"
      max_actions="${2:-}"
      shift 2
      ;;
    --continue-on-live-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        continue_on_live_fail="${2:-}"
        shift 2
      else
        continue_on_live_fail="1"
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

bool_arg_or_die "--refresh-manual-validation" "$refresh_manual_validation"
bool_arg_or_die "--refresh-single-machine-readiness" "$refresh_single_machine_readiness"
bool_arg_or_die "--parallel" "$parallel"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--allow-unsafe-shell-commands" "$allow_unsafe_shell_commands"
bool_arg_or_die "--continue-on-live-fail" "$continue_on_live_fail"
bool_arg_or_die "--run-live-archive" "$run_live_archive"
int_arg_or_die "--max-actions" "$max_actions"
int_arg_or_die "--action-timeout-sec" "$action_timeout_sec"
scope_arg_or_die "$scope"

runtime_host_a=""
runtime_host_a_source="summary_command"
runtime_host_a_configured="0"
runtime_host_b=""
runtime_host_b_source="summary_command"
runtime_host_b_configured="0"
runtime_campaign_subject=""
runtime_campaign_subject_source="summary_command"
runtime_campaign_subject_configured="0"
runtime_vm_command_source=""
runtime_vm_command_source_source="summary_command"
runtime_vm_command_source_configured="0"

runtime_value_candidate="$(trim "$host_a_override_arg")"
if [[ "$host_a_override_arg_provided" == "1" ]]; then
  if [[ -n "$runtime_value_candidate" ]] && ! host_a_value_looks_placeholder_01 "$runtime_value_candidate"; then
    runtime_host_a="$runtime_value_candidate"
    runtime_host_a_source="cli:--host-a"
    runtime_host_a_configured="1"
  else
    runtime_host_a_source="cli:--host-a=placeholder_or_empty"
  fi
elif [[ -n "$(trim "$host_a_override_env")" ]] && ! host_a_value_looks_placeholder_01 "$host_a_override_env"; then
  runtime_host_a="$(trim "$host_a_override_env")"
  runtime_host_a_source="env:host_a"
  runtime_host_a_configured="1"
fi

runtime_value_candidate="$(trim "$host_b_override_arg")"
if [[ "$host_b_override_arg_provided" == "1" ]]; then
  if [[ -n "$runtime_value_candidate" ]] && ! host_b_value_looks_placeholder_01 "$runtime_value_candidate"; then
    runtime_host_b="$runtime_value_candidate"
    runtime_host_b_source="cli:--host-b"
    runtime_host_b_configured="1"
  else
    runtime_host_b_source="cli:--host-b=placeholder_or_empty"
  fi
elif [[ -n "$(trim "$host_b_override_env")" ]] && ! host_b_value_looks_placeholder_01 "$host_b_override_env"; then
  runtime_host_b="$(trim "$host_b_override_env")"
  runtime_host_b_source="env:host_b"
  runtime_host_b_configured="1"
fi

runtime_value_candidate="$(trim "$campaign_subject_override_arg")"
if [[ "$campaign_subject_override_arg_provided" == "1" ]]; then
  if [[ -n "$runtime_value_candidate" ]] && ! subject_value_looks_placeholder_01 "$runtime_value_candidate"; then
    runtime_campaign_subject="$runtime_value_candidate"
    runtime_campaign_subject_source="cli:--campaign-subject"
    runtime_campaign_subject_configured="1"
  else
    runtime_campaign_subject_source="cli:--campaign-subject=placeholder_or_empty"
  fi
elif [[ -n "$(trim "$campaign_subject_override_env")" ]] && ! subject_value_looks_placeholder_01 "$campaign_subject_override_env"; then
  runtime_campaign_subject="$(trim "$campaign_subject_override_env")"
  runtime_campaign_subject_source="env:campaign_subject"
  runtime_campaign_subject_configured="1"
fi

runtime_value_candidate="$(trim "$vm_command_source_override_arg")"
if [[ "$vm_command_source_override_arg_provided" == "1" ]]; then
  if [[ -n "$runtime_value_candidate" ]] && ! vm_command_source_value_looks_placeholder_01 "$runtime_value_candidate"; then
    runtime_vm_command_source="$runtime_value_candidate"
    runtime_vm_command_source_source="cli:--vm-command-source"
    runtime_vm_command_source_configured="1"
  else
    runtime_vm_command_source_source="cli:--vm-command-source=placeholder_or_empty"
  fi
elif [[ -n "$(trim "$vm_command_source_override_env")" ]] && ! vm_command_source_value_looks_placeholder_01 "$vm_command_source_override_env"; then
  runtime_vm_command_source="$(trim "$vm_command_source_override_env")"
  runtime_vm_command_source_source="env:vm_command_source"
  runtime_vm_command_source_configured="1"
fi

if [[ -n "$roadmap_summary_json" && -z "$roadmap_report_md" ]] || [[ -z "$roadmap_summary_json" && -n "$roadmap_report_md" ]]; then
  echo "--roadmap-summary-json and --roadmap-report-md must be provided together"
  exit 2
fi

roadmap_paths_provided="0"
if [[ -n "$roadmap_summary_json" && -n "$roadmap_report_md" ]]; then
  roadmap_paths_provided="1"
  roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
  roadmap_report_md="$(abs_path "$roadmap_report_md")"
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/roadmap_live_and_pack_actionable_run_${run_stamp}"
fi
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/roadmap_live_and_pack_actionable_run_summary.json"
fi
summary_json="$(abs_path "$summary_json")"
mkdir -p "$(dirname "$summary_json")"

if [[ -z "$archive_root" ]]; then
  archive_root="$reports_dir/live_evidence_archive"
fi
archive_root="$(abs_path "$archive_root")"
mkdir -p "$archive_root"

live_script="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT:-$ROOT_DIR/scripts/roadmap_live_evidence_actionable_run.sh}"
archive_script="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ARCHIVE_SCRIPT:-$ROOT_DIR/scripts/roadmap_live_evidence_archive_run.sh}"
pack_script="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT:-$ROOT_DIR/scripts/roadmap_evidence_pack_actionable_run.sh}"

if [[ ! -f "$live_script" ]]; then
  echo "missing live-evidence script: $live_script"
  exit 2
fi
if [[ ! -r "$live_script" ]]; then
  echo "live-evidence script is not readable: $live_script"
  exit 2
fi
if [[ "$run_live_archive" == "1" ]]; then
  if [[ ! -f "$archive_script" ]]; then
    echo "missing live-evidence archive script: $archive_script"
    exit 2
  fi
  if [[ ! -r "$archive_script" ]]; then
    echo "live-evidence archive script is not readable: $archive_script"
    exit 2
  fi
fi
if [[ ! -f "$pack_script" ]]; then
  echo "missing evidence-pack script: $pack_script"
  exit 2
fi
if [[ ! -r "$pack_script" ]]; then
  echo "evidence-pack script is not readable: $pack_script"
  exit 2
fi

live_reports_dir="$reports_dir/live_evidence"
live_summary_json="$reports_dir/roadmap_live_evidence_actionable_run_summary.json"
live_log="$reports_dir/roadmap_live_evidence_actionable_run.log"
archive_summary_json="$reports_dir/roadmap_live_evidence_archive_run_summary.json"
archive_log="$reports_dir/roadmap_live_evidence_archive_run.log"
pack_reports_dir="$reports_dir/evidence_pack"
pack_summary_json="$reports_dir/roadmap_evidence_pack_actionable_run_summary.json"
pack_log="$reports_dir/roadmap_evidence_pack_actionable_run.log"

mkdir -p "$live_reports_dir" "$pack_reports_dir"

tmp_dir="$(mktemp -d "$reports_dir/.roadmap_live_and_pack_actionable_run_tmp.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
summary_tmp="$tmp_dir/summary.json"

live_status="fail"
live_rc=125
live_process_rc=125
live_summary_valid=0
live_contract_valid=0
live_contract_failure_reason=""
live_selected_actions_count_num=0
live_actions_executed_num=0
live_pass_num=0
live_fail_num=0
live_timed_out_num=0
live_soft_failed_num=0
live_selected_actions_count_json="null"
live_actions_executed_json="null"
live_pass_json="null"
live_fail_json="null"
live_timed_out_json="null"
live_soft_failed_json="null"
live_selected_action_ids_json="[]"
live_stage_pass=0
live_command_hygiene_json="$(command_hygiene_default_json)"

pack_status="skipped"
pack_skip_reason=""
pack_rc_num=0
pack_process_rc_num=0
pack_rc_json="null"
pack_process_rc_json="null"
pack_summary_valid=0
pack_contract_valid=0
pack_contract_failure_reason=""
pack_selected_actions_count_num=0
pack_actions_executed_num=0
pack_pass_num=0
pack_fail_num=0
pack_timed_out_num=0
pack_soft_failed_num=0
pack_selected_actions_count_json="null"
pack_actions_executed_json="null"
pack_pass_json="null"
pack_fail_json="null"
pack_timed_out_json="null"
pack_soft_failed_json="null"
pack_selected_action_ids_json="[]"
pack_stage_pass=0
pack_command_hygiene_json="$(command_hygiene_default_json)"

archive_attempted=0
archive_status="skipped"
archive_skip_reason="archive_not_requested"
archive_rc_num=0
archive_process_rc_num=0
archive_rc_json="null"
archive_process_rc_json="null"
archive_summary_valid=0
archive_contract_valid=0
archive_contract_failure_reason=""
archive_summary_status_json="null"
archive_summary_rc_json="null"
archive_candidate_total_num=0
archive_copied_total_num=0
archive_missing_total_num=0
archive_copy_error_total_num=0
archive_missing_family_count_num=0
archive_candidate_total_json="null"
archive_copied_total_json="null"
archive_missing_total_json="null"
archive_copy_error_total_json="null"
archive_missing_family_count_json="null"
archive_archive_dir=""
archive_fail_closed_blocking=0

shared_roadmap_summary_json="$roadmap_summary_json"
shared_roadmap_report_md="$roadmap_report_md"

live_cmd=(
  bash
  "$live_script"
  --reports-dir "$live_reports_dir"
  --summary-json "$live_summary_json"
  --action-timeout-sec "$action_timeout_sec"
  --allow-unsafe-shell-commands "$allow_unsafe_shell_commands"
  --refresh-manual-validation "$refresh_manual_validation"
  --refresh-single-machine-readiness "$refresh_single_machine_readiness"
  --scope "$scope"
  --parallel "$parallel"
  --max-actions "$max_actions"
  --print-summary-json 0
)
if [[ "$runtime_host_a_configured" == "1" ]]; then
  live_cmd+=(--host-a "$runtime_host_a")
fi
if [[ "$runtime_host_b_configured" == "1" ]]; then
  live_cmd+=(--host-b "$runtime_host_b")
fi
if [[ "$runtime_campaign_subject_configured" == "1" ]]; then
  live_cmd+=(--campaign-subject "$runtime_campaign_subject")
fi
if [[ "$runtime_vm_command_source_configured" == "1" ]]; then
  live_cmd+=(--vm-command-source "$runtime_vm_command_source")
fi
if [[ "$roadmap_paths_provided" == "1" ]]; then
  live_cmd+=(--roadmap-summary-json "$roadmap_summary_json" --roadmap-report-md "$roadmap_report_md")
fi

echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence status=running"
rm -f "$live_summary_json"
set +e
"${live_cmd[@]}" >"$live_log" 2>&1
live_process_rc=$?
set -e

if [[ -f "$live_summary_json" ]] && jq -e . "$live_summary_json" >/dev/null 2>&1; then
  live_summary_valid=1
  live_status="$(jq -r '.status // ""' "$live_summary_json")"
  live_rc_raw="$(jq -r '.rc // empty' "$live_summary_json")"
  if [[ -z "$live_status" || -z "$live_rc_raw" ]]; then
    live_contract_valid=0
    live_contract_failure_reason="live summary contract requires both status and rc fields"
    live_rc=1
    live_status="fail"
  elif ! [[ "$live_rc_raw" =~ ^-?[0-9]+$ ]]; then
    live_contract_valid=0
    live_contract_failure_reason="live summary rc must be an integer"
    live_rc=125
    live_status="fail"
  else
    live_rc="$live_rc_raw"
    live_status_norm="$(printf '%s' "${live_status:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    if [[ "$live_status_norm" != "pass" && "$live_status_norm" != "fail" ]]; then
      live_contract_valid=0
      live_contract_failure_reason="live summary status must be pass or fail"
      live_status="fail"
      if (( live_rc == 0 )); then
        live_rc=1
      fi
    elif (( live_rc == 0 )) && [[ "$live_status_norm" != "pass" ]]; then
      live_contract_valid=0
      live_contract_failure_reason="live summary contract mismatch: rc=0 requires status=pass"
      live_status="fail"
      live_rc=1
    elif (( live_rc != 0 )) && [[ "$live_status_norm" != "fail" ]]; then
      live_contract_valid=0
      live_contract_failure_reason="live summary contract mismatch: non-zero rc requires status=fail"
      live_status="fail"
    else
      live_contract_valid=1
      live_contract_failure_reason=""
    fi
  fi
  if (( live_process_rc != 0 && live_rc == 0 )); then
    live_contract_valid=0
    live_contract_failure_reason="live process rc and summary rc mismatch (process non-zero, summary rc=0)"
    live_rc="$live_process_rc"
    live_status="fail"
  fi
  live_status_norm="$(printf '%s' "${live_status:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  if [[ "$live_status_norm" == "pass" ]] && (( live_rc == 0 )) && (( live_contract_valid == 1 )); then
    live_stage_pass=1
  else
    live_stage_pass=0
    if (( live_rc == 0 )); then
      # Fail closed when stage status is not explicit pass.
      live_rc=1
    fi
  fi

  live_selected_action_ids_json="$(jq -c '.roadmap.selected_action_ids // []' "$live_summary_json")"

  value="$(jq -r '(.roadmap.actions_selected_count // ((.roadmap.selected_action_ids // []) | length) // empty)' "$live_summary_json")"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    live_selected_actions_count_num="$value"
    live_selected_actions_count_json="$value"
  fi

  value="$(jq -r '.summary.actions_executed // empty' "$live_summary_json")"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    live_actions_executed_num="$value"
    live_actions_executed_json="$value"
  fi

  value="$(jq -r '.summary.pass // empty' "$live_summary_json")"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    live_pass_num="$value"
    live_pass_json="$value"
  fi

  value="$(jq -r '.summary.fail // empty' "$live_summary_json")"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    live_fail_num="$value"
    live_fail_json="$value"
  fi

  value="$(jq -r '.summary.timed_out // empty' "$live_summary_json")"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    live_timed_out_num="$value"
    live_timed_out_json="$value"
  fi

  value="$(jq -r '.summary.soft_failed // empty' "$live_summary_json")"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    live_soft_failed_num="$value"
    live_soft_failed_json="$value"
  fi

  if [[ "$roadmap_paths_provided" != "1" ]]; then
    candidate_roadmap_summary_json="$(jq -r '.artifacts.roadmap_summary_json // ""' "$live_summary_json")"
    candidate_roadmap_report_md="$(jq -r '.artifacts.roadmap_report_md // ""' "$live_summary_json")"
    if [[ -n "$candidate_roadmap_summary_json" && -n "$candidate_roadmap_report_md" ]]; then
      shared_roadmap_summary_json="$candidate_roadmap_summary_json"
      shared_roadmap_report_md="$candidate_roadmap_report_md"
    fi
  fi

  live_command_hygiene_json="$(evaluate_selected_action_command_hygiene_json "$live_summary_json" "$allow_unsafe_shell_commands")"
  live_command_hygiene_contract_valid="$(printf '%s\n' "$live_command_hygiene_json" | jq -r '.contract_valid // false')"
  if [[ "$live_command_hygiene_contract_valid" != "true" ]]; then
    live_command_hygiene_contract_failure_reason="$(printf '%s\n' "$live_command_hygiene_json" | jq -r '.contract_failure_reason // ""')"
    if [[ -n "$live_command_hygiene_contract_failure_reason" ]]; then
      if [[ -n "$live_contract_failure_reason" ]]; then
        live_contract_failure_reason="${live_contract_failure_reason}; ${live_command_hygiene_contract_failure_reason}"
      else
        live_contract_failure_reason="$live_command_hygiene_contract_failure_reason"
      fi
    fi
    live_contract_valid=0
    live_status="fail"
    live_stage_pass=0
    if (( live_rc == 0 )); then
      live_rc=1
    fi
  fi
else
  live_summary_valid=0
  live_contract_valid=0
  live_contract_failure_reason="live summary missing or invalid after stage execution"
  live_rc="$live_process_rc"
  if (( live_rc == 0 )); then
    # Fail closed when the stage exits 0 but emits no valid summary artifact.
    live_rc=125
  fi
  live_status="fail"
  live_stage_pass=0
fi

echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence status=$live_status rc=$live_rc contract_valid=$live_contract_valid"
echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence command_hygiene=$(printf '%s\n' "$live_command_hygiene_json" | jq -c '{checked, selected_commands_count, unresolved_placeholder_count, unsafe_token_count, unsafe_tokens_blocked, contract_valid, contract_failure_reason}')"
if [[ "$live_status" != "pass" && -n "$live_contract_failure_reason" ]]; then
  echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence fail_reason=$live_contract_failure_reason"
fi
echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence summary_json=$live_summary_json log=$live_log"

run_pack_stage=1
allow_post_live=1
if (( live_stage_pass != 1 )) && [[ "$continue_on_live_fail" != "1" ]]; then
  allow_post_live=0
fi

if [[ "$run_live_archive" == "1" ]]; then
  if (( allow_post_live == 1 )); then
    archive_attempted=1
    archive_cmd=(
      bash
      "$archive_script"
      --reports-dir "$reports_dir"
      --archive-root "$archive_root"
      --scope "$scope"
      --summary-json "$archive_summary_json"
      --print-summary-json 0
    )
    if [[ -n "${shared_roadmap_summary_json:-}" ]]; then
      archive_cmd+=(--roadmap-summary-json "$shared_roadmap_summary_json")
    fi

    echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence_archive status=running"
    rm -f "$archive_summary_json"
    set +e
    "${archive_cmd[@]}" >"$archive_log" 2>&1
    archive_process_rc_num=$?
    set -e

    if [[ -f "$archive_summary_json" ]] && jq -e . "$archive_summary_json" >/dev/null 2>&1; then
      archive_summary_valid=1
      archive_status="$(jq -r '.status // ""' "$archive_summary_json")"
      archive_rc_raw="$(jq -r '.rc // empty' "$archive_summary_json")"
      if [[ -z "$archive_status" || -z "$archive_rc_raw" ]]; then
        archive_contract_valid=0
        archive_contract_failure_reason="archive summary contract requires both status and rc fields"
        archive_status="fail"
        archive_rc_num=1
      elif ! [[ "$archive_rc_raw" =~ ^-?[0-9]+$ ]]; then
        archive_contract_valid=0
        archive_contract_failure_reason="archive summary rc must be an integer"
        archive_status="fail"
        archive_rc_num=125
      else
        archive_rc_num="$archive_rc_raw"
        archive_status_norm="$(printf '%s' "${archive_status:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
        if [[ "$archive_status_norm" != "pass" && "$archive_status_norm" != "fail" ]]; then
          archive_contract_valid=0
          archive_contract_failure_reason="archive summary status must be pass or fail"
          archive_status="fail"
          if (( archive_rc_num == 0 )); then
            archive_rc_num=1
          fi
        elif (( archive_rc_num == 0 )) && [[ "$archive_status_norm" != "pass" ]]; then
          archive_contract_valid=0
          archive_contract_failure_reason="archive summary contract mismatch: rc=0 requires status=pass"
          archive_status="fail"
          archive_rc_num=1
        elif (( archive_rc_num != 0 )) && [[ "$archive_status_norm" != "fail" ]]; then
          archive_contract_valid=0
          archive_contract_failure_reason="archive summary contract mismatch: non-zero rc requires status=fail"
          archive_status="fail"
        else
          archive_contract_valid=1
          archive_contract_failure_reason=""
        fi
      fi
      if (( archive_process_rc_num != 0 && archive_rc_num == 0 )); then
        archive_contract_valid=0
        archive_contract_failure_reason="archive process rc and summary rc mismatch (process non-zero, summary rc=0)"
        archive_rc_num="$archive_process_rc_num"
        archive_status="fail"
      fi

      archive_summary_status_json="$(jq -c '.status // null' "$archive_summary_json")"
      archive_summary_rc_json="$(jq -c '.rc // null' "$archive_summary_json")"

      value="$(jq -r '.summary.candidate_total // empty' "$archive_summary_json")"
      if [[ "$value" =~ ^[0-9]+$ ]]; then
        archive_candidate_total_num="$value"
        archive_candidate_total_json="$value"
      fi
      value="$(jq -r '.summary.copied_total // empty' "$archive_summary_json")"
      if [[ "$value" =~ ^[0-9]+$ ]]; then
        archive_copied_total_num="$value"
        archive_copied_total_json="$value"
      fi
      value="$(jq -r '.summary.missing_total // empty' "$archive_summary_json")"
      if [[ "$value" =~ ^[0-9]+$ ]]; then
        archive_missing_total_num="$value"
        archive_missing_total_json="$value"
      fi
      value="$(jq -r '.summary.copy_error_total // empty' "$archive_summary_json")"
      if [[ "$value" =~ ^[0-9]+$ ]]; then
        archive_copy_error_total_num="$value"
        archive_copy_error_total_json="$value"
      fi
      value="$(jq -r '.summary.missing_family_count // empty' "$archive_summary_json")"
      if [[ "$value" =~ ^[0-9]+$ ]]; then
        archive_missing_family_count_num="$value"
        archive_missing_family_count_json="$value"
      fi
      archive_archive_dir="$(jq -r '.artifacts.archive_dir // ""' "$archive_summary_json")"
    else
      archive_summary_valid=0
      archive_contract_valid=0
      archive_contract_failure_reason="archive summary missing or invalid after stage execution"
      archive_rc_num="$archive_process_rc_num"
      if (( archive_rc_num == 0 )); then
        # Fail closed when the stage exits 0 but emits no valid summary artifact.
        archive_rc_num=125
      fi
      archive_status="fail"
    fi

    if [[ "$archive_status" != "pass" ]] || (( archive_rc_num != 0 )); then
      archive_fail_closed_blocking=1
    fi
    archive_rc_json="$archive_rc_num"
    archive_process_rc_json="$archive_process_rc_num"
    echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence_archive status=$archive_status rc=$archive_rc_num contract_valid=$archive_contract_valid"
    if [[ "$archive_status" != "pass" && -n "$archive_contract_failure_reason" ]]; then
      echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence_archive fail_reason=$archive_contract_failure_reason"
    fi
    echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence_archive summary_json=$archive_summary_json log=$archive_log"
  else
    archive_status="skipped"
    archive_skip_reason="live_step_failed_fail_closed"
    echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence_archive status=skipped reason=$archive_skip_reason"
  fi
fi

if (( allow_post_live == 0 )); then
  run_pack_stage=0
  pack_status="skipped"
  pack_skip_reason="live_step_failed_fail_closed"
fi
if [[ "$run_live_archive" == "1" ]] && (( allow_post_live == 1 )) && (( archive_fail_closed_blocking == 1 )); then
  run_pack_stage=0
  pack_status="skipped"
  pack_skip_reason="archive_step_failed_fail_closed"
fi

if (( run_pack_stage == 1 )); then
  pack_cmd=(
    bash
    "$pack_script"
    --reports-dir "$pack_reports_dir"
    --summary-json "$pack_summary_json"
    --action-timeout-sec "$action_timeout_sec"
    --allow-unsafe-shell-commands "$allow_unsafe_shell_commands"
    --refresh-manual-validation "$refresh_manual_validation"
    --refresh-single-machine-readiness "$refresh_single_machine_readiness"
    --scope "$scope"
    --parallel "$parallel"
    --max-actions "$max_actions"
    --print-summary-json 0
    --live-evidence-summary-json "$live_summary_json"
    --require-live-derived-evidence-pack-actions 1
  )

  if [[ -n "${shared_roadmap_summary_json:-}" && -n "${shared_roadmap_report_md:-}" ]]; then
    pack_cmd+=(--roadmap-summary-json "$shared_roadmap_summary_json" --roadmap-report-md "$shared_roadmap_report_md")
  fi

  echo "[roadmap-live-and-pack-actionable-run] stage=evidence_pack status=running"
  rm -f "$pack_summary_json"
  set +e
  "${pack_cmd[@]}" >"$pack_log" 2>&1
  pack_process_rc_num=$?
  set -e

  if [[ -f "$pack_summary_json" ]] && jq -e . "$pack_summary_json" >/dev/null 2>&1; then
    pack_summary_valid=1
    pack_status="$(jq -r '.status // ""' "$pack_summary_json")"
    pack_rc_raw="$(jq -r '.rc // empty' "$pack_summary_json")"
    if [[ -z "$pack_status" || -z "$pack_rc_raw" ]]; then
      pack_contract_valid=0
      pack_contract_failure_reason="evidence-pack summary contract requires both status and rc fields"
      pack_status="fail"
      pack_rc_num=1
    elif ! [[ "$pack_rc_raw" =~ ^-?[0-9]+$ ]]; then
      pack_contract_valid=0
      pack_contract_failure_reason="evidence-pack summary rc must be an integer"
      pack_status="fail"
      pack_rc_num=125
    else
      pack_rc_num="$pack_rc_raw"
      pack_status_norm="$(printf '%s' "${pack_status:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
      if [[ "$pack_status_norm" != "pass" && "$pack_status_norm" != "fail" ]]; then
        pack_contract_valid=0
        pack_contract_failure_reason="evidence-pack summary status must be pass or fail"
        pack_status="fail"
        if (( pack_rc_num == 0 )); then
          pack_rc_num=1
        fi
      elif (( pack_rc_num == 0 )) && [[ "$pack_status_norm" != "pass" ]]; then
        pack_contract_valid=0
        pack_contract_failure_reason="evidence-pack summary contract mismatch: rc=0 requires status=pass"
        pack_status="fail"
        pack_rc_num=1
      elif (( pack_rc_num != 0 )) && [[ "$pack_status_norm" != "fail" ]]; then
        pack_contract_valid=0
        pack_contract_failure_reason="evidence-pack summary contract mismatch: non-zero rc requires status=fail"
        pack_status="fail"
      else
        pack_contract_valid=1
        pack_contract_failure_reason=""
      fi
    fi
    if (( pack_process_rc_num != 0 && pack_rc_num == 0 )); then
      pack_contract_valid=0
      pack_contract_failure_reason="evidence-pack process rc and summary rc mismatch (process non-zero, summary rc=0)"
      pack_rc_num="$pack_process_rc_num"
      pack_status="fail"
    fi
    pack_status_norm="$(printf '%s' "${pack_status:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    if [[ "$pack_status_norm" == "pass" ]] && (( pack_rc_num == 0 )) && (( pack_contract_valid == 1 )); then
      pack_stage_pass=1
    else
      pack_stage_pass=0
      if (( pack_rc_num == 0 )); then
        # Fail closed when stage status is not explicit pass.
        pack_rc_num=1
      fi
    fi

    pack_selected_action_ids_json="$(jq -c '.roadmap.selected_action_ids // []' "$pack_summary_json")"

    value="$(jq -r '(.roadmap.actions_selected_count // ((.roadmap.selected_action_ids // []) | length) // empty)' "$pack_summary_json")"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
      pack_selected_actions_count_num="$value"
      pack_selected_actions_count_json="$value"
    fi

    value="$(jq -r '.summary.actions_executed // empty' "$pack_summary_json")"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
      pack_actions_executed_num="$value"
      pack_actions_executed_json="$value"
    fi

    value="$(jq -r '.summary.pass // empty' "$pack_summary_json")"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
      pack_pass_num="$value"
      pack_pass_json="$value"
    fi

    value="$(jq -r '.summary.fail // empty' "$pack_summary_json")"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
      pack_fail_num="$value"
      pack_fail_json="$value"
    fi

    value="$(jq -r '.summary.timed_out // empty' "$pack_summary_json")"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
      pack_timed_out_num="$value"
      pack_timed_out_json="$value"
    fi

    value="$(jq -r '.summary.soft_failed // empty' "$pack_summary_json")"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
      pack_soft_failed_num="$value"
      pack_soft_failed_json="$value"
    fi

    pack_command_hygiene_json="$(evaluate_selected_action_command_hygiene_json "$pack_summary_json" "$allow_unsafe_shell_commands")"
    pack_command_hygiene_contract_valid="$(printf '%s\n' "$pack_command_hygiene_json" | jq -r '.contract_valid // false')"
    if [[ "$pack_command_hygiene_contract_valid" != "true" ]]; then
      pack_command_hygiene_contract_failure_reason="$(printf '%s\n' "$pack_command_hygiene_json" | jq -r '.contract_failure_reason // ""')"
      if [[ -n "$pack_command_hygiene_contract_failure_reason" ]]; then
        if [[ -n "$pack_contract_failure_reason" ]]; then
          pack_contract_failure_reason="${pack_contract_failure_reason}; ${pack_command_hygiene_contract_failure_reason}"
        else
          pack_contract_failure_reason="$pack_command_hygiene_contract_failure_reason"
        fi
      fi
      pack_contract_valid=0
      pack_status="fail"
      pack_stage_pass=0
      if (( pack_rc_num == 0 )); then
        pack_rc_num=1
      fi
    fi
  else
    pack_summary_valid=0
    pack_contract_valid=0
    pack_contract_failure_reason="evidence-pack summary missing or invalid after stage execution"
    pack_rc_num="$pack_process_rc_num"
    if (( pack_rc_num == 0 )); then
      # Fail closed when the stage exits 0 but emits no valid summary artifact.
      pack_rc_num=125
    fi
    pack_status="fail"
    pack_stage_pass=0
  fi

  pack_rc_json="$pack_rc_num"
  pack_process_rc_json="$pack_process_rc_num"
  echo "[roadmap-live-and-pack-actionable-run] stage=evidence_pack status=$pack_status rc=$pack_rc_num contract_valid=$pack_contract_valid"
  echo "[roadmap-live-and-pack-actionable-run] stage=evidence_pack command_hygiene=$(printf '%s\n' "$pack_command_hygiene_json" | jq -c '{checked, selected_commands_count, unresolved_placeholder_count, unsafe_token_count, unsafe_tokens_blocked, contract_valid, contract_failure_reason}')"
  if [[ "$pack_status" != "pass" && -n "$pack_contract_failure_reason" ]]; then
    echo "[roadmap-live-and-pack-actionable-run] stage=evidence_pack fail_reason=$pack_contract_failure_reason"
  fi
  echo "[roadmap-live-and-pack-actionable-run] stage=evidence_pack summary_json=$pack_summary_json log=$pack_log"
else
  echo "[roadmap-live-and-pack-actionable-run] stage=evidence_pack status=skipped reason=$pack_skip_reason"
fi

final_rc=0
if (( live_stage_pass != 1 )); then
  if (( live_rc != 0 )); then
    final_rc="$live_rc"
  else
    final_rc=1
  fi
fi
if [[ "$run_live_archive" == "1" ]] && (( archive_attempted == 1 )) && (( final_rc == 0 )); then
  if (( archive_rc_num != 0 )); then
    final_rc="$archive_rc_num"
  elif [[ "$archive_status" != "pass" ]]; then
    final_rc=1
  fi
fi
if [[ "$pack_status" != "skipped" ]] && (( final_rc == 0 )); then
  if (( pack_stage_pass != 1 )); then
    if (( pack_rc_num != 0 )); then
      final_rc="$pack_rc_num"
    else
      final_rc=1
    fi
  fi
fi

if (( final_rc == 0 )); then
  final_status="pass"
else
  final_status="fail"
fi

final_failure_substep=""
if [[ "$final_status" == "fail" ]]; then
  if (( live_stage_pass != 1 )); then
    if (( live_contract_valid != 1 )); then
      final_failure_substep="live_evidence_summary_contract"
    else
      final_failure_substep="live_evidence_stage_failed"
    fi
  elif [[ "$run_live_archive" == "1" ]] && (( archive_attempted == 1 )) && (( archive_fail_closed_blocking == 1 )); then
    if (( archive_contract_valid != 1 )); then
      final_failure_substep="live_evidence_archive_summary_contract"
    else
      final_failure_substep="live_evidence_archive_stage_failed"
    fi
  elif [[ "$pack_status" != "skipped" ]] && (( pack_stage_pass != 1 )); then
    if (( pack_contract_valid != 1 )); then
      final_failure_substep="evidence_pack_summary_contract"
    else
      final_failure_substep="evidence_pack_stage_failed"
    fi
  elif [[ "$pack_status" == "skipped" ]]; then
    final_failure_substep="evidence_pack_skipped_due_to_fail_closed_gate"
  fi
fi

steps_executed=1
steps_skipped=2
steps_pass=0
steps_fail=0
if [[ "$live_status" == "pass" ]]; then
  steps_pass=$((steps_pass + 1))
else
  steps_fail=$((steps_fail + 1))
fi
if [[ "$archive_status" == "skipped" ]]; then
  :
else
  steps_executed=$((steps_executed + 1))
  steps_skipped=$((steps_skipped - 1))
  if [[ "$archive_status" == "pass" ]]; then
    steps_pass=$((steps_pass + 1))
  else
    steps_fail=$((steps_fail + 1))
  fi
fi
if [[ "$pack_status" == "skipped" ]]; then
  :
else
  steps_executed=$((steps_executed + 1))
  steps_skipped=$((steps_skipped - 1))
  if [[ "$pack_status" == "pass" ]]; then
    steps_pass=$((steps_pass + 1))
  else
    steps_fail=$((steps_fail + 1))
  fi
fi

selected_actions_total=$((live_selected_actions_count_num + pack_selected_actions_count_num))
actions_executed_total=$((live_actions_executed_num + pack_actions_executed_num))
pass_total=$((live_pass_num + pack_pass_num))
fail_total=$((live_fail_num + pack_fail_num))
timed_out_total=$((live_timed_out_num + pack_timed_out_num))
soft_failed_total=$((live_soft_failed_num + pack_soft_failed_num))

summary_command_input="./scripts/roadmap_live_and_pack_actionable_run.sh"
for arg in "${original_args[@]}"; do
  summary_command_input="${summary_command_input} $(render_log_token "$arg")"
done
summary_command_redacted="$(redact_command_secrets "$summary_command_input")"

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg final_failure_substep "$final_failure_substep" \
  --arg command "$summary_command_redacted" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg live_reports_dir "$live_reports_dir" \
  --arg live_summary_json "$live_summary_json" \
  --arg live_log "$live_log" \
  --arg archive_root "$archive_root" \
  --arg archive_summary_json "$archive_summary_json" \
  --arg archive_log "$archive_log" \
  --arg archive_archive_dir "$archive_archive_dir" \
  --arg archive_status "$archive_status" \
  --arg archive_skip_reason "$archive_skip_reason" \
  --arg pack_reports_dir "$pack_reports_dir" \
  --arg pack_summary_json "$pack_summary_json" \
  --arg pack_log "$pack_log" \
  --arg shared_roadmap_summary_json "${shared_roadmap_summary_json:-}" \
  --arg shared_roadmap_report_md "${shared_roadmap_report_md:-}" \
  --arg pack_skip_reason "$pack_skip_reason" \
  --arg live_status "$live_status" \
  --argjson live_rc "$live_rc" \
  --argjson live_process_rc "$live_process_rc" \
  --argjson live_summary_valid "$live_summary_valid" \
  --argjson live_contract_valid "$live_contract_valid" \
  --arg live_contract_failure_reason "$live_contract_failure_reason" \
  --argjson live_command_hygiene "$live_command_hygiene_json" \
  --argjson live_selected_actions_count "$live_selected_actions_count_json" \
  --argjson live_selected_action_ids "$live_selected_action_ids_json" \
  --argjson live_actions_executed "$live_actions_executed_json" \
  --argjson live_pass "$live_pass_json" \
  --argjson live_fail "$live_fail_json" \
  --argjson live_timed_out "$live_timed_out_json" \
  --argjson live_soft_failed "$live_soft_failed_json" \
  --argjson archive_attempted "$archive_attempted" \
  --argjson archive_rc "$archive_rc_json" \
  --argjson archive_process_rc "$archive_process_rc_json" \
  --argjson archive_summary_valid "$archive_summary_valid" \
  --argjson archive_contract_valid "$archive_contract_valid" \
  --arg archive_contract_failure_reason "$archive_contract_failure_reason" \
  --argjson archive_summary_status "$archive_summary_status_json" \
  --argjson archive_summary_rc "$archive_summary_rc_json" \
  --argjson archive_candidate_total "$archive_candidate_total_json" \
  --argjson archive_copied_total "$archive_copied_total_json" \
  --argjson archive_missing_total "$archive_missing_total_json" \
  --argjson archive_copy_error_total "$archive_copy_error_total_json" \
  --argjson archive_missing_family_count "$archive_missing_family_count_json" \
  --argjson archive_fail_closed_blocking "$archive_fail_closed_blocking" \
  --arg pack_status "$pack_status" \
  --argjson pack_rc "$pack_rc_json" \
  --argjson pack_process_rc "$pack_process_rc_json" \
  --argjson pack_summary_valid "$pack_summary_valid" \
  --argjson pack_contract_valid "$pack_contract_valid" \
  --arg pack_contract_failure_reason "$pack_contract_failure_reason" \
  --argjson pack_command_hygiene "$pack_command_hygiene_json" \
  --argjson pack_selected_actions_count "$pack_selected_actions_count_json" \
  --argjson pack_selected_action_ids "$pack_selected_action_ids_json" \
  --argjson pack_actions_executed "$pack_actions_executed_json" \
  --argjson pack_pass "$pack_pass_json" \
  --argjson pack_fail "$pack_fail_json" \
  --argjson pack_timed_out "$pack_timed_out_json" \
  --argjson pack_soft_failed "$pack_soft_failed_json" \
  --argjson refresh_manual_validation "$refresh_manual_validation" \
  --argjson refresh_single_machine_readiness "$refresh_single_machine_readiness" \
  --argjson parallel "$parallel" \
  --arg scope "$scope" \
  --argjson max_actions "$max_actions" \
  --argjson action_timeout_sec "$action_timeout_sec" \
  --argjson allow_unsafe_shell_commands "$allow_unsafe_shell_commands" \
  --argjson continue_on_live_fail "$continue_on_live_fail" \
  --argjson run_live_archive "$run_live_archive" \
  --argjson steps_executed "$steps_executed" \
  --argjson steps_skipped "$steps_skipped" \
  --argjson steps_pass "$steps_pass" \
  --argjson steps_fail "$steps_fail" \
  --argjson selected_actions_total "$selected_actions_total" \
  --argjson actions_executed_total "$actions_executed_total" \
  --argjson pass_total "$pass_total" \
  --argjson fail_total "$fail_total" \
  --argjson timed_out_total "$timed_out_total" \
  --argjson soft_failed_total "$soft_failed_total" \
  '{
    version: 1,
    schema: { id: "roadmap_live_and_pack_actionable_run_summary", major: 1, minor: 0 },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    failure_substep: (if $final_failure_substep == "" then null else $final_failure_substep end),
    command: $command,
    inputs: {
      refresh_manual_validation: ($refresh_manual_validation == 1),
      refresh_single_machine_readiness: ($refresh_single_machine_readiness == 1),
      parallel: ($parallel == 1),
      scope: $scope,
      max_actions: $max_actions,
      action_timeout_sec: $action_timeout_sec,
      allow_unsafe_shell_commands: ($allow_unsafe_shell_commands == 1),
      continue_on_live_fail: ($continue_on_live_fail == 1),
      run_live_archive: ($run_live_archive == 1)
    },
    steps: {
      live_evidence: {
        status: $live_status,
        rc: $live_rc,
        process_rc: $live_process_rc,
        summary_valid: ($live_summary_valid == 1),
        contract_valid: ($live_contract_valid == 1),
        contract_failure_reason: (if $live_contract_failure_reason == "" then null else $live_contract_failure_reason end),
        command_hygiene: $live_command_hygiene,
        selected_actions_count: $live_selected_actions_count,
        selected_action_ids: $live_selected_action_ids,
        actions_executed: $live_actions_executed,
        pass: $live_pass,
        fail: $live_fail,
        timed_out: $live_timed_out,
        soft_failed: $live_soft_failed,
        artifacts: {
          reports_dir: $live_reports_dir,
          summary_json: $live_summary_json,
          log: $live_log
        }
      },
      live_evidence_archive: {
        attempted: ($archive_attempted == 1),
        status: $archive_status,
        rc: $archive_rc,
        process_rc: $archive_process_rc,
        summary_valid: ($archive_summary_valid == 1),
        contract_valid: ($archive_contract_valid == 1),
        contract_failure_reason: (if $archive_contract_failure_reason == "" then null else $archive_contract_failure_reason end),
        skip_reason: (if $archive_status == "skipped" then $archive_skip_reason else null end),
        fail_closed_blocking: ($archive_fail_closed_blocking == 1),
        summary_status: $archive_summary_status,
        summary_rc: $archive_summary_rc,
        candidate_total: $archive_candidate_total,
        copied_total: $archive_copied_total,
        missing_total: $archive_missing_total,
        copy_error_total: $archive_copy_error_total,
        missing_family_count: $archive_missing_family_count,
        artifacts: {
          archive_root: $archive_root,
          archive_dir: (if $archive_archive_dir == "" then null else $archive_archive_dir end),
          summary_json: $archive_summary_json,
          log: $archive_log
        }
      },
      evidence_pack: {
        status: $pack_status,
        rc: $pack_rc,
        process_rc: $pack_process_rc,
        summary_valid: ($pack_summary_valid == 1),
        contract_valid: ($pack_contract_valid == 1),
        contract_failure_reason: (if $pack_contract_failure_reason == "" then null else $pack_contract_failure_reason end),
        command_hygiene: $pack_command_hygiene,
        skip_reason: (if $pack_status == "skipped" then $pack_skip_reason else null end),
        selected_actions_count: $pack_selected_actions_count,
        selected_action_ids: $pack_selected_action_ids,
        actions_executed: $pack_actions_executed,
        pass: $pack_pass,
        fail: $pack_fail,
        timed_out: $pack_timed_out,
        soft_failed: $pack_soft_failed,
        artifacts: {
          reports_dir: $pack_reports_dir,
          summary_json: $pack_summary_json,
          log: $pack_log
        }
      }
    },
    summary: {
      steps_total: 3,
      steps_executed: $steps_executed,
      steps_skipped: $steps_skipped,
      steps_pass: $steps_pass,
      steps_fail: $steps_fail,
      selected_actions_total: $selected_actions_total,
      actions_executed_total: $actions_executed_total,
      pass_total: $pass_total,
      fail_total: $fail_total,
      timed_out_total: $timed_out_total,
      soft_failed_total: $soft_failed_total
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      live_summary_json: $live_summary_json,
      live_log: $live_log,
      live_archive_summary_json: $archive_summary_json,
      live_archive_log: $archive_log,
      live_archive_root: $archive_root,
      live_archive_dir: (if $archive_archive_dir == "" then null else $archive_archive_dir end),
      evidence_pack_summary_json: $pack_summary_json,
      evidence_pack_log: $pack_log,
      roadmap_summary_json: (if $shared_roadmap_summary_json == "" then null else $shared_roadmap_summary_json end),
      roadmap_report_md: (if $shared_roadmap_report_md == "" then null else $shared_roadmap_report_md end)
    }
  }' >"$summary_tmp"

mv "$summary_tmp" "$summary_json"

echo "[roadmap-live-and-pack-actionable-run] status=$final_status rc=$final_rc scope=$scope continue_on_live_fail=$continue_on_live_fail run_live_archive=$run_live_archive failure_substep=${final_failure_substep:-none}"
if [[ "$final_status" == "fail" && -n "$final_failure_substep" ]]; then
  echo "[roadmap-live-and-pack-actionable-run] fail_substep=$final_failure_substep"
fi
echo "[roadmap-live-and-pack-actionable-run] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
