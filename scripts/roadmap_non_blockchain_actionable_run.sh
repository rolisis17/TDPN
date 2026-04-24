#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_non_blockchain_actionable_run.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--roadmap-summary-json PATH] \
    [--roadmap-report-md PATH] \
    [--action-timeout-sec N] \
    [--allow-unsafe-shell-commands [0|1]] \
    [--refresh-manual-validation [0|1]] \
    [--refresh-single-machine-readiness [0|1]] \
    [--allow-policy-no-go [0|1]] \
    [--parallel [0|1]] \
    [--recommended-only [0|1]] \
    [--max-actions N] \
    [--print-summary-json [0|1]]

Purpose:
  Resolve the non-blockchain actionable command list from roadmap_progress_report,
  then execute those no-sudo/no-GitHub commands in one deterministic wrapper run.

Defaults:
  --action-timeout-sec 0   (0 = no per-action timeout)
  --allow-unsafe-shell-commands 0
  --refresh-manual-validation 0
  --refresh-single-machine-readiness 0
  --allow-policy-no-go 0
  --parallel 0
  --recommended-only 0
  --max-actions 0   (0 = no limit)
  --print-summary-json 1

Exit behavior:
  - Runs all selected commands (sequential by default, concurrent when --parallel=1).
  - Returns rc=0 only when all selected commands pass (or no actions selected).
  - Returns first failing action command rc otherwise.
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
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
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

require_value_or_die() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
    echo "$flag requires a value"
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

sanitize_id() {
  local value
  value="$(trim "${1:-}")"
  value="${value//[^a-zA-Z0-9._-]/_}"
  if [[ -z "$value" ]]; then
    value="action"
  fi
  printf '%s' "$value"
}

is_sensitive_secret_flag() {
  case "${1:-}" in
    --campaign-subject|--subject|--key|--invite-key|--campaign-anon-cred|--anon-cred|--token|--auth-token|--admin-token|--authorization|--bearer)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
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
  local token=""
  local key=""
  local rendered=""
  local idx=0
  local token_count=0

  if command_string_to_argv "$line"; then
    token_count="${#COMMAND_STRING_ARGV[@]}"
    while (( idx < token_count )); do
      token="${COMMAND_STRING_ARGV[$idx]}"
      if is_sensitive_secret_flag "$token"; then
        rendered="${rendered}${rendered:+ }$(render_log_token "$token")"
        if (( idx + 1 < token_count )); then
          rendered="${rendered}${rendered:+ }[redacted]"
          idx=$((idx + 2))
        else
          idx=$((idx + 1))
        fi
        continue
      fi

      if [[ "$token" == --*=* ]]; then
        key="${token%%=*}"
        if is_sensitive_secret_flag "$key"; then
          rendered="${rendered}${rendered:+ }${key}=[redacted]"
          idx=$((idx + 1))
          continue
        fi
      fi

      rendered="${rendered}${rendered:+ }$(render_log_token "$token")"
      idx=$((idx + 1))
    done
    printf '%s' "$rendered"
    return
  fi

  line="$(printf '%s' "$line" | sed -E \
    -e "s/(${flag_regex})([[:space:]]+)\"[^\"]*\"/\\1\\2[redacted]/g" \
    -e "s/(${flag_regex})([[:space:]]+)'[^']*'/\\1\\2[redacted]/g" \
    -e "s/(${flag_regex})([[:space:]]+)[^[:space:]]+/\\1\\2[redacted]/g" \
    -e "s/(${flag_regex})=[^[:space:]]+/\\1=[redacted]/g")"
  printf '%s' "$line"
}

command_requires_shell_execution() {
  local command_text="${1:-}"
  if [[ -z "$command_text" ]]; then
    return 1
  fi
  if [[ "$command_text" == *$'\n'* || "$command_text" == *$'\r'* ]]; then
    return 0
  fi
  if [[ "$command_text" =~ [\;\|\&\<\>\`\$\(\)\{\}] ]]; then
    return 0
  fi
  return 1
}

command_string_to_argv() {
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

path_is_symlink_free_under_scripts_dir() {
  local candidate="${1:-}"
  local scripts_root="$ROOT_DIR/scripts"
  local current=""
  if [[ -z "$candidate" ]]; then
    return 1
  fi
  current="$candidate"
  while :; do
    if [[ -L "$current" ]]; then
      return 1
    fi
    if [[ "$current" == "$scripts_root" ]]; then
      return 0
    fi
    current="$(dirname "$current")"
    if [[ "$current" != "$scripts_root" && "$current" != "$scripts_root/"* ]]; then
      return 1
    fi
  done
}

canonical_existing_file_path() {
  local candidate="${1:-}"
  local parent_dir=""
  local base_name=""
  if [[ -z "$candidate" || ! -f "$candidate" ]]; then
    return 1
  fi
  parent_dir="$(dirname "$candidate")"
  base_name="$(basename "$candidate")"
  if ! parent_dir="$(cd -P "$parent_dir" 2>/dev/null && pwd)"; then
    return 1
  fi
  printf '%s/%s' "$parent_dir" "$base_name"
}

ACTION_COMMAND_VALIDATED_SCRIPT_PATH=""

action_command_argv_allowed() {
  local -a argv=("$@")
  local cmd
  local script_path
  local scripts_root="$ROOT_DIR/scripts"
  local scripts_root_canonical=""
  local canonical_script_path=""
  ACTION_COMMAND_VALIDATED_SCRIPT_PATH=""
  if [[ "${#argv[@]}" -eq 0 ]]; then
    return 1
  fi
  if ! scripts_root_canonical="$(cd -P "$scripts_root" 2>/dev/null && pwd)"; then
    return 1
  fi
  cmd="${argv[0]}"
  if [[ "$cmd" == "bash" ]]; then
    if [[ "${#argv[@]}" -lt 2 ]]; then
      return 1
    fi
    script_path="${argv[1]}"
    if [[ "$script_path" == -* ]]; then
      # Keep shell-evaluated modes blocked in argv-safe path mode.
      return 1
    fi
  else
    script_path="$cmd"
  fi
  case "$script_path" in
    "$scripts_root"/*)
      ;;
    scripts/*)
      script_path="$ROOT_DIR/$script_path"
      ;;
    ./scripts/*)
      script_path="$ROOT_DIR/${script_path#./}"
      ;;
    *)
      return 1
      ;;
  esac
  if [[ ! -f "$script_path" ]]; then
    return 1
  fi
  if ! path_is_symlink_free_under_scripts_dir "$script_path"; then
    return 1
  fi
  if ! canonical_script_path="$(canonical_existing_file_path "$script_path")"; then
    return 1
  fi
  if [[ "$canonical_script_path" != "$scripts_root_canonical/"* ]]; then
    return 1
  fi
  ACTION_COMMAND_VALIDATED_SCRIPT_PATH="$canonical_script_path"
  return 0
}

run_action_command_string() {
  local command_text="${1:-}"
  local log_path="${2:-}"
  local timeout_sec="${3:-0}"
  local redacted_command_text=""
  local -a command_argv=()
  local -a env_prefix=()
  local token
  local validated_script_path_initial=""
  local validated_script_path_pre_exec=""
  local pre_exec_revalidate_delay_sec="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_PRE_EXEC_REVALIDATE_DELAY_SEC:-0}"

  if [[ -z "$command_text" ]]; then
    return 4
  fi
  redacted_command_text="$(redact_command_secrets "$command_text")"

  if ! command_requires_shell_execution "$command_text" && command_string_to_argv "$command_text"; then
    for token in "${COMMAND_STRING_ARGV[@]}"; do
      if [[ "${#command_argv[@]}" -eq 0 && "$token" =~ ^[A-Za-z_][A-Za-z0-9_]*=.*$ ]]; then
        env_prefix+=("$token")
        continue
      fi
      command_argv+=("$token")
    done

    if [[ "${#command_argv[@]}" -gt 0 ]]; then
      if ! action_command_argv_allowed "${command_argv[@]}"; then
        {
          echo "refusing untrusted action command (outside scripts allowlist)"
          echo "command: $redacted_command_text"
        } >"$log_path"
        return 6
      fi
      validated_script_path_initial="$ACTION_COMMAND_VALIDATED_SCRIPT_PATH"
      if [[ "${#env_prefix[@]}" -gt 0 && "${allow_unsafe_shell_commands:-0}" != "1" ]]; then
        {
          echo "refusing env-prefixed action command (set --allow-unsafe-shell-commands 1 to override)"
          echo "command: $redacted_command_text"
        } >"$log_path"
        return 5
      fi
      if [[ "$pre_exec_revalidate_delay_sec" != "0" && "$pre_exec_revalidate_delay_sec" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        sleep "$pre_exec_revalidate_delay_sec"
      fi
      if ! action_command_argv_allowed "${command_argv[@]}"; then
        {
          echo "refusing untrusted action command (pre-exec validation mismatch)"
          echo "command: $redacted_command_text"
          if [[ -n "$validated_script_path_initial" ]]; then
            echo "validated_path_initial: $validated_script_path_initial"
          fi
        } >"$log_path"
        return 6
      fi
      validated_script_path_pre_exec="$ACTION_COMMAND_VALIDATED_SCRIPT_PATH"
      if [[ -n "$validated_script_path_initial" && "$validated_script_path_initial" != "$validated_script_path_pre_exec" ]]; then
        {
          echo "refusing untrusted action command (pre-exec validation mismatch)"
          echo "command: $redacted_command_text"
          echo "validated_path_initial: $validated_script_path_initial"
          echo "validated_path_pre_exec: $validated_script_path_pre_exec"
        } >"$log_path"
        return 6
      fi
      if (( timeout_sec > 0 )); then
        if [[ "${#env_prefix[@]}" -gt 0 ]]; then
          timeout --foreground "${timeout_sec}s" env "${env_prefix[@]}" "${command_argv[@]}" >"$log_path" 2>&1
        else
          timeout --foreground "${timeout_sec}s" "${command_argv[@]}" >"$log_path" 2>&1
        fi
      else
        if [[ "${#env_prefix[@]}" -gt 0 ]]; then
          env "${env_prefix[@]}" "${command_argv[@]}" >"$log_path" 2>&1
        else
          "${command_argv[@]}" >"$log_path" 2>&1
        fi
      fi
      return $?
    fi
  fi

  if (( timeout_sec > 0 )); then
    if [[ "${allow_unsafe_shell_commands:-0}" != "1" ]]; then
      {
        echo "refusing shell-evaluated action command (set --allow-unsafe-shell-commands 1 to override)"
        echo "command: $redacted_command_text"
      } >"$log_path"
      return 5
    fi
    timeout --foreground "${timeout_sec}s" bash -lc "$command_text" >"$log_path" 2>&1
  else
    if [[ "${allow_unsafe_shell_commands:-0}" != "1" ]]; then
      {
        echo "refusing shell-evaluated action command (set --allow-unsafe-shell-commands 1 to override)"
        echo "command: $redacted_command_text"
      } >"$log_path"
      return 5
    fi
    bash -lc "$command_text" >"$log_path" 2>&1
  fi
}

need_cmd jq
need_cmd bash
need_cmd date
need_cmd mktemp

reports_dir="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_REPORTS_DIR:-}"
summary_json="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_SUMMARY_JSON:-}"
roadmap_summary_json="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SUMMARY_JSON:-}"
roadmap_report_md="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_REPORT_MD:-}"
refresh_manual_validation="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_REFRESH_MANUAL_VALIDATION:-0}"
refresh_single_machine_readiness="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_REFRESH_SINGLE_MACHINE_READINESS:-0}"
allow_policy_no_go="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ALLOW_POLICY_NO_GO:-0}"
parallel="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_PARALLEL:-0}"
recommended_only="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_RECOMMENDED_ONLY:-0}"
max_actions="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_MAX_ACTIONS:-0}"
print_summary_json="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_PRINT_SUMMARY_JSON:-1}"
action_timeout_sec="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ACTION_TIMEOUT_SEC:-0}"
allow_unsafe_shell_commands="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ALLOW_UNSAFE_SHELL_COMMANDS:-0}"

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
    --allow-policy-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_policy_no_go="${2:-}"
        shift 2
      else
        allow_policy_no_go="1"
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
    --recommended-only)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        recommended_only="${2:-}"
        shift 2
      else
        recommended_only="1"
        shift
      fi
      ;;
    --max-actions)
      require_value_or_die "$1" "${2:-}"
      max_actions="${2:-}"
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

bool_arg_or_die "--refresh-manual-validation" "$refresh_manual_validation"
bool_arg_or_die "--refresh-single-machine-readiness" "$refresh_single_machine_readiness"
bool_arg_or_die "--allow-policy-no-go" "$allow_policy_no_go"
bool_arg_or_die "--parallel" "$parallel"
bool_arg_or_die "--recommended-only" "$recommended_only"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--allow-unsafe-shell-commands" "$allow_unsafe_shell_commands"
int_arg_or_die "--max-actions" "$max_actions"
int_arg_or_die "--action-timeout-sec" "$action_timeout_sec"

if (( action_timeout_sec > 0 )); then
  need_cmd timeout
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/roadmap_non_blockchain_actionable_run_${run_stamp}"
fi
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$roadmap_summary_json" ]]; then
  roadmap_summary_json="$reports_dir/roadmap_progress_summary.json"
fi
if [[ -z "$roadmap_report_md" ]]; then
  roadmap_report_md="$reports_dir/roadmap_progress_report.md"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/roadmap_non_blockchain_actionable_run_summary.json"
fi

roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
roadmap_report_md="$(abs_path "$roadmap_report_md")"
summary_json="$(abs_path "$summary_json")"
roadmap_log="$reports_dir/roadmap_progress_report.log"

mkdir -p "$(dirname "$roadmap_summary_json")" "$(dirname "$roadmap_report_md")" "$(dirname "$summary_json")"

roadmap_script="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"
if [[ ! -f "$roadmap_script" ]]; then
  echo "missing roadmap script: $roadmap_script"
  exit 2
fi
if [[ ! -r "$roadmap_script" ]]; then
  echo "roadmap script is not readable: $roadmap_script"
  exit 2
fi

roadmap_cmd=(
  bash
  "$roadmap_script"
  --refresh-manual-validation "$refresh_manual_validation"
  --refresh-single-machine-readiness "$refresh_single_machine_readiness"
  --summary-json "$roadmap_summary_json"
  --report-md "$roadmap_report_md"
  --print-report 0
  --print-summary-json 0
)

echo "[roadmap-non-blockchain-actionable-run] stage=roadmap_progress_report status=running"
set +e
"${roadmap_cmd[@]}" >"$roadmap_log" 2>&1
roadmap_rc=$?
set -e
if (( roadmap_rc != 0 )); then
  echo "[roadmap-non-blockchain-actionable-run] stage=roadmap_progress_report status=fail rc=$roadmap_rc"
  echo "roadmap_progress_report failed; see: $roadmap_log"
  exit "$roadmap_rc"
fi
echo "[roadmap-non-blockchain-actionable-run] stage=roadmap_progress_report status=pass rc=0"

if [[ ! -f "$roadmap_summary_json" ]] || ! jq -e . "$roadmap_summary_json" >/dev/null 2>&1; then
  echo "roadmap summary JSON missing or invalid: $roadmap_summary_json"
  exit 3
fi

recommended_id="$(jq -r '.vpn_track.non_blockchain_recommended_gate_id // ""' "$roadmap_summary_json")"
selected_actions_json="$(jq -c '.vpn_track.non_blockchain_actionable_no_sudo_or_github // []' "$roadmap_summary_json")"
recommended_only_selection_state="disabled"
recommended_only_selection_reason=""
recommended_only_fail_closed="false"
if [[ "$recommended_only" == "1" ]]; then
  if [[ -n "$recommended_id" ]]; then
    selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --arg rid "$recommended_id" '[.[] | select((.id // "") == $rid)]')"
    if printf '%s\n' "$selected_actions_json" | jq -e 'length == 0' >/dev/null 2>&1; then
      recommended_only_selection_state="recommended_id_not_found"
      recommended_only_selection_reason="recommended gate id '$recommended_id' was not present in actionable list"
      recommended_only_fail_closed="true"
      echo "[roadmap-non-blockchain-actionable-run] recommended-only strict mode: no actions selected; reason=$recommended_only_selection_state recommended_gate_id=$recommended_id"
    else
      recommended_only_selection_state="selected_recommended_action"
    fi
  else
    selected_actions_json="[]"
    recommended_only_selection_state="missing_recommended_id"
    recommended_only_selection_reason="no recommended gate id was provided"
    recommended_only_fail_closed="true"
    echo "[roadmap-non-blockchain-actionable-run] recommended-only strict mode: no actions selected; reason=$recommended_only_selection_state"
  fi
fi
if (( max_actions > 0 )); then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --argjson max_actions "$max_actions" '.[:$max_actions]')"
fi

actions_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"
selected_action_ids="$(printf '%s\n' "$selected_actions_json" | jq -r '[.[] | .id // "" | select(length > 0)] | join(",")')"
if [[ -z "$selected_action_ids" ]]; then
  selected_action_ids="none"
fi
recommended_gate_id_not_found="false"
if [[ "$recommended_only_selection_state" == "recommended_id_not_found" ]]; then
  recommended_gate_id_not_found="true"
fi
echo "[roadmap-non-blockchain-actionable-run] selected_actions=$actions_count parallel=$parallel action_timeout_sec=$action_timeout_sec recommended_only=$recommended_only recommended_gate_id=${recommended_id:-none}"
echo "[roadmap-non-blockchain-actionable-run] allow_unsafe_shell_commands=$allow_unsafe_shell_commands"
echo "[roadmap-non-blockchain-actionable-run] action_ids=$selected_action_ids"
if (( actions_count == 0 )); then
  if [[ "$recommended_only_fail_closed" == "true" ]]; then
    echo "[roadmap-non-blockchain-actionable-run] fail-closed: recommended-only strict mode selected zero actions (state=$recommended_only_selection_state)"
  else
    echo "[roadmap-non-blockchain-actionable-run] no actions selected; writing pass summary"
  fi
fi
actions_tmp="$(mktemp)"
actions_results_tmp_dir="$(mktemp -d)"
trap 'rm -f "$actions_tmp"; rm -rf "$actions_results_tmp_dir"' EXIT
: >"$actions_tmp"

declare -a action_result_files
declare -a action_pids
declare -a action_ids
declare -a action_labels
declare -a action_reasons
declare -a action_commands
declare -a action_commands_redacted
declare -a action_logs
declare -a action_allow_policy_applied

final_status="pass"
final_rc=0
executed_count=0
pass_count=0
fail_count=0
timed_out_count=0
if [[ "$recommended_only_fail_closed" == "true" ]]; then
  final_status="fail"
  final_rc=5
fi

for idx in $(seq 0 $(( actions_count - 1 )) 2>/dev/null || true); do
  action_json="$(printf '%s\n' "$selected_actions_json" | jq -c --argjson idx "$idx" '.[$idx]')"
  action_id="$(printf '%s\n' "$action_json" | jq -r '.id // ""')"
  action_label="$(printf '%s\n' "$action_json" | jq -r '.label // ""')"
  action_reason="$(printf '%s\n' "$action_json" | jq -r '.reason // ""')"
  action_command="$(printf '%s\n' "$action_json" | jq -r '.command // ""')"
  action_allow_policy_no_go_applied="false"
  action_id_safe="$(sanitize_id "$action_id")"
  action_log="$reports_dir/action_$((idx + 1))_${action_id_safe}.log"
  action_result_file="$actions_results_tmp_dir/action_$((idx + 1))_${action_id_safe}.json"

  if [[ "$allow_policy_no_go" == "1" ]]; then
    if [[ "$action_id" == "phase1_resilience_handoff_run_dry" || "$action_command" == *"phase1_resilience_handoff_run.sh"* ]]; then
      if [[ "$action_command" != *"--allow-policy-no-go"* ]]; then
        action_command="$action_command --allow-policy-no-go 1"
        action_allow_policy_no_go_applied="true"
        if [[ -n "$action_reason" ]]; then
          action_reason="$action_reason, allow_policy_no_go=1"
        else
          action_reason="allow_policy_no_go=1"
        fi
      fi
    fi
  fi

  action_ids[$idx]="$action_id"
  action_labels[$idx]="$action_label"
  action_reasons[$idx]="$action_reason"
  action_commands[$idx]="$action_command"
  action_command_redacted="$(redact_command_secrets "$action_command")"
  action_commands_redacted[$idx]="$action_command_redacted"
  action_logs[$idx]="$action_log"
  action_allow_policy_applied[$idx]="$action_allow_policy_no_go_applied"
  action_result_files[$idx]="$action_result_file"

  if [[ -z "$action_command" ]]; then
    jq -cn \
      --arg id "$action_id" \
      --arg label "$action_label" \
      --arg reason "$action_reason" \
      --arg command "$action_command_redacted" \
      --arg status "fail" \
      --arg notes "missing command" \
      --arg log "$action_log" \
      --arg failure_kind "missing_command" \
      --argjson rc 4 \
      --argjson command_rc 4 \
      --argjson timed_out false \
      --argjson timeout_sec "$action_timeout_sec" \
      --argjson allow_policy_no_go_applied "$action_allow_policy_no_go_applied" \
      '{
        id: $id,
        label: $label,
        reason: $reason,
        command: $command,
        allow_policy_no_go_applied: $allow_policy_no_go_applied,
        status: $status,
        rc: $rc,
        command_rc: $command_rc,
        timed_out: $timed_out,
        timeout_sec: (if $timeout_sec > 0 then $timeout_sec else null end),
        failure_kind: $failure_kind,
        notes: (if $notes == "" then null else $notes end),
        artifacts: { log: $log }
      }' >"$action_result_file"
  else
    echo "[roadmap-non-blockchain-actionable-run] action=$action_id status=running"
    if [[ "$parallel" == "1" ]]; then
      (
        action_status="fail"
        action_rc=125
        command_rc=125
        action_timed_out="false"
        action_failure_kind="command_failed"
        action_notes="command failed"
        set +e
        run_action_command_string "$action_command" "$action_log" "$action_timeout_sec"
        command_rc=$?
        set -e
        if (( command_rc == 0 )); then
          action_status="pass"
          action_rc=0
          action_notes=""
          action_failure_kind="none"
        else
          action_status="fail"
          action_rc="$command_rc"
          if (( command_rc == 124 )) && (( action_timeout_sec > 0 )); then
            action_timed_out="true"
            action_failure_kind="timed_out"
            action_notes="action timed out after ${action_timeout_sec}s"
          fi
        fi
        jq -cn \
          --arg id "$action_id" \
          --arg label "$action_label" \
          --arg reason "$action_reason" \
          --arg command "$action_command_redacted" \
          --arg status "$action_status" \
          --arg notes "$action_notes" \
          --arg log "$action_log" \
          --arg failure_kind "$action_failure_kind" \
          --argjson rc "$action_rc" \
          --argjson command_rc "$command_rc" \
          --argjson timed_out "$action_timed_out" \
          --argjson timeout_sec "$action_timeout_sec" \
          --argjson allow_policy_no_go_applied "$action_allow_policy_no_go_applied" \
          '{
            id: $id,
            label: $label,
            reason: $reason,
            command: $command,
            allow_policy_no_go_applied: $allow_policy_no_go_applied,
            status: $status,
            rc: $rc,
            command_rc: $command_rc,
            timed_out: $timed_out,
            timeout_sec: (if $timeout_sec > 0 then $timeout_sec else null end),
            failure_kind: $failure_kind,
            notes: (if $notes == "" then null else $notes end),
            artifacts: { log: $log }
          }' >"$action_result_file"
      ) &
      action_pids[$idx]=$!
    else
      action_status="fail"
      action_rc=125
      command_rc=125
      action_timed_out="false"
      action_failure_kind="command_failed"
      action_notes="command failed"
      set +e
      run_action_command_string "$action_command" "$action_log" "$action_timeout_sec"
      command_rc=$?
      set -e
      if (( command_rc == 0 )); then
        action_status="pass"
        action_rc=0
        action_notes=""
        action_failure_kind="none"
      else
        action_status="fail"
        action_rc="$command_rc"
        if (( command_rc == 124 )) && (( action_timeout_sec > 0 )); then
          action_timed_out="true"
          action_failure_kind="timed_out"
          action_notes="action timed out after ${action_timeout_sec}s"
        fi
      fi
      jq -cn \
        --arg id "$action_id" \
        --arg label "$action_label" \
        --arg reason "$action_reason" \
        --arg command "$action_command_redacted" \
        --arg status "$action_status" \
        --arg notes "$action_notes" \
        --arg log "$action_log" \
        --arg failure_kind "$action_failure_kind" \
        --argjson rc "$action_rc" \
        --argjson command_rc "$command_rc" \
        --argjson timed_out "$action_timed_out" \
        --argjson timeout_sec "$action_timeout_sec" \
        --argjson allow_policy_no_go_applied "$action_allow_policy_no_go_applied" \
        '{
          id: $id,
          label: $label,
          reason: $reason,
          command: $command,
          allow_policy_no_go_applied: $allow_policy_no_go_applied,
          status: $status,
          rc: $rc,
          command_rc: $command_rc,
          timed_out: $timed_out,
          timeout_sec: (if $timeout_sec > 0 then $timeout_sec else null end),
          failure_kind: $failure_kind,
          notes: (if $notes == "" then null else $notes end),
          artifacts: { log: $log }
        }' >"$action_result_file"
    fi
  fi
done

if [[ "$parallel" == "1" ]]; then
  for idx in $(seq 0 $(( actions_count - 1 )) 2>/dev/null || true); do
    action_pid="${action_pids[$idx]:-}"
    if [[ -n "$action_pid" ]]; then
      set +e
      wait "$action_pid"
      wait_rc=$?
      set -e
      if (( wait_rc != 0 )); then
        action_id="${action_ids[$idx]}"
        action_label="${action_labels[$idx]}"
        action_reason="${action_reasons[$idx]}"
        action_command="${action_commands[$idx]}"
        action_command_redacted="${action_commands_redacted[$idx]}"
        action_log="${action_logs[$idx]}"
        action_allow_policy_no_go_applied="${action_allow_policy_applied[$idx]}"
        action_result_file="${action_result_files[$idx]}"
        jq -cn \
          --arg id "$action_id" \
          --arg label "$action_label" \
          --arg reason "$action_reason" \
          --arg command "$action_command_redacted" \
          --arg status "fail" \
          --arg notes "internal runner error (wait rc=$wait_rc)" \
          --arg log "$action_log" \
          --arg failure_kind "runner_error" \
          --argjson rc "$wait_rc" \
          --argjson command_rc "$wait_rc" \
          --argjson timed_out false \
          --argjson timeout_sec "$action_timeout_sec" \
          --argjson allow_policy_no_go_applied "$action_allow_policy_no_go_applied" \
          '{
            id: $id,
            label: $label,
            reason: $reason,
            command: $command,
            allow_policy_no_go_applied: $allow_policy_no_go_applied,
            status: $status,
            rc: $rc,
            command_rc: $command_rc,
            timed_out: $timed_out,
            timeout_sec: (if $timeout_sec > 0 then $timeout_sec else null end),
            failure_kind: $failure_kind,
            notes: (if $notes == "" then null else $notes end),
            artifacts: { log: $log }
          }' >"$action_result_file"
      fi
    fi
  done
fi

for idx in $(seq 0 $(( actions_count - 1 )) 2>/dev/null || true); do
  action_result_file="${action_result_files[$idx]}"
  action_id="${action_ids[$idx]}"
  action_label="${action_labels[$idx]}"
  action_reason="${action_reasons[$idx]}"
  action_command="${action_commands[$idx]}"
  action_command_redacted="${action_commands_redacted[$idx]}"
  action_log="${action_logs[$idx]}"
  action_allow_policy_no_go_applied="${action_allow_policy_applied[$idx]}"

  if [[ ! -s "$action_result_file" ]] || ! jq -e . "$action_result_file" >/dev/null 2>&1; then
    jq -cn \
      --arg id "$action_id" \
      --arg label "$action_label" \
      --arg reason "$action_reason" \
      --arg command "$action_command_redacted" \
      --arg status "fail" \
      --arg notes "internal runner error (missing or invalid action result)" \
      --arg log "$action_log" \
      --arg failure_kind "runner_error" \
      --argjson rc 125 \
      --argjson command_rc 125 \
      --argjson timed_out false \
      --argjson timeout_sec "$action_timeout_sec" \
      --argjson allow_policy_no_go_applied "$action_allow_policy_no_go_applied" \
      '{
        id: $id,
        label: $label,
        reason: $reason,
        command: $command,
        allow_policy_no_go_applied: $allow_policy_no_go_applied,
        status: $status,
        rc: $rc,
        command_rc: $command_rc,
        timed_out: $timed_out,
        timeout_sec: (if $timeout_sec > 0 then $timeout_sec else null end),
        failure_kind: $failure_kind,
        notes: (if $notes == "" then null else $notes end),
        artifacts: { log: $log }
      }' >"$action_result_file"
  fi

  action_status="$(jq -r '.status // "fail"' "$action_result_file")"
  action_rc="$(jq -r '.rc // .command_rc // 125' "$action_result_file")"
  action_timed_out="$(jq -r '.timed_out // false' "$action_result_file")"
  action_failure_kind="$(jq -r '.failure_kind // "command_failed"' "$action_result_file")"
  action_notes="$(jq -r '.notes // ""' "$action_result_file")"

  if [[ "$action_status" == "pass" ]]; then
    echo "[roadmap-non-blockchain-actionable-run] action=$action_id status=pass rc=0"
  else
    echo "[roadmap-non-blockchain-actionable-run] action=$action_id status=fail rc=$action_rc failure_kind=$action_failure_kind"
    if [[ -n "$action_notes" ]]; then
      echo "[roadmap-non-blockchain-actionable-run] action=$action_id notes=$action_notes"
    fi
    echo "[roadmap-non-blockchain-actionable-run] action=$action_id log=$action_log"
  fi

  executed_count=$((executed_count + 1))
  if [[ "$action_status" == "pass" ]]; then
    pass_count=$((pass_count + 1))
  else
    fail_count=$((fail_count + 1))
    final_status="fail"
    if (( final_rc == 0 )); then
      final_rc="$action_rc"
    fi
    if [[ "$action_timed_out" == "true" ]]; then
      timed_out_count=$((timed_out_count + 1))
    fi
  fi

  jq -c '.' "$action_result_file" >>"$actions_tmp"
done

actions_results_json="$(jq -s '.' "$actions_tmp")"
if (( actions_count == 0 )) && [[ "$recommended_only_fail_closed" != "true" ]]; then
  final_status="pass"
  final_rc=0
fi
summary_command_input="./scripts/roadmap_non_blockchain_actionable_run.sh"
for arg in "$@"; do
  summary_command_input="${summary_command_input} $(render_log_token "$arg")"
done
summary_command_redacted="$(redact_command_secrets "$summary_command_input")"

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg command "$summary_command_redacted" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg roadmap_report_md "$roadmap_report_md" \
  --arg roadmap_log "$roadmap_log" \
  --arg recommended_id "$recommended_id" \
  --arg recommended_only_selection_state "$recommended_only_selection_state" \
  --arg recommended_only_selection_reason "$recommended_only_selection_reason" \
  --argjson refresh_manual_validation "$refresh_manual_validation" \
  --argjson refresh_single_machine_readiness "$refresh_single_machine_readiness" \
  --argjson allow_policy_no_go "$allow_policy_no_go" \
  --argjson parallel "$parallel" \
  --argjson recommended_only "$recommended_only" \
  --argjson max_actions "$max_actions" \
  --argjson action_timeout_sec "$action_timeout_sec" \
  --argjson allow_unsafe_shell_commands "$allow_unsafe_shell_commands" \
  --argjson actions_count "$actions_count" \
  --argjson recommended_gate_id_not_found "$recommended_gate_id_not_found" \
  --argjson recommended_only_fail_closed "$recommended_only_fail_closed" \
  --argjson executed_count "$executed_count" \
  --argjson pass_count "$pass_count" \
  --argjson fail_count "$fail_count" \
  --argjson timed_out_count "$timed_out_count" \
  --argjson actions "$actions_results_json" \
  '{
    version: 1,
    schema: { id: "roadmap_non_blockchain_actionable_run_summary", major: 1, minor: 0 },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    command: $command,
    inputs: {
      refresh_manual_validation: ($refresh_manual_validation == 1),
      refresh_single_machine_readiness: ($refresh_single_machine_readiness == 1),
      allow_policy_no_go: ($allow_policy_no_go == 1),
      parallel: ($parallel == 1),
      recommended_only: ($recommended_only == 1),
      max_actions: $max_actions,
      action_timeout_sec: $action_timeout_sec,
      allow_unsafe_shell_commands: ($allow_unsafe_shell_commands == 1)
    },
    roadmap: {
      recommended_gate_id: (if $recommended_id == "" then null else $recommended_id end),
      actions_selected_count: $actions_count,
      recommended_gate_id_not_found: $recommended_gate_id_not_found,
      recommended_only_selection_state: $recommended_only_selection_state,
      recommended_only_selection_reason: (if $recommended_only_selection_reason == "" then null else $recommended_only_selection_reason end),
      recommended_only_fail_closed: $recommended_only_fail_closed
    },
    summary: {
      actions_executed: $executed_count,
      pass: $pass_count,
      fail: $fail_count,
      timed_out: $timed_out_count
    },
    actions: $actions,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      roadmap_summary_json: $roadmap_summary_json,
      roadmap_report_md: $roadmap_report_md,
      roadmap_log: $roadmap_log
    }
  }' >"$summary_json"

echo "[roadmap-non-blockchain-actionable-run] status=$final_status rc=$final_rc selected=$actions_count executed=$executed_count pass=$pass_count fail=$fail_count"
echo "[roadmap-non-blockchain-actionable-run] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
