#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_next_actions_run.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--roadmap-summary-json PATH] \
    [--roadmap-report-md PATH] \
    [--action-timeout-sec N] \
    [--refresh-manual-validation [0|1]] \
    [--refresh-single-machine-readiness [0|1]] \
    [--parallel [0|1]] \
    [--max-actions N] \
    [--profile-default-gate-subject ID] \
    [--allow-profile-default-gate-unreachable [0|1]] \
    [--include-id-prefix PREFIX] \
    [--exclude-id-prefix PREFIX] \
    [--print-summary-json [0|1]]

Purpose:
  Resolve roadmap next_actions from roadmap_progress_report summary JSON,
  apply optional id-prefix filters, and execute selected commands in one
  deterministic wrapper run.

Defaults:
  --action-timeout-sec 0   (0 = no per-action timeout)
  profile_default_gate default timeout sec: 1200
    (env ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_DEFAULT_TIMEOUT_SEC)
  --refresh-manual-validation 0
  --refresh-single-machine-readiness 0
  --parallel 0
  --max-actions 0   (0 = no limit)
  --profile-default-gate-subject ""   (disabled)
  --allow-profile-default-gate-unreachable 0
  --include-id-prefix ""   (disabled)
  --exclude-id-prefix ""   (disabled)
  --print-summary-json 1

Exit behavior:
  - Runs all selected commands (sequential by default, concurrent when --parallel=1).
  - Returns rc=0 only when all selected commands pass (or no actions selected).
  - Returns first failing action command rc otherwise.
  - With --profile-default-gate-subject, profile_default_gate actions append
    --campaign-subject when no subject/anon override flag is already present.
  - With global --action-timeout-sec=0, profile_default_gate gets a default
    per-action timeout from ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_DEFAULT_TIMEOUT_SEC.
  - With --allow-profile-default-gate-unreachable=1, profile_default_gate can
    soft-fail on unreachable endpoint logs or missing invite-subject precondition logs.
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

command_has_profile_subject_or_anon_arg() {
  local command_text="${1:-}"
  [[ "$command_text" =~ (^|[[:space:]])--campaign-subject([[:space:]=]|$) ]] && return 0
  [[ "$command_text" =~ (^|[[:space:]])--subject([[:space:]=]|$) ]] && return 0
  [[ "$command_text" =~ (^|[[:space:]])--campaign-anon-cred([[:space:]=]|$) ]] && return 0
  [[ "$command_text" =~ (^|[[:space:]])--anon-cred([[:space:]=]|$) ]] && return 0
  return 1
}

command_has_profile_subject_placeholder_invite_key() {
  local command_text="${1:-}"
  [[ "$command_text" =~ (^|[[:space:]])--campaign-subject([[:space:]=]+)INVITE_KEY([[:space:]]|$) ]] && return 0
  [[ "$command_text" =~ (^|[[:space:]])--subject([[:space:]=]+)INVITE_KEY([[:space:]]|$) ]] && return 0
  return 1
}

command_replace_profile_subject_placeholder() {
  local command_text="${1:-}"
  local subject_value="${2:-}"
  local escaped_subject
  escaped_subject="$(printf '%q' "$subject_value")"
  command_text="${command_text//--campaign-subject INVITE_KEY/--campaign-subject ${escaped_subject}}"
  command_text="${command_text//--subject INVITE_KEY/--subject ${escaped_subject}}"
  command_text="${command_text//--campaign-subject=INVITE_KEY/--campaign-subject=${escaped_subject}}"
  command_text="${command_text//--subject=INVITE_KEY/--subject=${escaped_subject}}"
  printf '%s' "$command_text"
}

log_has_failure_kind_marker() {
  local log_path="${1:-}"
  local marker="${2:-}"
  [[ -f "$log_path" ]] || return 1
  grep -E -q "failure_kind[=:]\"?${marker}\"?([[:space:],]|$)" "$log_path"
}

need_cmd jq
need_cmd bash
need_cmd date
need_cmd mktemp

reports_dir="${ROADMAP_NEXT_ACTIONS_RUN_REPORTS_DIR:-}"
summary_json="${ROADMAP_NEXT_ACTIONS_RUN_SUMMARY_JSON:-}"
roadmap_summary_json="${ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SUMMARY_JSON:-}"
roadmap_report_md="${ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_REPORT_MD:-}"
refresh_manual_validation="${ROADMAP_NEXT_ACTIONS_RUN_REFRESH_MANUAL_VALIDATION:-0}"
refresh_single_machine_readiness="${ROADMAP_NEXT_ACTIONS_RUN_REFRESH_SINGLE_MACHINE_READINESS:-0}"
parallel="${ROADMAP_NEXT_ACTIONS_RUN_PARALLEL:-0}"
max_actions="${ROADMAP_NEXT_ACTIONS_RUN_MAX_ACTIONS:-0}"
profile_default_gate_subject="${ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_SUBJECT:-}"
allow_profile_default_gate_unreachable="${ROADMAP_NEXT_ACTIONS_RUN_ALLOW_PROFILE_DEFAULT_GATE_UNREACHABLE:-0}"
include_id_prefix="${ROADMAP_NEXT_ACTIONS_RUN_INCLUDE_ID_PREFIX:-}"
exclude_id_prefix="${ROADMAP_NEXT_ACTIONS_RUN_EXCLUDE_ID_PREFIX:-}"
print_summary_json="${ROADMAP_NEXT_ACTIONS_RUN_PRINT_SUMMARY_JSON:-1}"
action_timeout_sec="${ROADMAP_NEXT_ACTIONS_RUN_ACTION_TIMEOUT_SEC:-0}"
profile_default_gate_default_timeout_sec="${ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_DEFAULT_TIMEOUT_SEC:-1200}"

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
    --profile-default-gate-subject)
      require_value_or_die "$1" "${2:-}"
      profile_default_gate_subject="${2:-}"
      shift 2
      ;;
    --allow-profile-default-gate-unreachable)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_profile_default_gate_unreachable="${2:-}"
        shift 2
      else
        allow_profile_default_gate_unreachable="1"
        shift
      fi
      ;;
    --include-id-prefix)
      require_value_or_die "$1" "${2:-}"
      include_id_prefix="${2:-}"
      shift 2
      ;;
    --exclude-id-prefix)
      require_value_or_die "$1" "${2:-}"
      exclude_id_prefix="${2:-}"
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
bool_arg_or_die "--parallel" "$parallel"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--allow-profile-default-gate-unreachable" "$allow_profile_default_gate_unreachable"
int_arg_or_die "--max-actions" "$max_actions"
int_arg_or_die "--action-timeout-sec" "$action_timeout_sec"
int_arg_or_die "ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_DEFAULT_TIMEOUT_SEC" "$profile_default_gate_default_timeout_sec"
if (( profile_default_gate_default_timeout_sec < 1 )); then
  echo "ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_DEFAULT_TIMEOUT_SEC must be >= 1"
  exit 2
fi

if (( action_timeout_sec > 0 )); then
  need_cmd timeout
fi

roadmap_paths_provided="1"
if [[ -z "$roadmap_summary_json" || -z "$roadmap_report_md" ]]; then
  roadmap_paths_provided="0"
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/roadmap_next_actions_run_${run_stamp}"
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
  summary_json="$reports_dir/roadmap_next_actions_run_summary.json"
fi

roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
roadmap_report_md="$(abs_path "$roadmap_report_md")"
summary_json="$(abs_path "$summary_json")"
roadmap_log="$reports_dir/roadmap_progress_report.log"

mkdir -p "$(dirname "$roadmap_summary_json")" "$(dirname "$roadmap_report_md")" "$(dirname "$summary_json")"

roadmap_script="${ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"
ran_roadmap_report="0"

if [[ "$roadmap_paths_provided" != "1" ]]; then
  if [[ ! -x "$roadmap_script" ]]; then
    echo "missing executable roadmap script: $roadmap_script"
    exit 2
  fi
  roadmap_cmd=(
    "$roadmap_script"
    --refresh-manual-validation "$refresh_manual_validation"
    --refresh-single-machine-readiness "$refresh_single_machine_readiness"
    --summary-json "$roadmap_summary_json"
    --report-md "$roadmap_report_md"
    --print-report 0
    --print-summary-json 0
  )
  echo "[roadmap-next-actions-run] stage=roadmap_progress_report status=running"
  set +e
  "${roadmap_cmd[@]}" >"$roadmap_log" 2>&1
  roadmap_rc=$?
  set -e
  if (( roadmap_rc != 0 )); then
    echo "[roadmap-next-actions-run] stage=roadmap_progress_report status=fail rc=$roadmap_rc"
    echo "roadmap_progress_report failed; see: $roadmap_log"
    exit "$roadmap_rc"
  fi
  ran_roadmap_report="1"
  echo "[roadmap-next-actions-run] stage=roadmap_progress_report status=pass rc=0"
fi

if [[ ! -f "$roadmap_summary_json" ]] || ! jq -e . "$roadmap_summary_json" >/dev/null 2>&1; then
  echo "roadmap summary JSON missing or invalid: $roadmap_summary_json"
  exit 3
fi
if [[ ! -f "$roadmap_report_md" ]]; then
  echo "roadmap report missing: $roadmap_report_md"
  exit 3
fi

selected_actions_json="$(jq -c '[ (.next_actions // [])[] | select(((.command // "") | tostring | length) > 0) ]' "$roadmap_summary_json")"
if [[ -n "$include_id_prefix" ]]; then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --arg prefix "$include_id_prefix" '[.[] | select(((.id // "") | startswith($prefix)))]')"
fi
if [[ -n "$exclude_id_prefix" ]]; then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --arg prefix "$exclude_id_prefix" '[.[] | select(((.id // "") | startswith($prefix) | not))]')"
fi
if (( max_actions > 0 )); then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --argjson max_actions "$max_actions" '.[:$max_actions]')"
fi

selected_has_profile_default_gate="$(printf '%s\n' "$selected_actions_json" | jq -r 'any(.[]; (.id // "") == "profile_default_gate")')"
if [[ "$selected_has_profile_default_gate" == "true" && "$action_timeout_sec" == "0" ]]; then
  need_cmd timeout
fi

actions_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"
selected_action_ids_json="$(printf '%s\n' "$selected_actions_json" | jq -c '[.[] | .id // "" | select(length > 0)]')"
selected_action_ids_csv="$(printf '%s\n' "$selected_action_ids_json" | jq -r 'join(",")')"
if [[ -z "$selected_action_ids_csv" ]]; then
  selected_action_ids_csv="none"
fi
echo "[roadmap-next-actions-run] selected_actions=$actions_count parallel=$parallel action_timeout_sec=$action_timeout_sec"
echo "[roadmap-next-actions-run] include_id_prefix=${include_id_prefix:-none} exclude_id_prefix=${exclude_id_prefix:-none}"
echo "[roadmap-next-actions-run] action_ids=$selected_action_ids_csv"
if (( actions_count == 0 )); then
  echo "[roadmap-next-actions-run] no actions selected; writing pass summary"
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
declare -a action_logs
declare -a action_timeout_secs

final_status="pass"
final_rc=0
executed_count=0
pass_count=0
fail_count=0
timed_out_count=0
soft_fail_count=0

for idx in $(seq 0 $(( actions_count - 1 )) 2>/dev/null || true); do
  action_json="$(printf '%s\n' "$selected_actions_json" | jq -c --argjson idx "$idx" '.[$idx]')"
  action_id="$(printf '%s\n' "$action_json" | jq -r '.id // ""')"
  action_label="$(printf '%s\n' "$action_json" | jq -r '.label // ""')"
  action_reason="$(printf '%s\n' "$action_json" | jq -r '.reason // ""')"
  action_command="$(printf '%s\n' "$action_json" | jq -r '.command // ""')"
  action_timeout_sec_effective="$action_timeout_sec"
  if [[ "$action_id" == "profile_default_gate" && "$action_timeout_sec" == "0" ]]; then
    action_timeout_sec_effective="$profile_default_gate_default_timeout_sec"
  fi
  if [[ "$action_id" == "profile_default_gate" \
     && -n "$profile_default_gate_subject" \
     && -n "$action_command" ]]; then
    if command_has_profile_subject_placeholder_invite_key "$action_command"; then
      action_command="$(command_replace_profile_subject_placeholder "$action_command" "$profile_default_gate_subject")"
    elif ! command_has_profile_subject_or_anon_arg "$action_command"; then
      action_command="$action_command --campaign-subject $(printf '%q' "$profile_default_gate_subject")"
    fi
  fi
  action_id_safe="$(sanitize_id "$action_id")"
  action_log="$reports_dir/action_$((idx + 1))_${action_id_safe}.log"
  action_result_file="$actions_results_tmp_dir/action_$((idx + 1))_${action_id_safe}.json"

  action_ids[$idx]="$action_id"
  action_labels[$idx]="$action_label"
  action_reasons[$idx]="$action_reason"
  action_commands[$idx]="$action_command"
  action_logs[$idx]="$action_log"
  action_timeout_secs[$idx]="$action_timeout_sec_effective"
  action_result_files[$idx]="$action_result_file"

  if [[ -z "$action_command" ]]; then
    jq -cn \
      --arg id "$action_id" \
      --arg label "$action_label" \
      --arg reason "$action_reason" \
      --arg command "$action_command" \
      --arg status "fail" \
      --arg notes "missing command" \
      --arg log "$action_log" \
      --arg failure_kind "missing_command" \
      --argjson rc 4 \
      --argjson command_rc 4 \
      --argjson timed_out false \
      --argjson timeout_sec "$action_timeout_sec_effective" \
      '{
        id: $id,
        label: $label,
        reason: $reason,
        command: $command,
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
    echo "[roadmap-next-actions-run] action=$action_id status=running"
    if [[ "$parallel" == "1" ]]; then
      (
        action_status="fail"
        action_rc=125
        command_rc=125
        action_timed_out="false"
        action_failure_kind="command_failed"
        action_notes="command failed"
        set +e
        if (( action_timeout_sec_effective > 0 )); then
          timeout --foreground "${action_timeout_sec_effective}s" bash -lc "$action_command" >"$action_log" 2>&1
        else
          bash -lc "$action_command" >"$action_log" 2>&1
        fi
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
          if (( command_rc == 124 )) && (( action_timeout_sec_effective > 0 )); then
            action_timed_out="true"
            action_failure_kind="timed_out"
            action_notes="action timed out after ${action_timeout_sec_effective}s"
          fi
        fi
        jq -cn \
          --arg id "$action_id" \
          --arg label "$action_label" \
          --arg reason "$action_reason" \
          --arg command "$action_command" \
          --arg status "$action_status" \
          --arg notes "$action_notes" \
          --arg log "$action_log" \
          --arg failure_kind "$action_failure_kind" \
          --argjson rc "$action_rc" \
          --argjson command_rc "$command_rc" \
          --argjson timed_out "$action_timed_out" \
          --argjson timeout_sec "$action_timeout_sec_effective" \
          '{
            id: $id,
            label: $label,
            reason: $reason,
            command: $command,
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
      if (( action_timeout_sec_effective > 0 )); then
        timeout --foreground "${action_timeout_sec_effective}s" bash -lc "$action_command" >"$action_log" 2>&1
      else
        bash -lc "$action_command" >"$action_log" 2>&1
      fi
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
        if (( command_rc == 124 )) && (( action_timeout_sec_effective > 0 )); then
          action_timed_out="true"
          action_failure_kind="timed_out"
          action_notes="action timed out after ${action_timeout_sec_effective}s"
        fi
      fi
      jq -cn \
        --arg id "$action_id" \
        --arg label "$action_label" \
        --arg reason "$action_reason" \
        --arg command "$action_command" \
        --arg status "$action_status" \
        --arg notes "$action_notes" \
        --arg log "$action_log" \
        --arg failure_kind "$action_failure_kind" \
        --argjson rc "$action_rc" \
        --argjson command_rc "$command_rc" \
        --argjson timed_out "$action_timed_out" \
        --argjson timeout_sec "$action_timeout_sec_effective" \
        '{
          id: $id,
          label: $label,
          reason: $reason,
          command: $command,
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
        action_log="${action_logs[$idx]}"
        action_timeout_sec_effective="${action_timeout_secs[$idx]:-$action_timeout_sec}"
        action_result_file="${action_result_files[$idx]}"
        jq -cn \
          --arg id "$action_id" \
          --arg label "$action_label" \
          --arg reason "$action_reason" \
          --arg command "$action_command" \
          --arg status "fail" \
          --arg notes "internal runner error (wait rc=$wait_rc)" \
          --arg log "$action_log" \
          --arg failure_kind "runner_error" \
          --argjson rc "$wait_rc" \
          --argjson command_rc "$wait_rc" \
          --argjson timed_out false \
          --argjson timeout_sec "$action_timeout_sec_effective" \
          '{
            id: $id,
            label: $label,
            reason: $reason,
            command: $command,
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
  action_log="${action_logs[$idx]}"
  action_timeout_sec_effective="${action_timeout_secs[$idx]:-$action_timeout_sec}"

  if [[ ! -s "$action_result_file" ]] || ! jq -e . "$action_result_file" >/dev/null 2>&1; then
    jq -cn \
      --arg id "$action_id" \
      --arg label "$action_label" \
      --arg reason "$action_reason" \
      --arg command "$action_command" \
      --arg status "fail" \
      --arg notes "internal runner error (missing or invalid action result)" \
      --arg log "$action_log" \
      --arg failure_kind "runner_error" \
      --argjson rc 125 \
      --argjson command_rc 125 \
      --argjson timed_out false \
      --argjson timeout_sec "$action_timeout_sec_effective" \
      '{
        id: $id,
        label: $label,
        reason: $reason,
        command: $command,
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
  action_soft_failed="false"

  if [[ "$allow_profile_default_gate_unreachable" == "1" \
     && "$action_id" == "profile_default_gate" \
     && "$action_status" != "pass" ]]; then
    if log_has_failure_kind_marker "$action_log" "missing_invite_subject_precondition"; then
      action_status="pass"
      action_rc=0
      action_failure_kind="soft_failed_profile_default_gate_precondition"
      action_notes="soft-failed profile_default_gate missing invite-subject precondition (allow flag enabled)"
      action_soft_failed="true"
    elif log_has_failure_kind_marker "$action_log" "unreachable_directory_endpoint"; then
      action_status="pass"
      action_rc=0
      action_failure_kind="soft_failed_unreachable_profile_default_gate"
      action_notes="soft-failed unreachable profile_default_gate (allow flag enabled)"
      action_soft_failed="true"
    elif [[ -f "$action_log" ]] && grep -E -q 'profile-default-gate-run failed:[[:space:]]*missing invite key subject|provide[[:space:]]+--campaign-subject/--subject' "$action_log"; then
      action_status="pass"
      action_rc=0
      action_failure_kind="soft_failed_profile_default_gate_precondition"
      action_notes="soft-failed profile_default_gate missing invite-subject precondition (allow flag enabled)"
      action_soft_failed="true"
    elif [[ -f "$action_log" ]] && grep -E -q 'profile-default-gate-run failed:[[:space:]]*unreachable directory endpoint|[[:space:]]wait-fail[[:space:]]' "$action_log"; then
      action_status="pass"
      action_rc=0
      action_failure_kind="soft_failed_unreachable_profile_default_gate"
      action_notes="soft-failed unreachable profile_default_gate (allow flag enabled)"
      action_soft_failed="true"
    fi
  fi

  if [[ "$action_status" == "pass" && "$action_soft_failed" != "true" ]]; then
    echo "[roadmap-next-actions-run] action=$action_id status=pass rc=0"
  elif [[ "$action_status" == "pass" && "$action_soft_failed" == "true" ]]; then
    echo "[roadmap-next-actions-run] action=$action_id status=soft-fail rc=0 failure_kind=$action_failure_kind"
    echo "[roadmap-next-actions-run] action=$action_id notes=$action_notes"
    echo "[roadmap-next-actions-run] action=$action_id log=$action_log"
  else
    echo "[roadmap-next-actions-run] action=$action_id status=fail rc=$action_rc failure_kind=$action_failure_kind"
    if [[ -n "$action_notes" ]]; then
      echo "[roadmap-next-actions-run] action=$action_id notes=$action_notes"
    fi
    echo "[roadmap-next-actions-run] action=$action_id log=$action_log"
  fi

  executed_count=$((executed_count + 1))
  if [[ "$action_status" == "pass" ]]; then
    pass_count=$((pass_count + 1))
    if [[ "$action_soft_failed" == "true" ]]; then
      soft_fail_count=$((soft_fail_count + 1))
    fi
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

  jq -c \
    --arg status "$action_status" \
    --arg failure_kind "$action_failure_kind" \
    --arg notes "$action_notes" \
    --argjson rc "$action_rc" \
    --argjson soft_failed "$action_soft_failed" \
    '.status = $status
     | .rc = $rc
     | .failure_kind = $failure_kind
     | .notes = (if $notes == "" then null else $notes end)
     | .soft_failed = $soft_failed' \
    "$action_result_file" >>"$actions_tmp"
done

actions_results_json="$(jq -s '.' "$actions_tmp")"
if (( actions_count == 0 )); then
  final_status="pass"
  final_rc=0
fi

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg command "./scripts/roadmap_next_actions_run.sh $*" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg roadmap_report_md "$roadmap_report_md" \
  --arg roadmap_log "$roadmap_log" \
  --arg include_id_prefix "$include_id_prefix" \
  --arg exclude_id_prefix "$exclude_id_prefix" \
  --argjson ran_roadmap_report "$ran_roadmap_report" \
  --argjson refresh_manual_validation "$refresh_manual_validation" \
  --argjson refresh_single_machine_readiness "$refresh_single_machine_readiness" \
  --argjson parallel "$parallel" \
  --argjson max_actions "$max_actions" \
  --arg profile_default_gate_subject "$profile_default_gate_subject" \
  --argjson allow_profile_default_gate_unreachable "$allow_profile_default_gate_unreachable" \
  --argjson profile_default_gate_default_timeout_sec "$profile_default_gate_default_timeout_sec" \
  --argjson action_timeout_sec "$action_timeout_sec" \
  --argjson actions_count "$actions_count" \
  --argjson selected_action_ids "$selected_action_ids_json" \
  --argjson executed_count "$executed_count" \
  --argjson pass_count "$pass_count" \
  --argjson fail_count "$fail_count" \
  --argjson timed_out_count "$timed_out_count" \
  --argjson soft_fail_count "$soft_fail_count" \
  --argjson actions "$actions_results_json" \
  '{
    version: 1,
    schema: { id: "roadmap_next_actions_run_summary", major: 1, minor: 0 },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    command: $command,
    inputs: {
      refresh_manual_validation: ($refresh_manual_validation == 1),
      refresh_single_machine_readiness: ($refresh_single_machine_readiness == 1),
      parallel: ($parallel == 1),
      max_actions: $max_actions,
      action_timeout_sec: $action_timeout_sec,
      profile_default_gate_default_timeout_sec: $profile_default_gate_default_timeout_sec,
      profile_default_gate_subject: (if $profile_default_gate_subject == "" then null else $profile_default_gate_subject end),
      allow_profile_default_gate_unreachable: ($allow_profile_default_gate_unreachable == 1),
      include_id_prefix: (if $include_id_prefix == "" then null else $include_id_prefix end),
      exclude_id_prefix: (if $exclude_id_prefix == "" then null else $exclude_id_prefix end)
    },
    roadmap: {
      generated_this_run: ($ran_roadmap_report == 1),
      actions_selected_count: $actions_count,
      selected_action_ids: $selected_action_ids
    },
    summary: {
      actions_executed: $executed_count,
      pass: $pass_count,
      fail: $fail_count,
      timed_out: $timed_out_count,
      soft_failed: $soft_fail_count
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

echo "[roadmap-next-actions-run] status=$final_status rc=$final_rc selected=$actions_count executed=$executed_count pass=$pass_count fail=$fail_count"
echo "[roadmap-next-actions-run] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
