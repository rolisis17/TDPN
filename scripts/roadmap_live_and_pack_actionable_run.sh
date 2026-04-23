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
    2) roadmap_evidence_pack_actionable_run.sh

Defaults:
  --action-timeout-sec 0   (0 = no per-action timeout)
  --allow-unsafe-shell-commands 0
  --refresh-manual-validation 0
  --refresh-single-machine-readiness 0
  --scope profile-default
  --parallel 0
  --max-actions 0   (0 = no limit)
  --continue-on-live-fail 0
  --print-summary-json 1

Exit behavior:
  - Runs live-evidence stage first, then evidence-pack stage.
  - With --continue-on-live-fail=0 (default), evidence-pack is skipped when live fails.
  - With --continue-on-live-fail=1, evidence-pack still runs even when live fails.
  - Final rc is first failing stage rc (live first, then evidence-pack), else 0.
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

need_cmd jq
need_cmd bash
need_cmd date
need_cmd mktemp

reports_dir="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_REPORTS_DIR:-}"
summary_json="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_SUMMARY_JSON:-}"
roadmap_summary_json="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ROADMAP_SUMMARY_JSON:-}"
roadmap_report_md="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ROADMAP_REPORT_MD:-}"
refresh_manual_validation="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_REFRESH_MANUAL_VALIDATION:-0}"
refresh_single_machine_readiness="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_REFRESH_SINGLE_MACHINE_READINESS:-0}"
parallel="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PARALLEL:-0}"
max_actions="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_MAX_ACTIONS:-0}"
print_summary_json="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PRINT_SUMMARY_JSON:-1}"
action_timeout_sec="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ACTION_TIMEOUT_SEC:-0}"
allow_unsafe_shell_commands="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ALLOW_UNSAFE_SHELL_COMMANDS:-0}"
continue_on_live_fail="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_CONTINUE_ON_LIVE_FAIL:-0}"
scope="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_SCOPE:-${ROADMAP_LIVE_AND_PACK_ACTIONABLE_SCOPE:-profile-default}}"
original_args=("$@")

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
int_arg_or_die "--max-actions" "$max_actions"
int_arg_or_die "--action-timeout-sec" "$action_timeout_sec"
scope_arg_or_die "$scope"

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

live_script="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT:-$ROOT_DIR/scripts/roadmap_live_evidence_actionable_run.sh}"
pack_script="${ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT:-$ROOT_DIR/scripts/roadmap_evidence_pack_actionable_run.sh}"

if [[ ! -f "$live_script" ]]; then
  echo "missing live-evidence script: $live_script"
  exit 2
fi
if [[ ! -r "$live_script" ]]; then
  echo "live-evidence script is not readable: $live_script"
  exit 2
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

pack_status="skipped"
pack_skip_reason=""
pack_rc_num=0
pack_process_rc_num=0
pack_rc_json="null"
pack_process_rc_json="null"
pack_summary_valid=0
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
if [[ "$roadmap_paths_provided" == "1" ]]; then
  live_cmd+=(--roadmap-summary-json "$roadmap_summary_json" --roadmap-report-md "$roadmap_report_md")
fi

echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence status=running"
set +e
"${live_cmd[@]}" >"$live_log" 2>&1
live_process_rc=$?
set -e

if [[ -f "$live_summary_json" ]] && jq -e . "$live_summary_json" >/dev/null 2>&1; then
  live_summary_valid=1
  live_status="$(jq -r '.status // ""' "$live_summary_json")"
  live_rc="$(jq -r '.rc // 125' "$live_summary_json")"
  if [[ -z "$live_status" ]]; then
    if (( live_rc == 0 )); then
      live_status="pass"
    else
      live_status="fail"
    fi
  fi
  if (( live_process_rc != 0 && live_rc == 0 )); then
    live_rc="$live_process_rc"
    live_status="fail"
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
else
  live_summary_valid=0
  live_rc="$live_process_rc"
  if (( live_rc == 0 )); then
    live_status="pass"
  else
    live_status="fail"
  fi
fi

echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence status=$live_status rc=$live_rc"
echo "[roadmap-live-and-pack-actionable-run] stage=live_evidence summary_json=$live_summary_json log=$live_log"

run_pack_stage=1
if (( live_rc != 0 )) && [[ "$continue_on_live_fail" != "1" ]]; then
  run_pack_stage=0
  pack_status="skipped"
  pack_skip_reason="live_step_failed_fail_closed"
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
  )

  if [[ -n "${shared_roadmap_summary_json:-}" && -n "${shared_roadmap_report_md:-}" ]]; then
    pack_cmd+=(--roadmap-summary-json "$shared_roadmap_summary_json" --roadmap-report-md "$shared_roadmap_report_md")
  fi

  echo "[roadmap-live-and-pack-actionable-run] stage=evidence_pack status=running"
  set +e
  "${pack_cmd[@]}" >"$pack_log" 2>&1
  pack_process_rc_num=$?
  set -e

  if [[ -f "$pack_summary_json" ]] && jq -e . "$pack_summary_json" >/dev/null 2>&1; then
    pack_summary_valid=1
    pack_status="$(jq -r '.status // ""' "$pack_summary_json")"
    pack_rc_num="$(jq -r '.rc // 125' "$pack_summary_json")"
    if [[ -z "$pack_status" ]]; then
      if (( pack_rc_num == 0 )); then
        pack_status="pass"
      else
        pack_status="fail"
      fi
    fi
    if (( pack_process_rc_num != 0 && pack_rc_num == 0 )); then
      pack_rc_num="$pack_process_rc_num"
      pack_status="fail"
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
  else
    pack_summary_valid=0
    pack_rc_num="$pack_process_rc_num"
    if (( pack_rc_num == 0 )); then
      pack_status="pass"
    else
      pack_status="fail"
    fi
  fi

  pack_rc_json="$pack_rc_num"
  pack_process_rc_json="$pack_process_rc_num"
  echo "[roadmap-live-and-pack-actionable-run] stage=evidence_pack status=$pack_status rc=$pack_rc_num"
  echo "[roadmap-live-and-pack-actionable-run] stage=evidence_pack summary_json=$pack_summary_json log=$pack_log"
else
  echo "[roadmap-live-and-pack-actionable-run] stage=evidence_pack status=skipped reason=$pack_skip_reason"
fi

final_rc=0
if (( live_rc != 0 )); then
  final_rc="$live_rc"
fi
if [[ "$pack_status" != "skipped" ]] && (( pack_rc_num != 0 )) && (( final_rc == 0 )); then
  final_rc="$pack_rc_num"
fi

if (( final_rc == 0 )); then
  final_status="pass"
else
  final_status="fail"
fi

steps_executed=1
steps_skipped=1
steps_pass=0
steps_fail=0
if [[ "$live_status" == "pass" ]]; then
  steps_pass=$((steps_pass + 1))
else
  steps_fail=$((steps_fail + 1))
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
  --arg command "$summary_command_redacted" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg live_reports_dir "$live_reports_dir" \
  --arg live_summary_json "$live_summary_json" \
  --arg live_log "$live_log" \
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
  --argjson live_selected_actions_count "$live_selected_actions_count_json" \
  --argjson live_selected_action_ids "$live_selected_action_ids_json" \
  --argjson live_actions_executed "$live_actions_executed_json" \
  --argjson live_pass "$live_pass_json" \
  --argjson live_fail "$live_fail_json" \
  --argjson live_timed_out "$live_timed_out_json" \
  --argjson live_soft_failed "$live_soft_failed_json" \
  --arg pack_status "$pack_status" \
  --argjson pack_rc "$pack_rc_json" \
  --argjson pack_process_rc "$pack_process_rc_json" \
  --argjson pack_summary_valid "$pack_summary_valid" \
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
    command: $command,
    inputs: {
      refresh_manual_validation: ($refresh_manual_validation == 1),
      refresh_single_machine_readiness: ($refresh_single_machine_readiness == 1),
      parallel: ($parallel == 1),
      scope: $scope,
      max_actions: $max_actions,
      action_timeout_sec: $action_timeout_sec,
      allow_unsafe_shell_commands: ($allow_unsafe_shell_commands == 1),
      continue_on_live_fail: ($continue_on_live_fail == 1)
    },
    steps: {
      live_evidence: {
        status: $live_status,
        rc: $live_rc,
        process_rc: $live_process_rc,
        summary_valid: ($live_summary_valid == 1),
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
      evidence_pack: {
        status: $pack_status,
        rc: $pack_rc,
        process_rc: $pack_process_rc,
        summary_valid: ($pack_summary_valid == 1),
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
      steps_total: 2,
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
      evidence_pack_summary_json: $pack_summary_json,
      evidence_pack_log: $pack_log,
      roadmap_summary_json: (if $shared_roadmap_summary_json == "" then null else $shared_roadmap_summary_json end),
      roadmap_report_md: (if $shared_roadmap_report_md == "" then null else $shared_roadmap_report_md end)
    }
  }' >"$summary_tmp"

mv "$summary_tmp" "$summary_json"

echo "[roadmap-live-and-pack-actionable-run] status=$final_status rc=$final_rc scope=$scope continue_on_live_fail=$continue_on_live_fail"
echo "[roadmap-live-and-pack-actionable-run] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
