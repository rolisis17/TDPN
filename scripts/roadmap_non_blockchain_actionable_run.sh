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
    [--refresh-manual-validation [0|1]] \
    [--refresh-single-machine-readiness [0|1]] \
    [--allow-policy-no-go [0|1]] \
    [--recommended-only [0|1]] \
    [--max-actions N] \
    [--print-summary-json [0|1]]

Purpose:
  Resolve the non-blockchain actionable command list from roadmap_progress_report,
  then execute those no-sudo/no-GitHub commands in one deterministic wrapper run.

Defaults:
  --action-timeout-sec 0   (0 = no per-action timeout)
  --refresh-manual-validation 0
  --refresh-single-machine-readiness 0
  --allow-policy-no-go 0
  --recommended-only 0
  --max-actions 0   (0 = no limit)
  --print-summary-json 1

Exit behavior:
  - Runs all selected commands sequentially.
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
recommended_only="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_RECOMMENDED_ONLY:-0}"
max_actions="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_MAX_ACTIONS:-0}"
print_summary_json="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_PRINT_SUMMARY_JSON:-1}"
action_timeout_sec="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ACTION_TIMEOUT_SEC:-0}"

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
    --allow-policy-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_policy_no_go="${2:-}"
        shift 2
      else
        allow_policy_no_go="1"
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
bool_arg_or_die "--recommended-only" "$recommended_only"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
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
if [[ "$recommended_only" == "1" && -n "$recommended_id" ]]; then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --arg rid "$recommended_id" '[.[] | select((.id // "") == $rid)]')"
fi
if (( max_actions > 0 )); then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --argjson max_actions "$max_actions" '.[:$max_actions]')"
fi

actions_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"
actions_tmp="$(mktemp)"
trap 'rm -f "$actions_tmp"' EXIT
: >"$actions_tmp"

final_status="pass"
final_rc=0
executed_count=0
pass_count=0
fail_count=0
timed_out_count=0

for idx in $(seq 0 $(( actions_count - 1 )) 2>/dev/null || true); do
  action_json="$(printf '%s\n' "$selected_actions_json" | jq -c --argjson idx "$idx" '.[$idx]')"
  action_id="$(printf '%s\n' "$action_json" | jq -r '.id // ""')"
  action_label="$(printf '%s\n' "$action_json" | jq -r '.label // ""')"
  action_reason="$(printf '%s\n' "$action_json" | jq -r '.reason // ""')"
  action_command="$(printf '%s\n' "$action_json" | jq -r '.command // ""')"
  action_allow_policy_no_go_applied="false"
  action_id_safe="$(sanitize_id "$action_id")"
  action_log="$reports_dir/action_$((idx + 1))_${action_id_safe}.log"
  action_timed_out="false"
  action_failure_kind="none"

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

  if [[ -z "$action_command" ]]; then
    action_status="fail"
    action_rc=4
    command_rc=4
    action_notes="missing command"
    action_failure_kind="missing_command"
  else
    echo "[roadmap-non-blockchain-actionable-run] action=$action_id status=running"
    set +e
    if (( action_timeout_sec > 0 )); then
      timeout --foreground "${action_timeout_sec}s" bash -lc "$action_command" >"$action_log" 2>&1
    else
      bash -lc "$action_command" >"$action_log" 2>&1
    fi
    command_rc=$?
    set -e
    if (( command_rc == 0 )); then
      action_status="pass"
      action_rc=0
      action_notes=""
      echo "[roadmap-non-blockchain-actionable-run] action=$action_id status=pass rc=0"
    else
      action_status="fail"
      action_rc="$command_rc"
      if (( command_rc == 124 )) && (( action_timeout_sec > 0 )); then
        action_timed_out="true"
        action_failure_kind="timed_out"
        action_notes="action timed out after ${action_timeout_sec}s"
      else
        action_failure_kind="command_failed"
        action_notes="command failed"
      fi
      echo "[roadmap-non-blockchain-actionable-run] action=$action_id status=fail rc=$command_rc"
    fi
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
    }' >>"$actions_tmp"
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
  --arg command "./scripts/roadmap_non_blockchain_actionable_run.sh $*" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg roadmap_report_md "$roadmap_report_md" \
  --arg roadmap_log "$roadmap_log" \
  --arg recommended_id "$recommended_id" \
  --argjson refresh_manual_validation "$refresh_manual_validation" \
  --argjson refresh_single_machine_readiness "$refresh_single_machine_readiness" \
  --argjson allow_policy_no_go "$allow_policy_no_go" \
  --argjson recommended_only "$recommended_only" \
  --argjson max_actions "$max_actions" \
  --argjson action_timeout_sec "$action_timeout_sec" \
  --argjson actions_count "$actions_count" \
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
      recommended_only: ($recommended_only == 1),
      max_actions: $max_actions,
      action_timeout_sec: $action_timeout_sec
    },
    roadmap: {
      recommended_gate_id: (if $recommended_id == "" then null else $recommended_id end),
      actions_selected_count: $actions_count
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
