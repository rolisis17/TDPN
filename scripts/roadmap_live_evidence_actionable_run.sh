#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_live_evidence_actionable_run.sh \
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
    [--print-derived-evidence-pack-ids [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Resolve roadmap next_actions (via roadmap_progress_report when needed), then
  execute only live-cycle action ids:
    - profile_default_gate
    - runtime_actuation_promotion
    - profile_compare_multi_vm_stability
    - profile_compare_multi_vm_stability_promotion
  Execution is delegated to roadmap_next_actions_run to preserve pass/fail and
  exit-code aggregation semantics.

Defaults:
  --action-timeout-sec 0   (0 = no per-action timeout)
  --allow-unsafe-shell-commands 0
  --refresh-manual-validation 0
  --refresh-single-machine-readiness 0
  --scope profile-default
  --parallel 0
  --max-actions 0   (0 = no limit)
  --print-derived-evidence-pack-ids 0
  --print-summary-json 1

Exit behavior:
  - Mirrors roadmap_next_actions_run action pass/fail aggregation semantics.
  - Returns the delegated runner rc when execution starts.
  - Returns roadmap_progress_report rc if roadmap resolution fails first.
USAGE
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

render_invocation_command() {
  local script_path="$1"
  shift || true
  local rendered="$script_path"
  local token
  for token in "$@"; do
    rendered+=" $(printf '%q' "$token")"
  done
  printf '%s' "$rendered"
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

need_cmd jq
need_cmd bash
need_cmd date
need_cmd mktemp

reports_dir="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_REPORTS_DIR:-}"
summary_json="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_SUMMARY_JSON:-}"
roadmap_summary_json="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_ROADMAP_SUMMARY_JSON:-}"
roadmap_report_md="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_ROADMAP_REPORT_MD:-}"
refresh_manual_validation="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_REFRESH_MANUAL_VALIDATION:-0}"
refresh_single_machine_readiness="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_REFRESH_SINGLE_MACHINE_READINESS:-0}"
parallel="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_PARALLEL:-0}"
max_actions="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_MAX_ACTIONS:-0}"
print_derived_evidence_pack_ids="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_PRINT_DERIVED_EVIDENCE_PACK_IDS:-0}"
print_summary_json="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_PRINT_SUMMARY_JSON:-1}"
action_timeout_sec="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_ACTION_TIMEOUT_SEC:-0}"
allow_unsafe_shell_commands="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_ALLOW_UNSAFE_SHELL_COMMANDS:-0}"
scope="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_SCOPE:-${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_SCOPE:-profile-default}}"

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
    --print-derived-evidence-pack-ids)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_derived_evidence_pack_ids="${2:-}"
        shift 2
      else
        print_derived_evidence_pack_ids="1"
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
bool_arg_or_die "--print-derived-evidence-pack-ids" "$print_derived_evidence_pack_ids"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--allow-unsafe-shell-commands" "$allow_unsafe_shell_commands"
int_arg_or_die "--max-actions" "$max_actions"
int_arg_or_die "--action-timeout-sec" "$action_timeout_sec"
scope_arg_or_die "$scope"

roadmap_paths_provided="1"
if [[ -z "$roadmap_summary_json" || -z "$roadmap_report_md" ]]; then
  roadmap_paths_provided="0"
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/roadmap_live_evidence_actionable_run_${run_stamp}"
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
  summary_json="$reports_dir/roadmap_live_evidence_actionable_run_summary.json"
fi

roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
roadmap_report_md="$(abs_path "$roadmap_report_md")"
summary_json="$(abs_path "$summary_json")"
roadmap_log="$reports_dir/roadmap_progress_report.log"

mkdir -p "$(dirname "$roadmap_summary_json")" "$(dirname "$roadmap_report_md")" "$(dirname "$summary_json")"

roadmap_script="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_ROADMAP_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"
next_actions_script="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_NEXT_ACTIONS_SCRIPT:-$ROOT_DIR/scripts/roadmap_next_actions_run.sh}"
target_ids_json='[
  "profile_default_gate",
  "runtime_actuation_promotion",
  "profile_compare_multi_vm_stability",
  "profile_compare_multi_vm_stability_promotion"
]'
ran_roadmap_report="0"

if [[ "$roadmap_paths_provided" != "1" ]]; then
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
  echo "[roadmap-live-evidence-actionable-run] stage=roadmap_progress_report status=running"
  set +e
  "${roadmap_cmd[@]}" >"$roadmap_log" 2>&1
  roadmap_rc=$?
  set -e
  if (( roadmap_rc != 0 )); then
    echo "[roadmap-live-evidence-actionable-run] stage=roadmap_progress_report status=fail rc=$roadmap_rc"
    echo "roadmap_progress_report failed; see: $roadmap_log"
    exit "$roadmap_rc"
  fi
  ran_roadmap_report="1"
  echo "[roadmap-live-evidence-actionable-run] stage=roadmap_progress_report status=pass rc=0"
fi

if [[ ! -f "$roadmap_summary_json" ]] || ! jq -e . "$roadmap_summary_json" >/dev/null 2>&1; then
  echo "roadmap summary JSON missing or invalid: $roadmap_summary_json"
  exit 3
fi
if [[ ! -f "$roadmap_report_md" ]]; then
  echo "roadmap report missing: $roadmap_report_md"
  exit 3
fi
if [[ ! -f "$next_actions_script" ]]; then
  echo "missing next-actions script: $next_actions_script"
  exit 2
fi
if [[ ! -r "$next_actions_script" ]]; then
  echo "next-actions script is not readable: $next_actions_script"
  exit 2
fi

source_actions_with_command_count="$(jq -r '[ (.next_actions // [])[] | select(((.command // "") | tostring | length) > 0) ] | length' "$roadmap_summary_json")"
target_match_actions_json="$(jq -c --argjson target_ids "$target_ids_json" '[ (.next_actions // [])[] | select((.id // "") as $id | ($target_ids | index($id)) != null) | select(((.command // "") | tostring | length) > 0) ]' "$roadmap_summary_json")"
target_match_count="$(printf '%s\n' "$target_match_actions_json" | jq -r 'length')"
target_match_action_ids_json="$(printf '%s\n' "$target_match_actions_json" | jq -c '[.[] | .id // "" | select(length > 0)]')"
target_match_unique_actions_json="$(printf '%s\n' "$target_match_actions_json" | jq -c 'reduce .[] as $action ({ ids: [], actions: [] }; (($action.id // "") | tostring) as $id | if ($id | length) == 0 or ((.ids | index($id)) != null) then . else .ids += [$id] | .actions += [$action] end) | .actions')"
target_match_unique_count="$(printf '%s\n' "$target_match_unique_actions_json" | jq -r 'length')"
target_match_unique_action_ids_json="$(printf '%s\n' "$target_match_unique_actions_json" | jq -c '[.[] | .id // "" | select(length > 0)]')"

scope_target_action_ids_json='[]'
resolved_scope="$scope"
scope_inference_reason="explicit scope: $scope"
case "$scope" in
  profile-default)
    scope_target_action_ids_json='["profile_default_gate"]'
    ;;
  runtime-actuation)
    scope_target_action_ids_json='["runtime_actuation_promotion"]'
    ;;
  multi-vm)
    scope_target_action_ids_json='["profile_compare_multi_vm_stability","profile_compare_multi_vm_stability_promotion"]'
    ;;
  all)
    scope_target_action_ids_json="$target_ids_json"
    scope_inference_reason="explicit scope: all (include every live-evidence family action)"
    ;;
  auto)
    auto_scope_target_action_ids_json="$(printf '%s\n' "$target_match_action_ids_json" | jq -c '
      [
        (if index("profile_default_gate") != null then "profile_default_gate" else empty end),
        (if index("runtime_actuation_promotion") != null then "runtime_actuation_promotion" else empty end),
        (if index("profile_compare_multi_vm_stability") != null then "profile_compare_multi_vm_stability" else empty end),
        (if index("profile_compare_multi_vm_stability_promotion") != null then "profile_compare_multi_vm_stability_promotion" else empty end)
      ]'
    )"
    auto_scope_family_labels_json="$(printf '%s\n' "$auto_scope_target_action_ids_json" | jq -c '
      map(
        if . == "profile_default_gate" then "profile-default"
        elif . == "runtime_actuation_promotion" then "runtime-actuation"
        elif . == "profile_compare_multi_vm_stability" or . == "profile_compare_multi_vm_stability_promotion" then "multi-vm"
        else empty
        end
      )
      | reduce .[] as $family ({ seen: [], ordered: [] };
          if (.seen | index($family)) != null then .
          else .seen += [$family] | .ordered += [$family]
          end
        )
      | .ordered'
    )"
    auto_scope_family_count="$(printf '%s\n' "$auto_scope_family_labels_json" | jq -r 'length')"
    auto_scope_family_labels_csv="$(printf '%s\n' "$auto_scope_family_labels_json" | jq -r 'join(",")')"
    if (( auto_scope_family_count == 0 )); then
      resolved_scope="none"
      scope_target_action_ids_json='[]'
      scope_inference_reason="auto: no recognized live-evidence families are pending in roadmap next_actions"
    elif (( auto_scope_family_count == 1 )); then
      resolved_scope="$(printf '%s\n' "$auto_scope_family_labels_json" | jq -r '.[0]')"
      scope_target_action_ids_json="$auto_scope_target_action_ids_json"
      scope_inference_reason="auto: inferred single pending family ($auto_scope_family_labels_csv) from roadmap next_actions"
    else
      resolved_scope="all"
      scope_target_action_ids_json="$auto_scope_target_action_ids_json"
      scope_inference_reason="auto: inferred mixed pending families ($auto_scope_family_labels_csv) from roadmap next_actions"
    fi
    ;;
esac

scope_match_actions_json="$(printf '%s\n' "$target_match_actions_json" | jq -c --argjson target_ids "$scope_target_action_ids_json" '[ .[] | select((.id // "") as $id | ($target_ids | index($id)) != null) ]')"
scope_match_count="$(printf '%s\n' "$scope_match_actions_json" | jq -r 'length')"
scope_match_action_ids_json="$(printf '%s\n' "$scope_match_actions_json" | jq -c '[.[] | .id // "" | select(length > 0)]')"
scope_match_unique_actions_json="$(printf '%s\n' "$scope_match_actions_json" | jq -c 'reduce .[] as $action ({ ids: [], actions: [] }; (($action.id // "") | tostring) as $id | if ($id | length) == 0 or ((.ids | index($id)) != null) then . else .ids += [$id] | .actions += [$action] end) | .actions')"
scope_match_unique_count="$(printf '%s\n' "$scope_match_unique_actions_json" | jq -r 'length')"
scope_match_unique_action_ids_json="$(printf '%s\n' "$scope_match_unique_actions_json" | jq -c '[.[] | .id // "" | select(length > 0)]')"

derived_evidence_pack_map_json="$(jq -nc --argjson selected_ids "$scope_match_unique_action_ids_json" '
  def derive_evidence_pack_id($id):
    if $id == "profile_default_gate" then "profile_default_gate_evidence_pack"
    elif $id == "runtime_actuation_promotion" then "runtime_actuation_promotion_evidence_pack"
    elif $id == "profile_compare_multi_vm_stability" then "profile_compare_multi_vm_stability_promotion_evidence_pack"
    elif $id == "profile_compare_multi_vm_stability_promotion" then "profile_compare_multi_vm_stability_promotion_evidence_pack"
    else ($id + "_evidence_pack")
    end;
  [ $selected_ids[] as $id | { live_action_id: $id, evidence_pack_id: derive_evidence_pack_id($id) } ]
')"
derived_evidence_pack_ids_json="$(printf '%s\n' "$derived_evidence_pack_map_json" | jq -c 'reduce .[] as $item ({ ids: [], ordered: [] }; ($item.evidence_pack_id // "" | tostring) as $id | if ($id | length) == 0 or ((.ids | index($id)) != null) then . else .ids += [$id] | .ordered += [$id] end) | .ordered')"
derived_evidence_pack_count="$(printf '%s\n' "$derived_evidence_pack_ids_json" | jq -r 'length')"
roadmap_snapshot_action_ids_json="$(jq -c '[ (.next_actions // [])[] | .id // "" | tostring | select(length > 0) ]' "$roadmap_summary_json")"
roadmap_snapshot_unique_action_ids_json="$(printf '%s\n' "$roadmap_snapshot_action_ids_json" | jq -c 'reduce .[] as $id ({ ids: [], ordered: [] }; if (.ids | index($id)) != null then . else .ids += [$id] | .ordered += [$id] end) | .ordered')"
derived_evidence_pack_missing_ids_json="$(jq -nc --argjson derived_ids "$derived_evidence_pack_ids_json" --argjson snapshot_ids "$roadmap_snapshot_unique_action_ids_json" '[ $derived_ids[] as $id | select(($snapshot_ids | index($id)) == null) | $id ]')"
derived_evidence_pack_missing_count="$(printf '%s\n' "$derived_evidence_pack_missing_ids_json" | jq -r 'length')"
target_match_action_ids_csv="$(printf '%s\n' "$target_match_action_ids_json" | jq -r 'join(",")')"
if [[ -z "$target_match_action_ids_csv" ]]; then
  target_match_action_ids_csv="none"
fi
target_match_unique_action_ids_csv="$(printf '%s\n' "$target_match_unique_action_ids_json" | jq -r 'join(",")')"
if [[ -z "$target_match_unique_action_ids_csv" ]]; then
  target_match_unique_action_ids_csv="none"
fi
scope_match_action_ids_csv="$(printf '%s\n' "$scope_match_action_ids_json" | jq -r 'join(",")')"
if [[ -z "$scope_match_action_ids_csv" ]]; then
  scope_match_action_ids_csv="none"
fi
scope_match_unique_action_ids_csv="$(printf '%s\n' "$scope_match_unique_action_ids_json" | jq -r 'join(",")')"
if [[ -z "$scope_match_unique_action_ids_csv" ]]; then
  scope_match_unique_action_ids_csv="none"
fi
derived_evidence_pack_ids_csv="$(printf '%s\n' "$derived_evidence_pack_ids_json" | jq -r 'join(",")')"
if [[ -z "$derived_evidence_pack_ids_csv" ]]; then
  derived_evidence_pack_ids_csv="none"
fi
derived_evidence_pack_missing_ids_csv="$(printf '%s\n' "$derived_evidence_pack_missing_ids_json" | jq -r 'join(",")')"
if [[ -z "$derived_evidence_pack_missing_ids_csv" ]]; then
  derived_evidence_pack_missing_ids_csv="none"
fi
echo "[roadmap-live-evidence-actionable-run] scope=$scope resolved_scope=$resolved_scope source_actions_with_command=$source_actions_with_command_count target_matches=$target_match_count target_unique_matches=$target_match_unique_count scope_matches=$scope_match_count scope_unique_matches=$scope_match_unique_count"
echo "[roadmap-live-evidence-actionable-run] scope_inference_reason=$scope_inference_reason"
echo "[roadmap-live-evidence-actionable-run] target_match_action_ids=$target_match_action_ids_csv"
echo "[roadmap-live-evidence-actionable-run] target_match_unique_action_ids=$target_match_unique_action_ids_csv"
echo "[roadmap-live-evidence-actionable-run] scope_match_action_ids=$scope_match_action_ids_csv"
echo "[roadmap-live-evidence-actionable-run] scope_match_unique_action_ids=$scope_match_unique_action_ids_csv"
echo "[roadmap-live-evidence-actionable-run] derived_evidence_pack_count=$derived_evidence_pack_count derived_evidence_pack_ids=$derived_evidence_pack_ids_csv"
echo "[roadmap-live-evidence-actionable-run] derived_evidence_pack_missing_count=$derived_evidence_pack_missing_count derived_evidence_pack_missing_ids=$derived_evidence_pack_missing_ids_csv"

filtered_roadmap_summary_json="$reports_dir/roadmap_progress_summary_live_evidence_filtered.json"
jq --argjson actions "$scope_match_unique_actions_json" '.next_actions = $actions' "$roadmap_summary_json" >"$filtered_roadmap_summary_json"

next_actions_reports_dir="$reports_dir/next_actions_run"
next_actions_summary_json="$reports_dir/roadmap_next_actions_run_summary.json"
next_actions_log="$reports_dir/roadmap_next_actions_run.log"
mkdir -p "$next_actions_reports_dir"

next_actions_cmd=(
  bash
  "$next_actions_script"
  --reports-dir "$next_actions_reports_dir"
  --summary-json "$next_actions_summary_json"
  --roadmap-summary-json "$filtered_roadmap_summary_json"
  --roadmap-report-md "$roadmap_report_md"
  --action-timeout-sec "$action_timeout_sec"
  --allow-unsafe-shell-commands "$allow_unsafe_shell_commands"
  --refresh-manual-validation "$refresh_manual_validation"
  --refresh-single-machine-readiness "$refresh_single_machine_readiness"
  --parallel "$parallel"
  --max-actions "$max_actions"
  --print-summary-json 0
)

print_only_mode="0"
next_actions_rc=0
if [[ "$print_derived_evidence_pack_ids" == "1" ]]; then
  print_only_mode="1"
  if [[ "$derived_evidence_pack_count" -eq 0 ]]; then
    echo "none"
  else
    printf '%s\n' "$derived_evidence_pack_ids_json" | jq -r '.[]'
  fi
  echo "[roadmap-live-evidence-actionable-run] stage=roadmap_next_actions_run status=skipped reason=print-derived-evidence-pack-ids"
else
  echo "[roadmap-live-evidence-actionable-run] stage=roadmap_next_actions_run status=running"
  set +e
  "${next_actions_cmd[@]}" >"$next_actions_log" 2>&1
  next_actions_rc=$?
  set -e
fi

next_actions_summary_valid="0"
nested_runner_status=""
nested_runner_rc="$next_actions_rc"
selected_action_ids_json="$scope_match_unique_action_ids_json"
selected_actions_count="$scope_match_unique_count"
executed_count=0
pass_count=0
fail_count=0
timed_out_count=0
soft_fail_count=0
actions_results_json="[]"
final_rc="$next_actions_rc"
if [[ "$print_only_mode" == "1" ]]; then
  nested_runner_status="skipped_print_derived_evidence_pack_ids"
  nested_runner_rc=0
  final_rc=0
fi
if (( final_rc == 0 )); then
  final_status="pass"
else
  final_status="fail"
fi

if [[ "$print_only_mode" != "1" ]] && [[ -f "$next_actions_summary_json" ]] && jq -e . "$next_actions_summary_json" >/dev/null 2>&1; then
  next_actions_summary_valid="1"
  nested_runner_status="$(jq -r '.status // ""' "$next_actions_summary_json")"
  nested_runner_rc="$(jq -r '.rc // 125' "$next_actions_summary_json")"
  selected_action_ids_json="$(jq -c '.roadmap.selected_action_ids // []' "$next_actions_summary_json")"
  selected_actions_count="$(jq -r '(.roadmap.actions_selected_count // ((.roadmap.selected_action_ids // []) | length) // 0)' "$next_actions_summary_json")"
  executed_count="$(jq -r '.summary.actions_executed // 0' "$next_actions_summary_json")"
  pass_count="$(jq -r '.summary.pass // 0' "$next_actions_summary_json")"
  fail_count="$(jq -r '.summary.fail // 0' "$next_actions_summary_json")"
  timed_out_count="$(jq -r '.summary.timed_out // 0' "$next_actions_summary_json")"
  soft_fail_count="$(jq -r '.summary.soft_failed // 0' "$next_actions_summary_json")"
  actions_results_json="$(jq -c '.actions // []' "$next_actions_summary_json")"
  final_rc="$nested_runner_rc"
  if (( next_actions_rc != 0 && final_rc == 0 )); then
    final_rc="$next_actions_rc"
  fi
fi

if (( final_rc == 0 )); then
  final_status="pass"
else
  final_status="fail"
fi

selected_action_ids_csv="$(printf '%s\n' "$selected_action_ids_json" | jq -r 'join(",")')"
if [[ -z "$selected_action_ids_csv" ]]; then
  selected_action_ids_csv="none"
fi
command_display="$(render_invocation_command "./scripts/roadmap_live_evidence_actionable_run.sh" "$@")"

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg command "$command_display" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg roadmap_report_md "$roadmap_report_md" \
  --arg roadmap_log "$roadmap_log" \
  --arg filtered_roadmap_summary_json "$filtered_roadmap_summary_json" \
  --arg next_actions_summary_json "$next_actions_summary_json" \
  --arg next_actions_log "$next_actions_log" \
  --arg next_actions_reports_dir "$next_actions_reports_dir" \
  --arg scope "$scope" \
  --arg resolved_scope "$resolved_scope" \
  --arg scope_inference_reason "$scope_inference_reason" \
  --argjson target_action_ids "$target_ids_json" \
  --arg nested_runner_status "$nested_runner_status" \
  --argjson nested_runner_rc "$nested_runner_rc" \
  --argjson next_actions_rc "$next_actions_rc" \
  --argjson next_actions_summary_valid "$next_actions_summary_valid" \
  --argjson roadmap_paths_provided "$roadmap_paths_provided" \
  --argjson ran_roadmap_report "$ran_roadmap_report" \
  --argjson refresh_manual_validation "$refresh_manual_validation" \
  --argjson refresh_single_machine_readiness "$refresh_single_machine_readiness" \
  --argjson parallel "$parallel" \
  --argjson max_actions "$max_actions" \
  --argjson print_derived_evidence_pack_ids "$print_derived_evidence_pack_ids" \
  --argjson print_only_mode "$print_only_mode" \
  --argjson action_timeout_sec "$action_timeout_sec" \
  --argjson allow_unsafe_shell_commands "$allow_unsafe_shell_commands" \
  --argjson source_actions_with_command_count "$source_actions_with_command_count" \
  --argjson target_match_count "$target_match_count" \
  --argjson target_match_action_ids "$target_match_action_ids_json" \
  --argjson target_match_unique_count "$target_match_unique_count" \
  --argjson target_match_unique_action_ids "$target_match_unique_action_ids_json" \
  --argjson scope_target_action_ids "$scope_target_action_ids_json" \
  --argjson scope_match_count "$scope_match_count" \
  --argjson scope_match_action_ids "$scope_match_action_ids_json" \
  --argjson scope_match_unique_count "$scope_match_unique_count" \
  --argjson scope_match_unique_action_ids "$scope_match_unique_action_ids_json" \
  --argjson derived_evidence_pack_map "$derived_evidence_pack_map_json" \
  --argjson derived_evidence_pack_ids "$derived_evidence_pack_ids_json" \
  --argjson derived_evidence_pack_count "$derived_evidence_pack_count" \
  --argjson derived_evidence_pack_missing_ids "$derived_evidence_pack_missing_ids_json" \
  --argjson derived_evidence_pack_missing_count "$derived_evidence_pack_missing_count" \
  --argjson selected_unique_count "$scope_match_unique_count" \
  --argjson selected_actions_count "$selected_actions_count" \
  --argjson selected_action_ids "$selected_action_ids_json" \
  --argjson executed_count "$executed_count" \
  --argjson pass_count "$pass_count" \
  --argjson fail_count "$fail_count" \
  --argjson timed_out_count "$timed_out_count" \
  --argjson soft_fail_count "$soft_fail_count" \
  --argjson actions "$actions_results_json" \
  '{
    version: 1,
    schema: { id: "roadmap_live_evidence_actionable_run_summary", major: 1, minor: 0 },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    command: $command,
    inputs: {
      refresh_manual_validation: ($refresh_manual_validation == 1),
      refresh_single_machine_readiness: ($refresh_single_machine_readiness == 1),
      parallel: ($parallel == 1),
      max_actions: $max_actions,
      print_derived_evidence_pack_ids: ($print_derived_evidence_pack_ids == 1),
      print_only_mode: ($print_only_mode == 1),
      action_timeout_sec: $action_timeout_sec,
      allow_unsafe_shell_commands: ($allow_unsafe_shell_commands == 1),
      scope: $scope,
      resolved_scope: $resolved_scope,
      scope_inference_reason: $scope_inference_reason,
      target_action_ids: $target_action_ids
    },
    roadmap: {
      source_paths_provided: ($roadmap_paths_provided == 1),
      generated_this_run: ($ran_roadmap_report == 1),
      resolved_scope: $resolved_scope,
      scope_inference_reason: $scope_inference_reason,
      source_actions_with_command_count: $source_actions_with_command_count,
      target_match_count: $target_match_count,
      target_match_action_ids: $target_match_action_ids,
      target_match_unique_count: $target_match_unique_count,
      target_match_unique_action_ids: $target_match_unique_action_ids,
      scope_target_action_ids: $scope_target_action_ids,
      scope_match_count: $scope_match_count,
      scope_match_action_ids: $scope_match_action_ids,
      scope_match_unique_count: $scope_match_unique_count,
      scope_match_unique_action_ids: $scope_match_unique_action_ids,
      derived_evidence_pack_map: $derived_evidence_pack_map,
      derived_evidence_pack_ids: $derived_evidence_pack_ids,
      derived_evidence_pack_count: $derived_evidence_pack_count,
      derived_evidence_pack_missing_ids_in_snapshot: $derived_evidence_pack_missing_ids,
      derived_evidence_pack_missing_count_in_snapshot: $derived_evidence_pack_missing_count,
      selected_unique_count: $selected_unique_count,
      actions_selected_count: $selected_actions_count,
      selected_action_ids: $selected_action_ids
    },
    summary: {
      derived_evidence_pack_count: $derived_evidence_pack_count,
      derived_evidence_pack_missing_count_in_snapshot: $derived_evidence_pack_missing_count,
      selected_unique_count: $selected_unique_count,
      actions_executed: $executed_count,
      pass: $pass_count,
      fail: $fail_count,
      timed_out: $timed_out_count,
      soft_failed: $soft_fail_count
    },
    actions: $actions,
    delegated_runner: {
      summary_valid: ($next_actions_summary_valid == 1),
      status: (if $nested_runner_status == "" then null else $nested_runner_status end),
      rc: $nested_runner_rc,
      process_rc: $next_actions_rc
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      roadmap_summary_json: $roadmap_summary_json,
      roadmap_report_md: $roadmap_report_md,
      roadmap_log: $roadmap_log,
      filtered_roadmap_summary_json: $filtered_roadmap_summary_json,
      next_actions_summary_json: $next_actions_summary_json,
      next_actions_log: $next_actions_log,
      next_actions_reports_dir: $next_actions_reports_dir
    }
  }' >"$summary_json"

echo "[roadmap-live-evidence-actionable-run] stage=roadmap_next_actions_run status=$final_status rc=$final_rc selected_action_ids=$selected_action_ids_csv"
echo "[roadmap-live-evidence-actionable-run] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
