#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_evidence_pack_actionable_run.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--roadmap-summary-json PATH] \
    [--roadmap-report-md PATH] \
    [--live-evidence-summary-json PATH] \
    [--require-live-derived-evidence-pack-actions [0|1]] \
    [--action-timeout-sec N] \
    [--allow-unsafe-shell-commands [0|1]] \
    [--refresh-manual-validation [0|1]] \
    [--refresh-single-machine-readiness [0|1]] \
    [--scope auto|all|profile-default|runtime-actuation|multi-vm] \
    [--parallel [0|1]] \
    [--max-actions N] \
    [--print-summary-json [0|1]]

Purpose:
  Resolve roadmap next_actions (via roadmap_progress_report when needed), then
  execute only actions whose id ends with "_evidence_pack".
  Execution is delegated to roadmap_next_actions_run to preserve pass/fail and
  exit-code aggregation semantics.

Defaults:
  --live-evidence-summary-json <autodetect from reports-dir parent when available>
  --require-live-derived-evidence-pack-actions 1 when live summary is provided/autodetected, else 0
  --action-timeout-sec 0   (0 = no per-action timeout)
  --allow-unsafe-shell-commands 0
  --refresh-manual-validation 0
  --refresh-single-machine-readiness 0
  --scope profile-default
  --parallel 0
  --max-actions 0   (0 = no limit)
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

reports_dir="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_REPORTS_DIR:-}"
summary_json="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_SUMMARY_JSON:-}"
roadmap_summary_json="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SUMMARY_JSON:-}"
roadmap_report_md="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_REPORT_MD:-}"
live_evidence_summary_json="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_LIVE_EVIDENCE_SUMMARY_JSON:-}"
require_live_derived_evidence_pack_actions="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_REQUIRE_LIVE_DERIVED_EVIDENCE_PACK_ACTIONS:-}"
refresh_manual_validation="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_REFRESH_MANUAL_VALIDATION:-0}"
refresh_single_machine_readiness="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_REFRESH_SINGLE_MACHINE_READINESS:-0}"
parallel="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_PARALLEL:-0}"
max_actions="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_MAX_ACTIONS:-0}"
print_summary_json="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_PRINT_SUMMARY_JSON:-1}"
action_timeout_sec="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ACTION_TIMEOUT_SEC:-0}"
allow_unsafe_shell_commands="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ALLOW_UNSAFE_SHELL_COMMANDS:-0}"
scope="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_SCOPE:-${ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCOPE:-profile-default}}"

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
    --live-evidence-summary-json)
      require_value_or_die "$1" "${2:-}"
      live_evidence_summary_json="${2:-}"
      shift 2
      ;;
    --require-live-derived-evidence-pack-actions)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_live_derived_evidence_pack_actions="${2:-}"
        shift 2
      else
        require_live_derived_evidence_pack_actions="1"
        shift
      fi
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
int_arg_or_die "--max-actions" "$max_actions"
int_arg_or_die "--action-timeout-sec" "$action_timeout_sec"
scope_arg_or_die "$scope"

roadmap_paths_provided="1"
if [[ -z "$roadmap_summary_json" || -z "$roadmap_report_md" ]]; then
  roadmap_paths_provided="0"
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/roadmap_evidence_pack_actionable_run_${run_stamp}"
fi
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

live_evidence_summary_autodetected="0"
if [[ -z "$live_evidence_summary_json" ]]; then
  live_evidence_summary_candidate="$reports_dir/../roadmap_live_evidence_actionable_run_summary.json"
  if [[ -f "$live_evidence_summary_candidate" ]]; then
    live_evidence_summary_json="$live_evidence_summary_candidate"
    live_evidence_summary_autodetected="1"
  fi
fi
if [[ -n "$live_evidence_summary_json" ]]; then
  live_evidence_summary_json="$(abs_path "$live_evidence_summary_json")"
fi

if [[ -z "$require_live_derived_evidence_pack_actions" ]]; then
  if [[ -n "$live_evidence_summary_json" ]]; then
    require_live_derived_evidence_pack_actions="1"
  else
    require_live_derived_evidence_pack_actions="0"
  fi
fi
bool_arg_or_die "--require-live-derived-evidence-pack-actions" "$require_live_derived_evidence_pack_actions"

if [[ -z "$roadmap_summary_json" ]]; then
  roadmap_summary_json="$reports_dir/roadmap_progress_summary.json"
fi
if [[ -z "$roadmap_report_md" ]]; then
  roadmap_report_md="$reports_dir/roadmap_progress_report.md"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/roadmap_evidence_pack_actionable_run_summary.json"
fi

roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
roadmap_report_md="$(abs_path "$roadmap_report_md")"
summary_json="$(abs_path "$summary_json")"
roadmap_log="$reports_dir/roadmap_progress_report.log"

mkdir -p "$(dirname "$roadmap_summary_json")" "$(dirname "$roadmap_report_md")" "$(dirname "$summary_json")"

roadmap_script="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"
next_actions_script="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_NEXT_ACTIONS_SCRIPT:-$ROOT_DIR/scripts/roadmap_next_actions_run.sh}"
suffix_filter="_evidence_pack"
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
  echo "[roadmap-evidence-pack-actionable-run] stage=roadmap_progress_report status=running"
  set +e
  "${roadmap_cmd[@]}" >"$roadmap_log" 2>&1
  roadmap_rc=$?
  set -e
  if (( roadmap_rc != 0 )); then
    echo "[roadmap-evidence-pack-actionable-run] stage=roadmap_progress_report status=fail rc=$roadmap_rc"
    echo "roadmap_progress_report failed; see: $roadmap_log"
    exit "$roadmap_rc"
  fi
  ran_roadmap_report="1"
  echo "[roadmap-evidence-pack-actionable-run] stage=roadmap_progress_report status=pass rc=0"
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
suffix_match_actions_json="$(jq -c --arg suffix "$suffix_filter" '[ (.next_actions // [])[] | select((.id // "") | endswith($suffix)) | select(((.command // "") | tostring | length) > 0) ]' "$roadmap_summary_json")"
suffix_match_count="$(printf '%s\n' "$suffix_match_actions_json" | jq -r 'length')"
suffix_match_action_ids_json="$(printf '%s\n' "$suffix_match_actions_json" | jq -c '[.[] | .id // "" | select(length > 0)]')"
suffix_match_action_ids_csv="$(printf '%s\n' "$suffix_match_action_ids_json" | jq -r 'join(",")')"
if [[ -z "$suffix_match_action_ids_csv" ]]; then
  suffix_match_action_ids_csv="none"
fi
recognized_family_action_ids_json='["profile_default_gate_evidence_pack","runtime_actuation_promotion_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]'
recognized_family_match_actions_json="$(printf '%s\n' "$suffix_match_actions_json" | jq -c --argjson target_ids "$recognized_family_action_ids_json" '[ .[] | select((.id // "") as $id | ($target_ids | index($id)) != null) ]')"
recognized_family_match_count="$(printf '%s\n' "$recognized_family_match_actions_json" | jq -r 'length')"
recognized_family_match_action_ids_json="$(printf '%s\n' "$recognized_family_match_actions_json" | jq -c '[.[] | .id // "" | select(length > 0)]')"
recognized_family_match_action_ids_csv="$(printf '%s\n' "$recognized_family_match_action_ids_json" | jq -r 'join(",")')"
if [[ -z "$recognized_family_match_action_ids_csv" ]]; then
  recognized_family_match_action_ids_csv="none"
fi
scope_target_action_ids_json='[]'
resolved_scope="$scope"
scope_inference_reason="explicit scope: $scope"
case "$scope" in
  profile-default)
    scope_target_action_ids_json='["profile_default_gate_evidence_pack"]'
    ;;
  runtime-actuation)
    scope_target_action_ids_json='["runtime_actuation_promotion_evidence_pack"]'
    ;;
  multi-vm)
    scope_target_action_ids_json='["profile_compare_multi_vm_stability_promotion_evidence_pack"]'
    ;;
  all)
    scope_target_action_ids_json="$recognized_family_action_ids_json"
    scope_inference_reason="explicit scope: all (include every recognized evidence-pack family action)"
    ;;
  auto)
    auto_scope_target_action_ids_json="$(printf '%s\n' "$recognized_family_match_action_ids_json" | jq -c '
      [
        (if index("profile_default_gate_evidence_pack") != null then "profile_default_gate_evidence_pack" else empty end),
        (if index("runtime_actuation_promotion_evidence_pack") != null then "runtime_actuation_promotion_evidence_pack" else empty end),
        (if index("profile_compare_multi_vm_stability_promotion_evidence_pack") != null then "profile_compare_multi_vm_stability_promotion_evidence_pack" else empty end)
      ]'
    )"
    auto_scope_family_labels_json="$(printf '%s\n' "$auto_scope_target_action_ids_json" | jq -c '
      map(
        if . == "profile_default_gate_evidence_pack" then "profile-default"
        elif . == "runtime_actuation_promotion_evidence_pack" then "runtime-actuation"
        elif . == "profile_compare_multi_vm_stability_promotion_evidence_pack" then "multi-vm"
        else empty
        end
      )'
    )"
    auto_scope_family_count="$(printf '%s\n' "$auto_scope_family_labels_json" | jq -r 'length')"
    auto_scope_family_labels_csv="$(printf '%s\n' "$auto_scope_family_labels_json" | jq -r 'join(",")')"
    if (( auto_scope_family_count == 0 )); then
      resolved_scope="none"
      scope_target_action_ids_json='[]'
      scope_inference_reason="auto: no recognized evidence-pack families are pending in roadmap next_actions"
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

scope_match_actions_json="$(printf '%s\n' "$recognized_family_match_actions_json" | jq -c --argjson target_ids "$scope_target_action_ids_json" '[.[] | select((.id // "") as $id | ($target_ids | index($id)) != null)]')"
scope_match_count="$(printf '%s\n' "$scope_match_actions_json" | jq -r 'length')"
scope_match_action_ids_json="$(printf '%s\n' "$scope_match_actions_json" | jq -c '[.[] | .id // "" | select(length > 0)]')"
scope_match_unique_actions_json="$(printf '%s\n' "$scope_match_actions_json" | jq -c 'reduce .[] as $action ({ ids: [], actions: [] }; (($action.id // "") | tostring) as $id | if ($id | length) == 0 or ((.ids | index($id)) != null) then . else .ids += [$id] | .actions += [$action] end) | .actions')"
scope_match_unique_count="$(printf '%s\n' "$scope_match_unique_actions_json" | jq -r 'length')"
scope_match_unique_action_ids_json="$(printf '%s\n' "$scope_match_unique_actions_json" | jq -c '[.[] | .id // "" | select(length > 0)]')"
scope_match_action_ids_csv="$(printf '%s\n' "$scope_match_action_ids_json" | jq -r 'join(",")')"
if [[ -z "$scope_match_action_ids_csv" ]]; then
  scope_match_action_ids_csv="none"
fi
scope_match_unique_action_ids_csv="$(printf '%s\n' "$scope_match_unique_action_ids_json" | jq -r 'join(",")')"
if [[ -z "$scope_match_unique_action_ids_csv" ]]; then
  scope_match_unique_action_ids_csv="none"
fi

roadmap_snapshot_action_ids_json="$(jq -c '[ (.next_actions // [])[] | .id // "" | tostring | select(length > 0) ]' "$roadmap_summary_json")"
roadmap_snapshot_unique_action_ids_json="$(printf '%s\n' "$roadmap_snapshot_action_ids_json" | jq -c 'reduce .[] as $id ({ ids: [], ordered: [] }; if (.ids | index($id)) != null then . else .ids += [$id] | .ordered += [$id] end) | .ordered')"

live_evidence_summary_present="0"
live_evidence_summary_valid="0"
live_evidence_summary_load_error=""
live_required_evidence_pack_ids_json='[]'
live_required_evidence_pack_count=0
live_required_missing_in_snapshot_ids_json='[]'
live_required_missing_in_snapshot_count=0
live_required_missing_in_scope_ids_json='[]'
live_required_missing_in_scope_count=0
live_requirement_fail_closed="0"
live_requirement_failure_kind=""
live_requirement_failure_reason=""

if [[ -n "$live_evidence_summary_json" ]]; then
  if [[ -f "$live_evidence_summary_json" ]]; then
    live_evidence_summary_present="1"
  fi
  if [[ "$live_evidence_summary_present" == "1" ]] && jq -e 'type == "object"' "$live_evidence_summary_json" >/dev/null 2>&1; then
    live_evidence_summary_valid="1"
    live_required_evidence_pack_ids_json="$(jq -c '
      def normalize_ids:
        map(select(type == "string") | gsub("^\\s+|\\s+$"; "") | select(length > 0));
      def unique_stable:
        reduce .[] as $id ({ seen: [], ordered: [] };
          if (.seen | index($id)) != null then .
          else .seen += [$id] | .ordered += [$id]
          end
        ) | .ordered;
      def derive_evidence_pack_id($id):
        if $id == "profile_default_gate" then "profile_default_gate_evidence_pack"
        elif $id == "runtime_actuation_promotion" then "runtime_actuation_promotion_evidence_pack"
        elif $id == "profile_compare_multi_vm_stability" then "profile_compare_multi_vm_stability_promotion_evidence_pack"
        elif $id == "profile_compare_multi_vm_stability_promotion" then "profile_compare_multi_vm_stability_promotion_evidence_pack"
        else ($id + "_evidence_pack")
        end;
      (.roadmap.derived_evidence_pack_ids // null) as $derived
      | if ($derived | type) == "array" and (($derived | normalize_ids | length) > 0) then
          ($derived | normalize_ids | unique_stable)
        elif ((.roadmap.selected_action_ids // null) | type) == "array" then
          ([ .roadmap.selected_action_ids[] | select(type == "string") | gsub("^\\s+|\\s+$"; "") | select(length > 0) | derive_evidence_pack_id(.) ] | unique_stable)
        else
          []
        end
    ' "$live_evidence_summary_json")"
    live_required_evidence_pack_count="$(printf '%s\n' "$live_required_evidence_pack_ids_json" | jq -r 'length')"
    live_required_missing_in_snapshot_ids_json="$(jq -nc --argjson required "$live_required_evidence_pack_ids_json" --argjson snapshot_ids "$roadmap_snapshot_unique_action_ids_json" '[ $required[] as $id | select(($snapshot_ids | index($id)) == null) | $id ]')"
    live_required_missing_in_snapshot_count="$(printf '%s\n' "$live_required_missing_in_snapshot_ids_json" | jq -r 'length')"
    live_required_missing_in_scope_ids_json="$(jq -nc --argjson required "$live_required_evidence_pack_ids_json" --argjson selected_ids "$scope_match_unique_action_ids_json" '[ $required[] as $id | select(($selected_ids | index($id)) == null) | $id ]')"
    live_required_missing_in_scope_count="$(printf '%s\n' "$live_required_missing_in_scope_ids_json" | jq -r 'length')"
  else
    live_evidence_summary_load_error="missing_or_invalid_live_evidence_summary"
  fi
fi

if [[ "$require_live_derived_evidence_pack_actions" == "1" ]]; then
  if [[ -z "$live_evidence_summary_json" ]]; then
    live_requirement_fail_closed="1"
    live_requirement_failure_kind="required_live_evidence_summary_not_provided"
    live_requirement_failure_reason="required live evidence summary path is missing"
  elif [[ "$live_evidence_summary_valid" != "1" ]]; then
    live_requirement_fail_closed="1"
    live_requirement_failure_kind="required_live_evidence_summary_invalid"
    live_requirement_failure_reason="required live evidence summary JSON is missing or invalid"
  elif (( live_required_missing_in_scope_count > 0 )); then
    live_requirement_fail_closed="1"
    live_requirement_failure_kind="required_live_derived_evidence_pack_actions_missing_from_scope"
    live_requirement_failure_reason="required live-derived evidence-pack actions are missing from selected publish scope"
  fi
fi

live_required_evidence_pack_ids_csv="$(printf '%s\n' "$live_required_evidence_pack_ids_json" | jq -r 'join(",")')"
if [[ -z "$live_required_evidence_pack_ids_csv" ]]; then
  live_required_evidence_pack_ids_csv="none"
fi
live_required_missing_in_scope_ids_csv="$(printf '%s\n' "$live_required_missing_in_scope_ids_json" | jq -r 'join(",")')"
if [[ -z "$live_required_missing_in_scope_ids_csv" ]]; then
  live_required_missing_in_scope_ids_csv="none"
fi
live_required_missing_in_snapshot_ids_csv="$(printf '%s\n' "$live_required_missing_in_snapshot_ids_json" | jq -r 'join(",")')"
if [[ -z "$live_required_missing_in_snapshot_ids_csv" ]]; then
  live_required_missing_in_snapshot_ids_csv="none"
fi

echo "[roadmap-evidence-pack-actionable-run] scope=$scope resolved_scope=$resolved_scope suffix_filter=$suffix_filter source_actions_with_command=$source_actions_with_command_count suffix_matches=$suffix_match_count recognized_family_matches=$recognized_family_match_count scope_matches=$scope_match_count scope_unique_matches=$scope_match_unique_count"
echo "[roadmap-evidence-pack-actionable-run] scope_inference_reason=$scope_inference_reason"
echo "[roadmap-evidence-pack-actionable-run] suffix_match_action_ids=$suffix_match_action_ids_csv"
echo "[roadmap-evidence-pack-actionable-run] recognized_family_match_action_ids=$recognized_family_match_action_ids_csv"
echo "[roadmap-evidence-pack-actionable-run] scope_match_action_ids=$scope_match_action_ids_csv"
echo "[roadmap-evidence-pack-actionable-run] scope_match_unique_action_ids=$scope_match_unique_action_ids_csv"
echo "[roadmap-evidence-pack-actionable-run] live_required_check enabled=$require_live_derived_evidence_pack_actions summary_path=${live_evidence_summary_json:-none} summary_valid=$live_evidence_summary_valid required_ids=$live_required_evidence_pack_ids_csv missing_in_scope=$live_required_missing_in_scope_ids_csv missing_in_snapshot=$live_required_missing_in_snapshot_ids_csv fail_closed=$live_requirement_fail_closed"

filtered_roadmap_summary_json="$reports_dir/roadmap_progress_summary_evidence_pack_filtered.json"
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

next_actions_summary_valid="0"
nested_runner_status=""
nested_runner_rc=0
next_actions_rc=0
next_actions_skip_reason=""
delegated_summary_contract_fail_closed="0"
delegated_summary_contract_failure_kind=""
delegated_summary_contract_failure_reason=""
delegated_summary_contract_failure_reasons_json='[]'
delegated_summary_contract_next_operator_action=""
selected_action_ids_json="[]"
selected_actions_count=0
executed_count=0
pass_count=0
fail_count=0
timed_out_count=0
soft_fail_count=0
actions_results_json="[]"
actions_results_count=0
final_rc=0
final_status="pass"

if [[ "$live_requirement_fail_closed" == "1" ]]; then
  next_actions_skip_reason="$live_requirement_failure_kind"
  nested_runner_status="skipped_${next_actions_skip_reason}"
  nested_runner_rc=4
  final_rc=4
  final_status="fail"
  echo "[roadmap-evidence-pack-actionable-run] stage=roadmap_next_actions_run status=skipped reason=$next_actions_skip_reason"
else
  rm -f "$next_actions_summary_json" "$next_actions_log"
  echo "[roadmap-evidence-pack-actionable-run] stage=roadmap_next_actions_run status=running"
  set +e
  "${next_actions_cmd[@]}" >"$next_actions_log" 2>&1
  next_actions_rc=$?
  set -e

  nested_runner_rc="$next_actions_rc"
  final_rc="$next_actions_rc"
  if (( final_rc == 0 )); then
    final_status="pass"
  else
    final_status="fail"
  fi

  declare -a delegated_summary_contract_reasons=()

  if [[ -f "$next_actions_summary_json" ]] && jq -e . "$next_actions_summary_json" >/dev/null 2>&1; then
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
    actions_results_count="$(printf '%s\n' "$actions_results_json" | jq -r 'if type == "array" then length else 0 end' 2>/dev/null || printf '0')"

    if ! [[ "$nested_runner_rc" =~ ^-?[0-9]+$ ]]; then
      delegated_summary_contract_reasons+=("delegated summary rc field is not numeric")
      nested_runner_rc=125
    fi
    if ! [[ "$selected_actions_count" =~ ^[0-9]+$ ]]; then
      delegated_summary_contract_reasons+=("delegated summary roadmap.actions_selected_count is not a non-negative integer")
      selected_actions_count=0
    fi
    if ! [[ "$executed_count" =~ ^[0-9]+$ ]]; then
      delegated_summary_contract_reasons+=("delegated summary summary.actions_executed is not a non-negative integer")
      executed_count=0
    fi
    if ! [[ "$pass_count" =~ ^[0-9]+$ ]]; then
      delegated_summary_contract_reasons+=("delegated summary summary.pass is not a non-negative integer")
      pass_count=0
    fi
    if ! [[ "$fail_count" =~ ^[0-9]+$ ]]; then
      delegated_summary_contract_reasons+=("delegated summary summary.fail is not a non-negative integer")
      fail_count=0
    fi
    if ! [[ "$timed_out_count" =~ ^[0-9]+$ ]]; then
      delegated_summary_contract_reasons+=("delegated summary summary.timed_out is not a non-negative integer")
      timed_out_count=0
    fi
    if ! [[ "$soft_fail_count" =~ ^[0-9]+$ ]]; then
      delegated_summary_contract_reasons+=("delegated summary summary.soft_failed is not a non-negative integer")
      soft_fail_count=0
    fi
    if ! [[ "$actions_results_count" =~ ^[0-9]+$ ]]; then
      delegated_summary_contract_reasons+=("delegated summary actions array length is not available")
      actions_results_count=0
    fi
    if ! jq -e '(.actions // []) | type == "array"' "$next_actions_summary_json" >/dev/null 2>&1; then
      delegated_summary_contract_reasons+=("delegated summary actions field is not an array")
      actions_results_count=0
    fi
    if [[ "$selected_actions_count" =~ ^[0-9]+$ && "$scope_match_unique_count" =~ ^[0-9]+$ ]]; then
      if (( selected_actions_count > scope_match_unique_count )); then
        delegated_summary_contract_reasons+=("delegated summary selected action count (${selected_actions_count}) exceeds wrapper-selected count (${scope_match_unique_count})")
      fi
    fi
    if [[ "$executed_count" =~ ^[0-9]+$ \
      && "$pass_count" =~ ^[0-9]+$ \
      && "$fail_count" =~ ^[0-9]+$ \
      && "$timed_out_count" =~ ^[0-9]+$ \
      && "$soft_fail_count" =~ ^[0-9]+$ ]]; then
      accounted_count=$((pass_count + fail_count + timed_out_count + soft_fail_count))
      if (( accounted_count != executed_count )); then
        delegated_summary_contract_reasons+=("delegated summary counters mismatch: summary.actions_executed=${executed_count} but pass+fail+timed_out+soft_failed=${accounted_count}")
      fi
    fi
    if [[ "$actions_results_count" =~ ^[0-9]+$ && "$executed_count" =~ ^[0-9]+$ ]]; then
      if (( actions_results_count != executed_count )); then
        delegated_summary_contract_reasons+=("delegated summary actions length mismatch: actions=${actions_results_count} summary.actions_executed=${executed_count}")
      fi
    fi

    final_rc="$nested_runner_rc"
    if (( next_actions_rc != 0 && final_rc == 0 )); then
      final_rc="$next_actions_rc"
    fi
  fi

  if (( next_actions_rc == 0 )) && [[ "$next_actions_summary_valid" != "1" ]]; then
    delegated_summary_contract_reasons+=("delegated runner returned rc=0 but summary artifact is missing or invalid: ${next_actions_summary_json}")
    if [[ -z "$delegated_summary_contract_failure_kind" ]]; then
      delegated_summary_contract_failure_kind="delegated_summary_missing_or_invalid"
    fi
  fi

  if ((${#delegated_summary_contract_reasons[@]} > 0)); then
    delegated_summary_contract_fail_closed="1"
    if [[ -z "$delegated_summary_contract_failure_kind" ]]; then
      delegated_summary_contract_failure_kind="delegated_summary_contract_violation"
    fi
    delegated_summary_contract_failure_reason="${delegated_summary_contract_reasons[0]}"
    delegated_summary_contract_failure_reasons_json="$(printf '%s\n' "${delegated_summary_contract_reasons[@]}" | jq -R 'gsub("^\\s+|\\s+$"; "") | select(length > 0)' | jq -s '.')"
    delegated_summary_contract_next_operator_action="Inspect delegated artifacts ${next_actions_summary_json} and ${next_actions_log}, then rerun ./scripts/roadmap_next_actions_run.sh with the same --roadmap-summary-json and --roadmap-report-md inputs."
    final_status="fail"
    if (( final_rc == 0 )); then
      final_rc=6
    fi
    echo "[roadmap-evidence-pack-actionable-run] stage=roadmap_next_actions_run status=fail reason=${delegated_summary_contract_failure_kind}"
    echo "[roadmap-evidence-pack-actionable-run] delegated_summary_contract_diagnostic=${delegated_summary_contract_failure_reason}"
  fi

  if (( final_rc == 0 )); then
    final_status="pass"
  else
    final_status="fail"
  fi
fi

selected_action_ids_csv="$(printf '%s\n' "$selected_action_ids_json" | jq -r 'join(",")')"
if [[ -z "$selected_action_ids_csv" ]]; then
  selected_action_ids_csv="none"
fi
command_display="$(render_invocation_command "./scripts/roadmap_evidence_pack_actionable_run.sh" "$@")"

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
  --arg live_evidence_summary_json "$live_evidence_summary_json" \
  --arg live_evidence_summary_load_error "$live_evidence_summary_load_error" \
  --arg next_actions_skip_reason "$next_actions_skip_reason" \
  --arg suffix_filter "$suffix_filter" \
  --arg scope "$scope" \
  --arg resolved_scope "$resolved_scope" \
  --arg scope_inference_reason "$scope_inference_reason" \
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
  --argjson action_timeout_sec "$action_timeout_sec" \
  --argjson allow_unsafe_shell_commands "$allow_unsafe_shell_commands" \
  --argjson live_evidence_summary_autodetected "$live_evidence_summary_autodetected" \
  --argjson require_live_derived_evidence_pack_actions "$require_live_derived_evidence_pack_actions" \
  --argjson live_evidence_summary_present "$live_evidence_summary_present" \
  --argjson live_evidence_summary_valid "$live_evidence_summary_valid" \
  --argjson source_actions_with_command_count "$source_actions_with_command_count" \
  --argjson suffix_match_count "$suffix_match_count" \
  --argjson suffix_match_action_ids "$suffix_match_action_ids_json" \
  --argjson recognized_family_match_count "$recognized_family_match_count" \
  --argjson recognized_family_match_action_ids "$recognized_family_match_action_ids_json" \
  --argjson roadmap_snapshot_action_ids "$roadmap_snapshot_action_ids_json" \
  --argjson roadmap_snapshot_unique_action_ids "$roadmap_snapshot_unique_action_ids_json" \
  --argjson scope_target_action_ids "$scope_target_action_ids_json" \
  --argjson scope_match_count "$scope_match_count" \
  --argjson scope_match_action_ids "$scope_match_action_ids_json" \
  --argjson scope_match_unique_count "$scope_match_unique_count" \
  --argjson scope_match_unique_action_ids "$scope_match_unique_action_ids_json" \
  --argjson live_required_evidence_pack_ids "$live_required_evidence_pack_ids_json" \
  --argjson live_required_evidence_pack_count "$live_required_evidence_pack_count" \
  --argjson live_required_missing_in_snapshot_ids "$live_required_missing_in_snapshot_ids_json" \
  --argjson live_required_missing_in_snapshot_count "$live_required_missing_in_snapshot_count" \
  --argjson live_required_missing_in_scope_ids "$live_required_missing_in_scope_ids_json" \
  --argjson live_required_missing_in_scope_count "$live_required_missing_in_scope_count" \
  --argjson live_requirement_fail_closed "$live_requirement_fail_closed" \
  --arg live_requirement_failure_kind "$live_requirement_failure_kind" \
  --arg live_requirement_failure_reason "$live_requirement_failure_reason" \
  --argjson selected_unique_count "$scope_match_unique_count" \
  --argjson selected_actions_count "$selected_actions_count" \
  --argjson selected_action_ids "$selected_action_ids_json" \
  --argjson executed_count "$executed_count" \
  --argjson pass_count "$pass_count" \
  --argjson fail_count "$fail_count" \
  --argjson timed_out_count "$timed_out_count" \
  --argjson soft_fail_count "$soft_fail_count" \
  --argjson actions_results_count "$actions_results_count" \
  --argjson actions "$actions_results_json" \
  --argjson delegated_summary_contract_fail_closed "$delegated_summary_contract_fail_closed" \
  --arg delegated_summary_contract_failure_kind "$delegated_summary_contract_failure_kind" \
  --arg delegated_summary_contract_failure_reason "$delegated_summary_contract_failure_reason" \
  --argjson delegated_summary_contract_failure_reasons "$delegated_summary_contract_failure_reasons_json" \
  --arg delegated_summary_contract_next_operator_action "$delegated_summary_contract_next_operator_action" \
  '{
    version: 1,
    schema: { id: "roadmap_evidence_pack_actionable_run_summary", major: 1, minor: 0 },
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
      allow_unsafe_shell_commands: ($allow_unsafe_shell_commands == 1),
      suffix_filter: $suffix_filter,
      scope: $scope,
      resolved_scope: $resolved_scope,
      scope_inference_reason: $scope_inference_reason,
      live_evidence_summary_json: (
        if $live_evidence_summary_json == "" then null
        else $live_evidence_summary_json
        end
      ),
      live_evidence_summary_autodetected: ($live_evidence_summary_autodetected == 1),
      require_live_derived_evidence_pack_actions: ($require_live_derived_evidence_pack_actions == 1)
    },
    roadmap: {
      source_paths_provided: ($roadmap_paths_provided == 1),
      generated_this_run: ($ran_roadmap_report == 1),
      resolved_scope: $resolved_scope,
      scope_inference_reason: $scope_inference_reason,
      source_actions_with_command_count: $source_actions_with_command_count,
      suffix_match_count: $suffix_match_count,
      suffix_match_action_ids: $suffix_match_action_ids,
      recognized_family_match_count: $recognized_family_match_count,
      recognized_family_match_action_ids: $recognized_family_match_action_ids,
      snapshot_action_ids: $roadmap_snapshot_action_ids,
      snapshot_unique_action_ids: $roadmap_snapshot_unique_action_ids,
      scope_target_action_ids: $scope_target_action_ids,
      scope_match_count: $scope_match_count,
      scope_match_action_ids: $scope_match_action_ids,
      scope_match_unique_count: $scope_match_unique_count,
      scope_match_unique_action_ids: $scope_match_unique_action_ids,
      live_required_evidence_pack_ids: $live_required_evidence_pack_ids,
      live_required_evidence_pack_count: $live_required_evidence_pack_count,
      live_required_missing_in_snapshot_ids: $live_required_missing_in_snapshot_ids,
      live_required_missing_in_snapshot_count: $live_required_missing_in_snapshot_count,
      live_required_missing_in_scope_ids: $live_required_missing_in_scope_ids,
      live_required_missing_in_scope_count: $live_required_missing_in_scope_count,
      selected_unique_count: $selected_unique_count,
      actions_selected_count: $selected_actions_count,
      selected_action_ids: $selected_action_ids
    },
    summary: {
      selected_unique_count: $selected_unique_count,
      actions_executed: $executed_count,
      pass: $pass_count,
      fail: $fail_count,
      timed_out: $timed_out_count,
      soft_failed: $soft_fail_count,
      actions_results_count: $actions_results_count,
      live_required_evidence_pack_count: $live_required_evidence_pack_count,
      live_required_missing_in_scope_count: $live_required_missing_in_scope_count,
      live_requirement_fail_closed: ($live_requirement_fail_closed == 1),
      delegated_summary_contract_fail_closed: ($delegated_summary_contract_fail_closed == 1)
    },
    enforcement: {
      require_live_derived_evidence_pack_actions: ($require_live_derived_evidence_pack_actions == 1),
      live_evidence_summary_present: ($live_evidence_summary_present == 1),
      live_evidence_summary_valid: ($live_evidence_summary_valid == 1),
      live_evidence_summary_load_error: (
        if $live_evidence_summary_load_error == "" then null
        else $live_evidence_summary_load_error
        end
      ),
      live_required_evidence_pack_count: $live_required_evidence_pack_count,
      live_required_missing_in_snapshot_count: $live_required_missing_in_snapshot_count,
      live_required_missing_in_scope_count: $live_required_missing_in_scope_count,
      live_required_missing_in_snapshot_ids: $live_required_missing_in_snapshot_ids,
      live_required_missing_in_scope_ids: $live_required_missing_in_scope_ids,
      live_requirement_fail_closed: ($live_requirement_fail_closed == 1),
      live_requirement_failure_kind: (
        if $live_requirement_failure_kind == "" then null
        else $live_requirement_failure_kind
        end
      ),
      live_requirement_failure_reason: (
        if $live_requirement_failure_reason == "" then null
        else $live_requirement_failure_reason
        end
      ),
      delegated_summary_contract_fail_closed: ($delegated_summary_contract_fail_closed == 1),
      delegated_summary_contract_failure_kind: (
        if $delegated_summary_contract_failure_kind == "" then null
        else $delegated_summary_contract_failure_kind
        end
      ),
      delegated_summary_contract_failure_reason: (
        if $delegated_summary_contract_failure_reason == "" then null
        else $delegated_summary_contract_failure_reason
        end
      ),
      delegated_summary_contract_failure_reasons: $delegated_summary_contract_failure_reasons,
      delegated_summary_contract_next_operator_action: (
        if $delegated_summary_contract_next_operator_action == "" then null
        else $delegated_summary_contract_next_operator_action
        end
      )
    },
    actions: $actions,
    delegated_runner: {
      summary_valid: ($next_actions_summary_valid == 1),
      status: (if $nested_runner_status == "" then null else $nested_runner_status end),
      skip_reason: (if $next_actions_skip_reason == "" then null else $next_actions_skip_reason end),
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

echo "[roadmap-evidence-pack-actionable-run] stage=roadmap_next_actions_run status=$final_status rc=$final_rc selected_action_ids=$selected_action_ids_csv"
echo "[roadmap-evidence-pack-actionable-run] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
