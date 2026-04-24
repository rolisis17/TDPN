#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
original_args=("$@")

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_live_evidence_archive_run.sh \
    [--reports-dir DIR] \
    [--roadmap-summary-json PATH] \
    [--archive-root DIR] \
    [--scope auto|all|profile-default|runtime-actuation|multi-vm] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Archive roadmap live-evidence artifacts (M2/M4/M5 families) into a timestamped
  directory under --archive-root.

Behavior:
  - Discovers artifact paths from roadmap summary when available.
  - Falls back to deterministic default artifact paths under --reports-dir when
    summary paths are unavailable for a selected family.
  - Produces a fail-closed summary with copied/missing counts and next-action
    hints for families with no copied artifacts.
  - Does not abort early when some artifacts are missing.

Defaults:
  --reports-dir .easy-node-logs
  --roadmap-summary-json <reports-dir>/roadmap_progress_summary.json
  --archive-root <reports-dir>/roadmap_live_evidence_archive
  --scope auto
  --summary-json <reports-dir>/roadmap_live_evidence_archive_run_summary.json
  --print-summary-json 1
USAGE
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

strip_wrapping_quotes() {
  local value
  value="$(trim "${1:-}")"
  if [[ "${value:0:1}" == "\"" && "${value: -1}" == "\"" ]]; then
    value="${value:1:${#value}-2}"
  fi
  if [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  elif [[ "$path" =~ ^[A-Za-z]:[\\/].* ]]; then
    if command -v cygpath >/dev/null 2>&1; then
      cygpath -u "$path"
    else
      local drive="${path:0:1}"
      local tail="${path:2}"
      tail="${tail//\\//}"
      printf '/mnt/%s/%s' "${drive,,}" "${tail#/}"
    fi
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

canonicalize_existing_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" || ! -e "$path" ]]; then
    printf '%s' ""
    return 1
  fi
  if command -v realpath >/dev/null 2>&1; then
    realpath "$path" 2>/dev/null && return 0
  fi
  if command -v readlink >/dev/null 2>&1; then
    readlink -f "$path" 2>/dev/null && return 0
  fi
  local dir
  local base
  local dir_real
  dir="$(dirname "$path")"
  base="$(basename "$path")"
  if dir_real="$(cd "$dir" 2>/dev/null && pwd -P)"; then
    printf '%s/%s' "$dir_real" "$base"
    return 0
  fi
  printf '%s' "$path"
  return 0
}

normalize_path_prefix() {
  local path
  path="$(abs_path "${1:-}")"
  path="$(trim "$path")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
    return
  fi
  local canonical
  canonical="$(canonicalize_existing_path "$path" || true)"
  if [[ -n "$canonical" ]]; then
    path="$canonical"
  fi
  if [[ "$path" != "/" ]]; then
    path="${path%/}"
  fi
  printf '%s' "$path"
}

path_is_within_prefix() {
  local path="$1"
  local prefix="$2"
  if [[ "$prefix" == "/" ]]; then
    return 0
  fi
  [[ "$path" == "$prefix" || "$path" == "$prefix/"* ]]
}

source_path_allowlist=()

append_source_path_allowlist_prefix() {
  local raw_prefix="$1"
  local normalized_prefix
  local existing_prefix
  normalized_prefix="$(normalize_path_prefix "$raw_prefix")"
  if [[ -z "$normalized_prefix" ]]; then
    return
  fi
  for existing_prefix in "${source_path_allowlist[@]}"; do
    if [[ "$existing_prefix" == "$normalized_prefix" ]]; then
      return
    fi
  done
  source_path_allowlist+=("$normalized_prefix")
}

source_path_requires_allowlist() {
  local source="$1"
  case "$source" in
    roadmap_summary|next_action_command)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

source_path_is_allowlisted() {
  local path="$1"
  local source="$2"
  local allowlist_prefix
  if ! source_path_requires_allowlist "$source"; then
    return 0
  fi
  for allowlist_prefix in "${source_path_allowlist[@]}"; do
    if path_is_within_prefix "$path" "$allowlist_prefix"; then
      return 0
    fi
  done
  return 1
}

normalize_discovered_path() {
  local value
  value="$(strip_wrapping_quotes "${1:-}")"
  if [[ -z "$value" ]]; then
    printf '%s' ""
    return
  fi

  # Keep canonical WSL paths unchanged.
  if [[ "$value" =~ ^/mnt/[A-Za-z]/ ]]; then
    printf '%s' "$value"
    return
  fi

  # Normalize Git-Bash style /c/... to WSL /mnt/c/... when needed.
  if [[ "$value" =~ ^/([A-Za-z])/(.*)$ ]]; then
    local drive="${BASH_REMATCH[1],,}"
    local tail="${BASH_REMATCH[2]}"
    local wsl_path="/mnt/${drive}/${tail}"
    if [[ -e "$wsl_path" && ! -e "$value" ]]; then
      printf '%s' "$wsl_path"
      return
    fi
    printf '%s' "$value"
    return
  fi

  if [[ "$value" =~ ^[A-Za-z]:\\ ]]; then
    if command -v cygpath >/dev/null 2>&1; then
      cygpath -u "$value"
      return
    fi
    local drive="${value:0:1}"
    local tail="${value:2}"
    tail="${tail//\\//}"
    printf '/mnt/%s/%s' "${drive,,}" "${tail#/}"
    return
  fi

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

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
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
need_cmd mktemp
need_cmd mkdir
need_cmd awk
need_cmd cp
need_cmd date
need_cmd basename

reports_dir="${ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_REPORTS_DIR:-.easy-node-logs}"
roadmap_summary_json="${ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_ROADMAP_SUMMARY_JSON:-}"
archive_root="${ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_ARCHIVE_ROOT:-}"
scope="${ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_SCOPE:-auto}"
summary_json="${ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_SUMMARY_JSON:-}"
print_summary_json="${ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_PRINT_SUMMARY_JSON:-1}"

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
    --archive-root)
      require_value_or_die "$1" "${2:-}"
      archive_root="${2:-}"
      shift 2
      ;;
    --scope)
      require_value_or_die "$1" "${2:-}"
      scope="${2:-}"
      shift 2
      ;;
    --summary-json)
      require_value_or_die "$1" "${2:-}"
      summary_json="${2:-}"
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

bool_arg_or_die "--print-summary-json" "$print_summary_json"
scope_arg_or_die "$scope"

reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$roadmap_summary_json" ]]; then
  roadmap_summary_json="$reports_dir/roadmap_progress_summary.json"
fi
if [[ -z "$archive_root" ]]; then
  archive_root="$reports_dir/roadmap_live_evidence_archive"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/roadmap_live_evidence_archive_run_summary.json"
fi

roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
archive_root="$(abs_path "$archive_root")"
summary_json="$(abs_path "$summary_json")"
mkdir -p "$archive_root"
mkdir -p "$(dirname "$summary_json")"

append_source_path_allowlist_prefix "$ROOT_DIR"
append_source_path_allowlist_prefix "$reports_dir"
append_source_path_allowlist_prefix "$(dirname "$roadmap_summary_json")"

if [[ "${#source_path_allowlist[@]}" -gt 0 ]]; then
  source_path_allowlist_json="$(printf '%s\n' "${source_path_allowlist[@]}" | jq -Rsc 'split("\n")[:-1]')"
else
  source_path_allowlist_json='[]'
fi

tmp_dir="$(mktemp -d "$reports_dir/.roadmap_live_evidence_archive_run.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

all_candidates_tsv="$tmp_dir/all_candidates.tsv"
dedup_candidates_tsv="$tmp_dir/dedup_candidates.tsv"
family_results_jsonl="$tmp_dir/family_results.jsonl"
next_action_hints_jsonl="$tmp_dir/next_action_hints.jsonl"
touch "$all_candidates_tsv" "$family_results_jsonl" "$next_action_hints_jsonl"

jsonl_to_array() {
  local path="$1"
  if [[ -s "$path" ]]; then
    jq -s '.' "$path"
  else
    printf '%s\n' '[]'
  fi
}

family_action_ids_json() {
  local family="$1"
  case "$family" in
    profile-default)
      printf '%s\n' '["profile_default_gate","profile_default_gate_evidence_pack"]'
      ;;
    runtime-actuation)
      printf '%s\n' '["runtime_actuation_promotion","runtime_actuation_promotion_evidence_pack"]'
      ;;
    multi-vm)
      printf '%s\n' '["profile_compare_multi_vm_stability","profile_compare_multi_vm_stability_promotion","profile_compare_multi_vm_stability_promotion_evidence_pack"]'
      ;;
    *)
      printf '%s\n' '[]'
      ;;
  esac
}

family_default_hint_command() {
  local family="$1"
  case "$family" in
    profile-default)
      printf '%s' "./scripts/easy_node.sh profile-default-gate-live --reports-dir .easy-node-logs --print-summary-json 1"
      ;;
    runtime-actuation)
      printf '%s' "./scripts/easy_node.sh runtime-actuation-promotion-cycle --reports-dir .easy-node-logs --summary-json .easy-node-logs/runtime_actuation_promotion_cycle_latest_summary.json --print-summary-json 1"
      ;;
    multi-vm)
      printf '%s' "./scripts/easy_node.sh profile-compare-multi-vm-stability-promotion-cycle --reports-dir .easy-node-logs --summary-json .easy-node-logs/profile_compare_multi_vm_stability_promotion_cycle_summary.json --print-summary-json 1"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

extract_summary_paths_from_command() {
  local command
  command="$(trim "${1:-}")"
  local rest="$command"
  local match=""
  local maybe_path=""
  local summary_path_regex="--(summary-json|canonical-summary-json)[[:space:]]+(\"[^\"]+\"|'[^']+'|[^[:space:]]+)"
  while [[ "$rest" =~ $summary_path_regex ]]; do
    match="${BASH_REMATCH[0]}"
    maybe_path="$(strip_wrapping_quotes "${BASH_REMATCH[2]}")"
    maybe_path="$(trim "$maybe_path")"
    if [[ -n "$maybe_path" ]]; then
      printf '%s\n' "$maybe_path"
    fi
    rest="${rest#*"$match"}"
  done
}

add_candidate() {
  local family="$1"
  local raw_path="$2"
  local source="$3"
  local key="$4"
  local normalized
  local absolute

  normalized="$(normalize_discovered_path "$raw_path")"
  normalized="$(trim "$normalized")"
  if [[ -z "$normalized" || "$normalized" == "null" ]]; then
    return 0
  fi

  absolute="$(abs_path "$normalized")"
  if [[ -z "$absolute" ]]; then
    return 0
  fi

  printf '%s\t%s\t%s\t%s\n' "$family" "$absolute" "$source" "$key" >>"$all_candidates_tsv"
}

roadmap_summary_exists=0
roadmap_summary_valid=0
roadmap_summary_contract_state="missing"
roadmap_summary_contract_reason="roadmap summary file is missing"
if [[ -f "$roadmap_summary_json" ]]; then
  roadmap_summary_exists=1
  if jq -e . "$roadmap_summary_json" >/dev/null 2>&1; then
    roadmap_summary_valid=1
    roadmap_summary_status_present="$(jq -r 'if has("status") then 1 else 0 end' "$roadmap_summary_json")"
    roadmap_summary_rc_present="$(jq -r 'if has("rc") then 1 else 0 end' "$roadmap_summary_json")"
    if [[ "$roadmap_summary_status_present" != "1" || "$roadmap_summary_rc_present" != "1" ]]; then
      roadmap_summary_contract_state="invalid"
      roadmap_summary_contract_reason="roadmap summary contract requires both status and rc fields"
    else
      roadmap_summary_status_value="$(jq -r '.status // "" | tostring' "$roadmap_summary_json")"
      roadmap_summary_rc_value="$(jq -r '.rc' "$roadmap_summary_json")"
      if ! [[ "$roadmap_summary_rc_value" =~ ^-?[0-9]+$ ]]; then
        roadmap_summary_contract_state="invalid"
        roadmap_summary_contract_reason="roadmap summary rc must be an integer"
      elif [[ "$roadmap_summary_rc_value" != "0" ]]; then
        roadmap_summary_contract_state="invalid"
        roadmap_summary_contract_reason="roadmap summary contract requires rc=0"
      elif [[ "$roadmap_summary_status_value" != "pass" && "$roadmap_summary_status_value" != "ok" && "$roadmap_summary_status_value" != "warn" ]]; then
        roadmap_summary_contract_state="invalid"
        roadmap_summary_contract_reason="roadmap summary contract requires status in {pass,ok,warn} when rc=0"
      else
        roadmap_summary_contract_state="valid"
        roadmap_summary_contract_reason="status/rc contract satisfied"
      fi
    fi
  else
    roadmap_summary_contract_state="invalid"
    roadmap_summary_contract_reason="roadmap summary JSON is invalid"
  fi
fi

requested_scope="$scope"
resolved_scope="$scope"
scope_inference_reason="explicit scope: $scope"
included_families=()

if [[ "$scope" == "auto" ]]; then
  if [[ "$roadmap_summary_valid" == "1" ]]; then
    auto_family_labels_json="$(jq -c '
      ((.next_actions // []) | map(.id // "")) as $ids
      | [
          (if ($ids | index("profile_default_gate")) != null or ($ids | index("profile_default_gate_evidence_pack")) != null then "profile-default" else empty end),
          (if ($ids | index("runtime_actuation_promotion")) != null or ($ids | index("runtime_actuation_promotion_evidence_pack")) != null then "runtime-actuation" else empty end),
          (if ($ids | index("profile_compare_multi_vm_stability")) != null or ($ids | index("profile_compare_multi_vm_stability_promotion")) != null or ($ids | index("profile_compare_multi_vm_stability_promotion_evidence_pack")) != null then "multi-vm" else empty end)
        ]' "$roadmap_summary_json")"
    auto_family_count="$(printf '%s\n' "$auto_family_labels_json" | jq -r 'length')"
    auto_family_csv="$(printf '%s\n' "$auto_family_labels_json" | jq -r 'join(",")')"
    if (( auto_family_count == 0 )); then
      resolved_scope="none"
      scope_inference_reason="auto: no live-evidence families inferred from roadmap next_actions"
    elif (( auto_family_count == 1 )); then
      resolved_scope="$(printf '%s\n' "$auto_family_labels_json" | jq -r '.[0]')"
      scope_inference_reason="auto: inferred single family ($auto_family_csv) from roadmap next_actions"
    else
      resolved_scope="all"
      scope_inference_reason="auto: inferred mixed families ($auto_family_csv) from roadmap next_actions"
    fi
  else
    resolved_scope="none"
    scope_inference_reason="auto: roadmap summary missing or invalid; no family could be inferred"
  fi
fi

case "$resolved_scope" in
  profile-default)
    included_families=("profile-default")
    ;;
  runtime-actuation)
    included_families=("runtime-actuation")
    ;;
  multi-vm)
    included_families=("multi-vm")
    ;;
  all)
    included_families=("profile-default" "runtime-actuation" "multi-vm")
    ;;
  none)
    included_families=()
    ;;
  *)
    echo "internal error: unexpected resolved scope '$resolved_scope'"
    exit 2
    ;;
esac

roadmap_summary_fail_closed="0"
if [[ "$roadmap_summary_contract_state" != "valid" ]]; then
  roadmap_summary_fail_closed="1"
  echo "[roadmap-live-evidence-archive-run] stage=roadmap_summary_contract status=fail reason=$roadmap_summary_contract_reason"
fi

collect_roadmap_paths_for_family() {
  local family="$1"
  if [[ "$roadmap_summary_valid" != "1" ]]; then
    return 0
  fi

  case "$family" in
    profile-default)
      add_candidate "$family" "$(jq -r '.vpn_track.profile_default_gate.summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "vpn_track.profile_default_gate.summary_json"
      add_candidate "$family" "$(jq -r '.vpn_track.profile_default_gate.campaign_check_summary_json_resolved // empty' "$roadmap_summary_json")" "roadmap_summary" "vpn_track.profile_default_gate.campaign_check_summary_json_resolved"
      add_candidate "$family" "$(jq -r '.vpn_track.profile_default_gate.stability_summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "vpn_track.profile_default_gate.stability_summary_json"
      add_candidate "$family" "$(jq -r '.vpn_track.profile_default_gate.stability_check_summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "vpn_track.profile_default_gate.stability_check_summary_json"
      add_candidate "$family" "$(jq -r '.vpn_track.profile_default_gate.cycle_summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "vpn_track.profile_default_gate.cycle_summary_json"
      add_candidate "$family" "$(jq -r '.artifacts.profile_compare_signoff_summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "artifacts.profile_compare_signoff_summary_json"
      add_candidate "$family" "$(jq -r '.artifacts.profile_default_gate_evidence_pack_summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "artifacts.profile_default_gate_evidence_pack_summary_json"
      ;;
    runtime-actuation)
      add_candidate "$family" "$(jq -r '.artifacts.runtime_actuation_promotion_summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "artifacts.runtime_actuation_promotion_summary_json"
      add_candidate "$family" "$(jq -r '.artifacts.runtime_actuation_promotion_evidence_pack_summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "artifacts.runtime_actuation_promotion_evidence_pack_summary_json"
      ;;
    multi-vm)
      add_candidate "$family" "$(jq -r '.vpn_track.multi_vm_stability.input_summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "vpn_track.multi_vm_stability.input_summary_json"
      add_candidate "$family" "$(jq -r '.vpn_track.multi_vm_stability.source_summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "vpn_track.multi_vm_stability.source_summary_json"
      add_candidate "$family" "$(jq -r '.artifacts.profile_compare_multi_vm_stability_summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "artifacts.profile_compare_multi_vm_stability_summary_json"
      add_candidate "$family" "$(jq -r '.artifacts.profile_compare_multi_vm_stability_promotion_summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "artifacts.profile_compare_multi_vm_stability_promotion_summary_json"
      add_candidate "$family" "$(jq -r '.artifacts.profile_compare_multi_vm_stability_promotion_evidence_pack_summary_json // empty' "$roadmap_summary_json")" "roadmap_summary" "artifacts.profile_compare_multi_vm_stability_promotion_evidence_pack_summary_json"
      ;;
  esac

  while IFS=$'\t' read -r action_id action_command; do
    [[ -z "${action_command:-}" ]] && continue
    while IFS= read -r maybe_path; do
      [[ -z "$maybe_path" ]] && continue
      add_candidate "$family" "$maybe_path" "next_action_command" "next_actions[$action_id]"
    done < <(extract_summary_paths_from_command "$action_command")
  done < <(jq -r --argjson ids "$(family_action_ids_json "$family")" '
    (.next_actions // [])[]
    | select((.id // "") as $id | ($ids | index($id)) != null)
    | [(.id // ""), (.command // "")]
    | @tsv' "$roadmap_summary_json")
}

collect_fallback_paths_for_family() {
  local family="$1"
  local base="$reports_dir"
  case "$family" in
    profile-default)
      add_candidate "$family" "$base/profile_compare_campaign_signoff_summary.json" "default_fallback" "reports_dir.profile_compare_campaign_signoff_summary_json"
      add_candidate "$family" "$base/profile_default_gate_stability_summary.json" "default_fallback" "reports_dir.profile_default_gate_stability_summary_json"
      add_candidate "$family" "$base/profile_default_gate_stability_check_summary.json" "default_fallback" "reports_dir.profile_default_gate_stability_check_summary_json"
      add_candidate "$family" "$base/profile_default_gate_stability_cycle_summary.json" "default_fallback" "reports_dir.profile_default_gate_stability_cycle_summary_json"
      add_candidate "$family" "$base/profile_default_gate_evidence_pack_summary.json" "default_fallback" "reports_dir.profile_default_gate_evidence_pack_summary_json"
      ;;
    runtime-actuation)
      add_candidate "$family" "$base/runtime_actuation_promotion_cycle_latest_summary.json" "default_fallback" "reports_dir.runtime_actuation_promotion_cycle_latest_summary_json"
      add_candidate "$family" "$base/runtime_actuation_promotion_summary.json" "default_fallback" "reports_dir.runtime_actuation_promotion_summary_json"
      add_candidate "$family" "$base/runtime_actuation_promotion_evidence_pack_summary.json" "default_fallback" "reports_dir.runtime_actuation_promotion_evidence_pack_summary_json"
      ;;
    multi-vm)
      add_candidate "$family" "$base/profile_compare_multi_vm_stability_check_summary.json" "default_fallback" "reports_dir.profile_compare_multi_vm_stability_check_summary_json"
      add_candidate "$family" "$base/profile_compare_multi_vm_stability_cycle_summary.json" "default_fallback" "reports_dir.profile_compare_multi_vm_stability_cycle_summary_json"
      add_candidate "$family" "$base/profile_compare_multi_vm_stability_promotion_cycle_summary.json" "default_fallback" "reports_dir.profile_compare_multi_vm_stability_promotion_cycle_summary_json"
      add_candidate "$family" "$base/profile_compare_multi_vm_stability_summary.json" "default_fallback" "reports_dir.profile_compare_multi_vm_stability_summary_json"
      add_candidate "$family" "$base/profile_compare_multi_vm_stability_promotion_summary.json" "default_fallback" "reports_dir.profile_compare_multi_vm_stability_promotion_summary_json"
      add_candidate "$family" "$base/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json" "default_fallback" "reports_dir.profile_compare_multi_vm_stability_promotion_evidence_pack_summary_json"
      ;;
  esac
}

count_candidates_for_family() {
  local family="$1"
  if [[ ! -s "$all_candidates_tsv" ]]; then
    printf '0'
    return
  fi
  awk -F'\t' -v family="$family" '
    $1 == family { count += 1 }
    END { printf "%d", count + 0 }
  ' "$all_candidates_tsv"
}

for family in "${included_families[@]}"; do
  before_count="$(count_candidates_for_family "$family")"
  collect_roadmap_paths_for_family "$family"
  after_count="$(count_candidates_for_family "$family")"
  if [[ "$after_count" == "$before_count" ]]; then
    collect_fallback_paths_for_family "$family"
  fi
done

if [[ -s "$all_candidates_tsv" ]]; then
  awk -F'\t' '!seen[$1 FS $2]++ { print }' "$all_candidates_tsv" >"$dedup_candidates_tsv"
else
  : >"$dedup_candidates_tsv"
fi

if [[ "$roadmap_summary_fail_closed" == "1" ]]; then
  : >"$dedup_candidates_tsv"
fi

archive_stamp="$(date -u +%Y%m%d_%H%M%S)"
archive_dir="$archive_root/roadmap_live_evidence_archive_${archive_stamp}"
mkdir -p "$archive_dir"

candidate_total=0
copied_total=0
missing_total=0
copy_error_total=0
source_path_reject_total=0
missing_family_count=0
included_family_count="${#included_families[@]}"

build_next_action_hints_json() {
  local family="$1"
  if [[ "$roadmap_summary_valid" == "1" ]]; then
    local hints_from_roadmap
    hints_from_roadmap="$(jq -c --arg family "$family" --argjson ids "$(family_action_ids_json "$family")" '
      [
        (.next_actions // [])[]
        | select((.id // "") as $id | ($ids | index($id)) != null)
        | {
            family: $family,
            id: (.id // ""),
            label: (.label // ""),
            command: (.command // ""),
            reason: (.reason // "")
          }
      ]' "$roadmap_summary_json")"
    if [[ "$(printf '%s\n' "$hints_from_roadmap" | jq -r 'length')" != "0" ]]; then
      printf '%s\n' "$hints_from_roadmap"
      return
    fi
  fi

  jq -nc --arg family "$family" --arg command "$(family_default_hint_command "$family")" '
    [
      {
        family: $family,
        id: "",
        label: "Default operator action",
        command: $command,
        reason: "No family-specific roadmap next_action entry was available in the provided summary."
      }
    ]'
}

for family in "profile-default" "runtime-actuation" "multi-vm"; do
  included_flag=0
  for selected_family in "${included_families[@]}"; do
    if [[ "$selected_family" == "$family" ]]; then
      included_flag=1
      break
    fi
  done

  family_candidates_tsv="$tmp_dir/family_${family//-/_}_candidates.tsv"
  family_candidates_jsonl="$tmp_dir/family_${family//-/_}_candidates.jsonl"
  family_copied_jsonl="$tmp_dir/family_${family//-/_}_copied.jsonl"
  family_missing_jsonl="$tmp_dir/family_${family//-/_}_missing.jsonl"
  family_copy_errors_jsonl="$tmp_dir/family_${family//-/_}_copy_errors.jsonl"
  touch "$family_candidates_tsv" "$family_candidates_jsonl" "$family_copied_jsonl" "$family_missing_jsonl" "$family_copy_errors_jsonl"

  if [[ "$included_flag" == "1" ]]; then
    awk -F'\t' -v family="$family" '$1 == family { print }' "$dedup_candidates_tsv" >"$family_candidates_tsv"
  fi

  family_candidate_count=0
  family_copied_count=0
  family_missing_count=0
  family_copy_error_count=0
  family_source_path_reject_count=0

  if [[ "$included_flag" == "1" && -s "$family_candidates_tsv" ]]; then
    family_candidate_count="$(wc -l <"$family_candidates_tsv" | tr -d '[:space:]')"
    candidate_total=$((candidate_total + family_candidate_count))
    mkdir -p "$archive_dir/$family"

    while IFS=$'\t' read -r _family path source key; do
      [[ -z "$path" ]] && continue
      jq -nc --arg family "$family" --arg path "$path" --arg source "$source" --arg key "$key" \
        '{family: $family, path: $path, source: $source, key: $key}' >>"$family_candidates_jsonl"

      if [[ -f "$path" ]]; then
        resolved_source_path="$path"
        canonical_source_path="$(canonicalize_existing_path "$path" || true)"
        if [[ -n "$canonical_source_path" ]]; then
          resolved_source_path="$canonical_source_path"
        fi

        if ! source_path_is_allowlisted "$resolved_source_path" "$source"; then
          family_copy_error_count=$((family_copy_error_count + 1))
          copy_error_total=$((copy_error_total + 1))
          family_source_path_reject_count=$((family_source_path_reject_count + 1))
          source_path_reject_total=$((source_path_reject_total + 1))
          echo "[roadmap-live-evidence-archive-run] stage=source_path_allowlist status=fail family=$family source=$source path=$path resolved_path=$resolved_source_path"
          jq -nc \
            --arg family "$family" \
            --arg path "$path" \
            --arg resolved_path "$resolved_source_path" \
            --arg source "$source" \
            --arg key "$key" \
            --arg reason "source_path_out_of_scope" \
            --argjson allowlist_prefixes "$source_path_allowlist_json" \
            '{
              family: $family,
              path: $path,
              resolved_path: $resolved_path,
              source: $source,
              key: $key,
              reason: $reason,
              allowlist_prefixes: $allowlist_prefixes
            }' >>"$family_copy_errors_jsonl"
          continue
        fi

        destination_base="$(basename "$resolved_source_path")"
        destination="$archive_dir/$family/$destination_base"
        if [[ -e "$destination" ]]; then
          stem="$destination_base"
          extension=""
          if [[ "$destination_base" == *.* ]]; then
            stem="${destination_base%.*}"
            extension=".${destination_base##*.}"
          fi
          suffix=2
          while [[ -e "$archive_dir/$family/${stem}_${suffix}${extension}" ]]; do
            suffix=$((suffix + 1))
          done
          destination="$archive_dir/$family/${stem}_${suffix}${extension}"
        fi

        if cp -f "$resolved_source_path" "$destination"; then
          family_copied_count=$((family_copied_count + 1))
          copied_total=$((copied_total + 1))
          jq -nc --arg family "$family" --arg path "$path" --arg source "$source" --arg key "$key" --arg archive_path "$destination" \
            '{family: $family, path: $path, source: $source, key: $key, archive_path: $archive_path}' >>"$family_copied_jsonl"
        else
          family_copy_error_count=$((family_copy_error_count + 1))
          copy_error_total=$((copy_error_total + 1))
          jq -nc --arg family "$family" --arg path "$path" --arg source "$source" --arg key "$key" --arg reason "copy_failed" \
            '{family: $family, path: $path, source: $source, key: $key, reason: $reason}' >>"$family_copy_errors_jsonl"
        fi
      else
        family_missing_count=$((family_missing_count + 1))
        missing_total=$((missing_total + 1))
        jq -nc --arg family "$family" --arg path "$path" --arg source "$source" --arg key "$key" --arg reason "missing_source_file" \
          '{family: $family, path: $path, source: $source, key: $key, reason: $reason}' >>"$family_missing_jsonl"
      fi
    done <"$family_candidates_tsv"
  fi

  family_hints_json='[]'
  if [[ "$included_flag" == "1" && "$family_copied_count" -eq 0 ]]; then
    missing_family_count=$((missing_family_count + 1))
    family_hints_json="$(build_next_action_hints_json "$family")"
    if [[ "$(printf '%s\n' "$family_hints_json" | jq -r 'length')" != "0" ]]; then
      while IFS= read -r hint_line; do
        printf '%s\n' "$hint_line" >>"$next_action_hints_jsonl"
      done < <(printf '%s\n' "$family_hints_json" | jq -c '.[]')
    fi
  fi

  family_status="skipped"
  if [[ "$included_flag" == "1" ]]; then
    if (( family_copied_count == 0 )); then
      family_status="fail"
    elif (( family_missing_count > 0 || family_copy_error_count > 0 )); then
      family_status="fail"
    else
      family_status="pass"
    fi
  fi

  jq -nc \
    --arg family "$family" \
    --argjson included "$included_flag" \
    --arg status "$family_status" \
    --argjson candidate_count "$family_candidate_count" \
    --argjson copied_count "$family_copied_count" \
    --argjson missing_count "$family_missing_count" \
    --argjson copy_error_count "$family_copy_error_count" \
    --argjson source_path_reject_count "$family_source_path_reject_count" \
    --argjson candidates "$(jsonl_to_array "$family_candidates_jsonl")" \
    --argjson copied "$(jsonl_to_array "$family_copied_jsonl")" \
    --argjson missing "$(jsonl_to_array "$family_missing_jsonl")" \
    --argjson copy_errors "$(jsonl_to_array "$family_copy_errors_jsonl")" \
    --argjson next_action_hints "$family_hints_json" \
    '{
      family: $family,
      included: ($included == 1),
      status: $status,
      candidate_count: $candidate_count,
      copied_count: $copied_count,
      missing_count: $missing_count,
      copy_error_count: $copy_error_count,
      source_path_reject_count: $source_path_reject_count,
      candidates: $candidates,
      copied: $copied,
      missing: $missing,
      copy_errors: $copy_errors,
      next_action_hints: $next_action_hints
    }' >>"$family_results_jsonl"
done

if [[ "${#included_families[@]}" -gt 0 ]]; then
  included_families_json="$(printf '%s\n' "${included_families[@]}" | jq -Rsc 'split("\n")[:-1]')"
else
  included_families_json='[]'
fi

final_status="pass"
final_rc=0
final_reason="all selected artifact families were archived without missing files"
failure_substep=""
if [[ "$roadmap_summary_fail_closed" == "1" ]]; then
  final_status="fail"
  final_rc=4
  final_reason="$roadmap_summary_contract_reason"
  failure_substep="roadmap_summary_contract_invalid"
elif (( included_family_count == 0 )); then
  final_status="fail"
  final_rc=1
  final_reason="no artifact family was selected for archiving"
  failure_substep="scope_selected_no_families"
elif (( copied_total == 0 )); then
  final_status="fail"
  final_rc=1
  final_reason="no artifacts were copied for selected families"
  failure_substep="selected_families_no_artifacts_copied"
elif (( missing_total > 0 || copy_error_total > 0 || missing_family_count > 0 )); then
  final_status="fail"
  final_rc=1
  final_reason="archive completed with missing artifacts or copy errors"
  failure_substep="archive_copy_incomplete"
fi

included_families_csv="$(printf '%s\n' "$included_families_json" | jq -r 'join(",")')"
if [[ -z "$included_families_csv" ]]; then
  included_families_csv="none"
fi

echo "[roadmap-live-evidence-archive-run] scope=$requested_scope resolved_scope=$resolved_scope included_families=$included_families_csv candidate_total=$candidate_total copied_total=$copied_total missing_total=$missing_total copy_error_total=$copy_error_total source_path_reject_total=$source_path_reject_total missing_family_count=$missing_family_count status=$final_status failure_substep=${failure_substep:-none}"
if [[ "$final_status" == "fail" && -n "$failure_substep" ]]; then
  echo "[roadmap-live-evidence-archive-run] fail_substep=$failure_substep reason=$final_reason"
fi

command_display="$(render_invocation_command "./scripts/roadmap_live_evidence_archive_run.sh" "${original_args[@]}")"

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reason "$final_reason" \
  --arg failure_substep "$failure_substep" \
  --arg command "$command_display" \
  --arg reports_dir "$reports_dir" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg archive_root "$archive_root" \
  --arg archive_dir "$archive_dir" \
  --arg summary_json "$summary_json" \
  --arg requested_scope "$requested_scope" \
  --arg resolved_scope "$resolved_scope" \
  --arg scope_inference_reason "$scope_inference_reason" \
  --argjson roadmap_summary_exists "$roadmap_summary_exists" \
  --argjson roadmap_summary_valid "$roadmap_summary_valid" \
  --arg roadmap_summary_contract_state "$roadmap_summary_contract_state" \
  --arg roadmap_summary_contract_reason "$roadmap_summary_contract_reason" \
  --argjson included_families "$included_families_json" \
  --argjson included_family_count "$included_family_count" \
  --argjson candidate_total "$candidate_total" \
  --argjson copied_total "$copied_total" \
  --argjson missing_total "$missing_total" \
  --argjson copy_error_total "$copy_error_total" \
  --argjson source_path_reject_total "$source_path_reject_total" \
  --argjson missing_family_count "$missing_family_count" \
  --argjson source_path_allowlist "$source_path_allowlist_json" \
  --argjson family_results "$(jsonl_to_array "$family_results_jsonl")" \
  --argjson next_action_hints "$(jsonl_to_array "$next_action_hints_jsonl")" \
  '{
    version: 1,
    schema: { id: "roadmap_live_evidence_archive_run_summary", major: 1, minor: 0 },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    reason: $reason,
    failure_substep: (if $failure_substep == "" then null else $failure_substep end),
    command: $command,
    inputs: {
      requested_scope: $requested_scope,
      resolved_scope: $resolved_scope,
      scope_inference_reason: $scope_inference_reason
    },
    roadmap: {
      summary_json: $roadmap_summary_json,
      summary_exists: ($roadmap_summary_exists == 1),
      summary_valid: ($roadmap_summary_valid == 1),
      summary_contract_state: $roadmap_summary_contract_state,
      summary_contract_reason: $roadmap_summary_contract_reason
    },
    scope: {
      requested: $requested_scope,
      resolved: $resolved_scope,
      inference_reason: $scope_inference_reason,
      included_families: $included_families,
      included_family_count: $included_family_count
    },
    summary: {
      candidate_total: $candidate_total,
      copied_total: $copied_total,
      missing_total: $missing_total,
      copy_error_total: $copy_error_total,
      source_path_reject_total: $source_path_reject_total,
      missing_family_count: $missing_family_count
    },
    path_safety: {
      source_path_allowlist: $source_path_allowlist,
      enforced_candidate_sources: ["roadmap_summary", "next_action_command"]
    },
    family_results: $family_results,
    next_action_hints: $next_action_hints,
    artifacts: {
      reports_dir: $reports_dir,
      archive_root: $archive_root,
      archive_dir: $archive_dir,
      summary_json: $summary_json
    }
  }' >"$summary_json"

echo "[roadmap-live-evidence-archive-run] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
