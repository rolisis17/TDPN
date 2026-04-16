#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase5_settlement_layer_summary_report.sh \
    [--reports-dir DIR] \
    [--ci-summary-json PATH] \
    [--check-summary-json PATH] \
    [--run-summary-json PATH] \
    [--handoff-check-summary-json PATH] \
    [--handoff-run-summary-json PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Build one compact Phase-5 settlement operator summary from existing summary
  artifacts:
    - ci_phase5_settlement_layer_summary
    - phase5_settlement_layer_check_summary
    - phase5_settlement_layer_run_summary
    - phase5_settlement_layer_handoff_check_summary
    - phase5_settlement_layer_handoff_run_summary

Notes:
  - If no stage summary paths are explicitly provided, the helper probes
    canonical files under --reports-dir.
  - If canonical files are missing, timestamped fallback discovery is used.
    This includes at least ci and handoff-run stage families.
  - If one or more stage summary paths are explicitly provided, only those are
    evaluated.
  - Exit codes:
      0: pass (at least one summary passed and none failed/invalid)
      1: fail or missing-only
      2: usage/argument error
USAGE
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
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

array_to_json() {
  local -n arr_ref=$1
  if ((${#arr_ref[@]} == 0)); then
    printf '%s' "[]"
    return
  fi
  printf '%s\n' "${arr_ref[@]}" | jq -R . | jq -s .
}

display_stage_name() {
  case "${1:-}" in
    ci_phase5_settlement_layer) printf '%s' "ci_phase5_settlement_layer" ;;
    phase5_settlement_layer_check) printf '%s' "phase5_settlement_layer_check" ;;
    phase5_settlement_layer_run) printf '%s' "phase5_settlement_layer_run" ;;
    phase5_settlement_layer_handoff_check) printf '%s' "phase5_settlement_layer_handoff_check" ;;
    phase5_settlement_layer_handoff_run) printf '%s' "phase5_settlement_layer_handoff_run" ;;
    *) printf '%s' "${1:-unknown}" ;;
  esac
}

discover_latest_stage_summary() {
  local base_dir="$1"
  local dir_prefix="$2"
  local summary_filename="$3"
  local dir_name_re
  local dir

  dir_name_re="^${dir_prefix}[0-9]{8}_[0-9]{6}$"

  local -a timestamp_candidates=()
  shopt -s nullglob
  for dir in "$base_dir"/"${dir_prefix}"*; do
    [[ -d "$dir" ]] || continue
    if [[ "$(basename "$dir")" =~ $dir_name_re && -f "$dir/$summary_filename" ]]; then
      timestamp_candidates+=("$(basename "$dir")|$dir/$summary_filename")
    fi
  done
  shopt -u nullglob

  if ((${#timestamp_candidates[@]} > 0)); then
    printf '%s\n' "${timestamp_candidates[@]}" | LC_ALL=C sort | tail -n 1 | cut -d'|' -f2-
    return 0
  fi

  local -a mtime_candidates=()
  local summary_path
  while IFS= read -r summary_path; do
    [[ -n "$summary_path" ]] || continue
    local mtime
    mtime="$(stat -c %Y "$summary_path" 2>/dev/null || stat -f %m "$summary_path" 2>/dev/null || true)"
    if [[ "$mtime" =~ ^[0-9]+$ ]]; then
      mtime_candidates+=("${mtime}|${summary_path}")
    fi
  done < <(find "$base_dir" -maxdepth 2 -type f -name "$summary_filename" -path "$base_dir/${dir_prefix}*/$summary_filename" 2>/dev/null | LC_ALL=C sort)

  if ((${#mtime_candidates[@]} > 0)); then
    printf '%s\n' "${mtime_candidates[@]}" | LC_ALL=C sort -t'|' -k1,1n -k2,2 | tail -n 1 | cut -d'|' -f2-
    return 0
  fi

  return 1
}

resolve_path_with_base() {
  local candidate="${1:-}"
  local base_file="${2:-}"
  local base_dir=""
  if [[ -z "$candidate" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$candidate" == /* ]]; then
    printf '%s' "$candidate"
    return
  fi
  if [[ -n "$base_file" ]]; then
    base_dir="$(cd "$(dirname "$base_file")" && pwd)"
    if [[ -f "$base_dir/$candidate" ]]; then
      printf '%s' "$base_dir/$candidate"
      return
    fi
  fi
  printf '%s' "$ROOT_DIR/$candidate"
}

json_file_valid_01() {
  local path="${1:-}"
  if [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

json_text_or_empty() {
  local path="${1:-}"
  local expr="${2:-}"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  jq -r "($expr) | if . == null then empty else . end" "$path" 2>/dev/null || true
}

json_bool_or_empty() {
  local path="${1:-}"
  local expr="${2:-}"
  local value=""
  value="$(json_text_or_empty "$path" "$expr")"
  case "$value" in
    true|false)
      printf '%s' "$value"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

resolve_sponsor_from_handoff_or_check_summary() {
  local summary_path="${1:-}"
  if [[ "$(json_file_valid_01 "$summary_path")" != "1" ]]; then
    return 1
  fi

  local value=""
  local status=""
  local source_field=""
  local status_text=""

  value="$(json_bool_or_empty "$summary_path" '
    if (.handoff.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then .handoff.issuer_sponsor_api_live_smoke_ok
    elif (.signals.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then .signals.issuer_sponsor_api_live_smoke_ok
    elif (.stages.issuer_sponsor_api_live_smoke.ok | type) == "boolean" then .stages.issuer_sponsor_api_live_smoke.ok
    elif (.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then .phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok
    elif (.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok
    else empty
    end
  ')"
  if [[ -n "$value" ]]; then
    source_field="$(json_text_or_empty "$summary_path" '
      if (.handoff.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then "handoff.issuer_sponsor_api_live_smoke_ok"
      elif (.signals.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then "signals.issuer_sponsor_api_live_smoke_ok"
      elif (.stages.issuer_sponsor_api_live_smoke.ok | type) == "boolean" then "stages.issuer_sponsor_api_live_smoke.ok"
      elif (.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then "phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok"
      elif (.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then "vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok"
      else empty
      end
    ')"
    if [[ "$value" == "true" ]]; then
      status="pass"
    else
      status="fail"
    fi
    printf '%s|%s|%s\n' "$value" "$status" "$source_field"
    return 0
  fi

  status_text="$(json_text_or_empty "$summary_path" '
    if (.handoff.issuer_sponsor_api_live_smoke_status | type) == "string" then .handoff.issuer_sponsor_api_live_smoke_status
    elif (.stages.issuer_sponsor_api_live_smoke.status | type) == "string" then .stages.issuer_sponsor_api_live_smoke.status
    elif (.steps.issuer_sponsor_api_live_smoke.status | type) == "string" then .steps.issuer_sponsor_api_live_smoke.status
    else empty
    end
  ')"
  case "${status_text,,}" in
    pass)
      value="true"
      status="pass"
      ;;
    fail)
      value="false"
      status="fail"
      ;;
    *)
      return 1
      ;;
  esac

  source_field="$(json_text_or_empty "$summary_path" '
    if (.handoff.issuer_sponsor_api_live_smoke_status | type) == "string" then "handoff.issuer_sponsor_api_live_smoke_status"
    elif (.stages.issuer_sponsor_api_live_smoke.status | type) == "string" then "stages.issuer_sponsor_api_live_smoke.status"
    elif (.steps.issuer_sponsor_api_live_smoke.status | type) == "string" then "steps.issuer_sponsor_api_live_smoke.status"
    else empty
    end
  ')"

  printf '%s|%s|%s\n' "$value" "$status" "$source_field"
  return 0
}

resolve_sponsor_from_ci_summary() {
  local summary_path="${1:-}"
  if [[ "$(json_file_valid_01 "$summary_path")" != "1" ]]; then
    return 1
  fi

  local value=""
  local status=""
  local source_field=""
  local status_text=""

  value="$(json_bool_or_empty "$summary_path" '
    if (.signals.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then .signals.issuer_sponsor_api_live_smoke_ok
    elif (.steps.issuer_sponsor_api_live_smoke.ok | type) == "boolean" then .steps.issuer_sponsor_api_live_smoke.ok
    else empty
    end
  ')"
  if [[ -n "$value" ]]; then
    source_field="$(json_text_or_empty "$summary_path" '
      if (.signals.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then "signals.issuer_sponsor_api_live_smoke_ok"
      elif (.steps.issuer_sponsor_api_live_smoke.ok | type) == "boolean" then "steps.issuer_sponsor_api_live_smoke.ok"
      else empty
      end
    ')"
    if [[ "$value" == "true" ]]; then
      status="pass"
    else
      status="fail"
    fi
    printf '%s|%s|%s\n' "$value" "$status" "$source_field"
    return 0
  fi

  status_text="$(json_text_or_empty "$summary_path" '
    if (.steps.issuer_sponsor_api_live_smoke.status | type) == "string" then .steps.issuer_sponsor_api_live_smoke.status
    elif (.stages.issuer_sponsor_api_live_smoke.status | type) == "string" then .stages.issuer_sponsor_api_live_smoke.status
    else empty
    end
  ')"
  case "${status_text,,}" in
    pass)
      value="true"
      status="pass"
      ;;
    fail)
      value="false"
      status="fail"
      ;;
    *)
      return 1
      ;;
  esac

  source_field="$(json_text_or_empty "$summary_path" '
    if (.steps.issuer_sponsor_api_live_smoke.status | type) == "string" then "steps.issuer_sponsor_api_live_smoke.status"
    elif (.stages.issuer_sponsor_api_live_smoke.status | type) == "string" then "stages.issuer_sponsor_api_live_smoke.status"
    else empty
    end
  ')"

  printf '%s|%s|%s\n' "$value" "$status" "$source_field"
  return 0
}

resolve_dual_asset_from_handoff_or_check_summary() {
  local summary_path="${1:-}"
  if [[ "$(json_file_valid_01 "$summary_path")" != "1" ]]; then
    return 1
  fi

  local value=""
  local status=""
  local source_field=""
  local status_text=""

  value="$(json_bool_or_empty "$summary_path" '
    if (.handoff.settlement_dual_asset_parity_ok | type) == "boolean" then .handoff.settlement_dual_asset_parity_ok
    elif (.signals.settlement_dual_asset_parity_ok | type) == "boolean" then .signals.settlement_dual_asset_parity_ok
    elif (.stages.settlement_dual_asset_parity.ok | type) == "boolean" then .stages.settlement_dual_asset_parity.ok
    elif (.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok | type) == "boolean" then .phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok
    elif (.vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok
    else empty
    end
  ')"
  if [[ -n "$value" ]]; then
    source_field="$(json_text_or_empty "$summary_path" '
      if (.handoff.settlement_dual_asset_parity_ok | type) == "boolean" then "handoff.settlement_dual_asset_parity_ok"
      elif (.signals.settlement_dual_asset_parity_ok | type) == "boolean" then "signals.settlement_dual_asset_parity_ok"
      elif (.stages.settlement_dual_asset_parity.ok | type) == "boolean" then "stages.settlement_dual_asset_parity.ok"
      elif (.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok | type) == "boolean" then "phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok"
      elif (.vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok | type) == "boolean" then "vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok"
      else empty
      end
    ')"
    if [[ "$value" == "true" ]]; then
      status="pass"
    else
      status="fail"
    fi
    printf '%s|%s|%s\n' "$value" "$status" "$source_field"
    return 0
  fi

  status_text="$(json_text_or_empty "$summary_path" '
    if (.handoff.settlement_dual_asset_parity_status | type) == "string" then .handoff.settlement_dual_asset_parity_status
    elif (.stages.settlement_dual_asset_parity.status | type) == "string" then .stages.settlement_dual_asset_parity.status
    elif (.steps.settlement_dual_asset_parity.status | type) == "string" then .steps.settlement_dual_asset_parity.status
    else empty
    end
  ')"
  case "${status_text,,}" in
    pass)
      value="true"
      status="pass"
      ;;
    fail)
      value="false"
      status="fail"
      ;;
    *)
      return 1
      ;;
  esac

  source_field="$(json_text_or_empty "$summary_path" '
    if (.handoff.settlement_dual_asset_parity_status | type) == "string" then "handoff.settlement_dual_asset_parity_status"
    elif (.stages.settlement_dual_asset_parity.status | type) == "string" then "stages.settlement_dual_asset_parity.status"
    elif (.steps.settlement_dual_asset_parity.status | type) == "string" then "steps.settlement_dual_asset_parity.status"
    else empty
    end
  ')"

  printf '%s|%s|%s\n' "$value" "$status" "$source_field"
  return 0
}

resolve_dual_asset_from_ci_summary() {
  local summary_path="${1:-}"
  if [[ "$(json_file_valid_01 "$summary_path")" != "1" ]]; then
    return 1
  fi

  local value=""
  local status=""
  local source_field=""
  local status_text=""

  value="$(json_bool_or_empty "$summary_path" '
    if (.signals.settlement_dual_asset_parity_ok | type) == "boolean" then .signals.settlement_dual_asset_parity_ok
    elif (.steps.settlement_dual_asset_parity.ok | type) == "boolean" then .steps.settlement_dual_asset_parity.ok
    else empty
    end
  ')"
  if [[ -n "$value" ]]; then
    source_field="$(json_text_or_empty "$summary_path" '
      if (.signals.settlement_dual_asset_parity_ok | type) == "boolean" then "signals.settlement_dual_asset_parity_ok"
      elif (.steps.settlement_dual_asset_parity.ok | type) == "boolean" then "steps.settlement_dual_asset_parity.ok"
      else empty
      end
    ')"
    if [[ "$value" == "true" ]]; then
      status="pass"
    else
      status="fail"
    fi
    printf '%s|%s|%s\n' "$value" "$status" "$source_field"
    return 0
  fi

  status_text="$(json_text_or_empty "$summary_path" '
    if (.steps.settlement_dual_asset_parity.status | type) == "string" then .steps.settlement_dual_asset_parity.status
    elif (.stages.settlement_dual_asset_parity.status | type) == "string" then .stages.settlement_dual_asset_parity.status
    else empty
    end
  ')"
  case "${status_text,,}" in
    pass)
      value="true"
      status="pass"
      ;;
    fail)
      value="false"
      status="fail"
      ;;
    *)
      return 1
      ;;
  esac

  source_field="$(json_text_or_empty "$summary_path" '
    if (.steps.settlement_dual_asset_parity.status | type) == "string" then "steps.settlement_dual_asset_parity.status"
    elif (.stages.settlement_dual_asset_parity.status | type) == "string" then "stages.settlement_dual_asset_parity.status"
    else empty
    end
  ')"

  printf '%s|%s|%s\n' "$value" "$status" "$source_field"
  return 0
}

resolve_artifact_summary_path() {
  local summary_path="${1:-}"
  local expr="${2:-}"
  local nested_path=""
  if [[ "$(json_file_valid_01 "$summary_path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  nested_path="$(json_text_or_empty "$summary_path" "$expr")"
  if [[ -z "$nested_path" ]]; then
    printf '%s' ""
    return
  fi
  printf '%s' "$(resolve_path_with_base "$nested_path" "$summary_path")"
}

resolve_sponsor_live_smoke_signal() {
  local handoff_check_summary_path="${1:-}"
  local handoff_run_summary_path="${2:-}"
  local check_summary_path="${3:-}"
  local run_summary_path="${4:-}"
  local ci_summary_path="${5:-}"

  local parsed=""
  local value=""
  local status=""
  local source_field=""
  local fallback_path=""

  parsed="$(resolve_sponsor_from_handoff_or_check_summary "$handoff_check_summary_path" || true)"
  if [[ -n "$parsed" ]]; then
    value="${parsed%%|*}"
    parsed="${parsed#*|}"
    status="${parsed%%|*}"
    source_field="${parsed#*|}"
    printf '%s|%s|1|phase5_settlement_layer_handoff_check_summary|%s|%s|0|1\n' "$value" "$status" "$source_field" "$handoff_check_summary_path"
    return
  fi

  fallback_path="$(resolve_artifact_summary_path "$handoff_run_summary_path" '.steps.phase5_settlement_layer_handoff_check.artifacts.summary_json // .artifacts.handoff_summary_json // empty')"
  parsed="$(resolve_sponsor_from_handoff_or_check_summary "$fallback_path" || true)"
  if [[ -n "$parsed" ]]; then
    value="${parsed%%|*}"
    parsed="${parsed#*|}"
    status="${parsed%%|*}"
    source_field="${parsed#*|}"
    printf '%s|%s|1|phase5_settlement_layer_handoff_run_summary.artifacts.handoff_summary_json|%s|%s|1|2\n' "$value" "$status" "$source_field" "$fallback_path"
    return
  fi

  parsed="$(resolve_sponsor_from_handoff_or_check_summary "$check_summary_path" || true)"
  if [[ -n "$parsed" ]]; then
    value="${parsed%%|*}"
    parsed="${parsed#*|}"
    status="${parsed%%|*}"
    source_field="${parsed#*|}"
    printf '%s|%s|1|phase5_settlement_layer_check_summary|%s|%s|0|3\n' "$value" "$status" "$source_field" "$check_summary_path"
    return
  fi

  fallback_path="$(resolve_artifact_summary_path "$run_summary_path" '.steps.phase5_settlement_layer_check.artifacts.summary_json // .artifacts.check_summary_json // empty')"
  parsed="$(resolve_sponsor_from_handoff_or_check_summary "$fallback_path" || true)"
  if [[ -n "$parsed" ]]; then
    value="${parsed%%|*}"
    parsed="${parsed#*|}"
    status="${parsed%%|*}"
    source_field="${parsed#*|}"
    printf '%s|%s|1|phase5_settlement_layer_run_summary.artifacts.check_summary_json|%s|%s|1|4\n' "$value" "$status" "$source_field" "$fallback_path"
    return
  fi

  parsed="$(resolve_sponsor_from_ci_summary "$ci_summary_path" || true)"
  if [[ -n "$parsed" ]]; then
    value="${parsed%%|*}"
    parsed="${parsed#*|}"
    status="${parsed%%|*}"
    source_field="${parsed#*|}"
    printf '%s|%s|1|ci_phase5_settlement_layer_summary|%s|%s|0|5\n' "$value" "$status" "$source_field" "$ci_summary_path"
    return
  fi

  printf '%s|%s|0|unresolved|||0|null\n' "null" "missing"
}

resolve_dual_asset_parity_signal() {
  local handoff_check_summary_path="${1:-}"
  local handoff_run_summary_path="${2:-}"
  local check_summary_path="${3:-}"
  local run_summary_path="${4:-}"
  local ci_summary_path="${5:-}"

  local parsed=""
  local value=""
  local status=""
  local source_field=""
  local fallback_path=""

  parsed="$(resolve_dual_asset_from_handoff_or_check_summary "$handoff_check_summary_path" || true)"
  if [[ -n "$parsed" ]]; then
    value="${parsed%%|*}"
    parsed="${parsed#*|}"
    status="${parsed%%|*}"
    source_field="${parsed#*|}"
    printf '%s|%s|1|phase5_settlement_layer_handoff_check_summary|%s|%s|0|1\n' "$value" "$status" "$source_field" "$handoff_check_summary_path"
    return
  fi

  fallback_path="$(resolve_artifact_summary_path "$handoff_run_summary_path" '.steps.phase5_settlement_layer_handoff_check.artifacts.summary_json // .artifacts.handoff_summary_json // empty')"
  parsed="$(resolve_dual_asset_from_handoff_or_check_summary "$fallback_path" || true)"
  if [[ -n "$parsed" ]]; then
    value="${parsed%%|*}"
    parsed="${parsed#*|}"
    status="${parsed%%|*}"
    source_field="${parsed#*|}"
    printf '%s|%s|1|phase5_settlement_layer_handoff_run_summary.artifacts.handoff_summary_json|%s|%s|1|2\n' "$value" "$status" "$source_field" "$fallback_path"
    return
  fi

  parsed="$(resolve_dual_asset_from_handoff_or_check_summary "$check_summary_path" || true)"
  if [[ -n "$parsed" ]]; then
    value="${parsed%%|*}"
    parsed="${parsed#*|}"
    status="${parsed%%|*}"
    source_field="${parsed#*|}"
    printf '%s|%s|1|phase5_settlement_layer_check_summary|%s|%s|0|3\n' "$value" "$status" "$source_field" "$check_summary_path"
    return
  fi

  fallback_path="$(resolve_artifact_summary_path "$run_summary_path" '.steps.phase5_settlement_layer_check.artifacts.summary_json // .artifacts.check_summary_json // empty')"
  parsed="$(resolve_dual_asset_from_handoff_or_check_summary "$fallback_path" || true)"
  if [[ -n "$parsed" ]]; then
    value="${parsed%%|*}"
    parsed="${parsed#*|}"
    status="${parsed%%|*}"
    source_field="${parsed#*|}"
    printf '%s|%s|1|phase5_settlement_layer_run_summary.artifacts.check_summary_json|%s|%s|1|4\n' "$value" "$status" "$source_field" "$fallback_path"
    return
  fi

  parsed="$(resolve_dual_asset_from_ci_summary "$ci_summary_path" || true)"
  if [[ -n "$parsed" ]]; then
    value="${parsed%%|*}"
    parsed="${parsed#*|}"
    status="${parsed%%|*}"
    source_field="${parsed#*|}"
    printf '%s|%s|1|ci_phase5_settlement_layer_summary|%s|%s|0|5\n' "$value" "$status" "$source_field" "$ci_summary_path"
    return
  fi

  printf '%s|%s|0|unresolved|||0|null\n' "null" "missing"
}

need_cmd jq
need_cmd date

reports_dir="${PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
ci_summary_json=""
check_summary_json=""
run_summary_json=""
handoff_check_summary_json=""
handoff_run_summary_json=""
summary_json="${PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_SUMMARY_JSON:-}"
canonical_summary_json="${PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase5_settlement_layer_summary_report.json}"
print_summary_json="${PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_PRINT_SUMMARY_JSON:-1}"

declare -A stage_configured=(
  ["ci_phase5_settlement_layer"]="0"
  ["phase5_settlement_layer_check"]="0"
  ["phase5_settlement_layer_run"]="0"
  ["phase5_settlement_layer_handoff_check"]="0"
  ["phase5_settlement_layer_handoff_run"]="0"
)
declare -A stage_path=(
  ["ci_phase5_settlement_layer"]=""
  ["phase5_settlement_layer_check"]=""
  ["phase5_settlement_layer_run"]=""
  ["phase5_settlement_layer_handoff_check"]=""
  ["phase5_settlement_layer_handoff_run"]=""
)
declare -A stage_expected_schema=(
  ["ci_phase5_settlement_layer"]="ci_phase5_settlement_layer_summary"
  ["phase5_settlement_layer_check"]="phase5_settlement_layer_check_summary"
  ["phase5_settlement_layer_run"]="phase5_settlement_layer_run_summary"
  ["phase5_settlement_layer_handoff_check"]="phase5_settlement_layer_handoff_check_summary"
  ["phase5_settlement_layer_handoff_run"]="phase5_settlement_layer_handoff_run_summary"
)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --ci-summary-json)
      ci_summary_json="${2:-}"
      stage_configured["ci_phase5_settlement_layer"]="1"
      shift 2
      ;;
    --check-summary-json)
      check_summary_json="${2:-}"
      stage_configured["phase5_settlement_layer_check"]="1"
      shift 2
      ;;
    --run-summary-json)
      run_summary_json="${2:-}"
      stage_configured["phase5_settlement_layer_run"]="1"
      shift 2
      ;;
    --handoff-check-summary-json)
      handoff_check_summary_json="${2:-}"
      stage_configured["phase5_settlement_layer_handoff_check"]="1"
      shift 2
      ;;
    --handoff-run-summary-json)
      handoff_run_summary_json="${2:-}"
      stage_configured["phase5_settlement_layer_handoff_run"]="1"
      shift 2
      ;;
    --summary-json)
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
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

bool_arg_or_die "--print-summary-json" "$print_summary_json"

reports_dir="$(abs_path "$reports_dir")"
ci_summary_json="$(abs_path "$ci_summary_json")"
check_summary_json="$(abs_path "$check_summary_json")"
run_summary_json="$(abs_path "$run_summary_json")"
handoff_check_summary_json="$(abs_path "$handoff_check_summary_json")"
handoff_run_summary_json="$(abs_path "$handoff_run_summary_json")"

stage_path["ci_phase5_settlement_layer"]="$ci_summary_json"
stage_path["phase5_settlement_layer_check"]="$check_summary_json"
stage_path["phase5_settlement_layer_run"]="$run_summary_json"
stage_path["phase5_settlement_layer_handoff_check"]="$handoff_check_summary_json"
stage_path["phase5_settlement_layer_handoff_run"]="$handoff_run_summary_json"

configured_count=0
for stage_id in \
  ci_phase5_settlement_layer \
  phase5_settlement_layer_check \
  phase5_settlement_layer_run \
  phase5_settlement_layer_handoff_check \
  phase5_settlement_layer_handoff_run; do
  if [[ "${stage_configured[$stage_id]}" == "1" ]]; then
    configured_count=$((configured_count + 1))
  fi
done

if (( configured_count == 0 )); then
  stage_configured["ci_phase5_settlement_layer"]="1"
  stage_configured["phase5_settlement_layer_check"]="1"
  stage_configured["phase5_settlement_layer_run"]="1"
  stage_configured["phase5_settlement_layer_handoff_check"]="1"
  stage_configured["phase5_settlement_layer_handoff_run"]="1"

  stage_path["ci_phase5_settlement_layer"]="$reports_dir/phase5_settlement_layer_ci_summary.json"
  stage_path["phase5_settlement_layer_check"]="$reports_dir/phase5_settlement_layer_check_summary.json"
  stage_path["phase5_settlement_layer_run"]="$reports_dir/phase5_settlement_layer_run_summary.json"
  stage_path["phase5_settlement_layer_handoff_check"]="$reports_dir/phase5_settlement_layer_handoff_check_summary.json"
  stage_path["phase5_settlement_layer_handoff_run"]="$reports_dir/phase5_settlement_layer_handoff_run_summary.json"

  if [[ ! -f "${stage_path[ci_phase5_settlement_layer]}" ]]; then
    discovered_ci=""
    if discovered_ci="$(discover_latest_stage_summary "$reports_dir" "ci_phase5_settlement_layer_" "ci_phase5_settlement_layer_summary.json")"; then
      stage_path["ci_phase5_settlement_layer"]="$discovered_ci"
    fi
  fi

  if [[ ! -f "${stage_path[phase5_settlement_layer_check]}" ]]; then
    discovered_check=""
    if discovered_check="$(discover_latest_stage_summary "$reports_dir" "phase5_settlement_layer_check_" "phase5_settlement_layer_check_summary.json")"; then
      stage_path["phase5_settlement_layer_check"]="$discovered_check"
    fi
  fi

  if [[ ! -f "${stage_path[phase5_settlement_layer_run]}" ]]; then
    discovered_run=""
    if discovered_run="$(discover_latest_stage_summary "$reports_dir" "phase5_settlement_layer_run_" "phase5_settlement_layer_run_summary.json")"; then
      stage_path["phase5_settlement_layer_run"]="$discovered_run"
    fi
  fi

  if [[ ! -f "${stage_path[phase5_settlement_layer_handoff_check]}" ]]; then
    discovered_handoff_check=""
    if discovered_handoff_check="$(discover_latest_stage_summary "$reports_dir" "phase5_settlement_layer_handoff_check_" "phase5_settlement_layer_handoff_check_summary.json")"; then
      stage_path["phase5_settlement_layer_handoff_check"]="$discovered_handoff_check"
    fi
  fi

  if [[ ! -f "${stage_path[phase5_settlement_layer_handoff_run]}" ]]; then
    discovered_handoff_run=""
    if discovered_handoff_run="$(discover_latest_stage_summary "$reports_dir" "phase5_settlement_layer_handoff_run_" "phase5_settlement_layer_handoff_run_summary.json")"; then
      stage_path["phase5_settlement_layer_handoff_run"]="$discovered_handoff_run"
    fi
  fi
fi

for stage_id in \
  ci_phase5_settlement_layer \
  phase5_settlement_layer_check \
  phase5_settlement_layer_run \
  phase5_settlement_layer_handoff_check \
  phase5_settlement_layer_handoff_run; do
  if [[ "${stage_configured[$stage_id]}" == "1" && -z "$(trim "${stage_path[$stage_id]}")" ]]; then
    echo "missing path for configured stage: $stage_id"
    exit 2
  fi
done

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/phase5_settlement_layer_summary_report.json"
fi
summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"
mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"

declare -A stage_status
declare -A stage_schema_id
declare -A stage_rc
declare -A stage_entry_json

pass_count=0
fail_count=0
missing_count=0
invalid_count=0
considered_count=0
sponsor_signal_ok="null"
sponsor_signal_status="missing"
sponsor_signal_resolved="0"
sponsor_signal_source="unresolved"
sponsor_signal_source_field=""
sponsor_signal_source_path=""
sponsor_signal_source_fallback="0"
sponsor_signal_source_priority_index="null"
dual_asset_signal_ok="null"
dual_asset_signal_status="missing"
dual_asset_signal_resolved="0"
dual_asset_signal_source="unresolved"
dual_asset_signal_source_field=""
dual_asset_signal_source_path=""
dual_asset_signal_source_fallback="0"
dual_asset_signal_source_priority_index="null"

declare -a reasons=()
declare -a warnings=()

for stage_id in \
  ci_phase5_settlement_layer \
  phase5_settlement_layer_check \
  phase5_settlement_layer_run \
  phase5_settlement_layer_handoff_check \
  phase5_settlement_layer_handoff_run; do
  configured="${stage_configured[$stage_id]}"
  path="${stage_path[$stage_id]}"
  expected_schema="${stage_expected_schema[$stage_id]}"

  if [[ "$configured" != "1" ]]; then
    stage_status["$stage_id"]="skipped"
    stage_schema_id["$stage_id"]=""
    stage_rc["$stage_id"]="null"
    stage_entry_json["$stage_id"]="$(jq -n \
      --arg path "$path" \
      --arg expected_schema "$expected_schema" \
      '{
        configured: false,
        path: (if $path == "" then null else $path end),
        expected_schema_id: $expected_schema,
        exists: false,
        valid_json: false,
        schema_id: null,
        schema_valid: false,
        raw_status: null,
        raw_rc: null,
        status: "skipped",
        rc: null
      }'
    )"
    continue
  fi

  considered_count=$((considered_count + 1))
  exists="0"
  valid_json="0"
  schema_id=""
  schema_valid="0"
  raw_status=""
  raw_rc=""
  status="missing"

  if [[ -f "$path" ]]; then
    exists="1"
  fi

  if [[ "$exists" == "1" ]] && jq -e . "$path" >/dev/null 2>&1; then
    valid_json="1"
  fi

  if [[ "$exists" != "1" ]]; then
    status="missing"
    missing_count=$((missing_count + 1))
    warnings+=("${stage_id} summary is missing: ${path}")
  elif [[ "$valid_json" != "1" ]]; then
    status="invalid"
    invalid_count=$((invalid_count + 1))
    reasons+=("${stage_id} summary is not valid JSON: ${path}")
  else
    schema_id="$(jq -r '.schema.id // ""' "$path" 2>/dev/null || true)"
    raw_status="$(jq -r '.status // ""' "$path" 2>/dev/null || true)"
    raw_rc="$(jq -r '.rc // ""' "$path" 2>/dev/null || true)"

    if [[ "$schema_id" == "$expected_schema" ]]; then
      schema_valid="1"
    fi

    if [[ "$schema_valid" != "1" ]]; then
      status="invalid"
      invalid_count=$((invalid_count + 1))
      reasons+=("${stage_id} summary schema mismatch: expected ${expected_schema}, got ${schema_id:-<empty>}")
    elif [[ -z "$raw_status" || ! "$raw_rc" =~ ^-?[0-9]+$ ]]; then
      status="invalid"
      invalid_count=$((invalid_count + 1))
      reasons+=("${stage_id} summary missing status/rc contract fields")
    elif [[ "$raw_status" == "pass" && "$raw_rc" == "0" ]]; then
      status="pass"
      pass_count=$((pass_count + 1))
    else
      status="fail"
      fail_count=$((fail_count + 1))
      reasons+=("${stage_id} status is ${raw_status} (rc=${raw_rc})")
    fi
  fi

  stage_status["$stage_id"]="$status"
  stage_schema_id["$stage_id"]="$schema_id"
  if [[ "$raw_rc" =~ ^-?[0-9]+$ ]]; then
    stage_rc["$stage_id"]="$raw_rc"
  else
    stage_rc["$stage_id"]="null"
  fi

  stage_entry_json["$stage_id"]="$(jq -n \
    --arg configured "$configured" \
    --arg path "$path" \
    --arg expected_schema "$expected_schema" \
    --arg exists "$exists" \
    --arg valid_json "$valid_json" \
    --arg schema_id "$schema_id" \
    --arg schema_valid "$schema_valid" \
    --arg raw_status "$raw_status" \
    --arg raw_rc "$raw_rc" \
    --arg status "$status" \
    '{
      configured: ($configured == "1"),
      path: (if $path == "" then null else $path end),
      expected_schema_id: $expected_schema,
      exists: ($exists == "1"),
      valid_json: ($valid_json == "1"),
      schema_id: (if $schema_id == "" then null else $schema_id end),
      schema_valid: ($schema_valid == "1"),
      raw_status: (if $raw_status == "" then null else $raw_status end),
      raw_rc: (if ($raw_rc | test("^-?[0-9]+$")) then ($raw_rc | tonumber) else null end),
      status: $status,
      rc: (if ($raw_rc | test("^-?[0-9]+$")) then ($raw_rc | tonumber) else null end)
    }'
  )"
done

sponsor_signal_pair="$(resolve_sponsor_live_smoke_signal \
  "${stage_path[phase5_settlement_layer_handoff_check]}" \
  "${stage_path[phase5_settlement_layer_handoff_run]}" \
  "${stage_path[phase5_settlement_layer_check]}" \
  "${stage_path[phase5_settlement_layer_run]}" \
  "${stage_path[ci_phase5_settlement_layer]}" \
)"
sponsor_signal_ok="${sponsor_signal_pair%%|*}"
sponsor_signal_pair="${sponsor_signal_pair#*|}"
sponsor_signal_status="${sponsor_signal_pair%%|*}"
sponsor_signal_pair="${sponsor_signal_pair#*|}"
sponsor_signal_resolved="${sponsor_signal_pair%%|*}"
sponsor_signal_pair="${sponsor_signal_pair#*|}"
sponsor_signal_source="${sponsor_signal_pair%%|*}"
sponsor_signal_pair="${sponsor_signal_pair#*|}"
sponsor_signal_source_field="${sponsor_signal_pair%%|*}"
sponsor_signal_pair="${sponsor_signal_pair#*|}"
sponsor_signal_source_path="${sponsor_signal_pair%%|*}"
sponsor_signal_pair="${sponsor_signal_pair#*|}"
sponsor_signal_source_fallback="${sponsor_signal_pair%%|*}"
sponsor_signal_source_priority_index="${sponsor_signal_pair##*|}"

dual_asset_signal_pair="$(resolve_dual_asset_parity_signal \
  "${stage_path[phase5_settlement_layer_handoff_check]}" \
  "${stage_path[phase5_settlement_layer_handoff_run]}" \
  "${stage_path[phase5_settlement_layer_check]}" \
  "${stage_path[phase5_settlement_layer_run]}" \
  "${stage_path[ci_phase5_settlement_layer]}" \
)"
dual_asset_signal_ok="${dual_asset_signal_pair%%|*}"
dual_asset_signal_pair="${dual_asset_signal_pair#*|}"
dual_asset_signal_status="${dual_asset_signal_pair%%|*}"
dual_asset_signal_pair="${dual_asset_signal_pair#*|}"
dual_asset_signal_resolved="${dual_asset_signal_pair%%|*}"
dual_asset_signal_pair="${dual_asset_signal_pair#*|}"
dual_asset_signal_source="${dual_asset_signal_pair%%|*}"
dual_asset_signal_pair="${dual_asset_signal_pair#*|}"
dual_asset_signal_source_field="${dual_asset_signal_pair%%|*}"
dual_asset_signal_pair="${dual_asset_signal_pair#*|}"
dual_asset_signal_source_path="${dual_asset_signal_pair%%|*}"
dual_asset_signal_pair="${dual_asset_signal_pair#*|}"
dual_asset_signal_source_fallback="${dual_asset_signal_pair%%|*}"
dual_asset_signal_source_priority_index="${dual_asset_signal_pair##*|}"

overall_status="missing"
overall_rc=1
if (( fail_count > 0 || invalid_count > 0 )); then
  overall_status="fail"
  overall_rc=1
elif (( pass_count > 0 )); then
  overall_status="pass"
  overall_rc=0
else
  overall_status="missing"
  overall_rc=1
fi

reasons_json="$(array_to_json reasons)"
warnings_json="$(array_to_json warnings)"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$overall_status" \
  --argjson rc "$overall_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg print_summary_json "$print_summary_json" \
  --argjson reasons "$reasons_json" \
  --argjson warnings "$warnings_json" \
  --argjson ci_stage "${stage_entry_json[ci_phase5_settlement_layer]}" \
  --argjson check_stage "${stage_entry_json[phase5_settlement_layer_check]}" \
  --argjson run_stage "${stage_entry_json[phase5_settlement_layer_run]}" \
  --argjson handoff_check_stage "${stage_entry_json[phase5_settlement_layer_handoff_check]}" \
  --argjson handoff_run_stage "${stage_entry_json[phase5_settlement_layer_handoff_run]}" \
  --argjson considered_count "$considered_count" \
  --argjson pass_count "$pass_count" \
  --argjson fail_count "$fail_count" \
  --argjson missing_count "$missing_count" \
  --argjson invalid_count "$invalid_count" \
  --arg sponsor_signal_ok "$sponsor_signal_ok" \
  --arg sponsor_signal_status "$sponsor_signal_status" \
  --arg sponsor_signal_resolved "$sponsor_signal_resolved" \
  --arg sponsor_signal_source "$sponsor_signal_source" \
  --arg sponsor_signal_source_field "$sponsor_signal_source_field" \
  --arg sponsor_signal_source_path "$sponsor_signal_source_path" \
  --arg sponsor_signal_source_fallback "$sponsor_signal_source_fallback" \
  --arg sponsor_signal_source_priority_index "$sponsor_signal_source_priority_index" \
  --arg dual_asset_signal_ok "$dual_asset_signal_ok" \
  --arg dual_asset_signal_status "$dual_asset_signal_status" \
  --arg dual_asset_signal_resolved "$dual_asset_signal_resolved" \
  --arg dual_asset_signal_source "$dual_asset_signal_source" \
  --arg dual_asset_signal_source_field "$dual_asset_signal_source_field" \
  --arg dual_asset_signal_source_path "$dual_asset_signal_source_path" \
  --arg dual_asset_signal_source_fallback "$dual_asset_signal_source_fallback" \
  --arg dual_asset_signal_source_priority_index "$dual_asset_signal_source_priority_index" \
  '{
    version: 1,
    schema: {
      id: "phase5_settlement_layer_summary_report",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      print_summary_json: ($print_summary_json == "1")
    },
    summaries: {
      ci_phase5_settlement_layer_summary: $ci_stage,
      phase5_settlement_layer_check_summary: $check_stage,
      phase5_settlement_layer_run_summary: $run_stage,
      phase5_settlement_layer_handoff_check_summary: $handoff_check_stage,
      phase5_settlement_layer_handoff_run_summary: $handoff_run_stage
    },
    counts: {
      configured: $considered_count,
      pass: $pass_count,
      fail: $fail_count,
      missing: $missing_count,
      invalid: $invalid_count
    },
    signals: {
      issuer_sponsor_api_live_smoke: {
        ok: (
          if $sponsor_signal_ok == "true" then true
          elif $sponsor_signal_ok == "false" then false
          else null
          end
        ),
        status: $sponsor_signal_status,
        resolved: ($sponsor_signal_resolved == "1"),
        source: $sponsor_signal_source,
        source_field: (if $sponsor_signal_source_field == "" then null else $sponsor_signal_source_field end),
        source_path: (if $sponsor_signal_source_path == "" then null else $sponsor_signal_source_path end),
        fallback: ($sponsor_signal_source_fallback == "1"),
        source_priority_index: (
          if ($sponsor_signal_source_priority_index | test("^[0-9]+$")) then ($sponsor_signal_source_priority_index | tonumber)
          else null
          end
        ),
        source_priority: [
          "phase5_settlement_layer_handoff_check_summary",
          "phase5_settlement_layer_handoff_run_summary.artifacts.handoff_summary_json",
          "phase5_settlement_layer_check_summary",
          "phase5_settlement_layer_run_summary.artifacts.check_summary_json",
          "ci_phase5_settlement_layer_summary"
        ]
      },
      settlement_dual_asset_parity: {
        ok: (
          if $dual_asset_signal_ok == "true" then true
          elif $dual_asset_signal_ok == "false" then false
          else null
          end
        ),
        status: $dual_asset_signal_status,
        resolved: ($dual_asset_signal_resolved == "1"),
        source: $dual_asset_signal_source,
        source_field: (if $dual_asset_signal_source_field == "" then null else $dual_asset_signal_source_field end),
        source_path: (if $dual_asset_signal_source_path == "" then null else $dual_asset_signal_source_path end),
        fallback: ($dual_asset_signal_source_fallback == "1"),
        source_priority_index: (
          if ($dual_asset_signal_source_priority_index | test("^[0-9]+$")) then ($dual_asset_signal_source_priority_index | tonumber)
          else null
          end
        ),
        source_priority: [
          "phase5_settlement_layer_handoff_check_summary",
          "phase5_settlement_layer_handoff_run_summary.artifacts.handoff_summary_json",
          "phase5_settlement_layer_check_summary",
          "phase5_settlement_layer_run_summary.artifacts.check_summary_json",
          "ci_phase5_settlement_layer_summary"
        ]
      }
    },
    decision: {
      pass: ($status == "pass"),
      reasons: $reasons,
      warnings: $warnings
    },
    artifacts: {
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

if [[ "$summary_json" != "$canonical_summary_json" ]]; then
  canonical_tmp="$(mktemp "${canonical_summary_json}.tmp.XXXXXX")"
  cat "$summary_json" >"$canonical_tmp"
  mv -f "$canonical_tmp" "$canonical_summary_json"
fi

for stage_id in \
  ci_phase5_settlement_layer \
  phase5_settlement_layer_check \
  phase5_settlement_layer_run \
  phase5_settlement_layer_handoff_check \
  phase5_settlement_layer_handoff_run; do
  if [[ "${stage_configured[$stage_id]}" != "1" ]]; then
    continue
  fi
  status="${stage_status[$stage_id]}"
  schema_display="${stage_schema_id[$stage_id]:-n/a}"
  rc_display="${stage_rc[$stage_id]}"
  if [[ "$rc_display" == "null" ]]; then
    rc_display="n/a"
  fi
  echo "[phase5-summary] $(display_stage_name "$stage_id"): status=${status} rc=${rc_display} schema=${schema_display} path=${stage_path[$stage_id]}"
done
echo "[phase5-summary] overall: status=${overall_status} pass=${pass_count} fail=${fail_count} missing=${missing_count} invalid=${invalid_count}"
echo "[phase5-summary] issuer_sponsor_api_live_smoke: status=${sponsor_signal_status} ok=${sponsor_signal_ok} source=${sponsor_signal_source} fallback=${sponsor_signal_source_fallback} path=${sponsor_signal_source_path:-n/a}"
echo "[phase5-summary] settlement_dual_asset_parity: status=${dual_asset_signal_status} ok=${dual_asset_signal_ok} source=${dual_asset_signal_source} fallback=${dual_asset_signal_source_fallback} path=${dual_asset_signal_source_path:-n/a}"
echo "[phase5-summary] summary_json=${summary_json}"
echo "[phase5-summary] canonical_summary_json=${canonical_summary_json}"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$overall_rc"
