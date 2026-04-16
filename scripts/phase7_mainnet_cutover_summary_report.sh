#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase7_mainnet_cutover_summary_report.sh \
    [--reports-dir DIR] \
    [--check-summary-json PATH] \
    [--run-summary-json PATH] \
    [--handoff-check-summary-json PATH] \
    [--handoff-run-summary-json PATH] \
    [--summary-json PATH] \
    [--print-report [0|1]] \
    [--show-json [0|1]]

Purpose:
  Build one compact Phase-7 mainnet-cutover summary from:
    - phase7_mainnet_cutover_check_summary
    - phase7_mainnet_cutover_run_summary
    - phase7_mainnet_cutover_handoff_check_summary
    - phase7_mainnet_cutover_handoff_run_summary

Notes:
  - If no summary paths are explicitly provided, the helper probes default
    files under --reports-dir and then falls back to timestamped directories.
  - If one or more summary paths are explicitly provided, only those are
    evaluated.
  - Optional input signals are preserved as-is in the combined output, including
    `tdpnd_comet_runtime_smoke_ok` when the underlying phase7 summaries expose
    it.
  - Exit codes:
      0: pass (at least one configured summary passed and none failed/invalid)
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
    local best_timestamp_path
    best_timestamp_path="$(printf '%s\n' "${timestamp_candidates[@]}" | LC_ALL=C sort | tail -n 1 | cut -d'|' -f2-)"
    printf 'discovered_timestamp_dir|%s' "$best_timestamp_path"
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
    local best_mtime_path
    best_mtime_path="$(printf '%s\n' "${mtime_candidates[@]}" | LC_ALL=C sort -t'|' -k1,1n -k2,2 | tail -n 1 | cut -d'|' -f2-)"
    printf 'discovered_mtime|%s' "$best_mtime_path"
    return 0
  fi

  return 1
}

need_cmd jq
need_cmd date

reports_dir="${PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
check_summary_json=""
run_summary_json=""
handoff_check_summary_json=""
handoff_run_summary_json=""
summary_json="${PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_SUMMARY_JSON:-}"
canonical_summary_json="${PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase7_mainnet_cutover_summary_report.json}"
print_report="${PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_PRINT_REPORT:-1}"
show_json="${PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_SHOW_JSON:-0}"

declare -A stage_configured=(
  ["check"]="0"
  ["run"]="0"
  ["handoff_check"]="0"
  ["handoff_run"]="0"
)
declare -A stage_path=(
  ["check"]=""
  ["run"]=""
  ["handoff_check"]=""
  ["handoff_run"]=""
)
declare -A stage_source_kind=(
  ["check"]=""
  ["run"]=""
  ["handoff_check"]=""
  ["handoff_run"]=""
)
declare -A stage_expected_schema=(
  ["check"]="phase7_mainnet_cutover_check_summary"
  ["run"]="phase7_mainnet_cutover_run_summary"
  ["handoff_check"]="phase7_mainnet_cutover_handoff_check_summary"
  ["handoff_run"]="phase7_mainnet_cutover_handoff_run_summary"
)
stage_ids=(check run handoff_check handoff_run)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --check-summary-json)
      check_summary_json="${2:-}"
      stage_configured["check"]="1"
      stage_source_kind["check"]="explicit"
      shift 2
      ;;
    --run-summary-json)
      run_summary_json="${2:-}"
      stage_configured["run"]="1"
      stage_source_kind["run"]="explicit"
      shift 2
      ;;
    --handoff-check-summary-json)
      handoff_check_summary_json="${2:-}"
      stage_configured["handoff_check"]="1"
      stage_source_kind["handoff_check"]="explicit"
      shift 2
      ;;
    --handoff-run-summary-json)
      handoff_run_summary_json="${2:-}"
      stage_configured["handoff_run"]="1"
      stage_source_kind["handoff_run"]="explicit"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --print-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_report="${2:-}"
        shift 2
      else
        print_report="1"
        shift
      fi
      ;;
    --show-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_json="${2:-}"
        shift 2
      else
        show_json="1"
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

bool_arg_or_die "--print-report" "$print_report"
bool_arg_or_die "--show-json" "$show_json"

reports_dir="$(abs_path "$reports_dir")"
check_summary_json="$(abs_path "$check_summary_json")"
run_summary_json="$(abs_path "$run_summary_json")"
handoff_check_summary_json="$(abs_path "$handoff_check_summary_json")"
handoff_run_summary_json="$(abs_path "$handoff_run_summary_json")"

stage_path["check"]="$check_summary_json"
stage_path["run"]="$run_summary_json"
stage_path["handoff_check"]="$handoff_check_summary_json"
stage_path["handoff_run"]="$handoff_run_summary_json"

configured_count=0
for stage_id in "${stage_ids[@]}"; do
  if [[ "${stage_configured[$stage_id]}" == "1" ]]; then
    configured_count=$((configured_count + 1))
  fi
done

if (( configured_count == 0 )); then
  stage_configured["check"]="1"
  stage_configured["run"]="1"
  stage_configured["handoff_check"]="1"
  stage_configured["handoff_run"]="1"
  stage_source_kind["check"]="default"
  stage_source_kind["run"]="default"
  stage_source_kind["handoff_check"]="default"
  stage_source_kind["handoff_run"]="default"
  stage_path["check"]="$reports_dir/phase7_mainnet_cutover_check_summary.json"
  stage_path["run"]="$reports_dir/phase7_mainnet_cutover_run_summary.json"
  stage_path["handoff_check"]="$reports_dir/phase7_mainnet_cutover_handoff_check_summary.json"
  stage_path["handoff_run"]="$reports_dir/phase7_mainnet_cutover_handoff_run_summary.json"

  if [[ ! -f "${stage_path[check]}" ]]; then
    discovered_check=""
    if discovered_check="$(discover_latest_stage_summary "$reports_dir" "phase7_mainnet_cutover_check_" "phase7_mainnet_cutover_check_summary.json")"; then
      stage_source_kind["check"]="${discovered_check%%|*}"
      stage_path["check"]="${discovered_check#*|}"
    fi
  fi
  if [[ ! -f "${stage_path[run]}" ]]; then
    discovered_run=""
    if discovered_run="$(discover_latest_stage_summary "$reports_dir" "phase7_mainnet_cutover_run_" "phase7_mainnet_cutover_run_summary.json")"; then
      stage_source_kind["run"]="${discovered_run%%|*}"
      stage_path["run"]="${discovered_run#*|}"
    fi
  fi
  if [[ ! -f "${stage_path[handoff_check]}" ]]; then
    discovered_handoff_check=""
    if discovered_handoff_check="$(discover_latest_stage_summary "$reports_dir" "phase7_mainnet_cutover_handoff_check_" "phase7_mainnet_cutover_handoff_check_summary.json")"; then
      stage_source_kind["handoff_check"]="${discovered_handoff_check%%|*}"
      stage_path["handoff_check"]="${discovered_handoff_check#*|}"
    fi
  fi
  if [[ ! -f "${stage_path[handoff_run]}" ]]; then
    discovered_handoff_run=""
    if discovered_handoff_run="$(discover_latest_stage_summary "$reports_dir" "phase7_mainnet_cutover_handoff_run_" "phase7_mainnet_cutover_handoff_run_summary.json")"; then
      stage_source_kind["handoff_run"]="${discovered_handoff_run%%|*}"
      stage_path["handoff_run"]="${discovered_handoff_run#*|}"
    fi
  fi
fi

for stage_id in "${stage_ids[@]}"; do
  if [[ "${stage_configured[$stage_id]}" == "1" && -z "$(trim "${stage_path[$stage_id]}")" ]]; then
    echo "missing path for configured summary: $stage_id"
    exit 2
  fi
done

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/phase7_mainnet_cutover_summary_report.json"
fi
summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"
mkdir -p "$(dirname "$summary_json")" "$(dirname "$canonical_summary_json")"

declare -A stage_status
declare -A stage_schema_id
declare -A stage_rc
declare -A stage_entry_json

pass_count=0
fail_count=0
missing_count=0
invalid_count=0
considered_count=0

declare -a reasons=()
declare -a warnings=()

for stage_id in "${stage_ids[@]}"; do
  configured="${stage_configured[$stage_id]}"
  source_path="${stage_path[$stage_id]}"
  source_kind="${stage_source_kind[$stage_id]}"
  expected_schema="${stage_expected_schema[$stage_id]}"

  if [[ "$configured" != "1" ]]; then
    stage_status["$stage_id"]="skipped"
    stage_schema_id["$stage_id"]=""
    stage_rc["$stage_id"]="null"
    stage_entry_json["$stage_id"]="$(jq -n \
      --arg source_path "$source_path" \
      --arg source_kind "$source_kind" \
      '{
        configured: false,
        source_path: (if $source_path == "" then null else $source_path end),
        source_kind: (if $source_kind == "" then null else $source_kind end),
        exists: false,
        valid_json: false,
        schema_id: null,
        schema_valid: false,
        raw_status: null,
        raw_rc: null,
        signal_snapshot: null,
        status: "skipped"
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
  signal_snapshot_json="null"

  if [[ -f "$source_path" ]]; then
    exists="1"
  fi
  if [[ "$exists" == "1" ]] && jq -e . "$source_path" >/dev/null 2>&1; then
    valid_json="1"
    case "$stage_id" in
      check)
        signal_snapshot_json="$(jq -c '.signals // null' "$source_path" 2>/dev/null || true)"
        ;;
      run)
        signal_snapshot_json="$(jq -c '.steps.phase7_mainnet_cutover_check.signal_snapshot // null' "$source_path" 2>/dev/null || true)"
        ;;
      handoff_check|handoff_run)
        signal_snapshot_json="$(jq -c '.handoff // null' "$source_path" 2>/dev/null || true)"
        ;;
    esac
    if [[ -z "$signal_snapshot_json" ]]; then
      signal_snapshot_json="null"
    fi
  fi

  if [[ "$exists" != "1" ]]; then
    status="missing"
    missing_count=$((missing_count + 1))
    warnings+=("${stage_id} summary is missing: ${source_path}")
  elif [[ "$valid_json" != "1" ]]; then
    status="invalid"
    invalid_count=$((invalid_count + 1))
    reasons+=("${stage_id} summary is not valid JSON: ${source_path}")
  else
    schema_id="$(jq -r '.schema.id // ""' "$source_path" 2>/dev/null || true)"
    raw_status="$(jq -r '.status // ""' "$source_path" 2>/dev/null || true)"
    raw_rc="$(jq -r '.rc // ""' "$source_path" 2>/dev/null || true)"

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
    --arg source_path "$source_path" \
    --arg source_kind "$source_kind" \
    --arg exists "$exists" \
    --arg valid_json "$valid_json" \
    --arg schema_id "$schema_id" \
    --arg schema_valid "$schema_valid" \
    --arg raw_status "$raw_status" \
    --arg raw_rc "$raw_rc" \
    --argjson signal_snapshot "$signal_snapshot_json" \
    --arg status "$status" \
    '{
      configured: ($configured == "1"),
      source_path: (if $source_path == "" then null else $source_path end),
      source_kind: (if $source_kind == "" then null else $source_kind end),
      exists: ($exists == "1"),
      valid_json: ($valid_json == "1"),
      schema_id: (if $schema_id == "" then null else $schema_id end),
      schema_valid: ($schema_valid == "1"),
      raw_status: (if $raw_status == "" then null else $raw_status end),
      raw_rc: (if ($raw_rc | test("^-?[0-9]+$")) then ($raw_rc | tonumber) else null end),
      signal_snapshot: $signal_snapshot,
      status: $status
    }'
  )"
done

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
  --arg show_json "$show_json" \
  --arg print_report "$print_report" \
  --argjson reasons "$reasons_json" \
  --argjson warnings "$warnings_json" \
  --argjson check "${stage_entry_json[check]}" \
  --argjson run "${stage_entry_json[run]}" \
  --argjson handoff_check "${stage_entry_json[handoff_check]}" \
  --argjson handoff_run "${stage_entry_json[handoff_run]}" \
  --argjson considered_count "$considered_count" \
  --argjson pass_count "$pass_count" \
  --argjson fail_count "$fail_count" \
  --argjson missing_count "$missing_count" \
  --argjson invalid_count "$invalid_count" \
  '{
    version: 1,
    schema: {
      id: "phase7_mainnet_cutover_summary_report",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      show_json: ($show_json == "1"),
      print_report: ($print_report == "1")
    },
    summaries: {
      check: $check,
      run: $run,
      handoff_check: $handoff_check,
      handoff_run: $handoff_run
    },
    counts: {
      configured: $considered_count,
      pass: $pass_count,
      fail: $fail_count,
      missing: $missing_count,
      invalid: $invalid_count
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
  cp "$summary_json" "$canonical_tmp"
  mv -f "$canonical_tmp" "$canonical_summary_json"
fi

if [[ "$print_report" == "1" ]]; then
  for stage_id in "${stage_ids[@]}"; do
    if [[ "${stage_configured[$stage_id]}" != "1" ]]; then
      continue
    fi
    status="${stage_status[$stage_id]}"
    schema_display="${stage_schema_id[$stage_id]:-n/a}"
    rc_display="${stage_rc[$stage_id]}"
    source_kind_display="${stage_source_kind[$stage_id]:-n/a}"
    if [[ "$rc_display" == "null" ]]; then
      rc_display="n/a"
    fi
    echo "[phase7-summary] ${stage_id}: status=${status} rc=${rc_display} schema=${schema_display} source_kind=${source_kind_display} source_path=${stage_path[$stage_id]}"
  done
  echo "[phase7-summary] overall: status=${overall_status} pass=${pass_count} fail=${fail_count} missing=${missing_count} invalid=${invalid_count}"
  echo "[phase7-summary] summary_json=${summary_json}"
  echo "[phase7-summary] canonical_summary_json=${canonical_summary_json}"
fi

if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$overall_rc"
