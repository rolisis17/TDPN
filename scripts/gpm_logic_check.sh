#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

gpm_logic_check_default_checks_rel() {
  cat <<'DEFAULT_CHECKS'
scripts/integration_roadmap_next_actions_run.sh
scripts/integration_roadmap_non_blockchain_actionable_run.sh
scripts/integration_roadmap_blockchain_actionable_run.sh
scripts/integration_roadmap_evidence_pack_actionable_run.sh
scripts/integration_roadmap_live_evidence_actionable_run.sh
scripts/integration_roadmap_live_evidence_cycle_batch_run.sh
scripts/integration_roadmap_live_and_pack_actionable_run.sh
scripts/integration_roadmap_validation_debt_actionable_run.sh
scripts/integration_roadmap_progress_report.sh
DEFAULT_CHECKS
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/gpm_logic_check.sh [options]

Description:
  Runs a curated set of fast, high-signal roadmap/GPM integration checks and
  emits a deterministic JSON summary artifact.

Options:
  --reports-dir DIR            Directory for per-check logs
  --summary-json PATH          Summary JSON output path
  --print-summary-json [0|1]   Print summary JSON to stdout (default: 1)
  --print-default-checks [0|1] Print default check list and exit (default: 0)
  --fail-fast [0|1]            Stop on first failing check (default: 0)
  --include-check SCRIPT       Add check script (repeatable)
  --exclude-check SCRIPT       Remove check script (repeatable)
  -h, --help                   Show help

Default checks (included when present):
USAGE
  while IFS= read -r rel_path; do
    [[ -n "$rel_path" ]] || continue
    printf '  - %s\n' "$rel_path"
  done < <(gpm_logic_check_default_checks_rel)
  cat <<'USAGE'

Failure mode:
  Fails closed when no checks are selected or summary invariants are violated.
USAGE
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

require_value_or_die() {
  local flag="$1"
  local value="${2:-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    echo "$flag requires a value"
    exit 2
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

normalize_abs_path() {
  local raw="${1:-}"
  local path="$raw"
  local -a raw_parts=()
  local -a clean_parts=()
  local part
  local idx
  local normalized="/"

  path="${path//\\//}"
  if [[ "$path" != /* ]]; then
    path="$ROOT_DIR/$path"
  fi

  IFS='/' read -r -a raw_parts <<<"$path"
  for part in "${raw_parts[@]}"; do
    case "$part" in
      ""|".")
        ;;
      "..")
        if [[ "${#clean_parts[@]}" -gt 0 ]]; then
          unset "clean_parts[${#clean_parts[@]}-1]"
        fi
        ;;
      *)
        clean_parts+=("$part")
        ;;
    esac
  done

  if [[ "${#clean_parts[@]}" -gt 0 ]]; then
    normalized="/${clean_parts[0]}"
    for ((idx = 1; idx < ${#clean_parts[@]}; idx++)); do
      normalized="$normalized/${clean_parts[$idx]}"
    done
  fi

  printf '%s\n' "$normalized"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s\n' ""
    return
  fi
  normalize_abs_path "$path"
}

canonical_existing_path() {
  local path="$1"
  local dir base

  dir="$(cd "$(dirname "$path")" && pwd -P)"
  base="$(basename "$path")"
  printf '%s/%s\n' "$dir" "$base"
}

resolve_script_or_die() {
  local out_var="$1"
  local flag="$2"
  local raw_path="$3"
  local candidate canonical

  candidate="$(abs_path "$raw_path")"
  if [[ -z "$candidate" || ! -f "$candidate" ]]; then
    echo "$flag script not found: $raw_path" >&2
    return 2
  fi
  if [[ ! -r "$candidate" ]]; then
    echo "$flag script is not readable: $raw_path" >&2
    return 2
  fi
  canonical="$(canonical_existing_path "$candidate")"
  printf -v "$out_var" '%s' "$canonical"
}

resolve_exclude_match_path() {
  local out_var="$1"
  local raw_path="$2"
  local candidate resolved

  candidate="$(abs_path "$raw_path")"
  if [[ -z "$candidate" ]]; then
    printf -v "$out_var" '%s' ""
    return 0
  fi

  if [[ -f "$candidate" ]]; then
    resolved="$(canonical_existing_path "$candidate")"
  else
    resolved="$candidate"
  fi
  printf -v "$out_var" '%s' "$resolved"
}

array_contains() {
  local needle="$1"
  shift || true
  local item
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

validate_summary_invariants() {
  local idx expected_result_count result_state result_code result_path_value
  local computed_skipped
  local first_fail_rc=0
  local saw_fail=0
  local -A seen_selected_paths=()
  local -A seen_result_paths=()

  if [[ "$selected_count" -ne "${#selected_checks[@]}" ]]; then
    invariant_error="selected_count mismatch with selected_checks array length"
    return 1
  fi

  expected_result_count="${#result_name[@]}"
  if [[ "$executed_count" -ne "$expected_result_count" ]]; then
    invariant_error="executed_count mismatch with result_name array length"
    return 1
  fi

  if [[ "$executed_count" -ne "${#result_path[@]}" || "$executed_count" -ne "${#result_status[@]}" || "$executed_count" -ne "${#result_rc[@]}" || "$executed_count" -ne "${#result_duration[@]}" || "$executed_count" -ne "${#result_log_path[@]}" ]]; then
    invariant_error="result arrays length mismatch"
    return 1
  fi

  if [[ $((checks_passed + checks_failed)) -ne "$executed_count" ]]; then
    invariant_error="checks_passed + checks_failed must equal checks_executed"
    return 1
  fi

  if [[ "$executed_count" -gt "$selected_count" ]]; then
    invariant_error="checks_executed cannot exceed checks_selected"
    return 1
  fi

  computed_skipped=$((selected_count - executed_count))
  if [[ "$computed_skipped" -lt 0 ]]; then
    invariant_error="checks_skipped derived value cannot be negative"
    return 1
  fi
  if [[ "$checks_skipped" -ne "$computed_skipped" ]]; then
    invariant_error="checks_skipped must equal checks_selected - checks_executed"
    return 1
  fi

  for result_path_value in "${selected_checks[@]}"; do
    if [[ -z "$result_path_value" ]]; then
      invariant_error="selected_checks contains an empty path"
      return 1
    fi
    if [[ -n "${seen_selected_paths[$result_path_value]+x}" ]]; then
      invariant_error="selected_checks must be unique"
      return 1
    fi
    seen_selected_paths[$result_path_value]=1
  done

  for ((idx = 0; idx < executed_count; idx++)); do
    result_state="${result_status[$idx]}"
    result_code="${result_rc[$idx]}"
    result_path_value="${result_path[$idx]}"
    if [[ -z "$result_path_value" ]]; then
      invariant_error="check result path must be non-empty"
      return 1
    fi
    if [[ -z "${seen_selected_paths[$result_path_value]+x}" ]]; then
      invariant_error="check result path must exist in selected_checks"
      return 1
    fi
    if [[ -n "${seen_result_paths[$result_path_value]+x}" ]]; then
      invariant_error="check result path must be unique (duplicate execution detected)"
      return 1
    fi
    seen_result_paths[$result_path_value]=1
    if [[ "$result_state" != "pass" && "$result_state" != "fail" ]]; then
      invariant_error="check result status must be pass or fail"
      return 1
    fi
    if [[ "$result_state" == "pass" && "$result_code" -ne 0 ]]; then
      invariant_error="pass status requires rc=0"
      return 1
    fi
    if [[ "$result_state" == "fail" && "$result_code" -eq 0 ]]; then
      invariant_error="fail status requires rc!=0"
      return 1
    fi
    if [[ "$result_state" == "fail" && "$saw_fail" -eq 0 ]]; then
      first_fail_rc="$result_code"
      saw_fail=1
    fi
    if [[ "${result_duration[$idx]}" -lt 0 ]]; then
      invariant_error="check duration must be >= 0"
      return 1
    fi
    if [[ -z "${result_log_path[$idx]}" ]]; then
      invariant_error="check log_path must be non-empty"
      return 1
    fi
  done

  if [[ "$checks_failed" -eq 0 && -z "$selection_error" && "$overall_rc" -ne 0 ]]; then
    invariant_error="overall rc must be 0 when all checks pass"
    return 1
  fi

  if [[ "$checks_failed" -gt 0 && "$overall_rc" -eq 0 ]]; then
    invariant_error="overall rc must be non-zero when checks fail"
    return 1
  fi

  if [[ "$checks_failed" -gt 0 && -z "$selection_error" && "$saw_fail" -eq 1 && "$overall_rc" -ne "$first_fail_rc" ]]; then
    invariant_error="overall rc must match first failing check rc"
    return 1
  fi

  if [[ -n "$selection_error" && "$selected_count" -ne 0 ]]; then
    invariant_error="selection_error requires checks_selected=0"
    return 1
  fi

  return 0
}

for cmd in bash cat date dirname basename mkdir mktemp mv; do
  need_cmd "$cmd"
done

reports_dir="${GPM_LOGIC_CHECK_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs/gpm_logic_check}"
summary_json="${GPM_LOGIC_CHECK_SUMMARY_JSON:-}"
print_summary_json="${GPM_LOGIC_CHECK_PRINT_SUMMARY_JSON:-1}"
print_default_checks="${GPM_LOGIC_CHECK_PRINT_DEFAULT_CHECKS:-0}"
fail_fast="${GPM_LOGIC_CHECK_FAIL_FAST:-0}"

declare -a include_checks_raw=()
declare -a exclude_checks_raw=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      require_value_or_die "--reports-dir" "${2:-}"
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --summary-json)
      require_value_or_die "--summary-json" "${2:-}"
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
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
    --print-summary-json=*)
      print_summary_json="${1#*=}"
      shift
      ;;
    --print-default-checks)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_default_checks="${2:-}"
        shift 2
      else
        print_default_checks="1"
        shift
      fi
      ;;
    --print-default-checks=*)
      print_default_checks="${1#*=}"
      shift
      ;;
    --fail-fast)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_fast="${2:-}"
        shift 2
      else
        fail_fast="1"
        shift
      fi
      ;;
    --fail-fast=*)
      fail_fast="${1#*=}"
      shift
      ;;
    --include-check)
      require_value_or_die "--include-check" "${2:-}"
      include_checks_raw+=("${2:-}")
      shift 2
      ;;
    --include-check=*)
      include_checks_raw+=("${1#*=}")
      shift
      ;;
    --exclude-check)
      require_value_or_die "--exclude-check" "${2:-}"
      exclude_checks_raw+=("${2:-}")
      shift 2
      ;;
    --exclude-check=*)
      exclude_checks_raw+=("${1#*=}")
      shift
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
bool_arg_or_die "--print-default-checks" "$print_default_checks"
bool_arg_or_die "--fail-fast" "$fail_fast"

if [[ "$print_default_checks" == "1" ]]; then
  gpm_logic_check_default_checks_rel
  exit 0
fi

reports_dir="$(abs_path "$reports_dir")"
if [[ -z "$reports_dir" ]]; then
  echo "--reports-dir requires a non-empty value"
  exit 2
fi

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/gpm_logic_check_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$summary_json" ]]; then
  echo "--summary-json requires a non-empty value"
  exit 2
fi

if [[ -e "$reports_dir" && ! -d "$reports_dir" ]]; then
  echo "--reports-dir must reference a directory path: $reports_dir"
  exit 2
fi

summary_dir="$(dirname "$summary_json")"
if [[ -e "$summary_dir" && ! -d "$summary_dir" ]]; then
  echo "summary-json parent is not a directory: $summary_dir"
  exit 2
fi

mkdir -p "$reports_dir"
mkdir -p "$summary_dir"

declare -a default_checks_rel=()
while IFS= read -r rel_path; do
  [[ -n "$rel_path" ]] || continue
  default_checks_rel+=("$rel_path")
done < <(gpm_logic_check_default_checks_rel)

declare -a selected_checks=()
declare -a default_checks_present=()

for rel_path in "${default_checks_rel[@]}"; do
  candidate_path="$ROOT_DIR/$rel_path"
  if [[ -f "$candidate_path" ]]; then
    canonical_path="$(canonical_existing_path "$candidate_path")"
    default_checks_present+=("$canonical_path")
    if ! array_contains "$canonical_path" "${selected_checks[@]}"; then
      selected_checks+=("$canonical_path")
    fi
  fi
done

declare -a include_checks=()
for raw_path in "${include_checks_raw[@]}"; do
  if ! resolve_script_or_die canonical_path "--include-check" "$raw_path"; then
    exit 2
  fi
  include_checks+=("$canonical_path")
  if ! array_contains "$canonical_path" "${selected_checks[@]}"; then
    selected_checks+=("$canonical_path")
  fi
done

declare -a exclude_checks=()
declare -a exclude_checks_basename=()
for raw_path in "${exclude_checks_raw[@]}"; do
  resolve_exclude_match_path resolved_exclude "$raw_path"
  if [[ -n "$resolved_exclude" ]]; then
    exclude_checks+=("$resolved_exclude")
  fi
  if [[ "$raw_path" != */* ]]; then
    exclude_checks_basename+=("$(basename "$raw_path")")
  fi
done

declare -a filtered_checks=()
for check_path in "${selected_checks[@]}"; do
  check_base="$(basename "$check_path")"
  if array_contains "$check_path" "${exclude_checks[@]}"; then
    continue
  fi
  if array_contains "$check_base" "${exclude_checks_basename[@]}"; then
    continue
  fi
  filtered_checks+=("$check_path")
done
selected_checks=("${filtered_checks[@]}")

declare -a result_name=()
declare -a result_path=()
declare -a result_status=()
declare -a result_rc=()
declare -a result_duration=()
declare -a result_log_path=()

selected_count="${#selected_checks[@]}"
executed_count=0
checks_passed=0
checks_failed=0
overall_rc=0
selection_error=""
invariant_error=""

if [[ "$selected_count" -eq 0 ]]; then
  selection_error="no_checks_selected"
  overall_rc=1
  echo "[gpm-logic-check] no checks selected (fail-closed)" >&2
fi

check_index=0
for check_path in "${selected_checks[@]}"; do
  check_index=$((check_index + 1))
  check_base="$(basename "$check_path")"
  check_safe="${check_base//[^A-Za-z0-9._-]/_}"
  log_path="$reports_dir/$(printf '%02d_%s.log' "$check_index" "$check_safe")"

  echo "[gpm-logic-check] check=$check_base status=running log_path=$log_path"
  start_epoch="$(date +%s)"
  set +e
  bash "$check_path" >"$log_path" 2>&1
  check_rc=$?
  set -e
  end_epoch="$(date +%s)"
  duration_sec=$((end_epoch - start_epoch))

  if [[ "$check_rc" -eq 0 ]]; then
    check_status="pass"
    checks_passed=$((checks_passed + 1))
  else
    check_status="fail"
    checks_failed=$((checks_failed + 1))
    if [[ "$overall_rc" -eq 0 ]]; then
      overall_rc="$check_rc"
    fi
  fi

  executed_count=$((executed_count + 1))
  result_name+=("$check_base")
  result_path+=("$check_path")
  result_status+=("$check_status")
  result_rc+=("$check_rc")
  result_duration+=("$duration_sec")
  result_log_path+=("$log_path")

  echo "[gpm-logic-check] check=$check_base status=$check_status rc=$check_rc duration_sec=$duration_sec"

  if [[ "$check_rc" -ne 0 && "$fail_fast" == "1" ]]; then
    echo "[gpm-logic-check] fail-fast stop after check=$check_base rc=$check_rc"
    break
  fi
done

overall_status="pass"
if [[ "$checks_failed" -gt 0 || -n "$selection_error" ]]; then
  overall_status="fail"
fi

if [[ "$overall_status" == "fail" && "$overall_rc" -eq 0 ]]; then
  overall_rc=1
fi

checks_skipped=$((selected_count - executed_count))

if ! validate_summary_invariants; then
  overall_status="fail"
  if [[ "$overall_rc" -eq 0 ]]; then
    overall_rc=1
  fi
fi

print_summary_json_bool="false"
if [[ "$print_summary_json" == "1" ]]; then
  print_summary_json_bool="true"
fi

fail_fast_bool="false"
if [[ "$fail_fast" == "1" ]]; then
  fail_fast_bool="true"
fi

selection_error_json="null"
if [[ -n "$selection_error" ]]; then
  selection_error_json="\"$(json_escape "$selection_error")\""
fi

invariant_error_json="null"
if [[ -n "$invariant_error" ]]; then
  invariant_error_json="\"$(json_escape "$invariant_error")\""
fi

summary_tmp="$(mktemp "$summary_dir/gpm_logic_check_summary.tmp.XXXXXX")"

{
  echo "{"
  echo "  \"version\": 1,"
  echo "  \"schema\": {"
  echo "    \"id\": \"gpm_logic_check_summary\","
  echo "    \"major\": 1,"
  echo "    \"minor\": 0"
  echo "  },"
  echo "  \"generated_at_utc\": \"$(timestamp_utc)\","
  echo "  \"status\": \"$(json_escape "$overall_status")\","
  echo "  \"rc\": $overall_rc,"
  echo "  \"selection_error\": $selection_error_json,"
  echo "  \"invariant_error\": $invariant_error_json,"
  echo "  \"inputs\": {"
  echo "    \"reports_dir\": \"$(json_escape "$reports_dir")\","
  echo "    \"summary_json\": \"$(json_escape "$summary_json")\","
  echo "    \"print_summary_json\": $print_summary_json_bool,"
  echo "    \"fail_fast\": $fail_fast_bool,"
  echo "    \"default_checks_rel\": ["
  if [[ "${#default_checks_rel[@]}" -gt 0 ]]; then
    for ((idx = 0; idx < ${#default_checks_rel[@]}; idx++)); do
      comma=","
      if (( idx == ${#default_checks_rel[@]} - 1 )); then
        comma=""
      fi
      echo "      \"$(json_escape "${default_checks_rel[$idx]}")\"$comma"
    done
  fi
  echo "    ],"
  echo "    \"default_checks_present\": ["
  if [[ "${#default_checks_present[@]}" -gt 0 ]]; then
    for ((idx = 0; idx < ${#default_checks_present[@]}; idx++)); do
      comma=","
      if (( idx == ${#default_checks_present[@]} - 1 )); then
        comma=""
      fi
      echo "      \"$(json_escape "${default_checks_present[$idx]}")\"$comma"
    done
  fi
  echo "    ],"
  echo "    \"include_checks\": ["
  if [[ "${#include_checks[@]}" -gt 0 ]]; then
    for ((idx = 0; idx < ${#include_checks[@]}; idx++)); do
      comma=","
      if (( idx == ${#include_checks[@]} - 1 )); then
        comma=""
      fi
      echo "      \"$(json_escape "${include_checks[$idx]}")\"$comma"
    done
  fi
  echo "    ],"
  echo "    \"exclude_checks\": ["
  if [[ "${#exclude_checks[@]}" -gt 0 ]]; then
    for ((idx = 0; idx < ${#exclude_checks[@]}; idx++)); do
      comma=","
      if (( idx == ${#exclude_checks[@]} - 1 )); then
        comma=""
      fi
      echo "      \"$(json_escape "${exclude_checks[$idx]}")\"$comma"
    done
  fi
  echo "    ],"
  echo "    \"exclude_checks_basename\": ["
  if [[ "${#exclude_checks_basename[@]}" -gt 0 ]]; then
    for ((idx = 0; idx < ${#exclude_checks_basename[@]}; idx++)); do
      comma=","
      if (( idx == ${#exclude_checks_basename[@]} - 1 )); then
        comma=""
      fi
      echo "      \"$(json_escape "${exclude_checks_basename[$idx]}")\"$comma"
    done
  fi
  echo "    ]"
  echo "  },"
  echo "  \"default_checks_present\": ["
  if [[ "${#default_checks_present[@]}" -gt 0 ]]; then
    for ((idx = 0; idx < ${#default_checks_present[@]}; idx++)); do
      comma=","
      if (( idx == ${#default_checks_present[@]} - 1 )); then
        comma=""
      fi
      echo "    \"$(json_escape "${default_checks_present[$idx]}")\"$comma"
    done
  fi
  echo "  ],"
  echo "  \"selected_checks\": ["
  if [[ "${#selected_checks[@]}" -gt 0 ]]; then
    for ((idx = 0; idx < ${#selected_checks[@]}; idx++)); do
      comma=","
      if (( idx == ${#selected_checks[@]} - 1 )); then
        comma=""
      fi
      echo "    \"$(json_escape "${selected_checks[$idx]}")\"$comma"
    done
  fi
  echo "  ],"
  echo "  \"checks_selected\": $selected_count,"
  echo "  \"checks_executed\": $executed_count,"
  echo "  \"checks_skipped\": $checks_skipped,"
  echo "  \"checks_passed\": $checks_passed,"
  echo "  \"checks_failed\": $checks_failed,"
  echo "  \"checks\": ["
  if [[ "$executed_count" -gt 0 ]]; then
    for ((idx = 0; idx < executed_count; idx++)); do
      comma=","
      if (( idx == executed_count - 1 )); then
        comma=""
      fi
      echo "    {"
      echo "      \"name\": \"$(json_escape "${result_name[$idx]}")\","
      echo "      \"path\": \"$(json_escape "${result_path[$idx]}")\","
      echo "      \"status\": \"$(json_escape "${result_status[$idx]}")\","
      echo "      \"rc\": ${result_rc[$idx]},"
      echo "      \"duration_sec\": ${result_duration[$idx]},"
      echo "      \"log_path\": \"$(json_escape "${result_log_path[$idx]}")\""
      echo "    }$comma"
    done
  fi
  echo "  ]"
  echo "}"
} >"$summary_tmp"

mv -f "$summary_tmp" "$summary_json"

echo "[gpm-logic-check] summary_json=$summary_json status=$overall_status rc=$overall_rc checks_failed=$checks_failed checks_executed=$executed_count"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$overall_status" == "fail" ]]; then
  exit "$overall_rc"
fi
exit 0
