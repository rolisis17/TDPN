#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

declare -a default_check_ids=()
declare -a default_check_names=()
declare -a default_check_kinds=()
declare -a default_check_targets=()
declare -a default_check_run_regex=()
declare -a default_check_paths=()
declare -a default_check_command=()

build_command_display() {
  local kind="$1"
  local target="$2"
  local run_regex="${3:-}"
  local path="${4:-}"

  case "$kind" in
    go_test)
      if [[ -n "$run_regex" ]]; then
        printf 'go test -count=1 %s -run %s' "$target" "$run_regex"
      else
        printf 'go test -count=1 %s' "$target"
      fi
      ;;
    script)
      printf 'bash %s' "$path"
      ;;
    *)
      printf 'unknown'
      ;;
  esac
}

append_default_check() {
  local check_id="$1"
  local check_name="$2"
  local check_kind="$3"
  local check_target="$4"
  local check_run_regex="${5:-}"
  local check_path="${6:-}"
  local command_display

  command_display="$(build_command_display "$check_kind" "$check_target" "$check_run_regex" "$check_path")"

  default_check_ids+=("$check_id")
  default_check_names+=("$check_name")
  default_check_kinds+=("$check_kind")
  default_check_targets+=("$check_target")
  default_check_run_regex+=("$check_run_regex")
  default_check_paths+=("$check_path")
  default_check_command+=("$command_display")
}

gpm_vpn_logic_check_load_default_checks() {
  default_check_ids=()
  default_check_names=()
  default_check_kinds=()
  default_check_targets=()
  default_check_run_regex=()
  default_check_paths=()
  default_check_command=()

  append_default_check \
    "vpn_path_profile_contract" \
    "vpn_path_profile_contract" \
    "go_test" \
    "./internal/app" \
    "^TestResolvePathProfileValue"

  append_default_check \
    "vpn_wireguard_runtime_contract" \
    "vpn_wireguard_runtime_contract" \
    "go_test" \
    "./pkg/wg" \
    "^Test(Command|CommandClient|NewCommand|RunPreflight|IsTrustedBinaryPathForOS|ResolveClientBinaryPath)"

  append_default_check \
    "vpn_wireguard_key_contract" \
    "vpn_wireguard_key_contract" \
    "go_test" \
    "./pkg/wg" \
    "^Test(DerivePublicKeyFromPrivateFile|RunWGPubkeyCommandFailsWhenBinaryLookupFails|ReadPrivateKeyFileStrict|KeyValidation)"

  append_default_check \
    "vpn_wireguard_packet_contract" \
    "vpn_wireguard_packet_contract" \
    "go_test" \
    "./pkg/relay" \
    "^TestLooksLike"
}

gpm_vpn_logic_check_print_default_checks() {
  local idx
  gpm_vpn_logic_check_load_default_checks
  for ((idx = 0; idx < ${#default_check_ids[@]}; idx++)); do
    printf '%s\n' "${default_check_ids[$idx]}"
  done
}

usage() {
  local idx
  gpm_vpn_logic_check_load_default_checks
  cat <<'USAGE'
Usage:
  ./scripts/gpm_vpn_logic_check.sh [options]

Description:
  Runs a bounded, high-signal VPN logic validation suite and emits a
  deterministic JSON summary artifact.

Options:
  --reports-dir DIR            Directory for per-check logs
  --summary-json PATH          Summary JSON output path
  --print-summary-json [0|1]   Print summary JSON to stdout (default: 1)
  --print-default-checks [0|1] Print default check IDs and exit (default: 0)
  --fail-fast [0|1]            Stop on first failing check (default: 0)
  --check-timeout-sec SEC      Per-check timeout; 0 disables (default: 300)
  --progress-interval-sec SEC  Running heartbeat interval; 0 disables (default: 60)
  --include-check SCRIPT       Add check script (repeatable)
  --exclude-check CHECK        Remove selected check by ID/name/path (repeatable)
  -h, --help                   Show help

Default checks:
USAGE
  for ((idx = 0; idx < ${#default_check_ids[@]}; idx++)); do
    printf '  - %s (%s)\n' "${default_check_ids[$idx]}" "${default_check_command[$idx]}"
  done
  cat <<'USAGE'

Failure mode:
  Fails closed when no checks are selected or when selected checks are invalid.
  Also fails closed when summary invariants are violated.
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

non_negative_int_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be a non-negative integer"
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

declare -a selected_ids=()
declare -a selected_names=()
declare -a selected_kinds=()
declare -a selected_targets=()
declare -a selected_run_regex=()
declare -a selected_paths=()
declare -a selected_command=()

add_selected_check() {
  local check_id="$1"
  local check_name="$2"
  local check_kind="$3"
  local check_target="$4"
  local check_run_regex="$5"
  local check_path="$6"
  local check_command="$7"

  if array_contains "$check_id" "${selected_ids[@]}"; then
    return 0
  fi

  selected_ids+=("$check_id")
  selected_names+=("$check_name")
  selected_kinds+=("$check_kind")
  selected_targets+=("$check_target")
  selected_run_regex+=("$check_run_regex")
  selected_paths+=("$check_path")
  selected_command+=("$check_command")
}

check_is_excluded() {
  local check_id="$1"
  local check_name="$2"
  local check_target="$3"
  local check_path="$4"
  local match_value
  local check_base=""

  for match_value in "${exclude_checks[@]}"; do
    if [[ "$match_value" == "$check_id" || "$match_value" == "$check_name" || "$match_value" == "$check_target" ]]; then
      return 0
    fi
    if [[ -n "$check_path" && "$match_value" == "$check_path" ]]; then
      return 0
    fi
  done

  if [[ -n "$check_path" ]]; then
    check_base="$(basename "$check_path")"
  fi
  for match_value in "${exclude_checks_basename[@]}"; do
    if [[ "$match_value" == "$check_name" ]]; then
      return 0
    fi
    if [[ -n "$check_base" && "$match_value" == "$check_base" ]]; then
      return 0
    fi
  done

  return 1
}

validate_summary_invariants() {
  local idx expected_result_count result_state result_code result_id_value result_timed_out_value
  local computed_skipped
  local first_fail_rc=0
  local saw_fail=0
  local -A seen_selected_ids=()
  local -A seen_result_ids=()

  if [[ "$selected_count" -ne "${#selected_ids[@]}" ]]; then
    invariant_error="selected_count mismatch with selected_ids array length"
    return 1
  fi

  if [[ "$selected_count" -ne "${#selected_names[@]}" || "$selected_count" -ne "${#selected_kinds[@]}" || "$selected_count" -ne "${#selected_targets[@]}" || "$selected_count" -ne "${#selected_run_regex[@]}" || "$selected_count" -ne "${#selected_paths[@]}" || "$selected_count" -ne "${#selected_command[@]}" ]]; then
    invariant_error="selected check arrays length mismatch"
    return 1
  fi

  expected_result_count="${#result_id[@]}"
  if [[ "$executed_count" -ne "$expected_result_count" ]]; then
    invariant_error="executed_count mismatch with result_id array length"
    return 1
  fi

  if [[ "$executed_count" -ne "${#result_name[@]}" || "$executed_count" -ne "${#result_kind[@]}" || "$executed_count" -ne "${#result_target[@]}" || "$executed_count" -ne "${#result_path[@]}" || "$executed_count" -ne "${#result_status[@]}" || "$executed_count" -ne "${#result_rc[@]}" || "$executed_count" -ne "${#result_duration[@]}" || "$executed_count" -ne "${#result_log_path[@]}" || "$executed_count" -ne "${#result_timed_out[@]}" || "$executed_count" -ne "${#result_command[@]}" ]]; then
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

  for result_id_value in "${selected_ids[@]}"; do
    if [[ -z "$result_id_value" ]]; then
      invariant_error="selected_checks contains an empty id"
      return 1
    fi
    if [[ -n "${seen_selected_ids[$result_id_value]+x}" ]]; then
      invariant_error="selected_checks must be unique"
      return 1
    fi
    seen_selected_ids[$result_id_value]=1
  done

  for ((idx = 0; idx < executed_count; idx++)); do
    result_state="${result_status[$idx]}"
    result_code="${result_rc[$idx]}"
    result_id_value="${result_id[$idx]}"
    result_timed_out_value="${result_timed_out[$idx]}"
    if [[ -z "$result_id_value" ]]; then
      invariant_error="check result id must be non-empty"
      return 1
    fi
    if [[ -z "${seen_selected_ids[$result_id_value]+x}" ]]; then
      invariant_error="check result id must exist in selected_checks"
      return 1
    fi
    if [[ -n "${seen_result_ids[$result_id_value]+x}" ]]; then
      invariant_error="check result id must be unique (duplicate execution detected)"
      return 1
    fi
    seen_result_ids[$result_id_value]=1
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
    if [[ "$result_timed_out_value" != "0" && "$result_timed_out_value" != "1" ]]; then
      invariant_error="check timed_out flag must be 0 or 1"
      return 1
    fi
    if [[ "$result_timed_out_value" == "1" && "$result_state" != "fail" ]]; then
      invariant_error="timed_out check must have fail status"
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

  case "$selection_error" in
    "")
      ;;
    "no_checks_selected")
      if [[ "$selected_count" -ne 0 ]]; then
        invariant_error="no_checks_selected requires checks_selected=0"
        return 1
      fi
      ;;
    "invalid_selected_checks")
      if [[ "$invalid_selected_count" -le 0 ]]; then
        invariant_error="invalid_selected_checks requires invalid_selected_checks>0"
        return 1
      fi
      ;;
    *)
      invariant_error="selection_error value is invalid"
      return 1
      ;;
  esac

  if [[ -n "$selection_error" && "$overall_rc" -eq 0 ]]; then
    invariant_error="selection_error requires non-zero rc"
    return 1
  fi

  if [[ -n "$selection_error" && "$executed_count" -ne 0 ]]; then
    invariant_error="selection_error requires checks_executed=0"
    return 1
  fi

  if [[ -n "$selection_error" && "$checks_failed" -ne 0 ]]; then
    invariant_error="selection_error requires checks_failed=0"
    return 1
  fi

  return 0
}

for cmd in bash cat date dirname basename mkdir mktemp mv sleep tail go; do
  need_cmd "$cmd"
done

reports_dir="${GPM_VPN_LOGIC_CHECK_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs/gpm_vpn_logic_check}"
summary_json="${GPM_VPN_LOGIC_CHECK_SUMMARY_JSON:-}"
print_summary_json="${GPM_VPN_LOGIC_CHECK_PRINT_SUMMARY_JSON:-1}"
print_default_checks="${GPM_VPN_LOGIC_CHECK_PRINT_DEFAULT_CHECKS:-0}"
fail_fast="${GPM_VPN_LOGIC_CHECK_FAIL_FAST:-0}"
check_timeout_sec="${GPM_VPN_LOGIC_CHECK_CHECK_TIMEOUT_SEC:-300}"
progress_interval_sec="${GPM_VPN_LOGIC_CHECK_PROGRESS_INTERVAL_SEC:-60}"

declare -a include_checks_raw=()
declare -a include_checks=()
declare -a exclude_checks_raw=()
declare -a exclude_checks=()
declare -a exclude_checks_basename=()

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
    --check-timeout-sec)
      require_value_or_die "--check-timeout-sec" "${2:-}"
      check_timeout_sec="${2:-}"
      shift 2
      ;;
    --check-timeout-sec=*)
      check_timeout_sec="${1#*=}"
      shift
      ;;
    --progress-interval-sec)
      require_value_or_die "--progress-interval-sec" "${2:-}"
      progress_interval_sec="${2:-}"
      shift 2
      ;;
    --progress-interval-sec=*)
      progress_interval_sec="${1#*=}"
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
non_negative_int_arg_or_die "--check-timeout-sec" "$check_timeout_sec"
non_negative_int_arg_or_die "--progress-interval-sec" "$progress_interval_sec"

if [[ "$check_timeout_sec" -gt 0 ]]; then
  need_cmd timeout
fi

if [[ "$print_default_checks" == "1" ]]; then
  gpm_vpn_logic_check_print_default_checks
  exit 0
fi

reports_dir="$(abs_path "$reports_dir")"
if [[ -z "$reports_dir" ]]; then
  echo "--reports-dir requires a non-empty value"
  exit 2
fi

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/gpm_vpn_logic_check_summary.json"
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

gpm_vpn_logic_check_load_default_checks

selected_ids=()
selected_names=()
selected_kinds=()
selected_targets=()
selected_run_regex=()
selected_paths=()
selected_command=()

for ((idx = 0; idx < ${#default_check_ids[@]}; idx++)); do
  add_selected_check \
    "${default_check_ids[$idx]}" \
    "${default_check_names[$idx]}" \
    "${default_check_kinds[$idx]}" \
    "${default_check_targets[$idx]}" \
    "${default_check_run_regex[$idx]}" \
    "${default_check_paths[$idx]}" \
    "${default_check_command[$idx]}"
done

for raw_path in "${include_checks_raw[@]}"; do
  if ! resolve_script_or_die canonical_path "--include-check" "$raw_path"; then
    exit 2
  fi
  include_checks+=("$canonical_path")
  check_id="script:$canonical_path"
  check_name="$(basename "$canonical_path")"
  check_command="$(build_command_display "script" "$canonical_path" "" "$canonical_path")"
  add_selected_check "$check_id" "$check_name" "script" "$canonical_path" "" "$canonical_path" "$check_command"
done

for raw_path in "${exclude_checks_raw[@]}"; do
  resolve_exclude_match_path resolved_exclude "$raw_path"
  if [[ -n "$resolved_exclude" ]]; then
    exclude_checks+=("$resolved_exclude")
  fi
  if [[ "$raw_path" != */* ]]; then
    exclude_checks_basename+=("$(basename "$raw_path")")
  fi
done

declare -a filtered_ids=()
declare -a filtered_names=()
declare -a filtered_kinds=()
declare -a filtered_targets=()
declare -a filtered_run_regex=()
declare -a filtered_paths=()
declare -a filtered_command=()

for ((idx = 0; idx < ${#selected_ids[@]}; idx++)); do
  check_id="${selected_ids[$idx]}"
  check_name="${selected_names[$idx]}"
  check_kind="${selected_kinds[$idx]}"
  check_target="${selected_targets[$idx]}"
  check_run_regex="${selected_run_regex[$idx]}"
  check_path="${selected_paths[$idx]}"
  check_command="${selected_command[$idx]}"
  if check_is_excluded "$check_id" "$check_name" "$check_target" "$check_path"; then
    continue
  fi
  filtered_ids+=("$check_id")
  filtered_names+=("$check_name")
  filtered_kinds+=("$check_kind")
  filtered_targets+=("$check_target")
  filtered_run_regex+=("$check_run_regex")
  filtered_paths+=("$check_path")
  filtered_command+=("$check_command")
done

selected_ids=("${filtered_ids[@]}")
selected_names=("${filtered_names[@]}")
selected_kinds=("${filtered_kinds[@]}")
selected_targets=("${filtered_targets[@]}")
selected_run_regex=("${filtered_run_regex[@]}")
selected_paths=("${filtered_paths[@]}")
selected_command=("${filtered_command[@]}")

declare -a invalid_selected_checks=()
for ((idx = 0; idx < ${#selected_ids[@]}; idx++)); do
  check_id="${selected_ids[$idx]}"
  check_kind="${selected_kinds[$idx]}"
  check_target="${selected_targets[$idx]}"
  check_path="${selected_paths[$idx]}"
  case "$check_kind" in
    go_test)
      if [[ -z "$check_target" ]]; then
        invalid_selected_checks+=("$check_id (empty_target)")
      fi
      ;;
    script)
      if [[ ! -f "$check_path" ]]; then
        invalid_selected_checks+=("$check_path (missing)")
      elif [[ ! -r "$check_path" ]]; then
        invalid_selected_checks+=("$check_path (unreadable)")
      elif [[ ! -s "$check_path" ]]; then
        invalid_selected_checks+=("$check_path (empty)")
      fi
      ;;
    *)
      invalid_selected_checks+=("$check_id (unknown_kind:$check_kind)")
      ;;
  esac
done

declare -a result_id=()
declare -a result_name=()
declare -a result_kind=()
declare -a result_target=()
declare -a result_path=()
declare -a result_command=()
declare -a result_status=()
declare -a result_rc=()
declare -a result_duration=()
declare -a result_log_path=()
declare -a result_timed_out=()

selected_count="${#selected_ids[@]}"
invalid_selected_count="${#invalid_selected_checks[@]}"
executed_count=0
checks_passed=0
checks_failed=0
checks_skipped=0
overall_rc=0
selection_error=""
invariant_error=""

if [[ "$selected_count" -eq 0 ]]; then
  selection_error="no_checks_selected"
  overall_rc=1
  echo "[gpm-vpn-logic-check] no checks selected (fail-closed)" >&2
elif [[ "$invalid_selected_count" -gt 0 ]]; then
  selection_error="invalid_selected_checks"
  overall_rc=1
  echo "[gpm-vpn-logic-check] invalid selected checks (fail-closed)" >&2
  for invalid_check in "${invalid_selected_checks[@]}"; do
    echo "[gpm-vpn-logic-check] invalid_selected_check=$invalid_check" >&2
  done
fi

check_index=0
if [[ -z "$selection_error" ]]; then
for ((idx = 0; idx < ${#selected_ids[@]}; idx++)); do
  declare -a check_cmd=()
  declare -a run_cmd=()
  check_pid=0
  timeout_display="none"
  check_index=$((check_index + 1))
  check_id="${selected_ids[$idx]}"
  check_name="${selected_names[$idx]}"
  check_kind="${selected_kinds[$idx]}"
  check_target="${selected_targets[$idx]}"
  check_run_regex="${selected_run_regex[$idx]}"
  check_path="${selected_paths[$idx]}"
  check_command="${selected_command[$idx]}"
  check_safe="${check_name//[^A-Za-z0-9._-]/_}"
  log_path="$reports_dir/$(printf '%02d_%s.log' "$check_index" "$check_safe")"
  if [[ "$check_timeout_sec" -gt 0 ]]; then
    timeout_display="$check_timeout_sec"
  fi

  case "$check_kind" in
    go_test)
      check_cmd=(go test -count=1 "$check_target")
      if [[ -n "$check_run_regex" ]]; then
        check_cmd+=(-run "$check_run_regex")
      fi
      ;;
    script)
      check_cmd=(bash "$check_path")
      ;;
    *)
      check_cmd=(bash -lc "echo unsupported check kind: $check_kind >&2; exit 2")
      ;;
  esac

  run_cmd=("${check_cmd[@]}")
  if [[ "$check_timeout_sec" -gt 0 ]]; then
    run_cmd=(timeout --foreground --kill-after=15s "${check_timeout_sec}s" "${check_cmd[@]}")
  fi

  echo "[gpm-vpn-logic-check] check=$check_id status=running kind=$check_kind timeout_sec=$timeout_display progress_interval_sec=$progress_interval_sec log_path=$log_path"
  start_epoch="$(date +%s)"

  set +e
  "${run_cmd[@]}" >"$log_path" 2>&1 &
  check_pid=$!
  if [[ "$progress_interval_sec" -gt 0 ]]; then
    next_progress_epoch=$((start_epoch + progress_interval_sec))
    while kill -0 "$check_pid" >/dev/null 2>&1; do
      now_epoch="$(date +%s)"
      if [[ "$now_epoch" -ge "$next_progress_epoch" ]]; then
        elapsed_running_sec=$((now_epoch - start_epoch))
        echo "[gpm-vpn-logic-check] check=$check_id status=running elapsed_sec=$elapsed_running_sec log_path=$log_path"
        next_progress_epoch=$((now_epoch + progress_interval_sec))
      fi
      sleep 1
    done
  fi
  wait "$check_pid"
  check_rc=$?
  set -e
  end_epoch="$(date +%s)"
  duration_sec=$((end_epoch - start_epoch))
  check_timed_out=0
  if [[ "$check_timeout_sec" -gt 0 && ( "$check_rc" -eq 124 || "$check_rc" -eq 137 ) ]]; then
    check_timed_out=1
  fi

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
  result_id+=("$check_id")
  result_name+=("$check_name")
  result_kind+=("$check_kind")
  result_target+=("$check_target")
  result_path+=("$check_path")
  result_command+=("$check_command")
  result_status+=("$check_status")
  result_rc+=("$check_rc")
  result_duration+=("$duration_sec")
  result_log_path+=("$log_path")
  result_timed_out+=("$check_timed_out")

  echo "[gpm-vpn-logic-check] check=$check_id status=$check_status rc=$check_rc duration_sec=$duration_sec timed_out=$check_timed_out"
  if [[ "$check_status" == "fail" ]]; then
    if [[ "$check_timed_out" -eq 1 ]]; then
      echo "[gpm-vpn-logic-check] check=$check_id failure=timeout timeout_sec=$check_timeout_sec hint=inspect_log_tail_or_raise_timeout"
    else
      echo "[gpm-vpn-logic-check] check=$check_id failure=nonzero_exit"
    fi
    if [[ -s "$log_path" ]]; then
      echo "[gpm-vpn-logic-check] check=$check_id failure_log_tail_begin"
      tail -n 40 "$log_path"
      echo "[gpm-vpn-logic-check] check=$check_id failure_log_tail_end"
    else
      echo "[gpm-vpn-logic-check] check=$check_id failure_log_tail_unavailable reason=empty_log"
    fi
  fi

  if [[ "$check_rc" -ne 0 && "$fail_fast" == "1" ]]; then
    echo "[gpm-vpn-logic-check] fail-fast stop after check=$check_id rc=$check_rc"
    break
  fi
done
fi

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

summary_tmp="$(mktemp "$summary_dir/gpm_vpn_logic_check_summary.tmp.XXXXXX")"

{
  echo "{"
  echo "  \"version\": 1,"
  echo "  \"schema\": {"
  echo "    \"id\": \"gpm_vpn_logic_check_summary\","
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
  echo "    \"check_timeout_sec\": $check_timeout_sec,"
  echo "    \"progress_interval_sec\": $progress_interval_sec,"
  echo "    \"default_checks\": ["
  if [[ "${#default_check_ids[@]}" -gt 0 ]]; then
    for ((idx = 0; idx < ${#default_check_ids[@]}; idx++)); do
      comma=","
      if (( idx == ${#default_check_ids[@]} - 1 )); then
        comma=""
      fi
      echo "      {"
      echo "        \"id\": \"$(json_escape "${default_check_ids[$idx]}")\","
      echo "        \"name\": \"$(json_escape "${default_check_names[$idx]}")\","
      echo "        \"kind\": \"$(json_escape "${default_check_kinds[$idx]}")\","
      echo "        \"target\": \"$(json_escape "${default_check_targets[$idx]}")\","
      echo "        \"run_regex\": \"$(json_escape "${default_check_run_regex[$idx]}")\","
      echo "        \"path\": \"$(json_escape "${default_check_paths[$idx]}")\","
      echo "        \"command\": \"$(json_escape "${default_check_command[$idx]}")\""
      echo "      }$comma"
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
  echo "  \"invalid_selected_checks\": ["
  if [[ "${#invalid_selected_checks[@]}" -gt 0 ]]; then
    for ((idx = 0; idx < ${#invalid_selected_checks[@]}; idx++)); do
      comma=","
      if (( idx == ${#invalid_selected_checks[@]} - 1 )); then
        comma=""
      fi
      echo "    \"$(json_escape "${invalid_selected_checks[$idx]}")\"$comma"
    done
  fi
  echo "  ],"
  echo "  \"selected_checks\": ["
  if [[ "${#selected_ids[@]}" -gt 0 ]]; then
    for ((idx = 0; idx < ${#selected_ids[@]}; idx++)); do
      comma=","
      if (( idx == ${#selected_ids[@]} - 1 )); then
        comma=""
      fi
      echo "    \"$(json_escape "${selected_ids[$idx]}")\"$comma"
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
      check_timed_out_bool="false"
      if [[ "${result_timed_out[$idx]}" -eq 1 ]]; then
        check_timed_out_bool="true"
      fi
      echo "    {"
      echo "      \"id\": \"$(json_escape "${result_id[$idx]}")\","
      echo "      \"name\": \"$(json_escape "${result_name[$idx]}")\","
      echo "      \"kind\": \"$(json_escape "${result_kind[$idx]}")\","
      echo "      \"target\": \"$(json_escape "${result_target[$idx]}")\","
      echo "      \"path\": \"$(json_escape "${result_path[$idx]}")\","
      echo "      \"command\": \"$(json_escape "${result_command[$idx]}")\","
      echo "      \"status\": \"$(json_escape "${result_status[$idx]}")\","
      echo "      \"rc\": ${result_rc[$idx]},"
      echo "      \"timed_out\": $check_timed_out_bool,"
      echo "      \"duration_sec\": ${result_duration[$idx]},"
      echo "      \"log_path\": \"$(json_escape "${result_log_path[$idx]}")\""
      echo "    }$comma"
    done
  fi
  echo "  ]"
  echo "}"
} >"$summary_tmp"

mv -f "$summary_tmp" "$summary_json"

echo "[gpm-vpn-logic-check] summary_json=$summary_json status=$overall_status rc=$overall_rc checks_failed=$checks_failed checks_executed=$executed_count"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$overall_status" == "fail" ]]; then
  exit "$overall_rc"
fi
exit 0
