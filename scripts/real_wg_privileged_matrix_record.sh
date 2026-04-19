#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/real_wg_privileged_matrix_record.sh \
    [real-wg-privileged-matrix args...] \
    [--matrix-timeout-sec N] \
    [--record-result [0|1]] \
    [--manual-validation-report [0|1]] \
    [--manual-validation-report-summary-json PATH] \
    [--manual-validation-report-md PATH] \
    [--matrix-summary-json PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run Linux root real-WG privileged matrix checks and record the result into
  manual-validation receipts automatically.
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

non_negative_integer_or_die() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be a non-negative integer"
    exit 2
  fi
}

abs_path() {
  local path="$1"
  path="$(trim "$path")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" = /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

prepare_log_dir() {
  local dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
  mkdir -p "$dir"
  printf '%s\n' "$dir"
}

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

safe_append_to_array() {
  local array_name="$1"
  shift
  if [[ ! "$array_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    return 1
  fi
  local -n target_array="$array_name"
  target_array+=("$@")
}

append_existing_artifact() {
  local array_name="$1"
  local path="$2"
  [[ -z "$path" ]] && return 0
  if [[ -e "$path" ]]; then
    safe_append_to_array "$array_name" "$path" || return 1
  fi
}

extract_json_payload() {
  local prefix="$1"
  local text="$2"
  printf '%s\n' "$text" | awk -v p="$prefix" '$0 == "[" p "] summary_json_payload:" {flag=1; next} flag {print}'
}

persist_artifact_text() {
  local path="$1"
  local content="$2"
  [[ -z "$path" ]] && return 0
  if [[ -z "$content" ]]; then
    rm -f "$path" 2>/dev/null || true
  else
    printf '%s\n' "$content" >"$path"
  fi
}

run_and_capture() {
  local __var_name="$1"
  shift
  local tmp rc
  tmp="$(mktemp)"
  if "$@" >"$tmp" 2>&1; then
    printf '%s\n' "[$stage] command_ok: $(print_cmd "$@")" >>"$summary_log"
    cat "$tmp" >>"$summary_log"
    printf -v "$__var_name" '%s' "$(cat "$tmp")"
    rm -f "$tmp"
    return 0
  else
    rc=$?
    printf '%s\n' "[$stage] command_failed rc=$rc: $(print_cmd "$@")" >>"$summary_log"
    cat "$tmp" >>"$summary_log"
    printf -v "$__var_name" '%s' "$(cat "$tmp")"
    rm -f "$tmp"
    return "$rc"
  fi
}

run_with_optional_timeout() {
  local timeout_sec="$1"
  shift
  if [[ "$timeout_sec" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    timeout "${timeout_sec}s" "$@"
  else
    "$@"
  fi
}

easy_node_script="${REAL_WG_PRIVILEGED_MATRIX_RECORD_EASY_NODE_SCRIPT:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$easy_node_script" ]]; then
  echo "missing easy_node helper script: $easy_node_script"
  exit 2
fi

original_args=("$@")
record_result="1"
manual_validation_report_enabled="1"
manual_validation_report_summary_json=""
manual_validation_report_md=""
matrix_summary_json=""
summary_json=""
print_summary_json="0"
matrix_timeout_sec="${REAL_WG_PRIVILEGED_MATRIX_RECORD_TIMEOUT_SEC:-900}"
declare -a matrix_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --matrix-timeout-sec)
      matrix_timeout_sec="${2:-}"
      shift 2
      ;;
    --record-result)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        record_result="${2:-}"
        shift 2
      else
        record_result="1"
        shift
      fi
      ;;
    --manual-validation-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        manual_validation_report_enabled="${2:-}"
        shift 2
      else
        manual_validation_report_enabled="1"
        shift
      fi
      ;;
    --manual-validation-report-summary-json)
      manual_validation_report_summary_json="${2:-}"
      shift 2
      ;;
    --manual-validation-report-md)
      manual_validation_report_md="${2:-}"
      shift 2
      ;;
    --matrix-summary-json)
      matrix_summary_json="${2:-}"
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
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      matrix_args+=("$1")
      shift
      ;;
  esac
done

bool_arg_or_die "--record-result" "$record_result"
bool_arg_or_die "--manual-validation-report" "$manual_validation_report_enabled"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
non_negative_integer_or_die "--matrix-timeout-sec" "$matrix_timeout_sec"

log_dir="$(prepare_log_dir)"
timestamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/real_wg_privileged_matrix_record_${timestamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$matrix_summary_json" ]]; then
  matrix_summary_json="$log_dir/real_wg_privileged_matrix_record_${timestamp}_matrix.json"
else
  matrix_summary_json="$(abs_path "$matrix_summary_json")"
fi
if [[ -z "$manual_validation_report_summary_json" ]]; then
  manual_validation_report_summary_json="$log_dir/manual_validation_readiness_summary.json"
else
  manual_validation_report_summary_json="$(abs_path "$manual_validation_report_summary_json")"
fi
if [[ -z "$manual_validation_report_md" ]]; then
  manual_validation_report_md="$log_dir/manual_validation_readiness_report.md"
else
  manual_validation_report_md="$(abs_path "$manual_validation_report_md")"
fi

mkdir -p "$(dirname "$summary_json")" "$(dirname "$matrix_summary_json")" "$(dirname "$manual_validation_report_summary_json")" "$(dirname "$manual_validation_report_md")"
summary_log="$log_dir/real_wg_privileged_matrix_record_${timestamp}.log"
matrix_log="$log_dir/real_wg_privileged_matrix_record_${timestamp}_matrix.log"
manual_validation_report_log="$log_dir/real_wg_privileged_matrix_record_${timestamp}_manual_validation_report.log"
: >"$summary_log"

stage="matrix"
matrix_status="fail"
matrix_rc=1
notes=""
manual_validation_report_status="skipped"
manual_validation_report_readiness_status=""
manual_validation_report_next_action_check_id=""
matrix_timed_out="0"
matrix_timeout_guard_available="0"
if command -v timeout >/dev/null 2>&1; then
  matrix_timeout_guard_available="1"
fi

write_matrix_summary_json() {
  jq -n \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg status "$matrix_status" \
    --arg notes "$notes" \
    --arg command "$(print_cmd "$easy_node_script" real-wg-privileged-matrix "${matrix_args[@]}")" \
    --arg summary_log "$matrix_log" \
    --arg summary_json "$matrix_summary_json" \
    --argjson matrix_timeout_sec "$matrix_timeout_sec" \
    --arg matrix_timed_out "$matrix_timed_out" \
    --arg matrix_timeout_guard_available "$matrix_timeout_guard_available" \
    --argjson rc "$matrix_rc" \
    '{
      version: 1,
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      notes: $notes,
      command: $command,
      invocation: {
        timeout_sec: $matrix_timeout_sec,
        timed_out: ($matrix_timed_out == "1"),
        timeout_guard_available: ($matrix_timeout_guard_available == "1")
      },
      artifacts: {
        summary_log: $summary_log,
        summary_json: $summary_json
      }
    }' >"$matrix_summary_json"
}

write_summary_json() {
  jq -n \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg status "$matrix_status" \
    --arg notes "$notes" \
    --arg command "$(print_cmd "$0" "${original_args[@]}")" \
    --arg summary_log "$summary_log" \
    --arg summary_json "$summary_json" \
    --arg matrix_summary_json "$matrix_summary_json" \
    --arg matrix_log "$matrix_log" \
    --argjson matrix_timeout_sec "$matrix_timeout_sec" \
    --arg matrix_timed_out "$matrix_timed_out" \
    --arg matrix_timeout_guard_available "$matrix_timeout_guard_available" \
    --argjson matrix_rc "$matrix_rc" \
    --arg manual_validation_report_summary_json "$manual_validation_report_summary_json" \
    --arg manual_validation_report_md "$manual_validation_report_md" \
    --arg manual_validation_report_status "$manual_validation_report_status" \
    --arg manual_validation_report_readiness_status "$manual_validation_report_readiness_status" \
    --arg manual_validation_report_next_action_check_id "$manual_validation_report_next_action_check_id" \
    --arg manual_validation_report_log "$manual_validation_report_log" \
    --argjson manual_validation_report_enabled "$manual_validation_report_enabled" \
    '{
      version: 1,
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $matrix_rc,
      notes: $notes,
      command: $command,
      matrix: {
        status: $status,
        rc: $matrix_rc,
        timeout_sec: $matrix_timeout_sec,
        timed_out: ($matrix_timed_out == "1"),
        timeout_guard_available: ($matrix_timeout_guard_available == "1"),
        summary_json: $matrix_summary_json,
        summary_log: $matrix_log
      },
      manual_validation_report: {
        enabled: ($manual_validation_report_enabled == 1),
        status: $manual_validation_report_status,
        summary_json: $manual_validation_report_summary_json,
        report_md: $manual_validation_report_md,
        log: $manual_validation_report_log,
        readiness_status: $manual_validation_report_readiness_status,
        next_action_check_id: $manual_validation_report_next_action_check_id
      },
      artifacts: {
        summary_log: $summary_log,
        summary_json: $summary_json,
        matrix_summary_json: $matrix_summary_json,
        matrix_log: $matrix_log
      }
    }' >"$summary_json"
}

refresh_manual_validation_report() {
  local report_output=""
  local report_json=""
  local -a report_cmd=()

  if [[ "$manual_validation_report_enabled" != "1" ]]; then
    return 0
  fi

  report_cmd=(
    "$easy_node_script" manual-validation-report
    --overlay-check-id "real_wg_privileged_matrix"
    --overlay-status "$matrix_status"
    --overlay-notes "$notes"
    --overlay-command "$(print_cmd "$0" "${original_args[@]}")"
    --overlay-artifact "$summary_log"
    --overlay-artifact "$summary_json"
    --overlay-artifact "$matrix_summary_json"
    --overlay-artifact "$matrix_log"
    --summary-json "$manual_validation_report_summary_json"
    --report-md "$manual_validation_report_md"
    --print-report 0
    --print-summary-json 0
  )

  stage="manual-validation-report"
  if run_and_capture report_output "${report_cmd[@]}"; then
    manual_validation_report_status="ok"
  else
    manual_validation_report_status="fail"
  fi
  persist_artifact_text "$manual_validation_report_log" "$report_output"

  report_json="$(extract_json_payload "manual-validation-report" "$report_output")"
  if [[ -z "$report_json" && -f "$manual_validation_report_summary_json" ]] && jq -e . "$manual_validation_report_summary_json" >/dev/null 2>&1; then
    report_json="$(cat "$manual_validation_report_summary_json")"
  fi
  if [[ -n "$report_json" ]] && jq -e . >/dev/null 2>&1 <<<"$report_json"; then
    manual_validation_report_readiness_status="$(jq -r '.report.readiness_status // ""' <<<"$report_json")"
    manual_validation_report_next_action_check_id="$(jq -r '.summary.next_action_check_id // ""' <<<"$report_json")"
  fi
}

record_receipt() {
  local -a record_cmd=()
  local receipt_artifact=""

  record_cmd=(
    "$easy_node_script" manual-validation-record
    --check-id "real_wg_privileged_matrix"
    --status "$matrix_status"
    --notes "$notes"
    --command "$(print_cmd "$0" "${original_args[@]}")"
    --show-json 0
  )
  for receipt_artifact in "$@"; do
    record_cmd+=(--artifact "$receipt_artifact")
  done
  "${record_cmd[@]}" >>"$summary_log" 2>&1 || true
}

declare -a matrix_cmd=()
matrix_cmd=(
  "$easy_node_script" real-wg-privileged-matrix
  "${matrix_args[@]}"
)

matrix_output=""
if run_and_capture matrix_output run_with_optional_timeout "$matrix_timeout_sec" "${matrix_cmd[@]}"; then
  matrix_rc=0
else
  matrix_rc=$?
fi
persist_artifact_text "$matrix_log" "$matrix_output"

if [[ "$matrix_rc" -eq 124 ]]; then
  matrix_timed_out="1"
fi

if [[ "$matrix_rc" -eq 0 ]]; then
  matrix_status="pass"
  notes="Linux root real-WG privileged matrix passed"
elif [[ "$matrix_rc" -eq 124 && "$matrix_timeout_sec" -gt 0 && "$matrix_timeout_guard_available" == "1" ]]; then
  matrix_status="fail"
  notes="Linux root real-WG privileged matrix timed out after ${matrix_timeout_sec}s"
else
  matrix_status="fail"
  notes="Linux root real-WG privileged matrix failed"
fi

write_matrix_summary_json
write_summary_json
refresh_manual_validation_report
write_summary_json

declare -a receipt_artifacts=()
append_existing_artifact receipt_artifacts "$summary_log"
append_existing_artifact receipt_artifacts "$summary_json"
append_existing_artifact receipt_artifacts "$matrix_summary_json"
append_existing_artifact receipt_artifacts "$matrix_log"
append_existing_artifact receipt_artifacts "$manual_validation_report_log"
append_existing_artifact receipt_artifacts "$manual_validation_report_summary_json"
append_existing_artifact receipt_artifacts "$manual_validation_report_md"

if [[ "$record_result" == "1" ]]; then
  record_receipt "${receipt_artifacts[@]}"
fi

echo "real-wg-privileged-matrix-record: status=$matrix_status"
echo "summary_log: $summary_log"
echo "summary_json: $summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$matrix_status" != "pass" ]]; then
  exit 1
fi
exit 0
