#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_validation_debt_actionable_run.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--parallel [0|1]] \
    [--max-actions N] \
    [--include-id ID]... \
    [--exclude-id ID]... \
    [--print-summary-json [0|1]]

Purpose:
  Execute a deterministic actionable set of M1/M3 validation-debt checks that
  do not require real-host dependencies.

Default checks:
  - m1_client_3hop_runtime
      scripts/integration_client_3hop_runtime.sh
  - m1_roadmap_progress_report_contract
      scripts/integration_roadmap_progress_report.sh
  - m3_micro_relay_operator_floor
      scripts/integration_client_vpn_operator_floor.sh
  - m3_three_machine_real_host_validation_pack
      scripts/integration_three_machine_real_host_validation_pack.sh

Env-overridable check script paths (for stubbing/integration):
  - ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_CLIENT_3HOP_RUNTIME_SCRIPT
  - ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_ROADMAP_PROGRESS_REPORT_SCRIPT
  - ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_MICRO_RELAY_OPERATOR_FLOOR_SCRIPT
  - ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_THREE_MACHINE_REAL_HOST_VALIDATION_PACK_SCRIPT

Include/Exclude env defaults (CSV):
  - ROADMAP_VALIDATION_DEBT_ACTIONABLE_INCLUDE_IDS
  - ROADMAP_VALIDATION_DEBT_ACTIONABLE_EXCLUDE_IDS

Failure diagnostics:
  - ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_FAILURE_LOG_TAIL_LINES (default: 20)

Defaults:
  --parallel 0
  --max-actions 0        (0 = no limit)
  --print-summary-json 1

Failure mode:
  - Fails closed when no checks are selected after filtering.
  - Fails closed when selected checks contain duplicate ids with conflicting scripts.
  - Returns first failing check rc in deterministic selected-order.
USAGE
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local value
  value="$(trim "${1:-}")"
  if [[ -z "$value" ]]; then
    printf '%s' ""
  elif [[ "$value" == /* ]]; then
    printf '%s' "$value"
  else
    printf '%s' "$ROOT_DIR/$value"
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

int_arg_or_die() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an integer"
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

append_csv_tokens() {
  local csv="${1:-}"
  local target_name="$2"
  local token
  IFS=',' read -r -a __csv_parts <<<"$csv"
  for token in "${__csv_parts[@]}"; do
    token="$(trim "$token")"
    if [[ -n "$token" ]]; then
      eval "$target_name+=(\"\$token\")"
    fi
  done
}

append_unique_value() {
  local value="$1"
  local -n out_ref="$2"
  local existing
  for existing in "${out_ref[@]:-}"; do
    if [[ "$existing" == "$value" ]]; then
      return
    fi
  done
  out_ref+=("$value")
}

array_to_json() {
  local -a items=("$@")
  if [[ "${#items[@]}" -eq 0 ]]; then
    printf '[]'
    return
  fi
  printf '%s\n' "${items[@]}" | jq -R . | jq -s .
}

log_tail_window_json() {
  local log_path="${1:-}"
  local max_lines="${2:-0}"
  local total_line_count=0
  local -a tail_lines=()
  local line
  if [[ "$max_lines" =~ ^[0-9]+$ ]] && (( max_lines > 0 )) && [[ -f "$log_path" && -r "$log_path" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      total_line_count=$((total_line_count + 1))
      tail_lines+=("$line")
      if (( ${#tail_lines[@]} > max_lines )); then
        tail_lines=("${tail_lines[@]:1}")
      fi
    done < "$log_path"
  fi

  local tail_lines_json='[]'
  if (( ${#tail_lines[@]} > 0 )); then
    tail_lines_json="$(printf '%s\n' "${tail_lines[@]}" | jq -R . | jq -s .)"
  fi
  local line_count="${#tail_lines[@]}"
  local truncated_json="false"
  if (( total_line_count > line_count )); then
    truncated_json="true"
  fi

  jq -cn \
    --argjson lines "$tail_lines_json" \
    --argjson line_count "$line_count" \
    --argjson total_line_count "$total_line_count" \
    --argjson truncated "$truncated_json" \
    '{
      log_tail_lines: $lines,
      log_tail_line_count: $line_count,
      log_total_line_count: $total_line_count,
      log_tail_truncated: $truncated
    }'
}

augment_result_file_with_failure_diagnostics() {
  local result_path="$1"
  if [[ ! -s "$result_path" ]] || ! jq -e . "$result_path" >/dev/null 2>&1; then
    return
  fi
  local status
  status="$(jq -r '.status // ""' "$result_path")"
  if [[ "$status" != "fail" ]]; then
    return
  fi
  local log_path
  log_path="$(jq -r '.artifacts.log // .log // ""' "$result_path")"
  local failure_diagnostics_json
  failure_diagnostics_json="$(log_tail_window_json "$log_path" "$failure_log_tail_lines")"
  local updated_json
  updated_json="$(jq -c --argjson failure_diagnostics "$failure_diagnostics_json" '. + {failure_diagnostics: $failure_diagnostics}' "$result_path")"
  printf '%s\n' "$updated_json" >"$result_path"
}

need_cmd bash
need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_REPORTS_DIR:-}"
summary_json="${ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_SUMMARY_JSON:-}"
parallel="${ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_PARALLEL:-0}"
max_actions="${ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_MAX_ACTIONS:-0}"
print_summary_json="${ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_PRINT_SUMMARY_JSON:-1}"
failure_log_tail_lines="${ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_FAILURE_LOG_TAIL_LINES:-20}"

declare -a include_ids=()
declare -a exclude_ids=()
append_csv_tokens "${ROADMAP_VALIDATION_DEBT_ACTIONABLE_INCLUDE_IDS:-}" include_ids
append_csv_tokens "${ROADMAP_VALIDATION_DEBT_ACTIONABLE_EXCLUDE_IDS:-}" exclude_ids
include_ids_requested_count="${#include_ids[@]}"
exclude_ids_requested_count="${#exclude_ids[@]}"

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
    --parallel)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        parallel="${2:-}"
        shift 2
      else
        parallel="1"
        shift
      fi
      ;;
    --parallel=*)
      parallel="${1#*=}"
      shift
      ;;
    --max-actions)
      require_value_or_die "--max-actions" "${2:-}"
      max_actions="${2:-}"
      shift 2
      ;;
    --max-actions=*)
      max_actions="${1#*=}"
      shift
      ;;
    --include-id)
      require_value_or_die "--include-id" "${2:-}"
      include_ids+=("${2:-}")
      shift 2
      ;;
    --include-id=*)
      include_ids+=("${1#*=}")
      shift
      ;;
    --exclude-id)
      require_value_or_die "--exclude-id" "${2:-}"
      exclude_ids+=("${2:-}")
      shift 2
      ;;
    --exclude-id=*)
      exclude_ids+=("${1#*=}")
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

bool_arg_or_die "--parallel" "$parallel"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
int_arg_or_die "--max-actions" "$max_actions"
int_arg_or_die "--failure-log-tail-lines" "$failure_log_tail_lines"

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/roadmap_validation_debt_actionable_run_${run_stamp}"
fi
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/roadmap_validation_debt_actionable_run_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

declare -a check_ids=(
  "m1_client_3hop_runtime"
  "m1_roadmap_progress_report_contract"
  "m3_micro_relay_operator_floor"
  "m3_three_machine_real_host_validation_pack"
)
declare -a check_labels=(
  "M1 client 3-hop runtime validation"
  "M1 roadmap progress report contract validation"
  "M3 micro-relay operator-floor validation"
  "M3 three-machine real-host validation pack contract"
)
declare -a check_focus=(
  "m1"
  "m1"
  "m3_micro_relay"
  "m3_validation_pack"
)
declare -a check_default_rel=(
  "scripts/integration_client_3hop_runtime.sh"
  "scripts/integration_roadmap_progress_report.sh"
  "scripts/integration_client_vpn_operator_floor.sh"
  "scripts/integration_three_machine_real_host_validation_pack.sh"
)
declare -a check_env_var=(
  "ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_CLIENT_3HOP_RUNTIME_SCRIPT"
  "ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_ROADMAP_PROGRESS_REPORT_SCRIPT"
  "ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_MICRO_RELAY_OPERATOR_FLOOR_SCRIPT"
  "ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_THREE_MACHINE_REAL_HOST_VALIDATION_PACK_SCRIPT"
)
declare -a check_script_path=()

for idx in "${!check_ids[@]}"; do
  env_name="${check_env_var[$idx]}"
  default_path="$ROOT_DIR/${check_default_rel[$idx]}"
  override_path="${!env_name:-}"
  if [[ -n "$override_path" ]]; then
    resolved_path="$(abs_path "$override_path")"
  else
    resolved_path="$(abs_path "$default_path")"
  fi
  check_script_path+=("$resolved_path")
done

default_count="${#check_ids[@]}"

declare -a include_ids_unique=()
declare -a exclude_ids_unique=()
for id in "${include_ids[@]}"; do
  append_unique_value "$id" include_ids_unique
done
for id in "${exclude_ids[@]}"; do
  append_unique_value "$id" exclude_ids_unique
done
include_ids_unique_count="${#include_ids_unique[@]}"
exclude_ids_unique_count="${#exclude_ids_unique[@]}"

declare -a unknown_include_ids=()
declare -a unknown_exclude_ids=()
for id in "${include_ids_unique[@]}"; do
  if ! array_contains "$id" "${check_ids[@]}"; then
    unknown_include_ids+=("$id")
  fi
done
for id in "${exclude_ids_unique[@]}"; do
  if ! array_contains "$id" "${check_ids[@]}"; then
    unknown_exclude_ids+=("$id")
  fi
done

declare -a selected_indices=()
if [[ "${#include_ids_unique[@]}" -gt 0 ]]; then
  for idx in "${!check_ids[@]}"; do
    if array_contains "${check_ids[$idx]}" "${include_ids_unique[@]}"; then
      selected_indices+=("$idx")
    fi
  done
else
  for idx in "${!check_ids[@]}"; do
    selected_indices+=("$idx")
  done
fi
after_include_count="${#selected_indices[@]}"

if [[ "${#exclude_ids_unique[@]}" -gt 0 ]]; then
  declare -a after_exclude_indices=()
  for idx in "${selected_indices[@]}"; do
    if array_contains "${check_ids[$idx]}" "${exclude_ids_unique[@]}"; then
      continue
    fi
    after_exclude_indices+=("$idx")
  done
  selected_indices=("${after_exclude_indices[@]}")
fi
after_exclude_count="${#selected_indices[@]}"

if (( max_actions > 0 && ${#selected_indices[@]} > max_actions )); then
  selected_indices=("${selected_indices[@]:0:max_actions}")
fi
after_max_actions_count="${#selected_indices[@]}"

before_dedupe_count="${#selected_indices[@]}"
deduped_duplicate_count=0
declare -a conflicting_duplicate_check_ids=()
declare -A seen_script_by_check_id=()
declare -a selected_deduped_indices=()
for idx in "${selected_indices[@]}"; do
  check_id="${check_ids[$idx]}"
  script_path="${check_script_path[$idx]}"
  if [[ -n "${seen_script_by_check_id[$check_id]+x}" ]]; then
    if [[ "${seen_script_by_check_id[$check_id]}" == "$script_path" ]]; then
      deduped_duplicate_count=$((deduped_duplicate_count + 1))
      continue
    fi
    append_unique_value "$check_id" conflicting_duplicate_check_ids
    continue
  fi
  seen_script_by_check_id["$check_id"]="$script_path"
  selected_deduped_indices+=("$idx")
done
selected_indices=("${selected_deduped_indices[@]}")
after_dedupe_count="${#selected_indices[@]}"

declare -a selected_ids=()
for idx in "${selected_indices[@]}"; do
  selected_ids+=("${check_ids[$idx]}")
done

selected_count="${#selected_indices[@]}"
selection_error=""
selection_error_rc=0
if [[ "${#unknown_include_ids[@]}" -gt 0 || "${#unknown_exclude_ids[@]}" -gt 0 ]]; then
  selection_error="unknown_check_ids"
  selection_error_rc=3
  unknown_include_csv="none"
  unknown_exclude_csv="none"
  if [[ "${#unknown_include_ids[@]}" -gt 0 ]]; then
    unknown_include_csv="$(IFS=','; printf '%s' "${unknown_include_ids[*]}")"
  fi
  if [[ "${#unknown_exclude_ids[@]}" -gt 0 ]]; then
    unknown_exclude_csv="$(IFS=','; printf '%s' "${unknown_exclude_ids[*]}")"
  fi
  echo "[roadmap-validation-debt-actionable-run] stage=selection status=fail reason=unknown check id filters include=$unknown_include_csv exclude=$unknown_exclude_csv"
elif [[ "${#conflicting_duplicate_check_ids[@]}" -gt 0 ]]; then
  selection_error="conflicting_duplicate_check_ids"
  selection_error_rc=3
  conflicting_csv="$(IFS=','; printf '%s' "${conflicting_duplicate_check_ids[*]}")"
  echo "[roadmap-validation-debt-actionable-run] stage=selection status=fail reason=conflicting duplicate check ids ids=$conflicting_csv"
elif (( selected_count == 0 )); then
  selection_error="no_checks_selected"
  selection_error_rc=1
  echo "[roadmap-validation-debt-actionable-run] stage=selection status=fail reason=no checks selected (fail-closed)"
else
  selected_ids_csv_stage="$(IFS=','; printf '%s' "${selected_ids[*]}")"
  echo "[roadmap-validation-debt-actionable-run] stage=selection status=pass selected_count=$selected_count ids=$selected_ids_csv_stage"
fi

selected_ids_csv="none"
if (( selected_count > 0 )); then
  selected_ids_csv="$(IFS=','; printf '%s' "${selected_ids[*]}")"
fi
echo "[roadmap-validation-debt-actionable-run] selected_checks=$selected_count parallel=$parallel max_actions=$max_actions ids=$selected_ids_csv"

results_tmp="$(mktemp)"
results_tmp_dir="$(mktemp -d)"
trap 'rm -f "$results_tmp"; rm -rf "$results_tmp_dir"' EXIT
: >"$results_tmp"

declare -a result_files=()
declare -a result_pids=()

if [[ -z "$selection_error" && "$selected_count" -gt 0 ]]; then
  echo "[roadmap-validation-debt-actionable-run] stage=execution status=running selected_checks=$selected_count parallel=$parallel"
  for order_idx in "${!selected_indices[@]}"; do
    idx="${selected_indices[$order_idx]}"
    check_id="${check_ids[$idx]}"
    check_label="${check_labels[$idx]}"
    check_focus_value="${check_focus[$idx]}"
    script_path="${check_script_path[$idx]}"
    safe_id="${check_id//[^A-Za-z0-9._-]/_}"
    log_path="$reports_dir/check_$(printf '%02d' $((order_idx + 1)))_${safe_id}.log"
    result_path="$results_tmp_dir/check_$(printf '%02d' $((order_idx + 1)))_${safe_id}.json"
    result_files[$order_idx]="$result_path"

    if [[ ! -f "$script_path" ]]; then
      jq -cn \
        --arg id "$check_id" \
        --arg label "$check_label" \
        --arg focus "$check_focus_value" \
        --arg script_path "$script_path" \
        --arg status "fail" \
        --arg failure_kind "missing_script" \
        --arg notes "check script not found" \
        --arg log "$log_path" \
        --argjson rc 127 \
        --argjson duration_sec 0 \
        '{
          id: $id,
          label: $label,
          focus: $focus,
          script_path: $script_path,
          status: $status,
          rc: $rc,
          duration_sec: $duration_sec,
          failure_kind: $failure_kind,
          notes: $notes,
          artifacts: { log: $log }
        }' >"$result_path"
      continue
    fi

    if [[ ! -r "$script_path" ]]; then
      jq -cn \
        --arg id "$check_id" \
        --arg label "$check_label" \
        --arg focus "$check_focus_value" \
        --arg script_path "$script_path" \
        --arg status "fail" \
        --arg failure_kind "unreadable_script" \
        --arg notes "check script is not readable" \
        --arg log "$log_path" \
        --argjson rc 126 \
        --argjson duration_sec 0 \
        '{
          id: $id,
          label: $label,
          focus: $focus,
          script_path: $script_path,
          status: $status,
          rc: $rc,
          duration_sec: $duration_sec,
          failure_kind: $failure_kind,
          notes: $notes,
          artifacts: { log: $log }
        }' >"$result_path"
      continue
    fi

    echo "[roadmap-validation-debt-actionable-run] check=$check_id status=running"
    if [[ "$parallel" == "1" ]]; then
      (
        start_epoch="$(date +%s)"
        set +e
        bash "$script_path" >"$log_path" 2>&1
        check_rc=$?
        set -e
        end_epoch="$(date +%s)"
        duration_sec=$((end_epoch - start_epoch))
        check_status="pass"
        failure_kind="none"
        notes=""
        if (( check_rc != 0 )); then
          check_status="fail"
          failure_kind="check_failed"
          notes="check exited non-zero"
        fi
        jq -cn \
          --arg id "$check_id" \
          --arg label "$check_label" \
          --arg focus "$check_focus_value" \
          --arg script_path "$script_path" \
          --arg status "$check_status" \
          --arg failure_kind "$failure_kind" \
          --arg notes "$notes" \
          --arg log "$log_path" \
          --argjson rc "$check_rc" \
          --argjson duration_sec "$duration_sec" \
          '{
            id: $id,
            label: $label,
            focus: $focus,
            script_path: $script_path,
            status: $status,
            rc: $rc,
            duration_sec: $duration_sec,
            failure_kind: $failure_kind,
            notes: (if $notes == "" then null else $notes end),
            artifacts: { log: $log }
          }' >"$result_path"
      ) &
      result_pids[$order_idx]=$!
    else
      start_epoch="$(date +%s)"
      set +e
      bash "$script_path" >"$log_path" 2>&1
      check_rc=$?
      set -e
      end_epoch="$(date +%s)"
      duration_sec=$((end_epoch - start_epoch))
      check_status="pass"
      failure_kind="none"
      notes=""
      if (( check_rc != 0 )); then
        check_status="fail"
        failure_kind="check_failed"
        notes="check exited non-zero"
      fi
      jq -cn \
        --arg id "$check_id" \
        --arg label "$check_label" \
        --arg focus "$check_focus_value" \
        --arg script_path "$script_path" \
        --arg status "$check_status" \
        --arg failure_kind "$failure_kind" \
        --arg notes "$notes" \
        --arg log "$log_path" \
        --argjson rc "$check_rc" \
        --argjson duration_sec "$duration_sec" \
        '{
          id: $id,
          label: $label,
          focus: $focus,
          script_path: $script_path,
          status: $status,
          rc: $rc,
          duration_sec: $duration_sec,
          failure_kind: $failure_kind,
          notes: (if $notes == "" then null else $notes end),
          artifacts: { log: $log }
        }' >"$result_path"
    fi
  done
elif [[ -n "$selection_error" ]]; then
  echo "[roadmap-validation-debt-actionable-run] stage=execution status=skipped reason=$selection_error"
fi

if [[ -z "$selection_error" && "$parallel" == "1" ]]; then
  for order_idx in "${!selected_indices[@]}"; do
    pid="${result_pids[$order_idx]:-}"
    if [[ -n "$pid" ]]; then
      set +e
      wait "$pid"
      wait_rc=$?
      set -e
      if (( wait_rc != 0 )); then
        idx="${selected_indices[$order_idx]}"
        check_id="${check_ids[$idx]}"
        check_label="${check_labels[$idx]}"
        check_focus_value="${check_focus[$idx]}"
        script_path="${check_script_path[$idx]}"
        safe_id="${check_id//[^A-Za-z0-9._-]/_}"
        log_path="$reports_dir/check_$(printf '%02d' $((order_idx + 1)))_${safe_id}.log"
        result_path="${result_files[$order_idx]}"
        jq -cn \
          --arg id "$check_id" \
          --arg label "$check_label" \
          --arg focus "$check_focus_value" \
          --arg script_path "$script_path" \
          --arg status "fail" \
          --arg failure_kind "runner_error" \
          --arg notes "parallel worker failed (wait rc=$wait_rc)" \
          --arg log "$log_path" \
          --argjson rc "$wait_rc" \
          --argjson duration_sec 0 \
          '{
            id: $id,
            label: $label,
            focus: $focus,
            script_path: $script_path,
            status: $status,
            rc: $rc,
            duration_sec: $duration_sec,
            failure_kind: $failure_kind,
            notes: $notes,
            artifacts: { log: $log }
          }' >"$result_path"
      fi
    fi
  done
fi

executed_count=0
pass_count=0
fail_count=0
overall_rc=0
overall_status="pass"

if [[ -n "$selection_error" ]]; then
  overall_status="fail"
  overall_rc="$selection_error_rc"
fi

if [[ -z "$selection_error" ]]; then
  for order_idx in "${!selected_indices[@]}"; do
    idx="${selected_indices[$order_idx]}"
    check_id="${check_ids[$idx]}"
    result_path="${result_files[$order_idx]}"
    if [[ ! -s "$result_path" ]] || ! jq -e . "$result_path" >/dev/null 2>&1; then
      check_label="${check_labels[$idx]}"
      check_focus_value="${check_focus[$idx]}"
      script_path="${check_script_path[$idx]}"
      safe_id="${check_id//[^A-Za-z0-9._-]/_}"
      log_path="$reports_dir/check_$(printf '%02d' $((order_idx + 1)))_${safe_id}.log"
      jq -cn \
        --arg id "$check_id" \
        --arg label "$check_label" \
        --arg focus "$check_focus_value" \
        --arg script_path "$script_path" \
        --arg status "fail" \
        --arg failure_kind "missing_result" \
        --arg notes "missing check result payload" \
        --arg log "$log_path" \
        --argjson rc 125 \
        --argjson duration_sec 0 \
        '{
          id: $id,
          label: $label,
          focus: $focus,
          script_path: $script_path,
          status: $status,
          rc: $rc,
          duration_sec: $duration_sec,
          failure_kind: $failure_kind,
          notes: $notes,
          artifacts: { log: $log }
        }' >"$result_path"
      fi

    augment_result_file_with_failure_diagnostics "$result_path"
    check_status="$(jq -r '.status // "fail"' "$result_path")"
    check_rc="$(jq -r '.rc // 125' "$result_path")"
    executed_count=$((executed_count + 1))
    if [[ "$check_status" == "pass" ]]; then
      pass_count=$((pass_count + 1))
      echo "[roadmap-validation-debt-actionable-run] check=$check_id status=pass rc=0"
    else
      fail_count=$((fail_count + 1))
      echo "[roadmap-validation-debt-actionable-run] check=$check_id status=fail rc=$check_rc"
      if [[ "$overall_rc" -eq 0 ]]; then
        overall_rc="$check_rc"
      fi
      overall_status="fail"
    fi

    jq -c '.' "$result_path" >>"$results_tmp"
  done
fi

if [[ -n "$selection_error" ]]; then
  overall_status="fail"
  if [[ "$overall_rc" -eq 0 ]]; then
    overall_rc="$selection_error_rc"
  fi
fi

if [[ "$overall_status" == "pass" ]]; then
  echo "[roadmap-validation-debt-actionable-run] stage=execution status=pass executed=$executed_count pass=$pass_count fail=$fail_count"
else
  echo "[roadmap-validation-debt-actionable-run] stage=execution status=fail rc=$overall_rc executed=$executed_count pass=$pass_count fail=$fail_count"
fi

checks_json="$(jq -s '.' "$results_tmp")"
selected_ids_json="$(array_to_json "${selected_ids[@]}")"
include_ids_json="$(array_to_json "${include_ids_unique[@]}")"
exclude_ids_json="$(array_to_json "${exclude_ids_unique[@]}")"
unknown_include_ids_json="$(array_to_json "${unknown_include_ids[@]}")"
unknown_exclude_ids_json="$(array_to_json "${unknown_exclude_ids[@]}")"
conflicting_duplicate_check_ids_json="$(array_to_json "${conflicting_duplicate_check_ids[@]}")"

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$overall_status" \
  --argjson rc "$overall_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg selection_error "$selection_error" \
  --argjson selection_error_rc "$selection_error_rc" \
  --argjson parallel "$parallel" \
  --argjson max_actions "$max_actions" \
  --argjson print_summary_json "$print_summary_json" \
  --argjson failure_log_tail_lines "$failure_log_tail_lines" \
  --argjson include_ids "$include_ids_json" \
  --argjson exclude_ids "$exclude_ids_json" \
  --argjson selected_ids "$selected_ids_json" \
  --argjson checks "$checks_json" \
  --arg default_client_3hop_rel "${check_default_rel[0]}" \
  --arg default_roadmap_rel "${check_default_rel[1]}" \
  --arg default_micro_relay_rel "${check_default_rel[2]}" \
  --arg default_m3_validation_pack_rel "${check_default_rel[3]}" \
  --arg default_client_3hop_path "${check_script_path[0]}" \
  --arg default_roadmap_path "${check_script_path[1]}" \
  --arg default_micro_relay_path "${check_script_path[2]}" \
  --arg default_m3_validation_pack_path "${check_script_path[3]}" \
  --arg default_client_3hop_env "${check_env_var[0]}" \
  --arg default_roadmap_env "${check_env_var[1]}" \
  --arg default_micro_relay_env "${check_env_var[2]}" \
  --arg default_m3_validation_pack_env "${check_env_var[3]}" \
  --argjson default_count "$default_count" \
  --argjson include_ids_requested_count "$include_ids_requested_count" \
  --argjson include_ids_unique_count "$include_ids_unique_count" \
  --argjson exclude_ids_requested_count "$exclude_ids_requested_count" \
  --argjson exclude_ids_unique_count "$exclude_ids_unique_count" \
  --argjson before_dedupe_count "$before_dedupe_count" \
  --argjson deduped_duplicate_count "$deduped_duplicate_count" \
  --argjson after_dedupe_count "$after_dedupe_count" \
  --argjson unknown_include_ids "$unknown_include_ids_json" \
  --argjson unknown_exclude_ids "$unknown_exclude_ids_json" \
  --argjson conflicting_duplicate_check_ids "$conflicting_duplicate_check_ids_json" \
  --argjson after_include_count "$after_include_count" \
  --argjson after_exclude_count "$after_exclude_count" \
  --argjson after_max_actions_count "$after_max_actions_count" \
  --argjson selected_count "$selected_count" \
  --argjson executed_count "$executed_count" \
  --argjson pass_count "$pass_count" \
  --argjson fail_count "$fail_count" \
  '{
    version: 1,
    schema: { id: "roadmap_validation_debt_actionable_run_summary", major: 1, minor: 0 },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    selection_error_rc: (if $selection_error == "" then null else $selection_error_rc end),
    selection_error: (if $selection_error == "" then null else $selection_error end),
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      parallel: ($parallel == 1),
      max_actions: $max_actions,
      print_summary_json: ($print_summary_json == 1),
      failure_log_tail_lines: $failure_log_tail_lines,
      include_ids: $include_ids,
      exclude_ids: $exclude_ids
    },
    checks_catalog: [
      {
        id: "m1_client_3hop_runtime",
        label: "M1 client 3-hop runtime validation",
        focus: "m1",
        default_script_rel: $default_client_3hop_rel,
        resolved_script_path: $default_client_3hop_path,
        script_override_env: $default_client_3hop_env
      },
      {
        id: "m1_roadmap_progress_report_contract",
        label: "M1 roadmap progress report contract validation",
        focus: "m1",
        default_script_rel: $default_roadmap_rel,
        resolved_script_path: $default_roadmap_path,
        script_override_env: $default_roadmap_env
      },
      {
        id: "m3_micro_relay_operator_floor",
        label: "M3 micro-relay operator-floor validation",
        focus: "m3_micro_relay",
        default_script_rel: $default_micro_relay_rel,
        resolved_script_path: $default_micro_relay_path,
        script_override_env: $default_micro_relay_env
      },
      {
        id: "m3_three_machine_real_host_validation_pack",
        label: "M3 three-machine real-host validation pack contract",
        focus: "m3_validation_pack",
        default_script_rel: $default_m3_validation_pack_rel,
        resolved_script_path: $default_m3_validation_pack_path,
        script_override_env: $default_m3_validation_pack_env
      }
    ],
    selection_accounting: {
      default_count: $default_count,
      include_ids_requested_count: $include_ids_requested_count,
      include_ids_unique_count: $include_ids_unique_count,
      exclude_ids_requested_count: $exclude_ids_requested_count,
      exclude_ids_unique_count: $exclude_ids_unique_count,
      include_filter_applied: (($include_ids | length) > 0),
      exclude_filter_applied: (($exclude_ids | length) > 0),
      after_include_count: $after_include_count,
      after_exclude_count: $after_exclude_count,
      after_max_actions_count: $after_max_actions_count,
      before_dedupe_count: $before_dedupe_count,
      deduped_duplicate_count: $deduped_duplicate_count,
      after_dedupe_count: $after_dedupe_count,
      unknown_include_ids: $unknown_include_ids,
      unknown_exclude_ids: $unknown_exclude_ids,
      conflicting_duplicate_check_ids: $conflicting_duplicate_check_ids
    },
    stages: {
      selection: {
        status: (if $selection_error == "" then "pass" else "fail" end),
        reason: (if $selection_error == "" then null else $selection_error end)
      },
      execution: {
        status: (if $selection_error == "" then $status else "skip_due_to_selection_error" end)
      }
    },
    checks_selected_count: $selected_count,
    checks_selected_ids: $selected_ids,
    summary: {
      checks_executed: $executed_count,
      pass: $pass_count,
      fail: $fail_count
    },
    checks: $checks,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json
    }
  }' >"$summary_json"

echo "[roadmap-validation-debt-actionable-run] status=$overall_status rc=$overall_rc selected=$selected_count executed=$executed_count pass=$pass_count fail=$fail_count"
echo "[roadmap-validation-debt-actionable-run] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$overall_rc"
