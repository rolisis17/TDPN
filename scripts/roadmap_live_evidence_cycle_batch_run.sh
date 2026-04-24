#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--iterations N] \
    [--continue-on-fail [0|1]] \
    [--parallel [0|1]] \
    [--include-track-id ID] \
    [--exclude-track-id ID] \
    [--print-summary-json [0|1]]

Purpose:
  Run deterministic repeated evidence cycles for roadmap live-evidence tracks.
  Default tracks:
    - profile_default_gate_stability_cycle
    - runtime_actuation_promotion_cycle
    - profile_compare_multi_vm_stability_promotion_cycle

Defaults:
  --iterations 1
  --continue-on-fail 0
  --parallel 0
  --print-summary-json 1

Track path overrides:
  ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT
  ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT
  ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT

Failure diagnostics:
  ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_FAILURE_LOG_TAIL_LINES (default: 20)

Exit behavior:
  - With --continue-on-fail=0, stop after first failed track result.
  - With --continue-on-fail=1, execute all selected tracks for all iterations.
  - Fails closed when no tracks are selected after filtering.
  - Final rc is the first non-zero track rc in deterministic iteration/track order, else 0.
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

require_value_or_die() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
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

parse_id_list_arg() {
  local value="$1"
  local -n out_ref="$2"
  local item
  IFS=',' read -r -a _items <<<"$value"
  for item in "${_items[@]}"; do
    item="$(trim "$item")"
    if [[ -n "$item" ]]; then
      out_ref+=("$item")
    fi
  done
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
  log_path="$(jq -r '.log // .artifacts.log // ""' "$result_path")"
  local failure_diagnostics_json
  failure_diagnostics_json="$(log_tail_window_json "$log_path" "$failure_log_tail_lines")"
  local updated_json
  updated_json="$(jq -c --argjson failure_diagnostics "$failure_diagnostics_json" '. + {failure_diagnostics: $failure_diagnostics}' "$result_path")"
  printf '%s\n' "$updated_json" >"$result_path"
}

need_cmd jq
need_cmd bash
need_cmd date
need_cmd mktemp

reports_dir="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_REPORTS_DIR:-}"
summary_json="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_SUMMARY_JSON:-}"
iterations="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_ITERATIONS:-1}"
continue_on_fail="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_CONTINUE_ON_FAIL:-0}"
parallel="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_PARALLEL:-0}"
print_summary_json="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_PRINT_SUMMARY_JSON:-1}"
failure_log_tail_lines="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_FAILURE_LOG_TAIL_LINES:-20}"

declare -a include_track_ids=()
declare -a exclude_track_ids=()

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
    --iterations)
      require_value_or_die "$1" "${2:-}"
      iterations="${2:-}"
      shift 2
      ;;
    --continue-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        continue_on_fail="${2:-}"
        shift 2
      else
        continue_on_fail="1"
        shift
      fi
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
    --include-track-id)
      require_value_or_die "$1" "${2:-}"
      parse_id_list_arg "${2:-}" include_track_ids
      shift 2
      ;;
    --exclude-track-id)
      require_value_or_die "$1" "${2:-}"
      parse_id_list_arg "${2:-}" exclude_track_ids
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

int_arg_or_die "--iterations" "$iterations"
if (( iterations < 1 )); then
  echo "--iterations must be >= 1"
  exit 2
fi
bool_arg_or_die "--continue-on-fail" "$continue_on_fail"
bool_arg_or_die "--parallel" "$parallel"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
int_arg_or_die "--failure-log-tail-lines" "$failure_log_tail_lines"

include_track_ids_requested_count="${#include_track_ids[@]}"
exclude_track_ids_requested_count="${#exclude_track_ids[@]}"

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/roadmap_live_evidence_cycle_batch_run_${run_stamp}"
fi
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/roadmap_live_evidence_cycle_batch_run_summary.json"
fi
summary_json="$(abs_path "$summary_json")"
mkdir -p "$(dirname "$summary_json")"

default_track_ids_json='[
  "profile_default_gate_stability_cycle",
  "runtime_actuation_promotion_cycle",
  "profile_compare_multi_vm_stability_promotion_cycle"
]'

declare -a default_track_ids=(
  "profile_default_gate_stability_cycle"
  "runtime_actuation_promotion_cycle"
  "profile_compare_multi_vm_stability_promotion_cycle"
)

profile_default_gate_stability_cycle_script="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_stability_cycle.sh}"
runtime_actuation_promotion_cycle_script="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT:-$ROOT_DIR/scripts/runtime_actuation_promotion_cycle.sh}"
profile_compare_multi_vm_stability_promotion_cycle_script="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_promotion_cycle.sh}"

track_id_exists() {
  local id="$1"
  case "$id" in
    profile_default_gate_stability_cycle|runtime_actuation_promotion_cycle|profile_compare_multi_vm_stability_promotion_cycle)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

track_script_for_id() {
  local id="$1"
  case "$id" in
    profile_default_gate_stability_cycle)
      printf '%s' "$profile_default_gate_stability_cycle_script"
      ;;
    runtime_actuation_promotion_cycle)
      printf '%s' "$runtime_actuation_promotion_cycle_script"
      ;;
    profile_compare_multi_vm_stability_promotion_cycle)
      printf '%s' "$profile_compare_multi_vm_stability_promotion_cycle_script"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

append_unique_id() {
  local id="$1"
  local -n out_ref="$2"
  local existing
  for existing in "${out_ref[@]:-}"; do
    if [[ "$existing" == "$id" ]]; then
      return
    fi
  done
  out_ref+=("$id")
}

json_array_from_ref() {
  local -n arr_ref="$1"
  local out='[]'
  local value
  for value in "${arr_ref[@]}"; do
    out="$(jq -c --arg v "$value" '. + [$v]' <<<"$out")"
  done
  printf '%s' "$out"
}

for id in "${include_track_ids[@]}"; do
  if ! track_id_exists "$id"; then
    echo "unknown --include-track-id: $id"
    exit 2
  fi
done
for id in "${exclude_track_ids[@]}"; do
  if ! track_id_exists "$id"; then
    echo "unknown --exclude-track-id: $id"
    exit 2
  fi
done

declare -a include_unique_ids=()
declare -a exclude_unique_ids=()
for id in "${include_track_ids[@]}"; do
  append_unique_id "$id" include_unique_ids
done
for id in "${exclude_track_ids[@]}"; do
  append_unique_id "$id" exclude_unique_ids
done

include_track_ids_unique_count="${#include_unique_ids[@]}"
exclude_track_ids_unique_count="${#exclude_unique_ids[@]}"

declare -a base_track_ids=()
if (( ${#include_unique_ids[@]} > 0 )); then
  for id in "${default_track_ids[@]}"; do
    for include_id in "${include_unique_ids[@]}"; do
      if [[ "$id" == "$include_id" ]]; then
        base_track_ids+=("$id")
        break
      fi
    done
  done
else
  base_track_ids=("${default_track_ids[@]}")
fi
base_track_count="${#base_track_ids[@]}"

declare -a selected_track_ids=()
for id in "${base_track_ids[@]}"; do
  excluded="0"
  for exclude_id in "${exclude_unique_ids[@]:-}"; do
    if [[ "$id" == "$exclude_id" ]]; then
      excluded="1"
      break
    fi
  done
  if [[ "$excluded" == "0" ]]; then
    selected_track_ids+=("$id")
  fi
done
selected_track_ids_count="${#selected_track_ids[@]}"

declare -a selected_track_scripts=()
for id in "${selected_track_ids[@]}"; do
  script_path="$(track_script_for_id "$id")"
  if [[ -z "$script_path" ]]; then
    echo "track script unresolved for id: $id"
    exit 2
  fi
  if [[ ! -f "$script_path" ]]; then
    echo "track script is missing for id=$id path=$script_path"
    exit 2
  fi
  if [[ ! -r "$script_path" ]]; then
    echo "track script is not readable for id=$id path=$script_path"
    exit 2
  fi
  selected_track_scripts+=("$script_path")
done

selection_error=""
selection_error_rc=0
declare -a conflicting_duplicate_track_ids=()
if [[ "${#selected_track_ids[@]}" -gt 0 ]]; then
  declare -A seen_track_script_by_id=()
  for idx in "${!selected_track_ids[@]}"; do
    id="${selected_track_ids[$idx]}"
    script_path="${selected_track_scripts[$idx]}"
    if [[ -n "${seen_track_script_by_id[$id]+x}" && "${seen_track_script_by_id[$id]}" != "$script_path" ]]; then
      append_unique_id "$id" conflicting_duplicate_track_ids
      continue
    fi
    seen_track_script_by_id["$id"]="$script_path"
  done
fi
if [[ "${#conflicting_duplicate_track_ids[@]}" -gt 0 ]]; then
  selection_error="conflicting_duplicate_track_ids"
  selection_error_rc=3
  conflicting_ids_csv="$(IFS=','; printf '%s' "${conflicting_duplicate_track_ids[*]}")"
  echo "[roadmap-live-evidence-cycle-batch-run] stage=selection status=fail reason=conflicting duplicate track ids ids=$conflicting_ids_csv"
fi
if [[ "${#selected_track_ids[@]}" -eq 0 && -z "$selection_error" ]]; then
  selection_error="no_tracks_selected"
  selection_error_rc=1
  echo "[roadmap-live-evidence-cycle-batch-run] stage=selection status=fail reason=no tracks selected after filtering"
fi
if [[ -z "$selection_error" ]]; then
  selected_track_ids_csv="$(IFS=','; printf '%s' "${selected_track_ids[*]}")"
  echo "[roadmap-live-evidence-cycle-batch-run] stage=selection status=pass selected_track_count=${#selected_track_ids[@]} ids=$selected_track_ids_csv"
fi

declare -A pass_count_by_track=()
declare -A fail_count_by_track=()
declare -A skipped_count_by_track=()
declare -A total_count_by_track=()
for id in "${selected_track_ids[@]}"; do
  pass_count_by_track["$id"]=0
  fail_count_by_track["$id"]=0
  skipped_count_by_track["$id"]=0
  total_count_by_track["$id"]=0
done

iteration_results_json='[]'
executed_iterations=0
executed_tracks=0
skipped_tracks=0
final_rc=0
first_failure_iteration=0
first_failure_track_id=""

tmp_root="$(mktemp -d "$reports_dir/.roadmap_live_evidence_cycle_batch_run_tmp.XXXXXX")"
trap 'rm -rf "$tmp_root"' EXIT

execute_track_to_result_file() {
  local iter_idx="$1"
  local track_id="$2"
  local script_path="$3"
  local log_path="$4"
  local result_path="$5"

  local started_at ended_at duration_sec rc status
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local start_epoch end_epoch
  start_epoch="$(date +%s)"
  set +e
  bash "$script_path" >"$log_path" 2>&1
  rc=$?
  set -e
  end_epoch="$(date +%s)"
  ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  duration_sec=$((end_epoch - start_epoch))
  if (( rc == 0 )); then
    status="pass"
  else
    status="fail"
  fi

  jq -n \
    --argjson iteration "$iter_idx" \
    --arg track_id "$track_id" \
    --arg script_path "$script_path" \
    --arg log "$log_path" \
    --arg started_at_utc "$started_at" \
    --arg ended_at_utc "$ended_at" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --argjson duration_sec "$duration_sec" \
    '{
      iteration: $iteration,
      track_id: $track_id,
      script_path: $script_path,
      log: $log,
      started_at_utc: $started_at_utc,
      ended_at_utc: $ended_at_utc,
      status: $status,
      rc: $rc,
      duration_sec: $duration_sec
    }' >"$result_path"
  augment_result_file_with_failure_diagnostics "$result_path"
}

halt_after_iteration="0"
if [[ -z "$selection_error" ]]; then
  for ((iter=1; iter<=iterations; iter++)); do
    iter_name="$(printf 'iteration_%03d' "$iter")"
    iter_dir="$reports_dir/iterations/$iter_name"
    mkdir -p "$iter_dir"
    iter_tmp_dir="$tmp_root/$iter_name"
    mkdir -p "$iter_tmp_dir"
    iter_track_results_json='[]'
    iter_rc=0
    iter_status="pass"
    iter_failed_track_id=""
    echo "[roadmap-live-evidence-cycle-batch-run] stage=iteration status=running iteration=$iter selected_track_count=${#selected_track_ids[@]} parallel=$parallel"

    if [[ "$parallel" == "1" && "$continue_on_fail" != "0" && ${#selected_track_ids[@]} -gt 1 ]]; then
      declare -a pids=()
      for idx in "${!selected_track_ids[@]}"; do
        track_id="${selected_track_ids[$idx]}"
        script_path="${selected_track_scripts[$idx]}"
        log_path="$iter_dir/${track_id}.log"
        result_path="$iter_tmp_dir/${idx}_${track_id}.json"
        echo "[roadmap-live-evidence-cycle-batch-run] stage=track status=running iteration=$iter track_id=$track_id mode=parallel"
        execute_track_to_result_file "$iter" "$track_id" "$script_path" "$log_path" "$result_path" &
        pids+=("$!")
      done
      for pid in "${pids[@]}"; do
        set +e
        wait "$pid"
        wait_rc=$?
        set -e
        if (( wait_rc != 0 )); then
          :
        fi
      done
      for idx in "${!selected_track_ids[@]}"; do
        track_id="${selected_track_ids[$idx]}"
        script_path="${selected_track_scripts[$idx]}"
        log_path="$iter_dir/${track_id}.log"
        result_path="$iter_tmp_dir/${idx}_${track_id}.json"
        if [[ ! -s "$result_path" ]] || ! jq -e . "$result_path" >/dev/null 2>&1; then
          jq -n \
            --argjson iteration "$iter" \
            --arg track_id "$track_id" \
            --arg script_path "$script_path" \
            --arg log "$log_path" \
            --arg started_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg ended_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg status "fail" \
            --argjson rc 125 \
            --argjson duration_sec 0 \
            '{
              iteration: $iteration,
              track_id: $track_id,
              script_path: $script_path,
              log: $log,
              started_at_utc: $started_at_utc,
              ended_at_utc: $ended_at_utc,
              status: $status,
              rc: $rc,
              duration_sec: $duration_sec,
              failure_kind: "runner_error",
              notes: "missing or invalid track result payload"
            }' >"$result_path"
          augment_result_file_with_failure_diagnostics "$result_path"
        fi
        result_json="$(cat "$result_path")"
        iter_track_results_json="$(jq -c --argjson row "$result_json" '. + [$row]' <<<"$iter_track_results_json")"
      done
    else
      for idx in "${!selected_track_ids[@]}"; do
        track_id="${selected_track_ids[$idx]}"
        script_path="${selected_track_scripts[$idx]}"
        log_path="$iter_dir/${track_id}.log"
        result_path="$iter_tmp_dir/${idx}_${track_id}.json"
        echo "[roadmap-live-evidence-cycle-batch-run] stage=track status=running iteration=$iter track_id=$track_id mode=sequential"
        execute_track_to_result_file "$iter" "$track_id" "$script_path" "$log_path" "$result_path"
        if [[ ! -s "$result_path" ]] || ! jq -e . "$result_path" >/dev/null 2>&1; then
          jq -n \
            --argjson iteration "$iter" \
            --arg track_id "$track_id" \
            --arg script_path "$script_path" \
            --arg log "$log_path" \
            --arg started_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg ended_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg status "fail" \
            --argjson rc 125 \
            --argjson duration_sec 0 \
            '{
              iteration: $iteration,
              track_id: $track_id,
              script_path: $script_path,
              log: $log,
              started_at_utc: $started_at_utc,
              ended_at_utc: $ended_at_utc,
              status: $status,
              rc: $rc,
              duration_sec: $duration_sec,
              failure_kind: "runner_error",
              notes: "missing or invalid track result payload"
            }' >"$result_path"
          augment_result_file_with_failure_diagnostics "$result_path"
        fi
        result_json="$(cat "$result_path")"
        iter_track_results_json="$(jq -c --argjson row "$result_json" '. + [$row]' <<<"$iter_track_results_json")"
        row_rc="$(jq -r '.rc' <<<"$result_json")"
        if (( row_rc != 0 )) && [[ "$continue_on_fail" == "0" ]]; then
          if (( idx + 1 < ${#selected_track_ids[@]} )); then
            for ((skipped_idx=idx+1; skipped_idx<${#selected_track_ids[@]}; skipped_idx++)); do
              skipped_track_id="${selected_track_ids[$skipped_idx]}"
              skipped_script_path="${selected_track_scripts[$skipped_idx]}"
              skipped_log_path="$iter_dir/${skipped_track_id}.log"
              skipped_result_json="$(jq -c -n \
                --argjson iteration "$iter" \
                --arg track_id "$skipped_track_id" \
                --arg script_path "$skipped_script_path" \
                --arg log "$skipped_log_path" \
                --arg started_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                --arg ended_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                --arg status "skipped" \
                --argjson rc null \
                --argjson duration_sec 0 \
                '{
                  iteration: $iteration,
                  track_id: $track_id,
                  script_path: $script_path,
                  log: $log,
                  started_at_utc: $started_at_utc,
                  ended_at_utc: $ended_at_utc,
                  status: $status,
                  rc: $rc,
                  duration_sec: $duration_sec,
                  failure_kind: "skipped_due_to_fail_closed",
                  notes: "not executed because a previous track failed and continue_on_fail=0"
                }')"
              iter_track_results_json="$(jq -c --argjson row "$skipped_result_json" '. + [$row]' <<<"$iter_track_results_json")"
            done
          fi
          break
        fi
      done
    fi

    iter_track_count="$(jq -r 'length' <<<"$iter_track_results_json")"
    if (( iter_track_count > 0 )); then
      for idx in $(seq 0 $((iter_track_count - 1))); do
        row_json="$(jq -c ".[$idx]" <<<"$iter_track_results_json")"
        row_id="$(jq -r '.track_id' <<<"$row_json")"
        if [[ -z "${total_count_by_track[$row_id]+x}" ]]; then
          total_count_by_track["$row_id"]=0
          pass_count_by_track["$row_id"]=0
          fail_count_by_track["$row_id"]=0
          skipped_count_by_track["$row_id"]=0
        fi
        row_status="$(jq -r '.status // ""' <<<"$row_json")"
        row_rc_raw="$(jq -r '.rc // empty' <<<"$row_json")"
        if [[ "$row_status" == "skipped" ]]; then
          skipped_count_by_track["$row_id"]=$((skipped_count_by_track["$row_id"] + 1))
          skipped_tracks=$((skipped_tracks + 1))
          echo "[roadmap-live-evidence-cycle-batch-run] stage=track status=skipped iteration=$iter track_id=$row_id reason=fail_closed_previous_failure"
          continue
        fi
        if ! [[ "$row_rc_raw" =~ ^-?[0-9]+$ ]]; then
          row_rc_raw=125
        fi
        row_rc="$row_rc_raw"
        executed_tracks=$((executed_tracks + 1))
        total_count_by_track["$row_id"]=$((total_count_by_track["$row_id"] + 1))
        if (( row_rc == 0 )); then
          pass_count_by_track["$row_id"]=$((pass_count_by_track["$row_id"] + 1))
          echo "[roadmap-live-evidence-cycle-batch-run] stage=track status=pass iteration=$iter track_id=$row_id rc=0"
        else
          fail_count_by_track["$row_id"]=$((fail_count_by_track["$row_id"] + 1))
          echo "[roadmap-live-evidence-cycle-batch-run] stage=track status=fail iteration=$iter track_id=$row_id rc=$row_rc"
          if (( iter_rc == 0 )); then
            iter_rc="$row_rc"
            iter_status="fail"
            iter_failed_track_id="$row_id"
          fi
        fi
      done
    fi

    if (( iter_rc != 0 )) && (( final_rc == 0 )); then
      final_rc="$iter_rc"
      first_failure_iteration="$iter"
      first_failure_track_id="$iter_failed_track_id"
    fi

    iter_failure_substep=""
    if [[ "$iter_status" == "fail" ]]; then
      if [[ -n "$iter_failed_track_id" ]]; then
        iter_failure_substep="track_failed:$iter_failed_track_id"
      else
        iter_failure_substep="track_failed:unknown"
      fi
    fi

    iter_result_json="$(jq -c -n \
      --argjson iteration "$iter" \
      --arg status "$iter_status" \
      --argjson rc "$iter_rc" \
      --arg failed_track_id "$iter_failed_track_id" \
      --arg failure_substep "$iter_failure_substep" \
      --argjson tracks "$iter_track_results_json" \
      '{
        iteration: $iteration,
        status: $status,
        rc: $rc,
        failed_track_id: (if $failed_track_id == "" then null else $failed_track_id end),
        failure_substep: (if $failure_substep == "" then null else $failure_substep end),
        tracks: $tracks
      }')"
    iteration_results_json="$(jq -c --argjson row "$iter_result_json" '. + [$row]' <<<"$iteration_results_json")"
    executed_iterations=$((executed_iterations + 1))
    echo "[roadmap-live-evidence-cycle-batch-run] stage=iteration status=$iter_status iteration=$iter rc=$iter_rc"

    if (( iter_rc != 0 )) && [[ "$continue_on_fail" == "0" ]]; then
      halt_after_iteration="1"
      break
    fi
  done
fi

if [[ -n "$selection_error" ]]; then
  final_status="fail"
  final_rc="$selection_error_rc"
elif (( final_rc == 0 )); then
  final_status="pass"
else
  final_status="fail"
fi

failure_substep=""
failure_reason=""
if [[ -n "$selection_error" ]]; then
  failure_substep="selection:$selection_error"
  failure_reason="selection failed before execution"
elif [[ "$final_status" == "fail" ]]; then
  if (( first_failure_iteration > 0 )) && [[ -n "$first_failure_track_id" ]]; then
    failure_substep="execution:iteration_${first_failure_iteration}:track_${first_failure_track_id}"
    failure_reason="first failing track in deterministic iteration/track order"
  else
    failure_substep="execution:unknown"
    failure_reason="execution failed without first failure metadata"
  fi
fi

per_track_json='[]'
for id in "${selected_track_ids[@]}"; do
  row_json="$(jq -c -n \
    --arg id "$id" \
    --arg script_path "$(track_script_for_id "$id")" \
    --argjson total "${total_count_by_track[$id]}" \
    --argjson pass "${pass_count_by_track[$id]}" \
    --argjson fail "${fail_count_by_track[$id]}" \
    --argjson skipped "${skipped_count_by_track[$id]}" \
    '{
      id: $id,
      script_path: $script_path,
      total_runs: $total,
      pass: $pass,
      fail: $fail,
      skipped: $skipped
    }')"
  per_track_json="$(jq -c --argjson row "$row_json" '. + [$row]' <<<"$per_track_json")"
done

include_track_ids_json="$(json_array_from_ref include_unique_ids)"
exclude_track_ids_json="$(json_array_from_ref exclude_unique_ids)"
selected_track_ids_json="$(json_array_from_ref selected_track_ids)"
conflicting_duplicate_track_ids_json="$(json_array_from_ref conflicting_duplicate_track_ids)"

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg failure_substep "$failure_substep" \
  --arg failure_reason "$failure_reason" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg selection_error "$selection_error" \
  --argjson iterations_requested "$iterations" \
  --argjson iterations_completed "$executed_iterations" \
  --argjson continue_on_fail "$continue_on_fail" \
  --argjson parallel "$parallel" \
  --argjson print_summary_json "$print_summary_json" \
  --argjson failure_log_tail_lines "$failure_log_tail_lines" \
  --argjson default_track_ids "$default_track_ids_json" \
  --argjson include_track_ids "$include_track_ids_json" \
  --argjson exclude_track_ids "$exclude_track_ids_json" \
  --argjson selected_track_ids "$selected_track_ids_json" \
  --argjson default_track_count "${#default_track_ids[@]}" \
  --argjson include_track_ids_requested_count "$include_track_ids_requested_count" \
  --argjson include_track_ids_unique_count "$include_track_ids_unique_count" \
  --argjson exclude_track_ids_requested_count "$exclude_track_ids_requested_count" \
  --argjson exclude_track_ids_unique_count "$exclude_track_ids_unique_count" \
  --argjson base_track_count "$base_track_count" \
  --argjson selected_track_ids_count "$selected_track_ids_count" \
  --argjson conflicting_duplicate_track_ids "$conflicting_duplicate_track_ids_json" \
  --argjson per_track "$per_track_json" \
  --argjson iterations_results "$iteration_results_json" \
  --argjson executed_tracks "$executed_tracks" \
  --argjson skipped_tracks "$skipped_tracks" \
  --argjson halt_after_iteration "$halt_after_iteration" \
  --argjson first_failure_iteration "$first_failure_iteration" \
  --arg first_failure_track_id "$first_failure_track_id" \
  '{
    version: 1,
    schema: { id: "roadmap_live_evidence_cycle_batch_run_summary", major: 1, minor: 0 },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    failure_substep: (if $failure_substep == "" then null else $failure_substep end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    selection_error: (if $selection_error == "" then null else $selection_error end),
    inputs: {
      iterations: $iterations_requested,
      continue_on_fail: ($continue_on_fail == 1),
      parallel: ($parallel == 1),
      print_summary_json: ($print_summary_json == 1),
      failure_log_tail_lines: $failure_log_tail_lines,
      default_track_ids: $default_track_ids,
      include_track_ids: $include_track_ids,
      exclude_track_ids: $exclude_track_ids,
      selected_track_ids: $selected_track_ids
    },
    selection_accounting: {
      default_track_count: $default_track_count,
      include_track_ids_requested_count: $include_track_ids_requested_count,
      include_track_ids_unique_count: $include_track_ids_unique_count,
      exclude_track_ids_requested_count: $exclude_track_ids_requested_count,
      exclude_track_ids_unique_count: $exclude_track_ids_unique_count,
      base_track_count: $base_track_count,
      selected_track_ids_count: $selected_track_ids_count,
      conflicting_duplicate_track_ids: $conflicting_duplicate_track_ids
    },
    stages: {
      selection: {
        status: (if $selection_error == "" then "pass" else "fail" end),
        reason: (if $selection_error == "" then null else $selection_error end)
      },
      execution: {
        status: (if $selection_error == "" then $status else "skip_due_to_selection_error" end),
        halted_early: ($halt_after_iteration == 1)
      }
    },
    summary: {
      iterations_requested: $iterations_requested,
      iterations_completed: $iterations_completed,
      selected_track_count: ($selected_track_ids | length),
      executed_tracks: $executed_tracks,
      skipped_tracks: $skipped_tracks,
      halt_after_iteration: ($halt_after_iteration == 1),
      first_failure_iteration: (if $first_failure_iteration == 0 then null else $first_failure_iteration end),
      first_failure_track_id: (if $first_failure_track_id == "" then null else $first_failure_track_id end)
    },
    per_track: $per_track,
    iterations: $iterations_results,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json
    }
  }' >"$summary_json"

echo "[roadmap-live-evidence-cycle-batch-run] status=$final_status rc=$final_rc iterations_completed=$executed_iterations selected_tracks=${#selected_track_ids[@]} failure_substep=${failure_substep:-none}"
if [[ "$final_status" == "fail" && -n "$failure_substep" ]]; then
  echo "[roadmap-live-evidence-cycle-batch-run] fail_substep=$failure_substep reason=${failure_reason:-unknown}"
fi
echo "[roadmap-live-evidence-cycle-batch-run] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
