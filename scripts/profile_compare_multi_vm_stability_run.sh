#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CYCLE_SCRIPT="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_cycle.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_multi_vm_stability_run.sh \
    [--runs N] \
    [--sleep-between-sec N] \
    [--allow-partial [0|1]] \
    [--min-completed-runs N] \
    [--min-pass-runs N] \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--canonical-summary-json PATH] \
    [--report-md PATH] \
    [--cycle-timeout-sec N] \
    [--sweep-command-timeout-sec N] \
    [--vm-command SPEC]... \
    [--vm-command-file PATH]... \
    [--cycle-arg ARG]... \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Run repeated profile-compare multi-VM cycle evidence collection and emit one
  stability-oriented aggregate summary JSON + report markdown.

Notes:
  - Per-run artifacts/logs are archived under timestamped run directories.
  - Fail closed by default; allow partial completion with --allow-partial 1
    only when configured thresholds are satisfied.
  - Cycle script path can be overridden by:
    PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
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

require_value_or_die() {
  local flag="$1"
  local argc="$2"
  if (( argc < 2 )); then
    echo "$flag requires a value"
    exit 2
  fi
}

int_arg_or_die() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be a non-negative integer"
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

normalize_status() {
  local status
  status="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$status" in
    pass|ok) printf '%s\n' "pass" ;;
    warn|warning) printf '%s\n' "warn" ;;
    fail|failed|error|no-go|nogo|no_go) printf '%s\n' "fail" ;;
    *) printf '%s\n' "other" ;;
  esac
}

normalize_decision() {
  local decision
  decision="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
  case "$decision" in
    GO) printf '%s\n' "GO" ;;
    NO-GO|NOGO|NO_GO) printf '%s\n' "NO-GO" ;;
    *) printf '%s\n' "$decision" ;;
  esac
}

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

format_pct() {
  local numerator="$1"
  local denominator="$2"
  awk -v n="$numerator" -v d="$denominator" 'BEGIN { if (d <= 0) { printf "0.00"; exit } printf "%.2f", (n * 100.0) / d }'
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

need_cmd jq
need_cmd mktemp
need_cmd date
need_cmd bash
need_cmd timeout
need_cmd sleep
need_cmd awk

runs="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_RUNS:-3}"
sleep_between_sec="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SLEEP_BETWEEN_SEC:-5}"
allow_partial="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_ALLOW_PARTIAL:-0}"
min_completed_runs="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_MIN_COMPLETED_RUNS:-}"
min_pass_runs="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_MIN_PASS_RUNS:-}"
reports_dir="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SUMMARY_JSON:-}"
canonical_summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CANONICAL_SUMMARY_JSON:-}"
report_md="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_REPORT_MD:-}"
cycle_timeout_sec="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_TIMEOUT_SEC:-0}"
sweep_command_timeout_sec="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SWEEP_COMMAND_TIMEOUT_SEC:-}"
show_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SHOW_JSON:-0}"
print_summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_PRINT_SUMMARY_JSON:-0}"

declare -a vm_command_specs=()
declare -a vm_command_files=()
declare -a cycle_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs)
      require_value_or_die "$1" "$#"
      runs="${2:-}"
      shift 2
      ;;
    --runs=*)
      runs="${1#*=}"
      shift
      ;;
    --sleep-between-sec)
      require_value_or_die "$1" "$#"
      sleep_between_sec="${2:-}"
      shift 2
      ;;
    --sleep-between-sec=*)
      sleep_between_sec="${1#*=}"
      shift
      ;;
    --allow-partial)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_partial="${2:-}"
        shift 2
      else
        allow_partial="1"
        shift
      fi
      ;;
    --allow-partial=*)
      allow_partial="${1#*=}"
      shift
      ;;
    --min-completed-runs)
      require_value_or_die "$1" "$#"
      min_completed_runs="${2:-}"
      shift 2
      ;;
    --min-completed-runs=*)
      min_completed_runs="${1#*=}"
      shift
      ;;
    --min-pass-runs)
      require_value_or_die "$1" "$#"
      min_pass_runs="${2:-}"
      shift 2
      ;;
    --min-pass-runs=*)
      min_pass_runs="${1#*=}"
      shift
      ;;
    --reports-dir)
      require_value_or_die "$1" "$#"
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --summary-json)
      require_value_or_die "$1" "$#"
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    --canonical-summary-json)
      require_value_or_die "$1" "$#"
      canonical_summary_json="${2:-}"
      shift 2
      ;;
    --canonical-summary-json=*)
      canonical_summary_json="${1#*=}"
      shift
      ;;
    --report-md)
      require_value_or_die "$1" "$#"
      report_md="${2:-}"
      shift 2
      ;;
    --report-md=*)
      report_md="${1#*=}"
      shift
      ;;
    --cycle-timeout-sec)
      require_value_or_die "$1" "$#"
      cycle_timeout_sec="${2:-}"
      shift 2
      ;;
    --cycle-timeout-sec=*)
      cycle_timeout_sec="${1#*=}"
      shift
      ;;
    --sweep-command-timeout-sec)
      require_value_or_die "$1" "$#"
      sweep_command_timeout_sec="${2:-}"
      shift 2
      ;;
    --sweep-command-timeout-sec=*)
      sweep_command_timeout_sec="${1#*=}"
      shift
      ;;
    --vm-command)
      require_value_or_die "$1" "$#"
      vm_command_specs+=("${2:-}")
      shift 2
      ;;
    --vm-command=*)
      vm_command_specs+=("${1#*=}")
      shift
      ;;
    --vm-command-file)
      require_value_or_die "$1" "$#"
      vm_command_files+=("${2:-}")
      shift 2
      ;;
    --vm-command-file=*)
      vm_command_files+=("${1#*=}")
      shift
      ;;
    --cycle-arg)
      require_value_or_die "$1" "$#"
      cycle_args+=("${2:-}")
      shift 2
      ;;
    --cycle-arg=*)
      cycle_args+=("${1#*=}")
      shift
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
    --show-json=*)
      show_json="${1#*=}"
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
    -h|--help|help)
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

runs="$(trim "$runs")"
sleep_between_sec="$(trim "$sleep_between_sec")"
allow_partial="$(trim "$allow_partial")"
min_completed_runs="$(trim "$min_completed_runs")"
min_pass_runs="$(trim "$min_pass_runs")"
reports_dir="$(abs_path "$reports_dir")"
summary_json="$(trim "$summary_json")"
canonical_summary_json="$(trim "$canonical_summary_json")"
report_md="$(trim "$report_md")"
cycle_timeout_sec="$(trim "$cycle_timeout_sec")"
sweep_command_timeout_sec="$(trim "$sweep_command_timeout_sec")"
show_json="$(trim "$show_json")"
print_summary_json="$(trim "$print_summary_json")"
CYCLE_SCRIPT="$(abs_path "$CYCLE_SCRIPT")"

int_arg_or_die "--runs" "$runs"
int_arg_or_die "--sleep-between-sec" "$sleep_between_sec"
int_arg_or_die "--cycle-timeout-sec" "$cycle_timeout_sec"
bool_arg_or_die "--allow-partial" "$allow_partial"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

if [[ -n "$sweep_command_timeout_sec" ]]; then
  int_arg_or_die "--sweep-command-timeout-sec" "$sweep_command_timeout_sec"
  if (( sweep_command_timeout_sec < 1 )); then
    echo "--sweep-command-timeout-sec must be >= 1"
    exit 2
  fi
fi

if (( runs < 1 )); then
  echo "--runs must be >= 1"
  exit 2
fi

if [[ -z "$min_completed_runs" ]]; then
  min_completed_runs="$runs"
fi
if [[ -z "$min_pass_runs" ]]; then
  min_pass_runs="$runs"
fi
int_arg_or_die "--min-completed-runs" "$min_completed_runs"
int_arg_or_die "--min-pass-runs" "$min_pass_runs"
if (( min_completed_runs < 1 )); then
  echo "--min-completed-runs must be >= 1"
  exit 2
fi
if (( min_pass_runs < 1 )); then
  echo "--min-pass-runs must be >= 1"
  exit 2
fi
if (( min_completed_runs > runs )); then
  echo "--min-completed-runs must be <= --runs"
  exit 2
fi
if (( min_pass_runs > runs )); then
  echo "--min-pass-runs must be <= --runs"
  exit 2
fi

if [[ ! -f "$CYCLE_SCRIPT" ]]; then
  echo "cycle script not found: $CYCLE_SCRIPT"
  exit 2
fi
if [[ ${#vm_command_specs[@]} -eq 0 && ${#vm_command_files[@]} -eq 0 ]]; then
  echo "at least one --vm-command or --vm-command-file is required"
  exit 2
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
archive_root="$reports_dir/profile_compare_multi_vm_stability_run_${run_stamp}"
mkdir -p "$archive_root"

if [[ -z "$summary_json" ]]; then
  summary_json="$archive_root/profile_compare_multi_vm_stability_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$report_md" ]]; then
  report_md="$archive_root/profile_compare_multi_vm_stability_report.md"
else
  report_md="$(abs_path "$report_md")"
fi
if [[ -n "$canonical_summary_json" ]]; then
  canonical_summary_json="$(abs_path "$canonical_summary_json")"
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
if [[ -n "$canonical_summary_json" ]]; then
  mkdir -p "$(dirname "$canonical_summary_json")"
fi

runs_rows_file="$(mktemp)"
cleanup() {
  rm -f "$runs_rows_file" 2>/dev/null || true
}
trap cleanup EXIT

echo "[profile-compare-multi-vm-stability-run] $(timestamp_utc) start runs=$runs allow_partial=$allow_partial min_completed_runs=$min_completed_runs min_pass_runs=$min_pass_runs archive_root=$archive_root"

run_index=0
while (( run_index < runs )); do
  run_index=$((run_index + 1))
  run_id="$(printf 'run_%02d' "$run_index")"
  run_ts="$(date -u +%Y%m%d_%H%M%S)"
  run_dir="$archive_root/${run_ts}_${run_id}"
  mkdir -p "$run_dir"

  run_cycle_summary_json="$run_dir/cycle_summary.json"
  run_log="$run_dir/cycle.log"

  cycle_cmd=(bash "$CYCLE_SCRIPT" --reports-dir "$run_dir" --summary-json "$run_cycle_summary_json" --show-json 0 --print-summary-json 0)
  if [[ -n "$sweep_command_timeout_sec" ]]; then
    cycle_cmd+=(--sweep-command-timeout-sec "$sweep_command_timeout_sec")
  fi
  for vm_spec in "${vm_command_specs[@]}"; do
    cycle_cmd+=(--vm-command "$vm_spec")
  done
  for vm_file in "${vm_command_files[@]}"; do
    cycle_cmd+=(--vm-command-file "$vm_file")
  done
  if (( ${#cycle_args[@]} > 0 )); then
    cycle_cmd+=("${cycle_args[@]}")
  fi

  echo "[profile-compare-multi-vm-stability-run] $(timestamp_utc) run-start run_id=$run_id run_dir=$run_dir cycle_summary_json=$run_cycle_summary_json"

  run_started_epoch="$(date +%s)"
  run_started_utc="$(timestamp_utc)"
  set +e
  if (( cycle_timeout_sec > 0 )); then
    timeout "${cycle_timeout_sec}s" "${cycle_cmd[@]}" >"$run_log" 2>&1
  else
    "${cycle_cmd[@]}" >"$run_log" 2>&1
  fi
  command_rc=$?
  set -e
  run_completed_utc="$(timestamp_utc)"
  run_duration_sec=$(( $(date +%s) - run_started_epoch ))

  timed_out="0"
  if [[ "$command_rc" -eq 124 ]]; then
    timed_out="1"
  fi

  summary_exists="0"
  summary_valid="0"
  completed="0"
  run_status="fail"
  failure_reason=""
  cycle_status=""
  cycle_decision=""
  recommended_profile=""
  support_rate_pct_json="null"
  cycle_report_md=""
  cycle_report_exists="0"

  if [[ -f "$run_cycle_summary_json" ]]; then
    summary_exists="1"
    if jq -e 'type == "object"' "$run_cycle_summary_json" >/dev/null 2>&1; then
      summary_valid="1"
      completed="1"
      cycle_status="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$run_cycle_summary_json" 2>/dev/null || true)"
      run_status="$(normalize_status "$cycle_status")"
      if [[ "$run_status" == "other" ]]; then
        run_status="fail"
        failure_reason="cycle_summary_status_unrecognized"
      fi

      cycle_decision="$(jq -r '
        if (.decision | type) == "string" then .decision
        elif (.check.decision | type) == "string" then .check.decision
        elif (.reducer.decision | type) == "string" then .reducer.decision
        else ""
        end
      ' "$run_cycle_summary_json" 2>/dev/null || true)"
      cycle_decision="$(normalize_decision "$cycle_decision")"

      recommended_profile="$(jq -r '
        if (.check.recommended_profile | type) == "string" then .check.recommended_profile
        elif (.reducer.recommended_profile | type) == "string" then .reducer.recommended_profile
        elif (.decision.recommended_profile | type) == "string" then .decision.recommended_profile
        else ""
        end
      ' "$run_cycle_summary_json" 2>/dev/null || true)"
      recommended_profile="$(trim "$recommended_profile")"

      support_rate_raw="$(jq -r '
        (.check.recommendation_support_rate_pct // .reducer.support_rate_pct // .decision.support_rate_pct // null) as $v
        | if $v == null then ""
          elif ($v | type) == "number" then ($v | tostring)
          elif ($v | type) == "string" and ($v | test("^-?[0-9]+([.][0-9]+)?$")) then ($v | tonumber | tostring)
          else ""
          end
      ' "$run_cycle_summary_json" 2>/dev/null || true)"
      if [[ -n "$support_rate_raw" ]] && is_non_negative_decimal "$support_rate_raw"; then
        support_rate_pct_json="$support_rate_raw"
      fi

      cycle_report_md="$(jq -r '
        if (.artifacts.report_md | type) == "string" then .artifacts.report_md
        elif (.artifacts.sweep_report_md | type) == "string" then .artifacts.sweep_report_md
        else ""
        end
      ' "$run_cycle_summary_json" 2>/dev/null || true)"
      cycle_report_md="$(trim "$cycle_report_md")"
      if [[ -n "$cycle_report_md" ]]; then
        cycle_report_md="$(abs_path "$cycle_report_md")"
        if [[ -f "$cycle_report_md" ]]; then
          cycle_report_exists="1"
        fi
      fi
    fi
  fi

  if [[ "$summary_valid" != "1" ]]; then
    run_status="fail"
    if [[ -z "$failure_reason" ]]; then
      if [[ "$summary_exists" != "1" ]]; then
        failure_reason="cycle_summary_missing"
      else
        failure_reason="cycle_summary_invalid"
      fi
    fi
  fi
  if [[ "$timed_out" == "1" ]]; then
    run_status="fail"
    failure_reason="cycle_timeout"
  elif [[ "$command_rc" -ne 0 && "$run_status" == "pass" ]]; then
    run_status="fail"
    failure_reason="cycle_rc_nonzero"
  fi
  if [[ "$run_status" == "fail" && -z "$failure_reason" ]]; then
    failure_reason="cycle_failed"
  fi

  jq -n \
    --arg run_id "$run_id" \
    --arg run_dir "$run_dir" \
    --arg run_log "$run_log" \
    --arg summary_json "$run_cycle_summary_json" \
    --arg report_md "$cycle_report_md" \
    --arg started_at_utc "$run_started_utc" \
    --arg completed_at_utc "$run_completed_utc" \
    --arg status "$run_status" \
    --arg cycle_status "$cycle_status" \
    --arg decision "$cycle_decision" \
    --arg recommended_profile "$recommended_profile" \
    --arg summary_exists "$summary_exists" \
    --arg summary_valid "$summary_valid" \
    --arg completed "$completed" \
    --arg timed_out "$timed_out" \
    --arg cycle_report_exists "$cycle_report_exists" \
    --arg failure_reason "$failure_reason" \
    --argjson command_rc "$command_rc" \
    --argjson duration_sec "$run_duration_sec" \
    --argjson support_rate_pct "$support_rate_pct_json" \
    '{
      run_id: $run_id,
      run_dir: $run_dir,
      started_at_utc: $started_at_utc,
      completed_at_utc: $completed_at_utc,
      status: $status,
      cycle_status: (if $cycle_status == "" then null else $cycle_status end),
      decision: (if $decision == "" then null else $decision end),
      recommended_profile: (if $recommended_profile == "" then null else $recommended_profile end),
      support_rate_pct: $support_rate_pct,
      completed: ($completed == "1"),
      timed_out: ($timed_out == "1"),
      command_rc: $command_rc,
      duration_sec: $duration_sec,
      failure_reason: (if $failure_reason == "" then null else $failure_reason end),
      artifacts: {
        cycle_summary_json: $summary_json,
        cycle_summary_exists: ($summary_exists == "1"),
        cycle_summary_valid: ($summary_valid == "1"),
        cycle_report_md: (if $report_md == "" then null else $report_md end),
        cycle_report_exists: ($cycle_report_exists == "1"),
        cycle_log: $run_log
      }
    }' >>"$runs_rows_file"

  echo "[profile-compare-multi-vm-stability-run] $(timestamp_utc) run-end run_id=$run_id status=$run_status command_rc=$command_rc timed_out=$timed_out duration_sec=$run_duration_sec"

  if (( run_index < runs && sleep_between_sec > 0 )); then
    sleep "$sleep_between_sec"
  fi
done

runs_json='[]'
if [[ -s "$runs_rows_file" ]]; then
  runs_json="$(jq -s '.' "$runs_rows_file")"
fi

requested_runs="$runs"
completed_runs="$(jq '[.[] | select(.completed == true)] | length' <<<"$runs_json")"
pass_runs="$(jq '[.[] | select(.status == "pass")] | length' <<<"$runs_json")"
warn_runs="$(jq '[.[] | select(.status == "warn")] | length' <<<"$runs_json")"
fail_runs="$(jq '[.[] | select(.status == "fail")] | length' <<<"$runs_json")"
timeout_runs="$(jq '[.[] | select(.timed_out == true)] | length' <<<"$runs_json")"

decision_counts_json="$(jq '
  [ .[] | select(.completed == true and (.decision | type) == "string" and (.decision | length > 0)) | .decision ]
  | group_by(.)
  | map({ (.[0]): length })
  | add // {}
' <<<"$runs_json")"

profile_counts_json="$(jq '
  [ .[] | select(.completed == true and (.recommended_profile | type) == "string" and (.recommended_profile | length > 0)) | .recommended_profile ]
  | group_by(.)
  | map({ (.[0]): length })
  | add // {}
' <<<"$runs_json")"

support_rate_counts_json="$(jq '
  [ .[] | select(.completed == true and (.support_rate_pct | type) == "number") | (.support_rate_pct | tostring) ]
  | group_by(.)
  | map({ (.[0]): length })
  | add // {}
' <<<"$runs_json")"

modal_decision="$(jq -r '
  to_entries
  | sort_by(
      -.value,
      (if .key == "NO-GO" then 0 elif .key == "GO" then 1 else 2 end),
      .key
    )
  | .[0].key // ""
' <<<"$decision_counts_json")"
modal_decision_count="$(jq -r '
  to_entries
  | sort_by(
      -.value,
      (if .key == "NO-GO" then 0 elif .key == "GO" then 1 else 2 end),
      .key
    )
  | .[0].value // 0
' <<<"$decision_counts_json")"
modal_profile="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].key // ""' <<<"$profile_counts_json")"
modal_profile_count="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].value // 0' <<<"$profile_counts_json")"
modal_support_rate_raw="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].key // ""' <<<"$support_rate_counts_json")"
modal_support_rate_count="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].value // 0' <<<"$support_rate_counts_json")"
decision_counts_total="$(jq -r '[.[]] | add // 0' <<<"$decision_counts_json")"
decision_unique_count="$(jq -r 'keys | length' <<<"$decision_counts_json")"
decision_consensus="false"
decision_split_detected="0"
if (( decision_counts_total > 0 && decision_unique_count == 1 )); then
  decision_consensus="true"
fi
if (( decision_counts_total > 0 && decision_unique_count > 1 )); then
  decision_split_detected="1"
fi

modal_decision_support_rate_pct="$(format_pct "$modal_decision_count" "$completed_runs")"
modal_profile_support_rate_pct="$(format_pct "$modal_profile_count" "$completed_runs")"
modal_support_support_rate_pct="$(format_pct "$modal_support_rate_count" "$completed_runs")"

modal_support_rate_pct_json="null"
if [[ -n "$modal_support_rate_raw" ]] && is_non_negative_decimal "$modal_support_rate_raw"; then
  modal_support_rate_pct_json="$modal_support_rate_raw"
fi

overall_decision="$modal_decision"
if [[ -z "$overall_decision" || "$decision_split_detected" == "1" ]]; then
  overall_decision="NO-GO"
fi

overall_status="pass"
notes="all cycle runs passed"
overall_rc=0

if (( fail_runs == 0 && warn_runs == 0 && completed_runs == requested_runs )) \
   && [[ "$decision_split_detected" != "1" ]]; then
  overall_status="pass"
  notes="all cycle runs passed"
else
  if [[ "$decision_split_detected" == "1" ]]; then
    if [[ "$allow_partial" == "1" && "$completed_runs" -ge "$min_completed_runs" && "$pass_runs" -ge "$min_pass_runs" ]]; then
      overall_status="warn"
      notes="split decision outcomes detected; fail-closed NO-GO applied"
      overall_rc=0
    else
      overall_status="fail"
      notes="split decision outcomes detected; fail-closed NO-GO applied"
      overall_rc=1
    fi
  else
    if [[ "$allow_partial" == "1" && "$completed_runs" -ge "$min_completed_runs" && "$pass_runs" -ge "$min_pass_runs" ]]; then
      overall_status="warn"
      notes="partial stability thresholds satisfied"
      overall_rc=0
    else
      overall_status="fail"
      notes="stability thresholds not satisfied"
      overall_rc=1
    fi
  fi
fi

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$overall_status" \
  --arg decision "$overall_decision" \
  --arg modal_decision "$modal_decision" \
  --arg decision_consensus "$decision_consensus" \
  --arg modal_profile "$modal_profile" \
  --arg notes "$notes" \
  --arg reports_dir "$reports_dir" \
  --arg archive_root "$archive_root" \
  --arg summary_json_path "$summary_json" \
  --arg canonical_summary_json_path "$canonical_summary_json" \
  --arg report_md_path "$report_md" \
  --arg cycle_script "$CYCLE_SCRIPT" \
  --argjson rc "$overall_rc" \
  --argjson runs "$runs" \
  --argjson sleep_between_sec "$sleep_between_sec" \
  --argjson allow_partial "$allow_partial" \
  --argjson min_completed_runs "$min_completed_runs" \
  --argjson min_pass_runs "$min_pass_runs" \
  --argjson cycle_timeout_sec "$cycle_timeout_sec" \
  --argjson sweep_command_timeout_sec "${sweep_command_timeout_sec:-0}" \
  --argjson requested_runs "$requested_runs" \
  --argjson completed_runs "$completed_runs" \
  --argjson pass_runs "$pass_runs" \
  --argjson warn_runs "$warn_runs" \
  --argjson fail_runs "$fail_runs" \
  --argjson timeout_runs "$timeout_runs" \
  --argjson modal_support_rate_pct "$modal_support_rate_pct_json" \
  --argjson modal_decision_count "$modal_decision_count" \
  --argjson modal_profile_count "$modal_profile_count" \
  --argjson modal_support_rate_count "$modal_support_rate_count" \
  --argjson modal_decision_support_rate_pct "$modal_decision_support_rate_pct" \
  --argjson modal_profile_support_rate_pct "$modal_profile_support_rate_pct" \
  --argjson modal_support_support_rate_pct "$modal_support_support_rate_pct" \
  --argjson decision_counts_total "$decision_counts_total" \
  --argjson decision_unique_count "$decision_unique_count" \
  --argjson decision_split_detected "$decision_split_detected" \
  --argjson decision_counts "$decision_counts_json" \
  --argjson profile_counts "$profile_counts_json" \
  --argjson support_rate_counts "$support_rate_counts_json" \
  --argjson vm_command_count "${#vm_command_specs[@]}" \
  --argjson vm_command_file_count "${#vm_command_files[@]}" \
  --argjson cycle_arg_count "${#cycle_args[@]}" \
  --argjson runs_json "$runs_json" \
  '{
    version: 1,
    schema: {
      id: "profile_compare_multi_vm_stability_run_summary"
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    decision: (if $decision == "" then null else $decision end),
    decision_consensus: ($decision_consensus == "true"),
    decision_split_detected: ($decision_split_detected == 1),
    notes: $notes,
    inputs: {
      reports_dir: $reports_dir,
      archive_root: $archive_root,
      cycle_script: $cycle_script,
      runs: $runs,
      sleep_between_sec: $sleep_between_sec,
      allow_partial: ($allow_partial == 1),
      min_completed_runs: $min_completed_runs,
      min_pass_runs: $min_pass_runs,
      cycle_timeout_sec: $cycle_timeout_sec,
      sweep_command_timeout_sec: $sweep_command_timeout_sec,
      vm_command_count: $vm_command_count,
      vm_command_file_count: $vm_command_file_count,
      cycle_arg_count: $cycle_arg_count
    },
    counts: {
      requested: $requested_runs,
      completed: $completed_runs,
      pass: $pass_runs,
      warn: $warn_runs,
      fail: $fail_runs,
      timeout: $timeout_runs
    },
    modal: {
      decision: (if $modal_decision == "" then null else $modal_decision end),
      decision_tie_break: "prefer_no_go",
      decision_count: $modal_decision_count,
      decision_support_rate_pct: $modal_decision_support_rate_pct,
      recommended_profile: (if $modal_profile == "" then null else $modal_profile end),
      recommended_profile_count: $modal_profile_count,
      recommended_profile_support_rate_pct: $modal_profile_support_rate_pct,
      support_rate_pct: $modal_support_rate_pct,
      support_rate_count: $modal_support_rate_count,
      support_rate_support_rate_pct: $modal_support_support_rate_pct
    },
    histograms: {
      decision_counts: $decision_counts,
      decision_counts_total: $decision_counts_total,
      decision_unique_count: $decision_unique_count,
      recommended_profile_counts: $profile_counts,
      support_rate_counts: $support_rate_counts
    },
    runs: $runs_json,
    artifacts: {
      summary_json: $summary_json_path,
      canonical_summary_json: (if $canonical_summary_json_path == "" then null else $canonical_summary_json_path end),
      report_md: $report_md_path,
      run_dirs: [ $runs_json[] | .run_dir ],
      run_cycle_summary_jsons: [ $runs_json[] | .artifacts.cycle_summary_json ],
      run_logs: [ $runs_json[] | .artifacts.cycle_log ]
    }
  }' >"$summary_json"

{
  echo "# Profile Compare Multi-VM Stability Run Report"
  echo
  echo "- Generated at (UTC): \`$(jq -r '.generated_at_utc' "$summary_json")\`"
  echo "- Status: \`$(jq -r '.status' "$summary_json")\`"
  echo "- RC: \`$(jq -r '.rc' "$summary_json")\`"
  echo "- Decision: \`$(jq -r '.decision // ""' "$summary_json")\`"
  echo "- Notes: $(jq -r '.notes' "$summary_json")"
  echo
  echo "## Counts"
  echo
  echo "- Requested: \`$(jq -r '.counts.requested' "$summary_json")\`"
  echo "- Completed: \`$(jq -r '.counts.completed' "$summary_json")\`"
  echo "- Pass/Warn/Fail: \`$(jq -r '.counts.pass' "$summary_json")\` / \`$(jq -r '.counts.warn' "$summary_json")\` / \`$(jq -r '.counts.fail' "$summary_json")\`"
  echo "- Timeout: \`$(jq -r '.counts.timeout' "$summary_json")\`"
  echo
  echo "## Modal"
  echo
  echo "- Decision: \`$(jq -r '.modal.decision // ""' "$summary_json")\`"
  echo "- Profile: \`$(jq -r '.modal.recommended_profile // ""' "$summary_json")\`"
  echo "- Support rate: \`$(jq -r '.modal.support_rate_pct // ""' "$summary_json")\`"
  echo
  echo "## Runs"
  echo
  echo "| Run | Status | Decision | Profile | Support % | Completed | Timed out | RC | Summary | Log |"
  echo "|---|---|---|---|---:|:---:|:---:|---:|---|---|"
  jq -r '
    .runs[]
    | "| \(.run_id) | \(.status) | \(.decision // "") | \(.recommended_profile // "") | \((if .support_rate_pct == null then "" else (.support_rate_pct | tostring) end)) | \(.completed) | \(.timed_out) | \(.command_rc) | \(.artifacts.cycle_summary_json) | \(.artifacts.cycle_log) |"
  ' "$summary_json"
} >"$report_md"

if [[ -n "$canonical_summary_json" && "$canonical_summary_json" != "$summary_json" ]]; then
  cp "$summary_json" "$canonical_summary_json"
fi

echo "[profile-compare-multi-vm-stability-run] status=$overall_status rc=$overall_rc decision=${overall_decision:-unset} summary_json=$summary_json"
echo "[profile-compare-multi-vm-stability-run] report_md=$report_md"
if [[ -n "$canonical_summary_json" ]]; then
  echo "[profile-compare-multi-vm-stability-run] canonical_summary_json=$canonical_summary_json"
fi

if [[ "$show_json" == "1" ]]; then
  echo "[profile-compare-multi-vm-stability-run] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$overall_rc"
