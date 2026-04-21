#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_multi_vm_sweep.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--canonical-summary-json PATH] \
    [--report-md PATH] \
    [--command-timeout-sec N] \
    [--allow-partial [0|1]] \
    [--fail-fast [0|1]] \
    [--reducer-min-successful-vms N] \
    [--reducer-require-all-success [0|1]] \
    [--vm-command SPEC]... \
    [--vm-command-file PATH]... \
    [--print-summary-json [0|1]]

SPEC format:
  VM_ID::COMMAND
  COMMAND

Purpose:
  Run per-VM profile-compare campaign commands, capture logs/artifacts, and
  emit machine-readable sweep summary + markdown report for reducer handoff.

Notes:
  - VM_ID accepts only: [A-Za-z0-9._-]
  - Lines in --vm-command-file use the same SPEC format; blank lines and
    lines beginning with '#' are ignored.
  - Inputs fail closed on malformed command specs and shell parse errors.
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

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
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
    echo "$name must be a non-negative integer"
    exit 2
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

sanitize_vm_id_or_die() {
  local vm_id
  vm_id="$(trim "${1:-}")"
  if [[ -z "$vm_id" ]]; then
    echo "vm id must not be empty"
    exit 2
  fi
  if ! [[ "$vm_id" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "invalid vm id '$vm_id' (allowed: [A-Za-z0-9._-])"
    exit 2
  fi
  printf '%s' "$vm_id"
}

normalize_decision() {
  local decision
  decision="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
  case "$decision" in
    GO) printf '%s' "GO" ;;
    NO-GO|NOGO|NO_GO) printf '%s' "NO-GO" ;;
    "") printf '%s' "" ;;
    *) printf '%s' "$decision" ;;
  esac
}

redact_text() {
  local value="$1"
  local sensitive_flags sensitive_envs
  sensitive_flags='--campaign-subject|--subject|--key|--invite-key|--campaign-anon-cred|--anon-cred|--token|--auth-token|--admin-token|--authorization|--bearer|--password|--secret|--api-key'
  sensitive_envs='CAMPAIGN_SUBJECT|INVITE_KEY|ANON_CRED|AUTH_TOKEN|ADMIN_TOKEN|API_KEY|PASSWORD|SECRET'
  printf '%s' "$value" | sed -E \
    -e "s/(((${sensitive_flags})[[:space:]]+))\"([^\"]*)\"/\\1[redacted]/g" \
    -e "s/(((${sensitive_flags})[[:space:]]+))'([^']*)'/\\1[redacted]/g" \
    -e "s/(((${sensitive_flags})[[:space:]]+))([^[:space:]]+)/\\1[redacted]/g" \
    -e "s/(((${sensitive_flags})[[:space:]]*=[[:space:]]*))\"([^\"]*)\"/\\1[redacted]/g" \
    -e "s/(((${sensitive_flags})[[:space:]]*=[[:space:]]*))'([^']*)'/\\1[redacted]/g" \
    -e "s/(((${sensitive_flags})[[:space:]]*=[[:space:]]*))([^[:space:]]+)/\\1[redacted]/g" \
    -e "s/(((${sensitive_envs})[[:space:]]*=[[:space:]]*))\"([^\"]*)\"/\\1[redacted]/g" \
    -e "s/(((${sensitive_envs})[[:space:]]*=[[:space:]]*))'([^']*)'/\\1[redacted]/g" \
    -e "s/(((${sensitive_envs})[[:space:]]*=[[:space:]]*))([^[:space:]]+)/\\1[redacted]/g"
}

extract_flag_value_from_command() {
  local command="$1"
  local flag="$2"
  local escaped_flag value
  escaped_flag="${flag//-/\\-}"
  value=""

  if [[ "$command" =~ (^|[[:space:]])${escaped_flag}[[:space:]]*=[[:space:]]*\"([^\"]*)\" ]]; then
    value="${BASH_REMATCH[2]}"
  elif [[ "$command" =~ (^|[[:space:]])${escaped_flag}[[:space:]]*=[[:space:]]*\'([^\']*)\' ]]; then
    value="${BASH_REMATCH[2]}"
  elif [[ "$command" =~ (^|[[:space:]])${escaped_flag}[[:space:]]*=[[:space:]]*([^[:space:]]+) ]]; then
    value="${BASH_REMATCH[2]}"
  elif [[ "$command" =~ (^|[[:space:]])${escaped_flag}[[:space:]]+\"([^\"]*)\" ]]; then
    value="${BASH_REMATCH[2]}"
  elif [[ "$command" =~ (^|[[:space:]])${escaped_flag}[[:space:]]+\'([^\']*)\' ]]; then
    value="${BASH_REMATCH[2]}"
  elif [[ "$command" =~ (^|[[:space:]])${escaped_flag}[[:space:]]+([^[:space:]]+) ]]; then
    value="${BASH_REMATCH[2]}"
  fi

  printf '%s' "$(trim "$value")"
}

summary_value_str() {
  local summary_path="$1"
  local jq_expr="$2"
  jq -r "$jq_expr" "$summary_path" 2>/dev/null || true
}

file_mtime_epoch() {
  local path="$1"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '%s' "0"
    return
  fi
  if stat -c %Y "$path" >/dev/null 2>&1; then
    stat -c %Y "$path"
    return
  fi
  if stat -f %m "$path" >/dev/null 2>&1; then
    stat -f %m "$path"
    return
  fi
  printf '%s' "0"
}

need_cmd jq
need_cmd bash
need_cmd date
need_cmd mktemp
need_cmd mkdir
need_cmd timeout
need_cmd cp

reports_dir="${PROFILE_COMPARE_MULTI_VM_SWEEP_REPORTS_DIR:-}"
summary_json="${PROFILE_COMPARE_MULTI_VM_SWEEP_SUMMARY_JSON:-}"
canonical_summary_json="${PROFILE_COMPARE_MULTI_VM_SWEEP_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/profile_compare_multi_vm_sweep_summary.json}"
report_md="${PROFILE_COMPARE_MULTI_VM_SWEEP_REPORT_MD:-}"
command_timeout_sec="${PROFILE_COMPARE_MULTI_VM_SWEEP_COMMAND_TIMEOUT_SEC:-2400}"
allow_partial="${PROFILE_COMPARE_MULTI_VM_SWEEP_ALLOW_PARTIAL:-0}"
fail_fast="${PROFILE_COMPARE_MULTI_VM_SWEEP_FAIL_FAST:-0}"
reducer_min_successful_vms="${PROFILE_COMPARE_MULTI_VM_SWEEP_REDUCER_MIN_SUCCESSFUL_VMS:-1}"
reducer_require_all_success="${PROFILE_COMPARE_MULTI_VM_SWEEP_REDUCER_REQUIRE_ALL_SUCCESS:-0}"
print_summary_json="${PROFILE_COMPARE_MULTI_VM_SWEEP_PRINT_SUMMARY_JSON:-0}"

declare -a vm_command_specs=()
declare -a vm_command_files=()

while [[ $# -gt 0 ]]; do
  case "$1" in
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
    --command-timeout-sec)
      require_value_or_die "$1" "$#"
      command_timeout_sec="${2:-}"
      shift 2
      ;;
    --command-timeout-sec=*)
      command_timeout_sec="${1#*=}"
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
    --reducer-min-successful-vms)
      require_value_or_die "$1" "$#"
      reducer_min_successful_vms="${2:-}"
      shift 2
      ;;
    --reducer-min-successful-vms=*)
      reducer_min_successful_vms="${1#*=}"
      shift
      ;;
    --reducer-require-all-success)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        reducer_require_all_success="${2:-}"
        shift 2
      else
        reducer_require_all_success="1"
        shift
      fi
      ;;
    --reducer-require-all-success=*)
      reducer_require_all_success="${1#*=}"
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

bool_arg_or_die "--allow-partial" "$allow_partial"
bool_arg_or_die "--fail-fast" "$fail_fast"
bool_arg_or_die "--reducer-require-all-success" "$reducer_require_all_success"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
int_arg_or_die "--command-timeout-sec" "$command_timeout_sec"
int_arg_or_die "--reducer-min-successful-vms" "$reducer_min_successful_vms"
if (( reducer_min_successful_vms < 1 )); then
  echo "--reducer-min-successful-vms must be >= 1"
  exit 2
fi

if [[ ${#vm_command_specs[@]} -eq 0 && ${#vm_command_files[@]} -eq 0 ]]; then
  echo "at least one --vm-command or --vm-command-file is required"
  exit 2
fi

if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/profile_compare_multi_vm_sweep_$(date -u +%Y%m%d_%H%M%S)"
fi
reports_dir="$(abs_path "$reports_dir")"

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/profile_compare_multi_vm_sweep_summary.json"
fi
summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"

if [[ -z "$report_md" ]]; then
  report_md="$reports_dir/profile_compare_multi_vm_sweep_report.md"
fi
report_md="$(abs_path "$report_md")"

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"
mkdir -p "$(dirname "$report_md")"

declare -a vm_ids=()
declare -a vm_commands=()
declare -a vm_sources=()
declare -A seen_vm_ids=()
auto_vm_index=0

add_vm_spec_or_die() {
  local raw_spec="$1"
  local source="$2"
  local spec vm_id vm_command auto_candidate

  spec="$(trim "$raw_spec")"
  if [[ -z "$spec" ]]; then
    echo "empty vm command spec from $source"
    exit 2
  fi

  vm_id=""
  vm_command=""
  if [[ "$spec" == *"::"* ]]; then
    vm_id="$(trim "${spec%%::*}")"
    vm_command="$(trim "${spec#*::}")"
    if [[ -z "$vm_id" || -z "$vm_command" ]]; then
      echo "malformed vm spec at $source (expected VM_ID::COMMAND)"
      exit 2
    fi
    vm_id="$(sanitize_vm_id_or_die "$vm_id")"
  else
    vm_command="$spec"
  fi

  if [[ -z "$vm_command" ]]; then
    echo "empty command for vm spec at $source"
    exit 2
  fi
  if ! bash -n -c "$vm_command" >/dev/null 2>&1; then
    echo "malformed shell command at $source"
    exit 2
  fi

  if [[ -z "$vm_id" ]]; then
    while true; do
      auto_vm_index=$((auto_vm_index + 1))
      auto_candidate="$(printf 'vm_%02d' "$auto_vm_index")"
      if [[ -z "${seen_vm_ids[$auto_candidate]+x}" ]]; then
        vm_id="$auto_candidate"
        break
      fi
    done
  fi

  if [[ -n "${seen_vm_ids[$vm_id]+x}" ]]; then
    echo "duplicate vm id '$vm_id' from $source"
    exit 2
  fi
  seen_vm_ids["$vm_id"]=1

  vm_ids+=("$vm_id")
  vm_commands+=("$vm_command")
  vm_sources+=("$source")
}

for spec in "${vm_command_specs[@]}"; do
  add_vm_spec_or_die "$spec" "arg:--vm-command"
done

for file_spec in "${vm_command_files[@]}"; do
  file_spec="$(abs_path "$file_spec")"
  if [[ -z "$file_spec" || ! -f "$file_spec" ]]; then
    echo "vm command file not found: $file_spec"
    exit 2
  fi
  line_no=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))
    line="$(trim "$line")"
    if [[ -z "$line" || "$line" == \#* ]]; then
      continue
    fi
    add_vm_spec_or_die "$line" "file:$file_spec:$line_no"
  done <"$file_spec"
done

if [[ ${#vm_ids[@]} -eq 0 ]]; then
  echo "no runnable vm command specs found"
  exit 2
fi

rows_file="$(mktemp)"
cleanup_rows() {
  rm -f "$rows_file"
}
trap cleanup_rows EXIT

abort_remaining=0

for i in "${!vm_ids[@]}"; do
  vm_id="${vm_ids[$i]}"
  vm_command="${vm_commands[$i]}"
  vm_source="${vm_sources[$i]}"
  vm_dir="$reports_dir/vm_$vm_id"
  vm_log="$vm_dir/profile_compare_campaign.log"
  vm_command_redacted="$(redact_text "$vm_command")"
  pre_summary_hint="$(extract_flag_value_from_command "$vm_command" "--summary-json")"
  if [[ -z "$pre_summary_hint" ]]; then
    pre_summary_hint="$(extract_flag_value_from_command "$vm_command" "--campaign-summary-json")"
  fi
  pre_report_hint="$(extract_flag_value_from_command "$vm_command" "--report-md")"
  if [[ -z "$pre_report_hint" ]]; then
    pre_report_hint="$(extract_flag_value_from_command "$vm_command" "--campaign-report-md")"
  fi
  pre_summary_path=""
  pre_summary_exists="0"
  pre_summary_mtime_epoch="0"
  if [[ -n "$pre_summary_hint" ]]; then
    pre_summary_path="$(abs_path "$pre_summary_hint")"
    if [[ -f "$pre_summary_path" ]]; then
      pre_summary_exists="1"
      pre_summary_mtime_epoch="$(file_mtime_epoch "$pre_summary_path")"
    fi
  fi
  pre_report_path=""
  pre_report_exists="0"
  pre_report_mtime_epoch="0"
  if [[ -n "$pre_report_hint" ]]; then
    pre_report_path="$(abs_path "$pre_report_hint")"
    if [[ -f "$pre_report_path" ]]; then
      pre_report_exists="1"
      pre_report_mtime_epoch="$(file_mtime_epoch "$pre_report_path")"
    fi
  fi
  mkdir -p "$vm_dir"

  if (( abort_remaining == 1 )); then
    jq -cn \
      --arg vm_id "$vm_id" \
      --arg source "$vm_source" \
      --arg command_redacted "$vm_command_redacted" \
      --arg vm_log "$vm_log" \
      '{
        vm_id: $vm_id,
        source: $source,
        status: "skip",
        command: { redacted: $command_redacted },
        command_rc: null,
        timed_out: false,
        duration_sec: 0,
        started_at_utc: null,
        completed_at_utc: null,
        failure_reason: "fail_fast_abort",
        artifacts: {
          log: $vm_log,
          summary_json: null,
          summary_exists: false,
          summary_valid: false,
          report_md: null,
          report_exists: false
        },
        decision: {
          decision: null,
          recommended_profile: null,
          support_rate_pct: null
        },
        reducer_input_ready: false
      }' >>"$rows_file"
    continue
  fi

  run_started_utc="$(timestamp_utc)"
  run_started_epoch="$(date +%s)"
  echo "[profile-compare-multi-vm-sweep] $(timestamp_utc) vm-start vm_id=$vm_id source=$vm_source timeout_sec=$command_timeout_sec command=$vm_command_redacted"

  set +e
  if (( command_timeout_sec > 0 )); then
    timeout "${command_timeout_sec}s" bash -lc "$vm_command" >"$vm_log" 2>&1
    command_rc=$?
  else
    bash -lc "$vm_command" >"$vm_log" 2>&1
    command_rc=$?
  fi
  set -e

  run_completed_utc="$(timestamp_utc)"
  run_completed_epoch="$(date +%s)"
  if (( run_completed_epoch < run_started_epoch )); then
    run_duration_sec=0
  else
    run_duration_sec=$((run_completed_epoch - run_started_epoch))
  fi

  timed_out="0"
  status="pass"
  failure_reason=""
  if (( command_timeout_sec > 0 )) && (( command_rc == 124 || command_rc == 137 )); then
    timed_out="1"
    status="timeout"
    failure_reason="command_timeout"
  elif (( command_rc != 0 )); then
    status="fail"
    failure_reason="command_rc_$command_rc"
  fi

  summary_hint="$(extract_flag_value_from_command "$vm_command" "--summary-json")"
  if [[ -z "$summary_hint" ]]; then
    summary_hint="$(extract_flag_value_from_command "$vm_command" "--campaign-summary-json")"
  fi
  report_hint="$(extract_flag_value_from_command "$vm_command" "--report-md")"
  if [[ -z "$report_hint" ]]; then
    report_hint="$(extract_flag_value_from_command "$vm_command" "--campaign-report-md")"
  fi

  summary_path=""
  summary_exists="0"
  summary_valid="0"
  summary_fresh="0"
  report_path=""
  report_exists="0"
  report_fresh="0"
  decision_value=""
  recommended_profile=""
  support_rate_pct_json="null"

  if [[ -n "$summary_hint" ]]; then
    summary_path="$(abs_path "$summary_hint")"
    if [[ -f "$summary_path" ]]; then
      summary_exists="1"
      summary_mtime_epoch="$(file_mtime_epoch "$summary_path")"
      if [[ "$pre_summary_exists" != "1" ]]; then
        summary_fresh="1"
      elif [[ "$summary_mtime_epoch" =~ ^[0-9]+$ && "$pre_summary_mtime_epoch" =~ ^[0-9]+$ && "$summary_mtime_epoch" -gt "$pre_summary_mtime_epoch" ]]; then
        summary_fresh="1"
      fi
      if jq -e 'type == "object"' "$summary_path" >/dev/null 2>&1; then
        summary_valid="1"
      fi
    fi
  fi

  if [[ -n "$report_hint" ]]; then
    report_path="$(abs_path "$report_hint")"
    if [[ -f "$report_path" ]]; then
      report_exists="1"
      report_mtime_epoch="$(file_mtime_epoch "$report_path")"
      if [[ "$pre_report_exists" != "1" ]]; then
        report_fresh="1"
      elif [[ "$report_mtime_epoch" =~ ^[0-9]+$ && "$pre_report_mtime_epoch" =~ ^[0-9]+$ && "$report_mtime_epoch" -gt "$pre_report_mtime_epoch" ]]; then
        report_fresh="1"
      fi
    fi
  fi

  if [[ "$status" == "pass" && -n "$summary_path" && "$summary_exists" != "1" ]]; then
    status="fail"
    failure_reason="summary_json_missing"
  fi
  if [[ "$status" == "pass" && "$summary_exists" == "1" && "$summary_valid" != "1" ]]; then
    status="fail"
    failure_reason="summary_json_invalid"
  fi
  if [[ "$status" == "pass" && "$summary_exists" == "1" && "$summary_fresh" != "1" ]]; then
    status="fail"
    failure_reason="summary_json_not_fresh"
  fi
  if [[ "$status" == "pass" && -n "$report_path" && "$report_exists" != "1" ]]; then
    status="fail"
    failure_reason="report_md_missing"
  fi
  if [[ "$status" == "pass" && -n "$report_path" && "$report_exists" == "1" && "$report_fresh" != "1" ]]; then
    status="fail"
    failure_reason="report_md_not_fresh"
  fi

  if [[ "$summary_exists" == "1" && "$summary_valid" == "1" ]]; then
    decision_value="$(summary_value_str "$summary_path" '.decision.decision // .decision // ""')"
    decision_value="$(trim "$decision_value")"
    decision_value="$(normalize_decision "$decision_value")"
    recommended_profile="$(summary_value_str "$summary_path" '.decision.recommended_profile // .recommended_profile // ""')"
    recommended_profile="$(trim "$recommended_profile")"
    support_rate_pct_json="$(jq -r '
      (.decision.support_rate_pct // .support_rate_pct // null) as $v
      | if $v == null then "null"
        elif ($v | type) == "number" then ($v | tostring)
        elif ($v | type) == "string" and ($v | test("^-?[0-9]+([.][0-9]+)?$")) then ($v | tonumber | tostring)
        else "null"
        end
    ' "$summary_path" 2>/dev/null || echo "null")"
  fi

  reducer_input_ready="0"
  if [[ "$status" == "pass" && "$summary_exists" == "1" && "$summary_valid" == "1" ]]; then
    reducer_input_ready="1"
  fi

  echo "[profile-compare-multi-vm-sweep] $(timestamp_utc) vm-end vm_id=$vm_id status=$status rc=$command_rc duration_sec=$run_duration_sec timed_out=$timed_out summary_exists=$summary_exists summary_valid=$summary_valid"

  jq -cn \
    --arg vm_id "$vm_id" \
    --arg source "$vm_source" \
    --arg status "$status" \
    --arg command_redacted "$vm_command_redacted" \
    --argjson command_rc "$command_rc" \
    --arg timed_out "$timed_out" \
    --argjson duration_sec "$run_duration_sec" \
    --arg run_started_utc "$run_started_utc" \
    --arg run_completed_utc "$run_completed_utc" \
    --arg failure_reason "$failure_reason" \
    --arg vm_log "$vm_log" \
    --arg summary_path "$summary_path" \
    --arg summary_exists "$summary_exists" \
    --arg summary_valid "$summary_valid" \
    --arg summary_fresh "$summary_fresh" \
    --arg report_path "$report_path" \
    --arg report_exists "$report_exists" \
    --arg report_fresh "$report_fresh" \
    --arg decision_value "$decision_value" \
    --arg recommended_profile "$recommended_profile" \
    --argjson support_rate_pct "$support_rate_pct_json" \
    --arg reducer_input_ready "$reducer_input_ready" \
    '{
      vm_id: $vm_id,
      source: $source,
      status: $status,
      command: { redacted: $command_redacted },
      command_rc: $command_rc,
      timed_out: ($timed_out == "1"),
      duration_sec: $duration_sec,
      started_at_utc: $run_started_utc,
      completed_at_utc: $run_completed_utc,
      failure_reason: (if $failure_reason == "" then null else $failure_reason end),
      artifacts: {
        log: $vm_log,
        summary_json: (if $summary_path == "" then null else $summary_path end),
        summary_exists: ($summary_exists == "1"),
        summary_valid: ($summary_valid == "1"),
        summary_fresh: ($summary_fresh == "1"),
        report_md: (if $report_path == "" then null else $report_path end),
        report_exists: ($report_exists == "1"),
        report_fresh: ($report_fresh == "1")
      },
      decision: {
        decision: (if $decision_value == "" then null else $decision_value end),
        recommended_profile: (if $recommended_profile == "" then null else $recommended_profile end),
        support_rate_pct: $support_rate_pct
      },
      reducer_input_ready: ($reducer_input_ready == "1")
    }' >>"$rows_file"

  if [[ "$status" != "pass" && "$fail_fast" == "1" ]]; then
    abort_remaining=1
  fi
done

vms_json="$(jq -s '.' "$rows_file")"
vm_total="$(jq 'length' <<<"$vms_json")"
vm_pass="$(jq '[.[] | select(.status == "pass")] | length' <<<"$vms_json")"
vm_fail="$(jq '[.[] | select(.status == "fail")] | length' <<<"$vms_json")"
vm_timeout="$(jq '[.[] | select(.status == "timeout")] | length' <<<"$vms_json")"
vm_skip="$(jq '[.[] | select(.status == "skip")] | length' <<<"$vms_json")"
reducer_input_vm_count="$(jq '[.[] | select(.reducer_input_ready == true)] | length' <<<"$vms_json")"

decision_counts_json="$(jq '
  [ .[] | select(.reducer_input_ready == true) | .decision.decision // empty | strings | select(length > 0) ]
  | group_by(.)
  | map({ (.[0]): length })
  | add // {}
' <<<"$vms_json")"
recommended_profile_counts_json="$(jq '
  [ .[] | select(.reducer_input_ready == true) | .decision.recommended_profile // empty | strings | select(length > 0) ]
  | group_by(.)
  | map({ (.[0]): length })
  | add // {}
' <<<"$vms_json")"

modal_decision="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].key // ""' <<<"$decision_counts_json")"
modal_decision_count_json="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].value // 0' <<<"$decision_counts_json")"
modal_decision_support_rate_pct_json="$(jq -n \
  --argjson total "$reducer_input_vm_count" \
  --argjson modal "$modal_decision_count_json" \
  'if $total > 0 then (($modal * 100) / $total) else 0 end')"

support_rate_avg_json="$(jq '
  [ .[] | select(.reducer_input_ready == true) | .decision.support_rate_pct | select(type == "number") ] as $vals
  | if ($vals | length) == 0 then null else (($vals | add) / ($vals | length)) end
' <<<"$vms_json")"

reducer_ready="false"
reducer_not_ready_reason=""
if [[ "$reducer_require_all_success" == "1" ]]; then
  if (( vm_total > 0 && vm_pass == vm_total && reducer_input_vm_count == vm_total )); then
    reducer_ready="true"
  else
    reducer_not_ready_reason="reducer_require_all_success is enabled and not all VMs produced reducer-ready outputs"
  fi
else
  if (( reducer_input_vm_count >= reducer_min_successful_vms )); then
    reducer_ready="true"
  else
    reducer_not_ready_reason="insufficient reducer-ready VM outputs"
  fi
fi

status="pass"
notes="all VM commands passed"
final_rc=0

if (( vm_fail > 0 || vm_timeout > 0 )); then
  if [[ "$allow_partial" == "1" && "$reducer_ready" == "true" ]]; then
    status="warn"
    notes="partial VM failures observed; reducer threshold satisfied"
    final_rc=0
  else
    status="fail"
    notes="one or more VM commands failed or timed out"
    final_rc=1
  fi
fi

if (( vm_pass == 0 )); then
  status="fail"
  notes="no VM command completed successfully"
  final_rc=1
fi

if [[ "$reducer_ready" != "true" ]]; then
  if [[ "$allow_partial" == "1" && "$final_rc" -eq 0 ]]; then
    status="warn"
    notes="reducer handoff is not ready"
  else
    status="fail"
    notes="reducer handoff is not ready"
    final_rc=1
  fi
fi

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg report_md "$report_md" \
  --argjson rc "$final_rc" \
  --argjson command_timeout_sec "$command_timeout_sec" \
  --argjson allow_partial "$allow_partial" \
  --argjson fail_fast "$fail_fast" \
  --argjson reducer_min_successful_vms "$reducer_min_successful_vms" \
  --argjson reducer_require_all_success "$reducer_require_all_success" \
  --argjson vm_total "$vm_total" \
  --argjson vm_pass "$vm_pass" \
  --argjson vm_fail "$vm_fail" \
  --argjson vm_timeout "$vm_timeout" \
  --argjson vm_skip "$vm_skip" \
  --argjson reducer_input_vm_count "$reducer_input_vm_count" \
  --argjson decision_counts "$decision_counts_json" \
  --argjson recommended_profile_counts "$recommended_profile_counts_json" \
  --arg modal_decision "$modal_decision" \
  --argjson modal_decision_count "$modal_decision_count_json" \
  --argjson modal_decision_support_rate_pct "$modal_decision_support_rate_pct_json" \
  --argjson support_rate_avg "$support_rate_avg_json" \
  --arg reducer_ready "$reducer_ready" \
  --arg reducer_not_ready_reason "$reducer_not_ready_reason" \
  --argjson vms "$vms_json" \
  '{
    version: 1,
    schema: {
      id: "profile_compare_multi_vm_sweep_summary"
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    notes: $notes,
    inputs: {
      reports_dir: $reports_dir,
      command_timeout_sec: $command_timeout_sec,
      allow_partial: ($allow_partial == 1),
      fail_fast: ($fail_fast == 1),
      reducer_min_successful_vms: $reducer_min_successful_vms,
      reducer_require_all_success: ($reducer_require_all_success == 1)
    },
    counts: {
      vm_total: $vm_total,
      vm_pass: $vm_pass,
      vm_fail: $vm_fail,
      vm_timeout: $vm_timeout,
      vm_skip: $vm_skip
    },
    reducer_handoff: {
      ready: ($reducer_ready == "true"),
      not_ready_reason: (if $reducer_not_ready_reason == "" then null else $reducer_not_ready_reason end),
      input_vm_count: $reducer_input_vm_count,
      decision_counts: $decision_counts,
      recommended_profile_counts: $recommended_profile_counts,
      modal_decision: (if $modal_decision == "" then null else $modal_decision end),
      modal_decision_count: $modal_decision_count,
      modal_decision_support_rate_pct: $modal_decision_support_rate_pct,
      support_rate_pct_avg: $support_rate_avg,
      input_vm_ids: [ $vms[] | select(.reducer_input_ready == true) | .vm_id ],
      input_summary_jsons: [ $vms[] | select(.reducer_input_ready == true) | .artifacts.summary_json ],
      input_report_mds: [ $vms[] | select(.reducer_input_ready == true) | .artifacts.report_md ],
      input_logs: [ $vms[] | select(.reducer_input_ready == true) | .artifacts.log ]
    },
    vms: $vms,
    artifacts: {
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json,
      report_md: $report_md
    }
  }' >"$summary_json"

if [[ "$summary_json" != "$canonical_summary_json" ]]; then
  cp "$summary_json" "$canonical_summary_json"
fi

{
  echo "# Profile Compare Multi-VM Sweep Report"
  echo
  echo "- Generated at (UTC): $(jq -r '.generated_at_utc' "$summary_json")"
  echo "- Status: $(jq -r '.status' "$summary_json")"
  echo "- RC: $(jq -r '.rc' "$summary_json")"
  echo "- Notes: $(jq -r '.notes' "$summary_json")"
  echo "- Reducer ready: $(jq -r '.reducer_handoff.ready' "$summary_json")"
  echo
  echo "## VM Results"
  echo
  echo "| VM | Status | rc | timed_out | duration_sec | summary_json | report_md | log |"
  echo "|---|---|---:|:---:|---:|---|---|---|"
  while IFS= read -r row; do
    vm_id="$(jq -r '.vm_id' <<<"$row")"
    vm_status="$(jq -r '.status' <<<"$row")"
    vm_rc="$(jq -r '.command_rc // "null"' <<<"$row")"
    vm_timed_out="$(jq -r '.timed_out' <<<"$row")"
    vm_duration="$(jq -r '.duration_sec' <<<"$row")"
    vm_summary="$(jq -r '.artifacts.summary_json // ""' <<<"$row")"
    vm_report="$(jq -r '.artifacts.report_md // ""' <<<"$row")"
    vm_log="$(jq -r '.artifacts.log // ""' <<<"$row")"
    echo "| $vm_id | $vm_status | $vm_rc | $vm_timed_out | $vm_duration | $vm_summary | $vm_report | $vm_log |"
  done < <(jq -c '.vms[]' "$summary_json")
  echo
  echo "## Reducer Handoff"
  echo
  echo "- Input VM count: $(jq -r '.reducer_handoff.input_vm_count' "$summary_json")"
  echo "- Modal decision: $(jq -r '.reducer_handoff.modal_decision // "none"' "$summary_json")"
  echo "- Modal support rate pct: $(jq -r '.reducer_handoff.modal_decision_support_rate_pct' "$summary_json")"
  echo "- Input summary JSONs:"
  while IFS= read -r summary_path; do
    echo "  - $summary_path"
  done < <(jq -r '.reducer_handoff.input_summary_jsons[]? // empty' "$summary_json")
} >"$report_md"

echo "[profile-compare-multi-vm-sweep] status=$status rc=$final_rc"
echo "[profile-compare-multi-vm-sweep] summary_json=$summary_json"
echo "[profile-compare-multi-vm-sweep] canonical_summary_json=$canonical_summary_json"
echo "[profile-compare-multi-vm-sweep] report_md=$report_md"
if [[ "$print_summary_json" == "1" ]]; then
  echo "[profile-compare-multi-vm-sweep] summary_json_payload:"
  cat "$summary_json"
fi

exit "$final_rc"
