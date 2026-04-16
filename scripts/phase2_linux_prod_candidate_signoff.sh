#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase2_linux_prod_candidate_signoff.sh \
    [--reports-dir DIR] \
    [--run-summary-json PATH] \
    [--roadmap-summary-json PATH] \
    [--roadmap-report-md PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--run-<arg> ...] \
    [--roadmap-<arg> ...]

Purpose:
  One-command Phase-2 Linux production-candidate signoff wrapper:
    1) phase2_linux_prod_candidate_run.sh
    2) roadmap_progress_report.sh

Notes:
  - Wrapper-owned flags are reserved; stage pass-through uses prefixes:
      --run-...      -> forwarded to phase2_linux_prod_candidate_run.sh
      --roadmap-...  -> forwarded to roadmap_progress_report.sh
  - Dry-run forwards --dry-run 1 to the run stage.
    The roadmap stage defaults to no-refresh and quiet output unless explicit
    --roadmap-refresh-* or print overrides are supplied.
  - The roadmap stage still runs if the run stage fails so the handoff artifact
    is always attempted.
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

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
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

print_cmd() {
  local first=1
  local arg
  for arg in "$@"; do
    if [[ "$first" -eq 0 ]]; then
      printf ' '
    fi
    printf '%q' "$arg"
    first=0
  done
  printf '\n'
}

array_has_arg() {
  local needle="$1"
  shift
  local arg
  for arg in "$@"; do
    if [[ "$arg" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

json_file_valid() {
  local path="$1"
  [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1
}

run_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    type == "object"
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (.schema.id // "") == "phase2_linux_prod_candidate_run_summary"
    and ((.status | type) == "string")
    and ((.rc | type) == "number")
    and (
      (.status == "pass" and .rc == 0)
      or (.status != "pass" and .rc != 0)
    )
  ' "$path" >/dev/null 2>&1
}

roadmap_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    type == "object"
    and (.version // 0) == 1
    and ((.status | type) == "string")
    and ((.rc | type) == "number")
    and ((.vpn_track | type) == "object")
    and (
      (.status == "pass" and .rc == 0)
      or (.status == "warn" and .rc == 0)
      or (.status == "fail" and .rc != 0)
    )
  ' "$path" >/dev/null 2>&1
}

run_stage_capture() {
  local label="$1"
  local log_path="$2"
  shift 2
  local rc=0
  echo "[phase2-linux-prod-candidate-signoff] stage=$label status=running"
  set +e
  "$@" >"$log_path" 2>&1
  rc=$?
  if [[ "$rc" -eq 0 ]]; then
    echo "[phase2-linux-prod-candidate-signoff] stage=$label status=pass rc=0"
  else
    echo "[phase2-linux-prod-candidate-signoff] stage=$label status=fail rc=$rc"
  fi
  return "$rc"
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${PHASE2_LINUX_PROD_CANDIDATE_SIGNOFF_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
run_summary_json=""
roadmap_summary_json=""
roadmap_report_md=""
summary_json=""
print_summary_json="${PHASE2_LINUX_PROD_CANDIDATE_SIGNOFF_PRINT_SUMMARY_JSON:-1}"
dry_run="${PHASE2_LINUX_PROD_CANDIDATE_SIGNOFF_DRY_RUN:-0}"

declare -a run_passthrough_args=()
declare -a roadmap_passthrough_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      if [[ $# -lt 2 || "${2:-}" == --* ]]; then
        echo "--reports-dir requires a value"
        exit 2
      fi
      reports_dir="${2:-}"
      shift 2
      ;;
    --run-summary-json)
      if [[ $# -lt 2 || "${2:-}" == --* ]]; then
        echo "--run-summary-json requires a value"
        exit 2
      fi
      run_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-summary-json)
      if [[ $# -lt 2 || "${2:-}" == --* ]]; then
        echo "--roadmap-summary-json requires a value"
        exit 2
      fi
      roadmap_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-report-md)
      if [[ $# -lt 2 || "${2:-}" == --* ]]; then
        echo "--roadmap-report-md requires a value"
        exit 2
      fi
      roadmap_report_md="${2:-}"
      shift 2
      ;;
    --summary-json)
      if [[ $# -lt 2 || "${2:-}" == --* ]]; then
        echo "--summary-json requires a value"
        exit 2
      fi
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
    --dry-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dry_run="${2:-}"
        shift 2
      else
        dry_run="1"
        shift
      fi
      ;;
    --run-dry-run)
      echo "reserved wrapper arg: --run-dry-run; use --dry-run"
      exit 2
      ;;
    --roadmap-dry-run)
      echo "reserved wrapper arg: --roadmap-dry-run"
      exit 2
      ;;
    --run-*)
      forwarded_flag="--${1#--run-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid run-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        run_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        run_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    --roadmap-*)
      forwarded_flag="--${1#--roadmap-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid roadmap-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        roadmap_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        roadmap_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    -h|--help|help)
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
bool_arg_or_die "--dry-run" "$dry_run"

reports_dir="$(abs_path "$reports_dir")"
if [[ -z "$run_summary_json" ]]; then
  run_summary_json="$reports_dir/phase2_linux_prod_candidate_run_summary.json"
fi
if [[ -z "$roadmap_summary_json" ]]; then
  roadmap_summary_json="$reports_dir/roadmap_progress_summary.json"
fi
if [[ -z "$roadmap_report_md" ]]; then
  roadmap_report_md="$reports_dir/roadmap_progress_report.md"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/phase2_linux_prod_candidate_signoff_summary.json"
fi

run_summary_json="$(abs_path "$run_summary_json")"
roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
roadmap_report_md="$(abs_path "$roadmap_report_md")"
summary_json="$(abs_path "$summary_json")"

mkdir -p "$reports_dir" \
  "$(dirname "$run_summary_json")" \
  "$(dirname "$roadmap_summary_json")" \
  "$(dirname "$roadmap_report_md")" \
  "$(dirname "$summary_json")"

run_script="${PHASE2_LINUX_PROD_CANDIDATE_RUN_SCRIPT:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_run.sh}"
roadmap_script="${ROADMAP_PROGRESS_REPORT_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"

if [[ ! -x "$run_script" ]]; then
  echo "missing executable stage script: $run_script"
  exit 2
fi
if [[ ! -x "$roadmap_script" ]]; then
  echo "missing executable stage script: $roadmap_script"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

run_log="$TMP_DIR/run_stage.log"
roadmap_log="$TMP_DIR/roadmap_stage.log"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

declare run_command_rc=0
declare roadmap_command_rc=0
declare run_contract_valid=0
declare roadmap_contract_valid=0
declare run_status="fail"
declare roadmap_status="fail"
declare run_rc=0
declare roadmap_rc=0
declare run_contract_error=""
declare roadmap_contract_error=""
declare run_command=""
declare roadmap_command=""

declare -a run_command_args=("$run_script" --summary-json "$run_summary_json")
if [[ "$dry_run" == "1" ]]; then
  run_command_args+=(--dry-run 1)
fi
if ((${#run_passthrough_args[@]} > 0)); then
  run_command_args+=("${run_passthrough_args[@]}")
fi
run_command="$(print_cmd "${run_command_args[@]}")"

set +e
run_stage_capture "phase2_linux_prod_candidate_run" "$run_log" "${run_command_args[@]}"
run_command_rc=$?
set -e

if run_summary_contract_valid "$run_summary_json"; then
  run_contract_valid=1
  run_status="$(jq -r '.status // "fail"' "$run_summary_json" 2>/dev/null || echo fail)"
  run_rc="$(jq -r '.rc // 0' "$run_summary_json" 2>/dev/null || echo 0)"
  if [[ "$run_command_rc" -ne 0 ]]; then
    run_status="fail"
    run_rc="$run_command_rc"
  fi
else
  run_contract_valid=0
  run_contract_error="run summary JSON is missing required fields or uses an incompatible schema"
  run_status="fail"
  if [[ "$run_command_rc" -ne 0 ]]; then
    run_rc="$run_command_rc"
  else
    run_rc=3
  fi
fi

declare -a roadmap_command_args=("$roadmap_script" --summary-json "$roadmap_summary_json" --report-md "$roadmap_report_md")
if ! array_has_arg "--phase2-linux-prod-candidate-summary-json" "${roadmap_passthrough_args[@]}"; then
  roadmap_command_args+=(--phase2-linux-prod-candidate-summary-json "$run_summary_json")
fi
if [[ "$dry_run" == "1" ]]; then
  if ! array_has_arg "--refresh-manual-validation" "${roadmap_passthrough_args[@]}"; then
    roadmap_command_args+=(--refresh-manual-validation 0)
  fi
  if ! array_has_arg "--refresh-single-machine-readiness" "${roadmap_passthrough_args[@]}"; then
    roadmap_command_args+=(--refresh-single-machine-readiness 0)
  fi
  if ! array_has_arg "--print-report" "${roadmap_passthrough_args[@]}"; then
    roadmap_command_args+=(--print-report 0)
  fi
  if ! array_has_arg "--print-summary-json" "${roadmap_passthrough_args[@]}"; then
    roadmap_command_args+=(--print-summary-json 0)
  fi
fi
if ((${#roadmap_passthrough_args[@]} > 0)); then
  roadmap_command_args+=("${roadmap_passthrough_args[@]}")
fi
roadmap_command="$(print_cmd "${roadmap_command_args[@]}")"

set +e
run_stage_capture "roadmap_progress_report" "$roadmap_log" "${roadmap_command_args[@]}"
roadmap_command_rc=$?
set -e

if roadmap_summary_contract_valid "$roadmap_summary_json"; then
  roadmap_contract_valid=1
  roadmap_status="$(jq -r '.status // "fail"' "$roadmap_summary_json" 2>/dev/null || echo fail)"
  roadmap_rc="$(jq -r '.rc // 0' "$roadmap_summary_json" 2>/dev/null || echo 0)"
  if [[ "$roadmap_command_rc" -ne 0 ]]; then
    roadmap_status="fail"
    roadmap_rc="$roadmap_command_rc"
  fi
else
  roadmap_contract_valid=0
  roadmap_contract_error="roadmap summary JSON is missing required fields or uses an incompatible schema"
  roadmap_status="fail"
  if [[ "$roadmap_command_rc" -ne 0 ]]; then
    roadmap_rc="$roadmap_command_rc"
  else
    roadmap_rc=3
  fi
fi

final_status="pass"
final_rc=0
if [[ "$run_status" == "fail" ]]; then
  final_status="fail"
  final_rc="$run_rc"
elif [[ "$roadmap_status" == "fail" ]]; then
  final_status="fail"
  final_rc="$roadmap_rc"
elif [[ "$run_status" == "warn" || "$roadmap_status" == "warn" ]]; then
  final_status="warn"
  final_rc=0
fi
if [[ "$final_status" == "fail" && "$final_rc" -eq 0 ]]; then
  final_rc=1
fi

decision_reason_details_json='[]'
decision_warning_details_json='[]'

append_decision_reason() {
  local code="$1"
  local step="$2"
  local message="$3"
  local status="$4"
  local rc="$5"
  decision_reason_details_json="$(
    jq -cn \
      --argjson arr "$decision_reason_details_json" \
      --arg code "$code" \
      --arg step "$step" \
      --arg message "$message" \
      --arg status "$status" \
      --argjson rc "$rc" \
      '$arr + [{
        code: $code,
        step: $step,
        message: $message,
        status: $status,
        rc: $rc
      }]'
  )"
}

append_decision_warning() {
  local code="$1"
  local step="$2"
  local message="$3"
  local status="$4"
  decision_warning_details_json="$(
    jq -cn \
      --argjson arr "$decision_warning_details_json" \
      --arg code "$code" \
      --arg step "$step" \
      --arg message "$message" \
      --arg status "$status" \
      '$arr + [{
        code: $code,
        step: $step,
        message: $message,
        status: $status
      }]'
  )"
}

if [[ "$run_contract_valid" != "1" ]]; then
  append_decision_reason \
    "run_summary_contract_invalid" \
    "phase2_linux_prod_candidate_run" \
    "run summary JSON is missing required fields or uses an incompatible schema" \
    "$run_status" \
    "$run_rc"
fi
if [[ "$run_status" == "fail" ]]; then
  append_decision_reason \
    "run_step_not_pass" \
    "phase2_linux_prod_candidate_run" \
    "phase2 run step did not pass" \
    "$run_status" \
    "$run_rc"
fi
if [[ "$roadmap_contract_valid" != "1" ]]; then
  append_decision_reason \
    "roadmap_summary_contract_invalid" \
    "roadmap_progress_report" \
    "roadmap summary JSON is missing required fields or uses an incompatible schema" \
    "$roadmap_status" \
    "$roadmap_rc"
fi
if [[ "$roadmap_status" == "fail" ]]; then
  append_decision_reason \
    "roadmap_step_not_pass" \
    "roadmap_progress_report" \
    "roadmap progress report step did not pass" \
    "$roadmap_status" \
    "$roadmap_rc"
fi
if [[ "$roadmap_status" == "warn" ]]; then
  append_decision_warning \
    "roadmap_step_warn" \
    "roadmap_progress_report" \
    "roadmap progress report returned warn status" \
    "$roadmap_status"
fi

decision_reasons_json="$(
  jq -cn --argjson details "$decision_reason_details_json" '[ $details[] | .message ]'
)"
decision_warnings_json="$(
  jq -cn --argjson details "$decision_warning_details_json" '[ $details[] | .message ]'
)"

run_summary_exists="0"
roadmap_summary_exists="0"
roadmap_report_exists="0"
if [[ -f "$run_summary_json" ]]; then
  run_summary_exists="1"
fi
if [[ -f "$roadmap_summary_json" ]]; then
  roadmap_summary_exists="1"
fi
if [[ -f "$roadmap_report_md" ]]; then
  roadmap_report_exists="1"
fi

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg run_summary_json "$run_summary_json" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg roadmap_report_md "$roadmap_report_md" \
  --arg summary_json "$summary_json" \
  --argjson dry_run "$dry_run" \
  --argjson print_summary_json "$print_summary_json" \
  --arg run_command "$run_command" \
  --arg roadmap_command "$roadmap_command" \
  --arg run_status "$run_status" \
  --arg roadmap_status "$roadmap_status" \
  --arg run_log "$run_log" \
  --arg roadmap_log "$roadmap_log" \
  --argjson run_command_rc "$run_command_rc" \
  --argjson roadmap_command_rc "$roadmap_command_rc" \
  --argjson run_rc "$run_rc" \
  --argjson roadmap_rc "$roadmap_rc" \
  --argjson run_contract_valid "$run_contract_valid" \
  --argjson roadmap_contract_valid "$roadmap_contract_valid" \
  --arg run_contract_error "$run_contract_error" \
  --arg roadmap_contract_error "$roadmap_contract_error" \
  --argjson run_summary_exists "$run_summary_exists" \
  --argjson roadmap_summary_exists "$roadmap_summary_exists" \
  --argjson roadmap_report_exists "$roadmap_report_exists" \
  --argjson decision_reasons "$decision_reasons_json" \
  --argjson decision_reason_details "$decision_reason_details_json" \
  --argjson decision_warnings "$decision_warnings_json" \
  --argjson decision_warning_details "$decision_warning_details_json" \
  '{
    version: 1,
    schema: {
      id: "phase2_linux_prod_candidate_signoff_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    inputs: {
      reports_dir: $reports_dir,
      dry_run: ($dry_run == 1),
      print_summary_json: ($print_summary_json == 1)
    },
    steps: {
      phase2_linux_prod_candidate_run: {
        status: $run_status,
        rc: $run_rc,
        command_rc: $run_command_rc,
        command: $run_command,
        contract_valid: ($run_contract_valid == 1),
        contract_error: (if $run_contract_error == "" then null else $run_contract_error end),
        artifacts: {
          summary_json: $run_summary_json,
          summary_exists: ($run_summary_exists == 1),
          log: $run_log
        }
      },
      roadmap_progress_report: {
        status: $roadmap_status,
        rc: $roadmap_rc,
        command_rc: $roadmap_command_rc,
        command: $roadmap_command,
        contract_valid: ($roadmap_contract_valid == 1),
        contract_error: (if $roadmap_contract_error == "" then null else $roadmap_contract_error end),
        artifacts: {
          summary_json: $roadmap_summary_json,
          summary_exists: ($roadmap_summary_exists == 1),
          report_md: $roadmap_report_md,
          report_exists: ($roadmap_report_exists == 1),
          log: $roadmap_log
        }
      }
    },
    decision: {
      pass: ($status == "pass"),
      reasons: $decision_reasons,
      reason_details: $decision_reason_details,
      reason_codes: ($decision_reason_details | map(.code) | unique),
      warnings: $decision_warnings,
      warning_details: $decision_warning_details,
      warning_codes: ($decision_warning_details | map(.code) | unique)
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      run_summary_json: $run_summary_json,
      roadmap_summary_json: $roadmap_summary_json,
      roadmap_report_md: $roadmap_report_md
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[phase2-linux-prod-candidate-signoff] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[phase2-linux-prod-candidate-signoff] run_status=$run_status rc=$run_rc command_rc=$run_command_rc contract_valid=$run_contract_valid"
echo "[phase2-linux-prod-candidate-signoff] roadmap_status=$roadmap_status rc=$roadmap_rc command_rc=$roadmap_command_rc contract_valid=$roadmap_contract_valid"
echo "[phase2-linux-prod-candidate-signoff] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
