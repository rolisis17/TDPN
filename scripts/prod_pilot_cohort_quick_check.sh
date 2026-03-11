#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_quick_check.sh \
    [--run-report-json PATH] \
    [--reports-dir PATH] \
    [--require-status-ok [0|1]] \
    [--require-runbook-ok [0|1]] \
    [--require-signoff-attempted [0|1]] \
    [--require-signoff-ok [0|1]] \
    [--require-summary-json [0|1]] \
    [--require-summary-status-ok [0|1]] \
    [--max-duration-sec N] \
    [--show-json [0|1]]

Purpose:
  Verify quick sustained-pilot run-report artifacts and fail on non-signoff conditions.

Notes:
  - Provide one of:
    - --run-report-json (recommended; from prod-pilot-cohort-quick)
    - --reports-dir (auto-resolves <reports_dir>/prod_pilot_cohort_quick_report.json)
  - Default policy requires quick status=ok, runbook rc=0, signoff attempted+rc=0,
    and a summary JSON present with status=ok.
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    echo ""
    return
  fi
  if [[ "$path" == /* ]]; then
    echo "$path"
  else
    echo "$ROOT_DIR/$path"
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

json_bool() {
  if [[ "${1:-0}" == "1" ]]; then
    echo "true"
  else
    echo "false"
  fi
}

json_string() {
  local file="$1"
  local expr="$2"
  jq -r "$expr // \"\"" "$file" 2>/dev/null || true
}

json_int() {
  local file="$1"
  local expr="$2"
  local value
  value="$(jq -r "$expr // 0" "$file" 2>/dev/null || true)"
  if [[ -z "$value" || ! "$value" =~ ^-?[0-9]+$ ]]; then
    echo "0"
    return
  fi
  echo "$value"
}

json_bool_flag() {
  local file="$1"
  local expr="$2"
  local value
  value="$(jq -r "$expr // false | if . then \"1\" else \"0\" end" "$file" 2>/dev/null || true)"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "0"
    return
  fi
  echo "$value"
}

need_cmd jq

run_report_json=""
reports_dir=""
require_status_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_STATUS_OK:-1}"
require_runbook_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_RUNBOOK_OK:-1}"
require_signoff_attempted="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SIGNOFF_ATTEMPTED:-1}"
require_signoff_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SIGNOFF_OK:-1}"
require_summary_json="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SUMMARY_JSON:-1}"
require_summary_status_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SUMMARY_STATUS_OK:-1}"
max_duration_sec="${PROD_PILOT_COHORT_QUICK_CHECK_MAX_DURATION_SEC:-0}"
show_json="${PROD_PILOT_COHORT_QUICK_CHECK_SHOW_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-report-json)
      run_report_json="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --require-status-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_status_ok="${2:-}"
        shift 2
      else
        require_status_ok="1"
        shift
      fi
      ;;
    --require-runbook-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_runbook_ok="${2:-}"
        shift 2
      else
        require_runbook_ok="1"
        shift
      fi
      ;;
    --require-signoff-attempted)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_signoff_attempted="${2:-}"
        shift 2
      else
        require_signoff_attempted="1"
        shift
      fi
      ;;
    --require-signoff-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_signoff_ok="${2:-}"
        shift 2
      else
        require_signoff_ok="1"
        shift
      fi
      ;;
    --require-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_summary_json="${2:-}"
        shift 2
      else
        require_summary_json="1"
        shift
      fi
      ;;
    --require-summary-status-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_summary_status_ok="${2:-}"
        shift 2
      else
        require_summary_status_ok="1"
        shift
      fi
      ;;
    --max-duration-sec)
      max_duration_sec="${2:-}"
      shift 2
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

bool_arg_or_die "--require-status-ok" "$require_status_ok"
bool_arg_or_die "--require-runbook-ok" "$require_runbook_ok"
bool_arg_or_die "--require-signoff-attempted" "$require_signoff_attempted"
bool_arg_or_die "--require-signoff-ok" "$require_signoff_ok"
bool_arg_or_die "--require-summary-json" "$require_summary_json"
bool_arg_or_die "--require-summary-status-ok" "$require_summary_status_ok"
bool_arg_or_die "--show-json" "$show_json"
if [[ ! "$max_duration_sec" =~ ^[0-9]+$ ]]; then
  echo "--max-duration-sec must be an integer >= 0"
  exit 2
fi

run_report_json="$(abs_path "$run_report_json")"
reports_dir="$(abs_path "$reports_dir")"
if [[ -z "$run_report_json" && -n "$reports_dir" ]]; then
  run_report_json="$reports_dir/prod_pilot_cohort_quick_report.json"
fi
if [[ -z "$run_report_json" ]]; then
  echo "missing required input: set --run-report-json or --reports-dir"
  exit 2
fi
if [[ ! -f "$run_report_json" ]]; then
  echo "quick run report JSON not found: $run_report_json"
  exit 1
fi
if ! jq -e . "$run_report_json" >/dev/null 2>&1; then
  echo "quick run report JSON is not valid JSON: $run_report_json"
  exit 1
fi

status="$(json_string "$run_report_json" '.status')"
failure_step="$(json_string "$run_report_json" '.failure_step')"
final_rc="$(json_int "$run_report_json" '.final_rc')"
duration_sec="$(json_int "$run_report_json" '.duration_sec')"
runbook_rc="$(json_int "$run_report_json" '.runbook.rc')"
signoff_attempted="$(json_bool_flag "$run_report_json" '.signoff.attempted')"
signoff_rc="$(json_int "$run_report_json" '.signoff.rc')"
summary_json="$(json_string "$run_report_json" '.artifacts.summary_json')"
if [[ -n "$summary_json" && "$summary_json" != /* ]]; then
  summary_json="$ROOT_DIR/$summary_json"
fi
summary_status=""
if [[ -n "$summary_json" && -f "$summary_json" ]]; then
  summary_status="$(json_string "$summary_json" '.status')"
fi

declare -a errors=()

if [[ "$require_status_ok" == "1" && "$status" != "ok" ]]; then
  errors+=("quick status is not ok (status=${status:-unset}, failure_step=${failure_step:-none}, final_rc=$final_rc)")
fi
if [[ "$require_runbook_ok" == "1" && "$runbook_rc" -ne 0 ]]; then
  errors+=("runbook rc is non-zero (runbook_rc=$runbook_rc)")
fi
if [[ "$require_signoff_attempted" == "1" && "$signoff_attempted" != "1" ]]; then
  errors+=("signoff was not attempted")
fi
if [[ "$require_signoff_ok" == "1" && "$signoff_rc" -ne 0 ]]; then
  errors+=("signoff rc is non-zero (signoff_rc=$signoff_rc)")
fi
if [[ "$max_duration_sec" -gt 0 && "$duration_sec" -gt "$max_duration_sec" ]]; then
  errors+=("duration exceeds limit (${duration_sec}s > ${max_duration_sec}s)")
fi
if [[ "$require_summary_json" == "1" ]]; then
  if [[ -z "$summary_json" ]]; then
    errors+=("summary_json path missing in run report")
  elif [[ ! -f "$summary_json" ]]; then
    errors+=("summary_json file not found: $summary_json")
  fi
fi
if [[ "$require_summary_status_ok" == "1" ]]; then
  if [[ -z "$summary_json" || ! -f "$summary_json" ]]; then
    errors+=("cannot validate summary status because summary JSON is unavailable")
  elif [[ "$summary_status" != "ok" ]]; then
    errors+=("summary status is not ok (summary_status=${summary_status:-unset})")
  fi
fi

decision="GO"
if ((${#errors[@]} > 0)); then
  decision="NO-GO"
fi

echo "[prod-pilot-cohort-quick-check] run_report_json=$run_report_json"
echo "[prod-pilot-cohort-quick-check] decision=$decision status=${status:-unset} runbook_rc=$runbook_rc signoff_attempted=$signoff_attempted signoff_rc=$signoff_rc duration_sec=$duration_sec"

if ((${#errors[@]} > 0)); then
  echo "[prod-pilot-cohort-quick-check] failed with ${#errors[@]} issue(s):"
  for err in "${errors[@]}"; do
    echo "  - $err"
  done
  if [[ "$show_json" == "1" ]]; then
    echo "[prod-pilot-cohort-quick-check] run report payload:"
    cat "$run_report_json"
  fi
  exit 1
fi

if [[ "$show_json" == "1" ]]; then
  echo "[prod-pilot-cohort-quick-check] run report payload:"
  cat "$run_report_json"
fi
echo "[prod-pilot-cohort-quick-check] ok"
