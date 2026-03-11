#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EASY_NODE_SH="${PROD_PILOT_COHORT_QUICK_EASY_NODE_SH:-$ROOT_DIR/scripts/easy_node.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_quick.sh \
    [--bootstrap-directory URL] \
    [--subject ID] \
    [--rounds N] \
    [--pause-sec N] \
    [--continue-on-fail [0|1]] \
    [--require-all-rounds-ok [0|1]] \
    [--trend-min-go-rate-pct N] \
    [--max-alert-severity OK|WARN|CRITICAL] \
    [--reports-dir PATH] \
    [--summary-json PATH] \
    [--run-report-json PATH] \
    [--print-run-report [0|1]] \
    [--show-json [0|1]] \
    [-- <prod-pilot-runbook extra args...>]

Purpose:
  One-command sustained pilot for operators:
    1) run prod-pilot-cohort-runbook
    2) run prod-pilot-cohort-signoff (fail-closed)

Notes:
  - Uses strict defaults suitable for beta signoff.
  - If runbook exits non-zero but summary JSON exists, signoff still runs so you
    get an explicit policy verdict.
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
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

bool_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

int_or_die() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an integer >= 0"
    exit 2
  fi
}

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

for cmd in bash date dirname jq; do
  need_cmd "$cmd"
done

if [[ ! -x "$EASY_NODE_SH" ]]; then
  echo "missing executable easy_node.sh: $EASY_NODE_SH"
  exit 2
fi

bootstrap_directory="${PROD_PILOT_COHORT_QUICK_BOOTSTRAP_DIRECTORY:-}"
subject="${PROD_PILOT_COHORT_QUICK_SUBJECT:-pilot-client}"
rounds="${PROD_PILOT_COHORT_QUICK_ROUNDS:-5}"
pause_sec="${PROD_PILOT_COHORT_QUICK_PAUSE_SEC:-60}"
continue_on_fail="${PROD_PILOT_COHORT_QUICK_CONTINUE_ON_FAIL:-0}"
require_all_rounds_ok="${PROD_PILOT_COHORT_QUICK_REQUIRE_ALL_ROUNDS_OK:-1}"
trend_min_go_rate_pct="${PROD_PILOT_COHORT_QUICK_TREND_MIN_GO_RATE_PCT:-95}"
max_alert_severity="${PROD_PILOT_COHORT_QUICK_MAX_ALERT_SEVERITY:-WARN}"
bundle_outputs="${PROD_PILOT_COHORT_QUICK_BUNDLE_OUTPUTS:-1}"
bundle_fail_close="${PROD_PILOT_COHORT_QUICK_BUNDLE_FAIL_CLOSE:-1}"
reports_dir="${PROD_PILOT_COHORT_QUICK_REPORTS_DIR:-}"
summary_json="${PROD_PILOT_COHORT_QUICK_SUMMARY_JSON:-}"
run_report_json="${PROD_PILOT_COHORT_QUICK_RUN_REPORT_JSON:-}"
print_run_report="${PROD_PILOT_COHORT_QUICK_PRINT_RUN_REPORT:-0}"
show_json="${PROD_PILOT_COHORT_QUICK_SHOW_JSON:-0}"
signoff_check_tar_sha256="${PROD_PILOT_COHORT_QUICK_SIGNOFF_CHECK_TAR_SHA256:-1}"
signoff_check_manifest="${PROD_PILOT_COHORT_QUICK_SIGNOFF_CHECK_MANIFEST:-1}"
signoff_show_integrity_details="${PROD_PILOT_COHORT_QUICK_SIGNOFF_SHOW_INTEGRITY_DETAILS:-0}"
max_round_failures="${PROD_PILOT_COHORT_QUICK_MAX_ROUND_FAILURES:-0}"

declare -a runbook_extra_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bootstrap-directory)
      bootstrap_directory="${2:-}"
      shift 2
      ;;
    --subject)
      subject="${2:-}"
      shift 2
      ;;
    --rounds)
      rounds="${2:-}"
      shift 2
      ;;
    --pause-sec)
      pause_sec="${2:-}"
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
    --require-all-rounds-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_all_rounds_ok="${2:-}"
        shift 2
      else
        require_all_rounds_ok="1"
        shift
      fi
      ;;
    --trend-min-go-rate-pct)
      trend_min_go_rate_pct="${2:-}"
      shift 2
      ;;
    --max-alert-severity)
      max_alert_severity="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --run-report-json)
      run_report_json="${2:-}"
      shift 2
      ;;
    --print-run-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_run_report="${2:-}"
        shift 2
      else
        print_run_report="1"
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
    --)
      shift
      if [[ $# -gt 0 ]]; then
        runbook_extra_args=("$@")
      fi
      break
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

int_or_die "--rounds" "$rounds"
int_or_die "--pause-sec" "$pause_sec"
int_or_die "--max-round-failures" "$max_round_failures"
bool_or_die "--continue-on-fail" "$continue_on_fail"
bool_or_die "--require-all-rounds-ok" "$require_all_rounds_ok"
bool_or_die "--print-run-report" "$print_run_report"
bool_or_die "--show-json" "$show_json"
bool_or_die "--signoff-check-tar-sha256" "$signoff_check_tar_sha256"
bool_or_die "--signoff-check-manifest" "$signoff_check_manifest"
bool_or_die "--signoff-show-integrity-details" "$signoff_show_integrity_details"
bool_or_die "--bundle-outputs" "$bundle_outputs"
bool_or_die "--bundle-fail-close" "$bundle_fail_close"

if ! is_non_negative_decimal "$trend_min_go_rate_pct"; then
  echo "--trend-min-go-rate-pct must be a non-negative number"
  exit 2
fi

max_alert_severity="$(printf '%s' "$max_alert_severity" | tr '[:lower:]' '[:upper:]')"
if [[ "$max_alert_severity" != "OK" && "$max_alert_severity" != "WARN" && "$max_alert_severity" != "CRITICAL" ]]; then
  echo "--max-alert-severity must be OK, WARN, or CRITICAL"
  exit 2
fi

if [[ -z "$reports_dir" ]]; then
  ts="$(date +%Y%m%d_%H%M%S)"
  reports_dir="$ROOT_DIR/.easy-node-logs/prod_pilot_cohort_quick_${ts}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/prod_pilot_cohort_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$run_report_json" ]]; then
  run_report_json="$reports_dir/prod_pilot_cohort_quick_report.json"
else
  run_report_json="$(abs_path "$run_report_json")"
fi

mkdir -p "$reports_dir" "$(dirname "$summary_json")" "$(dirname "$run_report_json")"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_epoch="$(date -u +%s)"
runbook_rc=0
signoff_rc=0
signoff_attempted="0"
status="ok"
failure_step=""
final_rc=0

declare -a runbook_cmd=(
  "$EASY_NODE_SH" "prod-pilot-cohort-runbook"
  --rounds "$rounds"
  --pause-sec "$pause_sec"
  --continue-on-fail "$continue_on_fail"
  --require-all-rounds-ok "$require_all_rounds_ok"
  --trend-min-go-rate-pct "$trend_min_go_rate_pct"
  --max-alert-severity "$max_alert_severity"
  --bundle-outputs "$bundle_outputs"
  --bundle-fail-close "$bundle_fail_close"
  --reports-dir "$reports_dir"
  --summary-json "$summary_json"
  --print-summary-json "$show_json"
)

declare -a runbook_tail=()
if [[ -n "$bootstrap_directory" ]]; then
  runbook_tail+=(--bootstrap-directory "$bootstrap_directory")
fi
if [[ -n "$subject" ]]; then
  runbook_tail+=(--subject "$subject")
fi
if [[ "${#runbook_extra_args[@]}" -gt 0 ]]; then
  runbook_tail+=("${runbook_extra_args[@]}")
fi
if [[ "${#runbook_tail[@]}" -gt 0 ]]; then
  runbook_cmd+=(-- "${runbook_tail[@]}")
fi

echo "[prod-pilot-cohort-quick] runbook start reports_dir=$reports_dir"
set +e
"${runbook_cmd[@]}"
runbook_rc=$?
set -e

if [[ "$runbook_rc" -ne 0 ]]; then
  if [[ ! -f "$summary_json" ]]; then
    echo "[prod-pilot-cohort-quick] runbook failed and summary missing: rc=$runbook_rc summary_json=$summary_json"
    status="fail"
    failure_step="runbook_summary_missing"
    final_rc="$runbook_rc"
  else
    echo "[prod-pilot-cohort-quick] runbook failed (rc=$runbook_rc) but summary exists; continuing to signoff"
  fi
fi

if [[ "$failure_step" != "runbook_summary_missing" ]]; then
  declare -a signoff_cmd=(
    "$EASY_NODE_SH" "prod-pilot-cohort-signoff"
    --summary-json "$summary_json"
    --reports-dir "$reports_dir"
    --check-tar-sha256 "$signoff_check_tar_sha256"
    --check-manifest "$signoff_check_manifest"
    --show-integrity-details "$signoff_show_integrity_details"
    --require-status-ok 1
    --require-all-rounds-ok "$require_all_rounds_ok"
    --max-round-failures "$max_round_failures"
    --require-trend-go 1
    --min-go-rate-pct "$trend_min_go_rate_pct"
    --max-alert-severity "$max_alert_severity"
    --require-bundle-created "$bundle_outputs"
    --require-bundle-manifest "$bundle_outputs"
    --show-json "$show_json"
  )

  signoff_attempted="1"
  echo "[prod-pilot-cohort-quick] signoff start summary_json=$summary_json"
  set +e
  "${signoff_cmd[@]}"
  signoff_rc=$?
  set -e

  if [[ "$signoff_rc" -ne 0 ]]; then
    status="fail"
    failure_step="signoff"
    final_rc="$signoff_rc"
  elif [[ "$runbook_rc" -ne 0 ]]; then
    status="fail"
    failure_step="runbook"
    final_rc="$runbook_rc"
  fi
fi

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
finished_epoch="$(date -u +%s)"
duration_sec=$((finished_epoch - started_epoch))
if [[ "$duration_sec" -lt 0 ]]; then
  duration_sec=0
fi

jq -nc \
  --arg started_at "$started_at" \
  --arg finished_at "$finished_at" \
  --arg status "$status" \
  --arg failure_step "$failure_step" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg run_report_json "$run_report_json" \
  --arg bootstrap_directory "$bootstrap_directory" \
  --arg subject "$subject" \
  --arg max_alert_severity "$max_alert_severity" \
  --argjson rounds "$rounds" \
  --argjson pause_sec "$pause_sec" \
  --argjson continue_on_fail "$(json_bool "$continue_on_fail")" \
  --argjson require_all_rounds_ok "$(json_bool "$require_all_rounds_ok")" \
  --argjson trend_min_go_rate_pct "$trend_min_go_rate_pct" \
  --argjson bundle_outputs "$(json_bool "$bundle_outputs")" \
  --argjson bundle_fail_close "$(json_bool "$bundle_fail_close")" \
  --argjson runbook_rc "$runbook_rc" \
  --argjson signoff_attempted "$(json_bool "$signoff_attempted")" \
  --argjson signoff_rc "$signoff_rc" \
  --argjson final_rc "$final_rc" \
  --argjson duration_sec "$duration_sec" \
  '{
    started_at:$started_at,
    finished_at:$finished_at,
    duration_sec:$duration_sec,
    status:$status,
    failure_step:($failure_step // ""),
    final_rc:$final_rc,
    runbook:{
      rc:$runbook_rc
    },
    signoff:{
      attempted:$signoff_attempted,
      rc:$signoff_rc
    },
    config:{
      bootstrap_directory:($bootstrap_directory // ""),
      subject:($subject // ""),
      rounds:$rounds,
      pause_sec:$pause_sec,
      continue_on_fail:$continue_on_fail,
      require_all_rounds_ok:$require_all_rounds_ok,
      trend_min_go_rate_pct:$trend_min_go_rate_pct,
      max_alert_severity:$max_alert_severity,
      bundle_outputs:$bundle_outputs,
      bundle_fail_close:$bundle_fail_close
    },
    artifacts:{
      reports_dir:$reports_dir,
      summary_json:$summary_json,
      run_report_json:$run_report_json
    }
  }' >"$run_report_json"

echo "[prod-pilot-cohort-quick] run_report_json=$run_report_json"
if [[ "$print_run_report" == "1" ]]; then
  echo "[prod-pilot-cohort-quick] run_report_payload:"
  cat "$run_report_json"
fi

if [[ "$status" == "ok" ]]; then
  echo "[prod-pilot-cohort-quick] ok"
  exit 0
fi

echo "[prod-pilot-cohort-quick] failed step=${failure_step:-unknown} rc=$final_rc"
exit "$final_rc"
