#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

COHORT_CHECK_SCRIPT="${PROD_PILOT_COHORT_CHECK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_check.sh}"

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
    [--require-cohort-signoff-policy [0|1]] \
    [--require-trend-artifact-policy-match [0|1]] \
    [--require-trend-wg-validate-udp-source [0|1]] \
    [--require-trend-wg-validate-strict-distinct [0|1]] \
    [--require-trend-wg-soak-diversity-pass [0|1]] \
    [--min-trend-wg-soak-selection-lines N] \
    [--min-trend-wg-soak-entry-operators N] \
    [--min-trend-wg-soak-exit-operators N] \
    [--min-trend-wg-soak-cross-operator-pairs N] \
    [--min-go-rate-pct N] \
    [--max-alert-severity OK|WARN|CRITICAL] \
    [--require-bundle-created [0|1]] \
    [--require-bundle-manifest [0|1]] \
    [--require-summary-json [0|1]] \
    [--require-summary-status-ok [0|1]] \
    [--require-incident-snapshot-on-fail [0|1]] \
    [--require-incident-snapshot-artifacts [0|1]] \
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
  value="$(jq -r "$expr // false | if . == true or . == 1 or . == \"1\" then \"1\" elif . == false or . == 0 or . == \"0\" then \"0\" else \"0\" end" "$file" 2>/dev/null || true)"
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
require_cohort_signoff_policy="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_COHORT_SIGNOFF_POLICY:-0}"
require_trend_artifact_policy_match="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_TREND_ARTIFACT_POLICY_MATCH:-1}"
require_trend_wg_validate_udp_source="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_TREND_WG_VALIDATE_UDP_SOURCE:-1}"
require_trend_wg_validate_strict_distinct="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_TREND_WG_VALIDATE_STRICT_DISTINCT:-1}"
require_trend_wg_soak_diversity_pass="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_TREND_WG_SOAK_DIVERSITY_PASS:-1}"
min_trend_wg_soak_selection_lines="${PROD_PILOT_COHORT_QUICK_CHECK_MIN_TREND_WG_SOAK_SELECTION_LINES:-12}"
min_trend_wg_soak_entry_operators="${PROD_PILOT_COHORT_QUICK_CHECK_MIN_TREND_WG_SOAK_ENTRY_OPERATORS:-2}"
min_trend_wg_soak_exit_operators="${PROD_PILOT_COHORT_QUICK_CHECK_MIN_TREND_WG_SOAK_EXIT_OPERATORS:-2}"
min_trend_wg_soak_cross_operator_pairs="${PROD_PILOT_COHORT_QUICK_CHECK_MIN_TREND_WG_SOAK_CROSS_OPERATOR_PAIRS:-2}"
min_go_rate_pct="${PROD_PILOT_COHORT_QUICK_CHECK_MIN_GO_RATE_PCT:-95}"
max_alert_severity="${PROD_PILOT_COHORT_QUICK_CHECK_MAX_ALERT_SEVERITY:-WARN}"
require_bundle_created="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_BUNDLE_CREATED:-1}"
require_bundle_manifest="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_BUNDLE_MANIFEST:-1}"
require_summary_json="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SUMMARY_JSON:-1}"
require_summary_status_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SUMMARY_STATUS_OK:-1}"
require_incident_snapshot_on_fail="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-1}"
require_incident_snapshot_artifacts="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-1}"
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
    --require-cohort-signoff-policy)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_cohort_signoff_policy="${2:-}"
        shift 2
      else
        require_cohort_signoff_policy="1"
        shift
      fi
      ;;
    --require-trend-artifact-policy-match)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_trend_artifact_policy_match="${2:-}"
        shift 2
      else
        require_trend_artifact_policy_match="1"
        shift
      fi
      ;;
    --require-trend-wg-validate-udp-source)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_trend_wg_validate_udp_source="${2:-}"
        shift 2
      else
        require_trend_wg_validate_udp_source="1"
        shift
      fi
      ;;
    --require-trend-wg-validate-strict-distinct)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_trend_wg_validate_strict_distinct="${2:-}"
        shift 2
      else
        require_trend_wg_validate_strict_distinct="1"
        shift
      fi
      ;;
    --require-trend-wg-soak-diversity-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_trend_wg_soak_diversity_pass="${2:-}"
        shift 2
      else
        require_trend_wg_soak_diversity_pass="1"
        shift
      fi
      ;;
    --min-trend-wg-soak-selection-lines)
      min_trend_wg_soak_selection_lines="${2:-}"
      shift 2
      ;;
    --min-trend-wg-soak-entry-operators)
      min_trend_wg_soak_entry_operators="${2:-}"
      shift 2
      ;;
    --min-trend-wg-soak-exit-operators)
      min_trend_wg_soak_exit_operators="${2:-}"
      shift 2
      ;;
    --min-trend-wg-soak-cross-operator-pairs)
      min_trend_wg_soak_cross_operator_pairs="${2:-}"
      shift 2
      ;;
    --min-go-rate-pct)
      min_go_rate_pct="${2:-}"
      shift 2
      ;;
    --max-alert-severity)
      max_alert_severity="${2:-}"
      shift 2
      ;;
    --require-bundle-created)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_bundle_created="${2:-}"
        shift 2
      else
        require_bundle_created="1"
        shift
      fi
      ;;
    --require-bundle-manifest)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_bundle_manifest="${2:-}"
        shift 2
      else
        require_bundle_manifest="1"
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
    --require-incident-snapshot-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_incident_snapshot_on_fail="${2:-}"
        shift 2
      else
        require_incident_snapshot_on_fail="1"
        shift
      fi
      ;;
    --require-incident-snapshot-artifacts)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_incident_snapshot_artifacts="${2:-}"
        shift 2
      else
        require_incident_snapshot_artifacts="1"
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
bool_arg_or_die "--require-cohort-signoff-policy" "$require_cohort_signoff_policy"
bool_arg_or_die "--require-trend-artifact-policy-match" "$require_trend_artifact_policy_match"
bool_arg_or_die "--require-trend-wg-validate-udp-source" "$require_trend_wg_validate_udp_source"
bool_arg_or_die "--require-trend-wg-validate-strict-distinct" "$require_trend_wg_validate_strict_distinct"
bool_arg_or_die "--require-trend-wg-soak-diversity-pass" "$require_trend_wg_soak_diversity_pass"
bool_arg_or_die "--require-bundle-created" "$require_bundle_created"
bool_arg_or_die "--require-bundle-manifest" "$require_bundle_manifest"
bool_arg_or_die "--require-summary-json" "$require_summary_json"
bool_arg_or_die "--require-summary-status-ok" "$require_summary_status_ok"
bool_arg_or_die "--require-incident-snapshot-on-fail" "$require_incident_snapshot_on_fail"
bool_arg_or_die "--require-incident-snapshot-artifacts" "$require_incident_snapshot_artifacts"
bool_arg_or_die "--show-json" "$show_json"
if [[ ! "$max_duration_sec" =~ ^[0-9]+$ ]]; then
  echo "--max-duration-sec must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_trend_wg_soak_selection_lines" =~ ^[0-9]+$ ]]; then
  echo "--min-trend-wg-soak-selection-lines must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_trend_wg_soak_entry_operators" =~ ^[0-9]+$ ]]; then
  echo "--min-trend-wg-soak-entry-operators must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_trend_wg_soak_exit_operators" =~ ^[0-9]+$ ]]; then
  echo "--min-trend-wg-soak-exit-operators must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_trend_wg_soak_cross_operator_pairs" =~ ^[0-9]+$ ]]; then
  echo "--min-trend-wg-soak-cross-operator-pairs must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_go_rate_pct" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "--min-go-rate-pct must be a number >= 0"
  exit 2
fi
max_alert_severity="$(printf '%s' "$max_alert_severity" | tr '[:lower:]' '[:upper:]')"
if [[ "$max_alert_severity" != "OK" && "$max_alert_severity" != "WARN" && "$max_alert_severity" != "CRITICAL" ]]; then
  echo "--max-alert-severity must be OK, WARN, or CRITICAL"
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

if [[ "$require_cohort_signoff_policy" == "1" ]]; then
  if [[ -z "$summary_json" || ! -f "$summary_json" ]]; then
    errors+=("cannot validate cohort signoff policy because summary JSON is unavailable")
  elif [[ ! -x "$COHORT_CHECK_SCRIPT" ]]; then
    errors+=("cohort signoff policy checker is missing or not executable: $COHORT_CHECK_SCRIPT")
  else
    set +e
    cohort_policy_output="$(
      "$COHORT_CHECK_SCRIPT" \
        --summary-json "$summary_json" \
        --require-status-ok 1 \
        --require-all-rounds-ok 1 \
        --max-round-failures 0 \
        --require-trend-go 1 \
        --require-trend-artifact-policy-match "$require_trend_artifact_policy_match" \
        --require-trend-wg-validate-udp-source "$require_trend_wg_validate_udp_source" \
        --require-trend-wg-validate-strict-distinct "$require_trend_wg_validate_strict_distinct" \
        --require-trend-wg-soak-diversity-pass "$require_trend_wg_soak_diversity_pass" \
        --min-trend-wg-soak-selection-lines "$min_trend_wg_soak_selection_lines" \
        --min-trend-wg-soak-entry-operators "$min_trend_wg_soak_entry_operators" \
        --min-trend-wg-soak-exit-operators "$min_trend_wg_soak_exit_operators" \
        --min-trend-wg-soak-cross-operator-pairs "$min_trend_wg_soak_cross_operator_pairs" \
        --min-go-rate-pct "$min_go_rate_pct" \
        --max-alert-severity "$max_alert_severity" \
        --require-bundle-created "$require_bundle_created" \
        --require-bundle-manifest "$require_bundle_manifest" \
        --require-incident-snapshot-on-fail "$require_incident_snapshot_on_fail" \
        --require-incident-snapshot-artifacts "$require_incident_snapshot_artifacts" \
        --show-json 0 2>&1
    )"
    cohort_policy_rc=$?
    set -e
    if [[ "$cohort_policy_rc" -ne 0 ]]; then
      cohort_policy_reason="$(printf '%s\n' "$cohort_policy_output" | tail -n 1 | tr -s ' ')"
      errors+=("cohort signoff policy failed (cohort_check_rc=$cohort_policy_rc): ${cohort_policy_reason:-see cohort check output}")
    fi
  fi
fi

if [[ "$require_incident_snapshot_on_fail" == "1" || "$require_incident_snapshot_artifacts" == "1" ]]; then
  quick_failed=0
  if [[ "$status" != "ok" || "$final_rc" -ne 0 ]]; then
    quick_failed=1
  fi
  if [[ "$quick_failed" != "1" ]]; then
    :
  elif [[ -z "$summary_json" || ! -f "$summary_json" ]]; then
    errors+=("cannot validate incident snapshot policy because summary JSON is unavailable")
  elif [[ ! -x "$COHORT_CHECK_SCRIPT" ]]; then
    errors+=("cohort incident policy checker is missing or not executable: $COHORT_CHECK_SCRIPT")
  else
    set +e
    cohort_incident_output="$(
      "$COHORT_CHECK_SCRIPT" \
        --summary-json "$summary_json" \
        --require-status-ok 0 \
        --require-all-rounds-ok 0 \
        --max-round-failures 999999 \
        --require-trend-go 0 \
        --require-trend-artifact-policy-match 0 \
        --min-go-rate-pct 0 \
        --max-alert-severity CRITICAL \
        --require-bundle-created 0 \
        --require-bundle-manifest 0 \
        --require-incident-snapshot-on-fail "$require_incident_snapshot_on_fail" \
        --require-incident-snapshot-artifacts "$require_incident_snapshot_artifacts" \
        --show-json 0 2>&1
    )"
    cohort_incident_rc=$?
    set -e
    if [[ "$cohort_incident_rc" -ne 0 ]]; then
      cohort_incident_reason="$(printf '%s\n' "$cohort_incident_output" | tail -n 1 | tr -s ' ')"
      errors+=("incident snapshot policy failed (cohort_check_rc=$cohort_incident_rc): ${cohort_incident_reason:-see cohort check output}")
    fi
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
