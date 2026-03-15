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
    [--pre-real-host-readiness [0|1]] \
    [--pre-real-host-readiness-summary-json PATH] \
    [--rounds N] \
    [--pause-sec N] \
    [--continue-on-fail [0|1]] \
    [--require-all-rounds-ok [0|1]] \
    [--max-round-failures N] \
    [--trend-min-go-rate-pct N] \
    [--max-alert-severity OK|WARN|CRITICAL] \
    [--bundle-outputs [0|1]] \
    [--bundle-fail-close [0|1]] \
    [--reports-dir PATH] \
    [--summary-json PATH] \
    [--run-report-json PATH] \
    [--signoff-require-trend-artifact-policy-match [0|1]] \
    [--signoff-require-trend-wg-validate-udp-source [0|1]] \
    [--signoff-require-trend-wg-validate-strict-distinct [0|1]] \
    [--signoff-require-trend-wg-soak-diversity-pass [0|1]] \
    [--signoff-min-trend-wg-soak-selection-lines N] \
    [--signoff-min-trend-wg-soak-entry-operators N] \
    [--signoff-min-trend-wg-soak-exit-operators N] \
    [--signoff-min-trend-wg-soak-cross-operator-pairs N] \
    [--signoff-require-incident-snapshot-on-fail [0|1]] \
    [--signoff-require-incident-snapshot-artifacts [0|1]] \
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
pre_real_host_readiness="${PROD_PILOT_COHORT_QUICK_PRE_REAL_HOST_READINESS:-1}"
pre_real_host_readiness_summary_json="${PROD_PILOT_COHORT_QUICK_PRE_REAL_HOST_READINESS_SUMMARY_JSON:-}"
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
signoff_require_trend_artifact_policy_match="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_TREND_ARTIFACT_POLICY_MATCH:-1}"
signoff_require_trend_wg_validate_udp_source="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_TREND_WG_VALIDATE_UDP_SOURCE:-1}"
signoff_require_trend_wg_validate_strict_distinct="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_TREND_WG_VALIDATE_STRICT_DISTINCT:-1}"
signoff_require_trend_wg_soak_diversity_pass="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_TREND_WG_SOAK_DIVERSITY_PASS:-1}"
signoff_min_trend_wg_soak_selection_lines="${PROD_PILOT_COHORT_QUICK_SIGNOFF_MIN_TREND_WG_SOAK_SELECTION_LINES:-12}"
signoff_min_trend_wg_soak_entry_operators="${PROD_PILOT_COHORT_QUICK_SIGNOFF_MIN_TREND_WG_SOAK_ENTRY_OPERATORS:-2}"
signoff_min_trend_wg_soak_exit_operators="${PROD_PILOT_COHORT_QUICK_SIGNOFF_MIN_TREND_WG_SOAK_EXIT_OPERATORS:-2}"
signoff_min_trend_wg_soak_cross_operator_pairs="${PROD_PILOT_COHORT_QUICK_SIGNOFF_MIN_TREND_WG_SOAK_CROSS_OPERATOR_PAIRS:-2}"
signoff_require_incident_snapshot_on_fail="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-1}"
signoff_require_incident_snapshot_artifacts="${PROD_PILOT_COHORT_QUICK_SIGNOFF_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-1}"
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
    --pre-real-host-readiness)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        pre_real_host_readiness="${2:-}"
        shift 2
      else
        pre_real_host_readiness="1"
        shift
      fi
      ;;
    --pre-real-host-readiness-summary-json)
      pre_real_host_readiness_summary_json="${2:-}"
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
    --max-round-failures)
      max_round_failures="${2:-}"
      shift 2
      ;;
    --trend-min-go-rate-pct)
      trend_min_go_rate_pct="${2:-}"
      shift 2
      ;;
    --max-alert-severity)
      max_alert_severity="${2:-}"
      shift 2
      ;;
    --bundle-outputs)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        bundle_outputs="${2:-}"
        shift 2
      else
        bundle_outputs="1"
        shift
      fi
      ;;
    --bundle-fail-close)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        bundle_fail_close="${2:-}"
        shift 2
      else
        bundle_fail_close="1"
        shift
      fi
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
    --signoff-require-trend-artifact-policy-match)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_trend_artifact_policy_match="${2:-}"
        shift 2
      else
        signoff_require_trend_artifact_policy_match="1"
        shift
      fi
      ;;
    --signoff-require-trend-wg-validate-udp-source)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_trend_wg_validate_udp_source="${2:-}"
        shift 2
      else
        signoff_require_trend_wg_validate_udp_source="1"
        shift
      fi
      ;;
    --signoff-require-trend-wg-validate-strict-distinct)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_trend_wg_validate_strict_distinct="${2:-}"
        shift 2
      else
        signoff_require_trend_wg_validate_strict_distinct="1"
        shift
      fi
      ;;
    --signoff-require-trend-wg-soak-diversity-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_trend_wg_soak_diversity_pass="${2:-}"
        shift 2
      else
        signoff_require_trend_wg_soak_diversity_pass="1"
        shift
      fi
      ;;
    --signoff-min-trend-wg-soak-selection-lines)
      signoff_min_trend_wg_soak_selection_lines="${2:-}"
      shift 2
      ;;
    --signoff-min-trend-wg-soak-entry-operators)
      signoff_min_trend_wg_soak_entry_operators="${2:-}"
      shift 2
      ;;
    --signoff-min-trend-wg-soak-exit-operators)
      signoff_min_trend_wg_soak_exit_operators="${2:-}"
      shift 2
      ;;
    --signoff-min-trend-wg-soak-cross-operator-pairs)
      signoff_min_trend_wg_soak_cross_operator_pairs="${2:-}"
      shift 2
      ;;
    --signoff-require-incident-snapshot-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_incident_snapshot_on_fail="${2:-}"
        shift 2
      else
        signoff_require_incident_snapshot_on_fail="1"
        shift
      fi
      ;;
    --signoff-require-incident-snapshot-artifacts)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_incident_snapshot_artifacts="${2:-}"
        shift 2
      else
        signoff_require_incident_snapshot_artifacts="1"
        shift
      fi
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
bool_or_die "--pre-real-host-readiness" "$pre_real_host_readiness"
bool_or_die "--continue-on-fail" "$continue_on_fail"
bool_or_die "--require-all-rounds-ok" "$require_all_rounds_ok"
bool_or_die "--print-run-report" "$print_run_report"
bool_or_die "--show-json" "$show_json"
bool_or_die "--signoff-check-tar-sha256" "$signoff_check_tar_sha256"
bool_or_die "--signoff-check-manifest" "$signoff_check_manifest"
bool_or_die "--signoff-show-integrity-details" "$signoff_show_integrity_details"
bool_or_die "--signoff-require-trend-artifact-policy-match" "$signoff_require_trend_artifact_policy_match"
bool_or_die "--signoff-require-trend-wg-validate-udp-source" "$signoff_require_trend_wg_validate_udp_source"
bool_or_die "--signoff-require-trend-wg-validate-strict-distinct" "$signoff_require_trend_wg_validate_strict_distinct"
bool_or_die "--signoff-require-trend-wg-soak-diversity-pass" "$signoff_require_trend_wg_soak_diversity_pass"
bool_or_die "--signoff-require-incident-snapshot-on-fail" "$signoff_require_incident_snapshot_on_fail"
bool_or_die "--signoff-require-incident-snapshot-artifacts" "$signoff_require_incident_snapshot_artifacts"
int_or_die "--signoff-min-trend-wg-soak-selection-lines" "$signoff_min_trend_wg_soak_selection_lines"
int_or_die "--signoff-min-trend-wg-soak-entry-operators" "$signoff_min_trend_wg_soak_entry_operators"
int_or_die "--signoff-min-trend-wg-soak-exit-operators" "$signoff_min_trend_wg_soak_exit_operators"
int_or_die "--signoff-min-trend-wg-soak-cross-operator-pairs" "$signoff_min_trend_wg_soak_cross_operator_pairs"
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
if [[ -z "$pre_real_host_readiness_summary_json" ]]; then
  pre_real_host_readiness_summary_json="$reports_dir/pre_real_host_readiness_summary.json"
else
  pre_real_host_readiness_summary_json="$(abs_path "$pre_real_host_readiness_summary_json")"
fi

mkdir -p "$reports_dir" "$(dirname "$summary_json")" "$(dirname "$run_report_json")" "$(dirname "$pre_real_host_readiness_summary_json")"

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
  --pre-real-host-readiness "$pre_real_host_readiness"
  --pre-real-host-readiness-summary-json "$pre_real_host_readiness_summary_json"
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
    --require-trend-artifact-policy-match "$signoff_require_trend_artifact_policy_match"
    --require-trend-wg-validate-udp-source "$signoff_require_trend_wg_validate_udp_source"
    --require-trend-wg-validate-strict-distinct "$signoff_require_trend_wg_validate_strict_distinct"
    --require-trend-wg-soak-diversity-pass "$signoff_require_trend_wg_soak_diversity_pass"
    --min-trend-wg-soak-selection-lines "$signoff_min_trend_wg_soak_selection_lines"
    --min-trend-wg-soak-entry-operators "$signoff_min_trend_wg_soak_entry_operators"
    --min-trend-wg-soak-exit-operators "$signoff_min_trend_wg_soak_exit_operators"
    --min-trend-wg-soak-cross-operator-pairs "$signoff_min_trend_wg_soak_cross_operator_pairs"
    --min-go-rate-pct "$trend_min_go_rate_pct"
    --max-alert-severity "$max_alert_severity"
    --require-bundle-created "$bundle_outputs"
    --require-bundle-manifest "$bundle_outputs"
    --require-incident-snapshot-on-fail "$signoff_require_incident_snapshot_on_fail"
    --require-incident-snapshot-artifacts "$signoff_require_incident_snapshot_artifacts"
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
  --arg pre_real_host_readiness_summary_json "$pre_real_host_readiness_summary_json" \
  --arg bootstrap_directory "$bootstrap_directory" \
  --arg subject "$subject" \
  --arg max_alert_severity "$max_alert_severity" \
  --argjson rounds "$rounds" \
  --argjson pause_sec "$pause_sec" \
  --argjson continue_on_fail "$(json_bool "$continue_on_fail")" \
  --argjson require_all_rounds_ok "$(json_bool "$require_all_rounds_ok")" \
  --argjson max_round_failures "$max_round_failures" \
  --argjson trend_min_go_rate_pct "$trend_min_go_rate_pct" \
  --argjson bundle_outputs "$(json_bool "$bundle_outputs")" \
  --argjson bundle_fail_close "$(json_bool "$bundle_fail_close")" \
  --argjson runbook_rc "$runbook_rc" \
  --argjson signoff_attempted "$(json_bool "$signoff_attempted")" \
  --argjson signoff_rc "$signoff_rc" \
  --argjson final_rc "$final_rc" \
  --argjson duration_sec "$duration_sec" \
  --argjson pre_real_host_readiness "$(json_bool "$pre_real_host_readiness")" \
  --argjson signoff_check_tar_sha256 "$(json_bool "$signoff_check_tar_sha256")" \
  --argjson signoff_check_manifest "$(json_bool "$signoff_check_manifest")" \
  --argjson signoff_show_integrity_details "$(json_bool "$signoff_show_integrity_details")" \
  --argjson signoff_require_trend_artifact_policy_match "$(json_bool "$signoff_require_trend_artifact_policy_match")" \
  --argjson signoff_require_trend_wg_validate_udp_source "$(json_bool "$signoff_require_trend_wg_validate_udp_source")" \
  --argjson signoff_require_trend_wg_validate_strict_distinct "$(json_bool "$signoff_require_trend_wg_validate_strict_distinct")" \
  --argjson signoff_require_trend_wg_soak_diversity_pass "$(json_bool "$signoff_require_trend_wg_soak_diversity_pass")" \
  --argjson signoff_min_trend_wg_soak_selection_lines "$signoff_min_trend_wg_soak_selection_lines" \
  --argjson signoff_min_trend_wg_soak_entry_operators "$signoff_min_trend_wg_soak_entry_operators" \
  --argjson signoff_min_trend_wg_soak_exit_operators "$signoff_min_trend_wg_soak_exit_operators" \
  --argjson signoff_min_trend_wg_soak_cross_operator_pairs "$signoff_min_trend_wg_soak_cross_operator_pairs" \
  --argjson signoff_require_incident_snapshot_on_fail "$(json_bool "$signoff_require_incident_snapshot_on_fail")" \
  --argjson signoff_require_incident_snapshot_artifacts "$(json_bool "$signoff_require_incident_snapshot_artifacts")" \
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
      pre_real_host_readiness:$pre_real_host_readiness,
      rounds:$rounds,
      pause_sec:$pause_sec,
      continue_on_fail:$continue_on_fail,
      require_all_rounds_ok:$require_all_rounds_ok,
      max_round_failures:$max_round_failures,
      trend_min_go_rate_pct:$trend_min_go_rate_pct,
      max_alert_severity:$max_alert_severity,
      bundle_outputs:$bundle_outputs,
      bundle_fail_close:$bundle_fail_close,
      signoff_check_tar_sha256:$signoff_check_tar_sha256,
      signoff_check_manifest:$signoff_check_manifest,
      signoff_show_integrity_details:$signoff_show_integrity_details,
      signoff_require_trend_artifact_policy_match:$signoff_require_trend_artifact_policy_match,
      signoff_require_trend_wg_validate_udp_source:$signoff_require_trend_wg_validate_udp_source,
      signoff_require_trend_wg_validate_strict_distinct:$signoff_require_trend_wg_validate_strict_distinct,
      signoff_require_trend_wg_soak_diversity_pass:$signoff_require_trend_wg_soak_diversity_pass,
      signoff_min_trend_wg_soak_selection_lines:$signoff_min_trend_wg_soak_selection_lines,
      signoff_min_trend_wg_soak_entry_operators:$signoff_min_trend_wg_soak_entry_operators,
      signoff_min_trend_wg_soak_exit_operators:$signoff_min_trend_wg_soak_exit_operators,
      signoff_min_trend_wg_soak_cross_operator_pairs:$signoff_min_trend_wg_soak_cross_operator_pairs,
      signoff_require_incident_snapshot_on_fail:$signoff_require_incident_snapshot_on_fail,
      signoff_require_incident_snapshot_artifacts:$signoff_require_incident_snapshot_artifacts
    },
    artifacts:{
      reports_dir:$reports_dir,
      summary_json:$summary_json,
      run_report_json:$run_report_json,
      pre_real_host_readiness_summary_json:$pre_real_host_readiness_summary_json
    }
  }' >"$run_report_json"

echo "[prod-pilot-cohort-quick] run_report_json=$run_report_json"
echo "[prod-pilot-cohort-quick] pre_real_host_readiness_summary_json=$pre_real_host_readiness_summary_json"
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
