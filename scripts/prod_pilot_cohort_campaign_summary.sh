#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_campaign_summary.sh \
    [--runbook-summary-json PATH] \
    [--reports-dir PATH] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-report [0|1]] \
    [--print-summary-json [0|1]] \
    [--fail-on-no-go [0|1]]

Purpose:
  Build one operator-facing campaign handoff report from quick-runbook artifacts.

Notes:
  - Recommended input: --runbook-summary-json from prod-pilot-cohort-campaign or
    prod-pilot-cohort-quick-runbook.
  - --reports-dir auto-resolves:
      <reports_dir>/prod_pilot_cohort_quick_runbook_summary.json
  - Outputs:
      1) machine-readable summary JSON
      2) concise markdown handoff report
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

json_string() {
  local file="$1"
  local expr="$2"
  if [[ -z "$file" || ! -f "$file" ]]; then
    printf '%s' ""
    return
  fi
  jq -r "$expr // \"\"" "$file" 2>/dev/null || true
}

json_int() {
  local file="$1"
  local expr="$2"
  local value
  value="$(json_string "$file" "$expr")"
  if [[ -z "$value" || ! "$value" =~ ^-?[0-9]+$ ]]; then
    echo "0"
    return
  fi
  echo "$value"
}

json_bool01() {
  local file="$1"
  local expr="$2"
  local value
  value="$(json_string "$file" "$expr")"
  case "$value" in
    true|1) echo "1" ;;
    false|0|"") echo "0" ;;
    *) echo "0" ;;
  esac
}

path_exists01() {
  local path
  path="$(trim "${1:-}")"
  if [[ -n "$path" && -e "$path" ]]; then
    echo "1"
  else
    echo "0"
  fi
}

json_valid01() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" || ! -f "$path" ]]; then
    echo "0"
    return
  fi
  if jq -e . "$path" >/dev/null 2>&1; then
    echo "1"
  else
    echo "0"
  fi
}

md_escape() {
  local value="$1"
  value="${value//|/\\|}"
  printf '%s' "$value"
}

artifact_line() {
  local label="$1"
  local path="$2"
  local exists="$3"
  local status="missing"
  if [[ "$exists" == "1" ]]; then
    status="present"
  fi
  printf -- '- %s: `%s` (%s)\n' "$label" "$(md_escape "${path:-}")" "$status"
}

runbook_summary_json=""
reports_dir=""
summary_json=""
report_md=""
print_report="${PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_PRINT_REPORT:-1}"
print_summary_json="${PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_PRINT_SUMMARY_JSON:-0}"
fail_on_no_go="${PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_FAIL_ON_NO_GO:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runbook-summary-json)
      runbook_summary_json="${2:-}"
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
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --print-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_report="${2:-}"
        shift 2
      else
        print_report="1"
        shift
      fi
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
    --fail-on-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_no_go="${2:-}"
        shift 2
      else
        fail_on_no_go="1"
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

for cmd in bash jq date; do
  need_cmd "$cmd"
done

bool_arg_or_die "--print-report" "$print_report"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"

reports_dir="$(abs_path "$reports_dir")"
runbook_summary_json="$(abs_path "$runbook_summary_json")"

if [[ -z "$runbook_summary_json" && -n "$reports_dir" ]]; then
  runbook_summary_json="$reports_dir/prod_pilot_cohort_quick_runbook_summary.json"
fi
if [[ -z "$runbook_summary_json" ]]; then
  echo "missing required input: --runbook-summary-json or --reports-dir"
  exit 2
fi
if [[ ! -f "$runbook_summary_json" ]]; then
  echo "runbook summary JSON not found: $runbook_summary_json"
  exit 1
fi
if ! jq -e . "$runbook_summary_json" >/dev/null 2>&1; then
  echo "runbook summary JSON is invalid: $runbook_summary_json"
  exit 1
fi

runbook_reports_dir="$(abs_path "$(json_string "$runbook_summary_json" '.artifacts.reports_dir')")"
if [[ -z "$runbook_reports_dir" ]]; then
  runbook_reports_dir="$(dirname "$runbook_summary_json")"
fi
if [[ -z "$reports_dir" ]]; then
  reports_dir="$runbook_reports_dir"
fi

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/prod_pilot_campaign_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$report_md" ]]; then
  report_md="$reports_dir/prod_pilot_campaign_summary.md"
else
  report_md="$(abs_path "$report_md")"
fi

quick_run_report_json="$(abs_path "$(json_string "$runbook_summary_json" '.artifacts.run_report_json')")"
cohort_summary_json="$(abs_path "$(json_string "$runbook_summary_json" '.artifacts.summary_json')")"
signoff_json="$(abs_path "$(json_string "$runbook_summary_json" '.artifacts.signoff_json')")"
trend_summary_json="$(abs_path "$(json_string "$runbook_summary_json" '.artifacts.trend_summary_json')")"
alert_summary_json="$(abs_path "$(json_string "$runbook_summary_json" '.artifacts.alert_summary_json')")"
dashboard_md="$(abs_path "$(json_string "$runbook_summary_json" '.artifacts.dashboard_md')")"

if [[ -z "$quick_run_report_json" ]]; then
  quick_run_report_json="$reports_dir/prod_pilot_cohort_quick_report.json"
fi
if [[ -z "$cohort_summary_json" ]]; then
  cohort_summary_json="$reports_dir/prod_pilot_cohort_summary.json"
fi
if [[ -z "$signoff_json" ]]; then
  signoff_json="$reports_dir/prod_pilot_quick_signoff.json"
fi
if [[ -z "$trend_summary_json" ]]; then
  trend_summary_json="$reports_dir/prod_pilot_quick_signoff_trend.json"
fi
if [[ -z "$alert_summary_json" ]]; then
  alert_summary_json="$reports_dir/prod_pilot_quick_signoff_alert.json"
fi
if [[ -z "$dashboard_md" ]]; then
  dashboard_md="$reports_dir/prod_pilot_quick_dashboard.md"
fi

runbook_status="$(json_string "$runbook_summary_json" '.status')"
runbook_failure_step="$(json_string "$runbook_summary_json" '.failure_step')"
runbook_final_rc="$(json_int "$runbook_summary_json" '.final_rc')"
runbook_duration_sec="$(json_int "$runbook_summary_json" '.duration_sec')"
runbook_quick_rc="$(json_int "$runbook_summary_json" '.stages.quick.rc')"
runbook_quick_signoff_rc="$(json_int "$runbook_summary_json" '.stages.quick_signoff.rc')"
runbook_quick_dashboard_rc="$(json_int "$runbook_summary_json" '.stages.quick_dashboard.rc')"
campaign_rounds="$(json_int "$runbook_summary_json" '.config.rounds')"
campaign_pause_sec="$(json_int "$runbook_summary_json" '.config.pause_sec')"
max_alert_severity="$(json_string "$runbook_summary_json" '.config.max_alert_severity')"

quick_status="$(json_string "$quick_run_report_json" '.status')"
quick_failure_step="$(json_string "$quick_run_report_json" '.failure_step')"
quick_final_rc="$(json_int "$quick_run_report_json" '.final_rc')"
quick_signoff_attempted="$(json_bool01 "$quick_run_report_json" '.signoff.attempted')"
quick_signoff_rc="$(json_int "$quick_run_report_json" '.signoff.rc')"
bootstrap_directory="$(json_string "$quick_run_report_json" '.config.bootstrap_directory')"
subject="$(json_string "$quick_run_report_json" '.config.subject')"

cohort_status="$(json_string "$cohort_summary_json" '.status')"
cohort_final_rc="$(json_int "$cohort_summary_json" '.final_rc')"
cohort_rounds_requested="$(json_int "$cohort_summary_json" '.rounds.requested')"
cohort_rounds_attempted="$(json_int "$cohort_summary_json" '.rounds.attempted')"
cohort_rounds_passed="$(json_int "$cohort_summary_json" '.rounds.passed')"
cohort_rounds_failed="$(json_int "$cohort_summary_json" '.rounds.failed')"
cohort_bundle_created="$(json_bool01 "$cohort_summary_json" '.bundle.created')"
cohort_bundle_manifest_created="$(json_bool01 "$cohort_summary_json" '.bundle.manifest_created')"
cohort_bundle_tar="$(abs_path "$(json_string "$cohort_summary_json" '.artifacts.bundle_tar')")"
cohort_bundle_manifest_json="$(abs_path "$(json_string "$cohort_summary_json" '.artifacts.bundle_manifest_json')")"

signoff_status="$(json_string "$signoff_json" '.status')"
signoff_failure_step="$(json_string "$signoff_json" '.failure_step')"
signoff_final_rc="$(json_int "$signoff_json" '.final_rc')"
alert_severity="$(json_string "$signoff_json" '.observed.alert_severity')"

trend_decision="$(json_string "$trend_summary_json" '.decision')"
trend_go_rate_pct="$(json_string "$trend_summary_json" '.go_rate_pct')"
trend_no_go="$(json_int "$trend_summary_json" '.no_go')"
trend_eval_errors="$(json_int "$trend_summary_json" '.evaluation_errors')"
top_no_go_reason="$(json_string "$trend_summary_json" '.top_no_go_reasons[0].reason')"
if [[ -z "$alert_severity" ]]; then
  alert_severity="$(json_string "$alert_summary_json" '.severity')"
fi
if [[ -z "$top_no_go_reason" ]]; then
  top_no_go_reason="$(json_string "$alert_summary_json" '.trigger_reasons[0]')"
fi

runbook_summary_exists="1"
quick_run_report_exists="$(path_exists01 "$quick_run_report_json")"
cohort_summary_exists="$(path_exists01 "$cohort_summary_json")"
signoff_json_exists="$(path_exists01 "$signoff_json")"
trend_summary_exists="$(path_exists01 "$trend_summary_json")"
alert_summary_exists="$(path_exists01 "$alert_summary_json")"
dashboard_md_exists="$(path_exists01 "$dashboard_md")"
bundle_tar_exists="$(path_exists01 "$cohort_bundle_tar")"
bundle_manifest_exists="$(path_exists01 "$cohort_bundle_manifest_json")"
runbook_summary_valid_json="1"
quick_run_report_valid_json="$(json_valid01 "$quick_run_report_json")"
cohort_summary_valid_json="$(json_valid01 "$cohort_summary_json")"
signoff_json_valid_json="$(json_valid01 "$signoff_json")"
trend_summary_valid_json="$(json_valid01 "$trend_summary_json")"
alert_summary_valid_json="$(json_valid01 "$alert_summary_json")"
bundle_manifest_valid_json="$(json_valid01 "$cohort_bundle_manifest_json")"

declare -a missing_required_artifacts=()
if [[ "$quick_run_report_exists" != "1" ]]; then
  missing_required_artifacts+=("quick_run_report_json")
fi
if [[ "$cohort_summary_exists" != "1" ]]; then
  missing_required_artifacts+=("cohort_summary_json")
fi
if [[ "$signoff_json_exists" != "1" ]]; then
  missing_required_artifacts+=("signoff_json")
fi
if [[ "$trend_summary_exists" != "1" ]]; then
  missing_required_artifacts+=("trend_summary_json")
fi
if [[ "$alert_summary_exists" != "1" ]]; then
  missing_required_artifacts+=("alert_summary_json")
fi

declare -a invalid_required_artifacts=()
if [[ "$quick_run_report_exists" == "1" && "$quick_run_report_valid_json" != "1" ]]; then
  invalid_required_artifacts+=("quick_run_report_json")
fi
if [[ "$cohort_summary_exists" == "1" && "$cohort_summary_valid_json" != "1" ]]; then
  invalid_required_artifacts+=("cohort_summary_json")
fi
if [[ "$signoff_json_exists" == "1" && "$signoff_json_valid_json" != "1" ]]; then
  invalid_required_artifacts+=("signoff_json")
fi
if [[ "$trend_summary_exists" == "1" && "$trend_summary_valid_json" != "1" ]]; then
  invalid_required_artifacts+=("trend_summary_json")
fi
if [[ "$alert_summary_exists" == "1" && "$alert_summary_valid_json" != "1" ]]; then
  invalid_required_artifacts+=("alert_summary_json")
fi

missing_required_artifacts_json='[]'
if ((${#missing_required_artifacts[@]} > 0)); then
  missing_required_artifacts_json="$(printf '%s\n' "${missing_required_artifacts[@]}" | jq -R . | jq -s .)"
fi

invalid_required_artifacts_json='[]'
if ((${#invalid_required_artifacts[@]} > 0)); then
  invalid_required_artifacts_json="$(printf '%s\n' "${invalid_required_artifacts[@]}" | jq -R . | jq -s .)"
fi

decision="GO"
decision_reason="all required campaign gates passed"
if [[ "$runbook_status" != "ok" ]]; then
  decision="NO-GO"
  decision_reason="campaign runbook status=$runbook_status"
elif ((${#missing_required_artifacts[@]} > 0)); then
  decision="NO-GO"
  decision_reason="missing required artifacts: ${missing_required_artifacts[*]}"
elif ((${#invalid_required_artifacts[@]} > 0)); then
  decision="NO-GO"
  decision_reason="invalid required JSON artifacts: ${invalid_required_artifacts[*]}"
elif [[ -n "$quick_status" && "$quick_status" != "ok" ]]; then
  decision="NO-GO"
  decision_reason="quick execution status=$quick_status"
elif [[ -n "$signoff_status" && "$signoff_status" != "ok" ]]; then
  decision="NO-GO"
  decision_reason="quick signoff status=$signoff_status"
elif [[ -n "$cohort_status" && "$cohort_status" != "ok" ]]; then
  decision="NO-GO"
  decision_reason="cohort summary status=$cohort_status"
elif [[ -n "$trend_decision" && "$trend_decision" != "GO" ]]; then
  decision="NO-GO"
  decision_reason="trend decision=$trend_decision"
fi

mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

jq -nc \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg decision "$decision" \
  --arg decision_reason "$decision_reason" \
  --arg runbook_summary_json "$runbook_summary_json" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --arg reports_dir "$reports_dir" \
  --arg bootstrap_directory "$bootstrap_directory" \
  --arg subject "$subject" \
  --arg runbook_status "$runbook_status" \
  --arg runbook_failure_step "$runbook_failure_step" \
  --arg quick_status "$quick_status" \
  --arg quick_failure_step "$quick_failure_step" \
  --arg cohort_status "$cohort_status" \
  --arg signoff_status "$signoff_status" \
  --arg signoff_failure_step "$signoff_failure_step" \
  --arg trend_decision "$trend_decision" \
  --arg trend_go_rate_pct "$trend_go_rate_pct" \
  --arg alert_severity "$alert_severity" \
  --arg top_no_go_reason "$top_no_go_reason" \
  --arg max_alert_severity "$max_alert_severity" \
  --arg quick_run_report_json "$quick_run_report_json" \
  --arg cohort_summary_json "$cohort_summary_json" \
  --arg signoff_json "$signoff_json" \
  --arg trend_summary_json "$trend_summary_json" \
  --arg alert_summary_json "$alert_summary_json" \
  --arg dashboard_md "$dashboard_md" \
  --arg cohort_bundle_tar "$cohort_bundle_tar" \
  --arg cohort_bundle_manifest_json "$cohort_bundle_manifest_json" \
  --argjson runbook_final_rc "$runbook_final_rc" \
  --argjson runbook_duration_sec "$runbook_duration_sec" \
  --argjson runbook_quick_rc "$runbook_quick_rc" \
  --argjson runbook_quick_signoff_rc "$runbook_quick_signoff_rc" \
  --argjson runbook_quick_dashboard_rc "$runbook_quick_dashboard_rc" \
  --argjson campaign_rounds "$campaign_rounds" \
  --argjson campaign_pause_sec "$campaign_pause_sec" \
  --argjson quick_final_rc "$quick_final_rc" \
  --argjson quick_signoff_attempted "$quick_signoff_attempted" \
  --argjson quick_signoff_rc "$quick_signoff_rc" \
  --argjson cohort_final_rc "$cohort_final_rc" \
  --argjson cohort_rounds_requested "$cohort_rounds_requested" \
  --argjson cohort_rounds_attempted "$cohort_rounds_attempted" \
  --argjson cohort_rounds_passed "$cohort_rounds_passed" \
  --argjson cohort_rounds_failed "$cohort_rounds_failed" \
  --argjson cohort_bundle_created "$cohort_bundle_created" \
  --argjson cohort_bundle_manifest_created "$cohort_bundle_manifest_created" \
  --argjson signoff_final_rc "$signoff_final_rc" \
  --argjson trend_no_go "$trend_no_go" \
  --argjson trend_eval_errors "$trend_eval_errors" \
  --argjson runbook_summary_exists "$runbook_summary_exists" \
  --argjson runbook_summary_valid_json "$runbook_summary_valid_json" \
  --argjson quick_run_report_exists "$quick_run_report_exists" \
  --argjson quick_run_report_valid_json "$quick_run_report_valid_json" \
  --argjson cohort_summary_exists "$cohort_summary_exists" \
  --argjson cohort_summary_valid_json "$cohort_summary_valid_json" \
  --argjson signoff_json_exists "$signoff_json_exists" \
  --argjson signoff_json_valid_json "$signoff_json_valid_json" \
  --argjson trend_summary_exists "$trend_summary_exists" \
  --argjson trend_summary_valid_json "$trend_summary_valid_json" \
  --argjson alert_summary_exists "$alert_summary_exists" \
  --argjson alert_summary_valid_json "$alert_summary_valid_json" \
  --argjson dashboard_md_exists "$dashboard_md_exists" \
  --argjson bundle_tar_exists "$bundle_tar_exists" \
  --argjson bundle_manifest_exists "$bundle_manifest_exists" \
  --argjson bundle_manifest_valid_json "$bundle_manifest_valid_json" \
  --argjson missing_required_artifacts "$missing_required_artifacts_json" \
  --argjson invalid_required_artifacts "$invalid_required_artifacts_json" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    decision: $decision,
    decision_reason: $decision_reason,
    campaign: {
      bootstrap_directory: ($bootstrap_directory // ""),
      subject: ($subject // ""),
      rounds: $campaign_rounds,
      pause_sec: $campaign_pause_sec,
      max_alert_severity: ($max_alert_severity // "")
    },
    runbook: {
      status: ($runbook_status // ""),
      failure_step: ($runbook_failure_step // ""),
      final_rc: $runbook_final_rc,
      duration_sec: $runbook_duration_sec,
      stages: {
        quick_rc: $runbook_quick_rc,
        quick_signoff_rc: $runbook_quick_signoff_rc,
        quick_dashboard_rc: $runbook_quick_dashboard_rc
      }
    },
    quick: {
      status: ($quick_status // ""),
      failure_step: ($quick_failure_step // ""),
      final_rc: $quick_final_rc,
      signoff_attempted: $quick_signoff_attempted,
      signoff_rc: $quick_signoff_rc
    },
    cohort: {
      status: ($cohort_status // ""),
      final_rc: $cohort_final_rc,
      rounds: {
        requested: $cohort_rounds_requested,
        attempted: $cohort_rounds_attempted,
        passed: $cohort_rounds_passed,
        failed: $cohort_rounds_failed
      },
      bundle: {
        created: $cohort_bundle_created,
        manifest_created: $cohort_bundle_manifest_created
      }
    },
    signoff: {
      status: ($signoff_status // ""),
      failure_step: ($signoff_failure_step // ""),
      final_rc: $signoff_final_rc,
      alert_severity: ($alert_severity // "")
    },
    trend: {
      decision: ($trend_decision // ""),
      go_rate_pct: ($trend_go_rate_pct // ""),
      no_go: $trend_no_go,
      evaluation_errors: $trend_eval_errors,
      top_no_go_reason: ($top_no_go_reason // "")
    },
    artifacts: {
      reports_dir: {path: $reports_dir, exists: true},
      runbook_summary_json: {path: $runbook_summary_json, exists: $runbook_summary_exists, valid_json: $runbook_summary_valid_json},
      quick_run_report_json: {path: $quick_run_report_json, exists: $quick_run_report_exists, valid_json: $quick_run_report_valid_json},
      cohort_summary_json: {path: $cohort_summary_json, exists: $cohort_summary_exists, valid_json: $cohort_summary_valid_json},
      signoff_json: {path: $signoff_json, exists: $signoff_json_exists, valid_json: $signoff_json_valid_json},
      trend_summary_json: {path: $trend_summary_json, exists: $trend_summary_exists, valid_json: $trend_summary_valid_json},
      alert_summary_json: {path: $alert_summary_json, exists: $alert_summary_exists, valid_json: $alert_summary_valid_json},
      dashboard_md: {path: $dashboard_md, exists: $dashboard_md_exists},
      bundle_tar: {path: $cohort_bundle_tar, exists: $bundle_tar_exists},
      bundle_manifest_json: {path: $cohort_bundle_manifest_json, exists: $bundle_manifest_exists, valid_json: $bundle_manifest_valid_json},
      campaign_summary_json: {path: $summary_json, exists: true},
      campaign_report_md: {path: $report_md, exists: true}
    },
    missing_required_artifacts: $missing_required_artifacts,
    invalid_required_artifacts: $invalid_required_artifacts
  }' >"$summary_json"

{
  printf '# PROD Pilot Campaign Summary\n\n'
  printf -- '- Decision: %s\n' "$decision"
  printf -- '- Reason: %s\n' "$(md_escape "$decision_reason")"
  printf -- '- Runbook status: %s\n' "${runbook_status:-unknown}"
  printf -- '- Runbook failure step: %s\n' "${runbook_failure_step:-none}"
  printf -- '- Final rc: %s\n' "$runbook_final_rc"
  printf -- '- Bootstrap directory: `%s`\n' "$(md_escape "${bootstrap_directory:-}")"
  printf -- '- Subject: `%s`\n' "$(md_escape "${subject:-}")"
  printf -- '- Duration sec: %s\n' "$runbook_duration_sec"
  printf -- '- Campaign config: rounds=%s pause_sec=%s max_alert_severity=%s\n' "$campaign_rounds" "$campaign_pause_sec" "${max_alert_severity:-}"
  printf -- '- Quick status: %s (rc=%s signoff_attempted=%s signoff_rc=%s)\n' "${quick_status:-unknown}" "$quick_final_rc" "$quick_signoff_attempted" "$quick_signoff_rc"
  printf -- '- Cohort status: %s (requested=%s attempted=%s passed=%s failed=%s)\n' "${cohort_status:-unknown}" "$cohort_rounds_requested" "$cohort_rounds_attempted" "$cohort_rounds_passed" "$cohort_rounds_failed"
  printf -- '- Trend: decision=%s go_rate_pct=%s no_go=%s evaluation_errors=%s\n' "${trend_decision:-}" "${trend_go_rate_pct:-}" "$trend_no_go" "$trend_eval_errors"
  printf -- '- Alert severity: %s\n' "${alert_severity:-}"
  printf -- '- Top NO-GO reason: %s\n' "$(md_escape "${top_no_go_reason:-n/a}")"
  printf -- '- Bundle created: %s\n' "$cohort_bundle_created"
  printf -- '- Bundle manifest created: %s\n' "$cohort_bundle_manifest_created"
  if ((${#missing_required_artifacts[@]} > 0)); then
    printf -- '- Missing required artifacts: %s\n' "$(md_escape "${missing_required_artifacts[*]}")"
  else
    printf -- '- Missing required artifacts: none\n'
  fi
  if ((${#invalid_required_artifacts[@]} > 0)); then
    printf -- '- Invalid required JSON artifacts: %s\n' "$(md_escape "${invalid_required_artifacts[*]}")"
  else
    printf -- '- Invalid required JSON artifacts: none\n'
  fi
  printf '\n## Artifacts\n\n'
  artifact_line "Reports dir" "$reports_dir" "1"
  artifact_line "Runbook summary JSON" "$runbook_summary_json" "$runbook_summary_exists"
  artifact_line "Quick run report JSON" "$quick_run_report_json" "$quick_run_report_exists"
  artifact_line "Cohort summary JSON" "$cohort_summary_json" "$cohort_summary_exists"
  artifact_line "Quick signoff JSON" "$signoff_json" "$signoff_json_exists"
  artifact_line "Trend summary JSON" "$trend_summary_json" "$trend_summary_exists"
  artifact_line "Alert summary JSON" "$alert_summary_json" "$alert_summary_exists"
  artifact_line "Dashboard markdown" "$dashboard_md" "$dashboard_md_exists"
  artifact_line "Cohort bundle tar" "$cohort_bundle_tar" "$bundle_tar_exists"
  artifact_line "Cohort bundle manifest" "$cohort_bundle_manifest_json" "$bundle_manifest_exists"
  artifact_line "Campaign summary JSON" "$summary_json" "1"
  artifact_line "Campaign report markdown" "$report_md" "1"
} >"$report_md"

echo "[prod-pilot-cohort-campaign-summary] decision=$decision"
echo "[prod-pilot-cohort-campaign-summary] summary_json=$summary_json"
echo "[prod-pilot-cohort-campaign-summary] report_md=$report_md"

if [[ "$print_report" == "1" ]]; then
  cat "$report_md"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$fail_on_no_go" == "1" && "$decision" != "GO" ]]; then
  exit 1
fi
exit 0
