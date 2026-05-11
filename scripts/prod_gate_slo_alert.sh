#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TREND_SCRIPT="${PROD_GATE_SLO_TREND_SCRIPT:-$ROOT_DIR/scripts/prod_gate_slo_trend.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_gate_slo_alert.sh \
    [--trend-summary-json PATH] \
    [--run-report-json PATH]... \
    [--run-report-list FILE] \
    [--reports-dir DIR] \
    [--max-reports N] \
    [--since-hours N] \
    [--require-full-sequence [0|1]] \
    [--require-wg-validate-ok [0|1]] \
    [--require-wg-soak-ok [0|1]] \
    [--max-wg-soak-failed-rounds N] \
    [--require-preflight-ok [0|1]] \
    [--require-bundle-ok [0|1]] \
    [--require-integrity-ok [0|1]] \
    [--require-signoff-ok [0|1]] \
    [--require-incident-snapshot-on-fail [0|1]] \
    [--require-incident-snapshot-artifacts [0|1]] \
    [--require-wg-validate-udp-source [0|1]] \
    [--require-wg-validate-strict-distinct [0|1]] \
    [--require-wg-soak-diversity-pass [0|1]] \
    [--min-wg-soak-selection-lines N] \
    [--min-wg-soak-entry-operators N] \
    [--min-wg-soak-exit-operators N] \
    [--min-wg-soak-cross-operator-pairs N] \
    [--max-evidence-age-sec N] \
    [--warn-go-rate-pct N] \
    [--critical-go-rate-pct N] \
    [--warn-no-go-count N] \
    [--critical-no-go-count N] \
    [--warn-eval-errors N] \
    [--critical-eval-errors N] \
    [--fail-on-warn [0|1]] \
    [--fail-on-critical [0|1]] \
    [--show-top-reasons N] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Convert SLO trend metrics into alert severity (OK/WARN/CRITICAL).

Notes:
  - If --trend-summary-json is omitted, the script runs prod_gate_slo_trend.sh first.
  - Threshold defaults are tuned for operator warning/critical triage:
      warn-go-rate-pct=98, critical-go-rate-pct=90
      warn-no-go-count=1, critical-no-go-count=2
      warn-eval-errors=1, critical-eval-errors=2
  - Use --fail-on-warn and/or --fail-on-critical for fail-close automation exits.
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

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

is_non_negative_decimal() {
  local v="$1"
  [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

float_lt() {
  local left="$1"
  local right="$2"
  awk -v l="$left" -v r="$right" 'BEGIN { exit (l < r) ? 0 : 1 }'
}

float_gt() {
  local left="$1"
  local right="$2"
  awk -v l="$left" -v r="$right" 'BEGIN { exit (l > r) ? 0 : 1 }'
}

abs_path() {
  local path="$1"
  path="$(trim "$path")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" = /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

path_exists01() {
  local path="$1"
  if [[ -n "$path" && -e "$path" ]]; then
    echo "1"
  else
    echo "0"
  fi
}

json_valid01() {
  local path="$1"
  if [[ -n "$path" && -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    echo "1"
  else
    echo "0"
  fi
}

iso8601_utc_to_epoch() {
  local timestamp="$1"
  timestamp="$(trim "$timestamp")"
  if [[ ! "$timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    return 1
  fi
  jq -nr --arg ts "$timestamp" '$ts | fromdateiso8601 | floor' 2>/dev/null
}

json_policy_scalar() {
  local file="$1"
  local expr="$2"
  jq -r "$expr // \"\"" "$file" 2>/dev/null || true
}

trend_summary_json=""
run_report_list=""
reports_dir=""
max_reports="${PROD_GATE_SLO_TREND_MAX_REPORTS:-25}"
since_hours="${PROD_GATE_SLO_TREND_SINCE_HOURS:-0}"

require_full_sequence="${PROD_GATE_SLO_REQUIRE_FULL_SEQUENCE:-1}"
require_wg_validate_ok="${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_OK:-1}"
require_wg_soak_ok="${PROD_GATE_SLO_REQUIRE_WG_SOAK_OK:-1}"
max_wg_soak_failed_rounds="${PROD_GATE_SLO_MAX_WG_SOAK_FAILED_ROUNDS:-0}"
require_preflight_ok="${PROD_GATE_SLO_REQUIRE_PREFLIGHT_OK:-0}"
require_bundle_ok="${PROD_GATE_SLO_REQUIRE_BUNDLE_OK:-0}"
require_integrity_ok="${PROD_GATE_SLO_REQUIRE_INTEGRITY_OK:-0}"
require_signoff_ok="${PROD_GATE_SLO_REQUIRE_SIGNOFF_OK:-0}"
require_incident_snapshot_on_fail="${PROD_GATE_SLO_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-0}"
require_incident_snapshot_artifacts="${PROD_GATE_SLO_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-0}"
require_wg_validate_udp_source="${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_UDP_SOURCE:-0}"
require_wg_validate_strict_distinct="${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_STRICT_DISTINCT:-0}"
require_wg_soak_diversity_pass="${PROD_GATE_SLO_REQUIRE_WG_SOAK_DIVERSITY_PASS:-0}"
min_wg_soak_selection_lines="${PROD_GATE_SLO_MIN_WG_SOAK_SELECTION_LINES:-0}"
min_wg_soak_entry_operators="${PROD_GATE_SLO_MIN_WG_SOAK_ENTRY_OPERATORS:-0}"
min_wg_soak_exit_operators="${PROD_GATE_SLO_MIN_WG_SOAK_EXIT_OPERATORS:-0}"
min_wg_soak_cross_operator_pairs="${PROD_GATE_SLO_MIN_WG_SOAK_CROSS_OPERATOR_PAIRS:-0}"
max_evidence_age_sec="${PROD_GATE_SLO_TREND_MAX_EVIDENCE_AGE_SEC:-${PROD_GATE_SLO_MAX_EVIDENCE_AGE_SEC:-0}}"
max_evidence_future_skew_sec="${PROD_GATE_SLO_ALERT_MAX_EVIDENCE_FUTURE_SKEW_SEC:-${PROD_GATE_SLO_MAX_EVIDENCE_FUTURE_SKEW_SEC:-300}}"
max_evidence_now_epoch="${PROD_GATE_SLO_ALERT_NOW_EPOCH:-${PROD_GATE_SLO_TREND_NOW_EPOCH:-${PROD_GATE_SLO_NOW_EPOCH:-}}}"

warn_go_rate_pct="${PROD_GATE_SLO_ALERT_WARN_GO_RATE_PCT:-98}"
critical_go_rate_pct="${PROD_GATE_SLO_ALERT_CRITICAL_GO_RATE_PCT:-90}"
warn_no_go_count="${PROD_GATE_SLO_ALERT_WARN_NO_GO_COUNT:-1}"
critical_no_go_count="${PROD_GATE_SLO_ALERT_CRITICAL_NO_GO_COUNT:-2}"
warn_eval_errors="${PROD_GATE_SLO_ALERT_WARN_EVAL_ERRORS:-1}"
critical_eval_errors="${PROD_GATE_SLO_ALERT_CRITICAL_EVAL_ERRORS:-2}"

fail_on_warn="${PROD_GATE_SLO_ALERT_FAIL_ON_WARN:-0}"
fail_on_critical="${PROD_GATE_SLO_ALERT_FAIL_ON_CRITICAL:-0}"
show_top_reasons="${PROD_GATE_SLO_TREND_SHOW_TOP_REASONS:-5}"
summary_json=""
print_summary_json="${PROD_GATE_SLO_ALERT_PRINT_SUMMARY_JSON:-0}"

declare -a run_report_jsons=()

explicit_require_full_sequence=0
explicit_require_wg_validate_ok=0
explicit_require_wg_soak_ok=0
explicit_max_wg_soak_failed_rounds=0
explicit_require_preflight_ok=0
explicit_require_bundle_ok=0
explicit_require_integrity_ok=0
explicit_require_signoff_ok=0
explicit_require_incident_snapshot_on_fail=0
explicit_require_incident_snapshot_artifacts=0
explicit_require_wg_validate_udp_source=0
explicit_require_wg_validate_strict_distinct=0
explicit_require_wg_soak_diversity_pass=0
explicit_min_wg_soak_selection_lines=0
explicit_min_wg_soak_entry_operators=0
explicit_min_wg_soak_exit_operators=0
explicit_min_wg_soak_cross_operator_pairs=0
explicit_max_evidence_age_sec=0
[[ -n "${PROD_GATE_SLO_REQUIRE_FULL_SEQUENCE+x}" ]] && explicit_require_full_sequence=1
[[ -n "${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_OK+x}" ]] && explicit_require_wg_validate_ok=1
[[ -n "${PROD_GATE_SLO_REQUIRE_WG_SOAK_OK+x}" ]] && explicit_require_wg_soak_ok=1
[[ -n "${PROD_GATE_SLO_MAX_WG_SOAK_FAILED_ROUNDS+x}" ]] && explicit_max_wg_soak_failed_rounds=1
[[ -n "${PROD_GATE_SLO_REQUIRE_PREFLIGHT_OK+x}" ]] && explicit_require_preflight_ok=1
[[ -n "${PROD_GATE_SLO_REQUIRE_BUNDLE_OK+x}" ]] && explicit_require_bundle_ok=1
[[ -n "${PROD_GATE_SLO_REQUIRE_INTEGRITY_OK+x}" ]] && explicit_require_integrity_ok=1
[[ -n "${PROD_GATE_SLO_REQUIRE_SIGNOFF_OK+x}" ]] && explicit_require_signoff_ok=1
[[ -n "${PROD_GATE_SLO_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL+x}" ]] && explicit_require_incident_snapshot_on_fail=1
[[ -n "${PROD_GATE_SLO_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS+x}" ]] && explicit_require_incident_snapshot_artifacts=1
[[ -n "${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_UDP_SOURCE+x}" ]] && explicit_require_wg_validate_udp_source=1
[[ -n "${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_STRICT_DISTINCT+x}" ]] && explicit_require_wg_validate_strict_distinct=1
[[ -n "${PROD_GATE_SLO_REQUIRE_WG_SOAK_DIVERSITY_PASS+x}" ]] && explicit_require_wg_soak_diversity_pass=1
[[ -n "${PROD_GATE_SLO_MIN_WG_SOAK_SELECTION_LINES+x}" ]] && explicit_min_wg_soak_selection_lines=1
[[ -n "${PROD_GATE_SLO_MIN_WG_SOAK_ENTRY_OPERATORS+x}" ]] && explicit_min_wg_soak_entry_operators=1
[[ -n "${PROD_GATE_SLO_MIN_WG_SOAK_EXIT_OPERATORS+x}" ]] && explicit_min_wg_soak_exit_operators=1
[[ -n "${PROD_GATE_SLO_MIN_WG_SOAK_CROSS_OPERATOR_PAIRS+x}" ]] && explicit_min_wg_soak_cross_operator_pairs=1
[[ -n "${PROD_GATE_SLO_MAX_EVIDENCE_AGE_SEC+x}" || -n "${PROD_GATE_SLO_TREND_MAX_EVIDENCE_AGE_SEC+x}" ]] && explicit_max_evidence_age_sec=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --trend-summary-json)
      trend_summary_json="${2:-}"
      shift 2
      ;;
    --run-report-json)
      run_report_jsons+=("${2:-}")
      shift 2
      ;;
    --run-report-list)
      run_report_list="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --max-reports)
      max_reports="${2:-}"
      shift 2
      ;;
    --since-hours)
      since_hours="${2:-}"
      shift 2
      ;;
    --require-full-sequence)
      explicit_require_full_sequence=1
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_full_sequence="${2:-}"
        shift 2
      else
        require_full_sequence="1"
        shift
      fi
      ;;
    --require-wg-validate-ok)
      explicit_require_wg_validate_ok=1
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_ok="${2:-}"
        shift 2
      else
        require_wg_validate_ok="1"
        shift
      fi
      ;;
    --require-wg-soak-ok)
      explicit_require_wg_soak_ok=1
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_soak_ok="${2:-}"
        shift 2
      else
        require_wg_soak_ok="1"
        shift
      fi
      ;;
    --max-wg-soak-failed-rounds)
      explicit_max_wg_soak_failed_rounds=1
      max_wg_soak_failed_rounds="${2:-}"
      shift 2
      ;;
    --require-preflight-ok)
      explicit_require_preflight_ok=1
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_preflight_ok="${2:-}"
        shift 2
      else
        require_preflight_ok="1"
        shift
      fi
      ;;
    --require-bundle-ok)
      explicit_require_bundle_ok=1
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_bundle_ok="${2:-}"
        shift 2
      else
        require_bundle_ok="1"
        shift
      fi
      ;;
    --require-integrity-ok)
      explicit_require_integrity_ok=1
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_integrity_ok="${2:-}"
        shift 2
      else
        require_integrity_ok="1"
        shift
      fi
      ;;
    --require-signoff-ok)
      explicit_require_signoff_ok=1
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_signoff_ok="${2:-}"
        shift 2
      else
        require_signoff_ok="1"
        shift
      fi
      ;;
    --require-incident-snapshot-on-fail)
      explicit_require_incident_snapshot_on_fail=1
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_incident_snapshot_on_fail="${2:-}"
        shift 2
      else
        require_incident_snapshot_on_fail="1"
        shift
      fi
      ;;
    --require-incident-snapshot-artifacts)
      explicit_require_incident_snapshot_artifacts=1
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_incident_snapshot_artifacts="${2:-}"
        shift 2
      else
        require_incident_snapshot_artifacts="1"
        shift
      fi
      ;;
    --require-wg-validate-udp-source)
      explicit_require_wg_validate_udp_source=1
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_udp_source="${2:-}"
        shift 2
      else
        require_wg_validate_udp_source="1"
        shift
      fi
      ;;
    --require-wg-validate-strict-distinct)
      explicit_require_wg_validate_strict_distinct=1
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_strict_distinct="${2:-}"
        shift 2
      else
        require_wg_validate_strict_distinct="1"
        shift
      fi
      ;;
    --require-wg-soak-diversity-pass)
      explicit_require_wg_soak_diversity_pass=1
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_soak_diversity_pass="${2:-}"
        shift 2
      else
        require_wg_soak_diversity_pass="1"
        shift
      fi
      ;;
    --min-wg-soak-selection-lines)
      explicit_min_wg_soak_selection_lines=1
      min_wg_soak_selection_lines="${2:-}"
      shift 2
      ;;
    --min-wg-soak-entry-operators)
      explicit_min_wg_soak_entry_operators=1
      min_wg_soak_entry_operators="${2:-}"
      shift 2
      ;;
    --min-wg-soak-exit-operators)
      explicit_min_wg_soak_exit_operators=1
      min_wg_soak_exit_operators="${2:-}"
      shift 2
      ;;
    --min-wg-soak-cross-operator-pairs)
      explicit_min_wg_soak_cross_operator_pairs=1
      min_wg_soak_cross_operator_pairs="${2:-}"
      shift 2
      ;;
    --max-evidence-age-sec)
      explicit_max_evidence_age_sec=1
      max_evidence_age_sec="${2:-}"
      shift 2
      ;;
    --warn-go-rate-pct)
      warn_go_rate_pct="${2:-}"
      shift 2
      ;;
    --critical-go-rate-pct)
      critical_go_rate_pct="${2:-}"
      shift 2
      ;;
    --warn-no-go-count)
      warn_no_go_count="${2:-}"
      shift 2
      ;;
    --critical-no-go-count)
      critical_no_go_count="${2:-}"
      shift 2
      ;;
    --warn-eval-errors)
      warn_eval_errors="${2:-}"
      shift 2
      ;;
    --critical-eval-errors)
      critical_eval_errors="${2:-}"
      shift 2
      ;;
    --fail-on-warn)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_warn="${2:-}"
        shift 2
      else
        fail_on_warn="1"
        shift
      fi
      ;;
    --fail-on-critical)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_critical="${2:-}"
        shift 2
      else
        fail_on_critical="1"
        shift
      fi
      ;;
    --show-top-reasons)
      show_top_reasons="${2:-}"
      shift 2
      ;;
    --summary-json)
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

for cmd in bash jq awk mktemp date; do
  need_cmd "$cmd"
done

if [[ ! -x "$TREND_SCRIPT" ]]; then
  echo "missing executable trend script: $TREND_SCRIPT"
  exit 2
fi

bool_arg_or_die "--require-full-sequence" "$require_full_sequence"
bool_arg_or_die "--require-wg-validate-ok" "$require_wg_validate_ok"
bool_arg_or_die "--require-wg-soak-ok" "$require_wg_soak_ok"
bool_arg_or_die "--require-preflight-ok" "$require_preflight_ok"
bool_arg_or_die "--require-bundle-ok" "$require_bundle_ok"
bool_arg_or_die "--require-integrity-ok" "$require_integrity_ok"
bool_arg_or_die "--require-signoff-ok" "$require_signoff_ok"
bool_arg_or_die "--require-incident-snapshot-on-fail" "$require_incident_snapshot_on_fail"
bool_arg_or_die "--require-incident-snapshot-artifacts" "$require_incident_snapshot_artifacts"
bool_arg_or_die "--require-wg-validate-udp-source" "$require_wg_validate_udp_source"
bool_arg_or_die "--require-wg-validate-strict-distinct" "$require_wg_validate_strict_distinct"
bool_arg_or_die "--require-wg-soak-diversity-pass" "$require_wg_soak_diversity_pass"
bool_arg_or_die "--fail-on-warn" "$fail_on_warn"
bool_arg_or_die "--fail-on-critical" "$fail_on_critical"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

if [[ ! "$max_reports" =~ ^[0-9]+$ ]] || ((max_reports < 1)); then
  echo "--max-reports must be an integer >= 1"
  exit 2
fi
if [[ ! "$since_hours" =~ ^[0-9]+$ ]]; then
  echo "--since-hours must be an integer >= 0"
  exit 2
fi
if [[ ! "$max_wg_soak_failed_rounds" =~ ^[0-9]+$ ]]; then
  echo "--max-wg-soak-failed-rounds must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_wg_soak_selection_lines" =~ ^[0-9]+$ ]]; then
  echo "--min-wg-soak-selection-lines must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_wg_soak_entry_operators" =~ ^[0-9]+$ ]]; then
  echo "--min-wg-soak-entry-operators must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_wg_soak_exit_operators" =~ ^[0-9]+$ ]]; then
  echo "--min-wg-soak-exit-operators must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_wg_soak_cross_operator_pairs" =~ ^[0-9]+$ ]]; then
  echo "--min-wg-soak-cross-operator-pairs must be an integer >= 0"
  exit 2
fi
if [[ ! "$max_evidence_age_sec" =~ ^[0-9]+$ ]]; then
  echo "--max-evidence-age-sec must be an integer >= 0"
  exit 2
fi
if [[ ! "$max_evidence_future_skew_sec" =~ ^[0-9]+$ ]]; then
  echo "PROD_GATE_SLO_ALERT_MAX_EVIDENCE_FUTURE_SKEW_SEC must be an integer >= 0"
  exit 2
fi
if [[ -n "$max_evidence_now_epoch" && ! "$max_evidence_now_epoch" =~ ^[0-9]+$ ]]; then
  echo "PROD_GATE_SLO_ALERT_NOW_EPOCH must be an integer >= 0"
  exit 2
fi
if [[ ! "$show_top_reasons" =~ ^[0-9]+$ ]]; then
  echo "--show-top-reasons must be an integer >= 0"
  exit 2
fi
for pct_name in warn_go_rate_pct critical_go_rate_pct; do
  pct_val="${!pct_name}"
  if ! is_non_negative_decimal "$pct_val"; then
    echo "--${pct_name//_/-} must be a number between 0 and 100"
    exit 2
  fi
  if float_gt "$pct_val" "100"; then
    echo "--${pct_name//_/-} must be <= 100"
    exit 2
  fi
done
for int_name in warn_no_go_count critical_no_go_count warn_eval_errors critical_eval_errors; do
  int_val="${!int_name}"
  if [[ ! "$int_val" =~ ^[0-9]+$ ]]; then
    echo "--${int_name//_/-} must be an integer >= 0"
    exit 2
  fi
done
if float_lt "$warn_go_rate_pct" "$critical_go_rate_pct"; then
  echo "--warn-go-rate-pct must be >= --critical-go-rate-pct"
  exit 2
fi
if ((critical_no_go_count < warn_no_go_count)); then
  echo "--critical-no-go-count must be >= --warn-no-go-count"
  exit 2
fi
if ((critical_eval_errors < warn_eval_errors)); then
  echo "--critical-eval-errors must be >= --warn-eval-errors"
  exit 2
fi

trend_summary_json="$(trim "$trend_summary_json")"
run_report_list="$(trim "$run_report_list")"
reports_dir="$(trim "$reports_dir")"
summary_json="$(trim "$summary_json")"

if [[ -n "$trend_summary_json" && "$trend_summary_json" != /* ]]; then
  trend_summary_json="$ROOT_DIR/$trend_summary_json"
fi
if [[ -n "$summary_json" && "$summary_json" != /* ]]; then
  summary_json="$ROOT_DIR/$summary_json"
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

trend_source="provided"
if [[ -z "$trend_summary_json" ]]; then
  trend_source="generated"
  trend_summary_json="$tmp_dir/generated_slo_trend_summary.json"
  declare -a trend_args=(
    --max-reports "$max_reports"
    --since-hours "$since_hours"
    --require-full-sequence "$require_full_sequence"
    --require-wg-validate-ok "$require_wg_validate_ok"
    --require-wg-soak-ok "$require_wg_soak_ok"
    --max-wg-soak-failed-rounds "$max_wg_soak_failed_rounds"
    --require-preflight-ok "$require_preflight_ok"
    --require-bundle-ok "$require_bundle_ok"
    --require-integrity-ok "$require_integrity_ok"
    --require-signoff-ok "$require_signoff_ok"
    --require-incident-snapshot-on-fail "$require_incident_snapshot_on_fail"
    --require-incident-snapshot-artifacts "$require_incident_snapshot_artifacts"
    --require-wg-validate-udp-source "$require_wg_validate_udp_source"
    --require-wg-validate-strict-distinct "$require_wg_validate_strict_distinct"
    --require-wg-soak-diversity-pass "$require_wg_soak_diversity_pass"
    --min-wg-soak-selection-lines "$min_wg_soak_selection_lines"
    --min-wg-soak-entry-operators "$min_wg_soak_entry_operators"
    --min-wg-soak-exit-operators "$min_wg_soak_exit_operators"
    --min-wg-soak-cross-operator-pairs "$min_wg_soak_cross_operator_pairs"
    --max-evidence-age-sec "$max_evidence_age_sec"
    --fail-on-any-no-go 0
    --min-go-rate-pct 0
    --show-details 0
    --show-top-reasons "$show_top_reasons"
    --summary-json "$trend_summary_json"
    --print-summary-json 0
  )
  if [[ -n "$run_report_list" ]]; then
    trend_args+=(--run-report-list "$run_report_list")
  fi
  if [[ -n "$reports_dir" ]]; then
    trend_args+=(--reports-dir "$reports_dir")
  fi
  for rr in "${run_report_jsons[@]}"; do
    rr="$(trim "$rr")"
    [[ -z "$rr" ]] && continue
    trend_args+=(--run-report-json "$rr")
  done

  "$TREND_SCRIPT" "${trend_args[@]}"
fi

if [[ ! -f "$trend_summary_json" ]]; then
  echo "trend summary JSON file not found: $trend_summary_json"
  exit 1
fi
if ! jq -e . "$trend_summary_json" >/dev/null 2>&1; then
  echo "trend summary JSON is not valid: $trend_summary_json"
  exit 1
fi

declare -a freshness_reasons=()
declare -a policy_reasons=()
declare -a integrity_reasons=()

if [[ "$trend_source" == "provided" ]]; then
  explicit_require_full_sequence=1
  explicit_require_wg_validate_ok=1
  explicit_require_wg_soak_ok=1
  explicit_max_wg_soak_failed_rounds=1
  explicit_require_preflight_ok=1
  explicit_require_bundle_ok=1
  explicit_require_integrity_ok=1
  explicit_require_signoff_ok=1
  explicit_require_incident_snapshot_on_fail=1
  explicit_require_incident_snapshot_artifacts=1
  explicit_require_wg_validate_udp_source=1
  explicit_require_wg_validate_strict_distinct=1
  explicit_require_wg_soak_diversity_pass=1
  explicit_min_wg_soak_selection_lines=1
  explicit_min_wg_soak_entry_operators=1
  explicit_min_wg_soak_exit_operators=1
  explicit_min_wg_soak_cross_operator_pairs=1
fi

trend_generated_at_utc="$(jq -r '.generated_at_utc // ""' "$trend_summary_json" 2>/dev/null || true)"
freshness_status="disabled"
freshness_age_sec=""
if ((max_evidence_age_sec > 0)); then
  freshness_status="ok"
  if [[ -n "$max_evidence_now_epoch" ]]; then
    freshness_now_epoch="$max_evidence_now_epoch"
  else
    freshness_now_epoch="$(date -u +%s)"
  fi
  if [[ -z "$trend_generated_at_utc" ]]; then
    freshness_status="fail"
    freshness_reasons+=("trend summary generated_at_utc timestamp missing while --max-evidence-age-sec is enabled")
  elif ! trend_generated_epoch="$(iso8601_utc_to_epoch "$trend_generated_at_utc" 2>/dev/null)"; then
    freshness_status="fail"
    freshness_reasons+=("trend summary generated_at_utc timestamp is invalid (value=$trend_generated_at_utc)")
  elif (( trend_generated_epoch > freshness_now_epoch + max_evidence_future_skew_sec )); then
    freshness_status="fail"
    freshness_age_sec="$((freshness_now_epoch - trend_generated_epoch))"
    freshness_reasons+=("trend summary generated_at_utc timestamp is too far in the future (value=$trend_generated_at_utc, future_skew_sec=$((trend_generated_epoch - freshness_now_epoch)))")
  else
    freshness_age_sec="$((freshness_now_epoch - trend_generated_epoch))"
    if (( freshness_age_sec > max_evidence_age_sec )); then
      freshness_status="fail"
      freshness_reasons+=("trend summary generated_at_utc timestamp is stale (value=$trend_generated_at_utc, age_sec=$freshness_age_sec, max_evidence_age_sec=$max_evidence_age_sec)")
    fi
  fi
  trend_runs_total="$(jq -r '.runs | if type == "array" then length else 0 end' "$trend_summary_json" 2>/dev/null || echo 0)"
  trend_reports_total_for_freshness="$(jq -r '.reports_total // 0' "$trend_summary_json" 2>/dev/null || echo 0)"
  if [[ "$trend_reports_total_for_freshness" =~ ^[0-9]+$ && "$trend_reports_total_for_freshness" -gt 0 && "$trend_runs_total" -eq 0 ]]; then
    freshness_status="fail"
    freshness_reasons+=("trend summary runs are missing while --max-evidence-age-sec is enabled")
  fi
  while IFS=$'\t' read -r run_idx run_timestamp run_path || [[ -n "${run_idx:-}" ]]; do
    [[ -z "${run_idx:-}" ]] && continue
    if [[ -z "$run_timestamp" ]]; then
      freshness_status="fail"
      freshness_reasons+=("trend summary run[$run_idx] generated_at_utc timestamp missing while --max-evidence-age-sec is enabled (path=${run_path:-unset})")
      continue
    fi
    if ! run_generated_epoch="$(iso8601_utc_to_epoch "$run_timestamp" 2>/dev/null)"; then
      freshness_status="fail"
      freshness_reasons+=("trend summary run[$run_idx] generated_at_utc timestamp is invalid (value=$run_timestamp, path=${run_path:-unset})")
      continue
    fi
    if (( run_generated_epoch > freshness_now_epoch + max_evidence_future_skew_sec )); then
      freshness_status="fail"
      freshness_reasons+=("trend summary run[$run_idx] generated_at_utc timestamp is too far in the future (value=$run_timestamp, future_skew_sec=$((run_generated_epoch - freshness_now_epoch)), path=${run_path:-unset})")
      continue
    fi
    run_age_sec="$((freshness_now_epoch - run_generated_epoch))"
    if (( run_age_sec > max_evidence_age_sec )); then
      freshness_status="fail"
      freshness_reasons+=("trend summary run[$run_idx] generated_at_utc timestamp is stale (value=$run_timestamp, age_sec=$run_age_sec, max_evidence_age_sec=$max_evidence_age_sec, path=${run_path:-unset})")
    fi
  done < <(
    jq -r '
      (.runs // [])
      | to_entries[]
      | [(.key + 1), (.value.generated_at_utc // ""), (.value.report_path // "")]
      | @tsv
    ' "$trend_summary_json" 2>/dev/null || true
  )
fi

check_policy_bool() {
  local explicit="$1"
  local field="$2"
  local requested="$3"
  local actual=""
  [[ "$explicit" != "1" || "$requested" != "1" ]] && return
  actual="$(json_policy_scalar "$trend_summary_json" ".policy.$field")"
  if [[ "$actual" != "1" && "$actual" != "true" ]]; then
    policy_reasons+=("trend policy $field does not satisfy alert request (trend=${actual:-missing}, required=1)")
  fi
}

check_policy_min() {
  local explicit="$1"
  local field="$2"
  local requested="$3"
  local actual=""
  [[ "$explicit" != "1" || "$requested" -eq 0 ]] && return
  actual="$(json_policy_scalar "$trend_summary_json" ".policy.$field")"
  if [[ ! "$actual" =~ ^[0-9]+$ ]]; then
    policy_reasons+=("trend policy $field does not satisfy alert request (trend=${actual:-missing}, required>=$requested)")
  elif (( actual < requested )); then
    policy_reasons+=("trend policy $field does not satisfy alert request (trend=$actual, required>=$requested)")
  fi
}

check_policy_max() {
  local explicit="$1"
  local field="$2"
  local requested="$3"
  local actual=""
  [[ "$explicit" != "1" ]] && return
  actual="$(json_policy_scalar "$trend_summary_json" ".policy.$field")"
  if [[ ! "$actual" =~ ^[0-9]+$ ]]; then
    policy_reasons+=("trend policy $field does not satisfy alert request (trend=${actual:-missing}, required<=$requested)")
  elif (( actual > requested )); then
    policy_reasons+=("trend policy $field does not satisfy alert request (trend=$actual, required<=$requested)")
  fi
}

check_policy_bool "$explicit_require_full_sequence" "require_full_sequence" "$require_full_sequence"
check_policy_bool "$explicit_require_wg_validate_ok" "require_wg_validate_ok" "$require_wg_validate_ok"
check_policy_bool "$explicit_require_wg_soak_ok" "require_wg_soak_ok" "$require_wg_soak_ok"
check_policy_max "$explicit_max_wg_soak_failed_rounds" "max_wg_soak_failed_rounds" "$max_wg_soak_failed_rounds"
check_policy_bool "$explicit_require_preflight_ok" "require_preflight_ok" "$require_preflight_ok"
check_policy_bool "$explicit_require_bundle_ok" "require_bundle_ok" "$require_bundle_ok"
check_policy_bool "$explicit_require_integrity_ok" "require_integrity_ok" "$require_integrity_ok"
check_policy_bool "$explicit_require_signoff_ok" "require_signoff_ok" "$require_signoff_ok"
check_policy_bool "$explicit_require_incident_snapshot_on_fail" "require_incident_snapshot_on_fail" "$require_incident_snapshot_on_fail"
check_policy_bool "$explicit_require_incident_snapshot_artifacts" "require_incident_snapshot_artifacts" "$require_incident_snapshot_artifacts"
check_policy_bool "$explicit_require_wg_validate_udp_source" "require_wg_validate_udp_source" "$require_wg_validate_udp_source"
check_policy_bool "$explicit_require_wg_validate_strict_distinct" "require_wg_validate_strict_distinct" "$require_wg_validate_strict_distinct"
check_policy_bool "$explicit_require_wg_soak_diversity_pass" "require_wg_soak_diversity_pass" "$require_wg_soak_diversity_pass"
check_policy_min "$explicit_min_wg_soak_selection_lines" "min_wg_soak_selection_lines" "$min_wg_soak_selection_lines"
check_policy_min "$explicit_min_wg_soak_entry_operators" "min_wg_soak_entry_operators" "$min_wg_soak_entry_operators"
check_policy_min "$explicit_min_wg_soak_exit_operators" "min_wg_soak_exit_operators" "$min_wg_soak_exit_operators"
check_policy_min "$explicit_min_wg_soak_cross_operator_pairs" "min_wg_soak_cross_operator_pairs" "$min_wg_soak_cross_operator_pairs"
if (( max_evidence_age_sec > 0 )); then
  trend_policy_max_evidence_age_sec="$(json_policy_scalar "$trend_summary_json" '.policy.max_evidence_age_sec // .filters.max_evidence_age_sec')"
  if [[ ! "$trend_policy_max_evidence_age_sec" =~ ^[0-9]+$ ]]; then
    policy_reasons+=("trend policy max_evidence_age_sec does not satisfy alert request (trend=${trend_policy_max_evidence_age_sec:-missing}, required<=$max_evidence_age_sec)")
  elif (( trend_policy_max_evidence_age_sec == 0 || trend_policy_max_evidence_age_sec > max_evidence_age_sec )); then
    policy_reasons+=("trend policy max_evidence_age_sec does not satisfy alert request (trend=$trend_policy_max_evidence_age_sec, required<=$max_evidence_age_sec)")
  fi
fi

check_filter_exact() {
  local field="$1"
  local requested="$2"
  local actual=""
  actual="$(json_policy_scalar "$trend_summary_json" ".filters.$field")"
  if [[ ! "$actual" =~ ^[0-9]+$ ]]; then
    policy_reasons+=("trend filter $field does not match alert request (trend=${actual:-missing}, required=$requested)")
  elif (( actual != requested )); then
    policy_reasons+=("trend filter $field does not match alert request (trend=$actual, required=$requested)")
  fi
}

if [[ "$trend_source" == "provided" ]]; then
  check_filter_exact "max_reports" "$max_reports"
  check_filter_exact "since_hours" "$since_hours"

  provided_reports_total_raw="$(jq -r '.reports_total // 0' "$trend_summary_json" 2>/dev/null || echo 0)"
  provided_go_raw="$(jq -r 'if has("go") then .go else "" end' "$trend_summary_json" 2>/dev/null || true)"
  provided_no_go_raw="$(jq -r '.no_go // 0' "$trend_summary_json" 2>/dev/null || echo 0)"
  provided_eval_errors_raw="$(jq -r '.evaluation_errors // 0' "$trend_summary_json" 2>/dev/null || echo 0)"
  provided_run_count="$(jq -r '(.runs // []) | if type == "array" then length else 0 end' "$trend_summary_json" 2>/dev/null || echo 0)"
  run_metrics="$(jq -r '
    (.runs // []) as $runs
    | [
        ($runs | length),
        ($runs | map(select(.decision == "GO")) | length),
        ($runs | map(select(.decision == "NO-GO")) | length),
        ($runs | map(select((.decision != "GO") and (.decision != "NO-GO"))) | length)
      ]
    | @tsv
  ' "$trend_summary_json" 2>/dev/null || printf '0\t0\t0\t0')"
  IFS=$'\t' read -r recomputed_run_count recomputed_run_go recomputed_run_no_go recomputed_run_invalid <<<"$run_metrics"
  if [[ ! "$provided_reports_total_raw" =~ ^[0-9]+$ ]]; then
    integrity_reasons+=("provided trend reports_total is invalid (value=${provided_reports_total_raw:-unset})")
    provided_reports_total_raw="0"
  fi
  if (( provided_reports_total_raw > 0 && provided_run_count == 0 )); then
    integrity_reasons+=("provided trend summary runs are missing while reports_total is nonzero")
  elif (( provided_run_count != provided_reports_total_raw )); then
    integrity_reasons+=("provided trend reports_total does not match runs length (reports_total=$provided_reports_total_raw, runs=$provided_run_count)")
  fi
  if [[ ! "$provided_go_raw" =~ ^[0-9]+$ ]]; then
    integrity_reasons+=("provided trend go count is missing or invalid")
  elif (( provided_go_raw != recomputed_run_go )); then
    integrity_reasons+=("provided trend go count does not match runs (trend=$provided_go_raw, runs=$recomputed_run_go)")
  fi
  if [[ ! "$provided_no_go_raw" =~ ^[0-9]+$ ]]; then
    integrity_reasons+=("provided trend no_go count is invalid (value=${provided_no_go_raw:-unset})")
  elif (( provided_no_go_raw != recomputed_run_no_go )); then
    integrity_reasons+=("provided trend no_go count does not match runs (trend=$provided_no_go_raw, runs=$recomputed_run_no_go)")
  fi
  if [[ ! "$provided_eval_errors_raw" =~ ^[0-9]+$ ]]; then
    integrity_reasons+=("provided trend evaluation_errors count is invalid (value=${provided_eval_errors_raw:-unset})")
  elif (( recomputed_run_invalid > 0 && provided_eval_errors_raw < recomputed_run_invalid )); then
    integrity_reasons+=("provided trend evaluation_errors count does not account for invalid run decisions (trend=$provided_eval_errors_raw, invalid_runs=$recomputed_run_invalid)")
  fi
  if (( recomputed_run_invalid > 0 )); then
    integrity_reasons+=("provided trend contains invalid run decisions (invalid_runs=$recomputed_run_invalid)")
  fi

  path_integrity_failed=0
  declare -a provided_run_paths=()
  while IFS=$'\t' read -r run_idx run_path || [[ -n "${run_idx:-}" ]]; do
    [[ -z "${run_idx:-}" ]] && continue
    run_path="$(trim "${run_path:-}")"
    if [[ -z "$run_path" ]]; then
      integrity_reasons+=("provided trend run[$run_idx] report_path is missing")
      path_integrity_failed=1
      continue
    fi
    run_path="$(abs_path "$run_path")"
    if [[ ! -f "$run_path" ]]; then
      integrity_reasons+=("provided trend run[$run_idx] report_path does not exist: $run_path")
      path_integrity_failed=1
      continue
    fi
    provided_run_paths+=("$run_path")
  done < <(
    jq -r '
      (.runs // [])
      | to_entries[]
      | [(.key + 1), (.value.report_path // "")]
      | @tsv
    ' "$trend_summary_json" 2>/dev/null || true
  )

  if (( provided_run_count > 0 && path_integrity_failed == 0 )); then
    recomputed_trend_json="$tmp_dir/recomputed_provided_trend_summary.json"
    declare -a recompute_args=(
      --max-reports "$provided_run_count"
      --since-hours 0
      --require-full-sequence "$require_full_sequence"
      --require-wg-validate-ok "$require_wg_validate_ok"
      --require-wg-soak-ok "$require_wg_soak_ok"
      --max-wg-soak-failed-rounds "$max_wg_soak_failed_rounds"
      --require-preflight-ok "$require_preflight_ok"
      --require-bundle-ok "$require_bundle_ok"
      --require-integrity-ok "$require_integrity_ok"
      --require-signoff-ok "$require_signoff_ok"
      --require-incident-snapshot-on-fail "$require_incident_snapshot_on_fail"
      --require-incident-snapshot-artifacts "$require_incident_snapshot_artifacts"
      --require-wg-validate-udp-source "$require_wg_validate_udp_source"
      --require-wg-validate-strict-distinct "$require_wg_validate_strict_distinct"
      --require-wg-soak-diversity-pass "$require_wg_soak_diversity_pass"
      --min-wg-soak-selection-lines "$min_wg_soak_selection_lines"
      --min-wg-soak-entry-operators "$min_wg_soak_entry_operators"
      --min-wg-soak-exit-operators "$min_wg_soak_exit_operators"
      --min-wg-soak-cross-operator-pairs "$min_wg_soak_cross_operator_pairs"
      --max-evidence-age-sec "$max_evidence_age_sec"
      --fail-on-any-no-go 0
      --min-go-rate-pct 0
      --show-details 0
      --show-top-reasons "$show_top_reasons"
      --summary-json "$recomputed_trend_json"
      --print-summary-json 0
    )
    for run_path in "${provided_run_paths[@]}"; do
      recompute_args+=(--run-report-json "$run_path")
    done
    set +e
    if [[ -n "$max_evidence_now_epoch" ]]; then
      PROD_GATE_SLO_TREND_NOW_EPOCH="$max_evidence_now_epoch" "$TREND_SCRIPT" "${recompute_args[@]}" >/dev/null 2>&1
    else
      "$TREND_SCRIPT" "${recompute_args[@]}" >/dev/null 2>&1
    fi
    recompute_rc=$?
    set -e
    if [[ ! -f "$recomputed_trend_json" ]] || ! jq -e . "$recomputed_trend_json" >/dev/null 2>&1; then
      integrity_reasons+=("provided trend could not be recomputed from source reports (rc=$recompute_rc)")
    else
      recomputed_reports_total="$(jq -r '.reports_total // 0' "$recomputed_trend_json")"
      recomputed_go="$(jq -r '.go // 0' "$recomputed_trend_json")"
      recomputed_no_go="$(jq -r '.no_go // 0' "$recomputed_trend_json")"
      recomputed_eval_errors="$(jq -r '.evaluation_errors // 0' "$recomputed_trend_json")"
      if [[ "$provided_reports_total_raw" != "$recomputed_reports_total" ]]; then
        integrity_reasons+=("provided trend reports_total does not match recomputed source reports (trend=$provided_reports_total_raw, recomputed=$recomputed_reports_total)")
      fi
      if [[ "$provided_go_raw" =~ ^[0-9]+$ && "$provided_go_raw" != "$recomputed_go" ]]; then
        integrity_reasons+=("provided trend go count does not match recomputed source reports (trend=$provided_go_raw, recomputed=$recomputed_go)")
      fi
      if [[ "$provided_no_go_raw" =~ ^[0-9]+$ && "$provided_no_go_raw" != "$recomputed_no_go" ]]; then
        integrity_reasons+=("provided trend no_go count does not match recomputed source reports (trend=$provided_no_go_raw, recomputed=$recomputed_no_go)")
      fi
      if [[ "$provided_eval_errors_raw" =~ ^[0-9]+$ && "$provided_eval_errors_raw" != "$recomputed_eval_errors" ]]; then
        integrity_reasons+=("provided trend evaluation_errors count does not match recomputed source reports (trend=$provided_eval_errors_raw, recomputed=$recomputed_eval_errors)")
      fi
    fi
  fi
fi

go_rate_pct="$(jq -r '.go_rate_pct // 0' "$trend_summary_json")"
no_go_count="$(jq -r '.no_go // 0' "$trend_summary_json")"
eval_errors="$(jq -r '.evaluation_errors // 0' "$trend_summary_json")"
reports_total="$(jq -r '.reports_total // 0' "$trend_summary_json")"
if ! is_non_negative_decimal "$go_rate_pct"; then
  go_rate_pct="0"
fi
if [[ ! "$no_go_count" =~ ^[0-9]+$ ]]; then
  no_go_count="0"
fi
if [[ ! "$eval_errors" =~ ^[0-9]+$ ]]; then
  eval_errors="0"
fi
if [[ ! "$reports_total" =~ ^[0-9]+$ ]]; then
  reports_total="0"
fi

severity="OK"
severity_rank=0
declare -a alert_reasons=()

for reason in "${freshness_reasons[@]}"; do
  severity="CRITICAL"
  severity_rank=2
  alert_reasons+=("$reason")
done
for reason in "${policy_reasons[@]}"; do
  severity="CRITICAL"
  severity_rank=2
  alert_reasons+=("$reason")
done
for reason in "${integrity_reasons[@]}"; do
  severity="CRITICAL"
  severity_rank=2
  alert_reasons+=("$reason")
done

if float_lt "$go_rate_pct" "$critical_go_rate_pct"; then
  severity="CRITICAL"
  severity_rank=2
  alert_reasons+=("go_rate_pct $go_rate_pct < critical_go_rate_pct $critical_go_rate_pct")
fi
if ((no_go_count >= critical_no_go_count)); then
  severity="CRITICAL"
  severity_rank=2
  alert_reasons+=("no_go_count $no_go_count >= critical_no_go_count $critical_no_go_count")
fi
if ((eval_errors >= critical_eval_errors)); then
  severity="CRITICAL"
  severity_rank=2
  alert_reasons+=("evaluation_errors $eval_errors >= critical_eval_errors $critical_eval_errors")
fi

if ((severity_rank < 2)); then
  if float_lt "$go_rate_pct" "$warn_go_rate_pct"; then
    severity="WARN"
    severity_rank=1
    alert_reasons+=("go_rate_pct $go_rate_pct < warn_go_rate_pct $warn_go_rate_pct")
  fi
  if ((no_go_count >= warn_no_go_count)); then
    severity="WARN"
    severity_rank=1
    alert_reasons+=("no_go_count $no_go_count >= warn_no_go_count $warn_no_go_count")
  fi
  if ((eval_errors >= warn_eval_errors)); then
    severity="WARN"
    severity_rank=1
    alert_reasons+=("evaluation_errors $eval_errors >= warn_eval_errors $warn_eval_errors")
  fi
fi

incident_source_run_report_json="$(abs_path "$(jq -r '.incident_snapshot.latest_failed_run_report.source_run_report_json.path // .incident_snapshot.latest_failed_run_report.path // ""' "$trend_summary_json" 2>/dev/null || true)")"
incident_source_run_report_exists="$(path_exists01 "$incident_source_run_report_json")"
incident_source_summary_json="$(abs_path "$(jq -r '.incident_snapshot.latest_failed_run_report.source_summary_json.path // ""' "$trend_summary_json" 2>/dev/null || true)")"
incident_source_summary_exists="$(path_exists01 "$incident_source_summary_json")"
incident_source_summary_valid_json="$(json_valid01 "$incident_source_summary_json")"
incident_enabled="$(jq -r '.incident_snapshot.latest_failed_run_report.enabled // false | if . then 1 else 0 end' "$trend_summary_json" 2>/dev/null || echo 0)"
incident_status="$(jq -r '.incident_snapshot.latest_failed_run_report.status // ""' "$trend_summary_json" 2>/dev/null || true)"
incident_bundle_dir="$(abs_path "$(jq -r '.incident_snapshot.latest_failed_run_report.bundle_dir.path // ""' "$trend_summary_json" 2>/dev/null || true)")"
incident_bundle_dir_exists="$(path_exists01 "$incident_bundle_dir")"
incident_bundle_tar="$(abs_path "$(jq -r '.incident_snapshot.latest_failed_run_report.bundle_tar.path // ""' "$trend_summary_json" 2>/dev/null || true)")"
incident_bundle_tar_exists="$(path_exists01 "$incident_bundle_tar")"
incident_summary_json="$(abs_path "$(jq -r '.incident_snapshot.latest_failed_run_report.summary_json.path // ""' "$trend_summary_json" 2>/dev/null || true)")"
incident_summary_exists="$(path_exists01 "$incident_summary_json")"
incident_summary_valid_json="$(json_valid01 "$incident_summary_json")"
incident_report_md="$(abs_path "$(jq -r '.incident_snapshot.latest_failed_run_report.report_md.path // ""' "$trend_summary_json" 2>/dev/null || true)")"
incident_report_exists="$(path_exists01 "$incident_report_md")"
incident_attachment_manifest="$(abs_path "$(jq -r '.incident_snapshot.latest_failed_run_report.attachment_manifest.path // ""' "$trend_summary_json" 2>/dev/null || true)")"
incident_attachment_manifest_exists="$(path_exists01 "$incident_attachment_manifest")"
incident_attachment_skipped="$(abs_path "$(jq -r '.incident_snapshot.latest_failed_run_report.attachment_skipped.path // ""' "$trend_summary_json" 2>/dev/null || true)")"
incident_attachment_skipped_exists="$(path_exists01 "$incident_attachment_skipped")"
incident_attachment_count="$(jq -r '.incident_snapshot.latest_failed_run_report.attachment_count // 0' "$trend_summary_json" 2>/dev/null || echo 0)"

echo "[prod-gate-slo-alert] severity=$severity reports_total=$reports_total go_rate_pct=$go_rate_pct no_go=$no_go_count evaluation_errors=$eval_errors"
echo "[prod-gate-slo-alert] thresholds warn_go_rate_pct=$warn_go_rate_pct critical_go_rate_pct=$critical_go_rate_pct warn_no_go_count=$warn_no_go_count critical_no_go_count=$critical_no_go_count warn_eval_errors=$warn_eval_errors critical_eval_errors=$critical_eval_errors"
echo "[prod-gate-slo-alert] policy require_wg_validate_udp_source=$require_wg_validate_udp_source require_wg_validate_strict_distinct=$require_wg_validate_strict_distinct require_wg_soak_diversity_pass=$require_wg_soak_diversity_pass min_wg_soak_selection_lines=$min_wg_soak_selection_lines min_wg_soak_entry_operators=$min_wg_soak_entry_operators min_wg_soak_exit_operators=$min_wg_soak_exit_operators min_wg_soak_cross_operator_pairs=$min_wg_soak_cross_operator_pairs"
echo "[prod-gate-slo-alert] freshness status=$freshness_status max_evidence_age_sec=$max_evidence_age_sec trend_generated_at_utc=${trend_generated_at_utc:-unset} age_sec=${freshness_age_sec:-unset}"
echo "[prod-gate-slo-alert] trend_policy_check reasons=${#policy_reasons[@]}"
echo "[prod-gate-slo-alert] trend_integrity_check reasons=${#integrity_reasons[@]}"
echo "[prod-gate-slo-alert] trend_source=$trend_source trend_summary_json=$trend_summary_json"
if [[ -n "$incident_source_run_report_json" || -n "$incident_summary_json" || -n "$incident_report_md" || -n "$incident_attachment_manifest" || -n "$incident_attachment_skipped" ]]; then
  echo "[prod-gate-slo-alert] incident_handoff source_summary_json=${incident_source_summary_json:-unset} source_run_report=${incident_source_run_report_json:-unset} summary_json=${incident_summary_json:-unset} report_md=${incident_report_md:-unset} attachment_manifest=${incident_attachment_manifest:-unset} attachment_skipped=${incident_attachment_skipped:-unset} attachment_count=${incident_attachment_count}"
fi

if ((${#alert_reasons[@]} > 0)); then
  echo "[prod-gate-slo-alert] trigger_reasons:"
  for reason in "${alert_reasons[@]}"; do
    echo "  - $reason"
  done
fi

reasons_file="$tmp_dir/alert_reasons.txt"
: >"$reasons_file"
for reason in "${alert_reasons[@]}"; do
  printf '%s\n' "$reason" >>"$reasons_file"
done
reasons_json="$(jq -Rn '[inputs]' <"$reasons_file")"
freshness_reasons_file="$tmp_dir/freshness_reasons.txt"
: >"$freshness_reasons_file"
for reason in "${freshness_reasons[@]}"; do
  printf '%s\n' "$reason" >>"$freshness_reasons_file"
done
freshness_reasons_json="$(jq -Rn '[inputs]' <"$freshness_reasons_file")"
policy_reasons_file="$tmp_dir/policy_reasons.txt"
: >"$policy_reasons_file"
for reason in "${policy_reasons[@]}"; do
  printf '%s\n' "$reason" >>"$policy_reasons_file"
done
policy_reasons_json="$(jq -Rn '[inputs]' <"$policy_reasons_file")"
integrity_reasons_file="$tmp_dir/integrity_reasons.txt"
: >"$integrity_reasons_file"
for reason in "${integrity_reasons[@]}"; do
  printf '%s\n' "$reason" >>"$integrity_reasons_file"
done
integrity_reasons_json="$(jq -Rn '[inputs]' <"$integrity_reasons_file")"
top_reasons_json="$(jq -c '.top_no_go_reasons // []' "$trend_summary_json" 2>/dev/null || echo '[]')"

summary_payload="$(
  jq -n \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg severity "$severity" \
    --arg trend_source "$trend_source" \
    --arg trend_summary_json "$trend_summary_json" \
    --argjson reports_total "$reports_total" \
    --argjson go_rate_pct "$go_rate_pct" \
    --argjson no_go "$no_go_count" \
    --argjson evaluation_errors "$eval_errors" \
    --argjson warn_go_rate_pct "$warn_go_rate_pct" \
    --argjson critical_go_rate_pct "$critical_go_rate_pct" \
    --argjson warn_no_go_count "$warn_no_go_count" \
    --argjson critical_no_go_count "$critical_no_go_count" \
    --argjson warn_eval_errors "$warn_eval_errors" \
    --argjson critical_eval_errors "$critical_eval_errors" \
    --argjson fail_on_warn "$fail_on_warn" \
    --argjson fail_on_critical "$fail_on_critical" \
    --argjson max_evidence_age_sec "$max_evidence_age_sec" \
    --argjson max_evidence_future_skew_sec "$max_evidence_future_skew_sec" \
    --arg trend_generated_at_utc "$trend_generated_at_utc" \
    --arg freshness_status "$freshness_status" \
    --arg freshness_age_sec "$freshness_age_sec" \
    --argjson freshness_reasons "$freshness_reasons_json" \
    --argjson policy_reasons "$policy_reasons_json" \
    --argjson integrity_reasons "$integrity_reasons_json" \
    --argjson require_wg_validate_udp_source "$require_wg_validate_udp_source" \
    --argjson require_wg_validate_strict_distinct "$require_wg_validate_strict_distinct" \
    --argjson require_wg_soak_diversity_pass "$require_wg_soak_diversity_pass" \
    --argjson min_wg_soak_selection_lines "$min_wg_soak_selection_lines" \
    --argjson min_wg_soak_entry_operators "$min_wg_soak_entry_operators" \
    --argjson min_wg_soak_exit_operators "$min_wg_soak_exit_operators" \
    --argjson min_wg_soak_cross_operator_pairs "$min_wg_soak_cross_operator_pairs" \
    --argjson show_top_reasons "$show_top_reasons" \
    --argjson trigger_reasons "$reasons_json" \
    --argjson top_no_go_reasons "$top_reasons_json" \
    --argjson trend_policy "$(jq -c '.policy // {}' "$trend_summary_json" 2>/dev/null || echo '{}')" \
    --arg incident_source_run_report_json "$incident_source_run_report_json" \
    --arg incident_source_summary_json "$incident_source_summary_json" \
    --arg incident_status "$incident_status" \
    --arg incident_bundle_dir "$incident_bundle_dir" \
    --arg incident_bundle_tar "$incident_bundle_tar" \
    --arg incident_summary_json "$incident_summary_json" \
    --arg incident_report_md "$incident_report_md" \
    --arg incident_attachment_manifest "$incident_attachment_manifest" \
    --arg incident_attachment_skipped "$incident_attachment_skipped" \
    --argjson incident_source_run_report_exists "$incident_source_run_report_exists" \
    --argjson incident_source_summary_exists "$incident_source_summary_exists" \
    --argjson incident_source_summary_valid_json "$incident_source_summary_valid_json" \
    --argjson incident_enabled "$incident_enabled" \
    --argjson incident_bundle_dir_exists "$incident_bundle_dir_exists" \
    --argjson incident_bundle_tar_exists "$incident_bundle_tar_exists" \
    --argjson incident_summary_exists "$incident_summary_exists" \
    --argjson incident_summary_valid_json "$incident_summary_valid_json" \
    --argjson incident_report_exists "$incident_report_exists" \
    --argjson incident_attachment_manifest_exists "$incident_attachment_manifest_exists" \
    --argjson incident_attachment_skipped_exists "$incident_attachment_skipped_exists" \
    --argjson incident_attachment_count "$incident_attachment_count" \
    '{
      version: 1,
      generated_at_utc: $generated_at_utc,
      severity: $severity,
      trend_source: $trend_source,
      trend_summary_json: $trend_summary_json,
      metrics: {
        reports_total: $reports_total,
        go_rate_pct: $go_rate_pct,
        no_go: $no_go,
        evaluation_errors: $evaluation_errors
      },
      thresholds: {
        warn_go_rate_pct: $warn_go_rate_pct,
        critical_go_rate_pct: $critical_go_rate_pct,
        warn_no_go_count: $warn_no_go_count,
        critical_no_go_count: $critical_no_go_count,
        warn_eval_errors: $warn_eval_errors,
        critical_eval_errors: $critical_eval_errors
      },
      fail_policy: {
        fail_on_warn: $fail_on_warn,
        fail_on_critical: $fail_on_critical
      },
      evidence_freshness: {
        max_evidence_age_sec: $max_evidence_age_sec,
        max_evidence_future_skew_sec: $max_evidence_future_skew_sec,
        trend_generated_at_utc: ($trend_generated_at_utc // ""),
        age_sec: (if $freshness_age_sec == "" then null else ($freshness_age_sec | tonumber) end),
        status: $freshness_status,
        reasons: $freshness_reasons
      },
      wg_evidence_policy: {
        require_wg_validate_udp_source: $require_wg_validate_udp_source,
        require_wg_validate_strict_distinct: $require_wg_validate_strict_distinct,
        require_wg_soak_diversity_pass: $require_wg_soak_diversity_pass,
        min_wg_soak_selection_lines: $min_wg_soak_selection_lines,
        min_wg_soak_entry_operators: $min_wg_soak_entry_operators,
        min_wg_soak_exit_operators: $min_wg_soak_exit_operators,
        min_wg_soak_cross_operator_pairs: $min_wg_soak_cross_operator_pairs
      },
      trend_policy: $trend_policy,
      trend_policy_check: {
        status: (if ($policy_reasons | length) == 0 then "ok" else "fail" end),
        reasons: $policy_reasons
      },
      trend_integrity_check: {
        status: (if ($integrity_reasons | length) == 0 then "ok" else "fail" end),
        reasons: $integrity_reasons
      },
      incident_snapshot: {
        latest_failed_run_report: {
          source_run_report_json: {path: ($incident_source_run_report_json // ""), exists: $incident_source_run_report_exists},
          source_summary_json: {path: ($incident_source_summary_json // ""), exists: $incident_source_summary_exists, valid_json: $incident_source_summary_valid_json},
          path: ($incident_source_run_report_json // ""),
          enabled: $incident_enabled,
          status: ($incident_status // ""),
          bundle_dir: {path: ($incident_bundle_dir // ""), exists: $incident_bundle_dir_exists},
          bundle_tar: {path: ($incident_bundle_tar // ""), exists: $incident_bundle_tar_exists},
          summary_json: {path: ($incident_summary_json // ""), exists: $incident_summary_exists, valid_json: $incident_summary_valid_json},
          report_md: {path: ($incident_report_md // ""), exists: $incident_report_exists},
          attachment_manifest: {path: ($incident_attachment_manifest // ""), exists: $incident_attachment_manifest_exists},
          attachment_skipped: {path: ($incident_attachment_skipped // ""), exists: $incident_attachment_skipped_exists},
          attachment_count: $incident_attachment_count
        }
      },
      top_no_go_reasons_limit: $show_top_reasons,
      top_no_go_reasons: $top_no_go_reasons,
      trigger_reasons: $trigger_reasons
    }'
)"

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  printf '%s\n' "$summary_payload" >"$summary_json"
  echo "[prod-gate-slo-alert] summary_json=$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  echo "[prod-gate-slo-alert] summary_json_payload:"
  printf '%s\n' "$summary_payload"
fi

if [[ "$severity" == "CRITICAL" && "$fail_on_critical" == "1" ]]; then
  exit 2
fi
if [[ "$severity" == "WARN" && "$fail_on_warn" == "1" ]]; then
  exit 1
fi
exit 0
