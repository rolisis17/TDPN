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
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_full_sequence="${2:-}"
        shift 2
      else
        require_full_sequence="1"
        shift
      fi
      ;;
    --require-wg-validate-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_ok="${2:-}"
        shift 2
      else
        require_wg_validate_ok="1"
        shift
      fi
      ;;
    --require-wg-soak-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_soak_ok="${2:-}"
        shift 2
      else
        require_wg_soak_ok="1"
        shift
      fi
      ;;
    --max-wg-soak-failed-rounds)
      max_wg_soak_failed_rounds="${2:-}"
      shift 2
      ;;
    --require-preflight-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_preflight_ok="${2:-}"
        shift 2
      else
        require_preflight_ok="1"
        shift
      fi
      ;;
    --require-bundle-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_bundle_ok="${2:-}"
        shift 2
      else
        require_bundle_ok="1"
        shift
      fi
      ;;
    --require-integrity-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_integrity_ok="${2:-}"
        shift 2
      else
        require_integrity_ok="1"
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
    --require-wg-validate-udp-source)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_udp_source="${2:-}"
        shift 2
      else
        require_wg_validate_udp_source="1"
        shift
      fi
      ;;
    --require-wg-validate-strict-distinct)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_strict_distinct="${2:-}"
        shift 2
      else
        require_wg_validate_strict_distinct="1"
        shift
      fi
      ;;
    --require-wg-soak-diversity-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_soak_diversity_pass="${2:-}"
        shift 2
      else
        require_wg_soak_diversity_pass="1"
        shift
      fi
      ;;
    --min-wg-soak-selection-lines)
      min_wg_soak_selection_lines="${2:-}"
      shift 2
      ;;
    --min-wg-soak-entry-operators)
      min_wg_soak_entry_operators="${2:-}"
      shift 2
      ;;
    --min-wg-soak-exit-operators)
      min_wg_soak_exit_operators="${2:-}"
      shift 2
      ;;
    --min-wg-soak-cross-operator-pairs)
      min_wg_soak_cross_operator_pairs="${2:-}"
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

echo "[prod-gate-slo-alert] severity=$severity reports_total=$reports_total go_rate_pct=$go_rate_pct no_go=$no_go_count evaluation_errors=$eval_errors"
echo "[prod-gate-slo-alert] thresholds warn_go_rate_pct=$warn_go_rate_pct critical_go_rate_pct=$critical_go_rate_pct warn_no_go_count=$warn_no_go_count critical_no_go_count=$critical_no_go_count warn_eval_errors=$warn_eval_errors critical_eval_errors=$critical_eval_errors"
echo "[prod-gate-slo-alert] policy require_wg_validate_udp_source=$require_wg_validate_udp_source require_wg_validate_strict_distinct=$require_wg_validate_strict_distinct require_wg_soak_diversity_pass=$require_wg_soak_diversity_pass min_wg_soak_selection_lines=$min_wg_soak_selection_lines min_wg_soak_entry_operators=$min_wg_soak_entry_operators min_wg_soak_exit_operators=$min_wg_soak_exit_operators min_wg_soak_cross_operator_pairs=$min_wg_soak_cross_operator_pairs"
echo "[prod-gate-slo-alert] trend_source=$trend_source trend_summary_json=$trend_summary_json"

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
