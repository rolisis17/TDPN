#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PILOT_RUNBOOK_SCRIPT="${PROD_PILOT_RUNBOOK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_runbook.sh}"
SLO_TREND_SCRIPT="${PROD_GATE_SLO_TREND_SCRIPT:-$ROOT_DIR/scripts/prod_gate_slo_trend.sh}"
SLO_ALERT_SCRIPT="${PROD_GATE_SLO_ALERT_SCRIPT:-$ROOT_DIR/scripts/prod_gate_slo_alert.sh}"
PRE_REAL_HOST_READINESS_SCRIPT="${PRE_REAL_HOST_READINESS_SCRIPT:-$ROOT_DIR/scripts/pre_real_host_readiness.sh}"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
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

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
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

severity_rank() {
  local severity
  severity="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]')"
  case "$severity" in
    OK) echo "0" ;;
    WARN) echo "1" ;;
    CRITICAL) echo "2" ;;
    *) echo "-1" ;;
  esac
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print $NF}'
    return 0
  fi
  return 1
}

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

json_bool() {
  if [[ "${1:-0}" == "1" ]]; then
    echo "true"
  else
    echo "false"
  fi
}

output_indicates_root_requirement() {
  local text="$1"
  if [[ -z "$text" ]]; then
    return 1
  fi
  if printf '%s\n' "$text" | grep -Eqi 'requires root|run with sudo|must be root|root privileges required'; then
    return 0
  fi
  return 1
}

pre_real_host_readiness_failure_requires_root() {
  local readiness_output="$1"
  local readiness_json="$2"
  local readiness_notes=""
  local readiness_stage=""
  local blockers_only_wg_only="false"

  if output_indicates_root_requirement "$readiness_output"; then
    return 0
  fi

  if [[ -z "$readiness_json" ]]; then
    return 1
  fi

  readiness_notes="$(
    printf '%s\n' "$readiness_json" | jq -r '
      [
        (.notes // ""),
        (.runtime_fix.notes // ""),
        (.wg_only_stack_selftest.notes // "")
      ] | map(select(type == "string")) | join("\n")
    ' 2>/dev/null || true
  )"
  if output_indicates_root_requirement "$readiness_notes"; then
    return 0
  fi

  readiness_stage="$(printf '%s\n' "$readiness_json" | jq -r '.stage // ""' 2>/dev/null || true)"
  blockers_only_wg_only="$(
    printf '%s\n' "$readiness_json" | jq -r '
      (.machine_c_smoke_gate.blockers // []) as $b
      | (($b | type) == "array")
        and (($b | length) == 1)
        and (($b[0] // "") == "wg_only_stack_selftest")
    ' 2>/dev/null || printf 'false'
  )"
  if [[ "${EUID:-$(id -u)}" -ne 0 && "$readiness_stage" == "wg_only_stack_selftest" && "$blockers_only_wg_only" == "true" ]]; then
    return 0
  fi

  return 1
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_runbook.sh \
    [--pre-real-host-readiness [0|1]] \
    [--pre-real-host-readiness-summary-json PATH] \
    [--rounds N] \
    [--pause-sec N] \
    [--continue-on-fail [0|1]] \
    [--require-all-rounds-ok [0|1]] \
    [--reports-dir PATH] \
    [--summary-json PATH] \
    [--trend-summary-json PATH] \
    [--alert-summary-json PATH] \
    [--trend-min-go-rate-pct N] \
    [--trend-fail-on-any-no-go [0|1]] \
    [--trend-require-wg-validate-udp-source [0|1]] \
    [--trend-require-wg-validate-strict-distinct [0|1]] \
    [--trend-require-wg-soak-diversity-pass [0|1]] \
    [--trend-min-wg-soak-selection-lines N] \
    [--trend-min-wg-soak-entry-operators N] \
    [--trend-min-wg-soak-exit-operators N] \
    [--trend-min-wg-soak-cross-operator-pairs N] \
    [--trend-max-reports N] \
    [--trend-since-hours N] \
    [--trend-show-top-reasons N] \
    [--warn-go-rate-pct N] \
    [--critical-go-rate-pct N] \
    [--warn-no-go-count N] \
    [--critical-no-go-count N] \
    [--warn-eval-errors N] \
    [--critical-eval-errors N] \
    [--max-alert-severity OK|WARN|CRITICAL] \
    [--bundle-outputs [0|1]] \
    [--bundle-fail-close [0|1]] \
    [--bundle-tar PATH] \
    [--bundle-sha256-file PATH] \
    [--bundle-manifest-json PATH] \
    [--print-summary-json [0|1]] \
    [-- <prod_pilot_runbook args...>]

Purpose:
  Run sustained production pilot cohorts by executing prod_pilot_runbook in
  repeated rounds, then aggregate SLO trend/alert outputs into one summary.

Examples:
  ./scripts/prod_pilot_cohort_runbook.sh \
    --rounds 5 \
    --pause-sec 60 \
    --trend-min-go-rate-pct 95 \
    -- --bootstrap-directory https://A_HOST:8081 --subject pilot-alice

Notes:
  - Unknown args are forwarded to prod_pilot_runbook.
  - pre-real-host readiness runs once before the cohort by default, then inner
    prod-pilot-runbook rounds are told to skip duplicate readiness sweeps.
  - Summary JSON includes per-round command result + run report paths.
  - If --require-all-rounds-ok=1, any non-zero round exits mark cohort fail.
  - Bundle mode can produce one shareable tar + checksum + manifest for the full cohort.
USAGE
}

for cmd in bash jq awk sed mktemp date dirname sort; do
  need_cmd "$cmd"
done

if [[ ! -x "$PILOT_RUNBOOK_SCRIPT" ]]; then
  echo "missing executable pilot runbook script: $PILOT_RUNBOOK_SCRIPT"
  exit 2
fi
if [[ ! -x "$SLO_TREND_SCRIPT" ]]; then
  echo "missing executable slo trend script: $SLO_TREND_SCRIPT"
  exit 2
fi
if [[ ! -x "$SLO_ALERT_SCRIPT" ]]; then
  echo "missing executable slo alert script: $SLO_ALERT_SCRIPT"
  exit 2
fi
if [[ ! -x "$PRE_REAL_HOST_READINESS_SCRIPT" ]]; then
  echo "missing executable pre-real-host readiness script: $PRE_REAL_HOST_READINESS_SCRIPT"
  exit 2
fi

pre_real_host_readiness="${PROD_PILOT_COHORT_PRE_REAL_HOST_READINESS:-1}"
pre_real_host_readiness_defer_no_root_mode="${PROD_PILOT_COHORT_PRE_REAL_HOST_READINESS_DEFER_NO_ROOT:-auto}"
pre_real_host_readiness_summary_json=""
pre_real_host_readiness_summary_json_override="${PROD_PILOT_COHORT_PRE_REAL_HOST_READINESS_SUMMARY_JSON:-}"
rounds="${PROD_PILOT_COHORT_ROUNDS:-5}"
pause_sec="${PROD_PILOT_COHORT_PAUSE_SEC:-60}"
continue_on_fail="${PROD_PILOT_COHORT_CONTINUE_ON_FAIL:-0}"
require_all_rounds_ok="${PROD_PILOT_COHORT_REQUIRE_ALL_ROUNDS_OK:-1}"
reports_dir="${PROD_PILOT_COHORT_REPORTS_DIR:-}"
summary_json=""
trend_summary_json=""
alert_summary_json=""
trend_min_go_rate_pct="${PROD_PILOT_COHORT_TREND_MIN_GO_RATE_PCT:-95}"
trend_fail_on_any_no_go="${PROD_PILOT_COHORT_TREND_FAIL_ON_ANY_NO_GO:-0}"
trend_require_wg_validate_udp_source="${PROD_PILOT_COHORT_TREND_REQUIRE_WG_VALIDATE_UDP_SOURCE:-1}"
trend_require_wg_validate_strict_distinct="${PROD_PILOT_COHORT_TREND_REQUIRE_WG_VALIDATE_STRICT_DISTINCT:-1}"
trend_require_wg_soak_diversity_pass="${PROD_PILOT_COHORT_TREND_REQUIRE_WG_SOAK_DIVERSITY_PASS:-1}"
trend_min_wg_soak_selection_lines="${PROD_PILOT_COHORT_TREND_MIN_WG_SOAK_SELECTION_LINES:-12}"
trend_min_wg_soak_entry_operators="${PROD_PILOT_COHORT_TREND_MIN_WG_SOAK_ENTRY_OPERATORS:-2}"
trend_min_wg_soak_exit_operators="${PROD_PILOT_COHORT_TREND_MIN_WG_SOAK_EXIT_OPERATORS:-2}"
trend_min_wg_soak_cross_operator_pairs="${PROD_PILOT_COHORT_TREND_MIN_WG_SOAK_CROSS_OPERATOR_PAIRS:-2}"
trend_max_reports="${PROD_PILOT_COHORT_TREND_MAX_REPORTS:-0}"
trend_since_hours="${PROD_PILOT_COHORT_TREND_SINCE_HOURS:-0}"
trend_show_top_reasons="${PROD_PILOT_COHORT_TREND_SHOW_TOP_REASONS:-5}"
warn_go_rate_pct="${PROD_PILOT_COHORT_ALERT_WARN_GO_RATE_PCT:-98}"
critical_go_rate_pct="${PROD_PILOT_COHORT_ALERT_CRITICAL_GO_RATE_PCT:-90}"
warn_no_go_count="${PROD_PILOT_COHORT_ALERT_WARN_NO_GO_COUNT:-1}"
critical_no_go_count="${PROD_PILOT_COHORT_ALERT_CRITICAL_NO_GO_COUNT:-2}"
warn_eval_errors="${PROD_PILOT_COHORT_ALERT_WARN_EVAL_ERRORS:-1}"
critical_eval_errors="${PROD_PILOT_COHORT_ALERT_CRITICAL_EVAL_ERRORS:-2}"
max_alert_severity="${PROD_PILOT_COHORT_MAX_ALERT_SEVERITY:-WARN}"
bundle_outputs="${PROD_PILOT_COHORT_BUNDLE_OUTPUTS:-1}"
bundle_fail_close="${PROD_PILOT_COHORT_BUNDLE_FAIL_CLOSE:-1}"
bundle_tar=""
bundle_sha256_file=""
bundle_manifest_json=""
print_summary_json="${PROD_PILOT_COHORT_PRINT_SUMMARY_JSON:-0}"

declare -a pilot_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
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
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --trend-summary-json)
      trend_summary_json="${2:-}"
      shift 2
      ;;
    --alert-summary-json)
      alert_summary_json="${2:-}"
      shift 2
      ;;
    --trend-min-go-rate-pct)
      trend_min_go_rate_pct="${2:-}"
      shift 2
      ;;
    --trend-fail-on-any-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        trend_fail_on_any_no_go="${2:-}"
        shift 2
      else
        trend_fail_on_any_no_go="1"
        shift
      fi
      ;;
    --trend-require-wg-validate-udp-source)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        trend_require_wg_validate_udp_source="${2:-}"
        shift 2
      else
        trend_require_wg_validate_udp_source="1"
        shift
      fi
      ;;
    --trend-require-wg-validate-strict-distinct)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        trend_require_wg_validate_strict_distinct="${2:-}"
        shift 2
      else
        trend_require_wg_validate_strict_distinct="1"
        shift
      fi
      ;;
    --trend-require-wg-soak-diversity-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        trend_require_wg_soak_diversity_pass="${2:-}"
        shift 2
      else
        trend_require_wg_soak_diversity_pass="1"
        shift
      fi
      ;;
    --trend-min-wg-soak-selection-lines)
      trend_min_wg_soak_selection_lines="${2:-}"
      shift 2
      ;;
    --trend-min-wg-soak-entry-operators)
      trend_min_wg_soak_entry_operators="${2:-}"
      shift 2
      ;;
    --trend-min-wg-soak-exit-operators)
      trend_min_wg_soak_exit_operators="${2:-}"
      shift 2
      ;;
    --trend-min-wg-soak-cross-operator-pairs)
      trend_min_wg_soak_cross_operator_pairs="${2:-}"
      shift 2
      ;;
    --trend-max-reports)
      trend_max_reports="${2:-}"
      shift 2
      ;;
    --trend-since-hours)
      trend_since_hours="${2:-}"
      shift 2
      ;;
    --trend-show-top-reasons)
      trend_show_top_reasons="${2:-}"
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
    --bundle-tar)
      bundle_tar="${2:-}"
      shift 2
      ;;
    --bundle-sha256-file)
      bundle_sha256_file="${2:-}"
      shift 2
      ;;
    --bundle-manifest-json)
      bundle_manifest_json="${2:-}"
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
    --)
      shift
      while [[ $# -gt 0 ]]; do
        pilot_args+=("$1")
        shift
      done
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      pilot_args+=("$1")
      shift
      ;;
  esac
done

bool_or_die "--continue-on-fail" "$continue_on_fail"
bool_or_die "--require-all-rounds-ok" "$require_all_rounds_ok"
bool_or_die "--pre-real-host-readiness" "$pre_real_host_readiness"
bool_or_die "--trend-fail-on-any-no-go" "$trend_fail_on_any_no_go"
bool_or_die "--trend-require-wg-validate-udp-source" "$trend_require_wg_validate_udp_source"
bool_or_die "--trend-require-wg-validate-strict-distinct" "$trend_require_wg_validate_strict_distinct"
bool_or_die "--trend-require-wg-soak-diversity-pass" "$trend_require_wg_soak_diversity_pass"
bool_or_die "--bundle-outputs" "$bundle_outputs"
bool_or_die "--bundle-fail-close" "$bundle_fail_close"
bool_or_die "--print-summary-json" "$print_summary_json"
if [[ "$pre_real_host_readiness_defer_no_root_mode" != "auto" && "$pre_real_host_readiness_defer_no_root_mode" != "0" && "$pre_real_host_readiness_defer_no_root_mode" != "1" ]]; then
  echo "PROD_PILOT_COHORT_PRE_REAL_HOST_READINESS_DEFER_NO_ROOT must be auto, 0, or 1"
  exit 2
fi

int_or_die "--rounds" "$rounds"
int_or_die "--pause-sec" "$pause_sec"
int_or_die "--trend-max-reports" "$trend_max_reports"
int_or_die "--trend-since-hours" "$trend_since_hours"
int_or_die "--trend-show-top-reasons" "$trend_show_top_reasons"
int_or_die "--trend-min-wg-soak-selection-lines" "$trend_min_wg_soak_selection_lines"
int_or_die "--trend-min-wg-soak-entry-operators" "$trend_min_wg_soak_entry_operators"
int_or_die "--trend-min-wg-soak-exit-operators" "$trend_min_wg_soak_exit_operators"
int_or_die "--trend-min-wg-soak-cross-operator-pairs" "$trend_min_wg_soak_cross_operator_pairs"
int_or_die "--warn-no-go-count" "$warn_no_go_count"
int_or_die "--critical-no-go-count" "$critical_no_go_count"
int_or_die "--warn-eval-errors" "$warn_eval_errors"
int_or_die "--critical-eval-errors" "$critical_eval_errors"

if ((rounds <= 0)); then
  echo "--rounds must be >= 1"
  exit 2
fi
if ! is_non_negative_decimal "$trend_min_go_rate_pct"; then
  echo "--trend-min-go-rate-pct must be a non-negative number"
  exit 2
fi
if ! is_non_negative_decimal "$warn_go_rate_pct"; then
  echo "--warn-go-rate-pct must be a non-negative number"
  exit 2
fi
if ! is_non_negative_decimal "$critical_go_rate_pct"; then
  echo "--critical-go-rate-pct must be a non-negative number"
  exit 2
fi
max_alert_severity="$(printf '%s' "$max_alert_severity" | tr '[:lower:]' '[:upper:]')"
if [[ "$max_alert_severity" != "OK" && "$max_alert_severity" != "WARN" && "$max_alert_severity" != "CRITICAL" ]]; then
  echo "--max-alert-severity must be OK, WARN, or CRITICAL"
  exit 2
fi
if ((trend_max_reports == 0)); then
  trend_max_reports="$rounds"
fi

timestamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$(default_log_dir)/prod_pilot_cohort_${timestamp}"
fi
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$trend_summary_json" ]]; then
  trend_summary_json="$reports_dir/prod_pilot_cohort_trend.json"
fi
if [[ -z "$alert_summary_json" ]]; then
  alert_summary_json="$reports_dir/prod_pilot_cohort_alert.json"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/prod_pilot_cohort_summary.json"
fi
if [[ -z "$pre_real_host_readiness_summary_json" ]]; then
  if [[ -n "$pre_real_host_readiness_summary_json_override" ]]; then
    pre_real_host_readiness_summary_json="$pre_real_host_readiness_summary_json_override"
  else
    pre_real_host_readiness_summary_json="$reports_dir/pre_real_host_readiness_summary.json"
  fi
fi
if [[ -z "$bundle_manifest_json" ]]; then
  bundle_manifest_json="$reports_dir/prod_pilot_cohort_bundle_manifest.json"
fi
if [[ -z "$bundle_tar" ]]; then
  bundle_tar="${reports_dir}.tar.gz"
fi
if [[ -z "$bundle_sha256_file" ]]; then
  bundle_sha256_file="${bundle_tar}.sha256"
fi
trend_summary_json="$(abs_path "$trend_summary_json")"
alert_summary_json="$(abs_path "$alert_summary_json")"
summary_json="$(abs_path "$summary_json")"
pre_real_host_readiness_summary_json="$(abs_path "$pre_real_host_readiness_summary_json")"
bundle_manifest_json="$(abs_path "$bundle_manifest_json")"
bundle_tar="$(abs_path "$bundle_tar")"
bundle_sha256_file="$(abs_path "$bundle_sha256_file")"
mkdir -p "$(dirname "$trend_summary_json")" "$(dirname "$alert_summary_json")" "$(dirname "$summary_json")" "$(dirname "$pre_real_host_readiness_summary_json")" "$(dirname "$bundle_manifest_json")" "$(dirname "$bundle_tar")" "$(dirname "$bundle_sha256_file")"

pre_real_host_readiness_log="$reports_dir/pre_real_host_readiness.log"

report_list_file="$reports_dir/run_reports.list"
: >"$report_list_file"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_epoch="$(date -u +%s)"

rounds_attempted=0
rounds_passed=0
rounds_failed=0
stopped_early=0
first_failure_rc=0

round_results_json='[]'
declare -a run_reports=()
pre_real_host_readiness_rc=0
pre_real_host_readiness_status="skipped"
pre_real_host_readiness_machine_c_ready=""
pre_real_host_readiness_next_command=""
pre_real_host_readiness_readiness_status=""
pre_real_host_readiness_report_summary_json=""
pre_real_host_readiness_report_md=""
pre_real_host_readiness_blockers_json='[]'
pre_real_host_readiness_defer_no_root="0"
pre_real_host_readiness_deferred_no_root="0"
pre_real_host_readiness_defer_reason=""
pre_real_host_blocked=0
pilot_pre_real_host_readiness_explicit=0

if [[ "$pre_real_host_readiness_defer_no_root_mode" == "auto" ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    pre_real_host_readiness_defer_no_root="1"
  fi
else
  pre_real_host_readiness_defer_no_root="$pre_real_host_readiness_defer_no_root_mode"
fi

for arg in "${pilot_args[@]}"; do
  if [[ "$arg" == "--pre-real-host-readiness" ]]; then
    pilot_pre_real_host_readiness_explicit=1
    break
  fi
done

if [[ "$pre_real_host_readiness" == "1" ]]; then
  readiness_output=""
  readiness_json=""
  echo "[prod-pilot-cohort] running pre-real-host readiness gate"
  echo "[prod-pilot-cohort] pre_real_host_readiness_summary_json=$pre_real_host_readiness_summary_json"
  echo "[prod-pilot-cohort] pre_real_host_readiness_log=$pre_real_host_readiness_log"
  echo "[prod-pilot-cohort] pre_real_host_readiness_defer_no_root=$pre_real_host_readiness_defer_no_root mode=$pre_real_host_readiness_defer_no_root_mode"
  set +e
  "$PRE_REAL_HOST_READINESS_SCRIPT" \
    --summary-json "$pre_real_host_readiness_summary_json" \
    --defer-no-root "$pre_real_host_readiness_defer_no_root" \
    --print-summary-json 1 2>&1 | tee "$pre_real_host_readiness_log"
  pre_real_host_readiness_rc=${PIPESTATUS[0]}
  set -e
  if [[ -f "$pre_real_host_readiness_log" ]]; then
    readiness_output="$(cat "$pre_real_host_readiness_log" 2>/dev/null || true)"
  fi

  if [[ -f "$pre_real_host_readiness_summary_json" ]] && jq -e . "$pre_real_host_readiness_summary_json" >/dev/null 2>&1; then
    readiness_json="$(cat "$pre_real_host_readiness_summary_json")"
    pre_real_host_readiness_status="$(jq -r '.status // "fail"' "$pre_real_host_readiness_summary_json" 2>/dev/null || printf 'fail')"
    pre_real_host_readiness_machine_c_ready="$(jq -r '.machine_c_smoke_gate.ready // false' "$pre_real_host_readiness_summary_json" 2>/dev/null || printf 'false')"
    pre_real_host_readiness_next_command="$(jq -r '.machine_c_smoke_gate.next_command // ""' "$pre_real_host_readiness_summary_json" 2>/dev/null || true)"
    pre_real_host_readiness_readiness_status="$(jq -r '.manual_validation_report.readiness_status // ""' "$pre_real_host_readiness_summary_json" 2>/dev/null || true)"
    pre_real_host_readiness_report_summary_json="$(jq -r '.manual_validation_report.summary_json // ""' "$pre_real_host_readiness_summary_json" 2>/dev/null || true)"
    pre_real_host_readiness_report_md="$(jq -r '.manual_validation_report.report_md // ""' "$pre_real_host_readiness_summary_json" 2>/dev/null || true)"
    pre_real_host_readiness_blockers_json="$(jq -c '.machine_c_smoke_gate.blockers // []' "$pre_real_host_readiness_summary_json" 2>/dev/null || printf '[]')"
  fi

  if [[ "$pre_real_host_readiness_rc" -ne 0 || "$pre_real_host_readiness_machine_c_ready" != "true" ]]; then
    if [[ "$pre_real_host_readiness_defer_no_root" == "1" ]] && pre_real_host_readiness_failure_requires_root "$readiness_output" "$readiness_json"; then
      pre_real_host_readiness_deferred_no_root="1"
      pre_real_host_readiness_defer_reason="pre-real-host readiness requires root privileges; continuing cohort runbook with deferred gate"
      echo "[prod-pilot-cohort] $pre_real_host_readiness_defer_reason"
    else
      pre_real_host_blocked=1
      echo "[prod-pilot-cohort] pre-real-host readiness blocked cohort runbook: rc=$pre_real_host_readiness_rc"
    fi
  fi
fi

if [[ "$pre_real_host_blocked" != "1" ]]; then
for ((round = 1; round <= rounds; round++)); do
  rounds_attempted=$((rounds_attempted + 1))
  round_dir="$reports_dir/round_${round}"
  mkdir -p "$round_dir"
  round_report_json="$round_dir/prod_bundle_run_report.json"
  round_log="$round_dir/prod_pilot_round.log"

  cmd=(
    "$PILOT_RUNBOOK_SCRIPT"
    --bundle-dir "$round_dir"
    --run-report-json "$round_report_json"
  )
  if [[ "$pilot_pre_real_host_readiness_explicit" != "1" ]]; then
    cmd+=(--pre-real-host-readiness 0)
  fi
  cmd+=("${pilot_args[@]}")

  echo "[prod-pilot-cohort] round=$round/$rounds start"
  set +e
  "${cmd[@]}" >"$round_log" 2>&1
  rc=$?
  set -e

  if [[ -f "$round_report_json" ]]; then
    run_reports+=("$round_report_json")
    printf '%s\n' "$round_report_json" >>"$report_list_file"
  fi

  if [[ "$rc" -eq 0 ]]; then
    rounds_passed=$((rounds_passed + 1))
    round_status="ok"
  else
    rounds_failed=$((rounds_failed + 1))
    round_status="fail"
    if [[ "$first_failure_rc" -eq 0 ]]; then
      first_failure_rc="$rc"
    fi
  fi

  round_obj="$(
    jq -nc \
      --argjson round "$round" \
      --arg status "$round_status" \
      --argjson rc "$rc" \
      --arg bundle_dir "$round_dir" \
      --arg run_report_json "$round_report_json" \
      --arg log_file "$round_log" \
      '{
        round:$round,
        status:$status,
        rc:$rc,
        bundle_dir:$bundle_dir,
        run_report_json:$run_report_json,
        log_file:$log_file
      }'
  )"
  round_results_json="$(
    jq -nc \
      --argjson arr "$round_results_json" \
      --argjson obj "$round_obj" \
      '$arr + [$obj]'
  )"

  echo "[prod-pilot-cohort] round=$round status=$round_status rc=$rc"

  if [[ "$rc" -ne 0 && "$continue_on_fail" == "0" ]]; then
    stopped_early=1
    break
  fi

  if ((round < rounds)); then
    sleep "$pause_sec"
  fi
done
fi

trend_rc=0
alert_rc=0
if [[ -s "$report_list_file" ]]; then
  echo "[prod-pilot-cohort] running SLO trend summary"
  set +e
  "$SLO_TREND_SCRIPT" \
    --run-report-list "$report_list_file" \
    --max-reports "$trend_max_reports" \
    --since-hours "$trend_since_hours" \
    --show-details 0 \
    --show-top-reasons "$trend_show_top_reasons" \
    --fail-on-any-no-go "$trend_fail_on_any_no_go" \
    --min-go-rate-pct "$trend_min_go_rate_pct" \
    --require-wg-validate-udp-source "$trend_require_wg_validate_udp_source" \
    --require-wg-validate-strict-distinct "$trend_require_wg_validate_strict_distinct" \
    --require-wg-soak-diversity-pass "$trend_require_wg_soak_diversity_pass" \
    --min-wg-soak-selection-lines "$trend_min_wg_soak_selection_lines" \
    --min-wg-soak-entry-operators "$trend_min_wg_soak_entry_operators" \
    --min-wg-soak-exit-operators "$trend_min_wg_soak_exit_operators" \
    --min-wg-soak-cross-operator-pairs "$trend_min_wg_soak_cross_operator_pairs" \
    --summary-json "$trend_summary_json" \
    --print-summary-json 0
  trend_rc=$?
  set -e

  echo "[prod-pilot-cohort] running SLO alert summary"
  set +e
  "$SLO_ALERT_SCRIPT" \
    --trend-summary-json "$trend_summary_json" \
    --require-wg-validate-udp-source "$trend_require_wg_validate_udp_source" \
    --require-wg-validate-strict-distinct "$trend_require_wg_validate_strict_distinct" \
    --require-wg-soak-diversity-pass "$trend_require_wg_soak_diversity_pass" \
    --min-wg-soak-selection-lines "$trend_min_wg_soak_selection_lines" \
    --min-wg-soak-entry-operators "$trend_min_wg_soak_entry_operators" \
    --min-wg-soak-exit-operators "$trend_min_wg_soak_exit_operators" \
    --min-wg-soak-cross-operator-pairs "$trend_min_wg_soak_cross_operator_pairs" \
    --warn-go-rate-pct "$warn_go_rate_pct" \
    --critical-go-rate-pct "$critical_go_rate_pct" \
    --warn-no-go-count "$warn_no_go_count" \
    --critical-no-go-count "$critical_no_go_count" \
    --warn-eval-errors "$warn_eval_errors" \
    --critical-eval-errors "$critical_eval_errors" \
    --summary-json "$alert_summary_json" \
    --print-summary-json 0
  alert_rc=$?
  set -e
else
  jq -nc \
    --arg status "no_reports" \
    --arg reason "no run-report JSON artifacts were produced" \
    '{status:$status,reason:$reason}' >"$trend_summary_json"
  jq -nc \
    --arg severity "CRITICAL" \
    --arg reason "no run-report JSON artifacts were produced" \
    '{severity:$severity,reason:$reason}' >"$alert_summary_json"
  trend_rc=1
  alert_rc=1
fi

trend_go_rate_pct="$(jq -r '.go_rate_pct // ""' "$trend_summary_json" 2>/dev/null || true)"
alert_severity="$(jq -r '.severity // ""' "$alert_summary_json" 2>/dev/null || true)"
alert_severity="$(printf '%s' "$alert_severity" | tr '[:lower:]' '[:upper:]')"
alert_severity_rank="$(severity_rank "$alert_severity")"
max_alert_severity_rank="$(severity_rank "$max_alert_severity")"
alert_gate_violated=0

status="ok"
failure_step=""
final_rc=0

if [[ "$pre_real_host_blocked" == "1" ]]; then
  status="fail"
  failure_step="pre_real_host_readiness"
  final_rc="$pre_real_host_readiness_rc"
  if [[ "$final_rc" -eq 0 ]]; then
    final_rc=1
  fi
fi
if [[ "$require_all_rounds_ok" == "1" && "$rounds_failed" -gt 0 && "$status" == "ok" ]]; then
  status="fail"
  failure_step="pilot_rounds"
  final_rc="$first_failure_rc"
fi
if [[ "$trend_rc" -ne 0 && "$status" == "ok" ]]; then
  status="fail"
  failure_step="slo_trend"
  final_rc="$trend_rc"
fi
if [[ "$alert_rc" -ne 0 && "$status" == "ok" ]]; then
  status="fail"
  failure_step="slo_alert"
  final_rc="$alert_rc"
fi
if [[ "$status" == "ok" ]]; then
  if [[ "$alert_severity_rank" -lt 0 ]]; then
    status="fail"
    failure_step="alert_severity_parse"
    final_rc=23
  elif [[ "$max_alert_severity_rank" -ge 0 && "$alert_severity_rank" -gt "$max_alert_severity_rank" ]]; then
    status="fail"
    failure_step="alert_severity_policy"
    final_rc=24
    alert_gate_violated=1
  fi
fi
if [[ "$status" != "ok" && "$final_rc" -eq 0 ]]; then
  final_rc=1
fi

run_reports_json="$(printf '%s\n' "${run_reports[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"

bundle_created=0
bundle_rc=0
bundle_sha256=""
bundle_error=""
bundle_manifest_created=0
bundle_manifest_rc=0
bundle_manifest_error=""

if [[ "$bundle_outputs" == "1" ]]; then
  manifest_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  set +e
  jq -nc \
    --arg generated_at "$manifest_started_at" \
    --arg reports_dir "$reports_dir" \
    --arg report_list_file "$report_list_file" \
    --arg trend_summary_json "$trend_summary_json" \
    --arg alert_summary_json "$alert_summary_json" \
    --arg summary_json "$summary_json" \
    --argjson run_reports "$run_reports_json" \
    --argjson round_results "$round_results_json" \
    --arg status_before_bundle "$status" \
    --argjson final_rc_before_bundle "$final_rc" \
    '{
      generated_at:$generated_at,
      reports_dir:$reports_dir,
      report_list_file:$report_list_file,
      trend_summary_json:$trend_summary_json,
      alert_summary_json:$alert_summary_json,
      summary_json:$summary_json,
      status_before_bundle:$status_before_bundle,
      final_rc_before_bundle:$final_rc_before_bundle,
      run_reports:$run_reports,
      round_results:$round_results
    }' >"$bundle_manifest_json"
  bundle_manifest_rc=$?
  set -e
  if [[ "$bundle_manifest_rc" -eq 0 ]]; then
    bundle_manifest_created=1
  else
    bundle_manifest_error="failed to write bundle manifest"
    bundle_error="$bundle_manifest_error"
  fi

  if [[ "$bundle_manifest_created" -eq 1 ]]; then
    bundle_tmp="${bundle_tar}.tmp.$$"
    report_parent_dir="$(dirname "$reports_dir")"
    report_base_dir="$(basename "$reports_dir")"

    set +e
    tar -czf "$bundle_tmp" -C "$report_parent_dir" "$report_base_dir"
    tar_rc=$?
    if [[ "$tar_rc" -eq 0 ]]; then
      mv "$bundle_tmp" "$bundle_tar"
    else
      rm -f "$bundle_tmp"
    fi
    set -e

    if [[ "$tar_rc" -eq 0 ]]; then
      set +e
      bundle_sha256="$(sha256_file "$bundle_tar")"
      sha_rc=$?
      set -e
      if [[ "$sha_rc" -eq 0 && -n "$bundle_sha256" ]]; then
        printf '%s  %s\n' "$bundle_sha256" "$(basename "$bundle_tar")" >"$bundle_sha256_file"
        bundle_created=1
        bundle_rc=0
      else
        bundle_rc=26
        bundle_error="bundle created but sha256 tool unavailable"
      fi
    else
      bundle_rc="$tar_rc"
      bundle_error="failed to create cohort bundle tarball"
    fi
  else
    bundle_rc="$bundle_manifest_rc"
  fi

  if [[ "$bundle_created" -ne 1 && "$bundle_fail_close" == "1" ]]; then
    if [[ "$status" == "ok" ]]; then
      status="fail"
      failure_step="bundle_outputs"
      if [[ "$bundle_rc" -gt 0 ]]; then
        final_rc="$bundle_rc"
      else
        final_rc=25
      fi
    fi
  fi
fi

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
finished_epoch="$(date -u +%s)"
duration_sec=$((finished_epoch - started_epoch))
if [[ "$duration_sec" -lt 0 ]]; then
  duration_sec=0
fi

jq -nc \
  --arg status "$status" \
  --arg failure_step "$failure_step" \
  --arg started_at "$started_at" \
  --arg finished_at "$finished_at" \
  --arg reports_dir "$reports_dir" \
  --arg report_list_file "$report_list_file" \
  --arg trend_summary_json "$trend_summary_json" \
  --arg alert_summary_json "$alert_summary_json" \
  --arg summary_json "$summary_json" \
  --arg pre_real_host_readiness_summary_json "$pre_real_host_readiness_summary_json" \
  --arg pre_real_host_readiness_log "$pre_real_host_readiness_log" \
  --arg trend_go_rate_pct "$trend_go_rate_pct" \
  --arg alert_severity "$alert_severity" \
  --argjson rounds_requested "$rounds" \
  --argjson rounds_attempted "$rounds_attempted" \
  --argjson rounds_passed "$rounds_passed" \
  --argjson rounds_failed "$rounds_failed" \
  --argjson stopped_early "$(json_bool "$stopped_early")" \
  --argjson continue_on_fail "$(json_bool "$continue_on_fail")" \
  --argjson require_all_rounds_ok "$(json_bool "$require_all_rounds_ok")" \
  --argjson pre_real_host_readiness "$(json_bool "$pre_real_host_readiness")" \
  --argjson trend_fail_on_any_no_go "$(json_bool "$trend_fail_on_any_no_go")" \
  --argjson trend_require_wg_validate_udp_source "$(json_bool "$trend_require_wg_validate_udp_source")" \
  --argjson trend_require_wg_validate_strict_distinct "$(json_bool "$trend_require_wg_validate_strict_distinct")" \
  --argjson trend_require_wg_soak_diversity_pass "$(json_bool "$trend_require_wg_soak_diversity_pass")" \
  --argjson trend_min_wg_soak_selection_lines "$trend_min_wg_soak_selection_lines" \
  --argjson trend_min_wg_soak_entry_operators "$trend_min_wg_soak_entry_operators" \
  --argjson trend_min_wg_soak_exit_operators "$trend_min_wg_soak_exit_operators" \
  --argjson trend_min_wg_soak_cross_operator_pairs "$trend_min_wg_soak_cross_operator_pairs" \
  --argjson trend_show_top_reasons "$trend_show_top_reasons" \
  --argjson trend_max_reports "$trend_max_reports" \
  --argjson trend_since_hours "$trend_since_hours" \
  --argjson trend_min_go_rate_pct "$trend_min_go_rate_pct" \
  --argjson trend_rc "$trend_rc" \
  --argjson alert_rc "$alert_rc" \
  --arg max_alert_severity "$max_alert_severity" \
  --argjson max_alert_severity_rank "$max_alert_severity_rank" \
  --argjson alert_severity_rank "$alert_severity_rank" \
  --argjson alert_gate_violated "$(json_bool "$alert_gate_violated")" \
  --argjson bundle_outputs "$(json_bool "$bundle_outputs")" \
  --argjson bundle_fail_close "$(json_bool "$bundle_fail_close")" \
  --arg bundle_tar "$bundle_tar" \
  --arg bundle_sha256_file "$bundle_sha256_file" \
  --arg bundle_manifest_json "$bundle_manifest_json" \
  --arg bundle_sha256 "$bundle_sha256" \
  --argjson bundle_created "$(json_bool "$bundle_created")" \
  --argjson bundle_rc "$bundle_rc" \
  --arg bundle_error "$bundle_error" \
  --argjson bundle_manifest_created "$(json_bool "$bundle_manifest_created")" \
  --argjson bundle_manifest_rc "$bundle_manifest_rc" \
  --arg bundle_manifest_error "$bundle_manifest_error" \
  --argjson duration_sec "$duration_sec" \
  --argjson pre_real_host_readiness_rc "$pre_real_host_readiness_rc" \
  --arg pre_real_host_readiness_status "$pre_real_host_readiness_status" \
  --arg pre_real_host_readiness_machine_c_ready "$pre_real_host_readiness_machine_c_ready" \
  --arg pre_real_host_readiness_next_command "$pre_real_host_readiness_next_command" \
  --arg pre_real_host_readiness_readiness_status "$pre_real_host_readiness_readiness_status" \
  --arg pre_real_host_readiness_report_summary_json "$pre_real_host_readiness_report_summary_json" \
  --arg pre_real_host_readiness_report_md "$pre_real_host_readiness_report_md" \
  --arg pre_real_host_readiness_defer_no_root "$pre_real_host_readiness_defer_no_root" \
  --arg pre_real_host_readiness_defer_no_root_mode "$pre_real_host_readiness_defer_no_root_mode" \
  --arg pre_real_host_readiness_deferred_no_root "$pre_real_host_readiness_deferred_no_root" \
  --arg pre_real_host_readiness_defer_reason "$pre_real_host_readiness_defer_reason" \
  --argjson pre_real_host_readiness_blockers "$pre_real_host_readiness_blockers_json" \
  --argjson round_results "$round_results_json" \
  --argjson run_reports "$run_reports_json" \
  --argjson final_rc "$final_rc" \
  '{
    status:$status,
    failure_step:($failure_step // ""),
    final_rc:$final_rc,
    started_at:$started_at,
    finished_at:$finished_at,
    duration_sec:$duration_sec,
    rounds:{
      requested:$rounds_requested,
      attempted:$rounds_attempted,
      passed:$rounds_passed,
      failed:$rounds_failed,
      stopped_early:$stopped_early
    },
    policy:{
      continue_on_fail:$continue_on_fail,
      require_all_rounds_ok:$require_all_rounds_ok,
      pre_real_host_readiness:$pre_real_host_readiness,
      pre_real_host_readiness_defer_no_root:($pre_real_host_readiness_defer_no_root == "1"),
      pre_real_host_readiness_defer_mode:($pre_real_host_readiness_defer_no_root_mode // ""),
      trend_fail_on_any_no_go:$trend_fail_on_any_no_go,
      trend_require_wg_validate_udp_source:$trend_require_wg_validate_udp_source,
      trend_require_wg_validate_strict_distinct:$trend_require_wg_validate_strict_distinct,
      trend_require_wg_soak_diversity_pass:$trend_require_wg_soak_diversity_pass,
      trend_min_wg_soak_selection_lines:$trend_min_wg_soak_selection_lines,
      trend_min_wg_soak_entry_operators:$trend_min_wg_soak_entry_operators,
      trend_min_wg_soak_exit_operators:$trend_min_wg_soak_exit_operators,
      trend_min_wg_soak_cross_operator_pairs:$trend_min_wg_soak_cross_operator_pairs,
      trend_show_top_reasons:$trend_show_top_reasons,
      trend_max_reports:$trend_max_reports,
      trend_since_hours:$trend_since_hours,
      trend_min_go_rate_pct:$trend_min_go_rate_pct,
      max_alert_severity:$max_alert_severity,
      bundle_outputs:$bundle_outputs,
      bundle_fail_close:$bundle_fail_close
    },
    artifacts:{
      reports_dir:$reports_dir,
      report_list_file:$report_list_file,
      run_reports:$run_reports,
      pre_real_host_readiness_summary_json:($pre_real_host_readiness_summary_json // ""),
      pre_real_host_readiness_log:($pre_real_host_readiness_log // ""),
      trend_summary_json:$trend_summary_json,
      alert_summary_json:$alert_summary_json,
      summary_json:$summary_json,
      bundle_tar:($bundle_tar // ""),
      bundle_sha256_file:($bundle_sha256_file // ""),
      bundle_manifest_json:($bundle_manifest_json // "")
    },
    trend:{
      rc:$trend_rc,
      go_rate_pct:($trend_go_rate_pct // "")
    },
    pre_real_host_readiness:{
      rc:$pre_real_host_readiness_rc,
      status:($pre_real_host_readiness_status // ""),
      machine_c_smoke_ready:($pre_real_host_readiness_machine_c_ready == "true"),
      next_command:($pre_real_host_readiness_next_command // ""),
      readiness_status:($pre_real_host_readiness_readiness_status // ""),
      summary_json:($pre_real_host_readiness_summary_json // ""),
      log_file:($pre_real_host_readiness_log // ""),
      report_summary_json:($pre_real_host_readiness_report_summary_json // ""),
      report_md:($pre_real_host_readiness_report_md // ""),
      defer_no_root:($pre_real_host_readiness_defer_no_root == "1"),
      defer_mode:($pre_real_host_readiness_defer_no_root_mode // ""),
      deferred_no_root:($pre_real_host_readiness_deferred_no_root == "1"),
      defer_reason:($pre_real_host_readiness_defer_reason // ""),
      blockers:$pre_real_host_readiness_blockers
    },
    alert:{
      rc:$alert_rc,
      severity:($alert_severity // ""),
      severity_rank:$alert_severity_rank,
      max_allowed_severity_rank:$max_alert_severity_rank,
      policy_violation:$alert_gate_violated
    },
    bundle:{
      created:$bundle_created,
      rc:$bundle_rc,
      sha256:($bundle_sha256 // ""),
      error:($bundle_error // ""),
      manifest_created:$bundle_manifest_created,
      manifest_rc:$bundle_manifest_rc,
      manifest_error:($bundle_manifest_error // "")
    },
    round_results:$round_results
  }' >"$summary_json"

echo "[prod-pilot-cohort] status=$status rounds=$rounds_attempted/$rounds requested=$rounds passed=$rounds_passed failed=$rounds_failed"
echo "[prod-pilot-cohort] summary_json=$summary_json"
echo "[prod-pilot-cohort] trend_summary_json=$trend_summary_json"
echo "[prod-pilot-cohort] alert_summary_json=$alert_summary_json"
if [[ "$bundle_outputs" == "1" ]]; then
  echo "[prod-pilot-cohort] bundle_tar=$bundle_tar created=$bundle_created rc=$bundle_rc"
  echo "[prod-pilot-cohort] bundle_sha256_file=$bundle_sha256_file"
  echo "[prod-pilot-cohort] bundle_manifest_json=$bundle_manifest_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  echo "[prod-pilot-cohort] summary_json_payload:"
  cat "$summary_json"
fi

if [[ "$status" != "ok" ]]; then
  exit "$final_rc"
fi
