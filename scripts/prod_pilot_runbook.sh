#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EASY_NODE_SH="${EASY_NODE_SH:-$ROOT_DIR/scripts/easy_node.sh}"

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

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_runbook.sh \
    [--pre-real-host-readiness [0|1]] \
    [--pre-real-host-readiness-summary-json PATH] \
    [three-machine-prod-bundle args...]

Purpose:
  One-command production pilot runbook wrapper for machine C.
  Runs easy-node three-machine-prod-bundle with fail-closed defaults:
  - strict client preflight enabled
  - diagnostics bundle integrity verification enabled
  - artifact signoff policy enabled
  - strict distinct-operator defaults and recommended WG SLO profile
  - automatic SLO dashboard artifact generation (trend + alert + markdown)

Examples:
  ./scripts/prod_pilot_runbook.sh \
    --bootstrap-directory https://A_HOST:8081 \
    --subject pilot-client

  ./scripts/prod_pilot_runbook.sh \
    --directory-a https://A_HOST:8081 \
    --directory-b https://B_HOST:8081 \
    --issuer-url https://A_HOST:8082 \
    --entry-url https://A_HOST:8083 \
    --exit-url https://A_HOST:8084 \
    --bundle-dir .easy-node-logs/prod_pilot_bundle

Notes:
  - Any flags you pass are appended last and can override defaults.
  - pre-real-host readiness runs by default before the bundle flow so runtime
    hygiene and the recorded WG-only selftest stay aligned with machine-C
    operator runbooks. Use --pre-real-host-readiness 0 to skip it.
  - Set EASY_NODE_SH to point at a custom easy_node wrapper if needed.
  - Dashboard generation defaults to non-fail-close. Set
    PROD_PILOT_SLO_DASHBOARD_FAIL_CLOSE=1 to make dashboard failures fail the run
    when bundle execution succeeded.
USAGE
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

if [[ $# -gt 0 ]]; then
  case "${1:-}" in
    -h|--help|help)
      usage
      exit 0
      ;;
  esac
fi

if [[ ! -x "$EASY_NODE_SH" ]]; then
  echo "missing executable easy_node script: $EASY_NODE_SH"
  exit 2
fi

timestamp="$(date +%Y%m%d_%H%M%S)"

declare -a user_args=("$@")
declare -a filtered_user_args=()
user_run_report_json=""
user_bundle_dir=""
user_pre_real_host_readiness_explicit="0"
user_pre_real_host_readiness_value=""
user_pre_real_host_readiness_summary_json=""
idx=0
while ((idx < ${#user_args[@]})); do
  arg="${user_args[idx]}"
  case "$arg" in
    --run-report-json)
      if ((idx + 1 < ${#user_args[@]})); then
        user_run_report_json="${user_args[$((idx + 1))]}"
        filtered_user_args+=("$arg" "${user_args[$((idx + 1))]}")
      fi
      idx=$((idx + 2))
      ;;
    --bundle-dir)
      if ((idx + 1 < ${#user_args[@]})); then
        user_bundle_dir="${user_args[$((idx + 1))]}"
        filtered_user_args+=("$arg" "${user_args[$((idx + 1))]}")
      fi
      idx=$((idx + 2))
      ;;
    --pre-real-host-readiness)
      user_pre_real_host_readiness_explicit="1"
      if ((idx + 1 < ${#user_args[@]})) && [[ "${user_args[$((idx + 1))]}" =~ ^[01]$ ]]; then
        user_pre_real_host_readiness_value="${user_args[$((idx + 1))]}"
        idx=$((idx + 2))
      else
        user_pre_real_host_readiness_value="1"
        idx=$((idx + 1))
      fi
      ;;
    --pre-real-host-readiness-summary-json)
      if ((idx + 1 < ${#user_args[@]})); then
        user_pre_real_host_readiness_summary_json="${user_args[$((idx + 1))]}"
      fi
      idx=$((idx + 2))
      ;;
    *)
      filtered_user_args+=("$arg")
      idx=$((idx + 1))
      ;;
  esac
done

preflight_check="${PROD_PILOT_PREFLIGHT_CHECK:-1}"
preflight_timeout_sec="${PROD_PILOT_PREFLIGHT_TIMEOUT_SEC:-12}"
preflight_require_root="${PROD_PILOT_PREFLIGHT_REQUIRE_ROOT:-1}"
bundle_verify_check="${PROD_PILOT_BUNDLE_VERIFY_CHECK:-1}"
bundle_verify_show_details="${PROD_PILOT_BUNDLE_VERIFY_SHOW_DETAILS:-0}"
run_report_print="${PROD_PILOT_RUN_REPORT_PRINT:-1}"
run_report_json_override="${PROD_PILOT_RUN_REPORT_JSON:-}"
pre_real_host_readiness_default="${PROD_PILOT_PRE_REAL_HOST_READINESS:-1}"
pre_real_host_readiness_summary_json_override="${PROD_PILOT_PRE_REAL_HOST_READINESS_SUMMARY_JSON:-}"
pre_real_host_readiness_defer_no_root_mode="${PROD_PILOT_PRE_REAL_HOST_READINESS_DEFER_NO_ROOT:-auto}"
pre_real_host_readiness_effective_uid="${PROD_PILOT_PRE_REAL_HOST_READINESS_EFFECTIVE_UID_OVERRIDE:-$EUID}"
signoff_check="${PROD_PILOT_SIGNOFF_CHECK:-1}"
signoff_require_full_sequence="${PROD_PILOT_SIGNOFF_REQUIRE_FULL_SEQUENCE:-1}"
signoff_require_wg_validate_ok="${PROD_PILOT_SIGNOFF_REQUIRE_WG_VALIDATE_OK:-1}"
signoff_require_wg_soak_ok="${PROD_PILOT_SIGNOFF_REQUIRE_WG_SOAK_OK:-1}"
signoff_require_wg_validate_udp_source="${PROD_PILOT_SIGNOFF_REQUIRE_WG_VALIDATE_UDP_SOURCE:-1}"
signoff_require_wg_validate_strict_distinct="${PROD_PILOT_SIGNOFF_REQUIRE_WG_VALIDATE_STRICT_DISTINCT:-1}"
signoff_require_wg_soak_diversity_pass="${PROD_PILOT_SIGNOFF_REQUIRE_WG_SOAK_DIVERSITY_PASS:-1}"
signoff_min_wg_soak_selection_lines="${PROD_PILOT_SIGNOFF_MIN_WG_SOAK_SELECTION_LINES:-12}"
signoff_min_wg_soak_entry_operators="${PROD_PILOT_SIGNOFF_MIN_WG_SOAK_ENTRY_OPERATORS:-2}"
signoff_min_wg_soak_exit_operators="${PROD_PILOT_SIGNOFF_MIN_WG_SOAK_EXIT_OPERATORS:-2}"
signoff_min_wg_soak_cross_operator_pairs="${PROD_PILOT_SIGNOFF_MIN_WG_SOAK_CROSS_OPERATOR_PAIRS:-2}"
signoff_max_wg_soak_failed_rounds="${PROD_PILOT_SIGNOFF_MAX_WG_SOAK_FAILED_ROUNDS:-0}"
signoff_show_json="${PROD_PILOT_SIGNOFF_SHOW_JSON:-0}"
discovery_wait_sec="${PROD_PILOT_DISCOVERY_WAIT_SEC:-20}"
min_sources="${PROD_PILOT_MIN_SOURCES:-2}"
min_operators="${PROD_PILOT_MIN_OPERATORS:-2}"
federation_timeout_sec="${PROD_PILOT_FEDERATION_TIMEOUT_SEC:-90}"
control_timeout_sec="${PROD_PILOT_CONTROL_TIMEOUT_SEC:-50}"
control_soak_rounds="${PROD_PILOT_CONTROL_SOAK_ROUNDS:-6}"
control_soak_pause_sec="${PROD_PILOT_CONTROL_SOAK_PAUSE_SEC:-5}"
wg_client_timeout_sec="${PROD_PILOT_WG_CLIENT_TIMEOUT_SEC:-120}"
wg_session_sec="${PROD_PILOT_WG_SESSION_SEC:-30}"
wg_soak_rounds="${PROD_PILOT_WG_SOAK_ROUNDS:-8}"
wg_soak_pause_sec="${PROD_PILOT_WG_SOAK_PAUSE_SEC:-8}"
wg_slo_profile="${PROD_PILOT_WG_SLO_PROFILE:-recommended}"
wg_max_consecutive_failures="${PROD_PILOT_WG_MAX_CONSECUTIVE_FAILURES:-2}"
wg_max_round_duration_sec="${PROD_PILOT_WG_MAX_ROUND_DURATION_SEC:-120}"
wg_max_recovery_sec="${PROD_PILOT_WG_MAX_RECOVERY_SEC:-150}"
wg_max_failure_class="${PROD_PILOT_WG_MAX_FAILURE_CLASS:-strict_ingress_policy=0}"
wg_disallow_unknown_failure_class="${PROD_PILOT_WG_DISALLOW_UNKNOWN_FAILURE_CLASS:-1}"
wg_min_selection_lines="${PROD_PILOT_WG_MIN_SELECTION_LINES:-12}"
wg_min_entry_operators="${PROD_PILOT_WG_MIN_ENTRY_OPERATORS:-2}"
wg_min_exit_operators="${PROD_PILOT_WG_MIN_EXIT_OPERATORS:-2}"
wg_min_cross_operator_pairs="${PROD_PILOT_WG_MIN_CROSS_OPERATOR_PAIRS:-2}"
strict_distinct="${PROD_PILOT_STRICT_DISTINCT:-1}"
skip_control_soak="${PROD_PILOT_SKIP_CONTROL_SOAK:-0}"
skip_wg="${PROD_PILOT_SKIP_WG:-0}"
skip_wg_soak="${PROD_PILOT_SKIP_WG_SOAK:-0}"
control_fault_every="${PROD_PILOT_CONTROL_FAULT_EVERY:-0}"
control_continue_on_fail="${PROD_PILOT_CONTROL_CONTINUE_ON_FAIL:-0}"
wg_fault_every="${PROD_PILOT_WG_FAULT_EVERY:-0}"
wg_continue_on_fail="${PROD_PILOT_WG_CONTINUE_ON_FAIL:-0}"

dashboard_enable="${PROD_PILOT_SLO_DASHBOARD_ENABLE:-1}"
dashboard_fail_close="${PROD_PILOT_SLO_DASHBOARD_FAIL_CLOSE:-0}"
dashboard_max_reports="${PROD_PILOT_SLO_DASHBOARD_MAX_REPORTS:-25}"
dashboard_since_hours="${PROD_PILOT_SLO_DASHBOARD_SINCE_HOURS:-24}"
dashboard_show_top_reasons="${PROD_PILOT_SLO_DASHBOARD_SHOW_TOP_REASONS:-5}"
dashboard_min_go_rate_pct="${PROD_PILOT_SLO_DASHBOARD_MIN_GO_RATE_PCT:-95}"
dashboard_fail_on_any_no_go="${PROD_PILOT_SLO_DASHBOARD_FAIL_ON_ANY_NO_GO:-0}"
dashboard_warn_go_rate_pct="${PROD_PILOT_SLO_DASHBOARD_WARN_GO_RATE_PCT:-98}"
dashboard_critical_go_rate_pct="${PROD_PILOT_SLO_DASHBOARD_CRITICAL_GO_RATE_PCT:-90}"
dashboard_warn_no_go_count="${PROD_PILOT_SLO_DASHBOARD_WARN_NO_GO_COUNT:-1}"
dashboard_critical_no_go_count="${PROD_PILOT_SLO_DASHBOARD_CRITICAL_NO_GO_COUNT:-2}"
dashboard_warn_eval_errors="${PROD_PILOT_SLO_DASHBOARD_WARN_EVAL_ERRORS:-1}"
dashboard_critical_eval_errors="${PROD_PILOT_SLO_DASHBOARD_CRITICAL_EVAL_ERRORS:-2}"
dashboard_fail_on_warn="${PROD_PILOT_SLO_DASHBOARD_FAIL_ON_WARN:-0}"
dashboard_fail_on_critical="${PROD_PILOT_SLO_DASHBOARD_FAIL_ON_CRITICAL:-0}"
dashboard_print="${PROD_PILOT_SLO_DASHBOARD_PRINT:-1}"
dashboard_print_summary_json="${PROD_PILOT_SLO_DASHBOARD_PRINT_SUMMARY_JSON:-0}"
dashboard_out_dir="${PROD_PILOT_SLO_DASHBOARD_OUT_DIR:-}"

bool_or_die "PROD_PILOT_PREFLIGHT_CHECK" "$preflight_check"
bool_or_die "PROD_PILOT_PREFLIGHT_REQUIRE_ROOT" "$preflight_require_root"
bool_or_die "PROD_PILOT_BUNDLE_VERIFY_CHECK" "$bundle_verify_check"
bool_or_die "PROD_PILOT_BUNDLE_VERIFY_SHOW_DETAILS" "$bundle_verify_show_details"
bool_or_die "PROD_PILOT_RUN_REPORT_PRINT" "$run_report_print"
bool_or_die "PROD_PILOT_PRE_REAL_HOST_READINESS" "$pre_real_host_readiness_default"
bool_or_die "PROD_PILOT_SIGNOFF_CHECK" "$signoff_check"
bool_or_die "PROD_PILOT_SIGNOFF_REQUIRE_FULL_SEQUENCE" "$signoff_require_full_sequence"
bool_or_die "PROD_PILOT_SIGNOFF_REQUIRE_WG_VALIDATE_OK" "$signoff_require_wg_validate_ok"
bool_or_die "PROD_PILOT_SIGNOFF_REQUIRE_WG_SOAK_OK" "$signoff_require_wg_soak_ok"
bool_or_die "PROD_PILOT_SIGNOFF_REQUIRE_WG_VALIDATE_UDP_SOURCE" "$signoff_require_wg_validate_udp_source"
bool_or_die "PROD_PILOT_SIGNOFF_REQUIRE_WG_VALIDATE_STRICT_DISTINCT" "$signoff_require_wg_validate_strict_distinct"
bool_or_die "PROD_PILOT_SIGNOFF_REQUIRE_WG_SOAK_DIVERSITY_PASS" "$signoff_require_wg_soak_diversity_pass"
bool_or_die "PROD_PILOT_SIGNOFF_SHOW_JSON" "$signoff_show_json"
bool_or_die "PROD_PILOT_WG_DISALLOW_UNKNOWN_FAILURE_CLASS" "$wg_disallow_unknown_failure_class"
bool_or_die "PROD_PILOT_STRICT_DISTINCT" "$strict_distinct"
bool_or_die "PROD_PILOT_SKIP_CONTROL_SOAK" "$skip_control_soak"
bool_or_die "PROD_PILOT_SKIP_WG" "$skip_wg"
bool_or_die "PROD_PILOT_SKIP_WG_SOAK" "$skip_wg_soak"
bool_or_die "PROD_PILOT_CONTROL_CONTINUE_ON_FAIL" "$control_continue_on_fail"
bool_or_die "PROD_PILOT_WG_CONTINUE_ON_FAIL" "$wg_continue_on_fail"
bool_or_die "PROD_PILOT_SLO_DASHBOARD_ENABLE" "$dashboard_enable"
bool_or_die "PROD_PILOT_SLO_DASHBOARD_FAIL_CLOSE" "$dashboard_fail_close"
bool_or_die "PROD_PILOT_SLO_DASHBOARD_FAIL_ON_ANY_NO_GO" "$dashboard_fail_on_any_no_go"
bool_or_die "PROD_PILOT_SLO_DASHBOARD_FAIL_ON_WARN" "$dashboard_fail_on_warn"
bool_or_die "PROD_PILOT_SLO_DASHBOARD_FAIL_ON_CRITICAL" "$dashboard_fail_on_critical"
bool_or_die "PROD_PILOT_SLO_DASHBOARD_PRINT" "$dashboard_print"
bool_or_die "PROD_PILOT_SLO_DASHBOARD_PRINT_SUMMARY_JSON" "$dashboard_print_summary_json"

int_or_die "PROD_PILOT_PREFLIGHT_TIMEOUT_SEC" "$preflight_timeout_sec"
int_or_die "PROD_PILOT_SIGNOFF_MIN_WG_SOAK_SELECTION_LINES" "$signoff_min_wg_soak_selection_lines"
int_or_die "PROD_PILOT_SIGNOFF_MIN_WG_SOAK_ENTRY_OPERATORS" "$signoff_min_wg_soak_entry_operators"
int_or_die "PROD_PILOT_SIGNOFF_MIN_WG_SOAK_EXIT_OPERATORS" "$signoff_min_wg_soak_exit_operators"
int_or_die "PROD_PILOT_SIGNOFF_MIN_WG_SOAK_CROSS_OPERATOR_PAIRS" "$signoff_min_wg_soak_cross_operator_pairs"
int_or_die "PROD_PILOT_SIGNOFF_MAX_WG_SOAK_FAILED_ROUNDS" "$signoff_max_wg_soak_failed_rounds"
int_or_die "PROD_PILOT_DISCOVERY_WAIT_SEC" "$discovery_wait_sec"
int_or_die "PROD_PILOT_MIN_SOURCES" "$min_sources"
int_or_die "PROD_PILOT_MIN_OPERATORS" "$min_operators"
int_or_die "PROD_PILOT_FEDERATION_TIMEOUT_SEC" "$federation_timeout_sec"
int_or_die "PROD_PILOT_CONTROL_TIMEOUT_SEC" "$control_timeout_sec"
int_or_die "PROD_PILOT_CONTROL_SOAK_ROUNDS" "$control_soak_rounds"
int_or_die "PROD_PILOT_CONTROL_SOAK_PAUSE_SEC" "$control_soak_pause_sec"
int_or_die "PROD_PILOT_WG_CLIENT_TIMEOUT_SEC" "$wg_client_timeout_sec"
int_or_die "PROD_PILOT_WG_SESSION_SEC" "$wg_session_sec"
int_or_die "PROD_PILOT_WG_SOAK_ROUNDS" "$wg_soak_rounds"
int_or_die "PROD_PILOT_WG_SOAK_PAUSE_SEC" "$wg_soak_pause_sec"
int_or_die "PROD_PILOT_WG_MAX_CONSECUTIVE_FAILURES" "$wg_max_consecutive_failures"
int_or_die "PROD_PILOT_WG_MAX_ROUND_DURATION_SEC" "$wg_max_round_duration_sec"
int_or_die "PROD_PILOT_WG_MAX_RECOVERY_SEC" "$wg_max_recovery_sec"
int_or_die "PROD_PILOT_WG_MIN_SELECTION_LINES" "$wg_min_selection_lines"
int_or_die "PROD_PILOT_WG_MIN_ENTRY_OPERATORS" "$wg_min_entry_operators"
int_or_die "PROD_PILOT_WG_MIN_EXIT_OPERATORS" "$wg_min_exit_operators"
int_or_die "PROD_PILOT_WG_MIN_CROSS_OPERATOR_PAIRS" "$wg_min_cross_operator_pairs"
int_or_die "PROD_PILOT_CONTROL_FAULT_EVERY" "$control_fault_every"
int_or_die "PROD_PILOT_WG_FAULT_EVERY" "$wg_fault_every"
int_or_die "PROD_PILOT_SLO_DASHBOARD_MAX_REPORTS" "$dashboard_max_reports"
int_or_die "PROD_PILOT_SLO_DASHBOARD_SINCE_HOURS" "$dashboard_since_hours"
int_or_die "PROD_PILOT_SLO_DASHBOARD_SHOW_TOP_REASONS" "$dashboard_show_top_reasons"
int_or_die "PROD_PILOT_SLO_DASHBOARD_WARN_NO_GO_COUNT" "$dashboard_warn_no_go_count"
int_or_die "PROD_PILOT_SLO_DASHBOARD_CRITICAL_NO_GO_COUNT" "$dashboard_critical_no_go_count"
int_or_die "PROD_PILOT_SLO_DASHBOARD_WARN_EVAL_ERRORS" "$dashboard_warn_eval_errors"
int_or_die "PROD_PILOT_SLO_DASHBOARD_CRITICAL_EVAL_ERRORS" "$dashboard_critical_eval_errors"

if [[ "$pre_real_host_readiness_defer_no_root_mode" != "auto" && "$pre_real_host_readiness_defer_no_root_mode" != "0" && "$pre_real_host_readiness_defer_no_root_mode" != "1" ]]; then
  echo "PROD_PILOT_PRE_REAL_HOST_READINESS_DEFER_NO_ROOT must be one of: auto, 0, 1"
  exit 2
fi
if [[ ! "$pre_real_host_readiness_effective_uid" =~ ^[0-9]+$ ]]; then
  echo "PROD_PILOT_PRE_REAL_HOST_READINESS_EFFECTIVE_UID_OVERRIDE must be an integer >= 0"
  exit 2
fi

if [[ "$wg_slo_profile" != "off" && "$wg_slo_profile" != "recommended" && "$wg_slo_profile" != "strict" ]]; then
  echo "PROD_PILOT_WG_SLO_PROFILE must be one of: off, recommended, strict"
  exit 2
fi

run_report_json_path=""
if [[ -n "$user_run_report_json" ]]; then
  run_report_json_path="$user_run_report_json"
elif [[ -n "$run_report_json_override" ]]; then
  run_report_json_path="$run_report_json_override"
elif [[ -n "$user_bundle_dir" ]]; then
  run_report_json_path="$user_bundle_dir/prod_bundle_run_report.json"
else
  run_report_json_path="$(default_log_dir)/prod_pilot_run_report_${timestamp}.json"
fi

pre_real_host_readiness="$pre_real_host_readiness_default"
if [[ "$user_pre_real_host_readiness_explicit" == "1" ]]; then
  pre_real_host_readiness="$user_pre_real_host_readiness_value"
fi

pre_real_host_readiness_summary_json_path=""
if [[ -n "$user_pre_real_host_readiness_summary_json" ]]; then
  pre_real_host_readiness_summary_json_path="$user_pre_real_host_readiness_summary_json"
elif [[ -n "$pre_real_host_readiness_summary_json_override" ]]; then
  pre_real_host_readiness_summary_json_path="$pre_real_host_readiness_summary_json_override"
elif [[ -n "$user_bundle_dir" ]]; then
  pre_real_host_readiness_summary_json_path="$user_bundle_dir/prod_pilot_pre_real_host_readiness.json"
else
  pre_real_host_readiness_summary_json_path="$(default_log_dir)/prod_pilot_pre_real_host_readiness_${timestamp}.json"
fi

pre_real_host_readiness_log_path="$(dirname "$(abs_path "$pre_real_host_readiness_summary_json_path")")/prod_pilot_pre_real_host_readiness_${timestamp}.log"

pre_real_host_readiness_defer_no_root="0"
if [[ "$pre_real_host_readiness_defer_no_root_mode" == "auto" ]]; then
  if [[ "$pre_real_host_readiness_effective_uid" -ne 0 ]]; then
    pre_real_host_readiness_defer_no_root="1"
  fi
else
  pre_real_host_readiness_defer_no_root="$pre_real_host_readiness_defer_no_root_mode"
fi

cmd=(
  "$EASY_NODE_SH" "three-machine-prod-bundle"
  "--preflight-check" "$preflight_check"
  "--preflight-timeout-sec" "$preflight_timeout_sec"
  "--preflight-require-root" "$preflight_require_root"
  "--bundle-verify-check" "$bundle_verify_check"
  "--bundle-verify-show-details" "$bundle_verify_show_details"
  "--run-report-print" "$run_report_print"
  "--signoff-check" "$signoff_check"
  "--signoff-require-full-sequence" "$signoff_require_full_sequence"
  "--signoff-require-wg-validate-ok" "$signoff_require_wg_validate_ok"
  "--signoff-require-wg-soak-ok" "$signoff_require_wg_soak_ok"
  "--signoff-require-wg-validate-udp-source" "$signoff_require_wg_validate_udp_source"
  "--signoff-require-wg-validate-strict-distinct" "$signoff_require_wg_validate_strict_distinct"
  "--signoff-require-wg-soak-diversity-pass" "$signoff_require_wg_soak_diversity_pass"
  "--signoff-min-wg-soak-selection-lines" "$signoff_min_wg_soak_selection_lines"
  "--signoff-min-wg-soak-entry-operators" "$signoff_min_wg_soak_entry_operators"
  "--signoff-min-wg-soak-exit-operators" "$signoff_min_wg_soak_exit_operators"
  "--signoff-min-wg-soak-cross-operator-pairs" "$signoff_min_wg_soak_cross_operator_pairs"
  "--signoff-max-wg-soak-failed-rounds" "$signoff_max_wg_soak_failed_rounds"
  "--signoff-show-json" "$signoff_show_json"
  "--discovery-wait-sec" "$discovery_wait_sec"
  "--min-sources" "$min_sources"
  "--min-operators" "$min_operators"
  "--federation-timeout-sec" "$federation_timeout_sec"
  "--control-timeout-sec" "$control_timeout_sec"
  "--control-soak-rounds" "$control_soak_rounds"
  "--control-soak-pause-sec" "$control_soak_pause_sec"
  "--wg-client-timeout-sec" "$wg_client_timeout_sec"
  "--wg-session-sec" "$wg_session_sec"
  "--wg-soak-rounds" "$wg_soak_rounds"
  "--wg-soak-pause-sec" "$wg_soak_pause_sec"
  "--wg-slo-profile" "$wg_slo_profile"
  "--wg-max-consecutive-failures" "$wg_max_consecutive_failures"
  "--wg-max-round-duration-sec" "$wg_max_round_duration_sec"
  "--wg-max-recovery-sec" "$wg_max_recovery_sec"
  "--wg-max-failure-class" "$wg_max_failure_class"
  "--wg-disallow-unknown-failure-class" "$wg_disallow_unknown_failure_class"
  "--wg-min-selection-lines" "$wg_min_selection_lines"
  "--wg-min-entry-operators" "$wg_min_entry_operators"
  "--wg-min-exit-operators" "$wg_min_exit_operators"
  "--wg-min-cross-operator-pairs" "$wg_min_cross_operator_pairs"
  "--strict-distinct" "$strict_distinct"
  "--skip-control-soak" "$skip_control_soak"
  "--skip-wg" "$skip_wg"
  "--skip-wg-soak" "$skip_wg_soak"
  "--control-fault-every" "$control_fault_every"
  "--control-continue-on-fail" "$control_continue_on_fail"
  "--wg-fault-every" "$wg_fault_every"
  "--wg-continue-on-fail" "$wg_continue_on_fail"
  "--mtls-ca-file" "deploy/tls/ca.crt"
  "--mtls-client-cert-file" "deploy/tls/client.crt"
  "--mtls-client-key-file" "deploy/tls/client.key"
)

if [[ -z "$user_run_report_json" && -n "$run_report_json_path" ]]; then
  cmd+=("--run-report-json" "$run_report_json_path")
fi

if [[ ${#filtered_user_args[@]} -gt 0 ]]; then
  cmd+=("${filtered_user_args[@]}")
fi

if [[ "$pre_real_host_readiness" == "1" ]]; then
  mkdir -p "$(dirname "$pre_real_host_readiness_log_path")" "$(dirname "$(abs_path "$pre_real_host_readiness_summary_json_path")")"
  pre_real_host_readiness_cmd=(
    "$EASY_NODE_SH" "pre-real-host-readiness"
    "--defer-no-root" "$pre_real_host_readiness_defer_no_root"
    "--summary-json" "$pre_real_host_readiness_summary_json_path"
    "--print-summary-json" "1"
  )

  echo "[prod-pilot-runbook] running pre-real-host readiness gate"
  echo "[prod-pilot-runbook] pre_real_host_readiness_summary_json=$pre_real_host_readiness_summary_json_path"
  echo "[prod-pilot-runbook] pre_real_host_readiness_log=$pre_real_host_readiness_log_path"
  echo "[prod-pilot-runbook] pre_real_host_readiness_defer_no_root=$pre_real_host_readiness_defer_no_root mode=$pre_real_host_readiness_defer_no_root_mode effective_uid=$pre_real_host_readiness_effective_uid"
  set +e
  "${pre_real_host_readiness_cmd[@]}" 2>&1 | tee "$pre_real_host_readiness_log_path"
  pre_real_host_readiness_rc=${PIPESTATUS[0]}
  set -e
  if [[ "$pre_real_host_readiness_rc" -ne 0 ]]; then
    pre_real_host_readiness_root_only_deferred="0"
    if [[ -f "$pre_real_host_readiness_summary_json_path" ]] && jq -e . "$pre_real_host_readiness_summary_json_path" >/dev/null 2>&1; then
      pre_real_host_readiness_root_only_deferred="$(
        jq -r '
          (.machine_c_smoke_gate.blockers // []) as $blockers
          | (.wg_only_stack_selftest.status // "") as $wg_status
          | (.stage // "") as $stage
          | (((.wg_only_stack_selftest.notes // "") + "\n" + (.notes // "")) | test("requires root"; "i")) as $root_hint
          | (
              (($blockers | type) == "array")
              and (($blockers | length) == 1)
              and (($blockers[0] // "") == "wg_only_stack_selftest")
              and ($wg_status == "skip")
              and ($stage == "wg_only_stack_selftest")
              and $root_hint
            )
          | if . then "1" else "0" end
        ' "$pre_real_host_readiness_summary_json_path" 2>/dev/null || printf '0'
      )"
    fi
    if [[ "$pre_real_host_readiness_root_only_deferred" == "1" ]]; then
      echo "[prod-pilot-runbook] warning: pre-real-host readiness reported root-only deferred condition; continuing to bundle flow."
      echo "[prod-pilot-runbook] warning: rerun pre-real-host readiness with sudo before final production signoff."
    else
      echo "[prod-pilot-runbook] pre-real-host readiness blocked pilot runbook: rc=$pre_real_host_readiness_rc"
      exit "$pre_real_host_readiness_rc"
    fi
  fi
fi

echo "[prod-pilot-runbook] running production bundle flow with strict fail-closed defaults"
echo "[prod-pilot-runbook] easy_node=$EASY_NODE_SH"
echo "[prod-pilot-runbook] run_report_json_target=$run_report_json_path"

set +e
"${cmd[@]}"
rc=$?
set -e

final_rc="$rc"
dashboard_rc=0
dashboard_attempted=0
dashboard_trend_json=""
dashboard_alert_json=""
dashboard_md=""

if [[ "$dashboard_enable" == "1" ]]; then
  dashboard_attempted=1
  resolved_run_report_json="$(abs_path "$run_report_json_path")"
  resolved_logs_dir="$(abs_path "$(default_log_dir)")"

  dashboard_base_dir=""
  if [[ -n "$dashboard_out_dir" ]]; then
    dashboard_base_dir="$(abs_path "$dashboard_out_dir")"
  elif [[ -n "$resolved_run_report_json" ]]; then
    dashboard_base_dir="$(dirname "$resolved_run_report_json")"
  else
    dashboard_base_dir="$resolved_logs_dir"
  fi

  dashboard_trend_json="$dashboard_base_dir/prod_pilot_slo_trend_${timestamp}.json"
  dashboard_alert_json="$dashboard_base_dir/prod_pilot_slo_alert_${timestamp}.json"
  dashboard_md="$dashboard_base_dir/prod_pilot_slo_dashboard_${timestamp}.md"

  dashboard_cmd=(
    "$EASY_NODE_SH" "prod-gate-slo-dashboard"
    "--max-reports" "$dashboard_max_reports"
    "--since-hours" "$dashboard_since_hours"
    "--require-full-sequence" "$signoff_require_full_sequence"
    "--require-wg-validate-ok" "$signoff_require_wg_validate_ok"
    "--require-wg-soak-ok" "$signoff_require_wg_soak_ok"
    "--require-wg-validate-udp-source" "$signoff_require_wg_validate_udp_source"
    "--require-wg-validate-strict-distinct" "$signoff_require_wg_validate_strict_distinct"
    "--require-wg-soak-diversity-pass" "$signoff_require_wg_soak_diversity_pass"
    "--min-wg-soak-selection-lines" "$signoff_min_wg_soak_selection_lines"
    "--min-wg-soak-entry-operators" "$signoff_min_wg_soak_entry_operators"
    "--min-wg-soak-exit-operators" "$signoff_min_wg_soak_exit_operators"
    "--min-wg-soak-cross-operator-pairs" "$signoff_min_wg_soak_cross_operator_pairs"
    "--max-wg-soak-failed-rounds" "$signoff_max_wg_soak_failed_rounds"
    "--require-preflight-ok" "$preflight_check"
    "--require-bundle-ok" "1"
    "--require-integrity-ok" "$bundle_verify_check"
    "--require-signoff-ok" "$signoff_check"
    "--fail-on-any-no-go" "$dashboard_fail_on_any_no_go"
    "--min-go-rate-pct" "$dashboard_min_go_rate_pct"
    "--show-top-reasons" "$dashboard_show_top_reasons"
    "--warn-go-rate-pct" "$dashboard_warn_go_rate_pct"
    "--critical-go-rate-pct" "$dashboard_critical_go_rate_pct"
    "--warn-no-go-count" "$dashboard_warn_no_go_count"
    "--critical-no-go-count" "$dashboard_critical_no_go_count"
    "--warn-eval-errors" "$dashboard_warn_eval_errors"
    "--critical-eval-errors" "$dashboard_critical_eval_errors"
    "--fail-on-warn" "$dashboard_fail_on_warn"
    "--fail-on-critical" "$dashboard_fail_on_critical"
    "--trend-summary-json" "$dashboard_trend_json"
    "--alert-summary-json" "$dashboard_alert_json"
    "--dashboard-md" "$dashboard_md"
    "--print-dashboard" "$dashboard_print"
    "--print-summary-json" "$dashboard_print_summary_json"
  )

  if [[ -n "$resolved_run_report_json" && -f "$resolved_run_report_json" ]]; then
    dashboard_cmd+=("--run-report-json" "$resolved_run_report_json")
    dashboard_cmd+=("--max-reports" "1" "--since-hours" "0")
  else
    dashboard_cmd+=("--reports-dir" "$resolved_logs_dir")
  fi

  echo "[prod-pilot-runbook] running auto dashboard generation"
  set +e
  "${dashboard_cmd[@]}"
  dashboard_rc=$?
  set -e

  echo "[prod-pilot-runbook] dashboard_rc=$dashboard_rc"
  echo "[prod-pilot-runbook] dashboard_trend_json=$dashboard_trend_json"
  echo "[prod-pilot-runbook] dashboard_alert_json=$dashboard_alert_json"
  echo "[prod-pilot-runbook] dashboard_md=$dashboard_md"
fi

if [[ "$rc" -eq 0 ]]; then
  if [[ "$dashboard_attempted" == "1" && "$dashboard_rc" -ne 0 ]]; then
    if [[ "$dashboard_fail_close" == "1" ]]; then
      final_rc="$dashboard_rc"
      echo "[prod-pilot-runbook] bundle succeeded but dashboard failed (fail-close enabled): rc=$dashboard_rc"
    else
      echo "[prod-pilot-runbook] warning: bundle succeeded but dashboard generation failed (fail-close disabled): rc=$dashboard_rc"
    fi
  fi
fi

if [[ "$final_rc" -eq 0 ]]; then
  echo "[prod-pilot-runbook] completed successfully"
else
  echo "[prod-pilot-runbook] failed rc=$final_rc"
fi
exit "$final_rc"
