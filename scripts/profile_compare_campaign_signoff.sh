#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CAMPAIGN_SCRIPT="${PROFILE_COMPARE_CAMPAIGN_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign.sh}"
CAMPAIGN_CHECK_SCRIPT="${PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign_check.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_campaign_signoff.sh \
    [--reports-dir DIR] \
    [--campaign-summary-json PATH] \
    [--campaign-report-md PATH] \
    [--campaign-check-summary-json PATH] \
    [--refresh-campaign [0|1]] \
    [--fail-on-no-go [0|1]] \
    [--allow-summary-overwrite [0|1]] \
    [--require-status-pass [0|1]] \
    [--require-trend-status-pass [0|1]] \
    [--require-min-runs-total N] \
    [--require-max-runs-fail N] \
    [--require-max-runs-warn N] \
    [--require-min-runs-with-summary N] \
    [--require-recommendation-support-rate-pct N] \
    [--require-recommended-profile PROFILE] \
    [--allow-recommended-profiles CSV] \
    [--disallow-experimental-default [0|1]] \
    [--require-trend-source CSV] \
    [--campaign-execution-mode docker|local] \
    [--campaign-directory-urls URL[,URL...]] \
    [--campaign-bootstrap-directory URL] \
    [--campaign-discovery-wait-sec N] \
    [--campaign-issuer-url URL] \
    [--campaign-entry-url URL] \
    [--campaign-exit-url URL] \
    [--campaign-start-local-stack auto|0|1] \
    [--summary-json PATH] \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Run optional profile-compare campaign refresh and then apply the
  fail-closed campaign check gate in one command, writing one signoff
  summary artifact for handoff.

Notes:
  - Default behavior refreshes campaign artifacts first (--refresh-campaign 1).
  - Keep --allow-summary-overwrite 0 in normal operation to avoid output
    path collisions across campaign/check/signoff artifacts.
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

optional_bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    return
  fi
  bool_arg_or_die "$name" "$value"
}

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

quote_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
campaign_summary_json="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_SUMMARY_JSON:-}"
campaign_report_md="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_REPORT_MD:-}"
campaign_check_summary_json="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_CHECK_SUMMARY_JSON:-}"
refresh_campaign="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REFRESH_CAMPAIGN:-1}"
fail_on_no_go="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_FAIL_ON_NO_GO:-1}"
allow_summary_overwrite="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_ALLOW_SUMMARY_OVERWRITE:-0}"
summary_json="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SUMMARY_JSON:-}"
show_json="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SHOW_JSON:-0}"
print_summary_json="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_PRINT_SUMMARY_JSON:-0}"

require_status_pass="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_STATUS_PASS:-}"
require_trend_status_pass="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_TREND_STATUS_PASS:-}"
require_min_runs_total="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_MIN_RUNS_TOTAL:-}"
require_max_runs_fail="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_MAX_RUNS_FAIL:-}"
require_max_runs_warn="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_MAX_RUNS_WARN:-}"
require_min_runs_with_summary="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_MIN_RUNS_WITH_SUMMARY:-}"
require_recommendation_support_rate_pct="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_RECOMMENDATION_SUPPORT_RATE_PCT:-}"
require_recommended_profile="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_RECOMMENDED_PROFILE:-}"
allow_recommended_profiles="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_ALLOW_RECOMMENDED_PROFILES:-}"
disallow_experimental_default="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_DISALLOW_EXPERIMENTAL_DEFAULT:-}"
require_trend_source="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_TREND_SOURCE:-}"
campaign_execution_mode="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_EXECUTION_MODE:-}"
campaign_directory_urls="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_DIRECTORY_URLS:-}"
campaign_bootstrap_directory="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_BOOTSTRAP_DIRECTORY:-}"
campaign_discovery_wait_sec="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_DISCOVERY_WAIT_SEC:-}"
campaign_issuer_url="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_ISSUER_URL:-}"
campaign_entry_url="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_ENTRY_URL:-}"
campaign_exit_url="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_EXIT_URL:-}"
campaign_start_local_stack="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_START_LOCAL_STACK:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --campaign-summary-json)
      campaign_summary_json="${2:-}"
      shift 2
      ;;
    --campaign-report-md)
      campaign_report_md="${2:-}"
      shift 2
      ;;
    --campaign-check-summary-json)
      campaign_check_summary_json="${2:-}"
      shift 2
      ;;
    --refresh-campaign)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_campaign="${2:-}"
        shift 2
      else
        refresh_campaign="1"
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
    --allow-summary-overwrite)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_summary_overwrite="${2:-}"
        shift 2
      else
        allow_summary_overwrite="1"
        shift
      fi
      ;;
    --require-status-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_status_pass="${2:-}"
        shift 2
      else
        require_status_pass="1"
        shift
      fi
      ;;
    --require-trend-status-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_trend_status_pass="${2:-}"
        shift 2
      else
        require_trend_status_pass="1"
        shift
      fi
      ;;
    --require-min-runs-total)
      require_min_runs_total="${2:-}"
      shift 2
      ;;
    --require-max-runs-fail)
      require_max_runs_fail="${2:-}"
      shift 2
      ;;
    --require-max-runs-warn)
      require_max_runs_warn="${2:-}"
      shift 2
      ;;
    --require-min-runs-with-summary)
      require_min_runs_with_summary="${2:-}"
      shift 2
      ;;
    --require-recommendation-support-rate-pct)
      require_recommendation_support_rate_pct="${2:-}"
      shift 2
      ;;
    --require-recommended-profile)
      require_recommended_profile="${2:-}"
      shift 2
      ;;
    --allow-recommended-profiles)
      allow_recommended_profiles="${2:-}"
      shift 2
      ;;
    --disallow-experimental-default)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        disallow_experimental_default="${2:-}"
        shift 2
      else
        disallow_experimental_default="1"
        shift
      fi
      ;;
    --require-trend-source)
      require_trend_source="${2:-}"
      shift 2
      ;;
    --campaign-execution-mode)
      campaign_execution_mode="${2:-}"
      shift 2
      ;;
    --campaign-directory-urls)
      campaign_directory_urls="${2:-}"
      shift 2
      ;;
    --campaign-bootstrap-directory)
      campaign_bootstrap_directory="${2:-}"
      shift 2
      ;;
    --campaign-discovery-wait-sec)
      campaign_discovery_wait_sec="${2:-}"
      shift 2
      ;;
    --campaign-issuer-url)
      campaign_issuer_url="${2:-}"
      shift 2
      ;;
    --campaign-entry-url)
      campaign_entry_url="${2:-}"
      shift 2
      ;;
    --campaign-exit-url)
      campaign_exit_url="${2:-}"
      shift 2
      ;;
    --campaign-start-local-stack)
      campaign_start_local_stack="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
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

bool_arg_or_die "--refresh-campaign" "$refresh_campaign"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--allow-summary-overwrite" "$allow_summary_overwrite"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

optional_bool_arg_or_die "--require-status-pass" "$require_status_pass"
optional_bool_arg_or_die "--require-trend-status-pass" "$require_trend_status_pass"
optional_bool_arg_or_die "--disallow-experimental-default" "$disallow_experimental_default"

for int_arg in "$require_min_runs_total" "$require_max_runs_fail" "$require_max_runs_warn" "$require_min_runs_with_summary"; do
  if [[ -n "$int_arg" && ! "$int_arg" =~ ^[0-9]+$ ]]; then
    echo "run count thresholds must be non-negative integers"
    exit 2
  fi
done
if [[ -n "$require_recommendation_support_rate_pct" ]] && ! is_non_negative_decimal "$require_recommendation_support_rate_pct"; then
  echo "--require-recommendation-support-rate-pct must be a non-negative number"
  exit 2
fi
if [[ -n "$campaign_execution_mode" && "$campaign_execution_mode" != "docker" && "$campaign_execution_mode" != "local" ]]; then
  echo "--campaign-execution-mode must be docker or local"
  exit 2
fi
if [[ -n "$campaign_discovery_wait_sec" && ! "$campaign_discovery_wait_sec" =~ ^[0-9]+$ ]]; then
  echo "--campaign-discovery-wait-sec must be an integer"
  exit 2
fi
if [[ -n "$campaign_start_local_stack" ]]; then
  case "$campaign_start_local_stack" in
    auto|0|1) ;;
    *)
      echo "--campaign-start-local-stack must be one of: auto, 0, 1"
      exit 2
      ;;
  esac
fi

if [[ ! -x "$CAMPAIGN_SCRIPT" ]]; then
  echo "missing executable campaign script: $CAMPAIGN_SCRIPT"
  exit 2
fi
if [[ ! -x "$CAMPAIGN_CHECK_SCRIPT" ]]; then
  echo "missing executable campaign-check script: $CAMPAIGN_CHECK_SCRIPT"
  exit 2
fi

reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -n "$campaign_summary_json" ]]; then
  campaign_summary_json="$(abs_path "$campaign_summary_json")"
else
  campaign_summary_json="$reports_dir/profile_compare_campaign_summary.json"
fi
if [[ -n "$campaign_report_md" ]]; then
  campaign_report_md="$(abs_path "$campaign_report_md")"
else
  campaign_report_md="$reports_dir/profile_compare_campaign_report.md"
fi
if [[ -n "$campaign_check_summary_json" ]]; then
  campaign_check_summary_json="$(abs_path "$campaign_check_summary_json")"
else
  campaign_check_summary_json="$reports_dir/profile_compare_campaign_check_summary.json"
fi
if [[ -n "$summary_json" ]]; then
  summary_json="$(abs_path "$summary_json")"
else
  summary_json="$reports_dir/profile_compare_campaign_signoff_summary.json"
fi

mkdir -p "$(dirname "$campaign_summary_json")" "$(dirname "$campaign_report_md")" "$(dirname "$campaign_check_summary_json")" "$(dirname "$summary_json")"

if [[ "$allow_summary_overwrite" == "0" ]]; then
  if [[ "$summary_json" == "$campaign_summary_json" || "$summary_json" == "$campaign_check_summary_json" || "$summary_json" == "$campaign_report_md" ]]; then
    echo "profile-compare-campaign-signoff failed: summary-json path collides with campaign artifact path"
    exit 2
  fi
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"
campaign_log="$log_dir/profile_compare_campaign_signoff_${run_stamp}_campaign.log"
check_log="$log_dir/profile_compare_campaign_signoff_${run_stamp}_campaign_check.log"

campaign_attempted=0
campaign_status="skip"
campaign_rc=0
campaign_cmd_line=""

check_attempted=0
check_status="skip"
check_rc=0
check_cmd_line=""

status="ok"
final_rc=0
failure_stage=""

campaign_cmd=(
  "$CAMPAIGN_SCRIPT"
  --reports-dir "$reports_dir"
  --summary-json "$campaign_summary_json"
  --report-md "$campaign_report_md"
  --print-summary-json 0
)
if [[ -n "$campaign_execution_mode" ]]; then
  campaign_cmd+=(--execution-mode "$campaign_execution_mode")
fi
if [[ -n "$campaign_directory_urls" ]]; then
  campaign_cmd+=(--directory-urls "$campaign_directory_urls")
fi
if [[ -n "$campaign_bootstrap_directory" ]]; then
  campaign_cmd+=(--bootstrap-directory "$campaign_bootstrap_directory")
fi
if [[ -n "$campaign_discovery_wait_sec" ]]; then
  campaign_cmd+=(--discovery-wait-sec "$campaign_discovery_wait_sec")
fi
if [[ -n "$campaign_issuer_url" ]]; then
  campaign_cmd+=(--issuer-url "$campaign_issuer_url")
fi
if [[ -n "$campaign_entry_url" ]]; then
  campaign_cmd+=(--entry-url "$campaign_entry_url")
fi
if [[ -n "$campaign_exit_url" ]]; then
  campaign_cmd+=(--exit-url "$campaign_exit_url")
fi
if [[ -n "$campaign_start_local_stack" ]]; then
  campaign_cmd+=(--start-local-stack "$campaign_start_local_stack")
fi
campaign_cmd_line="$(quote_cmd "${campaign_cmd[@]}")"

if [[ "$refresh_campaign" == "1" ]]; then
  campaign_attempted=1
  if "${campaign_cmd[@]}" >"$campaign_log" 2>&1; then
    campaign_status="pass"
    campaign_rc=0
  else
    campaign_rc=$?
    campaign_status="fail"
    status="fail"
    final_rc="$campaign_rc"
    failure_stage="campaign"
  fi
fi

check_cmd=(
  "$CAMPAIGN_CHECK_SCRIPT"
  --campaign-summary-json "$campaign_summary_json"
  --summary-json "$campaign_check_summary_json"
  --fail-on-no-go "$fail_on_no_go"
  --show-json "$show_json"
  --print-summary-json 0
)

if [[ -n "$require_status_pass" ]]; then
  check_cmd+=(--require-status-pass "$require_status_pass")
fi
if [[ -n "$require_trend_status_pass" ]]; then
  check_cmd+=(--require-trend-status-pass "$require_trend_status_pass")
fi
if [[ -n "$require_min_runs_total" ]]; then
  check_cmd+=(--require-min-runs-total "$require_min_runs_total")
fi
if [[ -n "$require_max_runs_fail" ]]; then
  check_cmd+=(--require-max-runs-fail "$require_max_runs_fail")
fi
if [[ -n "$require_max_runs_warn" ]]; then
  check_cmd+=(--require-max-runs-warn "$require_max_runs_warn")
fi
if [[ -n "$require_min_runs_with_summary" ]]; then
  check_cmd+=(--require-min-runs-with-summary "$require_min_runs_with_summary")
fi
if [[ -n "$require_recommendation_support_rate_pct" ]]; then
  check_cmd+=(--require-recommendation-support-rate-pct "$require_recommendation_support_rate_pct")
fi
if [[ -n "$require_recommended_profile" ]]; then
  check_cmd+=(--require-recommended-profile "$require_recommended_profile")
fi
if [[ -n "$allow_recommended_profiles" ]]; then
  check_cmd+=(--allow-recommended-profiles "$allow_recommended_profiles")
fi
if [[ -n "$disallow_experimental_default" ]]; then
  check_cmd+=(--disallow-experimental-default "$disallow_experimental_default")
fi
if [[ -n "$require_trend_source" ]]; then
  check_cmd+=(--require-trend-source "$require_trend_source")
fi

check_cmd_line="$(quote_cmd "${check_cmd[@]}")"

if [[ -z "$failure_stage" ]]; then
  check_attempted=1
  if "${check_cmd[@]}" >"$check_log" 2>&1; then
    check_status="pass"
    check_rc=0
  else
    check_rc=$?
    check_status="fail"
    status="fail"
    final_rc="$check_rc"
    failure_stage="campaign_check"
  fi
fi

if [[ -z "$failure_stage" ]]; then
  final_rc=0
  status="ok"
fi

decision="unknown"
recommended_profile=""
support_rate_pct="0"
trend_source_value=""
if [[ -f "$campaign_check_summary_json" ]] && jq -e . "$campaign_check_summary_json" >/dev/null 2>&1; then
  decision="$(jq -r '.decision // "unknown"' "$campaign_check_summary_json")"
  recommended_profile="$(jq -r '.observed.recommended_profile // ""' "$campaign_check_summary_json")"
  support_rate_pct="$(jq -r '.observed.support_rate_pct // 0' "$campaign_check_summary_json")"
  trend_source_value="$(jq -r '.observed.trend_source // ""' "$campaign_check_summary_json")"
fi
if ! is_non_negative_decimal "$support_rate_pct"; then
  support_rate_pct="0"
fi

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"

jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$status" \
  --argjson final_rc "$final_rc" \
  --arg failure_stage "$failure_stage" \
  --arg reports_dir "$reports_dir" \
  --arg campaign_summary_json "$campaign_summary_json" \
  --arg campaign_report_md "$campaign_report_md" \
  --arg campaign_check_summary_json "$campaign_check_summary_json" \
  --arg summary_json "$summary_json" \
  --arg campaign_log "$campaign_log" \
  --arg check_log "$check_log" \
  --arg campaign_cmd "$campaign_cmd_line" \
  --arg check_cmd "$check_cmd_line" \
  --arg decision "$decision" \
  --arg recommended_profile "$recommended_profile" \
  --arg support_rate_pct "$support_rate_pct" \
  --arg trend_source "$trend_source_value" \
  --arg refresh_campaign "$refresh_campaign" \
  --arg fail_on_no_go "$fail_on_no_go" \
  --arg require_status_pass "$require_status_pass" \
  --arg require_trend_status_pass "$require_trend_status_pass" \
  --arg require_min_runs_total "$require_min_runs_total" \
  --arg require_max_runs_fail "$require_max_runs_fail" \
  --arg require_max_runs_warn "$require_max_runs_warn" \
  --arg require_min_runs_with_summary "$require_min_runs_with_summary" \
  --arg require_recommendation_support_rate_pct "$require_recommendation_support_rate_pct" \
  --arg require_recommended_profile "$require_recommended_profile" \
  --arg allow_recommended_profiles "$allow_recommended_profiles" \
  --arg disallow_experimental_default "$disallow_experimental_default" \
  --arg require_trend_source "$require_trend_source" \
  --arg campaign_execution_mode "$campaign_execution_mode" \
  --arg campaign_directory_urls "$campaign_directory_urls" \
  --arg campaign_bootstrap_directory "$campaign_bootstrap_directory" \
  --arg campaign_discovery_wait_sec "$campaign_discovery_wait_sec" \
  --arg campaign_issuer_url "$campaign_issuer_url" \
  --arg campaign_entry_url "$campaign_entry_url" \
  --arg campaign_exit_url "$campaign_exit_url" \
  --arg campaign_start_local_stack "$campaign_start_local_stack" \
  --argjson campaign_attempted "$campaign_attempted" \
  --arg campaign_status "$campaign_status" \
  --argjson campaign_rc "$campaign_rc" \
  --argjson check_attempted "$check_attempted" \
  --arg check_status "$check_status" \
  --argjson check_rc "$check_rc" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    status: $status,
    final_rc: $final_rc,
    failure_stage: $failure_stage,
    inputs: {
      reports_dir: $reports_dir,
      refresh_campaign: ($refresh_campaign == "1"),
      fail_on_no_go: ($fail_on_no_go == "1"),
      policy: {
        require_status_pass: (if $require_status_pass == "" then null else ($require_status_pass | tonumber) end),
        require_trend_status_pass: (if $require_trend_status_pass == "" then null else ($require_trend_status_pass | tonumber) end),
        require_min_runs_total: (if $require_min_runs_total == "" then null else ($require_min_runs_total | tonumber) end),
        require_max_runs_fail: (if $require_max_runs_fail == "" then null else ($require_max_runs_fail | tonumber) end),
        require_max_runs_warn: (if $require_max_runs_warn == "" then null else ($require_max_runs_warn | tonumber) end),
        require_min_runs_with_summary: (if $require_min_runs_with_summary == "" then null else ($require_min_runs_with_summary | tonumber) end),
        require_recommendation_support_rate_pct: (if $require_recommendation_support_rate_pct == "" then null else ($require_recommendation_support_rate_pct | tonumber) end),
        require_recommended_profile: (if $require_recommended_profile == "" then null else $require_recommended_profile end),
        allow_recommended_profiles: (if $allow_recommended_profiles == "" then null else ($allow_recommended_profiles | split(",") | map(gsub("^\\s+|\\s+$"; "") | select(length > 0))) end),
        disallow_experimental_default: (if $disallow_experimental_default == "" then null else ($disallow_experimental_default | tonumber) end),
        require_trend_source: (if $require_trend_source == "" then null else ($require_trend_source | split(",") | map(gsub("^\\s+|\\s+$"; "") | select(length > 0))) end)
      },
      campaign_refresh_overrides: {
        execution_mode: (if $campaign_execution_mode == "" then null else $campaign_execution_mode end),
        directory_urls: (if $campaign_directory_urls == "" then null else $campaign_directory_urls end),
        bootstrap_directory: (if $campaign_bootstrap_directory == "" then null else $campaign_bootstrap_directory end),
        discovery_wait_sec: (if $campaign_discovery_wait_sec == "" then null else ($campaign_discovery_wait_sec | tonumber) end),
        issuer_url: (if $campaign_issuer_url == "" then null else $campaign_issuer_url end),
        entry_url: (if $campaign_entry_url == "" then null else $campaign_entry_url end),
        exit_url: (if $campaign_exit_url == "" then null else $campaign_exit_url end),
        start_local_stack: (if $campaign_start_local_stack == "" then null else $campaign_start_local_stack end)
      }
    },
    stages: {
      campaign: {
        attempted: ($campaign_attempted == 1),
        status: $campaign_status,
        rc: $campaign_rc,
        command: $campaign_cmd,
        log: $campaign_log,
        summary_json: $campaign_summary_json,
        report_md: $campaign_report_md
      },
      campaign_check: {
        attempted: ($check_attempted == 1),
        status: $check_status,
        rc: $check_rc,
        command: $check_cmd,
        log: $check_log,
        summary_json: $campaign_check_summary_json
      }
    },
    decision: {
      decision: $decision,
      go: ($decision == "GO"),
      recommended_profile: $recommended_profile,
      support_rate_pct: ($support_rate_pct | tonumber),
      trend_source: $trend_source
    },
    artifacts: {
      summary_json: $summary_json,
      campaign_summary_json: $campaign_summary_json,
      campaign_report_md: $campaign_report_md,
      campaign_check_summary_json: $campaign_check_summary_json
    }
  }' >"$summary_tmp"

mv -f "$summary_tmp" "$summary_json"

echo "[profile-compare-campaign-signoff] status=$status final_rc=$final_rc decision=$decision recommended_profile=${recommended_profile:-unset} summary_json=$summary_json"
if [[ "$status" != "ok" ]]; then
  echo "[profile-compare-campaign-signoff] failure_stage=$failure_stage campaign_log=$campaign_log check_log=$check_log"
fi
if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  echo "[profile-compare-campaign-signoff] summary_json_payload:"
  cat "$summary_json"
fi

exit "$final_rc"
