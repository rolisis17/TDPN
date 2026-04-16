#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp date awk; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_campaign.sh \
    [--campaign-runs N] \
    [--campaign-pause-sec N] \
    [--reports-dir DIR] \
    [--profiles CSV] \
    [--rounds N] \
    [--timeout-sec N] \
    [--execution-mode docker|local] \
    [--directory-urls URL[,URL...]] \
    [--bootstrap-directory URL] \
    [--discovery-wait-sec N] \
    [--issuer-url URL] \
    [--entry-url URL] \
    [--exit-url URL] \
    [--subject ID | --anon-cred TOKEN] \
    [--min-sources N] \
    [--beta-profile [0|1]] \
    [--prod-profile [0|1]] \
    [--start-local-stack auto|0|1] \
    [--force-stack-reset [0|1]] \
    [--stack-strict-beta [0|1]] \
    [--base-port N] \
    [--client-iface IFACE] \
    [--exit-iface IFACE] \
    [--cleanup-ifaces [0|1]] \
    [--keep-stack [0|1]] \
    [--trend-max-reports N] \
    [--trend-since-hours N] \
    [--trend-min-profile-runs N] \
    [--trend-min-profile-pass-rate-pct N] \
    [--trend-balanced-latency-margin-pct N] \
    [--trend-fail-on-any-fail [0|1]] \
    [--trend-min-decision-rate-pct N] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run repeated `profile-compare-local` executions and automatically aggregate
  them with `profile-compare-trend` for one campaign-level recommendation.

Policy:
  - `speed-1hop` remains experimental/non-default.
  - campaign output is warning/fail aware and preserves per-run artifacts.
USAGE
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

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

tri_state_or_die() {
  local name="$1"
  local value="$2"
  case "$value" in
    auto|0|1) ;;
    *)
      echo "$name must be one of: auto, 0, 1"
      exit 2
      ;;
  esac
}

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

original_args=("$@")

campaign_runs="3"
campaign_pause_sec="0"
reports_dir=""

profiles_csv="balanced,speed,private,speed-1hop"
rounds="3"
timeout_sec="35"
execution_mode="${PROFILE_COMPARE_LOCAL_CLIENT_TEST_MODE:-local}"
directory_urls=""
bootstrap_directory=""
discovery_wait_sec="20"
issuer_url=""
entry_url=""
exit_url=""
subject=""
anon_cred=""
min_sources="1"
beta_profile="0"
prod_profile="0"
start_local_stack="auto"
force_stack_reset="1"
stack_strict_beta="0"
base_port="${PROFILE_COMPARE_LOCAL_BASE_PORT:-19280}"
client_iface="${PROFILE_COMPARE_LOCAL_CLIENT_IFACE:-wgcstack0}"
exit_iface="${PROFILE_COMPARE_LOCAL_EXIT_IFACE:-wgestack0}"
cleanup_ifaces="1"
keep_stack="0"

trend_max_reports="0"
trend_since_hours="0"
trend_min_profile_runs="3"
trend_min_profile_pass_rate_pct="95"
trend_balanced_latency_margin_pct="15"
trend_fail_on_any_fail="0"
trend_min_decision_rate_pct="0"

summary_json=""
report_md=""
print_summary_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --campaign-runs)
      campaign_runs="${2:-}"
      shift 2
      ;;
    --campaign-pause-sec)
      campaign_pause_sec="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --profiles)
      profiles_csv="${2:-}"
      shift 2
      ;;
    --rounds)
      rounds="${2:-}"
      shift 2
      ;;
    --timeout-sec)
      timeout_sec="${2:-}"
      shift 2
      ;;
    --execution-mode)
      execution_mode="${2:-}"
      shift 2
      ;;
    --directory-urls)
      directory_urls="${2:-}"
      shift 2
      ;;
    --bootstrap-directory)
      bootstrap_directory="${2:-}"
      shift 2
      ;;
    --discovery-wait-sec)
      discovery_wait_sec="${2:-}"
      shift 2
      ;;
    --issuer-url)
      issuer_url="${2:-}"
      shift 2
      ;;
    --entry-url)
      entry_url="${2:-}"
      shift 2
      ;;
    --exit-url)
      exit_url="${2:-}"
      shift 2
      ;;
    --subject)
      subject="${2:-}"
      shift 2
      ;;
    --anon-cred)
      anon_cred="${2:-}"
      shift 2
      ;;
    --min-sources)
      min_sources="${2:-}"
      shift 2
      ;;
    --beta-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        beta_profile="${2:-}"
        shift 2
      else
        beta_profile="1"
        shift
      fi
      ;;
    --prod-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        prod_profile="${2:-}"
        shift 2
      else
        prod_profile="1"
        shift
      fi
      ;;
    --start-local-stack)
      start_local_stack="${2:-}"
      shift 2
      ;;
    --force-stack-reset)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        force_stack_reset="${2:-}"
        shift 2
      else
        force_stack_reset="1"
        shift
      fi
      ;;
    --stack-strict-beta)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        stack_strict_beta="${2:-}"
        shift 2
      else
        stack_strict_beta="1"
        shift
      fi
      ;;
    --base-port)
      base_port="${2:-}"
      shift 2
      ;;
    --client-iface)
      client_iface="${2:-}"
      shift 2
      ;;
    --exit-iface)
      exit_iface="${2:-}"
      shift 2
      ;;
    --cleanup-ifaces)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        cleanup_ifaces="${2:-}"
        shift 2
      else
        cleanup_ifaces="1"
        shift
      fi
      ;;
    --keep-stack)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        keep_stack="${2:-}"
        shift 2
      else
        keep_stack="1"
        shift
      fi
      ;;
    --trend-max-reports)
      trend_max_reports="${2:-}"
      shift 2
      ;;
    --trend-since-hours)
      trend_since_hours="${2:-}"
      shift 2
      ;;
    --trend-min-profile-runs)
      trend_min_profile_runs="${2:-}"
      shift 2
      ;;
    --trend-min-profile-pass-rate-pct)
      trend_min_profile_pass_rate_pct="${2:-}"
      shift 2
      ;;
    --trend-balanced-latency-margin-pct)
      trend_balanced_latency_margin_pct="${2:-}"
      shift 2
      ;;
    --trend-fail-on-any-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        trend_fail_on_any_fail="${2:-}"
        shift 2
      else
        trend_fail_on_any_fail="1"
        shift
      fi
      ;;
    --trend-min-decision-rate-pct)
      trend_min_decision_rate_pct="${2:-}"
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

bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--force-stack-reset" "$force_stack_reset"
bool_arg_or_die "--stack-strict-beta" "$stack_strict_beta"
bool_arg_or_die "--cleanup-ifaces" "$cleanup_ifaces"
bool_arg_or_die "--keep-stack" "$keep_stack"
bool_arg_or_die "--trend-fail-on-any-fail" "$trend_fail_on_any_fail"
tri_state_or_die "--start-local-stack" "$start_local_stack"

if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
  echo "--beta-profile must be 0 or 1"
  exit 2
fi
if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
  echo "--prod-profile must be 0 or 1"
  exit 2
fi
if [[ "$execution_mode" != "docker" && "$execution_mode" != "local" ]]; then
  echo "--execution-mode must be one of: docker, local"
  exit 2
fi
if ! [[ "$campaign_runs" =~ ^[0-9]+$ ]] || ((campaign_runs < 1)); then
  echo "--campaign-runs must be >= 1"
  exit 2
fi
if ! [[ "$campaign_pause_sec" =~ ^[0-9]+$ ]]; then
  echo "--campaign-pause-sec must be a non-negative integer"
  exit 2
fi
if ! [[ "$rounds" =~ ^[0-9]+$ ]] || ((rounds < 1)); then
  echo "--rounds must be >= 1"
  exit 2
fi
if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || ((timeout_sec < 1)); then
  echo "--timeout-sec must be >= 1"
  exit 2
fi
if ! [[ "$discovery_wait_sec" =~ ^[0-9]+$ ]] || ((discovery_wait_sec < 1)); then
  echo "--discovery-wait-sec must be >= 1"
  exit 2
fi
if ! [[ "$min_sources" =~ ^[0-9]+$ ]] || ((min_sources < 1)); then
  echo "--min-sources must be >= 1"
  exit 2
fi
if ! [[ "$base_port" =~ ^[0-9]+$ ]] || ((base_port < 1)); then
  echo "--base-port must be >= 1"
  exit 2
fi
if [[ -z "$profiles_csv" ]]; then
  echo "--profiles must be non-empty"
  exit 2
fi
if [[ -n "$subject" && -n "$anon_cred" ]]; then
  echo "use either --subject or --anon-cred, not both"
  exit 2
fi
if ! [[ "$trend_max_reports" =~ ^[0-9]+$ ]]; then
  echo "--trend-max-reports must be a non-negative integer"
  exit 2
fi
if ! [[ "$trend_since_hours" =~ ^[0-9]+$ ]]; then
  echo "--trend-since-hours must be a non-negative integer"
  exit 2
fi
if ! [[ "$trend_min_profile_runs" =~ ^[0-9]+$ ]] || ((trend_min_profile_runs < 1)); then
  echo "--trend-min-profile-runs must be >= 1"
  exit 2
fi
for decimal_arg in "$trend_min_profile_pass_rate_pct" "$trend_balanced_latency_margin_pct" "$trend_min_decision_rate_pct"; do
  if ! is_non_negative_decimal "$decimal_arg"; then
    echo "trend percentage thresholds must be non-negative numbers"
    exit 2
  fi
done
if [[ -z "$client_iface" || -z "$exit_iface" ]]; then
  echo "--client-iface and --exit-iface must be non-empty"
  exit 2
fi

execution_mode_effective="$execution_mode"
start_local_stack_effective="$start_local_stack"
execution_mode_adjusted="0"
execution_mode_adjustment_reason=""
start_local_stack_adjusted="0"
start_local_stack_adjustment_reason=""
if [[ "$execution_mode_effective" == "local" && ( -n "$directory_urls" || -n "$bootstrap_directory" || -n "$issuer_url" || -n "$entry_url" || -n "$exit_url" ) ]]; then
  execution_mode_effective="docker"
  execution_mode_adjusted="1"
  execution_mode_adjustment_reason="remote endpoint overrides requested"
fi
if [[ "$execution_mode_effective" == "docker" && "$start_local_stack_effective" == "auto" ]]; then
  start_local_stack_effective="0"
  start_local_stack_adjusted="1"
  start_local_stack_adjustment_reason="docker mode disables implicit local stack bootstrap"
fi

local_compare_script="${PROFILE_COMPARE_CAMPAIGN_LOCAL_SCRIPT:-$ROOT_DIR/scripts/profile_compare_local.sh}"
trend_script="${PROFILE_COMPARE_CAMPAIGN_TREND_SCRIPT:-$ROOT_DIR/scripts/profile_compare_trend.sh}"
if [[ ! -x "$local_compare_script" ]]; then
  echo "missing profile compare local script: $local_compare_script"
  exit 2
fi
if [[ ! -x "$trend_script" ]]; then
  echo "missing profile compare trend script: $trend_script"
  exit 2
fi

log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"

if [[ -z "$reports_dir" ]]; then
  reports_dir="$log_dir/profile_compare_campaign_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
mkdir -p "$reports_dir"

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/profile_compare_campaign_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$report_md" ]]; then
  report_md="$reports_dir/profile_compare_campaign_report.md"
else
  report_md="$(abs_path "$report_md")"
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

summary_log="$reports_dir/profile_compare_campaign.log"
: >"$summary_log"

rows_file="$(mktemp)"
trap 'rm -f "$rows_file"' EXIT

declare -a compare_summary_paths=()

for ((run_idx = 1; run_idx <= campaign_runs; run_idx++)); do
  run_id="$(printf '%02d' "$run_idx")"
  compare_summary="$reports_dir/profile_compare_local_run_${run_id}.json"
  compare_report="$reports_dir/profile_compare_local_run_${run_id}.md"
  compare_log="$reports_dir/profile_compare_local_run_${run_id}.log"

  compare_cmd=(
    "$local_compare_script"
    --profiles "$profiles_csv"
    --rounds "$rounds"
    --timeout-sec "$timeout_sec"
    --execution-mode "$execution_mode_effective"
    --discovery-wait-sec "$discovery_wait_sec"
    --min-sources "$min_sources"
    --beta-profile "$beta_profile"
    --prod-profile "$prod_profile"
    --start-local-stack "$start_local_stack_effective"
    --force-stack-reset "$force_stack_reset"
    --stack-strict-beta "$stack_strict_beta"
    --base-port "$base_port"
    --client-iface "$client_iface"
    --exit-iface "$exit_iface"
    --cleanup-ifaces "$cleanup_ifaces"
    --keep-stack "$keep_stack"
    --summary-json "$compare_summary"
    --report-md "$compare_report"
    --print-summary-json 0
  )

  if [[ -n "$directory_urls" ]]; then
    compare_cmd+=(--directory-urls "$directory_urls")
  fi
  if [[ -n "$bootstrap_directory" ]]; then
    compare_cmd+=(--bootstrap-directory "$bootstrap_directory")
  fi
  if [[ -n "$issuer_url" ]]; then
    compare_cmd+=(--issuer-url "$issuer_url")
  fi
  if [[ -n "$entry_url" ]]; then
    compare_cmd+=(--entry-url "$entry_url")
  fi
  if [[ -n "$exit_url" ]]; then
    compare_cmd+=(--exit-url "$exit_url")
  fi
  if [[ -n "$subject" ]]; then
    compare_cmd+=(--subject "$subject")
  fi
  if [[ -n "$anon_cred" ]]; then
    compare_cmd+=(--anon-cred "$anon_cred")
  fi

  start_epoch="$(date +%s)"
  run_rc=0
  if "${compare_cmd[@]}" >"$compare_log" 2>&1; then
    run_rc=0
  else
    run_rc=$?
  fi
  end_epoch="$(date +%s)"
  duration_sec=$((end_epoch - start_epoch))

  run_status=""
  run_notes=""
  run_summary_rc="$run_rc"
  if [[ -f "$compare_summary" ]] && jq -e '.version == 1 and (.status | type == "string")' "$compare_summary" >/dev/null 2>&1; then
    run_status="$(jq -r '.status // "unknown"' "$compare_summary")"
    run_notes="$(jq -r '.notes // ""' "$compare_summary")"
    run_summary_rc="$(jq -r '.rc // 1' "$compare_summary")"
    compare_summary_paths+=("$compare_summary")
  else
    if [[ "$run_rc" -eq 0 ]]; then
      run_status="pass"
      run_notes="compare command succeeded without summary JSON artifact"
    else
      run_status="fail"
      run_notes="compare command failed and no valid summary JSON artifact was found"
    fi
  fi

  jq -n \
    --arg run_id "$run_id" \
    --arg status "$run_status" \
    --arg notes "$run_notes" \
    --arg log "$compare_log" \
    --arg summary_json "$compare_summary" \
    --arg report_md "$compare_report" \
    --arg command "$(print_cmd "${compare_cmd[@]}")" \
    --argjson rc "$run_summary_rc" \
    --argjson command_rc "$run_rc" \
    --argjson duration_sec "$duration_sec" \
    '{
      run_id: $run_id,
      status: $status,
      notes: $notes,
      rc: $rc,
      command_rc: $command_rc,
      duration_sec: $duration_sec,
      command: $command,
      artifacts: {
        log: $log,
        summary_json: $summary_json,
        report_md: $report_md
      }
    }' >>"$rows_file"

  echo "[profile-compare-campaign] run=$run_id status=$run_status rc=$run_summary_rc duration_sec=$duration_sec summary_json=$compare_summary log=$compare_log" | tee -a "$summary_log"

  if ((campaign_pause_sec > 0 && run_idx < campaign_runs)); then
    sleep "$campaign_pause_sec"
  fi
done

if [[ ${#compare_summary_paths[@]} -eq 0 ]]; then
  echo "profile-compare-campaign: no valid compare summaries were produced" | tee -a "$summary_log"
  exit 1
fi

if ((trend_max_reports == 0)); then
  trend_max_reports="${#compare_summary_paths[@]}"
fi
if ! [[ "$trend_max_reports" =~ ^[0-9]+$ ]] || ((trend_max_reports < 1)); then
  echo "--trend-max-reports must be >= 1 after defaults"
  exit 2
fi

trend_summary_json="$reports_dir/profile_compare_trend_summary.json"
trend_report_md="$reports_dir/profile_compare_trend_report.md"
trend_log="$reports_dir/profile_compare_trend.log"

trend_cmd=(
  "$trend_script"
  --max-reports "$trend_max_reports"
  --since-hours "$trend_since_hours"
  --min-profile-runs "$trend_min_profile_runs"
  --min-profile-pass-rate-pct "$trend_min_profile_pass_rate_pct"
  --balanced-latency-margin-pct "$trend_balanced_latency_margin_pct"
  --fail-on-any-fail "$trend_fail_on_any_fail"
  --min-decision-rate-pct "$trend_min_decision_rate_pct"
  --summary-json "$trend_summary_json"
  --report-md "$trend_report_md"
  --print-summary-json 0
)
summary_path=""
for summary_path in "${compare_summary_paths[@]}"; do
  trend_cmd+=(--compare-summary-json "$summary_path")
done

trend_rc=0
if "${trend_cmd[@]}" >"$trend_log" 2>&1; then
  trend_rc=0
else
  trend_rc=$?
fi

trend_status=""
trend_notes=""
recommended_default_profile=""
decision_source=""
decision_rationale=""
if [[ -f "$trend_summary_json" ]] && jq -e '.version == 1 and (.status | type == "string")' "$trend_summary_json" >/dev/null 2>&1; then
  trend_status="$(jq -r '.status // "unknown"' "$trend_summary_json")"
  trend_notes="$(jq -r '.notes // ""' "$trend_summary_json")"
  recommended_default_profile="$(jq -r '.decision.recommended_default_profile // ""' "$trend_summary_json")"
  decision_source="$(jq -r '.decision.source // ""' "$trend_summary_json")"
  decision_rationale="$(jq -r '.decision.rationale // ""' "$trend_summary_json")"
else
  if [[ "$trend_rc" -eq 0 ]]; then
    trend_status="pass"
    trend_notes="trend command succeeded without summary JSON artifact"
  else
    trend_status="fail"
    trend_notes="trend command failed and no valid summary JSON artifact was found"
  fi
fi

runs_json="$(jq -s '.' "$rows_file")"
runs_total="$(jq 'length' <<<"$runs_json")"
runs_pass="$(jq '[.[] | select(.status == "pass")] | length' <<<"$runs_json")"
runs_warn="$(jq '[.[] | select(.status == "warn")] | length' <<<"$runs_json")"
runs_fail="$(jq '[.[] | select(.status == "fail")] | length' <<<"$runs_json")"
runs_with_summary="${#compare_summary_paths[@]}"
runs_missing_summary=$((runs_total - runs_with_summary))

status="pass"
rc=0
notes="profile compare campaign completed"

if [[ "$trend_status" == "fail" || "$trend_rc" -ne 0 ]]; then
  status="fail"
  rc=1
  notes="trend aggregation failed"
elif ((runs_fail > 0)); then
  status="warn"
  notes="one or more compare runs failed before trend aggregation"
elif ((runs_warn > 0)) || [[ "$trend_status" == "warn" ]]; then
  status="warn"
  notes="one or more compare/trend runs reported warnings"
fi

if [[ "$recommended_default_profile" == "speed-1hop" ]]; then
  status="fail"
  rc=1
  notes="invalid recommendation: speed-1hop is experimental and cannot be campaign default"
fi
if [[ -z "$recommended_default_profile" ]]; then
  if [[ "$status" == "pass" ]]; then
    status="warn"
    notes="campaign completed but trend recommendation was empty"
  fi
fi

selected_summaries_json="$(printf '%s\n' "${compare_summary_paths[@]}" | jq -R . | jq -s '.')"

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg command "$(print_cmd "$0" "${original_args[@]}")" \
  --arg reports_dir "$reports_dir" \
  --arg summary_log "$summary_log" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --arg trend_summary_json "$trend_summary_json" \
  --arg trend_report_md "$trend_report_md" \
  --arg trend_log "$trend_log" \
  --arg recommended_default_profile "$recommended_default_profile" \
  --arg decision_source "$decision_source" \
  --arg decision_rationale "$decision_rationale" \
  --arg trend_status "$trend_status" \
  --arg trend_notes "$trend_notes" \
  --arg profiles "$profiles_csv" \
  --arg execution_mode "$execution_mode" \
  --arg execution_mode_effective "$execution_mode_effective" \
  --arg execution_mode_adjusted "$execution_mode_adjusted" \
  --arg execution_mode_adjustment_reason "$execution_mode_adjustment_reason" \
  --arg directory_urls "$directory_urls" \
  --arg bootstrap_directory "$bootstrap_directory" \
  --arg issuer_url "$issuer_url" \
  --arg entry_url "$entry_url" \
  --arg exit_url "$exit_url" \
  --arg subject "$subject" \
  --arg anon_cred "$anon_cred" \
  --arg start_local_stack "$start_local_stack" \
  --arg client_iface "$client_iface" \
  --arg exit_iface "$exit_iface" \
  --arg start_local_stack_effective "$start_local_stack_effective" \
  --arg start_local_stack_adjusted "$start_local_stack_adjusted" \
  --arg start_local_stack_adjustment_reason "$start_local_stack_adjustment_reason" \
  --argjson rc "$rc" \
  --argjson campaign_runs "$campaign_runs" \
  --argjson campaign_pause_sec "$campaign_pause_sec" \
  --argjson rounds "$rounds" \
  --argjson timeout_sec "$timeout_sec" \
  --argjson discovery_wait_sec "$discovery_wait_sec" \
  --argjson min_sources "$min_sources" \
  --argjson beta_profile "$beta_profile" \
  --argjson prod_profile "$prod_profile" \
  --argjson force_stack_reset "$force_stack_reset" \
  --argjson stack_strict_beta "$stack_strict_beta" \
  --argjson base_port "$base_port" \
  --argjson cleanup_ifaces "$cleanup_ifaces" \
  --argjson keep_stack "$keep_stack" \
  --argjson trend_max_reports "$trend_max_reports" \
  --argjson trend_since_hours "$trend_since_hours" \
  --argjson trend_min_profile_runs "$trend_min_profile_runs" \
  --argjson trend_min_profile_pass_rate_pct "$trend_min_profile_pass_rate_pct" \
  --argjson trend_balanced_latency_margin_pct "$trend_balanced_latency_margin_pct" \
  --argjson trend_fail_on_any_fail "$trend_fail_on_any_fail" \
  --argjson trend_min_decision_rate_pct "$trend_min_decision_rate_pct" \
  --argjson trend_rc "$trend_rc" \
  --argjson runs_total "$runs_total" \
  --argjson runs_pass "$runs_pass" \
  --argjson runs_warn "$runs_warn" \
  --argjson runs_fail "$runs_fail" \
  --argjson runs_with_summary "$runs_with_summary" \
  --argjson runs_missing_summary "$runs_missing_summary" \
  --argjson runs "$runs_json" \
  --argjson selected_summaries "$selected_summaries_json" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    notes: $notes,
    command: $command,
    inputs: {
      campaign_runs: $campaign_runs,
      campaign_pause_sec: $campaign_pause_sec,
      reports_dir: $reports_dir,
      compare: {
        profiles: $profiles,
        rounds: $rounds,
        timeout_sec: $timeout_sec,
        execution_mode: $execution_mode,
        execution_mode_effective: $execution_mode_effective,
        execution_mode_adjusted: ($execution_mode_adjusted == "1"),
        execution_mode_adjustment_reason: (if $execution_mode_adjustment_reason == "" then null else $execution_mode_adjustment_reason end),
        directory_urls: $directory_urls,
        bootstrap_directory: $bootstrap_directory,
        discovery_wait_sec: $discovery_wait_sec,
        issuer_url: $issuer_url,
        entry_url: $entry_url,
        exit_url: $exit_url,
        subject: $subject,
        anon_cred_present: ($anon_cred | length > 0),
        min_sources: $min_sources,
        beta_profile: ($beta_profile == 1),
        prod_profile: ($prod_profile == 1),
        start_local_stack: $start_local_stack,
        force_stack_reset: ($force_stack_reset == 1),
        stack_strict_beta: ($stack_strict_beta == 1),
        base_port: $base_port,
        client_iface: $client_iface,
        exit_iface: $exit_iface,
        cleanup_ifaces: ($cleanup_ifaces == 1),
        keep_stack: ($keep_stack == 1),
        start_local_stack_effective: $start_local_stack_effective,
        start_local_stack_adjusted: ($start_local_stack_adjusted == "1"),
        start_local_stack_adjustment_reason: (if $start_local_stack_adjustment_reason == "" then null else $start_local_stack_adjustment_reason end)
      },
      trend: {
        max_reports: $trend_max_reports,
        since_hours: $trend_since_hours,
        min_profile_runs: $trend_min_profile_runs,
        min_profile_pass_rate_pct: $trend_min_profile_pass_rate_pct,
        balanced_latency_margin_pct: $trend_balanced_latency_margin_pct,
        fail_on_any_fail: ($trend_fail_on_any_fail == 1),
        min_decision_rate_pct: $trend_min_decision_rate_pct
      }
    },
    summary: {
      runs_total: $runs_total,
      runs_pass: $runs_pass,
      runs_warn: $runs_warn,
      runs_fail: $runs_fail,
      runs_with_summary: $runs_with_summary,
      runs_missing_summary: $runs_missing_summary
    },
    decision: {
      recommended_default_profile: $recommended_default_profile,
      source: $decision_source,
      rationale: $decision_rationale,
      experimental_non_default_profiles: ["speed-1hop"]
    },
    trend: {
      status: $trend_status,
      rc: $trend_rc,
      notes: $trend_notes,
      summary_json: $trend_summary_json,
      report_md: $trend_report_md,
      log: $trend_log
    },
    selected_summaries: $selected_summaries,
    runs: $runs,
    artifacts: {
      summary_log: $summary_log,
      summary_json: $summary_json,
      report_md: $report_md,
      reports_dir: $reports_dir,
      trend_summary_json: $trend_summary_json,
      trend_report_md: $trend_report_md,
      trend_log: $trend_log
    }
  }' >"$summary_json"

{
  echo "# Profile Compare Campaign Report"
  echo
  echo "- Generated at (UTC): \`$(jq -r '.generated_at_utc' "$summary_json")\`"
  echo "- Status: \`$(jq -r '.status' "$summary_json")\`"
  echo "- Summary JSON: \`$summary_json\`"
  echo "- Summary Log: \`$summary_log\`"
  echo "- Reports dir: \`$reports_dir\`"
  echo
  echo "## Decision"
  echo
  echo "- Recommended default: \`$(jq -r '.decision.recommended_default_profile // ""' "$summary_json")\`"
  echo "- Source: \`$(jq -r '.decision.source // ""' "$summary_json")\`"
  echo "- Rationale: $(jq -r '.decision.rationale // ""' "$summary_json")"
  echo
  echo "## Campaign Summary"
  echo
  echo "- Runs total: \`$(jq -r '.summary.runs_total' "$summary_json")\`"
  echo "- Pass: \`$(jq -r '.summary.runs_pass' "$summary_json")\`"
  echo "- Warn: \`$(jq -r '.summary.runs_warn' "$summary_json")\`"
  echo "- Fail: \`$(jq -r '.summary.runs_fail' "$summary_json")\`"
  echo "- With summary artifacts: \`$(jq -r '.summary.runs_with_summary' "$summary_json")\`"
  echo
  echo "## Trend Aggregation"
  echo
  echo "- Trend status: \`$(jq -r '.trend.status' "$summary_json")\`"
  echo "- Trend summary JSON: \`$(jq -r '.trend.summary_json' "$summary_json")\`"
  echo "- Trend report: \`$(jq -r '.trend.report_md' "$summary_json")\`"
  echo
  echo "## Per-Run Results"
  echo
  echo "| Run | Status | RC | Duration (s) | Summary | Log |"
  echo "|---|---|---:|---:|---|---|"
  jq -r '.runs[] | "| \(.run_id) | \(.status) | \(.rc) | \(.duration_sec) | \(.artifacts.summary_json) | \(.artifacts.log) |"' "$summary_json"
} >"$report_md"

echo "profile-compare-campaign: status=$status"
echo "summary_log: $summary_log"
echo "summary_json: $summary_json"
echo "report_md: $report_md"
echo "trend_summary_json: $trend_summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
