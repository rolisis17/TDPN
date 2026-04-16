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
    [--allow-concurrent [0|1]] \
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
  - campaign lock is fail-fast by default; override with --allow-concurrent 1
    or PROFILE_COMPARE_CAMPAIGN_ALLOW_CONCURRENT=1 when intentional.
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

campaign_elapsed_sec() {
  local started_epoch="${1:-0}"
  local now_epoch
  now_epoch="$(date +%s)"
  if [[ ! "$started_epoch" =~ ^[0-9]+$ ]]; then
    printf '%s' "0"
    return 0
  fi
  if ((now_epoch < started_epoch)); then
    printf '%s' "0"
    return 0
  fi
  printf '%s' "$((now_epoch - started_epoch))"
}

campaign_log_event() {
  local message="$1"
  echo "[profile-compare-campaign] $message" | tee -a "$summary_log"
}

lock_owner_field() {
  local owner_file="$1"
  local key="$2"
  awk -F'=' -v key="$key" '$1 == key {sub(/^[^=]*=/, "", $0); print; exit}' "$owner_file" 2>/dev/null || true
}

declare -a acquired_lock_dirs=()
rows_file=""

cleanup_campaign_resources() {
  local lock_dir owner_file owner_pid
  if [[ -n "${rows_file:-}" ]]; then
    rm -f "$rows_file"
  fi
  for lock_dir in "${acquired_lock_dirs[@]:-}"; do
    [[ -z "$lock_dir" ]] && continue
    owner_file="$lock_dir/owner"
    owner_pid="$(lock_owner_field "$owner_file" "pid")"
    if [[ "$owner_pid" == "$$" ]]; then
      rm -rf "$lock_dir" 2>/dev/null || true
    fi
  done
}

acquire_campaign_lock() {
  local lock_dir="$1"
  local lock_scope="$2"
  local owner_file="$lock_dir/owner"
  local owner_pid owner_start_utc owner_command now_utc

  now_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if mkdir "$lock_dir" 2>/dev/null; then
    {
      printf 'pid=%s\n' "$$"
      printf 'start_utc=%s\n' "$now_utc"
      printf 'scope=%s\n' "$lock_scope"
      printf 'command=%s\n' "$(print_cmd "$0" "${original_args[@]}")"
    } >"$owner_file"
    acquired_lock_dirs+=("$lock_dir")
    return 0
  fi

  owner_pid="$(lock_owner_field "$owner_file" "pid")"
  owner_start_utc="$(lock_owner_field "$owner_file" "start_utc")"
  owner_command="$(lock_owner_field "$owner_file" "command")"

  if [[ -n "$owner_pid" && "$owner_pid" =~ ^[0-9]+$ ]] && kill -0 "$owner_pid" 2>/dev/null; then
    echo "profile-compare-campaign: another campaign run is active for $lock_scope"
    echo "lock: $lock_dir"
    echo "owner_pid: $owner_pid"
    echo "owner_start_utc: ${owner_start_utc:-unknown}"
    if [[ -n "$owner_command" ]]; then
      echo "owner_command: $owner_command"
    fi
    echo "override with --allow-concurrent 1 or PROFILE_COMPARE_CAMPAIGN_ALLOW_CONCURRENT=1"
    exit 1
  fi

  rm -rf "$lock_dir" 2>/dev/null || true
  if mkdir "$lock_dir" 2>/dev/null; then
    {
      printf 'pid=%s\n' "$$"
      printf 'start_utc=%s\n' "$now_utc"
      printf 'scope=%s\n' "$lock_scope"
      printf 'command=%s\n' "$(print_cmd "$0" "${original_args[@]}")"
    } >"$owner_file"
    acquired_lock_dirs+=("$lock_dir")
    return 0
  fi

  owner_pid="$(lock_owner_field "$owner_file" "pid")"
  owner_start_utc="$(lock_owner_field "$owner_file" "start_utc")"
  echo "profile-compare-campaign: unable to acquire campaign lock for $lock_scope"
  echo "lock: $lock_dir"
  if [[ -n "$owner_pid" ]]; then
    echo "owner_pid: $owner_pid"
    echo "owner_start_utc: ${owner_start_utc:-unknown}"
  fi
  echo "override with --allow-concurrent 1 or PROFILE_COMPARE_CAMPAIGN_ALLOW_CONCURRENT=1"
  exit 1
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

to_non_negative_int() {
  local value="${1:-0}"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    printf '%s' "$value"
    return 0
  fi
  if [[ "$value" =~ ^[0-9]+[.][0-9]+$ ]]; then
    awk -v raw="$value" 'BEGIN { n = int(raw + 0); if (n < 0) n = 0; printf "%d", n }'
    return 0
  fi
  printf '%s' "0"
}

extract_diagnostic_count() {
  local summary_json_path="$1"
  local key="$2"
  local raw_value
  raw_value="$(jq -r --arg key "$key" '
    [
      (.diagnostics[$key] // empty),
      (.summary.diagnostics[$key] // empty),
      (.summary[$key] // empty),
      (.[$key] // empty)
    ] | map(select(. != null)) | .[0] // 0
  ' "$summary_json_path" 2>/dev/null || printf '%s' "0")"
  to_non_negative_int "$raw_value"
}

has_diagnostic_key() {
  local summary_json_path="$1"
  local key="$2"
  jq -e --arg key "$key" '
    ((.diagnostics // {}) | has($key))
    or ((.summary.diagnostics // {}) | has($key))
    or ((.summary // {}) | has($key))
    or (has($key))
  ' "$summary_json_path" >/dev/null 2>&1
}

count_log_pattern() {
  local log_path="$1"
  local pattern="$2"
  local count="0"
  if [[ -n "$log_path" && -f "$log_path" ]]; then
    count="$(grep -Eic -- "$pattern" "$log_path" 2>/dev/null || true)"
  fi
  count="${count:-0}"
  if ! [[ "$count" =~ ^[0-9]+$ ]]; then
    count="0"
  fi
  printf '%s\n' "$count"
}

log_path_for_summary() {
  local summary_path="$1"
  local rows_json="$2"
  jq -r --arg summary_path "$summary_path" '
    ([.[] | select(.artifacts.summary_json == $summary_path) | .artifacts.log][0] // "")
  ' <<<"$rows_json" 2>/dev/null || printf '%s\n' ""
}

host_is_loopback_local() {
  local host="${1:-}"
  host="${host#[}"
  host="${host%]}"
  case "$host" in
    127.0.0.1|localhost|::1)
      return 0
      ;;
  esac
  return 1
}

url_host_from_endpoint() {
  local raw="${1:-}"
  local rest hostport host

  if [[ -z "$raw" ]]; then
    printf '%s\n' ""
    return 0
  fi

  if [[ "$raw" == *"://"* ]]; then
    rest="${raw#*://}"
  else
    rest="$raw"
  fi
  hostport="${rest%%/*}"
  hostport="${hostport##*@}"

  if [[ "$hostport" == \[*\]* ]]; then
    host="${hostport#\[}"
    host="${host%%]*}"
    printf '%s\n' "$host"
    return 0
  fi

  host="${hostport%%:*}"
  printf '%s\n' "$host"
}

url_is_non_loopback_host() {
  local host
  host="$(url_host_from_endpoint "${1:-}")"
  if [[ -z "$host" ]]; then
    return 1
  fi
  if host_is_loopback_local "$host"; then
    return 1
  fi
  return 0
}

url_csv_has_non_loopback_host() {
  local csv="$1"
  local item
  IFS=',' read -r -a items <<<"$csv"
  for item in "${items[@]}"; do
    item="$(trim "$item")"
    [[ -z "$item" ]] && continue
    if url_is_non_loopback_host "$item"; then
      return 0
    fi
  done
  return 1
}

original_args=("$@")

campaign_runs="3"
campaign_pause_sec="0"
allow_concurrent="${PROFILE_COMPARE_CAMPAIGN_ALLOW_CONCURRENT:-0}"
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
    --allow-concurrent)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_concurrent="${2:-}"
        shift 2
      else
        allow_concurrent="1"
        shift
      fi
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
bool_arg_or_die "--allow-concurrent" "$allow_concurrent"
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
if [[ "$execution_mode_effective" == "local" ]] && {
  [[ -n "$directory_urls" ]] ||
  [[ -n "$bootstrap_directory" ]] ||
  [[ -n "$issuer_url" ]] ||
  [[ -n "$entry_url" ]] ||
  [[ -n "$exit_url" ]];
}; then
  execution_mode_effective="docker"
  execution_mode_adjusted="1"
  execution_mode_adjustment_reason="remote endpoint overrides requested"
fi
if [[ "$execution_mode_effective" == "docker" && "$start_local_stack_effective" == "auto" ]]; then
  start_local_stack_effective="0"
  start_local_stack_adjusted="1"
  start_local_stack_adjustment_reason="docker mode disables implicit local stack bootstrap"
fi

explicit_remote_endpoints="0"
if [[ -n "$directory_urls" ]] && url_csv_has_non_loopback_host "$directory_urls"; then
  explicit_remote_endpoints="1"
fi
if [[ "$explicit_remote_endpoints" == "0" && -n "$bootstrap_directory" ]] && url_is_non_loopback_host "$bootstrap_directory"; then
  explicit_remote_endpoints="1"
fi
if [[ "$explicit_remote_endpoints" == "0" && -n "$issuer_url" ]] && url_is_non_loopback_host "$issuer_url"; then
  explicit_remote_endpoints="1"
fi
if [[ "$explicit_remote_endpoints" == "0" && -n "$entry_url" ]] && url_is_non_loopback_host "$entry_url"; then
  explicit_remote_endpoints="1"
fi
if [[ "$explicit_remote_endpoints" == "0" && -n "$exit_url" ]] && url_is_non_loopback_host "$exit_url"; then
  explicit_remote_endpoints="1"
fi

transport_auto_client_inner_source="0"
transport_auto_disable_synthetic_fallback="0"
transport_auto_data_plane_mode_opaque="0"
if [[ "$explicit_remote_endpoints" == "1" ]]; then
  if [[ -z "${CLIENT_INNER_SOURCE+x}" ]]; then
    transport_auto_client_inner_source="1"
  fi
  if [[ -z "${CLIENT_DISABLE_SYNTHETIC_FALLBACK+x}" ]]; then
    transport_auto_disable_synthetic_fallback="1"
  fi
  if [[ -z "${DATA_PLANE_MODE+x}" ]]; then
    transport_auto_data_plane_mode_opaque="1"
  fi
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

rows_file="$(mktemp)"
trap cleanup_campaign_resources EXIT

if [[ "$allow_concurrent" != "1" ]]; then
  reports_lock_dir="$reports_dir/.profile_compare_campaign.lock"
  summary_lock_dir="${summary_json}.lock"
  acquire_campaign_lock "$reports_lock_dir" "reports_dir"
  if [[ "$summary_lock_dir" != "$reports_lock_dir" ]]; then
    acquire_campaign_lock "$summary_lock_dir" "summary_json"
  fi
fi

: >"$summary_log"
campaign_started_epoch="$(date +%s)"
campaign_log_event "stage=campaign-start runs_total=$campaign_runs profiles=\"$profiles_csv\" execution_mode=$execution_mode_effective start_local_stack=$start_local_stack_effective elapsed_sec=0"

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

  campaign_log_event "stage=compare-start run_index=$run_idx run_total=$campaign_runs run_id=$run_id elapsed_sec=$(campaign_elapsed_sec "$campaign_started_epoch")"
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

  progress_marker=""
  if [[ -f "$compare_log" ]]; then
    progress_marker="$(grep -E '\[profile-compare-local\] profile=.*round=' "$compare_log" | tail -n 1 || true)"
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

  campaign_log_event "stage=compare-end run_index=$run_idx run_total=$campaign_runs run_id=$run_id status=$run_status rc=$run_summary_rc duration_sec=$duration_sec elapsed_sec=$(campaign_elapsed_sec "$campaign_started_epoch") summary_json=$compare_summary log=$compare_log"
  if [[ -n "$progress_marker" ]]; then
    campaign_log_event "stage=compare-progress run_index=$run_idx run_total=$campaign_runs run_id=$run_id marker=\"$progress_marker\" elapsed_sec=$(campaign_elapsed_sec "$campaign_started_epoch")"
  fi

  if ((campaign_pause_sec > 0 && run_idx < campaign_runs)); then
    campaign_log_event "stage=campaign-pause run_index=$run_idx run_total=$campaign_runs pause_sec=$campaign_pause_sec elapsed_sec=$(campaign_elapsed_sec "$campaign_started_epoch")"
    sleep "$campaign_pause_sec"
  fi
done

if [[ ${#compare_summary_paths[@]} -eq 0 ]]; then
  campaign_log_event "stage=campaign-abort reason=no_valid_compare_summaries elapsed_sec=$(campaign_elapsed_sec "$campaign_started_epoch")"
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
campaign_log_event "stage=trend-start reports=${#compare_summary_paths[@]} elapsed_sec=$(campaign_elapsed_sec "$campaign_started_epoch")"
if "${trend_cmd[@]}" >"$trend_log" 2>&1; then
  trend_rc=0
else
  trend_rc=$?
fi
campaign_log_event "stage=trend-end rc=$trend_rc elapsed_sec=$(campaign_elapsed_sec "$campaign_started_epoch") log=$trend_log"

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

transport_mismatch_failures=0
token_proof_invalid_failures=0
unknown_exit_failures=0
directory_trust_failures=0
root_required_failures=0
endpoint_unreachable_failures=0
for summary_path in "${compare_summary_paths[@]}"; do
  transport_mismatch_failures=$((transport_mismatch_failures + $(extract_diagnostic_count "$summary_path" "transport_mismatch_failures")))
  token_proof_invalid_failures=$((token_proof_invalid_failures + $(extract_diagnostic_count "$summary_path" "token_proof_invalid_failures")))
  unknown_exit_failures=$((unknown_exit_failures + $(extract_diagnostic_count "$summary_path" "unknown_exit_failures")))
  directory_trust_failures=$((directory_trust_failures + $(extract_diagnostic_count "$summary_path" "directory_trust_failures")))
  root_required_failures=$((root_required_failures + $(extract_diagnostic_count "$summary_path" "root_required_failures")))
  endpoint_unreachable_failures=$((endpoint_unreachable_failures + $(extract_diagnostic_count "$summary_path" "endpoint_unreachable_failures")))

  if ! has_diagnostic_key "$summary_path" "root_required_failures" || ! has_diagnostic_key "$summary_path" "endpoint_unreachable_failures"; then
    run_log_path="$(trim "$(log_path_for_summary "$summary_path" "$runs_json")")"
    root_required_failures=$((root_required_failures + $(count_log_pattern "$run_log_path" 'requires root|must be root|run with sudo|permission denied|operation not permitted')))
    endpoint_unreachable_failures=$((endpoint_unreachable_failures + $(count_log_pattern "$run_log_path" 'connection refused|no route to host|network is unreachable|could not resolve host|temporary failure in name resolution|name or service not known|context deadline exceeded|i/o timeout|timed out|dial tcp: lookup .*: no such host')))
  fi
done

likely_primary_failure="none"
if ((token_proof_invalid_failures > 0)); then
  likely_primary_failure="token_proof_invalid"
elif ((unknown_exit_failures > 0)); then
  likely_primary_failure="unknown_exit"
elif ((transport_mismatch_failures > 0)); then
  likely_primary_failure="transport_mismatch"
elif ((directory_trust_failures > 0)); then
  likely_primary_failure="directory_trust"
elif ((root_required_failures > 0 || endpoint_unreachable_failures > 0)); then
  if ((root_required_failures >= endpoint_unreachable_failures)); then
    likely_primary_failure="root_required"
  else
    likely_primary_failure="endpoint_unreachable"
  fi
fi

operator_hint="No dominant diagnostic failure signal detected across selected runs."
case "$likely_primary_failure" in
  token_proof_invalid|unknown_exit)
    operator_hint="Check invite/issuer alignment and retry with a fresh invite key."
    ;;
  transport_mismatch)
    operator_hint="Check live-WG transport requirements: DATA_PLANE_MODE and CLIENT_INNER_SOURCE must match the target environment."
    ;;
  directory_trust)
    operator_hint="Check trust reset and runtime trusted-directory key alignment before retrying."
    ;;
  root_required)
    operator_hint="Run the required privileged step with sudo/root or switch to docker-mode workflow that avoids root-only local stack requirements."
    ;;
  endpoint_unreachable)
    operator_hint="Check endpoint reachability and DNS/network routes for directory/issuer/entry/exit URLs before retrying."
    ;;
esac

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
  --arg allow_concurrent "$allow_concurrent" \
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
  --arg explicit_remote_endpoints "$explicit_remote_endpoints" \
  --arg transport_auto_client_inner_source "$transport_auto_client_inner_source" \
  --arg transport_auto_disable_synthetic_fallback "$transport_auto_disable_synthetic_fallback" \
  --arg transport_auto_data_plane_mode_opaque "$transport_auto_data_plane_mode_opaque" \
  --arg likely_primary_failure "$likely_primary_failure" \
  --arg operator_hint "$operator_hint" \
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
  --argjson transport_mismatch_failures "$transport_mismatch_failures" \
  --argjson token_proof_invalid_failures "$token_proof_invalid_failures" \
  --argjson unknown_exit_failures "$unknown_exit_failures" \
  --argjson directory_trust_failures "$directory_trust_failures" \
  --argjson root_required_failures "$root_required_failures" \
  --argjson endpoint_unreachable_failures "$endpoint_unreachable_failures" \
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
        allow_concurrent: ($allow_concurrent == "1"),
        rounds: $rounds,
        timeout_sec: $timeout_sec,
        execution_mode: $execution_mode,
        execution_mode_effective: $execution_mode_effective,
        execution_mode_adjusted: ($execution_mode_adjusted == "1"),
        execution_mode_adjustment_reason: (if $execution_mode_adjustment_reason == "" then null else $execution_mode_adjustment_reason end),
        explicit_remote_endpoints: ($explicit_remote_endpoints == "1"),
        transport_auto_defaults: {
          client_inner_source_udp: ($transport_auto_client_inner_source == "1"),
          disable_synthetic_fallback: ($transport_auto_disable_synthetic_fallback == "1"),
          data_plane_mode_opaque: ($transport_auto_data_plane_mode_opaque == "1")
        },
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
    aggregated_diagnostics: {
      transport_mismatch_failures: $transport_mismatch_failures,
      token_proof_invalid_failures: $token_proof_invalid_failures,
      unknown_exit_failures: $unknown_exit_failures,
      directory_trust_failures: $directory_trust_failures,
      root_required_failures: $root_required_failures,
      endpoint_unreachable_failures: $endpoint_unreachable_failures
    },
    likely_primary_failure: $likely_primary_failure,
    operator_hint: $operator_hint,
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
campaign_log_event "stage=campaign-end status=$status rc=$rc recommended_default_profile=$recommended_default_profile elapsed_sec=$(campaign_elapsed_sec "$campaign_started_epoch") summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
