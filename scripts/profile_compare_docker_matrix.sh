#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_docker_matrix.sh \
    [--dry-run [0|1]] \
    [profile-compare-campaign args...]

Purpose:
  Run profile-compare-campaign with docker-first defaults for direct
  `1hop|2hop|3hop` comparison, while still allowing pass-through overrides.

Defaults applied by this wrapper:
  --profiles 1hop,2hop,3hop
  --execution-mode docker
  --start-local-stack 1
  --force-stack-reset 1
  --beta-profile 0
  --prod-profile 0

Output:
  Prints summary/report/trend artifact paths after each run.
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

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

write_dry_run_artifacts() {
  local generated_at_utc
  local dry_run_notes
  local trend_notes
  local decision_rationale

  generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  dry_run_notes="dry-run synthetic campaign summary (insufficient data: campaign execution skipped)"
  trend_notes="dry-run synthetic trend summary (insufficient data: zero reports)"
  decision_rationale="dry-run synthetic safe fallback for contract continuity; not production signoff data"

  cat >"$trend_summary_json" <<EOF
{
  "version": 1,
  "generated_at_utc": "$(json_escape "$generated_at_utc")",
  "status": "warn",
  "rc": 0,
  "notes": "$(json_escape "$trend_notes")",
  "summary": {
    "reports_total": 0,
    "pass_reports": 0,
    "warn_reports": 0,
    "fail_reports": 0,
    "top_vote_profile": "",
    "top_vote_count": 0
  },
  "decision": {
    "recommended_default_profile": "balanced",
    "source": "safe_default_fallback",
    "rationale": "$(json_escape "$decision_rationale")",
    "recommendation_support_count": 0,
    "recommendation_support_rate_pct": 0,
    "experimental_non_default_profiles": [
      "speed-1hop"
    ]
  },
  "selected_summaries": [],
  "reports": [],
  "vote_summary": [],
  "profiles": [],
  "reliable_profiles": [],
  "artifacts": {
    "summary_log": "",
    "summary_json": "$(json_escape "$trend_summary_json")",
    "report_md": "$(json_escape "$trend_report_md")"
  }
}
EOF

  cat >"$trend_report_md" <<EOF
# Profile Compare Trend Report (Dry Run)

- Status: \`warn\`
- Notes: $trend_notes
- Reports considered: \`0\`
- Recommended default profile: \`balanced\` (\`safe_default_fallback\`)
EOF

  cat >"$summary_json" <<EOF
{
  "version": 1,
  "generated_at_utc": "$(json_escape "$generated_at_utc")",
  "status": "warn",
  "rc": 0,
  "notes": "$(json_escape "$dry_run_notes")",
  "command": "$(json_escape "$(print_cmd "$0" "$@")")",
  "summary": {
    "runs_total": 0,
    "runs_pass": 0,
    "runs_warn": 0,
    "runs_fail": 0,
    "runs_with_summary": 0,
    "runs_missing_summary": 0
  },
  "decision": {
    "recommended_default_profile": "balanced",
    "source": "safe_default_fallback",
    "rationale": "$(json_escape "$decision_rationale")",
    "experimental_non_default_profiles": [
      "speed-1hop"
    ]
  },
  "trend": {
    "status": "warn",
    "rc": 0,
    "notes": "$(json_escape "$trend_notes")",
    "summary_json": "$(json_escape "$trend_summary_json")",
    "report_md": "$(json_escape "$trend_report_md")",
    "log": ""
  },
  "selected_summaries": [],
  "runs": [],
  "artifacts": {
    "summary_json": "$(json_escape "$summary_json")",
    "report_md": "$(json_escape "$report_md")",
    "reports_dir": "$(json_escape "$reports_dir")",
    "trend_summary_json": "$(json_escape "$trend_summary_json")",
    "trend_report_md": "$(json_escape "$trend_report_md")"
  }
}
EOF

  cat >"$report_md" <<EOF
# Profile Compare Campaign Report (Dry Run)

- Status: \`warn\`
- Notes: $dry_run_notes
- Runs total: \`0\`
- Recommended default profile: \`balanced\` (\`safe_default_fallback\`)
- Trend summary JSON: \`$trend_summary_json\`
EOF
}

campaign_script="${PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign.sh}"
if [[ ! -x "$campaign_script" ]]; then
  echo "missing profile compare campaign script: $campaign_script"
  exit 2
fi

dry_run="${PROFILE_COMPARE_DOCKER_MATRIX_DRY_RUN:-0}"
campaign_runs="${PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_RUNS:-3}"
campaign_pause_sec="${PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_PAUSE_SEC:-0}"
rounds="${PROFILE_COMPARE_DOCKER_MATRIX_ROUNDS:-3}"
timeout_sec="${PROFILE_COMPARE_DOCKER_MATRIX_TIMEOUT_SEC:-35}"
discovery_wait_sec="${PROFILE_COMPARE_DOCKER_MATRIX_DISCOVERY_WAIT_SEC:-20}"
min_sources="${PROFILE_COMPARE_DOCKER_MATRIX_MIN_SOURCES:-1}"
profiles_csv="${PROFILE_COMPARE_DOCKER_MATRIX_PROFILES:-1hop,2hop,3hop}"
execution_mode="${PROFILE_COMPARE_DOCKER_MATRIX_EXECUTION_MODE:-docker}"
start_local_stack="${PROFILE_COMPARE_DOCKER_MATRIX_START_LOCAL_STACK:-1}"
force_stack_reset="${PROFILE_COMPARE_DOCKER_MATRIX_FORCE_STACK_RESET:-1}"
stack_strict_beta="${PROFILE_COMPARE_DOCKER_MATRIX_STACK_STRICT_BETA:-0}"
beta_profile="${PROFILE_COMPARE_DOCKER_MATRIX_BETA_PROFILE:-0}"
prod_profile="${PROFILE_COMPARE_DOCKER_MATRIX_PROD_PROFILE:-0}"
print_summary_json="${PROFILE_COMPARE_DOCKER_MATRIX_PRINT_SUMMARY_JSON:-0}"
start_local_stack_env_overridden="0"
if [[ -n "${PROFILE_COMPARE_DOCKER_MATRIX_START_LOCAL_STACK+x}" ]]; then
  start_local_stack_env_overridden="1"
fi

input_reports_dir=""
input_summary_json=""
input_report_md=""

declare -a passthrough_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dry_run="${2:-}"
        shift 2
      else
        dry_run="1"
        shift
      fi
      ;;
    --reports-dir)
      input_reports_dir="${2:-}"
      passthrough_args+=("$1" "${2:-}")
      shift 2
      ;;
    --summary-json)
      input_summary_json="${2:-}"
      passthrough_args+=("$1" "${2:-}")
      shift 2
      ;;
    --report-md)
      input_report_md="${2:-}"
      passthrough_args+=("$1" "${2:-}")
      shift 2
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      passthrough_args+=("$1")
      shift
      ;;
  esac
done

bool_arg_or_die "--dry-run" "$dry_run"
bool_arg_or_die "--force-stack-reset" "$force_stack_reset"
bool_arg_or_die "--stack-strict-beta" "$stack_strict_beta"
bool_arg_or_die "--beta-profile" "$beta_profile"
bool_arg_or_die "--prod-profile" "$prod_profile"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

effective_execution_mode="$execution_mode"
effective_start_local_stack="$start_local_stack"
effective_endpoints_present="0"
cli_overrode_start_local_stack="0"
if ((${#passthrough_args[@]} > 0)); then
  idx=0
  while ((idx < ${#passthrough_args[@]})); do
    arg="${passthrough_args[$idx]}"
    next_arg="${passthrough_args[$((idx + 1))]:-}"
    case "$arg" in
      --execution-mode)
        if ((idx + 1 < ${#passthrough_args[@]})); then
          effective_execution_mode="$next_arg"
          idx=$((idx + 2))
          continue
        fi
        ;;
      --start-local-stack)
        if ((idx + 1 < ${#passthrough_args[@]})); then
          effective_start_local_stack="$next_arg"
          cli_overrode_start_local_stack="1"
          idx=$((idx + 2))
          continue
        fi
        ;;
      --directory-urls|--bootstrap-directory|--issuer-url|--entry-url|--exit-url)
        if ((idx + 1 < ${#passthrough_args[@]})); then
          if [[ -n "$next_arg" && "$next_arg" != --* ]]; then
            effective_endpoints_present="1"
          fi
          idx=$((idx + 2))
          continue
        fi
        ;;
    esac
    idx=$((idx + 1))
  done
fi

non_root_fallback_note=""
if [[ "$dry_run" == "0" && "$effective_execution_mode" == "docker" && "$effective_start_local_stack" == "1" && "${EUID:-$(id -u)}" -ne 0 ]]; then
  explicit_start_local_stack="0"
  if [[ "$cli_overrode_start_local_stack" == "1" || "$start_local_stack_env_overridden" == "1" ]]; then
    explicit_start_local_stack="1"
  fi

  if [[ "$explicit_start_local_stack" == "1" ]]; then
    echo "profile-compare-docker-matrix: non-root cannot use --start-local-stack=1 in docker mode."
    echo "hint: run with sudo, or pass --start-local-stack 0 with --bootstrap-directory/--directory-urls."
    exit 2
  fi

  if [[ "$effective_endpoints_present" == "1" ]]; then
    passthrough_args+=(--start-local-stack 0)
    effective_start_local_stack="0"
    non_root_fallback_note="non-root default detected; forcing --start-local-stack 0 and using explicit endpoints"
  else
    dry_run="1"
    non_root_fallback_note="non-root default detected without explicit endpoints; switching to dry-run"
  fi
fi

log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"

run_stamp="$(date -u +%Y%m%d_%H%M%S)"

reports_dir=""
if [[ -n "$input_reports_dir" ]]; then
  reports_dir="$(abs_path "$input_reports_dir")"
else
  reports_dir="$log_dir/profile_compare_docker_matrix_${run_stamp}"
fi

summary_json=""
if [[ -n "$input_summary_json" ]]; then
  summary_json="$(abs_path "$input_summary_json")"
else
  summary_json="$reports_dir/profile_compare_docker_matrix_summary.json"
fi

report_md=""
if [[ -n "$input_report_md" ]]; then
  report_md="$(abs_path "$input_report_md")"
else
  report_md="$reports_dir/profile_compare_docker_matrix_report.md"
fi

trend_summary_json="$reports_dir/profile_compare_trend_summary.json"
trend_report_md="$reports_dir/profile_compare_trend_report.md"

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

campaign_cmd=(
  "$campaign_script"
  --campaign-runs "$campaign_runs"
  --campaign-pause-sec "$campaign_pause_sec"
  --profiles "$profiles_csv"
  --rounds "$rounds"
  --timeout-sec "$timeout_sec"
  --execution-mode "$execution_mode"
  --discovery-wait-sec "$discovery_wait_sec"
  --min-sources "$min_sources"
  --beta-profile "$beta_profile"
  --prod-profile "$prod_profile"
  --start-local-stack "$start_local_stack"
  --force-stack-reset "$force_stack_reset"
  --stack-strict-beta "$stack_strict_beta"
  --reports-dir "$reports_dir"
  --summary-json "$summary_json"
  --report-md "$report_md"
  --print-summary-json "$print_summary_json"
)
campaign_cmd+=("${passthrough_args[@]}")

if [[ "$dry_run" == "1" ]]; then
  write_dry_run_artifacts "${campaign_cmd[@]}"
  if [[ -n "$non_root_fallback_note" ]]; then
    echo "profile-compare-docker-matrix: $non_root_fallback_note"
    echo "hint: for a real run, provide --bootstrap-directory/--directory-urls with --start-local-stack 0, or run with sudo."
  fi
  echo "profile-compare-docker-matrix: dry-run"
  printf 'campaign_cmd: '
  print_cmd "${campaign_cmd[@]}"
  echo "reports_dir: $reports_dir"
  echo "summary_json: $summary_json"
  echo "report_md: $report_md"
  echo "trend_summary_json: $trend_summary_json"
  echo "trend_report_md: $trend_report_md"
  exit 0
fi

if [[ -n "$non_root_fallback_note" ]]; then
  echo "profile-compare-docker-matrix: $non_root_fallback_note"
fi

set +e
"${campaign_cmd[@]}"
rc=$?
set -e

echo "profile-compare-docker-matrix: rc=$rc"
echo "reports_dir: $reports_dir"
echo "summary_json: $summary_json"
echo "report_md: $report_md"
echo "trend_summary_json: $trend_summary_json"
echo "trend_report_md: $trend_report_md"

exit "$rc"
