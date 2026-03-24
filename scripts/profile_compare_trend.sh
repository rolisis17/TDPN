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
  ./scripts/profile_compare_trend.sh \
    [--compare-summary-json PATH]... \
    [--compare-summary-list FILE] \
    [--reports-dir DIR] \
    [--max-reports N] \
    [--since-hours N] \
    [--min-profile-runs N] \
    [--min-profile-pass-rate-pct N] \
    [--balanced-latency-margin-pct N] \
    [--fail-on-any-fail [0|1]] \
    [--min-decision-rate-pct N] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Aggregate multiple profile-compare-local summaries and produce one
  decision-grade default profile recommendation.

Policy:
  - `speed-1hop` is always treated as experimental/non-default.
  - Recommendation prefers reliable non-experimental profiles first.
  - `balanced` is preferred when latency stays within a configurable margin
    of the fastest reliable non-experimental profile.
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

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

file_mtime_epoch() {
  local file="$1"
  if stat -c %Y "$file" >/dev/null 2>&1; then
    stat -c %Y "$file"
    return
  fi
  if stat -f %m "$file" >/dev/null 2>&1; then
    stat -f %m "$file"
    return
  fi
  echo "0"
}

json_report_valid() {
  local file="$1"
  [[ -f "$file" ]] || return 1
  jq -e '.version == 1 and (.summary | type == "object") and (.profiles | type == "array") and (.decision | type == "object")' "$file" >/dev/null 2>&1
}

original_args=("$@")

declare -a compare_summary_jsons=()
compare_summary_list=""
reports_dir=""
max_reports="20"
since_hours="0"
min_profile_runs="3"
min_profile_pass_rate_pct="95"
balanced_latency_margin_pct="15"
fail_on_any_fail="0"
min_decision_rate_pct="0"
summary_json=""
report_md=""
print_summary_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --compare-summary-json)
      compare_summary_jsons+=("${2:-}")
      shift 2
      ;;
    --compare-summary-list)
      compare_summary_list="${2:-}"
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
    --min-profile-runs)
      min_profile_runs="${2:-}"
      shift 2
      ;;
    --min-profile-pass-rate-pct)
      min_profile_pass_rate_pct="${2:-}"
      shift 2
      ;;
    --balanced-latency-margin-pct)
      balanced_latency_margin_pct="${2:-}"
      shift 2
      ;;
    --fail-on-any-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_any_fail="${2:-}"
        shift 2
      else
        fail_on_any_fail="1"
        shift
      fi
      ;;
    --min-decision-rate-pct)
      min_decision_rate_pct="${2:-}"
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
bool_arg_or_die "--fail-on-any-fail" "$fail_on_any_fail"

if ! [[ "$max_reports" =~ ^[0-9]+$ ]] || ((max_reports < 1)); then
  echo "--max-reports must be >= 1"
  exit 2
fi
if ! [[ "$since_hours" =~ ^[0-9]+$ ]]; then
  echo "--since-hours must be a non-negative integer"
  exit 2
fi
if ! [[ "$min_profile_runs" =~ ^[0-9]+$ ]] || ((min_profile_runs < 1)); then
  echo "--min-profile-runs must be >= 1"
  exit 2
fi
for decimal_arg in "$min_profile_pass_rate_pct" "$balanced_latency_margin_pct" "$min_decision_rate_pct"; do
  if ! is_non_negative_decimal "$decimal_arg"; then
    echo "decimal thresholds must be non-negative numbers"
    exit 2
  fi
done

log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"

if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/profile_compare_trend_${run_stamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$report_md" ]]; then
  report_md="$log_dir/profile_compare_trend_${run_stamp}.md"
else
  report_md="$(abs_path "$report_md")"
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

summary_log="$log_dir/profile_compare_trend_${run_stamp}.log"
: >"$summary_log"

if [[ -n "$compare_summary_list" ]]; then
  compare_summary_list="$(abs_path "$compare_summary_list")"
  if [[ ! -f "$compare_summary_list" ]]; then
    echo "--compare-summary-list file not found: $compare_summary_list"
    exit 2
  fi
fi

if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs"
else
  reports_dir="$(abs_path "$reports_dir")"
fi

# Build candidate path list.
declare -a candidate_paths=()
for raw_path in "${compare_summary_jsons[@]}"; do
  path="$(abs_path "$raw_path")"
  [[ -n "$path" ]] && candidate_paths+=("$path")
done

if [[ -n "$compare_summary_list" ]]; then
  while IFS= read -r list_line || [[ -n "$list_line" ]]; do
    list_line="$(trim "$list_line")"
    [[ -z "$list_line" || "$list_line" == \#* ]] && continue
    path="$(abs_path "$list_line")"
    [[ -n "$path" ]] && candidate_paths+=("$path")
  done <"$compare_summary_list"
fi

if [[ ${#candidate_paths[@]} -eq 0 ]]; then
  if [[ -d "$reports_dir" ]]; then
    while IFS= read -r found_path; do
      [[ -n "$found_path" ]] && candidate_paths+=("$found_path")
    done < <(find "$reports_dir" -maxdepth 1 -type f -name 'profile_compare_local_*.json' 2>/dev/null)
  fi
fi

if [[ ${#candidate_paths[@]} -eq 0 ]]; then
  echo "profile-compare-trend: no input summaries found"
  exit 1
fi

# Deduplicate and filter by validity/time.
declare -A seen_paths=()
indexed_file="$(mktemp)"
reports_rows_file="$(mktemp)"
selected_paths_file="$(mktemp)"
trap 'rm -f "$indexed_file" "$reports_rows_file" "$selected_paths_file"' EXIT

now_epoch="$(date +%s)"
min_epoch="0"
if ((since_hours > 0)); then
  min_epoch=$((now_epoch - since_hours * 3600))
fi

for candidate in "${candidate_paths[@]}"; do
  candidate="$(trim "$candidate")"
  [[ -z "$candidate" ]] && continue
  if [[ -n "${seen_paths[$candidate]:-}" ]]; then
    continue
  fi
  seen_paths["$candidate"]="1"

  if ! json_report_valid "$candidate"; then
    continue
  fi

  mtime_epoch="$(file_mtime_epoch "$candidate")"
  if ! [[ "$mtime_epoch" =~ ^[0-9]+$ ]]; then
    mtime_epoch="0"
  fi
  if ((mtime_epoch < min_epoch)); then
    continue
  fi

  printf '%s|%s\n' "$mtime_epoch" "$candidate" >>"$indexed_file"
done

if [[ ! -s "$indexed_file" ]]; then
  echo "profile-compare-trend: no valid summaries matched filters"
  exit 1
fi

sort -t '|' -k1,1nr "$indexed_file" | head -n "$max_reports" | awk -F'|' '{print $2}' >"$selected_paths_file"

mapfile -t selected_paths <"$selected_paths_file"
if [[ ${#selected_paths[@]} -eq 0 ]]; then
  echo "profile-compare-trend: no summaries selected after sorting"
  exit 1
fi

for summary_path in "${selected_paths[@]}"; do
  generated_at="$(jq -r '.generated_at_utc // ""' "$summary_path")"
  report_status="$(jq -r '.status // "unknown"' "$summary_path")"
  report_rc="$(jq -r '.rc // 1' "$summary_path")"
  report_reco="$(jq -r '.decision.recommended_default_profile // ""' "$summary_path")"
  report_runs_executed="$(jq -r '.summary.runs_executed // 0' "$summary_path")"
  report_runs_fail="$(jq -r '.summary.runs_fail // 0' "$summary_path")"

  jq -n \
    --arg path "$summary_path" \
    --arg generated_at_utc "$generated_at" \
    --arg status "$report_status" \
    --argjson rc "$report_rc" \
    --arg recommended_default_profile "$report_reco" \
    --argjson runs_executed "$report_runs_executed" \
    --argjson runs_fail "$report_runs_fail" \
    '{
      path: $path,
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      recommended_default_profile: $recommended_default_profile,
      runs_executed: $runs_executed,
      runs_fail: $runs_fail
    }' >>"$reports_rows_file"
done

reports_json="$(jq -s '.' "${selected_paths[@]}")"
reports_rows_json="$(jq -s '.' "$reports_rows_file")"

reports_total="$(jq 'length' <<<"$reports_json")"
pass_reports="$(jq '[.[] | select(.status == "pass")] | length' <<<"$reports_json")"
warn_reports="$(jq '[.[] | select(.status == "warn")] | length' <<<"$reports_json")"
fail_reports="$(jq '[.[] | select(.status == "fail")] | length' <<<"$reports_json")"

profile_aggregate_json="$(jq '
  [ .[] | .profiles[]? ]
  | group_by(.profile)
  | map(
      {
        profile: .[0].profile,
        reports_seen: length,
        runs_executed: (map(.runs_executed // 0) | add),
        runs_pass: (map(.runs_pass // 0) | add),
        runs_fail: (map(.runs_fail // 0) | add),
        weighted_duration_sum: (map((.avg_duration_sec // 0) * (.runs_executed // 0)) | add)
      }
      | . + {
          pass_rate_pct: (if .runs_executed > 0 then ((.runs_pass * 100.0) / .runs_executed) else 0 end),
          avg_duration_sec: (if .runs_executed > 0 then (.weighted_duration_sum / .runs_executed) else 0 end)
        }
      | del(.weighted_duration_sum)
    )
  | sort_by(.profile)
' <<<"$reports_json")"

vote_summary_json="$(jq '
  [ .[] | .decision.recommended_default_profile // "" ]
  | map(select(length > 0 and . != "speed-1hop"))
  | group_by(.)
  | map({profile: .[0], count: length})
  | sort_by(-.count, .profile)
' <<<"$reports_json")"

top_vote_profile="$(jq -r '.[0].profile // ""' <<<"$vote_summary_json")"
top_vote_count="$(jq -r '.[0].count // 0' <<<"$vote_summary_json")"

reliable_profiles_json="$(jq \
  --argjson min_runs "$min_profile_runs" \
  --argjson min_pass "$min_profile_pass_rate_pct" \
  '[ .[] | select(.profile != "speed-1hop" and .runs_executed >= $min_runs and .pass_rate_pct >= $min_pass) ] | sort_by(.avg_duration_sec, .profile)' \
  <<<"$profile_aggregate_json")"

reliable_count="$(jq 'length' <<<"$reliable_profiles_json")"
fastest_reliable_profile="$(jq -r '.[0].profile // ""' <<<"$reliable_profiles_json")"
fastest_reliable_duration="$(jq -r '.[0].avg_duration_sec // 0' <<<"$reliable_profiles_json")"

balanced_reliable_duration="$(jq -r '[.[] | select(.profile == "balanced")][0].avg_duration_sec // ""' <<<"$reliable_profiles_json")"

recommended_default_profile=""
decision_source=""
decision_rationale=""

if ((reliable_count > 0)); then
  if [[ -n "$balanced_reliable_duration" ]] && awk -v bal="$balanced_reliable_duration" -v fastest="$fastest_reliable_duration" -v margin_pct="$balanced_latency_margin_pct" 'BEGIN { threshold = fastest * (1 + (margin_pct / 100.0)); exit !(bal <= threshold) }'; then
    recommended_default_profile="balanced"
    decision_source="policy_reliability_latency"
    decision_rationale="balanced is reliable and within ${balanced_latency_margin_pct}% of fastest reliable non-experimental profile"
  else
    recommended_default_profile="$fastest_reliable_profile"
    decision_source="policy_reliability_latency"
    decision_rationale="selected fastest reliable non-experimental profile from aggregated runs"
  fi
elif [[ -n "$top_vote_profile" ]]; then
  recommended_default_profile="$top_vote_profile"
  decision_source="vote_fallback"
  decision_rationale="no profile met reliability thresholds; using non-experimental majority vote fallback"
else
  recommended_default_profile="balanced"
  decision_source="safe_default_fallback"
  decision_rationale="no reliable/voted recommendation available; defaulting to balanced"
fi

recommendation_support_count="$(jq --arg p "$recommended_default_profile" '[.[] | select((.decision.recommended_default_profile // "") == $p)] | length' <<<"$reports_json")"
recommendation_support_rate_pct="0"
if ((reports_total > 0)); then
  recommendation_support_rate_pct="$(awk -v c="$recommendation_support_count" -v t="$reports_total" 'BEGIN { printf "%.2f", (c * 100.0) / t }')"
fi

status="pass"
rc=0
notes="aggregated profile comparison trend ready"
if ((warn_reports > 0 || fail_reports > 0)); then
  status="warn"
  notes="one or more source comparisons were warn/fail; recommendation includes degraded runs"
fi
if [[ "$fail_on_any_fail" == "1" ]] && ((fail_reports > 0)); then
  status="fail"
  rc=1
  notes="fail-on-any-fail gate tripped: at least one source comparison failed"
fi
if awk -v observed="$recommendation_support_rate_pct" -v min_required="$min_decision_rate_pct" 'BEGIN { exit !(observed < min_required) }'; then
  status="fail"
  rc=1
  notes="decision support rate below threshold (observed=${recommendation_support_rate_pct}%, required=${min_decision_rate_pct}%)"
fi
if [[ -z "$recommended_default_profile" ]]; then
  status="fail"
  rc=1
  notes="could not determine recommended default profile"
fi

selected_paths_json="$(printf '%s\n' "${selected_paths[@]}" | jq -R . | jq -s '.')"

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg command "$(print_cmd "$0" "${original_args[@]}")" \
  --arg summary_log "$summary_log" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --arg reports_dir "$reports_dir" \
  --argjson rc "$rc" \
  --argjson max_reports "$max_reports" \
  --argjson since_hours "$since_hours" \
  --argjson min_profile_runs "$min_profile_runs" \
  --argjson min_profile_pass_rate_pct "$min_profile_pass_rate_pct" \
  --argjson balanced_latency_margin_pct "$balanced_latency_margin_pct" \
  --arg fail_on_any_fail "$fail_on_any_fail" \
  --argjson min_decision_rate_pct "$min_decision_rate_pct" \
  --arg recommended_default_profile "$recommended_default_profile" \
  --arg decision_source "$decision_source" \
  --arg decision_rationale "$decision_rationale" \
  --argjson recommendation_support_count "$recommendation_support_count" \
  --argjson recommendation_support_rate_pct "$recommendation_support_rate_pct" \
  --argjson reports_total "$reports_total" \
  --argjson pass_reports "$pass_reports" \
  --argjson warn_reports "$warn_reports" \
  --argjson fail_reports "$fail_reports" \
  --arg top_vote_profile "$top_vote_profile" \
  --argjson top_vote_count "$top_vote_count" \
  --argjson selected_paths "$selected_paths_json" \
  --argjson reports "$reports_rows_json" \
  --argjson vote_summary "$vote_summary_json" \
  --argjson profiles "$profile_aggregate_json" \
  --argjson reliable_profiles "$reliable_profiles_json" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    notes: $notes,
    command: $command,
    inputs: {
      reports_dir: $reports_dir,
      max_reports: $max_reports,
      since_hours: $since_hours,
      min_profile_runs: $min_profile_runs,
      min_profile_pass_rate_pct: $min_profile_pass_rate_pct,
      balanced_latency_margin_pct: $balanced_latency_margin_pct,
      fail_on_any_fail: ($fail_on_any_fail == "1"),
      min_decision_rate_pct: $min_decision_rate_pct
    },
    summary: {
      reports_total: $reports_total,
      pass_reports: $pass_reports,
      warn_reports: $warn_reports,
      fail_reports: $fail_reports,
      top_vote_profile: $top_vote_profile,
      top_vote_count: $top_vote_count
    },
    decision: {
      recommended_default_profile: $recommended_default_profile,
      source: $decision_source,
      rationale: $decision_rationale,
      recommendation_support_count: $recommendation_support_count,
      recommendation_support_rate_pct: $recommendation_support_rate_pct,
      experimental_non_default_profiles: ["speed-1hop"]
    },
    selected_summaries: $selected_paths,
    reports: $reports,
    vote_summary: $vote_summary,
    profiles: $profiles,
    reliable_profiles: $reliable_profiles,
    artifacts: {
      summary_log: $summary_log,
      summary_json: $summary_json,
      report_md: $report_md
    }
  }' >"$summary_json"

{
  echo "# Profile Compare Trend Report"
  echo
  echo "- Generated at (UTC): \`$(jq -r '.generated_at_utc' "$summary_json")\`"
  echo "- Status: \`$(jq -r '.status' "$summary_json")\`"
  echo "- Summary JSON: \`$summary_json\`"
  echo "- Summary Log: \`$summary_log\`"
  echo
  echo "## Decision"
  echo
  echo "- Recommended default: \`$(jq -r '.decision.recommended_default_profile' "$summary_json")\`"
  echo "- Source: \`$(jq -r '.decision.source' "$summary_json")\`"
  echo "- Rationale: $(jq -r '.decision.rationale' "$summary_json")"
  echo "- Recommendation support: \`$(jq -r '.decision.recommendation_support_count' "$summary_json")\` / \`$(jq -r '.summary.reports_total' "$summary_json")\` (\`$(jq -r '.decision.recommendation_support_rate_pct' "$summary_json")%\`)"
  echo
  echo "## Source Summary"
  echo
  echo "- Reports considered: \`$(jq -r '.summary.reports_total' "$summary_json")\`"
  echo "- Pass: \`$(jq -r '.summary.pass_reports' "$summary_json")\`"
  echo "- Warn: \`$(jq -r '.summary.warn_reports' "$summary_json")\`"
  echo "- Fail: \`$(jq -r '.summary.fail_reports' "$summary_json")\`"
  echo
  echo "## Profile Aggregates"
  echo
  echo "| Profile | Runs Executed | Runs Pass | Runs Fail | Pass % | Avg Duration (s) |"
  echo "|---|---:|---:|---:|---:|---:|"
  jq -r '.profiles[] | "| \(.profile) | \(.runs_executed) | \(.runs_pass) | \(.runs_fail) | \(.pass_rate_pct) | \(.avg_duration_sec) |"' "$summary_json"
} >"$report_md"

echo "profile-compare-trend: status=$status"
echo "summary_log: $summary_log"
echo "summary_json: $summary_json"
echo "report_md: $report_md"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
