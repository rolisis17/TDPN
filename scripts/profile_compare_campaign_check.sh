#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_campaign_check.sh \
    [--campaign-summary-json PATH] \
    [--trend-summary-json PATH] \
    [--reports-dir DIR] \
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
    [--require-selection-policy-present [0|1]] \
    [--require-selection-policy-valid [0|1]] \
    [--fail-on-no-go [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Verify profile-compare campaign artifacts and emit a fail-closed
  GO/NO-GO decision for default-profile recommendation readiness.

Notes:
  - Recommended input: --campaign-summary-json from profile-compare-campaign.
  - If campaign summary is omitted, the latest
    profile_compare_campaign_summary.json under --reports-dir is used.
  - `speed-1hop` remains non-default by policy.
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

normalize_profile() {
  local profile
  profile="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$profile" in
    speed|balanced|private|speed-1hop) printf '%s\n' "$profile" ;;
    2hop|2-hop|hop2|hop-2|twohop) printf '%s\n' "balanced" ;;
    3hop|3-hop|hop3|hop-3|threehop) printf '%s\n' "private" ;;
    fast) printf '%s\n' "speed" ;;
    privacy) printf '%s\n' "private" ;;
    speed1hop|onehop|1hop|1-hop|hop1|hop-1|fast-1hop|fast1hop) printf '%s\n' "speed-1hop" ;;
    *) printf '%s\n' "$profile" ;;
  esac
}

csv_contains() {
  local csv="$1"
  local needle="$2"
  local item
  IFS=',' read -r -a _items <<<"$csv"
  for item in "${_items[@]}"; do
    item="$(normalize_profile "$item")"
    if [[ -n "$item" && "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

need_cmd jq
need_cmd date
need_cmd find

campaign_summary_json=""
trend_summary_json=""
reports_dir="${PROFILE_COMPARE_CAMPAIGN_CHECK_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"

require_status_pass="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_STATUS_PASS:-1}"
require_trend_status_pass="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_TREND_STATUS_PASS:-1}"
require_min_runs_total="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MIN_RUNS_TOTAL:-3}"
require_max_runs_fail="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MAX_RUNS_FAIL:-0}"
require_max_runs_warn="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MAX_RUNS_WARN:-0}"
require_min_runs_with_summary="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MIN_RUNS_WITH_SUMMARY:-3}"
require_recommendation_support_rate_pct="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_RECOMMENDATION_SUPPORT_RATE_PCT:-60}"
require_recommended_profile="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_RECOMMENDED_PROFILE:-}"
allow_recommended_profiles="${PROFILE_COMPARE_CAMPAIGN_CHECK_ALLOW_RECOMMENDED_PROFILES:-balanced,speed,private}"
disallow_experimental_default="${PROFILE_COMPARE_CAMPAIGN_CHECK_DISALLOW_EXPERIMENTAL_DEFAULT:-1}"
require_trend_source="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_TREND_SOURCE:-policy_reliability_latency,vote_fallback,safe_default_fallback}"
require_selection_policy_present="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_SELECTION_POLICY_PRESENT:-0}"
require_selection_policy_valid="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_SELECTION_POLICY_VALID:-0}"
fail_on_no_go="${PROFILE_COMPARE_CAMPAIGN_CHECK_FAIL_ON_NO_GO:-1}"
show_json="${PROFILE_COMPARE_CAMPAIGN_CHECK_SHOW_JSON:-0}"
print_summary_json="${PROFILE_COMPARE_CAMPAIGN_CHECK_PRINT_SUMMARY_JSON:-0}"
summary_json="${PROFILE_COMPARE_CAMPAIGN_CHECK_SUMMARY_JSON:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --campaign-summary-json)
      campaign_summary_json="${2:-}"
      shift 2
      ;;
    --trend-summary-json)
      trend_summary_json="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
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
    --require-selection-policy-present)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_selection_policy_present="${2:-}"
        shift 2
      else
        require_selection_policy_present="1"
        shift
      fi
      ;;
    --require-selection-policy-valid)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_selection_policy_valid="${2:-}"
        shift 2
      else
        require_selection_policy_valid="1"
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
    --summary-json)
      summary_json="${2:-}"
      shift 2
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

bool_arg_or_die "--require-status-pass" "$require_status_pass"
bool_arg_or_die "--require-trend-status-pass" "$require_trend_status_pass"
bool_arg_or_die "--disallow-experimental-default" "$disallow_experimental_default"
bool_arg_or_die "--require-selection-policy-present" "$require_selection_policy_present"
bool_arg_or_die "--require-selection-policy-valid" "$require_selection_policy_valid"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

for int_arg in "$require_min_runs_total" "$require_max_runs_fail" "$require_max_runs_warn" "$require_min_runs_with_summary"; do
  if ! [[ "$int_arg" =~ ^[0-9]+$ ]]; then
    echo "run count thresholds must be non-negative integers"
    exit 2
  fi
done

if ! is_non_negative_decimal "$require_recommendation_support_rate_pct"; then
  echo "--require-recommendation-support-rate-pct must be a non-negative number"
  exit 2
fi

reports_dir="$(abs_path "$reports_dir")"

if [[ -n "$campaign_summary_json" ]]; then
  campaign_summary_json="$(abs_path "$campaign_summary_json")"
fi
if [[ -n "$trend_summary_json" ]]; then
  trend_summary_json="$(abs_path "$trend_summary_json")"
fi

if [[ -z "$campaign_summary_json" ]]; then
  direct_candidate="$reports_dir/profile_compare_campaign_summary.json"
  if [[ -f "$direct_candidate" ]]; then
    campaign_summary_json="$direct_candidate"
  else
    latest_path=""
    latest_mtime="0"
    while IFS= read -r found_path; do
      found_mtime="$(file_mtime_epoch "$found_path")"
      if [[ ! "$found_mtime" =~ ^[0-9]+$ ]]; then
        continue
      fi
      if ((found_mtime > latest_mtime)); then
        latest_mtime="$found_mtime"
        latest_path="$found_path"
      fi
    done < <(find "$reports_dir" -type f -name 'profile_compare_campaign_summary.json' 2>/dev/null)
    campaign_summary_json="$latest_path"
  fi
fi

if [[ -z "$campaign_summary_json" || ! -f "$campaign_summary_json" ]]; then
  echo "profile-compare-campaign-check failed: campaign summary JSON not found"
  exit 1
fi
if ! jq -e '.version == 1 and (.summary | type == "object") and (.decision | type == "object") and (.trend | type == "object")' "$campaign_summary_json" >/dev/null 2>&1; then
  echo "profile-compare-campaign-check failed: invalid campaign summary JSON schema ($campaign_summary_json)"
  exit 1
fi

if [[ -z "$trend_summary_json" ]]; then
  trend_summary_json="$(jq -r '.trend.summary_json // ""' "$campaign_summary_json")"
  trend_summary_json="$(abs_path "$trend_summary_json")"
fi

trend_summary_present="0"
if [[ -n "$trend_summary_json" && -f "$trend_summary_json" ]] &&
  jq -e '.version == 1 and (.summary | type == "object") and (.decision | type == "object")' "$trend_summary_json" >/dev/null 2>&1; then
  trend_summary_present="1"
fi

campaign_status="$(jq -r '.status // ""' "$campaign_summary_json")"
campaign_rc="$(jq -r '.rc // 1' "$campaign_summary_json")"
runs_total="$(jq -r '.summary.runs_total // 0' "$campaign_summary_json")"
runs_pass="$(jq -r '.summary.runs_pass // 0' "$campaign_summary_json")"
runs_warn="$(jq -r '.summary.runs_warn // 0' "$campaign_summary_json")"
runs_fail="$(jq -r '.summary.runs_fail // 0' "$campaign_summary_json")"
runs_with_summary="$(jq -r '.summary.runs_with_summary // 0' "$campaign_summary_json")"
recommended_profile="$(normalize_profile "$(jq -r '.decision.recommended_default_profile // ""' "$campaign_summary_json")")"
decision_source="$(jq -r '.decision.source // ""' "$campaign_summary_json")"
trend_status="$(jq -r '.trend.status // ""' "$campaign_summary_json")"
trend_rc="$(jq -r '.trend.rc // 1' "$campaign_summary_json")"

support_rate_pct="0"
trend_source_value="$decision_source"
if [[ "$trend_summary_present" == "1" ]]; then
  support_rate_pct="$(jq -r '.decision.recommendation_support_rate_pct // 0' "$trend_summary_json")"
  trend_source_value="$(jq -r '.decision.source // ""' "$trend_summary_json")"
  if [[ -z "$decision_source" ]]; then
    decision_source="$trend_source_value"
  fi
fi

if ! is_non_negative_decimal "$support_rate_pct"; then
  support_rate_pct="0"
fi

if [[ -n "$require_recommended_profile" ]]; then
  require_recommended_profile="$(normalize_profile "$require_recommended_profile")"
fi

campaign_selection_policy_present=0
campaign_selection_policy_valid=0
if jq -e '.summary.selection_policy | type == "object"' "$campaign_summary_json" >/dev/null 2>&1; then
  campaign_selection_policy_present=1
fi
if jq -e '
  .summary.selection_policy
  and (.summary.selection_policy.sticky_pair_sec | type == "number")
  and (.summary.selection_policy.entry_rotation_sec | type == "number")
  and (.summary.selection_policy.entry_rotation_jitter_pct | type == "number")
  and (.summary.selection_policy.exit_exploration_pct | type == "number")
  and (.summary.selection_policy.path_profile | type == "string")
' "$campaign_summary_json" >/dev/null 2>&1; then
  campaign_selection_policy_valid=1
fi

selection_policy_selected_summaries_total="$(jq -r '[.selected_summaries[]? | select(type == "string" and length > 0)] | length' "$campaign_summary_json" 2>/dev/null || printf '0')"
if ! [[ "$selection_policy_selected_summaries_total" =~ ^[0-9]+$ ]]; then
  selection_policy_selected_summaries_total="0"
fi
selection_policy_selected_summaries_found=0
selection_policy_selected_summaries_present_count=0
selection_policy_selected_summaries_valid_count=0
while IFS= read -r selected_summary_path; do
  selected_summary_path="$(abs_path "$selected_summary_path")"
  if [[ -z "$selected_summary_path" || ! -f "$selected_summary_path" ]]; then
    continue
  fi
  selection_policy_selected_summaries_found=$((selection_policy_selected_summaries_found + 1))
  if jq -e '.summary.selection_policy | type == "object"' "$selected_summary_path" >/dev/null 2>&1; then
    selection_policy_selected_summaries_present_count=$((selection_policy_selected_summaries_present_count + 1))
  fi
  if jq -e '
    .summary.selection_policy
    and (.summary.selection_policy.sticky_pair_sec | type == "number")
    and (.summary.selection_policy.entry_rotation_sec | type == "number")
    and (.summary.selection_policy.entry_rotation_jitter_pct | type == "number")
    and (.summary.selection_policy.exit_exploration_pct | type == "number")
    and (.summary.selection_policy.path_profile | type == "string")
  ' "$selected_summary_path" >/dev/null 2>&1; then
    selection_policy_selected_summaries_valid_count=$((selection_policy_selected_summaries_valid_count + 1))
  fi
done < <(jq -r '.selected_summaries[]? | select(type == "string" and length > 0)' "$campaign_summary_json" 2>/dev/null || true)

selection_policy_selected_summaries_missing_or_unreadable_count=$((selection_policy_selected_summaries_total - selection_policy_selected_summaries_found))
if ((selection_policy_selected_summaries_missing_or_unreadable_count < 0)); then
  selection_policy_selected_summaries_missing_or_unreadable_count=0
fi
selection_policy_selected_summaries_invalid_or_missing_policy_count=$((selection_policy_selected_summaries_total - selection_policy_selected_summaries_valid_count))
if ((selection_policy_selected_summaries_invalid_or_missing_policy_count < 0)); then
  selection_policy_selected_summaries_invalid_or_missing_policy_count=0
fi

selection_policy_evidence_present=0
if ((campaign_selection_policy_present == 1 || selection_policy_selected_summaries_present_count > 0)); then
  selection_policy_evidence_present=1
fi
selection_policy_evidence_valid=0
if ((campaign_selection_policy_valid == 1)); then
  selection_policy_evidence_valid=1
elif ((selection_policy_selected_summaries_total > 0 && selection_policy_selected_summaries_valid_count == selection_policy_selected_summaries_total)); then
  selection_policy_evidence_valid=1
fi

declare -a errors=()

if [[ "$require_status_pass" == "1" ]] && [[ "$campaign_status" != "pass" ]]; then
  errors+=("campaign status must be pass (actual=${campaign_status:-unset})")
fi
if [[ "$campaign_rc" != "0" ]]; then
  errors+=("campaign rc must be 0 (actual=$campaign_rc)")
fi
if [[ "$require_trend_status_pass" == "1" ]] && [[ "$trend_status" != "pass" ]]; then
  errors+=("trend status must be pass (actual=${trend_status:-unset})")
fi
if [[ "$trend_rc" != "0" ]]; then
  errors+=("trend rc must be 0 (actual=$trend_rc)")
fi
if ((runs_total < require_min_runs_total)); then
  errors+=("runs_total below required minimum (actual=$runs_total required=$require_min_runs_total)")
fi
if ((runs_fail > require_max_runs_fail)); then
  errors+=("runs_fail exceeds allowed maximum (actual=$runs_fail max=$require_max_runs_fail)")
fi
if ((runs_warn > require_max_runs_warn)); then
  errors+=("runs_warn exceeds allowed maximum (actual=$runs_warn max=$require_max_runs_warn)")
fi
if ((runs_with_summary < require_min_runs_with_summary)); then
  errors+=("runs_with_summary below required minimum (actual=$runs_with_summary required=$require_min_runs_with_summary)")
fi
if [[ -z "$recommended_profile" ]]; then
  errors+=("recommended profile is empty")
fi
if [[ -n "$require_recommended_profile" && "$recommended_profile" != "$require_recommended_profile" ]]; then
  errors+=("recommended profile mismatch (actual=${recommended_profile:-unset} required=$require_recommended_profile)")
fi
if [[ -n "$allow_recommended_profiles" ]] && [[ -n "$recommended_profile" ]]; then
  if ! csv_contains "$allow_recommended_profiles" "$recommended_profile"; then
    errors+=("recommended profile is not in allowed set (actual=$recommended_profile allowed=$allow_recommended_profiles)")
  fi
fi
if [[ "$disallow_experimental_default" == "1" && "$recommended_profile" == "speed-1hop" ]]; then
  errors+=("recommended profile speed-1hop is experimental and cannot be a default")
fi
if awk -v observed="$support_rate_pct" -v min_required="$require_recommendation_support_rate_pct" 'BEGIN { exit !(observed < min_required) }'; then
  errors+=("recommendation support rate below threshold (actual=${support_rate_pct}% required=${require_recommendation_support_rate_pct}%)")
fi
if [[ "$trend_summary_present" != "1" ]]; then
  errors+=("trend summary JSON is missing or invalid (${trend_summary_json:-unset})")
fi
if [[ -n "$require_trend_source" ]]; then
  if [[ -z "$trend_source_value" ]]; then
    errors+=("trend source is missing")
  elif ! csv_contains "$require_trend_source" "$trend_source_value"; then
    errors+=("trend source is not allowed (actual=$trend_source_value allowed=$require_trend_source)")
  fi
fi
if [[ "$require_selection_policy_present" == "1" && "$selection_policy_evidence_present" != "1" ]]; then
  errors+=("selection policy evidence is required but not present")
fi
if [[ "$require_selection_policy_valid" == "1" && "$selection_policy_evidence_valid" != "1" ]]; then
  errors+=("selection policy evidence is required to be valid (valid_summaries=$selection_policy_selected_summaries_valid_count total_summaries=$selection_policy_selected_summaries_total)")
fi

decision="GO"
status="ok"
notes="campaign recommendation passes configured policy"
if ((${#errors[@]} > 0)); then
  decision="NO-GO"
  status="fail"
  notes="campaign recommendation violates one or more policy checks"
fi

rc=0
if [[ "$decision" == "NO-GO" && "$fail_on_no_go" == "1" ]]; then
  rc=1
fi

log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/profile_compare_campaign_check_${run_stamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

errors_json='[]'
if ((${#errors[@]} > 0)); then
  errors_json="$(printf '%s\n' "${errors[@]}" | jq -R . | jq -s '.')"
fi

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg decision "$decision" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg campaign_summary_json "$campaign_summary_json" \
  --arg trend_summary_json "$trend_summary_json" \
  --arg campaign_status "$campaign_status" \
  --argjson campaign_rc "$campaign_rc" \
  --argjson runs_total "$runs_total" \
  --argjson runs_pass "$runs_pass" \
  --argjson runs_warn "$runs_warn" \
  --argjson runs_fail "$runs_fail" \
  --argjson runs_with_summary "$runs_with_summary" \
  --arg recommended_profile "$recommended_profile" \
  --arg decision_source "$decision_source" \
  --arg trend_status "$trend_status" \
  --argjson trend_rc "$trend_rc" \
  --arg trend_source_value "$trend_source_value" \
  --argjson trend_summary_present "$trend_summary_present" \
  --argjson support_rate_pct "$support_rate_pct" \
  --argjson require_status_pass "$require_status_pass" \
  --argjson require_trend_status_pass "$require_trend_status_pass" \
  --argjson require_min_runs_total "$require_min_runs_total" \
  --argjson require_max_runs_fail "$require_max_runs_fail" \
  --argjson require_max_runs_warn "$require_max_runs_warn" \
  --argjson require_min_runs_with_summary "$require_min_runs_with_summary" \
  --argjson require_recommendation_support_rate_pct "$require_recommendation_support_rate_pct" \
  --arg require_recommended_profile "$require_recommended_profile" \
  --arg allow_recommended_profiles "$allow_recommended_profiles" \
  --argjson disallow_experimental_default "$disallow_experimental_default" \
  --arg require_trend_source "$require_trend_source" \
  --argjson require_selection_policy_present "$require_selection_policy_present" \
  --argjson require_selection_policy_valid "$require_selection_policy_valid" \
  --argjson selection_policy_evidence_present "$selection_policy_evidence_present" \
  --argjson selection_policy_evidence_valid "$selection_policy_evidence_valid" \
  --argjson campaign_selection_policy_present "$campaign_selection_policy_present" \
  --argjson campaign_selection_policy_valid "$campaign_selection_policy_valid" \
  --argjson selection_policy_selected_summaries_total "$selection_policy_selected_summaries_total" \
  --argjson selection_policy_selected_summaries_found "$selection_policy_selected_summaries_found" \
  --argjson selection_policy_selected_summaries_present_count "$selection_policy_selected_summaries_present_count" \
  --argjson selection_policy_selected_summaries_valid_count "$selection_policy_selected_summaries_valid_count" \
  --argjson selection_policy_selected_summaries_missing_or_unreadable_count "$selection_policy_selected_summaries_missing_or_unreadable_count" \
  --argjson selection_policy_selected_summaries_invalid_or_missing_policy_count "$selection_policy_selected_summaries_invalid_or_missing_policy_count" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --argjson rc "$rc" \
  --argjson errors "$errors_json" \
  --arg summary_json "$summary_json" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    decision: $decision,
    status: $status,
    rc: $rc,
    notes: $notes,
    inputs: {
      campaign_summary_json: $campaign_summary_json,
      trend_summary_json: $trend_summary_json,
      policy: {
        require_status_pass: ($require_status_pass == 1),
        require_trend_status_pass: ($require_trend_status_pass == 1),
        require_min_runs_total: $require_min_runs_total,
        require_max_runs_fail: $require_max_runs_fail,
        require_max_runs_warn: $require_max_runs_warn,
        require_min_runs_with_summary: $require_min_runs_with_summary,
        require_recommendation_support_rate_pct: $require_recommendation_support_rate_pct,
        require_recommended_profile: $require_recommended_profile,
        allow_recommended_profiles: $allow_recommended_profiles,
        disallow_experimental_default: ($disallow_experimental_default == 1),
        require_trend_source: $require_trend_source,
        require_selection_policy_present: ($require_selection_policy_present == 1),
        require_selection_policy_valid: ($require_selection_policy_valid == 1),
        fail_on_no_go: ($fail_on_no_go == 1)
      }
    },
    observed: {
      campaign_status: $campaign_status,
      campaign_rc: $campaign_rc,
      runs_total: $runs_total,
      runs_pass: $runs_pass,
      runs_warn: $runs_warn,
      runs_fail: $runs_fail,
      runs_with_summary: $runs_with_summary,
      recommended_profile: $recommended_profile,
      decision_source: $decision_source,
      trend_status: $trend_status,
      trend_rc: $trend_rc,
      trend_source: $trend_source_value,
      trend_summary_present: ($trend_summary_present == 1),
      recommendation_support_rate_pct: $support_rate_pct,
      selection_policy_evidence: {
        present: ($selection_policy_evidence_present == 1),
        valid: ($selection_policy_evidence_valid == 1),
        campaign_summary_present: ($campaign_selection_policy_present == 1),
        campaign_summary_valid: ($campaign_selection_policy_valid == 1),
        selected_summaries_total: $selection_policy_selected_summaries_total,
        selected_summaries_found: $selection_policy_selected_summaries_found,
        selected_summaries_with_policy_present: $selection_policy_selected_summaries_present_count,
        selected_summaries_with_policy_valid: $selection_policy_selected_summaries_valid_count,
        selected_summaries_missing_or_unreadable: $selection_policy_selected_summaries_missing_or_unreadable_count,
        selected_summaries_invalid_or_missing_policy: $selection_policy_selected_summaries_invalid_or_missing_policy_count
      }
    },
    errors: $errors,
    artifacts: {
      summary_json: $summary_json
    }
  }' >"$summary_json"

echo "[profile-compare-campaign-check] decision=$decision status=$status rc=$rc recommended_profile=${recommended_profile:-unset} support_rate_pct=${support_rate_pct}"
if ((${#errors[@]} > 0)); then
  echo "[profile-compare-campaign-check] failed with ${#errors[@]} issue(s):"
  idx=1
  for err in "${errors[@]}"; do
    echo "  $idx. $err"
    idx=$((idx + 1))
  done
fi

if [[ "$show_json" == "1" ]]; then
  echo "[profile-compare-campaign-check] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
