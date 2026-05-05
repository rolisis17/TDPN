#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_default_gate_stability_check.sh \
    [--stability-summary-json PATH] \
    [--reports-dir DIR] \
    [--require-status-pass [0|1]] \
    [--require-stability-ok [0|1]] \
    [--require-selection-policy-present-all [0|1]] \
    [--require-consistent-selection-policy [0|1]] \
    [--require-decision-consensus [0|1]] \
    [--require-min-runs-requested N] \
    [--require-min-runs-completed N] \
    [--require-max-runs-fail N] \
    [--require-modal-decision GO|NO-GO] \
    [--require-modal-decision-support-rate-pct N] \
    [--require-recommended-profile PROFILE] \
    [--allow-recommended-profiles CSV] \
    [--require-modal-support-rate-pct N] \
    [--fail-on-no-go [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Verify profile-default-gate stability summary artifacts and emit a
  fail-closed GO/NO-GO decision for default-profile stability readiness.
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

require_value_or_die() {
  local flag="$1"
  local argc="$2"
  if (( argc < 2 )); then
    echo "$flag requires a value"
    exit 2
  fi
}

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
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

normalize_decision() {
  local decision
  decision="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
  case "$decision" in
    GO) printf '%s\n' "GO" ;;
    NO-GO|NOGO|NO_GO) printf '%s\n' "NO-GO" ;;
    *) printf '%s\n' "$decision" ;;
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

stability_summary_json=""
reports_dir="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REPORTS_DIR:-${REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}}"

require_status_pass="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_STATUS_PASS:-${REQUIRE_STATUS_PASS:-1}}"
require_stability_ok="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_STABILITY_OK:-${REQUIRE_STABILITY_OK:-1}}"
require_selection_policy_present_all="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_SELECTION_POLICY_PRESENT_ALL:-${REQUIRE_SELECTION_POLICY_PRESENT_ALL:-1}}"
require_consistent_selection_policy="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_CONSISTENT_SELECTION_POLICY:-${REQUIRE_CONSISTENT_SELECTION_POLICY:-1}}"
require_decision_consensus="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_DECISION_CONSENSUS:-${REQUIRE_DECISION_CONSENSUS:-0}}"
require_min_runs_requested="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_MIN_RUNS_REQUESTED:-${REQUIRE_MIN_RUNS_REQUESTED:-3}}"
require_min_runs_completed="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_MIN_RUNS_COMPLETED:-${REQUIRE_MIN_RUNS_COMPLETED:-3}}"
require_max_runs_fail="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_MAX_RUNS_FAIL:-${REQUIRE_MAX_RUNS_FAIL:-0}}"
require_modal_decision="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_MODAL_DECISION:-${REQUIRE_MODAL_DECISION:-GO}}"
require_modal_decision_support_rate_pct="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_MODAL_DECISION_SUPPORT_RATE_PCT:-${REQUIRE_MODAL_DECISION_SUPPORT_RATE_PCT:-0}}"
require_recommended_profile="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_RECOMMENDED_PROFILE:-${REQUIRE_RECOMMENDED_PROFILE:-}}"
allow_recommended_profiles="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_ALLOW_RECOMMENDED_PROFILES:-${ALLOW_RECOMMENDED_PROFILES:-balanced,speed,private}}"
require_modal_support_rate_pct="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_REQUIRE_MODAL_SUPPORT_RATE_PCT:-${REQUIRE_MODAL_SUPPORT_RATE_PCT:-60}}"
fail_on_no_go="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_FAIL_ON_NO_GO:-${FAIL_ON_NO_GO:-1}}"

show_json="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_SHOW_JSON:-0}"
print_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_PRINT_SUMMARY_JSON:-0}"
summary_json="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_SUMMARY_JSON:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stability-summary-json)
      require_value_or_die "$1" "$#"
      stability_summary_json="${2:-}"
      shift 2
      ;;
    --stability-summary-json=*)
      stability_summary_json="${1#*=}"
      shift
      ;;
    --reports-dir)
      require_value_or_die "$1" "$#"
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
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
    --require-status-pass=*)
      require_status_pass="${1#*=}"
      shift
      ;;
    --require-stability-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_stability_ok="${2:-}"
        shift 2
      else
        require_stability_ok="1"
        shift
      fi
      ;;
    --require-stability-ok=*)
      require_stability_ok="${1#*=}"
      shift
      ;;
    --require-selection-policy-present-all)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_selection_policy_present_all="${2:-}"
        shift 2
      else
        require_selection_policy_present_all="1"
        shift
      fi
      ;;
    --require-selection-policy-present-all=*)
      require_selection_policy_present_all="${1#*=}"
      shift
      ;;
    --require-consistent-selection-policy)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_consistent_selection_policy="${2:-}"
        shift 2
      else
        require_consistent_selection_policy="1"
        shift
      fi
      ;;
    --require-consistent-selection-policy=*)
      require_consistent_selection_policy="${1#*=}"
      shift
      ;;
    --require-decision-consensus)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_decision_consensus="${2:-}"
        shift 2
      else
        require_decision_consensus="1"
        shift
      fi
      ;;
    --require-decision-consensus=*)
      require_decision_consensus="${1#*=}"
      shift
      ;;
    --require-min-runs-requested)
      require_value_or_die "$1" "$#"
      require_min_runs_requested="${2:-}"
      shift 2
      ;;
    --require-min-runs-requested=*)
      require_min_runs_requested="${1#*=}"
      shift
      ;;
    --require-min-runs-completed)
      require_value_or_die "$1" "$#"
      require_min_runs_completed="${2:-}"
      shift 2
      ;;
    --require-min-runs-completed=*)
      require_min_runs_completed="${1#*=}"
      shift
      ;;
    --require-max-runs-fail)
      require_value_or_die "$1" "$#"
      require_max_runs_fail="${2:-}"
      shift 2
      ;;
    --require-max-runs-fail=*)
      require_max_runs_fail="${1#*=}"
      shift
      ;;
    --require-modal-decision)
      require_value_or_die "$1" "$#"
      require_modal_decision="${2:-}"
      shift 2
      ;;
    --require-modal-decision=*)
      require_modal_decision="${1#*=}"
      shift
      ;;
    --require-modal-decision-support-rate-pct)
      require_value_or_die "$1" "$#"
      require_modal_decision_support_rate_pct="${2:-}"
      shift 2
      ;;
    --require-modal-decision-support-rate-pct=*)
      require_modal_decision_support_rate_pct="${1#*=}"
      shift
      ;;
    --require-recommended-profile)
      require_value_or_die "$1" "$#"
      require_recommended_profile="${2:-}"
      shift 2
      ;;
    --require-recommended-profile=*)
      require_recommended_profile="${1#*=}"
      shift
      ;;
    --allow-recommended-profiles)
      require_value_or_die "$1" "$#"
      allow_recommended_profiles="${2:-}"
      shift 2
      ;;
    --allow-recommended-profiles=*)
      allow_recommended_profiles="${1#*=}"
      shift
      ;;
    --require-modal-support-rate-pct)
      require_value_or_die "$1" "$#"
      require_modal_support_rate_pct="${2:-}"
      shift 2
      ;;
    --require-modal-support-rate-pct=*)
      require_modal_support_rate_pct="${1#*=}"
      shift
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
    --fail-on-no-go=*)
      fail_on_no_go="${1#*=}"
      shift
      ;;
    --summary-json)
      require_value_or_die "$1" "$#"
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
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
    --show-json=*)
      show_json="${1#*=}"
      shift
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
    --print-summary-json=*)
      print_summary_json="${1#*=}"
      shift
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
bool_arg_or_die "--require-stability-ok" "$require_stability_ok"
bool_arg_or_die "--require-selection-policy-present-all" "$require_selection_policy_present_all"
bool_arg_or_die "--require-consistent-selection-policy" "$require_consistent_selection_policy"
bool_arg_or_die "--require-decision-consensus" "$require_decision_consensus"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

for int_arg in "$require_min_runs_requested" "$require_min_runs_completed" "$require_max_runs_fail"; do
  if ! [[ "$int_arg" =~ ^[0-9]+$ ]]; then
    echo "run count thresholds must be non-negative integers"
    exit 2
  fi
done

if ! is_non_negative_decimal "$require_modal_support_rate_pct"; then
  echo "--require-modal-support-rate-pct must be a non-negative number"
  exit 2
fi
if ! is_non_negative_decimal "$require_modal_decision_support_rate_pct"; then
  echo "--require-modal-decision-support-rate-pct must be a non-negative number"
  exit 2
fi

reports_dir="$(abs_path "$reports_dir")"
if [[ -n "$stability_summary_json" ]]; then
  stability_summary_json="$(abs_path "$stability_summary_json")"
else
  stability_summary_json="$reports_dir/profile_default_gate_stability_summary.json"
fi

if [[ -n "$require_recommended_profile" ]]; then
  require_recommended_profile="$(normalize_profile "$require_recommended_profile")"
fi
if [[ -n "$require_modal_decision" ]]; then
  require_modal_decision="$(normalize_decision "$require_modal_decision")"
  if [[ "$require_modal_decision" != "GO" && "$require_modal_decision" != "NO-GO" ]]; then
    echo "--require-modal-decision must be GO or NO-GO"
    exit 2
  fi
fi

log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/profile_default_gate_stability_check_${run_stamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

declare -a errors=()

summary_exists="0"
schema_valid="0"
if [[ -f "$stability_summary_json" ]]; then
  summary_exists="1"
  if jq -e '.version == 1 and (.schema | type == "object") and (.schema.id == "profile_default_gate_stability_summary")' "$stability_summary_json" >/dev/null 2>&1; then
    schema_valid="1"
  else
    errors+=("stability summary schema.id must be profile_default_gate_stability_summary (path=$stability_summary_json)")
  fi
else
  errors+=("stability summary JSON not found ($stability_summary_json)")
fi

observed_status=""
observed_rc_json="null"
observed_runs_requested_json="null"
observed_runs_total_json="null"
observed_runs_completed_json="null"
observed_runs_pass_json="null"
observed_runs_fail_json="null"
observed_command_failures_json="null"
observed_summary_missing_count_json="null"
observed_summary_unreadable_count_json="null"
observed_evidence_state=""
observed_stability_ok=""
observed_selection_policy_present_all=""
observed_consistent_selection_policy=""
observed_recommended_profile_counts_json='{}'
observed_recommended_profile_total_json="0"
observed_modal_recommended_profile=""
observed_modal_recommended_profile_count_json="0"
observed_modal_support_rate_pct="0"
observed_decision_counts_json='{}'
observed_decision_total_json="0"
observed_modal_decision=""
observed_modal_decision_count_json="0"
observed_modal_decision_support_rate_pct="0"
observed_decision_consensus=""

if [[ "$schema_valid" == "1" ]]; then
  observed_status="$(jq -r '.status // ""' "$stability_summary_json" 2>/dev/null || true)"

  observed_rc_candidate="$(jq -r '
    if (.rc | type) == "number" then .rc
    elif (.rc | type) == "string" and (.rc | test("^-?[0-9]+$")) then (.rc | tonumber)
    else ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"
  if [[ -n "$observed_rc_candidate" ]]; then
    observed_rc_json="$observed_rc_candidate"
  fi

  observed_runs_requested_candidate="$(jq -r '
    if (.runs_requested | type) == "number" then .runs_requested
    elif (.runs_requested | type) == "string" and (.runs_requested | test("^[0-9]+$")) then (.runs_requested | tonumber)
    elif (.inputs.runs_requested | type) == "number" then .inputs.runs_requested
    elif (.inputs.runs_requested | type) == "string" and (.inputs.runs_requested | test("^[0-9]+$")) then (.inputs.runs_requested | tonumber)
    else ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"
  if [[ -n "$observed_runs_requested_candidate" ]]; then
    observed_runs_requested_json="$observed_runs_requested_candidate"
  fi

  observed_runs_completed_candidate="$(jq -r '
    if (.runs_completed | type) == "number" then .runs_completed
    elif (.runs_completed | type) == "string" and (.runs_completed | test("^[0-9]+$")) then (.runs_completed | tonumber)
    else ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"
  if [[ -n "$observed_runs_completed_candidate" ]]; then
    observed_runs_completed_json="$observed_runs_completed_candidate"
  fi

  observed_runs_total_candidate="$(jq -r '
    if (.runs_total | type) == "number" then .runs_total
    elif (.runs_total | type) == "string" and (.runs_total | test("^[0-9]+$")) then (.runs_total | tonumber)
    elif (.runs | type) == "array" then (.runs | length)
    else ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"
  if [[ -n "$observed_runs_total_candidate" ]]; then
    observed_runs_total_json="$observed_runs_total_candidate"
  fi

  observed_runs_pass_candidate="$(jq -r '
    if (.runs_pass | type) == "number" then .runs_pass
    elif (.runs_pass | type) == "string" and (.runs_pass | test("^[0-9]+$")) then (.runs_pass | tonumber)
    elif (.runs | type) == "array" then
      ([.runs[] | select(.command_rc == 0 and .summary_exists == true and .completed == true)] | length)
    else ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"
  if [[ -n "$observed_runs_pass_candidate" ]]; then
    observed_runs_pass_json="$observed_runs_pass_candidate"
  fi

  observed_runs_fail_candidate="$(jq -r '
    if (.runs_fail | type) == "number" then .runs_fail
    elif (.runs_fail | type) == "string" and (.runs_fail | test("^[0-9]+$")) then (.runs_fail | tonumber)
    else ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"
  if [[ -n "$observed_runs_fail_candidate" ]]; then
    observed_runs_fail_json="$observed_runs_fail_candidate"
  fi

  observed_command_failures_candidate="$(jq -r '
    if (.diagnostics.command_failures | type) == "number" then .diagnostics.command_failures
    elif (.diagnostics.command_failures | type) == "string" and (.diagnostics.command_failures | test("^[0-9]+$")) then (.diagnostics.command_failures | tonumber)
    elif (.runs | type) == "array" then ([.runs[] | select(.command_rc != 0)] | length)
    else ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"
  if [[ -n "$observed_command_failures_candidate" ]]; then
    observed_command_failures_json="$observed_command_failures_candidate"
  fi

  observed_summary_missing_count_candidate="$(jq -r '
    if (.diagnostics.summary_missing_count | type) == "number" then .diagnostics.summary_missing_count
    elif (.diagnostics.summary_missing_count | type) == "string" and (.diagnostics.summary_missing_count | test("^[0-9]+$")) then (.diagnostics.summary_missing_count | tonumber)
    elif (.runs | type) == "array" then ([.runs[] | select(.summary_exists != true)] | length)
    else ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"
  if [[ -n "$observed_summary_missing_count_candidate" ]]; then
    observed_summary_missing_count_json="$observed_summary_missing_count_candidate"
  fi

  observed_summary_unreadable_count_candidate="$(jq -r '
    if (.diagnostics.summary_unreadable_count | type) == "number" then .diagnostics.summary_unreadable_count
    elif (.diagnostics.summary_unreadable_count | type) == "string" and (.diagnostics.summary_unreadable_count | test("^[0-9]+$")) then (.diagnostics.summary_unreadable_count | tonumber)
    elif (.runs | type) == "array" then ([.runs[] | select(.summary_exists == true and .completed != true)] | length)
    else ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"
  if [[ -n "$observed_summary_unreadable_count_candidate" ]]; then
    observed_summary_unreadable_count_json="$observed_summary_unreadable_count_candidate"
  fi

  observed_stability_ok="$(jq -r '
    if (.stability_ok | type) == "boolean" then
      if .stability_ok then "true" else "false" end
    else
      ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"

  observed_selection_policy_present_all="$(jq -r '
    if (.selection_policy_present_all | type) == "boolean" then
      if .selection_policy_present_all then "true" else "false" end
    else
      ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"

  observed_consistent_selection_policy="$(jq -r '
    if (.consistent_selection_policy | type) == "boolean" then
      if .consistent_selection_policy then "true" else "false" end
    else
      ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"

  observed_recommended_profile_counts_json="$(jq -c '
    def normalize_profile:
      ascii_downcase
      | gsub("\\s+"; "")
      | if . == "speed" or . == "balanced" or . == "private" or . == "speed-1hop" then .
        elif . == "2hop" or . == "2-hop" or . == "hop2" or . == "hop-2" or . == "twohop" then "balanced"
        elif . == "3hop" or . == "3-hop" or . == "hop3" or . == "hop-3" or . == "threehop" then "private"
        elif . == "fast" then "speed"
        elif . == "privacy" then "private"
        elif . == "speed1hop" or . == "onehop" or . == "1hop" or . == "1-hop" or . == "hop1" or . == "hop-1" or . == "fast-1hop" or . == "fast1hop" then "speed-1hop"
        else .
        end;
    if (.recommended_profile_counts | type) != "object" then
      {}
    else
      reduce (.recommended_profile_counts | to_entries[]) as $entry
        ({};
          ($entry.key | tostring | normalize_profile) as $k
          | ($entry.value
             | if type == "number" then .
               elif type == "string" and test("^-?[0-9]+([.][0-9]+)?$") then tonumber
               else null
               end) as $v
          | if ($k | length) == 0 or $v == null or $v < 0 then
              .
            else
              .[$k] = ((.[$k] // 0) + $v)
            end
        )
    end
  ' "$stability_summary_json" 2>/dev/null || printf '{}')"

  observed_recommended_profile_total_json="$(jq -r '[.[]] | add // 0' <<<"$observed_recommended_profile_counts_json")"
  observed_modal_recommended_profile="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].key // ""' <<<"$observed_recommended_profile_counts_json")"
  observed_modal_recommended_profile_count_json="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].value // 0' <<<"$observed_recommended_profile_counts_json")"
  observed_modal_support_rate_pct="$(jq -n \
    --argjson total "$observed_recommended_profile_total_json" \
    --argjson modal "$observed_modal_recommended_profile_count_json" \
    'if $total > 0 then (($modal * 100) / $total) else 0 end')"

  observed_decision_counts_json="$(jq -c '
    def normalize_decision:
      ascii_upcase
      | gsub("\\s+"; "")
      | if . == "GO" then "GO"
        elif . == "NO-GO" or . == "NOGO" or . == "NO_GO" then "NO-GO"
        else .
        end;
    def parse_count:
      if type == "number" then .
      elif type == "string" and test("^-?[0-9]+([.][0-9]+)?$") then tonumber
      else null
      end;
    if (.decision_counts | type) == "object" then
      reduce (.decision_counts | to_entries[]) as $entry
        ({}; ($entry.key | tostring | normalize_decision) as $k
          | ($entry.value | parse_count) as $v
          | if ($k | length) == 0 or $v == null or $v < 0 then .
            else .[$k] = ((.[$k] // 0) + $v)
            end
        )
    elif (.runs | type) == "array" then
      [ .runs[]
        | select(.completed == true)
        | .decision.decision // empty
        | strings
        | gsub("^\\s+|\\s+$"; "")
        | select(length > 0)
        | normalize_decision
      ]
      | group_by(.)
      | map({ (.[0]): length })
      | add // {}
    else
      {}
    end
  ' "$stability_summary_json" 2>/dev/null || printf '{}')"

  observed_decision_total_json="$(jq -r '[.[]] | add // 0' <<<"$observed_decision_counts_json")"
  observed_modal_decision="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].key // ""' <<<"$observed_decision_counts_json")"
  observed_modal_decision_count_json="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].value // 0' <<<"$observed_decision_counts_json")"
  observed_modal_decision_support_rate_pct="$(jq -n \
    --argjson total "$observed_decision_total_json" \
    --argjson modal "$observed_modal_decision_count_json" \
    'if $total > 0 then (($modal * 100) / $total) else 0 end')"

  observed_decision_consensus="$(jq -r '
    def normalize_decision:
      ascii_upcase
      | gsub("\\s+"; "")
      | if . == "GO" then "GO"
        elif . == "NO-GO" or . == "NOGO" or . == "NO_GO" then "NO-GO"
        else .
        end;
    def runs_completed_count:
      if (.runs_completed | type) == "number" then .runs_completed
      elif (.runs_completed | type) == "string" and (.runs_completed | test("^[0-9]+$")) then (.runs_completed | tonumber)
      elif (.runs | type) == "array" then ([.runs[] | select(.completed == true)] | length)
      else null
      end;
    def decision_counts:
      if (.decision_counts | type) == "object" then
        reduce (.decision_counts | to_entries[]) as $entry
          ({}; ($entry.key | tostring | normalize_decision) as $k
            | ($entry.value
               | if type == "number" then .
                 elif type == "string" and test("^-?[0-9]+([.][0-9]+)?$") then tonumber
                 else null
                 end) as $v
            | if ($k | length) == 0 or $v == null or $v < 0 then .
              else .[$k] = ((.[$k] // 0) + $v)
              end
          )
      elif (.runs | type) == "array" then
        [ .runs[]
          | select(.completed == true)
          | .decision.decision // empty
          | strings
          | gsub("^\\s+|\\s+$"; "")
          | select(length > 0)
          | normalize_decision
        ]
        | group_by(.)
        | map({ (.[0]): length })
        | add // {}
      else
        {}
      end;
    if (.decision_consensus | type) == "boolean" then
      if .decision_consensus then "true" else "false" end
    else
      (runs_completed_count) as $completed
      | (decision_counts) as $counts
      | ([$counts[]] | add // 0) as $total
      | if $completed == null or $completed == 0 then ""
        elif $total != $completed then "false"
        elif (($counts | keys | length) == 1) then "true"
        else "false"
        end
    end
  ' "$stability_summary_json" 2>/dev/null || printf '%s' "")"

  observed_evidence_state="$(jq -r '
    if (.diagnostics.evidence_state | type) == "string" and ((.diagnostics.evidence_state | length) > 0) then
      .diagnostics.evidence_state
    else
      def command_failures_count:
        if (.diagnostics.command_failures | type) == "number" then .diagnostics.command_failures
        elif (.diagnostics.command_failures | type) == "string" and (.diagnostics.command_failures | test("^[0-9]+$")) then (.diagnostics.command_failures | tonumber)
        elif (.runs | type) == "array" then ([.runs[] | select(.command_rc != 0)] | length)
        else 0
        end;
      def summary_missing_count:
        if (.diagnostics.summary_missing_count | type) == "number" then .diagnostics.summary_missing_count
        elif (.diagnostics.summary_missing_count | type) == "string" and (.diagnostics.summary_missing_count | test("^[0-9]+$")) then (.diagnostics.summary_missing_count | tonumber)
        elif (.runs | type) == "array" then ([.runs[] | select(.summary_exists != true)] | length)
        else 0
        end;
      def summary_unreadable_count:
        if (.diagnostics.summary_unreadable_count | type) == "number" then .diagnostics.summary_unreadable_count
        elif (.diagnostics.summary_unreadable_count | type) == "string" and (.diagnostics.summary_unreadable_count | test("^[0-9]+$")) then (.diagnostics.summary_unreadable_count | tonumber)
        elif (.runs | type) == "array" then ([.runs[] | select(.summary_exists == true and .completed != true)] | length)
        else 0
        end;
      def completed_count:
        if (.runs_completed | type) == "number" then .runs_completed
        elif (.runs_completed | type) == "string" and (.runs_completed | test("^[0-9]+$")) then (.runs_completed | tonumber)
        elif (.runs | type) == "array" then ([.runs[] | select(.completed == true)] | length)
        else 0
        end;
      (completed_count) as $completed
      | (command_failures_count) as $command_failures
      | (summary_missing_count) as $summary_missing
      | (summary_unreadable_count) as $summary_unreadable
      | if $completed == 0 then "missing"
        elif ($command_failures > 0 or $summary_missing > 0 or $summary_unreadable > 0) then "partial"
        else "complete"
        end
    end
  ' "$stability_summary_json" 2>/dev/null || printf '%s' "")"
fi

if [[ "$schema_valid" == "1" ]]; then
  if [[ "$observed_runs_total_json" == "null" ]]; then
    if [[ "$observed_runs_requested_json" != "null" ]]; then
      observed_runs_total_json="$observed_runs_requested_json"
    elif [[ "$observed_runs_completed_json" != "null" ]]; then
      observed_runs_total_json="$observed_runs_completed_json"
    else
      observed_runs_total_json="0"
    fi
  fi

  if [[ "$observed_runs_pass_json" == "null" ]]; then
    if [[ "$observed_runs_completed_json" != "null" && "$observed_runs_fail_json" != "null" ]]; then
      observed_runs_pass_json=$(( observed_runs_completed_json - observed_runs_fail_json ))
      if (( observed_runs_pass_json < 0 )); then
        observed_runs_pass_json="0"
      fi
    elif [[ "$observed_runs_completed_json" != "null" ]]; then
      observed_runs_pass_json="$observed_runs_completed_json"
    else
      observed_runs_pass_json="0"
    fi
  fi

  if [[ "$observed_command_failures_json" == "null" ]]; then
    if [[ "$observed_runs_fail_json" != "null" ]]; then
      observed_command_failures_json="$observed_runs_fail_json"
    else
      observed_command_failures_json="0"
    fi
  fi

  if [[ "$observed_summary_missing_count_json" == "null" ]]; then
    observed_summary_missing_count_json="0"
  fi
  if [[ "$observed_summary_unreadable_count_json" == "null" ]]; then
    observed_summary_unreadable_count_json="0"
  fi

  if [[ -z "$observed_evidence_state" ]]; then
    if [[ "$observed_runs_completed_json" == "null" || "$observed_runs_completed_json" -eq 0 ]]; then
      observed_evidence_state="missing"
    elif [[ "$observed_command_failures_json" -gt 0 || "$observed_summary_missing_count_json" -gt 0 || "$observed_summary_unreadable_count_json" -gt 0 ]]; then
      observed_evidence_state="partial"
    else
      observed_evidence_state="complete"
    fi
  fi
fi

if [[ "$schema_valid" == "1" ]]; then
  if [[ "$require_status_pass" == "1" ]] && [[ "$observed_status" != "pass" ]]; then
    errors+=("stability status must be pass (actual=${observed_status:-unset})")
  fi

  if [[ "$require_stability_ok" == "1" && "$observed_stability_ok" != "true" ]]; then
    errors+=("stability_ok must be true (actual=${observed_stability_ok:-unset})")
  fi

  if [[ "$require_selection_policy_present_all" == "1" && "$observed_selection_policy_present_all" != "true" ]]; then
    errors+=("selection_policy_present_all must be true (actual=${observed_selection_policy_present_all:-unset})")
  fi

  if [[ "$require_consistent_selection_policy" == "1" && "$observed_consistent_selection_policy" != "true" ]]; then
    errors+=("consistent_selection_policy must be true (actual=${observed_consistent_selection_policy:-unset})")
  fi

  if [[ "$require_decision_consensus" == "1" && "$observed_decision_consensus" != "true" ]]; then
    errors+=("decision_consensus must be true (actual=${observed_decision_consensus:-unset})")
  fi

  if [[ "$observed_runs_requested_json" == "null" ]]; then
    errors+=("runs_requested is missing or invalid")
  elif (( observed_runs_requested_json < require_min_runs_requested )); then
    errors+=("runs_requested below required minimum (actual=$observed_runs_requested_json required=$require_min_runs_requested)")
  fi

  if [[ "$observed_runs_completed_json" == "null" ]]; then
    errors+=("runs_completed is missing or invalid")
  elif (( observed_runs_completed_json < require_min_runs_completed )); then
    errors+=("runs_completed below required minimum (actual=$observed_runs_completed_json required=$require_min_runs_completed)")
  fi

  if [[ "$observed_runs_fail_json" == "null" ]]; then
    errors+=("runs_fail is missing or invalid")
  elif (( observed_runs_fail_json > require_max_runs_fail )); then
    errors+=("runs_fail exceeds allowed maximum (actual=$observed_runs_fail_json max=$require_max_runs_fail)")
  fi

  if [[ -z "$observed_modal_recommended_profile" ]]; then
    errors+=("modal recommended profile is empty")
  fi

  if [[ -n "$require_recommended_profile" && "$observed_modal_recommended_profile" != "$require_recommended_profile" ]]; then
    errors+=("recommended profile mismatch (actual=${observed_modal_recommended_profile:-unset} required=$require_recommended_profile)")
  fi

  if [[ -n "$allow_recommended_profiles" && -n "$observed_modal_recommended_profile" ]]; then
    if ! csv_contains "$allow_recommended_profiles" "$observed_modal_recommended_profile"; then
      errors+=("recommended profile is not in allowed set (actual=$observed_modal_recommended_profile allowed=$allow_recommended_profiles)")
    fi
  fi

  if awk -v observed="$observed_modal_support_rate_pct" -v min_required="$require_modal_support_rate_pct" 'BEGIN { exit !(observed < min_required) }'; then
    errors+=("modal support rate below threshold (actual=${observed_modal_support_rate_pct}% required=${require_modal_support_rate_pct}%)")
  fi

  if [[ -n "$require_modal_decision" ]]; then
    if [[ -z "$observed_modal_decision" ]]; then
      errors+=("modal decision is empty")
    elif [[ "$observed_modal_decision" != "$require_modal_decision" ]]; then
      errors+=("modal decision mismatch (actual=${observed_modal_decision:-unset} required=$require_modal_decision)")
    fi
  fi

  if awk -v observed="$observed_modal_decision_support_rate_pct" -v min_required="$require_modal_decision_support_rate_pct" 'BEGIN { exit !(observed < min_required) }'; then
    errors+=("modal decision support rate below threshold (actual=${observed_modal_decision_support_rate_pct}% required=${require_modal_decision_support_rate_pct}%)")
  fi
fi

decision="GO"
status="ok"
notes="profile-default gate stability summary passes configured policy"
if ((${#errors[@]} > 0)); then
  decision="NO-GO"
  status="fail"
  notes="profile-default gate stability summary violates one or more policy checks"
fi

rc=0
if [[ "$decision" == "NO-GO" && "$fail_on_no_go" == "1" ]]; then
  rc=1
fi

errors_json='[]'
if ((${#errors[@]} > 0)); then
  errors_json="$(printf '%s\n' "${errors[@]}" | jq -R . | jq -s '.')"
fi

missing_or_invalid_evidence="false"
if [[ "$summary_exists" != "1" || "$schema_valid" != "1" ]]; then
  missing_or_invalid_evidence="true"
elif [[ "$observed_runs_completed_json" == "null" || "$observed_runs_completed_json" -eq 0 ]]; then
  missing_or_invalid_evidence="true"
fi

partial_evidence="false"
if [[ "$observed_evidence_state" == "partial" ]]; then
  partial_evidence="true"
elif [[ "$observed_runs_fail_json" != "null" && "$observed_runs_fail_json" -gt 0 ]]; then
  partial_evidence="true"
elif [[ "$observed_summary_missing_count_json" != "null" && "$observed_summary_missing_count_json" -gt 0 ]]; then
  partial_evidence="true"
elif [[ "$observed_summary_unreadable_count_json" != "null" && "$observed_summary_unreadable_count_json" -gt 0 ]]; then
  partial_evidence="true"
fi

next_operator_action="Stability evidence satisfies configured policy; promotion can proceed."
if [[ "$missing_or_invalid_evidence" == "true" ]]; then
  next_operator_action="Stability evidence is missing/invalid; regenerate run artifacts before evaluating promotion."
elif [[ "$partial_evidence" == "true" ]]; then
  next_operator_action="Stability evidence is partial; inspect failed runs and rerun collection/check before promotion."
elif [[ "$decision" == "NO-GO" ]]; then
  next_operator_action="Policy produced NO-GO; inspect failing checks and rerun with updated evidence or thresholds."
fi

rerun_run_command_template="./scripts/easy_node.sh profile-default-gate-stability-run --host-a HOST_A --host-b HOST_B --campaign-subject INVITE_KEY --reports-dir ${reports_dir} --summary-json ${stability_summary_json} --print-summary-json 1"
rerun_check_command_template="./scripts/easy_node.sh profile-default-gate-stability-check --stability-summary-json ${stability_summary_json} --require-status-pass ${require_status_pass} --require-stability-ok ${require_stability_ok} --require-selection-policy-present-all ${require_selection_policy_present_all} --require-consistent-selection-policy ${require_consistent_selection_policy} --require-decision-consensus ${require_decision_consensus} --require-min-runs-requested ${require_min_runs_requested} --require-min-runs-completed ${require_min_runs_completed} --require-max-runs-fail ${require_max_runs_fail} --require-modal-decision ${require_modal_decision} --require-modal-decision-support-rate-pct ${require_modal_decision_support_rate_pct} --require-modal-support-rate-pct ${require_modal_support_rate_pct} --fail-on-no-go ${fail_on_no_go} --summary-json ${summary_json} --print-summary-json 1"
rerun_cycle_command_template="./scripts/easy_node.sh profile-default-gate-stability-cycle --host-a HOST_A --host-b HOST_B --campaign-subject INVITE_KEY --reports-dir ${reports_dir} --print-summary-json 1"
inspect_summary_command_template="jq '.' ${stability_summary_json}"

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg decision "$decision" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg stability_summary_json "$stability_summary_json" \
  --argjson stability_summary_exists "$summary_exists" \
  --argjson stability_summary_schema_valid "$schema_valid" \
  --arg observed_status "$observed_status" \
  --argjson observed_rc "$observed_rc_json" \
  --argjson observed_runs_requested "$observed_runs_requested_json" \
  --argjson observed_runs_total "$observed_runs_total_json" \
  --argjson observed_runs_completed "$observed_runs_completed_json" \
  --argjson observed_runs_pass "$observed_runs_pass_json" \
  --argjson observed_runs_fail "$observed_runs_fail_json" \
  --argjson observed_command_failures "$observed_command_failures_json" \
  --argjson observed_summary_missing_count "$observed_summary_missing_count_json" \
  --argjson observed_summary_unreadable_count "$observed_summary_unreadable_count_json" \
  --arg observed_evidence_state "$observed_evidence_state" \
  --arg observed_stability_ok "$observed_stability_ok" \
  --arg observed_selection_policy_present_all "$observed_selection_policy_present_all" \
  --arg observed_consistent_selection_policy "$observed_consistent_selection_policy" \
  --argjson observed_recommended_profile_counts "$observed_recommended_profile_counts_json" \
  --arg observed_modal_recommended_profile "$observed_modal_recommended_profile" \
  --argjson observed_modal_recommended_profile_count "$observed_modal_recommended_profile_count_json" \
  --argjson observed_recommended_profile_total "$observed_recommended_profile_total_json" \
  --argjson observed_modal_support_rate_pct "$observed_modal_support_rate_pct" \
  --argjson observed_decision_counts "$observed_decision_counts_json" \
  --argjson observed_decision_total "$observed_decision_total_json" \
  --arg observed_modal_decision "$observed_modal_decision" \
  --argjson observed_modal_decision_count "$observed_modal_decision_count_json" \
  --argjson observed_modal_decision_support_rate_pct "$observed_modal_decision_support_rate_pct" \
  --arg observed_decision_consensus "$observed_decision_consensus" \
  --argjson require_status_pass "$require_status_pass" \
  --argjson require_stability_ok "$require_stability_ok" \
  --argjson require_selection_policy_present_all "$require_selection_policy_present_all" \
  --argjson require_consistent_selection_policy "$require_consistent_selection_policy" \
  --argjson require_decision_consensus "$require_decision_consensus" \
  --argjson require_min_runs_requested "$require_min_runs_requested" \
  --argjson require_min_runs_completed "$require_min_runs_completed" \
  --argjson require_max_runs_fail "$require_max_runs_fail" \
  --arg require_modal_decision "$require_modal_decision" \
  --argjson require_modal_decision_support_rate_pct "$require_modal_decision_support_rate_pct" \
  --arg require_recommended_profile "$require_recommended_profile" \
  --arg allow_recommended_profiles "$allow_recommended_profiles" \
  --argjson require_modal_support_rate_pct "$require_modal_support_rate_pct" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --argjson rc "$rc" \
  --argjson errors "$errors_json" \
  --arg missing_or_invalid_evidence "$missing_or_invalid_evidence" \
  --arg partial_evidence "$partial_evidence" \
  --arg next_operator_action "$next_operator_action" \
  --arg rerun_run_command_template "$rerun_run_command_template" \
  --arg rerun_check_command_template "$rerun_check_command_template" \
  --arg rerun_cycle_command_template "$rerun_cycle_command_template" \
  --arg inspect_summary_command_template "$inspect_summary_command_template" \
  --arg summary_json "$summary_json" \
  '{
    version: 1,
    schema: {
      id: "profile_default_gate_stability_check_summary"
    },
    generated_at_utc: $generated_at_utc,
    decision: $decision,
    status: $status,
    rc: $rc,
    notes: $notes,
    inputs: {
      stability_summary_json: $stability_summary_json,
      policy: {
        require_status_pass: ($require_status_pass == 1),
        require_stability_ok: ($require_stability_ok == 1),
        require_selection_policy_present_all: ($require_selection_policy_present_all == 1),
        require_consistent_selection_policy: ($require_consistent_selection_policy == 1),
        require_decision_consensus: ($require_decision_consensus == 1),
        require_min_runs_requested: $require_min_runs_requested,
        require_min_runs_completed: $require_min_runs_completed,
        require_max_runs_fail: $require_max_runs_fail,
        require_modal_decision: (
          if $require_modal_decision == "" then null
          else $require_modal_decision
          end
        ),
        require_modal_decision_support_rate_pct: $require_modal_decision_support_rate_pct,
        require_recommended_profile: $require_recommended_profile,
        allow_recommended_profiles: $allow_recommended_profiles,
        require_modal_support_rate_pct: $require_modal_support_rate_pct,
        fail_on_no_go: ($fail_on_no_go == 1)
      }
    },
    observed: {
      stability_summary_exists: ($stability_summary_exists == 1),
      stability_summary_schema_valid: ($stability_summary_schema_valid == 1),
      status: (if $observed_status == "" then null else $observed_status end),
      rc: $observed_rc,
      runs_requested: $observed_runs_requested,
      runs_total: $observed_runs_total,
      runs_completed: $observed_runs_completed,
      runs_pass: $observed_runs_pass,
      runs_fail: $observed_runs_fail,
      command_failures: $observed_command_failures,
      summary_missing_count: $observed_summary_missing_count,
      summary_unreadable_count: $observed_summary_unreadable_count,
      evidence_state: (
        if $observed_evidence_state == "" then null
        else $observed_evidence_state
        end
      ),
      stability_ok: (
        if $observed_stability_ok == "true" then true
        elif $observed_stability_ok == "false" then false
        else null
        end
      ),
      selection_policy_present_all: (
        if $observed_selection_policy_present_all == "true" then true
        elif $observed_selection_policy_present_all == "false" then false
        else null
        end
      ),
      consistent_selection_policy: (
        if $observed_consistent_selection_policy == "true" then true
        elif $observed_consistent_selection_policy == "false" then false
        else null
        end
      ),
      recommended_profile_counts: $observed_recommended_profile_counts,
      recommended_profile_counts_total: $observed_recommended_profile_total,
      modal_recommended_profile: (
        if $observed_modal_recommended_profile == "" then null
        else $observed_modal_recommended_profile
        end
      ),
      modal_recommended_profile_count: $observed_modal_recommended_profile_count,
      modal_support_rate_pct: $observed_modal_support_rate_pct,
      decision_counts: $observed_decision_counts,
      decision_counts_total: $observed_decision_total,
      modal_decision: (
        if $observed_modal_decision == "" then null
        else $observed_modal_decision
        end
      ),
      modal_decision_count: $observed_modal_decision_count,
      modal_decision_support_rate_pct: $observed_modal_decision_support_rate_pct,
      decision_consensus: (
        if $observed_decision_consensus == "true" then true
        elif $observed_decision_consensus == "false" then false
        else null
        end
      )
    },
    enforcement: {
      fail_on_no_go: ($fail_on_no_go == 1),
      no_go_detected: ($decision == "NO-GO"),
      no_go_enforced: ($decision == "NO-GO" and ($fail_on_no_go == 1)),
      terminal_outcome: (
        if $decision == "GO" then "pass"
        elif $fail_on_no_go == 1 then "blocked"
        else "warn"
        end
      )
    },
    outcome: {
      has_usable_decision: ($decision == "GO" or $decision == "NO-GO"),
      should_promote: ($decision == "GO"),
      action: (
        if $decision == "GO" then "promote_allowed"
        elif $fail_on_no_go == 1 then "hold_promotion_blocked"
        else "hold_promotion_warn_only"
        end
      )
    },
    diagnostics: {
      error_count: ($errors | length),
      missing_or_invalid_evidence: ($missing_or_invalid_evidence == "true"),
      partial_evidence: ($partial_evidence == "true"),
      next_operator_action: $next_operator_action,
      rerun_run_command_template: $rerun_run_command_template,
      rerun_check_command_template: $rerun_check_command_template,
      rerun_cycle_command_template: $rerun_cycle_command_template,
      inspect_summary_command_template: $inspect_summary_command_template
    },
    errors: $errors,
    artifacts: {
      summary_json: $summary_json
    }
  }' >"$summary_json"

echo "[profile-default-gate-stability-check] decision=$decision status=$status rc=$rc modal_profile=${observed_modal_recommended_profile:-unset} modal_support_rate_pct=${observed_modal_support_rate_pct} modal_decision=${observed_modal_decision:-unset} modal_decision_support_rate_pct=${observed_modal_decision_support_rate_pct}"
if ((${#errors[@]} > 0)); then
  echo "[profile-default-gate-stability-check] failed with ${#errors[@]} issue(s):"
  idx=1
  for err in "${errors[@]}"; do
    echo "  $idx. $err"
    idx=$((idx + 1))
  done
fi

if [[ "$show_json" == "1" ]]; then
  echo "[profile-default-gate-stability-check] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
