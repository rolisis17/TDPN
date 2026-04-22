#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_multi_vm_stability_check.sh \
    [--stability-summary-json PATH] \
    [--reports-dir DIR] \
    [--require-status-pass [0|1]] \
    [--require-min-runs-requested N] \
    [--require-min-runs-completed N] \
    [--require-max-runs-fail N] \
    [--require-decision-consensus [0|1]] \
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
  Verify profile-compare multi-VM stability summary artifacts and emit a
  fail-closed GO/NO-GO decision for stability readiness.
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
reports_dir="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REPORTS_DIR:-${REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}}"

require_status_pass="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_STATUS_PASS:-${REQUIRE_STATUS_PASS:-1}}"
require_min_runs_requested="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_MIN_RUNS_REQUESTED:-${REQUIRE_MIN_RUNS_REQUESTED:-3}}"
require_min_runs_completed="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_MIN_RUNS_COMPLETED:-${REQUIRE_MIN_RUNS_COMPLETED:-3}}"
require_max_runs_fail="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_MAX_RUNS_FAIL:-${REQUIRE_MAX_RUNS_FAIL:-0}}"
require_decision_consensus="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_DECISION_CONSENSUS:-${REQUIRE_DECISION_CONSENSUS:-1}}"
require_modal_decision="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_MODAL_DECISION:-${REQUIRE_MODAL_DECISION:-GO}}"
require_modal_decision_support_rate_pct="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_MODAL_DECISION_SUPPORT_RATE_PCT:-${REQUIRE_MODAL_DECISION_SUPPORT_RATE_PCT:-67}}"
require_recommended_profile="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_RECOMMENDED_PROFILE:-${REQUIRE_RECOMMENDED_PROFILE:-}}"
allow_recommended_profiles="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_ALLOW_RECOMMENDED_PROFILES:-${ALLOW_RECOMMENDED_PROFILES:-balanced,speed,private}}"
require_modal_support_rate_pct="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_REQUIRE_MODAL_SUPPORT_RATE_PCT:-${REQUIRE_MODAL_SUPPORT_RATE_PCT:-60}}"
fail_on_no_go="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_FAIL_ON_NO_GO:-${FAIL_ON_NO_GO:-1}}"

show_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SHOW_JSON:-0}"
print_summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_PRINT_SUMMARY_JSON:-0}"
summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SUMMARY_JSON:-}"

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
  stability_summary_json="$reports_dir/profile_compare_multi_vm_stability_summary.json"
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
  summary_json="$log_dir/profile_compare_multi_vm_stability_check_${run_stamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

declare -a errors=()

summary_exists="0"
schema_valid="0"
if [[ -f "$stability_summary_json" ]]; then
  summary_exists="1"
  if jq -e '
    .version == 1
    and (.schema | type == "object")
    and (
      .schema.id == "profile_compare_multi_vm_stability_summary"
      or .schema.id == "profile_compare_multi_vm_stability_run_summary"
    )
  ' "$stability_summary_json" >/dev/null 2>&1; then
    schema_valid="1"
  else
    errors+=("stability summary schema.id must be profile_compare_multi_vm_stability_summary or profile_compare_multi_vm_stability_run_summary (path=$stability_summary_json)")
  fi
else
  errors+=("stability summary JSON not found ($stability_summary_json)")
fi

observed_status=""
observed_runs_requested_json="null"
observed_runs_completed_json="null"
observed_runs_fail_json="null"
observed_recommended_profile_counts_json='{}'
observed_recommended_profile_total_json="0"
observed_modal_recommended_profile=""
observed_modal_recommended_profile_count_json="0"
observed_modal_support_rate_pct_json="0"
observed_decision_counts_json='{}'
observed_decision_total_json="0"
observed_modal_decision=""
observed_modal_decision_count_json="0"
observed_modal_decision_support_rate_pct_json="0"
observed_decision_consensus=""
observed_decision_consensus_reported=""
observed_decision_consensus_computed=""

if [[ "$schema_valid" == "1" ]]; then
  observed_status="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$stability_summary_json" 2>/dev/null || true)"

  observed_runs_requested_candidate="$(jq -r '
    if (.runs_requested | type) == "number" and .runs_requested >= 0 and (.runs_requested | floor == .) then .runs_requested
    elif (.runs_requested | type) == "string" and (.runs_requested | test("^[0-9]+$")) then (.runs_requested | tonumber)
    elif (.counts.requested | type) == "number" and .counts.requested >= 0 and (.counts.requested | floor == .) then .counts.requested
    elif (.counts.requested | type) == "string" and (.counts.requested | test("^[0-9]+$")) then (.counts.requested | tonumber)
    elif (.inputs.runs_requested | type) == "number" and .inputs.runs_requested >= 0 and (.inputs.runs_requested | floor == .) then .inputs.runs_requested
    elif (.inputs.runs_requested | type) == "string" and (.inputs.runs_requested | test("^[0-9]+$")) then (.inputs.runs_requested | tonumber)
    elif (.inputs.runs | type) == "number" and .inputs.runs >= 0 and (.inputs.runs | floor == .) then .inputs.runs
    elif (.inputs.runs | type) == "string" and (.inputs.runs | test("^[0-9]+$")) then (.inputs.runs | tonumber)
    else ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"
  if [[ -n "$observed_runs_requested_candidate" ]]; then
    observed_runs_requested_json="$observed_runs_requested_candidate"
  fi

  observed_runs_completed_candidate="$(jq -r '
    if (.runs_completed | type) == "number" and .runs_completed >= 0 and (.runs_completed | floor == .) then .runs_completed
    elif (.runs_completed | type) == "string" and (.runs_completed | test("^[0-9]+$")) then (.runs_completed | tonumber)
    elif (.counts.completed | type) == "number" and .counts.completed >= 0 and (.counts.completed | floor == .) then .counts.completed
    elif (.counts.completed | type) == "string" and (.counts.completed | test("^[0-9]+$")) then (.counts.completed | tonumber)
    else ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"
  if [[ -n "$observed_runs_completed_candidate" ]]; then
    observed_runs_completed_json="$observed_runs_completed_candidate"
  fi

  observed_runs_fail_candidate="$(jq -r '
    if (.runs_fail | type) == "number" and .runs_fail >= 0 and (.runs_fail | floor == .) then .runs_fail
    elif (.runs_fail | type) == "string" and (.runs_fail | test("^[0-9]+$")) then (.runs_fail | tonumber)
    elif (.counts.fail | type) == "number" and .counts.fail >= 0 and (.counts.fail | floor == .) then .counts.fail
    elif (.counts.fail | type) == "string" and (.counts.fail | test("^[0-9]+$")) then (.counts.fail | tonumber)
    elif (.counts.runs_fail | type) == "number" and .counts.runs_fail >= 0 and (.counts.runs_fail | floor == .) then .counts.runs_fail
    elif (.counts.runs_fail | type) == "string" and (.counts.runs_fail | test("^[0-9]+$")) then (.counts.runs_fail | tonumber)
    else ""
    end
  ' "$stability_summary_json" 2>/dev/null || true)"
  if [[ -n "$observed_runs_fail_candidate" ]]; then
    observed_runs_fail_json="$observed_runs_fail_candidate"
  fi

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
    if (.recommended_profile_counts | type) == "object" then
      reduce (.recommended_profile_counts | to_entries[]) as $entry
        ({};
          ($entry.key | tostring | normalize_profile) as $k
          | ($entry.value
             | if type == "number" then .
               elif type == "string" and test("^-?[0-9]+([.][0-9]+)?$") then tonumber
               else null
               end) as $v
          | if ($k | length) == 0 or $v == null or $v < 0 then .
            else .[$k] = ((.[$k] // 0) + $v)
            end
        )
    elif (.histograms.recommended_profile_counts | type) == "object" then
      reduce (.histograms.recommended_profile_counts | to_entries[]) as $entry
        ({};
          ($entry.key | tostring | normalize_profile) as $k
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
        | if (.recommended_profile | type) == "string"
          then .recommended_profile
          else (.decision.recommended_profile // empty)
          end
        | strings
        | gsub("^\\s+|\\s+$"; "")
        | select(length > 0)
        | normalize_profile
      ]
      | group_by(.)
      | map({ (.[0]): length })
      | add // {}
    else
      {}
    end
  ' "$stability_summary_json" 2>/dev/null || printf '{}')"

  observed_recommended_profile_total_json="$(jq -r '[.[]] | add // 0' <<<"$observed_recommended_profile_counts_json")"
  observed_modal_recommended_profile="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].key // ""' <<<"$observed_recommended_profile_counts_json")"
  observed_modal_recommended_profile_count_json="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].value // 0' <<<"$observed_recommended_profile_counts_json")"
  observed_modal_support_rate_pct_json="$(jq -n \
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
    if (.decision_counts | type) == "object" then
      reduce (.decision_counts | to_entries[]) as $entry
        ({};
          ($entry.key | tostring | normalize_decision) as $k
          | ($entry.value
             | if type == "number" then .
               elif type == "string" and test("^-?[0-9]+([.][0-9]+)?$") then tonumber
               else null
               end) as $v
          | if ($k | length) == 0 or $v == null or $v < 0 then .
            else .[$k] = ((.[$k] // 0) + $v)
            end
        )
    elif (.histograms.decision_counts | type) == "object" then
      reduce (.histograms.decision_counts | to_entries[]) as $entry
        ({};
          ($entry.key | tostring | normalize_decision) as $k
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
        | if (.decision | type) == "string" then .decision else (.decision.decision // empty) end
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
  observed_modal_decision="$(jq -r '
    to_entries
    | sort_by(
        -.value,
        (if .key == "NO-GO" then 0 elif .key == "GO" then 1 else 2 end),
        .key
      )
    | .[0].key // ""
  ' <<<"$observed_decision_counts_json")"
  observed_modal_decision_count_json="$(jq -r '
    to_entries
    | sort_by(
        -.value,
        (if .key == "NO-GO" then 0 elif .key == "GO" then 1 else 2 end),
        .key
      )
    | .[0].value // 0
  ' <<<"$observed_decision_counts_json")"
  observed_modal_decision_support_rate_pct_json="$(jq -n \
    --argjson total "$observed_decision_total_json" \
    --argjson modal "$observed_modal_decision_count_json" \
    'if $total > 0 then (($modal * 100) / $total) else 0 end')"

  observed_decision_consensus_reported="$(jq -r '
    if (.decision_consensus | type) == "boolean" then
      if .decision_consensus then "true" else "false" end
    else
      ""
    end
  ' "$stability_summary_json" 2>/dev/null || printf '%s' "")"

  observed_decision_consensus_computed="$(jq -r '
    def normalize_decision:
      ascii_upcase
      | gsub("\\s+"; "")
      | if . == "GO" then "GO"
        elif . == "NO-GO" or . == "NOGO" or . == "NO_GO" then "NO-GO"
        else .
        end;
    (
      if (.decision_counts | type) == "object" then
        reduce (.decision_counts | to_entries[]) as $entry
          ({};
            ($entry.key | tostring | normalize_decision) as $k
            | ($entry.value
               | if type == "number" then .
                 elif type == "string" and test("^-?[0-9]+([.][0-9]+)?$") then tonumber
                 else null
                 end) as $v
            | if ($k | length) == 0 or $v == null or $v < 0 then .
              else .[$k] = ((.[$k] // 0) + $v)
              end
          )
      elif (.histograms.decision_counts | type) == "object" then
        reduce (.histograms.decision_counts | to_entries[]) as $entry
          ({};
            ($entry.key | tostring | normalize_decision) as $k
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
          | if (.decision | type) == "string" then .decision else (.decision.decision // empty) end
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
    ) as $counts
    | ([$counts[]] | add // 0) as $total
    | if $total == 0 then ""
      elif (($counts | keys | length) == 1) then "true"
      else "false"
      end
  ' "$stability_summary_json" 2>/dev/null || printf '%s' "")"

  if [[ -n "$observed_decision_consensus_reported" ]]; then
    observed_decision_consensus="$observed_decision_consensus_reported"
  else
    observed_decision_consensus="$observed_decision_consensus_computed"
  fi
fi

if [[ "$schema_valid" == "1" ]]; then
  if [[ "$require_status_pass" == "1" ]] && [[ "$observed_status" != "pass" ]]; then
    errors+=("stability status must be pass (actual=${observed_status:-unset})")
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

  if [[ -n "$observed_decision_consensus_reported" && -n "$observed_decision_consensus_computed" ]] \
    && [[ "$observed_decision_consensus_reported" != "$observed_decision_consensus_computed" ]]; then
    errors+=("decision_consensus mismatch between reported and computed values (reported=$observed_decision_consensus_reported computed=$observed_decision_consensus_computed)")
  fi

  if [[ "$require_decision_consensus" == "1" && "$observed_decision_consensus" != "true" ]]; then
    errors+=("decision_consensus must be true (actual=${observed_decision_consensus:-unset})")
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

  if awk -v observed="$observed_modal_support_rate_pct_json" -v min_required="$require_modal_support_rate_pct" 'BEGIN { exit !(observed < min_required) }'; then
    errors+=("modal support rate below threshold (actual=${observed_modal_support_rate_pct_json}% required=${require_modal_support_rate_pct}%)")
  fi

  if [[ -n "$require_modal_decision" ]]; then
    if [[ -z "$observed_modal_decision" ]]; then
      errors+=("modal decision is empty")
    elif [[ "$observed_modal_decision" != "$require_modal_decision" ]]; then
      errors+=("modal decision mismatch (actual=${observed_modal_decision:-unset} required=$require_modal_decision)")
    fi
  fi

  if awk -v observed="$observed_modal_decision_support_rate_pct_json" -v min_required="$require_modal_decision_support_rate_pct" 'BEGIN { exit !(observed < min_required) }'; then
    errors+=("modal decision support rate below threshold (actual=${observed_modal_decision_support_rate_pct_json}% required=${require_modal_decision_support_rate_pct}%)")
  fi
fi

decision="GO"
status="ok"
notes="multi-VM stability summary passes configured policy"
if ((${#errors[@]} > 0)); then
  decision="NO-GO"
  status="fail"
  notes="multi-VM stability summary violates one or more policy checks"
fi

rc=0
if [[ "$decision" == "NO-GO" && "$fail_on_no_go" == "1" ]]; then
  rc=1
fi

errors_json='[]'
if ((${#errors[@]} > 0)); then
  errors_json="$(printf '%s\n' "${errors[@]}" | jq -R . | jq -s '.')"
fi

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg decision "$decision" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg stability_summary_json "$stability_summary_json" \
  --argjson stability_summary_exists "$summary_exists" \
  --argjson stability_summary_schema_valid "$schema_valid" \
  --arg observed_status "$observed_status" \
  --argjson observed_runs_requested "$observed_runs_requested_json" \
  --argjson observed_runs_completed "$observed_runs_completed_json" \
  --argjson observed_runs_fail "$observed_runs_fail_json" \
  --argjson observed_recommended_profile_counts "$observed_recommended_profile_counts_json" \
  --arg observed_modal_recommended_profile "$observed_modal_recommended_profile" \
  --argjson observed_modal_recommended_profile_count "$observed_modal_recommended_profile_count_json" \
  --argjson observed_recommended_profile_total "$observed_recommended_profile_total_json" \
  --argjson observed_modal_support_rate_pct "$observed_modal_support_rate_pct_json" \
  --argjson observed_decision_counts "$observed_decision_counts_json" \
  --argjson observed_decision_total "$observed_decision_total_json" \
  --arg observed_modal_decision "$observed_modal_decision" \
  --argjson observed_modal_decision_count "$observed_modal_decision_count_json" \
  --argjson observed_modal_decision_support_rate_pct "$observed_modal_decision_support_rate_pct_json" \
  --arg observed_decision_consensus "$observed_decision_consensus" \
  --arg observed_decision_consensus_reported "$observed_decision_consensus_reported" \
  --arg observed_decision_consensus_computed "$observed_decision_consensus_computed" \
  --argjson require_status_pass "$require_status_pass" \
  --argjson require_min_runs_requested "$require_min_runs_requested" \
  --argjson require_min_runs_completed "$require_min_runs_completed" \
  --argjson require_max_runs_fail "$require_max_runs_fail" \
  --argjson require_decision_consensus "$require_decision_consensus" \
  --arg require_modal_decision "$require_modal_decision" \
  --argjson require_modal_decision_support_rate_pct "$require_modal_decision_support_rate_pct" \
  --arg require_recommended_profile "$require_recommended_profile" \
  --arg allow_recommended_profiles "$allow_recommended_profiles" \
  --argjson require_modal_support_rate_pct "$require_modal_support_rate_pct" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --argjson rc "$rc" \
  --argjson errors "$errors_json" \
  --arg summary_json "$summary_json" \
  '{
    version: 1,
    schema: {
      id: "profile_compare_multi_vm_stability_check_summary"
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
        require_min_runs_requested: $require_min_runs_requested,
        require_min_runs_completed: $require_min_runs_completed,
        require_max_runs_fail: $require_max_runs_fail,
        require_decision_consensus: ($require_decision_consensus == 1),
        require_modal_decision: (
          if $require_modal_decision == "" then null
          else $require_modal_decision
          end
        ),
        require_modal_decision_support_rate_pct: $require_modal_decision_support_rate_pct,
        require_recommended_profile: (
          if $require_recommended_profile == "" then null
          else $require_recommended_profile
          end
        ),
        allow_recommended_profiles: (
          if $allow_recommended_profiles == "" then null
          else $allow_recommended_profiles
          end
        ),
        require_modal_support_rate_pct: $require_modal_support_rate_pct,
        fail_on_no_go: ($fail_on_no_go == 1)
      }
    },
    observed: {
      stability_summary_exists: ($stability_summary_exists == 1),
      stability_summary_schema_valid: ($stability_summary_schema_valid == 1),
      status: (if $observed_status == "" then null else $observed_status end),
      runs_requested: $observed_runs_requested,
      runs_completed: $observed_runs_completed,
      runs_fail: $observed_runs_fail,
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
      ),
      decision_consensus_reported: (
        if $observed_decision_consensus_reported == "true" then true
        elif $observed_decision_consensus_reported == "false" then false
        else null
        end
      ),
      decision_consensus_computed: (
        if $observed_decision_consensus_computed == "true" then true
        elif $observed_decision_consensus_computed == "false" then false
        else null
        end
      )
    },
    errors: $errors,
    artifacts: {
      summary_json: $summary_json
    }
  }' >"$summary_json"

echo "[profile-compare-multi-vm-stability-check] decision=$decision status=$status rc=$rc modal_profile=${observed_modal_recommended_profile:-unset} modal_support_rate_pct=${observed_modal_support_rate_pct_json} modal_decision=${observed_modal_decision:-unset} modal_decision_support_rate_pct=${observed_modal_decision_support_rate_pct_json}"
if ((${#errors[@]} > 0)); then
  echo "[profile-compare-multi-vm-stability-check] failed with ${#errors[@]} issue(s):"
  idx=1
  for err in "${errors[@]}"; do
    echo "  $idx. $err"
    idx=$((idx + 1))
  done
fi

if [[ "$show_json" == "1" ]]; then
  echo "[profile-compare-multi-vm-stability-check] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
