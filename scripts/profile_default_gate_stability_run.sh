#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_default_gate_stability_run.sh \
    --host-a HOST \
    --host-b HOST \
    [--campaign-subject ID | --subject ID] \
    [--runs N] \
    [--campaign-timeout-sec N] \
    [--sleep-between-sec N] \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--allow-partial [0|1]]

Purpose:
  Run repeated profile-default-gate-live evidence collection and emit one
  stability-oriented aggregate summary JSON.

Notes:
  - easy_node wrapper path can be overridden with:
    PROFILE_DEFAULT_GATE_STABILITY_EASY_NODE_SCRIPT
  - default easy_node path is: ./scripts/easy_node.sh
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim() {
  local value="${1:-}"
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

require_value_or_die() {
  local flag="$1"
  local argc="$2"
  if (( argc < 2 )); then
    echo "$flag requires a value"
    exit 2
  fi
}

int_arg_or_die() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be a non-negative integer"
    exit 2
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

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

need_cmd jq
need_cmd mktemp
need_cmd date
need_cmd bash
need_cmd sleep

host_a="${PROFILE_DEFAULT_GATE_STABILITY_HOST_A:-}"
host_b="${PROFILE_DEFAULT_GATE_STABILITY_HOST_B:-}"
campaign_subject="${PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT:-}"
campaign_subject_from_campaign=""
campaign_subject_from_alias=""
runs="${PROFILE_DEFAULT_GATE_STABILITY_RUNS:-3}"
campaign_timeout_sec="${PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_TIMEOUT_SEC:-2400}"
sleep_between_sec="${PROFILE_DEFAULT_GATE_STABILITY_SLEEP_BETWEEN_SEC:-5}"
reports_dir="${PROFILE_DEFAULT_GATE_STABILITY_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
summary_json="${PROFILE_DEFAULT_GATE_STABILITY_SUMMARY_JSON:-}"
print_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_PRINT_SUMMARY_JSON:-0}"
allow_partial="${PROFILE_DEFAULT_GATE_STABILITY_ALLOW_PARTIAL:-0}"
easy_node_script="${PROFILE_DEFAULT_GATE_STABILITY_EASY_NODE_SCRIPT:-$ROOT_DIR/scripts/easy_node.sh}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host-a)
      require_value_or_die "$1" "$#"
      host_a="${2:-}"
      shift 2
      ;;
    --host-a=*)
      host_a="${1#*=}"
      shift
      ;;
    --host-b)
      require_value_or_die "$1" "$#"
      host_b="${2:-}"
      shift 2
      ;;
    --host-b=*)
      host_b="${1#*=}"
      shift
      ;;
    --campaign-subject)
      require_value_or_die "$1" "$#"
      campaign_subject="${2:-}"
      campaign_subject_from_campaign="${2:-}"
      shift 2
      ;;
    --campaign-subject=*)
      campaign_subject="${1#*=}"
      campaign_subject_from_campaign="${1#*=}"
      shift
      ;;
    --subject)
      require_value_or_die "$1" "$#"
      campaign_subject="${2:-}"
      campaign_subject_from_alias="${2:-}"
      shift 2
      ;;
    --subject=*)
      campaign_subject="${1#*=}"
      campaign_subject_from_alias="${1#*=}"
      shift
      ;;
    --runs)
      require_value_or_die "$1" "$#"
      runs="${2:-}"
      shift 2
      ;;
    --runs=*)
      runs="${1#*=}"
      shift
      ;;
    --campaign-timeout-sec)
      require_value_or_die "$1" "$#"
      campaign_timeout_sec="${2:-}"
      shift 2
      ;;
    --campaign-timeout-sec=*)
      campaign_timeout_sec="${1#*=}"
      shift
      ;;
    --sleep-between-sec)
      require_value_or_die "$1" "$#"
      sleep_between_sec="${2:-}"
      shift 2
      ;;
    --sleep-between-sec=*)
      sleep_between_sec="${1#*=}"
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
    --summary-json)
      require_value_or_die "$1" "$#"
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
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
    --allow-partial)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_partial="${2:-}"
        shift 2
      else
        allow_partial="1"
        shift
      fi
      ;;
    --allow-partial=*)
      allow_partial="${1#*=}"
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

host_a="$(trim "$host_a")"
host_b="$(trim "$host_b")"
campaign_subject="$(trim "$campaign_subject")"
campaign_subject_from_campaign="$(trim "$campaign_subject_from_campaign")"
campaign_subject_from_alias="$(trim "$campaign_subject_from_alias")"
runs="$(trim "$runs")"
campaign_timeout_sec="$(trim "$campaign_timeout_sec")"
sleep_between_sec="$(trim "$sleep_between_sec")"
reports_dir="$(abs_path "$reports_dir")"
summary_json="$(trim "$summary_json")"
print_summary_json="$(trim "$print_summary_json")"
allow_partial="$(trim "$allow_partial")"
easy_node_script="$(abs_path "$easy_node_script")"

if [[ -z "$host_a" ]]; then
  echo "--host-a is required"
  exit 2
fi
if [[ -z "$host_b" ]]; then
  echo "--host-b is required"
  exit 2
fi
if [[ -z "$campaign_subject" ]]; then
  echo "--campaign-subject or --subject is required"
  exit 2
fi
if [[ -n "$campaign_subject_from_campaign" && -n "$campaign_subject_from_alias" && "$campaign_subject_from_campaign" != "$campaign_subject_from_alias" ]]; then
  echo "conflicting subject values: --campaign-subject and --subject must match when both are provided"
  exit 2
fi
if [[ ! -f "$easy_node_script" ]]; then
  echo "easy_node wrapper script not found: $easy_node_script"
  exit 2
fi

int_arg_or_die "--runs" "$runs"
int_arg_or_die "--campaign-timeout-sec" "$campaign_timeout_sec"
int_arg_or_die "--sleep-between-sec" "$sleep_between_sec"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--allow-partial" "$allow_partial"

if (( runs < 1 )); then
  echo "--runs must be >= 1"
  exit 2
fi
if (( campaign_timeout_sec < 1 )); then
  echo "--campaign-timeout-sec must be >= 1"
  exit 2
fi

mkdir -p "$reports_dir"
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/profile_default_gate_stability_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

runs_rows_file="$(mktemp)"
cleanup() {
  rm -f "$runs_rows_file" 2>/dev/null || true
}
trap cleanup EXIT

echo "[profile-default-gate-stability-run] $(timestamp_utc) start runs=$runs allow_partial=$allow_partial reports_dir=$reports_dir"

run_index=0
while (( run_index < runs )); do
  run_index=$((run_index + 1))
  run_id="$(printf 'run_%02d' "$run_index")"
  run_stamp="$(date -u +%Y%m%d_%H%M%S)_${run_id}"
  run_summary_json="$reports_dir/profile_default_gate_live_${run_stamp}_summary.json"
  run_log="$reports_dir/profile_default_gate_live_${run_stamp}.log"

  echo "[profile-default-gate-stability-run] $(timestamp_utc) run-start run_id=$run_id summary_json=$run_summary_json"

  run_started_epoch="$(date +%s)"
  set +e
  bash "$easy_node_script" profile-default-gate-live \
    --host-a "$host_a" \
    --host-b "$host_b" \
    --campaign-subject "$campaign_subject" \
    --reports-dir "$reports_dir" \
    --campaign-timeout-sec "$campaign_timeout_sec" \
    --summary-json "$run_summary_json" \
    --print-summary-json 0 >"$run_log" 2>&1
  command_rc=$?
  set -e
  run_duration_sec=$(( $(date +%s) - run_started_epoch ))

  summary_exists="0"
  completed="0"
  summary_status="missing"
  summary_rc_json="null"
  decision_value=""
  recommended_profile=""
  support_rate_pct_json="null"
  campaign_summary_json=""
  campaign_summary_exists="0"
  selection_policy_present="0"
  selection_policy_json="null"

  if [[ -f "$run_summary_json" ]]; then
    summary_exists="1"
    if jq -e 'type == "object"' "$run_summary_json" >/dev/null 2>&1; then
      completed="1"
      summary_status="$(jq -r '.status // "unknown"' "$run_summary_json" 2>/dev/null || printf '%s' "unknown")"
      decision_value="$(jq -r '.decision.decision // ""' "$run_summary_json" 2>/dev/null || printf '%s' "")"
      recommended_profile="$(jq -r '.decision.recommended_profile // ""' "$run_summary_json" 2>/dev/null || printf '%s' "")"
      summary_rc_candidate="$(jq -r 'if (.final_rc | type) == "number" then .final_rc elif (.rc | type) == "number" then .rc else "" end' "$run_summary_json" 2>/dev/null || true)"
      if [[ -n "$summary_rc_candidate" ]]; then
        summary_rc_json="$summary_rc_candidate"
      fi
      support_rate_candidate="$(jq -r '
        if (.decision.support_rate_pct | type) == "number" then .decision.support_rate_pct
        elif (.decision.support_rate_pct | type) == "string" and (.decision.support_rate_pct | test("^-?[0-9]+([.][0-9]+)?$")) then (.decision.support_rate_pct | tonumber)
        else ""
        end
      ' "$run_summary_json" 2>/dev/null || true)"
      if [[ -n "$support_rate_candidate" ]]; then
        support_rate_pct_json="$support_rate_candidate"
      fi

      campaign_summary_json="$(jq -r '.artifacts.campaign_summary_json // ""' "$run_summary_json" 2>/dev/null || printf '%s' "")"
      if [[ -n "$campaign_summary_json" ]]; then
        campaign_summary_json="$(abs_path "$campaign_summary_json")"
      fi
      if [[ -n "$campaign_summary_json" && -f "$campaign_summary_json" ]]; then
        campaign_summary_exists="1"
        selection_policy_candidate="$(jq -c '
          def scalar:
            if type == "array" then (.[0] // null) else . end;
          def to_num:
            scalar
            | if . == null then null
              elif type == "number" then .
              elif type == "string" and test("^-?[0-9]+([.][0-9]+)?$") then tonumber
              else null
              end;
          def to_str:
            scalar
            | if . == null then null
              elif type == "string" then .
              elif type == "number" then tostring
              else null
              end;
          (.summary.selection_policy // {}) as $p
          | {
              sticky_pair_sec: ($p.sticky_pair_sec | to_num),
              entry_rotation_sec: ($p.entry_rotation_sec | to_num),
              entry_rotation_jitter_pct: ($p.entry_rotation_jitter_pct | to_num),
              exit_exploration_pct: ($p.exit_exploration_pct | to_num),
              path_profile: ($p.path_profile | to_str)
            }
          | if (
              (.sticky_pair_sec != null)
              and (.entry_rotation_sec != null)
              and (.entry_rotation_jitter_pct != null)
              and (.exit_exploration_pct != null)
              and (.path_profile != null)
              and ((.path_profile | length) > 0)
            )
            then .
            else empty
            end
        ' "$campaign_summary_json" 2>/dev/null || true)"
        if [[ -n "$selection_policy_candidate" ]]; then
          selection_policy_present="1"
          selection_policy_json="$selection_policy_candidate"
        fi
      fi
    else
      summary_status="invalid_summary_json"
    fi
  fi

  jq -n \
    --arg run_id "$run_id" \
    --arg run_summary_json "$run_summary_json" \
    --arg run_log "$run_log" \
    --arg status "$summary_status" \
    --arg decision "$decision_value" \
    --arg recommended_profile "$recommended_profile" \
    --arg campaign_summary_json "$campaign_summary_json" \
    --arg summary_exists "$summary_exists" \
    --arg completed "$completed" \
    --arg campaign_summary_exists "$campaign_summary_exists" \
    --arg selection_policy_present "$selection_policy_present" \
    --argjson run_index "$run_index" \
    --argjson command_rc "$command_rc" \
    --argjson duration_sec "$run_duration_sec" \
    --argjson rc "$summary_rc_json" \
    --argjson support_rate_pct "$support_rate_pct_json" \
    --argjson selection_policy "$selection_policy_json" \
    '{
      run_index: $run_index,
      run_id: $run_id,
      command_rc: $command_rc,
      duration_sec: $duration_sec,
      summary_exists: ($summary_exists == "1"),
      completed: ($completed == "1"),
      status: $status,
      rc: $rc,
      decision: {
        decision: (if $decision == "" then null else $decision end),
        recommended_profile: (if $recommended_profile == "" then null else $recommended_profile end),
        support_rate_pct: $support_rate_pct
      },
      artifacts: {
        run_summary_json: $run_summary_json,
        run_log: $run_log,
        campaign_summary_json: (if $campaign_summary_json == "" then null else $campaign_summary_json end),
        campaign_summary_exists: ($campaign_summary_exists == "1")
      },
      selection_policy_present: ($selection_policy_present == "1"),
      selection_policy: $selection_policy
    }' >>"$runs_rows_file"

  echo "[profile-default-gate-stability-run] $(timestamp_utc) run-end run_id=$run_id command_rc=$command_rc summary_exists=$summary_exists completed=$completed status=$summary_status duration_sec=$run_duration_sec"

  if (( run_index < runs && sleep_between_sec > 0 )); then
    sleep "$sleep_between_sec"
  fi
done

runs_json="$(jq -s '.' "$runs_rows_file")"
runs_total="$(jq 'length' <<<"$runs_json")"
runs_completed="$(jq '[.[] | select(.completed == true)] | length' <<<"$runs_json")"
runs_pass="$(jq '[.[] | select(.command_rc == 0 and .summary_exists == true and .completed == true)] | length' <<<"$runs_json")"
runs_fail="$(jq '[.[] | select(.command_rc != 0 or .summary_exists != true or .completed != true)] | length' <<<"$runs_json")"
command_failures="$(jq '[.[] | select(.command_rc != 0)] | length' <<<"$runs_json")"
summary_missing_count="$(jq '[.[] | select(.summary_exists != true)] | length' <<<"$runs_json")"
summary_unreadable_count="$(jq '[.[] | select(.summary_exists == true and .completed != true)] | length' <<<"$runs_json")"

selection_policy_present_all="$(jq -r '
  ([.[] | select(.completed == true)] ) as $completed
  | if ($completed | length) == 0 then false
    else all($completed[]; .selection_policy_present == true)
    end
' <<<"$runs_json")"

consistent_selection_policy="$(jq -r '
  ([.[] | select(.completed == true)] ) as $completed
  | ([.[] | select(.completed == true and .selection_policy_present == true) | (.selection_policy | tojson)]) as $policies
  | if ($completed | length) == 0 then false
    elif ($policies | length) != ($completed | length) then false
    else (($policies | unique | length) == 1)
    end
' <<<"$runs_json")"

recommended_profile_counts_json="$(jq '
  [ .[] | select(.completed == true) | .decision.recommended_profile // empty | strings | select(length > 0) ]
  | group_by(.)
  | map({ (.[0]): length })
  | add // {}
' <<<"$runs_json")"

decision_counts_json="$(jq '
  def normalize_decision:
    ascii_upcase
    | if . == "GO" then "GO"
      elif . == "NO-GO" or . == "NOGO" or . == "NO_GO" then "NO-GO"
      else .
      end;
  [ .[] | select(.completed == true) | .decision.decision // empty | strings | gsub("^\\s+|\\s+$"; "") | select(length > 0) | normalize_decision ]
  | group_by(.)
  | map({ (.[0]): length })
  | add // {}
' <<<"$runs_json")"

decision_total_json="$(jq -r '[.[]] | add // 0' <<<"$decision_counts_json")"
modal_decision="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].key // ""' <<<"$decision_counts_json")"
modal_decision_count_json="$(jq -r 'to_entries | sort_by(-.value, .key) | .[0].value // 0' <<<"$decision_counts_json")"
modal_decision_support_rate_pct_json="$(jq -n \
  --argjson total "$decision_total_json" \
  --argjson modal "$modal_decision_count_json" \
  'if $total > 0 then (($modal * 100) / $total) else 0 end')"

decision_consensus="$(jq -r '
  def normalize_decision:
    ascii_upcase
    | if . == "GO" then "GO"
      elif . == "NO-GO" or . == "NOGO" or . == "NO_GO" then "NO-GO"
      else .
      end;
  ([.[] | select(.completed == true)] ) as $completed
  | ([.[] | select(.completed == true) | .decision.decision // empty | strings | gsub("^\\s+|\\s+$"; "") | select(length > 0) | normalize_decision ]) as $decisions
  | if ($completed | length) == 0 then false
    elif ($decisions | length) != ($completed | length) then false
    else (($decisions | unique | length) == 1)
    end
' <<<"$runs_json")"

stability_ok="$(jq -r '
  ([.[] | select(.completed == true)] ) as $completed
  | ([.[] | select(.completed == true and .selection_policy_present == true) | (.selection_policy | tojson)]) as $policies
  | if (length == 0) then false
    elif ($completed | length) != length then false
    elif any(.[]; .command_rc != 0 or .summary_exists != true) then false
    elif ($policies | length) != ($completed | length) then false
    else (($policies | unique | length) == 1)
    end
' <<<"$runs_json")"

status="pass"
notes="all requested runs completed with stable selection policy tuple"
if [[ "$stability_ok" != "true" ]]; then
  status="warn"
  notes="selection policy evidence is partial or inconsistent across completed runs"
fi
if (( runs_completed == 0 )); then
  status="fail"
  notes="no runs completed with a readable summary"
fi
if (( command_failures > 0 || summary_missing_count > 0 || summary_unreadable_count > 0 )); then
  status="warn"
  notes="one or more runs failed to execute or produce readable summary artifacts"
  if (( runs_completed == 0 )); then
    status="fail"
  fi
fi

final_rc=0
if [[ "$allow_partial" == "0" ]]; then
  if (( command_failures > 0 || summary_missing_count > 0 || summary_unreadable_count > 0 )); then
    final_rc=1
  fi
else
  if (( runs_completed < 1 )); then
    final_rc=1
  fi
fi

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json_path "$summary_json" \
  --arg host_a "$host_a" \
  --arg host_b "$host_b" \
  --arg allow_partial "$allow_partial" \
  --argjson rc "$final_rc" \
  --argjson runs_requested "$runs" \
  --argjson campaign_timeout_sec "$campaign_timeout_sec" \
  --argjson sleep_between_sec "$sleep_between_sec" \
  --argjson runs_total "$runs_total" \
  --argjson runs_completed "$runs_completed" \
  --argjson runs_pass "$runs_pass" \
  --argjson runs_fail "$runs_fail" \
  --argjson consistent_selection_policy "$consistent_selection_policy" \
  --argjson selection_policy_present_all "$selection_policy_present_all" \
  --argjson recommended_profile_counts "$recommended_profile_counts_json" \
  --argjson decision_counts "$decision_counts_json" \
  --argjson decision_total "$decision_total_json" \
  --arg modal_decision "$modal_decision" \
  --argjson modal_decision_count "$modal_decision_count_json" \
  --argjson modal_decision_support_rate_pct "$modal_decision_support_rate_pct_json" \
  --argjson decision_consensus "$decision_consensus" \
  --argjson stability_ok "$stability_ok" \
  --argjson runs "$runs_json" \
  '{
    version: 1,
    schema: {
      id: "profile_default_gate_stability_summary"
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    notes: $notes,
    inputs: {
      host_a: $host_a,
      host_b: $host_b,
      runs_requested: $runs_requested,
      campaign_timeout_sec: $campaign_timeout_sec,
      sleep_between_sec: $sleep_between_sec,
      allow_partial: ($allow_partial == "1"),
      reports_dir: $reports_dir
    },
    runs_total: $runs_total,
    runs_completed: $runs_completed,
    runs_pass: $runs_pass,
    runs_fail: $runs_fail,
    consistent_selection_policy: $consistent_selection_policy,
    selection_policy_present_all: $selection_policy_present_all,
    recommended_profile_counts: $recommended_profile_counts,
    decision_counts: $decision_counts,
    decision_total: $decision_total,
    modal_decision: (if $modal_decision == "" then null else $modal_decision end),
    modal_decision_count: $modal_decision_count,
    modal_decision_support_rate_pct: $modal_decision_support_rate_pct,
    decision_consensus: $decision_consensus,
    stability_ok: $stability_ok,
    runs: $runs,
    artifacts: {
      summary_json: $summary_json_path
    }
  }' >"$summary_json"

echo "profile-default-gate-stability-run: status=$status rc=$final_rc"
echo "summary_json: $summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
