#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_multi_vm_reducer.sh \
    [--campaign-summary-json PATH]... \
    [--campaign-summary-list FILE] \
    [--reports-dir DIR] \
    [--fail-on-no-go [0|1]] \
    [--min-support-rate-pct N] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Reduce multiple per-VM profile-campaign summary artifacts into one
  decision-grade reducer summary that preserves campaign-style decision fields.

Accepted input summary schemas:
  - profile-compare-campaign-signoff summary
  - profile-compare-campaign-check summary
  - profile-compare-campaign summary (requires valid trend summary with
    recommendation_support_rate_pct)
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
  if ((argc < 2)); then
    echo "$flag requires a value"
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

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

is_non_negative_int() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+$ ]]
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
    GO|PASS|OK) printf '%s\n' "GO" ;;
    NO-GO|NOGO|NO_GO|FAIL|FAILED|ERROR) printf '%s\n' "NO-GO" ;;
    *) printf '%s\n' "$decision" ;;
  esac
}

normalize_status() {
  local status
  status="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$status" in
    pass|ok|go) printf '%s\n' "pass" ;;
    warn|warning) printf '%s\n' "warn" ;;
    fail|failed|error|no-go|nogo|no_go) printf '%s\n' "fail" ;;
    *) printf '%s\n' "other" ;;
  esac
}

format_pct() {
  local numerator="$1"
  local denominator="$2"
  awk -v n="$numerator" -v d="$denominator" 'BEGIN { if (d <= 0) { printf "0.00"; exit } printf "%.2f", (n * 100.0) / d }'
}

need_cmd jq
need_cmd date
need_cmd find
need_cmd awk

declare -a campaign_summary_jsons=()
campaign_summary_list=""
reports_dir="${PROFILE_COMPARE_MULTI_VM_REDUCER_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
fail_on_no_go="${PROFILE_COMPARE_MULTI_VM_REDUCER_FAIL_ON_NO_GO:-1}"
min_support_rate_pct="${PROFILE_COMPARE_MULTI_VM_REDUCER_MIN_SUPPORT_RATE_PCT:-60}"
show_json="${PROFILE_COMPARE_MULTI_VM_REDUCER_SHOW_JSON:-0}"
print_summary_json="${PROFILE_COMPARE_MULTI_VM_REDUCER_PRINT_SUMMARY_JSON:-0}"
summary_json="${PROFILE_COMPARE_MULTI_VM_REDUCER_SUMMARY_JSON:-}"
report_md="${PROFILE_COMPARE_MULTI_VM_REDUCER_REPORT_MD:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --campaign-summary-json)
      require_value_or_die "$1" "$#"
      campaign_summary_jsons+=("${2:-}")
      shift 2
      ;;
    --campaign-summary-json=*)
      campaign_summary_jsons+=("${1#*=}")
      shift
      ;;
    --campaign-summary-list)
      require_value_or_die "$1" "$#"
      campaign_summary_list="${2:-}"
      shift 2
      ;;
    --campaign-summary-list=*)
      campaign_summary_list="${1#*=}"
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
    --min-support-rate-pct)
      require_value_or_die "$1" "$#"
      min_support_rate_pct="${2:-}"
      shift 2
      ;;
    --min-support-rate-pct=*)
      min_support_rate_pct="${1#*=}"
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
    --summary-json)
      require_value_or_die "$1" "$#"
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    --report-md)
      require_value_or_die "$1" "$#"
      report_md="${2:-}"
      shift 2
      ;;
    --report-md=*)
      report_md="${1#*=}"
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

reports_dir="$(abs_path "$reports_dir")"
campaign_summary_list="$(trim "$campaign_summary_list")"
if [[ -n "$campaign_summary_list" ]]; then
  campaign_summary_list="$(abs_path "$campaign_summary_list")"
  if [[ ! -f "$campaign_summary_list" ]]; then
    echo "--campaign-summary-list file not found: $campaign_summary_list"
    exit 2
  fi
fi

bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
if ! is_non_negative_decimal "$min_support_rate_pct"; then
  echo "--min-support-rate-pct must be a non-negative number"
  exit 2
fi
if awk -v raw="$min_support_rate_pct" 'BEGIN { exit !(raw > 100) }'; then
  echo "--min-support-rate-pct must be <= 100"
  exit 2
fi
min_support_rate_pct="$(awk -v raw="$min_support_rate_pct" 'BEGIN { printf "%.2f", raw + 0 }')"

log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"

if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/profile_compare_multi_vm_reducer_${run_stamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$report_md" ]]; then
  report_md="$log_dir/profile_compare_multi_vm_reducer_${run_stamp}.md"
else
  report_md="$(abs_path "$report_md")"
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

declare -a candidate_paths=()
declare -a errors=()
declare -A seen_paths=()

for raw_path in "${campaign_summary_jsons[@]}"; do
  path="$(abs_path "$raw_path")"
  [[ -n "$path" ]] && candidate_paths+=("$path")
done

if [[ -n "$campaign_summary_list" ]]; then
  while IFS= read -r list_line || [[ -n "$list_line" ]]; do
    list_line="$(trim "$list_line")"
    [[ -z "$list_line" || "$list_line" == \#* ]] && continue
    path="$(abs_path "$list_line")"
    [[ -n "$path" ]] && candidate_paths+=("$path")
  done <"$campaign_summary_list"
fi

if [[ ${#candidate_paths[@]} -eq 0 ]]; then
  if [[ -d "$reports_dir" ]]; then
    while IFS= read -r found_path; do
      [[ -n "$found_path" ]] && candidate_paths+=("$found_path")
    done < <(
      find "$reports_dir" -maxdepth 2 -type f \
        \( -name 'profile_compare_campaign_signoff_summary*.json' \
           -o -name 'profile_compare_campaign_check_summary*.json' \
           -o -name 'profile_compare_campaign_summary*.json' \) \
        2>/dev/null | sort
    )
  fi
fi

rows_file="$(mktemp)"
trap 'rm -f "$rows_file"' EXIT

declare -a unique_paths=()
for candidate in "${candidate_paths[@]}"; do
  candidate="$(trim "$candidate")"
  [[ -z "$candidate" ]] && continue
  if [[ -n "${seen_paths[$candidate]:-}" ]]; then
    continue
  fi
  seen_paths["$candidate"]="1"
  unique_paths+=("$candidate")
done

if [[ ${#unique_paths[@]} -eq 0 ]]; then
  errors+=("no input summaries found")
fi

for summary_path in "${unique_paths[@]}"; do
  vm_id="$(basename "$summary_path")"
  vm_id="${vm_id%.json}"
  schema_kind="unknown"

  status_raw=""
  decision_raw=""
  recommended_profile_raw=""
  support_rate_raw=""
  trend_source_raw=""
  runs_total_raw=""
  runs_pass_raw=""
  runs_warn_raw=""
  runs_fail_raw=""

  status_norm="other"
  decision_norm=""
  recommended_profile_norm=""
  support_rate_json="null"
  trend_source=""
  runs_total_json="null"
  runs_pass_json="null"
  runs_warn_json="null"
  runs_fail_json="null"

  row_valid_json="false"
  declare -a row_errors=()

  if [[ ! -f "$summary_path" ]]; then
    row_errors+=("summary file not found")
  elif ! jq -e . "$summary_path" >/dev/null 2>&1; then
    row_errors+=("summary file is not valid JSON")
  else
    if jq -e '.version == 1 and (.decision | type == "object") and (.decision.decision | type == "string")' "$summary_path" >/dev/null 2>&1; then
      schema_kind="campaign-signoff"
      IFS=$'\t' read -r status_raw decision_raw recommended_profile_raw support_rate_raw trend_source_raw < <(
        jq -r '[.status // "", .decision.decision // "", .decision.recommended_profile // "", (.decision.support_rate_pct // ""), .decision.trend_source // ""] | @tsv' "$summary_path"
      )
    elif jq -e '.version == 1 and (.decision | type == "string") and (.observed | type == "object")' "$summary_path" >/dev/null 2>&1; then
      schema_kind="campaign-check"
      IFS=$'\t' read -r status_raw decision_raw recommended_profile_raw support_rate_raw trend_source_raw runs_total_raw runs_pass_raw runs_warn_raw runs_fail_raw < <(
        jq -r '[.status // "", .decision // "", .observed.recommended_profile // "", (.observed.recommendation_support_rate_pct // .observed.support_rate_pct // ""), .observed.trend_source // "", (.observed.runs_total // ""), (.observed.runs_pass // ""), (.observed.runs_warn // ""), (.observed.runs_fail // "")] | @tsv' "$summary_path"
      )
    elif jq -e '.version == 1 and (.summary | type == "object") and (.decision | type == "object") and (.trend | type == "object")' "$summary_path" >/dev/null 2>&1; then
      schema_kind="campaign"
      local_rc_raw=""
      explicit_decision_raw=""
      trend_summary_json_raw=""
      campaign_source_raw=""
      IFS=$'\t' read -r status_raw local_rc_raw recommended_profile_raw campaign_source_raw trend_summary_json_raw runs_total_raw runs_pass_raw runs_warn_raw runs_fail_raw < <(
        jq -r '[.status // "", (.rc // ""), .decision.recommended_default_profile // "", .decision.source // "", .trend.summary_json // "", (.summary.runs_total // ""), (.summary.runs_pass // ""), (.summary.runs_warn // ""), (.summary.runs_fail // "")] | @tsv' "$summary_path"
      )
      explicit_decision_raw="$(jq -r '.decision.decision // .decision.result // .decision.outcome // ""' "$summary_path" 2>/dev/null || printf '%s' "")"

      local_rc_raw="$(trim "$local_rc_raw")"
      if [[ -z "$local_rc_raw" ]] || ! [[ "$local_rc_raw" =~ ^-?[0-9]+$ ]]; then
        row_errors+=("campaign summary rc is missing/invalid")
      fi
      if [[ -z "$status_raw" ]]; then
        row_errors+=("campaign summary status is missing")
      fi

      explicit_decision_raw="$(trim "$explicit_decision_raw")"
      if [[ -n "$explicit_decision_raw" ]]; then
        decision_raw="$explicit_decision_raw"
      else
        decision_raw="NO-GO"
        if [[ "$status_raw" == "pass" && "$local_rc_raw" == "0" ]]; then
          decision_raw="GO"
        fi
      fi

      trend_summary_json_raw="$(trim "$trend_summary_json_raw")"
      trend_summary_json_path="$(abs_path "$trend_summary_json_raw")"
      if [[ -z "$trend_summary_json_path" || ! -f "$trend_summary_json_path" ]]; then
        row_errors+=("campaign trend summary_json is missing/unreadable")
      elif ! jq -e '.version == 1 and (.decision | type == "object")' "$trend_summary_json_path" >/dev/null 2>&1; then
        row_errors+=("campaign trend summary_json is invalid")
      else
        IFS=$'\t' read -r support_rate_raw trend_source_raw < <(
          jq -r '[.decision.recommendation_support_rate_pct // "", .decision.source // ""] | @tsv' "$trend_summary_json_path"
        )
      fi
      if [[ -z "$trend_source_raw" ]]; then
        trend_source_raw="$campaign_source_raw"
      fi
    else
      row_errors+=("unsupported summary schema")
    fi
  fi

  status_raw="$(trim "$status_raw")"
  decision_raw="$(trim "$decision_raw")"
  recommended_profile_raw="$(trim "$recommended_profile_raw")"
  support_rate_raw="$(trim "$support_rate_raw")"
  trend_source_raw="$(trim "$trend_source_raw")"
  runs_total_raw="$(trim "$runs_total_raw")"
  runs_pass_raw="$(trim "$runs_pass_raw")"
  runs_warn_raw="$(trim "$runs_warn_raw")"
  runs_fail_raw="$(trim "$runs_fail_raw")"

  status_norm="$(normalize_status "$status_raw")"
  decision_norm="$(normalize_decision "$decision_raw")"
  recommended_profile_norm="$(normalize_profile "$recommended_profile_raw")"
  trend_source="$trend_source_raw"

  if [[ "$status_norm" == "other" ]]; then
    row_errors+=("status is missing/unsupported (raw=${status_raw:-unset})")
  fi
  if [[ "$decision_norm" != "GO" && "$decision_norm" != "NO-GO" ]]; then
    row_errors+=("decision is missing/unsupported (raw=${decision_raw:-unset})")
  fi
  if [[ -z "$recommended_profile_norm" ]]; then
    row_errors+=("recommended_profile is missing")
  fi
  if ! is_non_negative_decimal "$support_rate_raw"; then
    row_errors+=("support_rate_pct is missing/invalid")
  else
    support_rate_json="$support_rate_raw"
  fi
  if [[ -z "$trend_source" ]]; then
    row_errors+=("trend_source is missing")
  fi

  if [[ -n "$runs_total_raw" ]]; then
    if is_non_negative_int "$runs_total_raw"; then
      runs_total_json="$runs_total_raw"
    else
      row_errors+=("runs_total is invalid")
    fi
  fi
  if [[ -n "$runs_pass_raw" ]]; then
    if is_non_negative_int "$runs_pass_raw"; then
      runs_pass_json="$runs_pass_raw"
    else
      row_errors+=("runs_pass is invalid")
    fi
  fi
  if [[ -n "$runs_warn_raw" ]]; then
    if is_non_negative_int "$runs_warn_raw"; then
      runs_warn_json="$runs_warn_raw"
    else
      row_errors+=("runs_warn is invalid")
    fi
  fi
  if [[ -n "$runs_fail_raw" ]]; then
    if is_non_negative_int "$runs_fail_raw"; then
      runs_fail_json="$runs_fail_raw"
    else
      row_errors+=("runs_fail is invalid")
    fi
  fi

  if ((${#row_errors[@]} == 0)); then
    row_valid_json="true"
  fi

  row_errors_json='[]'
  if ((${#row_errors[@]} > 0)); then
    row_errors_json="$(printf '%s\n' "${row_errors[@]}" | jq -R . | jq -s '.')"
    for err in "${row_errors[@]}"; do
      errors+=("$summary_path: $err")
    done
  fi

  jq -n \
    --arg vm_id "$vm_id" \
    --arg input_summary_json "$summary_path" \
    --arg schema_kind "$schema_kind" \
    --arg status "$status_norm" \
    --arg decision "$decision_norm" \
    --arg recommended_profile "$recommended_profile_norm" \
    --arg trend_source "$trend_source" \
    --argjson support_rate_pct "$support_rate_json" \
    --argjson runs_total "$runs_total_json" \
    --argjson runs_pass "$runs_pass_json" \
    --argjson runs_warn "$runs_warn_json" \
    --argjson runs_fail "$runs_fail_json" \
    --argjson valid "$row_valid_json" \
    --argjson errors "$row_errors_json" \
    '{
      vm_id: $vm_id,
      input_summary_json: $input_summary_json,
      schema_kind: $schema_kind,
      status: $status,
      decision: $decision,
      recommended_profile: $recommended_profile,
      support_rate_pct: $support_rate_pct,
      trend_source: $trend_source,
      runs_total: $runs_total,
      runs_pass: $runs_pass,
      runs_warn: $runs_warn,
      runs_fail: $runs_fail,
      valid: $valid,
      errors: $errors
    }' >>"$rows_file"
done

rows_json='[]'
if [[ -s "$rows_file" ]]; then
  rows_json="$(jq -s '.' "$rows_file")"
fi

vm_total="$(jq 'length' <<<"$rows_json")"
vm_valid="$(jq '[.[] | select(.valid == true)] | length' <<<"$rows_json")"
vm_invalid="$(jq '[.[] | select(.valid != true)] | length' <<<"$rows_json")"

status_pass_count="$(jq '[.[] | select(.valid == true and .status == "pass")] | length' <<<"$rows_json")"
status_warn_count="$(jq '[.[] | select(.valid == true and .status == "warn")] | length' <<<"$rows_json")"
status_fail_count="$(jq '[.[] | select(.valid == true and .status == "fail")] | length' <<<"$rows_json")"
status_other_count="$(jq '[.[] | select(.valid == true and (.status != "pass" and .status != "warn" and .status != "fail"))] | length' <<<"$rows_json")"

decision_go_count="$(jq '[.[] | select(.valid == true and .decision == "GO")] | length' <<<"$rows_json")"
decision_no_go_count="$(jq '[.[] | select(.valid == true and .decision == "NO-GO")] | length' <<<"$rows_json")"

status_counts_json="$(jq -n \
  --argjson pass "$status_pass_count" \
  --argjson warn "$status_warn_count" \
  --argjson fail "$status_fail_count" \
  --argjson other "$status_other_count" \
  '{pass: $pass, warn: $warn, fail: $fail, other: $other}')"

decision_counts_json="$(jq -n \
  --argjson go "$decision_go_count" \
  --argjson no_go "$decision_no_go_count" \
  '{GO: $go, "NO-GO": $no_go}')"

recommended_profile_counts_json="$(jq '
  reduce ([.[] | select(.valid == true and (.recommended_profile | length > 0)) | .recommended_profile][]) as $p
    ({}; .[$p] = ((.[$p] // 0) + 1))
' <<<"$rows_json")"

modal_profile="$(jq -r '
  [.[] | select(.valid == true and (.recommended_profile | length > 0)) | .recommended_profile]
  | group_by(.)
  | map({profile: .[0], count: length})
  | sort_by(-.count, .profile)
  | .[0].profile // ""
' <<<"$rows_json")"
modal_profile_count="$(jq -r --arg p "$modal_profile" '
  if ($p | length) == 0 then 0 else ([.[] | select(.valid == true and .recommended_profile == $p)] | length) end
' <<<"$rows_json")"
if ! is_non_negative_int "$modal_profile_count"; then
  modal_profile_count="0"
fi

modal_support_rate_pct="$(format_pct "$modal_profile_count" "$vm_valid")"
support_rate_avg_pct="$(jq -r '
  [ .[] | select(.valid == true and (.support_rate_pct != null)) | .support_rate_pct ] as $rates
  | if ($rates | length) == 0 then 0 else (($rates | add) / ($rates | length)) end
' <<<"$rows_json")"
if ! is_non_negative_decimal "$support_rate_avg_pct"; then
  support_rate_avg_pct="0"
fi
support_rate_avg_pct="$(awk -v raw="$support_rate_avg_pct" 'BEGIN { printf "%.2f", raw + 0 }')"

modal_trend_source="$(jq -r --arg p "$modal_profile" '
  (
    [ .[] | select(.valid == true and .recommended_profile == $p and (.trend_source | length > 0)) | .trend_source ]
  ) as $primary
  | (
      if ($primary | length) > 0
      then $primary
      else [ .[] | select(.valid == true and (.trend_source | length > 0)) | .trend_source ]
      end
    )
  | group_by(.)
  | map({source: .[0], count: length})
  | sort_by(-.count, .source)
  | .[0].source // ""
' <<<"$rows_json")"

declare -a policy_errors=()
declare -a promotion_missing_evidence_reason_ids=()
declare -a promotion_missing_evidence_reason_messages=()
promotion_min_support_rate_pct="$min_support_rate_pct"

record_policy_failure() {
  local reason_id="$1"
  local reason_message="$2"
  policy_errors+=("$reason_message")
  promotion_missing_evidence_reason_ids+=("$reason_id")
  promotion_missing_evidence_reason_messages+=("$reason_message")
}

if ((vm_total < 1)); then
  record_policy_failure "no_input_summaries" "no input summaries were provided"
fi
if ((vm_valid < 1)); then
  record_policy_failure "no_valid_vm_summaries" "no valid per-VM summaries were available for reduction"
fi
if ((vm_invalid > 0)); then
  record_policy_failure "invalid_vm_summaries_present" "one or more per-VM summaries are invalid"
fi
if ((decision_go_count < vm_valid)); then
  record_policy_failure "vm_decisions_not_all_go" "not all per-VM decisions are GO"
fi
if ((status_fail_count > 0)); then
  record_policy_failure "vm_status_fail_present" "one or more per-VM statuses are fail"
fi
if ((status_warn_count > 0)); then
  record_policy_failure "vm_status_warn_present" "one or more per-VM statuses are warn"
fi
if [[ -z "$modal_profile" ]]; then
  record_policy_failure "missing_modal_recommended_profile" "could not determine modal recommended_profile"
fi
if awk -v observed="$modal_support_rate_pct" -v min_required="$promotion_min_support_rate_pct" 'BEGIN { exit !(observed < min_required) }'; then
  record_policy_failure "recommended_profile_support_rate_below_threshold" "recommended_profile support_rate_pct below threshold (observed=${modal_support_rate_pct}% required=${promotion_min_support_rate_pct}%)"
fi
if [[ -z "$modal_trend_source" ]]; then
  record_policy_failure "missing_trend_source" "could not determine trend_source"
fi

for err in "${policy_errors[@]}"; do
  errors+=("$err")
done

errors_json='[]'
if ((${#errors[@]} > 0)); then
  errors_json="$(printf '%s\n' "${errors[@]}" | jq -R . | jq -s '.')"
fi

promotion_missing_evidence_reasons_json='[]'
if ((${#promotion_missing_evidence_reason_ids[@]} > 0)); then
  for idx in "${!promotion_missing_evidence_reason_ids[@]}"; do
    promotion_missing_evidence_reasons_json="$(jq -c \
      --arg id "${promotion_missing_evidence_reason_ids[$idx]}" \
      --arg message "${promotion_missing_evidence_reason_messages[$idx]}" \
      '. + [{id: $id, message: $message}]' <<<"$promotion_missing_evidence_reasons_json")"
  done
fi
promotion_missing_evidence_reason_ids_json="$(jq -c '[.[] | .id]' <<<"$promotion_missing_evidence_reasons_json")"

overall_decision="GO"
overall_status="ok"
notes="multi-VM campaign reduction passes strict fail-closed policy"
if ((${#errors[@]} > 0)); then
  overall_decision="NO-GO"
  overall_status="fail"
  notes="multi-VM campaign reduction failed one or more strict policy checks"
fi

rc=0
if [[ "$overall_decision" == "NO-GO" && "$fail_on_no_go" == "1" ]]; then
  rc=1
fi

promotion_gate_status="pass"
promotion_gate_ready_json="true"
if [[ "$overall_decision" != "GO" ]]; then
  promotion_gate_status="fail"
  promotion_gate_ready_json="false"
fi

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg decision_value "$overall_decision" \
  --arg promotion_gate_status "$promotion_gate_status" \
  --arg recommended_profile "$modal_profile" \
  --arg trend_source "$modal_trend_source" \
  --arg notes "$notes" \
  --arg status "$overall_status" \
  --arg reports_dir "$reports_dir" \
  --arg campaign_summary_list "$campaign_summary_list" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --argjson rc "$rc" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --argjson vm_total "$vm_total" \
  --argjson vm_valid "$vm_valid" \
  --argjson vm_invalid "$vm_invalid" \
  --argjson decision_support_rate_pct "$modal_support_rate_pct" \
  --argjson average_support_rate_pct "$support_rate_avg_pct" \
  --argjson status_counts "$status_counts_json" \
  --argjson decision_counts "$decision_counts_json" \
  --argjson recommended_profile_counts "$recommended_profile_counts_json" \
  --argjson promotion_gate_ready "$promotion_gate_ready_json" \
  --argjson promotion_min_support_rate_pct "$promotion_min_support_rate_pct" \
  --argjson promotion_missing_evidence_reasons "$promotion_missing_evidence_reasons_json" \
  --argjson promotion_missing_evidence_reason_ids "$promotion_missing_evidence_reason_ids_json" \
  --argjson vm_summaries "$rows_json" \
  --argjson errors "$errors_json" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    decision: {
      decision: $decision_value,
      recommended_profile: $recommended_profile,
      support_rate_pct: $decision_support_rate_pct,
      trend_source: $trend_source
    },
    status: $status,
    rc: $rc,
    notes: $notes,
    promotion_gate: {
      decision: $decision_value,
      status: $promotion_gate_status,
      promotion_ready: $promotion_gate_ready,
      missing_evidence_reasons: $promotion_missing_evidence_reasons,
      missing_evidence_reason_ids: $promotion_missing_evidence_reason_ids,
      required_evidence: {
        minimum_valid_vm_summaries: 1,
        require_all_vm_summaries_valid: true,
        require_all_vm_decisions_go: true,
        require_no_vm_warn_or_fail_status: true,
        require_modal_recommended_profile: true,
        minimum_recommended_profile_support_rate_pct: $promotion_min_support_rate_pct,
        require_trend_source: true
      }
    },
    inputs: {
      reports_dir: $reports_dir,
      campaign_summary_list: (if $campaign_summary_list == "" then null else $campaign_summary_list end),
      min_support_rate_pct: $promotion_min_support_rate_pct,
      fail_on_no_go: ($fail_on_no_go == 1)
    },
    summary: {
      vm_summaries_total: $vm_total,
      vm_summaries_valid: $vm_valid,
      vm_summaries_invalid: $vm_invalid,
      status_counts: $status_counts,
      decision_counts: $decision_counts,
      recommended_profile_counts: $recommended_profile_counts,
      average_input_support_rate_pct: $average_support_rate_pct
    },
    vm_summaries: $vm_summaries,
    errors: $errors,
    artifacts: {
      summary_json: $summary_json,
      report_md: $report_md
    }
  }' >"$summary_json"

{
  echo "# Profile Compare Multi-VM Reducer Report"
  echo
  echo "- Generated at (UTC): \`$(jq -r '.generated_at_utc' "$summary_json")\`"
  echo "- Decision: \`$(jq -r '.decision.decision' "$summary_json")\`"
  echo "- Recommended profile: \`$(jq -r '.decision.recommended_profile // ""' "$summary_json")\`"
  echo "- Support rate: \`$(jq -r '.decision.support_rate_pct' "$summary_json")%\`"
  echo "- Trend source: \`$(jq -r '.decision.trend_source // ""' "$summary_json")\`"
  echo "- Status: \`$(jq -r '.status' "$summary_json")\`"
  echo "- RC: \`$(jq -r '.rc' "$summary_json")\`"
  echo "- Promotion gate decision: \`$(jq -r '.promotion_gate.decision' "$summary_json")\`"
  echo "- Promotion ready: \`$(jq -r '.promotion_gate.promotion_ready' "$summary_json")\`"
  echo "- Promotion missing evidence reasons: \`$(jq -r 'if (.promotion_gate.missing_evidence_reason_ids | length) == 0 then "none" else (.promotion_gate.missing_evidence_reason_ids | join(",")) end' "$summary_json")\`"
  echo
  echo "## Counts"
  echo
  echo "- VM summaries total: \`$(jq -r '.summary.vm_summaries_total' "$summary_json")\`"
  echo "- VM summaries valid: \`$(jq -r '.summary.vm_summaries_valid' "$summary_json")\`"
  echo "- VM summaries invalid: \`$(jq -r '.summary.vm_summaries_invalid' "$summary_json")\`"
  echo "- Status pass/warn/fail/other: \`$(jq -r '.summary.status_counts.pass' "$summary_json")\` / \`$(jq -r '.summary.status_counts.warn' "$summary_json")\` / \`$(jq -r '.summary.status_counts.fail' "$summary_json")\` / \`$(jq -r '.summary.status_counts.other' "$summary_json")\`"
  echo "- Decision GO/NO-GO: \`$(jq -r '.summary.decision_counts.GO' "$summary_json")\` / \`$(jq -r '.summary.decision_counts["NO-GO"]' "$summary_json")\`"
  echo
  echo "## Per-VM"
  echo
  echo "| VM | Schema | Status | Decision | Recommended | Support % | Trend Source | Valid |"
  echo "|---|---|---|---|---|---:|---|---|"
  jq -r '
    .vm_summaries[]
    | "| \(.vm_id) | \(.schema_kind) | \(.status) | \(.decision) | \(.recommended_profile) | \((if .support_rate_pct == null then "" else (.support_rate_pct | tostring) end)) | \(.trend_source) | \(.valid) |"
  ' "$summary_json"
} >"$report_md"

echo "[profile-compare-multi-vm-reducer] decision=$overall_decision status=$overall_status rc=$rc recommended_profile=${modal_profile:-unset} support_rate_pct=$modal_support_rate_pct trend_source=${modal_trend_source:-unset}"
if ((${#errors[@]} > 0)); then
  echo "[profile-compare-multi-vm-reducer] failed with ${#errors[@]} issue(s):"
  idx=1
  for err in "${errors[@]}"; do
    echo "  $idx. $err"
    idx=$((idx + 1))
  done
fi

if [[ "$show_json" == "1" ]]; then
  echo "[profile-compare-multi-vm-reducer] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
