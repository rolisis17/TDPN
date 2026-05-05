#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STABILITY_CYCLE_SCRIPT="${PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_STABILITY_CYCLE_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_cycle.sh}"
PROMOTION_CYCLE_SCRIPT="${PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_CYCLE_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_promotion_cycle.sh}"
PROMOTION_EVIDENCE_PACK_SCRIPT="${PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_EVIDENCE_PACK_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_promotion_evidence_pack.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_multi_vm_live_evidence_publish_bundle.sh \
    [--reports-dir DIR] \
    [--cycles N] \
    [--fail-on-no-go [0|1]] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Deterministically run the M5 live-evidence publish bundle in one command:
    1) profile_compare_multi_vm_stability_cycle.sh
    2) profile_compare_multi_vm_stability_promotion_cycle.sh
    3) profile_compare_multi_vm_stability_promotion_evidence_pack.sh

Notes:
  - Stage script overrides:
      PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_STABILITY_CYCLE_SCRIPT
      PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_CYCLE_SCRIPT
      PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_EVIDENCE_PACK_SCRIPT
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

strip_optional_wrapping_quotes_01() {
  local value=""
  local first_char=""
  local last_char=""
  value="$(trim "${1:-}")"
  if (( ${#value} < 2 )); then
    printf '%s' "$value"
    return
  fi
  first_char="${value:0:1}"
  last_char="${value: -1}"
  if [[ "$first_char" == '"' && "$last_char" == '"' ]]; then
    value="${value:1:${#value}-2}"
  elif [[ "$first_char" == "'" && "$last_char" == "'" ]]; then
    value="${value:1:${#value}-2}"
  fi
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

quote_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

file_fingerprint_01() {
  local path="$1"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '%s' ""
    return
  fi
  cksum "$path" 2>/dev/null | awk '{print $1 ":" $2}' || true
}

json_file_valid_01() {
  local path="$1"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e 'type == "object"' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
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

normalize_status() {
  local status
  status="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$status" in
    pass|ok|success) printf '%s\n' "pass" ;;
    warn|warning) printf '%s\n' "warn" ;;
    fail|failed|error) printf '%s\n' "fail" ;;
    *) printf '%s\n' "$status" ;;
  esac
}

is_placeholder_like_text_01() {
  local value
  value="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]')"
  if [[ -z "$value" ]]; then
    return 0
  fi
  if [[ "$value" == *"REPLACE_WITH_"* ]] \
    || [[ "$value" == *"[REDACTED]"* ]] \
    || [[ "$value" == *"<SET-REAL-INVITE-KEY>"* ]] \
    || [[ "$value" == *"INVITE_KEY"* ]] \
    || [[ "$value" == *"CAMPAIGN_SUBJECT"* ]] \
    || [[ "$value" == *"<HOST_A>"* ]] \
    || [[ "$value" == *"<HOST_B>"* ]] \
    || [[ "$value" == *"A_HOST"* ]] \
    || [[ "$value" == *"B_HOST"* ]] \
    || [[ "$value" == *"HOST_A"* ]] \
    || [[ "$value" == *"HOST_B"* ]] \
    || [[ "$value" == *"%INVITE_KEY%"* ]] \
    || [[ "$value" == *"%CAMPAIGN_SUBJECT%"* ]]; then
    return 0
  fi
  return 1
}

sanitize_text_hint_01() {
  local value
  value="$(trim "${1:-}")"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    printf '%s' ""
    return
  fi
  if is_placeholder_like_text_01 "$value"; then
    printf '%s' ""
    return
  fi
  if [[ "$value" == *";"* ]] || [[ "$value" == *"&&"* ]] || [[ "$value" == *"||"* ]] || [[ "$value" == *"|"* ]]; then
    printf '%s' ""
    return
  fi
  printf '%s' "$value"
}

action_command_is_safe_01() {
  local cmd=""
  cmd="$(trim "${1:-}")"
  cmd="$(strip_optional_wrapping_quotes_01 "$cmd")"
  cmd="${cmd//$'\r'/ }"
  cmd="${cmd//$'\n'/ }"
  cmd="$(trim "$cmd")"
  if [[ -z "$cmd" ]]; then
    return 1
  fi
  if is_placeholder_like_text_01 "$cmd"; then
    return 1
  fi
  case "$cmd" in
    ./*|bash\ ./*|sudo\ ./*)
      ;;
    *)
      return 1
      ;;
  esac
  if [[ "$cmd" == *";"* ]] || [[ "$cmd" == *"&&"* ]] || [[ "$cmd" == *"||"* ]] || [[ "$cmd" == *"|"* ]] || [[ "$cmd" == *'$('* ]] || [[ "$cmd" == *'`'* ]]; then
    return 1
  fi
  return 0
}

sanitize_action_command_01() {
  local cmd=""
  cmd="$(trim "${1:-}")"
  cmd="$(strip_optional_wrapping_quotes_01 "$cmd")"
  cmd="$(trim "$cmd")"
  if action_command_is_safe_01 "$cmd"; then
    printf '%s' "$cmd"
  else
    printf '%s' ""
  fi
}

first_non_empty_line_01() {
  local line=""
  for line in "$@"; do
    if [[ -n "$(trim "$line")" ]]; then
      printf '%s' "$(trim "$line")"
      return
    fi
  done
  printf '%s' ""
}

evaluate_stage_summary_json() {
  local summary_path="$1"
  local expected_schema_id="$2"
  local pre_fingerprint="$3"

  local summary_exists="false"
  local summary_valid_json="false"
  local summary_schema_id=""
  local summary_schema_valid="false"
  local summary_written_fresh="false"
  local summary_signals_stale="false"
  local summary_usable="false"
  local decision_norm=""
  local status_norm=""
  local rc_json="null"
  local failure_reason=""
  local failure_reason_code=""
  local next_operator_action=""
  local next_command_hint=""
  local post_fingerprint=""

  if [[ -f "$summary_path" ]]; then
    summary_exists="true"
  fi
  if [[ "$summary_exists" == "true" && "$(json_file_valid_01 "$summary_path")" == "1" ]]; then
    summary_valid_json="true"
    summary_schema_id="$(jq -r 'if (.schema.id | type) == "string" then .schema.id else "" end' "$summary_path" 2>/dev/null || true)"
    if [[ "$summary_schema_id" == "$expected_schema_id" ]]; then
      summary_schema_valid="true"
    fi

    post_fingerprint="$(file_fingerprint_01 "$summary_path")"
    if [[ -z "$pre_fingerprint" && -n "$post_fingerprint" ]]; then
      summary_written_fresh="true"
    elif [[ -n "$post_fingerprint" && "$post_fingerprint" != "$pre_fingerprint" ]]; then
      summary_written_fresh="true"
    fi

    decision_norm="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$summary_path" 2>/dev/null || true)"
    decision_norm="$(normalize_decision "$decision_norm")"
    status_norm="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$summary_path" 2>/dev/null || true)"
    status_norm="$(normalize_status "$status_norm")"
    rc_json="$(jq -r 'if (.rc | type) == "number" then .rc elif (.final_rc | type) == "number" then .final_rc else "null" end' "$summary_path" 2>/dev/null || printf '%s' "null")"
    failure_reason="$(jq -r 'if (.failure_reason | type) == "string" then .failure_reason else "" end' "$summary_path" 2>/dev/null || true)"
    failure_reason_code="$(jq -r 'if (.failure_reason_code | type) == "string" then .failure_reason_code else "" end' "$summary_path" 2>/dev/null || true)"
    next_operator_action="$(jq -r '
      if (.next_operator_action | type) == "string" and (.next_operator_action | length) > 0 then .next_operator_action
      elif (.outcome.next_operator_action | type) == "string" and (.outcome.next_operator_action | length) > 0 then .outcome.next_operator_action
      else ""
      end
    ' "$summary_path" 2>/dev/null || true)"
    next_command_hint="$(jq -r '
      if (.next_command | type) == "string" and (.next_command | length) > 0 then .next_command
      elif (.operator_next_action_command | type) == "string" and (.operator_next_action_command | length) > 0 then .operator_next_action_command
      elif (.outcome.next_command | type) == "string" and (.outcome.next_command | length) > 0 then .outcome.next_command
      else ""
      end
    ' "$summary_path" 2>/dev/null || true)"

    if jq -e '
      ((.run.summary_fresh? == false)
      or (.check.summary_fresh? == false)
      or (.promotion.summary_fresh? == false)
      or (.evidence.promotion_cycle.freshness.fresh? == false)
      or ((.failure_reason_code // "") | ascii_downcase | test("stale"))
      or ((.failure_reasons // []) | map(.code // "" | tostring | ascii_downcase | test("stale")) | any)
      or ((.reasons // []) | map(tostring | ascii_downcase | test("stale")) | any))
    ' "$summary_path" >/dev/null 2>&1; then
      summary_signals_stale="true"
    fi
  fi

  if [[ "$summary_exists" == "true" \
    && "$summary_valid_json" == "true" \
    && "$summary_schema_valid" == "true" \
    && "$summary_written_fresh" == "true" \
    && "$summary_signals_stale" != "true" ]]; then
    summary_usable="true"
  fi

  jq -n \
    --arg summary_path "$summary_path" \
    --arg expected_schema_id "$expected_schema_id" \
    --arg summary_exists "$summary_exists" \
    --arg summary_valid_json "$summary_valid_json" \
    --arg summary_schema_id "$summary_schema_id" \
    --arg summary_schema_valid "$summary_schema_valid" \
    --arg summary_written_fresh "$summary_written_fresh" \
    --arg summary_signals_stale "$summary_signals_stale" \
    --arg summary_usable "$summary_usable" \
    --arg decision_norm "$decision_norm" \
    --arg status_norm "$status_norm" \
    --arg failure_reason "$failure_reason" \
    --arg failure_reason_code "$failure_reason_code" \
    --arg next_operator_action "$next_operator_action" \
    --arg next_command_hint "$next_command_hint" \
    --argjson rc "$rc_json" \
    '{
      source_summary_json: $summary_path,
      expected_schema_id: $expected_schema_id,
      summary_exists: ($summary_exists == "true"),
      summary_valid_json: ($summary_valid_json == "true"),
      summary_schema_id: (if $summary_schema_id == "" then null else $summary_schema_id end),
      summary_schema_valid: ($summary_schema_valid == "true"),
      summary_written_fresh: ($summary_written_fresh == "true"),
      summary_signals_stale: ($summary_signals_stale == "true"),
      usable: ($summary_usable == "true"),
      decision: (if $decision_norm == "" then null else $decision_norm end),
      status: (if $status_norm == "" then null else $status_norm end),
      rc: (if ($rc | type) == "number" then $rc else null end),
      failure_reason: (if $failure_reason == "" then null else $failure_reason end),
      failure_reason_code: (if $failure_reason_code == "" then null else $failure_reason_code end),
      next_operator_action: (if $next_operator_action == "" then null else $next_operator_action end),
      next_command_hint: (if $next_command_hint == "" then null else $next_command_hint end)
    }'
}

render_command() {
  quote_cmd "$@"
}

need_cmd jq
need_cmd date
need_cmd bash
need_cmd mkdir
need_cmd cksum

reports_dir="${PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
cycles="${PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_CYCLES:-3}"
fail_on_no_go="${PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_FAIL_ON_NO_GO:-1}"
summary_json="${PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_SUMMARY_JSON:-}"
print_summary_json="${PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PRINT_SUMMARY_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      require_value_or_die "$1" "$#"
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --cycles)
      require_value_or_die "$1" "$#"
      cycles="${2:-}"
      shift 2
      ;;
    --cycles=*)
      cycles="${1#*=}"
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

reports_dir="$(abs_path "$reports_dir")"
cycles="$(trim "$cycles")"
fail_on_no_go="$(trim "$fail_on_no_go")"
summary_json="$(abs_path "$summary_json")"
print_summary_json="$(trim "$print_summary_json")"
STABILITY_CYCLE_SCRIPT="$(abs_path "$STABILITY_CYCLE_SCRIPT")"
PROMOTION_CYCLE_SCRIPT="$(abs_path "$PROMOTION_CYCLE_SCRIPT")"
PROMOTION_EVIDENCE_PACK_SCRIPT="$(abs_path "$PROMOTION_EVIDENCE_PACK_SCRIPT")"

int_arg_or_die "--cycles" "$cycles"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
if (( cycles < 1 )); then
  echo "--cycles must be >= 1"
  exit 2
fi

if [[ ! -f "$STABILITY_CYCLE_SCRIPT" ]]; then
  echo "stability cycle script not found: $STABILITY_CYCLE_SCRIPT"
  exit 2
fi
if [[ ! -f "$PROMOTION_CYCLE_SCRIPT" ]]; then
  echo "promotion cycle script not found: $PROMOTION_CYCLE_SCRIPT"
  exit 2
fi
if [[ ! -f "$PROMOTION_EVIDENCE_PACK_SCRIPT" ]]; then
  echo "promotion evidence-pack script not found: $PROMOTION_EVIDENCE_PACK_SCRIPT"
  exit 2
fi

mkdir -p "$reports_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"
archive_root="$reports_dir/profile_compare_multi_vm_live_evidence_publish_bundle_${run_stamp}"
mkdir -p "$archive_root"

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/profile_compare_multi_vm_live_evidence_publish_bundle_summary.json"
fi
report_md="$reports_dir/profile_compare_multi_vm_live_evidence_publish_bundle_report.md"
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

stability_cycle_summary_json="$archive_root/profile_compare_multi_vm_stability_cycle_summary.json"
promotion_cycle_summary_json="$archive_root/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
promotion_cycle_summary_list="$archive_root/profile_compare_multi_vm_stability_promotion_cycle_summary_paths.list"
promotion_check_summary_json="$archive_root/profile_compare_multi_vm_stability_promotion_check_summary.json"
evidence_pack_summary_json="$archive_root/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json"
evidence_pack_report_md="$archive_root/profile_compare_multi_vm_stability_promotion_evidence_pack_report.md"

stability_cycle_log="$archive_root/profile_compare_multi_vm_stability_cycle.log"
promotion_cycle_log="$archive_root/profile_compare_multi_vm_stability_promotion_cycle.log"
evidence_pack_log="$archive_root/profile_compare_multi_vm_stability_promotion_evidence_pack.log"

bundle_rerun_command="$(render_command bash ./scripts/profile_compare_multi_vm_live_evidence_publish_bundle.sh --reports-dir "$reports_dir" --cycles "$cycles" --fail-on-no-go "$fail_on_no_go" --summary-json "$summary_json" --print-summary-json 1)"
bundle_rerun_command="$(trim "$bundle_rerun_command")"

stability_cycle_rerun_command="$(render_command bash ./scripts/profile_compare_multi_vm_stability_cycle.sh --reports-dir "$reports_dir" --runs "$cycles" --fail-on-no-go "$fail_on_no_go" --summary-json "$stability_cycle_summary_json" --print-summary-json 1)"
stability_cycle_rerun_command="$(trim "$stability_cycle_rerun_command")"

promotion_cycle_rerun_command="$(render_command bash ./scripts/profile_compare_multi_vm_stability_promotion_cycle.sh --reports-dir "$reports_dir" --cycles "$cycles" --fail-on-no-go "$fail_on_no_go" --cycle-summary-list "$promotion_cycle_summary_list" --promotion-summary-json "$promotion_check_summary_json" --summary-json "$promotion_cycle_summary_json" --print-summary-json 1)"
promotion_cycle_rerun_command="$(trim "$promotion_cycle_rerun_command")"

promotion_evidence_pack_rerun_command="$(render_command bash ./scripts/profile_compare_multi_vm_stability_promotion_evidence_pack.sh --reports-dir "$reports_dir" --promotion-cycle-summary-json "$promotion_cycle_summary_json" --fail-on-no-go "$fail_on_no_go" --summary-json "$evidence_pack_summary_json" --report-md "$evidence_pack_report_md" --print-summary-json 1)"
promotion_evidence_pack_rerun_command="$(trim "$promotion_evidence_pack_rerun_command")"

echo "[profile-compare-multi-vm-live-evidence-publish-bundle] $(timestamp_utc) start reports_dir=$reports_dir cycles=$cycles fail_on_no_go=$fail_on_no_go"

stability_cycle_cmd=(
  bash "$STABILITY_CYCLE_SCRIPT"
  --reports-dir "$reports_dir"
  --runs "$cycles"
  --fail-on-no-go "$fail_on_no_go"
  --summary-json "$stability_cycle_summary_json"
  --show-json 0
  --print-summary-json 0
)
stability_cycle_command_display="$(quote_cmd "${stability_cycle_cmd[@]}")"
stability_cycle_pre_fingerprint="$(file_fingerprint_01 "$stability_cycle_summary_json")"
stability_cycle_started_at="$(timestamp_utc)"
set +e
"${stability_cycle_cmd[@]}" >"$stability_cycle_log" 2>&1
stability_cycle_stage_rc=$?
set -e
stability_cycle_completed_at="$(timestamp_utc)"
stability_cycle_eval_json="$(evaluate_stage_summary_json "$stability_cycle_summary_json" "profile_compare_multi_vm_stability_cycle_summary" "$stability_cycle_pre_fingerprint")"

stability_cycle_stage_status="fail"
if [[ "$stability_cycle_stage_rc" -eq 0 && "$(jq -r '.usable' <<<"$stability_cycle_eval_json")" == "true" ]]; then
  if [[ "$(jq -r '.decision // ""' <<<"$stability_cycle_eval_json")" == "NO-GO" ]]; then
    stability_cycle_stage_status="warn"
  else
    stability_cycle_stage_status="pass"
  fi
fi

promotion_cycle_stage_attempted="false"
promotion_cycle_stage_rc=0
promotion_cycle_started_at=""
promotion_cycle_completed_at=""
promotion_cycle_command_display=""
promotion_cycle_eval_json='{}'
promotion_cycle_stage_status="skip"

evidence_pack_stage_attempted="false"
evidence_pack_stage_rc=0
evidence_pack_started_at=""
evidence_pack_completed_at=""
evidence_pack_command_display=""
evidence_pack_eval_json='{}'
evidence_pack_stage_status="skip"

stability_prereq_usable="$(jq -r '.usable' <<<"$stability_cycle_eval_json")"
stability_prereq_ready="false"
if [[ "$stability_cycle_stage_rc" -eq 0 && "$stability_prereq_usable" == "true" ]]; then
  stability_prereq_ready="true"
fi
if [[ "$stability_prereq_ready" == "true" ]]; then
  promotion_cycle_stage_attempted="true"
  promotion_cycle_cmd=(
    bash "$PROMOTION_CYCLE_SCRIPT"
    --reports-dir "$reports_dir"
    --cycles "$cycles"
    --fail-on-no-go "$fail_on_no_go"
    --cycle-summary-list "$promotion_cycle_summary_list"
    --promotion-summary-json "$promotion_check_summary_json"
    --summary-json "$promotion_cycle_summary_json"
    --show-json 0
    --print-summary-json 0
  )
  promotion_cycle_command_display="$(quote_cmd "${promotion_cycle_cmd[@]}")"
  promotion_cycle_pre_fingerprint="$(file_fingerprint_01 "$promotion_cycle_summary_json")"
  promotion_cycle_started_at="$(timestamp_utc)"
  set +e
  "${promotion_cycle_cmd[@]}" >"$promotion_cycle_log" 2>&1
  promotion_cycle_stage_rc=$?
  set -e
  promotion_cycle_completed_at="$(timestamp_utc)"
  promotion_cycle_eval_json="$(evaluate_stage_summary_json "$promotion_cycle_summary_json" "profile_compare_multi_vm_stability_promotion_cycle_summary" "$promotion_cycle_pre_fingerprint")"

  if [[ "$promotion_cycle_stage_rc" -eq 0 && "$(jq -r '.usable' <<<"$promotion_cycle_eval_json")" == "true" ]]; then
    if [[ "$(jq -r '.decision // ""' <<<"$promotion_cycle_eval_json")" == "NO-GO" ]]; then
      promotion_cycle_stage_status="warn"
    else
      promotion_cycle_stage_status="pass"
    fi
  else
    promotion_cycle_stage_status="fail"
  fi

  promotion_prereq_usable="$(jq -r '.usable' <<<"$promotion_cycle_eval_json")"
  promotion_prereq_ready="false"
  if [[ "$promotion_cycle_stage_rc" -eq 0 && "$promotion_prereq_usable" == "true" ]]; then
    promotion_prereq_ready="true"
  fi
  if [[ "$promotion_prereq_ready" == "true" ]]; then
    evidence_pack_stage_attempted="true"
    evidence_pack_cmd=(
      bash "$PROMOTION_EVIDENCE_PACK_SCRIPT"
      --reports-dir "$reports_dir"
      --promotion-cycle-summary-json "$promotion_cycle_summary_json"
      --fail-on-no-go "$fail_on_no_go"
      --summary-json "$evidence_pack_summary_json"
      --report-md "$evidence_pack_report_md"
      --print-summary-json 0
    )
    evidence_pack_command_display="$(quote_cmd "${evidence_pack_cmd[@]}")"
    evidence_pack_pre_fingerprint="$(file_fingerprint_01 "$evidence_pack_summary_json")"
    evidence_pack_started_at="$(timestamp_utc)"
    set +e
    "${evidence_pack_cmd[@]}" >"$evidence_pack_log" 2>&1
    evidence_pack_stage_rc=$?
    set -e
    evidence_pack_completed_at="$(timestamp_utc)"
    evidence_pack_eval_json="$(evaluate_stage_summary_json "$evidence_pack_summary_json" "profile_compare_multi_vm_stability_promotion_evidence_pack_summary" "$evidence_pack_pre_fingerprint")"

    if [[ "$evidence_pack_stage_rc" -eq 0 && "$(jq -r '.usable' <<<"$evidence_pack_eval_json")" == "true" ]]; then
      if [[ "$(jq -r '.decision // ""' <<<"$evidence_pack_eval_json")" == "NO-GO" ]]; then
        evidence_pack_stage_status="warn"
      else
        evidence_pack_stage_status="pass"
      fi
    else
      evidence_pack_stage_status="fail"
    fi
  fi
fi

final_status="fail"
final_rc=1
final_decision="NO-GO"
failure_reason=""
failure_reason_code=""
failure_substep=""
next_command=""
next_command_reason=""
next_operator_action=""
fail_closed="true"

stability_next_action_hint="$(sanitize_text_hint_01 "$(jq -r '.next_operator_action // ""' <<<"$stability_cycle_eval_json")")"
promotion_next_action_hint="$(sanitize_text_hint_01 "$(jq -r '.next_operator_action // ""' <<<"$promotion_cycle_eval_json")")"
evidence_next_action_hint="$(sanitize_text_hint_01 "$(jq -r '.next_operator_action // ""' <<<"$evidence_pack_eval_json")")"

stability_next_command_hint="$(sanitize_action_command_01 "$(jq -r '.next_command_hint // ""' <<<"$stability_cycle_eval_json")")"
promotion_next_command_hint="$(sanitize_action_command_01 "$(jq -r '.next_command_hint // ""' <<<"$promotion_cycle_eval_json")")"
evidence_next_command_hint="$(sanitize_action_command_01 "$(jq -r '.next_command_hint // ""' <<<"$evidence_pack_eval_json")")"

if [[ "$stability_cycle_stage_rc" -ne 0 ]]; then
  failure_substep="stability_cycle_runner_nonzero"
  failure_reason_code="$failure_substep"
  failure_reason="stability cycle command failed (rc=$stability_cycle_stage_rc)"
  next_command="$stability_cycle_rerun_command"
  next_command_reason="stability-cycle command failed; inspect stage log and rerun stability cycle."
  next_operator_action="$(first_non_empty_line_01 "$stability_next_action_hint" "Regenerate stability-cycle evidence and rerun the bundle.")"
elif [[ "$stability_prereq_usable" != "true" ]]; then
  failure_substep="stability_cycle_summary_missing_or_stale"
  failure_reason_code="stability_cycle_summary_missing_or_stale"
  failure_reason="stability cycle summary artifact is missing, invalid, or stale"
  next_command="$stability_cycle_rerun_command"
  next_command_reason="stability cycle summary artifact is missing or stale; refresh stability cycle evidence before promotion and publish."
  next_operator_action="$(first_non_empty_line_01 "$stability_next_action_hint" "Regenerate stability-cycle evidence and rerun the bundle.")"
elif [[ "$promotion_cycle_stage_attempted" == "true" && "$promotion_cycle_stage_rc" -ne 0 ]]; then
  failure_substep="promotion_cycle_runner_nonzero"
  failure_reason_code="$failure_substep"
  failure_reason="promotion cycle command failed (rc=$promotion_cycle_stage_rc)"
  next_command="$promotion_cycle_rerun_command"
  next_command_reason="promotion-cycle command failed; inspect stage log and rerun promotion cycle."
  next_operator_action="$(first_non_empty_line_01 "$promotion_next_action_hint" "Regenerate promotion-cycle evidence and rerun the bundle.")"
elif [[ "$(jq -r '.usable' <<<"$promotion_cycle_eval_json")" != "true" ]]; then
  failure_substep="promotion_cycle_summary_missing_or_stale"
  failure_reason_code="promotion_cycle_summary_missing_or_stale"
  failure_reason="promotion cycle summary artifact is missing, invalid, or stale"
  next_command="$promotion_cycle_rerun_command"
  next_command_reason="promotion-cycle summary artifact is missing or stale; rerun promotion cycle before evidence-pack publish."
  next_operator_action="$(first_non_empty_line_01 "$promotion_next_action_hint" "Regenerate promotion-cycle evidence and rerun the bundle.")"
elif [[ "$evidence_pack_stage_attempted" == "true" && "$evidence_pack_stage_rc" -ne 0 ]]; then
  failure_substep="promotion_evidence_pack_runner_nonzero"
  failure_reason_code="$failure_substep"
  failure_reason="promotion evidence-pack publish command failed (rc=$evidence_pack_stage_rc)"
  next_command="$promotion_evidence_pack_rerun_command"
  next_command_reason="promotion evidence-pack publish command failed; inspect stage log and republish evidence pack."
  next_operator_action="$(first_non_empty_line_01 "$evidence_next_action_hint" "Republish promotion evidence pack and rerun the bundle.")"
elif [[ "$(jq -r '.usable' <<<"$evidence_pack_eval_json")" != "true" ]]; then
  failure_substep="promotion_evidence_pack_summary_missing_or_stale"
  failure_reason_code="promotion_evidence_pack_summary_missing_or_stale"
  failure_reason="promotion evidence-pack summary artifact is missing, invalid, or stale"
  next_command="$promotion_evidence_pack_rerun_command"
  next_command_reason="promotion evidence-pack summary is missing/stale/invalid; republish evidence pack from fresh promotion summary."
  next_operator_action="$(first_non_empty_line_01 "$evidence_next_action_hint" "Republish promotion evidence pack and rerun the bundle.")"
else
  fail_closed="false"
  promotion_decision_norm="$(jq -r '.decision // ""' <<<"$promotion_cycle_eval_json")"
  evidence_decision_norm="$(jq -r '.decision // ""' <<<"$evidence_pack_eval_json")"
  evidence_status_norm="$(jq -r '.status // ""' <<<"$evidence_pack_eval_json")"
  evidence_rc_norm="$(jq -r '.rc' <<<"$evidence_pack_eval_json")"

  if [[ "$evidence_decision_norm" == "GO" && "$evidence_status_norm" == "pass" && "$evidence_rc_norm" == "0" ]]; then
    final_status="pass"
    final_rc=0
    final_decision="GO"
    failure_reason=""
    failure_reason_code=""
    failure_substep=""
    next_command=""
    next_command_reason=""
    next_operator_action="Live evidence publish bundle is healthy."
  elif [[ "$promotion_decision_norm" == "NO-GO" || "$evidence_decision_norm" == "NO-GO" ]]; then
    final_decision="NO-GO"
    next_command="$(first_non_empty_line_01 "$evidence_next_command_hint" "$promotion_next_command_hint" "$promotion_cycle_rerun_command")"
    if [[ "$fail_on_no_go" == "1" ]]; then
      final_status="fail"
      final_rc=1
      failure_reason_code="promotion_decision_no_go"
      failure_substep="$failure_reason_code"
      failure_reason="promotion pipeline decision is NO-GO"
      next_command_reason="promotion decision is NO-GO and fail-on-no-go is enabled; resolve blockers and rerun promotion pipeline."
      next_operator_action="$(first_non_empty_line_01 "$evidence_next_action_hint" "$promotion_next_action_hint" "Resolve NO-GO blockers and rerun promotion cycle/evidence publish.")"
    else
      final_status="warn"
      final_rc=0
      failure_reason_code="promotion_decision_no_go_warn_only"
      failure_substep="$failure_reason_code"
      failure_reason="promotion pipeline decision is NO-GO (warn-only compatibility mode)"
      next_command_reason="promotion decision is NO-GO in warn-only mode; hold promotion and rerun after resolving blockers."
      next_operator_action="$(first_non_empty_line_01 "$evidence_next_action_hint" "$promotion_next_action_hint" "Hold promotion, resolve NO-GO blockers, then rerun.")"
    fi
  else
    final_status="fail"
    final_rc=1
    final_decision="NO-GO"
    failure_reason_code="promotion_pipeline_contract_invalid"
    failure_substep="$failure_reason_code"
    failure_reason="promotion pipeline produced usable summaries but non-GO contract state"
    next_command="$(first_non_empty_line_01 "$evidence_next_command_hint" "$promotion_next_command_hint" "$bundle_rerun_command")"
    next_command_reason="promotion pipeline contract is not GO/pass-ready; inspect decision/status/rc and rerun affected stages."
    next_operator_action="$(first_non_empty_line_01 "$evidence_next_action_hint" "$promotion_next_action_hint" "Inspect promotion pipeline contract outputs and rerun the bundle.")"
  fi
fi

if [[ -z "$(trim "$next_command")" && "$final_status" != "pass" ]]; then
  next_command="$bundle_rerun_command"
fi
if [[ -n "$(trim "$next_command")" ]] && ! action_command_is_safe_01 "$next_command"; then
  next_command="$bundle_rerun_command"
fi
if [[ -z "$(trim "$next_command_reason")" && "$final_status" != "pass" ]]; then
  next_command_reason="rerun bundle after resolving upstream failures."
fi
if [[ -z "$(trim "$next_operator_action")" ]]; then
  if [[ "$final_status" == "pass" ]]; then
    next_operator_action="Live evidence publish bundle is healthy."
  else
    next_operator_action="Resolve stage failures and rerun the bundle."
  fi
fi

summary_payload="$(jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg reports_dir "$reports_dir" \
  --arg archive_root "$archive_root" \
  --arg summary_json_path "$summary_json" \
  --arg report_md_path "$report_md" \
  --arg status "$final_status" \
  --arg decision "$final_decision" \
  --arg failure_reason "$failure_reason" \
  --arg failure_reason_code "$failure_reason_code" \
  --arg failure_substep "$failure_substep" \
  --arg next_operator_action "$next_operator_action" \
  --arg next_command "$next_command" \
  --arg next_command_reason "$next_command_reason" \
  --arg fail_closed "$fail_closed" \
  --arg stability_cycle_command "$stability_cycle_command_display" \
  --arg promotion_cycle_command "$promotion_cycle_command_display" \
  --arg evidence_pack_command "$evidence_pack_command_display" \
  --arg stability_cycle_log "$stability_cycle_log" \
  --arg promotion_cycle_log "$promotion_cycle_log" \
  --arg evidence_pack_log "$evidence_pack_log" \
  --arg stability_cycle_started_at "$stability_cycle_started_at" \
  --arg stability_cycle_completed_at "$stability_cycle_completed_at" \
  --arg promotion_cycle_started_at "$promotion_cycle_started_at" \
  --arg promotion_cycle_completed_at "$promotion_cycle_completed_at" \
  --arg evidence_pack_started_at "$evidence_pack_started_at" \
  --arg evidence_pack_completed_at "$evidence_pack_completed_at" \
  --argjson rc "$final_rc" \
  --argjson cycles "$cycles" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --argjson stability_cycle_stage_rc "$stability_cycle_stage_rc" \
  --argjson promotion_cycle_stage_attempted "$promotion_cycle_stage_attempted" \
  --argjson promotion_cycle_stage_rc "$promotion_cycle_stage_rc" \
  --argjson evidence_pack_stage_attempted "$evidence_pack_stage_attempted" \
  --argjson evidence_pack_stage_rc "$evidence_pack_stage_rc" \
  --argjson stability_cycle "$stability_cycle_eval_json" \
  --argjson promotion_cycle "$promotion_cycle_eval_json" \
  --argjson evidence_pack "$evidence_pack_eval_json" \
  '{
    version: 1,
    schema: {
      id: "profile_compare_multi_vm_live_evidence_publish_bundle_summary"
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    decision: $decision,
    fail_closed: ($fail_closed == "true"),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    failure_reason_code: (if $failure_reason_code == "" then null else $failure_reason_code end),
    failure_substep: (if $failure_substep == "" then null else $failure_substep end),
    next_operator_action: $next_operator_action,
    next_command: (if $next_command == "" then null else $next_command end),
    next_command_reason: (if $next_command_reason == "" then null else $next_command_reason end),
    inputs: {
      reports_dir: $reports_dir,
      cycles: $cycles,
      fail_on_no_go: ($fail_on_no_go == 1)
    },
    stages: {
      stability_cycle: {
        attempted: true,
        status: (
          if $stability_cycle_stage_rc == 0 and ($stability_cycle.usable == true) then
            (if ($stability_cycle.decision // "") == "NO-GO" then "warn" else "pass" end)
          else "fail"
          end
        ),
        rc: $stability_cycle_stage_rc,
        command: $stability_cycle_command,
        log: $stability_cycle_log,
        started_at_utc: $stability_cycle_started_at,
        completed_at_utc: $stability_cycle_completed_at,
        summary: $stability_cycle
      },
      promotion_cycle: {
        attempted: $promotion_cycle_stage_attempted,
        status: (
          if $promotion_cycle_stage_attempted != true then "skip"
          elif $promotion_cycle_stage_rc == 0 and ($promotion_cycle.usable == true) then
            (if ($promotion_cycle.decision // "") == "NO-GO" then "warn" else "pass" end)
          else "fail"
          end
        ),
        rc: (if $promotion_cycle_stage_attempted == true then $promotion_cycle_stage_rc else 0 end),
        command: (if $promotion_cycle_stage_attempted == true then $promotion_cycle_command else null end),
        log: (if $promotion_cycle_stage_attempted == true then $promotion_cycle_log else null end),
        started_at_utc: (if $promotion_cycle_stage_attempted == true then $promotion_cycle_started_at else null end),
        completed_at_utc: (if $promotion_cycle_stage_attempted == true then $promotion_cycle_completed_at else null end),
        summary: (if $promotion_cycle_stage_attempted == true then $promotion_cycle else null end)
      },
      promotion_evidence_pack_publish: {
        attempted: $evidence_pack_stage_attempted,
        status: (
          if $evidence_pack_stage_attempted != true then "skip"
          elif $evidence_pack_stage_rc == 0 and ($evidence_pack.usable == true) then
            (if ($evidence_pack.decision // "") == "NO-GO" then "warn" else "pass" end)
          else "fail"
          end
        ),
        rc: (if $evidence_pack_stage_attempted == true then $evidence_pack_stage_rc else 0 end),
        command: (if $evidence_pack_stage_attempted == true then $evidence_pack_command else null end),
        log: (if $evidence_pack_stage_attempted == true then $evidence_pack_log else null end),
        started_at_utc: (if $evidence_pack_stage_attempted == true then $evidence_pack_started_at else null end),
        completed_at_utc: (if $evidence_pack_stage_attempted == true then $evidence_pack_completed_at else null end),
        summary: (if $evidence_pack_stage_attempted == true then $evidence_pack else null end)
      }
    },
    outcome: {
      should_promote: ($status == "pass" and $decision == "GO" and $rc == 0),
      action: (
        if $status == "pass" and $decision == "GO" and $rc == 0 then "publish_bundle_pass"
        elif $status == "warn" then "publish_bundle_warn_only"
        else "publish_bundle_blocked"
        end
      ),
      next_operator_action: $next_operator_action,
      next_command: (if $next_command == "" then null else $next_command end),
      next_command_reason: (if $next_command_reason == "" then null else $next_command_reason end)
    },
    artifacts: {
      summary_json: $summary_json_path,
      report_md: $report_md_path,
      archive_root: $archive_root
    }
  }')"

printf '%s\n' "$summary_payload" >"$summary_json"

{
  printf '# Profile Compare Multi-VM Live Evidence Publish Bundle\n\n'
  printf -- '- Generated at (UTC): %s\n' "$(jq -r '.generated_at_utc' "$summary_json")"
  printf -- '- Status: %s\n' "$(jq -r '.status' "$summary_json")"
  printf -- '- Decision: %s\n' "$(jq -r '.decision' "$summary_json")"
  printf -- '- RC: %s\n' "$(jq -r '.rc' "$summary_json")"
  printf -- '- Fail closed: %s\n' "$(jq -r '.fail_closed | tostring' "$summary_json")"
  printf -- '- Failure substep: %s\n' "$(jq -r '.failure_substep // "none"' "$summary_json")"
  printf -- '- Next operator action: %s\n' "$(jq -r '.next_operator_action // "none"' "$summary_json")"
  printf -- '- Next command: %s\n' "$(jq -r '.next_command // "none"' "$summary_json")"
  printf -- '- Next command reason: %s\n' "$(jq -r '.next_command_reason // "none"' "$summary_json")"
  printf '\n'
  printf '## Stage: Stability Cycle\n\n'
  printf -- '- Attempted: %s\n' "$(jq -r '.stages.stability_cycle.attempted | tostring' "$summary_json")"
  printf -- '- Status: %s\n' "$(jq -r '.stages.stability_cycle.status' "$summary_json")"
  printf -- '- RC: %s\n' "$(jq -r '.stages.stability_cycle.rc' "$summary_json")"
  printf -- '- Summary usable: %s\n' "$(jq -r '.stages.stability_cycle.summary.usable | tostring' "$summary_json")"
  printf -- '- Summary fresh: %s\n' "$(jq -r '.stages.stability_cycle.summary.summary_written_fresh | tostring' "$summary_json")"
  printf -- '- Summary stale signal: %s\n' "$(jq -r '.stages.stability_cycle.summary.summary_signals_stale | tostring' "$summary_json")"
  printf -- '- Log: %s\n' "$(jq -r '.stages.stability_cycle.log' "$summary_json")"
  printf '\n'
  printf '## Stage: Promotion Cycle\n\n'
  printf -- '- Attempted: %s\n' "$(jq -r '.stages.promotion_cycle.attempted | tostring' "$summary_json")"
  printf -- '- Status: %s\n' "$(jq -r '.stages.promotion_cycle.status' "$summary_json")"
  printf -- '- RC: %s\n' "$(jq -r '.stages.promotion_cycle.rc' "$summary_json")"
  printf -- '- Summary usable: %s\n' "$(jq -r '.stages.promotion_cycle.summary.usable // false | tostring' "$summary_json")"
  printf -- '- Log: %s\n' "$(jq -r '.stages.promotion_cycle.log // "none"' "$summary_json")"
  printf '\n'
  printf '## Stage: Promotion Evidence-Pack Publish\n\n'
  printf -- '- Attempted: %s\n' "$(jq -r '.stages.promotion_evidence_pack_publish.attempted | tostring' "$summary_json")"
  printf -- '- Status: %s\n' "$(jq -r '.stages.promotion_evidence_pack_publish.status' "$summary_json")"
  printf -- '- RC: %s\n' "$(jq -r '.stages.promotion_evidence_pack_publish.rc' "$summary_json")"
  printf -- '- Summary usable: %s\n' "$(jq -r '.stages.promotion_evidence_pack_publish.summary.usable // false | tostring' "$summary_json")"
  printf -- '- Log: %s\n' "$(jq -r '.stages.promotion_evidence_pack_publish.log // "none"' "$summary_json")"
} >"$report_md"

echo "[profile-compare-multi-vm-live-evidence-publish-bundle] status=$final_status rc=$final_rc decision=${final_decision:-unset} summary_json=$summary_json report_md=$report_md"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
