#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/runtime_actuation_promotion_live_archive_and_pack.sh \
    [--reports-dir DIR] \
    [--cycles N] \
    [--fail-on-no-go [0|1]] \
    [--archive-root DIR] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [runtime_actuation_promotion_cycle passthrough args...]

Purpose:
  Deterministically run runtime-actuation live archive+pack flow:
    1) runtime_actuation_promotion_cycle.sh
    2) archive runtime-actuation live artifacts
    3) runtime_actuation_promotion_evidence_pack.sh

Fail-closed contract:
  - Missing/invalid/stale cycle summary blocks archive+pack.
  - Missing required archive inputs blocks evidence-pack.
  - Missing/invalid/stale evidence-pack summary blocks publish.
USAGE
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
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

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

is_positive_integer_01() {
  [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

normalize_status_01() {
  local status=""
  status="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$status" in
    pass|ok|success) printf '%s' "pass" ;;
    warn|warning) printf '%s' "warn" ;;
    fail|failed|error) printf '%s' "fail" ;;
    *) printf '%s' "$status" ;;
  esac
}

normalize_decision_01() {
  local decision=""
  decision="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]_-')"
  case "$decision" in
    go) printf '%s' "GO" ;;
    nogo) printf '%s' "NO-GO" ;;
    *) printf '%s' "" ;;
  esac
}

render_command() {
  local rendered=""
  local token=""
  for token in "$@"; do
    if [[ -n "$rendered" ]]; then
      rendered+=" "
    fi
    rendered+="$(printf '%q' "$token")"
  done
  printf '%s' "$rendered"
}

json_file_valid_01() {
  local path="$1"
  if [[ -f "$path" ]] && jq -e 'type == "object"' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

file_fingerprint_01() {
  local path="$1"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '%s' ""
    return
  fi
  cksum "$path" 2>/dev/null | awk '{print $1 ":" $2}' || true
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

text_has_placeholder_or_redacted_01() {
  local value=""
  local normalized=""
  value="$(trim "${1:-}")"
  value="$(strip_optional_wrapping_quotes_01 "$value")"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    return 1
  fi
  normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  if [[ "$normalized" == *"REPLACE_WITH_"* || "$normalized" == *"[REDACTED]"* || "$normalized" == *"<SET-REAL-INVITE-KEY>"* ]]; then
    return 0
  fi
  if [[ "$normalized" =~ (^|[^A-Z0-9_])(INVITE_KEY|CAMPAIGN_SUBJECT|REDACTED)([^A-Z0-9_]|$) ]]; then
    return 0
  fi
  if [[ "$normalized" =~ \$\{?(INVITE_KEY|CAMPAIGN_SUBJECT)(:[-?][^}]*)?\}? ]]; then
    return 0
  fi
  if [[ "$normalized" =~ %(INVITE_KEY|CAMPAIGN_SUBJECT)% ]]; then
    return 0
  fi
  if [[ "$normalized" =~ \{\{[[:space:]]*(INVITE_KEY|CAMPAIGN_SUBJECT)[[:space:]]*\}\} ]]; then
    return 0
  fi
  return 1
}

sanitize_guidance_text_01() {
  local text=""
  text="$(trim "${1:-}")"
  text="$(strip_optional_wrapping_quotes_01 "$text")"
  text="$(trim "$text")"
  if [[ -z "$text" ]]; then
    printf '%s' ""
    return
  fi
  if text_has_placeholder_or_redacted_01 "$text"; then
    printf '%s' ""
    return
  fi
  printf '%s' "$text"
}

action_command_is_safe_01() {
  local cmd=""
  cmd="$(trim "${1:-}")"
  cmd="$(strip_optional_wrapping_quotes_01 "$cmd")"
  cmd="$(trim "$cmd")"
  if [[ -z "$cmd" ]]; then
    return 1
  fi
  if text_has_placeholder_or_redacted_01 "$cmd"; then
    return 1
  fi
  if [[ "$cmd" == *$'\n'* || "$cmd" == *$'\r'* ]]; then
    return 1
  fi
  case "$cmd" in
    ./*|bash\ ./*|sudo\ ./*)
      ;;
    *)
      return 1
      ;;
  esac
  if [[ "$cmd" == *";"* || "$cmd" == *"&&"* || "$cmd" == *"||"* || "$cmd" == *"|"* || "$cmd" == *$'`'* || "$cmd" == *'$('* ]]; then
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

need_cmd jq
need_cmd date
need_cmd cksum
need_cmd cp
need_cmd mkdir

reports_dir="${RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
cycles="${RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_CYCLES:-3}"
fail_on_no_go="${RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_FAIL_ON_NO_GO:-1}"
archive_root="${RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_ARCHIVE_ROOT:-}"
summary_json="${RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_SUMMARY_JSON:-}"
print_summary_json="${RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_PRINT_SUMMARY_JSON:-0}"

declare -a cycle_passthrough_args=()

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
    --archive-root)
      require_value_or_die "$1" "$#"
      archive_root="${2:-}"
      shift 2
      ;;
    --archive-root=*)
      archive_root="${1#*=}"
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
    --)
      shift
      while [[ $# -gt 0 ]]; do
        cycle_passthrough_args+=("$1")
        shift
      done
      ;;
    *)
      cycle_passthrough_args+=("$1")
      shift
      ;;
  esac
done

reports_dir="$(abs_path "$reports_dir")"
archive_root="$(abs_path "$archive_root")"
summary_json="$(abs_path "$summary_json")"
cycles="$(trim "$cycles")"
fail_on_no_go="$(trim "$fail_on_no_go")"
print_summary_json="$(trim "$print_summary_json")"

if ! is_positive_integer_01 "$cycles"; then
  echo "--cycles must be a positive integer"
  exit 2
fi
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

if [[ -z "$archive_root" ]]; then
  archive_root="$reports_dir/runtime_actuation_live_archive"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/runtime_actuation_promotion_live_archive_and_pack_summary.json"
fi
report_md="$reports_dir/runtime_actuation_promotion_live_archive_and_pack_report.md"

runtime_cycle_script="${RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT:-$ROOT_DIR/scripts/runtime_actuation_promotion_cycle.sh}"
runtime_evidence_pack_script="${RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT:-$ROOT_DIR/scripts/runtime_actuation_promotion_evidence_pack.sh}"
runtime_cycle_script="$(abs_path "$runtime_cycle_script")"
runtime_evidence_pack_script="$(abs_path "$runtime_evidence_pack_script")"

if [[ ! -f "$runtime_cycle_script" ]]; then
  echo "missing runtime-actuation promotion cycle script: $runtime_cycle_script"
  exit 2
fi
if [[ ! -f "$runtime_evidence_pack_script" ]]; then
  echo "missing runtime-actuation promotion evidence-pack script: $runtime_evidence_pack_script"
  exit 2
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
runtime_cycle_summary_json="$reports_dir/runtime_actuation_promotion_cycle_latest_summary.json"
runtime_cycle_log="$reports_dir/runtime_actuation_promotion_live_archive_and_pack_${run_stamp}_runtime_cycle.log"
archive_log="$reports_dir/runtime_actuation_promotion_live_archive_and_pack_${run_stamp}_archive.log"
archive_dir="$archive_root/runtime_actuation_live_archive_${run_stamp}"
archive_manifest_json="$archive_dir/runtime_actuation_live_archive_manifest.json"
runtime_evidence_pack_summary_json="$reports_dir/runtime_actuation_promotion_evidence_pack_summary.json"
runtime_evidence_pack_report_md="$reports_dir/runtime_actuation_promotion_evidence_pack_report.md"
runtime_evidence_pack_log="$reports_dir/runtime_actuation_promotion_live_archive_and_pack_${run_stamp}_runtime_evidence_pack.log"

mkdir -p "$reports_dir" "$archive_root" "$(dirname "$summary_json")" "$(dirname "$report_md")"

declare -a runtime_cycle_cmd=(
  "$runtime_cycle_script"
  "--reports-dir" "$reports_dir"
  "--cycles" "$cycles"
  "--fail-on-no-go" "$fail_on_no_go"
  "--summary-json" "$runtime_cycle_summary_json"
  "--print-summary-json" "0"
)
if ((${#cycle_passthrough_args[@]} > 0)); then
  runtime_cycle_cmd+=("${cycle_passthrough_args[@]}")
fi
runtime_cycle_command_rendered="$(render_command "${runtime_cycle_cmd[@]}")"

declare -a runtime_evidence_pack_cmd=(
  "$runtime_evidence_pack_script"
  "--reports-dir" "$reports_dir"
  "--promotion-cycle-summary-json" "$runtime_cycle_summary_json"
  "--fail-on-no-go" "$fail_on_no_go"
  "--summary-json" "$runtime_evidence_pack_summary_json"
  "--report-md" "$runtime_evidence_pack_report_md"
  "--print-summary-json" "0"
  "--print-report" "0"
)
runtime_evidence_pack_command_rendered="$(render_command "${runtime_evidence_pack_cmd[@]}")"

cycle_rerun_command="$(render_command \
  "./scripts/easy_node.sh" \
  "runtime-actuation-promotion-cycle" \
  "--reports-dir" "$reports_dir" \
  "--cycles" "$cycles" \
  "--fail-on-no-go" "$fail_on_no_go" \
  "--summary-json" "$runtime_cycle_summary_json" \
  "--print-summary-json" "1"
)"

bundle_rerun_command="$(render_command \
  "./scripts/runtime_actuation_promotion_live_archive_and_pack.sh" \
  "--reports-dir" "$reports_dir" \
  "--cycles" "$cycles" \
  "--fail-on-no-go" "$fail_on_no_go" \
  "--archive-root" "$archive_root" \
  "--summary-json" "$summary_json" \
  "--print-summary-json" "1"
)"

runtime_cycle_stage_status="skipped"
runtime_cycle_runner_rc=0
runtime_cycle_summary_exists="false"
runtime_cycle_summary_valid_json="false"
runtime_cycle_summary_schema_id=""
runtime_cycle_summary_status=""
runtime_cycle_summary_status_normalized=""
runtime_cycle_summary_rc=""
runtime_cycle_summary_decision=""
runtime_cycle_summary_decision_normalized=""
runtime_cycle_summary_contract_valid="false"
runtime_cycle_summary_contract_failure_reason=""
runtime_cycle_summary_pre_fingerprint=""
runtime_cycle_summary_post_fingerprint=""
runtime_cycle_summary_fresh="false"
runtime_cycle_summary_usable_for_archive="false"
runtime_cycle_publish_ready="false"
runtime_cycle_publish_blocked="false"
runtime_cycle_publish_blocked_reason=""
runtime_cycle_summary_promotion_summary_json=""
runtime_cycle_summary_signoff_summary_list_json=""
cycle_failure_substep=""
cycle_failure_reason=""

archive_attempted="false"
archive_status="skipped"
archive_skip_reason=""
archive_rc_num=0
archive_candidate_total=0
archive_copied_total=0
archive_missing_total=0
archive_copy_error_total=0
archive_required_missing_total=0
archive_signoff_summary_total=0
archive_contract_valid="false"
archive_failure_substep=""
archive_failure_reason=""
archive_required_cycle_summary_exists="false"
archive_required_cycle_summary_copied="false"
archive_required_promotion_summary_exists="false"
archive_required_promotion_summary_copied="false"
archive_required_signoff_list_exists="false"
archive_required_signoff_list_copied="false"
archive_cycle_summary_copied_path=""
archive_promotion_summary_copied_path=""
archive_signoff_list_copied_path=""

runtime_evidence_pack_stage_status="skipped"
runtime_evidence_pack_skip_reason=""
runtime_evidence_pack_runner_rc=0
runtime_evidence_pack_summary_exists="false"
runtime_evidence_pack_summary_valid_json="false"
runtime_evidence_pack_summary_schema_id=""
runtime_evidence_pack_summary_status=""
runtime_evidence_pack_summary_status_normalized=""
runtime_evidence_pack_summary_rc=""
runtime_evidence_pack_summary_decision=""
runtime_evidence_pack_summary_decision_normalized=""
runtime_evidence_pack_summary_contract_valid="false"
runtime_evidence_pack_summary_contract_failure_reason=""
runtime_evidence_pack_publish_ready="false"
runtime_evidence_pack_summary_pre_fingerprint=""
runtime_evidence_pack_summary_post_fingerprint=""
runtime_evidence_pack_summary_fresh="false"
runtime_evidence_pack_source_next_command=""
runtime_evidence_pack_source_next_command_reason=""
runtime_evidence_pack_source_next_operator_action=""
runtime_evidence_pack_failure_substep=""
runtime_evidence_pack_failure_reason=""
runtime_evidence_pack_diagnostic_substep=""
runtime_evidence_pack_diagnostic_reason=""

echo "[runtime-actuation-promotion-live-archive-and-pack] stage=runtime_actuation_promotion_cycle status=running cycles=$cycles fail_on_no_go=$fail_on_no_go log=$runtime_cycle_log"
runtime_cycle_summary_pre_fingerprint="$(file_fingerprint_01 "$runtime_cycle_summary_json")"
set +e
"${runtime_cycle_cmd[@]}" >"$runtime_cycle_log" 2>&1
runtime_cycle_runner_rc=$?
set -e

if [[ "$runtime_cycle_runner_rc" -eq 0 ]]; then
  runtime_cycle_stage_status="pass"
else
  runtime_cycle_stage_status="fail"
fi

if [[ -f "$runtime_cycle_summary_json" ]]; then
  runtime_cycle_summary_exists="true"
fi
if [[ "$(json_file_valid_01 "$runtime_cycle_summary_json")" == "1" ]]; then
  runtime_cycle_summary_valid_json="true"
  runtime_cycle_summary_post_fingerprint="$(file_fingerprint_01 "$runtime_cycle_summary_json")"
  if [[ -z "$runtime_cycle_summary_pre_fingerprint" && -n "$runtime_cycle_summary_post_fingerprint" ]]; then
    runtime_cycle_summary_fresh="true"
  elif [[ -n "$runtime_cycle_summary_post_fingerprint" && "$runtime_cycle_summary_post_fingerprint" != "$runtime_cycle_summary_pre_fingerprint" ]]; then
    runtime_cycle_summary_fresh="true"
  fi

  runtime_cycle_summary_schema_id="$(jq -r 'if (.schema.id | type) == "string" then .schema.id else "" end' "$runtime_cycle_summary_json" 2>/dev/null || printf '%s' "")"
  runtime_cycle_summary_status="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$runtime_cycle_summary_json" 2>/dev/null || printf '%s' "")"
  runtime_cycle_summary_status_normalized="$(normalize_status_01 "$runtime_cycle_summary_status")"
  runtime_cycle_summary_rc="$(jq -r 'if (.rc | type) == "number" then (.rc | tostring) else "" end' "$runtime_cycle_summary_json" 2>/dev/null || printf '%s' "")"
  runtime_cycle_summary_decision="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$runtime_cycle_summary_json" 2>/dev/null || printf '%s' "")"
  runtime_cycle_summary_decision_normalized="$(normalize_decision_01 "$runtime_cycle_summary_decision")"
  runtime_cycle_summary_promotion_summary_json="$(jq -r 'if (.artifacts.promotion_summary_json | type) == "string" then .artifacts.promotion_summary_json else "" end' "$runtime_cycle_summary_json" 2>/dev/null || printf '%s' "")"
  runtime_cycle_summary_signoff_summary_list_json="$(jq -r 'if (.artifacts.signoff_summary_list | type) == "string" then .artifacts.signoff_summary_list else "" end' "$runtime_cycle_summary_json" 2>/dev/null || printf '%s' "")"

  if [[ "$runtime_cycle_summary_schema_id" != "runtime_actuation_promotion_cycle_summary" ]]; then
    runtime_cycle_summary_contract_valid="false"
    runtime_cycle_summary_contract_failure_reason="unexpected cycle summary schema id"
  elif [[ -z "$runtime_cycle_summary_rc" ]]; then
    runtime_cycle_summary_contract_valid="false"
    runtime_cycle_summary_contract_failure_reason="cycle summary rc is missing"
  elif [[ "$runtime_cycle_summary_status_normalized" != "pass" && "$runtime_cycle_summary_status_normalized" != "warn" && "$runtime_cycle_summary_status_normalized" != "fail" ]]; then
    runtime_cycle_summary_contract_valid="false"
    runtime_cycle_summary_contract_failure_reason="cycle summary status is invalid"
  elif [[ "$runtime_cycle_summary_decision_normalized" != "GO" && "$runtime_cycle_summary_decision_normalized" != "NO-GO" ]]; then
    runtime_cycle_summary_contract_valid="false"
    runtime_cycle_summary_contract_failure_reason="cycle summary decision is invalid"
  elif [[ "$runtime_cycle_summary_rc" == "0" && "$runtime_cycle_summary_status_normalized" != "pass" && "$runtime_cycle_summary_status_normalized" != "warn" ]]; then
    runtime_cycle_summary_contract_valid="false"
    runtime_cycle_summary_contract_failure_reason="cycle summary contract mismatch: rc=0 requires status pass or warn"
  elif [[ "$runtime_cycle_summary_rc" != "0" && "$runtime_cycle_summary_status_normalized" != "fail" ]]; then
    runtime_cycle_summary_contract_valid="false"
    runtime_cycle_summary_contract_failure_reason="cycle summary contract mismatch: rc!=0 requires status fail"
  else
    runtime_cycle_summary_contract_valid="true"
    runtime_cycle_summary_contract_failure_reason=""
  fi
fi

if [[ "$runtime_cycle_summary_contract_valid" == "true" \
   && "$runtime_cycle_summary_rc" == "0" \
   && "$runtime_cycle_summary_status_normalized" == "pass" \
   && "$runtime_cycle_summary_decision_normalized" == "GO" ]]; then
  runtime_cycle_publish_ready="true"
fi

if [[ "$runtime_cycle_summary_exists" == "true" \
   && "$runtime_cycle_summary_valid_json" == "true" \
   && "$runtime_cycle_summary_fresh" == "true" \
   && "$runtime_cycle_summary_contract_valid" == "true" ]]; then
  runtime_cycle_summary_usable_for_archive="true"
fi

if [[ "$runtime_cycle_summary_exists" != "true" || "$runtime_cycle_summary_valid_json" != "true" ]]; then
  runtime_cycle_stage_status="fail"
  cycle_failure_substep="runtime_actuation_promotion_cycle_summary_missing_or_invalid"
  cycle_failure_reason="runtime-actuation promotion cycle summary is missing or invalid JSON"
elif [[ "$runtime_cycle_summary_fresh" != "true" ]]; then
  runtime_cycle_stage_status="fail"
  cycle_failure_substep="runtime_actuation_promotion_cycle_summary_stale_reused"
  cycle_failure_reason="runtime-actuation promotion cycle summary was reused from a previous run (missing fresh write)"
elif [[ "$runtime_cycle_summary_contract_valid" != "true" ]]; then
  runtime_cycle_stage_status="fail"
  cycle_failure_substep="runtime_actuation_promotion_cycle_summary_contract_invalid"
  if [[ -n "$runtime_cycle_summary_contract_failure_reason" ]]; then
    cycle_failure_reason="$runtime_cycle_summary_contract_failure_reason"
  else
    cycle_failure_reason="runtime-actuation promotion cycle summary contract is invalid"
  fi
fi

if [[ "$runtime_cycle_summary_usable_for_archive" == "true" && "$runtime_cycle_publish_ready" != "true" ]]; then
  runtime_cycle_publish_blocked="true"
  runtime_cycle_publish_blocked_reason="runtime-actuation promotion cycle summary is not publish-ready (requires status=pass rc=0 decision=GO)"
  if [[ -z "$cycle_failure_substep" ]]; then
    runtime_cycle_stage_status="warn"
  fi
fi

if [[ -z "$cycle_failure_substep" && "$runtime_cycle_runner_rc" -ne 0 && "$runtime_cycle_publish_blocked" != "true" ]]; then
  runtime_cycle_stage_status="fail"
  cycle_failure_substep="runtime_actuation_promotion_cycle_runner_nonzero"
  cycle_failure_reason="runtime-actuation promotion cycle command failed (rc=$runtime_cycle_runner_rc)"
fi

echo "[runtime-actuation-promotion-live-archive-and-pack] stage=runtime_actuation_promotion_cycle status=$runtime_cycle_stage_status rc=$runtime_cycle_runner_rc summary_json=$runtime_cycle_summary_json contract_valid=$runtime_cycle_summary_contract_valid publish_ready=$runtime_cycle_publish_ready summary_usable_for_archive=$runtime_cycle_summary_usable_for_archive"

if [[ "$runtime_cycle_summary_usable_for_archive" == "true" ]]; then
  archive_attempted="true"
  archive_status="pass"
  archive_rc_num=0
  mkdir -p "$archive_dir/cycle/signoff_summaries"
  : >"$archive_log"

  cycle_source="$runtime_cycle_summary_json"
  promotion_source="$(trim "$runtime_cycle_summary_promotion_summary_json")"
  signoff_list_source="$(trim "$runtime_cycle_summary_signoff_summary_list_json")"

  required_cycle_dest="$archive_dir/cycle/runtime_actuation_promotion_cycle_latest_summary.json"
  required_promotion_dest="$archive_dir/cycle/runtime_actuation_promotion_cycle_latest_promotion_check_summary.json"
  required_signoff_list_dest="$archive_dir/cycle/runtime_actuation_promotion_cycle_latest_signoff_summaries.list"

  archive_candidate_total=$((archive_candidate_total + 1))
  if [[ -n "$cycle_source" && -f "$cycle_source" ]]; then
    archive_required_cycle_summary_exists="true"
    if cp -f "$cycle_source" "$required_cycle_dest" >>"$archive_log" 2>&1; then
      archive_required_cycle_summary_copied="true"
      archive_cycle_summary_copied_path="$required_cycle_dest"
      archive_copied_total=$((archive_copied_total + 1))
    else
      archive_copy_error_total=$((archive_copy_error_total + 1))
      archive_failure_reason="failed to copy required cycle summary to archive"
    fi
  else
    archive_missing_total=$((archive_missing_total + 1))
    archive_required_missing_total=$((archive_required_missing_total + 1))
  fi

  archive_candidate_total=$((archive_candidate_total + 1))
  if [[ -n "$promotion_source" && -f "$promotion_source" ]]; then
    archive_required_promotion_summary_exists="true"
    if cp -f "$promotion_source" "$required_promotion_dest" >>"$archive_log" 2>&1; then
      archive_required_promotion_summary_copied="true"
      archive_promotion_summary_copied_path="$required_promotion_dest"
      archive_copied_total=$((archive_copied_total + 1))
    else
      archive_copy_error_total=$((archive_copy_error_total + 1))
      archive_failure_reason="failed to copy required promotion summary to archive"
    fi
  else
    archive_missing_total=$((archive_missing_total + 1))
    archive_required_missing_total=$((archive_required_missing_total + 1))
  fi

  archive_candidate_total=$((archive_candidate_total + 1))
  if [[ -n "$signoff_list_source" && -f "$signoff_list_source" ]]; then
    archive_required_signoff_list_exists="true"
    if cp -f "$signoff_list_source" "$required_signoff_list_dest" >>"$archive_log" 2>&1; then
      archive_required_signoff_list_copied="true"
      archive_signoff_list_copied_path="$required_signoff_list_dest"
      archive_copied_total=$((archive_copied_total + 1))
    else
      archive_copy_error_total=$((archive_copy_error_total + 1))
      archive_failure_reason="failed to copy required signoff summary list to archive"
    fi
  else
    archive_missing_total=$((archive_missing_total + 1))
    archive_required_missing_total=$((archive_required_missing_total + 1))
  fi

  if [[ -n "$signoff_list_source" && -f "$signoff_list_source" ]]; then
    while IFS= read -r signoff_summary_path || [[ -n "$signoff_summary_path" ]]; do
      signoff_summary_path="$(trim "$signoff_summary_path")"
      if [[ -z "$signoff_summary_path" || "${signoff_summary_path:0:1}" == "#" ]]; then
        continue
      fi
      archive_signoff_summary_total=$((archive_signoff_summary_total + 1))
      archive_candidate_total=$((archive_candidate_total + 1))

      if [[ ! -f "$signoff_summary_path" ]]; then
        archive_missing_total=$((archive_missing_total + 1))
        continue
      fi

      signoff_dest="$archive_dir/cycle/signoff_summaries/$(printf '%03d_%s' "$archive_signoff_summary_total" "$(basename "$signoff_summary_path")")"
      if cp -f "$signoff_summary_path" "$signoff_dest" >>"$archive_log" 2>&1; then
        archive_copied_total=$((archive_copied_total + 1))
      else
        archive_copy_error_total=$((archive_copy_error_total + 1))
      fi
    done <"$signoff_list_source"
  fi

  if (( archive_required_missing_total > 0 )); then
    archive_status="fail"
    archive_rc_num=3
    archive_failure_substep="runtime_actuation_live_evidence_archive_required_artifacts_missing"
    archive_failure_reason="required runtime-actuation archive inputs are missing"
  elif (( archive_copy_error_total > 0 )); then
    archive_status="fail"
    archive_rc_num=4
    archive_failure_substep="runtime_actuation_live_evidence_archive_copy_error"
    if [[ -n "$archive_failure_reason" ]]; then
      :
    else
      archive_failure_reason="runtime-actuation live archive copy errors were detected"
    fi
  else
    archive_status="pass"
    archive_rc_num=0
  fi

  jq -n \
    --arg generated_at_utc "$(timestamp_utc)" \
    --arg status "$archive_status" \
    --arg archive_root "$archive_root" \
    --arg archive_dir "$archive_dir" \
    --arg cycle_source "$cycle_source" \
    --arg promotion_source "$promotion_source" \
    --arg signoff_list_source "$signoff_list_source" \
    --arg cycle_copied_path "$archive_cycle_summary_copied_path" \
    --arg promotion_copied_path "$archive_promotion_summary_copied_path" \
    --arg signoff_list_copied_path "$archive_signoff_list_copied_path" \
    --arg failure_substep "$archive_failure_substep" \
    --arg failure_reason "$archive_failure_reason" \
    --argjson rc "$archive_rc_num" \
    --argjson candidate_total "$archive_candidate_total" \
    --argjson copied_total "$archive_copied_total" \
    --argjson missing_total "$archive_missing_total" \
    --argjson copy_error_total "$archive_copy_error_total" \
    --argjson required_missing_total "$archive_required_missing_total" \
    --argjson signoff_summary_total "$archive_signoff_summary_total" \
    --argjson required_cycle_exists "$archive_required_cycle_summary_exists" \
    --argjson required_cycle_copied "$archive_required_cycle_summary_copied" \
    --argjson required_promotion_exists "$archive_required_promotion_summary_exists" \
    --argjson required_promotion_copied "$archive_required_promotion_summary_copied" \
    --argjson required_signoff_list_exists "$archive_required_signoff_list_exists" \
    --argjson required_signoff_list_copied "$archive_required_signoff_list_copied" \
    '{
      version: 1,
      schema: { id: "runtime_actuation_live_archive_manifest" },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      failure_substep: (if $failure_substep == "" then null else $failure_substep end),
      failure_reason: (if $failure_reason == "" then null else $failure_reason end),
      archive_root: $archive_root,
      archive_dir: $archive_dir,
      required_sources: {
        cycle_summary_json: {
          source: (if $cycle_source == "" then null else $cycle_source end),
          exists: $required_cycle_exists,
          copied: $required_cycle_copied,
          copied_path: (if $cycle_copied_path == "" then null else $cycle_copied_path end)
        },
        promotion_check_summary_json: {
          source: (if $promotion_source == "" then null else $promotion_source end),
          exists: $required_promotion_exists,
          copied: $required_promotion_copied,
          copied_path: (if $promotion_copied_path == "" then null else $promotion_copied_path end)
        },
        signoff_summary_list: {
          source: (if $signoff_list_source == "" then null else $signoff_list_source end),
          exists: $required_signoff_list_exists,
          copied: $required_signoff_list_copied,
          copied_path: (if $signoff_list_copied_path == "" then null else $signoff_list_copied_path end)
        }
      },
      counts: {
        candidate_total: $candidate_total,
        copied_total: $copied_total,
        missing_total: $missing_total,
        copy_error_total: $copy_error_total,
        required_missing_total: $required_missing_total,
        signoff_summary_total: $signoff_summary_total
      }
    }' >"$archive_manifest_json"

  if [[ ! -f "$archive_manifest_json" ]]; then
    archive_status="fail"
    archive_rc_num=5
    archive_failure_substep="runtime_actuation_live_evidence_archive_manifest_missing"
    archive_failure_reason="runtime-actuation live archive manifest was not written"
  fi
  if [[ "$archive_status" != "pass" && -z "$archive_failure_substep" ]]; then
    archive_failure_substep="runtime_actuation_live_evidence_archive_failed"
    archive_failure_reason="runtime-actuation live archive stage failed"
  fi
  if [[ "$archive_status" == "pass" || "$archive_status" == "fail" ]]; then
    archive_contract_valid="true"
  fi
  echo "[runtime-actuation-promotion-live-archive-and-pack] stage=live_evidence_archive status=$archive_status rc=$archive_rc_num archive_dir=$archive_dir manifest_json=$archive_manifest_json candidate_total=$archive_candidate_total copied_total=$archive_copied_total missing_total=$archive_missing_total copy_error_total=$archive_copy_error_total required_missing_total=$archive_required_missing_total"
else
  archive_status="skipped"
  archive_skip_reason="cycle_summary_unusable_for_archive"
  echo "[runtime-actuation-promotion-live-archive-and-pack] stage=live_evidence_archive status=skipped reason=$archive_skip_reason"
fi

if [[ "$runtime_cycle_summary_usable_for_archive" == "true" && "$archive_status" == "pass" ]]; then
  echo "[runtime-actuation-promotion-live-archive-and-pack] stage=runtime_actuation_promotion_evidence_pack status=running fail_on_no_go=$fail_on_no_go log=$runtime_evidence_pack_log"
  runtime_evidence_pack_summary_pre_fingerprint="$(file_fingerprint_01 "$runtime_evidence_pack_summary_json")"
  set +e
  "${runtime_evidence_pack_cmd[@]}" >"$runtime_evidence_pack_log" 2>&1
  runtime_evidence_pack_runner_rc=$?
  set -e

  if [[ -f "$runtime_evidence_pack_summary_json" ]]; then
    runtime_evidence_pack_summary_exists="true"
  fi
  if [[ "$(json_file_valid_01 "$runtime_evidence_pack_summary_json")" == "1" ]]; then
    runtime_evidence_pack_summary_valid_json="true"
    runtime_evidence_pack_summary_post_fingerprint="$(file_fingerprint_01 "$runtime_evidence_pack_summary_json")"
    if [[ -z "$runtime_evidence_pack_summary_pre_fingerprint" && -n "$runtime_evidence_pack_summary_post_fingerprint" ]]; then
      runtime_evidence_pack_summary_fresh="true"
    elif [[ -n "$runtime_evidence_pack_summary_post_fingerprint" && "$runtime_evidence_pack_summary_post_fingerprint" != "$runtime_evidence_pack_summary_pre_fingerprint" ]]; then
      runtime_evidence_pack_summary_fresh="true"
    fi

    runtime_evidence_pack_summary_schema_id="$(jq -r 'if (.schema.id | type) == "string" then .schema.id else "" end' "$runtime_evidence_pack_summary_json" 2>/dev/null || printf '%s' "")"
    runtime_evidence_pack_summary_status="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$runtime_evidence_pack_summary_json" 2>/dev/null || printf '%s' "")"
    runtime_evidence_pack_summary_status_normalized="$(normalize_status_01 "$runtime_evidence_pack_summary_status")"
    runtime_evidence_pack_summary_rc="$(jq -r 'if (.rc | type) == "number" then (.rc | tostring) else "" end' "$runtime_evidence_pack_summary_json" 2>/dev/null || printf '%s' "")"
    runtime_evidence_pack_summary_decision="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$runtime_evidence_pack_summary_json" 2>/dev/null || printf '%s' "")"
    runtime_evidence_pack_summary_decision_normalized="$(normalize_decision_01 "$runtime_evidence_pack_summary_decision")"
    runtime_evidence_pack_source_next_command="$(jq -r 'if (.next_command | type) == "string" then .next_command else "" end' "$runtime_evidence_pack_summary_json" 2>/dev/null || printf '%s' "")"
    runtime_evidence_pack_source_next_command_reason="$(jq -r 'if (.next_command_reason | type) == "string" then .next_command_reason else "" end' "$runtime_evidence_pack_summary_json" 2>/dev/null || printf '%s' "")"
    runtime_evidence_pack_source_next_operator_action="$(jq -r 'if (.next_operator_action | type) == "string" then .next_operator_action else "" end' "$runtime_evidence_pack_summary_json" 2>/dev/null || printf '%s' "")"

    if [[ "$runtime_evidence_pack_summary_schema_id" != "runtime_actuation_promotion_evidence_pack_summary" ]]; then
      runtime_evidence_pack_summary_contract_valid="false"
      runtime_evidence_pack_summary_contract_failure_reason="unexpected evidence-pack summary schema id"
    elif [[ -z "$runtime_evidence_pack_summary_rc" ]]; then
      runtime_evidence_pack_summary_contract_valid="false"
      runtime_evidence_pack_summary_contract_failure_reason="evidence-pack summary rc is missing"
    elif [[ "$runtime_evidence_pack_summary_status_normalized" != "pass" && "$runtime_evidence_pack_summary_status_normalized" != "warn" && "$runtime_evidence_pack_summary_status_normalized" != "fail" ]]; then
      runtime_evidence_pack_summary_contract_valid="false"
      runtime_evidence_pack_summary_contract_failure_reason="evidence-pack summary status is invalid"
    elif [[ "$runtime_evidence_pack_summary_decision_normalized" != "GO" && "$runtime_evidence_pack_summary_decision_normalized" != "NO-GO" ]]; then
      runtime_evidence_pack_summary_contract_valid="false"
      runtime_evidence_pack_summary_contract_failure_reason="evidence-pack summary decision is invalid"
    elif [[ "$runtime_evidence_pack_summary_rc" == "0" && "$runtime_evidence_pack_summary_status_normalized" != "pass" && "$runtime_evidence_pack_summary_status_normalized" != "warn" ]]; then
      runtime_evidence_pack_summary_contract_valid="false"
      runtime_evidence_pack_summary_contract_failure_reason="evidence-pack summary contract mismatch: rc=0 requires status pass or warn"
    elif [[ "$runtime_evidence_pack_summary_rc" != "0" && "$runtime_evidence_pack_summary_status_normalized" != "fail" ]]; then
      runtime_evidence_pack_summary_contract_valid="false"
      runtime_evidence_pack_summary_contract_failure_reason="evidence-pack summary contract mismatch: rc!=0 requires status fail"
    elif [[ "$runtime_evidence_pack_runner_rc" -ne 0 && "$runtime_evidence_pack_summary_rc" == "0" ]]; then
      runtime_evidence_pack_summary_contract_valid="false"
      runtime_evidence_pack_summary_contract_failure_reason="evidence-pack process rc and summary rc mismatch (process non-zero, summary rc=0)"
    else
      runtime_evidence_pack_summary_contract_valid="true"
      runtime_evidence_pack_summary_contract_failure_reason=""
    fi
  fi

  if [[ "$runtime_evidence_pack_summary_contract_valid" == "true" \
     && "$runtime_evidence_pack_summary_rc" == "0" \
     && "$runtime_evidence_pack_summary_status_normalized" == "pass" \
     && "$runtime_evidence_pack_summary_decision_normalized" == "GO" ]]; then
    runtime_evidence_pack_publish_ready="true"
  fi

  if [[ "$runtime_evidence_pack_summary_exists" != "true" || "$runtime_evidence_pack_summary_valid_json" != "true" ]]; then
    runtime_evidence_pack_stage_status="fail"
    runtime_evidence_pack_failure_substep="runtime_actuation_promotion_evidence_pack_summary_missing_or_invalid"
    runtime_evidence_pack_failure_reason="runtime-actuation promotion evidence-pack summary is missing or invalid JSON"
  elif [[ "$runtime_evidence_pack_summary_fresh" != "true" ]]; then
    runtime_evidence_pack_stage_status="fail"
    runtime_evidence_pack_failure_substep="runtime_actuation_promotion_evidence_pack_summary_stale_reused"
    runtime_evidence_pack_failure_reason="runtime-actuation promotion evidence-pack summary was reused from a previous run (missing fresh write)"
  elif [[ "$runtime_evidence_pack_summary_contract_valid" != "true" ]]; then
    runtime_evidence_pack_stage_status="fail"
    runtime_evidence_pack_failure_substep="runtime_actuation_promotion_evidence_pack_summary_contract_invalid"
    if [[ -n "$runtime_evidence_pack_summary_contract_failure_reason" ]]; then
      runtime_evidence_pack_failure_reason="$runtime_evidence_pack_summary_contract_failure_reason"
    else
      runtime_evidence_pack_failure_reason="runtime-actuation promotion evidence-pack summary contract is invalid"
    fi
  elif [[ "$runtime_evidence_pack_runner_rc" -ne 0 ]]; then
    runtime_evidence_pack_stage_status="fail"
    runtime_evidence_pack_failure_substep="runtime_actuation_promotion_evidence_pack_runner_nonzero"
    runtime_evidence_pack_failure_reason="runtime-actuation promotion evidence-pack command failed (rc=$runtime_evidence_pack_runner_rc)"
  elif [[ "$runtime_evidence_pack_publish_ready" != "true" ]]; then
    runtime_evidence_pack_stage_status="fail"
    runtime_evidence_pack_failure_substep="runtime_actuation_promotion_evidence_pack_not_publish_ready"
    runtime_evidence_pack_failure_reason="runtime-actuation promotion evidence-pack summary is not publish-ready (requires status=pass rc=0 decision=GO)"
  else
    runtime_evidence_pack_stage_status="pass"
  fi

  echo "[runtime-actuation-promotion-live-archive-and-pack] stage=runtime_actuation_promotion_evidence_pack status=$runtime_evidence_pack_stage_status rc=$runtime_evidence_pack_runner_rc summary_json=$runtime_evidence_pack_summary_json contract_valid=$runtime_evidence_pack_summary_contract_valid publish_ready=$runtime_evidence_pack_publish_ready"
else
  runtime_evidence_pack_stage_status="skipped"
  if [[ "$runtime_cycle_summary_usable_for_archive" != "true" ]]; then
    runtime_evidence_pack_skip_reason="cycle_summary_unusable_for_archive"
  else
    runtime_evidence_pack_skip_reason="live_evidence_archive_failed"
  fi
  echo "[runtime-actuation-promotion-live-archive-and-pack] stage=runtime_actuation_promotion_evidence_pack status=skipped reason=$runtime_evidence_pack_skip_reason"
fi

sanitized_pack_next_command="$(sanitize_action_command_01 "$runtime_evidence_pack_source_next_command")"
sanitized_pack_next_command_reason="$(sanitize_guidance_text_01 "$runtime_evidence_pack_source_next_command_reason")"
sanitized_pack_next_operator_action="$(sanitize_guidance_text_01 "$runtime_evidence_pack_source_next_operator_action")"

final_status="fail"
final_rc=1
final_failure_substep=""
final_failure_reason=""
next_command=""
next_command_reason=""
next_command_source=""
next_operator_action=""

if [[ -n "$cycle_failure_substep" ]]; then
  final_status="fail"
  final_failure_substep="$cycle_failure_substep"
  final_failure_reason="$cycle_failure_reason"
  if [[ "$runtime_cycle_runner_rc" -gt 0 ]]; then
    final_rc="$runtime_cycle_runner_rc"
  else
    final_rc=1
  fi
  next_command="$cycle_rerun_command"
  next_command_reason="runtime-actuation promotion cycle summary is not usable; rerun cycle to refresh live evidence"
  next_command_source="cycle_rerun_recovery"
elif [[ "$archive_status" == "fail" ]]; then
  final_status="fail"
  if [[ -n "$archive_failure_substep" ]]; then
    final_failure_substep="$archive_failure_substep"
  else
    final_failure_substep="runtime_actuation_live_evidence_archive_failed"
  fi
  if [[ -n "$archive_failure_reason" ]]; then
    final_failure_reason="$archive_failure_reason"
  else
    final_failure_reason="runtime-actuation live archive stage failed"
  fi
  if [[ "$archive_rc_num" -gt 0 ]]; then
    final_rc="$archive_rc_num"
  else
    final_rc=1
  fi
  next_command="$cycle_rerun_command"
  next_command_reason="runtime-actuation live archive failed; rerun cycle to regenerate required archive inputs"
  next_command_source="cycle_rerun_recovery"
elif [[ "$runtime_evidence_pack_stage_status" == "fail" ]]; then
  final_status="fail"
  if [[ "$runtime_cycle_publish_blocked" == "true" ]]; then
    final_failure_substep="runtime_actuation_publish_blocked_cycle_not_publish_ready"
    if [[ -n "$runtime_cycle_publish_blocked_reason" ]]; then
      final_failure_reason="$runtime_cycle_publish_blocked_reason"
    else
      final_failure_reason="runtime-actuation publish flow is blocked because cycle output is not publish-ready"
    fi
    final_rc=3
    runtime_evidence_pack_diagnostic_substep="$runtime_evidence_pack_failure_substep"
    runtime_evidence_pack_diagnostic_reason="$runtime_evidence_pack_failure_reason"
  else
    if [[ -n "$runtime_evidence_pack_failure_substep" ]]; then
      final_failure_substep="$runtime_evidence_pack_failure_substep"
    else
      final_failure_substep="runtime_actuation_promotion_evidence_pack_failed"
    fi
    if [[ -n "$runtime_evidence_pack_failure_reason" ]]; then
      final_failure_reason="$runtime_evidence_pack_failure_reason"
    else
      final_failure_reason="runtime-actuation promotion evidence-pack stage failed"
    fi
    if [[ "$runtime_evidence_pack_runner_rc" -gt 0 ]]; then
      final_rc="$runtime_evidence_pack_runner_rc"
    elif [[ -n "$runtime_evidence_pack_summary_rc" && "$runtime_evidence_pack_summary_rc" != "0" ]]; then
      final_rc="$runtime_evidence_pack_summary_rc"
    else
      final_rc=1
    fi
  fi

  if [[ -n "$sanitized_pack_next_command" ]]; then
    next_command="$sanitized_pack_next_command"
    next_command_source="runtime_evidence_pack_summary_next_command"
  else
    next_command="$cycle_rerun_command"
    next_command_source="cycle_rerun_recovery"
  fi
  if [[ -n "$sanitized_pack_next_command_reason" ]]; then
    next_command_reason="$sanitized_pack_next_command_reason"
  else
    next_command_reason="runtime-actuation promotion evidence-pack is blocked; refresh cycle evidence and rerun archive+pack"
  fi
elif [[ "$runtime_cycle_publish_blocked" == "true" ]]; then
  final_status="fail"
  final_failure_substep="runtime_actuation_publish_blocked_cycle_not_publish_ready"
  if [[ -n "$runtime_cycle_publish_blocked_reason" ]]; then
    final_failure_reason="$runtime_cycle_publish_blocked_reason"
  else
    final_failure_reason="runtime-actuation publish flow is blocked because cycle output is not publish-ready"
  fi
  final_rc=3
  if [[ -n "$sanitized_pack_next_command" ]]; then
    next_command="$sanitized_pack_next_command"
    next_command_source="runtime_evidence_pack_summary_next_command"
  else
    next_command="$cycle_rerun_command"
    next_command_source="cycle_rerun_recovery"
  fi
  if [[ -n "$sanitized_pack_next_command_reason" ]]; then
    next_command_reason="$sanitized_pack_next_command_reason"
  else
    next_command_reason="runtime-actuation promotion cycle is NO-GO; resolve blockers and rerun archive+pack"
  fi
else
  final_status="pass"
  final_rc=0
fi

if [[ "$final_status" == "pass" ]]; then
  next_operator_action="No action required; runtime-actuation live archive+pack flow is healthy."
else
  if [[ -n "$sanitized_pack_next_operator_action" ]]; then
    next_operator_action="$sanitized_pack_next_operator_action"
  elif [[ -n "$next_command_reason" ]]; then
    next_operator_action="$next_command_reason"
  else
    next_operator_action="Investigate runtime-actuation logs and rerun archive+pack with fresh evidence."
  fi
fi

if [[ -n "$next_command" ]] && ! action_command_is_safe_01 "$next_command"; then
  next_command="$bundle_rerun_command"
  next_command_source="bundle_rerun_recovery"
fi
if text_has_placeholder_or_redacted_01 "$next_command_reason"; then
  next_command_reason="rerun with real non-placeholder runtime-actuation inputs and fresh evidence"
fi

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$final_status" \
  --arg failure_substep "$final_failure_substep" \
  --arg failure_reason "$final_failure_reason" \
  --arg next_operator_action "$next_operator_action" \
  --arg next_command "$next_command" \
  --arg next_command_reason "$next_command_reason" \
  --arg next_command_source "$next_command_source" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json_path "$summary_json" \
  --arg report_md_path "$report_md" \
  --arg cycle_script "$runtime_cycle_script" \
  --arg cycle_command "$runtime_cycle_command_rendered" \
  --arg cycle_log "$runtime_cycle_log" \
  --arg cycle_summary_json "$runtime_cycle_summary_json" \
  --arg cycle_summary_schema_id "$runtime_cycle_summary_schema_id" \
  --arg cycle_summary_status "$runtime_cycle_summary_status" \
  --arg cycle_summary_status_normalized "$runtime_cycle_summary_status_normalized" \
  --arg cycle_summary_rc "$runtime_cycle_summary_rc" \
  --arg cycle_summary_decision "$runtime_cycle_summary_decision" \
  --arg cycle_summary_decision_normalized "$runtime_cycle_summary_decision_normalized" \
  --arg cycle_summary_contract_failure_reason "$runtime_cycle_summary_contract_failure_reason" \
  --arg cycle_stage_status "$runtime_cycle_stage_status" \
  --arg archive_root "$archive_root" \
  --arg archive_dir "$archive_dir" \
  --arg archive_manifest_json "$archive_manifest_json" \
  --arg archive_log "$archive_log" \
  --arg archive_skip_reason "$archive_skip_reason" \
  --arg archive_failure_substep "$archive_failure_substep" \
  --arg archive_failure_reason "$archive_failure_reason" \
  --arg evidence_script "$runtime_evidence_pack_script" \
  --arg evidence_command "$runtime_evidence_pack_command_rendered" \
  --arg evidence_log "$runtime_evidence_pack_log" \
  --arg evidence_summary_json "$runtime_evidence_pack_summary_json" \
  --arg evidence_report_md "$runtime_evidence_pack_report_md" \
  --arg evidence_stage_status "$runtime_evidence_pack_stage_status" \
  --arg evidence_skip_reason "$runtime_evidence_pack_skip_reason" \
  --arg evidence_summary_schema_id "$runtime_evidence_pack_summary_schema_id" \
  --arg evidence_summary_status "$runtime_evidence_pack_summary_status" \
  --arg evidence_summary_status_normalized "$runtime_evidence_pack_summary_status_normalized" \
  --arg evidence_summary_rc "$runtime_evidence_pack_summary_rc" \
  --arg evidence_summary_decision "$runtime_evidence_pack_summary_decision" \
  --arg evidence_summary_decision_normalized "$runtime_evidence_pack_summary_decision_normalized" \
  --arg evidence_summary_contract_failure_reason "$runtime_evidence_pack_summary_contract_failure_reason" \
  --arg evidence_failure_substep "$runtime_evidence_pack_failure_substep" \
  --arg evidence_failure_reason "$runtime_evidence_pack_failure_reason" \
  --arg evidence_diagnostic_substep "$runtime_evidence_pack_diagnostic_substep" \
  --arg evidence_diagnostic_reason "$runtime_evidence_pack_diagnostic_reason" \
  --argjson rc "$final_rc" \
  --argjson cycles "$cycles" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --argjson cycle_runner_rc "$runtime_cycle_runner_rc" \
  --argjson cycle_summary_exists "$runtime_cycle_summary_exists" \
  --argjson cycle_summary_valid_json "$runtime_cycle_summary_valid_json" \
  --argjson cycle_summary_fresh "$runtime_cycle_summary_fresh" \
  --argjson cycle_summary_contract_valid "$runtime_cycle_summary_contract_valid" \
  --argjson cycle_summary_usable_for_archive "$runtime_cycle_summary_usable_for_archive" \
  --argjson cycle_publish_ready "$runtime_cycle_publish_ready" \
  --argjson cycle_publish_blocked "$runtime_cycle_publish_blocked" \
  --arg cycle_publish_blocked_reason "$runtime_cycle_publish_blocked_reason" \
  --argjson archive_attempted "$archive_attempted" \
  --arg archive_status "$archive_status" \
  --argjson archive_rc "$archive_rc_num" \
  --argjson archive_candidate_total "$archive_candidate_total" \
  --argjson archive_copied_total "$archive_copied_total" \
  --argjson archive_missing_total "$archive_missing_total" \
  --argjson archive_copy_error_total "$archive_copy_error_total" \
  --argjson archive_required_missing_total "$archive_required_missing_total" \
  --argjson archive_signoff_summary_total "$archive_signoff_summary_total" \
  --argjson archive_contract_valid "$archive_contract_valid" \
  --argjson evidence_runner_rc "$runtime_evidence_pack_runner_rc" \
  --argjson evidence_summary_exists "$runtime_evidence_pack_summary_exists" \
  --argjson evidence_summary_valid_json "$runtime_evidence_pack_summary_valid_json" \
  --argjson evidence_summary_fresh "$runtime_evidence_pack_summary_fresh" \
  --argjson evidence_summary_contract_valid "$runtime_evidence_pack_summary_contract_valid" \
  --argjson evidence_publish_ready "$runtime_evidence_pack_publish_ready" \
  '{
    version: 1,
    schema: {
      id: "runtime_actuation_promotion_live_archive_and_pack_summary"
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    failure_substep: (if $failure_substep == "" then null else $failure_substep end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    next_operator_action: (if $next_operator_action == "" then null else $next_operator_action end),
    next_command: (if $next_command == "" then null else $next_command end),
    next_command_reason: (if $next_command_reason == "" then null else $next_command_reason end),
    next_command_source: (if $next_command_source == "" then null else $next_command_source end),
    inputs: {
      reports_dir: $reports_dir,
      cycles: $cycles,
      fail_on_no_go: ($fail_on_no_go == 1),
      archive_root: $archive_root
    },
    stages: {
      runtime_actuation_promotion_cycle: {
        status: $cycle_stage_status,
        rc: $cycle_runner_rc,
        script: $cycle_script,
        command: $cycle_command,
        log: $cycle_log,
        summary_json: $cycle_summary_json,
        summary_exists: $cycle_summary_exists,
        summary_valid_json: $cycle_summary_valid_json,
        summary_fresh_after_run: $cycle_summary_fresh,
        summary_schema_id: (if $cycle_summary_schema_id == "" then null else $cycle_summary_schema_id end),
        summary_status: (if $cycle_summary_status == "" then null else $cycle_summary_status end),
        summary_status_normalized: (if $cycle_summary_status_normalized == "" then null else $cycle_summary_status_normalized end),
        summary_rc: (if $cycle_summary_rc == "" then null else ($cycle_summary_rc | tonumber) end),
        summary_decision: (if $cycle_summary_decision == "" then null else $cycle_summary_decision end),
        summary_decision_normalized: (if $cycle_summary_decision_normalized == "" then null else $cycle_summary_decision_normalized end),
        summary_contract_valid: $cycle_summary_contract_valid,
        summary_contract_failure_reason: (if $cycle_summary_contract_failure_reason == "" then null else $cycle_summary_contract_failure_reason end),
        summary_usable_for_archive: $cycle_summary_usable_for_archive,
        publish_ready: $cycle_publish_ready,
        publish_blocked: $cycle_publish_blocked,
        publish_blocked_reason: (if $cycle_publish_blocked_reason == "" then null else $cycle_publish_blocked_reason end)
      },
      live_evidence_archive: {
        attempted: $archive_attempted,
        status: $archive_status,
        rc: $archive_rc,
        skip_reason: (if $archive_skip_reason == "" then null else $archive_skip_reason end),
        contract_valid: $archive_contract_valid,
        failure_substep: (if $archive_failure_substep == "" then null else $archive_failure_substep end),
        failure_reason: (if $archive_failure_reason == "" then null else $archive_failure_reason end),
        archive_root: $archive_root,
        archive_dir: (if $archive_dir == "" then null else $archive_dir end),
        archive_manifest_json: (if $archive_manifest_json == "" then null else $archive_manifest_json end),
        log: $archive_log,
        candidate_total: $archive_candidate_total,
        copied_total: $archive_copied_total,
        missing_total: $archive_missing_total,
        copy_error_total: $archive_copy_error_total,
        required_missing_total: $archive_required_missing_total,
        signoff_summary_total: $archive_signoff_summary_total
      },
      runtime_actuation_promotion_evidence_pack: {
        status: $evidence_stage_status,
        rc: $evidence_runner_rc,
        skip_reason: (if $evidence_skip_reason == "" then null else $evidence_skip_reason end),
        script: $evidence_script,
        command: $evidence_command,
        log: $evidence_log,
        summary_json: $evidence_summary_json,
        report_md: $evidence_report_md,
        summary_exists: $evidence_summary_exists,
        summary_valid_json: $evidence_summary_valid_json,
        summary_fresh_after_run: $evidence_summary_fresh,
        summary_schema_id: (if $evidence_summary_schema_id == "" then null else $evidence_summary_schema_id end),
        summary_status: (if $evidence_summary_status == "" then null else $evidence_summary_status end),
        summary_status_normalized: (if $evidence_summary_status_normalized == "" then null else $evidence_summary_status_normalized end),
        summary_rc: (if $evidence_summary_rc == "" then null else ($evidence_summary_rc | tonumber) end),
        summary_decision: (if $evidence_summary_decision == "" then null else $evidence_summary_decision end),
        summary_decision_normalized: (if $evidence_summary_decision_normalized == "" then null else $evidence_summary_decision_normalized end),
        summary_contract_valid: $evidence_summary_contract_valid,
        summary_contract_failure_reason: (if $evidence_summary_contract_failure_reason == "" then null else $evidence_summary_contract_failure_reason end),
        publish_ready: $evidence_publish_ready,
        failure_substep: (if $evidence_failure_substep == "" then null else $evidence_failure_substep end),
        failure_reason: (if $evidence_failure_reason == "" then null else $evidence_failure_reason end)
      }
    },
    outcome: {
      publish_ready: ($status == "pass" and $rc == 0),
      action: (if $status == "pass" and $rc == 0 then "archive_and_pack_complete" else "archive_and_pack_blocked" end),
      publish_blocked: (
        if $status == "pass" and $rc == 0 then
          null
        else
          {
            blocked: true,
            primary_substep: (if $failure_substep == "" then "unknown" else $failure_substep end),
            primary_reason: (if $failure_reason == "" then "archive+pack flow blocked" else $failure_reason end),
            cycle_publish_blocked: $cycle_publish_blocked,
            cycle_publish_blocked_reason: (if $cycle_publish_blocked_reason == "" then null else $cycle_publish_blocked_reason end),
            evidence_pack_diagnostic_substep: (if $evidence_diagnostic_substep == "" then null else $evidence_diagnostic_substep end),
            evidence_pack_diagnostic_reason: (if $evidence_diagnostic_reason == "" then null else $evidence_diagnostic_reason end),
            deterministic_next_command: (if $next_command == "" then null else $next_command end),
            deterministic_next_command_reason: (if $next_command_reason == "" then null else $next_command_reason end),
            deterministic_next_command_source: (if $next_command_source == "" then null else $next_command_source end)
          }
        end
      )
    },
    artifacts: {
      summary_json: $summary_json_path,
      report_md: $report_md_path,
      runtime_actuation_promotion_cycle_summary_json: $cycle_summary_json,
      runtime_actuation_promotion_cycle_log: $cycle_log,
      runtime_actuation_live_archive_root: $archive_root,
      runtime_actuation_live_archive_dir: (if $archive_dir == "" then null else $archive_dir end),
      runtime_actuation_live_archive_manifest_json: (if $archive_manifest_json == "" then null else $archive_manifest_json end),
      runtime_actuation_live_archive_log: $archive_log,
      runtime_actuation_promotion_evidence_pack_summary_json: $evidence_summary_json,
      runtime_actuation_promotion_evidence_pack_report_md: $evidence_report_md,
      runtime_actuation_promotion_evidence_pack_log: $evidence_log
    }
  }' >"$summary_json"

{
  printf '# Runtime Actuation Promotion Live Archive And Pack\n\n'
  printf -- '- Generated at (UTC): %s\n' "$(jq -r '.generated_at_utc' "$summary_json")"
  printf -- '- Status: %s\n' "$(jq -r '.status' "$summary_json")"
  printf -- '- rc: %s\n' "$(jq -r '.rc' "$summary_json")"
  printf -- '- Failure substep: %s\n' "$(jq -r '.failure_substep // "none"' "$summary_json")"
  printf -- '- Failure reason: %s\n' "$(jq -r '.failure_reason // "none"' "$summary_json")"
  printf -- '- Next operator action: %s\n' "$(jq -r '.next_operator_action // "none"' "$summary_json")"
  printf -- '- Next command: %s\n' "$(jq -r '.next_command // "none"' "$summary_json")"
  printf -- '- Next command reason: %s\n' "$(jq -r '.next_command_reason // "none"' "$summary_json")"
  printf -- '- Next command source: %s\n' "$(jq -r '.next_command_source // "none"' "$summary_json")"
  printf '\n'
  printf '## Stage: Runtime Actuation Promotion Cycle\n\n'
  printf -- '- Status: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.status' "$summary_json")"
  printf -- '- rc: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.rc' "$summary_json")"
  printf -- '- Summary: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.summary_json' "$summary_json")"
  printf -- '- Summary fresh after run: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.summary_fresh_after_run | tostring' "$summary_json")"
  printf -- '- Contract valid: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.summary_contract_valid | tostring' "$summary_json")"
  printf -- '- Publish ready: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.publish_ready | tostring' "$summary_json")"
  printf '\n'
  printf '## Stage: Live Evidence Archive\n\n'
  printf -- '- Attempted: %s\n' "$(jq -r '.stages.live_evidence_archive.attempted | tostring' "$summary_json")"
  printf -- '- Status: %s\n' "$(jq -r '.stages.live_evidence_archive.status' "$summary_json")"
  printf -- '- rc: %s\n' "$(jq -r '.stages.live_evidence_archive.rc' "$summary_json")"
  printf -- '- Archive dir: %s\n' "$(jq -r '.stages.live_evidence_archive.archive_dir // "none"' "$summary_json")"
  printf -- '- Archive manifest: %s\n' "$(jq -r '.stages.live_evidence_archive.archive_manifest_json // "none"' "$summary_json")"
  printf -- '- Candidate/copied/missing/errors: %s / %s / %s / %s\n' \
    "$(jq -r '.stages.live_evidence_archive.candidate_total // 0' "$summary_json")" \
    "$(jq -r '.stages.live_evidence_archive.copied_total // 0' "$summary_json")" \
    "$(jq -r '.stages.live_evidence_archive.missing_total // 0' "$summary_json")" \
    "$(jq -r '.stages.live_evidence_archive.copy_error_total // 0' "$summary_json")"
  printf '\n'
  printf '## Stage: Runtime Actuation Promotion Evidence Pack\n\n'
  printf -- '- Status: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.status' "$summary_json")"
  printf -- '- rc: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.rc' "$summary_json")"
  printf -- '- Summary: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.summary_json' "$summary_json")"
  printf -- '- Summary fresh after run: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.summary_fresh_after_run | tostring' "$summary_json")"
  printf -- '- Contract valid: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.summary_contract_valid | tostring' "$summary_json")"
  printf -- '- Publish ready: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.publish_ready | tostring' "$summary_json")"
} >"$report_md"

echo "[runtime-actuation-promotion-live-archive-and-pack] status=$final_status rc=$final_rc summary_json=$summary_json report_md=$report_md failure_substep=${final_failure_substep:-none}"
if [[ "$final_status" == "fail" && -n "$final_failure_substep" ]]; then
  echo "[runtime-actuation-promotion-live-archive-and-pack] fail_substep=$final_failure_substep reason=${final_failure_reason:-unknown}"
fi

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
