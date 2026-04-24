#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/runtime_actuation_live_evidence_publish_bundle.sh \
    [--reports-dir DIR] \
    [--cycles N] \
    [--fail-on-no-go [0|1]] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Deterministically run runtime-actuation live-evidence publish flow:
    1) runtime-actuation promotion cycle
    2) runtime-actuation promotion evidence-pack publish

Outputs:
  - Bundle summary JSON
  - Bundle report Markdown
  - Stage logs for cycle and evidence-pack steps
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

reports_dir="${RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
cycles="${RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_CYCLES:-3}"
fail_on_no_go="${RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_FAIL_ON_NO_GO:-1}"
summary_json="${RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_SUMMARY_JSON:-}"
print_summary_json="${RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_PRINT_SUMMARY_JSON:-0}"

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

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/runtime_actuation_live_evidence_publish_bundle_summary.json"
fi
report_md="$reports_dir/runtime_actuation_live_evidence_publish_bundle_report.md"

runtime_cycle_script="${RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT:-$ROOT_DIR/scripts/runtime_actuation_promotion_cycle.sh}"
runtime_evidence_pack_script="${RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT:-$ROOT_DIR/scripts/runtime_actuation_promotion_evidence_pack.sh}"

runtime_cycle_script="$(abs_path "$runtime_cycle_script")"
runtime_evidence_pack_script="$(abs_path "$runtime_evidence_pack_script")"

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
runtime_cycle_summary_json="$reports_dir/runtime_actuation_promotion_cycle_latest_summary.json"
runtime_cycle_log="$reports_dir/runtime_actuation_live_evidence_publish_bundle_${run_stamp}_runtime_cycle.log"
runtime_evidence_pack_summary_json="$reports_dir/runtime_actuation_promotion_evidence_pack_summary.json"
runtime_evidence_pack_report_md="$reports_dir/runtime_actuation_promotion_evidence_pack_report.md"
runtime_evidence_pack_log="$reports_dir/runtime_actuation_live_evidence_publish_bundle_${run_stamp}_runtime_evidence_pack.log"

mkdir -p "$reports_dir" "$(dirname "$summary_json")" "$(dirname "$report_md")"

runtime_cycle_command_rendered="$(render_command \
  "$runtime_cycle_script" \
  "--reports-dir" "$reports_dir" \
  "--cycles" "$cycles" \
  "--fail-on-no-go" "$fail_on_no_go" \
  "--summary-json" "$runtime_cycle_summary_json" \
  "--print-summary-json" "0"
)"

runtime_evidence_pack_command_rendered="$(render_command \
  "$runtime_evidence_pack_script" \
  "--reports-dir" "$reports_dir" \
  "--promotion-cycle-summary-json" "$runtime_cycle_summary_json" \
  "--fail-on-no-go" "$fail_on_no_go" \
  "--summary-json" "$runtime_evidence_pack_summary_json" \
  "--report-md" "$runtime_evidence_pack_report_md" \
  "--print-summary-json" "0" \
  "--print-report" "0"
)"

bundle_rerun_command="$(render_command \
  "./scripts/runtime_actuation_live_evidence_publish_bundle.sh" \
  "--reports-dir" "$reports_dir" \
  "--cycles" "$cycles" \
  "--fail-on-no-go" "$fail_on_no_go" \
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
runtime_cycle_publish_ready="false"
runtime_cycle_summary_pre_fingerprint=""
runtime_cycle_summary_post_fingerprint=""
runtime_cycle_summary_fresh="false"
runtime_cycle_summary_usable_for_evidence="false"
cycle_publish_blocked="false"
cycle_publish_blocked_reason=""

runtime_evidence_pack_stage_status="skipped"
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
runtime_evidence_pack_publish_ready="false"
runtime_evidence_pack_source_next_command=""
runtime_evidence_pack_source_next_command_reason=""
runtime_evidence_pack_source_next_operator_action=""
runtime_evidence_pack_summary_pre_fingerprint=""
runtime_evidence_pack_summary_post_fingerprint=""
runtime_evidence_pack_summary_fresh="false"
evidence_diagnostic_substep=""
evidence_diagnostic_reason=""

failure_substep=""
failure_reason=""
final_status="fail"
final_rc=1

echo "[runtime-actuation-live-evidence-publish-bundle] stage=runtime_actuation_promotion_cycle status=running cycles=$cycles fail_on_no_go=$fail_on_no_go log=$runtime_cycle_log"
runtime_cycle_summary_pre_fingerprint="$(file_fingerprint_01 "$runtime_cycle_summary_json")"
set +e
"$runtime_cycle_script" \
  --reports-dir "$reports_dir" \
  --cycles "$cycles" \
  --fail-on-no-go "$fail_on_no_go" \
  --summary-json "$runtime_cycle_summary_json" \
  --print-summary-json 0 \
  >"$runtime_cycle_log" 2>&1
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
  if [[ "$runtime_cycle_summary_schema_id" == "runtime_actuation_promotion_cycle_summary" ]] \
    && [[ -n "$runtime_cycle_summary_rc" ]] \
    && [[ -n "$runtime_cycle_summary_status_normalized" ]]; then
    if [[ "$runtime_cycle_summary_rc" == "0" && ( "$runtime_cycle_summary_status_normalized" == "pass" || "$runtime_cycle_summary_status_normalized" == "warn" ) ]]; then
      runtime_cycle_summary_contract_valid="true"
    elif [[ "$runtime_cycle_summary_rc" != "0" && "$runtime_cycle_summary_status_normalized" == "fail" ]]; then
      runtime_cycle_summary_contract_valid="true"
    fi
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
  runtime_cycle_summary_usable_for_evidence="true"
fi

if [[ "$runtime_cycle_summary_exists" != "true" || "$runtime_cycle_summary_valid_json" != "true" ]]; then
  runtime_cycle_stage_status="fail"
  failure_substep="runtime_actuation_promotion_cycle_summary_missing_or_invalid"
  failure_reason="runtime-actuation promotion cycle summary is missing or invalid JSON"
elif [[ "$runtime_cycle_summary_fresh" != "true" ]]; then
  runtime_cycle_stage_status="fail"
  failure_substep="runtime_actuation_promotion_cycle_summary_stale_reused"
  failure_reason="runtime-actuation promotion cycle summary was reused from a previous run (missing fresh write)"
elif [[ "$runtime_cycle_summary_contract_valid" != "true" ]]; then
  runtime_cycle_stage_status="fail"
  failure_substep="runtime_actuation_promotion_cycle_summary_contract_invalid"
  failure_reason="runtime-actuation promotion cycle summary contract is invalid"
elif [[ "$runtime_cycle_publish_ready" != "true" ]]; then
  runtime_cycle_stage_status="fail"
  cycle_publish_blocked="true"
  cycle_publish_blocked_reason="runtime-actuation promotion cycle summary is not publish-ready (requires status=pass rc=0 decision=GO)"
elif [[ "$runtime_cycle_runner_rc" -ne 0 ]]; then
  failure_substep="runtime_actuation_promotion_cycle_runner_nonzero"
  failure_reason="runtime-actuation promotion cycle command failed (rc=$runtime_cycle_runner_rc)"
fi

echo "[runtime-actuation-live-evidence-publish-bundle] stage=runtime_actuation_promotion_cycle status=$runtime_cycle_stage_status rc=$runtime_cycle_runner_rc summary_json=$runtime_cycle_summary_json contract_valid=$runtime_cycle_summary_contract_valid publish_ready=$runtime_cycle_publish_ready summary_usable_for_evidence=$runtime_cycle_summary_usable_for_evidence cycle_publish_blocked=$cycle_publish_blocked"

if [[ "$runtime_cycle_summary_usable_for_evidence" == "true" ]]; then
  echo "[runtime-actuation-live-evidence-publish-bundle] stage=runtime_actuation_promotion_evidence_pack status=running fail_on_no_go=$fail_on_no_go log=$runtime_evidence_pack_log"
  runtime_evidence_pack_summary_pre_fingerprint="$(file_fingerprint_01 "$runtime_evidence_pack_summary_json")"
  set +e
  "$runtime_evidence_pack_script" \
    --reports-dir "$reports_dir" \
    --promotion-cycle-summary-json "$runtime_cycle_summary_json" \
    --fail-on-no-go "$fail_on_no_go" \
    --summary-json "$runtime_evidence_pack_summary_json" \
    --report-md "$runtime_evidence_pack_report_md" \
    --print-summary-json 0 \
    --print-report 0 \
    >"$runtime_evidence_pack_log" 2>&1
  runtime_evidence_pack_runner_rc=$?
  set -e

  if [[ "$runtime_evidence_pack_runner_rc" -eq 0 ]]; then
    runtime_evidence_pack_stage_status="pass"
  else
    runtime_evidence_pack_stage_status="fail"
  fi

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
    if [[ "$runtime_evidence_pack_summary_schema_id" == "runtime_actuation_promotion_evidence_pack_summary" ]] \
      && [[ -n "$runtime_evidence_pack_summary_rc" ]] \
      && [[ -n "$runtime_evidence_pack_summary_status_normalized" ]]; then
      if [[ "$runtime_evidence_pack_summary_rc" == "0" && ( "$runtime_evidence_pack_summary_status_normalized" == "pass" || "$runtime_evidence_pack_summary_status_normalized" == "warn" ) ]]; then
        runtime_evidence_pack_summary_contract_valid="true"
      elif [[ "$runtime_evidence_pack_summary_rc" != "0" && "$runtime_evidence_pack_summary_status_normalized" == "fail" ]]; then
        runtime_evidence_pack_summary_contract_valid="true"
      fi
    fi
  fi

  if [[ "$runtime_evidence_pack_summary_contract_valid" == "true" \
     && "$runtime_evidence_pack_summary_rc" == "0" \
     && "$runtime_evidence_pack_summary_status_normalized" == "pass" \
     && "$runtime_evidence_pack_summary_decision_normalized" == "GO" ]]; then
    runtime_evidence_pack_publish_ready="true"
  fi

  evidence_failure_substep=""
  evidence_failure_reason=""
  if [[ "$runtime_evidence_pack_runner_rc" -ne 0 ]]; then
    evidence_failure_substep="runtime_actuation_promotion_evidence_pack_runner_nonzero"
    evidence_failure_reason="runtime-actuation promotion evidence-pack publish command failed (rc=$runtime_evidence_pack_runner_rc)"
  elif [[ "$runtime_evidence_pack_summary_exists" != "true" || "$runtime_evidence_pack_summary_valid_json" != "true" ]]; then
    runtime_evidence_pack_stage_status="fail"
    evidence_failure_substep="runtime_actuation_promotion_evidence_pack_summary_missing_or_invalid"
    evidence_failure_reason="runtime-actuation promotion evidence-pack summary is missing or invalid JSON"
  elif [[ "$runtime_evidence_pack_summary_fresh" != "true" ]]; then
    runtime_evidence_pack_stage_status="fail"
    evidence_failure_substep="runtime_actuation_promotion_evidence_pack_summary_stale_reused"
    evidence_failure_reason="runtime-actuation promotion evidence-pack summary was reused from a previous run (missing fresh write)"
  elif [[ "$runtime_evidence_pack_summary_contract_valid" != "true" ]]; then
    runtime_evidence_pack_stage_status="fail"
    evidence_failure_substep="runtime_actuation_promotion_evidence_pack_summary_contract_invalid"
    evidence_failure_reason="runtime-actuation promotion evidence-pack summary contract is invalid"
  elif [[ "$runtime_evidence_pack_publish_ready" != "true" ]]; then
    runtime_evidence_pack_stage_status="fail"
    evidence_failure_substep="runtime_actuation_promotion_evidence_pack_not_publish_ready"
    evidence_failure_reason="runtime-actuation promotion evidence-pack summary is not publish-ready (requires status=pass rc=0 decision=GO)"
  fi

  if [[ -n "$evidence_failure_substep" ]]; then
    if [[ "$cycle_publish_blocked" == "true" ]]; then
      evidence_diagnostic_substep="$evidence_failure_substep"
      evidence_diagnostic_reason="$evidence_failure_reason"
    else
      failure_substep="$evidence_failure_substep"
      failure_reason="$evidence_failure_reason"
    fi
  fi

  echo "[runtime-actuation-live-evidence-publish-bundle] stage=runtime_actuation_promotion_evidence_pack status=$runtime_evidence_pack_stage_status rc=$runtime_evidence_pack_runner_rc summary_json=$runtime_evidence_pack_summary_json contract_valid=$runtime_evidence_pack_summary_contract_valid publish_ready=$runtime_evidence_pack_publish_ready"
else
  runtime_evidence_pack_stage_status="skipped"
  echo "[runtime-actuation-live-evidence-publish-bundle] stage=runtime_actuation_promotion_evidence_pack status=skipped reason=cycle_summary_unusable_for_evidence_pack"
fi

next_command=""
next_command_reason=""
next_operator_action=""
next_command_source=""

sanitized_source_next_command="$(sanitize_action_command_01 "$runtime_evidence_pack_source_next_command")"
sanitized_source_next_command_reason="$(sanitize_guidance_text_01 "$runtime_evidence_pack_source_next_command_reason")"
sanitized_source_next_operator_action="$(sanitize_guidance_text_01 "$runtime_evidence_pack_source_next_operator_action")"

cycle_rerun_command="$(render_command \
  "./scripts/easy_node.sh" \
  "runtime-actuation-promotion-cycle" \
  "--reports-dir" "$reports_dir" \
  "--cycles" "$cycles" \
  "--fail-on-no-go" "$fail_on_no_go" \
  "--summary-json" "$runtime_cycle_summary_json" \
  "--print-summary-json" "1"
)"

if [[ -z "$failure_substep" && "$cycle_publish_blocked" == "true" ]]; then
  failure_substep="runtime_actuation_publish_blocked_cycle_not_publish_ready"
  if [[ -n "$cycle_publish_blocked_reason" ]]; then
    failure_reason="$cycle_publish_blocked_reason"
  else
    failure_reason="runtime-actuation publish flow is blocked because cycle output is not publish-ready"
  fi
fi

if [[ -z "$failure_substep" ]]; then
  final_status="pass"
  final_rc=0
else
  final_status="fail"
  case "$failure_substep" in
    runtime_actuation_promotion_cycle_runner_nonzero)
      if [[ "$runtime_cycle_runner_rc" -gt 0 ]]; then
        final_rc="$runtime_cycle_runner_rc"
      else
        final_rc=1
      fi
      next_command="$cycle_rerun_command"
      next_command_reason="runtime-actuation promotion cycle command failed; inspect cycle log and rerun cycle"
      next_command_source="cycle_rerun_recovery"
      ;;
    runtime_actuation_promotion_cycle_summary_missing_or_invalid|runtime_actuation_promotion_cycle_summary_stale_reused|runtime_actuation_promotion_cycle_summary_contract_invalid|runtime_actuation_promotion_cycle_not_publish_ready)
      final_rc=3
      next_command="$cycle_rerun_command"
      next_command_reason="runtime-actuation promotion cycle summary is not publish-ready; regenerate cycle evidence and rerun publish bundle"
      next_command_source="cycle_rerun_recovery"
      ;;
    runtime_actuation_publish_blocked_cycle_not_publish_ready)
      final_rc=3
      if [[ -n "$sanitized_source_next_command" ]]; then
        next_command="$sanitized_source_next_command"
        next_command_source="runtime_evidence_pack_summary_next_command"
      else
        next_command="$cycle_rerun_command"
        next_command_source="cycle_rerun_recovery"
      fi
      if [[ -n "$sanitized_source_next_command_reason" ]]; then
        next_command_reason="$sanitized_source_next_command_reason"
      else
        next_command_reason="runtime-actuation publish flow is blocked by cycle NO-GO; inspect publish_blocked diagnostics, resolve blockers, and rerun cycle"
      fi
      ;;
    runtime_actuation_promotion_evidence_pack_runner_nonzero)
      if [[ "$runtime_evidence_pack_runner_rc" -gt 0 ]]; then
        final_rc="$runtime_evidence_pack_runner_rc"
      else
        final_rc=1
      fi
      if [[ -n "$sanitized_source_next_command" ]]; then
        next_command="$sanitized_source_next_command"
        next_command_source="runtime_evidence_pack_summary_next_command"
      else
        next_command="$bundle_rerun_command"
        next_command_source="bundle_rerun_recovery"
      fi
      if [[ -n "$sanitized_source_next_command_reason" ]]; then
        next_command_reason="$sanitized_source_next_command_reason"
      else
        next_command_reason="runtime-actuation promotion evidence-pack publish failed; rerun with fresh cycle evidence"
      fi
      ;;
    runtime_actuation_promotion_evidence_pack_summary_missing_or_invalid|runtime_actuation_promotion_evidence_pack_summary_stale_reused|runtime_actuation_promotion_evidence_pack_summary_contract_invalid|runtime_actuation_promotion_evidence_pack_not_publish_ready)
      final_rc=4
      if [[ -n "$sanitized_source_next_command" ]]; then
        next_command="$sanitized_source_next_command"
        next_command_source="runtime_evidence_pack_summary_next_command"
      else
        next_command="$cycle_rerun_command"
        next_command_source="cycle_rerun_recovery"
      fi
      if [[ -n "$sanitized_source_next_command_reason" ]]; then
        next_command_reason="$sanitized_source_next_command_reason"
      else
        next_command_reason="runtime-actuation promotion evidence-pack summary is not publish-ready; refresh cycle evidence and republish evidence pack"
      fi
      ;;
    *)
      final_rc=1
      next_command="$bundle_rerun_command"
      next_command_reason="unknown publish-bundle failure; rerun bundle and inspect stage logs"
      next_command_source="bundle_rerun_recovery"
      ;;
  esac
fi

if [[ "$final_status" == "pass" ]]; then
  next_operator_action="No action required; runtime-actuation live-evidence publish bundle is healthy."
else
  if [[ -n "$sanitized_source_next_operator_action" ]]; then
    next_operator_action="$sanitized_source_next_operator_action"
  elif [[ -n "$next_command_reason" ]]; then
    next_operator_action="$next_command_reason"
  else
    next_operator_action="Investigate publish-bundle logs and rerun with fresh runtime-actuation evidence."
  fi
fi

if text_has_placeholder_or_redacted_01 "$next_command_reason"; then
  next_command_reason="rerun with real non-placeholder runtime-actuation inputs and fresh evidence"
fi
if [[ -n "$next_command" ]] && ! action_command_is_safe_01 "$next_command"; then
  next_command="$bundle_rerun_command"
  next_command_source="bundle_rerun_recovery"
fi

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg failure_substep "$failure_substep" \
  --arg failure_reason "$failure_reason" \
  --arg next_operator_action "$next_operator_action" \
  --arg next_command "$next_command" \
  --arg next_command_reason "$next_command_reason" \
  --arg next_command_source "$next_command_source" \
  --arg reports_dir "$reports_dir" \
  --argjson cycles "$cycles" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --arg summary_json_path "$summary_json" \
  --arg report_md_path "$report_md" \
  --arg cycle_script "$runtime_cycle_script" \
  --arg cycle_command "$runtime_cycle_command_rendered" \
  --arg cycle_log "$runtime_cycle_log" \
  --arg cycle_summary_json "$runtime_cycle_summary_json" \
  --argjson cycle_runner_rc "$runtime_cycle_runner_rc" \
  --arg cycle_stage_status "$runtime_cycle_stage_status" \
  --argjson cycle_summary_exists "$runtime_cycle_summary_exists" \
  --argjson cycle_summary_valid_json "$runtime_cycle_summary_valid_json" \
  --argjson cycle_summary_fresh "$runtime_cycle_summary_fresh" \
  --arg cycle_summary_schema_id "$runtime_cycle_summary_schema_id" \
  --arg cycle_summary_status "$runtime_cycle_summary_status" \
  --arg cycle_summary_status_normalized "$runtime_cycle_summary_status_normalized" \
  --arg cycle_summary_rc "$runtime_cycle_summary_rc" \
  --arg cycle_summary_decision "$runtime_cycle_summary_decision" \
  --arg cycle_summary_decision_normalized "$runtime_cycle_summary_decision_normalized" \
  --argjson cycle_summary_contract_valid "$runtime_cycle_summary_contract_valid" \
  --argjson cycle_publish_ready "$runtime_cycle_publish_ready" \
  --argjson cycle_summary_usable_for_evidence "$runtime_cycle_summary_usable_for_evidence" \
  --argjson cycle_publish_blocked "$cycle_publish_blocked" \
  --arg cycle_publish_blocked_reason "$cycle_publish_blocked_reason" \
  --arg evidence_script "$runtime_evidence_pack_script" \
  --arg evidence_command "$runtime_evidence_pack_command_rendered" \
  --arg evidence_log "$runtime_evidence_pack_log" \
  --arg evidence_summary_json "$runtime_evidence_pack_summary_json" \
  --arg evidence_report_md "$runtime_evidence_pack_report_md" \
  --argjson evidence_runner_rc "$runtime_evidence_pack_runner_rc" \
  --arg evidence_stage_status "$runtime_evidence_pack_stage_status" \
  --argjson evidence_summary_exists "$runtime_evidence_pack_summary_exists" \
  --argjson evidence_summary_valid_json "$runtime_evidence_pack_summary_valid_json" \
  --argjson evidence_summary_fresh "$runtime_evidence_pack_summary_fresh" \
  --arg evidence_summary_schema_id "$runtime_evidence_pack_summary_schema_id" \
  --arg evidence_summary_status "$runtime_evidence_pack_summary_status" \
  --arg evidence_summary_status_normalized "$runtime_evidence_pack_summary_status_normalized" \
  --arg evidence_summary_rc "$runtime_evidence_pack_summary_rc" \
  --arg evidence_summary_decision "$runtime_evidence_pack_summary_decision" \
  --arg evidence_summary_decision_normalized "$runtime_evidence_pack_summary_decision_normalized" \
  --argjson evidence_summary_contract_valid "$runtime_evidence_pack_summary_contract_valid" \
  --argjson evidence_publish_ready "$runtime_evidence_pack_publish_ready" \
  --arg evidence_diagnostic_substep "$evidence_diagnostic_substep" \
  --arg evidence_diagnostic_reason "$evidence_diagnostic_reason" \
  '{
    version: 1,
    schema: {
      id: "runtime_actuation_live_evidence_publish_bundle_summary"
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
      fail_on_no_go: $fail_on_no_go
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
        publish_ready: $cycle_publish_ready
      },
      runtime_actuation_promotion_evidence_pack: {
        status: $evidence_stage_status,
        rc: $evidence_runner_rc,
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
        publish_ready: $evidence_publish_ready
      }
    },
    outcome: {
      publish_ready: ($status == "pass" and $rc == 0),
      action: (if $status == "pass" and $rc == 0 then "publish_complete" else "publish_blocked" end),
      publish_blocked: (
        if $status == "pass" and $rc == 0 then
          null
        else
          {
            blocked: true,
            primary_substep: (if $failure_substep == "" then "unknown" else $failure_substep end),
            primary_reason: (if $failure_reason == "" then "publish flow blocked" else $failure_reason end),
            cycle_summary_usable_for_evidence_pack: $cycle_summary_usable_for_evidence,
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
      runtime_actuation_promotion_evidence_pack_summary_json: $evidence_summary_json,
      runtime_actuation_promotion_evidence_pack_report_md: $evidence_report_md,
      runtime_actuation_promotion_evidence_pack_log: $evidence_log
    }
  }' >"$summary_json"

{
  printf '# Runtime Actuation Live Evidence Publish Bundle\n\n'
  printf -- '- Generated at (UTC): %s\n' "$(jq -r '.generated_at_utc' "$summary_json")"
  printf -- '- Status: %s\n' "$(jq -r '.status' "$summary_json")"
  printf -- '- rc: %s\n' "$(jq -r '.rc' "$summary_json")"
  printf -- '- Failure substep: %s\n' "$(jq -r '.failure_substep // "none"' "$summary_json")"
  printf -- '- Failure reason: %s\n' "$(jq -r '.failure_reason // "none"' "$summary_json")"
  printf -- '- Next operator action: %s\n' "$(jq -r '.next_operator_action // "none"' "$summary_json")"
  printf -- '- Next command: %s\n' "$(jq -r '.next_command // "none"' "$summary_json")"
  printf -- '- Next command reason: %s\n' "$(jq -r '.next_command_reason // "none"' "$summary_json")"
  printf -- '- Next command source: %s\n' "$(jq -r '.next_command_source // "none"' "$summary_json")"
  printf -- '- Outcome action: %s\n' "$(jq -r '.outcome.action' "$summary_json")"
  printf -- '- Publish blocked primary substep: %s\n' "$(jq -r '.outcome.publish_blocked.primary_substep // "none"' "$summary_json")"
  printf -- '- Publish blocked evidence diagnostic substep: %s\n' "$(jq -r '.outcome.publish_blocked.evidence_pack_diagnostic_substep // "none"' "$summary_json")"
  printf '\n'
  printf '## Stage: Runtime Actuation Promotion Cycle\n\n'
  printf -- '- Status: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.status' "$summary_json")"
  printf -- '- rc: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.rc' "$summary_json")"
  printf -- '- Summary: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.summary_json' "$summary_json")"
  printf -- '- Summary fresh after run: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.summary_fresh_after_run | tostring' "$summary_json")"
  printf -- '- Contract valid: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.summary_contract_valid | tostring' "$summary_json")"
  printf -- '- Publish ready: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.publish_ready | tostring' "$summary_json")"
  printf -- '- Log: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_cycle.log' "$summary_json")"
  printf '\n'
  printf '## Stage: Runtime Actuation Promotion Evidence Pack\n\n'
  printf -- '- Status: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.status' "$summary_json")"
  printf -- '- rc: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.rc' "$summary_json")"
  printf -- '- Summary: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.summary_json' "$summary_json")"
  printf -- '- Summary fresh after run: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.summary_fresh_after_run | tostring' "$summary_json")"
  printf -- '- Contract valid: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.summary_contract_valid | tostring' "$summary_json")"
  printf -- '- Publish ready: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.publish_ready | tostring' "$summary_json")"
  printf -- '- Log: %s\n' "$(jq -r '.stages.runtime_actuation_promotion_evidence_pack.log' "$summary_json")"
} >"$report_md"

echo "[runtime-actuation-live-evidence-publish-bundle] status=$final_status rc=$final_rc summary_json=$summary_json report_md=$report_md failure_substep=${failure_substep:-none}"
if [[ "$final_status" == "fail" && -n "$failure_substep" ]]; then
  echo "[runtime-actuation-live-evidence-publish-bundle] fail_substep=$failure_substep reason=${failure_reason:-unknown}"
fi
echo "[runtime-actuation-live-evidence-publish-bundle] summary_json_payload:"
cat "$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
