#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/runtime_actuation_promotion_check.sh \
    [--campaign-check-summary-json PATH]... \
    [--signoff-summary-json PATH]... \
    [--summary-list FILE] \
    [--reports-dir DIR] \
    [--require-min-samples N] \
    [--require-min-pass-samples N] \
    [--require-max-fail-samples N] \
    [--require-max-warn-samples N] \
    [--require-min-ready-rate-pct N] \
    [--require-modal-runtime-actuation-status STATUS] \
    [--fail-on-no-go [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Reduce repeated profile-compare campaign-check (or signoff summaries with
  campaign-check context) into a fail-closed runtime-actuation promotion gate.
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

canonicalize_existing_path() {
  local path
  local base=""
  local dir=""
  path="$(abs_path "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s\n' ""
    return
  fi
  if [[ -e "$path" ]]; then
    base="$(basename "$path")"
    dir="$(cd "$(dirname "$path")" 2>/dev/null && pwd -P || true)"
    if [[ -n "$dir" ]]; then
      printf '%s\n' "$dir/$base"
      return
    fi
  fi
  printf '%s\n' "$path"
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
    fail|error|failed) printf '%s\n' "fail" ;;
    warn|warning) printf '%s\n' "warn" ;;
    *) printf '%s\n' "$status" ;;
  esac
}

normalize_runtime_actuation_status() {
  local status
  status="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$status" in
    pass|ok|ready|true) printf '%s\n' "pass" ;;
    fail|blocked|false) printf '%s\n' "fail" ;;
    warn|warning) printf '%s\n' "warn" ;;
    notrequired|not-required|not_required) printf '%s\n' "not-required" ;;
    unknown|unset|missing|"") printf '%s\n' "unknown" ;;
    *) printf '%s\n' "$status" ;;
  esac
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

need_cmd jq
need_cmd date
need_cmd sort

reports_dir="${RUNTIME_ACTUATION_PROMOTION_CHECK_REPORTS_DIR:-${REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}}"
summary_list="${RUNTIME_ACTUATION_PROMOTION_CHECK_SUMMARY_LIST:-}"

require_min_samples="${RUNTIME_ACTUATION_PROMOTION_CHECK_REQUIRE_MIN_SAMPLES:-${REQUIRE_MIN_SAMPLES:-3}}"
require_min_pass_samples="${RUNTIME_ACTUATION_PROMOTION_CHECK_REQUIRE_MIN_PASS_SAMPLES:-${REQUIRE_MIN_PASS_SAMPLES:-3}}"
require_max_fail_samples="${RUNTIME_ACTUATION_PROMOTION_CHECK_REQUIRE_MAX_FAIL_SAMPLES:-${REQUIRE_MAX_FAIL_SAMPLES:-0}}"
require_max_warn_samples="${RUNTIME_ACTUATION_PROMOTION_CHECK_REQUIRE_MAX_WARN_SAMPLES:-${REQUIRE_MAX_WARN_SAMPLES:-0}}"
require_min_ready_rate_pct="${RUNTIME_ACTUATION_PROMOTION_CHECK_REQUIRE_MIN_READY_RATE_PCT:-${REQUIRE_MIN_READY_RATE_PCT:-100}}"
require_modal_runtime_actuation_status="${RUNTIME_ACTUATION_PROMOTION_CHECK_REQUIRE_MODAL_RUNTIME_ACTUATION_STATUS:-${REQUIRE_MODAL_RUNTIME_ACTUATION_STATUS:-}}"
fail_on_no_go="${RUNTIME_ACTUATION_PROMOTION_CHECK_FAIL_ON_NO_GO:-${FAIL_ON_NO_GO:-1}}"

show_json="${RUNTIME_ACTUATION_PROMOTION_CHECK_SHOW_JSON:-0}"
print_summary_json="${RUNTIME_ACTUATION_PROMOTION_CHECK_PRINT_SUMMARY_JSON:-0}"
summary_json="${RUNTIME_ACTUATION_PROMOTION_CHECK_SUMMARY_JSON:-}"

declare -a campaign_check_summary_inputs=()
declare -a signoff_summary_inputs=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --campaign-check-summary-json)
      require_value_or_die "$1" "$#"
      campaign_check_summary_inputs+=("${2:-}")
      shift 2
      ;;
    --campaign-check-summary-json=*)
      campaign_check_summary_inputs+=("${1#*=}")
      shift
      ;;
    --signoff-summary-json)
      require_value_or_die "$1" "$#"
      signoff_summary_inputs+=("${2:-}")
      shift 2
      ;;
    --signoff-summary-json=*)
      signoff_summary_inputs+=("${1#*=}")
      shift
      ;;
    --summary-list)
      require_value_or_die "$1" "$#"
      summary_list="${2:-}"
      shift 2
      ;;
    --summary-list=*)
      summary_list="${1#*=}"
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
    --require-min-samples)
      require_value_or_die "$1" "$#"
      require_min_samples="${2:-}"
      shift 2
      ;;
    --require-min-samples=*)
      require_min_samples="${1#*=}"
      shift
      ;;
    --require-min-pass-samples)
      require_value_or_die "$1" "$#"
      require_min_pass_samples="${2:-}"
      shift 2
      ;;
    --require-min-pass-samples=*)
      require_min_pass_samples="${1#*=}"
      shift
      ;;
    --require-max-fail-samples)
      require_value_or_die "$1" "$#"
      require_max_fail_samples="${2:-}"
      shift 2
      ;;
    --require-max-fail-samples=*)
      require_max_fail_samples="${1#*=}"
      shift
      ;;
    --require-max-warn-samples)
      require_value_or_die "$1" "$#"
      require_max_warn_samples="${2:-}"
      shift 2
      ;;
    --require-max-warn-samples=*)
      require_max_warn_samples="${1#*=}"
      shift
      ;;
    --require-min-ready-rate-pct)
      require_value_or_die "$1" "$#"
      require_min_ready_rate_pct="${2:-}"
      shift 2
      ;;
    --require-min-ready-rate-pct=*)
      require_min_ready_rate_pct="${1#*=}"
      shift
      ;;
    --require-modal-runtime-actuation-status)
      require_value_or_die "$1" "$#"
      require_modal_runtime_actuation_status="${2:-}"
      shift 2
      ;;
    --require-modal-runtime-actuation-status=*)
      require_modal_runtime_actuation_status="${1#*=}"
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

reports_dir="$(abs_path "$reports_dir")"
summary_list="$(abs_path "$summary_list")"
require_min_samples="$(trim "$require_min_samples")"
require_min_pass_samples="$(trim "$require_min_pass_samples")"
require_max_fail_samples="$(trim "$require_max_fail_samples")"
require_max_warn_samples="$(trim "$require_max_warn_samples")"
require_min_ready_rate_pct="$(trim "$require_min_ready_rate_pct")"
require_modal_runtime_actuation_status="$(normalize_runtime_actuation_status "$(trim "$require_modal_runtime_actuation_status")")"
fail_on_no_go="$(trim "$fail_on_no_go")"
show_json="$(trim "$show_json")"
print_summary_json="$(trim "$print_summary_json")"

bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

for int_arg in "$require_min_samples" "$require_min_pass_samples" "$require_max_fail_samples" "$require_max_warn_samples"; do
  if ! [[ "$int_arg" =~ ^[0-9]+$ ]]; then
    echo "sample count thresholds must be non-negative integers"
    exit 2
  fi
done

if ! is_non_negative_decimal "$require_min_ready_rate_pct"; then
  echo "--require-min-ready-rate-pct must be a non-negative number"
  exit 2
fi

if [[ -n "$require_modal_runtime_actuation_status" ]]; then
  case "$require_modal_runtime_actuation_status" in
    pass|fail|warn|not-required|unknown) ;;
    *)
      echo "--require-modal-runtime-actuation-status must be one of: pass, fail, warn, not-required, unknown"
      exit 2
      ;;
  esac
fi

log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/runtime_actuation_promotion_check_${run_stamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

declare -a summary_paths_raw=()
for path in "${campaign_check_summary_inputs[@]}"; do
  summary_paths_raw+=("$path")
done
for path in "${signoff_summary_inputs[@]}"; do
  summary_paths_raw+=("$path")
done

if [[ -n "$summary_list" ]]; then
  if [[ ! -f "$summary_list" ]]; then
    echo "summary list not found: $summary_list"
    exit 2
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim "$line")"
    if [[ -z "$line" || "${line:0:1}" == "#" ]]; then
      continue
    fi
    summary_paths_raw+=("$line")
  done <"$summary_list"
fi

if ((${#summary_paths_raw[@]} == 0)); then
  shopt -s nullglob
  for candidate in "$reports_dir"/profile_compare_campaign_check_summary*.json; do
    summary_paths_raw+=("$candidate")
  done
  for candidate in "$reports_dir"/profile_compare_campaign_signoff_summary*.json; do
    summary_paths_raw+=("$candidate")
  done
  shopt -u nullglob
fi

declare -A seen_paths=()
declare -a sample_paths=()
for raw_path in "${summary_paths_raw[@]}"; do
  normalized_path="$(canonicalize_existing_path "$raw_path")"
  if [[ -z "$normalized_path" ]]; then
    continue
  fi
  if [[ -z "${seen_paths[$normalized_path]+x}" ]]; then
    seen_paths["$normalized_path"]="1"
    sample_paths+=("$normalized_path")
  fi
done

if ((${#sample_paths[@]} > 0)); then
  mapfile -t sample_paths < <(printf '%s\n' "${sample_paths[@]}" | sort)
fi

declare -A sample_path_set=()
for path in "${sample_paths[@]}"; do
  sample_path_set["$path"]="1"
done

samples_json='[]'
diagnostics_missing_samples=0
runtime_status_missing_samples=0
runtime_ready_missing_samples=0
source_not_go_samples=0
source_not_pass_samples=0

for sample_path in "${sample_paths[@]}"; do
  sample_exists="0"
  sample_valid_json="0"
  source_kind="unknown"
  source_status=""
  source_status_normalized="unknown"
  source_decision=""
  runtime_status="unknown"
  runtime_ready_raw="null"
  runtime_ready_present="0"
  runtime_ready_value="null"
  diagnostics_present="0"
  source_gate_required="null"
  source_gate_available="null"
  source_gate_blocking="null"
  source_gate_source=""
  source_actionable_reason=""
  source_next_operator_action=""
  campaign_check_summary_json_ref=""
  sample_status="fail"
  sample_reasons_json='[]'

  append_sample_reason() {
    local code="$1"
    local message="$2"
    local action="$3"
    local entry
    entry="$(jq -n --arg code "$code" --arg message "$message" --arg action "$action" '{
      code: $code,
      message: $message,
      next_operator_action: $action
    }')"
    sample_reasons_json="$(jq -c --argjson entry "$entry" '. + [$entry]' <<<"$sample_reasons_json")"
  }

  if [[ -f "$sample_path" ]]; then
    sample_exists="1"
  fi
  if [[ "$sample_exists" == "1" && "$(json_file_valid_01 "$sample_path")" == "1" ]]; then
    sample_valid_json="1"
  fi

  if [[ "$sample_exists" != "1" ]]; then
    append_sample_reason \
      "artifact_missing" \
      "summary artifact is missing" \
      "regenerate the missing summary artifact and rerun runtime-actuation promotion check"
  elif [[ "$sample_valid_json" != "1" ]]; then
    append_sample_reason \
      "artifact_invalid_json" \
      "summary artifact is not a valid JSON object" \
      "fix summary generation and rerun runtime-actuation promotion check"
  else
    extracted_json="$(jq -c '
      def campaign_gate: .decision_diagnostics.m4_policy.gate_evaluation.runtime_actuation_status_pass;
      def signoff_gate:
        if (.decision | type) == "object" then
          .decision.campaign_check_gate_diagnostics.runtime_actuation_status_pass
        else
          null
        end;
      def source_kind:
        if (campaign_gate | type) == "object" then "campaign_check_summary"
        elif (signoff_gate | type) == "object" then "signoff_summary_with_campaign_check_context"
        else "unknown"
        end;
      def gate_obj:
        if (campaign_gate | type) == "object" then campaign_gate
        elif (signoff_gate | type) == "object" then signoff_gate
        else {}
        end;
      def source_status:
        if (.status | type) == "string" then .status
        elif (.decision | type) == "object" and ((.decision.status | type) == "string") then .decision.status
        else ""
        end;
      def source_decision:
        if (.decision | type) == "string" then .decision
        elif (.decision.decision | type) == "string" then .decision.decision
        else ""
        end;
      (gate_obj) as $gate
      | {
          source_kind: source_kind,
          source_status: source_status,
          source_decision: source_decision,
          runtime_status_raw: (
            if ($gate.status | type) == "string" then $gate.status
            elif ($gate.runtime_actuation_status | type) == "string" then $gate.runtime_actuation_status
            else ""
            end
          ),
          runtime_ready: (
            if ($gate.runtime_actuation_ready | type) == "boolean" then $gate.runtime_actuation_ready
            elif ($gate.ready | type) == "boolean" then $gate.ready
            elif ($gate.observed | type) == "boolean" then $gate.observed
            elif ($gate.available | type) == "boolean" and ($gate.available == false) then null
            elif (($gate.status | type) == "string") then
              ((($gate.status | ascii_downcase) as $status
                | if $status == "pass" or $status == "ok" then true
                  elif $status == "fail" then false
                  else null
                  end))
            else
              null
            end
          ),
          source_gate_required: (
            if ($gate.required | type) == "boolean" then $gate.required else null end
          ),
          source_gate_available: (
            if ($gate.available | type) == "boolean" then $gate.available else null end
          ),
          source_gate_blocking: (
            if ($gate.blocking | type) == "boolean" then $gate.blocking else null end
          ),
          source_gate_source: (
            if ($gate.source | type) == "string" then $gate.source else "" end
          ),
          source_actionable_reason: (
            if ($gate.actionable_reason | type) == "string" then $gate.actionable_reason else "" end
          ),
          source_next_operator_action: (
            if (.decision | type) == "object" and ((.decision.next_operator_action | type) == "string") then .decision.next_operator_action else "" end
          ),
          campaign_check_summary_json_ref: (
            if (.artifacts.campaign_check_summary_json | type) == "string" then .artifacts.campaign_check_summary_json else "" end
          )
        }
    ' "$sample_path" 2>/dev/null || printf '%s' '{}')"

    source_kind="$(jq -r '.source_kind // "unknown"' <<<"$extracted_json")"
    source_status="$(jq -r '.source_status // ""' <<<"$extracted_json")"
    source_status_normalized="$(normalize_status "$source_status")"
    source_decision="$(normalize_decision "$(jq -r '.source_decision // ""' <<<"$extracted_json")")"
    runtime_status="$(normalize_runtime_actuation_status "$(jq -r '.runtime_status_raw // ""' <<<"$extracted_json")")"
    runtime_ready_raw="$(jq -r '
      if (.runtime_ready | type) == "boolean" then
        if .runtime_ready then "true" else "false" end
      else
        "null"
      end
    ' <<<"$extracted_json")"
    if [[ "$runtime_ready_raw" == "true" ]]; then
      runtime_ready_present="1"
      runtime_ready_value="true"
    elif [[ "$runtime_ready_raw" == "false" ]]; then
      runtime_ready_present="1"
      runtime_ready_value="false"
    fi
    source_gate_required="$(jq -r '
      if (.source_gate_required | type) == "boolean" then
        if .source_gate_required then "true" else "false" end
      else
        "null"
      end
    ' <<<"$extracted_json")"
    source_gate_available="$(jq -r '
      if (.source_gate_available | type) == "boolean" then
        if .source_gate_available then "true" else "false" end
      else
        "null"
      end
    ' <<<"$extracted_json")"
    source_gate_blocking="$(jq -r '
      if (.source_gate_blocking | type) == "boolean" then
        if .source_gate_blocking then "true" else "false" end
      else
        "null"
      end
    ' <<<"$extracted_json")"
    source_gate_source="$(jq -r '.source_gate_source // ""' <<<"$extracted_json")"
    source_actionable_reason="$(jq -r '.source_actionable_reason // ""' <<<"$extracted_json")"
    source_next_operator_action="$(jq -r '.source_next_operator_action // ""' <<<"$extracted_json")"
    campaign_check_summary_json_ref="$(canonicalize_existing_path "$(jq -r '.campaign_check_summary_json_ref // ""' <<<"$extracted_json")")"

    if [[ "$source_kind" == "signoff_summary_with_campaign_check_context" \
      && -n "$campaign_check_summary_json_ref" \
      && "$campaign_check_summary_json_ref" != "$sample_path" \
      && -n "${sample_path_set[$campaign_check_summary_json_ref]+x}" ]]; then
      continue
    fi

    if [[ "$source_kind" == "campaign_check_summary" || "$source_kind" == "signoff_summary_with_campaign_check_context" ]]; then
      diagnostics_present="1"
    fi

    if [[ "$diagnostics_present" != "1" ]]; then
      diagnostics_missing_samples=$((diagnostics_missing_samples + 1))
      append_sample_reason \
        "runtime_actuation_diagnostics_missing" \
        "runtime actuation gate diagnostics are missing from summary decision diagnostics" \
        "rerun campaign-check/signoff with runtime actuation gate diagnostics enabled"
    fi

    if [[ "$runtime_status" == "unknown" ]]; then
      runtime_status_missing_samples=$((runtime_status_missing_samples + 1))
      append_sample_reason \
        "runtime_actuation_status_missing" \
        "runtime_actuation_status is missing or unknown in diagnostics" \
        "publish explicit runtime_actuation_status diagnostics and rerun evidence capture"
    fi

    if [[ "$runtime_ready_present" != "1" ]]; then
      runtime_ready_missing_samples=$((runtime_ready_missing_samples + 1))
      append_sample_reason \
        "runtime_actuation_ready_missing" \
        "runtime_actuation_ready signal is missing in diagnostics" \
        "publish explicit runtime_actuation_ready/observed signal and rerun evidence capture"
    fi

    if [[ "$source_decision" != "GO" ]]; then
      source_not_go_samples=$((source_not_go_samples + 1))
      append_sample_reason \
        "source_decision_not_go" \
        "upstream summary decision is not GO" \
        "fix upstream campaign-check/signoff NO-GO blockers before promotion"
    fi

    if [[ "$source_status_normalized" != "pass" ]]; then
      source_not_pass_samples=$((source_not_pass_samples + 1))
      append_sample_reason \
        "source_status_not_pass" \
        "upstream summary status is not pass/ok" \
        "stabilize upstream campaign-check/signoff status before promotion"
    fi

    if [[ "$(jq -r 'length' <<<"$sample_reasons_json")" -eq 0 ]]; then
      if [[ "$runtime_status" == "pass" && "$runtime_ready_value" == "true" ]]; then
        sample_status="pass"
      elif [[ "$runtime_status" == "fail" || "$runtime_ready_value" == "false" ]]; then
        sample_status="fail"
      else
        sample_status="warn"
      fi
    else
      if [[ "$runtime_status" == "warn" || "$runtime_status" == "not-required" ]]; then
        sample_status="warn"
      else
        sample_status="fail"
      fi
    fi
  fi

  next_action_hint=""
  if [[ -n "$source_next_operator_action" ]]; then
    next_action_hint="$source_next_operator_action"
  elif [[ -n "$source_actionable_reason" ]]; then
    next_action_hint="$source_actionable_reason"
  fi

  sample_entry="$(jq -n \
    --arg path "$sample_path" \
    --arg source_kind "$source_kind" \
    --arg source_status "$source_status" \
    --arg source_status_normalized "$source_status_normalized" \
    --arg source_decision "$source_decision" \
    --arg runtime_status "$runtime_status" \
    --arg runtime_ready_value "$runtime_ready_value" \
    --arg diagnostics_present "$diagnostics_present" \
    --arg sample_status "$sample_status" \
    --arg source_gate_required "$source_gate_required" \
    --arg source_gate_available "$source_gate_available" \
    --arg source_gate_blocking "$source_gate_blocking" \
    --arg source_gate_source "$source_gate_source" \
    --arg source_actionable_reason "$source_actionable_reason" \
    --arg next_action_hint "$next_action_hint" \
    --arg campaign_check_summary_json_ref "$campaign_check_summary_json_ref" \
    --argjson reasons "$sample_reasons_json" \
    '{
      path: $path,
      source_kind: $source_kind,
      source_status: (if $source_status == "" then null else $source_status end),
      source_status_normalized: (if $source_status_normalized == "" then null else $source_status_normalized end),
      source_decision: (if $source_decision == "" then null else $source_decision end),
      runtime_actuation_status: (if $runtime_status == "" then null else $runtime_status end),
      runtime_actuation_ready: (
        if $runtime_ready_value == "true" then true
        elif $runtime_ready_value == "false" then false
        else null
        end
      ),
      runtime_actuation_diagnostics_present: ($diagnostics_present == "1"),
      source_gate_required: (
        if $source_gate_required == "true" then true
        elif $source_gate_required == "false" then false
        else null
        end
      ),
      source_gate_available: (
        if $source_gate_available == "true" then true
        elif $source_gate_available == "false" then false
        else null
        end
      ),
      source_gate_blocking: (
        if $source_gate_blocking == "true" then true
        elif $source_gate_blocking == "false" then false
        else null
        end
      ),
      source_gate_source: (if $source_gate_source == "" then null else $source_gate_source end),
      source_actionable_reason: (if $source_actionable_reason == "" then null else $source_actionable_reason end),
      sample_status: $sample_status,
      reasons: $reasons,
      next_operator_action_hint: (if $next_action_hint == "" then null else $next_action_hint end),
      artifact_references: {
        campaign_check_summary_json: (
          if $campaign_check_summary_json_ref == "" then null
          else $campaign_check_summary_json_ref
          end
        )
      }
    }')"
  samples_json="$(jq -c --argjson entry "$sample_entry" '. + [$entry]' <<<"$samples_json")"
done

samples_total="$(jq -r 'length' <<<"$samples_json")"
samples_pass="$(jq -r '[.[] | select(.sample_status == "pass")] | length' <<<"$samples_json")"
samples_warn="$(jq -r '[.[] | select(.sample_status == "warn")] | length' <<<"$samples_json")"
samples_fail="$(jq -r '[.[] | select(.sample_status == "fail")] | length' <<<"$samples_json")"
runtime_ready_samples="$(jq -r '[.[] | select(.runtime_actuation_ready == true)] | length' <<<"$samples_json")"

runtime_actuation_status_counts_json="$(jq -c '
  [ .[] | (.runtime_actuation_status // "unknown") ]
  | group_by(.)
  | map({ (.[0]): length })
  | add // {}
' <<<"$samples_json")"

modal_runtime_actuation_status="$(jq -r '
  to_entries
  | sort_by(
      -.value,
      (if .key == "fail" then 0
       elif .key == "pass" then 1
       elif .key == "warn" then 2
       elif .key == "not-required" then 3
       elif .key == "unknown" then 4
       else 5 end),
      .key
    )
  | .[0].key // ""
' <<<"$runtime_actuation_status_counts_json")"
modal_runtime_actuation_status_count="$(jq -r '
  to_entries
  | sort_by(
      -.value,
      (if .key == "fail" then 0
       elif .key == "pass" then 1
       elif .key == "warn" then 2
       elif .key == "not-required" then 3
       elif .key == "unknown" then 4
       else 5 end),
      .key
    )
  | .[0].value // 0
' <<<"$runtime_actuation_status_counts_json")"

runtime_ready_rate_pct="$(jq -n \
  --argjson ready "$runtime_ready_samples" \
  --argjson total "$samples_total" \
  'if $total > 0 then (($ready * 100) / $total) else 0 end')"

violations_json='[]'
declare -a errors=()

append_violation() {
  local code="$1"
  local field="$2"
  local message="$3"
  local required="$4"
  local observed="$5"
  local next_action="$6"
  local entry
  entry="$(jq -n \
    --arg code "$code" \
    --arg field "$field" \
    --arg message "$message" \
    --arg required "$required" \
    --arg observed "$observed" \
    --arg next_operator_action "$next_action" \
    '{
      code: $code,
      field: $field,
      severity: "error",
      message: $message,
      required: $required,
      observed: $observed,
      next_operator_action: $next_operator_action
    }')"
  violations_json="$(jq -c --argjson entry "$entry" '. + [$entry]' <<<"$violations_json")"
  errors+=("$message")
}

if (( samples_total < require_min_samples )); then
  append_violation \
    "min_samples_not_met" \
    "observed.samples_total" \
    "insufficient runtime-actuation evidence samples" \
    ">=${require_min_samples}" \
    "$samples_total" \
    "collect additional campaign-check/signoff samples and rerun runtime_actuation_promotion_check"
fi

if (( samples_pass < require_min_pass_samples )); then
  append_violation \
    "min_pass_samples_not_met" \
    "observed.samples_pass" \
    "runtime-actuation pass sample count is below threshold" \
    ">=${require_min_pass_samples}" \
    "$samples_pass" \
    "improve runtime-actuation readiness until pass samples meet threshold"
fi

if (( samples_fail > require_max_fail_samples )); then
  append_violation \
    "max_fail_samples_exceeded" \
    "observed.samples_fail" \
    "runtime-actuation fail sample count exceeds allowed maximum" \
    "<=${require_max_fail_samples}" \
    "$samples_fail" \
    "resolve runtime-actuation fail samples before promotion"
fi

if (( samples_warn > require_max_warn_samples )); then
  append_violation \
    "max_warn_samples_exceeded" \
    "observed.samples_warn" \
    "runtime-actuation warn sample count exceeds allowed maximum" \
    "<=${require_max_warn_samples}" \
    "$samples_warn" \
    "eliminate warn/partial runtime-actuation samples before promotion"
fi

if awk -v observed="$runtime_ready_rate_pct" -v required="$require_min_ready_rate_pct" 'BEGIN { exit !(observed < required) }'; then
  append_violation \
    "ready_rate_below_threshold" \
    "observed.runtime_actuation_ready_rate_pct" \
    "runtime-actuation ready rate is below required threshold" \
    ">=$require_min_ready_rate_pct%" \
    "${runtime_ready_rate_pct}%" \
    "increase runtime_actuation_ready pass ratio and rerun evidence capture"
fi

if [[ -n "$require_modal_runtime_actuation_status" && "$modal_runtime_actuation_status" != "$require_modal_runtime_actuation_status" ]]; then
  append_violation \
    "modal_runtime_actuation_status_mismatch" \
    "observed.modal_runtime_actuation_status" \
    "modal runtime_actuation_status does not match required status" \
    "$require_modal_runtime_actuation_status" \
    "${modal_runtime_actuation_status:-unset}" \
    "stabilize runtime_actuation_status distribution so modal status matches required value"
fi

if (( diagnostics_missing_samples > 0 )); then
  append_violation \
    "runtime_actuation_diagnostics_missing" \
    "observed.diagnostics_missing_samples" \
    "one or more samples are missing runtime actuation decision diagnostics" \
    "0" \
    "$diagnostics_missing_samples" \
    "rerun campaign-check/signoff so runtime actuation diagnostics are emitted"
fi

if (( runtime_status_missing_samples > 0 )); then
  append_violation \
    "runtime_actuation_status_missing" \
    "observed.runtime_status_missing_samples" \
    "one or more samples are missing runtime_actuation_status in diagnostics" \
    "0" \
    "$runtime_status_missing_samples" \
    "emit explicit runtime_actuation_status in decision diagnostics and rerun"
fi

if (( runtime_ready_missing_samples > 0 )); then
  append_violation \
    "runtime_actuation_ready_missing" \
    "observed.runtime_ready_missing_samples" \
    "one or more samples are missing runtime_actuation_ready signal in diagnostics" \
    "0" \
    "$runtime_ready_missing_samples" \
    "emit explicit runtime_actuation_ready/observed signal in diagnostics and rerun"
fi

decision="GO"
status="ok"
notes="runtime-actuation promotion evidence satisfies configured policy thresholds"
if [[ "$(jq -r 'length' <<<"$violations_json")" -gt 0 ]]; then
  decision="NO-GO"
  status="fail"
  notes="runtime-actuation promotion policy violations detected"
fi

rc=0
if [[ "$decision" == "NO-GO" && "$fail_on_no_go" == "1" ]]; then
  rc=1
fi

sample_next_operator_action_hint="$(jq -r '
  [.[] | select(.sample_status != "pass" and (.next_operator_action_hint | type) == "string" and (.next_operator_action_hint | length) > 0) | .next_operator_action_hint][0] // ""
' <<<"$samples_json")"
violation_next_operator_action="$(jq -r '
  [.[] | select((.next_operator_action | type) == "string" and (.next_operator_action | length) > 0) | .next_operator_action][0] // ""
' <<<"$violations_json")"
next_operator_action="No action required; runtime-actuation promotion gate is satisfied"
if [[ "$decision" == "NO-GO" ]]; then
  if [[ -n "$sample_next_operator_action_hint" ]]; then
    next_operator_action="$sample_next_operator_action_hint"
  elif [[ -n "$violation_next_operator_action" ]]; then
    next_operator_action="$violation_next_operator_action"
  else
    next_operator_action="Address runtime-actuation diagnostics/threshold violations and rerun runtime_actuation_promotion_check"
  fi
fi

errors_json='[]'
if ((${#errors[@]} > 0)); then
  errors_json="$(printf '%s\n' "${errors[@]}" | jq -R . | jq -s '.')"
fi

sample_paths_json='[]'
if ((${#sample_paths[@]} > 0)); then
  sample_paths_json="$(printf '%s\n' "${sample_paths[@]}" | jq -R . | jq -s '.')"
fi

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg decision "$decision" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg next_operator_action "$next_operator_action" \
  --arg reports_dir "$reports_dir" \
  --arg summary_list "$summary_list" \
  --arg summary_json "$summary_json" \
  --arg require_modal_runtime_actuation_status "$require_modal_runtime_actuation_status" \
  --arg modal_runtime_actuation_status "$modal_runtime_actuation_status" \
  --argjson rc "$rc" \
  --argjson sample_paths "$sample_paths_json" \
  --argjson require_min_samples "$require_min_samples" \
  --argjson require_min_pass_samples "$require_min_pass_samples" \
  --argjson require_max_fail_samples "$require_max_fail_samples" \
  --argjson require_max_warn_samples "$require_max_warn_samples" \
  --argjson require_min_ready_rate_pct "$require_min_ready_rate_pct" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --argjson samples_total "$samples_total" \
  --argjson samples_pass "$samples_pass" \
  --argjson samples_warn "$samples_warn" \
  --argjson samples_fail "$samples_fail" \
  --argjson runtime_ready_samples "$runtime_ready_samples" \
  --argjson runtime_ready_rate_pct "$runtime_ready_rate_pct" \
  --argjson runtime_actuation_status_counts "$runtime_actuation_status_counts_json" \
  --argjson modal_runtime_actuation_status_count "$modal_runtime_actuation_status_count" \
  --argjson diagnostics_missing_samples "$diagnostics_missing_samples" \
  --argjson runtime_status_missing_samples "$runtime_status_missing_samples" \
  --argjson runtime_ready_missing_samples "$runtime_ready_missing_samples" \
  --argjson source_not_go_samples "$source_not_go_samples" \
  --argjson source_not_pass_samples "$source_not_pass_samples" \
  --argjson violations "$violations_json" \
  --argjson errors "$errors_json" \
  --argjson samples "$samples_json" \
  '{
    version: 1,
    schema: {
      id: "runtime_actuation_promotion_check_summary"
    },
    generated_at_utc: $generated_at_utc,
    decision: $decision,
    status: $status,
    rc: $rc,
    notes: $notes,
    next_operator_action: $next_operator_action,
    inputs: {
      reports_dir: $reports_dir,
      summary_list: (if $summary_list == "" then null else $summary_list end),
      sample_summary_paths: $sample_paths,
      policy: {
        require_min_samples: $require_min_samples,
        require_min_pass_samples: $require_min_pass_samples,
        require_max_fail_samples: $require_max_fail_samples,
        require_max_warn_samples: $require_max_warn_samples,
        require_min_ready_rate_pct: $require_min_ready_rate_pct,
        require_modal_runtime_actuation_status: (
          if $require_modal_runtime_actuation_status == "" then null
          else $require_modal_runtime_actuation_status
          end
        ),
        fail_on_no_go: ($fail_on_no_go == 1),
        require_runtime_actuation_diagnostics: true
      }
    },
    observed: {
      samples_total: $samples_total,
      samples_pass: $samples_pass,
      samples_warn: $samples_warn,
      samples_fail: $samples_fail,
      runtime_actuation_ready_samples: $runtime_ready_samples,
      runtime_actuation_ready_rate_pct: $runtime_ready_rate_pct,
      runtime_actuation_status_counts: $runtime_actuation_status_counts,
      modal_runtime_actuation_status: (
        if $modal_runtime_actuation_status == "" then null
        else $modal_runtime_actuation_status
        end
      ),
      modal_runtime_actuation_status_count: $modal_runtime_actuation_status_count,
      diagnostics_missing_samples: $diagnostics_missing_samples,
      runtime_status_missing_samples: $runtime_status_missing_samples,
      runtime_ready_missing_samples: $runtime_ready_missing_samples,
      source_not_go_samples: $source_not_go_samples,
      source_not_pass_samples: $source_not_pass_samples
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
      should_promote: ($decision == "GO"),
      action: (
        if $decision == "GO" then "promote_allowed"
        elif $fail_on_no_go == 1 then "hold_promotion_blocked"
        else "hold_promotion_warn_only"
        end
      ),
      next_operator_action: $next_operator_action
    },
    violations: $violations,
    errors: $errors,
    samples: $samples,
    artifacts: {
      summary_json: $summary_json,
      sample_summary_paths: $sample_paths
    }
  }' >"$summary_json"

echo "[runtime-actuation-promotion-check] decision=$decision status=$status rc=$rc samples_total=$samples_total samples_pass=$samples_pass ready_rate_pct=$runtime_ready_rate_pct modal_runtime_status=${modal_runtime_actuation_status:-unset}"
if [[ "$(jq -r 'length' <<<"$violations_json")" -gt 0 ]]; then
  echo "[runtime-actuation-promotion-check] failed with $(jq -r 'length' <<<"$violations_json") violation(s):"
  jq -r '.[] | "  - [" + .code + "] " + .message' <<<"$violations_json"
fi

if [[ "$show_json" == "1" ]]; then
  echo "[runtime-actuation-promotion-check] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
