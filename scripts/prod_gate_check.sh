#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_gate_check.sh \
    [--bundle-dir PATH] \
    [--run-report-json PATH] \
    [--gate-summary-json PATH] \
    [--require-full-sequence [0|1]] \
    [--require-wg-validate-ok [0|1]] \
    [--require-wg-soak-ok [0|1]] \
    [--require-preflight-ok [0|1]] \
    [--require-bundle-ok [0|1]] \
    [--require-integrity-ok [0|1]] \
    [--require-signoff-ok [0|1]] \
    [--require-incident-snapshot-on-fail [0|1]] \
    [--require-incident-snapshot-artifacts [0|1]] \
    [--incident-snapshot-min-attachment-count N] \
    [--incident-snapshot-max-skipped-count N|-1] \
    [--require-wg-validate-udp-source [0|1]] \
    [--require-wg-validate-strict-distinct [0|1]] \
    [--require-wg-soak-diversity-pass [0|1]] \
    [--min-wg-soak-selection-lines N] \
    [--min-wg-soak-entry-operators N] \
    [--min-wg-soak-exit-operators N] \
    [--min-wg-soak-cross-operator-pairs N] \
    [--max-wg-soak-failed-rounds N] \
    [--max-evidence-age-sec N] \
    [--show-json [0|1]]

Purpose:
  Verify production gate result artifacts and fail fast on non-signoff conditions.
  This is intended for machine-C closed-beta/prod signoff automation.

Notes:
  - Provide one of:
    - --run-report-json (recommended; from three-machine-prod-bundle)
    - --bundle-dir (contains prod_gate_summary.json)
    - --gate-summary-json
  - Default policy is strict: full sequence, run-report stages, incident snapshot evidence, real-WG source/diversity evidence, and zero WG soak failed rounds are required.
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
  local path="$1"
  path="$(trim "$path")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" =~ ^[A-Za-z]:[\\/] ]]; then
    if command -v wslpath >/dev/null 2>&1; then
      wslpath -u "$path"
    elif command -v cygpath >/dev/null 2>&1; then
      cygpath -u "$path"
    else
      printf '%s' "$path"
    fi
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

path_under_dir() {
  local child="$1"
  local parent="$2"
  child="$(abs_path "$child")"
  parent="$(abs_path "$parent")"
  parent="${parent%/}"
  [[ -n "$child" && -n "$parent" ]] || return 1
  [[ "$child" == "$parent" || "$child" == "$parent/"* ]]
}

standard_artifact_ref_ok() {
  local reported="$1"
  local checked="$2"
  local expected_name="$3"
  reported="$(abs_path "$reported")"
  checked="$(abs_path "$checked")"
  [[ -n "$reported" && -n "$checked" ]] || return 1
  if [[ "$reported" == "$checked" ]]; then
    return 0
  fi
  [[ "${reported##*/}" == "$expected_name" && "${checked##*/}" == "$expected_name" ]] || return 1
  if [[ -n "${bundle_dir:-}" && -n "${run_report_parent_dir:-}" && "$run_report_parent_dir" == "$bundle_dir" ]]; then
    path_under_dir "$checked" "$bundle_dir"
    return
  fi
  return 1
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

bundle_dir=""
run_report_json=""
gate_summary_json=""
bundle_dir_supplied="0"
gate_summary_json_supplied="0"
require_full_sequence="${PROD_GATE_CHECK_REQUIRE_FULL_SEQUENCE:-1}"
require_wg_validate_ok="${PROD_GATE_CHECK_REQUIRE_WG_VALIDATE_OK:-1}"
require_wg_soak_ok="${PROD_GATE_CHECK_REQUIRE_WG_SOAK_OK:-1}"
require_preflight_ok="${PROD_GATE_CHECK_REQUIRE_PREFLIGHT_OK:-1}"
require_bundle_ok="${PROD_GATE_CHECK_REQUIRE_BUNDLE_OK:-1}"
require_integrity_ok="${PROD_GATE_CHECK_REQUIRE_INTEGRITY_OK:-1}"
require_signoff_ok="${PROD_GATE_CHECK_REQUIRE_SIGNOFF_OK:-1}"
require_incident_snapshot_on_fail="${PROD_GATE_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-1}"
require_incident_snapshot_artifacts="${PROD_GATE_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-1}"
incident_snapshot_min_attachment_count="${PROD_GATE_CHECK_INCIDENT_SNAPSHOT_MIN_ATTACHMENT_COUNT:-1}"
incident_snapshot_max_skipped_count="${PROD_GATE_CHECK_INCIDENT_SNAPSHOT_MAX_SKIPPED_COUNT:-0}"
require_wg_validate_udp_source="${PROD_GATE_CHECK_REQUIRE_WG_VALIDATE_UDP_SOURCE:-1}"
require_wg_validate_strict_distinct="${PROD_GATE_CHECK_REQUIRE_WG_VALIDATE_STRICT_DISTINCT:-1}"
require_wg_soak_diversity_pass="${PROD_GATE_CHECK_REQUIRE_WG_SOAK_DIVERSITY_PASS:-1}"
min_wg_soak_selection_lines="${PROD_GATE_CHECK_MIN_WG_SOAK_SELECTION_LINES:-12}"
min_wg_soak_entry_operators="${PROD_GATE_CHECK_MIN_WG_SOAK_ENTRY_OPERATORS:-2}"
min_wg_soak_exit_operators="${PROD_GATE_CHECK_MIN_WG_SOAK_EXIT_OPERATORS:-2}"
min_wg_soak_cross_operator_pairs="${PROD_GATE_CHECK_MIN_WG_SOAK_CROSS_OPERATOR_PAIRS:-2}"
max_wg_soak_failed_rounds="${PROD_GATE_CHECK_MAX_WG_SOAK_FAILED_ROUNDS:-0}"
max_evidence_age_sec="${PROD_GATE_CHECK_MAX_EVIDENCE_AGE_SEC:-0}"
max_evidence_future_skew_sec="${PROD_GATE_CHECK_MAX_EVIDENCE_FUTURE_SKEW_SEC:-300}"
max_evidence_now_epoch="${PROD_GATE_CHECK_NOW_EPOCH:-}"
show_json="${PROD_GATE_CHECK_SHOW_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      bundle_dir="${2:-}"
      bundle_dir_supplied="1"
      shift 2
      ;;
    --run-report-json)
      run_report_json="${2:-}"
      shift 2
      ;;
    --gate-summary-json)
      gate_summary_json="${2:-}"
      gate_summary_json_supplied="1"
      shift 2
      ;;
    --require-full-sequence)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_full_sequence="${2:-}"
        shift 2
      else
        require_full_sequence="1"
        shift
      fi
      ;;
    --require-wg-validate-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_ok="${2:-}"
        shift 2
      else
        require_wg_validate_ok="1"
        shift
      fi
      ;;
    --require-wg-soak-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_soak_ok="${2:-}"
        shift 2
      else
        require_wg_soak_ok="1"
        shift
      fi
      ;;
    --require-preflight-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_preflight_ok="${2:-}"
        shift 2
      else
        require_preflight_ok="1"
        shift
      fi
      ;;
    --require-bundle-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_bundle_ok="${2:-}"
        shift 2
      else
        require_bundle_ok="1"
        shift
      fi
      ;;
    --require-integrity-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_integrity_ok="${2:-}"
        shift 2
      else
        require_integrity_ok="1"
        shift
      fi
      ;;
    --require-signoff-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_signoff_ok="${2:-}"
        shift 2
      else
        require_signoff_ok="1"
        shift
      fi
      ;;
    --require-incident-snapshot-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_incident_snapshot_on_fail="${2:-}"
        shift 2
      else
        require_incident_snapshot_on_fail="1"
        shift
      fi
      ;;
    --require-incident-snapshot-artifacts)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_incident_snapshot_artifacts="${2:-}"
        shift 2
      else
        require_incident_snapshot_artifacts="1"
        shift
      fi
      ;;
    --incident-snapshot-min-attachment-count)
      incident_snapshot_min_attachment_count="${2:-}"
      shift 2
      ;;
    --incident-snapshot-max-skipped-count)
      incident_snapshot_max_skipped_count="${2:-}"
      shift 2
      ;;
    --require-wg-validate-udp-source)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_udp_source="${2:-}"
        shift 2
      else
        require_wg_validate_udp_source="1"
        shift
      fi
      ;;
    --require-wg-validate-strict-distinct)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_strict_distinct="${2:-}"
        shift 2
      else
        require_wg_validate_strict_distinct="1"
        shift
      fi
      ;;
    --require-wg-soak-diversity-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_soak_diversity_pass="${2:-}"
        shift 2
      else
        require_wg_soak_diversity_pass="1"
        shift
      fi
      ;;
    --min-wg-soak-selection-lines)
      min_wg_soak_selection_lines="${2:-}"
      shift 2
      ;;
    --min-wg-soak-entry-operators)
      min_wg_soak_entry_operators="${2:-}"
      shift 2
      ;;
    --min-wg-soak-exit-operators)
      min_wg_soak_exit_operators="${2:-}"
      shift 2
      ;;
    --min-wg-soak-cross-operator-pairs)
      min_wg_soak_cross_operator_pairs="${2:-}"
      shift 2
      ;;
    --max-wg-soak-failed-rounds)
      max_wg_soak_failed_rounds="${2:-}"
      shift 2
      ;;
    --max-evidence-age-sec)
      max_evidence_age_sec="${2:-}"
      shift 2
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

need_cmd jq

bool_arg_or_die "--require-full-sequence" "$require_full_sequence"
bool_arg_or_die "--require-wg-validate-ok" "$require_wg_validate_ok"
bool_arg_or_die "--require-wg-soak-ok" "$require_wg_soak_ok"
bool_arg_or_die "--require-preflight-ok" "$require_preflight_ok"
bool_arg_or_die "--require-bundle-ok" "$require_bundle_ok"
bool_arg_or_die "--require-integrity-ok" "$require_integrity_ok"
bool_arg_or_die "--require-signoff-ok" "$require_signoff_ok"
bool_arg_or_die "--require-incident-snapshot-on-fail" "$require_incident_snapshot_on_fail"
bool_arg_or_die "--require-incident-snapshot-artifacts" "$require_incident_snapshot_artifacts"
bool_arg_or_die "--require-wg-validate-udp-source" "$require_wg_validate_udp_source"
bool_arg_or_die "--require-wg-validate-strict-distinct" "$require_wg_validate_strict_distinct"
bool_arg_or_die "--require-wg-soak-diversity-pass" "$require_wg_soak_diversity_pass"
bool_arg_or_die "--show-json" "$show_json"
if [[ ! "$incident_snapshot_min_attachment_count" =~ ^[0-9]+$ ]]; then
  echo "--incident-snapshot-min-attachment-count must be an integer >= 0"
  exit 2
fi
if [[ ! "$incident_snapshot_max_skipped_count" =~ ^-?[0-9]+$ ]] || ((incident_snapshot_max_skipped_count < -1)); then
  echo "--incident-snapshot-max-skipped-count must be an integer >= -1"
  exit 2
fi
if [[ ! "$max_wg_soak_failed_rounds" =~ ^[0-9]+$ ]]; then
  echo "--max-wg-soak-failed-rounds must be an integer >= 0"
  exit 2
fi
if [[ ! "$max_evidence_age_sec" =~ ^[0-9]+$ ]]; then
  echo "--max-evidence-age-sec must be an integer >= 0"
  exit 2
fi
if [[ ! "$max_evidence_future_skew_sec" =~ ^[0-9]+$ ]]; then
  echo "PROD_GATE_CHECK_MAX_EVIDENCE_FUTURE_SKEW_SEC must be an integer >= 0"
  exit 2
fi
if [[ -n "$max_evidence_now_epoch" && ! "$max_evidence_now_epoch" =~ ^[0-9]+$ ]]; then
  echo "PROD_GATE_CHECK_NOW_EPOCH must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_wg_soak_selection_lines" =~ ^[0-9]+$ ]]; then
  echo "--min-wg-soak-selection-lines must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_wg_soak_entry_operators" =~ ^[0-9]+$ ]]; then
  echo "--min-wg-soak-entry-operators must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_wg_soak_exit_operators" =~ ^[0-9]+$ ]]; then
  echo "--min-wg-soak-exit-operators must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_wg_soak_cross_operator_pairs" =~ ^[0-9]+$ ]]; then
  echo "--min-wg-soak-cross-operator-pairs must be an integer >= 0"
  exit 2
fi

bundle_dir="$(trim "$bundle_dir")"
run_report_json="$(trim "$run_report_json")"
gate_summary_json="$(trim "$gate_summary_json")"
bundle_dir="$(abs_path "$bundle_dir")"
run_report_json="$(abs_path "$run_report_json")"
gate_summary_json="$(abs_path "$gate_summary_json")"
run_report_parent_dir=""
run_report_bundle_dir=""
run_report_gate_summary_json=""
run_report_wg_validate_summary_json=""
run_report_wg_soak_summary_json=""
if [[ -z "$run_report_json" && -n "$bundle_dir" ]]; then
  candidate_run_report="${bundle_dir%/}/prod_bundle_run_report.json"
  if [[ -f "$candidate_run_report" ]]; then
    run_report_json="$candidate_run_report"
  fi
fi
if [[ -n "$run_report_json" ]]; then
  if [[ ! -f "$run_report_json" ]]; then
    echo "run report JSON file not found: $run_report_json"
    exit 1
  fi
  if ! jq -e . "$run_report_json" >/dev/null 2>&1; then
    echo "run report JSON is not valid JSON: $run_report_json"
    exit 1
  fi
  run_report_parent_dir="$(dirname "$run_report_json")"
  run_report_bundle_dir="$(jq -r '.bundle_dir // ""' "$run_report_json" 2>/dev/null || true)"
  run_report_bundle_dir="$(trim "$run_report_bundle_dir")"
  run_report_bundle_dir="$(abs_path "$run_report_bundle_dir")"
  run_report_gate_summary_json="$(jq -r '.gate_summary_json // ""' "$run_report_json" 2>/dev/null || true)"
  run_report_gate_summary_json="$(trim "$run_report_gate_summary_json")"
  run_report_gate_summary_json="$(abs_path "$run_report_gate_summary_json")"
  run_report_wg_validate_summary_json="$(jq -r '.wg_validate_summary_json // ""' "$run_report_json" 2>/dev/null || true)"
  run_report_wg_validate_summary_json="$(trim "$run_report_wg_validate_summary_json")"
  run_report_wg_validate_summary_json="$(abs_path "$run_report_wg_validate_summary_json")"
  run_report_wg_soak_summary_json="$(jq -r '.wg_soak_summary_json // ""' "$run_report_json" 2>/dev/null || true)"
  run_report_wg_soak_summary_json="$(trim "$run_report_wg_soak_summary_json")"
  run_report_wg_soak_summary_json="$(abs_path "$run_report_wg_soak_summary_json")"
  if [[ -z "$bundle_dir" ]]; then
    if [[ -f "${run_report_parent_dir%/}/prod_gate_summary.json" ]]; then
      bundle_dir="$run_report_parent_dir"
    else
      bundle_dir="$run_report_bundle_dir"
    fi
  fi
  if [[ -z "$gate_summary_json" ]]; then
    gate_summary_json="$run_report_gate_summary_json"
  fi
fi
local_bundle_gate_summary_json=""
if [[ -n "$bundle_dir" ]]; then
  local_bundle_gate_summary_json="${bundle_dir%/}/prod_gate_summary.json"
  if [[ "$gate_summary_json_supplied" == "0" && -f "$local_bundle_gate_summary_json" ]]; then
    gate_summary_json="$local_bundle_gate_summary_json"
  fi
fi
if [[ -z "$gate_summary_json" && -n "$bundle_dir" ]]; then
  gate_summary_json="${bundle_dir%/}/prod_gate_summary.json"
fi
if [[ -z "$gate_summary_json" ]]; then
  echo "missing required input: set --run-report-json, --gate-summary-json, or --bundle-dir"
  exit 2
fi
if [[ ! -f "$gate_summary_json" ]]; then
  echo "gate summary file not found: $gate_summary_json"
  exit 1
fi
if ! jq -e . "$gate_summary_json" >/dev/null 2>&1; then
  echo "gate summary is not valid JSON: $gate_summary_json"
  exit 1
fi

json_string() {
  local file="$1"
  local expr="$2"
  jq -r "$expr // \"\"" "$file" 2>/dev/null || true
}

json_int() {
  local file="$1"
  local expr="$2"
  local value
  value="$(jq -r "$expr // 0" "$file" 2>/dev/null || true)"
  if [[ -z "$value" || ! "$value" =~ ^-?[0-9]+$ ]]; then
    echo "0"
    return
  fi
  echo "$value"
}

json_trueish() {
  local file="$1"
  local expr="$2"
  local value
  value="$(jq -r "($expr) // false | tostring" "$file" 2>/dev/null || true)"
  case "$value" in
    true|1)
      echo "1"
      ;;
    *)
      echo "0"
      ;;
  esac
}

iso8601_utc_to_epoch() {
  local timestamp="$1"
  timestamp="$(trim "$timestamp")"
  if [[ ! "$timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    return 1
  fi
  jq -nr --arg ts "$timestamp" '$ts | fromdateiso8601 | floor' 2>/dev/null
}

check_evidence_timestamp_age() {
  local label="$1"
  local timestamp="$2"
  local now_epoch="$3"
  local timestamp_epoch=""
  timestamp="$(trim "$timestamp")"
  if [[ -z "$timestamp" ]]; then
    errors+=("$label timestamp missing while --max-evidence-age-sec is enabled")
    return
  fi
  if ! timestamp_epoch="$(iso8601_utc_to_epoch "$timestamp" 2>/dev/null)"; then
    errors+=("$label timestamp is invalid (value=$timestamp)")
    return
  fi
  if (( timestamp_epoch > now_epoch + max_evidence_future_skew_sec )); then
    errors+=("$label timestamp is too far in the future (value=$timestamp, future_skew_sec=$((timestamp_epoch - now_epoch)))")
    return
  fi
  if (( now_epoch - timestamp_epoch > max_evidence_age_sec )); then
    errors+=("$label timestamp is stale (value=$timestamp, age_sec=$((now_epoch - timestamp_epoch)), max_evidence_age_sec=$max_evidence_age_sec)")
  fi
}

gate_status="$(json_string "$gate_summary_json" '.status')"
failed_step="$(json_string "$gate_summary_json" '.failed_step')"
failed_rc="$(json_int "$gate_summary_json" '.failed_rc')"
gate_started_at_utc="$(json_string "$gate_summary_json" '.started_at_utc')"
gate_finished_at_utc="$(json_string "$gate_summary_json" '.finished_at_utc')"
step_control_validate="$(json_string "$gate_summary_json" '.steps.control_validate')"
step_control_soak="$(json_string "$gate_summary_json" '.steps.control_soak')"
step_prod_wg_validate="$(json_string "$gate_summary_json" '.steps.prod_wg_validate')"
step_prod_wg_soak="$(json_string "$gate_summary_json" '.steps.prod_wg_soak')"

wg_validate_summary_json="$(json_string "$gate_summary_json" '.wg_validate_summary_json')"
wg_validate_summary_json="$(abs_path "$wg_validate_summary_json")"
local_bundle_wg_validate_summary_json=""
if [[ -n "$bundle_dir" && -f "${bundle_dir%/}/prod_wg_validate_summary.json" ]]; then
  local_bundle_wg_validate_summary_json="${bundle_dir%/}/prod_wg_validate_summary.json"
  wg_validate_summary_json="$local_bundle_wg_validate_summary_json"
fi
wg_validate_summary_status=""
wg_validate_started_at_utc=""
wg_validate_finished_at_utc=""
wg_validate_status="$(json_string "$gate_summary_json" '.wg_validate_status')"
wg_validate_failed_step="$(json_string "$gate_summary_json" '.wg_validate_failed_step')"

wg_soak_summary_json="$(json_string "$gate_summary_json" '.wg_soak_summary_json')"
wg_soak_summary_json="$(abs_path "$wg_soak_summary_json")"
local_bundle_wg_soak_summary_json=""
if [[ -n "$bundle_dir" && -f "${bundle_dir%/}/prod_wg_soak_summary.json" ]]; then
  local_bundle_wg_soak_summary_json="${bundle_dir%/}/prod_wg_soak_summary.json"
  wg_soak_summary_json="$local_bundle_wg_soak_summary_json"
fi
wg_soak_summary_status=""
wg_soak_summary_generated_at_utc=""
wg_soak_status="$(json_string "$gate_summary_json" '.wg_soak_status')"
wg_soak_rounds_failed="$(json_int "$gate_summary_json" '.wg_soak_rounds_failed')"
wg_soak_top_failure_class="$(json_string "$gate_summary_json" '.wg_soak_top_failure_class')"
wg_soak_top_failure_count="$(json_int "$gate_summary_json" '.wg_soak_top_failure_count')"
wg_validate_client_inner_source=""
wg_validate_strict_distinct="0"
wg_soak_selection_lines="0"
wg_soak_selection_entry_operators="0"
wg_soak_selection_exit_operators="0"
wg_soak_selection_cross_operator_pairs="0"
wg_soak_selection_diversity_failed="0"
if [[ -n "$wg_validate_summary_json" && -f "$wg_validate_summary_json" ]]; then
  wg_validate_summary_status="$(json_string "$wg_validate_summary_json" '.status')"
  wg_validate_started_at_utc="$(json_string "$wg_validate_summary_json" '.started_at_utc')"
  wg_validate_finished_at_utc="$(json_string "$wg_validate_summary_json" '.finished_at_utc')"
  wg_validate_client_inner_source="$(json_string "$wg_validate_summary_json" '.client_inner_source')"
  wg_validate_strict_distinct="$(json_trueish "$wg_validate_summary_json" '.strict_distinct')"
fi
if [[ -n "$wg_soak_summary_json" && -f "$wg_soak_summary_json" ]]; then
  wg_soak_summary_status="$(json_string "$wg_soak_summary_json" '.status')"
  wg_soak_summary_generated_at_utc="$(json_string "$wg_soak_summary_json" '.summary_generated_at_utc')"
  wg_soak_selection_lines="$(json_int "$wg_soak_summary_json" '.selection_lines_total')"
  wg_soak_selection_entry_operators="$(json_int "$wg_soak_summary_json" '.selection_entry_operators')"
  wg_soak_selection_exit_operators="$(json_int "$wg_soak_summary_json" '.selection_exit_operators')"
  wg_soak_selection_cross_operator_pairs="$(json_int "$wg_soak_summary_json" '.selection_cross_operator_pairs')"
  wg_soak_selection_diversity_failed="$(json_int "$wg_soak_summary_json" '.selection_diversity_failed')"
fi

run_report_status=""
run_report_generated_at_utc=""
run_report_final_rc=0
run_report_preflight_status=""
run_report_bundle_status=""
run_report_integrity_status=""
run_report_signoff_enabled=""
run_report_signoff_rc=0
run_report_incident_enabled_on_fail=""
run_report_incident_status=""
run_report_incident_rc=0
run_report_incident_bundle_dir=""
run_report_incident_bundle_tar=""
run_report_incident_summary_json=""
run_report_incident_report_md=""
run_report_incident_attachment_manifest=""
run_report_incident_attachment_skipped=""
run_report_incident_attachment_count=0
run_report_incident_attachment_skipped_count=0
if [[ -n "$run_report_json" ]]; then
  run_report_status="$(json_string "$run_report_json" '.status')"
  run_report_generated_at_utc="$(json_string "$run_report_json" '.generated_at_utc')"
  run_report_final_rc="$(json_int "$run_report_json" '.final_rc')"
  run_report_preflight_status="$(json_string "$run_report_json" '.preflight.status')"
  run_report_bundle_status="$(json_string "$run_report_json" '.bundle.status')"
  run_report_integrity_status="$(json_string "$run_report_json" '.integrity_verify.status')"
  run_report_signoff_enabled="$(json_string "$run_report_json" '.signoff.enabled')"
  run_report_signoff_rc="$(json_int "$run_report_json" '.signoff.rc')"
  run_report_incident_enabled_on_fail="$(json_string "$run_report_json" '.incident_snapshot.enabled_on_fail')"
  run_report_incident_status="$(json_string "$run_report_json" '.incident_snapshot.status')"
  run_report_incident_rc="$(json_int "$run_report_json" '.incident_snapshot.rc')"
  run_report_incident_bundle_dir="$(json_string "$run_report_json" '.incident_snapshot.bundle_dir')"
  run_report_incident_bundle_tar="$(json_string "$run_report_json" '.incident_snapshot.bundle_tar')"
  run_report_incident_summary_json="$(json_string "$run_report_json" '.incident_snapshot.summary_json')"
  run_report_incident_report_md="$(json_string "$run_report_json" '.incident_snapshot.report_md')"
  run_report_incident_attachment_manifest="$(json_string "$run_report_json" '.incident_snapshot.attachment_manifest')"
  run_report_incident_attachment_skipped="$(json_string "$run_report_json" '.incident_snapshot.attachment_skipped')"
  run_report_incident_attachment_count="$(json_int "$run_report_json" '.incident_snapshot.attachment_count')"
  run_report_incident_bundle_dir="$(abs_path "$run_report_incident_bundle_dir")"
  run_report_incident_bundle_tar="$(abs_path "$run_report_incident_bundle_tar")"
  run_report_incident_summary_json="$(abs_path "$run_report_incident_summary_json")"
  run_report_incident_report_md="$(abs_path "$run_report_incident_report_md")"
  run_report_incident_attachment_manifest="$(abs_path "$run_report_incident_attachment_manifest")"
  run_report_incident_attachment_skipped="$(abs_path "$run_report_incident_attachment_skipped")"
  if [[ -n "$run_report_incident_attachment_skipped" && -f "$run_report_incident_attachment_skipped" ]]; then
    run_report_incident_attachment_skipped_count="$(awk 'NF>0 {c++} END {print c+0}' "$run_report_incident_attachment_skipped" 2>/dev/null || echo "0")"
    if [[ -z "$run_report_incident_attachment_skipped_count" || ! "$run_report_incident_attachment_skipped_count" =~ ^[0-9]+$ ]]; then
      run_report_incident_attachment_skipped_count=0
    fi
  fi
fi

declare -a errors=()

if (( max_evidence_age_sec > 0 )); then
  if [[ -n "$max_evidence_now_epoch" ]]; then
    now_epoch="$max_evidence_now_epoch"
  else
    need_cmd date
    now_epoch="$(date -u +%s)"
  fi
  if [[ -z "$now_epoch" || ! "$now_epoch" =~ ^[0-9]+$ ]]; then
    errors+=("could not determine current UTC epoch for evidence freshness check")
  else
    check_evidence_timestamp_age "gate started_at_utc" "$gate_started_at_utc" "$now_epoch"
    check_evidence_timestamp_age "gate finished_at_utc" "$gate_finished_at_utc" "$now_epoch"
    if [[ -n "$run_report_json" ]]; then
      check_evidence_timestamp_age "run report generated_at_utc" "$run_report_generated_at_utc" "$now_epoch"
    fi
    if [[ "$require_wg_validate_ok" == "1" || -n "$wg_validate_summary_status" ]]; then
      check_evidence_timestamp_age "wg validate started_at_utc" "$wg_validate_started_at_utc" "$now_epoch"
      check_evidence_timestamp_age "wg validate finished_at_utc" "$wg_validate_finished_at_utc" "$now_epoch"
    fi
    if [[ "$require_wg_soak_ok" == "1" || -n "$wg_soak_summary_status" ]]; then
      check_evidence_timestamp_age "wg soak summary_generated_at_utc" "$wg_soak_summary_generated_at_utc" "$now_epoch"
    fi
  fi
fi

if [[ -n "$run_report_json" ]]; then
  if [[ -z "$run_report_bundle_dir" ]]; then
    errors+=("run report bundle_dir path missing")
  elif [[ -n "$bundle_dir" && "$run_report_bundle_dir" != "$bundle_dir" && "$bundle_dir" != "$run_report_parent_dir" ]]; then
    errors+=("run report bundle_dir does not match checked bundle_dir (run_report=$run_report_bundle_dir, checked=$bundle_dir)")
  fi
  if [[ -z "$run_report_gate_summary_json" ]]; then
    errors+=("run report gate_summary_json path missing")
  elif ! standard_artifact_ref_ok "$run_report_gate_summary_json" "$gate_summary_json" "prod_gate_summary.json"; then
    errors+=("run report gate_summary_json does not reference the checked bundle artifact (run_report=$run_report_gate_summary_json, checked=$gate_summary_json)")
  fi
  if [[ "$require_wg_validate_ok" == "1" || -n "$run_report_wg_validate_summary_json" ]]; then
    if [[ -z "$run_report_wg_validate_summary_json" ]]; then
      errors+=("run report wg_validate_summary_json path missing")
    elif [[ -n "$wg_validate_summary_json" ]] && ! standard_artifact_ref_ok "$run_report_wg_validate_summary_json" "$wg_validate_summary_json" "prod_wg_validate_summary.json"; then
      errors+=("run report wg_validate_summary_json does not reference the checked bundle artifact (run_report=$run_report_wg_validate_summary_json, checked=$wg_validate_summary_json)")
    fi
  fi
  if [[ "$require_wg_soak_ok" == "1" || -n "$run_report_wg_soak_summary_json" ]]; then
    if [[ -z "$run_report_wg_soak_summary_json" ]]; then
      errors+=("run report wg_soak_summary_json path missing")
    elif [[ -n "$wg_soak_summary_json" ]] && ! standard_artifact_ref_ok "$run_report_wg_soak_summary_json" "$wg_soak_summary_json" "prod_wg_soak_summary.json"; then
      errors+=("run report wg_soak_summary_json does not reference the checked bundle artifact (run_report=$run_report_wg_soak_summary_json, checked=$wg_soak_summary_json)")
    fi
  fi
fi

if [[ -n "$bundle_dir" ]]; then
  if [[ -n "$gate_summary_json" ]] && ! path_under_dir "$gate_summary_json" "$bundle_dir"; then
    errors+=("gate summary is outside checked bundle_dir (gate_summary_json=$gate_summary_json, bundle_dir=$bundle_dir)")
  fi
  if [[ -n "$wg_validate_summary_json" ]] && ! path_under_dir "$wg_validate_summary_json" "$bundle_dir"; then
    errors+=("wg_validate_summary_json is outside checked bundle_dir (wg_validate_summary_json=$wg_validate_summary_json, bundle_dir=$bundle_dir)")
  fi
  if [[ -n "$wg_soak_summary_json" ]] && ! path_under_dir "$wg_soak_summary_json" "$bundle_dir"; then
    errors+=("wg_soak_summary_json is outside checked bundle_dir (wg_soak_summary_json=$wg_soak_summary_json, bundle_dir=$bundle_dir)")
  fi
fi

if [[ "$gate_status" != "ok" ]]; then
  errors+=("gate status is not ok (status=${gate_status:-unset}, failed_step=${failed_step:-none}, failed_rc=$failed_rc)")
fi

if [[ -n "$wg_validate_summary_status" && -n "$wg_validate_status" && "$wg_validate_summary_status" != "$wg_validate_status" ]]; then
  errors+=("wg validate summary status does not match gate summary (summary_status=$wg_validate_summary_status, gate_status=$wg_validate_status)")
fi

if [[ -n "$wg_soak_summary_status" && -n "$wg_soak_status" && "$wg_soak_summary_status" != "$wg_soak_status" ]]; then
  errors+=("wg soak summary status does not match gate summary (summary_status=$wg_soak_summary_status, gate_status=$wg_soak_status)")
fi

if [[ "$require_full_sequence" == "1" ]]; then
  if [[ "$step_control_validate" != "ok" ]]; then
    errors+=("control_validate step is not ok (value=${step_control_validate:-unset})")
  fi
  if [[ "$step_control_soak" != "ok" ]]; then
    errors+=("control_soak step is not ok (value=${step_control_soak:-unset})")
  fi
  if [[ "$step_prod_wg_validate" != "ok" ]]; then
    errors+=("prod_wg_validate step is not ok (value=${step_prod_wg_validate:-unset})")
  fi
  if [[ "$step_prod_wg_soak" != "ok" ]]; then
    errors+=("prod_wg_soak step is not ok (value=${step_prod_wg_soak:-unset})")
  fi
fi

if [[ "$require_wg_validate_ok" == "1" ]]; then
  if [[ -z "$wg_validate_summary_json" ]]; then
    errors+=("wg_validate_summary_json path missing in gate summary")
  elif [[ ! -f "$wg_validate_summary_json" ]]; then
    errors+=("wg_validate_summary_json file not found: $wg_validate_summary_json")
  fi
  if [[ "$wg_validate_status" != "ok" ]]; then
    errors+=("wg_validate_status is not ok (status=${wg_validate_status:-unset}, failed_step=${wg_validate_failed_step:-none})")
  fi
fi

if [[ "$require_wg_soak_ok" == "1" ]]; then
  if [[ -z "$wg_soak_summary_json" ]]; then
    errors+=("wg_soak_summary_json path missing in gate summary")
  elif [[ ! -f "$wg_soak_summary_json" ]]; then
    errors+=("wg_soak_summary_json file not found: $wg_soak_summary_json")
  fi
  if [[ "$wg_soak_status" != "ok" ]]; then
    errors+=("wg_soak_status is not ok (status=${wg_soak_status:-unset}, top_failure_class=${wg_soak_top_failure_class:-none}, top_failure_count=$wg_soak_top_failure_count)")
  fi
fi

if (( wg_soak_rounds_failed > max_wg_soak_failed_rounds )); then
  errors+=("wg_soak_rounds_failed exceeds limit (${wg_soak_rounds_failed} > ${max_wg_soak_failed_rounds})")
fi

if [[ "$require_wg_validate_udp_source" == "1" ]]; then
  if [[ -z "$wg_validate_summary_json" ]]; then
    errors+=("require-wg-validate-udp-source requested but wg_validate_summary_json path is missing")
  elif [[ ! -f "$wg_validate_summary_json" ]]; then
    errors+=("require-wg-validate-udp-source requested but wg_validate_summary_json file not found: $wg_validate_summary_json")
  elif [[ "$wg_validate_client_inner_source" != "udp" ]]; then
    errors+=("wg validate summary does not show UDP inner source (client_inner_source=${wg_validate_client_inner_source:-unset})")
  fi
fi

if [[ "$require_wg_validate_strict_distinct" == "1" ]]; then
  if [[ -z "$wg_validate_summary_json" ]]; then
    errors+=("require-wg-validate-strict-distinct requested but wg_validate_summary_json path is missing")
  elif [[ ! -f "$wg_validate_summary_json" ]]; then
    errors+=("require-wg-validate-strict-distinct requested but wg_validate_summary_json file not found: $wg_validate_summary_json")
  elif [[ "$wg_validate_strict_distinct" != "1" ]]; then
    errors+=("wg validate summary does not show strict distinct mode enabled (strict_distinct=${wg_validate_strict_distinct})")
  fi
fi

if [[ "$require_wg_soak_diversity_pass" == "1" ]]; then
  if [[ -z "$wg_soak_summary_json" ]]; then
    errors+=("require-wg-soak-diversity-pass requested but wg_soak_summary_json path is missing")
  elif [[ ! -f "$wg_soak_summary_json" ]]; then
    errors+=("require-wg-soak-diversity-pass requested but wg_soak_summary_json file not found: $wg_soak_summary_json")
  elif [[ "$wg_soak_selection_diversity_failed" != "0" ]]; then
    errors+=("wg soak diversity summary indicates failure (selection_diversity_failed=${wg_soak_selection_diversity_failed})")
  fi
fi

if (( min_wg_soak_selection_lines > 0 || min_wg_soak_entry_operators > 0 || min_wg_soak_exit_operators > 0 || min_wg_soak_cross_operator_pairs > 0 )); then
  if [[ -z "$wg_soak_summary_json" ]]; then
    errors+=("wg soak diversity floors requested but wg_soak_summary_json path is missing")
  elif [[ ! -f "$wg_soak_summary_json" ]]; then
    errors+=("wg soak diversity floors requested but wg_soak_summary_json file not found: $wg_soak_summary_json")
  else
    if (( wg_soak_selection_lines < min_wg_soak_selection_lines )); then
      errors+=("wg soak selection_lines_total below floor (${wg_soak_selection_lines} < ${min_wg_soak_selection_lines})")
    fi
    if (( wg_soak_selection_entry_operators < min_wg_soak_entry_operators )); then
      errors+=("wg soak selection_entry_operators below floor (${wg_soak_selection_entry_operators} < ${min_wg_soak_entry_operators})")
    fi
    if (( wg_soak_selection_exit_operators < min_wg_soak_exit_operators )); then
      errors+=("wg soak selection_exit_operators below floor (${wg_soak_selection_exit_operators} < ${min_wg_soak_exit_operators})")
    fi
    if (( wg_soak_selection_cross_operator_pairs < min_wg_soak_cross_operator_pairs )); then
      errors+=("wg soak selection_cross_operator_pairs below floor (${wg_soak_selection_cross_operator_pairs} < ${min_wg_soak_cross_operator_pairs})")
    fi
  fi
fi

if [[ -n "$run_report_json" ]]; then
  if [[ "$run_report_status" == "ok" && "$run_report_final_rc" != "0" ]]; then
    errors+=("run report status/final_rc mismatch (status=ok but final_rc=$run_report_final_rc)")
  fi
  if [[ "$run_report_status" == "fail" && "$run_report_final_rc" == "0" ]]; then
    errors+=("run report status/final_rc mismatch (status=fail but final_rc=0)")
  fi
fi

if [[ "$require_preflight_ok" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    errors+=("require-preflight-ok requested but run report JSON was not provided")
  elif [[ "$run_report_preflight_status" != "ok" ]]; then
    errors+=("run report preflight status is not ok (value=${run_report_preflight_status:-unset})")
  fi
fi

if [[ "$require_bundle_ok" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    errors+=("require-bundle-ok requested but run report JSON was not provided")
  elif [[ "$run_report_bundle_status" != "ok" ]]; then
    errors+=("run report bundle status is not ok (value=${run_report_bundle_status:-unset})")
  fi
fi

if [[ "$require_integrity_ok" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    errors+=("require-integrity-ok requested but run report JSON was not provided")
  elif [[ "$run_report_integrity_status" != "ok" ]]; then
    errors+=("run report integrity status is not ok (value=${run_report_integrity_status:-unset})")
  fi
fi

if [[ "$require_signoff_ok" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    errors+=("require-signoff-ok requested but run report JSON was not provided")
  else
    if [[ "$run_report_signoff_enabled" != "true" ]]; then
      errors+=("run report signoff stage is not enabled (enabled=${run_report_signoff_enabled:-unset})")
    fi
    if [[ "$run_report_signoff_rc" != "0" ]]; then
      errors+=("run report signoff rc is not 0 (rc=$run_report_signoff_rc)")
    fi
  fi
fi

if [[ "$require_incident_snapshot_on_fail" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    errors+=("require-incident-snapshot-on-fail requested but run report JSON was not provided")
  else
    if [[ "$run_report_status" == "fail" || "$run_report_final_rc" != "0" ]]; then
      if [[ "$run_report_incident_enabled_on_fail" != "true" ]]; then
        errors+=("run report incident snapshot is not enabled on fail (enabled_on_fail=${run_report_incident_enabled_on_fail:-unset})")
      fi
      if [[ "$run_report_incident_status" != "ok" ]]; then
        errors+=("run report incident snapshot status is not ok (status=${run_report_incident_status:-unset}, rc=$run_report_incident_rc)")
      fi
    fi
  fi
fi

if [[ "$require_incident_snapshot_artifacts" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    errors+=("require-incident-snapshot-artifacts requested but run report JSON was not provided")
  else
    if [[ "$run_report_incident_status" == "ok" ]]; then
      if [[ -z "$run_report_incident_bundle_dir" ]]; then
        errors+=("run report incident snapshot bundle_dir missing")
      elif [[ ! -d "$run_report_incident_bundle_dir" ]]; then
        errors+=("run report incident snapshot bundle_dir not found: $run_report_incident_bundle_dir")
      fi
      if [[ -z "$run_report_incident_bundle_tar" ]]; then
        errors+=("run report incident snapshot bundle_tar missing")
      elif [[ ! -f "$run_report_incident_bundle_tar" ]]; then
        errors+=("run report incident snapshot bundle_tar not found: $run_report_incident_bundle_tar")
      fi
      if [[ -z "$run_report_incident_summary_json" ]]; then
        errors+=("run report incident snapshot summary_json missing")
      elif [[ ! -f "$run_report_incident_summary_json" ]]; then
        errors+=("run report incident snapshot summary_json not found: $run_report_incident_summary_json")
      elif ! jq -e . "$run_report_incident_summary_json" >/dev/null 2>&1; then
        errors+=("run report incident snapshot summary_json is not valid JSON: $run_report_incident_summary_json")
      fi
      if [[ -z "$run_report_incident_report_md" ]]; then
        errors+=("run report incident snapshot report_md missing")
      elif [[ ! -f "$run_report_incident_report_md" ]]; then
        errors+=("run report incident snapshot report_md not found: $run_report_incident_report_md")
      fi
      if [[ -n "$run_report_incident_attachment_manifest" && ! -f "$run_report_incident_attachment_manifest" ]]; then
        errors+=("run report incident snapshot attachment_manifest not found: $run_report_incident_attachment_manifest")
      fi
      if [[ -n "$run_report_incident_attachment_skipped" && ! -f "$run_report_incident_attachment_skipped" ]]; then
        errors+=("run report incident snapshot attachment_skipped not found: $run_report_incident_attachment_skipped")
      fi
    elif [[ "$run_report_status" == "fail" || "$run_report_final_rc" != "0" ]]; then
      errors+=("run report incident snapshot artifacts requested but snapshot status is not ok (status=${run_report_incident_status:-unset})")
    fi
  fi
fi

if ((incident_snapshot_min_attachment_count > 0 || incident_snapshot_max_skipped_count >= 0)); then
  if [[ -z "$run_report_json" ]]; then
    errors+=("incident snapshot attachment policy requested but run report JSON was not provided")
  elif [[ "$run_report_status" == "fail" || "$run_report_final_rc" != "0" ]]; then
    if [[ "$run_report_incident_status" != "ok" ]]; then
      errors+=("incident snapshot attachment policy requested but snapshot status is not ok (status=${run_report_incident_status:-unset})")
    else
      if ((incident_snapshot_min_attachment_count > 0 && run_report_incident_attachment_count < incident_snapshot_min_attachment_count)); then
        errors+=("incident snapshot attachment_count below floor (${run_report_incident_attachment_count} < ${incident_snapshot_min_attachment_count})")
      fi
      if ((incident_snapshot_max_skipped_count >= 0 && run_report_incident_attachment_skipped_count > incident_snapshot_max_skipped_count)); then
        errors+=("incident snapshot skipped attachment count exceeds policy (${run_report_incident_attachment_skipped_count} > ${incident_snapshot_max_skipped_count})")
      fi
    fi
  fi
fi

if [[ -n "$run_report_json" ]]; then
  echo "[prod-gate-check] run_report_json=$run_report_json"
fi
echo "[prod-gate-check] gate_summary_json=$gate_summary_json"
echo "[prod-gate-check] status=${gate_status:-unset} failed_step=${failed_step:-none} failed_rc=$failed_rc started_at_utc=${gate_started_at_utc:-unset} finished_at_utc=${gate_finished_at_utc:-unset}"
echo "[prod-gate-check] steps control_validate=${step_control_validate:-unset} control_soak=${step_control_soak:-unset} prod_wg_validate=${step_prod_wg_validate:-unset} prod_wg_soak=${step_prod_wg_soak:-unset}"
echo "[prod-gate-check] wg_validate status=${wg_validate_status:-unset} failed_step=${wg_validate_failed_step:-none} summary=${wg_validate_summary_json:-unset}"
echo "[prod-gate-check] wg_soak status=${wg_soak_status:-unset} rounds_failed=${wg_soak_rounds_failed} top_failure_class=${wg_soak_top_failure_class:-none} top_failure_count=${wg_soak_top_failure_count} summary=${wg_soak_summary_json:-unset}"
echo "[prod-gate-check] freshness max_evidence_age_sec=${max_evidence_age_sec} gate_started_at_utc=${gate_started_at_utc:-unset} gate_finished_at_utc=${gate_finished_at_utc:-unset} run_report_generated_at_utc=${run_report_generated_at_utc:-unset} wg_validate_started_at_utc=${wg_validate_started_at_utc:-unset} wg_validate_finished_at_utc=${wg_validate_finished_at_utc:-unset} wg_soak_summary_generated_at_utc=${wg_soak_summary_generated_at_utc:-unset}"
echo "[prod-gate-check] wg_validate_evidence client_inner_source=${wg_validate_client_inner_source:-unset} strict_distinct=${wg_validate_strict_distinct}"
echo "[prod-gate-check] wg_soak_diversity selection_lines_total=${wg_soak_selection_lines} selection_entry_operators=${wg_soak_selection_entry_operators} selection_exit_operators=${wg_soak_selection_exit_operators} selection_cross_operator_pairs=${wg_soak_selection_cross_operator_pairs} selection_diversity_failed=${wg_soak_selection_diversity_failed}"
if [[ -n "$run_report_json" ]]; then
  echo "[prod-gate-check] run_report status=${run_report_status:-unset} generated_at_utc=${run_report_generated_at_utc:-unset} final_rc=${run_report_final_rc} preflight=${run_report_preflight_status:-unset} bundle=${run_report_bundle_status:-unset} integrity=${run_report_integrity_status:-unset} signoff_enabled=${run_report_signoff_enabled:-unset} signoff_rc=${run_report_signoff_rc} incident_enabled_on_fail=${run_report_incident_enabled_on_fail:-unset} incident_status=${run_report_incident_status:-unset} incident_rc=${run_report_incident_rc}"
  if [[ -n "$run_report_incident_summary_json" || -n "$run_report_incident_report_md" || -n "$run_report_incident_attachment_manifest" || -n "$run_report_incident_attachment_skipped" ]]; then
    echo "[prod-gate-check] incident_handoff source_run_report=${run_report_json:-unset} summary_json=${run_report_incident_summary_json:-unset} report_md=${run_report_incident_report_md:-unset} attachment_manifest=${run_report_incident_attachment_manifest:-unset} attachment_skipped=${run_report_incident_attachment_skipped:-unset} attachment_count=${run_report_incident_attachment_count} attachment_skipped_count=${run_report_incident_attachment_skipped_count}"
  fi
fi

if ((${#errors[@]} > 0)); then
  echo "[prod-gate-check] failed with ${#errors[@]} issue(s):"
  for err in "${errors[@]}"; do
    echo "  - $err"
  done
  if [[ -n "$run_report_incident_summary_json" || -n "$run_report_incident_report_md" || -n "$run_report_incident_bundle_dir" || -n "$run_report_incident_bundle_tar" || -n "$run_report_incident_attachment_manifest" || -n "$run_report_incident_attachment_skipped" ]]; then
    echo "[prod-gate-check] incident handoff artifacts:"
    [[ -n "$run_report_incident_bundle_dir" ]] && echo "  - bundle_dir=$run_report_incident_bundle_dir"
    [[ -n "$run_report_incident_bundle_tar" ]] && echo "  - bundle_tar=$run_report_incident_bundle_tar"
    [[ -n "$run_report_incident_summary_json" ]] && echo "  - summary_json=$run_report_incident_summary_json"
    [[ -n "$run_report_incident_report_md" ]] && echo "  - report_md=$run_report_incident_report_md"
    [[ -n "$run_report_incident_attachment_manifest" ]] && echo "  - attachment_manifest=$run_report_incident_attachment_manifest"
    [[ -n "$run_report_incident_attachment_skipped" ]] && echo "  - attachment_skipped=$run_report_incident_attachment_skipped"
    echo "  - attachment_count=$run_report_incident_attachment_count"
    echo "  - attachment_skipped_count=$run_report_incident_attachment_skipped_count"
  fi
  if [[ "$show_json" == "1" ]]; then
    echo "[prod-gate-check] gate summary payload:"
    cat "$gate_summary_json"
  fi
  exit 1
fi

echo "[prod-gate-check] ok"
if [[ "$show_json" == "1" ]]; then
  echo "[prod-gate-check] gate summary payload:"
  cat "$gate_summary_json"
fi
