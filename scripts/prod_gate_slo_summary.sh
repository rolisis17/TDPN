#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_gate_slo_summary.sh \
    [--run-report-json PATH] \
    [--bundle-dir PATH] \
    [--gate-summary-json PATH] \
    [--wg-validate-summary-json PATH] \
    [--wg-soak-summary-json PATH] \
    [--require-full-sequence [0|1]] \
    [--require-wg-validate-ok [0|1]] \
    [--require-wg-soak-ok [0|1]] \
    [--max-wg-soak-failed-rounds N] \
    [--require-preflight-ok [0|1]] \
    [--require-bundle-ok [0|1]] \
    [--require-integrity-ok [0|1]] \
    [--require-signoff-ok [0|1]] \
    [--require-incident-snapshot-on-fail [0|1]] \
    [--require-incident-snapshot-artifacts [0|1]] \
    [--require-wg-validate-udp-source [0|1]] \
    [--require-wg-validate-strict-distinct [0|1]] \
    [--require-wg-soak-diversity-pass [0|1]] \
    [--min-wg-soak-selection-lines N] \
    [--min-wg-soak-entry-operators N] \
    [--min-wg-soak-exit-operators N] \
    [--min-wg-soak-cross-operator-pairs N] \
    [--fail-on-no-go [0|1]] \
    [--show-json [0|1]]

Purpose:
  Print a compact production gate SLO summary and GO/NO-GO decision.

Notes:
  - Recommended input: --run-report-json from three-machine-prod-bundle.
  - By default this summarizes gate/WG outcome only.
  - Enable additional run-report checks with:
    --require-preflight-ok=1 --require-bundle-ok=1 --require-integrity-ok=1 \
    --require-signoff-ok=1 --require-incident-snapshot-on-fail=1
  - Use --fail-on-no-go=1 to return non-zero on NO-GO.
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

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

abs_path() {
  local path="$1"
  path="$(trim "$path")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" = /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

path_exists01() {
  local path="$1"
  if [[ -n "$path" && -e "$path" ]]; then
    echo "1"
  else
    echo "0"
  fi
}

json_valid01() {
  local path="$1"
  if [[ -n "$path" && -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    echo "1"
  else
    echo "0"
  fi
}

json_string() {
  local file="$1"
  local expr="$2"
  if [[ -z "$file" || ! -f "$file" ]]; then
    printf '%s' ""
    return
  fi
  jq -r "$expr // \"\"" "$file" 2>/dev/null || true
}

json_int() {
  local file="$1"
  local expr="$2"
  local value
  value="$(json_string "$file" "$expr")"
  if [[ -z "$value" || ! "$value" =~ ^-?[0-9]+$ ]]; then
    echo "0"
    return
  fi
  echo "$value"
}

json_bool01() {
  local file="$1"
  local expr="$2"
  local value
  value="$(json_string "$file" "$expr")"
  case "$value" in
    true|1) echo "1" ;;
    false|0|"") echo "0" ;;
    *) echo "0" ;;
  esac
}

run_report_json=""
bundle_dir=""
gate_summary_json=""
wg_validate_summary_json=""
wg_soak_summary_json=""
require_full_sequence="${PROD_GATE_SLO_REQUIRE_FULL_SEQUENCE:-1}"
require_wg_validate_ok="${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_OK:-1}"
require_wg_soak_ok="${PROD_GATE_SLO_REQUIRE_WG_SOAK_OK:-1}"
max_wg_soak_failed_rounds="${PROD_GATE_SLO_MAX_WG_SOAK_FAILED_ROUNDS:-0}"
require_preflight_ok="${PROD_GATE_SLO_REQUIRE_PREFLIGHT_OK:-0}"
require_bundle_ok="${PROD_GATE_SLO_REQUIRE_BUNDLE_OK:-0}"
require_integrity_ok="${PROD_GATE_SLO_REQUIRE_INTEGRITY_OK:-0}"
require_signoff_ok="${PROD_GATE_SLO_REQUIRE_SIGNOFF_OK:-0}"
require_incident_snapshot_on_fail="${PROD_GATE_SLO_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-0}"
require_incident_snapshot_artifacts="${PROD_GATE_SLO_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-0}"
require_wg_validate_udp_source="${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_UDP_SOURCE:-0}"
require_wg_validate_strict_distinct="${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_STRICT_DISTINCT:-0}"
require_wg_soak_diversity_pass="${PROD_GATE_SLO_REQUIRE_WG_SOAK_DIVERSITY_PASS:-0}"
min_wg_soak_selection_lines="${PROD_GATE_SLO_MIN_WG_SOAK_SELECTION_LINES:-0}"
min_wg_soak_entry_operators="${PROD_GATE_SLO_MIN_WG_SOAK_ENTRY_OPERATORS:-0}"
min_wg_soak_exit_operators="${PROD_GATE_SLO_MIN_WG_SOAK_EXIT_OPERATORS:-0}"
min_wg_soak_cross_operator_pairs="${PROD_GATE_SLO_MIN_WG_SOAK_CROSS_OPERATOR_PAIRS:-0}"
fail_on_no_go="${PROD_GATE_SLO_FAIL_ON_NO_GO:-0}"
show_json="${PROD_GATE_SLO_SHOW_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-report-json)
      run_report_json="${2:-}"
      shift 2
      ;;
    --bundle-dir)
      bundle_dir="${2:-}"
      shift 2
      ;;
    --gate-summary-json)
      gate_summary_json="${2:-}"
      shift 2
      ;;
    --wg-validate-summary-json)
      wg_validate_summary_json="${2:-}"
      shift 2
      ;;
    --wg-soak-summary-json)
      wg_soak_summary_json="${2:-}"
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
    --max-wg-soak-failed-rounds)
      max_wg_soak_failed_rounds="${2:-}"
      shift 2
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
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--show-json" "$show_json"
if [[ ! "$max_wg_soak_failed_rounds" =~ ^[0-9]+$ ]]; then
  echo "--max-wg-soak-failed-rounds must be an integer >= 0"
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

run_report_json="$(trim "$run_report_json")"
bundle_dir="$(trim "$bundle_dir")"
gate_summary_json="$(trim "$gate_summary_json")"
wg_validate_summary_json="$(trim "$wg_validate_summary_json")"
wg_soak_summary_json="$(trim "$wg_soak_summary_json")"

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
  if [[ -z "$bundle_dir" ]]; then
    bundle_dir="$(json_string "$run_report_json" '.bundle_dir')"
  fi
  if [[ -z "$gate_summary_json" ]]; then
    gate_summary_json="$(json_string "$run_report_json" '.gate_summary_json')"
  fi
  if [[ -z "$wg_validate_summary_json" ]]; then
    wg_validate_summary_json="$(json_string "$run_report_json" '.wg_validate_summary_json')"
  fi
  if [[ -z "$wg_soak_summary_json" ]]; then
    wg_soak_summary_json="$(json_string "$run_report_json" '.wg_soak_summary_json')"
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

if [[ -z "$wg_validate_summary_json" ]]; then
  wg_validate_summary_json="$(json_string "$gate_summary_json" '.wg_validate_summary_json')"
fi
if [[ -z "$wg_soak_summary_json" ]]; then
  wg_soak_summary_json="$(json_string "$gate_summary_json" '.wg_soak_summary_json')"
fi
wg_validate_client_inner_source="$(json_string "$wg_validate_summary_json" '.client_inner_source')"
wg_validate_strict_distinct="$(json_bool01 "$wg_validate_summary_json" '.strict_distinct')"
wg_soak_selection_lines="$(json_int "$wg_soak_summary_json" '.selection_lines_total')"
wg_soak_selection_entry_operators="$(json_int "$wg_soak_summary_json" '.selection_entry_operators')"
wg_soak_selection_exit_operators="$(json_int "$wg_soak_summary_json" '.selection_exit_operators')"
wg_soak_selection_cross_operator_pairs="$(json_int "$wg_soak_summary_json" '.selection_cross_operator_pairs')"
wg_soak_selection_diversity_failed="$(json_int "$wg_soak_summary_json" '.selection_diversity_failed')"

gate_status="$(json_string "$gate_summary_json" '.status')"
failed_step="$(json_string "$gate_summary_json" '.failed_step')"
failed_rc="$(json_int "$gate_summary_json" '.failed_rc')"
step_control_validate="$(json_string "$gate_summary_json" '.steps.control_validate')"
step_control_soak="$(json_string "$gate_summary_json" '.steps.control_soak')"
step_prod_wg_validate="$(json_string "$gate_summary_json" '.steps.prod_wg_validate')"
step_prod_wg_soak="$(json_string "$gate_summary_json" '.steps.prod_wg_soak')"
wg_validate_status="$(json_string "$gate_summary_json" '.wg_validate_status')"
wg_validate_failed_step="$(json_string "$gate_summary_json" '.wg_validate_failed_step')"
wg_soak_status="$(json_string "$gate_summary_json" '.wg_soak_status')"
wg_soak_rounds_passed="$(json_int "$gate_summary_json" '.wg_soak_rounds_passed')"
wg_soak_rounds_failed="$(json_int "$gate_summary_json" '.wg_soak_rounds_failed')"
wg_soak_top_failure_class="$(json_string "$gate_summary_json" '.wg_soak_top_failure_class')"
wg_soak_top_failure_count="$(json_int "$gate_summary_json" '.wg_soak_top_failure_count')"

preflight_enabled="0"
preflight_status=""
preflight_rc="0"
bundle_status=""
bundle_rc="0"
integrity_enabled="0"
integrity_status=""
integrity_rc="0"
signoff_enabled="0"
signoff_rc="0"
incident_status=""
incident_rc="0"
incident_bundle_dir=""
incident_bundle_tar=""
incident_summary_json=""
incident_report_md=""
incident_attachment_manifest=""
incident_attachment_skipped=""
incident_attachment_count="0"
incident_summary_exists="0"
incident_summary_valid_json="0"
incident_report_exists="0"
incident_enabled_on_fail="0"
run_report_status=""
run_report_final_rc="0"

if [[ -n "$run_report_json" ]]; then
  run_report_status="$(json_string "$run_report_json" '.status')"
  run_report_final_rc="$(json_int "$run_report_json" '.final_rc')"
  preflight_enabled="$(json_bool01 "$run_report_json" '.preflight.enabled')"
  preflight_status="$(json_string "$run_report_json" '.preflight.status')"
  preflight_rc="$(json_int "$run_report_json" '.preflight.rc')"
  bundle_status="$(json_string "$run_report_json" '.bundle.status')"
  bundle_rc="$(json_int "$run_report_json" '.bundle.rc')"
  integrity_enabled="$(json_bool01 "$run_report_json" '.integrity_verify.enabled')"
  integrity_status="$(json_string "$run_report_json" '.integrity_verify.status')"
  integrity_rc="$(json_int "$run_report_json" '.integrity_verify.rc')"
  signoff_enabled="$(json_bool01 "$run_report_json" '.signoff.enabled')"
  signoff_rc="$(json_int "$run_report_json" '.signoff.rc')"
  incident_enabled_on_fail="$(json_bool01 "$run_report_json" '.incident_snapshot.enabled_on_fail')"
  incident_status="$(json_string "$run_report_json" '.incident_snapshot.status')"
  incident_rc="$(json_int "$run_report_json" '.incident_snapshot.rc')"
  incident_bundle_dir="$(abs_path "$(json_string "$run_report_json" '.incident_snapshot.bundle_dir')")"
  incident_bundle_tar="$(abs_path "$(json_string "$run_report_json" '.incident_snapshot.bundle_tar')")"
  incident_summary_json="$(abs_path "$(json_string "$run_report_json" '.incident_snapshot.summary_json')")"
  incident_report_md="$(abs_path "$(json_string "$run_report_json" '.incident_snapshot.report_md')")"
  incident_attachment_manifest="$(abs_path "$(json_string "$run_report_json" '.incident_snapshot.attachment_manifest')")"
  incident_attachment_skipped="$(abs_path "$(json_string "$run_report_json" '.incident_snapshot.attachment_skipped')")"
  incident_attachment_count="$(json_int "$run_report_json" '.incident_snapshot.attachment_count')"
  incident_summary_exists="$(path_exists01 "$incident_summary_json")"
  incident_summary_valid_json="$(json_valid01 "$incident_summary_json")"
  incident_report_exists="$(path_exists01 "$incident_report_md")"
fi

declare -a reasons=()

if [[ "$gate_status" != "ok" ]]; then
  reasons+=("gate status is not ok (status=${gate_status:-unset}, failed_step=${failed_step:-none}, failed_rc=$failed_rc)")
fi
if [[ "$require_full_sequence" == "1" ]]; then
  if [[ "$step_control_validate" != "ok" ]]; then
    reasons+=("control_validate step is not ok (value=${step_control_validate:-unset})")
  fi
  if [[ "$step_control_soak" != "ok" ]]; then
    reasons+=("control_soak step is not ok (value=${step_control_soak:-unset})")
  fi
  if [[ "$step_prod_wg_validate" != "ok" ]]; then
    reasons+=("prod_wg_validate step is not ok (value=${step_prod_wg_validate:-unset})")
  fi
  if [[ "$step_prod_wg_soak" != "ok" ]]; then
    reasons+=("prod_wg_soak step is not ok (value=${step_prod_wg_soak:-unset})")
  fi
fi
if [[ "$require_wg_validate_ok" == "1" && "$wg_validate_status" != "ok" ]]; then
  reasons+=("wg_validate_status is not ok (status=${wg_validate_status:-unset}, failed_step=${wg_validate_failed_step:-none})")
fi
if [[ "$require_wg_soak_ok" == "1" && "$wg_soak_status" != "ok" ]]; then
  reasons+=("wg_soak_status is not ok (status=${wg_soak_status:-unset}, top_failure_class=${wg_soak_top_failure_class:-none}, top_failure_count=$wg_soak_top_failure_count)")
fi
if ((wg_soak_rounds_failed > max_wg_soak_failed_rounds)); then
  reasons+=("wg_soak_rounds_failed exceeds limit (${wg_soak_rounds_failed} > ${max_wg_soak_failed_rounds})")
fi
if [[ "$require_wg_validate_udp_source" == "1" ]]; then
  if [[ -z "$wg_validate_summary_json" || ! -f "$wg_validate_summary_json" ]]; then
    reasons+=("wg_validate summary missing for UDP-source policy (${wg_validate_summary_json:-unset})")
  elif [[ "$wg_validate_client_inner_source" != "udp" ]]; then
    reasons+=("wg validate summary does not show UDP inner source (client_inner_source=${wg_validate_client_inner_source:-unset})")
  fi
fi
if [[ "$require_wg_validate_strict_distinct" == "1" ]]; then
  if [[ -z "$wg_validate_summary_json" || ! -f "$wg_validate_summary_json" ]]; then
    reasons+=("wg_validate summary missing for strict-distinct policy (${wg_validate_summary_json:-unset})")
  elif [[ "$wg_validate_strict_distinct" != "1" ]]; then
    reasons+=("wg validate summary does not show strict distinct mode enabled (strict_distinct=${wg_validate_strict_distinct})")
  fi
fi
if [[ "$require_wg_soak_diversity_pass" == "1" ]]; then
  if [[ -z "$wg_soak_summary_json" || ! -f "$wg_soak_summary_json" ]]; then
    reasons+=("wg_soak summary missing for diversity-pass policy (${wg_soak_summary_json:-unset})")
  elif [[ "$wg_soak_selection_diversity_failed" != "0" ]]; then
    reasons+=("wg soak diversity summary indicates failure (selection_diversity_failed=${wg_soak_selection_diversity_failed})")
  fi
fi
if ((min_wg_soak_selection_lines > 0 || min_wg_soak_entry_operators > 0 || min_wg_soak_exit_operators > 0 || min_wg_soak_cross_operator_pairs > 0)); then
  if [[ -z "$wg_soak_summary_json" || ! -f "$wg_soak_summary_json" ]]; then
    reasons+=("wg_soak summary missing for diversity floor checks (${wg_soak_summary_json:-unset})")
  else
    if ((wg_soak_selection_lines < min_wg_soak_selection_lines)); then
      reasons+=("wg soak selection_lines_total below floor (${wg_soak_selection_lines} < ${min_wg_soak_selection_lines})")
    fi
    if ((wg_soak_selection_entry_operators < min_wg_soak_entry_operators)); then
      reasons+=("wg soak selection_entry_operators below floor (${wg_soak_selection_entry_operators} < ${min_wg_soak_entry_operators})")
    fi
    if ((wg_soak_selection_exit_operators < min_wg_soak_exit_operators)); then
      reasons+=("wg soak selection_exit_operators below floor (${wg_soak_selection_exit_operators} < ${min_wg_soak_exit_operators})")
    fi
    if ((wg_soak_selection_cross_operator_pairs < min_wg_soak_cross_operator_pairs)); then
      reasons+=("wg soak selection_cross_operator_pairs below floor (${wg_soak_selection_cross_operator_pairs} < ${min_wg_soak_cross_operator_pairs})")
    fi
  fi
fi

if [[ "$require_preflight_ok" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    reasons+=("preflight policy requested but run report is missing")
  elif [[ "$preflight_enabled" != "1" || "$preflight_status" != "ok" || "$preflight_rc" != "0" ]]; then
    reasons+=("preflight is not ok (enabled=$preflight_enabled status=${preflight_status:-unset} rc=$preflight_rc)")
  fi
fi
if [[ "$require_bundle_ok" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    reasons+=("bundle policy requested but run report is missing")
  elif [[ "$bundle_status" != "ok" || "$bundle_rc" != "0" ]]; then
    reasons+=("bundle stage is not ok (status=${bundle_status:-unset} rc=$bundle_rc)")
  fi
fi
if [[ "$require_integrity_ok" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    reasons+=("integrity policy requested but run report is missing")
  elif [[ "$integrity_enabled" != "1" || "$integrity_status" != "ok" || "$integrity_rc" != "0" ]]; then
    reasons+=("integrity verify is not ok (enabled=$integrity_enabled status=${integrity_status:-unset} rc=$integrity_rc)")
  fi
fi
if [[ "$require_signoff_ok" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    reasons+=("signoff policy requested but run report is missing")
  elif [[ "$signoff_enabled" != "1" || "$signoff_rc" != "0" ]]; then
    reasons+=("signoff is not ok (enabled=$signoff_enabled rc=$signoff_rc)")
  fi
fi

if [[ "$require_incident_snapshot_on_fail" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    reasons+=("incident snapshot policy requested but run report is missing")
  else
    if [[ "$run_report_status" == "fail" || "$run_report_final_rc" != "0" ]]; then
      if [[ "$incident_enabled_on_fail" != "1" ]]; then
        reasons+=("incident snapshot is not enabled on fail (enabled_on_fail=$incident_enabled_on_fail)")
      fi
      if [[ "$incident_status" != "ok" || "$incident_rc" != "0" ]]; then
        reasons+=("incident snapshot is not ok (status=${incident_status:-unset} rc=$incident_rc)")
      fi
    fi
  fi
fi

if [[ "$require_incident_snapshot_artifacts" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    reasons+=("incident snapshot artifact policy requested but run report is missing")
  else
    if [[ "$incident_status" == "ok" ]]; then
      if [[ -z "$incident_bundle_dir" || ! -d "$incident_bundle_dir" ]]; then
        reasons+=("incident snapshot bundle_dir missing/unreadable (${incident_bundle_dir:-unset})")
      fi
      if [[ -z "$incident_bundle_tar" || ! -f "$incident_bundle_tar" ]]; then
        reasons+=("incident snapshot bundle_tar missing/unreadable (${incident_bundle_tar:-unset})")
      fi
      if [[ -z "$incident_summary_json" ]]; then
        reasons+=("incident snapshot summary_json missing")
      elif [[ "$incident_summary_exists" != "1" ]]; then
        reasons+=("incident snapshot summary_json missing/unreadable (${incident_summary_json:-unset})")
      elif [[ "$incident_summary_valid_json" != "1" ]]; then
        reasons+=("incident snapshot summary_json is invalid JSON (${incident_summary_json:-unset})")
      fi
      if [[ -z "$incident_report_md" ]]; then
        reasons+=("incident snapshot report_md missing")
      elif [[ "$incident_report_exists" != "1" ]]; then
        reasons+=("incident snapshot report_md missing/unreadable (${incident_report_md:-unset})")
      fi
      if [[ -n "$incident_attachment_manifest" && ! -f "$incident_attachment_manifest" ]]; then
        reasons+=("incident snapshot attachment_manifest missing/unreadable (${incident_attachment_manifest:-unset})")
      fi
      if [[ -n "$incident_attachment_skipped" && ! -f "$incident_attachment_skipped" ]]; then
        reasons+=("incident snapshot attachment_skipped missing/unreadable (${incident_attachment_skipped:-unset})")
      fi
    elif [[ "$run_report_status" == "fail" || "$run_report_final_rc" != "0" ]]; then
      reasons+=("incident snapshot artifacts requested but incident snapshot is not ok (status=${incident_status:-unset})")
    fi
  fi
fi

decision="GO"
if ((${#reasons[@]} > 0)); then
  decision="NO-GO"
fi

if [[ -n "$run_report_json" ]]; then
  echo "[prod-gate-slo] run_report_json=$run_report_json"
fi
echo "[prod-gate-slo] gate_summary_json=$gate_summary_json"
echo "[prod-gate-slo] decision=$decision"
echo "[prod-gate-slo] gate status=${gate_status:-unset} failed_step=${failed_step:-none} failed_rc=$failed_rc"
echo "[prod-gate-slo] steps control_validate=${step_control_validate:-unset} control_soak=${step_control_soak:-unset} prod_wg_validate=${step_prod_wg_validate:-unset} prod_wg_soak=${step_prod_wg_soak:-unset}"
echo "[prod-gate-slo] wg_validate status=${wg_validate_status:-unset} failed_step=${wg_validate_failed_step:-none} summary=${wg_validate_summary_json:-unset}"
echo "[prod-gate-slo] wg_soak status=${wg_soak_status:-unset} rounds_passed=${wg_soak_rounds_passed} rounds_failed=${wg_soak_rounds_failed} top_failure_class=${wg_soak_top_failure_class:-none} top_failure_count=${wg_soak_top_failure_count} summary=${wg_soak_summary_json:-unset}"
echo "[prod-gate-slo] wg_validate_evidence client_inner_source=${wg_validate_client_inner_source:-unset} strict_distinct=${wg_validate_strict_distinct}"
echo "[prod-gate-slo] wg_soak_diversity selection_lines_total=${wg_soak_selection_lines} selection_entry_operators=${wg_soak_selection_entry_operators} selection_exit_operators=${wg_soak_selection_exit_operators} selection_cross_operator_pairs=${wg_soak_selection_cross_operator_pairs} selection_diversity_failed=${wg_soak_selection_diversity_failed}"
if [[ -n "$run_report_json" ]]; then
  echo "[prod-gate-slo] run_report preflight=${preflight_status:-unset}/${preflight_rc} bundle=${bundle_status:-unset}/${bundle_rc} integrity=${integrity_status:-unset}/${integrity_rc} signoff_enabled=${signoff_enabled} signoff_rc=${signoff_rc} incident_enabled_on_fail=${incident_enabled_on_fail} incident_snapshot=${incident_status:-unset}/${incident_rc}"
  if [[ -n "$incident_bundle_dir" ]]; then
    echo "[prod-gate-slo] incident_snapshot_bundle_dir=$incident_bundle_dir"
  fi
  if [[ -n "$incident_bundle_tar" ]]; then
    echo "[prod-gate-slo] incident_snapshot_bundle_tar=$incident_bundle_tar"
  fi
  if [[ -n "$incident_attachment_manifest" ]]; then
    echo "[prod-gate-slo] incident_snapshot_attachment_manifest=$incident_attachment_manifest"
  fi
  if [[ -n "$incident_attachment_skipped" ]]; then
    echo "[prod-gate-slo] incident_snapshot_attachment_skipped=$incident_attachment_skipped"
  fi
  if [[ -n "$incident_summary_json" || -n "$incident_report_md" || -n "$incident_attachment_manifest" || -n "$incident_attachment_skipped" ]]; then
    echo "[prod-gate-slo] incident_handoff source_summary_json=${gate_summary_json:-unset} source_run_report=${run_report_json:-unset} summary_json=${incident_summary_json:-unset} report_md=${incident_report_md:-unset} attachment_manifest=${incident_attachment_manifest:-unset} attachment_skipped=${incident_attachment_skipped:-unset} attachment_count=${incident_attachment_count}"
  fi
fi

if ((${#reasons[@]} > 0)); then
  echo "[prod-gate-slo] no-go reasons (${#reasons[@]}):"
  for reason in "${reasons[@]}"; do
    echo "  - $reason"
  done
fi

if [[ "$show_json" == "1" ]]; then
  echo "[prod-gate-slo] gate summary payload:"
  cat "$gate_summary_json"
  if [[ -n "$run_report_json" ]]; then
    echo "[prod-gate-slo] run report payload:"
    cat "$run_report_json"
  fi
fi

if [[ "$decision" == "NO-GO" && "$fail_on_no_go" == "1" ]]; then
  exit 1
fi
exit 0
