#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CYCLE_SCRIPT="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_CYCLE_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_stability_cycle.sh}"
EVIDENCE_PACK_SCRIPT="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_EVIDENCE_PACK_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_stability_evidence_pack.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_default_gate_stability_live_archive_and_pack.sh \
    --host-a HOST \
    --host-b HOST \
    [--campaign-subject INVITE_KEY | --subject INVITE_KEY] \
    [--reports-dir DIR] \
    [--fail-on-no-go [0|1]] \
    [--stability-summary-json PATH | --run-summary-json PATH] \
    [--stability-check-summary-json PATH | --check-summary-json PATH] \
    [--stability-cycle-summary-json PATH | --cycle-summary-json PATH] \
    [--evidence-pack-summary-json PATH] \
    [--evidence-pack-report-md PATH] \
    [--archive-root DIR] \
    [--archive-summary-json PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run profile-default stability cycle, generate stability evidence-pack from the
  resulting artifacts, then archive outputs in one deterministic command.

Behavior:
  1) profile_default_gate_stability_cycle.sh
  2) profile_default_gate_stability_evidence_pack.sh
  3) deterministic archive copy + archive summary JSON

Fail-Closed Contract:
  - Emits a machine-readable bundle summary with:
      failure_reason_code
      failure_substep
      reasons[]
      prerequisites.missing_prerequisites[]
      prerequisites.missing_artifacts[]
  - Missing prerequisites or required artifacts force a non-zero exit.

Notes:
  - Stage scripts can be overridden with:
      PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_CYCLE_SCRIPT
      PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_EVIDENCE_PACK_SCRIPT
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
  value="${value//$'\r'/}"
  value="${value//$'\n'/}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
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

normalize_status_01() {
  local status
  status="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$status" in
    pass|ok|success) printf '%s' "pass" ;;
    warn|warning) printf '%s' "warn" ;;
    fail|failed|error) printf '%s' "fail" ;;
    *) printf '%s' "$status" ;;
  esac
}

normalize_decision_01() {
  local decision
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

json_array_from_lines() {
  local line=""
  local normalized=""
  local -a lines=()
  for line in "$@"; do
    normalized="$(trim "$line")"
    if [[ -n "$normalized" ]]; then
      lines+=("$normalized")
    fi
  done
  if [[ "${#lines[@]}" -eq 0 ]]; then
    printf '%s' "[]"
    return
  fi
  printf '%s\n' "${lines[@]}" | jq -R . | jq -s .
}

evaluate_summary_json() {
  local summary_path="$1"
  local expected_schema_id="$2"
  local pre_fingerprint="$3"
  local require_decision="$4"

  local exists="false"
  local valid_json="false"
  local schema_id=""
  local schema_valid="false"
  local written_fresh="false"
  local status_raw=""
  local status_norm=""
  local rc_json="null"
  local decision_raw=""
  local decision_norm=""
  local post_fingerprint=""
  local -a errors=()

  if [[ -f "$summary_path" ]]; then
    exists="true"
  else
    errors+=("summary file missing: $summary_path")
  fi

  if [[ "$exists" == "true" ]]; then
    if [[ "$(json_file_valid_01 "$summary_path")" == "1" ]]; then
      valid_json="true"
    else
      errors+=("summary JSON is missing/invalid object")
    fi
  fi

  if [[ "$valid_json" == "true" ]]; then
    schema_id="$(jq -r 'if (.schema.id | type) == "string" then .schema.id else "" end' "$summary_path" 2>/dev/null || true)"
    if [[ "$schema_id" == "$expected_schema_id" ]]; then
      schema_valid="true"
    else
      errors+=("schema.id mismatch (expected=$expected_schema_id actual=${schema_id:-unset})")
    fi

    post_fingerprint="$(file_fingerprint_01 "$summary_path")"
    if [[ -z "$pre_fingerprint" && -n "$post_fingerprint" ]]; then
      written_fresh="true"
    elif [[ -n "$post_fingerprint" && "$post_fingerprint" != "$pre_fingerprint" ]]; then
      written_fresh="true"
    fi
    if [[ "$written_fresh" != "true" ]]; then
      errors+=("summary file was not refreshed by current run")
    fi

    status_raw="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$summary_path" 2>/dev/null || true)"
    status_norm="$(normalize_status_01 "$status_raw")"
    if [[ -z "$status_norm" ]]; then
      errors+=("summary status missing/invalid")
    fi

    rc_json="$(jq -r '
      if (.rc | type) == "number" then .rc
      elif (.final_rc | type) == "number" then .final_rc
      else "null"
      end
    ' "$summary_path" 2>/dev/null || printf '%s' "null")"
    if [[ "$rc_json" == "null" ]]; then
      errors+=("summary rc missing/invalid")
    fi

    decision_raw="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$summary_path" 2>/dev/null || true)"
    decision_norm="$(normalize_decision_01 "$decision_raw")"
    if [[ "$require_decision" == "1" && -z "$decision_norm" ]]; then
      errors+=("summary decision missing/invalid GO|NO-GO")
    fi
  fi

  local errors_json
  errors_json="$(json_array_from_lines "${errors[@]:-}")"

  local usable="false"
  if [[ "$exists" == "true" \
    && "$valid_json" == "true" \
    && "$schema_valid" == "true" \
    && "$written_fresh" == "true" ]]; then
    if [[ "$require_decision" == "1" ]]; then
      if [[ "$decision_norm" == "GO" || "$decision_norm" == "NO-GO" ]]; then
        usable="true"
      fi
    else
      usable="true"
    fi
  fi

  jq -n \
    --arg path "$summary_path" \
    --arg expected_schema_id "$expected_schema_id" \
    --arg exists "$exists" \
    --arg valid_json "$valid_json" \
    --arg schema_id "$schema_id" \
    --arg schema_valid "$schema_valid" \
    --arg written_fresh "$written_fresh" \
    --arg status_raw "$status_raw" \
    --arg status_norm "$status_norm" \
    --arg decision_raw "$decision_raw" \
    --arg decision_norm "$decision_norm" \
    --argjson rc "$rc_json" \
    --arg require_decision "$require_decision" \
    --arg usable "$usable" \
    --argjson errors "$errors_json" \
    '{
      path: $path,
      expected_schema_id: $expected_schema_id,
      exists: ($exists == "true"),
      valid_json: ($valid_json == "true"),
      schema_id: (if $schema_id == "" then null else $schema_id end),
      schema_valid: ($schema_valid == "true"),
      fresh_after_run: ($written_fresh == "true"),
      status: (if $status_norm == "" then null else $status_norm end),
      status_raw: (if $status_raw == "" then null else $status_raw end),
      rc: (if ($rc | type) == "number" then $rc else null end),
      decision: (if $decision_norm == "" then null else $decision_norm end),
      decision_raw: (if $decision_raw == "" then null else $decision_raw end),
      decision_required: ($require_decision == "1"),
      usable: ($usable == "true"),
      errors: $errors
    }'
}

need_cmd bash
need_cmd jq
need_cmd date
need_cmd cksum
need_cmd cp
need_cmd mkdir
need_cmd basename

host_a="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_HOST_A:-${PROFILE_DEFAULT_GATE_STABILITY_HOST_A:-}}"
host_b="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_HOST_B:-${PROFILE_DEFAULT_GATE_STABILITY_HOST_B:-}}"
campaign_subject="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_CAMPAIGN_SUBJECT:-${PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT:-}}"
subject_alias=""
reports_dir="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_REPORTS_DIR:-${REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}}"
fail_on_no_go="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_FAIL_ON_NO_GO:-1}"
run_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_RUN_SUMMARY_JSON:-}"
check_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_CHECK_SUMMARY_JSON:-}"
cycle_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_CYCLE_SUMMARY_JSON:-}"
evidence_pack_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_EVIDENCE_PACK_SUMMARY_JSON:-}"
evidence_pack_report_md="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_EVIDENCE_PACK_REPORT_MD:-}"
archive_root="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_ARCHIVE_ROOT:-}"
archive_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_ARCHIVE_SUMMARY_JSON:-}"
summary_json="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_SUMMARY_JSON:-}"
print_summary_json="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_PRINT_SUMMARY_JSON:-0}"

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
      shift 2
      ;;
    --campaign-subject=*)
      campaign_subject="${1#*=}"
      shift
      ;;
    --subject)
      require_value_or_die "$1" "$#"
      subject_alias="${2:-}"
      shift 2
      ;;
    --subject=*)
      subject_alias="${1#*=}"
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
    --stability-summary-json|--run-summary-json)
      require_value_or_die "$1" "$#"
      run_summary_json="${2:-}"
      shift 2
      ;;
    --stability-summary-json=*|--run-summary-json=*)
      run_summary_json="${1#*=}"
      shift
      ;;
    --stability-check-summary-json|--check-summary-json)
      require_value_or_die "$1" "$#"
      check_summary_json="${2:-}"
      shift 2
      ;;
    --stability-check-summary-json=*|--check-summary-json=*)
      check_summary_json="${1#*=}"
      shift
      ;;
    --stability-cycle-summary-json|--cycle-summary-json)
      require_value_or_die "$1" "$#"
      cycle_summary_json="${2:-}"
      shift 2
      ;;
    --stability-cycle-summary-json=*|--cycle-summary-json=*)
      cycle_summary_json="${1#*=}"
      shift
      ;;
    --evidence-pack-summary-json)
      require_value_or_die "$1" "$#"
      evidence_pack_summary_json="${2:-}"
      shift 2
      ;;
    --evidence-pack-summary-json=*)
      evidence_pack_summary_json="${1#*=}"
      shift
      ;;
    --evidence-pack-report-md)
      require_value_or_die "$1" "$#"
      evidence_pack_report_md="${2:-}"
      shift 2
      ;;
    --evidence-pack-report-md=*)
      evidence_pack_report_md="${1#*=}"
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
    --archive-summary-json)
      require_value_or_die "$1" "$#"
      archive_summary_json="${2:-}"
      shift 2
      ;;
    --archive-summary-json=*)
      archive_summary_json="${1#*=}"
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

host_a="$(trim "$host_a")"
host_b="$(trim "$host_b")"
campaign_subject="$(trim "$campaign_subject")"
subject_alias="$(trim "$subject_alias")"
reports_dir="$(abs_path "$reports_dir")"
fail_on_no_go="$(trim "$fail_on_no_go")"
run_summary_json="$(trim "$run_summary_json")"
check_summary_json="$(trim "$check_summary_json")"
cycle_summary_json="$(trim "$cycle_summary_json")"
evidence_pack_summary_json="$(trim "$evidence_pack_summary_json")"
evidence_pack_report_md="$(trim "$evidence_pack_report_md")"
archive_root="$(trim "$archive_root")"
archive_summary_json="$(trim "$archive_summary_json")"
summary_json="$(trim "$summary_json")"
print_summary_json="$(trim "$print_summary_json")"
CYCLE_SCRIPT="$(abs_path "$CYCLE_SCRIPT")"
EVIDENCE_PACK_SCRIPT="$(abs_path "$EVIDENCE_PACK_SCRIPT")"

bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

if [[ -n "$campaign_subject" && -n "$subject_alias" && "$campaign_subject" != "$subject_alias" ]]; then
  echo "conflicting subject values: --campaign-subject and --subject must match when both are provided"
  exit 2
fi
if [[ -z "$campaign_subject" && -n "$subject_alias" ]]; then
  campaign_subject="$subject_alias"
fi

if [[ -z "$run_summary_json" ]]; then
  run_summary_json="$reports_dir/profile_default_gate_stability_summary.json"
fi
if [[ -z "$check_summary_json" ]]; then
  check_summary_json="$reports_dir/profile_default_gate_stability_check_summary.json"
fi
if [[ -z "$cycle_summary_json" ]]; then
  cycle_summary_json="$reports_dir/profile_default_gate_stability_cycle_summary.json"
fi
if [[ -z "$evidence_pack_summary_json" ]]; then
  evidence_pack_summary_json="$reports_dir/profile_default_gate_stability_evidence_pack_summary.json"
fi
if [[ -z "$evidence_pack_report_md" ]]; then
  evidence_pack_report_md="$reports_dir/profile_default_gate_stability_evidence_pack_report.md"
fi
if [[ -z "$archive_root" ]]; then
  archive_root="$reports_dir/profile_default_gate_stability_live_archive"
fi
if [[ -z "$archive_summary_json" ]]; then
  archive_summary_json="$reports_dir/profile_default_gate_stability_live_archive_summary.json"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/profile_default_gate_stability_live_archive_and_pack_summary.json"
fi

run_summary_json="$(abs_path "$run_summary_json")"
check_summary_json="$(abs_path "$check_summary_json")"
cycle_summary_json="$(abs_path "$cycle_summary_json")"
evidence_pack_summary_json="$(abs_path "$evidence_pack_summary_json")"
evidence_pack_report_md="$(abs_path "$evidence_pack_report_md")"
archive_root="$(abs_path "$archive_root")"
archive_summary_json="$(abs_path "$archive_summary_json")"
summary_json="$(abs_path "$summary_json")"

mkdir -p "$reports_dir" "$(dirname "$summary_json")" "$(dirname "$archive_summary_json")" "$archive_root"

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
cycle_log="$reports_dir/profile_default_gate_stability_live_archive_and_pack_${run_stamp}_cycle.log"
evidence_pack_log="$reports_dir/profile_default_gate_stability_live_archive_and_pack_${run_stamp}_evidence_pack.log"
archive_log="$reports_dir/profile_default_gate_stability_live_archive_and_pack_${run_stamp}_archive.log"

cycle_stage_attempted="false"
cycle_stage_status="skip"
cycle_stage_rc=0
cycle_stage_eval='{}'
cycle_stage_command=""

evidence_pack_stage_attempted="false"
evidence_pack_stage_status="skip"
evidence_pack_stage_rc=0
evidence_pack_stage_eval='{}'
evidence_pack_stage_command=""

archive_stage_attempted="false"
archive_stage_status="skip"
archive_stage_rc=0
archive_dir=""
archive_candidate_count=0
archive_copied_count=0
archive_missing_required_count=0
archive_copy_error_count=0
archive_missing_required_artifacts_json='[]'
archive_missing_required_artifact_paths_json='[]'
archive_copy_errors_json='[]'

final_status="fail"
final_rc=1
final_decision="NO-GO"
failure_reason_code=""
failure_substep=""
failure_reason=""

declare -a reasons=()
declare -a missing_prerequisites=()
declare -a missing_artifacts=()

if [[ ! -f "$CYCLE_SCRIPT" || ! -r "$CYCLE_SCRIPT" ]]; then
  missing_prerequisites+=("cycle_script_missing_or_unreadable:$CYCLE_SCRIPT")
  reasons+=("preflight: cycle script missing/unreadable: $CYCLE_SCRIPT")
fi
if [[ ! -f "$EVIDENCE_PACK_SCRIPT" || ! -r "$EVIDENCE_PACK_SCRIPT" ]]; then
  missing_prerequisites+=("evidence_pack_script_missing_or_unreadable:$EVIDENCE_PACK_SCRIPT")
  reasons+=("preflight: evidence-pack script missing/unreadable: $EVIDENCE_PACK_SCRIPT")
fi
if [[ -z "$host_a" ]]; then
  missing_prerequisites+=("host_a_missing")
  reasons+=("preflight: --host-a is required")
fi
if [[ -z "$host_b" ]]; then
  missing_prerequisites+=("host_b_missing")
  reasons+=("preflight: --host-b is required")
fi
if [[ -z "$campaign_subject" ]]; then
  missing_prerequisites+=("campaign_subject_missing")
  reasons+=("preflight: --campaign-subject/--subject is required")
fi

if [[ "${#missing_prerequisites[@]}" -gt 0 ]]; then
  failure_reason_code="preflight_missing_prerequisites"
  failure_substep="preflight_validation_failed"
  failure_reason="${reasons[0]}"
  final_status="fail"
  final_rc=2
else
  cycle_stage_attempted="true"
  cycle_stage_command="$(render_command \
    bash "$CYCLE_SCRIPT" \
    --host-a "$host_a" \
    --host-b "$host_b" \
    --campaign-subject "$campaign_subject" \
    --reports-dir "$reports_dir" \
    --stability-summary-json "$run_summary_json" \
    --stability-check-summary-json "$check_summary_json" \
    --summary-json "$cycle_summary_json" \
    --fail-on-no-go "$fail_on_no_go" \
    --print-summary-json 0
  )"

  cycle_pre_fp="$(file_fingerprint_01 "$cycle_summary_json")"
  set +e
  bash "$CYCLE_SCRIPT" \
    --host-a "$host_a" \
    --host-b "$host_b" \
    --campaign-subject "$campaign_subject" \
    --reports-dir "$reports_dir" \
    --stability-summary-json "$run_summary_json" \
    --stability-check-summary-json "$check_summary_json" \
    --summary-json "$cycle_summary_json" \
    --fail-on-no-go "$fail_on_no_go" \
    --print-summary-json 0 \
    >"$cycle_log" 2>&1
  cycle_stage_rc=$?
  set -e

  cycle_stage_eval="$(evaluate_summary_json "$cycle_summary_json" "profile_default_gate_stability_cycle_summary" "$cycle_pre_fp" "1")"
  cycle_usable="$(jq -r '.usable' <<<"$cycle_stage_eval")"
  cycle_decision="$(jq -r '.decision // ""' <<<"$cycle_stage_eval")"
  cycle_status_norm="$(jq -r '.status // ""' <<<"$cycle_stage_eval")"

  if [[ "$cycle_stage_rc" -ne 0 || "$cycle_usable" != "true" ]]; then
    cycle_stage_status="fail"
  elif [[ "$cycle_decision" == "NO-GO" || "$cycle_status_norm" == "warn" ]]; then
    cycle_stage_status="warn"
  else
    cycle_stage_status="pass"
  fi

  if [[ "$cycle_stage_rc" -ne 0 ]]; then
    reasons+=("cycle: command failed rc=$cycle_stage_rc")
  fi
  while IFS= read -r err_line; do
    [[ -n "$err_line" ]] || continue
    reasons+=("cycle: $err_line")
  done < <(jq -r '.errors[]?' <<<"$cycle_stage_eval")

  if [[ "$cycle_usable" == "true" ]]; then
    evidence_pack_stage_attempted="true"
    evidence_pack_stage_command="$(render_command \
      bash "$EVIDENCE_PACK_SCRIPT" \
      --reports-dir "$reports_dir" \
      --stability-summary-json "$run_summary_json" \
      --stability-check-summary-json "$check_summary_json" \
      --cycle-summary-json "$cycle_summary_json" \
      --summary-json "$evidence_pack_summary_json" \
      --report-md "$evidence_pack_report_md" \
      --fail-on-no-go "$fail_on_no_go" \
      --print-summary-json 0
    )"

    pack_pre_fp="$(file_fingerprint_01 "$evidence_pack_summary_json")"
    set +e
    bash "$EVIDENCE_PACK_SCRIPT" \
      --reports-dir "$reports_dir" \
      --stability-summary-json "$run_summary_json" \
      --stability-check-summary-json "$check_summary_json" \
      --cycle-summary-json "$cycle_summary_json" \
      --summary-json "$evidence_pack_summary_json" \
      --report-md "$evidence_pack_report_md" \
      --fail-on-no-go "$fail_on_no_go" \
      --print-summary-json 0 \
      >"$evidence_pack_log" 2>&1
    evidence_pack_stage_rc=$?
    set -e

    evidence_pack_stage_eval="$(evaluate_summary_json "$evidence_pack_summary_json" "profile_default_gate_stability_evidence_pack_summary" "$pack_pre_fp" "1")"
    pack_usable="$(jq -r '.usable' <<<"$evidence_pack_stage_eval")"
    pack_decision="$(jq -r '.decision // ""' <<<"$evidence_pack_stage_eval")"
    pack_status_norm="$(jq -r '.status // ""' <<<"$evidence_pack_stage_eval")"

    if [[ "$evidence_pack_stage_rc" -ne 0 || "$pack_usable" != "true" ]]; then
      evidence_pack_stage_status="fail"
    elif [[ "$pack_decision" == "NO-GO" || "$pack_status_norm" == "warn" ]]; then
      evidence_pack_stage_status="warn"
    else
      evidence_pack_stage_status="pass"
    fi

    if [[ "$evidence_pack_stage_rc" -ne 0 ]]; then
      reasons+=("evidence_pack: command failed rc=$evidence_pack_stage_rc")
    fi
    while IFS= read -r err_line; do
      [[ -n "$err_line" ]] || continue
      reasons+=("evidence_pack: $err_line")
    done < <(jq -r '.errors[]?' <<<"$evidence_pack_stage_eval")
  else
    reasons+=("evidence_pack: skipped because cycle summary is unusable")
  fi

  archive_stage_attempted="true"
  archive_dir="$archive_root/profile_default_gate_stability_live_archive_${run_stamp}"
  mkdir -p "$archive_dir"
  : >"$archive_log"

  declare -a archive_missing_required_artifacts=()
  declare -a archive_missing_required_artifact_paths=()
  declare -a archive_copy_errors=()

  archive_keys=(
    "run_summary_json"
    "check_summary_json"
    "cycle_summary_json"
    "evidence_pack_summary_json"
    "evidence_pack_report_md"
    "cycle_log"
    "evidence_pack_log"
  )
  archive_paths=(
    "$run_summary_json"
    "$check_summary_json"
    "$cycle_summary_json"
    "$evidence_pack_summary_json"
    "$evidence_pack_report_md"
    "$cycle_log"
    "$evidence_pack_log"
  )
  archive_required_flags=(1 1 1 1 0 0 0)

  archive_candidate_count="${#archive_keys[@]}"
  idx=0
  for key in "${archive_keys[@]}"; do
    src="${archive_paths[$idx]}"
    required="${archive_required_flags[$idx]}"
    if [[ -f "$src" ]]; then
      dest="$archive_dir/$(basename "$src")"
      if cp -f "$src" "$dest"; then
        archive_copied_count=$((archive_copied_count + 1))
        echo "copied key=$key src=$src dest=$dest" >>"$archive_log"
      else
        archive_copy_error_count=$((archive_copy_error_count + 1))
        archive_copy_errors+=("$key:$src")
        echo "copy_error key=$key src=$src" >>"$archive_log"
      fi
    else
      if [[ "$required" == "1" ]]; then
        archive_missing_required_count=$((archive_missing_required_count + 1))
        archive_missing_required_artifacts+=("$key")
        archive_missing_required_artifact_paths+=("$key:$src")
        echo "missing_required key=$key path=$src" >>"$archive_log"
      else
        echo "missing_optional key=$key path=$src" >>"$archive_log"
      fi
    fi
    idx=$((idx + 1))
  done

  archive_missing_required_artifacts_json="$(json_array_from_lines "${archive_missing_required_artifacts[@]:-}")"
  archive_missing_required_artifact_paths_json="$(json_array_from_lines "${archive_missing_required_artifact_paths[@]:-}")"
  archive_copy_errors_json="$(json_array_from_lines "${archive_copy_errors[@]:-}")"

  if (( archive_copy_error_count > 0 )); then
    archive_stage_status="fail"
    archive_stage_rc=1
    reasons+=("archive: copy errors while archiving required outputs")
    while IFS= read -r err_line; do
      [[ -n "$err_line" ]] || continue
      reasons+=("archive: copy error $err_line")
    done < <(jq -r '.[]?' <<<"$archive_copy_errors_json")
  elif (( archive_missing_required_count > 0 )); then
    archive_stage_status="fail"
    archive_stage_rc=1
    while IFS= read -r missing_key; do
      [[ -n "$missing_key" ]] || continue
      reasons+=("archive: missing required artifact $missing_key")
      missing_artifacts+=("$missing_key")
    done < <(jq -r '.[]?' <<<"$archive_missing_required_artifacts_json")
  else
    archive_stage_status="pass"
    archive_stage_rc=0
  fi

  jq -n \
    --arg generated_at_utc "$(timestamp_utc)" \
    --arg status "$archive_stage_status" \
    --arg archive_root "$archive_root" \
    --arg archive_dir "$archive_dir" \
    --arg archive_log "$archive_log" \
    --arg summary_json "$archive_summary_json" \
    --argjson rc "$archive_stage_rc" \
    --argjson candidate_count "$archive_candidate_count" \
    --argjson copied_count "$archive_copied_count" \
    --argjson missing_required_count "$archive_missing_required_count" \
    --argjson copy_error_count "$archive_copy_error_count" \
    --argjson missing_required_artifacts "$archive_missing_required_artifacts_json" \
    --argjson missing_required_artifact_paths "$archive_missing_required_artifact_paths_json" \
    --argjson copy_errors "$archive_copy_errors_json" \
    '{
      version: 1,
      schema: { id: "profile_default_gate_stability_live_archive_summary" },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      summary: {
        candidate_count: $candidate_count,
        copied_count: $copied_count,
        missing_required_count: $missing_required_count,
        copy_error_count: $copy_error_count
      },
      missing_required_artifacts: $missing_required_artifacts,
      missing_required_artifact_paths: $missing_required_artifact_paths,
      copy_errors: $copy_errors,
      artifacts: {
        archive_root: $archive_root,
        archive_dir: $archive_dir,
        archive_log: $archive_log,
        summary_json: $summary_json
      }
    }' >"$archive_summary_json"

  if [[ "$cycle_stage_status" == "fail" ]]; then
    final_status="fail"
    final_rc="$cycle_stage_rc"
    if [[ "$final_rc" -eq 0 ]]; then
      final_rc=1
    fi
    failure_reason_code="cycle_stage_failed"
    failure_substep="cycle_stage_failed"
    failure_reason="stability cycle stage failed"
  elif [[ "$evidence_pack_stage_attempted" == "true" && "$evidence_pack_stage_status" == "fail" ]]; then
    final_status="fail"
    final_rc="$evidence_pack_stage_rc"
    if [[ "$final_rc" -eq 0 ]]; then
      final_rc=1
    fi
    failure_reason_code="evidence_pack_stage_failed"
    failure_substep="evidence_pack_stage_failed"
    failure_reason="stability evidence-pack stage failed"
  elif [[ "$archive_stage_status" == "fail" ]]; then
    final_status="fail"
    final_rc="$archive_stage_rc"
    if [[ "$final_rc" -eq 0 ]]; then
      final_rc=1
    fi
    if (( archive_missing_required_count > 0 )); then
      failure_reason_code="archive_missing_required_artifacts"
      failure_substep="archive_missing_required_artifacts"
      failure_reason="archive stage missing required artifacts"
    else
      failure_reason_code="archive_copy_failed"
      failure_substep="archive_copy_failed"
      failure_reason="archive stage encountered copy errors"
    fi
  else
    warn_detected="false"
    if [[ "$cycle_stage_status" == "warn" || "$evidence_pack_stage_status" == "warn" ]]; then
      warn_detected="true"
    fi
    if [[ "$warn_detected" == "true" ]]; then
      final_status="warn"
      final_rc=0
    else
      final_status="pass"
      final_rc=0
    fi
  fi

  pack_decision_final="$(jq -r '.decision // ""' <<<"$evidence_pack_stage_eval")"
  cycle_decision_final="$(jq -r '.decision // ""' <<<"$cycle_stage_eval")"
  if [[ -n "$pack_decision_final" ]]; then
    final_decision="$pack_decision_final"
  elif [[ -n "$cycle_decision_final" ]]; then
    final_decision="$cycle_decision_final"
  else
    final_decision="NO-GO"
  fi
fi

missing_prerequisites_json="$(json_array_from_lines "${missing_prerequisites[@]:-}")"
missing_artifacts_json="$(json_array_from_lines "${missing_artifacts[@]:-}")"
reasons_json="$(json_array_from_lines "${reasons[@]:-}")"

if [[ "$failure_reason" == "" && "$(jq -r 'length' <<<"$reasons_json")" -gt 0 ]]; then
  failure_reason="$(jq -r '.[0]' <<<"$reasons_json")"
fi

if [[ "$failure_reason_code" == "" && "$final_status" == "fail" ]]; then
  failure_reason_code="bundle_failed"
fi
if [[ "$failure_substep" == "" && "$final_status" == "fail" ]]; then
  failure_substep="$failure_reason_code"
fi

if [[ "$cycle_stage_eval" == "{}" ]]; then
  cycle_stage_eval='{"usable":false,"errors":[]}'
fi
if [[ "$evidence_pack_stage_eval" == "{}" ]]; then
  evidence_pack_stage_eval='{"usable":false,"errors":[]}'
fi

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$final_status" \
  --arg decision "$final_decision" \
  --arg failure_reason_code "$failure_reason_code" \
  --arg failure_substep "$failure_substep" \
  --arg failure_reason "$failure_reason" \
  --arg host_a "$host_a" \
  --arg host_b "$host_b" \
  --arg reports_dir "$reports_dir" \
  --arg cycle_script "$CYCLE_SCRIPT" \
  --arg evidence_pack_script "$EVIDENCE_PACK_SCRIPT" \
  --arg cycle_command "$cycle_stage_command" \
  --arg evidence_pack_command "$evidence_pack_stage_command" \
  --arg cycle_log "$cycle_log" \
  --arg evidence_pack_log "$evidence_pack_log" \
  --arg archive_log "$archive_log" \
  --arg run_summary_json "$run_summary_json" \
  --arg check_summary_json "$check_summary_json" \
  --arg cycle_summary_json "$cycle_summary_json" \
  --arg evidence_pack_summary_json "$evidence_pack_summary_json" \
  --arg evidence_pack_report_md "$evidence_pack_report_md" \
  --arg archive_root "$archive_root" \
  --arg archive_dir "$archive_dir" \
  --arg archive_summary_json "$archive_summary_json" \
  --arg summary_json_path "$summary_json" \
  --argjson rc "$final_rc" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --argjson cycle_stage_attempted "$cycle_stage_attempted" \
  --arg cycle_stage_status "$cycle_stage_status" \
  --argjson cycle_stage_rc "$cycle_stage_rc" \
  --argjson evidence_pack_stage_attempted "$evidence_pack_stage_attempted" \
  --arg evidence_pack_stage_status "$evidence_pack_stage_status" \
  --argjson evidence_pack_stage_rc "$evidence_pack_stage_rc" \
  --argjson archive_stage_attempted "$archive_stage_attempted" \
  --arg archive_stage_status "$archive_stage_status" \
  --argjson archive_stage_rc "$archive_stage_rc" \
  --argjson archive_candidate_count "$archive_candidate_count" \
  --argjson archive_copied_count "$archive_copied_count" \
  --argjson archive_missing_required_count "$archive_missing_required_count" \
  --argjson archive_copy_error_count "$archive_copy_error_count" \
  --argjson archive_missing_required_artifacts "$archive_missing_required_artifacts_json" \
  --argjson archive_missing_required_artifact_paths "$archive_missing_required_artifact_paths_json" \
  --argjson archive_copy_errors "$archive_copy_errors_json" \
  --argjson missing_prerequisites "$missing_prerequisites_json" \
  --argjson missing_artifacts "$missing_artifacts_json" \
  --argjson reasons "$reasons_json" \
  --argjson cycle_summary "$cycle_stage_eval" \
  --argjson evidence_pack_summary "$evidence_pack_stage_eval" \
  '{
    version: 1,
    schema: {
      id: "profile_default_gate_stability_live_archive_and_pack_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    decision: $decision,
    failure_reason_code: (if $failure_reason_code == "" then null else $failure_reason_code end),
    failure_substep: (if $failure_substep == "" then null else $failure_substep end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    reasons: $reasons,
    inputs: {
      host_a: $host_a,
      host_b: $host_b,
      reports_dir: $reports_dir,
      fail_on_no_go: ($fail_on_no_go == 1)
    },
    prerequisites: {
      ok: (($missing_prerequisites | length) == 0 and ($missing_artifacts | length) == 0),
      missing_prerequisites: $missing_prerequisites,
      missing_prerequisites_count: ($missing_prerequisites | length),
      missing_artifacts: $missing_artifacts,
      missing_artifacts_count: ($missing_artifacts | length)
    },
    stages: {
      cycle: {
        attempted: ($cycle_stage_attempted == true),
        status: $cycle_stage_status,
        rc: $cycle_stage_rc,
        script: $cycle_script,
        command: (if $cycle_command == "" then null else $cycle_command end),
        log: $cycle_log,
        summary_json: $cycle_summary_json,
        run_summary_json: $run_summary_json,
        check_summary_json: $check_summary_json,
        summary: $cycle_summary
      },
      evidence_pack: {
        attempted: ($evidence_pack_stage_attempted == true),
        status: $evidence_pack_stage_status,
        rc: $evidence_pack_stage_rc,
        script: $evidence_pack_script,
        command: (if $evidence_pack_command == "" then null else $evidence_pack_command end),
        log: $evidence_pack_log,
        summary_json: $evidence_pack_summary_json,
        report_md: $evidence_pack_report_md,
        summary: (
          if $evidence_pack_stage_attempted == true then $evidence_pack_summary
          else null
          end
        )
      },
      archive: {
        attempted: ($archive_stage_attempted == true),
        status: $archive_stage_status,
        rc: $archive_stage_rc,
        archive_root: $archive_root,
        archive_dir: (if $archive_dir == "" then null else $archive_dir end),
        archive_log: (if $archive_stage_attempted == true then $archive_log else null end),
        summary_json: $archive_summary_json,
        candidate_count: $archive_candidate_count,
        copied_count: $archive_copied_count,
        missing_required_count: $archive_missing_required_count,
        copy_error_count: $archive_copy_error_count,
        missing_required_artifacts: $archive_missing_required_artifacts,
        missing_required_artifact_paths: $archive_missing_required_artifact_paths,
        copy_errors: $archive_copy_errors
      }
    },
    outcome: {
      action: (
        if $status == "pass" then "bundle_complete"
        elif $status == "warn" then "bundle_warn_only"
        else "bundle_failed"
        end
      ),
      should_promote: ($status == "pass" and $decision == "GO" and $rc == 0)
    },
    artifacts: {
      summary_json: $summary_json_path,
      archive_summary_json: $archive_summary_json,
      archive_root: $archive_root,
      archive_dir: (if $archive_dir == "" then null else $archive_dir end),
      run_summary_json: $run_summary_json,
      check_summary_json: $check_summary_json,
      cycle_summary_json: $cycle_summary_json,
      evidence_pack_summary_json: $evidence_pack_summary_json,
      evidence_pack_report_md: $evidence_pack_report_md,
      cycle_log: $cycle_log,
      evidence_pack_log: $evidence_pack_log
    }
  }' >"$summary_json"

echo "[profile-default-gate-stability-live-archive-and-pack] status=$final_status rc=$final_rc decision=$final_decision summary_json=$summary_json"
if [[ "$final_status" == "fail" ]]; then
  echo "[profile-default-gate-stability-live-archive-and-pack] fail_substep=${failure_substep:-none} failure_reason_code=${failure_reason_code:-none}"
fi
echo "[profile-default-gate-stability-live-archive-and-pack] archive_summary_json=$archive_summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
