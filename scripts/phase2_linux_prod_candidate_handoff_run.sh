#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase2_linux_prod_candidate_handoff_run.sh \
    [--reports-dir DIR] \
    [--signoff-summary-json PATH] \
    [--handoff-summary-json PATH] \
    [--summary-json PATH] \
    [--resume [0|1]] \
    [--run-phase2-linux-prod-candidate-signoff [0|1]] \
    [--run-phase2-linux-prod-candidate-handoff-check [0|1]] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--signoff-<arg> ...] \
    [--handoff-<arg> ...]

Purpose:
  One-command Phase-2 Linux production-candidate handoff runner:
    1) phase2_linux_prod_candidate_signoff.sh
    2) phase2_linux_prod_candidate_handoff_check.sh

Notes:
  - Wrapper-owned flags are reserved; stage pass-through uses prefixes:
      --signoff-...  -> forwarded to phase2_linux_prod_candidate_signoff.sh
      --handoff-...  -> forwarded to phase2_linux_prod_candidate_handoff_check.sh
  - Dry-run forwards --dry-run 1 to the signoff stage.
    The handoff check still executes against the generated summaries.
  - Resume mode (--resume 1) reuses pass summaries for signoff + handoff
    stages when available and contract-valid.
  - Dry-run relaxes handoff requirements to 0 unless explicitly supplied.
  - The handoff check runs even when the signoff stage fails.
USAGE
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

resolve_path_with_base() {
  local candidate="${1:-}"
  local base_file="${2:-}"
  local base_dir=""
  if [[ -z "$candidate" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$candidate" == /* ]]; then
    printf '%s' "$candidate"
    return
  fi
  if [[ -n "$base_file" ]]; then
    base_dir="$(cd "$(dirname "$base_file")" && pwd)"
    if [[ -f "$base_dir/$candidate" ]]; then
      printf '%s' "$base_dir/$candidate"
      return
    fi
  fi
  printf '%s' "$ROOT_DIR/$candidate"
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

array_has_arg() {
  local needle="$1"
  shift
  local arg
  for arg in "$@"; do
    if [[ "$arg" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

json_file_valid() {
  local path="$1"
  [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1
}

signoff_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    type == "object"
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (.schema.id // "") == "phase2_linux_prod_candidate_signoff_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) | floor) == (.schema.major // 0)
    and (.status | type) == "string"
    and (.rc | type) == "number"
    and (.steps.phase2_linux_prod_candidate_run | type) == "object"
    and (.steps.roadmap_progress_report | type) == "object"
    and ((.steps.phase2_linux_prod_candidate_run.status | type) == "string")
    and ((.steps.phase2_linux_prod_candidate_run.rc | type) == "number")
    and ((.steps.phase2_linux_prod_candidate_run.command_rc | type) == "number")
    and ((.steps.phase2_linux_prod_candidate_run.contract_valid | type) == "boolean")
    and ((.steps.phase2_linux_prod_candidate_run.artifacts.summary_json | type) == "string")
    and ((.steps.roadmap_progress_report.status | type) == "string")
    and ((.steps.roadmap_progress_report.rc | type) == "number")
    and ((.steps.roadmap_progress_report.command_rc | type) == "number")
    and ((.steps.roadmap_progress_report.contract_valid | type) == "boolean")
    and ((.steps.roadmap_progress_report.artifacts.summary_json | type) == "string")
    and (
      (.status == "pass" and .rc == 0)
      or (.status == "warn" and .rc == 0)
      or (.status == "fail" and .rc != 0)
    )
  ' "$path" >/dev/null 2>&1
}

handoff_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    type == "object"
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (.schema.id // "") == "phase2_linux_prod_candidate_handoff_check_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) | floor) == (.schema.major // 0)
    and (.status | type) == "string"
    and (.rc | type) == "number"
    and (.handoff | type) == "object"
    and (.decision | type) == "object"
    and (
      (.status == "pass" and .rc == 0)
      or (.status == "fail" and .rc != 0)
    )
  ' "$path" >/dev/null 2>&1
}

summary_pass_contract_valid() {
  local path="$1"
  local contract_fn="$2"
  if ! "$contract_fn" "$path"; then
    return 1
  fi
  jq -e '
    (.status | type) == "string"
    and .status == "pass"
    and (.rc | type) == "number"
    and .rc == 0
  ' "$path" >/dev/null 2>&1
}

run_stage_capture() {
  local label="$1"
  local log_path="$2"
  shift 2
  local rc=0
  echo "[phase2-linux-prod-candidate-handoff-run] stage=$label status=running"
  set +e
  "$@" >"$log_path" 2>&1
  rc=$?
  if (( rc == 0 )); then
    echo "[phase2-linux-prod-candidate-handoff-run] stage=$label status=pass rc=0"
  else
    echo "[phase2-linux-prod-candidate-handoff-run] stage=$label status=fail rc=$rc"
  fi
  return "$rc"
}

extract_roadmap_summary_path() {
  local signoff_summary_json="$1"
  local path=""
  if [[ -f "$signoff_summary_json" ]] && jq -e . "$signoff_summary_json" >/dev/null 2>&1; then
    path="$(jq -r '(.steps.roadmap_progress_report.artifacts.summary_json // .artifacts.roadmap_summary_json // empty)' "$signoff_summary_json" 2>/dev/null || true)"
  fi
  if [[ -n "$path" ]]; then
    printf '%s' "$(resolve_path_with_base "$path" "$signoff_summary_json")"
  else
    printf '%s' ""
  fi
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_REPORTS_DIR:-}"
signoff_summary_json="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SIGNOFF_SUMMARY_JSON:-}"
handoff_summary_json="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_HANDOFF_SUMMARY_JSON:-}"
summary_json="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SUMMARY_JSON:-}"
print_summary_json="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_PRINT_SUMMARY_JSON:-1}"
resume="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_RESUME:-0}"
dry_run="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_DRY_RUN:-0}"
run_phase2_linux_prod_candidate_signoff="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_RUN_PHASE2_LINUX_PROD_CANDIDATE_SIGNOFF:-1}"
run_phase2_linux_prod_candidate_handoff_check="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_RUN_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK:-1}"

declare -a signoff_passthrough_args=()
declare -a handoff_passthrough_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --signoff-summary-json)
      signoff_summary_json="${2:-}"
      shift 2
      ;;
    --handoff-summary-json)
      handoff_summary_json="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --resume)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        resume="${2:-}"
        shift 2
      else
        resume="1"
        shift
      fi
      ;;
    --run-phase2-linux-prod-candidate-signoff)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase2_linux_prod_candidate_signoff="${2:-}"
        shift 2
      else
        run_phase2_linux_prod_candidate_signoff="1"
        shift
      fi
      ;;
    --run-phase2-linux-prod-candidate-handoff-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase2_linux_prod_candidate_handoff_check="${2:-}"
        shift 2
      else
        run_phase2_linux_prod_candidate_handoff_check="1"
        shift
      fi
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
    --dry-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dry_run="${2:-}"
        shift 2
      else
        dry_run="1"
        shift
      fi
      ;;
    --signoff-*)
      forwarded_flag="--${1#--signoff-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid signoff-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        signoff_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        signoff_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    --handoff-*)
      forwarded_flag="--${1#--handoff-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid handoff-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        handoff_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        handoff_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg: $1"
      usage
      exit 2
      ;;
  esac
done

bool_arg_or_die "--run-phase2-linux-prod-candidate-signoff" "$run_phase2_linux_prod_candidate_signoff"
bool_arg_or_die "--run-phase2-linux-prod-candidate-handoff-check" "$run_phase2_linux_prod_candidate_handoff_check"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--resume" "$resume"
bool_arg_or_die "--dry-run" "$dry_run"

signoff_script="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_signoff.sh}"
handoff_check_script="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_handoff_check.sh}"

if [[ "$run_phase2_linux_prod_candidate_signoff" == "1" && ! -x "$signoff_script" ]]; then
  echo "missing executable stage script: $signoff_script"
  exit 2
fi
if [[ "$run_phase2_linux_prod_candidate_handoff_check" == "1" && ! -x "$handoff_check_script" ]]; then
  echo "missing executable stage script: $handoff_check_script"
  exit 2
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/phase2_linux_prod_candidate_handoff_run_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$signoff_summary_json" ]]; then
  signoff_summary_json="$reports_dir/phase2_linux_prod_candidate_signoff_summary.json"
else
  signoff_summary_json="$(abs_path "$signoff_summary_json")"
fi
if [[ -z "$handoff_summary_json" ]]; then
  handoff_summary_json="$reports_dir/phase2_linux_prod_candidate_handoff_check_summary.json"
else
  handoff_summary_json="$(abs_path "$handoff_summary_json")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/phase2_linux_prod_candidate_handoff_run_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi

mkdir -p "$reports_dir" \
  "$(dirname "$signoff_summary_json")" \
  "$(dirname "$handoff_summary_json")" \
  "$(dirname "$summary_json")"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

signoff_log="$TMP_DIR/signoff_stage.log"
handoff_log="$TMP_DIR/handoff_stage.log"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

declare signoff_command_rc=0
declare handoff_command_rc=0
declare signoff_contract_valid=0
declare handoff_contract_valid=0
declare signoff_status="skipped"
declare handoff_status="skipped"
declare signoff_rc=0
declare handoff_rc=0
declare signoff_contract_error=""
declare handoff_contract_error=""
declare signoff_command=""
declare handoff_command=""
declare signoff_roadmap_summary_json=""
declare signoff_reused_artifact="false"
declare handoff_reused_artifact="false"

declare -a signoff_cmd=("$signoff_script" --reports-dir "$reports_dir" --summary-json "$signoff_summary_json")
if [[ "$dry_run" == "1" ]]; then
  signoff_cmd+=(--dry-run 1)
fi
if ((${#signoff_passthrough_args[@]} > 0)); then
  signoff_cmd+=("${signoff_passthrough_args[@]}")
fi
signoff_command="$(print_cmd "${signoff_cmd[@]}")"

if [[ "$run_phase2_linux_prod_candidate_signoff" == "1" ]]; then
  if [[ "$resume" == "1" ]] && summary_pass_contract_valid "$signoff_summary_json" signoff_summary_contract_valid; then
    echo "[phase2-linux-prod-candidate-handoff-run] stage=phase2_linux_prod_candidate_signoff status=pass rc=0 reason=resume-artifact-pass"
    signoff_status="pass"
    signoff_rc=0
    signoff_command_rc=0
    signoff_contract_valid=1
    signoff_contract_error=""
    signoff_reused_artifact="true"
    signoff_roadmap_summary_json="$(extract_roadmap_summary_path "$signoff_summary_json")"
    if [[ -z "$signoff_roadmap_summary_json" ]]; then
      signoff_roadmap_summary_json="$reports_dir/roadmap_progress_summary.json"
    fi
  else
    set +e
    run_stage_capture "phase2_linux_prod_candidate_signoff" "$signoff_log" "${signoff_cmd[@]}"
    signoff_command_rc=$?
    set -e
    if signoff_summary_contract_valid "$signoff_summary_json"; then
      signoff_contract_valid=1
      signoff_status="$(jq -r '.status // "fail"' "$signoff_summary_json" 2>/dev/null || echo fail)"
      signoff_rc="$(jq -r '.rc // 0' "$signoff_summary_json" 2>/dev/null || echo 0)"
      if [[ "$signoff_command_rc" -ne 0 ]]; then
        signoff_status="fail"
        signoff_rc="$signoff_command_rc"
      fi
    else
      signoff_contract_valid=0
      signoff_contract_error="signoff summary JSON is missing required fields or uses an incompatible schema"
      signoff_status="fail"
      if [[ "$signoff_command_rc" -ne 0 ]]; then
        signoff_rc="$signoff_command_rc"
      else
        signoff_rc=3
      fi
    fi
    signoff_roadmap_summary_json="$(extract_roadmap_summary_path "$signoff_summary_json")"
    if [[ -z "$signoff_roadmap_summary_json" ]]; then
      signoff_roadmap_summary_json="$reports_dir/roadmap_progress_summary.json"
    fi
  fi
else
  echo "[phase2-linux-prod-candidate-handoff-run] stage=phase2_linux_prod_candidate_signoff status=skipped reason=disabled"
  signoff_roadmap_summary_json="$reports_dir/roadmap_progress_summary.json"
fi

declare -a handoff_cmd=(
  "$handoff_check_script"
  --phase2-signoff-summary-json "$signoff_summary_json"
  --roadmap-summary-json "$signoff_roadmap_summary_json"
  --summary-json "$handoff_summary_json"
)
if ((${#handoff_passthrough_args[@]} > 0)); then
  handoff_cmd+=("${handoff_passthrough_args[@]}")
fi
if ! array_has_arg "--show-json" "${handoff_cmd[@]:1}"; then
  handoff_cmd+=(--show-json 0)
fi
if [[ "$dry_run" == "1" ]]; then
  if ! array_has_arg "--require-signoff-pipeline-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-signoff-pipeline-ok 0)
  fi
  if ! array_has_arg "--require-release-integrity-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-release-integrity-ok 0)
  fi
  if ! array_has_arg "--require-release-policy-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-release-policy-ok 0)
  fi
  if ! array_has_arg "--require-operator-lifecycle-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-operator-lifecycle-ok 0)
  fi
  if ! array_has_arg "--require-pilot-signoff-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-pilot-signoff-ok 0)
  fi
fi
handoff_command="$(print_cmd "${handoff_cmd[@]}")"

if [[ "$run_phase2_linux_prod_candidate_handoff_check" == "1" ]]; then
  if [[ "$resume" == "1" ]] && summary_pass_contract_valid "$handoff_summary_json" handoff_summary_contract_valid; then
    echo "[phase2-linux-prod-candidate-handoff-run] stage=phase2_linux_prod_candidate_handoff_check status=pass rc=0 reason=resume-artifact-pass"
    handoff_status="pass"
    handoff_rc=0
    handoff_command_rc=0
    handoff_contract_valid=1
    handoff_contract_error=""
    handoff_reused_artifact="true"
  else
    set +e
    run_stage_capture "phase2_linux_prod_candidate_handoff_check" "$handoff_log" "${handoff_cmd[@]}"
    handoff_command_rc=$?
    set -e
    set +e
    if handoff_summary_contract_valid "$handoff_summary_json"; then
      handoff_contract_valid=1
      handoff_status="$(jq -r '.status // "fail"' "$handoff_summary_json" 2>/dev/null || echo fail)"
      handoff_rc="$(jq -r '.rc // 0' "$handoff_summary_json" 2>/dev/null || echo 0)"
      if [[ "$handoff_command_rc" -ne 0 ]]; then
        handoff_status="fail"
        handoff_rc="$handoff_command_rc"
      fi
    else
      handoff_contract_valid=0
      handoff_contract_error="handoff summary JSON is missing required fields or uses an incompatible schema"
      handoff_status="fail"
      if [[ "$handoff_command_rc" -ne 0 ]]; then
        handoff_rc="$handoff_command_rc"
      else
        handoff_rc=3
      fi
    fi
  fi
else
  echo "[phase2-linux-prod-candidate-handoff-run] stage=phase2_linux_prod_candidate_handoff_check status=skipped reason=disabled"
fi

final_rc=0
if [[ "$run_phase2_linux_prod_candidate_signoff" == "1" ]] && (( signoff_rc != 0 )) && (( final_rc == 0 )); then
  final_rc="$signoff_rc"
fi
if [[ "$run_phase2_linux_prod_candidate_handoff_check" == "1" ]] && (( handoff_rc != 0 )) && (( final_rc == 0 )); then
  final_rc="$handoff_rc"
fi

final_status="pass"
if (( final_rc != 0 )); then
  final_status="fail"
elif [[ "$signoff_status" == "warn" || "$handoff_status" == "warn" ]]; then
  final_status="warn"
fi
if [[ "$final_status" == "fail" && "$final_rc" -eq 0 ]]; then
  final_rc=1
fi

decision_reason_details_json='[]'
decision_warning_details_json='[]'

append_decision_reason() {
  local code="$1"
  local step="$2"
  local message="$3"
  local status="$4"
  local rc="$5"
  decision_reason_details_json="$(
    jq -cn \
      --argjson arr "$decision_reason_details_json" \
      --arg code "$code" \
      --arg step "$step" \
      --arg message "$message" \
      --arg status "$status" \
      --argjson rc "$rc" \
      '$arr + [{
        code: $code,
        step: $step,
        message: $message,
        status: $status,
        rc: $rc
      }]'
  )"
}

append_decision_warning() {
  local code="$1"
  local step="$2"
  local message="$3"
  local status="$4"
  decision_warning_details_json="$(
    jq -cn \
      --argjson arr "$decision_warning_details_json" \
      --arg code "$code" \
      --arg step "$step" \
      --arg message "$message" \
      --arg status "$status" \
      '$arr + [{
        code: $code,
        step: $step,
        message: $message,
        status: $status
      }]'
  )"
}

if [[ "$run_phase2_linux_prod_candidate_signoff" == "1" ]]; then
  if [[ "$signoff_contract_valid" != "1" ]]; then
    append_decision_reason \
      "signoff_summary_contract_invalid" \
      "phase2_linux_prod_candidate_signoff" \
      "signoff summary JSON is missing required fields or uses an incompatible schema" \
      "$signoff_status" \
      "$signoff_rc"
  fi
  if [[ "$signoff_status" == "fail" ]]; then
    append_decision_reason \
      "signoff_step_not_pass" \
      "phase2_linux_prod_candidate_signoff" \
      "phase2 signoff stage did not pass" \
      "$signoff_status" \
      "$signoff_rc"
  elif [[ "$signoff_status" == "warn" ]]; then
    append_decision_warning \
      "signoff_step_warn" \
      "phase2_linux_prod_candidate_signoff" \
      "phase2 signoff stage returned warn status" \
      "$signoff_status"
  fi
fi

if [[ "$run_phase2_linux_prod_candidate_handoff_check" == "1" ]]; then
  if [[ "$handoff_contract_valid" != "1" ]]; then
    append_decision_reason \
      "handoff_summary_contract_invalid" \
      "phase2_linux_prod_candidate_handoff_check" \
      "handoff summary JSON is missing required fields or uses an incompatible schema" \
      "$handoff_status" \
      "$handoff_rc"
  fi
  if [[ "$handoff_status" == "fail" ]]; then
    append_decision_reason \
      "handoff_step_not_pass" \
      "phase2_linux_prod_candidate_handoff_check" \
      "phase2 handoff check stage did not pass" \
      "$handoff_status" \
      "$handoff_rc"
  elif [[ "$handoff_status" == "warn" ]]; then
    append_decision_warning \
      "handoff_step_warn" \
      "phase2_linux_prod_candidate_handoff_check" \
      "phase2 handoff check stage returned warn status" \
      "$handoff_status"
  fi
fi

decision_reasons_json="$(
  jq -cn --argjson details "$decision_reason_details_json" '[ $details[] | .message ]'
)"
decision_warnings_json="$(
  jq -cn --argjson details "$decision_warning_details_json" '[ $details[] | .message ]'
)"

signoff_summary_exists="false"
handoff_summary_exists="false"
if [[ -f "$signoff_summary_json" ]]; then
  signoff_summary_exists="true"
fi
if [[ -f "$handoff_summary_json" ]]; then
  handoff_summary_exists="true"
fi

signoff_passthrough_json="$(printf '%s\n' "${signoff_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
handoff_passthrough_json="$(printf '%s\n' "${handoff_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg signoff_summary_json "$signoff_summary_json" \
  --arg handoff_summary_json "$handoff_summary_json" \
  --arg signoff_roadmap_summary_json "$signoff_roadmap_summary_json" \
  --argjson resume "$resume" \
  --argjson dry_run "$dry_run" \
  --argjson print_summary_json "$print_summary_json" \
  --argjson run_phase2_linux_prod_candidate_signoff "$run_phase2_linux_prod_candidate_signoff" \
  --argjson run_phase2_linux_prod_candidate_handoff_check "$run_phase2_linux_prod_candidate_handoff_check" \
  --argjson signoff_passthrough_args "$signoff_passthrough_json" \
  --argjson handoff_passthrough_args "$handoff_passthrough_json" \
  --arg signoff_status "$signoff_status" \
  --argjson signoff_rc "$signoff_rc" \
  --argjson signoff_command_rc "$signoff_command_rc" \
  --arg signoff_command "$signoff_command" \
  --arg signoff_contract_valid "$signoff_contract_valid" \
  --arg signoff_contract_error "$signoff_contract_error" \
  --arg signoff_summary_exists "$signoff_summary_exists" \
  --arg signoff_log "$signoff_log" \
  --arg signoff_reused_artifact "$signoff_reused_artifact" \
  --arg handoff_status "$handoff_status" \
  --argjson handoff_rc "$handoff_rc" \
  --argjson handoff_command_rc "$handoff_command_rc" \
  --arg handoff_command "$handoff_command" \
  --arg handoff_contract_valid "$handoff_contract_valid" \
  --arg handoff_contract_error "$handoff_contract_error" \
  --arg handoff_summary_exists "$handoff_summary_exists" \
  --arg handoff_log "$handoff_log" \
  --arg handoff_reused_artifact "$handoff_reused_artifact" \
  --argjson decision_reasons "$decision_reasons_json" \
  --argjson decision_reason_details "$decision_reason_details_json" \
  --argjson decision_warnings "$decision_warnings_json" \
  --argjson decision_warning_details "$decision_warning_details_json" \
  '{
    version: 1,
    schema: {
      id: "phase2_linux_prod_candidate_handoff_run_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    metadata: {
      contract: "phase2-linux-production-candidate",
      runner_script: "phase2_linux_prod_candidate_handoff_run.sh"
    },
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      resume: ($resume == 1),
      dry_run: ($dry_run == 1),
      print_summary_json: ($print_summary_json == 1),
      run_phase2_linux_prod_candidate_signoff: ($run_phase2_linux_prod_candidate_signoff == 1),
      run_phase2_linux_prod_candidate_handoff_check: ($run_phase2_linux_prod_candidate_handoff_check == 1),
      signoff_passthrough_args: $signoff_passthrough_args,
      handoff_passthrough_args: $handoff_passthrough_args
    },
    steps: {
      phase2_linux_prod_candidate_signoff: {
        enabled: ($run_phase2_linux_prod_candidate_signoff == 1),
        status: $signoff_status,
        rc: $signoff_rc,
        command_rc: $signoff_command_rc,
        command: (if $signoff_command == "" then null else $signoff_command end),
        reused_artifact: ($signoff_reused_artifact == "true"),
        contract_valid: (
          if $signoff_contract_valid == "1" then true
          elif $signoff_contract_valid == "0" then false
          else null
          end
        ),
        contract_error: (if $signoff_contract_error == "" then null else $signoff_contract_error end),
        artifacts: {
          summary_json: $signoff_summary_json,
          summary_exists: ($signoff_summary_exists == "true"),
          log: $signoff_log
        }
      },
      phase2_linux_prod_candidate_handoff_check: {
        enabled: ($run_phase2_linux_prod_candidate_handoff_check == 1),
        status: $handoff_status,
        rc: $handoff_rc,
        command_rc: $handoff_command_rc,
        command: (if $handoff_command == "" then null else $handoff_command end),
        reused_artifact: ($handoff_reused_artifact == "true"),
        contract_valid: (
          if $handoff_contract_valid == "1" then true
          elif $handoff_contract_valid == "0" then false
          else null
          end
        ),
        contract_error: (if $handoff_contract_error == "" then null else $handoff_contract_error end),
        artifacts: {
          summary_json: $handoff_summary_json,
          summary_exists: ($handoff_summary_exists == "true"),
          log: $handoff_log
        }
      }
    },
    decision: {
      pass: ($status == "pass"),
      reasons: $decision_reasons,
      reason_details: $decision_reason_details,
      reason_codes: ($decision_reason_details | map(.code) | unique),
      warnings: $decision_warnings,
      warning_details: $decision_warning_details,
      warning_codes: ($decision_warning_details | map(.code) | unique)
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      signoff_summary_json: $signoff_summary_json,
      handoff_summary_json: $handoff_summary_json,
      signoff_roadmap_summary_json: $signoff_roadmap_summary_json,
      signoff_log: $signoff_log,
      handoff_log: $handoff_log
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[phase2-linux-prod-candidate-handoff-run] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[phase2-linux-prod-candidate-handoff-run] reports_dir=$reports_dir"
echo "[phase2-linux-prod-candidate-handoff-run] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
