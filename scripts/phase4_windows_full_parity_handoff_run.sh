#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase4_windows_full_parity_handoff_run.sh \
    [--reports-dir DIR] \
    [--run-summary-json PATH] \
    [--handoff-summary-json PATH] \
    [--summary-json PATH] \
    [--resume [0|1]] \
    [--run-phase4-windows-full-parity-run [0|1]] \
    [--run-phase4-windows-full-parity-handoff-check [0|1]] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--run-<arg> ...] \
    [--handoff-<arg> ...]

Purpose:
  One-command Phase-4 Windows full-parity handoff runner:
    1) phase4_windows_full_parity_run.sh
    2) phase4_windows_full_parity_handoff_check.sh

Notes:
  - Wrapper-owned flags are reserved; stage pass-through uses prefixes:
      --run-...      -> forwarded to phase4_windows_full_parity_run.sh
      --handoff-...  -> forwarded to phase4_windows_full_parity_handoff_check.sh
  - Dry-run forwards --dry-run 1 to the run stage.
    The handoff check still executes against the generated summaries.
  - Dry-run relaxes handoff requirements to 0 unless explicitly supplied.
  - The handoff check runs even when the run stage fails.
  - Resume mode (--resume 1) reuses pass summaries for run + handoff-check
    stages when available.
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

run_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    type == "object"
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (.schema.id // "") == "phase4_windows_full_parity_run_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) | floor) == (.schema.major // 0)
    and (.status | type) == "string"
    and (.rc | type) == "number"
    and (.steps.ci_phase4_windows_full_parity | type) == "object"
    and (.steps.phase4_windows_full_parity_check | type) == "object"
    and ((.steps.ci_phase4_windows_full_parity.status | type) == "string")
    and ((.steps.ci_phase4_windows_full_parity.rc | type) == "number")
    and ((.steps.ci_phase4_windows_full_parity.command_rc | type) == "number")
    and ((.steps.ci_phase4_windows_full_parity.contract_valid | type) == "boolean")
    and ((.steps.phase4_windows_full_parity_check.status | type) == "string")
    and ((.steps.phase4_windows_full_parity_check.rc | type) == "number")
    and ((.steps.phase4_windows_full_parity_check.command_rc | type) == "number")
    and ((.steps.phase4_windows_full_parity_check.contract_valid | type) == "boolean")
    and (
      (.status == "pass" and .rc == 0)
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
    and (.schema.id // "") == "phase4_windows_full_parity_handoff_check_summary"
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
  echo "[phase4-windows-full-parity-handoff-run] stage=$label status=running"
  set +e
  "$@" >"$log_path" 2>&1
  rc=$?
  if (( rc == 0 )); then
    echo "[phase4-windows-full-parity-handoff-run] stage=$label status=pass rc=0"
  else
    echo "[phase4-windows-full-parity-handoff-run] stage=$label status=fail rc=$rc"
  fi
  return "$rc"
}

extract_roadmap_summary_path() {
  local run_summary_json="$1"
  local path=""
  if [[ -f "$run_summary_json" ]] && jq -e . "$run_summary_json" >/dev/null 2>&1; then
    path="$(jq -r '(.steps.phase4_windows_full_parity_check.artifacts.roadmap_summary_json // .artifacts.roadmap_summary_json // empty)' "$run_summary_json" 2>/dev/null || true)"
  fi
  if [[ -n "$path" ]]; then
    printf '%s' "$(resolve_path_with_base "$path" "$run_summary_json")"
  else
    printf '%s' ""
  fi
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_REPORTS_DIR:-}"
run_summary_json="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RUN_SUMMARY_JSON:-}"
handoff_summary_json="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_HANDOFF_SUMMARY_JSON:-}"
summary_json="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SUMMARY_JSON:-}"
print_summary_json="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_PRINT_SUMMARY_JSON:-1}"
resume="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RESUME:-0}"
dry_run="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_DRY_RUN:-0}"
run_phase4_windows_full_parity_run="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RUN_PHASE4_WINDOWS_FULL_PARITY_RUN:-1}"
run_phase4_windows_full_parity_handoff_check="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RUN_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK:-1}"

declare -a run_passthrough_args=()
declare -a handoff_passthrough_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --run-summary-json)
      run_summary_json="${2:-}"
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
    --run-phase4-windows-full-parity-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase4_windows_full_parity_run="${2:-}"
        shift 2
      else
        run_phase4_windows_full_parity_run="1"
        shift
      fi
      ;;
    --run-phase4-windows-full-parity-handoff-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase4_windows_full_parity_handoff_check="${2:-}"
        shift 2
      else
        run_phase4_windows_full_parity_handoff_check="1"
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
    --run-*)
      forwarded_flag="--${1#--run-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid run-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        run_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        run_passthrough_args+=("$forwarded_flag")
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

bool_arg_or_die "--run-phase4-windows-full-parity-run" "$run_phase4_windows_full_parity_run"
bool_arg_or_die "--run-phase4-windows-full-parity-handoff-check" "$run_phase4_windows_full_parity_handoff_check"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--resume" "$resume"
bool_arg_or_die "--dry-run" "$dry_run"

run_script="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RUN_SCRIPT:-$ROOT_DIR/scripts/phase4_windows_full_parity_run.sh}"
handoff_check_script="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase4_windows_full_parity_handoff_check.sh}"

if [[ "$run_phase4_windows_full_parity_run" == "1" && ! -x "$run_script" ]]; then
  echo "missing executable stage script: $run_script"
  exit 2
fi
if [[ "$run_phase4_windows_full_parity_handoff_check" == "1" && ! -x "$handoff_check_script" ]]; then
  echo "missing executable stage script: $handoff_check_script"
  exit 2
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/phase4_windows_full_parity_handoff_run_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$run_summary_json" ]]; then
  run_summary_json="$reports_dir/phase4_windows_full_parity_run_summary.json"
else
  run_summary_json="$(abs_path "$run_summary_json")"
fi
if [[ -z "$handoff_summary_json" ]]; then
  handoff_summary_json="$reports_dir/phase4_windows_full_parity_handoff_check_summary.json"
else
  handoff_summary_json="$(abs_path "$handoff_summary_json")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/phase4_windows_full_parity_handoff_run_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi

mkdir -p "$reports_dir" \
  "$(dirname "$run_summary_json")" \
  "$(dirname "$handoff_summary_json")" \
  "$(dirname "$summary_json")"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

run_log="$TMP_DIR/run_stage.log"
handoff_log="$TMP_DIR/handoff_stage.log"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

declare run_command_rc=0
declare handoff_command_rc=0
declare run_contract_valid=0
declare handoff_contract_valid=0
declare run_status="skipped"
declare handoff_status="skipped"
declare run_rc=0
declare handoff_rc=0
declare run_contract_error=""
declare handoff_contract_error=""
declare run_command=""
declare handoff_command=""
declare run_roadmap_summary_json=""
declare run_reused_artifact="false"
declare handoff_reused_artifact="false"
declare handoff_actionable_recommended_gate_id=""
declare handoff_actionable_count=-1

declare -a run_cmd=("$run_script" --reports-dir "$reports_dir" --summary-json "$run_summary_json")
if [[ "$dry_run" == "1" ]]; then
  run_cmd+=(--dry-run 1)
fi
if ((${#run_passthrough_args[@]} > 0)); then
  run_cmd+=("${run_passthrough_args[@]}")
fi
run_command="$(print_cmd "${run_cmd[@]}")"

if [[ "$run_phase4_windows_full_parity_run" == "1" ]]; then
  if [[ "$resume" == "1" ]] && summary_pass_contract_valid "$run_summary_json" run_summary_contract_valid; then
    echo "[phase4-windows-full-parity-handoff-run] stage=phase4_windows_full_parity_run status=pass rc=0 reason=resume-artifact-pass"
    run_contract_valid=1
    run_status="pass"
    run_rc=0
    run_command_rc=0
    run_reused_artifact="true"
  else
    set +e
    run_stage_capture "phase4_windows_full_parity_run" "$run_log" "${run_cmd[@]}"
    run_command_rc=$?
    set -e
    if run_summary_contract_valid "$run_summary_json"; then
      run_contract_valid=1
      run_status="$(jq -r '.status // "fail"' "$run_summary_json" 2>/dev/null || echo fail)"
      run_rc="$(jq -r '.rc // 0' "$run_summary_json" 2>/dev/null || echo 0)"
      if [[ "$run_command_rc" -ne 0 ]]; then
        run_status="fail"
        run_rc="$run_command_rc"
      fi
    else
      run_contract_valid=0
      run_contract_error="run summary JSON is missing required fields or uses an incompatible schema"
      run_status="fail"
      if [[ "$run_command_rc" -ne 0 ]]; then
        run_rc="$run_command_rc"
      else
        run_rc=3
      fi
    fi
  fi
  run_roadmap_summary_json="$(extract_roadmap_summary_path "$run_summary_json")"
else
  echo "[phase4-windows-full-parity-handoff-run] stage=phase4_windows_full_parity_run status=skipped reason=disabled"
fi

declare -a handoff_cmd=(
  "$handoff_check_script"
  --phase4-run-summary-json "$run_summary_json"
  --summary-json "$handoff_summary_json"
)
if [[ -n "$run_roadmap_summary_json" ]] && ! array_has_arg "--roadmap-summary-json" "${handoff_passthrough_args[@]}"; then
  handoff_cmd+=(--roadmap-summary-json "$run_roadmap_summary_json")
fi
if ((${#handoff_passthrough_args[@]} > 0)); then
  handoff_cmd+=("${handoff_passthrough_args[@]}")
fi
if ! array_has_arg "--show-json" "${handoff_cmd[@]:1}"; then
  handoff_cmd+=(--show-json 0)
fi
if [[ "$dry_run" == "1" ]]; then
  if ! array_has_arg "--require-run-pipeline-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-run-pipeline-ok 0)
  fi
  if ! array_has_arg "--require-windows-server-packaging-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-windows-server-packaging-ok 0)
  fi
  if ! array_has_arg "--require-windows-native-bootstrap-guardrails-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-windows-native-bootstrap-guardrails-ok 0)
  fi
  if ! array_has_arg "--require-windows-role-runbooks-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-windows-role-runbooks-ok 0)
  fi
  if ! array_has_arg "--require-cross-platform-interop-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-cross-platform-interop-ok 0)
  fi
  if ! array_has_arg "--require-role-combination-validation-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-role-combination-validation-ok 0)
  fi
fi
handoff_command="$(print_cmd "${handoff_cmd[@]}")"

if [[ "$run_phase4_windows_full_parity_handoff_check" == "1" ]]; then
  if [[ "$resume" == "1" ]] && summary_pass_contract_valid "$handoff_summary_json" handoff_summary_contract_valid; then
    echo "[phase4-windows-full-parity-handoff-run] stage=phase4_windows_full_parity_handoff_check status=pass rc=0 reason=resume-artifact-pass"
    handoff_contract_valid=1
    handoff_status="pass"
    handoff_rc=0
    handoff_command_rc=0
    handoff_reused_artifact="true"
  else
    set +e
    run_stage_capture "phase4_windows_full_parity_handoff_check" "$handoff_log" "${handoff_cmd[@]}"
    handoff_command_rc=$?
    set -e
    if handoff_summary_contract_valid "$handoff_summary_json"; then
      handoff_contract_valid=1
      handoff_status="$(jq -r '.status // "fail"' "$handoff_summary_json" 2>/dev/null || echo fail)"
      handoff_rc="$(jq -r '.rc // 0' "$handoff_summary_json" 2>/dev/null || echo 0)"
      handoff_actionable_recommended_gate_id="$(jq -r '.decision.actionable.recommended_gate_id // ""' "$handoff_summary_json" 2>/dev/null || true)"
      handoff_actionable_count="$(jq -r 'if (.decision.actionable.count | type) == "number" then .decision.actionable.count else -1 end' "$handoff_summary_json" 2>/dev/null || echo -1)"
      if ! [[ "$handoff_actionable_count" =~ ^-?[0-9]+$ ]]; then
        handoff_actionable_count=-1
      fi
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
  echo "[phase4-windows-full-parity-handoff-run] stage=phase4_windows_full_parity_handoff_check status=skipped reason=disabled"
fi

final_rc=0
if [[ "$run_phase4_windows_full_parity_run" == "1" ]] && (( run_rc != 0 )) && (( final_rc == 0 )); then
  final_rc="$run_rc"
fi
if [[ "$run_phase4_windows_full_parity_handoff_check" == "1" ]] && (( handoff_rc != 0 )) && (( final_rc == 0 )); then
  final_rc="$handoff_rc"
fi

final_status="pass"
if (( final_rc != 0 )); then
  final_status="fail"
fi

run_summary_exists="false"
handoff_summary_exists="false"
if [[ -f "$run_summary_json" ]]; then
  run_summary_exists="true"
fi
if [[ -f "$handoff_summary_json" ]]; then
  handoff_summary_exists="true"
fi

run_passthrough_json="$(printf '%s\n' "${run_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
handoff_passthrough_json="$(printf '%s\n' "${handoff_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg run_summary_json "$run_summary_json" \
  --arg handoff_summary_json "$handoff_summary_json" \
  --arg run_roadmap_summary_json "$run_roadmap_summary_json" \
  --argjson resume "$resume" \
  --argjson dry_run "$dry_run" \
  --argjson print_summary_json "$print_summary_json" \
  --argjson run_phase4_windows_full_parity_run "$run_phase4_windows_full_parity_run" \
  --argjson run_phase4_windows_full_parity_handoff_check "$run_phase4_windows_full_parity_handoff_check" \
  --argjson run_passthrough_args "$run_passthrough_json" \
  --argjson handoff_passthrough_args "$handoff_passthrough_json" \
  --arg run_status "$run_status" \
  --argjson run_rc "$run_rc" \
  --argjson run_command_rc "$run_command_rc" \
  --arg run_command "$run_command" \
  --arg run_contract_valid "$run_contract_valid" \
  --arg run_contract_error "$run_contract_error" \
  --arg run_summary_exists "$run_summary_exists" \
  --arg run_log "$run_log" \
  --arg run_reused_artifact "$run_reused_artifact" \
  --arg handoff_status "$handoff_status" \
  --argjson handoff_rc "$handoff_rc" \
  --argjson handoff_command_rc "$handoff_command_rc" \
  --arg handoff_command "$handoff_command" \
  --arg handoff_contract_valid "$handoff_contract_valid" \
  --arg handoff_contract_error "$handoff_contract_error" \
  --arg handoff_actionable_recommended_gate_id "$handoff_actionable_recommended_gate_id" \
  --argjson handoff_actionable_count "$handoff_actionable_count" \
  --arg handoff_summary_exists "$handoff_summary_exists" \
  --arg handoff_log "$handoff_log" \
  --arg handoff_reused_artifact "$handoff_reused_artifact" \
  '{
    version: 1,
    schema: {
      id: "phase4_windows_full_parity_handoff_run_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    metadata: {
      contract: "phase4-windows-full-parity",
      runner_script: "phase4_windows_full_parity_handoff_run.sh"
    },
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      resume: ($resume == 1),
      dry_run: ($dry_run == 1),
      print_summary_json: ($print_summary_json == 1),
      run_phase4_windows_full_parity_run: ($run_phase4_windows_full_parity_run == 1),
      run_phase4_windows_full_parity_handoff_check: ($run_phase4_windows_full_parity_handoff_check == 1),
      run_passthrough_args: $run_passthrough_args,
      handoff_passthrough_args: $handoff_passthrough_args
    },
    steps: {
      phase4_windows_full_parity_run: {
        enabled: ($run_phase4_windows_full_parity_run == 1),
        status: $run_status,
        rc: $run_rc,
        command_rc: $run_command_rc,
        command: (if $run_command == "" then null else $run_command end),
        reused_artifact: ($run_reused_artifact == "true"),
        contract_valid: (
          if $run_contract_valid == "1" then true
          elif $run_contract_valid == "0" then false
          else null
          end
        ),
        contract_error: (if $run_contract_error == "" then null else $run_contract_error end),
        failure_kind: (
          if $run_status == "pass" then "none"
          elif $run_contract_valid != "1" then "contract_invalid"
          elif $run_command_rc != 0 then "command_failed"
          elif $run_rc != 0 then "stage_failed"
          else "stage_failed"
          end
        ),
        artifacts: {
          summary_json: $run_summary_json,
          summary_exists: ($run_summary_exists == "true"),
          log: $run_log
        }
      },
      phase4_windows_full_parity_handoff_check: {
        enabled: ($run_phase4_windows_full_parity_handoff_check == 1),
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
        failure_kind: (
          if $handoff_status == "pass" then "none"
          elif $handoff_contract_valid != "1" then "contract_invalid"
          elif $handoff_command_rc != 0 then "command_failed"
          elif $handoff_rc != 0 then "stage_failed"
          else "stage_failed"
          end
        ),
        actionable: {
          recommended_gate_id: (if $handoff_actionable_recommended_gate_id == "" then null else $handoff_actionable_recommended_gate_id end),
          count: (if $handoff_actionable_count < 0 then null else $handoff_actionable_count end)
        },
        artifacts: {
          summary_json: $handoff_summary_json,
          summary_exists: ($handoff_summary_exists == "true"),
          log: $handoff_log
        }
      }
    },
    decision: {
      pass: ($status == "pass"),
      failure_stage: (
        if $status == "pass" then null
        elif ($run_phase4_windows_full_parity_run == 1 and $run_rc != 0) then "phase4_windows_full_parity_run"
        elif ($run_phase4_windows_full_parity_handoff_check == 1 and $handoff_rc != 0) then "phase4_windows_full_parity_handoff_check"
        elif ($run_phase4_windows_full_parity_run == 1 and $run_status != "pass") then "phase4_windows_full_parity_run"
        elif ($run_phase4_windows_full_parity_handoff_check == 1 and $handoff_status != "pass") then "phase4_windows_full_parity_handoff_check"
        else "unknown"
        end
      ),
      failure_kind: (
        if $status == "pass" then "none"
        elif ($run_phase4_windows_full_parity_run == 1 and $run_rc != 0) then
          (if $run_contract_valid != "1" then "contract_invalid"
           elif $run_command_rc != 0 then "command_failed"
           else "stage_failed" end)
        elif ($run_phase4_windows_full_parity_handoff_check == 1 and $handoff_rc != 0) then
          (if $handoff_contract_valid != "1" then "contract_invalid"
           elif $handoff_command_rc != 0 then "command_failed"
           else "stage_failed" end)
        elif ($run_phase4_windows_full_parity_run == 1 and $run_status != "pass") then
          (if $run_contract_valid != "1" then "contract_invalid" else "stage_failed" end)
        elif ($run_phase4_windows_full_parity_handoff_check == 1 and $handoff_status != "pass") then
          (if $handoff_contract_valid != "1" then "contract_invalid" else "stage_failed" end)
        else "unknown"
        end
      ),
      reason_codes: [
        (if ($run_phase4_windows_full_parity_run == 1 and $run_status != "pass" and $run_contract_valid != "1") then "phase4_windows_full_parity_run_contract_invalid"
         elif ($run_phase4_windows_full_parity_run == 1 and $run_status != "pass") then "phase4_windows_full_parity_run_stage_failed"
         else empty end),
        (if ($run_phase4_windows_full_parity_handoff_check == 1 and $handoff_status != "pass" and $handoff_contract_valid != "1") then "phase4_windows_full_parity_handoff_check_contract_invalid"
         elif ($run_phase4_windows_full_parity_handoff_check == 1 and $handoff_status != "pass") then "phase4_windows_full_parity_handoff_check_stage_failed"
         else empty end)
      ],
      reason_details: [
        (if ($run_phase4_windows_full_parity_run == 1 and $run_status != "pass") then {
          stage: "phase4_windows_full_parity_run",
          kind: (
            if $run_contract_valid != "1" then "contract_invalid"
            elif $run_command_rc != 0 then "command_failed"
            elif $run_rc != 0 then "stage_failed"
            else "stage_failed"
            end
          ),
          status: $run_status,
          rc: $run_rc,
          command_rc: $run_command_rc,
          contract_valid: (
            if $run_contract_valid == "1" then true
            elif $run_contract_valid == "0" then false
            else null
            end
          ),
          contract_error: (if $run_contract_error == "" then null else $run_contract_error end),
          reused_artifact: ($run_reused_artifact == "true")
        } else empty end),
        (if ($run_phase4_windows_full_parity_handoff_check == 1 and $handoff_status != "pass") then {
          stage: "phase4_windows_full_parity_handoff_check",
          kind: (
            if $handoff_contract_valid != "1" then "contract_invalid"
            elif $handoff_command_rc != 0 then "command_failed"
            elif $handoff_rc != 0 then "stage_failed"
            else "stage_failed"
            end
          ),
          status: $handoff_status,
          rc: $handoff_rc,
          command_rc: $handoff_command_rc,
          contract_valid: (
            if $handoff_contract_valid == "1" then true
            elif $handoff_contract_valid == "0" then false
            else null
            end
          ),
          contract_error: (if $handoff_contract_error == "" then null else $handoff_contract_error end),
          reused_artifact: ($handoff_reused_artifact == "true")
        } else empty end)
      ]
    },
    failure: {
      kind: (
        if $status == "pass" then "none"
        elif ($run_phase4_windows_full_parity_run == 1 and $run_rc != 0 and $run_contract_valid != "1") then "contract_invalid"
        elif ($run_phase4_windows_full_parity_run == 1 and $run_rc != 0) then "stage_failed"
        elif ($run_phase4_windows_full_parity_handoff_check == 1 and $handoff_rc != 0 and $handoff_contract_valid != "1") then "contract_invalid"
        elif ($run_phase4_windows_full_parity_handoff_check == 1 and $handoff_rc != 0) then "stage_failed"
        elif ($run_phase4_windows_full_parity_run == 1 and $run_status != "pass" and $run_contract_valid != "1") then "contract_invalid"
        elif ($run_phase4_windows_full_parity_handoff_check == 1 and $handoff_status != "pass" and $handoff_contract_valid != "1") then "contract_invalid"
        elif $status != "pass" then "stage_failed"
        else "unknown"
        end
      ),
      policy_no_go: ($status != "pass"),
      execution_failure: ($status != "pass")
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      run_summary_json: $run_summary_json,
      handoff_summary_json: $handoff_summary_json,
      run_roadmap_summary_json: (if $run_roadmap_summary_json == "" then null else $run_roadmap_summary_json end),
      run_log: $run_log,
      handoff_log: $handoff_log
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[phase4-windows-full-parity-handoff-run] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[phase4-windows-full-parity-handoff-run] reports_dir=$reports_dir"
echo "[phase4-windows-full-parity-handoff-run] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
