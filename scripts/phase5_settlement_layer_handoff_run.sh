#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase5_settlement_layer_handoff_run.sh \
    [--reports-dir DIR] \
    [--run-summary-json PATH] \
    [--handoff-summary-json PATH] \
    [--summary-json PATH] \
    [--run-phase5-settlement-layer-run [0|1]] \
    [--run-phase5-settlement-layer-handoff-check [0|1]] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--run-<arg> ...] \
    [--handoff-<arg> ...]

Purpose:
  One-command Phase-5 settlement layer handoff runner:
    1) phase5_settlement_layer_run.sh
    2) phase5_settlement_layer_handoff_check.sh

Notes:
  - Wrapper-owned flags are reserved; stage pass-through uses prefixes:
      --run-...      -> forwarded to phase5_settlement_layer_run.sh
      --handoff-...  -> forwarded to phase5_settlement_layer_handoff_check.sh
  - Dry-run forwards --dry-run 1 to the run stage.
    The handoff check still executes against the generated summaries.
  - Dry-run relaxes handoff requirements to 0 unless explicitly supplied.
  - The handoff check runs even when the run stage fails.
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
    and (.schema.id // "") == "phase5_settlement_layer_run_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) | floor) == (.schema.major // 0)
    and (.status | type) == "string"
    and (.rc | type) == "number"
    and (.steps.ci_phase5_settlement_layer | type) == "object"
    and (.steps.phase5_settlement_layer_check | type) == "object"
    and ((.steps.ci_phase5_settlement_layer.status | type) == "string")
    and ((.steps.ci_phase5_settlement_layer.rc | type) == "number")
    and ((.steps.ci_phase5_settlement_layer.command_rc | type) == "number")
    and ((.steps.ci_phase5_settlement_layer.contract_valid | type) == "boolean")
    and ((.steps.phase5_settlement_layer_check.status | type) == "string")
    and ((.steps.phase5_settlement_layer_check.rc | type) == "number")
    and ((.steps.phase5_settlement_layer_check.command_rc | type) == "number")
    and ((.steps.phase5_settlement_layer_check.contract_valid | type) == "boolean")
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
    and (.schema.id // "") == "phase5_settlement_layer_handoff_check_summary"
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

run_stage_capture() {
  local label="$1"
  local log_path="$2"
  shift 2
  local rc=0
  echo "[phase5-settlement-layer-handoff-run] stage=$label status=running"
  set +e
  "$@" >"$log_path" 2>&1
  rc=$?
  if (( rc == 0 )); then
    echo "[phase5-settlement-layer-handoff-run] stage=$label status=pass rc=0"
  else
    echo "[phase5-settlement-layer-handoff-run] stage=$label status=fail rc=$rc"
  fi
  return "$rc"
}

extract_roadmap_summary_path() {
  local run_summary_json="$1"
  local path=""
  if [[ -f "$run_summary_json" ]] && jq -e . "$run_summary_json" >/dev/null 2>&1; then
    path="$(jq -r '(.steps.phase5_settlement_layer_check.artifacts.roadmap_summary_json // .artifacts.roadmap_summary_json // empty)' "$run_summary_json" 2>/dev/null || true)"
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

reports_dir="${PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_REPORTS_DIR:-}"
run_summary_json="${PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_RUN_SUMMARY_JSON:-}"
handoff_summary_json="${PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_HANDOFF_SUMMARY_JSON:-}"
summary_json="${PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_SUMMARY_JSON:-}"
print_summary_json="${PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_PRINT_SUMMARY_JSON:-1}"
dry_run="${PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_DRY_RUN:-0}"
run_phase5_settlement_layer_run="${PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_RUN_PHASE5_SETTLEMENT_LAYER_RUN:-1}"
run_phase5_settlement_layer_handoff_check="${PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_RUN_PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK:-1}"

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
    --run-phase5-settlement-layer-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase5_settlement_layer_run="${2:-}"
        shift 2
      else
        run_phase5_settlement_layer_run="1"
        shift
      fi
      ;;
    --run-phase5-settlement-layer-handoff-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase5_settlement_layer_handoff_check="${2:-}"
        shift 2
      else
        run_phase5_settlement_layer_handoff_check="1"
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

bool_arg_or_die "--run-phase5-settlement-layer-run" "$run_phase5_settlement_layer_run"
bool_arg_or_die "--run-phase5-settlement-layer-handoff-check" "$run_phase5_settlement_layer_handoff_check"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--dry-run" "$dry_run"

run_script="${PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_RUN_SCRIPT:-$ROOT_DIR/scripts/phase5_settlement_layer_run.sh}"
handoff_check_script="${PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase5_settlement_layer_handoff_check.sh}"

if [[ "$run_phase5_settlement_layer_run" == "1" && ! -x "$run_script" ]]; then
  echo "missing executable stage script: $run_script"
  exit 2
fi
if [[ "$run_phase5_settlement_layer_handoff_check" == "1" && ! -x "$handoff_check_script" ]]; then
  echo "missing executable stage script: $handoff_check_script"
  exit 2
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/phase5_settlement_layer_handoff_run_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$run_summary_json" ]]; then
  run_summary_json="$reports_dir/phase5_settlement_layer_run_summary.json"
else
  run_summary_json="$(abs_path "$run_summary_json")"
fi
if [[ -z "$handoff_summary_json" ]]; then
  handoff_summary_json="$reports_dir/phase5_settlement_layer_handoff_check_summary.json"
else
  handoff_summary_json="$(abs_path "$handoff_summary_json")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/phase5_settlement_layer_handoff_run_summary.json"
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

declare -a run_cmd=("$run_script" --reports-dir "$reports_dir" --summary-json "$run_summary_json")
if [[ "$dry_run" == "1" ]]; then
  run_cmd+=(--dry-run 1)
fi
if ((${#run_passthrough_args[@]} > 0)); then
  run_cmd+=("${run_passthrough_args[@]}")
fi
run_command="$(print_cmd "${run_cmd[@]}")"

if [[ "$run_phase5_settlement_layer_run" == "1" ]]; then
  set +e
  run_stage_capture "phase5_settlement_layer_run" "$run_log" "${run_cmd[@]}"
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
  run_roadmap_summary_json="$(extract_roadmap_summary_path "$run_summary_json")"
else
  echo "[phase5-settlement-layer-handoff-run] stage=phase5_settlement_layer_run status=skipped reason=disabled"
fi

declare -a handoff_cmd=(
  "$handoff_check_script"
  --phase5-run-summary-json "$run_summary_json"
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

if [[ "$run_phase5_settlement_layer_handoff_check" == "1" ]]; then
  set +e
  run_stage_capture "phase5_settlement_layer_handoff_check" "$handoff_log" "${handoff_cmd[@]}"
  handoff_command_rc=$?
  set -e
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
else
  echo "[phase5-settlement-layer-handoff-run] stage=phase5_settlement_layer_handoff_check status=skipped reason=disabled"
fi

final_rc=0
if [[ "$run_phase5_settlement_layer_run" == "1" ]] && (( run_rc != 0 )) && (( final_rc == 0 )); then
  final_rc="$run_rc"
fi
if [[ "$run_phase5_settlement_layer_handoff_check" == "1" ]] && (( handoff_rc != 0 )) && (( final_rc == 0 )); then
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
  --argjson dry_run "$dry_run" \
  --argjson print_summary_json "$print_summary_json" \
  --argjson run_phase5_settlement_layer_run "$run_phase5_settlement_layer_run" \
  --argjson run_phase5_settlement_layer_handoff_check "$run_phase5_settlement_layer_handoff_check" \
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
  --arg handoff_status "$handoff_status" \
  --argjson handoff_rc "$handoff_rc" \
  --argjson handoff_command_rc "$handoff_command_rc" \
  --arg handoff_command "$handoff_command" \
  --arg handoff_contract_valid "$handoff_contract_valid" \
  --arg handoff_contract_error "$handoff_contract_error" \
  --arg handoff_summary_exists "$handoff_summary_exists" \
  --arg handoff_log "$handoff_log" \
  '{
    version: 1,
    schema: {
      id: "phase5_settlement_layer_handoff_run_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    metadata: {
      contract: "phase5-settlement-layer",
      runner_script: "phase5_settlement_layer_handoff_run.sh"
    },
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      dry_run: ($dry_run == 1),
      print_summary_json: ($print_summary_json == 1),
      run_phase5_settlement_layer_run: ($run_phase5_settlement_layer_run == 1),
      run_phase5_settlement_layer_handoff_check: ($run_phase5_settlement_layer_handoff_check == 1),
      run_passthrough_args: $run_passthrough_args,
      handoff_passthrough_args: $handoff_passthrough_args
    },
    steps: {
      phase5_settlement_layer_run: {
        enabled: ($run_phase5_settlement_layer_run == 1),
        status: $run_status,
        rc: $run_rc,
        command_rc: $run_command_rc,
        command: (if $run_command == "" then null else $run_command end),
        contract_valid: (
          if $run_contract_valid == "1" then true
          elif $run_contract_valid == "0" then false
          else null
          end
        ),
        contract_error: (if $run_contract_error == "" then null else $run_contract_error end),
        artifacts: {
          summary_json: $run_summary_json,
          summary_exists: ($run_summary_exists == "true"),
          log: $run_log
        }
      },
      phase5_settlement_layer_handoff_check: {
        enabled: ($run_phase5_settlement_layer_handoff_check == 1),
        status: $handoff_status,
        rc: $handoff_rc,
        command_rc: $handoff_command_rc,
        command: (if $handoff_command == "" then null else $handoff_command end),
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

echo "[phase5-settlement-layer-handoff-run] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[phase5-settlement-layer-handoff-run] reports_dir=$reports_dir"
echo "[phase5-settlement-layer-handoff-run] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
