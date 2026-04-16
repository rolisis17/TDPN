#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase7_mainnet_cutover_handoff_run.sh \
    [--reports-dir DIR] \
    [--run-summary-json PATH] \
    [--handoff-summary-json PATH] \
    [--summary-json PATH] \
    [--run-phase7-mainnet-cutover-run [0|1]] \
    [--run-phase7-mainnet-cutover-handoff-check [0|1]] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--run-<arg> ...] \
    [--handoff-<arg> ...]

Purpose:
  One-command Phase-7 mainnet cutover handoff runner:
    1) phase7_mainnet_cutover_run.sh
    2) phase7_mainnet_cutover_handoff_check.sh

Notes:
  - Wrapper-owned flags are reserved; stage pass-through uses prefixes:
      --run-...      -> forwarded to phase7_mainnet_cutover_run.sh
      --handoff-...  -> forwarded to phase7_mainnet_cutover_handoff_check.sh
  - Dry-run forwards --dry-run 1 to the run stage.
    The handoff check still executes against generated summaries.
  - Dry-run relaxes handoff requirements to 0 unless explicitly supplied:
      --require-run-pipeline-ok
      --require-module-tx-surface-ok
      --require-tdpnd-grpc-runtime-smoke-ok
      --require-tdpnd-grpc-live-smoke-ok
      --require-tdpnd-grpc-auth-live-smoke-ok
      --require-tdpnd-comet-runtime-smoke-ok
      --require-mainnet-activation-gate-go
      --require-dual-write-parity-ok
      --require-cosmos-module-coverage-floor-ok
      --require-cosmos-keeper-coverage-floor-ok
      --require-cosmos-app-coverage-floor-ok
      --require-rollback-path-ready (alias: --require-rollback-ready)
      --require-operator-approval-ok (alias: --require-operator-approval)
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
    and (.schema.id // "") == "phase7_mainnet_cutover_run_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) | floor) == (.schema.major // 0)
    and (.status | type) == "string"
    and (.rc | type) == "number"
    and (.steps.phase7_mainnet_cutover_check | type) == "object"
    and ((.steps.phase7_mainnet_cutover_check.status | type) == "string")
    and ((.steps.phase7_mainnet_cutover_check.rc | type) == "number")
    and ((.steps.phase7_mainnet_cutover_check.command_rc | type) == "number")
    and ((.steps.phase7_mainnet_cutover_check.contract_valid | type) == "boolean")
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
    and (.schema.id // "") == "phase7_mainnet_cutover_handoff_check_summary"
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
  echo "[phase7-mainnet-cutover-handoff-run] stage=$label status=running"
  set +e
  "$@" >"$log_path" 2>&1
  rc=$?
  if (( rc == 0 )); then
    echo "[phase7-mainnet-cutover-handoff-run] stage=$label status=pass rc=0"
  else
    echo "[phase7-mainnet-cutover-handoff-run] stage=$label status=fail rc=$rc"
  fi
  return "$rc"
}

extract_run_check_summary_path() {
  local run_summary_json="$1"
  local path=""
  if [[ -f "$run_summary_json" ]] && jq -e . "$run_summary_json" >/dev/null 2>&1; then
    path="$(jq -r '(.steps.phase7_mainnet_cutover_check.artifacts.summary_json // .artifacts.check_summary_json // empty)' "$run_summary_json" 2>/dev/null || true)"
  fi
  if [[ -n "$path" ]]; then
    printf '%s' "$(resolve_path_with_base "$path" "$run_summary_json")"
  else
    printf '%s' ""
  fi
}

extract_handoff_signal_json() {
  local handoff_summary_json="$1"
  local signal_key="$2"
  if ! json_file_valid "$handoff_summary_json"; then
    printf '%s' "null"
    return
  fi
  jq -c --arg signal_key "$signal_key" '.handoff[$signal_key] // .signals[$signal_key] // null' "$handoff_summary_json" 2>/dev/null || printf '%s' "null"
}

need_cmd jq
need_cmd date
need_cmd mktemp
need_cmd cp

reports_dir="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_REPORTS_DIR:-}"
run_summary_json="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_RUN_SUMMARY_JSON:-}"
handoff_summary_json="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_HANDOFF_SUMMARY_JSON:-}"
summary_json="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_SUMMARY_JSON:-}"
canonical_summary_json="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase7_mainnet_cutover_handoff_run_summary.json}"
print_summary_json="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_PRINT_SUMMARY_JSON:-1}"
dry_run="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_DRY_RUN:-0}"
run_phase7_mainnet_cutover_run="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_RUN_PHASE7_MAINNET_CUTOVER_RUN:-1}"
run_phase7_mainnet_cutover_handoff_check="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_RUN_PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK:-1}"

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
    --run-phase7-mainnet-cutover-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase7_mainnet_cutover_run="${2:-}"
        shift 2
      else
        run_phase7_mainnet_cutover_run="1"
        shift
      fi
      ;;
    --run-phase7-mainnet-cutover-handoff-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase7_mainnet_cutover_handoff_check="${2:-}"
        shift 2
      else
        run_phase7_mainnet_cutover_handoff_check="1"
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

bool_arg_or_die "--run-phase7-mainnet-cutover-run" "$run_phase7_mainnet_cutover_run"
bool_arg_or_die "--run-phase7-mainnet-cutover-handoff-check" "$run_phase7_mainnet_cutover_handoff_check"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--dry-run" "$dry_run"

run_script="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_RUN_SCRIPT:-$ROOT_DIR/scripts/phase7_mainnet_cutover_run.sh}"
handoff_check_script="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase7_mainnet_cutover_handoff_check.sh}"

if [[ "$run_phase7_mainnet_cutover_run" == "1" && ! -x "$run_script" ]]; then
  echo "missing executable stage script: $run_script"
  exit 2
fi
if [[ "$run_phase7_mainnet_cutover_handoff_check" == "1" && ! -x "$handoff_check_script" ]]; then
  echo "missing executable stage script: $handoff_check_script"
  exit 2
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/phase7_mainnet_cutover_handoff_run_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$run_summary_json" ]]; then
  run_summary_json="$reports_dir/phase7_mainnet_cutover_run_summary.json"
else
  run_summary_json="$(abs_path "$run_summary_json")"
fi
if [[ -z "$handoff_summary_json" ]]; then
  handoff_summary_json="$reports_dir/phase7_mainnet_cutover_handoff_check_summary.json"
else
  handoff_summary_json="$(abs_path "$handoff_summary_json")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/phase7_mainnet_cutover_handoff_run_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
canonical_summary_json="$(abs_path "$canonical_summary_json")"

mkdir -p "$reports_dir" \
  "$(dirname "$run_summary_json")" \
  "$(dirname "$handoff_summary_json")" \
  "$(dirname "$summary_json")" \
  "$(dirname "$canonical_summary_json")"

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
declare run_check_summary_json=""

declare -a run_cmd=("$run_script" --reports-dir "$reports_dir" --summary-json "$run_summary_json")
if [[ "$dry_run" == "1" ]]; then
  run_cmd+=(--dry-run 1)
fi
if ((${#run_passthrough_args[@]} > 0)); then
  run_cmd+=("${run_passthrough_args[@]}")
fi
run_command="$(print_cmd "${run_cmd[@]}")"

if [[ "$run_phase7_mainnet_cutover_run" == "1" ]]; then
  set +e
  run_stage_capture "phase7_mainnet_cutover_run" "$run_log" "${run_cmd[@]}"
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
  run_check_summary_json="$(extract_run_check_summary_path "$run_summary_json")"
else
  echo "[phase7-mainnet-cutover-handoff-run] stage=phase7_mainnet_cutover_run status=skipped reason=disabled"
fi

declare -a handoff_cmd=(
  "$handoff_check_script"
  --phase7-run-summary-json "$run_summary_json"
  --summary-json "$handoff_summary_json"
)
if [[ -n "$run_check_summary_json" ]] && ! array_has_arg "--phase7-check-summary-json" "${handoff_passthrough_args[@]}"; then
  handoff_cmd+=(--phase7-check-summary-json "$run_check_summary_json")
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
  if ! array_has_arg "--require-module-tx-surface-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-module-tx-surface-ok 0)
  fi
  if ! array_has_arg "--require-tdpnd-grpc-runtime-smoke-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-tdpnd-grpc-runtime-smoke-ok 0)
  fi
  if ! array_has_arg "--require-tdpnd-grpc-live-smoke-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-tdpnd-grpc-live-smoke-ok 0)
  fi
  if ! array_has_arg "--require-tdpnd-grpc-auth-live-smoke-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-tdpnd-grpc-auth-live-smoke-ok 0)
  fi
  if ! array_has_arg "--require-tdpnd-comet-runtime-smoke-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-tdpnd-comet-runtime-smoke-ok 0)
  fi
  if ! array_has_arg "--require-mainnet-activation-gate-go" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-mainnet-activation-gate-go 0)
  fi
  if ! array_has_arg "--require-dual-write-parity-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-dual-write-parity-ok 0)
  fi
  if ! array_has_arg "--require-cosmos-module-coverage-floor-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-cosmos-module-coverage-floor-ok 0)
  fi
  if ! array_has_arg "--require-cosmos-keeper-coverage-floor-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-cosmos-keeper-coverage-floor-ok 0)
  fi
  if ! array_has_arg "--require-cosmos-app-coverage-floor-ok" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-cosmos-app-coverage-floor-ok 0)
  fi
  if ! array_has_arg "--require-rollback-path-ready" "${handoff_cmd[@]:1}" \
    && ! array_has_arg "--require-rollback-ready" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-rollback-path-ready 0)
  fi
  if ! array_has_arg "--require-operator-approval-ok" "${handoff_cmd[@]:1}" \
    && ! array_has_arg "--require-operator-approval" "${handoff_cmd[@]:1}"; then
    handoff_cmd+=(--require-operator-approval-ok 0)
  fi
fi
handoff_command="$(print_cmd "${handoff_cmd[@]}")"

if [[ "$run_phase7_mainnet_cutover_handoff_check" == "1" ]]; then
  set +e
  run_stage_capture "phase7_mainnet_cutover_handoff_check" "$handoff_log" "${handoff_cmd[@]}"
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
  echo "[phase7-mainnet-cutover-handoff-run] stage=phase7_mainnet_cutover_handoff_check status=skipped reason=disabled"
fi

final_rc=0
if [[ "$run_phase7_mainnet_cutover_run" == "1" ]] && (( run_rc != 0 )) && (( final_rc == 0 )); then
  final_rc="$run_rc"
fi
if [[ "$run_phase7_mainnet_cutover_handoff_check" == "1" ]] && (( handoff_rc != 0 )) && (( final_rc == 0 )); then
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

signal_module_tx_surface_ok="null"
signal_tdpnd_grpc_auth_live_smoke_ok="null"
signal_tdpnd_comet_runtime_smoke_ok="null"
signal_mainnet_activation_gate_go="null"
signal_dual_write_parity_ok="null"
signal_cosmos_module_coverage_floor_ok="null"
signal_cosmos_keeper_coverage_floor_ok="null"
signal_cosmos_app_coverage_floor_ok="null"
signal_rollback_path_ready="null"
signal_operator_approval_ok="null"
if [[ "$handoff_contract_valid" == "1" ]]; then
  signal_module_tx_surface_ok="$(extract_handoff_signal_json "$handoff_summary_json" "module_tx_surface_ok")"
  signal_tdpnd_grpc_auth_live_smoke_ok="$(extract_handoff_signal_json "$handoff_summary_json" "tdpnd_grpc_auth_live_smoke_ok")"
  signal_tdpnd_comet_runtime_smoke_ok="$(extract_handoff_signal_json "$handoff_summary_json" "tdpnd_comet_runtime_smoke_ok")"
  signal_mainnet_activation_gate_go="$(extract_handoff_signal_json "$handoff_summary_json" "mainnet_activation_gate_go")"
  signal_dual_write_parity_ok="$(extract_handoff_signal_json "$handoff_summary_json" "dual_write_parity_ok")"
  signal_cosmos_module_coverage_floor_ok="$(extract_handoff_signal_json "$handoff_summary_json" "cosmos_module_coverage_floor_ok")"
  signal_cosmos_keeper_coverage_floor_ok="$(extract_handoff_signal_json "$handoff_summary_json" "cosmos_keeper_coverage_floor_ok")"
  signal_cosmos_app_coverage_floor_ok="$(extract_handoff_signal_json "$handoff_summary_json" "cosmos_app_coverage_floor_ok")"
  signal_rollback_path_ready="$(extract_handoff_signal_json "$handoff_summary_json" "rollback_path_ready")"
  signal_operator_approval_ok="$(extract_handoff_signal_json "$handoff_summary_json" "operator_approval_ok")"
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
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg run_summary_json "$run_summary_json" \
  --arg handoff_summary_json "$handoff_summary_json" \
  --arg run_check_summary_json "$run_check_summary_json" \
  --argjson dry_run "$dry_run" \
  --argjson print_summary_json "$print_summary_json" \
  --argjson run_phase7_mainnet_cutover_run "$run_phase7_mainnet_cutover_run" \
  --argjson run_phase7_mainnet_cutover_handoff_check "$run_phase7_mainnet_cutover_handoff_check" \
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
  --argjson signal_module_tx_surface_ok "$signal_module_tx_surface_ok" \
  --argjson signal_tdpnd_grpc_auth_live_smoke_ok "$signal_tdpnd_grpc_auth_live_smoke_ok" \
  --argjson signal_tdpnd_comet_runtime_smoke_ok "$signal_tdpnd_comet_runtime_smoke_ok" \
  --argjson signal_mainnet_activation_gate_go "$signal_mainnet_activation_gate_go" \
  --argjson signal_dual_write_parity_ok "$signal_dual_write_parity_ok" \
  --argjson signal_cosmos_module_coverage_floor_ok "$signal_cosmos_module_coverage_floor_ok" \
  --argjson signal_cosmos_keeper_coverage_floor_ok "$signal_cosmos_keeper_coverage_floor_ok" \
  --argjson signal_cosmos_app_coverage_floor_ok "$signal_cosmos_app_coverage_floor_ok" \
  --argjson signal_rollback_path_ready "$signal_rollback_path_ready" \
  --argjson signal_operator_approval_ok "$signal_operator_approval_ok" \
  '{
    version: 1,
    schema: {
      id: "phase7_mainnet_cutover_handoff_run_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    metadata: {
      contract: "phase7-mainnet-cutover-handoff",
      runner_script: "phase7_mainnet_cutover_handoff_run.sh"
    },
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      dry_run: ($dry_run == 1),
      print_summary_json: ($print_summary_json == 1),
      run_phase7_mainnet_cutover_run: ($run_phase7_mainnet_cutover_run == 1),
      run_phase7_mainnet_cutover_handoff_check: ($run_phase7_mainnet_cutover_handoff_check == 1),
      run_passthrough_args: $run_passthrough_args,
      handoff_passthrough_args: $handoff_passthrough_args
    },
    steps: {
      phase7_mainnet_cutover_run: {
        enabled: ($run_phase7_mainnet_cutover_run == 1),
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
      phase7_mainnet_cutover_handoff_check: {
        enabled: ($run_phase7_mainnet_cutover_handoff_check == 1),
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
        signal_snapshot: {
          module_tx_surface_ok: $signal_module_tx_surface_ok,
          tdpnd_grpc_auth_live_smoke_ok: $signal_tdpnd_grpc_auth_live_smoke_ok,
          tdpnd_comet_runtime_smoke_ok: $signal_tdpnd_comet_runtime_smoke_ok,
          mainnet_activation_gate_go: $signal_mainnet_activation_gate_go,
          dual_write_parity_ok: $signal_dual_write_parity_ok,
          cosmos_module_coverage_floor_ok: $signal_cosmos_module_coverage_floor_ok,
          cosmos_keeper_coverage_floor_ok: $signal_cosmos_keeper_coverage_floor_ok,
          cosmos_app_coverage_floor_ok: $signal_cosmos_app_coverage_floor_ok,
          rollback_path_ready: $signal_rollback_path_ready,
          operator_approval_ok: $signal_operator_approval_ok
        },
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
      canonical_summary_json: $canonical_summary_json,
      run_summary_json: $run_summary_json,
      handoff_summary_json: $handoff_summary_json,
      run_check_summary_json: (if $run_check_summary_json == "" then null else $run_check_summary_json end),
      run_log: $run_log,
      handoff_log: $handoff_log
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"
if [[ "$summary_json" != "$canonical_summary_json" ]]; then
  canonical_tmp="$(mktemp "${canonical_summary_json}.tmp.XXXXXX")"
  cp "$summary_json" "$canonical_tmp"
  mv -f "$canonical_tmp" "$canonical_summary_json"
fi

echo "[phase7-mainnet-cutover-handoff-run] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[phase7-mainnet-cutover-handoff-run] reports_dir=$reports_dir"
echo "[phase7-mainnet-cutover-handoff-run] summary_json=$summary_json"
echo "[phase7-mainnet-cutover-handoff-run] canonical_summary_json=$canonical_summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
