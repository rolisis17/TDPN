#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase7_mainnet_cutover_check.sh \
    [--phase6-handoff-summary-json PATH] \
    [--phase6-summary-json PATH] \
    [--phase6-contracts-summary-json PATH] \
    [--rollback-path-ready [0|1]] \
    [--operator-approval-ok [0|1]] \
    [--require-run-pipeline-ok [0|1]] \
    [--require-module-tx-surface-ok [0|1]] \
    [--require-tdpnd-grpc-runtime-smoke-ok [0|1]] \
    [--require-tdpnd-grpc-live-smoke-ok [0|1]] \
    [--require-tdpnd-grpc-auth-live-smoke-ok [0|1]] \
    [--require-dual-write-parity-ok [0|1]] \
    [--require-rollback-path-ready [0|1]] \
    [--require-operator-approval-ok [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]]

Purpose:
  Fail-closed checker for Phase-7 mainnet cutover readiness.
  Resolves readiness from Phase-6 handoff/contracts summaries plus manual
  operator gates and returns pass only when all required signals are true.

Resolved signals:
  - run_pipeline_ok
  - module_tx_surface_ok
  - tdpnd_grpc_runtime_smoke_ok
  - tdpnd_grpc_live_smoke_ok
  - tdpnd_grpc_auth_live_smoke_ok
  - dual_write_parity_ok (contracts summary; fallback stage/step: phase6_cosmos_dual_write_parity)
  - rollback_path_ready (manual)
  - operator_approval_ok (manual)

Notes:
  - Canonical handoff input flag is --phase6-handoff-summary-json.
  - Alias --phase6-summary-json is accepted.
  - Required toggles default to 1, except require_operator_approval_ok default 0.
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

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
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

optional_bool_arg_or_die() {
  local name="$1"
  local value
  value="$(trim "${2:-}")"
  if [[ -n "$value" && "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1 when provided"
    exit 2
  fi
}

json_file_valid_01() {
  local path="${1:-}"
  if [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

normalize_boolish_or_empty() {
  local value
  value="$(trim "${1:-}")"
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    true|1|pass|ok|passed|success|succeeded)
      printf '%s' "true"
      ;;
    false|0|fail|error|failed|blocked|skip|skipped|warn|warning)
      printf '%s' "false"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

resolve_signal_raw_or_empty() {
  local path="${1:-}"
  local signal="${2:-}"
  local stage="${3:-}"

  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' ""
    return
  fi

  jq -r \
    --arg signal "$signal" \
    --arg stage "$stage" \
    '(
      if (.[$signal]? != null) then .[$signal]
      elif (.summary[$signal]? != null) then .summary[$signal]
      elif (.signals[$signal]? != null) then .signals[$signal]
      elif (.handoff[$signal]? != null) then .handoff[$signal]
      elif (.stages[$stage].ok? != null) then .stages[$stage].ok
      elif (.stages[$stage].status? != null) then .stages[$stage].status
      elif (.steps[$stage].ok? != null) then .steps[$stage].ok
      elif (.steps[$stage].status? != null) then .steps[$stage].status
      else empty
      end
    ) | if . == null then empty else . end' \
    "$path" 2>/dev/null || true
}

resolve_summary_bool() {
  local path="${1:-}"
  local signal="${2:-}"
  local stage="${3:-}"
  local source="${4:-}"

  local raw normalized value status resolved
  raw="$(resolve_signal_raw_or_empty "$path" "$signal" "$stage")"
  normalized="$(normalize_boolish_or_empty "$raw")"
  value="null"
  status="missing"
  resolved="0"
  if [[ "$normalized" == "true" ]]; then
    value="true"
    status="pass"
    resolved="1"
  elif [[ "$normalized" == "false" ]]; then
    value="false"
    status="fail"
    resolved="1"
  fi
  printf '%s|%s|%s|%s\n' "$value" "$status" "$resolved" "$source"
}

resolve_manual_bool() {
  local raw
  raw="$(trim "${1:-}")"
  if [[ -z "$raw" ]]; then
    printf '%s|%s|%s|%s\n' "null" "missing" "0" "manual_input"
    return
  fi
  if [[ "$raw" == "1" ]]; then
    printf '%s|%s|%s|%s\n' "true" "pass" "1" "manual_input"
  else
    printf '%s|%s|%s|%s\n' "false" "fail" "1" "manual_input"
  fi
}

check_required_signal() {
  local require="$1"
  local value="$2"
  local status="$3"
  local signal_name="$4"
  local -n reasons_ref="$5"
  if [[ "$require" != "1" ]]; then
    return
  fi
  if [[ "$value" == "true" ]]; then
    return
  fi
  if [[ "$status" == "missing" ]]; then
    reasons_ref+=("$signal_name unresolved from provided inputs")
  else
    reasons_ref+=("$signal_name is false")
  fi
}

need_cmd jq
need_cmd date
need_cmd mktemp

phase6_handoff_summary_json="${PHASE7_MAINNET_CUTOVER_CHECK_PHASE6_HANDOFF_SUMMARY_JSON:-${PHASE7_MAINNET_CUTOVER_CHECK_PHASE6_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase6_cosmos_l1_build_testnet_handoff_check_summary.json}}"
phase6_contracts_summary_json="${PHASE7_MAINNET_CUTOVER_CHECK_PHASE6_CONTRACTS_SUMMARY_JSON:-}"
rollback_path_ready="${PHASE7_MAINNET_CUTOVER_CHECK_ROLLBACK_PATH_READY:-}"
operator_approval_ok="${PHASE7_MAINNET_CUTOVER_CHECK_OPERATOR_APPROVAL_OK:-}"
summary_json="${PHASE7_MAINNET_CUTOVER_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase7_mainnet_cutover_check_summary.json}"
canonical_summary_json="${PHASE7_MAINNET_CUTOVER_CHECK_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase7_mainnet_cutover_check_summary.json}"
show_json="${PHASE7_MAINNET_CUTOVER_CHECK_SHOW_JSON:-0}"

require_run_pipeline_ok="${PHASE7_MAINNET_CUTOVER_CHECK_REQUIRE_RUN_PIPELINE_OK:-1}"
require_module_tx_surface_ok="${PHASE7_MAINNET_CUTOVER_CHECK_REQUIRE_MODULE_TX_SURFACE_OK:-1}"
require_tdpnd_grpc_runtime_smoke_ok="${PHASE7_MAINNET_CUTOVER_CHECK_REQUIRE_TDPND_GRPC_RUNTIME_SMOKE_OK:-1}"
require_tdpnd_grpc_live_smoke_ok="${PHASE7_MAINNET_CUTOVER_CHECK_REQUIRE_TDPND_GRPC_LIVE_SMOKE_OK:-1}"
require_tdpnd_grpc_auth_live_smoke_ok="${PHASE7_MAINNET_CUTOVER_CHECK_REQUIRE_TDPND_GRPC_AUTH_LIVE_SMOKE_OK:-1}"
require_dual_write_parity_ok="${PHASE7_MAINNET_CUTOVER_CHECK_REQUIRE_DUAL_WRITE_PARITY_OK:-1}"
require_rollback_path_ready="${PHASE7_MAINNET_CUTOVER_CHECK_REQUIRE_ROLLBACK_PATH_READY:-1}"
require_operator_approval_ok="${PHASE7_MAINNET_CUTOVER_CHECK_REQUIRE_OPERATOR_APPROVAL_OK:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase6-handoff-summary-json|--phase6-summary-json)
      phase6_handoff_summary_json="${2:-}"
      shift 2
      ;;
    --phase6-contracts-summary-json)
      phase6_contracts_summary_json="${2:-}"
      shift 2
      ;;
    --rollback-path-ready)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        rollback_path_ready="${2:-}"
        shift 2
      else
        rollback_path_ready="1"
        shift
      fi
      ;;
    --operator-approval-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        operator_approval_ok="${2:-}"
        shift 2
      else
        operator_approval_ok="1"
        shift
      fi
      ;;
    --require-run-pipeline-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_run_pipeline_ok="${2:-}"
        shift 2
      else
        require_run_pipeline_ok="1"
        shift
      fi
      ;;
    --require-module-tx-surface-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_module_tx_surface_ok="${2:-}"
        shift 2
      else
        require_module_tx_surface_ok="1"
        shift
      fi
      ;;
    --require-tdpnd-grpc-runtime-smoke-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_tdpnd_grpc_runtime_smoke_ok="${2:-}"
        shift 2
      else
        require_tdpnd_grpc_runtime_smoke_ok="1"
        shift
      fi
      ;;
    --require-tdpnd-grpc-live-smoke-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_tdpnd_grpc_live_smoke_ok="${2:-}"
        shift 2
      else
        require_tdpnd_grpc_live_smoke_ok="1"
        shift
      fi
      ;;
    --require-tdpnd-grpc-auth-live-smoke-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_tdpnd_grpc_auth_live_smoke_ok="${2:-}"
        shift 2
      else
        require_tdpnd_grpc_auth_live_smoke_ok="1"
        shift
      fi
      ;;
    --require-dual-write-parity-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_dual_write_parity_ok="${2:-}"
        shift 2
      else
        require_dual_write_parity_ok="1"
        shift
      fi
      ;;
    --require-rollback-path-ready)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_rollback_path_ready="${2:-}"
        shift 2
      else
        require_rollback_path_ready="1"
        shift
      fi
      ;;
    --require-rollback-ready)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_rollback_path_ready="${2:-}"
        shift 2
      else
        require_rollback_path_ready="1"
        shift
      fi
      ;;
    --require-operator-approval-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_operator_approval_ok="${2:-}"
        shift 2
      else
        require_operator_approval_ok="1"
        shift
      fi
      ;;
    --require-operator-approval)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_operator_approval_ok="${2:-}"
        shift 2
      else
        require_operator_approval_ok="1"
        shift
      fi
      ;;
    --summary-json)
      summary_json="${2:-}"
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
    -h|--help)
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

bool_arg_or_die "--require-run-pipeline-ok" "$require_run_pipeline_ok"
bool_arg_or_die "--require-module-tx-surface-ok" "$require_module_tx_surface_ok"
bool_arg_or_die "--require-tdpnd-grpc-runtime-smoke-ok" "$require_tdpnd_grpc_runtime_smoke_ok"
bool_arg_or_die "--require-tdpnd-grpc-live-smoke-ok" "$require_tdpnd_grpc_live_smoke_ok"
bool_arg_or_die "--require-tdpnd-grpc-auth-live-smoke-ok" "$require_tdpnd_grpc_auth_live_smoke_ok"
bool_arg_or_die "--require-dual-write-parity-ok" "$require_dual_write_parity_ok"
bool_arg_or_die "--require-rollback-path-ready" "$require_rollback_path_ready"
bool_arg_or_die "--require-operator-approval-ok" "$require_operator_approval_ok"
optional_bool_arg_or_die "--rollback-path-ready" "$rollback_path_ready"
optional_bool_arg_or_die "--operator-approval-ok" "$operator_approval_ok"
bool_arg_or_die "--show-json" "$show_json"

phase6_handoff_summary_json="$(abs_path "$phase6_handoff_summary_json")"
phase6_contracts_summary_json="$(abs_path "$phase6_contracts_summary_json")"
summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"
mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"

phase6_handoff_summary_provided="0"
if [[ -n "$phase6_handoff_summary_json" ]]; then
  phase6_handoff_summary_provided="1"
fi
phase6_contracts_summary_provided="0"
if [[ -n "$phase6_contracts_summary_json" ]]; then
  phase6_contracts_summary_provided="1"
fi

phase6_handoff_summary_usable="$(json_file_valid_01 "$phase6_handoff_summary_json")"
phase6_contracts_summary_usable="$(json_file_valid_01 "$phase6_contracts_summary_json")"

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
declare -a reasons=()

if [[ "$phase6_handoff_summary_provided" == "1" && "$phase6_handoff_summary_usable" != "1" ]]; then
  reasons+=("phase6 handoff summary file not found or invalid JSON: $phase6_handoff_summary_json")
fi
if [[ "$phase6_contracts_summary_provided" == "1" && "$phase6_contracts_summary_usable" != "1" ]]; then
  reasons+=("phase6 contracts summary file not found or invalid JSON: $phase6_contracts_summary_json")
fi

run_pipeline_pair="$(resolve_summary_bool "$phase6_handoff_summary_json" "run_pipeline_ok" "run_pipeline" "phase6_handoff_summary_json")"
module_tx_surface_pair="$(resolve_summary_bool "$phase6_handoff_summary_json" "module_tx_surface_ok" "module_tx_surface" "phase6_handoff_summary_json")"
tdpnd_grpc_runtime_smoke_pair="$(resolve_summary_bool "$phase6_handoff_summary_json" "tdpnd_grpc_runtime_smoke_ok" "tdpnd_grpc_runtime_smoke" "phase6_handoff_summary_json")"
tdpnd_grpc_live_smoke_pair="$(resolve_summary_bool "$phase6_handoff_summary_json" "tdpnd_grpc_live_smoke_ok" "tdpnd_grpc_live_smoke" "phase6_handoff_summary_json")"
tdpnd_grpc_auth_live_smoke_pair="$(resolve_summary_bool "$phase6_handoff_summary_json" "tdpnd_grpc_auth_live_smoke_ok" "tdpnd_grpc_auth_live_smoke" "phase6_handoff_summary_json")"
dual_write_parity_pair="$(resolve_summary_bool "$phase6_contracts_summary_json" "dual_write_parity_ok" "phase6_cosmos_dual_write_parity" "phase6_contracts_summary_json")"
rollback_path_ready_pair="$(resolve_manual_bool "$rollback_path_ready")"
operator_approval_pair="$(resolve_manual_bool "$operator_approval_ok")"

run_pipeline_ok="${run_pipeline_pair%%|*}"; run_pipeline_pair="${run_pipeline_pair#*|}"
run_pipeline_status="${run_pipeline_pair%%|*}"; run_pipeline_pair="${run_pipeline_pair#*|}"
run_pipeline_resolved="${run_pipeline_pair%%|*}"; run_pipeline_source="${run_pipeline_pair##*|}"

module_tx_surface_ok="${module_tx_surface_pair%%|*}"; module_tx_surface_pair="${module_tx_surface_pair#*|}"
module_tx_surface_status="${module_tx_surface_pair%%|*}"; module_tx_surface_pair="${module_tx_surface_pair#*|}"
module_tx_surface_resolved="${module_tx_surface_pair%%|*}"; module_tx_surface_source="${module_tx_surface_pair##*|}"

tdpnd_grpc_runtime_smoke_ok="${tdpnd_grpc_runtime_smoke_pair%%|*}"; tdpnd_grpc_runtime_smoke_pair="${tdpnd_grpc_runtime_smoke_pair#*|}"
tdpnd_grpc_runtime_smoke_status="${tdpnd_grpc_runtime_smoke_pair%%|*}"; tdpnd_grpc_runtime_smoke_pair="${tdpnd_grpc_runtime_smoke_pair#*|}"
tdpnd_grpc_runtime_smoke_resolved="${tdpnd_grpc_runtime_smoke_pair%%|*}"; tdpnd_grpc_runtime_smoke_source="${tdpnd_grpc_runtime_smoke_pair##*|}"

tdpnd_grpc_live_smoke_ok="${tdpnd_grpc_live_smoke_pair%%|*}"; tdpnd_grpc_live_smoke_pair="${tdpnd_grpc_live_smoke_pair#*|}"
tdpnd_grpc_live_smoke_status="${tdpnd_grpc_live_smoke_pair%%|*}"; tdpnd_grpc_live_smoke_pair="${tdpnd_grpc_live_smoke_pair#*|}"
tdpnd_grpc_live_smoke_resolved="${tdpnd_grpc_live_smoke_pair%%|*}"; tdpnd_grpc_live_smoke_source="${tdpnd_grpc_live_smoke_pair##*|}"

tdpnd_grpc_auth_live_smoke_ok="${tdpnd_grpc_auth_live_smoke_pair%%|*}"; tdpnd_grpc_auth_live_smoke_pair="${tdpnd_grpc_auth_live_smoke_pair#*|}"
tdpnd_grpc_auth_live_smoke_status="${tdpnd_grpc_auth_live_smoke_pair%%|*}"; tdpnd_grpc_auth_live_smoke_pair="${tdpnd_grpc_auth_live_smoke_pair#*|}"
tdpnd_grpc_auth_live_smoke_resolved="${tdpnd_grpc_auth_live_smoke_pair%%|*}"; tdpnd_grpc_auth_live_smoke_source="${tdpnd_grpc_auth_live_smoke_pair##*|}"

dual_write_parity_ok="${dual_write_parity_pair%%|*}"; dual_write_parity_pair="${dual_write_parity_pair#*|}"
dual_write_parity_status="${dual_write_parity_pair%%|*}"; dual_write_parity_pair="${dual_write_parity_pair#*|}"
dual_write_parity_resolved="${dual_write_parity_pair%%|*}"; dual_write_parity_source="${dual_write_parity_pair##*|}"

rollback_path_ready_value="${rollback_path_ready_pair%%|*}"; rollback_path_ready_pair="${rollback_path_ready_pair#*|}"
rollback_path_ready_status="${rollback_path_ready_pair%%|*}"; rollback_path_ready_pair="${rollback_path_ready_pair#*|}"
rollback_path_ready_resolved="${rollback_path_ready_pair%%|*}"; rollback_path_ready_source="${rollback_path_ready_pair##*|}"

operator_approval_value="${operator_approval_pair%%|*}"; operator_approval_pair="${operator_approval_pair#*|}"
operator_approval_status="${operator_approval_pair%%|*}"; operator_approval_pair="${operator_approval_pair#*|}"
operator_approval_resolved="${operator_approval_pair%%|*}"; operator_approval_source="${operator_approval_pair##*|}"

check_required_signal "$require_run_pipeline_ok" "$run_pipeline_ok" "$run_pipeline_status" "run_pipeline_ok" reasons
check_required_signal "$require_module_tx_surface_ok" "$module_tx_surface_ok" "$module_tx_surface_status" "module_tx_surface_ok" reasons
check_required_signal "$require_tdpnd_grpc_runtime_smoke_ok" "$tdpnd_grpc_runtime_smoke_ok" "$tdpnd_grpc_runtime_smoke_status" "tdpnd_grpc_runtime_smoke_ok" reasons
check_required_signal "$require_tdpnd_grpc_live_smoke_ok" "$tdpnd_grpc_live_smoke_ok" "$tdpnd_grpc_live_smoke_status" "tdpnd_grpc_live_smoke_ok" reasons
check_required_signal "$require_tdpnd_grpc_auth_live_smoke_ok" "$tdpnd_grpc_auth_live_smoke_ok" "$tdpnd_grpc_auth_live_smoke_status" "tdpnd_grpc_auth_live_smoke_ok" reasons
check_required_signal "$require_dual_write_parity_ok" "$dual_write_parity_ok" "$dual_write_parity_status" "dual_write_parity_ok" reasons
check_required_signal "$require_rollback_path_ready" "$rollback_path_ready_value" "$rollback_path_ready_status" "rollback_path_ready" reasons
check_required_signal "$require_operator_approval_ok" "$operator_approval_value" "$operator_approval_status" "operator_approval_ok" reasons

status="pass"
rc=0
if ((${#reasons[@]} > 0)); then
  status="fail"
  rc=1
fi
if ((${#reasons[@]} > 0)); then
  reasons_json="$(printf '%s\n' "${reasons[@]}" | jq -R . | jq -s .)"
else
  reasons_json='[]'
fi

summary_tmp="$(mktemp)"
jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$status" \
  --argjson rc "$rc" \
  --arg phase6_handoff_summary_json "$phase6_handoff_summary_json" \
  --arg phase6_contracts_summary_json "$phase6_contracts_summary_json" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg show_json "$show_json" \
  --argjson phase6_handoff_summary_provided "$phase6_handoff_summary_provided" \
  --argjson phase6_contracts_summary_provided "$phase6_contracts_summary_provided" \
  --argjson phase6_handoff_summary_usable "$phase6_handoff_summary_usable" \
  --argjson phase6_contracts_summary_usable "$phase6_contracts_summary_usable" \
  --argjson require_run_pipeline_ok "$require_run_pipeline_ok" \
  --argjson require_module_tx_surface_ok "$require_module_tx_surface_ok" \
  --argjson require_tdpnd_grpc_runtime_smoke_ok "$require_tdpnd_grpc_runtime_smoke_ok" \
  --argjson require_tdpnd_grpc_live_smoke_ok "$require_tdpnd_grpc_live_smoke_ok" \
  --argjson require_tdpnd_grpc_auth_live_smoke_ok "$require_tdpnd_grpc_auth_live_smoke_ok" \
  --argjson require_dual_write_parity_ok "$require_dual_write_parity_ok" \
  --argjson require_rollback_path_ready "$require_rollback_path_ready" \
  --argjson require_operator_approval_ok "$require_operator_approval_ok" \
  --argjson run_pipeline_ok "$run_pipeline_ok" \
  --argjson module_tx_surface_ok "$module_tx_surface_ok" \
  --argjson tdpnd_grpc_runtime_smoke_ok "$tdpnd_grpc_runtime_smoke_ok" \
  --argjson tdpnd_grpc_live_smoke_ok "$tdpnd_grpc_live_smoke_ok" \
  --argjson tdpnd_grpc_auth_live_smoke_ok "$tdpnd_grpc_auth_live_smoke_ok" \
  --argjson dual_write_parity_ok "$dual_write_parity_ok" \
  --argjson rollback_path_ready "$rollback_path_ready_value" \
  --argjson operator_approval_ok "$operator_approval_value" \
  --arg run_pipeline_status "$run_pipeline_status" \
  --arg module_tx_surface_status "$module_tx_surface_status" \
  --arg tdpnd_grpc_runtime_smoke_status "$tdpnd_grpc_runtime_smoke_status" \
  --arg tdpnd_grpc_live_smoke_status "$tdpnd_grpc_live_smoke_status" \
  --arg tdpnd_grpc_auth_live_smoke_status "$tdpnd_grpc_auth_live_smoke_status" \
  --arg dual_write_parity_status "$dual_write_parity_status" \
  --arg rollback_path_ready_status "$rollback_path_ready_status" \
  --arg operator_approval_status "$operator_approval_status" \
  --argjson run_pipeline_resolved "$run_pipeline_resolved" \
  --argjson module_tx_surface_resolved "$module_tx_surface_resolved" \
  --argjson tdpnd_grpc_runtime_smoke_resolved "$tdpnd_grpc_runtime_smoke_resolved" \
  --argjson tdpnd_grpc_live_smoke_resolved "$tdpnd_grpc_live_smoke_resolved" \
  --argjson tdpnd_grpc_auth_live_smoke_resolved "$tdpnd_grpc_auth_live_smoke_resolved" \
  --argjson dual_write_parity_resolved "$dual_write_parity_resolved" \
  --argjson rollback_path_ready_resolved "$rollback_path_ready_resolved" \
  --argjson operator_approval_resolved "$operator_approval_resolved" \
  --arg run_pipeline_source "$run_pipeline_source" \
  --arg module_tx_surface_source "$module_tx_surface_source" \
  --arg tdpnd_grpc_runtime_smoke_source "$tdpnd_grpc_runtime_smoke_source" \
  --arg tdpnd_grpc_live_smoke_source "$tdpnd_grpc_live_smoke_source" \
  --arg tdpnd_grpc_auth_live_smoke_source "$tdpnd_grpc_auth_live_smoke_source" \
  --arg dual_write_parity_source "$dual_write_parity_source" \
  --arg rollback_path_ready_source "$rollback_path_ready_source" \
  --arg operator_approval_source "$operator_approval_source" \
  --argjson reasons "$reasons_json" \
  '{
    version: 1,
    schema: {
      id: "phase7_mainnet_cutover_check_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    fail_closed: true,
    metadata: {
      contract: "phase7-mainnet-cutover",
      script: "phase7_mainnet_cutover_check.sh"
    },
    inputs: {
      phase6_handoff_summary_json: (if $phase6_handoff_summary_json == "" then null else $phase6_handoff_summary_json end),
      phase6_contracts_summary_json: (if $phase6_contracts_summary_json == "" then null else $phase6_contracts_summary_json end),
      summary_json: $summary_json,
      show_json: ($show_json == "1"),
      provided: {
        phase6_handoff_summary_json: ($phase6_handoff_summary_provided == 1),
        phase6_contracts_summary_json: ($phase6_contracts_summary_provided == 1)
      },
      usable: {
        phase6_handoff_summary_json: ($phase6_handoff_summary_usable == 1),
        phase6_contracts_summary_json: ($phase6_contracts_summary_usable == 1)
      }
    },
    policy: {
      require_run_pipeline_ok: ($require_run_pipeline_ok == 1),
      require_module_tx_surface_ok: ($require_module_tx_surface_ok == 1),
      require_tdpnd_grpc_runtime_smoke_ok: ($require_tdpnd_grpc_runtime_smoke_ok == 1),
      require_tdpnd_grpc_live_smoke_ok: ($require_tdpnd_grpc_live_smoke_ok == 1),
      require_tdpnd_grpc_auth_live_smoke_ok: ($require_tdpnd_grpc_auth_live_smoke_ok == 1),
      require_dual_write_parity_ok: ($require_dual_write_parity_ok == 1),
      require_rollback_path_ready: ($require_rollback_path_ready == 1),
      require_operator_approval_ok: ($require_operator_approval_ok == 1)
    },
    signals: {
      run_pipeline_ok: $run_pipeline_ok,
      module_tx_surface_ok: $module_tx_surface_ok,
      tdpnd_grpc_runtime_smoke_ok: $tdpnd_grpc_runtime_smoke_ok,
      tdpnd_grpc_live_smoke_ok: $tdpnd_grpc_live_smoke_ok,
      tdpnd_grpc_auth_live_smoke_ok: $tdpnd_grpc_auth_live_smoke_ok,
      dual_write_parity_ok: $dual_write_parity_ok,
      rollback_path_ready: $rollback_path_ready,
      operator_approval_ok: $operator_approval_ok
    },
    stages: {
      run_pipeline: {
        enabled: ($require_run_pipeline_ok == 1),
        status: $run_pipeline_status,
        resolved: ($run_pipeline_resolved == 1),
        ok: $run_pipeline_ok,
        source: $run_pipeline_source
      },
      module_tx_surface: {
        enabled: ($require_module_tx_surface_ok == 1),
        status: $module_tx_surface_status,
        resolved: ($module_tx_surface_resolved == 1),
        ok: $module_tx_surface_ok,
        source: $module_tx_surface_source
      },
      tdpnd_grpc_runtime_smoke: {
        enabled: ($require_tdpnd_grpc_runtime_smoke_ok == 1),
        status: $tdpnd_grpc_runtime_smoke_status,
        resolved: ($tdpnd_grpc_runtime_smoke_resolved == 1),
        ok: $tdpnd_grpc_runtime_smoke_ok,
        source: $tdpnd_grpc_runtime_smoke_source
      },
      tdpnd_grpc_live_smoke: {
        enabled: ($require_tdpnd_grpc_live_smoke_ok == 1),
        status: $tdpnd_grpc_live_smoke_status,
        resolved: ($tdpnd_grpc_live_smoke_resolved == 1),
        ok: $tdpnd_grpc_live_smoke_ok,
        source: $tdpnd_grpc_live_smoke_source
      },
      tdpnd_grpc_auth_live_smoke: {
        enabled: ($require_tdpnd_grpc_auth_live_smoke_ok == 1),
        status: $tdpnd_grpc_auth_live_smoke_status,
        resolved: ($tdpnd_grpc_auth_live_smoke_resolved == 1),
        ok: $tdpnd_grpc_auth_live_smoke_ok,
        source: $tdpnd_grpc_auth_live_smoke_source
      },
      dual_write_parity: {
        enabled: ($require_dual_write_parity_ok == 1),
        status: $dual_write_parity_status,
        resolved: ($dual_write_parity_resolved == 1),
        ok: $dual_write_parity_ok,
        source: $dual_write_parity_source
      },
      rollback_path_ready: {
        enabled: ($require_rollback_path_ready == 1),
        status: $rollback_path_ready_status,
        resolved: ($rollback_path_ready_resolved == 1),
        ok: $rollback_path_ready,
        source: $rollback_path_ready_source
      },
      operator_approval: {
        enabled: ($require_operator_approval_ok == 1),
        status: $operator_approval_status,
        resolved: ($operator_approval_resolved == 1),
        ok: $operator_approval_ok,
        source: $operator_approval_source
      }
    },
    decision: {
      pass: ($status == "pass"),
      reasons: $reasons
    },
    artifacts: {
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

if [[ "$summary_json" != "$canonical_summary_json" ]]; then
  cp -f "$summary_json" "$canonical_summary_json"
fi

if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 1
