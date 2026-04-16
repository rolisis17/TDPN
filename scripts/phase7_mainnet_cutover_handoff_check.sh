#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase7_mainnet_cutover_handoff_check.sh \
    [--phase7-run-summary-json PATH] \
    [--phase7-check-summary-json PATH] \
    [--phase7-summary-report-json PATH] \
    [--require-run-pipeline-ok [0|1]] \
    [--require-summary-report-ok [0|1]] \
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
  Fail-closed checker for Phase-7 mainnet cutover handoff readiness.
  Reads Phase-7 run + summary-report artifacts and verifies handoff signals.

Resolved handoff signals:
  - run_pipeline_ok
  - summary_report_ok
  - module_tx_surface_ok
  - tdpnd_grpc_runtime_smoke_ok
  - tdpnd_grpc_live_smoke_ok
  - tdpnd_grpc_auth_live_smoke_ok
  - dual_write_parity_ok
  - rollback_path_ready
  - operator_approval_ok

Notes:
  - Canonical run input is --phase7-run-summary-json.
  - Optional check-summary input is --phase7-check-summary-json.
  - Canonical summary-report input is --phase7-summary-report-json.
  - Aliases are accepted:
      --phase7-mainnet-cutover-run-summary-json
      --phase7-mainnet-cutover-check-summary-json
      --phase7-mainnet-cutover-summary-report-json
      --require-rollback-ready
      --require-operator-approval
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

json_file_valid_01() {
  local path="${1:-}"
  if [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

json_text_or_empty() {
  local path="${1:-}"
  local expr="${2:-}"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  jq -r "($expr) | if . == null then empty else . end" "$path" 2>/dev/null || true
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

resolve_run_pipeline() {
  local run_summary_json="$1"
  local run_summary_usable="$2"
  local value="null"
  local status="missing"
  local source="unresolved"
  local resolved="0"
  local contract_valid="0"

  if [[ "$run_summary_usable" != "1" ]]; then
    printf '%s|%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved" "$contract_valid"
    return
  fi

  if jq -e '
    type == "object"
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (.schema.id // "") == "phase7_mainnet_cutover_run_summary"
    and ((.status | type) == "string")
    and ((.rc | type) == "number")
    and ((.steps.phase7_mainnet_cutover_check.status | type) == "string")
    and ((.steps.phase7_mainnet_cutover_check.rc | type) == "number")
    and ((.steps.phase7_mainnet_cutover_check.command_rc | type) == "number")
    and ((.steps.phase7_mainnet_cutover_check.contract_valid | type) == "boolean")
  ' "$run_summary_json" >/dev/null 2>&1; then
    contract_valid="1"
  fi

  local check_status=""
  local check_contract_valid="0"
  check_status="$(json_text_or_empty "$run_summary_json" '.steps.phase7_mainnet_cutover_check.status')"
  if [[ "$(json_text_or_empty "$run_summary_json" '.steps.phase7_mainnet_cutover_check.contract_valid')" == "true" ]]; then
    check_contract_valid="1"
  fi

  if [[ "$contract_valid" != "1" ]]; then
    value="false"
    status="invalid"
    source="phase7_run_summary.contract"
    resolved="1"
  elif [[ "$check_status" != "pass" || "$check_contract_valid" != "1" ]]; then
    value="false"
    status="fail"
    source="phase7_run_summary.steps.phase7_mainnet_cutover_check"
    resolved="1"
  else
    value="true"
    status="pass"
    source="phase7_run_summary"
    resolved="1"
  fi

  printf '%s|%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved" "$contract_valid"
}

resolve_run_signal() {
  local signal="$1"
  local run_summary_json="$2"
  local run_summary_usable="$3"
  local check_summary_json="$4"
  local check_summary_usable="$5"
  local value="null"
  local status="missing"
  local source="unresolved"
  local resolved="0"
  local raw=""
  local normalized=""

  if [[ "$run_summary_usable" == "1" ]]; then
    raw="$(json_text_or_empty "$run_summary_json" "if (.steps.phase7_mainnet_cutover_check.signal_snapshot.$signal | type) == \"boolean\" then .steps.phase7_mainnet_cutover_check.signal_snapshot.$signal elif (.steps.phase7_mainnet_cutover_check.signals.$signal | type) == \"boolean\" then .steps.phase7_mainnet_cutover_check.signals.$signal elif (.signals.$signal | type) == \"boolean\" then .signals.$signal elif (.handoff.$signal | type) == \"boolean\" then .handoff.$signal else empty end")"
    normalized="$(normalize_boolish_or_empty "$raw")"
    if [[ -n "$normalized" ]]; then
      value="$normalized"
      status="$( [[ "$value" == "true" ]] && printf '%s' "pass" || printf '%s' "fail" )"
      source="phase7_run_summary.steps.phase7_mainnet_cutover_check.signal_snapshot.$signal"
      resolved="1"
    fi
  fi

  if [[ "$resolved" != "1" && "$check_summary_usable" == "1" ]]; then
    raw="$(json_text_or_empty "$check_summary_json" "if (.signals.$signal | type) == \"boolean\" then .signals.$signal elif (.handoff.$signal | type) == \"boolean\" then .handoff.$signal elif (.stages.$signal.ok | type) == \"boolean\" then .stages.$signal.ok elif (.stages.$signal.status? != null) then .stages.$signal.status elif (.$signal | type) == \"boolean\" then .$signal else empty end")"
    normalized="$(normalize_boolish_or_empty "$raw")"
    if [[ -n "$normalized" ]]; then
      value="$normalized"
      status="$( [[ "$value" == "true" ]] && printf '%s' "pass" || printf '%s' "fail" )"
      source="phase7_check_summary.signals.$signal"
      resolved="1"
    fi
  fi

  printf '%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved"
}

resolve_summary_report_ok() {
  local summary_report_json="$1"
  local summary_report_usable="$2"
  local value="null"
  local status="missing"
  local source="unresolved"
  local resolved="0"
  local contract_valid="0"

  if [[ "$summary_report_usable" != "1" ]]; then
    printf '%s|%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved" "$contract_valid"
    return
  fi

  if jq -e '
    type == "object"
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (.schema.id // "") == "phase7_mainnet_cutover_summary_report"
    and ((.status | type) == "string")
    and ((.rc | type) == "number")
    and ((.summaries.check.status | type) == "string")
    and ((.summaries.run.status | type) == "string")
  ' "$summary_report_json" >/dev/null 2>&1; then
    contract_valid="1"
  fi

  local report_status=""
  local report_rc=""
  local check_status=""
  local run_status=""
  report_status="$(json_text_or_empty "$summary_report_json" '.status')"
  report_rc="$(json_text_or_empty "$summary_report_json" '.rc')"
  check_status="$(json_text_or_empty "$summary_report_json" '.summaries.check.status')"
  run_status="$(json_text_or_empty "$summary_report_json" '.summaries.run.status')"

  if [[ "$contract_valid" != "1" ]]; then
    value="false"
    status="invalid"
    source="phase7_summary_report.contract"
    resolved="1"
  elif [[ "$report_status" == "pass" && "$report_rc" == "0" && "$check_status" == "pass" && "$run_status" == "pass" ]]; then
    value="true"
    status="pass"
    source="phase7_summary_report"
    resolved="1"
  else
    value="false"
    status="fail"
    source="phase7_summary_report.status"
    resolved="1"
  fi

  printf '%s|%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved" "$contract_valid"
}

check_required_signal() {
  local require="$1"
  local value="$2"
  local signal_status="$3"
  local signal_name="$4"
  local -n reasons_ref="$5"
  if [[ "$require" != "1" ]]; then
    return
  fi
  if [[ "$value" == "true" ]]; then
    return
  fi
  if [[ "$signal_status" == "missing" ]]; then
    reasons_ref+=("$signal_name unresolved from provided artifacts")
  else
    reasons_ref+=("$signal_name is false")
  fi
}

need_cmd jq
need_cmd date
need_cmd mktemp
need_cmd cp

phase7_run_summary_json="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_PHASE7_RUN_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase7_mainnet_cutover_run_summary.json}"
phase7_check_summary_json="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_PHASE7_CHECK_SUMMARY_JSON:-}"
phase7_summary_report_json="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_PHASE7_SUMMARY_REPORT_JSON:-$ROOT_DIR/.easy-node-logs/phase7_mainnet_cutover_summary_report.json}"
summary_json="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase7_mainnet_cutover_handoff_check_summary.json}"
canonical_summary_json="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase7_mainnet_cutover_handoff_check_summary.json}"
show_json="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_SHOW_JSON:-0}"

require_run_pipeline_ok="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_REQUIRE_RUN_PIPELINE_OK:-1}"
require_summary_report_ok="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_REQUIRE_SUMMARY_REPORT_OK:-1}"
require_module_tx_surface_ok="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_REQUIRE_MODULE_TX_SURFACE_OK:-1}"
require_tdpnd_grpc_runtime_smoke_ok="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_REQUIRE_TDPND_GRPC_RUNTIME_SMOKE_OK:-1}"
require_tdpnd_grpc_live_smoke_ok="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_REQUIRE_TDPND_GRPC_LIVE_SMOKE_OK:-1}"
require_tdpnd_grpc_auth_live_smoke_ok="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_REQUIRE_TDPND_GRPC_AUTH_LIVE_SMOKE_OK:-1}"
require_dual_write_parity_ok="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_REQUIRE_DUAL_WRITE_PARITY_OK:-1}"
require_rollback_path_ready="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_REQUIRE_ROLLBACK_PATH_READY:-1}"
require_operator_approval_ok="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_REQUIRE_OPERATOR_APPROVAL_OK:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase7-run-summary-json|--phase7-mainnet-cutover-run-summary-json)
      phase7_run_summary_json="${2:-}"
      shift 2
      ;;
    --phase7-check-summary-json|--phase7-mainnet-cutover-check-summary-json)
      phase7_check_summary_json="${2:-}"
      shift 2
      ;;
    --phase7-summary-report-json|--phase7-mainnet-cutover-summary-report-json)
      phase7_summary_report_json="${2:-}"
      shift 2
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
    --require-summary-report-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_summary_report_ok="${2:-}"
        shift 2
      else
        require_summary_report_ok="1"
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
    --require-rollback-path-ready|--require-rollback-ready)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_rollback_path_ready="${2:-}"
        shift 2
      else
        require_rollback_path_ready="1"
        shift
      fi
      ;;
    --require-operator-approval-ok|--require-operator-approval)
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
bool_arg_or_die "--require-summary-report-ok" "$require_summary_report_ok"
bool_arg_or_die "--require-module-tx-surface-ok" "$require_module_tx_surface_ok"
bool_arg_or_die "--require-tdpnd-grpc-runtime-smoke-ok" "$require_tdpnd_grpc_runtime_smoke_ok"
bool_arg_or_die "--require-tdpnd-grpc-live-smoke-ok" "$require_tdpnd_grpc_live_smoke_ok"
bool_arg_or_die "--require-tdpnd-grpc-auth-live-smoke-ok" "$require_tdpnd_grpc_auth_live_smoke_ok"
bool_arg_or_die "--require-dual-write-parity-ok" "$require_dual_write_parity_ok"
bool_arg_or_die "--require-rollback-path-ready" "$require_rollback_path_ready"
bool_arg_or_die "--require-operator-approval-ok" "$require_operator_approval_ok"
bool_arg_or_die "--show-json" "$show_json"

phase7_run_summary_json="$(abs_path "$phase7_run_summary_json")"
phase7_check_summary_json="$(abs_path "$phase7_check_summary_json")"
phase7_summary_report_json="$(abs_path "$phase7_summary_report_json")"
summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"
mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

phase7_run_summary_provided="0"
if [[ -n "$phase7_run_summary_json" ]]; then
  phase7_run_summary_provided="1"
fi
phase7_check_summary_provided="0"
if [[ -n "$phase7_check_summary_json" ]]; then
  phase7_check_summary_provided="1"
fi
phase7_summary_report_provided="0"
if [[ -n "$phase7_summary_report_json" ]]; then
  phase7_summary_report_provided="1"
fi

phase7_run_summary_usable="$(json_file_valid_01 "$phase7_run_summary_json")"
phase7_check_summary_usable="$(json_file_valid_01 "$phase7_check_summary_json")"
phase7_summary_report_usable="$(json_file_valid_01 "$phase7_summary_report_json")"

declare -a reasons=()

run_pipeline_pair="$(resolve_run_pipeline "$phase7_run_summary_json" "$phase7_run_summary_usable")"
summary_report_pair="$(resolve_summary_report_ok "$phase7_summary_report_json" "$phase7_summary_report_usable")"
module_tx_surface_pair="$(resolve_run_signal "module_tx_surface_ok" "$phase7_run_summary_json" "$phase7_run_summary_usable" "$phase7_check_summary_json" "$phase7_check_summary_usable")"
tdpnd_grpc_runtime_smoke_pair="$(resolve_run_signal "tdpnd_grpc_runtime_smoke_ok" "$phase7_run_summary_json" "$phase7_run_summary_usable" "$phase7_check_summary_json" "$phase7_check_summary_usable")"
tdpnd_grpc_live_smoke_pair="$(resolve_run_signal "tdpnd_grpc_live_smoke_ok" "$phase7_run_summary_json" "$phase7_run_summary_usable" "$phase7_check_summary_json" "$phase7_check_summary_usable")"
tdpnd_grpc_auth_live_smoke_pair="$(resolve_run_signal "tdpnd_grpc_auth_live_smoke_ok" "$phase7_run_summary_json" "$phase7_run_summary_usable" "$phase7_check_summary_json" "$phase7_check_summary_usable")"
dual_write_parity_pair="$(resolve_run_signal "dual_write_parity_ok" "$phase7_run_summary_json" "$phase7_run_summary_usable" "$phase7_check_summary_json" "$phase7_check_summary_usable")"
rollback_path_ready_pair="$(resolve_run_signal "rollback_path_ready" "$phase7_run_summary_json" "$phase7_run_summary_usable" "$phase7_check_summary_json" "$phase7_check_summary_usable")"
operator_approval_pair="$(resolve_run_signal "operator_approval_ok" "$phase7_run_summary_json" "$phase7_run_summary_usable" "$phase7_check_summary_json" "$phase7_check_summary_usable")"

run_pipeline_ok="${run_pipeline_pair%%|*}"; run_pipeline_pair="${run_pipeline_pair#*|}"
run_pipeline_status="${run_pipeline_pair%%|*}"; run_pipeline_pair="${run_pipeline_pair#*|}"
run_pipeline_source="${run_pipeline_pair%%|*}"; run_pipeline_pair="${run_pipeline_pair#*|}"
run_pipeline_resolved="${run_pipeline_pair%%|*}"; run_pipeline_contract_valid="${run_pipeline_pair##*|}"

summary_report_ok="${summary_report_pair%%|*}"; summary_report_pair="${summary_report_pair#*|}"
summary_report_status="${summary_report_pair%%|*}"; summary_report_pair="${summary_report_pair#*|}"
summary_report_source="${summary_report_pair%%|*}"; summary_report_pair="${summary_report_pair#*|}"
summary_report_resolved="${summary_report_pair%%|*}"; summary_report_contract_valid="${summary_report_pair##*|}"

module_tx_surface_ok="${module_tx_surface_pair%%|*}"; module_tx_surface_pair="${module_tx_surface_pair#*|}"
module_tx_surface_status="${module_tx_surface_pair%%|*}"; module_tx_surface_pair="${module_tx_surface_pair#*|}"
module_tx_surface_source="${module_tx_surface_pair%%|*}"; module_tx_surface_resolved="${module_tx_surface_pair##*|}"

tdpnd_grpc_runtime_smoke_ok="${tdpnd_grpc_runtime_smoke_pair%%|*}"; tdpnd_grpc_runtime_smoke_pair="${tdpnd_grpc_runtime_smoke_pair#*|}"
tdpnd_grpc_runtime_smoke_status="${tdpnd_grpc_runtime_smoke_pair%%|*}"; tdpnd_grpc_runtime_smoke_pair="${tdpnd_grpc_runtime_smoke_pair#*|}"
tdpnd_grpc_runtime_smoke_source="${tdpnd_grpc_runtime_smoke_pair%%|*}"; tdpnd_grpc_runtime_smoke_resolved="${tdpnd_grpc_runtime_smoke_pair##*|}"

tdpnd_grpc_live_smoke_ok="${tdpnd_grpc_live_smoke_pair%%|*}"; tdpnd_grpc_live_smoke_pair="${tdpnd_grpc_live_smoke_pair#*|}"
tdpnd_grpc_live_smoke_status="${tdpnd_grpc_live_smoke_pair%%|*}"; tdpnd_grpc_live_smoke_pair="${tdpnd_grpc_live_smoke_pair#*|}"
tdpnd_grpc_live_smoke_source="${tdpnd_grpc_live_smoke_pair%%|*}"; tdpnd_grpc_live_smoke_resolved="${tdpnd_grpc_live_smoke_pair##*|}"

tdpnd_grpc_auth_live_smoke_ok="${tdpnd_grpc_auth_live_smoke_pair%%|*}"; tdpnd_grpc_auth_live_smoke_pair="${tdpnd_grpc_auth_live_smoke_pair#*|}"
tdpnd_grpc_auth_live_smoke_status="${tdpnd_grpc_auth_live_smoke_pair%%|*}"; tdpnd_grpc_auth_live_smoke_pair="${tdpnd_grpc_auth_live_smoke_pair#*|}"
tdpnd_grpc_auth_live_smoke_source="${tdpnd_grpc_auth_live_smoke_pair%%|*}"; tdpnd_grpc_auth_live_smoke_resolved="${tdpnd_grpc_auth_live_smoke_pair##*|}"

dual_write_parity_ok="${dual_write_parity_pair%%|*}"; dual_write_parity_pair="${dual_write_parity_pair#*|}"
dual_write_parity_status="${dual_write_parity_pair%%|*}"; dual_write_parity_pair="${dual_write_parity_pair#*|}"
dual_write_parity_source="${dual_write_parity_pair%%|*}"; dual_write_parity_resolved="${dual_write_parity_pair##*|}"

rollback_path_ready="${rollback_path_ready_pair%%|*}"; rollback_path_ready_pair="${rollback_path_ready_pair#*|}"
rollback_path_ready_status="${rollback_path_ready_pair%%|*}"; rollback_path_ready_pair="${rollback_path_ready_pair#*|}"
rollback_path_ready_source="${rollback_path_ready_pair%%|*}"; rollback_path_ready_resolved="${rollback_path_ready_pair##*|}"

operator_approval_ok="${operator_approval_pair%%|*}"; operator_approval_pair="${operator_approval_pair#*|}"
operator_approval_status="${operator_approval_pair%%|*}"; operator_approval_pair="${operator_approval_pair#*|}"
operator_approval_source="${operator_approval_pair%%|*}"; operator_approval_resolved="${operator_approval_pair##*|}"

check_required_signal "$require_run_pipeline_ok" "$run_pipeline_ok" "$run_pipeline_status" "run_pipeline_ok" reasons
check_required_signal "$require_summary_report_ok" "$summary_report_ok" "$summary_report_status" "summary_report_ok" reasons
check_required_signal "$require_module_tx_surface_ok" "$module_tx_surface_ok" "$module_tx_surface_status" "module_tx_surface_ok" reasons
check_required_signal "$require_tdpnd_grpc_runtime_smoke_ok" "$tdpnd_grpc_runtime_smoke_ok" "$tdpnd_grpc_runtime_smoke_status" "tdpnd_grpc_runtime_smoke_ok" reasons
check_required_signal "$require_tdpnd_grpc_live_smoke_ok" "$tdpnd_grpc_live_smoke_ok" "$tdpnd_grpc_live_smoke_status" "tdpnd_grpc_live_smoke_ok" reasons
check_required_signal "$require_tdpnd_grpc_auth_live_smoke_ok" "$tdpnd_grpc_auth_live_smoke_ok" "$tdpnd_grpc_auth_live_smoke_status" "tdpnd_grpc_auth_live_smoke_ok" reasons
check_required_signal "$require_dual_write_parity_ok" "$dual_write_parity_ok" "$dual_write_parity_status" "dual_write_parity_ok" reasons
check_required_signal "$require_rollback_path_ready" "$rollback_path_ready" "$rollback_path_ready_status" "rollback_path_ready" reasons
check_required_signal "$require_operator_approval_ok" "$operator_approval_ok" "$operator_approval_status" "operator_approval_ok" reasons

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
  --arg phase7_run_summary_json "$phase7_run_summary_json" \
  --arg phase7_check_summary_json "$phase7_check_summary_json" \
  --arg phase7_summary_report_json "$phase7_summary_report_json" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg show_json "$show_json" \
  --argjson phase7_run_summary_provided "$phase7_run_summary_provided" \
  --argjson phase7_check_summary_provided "$phase7_check_summary_provided" \
  --argjson phase7_summary_report_provided "$phase7_summary_report_provided" \
  --argjson phase7_run_summary_usable "$phase7_run_summary_usable" \
  --argjson phase7_check_summary_usable "$phase7_check_summary_usable" \
  --argjson phase7_summary_report_usable "$phase7_summary_report_usable" \
  --argjson require_run_pipeline_ok "$require_run_pipeline_ok" \
  --argjson require_summary_report_ok "$require_summary_report_ok" \
  --argjson require_module_tx_surface_ok "$require_module_tx_surface_ok" \
  --argjson require_tdpnd_grpc_runtime_smoke_ok "$require_tdpnd_grpc_runtime_smoke_ok" \
  --argjson require_tdpnd_grpc_live_smoke_ok "$require_tdpnd_grpc_live_smoke_ok" \
  --argjson require_tdpnd_grpc_auth_live_smoke_ok "$require_tdpnd_grpc_auth_live_smoke_ok" \
  --argjson require_dual_write_parity_ok "$require_dual_write_parity_ok" \
  --argjson require_rollback_path_ready "$require_rollback_path_ready" \
  --argjson require_operator_approval_ok "$require_operator_approval_ok" \
  --argjson run_pipeline_ok "$run_pipeline_ok" \
  --argjson summary_report_ok "$summary_report_ok" \
  --argjson module_tx_surface_ok "$module_tx_surface_ok" \
  --argjson tdpnd_grpc_runtime_smoke_ok "$tdpnd_grpc_runtime_smoke_ok" \
  --argjson tdpnd_grpc_live_smoke_ok "$tdpnd_grpc_live_smoke_ok" \
  --argjson tdpnd_grpc_auth_live_smoke_ok "$tdpnd_grpc_auth_live_smoke_ok" \
  --argjson dual_write_parity_ok "$dual_write_parity_ok" \
  --argjson rollback_path_ready "$rollback_path_ready" \
  --argjson operator_approval_ok "$operator_approval_ok" \
  --arg run_pipeline_status "$run_pipeline_status" \
  --arg summary_report_status "$summary_report_status" \
  --arg module_tx_surface_status "$module_tx_surface_status" \
  --arg tdpnd_grpc_runtime_smoke_status "$tdpnd_grpc_runtime_smoke_status" \
  --arg tdpnd_grpc_live_smoke_status "$tdpnd_grpc_live_smoke_status" \
  --arg tdpnd_grpc_auth_live_smoke_status "$tdpnd_grpc_auth_live_smoke_status" \
  --arg dual_write_parity_status "$dual_write_parity_status" \
  --arg rollback_path_ready_status "$rollback_path_ready_status" \
  --arg operator_approval_status "$operator_approval_status" \
  --argjson run_pipeline_resolved "$run_pipeline_resolved" \
  --argjson summary_report_resolved "$summary_report_resolved" \
  --argjson module_tx_surface_resolved "$module_tx_surface_resolved" \
  --argjson tdpnd_grpc_runtime_smoke_resolved "$tdpnd_grpc_runtime_smoke_resolved" \
  --argjson tdpnd_grpc_live_smoke_resolved "$tdpnd_grpc_live_smoke_resolved" \
  --argjson tdpnd_grpc_auth_live_smoke_resolved "$tdpnd_grpc_auth_live_smoke_resolved" \
  --argjson dual_write_parity_resolved "$dual_write_parity_resolved" \
  --argjson rollback_path_ready_resolved "$rollback_path_ready_resolved" \
  --argjson operator_approval_resolved "$operator_approval_resolved" \
  --argjson run_pipeline_contract_valid "$run_pipeline_contract_valid" \
  --argjson summary_report_contract_valid "$summary_report_contract_valid" \
  --arg run_pipeline_source "$run_pipeline_source" \
  --arg summary_report_source "$summary_report_source" \
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
      id: "phase7_mainnet_cutover_handoff_check_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    fail_closed: true,
    metadata: {
      contract: "phase7-mainnet-cutover-handoff",
      script: "phase7_mainnet_cutover_handoff_check.sh"
    },
    inputs: {
      phase7_run_summary_json: (if $phase7_run_summary_json == "" then null else $phase7_run_summary_json end),
      phase7_check_summary_json: (if $phase7_check_summary_json == "" then null else $phase7_check_summary_json end),
      phase7_summary_report_json: (if $phase7_summary_report_json == "" then null else $phase7_summary_report_json end),
      summary_json: $summary_json,
      show_json: ($show_json == "1"),
      provided: {
        phase7_run_summary_json: ($phase7_run_summary_provided == 1),
        phase7_check_summary_json: ($phase7_check_summary_provided == 1),
        phase7_summary_report_json: ($phase7_summary_report_provided == 1)
      },
      usable: {
        phase7_run_summary_json: ($phase7_run_summary_usable == 1),
        phase7_check_summary_json: ($phase7_check_summary_usable == 1),
        phase7_summary_report_json: ($phase7_summary_report_usable == 1)
      },
      requirements: {
        run_pipeline_ok: ($require_run_pipeline_ok == 1),
        summary_report_ok: ($require_summary_report_ok == 1),
        module_tx_surface_ok: ($require_module_tx_surface_ok == 1),
        tdpnd_grpc_runtime_smoke_ok: ($require_tdpnd_grpc_runtime_smoke_ok == 1),
        tdpnd_grpc_live_smoke_ok: ($require_tdpnd_grpc_live_smoke_ok == 1),
        tdpnd_grpc_auth_live_smoke_ok: ($require_tdpnd_grpc_auth_live_smoke_ok == 1),
        dual_write_parity_ok: ($require_dual_write_parity_ok == 1),
        rollback_path_ready: ($require_rollback_path_ready == 1),
        operator_approval_ok: ($require_operator_approval_ok == 1)
      }
    },
    handoff: {
      run_pipeline_ok: $run_pipeline_ok,
      run_pipeline_status: $run_pipeline_status,
      run_pipeline_resolved: ($run_pipeline_resolved == 1),
      run_pipeline_contract_valid: ($run_pipeline_contract_valid == 1),
      summary_report_ok: $summary_report_ok,
      summary_report_status: $summary_report_status,
      summary_report_resolved: ($summary_report_resolved == 1),
      summary_report_contract_valid: ($summary_report_contract_valid == 1),
      module_tx_surface_ok: $module_tx_surface_ok,
      module_tx_surface_status: $module_tx_surface_status,
      module_tx_surface_resolved: ($module_tx_surface_resolved == 1),
      tdpnd_grpc_runtime_smoke_ok: $tdpnd_grpc_runtime_smoke_ok,
      tdpnd_grpc_runtime_smoke_status: $tdpnd_grpc_runtime_smoke_status,
      tdpnd_grpc_runtime_smoke_resolved: ($tdpnd_grpc_runtime_smoke_resolved == 1),
      tdpnd_grpc_live_smoke_ok: $tdpnd_grpc_live_smoke_ok,
      tdpnd_grpc_live_smoke_status: $tdpnd_grpc_live_smoke_status,
      tdpnd_grpc_live_smoke_resolved: ($tdpnd_grpc_live_smoke_resolved == 1),
      tdpnd_grpc_auth_live_smoke_ok: $tdpnd_grpc_auth_live_smoke_ok,
      tdpnd_grpc_auth_live_smoke_status: $tdpnd_grpc_auth_live_smoke_status,
      tdpnd_grpc_auth_live_smoke_resolved: ($tdpnd_grpc_auth_live_smoke_resolved == 1),
      dual_write_parity_ok: $dual_write_parity_ok,
      dual_write_parity_status: $dual_write_parity_status,
      dual_write_parity_resolved: ($dual_write_parity_resolved == 1),
      rollback_path_ready: $rollback_path_ready,
      rollback_path_ready_status: $rollback_path_ready_status,
      rollback_path_ready_resolved: ($rollback_path_ready_resolved == 1),
      operator_approval_ok: $operator_approval_ok,
      operator_approval_status: $operator_approval_status,
      operator_approval_resolved: ($operator_approval_resolved == 1),
      sources: {
        run_pipeline_ok: $run_pipeline_source,
        summary_report_ok: $summary_report_source,
        module_tx_surface_ok: $module_tx_surface_source,
        tdpnd_grpc_runtime_smoke_ok: $tdpnd_grpc_runtime_smoke_source,
        tdpnd_grpc_live_smoke_ok: $tdpnd_grpc_live_smoke_source,
        tdpnd_grpc_auth_live_smoke_ok: $tdpnd_grpc_auth_live_smoke_source,
        dual_write_parity_ok: $dual_write_parity_source,
        rollback_path_ready: $rollback_path_ready_source,
        operator_approval_ok: $operator_approval_source
      }
    },
    decision: {
      pass: ($status == "pass"),
      reasons: $reasons,
      warnings: []
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
