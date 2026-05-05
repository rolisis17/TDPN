#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase6_cosmos_l1_build_testnet_handoff_check.sh \
    [--phase6-run-summary-json PATH] \
    [--phase6-check-summary-json PATH] \
    [--require-run-pipeline-ok [0|1]] \
    [--require-chain-scaffold-ok [0|1]] \
    [--require-proto-surface-ok [0|1]] \
    [--require-proto-codegen-surface-ok [0|1]] \
    [--require-query-surface-ok [0|1]] \
    [--require-module-tx-surface-ok [0|1]] \
    [--require-grpc-app-roundtrip-ok [0|1]] \
    [--require-tdpnd-grpc-runtime-smoke-ok [0|1]] \
    [--require-tdpnd-grpc-live-smoke-ok [0|1]] \
    [--require-tdpnd-grpc-auth-live-smoke-ok [0|1]] \
    [--require-tdpnd-comet-runtime-smoke-ok [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]]

Purpose:
  Fail-closed checker for Phase-6 Cosmos L1 build/testnet handoff readiness.
  Evaluates run pipeline readiness and the handoff booleans from run/check
  artifacts.

Notes:
  - Canonical inputs: --phase6-run-summary-json and --phase6-check-summary-json.
  - Aliases are accepted:
      --phase6-build-testnet-run-summary-json
      --phase6-build-testnet-check-summary-json
      --require-tdpnd-runtime-smoke-ok
      --require-tdpnd-live-smoke-ok
      --require-tdpnd-auth-live-smoke-ok
  - If check summary is omitted, the checker falls back to run summary artifacts:
      .steps.phase6_cosmos_l1_build_testnet_check.artifacts.summary_json
      (or .artifacts.check_summary_json)
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
    and (.schema.id // "") == "phase6_cosmos_l1_build_testnet_run_summary"
    and ((.steps.ci_phase6_cosmos_l1_build_testnet.status | type) == "string")
    and ((.steps.ci_phase6_cosmos_l1_build_testnet.contract_valid | type) == "boolean")
    and ((.steps.phase6_cosmos_l1_build_testnet_check.status | type) == "string")
    and ((.steps.phase6_cosmos_l1_build_testnet_check.contract_valid | type) == "boolean")
  ' "$run_summary_json" >/dev/null 2>&1; then
    contract_valid="1"
  fi

  ci_status="$(json_text_or_empty "$run_summary_json" '.steps.ci_phase6_cosmos_l1_build_testnet.status')"
  ci_cv="$(json_text_or_empty "$run_summary_json" '.steps.ci_phase6_cosmos_l1_build_testnet.contract_valid')"
  check_status="$(json_text_or_empty "$run_summary_json" '.steps.phase6_cosmos_l1_build_testnet_check.status')"
  check_cv="$(json_text_or_empty "$run_summary_json" '.steps.phase6_cosmos_l1_build_testnet_check.contract_valid')"

  if [[ "$contract_valid" != "1" ]]; then
    value="false"; status="invalid"; source="phase6_run_summary.contract"; resolved="1"
  elif [[ "$ci_status" != "pass" || "$ci_cv" != "true" ]]; then
    value="false"; status="fail"; source="phase6_run_summary.steps.ci_phase6_cosmos_l1_build_testnet"; resolved="1"
  elif [[ "$check_status" != "pass" || "$check_cv" != "true" ]]; then
    value="false"; status="fail"; source="phase6_run_summary.steps.phase6_cosmos_l1_build_testnet_check"; resolved="1"
  else
    value="true"; status="pass"; source="phase6_run_summary"; resolved="1"
  fi

  printf '%s|%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved" "$contract_valid"
}

resolve_handoff_bool() {
  local signal="$1"
  local stage="$2"
  local check_summary_json="$3"
  local check_summary_usable="$4"

  local value="null"
  local status="missing"
  local source="unresolved"
  local resolved="0"
  local raw=""
  local normalized=""

  if [[ "$check_summary_usable" == "1" ]]; then
    raw="$(json_text_or_empty "$check_summary_json" "if (.signals.$signal | type) == \"boolean\" then .signals.$signal elif (.stages.$stage.ok | type) == \"boolean\" then .stages.$stage.ok elif (.stages.$stage.status? != null) then .stages.$stage.status elif (.handoff.$signal | type) == \"boolean\" then .handoff.$signal elif (.$signal | type) == \"boolean\" then .$signal else empty end")"
    normalized="$(normalize_boolish_or_empty "$raw")"
    if [[ -n "$normalized" ]]; then
      value="$normalized"
      status="$( [[ "$value" == "true" ]] && printf '%s' "pass" || printf '%s' "fail" )"
      source="phase6_cosmos_l1_build_testnet_check_summary.$signal"
      resolved="1"
    fi
  fi

  printf '%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved"
}

need_cmd jq
need_cmd date
need_cmd mktemp

phase6_run_summary_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_PHASE6_RUN_SUMMARY_JSON:-${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_RUN_SUMMARY_JSON:-}}"
phase6_check_summary_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_PHASE6_CHECK_SUMMARY_JSON:-${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_CHECK_SUMMARY_JSON:-}}"
summary_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase6_cosmos_l1_build_testnet_handoff_check_summary.json}"
canonical_summary_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase6_cosmos_l1_build_testnet_handoff_check_summary.json}"
show_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_SHOW_JSON:-0}"
require_run_pipeline_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_RUN_PIPELINE_OK:-1}"
require_chain_scaffold_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_CHAIN_SCAFFOLD_OK:-1}"
require_proto_surface_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_PROTO_SURFACE_OK:-1}"
require_proto_codegen_surface_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_PROTO_CODEGEN_SURFACE_OK:-1}"
require_query_surface_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_QUERY_SURFACE_OK:-1}"
require_module_tx_surface_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_MODULE_TX_SURFACE_OK:-1}"
require_grpc_app_roundtrip_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_GRPC_APP_ROUNDTRIP_OK:-1}"
require_tdpnd_grpc_runtime_smoke_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_TDPND_GRPC_RUNTIME_SMOKE_OK:-${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_TDPND_RUNTIME_SMOKE_OK:-1}}"
require_tdpnd_grpc_live_smoke_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_TDPND_GRPC_LIVE_SMOKE_OK:-${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_TDPND_LIVE_SMOKE_OK:-1}}"
require_tdpnd_grpc_auth_live_smoke_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_TDPND_GRPC_AUTH_LIVE_SMOKE_OK:-${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_TDPND_AUTH_LIVE_SMOKE_OK:-1}}"
require_tdpnd_comet_runtime_smoke_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_REQUIRE_TDPND_COMET_RUNTIME_SMOKE_OK:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase6-run-summary-json|--phase6-build-testnet-run-summary-json) phase6_run_summary_json="${2:-}"; shift 2 ;;
    --phase6-check-summary-json|--phase6-build-testnet-check-summary-json) phase6_check_summary_json="${2:-}"; shift 2 ;;
    --require-run-pipeline-ok) require_run_pipeline_ok="${2:-1}"; shift $(( $#>=2 ? 2 : 1 )) ;;
    --require-chain-scaffold-ok) require_chain_scaffold_ok="${2:-1}"; shift $(( $#>=2 ? 2 : 1 )) ;;
    --require-proto-surface-ok) require_proto_surface_ok="${2:-1}"; shift $(( $#>=2 ? 2 : 1 )) ;;
    --require-proto-codegen-surface-ok) require_proto_codegen_surface_ok="${2:-1}"; shift $(( $#>=2 ? 2 : 1 )) ;;
    --require-query-surface-ok) require_query_surface_ok="${2:-1}"; shift $(( $#>=2 ? 2 : 1 )) ;;
    --require-module-tx-surface-ok) require_module_tx_surface_ok="${2:-1}"; shift $(( $#>=2 ? 2 : 1 )) ;;
    --require-grpc-app-roundtrip-ok) require_grpc_app_roundtrip_ok="${2:-1}"; shift $(( $#>=2 ? 2 : 1 )) ;;
    --require-tdpnd-grpc-runtime-smoke-ok|--require-tdpnd-runtime-smoke-ok) require_tdpnd_grpc_runtime_smoke_ok="${2:-1}"; shift $(( $#>=2 ? 2 : 1 )) ;;
    --require-tdpnd-grpc-live-smoke-ok|--require-tdpnd-live-smoke-ok) require_tdpnd_grpc_live_smoke_ok="${2:-1}"; shift $(( $#>=2 ? 2 : 1 )) ;;
    --require-tdpnd-grpc-auth-live-smoke-ok|--require-tdpnd-auth-live-smoke-ok) require_tdpnd_grpc_auth_live_smoke_ok="${2:-1}"; shift $(( $#>=2 ? 2 : 1 )) ;;
    --require-tdpnd-comet-runtime-smoke-ok) require_tdpnd_comet_runtime_smoke_ok="${2:-1}"; shift $(( $#>=2 ? 2 : 1 )) ;;
    --summary-json) summary_json="${2:-}"; shift 2 ;;
    --show-json) show_json="${2:-1}"; shift $(( $#>=2 ? 2 : 1 )) ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1"; usage; exit 2 ;;
  esac
done

bool_arg_or_die "--require-run-pipeline-ok" "$require_run_pipeline_ok"
bool_arg_or_die "--require-chain-scaffold-ok" "$require_chain_scaffold_ok"
bool_arg_or_die "--require-proto-surface-ok" "$require_proto_surface_ok"
bool_arg_or_die "--require-proto-codegen-surface-ok" "$require_proto_codegen_surface_ok"
bool_arg_or_die "--require-query-surface-ok" "$require_query_surface_ok"
bool_arg_or_die "--require-module-tx-surface-ok" "$require_module_tx_surface_ok"
bool_arg_or_die "--require-grpc-app-roundtrip-ok" "$require_grpc_app_roundtrip_ok"
bool_arg_or_die "--require-tdpnd-grpc-runtime-smoke-ok" "$require_tdpnd_grpc_runtime_smoke_ok"
bool_arg_or_die "--require-tdpnd-grpc-live-smoke-ok" "$require_tdpnd_grpc_live_smoke_ok"
bool_arg_or_die "--require-tdpnd-grpc-auth-live-smoke-ok" "$require_tdpnd_grpc_auth_live_smoke_ok"
bool_arg_or_die "--require-tdpnd-comet-runtime-smoke-ok" "$require_tdpnd_comet_runtime_smoke_ok"
bool_arg_or_die "--show-json" "$show_json"

phase6_run_summary_json="$(abs_path "$phase6_run_summary_json")"
phase6_check_summary_json="$(abs_path "$phase6_check_summary_json")"
summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"
mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

declare -a reasons=()
phase6_run_summary_usable="0"
phase6_check_summary_usable="0"
resolved_check_summary_json="$phase6_check_summary_json"

if [[ -n "$phase6_run_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$phase6_run_summary_json")" == "1" ]]; then
    phase6_run_summary_usable="1"
  else
    reasons+=("phase6 run summary file not found or invalid JSON: $phase6_run_summary_json")
  fi
fi
if [[ -n "$resolved_check_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$resolved_check_summary_json")" == "1" ]]; then
    phase6_check_summary_usable="1"
  else
    reasons+=("phase6 check summary file not found or invalid JSON: $resolved_check_summary_json")
  fi
fi
if [[ "$phase6_check_summary_usable" != "1" && "$phase6_run_summary_usable" == "1" ]]; then
  fallback_rel="$(json_text_or_empty "$phase6_run_summary_json" '.steps.phase6_cosmos_l1_build_testnet_check.artifacts.summary_json // .artifacts.check_summary_json')"
  if [[ -n "$fallback_rel" ]]; then
    fallback_abs="$(resolve_path_with_base "$fallback_rel" "$phase6_run_summary_json")"
    if [[ "$(json_file_valid_01 "$fallback_abs")" == "1" ]]; then
      resolved_check_summary_json="$fallback_abs"
      phase6_check_summary_usable="1"
    elif [[ -z "$phase6_check_summary_json" ]]; then
      reasons+=("phase6 check summary file not found or invalid JSON: $fallback_abs")
    fi
  fi
fi

run_pipeline_pair="$(resolve_run_pipeline "$phase6_run_summary_json" "$phase6_run_summary_usable")"
run_pipeline_ok="${run_pipeline_pair%%|*}"; run_pipeline_pair="${run_pipeline_pair#*|}"
run_pipeline_status="${run_pipeline_pair%%|*}"; run_pipeline_pair="${run_pipeline_pair#*|}"
run_pipeline_source="${run_pipeline_pair%%|*}"; run_pipeline_pair="${run_pipeline_pair#*|}"
run_pipeline_resolved="${run_pipeline_pair%%|*}"
run_pipeline_contract_valid="${run_pipeline_pair##*|}"

chain_scaffold_pair="$(resolve_handoff_bool "chain_scaffold_ok" "chain_scaffold" "$resolved_check_summary_json" "$phase6_check_summary_usable")"
proto_surface_pair="$(resolve_handoff_bool "proto_surface_ok" "proto_surface" "$resolved_check_summary_json" "$phase6_check_summary_usable")"
proto_codegen_surface_pair="$(resolve_handoff_bool "proto_codegen_surface_ok" "proto_codegen_surface" "$resolved_check_summary_json" "$phase6_check_summary_usable")"
query_surface_pair="$(resolve_handoff_bool "query_surface_ok" "query_surface" "$resolved_check_summary_json" "$phase6_check_summary_usable")"
module_tx_surface_pair="$(resolve_handoff_bool "module_tx_surface_ok" "module_tx_surface" "$resolved_check_summary_json" "$phase6_check_summary_usable")"
grpc_app_roundtrip_pair="$(resolve_handoff_bool "grpc_app_roundtrip_ok" "grpc_app_roundtrip" "$resolved_check_summary_json" "$phase6_check_summary_usable")"
tdpnd_grpc_runtime_smoke_pair="$(resolve_handoff_bool "tdpnd_grpc_runtime_smoke_ok" "tdpnd_grpc_runtime_smoke" "$resolved_check_summary_json" "$phase6_check_summary_usable")"
tdpnd_grpc_live_smoke_pair="$(resolve_handoff_bool "tdpnd_grpc_live_smoke_ok" "tdpnd_grpc_live_smoke" "$resolved_check_summary_json" "$phase6_check_summary_usable")"
tdpnd_grpc_auth_live_smoke_pair="$(resolve_handoff_bool "tdpnd_grpc_auth_live_smoke_ok" "tdpnd_grpc_auth_live_smoke" "$resolved_check_summary_json" "$phase6_check_summary_usable")"
tdpnd_comet_runtime_smoke_pair="$(resolve_handoff_bool "tdpnd_comet_runtime_smoke_ok" "tdpnd_comet_runtime_smoke" "$resolved_check_summary_json" "$phase6_check_summary_usable")"

chain_scaffold_ok="${chain_scaffold_pair%%|*}"; chain_scaffold_pair="${chain_scaffold_pair#*|}"
chain_scaffold_status="${chain_scaffold_pair%%|*}"; chain_scaffold_pair="${chain_scaffold_pair#*|}"
chain_scaffold_source="${chain_scaffold_pair%%|*}"; chain_scaffold_resolved="${chain_scaffold_pair##*|}"
proto_surface_ok="${proto_surface_pair%%|*}"; proto_surface_pair="${proto_surface_pair#*|}"
proto_surface_status="${proto_surface_pair%%|*}"; proto_surface_pair="${proto_surface_pair#*|}"
proto_surface_source="${proto_surface_pair%%|*}"; proto_surface_resolved="${proto_surface_pair##*|}"
proto_codegen_surface_ok="${proto_codegen_surface_pair%%|*}"; proto_codegen_surface_pair="${proto_codegen_surface_pair#*|}"
proto_codegen_surface_status="${proto_codegen_surface_pair%%|*}"; proto_codegen_surface_pair="${proto_codegen_surface_pair#*|}"
proto_codegen_surface_source="${proto_codegen_surface_pair%%|*}"; proto_codegen_surface_resolved="${proto_codegen_surface_pair##*|}"
query_surface_ok="${query_surface_pair%%|*}"; query_surface_pair="${query_surface_pair#*|}"
query_surface_status="${query_surface_pair%%|*}"; query_surface_pair="${query_surface_pair#*|}"
query_surface_source="${query_surface_pair%%|*}"; query_surface_resolved="${query_surface_pair##*|}"
module_tx_surface_ok="${module_tx_surface_pair%%|*}"; module_tx_surface_pair="${module_tx_surface_pair#*|}"
module_tx_surface_status="${module_tx_surface_pair%%|*}"; module_tx_surface_pair="${module_tx_surface_pair#*|}"
module_tx_surface_source="${module_tx_surface_pair%%|*}"; module_tx_surface_resolved="${module_tx_surface_pair##*|}"
grpc_app_roundtrip_ok="${grpc_app_roundtrip_pair%%|*}"; grpc_app_roundtrip_pair="${grpc_app_roundtrip_pair#*|}"
grpc_app_roundtrip_status="${grpc_app_roundtrip_pair%%|*}"; grpc_app_roundtrip_pair="${grpc_app_roundtrip_pair#*|}"
grpc_app_roundtrip_source="${grpc_app_roundtrip_pair%%|*}"; grpc_app_roundtrip_resolved="${grpc_app_roundtrip_pair##*|}"
tdpnd_grpc_runtime_smoke_ok="${tdpnd_grpc_runtime_smoke_pair%%|*}"; tdpnd_grpc_runtime_smoke_pair="${tdpnd_grpc_runtime_smoke_pair#*|}"
tdpnd_grpc_runtime_smoke_status="${tdpnd_grpc_runtime_smoke_pair%%|*}"; tdpnd_grpc_runtime_smoke_pair="${tdpnd_grpc_runtime_smoke_pair#*|}"
tdpnd_grpc_runtime_smoke_source="${tdpnd_grpc_runtime_smoke_pair%%|*}"; tdpnd_grpc_runtime_smoke_resolved="${tdpnd_grpc_runtime_smoke_pair##*|}"
tdpnd_grpc_live_smoke_ok="${tdpnd_grpc_live_smoke_pair%%|*}"; tdpnd_grpc_live_smoke_pair="${tdpnd_grpc_live_smoke_pair#*|}"
tdpnd_grpc_live_smoke_status="${tdpnd_grpc_live_smoke_pair%%|*}"; tdpnd_grpc_live_smoke_pair="${tdpnd_grpc_live_smoke_pair#*|}"
tdpnd_grpc_live_smoke_source="${tdpnd_grpc_live_smoke_pair%%|*}"; tdpnd_grpc_live_smoke_resolved="${tdpnd_grpc_live_smoke_pair##*|}"
tdpnd_grpc_auth_live_smoke_ok="${tdpnd_grpc_auth_live_smoke_pair%%|*}"; tdpnd_grpc_auth_live_smoke_pair="${tdpnd_grpc_auth_live_smoke_pair#*|}"
tdpnd_grpc_auth_live_smoke_status="${tdpnd_grpc_auth_live_smoke_pair%%|*}"; tdpnd_grpc_auth_live_smoke_pair="${tdpnd_grpc_auth_live_smoke_pair#*|}"
tdpnd_grpc_auth_live_smoke_source="${tdpnd_grpc_auth_live_smoke_pair%%|*}"; tdpnd_grpc_auth_live_smoke_resolved="${tdpnd_grpc_auth_live_smoke_pair##*|}"
tdpnd_comet_runtime_smoke_ok="${tdpnd_comet_runtime_smoke_pair%%|*}"; tdpnd_comet_runtime_smoke_pair="${tdpnd_comet_runtime_smoke_pair#*|}"
tdpnd_comet_runtime_smoke_status="${tdpnd_comet_runtime_smoke_pair%%|*}"; tdpnd_comet_runtime_smoke_pair="${tdpnd_comet_runtime_smoke_pair#*|}"
tdpnd_comet_runtime_smoke_source="${tdpnd_comet_runtime_smoke_pair%%|*}"; tdpnd_comet_runtime_smoke_resolved="${tdpnd_comet_runtime_smoke_pair##*|}"

check_required_signal() {
  local require="$1"; local value="$2"; local status="$3"; local key="$4"
  if [[ "$require" == "1" && "$value" != "true" ]]; then
    if [[ "$status" == "missing" ]]; then reasons+=("$key unresolved from provided artifacts"); else reasons+=("$key is false"); fi
  fi
}
check_required_signal "$require_run_pipeline_ok" "$run_pipeline_ok" "$run_pipeline_status" "run_pipeline_ok"
check_required_signal "$require_chain_scaffold_ok" "$chain_scaffold_ok" "$chain_scaffold_status" "chain_scaffold_ok"
check_required_signal "$require_proto_surface_ok" "$proto_surface_ok" "$proto_surface_status" "proto_surface_ok"
check_required_signal "$require_proto_codegen_surface_ok" "$proto_codegen_surface_ok" "$proto_codegen_surface_status" "proto_codegen_surface_ok"
check_required_signal "$require_query_surface_ok" "$query_surface_ok" "$query_surface_status" "query_surface_ok"
check_required_signal "$require_module_tx_surface_ok" "$module_tx_surface_ok" "$module_tx_surface_status" "module_tx_surface_ok"
check_required_signal "$require_grpc_app_roundtrip_ok" "$grpc_app_roundtrip_ok" "$grpc_app_roundtrip_status" "grpc_app_roundtrip_ok"
check_required_signal "$require_tdpnd_grpc_runtime_smoke_ok" "$tdpnd_grpc_runtime_smoke_ok" "$tdpnd_grpc_runtime_smoke_status" "tdpnd_grpc_runtime_smoke_ok"
check_required_signal "$require_tdpnd_grpc_live_smoke_ok" "$tdpnd_grpc_live_smoke_ok" "$tdpnd_grpc_live_smoke_status" "tdpnd_grpc_live_smoke_ok"
check_required_signal "$require_tdpnd_grpc_auth_live_smoke_ok" "$tdpnd_grpc_auth_live_smoke_ok" "$tdpnd_grpc_auth_live_smoke_status" "tdpnd_grpc_auth_live_smoke_ok"
check_required_signal "$require_tdpnd_comet_runtime_smoke_ok" "$tdpnd_comet_runtime_smoke_ok" "$tdpnd_comet_runtime_smoke_status" "tdpnd_comet_runtime_smoke_ok"

status="pass"; rc=0
if ((${#reasons[@]} > 0)); then status="fail"; rc=1; fi
if ((${#reasons[@]} > 0)); then reasons_json="$(printf '%s\n' "${reasons[@]}" | jq -R . | jq -s .)"; else reasons_json='[]'; fi

summary_tmp="$(mktemp)"
jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$status" \
  --argjson rc "$rc" \
  --arg phase6_run_summary_json "$phase6_run_summary_json" \
  --arg phase6_check_summary_json "$resolved_check_summary_json" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --argjson run_summary_usable "$phase6_run_summary_usable" \
  --argjson check_summary_usable "$phase6_check_summary_usable" \
  --arg show_json "$show_json" \
  --argjson require_run_pipeline_ok "$require_run_pipeline_ok" \
  --argjson require_chain_scaffold_ok "$require_chain_scaffold_ok" \
  --argjson require_proto_surface_ok "$require_proto_surface_ok" \
  --argjson require_proto_codegen_surface_ok "$require_proto_codegen_surface_ok" \
  --argjson require_query_surface_ok "$require_query_surface_ok" \
  --argjson require_module_tx_surface_ok "$require_module_tx_surface_ok" \
  --argjson require_grpc_app_roundtrip_ok "$require_grpc_app_roundtrip_ok" \
  --argjson require_tdpnd_grpc_runtime_smoke_ok "$require_tdpnd_grpc_runtime_smoke_ok" \
  --argjson require_tdpnd_grpc_live_smoke_ok "$require_tdpnd_grpc_live_smoke_ok" \
  --argjson require_tdpnd_grpc_auth_live_smoke_ok "$require_tdpnd_grpc_auth_live_smoke_ok" \
  --argjson require_tdpnd_comet_runtime_smoke_ok "$require_tdpnd_comet_runtime_smoke_ok" \
  --argjson run_pipeline_ok "$run_pipeline_ok" \
  --arg run_pipeline_status "$run_pipeline_status" \
  --argjson run_pipeline_resolved "$run_pipeline_resolved" \
  --argjson run_pipeline_contract_valid "$run_pipeline_contract_valid" \
  --arg run_pipeline_source "$run_pipeline_source" \
  --argjson chain_scaffold_ok "$chain_scaffold_ok" --arg chain_scaffold_status "$chain_scaffold_status" --argjson chain_scaffold_resolved "$chain_scaffold_resolved" --arg chain_scaffold_source "$chain_scaffold_source" \
  --argjson proto_surface_ok "$proto_surface_ok" --arg proto_surface_status "$proto_surface_status" --argjson proto_surface_resolved "$proto_surface_resolved" --arg proto_surface_source "$proto_surface_source" \
  --argjson proto_codegen_surface_ok "$proto_codegen_surface_ok" --arg proto_codegen_surface_status "$proto_codegen_surface_status" --argjson proto_codegen_surface_resolved "$proto_codegen_surface_resolved" --arg proto_codegen_surface_source "$proto_codegen_surface_source" \
  --argjson query_surface_ok "$query_surface_ok" --arg query_surface_status "$query_surface_status" --argjson query_surface_resolved "$query_surface_resolved" --arg query_surface_source "$query_surface_source" \
  --argjson module_tx_surface_ok "$module_tx_surface_ok" --arg module_tx_surface_status "$module_tx_surface_status" --argjson module_tx_surface_resolved "$module_tx_surface_resolved" --arg module_tx_surface_source "$module_tx_surface_source" \
  --argjson grpc_app_roundtrip_ok "$grpc_app_roundtrip_ok" --arg grpc_app_roundtrip_status "$grpc_app_roundtrip_status" --argjson grpc_app_roundtrip_resolved "$grpc_app_roundtrip_resolved" --arg grpc_app_roundtrip_source "$grpc_app_roundtrip_source" \
  --argjson tdpnd_grpc_runtime_smoke_ok "$tdpnd_grpc_runtime_smoke_ok" --arg tdpnd_grpc_runtime_smoke_status "$tdpnd_grpc_runtime_smoke_status" --argjson tdpnd_grpc_runtime_smoke_resolved "$tdpnd_grpc_runtime_smoke_resolved" --arg tdpnd_grpc_runtime_smoke_source "$tdpnd_grpc_runtime_smoke_source" \
  --argjson tdpnd_grpc_live_smoke_ok "$tdpnd_grpc_live_smoke_ok" --arg tdpnd_grpc_live_smoke_status "$tdpnd_grpc_live_smoke_status" --argjson tdpnd_grpc_live_smoke_resolved "$tdpnd_grpc_live_smoke_resolved" --arg tdpnd_grpc_live_smoke_source "$tdpnd_grpc_live_smoke_source" \
  --argjson tdpnd_grpc_auth_live_smoke_ok "$tdpnd_grpc_auth_live_smoke_ok" --arg tdpnd_grpc_auth_live_smoke_status "$tdpnd_grpc_auth_live_smoke_status" --argjson tdpnd_grpc_auth_live_smoke_resolved "$tdpnd_grpc_auth_live_smoke_resolved" --arg tdpnd_grpc_auth_live_smoke_source "$tdpnd_grpc_auth_live_smoke_source" \
  --argjson tdpnd_comet_runtime_smoke_ok "$tdpnd_comet_runtime_smoke_ok" --arg tdpnd_comet_runtime_smoke_status "$tdpnd_comet_runtime_smoke_status" --argjson tdpnd_comet_runtime_smoke_resolved "$tdpnd_comet_runtime_smoke_resolved" --arg tdpnd_comet_runtime_smoke_source "$tdpnd_comet_runtime_smoke_source" \
  --argjson reasons "$reasons_json" \
  '{
    version: 1,
    schema: { id: "phase6_cosmos_l1_build_testnet_handoff_check_summary", major: 1, minor: 0 },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    fail_closed: true,
    metadata: { contract: "phase6-cosmos-l1-build-testnet", script: "phase6_cosmos_l1_build_testnet_handoff_check.sh" },
    inputs: {
      phase6_run_summary_json: (if $phase6_run_summary_json == "" then null else $phase6_run_summary_json end),
      phase6_check_summary_json: (if $phase6_check_summary_json == "" then null else $phase6_check_summary_json end),
      show_json: ($show_json == "1"),
      requirements: {
        run_pipeline_ok: ($require_run_pipeline_ok == 1),
        chain_scaffold_ok: ($require_chain_scaffold_ok == 1),
        proto_surface_ok: ($require_proto_surface_ok == 1),
        proto_codegen_surface_ok: ($require_proto_codegen_surface_ok == 1),
        query_surface_ok: ($require_query_surface_ok == 1),
        module_tx_surface_ok: ($require_module_tx_surface_ok == 1),
        grpc_app_roundtrip_ok: ($require_grpc_app_roundtrip_ok == 1),
        tdpnd_grpc_runtime_smoke_ok: ($require_tdpnd_grpc_runtime_smoke_ok == 1),
        tdpnd_grpc_live_smoke_ok: ($require_tdpnd_grpc_live_smoke_ok == 1),
        tdpnd_grpc_auth_live_smoke_ok: ($require_tdpnd_grpc_auth_live_smoke_ok == 1),
        tdpnd_comet_runtime_smoke_ok: ($require_tdpnd_comet_runtime_smoke_ok == 1)
      },
      usable: {
        phase6_run_summary_json: ($run_summary_usable == 1),
        phase6_check_summary_json: ($check_summary_usable == 1)
      }
    },
    handoff: {
      run_pipeline_ok: $run_pipeline_ok,
      run_pipeline_status: $run_pipeline_status,
      run_pipeline_resolved: ($run_pipeline_resolved == 1),
      run_pipeline_contract_valid: ($run_pipeline_contract_valid == 1),
      chain_scaffold_ok: $chain_scaffold_ok,
      chain_scaffold_status: $chain_scaffold_status,
      chain_scaffold_resolved: ($chain_scaffold_resolved == 1),
      proto_surface_ok: $proto_surface_ok,
      proto_surface_status: $proto_surface_status,
      proto_surface_resolved: ($proto_surface_resolved == 1),
      proto_codegen_surface_ok: $proto_codegen_surface_ok,
      proto_codegen_surface_status: $proto_codegen_surface_status,
      proto_codegen_surface_resolved: ($proto_codegen_surface_resolved == 1),
      query_surface_ok: $query_surface_ok,
      query_surface_status: $query_surface_status,
      query_surface_resolved: ($query_surface_resolved == 1),
      module_tx_surface_ok: $module_tx_surface_ok,
      module_tx_surface_status: $module_tx_surface_status,
      module_tx_surface_resolved: ($module_tx_surface_resolved == 1),
      grpc_app_roundtrip_ok: $grpc_app_roundtrip_ok,
      grpc_app_roundtrip_status: $grpc_app_roundtrip_status,
      grpc_app_roundtrip_resolved: ($grpc_app_roundtrip_resolved == 1),
      tdpnd_grpc_runtime_smoke_ok: $tdpnd_grpc_runtime_smoke_ok,
      tdpnd_grpc_runtime_smoke_status: $tdpnd_grpc_runtime_smoke_status,
      tdpnd_grpc_runtime_smoke_resolved: ($tdpnd_grpc_runtime_smoke_resolved == 1),
      tdpnd_grpc_live_smoke_ok: $tdpnd_grpc_live_smoke_ok,
      tdpnd_grpc_live_smoke_status: $tdpnd_grpc_live_smoke_status,
      tdpnd_grpc_live_smoke_resolved: ($tdpnd_grpc_live_smoke_resolved == 1),
      tdpnd_grpc_auth_live_smoke_ok: $tdpnd_grpc_auth_live_smoke_ok,
      tdpnd_grpc_auth_live_smoke_status: $tdpnd_grpc_auth_live_smoke_status,
      tdpnd_grpc_auth_live_smoke_resolved: ($tdpnd_grpc_auth_live_smoke_resolved == 1),
      tdpnd_comet_runtime_smoke_ok: $tdpnd_comet_runtime_smoke_ok,
      tdpnd_comet_runtime_smoke_status: $tdpnd_comet_runtime_smoke_status,
      tdpnd_comet_runtime_smoke_resolved: ($tdpnd_comet_runtime_smoke_resolved == 1),
      sources: {
        run_pipeline_ok: $run_pipeline_source,
        chain_scaffold_ok: $chain_scaffold_source,
        proto_surface_ok: $proto_surface_source,
        proto_codegen_surface_ok: $proto_codegen_surface_source,
        query_surface_ok: $query_surface_source,
        module_tx_surface_ok: $module_tx_surface_source,
        grpc_app_roundtrip_ok: $grpc_app_roundtrip_source,
        tdpnd_grpc_runtime_smoke_ok: $tdpnd_grpc_runtime_smoke_source,
        tdpnd_grpc_live_smoke_ok: $tdpnd_grpc_live_smoke_source,
        tdpnd_grpc_auth_live_smoke_ok: $tdpnd_grpc_auth_live_smoke_source,
        tdpnd_comet_runtime_smoke_ok: $tdpnd_comet_runtime_smoke_source
      }
    },
    decision: { pass: ($status == "pass"), reasons: $reasons, warnings: [] },
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
