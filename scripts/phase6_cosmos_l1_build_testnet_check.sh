#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase6_cosmos_l1_build_testnet_check.sh \
    [--ci-phase6-summary-json PATH] \
    [--require-chain-scaffold-ok [0|1]] \
    [--require-proto-surface-ok [0|1]] \
    [--require-proto-codegen-surface-ok [0|1]] \
    [--require-query-surface-ok [0|1]] \
    [--require-grpc-app-roundtrip-ok [0|1]] \
    [--require-tdpnd-grpc-runtime-smoke-ok [0|1]] \
    [--require-tdpnd-grpc-live-smoke-ok [0|1]] \
    [--require-tdpnd-grpc-auth-live-smoke-ok [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]]

Purpose:
  Fail-closed checker for the Phase-6 Cosmos L1 build/testnet readiness contract.
  Evaluates required readiness booleans derived from the CI Phase-6 summary:
    - chain_scaffold_ok
    - proto_surface_ok
    - proto_codegen_surface_ok
    - query_surface_ok
    - grpc_app_roundtrip_ok
    - tdpnd_grpc_runtime_smoke_ok
    - tdpnd_grpc_live_smoke_ok
    - tdpnd_grpc_auth_live_smoke_ok

Notes:
  - Canonical CI summary flag is --ci-phase6-summary-json.
  - Aliases --ci-phase6-cosmos-l1-summary-json and --ci-phase6-build-testnet-summary-json are accepted.
  - Canonical tdpnd-smoke flags are --require-tdpnd-grpc-runtime-smoke-ok, --require-tdpnd-grpc-live-smoke-ok,
    and --require-tdpnd-grpc-auth-live-smoke-ok.
  - Aliases --require-tdpnd-runtime-smoke-ok, --require-tdpnd-live-smoke-ok,
    and --require-tdpnd-auth-live-smoke-ok are accepted.
  - Canonical env vars are PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_*_OK.
  - Alias env vars PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_TDPND_RUNTIME_SMOKE_OK and
    PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_TDPND_LIVE_SMOKE_OK and
    PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_TDPND_AUTH_LIVE_SMOKE_OK are accepted.
  - The checker treats unresolved or false required readiness signals as failures.
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

stage_status_from_raw() {
  local raw="${1:-}"
  local normalized
  normalized="$(normalize_boolish_or_empty "$raw")"
  case "$normalized" in
    true)
      printf '%s' "pass"
      ;;
    false)
      printf '%s' "fail"
      ;;
    *)
      if [[ -z "$(trim "$raw")" ]]; then
        printf '%s' "missing"
      else
        printf '%s' "fail"
      fi
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
      elif (.stages[$stage].status? != null) then .stages[$stage].status
      elif (.steps[$stage].status? != null) then .steps[$stage].status
      else empty
      end
    ) | if . == null then empty else . end' \
    "$path" 2>/dev/null || true
}

need_cmd jq
need_cmd date
need_cmd mktemp

ci_phase6_summary_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_CI_PHASE6_SUMMARY_JSON:-${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_CI_SUMMARY_JSON:-${CI_PHASE6_COSMOS_L1_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase6_cosmos_l1_build_testnet_ci_summary.json}}}"
summary_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase6_cosmos_l1_build_testnet_check_summary.json}"
show_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_SHOW_JSON:-0}"

require_chain_scaffold_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_CHAIN_SCAFFOLD_OK:-1}"
require_proto_surface_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_PROTO_SURFACE_OK:-1}"
require_proto_codegen_surface_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_PROTO_CODEGEN_SURFACE_OK:-1}"
require_query_surface_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_QUERY_SURFACE_OK:-1}"
require_grpc_app_roundtrip_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_GRPC_APP_ROUNDTRIP_OK:-1}"
require_tdpnd_grpc_runtime_smoke_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_TDPND_GRPC_RUNTIME_SMOKE_OK:-${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_TDPND_RUNTIME_SMOKE_OK:-1}}"
require_tdpnd_grpc_live_smoke_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_TDPND_GRPC_LIVE_SMOKE_OK:-${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_TDPND_LIVE_SMOKE_OK:-1}}"
require_tdpnd_grpc_auth_live_smoke_ok="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_TDPND_GRPC_AUTH_LIVE_SMOKE_OK:-${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_REQUIRE_TDPND_AUTH_LIVE_SMOKE_OK:-1}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci-phase6-summary-json|--ci-phase6-cosmos-l1-summary-json|--ci-phase6-build-testnet-summary-json)
      ci_phase6_summary_json="${2:-}"
      shift 2
      ;;
    --require-chain-scaffold-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_chain_scaffold_ok="${2:-}"
        shift 2
      else
        require_chain_scaffold_ok="1"
        shift
      fi
      ;;
    --require-proto-surface-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_proto_surface_ok="${2:-}"
        shift 2
      else
        require_proto_surface_ok="1"
        shift
      fi
      ;;
    --require-proto-codegen-surface-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_proto_codegen_surface_ok="${2:-}"
        shift 2
      else
        require_proto_codegen_surface_ok="1"
        shift
      fi
      ;;
    --require-query-surface-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_query_surface_ok="${2:-}"
        shift 2
      else
        require_query_surface_ok="1"
        shift
      fi
      ;;
    --require-grpc-app-roundtrip-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_grpc_app_roundtrip_ok="${2:-}"
        shift 2
      else
        require_grpc_app_roundtrip_ok="1"
        shift
      fi
      ;;
    --require-tdpnd-grpc-runtime-smoke-ok|--require-tdpnd-runtime-smoke-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_tdpnd_grpc_runtime_smoke_ok="${2:-}"
        shift 2
      else
        require_tdpnd_grpc_runtime_smoke_ok="1"
        shift
      fi
      ;;
    --require-tdpnd-grpc-live-smoke-ok|--require-tdpnd-live-smoke-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_tdpnd_grpc_live_smoke_ok="${2:-}"
        shift 2
      else
        require_tdpnd_grpc_live_smoke_ok="1"
        shift
      fi
      ;;
    --require-tdpnd-grpc-auth-live-smoke-ok|--require-tdpnd-auth-live-smoke-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_tdpnd_grpc_auth_live_smoke_ok="${2:-}"
        shift 2
      else
        require_tdpnd_grpc_auth_live_smoke_ok="1"
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

bool_arg_or_die "--require-chain-scaffold-ok" "$require_chain_scaffold_ok"
bool_arg_or_die "--require-proto-surface-ok" "$require_proto_surface_ok"
bool_arg_or_die "--require-proto-codegen-surface-ok" "$require_proto_codegen_surface_ok"
bool_arg_or_die "--require-query-surface-ok" "$require_query_surface_ok"
bool_arg_or_die "--require-grpc-app-roundtrip-ok" "$require_grpc_app_roundtrip_ok"
bool_arg_or_die "--require-tdpnd-grpc-runtime-smoke-ok" "$require_tdpnd_grpc_runtime_smoke_ok"
bool_arg_or_die "--require-tdpnd-grpc-live-smoke-ok" "$require_tdpnd_grpc_live_smoke_ok"
bool_arg_or_die "--require-tdpnd-grpc-auth-live-smoke-ok" "$require_tdpnd_grpc_auth_live_smoke_ok"
bool_arg_or_die "--show-json" "$show_json"

ci_phase6_summary_json="$(abs_path "$ci_phase6_summary_json")"
summary_json="$(abs_path "$summary_json")"
mkdir -p "$(dirname "$summary_json")"

stage_ids=(
  "chain_scaffold"
  "proto_surface"
  "proto_codegen_surface"
  "query_surface"
  "grpc_app_roundtrip"
  "tdpnd_grpc_runtime_smoke"
  "tdpnd_grpc_live_smoke"
  "tdpnd_grpc_auth_live_smoke"
)

declare -A stage_require=(
  ["chain_scaffold"]="$require_chain_scaffold_ok"
  ["proto_surface"]="$require_proto_surface_ok"
  ["proto_codegen_surface"]="$require_proto_codegen_surface_ok"
  ["query_surface"]="$require_query_surface_ok"
  ["grpc_app_roundtrip"]="$require_grpc_app_roundtrip_ok"
  ["tdpnd_grpc_runtime_smoke"]="$require_tdpnd_grpc_runtime_smoke_ok"
  ["tdpnd_grpc_live_smoke"]="$require_tdpnd_grpc_live_smoke_ok"
  ["tdpnd_grpc_auth_live_smoke"]="$require_tdpnd_grpc_auth_live_smoke_ok"
)

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ci_phase6_summary_usable="$(json_file_valid_01 "$ci_phase6_summary_json")"

declare -a reasons=()
if [[ "$ci_phase6_summary_usable" != "1" ]]; then
  reasons+=("ci phase6 summary file not found or invalid JSON: $ci_phase6_summary_json")
fi

declare -A stage_raw
declare -A stage_ok
declare -A stage_status
declare -A stage_resolved

for stage_id in "${stage_ids[@]}"; do
  signal_name="${stage_id}_ok"
  raw=""
  if [[ "$ci_phase6_summary_usable" == "1" ]]; then
    raw="$(resolve_signal_raw_or_empty "$ci_phase6_summary_json" "$signal_name" "$stage_id")"
  fi
  stage_raw["$stage_id"]="$raw"

  normalized="$(normalize_boolish_or_empty "$raw")"
  if [[ -z "$normalized" ]]; then
    normalized="false"
  fi
  stage_ok["$stage_id"]="$normalized"

  status="$(stage_status_from_raw "$raw")"
  stage_status["$stage_id"]="$status"

  resolved="0"
  if [[ -n "$(trim "$raw")" ]]; then
    resolved="1"
  elif [[ "$ci_phase6_summary_usable" == "1" ]]; then
    reasons+=("${signal_name} could not be resolved from ci phase6 summary")
  fi
  stage_resolved["$stage_id"]="$resolved"

  if [[ "${stage_require[$stage_id]}" == "1" && "${stage_ok[$stage_id]}" != "true" ]]; then
    reasons+=("${signal_name} is false")
  fi
done

if ((${#reasons[@]} > 0)); then
  reasons_json="$(printf '%s\n' "${reasons[@]}" | jq -R . | jq -s .)"
  status="fail"
  rc=1
else
  reasons_json='[]'
  status="pass"
  rc=0
fi

policy_json='{}'
stages_json='{}'
signals_json='{}'

for stage_id in "${stage_ids[@]}"; do
  signal_name="${stage_id}_ok"
  policy_key="require_${signal_name}"
  policy_json="$(
    jq -n \
      --argjson base "$policy_json" \
      --arg key "$policy_key" \
      --arg enabled "${stage_require[$stage_id]}" \
      '$base + {($key): ($enabled == "1")}'
  )"

  stage_entry="$(
    jq -n \
      --arg enabled "${stage_require[$stage_id]}" \
      --arg status "${stage_status[$stage_id]}" \
      --arg resolved "${stage_resolved[$stage_id]}" \
      --arg ok "${stage_ok[$stage_id]}" \
      '{
        enabled: ($enabled == "1"),
        status: $status,
        resolved: ($resolved == "1"),
        ok: ($ok == "true")
      }'
  )"
  stages_json="$(
    jq -n \
      --argjson base "$stages_json" \
      --arg key "$stage_id" \
      --argjson val "$stage_entry" \
      '$base + {($key): $val}'
  )"

  signals_json="$(
    jq -n \
      --argjson base "$signals_json" \
      --arg key "$signal_name" \
      --arg ok "${stage_ok[$stage_id]}" \
      '$base + {($key): ($ok == "true")}'
  )"
done

summary_tmp="$(mktemp)"
jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$status" \
  --argjson rc "$rc" \
  --arg ci_phase6_summary_json "$ci_phase6_summary_json" \
  --arg summary_json "$summary_json" \
  --arg show_json "$show_json" \
  --argjson ci_phase6_summary_usable "$ci_phase6_summary_usable" \
  --argjson policy "$policy_json" \
  --argjson stages "$stages_json" \
  --argjson signals "$signals_json" \
  --argjson reasons "$reasons_json" \
  '{
    version: 1,
    schema: {
      id: "phase6_cosmos_l1_build_testnet_check_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    metadata: {
      contract: "phase6-cosmos-l1-build-testnet",
      script: "phase6_cosmos_l1_build_testnet_check.sh"
    },
    inputs: {
      ci_phase6_summary_json: $ci_phase6_summary_json,
      summary_json: $summary_json,
      show_json: ($show_json == "1"),
      usable: {
        ci_phase6_summary_json: ($ci_phase6_summary_usable == 1)
      }
    },
    policy: $policy,
    stages: $stages,
    signals: $signals,
    decision: {
      pass: ($status == "pass"),
      reasons: $reasons
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 1
