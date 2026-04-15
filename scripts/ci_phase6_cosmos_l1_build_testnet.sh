#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/ci_phase6_cosmos_l1_build_testnet.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--run-chain-scaffold [0|1]] \
    [--run-local-testnet-smoke [0|1]] \
    [--run-proto-surface [0|1]] \
    [--run-proto-codegen-surface [0|1]] \
    [--run-query-surface [0|1]] \
    [--run-grpc-app-roundtrip [0|1]] \
    [--run-tdpnd-grpc-runtime-smoke [0|1]] \
    [--run-tdpnd-grpc-live-smoke [0|1]] \
    [--run-tdpnd-grpc-auth-live-smoke [0|1]]

Purpose:
  Run a focused Phase-6 Cosmos L1 build/testnet CI gate:
    1) integration_cosmos_chain_scaffold.sh
    2) integration_cosmos_local_testnet_smoke.sh
    3) integration_cosmos_proto_surface.sh
    4) integration_cosmos_proto_codegen_surface.sh
    5) integration_cosmos_query_surface.sh
    6) integration_cosmos_grpc_app_roundtrip.sh
    7) integration_cosmos_tdpnd_grpc_runtime_smoke.sh
    8) integration_cosmos_tdpnd_grpc_live_smoke.sh
    9) integration_cosmos_tdpnd_grpc_auth_live_smoke.sh

Dry-run mode:
  --dry-run 1 skips stage execution, records deterministic skip accounting,
  and still emits the runner summary JSON.
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

run_step() {
  local label="$1"
  shift
  local rc=0
  echo "[ci-phase6-cosmos-l1] step=${label} status=running"
  set +e
  "$@"
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "[ci-phase6-cosmos-l1] step=${label} status=pass rc=0"
  else
    echo "[ci-phase6-cosmos-l1] step=${label} status=fail rc=${rc}"
  fi
  return "$rc"
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${CI_PHASE6_COSMOS_L1_REPORTS_DIR:-}"
summary_json="${CI_PHASE6_COSMOS_L1_SUMMARY_JSON:-}"
print_summary_json="${CI_PHASE6_COSMOS_L1_PRINT_SUMMARY_JSON:-1}"
dry_run="${CI_PHASE6_COSMOS_L1_DRY_RUN:-0}"

run_chain_scaffold="${CI_PHASE6_COSMOS_L1_RUN_CHAIN_SCAFFOLD:-1}"
run_local_testnet_smoke="${CI_PHASE6_COSMOS_L1_RUN_LOCAL_TESTNET_SMOKE:-1}"
run_proto_surface="${CI_PHASE6_COSMOS_L1_RUN_PROTO_SURFACE:-1}"
run_proto_codegen_surface="${CI_PHASE6_COSMOS_L1_RUN_PROTO_CODEGEN_SURFACE:-1}"
run_query_surface="${CI_PHASE6_COSMOS_L1_RUN_QUERY_SURFACE:-1}"
run_grpc_app_roundtrip="${CI_PHASE6_COSMOS_L1_RUN_GRPC_APP_ROUNDTRIP:-1}"
run_tdpnd_grpc_runtime_smoke="${CI_PHASE6_COSMOS_L1_RUN_TDPND_GRPC_RUNTIME_SMOKE:-1}"
run_tdpnd_grpc_live_smoke="${CI_PHASE6_COSMOS_L1_RUN_TDPND_GRPC_LIVE_SMOKE:-1}"
run_tdpnd_grpc_auth_live_smoke="${CI_PHASE6_COSMOS_L1_RUN_TDPND_GRPC_AUTH_LIVE_SMOKE:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
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
    --run-chain-scaffold)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_chain_scaffold="${2:-}"
        shift 2
      else
        run_chain_scaffold="1"
        shift
      fi
      ;;
    --run-local-testnet-smoke)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_local_testnet_smoke="${2:-}"
        shift 2
      else
        run_local_testnet_smoke="1"
        shift
      fi
      ;;
    --run-proto-surface)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_proto_surface="${2:-}"
        shift 2
      else
        run_proto_surface="1"
        shift
      fi
      ;;
    --run-proto-codegen-surface)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_proto_codegen_surface="${2:-}"
        shift 2
      else
        run_proto_codegen_surface="1"
        shift
      fi
      ;;
    --run-query-surface)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_query_surface="${2:-}"
        shift 2
      else
        run_query_surface="1"
        shift
      fi
      ;;
    --run-grpc-app-roundtrip)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_grpc_app_roundtrip="${2:-}"
        shift 2
      else
        run_grpc_app_roundtrip="1"
        shift
      fi
      ;;
    --run-tdpnd-grpc-runtime-smoke)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_tdpnd_grpc_runtime_smoke="${2:-}"
        shift 2
      else
        run_tdpnd_grpc_runtime_smoke="1"
        shift
      fi
      ;;
    --run-tdpnd-grpc-live-smoke)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_tdpnd_grpc_live_smoke="${2:-}"
        shift 2
      else
        run_tdpnd_grpc_live_smoke="1"
        shift
      fi
      ;;
    --run-tdpnd-grpc-auth-live-smoke)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_tdpnd_grpc_auth_live_smoke="${2:-}"
        shift 2
      else
        run_tdpnd_grpc_auth_live_smoke="1"
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

bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--dry-run" "$dry_run"
bool_arg_or_die "--run-chain-scaffold" "$run_chain_scaffold"
bool_arg_or_die "--run-local-testnet-smoke" "$run_local_testnet_smoke"
bool_arg_or_die "--run-proto-surface" "$run_proto_surface"
bool_arg_or_die "--run-proto-codegen-surface" "$run_proto_codegen_surface"
bool_arg_or_die "--run-query-surface" "$run_query_surface"
bool_arg_or_die "--run-grpc-app-roundtrip" "$run_grpc_app_roundtrip"
bool_arg_or_die "--run-tdpnd-grpc-runtime-smoke" "$run_tdpnd_grpc_runtime_smoke"
bool_arg_or_die "--run-tdpnd-grpc-live-smoke" "$run_tdpnd_grpc_live_smoke"
bool_arg_or_die "--run-tdpnd-grpc-auth-live-smoke" "$run_tdpnd_grpc_auth_live_smoke"

chain_scaffold_script="${CI_PHASE6_COSMOS_L1_CHAIN_SCAFFOLD_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_chain_scaffold.sh}"
local_testnet_smoke_script="${CI_PHASE6_COSMOS_L1_LOCAL_TESTNET_SMOKE_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_local_testnet_smoke.sh}"
proto_surface_script="${CI_PHASE6_COSMOS_L1_PROTO_SURFACE_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_proto_surface.sh}"
proto_codegen_surface_script="${CI_PHASE6_COSMOS_L1_PROTO_CODEGEN_SURFACE_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_proto_codegen_surface.sh}"
query_surface_script="${CI_PHASE6_COSMOS_L1_QUERY_SURFACE_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_query_surface.sh}"
grpc_app_roundtrip_script="${CI_PHASE6_COSMOS_L1_GRPC_APP_ROUNDTRIP_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_grpc_app_roundtrip.sh}"
tdpnd_grpc_runtime_smoke_script="${CI_PHASE6_COSMOS_L1_TDPND_GRPC_RUNTIME_SMOKE_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_tdpnd_grpc_runtime_smoke.sh}"
tdpnd_grpc_live_smoke_script="${CI_PHASE6_COSMOS_L1_TDPND_GRPC_LIVE_SMOKE_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh}"
tdpnd_grpc_auth_live_smoke_script="${CI_PHASE6_COSMOS_L1_TDPND_GRPC_AUTH_LIVE_SMOKE_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh}"

stage_ids=(
  "chain_scaffold"
  "local_testnet_smoke"
  "proto_surface"
  "proto_codegen_surface"
  "query_surface"
  "grpc_app_roundtrip"
  "tdpnd_grpc_runtime_smoke"
  "tdpnd_grpc_live_smoke"
  "tdpnd_grpc_auth_live_smoke"
)

declare -A stage_script=(
  ["chain_scaffold"]="$chain_scaffold_script"
  ["local_testnet_smoke"]="$local_testnet_smoke_script"
  ["proto_surface"]="$proto_surface_script"
  ["proto_codegen_surface"]="$proto_codegen_surface_script"
  ["query_surface"]="$query_surface_script"
  ["grpc_app_roundtrip"]="$grpc_app_roundtrip_script"
  ["tdpnd_grpc_runtime_smoke"]="$tdpnd_grpc_runtime_smoke_script"
  ["tdpnd_grpc_live_smoke"]="$tdpnd_grpc_live_smoke_script"
  ["tdpnd_grpc_auth_live_smoke"]="$tdpnd_grpc_auth_live_smoke_script"
)

declare -A stage_enabled=(
  ["chain_scaffold"]="$run_chain_scaffold"
  ["local_testnet_smoke"]="$run_local_testnet_smoke"
  ["proto_surface"]="$run_proto_surface"
  ["proto_codegen_surface"]="$run_proto_codegen_surface"
  ["query_surface"]="$run_query_surface"
  ["grpc_app_roundtrip"]="$run_grpc_app_roundtrip"
  ["tdpnd_grpc_runtime_smoke"]="$run_tdpnd_grpc_runtime_smoke"
  ["tdpnd_grpc_live_smoke"]="$run_tdpnd_grpc_live_smoke"
  ["tdpnd_grpc_auth_live_smoke"]="$run_tdpnd_grpc_auth_live_smoke"
)

for stage_id in "${stage_ids[@]}"; do
  if [[ "${stage_enabled[$stage_id]}" == "1" && ! -x "${stage_script[$stage_id]}" ]]; then
    echo "missing executable stage script: ${stage_script[$stage_id]}"
    exit 2
  fi
done

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/ci_phase6_cosmos_l1_build_testnet_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/ci_phase6_cosmos_l1_build_testnet_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$summary_json")"

declare -A stage_status
declare -A stage_rc
declare -A stage_command
declare -A stage_reason

final_rc=0

for stage_id in "${stage_ids[@]}"; do
  script="${stage_script[$stage_id]}"
  enabled="${stage_enabled[$stage_id]}"

  stage_status["$stage_id"]="skip"
  stage_rc["$stage_id"]=0
  stage_command["$stage_id"]=""
  stage_reason["$stage_id"]=""

  if [[ "$enabled" == "1" ]]; then
    stage_command["$stage_id"]="$(print_cmd "$script")"
    if [[ "$dry_run" == "1" ]]; then
      stage_reason["$stage_id"]="dry-run"
      echo "[ci-phase6-cosmos-l1] step=${stage_id} status=skip reason=dry-run"
    elif run_step "$stage_id" "$script"; then
      stage_status["$stage_id"]="pass"
      stage_rc["$stage_id"]=0
    else
      step_rc=$?
      stage_status["$stage_id"]="fail"
      stage_rc["$stage_id"]=$step_rc
      if (( final_rc == 0 )); then
        final_rc=$step_rc
      fi
    fi
  else
    echo "[ci-phase6-cosmos-l1] step=${stage_id} status=skip reason=disabled"
    stage_reason["$stage_id"]="disabled"
  fi
done

final_status="pass"
if (( final_rc != 0 )); then
  final_status="fail"
fi

steps_json='{}'
for stage_id in "${stage_ids[@]}"; do
  stage_entry="$(
    jq -n \
      --arg enabled "${stage_enabled[$stage_id]}" \
      --arg status "${stage_status[$stage_id]}" \
      --argjson rc "${stage_rc[$stage_id]}" \
      --arg command "${stage_command[$stage_id]}" \
      --arg reason "${stage_reason[$stage_id]}" \
      '{
        enabled: ($enabled == "1"),
        status: $status,
        rc: $rc,
        command: (if $command == "" then null else $command end),
        reason: (if $reason == "" then null else $reason end),
        artifacts: {}
      }'
  )"
  steps_json="$(
    jq -n \
      --argjson base "$steps_json" \
      --arg key "$stage_id" \
      --argjson val "$stage_entry" \
      '$base + {($key): $val}'
  )"
done

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg dry_run "$dry_run" \
  --arg print_summary_json "$print_summary_json" \
  --arg run_chain_scaffold "$run_chain_scaffold" \
  --arg run_local_testnet_smoke "$run_local_testnet_smoke" \
  --arg run_proto_surface "$run_proto_surface" \
  --arg run_proto_codegen_surface "$run_proto_codegen_surface" \
  --arg run_query_surface "$run_query_surface" \
  --arg run_grpc_app_roundtrip "$run_grpc_app_roundtrip" \
  --arg run_tdpnd_grpc_runtime_smoke "$run_tdpnd_grpc_runtime_smoke" \
  --arg run_tdpnd_grpc_live_smoke "$run_tdpnd_grpc_live_smoke" \
  --arg run_tdpnd_grpc_auth_live_smoke "$run_tdpnd_grpc_auth_live_smoke" \
  --argjson steps "$steps_json" \
  '{
    version: 1,
    schema: {
      id: "ci_phase6_cosmos_l1_build_testnet_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    inputs: {
      dry_run: ($dry_run == "1"),
      print_summary_json: ($print_summary_json == "1"),
      run_chain_scaffold: ($run_chain_scaffold == "1"),
      run_local_testnet_smoke: ($run_local_testnet_smoke == "1"),
      run_proto_surface: ($run_proto_surface == "1"),
      run_proto_codegen_surface: ($run_proto_codegen_surface == "1"),
      run_query_surface: ($run_query_surface == "1"),
      run_grpc_app_roundtrip: ($run_grpc_app_roundtrip == "1"),
      run_tdpnd_grpc_runtime_smoke: ($run_tdpnd_grpc_runtime_smoke == "1"),
      run_tdpnd_grpc_live_smoke: ($run_tdpnd_grpc_live_smoke == "1"),
      run_tdpnd_grpc_auth_live_smoke: ($run_tdpnd_grpc_auth_live_smoke == "1")
    },
    steps: $steps,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[ci-phase6-cosmos-l1] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[ci-phase6-cosmos-l1] reports_dir=$reports_dir"
echo "[ci-phase6-cosmos-l1] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
