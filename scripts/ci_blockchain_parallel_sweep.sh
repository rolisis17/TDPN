#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/ci_blockchain_parallel_sweep.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--run-lane-cosmos-low-level [0|1]] \
    [--run-lane-phase-wrappers [0|1]] \
    [--run-lane-go-tests [0|1]]

Purpose:
  Run blockchain validation lanes in parallel:
    - cosmos_low_level: integration_cosmos_* suites
    - phase_wrappers: phase5/6/7 wrappers + blockchain gates/roadmap consistency
    - go_tests: blockchain/settlement + issuer/exit/localapi Go suites

Dry-run mode:
  --dry-run 1 skips lane execution, records deterministic skip accounting,
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

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${CI_BLOCKCHAIN_PARALLEL_SWEEP_REPORTS_DIR:-}"
summary_json="${CI_BLOCKCHAIN_PARALLEL_SWEEP_SUMMARY_JSON:-}"
canonical_summary_json="${CI_BLOCKCHAIN_PARALLEL_SWEEP_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/ci_blockchain_parallel_sweep_summary.json}"
print_summary_json="${CI_BLOCKCHAIN_PARALLEL_SWEEP_PRINT_SUMMARY_JSON:-1}"
dry_run="${CI_BLOCKCHAIN_PARALLEL_SWEEP_DRY_RUN:-0}"
run_lane_cosmos_low_level="${CI_BLOCKCHAIN_PARALLEL_SWEEP_RUN_LANE_COSMOS_LOW_LEVEL:-1}"
run_lane_phase_wrappers="${CI_BLOCKCHAIN_PARALLEL_SWEEP_RUN_LANE_PHASE_WRAPPERS:-1}"
run_lane_go_tests="${CI_BLOCKCHAIN_PARALLEL_SWEEP_RUN_LANE_GO_TESTS:-1}"

default_lane_cosmos_cmd="\
bash scripts/integration_cosmos_chain_scaffold.sh && \
bash scripts/integration_cosmos_proto_surface.sh && \
bash scripts/integration_cosmos_proto_grpc_surface.sh && \
bash scripts/integration_cosmos_proto_codegen_surface.sh && \
bash scripts/integration_cosmos_query_surface.sh && \
bash scripts/integration_cosmos_module_tx_surface.sh && \
bash scripts/integration_cosmos_grpc_app_roundtrip.sh && \
bash scripts/integration_cosmos_tdpnd_grpc_runtime_smoke.sh && \
bash scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh && \
bash scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh && \
bash scripts/integration_cosmos_tdpnd_settlement_bridge_smoke.sh && \
bash scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh && \
bash scripts/integration_cosmos_tdpnd_state_dir_persistence.sh && \
bash scripts/integration_cosmos_tdpnd_comet_runtime_smoke.sh && \
bash scripts/integration_cosmos_local_testnet_smoke.sh && \
bash scripts/integration_cosmos_bridge_local_stack_contract.sh && \
bash scripts/integration_cosmos_dual_write_parity.sh && \
bash scripts/integration_cosmos_module_coverage_floor.sh && \
bash scripts/integration_cosmos_keeper_coverage_floor.sh && \
bash scripts/integration_cosmos_app_coverage_floor.sh && \
bash scripts/integration_cosmos_settlement_acceptance_paths.sh && \
bash scripts/integration_cosmos_settlement_failsoft.sh && \
bash scripts/integration_cosmos_settlement_shadow_env.sh && \
bash scripts/integration_cosmos_settlement_shadow_status_surface.sh && \
bash scripts/integration_cosmos_settlement_dual_asset_parity.sh && \
bash scripts/integration_cosmos_vpnbilling_tx.sh && \
bash scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh && \
bash scripts/integration_cosmos_adapter_tdpnd_signed_tx_roundtrip.sh"

default_lane_phase_cmd="\
bash scripts/check_roadmap_consistency.sh && \
bash scripts/integration_ci_blockchain_parallel_sweep.sh && \
bash scripts/integration_roadmap_consistency.sh && \
bash scripts/integration_roadmap_progress_report.sh && \
bash scripts/integration_roadmap_progress_phase5_handoff.sh && \
bash scripts/integration_roadmap_blockchain_actionable_run.sh && \
bash scripts/integration_easy_node_roadmap_blockchain_actionable_run.sh && \
bash scripts/integration_blockchain_bootstrap_graduation_gate.sh && \
bash scripts/integration_blockchain_cosmos_only_guardrail.sh && \
bash scripts/integration_easy_node_blockchain_cosmos_only_guardrail.sh && \
bash scripts/integration_blockchain_mainnet_activation_metrics_input_template.sh && \
bash scripts/integration_blockchain_mainnet_activation_metrics_missing_input_template.sh && \
bash scripts/integration_blockchain_mainnet_activation_metrics_prefill.sh && \
bash scripts/integration_blockchain_mainnet_activation_metrics_missing_checklist.sh && \
bash scripts/integration_blockchain_mainnet_activation_operator_pack.sh && \
bash scripts/integration_blockchain_mainnet_activation_metrics_input.sh && \
bash scripts/integration_blockchain_mainnet_activation_metrics.sh && \
bash scripts/integration_blockchain_mainnet_activation_gate.sh && \
bash scripts/integration_blockchain_gate_bundle.sh && \
bash scripts/integration_blockchain_mainnet_activation_gate_cycle.sh && \
bash scripts/integration_blockchain_mainnet_activation_real_evidence_run.sh && \
bash scripts/integration_blockchain_staged_file_groups.sh && \
bash scripts/integration_easy_node_blockchain_staged_file_groups.sh && \
bash scripts/integration_blockchain_fastlane.sh && \
bash scripts/integration_easy_node_blockchain_fastlane_cohort_quick_check_shim.sh && \
bash scripts/integration_easy_node_blockchain_gate_wrappers.sh && \
bash scripts/integration_easy_node_blockchain_summary_reports.sh && \
bash scripts/integration_ci_phase5_settlement_layer.sh && \
bash scripts/integration_phase5_settlement_layer_check.sh && \
bash scripts/integration_phase5_settlement_layer_run.sh && \
bash scripts/integration_phase5_settlement_layer_handoff_check.sh && \
bash scripts/integration_phase5_settlement_layer_handoff_run.sh && \
bash scripts/integration_phase5_settlement_layer_summary_report.sh && \
bash scripts/integration_ci_phase6_cosmos_l1_build_testnet.sh && \
bash scripts/integration_ci_phase6_cosmos_l1_contracts.sh && \
bash scripts/integration_slash_violation_type_contract_consistency.sh && \
bash scripts/integration_cosmos_record_normalization_contract_consistency.sh && \
bash scripts/integration_phase6_cosmos_l1_build_testnet_check.sh && \
bash scripts/integration_phase6_cosmos_l1_build_testnet_run.sh && \
bash scripts/integration_phase6_cosmos_l1_build_testnet_handoff_check.sh && \
bash scripts/integration_phase6_cosmos_l1_build_testnet_handoff_run.sh && \
bash scripts/integration_phase6_cosmos_l1_build_testnet_suite.sh && \
bash scripts/integration_phase6_cosmos_l1_contracts_live_smoke.sh && \
bash scripts/integration_phase6_cosmos_l1_summary_report.sh && \
bash scripts/integration_ci_phase7_mainnet_cutover.sh && \
bash scripts/integration_phase7_mainnet_cutover_check.sh && \
bash scripts/integration_phase7_mainnet_cutover_run.sh && \
bash scripts/integration_phase7_mainnet_cutover_handoff_check.sh && \
bash scripts/integration_phase7_mainnet_cutover_handoff_run.sh && \
bash scripts/integration_phase7_mainnet_cutover_summary_report.sh && \
bash scripts/integration_phase7_mainnet_cutover_live_smoke.sh"

default_lane_go_cmd="\
(cd blockchain/tdpn-chain && go test ./...) && \
go test ./pkg/settlement/... && \
go test ./services/issuer ./services/exit ./services/localapi"

lane_cosmos_override="${CI_BLOCKCHAIN_PARALLEL_SWEEP_LANE_COSMOS_CMD:-}"
lane_phase_override="${CI_BLOCKCHAIN_PARALLEL_SWEEP_LANE_PHASE_CMD:-}"
lane_go_override="${CI_BLOCKCHAIN_PARALLEL_SWEEP_LANE_GO_CMD:-}"
allow_unsafe_cmd_override="${CI_BLOCKCHAIN_PARALLEL_SWEEP_ALLOW_UNSAFE_CMD_OVERRIDE:-0}"

if [[ "$allow_unsafe_cmd_override" != "1" ]]; then
  if [[ -n "$lane_cosmos_override" || -n "$lane_phase_override" || -n "$lane_go_override" ]]; then
    echo "unsafe lane command override rejected; set CI_BLOCKCHAIN_PARALLEL_SWEEP_ALLOW_UNSAFE_CMD_OVERRIDE=1 to opt in"
    exit 2
  fi
fi

lane_cosmos_low_level_cmd="${lane_cosmos_override:-$default_lane_cosmos_cmd}"
lane_phase_wrappers_cmd="${lane_phase_override:-$default_lane_phase_cmd}"
lane_go_tests_cmd="${lane_go_override:-$default_lane_go_cmd}"

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
    --run-lane-cosmos-low-level)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_lane_cosmos_low_level="${2:-}"
        shift 2
      else
        run_lane_cosmos_low_level="1"
        shift
      fi
      ;;
    --run-lane-phase-wrappers)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_lane_phase_wrappers="${2:-}"
        shift 2
      else
        run_lane_phase_wrappers="1"
        shift
      fi
      ;;
    --run-lane-go-tests)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_lane_go_tests="${2:-}"
        shift 2
      else
        run_lane_go_tests="1"
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
bool_arg_or_die "--run-lane-cosmos-low-level" "$run_lane_cosmos_low_level"
bool_arg_or_die "--run-lane-phase-wrappers" "$run_lane_phase_wrappers"
bool_arg_or_die "--run-lane-go-tests" "$run_lane_go_tests"

if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/ci_blockchain_parallel_sweep_$(date -u +%Y%m%d_%H%M%S)"
fi
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/ci_blockchain_parallel_sweep_summary.json"
fi
summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"

mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"

lane_ids=(
  "cosmos_low_level"
  "phase_wrappers"
  "go_tests"
)

declare -A lane_enabled=(
  ["cosmos_low_level"]="$run_lane_cosmos_low_level"
  ["phase_wrappers"]="$run_lane_phase_wrappers"
  ["go_tests"]="$run_lane_go_tests"
)

declare -A lane_cmd=(
  ["cosmos_low_level"]="$lane_cosmos_low_level_cmd"
  ["phase_wrappers"]="$lane_phase_wrappers_cmd"
  ["go_tests"]="$lane_go_tests_cmd"
)

declare -A lane_log_path=()
declare -A lane_rc_file=()
declare -A lane_status=()
declare -A lane_rc=()
declare -A lane_started_at=()
declare -A lane_completed_at=()
declare -A lane_duration_sec=()
declare -A lane_pid=()

for lane_id in "${lane_ids[@]}"; do
  lane_log_path["$lane_id"]="$reports_dir/${lane_id}.log"
  lane_rc_file["$lane_id"]="$reports_dir/${lane_id}.rc"
  lane_status["$lane_id"]="skipped"
  lane_rc["$lane_id"]="0"
  lane_started_at["$lane_id"]=""
  lane_completed_at["$lane_id"]=""
  lane_duration_sec["$lane_id"]="0"
  : >"${lane_log_path[$lane_id]}"
  rm -f "${lane_rc_file[$lane_id]}"
  if [[ "${lane_enabled[$lane_id]}" == "1" ]]; then
    if [[ -z "$(trim "${lane_cmd[$lane_id]}")" ]]; then
      echo "lane ${lane_id} command is empty"
      exit 2
    fi
    lane_status["$lane_id"]="pending"
  fi
done

run_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_started_epoch="$(date -u +%s)"

if [[ "$dry_run" == "0" ]]; then
  for lane_id in "${lane_ids[@]}"; do
    if [[ "${lane_enabled[$lane_id]}" != "1" ]]; then
      continue
    fi
    lane_status["$lane_id"]="running"
    lane_started_at["$lane_id"]="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    lane_start_epoch="$(date -u +%s)"
    lane_duration_sec["$lane_id"]="0"
    lane_cmd_value="${lane_cmd[$lane_id]}"
    lane_log="${lane_log_path[$lane_id]}"
    lane_rc_out="${lane_rc_file[$lane_id]}"
    echo "[ci-blockchain-parallel-sweep] lane=${lane_id} status=running"
    (
      cd "$ROOT_DIR"
      set +e
      bash -lc "$lane_cmd_value" >"$lane_log" 2>&1
      lane_exec_rc=$?
      set -e
      printf '%s' "$lane_exec_rc" >"$lane_rc_out"
      exit 0
    ) &
    lane_pid["$lane_id"]=$!
    # Keep start epoch in-memory for duration accounting.
    lane_duration_sec["$lane_id"]="-$lane_start_epoch"
  done

  for lane_id in "${lane_ids[@]}"; do
    if [[ "${lane_enabled[$lane_id]}" != "1" ]]; then
      continue
    fi
    wait "${lane_pid[$lane_id]}"
    lane_finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    lane_completed_at["$lane_id"]="$lane_finished_at"
    lane_end_epoch="$(date -u +%s)"
    lane_start_epoch="${lane_duration_sec[$lane_id]#-}"
    lane_elapsed="$((lane_end_epoch - lane_start_epoch))"
    if (( lane_elapsed < 0 )); then
      lane_elapsed=0
    fi
    lane_duration_sec["$lane_id"]="$lane_elapsed"

    lane_exec_rc="1"
    if [[ -f "${lane_rc_file[$lane_id]}" ]]; then
      lane_exec_rc="$(cat "${lane_rc_file[$lane_id]}")"
    fi
    lane_rc["$lane_id"]="$lane_exec_rc"
    if [[ "$lane_exec_rc" == "0" ]]; then
      lane_status["$lane_id"]="pass"
      echo "[ci-blockchain-parallel-sweep] lane=${lane_id} status=pass rc=0"
    else
      lane_status["$lane_id"]="fail"
      echo "[ci-blockchain-parallel-sweep] lane=${lane_id} status=fail rc=${lane_exec_rc}"
    fi
  done
else
  for lane_id in "${lane_ids[@]}"; do
    if [[ "${lane_enabled[$lane_id]}" == "1" ]]; then
      lane_status["$lane_id"]="skipped"
      lane_rc["$lane_id"]="0"
      echo "[ci-blockchain-parallel-sweep] lane=${lane_id} status=skipped reason=dry-run"
    fi
  done
fi

run_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_completed_epoch="$(date -u +%s)"
run_duration_sec="$((run_completed_epoch - run_started_epoch))"
if (( run_duration_sec < 0 )); then
  run_duration_sec=0
fi

enabled_count=0
pass_count=0
fail_count=0
skipped_count=0
first_failure_lane=""
first_failure_rc=0

for lane_id in "${lane_ids[@]}"; do
  if [[ "${lane_enabled[$lane_id]}" == "1" ]]; then
    enabled_count=$((enabled_count + 1))
  fi
  case "${lane_status[$lane_id]}" in
    pass) pass_count=$((pass_count + 1)) ;;
    fail) fail_count=$((fail_count + 1)) ;;
    *) skipped_count=$((skipped_count + 1)) ;;
  esac
  if [[ -z "$first_failure_lane" && "${lane_status[$lane_id]}" == "fail" ]]; then
    first_failure_lane="$lane_id"
    first_failure_rc="${lane_rc[$lane_id]}"
  fi
done

overall_status="pass"
overall_rc=0
if (( fail_count > 0 )); then
  overall_status="fail"
  overall_rc="$first_failure_rc"
fi

lane_object_json='{}'
for lane_id in "${lane_ids[@]}"; do
  lane_object_json="$(
    jq -cn \
      --argjson obj "$lane_object_json" \
      --arg lane_id "$lane_id" \
      --arg command "${lane_cmd[$lane_id]}" \
      --argjson enabled "$( [[ "${lane_enabled[$lane_id]}" == "1" ]] && echo true || echo false )" \
      --arg status "${lane_status[$lane_id]}" \
      --argjson rc "${lane_rc[$lane_id]}" \
      --arg started_at "${lane_started_at[$lane_id]}" \
      --arg completed_at "${lane_completed_at[$lane_id]}" \
      --argjson duration_sec "${lane_duration_sec[$lane_id]}" \
      --arg log_path "${lane_log_path[$lane_id]}" \
      '
      $obj + {
        ($lane_id): {
          enabled: $enabled,
          status: $status,
          rc: $rc,
          started_at: (if $started_at == "" then null else $started_at end),
          completed_at: (if $completed_at == "" then null else $completed_at end),
          duration_sec: $duration_sec,
          log_path: $log_path,
          command: $command
        }
      }'
  )"
done

jq -n \
  --arg generated_at "$run_completed_at" \
  --arg started_at "$run_started_at" \
  --arg completed_at "$run_completed_at" \
  --arg status "$overall_status" \
  --argjson rc "$overall_rc" \
  --argjson dry_run "$( [[ "$dry_run" == "1" ]] && echo true || echo false )" \
  --arg root_dir "$ROOT_DIR" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --argjson duration_sec "$run_duration_sec" \
  --argjson enabled "$enabled_count" \
  --argjson pass "$pass_count" \
  --argjson fail "$fail_count" \
  --argjson skipped "$skipped_count" \
  --arg first_failure_lane "$first_failure_lane" \
  --argjson first_failure_rc "$first_failure_rc" \
  --argjson lanes "$lane_object_json" \
  '
  {
    schema: {
      id: "ci_blockchain_parallel_sweep_summary",
      version: "1.0.0"
    },
    generated_at: $generated_at,
    started_at: $started_at,
    completed_at: $completed_at,
    duration_sec: $duration_sec,
    status: $status,
    rc: $rc,
    dry_run: $dry_run,
    root_dir: $root_dir,
    reports_dir: $reports_dir,
    summary_json: $summary_json,
    canonical_summary_json: $canonical_summary_json,
    totals: {
      enabled: $enabled,
      pass: $pass,
      fail: $fail,
      skipped: $skipped
    },
    first_failure: {
      lane_id: (if $first_failure_lane == "" then null else $first_failure_lane end),
      rc: (if $first_failure_lane == "" then null else $first_failure_rc end)
    },
    lanes: $lanes
  }' >"$summary_json"

cp "$summary_json" "$canonical_summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$overall_rc"
