#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

full_plan="docs/full-execution-plan-2026-2027.md"
product_roadmap="docs/product-roadmap.md"
roadmap_script="scripts/roadmap_progress_report.sh"
bootstrap_validator_doc="docs/blockchain-bootstrap-validator-plan.md"
cosmos_runtime_doc="docs/cosmos-settlement-runtime.md"
chain_readme="blockchain/tdpn-chain/README.md"
settlement_mapping_doc="blockchain/tdpn-chain/docs/settlement-bridge-mapping.md"
blockchain_sponsor_quickstart_doc="docs/blockchain-app-sponsorship-quickstart.md"
protocol_doc="docs/protocol.md"
phase5_ci_script="scripts/ci_phase5_settlement_layer.sh"
phase5_integration_script="scripts/integration_ci_phase5_settlement_layer.sh"
phase5_check_script="scripts/phase5_settlement_layer_check.sh"
phase5_run_script="scripts/phase5_settlement_layer_run.sh"
phase5_handoff_check_script="scripts/phase5_settlement_layer_handoff_check.sh"
phase5_handoff_run_script="scripts/phase5_settlement_layer_handoff_run.sh"
phase5_check_integration_script="scripts/integration_phase5_settlement_layer_check.sh"
phase5_run_integration_script="scripts/integration_phase5_settlement_layer_run.sh"
phase5_handoff_check_integration_script="scripts/integration_phase5_settlement_layer_handoff_check.sh"
phase5_handoff_run_integration_script="scripts/integration_phase5_settlement_layer_handoff_run.sh"
phase5_summary_report_script="scripts/phase5_settlement_layer_summary_report.sh"
phase5_summary_report_integration_script="scripts/integration_phase5_settlement_layer_summary_report.sh"
phase6_ci_script="scripts/ci_phase6_cosmos_l1_build_testnet.sh"
phase6_integration_script="scripts/integration_ci_phase6_cosmos_l1_build_testnet.sh"
phase6_contracts_ci_script="scripts/ci_phase6_cosmos_l1_contracts.sh"
phase6_contracts_integration_script="scripts/integration_ci_phase6_cosmos_l1_contracts.sh"
phase6_contracts_live_smoke_script="scripts/integration_phase6_cosmos_l1_contracts_live_smoke.sh"
phase6_module_coverage_floor_script="scripts/integration_cosmos_module_coverage_floor.sh"
phase6_keeper_coverage_floor_script="scripts/integration_cosmos_keeper_coverage_floor.sh"
phase6_check_script="scripts/phase6_cosmos_l1_build_testnet_check.sh"
phase6_run_script="scripts/phase6_cosmos_l1_build_testnet_run.sh"
phase6_check_integration_script="scripts/integration_phase6_cosmos_l1_build_testnet_check.sh"
phase6_run_integration_script="scripts/integration_phase6_cosmos_l1_build_testnet_run.sh"
phase6_suite_script="scripts/phase6_cosmos_l1_build_testnet_suite.sh"
phase6_suite_integration_script="scripts/integration_phase6_cosmos_l1_build_testnet_suite.sh"
phase6_handoff_check_script="scripts/phase6_cosmos_l1_build_testnet_handoff_check.sh"
phase6_handoff_run_script="scripts/phase6_cosmos_l1_build_testnet_handoff_run.sh"
phase6_handoff_check_integration_script="scripts/integration_phase6_cosmos_l1_build_testnet_handoff_check.sh"
phase6_handoff_run_integration_script="scripts/integration_phase6_cosmos_l1_build_testnet_handoff_run.sh"
phase6_summary_report_script="scripts/phase6_cosmos_l1_summary_report.sh"
phase6_summary_report_integration_script="scripts/integration_phase6_cosmos_l1_summary_report.sh"

check_confirmation_lifecycle_wording() {
  local file_path="$1"
  local label="$2"

  if rg -iq "submitted.*(->|to).*confirmed|confirmed.*(from|<-).*submitted" "$file_path"; then
    return 0
  fi

  # Fallback semantic guard for wording variations split across lines/sentences.
  if rg -iq "submitted" "$file_path" \
    && rg -iq "confirmed" "$file_path" \
    && rg -iq "confirmation lifecycle|reconcil|promot" "$file_path"
  then
    return 0
  fi

  echo "$label must document submitted->confirmed confirmation lifecycle progression"
  exit 1
}

check_adapter_roundtrip_wording() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq "settlement_adapter_roundtrip" "$file_path"; then
    echo "$label must document settlement_adapter_roundtrip phase5 stage"
    exit 1
  fi
  if ! rg -Fq "integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh" "$file_path"; then
    echo "$label must document adapter roundtrip integration script"
    exit 1
  fi
}

check_confirmation_interface_wording() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq "ChainConfirmationQuerier" "$file_path"; then
    echo "$label must reference ChainConfirmationQuerier confirmation interface"
    exit 1
  fi
  if ! rg -Fq "pkg/settlement/types.go" "$file_path"; then
    echo "$label must reference canonical confirmation interface location (pkg/settlement/types.go)"
    exit 1
  fi
}

for f in "$full_plan" "$product_roadmap" "$roadmap_script" "$bootstrap_validator_doc" "$cosmos_runtime_doc" "$chain_readme" "$settlement_mapping_doc" "$blockchain_sponsor_quickstart_doc" "$phase5_ci_script" "$phase5_integration_script" "$phase5_check_script" "$phase5_run_script" "$phase5_handoff_check_script" "$phase5_handoff_run_script" "$phase5_check_integration_script" "$phase5_run_integration_script" "$phase5_handoff_check_integration_script" "$phase5_handoff_run_integration_script" "$phase5_summary_report_script" "$phase5_summary_report_integration_script" "$phase6_ci_script" "$phase6_integration_script" "$phase6_contracts_ci_script" "$phase6_contracts_integration_script" "$phase6_contracts_live_smoke_script" "$phase6_module_coverage_floor_script" "$phase6_keeper_coverage_floor_script" "$phase6_check_script" "$phase6_run_script" "$phase6_check_integration_script" "$phase6_run_integration_script" "$phase6_suite_script" "$phase6_suite_integration_script" "$phase6_handoff_check_script" "$phase6_handoff_run_script" "$phase6_handoff_check_integration_script" "$phase6_handoff_run_integration_script" "$phase6_summary_report_script" "$phase6_summary_report_integration_script"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required file: $f"
    exit 1
  fi
done
if [[ ! -f "$protocol_doc" ]]; then
  echo "missing required file: $protocol_doc"
  exit 1
fi

if ! rg -q "authoritative source for sequencing" "$full_plan"; then
  echo "full execution plan must declare canonical/authoritative sequencing"
  exit 1
fi
if ! rg -Fq -- "--state-dir" "$full_plan"; then
  echo "full execution plan must document state-dir runtime integration milestone"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_state_dir_persistence.sh" "$full_plan"; then
  echo "full execution plan must document state-dir persistence integration coverage"
  exit 1
fi
if ! rg -Fq "Settlement bridge now includes read/query" "$full_plan"; then
  echo "full execution plan must document settlement bridge read/query expansion"
  exit 1
fi
if ! rg -Fq "settlement_adapter_roundtrip" "$full_plan"; then
  echo "full execution plan must document settlement_adapter_roundtrip gate posture"
  exit 1
fi
if ! rg -Fq "settlement_shadow_env" "$full_plan"; then
  echo "full execution plan must document settlement_shadow_env gate posture"
  exit 1
fi
if ! rg -Fq "integration_cosmos_settlement_shadow_env.sh" "$full_plan"; then
  echo "full execution plan must document settlement_shadow_env integration script"
  exit 1
fi
if ! rg -Fq "settlement_shadow_status_surface" "$full_plan"; then
  echo "full execution plan must document settlement_shadow_status_surface gate posture"
  exit 1
fi
if ! rg -Fq "integration_cosmos_settlement_shadow_status_surface.sh" "$full_plan"; then
  echo "full execution plan must document settlement_shadow_status_surface integration script"
  exit 1
fi
if ! rg -Fq "settlement_adapter_signed_tx_roundtrip" "$full_plan"; then
  echo "full execution plan must document settlement_adapter_signed_tx_roundtrip gate posture"
  exit 1
fi
if ! rg -Fq "integration_cosmos_adapter_tdpnd_signed_tx_roundtrip.sh" "$full_plan"; then
  echo "full execution plan must document signed-tx adapter roundtrip integration script"
  exit 1
fi
if ! rg -Fq "ci_phase6_cosmos_l1_build_testnet.sh" "$full_plan"; then
  echo "full execution plan must document phase6 cosmos l1 ci scaffold script"
  exit 1
fi
if ! rg -Fq "integration_ci_phase6_cosmos_l1_build_testnet.sh" "$full_plan"; then
  echo "full execution plan must document phase6 cosmos l1 ci integration contract script"
  exit 1
fi
if ! rg -Fq "local_testnet_smoke" "$full_plan"; then
  echo "full execution plan must document phase6 local_testnet_smoke stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_local_testnet_smoke.sh" "$full_plan"; then
  echo "full execution plan must document phase6 local testnet smoke integration script"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$full_plan"; then
  echo "full execution plan must document phase6 tdpnd_grpc_auth_live_smoke stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_grpc_auth_live_smoke.sh" "$full_plan"; then
  echo "full execution plan must document phase6 tdpnd gRPC auth live-smoke script"
  exit 1
fi
if ! rg -Fq "ci_phase6_cosmos_l1_contracts.sh" "$full_plan"; then
  echo "full execution plan must document phase6 cosmos l1 contracts ci gate script"
  exit 1
fi
if ! rg -Fq "integration_ci_phase6_cosmos_l1_contracts.sh" "$full_plan"; then
  echo "full execution plan must document phase6 cosmos l1 contracts ci integration contract script"
  exit 1
fi
if ! rg -Fq "integration_phase6_cosmos_l1_contracts_live_smoke.sh" "$full_plan"; then
  echo "full execution plan must document phase6 contracts live-smoke integration script"
  exit 1
fi
if ! rg -Fq "cosmos_module_coverage_floor" "$full_plan"; then
  echo "full execution plan must document phase6 contracts cosmos_module_coverage_floor stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_module_coverage_floor.sh" "$full_plan"; then
  echo "full execution plan must document phase6 contracts module coverage floor integration script"
  exit 1
fi
if ! rg -Fq "cosmos_keeper_coverage_floor" "$full_plan"; then
  echo "full execution plan must document phase6 contracts cosmos_keeper_coverage_floor stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_keeper_coverage_floor.sh" "$full_plan"; then
  echo "full execution plan must document phase6 contracts keeper coverage floor integration script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_check.sh" "$full_plan"; then
  echo "full execution plan must document phase6 check wrapper script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_run.sh" "$full_plan"; then
  echo "full execution plan must document phase6 run wrapper script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_suite.sh" "$full_plan"; then
  echo "full execution plan must document phase6 top-level suite wrapper script"
  exit 1
fi
if ! rg -Fq "integration_phase6_cosmos_l1_build_testnet_suite.sh" "$full_plan"; then
  echo "full execution plan must document phase6 top-level suite integration contract script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_handoff_check.sh" "$full_plan"; then
  echo "full execution plan must document phase6 handoff-check wrapper script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_handoff_run.sh" "$full_plan"; then
  echo "full execution plan must document phase6 handoff-run wrapper script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_summary_report.sh" "$full_plan"; then
  echo "full execution plan must document phase6 summary report helper script"
  exit 1
fi
if ! rg -Fq "integration_phase6_cosmos_l1_summary_report.sh" "$full_plan"; then
  echo "full execution plan must document phase6 summary report integration contract script"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_summary_report.sh" "$full_plan"; then
  echo "full execution plan must document phase5 summary report helper script"
  exit 1
fi
if ! rg -Fq "integration_phase5_settlement_layer_summary_report.sh" "$full_plan"; then
  echo "full execution plan must document phase5 summary report integration contract script"
  exit 1
fi
if ! rg -iq "phase[[:space:]]*5 summary helper fallback discovery" "$full_plan" \
  || ! rg -iq "timestamped[[:space:]]+ci" "$full_plan" \
  || ! rg -iq "handoff-run" "$full_plan"; then
  echo "full execution plan must document phase5 summary helper fallback discovery for timestamped CI/handoff-run summaries"
  exit 1
fi
if ! rg -Fq "phase5-settlement-layer-summary-report" "$full_plan"; then
  echo "full execution plan must document easy-node phase5 summary wrapper command"
  exit 1
fi
if ! rg -Fq "phase6-cosmos-l1-summary-report" "$full_plan"; then
  echo "full execution plan must document easy-node phase6 summary wrapper command"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke_ok" "$full_plan"; then
  echo "full execution plan must document phase6 readiness/handoff tdpnd_grpc_auth_live_smoke_ok signal"
  exit 1
fi
if ! rg -Fq "run/handoff-run dry-run relaxation" "$full_plan" \
  || ! rg -Fq "tdpnd_grpc_auth_live_smoke_ok" "$full_plan"; then
  echo "full execution plan must document phase6 run/handoff-run dry-run auth-live relaxation posture"
  exit 1
fi
if ! rg -qi "confirmation lifecycle" "$full_plan"; then
  echo "full execution plan must document settlement confirmation lifecycle posture"
  exit 1
fi
for settlement_state in pending submitted confirmed failed; do
  if ! rg -qw "$settlement_state" "$full_plan"; then
    echo "full execution plan confirmation lifecycle must include state: $settlement_state"
    exit 1
  fi
done
if ! rg -Fq "ci_phase6_cosmos_l1_build_testnet.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 cosmos l1 ci scaffold script"
  exit 1
fi
if ! rg -Fq "integration_ci_phase6_cosmos_l1_build_testnet.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 cosmos l1 ci integration contract script"
  exit 1
fi
if ! rg -Fq "local_testnet_smoke" "$product_roadmap"; then
  echo "product roadmap must document phase6 local_testnet_smoke stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_local_testnet_smoke.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 local testnet smoke integration script"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$product_roadmap"; then
  echo "product roadmap must document phase6 tdpnd_grpc_auth_live_smoke stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_grpc_auth_live_smoke.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 tdpnd gRPC auth live-smoke script"
  exit 1
fi
if ! rg -Fq "ci_phase6_cosmos_l1_contracts.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 cosmos l1 contracts ci gate script"
  exit 1
fi
if ! rg -Fq "integration_ci_phase6_cosmos_l1_contracts.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 cosmos l1 contracts ci integration contract script"
  exit 1
fi
if ! rg -Fq "integration_phase6_cosmos_l1_contracts_live_smoke.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 contracts live-smoke integration script"
  exit 1
fi
if ! rg -Fq "cosmos_module_coverage_floor" "$product_roadmap"; then
  echo "product roadmap must document phase6 contracts cosmos_module_coverage_floor stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_module_coverage_floor.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 contracts module coverage floor integration script"
  exit 1
fi
if ! rg -Fq "cosmos_keeper_coverage_floor" "$product_roadmap"; then
  echo "product roadmap must document phase6 contracts cosmos_keeper_coverage_floor stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_keeper_coverage_floor.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 contracts keeper coverage floor integration script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_check.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 check wrapper script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_run.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 run wrapper script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_suite.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 top-level suite wrapper script"
  exit 1
fi
if ! rg -Fq "integration_phase6_cosmos_l1_build_testnet_suite.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 top-level suite integration contract script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_handoff_check.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 handoff-check wrapper script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_handoff_run.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 handoff-run wrapper script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_summary_report.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 summary report helper script"
  exit 1
fi
if ! rg -Fq "integration_phase6_cosmos_l1_summary_report.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 summary report integration contract script"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_summary_report.sh" "$product_roadmap"; then
  echo "product roadmap must document phase5 summary report helper script"
  exit 1
fi
if ! rg -Fq "integration_phase5_settlement_layer_summary_report.sh" "$product_roadmap"; then
  echo "product roadmap must document phase5 summary report integration contract script"
  exit 1
fi
if ! rg -iq "phase[[:space:]]*5 summary helper fallback discovery" "$product_roadmap" \
  || ! rg -iq "timestamped[[:space:]]+ci" "$product_roadmap" \
  || ! rg -iq "handoff-run" "$product_roadmap"; then
  echo "product roadmap must document phase5 summary helper fallback discovery for timestamped CI/handoff-run summaries"
  exit 1
fi
if ! rg -Fq "phase5-settlement-layer-summary-report" "$product_roadmap"; then
  echo "product roadmap must document easy-node phase5 summary wrapper command"
  exit 1
fi
if ! rg -Fq "phase6-cosmos-l1-summary-report" "$product_roadmap"; then
  echo "product roadmap must document easy-node phase6 summary wrapper command"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke_ok" "$product_roadmap"; then
  echo "product roadmap must document phase6 readiness/handoff tdpnd_grpc_auth_live_smoke_ok signal"
  exit 1
fi
if ! rg -Fq "run/handoff-run dry-run relaxation" "$product_roadmap" \
  || ! rg -Fq "tdpnd_grpc_auth_live_smoke_ok" "$product_roadmap"; then
  echo "product roadmap must document phase6 run/handoff-run dry-run auth-live relaxation posture"
  exit 1
fi

phase6_stage_specs=(
  "chain_scaffold|integration_cosmos_chain_scaffold.sh"
  "local_testnet_smoke|integration_cosmos_local_testnet_smoke.sh"
  "proto_surface|integration_cosmos_proto_surface.sh"
  "proto_codegen_surface|integration_cosmos_proto_codegen_surface.sh"
  "query_surface|integration_cosmos_query_surface.sh"
  "grpc_app_roundtrip|integration_cosmos_grpc_app_roundtrip.sh"
  "tdpnd_grpc_runtime_smoke|integration_cosmos_tdpnd_grpc_runtime_smoke.sh"
  "tdpnd_grpc_auth_live_smoke|integration_cosmos_tdpnd_grpc_auth_live_smoke.sh"
  "tdpnd_grpc_live_smoke|integration_cosmos_tdpnd_grpc_live_smoke.sh"
)
for stage_spec in "${phase6_stage_specs[@]}"; do
  stage_id="${stage_spec%%|*}"
  stage_script="${stage_spec#*|}"
  if ! rg -Fq "$stage_id" "$phase6_ci_script"; then
    echo "phase6 ci script must include ${stage_id} stage"
    exit 1
  fi
  if ! rg -Fq "$stage_script" "$phase6_ci_script"; then
    echo "phase6 ci script must wire ${stage_script}"
    exit 1
  fi
  if ! rg -Fq "$stage_id" "$phase6_integration_script"; then
    echo "phase6 ci integration script must validate ${stage_id} stage"
    exit 1
  fi
done
phase6_contract_gate_specs=(
  "phase6_cosmos_l1_build_testnet_check|integration_phase6_cosmos_l1_build_testnet_check.sh"
  "phase6_cosmos_l1_build_testnet_run|integration_phase6_cosmos_l1_build_testnet_run.sh"
  "phase6_cosmos_l1_build_testnet_suite|integration_phase6_cosmos_l1_build_testnet_suite.sh"
  "phase6_cosmos_l1_build_testnet_handoff_check|integration_phase6_cosmos_l1_build_testnet_handoff_check.sh"
  "phase6_cosmos_l1_build_testnet_handoff_run|integration_phase6_cosmos_l1_build_testnet_handoff_run.sh"
)
for gate_spec in "${phase6_contract_gate_specs[@]}"; do
  gate_stage="${gate_spec%%|*}"
  gate_script="${gate_spec#*|}"
  if ! rg -Fq "$gate_script" "$phase6_contracts_ci_script"; then
    echo "phase6 contracts ci script must wire ${gate_script}"
    exit 1
  fi
  if ! rg -Fq "$gate_stage" "$phase6_contracts_integration_script"; then
    echo "phase6 contracts ci integration script must validate ${gate_stage} stage wiring"
    exit 1
  fi
done
if ! rg -Fq "cosmos_module_coverage_floor" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must include cosmos_module_coverage_floor stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_module_coverage_floor.sh" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must wire integration_cosmos_module_coverage_floor.sh"
  exit 1
fi
if ! rg -Fq "cosmos_module_coverage_floor" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must validate cosmos_module_coverage_floor stage wiring"
  exit 1
fi
if ! rg -Fq "CI_PHASE6_COSMOS_L1_CONTRACTS_PHASE6_COSMOS_MODULE_COVERAGE_FLOOR_SCRIPT" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must expose module coverage floor script override wiring"
  exit 1
fi
if ! rg -Fq "cosmos_keeper_coverage_floor" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must include cosmos_keeper_coverage_floor stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_keeper_coverage_floor.sh" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must wire integration_cosmos_keeper_coverage_floor.sh"
  exit 1
fi
if ! rg -Fq "cosmos_keeper_coverage_floor" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must validate cosmos_keeper_coverage_floor stage wiring"
  exit 1
fi
if ! rg -Fq "CI_PHASE6_COSMOS_L1_CONTRACTS_PHASE6_COSMOS_KEEPER_COVERAGE_FLOOR_SCRIPT" "$phase6_contracts_integration_script" \
  && ! rg -Fq "integration_cosmos_keeper_coverage_floor.sh" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must expose keeper coverage floor script wiring"
  exit 1
fi
if ! rg -Fq "ci_phase6_cosmos_l1_contracts.sh" "$phase6_contracts_live_smoke_script"; then
  echo "phase6 contracts live-smoke script must execute ci_phase6_cosmos_l1_contracts.sh"
  exit 1
fi
if ! rg -Fq "ci_phase6_cosmos_l1_contracts_summary" "$phase6_contracts_live_smoke_script"; then
  echo "phase6 contracts live-smoke script must validate phase6 contracts summary schema id"
  exit 1
fi
if ! rg -Fq "ci_phase6_cosmos_l1_contracts_summary" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must emit phase6 contracts summary schema id"
  exit 1
fi
if ! rg -Fq "CI_PHASE6_COSMOS_L1_CONTRACTS_CANONICAL_SUMMARY_JSON" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must emit canonical summary artifact metadata/logging"
  exit 1
fi
if ! rg -Fq "ci_phase6_cosmos_l1_contracts.sh" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must execute phase6 contracts ci script"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "CI_PHASE6_COSMOS_L1_BUILD_TESTNET_CANONICAL_SUMMARY_JSON" "$phase6_ci_script"; then
  echo "phase6 ci script must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_ci_script"; then
  echo "phase6 ci script must emit canonical summary artifact metadata/logging"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_integration_script"; then
  echo "phase6 ci integration script must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase6_integration_script"; then
  echo "phase6 ci integration script must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "ci_phase6_cosmos_l1_build_testnet.sh" "$phase6_run_script"; then
  echo "phase6 run wrapper must invoke ci_phase6_cosmos_l1_build_testnet.sh"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_check.sh" "$phase6_run_script"; then
  echo "phase6 run wrapper must invoke phase6_cosmos_l1_build_testnet_check.sh"
  exit 1
fi
if ! rg -Fq "require-tdpnd-grpc-auth-live-smoke-ok" "$phase6_run_script"; then
  echo "phase6 run wrapper must forward/handle tdpnd_grpc_auth_live_smoke requirement"
  exit 1
fi
if ! rg -Fq "PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CANONICAL_SUMMARY_JSON" "$phase6_run_script"; then
  echo "phase6 run wrapper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_run_script"; then
  echo "phase6 run wrapper must emit canonical summary artifact metadata/logging"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_check_summary" "$phase6_check_script"; then
  echo "phase6 check wrapper must emit phase6 check summary schema id"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$phase6_check_script"; then
  echo "phase6 check wrapper must include tdpnd_grpc_auth_live_smoke readiness signal"
  exit 1
fi
if ! rg -Fq "PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_CANONICAL_SUMMARY_JSON" "$phase6_check_script"; then
  echo "phase6 check wrapper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_check_script"; then
  echo "phase6 check wrapper must emit canonical summary artifact metadata"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_check_summary" "$phase6_run_script"; then
  echo "phase6 run wrapper must validate phase6 check summary schema id"
  exit 1
fi
if ! rg -Fq "ci_phase6_cosmos_l1_build_testnet.sh" "$phase6_suite_script"; then
  echo "phase6 suite wrapper must invoke ci_phase6_cosmos_l1_build_testnet.sh"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_run.sh" "$phase6_suite_script"; then
  echo "phase6 suite wrapper must invoke phase6 run wrapper"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_handoff_run.sh" "$phase6_suite_script"; then
  echo "phase6 suite wrapper must invoke phase6 handoff-run wrapper"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_suite_summary" "$phase6_suite_script"; then
  echo "phase6 suite wrapper must emit phase6 suite summary schema id"
  exit 1
fi
if ! rg -Fq "PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_CANONICAL_SUMMARY_JSON" "$phase6_suite_script"; then
  echo "phase6 suite wrapper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_suite_script"; then
  echo "phase6 suite wrapper must emit canonical summary artifact metadata/logging"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_run.sh" "$phase6_handoff_run_script"; then
  echo "phase6 handoff-run wrapper must invoke phase6 run wrapper"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_handoff_check.sh" "$phase6_handoff_run_script"; then
  echo "phase6 handoff-run wrapper must invoke phase6 handoff-check wrapper"
  exit 1
fi
if ! rg -Fq "require-tdpnd-grpc-auth-live-smoke-ok" "$phase6_handoff_run_script"; then
  echo "phase6 handoff-run wrapper must forward/handle tdpnd_grpc_auth_live_smoke requirement"
  exit 1
fi
if ! rg -Fq "PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_CANONICAL_SUMMARY_JSON" "$phase6_handoff_run_script"; then
  echo "phase6 handoff-run wrapper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_handoff_run_script"; then
  echo "phase6 handoff-run wrapper must emit canonical summary artifact metadata/logging"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_handoff_check_summary" "$phase6_handoff_check_script"; then
  echo "phase6 handoff-check wrapper must emit phase6 handoff-check summary schema id"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$phase6_handoff_check_script"; then
  echo "phase6 handoff-check wrapper must include tdpnd_grpc_auth_live_smoke readiness signal"
  exit 1
fi
if ! rg -Fq "PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON" "$phase6_handoff_check_script"; then
  echo "phase6 handoff-check wrapper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_handoff_check_script"; then
  echo "phase6 handoff-check wrapper must emit canonical summary artifact metadata"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_handoff_check_summary" "$phase6_handoff_run_script"; then
  echo "phase6 handoff-run wrapper must validate phase6 handoff-check summary schema id"
  exit 1
fi
if ! rg -Fq "ci-failure propagation" "$phase6_run_integration_script"; then
  echo "phase6 run integration must validate ci-failure propagation behavior"
  exit 1
fi
if ! rg -Fq "require-tdpnd-grpc-auth-live-smoke-ok" "$phase6_run_integration_script" \
  && ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$phase6_run_integration_script"; then
  echo "phase6 run integration must validate tdpnd_grpc_auth_live_smoke requirement forwarding/handling"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_run_integration_script"; then
  echo "phase6 run integration must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase6_run_integration_script"; then
  echo "phase6 run integration must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "fail-closed path" "$phase6_check_integration_script"; then
  echo "phase6 check integration must validate fail-closed behavior"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$phase6_check_integration_script"; then
  echo "phase6 check integration must validate tdpnd_grpc_auth_live_smoke readiness signal"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_check_integration_script"; then
  echo "phase6 check integration must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase6_check_integration_script"; then
  echo "phase6 check integration must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "stage-failure propagation path" "$phase6_suite_integration_script"; then
  echo "phase6 suite integration must validate stage-failure propagation behavior"
  exit 1
fi
if ! rg -Fq "fail-closed child summary contract path" "$phase6_suite_integration_script"; then
  echo "phase6 suite integration must validate fail-closed child contract behavior"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_suite_integration_script"; then
  echo "phase6 suite integration must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase6_suite_integration_script"; then
  echo "phase6 suite integration must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "run failure still runs handoff check" "$phase6_handoff_run_integration_script"; then
  echo "phase6 handoff-run integration must validate run-failure propagation behavior"
  exit 1
fi
if ! rg -Fq "require-tdpnd-grpc-auth-live-smoke-ok" "$phase6_handoff_run_integration_script" \
  && ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$phase6_handoff_run_integration_script"; then
  echo "phase6 handoff-run integration must validate tdpnd_grpc_auth_live_smoke requirement forwarding/handling"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_handoff_run_integration_script"; then
  echo "phase6 handoff-run integration must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase6_handoff_run_integration_script"; then
  echo "phase6 handoff-run integration must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "fail-closed path" "$phase6_handoff_check_integration_script"; then
  echo "phase6 handoff-check integration must validate fail-closed behavior"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$phase6_handoff_check_integration_script"; then
  echo "phase6 handoff-check integration must validate tdpnd_grpc_auth_live_smoke readiness signal"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_handoff_check_integration_script"; then
  echo "phase6 handoff-check integration must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase6_handoff_check_integration_script"; then
  echo "phase6 handoff-check integration must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_summary_report" "$phase6_summary_report_script"; then
  echo "phase6 summary report helper must emit phase6 summary report schema id"
  exit 1
fi
if ! rg -Fq "PHASE6_COSMOS_L1_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON" "$phase6_summary_report_script"; then
  echo "phase6 summary report helper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_summary_report_script"; then
  echo "phase6 summary report helper must emit canonical summary artifact metadata/logging"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_ci_summary.json" "$phase6_summary_report_script"; then
  echo "phase6 summary report helper must probe build/testnet ci summary artifact"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_contracts_summary.json" "$phase6_summary_report_script"; then
  echo "phase6 summary report helper must probe contracts summary artifact"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_suite_summary.json" "$phase6_summary_report_script"; then
  echo "phase6 summary report helper must probe suite summary artifact"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_build_testnet_suite_" "$phase6_summary_report_script"; then
  echo "phase6 summary report helper must support suite timestamped fallback discovery"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_summary_report.sh" "$phase6_summary_report_integration_script"; then
  echo "phase6 summary report integration script must execute summary report helper"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase6_summary_report_integration_script"; then
  echo "phase6 summary report integration script must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase6_summary_report_integration_script"; then
  echo "phase6 summary report integration script must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "pass path" "$phase6_summary_report_integration_script"; then
  echo "phase6 summary report integration script must validate pass path"
  exit 1
fi
if ! rg -Fq "fail path" "$phase6_summary_report_integration_script"; then
  echo "phase6 summary report integration script must validate fail path"
  exit 1
fi
if ! rg -Fq "missing-input path" "$phase6_summary_report_integration_script"; then
  echo "phase6 summary report integration script must validate missing-input path"
  exit 1
fi
if ! rg -Fq "expected_suite_path" "$phase6_summary_report_integration_script"; then
  echo "phase6 summary report integration script must validate suite fallback discovery path"
  exit 1
fi

if ! rg -q "Canonical source of truth" "$product_roadmap"; then
  echo "product roadmap must declare canonical source alignment"
  exit 1
fi

if ! rg -q "Parallel Track: Cosmos L1 Settlement and Governance Foundation" "$product_roadmap"; then
  echo "product roadmap missing Cosmos L1 parallel track heading"
  exit 1
fi

if rg -qi "sidecar recommendation" "$product_roadmap"; then
  echo "product roadmap should not contain legacy sidecar recommendation wording"
  exit 1
fi
if ! rg -Fq -- "--state-dir" "$product_roadmap"; then
  echo "product roadmap must document state-dir runtime integration"
  exit 1
fi
if ! rg -Fq 'module query `GET` endpoints' "$product_roadmap"; then
  echo "product roadmap must document settlement bridge GET query endpoints"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_state_dir_persistence.sh" "$product_roadmap"; then
  echo "product roadmap must document state-dir persistence integration check"
  exit 1
fi

if ! rg -q "canonical execution plan: docs/full-execution-plan-2026-2027.md" "$roadmap_script"; then
  echo "roadmap_progress_report.sh must point blockchain policy to canonical execution plan"
  exit 1
fi

if ! rg -q "Cosmos-first blockchain track" "$roadmap_script"; then
  echo "roadmap_progress_report.sh must use Cosmos-first blockchain recommendation"
  exit 1
fi

if rg -q "intentionally reported as deferred" "$roadmap_script"; then
  echo "roadmap_progress_report.sh still marks blockchain track as deferred"
  exit 1
fi

if rg -q 'blockchain_track_status="deferred"' "$roadmap_script"; then
  echo "roadmap_progress_report.sh must not set blockchain_track_status=deferred"
  exit 1
fi

if rg -qi "sidecar recommendation" "$roadmap_script"; then
  echo "roadmap_progress_report.sh contains stale sidecar recommendation wording"
  exit 1
fi
if ! rg -Fq "state-dir-capable file-backed module stores" "$roadmap_script"; then
  echo "roadmap_progress_report.sh must include state-dir-capable runtime recommendation wording"
  exit 1
fi

if ! rg -Fq "Status: active Cosmos-first parallel build track" "$bootstrap_validator_doc"; then
  echo "bootstrap validator plan must declare active Cosmos-first parallel build status"
  exit 1
fi

if ! rg -Fq "VPN dataplane remains independent from chain liveness" "$bootstrap_validator_doc"; then
  echo "bootstrap validator plan must enforce VPN dataplane independence from chain liveness"
  exit 1
fi

if ! rg -Fq "Hybrid governance: objective on-chain events + policy-governed subjective cases" "$bootstrap_validator_doc"; then
  echo "bootstrap validator plan must declare hybrid governance posture"
  exit 1
fi

if rg -qi "implementation deferred|\\(Deferred\\)|Deferred Track" "$bootstrap_validator_doc"; then
  echo "bootstrap validator plan contains stale deferred framing"
  exit 1
fi

if rg -qi "sidecar recommendation" "$bootstrap_validator_doc"; then
  echo "bootstrap validator plan contains stale sidecar recommendation wording"
  exit 1
fi

if ! rg -Fq "SETTLEMENT_CHAIN_ADAPTER=cosmos" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document adapter activation env"
  exit 1
fi

if ! rg -Fq "ISSUER_SETTLEMENT_RECONCILE_SEC" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document issuer reconcile loop env"
  exit 1
fi

if ! rg -Fq "EXIT_SETTLEMENT_RECONCILE_SEC" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document exit reconcile loop env"
  exit 1
fi
if ! rg -Fq -- "--state-dir" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document tdpnd --state-dir"
  exit 1
fi

for env_key in \
  "COSMOS_SETTLEMENT_SUBMIT_MODE" \
  "COSMOS_SETTLEMENT_SIGNED_TX_BROADCAST_PATH" \
  "COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID" \
  "COSMOS_SETTLEMENT_SIGNED_TX_SIGNER" \
  "COSMOS_SETTLEMENT_SIGNED_TX_SECRET" \
  "COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE" \
  "COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID"
do
  if ! rg -Fq "$env_key" "$cosmos_runtime_doc"; then
    echo "cosmos settlement runtime guide must document $env_key"
    exit 1
  fi
done
for shadow_env_key in \
  "COSMOS_SETTLEMENT_SHADOW_ENDPOINT" \
  "COSMOS_SETTLEMENT_SHADOW_API_KEY" \
  "COSMOS_SETTLEMENT_SHADOW_SUBMIT_MODE" \
  "COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_BROADCAST_PATH"
do
  if ! rg -Fq "$shadow_env_key" "$cosmos_runtime_doc"; then
    echo "cosmos settlement runtime guide must document $shadow_env_key"
    exit 1
  fi
done
if ! rg -Fq "Shadow submission failures never block primary adapter submission, session setup, or dataplane forwarding." "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document shadow adapter non-blocking behavior"
  exit 1
fi
if ! rg -Fq "Cosmos adapter retry policy" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document adapter retry policy"
  exit 1
fi
if ! rg -Fq "retryable: transport/network errors, HTTP \`408\`, \`425\`, \`429\`, and \`5xx\`." "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document retryable adapter error classes"
  exit 1
fi
if ! rg -Fq "non-retryable: other HTTP \`4xx\` validation/auth-style failures" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document non-retryable adapter error classes"
  exit 1
fi

if ! rg -Fq 'GET /v1/settlement/status' "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document settlement status endpoint"
  exit 1
fi
for bridge_query_path in \
  "GET /x/vpnbilling/reservations" \
  "GET /x/vpnrewards/accruals" \
  "GET /x/vpnsponsor/authorizations" \
  "GET /x/vpnslashing/penalties"
do
  if ! rg -Fq "$bridge_query_path" "$cosmos_runtime_doc"; then
    echo "cosmos settlement runtime guide must document bridge query endpoint: $bridge_query_path"
    exit 1
  fi
done
if ! rg -Fq "integration_cosmos_tdpnd_state_dir_persistence.sh" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document state-dir persistence integration script"
  exit 1
fi
if ! rg -Fq "settlement_shadow_env" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document settlement_shadow_env phase5 stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_settlement_shadow_env.sh" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document settlement_shadow_env integration script"
  exit 1
fi
if ! rg -Fq "settlement_shadow_status_surface" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document settlement_shadow_status_surface phase5 stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_settlement_shadow_status_surface.sh" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document settlement_shadow_status_surface integration script"
  exit 1
fi
if ! rg -Fq "blockchain-app-sponsorship-quickstart.md" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must link blockchain sponsor quickstart"
  exit 1
fi
if ! rg -Fq "Shadow telemetry fields in status payload" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document issuer shadow telemetry status fields"
  exit 1
fi
if ! rg -Fq "Shadow telemetry fields are also surfaced on exit status snapshots" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document exit shadow telemetry status fields"
  exit 1
fi
for shadow_status_key in \
  "shadow_adapter_configured" \
  "shadow_attempted_operations" \
  "shadow_submitted_operations" \
  "shadow_failed_operations"
do
  if ! rg -Fq "$shadow_status_key" "$cosmos_runtime_doc"; then
    echo "cosmos settlement runtime guide must document settlement shadow telemetry key: $shadow_status_key"
    exit 1
  fi
  if ! rg -Fq "$shadow_status_key" "$protocol_doc"; then
    echo "protocol doc must document settlement shadow telemetry key: $shadow_status_key"
    exit 1
  fi
done
check_confirmation_interface_wording "$cosmos_runtime_doc" "cosmos settlement runtime guide"

if ! rg -Fq -- "--state-dir" "$chain_readme"; then
  echo "chain README must document optional --state-dir runtime flag"
  exit 1
fi
if ! rg -Fq "GET /x/vpnbilling/reservations" "$chain_readme"; then
  echo "chain README must document settlement bridge GET query endpoints"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_state_dir_persistence.sh" "$chain_readme"; then
  echo "chain README must document state-dir persistence integration coverage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_local_testnet_smoke.sh" "$chain_readme"; then
  echo "chain README must document local multi-node smoke integration script"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$chain_readme"; then
  echo "chain README must document phase6 tdpnd_grpc_auth_live_smoke stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_grpc_auth_live_smoke.sh" "$chain_readme"; then
  echo "chain README must document tdpnd gRPC auth live-smoke script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_summary_report.sh" "$chain_readme"; then
  echo "chain README must document phase6 summary report helper script"
  exit 1
fi
if ! rg -Fq "integration_phase6_cosmos_l1_summary_report.sh" "$chain_readme"; then
  echo "chain README must document phase6 summary report integration contract script"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_summary_report.sh" "$chain_readme"; then
  echo "chain README must document phase5 summary report helper script"
  exit 1
fi
if ! rg -Fq "integration_phase5_settlement_layer_summary_report.sh" "$chain_readme"; then
  echo "chain README must document phase5 summary report integration contract script"
  exit 1
fi
if ! rg -Fq "integration_easy_node_blockchain_summary_reports.sh" "$chain_readme"; then
  echo "chain README must document easy-node blockchain summary-wrapper integration coverage script"
  exit 1
fi
if ! rg -Fq "blockchain-app-sponsorship-quickstart.md" "$chain_readme"; then
  echo "chain README must link blockchain sponsor quickstart"
  exit 1
fi
if rg -Fq "Storage remains an in-memory placeholder; Cosmos SDK KV store integration is still pending." "$chain_readme"; then
  echo "chain README contains stale in-memory-placeholder storage wording"
  exit 1
fi
if ! rg -Fq "in-memory default for lightweight/local runs" "$chain_readme"; then
  echo "chain README must document in-memory default storage posture"
  exit 1
fi
if ! rg -Fq "optional file-backed state-dir stores for persistence" "$chain_readme"; then
  echo "chain README must document file-backed state-dir storage posture"
  exit 1
fi
if ! rg -Fq "keeper KV-adapter seam for Cosmos SDK KV integration" "$chain_readme"; then
  echo "chain README must document keeper KV-adapter seam posture"
  exit 1
fi
check_confirmation_lifecycle_wording "$chain_readme" "chain README"
check_adapter_roundtrip_wording "$chain_readme" "chain README"
check_confirmation_interface_wording "$chain_readme" "chain README"

if ! rg -Fq "GET /x/vpnbilling/reservations[/{reservation_id}]" "$settlement_mapping_doc"; then
  echo "settlement bridge mapping must document list/by-id GET query mapping"
  exit 1
fi
if ! rg -Fq -- "--state-dir <path>" "$settlement_mapping_doc"; then
  echo "settlement bridge mapping must document --state-dir runtime persistence option"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_state_dir_persistence.sh" "$settlement_mapping_doc"; then
  echo "settlement bridge mapping must document state-dir persistence integration script"
  exit 1
fi
if rg -Fq "Keepers remain in-memory placeholders and intentionally do not block session dataplane behavior." "$settlement_mapping_doc"; then
  echo "settlement bridge mapping contains stale in-memory-placeholder keeper wording"
  exit 1
fi
if ! rg -Fq "Keepers use in-memory defaults for lightweight/local runs" "$settlement_mapping_doc"; then
  echo "settlement bridge mapping must document in-memory default keeper posture"
  exit 1
fi
if ! rg -Fq "file-backed \`--state-dir\` runtime persistence" "$settlement_mapping_doc"; then
  echo "settlement bridge mapping must document file-backed state-dir keeper posture"
  exit 1
fi
if ! rg -Fq "KV-adapter seam for Cosmos SDK integration" "$settlement_mapping_doc"; then
  echo "settlement bridge mapping must document keeper KV-adapter seam posture"
  exit 1
fi
check_confirmation_lifecycle_wording "$settlement_mapping_doc" "settlement bridge mapping"
check_adapter_roundtrip_wording "$settlement_mapping_doc" "settlement bridge mapping"
check_confirmation_interface_wording "$settlement_mapping_doc" "settlement bridge mapping"

for sponsor_quickstart_contract in \
  "/v1/sponsor/quote" \
  "/v1/sponsor/reserve" \
  "/v1/sponsor/token" \
  "/v1/sponsor/status?reservation_id=" \
  "X-Sponsor-Token" \
  "payment_proof"
do
  if ! rg -Fq "$sponsor_quickstart_contract" "$blockchain_sponsor_quickstart_doc"; then
    echo "blockchain sponsor quickstart must document contract field/path: $sponsor_quickstart_contract"
    exit 1
  fi
done
if ! rg -Fq "without requiring user wallet signing in the happy path" "$blockchain_sponsor_quickstart_doc"; then
  echo "blockchain sponsor quickstart must document no-wallet-signing happy path"
  exit 1
fi

for phase5_script in "$phase5_ci_script" "$phase5_integration_script"; do
  if rg -qi "phase4 windows full parity" "$phase5_script"; then
    echo "phase5 settlement tooling contains stale phase4 wording: $phase5_script"
    exit 1
  fi
done
if ! rg -Fq "settlement_adapter_roundtrip" "$phase5_ci_script"; then
  echo "phase5 ci script must include settlement_adapter_roundtrip stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh" "$phase5_ci_script"; then
  echo "phase5 ci script must wire integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh"
  exit 1
fi
if ! rg -Fq "settlement_adapter_signed_tx_roundtrip" "$phase5_ci_script"; then
  echo "phase5 ci script must include settlement_adapter_signed_tx_roundtrip stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_adapter_tdpnd_signed_tx_roundtrip.sh" "$phase5_ci_script"; then
  echo "phase5 ci script must wire integration_cosmos_adapter_tdpnd_signed_tx_roundtrip.sh"
  exit 1
fi
if ! rg -Fq "settlement_shadow_env" "$phase5_ci_script"; then
  echo "phase5 ci script must include settlement_shadow_env stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_settlement_shadow_env.sh" "$phase5_ci_script"; then
  echo "phase5 ci script must wire integration_cosmos_settlement_shadow_env.sh"
  exit 1
fi
if ! rg -Fq "settlement_shadow_status_surface" "$phase5_ci_script"; then
  echo "phase5 ci script must include settlement_shadow_status_surface stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_settlement_shadow_status_surface.sh" "$phase5_ci_script"; then
  echo "phase5 ci script must wire integration_cosmos_settlement_shadow_status_surface.sh"
  exit 1
fi
if [[ ! -f "$ROOT_DIR/scripts/integration_cosmos_settlement_shadow_env.sh" ]]; then
  echo "missing required script: scripts/integration_cosmos_settlement_shadow_env.sh"
  exit 1
fi
if [[ ! -f "$ROOT_DIR/scripts/integration_cosmos_settlement_shadow_status_surface.sh" ]]; then
  echo "missing required script: scripts/integration_cosmos_settlement_shadow_status_surface.sh"
  exit 1
fi
if ! rg -Fq "settlement_adapter_roundtrip" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate settlement_adapter_roundtrip stage"
  exit 1
fi
if ! rg -Fq "settlement_adapter_signed_tx_roundtrip" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate settlement_adapter_signed_tx_roundtrip stage"
  exit 1
fi
if ! rg -Fq "settlement_shadow_env" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate settlement_shadow_env stage"
  exit 1
fi
if ! rg -Fq "settlement_shadow_status_surface" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate settlement_shadow_status_surface stage"
  exit 1
fi
if ! rg -Fq "CI_PHASE5_SETTLEMENT_LAYER_CANONICAL_SUMMARY_JSON" "$phase5_ci_script"; then
  echo "phase5 ci script must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase5_ci_script"; then
  echo "phase5 ci script must emit canonical summary artifact metadata/logging"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "ci_phase5_settlement_layer.sh" "$phase5_run_script"; then
  echo "phase5 run wrapper must invoke ci_phase5_settlement_layer.sh"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_check.sh" "$phase5_run_script"; then
  echo "phase5 run wrapper must invoke phase5_settlement_layer_check.sh"
  exit 1
fi
if ! rg -Fq "PHASE5_SETTLEMENT_LAYER_RUN_CANONICAL_SUMMARY_JSON" "$phase5_run_script"; then
  echo "phase5 run wrapper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase5_run_script"; then
  echo "phase5 run wrapper must emit canonical summary artifact metadata/logging"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase5_run_integration_script"; then
  echo "phase5 run integration must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase5_run_integration_script"; then
  echo "phase5 run integration must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON" "$phase5_check_script"; then
  echo "phase5 check wrapper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase5_check_script"; then
  echo "phase5 check wrapper must emit canonical summary artifact metadata"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase5_check_integration_script"; then
  echo "phase5 check integration must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase5_check_integration_script"; then
  echo "phase5 check integration must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_run.sh" "$phase5_handoff_run_script"; then
  echo "phase5 handoff-run wrapper must invoke phase5_settlement_layer_run.sh"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_handoff_check.sh" "$phase5_handoff_run_script"; then
  echo "phase5 handoff-run wrapper must invoke phase5_settlement_layer_handoff_check.sh"
  exit 1
fi
if ! rg -Fq "PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON" "$phase5_handoff_run_script"; then
  echo "phase5 handoff-run wrapper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase5_handoff_run_script"; then
  echo "phase5 handoff-run wrapper must emit canonical summary artifact metadata/logging"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase5_handoff_run_integration_script"; then
  echo "phase5 handoff-run integration must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase5_handoff_run_integration_script"; then
  echo "phase5 handoff-run integration must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON" "$phase5_handoff_check_script"; then
  echo "phase5 handoff-check wrapper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase5_handoff_check_script"; then
  echo "phase5 handoff-check wrapper must emit canonical summary artifact metadata"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase5_handoff_check_integration_script"; then
  echo "phase5 handoff-check integration must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase5_handoff_check_integration_script"; then
  echo "phase5 handoff-check integration must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_summary_report" "$phase5_summary_report_script"; then
  echo "phase5 summary report helper must emit phase5 summary report schema id"
  exit 1
fi
if ! rg -Fq "PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON" "$phase5_summary_report_script"; then
  echo "phase5 summary report helper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase5_summary_report_script"; then
  echo "phase5 summary report helper must emit canonical summary artifact metadata/logging"
  exit 1
fi
for phase5_helper_artifact in \
  "phase5_settlement_layer_ci_summary.json" \
  "phase5_settlement_layer_check_summary.json" \
  "phase5_settlement_layer_run_summary.json" \
  "phase5_settlement_layer_handoff_check_summary.json" \
  "phase5_settlement_layer_handoff_run_summary.json"
do
  if ! rg -Fq "$phase5_helper_artifact" "$phase5_summary_report_script"; then
    echo "phase5 summary report helper must probe canonical phase5 artifact: $phase5_helper_artifact"
    exit 1
  fi
done
if ! rg -Fq "ci_phase5_settlement_layer_" "$phase5_summary_report_script"; then
  echo "phase5 summary report helper must include fallback discovery for timestamped ci summaries"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_handoff_run_" "$phase5_summary_report_script"; then
  echo "phase5 summary report helper must include fallback discovery for timestamped handoff-run summaries"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_summary_report.sh" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must execute summary report helper"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must validate canonical summary artifact wiring"
  exit 1
fi
if ! rg -Fq "cmp -s" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must validate canonical and run summary content parity"
  exit 1
fi
if ! rg -Fq "pass path" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must validate pass path"
  exit 1
fi
if ! rg -Fq "fail path" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must validate fail path"
  exit 1
fi
if ! rg -Fq "missing-input path" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must validate missing-input path"
  exit 1
fi
if ! rg -Fq "fallback discovery path" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must validate fallback path"
  exit 1
fi
for phase5_canonical_summary in \
  "phase5_settlement_layer_ci_summary.json" \
  "phase5_settlement_layer_check_summary.json" \
  "phase5_settlement_layer_run_summary.json" \
  "phase5_settlement_layer_handoff_check_summary.json" \
  "phase5_settlement_layer_handoff_run_summary.json"
do
  if ! rg -Fq "$phase5_canonical_summary" "$full_plan"; then
    echo "full execution plan must document phase5 canonical summary artifact: $phase5_canonical_summary"
    exit 1
  fi
  if ! rg -Fq "$phase5_canonical_summary" "$product_roadmap"; then
    echo "product roadmap must document phase5 canonical summary artifact: $phase5_canonical_summary"
    exit 1
  fi
  if ! rg -Fq "$phase5_canonical_summary" "$chain_readme"; then
    echo "chain README must document phase5 canonical summary artifact: $phase5_canonical_summary"
    exit 1
  fi
done
phase5_blockchain_gate_specs=(
  "settlement_adapter_roundtrip|scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh"
  "settlement_adapter_signed_tx_roundtrip|scripts/integration_cosmos_adapter_tdpnd_signed_tx_roundtrip.sh"
  "settlement_shadow_env|scripts/integration_cosmos_settlement_shadow_env.sh"
  "settlement_shadow_status_surface|scripts/integration_cosmos_settlement_shadow_status_surface.sh"
)
for gate_spec in "${phase5_blockchain_gate_specs[@]}"; do
  gate_stage="${gate_spec%%|*}"
  gate_script="${gate_spec#*|}"
  if ! rg -Fq "$gate_stage" "$product_roadmap"; then
    echo "product roadmap must document ${gate_stage} phase5 stage"
    exit 1
  fi
  if ! rg -Fq "$gate_script" "$product_roadmap"; then
    echo "product roadmap must document ${gate_script} phase5 integration script"
    exit 1
  fi
done

echo "roadmap consistency check ok"
