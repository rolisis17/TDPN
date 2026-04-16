#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

full_plan="docs/full-execution-plan-2026-2027.md"
product_roadmap="docs/product-roadmap.md"
roadmap_script="scripts/roadmap_progress_report.sh"
roadmap_integration_script="scripts/integration_roadmap_progress_report.sh"
bootstrap_validator_doc="docs/blockchain-bootstrap-validator-plan.md"
cosmos_runtime_doc="docs/cosmos-settlement-runtime.md"
testing_guide_doc="docs/testing-guide.md"
chain_readme="blockchain/tdpn-chain/README.md"
chain_scaffold_file="blockchain/tdpn-chain/app/scaffold.go"
chain_grpc_registry_file="blockchain/tdpn-chain/app/grpc_registry.go"
chain_grpc_registry_test_file="blockchain/tdpn-chain/app/grpc_registry_test.go"
chain_settlement_bridge_file="blockchain/tdpn-chain/cmd/tdpnd/settlement_bridge.go"
chain_runtime_test_file="blockchain/tdpn-chain/cmd/tdpnd/runtime_test.go"
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
phase5_issuer_admin_blockchain_handlers_coverage_script="scripts/integration_issuer_admin_blockchain_handlers_coverage_floor.sh"
blockchain_fastlane_script="scripts/blockchain_fastlane.sh"
blockchain_fastlane_integration_script="scripts/integration_blockchain_fastlane.sh"
blockchain_mainnet_activation_metrics_integration_script="scripts/integration_blockchain_mainnet_activation_metrics.sh"
blockchain_mainnet_activation_gate_script="scripts/blockchain_mainnet_activation_gate.sh"
blockchain_mainnet_activation_gate_integration_script="scripts/integration_blockchain_mainnet_activation_gate.sh"
ci_local_script="scripts/ci_local.sh"
easy_node_script="scripts/easy_node.sh"
easy_node_blockchain_gate_wrappers_integration_script="scripts/integration_easy_node_blockchain_gate_wrappers.sh"
easy_node_blockchain_summary_reports_integration_script="scripts/integration_easy_node_blockchain_summary_reports.sh"
phase6_ci_script="scripts/ci_phase6_cosmos_l1_build_testnet.sh"
phase6_integration_script="scripts/integration_ci_phase6_cosmos_l1_build_testnet.sh"
phase6_contracts_ci_script="scripts/ci_phase6_cosmos_l1_contracts.sh"
phase6_contracts_integration_script="scripts/integration_ci_phase6_cosmos_l1_contracts.sh"
phase6_contracts_live_smoke_script="scripts/integration_phase6_cosmos_l1_contracts_live_smoke.sh"
phase6_grpc_app_roundtrip_script="scripts/integration_cosmos_grpc_app_roundtrip.sh"
phase6_grpc_runtime_smoke_script="scripts/integration_cosmos_tdpnd_grpc_runtime_smoke.sh"
phase6_grpc_live_smoke_script="scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh"
phase6_grpc_auth_live_smoke_script="scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh"
phase6_settlement_bridge_smoke_script="scripts/integration_cosmos_tdpnd_settlement_bridge_smoke.sh"
phase6_settlement_bridge_live_smoke_script="scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh"
phase6_query_surface_script="scripts/integration_cosmos_query_surface.sh"
phase6_module_tx_surface_script="scripts/integration_cosmos_module_tx_surface.sh"
phase6_proto_surface_script="scripts/integration_cosmos_proto_surface.sh"
phase6_proto_grpc_surface_script="scripts/integration_cosmos_proto_grpc_surface.sh"
phase6_proto_codegen_surface_script="scripts/integration_cosmos_proto_codegen_surface.sh"
phase6_module_coverage_floor_script="scripts/integration_cosmos_module_coverage_floor.sh"
phase6_keeper_coverage_floor_script="scripts/integration_cosmos_keeper_coverage_floor.sh"
phase6_app_coverage_floor_script="scripts/integration_cosmos_app_coverage_floor.sh"
phase6_dual_write_parity_script="scripts/integration_cosmos_dual_write_parity.sh"
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
phase7_check_script="scripts/phase7_mainnet_cutover_check.sh"
phase7_check_integration_script="scripts/integration_phase7_mainnet_cutover_check.sh"
phase7_run_script="scripts/phase7_mainnet_cutover_run.sh"
phase7_run_integration_script="scripts/integration_phase7_mainnet_cutover_run.sh"
phase7_handoff_check_script="scripts/phase7_mainnet_cutover_handoff_check.sh"
phase7_handoff_check_integration_script="scripts/integration_phase7_mainnet_cutover_handoff_check.sh"
phase7_handoff_run_script="scripts/phase7_mainnet_cutover_handoff_run.sh"
phase7_handoff_run_integration_script="scripts/integration_phase7_mainnet_cutover_handoff_run.sh"
phase7_ci_script="scripts/ci_phase7_mainnet_cutover.sh"
phase7_ci_integration_script="scripts/integration_ci_phase7_mainnet_cutover.sh"
phase7_summary_report_script="scripts/phase7_mainnet_cutover_summary_report.sh"
phase7_summary_report_integration_script="scripts/integration_phase7_mainnet_cutover_summary_report.sh"

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

check_phase7_roadmap_surface_cli() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq -- "--phase7-mainnet-cutover-summary-json" "$file_path"; then
    echo "$label must accept --phase7-mainnet-cutover-summary-json for the Phase 7 roadmap summary surface"
    exit 1
  fi
  if ! rg -Fq "phase7_mainnet_cutover" "$file_path"; then
    echo "$label must reference phase7_mainnet_cutover in the roadmap progress report JSON surface"
    exit 1
  fi
}

check_phase7_roadmap_surface_integration() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq "blockchain_track.phase7_mainnet_cutover" "$file_path"; then
    echo "$label must assert blockchain_track.phase7_mainnet_cutover in roadmap progress report integration coverage"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.phase7_mainnet_cutover.status" "$file_path"; then
    echo "$label must assert blockchain_track.phase7_mainnet_cutover.status in roadmap progress report integration coverage"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.phase7_mainnet_cutover.rc" "$file_path"; then
    echo "$label must assert blockchain_track.phase7_mainnet_cutover.rc in roadmap progress report integration coverage"
    exit 1
  fi
}

check_phase7_roadmap_surface_docs() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq "phase7_mainnet_cutover_summary_report.sh" "$file_path"; then
    echo "$label must mention the Phase 7 operator summary helper (phase7_mainnet_cutover_summary_report.sh)"
    exit 1
  fi
  if ! rg -Fq "./scripts/easy_node.sh phase7-mainnet-cutover-summary-report" "$file_path"; then
    echo "$label must mention the Phase 7 easy-node summary wrapper (phase7-mainnet-cutover-summary-report)"
    exit 1
  fi
}

check_phase7_comet_signal_surface() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq "tdpnd_comet_runtime_smoke_ok" "$file_path"; then
    echo "$label must propagate tdpnd_comet_runtime_smoke_ok in phase7 handoff contracts"
    exit 1
  fi
}

check_phase7_summary_comet_signal_surface() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq "signal_snapshot" "$file_path"; then
    echo "$label must surface phase7 signal_snapshot in summary contracts"
    exit 1
  fi
  if ! rg -Fq "tdpnd_comet_runtime_smoke_ok" "$file_path"; then
    echo "$label must propagate tdpnd_comet_runtime_smoke_ok in phase7 summary contracts"
    exit 1
  fi
  if ! rg -Fq "tdpnd_grpc_live_smoke_ok" "$file_path"; then
    echo "$label must propagate tdpnd_grpc_live_smoke_ok in phase7 summary contracts"
    exit 1
  fi
}

check_phase7_comet_forwarding_surface() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq -- "--handoff-require-tdpnd-comet-runtime-smoke-ok" "$file_path" \
    && ! rg -Fq -- "--require-tdpnd-comet-runtime-smoke-ok" "$file_path"; then
    echo "$label must include comet signal forwarding for phase7 handoff dry-run coverage"
    exit 1
  fi
}

check_phase7_mainnet_activation_gate_doc_surface() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq "mainnet_activation_gate_go" "$file_path"; then
    echo "$label must document phase7 mainnet_activation_gate_go signal surfacing"
    exit 1
  fi
  if ! rg -Fq "check/run/handoff-check/handoff-run" "$file_path"; then
    echo "$label must scope mainnet_activation_gate_go to phase7 check/run/handoff-check/handoff-run contexts"
    exit 1
  fi
  if ! rg -Fq "optional by default" "$file_path"; then
    echo "$label must document that mainnet_activation_gate_go enforcement is optional by default"
    exit 1
  fi
}

check_phase7_coverage_floor_gating_doc_surface() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq "coverage-floor signals" "$file_path"; then
    echo "$label must document phase7 coverage-floor signal gating posture"
    exit 1
  fi
  for token in \
    "cosmos_module_coverage_floor" \
    "cosmos_keeper_coverage_floor" \
    "cosmos_app_coverage_floor" \
    "dual-write parity confirmation" \
    "phase7_mainnet_cutover_check.sh" \
    "phase7_mainnet_cutover_handoff_check.sh"
  do
    if ! rg -Fq "$token" "$file_path"; then
      echo "$label must include phase7 coverage-floor gating contract token: $token"
      exit 1
    fi
  done
  if ! rg -Fq -- "--require-mainnet-activation-gate-go" "$file_path"; then
    echo "$label must include phase7 coverage-floor gating flag surface: --require-mainnet-activation-gate-go"
    exit 1
  fi
}

check_phase7_summary_coverage_signal_doc_surface() {
  local file_path="$1"
  local label="$2"

  for token in \
    "phase7_mainnet_cutover_summary_report.sh" \
    "roadmap_progress_report.sh" \
    "cosmos_module_coverage_floor_ok" \
    "cosmos_keeper_coverage_floor_ok" \
    "cosmos_app_coverage_floor_ok" \
    "dual_write_parity_ok"
  do
    if ! rg -Fq "$token" "$file_path"; then
      echo "$label must document phase7 summary/report coverage-floor signal surfacing token: $token"
      exit 1
    fi
  done
}

check_phase7_summary_runtime_signal_doc_surface() {
  local file_path="$1"
  local label="$2"

  for token in \
    "phase7_mainnet_cutover_summary_report.sh" \
    "module_tx_surface_ok" \
    "tdpnd_grpc_live_smoke_ok" \
    "tdpnd_grpc_auth_live_smoke_ok"
  do
    if ! rg -Fq "$token" "$file_path"; then
      echo "$label must document phase7 summary/runtime signal surfacing token: $token"
      exit 1
    fi
  done
}

check_phase7_roadmap_summary_coverage_signal_surface() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq "phase7_mainnet_cutover_summary_report" "$file_path"; then
    echo "$label must reference phase7_mainnet_cutover_summary_report for phase7 coverage-floor signal surfacing"
    exit 1
  fi
  for signal in \
    "cosmos_module_coverage_floor_ok" \
    "cosmos_keeper_coverage_floor_ok" \
    "cosmos_app_coverage_floor_ok" \
    "dual_write_parity_ok"
  do
    if ! rg -Fq "$signal" "$file_path"; then
      echo "$label must reference phase7 coverage-floor summary signal: $signal"
      exit 1
    fi
  done
}

check_phase7_mainnet_activation_gate_signal_surface() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq "mainnet_activation_gate_go" "$file_path"; then
    echo "$label must reference mainnet_activation_gate_go in phase7 signal surfaces"
    exit 1
  fi
}

check_phase7_mainnet_activation_gate_requirement_surface() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq -- "--require-mainnet-activation-gate-go" "$file_path"; then
    echo "$label must expose --require-mainnet-activation-gate-go in phase7 handoff requirement surfaces"
    exit 1
  fi
}

check_blockchain_fastlane_activation_gate_surface() {
  local file_path="$1"
  local label="$2"
  local phase7_runtime_summary_signal

  for token in \
    "scripts/blockchain_fastlane.sh" \
    "scripts/integration_blockchain_fastlane.sh" \
    "./scripts/easy_node.sh blockchain-fastlane" \
    "./scripts/easy_node.sh blockchain-mainnet-activation-metrics" \
    "./scripts/easy_node.sh blockchain-mainnet-activation-gate" \
    "scripts/integration_easy_node_blockchain_gate_wrappers.sh" \
    "blockchain_mainnet_activation_metrics" \
    "scripts/blockchain_mainnet_activation_metrics.sh" \
    "scripts/integration_blockchain_mainnet_activation_metrics.sh" \
    "--blockchain-mainnet-activation-metrics-source-json" \
    "BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SOURCE_JSONS" \
    "inputs.blockchain_mainnet_activation_metrics_source_jsons" \
    "artifacts.blockchain_mainnet_activation_metrics_source_jsons" \
    "mainnet activation gate" \
    "scripts/blockchain_mainnet_activation_gate.sh" \
    "scripts/integration_blockchain_mainnet_activation_gate.sh" \
    "--blockchain-mainnet-activation-gate-summary-json" \
    "BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON" \
    "inputs.blockchain_mainnet_activation_gate_summary_json" \
    "artifacts.blockchain_mainnet_activation_gate_summary_json" \
    "blockchain_track.mainnet_activation_gate" \
    "fail-soft when the summary is missing or invalid" \
    "fail-closed control-plane wiring"
  do
    if [[ "$token" == --* ]]; then
      if ! rg -Fq -- "$token" "$file_path"; then
        echo "$label must document blockchain fastlane activation-gate contract token: $token"
        exit 1
      fi
    elif ! rg -Fq "$token" "$file_path"; then
      echo "$label must document blockchain fastlane activation-gate contract token: $token"
      exit 1
    fi
  done

  for phase7_runtime_summary_signal in \
    "module_tx_surface_ok" \
    "tdpnd_grpc_live_smoke_ok" \
    "tdpnd_grpc_auth_live_smoke_ok" \
    "tdpnd_comet_runtime_smoke_ok"
  do
    if ! rg -Fq "$phase7_runtime_summary_signal" "$file_path"; then
      echo "$label must document blockchain fastlane phase7 summary signal token: $phase7_runtime_summary_signal"
      exit 1
    fi
  done
  if ! rg -q -e "mainnet_activation_gate_go(_ok)?" "$file_path"; then
    echo "$label must document blockchain fastlane phase7 summary signal token: mainnet_activation_gate_go_ok (or mainnet_activation_gate_go)"
    exit 1
  fi
}

check_mainnet_activation_gate_surface() {
  local file_path="$1"
  local label="$2"

  if ! rg -Fq -- "--blockchain-mainnet-activation-gate-summary-json" "$file_path"; then
    echo "$label must accept --blockchain-mainnet-activation-gate-summary-json for the blockchain mainnet activation gate surface"
    exit 1
  fi
  if ! rg -Fq "blockchain_track.mainnet_activation_gate" "$file_path"; then
    echo "$label must surface blockchain_track.mainnet_activation_gate in the roadmap progress report JSON surface"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.mainnet_activation_gate.available" "$file_path"; then
    echo "$label must expose blockchain_track.mainnet_activation_gate.available in the roadmap progress report JSON surface"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.mainnet_activation_gate.input_summary_json" "$file_path"; then
    echo "$label must expose blockchain_track.mainnet_activation_gate.input_summary_json in the roadmap progress report JSON surface"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.mainnet_activation_gate.source_summary_json" "$file_path"; then
    echo "$label must expose blockchain_track.mainnet_activation_gate.source_summary_json in the roadmap progress report JSON surface"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.mainnet_activation_gate.source_summary_kind" "$file_path"; then
    echo "$label must expose blockchain_track.mainnet_activation_gate.source_summary_kind in the roadmap progress report JSON surface"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.mainnet_activation_gate.status" "$file_path"; then
    echo "$label must expose blockchain_track.mainnet_activation_gate.status in the roadmap progress report JSON surface"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.mainnet_activation_gate.decision" "$file_path"; then
    echo "$label must expose blockchain_track.mainnet_activation_gate.decision in the roadmap progress report JSON surface"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.mainnet_activation_gate.go" "$file_path"; then
    echo "$label must expose blockchain_track.mainnet_activation_gate.go in the roadmap progress report JSON surface"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.mainnet_activation_gate.no_go" "$file_path"; then
    echo "$label must expose blockchain_track.mainnet_activation_gate.no_go in the roadmap progress report JSON surface"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.mainnet_activation_gate.reasons" "$file_path"; then
    echo "$label must expose blockchain_track.mainnet_activation_gate.reasons in the roadmap progress report JSON surface"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.mainnet_activation_gate.source_paths" "$file_path"; then
    echo "$label must expose blockchain_track.mainnet_activation_gate.source_paths in the roadmap progress report JSON surface"
    exit 1
  fi
}

for f in "$full_plan" "$product_roadmap" "$roadmap_script" "$roadmap_integration_script" "$bootstrap_validator_doc" "$cosmos_runtime_doc" "$testing_guide_doc" "$chain_readme" "$chain_scaffold_file" "$chain_grpc_registry_file" "$chain_grpc_registry_test_file" "$chain_settlement_bridge_file" "$chain_runtime_test_file" "$settlement_mapping_doc" "$blockchain_sponsor_quickstart_doc" "$phase5_ci_script" "$phase5_integration_script" "$phase5_check_script" "$phase5_run_script" "$phase5_handoff_check_script" "$phase5_handoff_run_script" "$phase5_check_integration_script" "$phase5_run_integration_script" "$phase5_handoff_check_integration_script" "$phase5_handoff_run_integration_script" "$phase5_summary_report_script" "$phase5_summary_report_integration_script" "$blockchain_fastlane_script" "$blockchain_fastlane_integration_script" "$ci_local_script" "$easy_node_script" "$easy_node_blockchain_gate_wrappers_integration_script" "$easy_node_blockchain_summary_reports_integration_script" "$phase6_ci_script" "$phase6_integration_script" "$phase6_contracts_ci_script" "$phase6_contracts_integration_script" "$phase6_contracts_live_smoke_script" "$phase6_grpc_app_roundtrip_script" "$phase6_grpc_runtime_smoke_script" "$phase6_grpc_live_smoke_script" "$phase6_grpc_auth_live_smoke_script" "$phase6_settlement_bridge_smoke_script" "$phase6_settlement_bridge_live_smoke_script" "$phase6_query_surface_script" "$phase6_module_tx_surface_script" "$phase6_proto_surface_script" "$phase6_proto_grpc_surface_script" "$phase6_proto_codegen_surface_script" "$phase6_module_coverage_floor_script" "$phase6_keeper_coverage_floor_script" "$phase6_app_coverage_floor_script" "$phase6_dual_write_parity_script" "$phase6_check_script" "$phase6_run_script" "$phase6_check_integration_script" "$phase6_run_integration_script" "$phase6_suite_script" "$phase6_suite_integration_script" "$phase6_summary_report_script" "$phase6_summary_report_integration_script" "$phase7_check_script" "$phase7_check_integration_script" "$phase7_run_script" "$phase7_run_integration_script" "$phase7_handoff_check_script" "$phase7_handoff_check_integration_script" "$phase7_handoff_run_script" "$phase7_handoff_run_integration_script" "$phase7_ci_script" "$phase7_ci_integration_script" "$phase7_summary_report_script" "$phase7_summary_report_integration_script"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required file: $f"
    exit 1
  fi
done
for query_surface_contract in \
  "./x/vpnbilling/module" \
  "./x/vpnrewards/module" \
  "./x/vpnslashing/module" \
  "./x/vpnsponsor/module" \
  "./x/vpnvalidator/module" \
  "./x/vpngovernance/module"
do
  if ! rg -Fq "$query_surface_contract" "$phase6_query_surface_script"; then
    echo "phase6 query surface script must include six-module query test contract: $query_surface_contract"
    exit 1
  fi
done
for module_tx_surface_contract in \
  "./x/vpnbilling/keeper" \
  "./x/vpnrewards/keeper" \
  "./x/vpnslashing/keeper" \
  "./x/vpnsponsor/keeper" \
  "./x/vpnvalidator/keeper" \
  "./x/vpngovernance/keeper" \
  "./x/vpnbilling/module" \
  "./x/vpnrewards/module" \
  "./x/vpnslashing/module" \
  "./x/vpnsponsor/module" \
  "./x/vpnvalidator/module" \
  "./x/vpngovernance/module"
do
  if ! rg -Fq "$module_tx_surface_contract" "$phase6_module_tx_surface_script"; then
    echo "phase6 module tx surface script must include six-module tx contract: $module_tx_surface_contract"
    exit 1
  fi
done
for proto_module in vpnbilling vpnrewards vpnslashing vpnsponsor vpnvalidator vpngovernance; do
  if ! rg -Fq "tdpn/$proto_module/v1/types.proto" "$phase6_proto_surface_script"; then
    echo "phase6 proto surface script must include proto module: $proto_module"
    exit 1
  fi
  if ! rg -Fq "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/$proto_module/v1" "$phase6_proto_grpc_surface_script"; then
    echo "phase6 proto grpc surface script must include generated go package module: $proto_module"
    exit 1
  fi
done
for proto_codegen_contract in \
  "vpnvalidator/v1/query_grpc.pb.go:ListValidatorEligibilities" \
  "vpnvalidator/v1/query_grpc.pb.go:ListValidatorStatusRecords" \
  "vpnvalidator/v1/query_grpc.pb.go:PreviewEpochSelection" \
  "vpngovernance/v1/query_grpc.pb.go:ListGovernancePolicies" \
  "vpngovernance/v1/query_grpc.pb.go:ListGovernanceDecisions" \
  "vpngovernance/v1/query_grpc.pb.go:ListGovernanceAuditActions"
do
  if ! rg -Fq "$proto_codegen_contract" "$phase6_proto_codegen_surface_script"; then
    echo "phase6 proto codegen surface script must include validator/governance generated symbol contract: $proto_codegen_contract"
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
if ! rg -Fq "write \`POST\` endpoints across billing/rewards/sponsor/slashing plus validator/governance modules" "$full_plan"; then
  echo "full execution plan must document validator/governance settlement bridge POST write expansion"
  exit 1
fi
if ! rg -Fq "bearer auth applied to \`POST\` only when configured" "$full_plan"; then
  echo "full execution plan must document POST-only settlement bridge auth contract"
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
if ! rg -Fq "settlement_dual_asset_parity" "$full_plan"; then
  echo "full execution plan must document settlement_dual_asset_parity gate posture"
  exit 1
fi
if ! rg -Fq "integration_cosmos_settlement_dual_asset_parity.sh" "$full_plan"; then
  echo "full execution plan must document dual-asset parity integration script"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity_ok" "$full_plan"; then
  echo "full execution plan must document settlement_dual_asset_parity_ok summary signal posture"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke" "$full_plan"; then
  echo "full execution plan must document issuer_sponsor_api_live_smoke gate posture"
  exit 1
fi
if ! rg -Fq "integration_issuer_sponsor_api_live_smoke.sh" "$full_plan"; then
  echo "full execution plan must document issuer_sponsor_api_live_smoke integration script"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage" "$full_plan"; then
  echo "full execution plan must document issuer_admin_blockchain_handlers_coverage gate posture"
  exit 1
fi
if ! rg -Fq "integration_issuer_admin_blockchain_handlers_coverage_floor.sh" "$full_plan"; then
  echo "full execution plan must document issuer_admin_blockchain_handlers_coverage integration script"
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
if ! rg -Fq "module_tx_surface" "$full_plan"; then
  echo "full execution plan must document phase6 module_tx_surface stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_module_tx_surface.sh" "$full_plan"; then
  echo "full execution plan must document phase6 module_tx_surface integration script"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$full_plan"; then
  echo "full execution plan must document phase6 tdpnd_grpc_auth_live_smoke stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_grpc_app_roundtrip.sh" "$full_plan"; then
  echo "full execution plan must document phase6 grpc app roundtrip integration script"
  exit 1
fi
if ! rg -Fq "billing/rewards/slashing/sponsor/validator/governance Msg+Query roundtrip contracts" "$full_plan"; then
  echo "full execution plan must document six-module Msg+Query grpc app roundtrip posture"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_grpc_auth_live_smoke.sh" "$full_plan"; then
  echo "full execution plan must document phase6 tdpnd gRPC auth live-smoke script"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh" "$full_plan"; then
  echo "full execution plan must document settlement bridge live-smoke script"
  exit 1
fi
if ! rg -Fq "tdpnd_comet_runtime_smoke" "$full_plan"; then
  echo "full execution plan must document phase6 tdpnd_comet_runtime_smoke stage"
  exit 1
fi
if ! rg -Fq -- "--run-tdpnd-comet-runtime-smoke" "$full_plan"; then
  echo "full execution plan must document phase6 comet runtime smoke CLI toggle"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_comet_runtime_smoke.sh" "$full_plan"; then
  echo "full execution plan must document phase6 comet runtime smoke script"
  exit 1
fi
if ! rg -Fq "billing/rewards/slashing/sponsor/validator/governance query dispatch" "$full_plan"; then
  echo "full execution plan must document six-module gRPC live query dispatch posture"
  exit 1
fi
if ! rg -Fq "billing/rewards/slashing/sponsor/validator/governance query RPCs" "$full_plan"; then
  echo "full execution plan must document six-module gRPC auth query-RPC coverage posture"
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
if rg -Fq "fail-fast propagation" "$full_plan"; then
  echo "full execution plan must not claim fail-fast phase6 contracts behavior; gate uses first-failure RC with full-stage accounting"
  exit 1
fi
if ! rg -Fq "first-failure RC propagation with full-stage accounting" "$full_plan"; then
  echo "full execution plan must document first-failure RC propagation with full-stage accounting for phase6 contracts"
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
if ! rg -Fq "cosmos_app_coverage_floor" "$full_plan"; then
  echo "full execution plan must document phase6 contracts cosmos_app_coverage_floor stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_app_coverage_floor.sh" "$full_plan"; then
  echo "full execution plan must document phase6 contracts app coverage floor integration script"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_dual_write_parity" "$full_plan"; then
  echo "full execution plan must document phase6 contracts phase6_cosmos_dual_write_parity stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_dual_write_parity.sh" "$full_plan"; then
  echo "full execution plan must document phase6 contracts dual-write parity integration script"
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
if ! rg -Fq "phase7_mainnet_cutover_check.sh" "$full_plan"; then
  echo "full execution plan must document phase7 mainnet cutover check wrapper script"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_check.sh" "$full_plan"; then
  echo "full execution plan must document phase7 mainnet cutover check integration contract script"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_run.sh" "$full_plan"; then
  echo "full execution plan must document phase7 mainnet cutover run wrapper script"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_check.sh" "$full_plan"; then
  echo "full execution plan must document phase7 mainnet cutover handoff check wrapper script"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_handoff_check.sh" "$full_plan"; then
  echo "full execution plan must document phase7 mainnet cutover handoff check integration contract script"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_run.sh" "$full_plan"; then
  echo "full execution plan must document phase7 mainnet cutover handoff run wrapper script"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_handoff_run.sh" "$full_plan"; then
  echo "full execution plan must document phase7 mainnet cutover handoff run integration contract script"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_run.sh" "$full_plan"; then
  echo "full execution plan must document phase7 mainnet cutover run integration contract script"
  exit 1
fi
if ! rg -Fq "ci_phase7_mainnet_cutover.sh" "$full_plan"; then
  echo "full execution plan must document phase7 mainnet cutover ci wrapper script"
  exit 1
fi
if ! rg -Fq "integration_ci_phase7_mainnet_cutover.sh" "$full_plan"; then
  echo "full execution plan must document phase7 mainnet cutover ci integration contract script"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_summary_report.sh" "$full_plan"; then
  echo "full execution plan must document phase7 mainnet cutover summary report helper script"
  exit 1
fi
if ! rg -Fq "tdpnd_comet_runtime_smoke_ok" "$full_plan" \
  || ! rg -qi "optional|preserved when available|without making it a hard requirement" "$full_plan"; then
  echo "full execution plan must document optional tdpnd_comet_runtime_smoke_ok in phase7 summary surfaces"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_summary_report.sh" "$full_plan"; then
  echo "full execution plan must document phase7 mainnet cutover summary report integration contract script"
  exit 1
fi
if ! rg -Fq -- "--blockchain-mainnet-activation-gate-summary-json" "$full_plan"; then
  echo "full execution plan must document the blockchain mainnet activation gate summary input surface"
  exit 1
fi
if ! rg -Fq "blockchain_track.mainnet_activation_gate" "$full_plan"; then
  echo "full execution plan must document blockchain_track.mainnet_activation_gate summary surface"
  exit 1
fi
if ! rg -Fq "Phase-7 propagated \`mainnet_activation_gate_go\` signal" "$full_plan"; then
  echo "full execution plan must document phase7-signal fallback for mainnet activation gate summary surfacing"
  exit 1
fi
if ! rg -Fq "Mainnet Activation Go/No-Go Metrics Gate" "$full_plan"; then
  echo "full execution plan must reference the blockchain mainnet activation gate policy"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_check_summary.json" "$full_plan"; then
  echo "full execution plan must document phase7 handoff-check summary artifact"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_run_summary.json" "$full_plan"; then
  echo "full execution plan must document phase7 handoff-run summary artifact"
  exit 1
fi
if ! rg -Fq "phase6 readiness signals" "$full_plan"; then
  echo "full execution plan must document phase7 dependency on phase6 readiness signals"
  exit 1
fi
if ! rg -Fq "dual-write parity confirmation" "$full_plan"; then
  echo "full execution plan must document phase7 dual-write parity confirmation posture"
  exit 1
fi
if ! rg -Fq "rollback path readiness" "$full_plan"; then
  echo "full execution plan must document phase7 rollback path readiness posture"
  exit 1
fi
if ! rg -Fq "optional operator approval gate" "$full_plan"; then
  echo "full execution plan must document phase7 optional operator approval gate posture"
  exit 1
fi
if ! rg -qi "VPN dataplane.*independent.*chain liveness" "$full_plan"; then
  echo "full execution plan must preserve VPN dataplane independence from chain liveness in phase7 posture"
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
if ! rg -Fq "integration_easy_node_blockchain_gate_wrappers.sh" "$full_plan"; then
  echo "full execution plan must document easy-node blockchain gate-wrapper integration coverage script"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke_ok" "$full_plan"; then
  echo "full execution plan must document phase6 readiness/handoff tdpnd_grpc_auth_live_smoke_ok signal"
  exit 1
fi
if ! rg -Fq "module_tx_surface_ok" "$full_plan"; then
  echo "full execution plan must document phase6 readiness/handoff module_tx_surface_ok signal"
  exit 1
fi
if ! rg -Fq "run/handoff-run dry-run relaxation" "$full_plan" \
  || ! rg -Fq "module_tx_surface_ok" "$full_plan" \
  || ! rg -Fq "tdpnd_grpc_auth_live_smoke_ok" "$full_plan"; then
  echo "full execution plan must document phase6 run/handoff-run dry-run module-tx/auth-live relaxation posture"
  exit 1
fi
if ! rg -Fq "roadmap_progress_report.sh" "$full_plan" \
  || ! rg -Fq "phase6_cosmos_l1_handoff" "$full_plan" \
  || ! rg -Fq "integration_roadmap_progress_report.sh" "$full_plan"; then
  echo "full execution plan must document roadmap progress phase6 handoff signal surfacing contract"
  exit 1
fi
check_phase7_roadmap_surface_cli "$roadmap_script" "roadmap progress report script"
check_phase7_roadmap_surface_integration "$roadmap_integration_script" "roadmap progress report integration script"
check_phase7_roadmap_surface_docs "$full_plan" "full execution plan"
check_phase7_roadmap_surface_docs "$product_roadmap" "product roadmap"
check_phase7_roadmap_surface_docs "$cosmos_runtime_doc" "cosmos settlement runtime doc"
check_phase7_summary_coverage_signal_doc_surface "$full_plan" "full execution plan"
check_phase7_summary_coverage_signal_doc_surface "$product_roadmap" "product roadmap"
check_phase7_summary_coverage_signal_doc_surface "$cosmos_runtime_doc" "cosmos settlement runtime doc"
check_phase7_summary_runtime_signal_doc_surface "$full_plan" "full execution plan"
check_phase7_summary_runtime_signal_doc_surface "$product_roadmap" "product roadmap"
check_phase7_summary_runtime_signal_doc_surface "$cosmos_runtime_doc" "cosmos settlement runtime doc"
check_phase7_roadmap_summary_coverage_signal_surface "$roadmap_script" "roadmap progress report helper"
check_phase7_roadmap_summary_coverage_signal_surface "$roadmap_integration_script" "roadmap progress report integration script"
check_phase7_comet_signal_surface "$full_plan" "full execution plan"
check_phase7_comet_signal_surface "$product_roadmap" "product roadmap"
check_phase7_mainnet_activation_gate_doc_surface "$full_plan" "full execution plan"
check_phase7_mainnet_activation_gate_doc_surface "$product_roadmap" "product roadmap"
check_phase7_coverage_floor_gating_doc_surface "$full_plan" "full execution plan"
check_phase7_coverage_floor_gating_doc_surface "$product_roadmap" "product roadmap"
check_phase7_coverage_floor_gating_doc_surface "$cosmos_runtime_doc" "cosmos settlement runtime doc"
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
if ! rg -Fq "module_tx_surface" "$product_roadmap"; then
  echo "product roadmap must document phase6 module_tx_surface stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_module_tx_surface.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 module_tx_surface integration script"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$product_roadmap"; then
  echo "product roadmap must document phase6 tdpnd_grpc_auth_live_smoke stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_grpc_app_roundtrip.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 grpc app roundtrip integration script"
  exit 1
fi
if ! rg -Fq "billing/rewards/slashing/sponsor/validator/governance Msg+Query roundtrip contracts" "$product_roadmap"; then
  echo "product roadmap must document six-module Msg+Query grpc app roundtrip posture"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_grpc_auth_live_smoke.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 tdpnd gRPC auth live-smoke script"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh" "$product_roadmap"; then
  echo "product roadmap must document settlement bridge live-smoke script"
  exit 1
fi
if ! rg -Fq "tdpnd_comet_runtime_smoke" "$product_roadmap"; then
  echo "product roadmap must document phase6 tdpnd_comet_runtime_smoke stage"
  exit 1
fi
if ! rg -Fq -- "--run-tdpnd-comet-runtime-smoke" "$product_roadmap"; then
  echo "product roadmap must document phase6 comet runtime smoke CLI toggle"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_comet_runtime_smoke.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 comet runtime smoke script"
  exit 1
fi
if ! rg -Fq "billing/rewards/slashing/sponsor/validator/governance query dispatch" "$product_roadmap"; then
  echo "product roadmap must document six-module gRPC live query dispatch posture"
  exit 1
fi
if ! rg -Fq "billing/rewards/slashing/sponsor/validator/governance query RPCs" "$product_roadmap"; then
  echo "product roadmap must document six-module gRPC auth query-RPC coverage posture"
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
if rg -Fq "fail-fast propagation" "$product_roadmap"; then
  echo "product roadmap must not claim fail-fast phase6 contracts behavior; gate uses first-failure RC with full-stage accounting"
  exit 1
fi
if ! rg -Fq "first-failure RC propagation with full-stage accounting" "$product_roadmap"; then
  echo "product roadmap must document first-failure RC propagation with full-stage accounting for phase6 contracts"
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
if ! rg -Fq "cosmos_app_coverage_floor" "$product_roadmap"; then
  echo "product roadmap must document phase6 contracts cosmos_app_coverage_floor stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_app_coverage_floor.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 contracts app coverage floor integration script"
  exit 1
fi
for coverage_doc in "$full_plan" "$product_roadmap" "$chain_readme"; do
  if ! rg -Fq "billing/rewards/slashing/sponsor/validator/governance" "$coverage_doc"; then
    echo "$coverage_doc must explicitly document six-target phase6 coverage floor posture (billing/rewards/slashing/sponsor/validator/governance)"
    exit 1
  fi
done
if ! rg -Fq "phase6_cosmos_dual_write_parity" "$product_roadmap"; then
  echo "product roadmap must document phase6 contracts phase6_cosmos_dual_write_parity stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_dual_write_parity.sh" "$product_roadmap"; then
  echo "product roadmap must document phase6 contracts dual-write parity integration script"
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
if ! rg -Fq "phase7_mainnet_cutover_check.sh" "$product_roadmap"; then
  echo "product roadmap must document phase7 mainnet cutover check wrapper script"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_check.sh" "$product_roadmap"; then
  echo "product roadmap must document phase7 mainnet cutover check integration contract script"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_run.sh" "$product_roadmap"; then
  echo "product roadmap must document phase7 mainnet cutover run wrapper script"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_check.sh" "$product_roadmap"; then
  echo "product roadmap must document phase7 mainnet cutover handoff check wrapper script"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_handoff_check.sh" "$product_roadmap"; then
  echo "product roadmap must document phase7 mainnet cutover handoff check integration contract script"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_run.sh" "$product_roadmap"; then
  echo "product roadmap must document phase7 mainnet cutover handoff run wrapper script"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_handoff_run.sh" "$product_roadmap"; then
  echo "product roadmap must document phase7 mainnet cutover handoff run integration contract script"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_run.sh" "$product_roadmap"; then
  echo "product roadmap must document phase7 mainnet cutover run integration contract script"
  exit 1
fi
if ! rg -Fq "ci_phase7_mainnet_cutover.sh" "$product_roadmap"; then
  echo "product roadmap must document phase7 mainnet cutover ci wrapper script"
  exit 1
fi
if ! rg -Fq "integration_ci_phase7_mainnet_cutover.sh" "$product_roadmap"; then
  echo "product roadmap must document phase7 mainnet cutover ci integration contract script"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_summary_report.sh" "$product_roadmap"; then
  echo "product roadmap must document phase7 mainnet cutover summary report helper script"
  exit 1
fi
if ! rg -Fq "tdpnd_comet_runtime_smoke_ok" "$product_roadmap" \
  || ! rg -qi "optional|preserved when available|without making it a hard requirement" "$product_roadmap"; then
  echo "product roadmap must document optional tdpnd_comet_runtime_smoke_ok in phase7 summary surfaces"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_summary_report.sh" "$product_roadmap"; then
  echo "product roadmap must document phase7 mainnet cutover summary report integration contract script"
  exit 1
fi
if ! rg -Fq -- "--blockchain-mainnet-activation-gate-summary-json" "$product_roadmap"; then
  echo "product roadmap must document the blockchain mainnet activation gate summary input surface"
  exit 1
fi
if ! rg -Fq "blockchain_track.mainnet_activation_gate" "$product_roadmap"; then
  echo "product roadmap must document blockchain_track.mainnet_activation_gate summary surface"
  exit 1
fi
if ! rg -Fq "Phase-7 propagated \`mainnet_activation_gate_go\` signal" "$product_roadmap"; then
  echo "product roadmap must document phase7-signal fallback for mainnet activation gate summary surfacing"
  exit 1
fi
if ! rg -Fq "Mainnet Activation Go/No-Go Metrics Gate" "$product_roadmap"; then
  echo "product roadmap must reference the blockchain mainnet activation gate policy"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_check_summary.json" "$product_roadmap"; then
  echo "product roadmap must document phase7 handoff-check summary artifact"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_run_summary.json" "$product_roadmap"; then
  echo "product roadmap must document phase7 handoff-run summary artifact"
  exit 1
fi
if ! rg -Fq "phase6 readiness signals" "$product_roadmap"; then
  echo "product roadmap must document phase7 dependency on phase6 readiness signals"
  exit 1
fi
if ! rg -Fq "dual-write parity confirmation" "$product_roadmap"; then
  echo "product roadmap must document phase7 dual-write parity confirmation posture"
  exit 1
fi
if ! rg -Fq "rollback path readiness" "$product_roadmap"; then
  echo "product roadmap must document phase7 rollback path readiness posture"
  exit 1
fi
if ! rg -Fq "optional operator approval gate" "$product_roadmap"; then
  echo "product roadmap must document phase7 optional operator approval gate posture"
  exit 1
fi
if ! rg -qi "VPN dataplane.*independent.*chain liveness" "$product_roadmap"; then
  echo "product roadmap must preserve VPN dataplane independence from chain liveness in phase7 posture"
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
if ! rg -Fq "settlement_dual_asset_parity_ok" "$product_roadmap"; then
  echo "product roadmap must document phase5 settlement_dual_asset_parity_ok signal posture"
  exit 1
fi
if ! rg -iq "phase[[:space:]]*5 summary helper fallback discovery" "$product_roadmap" \
  || ! rg -iq "timestamped[[:space:]]+ci" "$product_roadmap" \
  || ! rg -iq "handoff-run" "$product_roadmap"; then
  echo "product roadmap must document phase5 summary helper fallback discovery for timestamped CI/handoff-run summaries"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity" "$testing_guide_doc"; then
  echo "testing guide must document settlement_dual_asset_parity stage in phase5 targeted gates"
  exit 1
fi
if ! rg -Fq "integration_cosmos_settlement_dual_asset_parity.sh" "$testing_guide_doc"; then
  echo "testing guide must document integration_cosmos_settlement_dual_asset_parity.sh in phase5 targeted gates"
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
if ! rg -Fq "integration_easy_node_blockchain_gate_wrappers.sh" "$product_roadmap"; then
  echo "product roadmap must document easy-node blockchain gate-wrapper integration coverage script"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke_ok" "$product_roadmap"; then
  echo "product roadmap must document phase6 readiness/handoff tdpnd_grpc_auth_live_smoke_ok signal"
  exit 1
fi
if ! rg -Fq "module_tx_surface_ok" "$product_roadmap"; then
  echo "product roadmap must document phase6 readiness/handoff module_tx_surface_ok signal"
  exit 1
fi
if ! rg -Fq "run/handoff-run dry-run relaxation" "$product_roadmap" \
  || ! rg -Fq "module_tx_surface_ok" "$product_roadmap" \
  || ! rg -Fq "tdpnd_grpc_auth_live_smoke_ok" "$product_roadmap"; then
  echo "product roadmap must document phase6 run/handoff-run dry-run module-tx/auth-live relaxation posture"
  exit 1
fi
if ! rg -Fq "roadmap_progress_report.sh" "$product_roadmap" \
  || ! rg -Fq "phase6_cosmos_l1_handoff" "$product_roadmap" \
  || ! rg -Fq "integration_roadmap_progress_report.sh" "$product_roadmap"; then
  echo "product roadmap must document roadmap progress phase6 handoff signal surfacing contract"
  exit 1
fi

phase6_stage_specs=(
  "chain_scaffold|integration_cosmos_chain_scaffold.sh"
  "local_testnet_smoke|integration_cosmos_local_testnet_smoke.sh"
  "proto_surface|integration_cosmos_proto_surface.sh"
  "proto_codegen_surface|integration_cosmos_proto_codegen_surface.sh"
  "query_surface|integration_cosmos_query_surface.sh"
  "module_tx_surface|integration_cosmos_module_tx_surface.sh"
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
if ! rg -Fq "TestRegisterGRPCServicesNilInputs" "$phase6_grpc_app_roundtrip_script"; then
  echo "phase6 grpc app roundtrip script must include nil-input grpc registration contract test"
  exit 1
fi
if ! rg -Fq "TestRegisterGRPCServicesBillingAndSponsorRoundTrip" "$phase6_grpc_app_roundtrip_script"; then
  echo "phase6 grpc app roundtrip script must include core-module grpc roundtrip contract test anchor"
  exit 1
fi
if ! rg -Fq "TestRegisterGRPCServicesValidatorAndGovernanceRoundTrip" "$phase6_grpc_app_roundtrip_script" \
  && ! rg -Fq "TestRegisterGRPCServicesValidatorGovernanceRoundTrip" "$phase6_grpc_app_roundtrip_script"; then
  echo "phase6 grpc app roundtrip script must include validator/governance Msg+Query grpc roundtrip contract test"
  exit 1
fi
if ! rg -Fq "PreviewEpochSelection" "$chain_grpc_registry_test_file"; then
  echo "grpc app roundtrip test suite must include validator PreviewEpochSelection contract coverage"
  exit 1
fi
for app_roundtrip_contract in \
  "ListSettlementRecords" \
  "ListDistributionRecords" \
  "ListDelegatedSessionCredits" \
  "ListValidatorStatusRecords" \
  "ListGovernanceDecisions" \
  "ListGovernanceAuditActions" \
  "ListRewardAccruals" \
  "ListSlashEvidence" \
  "ListPenaltyDecisions"
do
  if ! rg -Fq "$app_roundtrip_contract" "$chain_grpc_registry_test_file"; then
    echo "grpc app roundtrip test suite must include slashing/rewards contract marker: $app_roundtrip_contract"
    exit 1
  fi
done
if ! rg -Fq "TestRunTDPNDGRPCModeRealScaffoldValidatorAndGovernanceRoundTrip" "$phase6_grpc_runtime_smoke_script"; then
  echo "phase6 grpc runtime smoke script must include validator/governance real-scaffold runtime roundtrip contract test"
  exit 1
fi
if ! rg -Fq "TestRunTDPNDGRPCModeReflectionIncludesCoreModuleQueries" "$phase6_grpc_runtime_smoke_script"; then
  echo "phase6 grpc runtime smoke script must include reflected core-module query service contract test"
  exit 1
fi
if ! rg -Fq "TestRunTDPNDGRPCModeRealScaffoldValidatorAndGovernanceRoundTrip" "$chain_runtime_test_file"; then
  echo "runtime test suite must include validator/governance real-scaffold grpc roundtrip contract test"
  exit 1
fi
if ! rg -Fq "TestRunTDPNDGRPCModeReflectionIncludesCoreModuleQueries" "$chain_runtime_test_file"; then
  echo "runtime test suite must include reflected core-module query service contract test"
  exit 1
fi
for runtime_grpc_contract in \
  "ListSettlementRecords" \
  "ListDistributionRecords" \
  "ListDelegatedSessionCredits" \
  "ListValidatorStatusRecords" \
  "ListGovernanceDecisions" \
  "ListGovernanceAuditActions" \
  "ListRewardAccruals" \
  "ListSlashEvidence" \
  "ListPenaltyDecisions" \
  "ListSponsorAuthorizations" \
  "ListValidatorEligibilities" \
  "ListGovernancePolicies" \
  "PreviewEpochSelection"
do
  if ! rg -Fq "$runtime_grpc_contract" "$chain_runtime_test_file"; then
    echo "runtime test suite must include validator/governance grpc contract marker: $runtime_grpc_contract"
    exit 1
  fi
done
for runtime_reflection_service in \
  "tdpn.vpnbilling.v1.Query" \
  "tdpn.vpnrewards.v1.Query" \
  "tdpn.vpnslashing.v1.Query" \
  "tdpn.vpnsponsor.v1.Query" \
  "tdpn.vpnvalidator.v1.Query" \
  "tdpn.vpngovernance.v1.Query"
do
  if ! rg -Fq "$runtime_reflection_service" "$chain_runtime_test_file"; then
    echo "runtime reflection coverage must include core query service marker: $runtime_reflection_service"
    exit 1
  fi
done
for live_grpc_service in \
  "tdpn.vpnbilling.v1.Query" \
  "tdpn.vpnrewards.v1.Query" \
  "tdpn.vpnslashing.v1.Query" \
  "tdpn.vpnsponsor.v1.Query" \
  "tdpn.vpnvalidator.v1.Query" \
  "tdpn.vpngovernance.v1.Query"
do
  if ! rg -Fq "$live_grpc_service" "$phase6_grpc_live_smoke_script"; then
    echo "phase6 grpc live-smoke script must validate reflected service parity: $live_grpc_service"
    exit 1
  fi
done
for live_grpc_method in \
  "tdpn.vpnbilling.v1.Query/ListCreditReservations" \
  "tdpn.vpnbilling.v1.Query/ListSettlementRecords" \
  "tdpn.vpnrewards.v1.Query/ListRewardAccruals" \
  "tdpn.vpnrewards.v1.Query/ListDistributionRecords" \
  "tdpn.vpnslashing.v1.Query/ListSlashEvidence" \
  "tdpn.vpnslashing.v1.Query/ListPenaltyDecisions" \
  "tdpn.vpnsponsor.v1.Query/ListSponsorAuthorizations" \
  "tdpn.vpnsponsor.v1.Query/ListDelegatedSessionCredits" \
  "tdpn.vpnvalidator.v1.Query/ListValidatorEligibilities" \
  "tdpn.vpnvalidator.v1.Query/ListValidatorStatusRecords" \
  "tdpn.vpnvalidator.v1.Query/PreviewEpochSelection" \
  "tdpn.vpngovernance.v1.Query/ListGovernancePolicies" \
  "tdpn.vpngovernance.v1.Query/ListGovernanceDecisions" \
  "tdpn.vpngovernance.v1.Query/ListGovernanceAuditActions"
do
  if ! rg -Fq "$live_grpc_method" "$phase6_grpc_live_smoke_script"; then
    echo "phase6 grpc live-smoke script must validate live query dispatch method: $live_grpc_method"
    exit 1
  fi
done
phase6_contract_gate_specs=(
  "phase6_cosmos_l1_contracts_live_smoke|integration_phase6_cosmos_l1_contracts_live_smoke.sh"
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
if ! rg -Fq "phase6_cosmos_l1_contracts_live_smoke" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must include phase6_cosmos_l1_contracts_live_smoke stage"
  exit 1
fi
if ! rg -Fq "integration_phase6_cosmos_l1_contracts_live_smoke.sh" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must wire integration_phase6_cosmos_l1_contracts_live_smoke.sh by default"
  exit 1
fi
if ! rg -Fq "CI_PHASE6_COSMOS_L1_CONTRACTS_RUN_PHASE6_COSMOS_L1_CONTRACTS_LIVE_SMOKE=0" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must enforce live-smoke recursion-guard env override"
  exit 1
fi
if ! rg -Fq "assert_stage_order \"\$CAPTURE\" \"\${STAGE_IDS[@]}\"" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must include stable STAGE_IDS ordering checks"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_contracts_live_smoke.status == \"pass\"" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must validate live-smoke pass accounting"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_contracts_live_smoke.status == \"skip\"" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must validate live-smoke skip accounting"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_contracts_live_smoke.status == \"fail\"" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must validate live-smoke fail accounting"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_contracts_live_smoke.command | contains(\"CI_PHASE6_COSMOS_L1_CONTRACTS_RUN_PHASE6_COSMOS_L1_CONTRACTS_LIVE_SMOKE=0\")" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must validate live-smoke recursion-guard command marker"
  exit 1
fi
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
for module_floor_contract in \
  "COSMOS_MODULE_COVERAGE_FLOOR_VPNBILLING_MODULE" \
  "COSMOS_MODULE_COVERAGE_FLOOR_VPNREWARDS_MODULE" \
  "COSMOS_MODULE_COVERAGE_FLOOR_VPNSLASHING_MODULE" \
  "COSMOS_MODULE_COVERAGE_FLOOR_VPNSPONSOR_MODULE" \
  "COSMOS_MODULE_COVERAGE_FLOOR_VPNVALIDATOR_MODULE" \
  "COSMOS_MODULE_COVERAGE_FLOOR_VPNGOVERNANCE_MODULE" \
  "./x/vpnbilling/module" \
  "./x/vpnrewards/module" \
  "./x/vpnslashing/module" \
  "./x/vpnsponsor/module" \
  "./x/vpnvalidator/module" \
  "./x/vpngovernance/module"
do
  if ! rg -Fq "$module_floor_contract" "$phase6_module_coverage_floor_script"; then
    echo "phase6 module coverage floor script must include six-target contract: $module_floor_contract"
    exit 1
  fi
done
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
for keeper_floor_contract in \
  "COSMOS_KEEPER_COVERAGE_FLOOR_VPNBILLING_KEEPER" \
  "COSMOS_KEEPER_COVERAGE_FLOOR_VPNREWARDS_KEEPER" \
  "COSMOS_KEEPER_COVERAGE_FLOOR_VPNSLASHING_KEEPER" \
  "COSMOS_KEEPER_COVERAGE_FLOOR_VPNSPONSOR_KEEPER" \
  "COSMOS_KEEPER_COVERAGE_FLOOR_VPNVALIDATOR_KEEPER" \
  "COSMOS_KEEPER_COVERAGE_FLOOR_VPNGOVERNANCE_KEEPER" \
  "./x/vpnbilling/keeper" \
  "./x/vpnrewards/keeper" \
  "./x/vpnslashing/keeper" \
  "./x/vpnsponsor/keeper" \
  "./x/vpnvalidator/keeper" \
  "./x/vpngovernance/keeper"
do
  if ! rg -Fq "$keeper_floor_contract" "$phase6_keeper_coverage_floor_script"; then
    echo "phase6 keeper coverage floor script must include six-target contract: $keeper_floor_contract"
    exit 1
  fi
done
if ! rg -Fq "cosmos_app_coverage_floor" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must include cosmos_app_coverage_floor stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_app_coverage_floor.sh" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must wire integration_cosmos_app_coverage_floor.sh"
  exit 1
fi
if ! rg -Fq "cosmos_app_coverage_floor" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must validate cosmos_app_coverage_floor stage wiring"
  exit 1
fi
if ! rg -Fq "CI_PHASE6_COSMOS_L1_CONTRACTS_PHASE6_COSMOS_APP_COVERAGE_FLOOR_SCRIPT" "$phase6_contracts_integration_script" \
  && ! rg -Fq "integration_cosmos_app_coverage_floor.sh" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must expose app coverage floor script wiring"
  exit 1
fi
for app_floor_contract in \
  "COSMOS_APP_COVERAGE_FLOOR_DEFAULT" \
  "COSMOS_APP_COVERAGE_FLOOR" \
  "go test ./app -count=1 -cover" \
  "./app"
do
  if ! rg -Fq "$app_floor_contract" "$phase6_app_coverage_floor_script"; then
    echo "phase6 app coverage floor script must include app contract marker: $app_floor_contract"
    exit 1
  fi
done
if ! rg -Fq "phase6_cosmos_dual_write_parity" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must include phase6_cosmos_dual_write_parity stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_dual_write_parity.sh" "$phase6_contracts_ci_script"; then
  echo "phase6 contracts ci script must wire integration_cosmos_dual_write_parity.sh"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_dual_write_parity" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must validate phase6_cosmos_dual_write_parity stage wiring"
  exit 1
fi
if ! rg -Fq "CI_PHASE6_COSMOS_L1_CONTRACTS_PHASE6_COSMOS_DUAL_WRITE_PARITY_SCRIPT" "$phase6_contracts_integration_script" \
  && ! rg -Fq "integration_cosmos_dual_write_parity.sh" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must expose dual-write parity script wiring"
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
if ! rg -Fq "phase6_cosmos_app_coverage_floor" "$phase6_contracts_live_smoke_script"; then
  echo "phase6 contracts live-smoke script must validate phase6_cosmos_app_coverage_floor stage presence"
  exit 1
fi
if ! rg -Fq 'phase6_cosmos_app_coverage_floor.status == "pass"' "$phase6_contracts_live_smoke_script"; then
  echo "phase6 contracts live-smoke script must validate phase6_cosmos_app_coverage_floor pass status"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_app_coverage_floor.rc == 0" "$phase6_contracts_live_smoke_script"; then
  echo "phase6 contracts live-smoke script must validate phase6_cosmos_app_coverage_floor rc==0 contract"
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
if ! rg -Fq "[ci-phase6-cosmos-l1-contracts] canonical summary same-path" "$phase6_contracts_integration_script"; then
  echo "phase6 contracts ci integration script must include same-path canonical contract coverage marker"
  exit 1
fi
if ! rg -Fq "TestRunTDPNDSettlementHTTPAuthContractGETOpenPOSTBearerRequired" "$phase6_settlement_bridge_smoke_script"; then
  echo "settlement bridge smoke script must explicitly cover auth-contract regression test"
  exit 1
fi
if ! rg -Fq "TestRunTDPNDSettlementHTTPValidatorGovernanceWriteMethodContract" "$phase6_settlement_bridge_smoke_script"; then
  echo "settlement bridge smoke script must explicitly cover validator/governance write method contract test"
  exit 1
fi
if ! rg -Fq "TestRunTDPNDSettlementHTTPValidatorEpochSelectionPreviewContract" "$phase6_settlement_bridge_smoke_script"; then
  echo "settlement bridge smoke script must explicitly cover validator epoch-selection preview contract test"
  exit 1
fi
for settlement_bridge_smoke_contract in \
  "TestRunTDPNDSettlementHTTPSlashEvidenceRejectsInvalidObjectiveRef" \
  "TestRunTDPNDSettlementHTTPBillingZeroChargeSettlementContract" \
  "TestRunTDPNDSettlementHTTPSponsorIdentityMappingDistinctAppAndEndUser" \
  "TestRunTDPNDSettlementHTTPSponsorIdentityMappingLegacySubjectFallback"
do
  if ! rg -Fq "$settlement_bridge_smoke_contract" "$phase6_settlement_bridge_smoke_script"; then
    echo "settlement bridge smoke script must include expanded regression contract test: $settlement_bridge_smoke_contract"
    exit 1
  fi
done
for live_smoke_validator_governance_path in \
  "/x/vpnvalidator/eligibilities" \
  "/x/vpnvalidator/status-records" \
  "/x/vpngovernance/policies" \
  "/x/vpngovernance/decisions" \
  "/x/vpngovernance/audit-actions"
do
  if ! rg -Fq "$live_smoke_validator_governance_path" "$phase6_settlement_bridge_live_smoke_script"; then
    echo "settlement bridge live-smoke script must explicitly cover validator/governance route: $live_smoke_validator_governance_path"
    exit 1
  fi
done
for live_smoke_unauth_post_route in \
  "/x/vpnbilling/settlements" \
  "/x/vpnrewards/issues" \
  "/x/vpnsponsor/reservations" \
  "/x/vpnslashing/evidence" \
  "/x/vpnvalidator/eligibilities" \
  "/x/vpnvalidator/status-records" \
  "/x/vpngovernance/policies" \
  "/x/vpngovernance/decisions" \
  "/x/vpngovernance/audit-actions"
do
  if ! rg -F "post_expect_status \"\${BASE_URL}${live_smoke_unauth_post_route}\"" "$phase6_settlement_bridge_live_smoke_script" | rg -Fq '"401"'; then
    echo "settlement bridge live-smoke script must explicitly validate unauth POST auth-block coverage marker: $live_smoke_unauth_post_route"
    exit 1
  fi
done
if ! rg -Fq "post_expect_status \"\${BASE_URL}/x/vpnvalidator/eligibilities\"" "$phase6_settlement_bridge_live_smoke_script" \
  || ! rg -Fq "post_expect_status \"\${BASE_URL}/x/vpngovernance/policies\"" "$phase6_settlement_bridge_live_smoke_script"; then
  echo "settlement bridge live-smoke script must explicitly validate validator and governance POST auth contract"
  exit 1
fi
if ! rg -Fq "PreviewEpochSelection" "$phase6_settlement_bridge_live_smoke_script"; then
  echo "settlement bridge live-smoke script must explicitly validate validator preview query coverage"
  exit 1
fi
if ! rg -Fq "codes.Unauthenticated" "$phase6_settlement_bridge_live_smoke_script"; then
  echo "settlement bridge live-smoke script must explicitly validate unauthenticated validator preview rejection"
  exit 1
fi
if ! rg -Fq "tdpnd-validator-preview-seed" "$phase6_settlement_bridge_live_smoke_script"; then
  echo "settlement bridge live-smoke script must include the validator preview gRPC helper"
  exit 1
fi
for live_smoke_query_marker in \
  "/x/vpnbilling/reservations/bill-res-live-1" \
  "/x/vpnrewards/accruals/reward-live-1" \
  "/x/vpnrewards/distributions/dist:reward-live-1" \
  "/x/vpnsponsor/authorizations/auth:res-live-1" \
  "/x/vpnsponsor/delegations/res-live-1" \
  "/x/vpnslashing/evidence/ev-live-1" \
  "/x/vpnslashing/penalties/pen-live-1" \
  "/x/vpnvalidator/eligibilities/val-live-1" \
  "/x/vpnvalidator/status-records/status-live-1" \
  "/x/vpngovernance/policies/policy-live-1" \
  "/x/vpngovernance/decisions/decision-live-1" \
  "/x/vpngovernance/audit-actions/action-live-1" \
  "/x/vpnbilling/reservations\" \"200\"" \
  "/x/vpnrewards/accruals\" \"200\"" \
  "/x/vpnrewards/distributions\" \"200\"" \
  "/x/vpnsponsor/authorizations\" \"200\"" \
  "/x/vpnsponsor/delegations\" \"200\"" \
  "/x/vpnslashing/evidence\" \"200\"" \
  "/x/vpnslashing/penalties\" \"200\"" \
  "/x/vpnvalidator/eligibilities\" \"200\"" \
  "/x/vpnvalidator/status-records\" \"200\"" \
  "/x/vpngovernance/policies\" \"200\"" \
  "/x/vpngovernance/decisions\" \"200\"" \
  "/x/vpngovernance/audit-actions\" \"200\""
do
  if ! rg -Fq "$live_smoke_query_marker" "$phase6_settlement_bridge_live_smoke_script"; then
    echo "settlement bridge live-smoke script must explicitly validate GET query/list contract marker: $live_smoke_query_marker"
    exit 1
  fi
done
for grpc_auth_rpc_contract in \
  "tdpn.vpnbilling.v1.Query/ListCreditReservations" \
  "tdpn.vpnbilling.v1.Query/ListSettlementRecords" \
  "tdpn.vpnrewards.v1.Query/ListRewardAccruals" \
  "tdpn.vpnrewards.v1.Query/ListDistributionRecords" \
  "tdpn.vpnslashing.v1.Query/ListSlashEvidence" \
  "tdpn.vpnslashing.v1.Query/ListPenaltyDecisions" \
  "tdpn.vpnsponsor.v1.Query/ListSponsorAuthorizations" \
  "tdpn.vpnsponsor.v1.Query/ListDelegatedSessionCredits" \
  "tdpn.vpnvalidator.v1.Query/ListValidatorEligibilities" \
  "tdpn.vpnvalidator.v1.Query/ListValidatorStatusRecords" \
  "tdpn.vpnvalidator.v1.Query/PreviewEpochSelection" \
  "tdpn.vpngovernance.v1.Query/ListGovernancePolicies" \
  "tdpn.vpngovernance.v1.Query/ListGovernanceDecisions" \
  "tdpn.vpngovernance.v1.Query/ListGovernanceAuditActions"
do
  if ! rg -Fq "$grpc_auth_rpc_contract" "$phase6_grpc_auth_live_smoke_script"; then
    echo "phase6 grpc auth live-smoke script must include module auth contract RPC: $grpc_auth_rpc_contract"
    exit 1
  fi
done
if ! rg -Fq "MODULE_QUERY_CHECKS" "$phase6_grpc_auth_live_smoke_script"; then
  echo "phase6 grpc auth live-smoke script must use a multi-module query contract matrix"
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
if ! rg -Fq "[ci-phase6-cosmos-l1] same-path canonical summary path" "$phase6_integration_script"; then
  echo "phase6 ci integration script must include same-path canonical contract coverage marker"
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
if ! rg -Fq "require-tdpnd-comet-runtime-smoke-ok" "$phase6_run_script"; then
  echo "phase6 run wrapper must forward/handle tdpnd_comet_runtime_smoke requirement"
  exit 1
fi
if ! rg -Fq "require-module-tx-surface-ok" "$phase6_run_script"; then
  echo "phase6 run wrapper must forward/handle module_tx_surface requirement"
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
if ! rg -Fq "tdpnd_comet_runtime_smoke" "$phase6_check_script"; then
  echo "phase6 check wrapper must include tdpnd_comet_runtime_smoke readiness signal"
  exit 1
fi
if ! rg -Fq "tdpnd_comet_runtime_smoke" "$phase6_ci_script"; then
  echo "phase6 CI gate must include tdpnd_comet_runtime_smoke stage"
  exit 1
fi
if ! rg -Fq -- "--run-tdpnd-comet-runtime-smoke" "$phase6_ci_script"; then
  echo "phase6 CI gate must expose tdpnd_comet_runtime_smoke toggle"
  exit 1
fi
if ! rg -Fq "CI_PHASE6_COSMOS_L1_RUN_TDPND_COMET_RUNTIME_SMOKE" "$phase6_ci_script"; then
  echo "phase6 CI gate must expose comet runtime smoke env toggle"
  exit 1
fi
if ! rg -Fq "module_tx_surface" "$phase6_check_script"; then
  echo "phase6 check wrapper must include module_tx_surface readiness signal"
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
if ! rg -Fq "require-tdpnd-comet-runtime-smoke-ok" "$phase6_handoff_run_script"; then
  echo "phase6 handoff-run wrapper must forward/handle tdpnd_comet_runtime_smoke requirement"
  exit 1
fi
if ! rg -Fq "require-module-tx-surface-ok" "$phase6_handoff_run_script"; then
  echo "phase6 handoff-run wrapper must forward/handle module_tx_surface requirement"
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
if ! rg -Fq "module_tx_surface" "$phase6_handoff_check_script"; then
  echo "phase6 handoff-check wrapper must include module_tx_surface readiness signal"
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
if ! rg -Fq "tdpnd_comet_runtime_smoke" "$phase6_integration_script"; then
  echo "phase6 CI integration must validate tdpnd_comet_runtime_smoke stage"
  exit 1
fi
if ! rg -Fq -- "--run-tdpnd-comet-runtime-smoke" "$phase6_integration_script"; then
  echo "phase6 CI integration must validate comet runtime smoke CLI toggle"
  exit 1
fi
if ! rg -Fq "require-tdpnd-grpc-auth-live-smoke-ok" "$phase6_run_integration_script" \
  && ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$phase6_run_integration_script"; then
  echo "phase6 run integration must validate tdpnd_grpc_auth_live_smoke requirement forwarding/handling"
  exit 1
fi
if ! rg -Fq "require-tdpnd-comet-runtime-smoke-ok" "$phase6_run_integration_script" \
  && ! rg -Fq "tdpnd_comet_runtime_smoke" "$phase6_run_integration_script"; then
  echo "phase6 run integration must validate tdpnd_comet_runtime_smoke requirement forwarding/handling"
  exit 1
fi
if ! rg -Fq "require-module-tx-surface-ok" "$phase6_run_integration_script" \
  && ! rg -Fq "module_tx_surface" "$phase6_run_integration_script"; then
  echo "phase6 run integration must validate module_tx_surface requirement forwarding/handling"
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
if ! rg -Fq "tdpnd_comet_runtime_smoke" "$phase6_check_integration_script"; then
  echo "phase6 check integration must validate tdpnd_comet_runtime_smoke readiness signal"
  exit 1
fi
if ! rg -Fq "module_tx_surface" "$phase6_check_integration_script"; then
  echo "phase6 check integration must validate module_tx_surface readiness signal"
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
if ! rg -Fq "require-tdpnd-comet-runtime-smoke-ok" "$phase6_handoff_run_integration_script" \
  && ! rg -Fq "tdpnd_comet_runtime_smoke" "$phase6_handoff_run_integration_script"; then
  echo "phase6 handoff-run integration must validate tdpnd_comet_runtime_smoke requirement forwarding/handling"
  exit 1
fi
if ! rg -Fq "require-module-tx-surface-ok" "$phase6_handoff_run_integration_script" \
  && ! rg -Fq "module_tx_surface" "$phase6_handoff_run_integration_script"; then
  echo "phase6 handoff-run integration must validate module_tx_surface requirement forwarding/handling"
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
if ! rg -Fq "tdpnd_comet_runtime_smoke" "$phase6_handoff_check_integration_script"; then
  echo "phase6 handoff-check integration must validate tdpnd_comet_runtime_smoke readiness signal"
  exit 1
fi
if ! rg -Fq "module_tx_surface" "$phase6_handoff_check_integration_script"; then
  echo "phase6 handoff-check integration must validate module_tx_surface readiness signal"
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
if ! rg -Fq "[phase6-cosmos-l1-summary-report] canonical-same-path pass path" "$phase6_summary_report_integration_script"; then
  echo "phase6 summary report integration script must include same-path canonical contract coverage marker"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_check_summary" "$phase7_check_script"; then
  echo "phase7 check wrapper must emit phase7 check summary schema id"
  exit 1
fi
if ! rg -Fq "module_tx_surface" "$phase7_check_script"; then
  echo "phase7 check wrapper must include module_tx_surface readiness signal"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke" "$phase7_check_script"; then
  echo "phase7 check wrapper must include tdpnd_grpc_auth_live_smoke readiness signal"
  exit 1
fi
if ! rg -qi "dual[-_ ]write[-_ ]parity" "$phase7_check_script"; then
  echo "phase7 check wrapper must include dual-write parity confirmation signal"
  exit 1
fi
if ! rg -qi "rollback(_path)?(_ready)?(_ok)?|rollback path" "$phase7_check_script"; then
  echo "phase7 check wrapper must include rollback-path readiness signal"
  exit 1
fi
if ! rg -qi "operator(_approval)?(_gate)?(_ok)?|approval gate|require-operator-approval" "$phase7_check_script"; then
  echo "phase7 check wrapper must include optional operator approval gate signal/toggle"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_check.sh" "$phase7_run_script"; then
  echo "phase7 run wrapper must invoke phase7 mainnet cutover check wrapper"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_check_summary" "$phase7_run_script"; then
  echo "phase7 run wrapper must validate phase7 check summary schema id"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_summary_report" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must emit phase7 summary report schema id"
  exit 1
fi
check_phase7_summary_comet_signal_surface "$phase7_summary_report_script" "phase7 summary report helper"
if ! rg -Fq "phase7_mainnet_cutover_check_summary" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must reference phase7 check summary schema"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_run_summary" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must reference phase7 run summary schema"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_check_summary" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must reference phase7 handoff-check summary schema"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_run_summary" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must reference phase7 handoff-run summary schema"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_check_summary.json" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must probe canonical phase7 check summary artifact"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_run_summary.json" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must probe canonical phase7 run summary artifact"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_check_summary.json" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must probe canonical phase7 handoff-check summary artifact"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_run_summary.json" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must probe canonical phase7 handoff-run summary artifact"
  exit 1
fi
if ! rg -Fq "PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must emit canonical summary artifact metadata/logging"
  exit 1
fi
if ! rg -Fq -- "--handoff-check-summary-json" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must accept handoff-check summary input"
  exit 1
fi
if ! rg -Fq -- "--handoff-run-summary-json" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must accept handoff-run summary input"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_check_" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must include fallback discovery for timestamped handoff-check summaries"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_run_" "$phase7_summary_report_script"; then
  echo "phase7 summary report helper must include fallback discovery for timestamped handoff-run summaries"
  exit 1
fi
check_phase7_comet_signal_surface "$phase7_check_integration_script" "phase7 check integration script"
check_phase7_comet_signal_surface "$phase7_run_integration_script" "phase7 run integration script"
check_phase7_comet_signal_surface "$phase7_handoff_check_integration_script" "phase7 handoff-check integration script"
check_phase7_comet_signal_surface "$phase7_handoff_run_integration_script" "phase7 handoff-run integration script"
check_phase7_comet_forwarding_surface "$phase7_handoff_run_integration_script" "phase7 handoff-run integration script"
check_phase7_mainnet_activation_gate_signal_surface "$phase7_run_script" "phase7 run wrapper script"
check_phase7_mainnet_activation_gate_signal_surface "$phase7_run_integration_script" "phase7 run integration script"
check_phase7_mainnet_activation_gate_signal_surface "$phase7_handoff_check_script" "phase7 handoff-check wrapper script"
check_phase7_mainnet_activation_gate_signal_surface "$phase7_handoff_check_integration_script" "phase7 handoff-check integration script"
check_phase7_mainnet_activation_gate_signal_surface "$phase7_handoff_run_script" "phase7 handoff-run wrapper script"
check_phase7_mainnet_activation_gate_signal_surface "$phase7_handoff_run_integration_script" "phase7 handoff-run integration script"
check_phase7_mainnet_activation_gate_requirement_surface "$phase7_handoff_check_script" "phase7 handoff-check wrapper script"
check_phase7_mainnet_activation_gate_requirement_surface "$phase7_handoff_check_integration_script" "phase7 handoff-check integration script"
check_phase7_mainnet_activation_gate_requirement_surface "$phase7_handoff_run_script" "phase7 handoff-run wrapper script"
check_phase7_mainnet_activation_gate_requirement_surface "$phase7_handoff_run_integration_script" "phase7 handoff-run integration script"
if ! rg -Fq "phase7_mainnet_cutover_check.sh" "$phase7_check_integration_script"; then
  echo "phase7 check integration script must execute phase7 check wrapper"
  exit 1
fi
if ! rg -Fq "module_tx_surface_ok" "$phase7_check_integration_script"; then
  echo "phase7 check integration script must validate module_tx_surface_ok signal"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke_ok" "$phase7_check_integration_script"; then
  echo "phase7 check integration script must validate tdpnd_grpc_auth_live_smoke_ok signal"
  exit 1
fi
if ! rg -qi "dual[-_ ]write[-_ ]parity(_ok)?" "$phase7_check_integration_script"; then
  echo "phase7 check integration script must validate dual-write parity signal"
  exit 1
fi
if ! rg -qi "rollback(_path)?(_ready)?(_ok)?|rollback path" "$phase7_check_integration_script"; then
  echo "phase7 check integration script must validate rollback-path readiness signal"
  exit 1
fi
if ! rg -qi "operator(_approval)?(_gate)?(_ok)?|approval gate|require-operator-approval" "$phase7_check_integration_script"; then
  echo "phase7 check integration script must validate optional operator approval gate signal/toggle"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_run.sh" "$phase7_run_integration_script"; then
  echo "phase7 run integration script must execute phase7 run wrapper"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_check.sh" "$phase7_run_integration_script"; then
  echo "phase7 run integration script must validate run->check invocation"
  exit 1
fi
if ! rg -Fq "module_tx_surface_ok" "$phase7_run_integration_script"; then
  echo "phase7 run integration script must validate module_tx_surface_ok signal"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke_ok" "$phase7_run_integration_script"; then
  echo "phase7 run integration script must validate tdpnd_grpc_auth_live_smoke_ok signal"
  exit 1
fi
if ! rg -qi "dual[-_ ]write[-_ ]parity(_ok)?" "$phase7_run_integration_script"; then
  echo "phase7 run integration script must validate dual-write parity signal"
  exit 1
fi
if ! rg -qi "rollback(_path)?(_ready)?(_ok)?|rollback path" "$phase7_run_integration_script"; then
  echo "phase7 run integration script must validate rollback-path readiness signal"
  exit 1
fi
if ! rg -qi "operator(_approval)?(_gate)?(_ok)?|approval gate|require-operator-approval" "$phase7_run_integration_script"; then
  echo "phase7 run integration script must validate optional operator approval gate signal/toggle"
  exit 1
fi
if ! rg -Fq "ci_phase7_mainnet_cutover_summary" "$phase7_ci_script"; then
  echo "phase7 ci wrapper must emit phase7 ci summary schema id"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_check.sh" "$phase7_ci_script"; then
  echo "phase7 ci wrapper must wire phase7 check integration stage script"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_run.sh" "$phase7_ci_script"; then
  echo "phase7 ci wrapper must wire phase7 run integration stage script"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_handoff_check.sh" "$phase7_ci_script"; then
  echo "phase7 ci wrapper must wire phase7 handoff check integration stage script"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_handoff_run.sh" "$phase7_ci_script"; then
  echo "phase7 ci wrapper must wire phase7 handoff run integration stage script"
  exit 1
fi
if ! rg -Fq "integration_phase7_mainnet_cutover_summary_report.sh" "$phase7_ci_script"; then
  echo "phase7 ci wrapper must wire phase7 summary report integration stage script"
  exit 1
fi
for phase7_ci_stage_id in \
  "phase7_mainnet_cutover_check" \
  "phase7_mainnet_cutover_run" \
  "phase7_mainnet_cutover_handoff_check" \
  "phase7_mainnet_cutover_handoff_run" \
  "phase7_mainnet_cutover_summary_report"
do
  if ! rg -Fq "$phase7_ci_stage_id" "$phase7_ci_script"; then
    echo "phase7 ci wrapper must include stage id: $phase7_ci_stage_id"
    exit 1
  fi
done
if ! rg -Fq "ci_phase7_mainnet_cutover.sh" "$phase7_ci_integration_script"; then
  echo "phase7 ci integration script must execute phase7 ci wrapper"
  exit 1
fi
if ! rg -q "assert_stage_order.*STAGE_IDS" "$phase7_ci_integration_script"; then
  echo "phase7 ci integration script must validate deterministic stage ordering"
  exit 1
fi
if ! rg -qi "dry[-_ ]run" "$phase7_ci_integration_script"; then
  echo "phase7 ci integration script must validate dry-run semantics"
  exit 1
fi
if ! rg -qi "toggle" "$phase7_ci_integration_script"; then
  echo "phase7 ci integration script must validate toggle semantics"
  exit 1
fi
if ! rg -qi "first[-_ ]failure|failure propagation" "$phase7_ci_integration_script"; then
  echo "phase7 ci integration script must validate failure propagation semantics"
  exit 1
fi
for phase7_ci_integration_stage in \
  "phase7_mainnet_cutover_check" \
  "phase7_mainnet_cutover_run" \
  "phase7_mainnet_cutover_handoff_check" \
  "phase7_mainnet_cutover_handoff_run" \
  "phase7_mainnet_cutover_summary_report"
do
  if ! rg -Fq "$phase7_ci_integration_stage" "$phase7_ci_integration_script"; then
    echo "phase7 ci integration script must validate stage wiring for: $phase7_ci_integration_stage"
    exit 1
  fi
done
if ! rg -Fq "phase7_mainnet_cutover_summary_report.sh" "$phase7_summary_report_integration_script"; then
  echo "phase7 summary report integration script must execute phase7 summary report helper"
  exit 1
fi
check_phase7_summary_comet_signal_surface "$phase7_summary_report_integration_script" "phase7 summary report integration script"
if ! rg -Fq "phase7_mainnet_cutover_check_summary.json" "$phase7_summary_report_integration_script"; then
  echo "phase7 summary report integration script must validate canonical phase7 check summary artifact wiring"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_run_summary.json" "$phase7_summary_report_integration_script"; then
  echo "phase7 summary report integration script must validate canonical phase7 run summary artifact wiring"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_check_summary.json" "$phase7_summary_report_integration_script"; then
  echo "phase7 summary report integration script must validate canonical phase7 handoff-check summary artifact wiring"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_handoff_run_summary.json" "$phase7_summary_report_integration_script"; then
  echo "phase7 summary report integration script must validate canonical phase7 handoff-run summary artifact wiring"
  exit 1
fi
if ! rg -Fq "module_tx_surface_ok" "$phase7_summary_report_integration_script"; then
  echo "phase7 summary report integration script must validate module_tx_surface_ok summary signal"
  exit 1
fi
if ! rg -Fq "tdpnd_grpc_auth_live_smoke_ok" "$phase7_summary_report_integration_script"; then
  echo "phase7 summary report integration script must validate tdpnd_grpc_auth_live_smoke_ok summary signal"
  exit 1
fi
check_phase7_summary_comet_signal_surface "$phase7_summary_report_integration_script" "phase7 summary report integration script"
if ! rg -qi "dual[-_ ]write[-_ ]parity(_ok)?" "$phase7_summary_report_integration_script"; then
  echo "phase7 summary report integration script must validate dual-write parity summary signal"
  exit 1
fi
if ! rg -qi "rollback(_path)?(_ready)?(_ok)?|rollback path" "$phase7_summary_report_integration_script"; then
  echo "phase7 summary report integration script must validate rollback-path readiness summary signal"
  exit 1
fi
if ! rg -qi "operator(_approval)?(_gate)?(_ok)?|approval gate|require-operator-approval" "$phase7_summary_report_integration_script"; then
  echo "phase7 summary report integration script must validate optional operator approval gate summary signal/toggle"
  exit 1
fi
if ! rg -Fq "canonical_summary_json" "$phase7_summary_report_integration_script"; then
  echo "phase7 summary report integration script must validate canonical summary artifact wiring"
  exit 1
fi
check_mainnet_activation_gate_surface "$roadmap_script" "roadmap progress report helper"
check_mainnet_activation_gate_surface "$roadmap_integration_script" "roadmap progress report integration script"
if ! rg -Fq '.blockchain_track.mainnet_activation_gate.available == true' "$roadmap_integration_script"; then
  echo "roadmap progress report integration script must validate the available mainnet activation gate path"
  exit 1
fi
if ! rg -Fq '.blockchain_track.mainnet_activation_gate.status == "missing"' "$roadmap_integration_script"; then
  echo "roadmap progress report integration script must validate the missing mainnet activation gate path"
  exit 1
fi
if ! rg -Fq '.blockchain_track.mainnet_activation_gate.status == "invalid"' "$roadmap_integration_script"; then
  echo "roadmap progress report integration script must validate the invalid mainnet activation gate path"
  exit 1
fi
if ! rg -Fq "phase7-mainnet-cutover-signal" "$roadmap_script"; then
  echo "roadmap progress report helper must support phase7-signal fallback for mainnet activation gate when dedicated summary is absent"
  exit 1
fi
if ! rg -Fq "blockchain mainnet activation gate phase7 signal fallback path" "$roadmap_integration_script"; then
  echo "roadmap progress report integration script must validate the phase7-signal fallback path for mainnet activation gate"
  exit 1
fi
if ! rg -Fq "blockchain mainnet activation gate phase7 NO-GO signal fallback path" "$roadmap_integration_script"; then
  echo "roadmap progress report integration script must validate the phase7 NO-GO signal fallback path for mainnet activation gate"
  exit 1
fi
if ! rg -Fq '.blockchain_track.mainnet_activation_gate.source_summary_kind == "phase7-mainnet-cutover-signal"' "$roadmap_integration_script"; then
  echo "roadmap progress report integration script must validate phase7-signal source_summary_kind for mainnet activation gate fallback"
  exit 1
fi
for phase7_summary_signal in \
  "cosmos_module_coverage_floor_ok" \
  "cosmos_keeper_coverage_floor_ok" \
  "cosmos_app_coverage_floor_ok" \
  "dual_write_parity_ok"
do
  if ! rg -Fq ".blockchain_track.phase7_mainnet_cutover_summary_report.${phase7_summary_signal}" "$roadmap_script"; then
    echo "roadmap progress report helper must surface phase7 summary signal under blockchain_track.phase7_mainnet_cutover_summary_report: ${phase7_summary_signal}"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.phase7_mainnet_cutover_summary_report.${phase7_summary_signal}" "$roadmap_integration_script"; then
    echo "roadmap progress report integration script must validate phase7 summary signal under blockchain_track.phase7_mainnet_cutover_summary_report: ${phase7_summary_signal}"
    exit 1
  fi
  if ! rg -Fq "Phase-7 mainnet cutover ${phase7_summary_signal}" "$roadmap_script"; then
    echo "roadmap progress report helper markdown summary must print phase7 summary signal line: ${phase7_summary_signal}"
    exit 1
  fi
done
for phase7_summary_runtime_signal in \
  "module_tx_surface_ok" \
  "tdpnd_grpc_live_smoke_ok" \
  "tdpnd_grpc_auth_live_smoke_ok" \
  "tdpnd_comet_runtime_smoke_ok"
do
  if ! rg -Fq ".blockchain_track.phase7_mainnet_cutover_summary_report.${phase7_summary_runtime_signal}" "$roadmap_script"; then
    echo "roadmap progress report helper must surface phase7 summary signal under blockchain_track.phase7_mainnet_cutover_summary_report: ${phase7_summary_runtime_signal}"
    exit 1
  fi
  if ! rg -Fq ".blockchain_track.phase7_mainnet_cutover_summary_report.${phase7_summary_runtime_signal}" "$roadmap_integration_script"; then
    echo "roadmap progress report integration script must validate phase7 summary signal under blockchain_track.phase7_mainnet_cutover_summary_report: ${phase7_summary_runtime_signal}"
    exit 1
  fi
  if ! rg -Fq "Phase-7 mainnet cutover ${phase7_summary_runtime_signal}" "$roadmap_script"; then
    echo "roadmap progress report helper markdown summary must print phase7 summary signal line: ${phase7_summary_runtime_signal}"
    exit 1
  fi
done
if ! rg -Fq "ROADMAP_PROGRESS_LOG_DIR" "$roadmap_script"; then
  echo "roadmap progress report helper must expose ROADMAP_PROGRESS_LOG_DIR log-root override for deterministic isolated runs"
  exit 1
fi
if ! rg -Fq "EASY_NODE_LOG_DIR" "$roadmap_script"; then
  echo "roadmap progress report helper must honor EASY_NODE_LOG_DIR as a default log-root override"
  exit 1
fi
if ! rg -Fq "Mainnet Activation Go/No-Go Metrics Gate" "$bootstrap_validator_doc"; then
  echo "blockchain bootstrap validator plan must document the mainnet activation go/no-go metrics gate"
  exit 1
fi
if ! rg -Fq "Default decision remains **NO-GO**" "$bootstrap_validator_doc"; then
  echo "blockchain bootstrap validator plan must preserve the default NO-GO posture"
  exit 1
fi
if ! rg -Fq "scripts/blockchain_mainnet_activation_metrics.sh" "$bootstrap_validator_doc"; then
  echo "blockchain bootstrap validator plan must document the blockchain_mainnet_activation_metrics helper"
  exit 1
fi
if ! rg -Fq "scripts/integration_blockchain_mainnet_activation_metrics.sh" "$bootstrap_validator_doc"; then
  echo "blockchain bootstrap validator plan must document integration coverage for blockchain_mainnet_activation_metrics"
  exit 1
fi
if ! rg -Fq "scripts/blockchain_fastlane.sh" "$bootstrap_validator_doc"; then
  echo "blockchain bootstrap validator plan must document the blockchain_fastlane helper path"
  exit 1
fi
if ! rg -Fq "scripts/integration_blockchain_fastlane.sh" "$bootstrap_validator_doc"; then
  echo "blockchain bootstrap validator plan must document integration coverage for blockchain_fastlane"
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

if ! rg -Fq "no sidecar chain pivot" "$full_plan"; then
  echo "full execution plan must document Cosmos-first no sidecar chain pivot decision"
  exit 1
fi
if rg -Fq "validator eligibility/governance/reward modules" "$full_plan"; then
  echo "full execution plan must not contain stale three-module phase6 summary wording"
  exit 1
fi
if rg -qi "sidecar recommendation" "$full_plan"; then
  echo "full execution plan should not contain legacy sidecar recommendation wording"
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
if ! rg -Fq "validator/governance routes" "$product_roadmap"; then
  echo "product roadmap must document validator/governance settlement bridge route coverage"
  exit 1
fi
if ! rg -Fq "bearer auth applies to \`POST\` only" "$product_roadmap"; then
  echo "product roadmap must document POST-only settlement bridge auth contract"
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
if ! rg -q -e "--phase6-cosmos-l1-summary-json" -e "phase6_cosmos_l1_[a-z_]*summary_json" "$roadmap_script"; then
  echo "roadmap_progress_report.sh must include phase6-cosmos-l1 summary argument/variable wiring"
  exit 1
fi
if ! rg -Fq "phase6_cosmos_l1_handoff" "$roadmap_script"; then
  echo "roadmap_progress_report.sh must include phase6_cosmos_l1_handoff summary surface"
  exit 1
fi
if ! rg -Fq ".blockchain_track.phase6_cosmos_l1_handoff.module_tx_surface_ok" "$roadmap_script"; then
  echo "roadmap_progress_report.sh must surface phase6 module_tx_surface_ok in output paths"
  exit 1
fi
if ! rg -Fq ".blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_auth_live_smoke_ok" "$roadmap_script"; then
  echo "roadmap_progress_report.sh must surface phase6 tdpnd_grpc_auth_live_smoke_ok in output paths"
  exit 1
fi
if ! rg -Fq ".blockchain_track.phase6_cosmos_l1_handoff.tdpnd_comet_runtime_smoke_ok" "$roadmap_script"; then
  echo "roadmap_progress_report.sh must surface phase6 tdpnd_comet_runtime_smoke_ok in output paths"
  exit 1
fi
if ! rg -Fq ".artifacts.phase6_cosmos_l1_summary_json" "$roadmap_script"; then
  echo "roadmap_progress_report.sh must include phase6 artifact reference field"
  exit 1
fi
if ! rg -q -e "PHASE6_COSMOS_L1_SUMMARY_JSON" -e "--phase6-cosmos-l1-summary-json" "$roadmap_integration_script"; then
  echo "integration_roadmap_progress_report.sh must wire phase6 summary fixture/argument"
  exit 1
fi
if ! rg -Fq ".blockchain_track.phase6_cosmos_l1_handoff" "$roadmap_integration_script"; then
  echo "integration_roadmap_progress_report.sh must validate phase6_cosmos_l1_handoff summary surface"
  exit 1
fi
if ! rg -Fq ".blockchain_track.phase6_cosmos_l1_handoff.module_tx_surface_ok" "$roadmap_integration_script"; then
  echo "integration_roadmap_progress_report.sh must validate phase6 module_tx_surface_ok summary signal"
  exit 1
fi
if ! rg -Fq ".blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_auth_live_smoke_ok" "$roadmap_integration_script"; then
  echo "integration_roadmap_progress_report.sh must validate phase6 tdpnd_grpc_auth_live_smoke_ok summary signal"
  exit 1
fi
if ! rg -Fq ".blockchain_track.phase6_cosmos_l1_handoff.tdpnd_comet_runtime_smoke_ok" "$roadmap_integration_script"; then
  echo "integration_roadmap_progress_report.sh must validate phase6 tdpnd_comet_runtime_smoke_ok summary signal"
  exit 1
fi
if ! rg -Fq ".artifacts.phase6_cosmos_l1_summary_json" "$roadmap_integration_script"; then
  echo "integration_roadmap_progress_report.sh must validate phase6 artifact reference field"
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
for bridge_write_path in \
  "POST /x/vpnvalidator/eligibilities" \
  "POST /x/vpnvalidator/status-records" \
  "POST /x/vpngovernance/policies" \
  "POST /x/vpngovernance/decisions" \
  "POST /x/vpngovernance/audit-actions"
do
  if ! rg -Fq "$bridge_write_path" "$cosmos_runtime_doc"; then
    echo "cosmos settlement runtime guide must document validator/governance bridge write endpoint: $bridge_write_path"
    exit 1
  fi
done
if ! rg -Fq "including validator/governance writes" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document POST-only auth posture including validator/governance writes"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_state_dir_persistence.sh" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document state-dir persistence integration script"
  exit 1
fi
if ! rg -Fq "integration_cosmos_grpc_app_roundtrip.sh" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document grpc app roundtrip integration script"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_grpc_auth_live_smoke.sh" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document grpc auth live-smoke integration script"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document settlement bridge live-smoke integration script"
  exit 1
fi
if ! rg -Fq "PreviewEpochSelection" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document validator preview epoch-selection coverage"
  exit 1
fi
if ! rg -Fq "billing/rewards/slashing/sponsor/validator/governance \`Msg\`/\`Query\` contracts" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document six-module Msg+Query grpc app roundtrip posture"
  exit 1
fi
if ! rg -Fq "cosmos_app_coverage_floor" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document cosmos_app_coverage_floor phase6 contracts stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_app_coverage_floor.sh" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document cosmos_app_coverage_floor integration script"
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
if ! rg -Fq "settlement_dual_asset_parity" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document settlement_dual_asset_parity phase5 stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_settlement_dual_asset_parity.sh" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document settlement_dual_asset_parity integration script"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity_ok" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document settlement_dual_asset_parity_ok summary signal posture"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document issuer_sponsor_api_live_smoke phase5 stage"
  exit 1
fi
if ! rg -Fq "integration_issuer_sponsor_api_live_smoke.sh" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document issuer_sponsor_api_live_smoke integration script"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document issuer_admin_blockchain_handlers_coverage phase5 stage"
  exit 1
fi
if ! rg -Fq "integration_issuer_admin_blockchain_handlers_coverage_floor.sh" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document issuer_admin_blockchain_handlers_coverage integration script"
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
for bridge_write_path in \
  "POST /x/vpnvalidator/eligibilities" \
  "POST /x/vpnvalidator/status-records" \
  "POST /x/vpngovernance/policies" \
  "POST /x/vpngovernance/decisions" \
  "POST /x/vpngovernance/audit-actions"
do
  if ! rg -Fq "$bridge_write_path" "$chain_readme"; then
    echo "chain README must document validator/governance bridge write endpoint: $bridge_write_path"
    exit 1
  fi
done
if ! rg -Fq "including validator/governance writes" "$chain_readme"; then
  echo "chain README must document POST-only auth posture including validator/governance writes"
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
if ! rg -Fq "tdpnd_comet_runtime_smoke" "$chain_readme"; then
  echo "chain README must document phase6 tdpnd_comet_runtime_smoke stage"
  exit 1
fi
if ! rg -Fq -- "--run-tdpnd-comet-runtime-smoke" "$chain_readme"; then
  echo "chain README must document phase6 comet runtime smoke CLI toggle"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_comet_runtime_smoke.sh" "$chain_readme"; then
  echo "chain README must document comet runtime smoke script"
  exit 1
fi
if ! rg -Fq "integration_cosmos_tdpnd_grpc_auth_live_smoke.sh" "$chain_readme"; then
  echo "chain README must document tdpnd gRPC auth live-smoke script"
  exit 1
fi
if ! rg -Fq "integration_cosmos_grpc_app_roundtrip.sh" "$chain_readme"; then
  echo "chain README must document grpc app roundtrip integration script"
  exit 1
fi
if ! rg -Fq "billing/rewards/slashing/sponsor/validator/governance \`Msg\`/\`Query\` contracts" "$chain_readme"; then
  echo "chain README must document six-module Msg+Query grpc app roundtrip posture"
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
if ! rg -Fq "issuer_sponsor_api_live_smoke" "$chain_readme"; then
  echo "chain README must document issuer_sponsor_api_live_smoke phase5 stage"
  exit 1
fi
if ! rg -Fq "integration_issuer_sponsor_api_live_smoke.sh" "$chain_readme"; then
  echo "chain README must document issuer_sponsor_api_live_smoke integration script"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage" "$chain_readme"; then
  echo "chain README must document issuer_admin_blockchain_handlers_coverage phase5 stage"
  exit 1
fi
if ! rg -Fq "integration_issuer_admin_blockchain_handlers_coverage_floor.sh" "$chain_readme"; then
  echo "chain README must document issuer_admin_blockchain_handlers_coverage integration script"
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
for module_name in vpnvalidator vpngovernance; do
  if ! rg -Fq "$module_name" "$chain_readme"; then
    echo "chain README must reference ${module_name} module presence"
    exit 1
  fi
  if ! rg -Fq "$module_name" "$full_plan"; then
    echo "full execution plan must reference ${module_name} module presence"
    exit 1
  fi
  if ! rg -Fq "$module_name" "$product_roadmap"; then
    echo "product roadmap must reference ${module_name} module presence"
    exit 1
  fi
done
if ! rg -Fq "append-only admin audit actions" "$full_plan"; then
  echo "full execution plan must document append-only governance admin audit actions posture"
  exit 1
fi
if ! rg -Fq "deterministic epoch selection helpers" "$full_plan"; then
  echo "full execution plan must document deterministic validator epoch selection posture"
  exit 1
fi
if ! rg -Fq "RecordAuditAction" "$full_plan" \
  || ! rg -Fq "ListGovernanceAuditActions" "$full_plan"; then
  echo "full execution plan must document governance audit-action RPC/query surfaces"
  exit 1
fi
if ! rg -Fq "PreviewEpochSelection" "$full_plan"; then
  echo "full execution plan must document validator preview epoch-selection query surface"
  exit 1
fi
if ! rg -Fq "append-only governance admin audit actions" "$product_roadmap"; then
  echo "product roadmap must document append-only governance admin audit action posture"
  exit 1
fi
if ! rg -Fq "deterministic epoch selection helpers" "$product_roadmap"; then
  echo "product roadmap must document deterministic validator epoch selection posture"
  exit 1
fi
if ! rg -Fq "RecordAuditAction" "$product_roadmap" \
  || ! rg -Fq "ListGovernanceAuditActions" "$product_roadmap"; then
  echo "product roadmap must document governance audit-action RPC/query surfaces"
  exit 1
fi
if ! rg -Fq "PreviewEpochSelection" "$product_roadmap"; then
  echo "product roadmap must document validator preview epoch-selection query surface"
  exit 1
fi
if ! rg -Fq "x/vpngovernance" "$bootstrap_validator_doc" \
  || ! rg -Fq "append-only admin audit actions" "$bootstrap_validator_doc"; then
  echo "bootstrap validator plan must document vpngovernance append-only audit-action posture"
  exit 1
fi
if ! rg -Fq "x/vpnvalidator" "$bootstrap_validator_doc" \
  || ! rg -Fq "deterministic epoch selection helpers" "$bootstrap_validator_doc"; then
  echo "bootstrap validator plan must document vpnvalidator deterministic epoch-selection posture"
  exit 1
fi
if ! rg -Fq "append-only admin audit actions" "$chain_readme"; then
  echo "chain README must document vpngovernance append-only audit-action capability"
  exit 1
fi
if ! rg -Fq "deterministic epoch-selection helper logic" "$chain_readme"; then
  echo "chain README must document vpnvalidator deterministic epoch-selection capability"
  exit 1
fi
if ! rg -Fq "RecordAuditAction" "$chain_readme" \
  || ! rg -Fq "ListGovernanceAuditActions" "$chain_readme"; then
  echo "chain README must document governance audit-action RPC/query surfaces"
  exit 1
fi
if ! rg -Fq "PreviewEpochSelection" "$chain_readme"; then
  echo "chain README must document validator preview epoch-selection query surface"
  exit 1
fi
if ! rg -Fq "RecordAuditAction" "$cosmos_runtime_doc" \
  || ! rg -Fq "PreviewEpochSelection" "$cosmos_runtime_doc"; then
  echo "cosmos settlement runtime guide must document governance/validator bootstrap gRPC highlights"
  exit 1
fi
if ! rg -Fq "vpnvalidator.json" "$chain_scaffold_file"; then
  echo "chain scaffold must persist vpnvalidator state-dir file store"
  exit 1
fi
if ! rg -Fq "vpngovernance.json" "$chain_scaffold_file"; then
  echo "chain scaffold must persist vpngovernance state-dir file store"
  exit 1
fi
if ! rg -Fq "ValidatorModule" "$chain_scaffold_file"; then
  echo "chain scaffold must include validator module wiring in scaffold struct"
  exit 1
fi
if ! rg -Fq "GovernanceModule" "$chain_scaffold_file"; then
  echo "chain scaffold must include governance module wiring in scaffold struct"
  exit 1
fi
if ! rg -Fq "validatormodule.NewAppModule" "$chain_scaffold_file"; then
  echo "chain scaffold must instantiate vpnvalidator module app wiring"
  exit 1
fi
if ! rg -Fq "governancemodule.NewAppModule" "$chain_scaffold_file"; then
  echo "chain scaffold must instantiate vpngovernance module app wiring"
  exit 1
fi
if ! rg -Fq "vpnvalidatorpb.RegisterMsgServer" "$chain_grpc_registry_file"; then
  echo "chain grpc registry must wire vpnvalidator msg service registration"
  exit 1
fi
if ! rg -Fq "vpnvalidatorpb.RegisterQueryServer" "$chain_grpc_registry_file"; then
  echo "chain grpc registry must wire vpnvalidator query service registration"
  exit 1
fi
if ! rg -Fq "vpngovernancepb.RegisterMsgServer" "$chain_grpc_registry_file"; then
  echo "chain grpc registry must wire vpngovernance msg service registration"
  exit 1
fi
if ! rg -Fq "vpngovernancepb.RegisterQueryServer" "$chain_grpc_registry_file"; then
  echo "chain grpc registry must wire vpngovernance query service registration"
  exit 1
fi

if ! rg -Fq "GET /x/vpnbilling/reservations[/{reservation_id}]" "$settlement_mapping_doc"; then
  echo "settlement bridge mapping must document list/by-id GET query mapping"
  exit 1
fi
for new_bridge_get_path in \
  "GET /x/vpnvalidator/eligibilities[/{validator_id}]" \
  "GET /x/vpnvalidator/status-records[/{status_id}]" \
  "GET /x/vpngovernance/policies[/{policy_id}]" \
  "GET /x/vpngovernance/decisions[/{decision_id}]" \
  "GET /x/vpngovernance/audit-actions[/{action_id}]"
do
  if ! rg -Fq "$new_bridge_get_path" "$settlement_mapping_doc"; then
    echo "settlement bridge mapping must document validator/governance GET contract path: $new_bridge_get_path"
    exit 1
  fi
done
for new_bridge_post_path in \
  "POST /x/vpnvalidator/eligibilities" \
  "POST /x/vpnvalidator/status-records" \
  "POST /x/vpngovernance/policies" \
  "POST /x/vpngovernance/decisions" \
  "POST /x/vpngovernance/audit-actions"
do
  if ! rg -Fq "$new_bridge_post_path" "$settlement_mapping_doc"; then
    echo "settlement bridge mapping must document validator/governance POST contract path: $new_bridge_post_path"
    exit 1
  fi
done
if ! rg -Fq "including validator/governance write routes" "$settlement_mapping_doc"; then
  echo "settlement bridge mapping must document POST-only auth posture including validator/governance writes"
  exit 1
fi
for bridge_route in \
  "/x/vpnvalidator/eligibilities" \
  "/x/vpnvalidator/status-records" \
  "/x/vpngovernance/policies" \
  "/x/vpngovernance/decisions" \
  "/x/vpngovernance/audit-actions"
do
  if ! rg -Fq "$bridge_route" "$chain_settlement_bridge_file"; then
    echo "settlement bridge runtime must wire validator/governance route: $bridge_route"
    exit 1
  fi
  if ! rg -Fq "$bridge_route" "$cosmos_runtime_doc"; then
    echo "cosmos runtime guide must document validator/governance route: $bridge_route"
    exit 1
  fi
  if ! rg -Fq "$bridge_route" "$chain_readme"; then
    echo "chain README must document validator/governance route: $bridge_route"
    exit 1
  fi
done
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
if ! rg -Fq "settlement_dual_asset_parity" "$phase5_ci_script"; then
  echo "phase5 ci script must include settlement_dual_asset_parity stage"
  exit 1
fi
if ! rg -Fq "integration_cosmos_settlement_dual_asset_parity.sh" "$phase5_ci_script"; then
  echo "phase5 ci script must wire integration_cosmos_settlement_dual_asset_parity.sh"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke" "$phase5_ci_script"; then
  echo "phase5 ci script must include issuer_sponsor_api_live_smoke stage"
  exit 1
fi
if ! rg -Fq "integration_issuer_sponsor_api_live_smoke.sh" "$phase5_ci_script"; then
  echo "phase5 ci script must wire integration_issuer_sponsor_api_live_smoke.sh"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage" "$phase5_ci_script"; then
  echo "phase5 ci script must include issuer_admin_blockchain_handlers_coverage stage"
  exit 1
fi
if ! rg -Fq "integration_issuer_admin_blockchain_handlers_coverage_floor.sh" "$phase5_ci_script"; then
  echo "phase5 ci script must wire integration_issuer_admin_blockchain_handlers_coverage_floor.sh"
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
if [[ ! -f "$ROOT_DIR/scripts/integration_cosmos_settlement_dual_asset_parity.sh" ]]; then
  echo "missing required script: scripts/integration_cosmos_settlement_dual_asset_parity.sh"
  exit 1
fi
if [[ ! -f "$ROOT_DIR/scripts/integration_issuer_sponsor_api_live_smoke.sh" ]]; then
  echo "missing required script: scripts/integration_issuer_sponsor_api_live_smoke.sh"
  exit 1
fi
if [[ ! -f "$ROOT_DIR/$phase5_issuer_admin_blockchain_handlers_coverage_script" ]]; then
  echo "missing required script: $phase5_issuer_admin_blockchain_handlers_coverage_script"
  exit 1
fi
if ! rg -Fq "[issuer-sponsor-live-smoke] payment-proof happy path token issuance" "$ROOT_DIR/scripts/integration_issuer_sponsor_api_live_smoke.sh"; then
  echo "issuer sponsor live-smoke integration must include stable marker for payment-proof happy path token issuance"
  exit 1
fi
if ! rg -Fq "[issuer-sponsor-live-smoke] payment-proof negative path invalid proof (missing payment_proof)" "$ROOT_DIR/scripts/integration_issuer_sponsor_api_live_smoke.sh"; then
  echo "issuer sponsor live-smoke integration must include stable marker for payment-proof negative path missing payment_proof"
  exit 1
fi
if ! rg -Fq "[issuer-sponsor-live-smoke] payment-proof negative path invalid proof (mismatched sponsor)" "$ROOT_DIR/scripts/integration_issuer_sponsor_api_live_smoke.sh"; then
  echo "issuer sponsor live-smoke integration must include stable marker for payment-proof negative path mismatched sponsor"
  exit 1
fi
if ! rg -Fq "[issuer-sponsor-live-smoke] payment-proof negative path invalid proof (mismatched subject)" "$ROOT_DIR/scripts/integration_issuer_sponsor_api_live_smoke.sh"; then
  echo "issuer sponsor live-smoke integration must include stable marker for payment-proof negative path mismatched subject"
  exit 1
fi
if ! rg -Fq "[issuer-sponsor-live-smoke] payment-proof negative path invalid proof (mismatched session)" "$ROOT_DIR/scripts/integration_issuer_sponsor_api_live_smoke.sh"; then
  echo "issuer sponsor live-smoke integration must include stable marker for payment-proof negative path mismatched session"
  exit 1
fi
if ! rg -Fq "[issuer-sponsor-live-smoke] payment-proof negative path invalid proof (unknown reservation)" "$ROOT_DIR/scripts/integration_issuer_sponsor_api_live_smoke.sh"; then
  echo "issuer sponsor live-smoke integration must include stable marker for payment-proof negative path invalid proof unknown-reservation coverage"
  exit 1
fi
if ! rg -Fq "[issuer-sponsor-live-smoke] payment-proof negative path duplicate proof replay" "$ROOT_DIR/scripts/integration_issuer_sponsor_api_live_smoke.sh"; then
  echo "issuer sponsor live-smoke integration must include stable marker for payment-proof negative path duplicate proof replay"
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
if ! rg -Fq "settlement_dual_asset_parity" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate settlement_dual_asset_parity stage"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate issuer_sponsor_api_live_smoke stage"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate issuer_admin_blockchain_handlers_coverage stage"
  exit 1
fi
if ! rg -Fq "integration_issuer_admin_blockchain_handlers_coverage_floor.sh" "$phase5_integration_script" \
  && ! rg -Fq "CI_PHASE5_SETTLEMENT_LAYER_ISSUER_ADMIN_BLOCKCHAIN_HANDLERS_COVERAGE_SCRIPT" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate issuer_admin_blockchain_handlers_coverage stage wiring"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity.status == \"pass\"" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate settlement_dual_asset_parity pass accounting"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity.status == \"skip\"" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate settlement_dual_asset_parity skip accounting"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity.status == \"fail\"" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate settlement_dual_asset_parity fail accounting"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke.status == \"pass\"" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate issuer_sponsor_api_live_smoke pass accounting"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke.status == \"skip\"" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate issuer_sponsor_api_live_smoke skip accounting"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke.status == \"fail\"" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate issuer_sponsor_api_live_smoke fail accounting"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage.status == \"pass\"" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate issuer_admin_blockchain_handlers_coverage pass accounting"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage.status == \"skip\"" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate issuer_admin_blockchain_handlers_coverage skip accounting"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage.status == \"fail\"" "$phase5_integration_script"; then
  echo "phase5 ci integration script must validate issuer_admin_blockchain_handlers_coverage fail accounting"
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
if ! rg -Fq "[ci-phase5-settlement-layer] canonical summary same-path behavior" "$phase5_integration_script"; then
  echo "phase5 ci integration script must include same-path canonical contract coverage marker"
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
if ! rg -Fq "require-issuer-sponsor-api-live-smoke-ok" "$phase5_run_script"; then
  echo "phase5 run wrapper must forward issuer sponsor live-smoke requirement toggle to checker stage"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke_ok" "$phase5_run_script"; then
  echo "phase5 run wrapper must surface issuer_sponsor_api_live_smoke_ok contract field"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity_ok" "$phase5_run_script"; then
  echo "phase5 run wrapper must surface settlement_dual_asset_parity_ok contract field"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_ok" "$phase5_run_script"; then
  echo "phase5 run wrapper must surface issuer_admin_blockchain_handlers_coverage_ok contract field"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_status" "$phase5_run_script"; then
  echo "phase5 run wrapper must surface issuer_admin_blockchain_handlers_coverage_status contract field"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_check_summary.signals.issuer_admin_blockchain_handlers_coverage_ok" "$phase5_run_script"; then
  echo "phase5 run wrapper must reference consolidated summary node phase5_settlement_layer_check_summary.signals.issuer_admin_blockchain_handlers_coverage_ok"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_check_summary.stages.issuer_admin_blockchain_handlers_coverage.status" "$phase5_run_script"; then
  echo "phase5 run wrapper must reference consolidated summary node phase5_settlement_layer_check_summary.stages.issuer_admin_blockchain_handlers_coverage.status"
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
if ! rg -Fq "require-issuer-sponsor-api-live-smoke-ok 0" "$phase5_run_integration_script"; then
  echo "phase5 run integration must validate sponsor live-smoke dry-run policy toggle forwarding"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke_ok" "$phase5_run_integration_script"; then
  echo "phase5 run integration must validate issuer_sponsor_api_live_smoke_ok contract field coverage"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity_ok" "$phase5_run_integration_script"; then
  echo "phase5 run integration must validate settlement_dual_asset_parity_ok contract field coverage"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_ok" "$phase5_run_integration_script"; then
  echo "phase5 run integration must validate issuer_admin_blockchain_handlers_coverage_ok contract field coverage"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_status" "$phase5_run_integration_script"; then
  echo "phase5 run integration must validate issuer_admin_blockchain_handlers_coverage_status contract field coverage"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_check_summary.signals.issuer_admin_blockchain_handlers_coverage_ok" "$phase5_run_integration_script"; then
  echo "phase5 run integration must validate consolidated summary node phase5_settlement_layer_check_summary.signals.issuer_admin_blockchain_handlers_coverage_ok coverage"
  exit 1
fi
if ! rg -Fq "PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON" "$phase5_check_script"; then
  echo "phase5 check wrapper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "require-issuer-sponsor-api-live-smoke-ok" "$phase5_check_script"; then
  echo "phase5 check wrapper must expose issuer sponsor live-smoke requirement toggle"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke_ok" "$phase5_check_script"; then
  echo "phase5 check wrapper must surface issuer_sponsor_api_live_smoke_ok signal"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity_ok" "$phase5_check_script"; then
  echo "phase5 check wrapper must surface settlement_dual_asset_parity_ok signal"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_ok" "$phase5_check_script"; then
  echo "phase5 check wrapper must surface issuer_admin_blockchain_handlers_coverage_ok signal"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_status" "$phase5_check_script"; then
  echo "phase5 check wrapper must surface issuer_admin_blockchain_handlers_coverage_status signal"
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
if ! rg -Fq "sponsor live-smoke failure" "$phase5_check_integration_script"; then
  echo "phase5 check integration must validate sponsor live-smoke fail-closed behavior"
  exit 1
fi
if ! rg -Fq "require-issuer-sponsor-api-live-smoke-ok 0" "$phase5_check_integration_script"; then
  echo "phase5 check integration must validate sponsor live-smoke policy toggle behavior"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_ok" "$phase5_check_integration_script"; then
  echo "phase5 check integration must validate issuer_admin_blockchain_handlers_coverage_ok signal coverage"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_status" "$phase5_check_integration_script"; then
  echo "phase5 check integration must validate issuer_admin_blockchain_handlers_coverage_status signal coverage"
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
if ! rg -Fq "require-issuer-sponsor-api-live-smoke-ok" "$phase5_handoff_run_script"; then
  echo "phase5 handoff-run wrapper must forward issuer sponsor live-smoke requirement toggle to handoff checker"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke_ok" "$phase5_handoff_run_script"; then
  echo "phase5 handoff-run wrapper must surface issuer_sponsor_api_live_smoke_ok contract field"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity_ok" "$phase5_handoff_run_script"; then
  echo "phase5 handoff-run wrapper must surface settlement_dual_asset_parity_ok contract field"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_ok" "$phase5_handoff_run_script"; then
  echo "phase5 handoff-run wrapper must surface issuer_admin_blockchain_handlers_coverage_ok contract field"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_status" "$phase5_handoff_run_script"; then
  echo "phase5 handoff-run wrapper must surface issuer_admin_blockchain_handlers_coverage_status contract field"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_handoff_check_summary.signals.issuer_admin_blockchain_handlers_coverage_ok" "$phase5_handoff_run_script"; then
  echo "phase5 handoff-run wrapper must reference consolidated summary node phase5_settlement_layer_handoff_check_summary.signals.issuer_admin_blockchain_handlers_coverage_ok"
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
if ! rg -Fq "require-issuer-sponsor-api-live-smoke-ok 0" "$phase5_handoff_run_integration_script"; then
  echo "phase5 handoff-run integration must validate sponsor live-smoke dry-run policy toggle forwarding"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke_ok" "$phase5_handoff_run_integration_script"; then
  echo "phase5 handoff-run integration must validate issuer_sponsor_api_live_smoke_ok contract field coverage"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity_ok" "$phase5_handoff_run_integration_script"; then
  echo "phase5 handoff-run integration must validate settlement_dual_asset_parity_ok contract field coverage"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_ok" "$phase5_handoff_run_integration_script"; then
  echo "phase5 handoff-run integration must validate issuer_admin_blockchain_handlers_coverage_ok contract field coverage"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_status" "$phase5_handoff_run_integration_script"; then
  echo "phase5 handoff-run integration must validate issuer_admin_blockchain_handlers_coverage_status contract field coverage"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_handoff_check.signals.issuer_admin_blockchain_handlers_coverage_ok" "$phase5_handoff_run_integration_script"; then
  echo "phase5 handoff-run integration must validate consolidated summary node phase5_settlement_layer_handoff_check.signals.issuer_admin_blockchain_handlers_coverage_ok coverage"
  exit 1
fi
if ! rg -Fq "PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON" "$phase5_handoff_check_script"; then
  echo "phase5 handoff-check wrapper must expose canonical summary artifact override env"
  exit 1
fi
if ! rg -Fq "require-issuer-sponsor-api-live-smoke-ok" "$phase5_handoff_check_script"; then
  echo "phase5 handoff-check wrapper must expose issuer sponsor live-smoke requirement toggle"
  exit 1
fi
if ! rg -Fq "issuer_sponsor_api_live_smoke_ok" "$phase5_handoff_check_script"; then
  echo "phase5 handoff-check wrapper must surface issuer_sponsor_api_live_smoke_ok signal"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity_ok" "$phase5_handoff_check_script"; then
  echo "phase5 handoff-check wrapper must surface settlement_dual_asset_parity_ok signal"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_ok" "$phase5_handoff_check_script"; then
  echo "phase5 handoff-check wrapper must surface issuer_admin_blockchain_handlers_coverage_ok signal"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_status" "$phase5_handoff_check_script"; then
  echo "phase5 handoff-check wrapper must surface issuer_admin_blockchain_handlers_coverage_status signal"
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
if ! rg -Fq "issuer_sponsor_api_live_smoke_ok" "$phase5_handoff_check_integration_script"; then
  echo "phase5 handoff-check integration must validate issuer_sponsor_api_live_smoke_ok signal coverage"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity_ok" "$phase5_handoff_check_integration_script"; then
  echo "phase5 handoff-check integration must validate settlement_dual_asset_parity_ok signal coverage"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_ok" "$phase5_handoff_check_integration_script"; then
  echo "phase5 handoff-check integration must validate issuer_admin_blockchain_handlers_coverage_ok signal coverage"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_status" "$phase5_handoff_check_integration_script"; then
  echo "phase5 handoff-check integration must validate issuer_admin_blockchain_handlers_coverage_status signal coverage"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_check_summary.issuer_admin_blockchain_handlers_coverage_ok" "$phase5_handoff_check_integration_script"; then
  echo "phase5 handoff-check integration must validate consolidated summary node phase5_settlement_layer_check_summary.issuer_admin_blockchain_handlers_coverage_ok coverage"
  exit 1
fi
if ! rg -Fq "require-issuer-sponsor-api-live-smoke-ok 0" "$phase5_handoff_check_integration_script"; then
  echo "phase5 handoff-check integration must validate issuer sponsor live-smoke policy toggle behavior"
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
if ! rg -Fq "issuer_sponsor_api_live_smoke_ok" "$phase5_summary_report_script"; then
  echo "phase5 summary report helper must surface issuer_sponsor_api_live_smoke_ok contract field"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity_ok" "$phase5_summary_report_script"; then
  echo "phase5 summary report helper must surface settlement_dual_asset_parity_ok contract field"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_ok" "$phase5_summary_report_script"; then
  echo "phase5 summary report helper must surface issuer_admin_blockchain_handlers_coverage_ok contract field"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_status" "$phase5_summary_report_script"; then
  echo "phase5 summary report helper must surface issuer_admin_blockchain_handlers_coverage_status contract field"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_handoff_check_summary" "$phase5_summary_report_script"; then
  echo "phase5 summary report helper must reference consolidated summary node phase5_settlement_layer_handoff_check_summary"
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
if ! rg -Fq "issuer_sponsor_api_live_smoke_ok" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must validate issuer_sponsor_api_live_smoke_ok contract field coverage"
  exit 1
fi
if ! rg -Fq "settlement_dual_asset_parity_ok" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must validate settlement_dual_asset_parity_ok contract field coverage"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_ok" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must validate issuer_admin_blockchain_handlers_coverage_ok contract field coverage"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_status" "$phase5_summary_report_integration_script" \
  && ! rg -Fq ".signals.issuer_admin_blockchain_handlers_coverage.status" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must validate issuer_admin_blockchain_handlers_coverage_status contract field coverage"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_handoff_check_summary" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must validate consolidated summary node phase5_settlement_layer_handoff_check_summary coverage"
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
if ! rg -Fq "[phase5-settlement-summary-report] pass path (canonical equals summary path)" "$phase5_summary_report_integration_script"; then
  echo "phase5 summary report integration script must include same-path canonical contract coverage marker"
  exit 1
fi
if ! rg -Fq "scripts/integration_phase5_settlement_layer_summary_report.sh" "$ci_local_script"; then
  echo "ci_local.sh must run scripts/integration_phase5_settlement_layer_summary_report.sh"
  exit 1
fi
if ! rg -Fq "scripts/integration_phase6_cosmos_l1_summary_report.sh" "$ci_local_script"; then
  echo "ci_local.sh must run scripts/integration_phase6_cosmos_l1_summary_report.sh"
  exit 1
fi
if ! rg -Fq "scripts/integration_blockchain_fastlane.sh" "$ci_local_script"; then
  echo "ci_local.sh must run scripts/integration_blockchain_fastlane.sh"
  exit 1
fi
if ! rg -Fq "scripts/integration_ci_phase7_mainnet_cutover.sh" "$ci_local_script"; then
  echo "ci_local.sh must run scripts/integration_ci_phase7_mainnet_cutover.sh"
  exit 1
fi
if ! rg -Fq "scripts/integration_phase7_mainnet_cutover_check.sh" "$ci_local_script"; then
  echo "ci_local.sh must run scripts/integration_phase7_mainnet_cutover_check.sh"
  exit 1
fi
if ! rg -Fq "scripts/integration_phase7_mainnet_cutover_run.sh" "$ci_local_script"; then
  echo "ci_local.sh must run scripts/integration_phase7_mainnet_cutover_run.sh"
  exit 1
fi
if ! rg -Fq "scripts/integration_phase7_mainnet_cutover_handoff_check.sh" "$ci_local_script"; then
  echo "ci_local.sh must run scripts/integration_phase7_mainnet_cutover_handoff_check.sh"
  exit 1
fi
if ! rg -Fq "scripts/integration_phase7_mainnet_cutover_handoff_run.sh" "$ci_local_script"; then
  echo "ci_local.sh must run scripts/integration_phase7_mainnet_cutover_handoff_run.sh"
  exit 1
fi
if ! rg -Fq "scripts/integration_phase7_mainnet_cutover_summary_report.sh" "$ci_local_script"; then
  echo "ci_local.sh must run scripts/integration_phase7_mainnet_cutover_summary_report.sh"
  exit 1
fi
if ! rg -Fq "scripts/integration_easy_node_blockchain_gate_wrappers.sh" "$ci_local_script"; then
  echo "ci_local.sh must run scripts/integration_easy_node_blockchain_gate_wrappers.sh"
  exit 1
fi
if ! rg -Fq "scripts/integration_easy_node_blockchain_summary_reports.sh" "$ci_local_script"; then
  echo "ci_local.sh must run scripts/integration_easy_node_blockchain_summary_reports.sh"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_ok" "$easy_node_blockchain_summary_reports_integration_script" \
  && ! rg -Fq ".signals.issuer_admin_blockchain_handlers_coverage.ok" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "integration easy-node blockchain summary reports script must validate issuer_admin_blockchain_handlers_coverage_ok signal"
  exit 1
fi
if ! rg -Fq "issuer_admin_blockchain_handlers_coverage_status" "$easy_node_blockchain_summary_reports_integration_script" \
  && ! rg -Fq ".signals.issuer_admin_blockchain_handlers_coverage.status" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "integration easy-node blockchain summary reports script must validate issuer_admin_blockchain_handlers_coverage_status signal"
  exit 1
fi
if ! rg -Fq "phase5_settlement_layer_handoff_check_summary" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "integration easy-node blockchain summary reports script must validate consolidated summary node phase5_settlement_layer_handoff_check_summary"
  exit 1
fi
if ! rg -Fq "ci-phase5-settlement-layer" "$easy_node_script"; then
  echo "easy_node.sh must expose ci-phase5-settlement-layer command text"
  exit 1
fi
if ! rg -Fq "phase5-settlement-layer-check" "$easy_node_script"; then
  echo "easy_node.sh must expose phase5-settlement-layer-check command text"
  exit 1
fi
if ! rg -Fq "phase5-settlement-layer-run" "$easy_node_script"; then
  echo "easy_node.sh must expose phase5-settlement-layer-run command text"
  exit 1
fi
if ! rg -Fq "phase5-settlement-layer-handoff-check" "$easy_node_script"; then
  echo "easy_node.sh must expose phase5-settlement-layer-handoff-check command text"
  exit 1
fi
if ! rg -Fq "phase5-settlement-layer-handoff-run" "$easy_node_script"; then
  echo "easy_node.sh must expose phase5-settlement-layer-handoff-run command text"
  exit 1
fi
if ! rg -Fq "ci-phase6-cosmos-l1-build-testnet" "$easy_node_script"; then
  echo "easy_node.sh must expose ci-phase6-cosmos-l1-build-testnet command text"
  exit 1
fi
if ! rg -Fq "ci-phase6-cosmos-l1-contracts" "$easy_node_script"; then
  echo "easy_node.sh must expose ci-phase6-cosmos-l1-contracts command text"
  exit 1
fi
if ! rg -Fq "ci-phase7-mainnet-cutover" "$easy_node_script"; then
  echo "easy_node.sh must expose ci-phase7-mainnet-cutover command text"
  exit 1
fi
if ! rg -Fq "phase7-mainnet-cutover-check" "$easy_node_script"; then
  echo "easy_node.sh must expose phase7-mainnet-cutover-check command text"
  exit 1
fi
if ! rg -Fq "phase7-mainnet-cutover-run" "$easy_node_script"; then
  echo "easy_node.sh must expose phase7-mainnet-cutover-run command text"
  exit 1
fi
if ! rg -Fq "phase7-mainnet-cutover-handoff-check" "$easy_node_script"; then
  echo "easy_node.sh must expose phase7-mainnet-cutover-handoff-check command text"
  exit 1
fi
if ! rg -Fq "phase7-mainnet-cutover-handoff-run" "$easy_node_script"; then
  echo "easy_node.sh must expose phase7-mainnet-cutover-handoff-run command text"
  exit 1
fi
if ! rg -Fq "phase7-mainnet-cutover-summary-report" "$easy_node_script"; then
  echo "easy_node.sh must expose phase7-mainnet-cutover-summary-report command text"
  exit 1
fi
if ! rg -Fq "blockchain-fastlane" "$easy_node_script"; then
  echo "easy_node.sh must expose blockchain-fastlane command text"
  exit 1
fi
if ! rg -Fq "rg -Fq" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate command text via rg string checks"
  exit 1
fi
if ! rg -Fq "ci-phase5-settlement-layer" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate ci-phase5-settlement-layer command wiring"
  exit 1
fi
if ! rg -Fq "phase5-settlement-layer-check" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate phase5-settlement-layer-check command wiring"
  exit 1
fi
if ! rg -Fq "phase5-settlement-layer-run" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate phase5-settlement-layer-run command wiring"
  exit 1
fi
if ! rg -Fq "phase5-settlement-layer-handoff-check" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate phase5-settlement-layer-handoff-check command wiring"
  exit 1
fi
if ! rg -Fq "phase5-settlement-layer-handoff-run" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate phase5-settlement-layer-handoff-run command wiring"
  exit 1
fi
if ! rg -Fq "ci-phase6-cosmos-l1-build-testnet" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate ci-phase6-cosmos-l1-build-testnet command wiring"
  exit 1
fi
if ! rg -Fq "ci-phase6-cosmos-l1-contracts" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate ci-phase6-cosmos-l1-contracts command wiring"
  exit 1
fi
if ! rg -Fq "ci-phase7-mainnet-cutover" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate ci-phase7-mainnet-cutover command wiring"
  exit 1
fi
if ! rg -Fq "phase7-mainnet-cutover-check" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate phase7-mainnet-cutover-check command wiring"
  exit 1
fi
if ! rg -Fq "phase7-mainnet-cutover-run" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate phase7-mainnet-cutover-run command wiring"
  exit 1
fi
if ! rg -Fq "phase7-mainnet-cutover-handoff-check" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate phase7-mainnet-cutover-handoff-check command wiring"
  exit 1
fi
if ! rg -Fq "phase7-mainnet-cutover-handoff-run" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate phase7-mainnet-cutover-handoff-run command wiring"
  exit 1
fi
if ! rg -Fq "blockchain-fastlane" "$easy_node_blockchain_gate_wrappers_integration_script"; then
  echo "easy-node gate-wrapper integration must validate blockchain-fastlane command wiring"
  exit 1
fi
if ! rg -Fq "phase5-settlement-layer-summary-report" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "easy-node summary-report integration must validate phase5 wrapper command wiring"
  exit 1
fi
if ! rg -Fq "phase6-cosmos-l1-summary-report" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "easy-node summary-report integration must validate phase6 wrapper command wiring"
  exit 1
fi
if ! rg -Fq "phase7-mainnet-cutover-summary-report" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "easy-node summary-report integration must validate phase7 wrapper command wiring"
  exit 1
fi
if ! rg -Fq "phase7_mainnet_cutover_summary_report.sh" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "easy-node summary-report integration must validate phase7 summary wrapper path wiring"
  exit 1
fi
check_phase7_summary_comet_signal_surface "$easy_node_blockchain_summary_reports_integration_script" "easy-node summary-report integration"
for phase7_runtime_summary_signal in \
  "module_tx_surface_ok" \
  "tdpnd_grpc_live_smoke_ok" \
  "tdpnd_grpc_auth_live_smoke_ok"
do
  if ! rg -Fq "$phase7_runtime_summary_signal" "$easy_node_blockchain_summary_reports_integration_script"; then
    echo "easy-node summary-report integration must validate phase7 runtime summary signal: $phase7_runtime_summary_signal"
    exit 1
  fi
done
if ! rg -Fq -- "--summary-json" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "easy-node summary-report integration must validate summary-json forwarding"
  exit 1
fi
if ! rg -Fq -- "--print-summary-json" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "easy-node summary-report integration must validate print-summary-json forwarding"
  exit 1
fi
if ! rg -Fq ".signals.issuer_sponsor_api_live_smoke.status" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "easy-node summary-report integration must validate phase5 sponsor signal status surfacing"
  exit 1
fi
if ! rg -Fq ".signals.issuer_sponsor_api_live_smoke.ok" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "easy-node summary-report integration must validate phase5 sponsor signal health surfacing"
  exit 1
fi
if ! rg -Fq ".signals.settlement_dual_asset_parity.status" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "easy-node summary-report integration must validate phase5 dual-asset parity signal status surfacing"
  exit 1
fi
if ! rg -Fq ".signals.settlement_dual_asset_parity.ok" "$easy_node_blockchain_summary_reports_integration_script"; then
  echo "easy-node summary-report integration must validate phase5 dual-asset parity signal health surfacing"
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
for blockchain_fastlane_doc in "$full_plan" "$product_roadmap"; do
  doc_label="product roadmap"
  if [[ "$blockchain_fastlane_doc" == "$full_plan" ]]; then
    doc_label="full execution plan"
  fi
  check_blockchain_fastlane_activation_gate_surface "$blockchain_fastlane_doc" "$doc_label"
done
for f in "$blockchain_mainnet_activation_gate_script" "$blockchain_mainnet_activation_gate_integration_script"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required file: $f"
    exit 1
  fi
done
if [[ ! -f "$blockchain_mainnet_activation_metrics_integration_script" ]]; then
  echo "missing required file: $blockchain_mainnet_activation_metrics_integration_script"
  exit 1
fi
if ! rg -Fq "source-json env-only ingestion path" "$blockchain_mainnet_activation_metrics_integration_script"; then
  echo "integration blockchain mainnet activation metrics script must validate source-json env-only ingestion"
  exit 1
fi
if ! rg -Fq "source-json repeated cli dedupe + order path" "$blockchain_mainnet_activation_metrics_integration_script"; then
  echo "integration blockchain mainnet activation metrics script must validate repeated cli source-json dedupe/order semantics"
  exit 1
fi
if ! rg -Fq "explicit CLI source-json suppresses env fallback path" "$blockchain_mainnet_activation_metrics_integration_script"; then
  echo "integration blockchain mainnet activation metrics script must validate explicit CLI source-json suppresses env fallback semantics"
  exit 1
fi
if ! rg -Fq "BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SOURCE_JSONS" "$blockchain_mainnet_activation_metrics_integration_script"; then
  echo "integration blockchain mainnet activation metrics script must validate BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SOURCE_JSONS env wiring"
  exit 1
fi
if ! rg -Fq ".sources.source_jsons ==" "$blockchain_mainnet_activation_metrics_integration_script"; then
  echo "integration blockchain mainnet activation metrics script must validate deterministic sources.source_jsons contract"
  exit 1
fi
if ! rg -Fq ".sources.usable_source_jsons ==" "$blockchain_mainnet_activation_metrics_integration_script"; then
  echo "integration blockchain mainnet activation metrics script must validate deterministic sources.usable_source_jsons contract"
  exit 1
fi
if ! rg -Fq "measurement_window_weeks" "$blockchain_mainnet_activation_gate_script"; then
  echo "blockchain mainnet activation gate helper must enforce measurement_window_weeks metric gate"
  exit 1
fi
if ! rg -Fq "Readiness window - Measurement coverage" "$blockchain_mainnet_activation_gate_script"; then
  echo "blockchain mainnet activation gate helper must expose readiness-window measurement gate title"
  exit 1
fi
if ! rg -Fq "NO-GO measurement window too short" "$blockchain_mainnet_activation_gate_integration_script"; then
  echo "integration blockchain mainnet activation gate script must validate short measurement-window NO-GO path"
  exit 1
fi
if ! rg -Fq "NO-GO measurement window missing-or-invalid" "$blockchain_mainnet_activation_gate_integration_script"; then
  echo "integration blockchain mainnet activation gate script must validate missing/invalid measurement-window NO-GO path"
  exit 1
fi
if ! rg -Fq "blockchain_fastlane_summary" "$blockchain_fastlane_script"; then
  echo "blockchain fastlane script must emit blockchain_fastlane_summary schema id"
  exit 1
fi
for blockchain_fastlane_stage_script in \
  "scripts/ci_phase5_settlement_layer.sh" \
  "scripts/ci_phase6_cosmos_l1_build_testnet.sh" \
  "scripts/ci_phase6_cosmos_l1_contracts.sh" \
  "scripts/ci_phase7_mainnet_cutover.sh"
do
  if ! rg -Fq "$blockchain_fastlane_stage_script" "$blockchain_fastlane_script"; then
    echo "blockchain fastlane script must reference stage script: $blockchain_fastlane_stage_script"
    exit 1
  fi
done
if ! rg -Fq -- "--blockchain-mainnet-activation-gate-summary-json" "$blockchain_fastlane_script"; then
  echo "blockchain fastlane script must expose --blockchain-mainnet-activation-gate-summary-json deterministic gate summary input"
  exit 1
fi
if ! rg -Fq -- "--blockchain-mainnet-activation-metrics-source-json" "$blockchain_fastlane_script"; then
  echo "blockchain fastlane script must expose --blockchain-mainnet-activation-metrics-source-json deterministic metrics-source input"
  exit 1
fi
if ! rg -Fq -- "--phase7-mainnet-cutover-summary-report-json" "$blockchain_fastlane_script"; then
  echo "blockchain fastlane script must expose --phase7-mainnet-cutover-summary-report-json deterministic phase7 summary input"
  exit 1
fi
if ! rg -Fq "BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SOURCE_JSONS" "$blockchain_fastlane_script"; then
  echo "blockchain fastlane script must expose BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SOURCE_JSONS deterministic metrics-source env input"
  exit 1
fi
if ! rg -Fq "BLOCKCHAIN_FASTLANE_PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_JSON" "$blockchain_fastlane_script"; then
  echo "blockchain fastlane script must expose BLOCKCHAIN_FASTLANE_PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_JSON deterministic phase7 summary env input"
  exit 1
fi
if ! rg -Fq -- "--source-json" "$blockchain_fastlane_script"; then
  echo "blockchain fastlane script must forward metrics-source artifacts via --source-json stage args"
  exit 1
fi
if ! rg -Fq -- "--fail-close" "$blockchain_fastlane_script"; then
  echo "blockchain fastlane script must forward activation gate fail-close policy"
  exit 1
fi
if ! rg -Fq "BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON" "$blockchain_fastlane_script"; then
  echo "blockchain fastlane script must expose BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON deterministic gate summary env input"
  exit 1
fi
if ! rg -Fq "inputs.blockchain_mainnet_activation_metrics_source_jsons" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate inputs.blockchain_mainnet_activation_metrics_source_jsons contract"
  exit 1
fi
if ! rg -Fq "inputs.phase7_mainnet_cutover_summary_report_json" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate inputs.phase7_mainnet_cutover_summary_report_json contract"
  exit 1
fi
if ! rg -Fq "artifacts.blockchain_mainnet_activation_metrics_source_jsons" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate artifacts.blockchain_mainnet_activation_metrics_source_jsons contract"
  exit 1
fi
if ! rg -Fq "artifacts.phase7_mainnet_cutover_summary_report_json" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate artifacts.phase7_mainnet_cutover_summary_report_json contract"
  exit 1
fi
if ! rg -Fq -- "--source-json" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate metrics-source forwarding via --source-json"
  exit 1
fi
if ! rg -Fq "metrics source-json env-only ingestion" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate metrics source-json env-only ingestion"
  exit 1
fi
if ! rg -Fq "metrics source-json repeated cli forwarding" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate repeated metrics source-json cli forwarding"
  exit 1
fi
if ! rg -Fq -- "--fail-close" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate activation gate fail-close forwarding"
  exit 1
fi
if ! rg -Fq "inputs.blockchain_mainnet_activation_gate_summary_json" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate inputs.blockchain_mainnet_activation_gate_summary_json contract"
  exit 1
fi
if ! rg -Fq "artifacts.blockchain_mainnet_activation_gate_summary_json" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate artifacts.blockchain_mainnet_activation_gate_summary_json contract"
  exit 1
fi
if ! rg -Fq "ordering" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate ordering semantics"
  exit 1
fi
if ! rg -Fq "dry-run" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate dry-run semantics"
  exit 1
fi
if ! rg -Fq "toggle" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate toggle semantics"
  exit 1
fi
if ! rg -Fq "failure propagation" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate failure propagation semantics"
  exit 1
fi
if ! rg -Fq "grep -Fq" "$blockchain_fastlane_integration_script"; then
  echo "integration blockchain fastlane script must validate contracts via string checks"
  exit 1
fi
phase5_blockchain_gate_specs=(
  "settlement_adapter_roundtrip|scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh"
  "settlement_adapter_signed_tx_roundtrip|scripts/integration_cosmos_adapter_tdpnd_signed_tx_roundtrip.sh"
  "settlement_shadow_env|scripts/integration_cosmos_settlement_shadow_env.sh"
  "settlement_shadow_status_surface|scripts/integration_cosmos_settlement_shadow_status_surface.sh"
  "settlement_dual_asset_parity|scripts/integration_cosmos_settlement_dual_asset_parity.sh"
  "issuer_sponsor_api_live_smoke|scripts/integration_issuer_sponsor_api_live_smoke.sh"
  "issuer_admin_blockchain_handlers_coverage|scripts/integration_issuer_admin_blockchain_handlers_coverage_floor.sh"
)
for gate_spec in "${phase5_blockchain_gate_specs[@]}"; do
  gate_stage="${gate_spec%%|*}"
  gate_script="${gate_spec#*|}"
  if ! rg -Fq "$gate_stage" "$full_plan"; then
    echo "full execution plan must document ${gate_stage} phase5 stage"
    exit 1
  fi
  if ! rg -Fq "$gate_script" "$full_plan"; then
    echo "full execution plan must document ${gate_script} phase5 integration script"
    exit 1
  fi
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
