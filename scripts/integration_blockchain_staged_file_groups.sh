#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp cat grep cmp diff; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[integration-blockchain-staged-file-groups] help contract"
if ! ./scripts/blockchain_staged_file_groups.sh --help | grep -F -- "--staged-files-file PATH" >/dev/null; then
  echo "help output missing --staged-files-file PATH"
  exit 1
fi

echo "[integration-blockchain-staged-file-groups] mixed fixture classification"
FIXTURE_MIXED="$TMP_DIR/staged_mixed.txt"
SUMMARY_MIXED="$TMP_DIR/summary_mixed.json"
SUMMARY_MIXED_REPEAT="$TMP_DIR/summary_mixed_repeat.json"
cat >"$FIXTURE_MIXED" <<'EOF_FIXTURE_MIXED'
# core chain+settlement
blockchain/tdpn-chain/app/scaffold.go
blockchain\tdpn-chain\cmd\tdpnd\settlement_bridge.go
pkg/settlement/cosmos_adapter.go

# ci/contracts
scripts/ci_phase6_cosmos_l1_contracts.sh
scripts/integration_ci_phase5_settlement_layer.sh
scripts/phase5_settlement_layer_check.sh
scripts/phase7_mainnet_cutover_run.sh
scripts/integration_phase7_mainnet_cutover_summary_report.sh

# docs
docs/cosmos-settlement-runtime.md
docs/product-roadmap.md

# explicit spillover exclusions
services/entry/service.go
scripts/client_vpn_smoke.sh
apps/desktop/src-tauri/tauri.conf.json
scripts/ci_phase1_resilience.sh
docs/client-safety-guide.md
pkg/securehttp/securehttp.go
EOF_FIXTURE_MIXED

./scripts/blockchain_staged_file_groups.sh --staged-files-file "$FIXTURE_MIXED" >"$SUMMARY_MIXED"
./scripts/blockchain_staged_file_groups.sh --staged-files-file "$FIXTURE_MIXED" >"$SUMMARY_MIXED_REPEAT"

if ! cmp -s "$SUMMARY_MIXED" "$SUMMARY_MIXED_REPEAT"; then
  echo "deterministic output mismatch across identical fixture runs"
  diff -u "$SUMMARY_MIXED" "$SUMMARY_MIXED_REPEAT" || true
  exit 1
fi

if ! jq -e '
  .schema.id == "blockchain_staged_file_groups"
  and .summary.core_chain_settlement == 3
  and .summary.ci_contracts == 5
  and .summary.docs == 2
  and .summary.selected_total == 10
  and .summary.excluded_spillover_total == 6
  and .summary.unmatched_total == 0
  and .groups.core_chain_settlement == [
    "blockchain/tdpn-chain/app/scaffold.go",
    "blockchain/tdpn-chain/cmd/tdpnd/settlement_bridge.go",
    "pkg/settlement/cosmos_adapter.go"
  ]
  and .groups.ci_contracts == [
    "scripts/ci_phase6_cosmos_l1_contracts.sh",
    "scripts/integration_ci_phase5_settlement_layer.sh",
    "scripts/integration_phase7_mainnet_cutover_summary_report.sh",
    "scripts/phase5_settlement_layer_check.sh",
    "scripts/phase7_mainnet_cutover_run.sh"
  ]
  and .groups.docs == [
    "docs/cosmos-settlement-runtime.md",
    "docs/product-roadmap.md"
  ]
  and .excluded_non_blockchain_spillover == [
    "apps/desktop/src-tauri/tauri.conf.json",
    "docs/client-safety-guide.md",
    "pkg/securehttp/securehttp.go",
    "scripts/ci_phase1_resilience.sh",
    "scripts/client_vpn_smoke.sh",
    "services/entry/service.go"
  ]
  and .unmatched == []
' "$SUMMARY_MIXED" >/dev/null; then
  echo "mixed fixture summary mismatch"
  cat "$SUMMARY_MIXED"
  exit 1
fi

echo "[integration-blockchain-staged-file-groups] spillover + unmatched fixture"
FIXTURE_SPILLOVER="$TMP_DIR/staged_spillover.txt"
SUMMARY_SPILLOVER="$TMP_DIR/summary_spillover.json"
cat >"$FIXTURE_SPILLOVER" <<'EOF_FIXTURE_SPILLOVER'
scripts/integration_ci_phase4_windows_full_parity.sh
scripts/phase6_cosmos_l1_build_testnet_suite.sh
docs/exit-node-safety-guide.md
README.md
services/issuer/service.go
pkg/settlement/memory.go
docs/blockchain-app-sponsorship-quickstart.md
scripts/blockchain_mainnet_activation_gate.sh
scripts/blockchain_fastlane.sh
scripts/blockchain_fastlane.sh
EOF_FIXTURE_SPILLOVER

./scripts/blockchain_staged_file_groups.sh --staged-files-file "$FIXTURE_SPILLOVER" >"$SUMMARY_SPILLOVER"

if ! jq -e '
  .summary.core_chain_settlement == 1
  and .summary.ci_contracts == 3
  and .summary.docs == 1
  and .summary.selected_total == 5
  and .summary.excluded_spillover_total == 2
  and .summary.unmatched_total == 2
  and .groups.core_chain_settlement == [
    "pkg/settlement/memory.go"
  ]
  and .groups.ci_contracts == [
    "scripts/blockchain_fastlane.sh",
    "scripts/blockchain_mainnet_activation_gate.sh",
    "scripts/phase6_cosmos_l1_build_testnet_suite.sh"
  ]
  and .groups.docs == [
    "docs/blockchain-app-sponsorship-quickstart.md"
  ]
  and .excluded_non_blockchain_spillover == [
    "docs/exit-node-safety-guide.md",
    "scripts/integration_ci_phase4_windows_full_parity.sh"
  ]
  and .unmatched == [
    "README.md",
    "services/issuer/service.go"
  ]
  and .selected == [
    "docs/blockchain-app-sponsorship-quickstart.md",
    "pkg/settlement/memory.go",
    "scripts/blockchain_fastlane.sh",
    "scripts/blockchain_mainnet_activation_gate.sh",
    "scripts/phase6_cosmos_l1_build_testnet_suite.sh"
  ]
' "$SUMMARY_SPILLOVER" >/dev/null; then
  echo "spillover fixture summary mismatch"
  cat "$SUMMARY_SPILLOVER"
  exit 1
fi

echo "[integration-blockchain-staged-file-groups] ok"
