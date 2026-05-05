#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp cat grep cmp diff mkdir touch; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[integration-blockchain-cosmos-only-guardrail] help contract"
if ! ./scripts/blockchain_cosmos_only_guardrail.sh --help | grep -F -- "--root PATH" >/dev/null; then
  echo "help output missing --root PATH"
  exit 1
fi

echo "[integration-blockchain-cosmos-only-guardrail] clean fixture pass + deterministic output"
FIXTURE_CLEAN="$TMP_DIR/clean"
mkdir -p "$FIXTURE_CLEAN/blockchain/tdpn-chain/app"
mkdir -p "$FIXTURE_CLEAN/pkg/settlement"
mkdir -p "$FIXTURE_CLEAN/scripts"
mkdir -p "$FIXTURE_CLEAN/docs"
touch "$FIXTURE_CLEAN/blockchain/tdpn-chain/app/app.go"
touch "$FIXTURE_CLEAN/pkg/settlement/cosmos_adapter.go"
touch "$FIXTURE_CLEAN/scripts/ci_phase6_cosmos_l1_contracts.sh"
touch "$FIXTURE_CLEAN/docs/solana-guide.md"

CLEAN_SUMMARY_A="$TMP_DIR/clean_summary_a.json"
CLEAN_SUMMARY_B="$TMP_DIR/clean_summary_b.json"
./scripts/blockchain_cosmos_only_guardrail.sh --root "$FIXTURE_CLEAN" >"$CLEAN_SUMMARY_A"
./scripts/blockchain_cosmos_only_guardrail.sh --root "$FIXTURE_CLEAN" >"$CLEAN_SUMMARY_B"

if ! cmp -s "$CLEAN_SUMMARY_A" "$CLEAN_SUMMARY_B"; then
  echo "deterministic output mismatch for clean fixture"
  diff -u "$CLEAN_SUMMARY_A" "$CLEAN_SUMMARY_B" || true
  exit 1
fi

if ! jq -e '
  .schema.id == "blockchain_cosmos_only_guardrail"
  and .summary.status == "pass"
  and .summary.non_tdpn_chain_top_level_blockchain_entries == 0
  and .summary.suspicious_non_cosmos_paths == 0
  and .summary.violation_total == 0
  and .findings.non_tdpn_chain_top_level_blockchain_entries == []
  and .findings.suspicious_non_cosmos_paths == []
' "$CLEAN_SUMMARY_A" >/dev/null; then
  echo "clean fixture summary mismatch"
  cat "$CLEAN_SUMMARY_A"
  exit 1
fi

echo "[integration-blockchain-cosmos-only-guardrail] drift fixture fail-closed + deterministic output"
FIXTURE_DRIFT="$TMP_DIR/drift"
mkdir -p "$FIXTURE_DRIFT/blockchain/tdpn-chain/app"
mkdir -p "$FIXTURE_DRIFT/blockchain/solana-legacy"
mkdir -p "$FIXTURE_DRIFT/blockchain/evm-lab"
mkdir -p "$FIXTURE_DRIFT/pkg/settlement"
mkdir -p "$FIXTURE_DRIFT/scripts"
mkdir -p "$FIXTURE_DRIFT/docs"
touch "$FIXTURE_DRIFT/pkg/settlement/ethereum_adapter.go"
touch "$FIXTURE_DRIFT/scripts/hardhat_deploy.sh"
touch "$FIXTURE_DRIFT/scripts/substrate_setup.sh"
touch "$FIXTURE_DRIFT/docs/polkadot-guide.md"

DRIFT_SUMMARY_A="$TMP_DIR/drift_summary_a.json"
DRIFT_SUMMARY_B="$TMP_DIR/drift_summary_b.json"
set +e
./scripts/blockchain_cosmos_only_guardrail.sh --root "$FIXTURE_DRIFT" >"$DRIFT_SUMMARY_A"
rc_a=$?
./scripts/blockchain_cosmos_only_guardrail.sh --root "$FIXTURE_DRIFT" >"$DRIFT_SUMMARY_B"
rc_b=$?
set -e

if [[ "$rc_a" -ne 1 || "$rc_b" -ne 1 ]]; then
  echo "expected fail-closed exit code 1 for drift fixture (got $rc_a and $rc_b)"
  cat "$DRIFT_SUMMARY_A"
  exit 1
fi

if ! cmp -s "$DRIFT_SUMMARY_A" "$DRIFT_SUMMARY_B"; then
  echo "deterministic output mismatch for drift fixture"
  diff -u "$DRIFT_SUMMARY_A" "$DRIFT_SUMMARY_B" || true
  exit 1
fi

if ! jq -e '
  .schema.id == "blockchain_cosmos_only_guardrail"
  and .summary.status == "fail"
  and .summary.non_tdpn_chain_top_level_blockchain_entries == 2
  and .summary.suspicious_non_cosmos_paths == 5
  and .summary.violation_total == 7
  and .findings.non_tdpn_chain_top_level_blockchain_entries == [
    "blockchain/evm-lab",
    "blockchain/solana-legacy"
  ]
  and .findings.suspicious_non_cosmos_paths == [
    { path: "blockchain/evm-lab", token: "evm" },
    { path: "blockchain/solana-legacy", token: "solana" },
    { path: "pkg/settlement/ethereum_adapter.go", token: "ethereum" },
    { path: "scripts/hardhat_deploy.sh", token: "hardhat" },
    { path: "scripts/substrate_setup.sh", token: "substrate" }
  ]
  and ((.findings.suspicious_non_cosmos_paths | map(.path | startswith("docs/")) | any) == false)
' "$DRIFT_SUMMARY_A" >/dev/null; then
  echo "drift fixture summary mismatch"
  cat "$DRIFT_SUMMARY_A"
  exit 1
fi

echo "[integration-blockchain-cosmos-only-guardrail] ok"

