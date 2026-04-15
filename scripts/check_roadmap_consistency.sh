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
phase5_ci_script="scripts/ci_phase5_settlement_layer.sh"
phase5_integration_script="scripts/integration_ci_phase5_settlement_layer.sh"

for f in "$full_plan" "$product_roadmap" "$roadmap_script" "$bootstrap_validator_doc" "$cosmos_runtime_doc" "$chain_readme" "$settlement_mapping_doc" "$phase5_ci_script" "$phase5_integration_script"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required file: $f"
    exit 1
  fi
done

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

for phase5_script in "$phase5_ci_script" "$phase5_integration_script"; do
  if rg -qi "phase4 windows full parity" "$phase5_script"; then
    echo "phase5 settlement tooling contains stale phase4 wording: $phase5_script"
    exit 1
  fi
done

echo "roadmap consistency check ok"
