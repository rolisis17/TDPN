#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

run_go_tests="${GPM_ADMIN_SETTLEMENT_CONTRACT_RUN_GO_TESTS:-1}"
if [[ "$run_go_tests" != "0" && "$run_go_tests" != "1" ]]; then
  echo "GPM_ADMIN_SETTLEMENT_CONTRACT_RUN_GO_TESTS must be 0 or 1"
  exit 2
fi

LOCAL_API_DOC="docs/local-control-api.md"
GPM_TRACK_DOC="docs/global-privacy-mesh-track.md"
GPM_STATUS_DOC="docs/gpm-productization-status.md"
PRODUCT_ROADMAP_DOC="docs/product-roadmap.md"

require_file() {
  local file_path="$1"
  if [[ ! -f "$file_path" ]]; then
    echo "missing required docs contract file: $file_path"
    exit 1
  fi
}

require_contains() {
  local file_path="$1"
  local expected="$2"
  local description="$3"
  if ! grep -F -- "$expected" "$file_path" >/dev/null 2>&1; then
    echo "gpm admin settlement docs contract failed: missing ${description}"
    echo "file: $file_path"
    echo "expected marker: $expected"
    exit 1
  fi
}

for file_path in "$LOCAL_API_DOC" "$GPM_TRACK_DOC" "$GPM_STATUS_DOC" "$PRODUCT_ROADMAP_DOC"; do
  require_file "$file_path"
done

echo "[gpm-admin-settlement-contract] admin wallet allowlist and command-backed verification docs"
require_contains "$LOCAL_API_DOC" "GPM_ADMIN_WALLET_ALLOWLIST" "admin wallet allowlist env"
require_contains "$LOCAL_API_DOC" "TDPN_ADMIN_WALLET_ALLOWLIST" "legacy admin wallet allowlist alias"
require_contains "$LOCAL_API_DOC" "command-backed verification" "command-backed admin verification"
require_contains "$LOCAL_API_DOC" "baseline/local proof-shape validation alone never grants admin role" "admin role fail-closed baseline verifier wording"
require_contains "$LOCAL_API_DOC" "gpm_admin_wallet_allowlist_configured" "admin allowlist runtime config marker"
require_contains "$GPM_TRACK_DOC" "Admin Console admin role is wallet-allowlist gated" "GPM track admin split allowlist marker"

echo "[gpm-admin-settlement-contract] legacy service mutation production break-glass docs"
require_contains "$LOCAL_API_DOC" "GPM_ALLOW_LEGACY_SERVICE_MUTATIONS" "legacy service mutation break-glass env"
require_contains "$LOCAL_API_DOC" "TDPN_ALLOW_LEGACY_SERVICE_MUTATIONS" "legacy service mutation break-glass alias"
require_contains "$LOCAL_API_DOC" "legacy \`/v1/service/start|stop|restart\` mutations blocked" "production default legacy service block"
require_contains "$LOCAL_API_DOC" "break-glass support override only" "break-glass-only guidance"
require_contains "$LOCAL_API_DOC" "Invalid break-glass boolean values in production fail closed" "invalid break-glass fail-closed semantics"
require_contains "$LOCAL_API_DOC" "use \`/v1/gpm/service/*\` for normal Admin Console operation" "GPM service endpoint guidance"
require_contains "$GPM_TRACK_DOC" "production mode blocks legacy \`/v1/service/start|stop|restart\` mutations by default" "GPM track production mutation split"

echo "[gpm-admin-settlement-contract] reward finalize docs"
require_contains "$LOCAL_API_DOC" "POST /v1/gpm/admin/rewards/finalize" "reward finalize endpoint"
require_contains "$LOCAL_API_DOC" "only closed weekly reward epochs can be finalized" "closed-week finalize guard"
require_contains "$LOCAL_API_DOC" "weekly reward has active holds and cannot be finalized" "active-hold finalize guard"
require_contains "$LOCAL_API_DOC" "trusted traffic proof is required before weekly reward finalization" "trusted-proof finalize guard"
require_contains "$LOCAL_API_DOC" "objective signed or chain-queryable traffic proof evidence" "production objective traffic-proof evidence guard"
require_contains "$LOCAL_API_DOC" "not just env-derived trusted status" "production traffic-proof env-derived trust rejection"
require_contains "$LOCAL_API_DOC" "slashing_hold_integration=local_settlement_slash_evidence" "local slash-evidence hold integration marker"
require_contains "$LOCAL_API_DOC" "synthetic \`slashing_evidence\` holds are not cleared by manual hold release" "non-releaseable slash hold semantics"
require_contains "$LOCAL_API_DOC" "idempotent_replay=true" "idempotent finalize replay marker"
require_contains "$LOCAL_API_DOC" "status=finalized_chain_confirmed" "chain-confirmed reward status"
require_contains "$LOCAL_API_DOC" "settlement_finalization_state=chain_confirmed" "chain-confirmed finalization state"
require_contains "$LOCAL_API_DOC" "status=finalized_pending_chain_submission" "pending chain submission status"
require_contains "$LOCAL_API_DOC" "settlement_finalization_state=pending_chain_submission" "pending chain submission finalization state"
require_contains "$LOCAL_API_DOC" "status=finalized_pending_chain_confirmation" "pending chain confirmation status"
require_contains "$LOCAL_API_DOC" "settlement_finalization_state=pending_chain_confirmation" "pending chain confirmation finalization state"
require_contains "$LOCAL_API_DOC" "status=finalization_failed" "chain failed reward status"
require_contains "$LOCAL_API_DOC" "settlement_finalization_state=chain_failed" "chain failed finalization state"
require_contains "$GPM_TRACK_DOC" "keeps chain-pending settlement states non-payable until the chain confirms" "GPM track chain-pending payout semantics"
require_contains "$GPM_TRACK_DOC" "objective signed or chain-queryable traffic proof evidence in production" "GPM track production objective traffic-proof evidence"
require_contains "$GPM_TRACK_DOC" "local settlement slash evidence is now read into Admin Console review/finalize" "GPM track local slash hold semantics"

echo "[gpm-admin-settlement-contract] roadmap/status docs cross-links"
require_contains "$GPM_STATUS_DOC" "scripts/integration_gpm_admin_settlement_contract.sh" "status docs contract script reference"
require_contains "$GPM_STATUS_DOC" "scripts/linux/desktop_admin_console_release_bundle.sh" "status dedicated admin console bundle script reference"
require_contains "$GPM_STATUS_DOC" "slashing_hold_integration=local_settlement_slash_evidence" "status local slash evidence integration marker"
require_contains "$PRODUCT_ROADMAP_DOC" "scripts/integration_gpm_admin_settlement_contract.sh" "roadmap docs contract script reference"
require_contains "$PRODUCT_ROADMAP_DOC" "objective signed or chain-queryable traffic proof evidence in production" "roadmap production objective traffic-proof evidence"
require_contains "$PRODUCT_ROADMAP_DOC" "no local settlement slash-evidence holds" "roadmap local slash hold finalize guard"
require_contains "$PRODUCT_ROADMAP_DOC" "chain-pending rewards non-payable until confirmation" "roadmap chain-pending semantics"

if [[ "$run_go_tests" == "1" ]]; then
  if ! command -v go >/dev/null 2>&1; then
    echo "missing required command for executable admin settlement contract: go"
    exit 2
  fi

  echo "[gpm-admin-settlement-contract] executable local API payout/slash/finality regressions"
  go test ./services/localapi -run 'TestGPMAdminRewardReviewAndFinalizeHoldChainSlashEvidence|TestGPMAdminRewardFinalizeIdempotentReplayReconcilesChainStatus|TestGPMAdminRewardFinalizeReplayRequiresTrustedTrafficProof|TestGPMAdminRewardFinalizeReplayRejectsMaterialDrift|TestGPMAdminRewardFinalizeProductionRejectsTrustedCounterWithoutObjectiveProofRef|TestGPMAdminRewardFinalizeProductionRejectsFormatOnlyTrafficProofRef|TestGPMAdminRewardFinalizeProductionFailsClosedWithoutChainAdapter|TestGPMSettlementCosmosEnvWiringProductionFinalizesViaChainAdapter' -count=1

  echo "[gpm-admin-settlement-contract] executable settlement proof/slash/finality regressions"
  go test ./pkg/settlement -run 'TestMemoryServiceIssueRewardRequiresProofReferenceInBlockchainMode|TestMemoryServiceReconcileVerifiesTrafficProofBeforeRewardFinalization|TestMemoryServiceReconcileKeepsSubmittedWhenChainStatusIsNotFinal|TestMemoryServiceIssueRewardEnforcesWeeklyPayoutUniqueness|TestMemoryServiceListSlashEvidenceMergesChainEvidence|TestMemoryServiceListSlashEvidenceFailsClosedInBlockchainModeWithoutChainLister|TestMemoryServiceSubmitSlashEvidenceRejectsDuplicateIncidentDifferentID|TestMemoryServiceSubmitSlashEvidenceRequiresObjectiveSchema' -count=1
else
  echo "[gpm-admin-settlement-contract] executable Go regressions skipped by GPM_ADMIN_SETTLEMENT_CONTRACT_RUN_GO_TESTS=0"
fi

echo "gpm admin settlement contract ok"
