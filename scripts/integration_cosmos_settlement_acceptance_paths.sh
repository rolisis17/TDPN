#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

# Sponsor happy-path coverage: reserve -> authorize -> issue token.
timeout 30s go test ./pkg/settlement -count=1 -run '^(TestMemoryServiceSponsorFlowAuthorizeIdempotent)$'
timeout 30s go test ./services/issuer -count=1 -run '^(TestSponsorReserveAndIssueTokenFlow|TestHandleIssueTokenRequiresPaymentProofWhenEnabled)$'
timeout 90s ./scripts/integration_issuer_sponsor_api_live_smoke.sh

# Chain-outage fail-soft coverage: defer on adapter failure, replay to submitted, then confirm lifecycle advancement.
timeout 30s go test ./pkg/settlement -count=1 -run '^(TestMemoryServiceAdapterDeferredOnFailure|TestMemoryServiceReconcileReplaySuccessClearsBacklog|TestMemoryServiceReconcileReplayPromotesToConfirmedWhenQuerierAvailable)$'
timeout 30s go test ./services/exit -count=1 -run '^(TestSettlementReserveAndFinalizeWarningsDoNotBlockSessionClose|TestHandlePathCloseDeferredChainAdapterDoesNotBlockSessionClose|TestHandleSettlementStatusReconcileErrorIsFailSoft)$'

# Dual-asset pricing coverage: stable-denominated baseline plus native-token conversion/equivalence.
timeout 30s go test ./pkg/settlement -count=1 -run '^(TestMemoryServiceQuotePriceCurrencyConversion|TestMemoryServiceSettleSessionCurrencyConversion|TestMemoryServiceDualAssetSessionEntitlementEquivalence)$'
timeout 30s go test ./services/issuer -count=1 -run '^(TestNewSettlementServiceFromEnvCurrencyBaseFromEnv|TestNewSettlementServiceFromEnvDualNativeCurrencyConversion)$'
timeout 30s go test ./services/exit -count=1 -run '^(TestSettlementServiceFromEnvCurrencyNativeDualQuoteBehavior|TestSettlementServiceFromEnvDualNativeCurrencySettlementCoherence)$'

echo "cosmos settlement acceptance paths integration check ok"
