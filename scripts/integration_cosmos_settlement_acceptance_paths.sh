#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

# Sponsor happy-path coverage: reserve -> authorize -> issue token.
timeout 30s go test ./pkg/settlement -count=1 -run '^(TestMemoryServiceSponsorFlowAuthorizeIdempotent)$'
timeout 30s go test ./services/issuer -count=1 -run '^(TestSponsorReserveAndIssueTokenFlow|TestHandleIssueTokenRequiresPaymentProofWhenEnabled)$'

# Chain-outage fail-soft coverage: defer on adapter failure and keep close/status paths non-blocking.
timeout 30s go test ./pkg/settlement -count=1 -run '^(TestMemoryServiceAdapterDeferredOnFailure|TestMemoryServiceReconcileReplaySuccessClearsBacklog)$'
timeout 30s go test ./services/exit -count=1 -run '^(TestSettlementReserveAndFinalizeWarningsDoNotBlockSessionClose|TestHandlePathCloseDeferredChainAdapterDoesNotBlockSessionClose|TestHandleSettlementStatusReconcileErrorIsFailSoft)$'

# Dual-asset pricing surface coverage: stable-denominated baseline plus native-token conversion.
timeout 30s go test ./pkg/settlement -count=1 -run '^(TestMemoryServiceQuotePriceCurrencyConversion|TestMemoryServiceSettleSessionCurrencyConversion)$'

echo "cosmos settlement acceptance paths integration check ok"
