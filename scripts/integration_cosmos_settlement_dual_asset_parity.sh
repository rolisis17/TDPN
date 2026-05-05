#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

timeout 25s go test ./pkg/settlement -count=1 -run '^(TestMemoryServiceQuotePriceCurrencyConversion|TestMemoryServiceSettleSessionCurrencyConversion|TestMemoryServiceDualAssetSessionEntitlementEquivalence)$'

timeout 25s go test ./services/issuer -count=1 -run '^(TestNewSettlementServiceFromEnvCurrencyBaseFromEnv|TestNewSettlementServiceFromEnvDualNativeCurrencyConversion)$'

timeout 25s go test ./services/exit -count=1 -run '^(TestSettlementServiceFromEnvCurrencyNativeDualQuoteBehavior|TestSettlementServiceFromEnvDualNativeCurrencySettlementCoherence)$'

echo "cosmos settlement dual-asset parity integration check ok"
