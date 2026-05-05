#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

# Issuer shadow env wiring:
# - HTTP mirror to shadow
# - signed-tx shadow env wiring
# - fail-open when shadow init fails
timeout 30s go test ./services/issuer -count=1 -run '^(TestNewSettlementServiceFromEnvCosmosShadowMirrorsSponsorReservationToPrimaryAndShadow|TestNewSettlementServiceFromEnvCosmosShadowSignedTxModeUsesShadowEnv|TestNewSettlementServiceFromEnvCosmosShadowInitFailureDoesNotBreakPrimary)$'

# Exit shadow env wiring:
# - HTTP mirror to shadow
# - signed-tx shadow init fail-open behavior
timeout 30s go test ./services/exit -count=1 -run '^(TestNewSettlementServiceFromEnvCosmosShadowAdapterMirrorsSubmissions|TestNewSettlementServiceFromEnvCosmosShadowAdapterSignedTxModeUsesShadowEnv|TestNewSettlementServiceFromEnvCosmosShadowAdapterInitFailureDoesNotBlockPrimary)$'

echo "cosmos settlement shadow env integration check ok"
