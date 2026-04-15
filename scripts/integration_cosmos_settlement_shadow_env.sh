#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

# Issuer shadow env wiring: mirror to shadow + fail-open when shadow init fails.
timeout 30s go test ./services/issuer -count=1 -run '^(TestNewSettlementServiceFromEnvCosmosShadowMirrorsSponsorReservationToPrimaryAndShadow|TestNewSettlementServiceFromEnvCosmosShadowInitFailureDoesNotBreakPrimary)$'

# Exit shadow env wiring: mirror to shadow + fail-open when shadow init fails.
timeout 30s go test ./services/exit -count=1 -run '^(TestNewSettlementServiceFromEnvCosmosShadowAdapterMirrorsSubmissions|TestNewSettlementServiceFromEnvCosmosShadowAdapterInitFailureDoesNotBlockPrimary)$'

echo "cosmos settlement shadow env integration check ok"
