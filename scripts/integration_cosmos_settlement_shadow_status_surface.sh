#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

# Issuer status surface (fresh backlog + fresh ok) includes shadow telemetry fields.
timeout 30s go test ./services/issuer -count=1 -run '^(TestHandleSettlementStatusIncludesLifecycleCounters|TestHandleSettlementStatusIncludesConfirmedCounterWhenNoBacklog)$'

# Exit status surface includes fresh and fail-soft/stale shadow telemetry paths.
timeout 30s go test ./services/exit -count=1 -run '^(TestHandleSettlementStatusReturnsReport|TestHandleSettlementStatusReconcileErrorIsFailSoft)$'

echo "cosmos settlement shadow status surface integration check ok"
