#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

(
  cd blockchain/tdpn-chain
  timeout 30s go test ./x/vpnbilling/keeper -count=1
  timeout 30s go test ./x/vpnbilling/types -count=1
  timeout 30s go test ./x/vpnbilling/module -count=1
)

timeout 30s go test ./pkg/settlement -count=1 -run '^(TestCosmosAdapterSubmitsSettlementWithIdempotencyKey|TestCosmosAdapterSignedTxModeSubmitsBroadcast)$'
timeout 30s go test ./services/issuer -count=1 -run '^(TestNewSettlementServiceFromEnvCosmosSignedTxModeForwardsEnv)$'
timeout 30s go test ./services/exit -count=1 -run '^(TestNewSettlementServiceFromEnvCosmosSignedTxModeUsesConfiguredFields)$'

echo "cosmos vpnbilling tx integration check ok"
