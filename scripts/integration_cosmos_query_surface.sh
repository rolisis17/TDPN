#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

(
  cd blockchain/tdpn-chain
  timeout 30s go test ./x/vpnbilling/module -count=1 -run 'QueryServer'
  timeout 30s go test ./x/vpnrewards/module -count=1 -run 'QueryServer'
  timeout 30s go test ./x/vpnslashing/module -count=1 -run 'QueryServer'
  timeout 30s go test ./x/vpnsponsor/module -count=1 -run 'QueryServer'
  timeout 30s go test ./app -count=1 -run 'QueryServer'
)

echo "cosmos query surface integration check ok"
