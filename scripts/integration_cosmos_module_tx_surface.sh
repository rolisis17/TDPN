#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

(
  cd blockchain/tdpn-chain
  timeout 30s go test ./x/vpnbilling/keeper -count=1
  timeout 30s go test ./x/vpnbilling/module -count=1
  timeout 30s go test ./x/vpnrewards/keeper -count=1
  timeout 30s go test ./x/vpnrewards/module -count=1
  timeout 30s go test ./x/vpnslashing/keeper -count=1
  timeout 30s go test ./x/vpnslashing/module -count=1
  timeout 30s go test ./x/vpnsponsor/keeper -count=1
  timeout 30s go test ./x/vpnsponsor/module -count=1
  timeout 30s go test ./x/vpnvalidator/keeper -count=1
  timeout 30s go test ./x/vpnvalidator/module -count=1
  timeout 30s go test ./x/vpngovernance/keeper -count=1
  timeout 30s go test ./x/vpngovernance/module -count=1
)

echo "cosmos module tx surface integration check ok"
