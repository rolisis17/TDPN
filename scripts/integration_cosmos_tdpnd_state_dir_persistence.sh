#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

(
  cd blockchain/tdpn-chain
  timeout 60s go test ./app -count=1 -run '^(TestNewChainScaffoldWithStateDirPersistsAcrossReopen|TestChainScaffoldConfigureStateDirRequiresPath)$'
  timeout 60s go test ./cmd/tdpnd -count=1 -run '^(TestRunTDPNDConfiguresStateDirWhenSupported|TestRunTDPNDStateDirRequiresConfigurableScaffold|TestRunTDPNDStateDirConfigErrorPropagates)$'
)

echo "cosmos tdpnd state-dir persistence integration check ok"
