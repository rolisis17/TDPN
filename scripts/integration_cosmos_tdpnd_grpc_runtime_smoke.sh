#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

(
  cd blockchain/tdpn-chain
  timeout 60s go test ./cmd/tdpnd -count=1 -run '^(TestRunTDPNDGRPCModeInvalidTLSFlagCombinations|TestRunTDPNDGRPCModeListenError|TestRunTDPNDGRPCModeRegisterErrorClosesListener|TestRunTDPNDGRPCModeGracefulShutdownOnContextCancel|TestRunTDPNDGRPCModeRegistersHealthAndReflection|TestRunTDPNDGRPCModeAuthEnforcementAndHealth|TestRunTDPNDGRPCModeRealScaffoldValidatorAndGovernanceRoundTrip|TestRunTDPNDGRPCModeProcessRuntimeSmoke|TestRunTDPNDGRPCMode.*Process.*|TestRunTDPNDGRPCMode.*TLS.*)$'
)

echo "cosmos tdpnd grpc runtime smoke integration check ok"
