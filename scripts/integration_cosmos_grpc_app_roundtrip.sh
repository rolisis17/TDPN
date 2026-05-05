#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

(
  cd blockchain/tdpn-chain
  timeout 60s go test ./app -count=1 -run '^(TestRegisterGRPCServicesNilInputs|TestRegisterGRPCServicesBillingAndSponsorRoundTrip|TestRegisterGRPCServicesSlashingViolationTypeRoundTrip|TestRegisterGRPCServicesValidatorAndGovernanceRoundTrip|TestRegisterGRPCServicesValidatorGovernanceRoundTrip)$'
)

echo "cosmos grpc app roundtrip integration check ok"
