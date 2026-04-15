#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

TEST_REGEX='^(TestRunTDPNDSettlementHTTPHealth|TestRunTDPNDSettlementHTTPAuthRequiredOnPOST|TestRunTDPNDSettlementHTTPAuthContractGETOpenPOSTBearerRequired|TestRunTDPNDSettlementHTTPHappyPathPerEndpoint|TestRunTDPNDSettlementHTTPValidatorGovernanceWriteMethodContract|TestRunTDPNDSettlementHTTPQueryHappyPathAndLists|TestRunTDPNDSettlementHTTPQueryNotFoundByID|TestRunTDPNDSettlementHTTPGETQueriesRemainOpenWithAuth|TestRunTDPNDGRPCAndSettlementHTTPTogether)$'

(
  cd blockchain/tdpn-chain
  timeout 60s go test ./cmd/tdpnd -count=1 -run "${TEST_REGEX}"
)

echo "cosmos tdpnd settlement bridge smoke integration check ok"
