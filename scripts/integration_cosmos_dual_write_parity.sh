#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash go timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

TEST_TIMEOUT="${COSMOS_DUAL_WRITE_PARITY_TIMEOUT:-45s}"
if [[ -z "$TEST_TIMEOUT" ]]; then
  echo "invalid COSMOS_DUAL_WRITE_PARITY_TIMEOUT: value cannot be empty"
  exit 2
fi

run_go_test() {
  local stage="$1"
  local pkg="$2"
  local test_regex="$3"

  echo "[cosmos-dual-write-parity] stage=${stage} timeout=${TEST_TIMEOUT}"
  set +e
  timeout "$TEST_TIMEOUT" go test "$pkg" -count=1 -run "$test_regex"
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "[cosmos-dual-write-parity] stage=${stage} status=fail rc=${rc}"
    exit $rc
  fi
  echo "[cosmos-dual-write-parity] stage=${stage} status=pass"
}

run_go_test_in_chain_workspace() {
  local stage="$1"
  local pkg="$2"
  local test_regex="$3"

  echo "[cosmos-dual-write-parity] stage=${stage} timeout=${TEST_TIMEOUT}"
  set +e
  (
    cd blockchain/tdpn-chain
    timeout "$TEST_TIMEOUT" go test "$pkg" -count=1 -run "$test_regex"
  )
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "[cosmos-dual-write-parity] stage=${stage} status=fail rc=${rc}"
    exit $rc
  fi
  echo "[cosmos-dual-write-parity] stage=${stage} status=pass"
}

# Settlement adapter replay + idempotency parity slice.
run_go_test \
  "settlement-adapter-replay-idempotency" \
  "./pkg/settlement" \
  '^(TestCosmosAdapterFailureAfterEnqueueTransitionsToDeferredReplayable|TestCosmosAdapterCloseDrainsBacklogToDeferred|TestMemoryServiceReconcileReplayIsIdempotentAcrossRepeatedCalls|TestMemoryServiceCosmosAdapterAsyncFailureAfterEnqueueReplaysAndConfirms)$'

# Issuer payment-proof integrity parity slice.
run_go_test \
  "issuer-payment-proof-integrity" \
  "./services/issuer" \
  '^(TestIssueEndpointsValidateProvidedPaymentProofWhenGloballyOptional|TestIssueEndpointsPaymentProofEmptySubjectFallsBackToRequestSubject|TestSponsorIssueTokenRejectsPaymentProofMismatches|TestIssueEndpointsRejectRequestAndPaymentProofSubjectMismatch|TestSponsorIssueTokenRejectsExpiredPaymentReservation|TestSponsorIssueTokenAllowsDuplicatePaymentProofReplay)$'

# Chain settlement bridge identity mapping parity slice.
run_go_test_in_chain_workspace \
  "chain-settlement-bridge-mapping" \
  "./cmd/tdpnd" \
  '^(TestRunTDPNDSettlementHTTPSponsorIdentityMappingDistinctAppAndEndUser|TestRunTDPNDSettlementHTTPSponsorIdentityMappingLegacySubjectFallback)$'

echo "cosmos dual-write parity integration check ok"
