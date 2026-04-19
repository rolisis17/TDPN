#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CHAIN_DIR="blockchain/tdpn-chain"

required=(
  "$CHAIN_DIR/buf.yaml"
  "$CHAIN_DIR/buf.gen.yaml"
  "$CHAIN_DIR/scripts/gen_proto.sh"
)

for f in "${required[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "missing required proto toolchain file: $f"
    exit 1
  fi
done

bash -n "$CHAIN_DIR/scripts/gen_proto.sh"

if command -v buf >/dev/null 2>&1; then
  (
    cd "$CHAIN_DIR"
    timeout 60s ./scripts/gen_proto.sh --lint-only
  )
else
  set +e
  out="$(cd "$CHAIN_DIR" && ./scripts/gen_proto.sh --lint-only 2>&1)"
  code=$?
  set -e
  if [[ $code -eq 0 ]]; then
    echo "expected gen_proto.sh to fail without buf installed"
    exit 1
  fi
  if ! grep -q "buf' CLI is not installed" <<<"$out"; then
    echo "unexpected gen_proto.sh failure output without buf:"
    echo "$out"
    exit 1
  fi
fi

generated_checks=(
  "$CHAIN_DIR/proto/gen/go/tdpn/vpnbilling/v1/query_grpc.pb.go:ListCreditReservations"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpnbilling/v1/query_grpc.pb.go:ListSettlementRecords"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpnrewards/v1/query_grpc.pb.go:ListRewardAccruals"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpnrewards/v1/query_grpc.pb.go:ListDistributionRecords"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpnslashing/v1/query_grpc.pb.go:ListSlashEvidence"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpnslashing/v1/query_grpc.pb.go:ListPenaltyDecisions"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpnsponsor/v1/query_grpc.pb.go:ListSponsorAuthorizations"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpnsponsor/v1/query_grpc.pb.go:ListDelegatedSessionCredits"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpnvalidator/v1/query_grpc.pb.go:ListValidatorEligibilities"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpnvalidator/v1/query_grpc.pb.go:ListValidatorStatusRecords"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpnvalidator/v1/query_grpc.pb.go:PreviewEpochSelection"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpngovernance/v1/query_grpc.pb.go:ListGovernancePolicies"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpngovernance/v1/query_grpc.pb.go:ListGovernanceDecisions"
  "$CHAIN_DIR/proto/gen/go/tdpn/vpngovernance/v1/query_grpc.pb.go:ListGovernanceAuditActions"
)

for check in "${generated_checks[@]}"; do
  file="${check%%:*}"
  symbol="${check##*:}"
  if [[ ! -f "$file" ]]; then
    echo "missing generated proto grpc surface file: $file"
    exit 1
  fi
  if ! rg -q "$symbol" "$file"; then
    echo "generated proto grpc surface missing symbol $symbol in $file"
    exit 1
  fi
done

echo "cosmos proto codegen surface integration check ok"
