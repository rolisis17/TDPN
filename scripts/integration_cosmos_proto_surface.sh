#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PROTO_ROOT="blockchain/tdpn-chain/proto"
if [[ ! -d "$PROTO_ROOT" ]]; then
  echo "missing proto root: $PROTO_ROOT"
  exit 1
fi

required=(
  "tdpn/vpnbilling/v1/types.proto"
  "tdpn/vpnbilling/v1/tx.proto"
  "tdpn/vpnbilling/v1/query.proto"
  "tdpn/vpnrewards/v1/types.proto"
  "tdpn/vpnrewards/v1/tx.proto"
  "tdpn/vpnrewards/v1/query.proto"
  "tdpn/vpnslashing/v1/types.proto"
  "tdpn/vpnslashing/v1/tx.proto"
  "tdpn/vpnslashing/v1/query.proto"
  "tdpn/vpnsponsor/v1/types.proto"
  "tdpn/vpnsponsor/v1/tx.proto"
  "tdpn/vpnsponsor/v1/query.proto"
)

for rel in "${required[@]}"; do
  f="$PROTO_ROOT/$rel"
  if [[ ! -f "$f" ]]; then
    echo "missing required proto file: $f"
    exit 1
  fi
  if ! rg -q '^syntax = "proto3";' "$f"; then
    echo "proto missing proto3 syntax declaration: $f"
    exit 1
  fi
  if ! rg -q '^option go_package = ' "$f"; then
    echo "proto missing go_package option: $f"
    exit 1
  fi
done

for mod in vpnbilling vpnrewards vpnslashing vpnsponsor; do
  tx="$PROTO_ROOT/tdpn/$mod/v1/tx.proto"
  query="$PROTO_ROOT/tdpn/$mod/v1/query.proto"
  if ! rg -q '^service Msg \{' "$tx"; then
    echo "tx proto missing Msg service: $tx"
    exit 1
  fi
  if ! rg -q '^service Query \{' "$query"; then
    echo "query proto missing Query service: $query"
    exit 1
  fi
done

# Ensure list RPCs stay aligned with module query list surfaces.
if ! rg -q 'rpc ListCreditReservations\(QueryListCreditReservationsRequest\) returns \(QueryListCreditReservationsResponse\);' "$PROTO_ROOT/tdpn/vpnbilling/v1/query.proto"; then
  echo "vpnbilling query proto missing ListCreditReservations RPC"
  exit 1
fi
if ! rg -q 'rpc ListSettlementRecords\(QueryListSettlementRecordsRequest\) returns \(QueryListSettlementRecordsResponse\);' "$PROTO_ROOT/tdpn/vpnbilling/v1/query.proto"; then
  echo "vpnbilling query proto missing ListSettlementRecords RPC"
  exit 1
fi

if ! rg -q 'rpc ListRewardAccruals\(QueryListRewardAccrualsRequest\) returns \(QueryListRewardAccrualsResponse\);' "$PROTO_ROOT/tdpn/vpnrewards/v1/query.proto"; then
  echo "vpnrewards query proto missing ListRewardAccruals RPC"
  exit 1
fi
if ! rg -q 'rpc ListDistributionRecords\(QueryListDistributionRecordsRequest\) returns \(QueryListDistributionRecordsResponse\);' "$PROTO_ROOT/tdpn/vpnrewards/v1/query.proto"; then
  echo "vpnrewards query proto missing ListDistributionRecords RPC"
  exit 1
fi

if ! rg -q 'rpc ListSlashEvidence\(QueryListSlashEvidenceRequest\) returns \(QueryListSlashEvidenceResponse\);' "$PROTO_ROOT/tdpn/vpnslashing/v1/query.proto"; then
  echo "vpnslashing query proto missing ListSlashEvidence RPC"
  exit 1
fi
if ! rg -q 'rpc ListPenaltyDecisions\(QueryListPenaltyDecisionsRequest\) returns \(QueryListPenaltyDecisionsResponse\);' "$PROTO_ROOT/tdpn/vpnslashing/v1/query.proto"; then
  echo "vpnslashing query proto missing ListPenaltyDecisions RPC"
  exit 1
fi

if ! rg -q 'rpc ListSponsorAuthorizations\(QueryListSponsorAuthorizationsRequest\) returns \(QueryListSponsorAuthorizationsResponse\);' "$PROTO_ROOT/tdpn/vpnsponsor/v1/query.proto"; then
  echo "vpnsponsor query proto missing ListSponsorAuthorizations RPC"
  exit 1
fi
if ! rg -q 'rpc ListDelegatedSessionCredits\(QueryListDelegatedSessionCreditsRequest\) returns \(QueryListDelegatedSessionCreditsResponse\);' "$PROTO_ROOT/tdpn/vpnsponsor/v1/query.proto"; then
  echo "vpnsponsor query proto missing ListDelegatedSessionCredits RPC"
  exit 1
fi

echo "cosmos proto surface integration check ok"
