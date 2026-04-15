#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CHAIN_DIR="blockchain/tdpn-chain"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

if ! grep -Eq 'github\.com/tdpn/tdpn-chain/proto/gen/go[[:space:]]+v0\.0\.0' "$CHAIN_DIR/go.mod"; then
  echo "missing go.mod require for local proto module in $CHAIN_DIR/go.mod"
  exit 1
fi

if ! grep -Eq '^replace[[:space:]]+github.com/tdpn/tdpn-chain/proto/gen/go[[:space:]]+=>[[:space:]]+\./proto/gen/go$' "$CHAIN_DIR/go.mod"; then
  echo "missing go.mod replace for local proto module in $CHAIN_DIR/go.mod"
  exit 1
fi

(
  cd "$CHAIN_DIR"
  tmp_mod="$(mktemp .tmp-proto-grpc-mod.XXXXXX.mod)"
  tmp_sum="${tmp_mod%.mod}.sum"
  cp go.mod "$tmp_mod"
  trap 'rm -f "$tmp_mod" "$tmp_sum"' EXIT
  GOFLAGS="-mod=mod -modfile=$tmp_mod" timeout 60s go test -run '^$' \
    github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnbilling/v1 \
    github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnrewards/v1 \
    github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnslashing/v1 \
    github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnsponsor/v1
  rm -f "$tmp_mod" "$tmp_sum"
  trap - EXIT
)

for mod in vpnbilling vpnrewards vpnslashing vpnsponsor; do
  tx_file="$CHAIN_DIR/proto/gen/go/tdpn/$mod/v1/tx_grpc.pb.go"
  query_file="$CHAIN_DIR/proto/gen/go/tdpn/$mod/v1/query_grpc.pb.go"

  if [[ ! -f "$tx_file" ]]; then
    echo "missing generated grpc tx file: $tx_file"
    exit 1
  fi
  if [[ ! -f "$query_file" ]]; then
    echo "missing generated grpc query file: $query_file"
    exit 1
  fi

  if ! grep -q 'func RegisterMsgServer' "$tx_file"; then
    echo "missing RegisterMsgServer in $tx_file"
    exit 1
  fi
  if ! grep -q 'func RegisterQueryServer' "$query_file"; then
    echo "missing RegisterQueryServer in $query_file"
    exit 1
  fi
done

echo "cosmos proto grpc surface integration check ok"
