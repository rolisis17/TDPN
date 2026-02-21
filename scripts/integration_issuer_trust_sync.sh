#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

DIRECTORY_ISSUER_TRUST_URLS="http://127.0.0.1:8082" \
DIRECTORY_ISSUER_SYNC_SEC=1 \
EXIT_BOND_SCORE=0 \
EXIT_STAKE_SCORE=0 \
timeout 25s go run ./cmd/node --directory --issuer --entry --exit >/tmp/issuer_trust_sync_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 2

curl -fsS -X POST http://127.0.0.1:8082/v1/admin/subject/upsert \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data '{"subject":"exit-local-1","tier":1,"reputation":0.9,"bond":500}' >/tmp/issuer_trust_sync_admin.log

found=0
for _ in $(seq 1 12); do
  curl -fsS http://127.0.0.1:8081/v1/trust-attestations >/tmp/issuer_trust_sync_feed.json || true
  if rg -q '"relay_id":"exit-local-1"' /tmp/issuer_trust_sync_feed.json && rg -q '"bond_score":0.5' /tmp/issuer_trust_sync_feed.json; then
    found=1
    break
  fi
  sleep 1
done

if [[ "$found" -ne 1 ]]; then
  echo "expected directory trust feed to reflect issuer-backed bond signal"
  cat /tmp/issuer_trust_sync_feed.json
  cat /tmp/issuer_trust_sync_node.log
  exit 1
fi

echo "issuer trust sync integration check ok"
