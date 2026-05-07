#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

TMP_DIR="$(mktemp -d)"
NODE_LOG="$TMP_DIR/issuer_trust_sync_node.log"
ADMIN_LOG="$TMP_DIR/issuer_trust_sync_admin.log"
FEED_JSON="$TMP_DIR/issuer_trust_sync_feed.json"
ADMIN_TOKEN="integration-admin-token"

DIR_PORT=19301
ISSUER_PORT=19302
EXIT_PORT=19304
EXIT_DATA_PORT=20301
EXIT_WG_PORT=20302

cleanup() {
  kill "${node_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_ISSUER_TRUST_URLS="http://127.0.0.1:${ISSUER_PORT}" \
DIRECTORY_ISSUER_SYNC_SEC=1 \
DIRECTORY_PRIVATE_KEY_FILE="$TMP_DIR/directory.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_replay.json" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ISSUER_ADMIN_TOKEN="$ADMIN_TOKEN" \
ISSUER_PRIVATE_KEY_FILE="$TMP_DIR/issuer.key" \
ISSUER_SUBJECTS_FILE="$TMP_DIR/issuer_subjects.json" \
ISSUER_REVOCATIONS_FILE="$TMP_DIR/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$TMP_DIR/issuer_anon_revocations.json" \
EXIT_ADDR="127.0.0.1:${EXIT_PORT}" \
EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}" \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
EXIT_ENDPOINT="127.0.0.1:${EXIT_DATA_PORT}" \
EXIT_WG_LISTEN_PORT="$EXIT_WG_PORT" \
EXIT_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/exit_token_replay.json" \
EXIT_BOND_SCORE=0 \
EXIT_STAKE_SCORE=0 \
timeout 25s go run ./cmd/node --directory --issuer --exit >"$NODE_LOG" 2>&1 &
node_pid=$!

sleep 2

curl -fsS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/subject/upsert" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{"subject":"exit-local-1","tier":1,"reputation":0.9,"bond":500}' >"$ADMIN_LOG"

found=0
for _ in $(seq 1 12); do
  curl -fsS "http://127.0.0.1:${DIR_PORT}/v1/trust-attestations" >"$FEED_JSON" || true
  if rg -q '"relay_id":"exit-local-1"' "$FEED_JSON" && rg -q '"bond_score":0.5' "$FEED_JSON"; then
    found=1
    break
  fi
  sleep 1
done

if [[ "$found" -ne 1 ]]; then
  echo "expected directory trust feed to reflect issuer-backed bond signal"
  cat "$FEED_JSON"
  cat "$NODE_LOG"
  exit 1
fi

echo "issuer trust sync integration check ok"
