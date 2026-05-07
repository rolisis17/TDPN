#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

TMP_DIR="$(mktemp -d)"
ADMIN_TOKEN="integration-admin-token"
DIR_PORT=19361
ISSUER_PORT=19362
DIR_URL="http://127.0.0.1:${DIR_PORT}"
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}"
ISSUER_LOG="$TMP_DIR/adjudication_op_quorum_issuer.log"
DIRECTORY_LOG="$TMP_DIR/adjudication_op_quorum_directory.log"

cleanup() {
  kill "${issuer_pid:-}" "${directory_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_URL="$ISSUER_URL" \
ISSUER_ADMIN_TOKEN="$ADMIN_TOKEN" \
ISSUER_PRIVATE_KEY_FILE="$TMP_DIR/issuer.key" \
ISSUER_SUBJECTS_FILE="$TMP_DIR/issuer_subjects.json" \
ISSUER_REVOCATIONS_FILE="$TMP_DIR/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$TMP_DIR/issuer_anon_revocations.json" \
ISSUER_AUDIT_FILE="$TMP_DIR/issuer_audit.json" \
ISSUER_TRUST_OPERATOR_ID="issuer-op-a" \
timeout 90s go run ./cmd/node --issuer >"$ISSUER_LOG" 2>&1 &
issuer_pid=$!

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
DIRECTORY_PUBLIC_URL="$DIR_URL" \
DIRECTORY_ADMIN_TOKEN="$ADMIN_TOKEN" \
DIRECTORY_PRIVATE_KEY_FILE="$TMP_DIR/directory.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_replay.json" \
DIRECTORY_ISSUER_TRUST_URLS="$ISSUER_URL" \
DIRECTORY_ISSUER_SYNC_SEC=1 \
DIRECTORY_ISSUER_TRUST_MIN_VOTES=1 \
DIRECTORY_ISSUER_DISPUTE_MIN_VOTES=1 \
DIRECTORY_FINAL_DISPUTE_MIN_VOTES=1 \
DIRECTORY_FINAL_APPEAL_MIN_VOTES=1 \
DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS=2 \
DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO=0 \
timeout 90s go run ./cmd/node --directory >"$DIRECTORY_LOG" 2>&1 &
directory_pid=$!

sleep 2

curl -fsS -X POST "${ISSUER_URL}/v1/admin/subject/upsert" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{"subject":"exit-local-1","tier":3,"reputation":0.95,"bond":550}' >"$TMP_DIR/adjudication_op_quorum_upsert.json"

dispute_until=$(( $(date +%s) + 3600 ))
curl -fsS -X POST "${ISSUER_URL}/v1/admin/subject/dispute" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data "{\"subject\":\"exit-local-1\",\"tier_cap\":1,\"until\":${dispute_until},\"case_id\":\"case-operator-quorum\",\"evidence_ref\":\"evidence://operator-quorum\"}" >"$TMP_DIR/adjudication_op_quorum_dispute.json"

status_json=""
for _ in $(seq 1 40); do
  status_json="$(curl -fsS "${DIR_URL}/v1/admin/governance-status" -H "X-Admin-Token: ${ADMIN_TOKEN}" || true)"
  if echo "$status_json" | rg -q '"final_adjudication_min_operators":2'; then
    break
  fi
  sleep 0.25
done

if [[ -z "$status_json" ]]; then
  echo "expected governance status response"
  cat "$DIRECTORY_LOG"
  cat "$ISSUER_LOG"
  exit 1
fi
if ! echo "$status_json" | rg -q '"aggregated_disputed":0'; then
  echo "expected disputed count suppressed by operator quorum"
  echo "$status_json"
  cat "$DIRECTORY_LOG"
  cat "$ISSUER_LOG"
  exit 1
fi

feed_json=""
for _ in $(seq 1 40); do
  feed_json="$(curl -fsS "${DIR_URL}/v1/trust-attestations" || true)"
  if echo "$feed_json" | rg -q '"relay_id":"exit-local-1"'; then
    break
  fi
  sleep 0.25
done

if [[ -z "$feed_json" ]]; then
  echo "expected trust feed response"
  cat "$DIRECTORY_LOG"
  cat "$ISSUER_LOG"
  exit 1
fi
if ! echo "$feed_json" | rg -q '"relay_id":"exit-local-1"'; then
  echo "expected relay attestation for exit-local-1"
  echo "$feed_json"
  cat "$DIRECTORY_LOG"
  cat "$ISSUER_LOG"
  exit 1
fi
if echo "$feed_json" | rg -q '"dispute_until":[0-9]+'; then
  echo "expected dispute window omitted because final operator quorum not met"
  echo "$feed_json"
  cat "$DIRECTORY_LOG"
  cat "$ISSUER_LOG"
  exit 1
fi

echo "adjudication operator quorum integration check ok"
