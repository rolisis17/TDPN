#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

DIR_PORT=8141
ISSUER_PORT=8142

ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_PRIVATE_KEY_FILE="data/issuer_op_quorum_ed25519.key" \
ISSUER_SUBJECTS_FILE="data/issuer_op_quorum_subjects.json" \
ISSUER_REVOCATIONS_FILE="data/issuer_op_quorum_revocations.json" \
ISSUER_TRUST_OPERATOR_ID="issuer-op-a" \
timeout 90s go run ./cmd/node --issuer >/tmp/adjudication_op_quorum_issuer.log 2>&1 &
issuer_pid=$!

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE="data/directory_op_quorum_ed25519.key" \
DIRECTORY_ISSUER_TRUST_URLS="http://127.0.0.1:${ISSUER_PORT}" \
DIRECTORY_ISSUER_SYNC_SEC=1 \
DIRECTORY_ISSUER_TRUST_MIN_VOTES=1 \
DIRECTORY_ISSUER_DISPUTE_MIN_VOTES=1 \
DIRECTORY_FINAL_DISPUTE_MIN_VOTES=1 \
DIRECTORY_FINAL_APPEAL_MIN_VOTES=1 \
DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS=2 \
DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO=0 \
timeout 90s go run ./cmd/node --directory >/tmp/adjudication_op_quorum_directory.log 2>&1 &
directory_pid=$!

cleanup() {
  kill "${issuer_pid:-}" "${directory_pid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 2

curl -fsS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/subject/upsert" \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data '{"subject":"exit-local-1","tier":3,"reputation":0.95,"bond":550}' >/tmp/adjudication_op_quorum_upsert.json

dispute_until=$(( $(date +%s) + 3600 ))
curl -fsS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/subject/dispute" \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"subject\":\"exit-local-1\",\"tier_cap\":1,\"until\":${dispute_until},\"case_id\":\"case-operator-quorum\",\"evidence_ref\":\"evidence://operator-quorum\"}" >/tmp/adjudication_op_quorum_dispute.json

status_json=""
for _ in $(seq 1 40); do
  status_json="$(curl -fsS "http://127.0.0.1:${DIR_PORT}/v1/admin/governance-status" -H 'X-Admin-Token: dev-admin-token' || true)"
  if echo "$status_json" | rg -q '"final_adjudication_min_operators":2'; then
    break
  fi
  sleep 0.25
done

if [[ -z "$status_json" ]]; then
  echo "expected governance status response"
  cat /tmp/adjudication_op_quorum_directory.log
  cat /tmp/adjudication_op_quorum_issuer.log
  exit 1
fi
if ! echo "$status_json" | rg -q '"aggregated_disputed":0'; then
  echo "expected disputed count suppressed by operator quorum"
  echo "$status_json"
  cat /tmp/adjudication_op_quorum_directory.log
  cat /tmp/adjudication_op_quorum_issuer.log
  exit 1
fi

feed_json=""
for _ in $(seq 1 40); do
  feed_json="$(curl -fsS "http://127.0.0.1:${DIR_PORT}/v1/trust-attestations" || true)"
  if echo "$feed_json" | rg -q '"relay_id":"exit-local-1"'; then
    break
  fi
  sleep 0.25
done

if [[ -z "$feed_json" ]]; then
  echo "expected trust feed response"
  cat /tmp/adjudication_op_quorum_directory.log
  cat /tmp/adjudication_op_quorum_issuer.log
  exit 1
fi
if ! echo "$feed_json" | rg -q '"relay_id":"exit-local-1"'; then
  echo "expected relay attestation for exit-local-1"
  echo "$feed_json"
  cat /tmp/adjudication_op_quorum_directory.log
  cat /tmp/adjudication_op_quorum_issuer.log
  exit 1
fi
if echo "$feed_json" | rg -q '"dispute_until":[0-9]+'; then
  echo "expected dispute window omitted because final operator quorum not met"
  echo "$feed_json"
  cat /tmp/adjudication_op_quorum_directory.log
  cat /tmp/adjudication_op_quorum_issuer.log
  exit 1
fi

echo "adjudication operator quorum integration check ok"
