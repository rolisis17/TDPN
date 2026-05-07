#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

old_umask="$(umask)"
umask 077
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/issuer_dispute.XXXXXX")"
umask "$old_umask"
NODE_LOG="$TMP_DIR/issuer_dispute_node.log"
UPSERT_RESP="$TMP_DIR/issuer_dispute_upsert.json"
SUBJECT_BEFORE_RESP="$TMP_DIR/issuer_dispute_subject_before.json"
APPLY_RESP="$TMP_DIR/issuer_dispute_apply.json"
SUBJECT_DURING_RESP="$TMP_DIR/issuer_dispute_subject_during.json"
APPEAL_OPEN_RESP="$TMP_DIR/issuer_dispute_appeal_open.json"
SUBJECT_APPEAL_RESP="$TMP_DIR/issuer_dispute_subject_appeal.json"
TRUST_DURING_RESP="$TMP_DIR/issuer_dispute_trust_during.json"
APPEAL_RESOLVE_RESP="$TMP_DIR/issuer_dispute_appeal_resolve.json"
CLEAR_RESP="$TMP_DIR/issuer_dispute_clear.json"
SUBJECT_AFTER_RESP="$TMP_DIR/issuer_dispute_subject_after.json"
TRUST_AFTER_RESP="$TMP_DIR/issuer_dispute_trust_after.json"
node_pid=""
ADMIN_TOKEN="integration-admin-token"
ISSUER_PORT=19312
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}"

cleanup() {
  kill "$node_pid" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}

ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_URL="$ISSUER_URL" \
ISSUER_ADMIN_TOKEN="$ADMIN_TOKEN" \
ISSUER_PRIVATE_KEY_FILE="$TMP_DIR/issuer.key" \
ISSUER_SUBJECTS_FILE="$TMP_DIR/issuer_subjects.json" \
ISSUER_REVOCATIONS_FILE="$TMP_DIR/issuer_revocations.json" \
ISSUER_ANON_REVOCATIONS_FILE="$TMP_DIR/issuer_anon_revocations.json" \
ISSUER_AUDIT_FILE="$TMP_DIR/issuer_audit.json" \
ISSUER_TRUST_CONFIDENCE=0.9 \
timeout 25s go run ./cmd/node --issuer >"$NODE_LOG" 2>&1 &
node_pid=$!
trap cleanup EXIT

sleep 2

curl -fsS -X POST "${ISSUER_URL}/v1/admin/subject/upsert" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{"subject":"exit-local-1","tier":3,"reputation":0.97,"bond":600}' >"$UPSERT_RESP"

curl -fsS "${ISSUER_URL}/v1/admin/subject/get?subject=exit-local-1" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" >"$SUBJECT_BEFORE_RESP"
if ! rg -q '"tier":3' "$SUBJECT_BEFORE_RESP"; then
  echo "expected tier 3 before dispute"
  cat "$SUBJECT_BEFORE_RESP"
  cat "$NODE_LOG"
  exit 1
fi

until_ts=$(( $(date +%s) + 3600 ))
curl -fsS -X POST "${ISSUER_URL}/v1/admin/subject/dispute" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data "{\"subject\":\"exit-local-1\",\"tier_cap\":1,\"until\":${until_ts},\"case_id\":\"case-dispute-int-1\",\"evidence_ref\":\"evidence://dispute-int-1\",\"reason\":\"integration-test\"}" >"$APPLY_RESP"

curl -fsS "${ISSUER_URL}/v1/admin/subject/get?subject=exit-local-1" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" >"$SUBJECT_DURING_RESP"
if ! rg -q '"tier":1' "$SUBJECT_DURING_RESP"; then
  echo "expected tier 1 during dispute"
  cat "$SUBJECT_DURING_RESP"
  cat "$NODE_LOG"
  exit 1
fi
if ! rg -q '"dispute_case_id":"case-dispute-int-1"' "$SUBJECT_DURING_RESP"; then
  echo "expected dispute case metadata during dispute"
  cat "$SUBJECT_DURING_RESP"
  cat "$NODE_LOG"
  exit 1
fi

appeal_until=$(( $(date +%s) + 2400 ))
curl -fsS -X POST "${ISSUER_URL}/v1/admin/subject/appeal/open" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data "{\"subject\":\"exit-local-1\",\"until\":${appeal_until},\"case_id\":\"case-appeal-int-1\",\"evidence_ref\":\"evidence://appeal-int-1\",\"reason\":\"integration-appeal\"}" >"$APPEAL_OPEN_RESP"

curl -fsS "${ISSUER_URL}/v1/admin/subject/get?subject=exit-local-1" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" >"$SUBJECT_APPEAL_RESP"
if ! rg -q '"appeal_until":' "$SUBJECT_APPEAL_RESP"; then
  echo "expected appeal_until during open appeal"
  cat "$SUBJECT_APPEAL_RESP"
  cat "$NODE_LOG"
  exit 1
fi
if ! rg -q '"appeal_case_id":"case-appeal-int-1"' "$SUBJECT_APPEAL_RESP"; then
  echo "expected appeal case metadata during open appeal"
  cat "$SUBJECT_APPEAL_RESP"
  cat "$NODE_LOG"
  exit 1
fi

curl -fsS "${ISSUER_URL}/v1/trust/relays" >"$TRUST_DURING_RESP"
if ! rg -q '"relay_id":"exit-local-1"' "$TRUST_DURING_RESP"; then
  echo "expected trust feed attestation for exit-local-1 during dispute"
  cat "$TRUST_DURING_RESP"
  cat "$NODE_LOG"
  exit 1
fi
if ! rg -q '"abuse_penalty":' "$TRUST_DURING_RESP"; then
  echo "expected non-zero abuse penalty during dispute"
  cat "$TRUST_DURING_RESP"
  cat "$NODE_LOG"
  exit 1
fi
if ! rg -q '"appeal_until":' "$TRUST_DURING_RESP"; then
  echo "expected appeal signal in trust feed during open appeal"
  cat "$TRUST_DURING_RESP"
  cat "$NODE_LOG"
  exit 1
fi
if ! rg -q '"dispute_case_id":"case-dispute-int-1"' "$TRUST_DURING_RESP"; then
  echo "expected dispute case metadata in trust feed during dispute"
  cat "$TRUST_DURING_RESP"
  cat "$NODE_LOG"
  exit 1
fi
if ! rg -q '"appeal_case_id":"case-appeal-int-1"' "$TRUST_DURING_RESP"; then
  echo "expected appeal case metadata in trust feed during open appeal"
  cat "$TRUST_DURING_RESP"
  cat "$NODE_LOG"
  exit 1
fi

curl -fsS -X POST "${ISSUER_URL}/v1/admin/subject/appeal/resolve" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{"subject":"exit-local-1","reason":"integration-appeal-resolve"}' >"$APPEAL_RESOLVE_RESP"

curl -fsS -X POST "${ISSUER_URL}/v1/admin/subject/dispute/clear" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{"subject":"exit-local-1","reason":"integration-test-clear"}' >"$CLEAR_RESP"

curl -fsS "${ISSUER_URL}/v1/admin/subject/get?subject=exit-local-1" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" >"$SUBJECT_AFTER_RESP"
if ! rg -q '"tier":3' "$SUBJECT_AFTER_RESP"; then
  echo "expected tier 3 after dispute clear"
  cat "$SUBJECT_AFTER_RESP"
  cat "$NODE_LOG"
  exit 1
fi

curl -fsS "${ISSUER_URL}/v1/trust/relays" >"$TRUST_AFTER_RESP"
if rg -q '"abuse_penalty":' "$TRUST_AFTER_RESP"; then
  echo "expected dispute abuse penalty cleared"
  cat "$TRUST_AFTER_RESP"
  cat "$NODE_LOG"
  exit 1
fi
if rg -q '"appeal_until":' "$TRUST_AFTER_RESP"; then
  echo "expected appeal signal cleared"
  cat "$TRUST_AFTER_RESP"
  cat "$NODE_LOG"
  exit 1
fi
if rg -q '"dispute_case_id":' "$TRUST_AFTER_RESP"; then
  echo "expected dispute case metadata cleared"
  cat "$TRUST_AFTER_RESP"
  cat "$NODE_LOG"
  exit 1
fi
if rg -q '"appeal_case_id":' "$TRUST_AFTER_RESP"; then
  echo "expected appeal case metadata cleared"
  cat "$TRUST_AFTER_RESP"
  cat "$NODE_LOG"
  exit 1
fi

echo "issuer dispute integration check ok"
