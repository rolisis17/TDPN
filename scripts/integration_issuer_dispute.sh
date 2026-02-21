#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

ISSUER_TRUST_CONFIDENCE=0.9 \
timeout 25s go run ./cmd/node --directory --issuer --entry --exit >/tmp/issuer_dispute_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 2

curl -fsS -X POST http://127.0.0.1:8082/v1/admin/subject/upsert \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data '{"subject":"exit-local-1","tier":3,"reputation":0.97,"bond":600}' >/tmp/issuer_dispute_upsert.json

curl -fsS "http://127.0.0.1:8082/v1/admin/subject/get?subject=exit-local-1" \
  -H 'X-Admin-Token: dev-admin-token' >/tmp/issuer_dispute_subject_before.json
if ! rg -q '"tier":3' /tmp/issuer_dispute_subject_before.json; then
  echo "expected tier 3 before dispute"
  cat /tmp/issuer_dispute_subject_before.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi

until_ts=$(( $(date +%s) + 3600 ))
curl -fsS -X POST http://127.0.0.1:8082/v1/admin/subject/dispute \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"subject\":\"exit-local-1\",\"tier_cap\":1,\"until\":${until_ts},\"case_id\":\"case-dispute-int-1\",\"evidence_ref\":\"evidence://dispute-int-1\",\"reason\":\"integration-test\"}" >/tmp/issuer_dispute_apply.json

curl -fsS "http://127.0.0.1:8082/v1/admin/subject/get?subject=exit-local-1" \
  -H 'X-Admin-Token: dev-admin-token' >/tmp/issuer_dispute_subject_during.json
if ! rg -q '"tier":1' /tmp/issuer_dispute_subject_during.json; then
  echo "expected tier 1 during dispute"
  cat /tmp/issuer_dispute_subject_during.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi
if ! rg -q '"dispute_case_id":"case-dispute-int-1"' /tmp/issuer_dispute_subject_during.json; then
  echo "expected dispute case metadata during dispute"
  cat /tmp/issuer_dispute_subject_during.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi

appeal_until=$(( $(date +%s) + 2400 ))
curl -fsS -X POST http://127.0.0.1:8082/v1/admin/subject/appeal/open \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"subject\":\"exit-local-1\",\"until\":${appeal_until},\"case_id\":\"case-appeal-int-1\",\"evidence_ref\":\"evidence://appeal-int-1\",\"reason\":\"integration-appeal\"}" >/tmp/issuer_dispute_appeal_open.json

curl -fsS "http://127.0.0.1:8082/v1/admin/subject/get?subject=exit-local-1" \
  -H 'X-Admin-Token: dev-admin-token' >/tmp/issuer_dispute_subject_appeal.json
if ! rg -q '"appeal_until":' /tmp/issuer_dispute_subject_appeal.json; then
  echo "expected appeal_until during open appeal"
  cat /tmp/issuer_dispute_subject_appeal.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi
if ! rg -q '"appeal_case_id":"case-appeal-int-1"' /tmp/issuer_dispute_subject_appeal.json; then
  echo "expected appeal case metadata during open appeal"
  cat /tmp/issuer_dispute_subject_appeal.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi

curl -fsS http://127.0.0.1:8082/v1/trust/relays >/tmp/issuer_dispute_trust_during.json
if ! rg -q '"relay_id":"exit-local-1"' /tmp/issuer_dispute_trust_during.json; then
  echo "expected trust feed attestation for exit-local-1 during dispute"
  cat /tmp/issuer_dispute_trust_during.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi
if ! rg -q '"abuse_penalty":' /tmp/issuer_dispute_trust_during.json; then
  echo "expected non-zero abuse penalty during dispute"
  cat /tmp/issuer_dispute_trust_during.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi
if ! rg -q '"appeal_until":' /tmp/issuer_dispute_trust_during.json; then
  echo "expected appeal signal in trust feed during open appeal"
  cat /tmp/issuer_dispute_trust_during.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi
if ! rg -q '"dispute_case_id":"case-dispute-int-1"' /tmp/issuer_dispute_trust_during.json; then
  echo "expected dispute case metadata in trust feed during dispute"
  cat /tmp/issuer_dispute_trust_during.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi
if ! rg -q '"appeal_case_id":"case-appeal-int-1"' /tmp/issuer_dispute_trust_during.json; then
  echo "expected appeal case metadata in trust feed during open appeal"
  cat /tmp/issuer_dispute_trust_during.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi

curl -fsS -X POST http://127.0.0.1:8082/v1/admin/subject/appeal/resolve \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data '{"subject":"exit-local-1","reason":"integration-appeal-resolve"}' >/tmp/issuer_dispute_appeal_resolve.json

curl -fsS -X POST http://127.0.0.1:8082/v1/admin/subject/dispute/clear \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data '{"subject":"exit-local-1","reason":"integration-test-clear"}' >/tmp/issuer_dispute_clear.json

curl -fsS "http://127.0.0.1:8082/v1/admin/subject/get?subject=exit-local-1" \
  -H 'X-Admin-Token: dev-admin-token' >/tmp/issuer_dispute_subject_after.json
if ! rg -q '"tier":3' /tmp/issuer_dispute_subject_after.json; then
  echo "expected tier 3 after dispute clear"
  cat /tmp/issuer_dispute_subject_after.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi

curl -fsS http://127.0.0.1:8082/v1/trust/relays >/tmp/issuer_dispute_trust_after.json
if rg -q '"abuse_penalty":' /tmp/issuer_dispute_trust_after.json; then
  echo "expected dispute abuse penalty cleared"
  cat /tmp/issuer_dispute_trust_after.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi
if rg -q '"appeal_until":' /tmp/issuer_dispute_trust_after.json; then
  echo "expected appeal signal cleared"
  cat /tmp/issuer_dispute_trust_after.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi
if rg -q '"dispute_case_id":' /tmp/issuer_dispute_trust_after.json; then
  echo "expected dispute case metadata cleared"
  cat /tmp/issuer_dispute_trust_after.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi
if rg -q '"appeal_case_id":' /tmp/issuer_dispute_trust_after.json; then
  echo "expected appeal case metadata cleared"
  cat /tmp/issuer_dispute_trust_after.json
  cat /tmp/issuer_dispute_node.log
  exit 1
fi

echo "issuer dispute integration check ok"
