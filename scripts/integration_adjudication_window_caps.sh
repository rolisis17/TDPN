#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

DIR_PORT=8121
ISSUER_PORT=8122

ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_PRIVATE_KEY_FILE="data/issuer_caps_ed25519.key" \
ISSUER_SUBJECTS_FILE="data/issuer_caps_subjects.json" \
ISSUER_REVOCATIONS_FILE="data/issuer_caps_revocations.json" \
timeout 80s go run ./cmd/node --issuer >/tmp/adjudication_caps_issuer.log 2>&1 &
issuer_pid=$!

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE="data/directory_caps_ed25519.key" \
DIRECTORY_ISSUER_TRUST_URLS="http://127.0.0.1:${ISSUER_PORT}" \
DIRECTORY_ISSUER_SYNC_SEC=1 \
DIRECTORY_DISPUTE_MAX_TTL_SEC=120 \
DIRECTORY_APPEAL_MAX_TTL_SEC=60 \
timeout 80s go run ./cmd/node --directory >/tmp/adjudication_caps_directory.log 2>&1 &
directory_pid=$!

cleanup() {
  kill "${issuer_pid:-}" "${directory_pid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 2

curl -fsS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/subject/upsert" \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data '{"subject":"exit-local-1","tier":3,"reputation":0.95,"bond":500}' >/tmp/adjudication_caps_upsert.json

far_dispute=$(( $(date +%s) + 86400 ))
far_appeal=$(( $(date +%s) + 72000 ))

curl -fsS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/subject/dispute" \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"subject\":\"exit-local-1\",\"tier_cap\":2,\"until\":${far_dispute},\"case_id\":\"case-caps-dispute\",\"evidence_ref\":\"evidence://caps-dispute\"}" >/tmp/adjudication_caps_dispute.json

curl -fsS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/subject/appeal/open" \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"subject\":\"exit-local-1\",\"until\":${far_appeal},\"case_id\":\"case-caps-appeal\",\"evidence_ref\":\"evidence://caps-appeal\"}" >/tmp/adjudication_caps_appeal.json

feed_json=""
for _ in $(seq 1 40); do
  feed_json="$(curl -fsS "http://127.0.0.1:${DIR_PORT}/v1/trust-attestations" || true)"
  if echo "$feed_json" | rg -q '"relay_id":"exit-local-1"' && \
     echo "$feed_json" | rg -q '"dispute_until":[0-9]+' && \
     echo "$feed_json" | rg -q '"appeal_until":[0-9]+'; then
    break
  fi
  sleep 0.25
done

if [[ -z "$feed_json" ]]; then
  echo "expected directory trust feed response"
  cat /tmp/adjudication_caps_directory.log
  cat /tmp/adjudication_caps_issuer.log
  exit 1
fi

if ! echo "$feed_json" | rg -q '"relay_id":"exit-local-1"'; then
  echo "expected trust attestation for exit-local-1"
  echo "$feed_json"
  cat /tmp/adjudication_caps_directory.log
  cat /tmp/adjudication_caps_issuer.log
  exit 1
fi

dispute_until="$(echo "$feed_json" | rg -o '"dispute_until":[0-9]+' | head -n1 | cut -d: -f2 || true)"
appeal_until="$(echo "$feed_json" | rg -o '"appeal_until":[0-9]+' | head -n1 | cut -d: -f2 || true)"
if [[ -z "$dispute_until" || -z "$appeal_until" ]]; then
  echo "expected dispute_until and appeal_until in trust feed"
  echo "$feed_json"
  cat /tmp/adjudication_caps_directory.log
  cat /tmp/adjudication_caps_issuer.log
  exit 1
fi

now="$(date +%s)"
if (( dispute_until < now + 60 || dispute_until > now + 125 )); then
  echo "expected dispute_until capped near 120s horizon, got ${dispute_until}"
  echo "$feed_json"
  cat /tmp/adjudication_caps_directory.log
  cat /tmp/adjudication_caps_issuer.log
  exit 1
fi
if (( appeal_until < now + 25 || appeal_until > now + 65 )); then
  echo "expected appeal_until capped near 60s horizon, got ${appeal_until}"
  echo "$feed_json"
  cat /tmp/adjudication_caps_directory.log
  cat /tmp/adjudication_caps_issuer.log
  exit 1
fi

echo "adjudication window cap integration check ok"
