#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

DIR_PORT=8151
ISSUER_PORT=8152
TMP_DIR="$(mktemp -d)"

ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ISSUER_PRIVATE_KEY_FILE="$TMP_DIR/issuer_source_quorum_ed25519.key" \
ISSUER_SUBJECTS_FILE="$TMP_DIR/issuer_source_quorum_subjects.json" \
ISSUER_REVOCATIONS_FILE="$TMP_DIR/issuer_source_quorum_revocations.json" \
ISSUER_TRUST_OPERATOR_ID="issuer-source-a" \
timeout 90s go run ./cmd/node --issuer >/tmp/adjudication_source_quorum_issuer.log 2>&1 &
issuer_pid=$!

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${DIR_PORT}" \
DIRECTORY_PRIVATE_KEY_FILE="$TMP_DIR/directory_source_quorum_ed25519.key" \
DIRECTORY_ISSUER_TRUST_URLS="http://127.0.0.1:${ISSUER_PORT}" \
DIRECTORY_ISSUER_SYNC_SEC=1 \
DIRECTORY_ISSUER_TRUST_MIN_VOTES=1 \
DIRECTORY_ISSUER_DISPUTE_MIN_VOTES=1 \
DIRECTORY_FINAL_DISPUTE_MIN_VOTES=1 \
DIRECTORY_FINAL_APPEAL_MIN_VOTES=1 \
DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS=1 \
DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES=2 \
DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO=0 \
timeout 90s go run ./cmd/node --directory >/tmp/adjudication_source_quorum_directory.log 2>&1 &
directory_pid=$!

cleanup() {
  kill "${issuer_pid:-}" "${directory_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

wait_http_ok() {
  local url="$1"
  local timeout_sec="${2:-20}"
  local start
  start="$(date +%s)"
  while true; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    if (( $(date +%s) - start >= timeout_sec )); then
      return 1
    fi
    sleep 0.25
  done
}

if ! wait_http_ok "http://127.0.0.1:${ISSUER_PORT}/v1/pubkeys" 25; then
  echo "issuer did not become healthy for adjudication source-quorum integration"
  cat /tmp/adjudication_source_quorum_issuer.log
  exit 1
fi
if ! wait_http_ok "http://127.0.0.1:${DIR_PORT}/v1/relays" 25; then
  echo "directory did not become healthy for adjudication source-quorum integration"
  cat /tmp/adjudication_source_quorum_directory.log
  exit 1
fi

curl -fsS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/subject/upsert" \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data '{"subject":"exit-local-1","tier":3,"reputation":0.95,"bond":540}' >/tmp/adjudication_source_quorum_upsert.json

dispute_until=$(( $(date +%s) + 3600 ))
curl -fsS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/subject/dispute" \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"subject\":\"exit-local-1\",\"tier_cap\":1,\"until\":${dispute_until},\"case_id\":\"case-source-quorum\",\"evidence_ref\":\"evidence://source-quorum\"}" >/tmp/adjudication_source_quorum_dispute.json

status_json=""
for _ in $(seq 1 40); do
  status_json="$(curl -fsS "http://127.0.0.1:${DIR_PORT}/v1/admin/governance-status" -H 'X-Admin-Token: dev-admin-token' || true)"
  if echo "$status_json" | rg -q '"final_adjudication_min_sources":2' &&
    echo "$status_json" | rg -q '"aggregated_dispute_signals":1'; then
    break
  fi
  sleep 0.25
done

if [[ -z "$status_json" ]]; then
  echo "expected governance status response"
  cat /tmp/adjudication_source_quorum_directory.log
  cat /tmp/adjudication_source_quorum_issuer.log
  exit 1
fi
if ! echo "$status_json" | rg -q '"aggregated_disputed":0'; then
  echo "expected disputed signal suppressed by final source quorum"
  echo "$status_json"
  cat /tmp/adjudication_source_quorum_directory.log
  cat /tmp/adjudication_source_quorum_issuer.log
  exit 1
fi
if ! echo "$status_json" | rg -q '"suppressed_disputed":1'; then
  echo "expected one suppressed disputed signal under source quorum"
  echo "$status_json"
  cat /tmp/adjudication_source_quorum_directory.log
  cat /tmp/adjudication_source_quorum_issuer.log
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
  cat /tmp/adjudication_source_quorum_directory.log
  cat /tmp/adjudication_source_quorum_issuer.log
  exit 1
fi
if echo "$feed_json" | rg -q '"dispute_until":[0-9]+'; then
  echo "expected dispute window omitted because final source quorum not met"
  echo "$feed_json"
  cat /tmp/adjudication_source_quorum_directory.log
  cat /tmp/adjudication_source_quorum_issuer.log
  exit 1
fi

echo "adjudication source quorum integration check ok"
