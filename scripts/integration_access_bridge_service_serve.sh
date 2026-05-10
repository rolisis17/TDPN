#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in go jq mktemp curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access bridge service serve integration failed: missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
BRIDGE_PID=""
cleanup() {
  if [[ -n "$BRIDGE_PID" ]]; then
    kill "$BRIDGE_PID" >/dev/null 2>&1 || true
    wait "$BRIDGE_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

BUNDLE_DIR="$TMP_DIR/access-recovery-demo"
PORT="${ACCESS_BRIDGE_TEST_PORT:-19789}"
BASE_URL="http://127.0.0.1:${PORT}"
CODE_FILE="$TMP_DIR/bridge-code.txt"
CODE_HASH_JSON="$TMP_DIR/bridge-code-hash.json"
SERVICE_CONFIG="$TMP_DIR/bridge-service-config.json"
ABUSE_LOG="$TMP_DIR/bridge-abuse.jsonl"
SERVER_LOG="$TMP_DIR/bridge-service.log"

printf 'ticket-serve-123\n' >"$CODE_FILE"

go run ./cmd/gpmrecover demo-bundle \
  --out-dir "$BUNDLE_DIR" \
  --org-id serve-org \
  --org-name "Serve Org" \
  --base-url https://serve.example \
  --helper-id helper-serve \
  --helper-name "Serve Helper" \
  --helper-url https://helper.example/serve/bootstrap \
  --helper-contact mailto:helper-serve@example.com \
  >"$TMP_DIR/demo-bundle.stdout.json"

trust_store="$(jq -r '.files.trust_store' "$BUNDLE_DIR/demo-manifest.json")"
bridge_invite="$(jq -r '.files.bridge_invite_signed' "$BUNDLE_DIR/demo-manifest.json")"
signed_registry="$(jq -r '.files.bridge_helper_registry_signed' "$BUNDLE_DIR/demo-manifest.json")"

go run ./cmd/gpmrecover bridge-service-config \
  --invite "$bridge_invite" \
  --trust-store "$trust_store" \
  --signed-helper-registry "$signed_registry" \
  --out "$SERVICE_CONFIG" >/dev/null

go run ./cmd/gpmrecover bridge-service-code-hash --code-file "$CODE_FILE" --out "$CODE_HASH_JSON" >/dev/null
code_hash="$(jq -r '.sha256' "$CODE_HASH_JSON")"

go run ./cmd/gpmrecover bridge-service-serve \
  --config "$SERVICE_CONFIG" \
  --addr "127.0.0.1:${PORT}" \
  --rps 20 \
  --abuse-log "$ABUSE_LOG" \
  --access-code-sha256 "$code_hash" \
  >"$SERVER_LOG" 2>&1 &
BRIDGE_PID=$!

for _ in $(seq 1 60); do
  if curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$BRIDGE_PID" >/dev/null 2>&1; then
    echo "access bridge service serve integration failed: server exited early"
    cat "$SERVER_LOG"
    exit 1
  fi
  sleep 0.5
done

if ! curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
  echo "access bridge service serve integration failed: health did not become ready"
  cat "$SERVER_LOG"
  exit 1
fi

missing_code_status="$(curl -sS -o "$TMP_DIR/missing-code.json" -w '%{http_code}' "${BASE_URL}/bridge/helper-web")"
if [[ "$missing_code_status" != "401" ]]; then
  echo "access bridge service serve integration failed: expected missing code 401, got $missing_code_status"
  cat "$TMP_DIR/missing-code.json"
  exit 1
fi

headers_file="$TMP_DIR/bridge.headers"
allowed_body="$TMP_DIR/bridge.allowed.json"
allowed_status="$(curl -sS -D "$headers_file" -H 'X-GPM-Bridge-Code: ticket-serve-123' -o "$allowed_body" -w '%{http_code}' "${BASE_URL}/bridge/helper-web")"
if [[ "$allowed_status" != "200" ]]; then
  echo "access bridge service serve integration failed: expected allowed code 200, got $allowed_status"
  cat "$allowed_body"
  exit 1
fi
if [[ "$(jq -r '.status // ""' "$allowed_body")" != "ok" ]]; then
  echo "access bridge service serve integration failed: allowed response was not ok"
  cat "$allowed_body"
  exit 1
fi
if ! grep -iq '^Referrer-Policy: no-referrer' "$headers_file" || ! grep -iq '^Cache-Control: no-store' "$headers_file"; then
  echo "access bridge service serve integration failed: security headers missing"
  cat "$headers_file"
  exit 1
fi

abuse_status="$(curl -sS -X POST -H 'Content-Type: application/json' -d '{"path_id":"helper-web","message":"serve smoke"}' -o "$TMP_DIR/abuse.json" -w '%{http_code}' "${BASE_URL}/abuse")"
if [[ "$abuse_status" != "202" ]]; then
  echo "access bridge service serve integration failed: expected abuse 202, got $abuse_status"
  cat "$TMP_DIR/abuse.json"
  exit 1
fi
if ! grep -q '"message":"serve smoke"' "$ABUSE_LOG"; then
  echo "access bridge service serve integration failed: abuse log missing report"
  cat "$ABUSE_LOG"
  exit 1
fi

bash ./scripts/access_bridge_service_smoke.sh \
  --base-url "$BASE_URL" \
  --path-id helper-web \
  --code ticket-serve-123 \
  --summary-json "$TMP_DIR/operator-smoke-summary.json" \
  --abuse-message "operator smoke" >/dev/null
if [[ "$(jq -r '.status // ""' "$TMP_DIR/operator-smoke-summary.json")" != "pass" ]]; then
  echo "access bridge service serve integration failed: operator smoke summary not pass"
  cat "$TMP_DIR/operator-smoke-summary.json"
  exit 1
fi

echo "access bridge service serve integration check ok"
