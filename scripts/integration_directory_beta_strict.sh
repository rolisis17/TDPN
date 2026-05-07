#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in go curl rg timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

PORT=8581
ADDR="127.0.0.1:${PORT}"
RELAYS_URL="http://${ADDR}/v1/relays"

TMP_DIR="$(mktemp -d /tmp/integration_directory_beta_strict.XXXXXX)"
FAIL_LOG="$TMP_DIR/fail.log"
OK_LOG="$TMP_DIR/ok.log"
ISSUER_TRUST_FILE="$TMP_DIR/issuer_trusted_keys.txt"

issuer_pub_a="$(go run ./cmd/tokenpop gen | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
issuer_pub_b="$(go run ./cmd/tokenpop gen | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
if [[ -z "$issuer_pub_a" || -z "$issuer_pub_b" ]]; then
  echo "failed to generate issuer trust anchors"
  exit 1
fi
printf '%s\n%s\n' "$issuer_pub_a" "$issuer_pub_b" >"$ISSUER_TRUST_FILE"

if DIRECTORY_ADDR="$ADDR" \
  DIRECTORY_BETA_STRICT=1 \
  timeout 20s go run ./cmd/node --directory >"$FAIL_LOG" 2>&1; then
  echo "expected directory strict-mode startup failure with default config"
  cat "$FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires DIRECTORY_" "$FAIL_LOG"; then
  echo "missing expected strict-mode validation signal"
  cat "$FAIL_LOG"
  exit 1
fi

DIRECTORY_ADDR="$ADDR" \
DIRECTORY_BETA_STRICT=1 \
DIRECTORY_PEER_DISCOVERY=1 \
DIRECTORY_PEER_MIN_OPERATORS=2 \
DIRECTORY_PEER_MIN_VOTES=2 \
DIRECTORY_PEER_DISCOVERY_MIN_VOTES=2 \
DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1 \
DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE=8 \
DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR=8 \
DIRECTORY_PEER_TRUST_STRICT=1 \
DIRECTORY_PEER_TRUST_TOFU=0 \
DIRECTORY_PEER_TRUSTED_KEYS_FILE="$TMP_DIR/peer_trusted_keys.txt" \
DIRECTORY_ISSUER_TRUST_URLS="http://127.0.0.1:9682,http://127.0.0.1:9683" \
DIRECTORY_ISSUER_TRUSTED_KEYS_FILE="$ISSUER_TRUST_FILE" \
DIRECTORY_ISSUER_MIN_OPERATORS=2 \
DIRECTORY_ISSUER_TRUST_MIN_VOTES=2 \
DIRECTORY_ISSUER_DISPUTE_MIN_VOTES=2 \
DIRECTORY_ISSUER_APPEAL_MIN_VOTES=2 \
DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS=2 \
DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES=2 \
DIRECTORY_FINAL_DISPUTE_MIN_VOTES=2 \
DIRECTORY_FINAL_APPEAL_MIN_VOTES=2 \
DIRECTORY_KEY_ROTATE_SEC=60 \
DIRECTORY_ADMIN_TOKEN=integration-directory-admin-0001 \
DIRECTORY_PRIVATE_KEY_FILE="$TMP_DIR/directory_ed25519.key" \
DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE="$TMP_DIR/directory_provider_token_proof_replay.json" \
timeout 35s go run ./cmd/node --directory >"$OK_LOG" 2>&1 &
dir_pid=$!

cleanup() {
  kill "${dir_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ready=0
for _ in $(seq 1 120); do
  if curl -fsS "$RELAYS_URL" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$dir_pid" >/dev/null 2>&1; then
    echo "directory exited unexpectedly in strict mode"
    cat "$OK_LOG"
    exit 1
  fi
  sleep 0.2
done
if [[ "$ready" -ne 1 ]]; then
  echo "directory did not become healthy in strict mode"
  cat "$OK_LOG"
  exit 1
fi

if ! rg -q "directory federation policy: .*peer_min_operators=2 .*peer_min_votes=2 .*peer_discovery_min_votes=2 .*peer_discovery_require_hint=true .*peer_discovery_max_per_source=8 .*peer_discovery_max_per_operator=8 .*final_dispute_min_votes=2 .*final_appeal_min_votes=2 .*final_adjudication_min_operators=2 .*final_adjudication_min_sources=2 .*issuer_urls=2 .*issuer_min_operators=2 .*issuer_min_votes=2 .*key_rotate_sec=60" "$OK_LOG"; then
  echo "missing expected strict-governance policy signals in startup log"
  cat "$OK_LOG"
  exit 1
fi

echo "directory beta strict integration check ok"
