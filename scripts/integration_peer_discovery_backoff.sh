#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

umask 077
seed_log="$(mktemp "${TMPDIR:-/tmp}/discovery_backoff_seed.XXXXXX.log")"
main_log="$(mktemp "${TMPDIR:-/tmp}/discovery_backoff_main.XXXXXX.log")"
unauth_out="$(mktemp "${TMPDIR:-/tmp}/discovery_backoff_unauth.XXXXXX.out")"

PORT_SEED=8120
PORT_MAIN=8121
PORT_DOWN=8122
ADMIN_TOKEN="peer-status-admin"
DOWN_URL="http://127.0.0.1:${PORT_DOWN}"

DIRECTORY_ADDR="127.0.0.1:${PORT_SEED}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_SEED}" \
DIRECTORY_PRIVATE_KEY_FILE="data/discovery_backoff_seed.key" \
DIRECTORY_OPERATOR_ID="op-discovery-backoff-seed" \
ENTRY_RELAY_ID="entry-discovery-backoff-seed" \
EXIT_RELAY_ID="exit-discovery-backoff-seed" \
DIRECTORY_PEERS="${DOWN_URL}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
timeout 90s go run ./cmd/node --directory >"$seed_log" 2>&1 &
seed_pid=$!

seed_ready=0
for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${PORT_SEED}/v1/health" >/dev/null 2>&1; then
    seed_ready=1
    break
  fi
  sleep 0.25
done
if [[ "$seed_ready" -ne 1 ]]; then
  echo "seed directory did not become ready before launching main directory"
  cat "$seed_log"
  exit 1
fi

DIRECTORY_ADDR="127.0.0.1:${PORT_MAIN}" \
DIRECTORY_PUBLIC_URL="http://127.0.0.1:${PORT_MAIN}" \
DIRECTORY_PRIVATE_KEY_FILE="data/discovery_backoff_main.key" \
DIRECTORY_OPERATOR_ID="op-discovery-backoff-main" \
ENTRY_RELAY_ID="entry-discovery-backoff-main" \
EXIT_RELAY_ID="exit-discovery-backoff-main" \
DIRECTORY_PEERS="http://127.0.0.1:${PORT_SEED}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
DIRECTORY_PEER_DISCOVERY_FAIL_THRESHOLD=1 \
DIRECTORY_PEER_DISCOVERY_BACKOFF_SEC=20 \
DIRECTORY_PEER_DISCOVERY_MAX_BACKOFF_SEC=20 \
DIRECTORY_ADMIN_TOKEN="${ADMIN_TOKEN}" \
timeout 90s go run ./cmd/node --directory >"$main_log" 2>&1 &
main_pid=$!

cleanup() {
  kill "${seed_pid:-}" "${main_pid:-}" >/dev/null 2>&1 || true
  rm -f "$seed_log" "$main_log" "$unauth_out"
}
trap cleanup EXIT

main_ready=0
for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${PORT_MAIN}/v1/health" >/dev/null 2>&1; then
    main_ready=1
    break
  fi
  sleep 0.25
done
if [[ "$main_ready" -ne 1 ]]; then
  echo "main directory did not become ready for peer-status checks"
  cat "$main_log"
  exit 1
fi

code="$(curl -s -o "$unauth_out" -w '%{http_code}' "http://127.0.0.1:${PORT_MAIN}/v1/admin/peer-status" || true)"
if [[ "$code" != "401" ]]; then
  echo "expected unauthorized admin peer-status request to return 401, got $code"
  cat "$unauth_out" || true
  cat "$main_log"
  exit 1
fi

status=""
ready=0
for _ in $(seq 1 50); do
  status="$(curl -fsS "http://127.0.0.1:${PORT_MAIN}/v1/admin/peer-status" -H "X-Admin-Token: ${ADMIN_TOKEN}" || true)"
  if echo "$status" | rg -Fq "\"url\":\"${DOWN_URL}\"" && \
     echo "$status" | rg -q '"cooling_down":true' && \
     echo "$status" | rg -q '"eligible":false' && \
     echo "$status" | rg -q '"consecutive_failures":[1-9]'; then
    ready=1
    break
  fi
  sleep 0.25
done
if [[ "$ready" -ne 1 ]]; then
  echo "expected discovered down peer to show cooldown and failures in admin peer-status"
  echo "$status"
  cat "$seed_log"
  cat "$main_log"
  exit 1
fi

if ! echo "$status" | rg -Fq "\"url\":\"http://127.0.0.1:${PORT_SEED}\""; then
  echo "expected configured seed peer to be present in admin peer-status"
  echo "$status"
  cat "$main_log"
  exit 1
fi
if ! echo "$status" | rg -q '"configured":true'; then
  echo "expected configured seed peer metadata in peer-status"
  echo "$status"
  cat "$main_log"
  exit 1
fi

peers_feed="$(curl -fsS "http://127.0.0.1:${PORT_MAIN}/v1/peers" || true)"
if ! echo "$peers_feed" | rg -Fq "\"${DOWN_URL}\""; then
  echo "expected known discovered peer to remain visible in /v1/peers feed during cooldown"
  echo "$peers_feed"
  cat "$main_log"
  exit 1
fi

echo "peer discovery backoff integration check ok"
