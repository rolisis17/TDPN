#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE=/tmp/session_handoff.log
rm -f "$LOG_FILE"

CLIENT_SESSION_REUSE=1 \
CLIENT_SESSION_REFRESH_LEAD_SEC=5 \
CLIENT_BOOTSTRAP_INTERVAL_SEC=2 \
ISSUER_TOKEN_TTL_SEC=14 \
timeout 50s go run ./cmd/node --directory --issuer --entry --exit --client >"$LOG_FILE" 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

selected_ok=0
for _ in $(seq 1 80); do
  if rg -q "client selected entry=" "$LOG_FILE"; then
    selected_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$selected_ok" -ne 1 ]]; then
  echo "expected initial client selection log"
  cat "$LOG_FILE"
  exit 1
fi

refresh_ok=0
for _ in $(seq 1 160); do
  if rg -q "client active session refresh required session=" "$LOG_FILE"; then
    refresh_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$refresh_ok" -ne 1 ]]; then
  echo "expected refresh-required log before handoff"
  cat "$LOG_FILE"
  exit 1
fi

handoff_ok=0
for _ in $(seq 1 120); do
  if rg -q "client session handoff complete old_session=.* new_session=" "$LOG_FILE"; then
    handoff_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$handoff_ok" -ne 1 ]]; then
  echo "expected session handoff completion log"
  cat "$LOG_FILE"
  exit 1
fi

handoff_line=$(rg -N "client session handoff complete old_session=.* new_session=" "$LOG_FILE" | tail -n1)
old_session=$(echo "$handoff_line" | sed -E 's/.*old_session=([^ ]+).*/\1/')
new_session=$(echo "$handoff_line" | sed -E 's/.*new_session=([^ ]+).*/\1/')
if [[ -z "$old_session" || -z "$new_session" ]]; then
  echo "failed to parse session handoff ids"
  echo "$handoff_line"
  cat "$LOG_FILE"
  exit 1
fi
if [[ "$old_session" == "$new_session" ]]; then
  echo "expected distinct old/new session ids in handoff"
  echo "$handoff_line"
  cat "$LOG_FILE"
  exit 1
fi

post_handoff_reuse_ok=0
for _ in $(seq 1 80); do
  if rg -q "client reused active session session=${new_session}" "$LOG_FILE"; then
    post_handoff_reuse_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$post_handoff_reuse_ok" -ne 1 ]]; then
  echo "expected reused-active-session log for handed-off session"
  cat "$LOG_FILE"
  exit 1
fi

echo "session handoff integration check ok"
