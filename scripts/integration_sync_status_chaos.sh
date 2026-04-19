#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in curl jq rg timeout go; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

PORT_MAIN=8130
PORT_PEER_A=8131
PORT_PEER_B=8132
ADMIN_TOKEN="sync-status-admin"
URL_MAIN="http://127.0.0.1:${PORT_MAIN}"
URL_PEER_A="http://127.0.0.1:${PORT_PEER_A}"
URL_PEER_B="http://127.0.0.1:${PORT_PEER_B}"

old_umask="$(umask)"
umask 077
tmp_dir="$(mktemp -d /tmp/integration_sync_status_chaos.XXXXXX)"
umask "$old_umask"
main_log="$tmp_dir/sync_status_main.log"
peer_a_log="$tmp_dir/sync_status_peer_a.log"
peer_b_log="$tmp_dir/sync_status_peer_b.log"
admin_header_cfg="$tmp_dir/admin_header.cfg"
(umask 077 && printf 'header = "X-Admin-Token: %s"\n' "$ADMIN_TOKEN" >"$admin_header_cfg")

wait_for_health() {
  local url="$1"
  local log_file="$2"
  local name="$3"
  for _ in $(seq 1 50); do
    if curl -fsS "${url}/v1/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "${name} did not become healthy"
  cat "$log_file"
  exit 1
}

dump_logs() {
  cat "$main_log" 2>/dev/null || true
  cat "$peer_a_log" 2>/dev/null || true
  cat "$peer_b_log" 2>/dev/null || true
}

DIRECTORY_ADDR="127.0.0.1:${PORT_PEER_A}" \
DIRECTORY_PUBLIC_URL="${URL_PEER_A}" \
DIRECTORY_PRIVATE_KEY_FILE="data/sync_status_peer_a.key" \
DIRECTORY_OPERATOR_ID="op-sync-peer-a" \
DIRECTORY_SYNC_SEC=1 \
timeout 90s go run ./cmd/node --directory >"$peer_a_log" 2>&1 &
peer_a_pid=$!

DIRECTORY_ADDR="127.0.0.1:${PORT_PEER_B}" \
DIRECTORY_PUBLIC_URL="${URL_PEER_B}" \
DIRECTORY_PRIVATE_KEY_FILE="data/sync_status_peer_b.key" \
DIRECTORY_OPERATOR_ID="op-sync-peer-b" \
DIRECTORY_SYNC_SEC=1 \
timeout 90s go run ./cmd/node --directory >"$peer_b_log" 2>&1 &
peer_b_pid=$!

wait_for_health "$URL_PEER_A" "$peer_a_log" "peer-a directory"
wait_for_health "$URL_PEER_B" "$peer_b_log" "peer-b directory"

DIRECTORY_ADDR="127.0.0.1:${PORT_MAIN}" \
DIRECTORY_PUBLIC_URL="${URL_MAIN}" \
DIRECTORY_PRIVATE_KEY_FILE="data/sync_status_main.key" \
DIRECTORY_OPERATOR_ID="op-sync-main" \
DIRECTORY_PEERS="${URL_PEER_A},${URL_PEER_B}" \
DIRECTORY_SYNC_SEC=1 \
DIRECTORY_PEER_DISCOVERY=1 \
DIRECTORY_PEER_DISCOVERY_FAIL_THRESHOLD=1 \
DIRECTORY_PEER_DISCOVERY_BACKOFF_SEC=1 \
DIRECTORY_PEER_DISCOVERY_MAX_BACKOFF_SEC=2 \
DIRECTORY_ADMIN_TOKEN="${ADMIN_TOKEN}" \
timeout 90s go run ./cmd/node --directory >"$main_log" 2>&1 &
main_pid=$!

cleanup() {
  kill "${peer_a_pid:-}" >/dev/null 2>&1 || true
  kill "${peer_b_pid:-}" >/dev/null 2>&1 || true
  kill "${main_pid:-}" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

wait_for_health "$URL_MAIN" "$main_log" "main directory"

status_initial=""
for _ in $(seq 1 80); do
  status_initial="$(curl -fsS "${URL_MAIN}/v1/admin/sync-status" --config "$admin_header_cfg" || true)"
  if echo "$status_initial" | jq -e '.peer.success == true and .peer.quorum_met == true and (.peer.success_sources >= 2) and ((.peer.source_operators // []) | index("op-sync-peer-a") != null) and ((.peer.source_operators // []) | index("op-sync-peer-b") != null)' >/dev/null; then
    break
  fi
  sleep 0.25
done
if ! echo "$status_initial" | jq -e '.peer.success == true and .peer.quorum_met == true and (.peer.success_sources >= 2) and ((.peer.source_operators // []) | index("op-sync-peer-a") != null) and ((.peer.source_operators // []) | index("op-sync-peer-b") != null)' >/dev/null; then
  echo "expected healthy sync-status baseline with two live peers"
  echo "$status_initial"
  dump_logs
  exit 1
fi

kill "${peer_b_pid:-}" >/dev/null 2>&1 || true
unset peer_b_pid

status_after_loss=""
for _ in $(seq 1 80); do
  status_after_loss="$(curl -fsS "${URL_MAIN}/v1/admin/sync-status" --config "$admin_header_cfg" || true)"
  if echo "$status_after_loss" | jq -e '.peer.success == true and .peer.quorum_met == true and (.peer.success_sources >= 1) and ((.peer.source_operators // []) | index("op-sync-peer-a") != null) and ((.peer.source_operators // []) | index("op-sync-peer-b") == null)' >/dev/null; then
    break
  fi
  sleep 0.25
done
if ! echo "$status_after_loss" | jq -e '.peer.success == true and .peer.quorum_met == true and (.peer.success_sources >= 1) and ((.peer.source_operators // []) | index("op-sync-peer-a") != null) and ((.peer.source_operators // []) | index("op-sync-peer-b") == null)' >/dev/null; then
  echo "expected sync-status quorum to stay healthy with one surviving peer after single-peer loss"
  echo "$status_after_loss"
  dump_logs
  exit 1
fi

peer_status_after_loss=""
for _ in $(seq 1 80); do
  peer_status_after_loss="$(curl -fsS "${URL_MAIN}/v1/admin/peer-status" --config "$admin_header_cfg" || true)"
  if echo "$peer_status_after_loss" | jq -e --arg down "${URL_PEER_B}" --arg up "${URL_PEER_A}" '(.peers | map(select(.url == $down)) | length) == 1 and (.peers | map(select(.url == $up)) | length) == 1 and ((.peers | map(select(.url == $down))[0]) | .configured == true and .consecutive_failures >= 1 and ((.last_error // "") | length > 0) and .cooling_down == true and .eligible == false and .retry_after_sec > 0) and ((.peers | map(select(.url == $up))[0]) | .configured == true and .cooling_down == false and .eligible == true)' >/dev/null; then
    break
  fi
  sleep 0.25
done
if ! echo "$peer_status_after_loss" | jq -e --arg down "${URL_PEER_B}" --arg up "${URL_PEER_A}" '(.peers | map(select(.url == $down)) | length) == 1 and (.peers | map(select(.url == $up)) | length) == 1 and ((.peers | map(select(.url == $down))[0]) | .configured == true and .consecutive_failures >= 1 and ((.last_error // "") | length > 0) and .cooling_down == true and .eligible == false and .retry_after_sec > 0) and ((.peers | map(select(.url == $up))[0]) | .configured == true and .cooling_down == false and .eligible == true)' >/dev/null; then
  echo "expected failed peer metadata (cooldown/failure) in admin peer-status while surviving peer remains eligible"
  echo "$peer_status_after_loss"
  dump_logs
  exit 1
fi

for _ in $(seq 1 6); do
  status_after_loss="$(curl -fsS "${URL_MAIN}/v1/admin/sync-status" --config "$admin_header_cfg" || true)"
  if ! echo "$status_after_loss" | jq -e '.peer.success == true and .peer.quorum_met == true and (.peer.success_sources >= 1) and ((.peer.source_operators // []) | index("op-sync-peer-a") != null)' >/dev/null; then
    echo "expected sync-status to stay healthy across repeated polls after single-peer loss"
    echo "$status_after_loss"
    dump_logs
    exit 1
  fi
  sleep 0.5
done

if rg -q 'panic:' "$main_log"; then
  echo "unexpected panic in sync-status chaos main directory"
  dump_logs
  exit 1
fi

echo "sync-status chaos integration check ok"
