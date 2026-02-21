#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

EXIT_REPUTATION_SCORE="${EXIT_REPUTATION_SCORE:-0.9}"
EXIT_UPTIME_SCORE="${EXIT_UPTIME_SCORE:-0.85}"
EXIT_CAPACITY_SCORE="${EXIT_CAPACITY_SCORE:-0.8}"
EXIT_ABUSE_PENALTY="${EXIT_ABUSE_PENALTY:-0.1}"

EXIT_REPUTATION_SCORE="$EXIT_REPUTATION_SCORE" \
EXIT_UPTIME_SCORE="$EXIT_UPTIME_SCORE" \
EXIT_CAPACITY_SCORE="$EXIT_CAPACITY_SCORE" \
EXIT_ABUSE_PENALTY="$EXIT_ABUSE_PENALTY" \
timeout 20s go run ./cmd/node --directory --issuer --entry --exit >/tmp/selection_feed_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 2

CLIENT_SELECTION_FEED_REQUIRE=1 \
timeout 10s go run ./cmd/node --client >/tmp/selection_feed_client.log 2>&1 || true

if ! rg -q 'client selected entry=' /tmp/selection_feed_client.log; then
  echo "expected successful client bootstrap with required selection feed"
  cat /tmp/selection_feed_client.log
  cat /tmp/selection_feed_node.log
  exit 1
fi

echo "selection feed integration check ok"
