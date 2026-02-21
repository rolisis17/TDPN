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
EXIT_BOND_SCORE="${EXIT_BOND_SCORE:-0.95}"
EXIT_STAKE_SCORE="${EXIT_STAKE_SCORE:-0.75}"

EXIT_REPUTATION_SCORE="$EXIT_REPUTATION_SCORE" \
EXIT_UPTIME_SCORE="$EXIT_UPTIME_SCORE" \
EXIT_CAPACITY_SCORE="$EXIT_CAPACITY_SCORE" \
EXIT_ABUSE_PENALTY="$EXIT_ABUSE_PENALTY" \
EXIT_BOND_SCORE="$EXIT_BOND_SCORE" \
EXIT_STAKE_SCORE="$EXIT_STAKE_SCORE" \
timeout 20s go run ./cmd/node --directory --issuer --entry --exit >/tmp/trust_feed_node.log 2>&1 &
node_pid=$!
trap 'kill $node_pid >/dev/null 2>&1 || true' EXIT

sleep 2

curl -fsS http://127.0.0.1:8081/v1/trust-attestations >/tmp/trust_feed_response.json
if ! rg -q '"bond_score":0.95' /tmp/trust_feed_response.json; then
  echo "expected trust feed to include configured bond score"
  cat /tmp/trust_feed_response.json
  cat /tmp/trust_feed_node.log
  exit 1
fi
if ! rg -q '"stake_score":0.75' /tmp/trust_feed_response.json; then
  echo "expected trust feed to include configured stake score"
  cat /tmp/trust_feed_response.json
  cat /tmp/trust_feed_node.log
  exit 1
fi

CLIENT_TRUST_FEED_REQUIRE=1 \
timeout 10s go run ./cmd/node --client >/tmp/trust_feed_client.log 2>&1 || true

if ! rg -q 'client selected entry=' /tmp/trust_feed_client.log; then
  echo "expected successful client bootstrap with required trust feed"
  cat /tmp/trust_feed_client.log
  cat /tmp/trust_feed_node.log
  exit 1
fi

echo "trust feed integration check ok"
