#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

echo "[ci] unit tests"
go test ./...

echo "[ci] internal topology smoke"
DEMO_DURATION_SEC="${DEMO_DURATION_SEC:-8}" ./scripts/demo_internal_topology.sh >/tmp/ci_demo.log 2>&1 || true
if ! rg -q "exit accepted opaque packet" /tmp/ci_demo.log; then
  echo "[ci] missing expected packet acceptance log"
  cat /tmp/ci_demo.log
  exit 1
fi
if ! rg -q "wgiotap packets=" /tmp/ci_demo.log; then
  echo "[ci] missing expected tap stats log"
  cat /tmp/ci_demo.log
  exit 1
fi
if ! rg -q "client downlink opaque packets" /tmp/ci_demo.log; then
  echo "[ci] missing expected client downlink relay log"
  cat /tmp/ci_demo.log
  exit 1
fi

echo "[ci] challenge integration"
./scripts/integration_challenge.sh

echo "[ci] revocation integration"
./scripts/integration_revocation.sh

echo "[ci] token-proof replay integration"
./scripts/integration_token_proof_replay.sh

echo "[ci] provider api integration"
./scripts/integration_provider_api.sh

echo "[ci] federation integration"
./scripts/integration_federation.sh

echo "[ci] operator-quorum integration"
./scripts/integration_operator_quorum.sh

echo "[ci] sync-status-chaos integration"
./scripts/integration_sync_status_chaos.sh

echo "[ci] peer-discovery-backoff integration"
./scripts/integration_peer_discovery_backoff.sh

echo "[ci] peer-discovery-require-hint integration"
./scripts/integration_peer_discovery_require_hint.sh

echo "[ci] distinct-operator integration"
./scripts/integration_distinct_operators.sh

echo "[ci] directory-sync integration"
./scripts/integration_directory_sync.sh

echo "[ci] selection-feed integration"
./scripts/integration_selection_feed.sh

echo "[ci] trust-feed integration"
./scripts/integration_trust_feed.sh

echo "[ci] opaque-source integration"
./scripts/integration_opaque_source_downlink.sh

echo "[ci] opaque-udp-only integration"
./scripts/integration_opaque_udp_only.sh

echo "[ci] entry-live-wg-filter integration"
./scripts/integration_entry_live_wg_filter.sh

echo "[ci] session-reuse integration"
./scripts/integration_session_reuse.sh

echo "[ci] session-handoff integration"
./scripts/integration_session_handoff.sh

echo "[ci] issuer-trust-sync integration"
./scripts/integration_issuer_trust_sync.sh

echo "[ci] issuer-dispute integration"
./scripts/integration_issuer_dispute.sh

echo "[ci] adjudication-window-cap integration"
./scripts/integration_adjudication_window_caps.sh

echo "[ci] adjudication-quorum integration"
./scripts/integration_adjudication_quorum.sh

echo "[ci] adjudication-operator-quorum integration"
./scripts/integration_adjudication_operator_quorum.sh

echo "[ci] multi-issuer integration"
./scripts/integration_multi_issuer.sh

echo "[ci] load/chaos integration"
./scripts/integration_load_chaos.sh

echo "[ci] ok"
