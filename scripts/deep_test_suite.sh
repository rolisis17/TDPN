#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

echo "[deep] race tests"
go test -race ./services/entry ./services/exit ./services/directory ./services/issuer ./internal/app

echo "[deep] http cache"
./scripts/integration_http_cache.sh

echo "[deep] key epoch rotation"
./scripts/integration_key_epoch_rotation.sh

echo "[deep] token proof replay"
./scripts/integration_token_proof_replay.sh

echo "[deep] provider api"
./scripts/integration_provider_api.sh

echo "[deep] directory key rotation"
./scripts/integration_directory_key_rotation.sh

echo "[deep] directory auto key rotation"
./scripts/integration_directory_auto_key_rotation.sh

echo "[deep] directory gossip"
./scripts/integration_directory_gossip.sh

echo "[deep] operator quorum"
./scripts/integration_operator_quorum.sh

echo "[deep] distinct operators"
./scripts/integration_distinct_operators.sh

echo "[deep] peer discovery"
./scripts/integration_peer_discovery.sh

echo "[deep] peer discovery quorum"
./scripts/integration_peer_discovery_quorum.sh

echo "[deep] opaque source downlink"
./scripts/integration_opaque_source_downlink.sh

echo "[deep] persistent opaque session"
./scripts/integration_persistent_opaque_session.sh

echo "[deep] session reuse"
./scripts/integration_session_reuse.sh

echo "[deep] session handoff"
./scripts/integration_session_handoff.sh

echo "[deep] trust feed"
./scripts/integration_trust_feed.sh

echo "[deep] issuer trust sync"
./scripts/integration_issuer_trust_sync.sh

echo "[deep] issuer dispute"
./scripts/integration_issuer_dispute.sh

echo "[deep] adjudication window caps"
./scripts/integration_adjudication_window_caps.sh

echo "[deep] lifecycle chaos"
./scripts/integration_lifecycle_chaos.sh

echo "[deep] stress bootstrap"
./scripts/integration_stress_bootstrap.sh

echo "[deep] load chaos"
./scripts/integration_load_chaos.sh

echo "[deep] ok"
