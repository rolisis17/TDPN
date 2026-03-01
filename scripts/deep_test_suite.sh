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

echo "[deep] sync status chaos"
./scripts/integration_sync_status_chaos.sh

echo "[deep] directory beta strict"
./scripts/integration_directory_beta_strict.sh

echo "[deep] directory operator churn scale"
./scripts/integration_directory_operator_churn_scale.sh

echo "[deep] distinct operators"
./scripts/integration_distinct_operators.sh

echo "[deep] peer discovery"
./scripts/integration_peer_discovery.sh

echo "[deep] peer discovery quorum"
./scripts/integration_peer_discovery_quorum.sh

echo "[deep] peer discovery backoff"
./scripts/integration_peer_discovery_backoff.sh

echo "[deep] peer discovery require hint"
./scripts/integration_peer_discovery_require_hint.sh

echo "[deep] peer discovery source cap"
./scripts/integration_peer_discovery_source_cap.sh

echo "[deep] peer discovery operator cap"
./scripts/integration_peer_discovery_operator_cap.sh

echo "[deep] opaque source downlink"
./scripts/integration_opaque_source_downlink.sh

echo "[deep] opaque udp-only"
./scripts/integration_opaque_udp_only.sh

echo "[deep] client wg kernel proxy"
./scripts/integration_client_wg_kernel_proxy.sh

echo "[deep] exit wg proxy limit"
./scripts/integration_exit_wg_proxy_limit.sh

echo "[deep] exit wg proxy idle cleanup"
./scripts/integration_exit_wg_proxy_idle_cleanup.sh

echo "[deep] entry live-wg filter"
./scripts/integration_entry_live_wg_filter.sh

echo "[deep] exit live-wg mode"
./scripts/integration_exit_live_wg_mode.sh

echo "[deep] live-wg full path"
./scripts/integration_live_wg_full_path.sh

echo "[deep] client bootstrap recovery"
./scripts/integration_client_bootstrap_recovery.sh

echo "[deep] client bootstrap recovery matrix"
./scripts/integration_client_bootstrap_recovery_matrix.sh

echo "[deep] client startup sync"
./scripts/integration_client_startup_sync.sh

echo "[deep] exit startup sync"
./scripts/integration_exit_startup_sync.sh

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

echo "[deep] anonymous credential"
./scripts/integration_anon_credential.sh

echo "[deep] anonymous credential dispute"
./scripts/integration_anon_credential_dispute.sh

echo "[deep] adjudication window caps"
./scripts/integration_adjudication_window_caps.sh

echo "[deep] adjudication quorum"
./scripts/integration_adjudication_quorum.sh

echo "[deep] adjudication operator quorum"
./scripts/integration_adjudication_operator_quorum.sh

echo "[deep] adjudication source quorum"
./scripts/integration_adjudication_source_quorum.sh

echo "[deep] lifecycle chaos"
./scripts/integration_lifecycle_chaos.sh

echo "[deep] lifecycle chaos matrix"
./scripts/integration_lifecycle_chaos_matrix.sh

echo "[deep] client startup burst"
./scripts/integration_client_startup_burst.sh

echo "[deep] stress bootstrap"
./scripts/integration_stress_bootstrap.sh

echo "[deep] load chaos"
./scripts/integration_load_chaos.sh

echo "[deep] load chaos matrix"
./scripts/integration_load_chaos_matrix.sh

echo "[deep] ok"
