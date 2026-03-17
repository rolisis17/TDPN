#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

# Keep local CI hermetic: some integrations exercise issuer/runtime state paths
# under tracked files in data/. Snapshot and restore those tracked files so
# running ci_local.sh does not leave working-tree noise.
CI_LOCAL_STATE_DIR="$(mktemp -d)"
declare -a CI_LOCAL_TRACKED_STATE_FILES=()
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  while IFS= read -r rel; do
    [[ -z "$rel" ]] && continue
    [[ -f "$rel" ]] || continue
    [[ -w "$rel" ]] || continue
    CI_LOCAL_TRACKED_STATE_FILES+=("$rel")
    mkdir -p "$CI_LOCAL_STATE_DIR/orig/$(dirname "$rel")"
    cp -p "$rel" "$CI_LOCAL_STATE_DIR/orig/$rel"
  done < <(git ls-files 'data/issuer*.json' 'deploy/data/issuer*.json' 2>/dev/null || true)
fi

ci_local_restore_tracked_state() {
  local rel
  local restore_errors=0
  set +e
  if [[ ${#CI_LOCAL_TRACKED_STATE_FILES[@]} -gt 0 ]]; then
    for rel in "${CI_LOCAL_TRACKED_STATE_FILES[@]}"; do
      if [[ -f "$CI_LOCAL_STATE_DIR/orig/$rel" ]]; then
        mkdir -p "$(dirname "$rel")"
        cp -p "$CI_LOCAL_STATE_DIR/orig/$rel" "$rel" || restore_errors=$((restore_errors + 1))
      else
        rm -f "$rel" || restore_errors=$((restore_errors + 1))
      fi
    done
  fi
  rm -rf "$CI_LOCAL_STATE_DIR"
  set -e
  if ((restore_errors > 0)); then
    echo "[ci] warning: failed to restore ${restore_errors} tracked state file(s)"
  fi
}
trap ci_local_restore_tracked_state EXIT

echo "[ci] unit tests"
go test ./...

echo "[ci] secret hygiene integration"
./scripts/integration_secret_hygiene.sh

echo "[ci] security baseline integration"
./scripts/integration_security_baseline.sh

echo "[ci] github repo security baseline integration"
./scripts/integration_github_repo_security_baseline.sh

echo "[ci] release integrity integration"
./scripts/integration_release_integrity.sh

echo "[ci] release sbom integration"
./scripts/integration_release_sbom.sh

echo "[ci] release tag verify integration"
./scripts/integration_release_tag_verify.sh

echo "[ci] release policy gate integration"
./scripts/integration_release_policy_gate.sh

echo "[ci] runtime doctor integration"
./scripts/integration_runtime_doctor.sh

echo "[ci] manual validation status integration"
./scripts/integration_manual_validation_status.sh

echo "[ci] manual validation report integration"
./scripts/integration_manual_validation_report.sh

echo "[ci] pre-real-host readiness integration"
./scripts/integration_pre_real_host_readiness.sh

echo "[ci] runtime fix integration"
./scripts/integration_runtime_fix.sh

echo "[ci] client-vpn smoke integration"
./scripts/integration_client_vpn_smoke.sh

echo "[ci] three-machine prod signoff integration"
./scripts/integration_three_machine_prod_signoff.sh

echo "[ci] wg-only stack selftest record integration"
./scripts/integration_wg_only_stack_selftest_record.sh

echo "[ci] wg-only stack wiring integration"
./scripts/integration_wg_only_stack_wiring.sh

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
if ! rg -q "(client downlink opaque packets|client forwarded opaque udp packets count=)" /tmp/ci_demo.log; then
  echo "[ci] missing expected client relay/downlink log"
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

echo "[ci] easy-node role guard integration"
./scripts/integration_easy_node_role_guard.sh

echo "[ci] easy-node peer identity guard integration"
./scripts/integration_easy_node_peer_identity_guard.sh

echo "[ci] easy-node server preflight integration"
./scripts/integration_easy_node_server_preflight.sh

echo "[ci] easy-node prod authority/provider env wiring integration"
./scripts/integration_easy_node_prod_server_env.sh

echo "[ci] easy-node server-up auto-invite integration"
./scripts/integration_easy_node_server_up_auto_invite.sh

echo "[ci] easy-node server federation status integration"
./scripts/integration_easy_node_server_federation_status.sh

echo "[ci] easy-node server federation wait integration"
./scripts/integration_easy_node_server_federation_wait.sh

echo "[ci] easy-node self-update integration"
./scripts/integration_easy_node_self_update.sh

echo "[ci] easy-node client profile env integration"
./scripts/integration_easy_node_client_profile_env.sh

echo "[ci] easy-mode launcher wiring integration"
./scripts/integration_easy_mode_launcher_wiring.sh

echo "[ci] easy-mode launcher runtime integration"
./scripts/integration_easy_mode_launcher_runtime.sh

echo "[ci] incident snapshot integration"
./scripts/integration_incident_snapshot.sh

echo "[ci] incident snapshot attach artifacts integration"
./scripts/integration_incident_snapshot_attach_artifacts.sh

echo "[ci] incident snapshot summary integration"
./scripts/integration_incident_snapshot_summary.sh

echo "[ci] 3-machine prod-profile wiring integration"
./scripts/integration_3machine_prod_profile_wiring.sh

echo "[ci] 3-machine prod wg soak stall guard integration"
./scripts/integration_3machine_prod_wg_soak_stall_guard.sh

echo "[ci] prod gate check integration"
./scripts/integration_prod_gate_check.sh

echo "[ci] prod gate slo summary integration"
./scripts/integration_prod_gate_slo_summary.sh

echo "[ci] prod gate slo trend integration"
./scripts/integration_prod_gate_slo_trend.sh

echo "[ci] prod gate slo alert integration"
./scripts/integration_prod_gate_slo_alert.sh

echo "[ci] prod gate slo dashboard integration"
./scripts/integration_prod_gate_slo_dashboard.sh

echo "[ci] prod gate bundle verify integration"
./scripts/integration_prod_gate_bundle_verify.sh

echo "[ci] prod bundle incident snapshot integration"
./scripts/integration_prod_bundle_incident_snapshot.sh

echo "[ci] prod gate signoff integration"
./scripts/integration_prod_gate_signoff.sh

echo "[ci] prod pilot runbook integration"
./scripts/integration_prod_pilot_runbook.sh

echo "[ci] prod pilot cohort campaign integration"
./scripts/integration_prod_pilot_cohort_campaign.sh

echo "[ci] prod pilot cohort campaign summary integration"
./scripts/integration_prod_pilot_cohort_campaign_summary.sh

echo "[ci] prod pilot cohort campaign check integration"
./scripts/integration_prod_pilot_cohort_campaign_check.sh

echo "[ci] prod pilot cohort campaign signoff integration"
./scripts/integration_prod_pilot_cohort_campaign_signoff.sh

echo "[ci] prod pilot cohort runbook integration"
./scripts/integration_prod_pilot_cohort_runbook.sh

echo "[ci] prod pilot cohort quick integration"
./scripts/integration_prod_pilot_cohort_quick.sh

echo "[ci] prod pilot cohort quick check integration"
./scripts/integration_prod_pilot_cohort_quick_check.sh

echo "[ci] prod pilot cohort quick trend integration"
./scripts/integration_prod_pilot_cohort_quick_trend.sh

echo "[ci] prod pilot cohort quick alert integration"
./scripts/integration_prod_pilot_cohort_quick_alert.sh

echo "[ci] prod pilot cohort quick dashboard integration"
./scripts/integration_prod_pilot_cohort_quick_dashboard.sh

echo "[ci] prod pilot cohort quick signoff integration"
./scripts/integration_prod_pilot_cohort_quick_signoff.sh

echo "[ci] prod pilot cohort quick runbook integration"
./scripts/integration_prod_pilot_cohort_quick_runbook.sh

echo "[ci] prod pilot cohort bundle verify integration"
./scripts/integration_prod_pilot_cohort_bundle_verify.sh

echo "[ci] prod pilot cohort check integration"
./scripts/integration_prod_pilot_cohort_check.sh

echo "[ci] prod pilot cohort signoff integration"
./scripts/integration_prod_pilot_cohort_signoff.sh

echo "[ci] prod key-rotation runbook integration"
./scripts/integration_prod_key_rotation_runbook.sh

echo "[ci] prod upgrade runbook integration"
./scripts/integration_prod_upgrade_runbook.sh

echo "[ci] prod operator lifecycle runbook integration"
./scripts/integration_prod_operator_lifecycle_runbook.sh

echo "[ci] rotate-server-secrets integration"
./scripts/integration_rotate_server_secrets.sh

echo "[ci] prod preflight/admin-signing integration"
./scripts/integration_prod_preflight_tools.sh

echo "[ci] federation integration"
./scripts/integration_federation.sh

echo "[ci] operator-quorum integration"
./scripts/integration_operator_quorum.sh

echo "[ci] sync-status-chaos integration"
./scripts/integration_sync_status_chaos.sh

echo "[ci] directory-beta-strict integration"
./scripts/integration_directory_beta_strict.sh

echo "[ci] cross-role-beta-strict integration"
./scripts/integration_beta_strict_roles.sh

echo "[ci] directory-operator-churn-scale integration"
./scripts/integration_directory_operator_churn_scale.sh

echo "[ci] peer-discovery-backoff integration"
./scripts/integration_peer_discovery_backoff.sh

echo "[ci] peer-discovery-require-hint integration"
./scripts/integration_peer_discovery_require_hint.sh

echo "[ci] peer-discovery-source-cap integration"
./scripts/integration_peer_discovery_source_cap.sh

echo "[ci] peer-discovery-operator-cap integration"
./scripts/integration_peer_discovery_operator_cap.sh

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

echo "[ci] client-wg-kernel-proxy integration"
./scripts/integration_client_wg_kernel_proxy.sh

echo "[ci] exit-wg-proxy-limit integration"
./scripts/integration_exit_wg_proxy_limit.sh

echo "[ci] exit-wg-proxy-idle-cleanup integration"
./scripts/integration_exit_wg_proxy_idle_cleanup.sh

echo "[ci] entry-live-wg-filter integration"
./scripts/integration_entry_live_wg_filter.sh

echo "[ci] exit-live-wg-mode integration"
./scripts/integration_exit_live_wg_mode.sh

echo "[ci] live-wg-full-path integration"
./scripts/integration_live_wg_full_path.sh

echo "[ci] strict live-wg-full-path integration"
./scripts/integration_live_wg_full_path_strict.sh

echo "[ci] wg-only-mode guardrails integration"
./scripts/integration_wg_only_mode.sh

echo "[ci] client-bootstrap-recovery integration"
./scripts/integration_client_bootstrap_recovery.sh

echo "[ci] client-startup-sync integration"
./scripts/integration_client_startup_sync.sh

echo "[ci] exit-startup-sync integration"
./scripts/integration_exit_startup_sync.sh

if [[ "${CI_LOCAL_INCLUDE_BETA_FAULT_MATRIX:-0}" == "1" ]]; then
  echo "[ci] beta-fault-matrix integration"
  ./scripts/integration_beta_fault_matrix.sh
fi

echo "[ci] session-reuse integration"
./scripts/integration_session_reuse.sh

echo "[ci] session-handoff integration"
./scripts/integration_session_handoff.sh

echo "[ci] issuer-trust-sync integration"
./scripts/integration_issuer_trust_sync.sh

echo "[ci] issuer-dispute integration"
./scripts/integration_issuer_dispute.sh

echo "[ci] anonymous credential integration"
./scripts/integration_anon_credential.sh

echo "[ci] anonymous credential dispute integration"
./scripts/integration_anon_credential_dispute.sh

echo "[ci] adjudication-window-cap integration"
./scripts/integration_adjudication_window_caps.sh

echo "[ci] adjudication-quorum integration"
./scripts/integration_adjudication_quorum.sh

echo "[ci] adjudication-operator-quorum integration"
./scripts/integration_adjudication_operator_quorum.sh

echo "[ci] adjudication-source-quorum integration"
./scripts/integration_adjudication_source_quorum.sh

echo "[ci] multi-issuer integration"
./scripts/integration_multi_issuer.sh

echo "[ci] load/chaos integration"
./scripts/integration_load_chaos.sh

if [[ "${CI_LOCAL_INCLUDE_LOAD_CHAOS_MATRIX:-0}" == "1" ]]; then
  echo "[ci] load/chaos matrix integration"
  ./scripts/integration_load_chaos_matrix.sh
fi

if [[ "${CI_LOCAL_INCLUDE_LIFECYCLE_CHAOS_MATRIX:-0}" == "1" ]]; then
  echo "[ci] lifecycle chaos matrix integration"
  ./scripts/integration_lifecycle_chaos_matrix.sh
fi

echo "[ci] ok"
