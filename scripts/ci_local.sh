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
CI_LOCAL_DEMO_LOG=""
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  ci_local_tracked_state_listing="$(git ls-files 'data/issuer*.json' 'deploy/data/issuer*.json' 2>/dev/null)"
  while IFS= read -r rel; do
    [[ -z "$rel" ]] && continue
    [[ -f "$rel" ]] || continue
    [[ -w "$rel" ]] || continue
    CI_LOCAL_TRACKED_STATE_FILES+=("$rel")
    mkdir -p "$CI_LOCAL_STATE_DIR/orig/$(dirname "$rel")"
    cp -p "$rel" "$CI_LOCAL_STATE_DIR/orig/$rel"
  done <<<"$ci_local_tracked_state_listing"
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
  if [[ -n "${CI_LOCAL_DEMO_LOG:-}" ]]; then
    rm -f "$CI_LOCAL_DEMO_LOG" || restore_errors=$((restore_errors + 1))
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

echo "[ci] roadmap progress report integration"
./scripts/integration_roadmap_progress_report.sh

echo "[ci] roadmap progress resilience handoff integration"
./scripts/integration_roadmap_progress_resilience_handoff.sh

echo "[ci] roadmap progress phase-2 handoff integration"
./scripts/integration_roadmap_progress_phase2_handoff.sh

echo "[ci] roadmap progress phase-3 handoff integration"
./scripts/integration_roadmap_progress_phase3_handoff.sh

echo "[ci] roadmap progress phase-4 handoff integration"
./scripts/integration_roadmap_progress_phase4_handoff.sh

echo "[ci] roadmap progress phase-5 handoff integration"
./scripts/integration_roadmap_progress_phase5_handoff.sh

echo "[ci] roadmap consistency integration"
bash ./scripts/integration_roadmap_consistency.sh

echo "[ci] roadmap next actions run integration"
./scripts/integration_roadmap_next_actions_run.sh

echo "[ci] easy-node roadmap next actions run integration"
./scripts/integration_easy_node_roadmap_next_actions_run.sh

echo "[ci] roadmap non-blockchain actionable run integration"
./scripts/integration_roadmap_non_blockchain_actionable_run.sh

echo "[ci] easy-node roadmap non-blockchain actionable run integration"
./scripts/integration_easy_node_roadmap_non_blockchain_actionable_run.sh

echo "[ci] pre-real-host readiness integration"
./scripts/integration_pre_real_host_readiness.sh

echo "[ci] runtime fix integration"
./scripts/integration_runtime_fix.sh

echo "[ci] runtime fix record integration"
./scripts/integration_runtime_fix_record.sh

echo "[ci] single-machine prod readiness integration"
./scripts/integration_single_machine_prod_readiness.sh

echo "[ci] vpn-rc standard path integration"
./scripts/integration_vpn_rc_standard_path.sh

echo "[ci] vpn-rc matrix path integration"
./scripts/integration_vpn_rc_matrix_path.sh

echo "[ci] vpn-rc resilience path integration"
./scripts/integration_vpn_rc_resilience_path.sh

echo "[ci] vpn non-blockchain fastlane integration"
./scripts/integration_vpn_non_blockchain_fastlane.sh

echo "[ci] blockchain fastlane integration"
./scripts/integration_blockchain_fastlane.sh

echo "[ci] phase-1 resilience gate (dry-run contract)"
ci_local_phase1_run_session_churn_guard="${CI_LOCAL_PHASE1_RUN_SESSION_CHURN_GUARD:-${CI_PHASE1_RESILIENCE_RUN_SESSION_CHURN_GUARD:-1}}"
ci_local_phase1_run_3hop_runtime_integration="${CI_LOCAL_PHASE1_RUN_3HOP_RUNTIME_INTEGRATION:-${CI_PHASE1_RESILIENCE_RUN_3HOP_RUNTIME_INTEGRATION:-0}}"
./scripts/ci_phase1_resilience.sh \
  --dry-run 1 \
  --print-summary-json 0 \
  --run-session-churn-guard "$ci_local_phase1_run_session_churn_guard" \
  --run-3hop-runtime-integration "$ci_local_phase1_run_3hop_runtime_integration"

echo "[ci] phase-1 resilience gate integration"
./scripts/integration_ci_phase1_resilience.sh

echo "[ci] phase-2 linux prod candidate gate integration"
./scripts/integration_ci_phase2_linux_prod_candidate.sh

echo "[ci] phase-2 linux prod candidate check integration"
./scripts/integration_phase2_linux_prod_candidate_check.sh

echo "[ci] phase-2 linux prod candidate handoff check integration"
./scripts/integration_phase2_linux_prod_candidate_handoff_check.sh

echo "[ci] phase-2 linux prod candidate run integration"
./scripts/integration_phase2_linux_prod_candidate_run.sh

echo "[ci] phase-2 linux prod candidate handoff run integration"
./scripts/integration_phase2_linux_prod_candidate_handoff_run.sh

echo "[ci] phase-2 linux prod candidate signoff integration"
./scripts/integration_phase2_linux_prod_candidate_signoff.sh

echo "[ci] phase-3 windows client beta gate integration"
./scripts/integration_ci_phase3_windows_client_beta.sh

echo "[ci] phase-3 windows client beta check integration"
./scripts/integration_phase3_windows_client_beta_check.sh

echo "[ci] phase-3 windows client beta run integration"
./scripts/integration_phase3_windows_client_beta_run.sh

echo "[ci] phase-3 windows client beta handoff check integration"
./scripts/integration_phase3_windows_client_beta_handoff_check.sh

echo "[ci] phase-3 windows client beta handoff run integration"
./scripts/integration_phase3_windows_client_beta_handoff_run.sh

echo "[ci] phase-4 windows full parity gate integration"
./scripts/integration_ci_phase4_windows_full_parity.sh

echo "[ci] phase-4 windows full parity check integration"
./scripts/integration_phase4_windows_full_parity_check.sh

echo "[ci] phase-4 windows full parity run integration"
./scripts/integration_phase4_windows_full_parity_run.sh

echo "[ci] phase-4 windows full parity handoff check integration"
./scripts/integration_phase4_windows_full_parity_handoff_check.sh

echo "[ci] phase-4 windows full parity handoff run integration"
./scripts/integration_phase4_windows_full_parity_handoff_run.sh

echo "[ci] easy-node windows gate-wrapper integration"
./scripts/integration_easy_node_windows_gate_wrappers.sh

echo "[ci] easy-node windows desktop wrappers integration"
./scripts/integration_easy_node_windows_desktop_wrappers.sh

echo "[ci] easy-node windows desktop installer wrappers integration"
EASY_NODE_WINDOWS_DESKTOP_WRAPPERS_SCOPE=installer ./scripts/integration_easy_node_windows_desktop_wrappers.sh

echo "[ci] easy-node desktop wrappers integration"
./scripts/integration_easy_node_desktop_wrappers.sh

echo "[ci] windows desktop doctor guardrails integration"
./scripts/integration_windows_desktop_doctor_guardrails.sh

echo "[ci] windows desktop native bootstrap guardrails integration"
./scripts/integration_windows_desktop_native_bootstrap_guardrails.sh

echo "[ci] windows desktop shell guardrails integration"
./scripts/integration_windows_desktop_shell_guardrails.sh

echo "[ci] windows local api session guardrails integration"
./scripts/integration_windows_local_api_session_guardrails.sh

echo "[ci] windows desktop dev guardrails integration"
./scripts/integration_windows_desktop_dev_guardrails.sh

echo "[ci] windows desktop packaged-run guardrails integration"
./scripts/integration_windows_desktop_packaged_run_guardrails.sh

echo "[ci] windows desktop one-click guardrails integration"
./scripts/integration_windows_desktop_one_click_guardrails.sh

echo "[ci] windows desktop installer guardrails integration"
./scripts/integration_windows_desktop_installer_guardrails.sh

echo "[ci] linux desktop doctor guardrails integration"
./scripts/integration_linux_desktop_doctor_guardrails.sh

echo "[ci] linux desktop native bootstrap guardrails integration"
./scripts/integration_linux_desktop_native_bootstrap_guardrails.sh

echo "[ci] linux desktop dev guardrails integration"
./scripts/integration_linux_desktop_dev_guardrails.sh

echo "[ci] linux desktop packaged-run guardrails integration"
./scripts/integration_linux_desktop_packaged_run_guardrails.sh

echo "[ci] linux desktop one-click guardrails integration"
./scripts/integration_linux_desktop_one_click_guardrails.sh

echo "[ci] linux desktop installer guardrails integration"
./scripts/integration_linux_desktop_installer_guardrails.sh

echo "[ci] desktop release bundle guardrails integration"
./scripts/integration_desktop_release_bundle_guardrails.sh

echo "[ci] desktop linux release bundle guardrails integration"
./scripts/integration_desktop_linux_release_bundle_guardrails.sh

echo "[ci] phase-5 settlement layer gate integration"
./scripts/integration_ci_phase5_settlement_layer.sh

echo "[ci] phase-5 settlement layer check integration"
./scripts/integration_phase5_settlement_layer_check.sh

echo "[ci] phase-5 settlement layer run integration"
./scripts/integration_phase5_settlement_layer_run.sh

echo "[ci] phase-5 settlement layer handoff check integration"
./scripts/integration_phase5_settlement_layer_handoff_check.sh

echo "[ci] phase-5 settlement layer handoff run integration"
./scripts/integration_phase5_settlement_layer_handoff_run.sh

echo "[ci] phase-5 settlement layer summary report integration"
./scripts/integration_phase5_settlement_layer_summary_report.sh

echo "[ci] phase-6 cosmos l1 contracts gate integration"
./scripts/integration_ci_phase6_cosmos_l1_contracts.sh

echo "[ci] phase-6 cosmos l1 contracts live smoke integration"
./scripts/integration_phase6_cosmos_l1_contracts_live_smoke.sh

echo "[ci] phase-6 cosmos l1 summary report integration"
./scripts/integration_phase6_cosmos_l1_summary_report.sh

echo "[ci] phase-7 mainnet cutover gate integration"
./scripts/integration_ci_phase7_mainnet_cutover.sh

echo "[ci] phase-7 mainnet cutover check integration"
./scripts/integration_phase7_mainnet_cutover_check.sh

echo "[ci] phase-7 mainnet cutover run integration"
./scripts/integration_phase7_mainnet_cutover_run.sh

echo "[ci] phase-7 mainnet cutover handoff check integration"
./scripts/integration_phase7_mainnet_cutover_handoff_check.sh

echo "[ci] phase-7 mainnet cutover handoff run integration"
./scripts/integration_phase7_mainnet_cutover_handoff_run.sh

echo "[ci] phase-7 mainnet cutover summary report integration"
./scripts/integration_phase7_mainnet_cutover_summary_report.sh

echo "[ci] phase-7 mainnet cutover live smoke integration"
./scripts/integration_phase7_mainnet_cutover_live_smoke.sh

# Ordering contract: keep gate-wrapper coverage ahead of summary-wrapper coverage.
echo "[ci] easy-node blockchain gate-wrapper integration"
./scripts/integration_easy_node_blockchain_gate_wrappers.sh

echo "[ci] easy-node blockchain summary-wrapper integration"
./scripts/integration_easy_node_blockchain_summary_reports.sh

echo "[ci] client-vpn smoke integration"
./scripts/integration_client_vpn_smoke.sh

echo "[ci] client-vpn profile compare integration"
./scripts/integration_client_vpn_profile_compare.sh

echo "[ci] client-vpn trust-scope wiring integration"
./scripts/integration_client_vpn_trust_scope_wiring.sh

echo "[ci] client-vpn path-profile wiring integration"
./scripts/integration_client_vpn_path_profile_wiring.sh

echo "[ci] client-vpn trust-reset integration"
./scripts/integration_client_vpn_trust_reset.sh

echo "[ci] three-machine prod signoff integration"
./scripts/integration_three_machine_prod_signoff.sh

echo "[ci] three-machine docker readiness integration"
./scripts/integration_three_machine_docker_readiness.sh

echo "[ci] three-machine docker profile matrix integration"
./scripts/integration_three_machine_docker_profile_matrix.sh

echo "[ci] three-machine docker profile matrix record integration"
./scripts/integration_three_machine_docker_profile_matrix_record.sh

echo "[ci] three-machine docker readiness record integration"
./scripts/integration_three_machine_docker_readiness_record.sh

echo "[ci] real-wg privileged matrix record integration"
./scripts/integration_real_wg_privileged_matrix_record.sh

echo "[ci] 3-machine validate loopback rewrite integration"
./scripts/integration_3machine_beta_validate_loopback_rewrite.sh

echo "[ci] wg-only stack selftest record integration"
./scripts/integration_wg_only_stack_selftest_record.sh

echo "[ci] wg-only stack wiring integration"
./scripts/integration_wg_only_stack_wiring.sh

echo "[ci] internal topology smoke"
CI_LOCAL_DEMO_LOG="$(mktemp "${TMPDIR:-/tmp}/ci_demo.XXXXXX.log")"
set +e
DEMO_DURATION_SEC="${DEMO_DURATION_SEC:-8}" ./scripts/demo_internal_topology.sh >"$CI_LOCAL_DEMO_LOG" 2>&1
ci_local_demo_rc=$?
set -e
if [[ "$ci_local_demo_rc" -ne 0 && "$ci_local_demo_rc" -ne 124 && "$ci_local_demo_rc" -ne 137 ]]; then
  echo "[ci] internal topology smoke failed with unexpected exit code: ${ci_local_demo_rc}"
  cat "$CI_LOCAL_DEMO_LOG"
  exit "$ci_local_demo_rc"
fi
if ! rg -q "exit accepted opaque packet" "$CI_LOCAL_DEMO_LOG"; then
  echo "[ci] missing expected packet acceptance log"
  cat "$CI_LOCAL_DEMO_LOG"
  exit 1
fi
if ! rg -q "wgiotap packets=" "$CI_LOCAL_DEMO_LOG"; then
  echo "[ci] missing expected tap stats log"
  cat "$CI_LOCAL_DEMO_LOG"
  exit 1
fi
if ! rg -q "(client downlink opaque packets|client forwarded opaque udp packets count=)" "$CI_LOCAL_DEMO_LOG"; then
  echo "[ci] missing expected client relay/downlink log"
  cat "$CI_LOCAL_DEMO_LOG"
  exit 1
fi

echo "[ci] challenge integration"
./scripts/integration_challenge.sh

echo "[ci] revocation integration"
./scripts/integration_revocation.sh

echo "[ci] issuer slash-evidence integration"
./scripts/integration_issuer_slash_evidence.sh

echo "[ci] cosmos settlement fail-soft integration"
./scripts/integration_cosmos_settlement_failsoft.sh

echo "[ci] cosmos settlement acceptance paths integration"
./scripts/integration_cosmos_settlement_acceptance_paths.sh

echo "[ci] cosmos chain scaffold integration"
./scripts/integration_cosmos_chain_scaffold.sh

echo "[ci] cosmos vpnbilling tx integration"
./scripts/integration_cosmos_vpnbilling_tx.sh

echo "[ci] cosmos module tx surface integration"
./scripts/integration_cosmos_module_tx_surface.sh

echo "[ci] cosmos query surface integration"
./scripts/integration_cosmos_query_surface.sh

echo "[ci] cosmos proto surface integration"
./scripts/integration_cosmos_proto_surface.sh

echo "[ci] cosmos proto codegen surface integration"
./scripts/integration_cosmos_proto_codegen_surface.sh

echo "[ci] cosmos proto grpc surface integration"
./scripts/integration_cosmos_proto_grpc_surface.sh

echo "[ci] cosmos grpc app roundtrip integration"
./scripts/integration_cosmos_grpc_app_roundtrip.sh

echo "[ci] cosmos tdpnd grpc runtime smoke integration"
./scripts/integration_cosmos_tdpnd_grpc_runtime_smoke.sh

echo "[ci] cosmos tdpnd settlement bridge smoke integration"
./scripts/integration_cosmos_tdpnd_settlement_bridge_smoke.sh

echo "[ci] cosmos tdpnd state-dir persistence integration"
./scripts/integration_cosmos_tdpnd_state_dir_persistence.sh

echo "[ci] cosmos tdpnd settlement bridge live smoke integration"
./scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh

echo "[ci] cosmos bridge local stack contract integration"
./scripts/integration_cosmos_bridge_local_stack_contract.sh

echo "[ci] cosmos adapter to tdpnd bridge roundtrip integration"
./scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh

echo "[ci] cosmos tdpnd grpc live smoke integration"
./scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh

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

echo "[ci] compose privilege guardrails integration"
./scripts/integration_compose_privilege_guardrails.sh

echo "[ci] tokenpop redaction guardrails integration"
./scripts/integration_tokenpop_redaction_guardrails.sh

echo "[ci] replay shared-mode guardrails integration"
./scripts/integration_replay_shared_mode_guardrails.sh

echo "[ci] replay redis-mode integration"
./scripts/integration_replay_redis_mode.sh

echo "[ci] easy-node server-up auto-invite integration"
./scripts/integration_easy_node_server_up_auto_invite.sh

echo "[ci] easy-node server federation status integration"
./scripts/integration_easy_node_server_federation_status.sh

echo "[ci] easy-node server federation wait integration"
./scripts/integration_easy_node_server_federation_wait.sh

echo "[ci] easy-node self-update integration"
./scripts/integration_easy_node_self_update.sh

echo "[ci] phase-0 gate"
./scripts/ci_phase0.sh

echo "[ci] local API config-v1 defaults integration"
./scripts/integration_local_api_config_defaults.sh

echo "[ci] local API gpm bootstrap trust integration"
./scripts/integration_local_control_api_gpm_manifest_trust.sh

echo "[ci] desktop scaffold contract integration"
./scripts/integration_desktop_scaffold_contract.sh

echo "[ci] web portal contract integration"
./scripts/integration_web_portal_contract.sh

echo "[ci] web home contract integration"
./scripts/integration_web_home_contract.sh

echo "[ci] easy-node client profile env integration"
./scripts/integration_easy_node_client_profile_env.sh

echo "[ci] path profile contract integration"
./scripts/integration_path_profile_contract.sh

echo "[ci] profile compare local integration"
./scripts/integration_profile_compare_local.sh

echo "[ci] profile compare trend integration"
./scripts/integration_profile_compare_trend.sh

echo "[ci] profile compare campaign integration"
./scripts/integration_profile_compare_campaign.sh

echo "[ci] profile compare docker matrix integration"
./scripts/integration_profile_compare_docker_matrix.sh

echo "[ci] profile compare campaign check integration"
./scripts/integration_profile_compare_campaign_check.sh

echo "[ci] profile compare campaign signoff integration"
./scripts/integration_profile_compare_campaign_signoff.sh

echo "[ci] profile default gate run integration"
./scripts/integration_profile_default_gate_run.sh

echo "[ci] profile default gate stability run integration"
./scripts/integration_profile_default_gate_stability_run.sh

echo "[ci] easy-node profile default gate stability run integration"
./scripts/integration_easy_node_profile_default_gate_stability_run.sh

echo "[ci] easy-node profile default gate stability check integration"
./scripts/integration_easy_node_profile_default_gate_stability_check.sh

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

echo "[ci] 3-machine prod wg validate ingress guard integration"
./scripts/integration_3machine_prod_wg_validate_ingress_guard.sh

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

echo "[ci] session churn guard integration"
./scripts/integration_session_churn_guard.sh

echo "[ci] client 3hop runtime integration"
./scripts/integration_client_3hop_runtime.sh

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
