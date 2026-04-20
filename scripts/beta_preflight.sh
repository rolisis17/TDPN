#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in go rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

run_step() {
  local label="$1"
  shift
  echo "[beta-preflight] ${label}"
  "$@"
}

run_step "unit tests" go test ./...
run_step "secret hygiene" ./scripts/integration_secret_hygiene.sh
run_step "security baseline" ./scripts/integration_security_baseline.sh
run_step "github repo security baseline" ./scripts/integration_github_repo_security_baseline.sh
run_step "release integrity" ./scripts/integration_release_integrity.sh
run_step "release sbom" ./scripts/integration_release_sbom.sh
run_step "release tag verify" ./scripts/integration_release_tag_verify.sh
run_step "release policy gate" ./scripts/integration_release_policy_gate.sh
run_step "runtime doctor" ./scripts/integration_runtime_doctor.sh
run_step "manual validation status" ./scripts/integration_manual_validation_status.sh
run_step "manual validation report" ./scripts/integration_manual_validation_report.sh
run_step "roadmap progress report" ./scripts/integration_roadmap_progress_report.sh
run_step "roadmap progress resilience handoff" ./scripts/integration_roadmap_progress_resilience_handoff.sh
run_step "roadmap progress phase-2 handoff" ./scripts/integration_roadmap_progress_phase2_handoff.sh
run_step "roadmap progress phase-3 handoff" ./scripts/integration_roadmap_progress_phase3_handoff.sh
run_step "roadmap progress phase-4 handoff" ./scripts/integration_roadmap_progress_phase4_handoff.sh
run_step "roadmap progress phase-5 handoff" ./scripts/integration_roadmap_progress_phase5_handoff.sh
run_step "roadmap next actions run integration" ./scripts/integration_roadmap_next_actions_run.sh
run_step "easy-node roadmap next actions run integration" ./scripts/integration_easy_node_roadmap_next_actions_run.sh
run_step "roadmap non-blockchain actionable run integration" ./scripts/integration_roadmap_non_blockchain_actionable_run.sh
run_step "easy-node roadmap non-blockchain actionable run integration" ./scripts/integration_easy_node_roadmap_non_blockchain_actionable_run.sh
run_step "pre-real-host readiness" ./scripts/integration_pre_real_host_readiness.sh
run_step "runtime fix" ./scripts/integration_runtime_fix.sh
run_step "runtime fix record" ./scripts/integration_runtime_fix_record.sh
run_step "single-machine prod readiness" ./scripts/integration_single_machine_prod_readiness.sh
run_step "client-vpn smoke" ./scripts/integration_client_vpn_smoke.sh
run_step "client-vpn profile compare" ./scripts/integration_client_vpn_profile_compare.sh
run_step "client-vpn trust-scope wiring" ./scripts/integration_client_vpn_trust_scope_wiring.sh
run_step "client-vpn path-profile wiring" ./scripts/integration_client_vpn_path_profile_wiring.sh
run_step "client-vpn trust-reset" ./scripts/integration_client_vpn_trust_reset.sh
run_step "three-machine prod signoff" ./scripts/integration_three_machine_prod_signoff.sh
run_step "three-machine docker profile matrix" ./scripts/integration_three_machine_docker_profile_matrix.sh
run_step "three-machine docker profile matrix record" ./scripts/integration_three_machine_docker_profile_matrix_record.sh
run_step "wg-only stack selftest record" ./scripts/integration_wg_only_stack_selftest_record.sh
run_step "wg-only stack wiring" ./scripts/integration_wg_only_stack_wiring.sh
run_step "rotate server secrets" ./scripts/integration_rotate_server_secrets.sh
run_step "directory strict governance" ./scripts/integration_directory_beta_strict.sh
run_step "cross-role strict guardrails" ./scripts/integration_beta_strict_roles.sh
run_step "easy-node client profile env wiring" ./scripts/integration_easy_node_client_profile_env.sh
run_step "path profile contract integration" ./scripts/integration_path_profile_contract.sh
run_step "profile compare local integration" ./scripts/integration_profile_compare_local.sh
run_step "profile compare trend integration" ./scripts/integration_profile_compare_trend.sh
run_step "profile compare campaign integration" ./scripts/integration_profile_compare_campaign.sh
run_step "profile compare docker matrix integration" ./scripts/integration_profile_compare_docker_matrix.sh
run_step "profile compare campaign check integration" ./scripts/integration_profile_compare_campaign_check.sh
run_step "profile compare campaign signoff integration" ./scripts/integration_profile_compare_campaign_signoff.sh
run_step "profile default gate run integration" ./scripts/integration_profile_default_gate_run.sh
run_step "vpn-rc matrix path integration" ./scripts/integration_vpn_rc_matrix_path.sh
run_step "vpn-rc resilience path integration" ./scripts/integration_vpn_rc_resilience_path.sh
run_step "vpn non-blockchain fastlane integration" ./scripts/integration_vpn_non_blockchain_fastlane.sh
beta_preflight_phase1_run_session_churn_guard="${BETA_PREFLIGHT_PHASE1_RUN_SESSION_CHURN_GUARD:-${CI_PHASE1_RESILIENCE_RUN_SESSION_CHURN_GUARD:-1}}"
beta_preflight_phase1_run_3hop_runtime_integration="${BETA_PREFLIGHT_PHASE1_RUN_3HOP_RUNTIME_INTEGRATION:-${CI_PHASE1_RESILIENCE_RUN_3HOP_RUNTIME_INTEGRATION:-0}}"
run_step "phase-1 resilience gate (dry-run contract)" ./scripts/ci_phase1_resilience.sh \
  --dry-run 1 \
  --print-summary-json 0 \
  --run-session-churn-guard "$beta_preflight_phase1_run_session_churn_guard" \
  --run-3hop-runtime-integration "$beta_preflight_phase1_run_3hop_runtime_integration"
run_step "phase-1 resilience gate integration" ./scripts/integration_ci_phase1_resilience.sh
run_step "phase-2 linux prod candidate gate integration" ./scripts/integration_ci_phase2_linux_prod_candidate.sh
run_step "phase-2 linux prod candidate check integration" ./scripts/integration_phase2_linux_prod_candidate_check.sh
run_step "phase-2 linux prod candidate handoff check integration" ./scripts/integration_phase2_linux_prod_candidate_handoff_check.sh
run_step "phase-2 linux prod candidate run integration" ./scripts/integration_phase2_linux_prod_candidate_run.sh
run_step "phase-2 linux prod candidate handoff run integration" ./scripts/integration_phase2_linux_prod_candidate_handoff_run.sh
run_step "phase-2 linux prod candidate signoff integration" ./scripts/integration_phase2_linux_prod_candidate_signoff.sh
run_step "phase-3 windows client beta gate integration" ./scripts/integration_ci_phase3_windows_client_beta.sh
run_step "phase-3 windows client beta check integration" ./scripts/integration_phase3_windows_client_beta_check.sh
run_step "phase-3 windows client beta run integration" ./scripts/integration_phase3_windows_client_beta_run.sh
run_step "phase-3 windows client beta handoff check integration" ./scripts/integration_phase3_windows_client_beta_handoff_check.sh
run_step "phase-3 windows client beta handoff run integration" ./scripts/integration_phase3_windows_client_beta_handoff_run.sh
run_step "phase-4 windows full parity gate integration" ./scripts/integration_ci_phase4_windows_full_parity.sh
run_step "phase-4 windows full parity check integration" ./scripts/integration_phase4_windows_full_parity_check.sh
run_step "phase-4 windows full parity run integration" ./scripts/integration_phase4_windows_full_parity_run.sh
run_step "phase-4 windows full parity handoff check integration" ./scripts/integration_phase4_windows_full_parity_handoff_check.sh
run_step "phase-4 windows full parity handoff run integration" ./scripts/integration_phase4_windows_full_parity_handoff_run.sh
run_step "easy-node windows gate-wrapper integration" ./scripts/integration_easy_node_windows_gate_wrappers.sh
run_step "easy-node windows desktop wrappers integration" ./scripts/integration_easy_node_windows_desktop_wrappers.sh
run_step "easy-node desktop wrappers integration" ./scripts/integration_easy_node_desktop_wrappers.sh
run_step "windows desktop doctor guardrails integration" ./scripts/integration_windows_desktop_doctor_guardrails.sh
run_step "windows desktop native bootstrap guardrails integration" ./scripts/integration_windows_desktop_native_bootstrap_guardrails.sh
run_step "windows desktop dev guardrails integration" ./scripts/integration_windows_desktop_dev_guardrails.sh
run_step "windows desktop packaged run guardrails integration" ./scripts/integration_windows_desktop_packaged_run_guardrails.sh
run_step "windows desktop one-click guardrails integration" ./scripts/integration_windows_desktop_one_click_guardrails.sh
run_step "linux desktop doctor guardrails integration" ./scripts/integration_linux_desktop_doctor_guardrails.sh
run_step "linux desktop native bootstrap guardrails integration" ./scripts/integration_linux_desktop_native_bootstrap_guardrails.sh
run_step "linux desktop packaged run guardrails integration" ./scripts/integration_linux_desktop_packaged_run_guardrails.sh
run_step "linux desktop one-click guardrails integration" ./scripts/integration_linux_desktop_one_click_guardrails.sh
run_step "desktop release bundle guardrails integration" ./scripts/integration_desktop_release_bundle_guardrails.sh
run_step "desktop linux release bundle guardrails integration" ./scripts/integration_desktop_linux_release_bundle_guardrails.sh
run_step "phase-5 settlement layer gate integration" ./scripts/integration_ci_phase5_settlement_layer.sh
run_step "phase-5 settlement layer check integration" ./scripts/integration_phase5_settlement_layer_check.sh
run_step "phase-5 settlement layer run integration" ./scripts/integration_phase5_settlement_layer_run.sh
run_step "phase-5 settlement layer handoff check integration" ./scripts/integration_phase5_settlement_layer_handoff_check.sh
run_step "phase-5 settlement layer handoff run integration" ./scripts/integration_phase5_settlement_layer_handoff_run.sh
run_step "incident snapshot tooling" ./scripts/integration_incident_snapshot.sh
run_step "incident snapshot attachment tooling" ./scripts/integration_incident_snapshot_attach_artifacts.sh
run_step "incident snapshot summary tooling" ./scripts/integration_incident_snapshot_summary.sh
run_step "easy-node prod authority env wiring" ./scripts/integration_easy_node_prod_server_env.sh
run_step "easy-node server-up auto invite" ./scripts/integration_easy_node_server_up_auto_invite.sh
run_step "easy-node server federation status" ./scripts/integration_easy_node_server_federation_status.sh
run_step "easy-node server federation wait" ./scripts/integration_easy_node_server_federation_wait.sh
run_step "easy-node self-update" ./scripts/integration_easy_node_self_update.sh
run_step "phase-0 gate" ./scripts/ci_phase0.sh
run_step "local API config-v1 defaults" ./scripts/integration_local_api_config_defaults.sh
run_step "local API gpm bootstrap trust" ./scripts/integration_local_control_api_gpm_manifest_trust.sh
run_step "desktop scaffold contract" ./scripts/integration_desktop_scaffold_contract.sh
run_step "web portal contract" ./scripts/integration_web_portal_contract.sh
run_step "easy-node role guard" ./scripts/integration_easy_node_role_guard.sh
run_step "easy-node invite auth policy" ./scripts/integration_easy_node_invite_auth_policy.sh
run_step "easy-node peer identity guard" ./scripts/integration_easy_node_peer_identity_guard.sh
run_step "easy-node server preflight" ./scripts/integration_easy_node_server_preflight.sh
run_step "easy-node prod preflight tools" ./scripts/integration_prod_preflight_tools.sh
run_step "client-vpn issuer quorum" ./scripts/integration_client_vpn_issuer_quorum.sh
run_step "client-vpn operator floor" ./scripts/integration_client_vpn_operator_floor.sh
run_step "3-machine prod-profile wiring" ./scripts/integration_3machine_prod_profile_wiring.sh
run_step "3-machine prod wg soak stall guard" ./scripts/integration_3machine_prod_wg_soak_stall_guard.sh
run_step "3-machine prod wg validate ingress guard" ./scripts/integration_3machine_prod_wg_validate_ingress_guard.sh
run_step "prod gate check integration" ./scripts/integration_prod_gate_check.sh
run_step "prod gate slo summary integration" ./scripts/integration_prod_gate_slo_summary.sh
run_step "prod gate slo trend integration" ./scripts/integration_prod_gate_slo_trend.sh
run_step "prod gate slo alert integration" ./scripts/integration_prod_gate_slo_alert.sh
run_step "prod gate slo dashboard integration" ./scripts/integration_prod_gate_slo_dashboard.sh
run_step "prod gate bundle verify integration" ./scripts/integration_prod_gate_bundle_verify.sh
run_step "prod bundle incident snapshot integration" ./scripts/integration_prod_bundle_incident_snapshot.sh
run_step "prod gate signoff integration" ./scripts/integration_prod_gate_signoff.sh
run_step "prod pilot runbook integration" ./scripts/integration_prod_pilot_runbook.sh
run_step "prod pilot cohort campaign integration" ./scripts/integration_prod_pilot_cohort_campaign.sh
run_step "prod pilot cohort campaign summary integration" ./scripts/integration_prod_pilot_cohort_campaign_summary.sh
run_step "prod pilot cohort campaign check integration" ./scripts/integration_prod_pilot_cohort_campaign_check.sh
run_step "prod pilot cohort campaign signoff integration" ./scripts/integration_prod_pilot_cohort_campaign_signoff.sh
run_step "prod pilot cohort runbook integration" ./scripts/integration_prod_pilot_cohort_runbook.sh
run_step "prod pilot cohort quick integration" ./scripts/integration_prod_pilot_cohort_quick.sh
run_step "prod pilot cohort quick check integration" ./scripts/integration_prod_pilot_cohort_quick_check.sh
run_step "prod pilot cohort quick trend integration" ./scripts/integration_prod_pilot_cohort_quick_trend.sh
run_step "prod pilot cohort quick alert integration" ./scripts/integration_prod_pilot_cohort_quick_alert.sh
run_step "prod pilot cohort quick dashboard integration" ./scripts/integration_prod_pilot_cohort_quick_dashboard.sh
run_step "prod pilot cohort quick signoff integration" ./scripts/integration_prod_pilot_cohort_quick_signoff.sh
run_step "prod pilot cohort quick runbook integration" ./scripts/integration_prod_pilot_cohort_quick_runbook.sh
run_step "prod pilot cohort bundle verify integration" ./scripts/integration_prod_pilot_cohort_bundle_verify.sh
run_step "prod pilot cohort check integration" ./scripts/integration_prod_pilot_cohort_check.sh
run_step "prod pilot cohort signoff integration" ./scripts/integration_prod_pilot_cohort_signoff.sh
run_step "prod key-rotation runbook integration" ./scripts/integration_prod_key_rotation_runbook.sh
run_step "prod upgrade runbook integration" ./scripts/integration_prod_upgrade_runbook.sh
run_step "prod operator lifecycle runbook integration" ./scripts/integration_prod_operator_lifecycle_runbook.sh
run_step "distinct-operator anti-collusion" ./scripts/integration_distinct_operators.sh
run_step "peer discovery operator cap" ./scripts/integration_peer_discovery_operator_cap.sh
run_step "anonymous credential dispute" ./scripts/integration_anon_credential_dispute.sh
run_step "client bootstrap recovery matrix" ./scripts/integration_client_bootstrap_recovery_matrix.sh
run_step "client startup sync" ./scripts/integration_client_startup_sync.sh
run_step "session churn guard" ./scripts/integration_session_churn_guard.sh
run_step "client 3hop runtime" ./scripts/integration_client_3hop_runtime.sh
run_step "beta fault matrix" ./scripts/integration_beta_fault_matrix.sh
run_step "strict live-wg full path" ./scripts/integration_live_wg_full_path_strict.sh
run_step "wg-only mode guardrails" ./scripts/integration_wg_only_mode.sh
run_step "load chaos matrix" ./scripts/integration_load_chaos_matrix.sh
run_step "lifecycle chaos matrix" ./scripts/integration_lifecycle_chaos_matrix.sh

if [[ "${BETA_PREFLIGHT_PRIVILEGED:-0}" == "1" ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[beta-preflight] privileged checks requested but not running as root"
    echo "[beta-preflight] re-run with sudo and BETA_PREFLIGHT_PRIVILEGED=1"
    exit 1
  fi
  run_step "real wireguard privileged matrix" ./scripts/integration_real_wg_privileged_matrix.sh
  if [[ "${BETA_PREFLIGHT_INCLUDE_WG_ONLY_STACK_SELFTEST:-0}" == "1" ]]; then
    run_step "wg-only stack lifecycle selftest" ./scripts/integration_wg_only_stack_selftest.sh
  fi
  if [[ "${BETA_PREFLIGHT_INCLUDE_STOP_ALL_WG_ONLY_CLEANUP:-0}" == "1" ]]; then
    run_step "stop-all wg-only cleanup" ./scripts/integration_stop_all_wg_only_cleanup.sh
  fi
fi

echo "[beta-preflight] ok"
