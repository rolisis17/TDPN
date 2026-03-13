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
run_step "rotate server secrets" ./scripts/integration_rotate_server_secrets.sh
run_step "directory strict governance" ./scripts/integration_directory_beta_strict.sh
run_step "cross-role strict guardrails" ./scripts/integration_beta_strict_roles.sh
run_step "easy-node client profile env wiring" ./scripts/integration_easy_node_client_profile_env.sh
run_step "easy-mode launcher wiring" ./scripts/integration_easy_mode_launcher_wiring.sh
run_step "easy-mode launcher runtime" ./scripts/integration_easy_mode_launcher_runtime.sh
run_step "incident snapshot tooling" ./scripts/integration_incident_snapshot.sh
run_step "easy-node prod authority env wiring" ./scripts/integration_easy_node_prod_server_env.sh
run_step "easy-node role guard" ./scripts/integration_easy_node_role_guard.sh
run_step "easy-node invite auth policy" ./scripts/integration_easy_node_invite_auth_policy.sh
run_step "easy-node peer identity guard" ./scripts/integration_easy_node_peer_identity_guard.sh
run_step "easy-node server preflight" ./scripts/integration_easy_node_server_preflight.sh
run_step "easy-node prod preflight tools" ./scripts/integration_prod_preflight_tools.sh
run_step "client-vpn issuer quorum" ./scripts/integration_client_vpn_issuer_quorum.sh
run_step "client-vpn operator floor" ./scripts/integration_client_vpn_operator_floor.sh
run_step "3-machine prod-profile wiring" ./scripts/integration_3machine_prod_profile_wiring.sh
run_step "3-machine prod wg soak stall guard" ./scripts/integration_3machine_prod_wg_soak_stall_guard.sh
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
