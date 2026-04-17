#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT_DIR/deploy"
AUTHORITY_ENV_FILE="$DEPLOY_DIR/.env.easy.server"
PROVIDER_ENV_FILE="$DEPLOY_DIR/.env.easy.provider"
# Backward-compatible alias for older helpers that expect SERVER_ENV_FILE.
SERVER_ENV_FILE="$AUTHORITY_ENV_FILE"
CLIENT_ENV_FILE_DEFAULT="$DEPLOY_DIR/.env.easy.client"
CLIENT_ENV_FILE="${EASY_NODE_CLIENT_ENV_FILE:-$CLIENT_ENV_FILE_DEFAULT}"
EASY_MODE_CONFIG_V1_FILE_DEFAULT="$DEPLOY_DIR/config/easy_mode_config_v1.conf"
EASY_MODE_CONFIG_V1_FILE="${EASY_NODE_CONFIG_V1_FILE:-$EASY_MODE_CONFIG_V1_FILE_DEFAULT}"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

prepare_log_dir() {
  local dir
  dir="$(default_log_dir)"
  mkdir -p "$dir"
  echo "$dir"
}

resolve_client_env_file() {
  local requested="${EASY_NODE_CLIENT_ENV_FILE:-$CLIENT_ENV_FILE_DEFAULT}"
  local dir=""
  local fallback=""
  if [[ -z "$requested" ]]; then
    requested="$CLIENT_ENV_FILE_DEFAULT"
  fi
  if [[ "$requested" = /* ]]; then
    :
  else
    requested="$ROOT_DIR/$requested"
  fi

  dir="$(dirname "$requested")"
  if [[ -e "$requested" ]]; then
    if [[ -w "$requested" ]]; then
      printf '%s\n' "$requested"
      return
    fi
  else
    mkdir -p "$dir" >/dev/null 2>&1 || true
    if [[ -d "$dir" && -w "$dir" ]]; then
      printf '%s\n' "$requested"
      return
    fi
  fi

  fallback="$(prepare_log_dir)/.env.easy.client.$(id -u).$$"
  echo "client test: env file not writable at $requested; using fallback $fallback" >&2
  printf '%s\n' "$fallback"
}

default_client_vpn_key_dir() {
  local dir="${EASY_NODE_CLIENT_VPN_KEY_DIR:-}"
  if [[ -n "$dir" ]]; then
    echo "$dir"
    return
  fi
  if [[ "$ROOT_DIR" == /mnt/* ]]; then
    if [[ -n "${XDG_STATE_HOME:-}" ]]; then
      dir="$XDG_STATE_HOME/privacynode/client_vpn"
    elif [[ -n "${HOME:-}" ]]; then
      dir="$HOME/.local/state/privacynode/client_vpn"
    else
      dir="/tmp/privacynode_client_vpn"
    fi
  else
    dir="$DEPLOY_DIR/data/client_vpn"
  fi
  echo "$dir"
}

default_client_vpn_trust_file() {
  echo "$(default_client_vpn_key_dir)/trusted_directory_keys.txt"
}

normalize_client_vpn_trust_scope_mode() {
  local value="${1:-scoped}"
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$value" in
    scoped|global)
      printf '%s\n' "$value"
      ;;
    *)
      return 1
      ;;
  esac
}

normalize_client_vpn_directory_scope_input() {
  local urls="$1"
  local -a raw_items=()
  local -a cleaned_items=()
  local item=""
  IFS=',' read -r -a raw_items <<<"$urls"
  for item in "${raw_items[@]}"; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    while [[ "$item" == */ ]]; do
      item="${item%/}"
    done
    if [[ -n "$item" ]]; then
      cleaned_items+=("$item")
    fi
  done
  if ((${#cleaned_items[@]} == 0)); then
    echo "none"
    return
  fi
  printf '%s\n' "${cleaned_items[@]}" | sort -u | paste -sd, -
}

short_hash_for_string() {
  local value="$1"
  local digest=""
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(printf '%s' "$value" | sha256sum | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    digest="$(printf '%s' "$value" | shasum -a 256 | awk '{print $1}')"
  elif command -v cksum >/dev/null 2>&1; then
    digest="$(printf '%s' "$value" | cksum | awk '{print $1}')"
  fi
  digest="${digest//[^A-Za-z0-9]/}"
  if [[ -z "$digest" ]]; then
    digest="default"
  fi
  printf '%s' "${digest:0:16}"
}

default_client_vpn_trust_file_for_directory_urls() {
  local directory_urls="$1"
  local trust_scope_mode="${2:-${EASY_NODE_CLIENT_VPN_TRUST_SCOPE:-scoped}}"
  trust_scope_mode="$(normalize_client_vpn_trust_scope_mode "$trust_scope_mode" 2>/dev/null || printf '%s' "scoped")"
  if [[ "$trust_scope_mode" == "global" ]]; then
    default_client_vpn_trust_file
    return
  fi
  local normalized_scope scope_suffix
  normalized_scope="$(normalize_client_vpn_directory_scope_input "$directory_urls")"
  scope_suffix="$(short_hash_for_string "$normalized_scope")"
  echo "$(default_client_vpn_key_dir)/trusted_directory_keys_${scope_suffix}.txt"
}

print_client_vpn_trust_mismatch_hint() {
  local log_file="$1"
  local trusted_keys_file="$2"
  local trust_scope_mode="$3"

  if [[ -z "$log_file" || ! -f "$log_file" ]]; then
    return 0
  fi
  if ! rg -q 'directory key is not trusted' "$log_file"; then
    return 0
  fi

  echo "hint: directory trust pin mismatch detected."
  echo "hint: pinned trust file: $trusted_keys_file"
  echo "hint: if this is a fresh directory key rotation, rotate/remove that pinned trust file and retry."
  if [[ "$trust_scope_mode" == "global" ]]; then
    echo "hint: current trust scope is global; set EASY_NODE_CLIENT_VPN_TRUST_SCOPE=scoped to isolate pins per directory set."
  fi
}

seed_client_vpn_trust_file_if_empty() {
  local trusted_keys_file="$1"
  local directory_urls="$2"

  if [[ -z "$trusted_keys_file" || -z "$directory_urls" ]]; then
    return 0
  fi
  if [[ -s "$trusted_keys_file" ]]; then
    return 0
  fi

  local keys_tmp durl payload parsed
  local -a tls_opts
  keys_tmp="$(mktemp)"
  : >"$keys_tmp"

  while IFS= read -r durl; do
    [[ -z "$durl" ]] && continue
    mapfile -t tls_opts < <(curl_tls_opts_for_url "$durl")
    payload="$(curl -fsS --connect-timeout 2 --max-time 6 "${tls_opts[@]}" "${durl%/}/v1/pubkeys" 2>/dev/null || true)"
    [[ -z "$payload" ]] && continue
    parsed="$(printf '%s\n' "$payload" | jq -r '.pub_keys[]? | tostring' 2>/dev/null || true)"
    [[ -z "$parsed" ]] && continue
    printf '%s\n' "$parsed" >>"$keys_tmp"
  done < <(split_csv_lines "$directory_urls")

  if [[ -s "$keys_tmp" ]]; then
    awk 'NF > 0' "$keys_tmp" | LC_ALL=C sort -u >"$trusted_keys_file"
    secure_file_permissions "$trusted_keys_file"
  fi

  rm -f "$keys_tmp"
}

root_help_is_expert() {
  local mode="${EASY_NODE_HELP_MODE:-}"
  mode="$(printf '%s' "$mode" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  if [[ "$mode" == "expert" ]]; then
    return 0
  fi

  local arg
  for arg in "$@"; do
    if [[ "$arg" == "--expert" ]]; then
      return 0
    fi
  done

  return 1
}

usage_concise() {
  cat <<'USAGE'
Usage:
  ./scripts/easy_node.sh check
  ./scripts/easy_node.sh server-status
  ./scripts/easy_node.sh server-logs [--follow [0|1]] [--tail N]
  ./scripts/easy_node.sh server-down
  ./scripts/easy_node.sh stop-all [--with-wg-only [0|1]] [--force-iface-cleanup [0|1]]
  ./scripts/easy_node.sh client-vpn-status [--show-json [0|1]]
  ./scripts/easy_node.sh client-vpn-logs [--follow [0|1]] [--tail N]
  ./scripts/easy_node.sh client-vpn-down [--force-iface-cleanup [0|1]]
  ./scripts/easy_node.sh three-machine-reminder
  ./scripts/easy_node.sh three-machine-docker-profile-matrix [three_machine_docker_profile_matrix args...]
  ./scripts/easy_node.sh three-machine-docker-profile-matrix-record [three_machine_docker_profile_matrix_record args...]
  ./scripts/easy_node.sh manual-validation-backlog
  ./scripts/easy_node.sh config-v1-show [--path PATH]
  ./scripts/easy_node.sh config-v1-init [--path PATH] [--force [0|1]]
  ./scripts/easy_node.sh local-api-session [--api-addr HOST:PORT] [--config PATH] [--config-v1-path PATH] [--service-status-command CMD] [--service-start-command CMD] [--service-stop-command CMD] [--service-restart-command CMD] [--dry-run [0|1]]
  ./scripts/easy_node.sh profile-compare-docker-matrix [--dry-run [0|1]] [profile-compare-campaign args...]
  ./scripts/easy_node.sh profile-default-gate-run [--directory-a HOST_OR_URL|--host-a HOST_OR_URL] [--directory-b HOST_OR_URL|--host-b HOST_OR_URL] [--campaign-subject INVITE_KEY|--subject INVITE_KEY] [profile-compare-campaign-signoff args...]
  ./scripts/easy_node.sh profile-default-gate-live [--host-a HOST|--directory-a HOST_OR_URL] [--host-b HOST|--directory-b HOST_OR_URL] [--campaign-subject INVITE_KEY|--subject INVITE_KEY|--key INVITE_KEY] [profile-default-gate-run args...]
  ./scripts/easy_node.sh vpn-rc-matrix-path [--reports-dir DIR] [--print-report [0|1]] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh vpn-rc-standard-path [--print-report [0|1]] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh vpn-rc-resilience-path [--docker-profile-matrix-timeout-sec N] [--rc-matrix-path-timeout-sec N] [vpn_rc_resilience_path args...]
  ./scripts/easy_node.sh vpn-non-blockchain-fastlane [--parallel [0|1]] [vpn_non_blockchain_fastlane args...]
  ./scripts/easy_node.sh blockchain-fastlane [blockchain_fastlane args...]
  ./scripts/easy_node.sh blockchain-gate-bundle [blockchain_gate_bundle args...]
  ./scripts/easy_node.sh ci-blockchain-parallel-sweep [ci_blockchain_parallel_sweep args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-metrics-input [blockchain_mainnet_activation_metrics_input args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-metrics-missing-checklist [blockchain_mainnet_activation_metrics_missing_checklist args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-metrics-missing-input-template [blockchain_mainnet_activation_metrics_missing_input_template args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-metrics-input-template [blockchain_mainnet_activation_metrics_input_template args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-metrics [blockchain_mainnet_activation_metrics args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-gate [blockchain_mainnet_activation_gate args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-gate-cycle [blockchain_mainnet_activation_gate_cycle args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-gate-cycle-seeded [blockchain_mainnet_activation_gate_cycle args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-operator-pack [blockchain_mainnet_activation_operator_pack args...]
  ./scripts/easy_node.sh blockchain-bootstrap-governance-graduation-gate [blockchain_bootstrap_governance_graduation_gate args...]
  ./scripts/easy_node.sh roadmap-non-blockchain-actionable-run [--recommended-only [0|1]] [--max-actions N] [--action-timeout-sec N] [--allow-policy-no-go [0|1]] [--parallel [0|1]] [roadmap_non_blockchain_actionable_run args...]
  ./scripts/easy_node.sh roadmap-blockchain-actionable-run [--recommended-only [0|1]] [--max-actions N] [--action-timeout-sec N] [--parallel [0|1]] [roadmap_blockchain_actionable_run args...]
  ./scripts/easy_node.sh roadmap-next-actions-run [--max-actions N] [--action-timeout-sec N] [--parallel [0|1]] [--allow-profile-default-gate-unreachable [0|1]] [--profile-default-gate-subject ID] [--include-id-prefix PREFIX] [--exclude-id-prefix PREFIX] [roadmap_next_actions_run args...]
  ./scripts/easy_node.sh ci-phase0 [ci_phase0 args...]
  ./scripts/easy_node.sh ci-phase1-resilience [--three-machine-docker-profile-matrix-timeout-sec N] [--profile-compare-docker-matrix-timeout-sec N] [--three-machine-docker-profile-matrix-record-timeout-sec N] [--vpn-rc-matrix-path-timeout-sec N] [--vpn-rc-resilience-path-timeout-sec N] [--session-churn-guard-timeout-sec N] [--3hop-runtime-integration-timeout-sec N] [ci_phase1_resilience args...]
  ./scripts/easy_node.sh phase1-resilience-handoff-check [phase1_resilience_handoff_check args...]
  ./scripts/easy_node.sh phase1-resilience-handoff-run [--refresh-from-ci-summary [0|1]] [phase1_resilience_handoff_run args...]
  ./scripts/easy_node.sh ci-phase2-linux-prod-candidate [ci_phase2_linux_prod_candidate args...]
  ./scripts/easy_node.sh phase2-linux-prod-candidate-check [phase2_linux_prod_candidate_check args...]
  ./scripts/easy_node.sh phase2-linux-prod-candidate-run [phase2_linux_prod_candidate_run args...]
  ./scripts/easy_node.sh phase2-linux-prod-candidate-signoff [phase2_linux_prod_candidate_signoff args...]
  ./scripts/easy_node.sh phase2-linux-prod-candidate-handoff-check [phase2_linux_prod_candidate_handoff_check args...]
  ./scripts/easy_node.sh phase2-linux-prod-candidate-handoff-run [phase2_linux_prod_candidate_handoff_run args...]
  ./scripts/easy_node.sh ci-phase3-windows-client-beta [ci_phase3_windows_client_beta args...]
  ./scripts/easy_node.sh phase3-windows-client-beta-check [phase3_windows_client_beta_check args...]
  ./scripts/easy_node.sh phase3-windows-client-beta-run [phase3_windows_client_beta_run args...]
  ./scripts/easy_node.sh phase3-windows-client-beta-handoff-check [phase3_windows_client_beta_handoff_check args...]
  ./scripts/easy_node.sh phase3-windows-client-beta-handoff-run [phase3_windows_client_beta_handoff_run args...]
  ./scripts/easy_node.sh ci-phase4-windows-full-parity [ci_phase4_windows_full_parity args...]
  ./scripts/easy_node.sh phase4-windows-full-parity-check [phase4_windows_full_parity_check args...]
  ./scripts/easy_node.sh phase4-windows-full-parity-run [phase4_windows_full_parity_run args...]
  ./scripts/easy_node.sh phase4-windows-full-parity-handoff-check [phase4_windows_full_parity_handoff_check args...]
  ./scripts/easy_node.sh phase4-windows-full-parity-handoff-run [phase4_windows_full_parity_handoff_run args...]
  ./scripts/easy_node.sh ci-phase5-settlement-layer [ci_phase5_settlement_layer args...]
  ./scripts/easy_node.sh phase5-settlement-layer-check [phase5_settlement_layer_check args...]
  ./scripts/easy_node.sh phase5-settlement-layer-run [phase5_settlement_layer_run args...]
  ./scripts/easy_node.sh phase5-settlement-layer-handoff-check [phase5_settlement_layer_handoff_check args...]
  ./scripts/easy_node.sh phase5-settlement-layer-handoff-run [phase5_settlement_layer_handoff_run args...]
  ./scripts/easy_node.sh phase5-settlement-layer-summary-report [phase5_settlement_layer_summary_report args...]
  ./scripts/easy_node.sh issuer-sponsor-api-live-smoke [issuer_sponsor_api_live_smoke args...]
  ./scripts/easy_node.sh issuer-settlement-status-live-smoke [issuer_settlement_status_live_smoke args...]
  ./scripts/easy_node.sh ci-phase6-cosmos-l1-build-testnet [ci_phase6_cosmos_l1_build_testnet args...]
  ./scripts/easy_node.sh ci-phase6-cosmos-l1-contracts [ci_phase6_cosmos_l1_contracts args...]
  ./scripts/easy_node.sh phase6-cosmos-l1-build-testnet-check [phase6_cosmos_l1_build_testnet_check args...]
  ./scripts/easy_node.sh phase6-cosmos-l1-build-testnet-run [phase6_cosmos_l1_build_testnet_run args...]
  ./scripts/easy_node.sh phase6-cosmos-l1-build-testnet-handoff-check [phase6_cosmos_l1_build_testnet_handoff_check args...]
  ./scripts/easy_node.sh phase6-cosmos-l1-build-testnet-handoff-run [phase6_cosmos_l1_build_testnet_handoff_run args...]
  ./scripts/easy_node.sh phase6-cosmos-l1-build-testnet-suite [phase6_cosmos_l1_build_testnet_suite args...]
  ./scripts/easy_node.sh phase6-cosmos-l1-summary-report [phase6_cosmos_l1_summary_report args...]
  ./scripts/easy_node.sh ci-phase7-mainnet-cutover [ci_phase7_mainnet_cutover args...]
  ./scripts/easy_node.sh phase7-mainnet-cutover-check [phase7_mainnet_cutover_check args...]
  ./scripts/easy_node.sh phase7-mainnet-cutover-run [phase7_mainnet_cutover_run args...]
  ./scripts/easy_node.sh phase7-mainnet-cutover-handoff-check [phase7_mainnet_cutover_handoff_check args...]
  ./scripts/easy_node.sh phase7-mainnet-cutover-handoff-run [phase7_mainnet_cutover_handoff_run args...]
  ./scripts/easy_node.sh phase7-mainnet-cutover-summary-report [phase7_mainnet_cutover_summary_report args...]
  ./scripts/easy_node.sh manual-validation-status
  ./scripts/easy_node.sh manual-validation-report
  ./scripts/easy_node.sh incident-snapshot [--bundle-dir PATH]

Simple mode commands are listed above. Advanced flags are intentionally omitted here and grouped in expert help.
Expert help:
  ./scripts/easy_node.sh --help --expert
  ./scripts/easy_node.sh help --expert
  EASY_NODE_HELP_MODE=expert ./scripts/easy_node.sh --help
USAGE
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/easy_node.sh check
  ./scripts/easy_node.sh self-update [--remote NAME] [--branch NAME] [--allow-dirty [0|1]] [--show-status [0|1]]
  ./scripts/easy_node.sh server-preflight [--mode authority|provider] [--public-host HOST] [--operator-id ID] [--issuer-id ID] [--authority-directory URL] [--authority-issuer URL] [--peer-directories URLS] [--bootstrap-directory URL] [--peer-identity-strict 0|1|auto] [--min-peer-operators N] [--timeout-sec N] [--beta-profile [0|1]] [--prod-profile [0|1]]
  ./scripts/easy_node.sh simple-server-preflight [--mode authority|provider] [--public-host HOST] [--peer-host HOST] [--prod-profile [0|1]] [--peer-identity-strict 0|1|auto] [--timeout-sec N]
  ./scripts/easy_node.sh server-up [--mode authority|provider] [--public-host HOST] [--operator-id ID] [--issuer-id ID] [--issuer-admin-token TOKEN] [--directory-admin-token TOKEN] [--entry-puzzle-secret SECRET] [--authority-directory URL] [--authority-issuer URL] [--peer-directories URLS] [--bootstrap-directory URL] [--peer-identity-strict 0|1|auto] [--client-allowlist [0|1]] [--allow-anon-cred [0|1]] [--beta-profile [0|1]] [--prod-profile [0|1]] [--show-admin-token [0|1]] [--federation-wait [0|1]] [--federation-ready-timeout-sec N] [--federation-poll-sec N] [--federation-require-configured-healthy [0|1]] [--federation-max-cooling-retry-sec N] [--federation-max-peer-sync-age-sec N] [--federation-max-issuer-sync-age-sec N] [--federation-min-peer-success-sources N] [--federation-min-issuer-success-sources N] [--federation-min-peer-source-operators N] [--federation-min-issuer-source-operators N] [--federation-wait-summary-json PATH] [--federation-wait-print-summary-json [0|1]] [--auto-invite [0|1]] [--auto-invite-count N] [--auto-invite-tier 1|2|3] [--auto-invite-wait-sec N] [--auto-invite-fail-open [0|1]]
  ./scripts/easy_node.sh server-status
  ./scripts/easy_node.sh server-federation-status [--directory-url URL] [--admin-token TOKEN] [--timeout-sec N] [--show-json [0|1]] [--require-configured-healthy [0|1]] [--max-cooling-retry-sec N] [--max-peer-sync-age-sec N] [--max-issuer-sync-age-sec N] [--min-peer-success-sources N] [--min-issuer-success-sources N] [--min-peer-source-operators N] [--min-issuer-source-operators N] [--fail-on-not-ready [0|1]] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh server-federation-wait [--directory-url URL] [--admin-token TOKEN] [--ready-timeout-sec N] [--poll-sec N] [--timeout-sec N] [--require-configured-healthy [0|1]] [--max-cooling-retry-sec N] [--max-peer-sync-age-sec N] [--max-issuer-sync-age-sec N] [--min-peer-success-sources N] [--min-issuer-success-sources N] [--min-peer-source-operators N] [--min-issuer-source-operators N] [--summary-json PATH] [--print-summary-json [0|1]] [--show-json [0|1]]
  ./scripts/easy_node.sh server-logs [--follow [0|1]] [--tail N]
  ./scripts/easy_node.sh server-session [server-up args...] [--cleanup-all [0|1]]
  ./scripts/easy_node.sh simple-server-session [--mode authority|provider] [--public-host HOST] [--peer-host HOST] [--prod-profile [0|1]] [--peer-identity-strict 0|1|auto] [--federation-wait [0|1]] [--federation-ready-timeout-sec N] [--federation-poll-sec N] [--auto-invite [0|1]] [--auto-invite-count N] [--auto-invite-tier 1|2|3] [--auto-invite-wait-sec N]
  ./scripts/easy_node.sh server-down
  ./scripts/easy_node.sh rotate-server-secrets [--restart [0|1]] [--rotate-issuer-admin [0|1]] [--show-secrets [0|1]]
  ./scripts/easy_node.sh stop-all [--with-wg-only [0|1]] [--force-iface-cleanup [0|1]]
  ./scripts/easy_node.sh install-deps-ubuntu
  ./scripts/easy_node.sh wg-only-check
  ./scripts/easy_node.sh wg-only-local-test [--matrix [0|1]] [--strict-beta [0|1]] [--timeout-sec N]
  ./scripts/easy_node.sh real-wg-privileged-matrix [integration_real_wg_privileged_matrix args...]
  ./scripts/easy_node.sh real-wg-privileged-matrix-record [real-wg-privileged-matrix args...] [--record-result [0|1]] [--manual-validation-report [0|1]] [--manual-validation-report-summary-json PATH] [--manual-validation-report-md PATH] [--matrix-summary-json PATH] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh wg-only-stack-up [--strict-beta [0|1]] [--detach [0|1]] [--base-port N] [--client-iface IFACE] [--exit-iface IFACE] [--force-iface-reset [0|1]] [--cleanup-ifaces [0|1]] [--log-file PATH]
  ./scripts/easy_node.sh wg-only-stack-status
  ./scripts/easy_node.sh wg-only-stack-down [--force-iface-cleanup [0|1]]
  ./scripts/easy_node.sh wg-only-stack-selftest [--strict-beta [0|1]] [--base-port N] [--timeout-sec N] [--min-selection-lines N] [--force-iface-reset [0|1]] [--cleanup-ifaces [0|1]] [--keep-stack [0|1]]
  ./scripts/easy_node.sh wg-only-stack-selftest-record [wg-only-stack-selftest args...] [--record-result [0|1]] [--manual-validation-report [0|1]] [--manual-validation-report-summary-json PATH] [--manual-validation-report-md PATH] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh pre-real-host-readiness [--base-port N] [--client-iface IFACE] [--exit-iface IFACE] [--vpn-iface IFACE] [--runtime-fix-prune-wg-only-dir [0|1]] [--strict-beta [0|1]] [--timeout-sec N] [--min-selection-lines N] [--force-iface-reset [0|1]] [--cleanup-ifaces [0|1]] [--keep-stack [0|1]] [--manual-validation-report-summary-json PATH] [--manual-validation-report-md PATH] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh client-test [--directory-urls URL[,URL...]] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--exit-country CC] [--exit-region REGION] [--timeout-sec N] [--path-profile 1hop|2hop|3hop|speed|speed-1hop|balanced|private] [--distinct-operators [0|1]] [--distinct-countries [0|1]] [--locality-soft-bias [0|1]] [--country-bias N] [--region-bias N] [--region-prefix-bias N] [--force-direct-exit [0|1]] [--min-selection-lines N] [--min-entry-operators N] [--min-exit-operators N] [--require-cross-operator-pair [0|1]] [--beta-profile [0|1]] [--prod-profile [0|1]]
  ./scripts/easy_node.sh simple-client-test [--bootstrap-directory URL] [--discovery-wait-sec N] [--subject ID|--anon-cred TOKEN] [--timeout-sec N] [--path-profile 1hop|2hop|3hop|speed|balanced|private] [--beta-profile [0|1]] [--prod-profile [0|1]]
  ./scripts/easy_node.sh profile-compare-local [--profiles CSV] [--rounds N] [--timeout-sec N] [--execution-mode docker|local] [--directory-urls URL[,URL...]] [--bootstrap-directory URL] [--issuer-url URL] [--entry-url URL] [--exit-url URL] [--subject ID|--anon-cred TOKEN] [--min-sources N] [--beta-profile [0|1]] [--prod-profile [0|1]] [--start-local-stack auto|0|1] [--force-stack-reset [0|1]] [--stack-strict-beta [0|1]] [--base-port N] [--client-iface IFACE] [--exit-iface IFACE] [--cleanup-ifaces [0|1]] [--keep-stack [0|1]] [--summary-json PATH] [--report-md PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh profile-compare-trend [--compare-summary-json PATH]... [--compare-summary-list FILE] [--reports-dir DIR] [--max-reports N] [--since-hours N] [--min-profile-runs N] [--min-profile-pass-rate-pct N] [--balanced-latency-margin-pct N] [--fail-on-any-fail [0|1]] [--min-decision-rate-pct N] [--summary-json PATH] [--report-md PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh profile-compare-campaign [--campaign-runs N] [--campaign-pause-sec N] [--reports-dir DIR] [--profiles CSV] [--rounds N] [--timeout-sec N] [--execution-mode docker|local] [--directory-urls URL[,URL...]] [--bootstrap-directory URL] [--issuer-url URL] [--entry-url URL] [--exit-url URL] [--subject ID|--anon-cred TOKEN] [--min-sources N] [--beta-profile [0|1]] [--prod-profile [0|1]] [--start-local-stack auto|0|1] [--force-stack-reset [0|1]] [--stack-strict-beta [0|1]] [--base-port N] [--client-iface IFACE] [--exit-iface IFACE] [--cleanup-ifaces [0|1]] [--keep-stack [0|1]] [--trend-max-reports N] [--trend-since-hours N] [--trend-min-profile-runs N] [--trend-min-profile-pass-rate-pct N] [--trend-balanced-latency-margin-pct N] [--trend-fail-on-any-fail [0|1]] [--trend-min-decision-rate-pct N] [--summary-json PATH] [--report-md PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh profile-compare-docker-matrix [--dry-run [0|1]] [profile-compare-campaign args...]
  ./scripts/easy_node.sh profile-compare-campaign-check [--campaign-summary-json PATH] [--trend-summary-json PATH] [--reports-dir DIR] [--require-status-pass [0|1]] [--require-trend-status-pass [0|1]] [--require-min-runs-total N] [--require-max-runs-fail N] [--require-max-runs-warn N] [--require-min-runs-with-summary N] [--require-recommendation-support-rate-pct N] [--require-recommended-profile PROFILE] [--allow-recommended-profiles CSV] [--disallow-experimental-default [0|1]] [--require-trend-source CSV] [--fail-on-no-go [0|1]] [--summary-json PATH] [--show-json [0|1]] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh profile-compare-campaign-signoff [--reports-dir DIR] [--campaign-summary-json PATH] [--campaign-report-md PATH] [--campaign-check-summary-json PATH] [--refresh-campaign [0|1]] [--fail-on-no-go [0|1]] [--allow-concurrent [0|1]] [--allow-summary-overwrite [0|1]] [--require-status-pass [0|1]] [--require-trend-status-pass [0|1]] [--require-min-runs-total N] [--require-max-runs-fail N] [--require-max-runs-warn N] [--require-min-runs-with-summary N] [--require-recommendation-support-rate-pct N] [--require-recommended-profile PROFILE] [--allow-recommended-profiles CSV] [--disallow-experimental-default [0|1]] [--require-trend-source CSV] [--campaign-execution-mode docker|local] [--campaign-directory-urls URL[,URL...]] [--campaign-bootstrap-directory URL] [--campaign-discovery-wait-sec N] [--campaign-issuer-url URL] [--campaign-entry-url URL] [--campaign-exit-url URL] [--campaign-subject ID|--campaign-anon-cred TOKEN] [--subject ID (alias for --campaign-subject)|--anon-cred TOKEN (alias for --campaign-anon-cred)] [--campaign-start-local-stack auto|0|1] [--campaign-timeout-sec N] [--campaign-endpoint-preflight-timeout-sec N] [--summary-json PATH] [--show-json [0|1]] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh profile-default-gate-run [--directory-a HOST_OR_URL|--host-a HOST_OR_URL] [--directory-b HOST_OR_URL|--host-b HOST_OR_URL] [--directory-a-port N] [--directory-b-port N] [--endpoint-wait-timeout-sec N] [--endpoint-wait-interval-sec N] [--endpoint-connect-timeout-sec N] [--campaign-subject INVITE_KEY|--subject INVITE_KEY] [profile-compare-campaign-signoff args...]
  ./scripts/easy_node.sh profile-default-gate-live [--host-a HOST|--directory-a HOST_OR_URL] [--host-b HOST|--directory-b HOST_OR_URL] [--campaign-subject INVITE_KEY|--subject INVITE_KEY|--key INVITE_KEY] [--reports-dir DIR] [--campaign-timeout-sec N] [--summary-json PATH] [--print-summary-json [0|1]] [profile-default-gate-run args...]
  ./scripts/easy_node.sh client-vpn-preflight [--directory-urls URL[,URL...]] [--bootstrap-directory URL] [--discovery-wait-sec N] [--path-profile 1hop|2hop|3hop|speed|balanced|private] [--issuer-url URL] [--issuer-urls URL[,URL...]] [--entry-url URL] [--exit-url URL] [--prod-profile [0|1]] [--interface IFACE] [--timeout-sec N] [--require-root [0|1]] [--operator-floor-check [0|1]] [--operator-min-operators N] [--operator-min-entry-operators N] [--operator-min-exit-operators N] [--middle-relay-check [0|1]] [--middle-relay-min-operators N] [--middle-relay-require-distinct [0|1]] [--issuer-quorum-check [0|1]] [--issuer-min-operators N] [--mtls-ca-file PATH] [--mtls-client-cert-file PATH] [--mtls-client-key-file PATH]
  ./scripts/easy_node.sh simple-client-vpn-preflight [--bootstrap-directory URL] [--discovery-wait-sec N] [--path-profile 1hop|2hop|3hop|speed|balanced|private] [--prod-profile [0|1]] [--interface IFACE]
  ./scripts/easy_node.sh client-vpn-up [--directory-urls URL[,URL...]] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--issuer-urls URL[,URL...]] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--min-operators N] [--path-profile 1hop|2hop|3hop|speed|balanced|private] [--distinct-operators [0|1]] [--distinct-countries [0|1]] [--exit-country CC] [--exit-region REGION] [--locality-soft-bias [0|1]] [--country-bias N] [--region-bias N] [--region-prefix-bias N] [--beta-profile [0|1]] [--prod-profile [0|1]] [--operator-floor-check [0|1]] [--operator-min-operators N] [--operator-min-entry-operators N] [--operator-min-exit-operators N] [--issuer-quorum-check [0|1]] [--issuer-min-operators N] [--interface IFACE] [--proxy-addr HOST:PORT] [--private-key-file PATH] [--allowed-ips CIDR] [--install-route [0|1]] [--startup-sync-timeout-sec N] [--session-reuse [0|1]] [--allow-session-churn [0|1]] [--ready-timeout-sec N] [--force-restart [0|1]] [--foreground [0|1]] [--mtls-ca-file PATH] [--mtls-client-cert-file PATH] [--mtls-client-key-file PATH] [--log-file PATH]
  ./scripts/easy_node.sh client-vpn-smoke [client-vpn-up args...] [--run-preflight [0|1]] [--defer-no-root [0|1]] [--status-check [0|1]] [--keep-up [0|1]] [--record-result [0|1]] [--pre-real-host-readiness [0|1]] [--pre-real-host-readiness-summary-json PATH] [--runtime-doctor [0|1]] [--runtime-fix [0|1]] [--runtime-fix-prune-wg-only-dir [0|1]] [--trust-reset-on-key-mismatch [0|1]] [--trust-reset-scope scoped|global] [--runtime-base-port N] [--runtime-client-iface IFACE] [--runtime-exit-iface IFACE] [--runtime-vpn-iface IFACE] [--incident-snapshot-on-fail [0|1]] [--incident-snapshot-timeout-sec N] [--incident-bundle-dir PATH] [--manual-validation-report [0|1]] [--manual-validation-report-summary-json PATH] [--manual-validation-report-md PATH] [--public-ip-url URL] [--country-url URL] [--curl-timeout-sec N] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh client-vpn-profile-compare [--profiles CSV] [--rounds N] [--pause-sec N] [--min-pass-rate-pct N] [--fail-on-any-fail [0|1]] [--directory-urls URL[,URL...]] [--bootstrap-directory URL] [--issuer-url URL] [--issuer-urls URL[,URL...]] [--entry-url URL] [--exit-url URL] [--subject ID|--anon-cred TOKEN] [--min-sources N] [--min-operators N] [--beta-profile [0|1]] [--prod-profile [0|1]] [--operator-floor-check [0|1]] [--issuer-quorum-check [0|1]] [--issuer-min-operators N] [--interface IFACE] [--proxy-addr HOST:PORT] [--mtls-ca-file PATH] [--mtls-client-cert-file PATH] [--mtls-client-key-file PATH] [--run-preflight [0|1]] [--status-check [0|1]] [--runtime-doctor [0|1]] [--runtime-fix [0|1]] [--trust-reset-on-key-mismatch [0|1]] [--trust-reset-scope scoped|global] [--public-ip-url URL] [--country-url URL] [--summary-json PATH] [--report-md PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh client-vpn-status [--show-json [0|1]]
  ./scripts/easy_node.sh config-v1-show [--path PATH]
  ./scripts/easy_node.sh config-v1-init [--path PATH] [--force [0|1]]
  ./scripts/easy_node.sh config-v1-set-profile --path-profile 1hop|2hop|3hop [--path PATH]
  ./scripts/easy_node.sh local-api-session [--api-addr HOST:PORT] [--config PATH] [--config-v1-path PATH] [--script-path PATH] [--allow-update [0|1]] [--command-timeout-sec N] [--service-status-command CMD] [--service-start-command CMD] [--service-stop-command CMD] [--service-restart-command CMD] [--connect-path-profile-default 1hop|2hop|3hop] [--connect-interface-default IFACE] [--connect-run-preflight-default [0|1]] [--connect-prod-profile-default auto|0|1] [--dry-run [0|1]]
  ./scripts/easy_node.sh client-vpn-logs [--follow [0|1]] [--tail N]
  ./scripts/easy_node.sh client-vpn-session [client-vpn-up args...] [--cleanup-all [0|1]]
  ./scripts/easy_node.sh simple-client-vpn-session [--bootstrap-directory URL] [--discovery-wait-sec N] [--subject ID] [--path-profile 1hop|2hop|3hop|speed|balanced|private] [--beta-profile [0|1]] [--prod-profile [0|1]] [--interface IFACE] [--ready-timeout-sec N]
  ./scripts/easy_node.sh client-vpn-down [--force-iface-cleanup [0|1]] [--iface IFACE] [--keep-key [0|1]]
  ./scripts/easy_node.sh client-vpn-trust-reset [--directory-urls URL[,URL...]] [--bootstrap-directory URL] [--discovery-wait-sec N] [--trust-scope scoped|global] [--all-scoped [0|1]] [--dry-run [0|1]] [--trust-file PATH]
  ./scripts/easy_node.sh three-machine-validate [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--issuer-a-url URL] [--issuer-b-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--client-min-selection-lines N] [--client-min-entry-operators N] [--client-min-exit-operators N] [--client-require-cross-operator-pair [0|1]] [--exit-country CC] [--exit-region REGION] [--path-profile 1hop|2hop|3hop|speed|balanced|private] [--distinct-operators [0|1]] [--distinct-countries [0|1]] [--locality-soft-bias [0|1]] [--country-bias N] [--region-bias N] [--region-prefix-bias N] [--require-issuer-quorum [0|1]] [--beta-profile [0|1]] [--prod-profile [0|1]]
  ./scripts/easy_node.sh three-machine-soak [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--issuer-a-url URL] [--issuer-b-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--rounds N] [--pause-sec N] [--fault-every N] [--fault-command CMD] [--continue-on-fail [0|1]] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--client-min-selection-lines N] [--client-min-entry-operators N] [--client-min-exit-operators N] [--client-require-cross-operator-pair [0|1]] [--exit-country CC] [--exit-region REGION] [--path-profile 1hop|2hop|3hop|speed|balanced|private] [--distinct-operators [0|1]] [--distinct-countries [0|1]] [--locality-soft-bias [0|1]] [--country-bias N] [--region-bias N] [--region-prefix-bias N] [--require-issuer-quorum [0|1]] [--beta-profile [0|1]] [--prod-profile [0|1]] [--report-file PATH]
  ./scripts/easy_node.sh three-machine-prod-gate [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--control-timeout-sec N] [--control-soak-rounds N] [--control-soak-pause-sec N] [--control-fault-every N] [--control-fault-command CMD] [--control-continue-on-fail [0|1]] [--wg-client-timeout-sec N] [--wg-session-sec N] [--wg-soak-rounds N] [--wg-soak-pause-sec N] [--wg-slo-profile off|recommended|strict] [--wg-max-consecutive-failures N] [--wg-max-round-duration-sec N] [--wg-max-recovery-sec N] [--wg-max-failure-class CLASS=N] [--wg-disallow-unknown-failure-class [0|1]] [--wg-strict-ingress-rehearsal [0|1]] [--wg-min-selection-lines N] [--wg-min-entry-operators N] [--wg-min-exit-operators N] [--wg-min-cross-operator-pairs N] [--wg-fault-every N] [--wg-fault-command CMD] [--wg-continue-on-fail [0|1]] [--wg-validate-summary-json PATH] [--wg-soak-summary-json PATH] [--gate-summary-json PATH] [--fault-every N] [--fault-command CMD] [--continue-on-fail [0|1]] [--strict-distinct [0|1]] [--skip-control-soak [0|1]] [--skip-wg [0|1]] [--skip-wg-soak [0|1]] [--mtls-ca-file PATH] [--mtls-client-cert-file PATH] [--mtls-client-key-file PATH] [--report-file PATH]
  ./scripts/easy_node.sh three-machine-prod-bundle [--bundle-dir PATH] [--preflight-check [0|1]] [--preflight-timeout-sec N] [--preflight-require-root [0|1]] [--bundle-verify-check [0|1]] [--bundle-verify-show-details [0|1]] [--run-report-json PATH] [--run-report-print [0|1]] [--incident-snapshot-on-fail [0|1]] [--incident-snapshot-include-docker-logs [0|1]] [--incident-snapshot-docker-log-lines N] [--incident-snapshot-timeout-sec N] [--incident-snapshot-compose-project NAME] [--incident-snapshot-attach-artifact PATH]... [--signoff-check [0|1]] [--signoff-require-full-sequence [0|1]] [--signoff-require-wg-validate-ok [0|1]] [--signoff-require-wg-soak-ok [0|1]] [--signoff-require-wg-validate-udp-source [0|1]] [--signoff-require-wg-validate-strict-distinct [0|1]] [--signoff-require-wg-soak-diversity-pass [0|1]] [--signoff-min-wg-soak-selection-lines N] [--signoff-min-wg-soak-entry-operators N] [--signoff-min-wg-soak-exit-operators N] [--signoff-min-wg-soak-cross-operator-pairs N] [--signoff-max-wg-soak-failed-rounds N] [--signoff-show-json [0|1]] [three-machine-prod-gate args...]
  ./scripts/easy_node.sh three-machine-prod-signoff [three-machine-prod-bundle args...] [--bundle-dir PATH] [--run-report-json PATH] [--record-result [0|1]] [--pre-real-host-readiness [0|1]] [--pre-real-host-readiness-summary-json PATH] [--runtime-doctor [0|1]] [--runtime-fix [0|1]] [--runtime-fix-prune-wg-only-dir [0|1]] [--runtime-base-port N] [--runtime-client-iface IFACE] [--runtime-exit-iface IFACE] [--runtime-vpn-iface IFACE] [--manual-validation-report [0|1]] [--manual-validation-report-summary-json PATH] [--manual-validation-report-md PATH] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh three-machine-reminder
  ./scripts/easy_node.sh three-machine-docker-profile-matrix [three_machine_docker_profile_matrix args...]
  ./scripts/easy_node.sh three-machine-docker-profile-matrix-record [three_machine_docker_profile_matrix_record args...]
  ./scripts/easy_node.sh three-machine-docker-readiness [--run-validate [0|1]] [--run-soak [0|1]] [--run-peer-failover [0|1]] [--peer-failover-downtime-sec N] [--peer-failover-timeout-sec N] [--soak-rounds N] [--soak-pause-sec N] [--keep-stacks [0|1]] [--reset-data [0|1]] [--stack-a-base-port N] [--stack-b-base-port N] [--docker-host-alias HOST] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--path-profile 1hop|2hop|3hop|speed|balanced|private] [--distinct-operators [0|1]] [--require-issuer-quorum [0|1]] [--beta-profile [0|1]] [--prod-profile [0|1]] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh three-machine-docker-readiness-record [three-machine-docker-readiness args...] [--record-result [0|1]] [--manual-validation-report [0|1]] [--manual-validation-report-summary-json PATH] [--manual-validation-report-md PATH] [--rehearsal-summary-json PATH] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh manual-validation-backlog
  ./scripts/easy_node.sh single-machine-prod-readiness [--run-ci-local 0|1] [--run-beta-preflight 0|1] [--run-deep-suite 0|1] [--run-runtime-fix-record 0|1] [--run-three-machine-docker-readiness auto|0|1] [--three-machine-docker-readiness-run-validate 0|1] [--three-machine-docker-readiness-run-soak 0|1] [--three-machine-docker-readiness-run-peer-failover 0|1] [--three-machine-docker-readiness-peer-failover-downtime-sec N] [--three-machine-docker-readiness-peer-failover-timeout-sec N] [--three-machine-docker-readiness-soak-rounds N] [--three-machine-docker-readiness-soak-pause-sec N] [--three-machine-docker-readiness-path-profile speed|balanced|private] [--three-machine-docker-readiness-keep-stacks 0|1] [--three-machine-docker-readiness-summary-json PATH] [--run-profile-compare-campaign-signoff auto|0|1] [--profile-compare-campaign-signoff-refresh-campaign 0|1] [--profile-compare-campaign-signoff-fail-on-no-go 0|1] [--profile-compare-campaign-signoff-reports-dir PATH] [--profile-compare-campaign-signoff-summary-json PATH] [--profile-compare-campaign-signoff-campaign-execution-mode auto|docker|local] [--profile-compare-campaign-signoff-campaign-directory-urls URL[,URL...]] [--profile-compare-campaign-signoff-campaign-bootstrap-directory URL] [--profile-compare-campaign-signoff-campaign-discovery-wait-sec N] [--profile-compare-campaign-signoff-campaign-issuer-url URL] [--profile-compare-campaign-signoff-campaign-entry-url URL] [--profile-compare-campaign-signoff-campaign-exit-url URL] [--profile-compare-campaign-signoff-campaign-start-local-stack auto|0|1] [--run-pre-real-host-readiness auto|0|1] [--run-real-wg-privileged-matrix auto|0|1] [--beta-preflight-privileged auto|0|1] [--summary-json PATH] [--manual-validation-report-summary-json PATH] [--manual-validation-report-md PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh vpn-rc-matrix-path [--reports-dir DIR] [--matrix-summary-json PATH] [--matrix-report-md PATH] [--signoff-summary-json PATH] [--roadmap-summary-json PATH] [--roadmap-report-md PATH] [--summary-json PATH] [--campaign-execution-mode docker|local] [--campaign-bootstrap-directory URL] [--campaign-discovery-wait-sec N] [--signoff-refresh-campaign [0|1]] [--signoff-fail-on-no-go [0|1]] [--roadmap-refresh-manual-validation [0|1]] [--roadmap-refresh-single-machine-readiness [0|1]] [--print-report [0|1]] [--print-summary-json [0|1]] [--dry-run [0|1]]
  ./scripts/easy_node.sh vpn-rc-standard-path [--run-profile-compare-campaign-signoff auto|0|1] [--profile-compare-campaign-signoff-refresh-campaign 0|1] [--single-machine-summary-json PATH] [--roadmap-summary-json PATH] [--roadmap-report-md PATH] [--print-report [0|1]] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh vpn-rc-resilience-path [--docker-profile-matrix-timeout-sec N] [--rc-matrix-path-timeout-sec N] [vpn_rc_resilience_path args...]
  ./scripts/easy_node.sh vpn-non-blockchain-fastlane [--parallel [0|1]] [vpn_non_blockchain_fastlane args...]
  ./scripts/easy_node.sh blockchain-fastlane [blockchain_fastlane args...]
  ./scripts/easy_node.sh blockchain-gate-bundle [blockchain_gate_bundle args...]
  ./scripts/easy_node.sh ci-blockchain-parallel-sweep [ci_blockchain_parallel_sweep args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-metrics-input [blockchain_mainnet_activation_metrics_input args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-metrics-missing-checklist [blockchain_mainnet_activation_metrics_missing_checklist args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-metrics-missing-input-template [blockchain_mainnet_activation_metrics_missing_input_template args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-metrics-input-template [blockchain_mainnet_activation_metrics_input_template args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-metrics [blockchain_mainnet_activation_metrics args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-gate [blockchain_mainnet_activation_gate args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-gate-cycle [blockchain_mainnet_activation_gate_cycle args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-gate-cycle-seeded [blockchain_mainnet_activation_gate_cycle args...]
  ./scripts/easy_node.sh blockchain-mainnet-activation-operator-pack [blockchain_mainnet_activation_operator_pack args...]
  ./scripts/easy_node.sh blockchain-bootstrap-governance-graduation-gate [blockchain_bootstrap_governance_graduation_gate args...]
  ./scripts/easy_node.sh roadmap-non-blockchain-actionable-run [--recommended-only [0|1]] [--max-actions N] [--action-timeout-sec N] [--allow-policy-no-go [0|1]] [--parallel [0|1]] [roadmap_non_blockchain_actionable_run args...]
  ./scripts/easy_node.sh roadmap-blockchain-actionable-run [--recommended-only [0|1]] [--max-actions N] [--action-timeout-sec N] [--parallel [0|1]] [roadmap_blockchain_actionable_run args...]
  ./scripts/easy_node.sh roadmap-next-actions-run [--max-actions N] [--action-timeout-sec N] [--parallel [0|1]] [--allow-profile-default-gate-unreachable [0|1]] [--profile-default-gate-subject ID] [--include-id-prefix PREFIX] [--exclude-id-prefix PREFIX] [roadmap_next_actions_run args...]
  ./scripts/easy_node.sh ci-phase0 [ci_phase0 args...]
  ./scripts/easy_node.sh ci-phase1-resilience [--three-machine-docker-profile-matrix-timeout-sec N] [--profile-compare-docker-matrix-timeout-sec N] [--three-machine-docker-profile-matrix-record-timeout-sec N] [--vpn-rc-matrix-path-timeout-sec N] [--vpn-rc-resilience-path-timeout-sec N] [--session-churn-guard-timeout-sec N] [--3hop-runtime-integration-timeout-sec N] [ci_phase1_resilience args...]
  ./scripts/easy_node.sh phase1-resilience-handoff-check [phase1_resilience_handoff_check args...]
  ./scripts/easy_node.sh phase1-resilience-handoff-run [--refresh-from-ci-summary [0|1]] [phase1_resilience_handoff_run args...]
  ./scripts/easy_node.sh ci-phase2-linux-prod-candidate [ci_phase2_linux_prod_candidate args...]
  ./scripts/easy_node.sh phase2-linux-prod-candidate-check [phase2_linux_prod_candidate_check args...]
  ./scripts/easy_node.sh phase2-linux-prod-candidate-run [phase2_linux_prod_candidate_run args...]
  ./scripts/easy_node.sh phase2-linux-prod-candidate-signoff [phase2_linux_prod_candidate_signoff args...]
  ./scripts/easy_node.sh phase2-linux-prod-candidate-handoff-check [phase2_linux_prod_candidate_handoff_check args...]
  ./scripts/easy_node.sh phase2-linux-prod-candidate-handoff-run [phase2_linux_prod_candidate_handoff_run args...]
  ./scripts/easy_node.sh ci-phase3-windows-client-beta [ci_phase3_windows_client_beta args...]
  ./scripts/easy_node.sh phase3-windows-client-beta-check [phase3_windows_client_beta_check args...]
  ./scripts/easy_node.sh phase3-windows-client-beta-run [phase3_windows_client_beta_run args...]
  ./scripts/easy_node.sh phase3-windows-client-beta-handoff-check [phase3_windows_client_beta_handoff_check args...]
  ./scripts/easy_node.sh phase3-windows-client-beta-handoff-run [phase3_windows_client_beta_handoff_run args...]
  ./scripts/easy_node.sh ci-phase4-windows-full-parity [ci_phase4_windows_full_parity args...]
  ./scripts/easy_node.sh phase4-windows-full-parity-check [phase4_windows_full_parity_check args...]
  ./scripts/easy_node.sh phase4-windows-full-parity-run [phase4_windows_full_parity_run args...]
  ./scripts/easy_node.sh phase4-windows-full-parity-handoff-check [phase4_windows_full_parity_handoff_check args...]
  ./scripts/easy_node.sh phase4-windows-full-parity-handoff-run [phase4_windows_full_parity_handoff_run args...]
  ./scripts/easy_node.sh ci-phase5-settlement-layer [ci_phase5_settlement_layer args...]
  ./scripts/easy_node.sh phase5-settlement-layer-check [phase5_settlement_layer_check args...]
  ./scripts/easy_node.sh phase5-settlement-layer-run [phase5_settlement_layer_run args...]
  ./scripts/easy_node.sh phase5-settlement-layer-handoff-check [phase5_settlement_layer_handoff_check args...]
  ./scripts/easy_node.sh phase5-settlement-layer-handoff-run [phase5_settlement_layer_handoff_run args...]
  ./scripts/easy_node.sh phase5-settlement-layer-summary-report [phase5_settlement_layer_summary_report args...]
  ./scripts/easy_node.sh issuer-sponsor-api-live-smoke [issuer_sponsor_api_live_smoke args...]
  ./scripts/easy_node.sh issuer-settlement-status-live-smoke [issuer_settlement_status_live_smoke args...]
  ./scripts/easy_node.sh ci-phase6-cosmos-l1-build-testnet [ci_phase6_cosmos_l1_build_testnet args...]
  ./scripts/easy_node.sh ci-phase6-cosmos-l1-contracts [ci_phase6_cosmos_l1_contracts args...]
  ./scripts/easy_node.sh phase6-cosmos-l1-build-testnet-check [phase6_cosmos_l1_build_testnet_check args...]
  ./scripts/easy_node.sh phase6-cosmos-l1-build-testnet-run [phase6_cosmos_l1_build_testnet_run args...]
  ./scripts/easy_node.sh phase6-cosmos-l1-build-testnet-handoff-check [phase6_cosmos_l1_build_testnet_handoff_check args...]
  ./scripts/easy_node.sh phase6-cosmos-l1-build-testnet-handoff-run [phase6_cosmos_l1_build_testnet_handoff_run args...]
  ./scripts/easy_node.sh phase6-cosmos-l1-build-testnet-suite [phase6_cosmos_l1_build_testnet_suite args...]
  ./scripts/easy_node.sh phase6-cosmos-l1-summary-report [phase6_cosmos_l1_summary_report args...]
  ./scripts/easy_node.sh ci-phase7-mainnet-cutover [ci_phase7_mainnet_cutover args...]
  ./scripts/easy_node.sh phase7-mainnet-cutover-check [phase7_mainnet_cutover_check args...]
  ./scripts/easy_node.sh phase7-mainnet-cutover-run [phase7_mainnet_cutover_run args...]
  ./scripts/easy_node.sh phase7-mainnet-cutover-handoff-check [phase7_mainnet_cutover_handoff_check args...]
  ./scripts/easy_node.sh phase7-mainnet-cutover-handoff-run [phase7_mainnet_cutover_handoff_run args...]
  ./scripts/easy_node.sh phase7-mainnet-cutover-summary-report [phase7_mainnet_cutover_summary_report args...]
  ./scripts/easy_node.sh manual-validation-status [--base-port N] [--client-iface IFACE] [--exit-iface IFACE] [--vpn-iface IFACE] [--profile-compare-signoff-summary-json PATH] [--overlay-check-id CHECK_ID] [--overlay-status pass|fail|warn|pending|skip] [--overlay-notes TEXT] [--overlay-command TEXT] [--overlay-artifact PATH]... [--show-json [0|1]]
  ./scripts/easy_node.sh manual-validation-report [--base-port N] [--client-iface IFACE] [--exit-iface IFACE] [--vpn-iface IFACE] [--profile-compare-signoff-summary-json PATH] [--overlay-check-id CHECK_ID] [--overlay-status pass|fail|warn|pending|skip] [--overlay-notes TEXT] [--overlay-command TEXT] [--overlay-artifact PATH]... [--summary-json PATH] [--report-md PATH] [--print-report [0|1]] [--print-summary-json [0|1]] [--fail-on-not-ready [0|1]]
  ./scripts/easy_node.sh roadmap-progress-report [--refresh-manual-validation [0|1]] [--refresh-single-machine-readiness [0|1]] [--manual-validation-summary-json PATH] [--manual-validation-report-md PATH] [--profile-compare-signoff-summary-json PATH] [--single-machine-summary-json PATH] [--vpn-rc-resilience-summary-json PATH] [--phase2-linux-prod-candidate-summary-json PATH] [--phase3-windows-client-beta-summary-json PATH] [--phase4-windows-full-parity-summary-json PATH] [--phase5-settlement-layer-summary-json PATH] [--summary-json PATH] [--report-md PATH] [--print-report [0|1]] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh manual-validation-record --check-id CHECK_ID --status pass|fail|warn|pending|skip [--notes TEXT] [--artifact PATH]... [--command TEXT] [--show-json [0|1]]
  ./scripts/easy_node.sh runtime-doctor [--base-port N] [--client-iface IFACE] [--exit-iface IFACE] [--vpn-iface IFACE] [--show-json [0|1]]
  ./scripts/easy_node.sh runtime-fix [--base-port N] [--client-iface IFACE] [--exit-iface IFACE] [--vpn-iface IFACE] [--prune-wg-only-dir [0|1]] [--manual-validation-report [0|1]] [--manual-validation-report-summary-json PATH] [--manual-validation-report-md PATH] [--show-json [0|1]]
  ./scripts/easy_node.sh runtime-fix-record [runtime-fix args...] [--record-result [0|1]] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh prod-gate-check [--bundle-dir PATH] [--run-report-json PATH] [--gate-summary-json PATH] [--require-full-sequence [0|1]] [--require-wg-validate-ok [0|1]] [--require-wg-soak-ok [0|1]] [--require-preflight-ok [0|1]] [--require-bundle-ok [0|1]] [--require-integrity-ok [0|1]] [--require-signoff-ok [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--incident-snapshot-min-attachment-count N] [--incident-snapshot-max-skipped-count N|-1] [--require-wg-validate-udp-source [0|1]] [--require-wg-validate-strict-distinct [0|1]] [--require-wg-soak-diversity-pass [0|1]] [--min-wg-soak-selection-lines N] [--min-wg-soak-entry-operators N] [--min-wg-soak-exit-operators N] [--min-wg-soak-cross-operator-pairs N] [--max-wg-soak-failed-rounds N] [--show-json [0|1]]
  ./scripts/easy_node.sh prod-gate-slo-summary [--run-report-json PATH] [--bundle-dir PATH] [--gate-summary-json PATH] [--wg-validate-summary-json PATH] [--wg-soak-summary-json PATH] [--require-full-sequence [0|1]] [--require-wg-validate-ok [0|1]] [--require-wg-soak-ok [0|1]] [--max-wg-soak-failed-rounds N] [--require-preflight-ok [0|1]] [--require-bundle-ok [0|1]] [--require-integrity-ok [0|1]] [--require-signoff-ok [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--require-wg-validate-udp-source [0|1]] [--require-wg-validate-strict-distinct [0|1]] [--require-wg-soak-diversity-pass [0|1]] [--min-wg-soak-selection-lines N] [--min-wg-soak-entry-operators N] [--min-wg-soak-exit-operators N] [--min-wg-soak-cross-operator-pairs N] [--fail-on-no-go [0|1]] [--show-json [0|1]]
  ./scripts/easy_node.sh prod-gate-slo-trend [--run-report-json PATH]... [--run-report-list FILE] [--reports-dir DIR] [--max-reports N] [--since-hours N] [--require-full-sequence [0|1]] [--require-wg-validate-ok [0|1]] [--require-wg-soak-ok [0|1]] [--max-wg-soak-failed-rounds N] [--require-preflight-ok [0|1]] [--require-bundle-ok [0|1]] [--require-integrity-ok [0|1]] [--require-signoff-ok [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--require-wg-validate-udp-source [0|1]] [--require-wg-validate-strict-distinct [0|1]] [--require-wg-soak-diversity-pass [0|1]] [--min-wg-soak-selection-lines N] [--min-wg-soak-entry-operators N] [--min-wg-soak-exit-operators N] [--min-wg-soak-cross-operator-pairs N] [--fail-on-any-no-go [0|1]] [--min-go-rate-pct N] [--show-details [0|1]] [--show-top-reasons N] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh prod-gate-slo-alert [--trend-summary-json PATH] [--run-report-json PATH]... [--run-report-list FILE] [--reports-dir DIR] [--max-reports N] [--since-hours N] [--require-full-sequence [0|1]] [--require-wg-validate-ok [0|1]] [--require-wg-soak-ok [0|1]] [--max-wg-soak-failed-rounds N] [--require-preflight-ok [0|1]] [--require-bundle-ok [0|1]] [--require-integrity-ok [0|1]] [--require-signoff-ok [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--require-wg-validate-udp-source [0|1]] [--require-wg-validate-strict-distinct [0|1]] [--require-wg-soak-diversity-pass [0|1]] [--min-wg-soak-selection-lines N] [--min-wg-soak-entry-operators N] [--min-wg-soak-exit-operators N] [--min-wg-soak-cross-operator-pairs N] [--warn-go-rate-pct N] [--critical-go-rate-pct N] [--warn-no-go-count N] [--critical-no-go-count N] [--warn-eval-errors N] [--critical-eval-errors N] [--fail-on-warn [0|1]] [--fail-on-critical [0|1]] [--show-top-reasons N] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh prod-gate-slo-dashboard [--run-report-json PATH]... [--run-report-list FILE] [--reports-dir DIR] [--max-reports N] [--since-hours N] [--require-full-sequence [0|1]] [--require-wg-validate-ok [0|1]] [--require-wg-soak-ok [0|1]] [--max-wg-soak-failed-rounds N] [--require-preflight-ok [0|1]] [--require-bundle-ok [0|1]] [--require-integrity-ok [0|1]] [--require-signoff-ok [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--require-wg-validate-udp-source [0|1]] [--require-wg-validate-strict-distinct [0|1]] [--require-wg-soak-diversity-pass [0|1]] [--min-wg-soak-selection-lines N] [--min-wg-soak-entry-operators N] [--min-wg-soak-exit-operators N] [--min-wg-soak-cross-operator-pairs N] [--fail-on-any-no-go [0|1]] [--min-go-rate-pct N] [--show-top-reasons N] [--warn-go-rate-pct N] [--critical-go-rate-pct N] [--warn-no-go-count N] [--critical-no-go-count N] [--warn-eval-errors N] [--critical-eval-errors N] [--fail-on-warn [0|1]] [--fail-on-critical [0|1]] [--trend-summary-json PATH] [--alert-summary-json PATH] [--dashboard-md PATH] [--print-dashboard [0|1]] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh prod-gate-bundle-verify [--run-report-json PATH] [--bundle-dir PATH] [--bundle-tar PATH] [--bundle-tar-sha256-file PATH] [--check-tar-sha256 [0|1]] [--check-manifest [0|1]] [--show-details [0|1]]
  ./scripts/easy_node.sh prod-gate-signoff [--run-report-json PATH] [--bundle-dir PATH] [--bundle-tar PATH] [--bundle-tar-sha256-file PATH] [--check-tar-sha256 [0|1]] [--check-manifest [0|1]] [--show-integrity-details [0|1]] [--gate-summary-json PATH] [--require-full-sequence [0|1]] [--require-wg-validate-ok [0|1]] [--require-wg-soak-ok [0|1]] [--require-preflight-ok [0|1]] [--require-bundle-ok [0|1]] [--require-integrity-ok [0|1]] [--require-signoff-ok [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--incident-snapshot-min-attachment-count N] [--incident-snapshot-max-skipped-count N|-1] [--require-wg-validate-udp-source [0|1]] [--require-wg-validate-strict-distinct [0|1]] [--require-wg-soak-diversity-pass [0|1]] [--min-wg-soak-selection-lines N] [--min-wg-soak-entry-operators N] [--min-wg-soak-exit-operators N] [--min-wg-soak-cross-operator-pairs N] [--max-wg-soak-failed-rounds N] [--show-json [0|1]]
  ./scripts/easy_node.sh prod-pilot-cohort-bundle-verify [--summary-json PATH] [--reports-dir PATH] [--bundle-tar PATH] [--bundle-sha256-file PATH] [--bundle-manifest-json PATH] [--check-tar-sha256 [0|1]] [--check-manifest [0|1]] [--show-details [0|1]]
  ./scripts/easy_node.sh prod-pilot-cohort-check [--summary-json PATH] [--reports-dir PATH] [--require-status-ok [0|1]] [--require-all-rounds-ok [0|1]] [--max-round-failures N] [--require-trend-go [0|1]] [--require-trend-artifact-policy-match [0|1]] [--require-trend-wg-validate-udp-source [0|1]] [--require-trend-wg-validate-strict-distinct [0|1]] [--require-trend-wg-soak-diversity-pass [0|1]] [--min-trend-wg-soak-selection-lines N] [--min-trend-wg-soak-entry-operators N] [--min-trend-wg-soak-exit-operators N] [--min-trend-wg-soak-cross-operator-pairs N] [--min-go-rate-pct N] [--max-alert-severity OK|WARN|CRITICAL] [--require-bundle-created [0|1]] [--require-bundle-manifest [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--incident-snapshot-min-attachment-count N] [--incident-snapshot-max-skipped-count N|-1] [--show-json [0|1]]
  ./scripts/easy_node.sh prod-pilot-cohort-signoff [--summary-json PATH] [--reports-dir PATH] [--bundle-tar PATH] [--bundle-sha256-file PATH] [--bundle-manifest-json PATH] [--check-tar-sha256 [0|1]] [--check-manifest [0|1]] [--show-integrity-details [0|1]] [--require-status-ok [0|1]] [--require-all-rounds-ok [0|1]] [--max-round-failures N] [--require-trend-go [0|1]] [--require-trend-artifact-policy-match [0|1]] [--require-trend-wg-validate-udp-source [0|1]] [--require-trend-wg-validate-strict-distinct [0|1]] [--require-trend-wg-soak-diversity-pass [0|1]] [--min-trend-wg-soak-selection-lines N] [--min-trend-wg-soak-entry-operators N] [--min-trend-wg-soak-exit-operators N] [--min-trend-wg-soak-cross-operator-pairs N] [--min-go-rate-pct N] [--max-alert-severity OK|WARN|CRITICAL] [--require-bundle-created [0|1]] [--require-bundle-manifest [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--incident-snapshot-min-attachment-count N] [--incident-snapshot-max-skipped-count N|-1] [--show-json [0|1]]
  ./scripts/easy_node.sh prod-wg-validate [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--entry-url URL] [--exit-url URL] [--exit-a-url URL] [--exit-b-url URL] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--control-timeout-sec N] [--client-timeout-sec N] [--wg-session-sec N] [--client-iface IFACE] [--client-proxy-addr HOST:PORT] [--client-inner-source udp|synthetic] [--allow-synthetic-ingress [0|1]] [--inject-attempts N] [--strict-distinct [0|1]] [--skip-control-plane-check [0|1]] [--mtls-ca-file PATH] [--mtls-client-cert-file PATH] [--mtls-client-key-file PATH] [--summary-json PATH] [--report-file PATH]
  ./scripts/easy_node.sh prod-wg-soak [--rounds N] [--pause-sec N] [--fault-every N] [--fault-command CMD] [--continue-on-fail [0|1]] [--max-consecutive-failures N] [--strict-ingress-rehearsal [0|1]] [--summary-json PATH] [--report-file PATH] [prod-wg-validate args...]
  ./scripts/easy_node.sh prod-wg-strict-ingress-rehearsal [prod-wg-soak/prod-wg-validate args...]
  ./scripts/easy_node.sh prod-pilot-runbook [--pre-real-host-readiness [0|1]] [--pre-real-host-readiness-summary-json PATH] [three-machine-prod-bundle args...]
  ./scripts/easy_node.sh prod-pilot-cohort-runbook [--pre-real-host-readiness [0|1]] [--pre-real-host-readiness-summary-json PATH] [--rounds N] [--pause-sec N] [--continue-on-fail [0|1]] [--require-all-rounds-ok [0|1]] [--reports-dir PATH] [--summary-json PATH] [--trend-summary-json PATH] [--alert-summary-json PATH] [--trend-min-go-rate-pct N] [--trend-fail-on-any-no-go [0|1]] [--trend-require-wg-validate-udp-source [0|1]] [--trend-require-wg-validate-strict-distinct [0|1]] [--trend-require-wg-soak-diversity-pass [0|1]] [--trend-min-wg-soak-selection-lines N] [--trend-min-wg-soak-entry-operators N] [--trend-min-wg-soak-exit-operators N] [--trend-min-wg-soak-cross-operator-pairs N] [--trend-max-reports N] [--trend-since-hours N] [--trend-show-top-reasons N] [--warn-go-rate-pct N] [--critical-go-rate-pct N] [--warn-no-go-count N] [--critical-no-go-count N] [--warn-eval-errors N] [--critical-eval-errors N] [--max-alert-severity OK|WARN|CRITICAL] [--bundle-outputs [0|1]] [--bundle-fail-close [0|1]] [--bundle-tar PATH] [--bundle-sha256-file PATH] [--bundle-manifest-json PATH] [--print-summary-json [0|1]] [-- <prod-pilot-runbook args...>]
  ./scripts/easy_node.sh prod-pilot-cohort-campaign [--pre-real-host-readiness [0|1]] [--pre-real-host-readiness-summary-json PATH] [--campaign-summary-json PATH] [--campaign-report-md PATH] [--campaign-run-report-json PATH] [--campaign-signoff-check [0|1]] [--campaign-signoff-required [0|1]] [--campaign-signoff-summary-json PATH] [--campaign-signoff-print-summary-json [0|1]] [--campaign-signoff-refresh-summary [0|1]] [--campaign-signoff-summary-fail-on-no-go [0|1]] [--campaign-print-report [0|1]] [--campaign-print-run-report [0|1]] [--campaign-print-summary-json [0|1]] [--campaign-summary-fail-close [0|1]] [--campaign-run-report-required [0|1]] [--campaign-run-report-json-required [0|1]] [--campaign-require-incident-snapshot-on-fail [0|1]] [--campaign-require-incident-snapshot-artifacts [0|1]] [--campaign-incident-snapshot-min-attachment-count N] [--campaign-incident-snapshot-max-skipped-count N|-1] [prod-pilot-cohort-quick-runbook args...]
  ./scripts/easy_node.sh prod-pilot-cohort-campaign-summary [--runbook-summary-json PATH] [--reports-dir PATH] [--summary-json PATH] [--report-md PATH] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--incident-snapshot-min-attachment-count N] [--incident-snapshot-max-skipped-count N|-1] [--print-report [0|1]] [--print-summary-json [0|1]] [--fail-on-no-go [0|1]]
  ./scripts/easy_node.sh prod-pilot-cohort-campaign-check [--campaign-run-report-json PATH] [--campaign-summary-json PATH] [--campaign-report-md PATH] [--campaign-signoff-summary-json PATH] [--reports-dir PATH] [--require-status-ok [0|1]] [--require-quick-runbook-ok [0|1]] [--require-runbook-summary-json [0|1]] [--require-quick-run-report-json [0|1]] [--require-campaign-summary-attempted [0|1]] [--require-campaign-summary-ok [0|1]] [--require-campaign-summary-json [0|1]] [--require-campaign-summary-go [0|1]] [--require-campaign-report-md [0|1]] [--require-campaign-signoff-enabled [0|1]] [--require-campaign-signoff-required [0|1]] [--require-campaign-signoff-attempted [0|1]] [--require-campaign-signoff-ok [0|1]] [--require-campaign-signoff-summary-json [0|1]] [--require-campaign-signoff-summary-json-valid [0|1]] [--require-campaign-signoff-summary-status-ok [0|1]] [--require-campaign-signoff-summary-final-rc-zero [0|1]] [--require-campaign-summary-fail-close [0|1]] [--require-campaign-signoff-check [0|1]] [--require-campaign-run-report-required [0|1]] [--require-campaign-run-report-json-required [0|1]] [--require-artifact-path-match [0|1]] [--require-distinct-artifact-paths [0|1]] [--require-summary-policy-match [0|1]] [--require-incident-policy-clean [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--incident-snapshot-min-attachment-count N] [--incident-snapshot-max-skipped-count N|-1] [--summary-json PATH] [--print-summary-json [0|1]] [--show-json [0|1]]
  ./scripts/easy_node.sh prod-pilot-cohort-campaign-signoff [--runbook-summary-json PATH] [--campaign-run-report-json PATH] [--campaign-summary-json PATH] [--campaign-report-md PATH] [--campaign-signoff-summary-json PATH] [--reports-dir PATH] [--refresh-summary [0|1]] [--summary-fail-on-no-go [0|1]] [--require-campaign-signoff-enabled [0|1]] [--require-campaign-signoff-required [0|1]] [--require-campaign-signoff-attempted [0|1]] [--require-campaign-signoff-ok [0|1]] [--require-campaign-signoff-summary-json [0|1]] [--require-campaign-signoff-summary-json-valid [0|1]] [--require-campaign-signoff-summary-status-ok [0|1]] [--require-campaign-signoff-summary-final-rc-zero [0|1]] [--require-campaign-summary-fail-close [0|1]] [--require-campaign-signoff-check [0|1]] [--require-campaign-run-report-required [0|1]] [--require-campaign-run-report-json-required [0|1]] [--require-artifact-path-match [0|1]] [--require-distinct-artifact-paths [0|1]] [--allow-summary-overwrite [0|1]] [--summary-json PATH] [--print-summary-json [0|1]] [prod-pilot-cohort-campaign-check args...]
  ./scripts/easy_node.sh prod-pilot-cohort-quick-check [--run-report-json PATH] [--reports-dir PATH] [--require-status-ok [0|1]] [--require-runbook-ok [0|1]] [--require-signoff-attempted [0|1]] [--require-signoff-ok [0|1]] [--require-cohort-signoff-policy [0|1]] [--require-trend-artifact-policy-match [0|1]] [--require-trend-wg-validate-udp-source [0|1]] [--require-trend-wg-validate-strict-distinct [0|1]] [--require-trend-wg-soak-diversity-pass [0|1]] [--min-trend-wg-soak-selection-lines N] [--min-trend-wg-soak-entry-operators N] [--min-trend-wg-soak-exit-operators N] [--min-trend-wg-soak-cross-operator-pairs N] [--min-go-rate-pct N] [--max-alert-severity OK|WARN|CRITICAL] [--require-bundle-created [0|1]] [--require-bundle-manifest [0|1]] [--require-summary-json [0|1]] [--require-summary-status-ok [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--incident-snapshot-min-attachment-count N] [--incident-snapshot-max-skipped-count N|-1] [--max-duration-sec N] [--show-json [0|1]]
  ./scripts/easy_node.sh prod-pilot-cohort-quick-trend [--run-report-json PATH]... [--run-report-list FILE] [--reports-dir DIR] [--max-reports N] [--since-hours N] [--require-status-ok [0|1]] [--require-runbook-ok [0|1]] [--require-signoff-attempted [0|1]] [--require-signoff-ok [0|1]] [--require-cohort-signoff-policy [0|1]] [--require-summary-json [0|1]] [--require-summary-status-ok [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--incident-snapshot-min-attachment-count N] [--incident-snapshot-max-skipped-count N|-1] [--max-duration-sec N] [--fail-on-any-no-go [0|1]] [--min-go-rate-pct N] [--show-details [0|1]] [--show-top-reasons N] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh prod-pilot-cohort-quick-alert [--trend-summary-json PATH] [--run-report-json PATH]... [--run-report-list FILE] [--reports-dir DIR] [--max-reports N] [--since-hours N] [--require-status-ok [0|1]] [--require-runbook-ok [0|1]] [--require-signoff-attempted [0|1]] [--require-signoff-ok [0|1]] [--require-cohort-signoff-policy [0|1]] [--require-summary-json [0|1]] [--require-summary-status-ok [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--incident-snapshot-min-attachment-count N] [--incident-snapshot-max-skipped-count N|-1] [--max-duration-sec N] [--warn-go-rate-pct N] [--critical-go-rate-pct N] [--warn-no-go-count N] [--critical-no-go-count N] [--warn-eval-errors N] [--critical-eval-errors N] [--fail-on-warn [0|1]] [--fail-on-critical [0|1]] [--show-top-reasons N] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh prod-pilot-cohort-quick-dashboard [--run-report-json PATH]... [--run-report-list FILE] [--reports-dir DIR] [--max-reports N] [--since-hours N] [--require-status-ok [0|1]] [--require-runbook-ok [0|1]] [--require-signoff-attempted [0|1]] [--require-signoff-ok [0|1]] [--require-cohort-signoff-policy [0|1]] [--require-summary-json [0|1]] [--require-summary-status-ok [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--incident-snapshot-min-attachment-count N] [--incident-snapshot-max-skipped-count N|-1] [--max-duration-sec N] [--fail-on-any-no-go [0|1]] [--min-go-rate-pct N] [--show-top-reasons N] [--warn-go-rate-pct N] [--critical-go-rate-pct N] [--warn-no-go-count N] [--critical-no-go-count N] [--warn-eval-errors N] [--critical-eval-errors N] [--fail-on-warn [0|1]] [--fail-on-critical [0|1]] [--trend-summary-json PATH] [--alert-summary-json PATH] [--dashboard-md PATH] [--print-dashboard [0|1]] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh prod-pilot-cohort-quick-signoff [--run-report-json PATH] [--reports-dir PATH] [--check-latest [0|1]] [--check-trend [0|1]] [--check-alert [0|1]] [--require-status-ok [0|1]] [--require-runbook-ok [0|1]] [--require-signoff-attempted [0|1]] [--require-signoff-ok [0|1]] [--require-cohort-signoff-policy [0|1]] [--require-trend-artifact-policy-match [0|1]] [--require-trend-wg-validate-udp-source [0|1]] [--require-trend-wg-validate-strict-distinct [0|1]] [--require-trend-wg-soak-diversity-pass [0|1]] [--min-trend-wg-soak-selection-lines N] [--min-trend-wg-soak-entry-operators N] [--min-trend-wg-soak-exit-operators N] [--min-trend-wg-soak-cross-operator-pairs N] [--require-bundle-created [0|1]] [--require-bundle-manifest [0|1]] [--require-summary-json [0|1]] [--require-summary-status-ok [0|1]] [--require-incident-snapshot-on-fail [0|1]] [--require-incident-snapshot-artifacts [0|1]] [--incident-snapshot-min-attachment-count N] [--incident-snapshot-max-skipped-count N|-1] [--max-duration-sec N] [--max-reports N] [--since-hours N] [--fail-on-any-no-go [0|1]] [--min-go-rate-pct N] [--warn-go-rate-pct N] [--critical-go-rate-pct N] [--warn-no-go-count N] [--critical-no-go-count N] [--warn-eval-errors N] [--critical-eval-errors N] [--max-alert-severity OK|WARN|CRITICAL] [--trend-summary-json PATH] [--alert-summary-json PATH] [--signoff-json PATH] [--show-json [0|1]]
  ./scripts/easy_node.sh prod-pilot-cohort-quick-runbook [--bootstrap-directory URL] [--subject ID] [--pre-real-host-readiness [0|1]] [--pre-real-host-readiness-summary-json PATH] [--rounds N] [--pause-sec N] [--continue-on-fail [0|1]] [--require-all-rounds-ok [0|1]] [--max-round-failures N] [--trend-min-go-rate-pct N] [--max-alert-severity OK|WARN|CRITICAL] [--bundle-outputs [0|1]] [--bundle-fail-close [0|1]] [--reports-dir PATH] [--summary-json PATH] [--run-report-json PATH] [--signoff-json PATH] [--trend-summary-json PATH] [--alert-summary-json PATH] [--dashboard-md PATH] [--signoff-max-reports N] [--signoff-since-hours N] [--signoff-fail-on-any-no-go [0|1]] [--signoff-min-go-rate-pct N] [--signoff-require-cohort-signoff-policy [0|1]] [--signoff-require-trend-artifact-policy-match [0|1]] [--signoff-require-trend-wg-validate-udp-source [0|1]] [--signoff-require-trend-wg-validate-strict-distinct [0|1]] [--signoff-require-trend-wg-soak-diversity-pass [0|1]] [--signoff-min-trend-wg-soak-selection-lines N] [--signoff-min-trend-wg-soak-entry-operators N] [--signoff-min-trend-wg-soak-exit-operators N] [--signoff-min-trend-wg-soak-cross-operator-pairs N] [--signoff-require-incident-snapshot-on-fail [0|1]] [--signoff-require-incident-snapshot-artifacts [0|1]] [--signoff-incident-snapshot-min-attachment-count N] [--signoff-incident-snapshot-max-skipped-count N|-1] [--dashboard-enable [0|1]] [--dashboard-fail-close [0|1]] [--dashboard-print [0|1]] [--dashboard-print-summary-json [0|1]] [--show-json [0|1]] [-- <prod-pilot-runbook extra args...>]
  ./scripts/easy_node.sh prod-pilot-cohort-quick [--bootstrap-directory URL] [--subject ID] [--pre-real-host-readiness [0|1]] [--pre-real-host-readiness-summary-json PATH] [--rounds N] [--pause-sec N] [--continue-on-fail [0|1]] [--require-all-rounds-ok [0|1]] [--max-round-failures N] [--trend-min-go-rate-pct N] [--max-alert-severity OK|WARN|CRITICAL] [--bundle-outputs [0|1]] [--bundle-fail-close [0|1]] [--reports-dir PATH] [--summary-json PATH] [--run-report-json PATH] [--signoff-require-trend-artifact-policy-match [0|1]] [--signoff-require-trend-wg-validate-udp-source [0|1]] [--signoff-require-trend-wg-validate-strict-distinct [0|1]] [--signoff-require-trend-wg-soak-diversity-pass [0|1]] [--signoff-min-trend-wg-soak-selection-lines N] [--signoff-min-trend-wg-soak-entry-operators N] [--signoff-min-trend-wg-soak-exit-operators N] [--signoff-min-trend-wg-soak-cross-operator-pairs N] [--signoff-require-incident-snapshot-on-fail [0|1]] [--signoff-require-incident-snapshot-artifacts [0|1]] [--signoff-incident-snapshot-min-attachment-count N] [--signoff-incident-snapshot-max-skipped-count N|-1] [--print-run-report [0|1]] [--show-json [0|1]] [-- <prod-pilot-runbook extra args...>]
  ./scripts/easy_node.sh prod-key-rotation-runbook [--mode auto|authority|provider] [--backup-dir PATH] [--summary-json PATH] [--preflight-check [0|1]] [--preflight-live [0|1]] [--preflight-timeout-sec N] [--rotate-server-secrets [0|1]] [--rotate-admin-signing [0|1]] [--key-history N] [--restart [0|1]] [--restart-issuer [0|1]] [--show-secrets [0|1]] [--rollback-on-fail [0|1]] [--restart-after-rollback [0|1]] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh prod-upgrade-runbook [--mode auto|authority|provider] [--backup-dir PATH] [--summary-json PATH] [--preflight-check [0|1]] [--preflight-live [0|1]] [--preflight-timeout-sec N] [--compose-pull [0|1]] [--compose-build [0|1]] [--restart [0|1]] [--rollback-on-fail [0|1]] [--restart-after-rollback [0|1]] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh prod-operator-lifecycle-runbook [--action onboard|offboard] [--mode auto|authority|provider] [--public-host HOST] [--operator-id ID] [--issuer-id ID] [--authority-directory URL] [--authority-issuer URL] [--peer-directories URLS] [--bootstrap-directory URL] [--peer-identity-strict 0|1|auto] [--min-peer-operators N] [--client-allowlist [0|1]] [--allow-anon-cred [0|1]] [--beta-profile [0|1]] [--prod-profile [0|1]] [--preflight-check [0|1]] [--preflight-timeout-sec N] [--health-check [0|1]] [--health-timeout-sec N] [--directory-url URL] [--verify-relays [0|1]] [--verify-absent [0|1]] [--verify-relay-timeout-sec N] [--verify-relay-min-count N] [--federation-check [0|1]] [--federation-ready-timeout-sec N] [--federation-poll-sec N] [--federation-timeout-sec N] [--federation-require-configured-healthy [0|1]] [--federation-max-cooling-retry-sec N] [--federation-max-peer-sync-age-sec N] [--federation-max-issuer-sync-age-sec N] [--federation-min-peer-success-sources N] [--federation-min-issuer-success-sources N] [--federation-min-peer-source-operators N] [--federation-min-issuer-source-operators N] [--federation-wait-file PATH] [--federation-wait-file-required [0|1]] [--federation-wait-summary-json PATH] [--federation-wait-print-summary-json [0|1]] [--federation-wait-summary-required [0|1]] [--federation-status-fail-on-not-ready [0|1]] [--federation-status-file PATH] [--federation-status-file-required [0|1]] [--federation-status-summary-json PATH] [--federation-status-summary-required [0|1]] [--onboard-invite [0|1]] [--onboard-invite-count N] [--onboard-invite-tier 1|2|3] [--onboard-invite-wait-sec N] [--onboard-invite-fail-open [0|1]] [--onboard-invite-file PATH] [--rollback-on-fail [0|1]] [--rollback-verify-absent [0|1]] [--rollback-verify-timeout-sec N] [--runtime-doctor-on-fail [0|1]] [--runtime-doctor-base-port N] [--runtime-doctor-client-iface IFACE] [--runtime-doctor-exit-iface IFACE] [--runtime-doctor-vpn-iface IFACE] [--runtime-doctor-file PATH] [--runtime-doctor-file-required [0|1]] [--incident-snapshot-on-fail [0|1]] [--incident-bundle-dir PATH] [--incident-timeout-sec N] [--incident-include-docker-logs [0|1]] [--incident-docker-log-lines N] [--incident-summary-required [0|1]] [--incident-bundle-required [0|1]] [--incident-attachment-manifest-required [0|1]] [--incident-attachment-no-skips-required [0|1]] [--incident-attach-min-count N] [--incident-attachment-manifest-min-count N] [--incident-attach-artifact PATH]... [--report-md PATH] [--summary-json PATH] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh incident-snapshot [--bundle-dir PATH] [--mode auto|authority|provider|client] [--env-file PATH] [--directory-url URL] [--issuer-url URL] [--entry-url URL] [--exit-url URL] [--compose-project NAME] [--include-docker-logs [0|1]] [--docker-log-lines N] [--timeout-sec N] [--attach-artifact PATH]...
  ./scripts/easy_node.sh incident-snapshot-summary [--bundle-dir PATH] [--bundle-tar PATH] [--summary-json PATH] [--report-md PATH] [--print-report [0|1]] [--print-summary-json [0|1]]
  ./scripts/easy_node.sh pilot-runbook [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--issuer-a-url URL] [--issuer-b-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--rounds N] [--pause-sec N] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--client-min-selection-lines N] [--client-min-entry-operators N] [--client-min-exit-operators N] [--client-require-cross-operator-pair [0|1]] [--path-profile 1hop|2hop|3hop|speed|balanced|private] [--distinct-operators [0|1]] [--distinct-countries [0|1]] [--locality-soft-bias [0|1]] [--country-bias N] [--region-bias N] [--region-prefix-bias N] [--require-issuer-quorum [0|1]] [--beta-profile [0|1]] [--prod-profile [0|1]] [--bundle-dir PATH]
  ./scripts/easy_node.sh invite-generate [--issuer-url URL] [--admin-token TOKEN] [--admin-key-file FILE] [--admin-key-id ID] [--count N] [--prefix PREFIX] [--tier 1|2|3] [--wait-sec N]
  ./scripts/easy_node.sh invite-check --key KEY [--issuer-url URL] [--admin-token TOKEN] [--admin-key-file FILE] [--admin-key-id ID]
  ./scripts/easy_node.sh invite-disable --key KEY [--issuer-url URL] [--admin-token TOKEN] [--admin-key-file FILE] [--admin-key-id ID]
  ./scripts/easy_node.sh admin-signing-status
  ./scripts/easy_node.sh admin-signing-rotate [--restart-issuer [0|1]] [--key-history N]
  ./scripts/easy_node.sh prod-preflight [--days-min N] [--check-live [0|1]] [--timeout-sec N] [--live-require-configured-healthy [0|1]] [--live-max-cooling-retry-sec N] [--live-max-peer-sync-age-sec N] [--live-max-issuer-sync-age-sec N] [--live-min-peer-success-sources N] [--live-min-issuer-success-sources N] [--live-min-peer-source-operators N] [--live-min-issuer-source-operators N]
  ./scripts/easy_node.sh bootstrap-mtls [--out-dir DIR] [--public-host HOST] [--san HOST] [--days N] [--rotate-leaf [0|1]] [--rotate-ca [0|1]]
  ./scripts/easy_node.sh machine-a-test [--public-host HOST] [--report-file PATH]
  ./scripts/easy_node.sh machine-b-test --peer-directory-a URL [--public-host HOST] [--min-operators N] [--federation-timeout-sec N] [--report-file PATH]
  ./scripts/easy_node.sh machine-c-test [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--exit-country CC] [--exit-region REGION] [--path-profile 1hop|2hop|3hop|speed|balanced|private] [--distinct-operators [0|1]] [--distinct-countries [0|1]] [--locality-soft-bias [0|1]] [--country-bias N] [--region-bias N] [--region-prefix-bias N] [--beta-profile [0|1]] [--prod-profile [0|1]] [--report-file PATH]
  ./scripts/easy_node.sh discover-hosts --bootstrap-directory URL [--wait-sec N] [--min-hosts N] [--write-config [0|1]]

Notes:
  - self-update fast-forwards this repo from git remote/branch (safe default: skip dirty or non-fast-forward local state).
  - set SIMPLE_AUTO_UPDATE=1 in config-v1 (or EASY_NODE_AUTO_UPDATE=1) to auto-run self-update before selected commands (defaults include server/session + client test/VPN commands and simple wrapper variants).
  - server-preflight validates peer/issuer reachability plus identity/quorum readiness before server-up.
  - server-up --mode authority runs directory + issuer + entry-exit.
  - server-up --mode provider runs directory + entry-exit only (no local issuer/admin token).
  - server-up authority mode can auto-generate invite keys with --auto-invite (useful for quick onboarding).
  - server-up peer identity checks default to strict in beta/prod when peers are configured; in non-prod authority->provider peering, issuer-id strictness auto-relaxes when peer issuers are not reachable. use --peer-identity-strict 0 only for temporary bypass during diagnostics.
  - rotate-server-secrets rotates local server secret material in env files; use --restart 1 to apply immediately.
  - server-up --prod-profile enables fail-closed production strict mode (requires mTLS + signed issuer-admin auth).
  - admin-signing-status/admin-signing-rotate are authority-only issuer admin signer maintenance tools.
  - prod-preflight validates strict prod profile wiring (mTLS material, HTTPS URLs, and authority signer config).
  - server-federation-status prints directory peer+sync health (including configured/discovered peer failure streaks), can evaluate strict policy thresholds in one shot, and can emit machine-readable summary JSON for automation/handoff.
  - server-federation-wait blocks until directory peer-sync + issuer-sync quorum and peer-health readiness are met (or timeout), can optionally fail-close on configured-peer degradation/excessive cooldown/stale sync age, and can emit machine-readable summary JSON for automation.
  - client-test runs client-demo with --no-deps (no local server required on the client machine).
  - profile-compare-local runs repeated client-test rounds across profiles (`speed`, `balanced`, `private`, `speed-1hop`), emits JSON/markdown comparison artifacts, and recommends a default while keeping `speed-1hop` experimental/non-default and out of simple mode.
  - profile-compare-trend aggregates multiple profile-compare-local summaries into one recommendation trend report, applies reliability/latency policy thresholds, and keeps `speed-1hop` non-default and expert-only.
  - client-vpn-profile-compare runs repeatable real client-vpn-smoke rounds across `1hop|2hop|3hop`, emits JSON/markdown comparison artifacts, and recommends default/latency/privacy profiles while keeping `1hop` experimental/non-default and outside the simple path.
  - profile-compare-campaign runs repeat local profile comparisons and auto-aggregates them into one campaign-level recommendation/report bundle.
  - profile-compare-docker-matrix wraps profile-compare-campaign with docker-first defaults (`1hop,2hop,3hop`) while preserving pass-through overrides and printing summary/report artifact paths.
  - profile-compare-campaign-check applies fail-closed policy gates to campaign artifacts and emits one GO/NO-GO decision for default-profile readiness.
  - profile-compare-campaign-signoff runs campaign-check fail-closed in one command; `--refresh-campaign 1` attempts a fresh campaign run, while `--refresh-campaign 0` reuses existing campaign artifacts, and emits one signoff summary JSON for handoff. In invite-key flows, prefer `--campaign-subject` (alias `--subject`) with a real key value; fallback order is `CAMPAIGN_SUBJECT` then `INVITE_KEY`.
  - profile-default-gate-run wraps profile-compare-campaign-signoff for final optional VPN default-profile gating with A/B endpoint wait-retry preflight and roadmap docker defaults. This wrapper is invite-key subject only and rejects anon-cred flags.
  - profile-default-gate-live is a convenience wrapper for real-host runs that derives A/B hosts from `A_HOST`/`B_HOST` and subject from `INVITE_KEY` when flags are omitted, then calls `profile-default-gate-run` with standard `:8081-:8084` endpoint mapping.
  - public path-profile contract is `1hop|2hop|3hop` with compatibility aliases `speed|balanced|private` (plus explicit experimental `speed-1hop` alias on non-strict `client-test`/`client-vpn-up` only). Legacy aliases `fast|privacy` are still accepted for compatibility but are deprecated; simple help should surface the preset aliases first and push experimental aliases into expert help.
  - wg-only-local-test runs host real-WireGuard integration checks (Linux + root required).
  - real-wg-privileged-matrix runs the host Linux root real-WG privileged matrix directly.
  - real-wg-privileged-matrix-record wraps that matrix into one recorded manual-validation step and refreshes the shared readiness report automatically.
  - wg-only-stack-up/status/down manages a reusable host real-WireGuard demo stack (Linux + root required).
  - wg-only-stack-selftest runs stack-up + live-WG validation + stack-down as one command (Linux + root required) and auto-resets scoped client trust once when a local directory key mismatch is detected.
  - wg-only-stack-selftest-record wraps that Linux root selftest into one recorded manual-validation step and refreshes the shared readiness report automatically.
  - pre-real-host-readiness chains runtime-fix-record + wg-only-stack-selftest-record + manual-validation-report and answers whether machine-C VPN smoke is the next safe real-host step.
  - stop-all can also clean WG-only and client-vpn state/process/interfaces when requested (root needed for interface cleanup).
  - three-machine-validate runs health + federation checks then runs client-test with both directories.
  - client-vpn-preflight checks host prerequisites, endpoint reachability, and optional operator/issuer quorum diversity before starting client-vpn-up (operator floors are tunable with --operator-min-* flags).
  - client-vpn-up runs a real local VPN client (host WireGuard interface) for external testers; trust pinning defaults to scoped files per directory set (`EASY_NODE_CLIENT_VPN_TRUST_SCOPE=scoped`, legacy `global` mode available), and use client-vpn-down to stop/cleanup.
  - client-vpn-trust-reset removes pinned client directory trust files (scoped/global, state-aware fallback) to recover cleanly after expected directory key rotations in lab/staging environments.
  - server-session and client-vpn-session keep a live log terminal open and run cleanup automatically when that terminal exits.
  - client-vpn-smoke runs preflight + up + status + optional egress checks + down as one real-host smoke flow, can gate on pre-real-host-readiness and runtime-doctor/runtime-fix first, can optionally auto-reset pinned trust and retry once on directory-key mismatch (`--trust-reset-on-key-mismatch 1`), can defer as `skip` on root-required failures when explicitly enabled (`--defer-no-root 1`), records machine-C validation automatically, and refreshes the shared manual-validation report by default.
  - three-machine-prod-gate runs production-grade 3-machine sequencing (strict control validate + control soak + real WG validate + WG soak).
  - three-machine-prod-bundle runs strict machine-C preflight by default, then runs the same gate and always produces a shareable diagnostics tarball bundle; disable preflight only for diagnostics with --preflight-check=0, bundle integrity verification is enabled by default (disable only for diagnostics with --bundle-verify-check=0), emit a one-command run report JSON by default (override with --run-report-json), capture an automatic incident snapshot on failed runs by default (disable with --incident-snapshot-on-fail=0), optionally attach extra evidence files into that incident bundle with --incident-snapshot-attach-artifact, and enable fail-close artifact signoff inline with --signoff-check=1.
  - three-machine-prod-signoff wraps three-machine-prod-bundle into one recorded manual-validation step for the final machine-C production signoff rerun, can gate on pre-real-host-readiness and runtime-doctor/runtime-fix first, and refreshes the shared manual-validation report by default.
  - three-machine-reminder prints the true 3-machine production test checklist.
  - three-machine-docker-profile-matrix wraps the three-machine docker profile matrix helper script with pass-through args.
  - three-machine-docker-profile-matrix-record wraps the three-machine docker profile matrix record helper script with pass-through args.
  - three-machine-docker-readiness provisions two independent dockerized operator stacks on one host and runs machine-C style control-plane validate/soak checks (real multi-host WG signoff remains a separate final gate).
  - three-machine-docker-readiness-record wraps that docker rehearsal into one recorded manual-validation receipt and refreshes the shared readiness report automatically.
  - vpn-rc-matrix-path runs profile-compare-docker-matrix + profile-compare-campaign-signoff fail-closed + roadmap-progress-report in one chain and writes a machine-readable RC summary JSON.
  - vpn-rc-standard-path runs the locked VPN RC one-host execution path in one command (single-machine production readiness sweep with docker rehearsal defaults, then roadmap-progress-report refresh) and prints a final handoff summary.
  - vpn-rc-resilience-path wraps the VPN RC resilience helper path, forwards timeout controls (`--docker-profile-matrix-timeout-sec`, `--rc-matrix-path-timeout-sec`), and preserves pass-through args.
  - vpn-non-blockchain-fastlane wraps the non-blockchain acceleration helper path, forwards `--parallel [0|1]`, and preserves pass-through args.
  - blockchain-fastlane wraps the blockchain acceleration helper path and preserves pass-through args.
  - blockchain-gate-bundle wraps the blockchain gate bundle helper path and preserves pass-through args.
  - ci-blockchain-parallel-sweep wraps the blockchain parallel sweep helper path and preserves pass-through args.
  - blockchain-mainnet-activation-metrics-input wraps the blockchain metrics evidence normalizer helper path and preserves pass-through args.
  - blockchain-mainnet-activation-metrics-missing-checklist wraps the blockchain missing-metrics checklist helper path and preserves pass-through args.
  - blockchain-mainnet-activation-metrics-missing-input-template wraps the blockchain missing-input-template helper path and preserves pass-through args.
  - blockchain-mainnet-activation-metrics-input-template wraps the blockchain metrics evidence template helper path and preserves pass-through args.
  - blockchain-mainnet-activation-metrics wraps the blockchain mainnet activation metrics producer helper path and preserves pass-through args.
  - blockchain-mainnet-activation-gate wraps the blockchain mainnet activation gate helper path and preserves pass-through args.
  - blockchain-mainnet-activation-gate-cycle wraps the blockchain mainnet activation gate cycle helper path and preserves pass-through args.
  - blockchain-mainnet-activation-gate-cycle-seeded wraps the blockchain mainnet activation gate cycle helper path, auto-adds `--seed-example-input 1` for quick local runs, and preserves pass-through args.
  - blockchain-mainnet-activation-operator-pack wraps the blockchain mainnet activation operator pack helper path and preserves pass-through args.
  - blockchain-bootstrap-governance-graduation-gate wraps the blockchain bootstrap governance graduation gate helper path and preserves pass-through args.
  - roadmap-non-blockchain-actionable-run resolves and runs the current roadmap no-sudo/no-GitHub actionable gate list in one command (supports `--recommended-only 1`, `--max-actions N`, per-action timeout via `--action-timeout-sec N`, policy override via `--allow-policy-no-go [0|1]`, and `--parallel [0|1]`).
  - roadmap-blockchain-actionable-run resolves and runs the current roadmap blockchain actionable gate list in one command (supports `--recommended-only 1`, `--max-actions N`, per-action timeout via `--action-timeout-sec N`, and `--parallel [0|1]`).
  - roadmap-next-actions-run wraps roadmap `next_actions` in one command with optional ID-prefix filtering, per-action timeout, parallel execution controls, optional soft-fail for unreachable profile-default endpoints, and explicit profile-default subject override via `--profile-default-gate-subject ID`.
  - ci-phase0 runs the fast Phase-0 simplification gate (launcher wiring/runtime + config-v1 + local API contract checks) with fail-fast behavior.
  - ci-phase1-resilience runs the Phase-1 resilience gate (route profile + peer churn + lifecycle stability checks), forwards per-stage timeout controls (`--*-timeout-sec`), and keeps fail-fast behavior.
  - phase1-resilience-handoff-check wraps the Phase-1 resilience handoff check helper script with pass-through args.
  - phase1-resilience-handoff-run wraps the Phase-1 resilience handoff run helper script with pass-through args, including fast refresh mode via `--refresh-from-ci-summary 1` to reuse an existing ci summary artifact and rerun only handoff-check.
  - ci-phase2-linux-prod-candidate runs the Phase-2 Linux production-candidate gate with fail-fast behavior.
  - phase2-linux-prod-candidate-check wraps the Phase-2 Linux production-candidate fail-closed check helper script with pass-through args.
  - phase2-linux-prod-candidate-run wraps the Phase-2 Linux production-candidate run helper script with pass-through args.
  - phase2-linux-prod-candidate-signoff wraps the Phase-2 Linux production-candidate signoff helper script with pass-through args.
  - phase2-linux-prod-candidate-handoff-check wraps the Phase-2 Linux production-candidate handoff check helper script with pass-through args.
  - phase2-linux-prod-candidate-handoff-run wraps the Phase-2 Linux production-candidate handoff run helper script with pass-through args.
  - ci-phase3-windows-client-beta runs the Phase-3 Windows client-beta gate with fail-fast behavior.
  - phase3-windows-client-beta-check wraps the Phase-3 Windows client-beta fail-closed check helper script with pass-through args.
  - phase3-windows-client-beta-run wraps the Phase-3 Windows client-beta run helper script with pass-through args.
  - phase3-windows-client-beta-handoff-check wraps the Phase-3 Windows client-beta handoff check helper script with pass-through args.
  - phase3-windows-client-beta-handoff-run wraps the Phase-3 Windows client-beta handoff run helper script with pass-through args.
  - ci-phase4-windows-full-parity runs the Phase-4 Windows full-parity gate with fail-fast behavior.
  - phase4-windows-full-parity-check wraps the Phase-4 Windows full-parity fail-closed check helper script with pass-through args.
  - phase4-windows-full-parity-run wraps the Phase-4 Windows full-parity run helper script with pass-through args.
  - phase4-windows-full-parity-handoff-check wraps the Phase-4 Windows full-parity handoff check helper script with pass-through args.
  - phase4-windows-full-parity-handoff-run wraps the Phase-4 Windows full-parity handoff run helper script with pass-through args.
  - ci-phase5-settlement-layer runs the Phase-5 settlement-layer gate with fail-fast behavior.
  - phase5-settlement-layer-check wraps the Phase-5 settlement-layer fail-closed check helper script with pass-through args.
  - phase5-settlement-layer-run wraps the Phase-5 settlement-layer run helper script with pass-through args.
  - phase5-settlement-layer-handoff-check wraps the Phase-5 settlement-layer handoff check helper script with pass-through args.
  - phase5-settlement-layer-handoff-run wraps the Phase-5 settlement-layer handoff run helper script with pass-through args.
  - phase5-settlement-layer-summary-report wraps the Phase-5 settlement summary-report helper script with pass-through args.
  - issuer-sponsor-api-live-smoke wraps the phase5 issuer sponsor API live-smoke helper script with pass-through args.
  - issuer-settlement-status-live-smoke wraps the phase5 issuer settlement-status live-smoke helper script with pass-through args.
  - ci-phase6-cosmos-l1-build-testnet runs the Phase-6 Cosmos L1 build-testnet gate with fail-fast behavior.
  - ci-phase6-cosmos-l1-contracts runs the Phase-6 Cosmos L1 contracts gate with fail-fast behavior.
  - phase6-cosmos-l1-build-testnet-check wraps the Phase-6 Cosmos L1 build-testnet fail-closed check helper script with pass-through args.
  - phase6-cosmos-l1-build-testnet-run wraps the Phase-6 Cosmos L1 build-testnet run helper script with pass-through args.
  - phase6-cosmos-l1-build-testnet-handoff-check wraps the Phase-6 Cosmos L1 build-testnet handoff check helper script with pass-through args.
  - phase6-cosmos-l1-build-testnet-handoff-run wraps the Phase-6 Cosmos L1 build-testnet handoff run helper script with pass-through args.
  - phase6-cosmos-l1-build-testnet-suite wraps the Phase-6 Cosmos L1 build-testnet suite helper script with pass-through args.
  - phase6-cosmos-l1-summary-report wraps the Phase-6 Cosmos L1 summary-report helper script with pass-through args.
  - ci-phase7-mainnet-cutover runs the Phase-7 mainnet cutover gate with fail-fast behavior.
  - phase7-mainnet-cutover-check wraps the Phase-7 mainnet cutover fail-closed check helper script with pass-through args.
  - phase7-mainnet-cutover-run wraps the Phase-7 mainnet cutover run helper script with pass-through args.
  - phase7-mainnet-cutover-handoff-check wraps the Phase-7 mainnet cutover handoff check helper script with pass-through args.
  - phase7-mainnet-cutover-handoff-run wraps the Phase-7 mainnet cutover handoff run helper script with pass-through args.
  - phase7-mainnet-cutover-summary-report wraps the Phase-7 mainnet cutover summary-report helper script with pass-through args.
  - manual-validation-backlog prints the deferred real-host validation list so we can resume manual testing cleanly later.
  - local-api-session launches `go run ./cmd/node --local-api`, wires config-v1 simple client defaults into local control API connect defaults, supports optional service lifecycle command overrides, and supports deterministic dry-run output.
  - single-machine-prod-readiness runs all production-grade checks feasible on one host (ci_local, beta_preflight, deep_test_suite, runtime-fix-record, optional dockerized 3-machine rehearsal, optional profile-compare campaign signoff, optional pre-real-host-readiness, optional Linux root real-WG matrix receipt refresh), then reports exactly which remaining blockers require machine-C/3-machine execution; in auto mode it bootstraps missing profile-compare campaign artifacts, preferring docker rehearsal endpoints when available.
  - manual-validation-status combines live runtime-doctor output with recorded manual real-host validation receipts, points at the latest failed incident handoff when a recorded smoke/signoff run captured one, and now exposes staged roadmap progress (`BLOCKED_LOCAL`, `READY_FOR_MACHINE_C_SMOKE`, `READY_FOR_3_MACHINE_PROD_SIGNOFF`, `PRODUCTION_SIGNOFF_COMPLETE`).
  - manual-validation-report turns that readiness state into one shareable markdown + JSON handoff artifact, includes the same staged roadmap signal for single-machine operators, and can fail-close with --fail-on-not-ready=1.
  - roadmap-progress-report generates one concise execution report (JSON + markdown) from manual-validation readiness, optionally refreshing single-machine readiness first, and always includes VPN gate status plus the deferred blockchain-track policy note.
  - manual-validation-record stores the result of a manual real-host validation step in local status/receipt files.
  - runtime-doctor checks for stale state, busy default ports, lingering interfaces, and unwritable runtime files before the next real-host test.
  - runtime-fix applies safe cleanup actions from runtime-doctor findings (stale wg-only/client-vpn/demo leftovers), reruns runtime-doctor, and now refreshes the shared manual-validation readiness report by default.
  - runtime-fix-record wraps runtime-fix into one recorded runtime-hygiene step with a durable summary/log artifact plus receipt metadata.
  - prod-gate-check verifies gate/bundle JSON artifacts against signoff policy and fails fast when criteria are not met (recommended input: --run-report-json from three-machine-prod-bundle).
  - prod-gate-slo-summary prints an operator SLO decision summary (GO/NO-GO) from prod-gate artifacts and can optionally fail-close with --fail-on-no-go=1.
  - prod-gate-slo-trend computes GO/NO-GO trend across multiple run reports with optional fail-close thresholds (any NO-GO or minimum GO-rate percent), optional time window filtering, and machine-readable summary JSON output.
  - prod-gate-slo-alert converts SLO trend metrics into operator alert severity (OK/WARN/CRITICAL) with configurable thresholds and optional fail-close exits.
  - prod-gate-slo-dashboard runs trend + alert and writes a single markdown operator dashboard plus trend/alert JSON artifacts.
  - prod-gate-bundle-verify verifies bundle integrity artifacts (manifest + tarball checksum sidecar), recommended input: --run-report-json.
  - prod-gate-signoff runs prod-gate-bundle-verify + prod-gate-check fail-closed in one command.
  - prod-pilot-cohort-bundle-verify verifies sustained-pilot cohort bundle artifacts (tar checksum + manifest + round structure), recommended input: --summary-json.
  - prod-pilot-cohort-check evaluates sustained-pilot cohort summary artifacts against fail-close signoff policy.
  - prod-pilot-cohort-signoff runs prod-pilot-cohort-bundle-verify + prod-pilot-cohort-check fail-closed in one command.
  - prod-pilot-cohort-quick-check verifies quick run-report artifacts, enforces fail-close quick signoff policy, and now prints the upstream pre-real-host readiness summary path when the quick run report carries it.
  - prod-pilot-cohort-quick-trend computes GO/NO-GO trend across quick run reports with fail-close thresholds and JSON output.
  - prod-pilot-cohort-quick-alert converts quick trend metrics into OK/WARN/CRITICAL severity with configurable fail-close exits.
  - prod-pilot-cohort-quick-dashboard writes one quick-mode operator dashboard (trend JSON + alert JSON + markdown).
  - prod-pilot-cohort-quick-signoff runs quick-check + quick-trend + quick-alert in one fail-closed command with max-alert-severity policy, and now preserves the upstream pre-real-host readiness summary path in both signoff JSON and operator output when present.
  - prod-pilot-cohort-quick-runbook runs quick execution + quick-signoff + optional dashboard in one operator command, exposes the one-time top-level pre-real-host gate used by the underlying cohort runbook, and writes a runbook summary artifact.
  - prod-wg-validate/prod-wg-soak run real WireGuard dataplane validation from machine C (Linux root) in production strict profile.
  - prod-wg-strict-ingress-rehearsal runs a controlled negative rehearsal that should fail with failure class strict_ingress_policy.
  - pilot-runbook wraps machine-C validation + soak + bundle capture and now treats the public no-override path as balanced by default while keeping expert path-policy overrides available.
  - prod-pilot-runbook wraps three-machine-prod-bundle with strict fail-closed production defaults for machine-C pilot runs, gates on pre-real-host-readiness by default, and auto-generates SLO dashboard artifacts by default; append your own args to override.
  - prod-pilot-cohort-runbook runs sustained pilot rounds (multiple prod-pilot-runbook executions), runs pre-real-host-readiness once before the cohort by default, and aggregates trend/alert summaries for cohort signoff, including fail-close alert-severity policy and optional tar+sha256+manifest cohort bundle output.
  - prod-pilot-cohort-campaign wraps prod-pilot-cohort-quick-runbook with low-prompt sustained campaign defaults, deterministic artifact paths, the same top-level pre-real-host gate control, generated markdown/JSON handoff summaries, a machine-readable campaign run-report artifact, fail-close incident snapshot policy controls for failed campaigns, and optional inline campaign-signoff gating with its own summary artifact.
  - prod-pilot-cohort-campaign-summary regenerates one concise operator handoff report from saved campaign/runbook artifacts, preserves normalized source pointers (including upstream pre-real-host readiness summary when present), and can enforce fail-close incident snapshot attachment policy on failed runs.
  - prod-pilot-cohort-campaign-check fail-closed validates campaign run-report + summary artifacts, upstream runbook/quick artifact completeness metadata, campaign-signoff stage config/RC requirements, campaign-signoff summary status/final_rc integrity, campaign fail-close config floors, cross-artifact path consistency, and optional distinct artifact-path collision checks before operator signoff; it can emit a machine-readable summary with --summary-json.
  - prod-pilot-cohort-campaign-signoff runs optional campaign-summary refresh + campaign-check fail-closed in one operator command, including upstream runbook/quick artifact policy checks, campaign fail-close config floor checks, cross-artifact path consistency checks, and fail-fast output-path collision guards (override only for diagnostics with --allow-summary-overwrite 1); it can emit a machine-readable summary with --summary-json.
  - prod-pilot-cohort-quick runs one-command sustained pilot + fail-closed cohort signoff with minimal operator flags, exposes the one-time top-level pre-real-host gate used by the underlying cohort runbook, and emits a quick run report JSON artifact.
  - prod-key-rotation-runbook performs production key/secret rotation with backup, preflight checks, and rollback support.
  - prod-upgrade-runbook performs production compose upgrade flow (pull/build/restart) with backup, preflight checks, and rollback support.
  - prod-operator-lifecycle-runbook performs repeatable operator onboarding/offboarding with optional preflight, health checks, federation readiness gating, relay visibility checks, optional authority invite bootstrap, optional onboard rollback-on-failure, optional failed-run runtime-doctor diagnostics, and optional failed-run incident snapshot capture.
  - incident-snapshot captures a shareable incident bundle (endpoint probes + docker/system snapshots), can attach extra evidence files with --attach-artifact, and auto-generates summary JSON + markdown report artifacts for operator debugging.
  - incident-snapshot-summary rebuilds the concise operator summary from an existing incident bundle directory.
  - bootstrap discovery mode lets you provide one directory URL and auto-discover other server hosts.
  - machine-a-test/machine-b-test/machine-c-test are machine-role-specific automated validations with optional report files.
  - default logs are written to ./.easy-node-logs (override with EASY_NODE_LOG_DIR).
  - For a 3-machine test: run server-up on machine A and B, then run client-test on machine C with both directory URLs.
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing dependency: $1"
    dependency_install_hint "$1"
    return 1
  fi
}

dependency_install_hint() {
  local cmd="${1:-}"
  case "$cmd" in
    wg)
      echo "hint: install wireguard-tools (sudo apt-get update && sudo apt-get install -y wireguard-tools)"
      ;;
    rg)
      echo "hint: install ripgrep (sudo apt-get update && sudo apt-get install -y ripgrep)"
      ;;
    jq)
      echo "hint: install jq (sudo apt-get update && sudo apt-get install -y jq)"
      ;;
    go)
      echo "hint: install golang-go (sudo apt-get update && sudo apt-get install -y golang-go)"
      ;;
    docker)
      echo "hint: install docker engine + compose plugin, or run: ./scripts/easy_node.sh install-deps-ubuntu"
      ;;
    timeout)
      echo "hint: install coreutils (sudo apt-get update && sudo apt-get install -y coreutils)"
      ;;
    curl)
      echo "hint: install curl (sudo apt-get update && sudo apt-get install -y curl)"
      ;;
    openssl)
      echo "hint: install openssl (sudo apt-get update && sudo apt-get install -y openssl)"
      ;;
  esac
}

secure_file_permissions() {
  local file="$1"
  if [[ -f "$file" ]]; then
    chmod 600 "$file" 2>/dev/null || true
  fi
}

resolve_entry_exit_user_non_prod() {
  local data_dir="$DEPLOY_DIR/data/entry-exit"
  local uid gid

  # When launched with sudo, prefer the original caller's uid/gid so bind-mount
  # writes land on the host with expected ownership.
  if [[ "${EUID:-$(id -u)}" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    uid="$SUDO_UID"
    gid="$SUDO_GID"
  else
    uid="$(id -u)"
    gid="$(id -g)"
  fi

  mkdir -p "$data_dir" >/dev/null 2>&1 || true
  if [[ ! -w "$data_dir" ]]; then
    # Fallback for stale root-owned bind-mount directories from older runs.
    echo "0:0"
    return
  fi

  echo "${uid}:${gid}"
}

check_dependencies() {
  local ok=1
  need_cmd docker || ok=0
  need_cmd curl || ok=0
  need_cmd timeout || ok=0
  need_cmd rg || ok=0
  need_cmd jq || ok=0
  need_cmd go || ok=0
  need_cmd openssl || ok=0

  if ! docker compose version >/dev/null 2>&1; then
    echo "missing dependency: docker compose plugin"
    ok=0
  fi

  if [[ $ok -eq 1 ]]; then
    echo "dependency check: ok"
    docker --version
    docker compose version
    if ! docker info >/dev/null 2>&1; then
      echo "note: docker daemon is not reachable for this user yet"
      echo "      fix by adding your user to docker group or use sudo"
    fi
    return 0
  fi
  return 1
}

EASY_NODE_SELF_UPDATE_APPLIED=0

normalize_config_bool_01() {
  local value="${1:-}"
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$value" in
    1|true|yes|on|y)
      printf '%s\n' "1"
      ;;
    0|false|no|off|n)
      printf '%s\n' "0"
      ;;
    *)
      return 1
      ;;
  esac
}

apply_config_v1_auto_update_defaults() {
  local cfg_path="${EASY_MODE_CONFIG_V1_FILE:-$EASY_MODE_CONFIG_V1_FILE_DEFAULT}"
  local cfg_version=""
  local raw_value=""
  local normalized_bool=""

  if [[ -z "$cfg_path" ]]; then
    return 0
  fi
  if [[ "$cfg_path" != /* ]]; then
    cfg_path="$ROOT_DIR/$cfg_path"
  fi
  if [[ ! -f "$cfg_path" ]]; then
    return 0
  fi

  cfg_version="$(identity_value "$cfg_path" "EASY_MODE_CONFIG_VERSION")"
  if [[ "$cfg_version" != "1" ]]; then
    return 0
  fi

  if [[ -z "${EASY_NODE_AUTO_UPDATE+x}" ]]; then
    raw_value="$(identity_value "$cfg_path" "SIMPLE_AUTO_UPDATE")"
    normalized_bool="$(normalize_config_bool_01 "$raw_value" 2>/dev/null || true)"
    if [[ -n "$normalized_bool" ]]; then
      export EASY_NODE_AUTO_UPDATE="$normalized_bool"
    fi
  fi

  if [[ -z "${EASY_NODE_AUTO_UPDATE_ALLOW_DIRTY+x}" ]]; then
    raw_value="$(identity_value "$cfg_path" "SIMPLE_AUTO_UPDATE_ALLOW_DIRTY")"
    normalized_bool="$(normalize_config_bool_01 "$raw_value" 2>/dev/null || true)"
    if [[ -n "$normalized_bool" ]]; then
      export EASY_NODE_AUTO_UPDATE_ALLOW_DIRTY="$normalized_bool"
    fi
  fi

  if [[ -z "${EASY_NODE_AUTO_UPDATE_SHOW_STATUS+x}" ]]; then
    raw_value="$(identity_value "$cfg_path" "SIMPLE_AUTO_UPDATE_SHOW_STATUS")"
    normalized_bool="$(normalize_config_bool_01 "$raw_value" 2>/dev/null || true)"
    if [[ -n "$normalized_bool" ]]; then
      export EASY_NODE_AUTO_UPDATE_SHOW_STATUS="$normalized_bool"
    fi
  fi

  if [[ -z "${EASY_NODE_AUTO_UPDATE_REMOTE+x}" ]]; then
    raw_value="$(identity_value "$cfg_path" "SIMPLE_AUTO_UPDATE_REMOTE")"
    if [[ -n "$raw_value" ]]; then
      export EASY_NODE_AUTO_UPDATE_REMOTE="$raw_value"
    fi
  fi

  if [[ -z "${EASY_NODE_AUTO_UPDATE_BRANCH+x}" ]]; then
    raw_value="$(identity_value "$cfg_path" "SIMPLE_AUTO_UPDATE_BRANCH")"
    if [[ -n "$raw_value" ]]; then
      export EASY_NODE_AUTO_UPDATE_BRANCH="$raw_value"
    fi
  fi

  if [[ -z "${EASY_NODE_AUTO_UPDATE_COMMANDS+x}" ]]; then
    raw_value="$(identity_value "$cfg_path" "SIMPLE_AUTO_UPDATE_COMMANDS")"
    if [[ -n "$raw_value" ]]; then
      export EASY_NODE_AUTO_UPDATE_COMMANDS="$raw_value"
    fi
  fi
}

self_update_repo() {
  local remote="${EASY_NODE_AUTO_UPDATE_REMOTE:-origin}"
  local branch="${EASY_NODE_AUTO_UPDATE_BRANCH:-}"
  local allow_dirty="${EASY_NODE_AUTO_UPDATE_ALLOW_DIRTY:-0}"
  local show_status="${EASY_NODE_AUTO_UPDATE_SHOW_STATUS:-1}"
  local local_sha remote_sha base_sha new_sha

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --remote)
        remote="${2:-}"
        shift 2
        ;;
      --branch)
        branch="${2:-}"
        shift 2
        ;;
      --allow-dirty)
        allow_dirty="${2:-}"
        shift 2
        ;;
      --show-status)
        show_status="${2:-}"
        shift 2
        ;;
      *)
        echo "unknown arg for self-update: $1"
        return 2
        ;;
    esac
  done

  if [[ -z "$remote" ]]; then
    echo "self-update requires --remote (or EASY_NODE_AUTO_UPDATE_REMOTE)"
    return 1
  fi
  if [[ "$allow_dirty" != "0" && "$allow_dirty" != "1" ]]; then
    echo "self-update requires --allow-dirty (or EASY_NODE_AUTO_UPDATE_ALLOW_DIRTY) to be 0 or 1"
    return 1
  fi
  if [[ "$show_status" != "0" && "$show_status" != "1" ]]; then
    echo "self-update requires --show-status (or EASY_NODE_AUTO_UPDATE_SHOW_STATUS) to be 0 or 1"
    return 1
  fi

  EASY_NODE_SELF_UPDATE_APPLIED=0

  if ! command -v git >/dev/null 2>&1; then
    echo "self-update skipped: git is not installed"
    return 0
  fi
  if ! git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "self-update skipped: $ROOT_DIR is not a git working tree"
    return 0
  fi
  if ! git -C "$ROOT_DIR" remote get-url "$remote" >/dev/null 2>&1; then
    echo "self-update skipped: git remote '$remote' is not configured"
    return 0
  fi

  if [[ -z "$branch" ]]; then
    branch="$(git -C "$ROOT_DIR" symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
  fi
  if [[ -z "$branch" ]]; then
    echo "self-update skipped: detached HEAD (set --branch or EASY_NODE_AUTO_UPDATE_BRANCH)"
    return 0
  fi

  if [[ "$allow_dirty" != "1" ]]; then
    if [[ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=no 2>/dev/null || true)" ]]; then
      echo "self-update skipped: working tree has local tracked changes"
      return 0
    fi
  fi

  if ! git -C "$ROOT_DIR" fetch --quiet "$remote" "$branch"; then
    echo "self-update failed: fetch error for ${remote}/${branch}"
    return 1
  fi

  local_sha="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || true)"
  remote_sha="$(git -C "$ROOT_DIR" rev-parse "${remote}/${branch}" 2>/dev/null || true)"
  if [[ -z "$local_sha" || -z "$remote_sha" ]]; then
    echo "self-update failed: unable to resolve local/remote revision"
    return 1
  fi

  if [[ "$local_sha" == "$remote_sha" ]]; then
    if [[ "$show_status" == "1" ]]; then
      echo "self-update: already up to date (${remote}/${branch})"
    fi
    return 0
  fi

  base_sha="$(git -C "$ROOT_DIR" merge-base "$local_sha" "$remote_sha" 2>/dev/null || true)"
  if [[ -z "$base_sha" ]]; then
    echo "self-update failed: unable to compute merge-base"
    return 1
  fi
  if [[ "$base_sha" != "$local_sha" ]]; then
    echo "self-update skipped: local branch has non-fast-forward changes (manual merge/rebase required)"
    return 0
  fi

  if ! git -C "$ROOT_DIR" merge --ff-only "${remote}/${branch}" >/dev/null 2>&1; then
    echo "self-update failed: fast-forward merge failed for ${remote}/${branch}"
    return 1
  fi

  new_sha="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || true)"
  EASY_NODE_SELF_UPDATE_APPLIED=1
  if [[ "$show_status" == "1" ]]; then
    echo "self-update: updated ${local_sha:0:12} -> ${new_sha:0:12} (${remote}/${branch})"
  fi
  return 0
}

auto_update_command_enabled() {
  local cmd
  cmd="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  local commands_csv="${EASY_NODE_AUTO_UPDATE_COMMANDS:-server-up,server-session,client-test,client-vpn-up,client-vpn-session,simple-server-preflight,simple-server-session,simple-client-test,simple-client-vpn-preflight,simple-client-vpn-session}"
  local normalized_csv
  normalized_csv="$(printf '%s' "$commands_csv" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case ",${normalized_csv}," in
    *,"$cmd",*)
      return 0
      ;;
  esac
  return 1
}

maybe_auto_update_and_reexec() {
  local cmd="${1:-}"
  if [[ $# -gt 0 ]]; then
    shift
  fi

  if [[ "${EASY_NODE_AUTO_UPDATE:-0}" != "1" ]]; then
    return 0
  fi
  if [[ "$cmd" == "self-update" || "$cmd" == "-h" || "$cmd" == "--help" || "$cmd" == "help" || -z "$cmd" ]]; then
    return 0
  fi
  if ! auto_update_command_enabled "$cmd"; then
    return 0
  fi
  if [[ "${EASY_NODE_AUTO_UPDATE_REEXECED:-0}" == "1" ]]; then
    return 0
  fi

  if ! self_update_repo; then
    echo "auto-update warning: continuing with current local code"
    return 0
  fi

  if [[ "${EASY_NODE_SELF_UPDATE_APPLIED:-0}" == "1" ]]; then
    echo "auto-update: reloading command with updated code"
    export EASY_NODE_AUTO_UPDATE_REEXECED=1
    exec "$0" "$cmd" "$@"
  fi
}

wait_http_ok() {
  local url="$1"
  local name="$2"
  local attempts="${3:-30}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS --connect-timeout 2 --max-time 4 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "$name did not become healthy at $url"
  return 1
}

wait_http_ok_with_opts() {
  local url="$1"
  local name="$2"
  local attempts="${3:-30}"
  shift 3
  local i
  local -a opts=("$@")
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS --connect-timeout 2 --max-time 6 "${opts[@]}" "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "$name did not become healthy at $url"
  return 1
}

host_is_loopback() {
  local host="$1"
  [[ "$host" == "127.0.0.1" || "$host" == "localhost" || "$host" == "::1" ]]
}

host_is_private_or_loopback() {
  local host="$1"
  local h
  h="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
  h="${h#[}"
  h="${h%]}"
  if host_is_loopback "$h"; then
    return 0
  fi
  if [[ "$h" == 10.* ]]; then
    return 0
  fi
  if [[ "$h" == 192.168.* ]]; then
    return 0
  fi
  if [[ "$h" =~ ^172\.([1][6-9]|2[0-9]|3[0-1])\. ]]; then
    return 0
  fi
  if [[ "$h" == 169.254.* ]]; then
    return 0
  fi
  if [[ "$h" == fc* || "$h" == fd* || "$h" == fe80:* ]]; then
    return 0
  fi
  return 1
}

hosts_config_file() {
  echo "$ROOT_DIR/data/easy_mode_hosts.conf"
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

trim_url() {
  local value="$1"
  while [[ "$value" == */ ]]; do
    value="${value%/}"
  done
  echo "$value"
}

normalize_path_profile() {
  local profile
  profile="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$profile" in
    speed|fast)
      printf '%s\n' "fast"
      ;;
    speed-1hop|speed1hop|fast-1hop|fast1hop|onehop|1hop|1-hop|hop1|hop-1)
      printf '%s\n' "speed-1hop"
      ;;
    balanced|2hop|2-hop|hop2|hop-2|twohop)
      printf '%s\n' "balanced"
      ;;
    private|privacy|3hop|3-hop|hop3|hop-3|threehop)
      printf '%s\n' "privacy"
      ;;
    "")
      printf '%s\n' ""
      ;;
    *)
      return 1
      ;;
  esac
}

path_profile_values() {
  local profile
  profile="$(normalize_path_profile "${1:-}")" || return 1
  case "$profile" in
    fast)
      # distinct_operators|distinct_countries|locality_soft_bias|country_bias|region_bias|region_prefix_bias
      printf '%s\n' "1|0|1|1.80|1.35|1.15"
      ;;
    speed-1hop)
      # speed-1hop uses speed locality defaults; client-test applies one-hop-only
      # safety overrides (non-strict mode, direct-exit path) separately.
      printf '%s\n' "1|0|1|1.80|1.35|1.15"
      ;;
    privacy)
      printf '%s\n' "1|1|0|1.60|1.25|1.10"
      ;;
    balanced|"")
      printf '%s\n' "1|0|1|1.50|1.25|1.10"
      ;;
    *)
      return 1
      ;;
  esac
}

hostport_from_url() {
  local value="$1"
  value="${value#http://}"
  value="${value#https://}"
  value="${value%%/*}"
  echo "$value"
}

host_from_hostport() {
  local value="$1"
  if [[ "$value" == \[*\]* ]]; then
    # Bracketed IPv6 literal, with optional :port.
    echo "${value%%]*}]"
    return
  fi
  local colon_count
  colon_count="$(printf '%s' "$value" | awk -F: '{print NF-1}')"
  if [[ "$colon_count" == "1" ]]; then
    local maybe_port="${value##*:}"
    if [[ "$maybe_port" =~ ^[0-9]+$ ]]; then
      echo "${value%:*}"
      return
    fi
  fi
  echo "$value"
}

host_from_url() {
  local value="$1"
  host_from_hostport "$(hostport_from_url "$value")"
}

normalize_host_for_endpoint() {
  local host="$1"
  host="$(trim_url "$host")"
  if [[ "$host" == \[*\] ]]; then
    echo "$host"
    return
  fi
  if [[ "$host" == *:* ]]; then
    echo "[$host]"
    return
  fi
  echo "$host"
}

url_from_host_port() {
  local host="$1"
  local port="$2"
  printf 'http://%s:%s' "$(normalize_host_for_endpoint "$host")" "$port"
}

ensure_url_scheme() {
  local raw="$1"
  local scheme="$2"
  raw="$(trim_url "$raw")"
  scheme="$(trim "$scheme")"
  if [[ -z "$raw" || -z "$scheme" ]]; then
    echo "$raw"
    return
  fi
  if [[ "$raw" == "$scheme://"* ]]; then
    echo "$raw"
    return
  fi
  if [[ "$raw" == http://* || "$raw" == https://* ]]; then
    echo "${scheme}://${raw#*://}"
    return
  fi
  echo "${scheme}://${raw}"
}

is_https_url() {
  local raw
  raw="$(trim "$1")"
  [[ "$raw" == https://* ]]
}

bootstrap_mtls() {
  local script="$ROOT_DIR/scripts/bootstrap_mtls.sh"
  if [[ ! -x "$script" ]]; then
    echo "missing helper script: $script"
    exit 2
  fi
  "$script" "$@"
}

ensure_admin_signing_material() {
  local rotate="${1:-0}"
  local history_raw="${2:-${EASY_NODE_ADMIN_SIGNING_KEY_HISTORY:-3}}"
  local issuer_data_dir="$DEPLOY_DIR/data/issuer"
  local key_file="$issuer_data_dir/issuer_admin_signer.key"
  local key_id_file="$issuer_data_dir/issuer_admin_signer.keyid"
  local signers_file="$issuer_data_dir/issuer_admin_signers.txt"
  local signers_file_container="/app/data/issuer_admin_signers.txt"
  local inspect_json key_id pub_key
  local key_history=3

  if [[ "$history_raw" =~ ^[0-9]+$ ]] && ((history_raw > 0)); then
    key_history="$history_raw"
  fi

  mkdir -p "$issuer_data_dir"
  if [[ "$rotate" == "1" ]]; then
    rm -f "$key_file" "$key_id_file"
  fi
  if [[ ! -f "$key_file" ]]; then
    (
      cd "$ROOT_DIR"
      go run ./cmd/adminsig gen --private-key-out "$key_file" --key-id-out "$key_id_file" >/dev/null
    )
  fi

  inspect_json="$(
    cd "$ROOT_DIR"
    go run ./cmd/adminsig inspect --private-key-file "$key_file"
  )"
  key_id="$(printf '%s\n' "$inspect_json" | jq -r '.key_id')"
  pub_key="$(printf '%s\n' "$inspect_json" | jq -r '.public_key')"
  if [[ -z "$key_id" || -z "$pub_key" || "$key_id" == "null" || "$pub_key" == "null" ]]; then
    echo "failed to inspect issuer admin signing key material"
    exit 1
  fi

  local signers_tmp
  signers_tmp="$(mktemp)"
  {
    printf '%s=%s\n' "$key_id" "$pub_key"
    if [[ -f "$signers_file" ]]; then
      cat "$signers_file"
    fi
  } | awk '
      NF == 0 { next }
      /^#/ { next }
      {
        split($0, p, "=")
        k = p[1]
        if (k == "") next
        if (!(k in seen)) {
          seen[k] = 1
          print $0
        }
      }
    ' | head -n "$key_history" >"$signers_tmp"
  mv "$signers_tmp" "$signers_file"

  printf '%s\n' "$key_id" >"$key_id_file"
  secure_file_permissions "$key_file"
  chmod 644 "$signers_file" "$key_id_file" 2>/dev/null || true

  echo "$key_file|$key_id|$signers_file|$signers_file_container"
}

resolve_invite_admin_auth() {
  local cli_token="${1:-}"
  local cli_key_file="${2:-}"
  local cli_key_id="${3:-}"
  local env_token env_key_file env_key_id

  if [[ -n "$cli_token" ]]; then
    echo "token|$cli_token||"
    return
  fi
  if [[ -n "$cli_key_file" && -n "$cli_key_id" ]]; then
    echo "signed||$cli_key_file|$cli_key_id"
    return
  fi

  env_key_file="$(server_env_value "ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL" | tr -d '\r')"
  env_key_id="$(server_env_value "ISSUER_ADMIN_SIGNING_KEY_ID" | tr -d '\r')"
  if [[ -n "$env_key_file" && -n "$env_key_id" ]]; then
    echo "signed||$env_key_file|$env_key_id"
    return
  fi

  env_token="$(resolve_invite_admin_token "")"
  if [[ -n "$env_token" ]]; then
    echo "token|$env_token||"
    return
  fi

  echo "none|||"
}

enforce_invite_auth_mode_or_die() {
  local action="$1"
  local auth_mode="$2"
  local require_signed allow_token
  require_signed="$(server_env_value "ISSUER_ADMIN_REQUIRE_SIGNED" | tr -d '\r')"
  allow_token="$(server_env_value "ISSUER_ADMIN_ALLOW_TOKEN" | tr -d '\r')"

  if [[ "$auth_mode" == "none" ]]; then
    if [[ "$require_signed" == "1" || "$allow_token" == "0" ]]; then
      echo "${action} requires signed admin auth (--admin-key-file + --admin-key-id)"
      echo "token admin auth is disabled for this authority (ISSUER_ADMIN_ALLOW_TOKEN=0)"
    else
      echo "${action} requires admin auth (--admin-token or --admin-key-file + --admin-key-id)"
    fi
    exit 2
  fi

  if [[ "$auth_mode" == "token" && "$allow_token" == "0" ]]; then
    echo "${action} refused: token admin auth is disabled for this authority (ISSUER_ADMIN_ALLOW_TOKEN=0)"
    echo "use signed admin auth: --admin-key-file + --admin-key-id"
    exit 2
  fi
  if [[ "$auth_mode" != "signed" && "$require_signed" == "1" ]]; then
    echo "${action} refused: signed admin auth is required (ISSUER_ADMIN_REQUIRE_SIGNED=1)"
    echo "use signed admin auth: --admin-key-file + --admin-key-id"
    exit 2
  fi
}

resolve_local_mtls_material() {
  local ca cert key
  local fallback_ca fallback_cert fallback_key
  fallback_ca="$DEPLOY_DIR/tls/ca.crt"
  fallback_cert="$DEPLOY_DIR/tls/client.crt"
  fallback_key="$DEPLOY_DIR/tls/client.key"
  ca="$(server_env_value "EASY_NODE_MTLS_CA_FILE_LOCAL" | tr -d '\r')"
  cert="$(server_env_value "EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL" | tr -d '\r')"
  key="$(server_env_value "EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL" | tr -d '\r')"
  if [[ -z "$ca" || ! -r "$ca" ]]; then
    ca="$fallback_ca"
  fi
  if [[ -z "$cert" || ! -r "$cert" ]]; then
    cert="$fallback_cert"
  fi
  if [[ -z "$key" || ! -r "$key" ]]; then
    key="$fallback_key"
  fi
  echo "$ca|$cert|$key"
}

curl_tls_opts_for_url() {
  local url="$1"
  if ! is_https_url "$url"; then
    return
  fi
  local triple ca cert key
  triple="$(resolve_local_mtls_material)"
  IFS='|' read -r ca cert key <<<"$triple"
  if [[ -f "$ca" ]]; then
    printf '%s\n' "--cacert" "$ca"
  fi
  if [[ -f "$cert" && -f "$key" ]]; then
    printf '%s\n' "--cert" "$cert" "--key" "$key"
  fi
}

build_admin_header_args() {
  local method="$1"
  local url="$2"
  local body_file="$3"
  local auth_mode="$4"
  local admin_token="$5"
  local admin_key_file="$6"
  local admin_key_id="$7"
  local out_var="$8"
  local -a header_args=()

  if [[ "$auth_mode" == "signed" ]]; then
    if [[ -z "$admin_key_file" || -z "$admin_key_id" ]]; then
      echo "missing admin signing credentials" >&2
      return 1
    fi
    if [[ ! -f "$admin_key_file" ]]; then
      echo "admin signing key file not found: $admin_key_file" >&2
      return 1
    fi
    local sign_json
    local -a sign_cmd=(
      go run ./cmd/adminsig sign
      --private-key-file "$admin_key_file"
      --key-id "$admin_key_id"
      --method "$method"
      --url "$url"
    )
    if [[ -n "$body_file" ]]; then
      sign_cmd+=(--body-file "$body_file")
    fi
    sign_json="$(
      cd "$ROOT_DIR"
      "${sign_cmd[@]}"
    )"

    local h_key_id h_ts h_nonce h_sig
    h_key_id="$(printf '%s\n' "$sign_json" | jq -r '.headers["X-Admin-Key-Id"]')"
    h_ts="$(printf '%s\n' "$sign_json" | jq -r '.headers["X-Admin-Timestamp"]')"
    h_nonce="$(printf '%s\n' "$sign_json" | jq -r '.headers["X-Admin-Nonce"]')"
    h_sig="$(printf '%s\n' "$sign_json" | jq -r '.headers["X-Admin-Signature"]')"
    if [[ -z "$h_key_id" || -z "$h_ts" || -z "$h_nonce" || -z "$h_sig" || "$h_key_id" == "null" || "$h_sig" == "null" ]]; then
      echo "failed to generate signed admin headers" >&2
      return 1
    fi
    header_args+=(-H "X-Admin-Key-Id: ${h_key_id}")
    header_args+=(-H "X-Admin-Timestamp: ${h_ts}")
    header_args+=(-H "X-Admin-Nonce: ${h_nonce}")
    header_args+=(-H "X-Admin-Signature: ${h_sig}")
  else
    if [[ -z "$admin_token" ]]; then
      echo "missing admin token" >&2
      return 1
    fi
    header_args+=(-H "X-Admin-Token: ${admin_token}")
  fi

  local -n _header_out="$out_var"
  _header_out=("${header_args[@]}")
}

discover_directory_urls() {
  local bootstrap_url="$1"
  local wait_sec="${2:-12}"
  local min_hosts="${3:-2}"
  local seed_host
  bootstrap_url="$(trim_url "$bootstrap_url")"
  seed_host="$(host_from_url "$bootstrap_url")"

  declare -A seen_hosts=()
  if [[ -n "$seed_host" ]]; then
    seen_hosts["$seed_host"]=1
  fi

  local i payload relay_urls peer_urls endpoint_values u h count
  for ((i = 1; i <= wait_sec; i++)); do
    payload="$(curl -fsS --connect-timeout 2 --max-time 4 "${bootstrap_url}/v1/relays" 2>/dev/null || true)"
    relay_urls="$(printf '%s\n' "$payload" | rg -o '"control_url":"https?://[^"]+"' || true)"
    endpoint_values="$(printf '%s\n' "$payload" | rg -o '"endpoint":"[^"]+"' || true)"
    while IFS= read -r u; do
      u="$(printf '%s' "$u" | sed -E 's/^"control_url":"(https?:\/\/[^"]+)"$/\1/')"
      h="$(host_from_url "$u")"
      if [[ -n "$h" ]]; then
        seen_hosts["$h"]=1
      fi
    done <<<"$relay_urls"
    while IFS= read -r u; do
      u="$(printf '%s' "$u" | sed -E 's/^"endpoint":"([^"]+)"$/\1/')"
      h="$(host_from_hostport "$u")"
      if [[ -n "$h" ]]; then
        seen_hosts["$h"]=1
      fi
    done <<<"$endpoint_values"

    payload="$(curl -fsS --connect-timeout 2 --max-time 4 "${bootstrap_url}/v1/peers" 2>/dev/null || true)"
    peer_urls="$(printf '%s\n' "$payload" | rg -o '"url":"https?://[^"]+"' || true)"
    while IFS= read -r u; do
      u="$(printf '%s' "$u" | sed -E 's/^"url":"(https?:\/\/[^"]+)"$/\1/')"
      h="$(host_from_url "$u")"
      if [[ -n "$h" ]]; then
        seen_hosts["$h"]=1
      fi
    done <<<"$peer_urls"

    count="${#seen_hosts[@]}"
    if ((count >= min_hosts)); then
      break
    fi
    sleep 1
  done

  if [[ -z "$seed_host" ]]; then
    seed_host="$(host_from_url "$bootstrap_url")"
  fi

  local out=()
  if [[ -n "$seed_host" ]]; then
    out+=("$(url_from_host_port "$seed_host" 8081)")
    unset 'seen_hosts[$seed_host]'
  fi

  local sorted_hosts
  sorted_hosts="$(printf '%s\n' "${!seen_hosts[@]}" | awk 'NF > 0' | sort -u)"
  while IFS= read -r h; do
    [[ -z "$h" ]] && continue
    out+=("$(url_from_host_port "$h" 8081)")
  done <<<"$sorted_hosts"

  local joined=""
  local item
  for item in "${out[@]}"; do
    if [[ -n "$joined" ]]; then
      joined+=","
    fi
    joined+="$item"
  done
  echo "$joined"
}

merge_url_csv() {
  local left="$1"
  local right="$2"
  local combined
  combined="$(
    {
      printf '%s' "$left" | tr ',' '\n'
      printf '\n'
      printf '%s' "$right" | tr ',' '\n'
    } | awk 'NF > 0' | awk '!seen[$0]++'
  )"
  printf '%s\n' "$combined" | paste -sd, -
}

normalize_url_csv_scheme() {
  local csv="$1"
  local scheme="$2"
  local out=""
  local item normalized
  while IFS= read -r item; do
    [[ -z "$item" ]] && continue
    normalized="$(ensure_url_scheme "$item" "$scheme")"
    if [[ -n "$out" ]]; then
      out+=","
    fi
    out+="$normalized"
  done < <(split_csv_lines "$csv")
  echo "$out"
}

normalize_url_csv_scheme_unique() {
  local csv="$1"
  local scheme="$2"
  local out=""
  local item normalized dedupe_key
  declare -A seen=()
  while IFS= read -r item; do
    [[ -z "$item" ]] && continue
    normalized="$(trim_url "$(ensure_url_scheme "$item" "$scheme")")"
    [[ -z "$normalized" ]] && continue
    # URL host/scheme are case-insensitive; keep first-seen value but dedupe by lowercase key.
    dedupe_key="$(printf '%s' "$normalized" | tr '[:upper:]' '[:lower:]')"
    if [[ -n "${seen[$dedupe_key]+x}" ]]; then
      continue
    fi
    seen["$dedupe_key"]=1
    if [[ -n "$out" ]]; then
      out+=","
    fi
    out+="$normalized"
  done < <(split_csv_lines "$csv")
  echo "$out"
}

split_csv_lines() {
  local csv="$1"
  printf '%s' "$csv" |
    tr ',' '\n' |
    sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' |
    awk 'NF > 0'
}

filter_peer_dirs_excluding_host() {
  local peer_dirs="$1"
  local local_host="$2"
  local out=""
  local peer
  local peer_host
  while IFS= read -r peer; do
    [[ -z "$peer" ]] && continue
    peer_host="$(host_from_url "$peer")"
    if [[ -n "$local_host" && -n "$peer_host" && "$peer_host" == "$local_host" ]]; then
      continue
    fi
    if [[ -n "$out" ]]; then
      out+=","
    fi
    out+="$peer"
  done < <(split_csv_lines "$peer_dirs")
  echo "$out"
}

detect_local_host() {
  local candidate=""
  if command -v tailscale >/dev/null 2>&1; then
    candidate="$(tailscale ip -4 2>/dev/null | awk 'NF > 0 {print; exit}' || true)"
    if [[ -n "$candidate" ]]; then
      echo "$candidate"
      return
    fi
  fi

  if command -v ip >/dev/null 2>&1; then
    candidate="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}' || true)"
    if [[ -n "$candidate" && "$candidate" != "127.0.0.1" ]]; then
      echo "$candidate"
      return
    fi
  fi

  if command -v hostname >/dev/null 2>&1; then
    candidate="$(hostname -I 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i !~ /^127\./) {print $i; exit}}' || true)"
    if [[ -n "$candidate" ]]; then
      echo "$candidate"
      return
    fi
  fi
}

write_hosts_config() {
  local host_a="$1"
  local host_b="$2"
  local file
  file="$(hosts_config_file)"
  mkdir -p "$(dirname "$file")"
  cat >"$file" <<EOF_HOSTS
MACHINE_A_HOST=$host_a
MACHINE_B_HOST=$host_b
EOF_HOSTS
}

identity_config_file() {
  echo "$DEPLOY_DIR/data/easy_node_identity.conf"
}

server_mode_file() {
  echo "$DEPLOY_DIR/data/easy_node_server_mode.conf"
}

sanitize_id_component() {
  local raw="$1"
  local out
  out="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-')"
  out="${out#-}"
  out="${out%-}"
  if [[ -z "$out" ]]; then
    out="node"
  fi
  echo "$out"
}

safe_wg_iface_name() {
  local raw="$1"
  local cleaned
  cleaned="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
  if [[ -z "$cleaned" ]]; then
    cleaned="node"
  fi
  cleaned="${cleaned:0:9}"
  printf 'wge%s' "$cleaned"
}

csv_count() {
  local csv="$1"
  awk 'NF > 0 {n++} END {print n + 0}' < <(split_csv_lines "$csv")
}

build_issuer_urls_csv() {
  local base_issuer_url="$1"
  local peer_dirs="$2"
  local scheme="$3"
  local out=""
  declare -A seen=()

  add_url() {
    local candidate
    candidate="$(trim_url "$(ensure_url_scheme "$1" "$scheme")")"
    if [[ -z "$candidate" ]]; then
      return
    fi
    if [[ -n "${seen[$candidate]+x}" ]]; then
      return
    fi
    seen["$candidate"]=1
    if [[ -n "$out" ]]; then
      out+=","
    fi
    out+="$candidate"
  }

  if [[ -n "$base_issuer_url" ]]; then
    add_url "$base_issuer_url"
  fi

  local peer peer_host peer_issuer
  while IFS= read -r peer; do
    [[ -z "$peer" ]] && continue
    peer_host="$(host_from_url "$peer")"
    [[ -z "$peer_host" ]] && continue
    peer_issuer="$(url_from_host_port "$peer_host" 8082)"
    add_url "$peer_issuer"
  done < <(split_csv_lines "$peer_dirs")

  echo "$out"
}

random_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 16
    return
  fi
  # Fallback entropy path when openssl is unavailable.
  if [[ -r /dev/urandom ]] && command -v od >/dev/null 2>&1; then
    od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n'
    return
  fi
  # Last-resort fallback.
  date +%s%N | sha256sum | awk '{print substr($1,1,32)}'
}

random_id_suffix() {
  local token
  token="$(random_token | tr -cd 'a-zA-Z0-9' | tr '[:upper:]' '[:lower:]' | head -c 10)"
  if [[ -z "$token" ]]; then
    token="$(date +%s%N | tail -c 11)"
  fi
  echo "$token"
}

identity_value() {
  local file="$1"
  local key="$2"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  awk -F= -v k="$key" '
    $1 == k {
      v = substr($0, index($0, "=") + 1)
      gsub(/\r/, "", v)
      sub(/^[[:space:]]+/, "", v)
      sub(/[[:space:]]+$/, "", v)
      print v
      exit
    }
  ' "$file"
}

write_identity_config() {
  local operator_id="$1"
  local issuer_id="$2"
  local file
  file="$(identity_config_file)"
  mkdir -p "$(dirname "$file")"
  cat >"$file" <<EOF_ID
EASY_NODE_OPERATOR_ID=${operator_id}
EASY_NODE_ISSUER_ID=${issuer_id}
EOF_ID
  secure_file_permissions "$file"
}

write_server_mode() {
  local mode="$1"
  local file
  file="$(server_mode_file)"
  mkdir -p "$(dirname "$file")"
  cat >"$file" <<EOF_MODE
EASY_NODE_SERVER_MODE=${mode}
EASY_NODE_SERVER_MODE_UPDATED_UNIX=$(date +%s)
EOF_MODE
  secure_file_permissions "$file"
}

active_server_mode() {
  local mode_file mode
  mode_file="$(server_mode_file)"
  mode="$(identity_value "$mode_file" "EASY_NODE_SERVER_MODE")"
  if [[ -n "$mode" ]]; then
    echo "$mode"
    return
  fi
  if [[ -f "$AUTHORITY_ENV_FILE" && ! -f "$PROVIDER_ENV_FILE" ]]; then
    echo "authority"
    return
  fi
  if [[ -f "$PROVIDER_ENV_FILE" && ! -f "$AUTHORITY_ENV_FILE" ]]; then
    echo "provider"
    return
  fi
  echo "unknown"
}

active_server_env_file() {
  local mode
  mode="$(active_server_mode)"
  if [[ "$mode" == "provider" ]]; then
    echo "$PROVIDER_ENV_FILE"
    return
  fi
  echo "$AUTHORITY_ENV_FILE"
}

require_authority_mode() {
  local action="$1"
  local mode
  mode="$(active_server_mode)"
  if [[ "$mode" == "authority" ]]; then
    return
  fi
  echo "$action is allowed only on authority nodes."
  echo "detected mode: $mode"
  echo "run server-up --mode authority on your admin machine."
  exit 2
}

directory_has_operator_id() {
  local directory_url="$1"
  local operator_id="$2"
  local local_host="${3:-}"
  local payload
  local -a tls_opts
  mapfile -t tls_opts < <(curl_tls_opts_for_url "$directory_url")
  payload="$(curl -fsS --connect-timeout 2 --max-time 4 "${tls_opts[@]}" "$(trim_url "$directory_url")/v1/relays" 2>/dev/null || true)"
  if [[ -z "$payload" ]]; then
    return 2
  fi

  local ids
  if ! ids="$(printf '%s\n' "$payload" | jq -r '.relays[]? | ((.operator_id // .operator // .origin_operator // "") | tostring)' 2>/dev/null)"; then
    return 2
  fi
  if [[ -n "$local_host" ]]; then
    local conflict_count
    if ! conflict_count="$(
      printf '%s\n' "$payload" | jq -r --arg target "$operator_id" --arg local_host "$local_host" '
        [
          .relays[]?
          | select(((.operator_id // .operator // .origin_operator // "") | tostring) == $target)
          | (
              (.control_url // "") | tostring
            ) as $control_url
          | (
            if ($control_url | length) == 0 then
              true
            else
              (
                $control_url
                | sub("^[A-Za-z][A-Za-z0-9+.-]*://"; "")
                | split("/")[0]
                | split("@")[-1]
                | split(":")[0]
                | ascii_downcase
              ) as $relay_host
              | ($relay_host != ($local_host | ascii_downcase))
            end
          ) as $is_conflict
          | select($is_conflict)
        ] | length
      ' 2>/dev/null
    )"; then
      return 2
    fi
    if [[ "$conflict_count" =~ ^[0-9]+$ ]] && ((conflict_count > 0)); then
      return 0
    fi
    return 1
  fi
  if printf '%s\n' "$ids" | awk -v target="$operator_id" '$0 == target {found=1} END {exit(found ? 0 : 1)}'; then
    return 0
  fi
  return 1
}

issuer_id_from_url_checked() {
  local issuer_url="$1"
  local payload
  local -a tls_opts
  mapfile -t tls_opts < <(curl_tls_opts_for_url "$issuer_url")
  payload="$(curl -fsS --connect-timeout 2 --max-time 4 "${tls_opts[@]}" "$(trim_url "$issuer_url")/v1/pubkeys" 2>/dev/null || true)"
  if [[ -z "$payload" ]]; then
    return 2
  fi
  local issuer_id
  if ! issuer_id="$(printf '%s\n' "$payload" | jq -r '(.issuer // "") | tostring' 2>/dev/null)"; then
    return 2
  fi
  if [[ "$issuer_id" == "null" ]]; then
    issuer_id=""
  fi
  printf '%s\n' "$issuer_id"
  return 0
}

operator_id_conflicts_with_peers() {
  local operator_id="$1"
  local peer_dirs="$2"
  local local_host="${3:-}"
  local peer
  local unknown=0
  while IFS= read -r peer; do
    [[ -z "$peer" ]] && continue
    if directory_has_operator_id "$peer" "$operator_id" "$local_host"; then
      return 0
    else
      local rc=$?
      if [[ "$rc" == "2" ]]; then
        unknown=1
      fi
    fi
  done < <(split_csv_lines "$peer_dirs")
  if [[ "$unknown" == "1" ]]; then
    return 2
  fi
  return 1
}

issuer_id_conflicts_with_peers() {
  local issuer_id="$1"
  local peer_dirs="$2"
  local peer
  local peer_host
  local peer_issuer_url
  local peer_issuer_id
  local unknown=0
  while IFS= read -r peer; do
    [[ -z "$peer" ]] && continue
    peer_host="$(host_from_url "$peer")"
    [[ -z "$peer_host" ]] && continue
    peer_issuer_url="$(url_from_host_port "$peer_host" 8082)"
    if peer_issuer_id="$(issuer_id_from_url_checked "$peer_issuer_url" 2>/dev/null)"; then
      :
    else
      local rc=$?
      if [[ "$rc" == "2" ]]; then
        unknown=1
        continue
      fi
      continue
    fi
    if [[ -n "$peer_issuer_id" && "$peer_issuer_id" == "$issuer_id" ]]; then
      return 0
    fi
  done < <(split_csv_lines "$peer_dirs")
  if [[ "$unknown" == "1" ]]; then
    return 2
  fi
  return 1
}

peer_dirs_have_reachable_issuer() {
  local peer_dirs="$1"
  local peer
  local peer_host
  local peer_issuer_url
  local peer_issuer_id
  while IFS= read -r peer; do
    [[ -z "$peer" ]] && continue
    peer_host="$(host_from_url "$peer")"
    [[ -z "$peer_host" ]] && continue
    peer_issuer_url="$(url_from_host_port "$peer_host" 8082)"
    if peer_issuer_id="$(issuer_id_from_url_checked "$peer_issuer_url" 2>/dev/null)"; then
      if [[ -n "$peer_issuer_id" ]]; then
        return 0
      fi
    fi
  done < <(split_csv_lines "$peer_dirs")
  return 1
}

peer_dirs_have_reachable_relays() {
  local peer_dirs="$1"
  local peer
  local payload
  local -a tls_opts
  while IFS= read -r peer; do
    [[ -z "$peer" ]] && continue
    mapfile -t tls_opts < <(curl_tls_opts_for_url "$peer")
    payload="$(curl -fsS --connect-timeout 2 --max-time 4 "${tls_opts[@]}" "$(trim_url "$peer")/v1/relays" 2>/dev/null || true)"
    if [[ -z "$payload" ]]; then
      continue
    fi
    if printf '%s\n' "$payload" | jq -e '.relays' >/dev/null 2>&1; then
      return 0
    fi
  done < <(split_csv_lines "$peer_dirs")
  return 1
}

print_prod_https_mismatch_hint_for_endpoint() {
  local endpoint_url="$1"
  local endpoint_label="$2"
  local timeout_sec="${3:-4}"
  endpoint_url="$(trim_url "$endpoint_url")"
  if ! is_https_url "$endpoint_url"; then
    return 1
  fi
  local http_probe_url
  http_probe_url="http://${endpoint_url#https://}"
  if curl -fsS --connect-timeout 2 --max-time "$timeout_sec" "$http_probe_url" >/dev/null 2>&1; then
    echo "hint: ${endpoint_label} appears reachable over plain HTTP (${http_probe_url}) while HTTPS failed."
    echo "hint: prod profile is fail-closed and requires TLS/mTLS-capable peer and authority endpoints."
    echo "hint: either run all peered nodes with --prod-profile 1, or use --prod-profile 0 for non-TLS lab peering."
    return 0
  fi
  return 1
}

print_prod_https_mismatch_hint_for_peer_relays() {
  local peer_dirs="$1"
  local timeout_sec="${2:-4}"
  local peer endpoint_url
  while IFS= read -r peer; do
    [[ -z "$peer" ]] && continue
    endpoint_url="$(trim_url "$peer")/v1/relays"
    if print_prod_https_mismatch_hint_for_endpoint "$endpoint_url" "peer directory ${peer}" "$timeout_sec"; then
      return 0
    fi
  done < <(split_csv_lines "$peer_dirs")
  return 1
}

print_prod_https_mismatch_hint_for_peer_issuers() {
  local peer_dirs="$1"
  local timeout_sec="${2:-4}"
  local peer peer_host peer_issuer_url endpoint_url
  while IFS= read -r peer; do
    [[ -z "$peer" ]] && continue
    peer_host="$(host_from_url "$peer")"
    [[ -z "$peer_host" ]] && continue
    peer_issuer_url="$(ensure_url_scheme "$(url_from_host_port "$peer_host" 8082)" "https")"
    endpoint_url="$(trim_url "$peer_issuer_url")/v1/pubkeys"
    if print_prod_https_mismatch_hint_for_endpoint "$endpoint_url" "peer issuer ${peer_issuer_url}" "$timeout_sec"; then
      return 0
    fi
  done < <(split_csv_lines "$peer_dirs")
  return 1
}

print_provider_prod_http_authority_hint() {
  local authority_directory="$1"
  local authority_issuer="$2"
  if [[ "$authority_directory" == http://* || "$authority_issuer" == http://* ]]; then
    echo "hint: provider preflight is running with --prod-profile 1, so authority URLs are normalized to https before probing."
    echo "hint: configured authority looks non-prod/http (directory=${authority_directory}, issuer=${authority_issuer:-[derived]})."
    echo "hint: use --prod-profile 0 for a non-prod authority, or move the authority to HTTPS/mTLS before rerunning."
    return 0
  fi
  return 1
}

issuer_sync_optional_no_sources() {
  local issuer_success="$1"
  local issuer_quorum="$2"
  local issuer_sources="$3"
  local issuer_source_operator_count="$4"
  local issuer_required="$5"
  local issuer_error="${6:-}"
  local max_issuer_sync_age_sec="$7"
  local min_issuer_success_sources="$8"
  local min_issuer_source_operators="$9"

  # When issuer trust sources are not configured, directory reports:
  #   success=true, quorum_met=false, success_sources=0, source_operators=0, error=""
  # Treat issuer sync as optional in this baseline shape unless explicit issuer floors/age policy were requested.
  if [[ "$issuer_success" != "true" || "$issuer_quorum" == "true" ]]; then
    return 1
  fi
  if ! [[ "$issuer_sources" =~ ^[0-9]+$ ]] || ((issuer_sources != 0)); then
    return 1
  fi
  if ! [[ "$issuer_source_operator_count" =~ ^[0-9]+$ ]] || ((issuer_source_operator_count != 0)); then
    return 1
  fi
  if ! [[ "$issuer_required" =~ ^[0-9]+$ ]] || ((issuer_required <= 0)); then
    return 1
  fi
  if [[ -n "$issuer_error" ]]; then
    return 1
  fi
  if ! [[ "$max_issuer_sync_age_sec" =~ ^[0-9]+$ ]] || ((max_issuer_sync_age_sec != 0)); then
    return 1
  fi
  if ! [[ "$min_issuer_success_sources" =~ ^[0-9]+$ ]] || ((min_issuer_success_sources != 0)); then
    return 1
  fi
  if ! [[ "$min_issuer_source_operators" =~ ^[0-9]+$ ]] || ((min_issuer_source_operators != 0)); then
    return 1
  fi
  return 0
}

ensure_deps_or_die() {
  local log_dir
  local log_file
  log_dir="$(prepare_log_dir)"
  log_file="$log_dir/easy_node_depcheck.log"
  if ! check_dependencies >"$log_file" 2>&1; then
    cat "$log_file"
    echo "dependency check log: $log_file"
    exit 1
  fi
}

check_compose_dependencies() {
  local ok=1
  need_cmd docker || ok=0
  if ! docker compose version >/dev/null 2>&1; then
    echo "missing dependency: docker compose plugin"
    echo "hint: install docker compose plugin (sudo apt-get update && sudo apt-get install -y docker-compose-plugin)"
    ok=0
  fi
  if [[ $ok -eq 1 ]]; then
    echo "dependency check: ok"
    docker --version
    docker compose version
    if ! docker info >/dev/null 2>&1; then
      echo "note: docker daemon is not reachable for this user yet"
      echo "      fix by adding your user to docker group or use sudo"
    fi
    return 0
  fi
  return 1
}

ensure_compose_deps_or_die() {
  local log_dir
  local log_file
  log_dir="$(prepare_log_dir)"
  log_file="$log_dir/easy_node_depcheck.log"
  if ! check_compose_dependencies >"$log_file" 2>&1; then
    cat "$log_file"
    echo "dependency check log: $log_file"
    exit 1
  fi
}

check_server_up_dependencies() {
  local mode="${1:-authority}"
  local prod_profile="${2:-0}"
  local peer_dirs="${3:-}"
  local bootstrap_directory="${4:-}"
  local beta_profile="${5:-0}"
  local ok=1

  need_cmd docker || ok=0
  need_cmd curl || ok=0

  # Peer discovery and cross-peer identity checks parse JSON/URL fields.
  if [[ -n "$peer_dirs" || -n "$bootstrap_directory" ]]; then
    need_cmd jq || ok=0
    need_cmd rg || ok=0
  fi

  # Production authority mode uses admin signing/key tooling.
  if [[ "$prod_profile" == "1" ]]; then
    need_cmd openssl || ok=0
    if [[ "$mode" == "authority" ]]; then
      need_cmd go || ok=0
      need_cmd jq || ok=0
      need_cmd rg || ok=0
    fi
  fi
  if [[ "$prod_profile" == "1" || "$beta_profile" == "1" ]]; then
    # server-up writes/derives exit wireguard key material for beta/prod defaults.
    need_cmd wg || ok=0
  fi

  if ! docker compose version >/dev/null 2>&1; then
    echo "missing dependency: docker compose plugin"
    echo "hint: install docker compose plugin (sudo apt-get update && sudo apt-get install -y docker-compose-plugin)"
    ok=0
  fi

  if [[ $ok -eq 1 ]]; then
    echo "dependency check: ok"
    docker --version
    docker compose version
    if ! docker info >/dev/null 2>&1; then
      echo "note: docker daemon is not reachable for this user yet"
      echo "      fix by adding your user to docker group or use sudo"
    fi
    return 0
  fi
  return 1
}

ensure_server_up_deps_or_die() {
  local mode="${1:-authority}"
  local prod_profile="${2:-0}"
  local peer_dirs="${3:-}"
  local bootstrap_directory="${4:-}"
  local beta_profile="${5:-0}"
  local log_dir
  local log_file
  log_dir="$(prepare_log_dir)"
  log_file="$log_dir/easy_node_depcheck.log"
  if ! check_server_up_dependencies "$mode" "$prod_profile" "$peer_dirs" "$bootstrap_directory" "$beta_profile" >"$log_file" 2>&1; then
    cat "$log_file"
    echo "dependency check log: $log_file"
    exit 1
  fi
}

ensure_client_vpn_deps_or_die() {
  local missing=0
  local cmd
  for cmd in go wg ip curl rg timeout jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "missing dependency for client-vpn: $cmd"
      dependency_install_hint "$cmd"
      missing=1
    fi
  done
  if [[ "$missing" -ne 0 ]]; then
    echo "install dependencies with: ./scripts/easy_node.sh install-deps-ubuntu"
    exit 1
  fi
}

sorted_csv() {
  if (($# == 0)); then
    echo ""
    return
  fi
  printf '%s\n' "$@" | LC_ALL=C sort -u | paste -sd, -
}

client_vpn_operator_floor_summary() {
  local directory_urls="$1"
  local timeout_sec="${2:-8}"
  declare -A all_ops=()
  declare -A entry_ops=()
  declare -A exit_ops=()
  local missing_operator=0
  local fetch_fail=0
  local parse_fail=0
  local directory_url payload parsed role op
  local -a tls_opts

  while IFS= read -r directory_url; do
    [[ -z "$directory_url" ]] && continue
    mapfile -t tls_opts < <(curl_tls_opts_for_url "$directory_url")
    payload="$(curl -fsS --connect-timeout 2 --max-time "$timeout_sec" "${tls_opts[@]}" "${directory_url%/}/v1/relays" 2>/dev/null || true)"
    if [[ -z "$payload" ]]; then
      fetch_fail=$((fetch_fail + 1))
      continue
    fi

    parsed=0
    while IFS=$'\t' read -r role op; do
      parsed=1
      role="$(trim "$role")"
      op="$(trim "$op")"
      [[ -z "$role" ]] && continue
      if [[ -z "$op" || "$op" == "null" ]]; then
        if [[ "$role" == "entry" || "$role" == "exit" ]]; then
          missing_operator=$((missing_operator + 1))
        fi
        continue
      fi
      all_ops["$op"]=1
      if [[ "$role" == "entry" ]]; then
        entry_ops["$op"]=1
      elif [[ "$role" == "exit" ]]; then
        exit_ops["$op"]=1
      fi
    done < <(printf '%s\n' "$payload" | jq -r '.relays[]? | [(.role // ""), ((.operator_id // .operator // .origin_operator // "") | tostring)] | @tsv' 2>/dev/null || true)

    if [[ "$parsed" -eq 0 ]]; then
      if ! printf '%s\n' "$payload" | jq -e '.relays' >/dev/null 2>&1; then
        parse_fail=$((parse_fail + 1))
      fi
    fi
  done < <(split_csv_lines "$directory_urls")

  local all_ops_csv entry_ops_csv exit_ops_csv
  all_ops_csv="$(sorted_csv "${!all_ops[@]}")"
  entry_ops_csv="$(sorted_csv "${!entry_ops[@]}")"
  exit_ops_csv="$(sorted_csv "${!exit_ops[@]}")"
  echo "${#all_ops[@]}|${#entry_ops[@]}|${#exit_ops[@]}|$missing_operator|$fetch_fail|$parse_fail|$all_ops_csv|$entry_ops_csv|$exit_ops_csv"
}

csv_has_middle_signal() {
  local csv="${1:-}"
  local token
  while IFS= read -r token; do
    token="$(printf '%s' "$token" | tr '[:upper:]' '[:lower:]')"
    token="$(trim "$token")"
    case "$token" in
      middle|relay|micro-relay|micro_relay|transit|three-hop-middle)
        return 0
        ;;
    esac
  done < <(printf '%s\n' "$csv" | tr ',' '\n')
  return 1
}

client_vpn_middle_relay_summary() {
  local directory_urls="$1"
  local timeout_sec="${2:-8}"
  declare -A middle_ops=()
  declare -A entry_ops=()
  declare -A exit_ops=()
  local middle_relays=0
  local missing_middle_operator=0
  local fetch_fail=0
  local parse_fail=0
  local directory_url payload parsed role op hop_roles capabilities
  local -a tls_opts

  while IFS= read -r directory_url; do
    [[ -z "$directory_url" ]] && continue
    mapfile -t tls_opts < <(curl_tls_opts_for_url "$directory_url")
    payload="$(curl -fsS --connect-timeout 2 --max-time "$timeout_sec" "${tls_opts[@]}" "${directory_url%/}/v1/relays" 2>/dev/null || true)"
    if [[ -z "$payload" ]]; then
      fetch_fail=$((fetch_fail + 1))
      continue
    fi

    parsed=0
    while IFS=$'\t' read -r role op hop_roles capabilities; do
      parsed=1
      role="$(printf '%s' "$role" | tr '[:upper:]' '[:lower:]')"
      role="$(trim "$role")"
      op="$(trim "$op")"
      hop_roles="$(trim "$hop_roles")"
      capabilities="$(trim "$capabilities")"
      [[ -z "$role" ]] && continue
      if [[ "$role" == "entry" && -n "$op" && "$op" != "null" ]]; then
        entry_ops["$op"]=1
      fi
      if [[ "$role" == "exit" && -n "$op" && "$op" != "null" ]]; then
        exit_ops["$op"]=1
      fi

      local middle_like=0
      if [[ "$role" == "middle" ]]; then
        middle_like=1
      elif csv_has_middle_signal "$hop_roles"; then
        middle_like=1
      elif csv_has_middle_signal "$capabilities"; then
        middle_like=1
      fi
      if [[ "$middle_like" == "1" ]]; then
        middle_relays=$((middle_relays + 1))
        if [[ -z "$op" || "$op" == "null" ]]; then
          missing_middle_operator=$((missing_middle_operator + 1))
        else
          middle_ops["$op"]=1
        fi
      fi
    done < <(printf '%s\n' "$payload" | jq -r '.relays[]? | [(.role // ""), ((.operator_id // .operator // .origin_operator // "") | tostring), ((.hop_roles // []) | map(tostring) | join(",")), ((.capabilities // []) | map(tostring) | join(","))] | @tsv' 2>/dev/null || true)

    if [[ "$parsed" -eq 0 ]]; then
      if ! printf '%s\n' "$payload" | jq -e '.relays' >/dev/null 2>&1; then
        parse_fail=$((parse_fail + 1))
      fi
    fi
  done < <(split_csv_lines "$directory_urls")

  declare -A eligible_middle_ops=()
  local op
  for op in "${!middle_ops[@]}"; do
    if [[ -n "${entry_ops[$op]+x}" || -n "${exit_ops[$op]+x}" ]]; then
      continue
    fi
    eligible_middle_ops["$op"]=1
  done

  local middle_ops_csv eligible_middle_ops_csv
  middle_ops_csv="$(sorted_csv "${!middle_ops[@]}")"
  eligible_middle_ops_csv="$(sorted_csv "${!eligible_middle_ops[@]}")"
  echo "${#middle_ops[@]}|${#eligible_middle_ops[@]}|$middle_relays|$missing_middle_operator|$fetch_fail|$parse_fail|$middle_ops_csv|$eligible_middle_ops_csv"
}

client_vpn_issuer_quorum_summary() {
  local issuer_urls="$1"
  local timeout_sec="${2:-8}"
  declare -A issuer_ids=()
  local missing_issuer=0
  local missing_keys=0
  local fetch_fail=0
  local parse_fail=0
  local issuer_url payload issuer_id key_count
  local -a tls_opts

  while IFS= read -r issuer_url; do
    [[ -z "$issuer_url" ]] && continue
    mapfile -t tls_opts < <(curl_tls_opts_for_url "$issuer_url")
    payload="$(curl -fsS --connect-timeout 2 --max-time "$timeout_sec" "${tls_opts[@]}" "${issuer_url%/}/v1/pubkeys" 2>/dev/null || true)"
    if [[ -z "$payload" ]]; then
      fetch_fail=$((fetch_fail + 1))
      continue
    fi

    if ! printf '%s\n' "$payload" | jq -e '.pub_keys' >/dev/null 2>&1; then
      parse_fail=$((parse_fail + 1))
      continue
    fi

    issuer_id="$(printf '%s\n' "$payload" | jq -r '(.issuer // "") | tostring' 2>/dev/null || true)"
    key_count="$(printf '%s\n' "$payload" | jq -r '((.pub_keys // []) | length)' 2>/dev/null || true)"
    if [[ -z "$issuer_id" || "$issuer_id" == "null" ]]; then
      missing_issuer=$((missing_issuer + 1))
    else
      issuer_ids["$issuer_id"]=1
    fi
    if ! [[ "$key_count" =~ ^[0-9]+$ ]]; then
      parse_fail=$((parse_fail + 1))
      continue
    fi
    if ((key_count < 1)); then
      missing_keys=$((missing_keys + 1))
    fi
  done < <(split_csv_lines "$issuer_urls")

  echo "${#issuer_ids[@]}|$missing_issuer|$missing_keys|$fetch_fail|$parse_fail"
}

compose_with_env() {
  local env_file="$1"
  shift
  local -a clear_env_args
  local clear_var
  # Prevent ambient shell exports from overriding generated easy-node env files.
  # This is especially important for WG key material during server-up.
  for clear_var in \
    DATA_PLANE_MODE \
    WG_BACKEND \
    EXIT_WG_PRIVATE_KEY_PATH \
    EXIT_WG_PUBKEY \
    EXIT_WG_INTERFACE \
    EXIT_WG_AUTO_CREATE_INTERFACE \
    EXIT_WG_KERNEL_PROXY \
    EXIT_LIVE_WG_MODE \
    EXIT_OPAQUE_ECHO \
    EXIT_OPAQUE_SINK_ADDR \
    EXIT_OPAQUE_SOURCE_ADDR \
    ENTRY_LIVE_WG_MODE; do
    clear_env_args+=("-u" "$clear_var")
  done
  if [[ -f "$env_file" ]]; then
    (cd "$DEPLOY_DIR" && env "${clear_env_args[@]}" docker compose --env-file "$env_file" "$@")
  else
    (cd "$DEPLOY_DIR" && env "${clear_env_args[@]}" docker compose "$@")
  fi
}

clear_runtime_override_env_vars() {
  # Clears known runtime override vars in this process so cleanup/start flows
  # are deterministic even if the caller shell exported stale values.
  local -a runtime_vars
  runtime_vars=(
    DATA_PLANE_MODE
    WG_BACKEND
    EXIT_WG_PRIVATE_KEY_PATH
    EXIT_WG_PUBKEY
    EXIT_WG_INTERFACE
    EXIT_WG_AUTO_CREATE_INTERFACE
    EXIT_WG_KERNEL_PROXY
    EXIT_LIVE_WG_MODE
    EXIT_OPAQUE_ECHO
    EXIT_OPAQUE_SINK_ADDR
    EXIT_OPAQUE_SOURCE_ADDR
    ENTRY_LIVE_WG_MODE
  )
  local v
  local cleared=0
  for v in "${runtime_vars[@]}"; do
    if [[ -n "${!v+x}" ]]; then
      unset "$v"
      cleared=$((cleared + 1))
    fi
  done
  if ((cleared > 0)); then
    echo "runtime override cleanup: cleared $cleared process env override(s)"
  fi
}

compose_server() {
  compose_with_env "$AUTHORITY_ENV_FILE" "$@"
}

write_authority_env() {
  local public_host="$1"
  local operator_id="$2"
  local issuer_id="$3"
  local issuer_admin_token="$4"
  local directory_admin_token="$5"
  local entry_puzzle_secret="$6"
  local peer_dirs="$7"
  local beta_profile="$8"
  local client_allowlist="$9"
  local allow_anon_cred="${10}"
  local prod_profile="${11}"
  local admin_signers_file_container="${12:-}"
  local admin_sign_key_id="${13:-}"
  local admin_sign_key_file_local="${14:-}"
  local issuer_urls_csv="${15:-}"
  local exit_wg_private_key_path="${16:-}"
  local exit_wg_interface="${17:-}"
  local exit_wg_pubkey="${18:-}"
  local issuer_admin_token_effective="$issuer_admin_token"
  local public_scheme="http"
  local relay_suffix
  local issuer_suffix
  local entry_exit_user_non_prod
  local peer_sources_count=0
  local peer_gossip_sec="5"
  local entry_directory_urls=""
  if [[ "$prod_profile" == "1" ]]; then
    public_scheme="https"
    # In strict prod profile token admin auth is disabled; avoid persisting an unused token.
    issuer_admin_token_effective=""
  fi
  relay_suffix="$(sanitize_id_component "$operator_id")"
  if [[ -z "$issuer_id" ]]; then
    issuer_id="issuer-$(random_id_suffix)"
  fi
  issuer_suffix="$(sanitize_id_component "$issuer_id")"
  entry_directory_urls="${public_scheme}://directory:8081"

  cat >"$AUTHORITY_ENV_FILE" <<EOF_ENV
EASY_NODE_SERVER_MODE=authority
DIRECTORY_PUBLIC_URL=${public_scheme}://${public_host}:8081
ENTRY_URL_PUBLIC=${public_scheme}://${public_host}:8083
EXIT_CONTROL_URL_PUBLIC=${public_scheme}://${public_host}:8084
ENTRY_ENDPOINT_PUBLIC=${public_host}:51820
EXIT_ENDPOINT_PUBLIC=${public_host}:51821
DIRECTORY_OPERATOR_ID=${operator_id}
ENTRY_OPERATOR_ID=${operator_id}
ENTRY_RELAY_ID=entry-${relay_suffix}
EXIT_RELAY_ID=exit-${relay_suffix}
DIRECTORY_PRIVATE_KEY_FILE=/app/data/directory_${relay_suffix}_ed25519.key
DIRECTORY_PREVIOUS_PUBKEYS_FILE=/app/data/directory_${relay_suffix}_previous_pubkeys.txt
ISSUER_ID=${issuer_id}
ISSUER_PRIVATE_KEY_FILE=/app/data/issuer_${issuer_suffix}_ed25519.key
ISSUER_PREVIOUS_PUBKEYS_FILE=/app/data/issuer_${issuer_suffix}_previous_pubkeys.txt
ISSUER_EPOCHS_FILE=/app/data/issuer_${issuer_suffix}_epochs.json
ISSUER_SUBJECTS_FILE=/app/data/issuer_${issuer_suffix}_subjects.json
ISSUER_REVOCATIONS_FILE=/app/data/issuer_${issuer_suffix}_revocations.json
ISSUER_ANON_REVOCATIONS_FILE=/app/data/issuer_${issuer_suffix}_anon_revocations.json
ISSUER_ANON_DISPUTES_FILE=/app/data/issuer_${issuer_suffix}_anon_disputes.json
ISSUER_AUDIT_FILE=/app/data/issuer_${issuer_suffix}_audit.json
ISSUER_ADMIN_TOKEN=${issuer_admin_token_effective}
DIRECTORY_ADMIN_TOKEN=${directory_admin_token}
ENTRY_PUZZLE_SECRET=${entry_puzzle_secret}
ISSUER_CLIENT_ALLOWLIST_ONLY=${client_allowlist}
ISSUER_ALLOW_ANON_CRED=${allow_anon_cred}
EOF_ENV
  secure_file_permissions "$AUTHORITY_ENV_FILE"

  if [[ -n "$peer_dirs" ]]; then
    peer_sources_count="$(csv_count "$peer_dirs")"
    if ((peer_sources_count < 2)); then
      # With one configured peer, push-gossip often becomes one-way and noisy (403).
      # Pull sync still runs every cycle, so disable push-gossip for this bootstrap shape.
      peer_gossip_sec="0"
    fi
  fi

  if [[ -n "$peer_dirs" ]]; then
    echo "DIRECTORY_PEERS=${peer_dirs}" >>"$AUTHORITY_ENV_FILE"
    echo "DIRECTORY_SYNC_SEC=5" >>"$AUTHORITY_ENV_FILE"
    echo "DIRECTORY_GOSSIP_SEC=${peer_gossip_sec}" >>"$AUTHORITY_ENV_FILE"
    entry_directory_urls="$(merge_url_csv "$entry_directory_urls" "$peer_dirs")"
  fi
  echo "DIRECTORY_URLS=${entry_directory_urls}" >>"$AUTHORITY_ENV_FILE"

  if [[ "$prod_profile" != "1" ]]; then
    if [[ "$beta_profile" == "1" ]]; then
      # Keep beta non-prod server-up transport-compatible with client-vpn-up/smoke
      # (opaque wireguard transport) without requiring prod mTLS.
      cat >>"$AUTHORITY_ENV_FILE" <<EOF_RUNTIME
DATA_PLANE_MODE=opaque
WG_BACKEND=command
ENTRY_LIVE_WG_MODE=1
ENTRY_OPEN_RPS=12
ENTRY_BAN_THRESHOLD=3
ENTRY_BAN_SEC=90
ENTRY_MAX_CONCURRENT_OPENS=96
EXIT_WG_PRIVATE_KEY_PATH=${exit_wg_private_key_path}
EXIT_WG_PUBKEY=${exit_wg_pubkey}
EXIT_WG_INTERFACE=${exit_wg_interface}
EXIT_WG_AUTO_CREATE_INTERFACE=1
EXIT_WG_KERNEL_PROXY=1
EXIT_LIVE_WG_MODE=1
EXIT_OPAQUE_ECHO=0
EXIT_OPAQUE_SINK_ADDR=127.0.0.1:51982
EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:51983
EXIT_TOKEN_PROOF_REPLAY_GUARD=1
EXIT_PEER_REBIND_SEC=0
EXIT_STARTUP_SYNC_TIMEOUT_SEC=30
ENTRY_EXIT_USER=0:0
ENTRY_EXIT_PRIVILEGED=true
EOF_RUNTIME
    else
      entry_exit_user_non_prod="$(resolve_entry_exit_user_non_prod)"
      cat >>"$AUTHORITY_ENV_FILE" <<EOF_RUNTIME
ENTRY_EXIT_USER=${entry_exit_user_non_prod}
ENTRY_EXIT_PRIVILEGED=false
EOF_RUNTIME
    fi
  fi

  local beta_peer_min_operators="2"
  local beta_peer_min_votes="2"
  local beta_peer_discovery_min_votes="2"
  local beta_entry_min_operators="2"
  local beta_entry_min_votes="2"
  if [[ "$beta_profile" == "1" && "$prod_profile" != "1" ]]; then
    # Bootstrap-friendly beta defaults: if only one peer source is configured,
    # avoid permanent quorum churn while still keeping prod strict settings.
    if ((peer_sources_count < 2)); then
      beta_peer_min_operators="1"
      beta_peer_min_votes="1"
      beta_peer_discovery_min_votes="1"
    fi
    if ((peer_sources_count < 1)); then
      beta_entry_min_operators="1"
      beta_entry_min_votes="1"
    fi
  fi

  if [[ "$beta_profile" == "1" ]]; then
    cat >>"$AUTHORITY_ENV_FILE" <<EOF_BETA
DIRECTORY_MIN_OPERATORS=2
DIRECTORY_MIN_RELAY_VOTES=2
ENTRY_DIRECTORY_MIN_OPERATORS=${beta_entry_min_operators}
ENTRY_DIRECTORY_MIN_RELAY_VOTES=${beta_entry_min_votes}
ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1
DIRECTORY_PEER_MIN_OPERATORS=${beta_peer_min_operators}
DIRECTORY_PEER_MIN_VOTES=${beta_peer_min_votes}
DIRECTORY_PEER_DISCOVERY_MIN_VOTES=${beta_peer_discovery_min_votes}
DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE=8
DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR=4
DIRECTORY_PROVIDER_MAX_RELAYS_PER_OPERATOR=32
DIRECTORY_PROVIDER_SPLIT_ROLES=1
ISSUER_TOKEN_TTL_SEC=300
EOF_BETA
  fi
  if [[ "$prod_profile" == "1" ]]; then
    cat >>"$AUTHORITY_ENV_FILE" <<EOF_PROD
BETA_STRICT_MODE=1
PROD_STRICT_MODE=1
DATA_PLANE_MODE=opaque
MTLS_ENABLE=1
MTLS_CA_FILE=/app/tls/ca.crt
MTLS_CERT_FILE=/app/tls/node.crt
MTLS_KEY_FILE=/app/tls/node.key
MTLS_CLIENT_CERT_FILE=/app/tls/node.crt
MTLS_CLIENT_KEY_FILE=/app/tls/node.key
MTLS_REQUIRE_CLIENT_CERT=1
MTLS_MIN_VERSION=1.3
DIRECTORY_TRUST_STRICT=1
DIRECTORY_TRUST_TOFU=0
ENTRY_DIRECTORY_TRUST_STRICT=1
ENTRY_DIRECTORY_TRUST_TOFU=0
ENTRY_DIRECTORY_MIN_SOURCES=2
ENTRY_DIRECTORY_MIN_OPERATORS=2
ENTRY_DIRECTORY_MIN_RELAY_VOTES=2
DIRECTORY_PEER_TRUST_STRICT=1
DIRECTORY_PEER_TRUST_TOFU=0
DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1
DIRECTORY_ISSUER_TRUST_URLS=${issuer_urls_csv}
DIRECTORY_PROVIDER_ISSUER_URLS=${issuer_urls_csv}
DIRECTORY_ISSUER_MIN_OPERATORS=2
DIRECTORY_ISSUER_TRUST_MIN_VOTES=2
DIRECTORY_ISSUER_DISPUTE_MIN_VOTES=2
DIRECTORY_ISSUER_APPEAL_MIN_VOTES=2
DIRECTORY_PEER_DISPUTE_MIN_VOTES=2
DIRECTORY_PEER_APPEAL_MIN_VOTES=2
DIRECTORY_ADJUDICATION_META_MIN_VOTES=2
DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS=2
DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES=2
DIRECTORY_FINAL_DISPUTE_MIN_VOTES=2
DIRECTORY_FINAL_APPEAL_MIN_VOTES=2
DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO=0.67
DIRECTORY_DISPUTE_MAX_TTL_SEC=259200
DIRECTORY_APPEAL_MAX_TTL_SEC=259200
DIRECTORY_KEY_ROTATE_SEC=86400
ISSUER_URLS=${issuer_urls_csv}
ENTRY_LIVE_WG_MODE=1
WG_BACKEND=command
ENTRY_OPEN_RPS=12
ENTRY_BAN_THRESHOLD=3
ENTRY_BAN_SEC=90
ENTRY_MAX_CONCURRENT_OPENS=96
EXIT_WG_PRIVATE_KEY_PATH=${exit_wg_private_key_path}
EXIT_WG_PUBKEY=${exit_wg_pubkey}
EXIT_WG_INTERFACE=${exit_wg_interface}
EXIT_WG_AUTO_CREATE_INTERFACE=1
EXIT_WG_KERNEL_PROXY=1
EXIT_LIVE_WG_MODE=1
EXIT_OPAQUE_ECHO=0
EXIT_OPAQUE_SINK_ADDR=127.0.0.1:51982
EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:51983
EXIT_TOKEN_PROOF_REPLAY_GUARD=1
EXIT_PEER_REBIND_SEC=0
EXIT_STARTUP_SYNC_TIMEOUT_SEC=30
EXIT_ISSUER_MIN_SOURCES=2
EXIT_ISSUER_MIN_OPERATORS=2
EXIT_ISSUER_REQUIRE_ID=1
ENTRY_PUZZLE_DIFFICULTY=1
ISSUER_KEY_ROTATE_SEC=86400
ISSUER_TOKEN_TTL_SEC=300
ISSUER_ANON_CRED_EXPOSE_ID=0
ENTRY_EXIT_USER=0:0
ENTRY_EXIT_PRIVILEGED=true
ISSUER_ADMIN_REQUIRE_SIGNED=1
ISSUER_ADMIN_ALLOW_TOKEN=0
ISSUER_ADMIN_SIGNED_WINDOW_SEC=90
ISSUER_ADMIN_SIGNING_KEYS_FILE=${admin_signers_file_container}
ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL=${admin_sign_key_file_local}
ISSUER_ADMIN_SIGNING_KEY_ID=${admin_sign_key_id}
EASY_NODE_MTLS_CA_FILE_LOCAL=${DEPLOY_DIR}/tls/ca.crt
EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL=${DEPLOY_DIR}/tls/client.crt
EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL=${DEPLOY_DIR}/tls/client.key
EOF_PROD
  fi
  secure_file_permissions "$AUTHORITY_ENV_FILE"
}

write_provider_env() {
  local public_host="$1"
  local operator_id="$2"
  local directory_admin_token="$3"
  local entry_puzzle_secret="$4"
  local peer_dirs="$5"
  local beta_profile="$6"
  local authority_issuer="$7"
  local prod_profile="$8"
  local issuer_urls_csv="$9"
  local exit_wg_private_key_path="${10:-}"
  local exit_wg_interface="${11:-}"
  local exit_wg_pubkey="${12:-}"
  local public_scheme="http"
  local relay_suffix
  local entry_exit_user_non_prod
  local peer_sources_count=0
  local peer_gossip_sec="5"
  local entry_directory_urls=""

  if [[ "$prod_profile" == "1" ]]; then
    public_scheme="https"
  fi
  relay_suffix="$(sanitize_id_component "$operator_id")"
  authority_issuer="$(trim_url "$authority_issuer")"
  entry_directory_urls="${public_scheme}://directory:8081"

  cat >"$PROVIDER_ENV_FILE" <<EOF_ENV
EASY_NODE_SERVER_MODE=provider
DIRECTORY_PUBLIC_URL=${public_scheme}://${public_host}:8081
ENTRY_URL_PUBLIC=${public_scheme}://${public_host}:8083
EXIT_CONTROL_URL_PUBLIC=${public_scheme}://${public_host}:8084
ENTRY_ENDPOINT_PUBLIC=${public_host}:51820
EXIT_ENDPOINT_PUBLIC=${public_host}:51821
DIRECTORY_OPERATOR_ID=${operator_id}
ENTRY_OPERATOR_ID=${operator_id}
ENTRY_RELAY_ID=entry-${relay_suffix}
EXIT_RELAY_ID=exit-${relay_suffix}
DIRECTORY_PRIVATE_KEY_FILE=/app/data/directory_${relay_suffix}_ed25519.key
DIRECTORY_PREVIOUS_PUBKEYS_FILE=/app/data/directory_${relay_suffix}_previous_pubkeys.txt
DIRECTORY_ADMIN_TOKEN=${directory_admin_token}
ENTRY_PUZZLE_SECRET=${entry_puzzle_secret}
CORE_DIRECTORY_URL=${public_scheme}://directory:8081
CORE_ISSUER_URL=${authority_issuer}
EOF_ENV
  secure_file_permissions "$PROVIDER_ENV_FILE"

  if [[ -n "$peer_dirs" ]]; then
    peer_sources_count="$(csv_count "$peer_dirs")"
    if ((peer_sources_count < 2)); then
      peer_gossip_sec="0"
    fi
  fi

  if [[ -n "$peer_dirs" ]]; then
    echo "DIRECTORY_PEERS=${peer_dirs}" >>"$PROVIDER_ENV_FILE"
    echo "DIRECTORY_SYNC_SEC=5" >>"$PROVIDER_ENV_FILE"
    echo "DIRECTORY_GOSSIP_SEC=${peer_gossip_sec}" >>"$PROVIDER_ENV_FILE"
    entry_directory_urls="$(merge_url_csv "$entry_directory_urls" "$peer_dirs")"
  fi
  echo "DIRECTORY_URLS=${entry_directory_urls}" >>"$PROVIDER_ENV_FILE"

  if [[ "$prod_profile" != "1" ]]; then
    if [[ "$beta_profile" == "1" ]]; then
      # Keep beta non-prod server-up transport-compatible with client-vpn-up/smoke
      # (opaque wireguard transport) without requiring prod mTLS.
      cat >>"$PROVIDER_ENV_FILE" <<EOF_RUNTIME
DATA_PLANE_MODE=opaque
WG_BACKEND=command
ENTRY_LIVE_WG_MODE=1
ENTRY_OPEN_RPS=12
ENTRY_BAN_THRESHOLD=3
ENTRY_BAN_SEC=90
ENTRY_MAX_CONCURRENT_OPENS=96
EXIT_WG_PRIVATE_KEY_PATH=${exit_wg_private_key_path}
EXIT_WG_PUBKEY=${exit_wg_pubkey}
EXIT_WG_INTERFACE=${exit_wg_interface}
EXIT_WG_AUTO_CREATE_INTERFACE=1
EXIT_WG_KERNEL_PROXY=1
EXIT_LIVE_WG_MODE=1
EXIT_OPAQUE_ECHO=0
EXIT_OPAQUE_SINK_ADDR=127.0.0.1:51982
EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:51983
EXIT_TOKEN_PROOF_REPLAY_GUARD=1
EXIT_PEER_REBIND_SEC=0
EXIT_STARTUP_SYNC_TIMEOUT_SEC=30
ENTRY_EXIT_USER=0:0
ENTRY_EXIT_PRIVILEGED=true
EOF_RUNTIME
    else
      entry_exit_user_non_prod="$(resolve_entry_exit_user_non_prod)"
      cat >>"$PROVIDER_ENV_FILE" <<EOF_RUNTIME
ENTRY_EXIT_USER=${entry_exit_user_non_prod}
ENTRY_EXIT_PRIVILEGED=false
EOF_RUNTIME
    fi
  fi

  local beta_peer_min_operators="2"
  local beta_peer_min_votes="2"
  local beta_peer_discovery_min_votes="2"
  local beta_entry_min_operators="2"
  local beta_entry_min_votes="2"
  if [[ "$beta_profile" == "1" && "$prod_profile" != "1" ]]; then
    if ((peer_sources_count < 2)); then
      beta_peer_min_operators="1"
      beta_peer_min_votes="1"
      beta_peer_discovery_min_votes="1"
    fi
    if ((peer_sources_count < 1)); then
      beta_entry_min_operators="1"
      beta_entry_min_votes="1"
    fi
  fi

  if [[ "$beta_profile" == "1" ]]; then
    cat >>"$PROVIDER_ENV_FILE" <<EOF_BETA
DIRECTORY_MIN_OPERATORS=2
DIRECTORY_MIN_RELAY_VOTES=2
ENTRY_DIRECTORY_MIN_OPERATORS=${beta_entry_min_operators}
ENTRY_DIRECTORY_MIN_RELAY_VOTES=${beta_entry_min_votes}
ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1
DIRECTORY_PEER_MIN_OPERATORS=${beta_peer_min_operators}
DIRECTORY_PEER_MIN_VOTES=${beta_peer_min_votes}
DIRECTORY_PEER_DISCOVERY_MIN_VOTES=${beta_peer_discovery_min_votes}
DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE=8
DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR=4
DIRECTORY_PROVIDER_MAX_RELAYS_PER_OPERATOR=32
DIRECTORY_PROVIDER_SPLIT_ROLES=1
EOF_BETA
  fi
  if [[ "$prod_profile" == "1" ]]; then
    cat >>"$PROVIDER_ENV_FILE" <<EOF_PROD
BETA_STRICT_MODE=1
PROD_STRICT_MODE=1
DATA_PLANE_MODE=opaque
MTLS_ENABLE=1
MTLS_CA_FILE=/app/tls/ca.crt
MTLS_CERT_FILE=/app/tls/node.crt
MTLS_KEY_FILE=/app/tls/node.key
MTLS_CLIENT_CERT_FILE=/app/tls/node.crt
MTLS_CLIENT_KEY_FILE=/app/tls/node.key
MTLS_REQUIRE_CLIENT_CERT=1
MTLS_MIN_VERSION=1.3
DIRECTORY_TRUST_STRICT=1
DIRECTORY_TRUST_TOFU=0
ENTRY_DIRECTORY_TRUST_STRICT=1
ENTRY_DIRECTORY_TRUST_TOFU=0
ENTRY_DIRECTORY_MIN_SOURCES=2
ENTRY_DIRECTORY_MIN_OPERATORS=2
ENTRY_DIRECTORY_MIN_RELAY_VOTES=2
DIRECTORY_PEER_TRUST_STRICT=1
DIRECTORY_PEER_TRUST_TOFU=0
DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1
DIRECTORY_ISSUER_TRUST_URLS=${issuer_urls_csv}
DIRECTORY_PROVIDER_ISSUER_URLS=${issuer_urls_csv}
DIRECTORY_ISSUER_MIN_OPERATORS=2
DIRECTORY_ISSUER_TRUST_MIN_VOTES=2
DIRECTORY_ISSUER_DISPUTE_MIN_VOTES=2
DIRECTORY_ISSUER_APPEAL_MIN_VOTES=2
DIRECTORY_PEER_DISPUTE_MIN_VOTES=2
DIRECTORY_PEER_APPEAL_MIN_VOTES=2
DIRECTORY_ADJUDICATION_META_MIN_VOTES=2
DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS=2
DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES=2
DIRECTORY_FINAL_DISPUTE_MIN_VOTES=2
DIRECTORY_FINAL_APPEAL_MIN_VOTES=2
DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO=0.67
DIRECTORY_DISPUTE_MAX_TTL_SEC=259200
DIRECTORY_APPEAL_MAX_TTL_SEC=259200
DIRECTORY_KEY_ROTATE_SEC=86400
ISSUER_URLS=${issuer_urls_csv}
ENTRY_LIVE_WG_MODE=1
WG_BACKEND=command
ENTRY_OPEN_RPS=12
ENTRY_BAN_THRESHOLD=3
ENTRY_BAN_SEC=90
ENTRY_MAX_CONCURRENT_OPENS=96
EXIT_WG_PRIVATE_KEY_PATH=${exit_wg_private_key_path}
EXIT_WG_PUBKEY=${exit_wg_pubkey}
EXIT_WG_INTERFACE=${exit_wg_interface}
EXIT_WG_AUTO_CREATE_INTERFACE=1
EXIT_WG_KERNEL_PROXY=1
EXIT_LIVE_WG_MODE=1
EXIT_OPAQUE_ECHO=0
EXIT_OPAQUE_SINK_ADDR=127.0.0.1:51982
EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:51983
EXIT_TOKEN_PROOF_REPLAY_GUARD=1
EXIT_PEER_REBIND_SEC=0
EXIT_STARTUP_SYNC_TIMEOUT_SEC=30
EXIT_ISSUER_MIN_SOURCES=2
EXIT_ISSUER_MIN_OPERATORS=2
EXIT_ISSUER_REQUIRE_ID=1
ENTRY_PUZZLE_DIFFICULTY=1
ENTRY_EXIT_USER=0:0
ENTRY_EXIT_PRIVILEGED=true
EASY_NODE_MTLS_CA_FILE_LOCAL=${DEPLOY_DIR}/tls/ca.crt
EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL=${DEPLOY_DIR}/tls/client.crt
EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL=${DEPLOY_DIR}/tls/client.key
EOF_PROD
  fi
  secure_file_permissions "$PROVIDER_ENV_FILE"
}

first_csv_item() {
  local csv="$1"
  IFS=',' read -r first _ <<<"$csv"
  echo "${first//[[:space:]]/}"
}

looks_like_loopback_url() {
  local u="$1"
  [[ "$u" == *"127.0.0.1"* || "$u" == *"localhost"* ]]
}

rewrite_loopback_url_for_docker() {
  local raw="$1"
  local docker_host="${2:-host.docker.internal}"
  local scheme="http"
  local hostport host port
  if [[ "$raw" == https://* ]]; then
    scheme="https"
  fi
  hostport="$(hostport_from_url "$raw")"
  host="$(host_from_hostport "$hostport")"
  host="${host#[}"
  host="${host%]}"
  if ! host_is_loopback "$host"; then
    echo "$raw"
    return
  fi
  if [[ "$hostport" == \[*\]:* ]]; then
    port="${hostport##*]:}"
  elif [[ "$hostport" == *:* ]]; then
    port="${hostport##*:}"
  else
    echo "$raw"
    return
  fi
  printf '%s://%s:%s' "$scheme" "$docker_host" "$port"
}

wg_only_port_list() {
  local base_port="${1:-}"
  if ! [[ "$base_port" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  printf '%s\n' \
    "$((base_port + 1))" \
    "$((base_port + 2))" \
    "$((base_port + 3))" \
    "$((base_port + 4))" \
    "$((base_port + 100))" \
    "$((base_port + 101))" \
    "$((base_port + 102))" \
    "$((base_port + 103))"
}

wg_only_listener_pids() {
  local port="${1:-}"
  local line remainder pid
  if [[ -z "$port" ]]; then
    return 0
  fi
  while IFS= read -r line; do
    remainder="$line"
    while [[ "$remainder" =~ pid=([0-9]+) ]]; do
      pid="${BASH_REMATCH[1]}"
      printf '%s\n' "$pid"
      remainder="${remainder#*pid=${pid}}"
    done
  done < <(ss -H -ltnup "( sport = :${port} )" 2>/dev/null || true)
}

wg_only_kill_stale_ports() {
  local -a ports=("$@")
  local -a pids=()
  local pid i alive
  if [[ "${EUID:-$(id -u)}" -ne 0 ]] || ((${#ports[@]} == 0)); then
    return 0
  fi
  mapfile -t pids < <(
    for port in "${ports[@]}"; do
      wg_only_listener_pids "$port"
    done | awk 'NF { if (!seen[$0]++) print $0 }'
  )
  if ((${#pids[@]} == 0)); then
    return 0
  fi
  kill "${pids[@]}" >/dev/null 2>&1 || true
  for i in $(seq 1 20); do
    alive="0"
    for pid in "${pids[@]}"; do
      if kill -0 "$pid" >/dev/null 2>&1; then
        alive="1"
        break
      fi
    done
    if [[ "$alive" == "0" ]]; then
      return 0
    fi
    sleep 0.2
  done
  kill -9 "${pids[@]}" >/dev/null 2>&1 || true
}

server_preflight() {
  local mode="${EASY_NODE_SERVER_MODE:-authority}"
  local public_host=""
  local operator_id=""
  local issuer_id=""
  local authority_directory="${EASY_NODE_AUTHORITY_DIRECTORY:-}"
  local authority_issuer="${EASY_NODE_AUTHORITY_ISSUER:-}"
  local peer_dirs=""
  local bootstrap_directory=""
  local beta_profile="${EASY_NODE_BETA_PROFILE:-0}"
  local prod_profile="${EASY_NODE_PROD_PROFILE:-0}"
  local peer_identity_strict="${EASY_NODE_PEER_IDENTITY_STRICT:-auto}"
  local min_peer_operators="${EASY_NODE_SERVER_PREFLIGHT_MIN_PEER_OPERATORS:-1}"
  local timeout_sec="${EASY_NODE_SERVER_PREFLIGHT_TIMEOUT_SEC:-8}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        mode="${2:-}"
        shift 2
        ;;
      --public-host)
        public_host="${2:-}"
        shift 2
        ;;
      --operator-id)
        operator_id="${2:-}"
        shift 2
        ;;
      --issuer-id)
        issuer_id="${2:-}"
        shift 2
        ;;
      --authority-directory)
        authority_directory="${2:-}"
        shift 2
        ;;
      --authority-issuer)
        authority_issuer="${2:-}"
        shift 2
        ;;
      --peer-directories)
        peer_dirs="${2:-}"
        shift 2
        ;;
      --bootstrap-directory)
        bootstrap_directory="${2:-}"
        shift 2
        ;;
      --peer-identity-strict)
        peer_identity_strict="${2:-}"
        shift 2
        ;;
      --min-peer-operators)
        min_peer_operators="${2:-}"
        shift 2
        ;;
      --timeout-sec)
        timeout_sec="${2:-}"
        shift 2
        ;;
      --beta-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          beta_profile="${2:-}"
          shift 2
        else
          beta_profile="1"
          shift
        fi
        ;;
      --prod-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          prod_profile="${2:-}"
          shift 2
        else
          prod_profile="1"
          shift
        fi
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for server-preflight: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$mode" != "authority" && "$mode" != "provider" ]]; then
    echo "server-preflight requires --mode authority|provider"
    exit 2
  fi
  if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
    echo "server-preflight requires --beta-profile to be 0 or 1"
    exit 2
  fi
  if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
    echo "server-preflight requires --prod-profile to be 0 or 1"
    exit 2
  fi
  if [[ "$prod_profile" == "1" ]]; then
    beta_profile="1"
  fi
  if [[ "$peer_identity_strict" != "0" && "$peer_identity_strict" != "1" && "$peer_identity_strict" != "auto" ]]; then
    echo "server-preflight requires --peer-identity-strict to be 0, 1, or auto"
    exit 2
  fi
  if ! [[ "$min_peer_operators" =~ ^[0-9]+$ ]] || ((min_peer_operators < 0)); then
    echo "server-preflight requires --min-peer-operators to be >= 0"
    exit 2
  fi
  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || ((timeout_sec < 2)); then
    echo "server-preflight requires --timeout-sec to be >= 2"
    exit 2
  fi

  local url_scheme="http"
  if [[ "$prod_profile" == "1" ]]; then
    url_scheme="https"
  fi

  if [[ -n "$bootstrap_directory" ]]; then
    bootstrap_directory="$(ensure_url_scheme "$bootstrap_directory" "$url_scheme")"
    if [[ -z "$peer_dirs" ]]; then
      peer_dirs="$bootstrap_directory"
    else
      peer_dirs="$(merge_url_csv "$peer_dirs" "$bootstrap_directory")"
    fi
    if [[ "$mode" == "provider" && -z "$authority_directory" ]]; then
      authority_directory="$bootstrap_directory"
    fi
  fi

  local local_host=""
  if [[ -n "$public_host" ]]; then
    local_host="$(host_from_hostport "$public_host")"
  else
    local_host="$(detect_local_host || true)"
  fi

  if [[ "$mode" == "provider" ]]; then
    local authority_directory_input="$authority_directory"
    local authority_issuer_input="$authority_issuer"
    if [[ -z "$authority_directory" && -n "$peer_dirs" ]]; then
      authority_directory="$(first_csv_item "$peer_dirs")"
    fi
    if [[ -z "$authority_directory" ]]; then
      echo "server-preflight --mode provider requires --authority-directory (or --bootstrap-directory)"
      exit 2
    fi
    authority_directory="$(ensure_url_scheme "$authority_directory" "$url_scheme")"
    local authority_host
    authority_host="$(host_from_url "$authority_directory")"
    if [[ -z "$authority_issuer" && -n "$authority_host" ]]; then
      authority_issuer="$(url_from_host_port "$authority_host" 8082)"
    fi
    if [[ -z "$authority_issuer" ]]; then
      echo "server-preflight --mode provider requires --authority-issuer URL"
      exit 2
    fi
    authority_issuer="$(ensure_url_scheme "$authority_issuer" "$url_scheme")"
    if [[ -z "$peer_dirs" ]]; then
      peer_dirs="$authority_directory"
    else
      peer_dirs="$(merge_url_csv "$peer_dirs" "$authority_directory")"
    fi
    if [[ "$prod_profile" == "1" ]]; then
      print_provider_prod_http_authority_hint "$authority_directory_input" "$authority_issuer_input" || true
    fi
  fi

  if [[ -n "$peer_dirs" ]]; then
    peer_dirs="$(normalize_url_csv_scheme_unique "$peer_dirs" "$url_scheme")"
    peer_dirs="$(filter_peer_dirs_excluding_host "$peer_dirs" "$local_host")"
  fi

  local peer_identity_strict_effective="$peer_identity_strict"
  if [[ "$peer_identity_strict_effective" == "auto" ]]; then
    if [[ -n "$peer_dirs" && ( "$beta_profile" == "1" || "$prod_profile" == "1" ) ]]; then
      peer_identity_strict_effective="1"
    else
      peer_identity_strict_effective="0"
    fi
  fi
  local issuer_identity_strict_effective="$peer_identity_strict_effective"
  if [[ "$peer_identity_strict" == "auto" && "$peer_identity_strict_effective" == "1" && "$prod_profile" != "1" && -n "$peer_dirs" ]]; then
    if ! peer_dirs_have_reachable_relays "$peer_dirs"; then
      peer_identity_strict_effective="0"
      issuer_identity_strict_effective="0"
      echo "note: peer operator/issuer identity strict checks auto-relaxed (non-prod bootstrap; peer directories currently unreachable)"
    fi
  fi
  if [[ "$mode" == "authority" && "$peer_identity_strict" == "auto" && "$peer_identity_strict_effective" == "1" && "$prod_profile" != "1" && -n "$peer_dirs" ]]; then
    if ! peer_dirs_have_reachable_issuer "$peer_dirs"; then
      issuer_identity_strict_effective="0"
      echo "note: peer issuer identity strict checks auto-relaxed (non-prod authority peering appears provider-only)"
    fi
  fi

  for cmd in curl jq rg; do
    need_cmd "$cmd" || exit 2
  done

  local identity_file stored_operator_id stored_issuer_id candidate_operator_id candidate_issuer_id
  identity_file="$(identity_config_file)"
  stored_operator_id="$(identity_value "$identity_file" "EASY_NODE_OPERATOR_ID")"
  stored_issuer_id="$(identity_value "$identity_file" "EASY_NODE_ISSUER_ID")"
  candidate_operator_id="${operator_id:-$stored_operator_id}"
  candidate_issuer_id="${issuer_id:-$stored_issuer_id}"

  local failures=0
  local warnings=0
  local peer_count=0
  declare -A peer_ops_seen=()
  declare -A peer_issuer_seen=()

  echo "server preflight started"
  echo "mode: $mode"
  echo "prod_profile: $prod_profile beta_profile: $beta_profile"
  echo "peer_identity_strict: $peer_identity_strict_effective (configured=$peer_identity_strict)"
  echo "timeout_sec: $timeout_sec"
  if [[ -n "$peer_dirs" ]]; then
    echo "peer_directories: $peer_dirs"
  else
    echo "peer_directories: [none]"
  fi
  if [[ "$mode" == "provider" ]]; then
    echo "authority_directory: $authority_directory"
    echo "authority_issuer: $authority_issuer"
  fi

  if [[ -n "$peer_dirs" ]]; then
    local peer_url peer_payload peer_ops peer_op_count peer_host peer_issuer_url peer_issuer_id
    local peer_fetch_fail=0
    local peer_parse_fail=0
    while IFS= read -r peer_url; do
      [[ -z "$peer_url" ]] && continue
      peer_count=$((peer_count + 1))
      local -a peer_tls_opts
      mapfile -t peer_tls_opts < <(curl_tls_opts_for_url "$peer_url")
      peer_payload="$(curl -fsS --connect-timeout 2 --max-time "$timeout_sec" "${peer_tls_opts[@]}" "$(trim_url "$peer_url")/v1/relays" 2>/dev/null || true)"
      if [[ -z "$peer_payload" ]]; then
        echo "[peer] fail: ${peer_url}/v1/relays unreachable"
        if [[ "$prod_profile" == "1" ]]; then
          print_prod_https_mismatch_hint_for_endpoint "$(trim_url "$peer_url")/v1/relays" "peer directory ${peer_url}" "$timeout_sec" || true
        fi
        peer_fetch_fail=$((peer_fetch_fail + 1))
        continue
      fi
      if ! peer_ops="$(printf '%s\n' "$peer_payload" | jq -r '.relays[]? | ((.operator_id // .operator // .origin_operator // "") | tostring)' 2>/dev/null)"; then
        echo "[peer] fail: ${peer_url}/v1/relays payload parse failed"
        peer_parse_fail=$((peer_parse_fail + 1))
        continue
      fi
      peer_op_count="$(printf '%s\n' "$peer_ops" | awk 'NF > 0' | sort -u | wc -l | tr -d ' ')"
      echo "[peer] ok: ${peer_url} operators=${peer_op_count}"
      while IFS= read -r op; do
        [[ -z "$op" ]] && continue
        peer_ops_seen["$op"]=1
      done < <(printf '%s\n' "$peer_ops" | awk 'NF > 0')

      peer_host="$(host_from_url "$peer_url")"
      if [[ -n "$peer_host" ]]; then
        peer_issuer_url="$(url_from_host_port "$peer_host" 8082)"
        local -a issuer_tls_opts
        mapfile -t issuer_tls_opts < <(curl_tls_opts_for_url "$peer_issuer_url")
        peer_issuer_id="$(curl -fsS --connect-timeout 2 --max-time "$timeout_sec" "${issuer_tls_opts[@]}" "$(trim_url "$peer_issuer_url")/v1/pubkeys" 2>/dev/null | jq -r '(.issuer // "") | tostring' 2>/dev/null || true)"
        if [[ -n "$peer_issuer_id" && "$peer_issuer_id" != "null" ]]; then
          peer_issuer_seen["$peer_issuer_id"]=1
        fi
      fi
    done < <(split_csv_lines "$peer_dirs")

    local peer_distinct_ops="${#peer_ops_seen[@]}"
    echo "[peer] summary: peers=$peer_count distinct_operators=$peer_distinct_ops"
    if ((peer_distinct_ops < min_peer_operators)); then
      echo "[peer] fail: distinct operator floor not met (required=${min_peer_operators}, got=${peer_distinct_ops})"
      failures=$((failures + 1))
    fi
    if ((peer_fetch_fail > 0 || peer_parse_fail > 0)); then
      if [[ "$peer_identity_strict_effective" == "1" ]]; then
        echo "[peer] fail: peer directory verification incomplete (fetch_fail=${peer_fetch_fail}, parse_fail=${peer_parse_fail})"
        failures=$((failures + 1))
      else
        echo "[peer] warning: peer directory verification incomplete (fetch_fail=${peer_fetch_fail}, parse_fail=${peer_parse_fail})"
        warnings=$((warnings + 1))
      fi
    fi
  fi

  if [[ "$mode" == "provider" ]]; then
    local -a authority_tls_opts
    mapfile -t authority_tls_opts < <(curl_tls_opts_for_url "$authority_issuer")
    local authority_payload authority_issuer_id authority_key_count
    authority_payload="$(curl -fsS --connect-timeout 2 --max-time "$timeout_sec" "${authority_tls_opts[@]}" "$(trim_url "$authority_issuer")/v1/pubkeys" 2>/dev/null || true)"
    if [[ -z "$authority_payload" ]]; then
      echo "[issuer] fail: authority issuer unreachable: ${authority_issuer}/v1/pubkeys"
      if [[ "$prod_profile" == "1" ]]; then
        print_prod_https_mismatch_hint_for_endpoint "$(trim_url "$authority_issuer")/v1/pubkeys" "authority issuer ${authority_issuer}" "$timeout_sec" || true
      fi
      failures=$((failures + 1))
    elif ! authority_issuer_id="$(printf '%s\n' "$authority_payload" | jq -r '(.issuer // "") | tostring' 2>/dev/null)"; then
      echo "[issuer] fail: authority issuer payload parse failed"
      failures=$((failures + 1))
    else
      authority_key_count="$(printf '%s\n' "$authority_payload" | jq -r '((.pub_keys // []) | length)' 2>/dev/null || echo "0")"
      if ! [[ "$authority_key_count" =~ ^[0-9]+$ ]] || ((authority_key_count < 1)); then
        echo "[issuer] fail: authority issuer has no active pubkeys"
        failures=$((failures + 1))
      else
        if [[ "$authority_issuer_id" == "null" ]]; then
          authority_issuer_id=""
        fi
        echo "[issuer] ok: authority_issuer_id=${authority_issuer_id:-unknown} pub_keys=${authority_key_count}"
      fi
    fi
  fi

  if [[ "$mode" == "authority" && "$prod_profile" == "1" && -n "$peer_dirs" ]]; then
    local peer_issuer_count="${#peer_issuer_seen[@]}"
    echo "[issuer] peer issuer ids observed: ${peer_issuer_count}"
    if ((peer_issuer_count < 1)); then
      echo "[issuer] fail: prod profile requires at least one reachable peer issuer id (self + peer => quorum of 2 issuer URLs)"
      print_prod_https_mismatch_hint_for_peer_issuers "$peer_dirs" "$timeout_sec" || true
      failures=$((failures + 1))
    fi
  fi

  if [[ -n "$peer_dirs" && -n "$candidate_operator_id" ]]; then
    local op_rc=0
    if operator_id_conflicts_with_peers "$candidate_operator_id" "$peer_dirs" "$local_host"; then
      op_rc=0
    else
      op_rc=$?
    fi
    if [[ "$op_rc" == "0" ]]; then
      echo "[identity] fail: operator_id collision with peers: $candidate_operator_id"
      failures=$((failures + 1))
    elif [[ "$op_rc" == "2" ]]; then
      if [[ "$peer_identity_strict_effective" == "1" ]]; then
        echo "[identity] fail: could not verify operator_id collision status against peers"
        failures=$((failures + 1))
      else
        echo "[identity] warning: operator_id collision status unknown (peer verify incomplete)"
        warnings=$((warnings + 1))
      fi
    else
      echo "[identity] ok: operator_id candidate clear: $candidate_operator_id"
    fi
  elif [[ -n "$peer_dirs" ]]; then
    echo "[identity] note: operator_id not provided/stored; collision check skipped"
  fi

  if [[ "$mode" == "authority" && -n "$peer_dirs" && -n "$candidate_issuer_id" ]]; then
    local issuer_rc=0
    if issuer_id_conflicts_with_peers "$candidate_issuer_id" "$peer_dirs"; then
      issuer_rc=0
    else
      issuer_rc=$?
    fi
    if [[ "$issuer_rc" == "0" ]]; then
      echo "[identity] fail: issuer_id collision with peers: $candidate_issuer_id"
      failures=$((failures + 1))
    elif [[ "$issuer_rc" == "2" ]]; then
      if [[ "$issuer_identity_strict_effective" == "1" ]]; then
        echo "[identity] fail: could not verify issuer_id collision status against peers"
        failures=$((failures + 1))
      else
        echo "[identity] warning: issuer_id collision status unknown (peer verify incomplete)"
        warnings=$((warnings + 1))
      fi
    else
      echo "[identity] ok: issuer_id candidate clear: $candidate_issuer_id"
    fi
  elif [[ "$mode" == "authority" && -n "$peer_dirs" ]]; then
    echo "[identity] note: issuer_id not provided/stored; collision check skipped"
  fi

  if ((failures > 0)); then
    echo "server preflight: FAILED (failures=${failures}, warnings=${warnings})"
    return 1
  fi
  echo "server preflight: ok (warnings=${warnings})"
}

server_up() {
  local mode="${EASY_NODE_SERVER_MODE:-authority}"
  local public_host=""
  local operator_id=""
  local operator_id_explicit="0"
  local issuer_id=""
  local issuer_id_explicit="0"
  local issuer_admin_token=""
  local issuer_admin_token_explicit="0"
  local directory_admin_token="${EASY_NODE_DIRECTORY_ADMIN_TOKEN:-}"
  local entry_puzzle_secret="${EASY_NODE_ENTRY_PUZZLE_SECRET:-}"
  local peer_dirs=""
  local bootstrap_directory=""
  local authority_directory="${EASY_NODE_AUTHORITY_DIRECTORY:-}"
  local authority_issuer="${EASY_NODE_AUTHORITY_ISSUER:-}"
  local peer_identity_strict="${EASY_NODE_PEER_IDENTITY_STRICT:-auto}"
  local client_allowlist="${EASY_NODE_CLIENT_ALLOWLIST_ONLY:-0}"
  local client_allowlist_explicit="0"
  local allow_anon_cred="${EASY_NODE_ALLOW_ANON_CRED:-1}"
  local allow_anon_cred_explicit="0"
  local beta_profile="${EASY_NODE_BETA_PROFILE:-0}"
  local prod_profile="${EASY_NODE_PROD_PROFILE:-0}"
  local show_admin_token="${EASY_NODE_SHOW_ADMIN_TOKEN:-0}"
  local federation_wait="${EASY_NODE_FEDERATION_WAIT:-0}"
  local federation_ready_timeout_sec="${EASY_NODE_FEDERATION_READY_TIMEOUT_SEC:-90}"
  local federation_poll_sec="${EASY_NODE_FEDERATION_POLL_SEC:-5}"
  local federation_require_configured_healthy="${EASY_NODE_FEDERATION_REQUIRE_CONFIGURED_HEALTHY:-0}"
  local federation_max_cooling_retry_sec="${EASY_NODE_FEDERATION_MAX_COOLING_RETRY_SEC:-0}"
  local federation_max_peer_sync_age_sec="${EASY_NODE_FEDERATION_MAX_PEER_SYNC_AGE_SEC:-0}"
  local federation_max_issuer_sync_age_sec="${EASY_NODE_FEDERATION_MAX_ISSUER_SYNC_AGE_SEC:-0}"
  local federation_min_peer_success_sources="${EASY_NODE_FEDERATION_MIN_PEER_SUCCESS_SOURCES:-0}"
  local federation_min_issuer_success_sources="${EASY_NODE_FEDERATION_MIN_ISSUER_SUCCESS_SOURCES:-0}"
  local federation_min_peer_source_operators="${EASY_NODE_FEDERATION_MIN_PEER_SOURCE_OPERATORS:-0}"
  local federation_min_issuer_source_operators="${EASY_NODE_FEDERATION_MIN_ISSUER_SOURCE_OPERATORS:-0}"
  local federation_wait_summary_json=""
  local federation_wait_print_summary_json="${EASY_NODE_FEDERATION_WAIT_PRINT_SUMMARY_JSON:-0}"
  local auto_invite="${EASY_NODE_AUTO_INVITE:-0}"
  local auto_invite_count="${EASY_NODE_AUTO_INVITE_COUNT:-1}"
  local auto_invite_tier="${EASY_NODE_AUTO_INVITE_TIER:-1}"
  local auto_invite_wait_sec="${EASY_NODE_AUTO_INVITE_WAIT_SEC:-10}"
  local auto_invite_fail_open="${EASY_NODE_AUTO_INVITE_FAIL_OPEN:-1}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        mode="${2:-}"
        shift 2
        ;;
      --public-host)
        public_host="${2:-}"
        shift 2
        ;;
      --operator-id)
        operator_id="${2:-}"
        operator_id_explicit="1"
        shift 2
        ;;
      --issuer-id)
        issuer_id="${2:-}"
        issuer_id_explicit="1"
        shift 2
        ;;
      --issuer-admin-token)
        issuer_admin_token="${2:-}"
        issuer_admin_token_explicit="1"
        shift 2
        ;;
      --directory-admin-token)
        directory_admin_token="${2:-}"
        shift 2
        ;;
      --entry-puzzle-secret)
        entry_puzzle_secret="${2:-}"
        shift 2
        ;;
      --authority-directory)
        authority_directory="${2:-}"
        shift 2
        ;;
      --authority-issuer)
        authority_issuer="${2:-}"
        shift 2
        ;;
      --peer-directories)
        peer_dirs="${2:-}"
        shift 2
        ;;
      --bootstrap-directory)
        bootstrap_directory="${2:-}"
        shift 2
        ;;
      --peer-identity-strict)
        peer_identity_strict="${2:-}"
        shift 2
        ;;
      --client-allowlist)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          client_allowlist="${2:-}"
          client_allowlist_explicit="1"
          shift 2
        else
          client_allowlist="1"
          client_allowlist_explicit="1"
          shift
        fi
        ;;
      --allow-anon-cred)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          allow_anon_cred="${2:-}"
          allow_anon_cred_explicit="1"
          shift 2
        else
          allow_anon_cred="0"
          allow_anon_cred_explicit="1"
          shift
        fi
        ;;
      --beta-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          beta_profile="${2:-}"
          shift 2
        else
          beta_profile="1"
          shift
        fi
        ;;
      --prod-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          prod_profile="${2:-}"
          shift 2
        else
          prod_profile="1"
          shift
        fi
        ;;
      --show-admin-token)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          show_admin_token="${2:-}"
          shift 2
        else
          show_admin_token="1"
          shift
        fi
        ;;
      --federation-wait)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          federation_wait="${2:-}"
          shift 2
        else
          federation_wait="1"
          shift
        fi
        ;;
      --federation-ready-timeout-sec)
        federation_ready_timeout_sec="${2:-}"
        shift 2
        ;;
      --federation-poll-sec)
        federation_poll_sec="${2:-}"
        shift 2
        ;;
      --federation-require-configured-healthy)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          federation_require_configured_healthy="${2:-}"
          shift 2
        else
          federation_require_configured_healthy="1"
          shift
        fi
        ;;
      --federation-max-cooling-retry-sec)
        federation_max_cooling_retry_sec="${2:-}"
        shift 2
        ;;
      --federation-max-peer-sync-age-sec)
        federation_max_peer_sync_age_sec="${2:-}"
        shift 2
        ;;
      --federation-max-issuer-sync-age-sec)
        federation_max_issuer_sync_age_sec="${2:-}"
        shift 2
        ;;
      --federation-min-peer-success-sources)
        federation_min_peer_success_sources="${2:-}"
        shift 2
        ;;
      --federation-min-issuer-success-sources)
        federation_min_issuer_success_sources="${2:-}"
        shift 2
        ;;
      --federation-min-peer-source-operators)
        federation_min_peer_source_operators="${2:-}"
        shift 2
        ;;
      --federation-min-issuer-source-operators)
        federation_min_issuer_source_operators="${2:-}"
        shift 2
        ;;
      --federation-wait-summary-json)
        federation_wait_summary_json="${2:-}"
        shift 2
        ;;
      --federation-wait-print-summary-json)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          federation_wait_print_summary_json="${2:-}"
          shift 2
        else
          federation_wait_print_summary_json="1"
          shift
        fi
        ;;
      --auto-invite)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          auto_invite="${2:-}"
          shift 2
        else
          auto_invite="1"
          shift
        fi
        ;;
      --auto-invite-count)
        auto_invite_count="${2:-}"
        shift 2
        ;;
      --auto-invite-tier)
        auto_invite_tier="${2:-}"
        shift 2
        ;;
      --auto-invite-wait-sec)
        auto_invite_wait_sec="${2:-}"
        shift 2
        ;;
      --auto-invite-fail-open)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          auto_invite_fail_open="${2:-}"
          shift 2
        else
          auto_invite_fail_open="1"
          shift
        fi
        ;;
      *)
        echo "unknown arg for server-up: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$mode" != "authority" && "$mode" != "provider" ]]; then
    echo "server-up requires --mode authority|provider"
    exit 2
  fi
  if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
    echo "server-up requires --beta-profile (or EASY_NODE_BETA_PROFILE) to be 0 or 1"
    exit 2
  fi
  if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
    echo "server-up requires --prod-profile (or EASY_NODE_PROD_PROFILE) to be 0 or 1"
    exit 2
  fi
  if [[ "$prod_profile" == "1" ]]; then
    beta_profile="1"
  fi
  if [[ "$show_admin_token" != "0" && "$show_admin_token" != "1" ]]; then
    echo "server-up requires --show-admin-token (or EASY_NODE_SHOW_ADMIN_TOKEN) to be 0 or 1"
    exit 2
  fi
  if [[ "$federation_wait" != "0" && "$federation_wait" != "1" ]]; then
    echo "server-up requires --federation-wait (or EASY_NODE_FEDERATION_WAIT) to be 0 or 1"
    exit 2
  fi
  if [[ "$federation_wait_print_summary_json" != "0" && "$federation_wait_print_summary_json" != "1" ]]; then
    echo "server-up requires --federation-wait-print-summary-json (or EASY_NODE_FEDERATION_WAIT_PRINT_SUMMARY_JSON) to be 0 or 1"
    exit 2
  fi
  if [[ "$auto_invite" != "0" && "$auto_invite" != "1" ]]; then
    echo "server-up requires --auto-invite (or EASY_NODE_AUTO_INVITE) to be 0 or 1"
    exit 2
  fi
  if [[ "$auto_invite_fail_open" != "0" && "$auto_invite_fail_open" != "1" ]]; then
    echo "server-up requires --auto-invite-fail-open (or EASY_NODE_AUTO_INVITE_FAIL_OPEN) to be 0 or 1"
    exit 2
  fi
  if ! [[ "$auto_invite_count" =~ ^[0-9]+$ ]] || ((auto_invite_count < 1)); then
    echo "server-up requires --auto-invite-count (or EASY_NODE_AUTO_INVITE_COUNT) to be >= 1"
    exit 2
  fi
  if [[ "$auto_invite_tier" != "1" && "$auto_invite_tier" != "2" && "$auto_invite_tier" != "3" ]]; then
    echo "server-up requires --auto-invite-tier (or EASY_NODE_AUTO_INVITE_TIER) to be 1, 2, or 3"
    exit 2
  fi
  if ! [[ "$auto_invite_wait_sec" =~ ^[0-9]+$ ]]; then
    echo "server-up requires --auto-invite-wait-sec (or EASY_NODE_AUTO_INVITE_WAIT_SEC) to be >= 0"
    exit 2
  fi
  if ! [[ "$federation_ready_timeout_sec" =~ ^[0-9]+$ ]] || ((federation_ready_timeout_sec < 1)); then
    echo "server-up requires --federation-ready-timeout-sec (or EASY_NODE_FEDERATION_READY_TIMEOUT_SEC) to be >= 1"
    exit 2
  fi
  if ! [[ "$federation_poll_sec" =~ ^[0-9]+$ ]] || ((federation_poll_sec < 1)); then
    echo "server-up requires --federation-poll-sec (or EASY_NODE_FEDERATION_POLL_SEC) to be >= 1"
    exit 2
  fi
  if [[ "$federation_require_configured_healthy" != "0" && "$federation_require_configured_healthy" != "1" ]]; then
    echo "server-up requires --federation-require-configured-healthy (or EASY_NODE_FEDERATION_REQUIRE_CONFIGURED_HEALTHY) to be 0 or 1"
    exit 2
  fi
  if ! [[ "$federation_max_cooling_retry_sec" =~ ^[0-9]+$ ]]; then
    echo "server-up requires --federation-max-cooling-retry-sec (or EASY_NODE_FEDERATION_MAX_COOLING_RETRY_SEC) to be >= 0"
    exit 2
  fi
  if ! [[ "$federation_max_peer_sync_age_sec" =~ ^[0-9]+$ ]]; then
    echo "server-up requires --federation-max-peer-sync-age-sec (or EASY_NODE_FEDERATION_MAX_PEER_SYNC_AGE_SEC) to be >= 0"
    exit 2
  fi
  if ! [[ "$federation_max_issuer_sync_age_sec" =~ ^[0-9]+$ ]]; then
    echo "server-up requires --federation-max-issuer-sync-age-sec (or EASY_NODE_FEDERATION_MAX_ISSUER_SYNC_AGE_SEC) to be >= 0"
    exit 2
  fi
  if ! [[ "$federation_min_peer_success_sources" =~ ^[0-9]+$ ]]; then
    echo "server-up requires --federation-min-peer-success-sources (or EASY_NODE_FEDERATION_MIN_PEER_SUCCESS_SOURCES) to be >= 0"
    exit 2
  fi
  if ! [[ "$federation_min_issuer_success_sources" =~ ^[0-9]+$ ]]; then
    echo "server-up requires --federation-min-issuer-success-sources (or EASY_NODE_FEDERATION_MIN_ISSUER_SUCCESS_SOURCES) to be >= 0"
    exit 2
  fi
  if ! [[ "$federation_min_peer_source_operators" =~ ^[0-9]+$ ]]; then
    echo "server-up requires --federation-min-peer-source-operators (or EASY_NODE_FEDERATION_MIN_PEER_SOURCE_OPERATORS) to be >= 0"
    exit 2
  fi
  if ! [[ "$federation_min_issuer_source_operators" =~ ^[0-9]+$ ]]; then
    echo "server-up requires --federation-min-issuer-source-operators (or EASY_NODE_FEDERATION_MIN_ISSUER_SOURCE_OPERATORS) to be >= 0"
    exit 2
  fi
  if [[ "$client_allowlist" != "0" && "$client_allowlist" != "1" ]]; then
    echo "server-up requires --client-allowlist (or EASY_NODE_CLIENT_ALLOWLIST_ONLY) to be 0 or 1"
    exit 2
  fi
  if [[ "$allow_anon_cred" != "0" && "$allow_anon_cred" != "1" ]]; then
    echo "server-up requires --allow-anon-cred (or EASY_NODE_ALLOW_ANON_CRED) to be 0 or 1"
    exit 2
  fi
  if [[ "$peer_identity_strict" != "0" && "$peer_identity_strict" != "1" && "$peer_identity_strict" != "auto" ]]; then
    echo "server-up requires --peer-identity-strict (or EASY_NODE_PEER_IDENTITY_STRICT) to be 0, 1, or auto"
    exit 2
  fi

  clear_runtime_override_env_vars

  local url_scheme="http"
  if [[ "$prod_profile" == "1" ]]; then
    url_scheme="https"
  fi

  if [[ -n "$bootstrap_directory" ]]; then
    bootstrap_directory="$(ensure_url_scheme "$bootstrap_directory" "$url_scheme")"
    if [[ -z "$peer_dirs" ]]; then
      peer_dirs="$bootstrap_directory"
    else
      peer_dirs="$(merge_url_csv "$peer_dirs" "$bootstrap_directory")"
    fi
    if [[ "$mode" == "provider" && -z "$authority_directory" ]]; then
      authority_directory="$bootstrap_directory"
    fi
  fi

  if [[ -z "$public_host" ]]; then
    public_host="$(detect_local_host || true)"
    if [[ -n "$public_host" ]]; then
      echo "server-up auto-detected public host: $public_host"
    else
      echo "server-up requires --public-host (or a detectable local host)"
      exit 2
    fi
  fi

  local local_host
  local_host="$(host_from_hostport "$public_host")"
  if [[ "$mode" == "provider" ]]; then
    if [[ -z "$authority_directory" && -n "$peer_dirs" ]]; then
      authority_directory="$(first_csv_item "$peer_dirs")"
    fi
    if [[ -z "$authority_directory" ]]; then
      echo "server-up --mode provider requires --authority-directory (or --bootstrap-directory)"
      exit 2
    fi
    authority_directory="$(ensure_url_scheme "$authority_directory" "$url_scheme")"
    local authority_host
    authority_host="$(host_from_url "$authority_directory")"
    if [[ -z "$authority_issuer" && -n "$authority_host" ]]; then
      authority_issuer="$(url_from_host_port "$authority_host" 8082)"
    fi
    if [[ -z "$authority_issuer" ]]; then
      echo "server-up --mode provider requires --authority-issuer URL"
      exit 2
    fi
    authority_issuer="$(ensure_url_scheme "$authority_issuer" "$url_scheme")"
    if [[ -z "$peer_dirs" ]]; then
      peer_dirs="$authority_directory"
    else
      peer_dirs="$(merge_url_csv "$peer_dirs" "$authority_directory")"
    fi
    if [[ "$issuer_admin_token_explicit" == "1" ]]; then
      echo "note: --issuer-admin-token is ignored in provider mode (no local issuer/admin)."
    fi
    if [[ "$issuer_id_explicit" == "1" ]]; then
      echo "note: --issuer-id is ignored in provider mode."
    fi
    if [[ "$client_allowlist_explicit" == "1" || "$allow_anon_cred_explicit" == "1" ]]; then
      echo "note: --client-allowlist/--allow-anon-cred are issuer settings and are ignored in provider mode."
    fi
    if [[ "$auto_invite" == "1" ]]; then
      echo "note: --auto-invite is authority-only and is ignored in provider mode."
      auto_invite="0"
    fi
  fi

  if [[ -n "$peer_dirs" ]]; then
    peer_dirs="$(normalize_url_csv_scheme_unique "$peer_dirs" "$url_scheme")"
  fi

  if [[ -n "$peer_dirs" ]]; then
    peer_dirs="$(filter_peer_dirs_excluding_host "$peer_dirs" "$local_host")"
  fi

  local peer_identity_strict_effective="$peer_identity_strict"
  if [[ "$peer_identity_strict_effective" == "auto" ]]; then
    if [[ -n "$peer_dirs" && ( "$beta_profile" == "1" || "$prod_profile" == "1" ) ]]; then
      peer_identity_strict_effective="1"
    else
      peer_identity_strict_effective="0"
    fi
  fi
  local issuer_identity_strict_effective="$peer_identity_strict_effective"
  if [[ "$peer_identity_strict" == "auto" && "$peer_identity_strict_effective" == "1" && "$prod_profile" != "1" && -n "$peer_dirs" ]]; then
    if ! peer_dirs_have_reachable_relays "$peer_dirs"; then
      peer_identity_strict_effective="0"
      issuer_identity_strict_effective="0"
      echo "note: peer operator/issuer identity strict checks auto-relaxed (non-prod bootstrap; peer directories currently unreachable)"
    fi
  fi
  if [[ "$mode" == "authority" && "$peer_identity_strict" == "auto" && "$peer_identity_strict_effective" == "1" && "$prod_profile" != "1" && -n "$peer_dirs" ]]; then
    if ! peer_dirs_have_reachable_issuer "$peer_dirs"; then
      issuer_identity_strict_effective="0"
      echo "note: peer issuer identity strict checks auto-relaxed (non-prod authority peering appears provider-only)"
    fi
  fi

  ensure_server_up_deps_or_die "$mode" "$prod_profile" "$peer_dirs" "$bootstrap_directory" "$beta_profile"

  if [[ -z "$directory_admin_token" ]]; then
    directory_admin_token="$(random_token)"
  fi
  if [[ -z "$entry_puzzle_secret" ]]; then
    entry_puzzle_secret="$(random_token)"
  fi
  if [[ "$prod_profile" == "1" ]]; then
    if [[ "$directory_admin_token" == "dev-admin-token" || "${#directory_admin_token}" -lt 16 ]]; then
      echo "server-up requires a strong DIRECTORY_ADMIN_TOKEN in prod profile (len>=16, non-default)"
      exit 2
    fi
    if [[ "$entry_puzzle_secret" == "entry-secret-default" || "${#entry_puzzle_secret}" -lt 16 ]]; then
      echo "server-up requires a strong ENTRY_PUZZLE_SECRET in prod profile (len>=16, non-default)"
      exit 2
    fi
  fi

  local identity_file
  local stored_operator_id
  local stored_issuer_id
  identity_file="$(identity_config_file)"
  stored_operator_id="$(identity_value "$identity_file" "EASY_NODE_OPERATOR_ID")"
  stored_issuer_id="$(identity_value "$identity_file" "EASY_NODE_ISSUER_ID")"

  if [[ -z "$operator_id" ]]; then
    if [[ -n "$stored_operator_id" ]]; then
      operator_id="$stored_operator_id"
    else
      operator_id="op-$(random_id_suffix)"
    fi
  fi

  if [[ "$mode" == "authority" ]]; then
    if [[ -z "$issuer_id" ]]; then
      if [[ -n "$stored_issuer_id" ]]; then
        issuer_id="$stored_issuer_id"
      else
        issuer_id="issuer-$(random_id_suffix)"
      fi
    fi
    if [[ -z "$issuer_admin_token" ]]; then
      issuer_admin_token="$(random_token)"
    fi
  else
    issuer_id="${stored_issuer_id:-}"
  fi

  local admin_sign_key_file_local=""
  local admin_sign_key_id=""
  local admin_signers_file_local=""
  local admin_signers_file_container=""
  if [[ "$prod_profile" == "1" ]]; then
    local -a mtls_args
    mtls_args=(--out-dir "$DEPLOY_DIR/tls")
    if [[ -n "$local_host" ]]; then
      mtls_args+=(--public-host "$local_host")
    fi
    if [[ -n "$public_host" && "$public_host" != "$local_host" ]]; then
      mtls_args+=(--san "$public_host")
    fi
    if [[ -n "$peer_dirs" ]]; then
      local peer_url peer_host
      while IFS= read -r peer_url; do
        [[ -z "$peer_url" ]] && continue
        peer_host="$(host_from_url "$peer_url")"
        if [[ -n "$peer_host" ]]; then
          mtls_args+=(--san "$peer_host")
        fi
      done < <(split_csv_lines "$peer_dirs")
    fi
    if [[ "$mode" == "provider" && -n "$authority_directory" ]]; then
      local authority_host
      authority_host="$(host_from_url "$authority_directory")"
      if [[ -n "$authority_host" ]]; then
        mtls_args+=(--san "$authority_host")
      fi
    fi
    bootstrap_mtls "${mtls_args[@]}"
    if [[ "$mode" == "authority" ]]; then
      local signer_material
      signer_material="$(ensure_admin_signing_material)"
      IFS='|' read -r admin_sign_key_file_local admin_sign_key_id admin_signers_file_local admin_signers_file_container <<<"$signer_material"
      if [[ -z "$admin_sign_key_file_local" || -z "$admin_sign_key_id" || -z "$admin_signers_file_container" ]]; then
        echo "server-up failed to initialize issuer admin signing material"
        exit 1
      fi
    fi
  fi

  if [[ -n "$peer_dirs" ]]; then
    local operator_attempts=0
    while true; do
      local op_check_rc=0
      if operator_id_conflicts_with_peers "$operator_id" "$peer_dirs" "$local_host"; then
        op_check_rc=0
      else
        op_check_rc=$?
      fi
      if [[ "$op_check_rc" == "0" ]]; then
        if [[ "$operator_id_explicit" == "1" ]]; then
          echo "server-up refused: --operator-id '$operator_id' already exists on peer directories."
          echo "choose a unique operator id or omit --operator-id for automatic unique generation."
          exit 2
        fi
        operator_id="op-$(random_id_suffix)"
        operator_attempts=$((operator_attempts + 1))
        if ((operator_attempts >= 8)); then
          echo "server-up could not generate a unique operator id after ${operator_attempts} attempts."
          exit 1
        fi
        continue
      fi
      if [[ "$op_check_rc" == "2" ]]; then
        if [[ "$peer_identity_strict_effective" == "1" ]]; then
          echo "server-up refused: could not verify operator-id uniqueness against peer directories."
          if [[ "$prod_profile" == "1" ]]; then
            print_prod_https_mismatch_hint_for_peer_relays "$peer_dirs" 4 || true
          fi
          echo "check peer directory reachability and mTLS trust/certs, then retry."
          echo "temporary bypass (diagnostics only): --peer-identity-strict 0"
          exit 2
        fi
        echo "warning: operator-id uniqueness check skipped (peer directory unavailable/unparseable)."
      fi
      break
    done
  fi

  if [[ "$mode" == "authority" && -n "$peer_dirs" ]]; then
    local issuer_attempts=0
    while true; do
      local issuer_check_rc=0
      if issuer_id_conflicts_with_peers "$issuer_id" "$peer_dirs"; then
        issuer_check_rc=0
      else
        issuer_check_rc=$?
      fi
      if [[ "$issuer_check_rc" == "0" ]]; then
        if [[ "$issuer_id_explicit" == "1" ]]; then
          echo "server-up refused: --issuer-id '$issuer_id' already exists on peer directories."
          echo "choose a unique issuer id or omit --issuer-id for automatic unique generation."
          exit 2
        fi
        issuer_id="issuer-$(random_id_suffix)"
        issuer_attempts=$((issuer_attempts + 1))
        if ((issuer_attempts >= 8)); then
          echo "server-up could not generate a unique issuer id after ${issuer_attempts} attempts."
          exit 1
        fi
        continue
      fi
      if [[ "$issuer_check_rc" == "2" ]]; then
        if [[ "$issuer_identity_strict_effective" == "1" ]]; then
          echo "server-up refused: could not verify issuer-id uniqueness against peer directories."
          if [[ "$prod_profile" == "1" ]]; then
            print_prod_https_mismatch_hint_for_peer_issuers "$peer_dirs" 4 || true
          fi
          echo "check peer issuer reachability and mTLS trust/certs, then retry."
          echo "temporary bypass (diagnostics only): --peer-identity-strict 0"
          exit 2
        fi
        echo "warning: issuer-id uniqueness check skipped (peer issuer unavailable/unparseable)."
      fi
      break
    done
  fi

  local issuer_urls_csv=""
  local issuer_urls_count=0
  local exit_wg_interface=""
  local exit_wg_private_key_local=""
  local exit_wg_private_key_container=""
  local exit_wg_pubkey=""
  local need_beta_or_prod_wg_defaults="0"
  if [[ "$beta_profile" == "1" || "$prod_profile" == "1" ]]; then
    need_beta_or_prod_wg_defaults="1"
  fi
  if [[ "$prod_profile" == "1" ]]; then
    local base_issuer_url
    if [[ "$mode" == "authority" ]]; then
      base_issuer_url="$(url_from_host_port "$public_host" 8082)"
    else
      base_issuer_url="$authority_issuer"
    fi
    issuer_urls_csv="$(build_issuer_urls_csv "$base_issuer_url" "$peer_dirs" "$url_scheme")"
    issuer_urls_count="$(csv_count "$issuer_urls_csv")"
    if ((issuer_urls_count < 2)); then
      echo "server-up --prod-profile requires at least 2 issuer URLs for strict quorum."
      echo "current issuer URLs (${issuer_urls_count}): ${issuer_urls_csv:-none}"
      echo "add at least one peer directory from a distinct authority/issuer operator."
      exit 2
    fi
  fi
  if [[ "$need_beta_or_prod_wg_defaults" == "1" ]]; then
    local relay_suffix_for_wg
    local exit_wg_key_prepared="0"
    relay_suffix_for_wg="$(sanitize_id_component "$operator_id")"
    exit_wg_interface="$(safe_wg_iface_name "$relay_suffix_for_wg")"
    exit_wg_private_key_local="$DEPLOY_DIR/data/entry-exit/exit_${relay_suffix_for_wg}_wg.key"
    exit_wg_private_key_container="/app/data/$(basename "$exit_wg_private_key_local")"
    mkdir -p "$(dirname "$exit_wg_private_key_local")"
    if [[ -f "$exit_wg_private_key_local" && -r "$exit_wg_private_key_local" ]]; then
      exit_wg_key_prepared="1"
    elif [[ -f "$exit_wg_private_key_local" ]]; then
      secure_file_permissions "$exit_wg_private_key_local"
      if [[ -r "$exit_wg_private_key_local" ]]; then
        exit_wg_key_prepared="1"
        echo "note: repaired exit wg private-key permissions before deriving EXIT_WG_PUBKEY ($exit_wg_private_key_local)"
      elif [[ "$prod_profile" == "1" ]]; then
        echo "server-up refused: exit wg private key is not readable and prod profile must fail closed ($exit_wg_private_key_local)"
        echo "fix ownership or permissions (for example: chmod 600 '$exit_wg_private_key_local') or recreate the key as the current user, then rerun server-up."
        exit 2
      else
        # Root-owned leftovers can exist after prior sudo-based runs. Do not fail
        # startup here; allow runtime generation inside the container path.
        echo "note: exit wg private-key exists but is not readable; deferring key initialization to runtime ($exit_wg_private_key_local)"
      fi
    elif [[ -w "$(dirname "$exit_wg_private_key_local")" ]]; then
      if (umask 077 && wg genkey >"$exit_wg_private_key_local"); then
        exit_wg_key_prepared="1"
      else
        echo "note: failed to write exit wg private-key before compose; deferring key initialization to runtime ($exit_wg_private_key_local)"
      fi
    else
      # Some local test environments may have stale root-owned bind-mount dirs.
      # Defer key init to runtime instead of failing server-up preflight.
      echo "note: exit wg private-key path not writable before compose; deferring key initialization to runtime ($exit_wg_private_key_local)"
    fi
    if [[ "$exit_wg_key_prepared" == "1" ]]; then
      secure_file_permissions "$exit_wg_private_key_local"
      if exit_wg_pubkey="$(wg pubkey <"$exit_wg_private_key_local" 2>/dev/null)"; then
        exit_wg_pubkey="$(printf '%s' "$exit_wg_pubkey" | tr -d '\r\n')"
        if [[ -z "$exit_wg_pubkey" ]]; then
          if [[ "$prod_profile" == "1" ]]; then
            echo "server-up refused: derived EXIT_WG_PUBKEY was empty in prod profile ($exit_wg_private_key_local)"
            echo "fix the file permissions/contents or recreate the key as the current user, then rerun server-up."
            exit 2
          fi
          echo "note: derived EXIT_WG_PUBKEY was empty; deferring pubkey derivation to runtime ($exit_wg_private_key_local)"
          exit_wg_key_prepared="0"
        fi
      else
        if [[ "$prod_profile" == "1" ]]; then
          echo "server-up refused: could not derive EXIT_WG_PUBKEY from local key in prod profile ($exit_wg_private_key_local)"
          echo "fix the file permissions/contents or recreate the key as the current user, then rerun server-up."
          exit 2
        fi
        secure_file_permissions "$exit_wg_private_key_local"
        if exit_wg_pubkey="$(wg pubkey <"$exit_wg_private_key_local" 2>/dev/null)"; then
          exit_wg_pubkey="$(printf '%s' "$exit_wg_pubkey" | tr -d '\r\n')"
          if [[ -n "$exit_wg_pubkey" ]]; then
            echo "note: repaired exit wg private-key permissions before deriving EXIT_WG_PUBKEY ($exit_wg_private_key_local)"
          else
            echo "note: derived EXIT_WG_PUBKEY was empty; deferring pubkey derivation to runtime ($exit_wg_private_key_local)"
            exit_wg_key_prepared="0"
          fi
        else
          echo "note: could not derive EXIT_WG_PUBKEY from local key; deferring pubkey derivation to runtime ($exit_wg_private_key_local)"
          exit_wg_key_prepared="0"
        fi
      fi
    fi
    if [[ "$exit_wg_key_prepared" != "1" ]]; then
      exit_wg_pubkey="derive"
    else
      :
    fi
  fi

  write_identity_config "$operator_id" "$issuer_id"

  if [[ "$mode" == "authority" ]]; then
    write_authority_env "$public_host" "$operator_id" "$issuer_id" "$issuer_admin_token" "$directory_admin_token" "$entry_puzzle_secret" "$peer_dirs" "$beta_profile" "$client_allowlist" "$allow_anon_cred" "$prod_profile" "$admin_signers_file_container" "$admin_sign_key_id" "$admin_sign_key_file_local" "$issuer_urls_csv" "$exit_wg_private_key_container" "$exit_wg_interface" "$exit_wg_pubkey"
    compose_with_env "$AUTHORITY_ENV_FILE" up -d --build directory issuer entry-exit

    local -a local_opts
    local -a public_opts
    mapfile -t local_opts < <(curl_tls_opts_for_url "${url_scheme}://127.0.0.1:8081")
    mapfile -t public_opts < <(curl_tls_opts_for_url "${url_scheme}://${public_host}:8081")

    # Always validate local container reachability first.
    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8081/v1/relays" "local directory" 40 "${local_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=80 directory; exit 1; }
    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8082/v1/pubkeys" "local issuer" 40 "${local_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=80 issuer; exit 1; }
    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8083/v1/health" "local entry" 40 "${local_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8084/v1/health" "local exit" 40 "${local_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=120 entry-exit; exit 1; }

    # Optional public endpoint validation (can fail on NAT loopback setups).
    if [[ "${EASY_NODE_VERIFY_PUBLIC:-0}" == "1" ]] && ! host_is_loopback "$public_host"; then
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8081/v1/relays" "public directory" 15 "${public_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=80 directory; exit 1; }
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8082/v1/pubkeys" "public issuer" 15 "${public_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=80 issuer; exit 1; }
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8083/v1/health" "public entry" 15 "${public_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8084/v1/health" "public exit" 15 "${public_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
    fi
    write_server_mode "authority"

    echo "server stack started"
    echo "mode: authority"
    echo "env file: $AUTHORITY_ENV_FILE"
    echo "operator_id: $operator_id"
    echo "issuer_id: $issuer_id"
    echo "identity file: $identity_file"
    if [[ "$prod_profile" == "1" ]]; then
      echo "issuer_admin_token: [disabled in prod profile; signed admin auth only]"
    else
      if [[ "$show_admin_token" == "1" ]]; then
        echo "issuer_admin_token: $issuer_admin_token"
      else
        echo "issuer_admin_token: [hidden] (set --show-admin-token to print)"
      fi
    fi
    echo "directory_admin_token: [hidden]"
    echo "entry_puzzle_secret: [hidden]"
    if [[ "$beta_profile" == "1" ]]; then
      echo "beta profile: enabled (quorum and anti-concentration defaults applied)"
    fi
    if [[ -n "$peer_dirs" ]]; then
      echo "peer_identity_strict: $peer_identity_strict_effective (configured=$peer_identity_strict)"
    fi
    echo "client_allowlist: $client_allowlist"
    echo "allow_anon_cred: $allow_anon_cred"
    if [[ "$prod_profile" == "1" ]]; then
      echo "prod profile: enabled (mTLS + signed admin controls enforced)"
      echo "admin_signing_key_id: $admin_sign_key_id"
      echo "admin_signing_public_keys_file: $admin_signers_file_local"
      echo "issuer_urls: $issuer_urls_csv"
      echo "exit_wg_interface: $exit_wg_interface"
      echo "exit_wg_private_key_file: $exit_wg_private_key_local"
    fi
    echo "health checks:"
    if [[ "$prod_profile" == "1" ]]; then
      local mtls_material ca_file cert_file key_file
      mtls_material="$(resolve_local_mtls_material)"
      IFS='|' read -r ca_file cert_file key_file <<<"$mtls_material"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8081/v1/relays"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8082/v1/pubkeys"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8083/v1/health"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8084/v1/health"
    else
      echo "  curl ${url_scheme}://${public_host}:8081/v1/relays"
      echo "  curl ${url_scheme}://${public_host}:8082/v1/pubkeys"
      echo "  curl ${url_scheme}://${public_host}:8083/v1/health"
      echo "  curl ${url_scheme}://${public_host}:8084/v1/health"
    fi
    if [[ "$auto_invite" == "1" ]]; then
      local auto_invite_issuer_url
      auto_invite_issuer_url="$(ensure_url_scheme "127.0.0.1:8082" "$url_scheme")"
      echo "auto invite: generating ${auto_invite_count} key(s) tier=${auto_invite_tier} wait=${auto_invite_wait_sec}s"
      local auto_invite_rc=0
      set +e
      "$ROOT_DIR/scripts/easy_node.sh" invite-generate \
        --issuer-url "$auto_invite_issuer_url" \
        --count "$auto_invite_count" \
        --tier "$auto_invite_tier" \
        --wait-sec "$auto_invite_wait_sec"
      auto_invite_rc=$?
      set -e
      if [[ "$auto_invite_rc" -ne 0 ]]; then
        if [[ "$auto_invite_fail_open" == "1" ]]; then
          echo "auto invite: warning: invite generation failed (rc=$auto_invite_rc); continuing because --auto-invite-fail-open=1"
        else
          echo "auto invite: invite generation failed (rc=$auto_invite_rc); failing because --auto-invite-fail-open=0"
          exit "$auto_invite_rc"
        fi
      fi
    fi
  else
    write_provider_env "$public_host" "$operator_id" "$directory_admin_token" "$entry_puzzle_secret" "$peer_dirs" "$beta_profile" "$authority_issuer" "$prod_profile" "$issuer_urls_csv" "$exit_wg_private_key_container" "$exit_wg_interface" "$exit_wg_pubkey"
    compose_with_env "$PROVIDER_ENV_FILE" up -d --build --no-deps directory entry-exit

    local -a local_opts
    local -a public_opts
    local -a issuer_opts
    mapfile -t local_opts < <(curl_tls_opts_for_url "${url_scheme}://127.0.0.1:8081")
    mapfile -t public_opts < <(curl_tls_opts_for_url "${url_scheme}://${public_host}:8081")
    mapfile -t issuer_opts < <(curl_tls_opts_for_url "${authority_issuer}")

    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8081/v1/relays" "local directory" 40 "${local_opts[@]}" || { compose_with_env "$PROVIDER_ENV_FILE" logs --tail=80 directory; exit 1; }
    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8083/v1/health" "local entry" 40 "${local_opts[@]}" || { compose_with_env "$PROVIDER_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8084/v1/health" "local exit" 40 "${local_opts[@]}" || { compose_with_env "$PROVIDER_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
    wait_http_ok_with_opts "${authority_issuer}/v1/pubkeys" "authority issuer" 20 "${issuer_opts[@]}" || {
      if [[ "$prod_profile" == "1" ]]; then
        print_prod_https_mismatch_hint_for_endpoint "$(trim_url "$authority_issuer")/v1/pubkeys" "authority issuer ${authority_issuer}" 4 || true
      fi
      echo "provider mode requires reachable authority issuer."
      exit 1
    }

    if [[ "${EASY_NODE_VERIFY_PUBLIC:-0}" == "1" ]] && ! host_is_loopback "$public_host"; then
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8081/v1/relays" "public directory" 15 "${public_opts[@]}" || { compose_with_env "$PROVIDER_ENV_FILE" logs --tail=80 directory; exit 1; }
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8083/v1/health" "public entry" 15 "${public_opts[@]}" || { compose_with_env "$PROVIDER_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8084/v1/health" "public exit" 15 "${public_opts[@]}" || { compose_with_env "$PROVIDER_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
    fi
    write_server_mode "provider"

    echo "server stack started"
    echo "mode: provider"
    echo "env file: $PROVIDER_ENV_FILE"
    echo "operator_id: $operator_id"
    echo "identity file: $identity_file"
    echo "directory_admin_token: [hidden]"
    echo "entry_puzzle_secret: [hidden]"
    if [[ "$beta_profile" == "1" ]]; then
      echo "beta profile: enabled (quorum and anti-concentration defaults applied)"
    fi
    if [[ -n "$peer_dirs" ]]; then
      echo "peer_identity_strict: $peer_identity_strict_effective (configured=$peer_identity_strict)"
    fi
    if [[ "$prod_profile" == "1" ]]; then
      echo "prod profile: enabled (mTLS + strict trust checks enforced)"
      echo "issuer_urls: $issuer_urls_csv"
      echo "exit_wg_interface: $exit_wg_interface"
      echo "exit_wg_private_key_file: $exit_wg_private_key_local"
    fi
    echo "authority_directory: $authority_directory"
    echo "authority_issuer: $authority_issuer"
    echo "health checks:"
    if [[ "$prod_profile" == "1" ]]; then
      local mtls_material ca_file cert_file key_file
      mtls_material="$(resolve_local_mtls_material)"
      IFS='|' read -r ca_file cert_file key_file <<<"$mtls_material"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8081/v1/relays"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8083/v1/health"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8084/v1/health"
    else
      echo "  curl ${url_scheme}://${public_host}:8081/v1/relays"
      echo "  curl ${url_scheme}://${public_host}:8083/v1/health"
      echo "  curl ${url_scheme}://${public_host}:8084/v1/health"
    fi
  fi

  if [[ -n "$peer_dirs" ]]; then
    local bootstrap_host
    bootstrap_host="$(host_from_url "$(first_csv_item "$peer_dirs")")"
    if [[ -n "$local_host" && -n "$bootstrap_host" && "$local_host" != "$bootstrap_host" ]]; then
      write_hosts_config "$bootstrap_host" "$local_host"
      echo "updated host config: $(hosts_config_file)"
    fi
  fi

  if [[ "$federation_wait" == "1" ]]; then
    if [[ -z "$peer_dirs" ]]; then
      echo "server-up federation wait skipped: no peer directories configured."
    else
      local federation_directory_url
      federation_directory_url="$(ensure_url_scheme "127.0.0.1:8081" "$url_scheme")"
      echo "server-up federation wait: checking local directory federation readiness..."
      if ! server_federation_wait \
        --directory-url "$federation_directory_url" \
        --admin-token "$directory_admin_token" \
        --ready-timeout-sec "$federation_ready_timeout_sec" \
        --poll-sec "$federation_poll_sec" \
        --require-configured-healthy "$federation_require_configured_healthy" \
        --max-cooling-retry-sec "$federation_max_cooling_retry_sec" \
        --max-peer-sync-age-sec "$federation_max_peer_sync_age_sec" \
        --max-issuer-sync-age-sec "$federation_max_issuer_sync_age_sec" \
        --min-peer-success-sources "$federation_min_peer_success_sources" \
        --min-issuer-success-sources "$federation_min_issuer_success_sources" \
        --min-peer-source-operators "$federation_min_peer_source_operators" \
        --min-issuer-source-operators "$federation_min_issuer_source_operators" \
        --summary-json "$federation_wait_summary_json" \
        --print-summary-json "$federation_wait_print_summary_json" \
        --timeout-sec 8; then
        echo "server-up federation wait failed; stack is running but federation is not ready."
        echo "hint: run './scripts/easy_node.sh server-federation-status --directory-url ${federation_directory_url}' for diagnostics."
        exit 1
      fi
    fi
  fi
}

server_status() {
  ensure_compose_deps_or_die
  local env_file
  env_file="$(active_server_env_file)"
  compose_with_env "$env_file" ps
}

server_federation_status() {
  local directory_url=""
  local admin_token=""
  local timeout_sec="8"
  local require_configured_healthy="${EASY_NODE_FEDERATION_REQUIRE_CONFIGURED_HEALTHY:-0}"
  local max_cooling_retry_sec="${EASY_NODE_FEDERATION_MAX_COOLING_RETRY_SEC:-0}"
  local max_peer_sync_age_sec="${EASY_NODE_FEDERATION_MAX_PEER_SYNC_AGE_SEC:-0}"
  local max_issuer_sync_age_sec="${EASY_NODE_FEDERATION_MAX_ISSUER_SYNC_AGE_SEC:-0}"
  local min_peer_success_sources="${EASY_NODE_FEDERATION_MIN_PEER_SUCCESS_SOURCES:-0}"
  local min_issuer_success_sources="${EASY_NODE_FEDERATION_MIN_ISSUER_SUCCESS_SOURCES:-0}"
  local min_peer_source_operators="${EASY_NODE_FEDERATION_MIN_PEER_SOURCE_OPERATORS:-0}"
  local min_issuer_source_operators="${EASY_NODE_FEDERATION_MIN_ISSUER_SOURCE_OPERATORS:-0}"
  local fail_on_not_ready="${EASY_NODE_FEDERATION_STATUS_FAIL_ON_NOT_READY:-0}"
  local summary_json=""
  local print_summary_json="${EASY_NODE_FEDERATION_STATUS_PRINT_SUMMARY_JSON:-0}"
  local show_json="0"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --directory-url)
        directory_url="${2:-}"
        shift 2
        ;;
      --admin-token)
        admin_token="${2:-}"
        shift 2
        ;;
      --timeout-sec)
        timeout_sec="${2:-}"
        shift 2
        ;;
      --require-configured-healthy)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          require_configured_healthy="${2:-}"
          shift 2
        else
          require_configured_healthy="1"
          shift
        fi
        ;;
      --max-cooling-retry-sec)
        max_cooling_retry_sec="${2:-}"
        shift 2
        ;;
      --max-peer-sync-age-sec)
        max_peer_sync_age_sec="${2:-}"
        shift 2
        ;;
      --max-issuer-sync-age-sec)
        max_issuer_sync_age_sec="${2:-}"
        shift 2
        ;;
      --min-peer-success-sources)
        min_peer_success_sources="${2:-}"
        shift 2
        ;;
      --min-issuer-success-sources)
        min_issuer_success_sources="${2:-}"
        shift 2
        ;;
      --min-peer-source-operators)
        min_peer_source_operators="${2:-}"
        shift 2
        ;;
      --min-issuer-source-operators)
        min_issuer_source_operators="${2:-}"
        shift 2
        ;;
      --fail-on-not-ready)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          fail_on_not_ready="${2:-}"
          shift 2
        else
          fail_on_not_ready="1"
          shift
        fi
        ;;
      --summary-json)
        summary_json="${2:-}"
        shift 2
        ;;
      --print-summary-json)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          print_summary_json="${2:-}"
          shift 2
        else
          print_summary_json="1"
          shift
        fi
        ;;
      --show-json)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          show_json="${2:-}"
          shift 2
        else
          show_json="1"
          shift
        fi
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for server-federation-status: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$show_json" != "0" && "$show_json" != "1" ]]; then
    echo "server-federation-status requires --show-json to be 0 or 1"
    exit 2
  fi
  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || ((timeout_sec < 1)); then
    echo "server-federation-status requires --timeout-sec >= 1"
    exit 2
  fi
  if [[ "$require_configured_healthy" != "0" && "$require_configured_healthy" != "1" ]]; then
    echo "server-federation-status requires --require-configured-healthy to be 0 or 1"
    exit 2
  fi
  if ! [[ "$max_cooling_retry_sec" =~ ^[0-9]+$ ]]; then
    echo "server-federation-status requires --max-cooling-retry-sec to be >= 0"
    exit 2
  fi
  if ! [[ "$max_peer_sync_age_sec" =~ ^[0-9]+$ ]]; then
    echo "server-federation-status requires --max-peer-sync-age-sec to be >= 0"
    exit 2
  fi
  if ! [[ "$max_issuer_sync_age_sec" =~ ^[0-9]+$ ]]; then
    echo "server-federation-status requires --max-issuer-sync-age-sec to be >= 0"
    exit 2
  fi
  if ! [[ "$min_peer_success_sources" =~ ^[0-9]+$ ]]; then
    echo "server-federation-status requires --min-peer-success-sources to be >= 0"
    exit 2
  fi
  if ! [[ "$min_issuer_success_sources" =~ ^[0-9]+$ ]]; then
    echo "server-federation-status requires --min-issuer-success-sources to be >= 0"
    exit 2
  fi
  if ! [[ "$min_peer_source_operators" =~ ^[0-9]+$ ]]; then
    echo "server-federation-status requires --min-peer-source-operators to be >= 0"
    exit 2
  fi
  if ! [[ "$min_issuer_source_operators" =~ ^[0-9]+$ ]]; then
    echo "server-federation-status requires --min-issuer-source-operators to be >= 0"
    exit 2
  fi
  if [[ "$fail_on_not_ready" != "0" && "$fail_on_not_ready" != "1" ]]; then
    echo "server-federation-status requires --fail-on-not-ready to be 0 or 1"
    exit 2
  fi
  if [[ "$print_summary_json" != "0" && "$print_summary_json" != "1" ]]; then
    echo "server-federation-status requires --print-summary-json to be 0 or 1"
    exit 2
  fi

  local env_file
  env_file="$(active_server_env_file)"
  if [[ ! -f "$env_file" ]]; then
    echo "server-federation-status requires an existing server env file: $env_file"
    exit 2
  fi

  local prod_strict
  prod_strict="$(identity_value "$env_file" "PROD_STRICT_MODE")"
  local url_scheme="http"
  if [[ "$prod_strict" == "1" ]]; then
    url_scheme="https"
  fi

  if [[ -z "$directory_url" ]]; then
    directory_url="$(identity_value "$env_file" "DIRECTORY_PUBLIC_URL")"
  fi
  if [[ -z "$directory_url" ]]; then
    directory_url="${url_scheme}://127.0.0.1:8081"
  else
    directory_url="$(trim_url "$directory_url")"
    if [[ "$directory_url" != http://* && "$directory_url" != https://* ]]; then
      directory_url="$(ensure_url_scheme "$directory_url" "$url_scheme")"
    fi
  fi

  if [[ -z "$admin_token" ]]; then
    admin_token="$(identity_value "$env_file" "DIRECTORY_ADMIN_TOKEN")"
  fi
  admin_token="$(printf '%s' "$admin_token" | tr -d '\r')"
  if [[ -z "$admin_token" ]]; then
    echo "server-federation-status requires directory admin token (set in env file or pass --admin-token)"
    exit 2
  fi

  local peer_status_url sync_status_url
  peer_status_url="${directory_url%/}/v1/admin/peer-status"
  sync_status_url="${directory_url%/}/v1/admin/sync-status"
  local peer_status_body sync_status_body
  peer_status_body="$(mktemp)"
  sync_status_body="$(mktemp)"
  local -a tls_opts=()
  mapfile -t tls_opts < <(curl_tls_opts_for_url "$directory_url")

  local peer_status_code
  peer_status_code="$(
    curl -sS -o "$peer_status_body" -w "%{http_code}" \
      --connect-timeout 3 --max-time "$timeout_sec" \
      "${tls_opts[@]}" \
      -H "X-Admin-Token: ${admin_token}" \
      "$peer_status_url" || true
  )"
  if [[ "$peer_status_code" != "200" ]]; then
    echo "server-federation-status failed: peer-status endpoint returned code=${peer_status_code:-none}"
    rm -f "$peer_status_body" "$sync_status_body"
    exit 1
  fi
  if ! jq -e '.peers | arrays' <"$peer_status_body" >/dev/null 2>&1; then
    echo "server-federation-status failed: invalid peer-status payload from $peer_status_url"
    rm -f "$peer_status_body" "$sync_status_body"
    exit 1
  fi

  local sync_status_code
  sync_status_code="$(
    curl -sS -o "$sync_status_body" -w "%{http_code}" \
      --connect-timeout 3 --max-time "$timeout_sec" \
      "${tls_opts[@]}" \
      -H "X-Admin-Token: ${admin_token}" \
      "$sync_status_url" || true
  )"
  if [[ "$sync_status_code" != "200" ]]; then
    echo "server-federation-status failed: sync-status endpoint returned code=${sync_status_code:-none}"
    rm -f "$peer_status_body" "$sync_status_body"
    exit 1
  fi
  if ! jq -e '.peer and .issuer' <"$sync_status_body" >/dev/null 2>&1; then
    echo "server-federation-status failed: invalid sync-status payload from $sync_status_url"
    rm -f "$peer_status_body" "$sync_status_body"
    exit 1
  fi

  local total configured discovered eligible cooling failing configured_healthy configured_failing discovered_eligible cooling_retry_max_sec
  total="$(jq -r '(.peers | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
  configured="$(jq -r '([.peers[] | select(.configured == true)] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
  discovered="$(jq -r '([.peers[] | select(.discovered == true)] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
  eligible="$(jq -r '([.peers[] | select(.eligible == true)] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
  cooling="$(jq -r '([.peers[] | select(.cooling_down == true)] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
  failing="$(jq -r '([.peers[] | select((.consecutive_failures // 0) > 0)] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
  configured_healthy="$(jq -r '([.peers[] | select(.configured == true and ((.consecutive_failures // 0) == 0))] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
  configured_failing="$(jq -r '([.peers[] | select(.configured == true and ((.consecutive_failures // 0) > 0))] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
  discovered_eligible="$(jq -r '([.peers[] | select(.discovered == true and .eligible == true)] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
  cooling_retry_max_sec="$(jq -r '([.peers[] | select(.cooling_down == true) | (.retry_after_sec // 0)] | max // 0)' <"$peer_status_body" 2>/dev/null || echo "0")"

  local peer_quorum peer_success peer_sources peer_source_operator_count peer_source_operators peer_required peer_error peer_last_run
  local issuer_quorum issuer_success issuer_sources issuer_source_operator_count issuer_source_operators issuer_required issuer_error issuer_last_run
  local sync_generated_at sync_ref_epoch status_now_epoch peer_sync_age_sec issuer_sync_age_sec
  local peer_sync_age_display issuer_sync_age_display
  local peer_sync_ready issuer_sync_ready issuer_sync_required peer_health_ready cooling_retry_exceeded federation_ready
  local readiness_failure_reasons_json readiness_failure_reasons_csv
  peer_quorum="$(jq -r '.peer.quorum_met // false' <"$sync_status_body" 2>/dev/null || echo "false")"
  peer_success="$(jq -r '.peer.success // false' <"$sync_status_body" 2>/dev/null || echo "false")"
  peer_sources="$(jq -r '.peer.success_sources // 0' <"$sync_status_body" 2>/dev/null || echo "0")"
  peer_source_operator_count="$(jq -r '((.peer.source_operators // []) | length) // 0' <"$sync_status_body" 2>/dev/null || echo "0")"
  peer_source_operators="$(jq -r '((.peer.source_operators // []) | map(tostring) | unique | join(",")) // ""' <"$sync_status_body" 2>/dev/null || true)"
  peer_required="$(jq -r '.peer.required_operators // 0' <"$sync_status_body" 2>/dev/null || echo "0")"
  peer_last_run="$(jq -r '.peer.last_run_at // 0' <"$sync_status_body" 2>/dev/null || echo "0")"
  peer_error="$(jq -r '.peer.error // ""' <"$sync_status_body" 2>/dev/null || true)"
  issuer_quorum="$(jq -r '.issuer.quorum_met // false' <"$sync_status_body" 2>/dev/null || echo "false")"
  issuer_success="$(jq -r '.issuer.success // false' <"$sync_status_body" 2>/dev/null || echo "false")"
  issuer_sources="$(jq -r '.issuer.success_sources // 0' <"$sync_status_body" 2>/dev/null || echo "0")"
  issuer_source_operator_count="$(jq -r '((.issuer.source_operators // []) | length) // 0' <"$sync_status_body" 2>/dev/null || echo "0")"
  issuer_source_operators="$(jq -r '((.issuer.source_operators // []) | map(tostring) | unique | join(",")) // ""' <"$sync_status_body" 2>/dev/null || true)"
  issuer_required="$(jq -r '.issuer.required_operators // 0' <"$sync_status_body" 2>/dev/null || echo "0")"
  issuer_last_run="$(jq -r '.issuer.last_run_at // 0' <"$sync_status_body" 2>/dev/null || echo "0")"
  issuer_error="$(jq -r '.issuer.error // ""' <"$sync_status_body" 2>/dev/null || true)"
  sync_generated_at="$(jq -r '.generated_at // 0' <"$sync_status_body" 2>/dev/null || echo "0")"
  status_now_epoch="$(date +%s)"
  sync_ref_epoch="$status_now_epoch"
  if [[ "$sync_generated_at" =~ ^[0-9]+$ ]] && ((sync_generated_at > 0)); then
    sync_ref_epoch="$sync_generated_at"
  fi
  peer_sync_age_sec="-1"
  if [[ "$peer_last_run" =~ ^[0-9]+$ ]] && ((peer_last_run > 0)); then
    peer_sync_age_sec=$((sync_ref_epoch - peer_last_run))
    if ((peer_sync_age_sec < 0)); then
      peer_sync_age_sec=0
    fi
  fi
  issuer_sync_age_sec="-1"
  if [[ "$issuer_last_run" =~ ^[0-9]+$ ]] && ((issuer_last_run > 0)); then
    issuer_sync_age_sec=$((sync_ref_epoch - issuer_last_run))
    if ((issuer_sync_age_sec < 0)); then
      issuer_sync_age_sec=0
    fi
  fi
  peer_sync_age_display="n/a"
  if ((peer_sync_age_sec >= 0)); then
    peer_sync_age_display="$peer_sync_age_sec"
  fi
  issuer_sync_age_display="n/a"
  if ((issuer_sync_age_sec >= 0)); then
    issuer_sync_age_display="$issuer_sync_age_sec"
  fi

  peer_sync_ready="0"
  issuer_sync_ready="0"
  peer_health_ready="0"
  cooling_retry_exceeded="0"
  federation_ready="0"

  if [[ "$peer_last_run" =~ ^[0-9]+$ ]] && ((peer_last_run > 0)) &&
    [[ "$peer_success" == "true" && "$peer_quorum" == "true" ]]; then
    peer_sync_ready="1"
  fi
  if [[ "$max_peer_sync_age_sec" =~ ^[0-9]+$ ]] && ((max_peer_sync_age_sec > 0)); then
    if ! [[ "$peer_sync_age_sec" =~ ^[0-9]+$ ]] || ((peer_sync_age_sec > max_peer_sync_age_sec)); then
      peer_sync_ready="0"
    fi
  fi
  if [[ "$min_peer_success_sources" =~ ^[0-9]+$ ]] && ((min_peer_success_sources > 0)); then
    if ! [[ "$peer_sources" =~ ^[0-9]+$ ]] || ((peer_sources < min_peer_success_sources)); then
      peer_sync_ready="0"
    fi
  fi
  if [[ "$min_peer_source_operators" =~ ^[0-9]+$ ]] && ((min_peer_source_operators > 0)); then
    if ! [[ "$peer_source_operator_count" =~ ^[0-9]+$ ]] || ((peer_source_operator_count < min_peer_source_operators)); then
      peer_sync_ready="0"
    fi
  fi

  if [[ "$issuer_success" == "true" && "$issuer_quorum" == "true" ]]; then
    issuer_sync_ready="1"
  fi
  if [[ "$max_issuer_sync_age_sec" =~ ^[0-9]+$ ]] && ((max_issuer_sync_age_sec > 0)); then
    if ! [[ "$issuer_sync_age_sec" =~ ^[0-9]+$ ]] || ((issuer_sync_age_sec > max_issuer_sync_age_sec)); then
      issuer_sync_ready="0"
    fi
  fi
  if [[ "$min_issuer_success_sources" =~ ^[0-9]+$ ]] && ((min_issuer_success_sources > 0)); then
    if ! [[ "$issuer_sources" =~ ^[0-9]+$ ]] || ((issuer_sources < min_issuer_success_sources)); then
      issuer_sync_ready="0"
    fi
  fi
  if [[ "$min_issuer_source_operators" =~ ^[0-9]+$ ]] && ((min_issuer_source_operators > 0)); then
    if ! [[ "$issuer_source_operator_count" =~ ^[0-9]+$ ]] || ((issuer_source_operator_count < min_issuer_source_operators)); then
      issuer_sync_ready="0"
    fi
  fi
  issuer_sync_required="1"
  if issuer_sync_optional_no_sources \
    "$issuer_success" \
    "$issuer_quorum" \
    "$issuer_sources" \
    "$issuer_source_operator_count" \
    "$issuer_required" \
    "$issuer_error" \
    "$max_issuer_sync_age_sec" \
    "$min_issuer_success_sources" \
    "$min_issuer_source_operators"; then
    issuer_sync_required="0"
    issuer_sync_ready="1"
  fi

  if [[ "$configured" =~ ^[0-9]+$ ]] && ((configured > 0)); then
    if [[ "$require_configured_healthy" == "1" ]]; then
      if [[ "$configured_healthy" =~ ^[0-9]+$ ]] && ((configured_healthy >= configured)); then
        peer_health_ready="1"
      fi
    elif [[ "$configured_healthy" =~ ^[0-9]+$ ]] && ((configured_healthy > 0)); then
      peer_health_ready="1"
    elif [[ "$discovered_eligible" =~ ^[0-9]+$ ]] && ((discovered_eligible > 0)); then
      peer_health_ready="1"
    fi
  elif [[ "$discovered_eligible" =~ ^[0-9]+$ ]] && ((discovered_eligible > 0)); then
    peer_health_ready="1"
  fi

  if [[ "$max_cooling_retry_sec" =~ ^[0-9]+$ ]] && ((max_cooling_retry_sec > 0)) &&
    [[ "$cooling_retry_max_sec" =~ ^[0-9]+$ ]] && ((cooling_retry_max_sec > max_cooling_retry_sec)); then
    cooling_retry_exceeded="1"
  fi
  if [[ "$peer_sync_ready" == "1" && "$issuer_sync_ready" == "1" && "$peer_health_ready" == "1" && "$cooling_retry_exceeded" == "0" ]]; then
    federation_ready="1"
  fi

  readiness_failure_reasons_json="$(
    jq -nc \
      --argjson peer_last_run "$peer_last_run" \
      --argjson peer_success "$(if [[ "$peer_success" == "true" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson peer_quorum "$(if [[ "$peer_quorum" == "true" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson max_peer_sync_age_sec "$max_peer_sync_age_sec" \
      --argjson peer_sync_age_sec "$peer_sync_age_sec" \
      --argjson min_peer_success_sources "$min_peer_success_sources" \
      --argjson peer_sources "$peer_sources" \
      --argjson min_peer_source_operators "$min_peer_source_operators" \
      --argjson peer_source_operator_count "$peer_source_operator_count" \
      --argjson issuer_success "$(if [[ "$issuer_success" == "true" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson issuer_quorum "$(if [[ "$issuer_quorum" == "true" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson max_issuer_sync_age_sec "$max_issuer_sync_age_sec" \
      --argjson issuer_sync_age_sec "$issuer_sync_age_sec" \
      --argjson min_issuer_success_sources "$min_issuer_success_sources" \
      --argjson issuer_sources "$issuer_sources" \
      --argjson min_issuer_source_operators "$min_issuer_source_operators" \
      --argjson issuer_source_operator_count "$issuer_source_operator_count" \
      --argjson issuer_sync_required "$(if [[ "$issuer_sync_required" == "1" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson require_configured_healthy "$(if [[ "$require_configured_healthy" == "1" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson configured "$configured" \
      --argjson configured_healthy "$configured_healthy" \
      --argjson discovered_eligible "$discovered_eligible" \
      --argjson max_cooling_retry_sec "$max_cooling_retry_sec" \
      --argjson cooling_retry_max_sec "$cooling_retry_max_sec" \
      --argjson federation_ready "$(if [[ "$federation_ready" == "1" ]]; then echo "true"; else echo "false"; fi)" \
      '
      if $federation_ready then
        []
      else
        [
          (if $peer_last_run <= 0 then "peer_sync_not_started" else empty end),
          (if ($peer_success | not) then "peer_sync_not_success" else empty end),
          (if ($peer_quorum | not) then "peer_sync_quorum_not_met" else empty end),
          (if $max_peer_sync_age_sec > 0 and ($peer_sync_age_sec < 0 or $peer_sync_age_sec > $max_peer_sync_age_sec) then "peer_sync_age_stale" else empty end),
          (if $min_peer_success_sources > 0 and $peer_sources < $min_peer_success_sources then "peer_success_sources_below_floor" else empty end),
          (if $min_peer_source_operators > 0 and $peer_source_operator_count < $min_peer_source_operators then "peer_source_operators_below_floor" else empty end),
          (if $issuer_sync_required and ($issuer_success | not) then "issuer_sync_not_success" else empty end),
          (if $issuer_sync_required and ($issuer_quorum | not) then "issuer_sync_quorum_not_met" else empty end),
          (if $issuer_sync_required and $max_issuer_sync_age_sec > 0 and ($issuer_sync_age_sec < 0 or $issuer_sync_age_sec > $max_issuer_sync_age_sec) then "issuer_sync_age_stale" else empty end),
          (if $issuer_sync_required and $min_issuer_success_sources > 0 and $issuer_sources < $min_issuer_success_sources then "issuer_success_sources_below_floor" else empty end),
          (if $issuer_sync_required and $min_issuer_source_operators > 0 and $issuer_source_operator_count < $min_issuer_source_operators then "issuer_source_operators_below_floor" else empty end),
          (if $require_configured_healthy and $configured > 0 and $configured_healthy < $configured then "configured_peers_not_all_healthy" else empty end),
          (if ($configured > 0 and ($require_configured_healthy | not) and $configured_healthy <= 0 and $discovered_eligible <= 0) then "no_healthy_or_discovered_eligible_peer" else empty end),
          (if ($configured <= 0 and $discovered_eligible <= 0) then "no_discovered_eligible_peer" else empty end),
          (if $max_cooling_retry_sec > 0 and $cooling_retry_max_sec > $max_cooling_retry_sec then "cooling_retry_above_threshold" else empty end)
        ] | unique
      end
      '
  )"
  readiness_failure_reasons_csv="$(jq -r 'if length == 0 then "none" else join(",") end' <<<"$readiness_failure_reasons_json")"

  echo "server federation status:"
  echo "  directory_url: $directory_url"
  echo "  policy: require_configured_healthy=$require_configured_healthy max_cooling_retry_sec=$max_cooling_retry_sec max_peer_sync_age_sec=$max_peer_sync_age_sec max_issuer_sync_age_sec=$max_issuer_sync_age_sec min_peer_success_sources=$min_peer_success_sources min_issuer_success_sources=$min_issuer_success_sources min_peer_source_operators=$min_peer_source_operators min_issuer_source_operators=$min_issuer_source_operators"
  echo "  peer_summary: total=$total configured=$configured discovered=$discovered eligible=$eligible cooling_down=$cooling failing=$failing cooling_retry_max_sec=$cooling_retry_max_sec"
  echo "  peer_health: configured_healthy=$configured_healthy configured_failing=$configured_failing discovered_eligible=$discovered_eligible"
  echo "  peer_sync: success=$peer_success quorum_met=$peer_quorum success_sources=$peer_sources source_operator_count=$peer_source_operator_count required_operators=$peer_required last_run_at=$peer_last_run age_sec=$peer_sync_age_display"
  if [[ -n "$peer_source_operators" ]]; then
    echo "  peer_sync_source_operators: $peer_source_operators"
  fi
  if [[ -n "$peer_error" ]]; then
    echo "  peer_sync_error: $peer_error"
  fi
  echo "  issuer_sync: success=$issuer_success quorum_met=$issuer_quorum success_sources=$issuer_sources source_operator_count=$issuer_source_operator_count required_operators=$issuer_required last_run_at=$issuer_last_run age_sec=$issuer_sync_age_display"
  if [[ "$issuer_sync_required" != "1" ]]; then
    echo "  issuer_sync_note: optional (no issuer trust sources configured)"
  fi
  if [[ -n "$issuer_source_operators" ]]; then
    echo "  issuer_sync_source_operators: $issuer_source_operators"
  fi
  if [[ -n "$issuer_error" ]]; then
    echo "  issuer_sync_error: $issuer_error"
  fi
  echo "  readiness: federation_ready=$federation_ready peer_sync_ready=$peer_sync_ready issuer_sync_ready=$issuer_sync_ready peer_health_ready=$peer_health_ready cooling_retry_exceeded=$cooling_retry_exceeded"
  echo "  readiness_failure_reasons: $readiness_failure_reasons_csv"
  echo "  peers:"
  jq -r '
    .peers[]
    | "- \(.url) configured=\(if .configured then 1 else 0 end) discovered=\(if .discovered then 1 else 0 end) eligible=\(if .eligible then 1 else 0 end) cooling=\(if .cooling_down then 1 else 0 end) failures=\(.consecutive_failures // 0)"
      + (if (.vote_operators // 0) > 0 then " votes=\(.vote_operators)" else "" end)
      + (if (.hint_operator // "") != "" then " hint_op=\(.hint_operator)" else "" end)
      + (if (.retry_after_sec // 0) > 0 then " retry_in_sec=\(.retry_after_sec)" else "" end)
      + (if (.last_error // "") != "" then (" last_error=" + ((.last_error | gsub("\\s+"; " ") | if length > 120 then .[:120] + "..." else . end))) else "" end)
  ' <"$peer_status_body" | sed 's/^/    /'

  local status_summary_json
  status_summary_json="$(
    jq -nc \
      --arg directory_url "$directory_url" \
      --argjson require_configured_healthy "$(if [[ "$require_configured_healthy" == "1" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson max_cooling_retry_sec "$max_cooling_retry_sec" \
      --argjson max_peer_sync_age_sec "$max_peer_sync_age_sec" \
      --argjson max_issuer_sync_age_sec "$max_issuer_sync_age_sec" \
      --argjson min_peer_success_sources "$min_peer_success_sources" \
      --argjson min_issuer_success_sources "$min_issuer_success_sources" \
      --argjson min_peer_source_operators "$min_peer_source_operators" \
      --argjson min_issuer_source_operators "$min_issuer_source_operators" \
      --argjson fail_on_not_ready "$(if [[ "$fail_on_not_ready" == "1" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson federation_ready "$(if [[ "$federation_ready" == "1" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson peer_sync_ready "$(if [[ "$peer_sync_ready" == "1" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson issuer_sync_ready "$(if [[ "$issuer_sync_ready" == "1" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson peer_health_ready "$(if [[ "$peer_health_ready" == "1" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson cooling_retry_exceeded "$(if [[ "$cooling_retry_exceeded" == "1" ]]; then echo "true"; else echo "false"; fi)" \
      --argjson readiness_failure_reasons "$readiness_failure_reasons_json" \
      --argjson total "$total" \
      --argjson configured "$configured" \
      --argjson discovered "$discovered" \
      --argjson eligible "$eligible" \
      --argjson cooling "$cooling" \
      --argjson failing "$failing" \
      --argjson configured_healthy "$configured_healthy" \
      --argjson configured_failing "$configured_failing" \
      --argjson discovered_eligible "$discovered_eligible" \
      --argjson cooling_retry_max_sec "$cooling_retry_max_sec" \
      --argjson peer_quorum "$peer_quorum" \
      --argjson peer_success "$peer_success" \
      --argjson peer_sources "$peer_sources" \
      --argjson peer_source_operator_count "$peer_source_operator_count" \
      --arg peer_source_operators "$peer_source_operators" \
      --argjson peer_required "$peer_required" \
      --argjson peer_last_run "$peer_last_run" \
      --argjson peer_sync_age_sec "$peer_sync_age_sec" \
      --arg peer_sync_age_display "$peer_sync_age_display" \
      --arg peer_error "$peer_error" \
      --argjson issuer_quorum "$issuer_quorum" \
      --argjson issuer_success "$issuer_success" \
      --argjson issuer_sources "$issuer_sources" \
      --argjson issuer_source_operator_count "$issuer_source_operator_count" \
      --arg issuer_source_operators "$issuer_source_operators" \
      --argjson issuer_required "$issuer_required" \
      --argjson issuer_last_run "$issuer_last_run" \
      --argjson issuer_sync_age_sec "$issuer_sync_age_sec" \
      --arg issuer_sync_age_display "$issuer_sync_age_display" \
      --arg issuer_error "$issuer_error" \
      --slurpfile peer "$peer_status_body" \
      --slurpfile sync "$sync_status_body" \
      '{
        directory_url:$directory_url,
        policy:{
          require_configured_healthy:$require_configured_healthy,
          max_cooling_retry_sec:$max_cooling_retry_sec,
          max_peer_sync_age_sec:$max_peer_sync_age_sec,
          max_issuer_sync_age_sec:$max_issuer_sync_age_sec,
          min_peer_success_sources:$min_peer_success_sources,
          min_issuer_success_sources:$min_issuer_success_sources,
          min_peer_source_operators:$min_peer_source_operators,
          min_issuer_source_operators:$min_issuer_source_operators,
          fail_on_not_ready:$fail_on_not_ready
        },
        readiness:{
          federation_ready:$federation_ready,
          peer_sync_ready:$peer_sync_ready,
          issuer_sync_ready:$issuer_sync_ready,
          peer_health_ready:$peer_health_ready,
          cooling_retry_exceeded:$cooling_retry_exceeded,
          failure_reasons:$readiness_failure_reasons,
          failure_count:($readiness_failure_reasons | length)
        },
        observed:{
          peer_summary:{
            total:$total,
            configured:$configured,
            discovered:$discovered,
            eligible:$eligible,
            cooling:$cooling,
            failing:$failing,
            cooling_retry_max_sec:$cooling_retry_max_sec
          },
          peer_health:{
            configured_healthy:$configured_healthy,
            configured_failing:$configured_failing,
            discovered_eligible:$discovered_eligible
          },
          peer_sync:{
            success:$peer_success,
            quorum_met:$peer_quorum,
            success_sources:$peer_sources,
            source_operator_count:$peer_source_operator_count,
            source_operators:($peer_source_operators | if length == 0 then [] else split(",") end),
            required_operators:$peer_required,
            last_run_at:$peer_last_run,
            age_sec:$peer_sync_age_sec,
            age_sec_display:$peer_sync_age_display,
            error:$peer_error
          },
          issuer_sync:{
            success:$issuer_success,
            quorum_met:$issuer_quorum,
            success_sources:$issuer_sources,
            source_operator_count:$issuer_source_operator_count,
            source_operators:($issuer_source_operators | if length == 0 then [] else split(",") end),
            required_operators:$issuer_required,
            last_run_at:$issuer_last_run,
            age_sec:$issuer_sync_age_sec,
            age_sec_display:$issuer_sync_age_display,
            error:$issuer_error
          }
        },
        peer_status:$peer[0],
        sync_status:$sync[0]
      }'
  )"

  if [[ -n "$summary_json" ]]; then
    mkdir -p "$(dirname "$summary_json")"
    printf '%s\n' "$status_summary_json" >"$summary_json"
    echo "  summary_json: $summary_json"
  fi

  if [[ "$print_summary_json" == "1" ]]; then
    echo "summary_json:"
    printf '%s\n' "$status_summary_json"
  fi

  if [[ "$show_json" == "1" ]]; then
    echo "json:"
    jq -n --slurpfile peer "$peer_status_body" --slurpfile sync "$sync_status_body" \
      '{peer_status: $peer[0], sync_status: $sync[0]}'
  fi

  if [[ "$fail_on_not_ready" == "1" ]]; then
    if [[ "$federation_ready" == "1" ]]; then
      echo "server-federation-status policy check: PASS"
    else
      echo "server-federation-status policy check: FAIL"
      echo "hints:"
      echo "  - run './scripts/easy_node.sh server-federation-wait --directory-url ${directory_url} --ready-timeout-sec 90 --poll-sec 5' to wait for convergence"
      echo "  - verify DIRECTORY_PEERS references healthy peers and tune policy thresholds only when justified"
      rm -f "$peer_status_body" "$sync_status_body"
      exit 1
    fi
  fi

  rm -f "$peer_status_body" "$sync_status_body"
}

server_federation_wait() {
  local directory_url=""
  local admin_token=""
  local ready_timeout_sec="${EASY_NODE_FEDERATION_READY_TIMEOUT_SEC:-90}"
  local poll_sec="${EASY_NODE_FEDERATION_POLL_SEC:-5}"
  local timeout_sec="8"
  local require_configured_healthy="${EASY_NODE_FEDERATION_REQUIRE_CONFIGURED_HEALTHY:-0}"
  local max_cooling_retry_sec="${EASY_NODE_FEDERATION_MAX_COOLING_RETRY_SEC:-0}"
  local max_peer_sync_age_sec="${EASY_NODE_FEDERATION_MAX_PEER_SYNC_AGE_SEC:-0}"
  local max_issuer_sync_age_sec="${EASY_NODE_FEDERATION_MAX_ISSUER_SYNC_AGE_SEC:-0}"
  local min_peer_success_sources="${EASY_NODE_FEDERATION_MIN_PEER_SUCCESS_SOURCES:-0}"
  local min_issuer_success_sources="${EASY_NODE_FEDERATION_MIN_ISSUER_SUCCESS_SOURCES:-0}"
  local min_peer_source_operators="${EASY_NODE_FEDERATION_MIN_PEER_SOURCE_OPERATORS:-0}"
  local min_issuer_source_operators="${EASY_NODE_FEDERATION_MIN_ISSUER_SOURCE_OPERATORS:-0}"
  local summary_json=""
  local print_summary_json="${EASY_NODE_FEDERATION_WAIT_PRINT_SUMMARY_JSON:-0}"
  local show_json="0"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --directory-url)
        directory_url="${2:-}"
        shift 2
        ;;
      --admin-token)
        admin_token="${2:-}"
        shift 2
        ;;
      --ready-timeout-sec)
        ready_timeout_sec="${2:-}"
        shift 2
        ;;
      --poll-sec)
        poll_sec="${2:-}"
        shift 2
        ;;
      --timeout-sec)
        timeout_sec="${2:-}"
        shift 2
        ;;
      --require-configured-healthy)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          require_configured_healthy="${2:-}"
          shift 2
        else
          require_configured_healthy="1"
          shift
        fi
        ;;
      --max-cooling-retry-sec)
        max_cooling_retry_sec="${2:-}"
        shift 2
        ;;
      --max-peer-sync-age-sec)
        max_peer_sync_age_sec="${2:-}"
        shift 2
        ;;
      --max-issuer-sync-age-sec)
        max_issuer_sync_age_sec="${2:-}"
        shift 2
        ;;
      --min-peer-success-sources)
        min_peer_success_sources="${2:-}"
        shift 2
        ;;
      --min-issuer-success-sources)
        min_issuer_success_sources="${2:-}"
        shift 2
        ;;
      --min-peer-source-operators)
        min_peer_source_operators="${2:-}"
        shift 2
        ;;
      --min-issuer-source-operators)
        min_issuer_source_operators="${2:-}"
        shift 2
        ;;
      --summary-json)
        summary_json="${2:-}"
        shift 2
        ;;
      --print-summary-json)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          print_summary_json="${2:-}"
          shift 2
        else
          print_summary_json="1"
          shift
        fi
        ;;
      --show-json)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          show_json="${2:-}"
          shift 2
        else
          show_json="1"
          shift
        fi
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for server-federation-wait: $1"
        exit 2
        ;;
    esac
  done

  if ! [[ "$ready_timeout_sec" =~ ^[0-9]+$ ]] || ((ready_timeout_sec < 1)); then
    echo "server-federation-wait requires --ready-timeout-sec >= 1"
    exit 2
  fi
  if ! [[ "$poll_sec" =~ ^[0-9]+$ ]] || ((poll_sec < 1)); then
    echo "server-federation-wait requires --poll-sec >= 1"
    exit 2
  fi
  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || ((timeout_sec < 1)); then
    echo "server-federation-wait requires --timeout-sec >= 1"
    exit 2
  fi
  if [[ "$require_configured_healthy" != "0" && "$require_configured_healthy" != "1" ]]; then
    echo "server-federation-wait requires --require-configured-healthy to be 0 or 1"
    exit 2
  fi
  if ! [[ "$max_cooling_retry_sec" =~ ^[0-9]+$ ]]; then
    echo "server-federation-wait requires --max-cooling-retry-sec to be >= 0"
    exit 2
  fi
  if ! [[ "$max_peer_sync_age_sec" =~ ^[0-9]+$ ]]; then
    echo "server-federation-wait requires --max-peer-sync-age-sec to be >= 0"
    exit 2
  fi
  if ! [[ "$max_issuer_sync_age_sec" =~ ^[0-9]+$ ]]; then
    echo "server-federation-wait requires --max-issuer-sync-age-sec to be >= 0"
    exit 2
  fi
  if ! [[ "$min_peer_success_sources" =~ ^[0-9]+$ ]]; then
    echo "server-federation-wait requires --min-peer-success-sources to be >= 0"
    exit 2
  fi
  if ! [[ "$min_issuer_success_sources" =~ ^[0-9]+$ ]]; then
    echo "server-federation-wait requires --min-issuer-success-sources to be >= 0"
    exit 2
  fi
  if ! [[ "$min_peer_source_operators" =~ ^[0-9]+$ ]]; then
    echo "server-federation-wait requires --min-peer-source-operators to be >= 0"
    exit 2
  fi
  if ! [[ "$min_issuer_source_operators" =~ ^[0-9]+$ ]]; then
    echo "server-federation-wait requires --min-issuer-source-operators to be >= 0"
    exit 2
  fi
  if [[ "$show_json" != "0" && "$show_json" != "1" ]]; then
    echo "server-federation-wait requires --show-json to be 0 or 1"
    exit 2
  fi
  if [[ "$print_summary_json" != "0" && "$print_summary_json" != "1" ]]; then
    echo "server-federation-wait requires --print-summary-json to be 0 or 1"
    exit 2
  fi

  local env_file
  env_file="$(active_server_env_file)"
  if [[ ! -f "$env_file" ]]; then
    echo "server-federation-wait requires an existing server env file: $env_file"
    exit 2
  fi

  local prod_strict
  prod_strict="$(identity_value "$env_file" "PROD_STRICT_MODE")"
  local url_scheme="http"
  if [[ "$prod_strict" == "1" ]]; then
    url_scheme="https"
  fi

  if [[ -z "$directory_url" ]]; then
    directory_url="$(identity_value "$env_file" "DIRECTORY_PUBLIC_URL")"
  fi
  if [[ -z "$directory_url" ]]; then
    directory_url="${url_scheme}://127.0.0.1:8081"
  else
    directory_url="$(trim_url "$directory_url")"
    if [[ "$directory_url" != http://* && "$directory_url" != https://* ]]; then
      directory_url="$(ensure_url_scheme "$directory_url" "$url_scheme")"
    fi
  fi

  if [[ -z "$admin_token" ]]; then
    admin_token="$(identity_value "$env_file" "DIRECTORY_ADMIN_TOKEN")"
  fi
  admin_token="$(printf '%s' "$admin_token" | tr -d '\r')"
  if [[ -z "$admin_token" ]]; then
    echo "server-federation-wait requires directory admin token (set in env file or pass --admin-token)"
    exit 2
  fi

  local sync_status_url peer_status_url
  sync_status_url="${directory_url%/}/v1/admin/sync-status"
  peer_status_url="${directory_url%/}/v1/admin/peer-status"

  local start_epoch deadline_epoch now_epoch elapsed_sec remaining_sec attempt
  local last_sync_json last_peer_json
  start_epoch="$(date +%s)"
  deadline_epoch=$((start_epoch + ready_timeout_sec))
  attempt=0
  last_sync_json=""
  last_peer_json=""

  local last_peer_sync_ready="0"
  local last_issuer_sync_ready="0"
  local last_peer_health_ready="0"
  local last_configured_peers="0"
  local last_configured_healthy="0"
  local last_discovered_eligible="0"
  local last_peer_success="false"
  local last_peer_quorum="false"
  local last_peer_last_run="0"
  local last_issuer_success="false"
  local last_issuer_quorum="false"
  local last_issuer_last_run="0"
  local last_peer_sync_age_sec="-1"
  local last_issuer_sync_age_sec="-1"
  local last_peer_sources="0"
  local last_issuer_sources="0"
  local last_peer_source_operators_count="0"
  local last_issuer_source_operators_count="0"
  local last_peer_source_operators=""
  local last_issuer_source_operators=""
  local last_configured_failing="0"
  local last_cooling_retry_max_sec="0"
  local last_failure_reasons_json="[]"
  local last_failure_state="not_started"
  local last_elapsed_sec="0"
  local last_remaining_sec="$ready_timeout_sec"

  emit_federation_wait_summary() {
    local status="$1"
    local state="$2"
    local failure_reasons_json="$3"
    local sync_json_input="$4"
    local peer_json_input="$5"
    local summary_payload

    if ! jq -e 'type == "array"' <<<"$failure_reasons_json" >/dev/null 2>&1; then
      failure_reasons_json='[]'
    fi

    summary_payload="$(
      jq -nc \
        --arg status "$status" \
        --arg state "$state" \
        --arg directory_url "$directory_url" \
        --argjson attempts "$attempt" \
        --argjson elapsed_sec "$last_elapsed_sec" \
        --argjson remaining_sec "$last_remaining_sec" \
        --argjson ready_timeout_sec "$ready_timeout_sec" \
        --argjson poll_sec "$poll_sec" \
        --argjson request_timeout_sec "$timeout_sec" \
        --argjson require_configured_healthy "$(if [[ "$require_configured_healthy" == "1" ]]; then echo "true"; else echo "false"; fi)" \
        --argjson max_cooling_retry_sec "$max_cooling_retry_sec" \
        --argjson max_peer_sync_age_sec "$max_peer_sync_age_sec" \
        --argjson max_issuer_sync_age_sec "$max_issuer_sync_age_sec" \
        --argjson min_peer_success_sources "$min_peer_success_sources" \
        --argjson min_issuer_success_sources "$min_issuer_success_sources" \
        --argjson min_peer_source_operators "$min_peer_source_operators" \
        --argjson min_issuer_source_operators "$min_issuer_source_operators" \
        --argjson peer_sync_ready "$(if [[ "$last_peer_sync_ready" == "1" ]]; then echo "true"; else echo "false"; fi)" \
        --argjson issuer_sync_ready "$(if [[ "$last_issuer_sync_ready" == "1" ]]; then echo "true"; else echo "false"; fi)" \
        --argjson peer_health_ready "$(if [[ "$last_peer_health_ready" == "1" ]]; then echo "true"; else echo "false"; fi)" \
        --argjson configured_peers "$last_configured_peers" \
        --argjson configured_healthy "$last_configured_healthy" \
        --argjson configured_failing "$last_configured_failing" \
        --argjson discovered_eligible "$last_discovered_eligible" \
        --argjson cooling_retry_max_sec "$last_cooling_retry_max_sec" \
        --arg peer_success "$last_peer_success" \
        --arg peer_quorum "$last_peer_quorum" \
        --argjson peer_last_run "$last_peer_last_run" \
        --argjson peer_sync_age_sec "$last_peer_sync_age_sec" \
        --argjson peer_success_sources "$last_peer_sources" \
        --argjson peer_source_operator_count "$last_peer_source_operators_count" \
        --arg peer_source_operators "$last_peer_source_operators" \
        --arg issuer_success "$last_issuer_success" \
        --arg issuer_quorum "$last_issuer_quorum" \
        --argjson issuer_last_run "$last_issuer_last_run" \
        --argjson issuer_sync_age_sec "$last_issuer_sync_age_sec" \
        --argjson issuer_success_sources "$last_issuer_sources" \
        --argjson issuer_source_operator_count "$last_issuer_source_operators_count" \
        --arg issuer_source_operators "$last_issuer_source_operators" \
        --argjson failure_reasons "$failure_reasons_json" \
        --arg sync_json "$sync_json_input" \
        --arg peer_json "$peer_json_input" \
        '{
          status:$status,
          state:$state,
          directory_url:$directory_url,
          timing:{
            attempts:$attempts,
            elapsed_sec:$elapsed_sec,
            remaining_sec:$remaining_sec,
            ready_timeout_sec:$ready_timeout_sec,
            poll_sec:$poll_sec,
            request_timeout_sec:$request_timeout_sec
          },
          policy:{
            require_configured_healthy:$require_configured_healthy,
            max_cooling_retry_sec:$max_cooling_retry_sec,
            max_peer_sync_age_sec:$max_peer_sync_age_sec,
            max_issuer_sync_age_sec:$max_issuer_sync_age_sec,
            min_peer_success_sources:$min_peer_success_sources,
            min_issuer_success_sources:$min_issuer_success_sources,
            min_peer_source_operators:$min_peer_source_operators,
            min_issuer_source_operators:$min_issuer_source_operators
          },
          readiness:{
            peer_sync_ready:$peer_sync_ready,
            issuer_sync_ready:$issuer_sync_ready,
            peer_health_ready:$peer_health_ready,
            failure_reasons:$failure_reasons,
            failure_count:($failure_reasons | length)
          },
          observed:{
            peer_health:{
              configured:$configured_peers,
              configured_healthy:$configured_healthy,
              configured_failing:$configured_failing,
              discovered_eligible:$discovered_eligible,
              cooling_retry_max_sec:$cooling_retry_max_sec
            },
            peer_sync:{
              success:($peer_success == "true"),
              quorum_met:($peer_quorum == "true"),
              success_sources:$peer_success_sources,
              source_operator_count:$peer_source_operator_count,
              source_operators:($peer_source_operators | if length == 0 then [] else split(",") end),
              last_run_at:$peer_last_run,
              age_sec:$peer_sync_age_sec
            },
            issuer_sync:{
              success:($issuer_success == "true"),
              quorum_met:($issuer_quorum == "true"),
              success_sources:$issuer_success_sources,
              source_operator_count:$issuer_source_operator_count,
              source_operators:($issuer_source_operators | if length == 0 then [] else split(",") end),
              last_run_at:$issuer_last_run,
              age_sec:$issuer_sync_age_sec
            }
          },
          sync_status:(if ($sync_json | length) > 0 then (try ($sync_json | fromjson) catch null) else null end),
          peer_status:(if ($peer_json | length) > 0 then (try ($peer_json | fromjson) catch null) else null end)
        }'
    )"

    if [[ -n "$summary_json" ]]; then
      mkdir -p "$(dirname "$summary_json")"
      printf '%s\n' "$summary_payload" >"$summary_json"
      echo "  summary_json: $summary_json"
    fi
    if [[ "$print_summary_json" == "1" ]]; then
      echo "summary_json:"
      printf '%s\n' "$summary_payload"
    fi
  }

  echo "server-federation-wait:"
  echo "  directory_url: $directory_url"
  echo "  ready_timeout_sec: $ready_timeout_sec"
  echo "  poll_sec: $poll_sec"
  echo "  require_configured_healthy: $require_configured_healthy"
  echo "  max_cooling_retry_sec: $max_cooling_retry_sec"
  echo "  max_peer_sync_age_sec: $max_peer_sync_age_sec"
  echo "  max_issuer_sync_age_sec: $max_issuer_sync_age_sec"
  echo "  min_peer_success_sources: $min_peer_success_sources"
  echo "  min_issuer_success_sources: $min_issuer_success_sources"
  echo "  min_peer_source_operators: $min_peer_source_operators"
  echo "  min_issuer_source_operators: $min_issuer_source_operators"

  while true; do
    attempt=$((attempt + 1))
    now_epoch="$(date +%s)"
    elapsed_sec=$((now_epoch - start_epoch))
    remaining_sec=$((deadline_epoch - now_epoch))
    if ((remaining_sec < 0)); then
      remaining_sec=0
    fi
    last_elapsed_sec="$elapsed_sec"
    last_remaining_sec="$remaining_sec"

    local sync_body peer_status_body
    sync_body="$(mktemp)"
    peer_status_body="$(mktemp)"
    local -a tls_opts=()
    mapfile -t tls_opts < <(curl_tls_opts_for_url "$directory_url")

    local sync_code peer_status_code
    sync_code="$(
      curl -sS -o "$sync_body" -w "%{http_code}" \
        --connect-timeout 3 --max-time "$timeout_sec" \
        "${tls_opts[@]}" \
        -H "X-Admin-Token: ${admin_token}" \
        "$sync_status_url" || true
    )"
    peer_status_code="$(
      curl -sS -o "$peer_status_body" -w "%{http_code}" \
        --connect-timeout 3 --max-time "$timeout_sec" \
        "${tls_opts[@]}" \
        -H "X-Admin-Token: ${admin_token}" \
        "$peer_status_url" || true
    )"

    if [[ "$sync_code" == "401" || "$sync_code" == "403" || "$peer_status_code" == "401" || "$peer_status_code" == "403" ]]; then
      rm -f "$sync_body" "$peer_status_body"
      echo "server-federation-wait failed: admin token unauthorized for directory admin endpoints"
      last_failure_state="admin_token_unauthorized"
      last_failure_reasons_json='["admin_token_unauthorized"]'
      emit_federation_wait_summary "fail" "$last_failure_state" "$last_failure_reasons_json" "$last_sync_json" "$last_peer_json"
      return 1
    fi

    if [[ "$sync_code" == "200" && "$peer_status_code" == "200" ]] &&
      jq -e '.peer and .issuer' <"$sync_body" >/dev/null 2>&1 &&
      jq -e '.peers | arrays' <"$peer_status_body" >/dev/null 2>&1; then
      last_sync_json="$(cat "$sync_body")"
      last_peer_json="$(cat "$peer_status_body")"

      local peer_success peer_quorum peer_sources peer_source_operators_count peer_source_operators peer_last_run peer_sync_age_sec peer_sync_age_display
      local issuer_success issuer_quorum issuer_sources issuer_source_operators_count issuer_source_operators issuer_required issuer_error issuer_last_run issuer_sync_age_sec issuer_sync_age_display
      local sync_generated_at sync_ref_epoch
      local configured_peers configured_healthy discovered_eligible configured_failing cooling_retry_max_sec
      peer_success="$(jq -r '.peer.success // false' <"$sync_body" 2>/dev/null || echo "false")"
      peer_quorum="$(jq -r '.peer.quorum_met // false' <"$sync_body" 2>/dev/null || echo "false")"
      peer_sources="$(jq -r '.peer.success_sources // 0' <"$sync_body" 2>/dev/null || echo "0")"
      peer_source_operators_count="$(jq -r '((.peer.source_operators // []) | length) // 0' <"$sync_body" 2>/dev/null || echo "0")"
      peer_source_operators="$(jq -r '((.peer.source_operators // []) | map(tostring) | unique | join(",")) // ""' <"$sync_body" 2>/dev/null || true)"
      peer_last_run="$(jq -r '.peer.last_run_at // 0' <"$sync_body" 2>/dev/null || echo "0")"
      issuer_success="$(jq -r '.issuer.success // false' <"$sync_body" 2>/dev/null || echo "false")"
      issuer_quorum="$(jq -r '.issuer.quorum_met // false' <"$sync_body" 2>/dev/null || echo "false")"
      issuer_sources="$(jq -r '.issuer.success_sources // 0' <"$sync_body" 2>/dev/null || echo "0")"
      issuer_source_operators_count="$(jq -r '((.issuer.source_operators // []) | length) // 0' <"$sync_body" 2>/dev/null || echo "0")"
      issuer_source_operators="$(jq -r '((.issuer.source_operators // []) | map(tostring) | unique | join(",")) // ""' <"$sync_body" 2>/dev/null || true)"
      issuer_required="$(jq -r '.issuer.required_operators // 0' <"$sync_body" 2>/dev/null || echo "0")"
      issuer_error="$(jq -r '.issuer.error // ""' <"$sync_body" 2>/dev/null || true)"
      issuer_last_run="$(jq -r '.issuer.last_run_at // 0' <"$sync_body" 2>/dev/null || echo "0")"
      sync_generated_at="$(jq -r '.generated_at // 0' <"$sync_body" 2>/dev/null || echo "0")"
      configured_peers="$(jq -r '([.peers[] | select(.configured == true)] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
      configured_healthy="$(jq -r '([.peers[] | select(.configured == true and ((.consecutive_failures // 0) == 0))] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
      discovered_eligible="$(jq -r '([.peers[] | select(.discovered == true and .eligible == true)] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
      configured_failing="$(jq -r '([.peers[] | select(.configured == true and ((.consecutive_failures // 0) > 0))] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
      cooling_retry_max_sec="$(jq -r '([.peers[] | select(.cooling_down == true) | (.retry_after_sec // 0)] | max // 0)' <"$peer_status_body" 2>/dev/null || echo "0")"
      sync_ref_epoch="$now_epoch"
      if [[ "$sync_generated_at" =~ ^[0-9]+$ ]] && ((sync_generated_at > 0)); then
        sync_ref_epoch="$sync_generated_at"
      fi
      peer_sync_age_sec="-1"
      if [[ "$peer_last_run" =~ ^[0-9]+$ ]] && ((peer_last_run > 0)); then
        peer_sync_age_sec=$((sync_ref_epoch - peer_last_run))
        if ((peer_sync_age_sec < 0)); then
          peer_sync_age_sec=0
        fi
      fi
      issuer_sync_age_sec="-1"
      if [[ "$issuer_last_run" =~ ^[0-9]+$ ]] && ((issuer_last_run > 0)); then
        issuer_sync_age_sec=$((sync_ref_epoch - issuer_last_run))
        if ((issuer_sync_age_sec < 0)); then
          issuer_sync_age_sec=0
        fi
      fi
      peer_sync_age_display="n/a"
      if ((peer_sync_age_sec >= 0)); then
        peer_sync_age_display="$peer_sync_age_sec"
      fi
      issuer_sync_age_display="n/a"
      if ((issuer_sync_age_sec >= 0)); then
        issuer_sync_age_display="$issuer_sync_age_sec"
      fi

      local peer_sync_ready="0"
      local issuer_sync_ready="0"
      local issuer_sync_required="1"
      local peer_health_ready="0"
      if [[ "$peer_last_run" =~ ^[0-9]+$ ]] && ((peer_last_run > 0)) &&
        [[ "$peer_success" == "true" && "$peer_quorum" == "true" ]]; then
        peer_sync_ready="1"
      fi
      if [[ "$max_peer_sync_age_sec" =~ ^[0-9]+$ ]] && ((max_peer_sync_age_sec > 0)); then
        if ! [[ "$peer_sync_age_sec" =~ ^[0-9]+$ ]] || ((peer_sync_age_sec > max_peer_sync_age_sec)); then
          peer_sync_ready="0"
        fi
      fi
      if [[ "$min_peer_success_sources" =~ ^[0-9]+$ ]] && ((min_peer_success_sources > 0)); then
        if ! [[ "$peer_sources" =~ ^[0-9]+$ ]] || ((peer_sources < min_peer_success_sources)); then
          peer_sync_ready="0"
        fi
      fi
      if [[ "$min_peer_source_operators" =~ ^[0-9]+$ ]] && ((min_peer_source_operators > 0)); then
        if ! [[ "$peer_source_operators_count" =~ ^[0-9]+$ ]] || ((peer_source_operators_count < min_peer_source_operators)); then
          peer_sync_ready="0"
        fi
      fi
      if [[ "$issuer_success" == "true" && "$issuer_quorum" == "true" ]]; then
        issuer_sync_ready="1"
      fi
      if [[ "$max_issuer_sync_age_sec" =~ ^[0-9]+$ ]] && ((max_issuer_sync_age_sec > 0)); then
        if ! [[ "$issuer_sync_age_sec" =~ ^[0-9]+$ ]] || ((issuer_sync_age_sec > max_issuer_sync_age_sec)); then
          issuer_sync_ready="0"
        fi
      fi
      if [[ "$min_issuer_success_sources" =~ ^[0-9]+$ ]] && ((min_issuer_success_sources > 0)); then
        if ! [[ "$issuer_sources" =~ ^[0-9]+$ ]] || ((issuer_sources < min_issuer_success_sources)); then
          issuer_sync_ready="0"
        fi
      fi
      if [[ "$min_issuer_source_operators" =~ ^[0-9]+$ ]] && ((min_issuer_source_operators > 0)); then
        if ! [[ "$issuer_source_operators_count" =~ ^[0-9]+$ ]] || ((issuer_source_operators_count < min_issuer_source_operators)); then
          issuer_sync_ready="0"
        fi
      fi
      if issuer_sync_optional_no_sources \
        "$issuer_success" \
        "$issuer_quorum" \
        "$issuer_sources" \
        "$issuer_source_operators_count" \
        "$issuer_required" \
        "$issuer_error" \
        "$max_issuer_sync_age_sec" \
        "$min_issuer_success_sources" \
        "$min_issuer_source_operators"; then
        issuer_sync_required="0"
        issuer_sync_ready="1"
      fi
      if [[ "$configured_peers" =~ ^[0-9]+$ ]] && ((configured_peers > 0)); then
        if [[ "$require_configured_healthy" == "1" ]]; then
          if [[ "$configured_healthy" =~ ^[0-9]+$ ]] && ((configured_healthy >= configured_peers)); then
            peer_health_ready="1"
          fi
        elif [[ "$configured_healthy" =~ ^[0-9]+$ ]] && ((configured_healthy > 0)); then
          peer_health_ready="1"
        elif [[ "$discovered_eligible" =~ ^[0-9]+$ ]] && ((discovered_eligible > 0)); then
          peer_health_ready="1"
        fi
      elif [[ "$discovered_eligible" =~ ^[0-9]+$ ]] && ((discovered_eligible > 0)); then
        peer_health_ready="1"
      fi

      local current_failure_reasons_json
      current_failure_reasons_json="$(
        jq -nc \
          --argjson peer_last_run "$peer_last_run" \
          --argjson peer_success "$(if [[ "$peer_success" == "true" ]]; then echo "true"; else echo "false"; fi)" \
          --argjson peer_quorum "$(if [[ "$peer_quorum" == "true" ]]; then echo "true"; else echo "false"; fi)" \
          --argjson max_peer_sync_age_sec "$max_peer_sync_age_sec" \
          --argjson peer_sync_age_sec "$peer_sync_age_sec" \
          --argjson min_peer_success_sources "$min_peer_success_sources" \
          --argjson peer_sources "$peer_sources" \
          --argjson min_peer_source_operators "$min_peer_source_operators" \
          --argjson peer_source_operators_count "$peer_source_operators_count" \
          --argjson issuer_success "$(if [[ "$issuer_success" == "true" ]]; then echo "true"; else echo "false"; fi)" \
          --argjson issuer_quorum "$(if [[ "$issuer_quorum" == "true" ]]; then echo "true"; else echo "false"; fi)" \
          --argjson max_issuer_sync_age_sec "$max_issuer_sync_age_sec" \
          --argjson issuer_sync_age_sec "$issuer_sync_age_sec" \
          --argjson min_issuer_success_sources "$min_issuer_success_sources" \
          --argjson issuer_sources "$issuer_sources" \
          --argjson min_issuer_source_operators "$min_issuer_source_operators" \
          --argjson issuer_source_operators_count "$issuer_source_operators_count" \
          --argjson issuer_sync_required "$(if [[ "$issuer_sync_required" == "1" ]]; then echo "true"; else echo "false"; fi)" \
          --argjson require_configured_healthy "$(if [[ "$require_configured_healthy" == "1" ]]; then echo "true"; else echo "false"; fi)" \
          --argjson configured_peers "$configured_peers" \
          --argjson configured_healthy "$configured_healthy" \
          --argjson discovered_eligible "$discovered_eligible" \
          --argjson max_cooling_retry_sec "$max_cooling_retry_sec" \
          --argjson cooling_retry_max_sec "$cooling_retry_max_sec" \
          --argjson peer_sync_ready "$(if [[ "$peer_sync_ready" == "1" ]]; then echo "true"; else echo "false"; fi)" \
          --argjson issuer_sync_ready "$(if [[ "$issuer_sync_ready" == "1" ]]; then echo "true"; else echo "false"; fi)" \
          --argjson peer_health_ready "$(if [[ "$peer_health_ready" == "1" ]]; then echo "true"; else echo "false"; fi)" \
          '
          [
            (if $peer_last_run <= 0 then "peer_sync_not_started" else empty end),
            (if ($peer_success | not) then "peer_sync_not_success" else empty end),
            (if ($peer_quorum | not) then "peer_sync_quorum_not_met" else empty end),
            (if $max_peer_sync_age_sec > 0 and ($peer_sync_age_sec < 0 or $peer_sync_age_sec > $max_peer_sync_age_sec) then "peer_sync_age_stale" else empty end),
            (if $min_peer_success_sources > 0 and $peer_sources < $min_peer_success_sources then "peer_success_sources_below_floor" else empty end),
            (if $min_peer_source_operators > 0 and $peer_source_operators_count < $min_peer_source_operators then "peer_source_operators_below_floor" else empty end),
            (if $issuer_sync_required and ($issuer_success | not) then "issuer_sync_not_success" else empty end),
            (if $issuer_sync_required and ($issuer_quorum | not) then "issuer_sync_quorum_not_met" else empty end),
            (if $issuer_sync_required and $max_issuer_sync_age_sec > 0 and ($issuer_sync_age_sec < 0 or $issuer_sync_age_sec > $max_issuer_sync_age_sec) then "issuer_sync_age_stale" else empty end),
            (if $issuer_sync_required and $min_issuer_success_sources > 0 and $issuer_sources < $min_issuer_success_sources then "issuer_success_sources_below_floor" else empty end),
            (if $issuer_sync_required and $min_issuer_source_operators > 0 and $issuer_source_operators_count < $min_issuer_source_operators then "issuer_source_operators_below_floor" else empty end),
            (if $require_configured_healthy and $configured_peers > 0 and $configured_healthy < $configured_peers then "configured_peers_not_all_healthy" else empty end),
            (if ($configured_peers > 0 and ($require_configured_healthy | not) and $configured_healthy <= 0 and $discovered_eligible <= 0) then "no_healthy_or_discovered_eligible_peer" else empty end),
            (if ($configured_peers <= 0 and $discovered_eligible <= 0) then "no_discovered_eligible_peer" else empty end),
            (if $max_cooling_retry_sec > 0 and $cooling_retry_max_sec > $max_cooling_retry_sec then "cooling_retry_above_threshold" else empty end)
          ] | map(select(. != null)) | unique
          '
      )"
      if [[ "$peer_sync_ready" == "1" && "$issuer_sync_ready" == "1" && "$peer_health_ready" == "1" ]]; then
        current_failure_reasons_json='[]'
      fi
      last_failure_reasons_json="$current_failure_reasons_json"
      if [[ "$peer_sync_ready" == "1" && "$issuer_sync_ready" == "1" && "$peer_health_ready" == "1" ]]; then
        last_failure_state="ready"
      else
        last_failure_state="not_ready"
      fi

      if [[ "$max_cooling_retry_sec" =~ ^[0-9]+$ ]] && ((max_cooling_retry_sec > 0)) &&
        [[ "$cooling_retry_max_sec" =~ ^[0-9]+$ ]] && ((cooling_retry_max_sec > max_cooling_retry_sec)); then
        last_failure_state="cooling_retry_exceeded"
        if ! jq -e 'index("cooling_retry_above_threshold") != null' <<<"$last_failure_reasons_json" >/dev/null 2>&1; then
          last_failure_reasons_json="$(
            jq -nc --argjson base "$last_failure_reasons_json" '$base + ["cooling_retry_above_threshold"] | unique'
          )"
        fi
        echo "server-federation-wait: FAIL cooling retry window exceeds threshold (observed=${cooling_retry_max_sec}s threshold=${max_cooling_retry_sec}s)"
        echo "  peer_sync: success=$peer_success quorum_met=$peer_quorum success_sources=$peer_sources source_operator_count=$peer_source_operators_count last_run_at=$peer_last_run age_sec=$peer_sync_age_display"
        if [[ -n "$peer_source_operators" ]]; then
          echo "  peer_sync_source_operators: $peer_source_operators"
        fi
        echo "  issuer_sync: success=$issuer_success quorum_met=$issuer_quorum success_sources=$issuer_sources source_operator_count=$issuer_source_operators_count last_run_at=$issuer_last_run age_sec=$issuer_sync_age_display"
        if [[ -n "$issuer_source_operators" ]]; then
          echo "  issuer_sync_source_operators: $issuer_source_operators"
        fi
        echo "  peer_health: configured_failing=${configured_failing}/${configured_peers} discovered_eligible=$discovered_eligible cooling_retry_max_sec=$cooling_retry_max_sec"
        if [[ "$show_json" == "1" ]]; then
          echo "json:"
          jq -n --argjson sync "$last_sync_json" --argjson peer "$last_peer_json" \
            '{sync_status: $sync, peer_status: $peer}'
        fi
        emit_federation_wait_summary "fail" "$last_failure_state" "$last_failure_reasons_json" "$last_sync_json" "$last_peer_json"
        rm -f "$sync_body" "$peer_status_body"
        return 1
      fi

      last_peer_sync_ready="$peer_sync_ready"
      last_issuer_sync_ready="$issuer_sync_ready"
      last_peer_health_ready="$peer_health_ready"
      last_configured_peers="$configured_peers"
      last_configured_healthy="$configured_healthy"
      last_discovered_eligible="$discovered_eligible"
      last_peer_success="$peer_success"
      last_peer_quorum="$peer_quorum"
      last_peer_last_run="$peer_last_run"
      last_issuer_success="$issuer_success"
      last_issuer_quorum="$issuer_quorum"
      last_issuer_last_run="$issuer_last_run"
      last_peer_sync_age_sec="$peer_sync_age_sec"
      last_issuer_sync_age_sec="$issuer_sync_age_sec"
      last_peer_sources="$peer_sources"
      last_issuer_sources="$issuer_sources"
      last_peer_source_operators_count="$peer_source_operators_count"
      last_issuer_source_operators_count="$issuer_source_operators_count"
      last_peer_source_operators="$peer_source_operators"
      last_issuer_source_operators="$issuer_source_operators"
      last_configured_failing="$configured_failing"
      last_cooling_retry_max_sec="$cooling_retry_max_sec"

      if [[ "$peer_sync_ready" == "1" && "$issuer_sync_ready" == "1" && "$peer_health_ready" == "1" ]]; then
        echo "server-federation-wait: READY (attempts=$attempt elapsed_sec=$elapsed_sec)"
        echo "  peer_sync: success=$peer_success quorum_met=$peer_quorum success_sources=$peer_sources source_operator_count=$peer_source_operators_count last_run_at=$peer_last_run age_sec=$peer_sync_age_display"
        if [[ -n "$peer_source_operators" ]]; then
          echo "  peer_sync_source_operators: $peer_source_operators"
        fi
        echo "  issuer_sync: success=$issuer_success quorum_met=$issuer_quorum success_sources=$issuer_sources source_operator_count=$issuer_source_operators_count last_run_at=$issuer_last_run age_sec=$issuer_sync_age_display"
        if [[ -n "$issuer_source_operators" ]]; then
          echo "  issuer_sync_source_operators: $issuer_source_operators"
        fi
        echo "  peer_health: configured_healthy=${configured_healthy}/${configured_peers} configured_failing=$configured_failing discovered_eligible=$discovered_eligible cooling_retry_max_sec=$cooling_retry_max_sec"
        if [[ "$show_json" == "1" ]]; then
          echo "json:"
          jq -n --argjson sync "$last_sync_json" --argjson peer "$last_peer_json" \
            '{sync_status: $sync, peer_status: $peer}'
        fi
        emit_federation_wait_summary "ready" "ready" "$last_failure_reasons_json" "$last_sync_json" "$last_peer_json"
        rm -f "$sync_body" "$peer_status_body"
        return 0
      fi

      echo "server-federation-wait poll: attempt=$attempt remaining_sec=$remaining_sec peer_sync_ready=$peer_sync_ready issuer_sync_ready=$issuer_sync_ready peer_health_ready=$peer_health_ready peer_success_sources=$peer_sources issuer_success_sources=$issuer_sources peer_source_operators=$peer_source_operators_count issuer_source_operators=$issuer_source_operators_count peer_sync_age_sec=$peer_sync_age_display issuer_sync_age_sec=$issuer_sync_age_display configured_healthy=${configured_healthy}/${configured_peers} configured_failing=$configured_failing discovered_eligible=$discovered_eligible cooling_retry_max_sec=$cooling_retry_max_sec"
    else
      last_failure_state="admin_endpoints_unreachable"
      if [[ -z "$last_sync_json" || -z "$last_peer_json" ]]; then
        last_failure_reasons_json='["admin_endpoints_unreachable"]'
      fi
      echo "server-federation-wait poll: attempt=$attempt remaining_sec=$remaining_sec sync_code=${sync_code:-none} peer_status_code=${peer_status_code:-none} (waiting for admin endpoints)"
    fi

    rm -f "$sync_body" "$peer_status_body"

    if ((remaining_sec <= 0)); then
      break
    fi
    local sleep_sec="$poll_sec"
    if ((sleep_sec > remaining_sec)); then
      sleep_sec="$remaining_sec"
    fi
    sleep "$sleep_sec"
  done

  echo "server-federation-wait: TIMEOUT after ${ready_timeout_sec}s"
  local last_peer_sync_age_display last_issuer_sync_age_display
  last_peer_sync_age_display="n/a"
  if [[ "$last_peer_sync_age_sec" =~ ^[0-9]+$ ]] && ((last_peer_sync_age_sec >= 0)); then
    last_peer_sync_age_display="$last_peer_sync_age_sec"
  fi
  last_issuer_sync_age_display="n/a"
  if [[ "$last_issuer_sync_age_sec" =~ ^[0-9]+$ ]] && ((last_issuer_sync_age_sec >= 0)); then
    last_issuer_sync_age_display="$last_issuer_sync_age_sec"
  fi
  echo "  peer_sync_ready=$last_peer_sync_ready (success=$last_peer_success quorum_met=$last_peer_quorum success_sources=$last_peer_sources source_operator_count=$last_peer_source_operators_count last_run_at=$last_peer_last_run age_sec=$last_peer_sync_age_display)"
  if [[ -n "$last_peer_source_operators" ]]; then
    echo "  peer_sync_source_operators=$last_peer_source_operators"
  fi
  echo "  issuer_sync_ready=$last_issuer_sync_ready (success=$last_issuer_success quorum_met=$last_issuer_quorum success_sources=$last_issuer_sources source_operator_count=$last_issuer_source_operators_count last_run_at=$last_issuer_last_run age_sec=$last_issuer_sync_age_display)"
  if [[ -n "$last_issuer_source_operators" ]]; then
    echo "  issuer_sync_source_operators=$last_issuer_source_operators"
  fi
  echo "  peer_health_ready=$last_peer_health_ready (configured_healthy=${last_configured_healthy}/${last_configured_peers} configured_failing=$last_configured_failing discovered_eligible=$last_discovered_eligible cooling_retry_max_sec=$last_cooling_retry_max_sec)"
  echo "hints:"
  echo "  - run './scripts/easy_node.sh server-federation-status --directory-url ${directory_url}' for full per-peer diagnostics"
  echo "  - verify DIRECTORY_PEERS points at reachable peer directories and at least one healthy peer is available"
  echo "  - if a peer was decommissioned, remove it from DIRECTORY_PEERS or rely on discovered eligible peers"

  if [[ "$show_json" == "1" && -n "$last_sync_json" && -n "$last_peer_json" ]]; then
    echo "json:"
    jq -n --argjson sync "$last_sync_json" --argjson peer "$last_peer_json" \
      '{sync_status: $sync, peer_status: $peer}'
  fi
  local timeout_failure_reasons_json
  timeout_failure_reasons_json="$last_failure_reasons_json"
  if ! jq -e 'type == "array"' <<<"$timeout_failure_reasons_json" >/dev/null 2>&1; then
    timeout_failure_reasons_json='[]'
  fi
  if jq -e 'length == 0' <<<"$timeout_failure_reasons_json" >/dev/null 2>&1; then
    if [[ "$last_failure_state" == "admin_endpoints_unreachable" ]]; then
      timeout_failure_reasons_json='["admin_endpoints_unreachable"]'
    elif [[ "$last_peer_sync_ready" != "1" || "$last_issuer_sync_ready" != "1" || "$last_peer_health_ready" != "1" ]]; then
      timeout_failure_reasons_json='["federation_not_ready"]'
    fi
  fi
  emit_federation_wait_summary "timeout" "timeout" "$timeout_failure_reasons_json" "$last_sync_json" "$last_peer_json"
  return 1
}

server_logs() {
  local follow="0"
  local tail_lines="150"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --follow)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          follow="${2:-}"
          shift 2
        else
          follow="1"
          shift
        fi
        ;;
      --tail)
        if [[ $# -lt 2 ]]; then
          echo "server-logs requires --tail N"
          exit 2
        fi
        tail_lines="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for server-logs: $1"
        exit 2
        ;;
    esac
  done
  if [[ "$follow" != "0" && "$follow" != "1" ]]; then
    echo "server-logs requires --follow to be 0 or 1"
    exit 2
  fi
  if ! [[ "$tail_lines" =~ ^[0-9]+$ ]] || ((tail_lines < 1)); then
    echo "server-logs requires --tail to be >= 1"
    exit 2
  fi

  ensure_compose_deps_or_die
  local env_file mode
  env_file="$(active_server_env_file)"
  mode="$(active_server_mode)"
  local -a log_args
  log_args=(--tail "$tail_lines")
  if [[ "$follow" == "1" ]]; then
    log_args+=(--follow)
  fi
  if [[ "$mode" == "provider" ]]; then
    compose_with_env "$env_file" logs "${log_args[@]}" directory entry-exit
  else
    compose_with_env "$env_file" logs "${log_args[@]}" directory issuer entry-exit
  fi
}

server_session() {
  local cleanup_all="1"
  local -a forward_args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help|help)
        usage || true
        return 0
        ;;
      --cleanup-all)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          cleanup_all="${2:-}"
          shift 2
        else
          cleanup_all="1"
          shift
        fi
        ;;
      *)
        forward_args+=("$1")
        shift
        ;;
    esac
  done

  if [[ "$cleanup_all" != "0" && "$cleanup_all" != "1" ]]; then
    echo "server-session requires --cleanup-all to be 0 or 1"
    exit 2
  fi

  local cleanup_ran="0"
  cleanup_server_session() {
    if [[ "$cleanup_ran" == "1" ]]; then
      return
    fi
    cleanup_ran="1"
    if [[ "$cleanup_all" == "1" ]]; then
      echo "server-session cleanup: stop-all"
      stop_all --with-wg-only 1 --force-iface-cleanup 1 || true
    else
      echo "server-session cleanup: server-down"
      server_down || true
    fi
  }
  trap cleanup_server_session EXIT INT TERM

  server_up "${forward_args[@]}"
  echo "server-session: streaming live logs (Ctrl+C or close terminal to cleanup)"
  server_logs --follow 1 --tail 200
}

server_down() {
  clear_runtime_override_env_vars
  ensure_compose_deps_or_die
  local env_file
  env_file="$(active_server_env_file)"
  compose_with_env "$env_file" down --remove-orphans
}

rotate_server_secrets() {
  local restart="1"
  local rotate_issuer_admin="1"
  local show_secrets="0"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --restart)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          restart="${2:-}"
          shift 2
        else
          restart="1"
          shift
        fi
        ;;
      --rotate-issuer-admin)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          rotate_issuer_admin="${2:-}"
          shift 2
        else
          rotate_issuer_admin="1"
          shift
        fi
        ;;
      --show-secrets)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          show_secrets="${2:-}"
          shift 2
        else
          show_secrets="1"
          shift
        fi
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for rotate-server-secrets: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$restart" != "0" && "$restart" != "1" ]]; then
    echo "rotate-server-secrets requires --restart to be 0 or 1"
    exit 2
  fi
  if [[ "$rotate_issuer_admin" != "0" && "$rotate_issuer_admin" != "1" ]]; then
    echo "rotate-server-secrets requires --rotate-issuer-admin to be 0 or 1"
    exit 2
  fi
  if [[ "$show_secrets" != "0" && "$show_secrets" != "1" ]]; then
    echo "rotate-server-secrets requires --show-secrets to be 0 or 1"
    exit 2
  fi

  local mode env_file
  mode="$(active_server_mode)"
  env_file="$(active_server_env_file)"
  if [[ ! -f "$env_file" ]]; then
    echo "rotate-server-secrets requires existing env file: $env_file"
    exit 2
  fi

  local directory_admin_token entry_puzzle_secret issuer_admin_token=""
  local issuer_token_disabled="0"
  local issuer_allow_token=""
  directory_admin_token="$(random_token)"
  entry_puzzle_secret="$(random_token)"

  set_env_kv "$env_file" "DIRECTORY_ADMIN_TOKEN" "$directory_admin_token"
  set_env_kv "$env_file" "ENTRY_PUZZLE_SECRET" "$entry_puzzle_secret"

  if [[ "$mode" == "authority" && "$rotate_issuer_admin" == "1" ]]; then
    issuer_allow_token="$(identity_value "$env_file" "ISSUER_ADMIN_ALLOW_TOKEN")"
    if [[ "$issuer_allow_token" == "0" ]]; then
      issuer_token_disabled="1"
      set_env_kv "$env_file" "ISSUER_ADMIN_TOKEN" ""
    else
      issuer_admin_token="$(random_token)"
      set_env_kv "$env_file" "ISSUER_ADMIN_TOKEN" "$issuer_admin_token"
    fi
  fi
  secure_file_permissions "$env_file"

  if [[ "$restart" == "1" ]]; then
    ensure_compose_deps_or_die
    if [[ "$mode" == "authority" ]]; then
      compose_with_env "$env_file" up -d directory issuer entry-exit
    else
      compose_with_env "$env_file" up -d --no-deps directory entry-exit
    fi
  fi

  echo "server secrets rotated"
  echo "mode: $mode"
  echo "env file: $env_file"
  echo "restart: $restart"
  if [[ "$show_secrets" == "1" ]]; then
    echo "directory_admin_token: $directory_admin_token"
    echo "entry_puzzle_secret: $entry_puzzle_secret"
    if [[ "$issuer_token_disabled" == "1" ]]; then
      echo "issuer_admin_token: [disabled by ISSUER_ADMIN_ALLOW_TOKEN=0]"
    elif [[ -n "$issuer_admin_token" ]]; then
      echo "issuer_admin_token: $issuer_admin_token"
    elif [[ "$mode" == "authority" ]]; then
      echo "issuer_admin_token: [unchanged]"
    fi
  else
    echo "directory_admin_token: [hidden]"
    echo "entry_puzzle_secret: [hidden]"
    if [[ "$mode" == "authority" ]]; then
      if [[ "$issuer_token_disabled" == "1" ]]; then
        echo "issuer_admin_token: [disabled by ISSUER_ADMIN_ALLOW_TOKEN=0]"
      elif [[ "$rotate_issuer_admin" == "1" ]]; then
        echo "issuer_admin_token: [hidden]"
      else
        echo "issuer_admin_token: [unchanged]"
      fi
    fi
    echo "use --show-secrets 1 only when explicitly needed."
  fi
}

cleanup_client_demo_artifacts() {
  local stale_runs=""

  stale_runs="$(docker ps -aq --filter "name=deploy-client-demo-run-" || true)"
  if [[ -n "$stale_runs" ]]; then
    # Best-effort cleanup for interrupted client runs.
    docker rm -f $stale_runs >/dev/null 2>&1 || true
  fi

  # Remove dangling default network if it is no longer in use.
  if docker network inspect deploy_default >/dev/null 2>&1; then
    docker network rm deploy_default >/dev/null 2>&1 || true
  fi
}

stop_all() {
  local with_wg_only="1"
  local force_iface_cleanup="1"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --with-wg-only)
        if [[ $# -ge 2 && "${2:-}" != --* ]]; then
          with_wg_only="${2:-}"
          shift 2
        else
          with_wg_only="1"
          shift
        fi
        ;;
      --force-iface-cleanup)
        if [[ $# -ge 2 && "${2:-}" != --* ]]; then
          force_iface_cleanup="${2:-}"
          shift 2
        else
          force_iface_cleanup="1"
          shift
        fi
        ;;
      *)
        echo "unknown arg for stop-all: $1"
        exit 2
        ;;
    esac
  done
  if [[ "$with_wg_only" != "0" && "$with_wg_only" != "1" ]]; then
    echo "stop-all requires --with-wg-only to be 0 or 1"
    exit 2
  fi
  if [[ "$force_iface_cleanup" != "0" && "$force_iface_cleanup" != "1" ]]; then
    echo "stop-all requires --force-iface-cleanup to be 0 or 1"
    exit 2
  fi

  clear_runtime_override_env_vars
  ensure_compose_deps_or_die

  if [[ "$with_wg_only" == "1" ]]; then
    local state_file
    state_file="$(wg_only_state_file)"
    if [[ -f "$state_file" ]]; then
      if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        wg_only_stack_down --force-iface-cleanup "$force_iface_cleanup" >/dev/null 2>&1 || true
        echo "wg-only stack cleanup: done"
      else
        local pid
        pid="$(identity_value "$state_file" "WG_ONLY_PID")"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
          echo "wg-only stack cleanup: skipped (root required)."
          echo "run: sudo ./scripts/easy_node.sh wg-only-stack-down --force-iface-cleanup $force_iface_cleanup"
        else
          rm -f "$state_file" >/dev/null 2>&1 || true
          echo "wg-only stack cleanup: cleared stale state file"
        fi
      fi
    fi
  fi

  local client_vpn_state
  client_vpn_state="$(client_vpn_state_file)"
  if [[ -f "$client_vpn_state" ]]; then
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
      client_vpn_down --force-iface-cleanup "$force_iface_cleanup" --keep-key 1 >/dev/null 2>&1 || true
      echo "client-vpn cleanup: done"
    else
      local client_pid
      client_pid="$(identity_value "$client_vpn_state" "CLIENT_VPN_PID")"
      if [[ -n "$client_pid" ]] && kill -0 "$client_pid" >/dev/null 2>&1; then
        echo "client-vpn cleanup: skipped (root required)."
        echo "run: sudo ./scripts/easy_node.sh client-vpn-down --force-iface-cleanup $force_iface_cleanup"
      else
        rm -f "$client_vpn_state" >/dev/null 2>&1 || true
        echo "client-vpn cleanup: cleared stale state file"
      fi
    fi
  fi

  compose_with_env "$AUTHORITY_ENV_FILE" down --remove-orphans >/dev/null 2>&1 || true
  compose_with_env "$PROVIDER_ENV_FILE" down --remove-orphans >/dev/null 2>&1 || true
  (
    cd "$DEPLOY_DIR"
    env COMPOSE_INTERACTIVE_NO_CLI=1 COMPOSE_MENU=0 docker compose --profile demo down --remove-orphans >/dev/null 2>&1 || true
  )
  cleanup_client_demo_artifacts

  local compose_ids=""
  compose_ids="$(docker ps -aq --filter "label=com.docker.compose.project=deploy" || true)"
  if [[ -n "$compose_ids" ]]; then
    docker rm -f $compose_ids >/dev/null 2>&1 || true
  fi

  local compose_networks=""
  compose_networks="$(docker network ls -q --filter "label=com.docker.compose.project=deploy" || true)"
  if [[ -n "$compose_networks" ]]; then
    docker network rm $compose_networks >/dev/null 2>&1 || true
  fi

  echo "all local Privacynode docker resources are stopped"
}

install_deps_ubuntu() {
  local installer="$ROOT_DIR/scripts/install_deps_ubuntu.sh"
  if [[ ! -x "$installer" ]]; then
    echo "missing installer script: $installer"
    exit 2
  fi
  "$installer"
}

wg_only_check() {
  local ok=1
  echo "wg-only preflight checks:"
  if [[ "$(uname -s)" == "Linux" ]]; then
    echo "  [ok] linux kernel"
  else
    echo "  [fail] requires Linux (found: $(uname -s))"
    ok=0
  fi

  for cmd in go wg ip timeout rg curl; do
    if command -v "$cmd" >/dev/null 2>&1; then
      echo "  [ok] command: $cmd"
    else
      echo "  [fail] missing command: $cmd"
      ok=0
    fi
  done

  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    echo "  [ok] running as root"
  else
    echo "  [fail] root privileges required (re-run with sudo)"
    ok=0
  fi

  if [[ $ok -eq 1 ]]; then
    local probe_iface="wgpvtst$RANDOM"
    if ip link add dev "$probe_iface" type wireguard >/dev/null 2>&1; then
      ip link delete "$probe_iface" >/dev/null 2>&1 || true
      echo "  [ok] can create wireguard interface"
    else
      echo "  [fail] cannot create wireguard interface (kernel module/capabilities issue)"
      ok=0
    fi
  fi

  if [[ $ok -eq 1 ]]; then
    echo "wg-only preflight: ok"
    return 0
  fi
  echo "wg-only preflight: failed"
  return 1
}

wg_only_local_test() {
  local matrix="${EASY_NODE_WG_ONLY_MATRIX:-1}"
  local strict_beta="${EASY_NODE_WG_ONLY_STRICT_BETA:-1}"
  local timeout_sec="${EASY_NODE_WG_ONLY_TIMEOUT_SEC:-150}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --matrix)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          matrix="${2:-}"
          shift 2
        else
          matrix="1"
          shift
        fi
        ;;
      --strict-beta)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          strict_beta="${2:-}"
          shift 2
        else
          strict_beta="1"
          shift
        fi
        ;;
      --timeout-sec)
        timeout_sec="${2:-}"
        shift 2
        ;;
      *)
        echo "unknown arg for wg-only-local-test: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$matrix" != "0" && "$matrix" != "1" ]]; then
    echo "wg-only-local-test requires --matrix to be 0 or 1"
    exit 2
  fi
  if [[ "$strict_beta" != "0" && "$strict_beta" != "1" ]]; then
    echo "wg-only-local-test requires --strict-beta to be 0 or 1"
    exit 2
  fi
  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || ((timeout_sec < 30)); then
    echo "wg-only-local-test requires --timeout-sec >= 30"
    exit 2
  fi

  if ! wg_only_check; then
    exit 1
  fi

  local log_dir out
  log_dir="$(prepare_log_dir)"
  out="$log_dir/easy_node_wg_only_test_$(date +%Y%m%d_%H%M%S).log"
  rm -f "$out"

  echo "wg-only local test started"
  echo "matrix: $matrix"
  echo "strict_beta: $strict_beta"
  echo "timeout_sec: $timeout_sec"
  echo "report: $out"

  local -a cmd
  if [[ "$matrix" == "1" ]]; then
    cmd=("./scripts/integration_real_wg_privileged_matrix.sh")
  else
    cmd=(
      env
      "SCRIPT_TIMEOUT_SEC=$timeout_sec"
      "STRICT_BETA_PROFILE=$strict_beta"
      "./scripts/integration_real_wg_privileged.sh"
    )
  fi

  if "${cmd[@]}" >"$out" 2>&1; then
    echo "wg-only local test: ok"
    echo "log: $out"
    rg "real wg privileged integration check ok|real wg privileged matrix integration check ok|profile=.* ok" "$out" || true
    return 0
  fi

  echo "wg-only local test: failed"
  echo "log: $out"
  cat "$out"
  return 1
}

real_wg_privileged_matrix() {
  ensure_deps_or_die
  local script="${REAL_WG_PRIVILEGED_MATRIX_SCRIPT:-$ROOT_DIR/scripts/integration_real_wg_privileged_matrix.sh}"
  "$script" "$@"
}

real_wg_privileged_matrix_record() {
  ensure_deps_or_die
  local script="${REAL_WG_PRIVILEGED_MATRIX_RECORD_SCRIPT:-$ROOT_DIR/scripts/real_wg_privileged_matrix_record.sh}"
  "$script" "$@"
}

wg_only_state_file() {
  echo "$DEPLOY_DIR/data/wg_only_stack.state"
}

wg_only_stack_status() {
  local state_file
  state_file="$(wg_only_state_file)"
  if [[ ! -f "$state_file" ]]; then
    echo "wg-only stack status: not running"
    return 0
  fi

  local pid client_iface exit_iface log_file strict_beta dir_url issuer_url entry_url exit_url
  pid="$(identity_value "$state_file" "WG_ONLY_PID")"
  client_iface="$(identity_value "$state_file" "WG_ONLY_CLIENT_IFACE")"
  exit_iface="$(identity_value "$state_file" "WG_ONLY_EXIT_IFACE")"
  log_file="$(identity_value "$state_file" "WG_ONLY_LOG_FILE")"
  strict_beta="$(identity_value "$state_file" "WG_ONLY_STRICT_BETA")"
  dir_url="$(identity_value "$state_file" "WG_ONLY_DIRECTORY_URL")"
  issuer_url="$(identity_value "$state_file" "WG_ONLY_ISSUER_URL")"
  entry_url="$(identity_value "$state_file" "WG_ONLY_ENTRY_URL")"
  exit_url="$(identity_value "$state_file" "WG_ONLY_EXIT_URL")"

  local running="0"
  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    running="1"
  fi

  echo "wg-only stack status:"
  echo "  running: $running"
  echo "  pid: ${pid:-unknown}"
  echo "  strict_beta: ${strict_beta:-unknown}"
  echo "  client_iface: ${client_iface:-unknown}"
  echo "  exit_iface: ${exit_iface:-unknown}"
  echo "  directory_url: ${dir_url:-unknown}"
  echo "  issuer_url: ${issuer_url:-unknown}"
  echo "  entry_url: ${entry_url:-unknown}"
  echo "  exit_url: ${exit_url:-unknown}"
  echo "  log_file: ${log_file:-unknown}"
  if [[ "$running" == "0" ]]; then
    echo "note: state file is stale; run wg-only-stack-down to clean up."
  fi
  return 0
}

wg_only_stack_up() {
  local strict_beta="${EASY_NODE_WG_ONLY_STACK_STRICT_BETA:-1}"
  local detach="${EASY_NODE_WG_ONLY_STACK_DETACH:-1}"
  local base_port="${EASY_NODE_WG_ONLY_STACK_BASE_PORT:-19080}"
  local client_iface="${EASY_NODE_WG_ONLY_STACK_CLIENT_IFACE:-wgcstack0}"
  local exit_iface="${EASY_NODE_WG_ONLY_STACK_EXIT_IFACE:-wgestack0}"
  local control_bind_host="${EASY_NODE_WG_ONLY_STACK_CONTROL_BIND_HOST:-127.0.0.1}"
  local force_iface_reset="${EASY_NODE_WG_ONLY_STACK_FORCE_IFACE_RESET:-0}"
  local cleanup_ifaces="${EASY_NODE_WG_ONLY_STACK_CLEANUP_IFACES:-1}"
  local log_file="${EASY_NODE_WG_ONLY_STACK_LOG_FILE:-}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --strict-beta)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          strict_beta="${2:-}"
          shift 2
        else
          strict_beta="1"
          shift
        fi
        ;;
      --detach)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          detach="${2:-}"
          shift 2
        else
          detach="1"
          shift
        fi
        ;;
      --base-port)
        base_port="${2:-}"
        shift 2
        ;;
      --client-iface)
        client_iface="${2:-}"
        shift 2
        ;;
      --exit-iface)
        exit_iface="${2:-}"
        shift 2
        ;;
      --control-bind-host)
        control_bind_host="${2:-}"
        shift 2
        ;;
      --force-iface-reset)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          force_iface_reset="${2:-}"
          shift 2
        else
          force_iface_reset="1"
          shift
        fi
        ;;
      --cleanup-ifaces)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          cleanup_ifaces="${2:-}"
          shift 2
        else
          cleanup_ifaces="1"
          shift
        fi
        ;;
      --log-file)
        log_file="${2:-}"
        shift 2
        ;;
      *)
        echo "unknown arg for wg-only-stack-up: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$strict_beta" != "0" && "$strict_beta" != "1" ]]; then
    echo "wg-only-stack-up requires --strict-beta to be 0 or 1"
    exit 2
  fi
  if [[ "$detach" != "0" && "$detach" != "1" ]]; then
    echo "wg-only-stack-up requires --detach to be 0 or 1"
    exit 2
  fi
  if [[ "$force_iface_reset" != "0" && "$force_iface_reset" != "1" ]]; then
    echo "wg-only-stack-up requires --force-iface-reset to be 0 or 1"
    exit 2
  fi
  if [[ "$cleanup_ifaces" != "0" && "$cleanup_ifaces" != "1" ]]; then
    echo "wg-only-stack-up requires --cleanup-ifaces to be 0 or 1"
    exit 2
  fi
  if ! [[ "$base_port" =~ ^[0-9]+$ ]] || ((base_port < 1024 || base_port > 65400)); then
    echo "wg-only-stack-up requires --base-port in 1024..65400"
    exit 2
  fi
  if [[ -z "$client_iface" || -z "$exit_iface" ]]; then
    echo "wg-only-stack-up requires non-empty --client-iface and --exit-iface"
    exit 2
  fi
  if [[ -z "$control_bind_host" ]]; then
    echo "wg-only-stack-up requires non-empty --control-bind-host"
    exit 2
  fi

  if ! wg_only_check; then
    exit 1
  fi

  local state_file
  state_file="$(wg_only_state_file)"
  mkdir -p "$(dirname "$state_file")"
  if [[ -f "$state_file" ]]; then
    local existing_pid
    existing_pid="$(identity_value "$state_file" "WG_ONLY_PID")"
    if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" >/dev/null 2>&1; then
      echo "wg-only stack appears to be already running (pid=$existing_pid)"
      echo "use './scripts/easy_node.sh wg-only-stack-status' or './scripts/easy_node.sh wg-only-stack-down'"
      exit 1
    fi
    rm -f "$state_file"
  fi

  local dir_port issuer_port entry_port exit_port entry_data_port exit_data_port exit_wg_port proxy_port sink_port source_port
  dir_port=$((base_port + 1))
  issuer_port=$((base_port + 2))
  entry_port=$((base_port + 3))
  exit_port=$((base_port + 4))
  entry_data_port=$((base_port + 100))
  exit_data_port=$((base_port + 101))
  exit_wg_port=$((base_port + 102))
  proxy_port=$((base_port + 103))
  sink_port=$((base_port + 104))
  source_port=$((base_port + 105))
  if ((source_port > 65535)); then
    echo "wg-only-stack-up computed ports exceed 65535; lower --base-port"
    exit 2
  fi

  local -a stack_ports
  mapfile -t stack_ports < <(wg_only_port_list "$base_port")

  local directory_url issuer_url entry_url exit_url entry_data_addr exit_data_addr
  directory_url="http://127.0.0.1:${dir_port}"
  issuer_url="http://127.0.0.1:${issuer_port}"
  entry_url="http://127.0.0.1:${entry_port}"
  exit_url="http://127.0.0.1:${exit_port}"
  entry_data_addr="127.0.0.1:${entry_data_port}"
  exit_data_addr="127.0.0.1:${exit_data_port}"

  if [[ "$force_iface_reset" == "1" ]]; then
    ip link delete "$client_iface" >/dev/null 2>&1 || true
    ip link delete "$exit_iface" >/dev/null 2>&1 || true
    wg_only_kill_stale_ports "${stack_ports[@]}"
  fi
  if ip link show dev "$client_iface" >/dev/null 2>&1; then
    echo "wg-only-stack-up refused: interface '$client_iface' already exists"
    echo "use --force-iface-reset 1 or choose a different --client-iface"
    exit 1
  fi
  if ip link show dev "$exit_iface" >/dev/null 2>&1; then
    echo "wg-only-stack-up refused: interface '$exit_iface' already exists"
    echo "use --force-iface-reset 1 or choose a different --exit-iface"
    exit 1
  fi

  if ! ip link add dev "$client_iface" type wireguard >/dev/null 2>&1; then
    echo "failed to create wireguard interface '$client_iface'"
    exit 1
  fi
  if ! ip link add dev "$exit_iface" type wireguard >/dev/null 2>&1; then
    ip link delete "$client_iface" >/dev/null 2>&1 || true
    echo "failed to create wireguard interface '$exit_iface'"
    exit 1
  fi

  local key_dir client_key_file exit_key_file directory_key_file issuer_key_file
  local wg_only_trust_file entry_directory_trust_file
  local directory_admin_token issuer_admin_token client_wg_pub exit_wg_pub
  key_dir="$DEPLOY_DIR/data/wg_only"
  mkdir -p "$key_dir"
  client_key_file="$key_dir/client_${client_iface}.key"
  exit_key_file="$key_dir/exit_${exit_iface}.key"
  directory_key_file="$key_dir/directory_${base_port}_ed25519.key"
  issuer_key_file="$key_dir/issuer_${base_port}_ed25519.key"
  wg_only_trust_file="$key_dir/trusted_directory_keys_${base_port}.txt"
  entry_directory_trust_file="$key_dir/entry_trusted_directory_keys_${base_port}.txt"
  directory_admin_token="wg-only-directory-admin-token-${base_port}"
  issuer_admin_token="wg-only-issuer-admin-token-${base_port}"
  if [[ "$force_iface_reset" == "1" ]]; then
    rm -f "$wg_only_trust_file" "$entry_directory_trust_file"
  fi
  if [[ ! -f "$client_key_file" ]]; then
    (umask 077 && wg genkey >"$client_key_file")
  fi
  if [[ ! -f "$exit_key_file" ]]; then
    (umask 077 && wg genkey >"$exit_key_file")
  fi
  chmod 600 "$client_key_file" "$exit_key_file" 2>/dev/null || true
  if ! client_wg_pub="$(wg pubkey <"$client_key_file")"; then
    ip link delete "$client_iface" >/dev/null 2>&1 || true
    ip link delete "$exit_iface" >/dev/null 2>&1 || true
    echo "failed to derive client wireguard public key"
    exit 1
  fi
  if ! exit_wg_pub="$(wg pubkey <"$exit_key_file")"; then
    ip link delete "$client_iface" >/dev/null 2>&1 || true
    ip link delete "$exit_iface" >/dev/null 2>&1 || true
    echo "failed to derive exit wireguard public key"
    exit 1
  fi

  local log_dir
  log_dir="$(prepare_log_dir)"
  if [[ -z "$log_file" ]]; then
    log_file="$log_dir/easy_node_wg_only_stack_$(date +%Y%m%d_%H%M%S).log"
  fi
  mkdir -p "$(dirname "$log_file")"

  local -a env_vars
  env_vars=(
    "WG_ONLY_MODE=1"
    "DATA_PLANE_MODE=opaque"
    "DIRECTORY_ADDR=${control_bind_host}:${dir_port}"
    "ISSUER_ADDR=${control_bind_host}:${issuer_port}"
    "ENTRY_ADDR=${control_bind_host}:${entry_port}"
    "EXIT_ADDR=${control_bind_host}:${exit_port}"
    "DIRECTORY_PRIVATE_KEY_FILE=${directory_key_file}"
    "ISSUER_PRIVATE_KEY_FILE=${issuer_key_file}"
    "DIRECTORY_ADMIN_TOKEN=${directory_admin_token}"
    "ISSUER_ADMIN_TOKEN=${issuer_admin_token}"
    "DIRECTORY_URL=${directory_url}"
    "ISSUER_URL=${issuer_url}"
    "ENTRY_URL=${entry_url}"
    "EXIT_CONTROL_URL=${exit_url}"
    "ENTRY_DATA_ADDR=${entry_data_addr}"
    "ENTRY_ENDPOINT=${entry_data_addr}"
    "EXIT_DATA_ADDR=${exit_data_addr}"
    "EXIT_ENDPOINT=${exit_data_addr}"
    "CLIENT_WG_BACKEND=command"
    "WG_BACKEND=command"
    "CLIENT_WG_PRIVATE_KEY_PATH=${client_key_file}"
    "CLIENT_WG_PUBLIC_KEY=${client_wg_pub}"
    "EXIT_WG_PRIVATE_KEY_PATH=${exit_key_file}"
    "EXIT_WG_PUBKEY=${exit_wg_pub}"
    "CLIENT_WG_INTERFACE=${client_iface}"
    "EXIT_WG_INTERFACE=${exit_iface}"
    "CLIENT_WG_INSTALL_ROUTE=0"
    "CLIENT_WG_KERNEL_PROXY=1"
    "CLIENT_WG_PROXY_ADDR=127.0.0.1:${proxy_port}"
    "CLIENT_INNER_SOURCE=udp"
    "CLIENT_DISABLE_SYNTHETIC_FALLBACK=1"
    "CLIENT_LIVE_WG_MODE=1"
    "DIRECTORY_TRUST_STRICT=1"
    "DIRECTORY_TRUST_TOFU=1"
    "DIRECTORY_TRUSTED_KEYS_FILE=${wg_only_trust_file}"
    "ENTRY_LIVE_WG_MODE=1"
    "ENTRY_DIRECTORY_TRUST_STRICT=1"
    "ENTRY_DIRECTORY_TRUST_TOFU=1"
    "ENTRY_DIRECTORY_TRUSTED_KEYS_FILE=${entry_directory_trust_file}"
    "ENTRY_PUZZLE_DIFFICULTY=1"
    "EXIT_LIVE_WG_MODE=1"
    "EXIT_TOKEN_PROOF_REPLAY_GUARD=1"
    "EXIT_PEER_REBIND_SEC=0"
    "EXIT_STARTUP_SYNC_TIMEOUT_SEC=8"
    "CLIENT_STARTUP_SYNC_TIMEOUT_SEC=8"
    "EXIT_OPAQUE_SINK_ADDR=127.0.0.1:${sink_port}"
    "EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:${source_port}"
    "EXIT_WG_LISTEN_PORT=${exit_wg_port}"
    "EXIT_WG_KERNEL_PROXY=1"
  )

  if [[ "$strict_beta" == "1" ]]; then
    env_vars+=(
      "CLIENT_BETA_STRICT=1"
      "ENTRY_BETA_STRICT=1"
      "EXIT_BETA_STRICT=1"
      "CLIENT_REQUIRE_DISTINCT_OPERATORS=1"
      "ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1"
      "ENTRY_PUZZLE_SECRET=wg-only-entry-secret-0001"
      "ENTRY_OPERATOR_ID=op-entry"
      "EXIT_OPERATOR_ID=op-exit"
      "EXIT_OPAQUE_ECHO=0"
    )
  fi

  local pid=""
  if [[ "$detach" == "1" ]]; then
    local pid_tmp
    pid_tmp="$(mktemp)"
    (
      cd "$ROOT_DIR"
      nohup env "${env_vars[@]}" go run ./cmd/node --directory --issuer --entry --exit --client >"$log_file" 2>&1 &
      echo "$!" >"$pid_tmp"
    )
    pid="$(cat "$pid_tmp")"
    rm -f "$pid_tmp"
    sleep 1
    if [[ -z "$pid" ]] || ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "wg-only stack failed to start; log follows:"
      cat "$log_file"
      ip link delete "$client_iface" >/dev/null 2>&1 || true
      ip link delete "$exit_iface" >/dev/null 2>&1 || true
      exit 1
    fi

    if ! wait_http_ok "${directory_url}/v1/relays" "wg-only directory" 30; then
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
      ip link delete "$client_iface" >/dev/null 2>&1 || true
      ip link delete "$exit_iface" >/dev/null 2>&1 || true
      echo "wg-only stack did not become healthy; log follows:"
      cat "$log_file"
      exit 1
    fi
    if ! wait_http_ok "${issuer_url}/v1/pubkeys" "wg-only issuer" 30; then
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
      ip link delete "$client_iface" >/dev/null 2>&1 || true
      ip link delete "$exit_iface" >/dev/null 2>&1 || true
      echo "wg-only stack issuer did not become healthy; log follows:"
      cat "$log_file"
      exit 1
    fi
    if ! wait_http_ok "${entry_url}/v1/health" "wg-only entry" 30; then
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
      ip link delete "$client_iface" >/dev/null 2>&1 || true
      ip link delete "$exit_iface" >/dev/null 2>&1 || true
      echo "wg-only stack entry did not become healthy; log follows:"
      cat "$log_file"
      exit 1
    fi
    if ! wait_http_ok "${exit_url}/v1/health" "wg-only exit" 30; then
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
      ip link delete "$client_iface" >/dev/null 2>&1 || true
      ip link delete "$exit_iface" >/dev/null 2>&1 || true
      echo "wg-only stack exit did not become healthy; log follows:"
      cat "$log_file"
      exit 1
    fi

    cat >"$state_file" <<EOF_STATE
WG_ONLY_PID=$pid
WG_ONLY_CLIENT_IFACE=$client_iface
WG_ONLY_EXIT_IFACE=$exit_iface
WG_ONLY_LOG_FILE=$log_file
WG_ONLY_STRICT_BETA=$strict_beta
WG_ONLY_BASE_PORT=$base_port
WG_ONLY_CONTROL_BIND_HOST=$control_bind_host
WG_ONLY_CLEANUP_IFACES=$cleanup_ifaces
WG_ONLY_DIRECTORY_URL=$directory_url
WG_ONLY_ISSUER_URL=$issuer_url
WG_ONLY_ENTRY_URL=$entry_url
WG_ONLY_EXIT_URL=$exit_url
WG_ONLY_DIRECTORY_TRUST_FILE=$wg_only_trust_file
WG_ONLY_ENTRY_DIRECTORY_TRUST_FILE=$entry_directory_trust_file
EOF_STATE
    secure_file_permissions "$state_file"

    echo "wg-only stack started"
    echo "  pid: $pid"
    echo "  strict_beta: $strict_beta"
    echo "  directory: $directory_url"
    echo "  issuer: $issuer_url"
    echo "  entry: $entry_url"
    echo "  exit: $exit_url"
    echo "  log: $log_file"
    echo "use './scripts/easy_node.sh wg-only-stack-status' to inspect"
    echo "use './scripts/easy_node.sh wg-only-stack-down' to stop"
    return 0
  fi

  echo "wg-only stack starting in foreground (strict_beta=$strict_beta)"
  echo "log: $log_file"
  echo "press Ctrl+C to stop"
  (
    cd "$ROOT_DIR"
    env "${env_vars[@]}" go run ./cmd/node --directory --issuer --entry --exit --client
  ) 2>&1 | tee "$log_file"
  local rc=$?
  if [[ "$cleanup_ifaces" == "1" ]]; then
    ip link delete "$client_iface" >/dev/null 2>&1 || true
    ip link delete "$exit_iface" >/dev/null 2>&1 || true
  fi
  return "$rc"
}

wg_only_stack_down() {
  local force_iface_cleanup="0"
  local base_port=""
  local client_iface=""
  local exit_iface=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force-iface-cleanup)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          force_iface_cleanup="${2:-}"
          shift 2
        else
          force_iface_cleanup="1"
          shift
        fi
        ;;
      --base-port)
        base_port="${2:-}"
        shift 2
        ;;
      --client-iface)
        client_iface="${2:-}"
        shift 2
        ;;
      --exit-iface)
        exit_iface="${2:-}"
        shift 2
        ;;
      *)
        echo "unknown arg for wg-only-stack-down: $1"
        exit 2
        ;;
    esac
  done
  if [[ "$force_iface_cleanup" != "0" && "$force_iface_cleanup" != "1" ]]; then
    echo "wg-only-stack-down requires --force-iface-cleanup to be 0 or 1"
    exit 2
  fi
  if [[ -n "$base_port" ]] && ( ! [[ "$base_port" =~ ^[0-9]+$ ]] || ((base_port < 1024 || base_port > 65400)) ); then
    echo "wg-only-stack-down requires --base-port in 1024..65400"
    exit 2
  fi
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "wg-only-stack-down requires root privileges (run with sudo)"
    exit 1
  fi

  local state_file
  state_file="$(wg_only_state_file)"
  if [[ ! -f "$state_file" ]]; then
    if [[ "$force_iface_cleanup" == "1" ]]; then
      if [[ -z "$client_iface" ]]; then
        client_iface="${EASY_NODE_WG_ONLY_STACK_CLIENT_IFACE:-wgcstack0}"
      fi
      if [[ -z "$exit_iface" ]]; then
        exit_iface="${EASY_NODE_WG_ONLY_STACK_EXIT_IFACE:-wgestack0}"
      fi
      if [[ -n "$client_iface" ]]; then
        ip link delete "$client_iface" >/dev/null 2>&1 || true
      fi
      if [[ -n "$exit_iface" ]]; then
        ip link delete "$exit_iface" >/dev/null 2>&1 || true
      fi
      if [[ -n "$base_port" ]]; then
        local -a stack_ports
        mapfile -t stack_ports < <(wg_only_port_list "$base_port")
        wg_only_kill_stale_ports "${stack_ports[@]}"
      fi
      echo "wg-only stack state missing; forced cleanup applied"
    else
      echo "wg-only stack is not running (no state file)"
    fi
    return 0
  fi

  local pid cleanup_ifaces
  pid="$(identity_value "$state_file" "WG_ONLY_PID")"
  if [[ -z "$base_port" ]]; then
    base_port="$(identity_value "$state_file" "WG_ONLY_BASE_PORT")"
  fi
  if [[ -z "$client_iface" ]]; then
    client_iface="$(identity_value "$state_file" "WG_ONLY_CLIENT_IFACE")"
  fi
  if [[ -z "$exit_iface" ]]; then
    exit_iface="$(identity_value "$state_file" "WG_ONLY_EXIT_IFACE")"
  fi
  cleanup_ifaces="$(identity_value "$state_file" "WG_ONLY_CLEANUP_IFACES")"
  if [[ "$cleanup_ifaces" != "1" ]]; then
    cleanup_ifaces="0"
  fi

  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    local i
    for i in $(seq 1 20); do
      if ! kill -0 "$pid" >/dev/null 2>&1; then
        break
      fi
      sleep 0.2
    done
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
    echo "wg-only stack process stopped (pid=$pid)"
  else
    echo "wg-only stack process was not running"
  fi

  if [[ "$cleanup_ifaces" == "1" || "$force_iface_cleanup" == "1" ]]; then
    if [[ -n "$client_iface" ]]; then
      ip link delete "$client_iface" >/dev/null 2>&1 || true
    fi
    if [[ -n "$exit_iface" ]]; then
      ip link delete "$exit_iface" >/dev/null 2>&1 || true
    fi
    if [[ -n "$base_port" ]]; then
      local -a stack_ports
      mapfile -t stack_ports < <(wg_only_port_list "$base_port")
      wg_only_kill_stale_ports "${stack_ports[@]}"
    fi
    echo "wg-only stack interfaces cleaned up"
  else
    echo "wg-only stack interfaces left intact (set --force-iface-cleanup 1 to remove)"
  fi

  rm -f "$state_file"
  echo "wg-only stack state cleared"
  return 0
}

wg_only_stack_selftest() {
  local strict_beta="${EASY_NODE_WG_ONLY_SELFTEST_STRICT_BETA:-1}"
  local base_port="${EASY_NODE_WG_ONLY_SELFTEST_BASE_PORT:-19080}"
  local timeout_sec="${EASY_NODE_WG_ONLY_SELFTEST_TIMEOUT_SEC:-80}"
  local min_selection_lines="${EASY_NODE_WG_ONLY_SELFTEST_MIN_SELECTION_LINES:-8}"
  local force_iface_reset="${EASY_NODE_WG_ONLY_SELFTEST_FORCE_IFACE_RESET:-1}"
  local cleanup_ifaces="${EASY_NODE_WG_ONLY_SELFTEST_CLEANUP_IFACES:-1}"
  local keep_stack="${EASY_NODE_WG_ONLY_SELFTEST_KEEP_STACK:-0}"
  local client_iface="${EASY_NODE_WG_ONLY_STACK_CLIENT_IFACE:-wgcstack0}"
  local exit_iface="${EASY_NODE_WG_ONLY_STACK_EXIT_IFACE:-wgestack0}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --strict-beta)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          strict_beta="${2:-}"
          shift 2
        else
          strict_beta="1"
          shift
        fi
        ;;
      --base-port)
        base_port="${2:-}"
        shift 2
        ;;
      --timeout-sec)
        timeout_sec="${2:-}"
        shift 2
        ;;
      --min-selection-lines)
        min_selection_lines="${2:-}"
        shift 2
        ;;
      --client-iface)
        client_iface="${2:-}"
        shift 2
        ;;
      --exit-iface)
        exit_iface="${2:-}"
        shift 2
        ;;
      --force-iface-reset)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          force_iface_reset="${2:-}"
          shift 2
        else
          force_iface_reset="1"
          shift
        fi
        ;;
      --cleanup-ifaces)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          cleanup_ifaces="${2:-}"
          shift 2
        else
          cleanup_ifaces="1"
          shift
        fi
        ;;
      --keep-stack)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          keep_stack="${2:-}"
          shift 2
        else
          keep_stack="1"
          shift
        fi
        ;;
      *)
        echo "unknown arg for wg-only-stack-selftest: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$strict_beta" != "0" && "$strict_beta" != "1" ]]; then
    echo "wg-only-stack-selftest requires --strict-beta to be 0 or 1"
    exit 2
  fi
  if [[ "$force_iface_reset" != "0" && "$force_iface_reset" != "1" ]]; then
    echo "wg-only-stack-selftest requires --force-iface-reset to be 0 or 1"
    exit 2
  fi
  if [[ "$cleanup_ifaces" != "0" && "$cleanup_ifaces" != "1" ]]; then
    echo "wg-only-stack-selftest requires --cleanup-ifaces to be 0 or 1"
    exit 2
  fi
  if [[ "$keep_stack" != "0" && "$keep_stack" != "1" ]]; then
    echo "wg-only-stack-selftest requires --keep-stack to be 0 or 1"
    exit 2
  fi
  if ! [[ "$base_port" =~ ^[0-9]+$ ]] || ((base_port < 1024 || base_port > 65400)); then
    echo "wg-only-stack-selftest requires --base-port in 1024..65400"
    exit 2
  fi
  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || ((timeout_sec < 40)); then
    echo "wg-only-stack-selftest requires --timeout-sec >= 40"
    exit 2
  fi
  if ! [[ "$min_selection_lines" =~ ^[0-9]+$ ]] || ((min_selection_lines < 1)); then
    echo "wg-only-stack-selftest requires --min-selection-lines >= 1"
    exit 2
  fi
  if [[ -z "$client_iface" || -z "$exit_iface" ]]; then
    echo "wg-only-stack-selftest requires non-empty --client-iface and --exit-iface"
    exit 2
  fi

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "wg-only-stack-selftest requires root privileges (run with sudo)"
    exit 1
  fi

  local started="0"
  wg_only_stack_selftest_cleanup() {
    if [[ "$started" == "1" && "$keep_stack" == "0" ]]; then
      wg_only_stack_down \
        --force-iface-cleanup "$cleanup_ifaces" \
        --base-port "$base_port" \
        --client-iface "$client_iface" \
        --exit-iface "$exit_iface" >/dev/null 2>&1 || true
    fi
  }
  trap wg_only_stack_selftest_cleanup EXIT INT TERM

  echo "wg-only stack selftest: starting stack"
  wg_only_stack_up \
    --strict-beta "$strict_beta" \
    --detach 1 \
    --base-port "$base_port" \
    --client-iface "$client_iface" \
    --exit-iface "$exit_iface" \
    --control-bind-host "0.0.0.0" \
    --force-iface-reset "$force_iface_reset" \
    --cleanup-ifaces "$cleanup_ifaces"
  started="1"

  local state_file directory_url issuer_url entry_url exit_url log_file
  state_file="$(wg_only_state_file)"
  directory_url="$(identity_value "$state_file" "WG_ONLY_DIRECTORY_URL")"
  issuer_url="$(identity_value "$state_file" "WG_ONLY_ISSUER_URL")"
  entry_url="$(identity_value "$state_file" "WG_ONLY_ENTRY_URL")"
  exit_url="$(identity_value "$state_file" "WG_ONLY_EXIT_URL")"
  log_file="$(identity_value "$state_file" "WG_ONLY_LOG_FILE")"
  if [[ -z "$directory_url" || -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" || -z "$log_file" ]]; then
    echo "wg-only-stack-selftest failed: missing stack endpoint state"
    exit 1
  fi

  echo "wg-only stack selftest: running live-WG validation"
  local ready="0"
  local strict_log_ok="0"
  local exit_accept_ok="0"
  local metrics_ok="0"
  local relay_ok="0"
  local proxy_addr exit_metrics_url relay_json
  proxy_addr="127.0.0.1:$((base_port + 103))"
  exit_metrics_url="${exit_url%/}/v1/metrics"

  wait_for_wg_session_config() {
    local attempts="${1:-240}"
    local i
    for i in $(seq 1 "$attempts"); do
      if rg -q "client received wg-session config:" "$log_file"; then
        return 0
      fi
      sleep 0.2
    done
    return 1
  }

  if wait_for_wg_session_config 240; then
    ready="1"
  elif rg -q 'directory key is not trusted' "$log_file"; then
    local trust_reset_output=""
    echo "wg-only stack selftest: directory key mismatch detected; resetting pinned client trust (scoped)"
    if trust_reset_output="$(client_vpn_trust_reset --directory-urls "$directory_url" --trust-scope scoped 2>&1)"; then
      [[ -n "$trust_reset_output" ]] && printf '%s\n' "$trust_reset_output"
      echo "wg-only stack selftest: waiting for client bootstrap retry after trust reset"
      if wait_for_wg_session_config 240; then
        ready="1"
      fi
    else
      echo "wg-only stack selftest: client trust reset failed"
      [[ -n "$trust_reset_output" ]] && printf '%s\n' "$trust_reset_output"
      cat "$log_file"
      exit 1
    fi
  fi
  if [[ "$ready" != "1" ]]; then
    echo "wg-only stack selftest: client did not receive wg-session config"
    cat "$log_file"
    exit 1
  fi

  relay_json="$(curl -fsS "${directory_url%/}/v1/relays" || true)"
  if echo "$relay_json" | rg -q '"role":"entry"[^\}]*"operator_id":"op-entry"' &&
    echo "$relay_json" | rg -q '"role":"exit"[^\}]*"operator_id":"op-exit"'; then
    relay_ok="1"
  fi

  for _ in $(seq 1 6); do
    perl -MIO::Socket::INET -e '
      my $target = shift @ARGV;
      my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or exit 1;
      my $pkt = pack("C4", 4, 0, 0, 0) . ("\0" x 28);
      print {$sock} $pkt or exit 1;
    ' "$proxy_addr"
    sleep 0.12
  done

  for _ in $(seq 1 140); do
    if rg -q "client role enabled: .*mode=opaque .*source=udp .*wg_backend=command .*wg_only=true .*beta_strict=true" "$log_file" &&
      rg -q "entry route discovery: .*live_wg_mode=true .*wg_only=true .*distinct_exit_operator=true operator_id=op-entry" "$log_file" &&
      rg -q "exit wg backend=command .*wg_only=true .*beta_strict=true" "$log_file"; then
      strict_log_ok="1"
    fi
    if rg -q "exit accepted opaque packet session=.*wg_like=true" "$log_file"; then
      exit_accept_ok="1"
    fi
    local m
    m="$(curl -fsS "$exit_metrics_url" || true)"
    if echo "$m" | rg -q '"accepted_packets"[[:space:]]*:[[:space:]]*[1-9][0-9]*' &&
      echo "$m" | rg -q '"wg_proxy_created"[[:space:]]*:[[:space:]]*[1-9][0-9]*'; then
      metrics_ok="1"
    fi
    if [[ "$strict_log_ok" == "1" && "$relay_ok" == "1" && ( "$exit_accept_ok" == "1" || "$metrics_ok" == "1" ) ]]; then
      break
    fi
    sleep 0.2
  done

  if [[ "$relay_ok" != "1" ]]; then
    echo "wg-only stack selftest: relay operator metadata missing"
    echo "$relay_json"
    cat "$log_file"
    exit 1
  fi
  if [[ "$strict_log_ok" != "1" ]]; then
    echo "wg-only stack selftest: missing strict live-WG startup log signals"
    cat "$log_file"
    exit 1
  fi
  if [[ "$exit_accept_ok" != "1" && "$metrics_ok" != "1" ]]; then
    echo "wg-only stack selftest: missing live-WG dataplane acceptance signals"
    echo "latest exit metrics: $(curl -fsS "$exit_metrics_url" || true)"
    echo "wg-only stack selftest: failed"
    cat "$log_file"
    exit 1
  fi

  if [[ "$keep_stack" == "1" ]]; then
    echo "wg-only stack selftest: ok (stack left running)"
    trap - EXIT INT TERM
    return 0
  fi

  wg_only_stack_down \
    --force-iface-cleanup "$cleanup_ifaces" \
    --base-port "$base_port" \
    --client-iface "$client_iface" \
    --exit-iface "$exit_iface"
  started="0"
  trap - EXIT INT TERM
  echo "wg-only stack selftest: ok"
  return 0
}

three_machine_validate() {
  ensure_deps_or_die
  local default_script="$ROOT_DIR/scripts/integration_3machine_beta_validate.sh"
  local script="${THREE_MACHINE_BETA_VALIDATE_SCRIPT:-$default_script}"
  local ci_stub_mode="${THREE_MACHINE_VALIDATE_CI_STUB_MODE:-}"
  local forwarded_path_profile="${EASY_NODE_PATH_PROFILE:-}"
  local arg_path_profile=""
  local prev=""
  local arg
  for arg in "$@"; do
    if [[ "$prev" == "--path-profile" ]]; then
      arg_path_profile="$arg"
    fi
    prev="$arg"
  done
  if [[ -n "$arg_path_profile" ]]; then
    forwarded_path_profile="$arg_path_profile"
  fi
  if [[ -z "$ci_stub_mode" ]]; then
    if [[ "$script" != "$default_script" ]]; then
      ci_stub_mode="1"
    else
      ci_stub_mode="0"
    fi
  fi
  if [[ "$ci_stub_mode" != "0" && "$ci_stub_mode" != "1" ]]; then
    echo "three-machine-validate requires THREE_MACHINE_VALIDATE_CI_STUB_MODE to be 0 or 1 when set"
    exit 2
  fi
  if [[ -n "$forwarded_path_profile" ]]; then
    EASY_NODE_PATH_PROFILE="$forwarded_path_profile" THREE_MACHINE_VALIDATE_CI_STUB_MODE="$ci_stub_mode" "$script" "$@"
    return
  fi
  THREE_MACHINE_VALIDATE_CI_STUB_MODE="$ci_stub_mode" "$script" "$@"
}

three_machine_soak() {
  ensure_deps_or_die
  local script="${THREE_MACHINE_BETA_SOAK_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_beta_soak.sh}"
  local forwarded_path_profile="${EASY_NODE_PATH_PROFILE:-}"
  local arg_path_profile=""
  local prev=""
  local arg
  for arg in "$@"; do
    if [[ "$prev" == "--path-profile" ]]; then
      arg_path_profile="$arg"
    fi
    prev="$arg"
  done
  if [[ -n "$arg_path_profile" ]]; then
    forwarded_path_profile="$arg_path_profile"
  fi
  if [[ -n "$forwarded_path_profile" ]]; then
    EASY_NODE_PATH_PROFILE="$forwarded_path_profile" "$script" "$@"
    return
  fi
  "$script" "$@"
}

three_machine_prod_gate() {
  ensure_deps_or_die
  local gate_script="${THREE_MACHINE_PROD_GATE_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_prod_gate.sh}"
  "$gate_script" "$@"
}

three_machine_docker_readiness() {
  ensure_deps_or_die
  local script="${THREE_MACHINE_DOCKER_READINESS_SCRIPT:-$ROOT_DIR/scripts/three_machine_docker_readiness.sh}"
  "$script" "$@"
}

three_machine_docker_profile_matrix() {
  ensure_deps_or_die
  local script="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_SCRIPT:-$ROOT_DIR/scripts/three_machine_docker_profile_matrix.sh}"
  "$script" "$@"
}

three_machine_docker_profile_matrix_record() {
  ensure_deps_or_die
  local script="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_SCRIPT:-$ROOT_DIR/scripts/three_machine_docker_profile_matrix_record.sh}"
  "$script" "$@"
}

three_machine_docker_readiness_record() {
  ensure_deps_or_die
  local script="${THREE_MACHINE_DOCKER_READINESS_RECORD_SCRIPT:-$ROOT_DIR/scripts/three_machine_docker_readiness_record.sh}"
  "$script" "$@"
}

three_machine_prod_bundle() {
  ensure_deps_or_die
  local bundle_script="${THREE_MACHINE_PROD_BUNDLE_SCRIPT:-$ROOT_DIR/scripts/prod_gate_bundle.sh}"
  local verify_script="${THREE_MACHINE_PROD_GATE_BUNDLE_VERIFY_SCRIPT:-$ROOT_DIR/scripts/prod_gate_bundle_verify.sh}"
  local preflight_script="${THREE_MACHINE_PROD_BUNDLE_PREFLIGHT_SCRIPT:-}"
  local preflight_check="${EASY_NODE_PROD_BUNDLE_PREFLIGHT_CHECK:-1}"
  local preflight_timeout_sec="${EASY_NODE_PROD_BUNDLE_PREFLIGHT_TIMEOUT_SEC:-12}"
  local preflight_require_root="${EASY_NODE_PROD_BUNDLE_PREFLIGHT_REQUIRE_ROOT:-1}"
  local bundle_verify_check="${EASY_NODE_PROD_BUNDLE_VERIFY_CHECK:-1}"
  local bundle_verify_show_details="${EASY_NODE_PROD_BUNDLE_VERIFY_SHOW_DETAILS:-0}"
  local run_report_json="${EASY_NODE_PROD_BUNDLE_RUN_REPORT_JSON:-}"
  local run_report_print="${EASY_NODE_PROD_BUNDLE_RUN_REPORT_PRINT:-1}"
  local incident_snapshot_on_fail="${EASY_NODE_PROD_BUNDLE_INCIDENT_SNAPSHOT_ON_FAIL:-1}"
  local incident_snapshot_include_docker_logs="${EASY_NODE_PROD_BUNDLE_INCIDENT_SNAPSHOT_INCLUDE_DOCKER_LOGS:-1}"
  local incident_snapshot_docker_log_lines="${EASY_NODE_PROD_BUNDLE_INCIDENT_SNAPSHOT_DOCKER_LOG_LINES:-120}"
  local incident_snapshot_timeout_sec="${EASY_NODE_PROD_BUNDLE_INCIDENT_SNAPSHOT_TIMEOUT_SEC:-8}"
  local incident_snapshot_compose_project="${EASY_NODE_PROD_BUNDLE_INCIDENT_SNAPSHOT_COMPOSE_PROJECT:-deploy}"
  local snapshot_script="${INCIDENT_SNAPSHOT_SCRIPT:-$ROOT_DIR/scripts/incident_snapshot.sh}"
  local -a incident_snapshot_attach_artifacts=()
  local skip_wg="0"
  local discovery_wait_sec="${EASY_NODE_DISCOVERY_WAIT_SEC:-20}"
  local bootstrap_directory=""
  local bundle_dir=""
  local directory_a=""
  local directory_b=""
  local issuer_url=""
  local entry_url=""
  local exit_url=""
  local mtls_ca_file="$DEPLOY_DIR/tls/ca.crt"
  local mtls_client_cert_file="$DEPLOY_DIR/tls/client.crt"
  local mtls_client_key_file="$DEPLOY_DIR/tls/client.key"
  local -a bundle_args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --preflight-check)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          preflight_check="${2:-}"
          shift 2
        else
          preflight_check="1"
          shift
        fi
        ;;
      --preflight-timeout-sec)
        preflight_timeout_sec="${2:-}"
        shift 2
        ;;
      --preflight-require-root)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          preflight_require_root="${2:-}"
          shift 2
        else
          preflight_require_root="1"
          shift
        fi
        ;;
      --bundle-verify-check)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          bundle_verify_check="${2:-}"
          shift 2
        else
          bundle_verify_check="1"
          shift
        fi
        ;;
      --bundle-verify-show-details)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          bundle_verify_show_details="${2:-}"
          shift 2
        else
          bundle_verify_show_details="1"
          shift
        fi
        ;;
      --run-report-json)
        run_report_json="${2:-}"
        shift 2
        ;;
      --run-report-print)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          run_report_print="${2:-}"
          shift 2
        else
          run_report_print="1"
          shift
        fi
        ;;
      --incident-snapshot-on-fail)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          incident_snapshot_on_fail="${2:-}"
          shift 2
        else
          incident_snapshot_on_fail="1"
          shift
        fi
        ;;
      --incident-snapshot-include-docker-logs)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          incident_snapshot_include_docker_logs="${2:-}"
          shift 2
        else
          incident_snapshot_include_docker_logs="1"
          shift
        fi
        ;;
      --incident-snapshot-docker-log-lines)
        incident_snapshot_docker_log_lines="${2:-}"
        shift 2
        ;;
      --incident-snapshot-timeout-sec)
        incident_snapshot_timeout_sec="${2:-}"
        shift 2
        ;;
      --incident-snapshot-compose-project)
        incident_snapshot_compose_project="${2:-}"
        shift 2
        ;;
      --incident-snapshot-attach-artifact)
        incident_snapshot_attach_artifacts+=("${2:-}")
        shift 2
        ;;
      --bundle-dir)
        bundle_dir="${2:-}"
        shift 2
        ;;
      --bootstrap-directory)
        bootstrap_directory="${2:-}"
        bundle_args+=("$1" "${2:-}")
        shift 2
        ;;
      --directory-a)
        directory_a="${2:-}"
        bundle_args+=("$1" "${2:-}")
        shift 2
        ;;
      --directory-b)
        directory_b="${2:-}"
        bundle_args+=("$1" "${2:-}")
        shift 2
        ;;
      --issuer-url)
        issuer_url="${2:-}"
        bundle_args+=("$1" "${2:-}")
        shift 2
        ;;
      --entry-url)
        entry_url="${2:-}"
        bundle_args+=("$1" "${2:-}")
        shift 2
        ;;
      --exit-url)
        exit_url="${2:-}"
        bundle_args+=("$1" "${2:-}")
        shift 2
        ;;
      --discovery-wait-sec)
        discovery_wait_sec="${2:-}"
        bundle_args+=("$1" "${2:-}")
        shift 2
        ;;
      --mtls-ca-file)
        mtls_ca_file="${2:-}"
        bundle_args+=("$1" "${2:-}")
        shift 2
        ;;
      --mtls-client-cert-file)
        mtls_client_cert_file="${2:-}"
        bundle_args+=("$1" "${2:-}")
        shift 2
        ;;
      --mtls-client-key-file)
        mtls_client_key_file="${2:-}"
        bundle_args+=("$1" "${2:-}")
        shift 2
        ;;
      --skip-wg)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          skip_wg="${2:-}"
          bundle_args+=("$1" "${2:-}")
          shift 2
        else
          skip_wg="1"
          bundle_args+=("$1" "1")
          shift
        fi
        ;;
      *)
        bundle_args+=("$1")
        shift
        ;;
    esac
  done

  if [[ "$preflight_check" != "0" && "$preflight_check" != "1" ]]; then
    echo "three-machine-prod-bundle requires --preflight-check 0 or 1"
    exit 2
  fi
  if [[ "$preflight_require_root" != "0" && "$preflight_require_root" != "1" ]]; then
    echo "three-machine-prod-bundle requires --preflight-require-root 0 or 1"
    exit 2
  fi
  if [[ "$bundle_verify_check" != "0" && "$bundle_verify_check" != "1" ]]; then
    echo "three-machine-prod-bundle requires --bundle-verify-check 0 or 1"
    exit 2
  fi
  if [[ "$bundle_verify_show_details" != "0" && "$bundle_verify_show_details" != "1" ]]; then
    echo "three-machine-prod-bundle requires --bundle-verify-show-details 0 or 1"
    exit 2
  fi
  if [[ "$run_report_print" != "0" && "$run_report_print" != "1" ]]; then
    echo "three-machine-prod-bundle requires --run-report-print 0 or 1"
    exit 2
  fi
  if [[ "$incident_snapshot_on_fail" != "0" && "$incident_snapshot_on_fail" != "1" ]]; then
    echo "three-machine-prod-bundle requires --incident-snapshot-on-fail 0 or 1"
    exit 2
  fi
  if [[ "$incident_snapshot_include_docker_logs" != "0" && "$incident_snapshot_include_docker_logs" != "1" ]]; then
    echo "three-machine-prod-bundle requires --incident-snapshot-include-docker-logs 0 or 1"
    exit 2
  fi
  if [[ ! "$preflight_timeout_sec" =~ ^[0-9]+$ ]] || ((preflight_timeout_sec < 1)); then
    echo "three-machine-prod-bundle requires --preflight-timeout-sec >= 1"
    exit 2
  fi
  if [[ ! "$incident_snapshot_docker_log_lines" =~ ^[0-9]+$ ]] || ((incident_snapshot_docker_log_lines < 1)); then
    echo "three-machine-prod-bundle requires --incident-snapshot-docker-log-lines >= 1"
    exit 2
  fi
  if [[ ! "$incident_snapshot_timeout_sec" =~ ^[0-9]+$ ]] || ((incident_snapshot_timeout_sec < 1)); then
    echo "three-machine-prod-bundle requires --incident-snapshot-timeout-sec >= 1"
    exit 2
  fi
  local incident_attachment
  for incident_attachment in "${incident_snapshot_attach_artifacts[@]}"; do
    if [[ -z "$incident_attachment" ]]; then
      echo "three-machine-prod-bundle requires non-empty --incident-snapshot-attach-artifact values"
      exit 2
    fi
  done
  if [[ -z "$bundle_dir" ]]; then
    bundle_dir="$(prepare_log_dir)/prod_gate_bundle_$(date +%Y%m%d_%H%M%S)"
  elif [[ "$bundle_dir" != /* ]]; then
    bundle_dir="$ROOT_DIR/$bundle_dir"
  fi
  if [[ -z "$run_report_json" ]]; then
    run_report_json="$bundle_dir/prod_bundle_run_report.json"
  elif [[ "$run_report_json" != /* ]]; then
    run_report_json="$ROOT_DIR/$run_report_json"
  fi
  bundle_args+=(--bundle-dir "$bundle_dir")

  local preflight_rc="-1"
  local preflight_status="skipped"
  local bundle_rc="-1"
  local bundle_status="skipped"
  local bundle_verify_rc="-1"
  local bundle_verify_status="skipped"
  local incident_snapshot_rc="-1"
  local incident_snapshot_status="skipped"
  local incident_snapshot_bundle_dir=""
  local incident_snapshot_bundle_tar=""
  local incident_snapshot_summary_json=""
  local incident_snapshot_report_md=""
  local incident_snapshot_attachment_manifest=""
  local incident_snapshot_attachment_skipped=""
  local incident_snapshot_attachment_count="0"
  local final_rc=0

  local bundle_tar="${bundle_dir}.tar.gz"
  local bundle_tar_sha256_file="${bundle_tar}.sha256"
  local manifest_file="$bundle_dir/manifest.sha256"
  local metadata_file="$bundle_dir/metadata.txt"
  local gate_summary_json="$bundle_dir/prod_gate_summary.json"
  local wg_validate_summary_json="$bundle_dir/prod_wg_validate_summary.json"
  local wg_soak_summary_json="$bundle_dir/prod_wg_soak_summary.json"

  json_escape_prod_bundle() {
    local s="${1-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  bool_to_json_prod_bundle() {
    case "${1:-}" in
      0) printf 'false' ;;
      1) printf 'true' ;;
      *) printf 'null' ;;
    esac
  }

  num_to_json_prod_bundle() {
    local v="${1:-}"
    if [[ "$v" =~ ^-?[0-9]+$ ]]; then
      printf '%s' "$v"
    else
      printf 'null'
    fi
  }

  json_array_strings_prod_bundle() {
    local first="1"
    local value
    printf '['
    for value in "$@"; do
      if [[ "$first" == "0" ]]; then
        printf ','
      fi
      first="0"
      printf '"%s"' "$(json_escape_prod_bundle "$value")"
    done
    printf ']'
  }

  metadata_value_prod_bundle() {
    local key="$1"
    local file="$2"
    if [[ ! -f "$file" ]]; then
      return 0
    fi
    sed -nE "s/^${key}=//p" "$file" | head -n1
  }

  write_prod_bundle_run_report() {
    local parent
    parent="$(dirname "$run_report_json")"
    mkdir -p "$parent"

    local gate_rc_meta signoff_enabled_meta signoff_rc_meta
    gate_rc_meta="$(metadata_value_prod_bundle "gate_rc" "$metadata_file")"
    signoff_enabled_meta="$(metadata_value_prod_bundle "signoff_enabled" "$metadata_file")"
    signoff_rc_meta="$(metadata_value_prod_bundle "signoff_rc" "$metadata_file")"

    local overall_status="ok"
    if ((final_rc != 0)); then
      overall_status="fail"
    fi
    local bundle_exists="0"
    [[ -f "$bundle_tar" ]] && bundle_exists="1"
    local manifest_exists="0"
    [[ -f "$manifest_file" ]] && manifest_exists="1"

    local generated_at_utc
    generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local incident_snapshot_requested_attachments_json
    incident_snapshot_requested_attachments_json="$(json_array_strings_prod_bundle "${incident_snapshot_attach_artifacts[@]}")"

    cat >"$run_report_json" <<EOF
{
  "version": 1,
  "generated_at_utc": "$(json_escape_prod_bundle "$generated_at_utc")",
  "status": "$(json_escape_prod_bundle "$overall_status")",
  "final_rc": $(num_to_json_prod_bundle "$final_rc"),
  "bundle_dir": "$(json_escape_prod_bundle "$bundle_dir")",
  "bundle_tar": "$(json_escape_prod_bundle "$bundle_tar")",
  "bundle_tar_sha256_file": "$(json_escape_prod_bundle "$bundle_tar_sha256_file")",
  "manifest_file": "$(json_escape_prod_bundle "$manifest_file")",
  "metadata_file": "$(json_escape_prod_bundle "$metadata_file")",
  "gate_summary_json": "$(json_escape_prod_bundle "$gate_summary_json")",
  "wg_validate_summary_json": "$(json_escape_prod_bundle "$wg_validate_summary_json")",
  "wg_soak_summary_json": "$(json_escape_prod_bundle "$wg_soak_summary_json")",
  "preflight": {
    "enabled": $(bool_to_json_prod_bundle "$preflight_check"),
    "status": "$(json_escape_prod_bundle "$preflight_status")",
    "rc": $(num_to_json_prod_bundle "$preflight_rc")
  },
  "bundle": {
    "status": "$(json_escape_prod_bundle "$bundle_status")",
    "rc": $(num_to_json_prod_bundle "$bundle_rc"),
    "tar_exists": $(bool_to_json_prod_bundle "$bundle_exists"),
    "manifest_exists": $(bool_to_json_prod_bundle "$manifest_exists")
  },
  "integrity_verify": {
    "enabled": $(bool_to_json_prod_bundle "$bundle_verify_check"),
    "status": "$(json_escape_prod_bundle "$bundle_verify_status")",
    "rc": $(num_to_json_prod_bundle "$bundle_verify_rc")
  },
  "incident_snapshot": {
    "enabled": $(bool_to_json_prod_bundle "$incident_snapshot_on_fail"),
    "enabled_on_fail": $(bool_to_json_prod_bundle "$incident_snapshot_on_fail"),
    "status": "$(json_escape_prod_bundle "$incident_snapshot_status")",
    "rc": $(num_to_json_prod_bundle "$incident_snapshot_rc"),
    "bundle_dir": "$(json_escape_prod_bundle "$incident_snapshot_bundle_dir")",
    "bundle_tar": "$(json_escape_prod_bundle "$incident_snapshot_bundle_tar")",
    "summary_json": "$(json_escape_prod_bundle "$incident_snapshot_summary_json")",
    "report_md": "$(json_escape_prod_bundle "$incident_snapshot_report_md")",
    "attachment_manifest": "$(json_escape_prod_bundle "$incident_snapshot_attachment_manifest")",
    "attachment_skipped": "$(json_escape_prod_bundle "$incident_snapshot_attachment_skipped")",
    "attachment_count": $(num_to_json_prod_bundle "$incident_snapshot_attachment_count"),
    "requested_attachment_inputs": $incident_snapshot_requested_attachments_json
  },
  "gate": {
    "rc": $(num_to_json_prod_bundle "$gate_rc_meta")
  },
  "signoff": {
    "enabled": $(bool_to_json_prod_bundle "$signoff_enabled_meta"),
    "rc": $(num_to_json_prod_bundle "$signoff_rc_meta")
  }
}
EOF
  }

  if [[ "$preflight_check" == "1" ]]; then
    preflight_status="ok"
    preflight_rc=0
    local using_https_endpoints="0"
    if [[ "$bootstrap_directory" == https://* || "$directory_a" == https://* || "$directory_b" == https://* || "$issuer_url" == https://* || "$entry_url" == https://* || "$exit_url" == https://* ]]; then
      using_https_endpoints="1"
    fi
    local preflight_require_root_effective="$preflight_require_root"
    if [[ "$skip_wg" == "1" ]]; then
      preflight_require_root_effective="0"
    fi

    local -a preflight_args
    preflight_args=(
      --discovery-wait-sec "$discovery_wait_sec"
      --prod-profile 1
      --operator-floor-check 1
      --issuer-quorum-check 1
      --issuer-min-operators 2
      --timeout-sec "$preflight_timeout_sec"
      --require-root "$preflight_require_root_effective"
      --mtls-ca-file "$mtls_ca_file"
      --mtls-client-cert-file "$mtls_client_cert_file"
      --mtls-client-key-file "$mtls_client_key_file"
    )
    if [[ -n "$bootstrap_directory" ]]; then
      preflight_args+=(--bootstrap-directory "$bootstrap_directory")
    else
      if [[ -z "$directory_a" || -z "$directory_b" || -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" ]]; then
        echo "three-machine-prod-bundle preflight requires --bootstrap-directory or explicit --directory-a/--directory-b/--issuer-url/--entry-url/--exit-url"
        preflight_status="fail"
        preflight_rc=2
        final_rc=2
      else
        preflight_args+=(
          --directory-urls "${directory_a},${directory_b}"
          --issuer-url "$issuer_url"
          --entry-url "$entry_url"
          --exit-url "$exit_url"
        )
      fi
    fi

    if ((final_rc == 0)); then
      echo "three-machine-prod-bundle: running strict preflight (prod profile + operator/issuer quorum)"
      if [[ -n "$preflight_script" ]]; then
        if [[ ! -x "$preflight_script" ]]; then
          echo "three-machine-prod-bundle preflight script is not executable: $preflight_script"
          preflight_status="fail"
          preflight_rc=2
          final_rc=2
        else
          set +e
          "$preflight_script" "${preflight_args[@]}"
          preflight_rc=$?
          set -e
        fi
      else
        set +e
        client_vpn_preflight "${preflight_args[@]}"
        preflight_rc=$?
        set -e
      fi
      if [[ "$preflight_rc" != "0" ]]; then
        preflight_status="fail"
        final_rc="$preflight_rc"
        if [[ "$preflight_require_root_effective" == "1" && "${EUID:-$(id -u)}" != "0" ]]; then
          echo "hint: rerun with sudo (strict preflight requires root for privileged checks)."
        fi
        if [[ ! -f "$mtls_ca_file" || ! -f "$mtls_client_cert_file" || ! -f "$mtls_client_key_file" ]]; then
          echo "hint: strict preflight needs local mTLS files (ca/cert/key); generate or copy them, or pass --mtls-*-file explicitly."
        fi
        if [[ "$using_https_endpoints" == "1" ]]; then
          echo "hint: verify this host can reach the remote HTTPS control-plane endpoints with the same mTLS trust bundle."
        fi
      fi
    fi
  fi

  if ((final_rc == 0)); then
    bundle_status="ok"
    bundle_rc=0
    set +e
    "$bundle_script" "${bundle_args[@]}"
    bundle_rc=$?
    set -e
    if [[ "$bundle_rc" != "0" ]]; then
      bundle_status="fail"
    fi
    final_rc="$bundle_rc"
  fi

  if [[ "$bundle_verify_check" == "1" && "$bundle_status" != "skipped" ]]; then
    bundle_verify_status="ok"
    bundle_verify_rc=0
    echo "three-machine-prod-bundle: verifying bundle integrity (manifest + tar checksum)"
    if [[ ! -x "$verify_script" ]]; then
      echo "three-machine-prod-bundle bundle verify script is not executable: $verify_script"
      bundle_verify_rc=2
      bundle_verify_status="fail"
    else
      set +e
      "$verify_script" \
        --bundle-dir "$bundle_dir" \
        --bundle-tar "$bundle_tar" \
        --check-tar-sha256 1 \
        --check-manifest 1 \
        --show-details "$bundle_verify_show_details"
      bundle_verify_rc=$?
      set -e
      echo "three-machine-prod-bundle: bundle_verify_rc=$bundle_verify_rc"
      if [[ "$bundle_verify_rc" != "0" ]]; then
        bundle_verify_status="fail"
      fi
    fi
    if [[ "$bundle_rc" == "0" && "$bundle_verify_rc" != "0" && "$final_rc" == "0" ]]; then
      final_rc="$bundle_verify_rc"
    fi
  fi

  if [[ "$incident_snapshot_on_fail" == "1" && "$final_rc" != "0" ]]; then
    incident_snapshot_status="ok"
    incident_snapshot_rc=0
    incident_snapshot_bundle_dir="$bundle_dir/incident_snapshot"
    incident_snapshot_bundle_tar="${incident_snapshot_bundle_dir}.tar.gz"
    incident_snapshot_summary_json="$incident_snapshot_bundle_dir/incident_summary.json"
    incident_snapshot_report_md="$incident_snapshot_bundle_dir/incident_report.md"

    if [[ ! -x "$snapshot_script" ]]; then
      echo "three-machine-prod-bundle incident snapshot script is not executable: $snapshot_script"
      incident_snapshot_status="fail"
      incident_snapshot_rc=2
    else
      local -a incident_args
      incident_args=(
        --bundle-dir "$incident_snapshot_bundle_dir"
        --mode auto
        --compose-project "$incident_snapshot_compose_project"
        --include-docker-logs "$incident_snapshot_include_docker_logs"
        --docker-log-lines "$incident_snapshot_docker_log_lines"
        --timeout-sec "$incident_snapshot_timeout_sec"
      )
      if [[ -n "$directory_a" ]]; then
        incident_args+=(--directory-url "$directory_a")
      fi
      if [[ -n "$issuer_url" ]]; then
        incident_args+=(--issuer-url "$issuer_url")
      fi
      if [[ -n "$entry_url" ]]; then
        incident_args+=(--entry-url "$entry_url")
      fi
      if [[ -n "$exit_url" ]]; then
        incident_args+=(--exit-url "$exit_url")
      fi
      for incident_attachment in "${incident_snapshot_attach_artifacts[@]}"; do
        incident_args+=(--attach-artifact "$incident_attachment")
      done
      set +e
      "$snapshot_script" "${incident_args[@]}"
      incident_snapshot_rc=$?
      set -e
      echo "three-machine-prod-bundle: incident_snapshot_rc=$incident_snapshot_rc"
      if [[ "$incident_snapshot_rc" != "0" ]]; then
        incident_snapshot_status="fail"
      fi
      if [[ -f "$incident_snapshot_bundle_dir/attachments/manifest.tsv" ]]; then
        incident_snapshot_attachment_manifest="$incident_snapshot_bundle_dir/attachments/manifest.tsv"
        incident_snapshot_attachment_count="$(awk 'END {print NR+0}' "$incident_snapshot_attachment_manifest" 2>/dev/null)"
      fi
      if [[ -f "$incident_snapshot_bundle_dir/attachments/skipped.tsv" ]]; then
        incident_snapshot_attachment_skipped="$incident_snapshot_bundle_dir/attachments/skipped.tsv"
      fi
    fi
  fi

  write_prod_bundle_run_report
  if [[ "$run_report_print" == "1" ]]; then
    echo "three-machine-prod-bundle: run report json: $run_report_json"
    echo "three-machine-prod-bundle: bundle dir: $bundle_dir"
    echo "three-machine-prod-bundle: bundle tar: $bundle_tar"
  fi

  return "$final_rc"
}

three_machine_prod_signoff() {
  local signoff_script="${THREE_MACHINE_PROD_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/three_machine_prod_signoff.sh}"
  "$signoff_script" "$@"
}

prod_gate_check() {
  local check_script="${THREE_MACHINE_PROD_GATE_CHECK_SCRIPT:-$ROOT_DIR/scripts/prod_gate_check.sh}"
  "$check_script" "$@"
}

prod_gate_slo_summary() {
  local summary_script="${PROD_GATE_SLO_SUMMARY_SCRIPT:-$ROOT_DIR/scripts/prod_gate_slo_summary.sh}"
  "$summary_script" "$@"
}

prod_gate_slo_trend() {
  local trend_script="${PROD_GATE_SLO_TREND_SCRIPT:-$ROOT_DIR/scripts/prod_gate_slo_trend.sh}"
  "$trend_script" "$@"
}

prod_gate_slo_alert() {
  local alert_script="${PROD_GATE_SLO_ALERT_SCRIPT:-$ROOT_DIR/scripts/prod_gate_slo_alert.sh}"
  "$alert_script" "$@"
}

prod_gate_slo_dashboard() {
  local dashboard_script="${PROD_GATE_SLO_DASHBOARD_SCRIPT:-$ROOT_DIR/scripts/prod_gate_slo_dashboard.sh}"
  "$dashboard_script" "$@"
}

prod_gate_bundle_verify() {
  local verify_script="${THREE_MACHINE_PROD_GATE_BUNDLE_VERIFY_SCRIPT:-$ROOT_DIR/scripts/prod_gate_bundle_verify.sh}"
  "$verify_script" "$@"
}

prod_gate_signoff() {
  local run_report_json=""
  local bundle_dir=""
  local bundle_tar=""
  local bundle_tar_sha256_file=""
  local check_tar_sha256="1"
  local check_manifest="1"
  local show_integrity_details="0"
  local gate_summary_json=""
  local require_full_sequence="1"
  local require_wg_validate_ok="1"
  local require_wg_soak_ok="1"
  local require_preflight_ok="0"
  local require_bundle_ok="0"
  local require_integrity_ok="0"
  local require_signoff_ok="0"
  local require_incident_snapshot_on_fail="0"
  local require_incident_snapshot_artifacts="0"
  local incident_snapshot_min_attachment_count="0"
  local incident_snapshot_max_skipped_count="-1"
  local require_wg_validate_udp_source="0"
  local require_wg_validate_strict_distinct="0"
  local require_wg_soak_diversity_pass="0"
  local min_wg_soak_selection_lines="0"
  local min_wg_soak_entry_operators="0"
  local min_wg_soak_exit_operators="0"
  local min_wg_soak_cross_operator_pairs="0"
  local max_wg_soak_failed_rounds="0"
  local show_json="0"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --run-report-json)
        run_report_json="${2:-}"
        shift 2
        ;;
      --bundle-dir)
        bundle_dir="${2:-}"
        shift 2
        ;;
      --bundle-tar)
        bundle_tar="${2:-}"
        shift 2
        ;;
      --bundle-tar-sha256-file)
        bundle_tar_sha256_file="${2:-}"
        shift 2
        ;;
      --check-tar-sha256)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          check_tar_sha256="${2:-}"
          shift 2
        else
          check_tar_sha256="1"
          shift
        fi
        ;;
      --check-manifest)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          check_manifest="${2:-}"
          shift 2
        else
          check_manifest="1"
          shift
        fi
        ;;
      --show-integrity-details)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          show_integrity_details="${2:-}"
          shift 2
        else
          show_integrity_details="1"
          shift
        fi
        ;;
      --gate-summary-json)
        gate_summary_json="${2:-}"
        shift 2
        ;;
      --require-full-sequence)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          require_full_sequence="${2:-}"
          shift 2
        else
          require_full_sequence="1"
          shift
        fi
        ;;
      --require-wg-validate-ok)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          require_wg_validate_ok="${2:-}"
          shift 2
        else
          require_wg_validate_ok="1"
          shift
        fi
        ;;
      --require-wg-soak-ok)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          require_wg_soak_ok="${2:-}"
          shift 2
        else
          require_wg_soak_ok="1"
          shift
        fi
        ;;
      --require-preflight-ok)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          require_preflight_ok="${2:-}"
          shift 2
        else
          require_preflight_ok="1"
          shift
        fi
        ;;
      --require-bundle-ok)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          require_bundle_ok="${2:-}"
          shift 2
        else
          require_bundle_ok="1"
          shift
        fi
        ;;
      --require-integrity-ok)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          require_integrity_ok="${2:-}"
          shift 2
        else
          require_integrity_ok="1"
          shift
        fi
        ;;
      --require-signoff-ok)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          require_signoff_ok="${2:-}"
          shift 2
        else
          require_signoff_ok="1"
          shift
        fi
        ;;
      --require-incident-snapshot-on-fail)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          require_incident_snapshot_on_fail="${2:-}"
          shift 2
        else
          require_incident_snapshot_on_fail="1"
          shift
        fi
        ;;
      --require-incident-snapshot-artifacts)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          require_incident_snapshot_artifacts="${2:-}"
          shift 2
        else
          require_incident_snapshot_artifacts="1"
          shift
        fi
        ;;
      --incident-snapshot-min-attachment-count)
        incident_snapshot_min_attachment_count="${2:-}"
        shift 2
        ;;
      --incident-snapshot-max-skipped-count)
        incident_snapshot_max_skipped_count="${2:-}"
        shift 2
        ;;
      --require-wg-validate-udp-source)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          require_wg_validate_udp_source="${2:-}"
          shift 2
        else
          require_wg_validate_udp_source="1"
          shift
        fi
        ;;
      --require-wg-validate-strict-distinct)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          require_wg_validate_strict_distinct="${2:-}"
          shift 2
        else
          require_wg_validate_strict_distinct="1"
          shift
        fi
        ;;
      --require-wg-soak-diversity-pass)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          require_wg_soak_diversity_pass="${2:-}"
          shift 2
        else
          require_wg_soak_diversity_pass="1"
          shift
        fi
        ;;
      --min-wg-soak-selection-lines)
        min_wg_soak_selection_lines="${2:-}"
        shift 2
        ;;
      --min-wg-soak-entry-operators)
        min_wg_soak_entry_operators="${2:-}"
        shift 2
        ;;
      --min-wg-soak-exit-operators)
        min_wg_soak_exit_operators="${2:-}"
        shift 2
        ;;
      --min-wg-soak-cross-operator-pairs)
        min_wg_soak_cross_operator_pairs="${2:-}"
        shift 2
        ;;
      --max-wg-soak-failed-rounds)
        max_wg_soak_failed_rounds="${2:-}"
        shift 2
        ;;
      --show-json)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          show_json="${2:-}"
          shift 2
        else
          show_json="1"
          shift
        fi
        ;;
      -h|--help|help)
        cat <<'EOF_PROD_GATE_SIGNOFF_HELP'
Usage:
  ./scripts/easy_node.sh prod-gate-signoff \
    [--run-report-json PATH] \
    [--bundle-dir PATH] \
    [--bundle-tar PATH] \
    [--bundle-tar-sha256-file PATH] \
    [--check-tar-sha256 [0|1]] \
    [--check-manifest [0|1]] \
    [--show-integrity-details [0|1]] \
    [--gate-summary-json PATH] \
    [--require-full-sequence [0|1]] \
    [--require-wg-validate-ok [0|1]] \
    [--require-wg-soak-ok [0|1]] \
    [--require-preflight-ok [0|1]] \
    [--require-bundle-ok [0|1]] \
    [--require-integrity-ok [0|1]] \
    [--require-signoff-ok [0|1]] \
    [--require-incident-snapshot-on-fail [0|1]] \
    [--require-incident-snapshot-artifacts [0|1]] \
    [--incident-snapshot-min-attachment-count N] \
    [--incident-snapshot-max-skipped-count N|-1] \
    [--require-wg-validate-udp-source [0|1]] \
    [--require-wg-validate-strict-distinct [0|1]] \
    [--require-wg-soak-diversity-pass [0|1]] \
    [--min-wg-soak-selection-lines N] \
    [--min-wg-soak-entry-operators N] \
    [--min-wg-soak-exit-operators N] \
    [--min-wg-soak-cross-operator-pairs N] \
    [--max-wg-soak-failed-rounds N] \
    [--show-json [0|1]]

Purpose:
  Run bundle integrity verification and gate artifact policy signoff in one fail-closed command.
  Recommended input is --run-report-json from three-machine-prod-bundle.
EOF_PROD_GATE_SIGNOFF_HELP
        return 0
        ;;
      *)
        echo "unknown argument: $1"
        return 2
        ;;
    esac
  done

  local -a verify_args=(
    --check-tar-sha256 "$check_tar_sha256"
    --check-manifest "$check_manifest"
    --show-details "$show_integrity_details"
  )
  if [[ -n "$run_report_json" ]]; then
    verify_args+=(--run-report-json "$run_report_json")
  fi
  if [[ -n "$bundle_dir" ]]; then
    verify_args+=(--bundle-dir "$bundle_dir")
  fi
  if [[ -n "$bundle_tar" ]]; then
    verify_args+=(--bundle-tar "$bundle_tar")
  fi
  if [[ -n "$bundle_tar_sha256_file" ]]; then
    verify_args+=(--bundle-tar-sha256-file "$bundle_tar_sha256_file")
  fi

  local -a check_args=(
    --require-full-sequence "$require_full_sequence"
    --require-wg-validate-ok "$require_wg_validate_ok"
    --require-wg-soak-ok "$require_wg_soak_ok"
    --require-preflight-ok "$require_preflight_ok"
    --require-bundle-ok "$require_bundle_ok"
    --require-integrity-ok "$require_integrity_ok"
    --require-signoff-ok "$require_signoff_ok"
    --require-incident-snapshot-on-fail "$require_incident_snapshot_on_fail"
    --require-incident-snapshot-artifacts "$require_incident_snapshot_artifacts"
    --incident-snapshot-min-attachment-count "$incident_snapshot_min_attachment_count"
    --incident-snapshot-max-skipped-count "$incident_snapshot_max_skipped_count"
    --require-wg-validate-udp-source "$require_wg_validate_udp_source"
    --require-wg-validate-strict-distinct "$require_wg_validate_strict_distinct"
    --require-wg-soak-diversity-pass "$require_wg_soak_diversity_pass"
    --min-wg-soak-selection-lines "$min_wg_soak_selection_lines"
    --min-wg-soak-entry-operators "$min_wg_soak_entry_operators"
    --min-wg-soak-exit-operators "$min_wg_soak_exit_operators"
    --min-wg-soak-cross-operator-pairs "$min_wg_soak_cross_operator_pairs"
    --max-wg-soak-failed-rounds "$max_wg_soak_failed_rounds"
    --show-json "$show_json"
  )
  if [[ -n "$run_report_json" ]]; then
    check_args+=(--run-report-json "$run_report_json")
  fi
  if [[ -n "$bundle_dir" ]]; then
    check_args+=(--bundle-dir "$bundle_dir")
  fi
  if [[ -n "$gate_summary_json" ]]; then
    check_args+=(--gate-summary-json "$gate_summary_json")
  fi

  echo "prod-gate-signoff: verifying bundle integrity"
  prod_gate_bundle_verify "${verify_args[@]}"
  echo "prod-gate-signoff: checking gate signoff policy"
  prod_gate_check "${check_args[@]}"
}

three_machine_reminder() {
  cat <<'REMINDER'
True 3-machine production reminder checklist

Run order:
  1) Machine A: authority/provider stack healthy
  2) Machine B: provider stack healthy and federating with A
  3) Machine C: strict control-plane validation
  4) Machine C: control-plane soak/fault
  5) Machine C (Linux root): real WG production dataplane validate
  6) Machine C (Linux root): real WG production dataplane soak/fault

Recommended commands:
  ./scripts/easy_node.sh machine-a-test --public-host A_HOST
  ./scripts/easy_node.sh machine-b-test --peer-directory-a http://A_HOST:8081 --public-host B_HOST
  ./scripts/easy_node.sh three-machine-validate --directory-a http://A_HOST:8081 --directory-b http://B_HOST:8081 --issuer-url http://A_HOST:8082 --entry-url http://A_HOST:8083 --exit-url http://A_HOST:8084 --prod-profile 1 --path-profile balanced
  ./scripts/easy_node.sh three-machine-soak --directory-a http://A_HOST:8081 --directory-b http://B_HOST:8081 --issuer-url http://A_HOST:8082 --entry-url http://A_HOST:8083 --exit-url http://A_HOST:8084 --rounds 12 --pause-sec 5 --prod-profile 1 --path-profile balanced
  sudo ./scripts/easy_node.sh prod-wg-validate --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084 --strict-distinct 1
  sudo ./scripts/easy_node.sh prod-wg-soak --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084 --rounds 12 --pause-sec 10 --strict-distinct 1
  sudo ./scripts/easy_node.sh prod-wg-strict-ingress-rehearsal --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084

One-command sequence:
  sudo ./scripts/easy_node.sh three-machine-prod-gate --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084
  sudo ./scripts/easy_node.sh three-machine-prod-bundle --bundle-dir .easy-node-logs/prod_gate_bundle --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084

Pass criteria:
  - both directories show at least 2 operators
  - issuer quorum checks pass with distinct issuer identities in strict profile
  - client selection shows distinct entry/exit operator pairing
  - real WG validation shows handshake + transfer and exit accepted_packets > 0
  - soak runs complete with zero failed rounds
REMINDER
}

manual_validation_backlog() {
  cat <<'BACKLOG'
Deferred manual validation backlog

Purpose:
  Keep the remaining real-host checks visible while automated hardening continues.

Live status:
  ./scripts/easy_node.sh manual-validation-status --show-json 1
  ./scripts/easy_node.sh manual-validation-report --print-report 1 --print-summary-json 1
  ./scripts/easy_node.sh single-machine-prod-readiness --print-summary-json 1

Roadmap stage signal:
  - BLOCKED_LOCAL
  - READY_FOR_MACHINE_C_SMOKE
  - READY_FOR_3_MACHINE_PROD_SIGNOFF
  - PRODUCTION_SIGNOFF_COMPLETE

Current pending reruns:
  0) Pre-machine-C readiness sweep before the next real-host rerun
     Goal:
       - clean stale runtime leftovers
       - rerun the Linux root WG-only proof
       - refresh the shared readiness report in one command
     Command:
       sudo ./scripts/easy_node.sh pre-real-host-readiness --strict-beta 1 --base-port 19280 --client-iface wgcstack0 --exit-iface wgestack0 --vpn-iface wgvpn0 --print-summary-json 1

  1) Linux root WG-only selftest rerun on a real host
     Why:
       - fallback drill if the combined readiness sweep blocks at WG-only validation
     Command:
       sudo ./scripts/easy_node.sh wg-only-stack-down --force-iface-cleanup 1 --base-port 19280 --client-iface wgcstack0 --exit-iface wgestack0
       sudo rm -rf deploy/data/wg_only
       sudo ./scripts/easy_node.sh wg-only-stack-selftest-record --strict-beta 1 --base-port 19280 --client-iface wgcstack0 --exit-iface wgestack0 --print-summary-json 1
     If it fails:
       tail -n 120 .easy-node-logs/wg_only_stack_selftest_record_*.log

  1b) Optional Linux root real-WG privileged matrix confidence run
     Why:
       - stronger one-host dataplane confidence before the external machine-C smoke rerun
     Command:
       sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1

  2) Real machine-C VPN smoke test against A/B
     Goal:
       - confirm host WireGuard tunnel bring-up from an external client machine
       - confirm exit IP changes and real session establishment
     Commands:
       sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country --print-summary-json 1

  3) True 3-machine production signoff run
     Goal:
       - run strict control-plane + real-WG production gate from machine C
       - produce bundle/signoff artifacts for operator review
       - record the outcome automatically in manual-validation status
     Commands:
       ./scripts/easy_node.sh three-machine-reminder
       sudo ./scripts/easy_node.sh three-machine-prod-signoff --bundle-dir .easy-node-logs/prod_gate_bundle --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084 --pre-real-host-readiness 1 --runtime-fix 1 --print-summary-json 1

Reference:
  docs/manual-validation-backlog.md
BACKLOG
}

manual_validation_status() {
  local status_script="${MANUAL_VALIDATION_STATUS_SCRIPT:-$ROOT_DIR/scripts/manual_validation_status.sh}"
  "$status_script" "$@"
}

single_machine_prod_readiness() {
  local readiness_script="${SINGLE_MACHINE_PROD_READINESS_SCRIPT:-$ROOT_DIR/scripts/single_machine_prod_readiness.sh}"
  "$readiness_script" "$@"
}

vpn_rc_standard_path() {
  local rc_script="${VPN_RC_STANDARD_PATH_SCRIPT:-$ROOT_DIR/scripts/vpn_rc_standard_path.sh}"
  "$rc_script" "$@"
}

vpn_rc_resilience_path() {
  local rc_script="${VPN_RC_RESILIENCE_PATH_SCRIPT:-$ROOT_DIR/scripts/vpn_rc_resilience_path.sh}"
  "$rc_script" "$@"
}

vpn_rc_matrix_path() {
  local rc_script="${VPN_RC_MATRIX_PATH_SCRIPT:-$ROOT_DIR/scripts/vpn_rc_matrix_path.sh}"
  "$rc_script" "$@"
}

vpn_non_blockchain_fastlane() {
  local script="${VPN_NON_BLOCKCHAIN_FASTLANE_SCRIPT:-$ROOT_DIR/scripts/vpn_non_blockchain_fastlane.sh}"
  "$script" "$@"
}

blockchain_fastlane() {
  local fastlane_script="${BLOCKCHAIN_FASTLANE_SCRIPT:-$ROOT_DIR/scripts/blockchain_fastlane.sh}"
  if [[ ! -x "$fastlane_script" ]]; then
    echo "missing helper script: $fastlane_script"
    exit 2
  fi
  "$fastlane_script" "$@"
}

blockchain_gate_bundle() {
  local bundle_script="${BLOCKCHAIN_GATE_BUNDLE_SCRIPT:-$ROOT_DIR/scripts/blockchain_gate_bundle.sh}"
  if [[ ! -x "$bundle_script" ]]; then
    echo "missing helper script: $bundle_script"
    exit 2
  fi
  "$bundle_script" "$@"
}

ci_blockchain_parallel_sweep() {
  local sweep_script="${CI_BLOCKCHAIN_PARALLEL_SWEEP_SCRIPT:-$ROOT_DIR/scripts/ci_blockchain_parallel_sweep.sh}"
  if [[ ! -x "$sweep_script" ]]; then
    echo "missing helper script: $sweep_script"
    exit 2
  fi
  "$sweep_script" "$@"
}

blockchain_mainnet_activation_metrics_input() {
  local metrics_input_script="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_input.sh}"
  if [[ ! -x "$metrics_input_script" ]]; then
    echo "missing helper script: $metrics_input_script"
    exit 2
  fi
  "$metrics_input_script" "$@"
}

blockchain_mainnet_activation_metrics_missing_checklist() {
  local metrics_missing_checklist_script="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_CHECKLIST_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_missing_checklist.sh}"
  if [[ ! -x "$metrics_missing_checklist_script" ]]; then
    echo "missing helper script: $metrics_missing_checklist_script"
    exit 2
  fi
  "$metrics_missing_checklist_script" "$@"
}

blockchain_mainnet_activation_metrics_missing_input_template() {
  local metrics_missing_input_template_script="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_INPUT_TEMPLATE_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_missing_input_template.sh}"
  if [[ ! -x "$metrics_missing_input_template_script" ]]; then
    echo "missing helper script: $metrics_missing_input_template_script"
    exit 2
  fi
  "$metrics_missing_input_template_script" "$@"
}

blockchain_mainnet_activation_metrics_input_template() {
  local metrics_input_template_script="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_TEMPLATE_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_input_template.sh}"
  if [[ ! -x "$metrics_input_template_script" ]]; then
    echo "missing helper script: $metrics_input_template_script"
    exit 2
  fi
  "$metrics_input_template_script" "$@"
}

blockchain_mainnet_activation_metrics() {
  local metrics_script="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics.sh}"
  if [[ ! -x "$metrics_script" ]]; then
    echo "missing helper script: $metrics_script"
    exit 2
  fi
  "$metrics_script" "$@"
}

blockchain_mainnet_activation_gate() {
  local gate_script="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_gate.sh}"
  if [[ ! -x "$gate_script" ]]; then
    echo "missing helper script: $gate_script"
    exit 2
  fi
  "$gate_script" "$@"
}

blockchain_mainnet_activation_gate_cycle() {
  local gate_cycle_script="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_gate_cycle.sh}"
  if [[ ! -x "$gate_cycle_script" ]]; then
    echo "missing helper script: $gate_cycle_script"
    exit 2
  fi
  "$gate_cycle_script" "$@"
}

blockchain_mainnet_activation_gate_cycle_seeded() {
  local gate_cycle_script="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_gate_cycle.sh}"
  if [[ ! -x "$gate_cycle_script" ]]; then
    echo "missing helper script: $gate_cycle_script"
    exit 2
  fi
  "$gate_cycle_script" --seed-example-input 1 "$@"
}

blockchain_mainnet_activation_operator_pack() {
  local operator_pack_script="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_operator_pack.sh}"
  if [[ ! -x "$operator_pack_script" ]]; then
    echo "missing helper script: $operator_pack_script"
    exit 2
  fi
  "$operator_pack_script" "$@"
}

blockchain_bootstrap_governance_graduation_gate() {
  local gate_script="${BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SCRIPT:-$ROOT_DIR/scripts/blockchain_bootstrap_graduation_gate.sh}"
  if [[ ! -x "$gate_script" ]]; then
    echo "missing helper script: $gate_script"
    exit 2
  fi
  "$gate_script" "$@"
}

roadmap_non_blockchain_actionable_run() {
  local script="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_SCRIPT:-$ROOT_DIR/scripts/roadmap_non_blockchain_actionable_run.sh}"
  "$script" "$@"
}

roadmap_blockchain_actionable_run() {
  local script="${ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_SCRIPT:-$ROOT_DIR/scripts/roadmap_blockchain_actionable_run.sh}"
  "$script" "$@"
}

roadmap_next_actions_run() {
  local script="${ROADMAP_NEXT_ACTIONS_RUN_SCRIPT:-$ROOT_DIR/scripts/roadmap_next_actions_run.sh}"
  "$script" "$@"
}

ci_phase0() {
  local gate_script="${CI_PHASE0_SCRIPT:-$ROOT_DIR/scripts/ci_phase0.sh}"
  "$gate_script" "$@"
}

ci_phase1_resilience() {
  local gate_script="${CI_PHASE1_RESILIENCE_SCRIPT:-$ROOT_DIR/scripts/ci_phase1_resilience.sh}"
  "$gate_script" "$@"
}

phase1_resilience_handoff_check() {
  local handoff_check_script="${PHASE1_RESILIENCE_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase1_resilience_handoff_check.sh}"
  "$handoff_check_script" "$@"
}

phase1_resilience_handoff_run() {
  local handoff_run_script="${PHASE1_RESILIENCE_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/phase1_resilience_handoff_run.sh}"
  "$handoff_run_script" "$@"
}

ci_phase2_linux_prod_candidate() {
  local gate_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_SCRIPT:-$ROOT_DIR/scripts/ci_phase2_linux_prod_candidate.sh}"
  "$gate_script" "$@"
}

phase2_linux_prod_candidate_check() {
  local check_script="${PHASE2_LINUX_PROD_CANDIDATE_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_check.sh}"
  "$check_script" "$@"
}

phase2_linux_prod_candidate_run() {
  local run_script="${PHASE2_LINUX_PROD_CANDIDATE_RUN_SCRIPT:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_run.sh}"
  "$run_script" "$@"
}

phase2_linux_prod_candidate_signoff() {
  local signoff_script="${PHASE2_LINUX_PROD_CANDIDATE_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_signoff.sh}"
  "$signoff_script" "$@"
}

phase2_linux_prod_candidate_handoff_check() {
  local handoff_check_script="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_handoff_check.sh}"
  "$handoff_check_script" "$@"
}

phase2_linux_prod_candidate_handoff_run() {
  local handoff_run_script="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_handoff_run.sh}"
  "$handoff_run_script" "$@"
}

ci_phase3_windows_client_beta() {
  local gate_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_SCRIPT:-$ROOT_DIR/scripts/ci_phase3_windows_client_beta.sh}"
  "$gate_script" "$@"
}

phase3_windows_client_beta_check() {
  local check_script="${PHASE3_WINDOWS_CLIENT_BETA_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase3_windows_client_beta_check.sh}"
  "$check_script" "$@"
}

phase3_windows_client_beta_run() {
  local run_script="${PHASE3_WINDOWS_CLIENT_BETA_RUN_SCRIPT:-$ROOT_DIR/scripts/phase3_windows_client_beta_run.sh}"
  "$run_script" "$@"
}

phase3_windows_client_beta_handoff_check() {
  local handoff_check_script="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase3_windows_client_beta_handoff_check.sh}"
  "$handoff_check_script" "$@"
}

phase3_windows_client_beta_handoff_run() {
  local handoff_run_script="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/phase3_windows_client_beta_handoff_run.sh}"
  "$handoff_run_script" "$@"
}

ci_phase4_windows_full_parity() {
  local gate_script="${CI_PHASE4_WINDOWS_FULL_PARITY_SCRIPT:-$ROOT_DIR/scripts/ci_phase4_windows_full_parity.sh}"
  "$gate_script" "$@"
}

phase4_windows_full_parity_check() {
  local check_script="${PHASE4_WINDOWS_FULL_PARITY_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase4_windows_full_parity_check.sh}"
  "$check_script" "$@"
}

phase4_windows_full_parity_run() {
  local run_script="${PHASE4_WINDOWS_FULL_PARITY_RUN_SCRIPT:-$ROOT_DIR/scripts/phase4_windows_full_parity_run.sh}"
  "$run_script" "$@"
}

phase4_windows_full_parity_handoff_check() {
  local handoff_check_script="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase4_windows_full_parity_handoff_check.sh}"
  "$handoff_check_script" "$@"
}

phase4_windows_full_parity_handoff_run() {
  local handoff_run_script="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/phase4_windows_full_parity_handoff_run.sh}"
  "$handoff_run_script" "$@"
}

ci_phase5_settlement_layer() {
  local gate_script="${CI_PHASE5_SETTLEMENT_LAYER_SCRIPT:-$ROOT_DIR/scripts/ci_phase5_settlement_layer.sh}"
  "$gate_script" "$@"
}

phase5_settlement_layer_check() {
  local check_script="${PHASE5_SETTLEMENT_LAYER_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase5_settlement_layer_check.sh}"
  "$check_script" "$@"
}

phase5_settlement_layer_run() {
  local run_script="${PHASE5_SETTLEMENT_LAYER_RUN_SCRIPT:-$ROOT_DIR/scripts/phase5_settlement_layer_run.sh}"
  "$run_script" "$@"
}

phase5_settlement_layer_handoff_check() {
  local handoff_check_script="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase5_settlement_layer_handoff_check.sh}"
  "$handoff_check_script" "$@"
}

phase5_settlement_layer_handoff_run() {
  local handoff_run_script="${PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/phase5_settlement_layer_handoff_run.sh}"
  "$handoff_run_script" "$@"
}

phase5_settlement_layer_summary_report() {
  local summary_report_script="${PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_SCRIPT:-$ROOT_DIR/scripts/phase5_settlement_layer_summary_report.sh}"
  "$summary_report_script" "$@"
}

issuer_sponsor_api_live_smoke() {
  local live_smoke_script="${ISSUER_SPONSOR_API_LIVE_SMOKE_SCRIPT:-$ROOT_DIR/scripts/integration_issuer_sponsor_api_live_smoke.sh}"
  "$live_smoke_script" "$@"
}

issuer_settlement_status_live_smoke() {
  local live_smoke_script="${ISSUER_SETTLEMENT_STATUS_LIVE_SMOKE_SCRIPT:-$ROOT_DIR/scripts/integration_issuer_settlement_status_live_smoke.sh}"
  "$live_smoke_script" "$@"
}

ci_phase6_cosmos_l1_build_testnet() {
  local gate_script="${CI_PHASE6_COSMOS_L1_BUILD_TESTNET_SCRIPT:-$ROOT_DIR/scripts/ci_phase6_cosmos_l1_build_testnet.sh}"
  if [[ ! -x "$gate_script" ]]; then
    echo "missing helper script: $gate_script"
    exit 2
  fi
  "$gate_script" "$@"
}

ci_phase6_cosmos_l1_contracts() {
  local gate_script="${CI_PHASE6_COSMOS_L1_CONTRACTS_SCRIPT:-$ROOT_DIR/scripts/ci_phase6_cosmos_l1_contracts.sh}"
  if [[ ! -x "$gate_script" ]]; then
    echo "missing helper script: $gate_script"
    exit 2
  fi
  "$gate_script" "$@"
}

phase6_cosmos_l1_build_testnet_check() {
  local check_script="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase6_cosmos_l1_build_testnet_check.sh}"
  if [[ ! -x "$check_script" ]]; then
    echo "missing helper script: $check_script"
    exit 2
  fi
  "$check_script" "$@"
}

phase6_cosmos_l1_build_testnet_run() {
  local run_script="${PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_SCRIPT:-$ROOT_DIR/scripts/phase6_cosmos_l1_build_testnet_run.sh}"
  if [[ ! -x "$run_script" ]]; then
    echo "missing helper script: $run_script"
    exit 2
  fi
  "$run_script" "$@"
}

phase6_cosmos_l1_build_testnet_handoff_check() {
  local handoff_check_script="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase6_cosmos_l1_build_testnet_handoff_check.sh}"
  if [[ ! -x "$handoff_check_script" ]]; then
    echo "missing helper script: $handoff_check_script"
    exit 2
  fi
  "$handoff_check_script" "$@"
}

phase6_cosmos_l1_build_testnet_handoff_run() {
  local handoff_run_script="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/phase6_cosmos_l1_build_testnet_handoff_run.sh}"
  if [[ ! -x "$handoff_run_script" ]]; then
    echo "missing helper script: $handoff_run_script"
    exit 2
  fi
  "$handoff_run_script" "$@"
}

phase6_cosmos_l1_build_testnet_suite() {
  local suite_script="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_SCRIPT:-$ROOT_DIR/scripts/phase6_cosmos_l1_build_testnet_suite.sh}"
  if [[ ! -x "$suite_script" ]]; then
    echo "missing helper script: $suite_script"
    exit 2
  fi
  "$suite_script" "$@"
}

phase6_cosmos_l1_summary_report() {
  local summary_report_script="${PHASE6_COSMOS_L1_SUMMARY_REPORT_SCRIPT:-$ROOT_DIR/scripts/phase6_cosmos_l1_summary_report.sh}"
  "$summary_report_script" "$@"
}

ci_phase7_mainnet_cutover() {
  local gate_script="${CI_PHASE7_MAINNET_CUTOVER_SCRIPT:-$ROOT_DIR/scripts/ci_phase7_mainnet_cutover.sh}"
  if [[ ! -x "$gate_script" ]]; then
    echo "missing helper script: $gate_script"
    exit 2
  fi
  "$gate_script" "$@"
}

phase7_mainnet_cutover_check() {
  local check_script="${PHASE7_MAINNET_CUTOVER_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase7_mainnet_cutover_check.sh}"
  if [[ ! -x "$check_script" ]]; then
    echo "missing helper script: $check_script"
    exit 2
  fi
  "$check_script" "$@"
}

phase7_mainnet_cutover_run() {
  local run_script="${PHASE7_MAINNET_CUTOVER_RUN_SCRIPT:-$ROOT_DIR/scripts/phase7_mainnet_cutover_run.sh}"
  if [[ ! -x "$run_script" ]]; then
    echo "missing helper script: $run_script"
    exit 2
  fi
  "$run_script" "$@"
}

phase7_mainnet_cutover_handoff_check() {
  local handoff_check_script="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase7_mainnet_cutover_handoff_check.sh}"
  if [[ ! -x "$handoff_check_script" ]]; then
    echo "missing helper script: $handoff_check_script"
    exit 2
  fi
  "$handoff_check_script" "$@"
}

phase7_mainnet_cutover_handoff_run() {
  local handoff_run_script="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/phase7_mainnet_cutover_handoff_run.sh}"
  if [[ ! -x "$handoff_run_script" ]]; then
    echo "missing helper script: $handoff_run_script"
    exit 2
  fi
  "$handoff_run_script" "$@"
}

phase7_mainnet_cutover_summary_report() {
  local summary_report_script="${PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_SCRIPT:-$ROOT_DIR/scripts/phase7_mainnet_cutover_summary_report.sh}"
  "$summary_report_script" "$@"
}

profile_compare_local() {
  local compare_script="${PROFILE_COMPARE_LOCAL_SCRIPT:-$ROOT_DIR/scripts/profile_compare_local.sh}"
  "$compare_script" "$@"
}

profile_compare_trend() {
  local trend_script="${PROFILE_COMPARE_TREND_SCRIPT:-$ROOT_DIR/scripts/profile_compare_trend.sh}"
  "$trend_script" "$@"
}

client_vpn_profile_compare() {
  local compare_script="${CLIENT_VPN_PROFILE_COMPARE_SCRIPT:-$ROOT_DIR/scripts/client_vpn_profile_compare.sh}"
  "$compare_script" "$@"
}

profile_compare_campaign() {
  local campaign_script="${PROFILE_COMPARE_CAMPAIGN_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign.sh}"
  "$campaign_script" "$@"
}

profile_compare_docker_matrix() {
  local matrix_script="${PROFILE_COMPARE_DOCKER_MATRIX_SCRIPT:-$ROOT_DIR/scripts/profile_compare_docker_matrix.sh}"
  "$matrix_script" "$@"
}

profile_compare_campaign_check() {
  local campaign_check_script="${PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign_check.sh}"
  "$campaign_check_script" "$@"
}

profile_compare_campaign_signoff() {
  local campaign_signoff_script="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign_signoff.sh}"
  local -a forwarded=()
  local subject_alias_value=""
  local campaign_subject_value=""
  local anon_alias_value=""
  local campaign_anon_value=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --campaign-subject)
        forwarded+=("$1")
        if [[ $# -ge 2 ]]; then
          campaign_subject_value="${2:-}"
          forwarded+=("$2")
          shift 2
        else
          shift
        fi
        ;;
      --campaign-subject=*)
        campaign_subject_value="${1#--campaign-subject=}"
        forwarded+=("$1")
        shift
        ;;
      --subject)
        forwarded+=(--campaign-subject)
        if [[ $# -ge 2 ]]; then
          subject_alias_value="${2:-}"
          forwarded+=("$2")
          shift 2
        else
          shift
        fi
        ;;
      --subject=*)
        subject_alias_value="${1#--subject=}"
        forwarded+=(--campaign-subject "${1#--subject=}")
        shift
        ;;
      --campaign-anon-cred)
        forwarded+=("$1")
        if [[ $# -ge 2 ]]; then
          campaign_anon_value="${2:-}"
          forwarded+=("$2")
          shift 2
        else
          shift
        fi
        ;;
      --campaign-anon-cred=*)
        campaign_anon_value="${1#--campaign-anon-cred=}"
        forwarded+=("$1")
        shift
        ;;
      --anon-cred)
        forwarded+=(--campaign-anon-cred)
        if [[ $# -ge 2 ]]; then
          anon_alias_value="${2:-}"
          forwarded+=("$2")
          shift 2
        else
          shift
        fi
        ;;
      --anon-cred=*)
        anon_alias_value="${1#--anon-cred=}"
        forwarded+=(--campaign-anon-cred "${1#--anon-cred=}")
        shift
        ;;
      *)
        forwarded+=("$1")
        shift
        ;;
    esac
  done
  if [[ -n "$subject_alias_value" && -n "$campaign_subject_value" && "$subject_alias_value" != "$campaign_subject_value" ]]; then
    echo "conflicting subject values: --subject and --campaign-subject must match when both are provided"
    exit 2
  fi
  if [[ -n "$anon_alias_value" && -n "$campaign_anon_value" && "$anon_alias_value" != "$campaign_anon_value" ]]; then
    echo "conflicting anon credential values: --anon-cred and --campaign-anon-cred must match when both are provided"
    exit 2
  fi
  "$campaign_signoff_script" "${forwarded[@]}"
}

profile_default_gate_run() {
  local profile_default_gate_run_script="${PROFILE_DEFAULT_GATE_RUN_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_run.sh}"
  "$profile_default_gate_run_script" "$@"
}

profile_default_gate_live() {
  local raw_host_a="${A_HOST:-}"
  local raw_host_b="${B_HOST:-}"
  local campaign_subject="${INVITE_KEY:-}"
  local reports_dir=".easy-node-logs"
  local campaign_timeout_sec="1200"
  local summary_json=".easy-node-logs/profile_compare_campaign_signoff_summary.json"
  local print_summary_json="1"
  local -a passthrough=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host-a|--a-host|--directory-a)
        if [[ $# -lt 2 ]]; then
          echo "profile-default-gate-live requires --host-a HOST"
          exit 2
        fi
        raw_host_a="$2"
        shift 2
        ;;
      --host-b|--b-host|--directory-b)
        if [[ $# -lt 2 ]]; then
          echo "profile-default-gate-live requires --host-b HOST"
          exit 2
        fi
        raw_host_b="$2"
        shift 2
        ;;
      --campaign-subject|--subject|--key|--invite-key)
        if [[ $# -lt 2 ]]; then
          echo "profile-default-gate-live requires --campaign-subject INVITE_KEY"
          exit 2
        fi
        campaign_subject="$2"
        shift 2
        ;;
      --reports-dir)
        if [[ $# -lt 2 ]]; then
          echo "profile-default-gate-live requires --reports-dir DIR"
          exit 2
        fi
        reports_dir="$2"
        shift 2
        ;;
      --campaign-timeout-sec)
        if [[ $# -lt 2 ]]; then
          echo "profile-default-gate-live requires --campaign-timeout-sec N"
          exit 2
        fi
        campaign_timeout_sec="$2"
        shift 2
        ;;
      --summary-json)
        if [[ $# -lt 2 ]]; then
          echo "profile-default-gate-live requires --summary-json PATH"
          exit 2
        fi
        summary_json="$2"
        shift 2
        ;;
      --print-summary-json)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          print_summary_json="${2:-}"
          shift 2
        else
          print_summary_json="1"
          shift
        fi
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        passthrough+=("$1")
        shift
        ;;
    esac
  done

  normalize_live_host() {
    local raw="$1"
    raw="${raw#http://}"
    raw="${raw#https://}"
    raw="${raw%%/*}"
    raw="${raw%%:*}"
    printf '%s\n' "$raw"
  }

  local host_a=""
  local host_b=""
  host_a="$(normalize_live_host "$raw_host_a")"
  host_b="$(normalize_live_host "$raw_host_b")"

  if [[ -z "$host_a" ]]; then
    echo "profile-default-gate-live requires host A (set --host-a or A_HOST)"
    exit 2
  fi
  if [[ -z "$host_b" ]]; then
    echo "profile-default-gate-live requires host B (set --host-b or B_HOST)"
    exit 2
  fi
  if [[ -z "$campaign_subject" ]]; then
    echo "profile-default-gate-live requires invite subject (set --campaign-subject/--subject/--key or INVITE_KEY)"
    exit 2
  fi
  if ! [[ "$campaign_timeout_sec" =~ ^[0-9]+$ ]] || (( campaign_timeout_sec <= 0 )); then
    echo "profile-default-gate-live requires --campaign-timeout-sec > 0"
    exit 2
  fi

  local directory_a="http://${host_a}:8081"
  local directory_b="http://${host_b}:8081"
  local issuer_a="http://${host_a}:8082"
  local entry_a="http://${host_a}:8083"
  local exit_a="http://${host_a}:8084"

  echo "profile-default-gate-live:"
  echo "  directory_a: $directory_a"
  echo "  directory_b: $directory_b"
  echo "  subject: $campaign_subject"
  echo "  reports_dir: $reports_dir"
  echo "  summary_json: $summary_json"

  profile_default_gate_run \
    --directory-a "$directory_a" \
    --directory-b "$directory_b" \
    --campaign-bootstrap-directory "$directory_a" \
    --campaign-issuer-url "$issuer_a" \
    --campaign-entry-url "$entry_a" \
    --campaign-exit-url "$exit_a" \
    --campaign-subject "$campaign_subject" \
    --reports-dir "$reports_dir" \
    --campaign-timeout-sec "$campaign_timeout_sec" \
    --summary-json "$summary_json" \
    --print-summary-json "$print_summary_json" \
    "${passthrough[@]}"
}

manual_validation_report() {
  local report_script="${MANUAL_VALIDATION_REPORT_SCRIPT:-$ROOT_DIR/scripts/manual_validation_report.sh}"
  "$report_script" "$@"
}

roadmap_progress_report() {
  local report_script="${ROADMAP_PROGRESS_REPORT_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"
  "$report_script" "$@"
}

pre_real_host_readiness() {
  local readiness_script="${PRE_REAL_HOST_READINESS_SCRIPT:-$ROOT_DIR/scripts/pre_real_host_readiness.sh}"
  "$readiness_script" "$@"
}

manual_validation_record() {
  local record_script="${MANUAL_VALIDATION_RECORD_SCRIPT:-$ROOT_DIR/scripts/manual_validation_record.sh}"
  "$record_script" "$@"
}

wg_only_stack_selftest_record() {
  local record_script="${WG_ONLY_STACK_SELFTEST_RECORD_SCRIPT:-$ROOT_DIR/scripts/wg_only_stack_selftest_record.sh}"
  "$record_script" "$@"
}

runtime_doctor() {
  local doctor_script="${RUNTIME_DOCTOR_SCRIPT:-$ROOT_DIR/scripts/runtime_doctor.sh}"
  "$doctor_script" "$@"
}

runtime_fix() {
  local fix_script="${RUNTIME_FIX_SCRIPT:-$ROOT_DIR/scripts/runtime_fix.sh}"
  "$fix_script" "$@"
}

runtime_fix_record() {
  local fix_record_script="${RUNTIME_FIX_RECORD_SCRIPT:-$ROOT_DIR/scripts/runtime_fix_record.sh}"
  "$fix_record_script" "$@"
}

prod_wg_validate() {
  ensure_deps_or_die
  local validate_script="${THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_prod_wg_validate.sh}"
  "$validate_script" "$@"
}

prod_wg_soak() {
  ensure_deps_or_die
  local soak_script="${THREE_MACHINE_PROD_WG_SOAK_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_prod_wg_soak.sh}"
  "$soak_script" "$@"
}

prod_wg_strict_ingress_rehearsal() {
  ensure_deps_or_die
  local soak_script="${THREE_MACHINE_PROD_WG_SOAK_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_prod_wg_soak.sh}"

  local log_dir ts report_file summary_json
  log_dir="$(prepare_log_dir)"
  ts="$(date +%Y%m%d_%H%M%S)"
  report_file="$log_dir/privacynode_prod_wg_strict_ingress_rehearsal_${ts}.log"
  summary_json="$log_dir/privacynode_prod_wg_strict_ingress_rehearsal_${ts}.json"

  local -a cmd=(
    "$soak_script"
    --rounds 1
    --pause-sec 0
    --continue-on-fail 1
    --max-consecutive-failures 1
    --strict-ingress-rehearsal 1
    --max-failure-class strict_ingress_policy=0
    --disallow-unknown-failure-class 1
    --report-file "$report_file"
    --summary-json "$summary_json"
    "$@"
  )

  set +e
  "${cmd[@]}"
  local rc=$?
  set -e

  if [[ "$rc" -eq 0 ]]; then
    echo "prod-wg-strict-ingress-rehearsal failed: expected non-zero rc from controlled strict-ingress failure path"
    echo "report: $report_file"
    echo "summary_json: $summary_json"
    exit 1
  fi

  if [[ ! -f "$report_file" ]] || ! rg -q 'class=strict_ingress_policy|failure_class strict_ingress_policy=' "$report_file"; then
    echo "prod-wg-strict-ingress-rehearsal failed: strict_ingress_policy class not observed in soak report"
    echo "report: $report_file"
    [[ -f "$report_file" ]] && cat "$report_file"
    exit 1
  fi
  if [[ ! -f "$summary_json" ]] || ! rg -q '"strict_ingress_policy"[[:space:]]*:[[:space:]]*[1-9][0-9]*' "$summary_json"; then
    echo "prod-wg-strict-ingress-rehearsal failed: summary missing strict_ingress_policy count"
    echo "summary_json: $summary_json"
    [[ -f "$summary_json" ]] && cat "$summary_json"
    exit 1
  fi

  echo "prod wg strict-ingress rehearsal check ok"
  echo "report: $report_file"
  echo "summary_json: $summary_json"
}

discover_hosts() {
  local bootstrap_directory=""
  local wait_sec="${EASY_NODE_DISCOVERY_WAIT_SEC:-12}"
  local min_hosts="2"
  local write_config="0"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bootstrap-directory)
        bootstrap_directory="${2:-}"
        shift 2
        ;;
      --wait-sec)
        wait_sec="${2:-}"
        shift 2
        ;;
      --min-hosts)
        min_hosts="${2:-}"
        shift 2
        ;;
      --write-config)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          write_config="${2:-}"
          shift 2
        else
          write_config="1"
          shift
        fi
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for discover-hosts: $1"
        exit 2
        ;;
    esac
  done

  if [[ -z "$bootstrap_directory" ]]; then
    echo "discover-hosts requires --bootstrap-directory URL"
    exit 2
  fi
  if ! [[ "$wait_sec" =~ ^[0-9]+$ && "$min_hosts" =~ ^[0-9]+$ ]]; then
    echo "discover-hosts requires numeric --wait-sec and --min-hosts"
    exit 2
  fi
  if [[ "$write_config" != "0" && "$write_config" != "1" ]]; then
    echo "discover-hosts requires --write-config to be 0 or 1"
    exit 2
  fi

  need_cmd curl || exit 2
  need_cmd rg || exit 2

  bootstrap_directory="$(trim_url "$bootstrap_directory")"
  local discovered_csv
  discovered_csv="$(discover_directory_urls "$bootstrap_directory" "$wait_sec" "$min_hosts")"
  if [[ -z "$discovered_csv" ]]; then
    echo "no hosts discovered from $bootstrap_directory"
    exit 1
  fi

  echo "bootstrap_directory=$bootstrap_directory"
  echo "discovered_directory_urls=$discovered_csv"

  local discovered_hosts
  discovered_hosts="$(
    printf '%s\n' "$discovered_csv" | tr ',' '\n' | sed '/^$/d' |
      while IFS= read -r u; do host_from_url "$u"; done |
      awk 'NF > 0' | sort -u
  )"
  echo "discovered_hosts:"
  printf '%s\n' "$discovered_hosts"

  if [[ "$write_config" == "1" ]]; then
    local host_a host_b bootstrap_host
    bootstrap_host="$(host_from_url "$bootstrap_directory")"
    if [[ -n "$bootstrap_host" ]]; then
      host_a="$bootstrap_host"
      host_b="$(printf '%s\n' "$discovered_hosts" | awk -v bootstrap="$bootstrap_host" '$0 != bootstrap {print; exit}')"
    else
      host_a="$(printf '%s\n' "$discovered_hosts" | sed -n '1p')"
      host_b="$(printf '%s\n' "$discovered_hosts" | sed -n '2p')"
    fi
    if [[ -n "$host_a" && -n "$host_b" ]]; then
      write_hosts_config "$host_a" "$host_b"
      echo "updated host config: $(hosts_config_file)"
    else
      echo "not enough hosts to update config (need at least 2)"
      exit 1
    fi
  fi
}

machine_a_test() {
  ensure_deps_or_die
  "$ROOT_DIR/scripts/integration_machine_a_server_check.sh" "$@"
}

machine_b_test() {
  ensure_deps_or_die
  "$ROOT_DIR/scripts/integration_machine_b_federation_check.sh" "$@"
}

machine_c_test() {
  ensure_deps_or_die
  "$ROOT_DIR/scripts/integration_machine_c_client_check.sh" "$@"
}

pilot_runbook() {
  ensure_deps_or_die
  "$ROOT_DIR/scripts/beta_pilot_runbook.sh" "$@"
}

prod_pilot_runbook() {
  ensure_deps_or_die
  local runbook_script="${PROD_PILOT_RUNBOOK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_runbook.sh}"
  "$runbook_script" "$@"
}

prod_pilot_cohort_runbook() {
  ensure_deps_or_die
  local runbook_script="${PROD_PILOT_COHORT_RUNBOOK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_runbook.sh}"
  "$runbook_script" "$@"
}

prod_pilot_cohort_campaign() {
  ensure_deps_or_die
  local campaign_script="${PROD_PILOT_COHORT_CAMPAIGN_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_campaign.sh}"
  "$campaign_script" "$@"
}

prod_pilot_cohort_campaign_summary() {
  ensure_deps_or_die
  local summary_script="${PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_campaign_summary.sh}"
  "$summary_script" "$@"
}

prod_pilot_cohort_campaign_check() {
  ensure_deps_or_die
  local check_script="${PROD_PILOT_COHORT_CAMPAIGN_CHECK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_campaign_check.sh}"
  bash "$check_script" "$@"
}

prod_pilot_cohort_campaign_signoff() {
  ensure_deps_or_die
  local signoff_script="${PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_campaign_signoff.sh}"
  bash "$signoff_script" "$@"
}

prod_pilot_cohort_quick() {
  ensure_deps_or_die
  local quick_script="${PROD_PILOT_COHORT_QUICK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick.sh}"
  "$quick_script" "$@"
}

prod_pilot_cohort_bundle_verify() {
  ensure_deps_or_die
  local verify_script="${PROD_PILOT_COHORT_BUNDLE_VERIFY_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_bundle_verify.sh}"
  "$verify_script" "$@"
}

prod_pilot_cohort_check() {
  ensure_deps_or_die
  local check_script="${PROD_PILOT_COHORT_CHECK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_check.sh}"
  "$check_script" "$@"
}

prod_pilot_cohort_signoff() {
  ensure_deps_or_die
  local signoff_script="${PROD_PILOT_COHORT_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_signoff.sh}"
  "$signoff_script" "$@"
}

prod_pilot_cohort_quick_check() {
  ensure_deps_or_die
  local check_script="${PROD_PILOT_COHORT_QUICK_CHECK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick_check.sh}"
  "$check_script" "$@"
}

# Backward-compatible shim for stale call-sites that still invoke
# "cohort_quick_check" directly.
cohort_quick_check() {
  prod_pilot_cohort_quick_check "$@"
}

prod_pilot_cohort_quick_trend() {
  ensure_deps_or_die
  local trend_script="${PROD_PILOT_COHORT_QUICK_TREND_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick_trend.sh}"
  "$trend_script" "$@"
}

prod_pilot_cohort_quick_alert() {
  ensure_deps_or_die
  local alert_script="${PROD_PILOT_COHORT_QUICK_ALERT_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick_alert.sh}"
  "$alert_script" "$@"
}

prod_pilot_cohort_quick_dashboard() {
  ensure_deps_or_die
  local dashboard_script="${PROD_PILOT_COHORT_QUICK_DASHBOARD_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick_dashboard.sh}"
  "$dashboard_script" "$@"
}

prod_pilot_cohort_quick_signoff() {
  ensure_deps_or_die
  local signoff_script="${PROD_PILOT_COHORT_QUICK_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick_signoff.sh}"
  "$signoff_script" "$@"
}

prod_pilot_cohort_quick_runbook() {
  ensure_deps_or_die
  local runbook_script="${PROD_PILOT_COHORT_QUICK_RUNBOOK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick_runbook.sh}"
  "$runbook_script" "$@"
}

prod_key_rotation_runbook() {
  ensure_deps_or_die
  local runbook_script="${PROD_KEY_ROTATION_RUNBOOK_SCRIPT:-$ROOT_DIR/scripts/prod_key_rotation_runbook.sh}"
  "$runbook_script" "$@"
}

prod_upgrade_runbook() {
  ensure_deps_or_die
  local runbook_script="${PROD_UPGRADE_RUNBOOK_SCRIPT:-$ROOT_DIR/scripts/prod_upgrade_runbook.sh}"
  "$runbook_script" "$@"
}

prod_operator_lifecycle_runbook() {
  ensure_deps_or_die
  local runbook_script="${PROD_OPERATOR_LIFECYCLE_RUNBOOK_SCRIPT:-$ROOT_DIR/scripts/prod_operator_lifecycle_runbook.sh}"
  "$runbook_script" "$@"
}

incident_snapshot() {
  local snapshot_script="${INCIDENT_SNAPSHOT_SCRIPT:-$ROOT_DIR/scripts/incident_snapshot.sh}"
  "$snapshot_script" "$@"
}

incident_snapshot_summary() {
  local summary_script="${INCIDENT_SNAPSHOT_SUMMARY_SCRIPT:-$ROOT_DIR/scripts/incident_snapshot_summary.sh}"
  "$summary_script" "$@"
}

# Backward-compatible shim for stale typo call-sites that used
# "apshot_summary" instead of "incident_snapshot_summary".
apshot_summary() {
  incident_snapshot_summary "$@"
}

server_env_value() {
  local key="$1"
  identity_value "$SERVER_ENV_FILE" "$key"
}

cert_not_after_unix() {
  local cert_file="$1"
  local end_raw end_epoch
  end_raw="$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | sed -E 's/^notAfter=//')"
  if [[ -z "$end_raw" ]]; then
    return 1
  fi
  end_epoch="$(date -u -d "$end_raw" +%s 2>/dev/null || true)"
  if [[ -z "$end_epoch" ]]; then
    return 1
  fi
  echo "$end_epoch"
}

file_mode_octal() {
  local file="$1"
  local mode=""
  if mode="$(stat -c "%a" "$file" 2>/dev/null)"; then
    :
  elif mode="$(stat -f "%Lp" "$file" 2>/dev/null)"; then
    :
  else
    return 1
  fi
  mode="$(printf '%s' "$mode" | tr -cd '0-7')"
  if [[ -z "$mode" ]]; then
    return 1
  fi
  echo "$mode"
}

filesystem_supports_secure_mode_bits() {
  local file="$1"
  local dir probe mode
  if [[ "$file" == /mnt/* ]]; then
    return 1
  fi
  dir="$(dirname "$file")"
  if [[ ! -d "$dir" || ! -w "$dir" ]]; then
    return 0
  fi
  probe="$(mktemp "$dir/.perm_probe.XXXXXX" 2>/dev/null || true)"
  if [[ -z "$probe" ]]; then
    return 0
  fi
  chmod 600 "$probe" 2>/dev/null || true
  mode="$(file_mode_octal "$probe" || true)"
  rm -f "$probe"
  [[ "$mode" == "600" ]]
}

private_file_mode_secure() {
  local file="$1"
  local mode oct
  if ! filesystem_supports_secure_mode_bits "$file"; then
    return 3
  fi
  mode="$(file_mode_octal "$file" || true)"
  if [[ -z "$mode" ]]; then
    return 2
  fi
  oct=$((8#$mode))
  if (( (oct & 0077) == 0 )); then
    return 0
  fi
  return 1
}

is_valid_wg_public_key() {
  local key="${1:-}"
  if [[ -z "$key" ]]; then
    return 1
  fi
  if [[ ! "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    return 1
  fi
  if command -v openssl >/dev/null 2>&1; then
    local decoded_len
    decoded_len="$(
      (printf '%s' "$key" | openssl base64 -d -A 2>/dev/null | wc -c | tr -d '[:space:]') || true
    )"
    if [[ "$decoded_len" != "32" ]]; then
      return 1
    fi
  fi
  return 0
}

default_issuer_url_for_invites() {
  local issuer_url=""
  local directory_public_url=""
  local public_host=""
  local scheme="http"
  local local_issuer_url=""
  local -a local_opts

  directory_public_url="$(trim_url "$(server_env_value "DIRECTORY_PUBLIC_URL")")"
  if is_https_url "$directory_public_url"; then
    scheme="https"
  fi
  local_issuer_url="$(ensure_url_scheme "127.0.0.1:8082" "$scheme")"
  mapfile -t local_opts < <(curl_tls_opts_for_url "$local_issuer_url")

  # Prefer local issuer endpoint when this command runs on a server machine.
  if curl -fsS --connect-timeout 2 --max-time 6 "${local_opts[@]}" "${local_issuer_url}/v1/pubkeys" >/dev/null 2>&1; then
    echo "$local_issuer_url"
    return
  fi

  if [[ -n "$directory_public_url" ]]; then
    public_host="$(host_from_url "$directory_public_url")"
    if [[ -n "$public_host" ]]; then
      issuer_url="$(ensure_url_scheme "$(url_from_host_port "$public_host" 8082)" "$scheme")"
    fi
  fi
  if [[ -z "$issuer_url" ]]; then
    issuer_url="$local_issuer_url"
  fi
  echo "$issuer_url"
}

resolve_invite_admin_token() {
  local cli_token="${1:-}"
  local file_token=""

  if [[ -n "$cli_token" ]]; then
    printf '%s\n' "$cli_token" | tr -d '\r'
    return
  fi

  file_token="$(server_env_value "ISSUER_ADMIN_TOKEN" | tr -d '\r')"
  if [[ -n "$file_token" ]]; then
    echo "$file_token"
    return
  fi

  if [[ -n "${ISSUER_ADMIN_TOKEN:-}" ]]; then
    printf '%s\n' "${ISSUER_ADMIN_TOKEN}" | tr -d '\r'
    return
  fi
}

invite_generate() {
  require_authority_mode "invite-generate"
  local issuer_url="${ISSUER_URL:-}"
  local admin_token=""
  local admin_key_file=""
  local admin_key_id=""
  local count="1"
  local prefix="inv"
  local tier="1"
  local wait_sec="0"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --issuer-url)
        issuer_url="${2:-}"
        shift 2
        ;;
      --admin-token)
        admin_token="${2:-}"
        shift 2
        ;;
      --admin-key-file)
        admin_key_file="${2:-}"
        shift 2
        ;;
      --admin-key-id)
        admin_key_id="${2:-}"
        shift 2
        ;;
      --count)
        count="${2:-}"
        shift 2
        ;;
      --prefix)
        prefix="${2:-}"
        shift 2
        ;;
      --tier)
        tier="${2:-}"
        shift 2
        ;;
      --wait-sec)
        wait_sec="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for invite-generate: $1"
        exit 2
        ;;
    esac
  done

  if [[ -z "$issuer_url" ]]; then
    issuer_url="$(default_issuer_url_for_invites)"
  fi
  issuer_url="$(trim_url "$issuer_url")"
  if [[ "$issuer_url" != http://* && "$issuer_url" != https://* ]]; then
    issuer_url="$(ensure_url_scheme "$issuer_url" "http")"
  fi
  if ! [[ "$wait_sec" =~ ^[0-9]+$ ]]; then
    echo "invite-generate requires --wait-sec >= 0"
    exit 2
  fi
  if [[ -n "$admin_key_file" || -n "$admin_key_id" ]]; then
    if [[ -z "$admin_key_file" || -z "$admin_key_id" ]]; then
      echo "invite-generate requires --admin-key-file and --admin-key-id together"
      exit 2
    fi
  fi
  if ((wait_sec > 0)); then
    local -a issuer_opts
    mapfile -t issuer_opts < <(curl_tls_opts_for_url "$issuer_url")
    wait_http_ok_with_opts "${issuer_url%/}/v1/pubkeys" "issuer for invite-generate" "$wait_sec" "${issuer_opts[@]}" || {
      echo "invite-generate failed: issuer not ready at ${issuer_url%/}/v1/pubkeys within ${wait_sec}s"
      exit 1
    }
  fi

  local auth_details auth_mode
  auth_details="$(resolve_invite_admin_auth "$admin_token" "$admin_key_file" "$admin_key_id")"
  IFS='|' read -r auth_mode admin_token admin_key_file admin_key_id <<<"$auth_details"
  enforce_invite_auth_mode_or_die "invite-generate" "$auth_mode"
  if ! [[ "$count" =~ ^[0-9]+$ ]] || ((count < 1)); then
    echo "invite-generate requires --count >= 1"
    exit 2
  fi
  if [[ "$tier" != "1" && "$tier" != "2" && "$tier" != "3" ]]; then
    echo "invite-generate requires --tier 1|2|3"
    exit 2
  fi
  prefix="$(printf '%s' "$prefix" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-_')"
  if [[ -z "$prefix" ]]; then
    prefix="inv"
  fi

  local upsert_script="$ROOT_DIR/scripts/beta_subject_upsert.sh"
  if [[ ! -x "$upsert_script" ]]; then
    echo "missing helper script: $upsert_script"
    exit 2
  fi

  local generated=0
  local attempts=0
  local max_attempts=$((count * 8))
  local last_error=""
  if ((max_attempts < 8)); then
    max_attempts=8
  fi
  local key
  while ((generated < count)); do
    attempts=$((attempts + 1))
    if ((attempts > max_attempts)); then
      echo "invite-generate failed: could not create requested keys after $max_attempts attempts"
      echo "check issuer URL/admin auth: issuer=$issuer_url"
      if [[ -n "$last_error" ]]; then
        echo "last error:"
        echo "$last_error"
      fi
      exit 1
    fi
    key="${prefix}-$(random_token | tr -cd 'a-zA-Z0-9' | tr '[:upper:]' '[:lower:]' | head -c 22)"
    if [[ -z "$key" ]]; then
      continue
    fi
    local upsert_out=""
    local -a upsert_cmd=(
      "$upsert_script"
      --issuer-url "$issuer_url"
      --subject "$key"
      --kind "client"
      --tier "$tier"
    )
    if [[ "$auth_mode" == "signed" ]]; then
      upsert_cmd+=(--admin-key-file "$admin_key_file" --admin-key-id "$admin_key_id")
    else
      upsert_cmd+=(--admin-token "$admin_token")
    fi
    set +e
    upsert_out="$("${upsert_cmd[@]}" 2>&1)"
    local upsert_rc=$?
    set -e
    if [[ $upsert_rc -eq 0 ]]; then
      generated=$((generated + 1))
      echo "$key"
    else
      last_error="$upsert_out"
      if [[ "$upsert_out" == *"401"* || "$upsert_out" == *"403"* ]]; then
        echo "invite-generate failed: issuer rejected admin auth (issuer=$issuer_url)"
        if [[ -n "$last_error" ]]; then
          echo "$last_error"
        fi
        exit 1
      fi
    fi
  done
  echo "invite keys generated: $generated (issuer=$issuer_url)"
  if [[ -n "$last_error" && "$generated" -lt "$count" ]]; then
    echo "last invite-generate error:"
    echo "$last_error"
  fi
}

invite_check() {
  require_authority_mode "invite-check"
  local key=""
  local issuer_url="${ISSUER_URL:-}"
  local admin_token=""
  local admin_key_file=""
  local admin_key_id=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key|--subject)
        key="${2:-}"
        shift 2
        ;;
      --issuer-url)
        issuer_url="${2:-}"
        shift 2
        ;;
      --admin-token)
        admin_token="${2:-}"
        shift 2
        ;;
      --admin-key-file)
        admin_key_file="${2:-}"
        shift 2
        ;;
      --admin-key-id)
        admin_key_id="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for invite-check: $1"
        exit 2
        ;;
    esac
  done

  key="$(trim "$key")"
  if [[ -z "$key" ]]; then
    echo "invite-check requires --key"
    exit 2
  fi
  if [[ -z "$issuer_url" ]]; then
    issuer_url="$(default_issuer_url_for_invites)"
  fi
  issuer_url="$(trim_url "$issuer_url")"
  if [[ "$issuer_url" != http://* && "$issuer_url" != https://* ]]; then
    issuer_url="$(ensure_url_scheme "$issuer_url" "http")"
  fi
  if [[ -n "$admin_key_file" || -n "$admin_key_id" ]]; then
    if [[ -z "$admin_key_file" || -z "$admin_key_id" ]]; then
      echo "invite-check requires --admin-key-file and --admin-key-id together"
      exit 2
    fi
  fi

  local auth_details auth_mode
  auth_details="$(resolve_invite_admin_auth "$admin_token" "$admin_key_file" "$admin_key_id")"
  IFS='|' read -r auth_mode admin_token admin_key_file admin_key_id <<<"$auth_details"
  enforce_invite_auth_mode_or_die "invite-check" "$auth_mode"

  local request_url="${issuer_url}/v1/admin/subject/get?subject=${key}"
  local -a header_args=()
  local -a tls_args=()
  build_admin_header_args "GET" "$request_url" "" "$auth_mode" "$admin_token" "$admin_key_file" "$admin_key_id" header_args
  mapfile -t tls_args < <(curl_tls_opts_for_url "$issuer_url")

  local payload
  payload="$(curl -fsS --connect-timeout 4 --max-time 12 "${tls_args[@]}" "${header_args[@]}" "$request_url" 2>/dev/null || true)"
  if [[ -z "$payload" ]]; then
    echo "invite key not found: $key"
    exit 1
  fi

  local kind tier
  kind="$(printf '%s\n' "$payload" | rg -o '"kind":"[^"]+"' | head -n 1 | sed -E 's/^"kind":"([^"]+)"$/\1/')"
  tier="$(printf '%s\n' "$payload" | rg -o '"tier":[0-9]+' | head -n 1 | sed -E 's/^"tier":([0-9]+)$/\1/')"
  if [[ "$kind" == "client" && "${tier:-0}" -ge 1 ]]; then
    echo "invite key valid: key=$key kind=$kind tier=$tier issuer=$issuer_url"
    return 0
  fi
  echo "invite key not eligible for client use: key=$key kind=${kind:-unknown} tier=${tier:-unknown}"
  return 1
}

invite_disable() {
  require_authority_mode "invite-disable"
  local key=""
  local issuer_url="${ISSUER_URL:-}"
  local admin_token=""
  local admin_key_file=""
  local admin_key_id=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key|--subject)
        key="${2:-}"
        shift 2
        ;;
      --issuer-url)
        issuer_url="${2:-}"
        shift 2
        ;;
      --admin-token)
        admin_token="${2:-}"
        shift 2
        ;;
      --admin-key-file)
        admin_key_file="${2:-}"
        shift 2
        ;;
      --admin-key-id)
        admin_key_id="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for invite-disable: $1"
        exit 2
        ;;
    esac
  done

  key="$(trim "$key")"
  if [[ -z "$key" ]]; then
    echo "invite-disable requires --key"
    exit 2
  fi
  if [[ -z "$issuer_url" ]]; then
    issuer_url="$(default_issuer_url_for_invites)"
  fi
  issuer_url="$(trim_url "$issuer_url")"
  if [[ "$issuer_url" != http://* && "$issuer_url" != https://* ]]; then
    issuer_url="$(ensure_url_scheme "$issuer_url" "http")"
  fi
  if [[ -n "$admin_key_file" || -n "$admin_key_id" ]]; then
    if [[ -z "$admin_key_file" || -z "$admin_key_id" ]]; then
      echo "invite-disable requires --admin-key-file and --admin-key-id together"
      exit 2
    fi
  fi

  local auth_details auth_mode
  auth_details="$(resolve_invite_admin_auth "$admin_token" "$admin_key_file" "$admin_key_id")"
  IFS='|' read -r auth_mode admin_token admin_key_file admin_key_id <<<"$auth_details"
  enforce_invite_auth_mode_or_die "invite-disable" "$auth_mode"

  local upsert_script="$ROOT_DIR/scripts/beta_subject_upsert.sh"
  if [[ ! -x "$upsert_script" ]]; then
    echo "missing helper script: $upsert_script"
    exit 2
  fi
  local -a upsert_cmd=(
    "$upsert_script"
    --issuer-url "$issuer_url"
    --subject "$key"
    --kind "relay-exit"
    --tier "1"
  )
  if [[ "$auth_mode" == "signed" ]]; then
    upsert_cmd+=(--admin-key-file "$admin_key_file" --admin-key-id "$admin_key_id")
  else
    upsert_cmd+=(--admin-token "$admin_token")
  fi
  "${upsert_cmd[@]}" >/dev/null
  echo "invite key disabled: $key (issuer=$issuer_url)"
}

set_env_kv() {
  local env_file="$1"
  local key="$2"
  local value="$3"
  local escaped
  escaped="$(printf '%s' "$value" | sed -e 's/[&|]/\\&/g')"
  if rg -q "^${key}=" "$env_file"; then
    sed -i -E "s|^${key}=.*$|${key}=${escaped}|" "$env_file"
  else
    printf '%s=%s\n' "$key" "$value" >>"$env_file"
  fi
}

admin_signing_status() {
  require_authority_mode "admin-signing-status"
  ensure_deps_or_die
  need_cmd go || exit 2

  local env_file="$AUTHORITY_ENV_FILE"
  if [[ ! -f "$env_file" ]]; then
    echo "admin-signing-status requires authority env file: $env_file"
    exit 2
  fi

  local key_file key_id signers_container signers_local
  key_file="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL")"
  key_id="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_KEY_ID")"
  signers_container="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_KEYS_FILE")"

  if [[ -z "$key_file" ]]; then
    key_file="$DEPLOY_DIR/data/issuer/issuer_admin_signer.key"
  fi
  if [[ -z "$signers_container" ]]; then
    signers_container="/app/data/issuer_admin_signers.txt"
  fi
  signers_local="$DEPLOY_DIR/data/issuer/$(basename "$signers_container")"
  if [[ -z "$key_id" && -f "${key_file}.keyid" ]]; then
    key_id="$(tr -d '\r\n' <"${key_file}.keyid")"
  fi

  echo "authority env: $env_file"
  echo "admin_signing_key_file: $key_file"
  echo "admin_signing_key_id: ${key_id:-<unset>}"
  echo "admin_signing_pubkeys_file(local): $signers_local"
  echo "admin_signing_pubkeys_file(container): $signers_container"

  if [[ ! -f "$key_file" ]]; then
    echo "status: missing private signing key file"
    return 1
  fi
  if [[ ! -f "$signers_local" ]]; then
    echo "status: missing signer public-key file"
    return 1
  fi

  local inspect_json derived_id derived_pub
  inspect_json="$(
    cd "$ROOT_DIR"
    go run ./cmd/adminsig inspect --private-key-file "$key_file"
  )"
  derived_id="$(printf '%s\n' "$inspect_json" | rg -o '"key_id":"[^"]+"' | head -n1 | sed -E 's/^"key_id":"([^"]+)"$/\1/')"
  derived_pub="$(printf '%s\n' "$inspect_json" | rg -o '"public_key":"[^"]+"' | head -n1 | sed -E 's/^"public_key":"([^"]+)"$/\1/')"
  if [[ -z "$derived_id" || -z "$derived_pub" ]]; then
    echo "status: failed to inspect signing key"
    return 1
  fi
  echo "derived_key_id: $derived_id"

  if [[ -n "$key_id" && "$key_id" != "$derived_id" ]]; then
    echo "status: key id mismatch (env=$key_id derived=$derived_id)"
    return 1
  fi
  if ! rg -q "^${derived_id}=${derived_pub}$" "$signers_local"; then
    echo "status: signer public-key file missing derived key mapping"
    return 1
  fi
  local first_key_id key_count
  first_key_id="$(awk -F= 'NF > 0 {print $1; exit}' "$signers_local")"
  key_count="$(awk 'NF > 0 && $0 !~ /^#/ {n++} END {print n + 0}' "$signers_local")"
  echo "signing_key_history_count: $key_count"
  if [[ "$first_key_id" != "$derived_id" ]]; then
    echo "status: signer public-key file does not prioritize active key"
    return 1
  fi
  echo "status: ok"
}

admin_signing_rotate() {
  require_authority_mode "admin-signing-rotate"
  ensure_deps_or_die
  need_cmd go || exit 2

  local restart_issuer="1"
  local key_history="${EASY_NODE_ADMIN_SIGNING_KEY_HISTORY:-3}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --restart-issuer)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          restart_issuer="${2:-}"
          shift 2
        else
          restart_issuer="1"
          shift
        fi
        ;;
      --key-history)
        key_history="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for admin-signing-rotate: $1"
        exit 2
        ;;
    esac
  done
  if ! [[ "$key_history" =~ ^[0-9]+$ ]] || ((key_history < 1)); then
    echo "admin-signing-rotate requires --key-history >= 1"
    exit 2
  fi

  local material key_file key_id signers_local signers_container
  material="$(ensure_admin_signing_material 1 "$key_history")"
  IFS='|' read -r key_file key_id signers_local signers_container <<<"$material"
  if [[ -z "$key_file" || -z "$key_id" || -z "$signers_container" ]]; then
    echo "admin-signing-rotate failed to generate signing material"
    exit 1
  fi

  set_env_kv "$AUTHORITY_ENV_FILE" "ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL" "$key_file"
  set_env_kv "$AUTHORITY_ENV_FILE" "ISSUER_ADMIN_SIGNING_KEY_ID" "$key_id"
  set_env_kv "$AUTHORITY_ENV_FILE" "ISSUER_ADMIN_SIGNING_KEYS_FILE" "$signers_container"
  set_env_kv "$AUTHORITY_ENV_FILE" "ISSUER_ADMIN_REQUIRE_SIGNED" "1"
  set_env_kv "$AUTHORITY_ENV_FILE" "ISSUER_ADMIN_ALLOW_TOKEN" "0"
  set_env_kv "$AUTHORITY_ENV_FILE" "EASY_NODE_ADMIN_SIGNING_KEY_HISTORY" "$key_history"
  secure_file_permissions "$AUTHORITY_ENV_FILE"

  echo "admin signing key rotated"
  echo "key_id: $key_id"
  echo "key_file: $key_file"
  echo "signers_file: $signers_local"
  echo "key_history: $key_history"

  if [[ "$restart_issuer" == "1" ]]; then
    compose_with_env "$AUTHORITY_ENV_FILE" up -d issuer
    local scheme issuer_url
    scheme="http"
    if [[ "$(identity_value "$AUTHORITY_ENV_FILE" "PROD_STRICT_MODE")" == "1" ]]; then
      scheme="https"
    fi
    issuer_url="${scheme}://127.0.0.1:8082/v1/pubkeys"
    local -a tls_opts
    mapfile -t tls_opts < <(curl_tls_opts_for_url "${scheme}://127.0.0.1:8082")
    wait_http_ok_with_opts "$issuer_url" "issuer after signer rotate" 40 "${tls_opts[@]}" || {
      compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=120 issuer
      exit 1
    }
    echo "issuer restarted with rotated signing key"
  fi
}

prod_preflight() {
  ensure_deps_or_die
  need_cmd openssl || exit 2
  need_cmd go || exit 2

  local days_min="14"
  local check_live="${EASY_NODE_PROD_PREFLIGHT_CHECK_LIVE:-0}"
  local timeout_sec="${EASY_NODE_PROD_PREFLIGHT_TIMEOUT_SEC:-12}"
  local live_require_configured_healthy="${EASY_NODE_PROD_PREFLIGHT_LIVE_REQUIRE_CONFIGURED_HEALTHY:-0}"
  local live_max_cooling_retry_sec="${EASY_NODE_PROD_PREFLIGHT_LIVE_MAX_COOLING_RETRY_SEC:-0}"
  local live_max_peer_sync_age_sec="${EASY_NODE_PROD_PREFLIGHT_LIVE_MAX_PEER_SYNC_AGE_SEC:-0}"
  local live_max_issuer_sync_age_sec="${EASY_NODE_PROD_PREFLIGHT_LIVE_MAX_ISSUER_SYNC_AGE_SEC:-0}"
  local live_min_peer_success_sources="${EASY_NODE_PROD_PREFLIGHT_LIVE_MIN_PEER_SUCCESS_SOURCES:-0}"
  local live_min_issuer_success_sources="${EASY_NODE_PROD_PREFLIGHT_LIVE_MIN_ISSUER_SUCCESS_SOURCES:-0}"
  local live_min_peer_source_operators="${EASY_NODE_PROD_PREFLIGHT_LIVE_MIN_PEER_SOURCE_OPERATORS:-0}"
  local live_min_issuer_source_operators="${EASY_NODE_PROD_PREFLIGHT_LIVE_MIN_ISSUER_SOURCE_OPERATORS:-0}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --days-min)
        days_min="${2:-}"
        shift 2
        ;;
      --check-live)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          check_live="${2:-}"
          shift 2
        else
          check_live="1"
          shift
        fi
        ;;
      --timeout-sec)
        timeout_sec="${2:-}"
        shift 2
        ;;
      --live-require-configured-healthy)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          live_require_configured_healthy="${2:-}"
          shift 2
        else
          live_require_configured_healthy="1"
          shift
        fi
        ;;
      --live-max-cooling-retry-sec)
        live_max_cooling_retry_sec="${2:-}"
        shift 2
        ;;
      --live-max-peer-sync-age-sec)
        live_max_peer_sync_age_sec="${2:-}"
        shift 2
        ;;
      --live-max-issuer-sync-age-sec)
        live_max_issuer_sync_age_sec="${2:-}"
        shift 2
        ;;
      --live-min-peer-success-sources)
        live_min_peer_success_sources="${2:-}"
        shift 2
        ;;
      --live-min-issuer-success-sources)
        live_min_issuer_success_sources="${2:-}"
        shift 2
        ;;
      --live-min-peer-source-operators)
        live_min_peer_source_operators="${2:-}"
        shift 2
        ;;
      --live-min-issuer-source-operators)
        live_min_issuer_source_operators="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for prod-preflight: $1"
        exit 2
        ;;
    esac
  done
  if ! [[ "$days_min" =~ ^[0-9]+$ ]]; then
    echo "prod-preflight requires --days-min to be numeric"
    exit 2
  fi
  if [[ "$check_live" != "0" && "$check_live" != "1" ]]; then
    echo "prod-preflight requires --check-live to be 0 or 1"
    exit 2
  fi
  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || ((timeout_sec < 1)); then
    echo "prod-preflight requires --timeout-sec >= 1"
    exit 2
  fi
  if [[ "$live_require_configured_healthy" != "0" && "$live_require_configured_healthy" != "1" ]]; then
    echo "prod-preflight requires --live-require-configured-healthy to be 0 or 1"
    exit 2
  fi
  if ! [[ "$live_max_cooling_retry_sec" =~ ^[0-9]+$ ]]; then
    echo "prod-preflight requires --live-max-cooling-retry-sec to be >= 0"
    exit 2
  fi
  if ! [[ "$live_max_peer_sync_age_sec" =~ ^[0-9]+$ ]]; then
    echo "prod-preflight requires --live-max-peer-sync-age-sec to be >= 0"
    exit 2
  fi
  if ! [[ "$live_max_issuer_sync_age_sec" =~ ^[0-9]+$ ]]; then
    echo "prod-preflight requires --live-max-issuer-sync-age-sec to be >= 0"
    exit 2
  fi
  if ! [[ "$live_min_peer_success_sources" =~ ^[0-9]+$ ]]; then
    echo "prod-preflight requires --live-min-peer-success-sources to be >= 0"
    exit 2
  fi
  if ! [[ "$live_min_issuer_success_sources" =~ ^[0-9]+$ ]]; then
    echo "prod-preflight requires --live-min-issuer-success-sources to be >= 0"
    exit 2
  fi
  if ! [[ "$live_min_peer_source_operators" =~ ^[0-9]+$ ]]; then
    echo "prod-preflight requires --live-min-peer-source-operators to be >= 0"
    exit 2
  fi
  if ! [[ "$live_min_issuer_source_operators" =~ ^[0-9]+$ ]]; then
    echo "prod-preflight requires --live-min-issuer-source-operators to be >= 0"
    exit 2
  fi

  local mode env_file
  mode="$(active_server_mode)"
  env_file="$(active_server_env_file)"
  if [[ ! -f "$env_file" ]]; then
    echo "prod-preflight requires an existing server env file: $env_file"
    exit 2
  fi

  local fail=0
  local check_total=0
  check_ok() {
    local msg="$1"
    check_total=$((check_total + 1))
    echo "[ok] $msg"
  }
  check_fail() {
    local msg="$1"
    check_total=$((check_total + 1))
    fail=$((fail + 1))
    echo "[fail] $msg"
  }

  local prod_strict beta_strict mtls_enable
  prod_strict="$(identity_value "$env_file" "PROD_STRICT_MODE")"
  beta_strict="$(identity_value "$env_file" "BETA_STRICT_MODE")"
  mtls_enable="$(identity_value "$env_file" "MTLS_ENABLE")"
  if [[ "$prod_strict" == "1" ]]; then
    check_ok "PROD_STRICT_MODE=1"
  else
    check_fail "PROD_STRICT_MODE must be 1"
  fi
  if [[ "$beta_strict" == "1" ]]; then
    check_ok "BETA_STRICT_MODE=1"
  else
    check_fail "BETA_STRICT_MODE must be 1"
  fi
  if [[ "$mtls_enable" == "1" ]]; then
    check_ok "MTLS_ENABLE=1"
  else
    check_fail "MTLS_ENABLE must be 1"
  fi

  local public_urls=()
  local directory_public_url entry_public_url exit_public_url
  directory_public_url="$(identity_value "$env_file" "DIRECTORY_PUBLIC_URL")"
  entry_public_url="$(identity_value "$env_file" "ENTRY_URL_PUBLIC")"
  exit_public_url="$(identity_value "$env_file" "EXIT_CONTROL_URL_PUBLIC")"
  [[ -n "$directory_public_url" ]] && public_urls+=("$directory_public_url")
  [[ -n "$entry_public_url" ]] && public_urls+=("$entry_public_url")
  [[ -n "$exit_public_url" ]] && public_urls+=("$exit_public_url")
  local u
  for u in "${public_urls[@]}"; do
    if is_https_url "$u"; then
      check_ok "HTTPS URL set: $u"
    else
      check_fail "non-HTTPS URL in prod profile: $u"
    fi
    local public_host
    public_host="$(host_from_url "$u")"
    if [[ -z "$public_host" ]]; then
      check_fail "unable to parse public URL host: $u"
    elif host_is_private_or_loopback "$public_host"; then
      check_fail "public URL host must not be private/loopback in prod profile: $u"
    else
      check_ok "public URL host is non-private: $u"
    fi
  done

  local ca_file cert_file key_file client_cert_file client_key_file
  ca_file="$(identity_value "$env_file" "EASY_NODE_MTLS_CA_FILE_LOCAL")"
  cert_file="$(identity_value "$env_file" "MTLS_CERT_FILE")"
  key_file="$(identity_value "$env_file" "MTLS_KEY_FILE")"
  client_cert_file="$(identity_value "$env_file" "EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL")"
  client_key_file="$(identity_value "$env_file" "EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL")"
  [[ -z "$ca_file" ]] && ca_file="$DEPLOY_DIR/tls/ca.crt"
  if [[ -z "$cert_file" ]]; then
    cert_file="$DEPLOY_DIR/tls/node.crt"
  elif [[ "$cert_file" == /app/tls/* ]]; then
    cert_file="$DEPLOY_DIR/tls/$(basename "$cert_file")"
  fi
  if [[ -z "$key_file" ]]; then
    key_file="$DEPLOY_DIR/tls/node.key"
  elif [[ "$key_file" == /app/tls/* ]]; then
    key_file="$DEPLOY_DIR/tls/$(basename "$key_file")"
  fi
  [[ -z "$client_cert_file" ]] && client_cert_file="$DEPLOY_DIR/tls/client.crt"
  [[ -z "$client_key_file" ]] && client_key_file="$DEPLOY_DIR/tls/client.key"

  local required_files=("$ca_file" "$cert_file" "$key_file" "$client_cert_file" "$client_key_file")
  local f
  for f in "${required_files[@]}"; do
    if [[ -f "$f" ]]; then
      check_ok "file exists: $f"
    else
      check_fail "missing file: $f"
    fi
  done

  local directory_admin_token entry_puzzle_secret
  directory_admin_token="$(identity_value "$env_file" "DIRECTORY_ADMIN_TOKEN")"
  entry_puzzle_secret="$(identity_value "$env_file" "ENTRY_PUZZLE_SECRET")"
  if [[ -n "$directory_admin_token" && "$directory_admin_token" != "dev-admin-token" && "${#directory_admin_token}" -ge 16 ]]; then
    check_ok "DIRECTORY_ADMIN_TOKEN configured and non-default"
  else
    check_fail "DIRECTORY_ADMIN_TOKEN must be set, non-default, and len>=16"
  fi
  if [[ -n "$entry_puzzle_secret" && "$entry_puzzle_secret" != "entry-secret-default" && "${#entry_puzzle_secret}" -ge 16 ]]; then
    check_ok "ENTRY_PUZZLE_SECRET configured and non-default"
  else
    check_fail "ENTRY_PUZZLE_SECRET must be set, non-default, and len>=16"
  fi
  local entry_puzzle_difficulty_raw entry_puzzle_difficulty
  entry_puzzle_difficulty_raw="$(identity_value "$env_file" "ENTRY_PUZZLE_DIFFICULTY")"
  entry_puzzle_difficulty="$entry_puzzle_difficulty_raw"
  if [[ -z "$entry_puzzle_difficulty" ]]; then
    # docker-compose default is 1 when unset
    entry_puzzle_difficulty="1"
  fi
  if [[ "$entry_puzzle_difficulty" =~ ^[0-9]+$ ]] && ((entry_puzzle_difficulty > 0)); then
    check_ok "ENTRY_PUZZLE_DIFFICULTY effective >0 (${entry_puzzle_difficulty})"
  else
    check_fail "ENTRY_PUZZLE_DIFFICULTY must be >0 in prod profile (effective value: ${entry_puzzle_difficulty_raw:-default})"
  fi

  local data_mode wg_backend entry_live_wg exit_live_wg exit_wg_kernel_proxy
  local exit_wg_private_key_path exit_wg_interface exit_wg_auto_create exit_wg_pubkey
  local exit_opaque_sink exit_opaque_source exit_issuer_min_sources exit_issuer_min_operators
  local exit_issuer_require_id issuer_urls_csv issuer_urls_n directory_issuer_urls_csv directory_issuer_urls_n
  local entry_open_rps entry_ban_threshold entry_ban_sec entry_max_concurrent_opens
  local dir_peer_dispute_min_votes dir_peer_appeal_min_votes dir_adjudication_meta_min_votes
  local dir_final_dispute_min_votes dir_final_appeal_min_votes
  local dir_final_min_operators dir_final_min_sources
  local dir_final_adjudication_min_ratio dir_dispute_max_ttl_sec dir_appeal_max_ttl_sec
  local entry_exit_user entry_exit_privileged
  data_mode="$(identity_value "$env_file" "DATA_PLANE_MODE")"
  wg_backend="$(identity_value "$env_file" "WG_BACKEND")"
  entry_live_wg="$(identity_value "$env_file" "ENTRY_LIVE_WG_MODE")"
  exit_live_wg="$(identity_value "$env_file" "EXIT_LIVE_WG_MODE")"
  exit_wg_kernel_proxy="$(identity_value "$env_file" "EXIT_WG_KERNEL_PROXY")"
  exit_wg_private_key_path="$(identity_value "$env_file" "EXIT_WG_PRIVATE_KEY_PATH")"
  exit_wg_interface="$(identity_value "$env_file" "EXIT_WG_INTERFACE")"
  exit_wg_auto_create="$(identity_value "$env_file" "EXIT_WG_AUTO_CREATE_INTERFACE")"
  exit_wg_pubkey="$(identity_value "$env_file" "EXIT_WG_PUBKEY")"
  exit_opaque_sink="$(identity_value "$env_file" "EXIT_OPAQUE_SINK_ADDR")"
  exit_opaque_source="$(identity_value "$env_file" "EXIT_OPAQUE_SOURCE_ADDR")"
  exit_issuer_min_sources="$(identity_value "$env_file" "EXIT_ISSUER_MIN_SOURCES")"
  exit_issuer_min_operators="$(identity_value "$env_file" "EXIT_ISSUER_MIN_OPERATORS")"
  exit_issuer_require_id="$(identity_value "$env_file" "EXIT_ISSUER_REQUIRE_ID")"
  issuer_urls_csv="$(identity_value "$env_file" "ISSUER_URLS")"
  issuer_urls_n="$(csv_count "$issuer_urls_csv")"
  directory_issuer_urls_csv="$(identity_value "$env_file" "DIRECTORY_ISSUER_TRUST_URLS")"
  directory_issuer_urls_n="$(csv_count "$directory_issuer_urls_csv")"
  entry_open_rps="$(identity_value "$env_file" "ENTRY_OPEN_RPS")"
  entry_ban_threshold="$(identity_value "$env_file" "ENTRY_BAN_THRESHOLD")"
  entry_ban_sec="$(identity_value "$env_file" "ENTRY_BAN_SEC")"
  entry_max_concurrent_opens="$(identity_value "$env_file" "ENTRY_MAX_CONCURRENT_OPENS")"
  dir_peer_dispute_min_votes="$(identity_value "$env_file" "DIRECTORY_PEER_DISPUTE_MIN_VOTES")"
  dir_peer_appeal_min_votes="$(identity_value "$env_file" "DIRECTORY_PEER_APPEAL_MIN_VOTES")"
  dir_adjudication_meta_min_votes="$(identity_value "$env_file" "DIRECTORY_ADJUDICATION_META_MIN_VOTES")"
  dir_final_dispute_min_votes="$(identity_value "$env_file" "DIRECTORY_FINAL_DISPUTE_MIN_VOTES")"
  dir_final_appeal_min_votes="$(identity_value "$env_file" "DIRECTORY_FINAL_APPEAL_MIN_VOTES")"
  dir_final_min_operators="$(identity_value "$env_file" "DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS")"
  dir_final_min_sources="$(identity_value "$env_file" "DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES")"
  dir_final_adjudication_min_ratio="$(identity_value "$env_file" "DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO")"
  dir_dispute_max_ttl_sec="$(identity_value "$env_file" "DIRECTORY_DISPUTE_MAX_TTL_SEC")"
  dir_appeal_max_ttl_sec="$(identity_value "$env_file" "DIRECTORY_APPEAL_MAX_TTL_SEC")"
  entry_exit_user="$(identity_value "$env_file" "ENTRY_EXIT_USER")"
  entry_exit_privileged="$(identity_value "$env_file" "ENTRY_EXIT_PRIVILEGED")"

  if [[ "$data_mode" == "opaque" ]]; then
    check_ok "DATA_PLANE_MODE=opaque"
  else
    check_fail "DATA_PLANE_MODE must be opaque in prod profile"
  fi
  if [[ "$wg_backend" == "command" ]]; then
    check_ok "WG_BACKEND=command"
  else
    check_fail "WG_BACKEND must be command in prod profile"
  fi
  if [[ "$entry_live_wg" == "1" ]]; then
    check_ok "ENTRY_LIVE_WG_MODE=1"
  else
    check_fail "ENTRY_LIVE_WG_MODE must be 1 in prod profile"
  fi
  if [[ "$exit_live_wg" == "1" ]]; then
    check_ok "EXIT_LIVE_WG_MODE=1"
  else
    check_fail "EXIT_LIVE_WG_MODE must be 1 in prod profile"
  fi
  if [[ "$exit_wg_kernel_proxy" == "1" ]]; then
    check_ok "EXIT_WG_KERNEL_PROXY=1"
  else
    check_fail "EXIT_WG_KERNEL_PROXY must be 1 in prod profile"
  fi
  if [[ "$exit_wg_auto_create" == "1" ]]; then
    check_ok "EXIT_WG_AUTO_CREATE_INTERFACE=1"
  else
    check_fail "EXIT_WG_AUTO_CREATE_INTERFACE must be 1 in prod profile"
  fi
  if [[ -n "$exit_wg_interface" ]]; then
    check_ok "EXIT_WG_INTERFACE configured"
  else
    check_fail "EXIT_WG_INTERFACE must be configured"
  fi
  if [[ -n "$exit_wg_pubkey" ]]; then
    if is_valid_wg_public_key "$exit_wg_pubkey"; then
      check_ok "EXIT_WG_PUBKEY valid"
    else
      check_fail "EXIT_WG_PUBKEY invalid; must be a valid WireGuard public key or unset for runtime derivation"
    fi
  else
    check_ok "EXIT_WG_PUBKEY unset (runtime derivation expected)"
  fi
  if [[ -n "$exit_opaque_sink" ]]; then
    check_ok "EXIT_OPAQUE_SINK_ADDR configured"
  else
    check_fail "EXIT_OPAQUE_SINK_ADDR must be configured"
  fi
  if [[ -n "$exit_opaque_source" ]]; then
    check_ok "EXIT_OPAQUE_SOURCE_ADDR configured"
  else
    check_fail "EXIT_OPAQUE_SOURCE_ADDR must be configured"
  fi
  if [[ "$exit_issuer_min_sources" =~ ^[0-9]+$ ]] && ((exit_issuer_min_sources >= 2)); then
    check_ok "EXIT_ISSUER_MIN_SOURCES>=2 (${exit_issuer_min_sources})"
  else
    check_fail "EXIT_ISSUER_MIN_SOURCES must be >=2 in prod profile"
  fi
  if [[ "$exit_issuer_min_operators" =~ ^[0-9]+$ ]] && ((exit_issuer_min_operators >= 2)); then
    check_ok "EXIT_ISSUER_MIN_OPERATORS>=2 (${exit_issuer_min_operators})"
  else
    check_fail "EXIT_ISSUER_MIN_OPERATORS must be >=2 in prod profile"
  fi
  if [[ "$exit_issuer_require_id" == "1" ]]; then
    check_ok "EXIT_ISSUER_REQUIRE_ID=1"
  else
    check_fail "EXIT_ISSUER_REQUIRE_ID must be 1 in prod profile"
  fi
  if ((issuer_urls_n >= 2)); then
    check_ok "ISSUER_URLS count>=2 (${issuer_urls_n})"
  else
    check_fail "ISSUER_URLS must contain at least 2 URLs in prod profile"
  fi
  if ((directory_issuer_urls_n >= 2)); then
    check_ok "DIRECTORY_ISSUER_TRUST_URLS count>=2 (${directory_issuer_urls_n})"
  else
    check_fail "DIRECTORY_ISSUER_TRUST_URLS must contain at least 2 URLs in prod profile"
  fi
  if [[ "$entry_open_rps" =~ ^[0-9]+$ ]] && ((entry_open_rps >= 1 && entry_open_rps <= 12)); then
    check_ok "ENTRY_OPEN_RPS abuse guard <=12 (${entry_open_rps})"
  else
    check_fail "ENTRY_OPEN_RPS must be set in range 1..12 in prod profile"
  fi
  if [[ "$entry_ban_threshold" =~ ^[0-9]+$ ]] && ((entry_ban_threshold >= 2 && entry_ban_threshold <= 3)); then
    check_ok "ENTRY_BAN_THRESHOLD abuse guard in [2,3] (${entry_ban_threshold})"
  else
    check_fail "ENTRY_BAN_THRESHOLD must be set in range 2..3 in prod profile"
  fi
  if [[ "$entry_ban_sec" =~ ^[0-9]+$ ]] && ((entry_ban_sec >= 60)); then
    check_ok "ENTRY_BAN_SEC abuse guard >=60s (${entry_ban_sec})"
  else
    check_fail "ENTRY_BAN_SEC must be >=60 in prod profile"
  fi
  if [[ "$entry_max_concurrent_opens" =~ ^[0-9]+$ ]] && ((entry_max_concurrent_opens >= 1 && entry_max_concurrent_opens <= 96)); then
    check_ok "ENTRY_MAX_CONCURRENT_OPENS abuse guard <=96 (${entry_max_concurrent_opens})"
  else
    check_fail "ENTRY_MAX_CONCURRENT_OPENS must be set in range 1..96 in prod profile"
  fi
  if [[ "$dir_peer_dispute_min_votes" =~ ^[0-9]+$ ]] && ((dir_peer_dispute_min_votes >= 2)); then
    check_ok "DIRECTORY_PEER_DISPUTE_MIN_VOTES>=2 (${dir_peer_dispute_min_votes})"
  else
    check_fail "DIRECTORY_PEER_DISPUTE_MIN_VOTES must be >=2 in prod profile"
  fi
  if [[ "$dir_peer_appeal_min_votes" =~ ^[0-9]+$ ]] && ((dir_peer_appeal_min_votes >= 2)); then
    check_ok "DIRECTORY_PEER_APPEAL_MIN_VOTES>=2 (${dir_peer_appeal_min_votes})"
  else
    check_fail "DIRECTORY_PEER_APPEAL_MIN_VOTES must be >=2 in prod profile"
  fi
  if [[ "$dir_adjudication_meta_min_votes" =~ ^[0-9]+$ ]] && ((dir_adjudication_meta_min_votes >= 2)); then
    check_ok "DIRECTORY_ADJUDICATION_META_MIN_VOTES>=2 (${dir_adjudication_meta_min_votes})"
  else
    check_fail "DIRECTORY_ADJUDICATION_META_MIN_VOTES must be >=2 in prod profile"
  fi
  if [[ "$dir_final_dispute_min_votes" =~ ^[0-9]+$ ]] && ((dir_final_dispute_min_votes >= 2)); then
    check_ok "DIRECTORY_FINAL_DISPUTE_MIN_VOTES>=2 (${dir_final_dispute_min_votes})"
  else
    check_fail "DIRECTORY_FINAL_DISPUTE_MIN_VOTES must be >=2 in prod profile"
  fi
  if [[ "$dir_final_appeal_min_votes" =~ ^[0-9]+$ ]] && ((dir_final_appeal_min_votes >= 2)); then
    check_ok "DIRECTORY_FINAL_APPEAL_MIN_VOTES>=2 (${dir_final_appeal_min_votes})"
  else
    check_fail "DIRECTORY_FINAL_APPEAL_MIN_VOTES must be >=2 in prod profile"
  fi
  if [[ "$dir_final_min_operators" =~ ^[0-9]+$ ]] && ((dir_final_min_operators >= 2)); then
    check_ok "DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS>=2 (${dir_final_min_operators})"
  else
    check_fail "DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS must be >=2 in prod profile"
  fi
  if [[ "$dir_final_min_sources" =~ ^[0-9]+$ ]] && ((dir_final_min_sources >= 2)); then
    check_ok "DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES>=2 (${dir_final_min_sources})"
  else
    check_fail "DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES must be >=2 in prod profile"
  fi
  if [[ "$dir_final_adjudication_min_ratio" =~ ^[0-9]+(\.[0-9]+)?$ ]] &&
    awk "BEGIN {exit !($dir_final_adjudication_min_ratio >= 0.67)}"; then
    check_ok "DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO>=0.67 (${dir_final_adjudication_min_ratio})"
  else
    check_fail "DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO must be >=0.67 in prod profile"
  fi
  if [[ "$dir_dispute_max_ttl_sec" =~ ^[0-9]+$ ]] && ((dir_dispute_max_ttl_sec >= 1 && dir_dispute_max_ttl_sec <= 259200)); then
    check_ok "DIRECTORY_DISPUTE_MAX_TTL_SEC capped <=259200 (${dir_dispute_max_ttl_sec})"
  else
    check_fail "DIRECTORY_DISPUTE_MAX_TTL_SEC must be set in range 1..259200 in prod profile"
  fi
  if [[ "$dir_appeal_max_ttl_sec" =~ ^[0-9]+$ ]] && ((dir_appeal_max_ttl_sec >= 1 && dir_appeal_max_ttl_sec <= 259200)); then
    check_ok "DIRECTORY_APPEAL_MAX_TTL_SEC capped <=259200 (${dir_appeal_max_ttl_sec})"
  else
    check_fail "DIRECTORY_APPEAL_MAX_TTL_SEC must be set in range 1..259200 in prod profile"
  fi
  if [[ -n "$exit_wg_private_key_path" ]]; then
    local exit_wg_private_key_local
    exit_wg_private_key_local="$exit_wg_private_key_path"
    if [[ "$exit_wg_private_key_local" == /app/data/* ]]; then
      exit_wg_private_key_local="$DEPLOY_DIR/data/entry-exit/$(basename "$exit_wg_private_key_local")"
    fi
    if [[ -f "$exit_wg_private_key_local" ]]; then
      check_ok "exit wg private key exists: $exit_wg_private_key_local"
      local exit_key_mode
      exit_key_mode="$(file_mode_octal "$exit_wg_private_key_local" || true)"
      if private_file_mode_secure "$exit_wg_private_key_local"; then
        check_ok "exit wg private key permissions secure: $exit_wg_private_key_local mode=${exit_key_mode:-unknown}"
      else
        local exit_key_mode_rc="$?"
        if [[ "$exit_key_mode_rc" -eq 3 ]]; then
          check_ok "exit wg private key permission check skipped (filesystem lacks POSIX mode-bit enforcement): $exit_wg_private_key_local mode=${exit_key_mode:-unknown}"
        else
          check_fail "exit wg private key permissions too open: $exit_wg_private_key_local mode=${exit_key_mode:-unknown}"
        fi
      fi
    else
      check_fail "missing exit wg private key file: $exit_wg_private_key_local"
    fi
  else
    check_fail "EXIT_WG_PRIVATE_KEY_PATH must be configured"
  fi
  case "$entry_exit_user" in
    "0"|"0:0"|"root"|"root:root")
      check_ok "ENTRY_EXIT_USER has root privileges (${entry_exit_user})"
      ;;
    *)
      check_fail "ENTRY_EXIT_USER must be root/0 in prod profile (found: ${entry_exit_user:-unset})"
      ;;
  esac
  if [[ "$entry_exit_privileged" == "1" || "$entry_exit_privileged" == "true" ]]; then
    check_ok "ENTRY_EXIT_PRIVILEGED enabled (${entry_exit_privileged})"
  else
    check_fail "ENTRY_EXIT_PRIVILEGED must be true/1 in prod profile"
  fi

  local private_files=("$env_file" "$key_file" "$client_key_file")
  local pf pf_mode
  for pf in "${private_files[@]}"; do
    if [[ ! -f "$pf" ]]; then
      continue
    fi
    pf_mode="$(file_mode_octal "$pf" || true)"
    if private_file_mode_secure "$pf"; then
      check_ok "private file permissions secure (no group/other access): $pf mode=${pf_mode:-unknown}"
    else
      local pf_mode_rc="$?"
      if [[ "$pf_mode_rc" -eq 3 ]]; then
        check_ok "private file permission check skipped (filesystem lacks POSIX mode-bit enforcement): $pf mode=${pf_mode:-unknown}"
      elif [[ -n "$pf_mode" ]]; then
        check_fail "private file permissions too open: $pf mode=${pf_mode} (expected group/other=0)"
      else
        check_fail "unable to read file permissions: $pf"
      fi
    fi
  done

  local now_epoch min_epoch
  now_epoch="$(date -u +%s)"
  min_epoch=$((now_epoch + days_min * 86400))
  local certs_to_check=("$ca_file" "$cert_file" "$client_cert_file")
  for f in "${certs_to_check[@]}"; do
    if [[ ! -f "$f" ]]; then
      continue
    fi
    local not_after
    not_after="$(cert_not_after_unix "$f" || true)"
    if [[ -z "$not_after" ]]; then
      check_fail "failed to parse certificate expiry: $f"
      continue
    fi
    if ((not_after > min_epoch)); then
      local days_left
      days_left=$(((not_after - now_epoch) / 86400))
      check_ok "certificate valid >= ${days_min}d: $f (${days_left}d left)"
    else
      check_fail "certificate expires too soon (<${days_min}d): $f"
    fi
  done

  if [[ "$mode" == "authority" ]]; then
    local require_signed allow_token key_id key_path signers_container signers_local
    require_signed="$(identity_value "$env_file" "ISSUER_ADMIN_REQUIRE_SIGNED")"
    allow_token="$(identity_value "$env_file" "ISSUER_ADMIN_ALLOW_TOKEN")"
    local issuer_admin_token_val
    issuer_admin_token_val="$(identity_value "$env_file" "ISSUER_ADMIN_TOKEN")"
    key_id="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_KEY_ID")"
    key_path="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL")"
    signers_container="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_KEYS_FILE")"
    [[ -z "$key_path" ]] && key_path="$DEPLOY_DIR/data/issuer/issuer_admin_signer.key"
    [[ -z "$signers_container" ]] && signers_container="/app/data/issuer_admin_signers.txt"
    signers_local="$DEPLOY_DIR/data/issuer/$(basename "$signers_container")"

    if [[ "$require_signed" == "1" ]]; then
      check_ok "ISSUER_ADMIN_REQUIRE_SIGNED=1"
    else
      check_fail "ISSUER_ADMIN_REQUIRE_SIGNED must be 1 on authority prod profile"
    fi
    if [[ "$allow_token" == "0" ]]; then
      check_ok "ISSUER_ADMIN_ALLOW_TOKEN=0"
    else
      check_fail "ISSUER_ADMIN_ALLOW_TOKEN must be 0 on authority prod profile"
    fi
    if [[ -z "$issuer_admin_token_val" ]]; then
      check_ok "ISSUER_ADMIN_TOKEN cleared when token auth disabled"
    else
      check_fail "ISSUER_ADMIN_TOKEN must be empty when ISSUER_ADMIN_ALLOW_TOKEN=0"
    fi
    if [[ -n "$key_id" ]]; then
      check_ok "admin signing key id configured"
    else
      check_fail "missing ISSUER_ADMIN_SIGNING_KEY_ID"
    fi
      if [[ -f "$key_path" ]]; then
        check_ok "admin signing key exists: $key_path"
        local key_mode
        key_mode="$(file_mode_octal "$key_path" || true)"
        if private_file_mode_secure "$key_path"; then
          check_ok "admin signing private key permissions secure (no group/other access): $key_path mode=${key_mode:-unknown}"
        else
          local key_mode_rc="$?"
          if [[ "$key_mode_rc" -eq 3 ]]; then
            check_ok "admin signing private key permission check skipped (filesystem lacks POSIX mode-bit enforcement): $key_path mode=${key_mode:-unknown}"
          elif [[ -n "$key_mode" ]]; then
            check_fail "admin signing private key permissions too open: $key_path mode=${key_mode} (expected group/other=0)"
          else
            check_fail "unable to read admin signing private key permissions: $key_path"
          fi
        fi
        local inspect_json derived_id derived_pub
        inspect_json="$(
          cd "$ROOT_DIR"
        go run ./cmd/adminsig inspect --private-key-file "$key_path"
      )"
      derived_id="$(printf '%s\n' "$inspect_json" | rg -o '"key_id":"[^"]+"' | head -n1 | sed -E 's/^"key_id":"([^"]+)"$/\1/')"
      derived_pub="$(printf '%s\n' "$inspect_json" | rg -o '"public_key":"[^"]+"' | head -n1 | sed -E 's/^"public_key":"([^"]+)"$/\1/')"
      if [[ -n "$derived_id" && -n "$key_id" && "$derived_id" == "$key_id" ]]; then
        check_ok "admin signing key id matches private key"
      else
        check_fail "admin signing key id does not match private key"
      fi
      if [[ -f "$signers_local" && -n "$derived_id" && -n "$derived_pub" ]]; then
        if rg -q "^${derived_id}=${derived_pub}$" "$signers_local"; then
          check_ok "signers file includes active signing key mapping"
        else
          check_fail "signers file missing active signing key mapping"
        fi
      else
        check_fail "missing admin signers file: $signers_local"
      fi
    else
      check_fail "missing admin signing private key file: $key_path"
    fi
  elif [[ "$mode" == "provider" ]]; then
    local provider_core_issuer_url provider_admin_token
    local provider_sign_key_id provider_sign_key_file provider_sign_keys_file
    provider_core_issuer_url="$(identity_value "$env_file" "CORE_ISSUER_URL")"
    provider_admin_token="$(identity_value "$env_file" "ISSUER_ADMIN_TOKEN")"
    provider_sign_key_id="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_KEY_ID")"
    provider_sign_key_file="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL")"
    provider_sign_keys_file="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_KEYS_FILE")"

    if [[ -n "$provider_core_issuer_url" ]]; then
      if is_https_url "$provider_core_issuer_url"; then
        check_ok "provider CORE_ISSUER_URL uses HTTPS"
      else
        check_fail "provider CORE_ISSUER_URL must be HTTPS"
      fi
      local provider_issuer_host
      provider_issuer_host="$(host_from_url "$provider_core_issuer_url")"
      if [[ -z "$provider_issuer_host" ]]; then
        check_fail "provider CORE_ISSUER_URL host parse failed"
      elif host_is_private_or_loopback "$provider_issuer_host"; then
        check_fail "provider CORE_ISSUER_URL host must not be private/loopback"
      else
        check_ok "provider CORE_ISSUER_URL host is non-private"
      fi
    else
      check_fail "provider CORE_ISSUER_URL must be configured"
    fi
    if [[ -z "$provider_admin_token" ]]; then
      check_ok "provider ISSUER_ADMIN_TOKEN not persisted"
    else
      check_fail "provider env must not persist ISSUER_ADMIN_TOKEN"
    fi
    if [[ -z "$provider_sign_key_id" && -z "$provider_sign_key_file" && -z "$provider_sign_keys_file" ]]; then
      check_ok "provider env does not include issuer admin signing material"
    else
      check_fail "provider env must not include issuer admin signing material"
    fi
  fi

  if [[ "$check_live" == "1" ]]; then
    local live_issuer_url=""
    if [[ "$mode" == "authority" ]]; then
      if [[ -n "$directory_public_url" ]]; then
        local directory_host
        directory_host="$(host_from_url "$directory_public_url")"
        if [[ -n "$directory_host" ]]; then
          live_issuer_url="$(url_from_host_port "$directory_host" 8082)"
          if is_https_url "$directory_public_url"; then
            live_issuer_url="$(ensure_url_scheme "$live_issuer_url" "https")"
          else
            live_issuer_url="$(ensure_url_scheme "$live_issuer_url" "http")"
          fi
        fi
      fi
      if [[ -z "$live_issuer_url" ]]; then
        live_issuer_url="$(ensure_url_scheme "127.0.0.1:8082" "https")"
      fi
    else
      live_issuer_url="$(identity_value "$env_file" "CORE_ISSUER_URL")"
      if [[ -z "$live_issuer_url" ]]; then
        live_issuer_url="$(identity_value "$env_file" "ISSUER_URL")"
      fi
    fi

    check_live_endpoint() {
      local label="$1"
      local url="$2"
      local -a tls_opts=()
      mapfile -t tls_opts < <(curl_tls_opts_for_url "$url")
      if wait_http_ok_with_opts "$url" "live ${label}" "$timeout_sec" "${tls_opts[@]}"; then
        check_ok "live endpoint healthy: $label ($url)"
      else
        check_fail "live endpoint unreachable: $label ($url)"
      fi
    }

    if [[ -n "$directory_public_url" ]]; then
      check_live_endpoint "directory" "${directory_public_url%/}/v1/relays"
    fi
    if [[ -n "$entry_public_url" ]]; then
      check_live_endpoint "entry" "${entry_public_url%/}/v1/health"
    fi
    if [[ -n "$exit_public_url" ]]; then
      check_live_endpoint "exit" "${exit_public_url%/}/v1/health"
    fi
    if [[ -n "$live_issuer_url" ]]; then
      check_live_endpoint "issuer" "${live_issuer_url%/}/v1/pubkeys"
    fi

    if [[ -n "$directory_public_url" ]]; then
      local governance_url governance_body governance_code
      governance_url="${directory_public_url%/}/v1/admin/governance-status"
      governance_body="$(mktemp)"
      local -a governance_tls_opts=()
      mapfile -t governance_tls_opts < <(curl_tls_opts_for_url "$directory_public_url")
      governance_code="$(
        curl -sS -o "$governance_body" -w "%{http_code}" \
          --connect-timeout 3 --max-time "$timeout_sec" \
          "${governance_tls_opts[@]}" \
          -H "X-Admin-Token: ${directory_admin_token}" \
          "$governance_url" || true
      )"
      if [[ "$governance_code" != "200" ]]; then
        check_fail "live governance endpoint unreachable/unauthorized: ${governance_url} (code=${governance_code:-none})"
      else
        check_ok "live governance endpoint healthy: ${governance_url}"
        local policy_meta_votes policy_final_dispute policy_final_appeal
        local policy_final_ops policy_final_sources policy_final_ratio
        policy_meta_votes="$(jq -r '(.policy.meta_min_votes // 0)' <"$governance_body" 2>/dev/null || echo "0")"
        policy_final_dispute="$(jq -r '(.policy.final_dispute_min_votes // 0)' <"$governance_body" 2>/dev/null || echo "0")"
        policy_final_appeal="$(jq -r '(.policy.final_appeal_min_votes // 0)' <"$governance_body" 2>/dev/null || echo "0")"
        policy_final_ops="$(jq -r '(.policy.final_adjudication_min_operators // 0)' <"$governance_body" 2>/dev/null || echo "0")"
        policy_final_sources="$(jq -r '(.policy.final_adjudication_min_sources // 0)' <"$governance_body" 2>/dev/null || echo "0")"
        policy_final_ratio="$(jq -r '(.policy.final_adjudication_min_ratio // 0)' <"$governance_body" 2>/dev/null || echo "0")"
        if [[ "$policy_meta_votes" =~ ^[0-9]+$ ]] && ((policy_meta_votes >= 2)); then
          check_ok "live governance policy meta_min_votes>=2 (${policy_meta_votes})"
        else
          check_fail "live governance policy too weak: meta_min_votes must be >=2 (got ${policy_meta_votes})"
        fi
        if [[ "$policy_final_dispute" =~ ^[0-9]+$ ]] && ((policy_final_dispute >= 2)); then
          check_ok "live governance policy final_dispute_min_votes>=2 (${policy_final_dispute})"
        else
          check_fail "live governance policy too weak: final_dispute_min_votes must be >=2 (got ${policy_final_dispute})"
        fi
        if [[ "$policy_final_appeal" =~ ^[0-9]+$ ]] && ((policy_final_appeal >= 2)); then
          check_ok "live governance policy final_appeal_min_votes>=2 (${policy_final_appeal})"
        else
          check_fail "live governance policy too weak: final_appeal_min_votes must be >=2 (got ${policy_final_appeal})"
        fi
        if [[ "$policy_final_ops" =~ ^[0-9]+$ ]] && ((policy_final_ops >= 2)); then
          check_ok "live governance policy final_adjudication_min_operators>=2 (${policy_final_ops})"
        else
          check_fail "live governance policy too weak: final_adjudication_min_operators must be >=2 (got ${policy_final_ops})"
        fi
        if [[ "$policy_final_sources" =~ ^[0-9]+$ ]] && ((policy_final_sources >= 2)); then
          check_ok "live governance policy final_adjudication_min_sources>=2 (${policy_final_sources})"
        else
          check_fail "live governance policy too weak: final_adjudication_min_sources must be >=2 (got ${policy_final_sources})"
        fi
        if [[ "$policy_final_ratio" =~ ^[0-9]+(\.[0-9]+)?$ ]] &&
          awk "BEGIN {exit !($policy_final_ratio >= 0.67)}"; then
          check_ok "live governance policy final_adjudication_min_ratio>=0.67 (${policy_final_ratio})"
        else
          check_fail "live governance policy too weak: final_adjudication_min_ratio must be >=0.67 (got ${policy_final_ratio})"
        fi
      fi
      rm -f "$governance_body"

      local sync_url sync_body sync_code
      sync_url="${directory_public_url%/}/v1/admin/sync-status"
      sync_body="$(mktemp)"
      sync_code="$(
        curl -sS -o "$sync_body" -w "%{http_code}" \
          --connect-timeout 3 --max-time "$timeout_sec" \
          "${governance_tls_opts[@]}" \
          -H "X-Admin-Token: ${directory_admin_token}" \
          "$sync_url" || true
      )"
      if [[ "$sync_code" != "200" ]]; then
        check_fail "live sync-status endpoint unreachable/unauthorized: ${sync_url} (code=${sync_code:-none})"
      else
        check_ok "live sync-status endpoint healthy: ${sync_url}"
        if ! jq -e '.peer and .issuer' <"$sync_body" >/dev/null 2>&1; then
          check_fail "live sync-status payload invalid: expected peer+issuer fields"
        else
          local live_peer_quorum live_peer_success live_peer_sources live_peer_source_operators
          local live_issuer_quorum live_issuer_success live_issuer_sources live_issuer_source_operators
          local live_peer_last_run live_issuer_last_run live_sync_generated_at live_sync_ref_epoch
          local live_peer_sync_age_sec live_issuer_sync_age_sec
          live_peer_quorum="$(jq -r '.peer.quorum_met // false' <"$sync_body" 2>/dev/null || echo "false")"
          live_peer_success="$(jq -r '.peer.success // false' <"$sync_body" 2>/dev/null || echo "false")"
          live_peer_sources="$(jq -r '.peer.success_sources // 0' <"$sync_body" 2>/dev/null || echo "0")"
          live_peer_source_operators="$(jq -r '((.peer.source_operators // []) | length) // 0' <"$sync_body" 2>/dev/null || echo "0")"
          live_issuer_quorum="$(jq -r '.issuer.quorum_met // false' <"$sync_body" 2>/dev/null || echo "false")"
          live_issuer_success="$(jq -r '.issuer.success // false' <"$sync_body" 2>/dev/null || echo "false")"
          live_issuer_sources="$(jq -r '.issuer.success_sources // 0' <"$sync_body" 2>/dev/null || echo "0")"
          live_issuer_source_operators="$(jq -r '((.issuer.source_operators // []) | length) // 0' <"$sync_body" 2>/dev/null || echo "0")"
          live_peer_last_run="$(jq -r '.peer.last_run_at // 0' <"$sync_body" 2>/dev/null || echo "0")"
          live_issuer_last_run="$(jq -r '.issuer.last_run_at // 0' <"$sync_body" 2>/dev/null || echo "0")"
          live_sync_generated_at="$(jq -r '.generated_at // 0' <"$sync_body" 2>/dev/null || echo "0")"
          live_sync_ref_epoch="$(date +%s)"
          if [[ "$live_sync_generated_at" =~ ^[0-9]+$ ]] && ((live_sync_generated_at > 0)); then
            live_sync_ref_epoch="$live_sync_generated_at"
          fi
          live_peer_sync_age_sec="-1"
          if [[ "$live_peer_last_run" =~ ^[0-9]+$ ]] && ((live_peer_last_run > 0)); then
            live_peer_sync_age_sec=$((live_sync_ref_epoch - live_peer_last_run))
            if ((live_peer_sync_age_sec < 0)); then
              live_peer_sync_age_sec=0
            fi
          fi
          live_issuer_sync_age_sec="-1"
          if [[ "$live_issuer_last_run" =~ ^[0-9]+$ ]] && ((live_issuer_last_run > 0)); then
            live_issuer_sync_age_sec=$((live_sync_ref_epoch - live_issuer_last_run))
            if ((live_issuer_sync_age_sec < 0)); then
              live_issuer_sync_age_sec=0
            fi
          fi

          if [[ "$live_peer_last_run" =~ ^[0-9]+$ ]] && ((live_peer_last_run > 0)); then
            if [[ "$live_peer_quorum" == "true" && "$live_peer_success" == "true" ]]; then
              check_ok "live peer-sync quorum met"
            else
              check_fail "live peer-sync quorum not met (success=${live_peer_success} quorum=${live_peer_quorum})"
            fi
          else
            check_ok "live peer-sync not started yet (no last_run_at); skipping quorum gate"
          fi
          if [[ "$live_issuer_quorum" == "true" && "$live_issuer_success" == "true" ]]; then
            check_ok "live issuer-sync quorum met"
          else
            check_fail "live issuer-sync quorum not met (success=${live_issuer_success} quorum=${live_issuer_quorum})"
          fi
          if [[ "$live_max_peer_sync_age_sec" =~ ^[0-9]+$ ]] && ((live_max_peer_sync_age_sec > 0)); then
            if [[ "$live_peer_sync_age_sec" =~ ^[0-9]+$ ]] && ((live_peer_sync_age_sec <= live_max_peer_sync_age_sec)); then
              check_ok "live peer-sync freshness within threshold (${live_peer_sync_age_sec}s <= ${live_max_peer_sync_age_sec}s)"
            else
              check_fail "live peer-sync freshness too old: age=${live_peer_sync_age_sec}s threshold=${live_max_peer_sync_age_sec}s"
            fi
          fi
          if [[ "$live_min_peer_success_sources" =~ ^[0-9]+$ ]] && ((live_min_peer_success_sources > 0)); then
            if [[ "$live_peer_sources" =~ ^[0-9]+$ ]] && ((live_peer_sources >= live_min_peer_success_sources)); then
              check_ok "live peer-sync success_sources floor met (${live_peer_sources} >= ${live_min_peer_success_sources})"
            else
              check_fail "live peer-sync success_sources too low: observed ${live_peer_sources} required ${live_min_peer_success_sources}"
            fi
          fi
          if [[ "$live_min_peer_source_operators" =~ ^[0-9]+$ ]] && ((live_min_peer_source_operators > 0)); then
            if [[ "$live_peer_source_operators" =~ ^[0-9]+$ ]] && ((live_peer_source_operators >= live_min_peer_source_operators)); then
              check_ok "live peer-sync source_operators floor met (${live_peer_source_operators} >= ${live_min_peer_source_operators})"
            else
              check_fail "live peer-sync source_operators too low: observed ${live_peer_source_operators} required ${live_min_peer_source_operators}"
            fi
          fi
          if [[ "$live_max_issuer_sync_age_sec" =~ ^[0-9]+$ ]] && ((live_max_issuer_sync_age_sec > 0)); then
            if [[ "$live_issuer_sync_age_sec" =~ ^[0-9]+$ ]] && ((live_issuer_sync_age_sec <= live_max_issuer_sync_age_sec)); then
              check_ok "live issuer-sync freshness within threshold (${live_issuer_sync_age_sec}s <= ${live_max_issuer_sync_age_sec}s)"
            else
              check_fail "live issuer-sync freshness too old: age=${live_issuer_sync_age_sec}s threshold=${live_max_issuer_sync_age_sec}s"
            fi
          fi
          if [[ "$live_min_issuer_success_sources" =~ ^[0-9]+$ ]] && ((live_min_issuer_success_sources > 0)); then
            if [[ "$live_issuer_sources" =~ ^[0-9]+$ ]] && ((live_issuer_sources >= live_min_issuer_success_sources)); then
              check_ok "live issuer-sync success_sources floor met (${live_issuer_sources} >= ${live_min_issuer_success_sources})"
            else
              check_fail "live issuer-sync success_sources too low: observed ${live_issuer_sources} required ${live_min_issuer_success_sources}"
            fi
          fi
          if [[ "$live_min_issuer_source_operators" =~ ^[0-9]+$ ]] && ((live_min_issuer_source_operators > 0)); then
            if [[ "$live_issuer_source_operators" =~ ^[0-9]+$ ]] && ((live_issuer_source_operators >= live_min_issuer_source_operators)); then
              check_ok "live issuer-sync source_operators floor met (${live_issuer_source_operators} >= ${live_min_issuer_source_operators})"
            else
              check_fail "live issuer-sync source_operators too low: observed ${live_issuer_source_operators} required ${live_min_issuer_source_operators}"
            fi
          fi
        fi
      fi
      rm -f "$sync_body"

      local peer_status_url peer_status_body peer_status_code
      peer_status_url="${directory_public_url%/}/v1/admin/peer-status"
      peer_status_body="$(mktemp)"
      peer_status_code="$(
        curl -sS -o "$peer_status_body" -w "%{http_code}" \
          --connect-timeout 3 --max-time "$timeout_sec" \
          "${governance_tls_opts[@]}" \
          -H "X-Admin-Token: ${directory_admin_token}" \
          "$peer_status_url" || true
      )"
      if [[ "$peer_status_code" != "200" ]]; then
        check_fail "live peer-status endpoint unreachable/unauthorized: ${peer_status_url} (code=${peer_status_code:-none})"
      else
        check_ok "live peer-status endpoint healthy: ${peer_status_url}"
        if ! jq -e '.peers | arrays' <"$peer_status_body" >/dev/null 2>&1; then
          check_fail "live peer-status payload invalid: expected peers[] array"
        else
          local configured_peers configured_healthy discovered_eligible configured_failing cooling_retry_max_sec
          configured_peers="$(jq -r '([.peers[] | select(.configured == true)] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
          configured_healthy="$(jq -r '([.peers[] | select(.configured == true and ((.consecutive_failures // 0) == 0))] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
          discovered_eligible="$(jq -r '([.peers[] | select(.discovered == true and .eligible == true)] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
          configured_failing="$(jq -r '([.peers[] | select(.configured == true and ((.consecutive_failures // 0) > 0))] | length) // 0' <"$peer_status_body" 2>/dev/null || echo "0")"
          cooling_retry_max_sec="$(jq -r '([.peers[] | select(.cooling_down == true) | (.retry_after_sec // 0)] | max // 0)' <"$peer_status_body" 2>/dev/null || echo "0")"
          if [[ "$configured_peers" =~ ^[0-9]+$ ]] && ((configured_peers > 0)); then
            if [[ "$live_require_configured_healthy" == "1" ]]; then
              if [[ "$configured_healthy" =~ ^[0-9]+$ ]] && ((configured_healthy >= configured_peers)); then
                check_ok "live configured peers all healthy (${configured_healthy}/${configured_peers})"
              else
                check_fail "live configured peer health degraded: all configured peers must be healthy when --live-require-configured-healthy=1 (healthy=${configured_healthy}/${configured_peers})"
              fi
            elif [[ "$configured_healthy" =~ ^[0-9]+$ ]] && ((configured_healthy > 0)); then
              check_ok "live configured peer health looks good (${configured_healthy}/${configured_peers} configured peers with zero failure streak)"
            elif [[ "$discovered_eligible" =~ ^[0-9]+$ ]] && ((discovered_eligible > 0)); then
              check_ok "live configured peers currently unhealthy but discovered eligible peers are available (${discovered_eligible})"
            else
              check_fail "live peer health degraded: no healthy configured peers and no discovered eligible peers"
            fi
          else
            check_ok "live peer-status has no configured peer list; skipping configured peer health gate"
          fi
          if [[ "$live_max_cooling_retry_sec" =~ ^[0-9]+$ ]] && ((live_max_cooling_retry_sec > 0)); then
            if [[ "$cooling_retry_max_sec" =~ ^[0-9]+$ ]] && ((cooling_retry_max_sec <= live_max_cooling_retry_sec)); then
              check_ok "live cooling retry window within threshold (${cooling_retry_max_sec}s <= ${live_max_cooling_retry_sec}s)"
            else
              check_fail "live cooling retry window too high: observed ${cooling_retry_max_sec}s exceeds threshold ${live_max_cooling_retry_sec}s"
            fi
          fi
          if [[ "$configured_failing" =~ ^[0-9]+$ ]] && ((configured_failing > 0)); then
            check_ok "live configured failing peers observed=${configured_failing} (review with server-federation-status)"
          else
            check_ok "live configured failing peers observed=0"
          fi
        fi
      fi
      rm -f "$peer_status_body"
    fi

    if [[ "$mode" == "authority" && -n "$live_issuer_url" ]]; then
      local token_probe_code token_probe_body
      token_probe_body="$(mktemp)"
      local -a tls_opts=()
      mapfile -t tls_opts < <(curl_tls_opts_for_url "$live_issuer_url")
      token_probe_code="$(
        curl -sS -o "$token_probe_body" -w "%{http_code}" \
          --connect-timeout 3 --max-time 8 \
          "${tls_opts[@]}" \
          -H "X-Admin-Token: preflight-invalid-token" \
          "${live_issuer_url%/}/v1/admin/subject/get?subject=preflight-token-check" || true
      )"
      if [[ "$token_probe_code" == "401" || "$token_probe_code" == "403" ]]; then
        check_ok "issuer admin token path rejected as expected in strict mode (code=$token_probe_code)"
      else
        check_fail "issuer admin token path unexpectedly accepted/unreachable (code=${token_probe_code:-none})"
      fi
      rm -f "$token_probe_body"
    fi
  fi

  echo "prod preflight summary: checks=$check_total failures=$fail mode=$mode env=$env_file check_live=$check_live"
  if ((fail > 0)); then
    if [[ "$check_live" == "1" ]]; then
      local federation_dir_hint=""
      if [[ -n "$directory_public_url" ]]; then
        federation_dir_hint=" --directory-url ${directory_public_url}"
      fi
      echo "prod preflight remediation hints:"
      echo "  ./scripts/easy_node.sh server-federation-status${federation_dir_hint} --timeout-sec ${timeout_sec}"
      echo "  ./scripts/easy_node.sh server-federation-wait${federation_dir_hint} --ready-timeout-sec 90 --poll-sec 5 --timeout-sec ${timeout_sec}"
    fi
    return 1
  fi
  return 0
}

client_test() {
  local directory_urls=""
  local issuer_url=""
  local entry_url=""
  local exit_url=""
  local min_sources="1"
  local client_subject="${CLIENT_SUBJECT:-}"
  local client_anon_cred="${CLIENT_ANON_CRED:-}"
  local exit_country=""
  local exit_region=""
  local timeout_sec="35"
  local build_timeout_sec="${EASY_NODE_CLIENT_BUILD_TIMEOUT_SEC:-180}"
  local force_build="${EASY_NODE_CLIENT_FORCE_BUILD:-0}"
  local execution_mode="${EASY_NODE_CLIENT_TEST_MODE:-docker}"
  local path_profile="${EASY_NODE_PATH_PROFILE:-}"
  local require_distinct_operators="${CLIENT_REQUIRE_DISTINCT_OPERATORS:-0}"
  local require_distinct_countries="${CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY:-0}"
  local locality_soft_bias="${CLIENT_EXIT_LOCALITY_SOFT_BIAS:-0}"
  local locality_country_bias="${CLIENT_EXIT_COUNTRY_BIAS:-1.60}"
  local locality_region_bias="${CLIENT_EXIT_REGION_BIAS:-1.25}"
  local locality_region_prefix_bias="${CLIENT_EXIT_REGION_PREFIX_BIAS:-1.10}"
  local entry_rotation_sec="${CLIENT_ENTRY_ROTATION_SEC:-0}"
  local entry_rotation_seed="${CLIENT_ENTRY_ROTATION_SEED:-0}"
  local min_selection_lines="${EASY_NODE_CLIENT_MIN_SELECTION_LINES:-1}"
  local min_entry_operators="${EASY_NODE_CLIENT_MIN_ENTRY_OPERATORS:-1}"
  local min_exit_operators="${EASY_NODE_CLIENT_MIN_EXIT_OPERATORS:-1}"
  local require_cross_operator_pair="${EASY_NODE_CLIENT_REQUIRE_CROSS_OPERATOR_PAIR:-0}"
  local require_middle_relay="${CLIENT_REQUIRE_MIDDLE_RELAY:-}"
  local allow_direct_exit_fallback="${CLIENT_ALLOW_DIRECT_EXIT_FALLBACK:-}"
  local force_direct_exit="${CLIENT_FORCE_DIRECT_EXIT:-}"
  local client_inner_source="${CLIENT_INNER_SOURCE:-}"
  local client_disable_synthetic_fallback="${CLIENT_DISABLE_SYNTHETIC_FALLBACK:-}"
  local data_plane_mode="${DATA_PLANE_MODE:-}"
  local beta_profile="${EASY_NODE_BETA_PROFILE:-0}"
  local prod_profile="${EASY_NODE_PROD_PROFILE:-0}"
  local bootstrap_directory=""
  local discovery_wait_sec="${EASY_NODE_DISCOVERY_WAIT_SEC:-12}"
  local min_sources_set=0
  local distinct_set=0
  local distinct_countries_set=0
  local locality_soft_bias_set=0
  local locality_country_bias_set=0
  local locality_region_bias_set=0
  local locality_region_prefix_bias_set=0
  local speed_onehop_profile=0
  local force_direct_exit_set=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --directory-urls)
        directory_urls="${2:-}"
        shift 2
        ;;
      --issuer-url)
        issuer_url="${2:-}"
        shift 2
        ;;
      --bootstrap-directory)
        bootstrap_directory="${2:-}"
        shift 2
        ;;
      --discovery-wait-sec)
        discovery_wait_sec="${2:-}"
        shift 2
        ;;
      --path-profile)
        path_profile="${2:-}"
        shift 2
        ;;
      --path-profile)
        path_profile="${2:-}"
        shift 2
        ;;
      --entry-url)
        entry_url="${2:-}"
        shift 2
        ;;
      --exit-url)
        exit_url="${2:-}"
        shift 2
        ;;
      --min-sources)
        min_sources="${2:-}"
        min_sources_set=1
        shift 2
        ;;
      --subject)
        client_subject="${2:-}"
        shift 2
        ;;
      --anon-cred)
        client_anon_cred="${2:-}"
        shift 2
        ;;
      --exit-country)
        exit_country="${2:-}"
        shift 2
        ;;
      --exit-region)
        exit_region="${2:-}"
        shift 2
        ;;
      --timeout-sec)
        timeout_sec="${2:-}"
        shift 2
        ;;
      --path-profile)
        path_profile="${2:-}"
        shift 2
        ;;
      --distinct-operators)
        if [[ "${2:-}" == "0" || "${2:-}" == "1" ]]; then
          require_distinct_operators="${2:-}"
          distinct_set=1
          shift 2
        else
          require_distinct_operators="1"
          distinct_set=1
          shift
        fi
        ;;
      --distinct-countries)
        if [[ "${2:-}" == "0" || "${2:-}" == "1" ]]; then
          require_distinct_countries="${2:-}"
          distinct_countries_set=1
          shift 2
        else
          require_distinct_countries="1"
          distinct_countries_set=1
          shift
        fi
        ;;
      --locality-soft-bias)
        if [[ "${2:-}" == "0" || "${2:-}" == "1" ]]; then
          locality_soft_bias="${2:-}"
          locality_soft_bias_set=1
          shift 2
        else
          locality_soft_bias="1"
          locality_soft_bias_set=1
          shift
        fi
        ;;
      --country-bias)
        locality_country_bias="${2:-}"
        locality_country_bias_set=1
        shift 2
        ;;
      --region-bias)
        locality_region_bias="${2:-}"
        locality_region_bias_set=1
        shift 2
        ;;
      --region-prefix-bias)
        locality_region_prefix_bias="${2:-}"
        locality_region_prefix_bias_set=1
        shift 2
        ;;
      --force-direct-exit)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          force_direct_exit="${2:-}"
          force_direct_exit_set=1
          shift 2
        else
          force_direct_exit="1"
          force_direct_exit_set=1
          shift
        fi
        ;;
      --min-selection-lines)
        min_selection_lines="${2:-}"
        shift 2
        ;;
      --min-entry-operators)
        min_entry_operators="${2:-}"
        shift 2
        ;;
      --min-exit-operators)
        min_exit_operators="${2:-}"
        shift 2
        ;;
      --require-cross-operator-pair)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          require_cross_operator_pair="${2:-}"
          shift 2
        else
          require_cross_operator_pair="1"
          shift
        fi
        ;;
      --beta-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          beta_profile="${2:-}"
          shift 2
        else
          beta_profile="1"
          shift
        fi
        ;;
      --prod-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          prod_profile="${2:-}"
          shift 2
        else
          prod_profile="1"
          shift
        fi
        ;;
      *)
        echo "unknown arg for client-test: $1"
        exit 2
        ;;
    esac
  done

  local normalized_path_profile=""
  normalized_path_profile="$(normalize_path_profile "$path_profile")" || {
    echo "client-test requires --path-profile to be one of: 1hop, 2hop, 3hop, speed, speed-1hop, balanced, private (legacy aliases: fast, privacy)"
    exit 2
  }
  local canonical_path_profile="2hop"
  case "$normalized_path_profile" in
    speed-1hop)
      canonical_path_profile="1hop"
      ;;
    privacy)
      canonical_path_profile="3hop"
      ;;
    *)
      canonical_path_profile="2hop"
      ;;
  esac
  local speed_onehop_profile=0
  if [[ "$normalized_path_profile" == "speed-1hop" ]]; then
    speed_onehop_profile=1
  fi
  if [[ -n "$normalized_path_profile" ]]; then
    local profile_values profile_distinct profile_distinct_countries profile_locality_soft profile_country_bias profile_region_bias profile_region_prefix_bias
    profile_values="$(path_profile_values "$normalized_path_profile")"
    IFS='|' read -r profile_distinct profile_distinct_countries profile_locality_soft profile_country_bias profile_region_bias profile_region_prefix_bias <<<"$profile_values"
    if [[ "$distinct_set" -eq 0 ]]; then
      require_distinct_operators="$profile_distinct"
    fi
    if [[ "$distinct_countries_set" -eq 0 ]]; then
      require_distinct_countries="$profile_distinct_countries"
    fi
    if [[ "$locality_soft_bias_set" -eq 0 ]]; then
      locality_soft_bias="$profile_locality_soft"
    fi
    if [[ "$locality_country_bias_set" -eq 0 ]]; then
      locality_country_bias="$profile_country_bias"
    fi
    if [[ "$locality_region_bias_set" -eq 0 ]]; then
      locality_region_bias="$profile_region_bias"
    fi
    if [[ "$locality_region_prefix_bias_set" -eq 0 ]]; then
      locality_region_prefix_bias="$profile_region_prefix_bias"
    fi
  fi
  if [[ "$speed_onehop_profile" == "1" ]]; then
    if [[ "$distinct_set" -eq 0 ]]; then
      require_distinct_operators="0"
    fi
    if [[ -z "$allow_direct_exit_fallback" ]]; then
      allow_direct_exit_fallback="1"
    fi
    if [[ "$force_direct_exit_set" -eq 0 && -z "$force_direct_exit" ]]; then
      force_direct_exit="1"
    fi
  fi

  if [[ "$require_distinct_operators" != "0" && "$require_distinct_operators" != "1" ]]; then
    echo "client-test requires CLIENT_REQUIRE_DISTINCT_OPERATORS or --distinct-operators to be 0 or 1"
    exit 2
  fi
  if [[ "$require_distinct_countries" != "0" && "$require_distinct_countries" != "1" ]]; then
    echo "client-test requires CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY or --distinct-countries to be 0 or 1"
    exit 2
  fi
  if [[ "$locality_soft_bias" != "0" && "$locality_soft_bias" != "1" ]]; then
    echo "client-test requires --locality-soft-bias to be 0 or 1"
    exit 2
  fi
  if ! [[ "$locality_country_bias" =~ ^[0-9]+([.][0-9]+)?$ && "$locality_region_bias" =~ ^[0-9]+([.][0-9]+)?$ && "$locality_region_prefix_bias" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "client-test requires --country-bias, --region-bias and --region-prefix-bias to be numeric"
    exit 2
  fi
  if [[ "$require_cross_operator_pair" != "0" && "$require_cross_operator_pair" != "1" ]]; then
    echo "client-test requires --require-cross-operator-pair to be 0 or 1"
    exit 2
  fi
  if [[ -n "$client_inner_source" && "$client_inner_source" != "udp" && "$client_inner_source" != "synthetic" ]]; then
    echo "client-test requires CLIENT_INNER_SOURCE to be udp or synthetic when set"
    exit 2
  fi
  if [[ -n "$client_disable_synthetic_fallback" && "$client_disable_synthetic_fallback" != "0" && "$client_disable_synthetic_fallback" != "1" ]]; then
    echo "client-test requires CLIENT_DISABLE_SYNTHETIC_FALLBACK to be 0 or 1 when set"
    exit 2
  fi
  if [[ -n "$data_plane_mode" && "$data_plane_mode" != "json" && "$data_plane_mode" != "opaque" ]]; then
    echo "client-test requires DATA_PLANE_MODE to be json or opaque when set"
    exit 2
  fi
  if [[ -n "$require_middle_relay" && "$require_middle_relay" != "0" && "$require_middle_relay" != "1" ]]; then
    echo "client-test requires CLIENT_REQUIRE_MIDDLE_RELAY to be 0 or 1 when set"
    exit 2
  fi
  if ! [[ "$entry_rotation_sec" =~ ^[0-9]+$ ]]; then
    echo "client-test requires CLIENT_ENTRY_ROTATION_SEC to be numeric"
    exit 2
  fi
  if ! [[ "$entry_rotation_seed" =~ ^-?[0-9]+$ ]]; then
    echo "client-test requires CLIENT_ENTRY_ROTATION_SEED to be numeric"
    exit 2
  fi
  if ! [[ "$min_selection_lines" =~ ^[0-9]+$ && "$min_entry_operators" =~ ^[0-9]+$ && "$min_exit_operators" =~ ^[0-9]+$ ]]; then
    echo "client-test requires --min-selection-lines, --min-entry-operators and --min-exit-operators to be numeric"
    exit 2
  fi
  if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
    echo "client-test requires --beta-profile (or EASY_NODE_BETA_PROFILE) to be 0 or 1"
    exit 2
  fi
  if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
    echo "client-test requires --prod-profile (or EASY_NODE_PROD_PROFILE) to be 0 or 1"
    exit 2
  fi
  if [[ "$execution_mode" != "docker" && "$execution_mode" != "local" ]]; then
    echo "client-test requires EASY_NODE_CLIENT_TEST_MODE to be docker or local"
    exit 2
  fi
  if [[ "$prod_profile" == "1" ]]; then
    beta_profile="1"
  fi
  if [[ "$speed_onehop_profile" == "1" && ( "$beta_profile" == "1" || "$prod_profile" == "1" ) ]]; then
    echo "client-test --path-profile 1hop/speed-1hop requires --beta-profile 0 and --prod-profile 0"
    exit 2
  fi
  if [[ -z "$allow_direct_exit_fallback" ]]; then
    if [[ "$beta_profile" == "1" || "$prod_profile" == "1" ]]; then
      allow_direct_exit_fallback="0"
    elif [[ "$require_distinct_operators" == "1" ]]; then
      allow_direct_exit_fallback="0"
    else
      allow_direct_exit_fallback="1"
    fi
  fi
  if [[ "$allow_direct_exit_fallback" != "0" && "$allow_direct_exit_fallback" != "1" ]]; then
    echo "client-test requires CLIENT_ALLOW_DIRECT_EXIT_FALLBACK to be 0 or 1"
    exit 2
  fi
  if [[ "$allow_direct_exit_fallback" == "1" && "$beta_profile" == "1" ]]; then
    echo "client-test does not allow CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=1 with beta/prod profile"
    exit 2
  fi
  if [[ "$allow_direct_exit_fallback" == "1" && "$require_distinct_operators" == "1" ]]; then
    echo "client-test requires --distinct-operators 0 when CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=1"
    exit 2
  fi
  if [[ -z "$force_direct_exit" ]]; then
    force_direct_exit="0"
  fi
  if [[ "$force_direct_exit" != "0" && "$force_direct_exit" != "1" ]]; then
    echo "client-test requires CLIENT_FORCE_DIRECT_EXIT or --force-direct-exit to be 0 or 1"
    exit 2
  fi
  if [[ "$force_direct_exit" == "1" && "$allow_direct_exit_fallback" != "1" ]]; then
    echo "client-test requires CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=1 when --force-direct-exit is enabled"
    exit 2
  fi
  if [[ "$force_direct_exit" == "1" && ( "$beta_profile" == "1" || "$prod_profile" == "1" ) ]]; then
    echo "client-test does not allow --force-direct-exit with beta/prod profile"
    exit 2
  fi
  if [[ "$force_direct_exit" == "1" && "$require_distinct_operators" == "1" ]]; then
    echo "client-test requires --distinct-operators 0 when --force-direct-exit is enabled"
    exit 2
  fi
  if [[ "$beta_profile" == "1" ]]; then
    if [[ "$distinct_set" -eq 0 ]]; then
      require_distinct_operators="1"
    fi
    if [[ "$min_sources_set" -eq 0 ]] && [[ "$directory_urls" == *,* ]]; then
      min_sources="2"
    fi
  fi
  if [[ -n "$client_subject" && -n "$client_anon_cred" ]]; then
    echo "client-test requires exactly one of --subject or --anon-cred"
    exit 2
  fi

  local client_url_scheme="http"
  if [[ "$prod_profile" == "1" ]]; then
    client_url_scheme="https"
  fi
  local container_directory_urls="${EASY_NODE_CLIENT_TEST_CONTAINER_DIRECTORY_URLS:-}"
  local container_issuer_url="${EASY_NODE_CLIENT_TEST_CONTAINER_ISSUER_URL:-}"
  local container_entry_url="${EASY_NODE_CLIENT_TEST_CONTAINER_ENTRY_URL:-}"
  local container_exit_url="${EASY_NODE_CLIENT_TEST_CONTAINER_EXIT_URL:-}"

  if [[ -n "$bootstrap_directory" ]]; then
    bootstrap_directory="$(ensure_url_scheme "$bootstrap_directory" "$client_url_scheme")"
    if ! [[ "$discovery_wait_sec" =~ ^[0-9]+$ ]]; then
      echo "client-test requires --discovery-wait-sec to be numeric"
      exit 2
    fi
    local discovered
    discovered="$(discover_directory_urls "$bootstrap_directory" "$discovery_wait_sec" "$min_sources")"
    if [[ -z "$directory_urls" ]]; then
      directory_urls="$discovered"
    else
      directory_urls="$(merge_url_csv "$directory_urls" "$discovered")"
    fi

    local bootstrap_host
    bootstrap_host="$(host_from_url "$bootstrap_directory")"
    if [[ -z "$issuer_url" && -n "$bootstrap_host" ]]; then
      issuer_url="$(url_from_host_port "$bootstrap_host" 8082)"
    fi
    if [[ -z "$entry_url" && -n "$bootstrap_host" ]]; then
      entry_url="$(url_from_host_port "$bootstrap_host" 8083)"
    fi
    if [[ -z "$exit_url" && -n "$bootstrap_host" ]]; then
      exit_url="$(url_from_host_port "$bootstrap_host" 8084)"
    fi
  fi

  if [[ -z "$directory_urls" || -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" ]]; then
    echo "client-test requires directory, issuer, entry and exit URLs."
    echo "provide explicit --directory-urls/--issuer-url/--entry-url/--exit-url"
    echo "or use --bootstrap-directory for automatic discovery."
    exit 2
  fi
  directory_urls="$(normalize_url_csv_scheme "$directory_urls" "$client_url_scheme")"
  issuer_url="$(ensure_url_scheme "$issuer_url" "$client_url_scheme")"
  entry_url="$(ensure_url_scheme "$entry_url" "$client_url_scheme")"
  exit_url="$(ensure_url_scheme "$exit_url" "$client_url_scheme")"
  if [[ -z "$container_directory_urls" ]]; then
    container_directory_urls="$directory_urls"
  else
    container_directory_urls="$(normalize_url_csv_scheme "$container_directory_urls" "$client_url_scheme")"
  fi
  if [[ -z "$container_issuer_url" ]]; then
    container_issuer_url="$issuer_url"
  else
    container_issuer_url="$(ensure_url_scheme "$container_issuer_url" "$client_url_scheme")"
  fi
  if [[ -z "$container_entry_url" ]]; then
    container_entry_url="$entry_url"
  else
    container_entry_url="$(ensure_url_scheme "$container_entry_url" "$client_url_scheme")"
  fi
  if [[ -z "$container_exit_url" ]]; then
    container_exit_url="$exit_url"
  else
    container_exit_url="$(ensure_url_scheme "$container_exit_url" "$client_url_scheme")"
  fi

  ensure_deps_or_die
  if [[ "$execution_mode" == "docker" ]]; then
    cleanup_client_demo_artifacts
  fi

  local client_env_file
  client_env_file="$(resolve_client_env_file)"
  local first_dir
  first_dir="$(first_csv_item "$directory_urls")"

  cat >"$client_env_file" <<EOF_CLIENT
CLIENT_DIRECTORY_URL=${first_dir}
CLIENT_ISSUER_URL=${issuer_url}
CLIENT_ENTRY_URL=${entry_url}
CLIENT_EXIT_CONTROL_URL=${exit_url}
CLIENT_ENTRY_ROTATION_SEC=${entry_rotation_sec}
CLIENT_ENTRY_ROTATION_SEED=${entry_rotation_seed}
EOF_CLIENT

  local log_dir
  local out
  local build_log
  log_dir="$(prepare_log_dir)"
  build_log="$log_dir/easy_node_client_build_$(date +%Y%m%d_%H%M%S).log"
  out="$log_dir/easy_node_client_test_$(date +%Y%m%d_%H%M%S).log"
  rm -f "$out"

  if looks_like_loopback_url "$first_dir" || looks_like_loopback_url "$issuer_url" || looks_like_loopback_url "$entry_url" || looks_like_loopback_url "$exit_url"; then
    echo "note: one or more URLs use localhost/127.0.0.1"
    echo "      this only works when those addresses are reachable from inside the client container."
  fi

  local -a dir_opts issuer_opts entry_opts exit_opts
  mapfile -t dir_opts < <(curl_tls_opts_for_url "$first_dir")
  mapfile -t issuer_opts < <(curl_tls_opts_for_url "$issuer_url")
  mapfile -t entry_opts < <(curl_tls_opts_for_url "$entry_url")
  mapfile -t exit_opts < <(curl_tls_opts_for_url "$exit_url")
  wait_http_ok_with_opts "${first_dir%/}/v1/pubkeys" "directory" 8 "${dir_opts[@]}" || return 1
  wait_http_ok_with_opts "${issuer_url%/}/v1/pubkeys" "issuer" 8 "${issuer_opts[@]}" || return 1
  wait_http_ok_with_opts "${entry_url%/}/v1/health" "entry" 8 "${entry_opts[@]}" || return 1
  wait_http_ok_with_opts "${exit_url%/}/v1/health" "exit" 8 "${exit_opts[@]}" || return 1

  if [[ "$execution_mode" == "docker" ]]; then
    local do_build=0
    if [[ "$force_build" == "1" ]]; then
      do_build=1
    elif ! docker image inspect deploy-client-demo:latest >/dev/null 2>&1; then
      do_build=1
    fi

    if [[ "$do_build" -eq 1 ]]; then
      echo "client test: building client image (timeout=${build_timeout_sec}s)"
      if ! (
        cd "$DEPLOY_DIR"
        timeout --foreground -k 15s "${build_timeout_sec}s" env COMPOSE_INTERACTIVE_NO_CLI=1 COMPOSE_MENU=0 docker compose --profile demo build client-demo >"$build_log" 2>&1
      ); then
        echo "client image build failed or timed out"
        echo "client build log: $build_log"
        cat "$build_log"
        return 1
      fi
      echo "client test: build done"
    else
      echo "client test: using existing deploy-client-demo:latest image (set EASY_NODE_CLIENT_FORCE_BUILD=1 to rebuild)"
    fi
  else
    echo "client test: local host mode"
  fi
  if [[ "$beta_profile" == "1" ]]; then
    echo "client test: beta profile enabled (distinct operators + multi-source defaults)"
  fi
  if [[ "$prod_profile" == "1" ]]; then
    echo "client test: prod profile enabled (mTLS + trust hardening)"
    echo "note: full fail-closed strict runtime is validated via wg-only/strict integration flows"
  fi

  if [[ "$execution_mode" == "docker" ]]; then
    local -a run_cmd
    run_cmd=(
      env
      COMPOSE_INTERACTIVE_NO_CLI=1
      COMPOSE_MENU=0
      docker compose
      --env-file "$client_env_file"
      --profile demo
      run -T --no-deps --rm
      -e "DIRECTORY_URLS=$container_directory_urls"
      -e "DIRECTORY_MIN_SOURCES=$min_sources"
      -e "ISSUER_URL=$container_issuer_url"
      -e "ENTRY_URL=$container_entry_url"
      -e "EXIT_CONTROL_URL=$container_exit_url"
      -e "CLIENT_PATH_PROFILE=$canonical_path_profile"
      -e "CLIENT_BOOTSTRAP_INTERVAL_SEC=2"
      -e "CLIENT_REQUIRE_DISTINCT_OPERATORS=$require_distinct_operators"
      -e "CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY=$require_distinct_countries"
      -e "CLIENT_EXIT_LOCALITY_SOFT_BIAS=$locality_soft_bias"
      -e "CLIENT_EXIT_COUNTRY_BIAS=$locality_country_bias"
      -e "CLIENT_EXIT_REGION_BIAS=$locality_region_bias"
      -e "CLIENT_EXIT_REGION_PREFIX_BIAS=$locality_region_prefix_bias"
      -e "CLIENT_ENTRY_ROTATION_SEC=$entry_rotation_sec"
      -e "CLIENT_ENTRY_ROTATION_SEED=$entry_rotation_seed"
      -e "CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=$allow_direct_exit_fallback"
      -e "CLIENT_FORCE_DIRECT_EXIT=$force_direct_exit"
    )
    if [[ -n "$client_subject" ]]; then
      run_cmd+=(-e "CLIENT_SUBJECT=$client_subject")
    fi
    if [[ -n "$client_anon_cred" ]]; then
      run_cmd+=(-e "CLIENT_ANON_CRED=$client_anon_cred")
    fi
    if [[ -n "$require_middle_relay" ]]; then
      run_cmd+=(-e "CLIENT_REQUIRE_MIDDLE_RELAY=$require_middle_relay")
    fi
    if [[ "$beta_profile" == "1" && "$container_directory_urls" == *,* ]]; then
      run_cmd+=(
        -e "DIRECTORY_MIN_OPERATORS=2"
        -e "CLIENT_DIRECTORY_MIN_OPERATORS=2"
      )
    fi
    if [[ "$prod_profile" == "1" ]]; then
      run_cmd+=(
        -e "MTLS_ENABLE=1"
        -e "MTLS_CA_FILE=/app/tls/ca.crt"
        -e "MTLS_CLIENT_CERT_FILE=/app/tls/client.crt"
        -e "MTLS_CLIENT_KEY_FILE=/app/tls/client.key"
        -e "MTLS_CERT_FILE=/app/tls/client.crt"
        -e "MTLS_KEY_FILE=/app/tls/client.key"
        -e "DIRECTORY_TRUST_STRICT=1"
        -e "DIRECTORY_TRUST_TOFU=0"
      )
    fi
    if [[ -n "$exit_country" ]]; then
      run_cmd+=(-e "CLIENT_EXIT_COUNTRY=$exit_country")
    fi
    if [[ -n "$exit_region" ]]; then
      run_cmd+=(-e "CLIENT_EXIT_REGION=$exit_region")
    fi
    if [[ -n "$client_inner_source" ]]; then
      run_cmd+=(-e "CLIENT_INNER_SOURCE=$client_inner_source")
    fi
    if [[ -n "$client_disable_synthetic_fallback" ]]; then
      run_cmd+=(-e "CLIENT_DISABLE_SYNTHETIC_FALLBACK=$client_disable_synthetic_fallback")
    fi
    if [[ -n "$data_plane_mode" ]]; then
      run_cmd+=(-e "DATA_PLANE_MODE=$data_plane_mode")
    fi
    run_cmd+=(client-demo)

    (
      cd "$DEPLOY_DIR"
      timeout --foreground -k 10s "${timeout_sec}s" "${run_cmd[@]}" >"$out" 2>&1
    ) || true
    cleanup_client_demo_artifacts
  else
    local -a local_cmd
    local_cmd=(
      env
      "DIRECTORY_URLS=$directory_urls"
      "DIRECTORY_MIN_SOURCES=$min_sources"
      "ISSUER_URL=$issuer_url"
      "ENTRY_URL=$entry_url"
      "EXIT_CONTROL_URL=$exit_url"
      "CLIENT_PATH_PROFILE=$canonical_path_profile"
      "CLIENT_BOOTSTRAP_INTERVAL_SEC=2"
      "CLIENT_REQUIRE_DISTINCT_OPERATORS=$require_distinct_operators"
      "CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY=$require_distinct_countries"
      "CLIENT_EXIT_LOCALITY_SOFT_BIAS=$locality_soft_bias"
      "CLIENT_EXIT_COUNTRY_BIAS=$locality_country_bias"
      "CLIENT_EXIT_REGION_BIAS=$locality_region_bias"
      "CLIENT_EXIT_REGION_PREFIX_BIAS=$locality_region_prefix_bias"
      "CLIENT_ENTRY_ROTATION_SEC=$entry_rotation_sec"
      "CLIENT_ENTRY_ROTATION_SEED=$entry_rotation_seed"
      "CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=$allow_direct_exit_fallback"
      "CLIENT_FORCE_DIRECT_EXIT=$force_direct_exit"
    )
    if [[ -n "$client_subject" ]]; then
      local_cmd+=("CLIENT_SUBJECT=$client_subject")
    fi
    if [[ -n "$client_anon_cred" ]]; then
      local_cmd+=("CLIENT_ANON_CRED=$client_anon_cred")
    fi
    if [[ -n "$require_middle_relay" ]]; then
      local_cmd+=("CLIENT_REQUIRE_MIDDLE_RELAY=$require_middle_relay")
    fi
    if [[ "$beta_profile" == "1" && "$directory_urls" == *,* ]]; then
      local_cmd+=(
        "DIRECTORY_MIN_OPERATORS=2"
        "CLIENT_DIRECTORY_MIN_OPERATORS=2"
      )
    fi
    if [[ "$prod_profile" == "1" ]]; then
      local_cmd+=(
        "MTLS_ENABLE=1"
        "MTLS_CA_FILE=$DEPLOY_DIR/tls/ca.crt"
        "MTLS_CLIENT_CERT_FILE=$DEPLOY_DIR/tls/client.crt"
        "MTLS_CLIENT_KEY_FILE=$DEPLOY_DIR/tls/client.key"
        "MTLS_CERT_FILE=$DEPLOY_DIR/tls/client.crt"
        "MTLS_KEY_FILE=$DEPLOY_DIR/tls/client.key"
        "DIRECTORY_TRUST_STRICT=1"
        "DIRECTORY_TRUST_TOFU=0"
      )
    fi
    if [[ -n "$exit_country" ]]; then
      local_cmd+=("CLIENT_EXIT_COUNTRY=$exit_country")
    fi
    if [[ -n "$exit_region" ]]; then
      local_cmd+=("CLIENT_EXIT_REGION=$exit_region")
    fi
    if [[ -n "$client_inner_source" ]]; then
      local_cmd+=("CLIENT_INNER_SOURCE=$client_inner_source")
    fi
    if [[ -n "$client_disable_synthetic_fallback" ]]; then
      local_cmd+=("CLIENT_DISABLE_SYNTHETIC_FALLBACK=$client_disable_synthetic_fallback")
    fi
    if [[ -n "$data_plane_mode" ]]; then
      local_cmd+=("DATA_PLANE_MODE=$data_plane_mode")
    fi
    local_cmd+=(go run ./cmd/node --client)

    (
      cd "$ROOT_DIR"
      timeout --foreground -k 10s "${timeout_sec}s" "${local_cmd[@]}" >"$out" 2>&1
    ) || true
  fi

  if rg -q 'client selected entry=' "$out"; then
    local same_ops missing_ops selection_count entry_op_count exit_op_count cross_pair_count
    read -r same_ops missing_ops selection_count entry_op_count exit_op_count cross_pair_count < <(
        awk '
          /client selected entry=/ {
            selected++
            entry_op=""
            exit_op=""
            for (i = 1; i <= NF; i++) {
              if ($i ~ /^entry_op=/) {
                entry_op = substr($i, 10)
              } else if ($i ~ /^exit_op=/) {
                exit_op = substr($i, 9)
              }
            }
            if (entry_op == "" || exit_op == "") {
              missing++
            } else if (entry_op == exit_op) {
              same++
            } else {
              cross++
            }
            if (entry_op != "") {
              entry_seen[entry_op] = 1
            }
            if (exit_op != "") {
              exit_seen[exit_op] = 1
            }
          }
          END {
            entry_count = 0
            exit_count = 0
            for (k in entry_seen) {
              entry_count++
            }
            for (k in exit_seen) {
              exit_count++
            }
            if (same == "") {
              same = 0
            }
            if (missing == "") {
              missing = 0
            }
            if (selected == "") {
              selected = 0
            }
            if (cross == "") {
              cross = 0
            }
            printf "%d %d %d %d %d %d\n", same, missing, selected, entry_count, exit_count, cross
          }
        ' "$out"
      )
    echo "client selection summary: selections=$selection_count entry_ops=$entry_op_count exit_ops=$exit_op_count cross_pairs=$cross_pair_count same_ops=$same_ops missing_ops=$missing_ops"
    if ((selection_count < min_selection_lines)); then
      echo "client test: failed selection volume validation (observed=$selection_count required=$min_selection_lines)"
      echo "client test log: $out"
      rg 'client selected entry=' "$out" || true
      return 1
    fi
    if ((entry_op_count < min_entry_operators)); then
      echo "client test: failed entry-operator diversity validation (observed=$entry_op_count required=$min_entry_operators)"
      echo "client test log: $out"
      rg 'client selected entry=' "$out" || true
      return 1
    fi
    if ((exit_op_count < min_exit_operators)); then
      echo "client test: failed exit-operator diversity validation (observed=$exit_op_count required=$min_exit_operators)"
      echo "client test log: $out"
      rg 'client selected entry=' "$out" || true
      return 1
    fi
    if [[ "$require_cross_operator_pair" == "1" ]] && ((cross_pair_count < 1)); then
      echo "client test: failed cross-operator-pair validation (observed=$cross_pair_count required>=1)"
      echo "client test log: $out"
      rg 'client selected entry=' "$out" || true
      return 1
    fi
    if [[ "$require_distinct_operators" == "1" ]]; then
      if ((same_ops > 0 || missing_ops > 0)); then
        echo "client test: failed distinct-operator validation (same_ops=$same_ops missing_ops=$missing_ops)"
        echo "client test log: $out"
        rg 'client selected entry=' "$out" || true
        return 1
      fi
    fi
    echo "client test: ok"
    echo "client test log: $out"
    echo "key log lines:"
    rg 'client selected entry=|client received wg-session config|bootstrap failed' "$out" || true
    return 0
  fi

  echo "client test: failed"
  echo "client test log: $out"
  cat "$out"
  return 1
}

client_vpn_preflight() {
  local directory_urls=""
  local issuer_url=""
  local issuer_urls=""
  local entry_url=""
  local exit_url=""
  local bootstrap_directory=""
  local discovery_wait_sec="${EASY_NODE_DISCOVERY_WAIT_SEC:-20}"
  local path_profile="${EASY_NODE_PATH_PROFILE:-}"
  local prod_profile="${EASY_NODE_PROD_PROFILE:-0}"
  local interface_name="${CLIENT_WG_INTERFACE:-wgvpn0}"
  local timeout_sec="${EASY_NODE_CLIENT_VPN_PREFLIGHT_TIMEOUT_SEC:-12}"
  local require_root="1"
  local operator_floor_check="${EASY_NODE_CLIENT_VPN_OPERATOR_FLOOR_CHECK:-}"
  local operator_min_operators="${EASY_NODE_CLIENT_VPN_OPERATOR_MIN_OPERATORS:-2}"
  local operator_min_entry_operators="${EASY_NODE_CLIENT_VPN_OPERATOR_MIN_ENTRY_OPERATORS:-}"
  local operator_min_exit_operators="${EASY_NODE_CLIENT_VPN_OPERATOR_MIN_EXIT_OPERATORS:-}"
  local middle_relay_check="${EASY_NODE_CLIENT_VPN_MIDDLE_RELAY_CHECK:-}"
  local middle_relay_min_operators="${EASY_NODE_CLIENT_VPN_MIDDLE_RELAY_MIN_OPERATORS:-1}"
  local middle_relay_require_distinct="${EASY_NODE_CLIENT_VPN_MIDDLE_RELAY_REQUIRE_DISTINCT:-1}"
  local issuer_quorum_check="${EASY_NODE_CLIENT_VPN_ISSUER_QUORUM_CHECK:-}"
  local issuer_min_operators="${EASY_NODE_CLIENT_VPN_ISSUER_MIN_OPERATORS:-2}"
  local mtls_ca_file="$DEPLOY_DIR/tls/ca.crt"
  local mtls_client_cert_file="$DEPLOY_DIR/tls/client.crt"
  local mtls_client_key_file="$DEPLOY_DIR/tls/client.key"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --directory-urls)
        directory_urls="${2:-}"
        shift 2
        ;;
      --bootstrap-directory)
        bootstrap_directory="${2:-}"
        shift 2
        ;;
      --discovery-wait-sec)
        discovery_wait_sec="${2:-}"
        shift 2
        ;;
      --path-profile)
        path_profile="${2:-}"
        shift 2
        ;;
      --issuer-url)
        issuer_url="${2:-}"
        shift 2
        ;;
      --issuer-urls)
        issuer_urls="${2:-}"
        shift 2
        ;;
      --entry-url)
        entry_url="${2:-}"
        shift 2
        ;;
      --exit-url)
        exit_url="${2:-}"
        shift 2
        ;;
      --prod-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          prod_profile="${2:-}"
          shift 2
        else
          prod_profile="1"
          shift
        fi
        ;;
      --interface)
        interface_name="${2:-}"
        shift 2
        ;;
      --timeout-sec)
        timeout_sec="${2:-}"
        shift 2
        ;;
      --require-root)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          require_root="${2:-}"
          shift 2
        else
          require_root="1"
          shift
        fi
        ;;
      --operator-floor-check)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          operator_floor_check="${2:-}"
          shift 2
        else
          operator_floor_check="1"
          shift
        fi
        ;;
      --operator-min-operators)
        operator_min_operators="${2:-}"
        shift 2
        ;;
      --operator-min-entry-operators)
        operator_min_entry_operators="${2:-}"
        shift 2
        ;;
      --operator-min-exit-operators)
        operator_min_exit_operators="${2:-}"
        shift 2
        ;;
      --middle-relay-check)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          middle_relay_check="${2:-}"
          shift 2
        else
          middle_relay_check="1"
          shift
        fi
        ;;
      --middle-relay-min-operators)
        middle_relay_min_operators="${2:-}"
        shift 2
        ;;
      --middle-relay-require-distinct)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
          middle_relay_require_distinct="${2:-}"
          shift 2
        else
          middle_relay_require_distinct="1"
          shift
        fi
        ;;
      --issuer-quorum-check)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          issuer_quorum_check="${2:-}"
          shift 2
        else
          issuer_quorum_check="1"
          shift
        fi
        ;;
      --issuer-min-operators)
        issuer_min_operators="${2:-}"
        shift 2
        ;;
      --mtls-ca-file)
        mtls_ca_file="${2:-}"
        shift 2
        ;;
      --mtls-client-cert-file)
        mtls_client_cert_file="${2:-}"
        shift 2
        ;;
      --mtls-client-key-file)
        mtls_client_key_file="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for client-vpn-preflight: $1"
        exit 2
        ;;
    esac
  done

  ensure_client_vpn_deps_or_die

  if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
    echo "client-vpn-preflight requires --prod-profile 0 or 1"
    exit 2
  fi
  if [[ "$require_root" != "0" && "$require_root" != "1" ]]; then
    echo "client-vpn-preflight requires --require-root 0 or 1"
    exit 2
  fi
  if [[ -z "$operator_floor_check" ]]; then
    if [[ "$prod_profile" == "1" ]]; then
      operator_floor_check="1"
    else
      operator_floor_check="0"
    fi
  fi
  if [[ "$operator_floor_check" != "0" && "$operator_floor_check" != "1" ]]; then
    echo "client-vpn-preflight requires --operator-floor-check 0 or 1"
    exit 2
  fi
  local normalized_path_profile=""
  normalized_path_profile="$(normalize_path_profile "$path_profile")" || {
    echo "client-vpn-preflight requires --path-profile to be one of: 1hop, 2hop, 3hop, speed, balanced, private"
    exit 2
  }
  if [[ -z "$middle_relay_check" ]]; then
    if [[ "$normalized_path_profile" == "privacy" ]]; then
      middle_relay_check="1"
    else
      middle_relay_check="0"
    fi
  fi
  if [[ "$middle_relay_check" != "0" && "$middle_relay_check" != "1" ]]; then
    echo "client-vpn-preflight requires --middle-relay-check 0 or 1"
    exit 2
  fi
  if [[ "$middle_relay_require_distinct" != "0" && "$middle_relay_require_distinct" != "1" ]]; then
    echo "client-vpn-preflight requires --middle-relay-require-distinct 0 or 1"
    exit 2
  fi
  if ! [[ "$middle_relay_min_operators" =~ ^[0-9]+$ ]] || ((middle_relay_min_operators < 1)); then
    echo "client-vpn-preflight requires --middle-relay-min-operators >= 1"
    exit 2
  fi
  if [[ -z "$operator_min_entry_operators" ]]; then
    operator_min_entry_operators="$operator_min_operators"
  fi
  if [[ -z "$operator_min_exit_operators" ]]; then
    operator_min_exit_operators="$operator_min_operators"
  fi
  if ! [[ "$operator_min_operators" =~ ^[0-9]+$ ]] || ((operator_min_operators < 1)); then
    echo "client-vpn-preflight requires --operator-min-operators >= 1"
    exit 2
  fi
  if ! [[ "$operator_min_entry_operators" =~ ^[0-9]+$ ]] || ((operator_min_entry_operators < 1)); then
    echo "client-vpn-preflight requires --operator-min-entry-operators >= 1"
    exit 2
  fi
  if ! [[ "$operator_min_exit_operators" =~ ^[0-9]+$ ]] || ((operator_min_exit_operators < 1)); then
    echo "client-vpn-preflight requires --operator-min-exit-operators >= 1"
    exit 2
  fi
  if [[ -z "$issuer_quorum_check" ]]; then
    if [[ "$prod_profile" == "1" ]]; then
      issuer_quorum_check="1"
    else
      issuer_quorum_check="0"
    fi
  fi
  if [[ "$issuer_quorum_check" != "0" && "$issuer_quorum_check" != "1" ]]; then
    echo "client-vpn-preflight requires --issuer-quorum-check 0 or 1"
    exit 2
  fi
  if ! [[ "$issuer_min_operators" =~ ^[0-9]+$ ]] || ((issuer_min_operators < 1)); then
    echo "client-vpn-preflight requires --issuer-min-operators >= 1"
    exit 2
  fi
  if ! [[ "$discovery_wait_sec" =~ ^[0-9]+$ && "$timeout_sec" =~ ^[0-9]+$ ]]; then
    echo "client-vpn-preflight requires numeric --discovery-wait-sec and --timeout-sec"
    exit 2
  fi
  if [[ -z "$interface_name" ]]; then
    echo "client-vpn-preflight requires --interface"
    exit 2
  fi

  local client_url_scheme="http"
  if [[ "$prod_profile" == "1" ]]; then
    client_url_scheme="https"
  fi

  if [[ -n "$bootstrap_directory" ]]; then
    bootstrap_directory="$(ensure_url_scheme "$bootstrap_directory" "$client_url_scheme")"
    local discovered
    discovered="$(discover_directory_urls "$bootstrap_directory" "$discovery_wait_sec" 1)"
    if [[ -z "$directory_urls" ]]; then
      directory_urls="$discovered"
    else
      directory_urls="$(merge_url_csv "$directory_urls" "$discovered")"
    fi
    local bootstrap_host
    bootstrap_host="$(host_from_url "$bootstrap_directory")"
    if [[ -z "$issuer_url" && -n "$bootstrap_host" ]]; then
      issuer_url="$(url_from_host_port "$bootstrap_host" 8082)"
    fi
    if [[ -z "$entry_url" && -n "$bootstrap_host" ]]; then
      entry_url="$(url_from_host_port "$bootstrap_host" 8083)"
    fi
    if [[ -z "$exit_url" && -n "$bootstrap_host" ]]; then
      exit_url="$(url_from_host_port "$bootstrap_host" 8084)"
    fi
  fi

  if [[ -z "$directory_urls" || -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" ]]; then
    echo "client-vpn-preflight requires directory, issuer, entry and exit URLs"
    exit 2
  fi

  directory_urls="$(normalize_url_csv_scheme "$directory_urls" "$client_url_scheme")"
  issuer_url="$(ensure_url_scheme "$issuer_url" "$client_url_scheme")"
  entry_url="$(ensure_url_scheme "$entry_url" "$client_url_scheme")"
  exit_url="$(ensure_url_scheme "$exit_url" "$client_url_scheme")"
  if [[ -z "$issuer_urls" ]]; then
    issuer_urls="$issuer_url"
  fi
  issuer_urls="$(merge_url_csv "$issuer_urls" "$issuer_url")"
  local durl dhost
  while IFS= read -r durl; do
    [[ -z "$durl" ]] && continue
    dhost="$(host_from_url "$durl")"
    if [[ -n "$dhost" ]]; then
      issuer_urls="$(merge_url_csv "$issuer_urls" "$(url_from_host_port "$dhost" 8082)")"
    fi
  done < <(split_csv_lines "$directory_urls")
  issuer_urls="$(normalize_url_csv_scheme "$issuer_urls" "$client_url_scheme")"

  local fail=0
  local first_dir
  first_dir="$(first_csv_item "$directory_urls")"

  echo "client-vpn preflight:"
  echo "  directory_urls: $directory_urls"
  echo "  issuer_url: $issuer_url"
  echo "  entry_url: $entry_url"
  echo "  exit_url: $exit_url"
  echo "  interface: $interface_name"
  echo "  prod_profile: $prod_profile"
  echo "  path_profile: ${normalized_path_profile:-balanced}"
  echo "  operator_floor_check: $operator_floor_check"
  echo "  operator_min_operators: $operator_min_operators"
  echo "  operator_min_entry_operators: $operator_min_entry_operators"
  echo "  operator_min_exit_operators: $operator_min_exit_operators"
  echo "  middle_relay_check: $middle_relay_check"
  echo "  middle_relay_min_operators: $middle_relay_min_operators"
  echo "  middle_relay_require_distinct: $middle_relay_require_distinct"
  echo "  issuer_quorum_check: $issuer_quorum_check"
  echo "  issuer_urls: $issuer_urls"

  local -a dir_opts issuer_opts entry_opts exit_opts
  mapfile -t dir_opts < <(curl_tls_opts_for_url "$first_dir")
  mapfile -t issuer_opts < <(curl_tls_opts_for_url "$issuer_url")
  mapfile -t entry_opts < <(curl_tls_opts_for_url "$entry_url")
  mapfile -t exit_opts < <(curl_tls_opts_for_url "$exit_url")

  if wait_http_ok_with_opts "${first_dir%/}/v1/pubkeys" "directory" "$timeout_sec" "${dir_opts[@]}"; then
    echo "  [ok] directory reachable"
  else
    echo "  [fail] directory unreachable"
    fail=$((fail + 1))
  fi
  if wait_http_ok_with_opts "${issuer_url%/}/v1/pubkeys" "issuer" "$timeout_sec" "${issuer_opts[@]}"; then
    echo "  [ok] issuer reachable"
  else
    echo "  [fail] issuer unreachable"
    fail=$((fail + 1))
  fi
  if wait_http_ok_with_opts "${entry_url%/}/v1/health" "entry" "$timeout_sec" "${entry_opts[@]}"; then
    echo "  [ok] entry reachable"
  else
    echo "  [fail] entry unreachable"
    fail=$((fail + 1))
  fi
  if wait_http_ok_with_opts "${exit_url%/}/v1/health" "exit" "$timeout_sec" "${exit_opts[@]}"; then
    echo "  [ok] exit reachable"
  else
    echo "  [fail] exit unreachable"
    fail=$((fail + 1))
  fi

  if [[ "$operator_floor_check" == "1" ]]; then
    local all_ops entry_ops exit_ops missing_ops fetch_fail parse_fail
    local all_ops_list entry_ops_list exit_ops_list
    local operator_floor_failed=0
    IFS='|' read -r all_ops entry_ops exit_ops missing_ops fetch_fail parse_fail all_ops_list entry_ops_list exit_ops_list < <(client_vpn_operator_floor_summary "$directory_urls" "$timeout_sec")
    echo "  operator diversity: all_ops=$all_ops entry_ops=$entry_ops exit_ops=$exit_ops missing_operator_fields=$missing_ops fetch_failures=$fetch_fail parse_failures=$parse_fail"
    if ((fetch_fail > 0)); then
      echo "  [fail] could not fetch relay set from all configured directories"
      fail=$((fail + 1))
      operator_floor_failed=1
    fi
    if ((parse_fail > 0)); then
      echo "  [fail] failed to parse one or more directory relay payloads"
      fail=$((fail + 1))
      operator_floor_failed=1
    fi
    if ((missing_ops > 0)); then
      echo "  [fail] relay descriptors missing operator metadata"
      fail=$((fail + 1))
      operator_floor_failed=1
    fi
    if ((all_ops < operator_min_operators)); then
      echo "  [fail] operator floor not met (need >=$operator_min_operators distinct operators, observed=$all_ops)"
      fail=$((fail + 1))
      operator_floor_failed=1
    fi
    if ((entry_ops < operator_min_entry_operators)); then
      echo "  [fail] entry operator floor not met (need >=$operator_min_entry_operators, observed=$entry_ops)"
      fail=$((fail + 1))
      operator_floor_failed=1
    fi
    if ((exit_ops < operator_min_exit_operators)); then
      echo "  [fail] exit operator floor not met (need >=$operator_min_exit_operators, observed=$exit_ops)"
      fail=$((fail + 1))
      operator_floor_failed=1
    fi
    if ((operator_floor_failed > 0)); then
      echo "  observed operators: all=${all_ops_list:-none} entry=${entry_ops_list:-none} exit=${exit_ops_list:-none}"
      echo "  hint: staged/single-operator labs can keep checks enabled with --operator-min-operators 1 --operator-min-entry-operators 1 --operator-min-exit-operators 1"
    fi
  fi

  if [[ "$middle_relay_check" == "1" ]]; then
    local middle_ops eligible_middle_ops middle_relays missing_middle_ops middle_fetch_fail middle_parse_fail
    local middle_ops_list eligible_middle_ops_list
    local middle_floor_failed=0
    IFS='|' read -r middle_ops eligible_middle_ops middle_relays missing_middle_ops middle_fetch_fail middle_parse_fail middle_ops_list eligible_middle_ops_list < <(client_vpn_middle_relay_summary "$directory_urls" "$timeout_sec")
    echo "  middle relay diversity: middle_ops=$middle_ops eligible_middle_ops=$eligible_middle_ops middle_relays=$middle_relays missing_middle_operator_fields=$missing_middle_ops fetch_failures=$middle_fetch_fail parse_failures=$middle_parse_fail"
    if ((middle_fetch_fail > 0)); then
      echo "  [fail] could not fetch relay set from all configured directories for middle-relay check"
      fail=$((fail + 1))
      middle_floor_failed=1
    fi
    if ((middle_parse_fail > 0)); then
      echo "  [fail] failed to parse one or more directory relay payloads for middle-relay check"
      fail=$((fail + 1))
      middle_floor_failed=1
    fi
    if ((middle_relay_require_distinct > 0)); then
      if ((missing_middle_ops > 0)); then
        echo "  [fail] middle-relay descriptors missing operator metadata under distinct middle-relay policy"
        fail=$((fail + 1))
        middle_floor_failed=1
      fi
      if ((eligible_middle_ops < middle_relay_min_operators)); then
        echo "  [fail] middle-relay operator floor not met (need >=$middle_relay_min_operators distinct middle operators not used by entry/exit, observed=$eligible_middle_ops)"
        fail=$((fail + 1))
        middle_floor_failed=1
      fi
    else
      if ((middle_ops < middle_relay_min_operators)); then
        echo "  [fail] middle-relay operator floor not met (need >=$middle_relay_min_operators distinct middle operators, observed=$middle_ops)"
        fail=$((fail + 1))
        middle_floor_failed=1
      fi
    fi
    if ((middle_floor_failed > 0)); then
      echo "  observed middle operators: all=${middle_ops_list:-none} eligible_distinct=${eligible_middle_ops_list:-none}"
      echo "  hint: for staged labs, lower the middle floor with --middle-relay-min-operators 1 or disable with --middle-relay-check 0"
    fi
  fi

  if [[ "$issuer_quorum_check" == "1" ]]; then
    local issuer_ops missing_issuer missing_keys issuer_fetch_fail issuer_parse_fail
    IFS='|' read -r issuer_ops missing_issuer missing_keys issuer_fetch_fail issuer_parse_fail < <(client_vpn_issuer_quorum_summary "$issuer_urls" "$timeout_sec")
    echo "  issuer diversity: issuer_ops=$issuer_ops missing_issuer_ids=$missing_issuer missing_key_sets=$missing_keys fetch_failures=$issuer_fetch_fail parse_failures=$issuer_parse_fail"
    if ((issuer_fetch_fail > 0)); then
      echo "  [fail] could not fetch pubkeys from all configured issuer URLs"
      fail=$((fail + 1))
    fi
    if ((issuer_parse_fail > 0)); then
      echo "  [fail] failed to parse one or more issuer pubkey payloads"
      fail=$((fail + 1))
    fi
    if ((missing_issuer > 0)); then
      echo "  [fail] issuer feed missing issuer identity"
      fail=$((fail + 1))
    fi
    if ((missing_keys > 0)); then
      echo "  [fail] issuer feed missing signing keys"
      fail=$((fail + 1))
    fi
    if ((issuer_ops < issuer_min_operators)); then
      echo "  [fail] issuer operator floor not met (need >=$issuer_min_operators distinct issuers, observed=$issuer_ops)"
      fail=$((fail + 1))
    fi
  fi

  if [[ "$prod_profile" == "1" ]]; then
    local f
    for f in "$mtls_ca_file" "$mtls_client_cert_file" "$mtls_client_key_file"; do
      if [[ -f "$f" ]]; then
        echo "  [ok] mTLS file exists: $f"
      else
        echo "  [fail] missing mTLS file: $f"
        fail=$((fail + 1))
      fi
    done
  fi

  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    if ip link show dev "$interface_name" >/dev/null 2>&1; then
      echo "  [warn] interface already exists: $interface_name (client-vpn-up will replace it)"
    fi
    local probe_iface="wgpchk$((RANDOM % 9000 + 1000))"
    if ip link add dev "$probe_iface" type wireguard >/dev/null 2>&1; then
      ip link delete "$probe_iface" >/dev/null 2>&1 || true
      echo "  [ok] wireguard interface create/delete check passed"
    else
      echo "  [fail] unable to create wireguard interface (kernel/module/capability issue)"
      fail=$((fail + 1))
    fi
  else
    if [[ "$require_root" == "1" ]]; then
      echo "  [fail] run preflight with sudo for real VPN validation"
      fail=$((fail + 1))
    else
      echo "  [warn] not running as root; skipped interface capability checks"
    fi
  fi

  if ((fail > 0)); then
    echo "client-vpn preflight: FAIL (issues=$fail)"
    return 1
  fi
  echo "client-vpn preflight: OK"
  return 0
}

write_easy_mode_config_v1_template() {
  local out_path="$1"
  cat >"$out_path" <<'EOF_CFG'
# Privacynode easy launcher config (versioned contract).
# This file is intended to be shared by launcher, daemon wrappers, and future desktop app control paths.
EASY_MODE_CONFIG_VERSION=1

# Client simple-flow defaults
SIMPLE_CLIENT_PROFILE_DEFAULT=2hop
SIMPLE_CLIENT_REAL_VPN_DEFAULT=1
SIMPLE_CLIENT_DISCOVERY_WAIT_SEC=20
SIMPLE_CLIENT_PROD_PROFILE_DEFAULT=auto
SIMPLE_CLIENT_INTERFACE=wgvpn0
SIMPLE_CLIENT_READY_TIMEOUT_SEC=35
SIMPLE_CLIENT_RUN_PREFLIGHT=1
SIMPLE_CLIENT_OPEN_TERMINAL=0
SIMPLE_CLIENT_PREFLIGHT_USE_SUDO=1
SIMPLE_CLIENT_SESSION_USE_SUDO=1
SIMPLE_CLIENT_PROMPT_REAL_VPN_IN_SIMPLE=0

# Server simple-flow defaults
SIMPLE_SERVER_PROD_PROFILE_DEFAULT=1
SIMPLE_SERVER_RUN_PREFLIGHT=1
SIMPLE_SERVER_FEDERATION_WAIT=1
SIMPLE_SERVER_FEDERATION_READY_TIMEOUT_SEC=90
SIMPLE_SERVER_FEDERATION_POLL_SEC=5
SIMPLE_SERVER_PEER_IDENTITY_STRICT=auto
SIMPLE_SERVER_PREFLIGHT_TIMEOUT_SEC=8
SIMPLE_SERVER_AUTO_INVITE=1
SIMPLE_SERVER_AUTO_INVITE_COUNT=1
SIMPLE_SERVER_AUTO_INVITE_TIER=1
SIMPLE_SERVER_AUTO_INVITE_WAIT_SEC=10
SIMPLE_SERVER_SESSION_USE_SUDO=0

# Optional automatic git fast-forward update (opt-in by default)
SIMPLE_AUTO_UPDATE=0
SIMPLE_AUTO_UPDATE_REMOTE=origin
SIMPLE_AUTO_UPDATE_BRANCH=
SIMPLE_AUTO_UPDATE_ALLOW_DIRTY=0
SIMPLE_AUTO_UPDATE_SHOW_STATUS=1
SIMPLE_AUTO_UPDATE_COMMANDS=server-up,server-session,client-test,client-vpn-up,client-vpn-session,simple-server-preflight,simple-server-session,simple-client-test,simple-client-vpn-preflight,simple-client-vpn-session
EOF_CFG
}

config_v1_init() {
  local out_path="$EASY_MODE_CONFIG_V1_FILE"
  local force="0"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --path)
        if [[ $# -lt 2 ]]; then
          echo "config-v1-init requires --path PATH"
          exit 2
        fi
        out_path="$2"
        shift 2
        ;;
      --force)
        if [[ $# -lt 2 ]]; then
          echo "config-v1-init requires --force 0 or 1"
          exit 2
        fi
        force="$2"
        shift 2
        ;;
      *)
        echo "unknown arg for config-v1-init: $1"
        exit 2
        ;;
    esac
  done
  if [[ "$force" != "0" && "$force" != "1" ]]; then
    echo "config-v1-init requires --force 0 or 1"
    exit 2
  fi
  if [[ "$out_path" != /* ]]; then
    out_path="$ROOT_DIR/$out_path"
  fi
  if [[ -f "$out_path" && "$force" != "1" ]]; then
    echo "config-v1-init: config already exists at $out_path (use --force 1 to overwrite)"
    return 0
  fi
  mkdir -p "$(dirname "$out_path")"
  write_easy_mode_config_v1_template "$out_path"
  echo "config-v1-init: wrote $out_path"
}

config_v1_show() {
  local path="$EASY_MODE_CONFIG_V1_FILE"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --path)
        if [[ $# -lt 2 ]]; then
          echo "config-v1-show requires --path PATH"
          exit 2
        fi
        path="$2"
        shift 2
        ;;
      *)
        echo "unknown arg for config-v1-show: $1"
        exit 2
        ;;
    esac
  done
  if [[ "$path" != /* ]]; then
    path="$ROOT_DIR/$path"
  fi
  if [[ ! -f "$path" ]]; then
    echo "config-v1-show: file not found: $path"
    exit 1
  fi
  echo "config_v1_path: $path"
  cat "$path"
}

upsert_key_value_file() {
  local path="$1"
  local key="$2"
  local value="$3"
  local tmp
  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { updated = 0 }
    {
      if ($0 ~ "^[[:space:]]*" key "[[:space:]]*=") {
        print key "=" value
        updated = 1
      } else {
        print $0
      }
    }
    END {
      if (!updated) {
        print key "=" value
      }
    }
  ' "$path" >"$tmp"
  mv "$tmp" "$path"
}

normalize_profile_for_config_v1() {
  local normalized
  normalized="$(normalize_path_profile "$1")" || return 1
  case "$normalized" in
    speed-1hop)
      printf '%s\n' "1hop"
      ;;
    fast|balanced|"")
      printf '%s\n' "2hop"
      ;;
    private|privacy)
      printf '%s\n' "3hop"
      ;;
    *)
      return 1
      ;;
  esac
}

config_v1_set_profile() {
  local path="$EASY_MODE_CONFIG_V1_FILE"
  local path_profile=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --path)
        if [[ $# -lt 2 ]]; then
          echo "config-v1-set-profile requires --path PATH"
          exit 2
        fi
        path="$2"
        shift 2
        ;;
      --path-profile)
        if [[ $# -lt 2 ]]; then
          echo "config-v1-set-profile requires --path-profile"
          exit 2
        fi
        path_profile="$2"
        shift 2
        ;;
      *)
        echo "unknown arg for config-v1-set-profile: $1"
        exit 2
        ;;
    esac
  done
  if [[ -z "$path_profile" ]]; then
    echo "config-v1-set-profile requires --path-profile"
    exit 2
  fi
  if [[ "$path" != /* ]]; then
    path="$ROOT_DIR/$path"
  fi
  local normalized
  normalized="$(normalize_profile_for_config_v1 "$path_profile")" || {
    echo "config-v1-set-profile requires --path-profile 1hop|2hop|3hop (aliases: speed|balanced|private)"
    exit 2
  }
  if [[ ! -f "$path" ]]; then
    mkdir -p "$(dirname "$path")"
    write_easy_mode_config_v1_template "$path"
  fi
  upsert_key_value_file "$path" "SIMPLE_CLIENT_PROFILE_DEFAULT" "$normalized"
  if [[ "$normalized" == "1hop" ]]; then
    upsert_key_value_file "$path" "SIMPLE_CLIENT_PROD_PROFILE_DEFAULT" "0"
  else
    upsert_key_value_file "$path" "SIMPLE_CLIENT_PROD_PROFILE_DEFAULT" "auto"
  fi
  echo "config-v1-set-profile: SIMPLE_CLIENT_PROFILE_DEFAULT=$normalized"
  echo "config-v1-set-profile: updated $path"
}

local_api_session_apply_config_v1_defaults() {
  local cfg_path="$1"
  if [[ -z "$cfg_path" || ! -f "$cfg_path" ]]; then
    return 0
  fi

  local path_profile_default interface_default run_preflight_default prod_profile_default normalized_profile

  path_profile_default="$(identity_value "$cfg_path" "SIMPLE_CLIENT_PROFILE_DEFAULT")"
  if [[ -z "${LOCAL_CONTROL_API_CONNECT_PATH_PROFILE:-}" && -n "$path_profile_default" ]]; then
    normalized_profile="$(normalize_profile_for_config_v1 "$path_profile_default" 2>/dev/null || true)"
    if [[ -n "$normalized_profile" ]]; then
      export LOCAL_CONTROL_API_CONNECT_PATH_PROFILE="$normalized_profile"
    fi
  fi

  interface_default="$(identity_value "$cfg_path" "SIMPLE_CLIENT_INTERFACE")"
  if [[ -z "${LOCAL_CONTROL_API_CONNECT_INTERFACE:-}" && -n "$interface_default" ]]; then
    export LOCAL_CONTROL_API_CONNECT_INTERFACE="$interface_default"
  fi

  run_preflight_default="$(identity_value "$cfg_path" "SIMPLE_CLIENT_RUN_PREFLIGHT")"
  if [[ -z "${LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT:-}" && ( "$run_preflight_default" == "0" || "$run_preflight_default" == "1" ) ]]; then
    export LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT="$run_preflight_default"
  fi

  prod_profile_default="$(identity_value "$cfg_path" "SIMPLE_CLIENT_PROD_PROFILE_DEFAULT")"
  if [[ -z "${LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT:-}" ]]; then
    case "$prod_profile_default" in
      auto|0|1)
        export LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT="$prod_profile_default"
        ;;
    esac
  fi
}

local_api_session() {
  local api_addr="${LOCAL_CONTROL_API_ADDR:-127.0.0.1:8095}"
  local node_config=""
  local config_v1_path="$EASY_MODE_CONFIG_V1_FILE"
  local script_path="${LOCAL_CONTROL_API_SCRIPT:-$ROOT_DIR/scripts/easy_node.sh}"
  local allow_update="${LOCAL_CONTROL_API_ALLOW_UPDATE:-0}"
  local command_timeout_sec="${LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC:-120}"
  local service_status_command="${LOCAL_CONTROL_API_SERVICE_STATUS_COMMAND:-}"
  local service_start_command="${LOCAL_CONTROL_API_SERVICE_START_COMMAND:-}"
  local service_stop_command="${LOCAL_CONTROL_API_SERVICE_STOP_COMMAND:-}"
  local service_restart_command="${LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND:-}"
  local connect_path_profile_default=""
  local connect_interface_default=""
  local connect_run_preflight_default=""
  local connect_prod_profile_default=""
  local dry_run="0"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --api-addr)
        if [[ $# -lt 2 ]]; then
          echo "local-api-session requires --api-addr HOST:PORT"
          exit 2
        fi
        api_addr="$2"
        shift 2
        ;;
      --config)
        if [[ $# -lt 2 ]]; then
          echo "local-api-session requires --config PATH"
          exit 2
        fi
        node_config="$2"
        shift 2
        ;;
      --config-v1-path)
        if [[ $# -lt 2 ]]; then
          echo "local-api-session requires --config-v1-path PATH"
          exit 2
        fi
        config_v1_path="$2"
        shift 2
        ;;
      --script-path)
        if [[ $# -lt 2 ]]; then
          echo "local-api-session requires --script-path PATH"
          exit 2
        fi
        script_path="$2"
        shift 2
        ;;
      --allow-update)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          allow_update="${2:-}"
          shift 2
        else
          allow_update="1"
          shift
        fi
        ;;
      --command-timeout-sec)
        if [[ $# -lt 2 ]]; then
          echo "local-api-session requires --command-timeout-sec N"
          exit 2
        fi
        command_timeout_sec="$2"
        shift 2
        ;;
      --service-status-command)
        if [[ $# -lt 2 ]]; then
          echo "local-api-session requires --service-status-command CMD"
          exit 2
        fi
        service_status_command="$2"
        shift 2
        ;;
      --service-start-command)
        if [[ $# -lt 2 ]]; then
          echo "local-api-session requires --service-start-command CMD"
          exit 2
        fi
        service_start_command="$2"
        shift 2
        ;;
      --service-stop-command)
        if [[ $# -lt 2 ]]; then
          echo "local-api-session requires --service-stop-command CMD"
          exit 2
        fi
        service_stop_command="$2"
        shift 2
        ;;
      --service-restart-command)
        if [[ $# -lt 2 ]]; then
          echo "local-api-session requires --service-restart-command CMD"
          exit 2
        fi
        service_restart_command="$2"
        shift 2
        ;;
      --connect-path-profile-default)
        if [[ $# -lt 2 ]]; then
          echo "local-api-session requires --connect-path-profile-default 1hop|2hop|3hop"
          exit 2
        fi
        connect_path_profile_default="$2"
        shift 2
        ;;
      --connect-interface-default)
        if [[ $# -lt 2 ]]; then
          echo "local-api-session requires --connect-interface-default IFACE"
          exit 2
        fi
        connect_interface_default="$2"
        shift 2
        ;;
      --connect-run-preflight-default)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          connect_run_preflight_default="${2:-}"
          shift 2
        else
          connect_run_preflight_default="1"
          shift
        fi
        ;;
      --connect-prod-profile-default)
        if [[ $# -lt 2 ]]; then
          echo "local-api-session requires --connect-prod-profile-default auto|0|1"
          exit 2
        fi
        connect_prod_profile_default="$2"
        shift 2
        ;;
      --dry-run)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          dry_run="${2:-}"
          shift 2
        else
          dry_run="1"
          shift
        fi
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for local-api-session: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$allow_update" != "0" && "$allow_update" != "1" ]]; then
    echo "local-api-session requires --allow-update to be 0 or 1"
    exit 2
  fi
  if ! [[ "$command_timeout_sec" =~ ^[0-9]+$ ]] || ((command_timeout_sec < 5)); then
    echo "local-api-session requires --command-timeout-sec >= 5"
    exit 2
  fi
  if [[ "$dry_run" != "0" && "$dry_run" != "1" ]]; then
    echo "local-api-session requires --dry-run to be 0 or 1"
    exit 2
  fi
  if [[ -z "$api_addr" ]]; then
    echo "local-api-session requires --api-addr HOST:PORT"
    exit 2
  fi

  if [[ -n "$node_config" && "$node_config" != /* ]]; then
    node_config="$ROOT_DIR/$node_config"
  fi
  if [[ -n "$config_v1_path" && "$config_v1_path" != /* ]]; then
    config_v1_path="$ROOT_DIR/$config_v1_path"
  fi
  if [[ -n "$script_path" && "$script_path" != /* ]]; then
    script_path="$ROOT_DIR/$script_path"
  fi

  if [[ -n "$connect_path_profile_default" ]]; then
    connect_path_profile_default="$(normalize_profile_for_config_v1 "$connect_path_profile_default" 2>/dev/null || true)"
    if [[ -z "$connect_path_profile_default" ]]; then
      echo "local-api-session requires --connect-path-profile-default 1hop|2hop|3hop"
      exit 2
    fi
  fi
  if [[ -n "$connect_run_preflight_default" && "$connect_run_preflight_default" != "0" && "$connect_run_preflight_default" != "1" ]]; then
    echo "local-api-session requires --connect-run-preflight-default to be 0 or 1"
    exit 2
  fi
  if [[ -n "$connect_prod_profile_default" ]]; then
    case "$connect_prod_profile_default" in
      auto|0|1)
        ;;
      *)
        echo "local-api-session requires --connect-prod-profile-default auto|0|1"
        exit 2
        ;;
    esac
  fi

  export LOCAL_CONTROL_API_ADDR="$api_addr"
  export LOCAL_CONTROL_API_SCRIPT="$script_path"
  export LOCAL_CONTROL_API_ALLOW_UPDATE="$allow_update"
  export LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC="$command_timeout_sec"
  export LOCAL_CONTROL_API_SERVICE_STATUS_COMMAND="$service_status_command"
  export LOCAL_CONTROL_API_SERVICE_START_COMMAND="$service_start_command"
  export LOCAL_CONTROL_API_SERVICE_STOP_COMMAND="$service_stop_command"
  export LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND="$service_restart_command"
  export EASY_NODE_CONFIG_V1_FILE="$config_v1_path"

  local_api_session_apply_config_v1_defaults "$config_v1_path"
  if [[ -n "$connect_path_profile_default" ]]; then
    export LOCAL_CONTROL_API_CONNECT_PATH_PROFILE="$connect_path_profile_default"
  fi
  if [[ -n "$connect_interface_default" ]]; then
    export LOCAL_CONTROL_API_CONNECT_INTERFACE="$connect_interface_default"
  fi
  if [[ -n "$connect_run_preflight_default" ]]; then
    export LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT="$connect_run_preflight_default"
  fi
  if [[ -n "$connect_prod_profile_default" ]]; then
    export LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT="$connect_prod_profile_default"
  fi

  local config_v1_status="missing"
  if [[ -n "$config_v1_path" && -f "$config_v1_path" ]]; then
    config_v1_status="present"
  fi

  local -a cmd
  cmd=(go run ./cmd/node)
  if [[ -n "$node_config" ]]; then
    cmd+=(--config "$node_config")
  fi
  cmd+=(--local-api)

  local cmd_preview=""
  printf -v cmd_preview '%q ' "${cmd[@]}"
  cmd_preview="${cmd_preview% }"

  echo "local-api-session:"
  echo "  api_addr: $LOCAL_CONTROL_API_ADDR"
  echo "  script_path: $LOCAL_CONTROL_API_SCRIPT"
  echo "  config_v1_path: ${config_v1_path:-none} (${config_v1_status})"
  echo "  command_timeout_sec: $LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC"
  echo "  allow_update: $LOCAL_CONTROL_API_ALLOW_UPDATE"
  echo "  service_status_command: ${LOCAL_CONTROL_API_SERVICE_STATUS_COMMAND:-none}"
  echo "  service_start_command: ${LOCAL_CONTROL_API_SERVICE_START_COMMAND:-none}"
  echo "  service_stop_command: ${LOCAL_CONTROL_API_SERVICE_STOP_COMMAND:-none}"
  echo "  service_restart_command: ${LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND:-none}"
  echo "  connect_path_profile_default: ${LOCAL_CONTROL_API_CONNECT_PATH_PROFILE:-2hop}"
  echo "  connect_interface_default: ${LOCAL_CONTROL_API_CONNECT_INTERFACE:-wgvpn0}"
  echo "  connect_run_preflight_default: ${LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT:-1}"
  echo "  connect_prod_profile_default: ${LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT:-0}"
  echo "  command: $cmd_preview"

  if [[ "$dry_run" == "1" ]]; then
    echo "local-api-session dry-run: command not executed"
    return 0
  fi

  if ! command -v go >/dev/null 2>&1; then
    echo "local-api-session requires go in PATH"
    exit 2
  fi
  if [[ -n "$script_path" && ! -f "$script_path" ]]; then
    echo "local-api-session script path not found: $script_path"
    exit 1
  fi

  (
    cd "$ROOT_DIR"
    "${cmd[@]}"
  )
}

client_vpn_state_file() {
  echo "$DEPLOY_DIR/data/client_vpn.state"
}

client_vpn_smoke() {
  local smoke_script="${CLIENT_VPN_SMOKE_SCRIPT:-$ROOT_DIR/scripts/client_vpn_smoke.sh}"
  "$smoke_script" "$@"
}

client_vpn_status() {
  local show_json="0"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --show-json)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          show_json="${2:-}"
          shift 2
        else
          show_json="1"
          shift
        fi
        ;;
      *)
        echo "unknown arg for client-vpn-status: $1"
        exit 2
        ;;
    esac
  done

  local state_file
  state_file="$(client_vpn_state_file)"
  if [[ ! -f "$state_file" ]]; then
    if [[ "$show_json" == "1" ]]; then
      echo '{"running":false,"reason":"no_state_file"}'
      return 0
    fi
    echo "client-vpn is not running (no state file)"
    return 0
  fi

  local pid iface log_file key_file trust_file trust_scope proxy_addr directory_urls issuer_url issuer_urls entry_url exit_url subject path_profile prod_profile beta_profile session_reuse allow_session_churn
  pid="$(identity_value "$state_file" "CLIENT_VPN_PID")"
  iface="$(identity_value "$state_file" "CLIENT_VPN_IFACE")"
  log_file="$(identity_value "$state_file" "CLIENT_VPN_LOG_FILE")"
  key_file="$(identity_value "$state_file" "CLIENT_VPN_KEY_FILE")"
  trust_file="$(identity_value "$state_file" "CLIENT_VPN_TRUST_FILE")"
  trust_scope="$(identity_value "$state_file" "CLIENT_VPN_TRUST_SCOPE")"
  proxy_addr="$(identity_value "$state_file" "CLIENT_VPN_PROXY_ADDR")"
  directory_urls="$(identity_value "$state_file" "CLIENT_VPN_DIRECTORY_URLS")"
  issuer_url="$(identity_value "$state_file" "CLIENT_VPN_ISSUER_URL")"
  issuer_urls="$(identity_value "$state_file" "CLIENT_VPN_ISSUER_URLS")"
  entry_url="$(identity_value "$state_file" "CLIENT_VPN_ENTRY_URL")"
  exit_url="$(identity_value "$state_file" "CLIENT_VPN_EXIT_URL")"
  subject="$(identity_value "$state_file" "CLIENT_VPN_SUBJECT")"
  path_profile="$(identity_value "$state_file" "CLIENT_VPN_PATH_PROFILE")"
  session_reuse="$(identity_value "$state_file" "CLIENT_VPN_SESSION_REUSE")"
  allow_session_churn="$(identity_value "$state_file" "CLIENT_VPN_ALLOW_SESSION_CHURN")"
  prod_profile="$(identity_value "$state_file" "CLIENT_VPN_PROD_PROFILE")"
  beta_profile="$(identity_value "$state_file" "CLIENT_VPN_BETA_PROFILE")"

  local running="no"
  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    running="yes"
  fi

  local interface_state="missing"
  if [[ -n "$iface" ]] && ip link show dev "$iface" >/dev/null 2>&1; then
    interface_state="present"
  fi

  if [[ "$show_json" == "1" ]]; then
    if command -v jq >/dev/null 2>&1; then
      jq -n \
        --arg running "$running" \
        --arg pid "${pid:-}" \
        --arg interface "${iface:-}" \
        --arg interface_state "$interface_state" \
        --arg proxy_addr "${proxy_addr:-}" \
        --arg subject "${subject:-}" \
        --arg path_profile "${path_profile:-}" \
        --arg session_reuse "${session_reuse:-}" \
        --arg allow_session_churn "${allow_session_churn:-}" \
        --arg beta_profile "${beta_profile:-}" \
        --arg prod_profile "${prod_profile:-}" \
        --arg directory_urls "${directory_urls:-}" \
        --arg issuer_url "${issuer_url:-}" \
        --arg issuer_urls "${issuer_urls:-}" \
        --arg entry_url "${entry_url:-}" \
        --arg exit_url "${exit_url:-}" \
        --arg key_file "${key_file:-}" \
        --arg trust_file "${trust_file:-}" \
        --arg trust_scope "${trust_scope:-}" \
        --arg log_file "${log_file:-}" \
        '{
          running: ($running == "yes"),
          pid: $pid,
          interface: $interface,
          interface_state: $interface_state,
          proxy_addr: $proxy_addr,
          subject: $subject,
          path_profile: $path_profile,
          session_reuse: $session_reuse,
          allow_session_churn: $allow_session_churn,
          beta_profile: $beta_profile,
          prod_profile: $prod_profile,
          directory_urls: $directory_urls,
          issuer_url: $issuer_url,
          issuer_urls: $issuer_urls,
          entry_url: $entry_url,
          exit_url: $exit_url,
          key_file: $key_file,
          trust_file: $trust_file,
          trust_scope: $trust_scope,
          log_file: $log_file
        }'
    else
      printf '{"running":%s,"pid":"%s","interface":"%s","interface_state":"%s","subject":"%s","path_profile":"%s"}\n' \
        "$([[ "$running" == "yes" ]] && printf 'true' || printf 'false')" \
        "${pid:-}" \
        "${iface:-}" \
        "$interface_state" \
        "${subject:-}" \
        "${path_profile:-}"
    fi
    return 0
  fi

  echo "client-vpn status:"
  echo "  running: $running"
  echo "  pid: ${pid:-unknown}"
  echo "  interface: ${iface:-unknown}"
  echo "  proxy_addr: ${proxy_addr:-unknown}"
  echo "  subject: ${subject:-none}"
  echo "  path_profile: ${path_profile:-default}"
  echo "  session_reuse: ${session_reuse:-unknown}"
  echo "  allow_session_churn: ${allow_session_churn:-unknown}"
  echo "  beta_profile: ${beta_profile:-0}"
  echo "  prod_profile: ${prod_profile:-0}"
  echo "  directory_urls: ${directory_urls:-unknown}"
  echo "  issuer_url: ${issuer_url:-unknown}"
  echo "  issuer_urls: ${issuer_urls:-unknown}"
  echo "  entry_url: ${entry_url:-unknown}"
  echo "  exit_url: ${exit_url:-unknown}"
  echo "  key_file: ${key_file:-unknown}"
  echo "  trust_file: ${trust_file:-unknown}"
  echo "  trust_scope: ${trust_scope:-unknown}"
  echo "  log_file: ${log_file:-unknown}"

  if [[ -n "$iface" ]]; then
    if [[ "$interface_state" == "present" ]]; then
      echo "  interface_state: present"
      ip -brief address show dev "$iface" 2>/dev/null || true
      wg show "$iface" 2>/dev/null || true
    else
      echo "  interface_state: missing"
    fi
  fi

  if [[ -n "$log_file" && -f "$log_file" ]]; then
    echo "  recent log lines:"
    tail -n 15 "$log_file" || true
  fi
}

client_vpn_logs() {
  local follow="0"
  local tail_lines="120"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --follow)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          follow="${2:-}"
          shift 2
        else
          follow="1"
          shift
        fi
        ;;
      --tail)
        if [[ $# -lt 2 ]]; then
          echo "client-vpn-logs requires --tail N"
          exit 2
        fi
        tail_lines="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for client-vpn-logs: $1"
        exit 2
        ;;
    esac
  done
  if [[ "$follow" != "0" && "$follow" != "1" ]]; then
    echo "client-vpn-logs requires --follow to be 0 or 1"
    exit 2
  fi
  if ! [[ "$tail_lines" =~ ^[0-9]+$ ]] || ((tail_lines < 1)); then
    echo "client-vpn-logs requires --tail to be >= 1"
    exit 2
  fi

  local state_file log_file
  state_file="$(client_vpn_state_file)"
  if [[ ! -f "$state_file" ]]; then
    echo "client-vpn-logs: no active state file: $state_file"
    exit 1
  fi
  log_file="$(identity_value "$state_file" "CLIENT_VPN_LOG_FILE")"
  if [[ -z "$log_file" ]]; then
    echo "client-vpn-logs: missing CLIENT_VPN_LOG_FILE in state file"
    exit 1
  fi
  if [[ ! -f "$log_file" ]]; then
    echo "client-vpn-logs: log file does not exist: $log_file"
    exit 1
  fi

  if [[ "$follow" == "1" ]]; then
    tail -n "$tail_lines" -F "$log_file"
  else
    tail -n "$tail_lines" "$log_file"
  fi
}

client_vpn_down() {
  local force_iface_cleanup="1"
  local iface_override=""
  local keep_key="1"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force-iface-cleanup)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          force_iface_cleanup="${2:-}"
          shift 2
        else
          force_iface_cleanup="1"
          shift
        fi
        ;;
      --iface)
        iface_override="${2:-}"
        shift 2
        ;;
      --keep-key)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          keep_key="${2:-}"
          shift 2
        else
          keep_key="1"
          shift
        fi
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for client-vpn-down: $1"
        exit 2
        ;;
    esac
  done
  if [[ "$force_iface_cleanup" != "0" && "$force_iface_cleanup" != "1" ]]; then
    echo "client-vpn-down requires --force-iface-cleanup 0 or 1"
    exit 2
  fi
  if [[ "$keep_key" != "0" && "$keep_key" != "1" ]]; then
    echo "client-vpn-down requires --keep-key 0 or 1"
    exit 2
  fi

  local state_file
  state_file="$(client_vpn_state_file)"
  local pid="" iface="" key_file=""
  if [[ -f "$state_file" ]]; then
    pid="$(identity_value "$state_file" "CLIENT_VPN_PID")"
    iface="$(identity_value "$state_file" "CLIENT_VPN_IFACE")"
    key_file="$(identity_value "$state_file" "CLIENT_VPN_KEY_FILE")"
  fi
  if [[ -n "$iface_override" ]]; then
    iface="$iface_override"
  fi

  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    local i
    for i in $(seq 1 20); do
      if ! kill -0 "$pid" >/dev/null 2>&1; then
        break
      fi
      sleep 0.2
    done
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
    echo "client-vpn process stopped (pid=$pid)"
  fi

  if [[ "$force_iface_cleanup" == "1" && -n "$iface" ]]; then
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      echo "client-vpn interface cleanup requires root: sudo ./scripts/easy_node.sh client-vpn-down --iface $iface"
    else
      ip link delete "$iface" >/dev/null 2>&1 || true
      echo "client-vpn interface cleaned: $iface"
    fi
  fi

  if [[ -f "$state_file" ]]; then
    rm -f "$state_file"
  fi
  if [[ "$keep_key" == "0" && -n "$key_file" && -f "$key_file" ]]; then
    rm -f "$key_file"
  fi
  echo "client-vpn state cleared"
}

client_vpn_trust_reset() {
  local directory_urls=""
  local bootstrap_directory=""
  local discovery_wait_sec="${EASY_NODE_DISCOVERY_WAIT_SEC:-20}"
  local trust_scope_arg=""
  local all_scoped="0"
  local dry_run="0"
  local trust_file_override=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --directory-urls)
        directory_urls="${2:-}"
        shift 2
        ;;
      --bootstrap-directory)
        bootstrap_directory="${2:-}"
        shift 2
        ;;
      --discovery-wait-sec)
        discovery_wait_sec="${2:-}"
        shift 2
        ;;
      --trust-scope)
        trust_scope_arg="${2:-}"
        shift 2
        ;;
      --all-scoped)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          all_scoped="${2:-}"
          shift 2
        else
          all_scoped="1"
          shift
        fi
        ;;
      --dry-run)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          dry_run="${2:-}"
          shift 2
        else
          dry_run="1"
          shift
        fi
        ;;
      --trust-file)
        trust_file_override="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for client-vpn-trust-reset: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$all_scoped" != "0" && "$all_scoped" != "1" ]]; then
    echo "client-vpn-trust-reset requires --all-scoped 0 or 1"
    exit 2
  fi
  if [[ "$dry_run" != "0" && "$dry_run" != "1" ]]; then
    echo "client-vpn-trust-reset requires --dry-run 0 or 1"
    exit 2
  fi
  if ! [[ "$discovery_wait_sec" =~ ^[0-9]+$ ]]; then
    echo "client-vpn-trust-reset requires --discovery-wait-sec to be numeric"
    exit 2
  fi

  local state_file state_scope trust_scope_source trust_scope_mode
  state_file="$(client_vpn_state_file)"
  state_scope="$(identity_value "$state_file" "CLIENT_VPN_TRUST_SCOPE")"
  if [[ -n "$trust_scope_arg" ]]; then
    trust_scope_source="$trust_scope_arg"
  elif [[ -n "${EASY_NODE_CLIENT_VPN_TRUST_SCOPE:-}" ]]; then
    trust_scope_source="${EASY_NODE_CLIENT_VPN_TRUST_SCOPE:-}"
  elif [[ -n "$state_scope" ]]; then
    trust_scope_source="$state_scope"
  else
    trust_scope_source="scoped"
  fi
  trust_scope_mode="$(normalize_client_vpn_trust_scope_mode "$trust_scope_source" 2>/dev/null || true)"
  if [[ -z "$trust_scope_mode" ]]; then
    echo "client-vpn-trust-reset requires --trust-scope (or EASY_NODE_CLIENT_VPN_TRUST_SCOPE) to be one of: scoped, global"
    exit 2
  fi

  if [[ -n "$bootstrap_directory" && -z "$directory_urls" ]]; then
    directory_urls="$(discover_directory_urls "$bootstrap_directory" "$discovery_wait_sec" 1)"
  fi
  if [[ -z "$directory_urls" ]]; then
    directory_urls="$(identity_value "$state_file" "CLIENT_VPN_DIRECTORY_URLS")"
  fi

  local key_dir
  key_dir="$(default_client_vpn_key_dir)"
  mkdir -p "$key_dir" >/dev/null 2>&1 || true

  local -a requested_files=()
  if [[ -n "$trust_file_override" ]]; then
    requested_files+=("$trust_file_override")
  elif [[ -n "${DIRECTORY_TRUSTED_KEYS_FILE:-}" ]]; then
    requested_files+=("${DIRECTORY_TRUSTED_KEYS_FILE}")
  elif [[ "$all_scoped" == "1" ]]; then
    local scoped_file
    while IFS= read -r -d '' scoped_file; do
      requested_files+=("$scoped_file")
    done < <(find "$key_dir" -maxdepth 1 -type f -name 'trusted_directory_keys_*.txt' -print0 2>/dev/null || true)
  elif [[ "$trust_scope_mode" == "global" ]]; then
    requested_files+=("$(default_client_vpn_trust_file)")
  elif [[ -n "$directory_urls" ]]; then
    requested_files+=("$(default_client_vpn_trust_file_for_directory_urls "$directory_urls" "$trust_scope_mode")")
  else
    local state_trust_file
    state_trust_file="$(identity_value "$state_file" "CLIENT_VPN_TRUST_FILE")"
    if [[ -n "$state_trust_file" ]]; then
      requested_files+=("$state_trust_file")
    fi
  fi

  local -a target_files=()
  local file abs_file
  declare -A seen_files=()
  for file in "${requested_files[@]}"; do
    [[ -z "$file" ]] && continue
    if [[ "$file" == /* ]]; then
      abs_file="$file"
    else
      abs_file="$ROOT_DIR/$file"
    fi
    if [[ -n "${seen_files[$abs_file]:-}" ]]; then
      continue
    fi
    seen_files["$abs_file"]=1
    target_files+=("$abs_file")
  done

  if ((${#target_files[@]} == 0)); then
    if [[ "$all_scoped" == "1" ]]; then
      echo "client-vpn trust reset: no scoped trust files found under $key_dir"
      return 0
    fi
    echo "client-vpn-trust-reset could not resolve a trust file target."
    echo "provide --directory-urls, --trust-file, set DIRECTORY_TRUSTED_KEYS_FILE, or ensure client-vpn state exists."
    exit 1
  fi

  local active_pid active_trust_file active_running
  active_pid="$(identity_value "$state_file" "CLIENT_VPN_PID")"
  active_trust_file="$(identity_value "$state_file" "CLIENT_VPN_TRUST_FILE")"
  active_running="0"
  if [[ -n "$active_pid" ]] && kill -0 "$active_pid" >/dev/null 2>&1; then
    active_running="1"
  fi
  if [[ -n "$active_trust_file" && "$active_trust_file" != /* ]]; then
    active_trust_file="$ROOT_DIR/$active_trust_file"
  fi

  echo "client-vpn trust reset:"
  echo "  trust_scope: $trust_scope_mode"
  echo "  directory_urls: ${directory_urls:-none}"
  echo "  all_scoped: $all_scoped"
  echo "  dry_run: $dry_run"
  echo "  key_dir: $key_dir"
  echo "  targeted_files: ${#target_files[@]}"

  local removed_count=0
  local missing_count=0
  for file in "${target_files[@]}"; do
    echo "target_file: $file"
    if [[ "$active_running" == "1" && "$file" == "$active_trust_file" ]]; then
      echo "warn: client-vpn appears to be running (pid=$active_pid) and this is its active trust file."
    fi
    if [[ -f "$file" ]]; then
      if [[ "$dry_run" == "1" ]]; then
        echo "would_remove_file: $file"
      else
        rm -f "$file"
        echo "removed_file: $file"
      fi
      removed_count=$((removed_count + 1))
    else
      echo "missing_file: $file"
      missing_count=$((missing_count + 1))
    fi
  done

  echo "client-vpn trust reset summary:"
  if [[ "$dry_run" == "1" ]]; then
    echo "  would_remove: $removed_count"
  else
    echo "  removed: $removed_count"
  fi
  echo "  missing: $missing_count"
}

client_vpn_session() {
  local cleanup_all="1"
  local -a forward_args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help|help)
        usage || true
        return 0
        ;;
      --cleanup-all)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          cleanup_all="${2:-}"
          shift 2
        else
          cleanup_all="1"
          shift
        fi
        ;;
      --foreground)
        # Session mode enforces background client plus log follow in this terminal.
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          shift 2
        else
          shift
        fi
        ;;
      *)
        forward_args+=("$1")
        shift
        ;;
    esac
  done

  if [[ "$cleanup_all" != "0" && "$cleanup_all" != "1" ]]; then
    echo "client-vpn-session requires --cleanup-all to be 0 or 1"
    exit 2
  fi

  local cleanup_ran="0"
  cleanup_client_vpn_session() {
    if [[ "$cleanup_ran" == "1" ]]; then
      return
    fi
    cleanup_ran="1"
    echo "client-vpn-session cleanup: client-vpn-down"
    client_vpn_down --force-iface-cleanup 1 --keep-key 1 || true
    if [[ "$cleanup_all" == "1" ]]; then
      echo "client-vpn-session cleanup: stop-all"
      stop_all --with-wg-only 1 --force-iface-cleanup 1 || true
    fi
  }
  trap cleanup_client_vpn_session EXIT INT TERM

  client_vpn_up "${forward_args[@]}" --foreground 0
  echo "client-vpn-session: streaming live logs (Ctrl+C or close terminal to cleanup)"
  client_vpn_logs --follow 1 --tail 120
}

simple_wrapper_normalize_host() {
  local raw="$1"
  raw="$(trim "$raw")"
  if [[ -z "$raw" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$raw" == http://* || "$raw" == https://* ]]; then
    printf '%s' "$(host_from_url "$raw")"
    return
  fi
  printf '%s' "$(host_from_hostport "$raw")"
}

simple_client_test() {
  local bootstrap_directory=""
  local discovery_wait_sec="${EASY_NODE_DISCOVERY_WAIT_SEC:-20}"
  local client_subject=""
  local client_anon_cred=""
  local path_profile="${EASY_NODE_PATH_PROFILE:-2hop}"
  local timeout_sec="45"
  local beta_profile="${EASY_NODE_BETA_PROFILE:-1}"
  local prod_profile="${EASY_NODE_PROD_PROFILE:-0}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bootstrap-directory)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-test requires --bootstrap-directory URL"
          exit 2
        fi
        bootstrap_directory="$2"
        shift 2
        ;;
      --discovery-wait-sec)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-test requires --discovery-wait-sec N"
          exit 2
        fi
        discovery_wait_sec="$2"
        shift 2
        ;;
      --subject)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-test requires --subject ID"
          exit 2
        fi
        client_subject="$2"
        shift 2
        ;;
      --anon-cred)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-test requires --anon-cred TOKEN"
          exit 2
        fi
        client_anon_cred="$2"
        shift 2
        ;;
      --path-profile)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-test requires --path-profile 1hop|2hop|3hop"
          exit 2
        fi
        path_profile="$2"
        shift 2
        ;;
      --timeout-sec)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-test requires --timeout-sec N"
          exit 2
        fi
        timeout_sec="$2"
        shift 2
        ;;
      --beta-profile)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-test requires --beta-profile 0 or 1"
          exit 2
        fi
        beta_profile="$2"
        shift 2
        ;;
      --prod-profile)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-test requires --prod-profile 0 or 1"
          exit 2
        fi
        prod_profile="$2"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for simple-client-test: $1"
        exit 2
        ;;
    esac
  done

  if [[ -z "$bootstrap_directory" ]]; then
    echo "simple-client-test requires --bootstrap-directory URL"
    exit 2
  fi
  if [[ -n "$client_subject" && -n "$client_anon_cred" ]]; then
    echo "simple-client-test requires exactly one of --subject or --anon-cred"
    exit 2
  fi
  if [[ -z "$client_subject" && -z "$client_anon_cred" ]]; then
    echo "simple-client-test requires --subject or --anon-cred"
    exit 2
  fi
  if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
    echo "simple-client-test requires --beta-profile 0 or 1"
    exit 2
  fi
  if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
    echo "simple-client-test requires --prod-profile 0 or 1"
    exit 2
  fi
  if ! [[ "$discovery_wait_sec" =~ ^[0-9]+$ && "$timeout_sec" =~ ^[0-9]+$ ]]; then
    echo "simple-client-test requires numeric --discovery-wait-sec and --timeout-sec"
    exit 2
  fi

  local normalized_path_profile=""
  normalized_path_profile="$(normalize_path_profile "$path_profile")" || {
    echo "simple-client-test requires --path-profile 1hop|2hop|3hop (aliases: speed|balanced|private)"
    exit 2
  }
  if [[ "$normalized_path_profile" == "speed-1hop" && ( "$beta_profile" == "1" || "$prod_profile" == "1" ) ]]; then
    echo "simple-client-test: 1-hop profile is non-strict only; forcing --beta-profile 0 and --prod-profile 0"
    beta_profile="0"
    prod_profile="0"
  fi

  local -a args=(
    --bootstrap-directory "$bootstrap_directory"
    --discovery-wait-sec "$discovery_wait_sec"
    --min-sources 1
    --timeout-sec "$timeout_sec"
    --path-profile "$path_profile"
    --beta-profile "$beta_profile"
    --prod-profile "$prod_profile"
  )
  if [[ -n "$client_subject" ]]; then
    args+=(--subject "$client_subject")
  else
    args+=(--anon-cred "$client_anon_cred")
  fi

  client_test "${args[@]}"
}

simple_client_vpn_preflight() {
  local bootstrap_directory=""
  local discovery_wait_sec="${EASY_NODE_DISCOVERY_WAIT_SEC:-20}"
  local path_profile="${EASY_NODE_PATH_PROFILE:-2hop}"
  local prod_profile="${EASY_NODE_PROD_PROFILE:-1}"
  local interface_name="${CLIENT_WG_INTERFACE:-wgvpn0}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bootstrap-directory)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-preflight requires --bootstrap-directory URL"
          exit 2
        fi
        bootstrap_directory="$2"
        shift 2
        ;;
      --discovery-wait-sec)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-preflight requires --discovery-wait-sec N"
          exit 2
        fi
        discovery_wait_sec="$2"
        shift 2
        ;;
      --path-profile)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-preflight requires --path-profile 1hop|2hop|3hop"
          exit 2
        fi
        path_profile="$2"
        shift 2
        ;;
      --prod-profile)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-preflight requires --prod-profile 0 or 1"
          exit 2
        fi
        prod_profile="$2"
        shift 2
        ;;
      --interface)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-preflight requires --interface IFACE"
          exit 2
        fi
        interface_name="$2"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for simple-client-vpn-preflight: $1"
        exit 2
        ;;
    esac
  done

  if [[ -z "$bootstrap_directory" ]]; then
    echo "simple-client-vpn-preflight requires --bootstrap-directory URL"
    exit 2
  fi
  if [[ -z "$interface_name" ]]; then
    echo "simple-client-vpn-preflight requires --interface IFACE"
    exit 2
  fi
  if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
    echo "simple-client-vpn-preflight requires --prod-profile 0 or 1"
    exit 2
  fi
  if ! [[ "$discovery_wait_sec" =~ ^[0-9]+$ ]]; then
    echo "simple-client-vpn-preflight requires numeric --discovery-wait-sec"
    exit 2
  fi

  local normalized_path_profile=""
  normalized_path_profile="$(normalize_path_profile "$path_profile")" || {
    echo "simple-client-vpn-preflight requires --path-profile 1hop|2hop|3hop (aliases: speed|balanced|private)"
    exit 2
  }

  local operator_floor_check="1"
  local operator_min_operators="2"
  local issuer_quorum_check="1"
  local issuer_min_operators="2"
  if [[ "$normalized_path_profile" == "speed-1hop" ]]; then
    operator_floor_check="0"
    operator_min_operators="1"
    issuer_quorum_check="0"
    issuer_min_operators="1"
  fi

  client_vpn_preflight \
    --bootstrap-directory "$bootstrap_directory" \
    --discovery-wait-sec "$discovery_wait_sec" \
    --path-profile "$path_profile" \
    --prod-profile "$prod_profile" \
    --interface "$interface_name" \
    --operator-floor-check "$operator_floor_check" \
    --operator-min-operators "$operator_min_operators" \
    --issuer-quorum-check "$issuer_quorum_check" \
    --issuer-min-operators "$issuer_min_operators"
}

simple_client_vpn_session() {
  local bootstrap_directory=""
  local discovery_wait_sec="${EASY_NODE_DISCOVERY_WAIT_SEC:-20}"
  local client_subject=""
  local path_profile="${EASY_NODE_PATH_PROFILE:-2hop}"
  local beta_profile="${EASY_NODE_BETA_PROFILE:-1}"
  local prod_profile="${EASY_NODE_PROD_PROFILE:-1}"
  local interface_name="${CLIENT_WG_INTERFACE:-wgvpn0}"
  local ready_timeout_sec="${EASY_NODE_CLIENT_VPN_READY_TIMEOUT_SEC:-35}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bootstrap-directory)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-session requires --bootstrap-directory URL"
          exit 2
        fi
        bootstrap_directory="$2"
        shift 2
        ;;
      --discovery-wait-sec)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-session requires --discovery-wait-sec N"
          exit 2
        fi
        discovery_wait_sec="$2"
        shift 2
        ;;
      --subject)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-session requires --subject ID"
          exit 2
        fi
        client_subject="$2"
        shift 2
        ;;
      --path-profile)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-session requires --path-profile 1hop|2hop|3hop"
          exit 2
        fi
        path_profile="$2"
        shift 2
        ;;
      --beta-profile)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-session requires --beta-profile 0 or 1"
          exit 2
        fi
        beta_profile="$2"
        shift 2
        ;;
      --prod-profile)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-session requires --prod-profile 0 or 1"
          exit 2
        fi
        prod_profile="$2"
        shift 2
        ;;
      --interface)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-session requires --interface IFACE"
          exit 2
        fi
        interface_name="$2"
        shift 2
        ;;
      --ready-timeout-sec)
        if [[ $# -lt 2 ]]; then
          echo "simple-client-vpn-session requires --ready-timeout-sec N"
          exit 2
        fi
        ready_timeout_sec="$2"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for simple-client-vpn-session: $1"
        exit 2
        ;;
    esac
  done

  if [[ -z "$bootstrap_directory" ]]; then
    echo "simple-client-vpn-session requires --bootstrap-directory URL"
    exit 2
  fi
  if [[ -z "$client_subject" ]]; then
    echo "simple-client-vpn-session requires --subject ID"
    exit 2
  fi
  if [[ -z "$interface_name" ]]; then
    echo "simple-client-vpn-session requires --interface IFACE"
    exit 2
  fi
  if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
    echo "simple-client-vpn-session requires --beta-profile 0 or 1"
    exit 2
  fi
  if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
    echo "simple-client-vpn-session requires --prod-profile 0 or 1"
    exit 2
  fi
  if ! [[ "$discovery_wait_sec" =~ ^[0-9]+$ && "$ready_timeout_sec" =~ ^[0-9]+$ ]]; then
    echo "simple-client-vpn-session requires numeric --discovery-wait-sec and --ready-timeout-sec"
    exit 2
  fi

  local normalized_path_profile=""
  normalized_path_profile="$(normalize_path_profile "$path_profile")" || {
    echo "simple-client-vpn-session requires --path-profile 1hop|2hop|3hop (aliases: speed|balanced|private)"
    exit 2
  }

  local min_operators="2"
  local operator_floor_check="1"
  local operator_min_operators="2"
  local issuer_quorum_check="1"
  local issuer_min_operators="2"
  local install_route="1"
  if [[ "$normalized_path_profile" == "speed-1hop" ]]; then
    min_operators="1"
    operator_floor_check="0"
    operator_min_operators="1"
    issuer_quorum_check="0"
    issuer_min_operators="1"
    install_route="0"
    echo "1-hop quick mode: forcing --install-route 0 for stable control-plane connectivity."
    echo "Use expert option 34 if you want to override route behavior manually."
  fi

  client_vpn_session \
    --bootstrap-directory "$bootstrap_directory" \
    --discovery-wait-sec "$discovery_wait_sec" \
    --subject "$client_subject" \
    --min-sources 1 \
    --min-operators "$min_operators" \
    --operator-floor-check "$operator_floor_check" \
    --operator-min-operators "$operator_min_operators" \
    --path-profile "$path_profile" \
    --beta-profile "$beta_profile" \
    --prod-profile "$prod_profile" \
    --issuer-quorum-check "$issuer_quorum_check" \
    --issuer-min-operators "$issuer_min_operators" \
    --interface "$interface_name" \
    --ready-timeout-sec "$ready_timeout_sec" \
    --install-route "$install_route" \
    --cleanup-all 1
}

simple_server_preflight() {
  local mode="authority"
  local public_host=""
  local peer_host=""
  local prod_profile="${EASY_NODE_PROD_PROFILE:-1}"
  local peer_identity_strict="${EASY_NODE_PEER_IDENTITY_STRICT:-auto}"
  local timeout_sec="${EASY_NODE_SERVER_PREFLIGHT_TIMEOUT_SEC:-8}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-preflight requires --mode authority|provider"
          exit 2
        fi
        mode="$2"
        shift 2
        ;;
      --public-host)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-preflight requires --public-host HOST"
          exit 2
        fi
        public_host="$2"
        shift 2
        ;;
      --peer-host)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-preflight requires --peer-host HOST"
          exit 2
        fi
        peer_host="$2"
        shift 2
        ;;
      --prod-profile)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-preflight requires --prod-profile 0 or 1"
          exit 2
        fi
        prod_profile="$2"
        shift 2
        ;;
      --peer-identity-strict)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-preflight requires --peer-identity-strict 0|1|auto"
          exit 2
        fi
        peer_identity_strict="$2"
        shift 2
        ;;
      --timeout-sec)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-preflight requires --timeout-sec N"
          exit 2
        fi
        timeout_sec="$2"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for simple-server-preflight: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$mode" != "authority" && "$mode" != "provider" ]]; then
    echo "simple-server-preflight requires --mode authority|provider"
    exit 2
  fi
  if [[ -z "$public_host" ]]; then
    echo "simple-server-preflight requires --public-host HOST"
    exit 2
  fi
  if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
    echo "simple-server-preflight requires --prod-profile 0 or 1"
    exit 2
  fi
  if [[ "$peer_identity_strict" != "0" && "$peer_identity_strict" != "1" && "$peer_identity_strict" != "auto" ]]; then
    echo "simple-server-preflight requires --peer-identity-strict 0|1|auto"
    exit 2
  fi
  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]]; then
    echo "simple-server-preflight requires numeric --timeout-sec"
    exit 2
  fi

  public_host="$(simple_wrapper_normalize_host "$public_host")"
  peer_host="$(simple_wrapper_normalize_host "$peer_host")"

  local peer_directories=""
  local authority_directory=""
  local authority_issuer=""
  if [[ "$mode" == "provider" ]]; then
    if [[ -z "$peer_host" ]]; then
      echo "simple-server-preflight requires --peer-host when --mode provider"
      exit 2
    fi
    authority_directory="$(url_from_host_port "$peer_host" 8081)"
    authority_issuer="$(url_from_host_port "$peer_host" 8082)"
    peer_directories="$authority_directory"
  elif [[ -n "$peer_host" ]]; then
    peer_directories="$(url_from_host_port "$peer_host" 8081)"
  fi

  local min_peer_operators="0"
  if [[ -n "$peer_directories" ]]; then
    min_peer_operators="1"
  fi

  local -a args=(
    --mode "$mode"
    --public-host "$public_host"
    --beta-profile 1
    --prod-profile "$prod_profile"
    --peer-identity-strict "$peer_identity_strict"
    --min-peer-operators "$min_peer_operators"
    --timeout-sec "$timeout_sec"
  )
  if [[ -n "$peer_directories" ]]; then
    args+=(--peer-directories "$peer_directories")
  fi
  if [[ -n "$authority_directory" ]]; then
    args+=(--authority-directory "$authority_directory")
  fi
  if [[ -n "$authority_issuer" ]]; then
    args+=(--authority-issuer "$authority_issuer")
  fi

  server_preflight "${args[@]}"
}

simple_server_session() {
  local mode="authority"
  local public_host=""
  local peer_host=""
  local prod_profile="${EASY_NODE_PROD_PROFILE:-1}"
  local peer_identity_strict="${EASY_NODE_PEER_IDENTITY_STRICT:-auto}"
  local federation_wait="1"
  local federation_ready_timeout_sec="90"
  local federation_poll_sec="5"
  local auto_invite="1"
  local auto_invite_count="1"
  local auto_invite_tier="1"
  local auto_invite_wait_sec="10"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-session requires --mode authority|provider"
          exit 2
        fi
        mode="$2"
        shift 2
        ;;
      --public-host)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-session requires --public-host HOST"
          exit 2
        fi
        public_host="$2"
        shift 2
        ;;
      --peer-host)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-session requires --peer-host HOST"
          exit 2
        fi
        peer_host="$2"
        shift 2
        ;;
      --prod-profile)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-session requires --prod-profile 0 or 1"
          exit 2
        fi
        prod_profile="$2"
        shift 2
        ;;
      --peer-identity-strict)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-session requires --peer-identity-strict 0|1|auto"
          exit 2
        fi
        peer_identity_strict="$2"
        shift 2
        ;;
      --federation-wait)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-session requires --federation-wait 0 or 1"
          exit 2
        fi
        federation_wait="$2"
        shift 2
        ;;
      --federation-ready-timeout-sec)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-session requires --federation-ready-timeout-sec N"
          exit 2
        fi
        federation_ready_timeout_sec="$2"
        shift 2
        ;;
      --federation-poll-sec)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-session requires --federation-poll-sec N"
          exit 2
        fi
        federation_poll_sec="$2"
        shift 2
        ;;
      --auto-invite)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-session requires --auto-invite 0 or 1"
          exit 2
        fi
        auto_invite="$2"
        shift 2
        ;;
      --auto-invite-count)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-session requires --auto-invite-count N"
          exit 2
        fi
        auto_invite_count="$2"
        shift 2
        ;;
      --auto-invite-tier)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-session requires --auto-invite-tier 1|2|3"
          exit 2
        fi
        auto_invite_tier="$2"
        shift 2
        ;;
      --auto-invite-wait-sec)
        if [[ $# -lt 2 ]]; then
          echo "simple-server-session requires --auto-invite-wait-sec N"
          exit 2
        fi
        auto_invite_wait_sec="$2"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for simple-server-session: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$mode" != "authority" && "$mode" != "provider" ]]; then
    echo "simple-server-session requires --mode authority|provider"
    exit 2
  fi
  if [[ -z "$public_host" ]]; then
    echo "simple-server-session requires --public-host HOST"
    exit 2
  fi
  if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
    echo "simple-server-session requires --prod-profile 0 or 1"
    exit 2
  fi
  if [[ "$peer_identity_strict" != "0" && "$peer_identity_strict" != "1" && "$peer_identity_strict" != "auto" ]]; then
    echo "simple-server-session requires --peer-identity-strict 0|1|auto"
    exit 2
  fi
  if [[ "$federation_wait" != "0" && "$federation_wait" != "1" ]]; then
    echo "simple-server-session requires --federation-wait 0 or 1"
    exit 2
  fi
  if [[ "$auto_invite" != "0" && "$auto_invite" != "1" ]]; then
    echo "simple-server-session requires --auto-invite 0 or 1"
    exit 2
  fi
  if ! [[ "$federation_ready_timeout_sec" =~ ^[0-9]+$ && "$federation_poll_sec" =~ ^[0-9]+$ ]]; then
    echo "simple-server-session requires numeric federation timeout/poll values"
    exit 2
  fi

  public_host="$(simple_wrapper_normalize_host "$public_host")"
  peer_host="$(simple_wrapper_normalize_host "$peer_host")"

  local -a args=(
    --mode "$mode"
    --public-host "$public_host"
    --beta-profile 1
    --prod-profile "$prod_profile"
    --peer-identity-strict "$peer_identity_strict"
    --cleanup-all 1
  )
  if [[ "$federation_wait" == "1" ]]; then
    args+=(
      --federation-wait 1
      --federation-ready-timeout-sec "$federation_ready_timeout_sec"
      --federation-poll-sec "$federation_poll_sec"
    )
  else
    args+=(--federation-wait 0)
  fi

  if [[ "$mode" == "provider" ]]; then
    if [[ -z "$peer_host" ]]; then
      echo "simple-server-session requires --peer-host when --mode provider"
      exit 2
    fi
    local authority_directory authority_issuer
    authority_directory="$(url_from_host_port "$peer_host" 8081)"
    authority_issuer="$(url_from_host_port "$peer_host" 8082)"
    args+=(
      --authority-directory "$authority_directory"
      --authority-issuer "$authority_issuer"
      --peer-directories "$authority_directory"
    )
  else
    if ! [[ "$auto_invite_count" =~ ^[0-9]+$ ]] || [[ "$auto_invite_count" == "0" ]]; then
      auto_invite_count="1"
    fi
    if [[ "$auto_invite_tier" != "1" && "$auto_invite_tier" != "2" && "$auto_invite_tier" != "3" ]]; then
      auto_invite_tier="1"
    fi
    if ! [[ "$auto_invite_wait_sec" =~ ^[0-9]+$ ]]; then
      auto_invite_wait_sec="10"
    fi
    args+=(
      --client-allowlist 1
      --allow-anon-cred 0
      --auto-invite "$auto_invite"
      --auto-invite-count "$auto_invite_count"
      --auto-invite-tier "$auto_invite_tier"
      --auto-invite-wait-sec "$auto_invite_wait_sec"
      --auto-invite-fail-open 0
    )
    if [[ -n "$peer_host" ]]; then
      args+=(--peer-directories "$(url_from_host_port "$peer_host" 8081)")
    fi
  fi

  server_session "${args[@]}"
}

client_vpn_up() {
  local directory_urls=""
  local issuer_url=""
  local issuer_urls=""
  local entry_url=""
  local exit_url=""
  local bootstrap_directory=""
  local discovery_wait_sec="${EASY_NODE_DISCOVERY_WAIT_SEC:-20}"
  local client_subject="${CLIENT_SUBJECT:-}"
  local client_anon_cred="${CLIENT_ANON_CRED:-}"
  local min_sources="1"
  local min_operators="1"
  local path_profile="${EASY_NODE_PATH_PROFILE:-}"
  local require_distinct_operators="${CLIENT_REQUIRE_DISTINCT_OPERATORS:-1}"
  local require_distinct_countries="${CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY:-0}"
  local exit_country="${CLIENT_EXIT_COUNTRY:-}"
  local exit_region="${CLIENT_EXIT_REGION:-}"
  local locality_soft_bias="${CLIENT_EXIT_LOCALITY_SOFT_BIAS:-0}"
  local locality_country_bias="${CLIENT_EXIT_COUNTRY_BIAS:-1.60}"
  local locality_region_bias="${CLIENT_EXIT_REGION_BIAS:-1.25}"
  local locality_region_prefix_bias="${CLIENT_EXIT_REGION_PREFIX_BIAS:-1.10}"
  local beta_profile="${EASY_NODE_BETA_PROFILE:-1}"
  local prod_profile="${EASY_NODE_PROD_PROFILE:-0}"
  local operator_floor_check="${EASY_NODE_CLIENT_VPN_OPERATOR_FLOOR_CHECK:-}"
  local operator_min_operators="${EASY_NODE_CLIENT_VPN_OPERATOR_MIN_OPERATORS:-2}"
  local operator_min_entry_operators="${EASY_NODE_CLIENT_VPN_OPERATOR_MIN_ENTRY_OPERATORS:-}"
  local operator_min_exit_operators="${EASY_NODE_CLIENT_VPN_OPERATOR_MIN_EXIT_OPERATORS:-}"
  local issuer_quorum_check="${EASY_NODE_CLIENT_VPN_ISSUER_QUORUM_CHECK:-}"
  local issuer_min_operators="${EASY_NODE_CLIENT_VPN_ISSUER_MIN_OPERATORS:-2}"
  local interface_name="${CLIENT_WG_INTERFACE:-wgvpn0}"
  local proxy_addr="${CLIENT_WG_PROXY_ADDR:-127.0.0.1:57970}"
  local private_key_file=""
  local allowed_ips="${CLIENT_WG_ALLOWED_IPS:-0.0.0.0/0}"
  local install_route="${CLIENT_WG_INSTALL_ROUTE:-1}"
  local startup_sync_timeout_sec="${CLIENT_STARTUP_SYNC_TIMEOUT_SEC:-12}"
  local session_reuse="${CLIENT_SESSION_REUSE:-1}"
  local allow_session_churn="${CLIENT_DIRECT_EXIT_ALLOW_SESSION_CHURN:-0}"
  local session_refresh_lead_sec="${CLIENT_SESSION_REFRESH_LEAD_SEC:-20}"
  local ready_timeout_sec="${EASY_NODE_CLIENT_VPN_READY_TIMEOUT_SEC:-35}"
  local force_restart="0"
  local foreground="0"
  local mtls_ca_file="$DEPLOY_DIR/tls/ca.crt"
  local mtls_client_cert_file="$DEPLOY_DIR/tls/client.crt"
  local mtls_client_key_file="$DEPLOY_DIR/tls/client.key"
  local trust_scope_mode="${EASY_NODE_CLIENT_VPN_TRUST_SCOPE:-scoped}"
  local log_file=""
  local min_sources_set=0
  local min_operators_set=0
  local distinct_set=0
  local distinct_countries_set=0
  local locality_soft_bias_set=0
  local locality_country_bias_set=0
  local locality_region_bias_set=0
  local locality_region_prefix_bias_set=0
  local speed_onehop_profile=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --directory-urls)
        directory_urls="${2:-}"
        shift 2
        ;;
      --bootstrap-directory)
        bootstrap_directory="${2:-}"
        shift 2
        ;;
      --discovery-wait-sec)
        discovery_wait_sec="${2:-}"
        shift 2
        ;;
      --issuer-url)
        issuer_url="${2:-}"
        shift 2
        ;;
      --issuer-urls)
        issuer_urls="${2:-}"
        shift 2
        ;;
      --entry-url)
        entry_url="${2:-}"
        shift 2
        ;;
      --exit-url)
        exit_url="${2:-}"
        shift 2
        ;;
      --subject)
        client_subject="${2:-}"
        shift 2
        ;;
      --anon-cred)
        client_anon_cred="${2:-}"
        shift 2
        ;;
      --min-sources)
        min_sources="${2:-}"
        min_sources_set=1
        shift 2
        ;;
      --min-operators)
        min_operators="${2:-}"
        min_operators_set=1
        shift 2
        ;;
      --path-profile)
        path_profile="${2:-}"
        shift 2
        ;;
      --distinct-operators)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          require_distinct_operators="${2:-}"
          distinct_set=1
          shift 2
        else
          require_distinct_operators="1"
          distinct_set=1
          shift
        fi
        ;;
      --distinct-countries)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          require_distinct_countries="${2:-}"
          distinct_countries_set=1
          shift 2
        else
          require_distinct_countries="1"
          distinct_countries_set=1
          shift
        fi
        ;;
      --exit-country)
        exit_country="${2:-}"
        shift 2
        ;;
      --exit-region)
        exit_region="${2:-}"
        shift 2
        ;;
      --locality-soft-bias)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          locality_soft_bias="${2:-}"
          locality_soft_bias_set=1
          shift 2
        else
          locality_soft_bias="1"
          locality_soft_bias_set=1
          shift
        fi
        ;;
      --country-bias)
        locality_country_bias="${2:-}"
        locality_country_bias_set=1
        shift 2
        ;;
      --region-bias)
        locality_region_bias="${2:-}"
        locality_region_bias_set=1
        shift 2
        ;;
      --region-prefix-bias)
        locality_region_prefix_bias="${2:-}"
        locality_region_prefix_bias_set=1
        shift 2
        ;;
      --beta-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          beta_profile="${2:-}"
          shift 2
        else
          beta_profile="1"
          shift
        fi
        ;;
      --prod-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          prod_profile="${2:-}"
          shift 2
        else
          prod_profile="1"
          shift
        fi
        ;;
      --operator-floor-check)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          operator_floor_check="${2:-}"
          shift 2
        else
          operator_floor_check="1"
          shift
        fi
        ;;
      --operator-min-operators)
        operator_min_operators="${2:-}"
        shift 2
        ;;
      --operator-min-entry-operators)
        operator_min_entry_operators="${2:-}"
        shift 2
        ;;
      --operator-min-exit-operators)
        operator_min_exit_operators="${2:-}"
        shift 2
        ;;
      --issuer-quorum-check)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          issuer_quorum_check="${2:-}"
          shift 2
        else
          issuer_quorum_check="1"
          shift
        fi
        ;;
      --issuer-min-operators)
        issuer_min_operators="${2:-}"
        shift 2
        ;;
      --interface)
        interface_name="${2:-}"
        shift 2
        ;;
      --proxy-addr)
        proxy_addr="${2:-}"
        shift 2
        ;;
      --private-key-file)
        private_key_file="${2:-}"
        shift 2
        ;;
      --allowed-ips)
        allowed_ips="${2:-}"
        shift 2
        ;;
      --install-route)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          install_route="${2:-}"
          shift 2
        else
          install_route="1"
          shift
        fi
        ;;
      --startup-sync-timeout-sec)
        startup_sync_timeout_sec="${2:-}"
        shift 2
        ;;
      --session-reuse)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          session_reuse="${2:-}"
          shift 2
        else
          session_reuse="1"
          shift
        fi
        ;;
      --allow-session-churn)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          allow_session_churn="${2:-}"
          shift 2
        else
          allow_session_churn="1"
          shift
        fi
        ;;
      --ready-timeout-sec)
        ready_timeout_sec="${2:-}"
        shift 2
        ;;
      --force-restart)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          force_restart="${2:-}"
          shift 2
        else
          force_restart="1"
          shift
        fi
        ;;
      --foreground)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          foreground="${2:-}"
          shift 2
        else
          foreground="1"
          shift
        fi
        ;;
      --mtls-ca-file)
        mtls_ca_file="${2:-}"
        shift 2
        ;;
      --mtls-client-cert-file)
        mtls_client_cert_file="${2:-}"
        shift 2
        ;;
      --mtls-client-key-file)
        mtls_client_key_file="${2:-}"
        shift 2
        ;;
      --log-file)
        log_file="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage || true
        return 0
        ;;
      *)
        echo "unknown arg for client-vpn-up: $1"
        exit 2
        ;;
    esac
  done

  local normalized_path_profile=""
  normalized_path_profile="$(normalize_path_profile "$path_profile")" || {
    echo "client-vpn-up requires --path-profile to be one of: 1hop, 2hop, 3hop, speed, balanced, private (legacy aliases: fast, privacy)"
    exit 2
  }
  local canonical_path_profile="2hop"
  case "$normalized_path_profile" in
    speed-1hop)
      canonical_path_profile="1hop"
      ;;
    privacy)
      canonical_path_profile="3hop"
      ;;
    *)
      canonical_path_profile="2hop"
      ;;
  esac
  if [[ "$normalized_path_profile" == "speed-1hop" ]]; then
    speed_onehop_profile=1
  fi
  if [[ -n "$normalized_path_profile" ]]; then
    local profile_values profile_distinct profile_distinct_countries profile_locality_soft profile_country_bias profile_region_bias profile_region_prefix_bias
    profile_values="$(path_profile_values "$normalized_path_profile")"
    IFS='|' read -r profile_distinct profile_distinct_countries profile_locality_soft profile_country_bias profile_region_bias profile_region_prefix_bias <<<"$profile_values"
    if [[ "$distinct_set" -eq 0 ]]; then
      require_distinct_operators="$profile_distinct"
    fi
    if [[ "$distinct_countries_set" -eq 0 ]]; then
      require_distinct_countries="$profile_distinct_countries"
    fi
    if [[ "$locality_soft_bias_set" -eq 0 ]]; then
      locality_soft_bias="$profile_locality_soft"
    fi
    if [[ "$locality_country_bias_set" -eq 0 ]]; then
      locality_country_bias="$profile_country_bias"
    fi
    if [[ "$locality_region_bias_set" -eq 0 ]]; then
      locality_region_bias="$profile_region_bias"
    fi
    if [[ "$locality_region_prefix_bias_set" -eq 0 ]]; then
      locality_region_prefix_bias="$profile_region_prefix_bias"
    fi
  fi
  if [[ "$speed_onehop_profile" == "1" && "$distinct_set" -eq 0 ]]; then
    require_distinct_operators="0"
  fi

  ensure_client_vpn_deps_or_die

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "client-vpn-up requires root privileges (run with sudo)"
    exit 1
  fi
  if [[ "$require_distinct_operators" != "0" && "$require_distinct_operators" != "1" ]]; then
    echo "client-vpn-up requires --distinct-operators 0 or 1"
    exit 2
  fi
  if [[ "$require_distinct_countries" != "0" && "$require_distinct_countries" != "1" ]]; then
    echo "client-vpn-up requires --distinct-countries 0 or 1"
    exit 2
  fi
  if [[ "$locality_soft_bias" != "0" && "$locality_soft_bias" != "1" ]]; then
    echo "client-vpn-up requires --locality-soft-bias 0 or 1"
    exit 2
  fi
  if ! [[ "$locality_country_bias" =~ ^[0-9]+([.][0-9]+)?$ && "$locality_region_bias" =~ ^[0-9]+([.][0-9]+)?$ && "$locality_region_prefix_bias" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "client-vpn-up requires numeric --country-bias, --region-bias and --region-prefix-bias"
    exit 2
  fi
  if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
    echo "client-vpn-up requires --beta-profile 0 or 1"
    exit 2
  fi
  if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
    echo "client-vpn-up requires --prod-profile 0 or 1"
    exit 2
  fi
  if [[ -z "$operator_floor_check" ]]; then
    if [[ "$prod_profile" == "1" ]]; then
      operator_floor_check="1"
    else
      operator_floor_check="0"
    fi
  fi
  if [[ "$operator_floor_check" != "0" && "$operator_floor_check" != "1" ]]; then
    echo "client-vpn-up requires --operator-floor-check 0 or 1"
    exit 2
  fi
  if [[ -z "$operator_min_entry_operators" ]]; then
    operator_min_entry_operators="$operator_min_operators"
  fi
  if [[ -z "$operator_min_exit_operators" ]]; then
    operator_min_exit_operators="$operator_min_operators"
  fi
  if ! [[ "$operator_min_operators" =~ ^[0-9]+$ ]] || ((operator_min_operators < 1)); then
    echo "client-vpn-up requires --operator-min-operators >= 1"
    exit 2
  fi
  if ! [[ "$operator_min_entry_operators" =~ ^[0-9]+$ ]] || ((operator_min_entry_operators < 1)); then
    echo "client-vpn-up requires --operator-min-entry-operators >= 1"
    exit 2
  fi
  if ! [[ "$operator_min_exit_operators" =~ ^[0-9]+$ ]] || ((operator_min_exit_operators < 1)); then
    echo "client-vpn-up requires --operator-min-exit-operators >= 1"
    exit 2
  fi
  if [[ -z "$issuer_quorum_check" ]]; then
    if [[ "$prod_profile" == "1" ]]; then
      issuer_quorum_check="1"
    else
      issuer_quorum_check="0"
    fi
  fi
  if [[ "$issuer_quorum_check" != "0" && "$issuer_quorum_check" != "1" ]]; then
    echo "client-vpn-up requires --issuer-quorum-check 0 or 1"
    exit 2
  fi
  if ! [[ "$issuer_min_operators" =~ ^[0-9]+$ ]] || ((issuer_min_operators < 1)); then
    echo "client-vpn-up requires --issuer-min-operators >= 1"
    exit 2
  fi
  if [[ "$install_route" != "0" && "$install_route" != "1" ]]; then
    echo "client-vpn-up requires --install-route 0 or 1"
    exit 2
  fi
  if [[ "$force_restart" != "0" && "$force_restart" != "1" ]]; then
    echo "client-vpn-up requires --force-restart 0 or 1"
    exit 2
  fi
  if [[ "$foreground" != "0" && "$foreground" != "1" ]]; then
    echo "client-vpn-up requires --foreground 0 or 1"
    exit 2
  fi
  if [[ "$session_reuse" != "0" && "$session_reuse" != "1" ]]; then
    echo "client-vpn-up requires CLIENT_SESSION_REUSE to be 0 or 1"
    exit 2
  fi
  if [[ "$allow_session_churn" != "0" && "$allow_session_churn" != "1" ]]; then
    echo "client-vpn-up requires --allow-session-churn 0 or 1"
    exit 2
  fi
  if ! [[ "$session_refresh_lead_sec" =~ ^[0-9]+$ ]] || ((session_refresh_lead_sec < 1)); then
    echo "client-vpn-up requires CLIENT_SESSION_REFRESH_LEAD_SEC >= 1"
    exit 2
  fi
  if ! [[ "$min_sources" =~ ^[0-9]+$ && "$min_operators" =~ ^[0-9]+$ && "$discovery_wait_sec" =~ ^[0-9]+$ && "$startup_sync_timeout_sec" =~ ^[0-9]+$ && "$ready_timeout_sec" =~ ^[0-9]+$ ]]; then
    echo "client-vpn-up requires numeric --min-sources, --min-operators, --discovery-wait-sec, --startup-sync-timeout-sec and --ready-timeout-sec"
    exit 2
  fi
  if [[ -z "$interface_name" ]]; then
    echo "client-vpn-up requires --interface"
    exit 2
  fi
  if [[ -z "$proxy_addr" ]]; then
    echo "client-vpn-up requires --proxy-addr"
    exit 2
  fi
  if [[ -n "$client_subject" && -n "$client_anon_cred" ]]; then
    echo "client-vpn-up requires exactly one of --subject or --anon-cred"
    exit 2
  fi
  trust_scope_mode="$(printf '%s' "$trust_scope_mode" | tr '[:upper:]' '[:lower:]')"
  if [[ "$trust_scope_mode" != "scoped" && "$trust_scope_mode" != "global" ]]; then
    echo "client-vpn-up requires EASY_NODE_CLIENT_VPN_TRUST_SCOPE to be one of: scoped, global"
    exit 2
  fi

  local client_url_scheme="http"
  if [[ "$prod_profile" == "1" ]]; then
    beta_profile="1"
    client_url_scheme="https"
  fi
  if [[ "$beta_profile" == "1" ]]; then
    if [[ "$distinct_set" -eq 0 ]]; then
      require_distinct_operators="1"
    fi
    if [[ "$min_sources_set" -eq 0 ]] && [[ "$directory_urls" == *,* ]]; then
      min_sources="2"
    fi
    if [[ "$min_operators_set" -eq 0 ]] && [[ "$directory_urls" == *,* ]]; then
      min_operators="2"
    fi
  fi
  if [[ "$speed_onehop_profile" == "1" && ( "$beta_profile" == "1" || "$prod_profile" == "1" ) ]]; then
    echo "client-vpn-up --path-profile 1hop/speed-1hop requires --beta-profile 0 and --prod-profile 0"
    exit 2
  fi
  if [[ "$speed_onehop_profile" == "1" && "$require_distinct_operators" == "1" ]]; then
    echo "client-vpn-up --path-profile 1hop/speed-1hop requires --distinct-operators 0 (one-hop direct-exit mode)"
    exit 2
  fi

  if [[ -n "$bootstrap_directory" ]]; then
    bootstrap_directory="$(ensure_url_scheme "$bootstrap_directory" "$client_url_scheme")"
    local discovered
    discovered="$(discover_directory_urls "$bootstrap_directory" "$discovery_wait_sec" "$min_sources")"
    if [[ -z "$directory_urls" ]]; then
      directory_urls="$discovered"
    else
      directory_urls="$(merge_url_csv "$directory_urls" "$discovered")"
    fi
    local bootstrap_host
    bootstrap_host="$(host_from_url "$bootstrap_directory")"
    if [[ -z "$issuer_url" && -n "$bootstrap_host" ]]; then
      issuer_url="$(url_from_host_port "$bootstrap_host" 8082)"
    fi
    if [[ -z "$entry_url" && -n "$bootstrap_host" ]]; then
      entry_url="$(url_from_host_port "$bootstrap_host" 8083)"
    fi
    if [[ -z "$exit_url" && -n "$bootstrap_host" ]]; then
      exit_url="$(url_from_host_port "$bootstrap_host" 8084)"
    fi
  fi

  if [[ -z "$directory_urls" || -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" ]]; then
    echo "client-vpn-up requires directory, issuer, entry and exit URLs."
    echo "provide explicit --directory-urls/--issuer-url/--entry-url/--exit-url"
    echo "or use --bootstrap-directory for automatic discovery."
    exit 2
  fi

  directory_urls="$(normalize_url_csv_scheme "$directory_urls" "$client_url_scheme")"
  issuer_url="$(ensure_url_scheme "$issuer_url" "$client_url_scheme")"
  entry_url="$(ensure_url_scheme "$entry_url" "$client_url_scheme")"
  exit_url="$(ensure_url_scheme "$exit_url" "$client_url_scheme")"
  if [[ -z "$issuer_urls" ]]; then
    issuer_urls="$issuer_url"
  fi
  issuer_urls="$(merge_url_csv "$issuer_urls" "$issuer_url")"
  local durl dhost
  while IFS= read -r durl; do
    [[ -z "$durl" ]] && continue
    dhost="$(host_from_url "$durl")"
    if [[ -n "$dhost" ]]; then
      issuer_urls="$(merge_url_csv "$issuer_urls" "$(url_from_host_port "$dhost" 8082)")"
    fi
  done < <(split_csv_lines "$directory_urls")
  issuer_urls="$(normalize_url_csv_scheme "$issuer_urls" "$client_url_scheme")"
  if [[ "$beta_profile" == "1" ]]; then
    if [[ "$min_sources_set" -eq 0 ]] && [[ "$directory_urls" == *,* ]]; then
      min_sources="2"
    fi
    if [[ "$min_operators_set" -eq 0 ]] && [[ "$directory_urls" == *,* ]]; then
      min_operators="2"
    fi
  fi

  local first_dir
  first_dir="$(first_csv_item "$directory_urls")"
  local -a dir_opts issuer_opts entry_opts exit_opts
  mapfile -t dir_opts < <(curl_tls_opts_for_url "$first_dir")
  mapfile -t issuer_opts < <(curl_tls_opts_for_url "$issuer_url")
  mapfile -t entry_opts < <(curl_tls_opts_for_url "$entry_url")
  mapfile -t exit_opts < <(curl_tls_opts_for_url "$exit_url")
  wait_http_ok_with_opts "${first_dir%/}/v1/pubkeys" "directory" 15 "${dir_opts[@]}" || exit 1
  wait_http_ok_with_opts "${issuer_url%/}/v1/pubkeys" "issuer" 15 "${issuer_opts[@]}" || exit 1
  wait_http_ok_with_opts "${entry_url%/}/v1/health" "entry" 15 "${entry_opts[@]}" || exit 1
  wait_http_ok_with_opts "${exit_url%/}/v1/health" "exit" 15 "${exit_opts[@]}" || exit 1

  if [[ "$operator_floor_check" == "1" ]]; then
    local all_ops entry_ops exit_ops missing_ops fetch_fail parse_fail
    local all_ops_list entry_ops_list exit_ops_list
    IFS='|' read -r all_ops entry_ops exit_ops missing_ops fetch_fail parse_fail all_ops_list entry_ops_list exit_ops_list < <(client_vpn_operator_floor_summary "$directory_urls" 8)
    if ((fetch_fail > 0)); then
      echo "client-vpn-up operator-floor check failed: could not fetch relays from all configured directories (failures=$fetch_fail)"
      exit 1
    fi
    if ((parse_fail > 0)); then
      echo "client-vpn-up operator-floor check failed: parse errors while reading directory relays (errors=$parse_fail)"
      exit 1
    fi
    if ((missing_ops > 0)); then
      echo "client-vpn-up operator-floor check failed: relay descriptors missing operator metadata (count=$missing_ops)"
      exit 1
    fi
    if ((all_ops < operator_min_operators)); then
      echo "client-vpn-up operator-floor check failed: need >=$operator_min_operators distinct operators (observed=$all_ops)"
      echo "observed operators: all=${all_ops_list:-none} entry=${entry_ops_list:-none} exit=${exit_ops_list:-none}"
      exit 1
    fi
    if ((entry_ops < operator_min_entry_operators)); then
      echo "client-vpn-up operator-floor check failed: need >=$operator_min_entry_operators entry operators (observed=$entry_ops)"
      echo "observed operators: all=${all_ops_list:-none} entry=${entry_ops_list:-none} exit=${exit_ops_list:-none}"
      exit 1
    fi
    if ((exit_ops < operator_min_exit_operators)); then
      echo "client-vpn-up operator-floor check failed: need >=$operator_min_exit_operators exit operators (observed=$exit_ops)"
      echo "observed operators: all=${all_ops_list:-none} entry=${entry_ops_list:-none} exit=${exit_ops_list:-none}"
      exit 1
    fi
  fi

  if [[ "$issuer_quorum_check" == "1" ]]; then
    local issuer_ops missing_issuer missing_keys issuer_fetch_fail issuer_parse_fail
    IFS='|' read -r issuer_ops missing_issuer missing_keys issuer_fetch_fail issuer_parse_fail < <(client_vpn_issuer_quorum_summary "$issuer_urls" 8)
    if ((issuer_fetch_fail > 0)); then
      echo "client-vpn-up issuer-quorum check failed: could not fetch all issuer feeds (failures=$issuer_fetch_fail)"
      exit 1
    fi
    if ((issuer_parse_fail > 0)); then
      echo "client-vpn-up issuer-quorum check failed: parse errors while reading issuer feeds (errors=$issuer_parse_fail)"
      exit 1
    fi
    if ((missing_issuer > 0)); then
      echo "client-vpn-up issuer-quorum check failed: issuer identity missing from one or more feeds (count=$missing_issuer)"
      exit 1
    fi
    if ((missing_keys > 0)); then
      echo "client-vpn-up issuer-quorum check failed: issuer feed missing pub_keys (count=$missing_keys)"
      exit 1
    fi
    if ((issuer_ops < issuer_min_operators)); then
      echo "client-vpn-up issuer-quorum check failed: need >=$issuer_min_operators distinct issuer identities (observed=$issuer_ops)"
      exit 1
    fi
  fi

  local state_file
  state_file="$(client_vpn_state_file)"
  mkdir -p "$(dirname "$state_file")"
  if [[ -f "$state_file" ]]; then
    local old_pid
    old_pid="$(identity_value "$state_file" "CLIENT_VPN_PID")"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" >/dev/null 2>&1; then
      if [[ "$force_restart" == "1" ]]; then
        client_vpn_down --force-iface-cleanup 1 --keep-key 1 >/dev/null 2>&1 || true
      else
        echo "client-vpn appears to be running already (pid=$old_pid)"
        echo "use --force-restart 1 or run ./scripts/easy_node.sh client-vpn-down first"
        exit 1
      fi
    else
      rm -f "$state_file" >/dev/null 2>&1 || true
    fi
  fi

  if [[ -z "$private_key_file" ]]; then
    private_key_file="$(default_client_vpn_key_dir)/${interface_name}.key"
  fi
  mkdir -p "$(dirname "$private_key_file")"
  if [[ ! -f "$private_key_file" ]]; then
    (umask 077 && wg genkey >"$private_key_file")
  fi
  secure_file_permissions "$private_key_file"
  local client_wg_pub=""
  if ! client_wg_pub="$(wg pubkey <"$private_key_file")"; then
    echo "client-vpn failed to derive client wireguard public key"
    exit 1
  fi
  client_wg_pub="$(printf '%s' "$client_wg_pub" | tr -d '\r\n')"
  if ! is_valid_wg_public_key "$client_wg_pub"; then
    echo "client-vpn derived invalid client wireguard public key"
    exit 1
  fi

  if [[ "$prod_profile" == "1" ]]; then
    for f in "$mtls_ca_file" "$mtls_client_cert_file" "$mtls_client_key_file"; do
      if [[ ! -f "$f" ]]; then
        echo "missing mTLS file for prod profile: $f"
        exit 2
      fi
    done
  fi

  local log_dir
  log_dir="$(prepare_log_dir)"
  if [[ -z "$log_file" ]]; then
    log_file="$log_dir/easy_node_client_vpn_$(date +%Y%m%d_%H%M%S).log"
  fi
  rm -f "$log_file"

  ip link delete "$interface_name" >/dev/null 2>&1 || true
  if ! ip link add dev "$interface_name" type wireguard >/dev/null 2>&1; then
    echo "client-vpn failed to create wireguard interface: $interface_name"
    exit 1
  fi

  local trusted_keys_file="${DIRECTORY_TRUSTED_KEYS_FILE:-}"
  if [[ -z "$trusted_keys_file" ]]; then
    trusted_keys_file="$(default_client_vpn_trust_file_for_directory_urls "$directory_urls" "$trust_scope_mode")"
  fi
  local trusted_keys_dir
  if [[ "$trusted_keys_file" == /* ]]; then
    trusted_keys_dir="$(dirname "$trusted_keys_file")"
  else
    trusted_keys_dir="$ROOT_DIR/$(dirname "$trusted_keys_file")"
  fi
  mkdir -p "$trusted_keys_dir" >/dev/null 2>&1 || true
  seed_client_vpn_trust_file_if_empty "$trusted_keys_file" "$directory_urls"

  local -a env_vars
  env_vars=(
    "DATA_PLANE_MODE=opaque"
    "DIRECTORY_URLS=$directory_urls"
    "DIRECTORY_MIN_SOURCES=$min_sources"
    "CLIENT_DIRECTORY_MIN_OPERATORS=$min_operators"
    "DIRECTORY_TRUST_STRICT=1"
    "DIRECTORY_TRUST_TOFU=$([[ "$prod_profile" == "1" ]] && echo 0 || echo 1)"
    "DIRECTORY_TRUSTED_KEYS_FILE=$trusted_keys_file"
    "ISSUER_URL=$issuer_url"
    "ENTRY_URL=$entry_url"
    "EXIT_CONTROL_URL=$exit_url"
    "CLIENT_PATH_PROFILE=$canonical_path_profile"
    "CLIENT_WG_BACKEND=command"
    "CLIENT_WG_INTERFACE=$interface_name"
    "CLIENT_WG_PRIVATE_KEY_PATH=$private_key_file"
    "CLIENT_WG_PUBLIC_KEY=$client_wg_pub"
    "CLIENT_WG_ALLOWED_IPS=$allowed_ips"
    "CLIENT_WG_INSTALL_ROUTE=$install_route"
    "CLIENT_WG_KERNEL_PROXY=1"
    "CLIENT_WG_PROXY_ADDR=$proxy_addr"
    "CLIENT_INNER_SOURCE=udp"
    "CLIENT_DISABLE_SYNTHETIC_FALLBACK=1"
    "CLIENT_LIVE_WG_MODE=1"
    "CLIENT_REQUIRE_DISTINCT_OPERATORS=$require_distinct_operators"
    "CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY=$require_distinct_countries"
    "CLIENT_EXIT_LOCALITY_SOFT_BIAS=$locality_soft_bias"
    "CLIENT_EXIT_COUNTRY_BIAS=$locality_country_bias"
    "CLIENT_EXIT_REGION_BIAS=$locality_region_bias"
    "CLIENT_EXIT_REGION_PREFIX_BIAS=$locality_region_prefix_bias"
    "CLIENT_BOOTSTRAP_INTERVAL_SEC=2"
    "CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC=4"
    "CLIENT_BOOTSTRAP_JITTER_PCT=10"
    "CLIENT_SESSION_REUSE=$session_reuse"
    "CLIENT_DIRECT_EXIT_ALLOW_SESSION_CHURN=$allow_session_churn"
    "CLIENT_SESSION_REFRESH_LEAD_SEC=$session_refresh_lead_sec"
    "CLIENT_STARTUP_SYNC_TIMEOUT_SEC=$startup_sync_timeout_sec"
    "BETA_STRICT_MODE=$beta_profile"
    "PROD_STRICT_MODE=$prod_profile"
  )
  if [[ "$speed_onehop_profile" == "1" ]]; then
    env_vars+=(
      "CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=1"
      "CLIENT_FORCE_DIRECT_EXIT=1"
    )
    if [[ "$allow_session_churn" != "1" ]]; then
      env_vars+=(
        "CLIENT_SESSION_REUSE=1"
        "CLIENT_STICKY_PAIR_SEC=300"
      )
    fi
  fi
  if [[ -n "$client_subject" ]]; then
    env_vars+=("CLIENT_SUBJECT=$client_subject")
  fi
  if [[ -n "$client_anon_cred" ]]; then
    env_vars+=("CLIENT_ANON_CRED=$client_anon_cred")
  fi
  if [[ -n "$exit_country" ]]; then
    env_vars+=("CLIENT_EXIT_COUNTRY=$exit_country")
  fi
  if [[ -n "$exit_region" ]]; then
    env_vars+=("CLIENT_EXIT_REGION=$exit_region")
  fi
  if [[ "$prod_profile" == "1" ]]; then
    env_vars+=(
      "MTLS_ENABLE=1"
      "MTLS_CA_FILE=$mtls_ca_file"
      "MTLS_CLIENT_CERT_FILE=$mtls_client_cert_file"
      "MTLS_CLIENT_KEY_FILE=$mtls_client_key_file"
      "MTLS_CERT_FILE=$mtls_client_cert_file"
      "MTLS_KEY_FILE=$mtls_client_key_file"
    )
  fi

  if [[ "$foreground" == "1" ]]; then
    echo "client-vpn starting in foreground"
    echo "log: $log_file"
    (
      cd "$ROOT_DIR"
      env "${env_vars[@]}" go run ./cmd/node --client
    ) 2>&1 | tee -a "$log_file"
    return $?
  fi

  local pid=""
  local pid_tmp
  pid_tmp="$(mktemp)"
  (
    cd "$ROOT_DIR"
    nohup env "${env_vars[@]}" go run ./cmd/node --client >"$log_file" 2>&1 &
    echo "$!" >"$pid_tmp"
  )
  pid="$(cat "$pid_tmp")"
  rm -f "$pid_tmp"

  if [[ -z "$pid" ]] || ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "client-vpn failed to start; log follows:"
    cat "$log_file"
    exit 1
  fi

  local ready=0
  local i
  for i in $(seq 1 "$ready_timeout_sec"); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "client-vpn exited before tunnel became ready"
      cat "$log_file"
      print_client_vpn_trust_mismatch_hint "$log_file" "$trusted_keys_file" "$trust_scope_mode"
      exit 1
    fi
    if rg -q "client received wg-session config" "$log_file"; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "$ready" -ne 1 ]]; then
    echo "client-vpn did not receive wg-session config within ${ready_timeout_sec}s"
    echo "log: $log_file"
    tail -n 120 "$log_file" || true
    print_client_vpn_trust_mismatch_hint "$log_file" "$trusted_keys_file" "$trust_scope_mode"
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
    ip link delete "$interface_name" >/dev/null 2>&1 || true
    exit 1
  fi

  local exit_wg_pub
  exit_wg_pub="$(rg -o 'exit_pub=[^ ]+' "$log_file" | tail -n 1 | sed -E 's/^exit_pub=//' | tr -d '\r\n')"
  if [[ -z "$exit_wg_pub" ]]; then
    echo "client-vpn could not parse exit wg pubkey from session config"
    tail -n 120 "$log_file" || true
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
    ip link delete "$interface_name" >/dev/null 2>&1 || true
    exit 1
  fi
  if ! is_valid_wg_public_key "$exit_wg_pub"; then
    echo "client-vpn received invalid exit wg pubkey in session config: $exit_wg_pub"
    tail -n 120 "$log_file" || true
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
    ip link delete "$interface_name" >/dev/null 2>&1 || true
    exit 1
  fi

  if ! ip link show dev "$interface_name" >/dev/null 2>&1; then
    echo "client-vpn missing interface after session config: $interface_name"
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
    exit 1
  fi

  cat >"$state_file" <<EOF_STATE
CLIENT_VPN_PID=$pid
CLIENT_VPN_IFACE=$interface_name
CLIENT_VPN_LOG_FILE=$log_file
CLIENT_VPN_KEY_FILE=$private_key_file
CLIENT_VPN_TRUST_FILE=$trusted_keys_file
CLIENT_VPN_TRUST_SCOPE=$trust_scope_mode
CLIENT_VPN_PROXY_ADDR=$proxy_addr
CLIENT_VPN_DIRECTORY_URLS=$directory_urls
CLIENT_VPN_ISSUER_URL=$issuer_url
CLIENT_VPN_ISSUER_URLS=$issuer_urls
CLIENT_VPN_ENTRY_URL=$entry_url
CLIENT_VPN_EXIT_URL=$exit_url
CLIENT_VPN_EXIT_WG_PUBKEY=$exit_wg_pub
CLIENT_VPN_SUBJECT=$client_subject
CLIENT_VPN_PATH_PROFILE=$normalized_path_profile
CLIENT_VPN_SESSION_REUSE=$session_reuse
CLIENT_VPN_ALLOW_SESSION_CHURN=$allow_session_churn
CLIENT_VPN_BETA_PROFILE=$beta_profile
CLIENT_VPN_PROD_PROFILE=$prod_profile
EOF_STATE
  secure_file_permissions "$state_file"

  echo "client-vpn started"
  echo "  pid: $pid"
  echo "  interface: $interface_name"
  echo "  allowed_ips: $allowed_ips"
  echo "  install_route: $install_route"
  echo "  subject: ${client_subject:-none}"
  echo "  path_profile: ${normalized_path_profile:-default}"
  echo "  session_reuse: $session_reuse"
  echo "  allow_session_churn: $allow_session_churn"
  echo "  directory_urls: $directory_urls"
  echo "  trusted_keys_file: $trusted_keys_file"
  echo "  trust_scope: $trust_scope_mode"
  echo "  operator_floor_check: $operator_floor_check"
  echo "  issuer_quorum_check: $issuer_quorum_check"
  echo "  issuer_urls: $issuer_urls"
  echo "  log: $log_file"
  echo "use './scripts/easy_node.sh client-vpn-status' to inspect"
  echo "use 'sudo ./scripts/easy_node.sh client-vpn-down' to stop and cleanup"
}

main() {
  local cmd="${1:-}"
  apply_config_v1_auto_update_defaults
  maybe_auto_update_and_reexec "$@"
  case "$cmd" in
    check)
      check_dependencies
      ;;
    self-update)
      shift
      self_update_repo "$@"
      ;;
    config-v1-show)
      shift
      config_v1_show "$@"
      ;;
    config-v1-init)
      shift
      config_v1_init "$@"
      ;;
    config-v1-set-profile)
      shift
      config_v1_set_profile "$@"
      ;;
    local-api-session)
      shift
      local_api_session "$@"
      ;;
    server-preflight)
      shift
      server_preflight "$@"
      ;;
    simple-server-preflight)
      shift
      simple_server_preflight "$@"
      ;;
    server-up)
      shift
      server_up "$@"
      ;;
    server-status)
      server_status
      ;;
    server-federation-status)
      shift
      server_federation_status "$@"
      ;;
    server-federation-wait)
      shift
      server_federation_wait "$@"
      ;;
    server-logs)
      shift
      server_logs "$@"
      ;;
    server-session)
      shift
      server_session "$@"
      ;;
    simple-server-session)
      shift
      simple_server_session "$@"
      ;;
    server-down)
      server_down
      ;;
    rotate-server-secrets)
      shift
      rotate_server_secrets "$@"
      ;;
    stop-all)
      shift
      stop_all "$@"
      ;;
    install-deps-ubuntu)
      install_deps_ubuntu
      ;;
    wg-only-check)
      wg_only_check
      ;;
    wg-only-stack-up)
      shift
      wg_only_stack_up "$@"
      ;;
    wg-only-stack-status)
      wg_only_stack_status
      ;;
    wg-only-stack-down)
      shift
      wg_only_stack_down "$@"
      ;;
    wg-only-stack-selftest)
      shift
      wg_only_stack_selftest "$@"
      ;;
    wg-only-stack-selftest-record)
      shift
      wg_only_stack_selftest_record "$@"
      ;;
    wg-only-local-test)
      shift
      wg_only_local_test "$@"
      ;;
    real-wg-privileged-matrix)
      shift
      real_wg_privileged_matrix "$@"
      ;;
    real-wg-privileged-matrix-record)
      shift
      real_wg_privileged_matrix_record "$@"
      ;;
    client-test)
      shift
      client_test "$@"
      ;;
    simple-client-test)
      shift
      simple_client_test "$@"
      ;;
    profile-compare-local)
      shift
      profile_compare_local "$@"
      ;;
    profile-compare-trend)
      shift
      profile_compare_trend "$@"
      ;;
    profile-compare-campaign)
      shift
      profile_compare_campaign "$@"
      ;;
    profile-compare-docker-matrix)
      shift
      profile_compare_docker_matrix "$@"
      ;;
    profile-compare-campaign-check)
      shift
      profile_compare_campaign_check "$@"
      ;;
    profile-compare-campaign-signoff)
      shift
      profile_compare_campaign_signoff "$@"
      ;;
    profile-default-gate-run)
      shift
      profile_default_gate_run "$@"
      ;;
    profile-default-gate-live)
      shift
      profile_default_gate_live "$@"
      ;;
    client-vpn-preflight)
      shift
      client_vpn_preflight "$@"
      ;;
    simple-client-vpn-preflight)
      shift
      simple_client_vpn_preflight "$@"
      ;;
    client-vpn-up)
      shift
      client_vpn_up "$@"
      ;;
    client-vpn-smoke)
      shift
      client_vpn_smoke "$@"
      ;;
    client-vpn-profile-compare)
      shift
      client_vpn_profile_compare "$@"
      ;;
    client-vpn-status)
      shift
      client_vpn_status "$@"
      ;;
    client-vpn-logs)
      shift
      client_vpn_logs "$@"
      ;;
    client-vpn-session)
      shift
      client_vpn_session "$@"
      ;;
    simple-client-vpn-session)
      shift
      simple_client_vpn_session "$@"
      ;;
    client-vpn-down)
      shift
      client_vpn_down "$@"
      ;;
    client-vpn-trust-reset)
      shift
      client_vpn_trust_reset "$@"
      ;;
    three-machine-validate)
      shift
      three_machine_validate "$@"
      ;;
    three-machine-soak)
      shift
      three_machine_soak "$@"
      ;;
    three-machine-prod-gate)
      shift
      three_machine_prod_gate "$@"
      ;;
    three-machine-prod-bundle)
      shift
      three_machine_prod_bundle "$@"
      ;;
    three-machine-prod-signoff)
      shift
      three_machine_prod_signoff "$@"
      ;;
    three-machine-reminder)
      shift
      three_machine_reminder "$@"
      ;;
    three-machine-docker-profile-matrix)
      shift
      three_machine_docker_profile_matrix "$@"
      ;;
    three-machine-docker-profile-matrix-record)
      shift
      three_machine_docker_profile_matrix_record "$@"
      ;;
    three-machine-docker-readiness)
      shift
      three_machine_docker_readiness "$@"
      ;;
    three-machine-docker-readiness-record)
      shift
      three_machine_docker_readiness_record "$@"
      ;;
    manual-validation-backlog)
      shift
      manual_validation_backlog "$@"
      ;;
    single-machine-prod-readiness)
      shift
      single_machine_prod_readiness "$@"
      ;;
    vpn-rc-matrix-path)
      shift
      vpn_rc_matrix_path "$@"
      ;;
    vpn-rc-standard-path)
      shift
      vpn_rc_standard_path "$@"
      ;;
    vpn-rc-resilience-path)
      shift
      vpn_rc_resilience_path "$@"
      ;;
    vpn-non-blockchain-fastlane)
      shift
      vpn_non_blockchain_fastlane "$@"
      ;;
    blockchain-fastlane)
      shift
      blockchain_fastlane "$@"
      ;;
    blockchain-gate-bundle)
      shift
      blockchain_gate_bundle "$@"
      ;;
    ci-blockchain-parallel-sweep)
      shift
      ci_blockchain_parallel_sweep "$@"
      ;;
    blockchain-mainnet-activation-metrics-input)
      shift
      blockchain_mainnet_activation_metrics_input "$@"
      ;;
    blockchain-mainnet-activation-metrics-missing-checklist)
      shift
      blockchain_mainnet_activation_metrics_missing_checklist "$@"
      ;;
    blockchain-mainnet-activation-metrics-missing-input-template)
      shift
      blockchain_mainnet_activation_metrics_missing_input_template "$@"
      ;;
    blockchain-mainnet-activation-metrics-input-template)
      shift
      blockchain_mainnet_activation_metrics_input_template "$@"
      ;;
    blockchain-mainnet-activation-metrics)
      shift
      blockchain_mainnet_activation_metrics "$@"
      ;;
    blockchain-mainnet-activation-gate)
      shift
      blockchain_mainnet_activation_gate "$@"
      ;;
    blockchain-mainnet-activation-gate-cycle)
      shift
      blockchain_mainnet_activation_gate_cycle "$@"
      ;;
    blockchain-mainnet-activation-gate-cycle-seeded)
      shift
      blockchain_mainnet_activation_gate_cycle_seeded "$@"
      ;;
    blockchain-mainnet-activation-operator-pack)
      shift
      blockchain_mainnet_activation_operator_pack "$@"
      ;;
    blockchain-bootstrap-governance-graduation-gate)
      shift
      blockchain_bootstrap_governance_graduation_gate "$@"
      ;;
    roadmap-non-blockchain-actionable-run)
      shift
      roadmap_non_blockchain_actionable_run "$@"
      ;;
    roadmap-blockchain-actionable-run)
      shift
      roadmap_blockchain_actionable_run "$@"
      ;;
    roadmap-next-actions-run)
      shift
      roadmap_next_actions_run "$@"
      ;;
    ci-phase0)
      shift
      ci_phase0 "$@"
      ;;
    ci-phase1-resilience)
      shift
      ci_phase1_resilience "$@"
      ;;
    phase1-resilience-handoff-check)
      shift
      phase1_resilience_handoff_check "$@"
      ;;
    phase1-resilience-handoff-run)
      shift
      phase1_resilience_handoff_run "$@"
      ;;
    ci-phase2-linux-prod-candidate)
      shift
      ci_phase2_linux_prod_candidate "$@"
      ;;
    phase2-linux-prod-candidate-check)
      shift
      phase2_linux_prod_candidate_check "$@"
      ;;
    phase2-linux-prod-candidate-run)
      shift
      phase2_linux_prod_candidate_run "$@"
      ;;
    phase2-linux-prod-candidate-signoff)
      shift
      phase2_linux_prod_candidate_signoff "$@"
      ;;
    phase2-linux-prod-candidate-handoff-check)
      shift
      phase2_linux_prod_candidate_handoff_check "$@"
      ;;
    phase2-linux-prod-candidate-handoff-run)
      shift
      phase2_linux_prod_candidate_handoff_run "$@"
      ;;
    ci-phase3-windows-client-beta)
      shift
      ci_phase3_windows_client_beta "$@"
      ;;
    phase3-windows-client-beta-check)
      shift
      phase3_windows_client_beta_check "$@"
      ;;
    phase3-windows-client-beta-run)
      shift
      phase3_windows_client_beta_run "$@"
      ;;
    phase3-windows-client-beta-handoff-check)
      shift
      phase3_windows_client_beta_handoff_check "$@"
      ;;
    phase3-windows-client-beta-handoff-run)
      shift
      phase3_windows_client_beta_handoff_run "$@"
      ;;
    ci-phase4-windows-full-parity)
      shift
      ci_phase4_windows_full_parity "$@"
      ;;
    phase4-windows-full-parity-check)
      shift
      phase4_windows_full_parity_check "$@"
      ;;
    phase4-windows-full-parity-run)
      shift
      phase4_windows_full_parity_run "$@"
      ;;
    phase4-windows-full-parity-handoff-check)
      shift
      phase4_windows_full_parity_handoff_check "$@"
      ;;
    phase4-windows-full-parity-handoff-run)
      shift
      phase4_windows_full_parity_handoff_run "$@"
      ;;
    ci-phase5-settlement-layer)
      shift
      ci_phase5_settlement_layer "$@"
      ;;
    phase5-settlement-layer-check)
      shift
      phase5_settlement_layer_check "$@"
      ;;
    phase5-settlement-layer-run)
      shift
      phase5_settlement_layer_run "$@"
      ;;
    phase5-settlement-layer-handoff-check)
      shift
      phase5_settlement_layer_handoff_check "$@"
      ;;
    phase5-settlement-layer-handoff-run)
      shift
      phase5_settlement_layer_handoff_run "$@"
      ;;
    phase5-settlement-layer-summary-report)
      shift
      phase5_settlement_layer_summary_report "$@"
      ;;
    issuer-sponsor-api-live-smoke)
      shift
      issuer_sponsor_api_live_smoke "$@"
      ;;
    issuer-settlement-status-live-smoke)
      shift
      issuer_settlement_status_live_smoke "$@"
      ;;
    ci-phase6-cosmos-l1-build-testnet)
      shift
      ci_phase6_cosmos_l1_build_testnet "$@"
      ;;
    ci-phase6-cosmos-l1-contracts)
      shift
      ci_phase6_cosmos_l1_contracts "$@"
      ;;
    phase6-cosmos-l1-build-testnet-check)
      shift
      phase6_cosmos_l1_build_testnet_check "$@"
      ;;
    phase6-cosmos-l1-build-testnet-run)
      shift
      phase6_cosmos_l1_build_testnet_run "$@"
      ;;
    phase6-cosmos-l1-build-testnet-handoff-check)
      shift
      phase6_cosmos_l1_build_testnet_handoff_check "$@"
      ;;
    phase6-cosmos-l1-build-testnet-handoff-run)
      shift
      phase6_cosmos_l1_build_testnet_handoff_run "$@"
      ;;
    phase6-cosmos-l1-build-testnet-suite)
      shift
      phase6_cosmos_l1_build_testnet_suite "$@"
      ;;
    phase6-cosmos-l1-summary-report)
      shift
      phase6_cosmos_l1_summary_report "$@"
      ;;
    ci-phase7-mainnet-cutover)
      shift
      ci_phase7_mainnet_cutover "$@"
      ;;
    phase7-mainnet-cutover-check)
      shift
      phase7_mainnet_cutover_check "$@"
      ;;
    phase7-mainnet-cutover-run)
      shift
      phase7_mainnet_cutover_run "$@"
      ;;
    phase7-mainnet-cutover-handoff-check)
      shift
      phase7_mainnet_cutover_handoff_check "$@"
      ;;
    phase7-mainnet-cutover-handoff-run)
      shift
      phase7_mainnet_cutover_handoff_run "$@"
      ;;
    phase7-mainnet-cutover-summary-report)
      shift
      phase7_mainnet_cutover_summary_report "$@"
      ;;
    manual-validation-status)
      shift
      manual_validation_status "$@"
      ;;
    manual-validation-report)
      shift
      manual_validation_report "$@"
      ;;
    roadmap-progress-report)
      shift
      roadmap_progress_report "$@"
      ;;
    pre-real-host-readiness)
      shift
      pre_real_host_readiness "$@"
      ;;
    manual-validation-record)
      shift
      manual_validation_record "$@"
      ;;
    runtime-doctor)
      shift
      runtime_doctor "$@"
      ;;
    runtime-fix)
      shift
      runtime_fix "$@"
      ;;
    runtime-fix-record)
      shift
      runtime_fix_record "$@"
      ;;
    prod-gate-check)
      shift
      prod_gate_check "$@"
      ;;
    prod-gate-slo-summary)
      shift
      prod_gate_slo_summary "$@"
      ;;
    prod-gate-slo-trend)
      shift
      prod_gate_slo_trend "$@"
      ;;
    prod-gate-slo-alert)
      shift
      prod_gate_slo_alert "$@"
      ;;
    prod-gate-slo-dashboard)
      shift
      prod_gate_slo_dashboard "$@"
      ;;
    prod-gate-bundle-verify)
      shift
      prod_gate_bundle_verify "$@"
      ;;
    prod-gate-signoff)
      shift
      prod_gate_signoff "$@"
      ;;
    prod-wg-validate)
      shift
      prod_wg_validate "$@"
      ;;
    prod-wg-soak)
      shift
      prod_wg_soak "$@"
      ;;
    prod-wg-strict-ingress-rehearsal)
      shift
      prod_wg_strict_ingress_rehearsal "$@"
      ;;
    invite-generate)
      shift
      invite_generate "$@"
      ;;
    invite-check)
      shift
      invite_check "$@"
      ;;
    invite-disable)
      shift
      invite_disable "$@"
      ;;
    admin-signing-status)
      shift
      admin_signing_status "$@"
      ;;
    admin-signing-rotate)
      shift
      admin_signing_rotate "$@"
      ;;
    prod-preflight)
      shift
      prod_preflight "$@"
      ;;
    bootstrap-mtls)
      shift
      bootstrap_mtls "$@"
      ;;
    machine-a-test)
      shift
      machine_a_test "$@"
      ;;
    machine-b-test)
      shift
      machine_b_test "$@"
      ;;
    machine-c-test)
      shift
      machine_c_test "$@"
      ;;
    pilot-runbook)
      shift
      pilot_runbook "$@"
      ;;
    prod-pilot-runbook)
      shift
      prod_pilot_runbook "$@"
      ;;
    prod-pilot-cohort-runbook)
      shift
      prod_pilot_cohort_runbook "$@"
      ;;
    prod-pilot-cohort-campaign)
      shift
      prod_pilot_cohort_campaign "$@"
      ;;
    prod-pilot-cohort-campaign-summary)
      shift
      prod_pilot_cohort_campaign_summary "$@"
      ;;
    prod-pilot-cohort-campaign-check)
      shift
      prod_pilot_cohort_campaign_check "$@"
      ;;
    prod-pilot-cohort-campaign-signoff)
      shift
      prod_pilot_cohort_campaign_signoff "$@"
      ;;
    prod-pilot-cohort-quick)
      shift
      prod_pilot_cohort_quick "$@"
      ;;
    prod-pilot-cohort-bundle-verify)
      shift
      prod_pilot_cohort_bundle_verify "$@"
      ;;
    prod-pilot-cohort-check)
      shift
      prod_pilot_cohort_check "$@"
      ;;
    prod-pilot-cohort-signoff)
      shift
      prod_pilot_cohort_signoff "$@"
      ;;
    prod-pilot-cohort-quick-check)
      shift
      prod_pilot_cohort_quick_check "$@"
      ;;
    prod-pilot-cohort-quick-trend)
      shift
      prod_pilot_cohort_quick_trend "$@"
      ;;
    prod-pilot-cohort-quick-alert)
      shift
      prod_pilot_cohort_quick_alert "$@"
      ;;
    prod-pilot-cohort-quick-dashboard)
      shift
      prod_pilot_cohort_quick_dashboard "$@"
      ;;
    prod-pilot-cohort-quick-signoff)
      shift
      prod_pilot_cohort_quick_signoff "$@"
      ;;
    prod-pilot-cohort-quick-runbook)
      shift
      prod_pilot_cohort_quick_runbook "$@"
      ;;
    prod-key-rotation-runbook)
      shift
      prod_key_rotation_runbook "$@"
      ;;
    prod-upgrade-runbook)
      shift
      prod_upgrade_runbook "$@"
      ;;
    prod-operator-lifecycle-runbook)
      shift
      prod_operator_lifecycle_runbook "$@"
      ;;
    incident-snapshot)
      shift
      incident_snapshot "$@"
      ;;
    incident-snapshot-summary)
      shift
      incident_snapshot_summary "$@"
      ;;
    discover-hosts)
      shift
      discover_hosts "$@"
      ;;
    -h|--help|help|"")
      if root_help_is_expert "$@"; then
        usage || true
      else
        usage_concise || true
      fi
      ;;
    *)
      echo "unknown command: $cmd"
      usage
      exit 2
      ;;
  esac
}

main "$@"
