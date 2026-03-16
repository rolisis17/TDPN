#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EASY_NODE_SH="${EASY_NODE_SH:-$ROOT_DIR/scripts/easy_node.sh}"
CURL_BIN="${PROD_OPERATOR_LIFECYCLE_CURL_BIN:-curl}"

MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"
AUTH_ENV_FILE="$ROOT_DIR/deploy/.env.easy.server"
PROVIDER_ENV_FILE="$ROOT_DIR/deploy/.env.easy.provider"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    echo ""
    return
  fi
  if [[ "$path" == /* ]]; then
    echo "$path"
  else
    echo "$ROOT_DIR/$path"
  fi
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

bool_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

int_or_die() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an integer >= 0"
    exit 2
  fi
}

csv_count() {
  local value
  value="$(trim "${1:-}")"
  if [[ -z "$value" ]]; then
    echo "0"
    return
  fi
  awk -F',' '
    {
      count = 0
      for (i = 1; i <= NF; i++) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $i)
        if ($i != "") {
          count++
        }
      }
      print count
    }
  ' <<<"$value"
}

json_bool() {
  if [[ "${1:-0}" == "1" ]]; then
    echo "true"
  else
    echo "false"
  fi
}

mode_env_file() {
  local mode="$1"
  if [[ "$mode" == "provider" ]]; then
    echo "$PROVIDER_ENV_FILE"
  else
    echo "$AUTH_ENV_FILE"
  fi
}

active_mode_from_file() {
  if [[ -f "$MODE_FILE" ]]; then
    local mode
    mode="$(awk -F= '$1=="EASY_NODE_SERVER_MODE"{print $2; exit}' "$MODE_FILE")"
    mode="$(trim "$mode")"
    if [[ "$mode" == "authority" || "$mode" == "provider" ]]; then
      echo "$mode"
      return
    fi
  fi
  echo "authority"
}

identity_value() {
  local env_file="$1"
  local key="$2"
  local value=""
  if [[ -f "$env_file" ]]; then
    value="$(awk -F= -v key="$key" '$1==key{print $2; exit}' "$env_file")"
  fi
  trim "$value"
}

normalized_directory_base() {
  local input
  input="$(trim "${1:-}")"
  input="${input%/}"
  if [[ "$input" == */v1/relays ]]; then
    input="${input%/v1/relays}"
  fi
  echo "$input"
}

wait_http_ok() {
  local url="$1"
  local name="$2"
  local attempts="$3"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if "$CURL_BIN" -fsS --connect-timeout 2 --max-time 5 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "$name did not become healthy at $url"
  return 1
}

operator_relay_count() {
  local directory_base="$1"
  local operator_id="$2"
  local payload
  payload="$("$CURL_BIN" -fsS --connect-timeout 2 --max-time 5 "${directory_base}/v1/relays")"
  jq -r --arg operator "$operator_id" '[.relays[]? | select(.operator_id == $operator)] | length' <<<"$payload"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_operator_lifecycle_runbook.sh \
    [--action onboard|offboard] \
    [--mode auto|authority|provider] \
    [--public-host HOST] \
    [--operator-id ID] \
    [--issuer-id ID] \
    [--issuer-admin-token TOKEN] \
    [--directory-admin-token TOKEN] \
    [--entry-puzzle-secret SECRET] \
    [--authority-directory URL] \
    [--authority-issuer URL] \
    [--peer-directories URLS] \
    [--bootstrap-directory URL] \
    [--peer-identity-strict 0|1|auto] \
    [--min-peer-operators N] \
    [--client-allowlist [0|1]] \
    [--allow-anon-cred [0|1]] \
    [--beta-profile [0|1]] \
    [--prod-profile [0|1]] \
    [--show-admin-token [0|1]] \
    [--preflight-check [0|1]] \
    [--preflight-timeout-sec N] \
    [--health-check [0|1]] \
    [--health-timeout-sec N] \
    [--directory-url URL] \
    [--verify-relays [0|1]] \
    [--verify-absent [0|1]] \
    [--verify-relay-timeout-sec N] \
    [--verify-relay-min-count N] \
    [--federation-check [0|1]] \
    [--federation-ready-timeout-sec N] \
    [--federation-poll-sec N] \
    [--federation-timeout-sec N] \
    [--federation-require-configured-healthy [0|1]] \
    [--federation-max-cooling-retry-sec N] \
    [--federation-max-peer-sync-age-sec N] \
    [--federation-max-issuer-sync-age-sec N] \
    [--federation-min-peer-success-sources N] \
    [--federation-min-issuer-success-sources N] \
    [--federation-min-peer-source-operators N] \
    [--federation-min-issuer-source-operators N] \
    [--federation-wait-file PATH] \
    [--federation-wait-file-required [0|1]] \
    [--federation-wait-summary-json PATH] \
    [--federation-wait-print-summary-json [0|1]] \
    [--federation-wait-summary-required [0|1]] \
    [--federation-status-fail-on-not-ready [0|1]] \
    [--federation-status-file PATH] \
    [--federation-status-file-required [0|1]] \
    [--federation-status-summary-json PATH] \
    [--federation-status-summary-required [0|1]] \
    [--onboard-invite [0|1]] \
    [--onboard-invite-count N] \
    [--onboard-invite-tier 1|2|3] \
    [--onboard-invite-wait-sec N] \
    [--onboard-invite-fail-open [0|1]] \
    [--onboard-invite-file PATH] \
    [--rollback-on-fail [0|1]] \
    [--rollback-verify-absent [0|1]] \
    [--rollback-verify-timeout-sec N] \
    [--runtime-doctor-on-fail [0|1]] \
    [--runtime-doctor-base-port N] \
    [--runtime-doctor-client-iface IFACE] \
    [--runtime-doctor-exit-iface IFACE] \
    [--runtime-doctor-vpn-iface IFACE] \
    [--runtime-doctor-file PATH] \
    [--runtime-doctor-file-required [0|1]] \
    [--incident-snapshot-on-fail [0|1]] \
    [--incident-bundle-dir PATH] \
    [--incident-timeout-sec N] \
    [--incident-include-docker-logs [0|1]] \
    [--incident-docker-log-lines N] \
    [--incident-summary-required [0|1]] \
    [--incident-bundle-required [0|1]] \
    [--incident-attachment-manifest-required [0|1]] \
    [--incident-attachment-no-skips-required [0|1]] \
    [--incident-attach-min-count N] \
    [--incident-attachment-manifest-min-count N] \
    [--incident-attach-artifact PATH]... \
    [--report-md PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Operator-safe onboarding/offboarding runbook with health and relay visibility checks.

Actions:
  - onboard (default): optional preflight -> server-up -> optional health checks ->
    optional federation readiness gate -> optional relay publication verification on directory feed.
    authority mode can optionally auto-generate onboarding invite keys after successful startup/verification.
    when onboarding fails after startup, optional rollback can stop the stack and verify relay disappearance.
    failed runs can optionally capture runtime-doctor diagnostics before incident handoff.
    failed runs can optionally auto-capture an incident snapshot bundle for operator handoff.
  - offboard: server-down -> optional relay disappearance verification.
USAGE
}

for cmd in bash jq date awk mktemp mkdir; do
  need_cmd "$cmd"
done
if [[ ! -x "$EASY_NODE_SH" ]]; then
  echo "missing executable easy_node wrapper: $EASY_NODE_SH"
  exit 2
fi

action="onboard"
mode="auto"
public_host=""
operator_id=""
issuer_id=""
issuer_admin_token=""
directory_admin_token=""
entry_puzzle_secret=""
authority_directory=""
authority_issuer=""
peer_directories=""
bootstrap_directory=""
peer_identity_strict=""
min_peer_operators=""
client_allowlist=""
allow_anon_cred=""
beta_profile=""
prod_profile=""
show_admin_token=""
preflight_check="${PROD_OPERATOR_LIFECYCLE_PREFLIGHT_CHECK:-1}"
preflight_timeout_sec="${PROD_OPERATOR_LIFECYCLE_PREFLIGHT_TIMEOUT_SEC:-30}"
health_check="${PROD_OPERATOR_LIFECYCLE_HEALTH_CHECK:-1}"
health_timeout_sec="${PROD_OPERATOR_LIFECYCLE_HEALTH_TIMEOUT_SEC:-60}"
directory_url=""
verify_relays="${PROD_OPERATOR_LIFECYCLE_VERIFY_RELAYS:-1}"
verify_absent="${PROD_OPERATOR_LIFECYCLE_VERIFY_ABSENT:-1}"
verify_relay_timeout_sec="${PROD_OPERATOR_LIFECYCLE_VERIFY_RELAY_TIMEOUT_SEC:-90}"
verify_relay_min_count="${PROD_OPERATOR_LIFECYCLE_VERIFY_RELAY_MIN_COUNT:-2}"
federation_check="${PROD_OPERATOR_LIFECYCLE_FEDERATION_CHECK:-1}"
federation_ready_timeout_sec="${PROD_OPERATOR_LIFECYCLE_FEDERATION_READY_TIMEOUT_SEC:-90}"
federation_poll_sec="${PROD_OPERATOR_LIFECYCLE_FEDERATION_POLL_SEC:-5}"
federation_timeout_sec="${PROD_OPERATOR_LIFECYCLE_FEDERATION_TIMEOUT_SEC:-8}"
federation_require_configured_healthy="${PROD_OPERATOR_LIFECYCLE_FEDERATION_REQUIRE_CONFIGURED_HEALTHY:-0}"
federation_max_cooling_retry_sec="${PROD_OPERATOR_LIFECYCLE_FEDERATION_MAX_COOLING_RETRY_SEC:-0}"
federation_max_peer_sync_age_sec="${PROD_OPERATOR_LIFECYCLE_FEDERATION_MAX_PEER_SYNC_AGE_SEC:-0}"
federation_max_issuer_sync_age_sec="${PROD_OPERATOR_LIFECYCLE_FEDERATION_MAX_ISSUER_SYNC_AGE_SEC:-0}"
federation_min_peer_success_sources="${PROD_OPERATOR_LIFECYCLE_FEDERATION_MIN_PEER_SUCCESS_SOURCES:-0}"
federation_min_issuer_success_sources="${PROD_OPERATOR_LIFECYCLE_FEDERATION_MIN_ISSUER_SUCCESS_SOURCES:-0}"
federation_min_peer_source_operators="${PROD_OPERATOR_LIFECYCLE_FEDERATION_MIN_PEER_SOURCE_OPERATORS:-0}"
federation_min_issuer_source_operators="${PROD_OPERATOR_LIFECYCLE_FEDERATION_MIN_ISSUER_SOURCE_OPERATORS:-0}"
federation_wait_file=""
federation_wait_file_required="${PROD_OPERATOR_LIFECYCLE_FEDERATION_WAIT_FILE_REQUIRED:-0}"
federation_wait_summary_json=""
federation_wait_print_summary_json="${PROD_OPERATOR_LIFECYCLE_FEDERATION_WAIT_PRINT_SUMMARY_JSON:-0}"
federation_wait_summary_required="${PROD_OPERATOR_LIFECYCLE_FEDERATION_WAIT_SUMMARY_REQUIRED:-0}"
federation_status_fail_on_not_ready="${PROD_OPERATOR_LIFECYCLE_FEDERATION_STATUS_FAIL_ON_NOT_READY:-0}"
federation_status_file=""
federation_status_file_required="${PROD_OPERATOR_LIFECYCLE_FEDERATION_STATUS_FILE_REQUIRED:-0}"
federation_status_summary_json=""
federation_status_summary_required="${PROD_OPERATOR_LIFECYCLE_FEDERATION_STATUS_SUMMARY_REQUIRED:-0}"
onboard_invite="${PROD_OPERATOR_LIFECYCLE_ONBOARD_INVITE:-0}"
onboard_invite_count="${PROD_OPERATOR_LIFECYCLE_ONBOARD_INVITE_COUNT:-1}"
onboard_invite_tier="${PROD_OPERATOR_LIFECYCLE_ONBOARD_INVITE_TIER:-1}"
onboard_invite_wait_sec="${PROD_OPERATOR_LIFECYCLE_ONBOARD_INVITE_WAIT_SEC:-10}"
onboard_invite_fail_open="${PROD_OPERATOR_LIFECYCLE_ONBOARD_INVITE_FAIL_OPEN:-1}"
onboard_invite_file=""
rollback_on_fail="${PROD_OPERATOR_LIFECYCLE_ROLLBACK_ON_FAIL:-1}"
rollback_verify_absent="${PROD_OPERATOR_LIFECYCLE_ROLLBACK_VERIFY_ABSENT:-1}"
rollback_verify_timeout_sec="${PROD_OPERATOR_LIFECYCLE_ROLLBACK_VERIFY_TIMEOUT_SEC:-90}"
runtime_doctor_on_fail="${PROD_OPERATOR_LIFECYCLE_RUNTIME_DOCTOR_ON_FAIL:-1}"
runtime_doctor_base_port="${PROD_OPERATOR_LIFECYCLE_RUNTIME_DOCTOR_BASE_PORT:-19280}"
runtime_doctor_client_iface="${PROD_OPERATOR_LIFECYCLE_RUNTIME_DOCTOR_CLIENT_IFACE:-wgcstack0}"
runtime_doctor_exit_iface="${PROD_OPERATOR_LIFECYCLE_RUNTIME_DOCTOR_EXIT_IFACE:-wgestack0}"
runtime_doctor_vpn_iface="${PROD_OPERATOR_LIFECYCLE_RUNTIME_DOCTOR_VPN_IFACE:-wgvpn0}"
runtime_doctor_file=""
runtime_doctor_file_required="${PROD_OPERATOR_LIFECYCLE_RUNTIME_DOCTOR_FILE_REQUIRED:-0}"
incident_snapshot_on_fail="${PROD_OPERATOR_LIFECYCLE_INCIDENT_SNAPSHOT_ON_FAIL:-1}"
incident_bundle_dir=""
incident_timeout_sec="${PROD_OPERATOR_LIFECYCLE_INCIDENT_TIMEOUT_SEC:-20}"
incident_include_docker_logs="${PROD_OPERATOR_LIFECYCLE_INCIDENT_INCLUDE_DOCKER_LOGS:-1}"
incident_docker_log_lines="${PROD_OPERATOR_LIFECYCLE_INCIDENT_DOCKER_LOG_LINES:-120}"
incident_summary_required="${PROD_OPERATOR_LIFECYCLE_INCIDENT_SUMMARY_REQUIRED:-0}"
incident_bundle_required="${PROD_OPERATOR_LIFECYCLE_INCIDENT_BUNDLE_REQUIRED:-0}"
incident_attachment_manifest_required="${PROD_OPERATOR_LIFECYCLE_INCIDENT_ATTACHMENT_MANIFEST_REQUIRED:-0}"
incident_attachment_no_skips_required="${PROD_OPERATOR_LIFECYCLE_INCIDENT_ATTACHMENT_NO_SKIPS_REQUIRED:-0}"
incident_attach_min_count="${PROD_OPERATOR_LIFECYCLE_INCIDENT_ATTACH_MIN_COUNT:-0}"
incident_attachment_manifest_min_count="${PROD_OPERATOR_LIFECYCLE_INCIDENT_ATTACHMENT_MANIFEST_MIN_COUNT:-0}"
declare -a incident_attach_artifacts_cli=()
report_md=""
summary_json=""
print_summary_json="${PROD_OPERATOR_LIFECYCLE_PRINT_SUMMARY_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --action)
      action="${2:-}"
      shift 2
      ;;
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
    --issuer-admin-token)
      issuer_admin_token="${2:-}"
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
      peer_directories="${2:-}"
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
    --client-allowlist)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        client_allowlist="${2:-}"
        shift 2
      else
        client_allowlist="1"
        shift
      fi
      ;;
    --allow-anon-cred)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_anon_cred="${2:-}"
        shift 2
      else
        allow_anon_cred="1"
        shift
      fi
      ;;
    --beta-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        beta_profile="${2:-}"
        shift 2
      else
        beta_profile="1"
        shift
      fi
      ;;
    --prod-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        prod_profile="${2:-}"
        shift 2
      else
        prod_profile="1"
        shift
      fi
      ;;
    --show-admin-token)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_admin_token="${2:-}"
        shift 2
      else
        show_admin_token="1"
        shift
      fi
      ;;
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
    --health-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        health_check="${2:-}"
        shift 2
      else
        health_check="1"
        shift
      fi
      ;;
    --health-timeout-sec)
      health_timeout_sec="${2:-}"
      shift 2
      ;;
    --directory-url)
      directory_url="${2:-}"
      shift 2
      ;;
    --verify-relays)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        verify_relays="${2:-}"
        shift 2
      else
        verify_relays="1"
        shift
      fi
      ;;
    --verify-absent)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        verify_absent="${2:-}"
        shift 2
      else
        verify_absent="1"
        shift
      fi
      ;;
    --verify-relay-timeout-sec)
      verify_relay_timeout_sec="${2:-}"
      shift 2
      ;;
    --verify-relay-min-count)
      verify_relay_min_count="${2:-}"
      shift 2
      ;;
    --federation-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        federation_check="${2:-}"
        shift 2
      else
        federation_check="1"
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
    --federation-timeout-sec)
      federation_timeout_sec="${2:-}"
      shift 2
      ;;
    --federation-require-configured-healthy)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
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
    --federation-wait-file)
      federation_wait_file="${2:-}"
      shift 2
      ;;
    --federation-wait-file-required)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        federation_wait_file_required="${2:-}"
        shift 2
      else
        federation_wait_file_required="1"
        shift
      fi
      ;;
    --federation-wait-summary-json)
      federation_wait_summary_json="${2:-}"
      shift 2
      ;;
    --federation-wait-print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        federation_wait_print_summary_json="${2:-}"
        shift 2
      else
        federation_wait_print_summary_json="1"
        shift
      fi
      ;;
    --federation-wait-summary-required)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        federation_wait_summary_required="${2:-}"
        shift 2
      else
        federation_wait_summary_required="1"
        shift
      fi
      ;;
    --federation-status-fail-on-not-ready)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        federation_status_fail_on_not_ready="${2:-}"
        shift 2
      else
        federation_status_fail_on_not_ready="1"
        shift
      fi
      ;;
    --federation-status-file)
      federation_status_file="${2:-}"
      shift 2
      ;;
    --federation-status-file-required)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        federation_status_file_required="${2:-}"
        shift 2
      else
        federation_status_file_required="1"
        shift
      fi
      ;;
    --federation-status-summary-json)
      federation_status_summary_json="${2:-}"
      shift 2
      ;;
    --federation-status-summary-required)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        federation_status_summary_required="${2:-}"
        shift 2
      else
        federation_status_summary_required="1"
        shift
      fi
      ;;
    --onboard-invite)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        onboard_invite="${2:-}"
        shift 2
      else
        onboard_invite="1"
        shift
      fi
      ;;
    --onboard-invite-count)
      onboard_invite_count="${2:-}"
      shift 2
      ;;
    --onboard-invite-tier)
      onboard_invite_tier="${2:-}"
      shift 2
      ;;
    --onboard-invite-wait-sec)
      onboard_invite_wait_sec="${2:-}"
      shift 2
      ;;
    --onboard-invite-fail-open)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        onboard_invite_fail_open="${2:-}"
        shift 2
      else
        onboard_invite_fail_open="1"
        shift
      fi
      ;;
    --onboard-invite-file)
      onboard_invite_file="${2:-}"
      shift 2
      ;;
    --rollback-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        rollback_on_fail="${2:-}"
        shift 2
      else
        rollback_on_fail="1"
        shift
      fi
      ;;
    --rollback-verify-absent)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        rollback_verify_absent="${2:-}"
        shift 2
      else
        rollback_verify_absent="1"
        shift
      fi
      ;;
    --rollback-verify-timeout-sec)
      rollback_verify_timeout_sec="${2:-}"
      shift 2
      ;;
    --runtime-doctor-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        runtime_doctor_on_fail="${2:-}"
        shift 2
      else
        runtime_doctor_on_fail="1"
        shift
      fi
      ;;
    --runtime-doctor-base-port)
      runtime_doctor_base_port="${2:-}"
      shift 2
      ;;
    --runtime-doctor-client-iface)
      runtime_doctor_client_iface="${2:-}"
      shift 2
      ;;
    --runtime-doctor-exit-iface)
      runtime_doctor_exit_iface="${2:-}"
      shift 2
      ;;
    --runtime-doctor-vpn-iface)
      runtime_doctor_vpn_iface="${2:-}"
      shift 2
      ;;
    --runtime-doctor-file)
      runtime_doctor_file="${2:-}"
      shift 2
      ;;
    --runtime-doctor-file-required)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        runtime_doctor_file_required="${2:-}"
        shift 2
      else
        runtime_doctor_file_required="1"
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
    --incident-bundle-dir)
      incident_bundle_dir="${2:-}"
      shift 2
      ;;
    --incident-timeout-sec)
      incident_timeout_sec="${2:-}"
      shift 2
      ;;
    --incident-include-docker-logs)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        incident_include_docker_logs="${2:-}"
        shift 2
      else
        incident_include_docker_logs="1"
        shift
      fi
      ;;
    --incident-docker-log-lines)
      incident_docker_log_lines="${2:-}"
      shift 2
      ;;
    --incident-summary-required)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        incident_summary_required="${2:-}"
        shift 2
      else
        incident_summary_required="1"
        shift
      fi
      ;;
    --incident-bundle-required)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        incident_bundle_required="${2:-}"
        shift 2
      else
        incident_bundle_required="1"
        shift
      fi
      ;;
    --incident-attachment-manifest-required)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        incident_attachment_manifest_required="${2:-}"
        shift 2
      else
        incident_attachment_manifest_required="1"
        shift
      fi
      ;;
    --incident-attachment-no-skips-required)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        incident_attachment_no_skips_required="${2:-}"
        shift 2
      else
        incident_attachment_no_skips_required="1"
        shift
      fi
      ;;
    --incident-attach-min-count)
      incident_attach_min_count="${2:-}"
      shift 2
      ;;
    --incident-attachment-manifest-min-count)
      incident_attachment_manifest_min_count="${2:-}"
      shift 2
      ;;
    --incident-attach-artifact)
      incident_attach_artifacts_cli+=("${2:-}")
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
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
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

if [[ "$action" != "onboard" && "$action" != "offboard" ]]; then
  echo "--action must be onboard or offboard"
  exit 2
fi
if [[ "$mode" != "auto" && "$mode" != "authority" && "$mode" != "provider" ]]; then
  echo "--mode must be auto, authority, or provider"
  exit 2
fi
if [[ -n "$peer_identity_strict" && "$peer_identity_strict" != "0" && "$peer_identity_strict" != "1" && "$peer_identity_strict" != "auto" ]]; then
  echo "--peer-identity-strict must be 0, 1, or auto"
  exit 2
fi
if [[ -n "$client_allowlist" ]]; then
  bool_or_die "--client-allowlist" "$client_allowlist"
fi
if [[ -n "$allow_anon_cred" ]]; then
  bool_or_die "--allow-anon-cred" "$allow_anon_cred"
fi
if [[ -n "$beta_profile" ]]; then
  bool_or_die "--beta-profile" "$beta_profile"
fi
if [[ -n "$prod_profile" ]]; then
  bool_or_die "--prod-profile" "$prod_profile"
fi
if [[ -n "$show_admin_token" ]]; then
  bool_or_die "--show-admin-token" "$show_admin_token"
fi
bool_or_die "--preflight-check" "$preflight_check"
bool_or_die "--health-check" "$health_check"
bool_or_die "--verify-relays" "$verify_relays"
bool_or_die "--verify-absent" "$verify_absent"
bool_or_die "--federation-check" "$federation_check"
bool_or_die "--federation-require-configured-healthy" "$federation_require_configured_healthy"
bool_or_die "--federation-wait-file-required" "$federation_wait_file_required"
bool_or_die "--federation-wait-print-summary-json" "$federation_wait_print_summary_json"
bool_or_die "--federation-wait-summary-required" "$federation_wait_summary_required"
bool_or_die "--federation-status-fail-on-not-ready" "$federation_status_fail_on_not_ready"
bool_or_die "--federation-status-file-required" "$federation_status_file_required"
bool_or_die "--federation-status-summary-required" "$federation_status_summary_required"
bool_or_die "--onboard-invite" "$onboard_invite"
bool_or_die "--onboard-invite-fail-open" "$onboard_invite_fail_open"
bool_or_die "--rollback-on-fail" "$rollback_on_fail"
bool_or_die "--rollback-verify-absent" "$rollback_verify_absent"
bool_or_die "--runtime-doctor-on-fail" "$runtime_doctor_on_fail"
bool_or_die "--runtime-doctor-file-required" "$runtime_doctor_file_required"
bool_or_die "--incident-snapshot-on-fail" "$incident_snapshot_on_fail"
bool_or_die "--incident-include-docker-logs" "$incident_include_docker_logs"
bool_or_die "--incident-summary-required" "$incident_summary_required"
bool_or_die "--incident-bundle-required" "$incident_bundle_required"
bool_or_die "--incident-attachment-manifest-required" "$incident_attachment_manifest_required"
bool_or_die "--incident-attachment-no-skips-required" "$incident_attachment_no_skips_required"
bool_or_die "--print-summary-json" "$print_summary_json"
int_or_die "--preflight-timeout-sec" "$preflight_timeout_sec"
int_or_die "--health-timeout-sec" "$health_timeout_sec"
int_or_die "--verify-relay-timeout-sec" "$verify_relay_timeout_sec"
int_or_die "--verify-relay-min-count" "$verify_relay_min_count"
int_or_die "--federation-ready-timeout-sec" "$federation_ready_timeout_sec"
int_or_die "--federation-poll-sec" "$federation_poll_sec"
int_or_die "--federation-timeout-sec" "$federation_timeout_sec"
int_or_die "--federation-max-cooling-retry-sec" "$federation_max_cooling_retry_sec"
int_or_die "--federation-max-peer-sync-age-sec" "$federation_max_peer_sync_age_sec"
int_or_die "--federation-max-issuer-sync-age-sec" "$federation_max_issuer_sync_age_sec"
int_or_die "--federation-min-peer-success-sources" "$federation_min_peer_success_sources"
int_or_die "--federation-min-issuer-success-sources" "$federation_min_issuer_success_sources"
int_or_die "--federation-min-peer-source-operators" "$federation_min_peer_source_operators"
int_or_die "--federation-min-issuer-source-operators" "$federation_min_issuer_source_operators"
int_or_die "--onboard-invite-count" "$onboard_invite_count"
int_or_die "--onboard-invite-wait-sec" "$onboard_invite_wait_sec"
int_or_die "--rollback-verify-timeout-sec" "$rollback_verify_timeout_sec"
int_or_die "--runtime-doctor-base-port" "$runtime_doctor_base_port"
int_or_die "--incident-timeout-sec" "$incident_timeout_sec"
int_or_die "--incident-docker-log-lines" "$incident_docker_log_lines"
int_or_die "--incident-attach-min-count" "$incident_attach_min_count"
int_or_die "--incident-attachment-manifest-min-count" "$incident_attachment_manifest_min_count"
if ((federation_ready_timeout_sec < 1)); then
  echo "--federation-ready-timeout-sec must be >= 1"
  exit 2
fi
if ((federation_poll_sec < 1)); then
  echo "--federation-poll-sec must be >= 1"
  exit 2
fi
if ((federation_timeout_sec < 1)); then
  echo "--federation-timeout-sec must be >= 1"
  exit 2
fi
if ((onboard_invite_count < 1)); then
  echo "--onboard-invite-count must be >= 1"
  exit 2
fi
if [[ "$onboard_invite_tier" != "1" && "$onboard_invite_tier" != "2" && "$onboard_invite_tier" != "3" ]]; then
  echo "--onboard-invite-tier must be 1, 2, or 3"
  exit 2
fi
if ((rollback_verify_timeout_sec < 1)); then
  echo "--rollback-verify-timeout-sec must be >= 1"
  exit 2
fi
if ((runtime_doctor_base_port < 1)); then
  echo "--runtime-doctor-base-port must be >= 1"
  exit 2
fi
if ((incident_timeout_sec < 1)); then
  echo "--incident-timeout-sec must be >= 1"
  exit 2
fi
if ((incident_docker_log_lines < 1)); then
  echo "--incident-docker-log-lines must be >= 1"
  exit 2
fi
if [[ -n "$min_peer_operators" ]]; then
  int_or_die "--min-peer-operators" "$min_peer_operators"
fi

resolved_mode="$mode"
if [[ "$resolved_mode" == "auto" ]]; then
  resolved_mode="$(active_mode_from_file)"
fi

if [[ -z "$summary_json" ]]; then
  mkdir -p "$(default_log_dir)"
  ts="$(date -u +%Y%m%d_%H%M%S)"
  summary_json="$(default_log_dir)/prod_operator_lifecycle_${action}_${ts}.json"
fi
summary_json="$(abs_path "$summary_json")"
mkdir -p "$(dirname "$summary_json")"
if [[ -z "$report_md" ]]; then
  report_md="${summary_json%.json}.report.md"
fi
report_md="$(abs_path "$report_md")"
mkdir -p "$(dirname "$report_md")"
if [[ -z "$federation_status_file" ]]; then
  federation_status_file="${summary_json%.json}.federation_status.log"
fi
federation_status_file="$(abs_path "$federation_status_file")"
mkdir -p "$(dirname "$federation_status_file")"
if [[ -z "$federation_wait_file" ]]; then
  federation_wait_file="${summary_json%.json}.federation_wait.log"
fi
federation_wait_file="$(abs_path "$federation_wait_file")"
mkdir -p "$(dirname "$federation_wait_file")"
if [[ -z "$federation_wait_summary_json" ]]; then
  federation_wait_summary_json="${summary_json%.json}.federation_wait.summary.json"
fi
federation_wait_summary_json="$(abs_path "$federation_wait_summary_json")"
mkdir -p "$(dirname "$federation_wait_summary_json")"
if [[ -z "$federation_status_summary_json" ]]; then
  federation_status_summary_json="${summary_json%.json}.federation_status.summary.json"
fi
federation_status_summary_json="$(abs_path "$federation_status_summary_json")"
mkdir -p "$(dirname "$federation_status_summary_json")"
if [[ -z "$onboard_invite_file" ]]; then
  onboard_invite_file="${summary_json%.json}.invite_keys.txt"
fi
onboard_invite_file="$(abs_path "$onboard_invite_file")"
mkdir -p "$(dirname "$onboard_invite_file")"
if [[ -z "$incident_bundle_dir" ]]; then
  incident_bundle_dir="${summary_json%.json}.incident_bundle"
fi
incident_bundle_dir="$(abs_path "$incident_bundle_dir")"
mkdir -p "$(dirname "$incident_bundle_dir")"
if [[ -z "$runtime_doctor_file" ]]; then
  runtime_doctor_file="${summary_json%.json}.runtime_doctor.log"
fi
runtime_doctor_file="$(abs_path "$runtime_doctor_file")"
mkdir -p "$(dirname "$runtime_doctor_file")"

resolved_directory_base="$(normalized_directory_base "$directory_url")"
if [[ -z "$resolved_directory_base" ]]; then
  host_for_checks="${public_host:-127.0.0.1}"
  resolved_directory_base="http://${host_for_checks}:8081"
fi

resolved_operator_id="$(trim "$operator_id")"
if [[ -z "$resolved_operator_id" ]]; then
  env_file="$(mode_env_file "$resolved_mode")"
  resolved_operator_id="$(identity_value "$env_file" "DIRECTORY_OPERATOR_ID")"
fi

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_epoch="$(date -u +%s)"
status="ok"
failure_step=""
failure_rc=0
completed_steps_json='[]'
relay_observed_count=-1
server_started=0
federation_wait_state="disabled"
if [[ "$federation_check" == "1" ]]; then
  federation_wait_state="not_run"
fi
federation_wait_capture_rc=0
federation_wait_file_required_met=true
federation_wait_summary_capture_rc=0
federation_wait_summary_state="disabled"
federation_wait_summary_status="disabled"
federation_wait_summary_final_state=""
federation_wait_summary_required_met=true
federation_wait_peer_sync_ready=false
federation_wait_issuer_sync_ready=false
federation_wait_peer_health_ready=false
federation_wait_cooling_retry_exceeded=false
federation_wait_failure_reasons_json='[]'
federation_wait_failure_reasons_csv=""
federation_wait_peer_sync_age_sec=-1
federation_wait_issuer_sync_age_sec=-1
federation_wait_peer_source_operator_count=0
federation_wait_issuer_source_operator_count=0
federation_wait_configured_failing=0
federation_wait_discovered_eligible=0
federation_wait_cooling_retry_max_sec=0
federation_wait_attempts=0
federation_wait_elapsed_sec=0
federation_wait_remaining_sec=0
if [[ "$federation_check" == "1" ]]; then
  federation_wait_summary_state="not_run"
  federation_wait_summary_status="not_run"
fi
effective_peer_directories=""
effective_peer_count=0
federation_status_capture_rc=0
federation_status_file_required_met=true
federation_status_summary_capture_rc=0
federation_status_summary_state="disabled"
federation_status_summary_required_met=true
federation_status_ready=false
federation_status_peer_sync_ready=false
federation_status_issuer_sync_ready=false
federation_status_peer_health_ready=false
federation_status_cooling_retry_exceeded=false
federation_status_failure_reasons_json='[]'
federation_status_failure_reasons_csv=""
federation_status_peer_sync_age_sec=-1
federation_status_issuer_sync_age_sec=-1
federation_status_peer_source_operator_count=0
federation_status_issuer_source_operator_count=0
federation_status_configured_failing=0
federation_status_discovered_eligible=0
federation_status_cooling_retry_max_sec=0
if [[ "$federation_check" == "1" ]]; then
  federation_status_summary_state="not_run"
fi
onboard_invite_state="disabled"
if [[ "$onboard_invite" == "1" ]]; then
  onboard_invite_state="not_run"
  if [[ "$action" != "onboard" ]]; then
    onboard_invite_state="skipped_offboard_action"
  fi
fi
onboard_invite_generated_count=0
onboard_invite_rc=0
rollback_state="not_applicable"
rollback_performed=0
rollback_trigger_step=""
rollback_trigger_rc=0
rollback_server_down_rc=0
rollback_absent_verify_state="not_applicable"
rollback_absent_observed_count=-1
rollback_enabled_effective=0
rollback_verify_absent_effective=0
runtime_doctor_state="disabled"
runtime_doctor_rc=0
runtime_doctor_file_effective=""
runtime_doctor_on_fail_effective=0
runtime_doctor_file_required_met=true
incident_snapshot_state="disabled"
incident_snapshot_rc=0
incident_attach_count=0
incident_attach_list=""
incident_bundle_effective=""
incident_summary_json_effective=""
incident_report_md_effective=""
incident_bundle_tar_effective=""
incident_bundle_tar_sha_effective=""
incident_attachment_manifest_effective=""
incident_attachment_skipped_effective=""
incident_attachment_manifest_count=0
incident_attachment_skipped_count=0
incident_artifact_state="not_applicable"
incident_summary_required_met=true
incident_bundle_required_met=true
incident_required_artifacts_met=true
incident_attachment_manifest_required_met=true
incident_attachment_no_skips_required_met=true
incident_attach_min_count_required_met=true
incident_attachment_manifest_min_count_met=true
incident_required_attachment_policy_met=true
incident_attachment_policy_failure_count=0
incident_required_policies_met=true
if [[ "$runtime_doctor_on_fail" == "1" ]]; then
  runtime_doctor_state="not_run"
  runtime_doctor_on_fail_effective=1
fi
if [[ "$incident_snapshot_on_fail" == "1" ]]; then
  incident_snapshot_state="not_run"
fi
if [[ "$action" == "onboard" ]]; then
  rollback_enabled_effective="$rollback_on_fail"
  if [[ "$rollback_on_fail" == "1" ]]; then
    rollback_state="not_triggered"
    if [[ "$rollback_verify_absent" == "1" ]]; then
      rollback_absent_verify_state="not_run"
      rollback_verify_absent_effective=1
    else
      rollback_absent_verify_state="disabled"
    fi
  else
    rollback_state="disabled"
    rollback_absent_verify_state="disabled"
  fi
fi

step_ok() {
  local name="$1"
  completed_steps_json="$(
    jq -nc --argjson steps "$completed_steps_json" --arg name "$name" '$steps + [$name]'
  )"
}

set_failure() {
  local step="$1"
  local rc="$2"
  status="fail"
  failure_step="$step"
  failure_rc="$rc"
}

if [[ "$action" == "onboard" ]]; then
  if [[ "$preflight_check" == "1" ]]; then
    preflight_cmd=("$EASY_NODE_SH" "server-preflight" "--mode" "$resolved_mode" "--timeout-sec" "$preflight_timeout_sec")
    if [[ -n "$public_host" ]]; then
      preflight_cmd+=("--public-host" "$public_host")
    fi
    if [[ -n "$resolved_operator_id" ]]; then
      preflight_cmd+=("--operator-id" "$resolved_operator_id")
    fi
    if [[ -n "$issuer_id" ]]; then
      preflight_cmd+=("--issuer-id" "$issuer_id")
    fi
    if [[ -n "$authority_directory" ]]; then
      preflight_cmd+=("--authority-directory" "$authority_directory")
    fi
    if [[ -n "$authority_issuer" ]]; then
      preflight_cmd+=("--authority-issuer" "$authority_issuer")
    fi
    if [[ -n "$peer_directories" ]]; then
      preflight_cmd+=("--peer-directories" "$peer_directories")
    fi
    if [[ -n "$bootstrap_directory" ]]; then
      preflight_cmd+=("--bootstrap-directory" "$bootstrap_directory")
    fi
    if [[ -n "$peer_identity_strict" ]]; then
      preflight_cmd+=("--peer-identity-strict" "$peer_identity_strict")
    fi
    if [[ -n "$min_peer_operators" ]]; then
      preflight_cmd+=("--min-peer-operators" "$min_peer_operators")
    fi
    if [[ -n "$beta_profile" ]]; then
      preflight_cmd+=("--beta-profile" "$beta_profile")
    fi
    if [[ -n "$prod_profile" ]]; then
      preflight_cmd+=("--prod-profile" "$prod_profile")
    fi
    set +e
    "${preflight_cmd[@]}"
    rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
      set_failure "server_preflight" "$rc"
    else
      step_ok "server_preflight"
    fi
  fi

  if [[ "$status" == "ok" ]]; then
    server_up_cmd=("$EASY_NODE_SH" "server-up" "--mode" "$resolved_mode")
    if [[ -n "$public_host" ]]; then
      server_up_cmd+=("--public-host" "$public_host")
    fi
    if [[ -n "$resolved_operator_id" ]]; then
      server_up_cmd+=("--operator-id" "$resolved_operator_id")
    fi
    if [[ -n "$issuer_id" ]]; then
      server_up_cmd+=("--issuer-id" "$issuer_id")
    fi
    if [[ -n "$issuer_admin_token" ]]; then
      server_up_cmd+=("--issuer-admin-token" "$issuer_admin_token")
    fi
    if [[ -n "$directory_admin_token" ]]; then
      server_up_cmd+=("--directory-admin-token" "$directory_admin_token")
    fi
    if [[ -n "$entry_puzzle_secret" ]]; then
      server_up_cmd+=("--entry-puzzle-secret" "$entry_puzzle_secret")
    fi
    if [[ -n "$authority_directory" ]]; then
      server_up_cmd+=("--authority-directory" "$authority_directory")
    fi
    if [[ -n "$authority_issuer" ]]; then
      server_up_cmd+=("--authority-issuer" "$authority_issuer")
    fi
    if [[ -n "$peer_directories" ]]; then
      server_up_cmd+=("--peer-directories" "$peer_directories")
    fi
    if [[ -n "$bootstrap_directory" ]]; then
      server_up_cmd+=("--bootstrap-directory" "$bootstrap_directory")
    fi
    if [[ -n "$peer_identity_strict" ]]; then
      server_up_cmd+=("--peer-identity-strict" "$peer_identity_strict")
    fi
    if [[ -n "$client_allowlist" ]]; then
      server_up_cmd+=("--client-allowlist" "$client_allowlist")
    fi
    if [[ -n "$allow_anon_cred" ]]; then
      server_up_cmd+=("--allow-anon-cred" "$allow_anon_cred")
    fi
    if [[ -n "$beta_profile" ]]; then
      server_up_cmd+=("--beta-profile" "$beta_profile")
    fi
    if [[ -n "$prod_profile" ]]; then
      server_up_cmd+=("--prod-profile" "$prod_profile")
    fi
    if [[ -n "$show_admin_token" ]]; then
      server_up_cmd+=("--show-admin-token" "$show_admin_token")
    fi
    set +e
    "${server_up_cmd[@]}"
    rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
      set_failure "server_up" "$rc"
    else
      step_ok "server_up"
      server_started=1
      if [[ -z "$resolved_operator_id" ]]; then
        env_file="$(mode_env_file "$resolved_mode")"
        resolved_operator_id="$(identity_value "$env_file" "DIRECTORY_OPERATOR_ID")"
      fi
    fi
  fi

  if [[ "$status" == "ok" && "$health_check" == "1" ]]; then
    need_cmd "$CURL_BIN"
    host_for_health="${public_host:-127.0.0.1}"
    set +e
    wait_http_ok "${resolved_directory_base}/v1/relays" "directory" "$health_timeout_sec"
    rc=$?
    if [[ "$rc" -eq 0 && "$resolved_mode" == "authority" ]]; then
      wait_http_ok "http://${host_for_health}:8082/v1/pubkeys" "issuer" "$health_timeout_sec"
      rc=$?
    fi
    if [[ "$rc" -eq 0 ]]; then
      wait_http_ok "http://${host_for_health}:8083/v1/health" "entry" "$health_timeout_sec"
      rc=$?
    fi
    if [[ "$rc" -eq 0 ]]; then
      wait_http_ok "http://${host_for_health}:8084/v1/health" "exit" "$health_timeout_sec"
      rc=$?
    fi
    set -e
    if [[ "$rc" -ne 0 ]]; then
      set_failure "health_check" "$rc"
    else
      step_ok "health_check"
    fi
  fi

  if [[ "$status" == "ok" && "$federation_check" == "1" ]]; then
    env_file="$(mode_env_file "$resolved_mode")"
    effective_peer_directories="$(trim "$peer_directories")"
    if [[ -z "$effective_peer_directories" ]]; then
      effective_peer_directories="$(identity_value "$env_file" "DIRECTORY_PEERS")"
    fi
    if [[ -z "$effective_peer_directories" && -n "$bootstrap_directory" ]]; then
      effective_peer_directories="$(trim "$bootstrap_directory")"
    fi
    effective_peer_count="$(csv_count "$effective_peer_directories")"
    if [[ "$effective_peer_count" =~ ^[0-9]+$ ]] && ((effective_peer_count > 0)); then
      rm -f "$federation_wait_file" >/dev/null 2>&1 || true
      rm -f "$federation_wait_summary_json" >/dev/null 2>&1 || true
      set +e
      "$EASY_NODE_SH" server-federation-wait \
        --directory-url "$resolved_directory_base" \
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
        --timeout-sec "$federation_timeout_sec" >"$federation_wait_file" 2>&1
      rc=$?
      set -e
      federation_wait_capture_rc="$rc"
      federation_wait_file_required_met=false
      if [[ -s "$federation_wait_file" ]]; then
        federation_wait_file_required_met=true
      fi
      if [[ -f "$federation_wait_file" ]]; then
        cat "$federation_wait_file"
      fi
      federation_wait_summary_required_met=false
      federation_wait_summary_capture_rc="$rc"
      federation_wait_summary_state="missing_or_invalid"
      if [[ -s "$federation_wait_summary_json" ]] && jq -e '.status != null and .readiness.federation_ready != null' "$federation_wait_summary_json" >/dev/null 2>&1; then
        federation_wait_summary_state="captured"
        federation_wait_summary_required_met=true
        federation_wait_summary_status="$(jq -r '.status // "unknown"' "$federation_wait_summary_json" 2>/dev/null || echo "unknown")"
        federation_wait_summary_final_state="$(jq -r '.state // ""' "$federation_wait_summary_json" 2>/dev/null || true)"
        federation_wait_peer_sync_ready="$(jq -r '.readiness.peer_sync_ready // false' "$federation_wait_summary_json" 2>/dev/null || echo "false")"
        federation_wait_issuer_sync_ready="$(jq -r '.readiness.issuer_sync_ready // false' "$federation_wait_summary_json" 2>/dev/null || echo "false")"
        federation_wait_peer_health_ready="$(jq -r '.readiness.peer_health_ready // false' "$federation_wait_summary_json" 2>/dev/null || echo "false")"
        federation_wait_cooling_retry_exceeded="$(jq -r '.readiness.cooling_retry_exceeded // false' "$federation_wait_summary_json" 2>/dev/null || echo "false")"
        federation_wait_failure_reasons_json="$(jq -c '(.readiness.failure_reasons // []) | if type == "array" then . else [] end' "$federation_wait_summary_json" 2>/dev/null || echo '[]')"
        federation_wait_peer_sync_age_sec="$(jq -r '.observed.peer_sync.age_sec // -1' "$federation_wait_summary_json" 2>/dev/null || echo "-1")"
        federation_wait_issuer_sync_age_sec="$(jq -r '.observed.issuer_sync.age_sec // -1' "$federation_wait_summary_json" 2>/dev/null || echo "-1")"
        federation_wait_peer_source_operator_count="$(jq -r '.observed.peer_sync.source_operator_count // 0' "$federation_wait_summary_json" 2>/dev/null || echo "0")"
        federation_wait_issuer_source_operator_count="$(jq -r '.observed.issuer_sync.source_operator_count // 0' "$federation_wait_summary_json" 2>/dev/null || echo "0")"
        federation_wait_configured_failing="$(jq -r '.observed.peer_health.configured_failing // 0' "$federation_wait_summary_json" 2>/dev/null || echo "0")"
        federation_wait_discovered_eligible="$(jq -r '.observed.peer_health.discovered_eligible // 0' "$federation_wait_summary_json" 2>/dev/null || echo "0")"
        federation_wait_cooling_retry_max_sec="$(jq -r '.observed.peer_summary.cooling_retry_max_sec // 0' "$federation_wait_summary_json" 2>/dev/null || echo "0")"
        federation_wait_attempts="$(jq -r '.timing.attempts // 0' "$federation_wait_summary_json" 2>/dev/null || echo "0")"
        federation_wait_elapsed_sec="$(jq -r '.timing.elapsed_sec // 0' "$federation_wait_summary_json" 2>/dev/null || echo "0")"
        federation_wait_remaining_sec="$(jq -r '.timing.remaining_sec // 0' "$federation_wait_summary_json" 2>/dev/null || echo "0")"
        step_ok "federation_wait_summary"
      else
        federation_wait_summary_status="unknown"
        federation_wait_peer_sync_ready="false"
        federation_wait_issuer_sync_ready="false"
        federation_wait_peer_health_ready="false"
        federation_wait_cooling_retry_exceeded="false"
        federation_wait_failure_reasons_json='["wait_summary_missing_or_invalid"]'
        federation_wait_failure_reasons_csv="wait_summary_missing_or_invalid"
        echo "federation wait warning: summary JSON missing or invalid: $federation_wait_summary_json"
      fi
      if [[ -z "$federation_wait_failure_reasons_csv" ]]; then
        federation_wait_failure_reasons_csv="$(jq -r 'if length == 0 then "" else join(",") end' <<<"$federation_wait_failure_reasons_json" 2>/dev/null || true)"
      fi
      if [[ "$rc" -eq 0 && "$federation_wait_file_required" == "1" && "$federation_wait_file_required_met" != "true" ]]; then
        federation_wait_state="failed_wait_file_required"
        set_failure "federation_wait_file" 12
      elif [[ "$rc" -eq 0 && "$federation_wait_summary_required" == "1" && "$federation_wait_summary_required_met" != "true" ]]; then
        federation_wait_state="failed_summary_required"
        set_failure "federation_wait_summary" 10
      elif [[ "$rc" -ne 0 ]]; then
        federation_wait_state="failed"
        set_failure "federation_wait" "$rc"
      else
        federation_wait_state="ready"
        step_ok "federation_wait"
      fi
    else
      federation_wait_state="skipped_no_peers"
      federation_wait_file_required_met=true
      federation_wait_summary_required_met=true
      federation_wait_summary_state="skipped_no_peers"
      federation_wait_summary_status="skipped"
      federation_wait_summary_final_state="skipped_no_peers"
      step_ok "federation_wait_skipped_no_peers"
    fi
  fi

  if [[ "$federation_check" == "1" && "$server_started" == "1" ]]; then
    rm -f "$federation_status_summary_json" >/dev/null 2>&1 || true
    set +e
    "$EASY_NODE_SH" server-federation-status \
      --directory-url "$resolved_directory_base" \
      --timeout-sec "$federation_timeout_sec" \
      --require-configured-healthy "$federation_require_configured_healthy" \
      --max-cooling-retry-sec "$federation_max_cooling_retry_sec" \
      --max-peer-sync-age-sec "$federation_max_peer_sync_age_sec" \
      --max-issuer-sync-age-sec "$federation_max_issuer_sync_age_sec" \
      --min-peer-success-sources "$federation_min_peer_success_sources" \
      --min-issuer-success-sources "$federation_min_issuer_success_sources" \
      --min-peer-source-operators "$federation_min_peer_source_operators" \
      --min-issuer-source-operators "$federation_min_issuer_source_operators" \
      --fail-on-not-ready "$federation_status_fail_on_not_ready" \
      --summary-json "$federation_status_summary_json" \
      --show-json 1 >"$federation_status_file" 2>&1
    rc=$?
    set -e
    federation_status_capture_rc="$rc"
    federation_status_file_required_met=false
    if [[ -s "$federation_status_file" ]]; then
      federation_status_file_required_met=true
    fi
    federation_status_summary_capture_rc="$rc"
    federation_status_summary_required_met=false
    if [[ "$rc" -eq 0 ]]; then
      federation_status_summary_state="missing_or_invalid"
      if [[ -s "$federation_status_summary_json" ]] && jq -e '.readiness.federation_ready != null' "$federation_status_summary_json" >/dev/null 2>&1; then
        federation_status_summary_state="captured"
        federation_status_summary_required_met=true
        federation_status_ready="$(jq -r '.readiness.federation_ready // false' "$federation_status_summary_json" 2>/dev/null || echo "false")"
        federation_status_peer_sync_ready="$(jq -r '.readiness.peer_sync_ready // false' "$federation_status_summary_json" 2>/dev/null || echo "false")"
        federation_status_issuer_sync_ready="$(jq -r '.readiness.issuer_sync_ready // false' "$federation_status_summary_json" 2>/dev/null || echo "false")"
        federation_status_peer_health_ready="$(jq -r '.readiness.peer_health_ready // false' "$federation_status_summary_json" 2>/dev/null || echo "false")"
        federation_status_cooling_retry_exceeded="$(jq -r '.readiness.cooling_retry_exceeded // false' "$federation_status_summary_json" 2>/dev/null || echo "false")"
        federation_status_failure_reasons_json="$(jq -c '(.readiness.failure_reasons // []) | if type == "array" then . else [] end' "$federation_status_summary_json" 2>/dev/null || echo '[]')"
        federation_status_peer_sync_age_sec="$(jq -r '.observed.peer_sync.age_sec // -1' "$federation_status_summary_json" 2>/dev/null || echo "-1")"
        federation_status_issuer_sync_age_sec="$(jq -r '.observed.issuer_sync.age_sec // -1' "$federation_status_summary_json" 2>/dev/null || echo "-1")"
        federation_status_peer_source_operator_count="$(jq -r '.observed.peer_sync.source_operator_count // 0' "$federation_status_summary_json" 2>/dev/null || echo "0")"
        federation_status_issuer_source_operator_count="$(jq -r '.observed.issuer_sync.source_operator_count // 0' "$federation_status_summary_json" 2>/dev/null || echo "0")"
        federation_status_configured_failing="$(jq -r '.observed.peer_health.configured_failing // 0' "$federation_status_summary_json" 2>/dev/null || echo "0")"
        federation_status_discovered_eligible="$(jq -r '.observed.peer_health.discovered_eligible // 0' "$federation_status_summary_json" 2>/dev/null || echo "0")"
        federation_status_cooling_retry_max_sec="$(jq -r '.observed.peer_summary.cooling_retry_max_sec // 0' "$federation_status_summary_json" 2>/dev/null || echo "0")"
        step_ok "federation_status_summary"
      else
        federation_status_ready="false"
        federation_status_peer_sync_ready="false"
        federation_status_issuer_sync_ready="false"
        federation_status_peer_health_ready="false"
        federation_status_cooling_retry_exceeded="false"
        federation_status_failure_reasons_json='["status_summary_missing_or_invalid"]'
        federation_status_failure_reasons_csv="status_summary_missing_or_invalid"
        echo "federation status warning: summary JSON missing or invalid: $federation_status_summary_json"
      fi
      if [[ -z "$federation_status_failure_reasons_csv" ]]; then
        federation_status_failure_reasons_csv="$(jq -r 'if length == 0 then "" else join(",") end' <<<"$federation_status_failure_reasons_json" 2>/dev/null || true)"
      fi
      if [[ "$federation_status_file_required" == "1" && "$federation_status_file_required_met" != "true" ]]; then
        if [[ "$status" == "ok" ]]; then
          set_failure "federation_status_file" 13
        fi
      elif [[ "$federation_status_summary_required" == "1" && "$federation_status_summary_required_met" != "true" ]]; then
        if [[ "$status" == "ok" ]]; then
          set_failure "federation_status_summary" 11
        fi
      else
        step_ok "federation_status"
      fi
    else
      federation_status_summary_state="failed"
      federation_status_failure_reasons_json='["status_capture_failed"]'
      federation_status_failure_reasons_csv="status_capture_failed"
      federation_status_summary_required_met=false
      if [[ "$status" == "ok" ]]; then
        set_failure "federation_status" "$rc"
      fi
    fi
  fi

  if [[ "$status" == "ok" && "$verify_relays" == "1" ]]; then
    need_cmd "$CURL_BIN"
    if [[ -z "$resolved_operator_id" ]]; then
      set_failure "relay_verify" 3
      echo "relay verify failed: operator id unavailable (provide --operator-id or ensure env has DIRECTORY_OPERATOR_ID)"
    else
      verify_ok=0
      for ((i = 1; i <= verify_relay_timeout_sec; i++)); do
        set +e
        observed="$(operator_relay_count "$resolved_directory_base" "$resolved_operator_id" 2>/dev/null)"
        rc=$?
        set -e
        if [[ "$rc" -eq 0 && "$observed" =~ ^[0-9]+$ ]]; then
          relay_observed_count="$observed"
          if (( observed >= verify_relay_min_count )); then
            verify_ok=1
            break
          fi
        fi
        sleep 1
      done
      if [[ "$verify_ok" -ne 1 ]]; then
        set_failure "relay_verify" 4
        echo "relay verify failed: operator=$resolved_operator_id observed_count=$relay_observed_count required_min=$verify_relay_min_count directory=$resolved_directory_base"
      else
        step_ok "relay_verify"
      fi
    fi
  fi

  if [[ "$status" == "ok" && "$onboard_invite" == "1" ]]; then
    if [[ "$resolved_mode" != "authority" ]]; then
      onboard_invite_state="skipped_non_authority"
      step_ok "onboard_invite_skipped_non_authority"
    elif [[ "$server_started" != "1" ]]; then
      onboard_invite_state="skipped_server_not_started"
      step_ok "onboard_invite_skipped_server_not_started"
    else
      invite_tmp_out="$(mktemp)"
      set +e
      "$EASY_NODE_SH" invite-generate \
        --count "$onboard_invite_count" \
        --tier "$onboard_invite_tier" \
        --wait-sec "$onboard_invite_wait_sec" >"$invite_tmp_out" 2>&1
      rc=$?
      set -e
      onboard_invite_rc="$rc"
      if [[ "$rc" -eq 0 ]]; then
        awk '/^[[:alnum:]][[:alnum:]_-]*$/ {print $0}' "$invite_tmp_out" >"$onboard_invite_file"
        onboard_invite_generated_count="$(awk 'NF>0 { count++ } END { print count+0 }' "$onboard_invite_file")"
        if ((onboard_invite_generated_count > 0)); then
          onboard_invite_state="generated"
          step_ok "onboard_invite"
        else
          onboard_invite_state="failed"
          onboard_invite_rc=9
          cp "$invite_tmp_out" "$onboard_invite_file"
          if [[ "$onboard_invite_fail_open" == "1" ]]; then
            step_ok "onboard_invite_failed_open"
            echo "onboard invite warning: invite output did not include usable keys; continuing (fail-open). output=$onboard_invite_file"
          else
            set_failure "onboard_invite" "$onboard_invite_rc"
          fi
        fi
      else
        onboard_invite_state="failed"
        cp "$invite_tmp_out" "$onboard_invite_file"
        if [[ "$onboard_invite_fail_open" == "1" ]]; then
          step_ok "onboard_invite_failed_open"
          echo "onboard invite warning: invite generation failed rc=$rc; continuing (fail-open). output=$onboard_invite_file"
        else
          set_failure "onboard_invite" "$rc"
        fi
      fi
      rm -f "$invite_tmp_out"
    fi
  fi
else
  server_down_cmd=("$EASY_NODE_SH" "server-down")
  set +e
  "${server_down_cmd[@]}"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    set_failure "server_down" "$rc"
  else
    step_ok "server_down"
  fi

  if [[ "$status" == "ok" && "$verify_absent" == "1" ]]; then
    need_cmd "$CURL_BIN"
    if [[ -z "$resolved_operator_id" ]]; then
      set_failure "relay_absent_verify" 3
      echo "relay absent verify failed: operator id unavailable (provide --operator-id or ensure env has DIRECTORY_OPERATOR_ID)"
    else
      absent_ok=0
      for ((i = 1; i <= verify_relay_timeout_sec; i++)); do
        set +e
        observed="$(operator_relay_count "$resolved_directory_base" "$resolved_operator_id" 2>/dev/null)"
        rc=$?
        set -e
        if [[ "$rc" -eq 0 && "$observed" =~ ^[0-9]+$ ]]; then
          relay_observed_count="$observed"
          if (( observed == 0 )); then
            absent_ok=1
            break
          fi
        fi
        sleep 1
      done
      if [[ "$absent_ok" -ne 1 ]]; then
        set_failure "relay_absent_verify" 4
        echo "relay absent verify failed: operator=$resolved_operator_id observed_count=$relay_observed_count expected=0 directory=$resolved_directory_base"
      else
        step_ok "relay_absent_verify"
      fi
    fi
  fi
fi

if [[ "$action" == "onboard" && "$status" == "fail" && "$rollback_on_fail" == "1" ]]; then
  rollback_trigger_step="$failure_step"
  rollback_trigger_rc="$failure_rc"
  if [[ "$server_started" != "1" ]]; then
    rollback_state="skipped_server_not_started"
  else
    rollback_performed=1
    set +e
    "$EASY_NODE_SH" server-down
    rc=$?
    set -e
    rollback_server_down_rc="$rc"
    if [[ "$rc" -ne 0 ]]; then
      rollback_state="server_down_failed"
      echo "rollback warning: server-down failed rc=$rc"
    else
      step_ok "rollback_server_down"
      if [[ "$rollback_verify_absent" == "1" ]]; then
        if [[ -z "$resolved_operator_id" ]]; then
          rollback_absent_verify_state="skipped_operator_id_missing"
          rollback_state="completed"
          echo "rollback relay-absence verify skipped: operator id unavailable"
        else
          need_cmd "$CURL_BIN"
          absent_ok=0
          for ((i = 1; i <= rollback_verify_timeout_sec; i++)); do
            set +e
            observed="$(operator_relay_count "$resolved_directory_base" "$resolved_operator_id" 2>/dev/null)"
            rc=$?
            set -e
            if [[ "$rc" -eq 0 && "$observed" =~ ^[0-9]+$ ]]; then
              rollback_absent_observed_count="$observed"
              if (( observed == 0 )); then
                absent_ok=1
                break
              fi
            fi
            sleep 1
          done
          if [[ "$absent_ok" -eq 1 ]]; then
            rollback_absent_verify_state="ok"
            rollback_state="completed"
            step_ok "rollback_relay_absent_verify"
          else
            rollback_absent_verify_state="failed"
            rollback_state="verify_absent_failed"
            echo "rollback relay-absence verify failed: operator=$resolved_operator_id observed_count=$rollback_absent_observed_count expected=0 directory=$resolved_directory_base"
          fi
        fi
      else
        rollback_state="completed"
      fi
    fi
  fi
fi

if [[ "$runtime_doctor_on_fail" == "1" ]]; then
  if [[ "$status" == "fail" ]]; then
    runtime_doctor_file_effective="$runtime_doctor_file"
    runtime_doctor_cmd=(
      "$EASY_NODE_SH" "runtime-doctor"
      "--base-port" "$runtime_doctor_base_port"
      "--client-iface" "$runtime_doctor_client_iface"
      "--exit-iface" "$runtime_doctor_exit_iface"
      "--vpn-iface" "$runtime_doctor_vpn_iface"
      "--show-json" "1"
    )
    set +e
    "${runtime_doctor_cmd[@]}" >"$runtime_doctor_file" 2>&1
    rc=$?
    set -e
    runtime_doctor_rc="$rc"
    runtime_doctor_file_required_met=false
    if [[ -s "$runtime_doctor_file" ]]; then
      runtime_doctor_file_required_met=true
    fi
    if [[ "$rc" -eq 0 ]]; then
      if [[ "$runtime_doctor_file_required" == "1" && "$runtime_doctor_file_required_met" != "true" ]]; then
        runtime_doctor_state="failed_file_required"
        echo "runtime doctor warning: required output artifact missing/empty: $runtime_doctor_file"
      elif [[ "$runtime_doctor_file_required_met" == "true" ]]; then
        runtime_doctor_state="captured"
        step_ok "runtime_doctor"
      else
        runtime_doctor_state="captured_empty"
        step_ok "runtime_doctor"
        echo "runtime doctor warning: output artifact is empty: $runtime_doctor_file"
      fi
    else
      if [[ "$runtime_doctor_file_required_met" == "true" ]]; then
        runtime_doctor_state="failed_command"
      else
        runtime_doctor_state="failed"
      fi
      echo "runtime doctor warning: command failed rc=$rc output=$runtime_doctor_file"
    fi
  else
    runtime_doctor_state="skipped_status_ok"
  fi
fi

if [[ "$incident_snapshot_on_fail" == "1" ]]; then
  if [[ "$status" == "fail" ]]; then
    incident_snapshot_state="attempted"
    incident_bundle_effective="$incident_bundle_dir"
    incident_host="${public_host:-127.0.0.1}"
    incident_issuer_url=""
    if [[ "$resolved_mode" == "authority" ]]; then
      incident_issuer_url="http://${incident_host}:8082"
    elif [[ -n "$authority_issuer" ]]; then
      incident_issuer_url="$(trim "$authority_issuer")"
    fi
    incident_entry_url="http://${incident_host}:8083"
    incident_exit_url="http://${incident_host}:8084"

    incident_cmd=(
      "$EASY_NODE_SH" "incident-snapshot"
      "--mode" "$resolved_mode"
      "--bundle-dir" "$incident_bundle_dir"
      "--timeout-sec" "$incident_timeout_sec"
      "--include-docker-logs" "$incident_include_docker_logs"
      "--docker-log-lines" "$incident_docker_log_lines"
      "--directory-url" "$resolved_directory_base"
      "--entry-url" "$incident_entry_url"
      "--exit-url" "$incident_exit_url"
    )
    if [[ -n "$incident_issuer_url" ]]; then
      incident_cmd+=("--issuer-url" "$incident_issuer_url")
    fi

    declare -a incident_attach_effective=()
    if [[ -f "$federation_status_file" ]]; then
      incident_attach_effective+=("$federation_status_file")
    fi
    if [[ -f "$federation_status_summary_json" ]]; then
      incident_attach_effective+=("$federation_status_summary_json")
    fi
    if [[ -f "$federation_wait_summary_json" ]]; then
      incident_attach_effective+=("$federation_wait_summary_json")
    fi
    if [[ -f "$federation_wait_file" ]]; then
      incident_attach_effective+=("$federation_wait_file")
    fi
    if [[ -f "$onboard_invite_file" ]]; then
      incident_attach_effective+=("$onboard_invite_file")
    fi
    if [[ -f "$runtime_doctor_file" ]]; then
      incident_attach_effective+=("$runtime_doctor_file")
    fi
    if ((${#incident_attach_artifacts_cli[@]} > 0)); then
      for artifact in "${incident_attach_artifacts_cli[@]}"; do
        artifact_path="$(abs_path "$artifact")"
        if [[ -z "$artifact_path" ]]; then
          continue
        fi
        if [[ -e "$artifact_path" ]]; then
          incident_attach_effective+=("$artifact_path")
        else
          echo "incident snapshot warning: attach artifact missing: $artifact_path"
        fi
      done
    fi
    incident_attach_count="${#incident_attach_effective[@]}"
    if ((incident_attach_count > 0)); then
      incident_attach_list="$(printf '%s\n' "${incident_attach_effective[@]}" | paste -sd ',' -)"
      for artifact in "${incident_attach_effective[@]}"; do
        incident_cmd+=("--attach-artifact" "$artifact")
      done
    fi

    set +e
    "${incident_cmd[@]}"
    rc=$?
    set -e
    incident_snapshot_rc="$rc"
    if [[ "$rc" -eq 0 ]]; then
      incident_snapshot_state="captured"
      step_ok "incident_snapshot"
    else
      incident_snapshot_state="failed"
      echo "incident snapshot warning: capture failed rc=$rc"
    fi

    incident_summary_candidate="$incident_bundle_dir/incident_summary.json"
    incident_report_candidate="$incident_bundle_dir/incident_report.md"
    incident_bundle_tar_candidate="${incident_bundle_dir}.tar.gz"
    incident_bundle_tar_sha_candidate="${incident_bundle_tar_candidate}.sha256"
    incident_manifest_candidate="$incident_bundle_dir/attachments/manifest.tsv"
    incident_skipped_candidate="$incident_bundle_dir/attachments/skipped.tsv"

    if [[ -f "$incident_summary_candidate" ]]; then
      incident_summary_json_effective="$incident_summary_candidate"
    fi
    if [[ -f "$incident_report_candidate" ]]; then
      incident_report_md_effective="$incident_report_candidate"
    fi
    if [[ -f "$incident_bundle_tar_candidate" ]]; then
      incident_bundle_tar_effective="$incident_bundle_tar_candidate"
    fi
    if [[ -f "$incident_bundle_tar_sha_candidate" ]]; then
      incident_bundle_tar_sha_effective="$incident_bundle_tar_sha_candidate"
    fi
    if [[ -f "$incident_manifest_candidate" ]]; then
      incident_attachment_manifest_effective="$incident_manifest_candidate"
      incident_attachment_manifest_count="$(awk 'NF>0 {c++} END {print c+0}' "$incident_manifest_candidate")"
    fi
    if [[ -f "$incident_skipped_candidate" ]]; then
      incident_attachment_skipped_effective="$incident_skipped_candidate"
      incident_attachment_skipped_count="$(awk 'NF>0 {c++} END {print c+0}' "$incident_skipped_candidate")"
    fi

    if [[ "$incident_snapshot_state" == "captured" ]]; then
      if [[ -n "$incident_summary_json_effective" && -n "$incident_report_md_effective" && -n "$incident_bundle_tar_effective" && -n "$incident_bundle_tar_sha_effective" ]]; then
        incident_artifact_state="complete"
      elif [[ -n "$incident_summary_json_effective" || -n "$incident_report_md_effective" || -n "$incident_bundle_tar_effective" || -n "$incident_bundle_tar_sha_effective" ]]; then
        incident_artifact_state="partial"
      else
        incident_artifact_state="missing"
      fi
      if [[ "$incident_summary_required" == "1" ]]; then
        incident_summary_required_met=false
        if [[ -s "$incident_summary_json_effective" && -s "$incident_report_md_effective" ]]; then
          incident_summary_required_met=true
        fi
      else
        incident_summary_required_met=true
      fi
      if [[ "$incident_bundle_required" == "1" ]]; then
        incident_bundle_required_met=false
        if [[ -s "$incident_bundle_tar_effective" && -s "$incident_bundle_tar_sha_effective" ]]; then
          incident_bundle_required_met=true
        fi
      else
        incident_bundle_required_met=true
      fi
      incident_required_artifacts_met=true
      if [[ "$incident_summary_required_met" != "true" || "$incident_bundle_required_met" != "true" ]]; then
        incident_required_artifacts_met=false
      fi
      if [[ "$incident_attachment_manifest_required" == "1" && "$incident_attach_count" =~ ^[0-9]+$ ]] && ((incident_attach_count > 0)); then
        incident_attachment_manifest_required_met=false
        if [[ -s "$incident_attachment_manifest_effective" && "$incident_attachment_manifest_count" =~ ^[0-9]+$ ]] && ((incident_attachment_manifest_count > 0)); then
          incident_attachment_manifest_required_met=true
        fi
      else
        incident_attachment_manifest_required_met=true
      fi
      if [[ "$incident_attachment_no_skips_required" == "1" ]]; then
        incident_attachment_no_skips_required_met=false
        if [[ "$incident_attachment_skipped_count" =~ ^[0-9]+$ ]] && ((incident_attachment_skipped_count == 0)); then
          incident_attachment_no_skips_required_met=true
        fi
      else
        incident_attachment_no_skips_required_met=true
      fi
      if ((incident_attach_min_count > 0)); then
        incident_attach_min_count_required_met=false
        if [[ "$incident_attach_count" =~ ^[0-9]+$ ]] && ((incident_attach_count >= incident_attach_min_count)); then
          incident_attach_min_count_required_met=true
        fi
      else
        incident_attach_min_count_required_met=true
      fi
      if ((incident_attachment_manifest_min_count > 0)); then
        incident_attachment_manifest_min_count_met=false
        if [[ "$incident_attachment_manifest_count" =~ ^[0-9]+$ ]] && ((incident_attachment_manifest_count >= incident_attachment_manifest_min_count)); then
          incident_attachment_manifest_min_count_met=true
        fi
      else
        incident_attachment_manifest_min_count_met=true
      fi
      incident_attachment_policy_failure_count=0
      if [[ "$incident_attachment_manifest_required_met" != "true" ]]; then
        incident_attachment_policy_failure_count=$((incident_attachment_policy_failure_count + 1))
      fi
      if [[ "$incident_attachment_no_skips_required_met" != "true" ]]; then
        incident_attachment_policy_failure_count=$((incident_attachment_policy_failure_count + 1))
      fi
      if [[ "$incident_attach_min_count_required_met" != "true" ]]; then
        incident_attachment_policy_failure_count=$((incident_attachment_policy_failure_count + 1))
      fi
      if [[ "$incident_attachment_manifest_min_count_met" != "true" ]]; then
        incident_attachment_policy_failure_count=$((incident_attachment_policy_failure_count + 1))
      fi
      incident_required_attachment_policy_met=true
      if ((incident_attachment_policy_failure_count > 0)); then
        incident_required_attachment_policy_met=false
      fi
      incident_required_policies_met=true
      if [[ "$incident_required_artifacts_met" != "true" || "$incident_required_attachment_policy_met" != "true" ]]; then
        incident_required_policies_met=false
      fi

      if [[ "$incident_required_artifacts_met" != "true" && "$incident_required_attachment_policy_met" != "true" ]]; then
        incident_snapshot_state="captured_missing_required_artifacts_and_attachments"
        echo "incident snapshot warning: required summary/bundle and attachment policies failed"
      elif [[ "$incident_required_artifacts_met" != "true" ]]; then
        if [[ "$incident_summary_required_met" != "true" && "$incident_bundle_required_met" != "true" ]]; then
          incident_snapshot_state="captured_missing_required_artifacts"
          echo "incident snapshot warning: required summary and bundle artifacts missing/incomplete"
        elif [[ "$incident_summary_required_met" != "true" ]]; then
          incident_snapshot_state="captured_missing_summary_required"
          echo "incident snapshot warning: required summary artifacts missing/incomplete"
        elif [[ "$incident_bundle_required_met" != "true" ]]; then
          incident_snapshot_state="captured_missing_bundle_required"
          echo "incident snapshot warning: required bundle artifacts missing/incomplete"
        fi
      elif [[ "$incident_required_attachment_policy_met" != "true" ]]; then
        if ((incident_attachment_policy_failure_count > 1)); then
          incident_snapshot_state="captured_attachment_policy_required"
          echo "incident snapshot warning: required attachment policies failed (failed_checks=$incident_attachment_policy_failure_count)"
        elif [[ "$incident_attachment_manifest_required_met" != "true" ]]; then
          incident_snapshot_state="captured_missing_attachment_manifest_required"
          echo "incident snapshot warning: required attachment manifest missing/incomplete"
        elif [[ "$incident_attachment_no_skips_required_met" != "true" ]]; then
          incident_snapshot_state="captured_attachment_skips_required"
          echo "incident snapshot warning: required no-skipped-attachments policy failed"
        elif [[ "$incident_attach_min_count_required_met" != "true" ]]; then
          incident_snapshot_state="captured_attachment_min_count_required"
          echo "incident snapshot warning: required attachment count floor not met (need >=$incident_attach_min_count observed=$incident_attach_count)"
        elif [[ "$incident_attachment_manifest_min_count_met" != "true" ]]; then
          incident_snapshot_state="captured_attachment_manifest_min_count_required"
          echo "incident snapshot warning: required attachment manifest entry floor not met (need >=$incident_attachment_manifest_min_count observed=$incident_attachment_manifest_count)"
        else
          incident_snapshot_state="captured_attachment_policy_required"
          echo "incident snapshot warning: required attachment policy failed"
        fi
      fi
    else
      incident_artifact_state="unknown"
      incident_summary_required_met=true
      incident_bundle_required_met=true
      incident_required_artifacts_met=true
      incident_attachment_manifest_required_met=true
      incident_attachment_no_skips_required_met=true
      incident_attach_min_count_required_met=true
      incident_attachment_manifest_min_count_met=true
      incident_required_attachment_policy_met=true
      incident_attachment_policy_failure_count=0
      incident_required_policies_met=true
    fi
  else
    incident_snapshot_state="skipped_status_ok"
    incident_artifact_state="skipped_status_ok"
    incident_summary_required_met=true
    incident_bundle_required_met=true
    incident_required_artifacts_met=true
    incident_attachment_manifest_required_met=true
    incident_attachment_no_skips_required_met=true
    incident_attach_min_count_required_met=true
    incident_attachment_manifest_min_count_met=true
    incident_required_attachment_policy_met=true
    incident_attachment_policy_failure_count=0
    incident_required_policies_met=true
  fi
fi

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
finished_epoch="$(date -u +%s)"
duration_sec=$((finished_epoch - started_epoch))
if [[ "$duration_sec" -lt 0 ]]; then
  duration_sec=0
fi

jq -nc \
  --arg action "$action" \
  --arg status "$status" \
  --arg mode "$resolved_mode" \
  --arg started_at "$started_at" \
  --arg finished_at "$finished_at" \
  --argjson duration_sec "$duration_sec" \
  --arg operator_id "$resolved_operator_id" \
  --arg directory_url "$resolved_directory_base" \
  --arg failure_step "$failure_step" \
  --argjson failure_rc "$failure_rc" \
  --argjson completed_steps "$completed_steps_json" \
  --argjson preflight_check "$(json_bool "$preflight_check")" \
  --argjson health_check "$(json_bool "$health_check")" \
  --argjson verify_relays "$(json_bool "$verify_relays")" \
  --argjson verify_absent "$(json_bool "$verify_absent")" \
  --argjson federation_check "$(json_bool "$federation_check")" \
  --argjson federation_ready_timeout_sec "$federation_ready_timeout_sec" \
  --argjson federation_poll_sec "$federation_poll_sec" \
  --argjson federation_timeout_sec "$federation_timeout_sec" \
  --argjson federation_require_configured_healthy "$(json_bool "$federation_require_configured_healthy")" \
  --argjson federation_max_cooling_retry_sec "$federation_max_cooling_retry_sec" \
  --argjson federation_max_peer_sync_age_sec "$federation_max_peer_sync_age_sec" \
  --argjson federation_max_issuer_sync_age_sec "$federation_max_issuer_sync_age_sec" \
  --argjson federation_min_peer_success_sources "$federation_min_peer_success_sources" \
  --argjson federation_min_issuer_success_sources "$federation_min_issuer_success_sources" \
  --argjson federation_min_peer_source_operators "$federation_min_peer_source_operators" \
  --argjson federation_min_issuer_source_operators "$federation_min_issuer_source_operators" \
  --arg federation_wait_file "$federation_wait_file" \
  --argjson federation_wait_file_required "$(json_bool "$federation_wait_file_required")" \
  --argjson federation_wait_file_required_met "$federation_wait_file_required_met" \
  --argjson federation_wait_capture_rc "$federation_wait_capture_rc" \
  --arg federation_wait_summary_json "$federation_wait_summary_json" \
  --argjson federation_wait_print_summary_json "$(json_bool "$federation_wait_print_summary_json")" \
  --argjson federation_wait_summary_required "$(json_bool "$federation_wait_summary_required")" \
  --argjson federation_wait_summary_required_met "$federation_wait_summary_required_met" \
  --argjson federation_wait_summary_capture_rc "$federation_wait_summary_capture_rc" \
  --arg federation_wait_summary_state "$federation_wait_summary_state" \
  --arg federation_wait_summary_status "$federation_wait_summary_status" \
  --arg federation_wait_summary_final_state "$federation_wait_summary_final_state" \
  --argjson federation_wait_peer_sync_ready "$federation_wait_peer_sync_ready" \
  --argjson federation_wait_issuer_sync_ready "$federation_wait_issuer_sync_ready" \
  --argjson federation_wait_peer_health_ready "$federation_wait_peer_health_ready" \
  --argjson federation_wait_cooling_retry_exceeded "$federation_wait_cooling_retry_exceeded" \
  --argjson federation_wait_failure_reasons "$federation_wait_failure_reasons_json" \
  --arg federation_wait_failure_reasons_csv "$federation_wait_failure_reasons_csv" \
  --argjson federation_wait_peer_sync_age_sec "$federation_wait_peer_sync_age_sec" \
  --argjson federation_wait_issuer_sync_age_sec "$federation_wait_issuer_sync_age_sec" \
  --argjson federation_wait_peer_source_operator_count "$federation_wait_peer_source_operator_count" \
  --argjson federation_wait_issuer_source_operator_count "$federation_wait_issuer_source_operator_count" \
  --argjson federation_wait_configured_failing "$federation_wait_configured_failing" \
  --argjson federation_wait_discovered_eligible "$federation_wait_discovered_eligible" \
  --argjson federation_wait_cooling_retry_max_sec "$federation_wait_cooling_retry_max_sec" \
  --argjson federation_wait_attempts "$federation_wait_attempts" \
  --argjson federation_wait_elapsed_sec "$federation_wait_elapsed_sec" \
  --argjson federation_wait_remaining_sec "$federation_wait_remaining_sec" \
  --argjson federation_status_fail_on_not_ready "$(json_bool "$federation_status_fail_on_not_ready")" \
  --arg federation_wait_state "$federation_wait_state" \
  --arg federation_peer_directories "$effective_peer_directories" \
  --argjson federation_peer_count "$effective_peer_count" \
  --arg federation_status_file "$federation_status_file" \
  --argjson federation_status_file_required "$(json_bool "$federation_status_file_required")" \
  --argjson federation_status_file_required_met "$federation_status_file_required_met" \
  --argjson federation_status_capture_rc "$federation_status_capture_rc" \
  --arg federation_status_summary_json "$federation_status_summary_json" \
  --argjson federation_status_summary_capture_rc "$federation_status_summary_capture_rc" \
  --arg federation_status_summary_state "$federation_status_summary_state" \
  --argjson federation_status_summary_required "$(json_bool "$federation_status_summary_required")" \
  --argjson federation_status_summary_required_met "$federation_status_summary_required_met" \
  --argjson federation_status_ready "$federation_status_ready" \
  --argjson federation_status_peer_sync_ready "$federation_status_peer_sync_ready" \
  --argjson federation_status_issuer_sync_ready "$federation_status_issuer_sync_ready" \
  --argjson federation_status_peer_health_ready "$federation_status_peer_health_ready" \
  --argjson federation_status_cooling_retry_exceeded "$federation_status_cooling_retry_exceeded" \
  --argjson federation_status_failure_reasons "$federation_status_failure_reasons_json" \
  --arg federation_status_failure_reasons_csv "$federation_status_failure_reasons_csv" \
  --argjson federation_status_peer_sync_age_sec "$federation_status_peer_sync_age_sec" \
  --argjson federation_status_issuer_sync_age_sec "$federation_status_issuer_sync_age_sec" \
  --argjson federation_status_peer_source_operator_count "$federation_status_peer_source_operator_count" \
  --argjson federation_status_issuer_source_operator_count "$federation_status_issuer_source_operator_count" \
  --argjson federation_status_configured_failing "$federation_status_configured_failing" \
  --argjson federation_status_discovered_eligible "$federation_status_discovered_eligible" \
  --argjson federation_status_cooling_retry_max_sec "$federation_status_cooling_retry_max_sec" \
  --argjson onboard_invite "$(json_bool "$onboard_invite")" \
  --argjson onboard_invite_count "$onboard_invite_count" \
  --argjson onboard_invite_tier "$onboard_invite_tier" \
  --argjson onboard_invite_wait_sec "$onboard_invite_wait_sec" \
  --argjson onboard_invite_fail_open "$(json_bool "$onboard_invite_fail_open")" \
  --arg onboard_invite_state "$onboard_invite_state" \
  --arg onboard_invite_file "$onboard_invite_file" \
  --argjson onboard_invite_generated_count "$onboard_invite_generated_count" \
  --argjson onboard_invite_rc "$onboard_invite_rc" \
  --argjson rollback_on_fail "$(json_bool "$rollback_enabled_effective")" \
  --argjson rollback_verify_absent "$(json_bool "$rollback_verify_absent_effective")" \
  --argjson rollback_verify_timeout_sec "$rollback_verify_timeout_sec" \
  --arg rollback_state "$rollback_state" \
  --argjson rollback_performed "$(json_bool "$rollback_performed")" \
  --arg rollback_trigger_step "$rollback_trigger_step" \
  --argjson rollback_trigger_rc "$rollback_trigger_rc" \
  --argjson rollback_server_down_rc "$rollback_server_down_rc" \
  --arg rollback_absent_verify_state "$rollback_absent_verify_state" \
  --argjson rollback_absent_observed_count "$rollback_absent_observed_count" \
  --argjson runtime_doctor_on_fail "$(json_bool "$runtime_doctor_on_fail_effective")" \
  --arg runtime_doctor_state "$runtime_doctor_state" \
  --argjson runtime_doctor_rc "$runtime_doctor_rc" \
  --arg runtime_doctor_file "$runtime_doctor_file_effective" \
  --argjson runtime_doctor_file_required "$(json_bool "$runtime_doctor_file_required")" \
  --argjson runtime_doctor_file_required_met "$runtime_doctor_file_required_met" \
  --argjson runtime_doctor_base_port "$runtime_doctor_base_port" \
  --arg runtime_doctor_client_iface "$runtime_doctor_client_iface" \
  --arg runtime_doctor_exit_iface "$runtime_doctor_exit_iface" \
  --arg runtime_doctor_vpn_iface "$runtime_doctor_vpn_iface" \
  --argjson incident_snapshot_on_fail "$(json_bool "$incident_snapshot_on_fail")" \
  --arg incident_bundle_dir "$incident_bundle_dir" \
  --arg incident_bundle_effective "$incident_bundle_effective" \
  --argjson incident_timeout_sec "$incident_timeout_sec" \
  --argjson incident_include_docker_logs "$(json_bool "$incident_include_docker_logs")" \
  --argjson incident_docker_log_lines "$incident_docker_log_lines" \
  --arg incident_snapshot_state "$incident_snapshot_state" \
  --argjson incident_snapshot_rc "$incident_snapshot_rc" \
  --argjson incident_attach_count "$incident_attach_count" \
  --arg incident_attach_list "$incident_attach_list" \
  --arg incident_summary_json "$incident_summary_json_effective" \
  --arg incident_report_md "$incident_report_md_effective" \
  --arg incident_bundle_tar "$incident_bundle_tar_effective" \
  --arg incident_bundle_tar_sha "$incident_bundle_tar_sha_effective" \
  --arg incident_attachment_manifest "$incident_attachment_manifest_effective" \
  --arg incident_attachment_skipped "$incident_attachment_skipped_effective" \
  --argjson incident_attachment_manifest_count "$incident_attachment_manifest_count" \
  --argjson incident_attachment_skipped_count "$incident_attachment_skipped_count" \
  --arg incident_artifact_state "$incident_artifact_state" \
  --argjson incident_summary_required "$(json_bool "$incident_summary_required")" \
  --argjson incident_summary_required_met "$incident_summary_required_met" \
  --argjson incident_bundle_required "$(json_bool "$incident_bundle_required")" \
  --argjson incident_bundle_required_met "$incident_bundle_required_met" \
  --argjson incident_required_artifacts_met "$incident_required_artifacts_met" \
  --argjson incident_attachment_manifest_required "$(json_bool "$incident_attachment_manifest_required")" \
  --argjson incident_attachment_manifest_required_met "$incident_attachment_manifest_required_met" \
  --argjson incident_attachment_no_skips_required "$(json_bool "$incident_attachment_no_skips_required")" \
  --argjson incident_attachment_no_skips_required_met "$incident_attachment_no_skips_required_met" \
  --argjson incident_attach_min_count "$incident_attach_min_count" \
  --argjson incident_attach_min_count_required_met "$incident_attach_min_count_required_met" \
  --argjson incident_attachment_manifest_min_count "$incident_attachment_manifest_min_count" \
  --argjson incident_attachment_manifest_min_count_met "$incident_attachment_manifest_min_count_met" \
  --argjson incident_attachment_policy_failure_count "$incident_attachment_policy_failure_count" \
  --argjson incident_required_attachment_policy_met "$incident_required_attachment_policy_met" \
  --argjson incident_required_policies_met "$incident_required_policies_met" \
  --argjson verify_relay_min_count "$verify_relay_min_count" \
  --argjson verify_relay_timeout_sec "$verify_relay_timeout_sec" \
  --argjson relay_observed_count "$relay_observed_count" \
  --arg peer_identity_strict "$peer_identity_strict" \
  --arg min_peer_operators "$min_peer_operators" \
  --arg client_allowlist "$client_allowlist" \
  --arg allow_anon_cred "$allow_anon_cred" \
  --arg beta_profile "$beta_profile" \
  --arg prod_profile "$prod_profile" \
  --arg report_md "$report_md" \
  --arg summary_json "$summary_json" \
  '{
    action:$action,
    status:$status,
    mode:$mode,
    started_at:$started_at,
    finished_at:$finished_at,
    duration_sec:$duration_sec,
    operator_id:($operator_id // ""),
    directory_url:$directory_url,
    failure_step:($failure_step // ""),
    failure_rc:$failure_rc,
    completed_steps:$completed_steps,
    checks:{
      preflight_enabled:$preflight_check,
      health_enabled:$health_check,
      federation_enabled:$federation_check,
      onboard_invite_enabled:$onboard_invite,
      runtime_doctor_on_fail_enabled:$runtime_doctor_on_fail,
      incident_snapshot_on_fail_enabled:$incident_snapshot_on_fail,
      relay_verify_enabled:$verify_relays,
      relay_absent_verify_enabled:$verify_absent
    },
    federation:{
      wait_state:($federation_wait_state // ""),
      ready_timeout_sec:$federation_ready_timeout_sec,
      poll_sec:$federation_poll_sec,
      request_timeout_sec:$federation_timeout_sec,
      require_configured_healthy:$federation_require_configured_healthy,
      max_cooling_retry_sec:$federation_max_cooling_retry_sec,
      max_peer_sync_age_sec:$federation_max_peer_sync_age_sec,
      max_issuer_sync_age_sec:$federation_max_issuer_sync_age_sec,
      min_peer_success_sources:$federation_min_peer_success_sources,
      min_issuer_success_sources:$federation_min_issuer_success_sources,
      min_peer_source_operators:$federation_min_peer_source_operators,
      min_issuer_source_operators:$federation_min_issuer_source_operators,
      wait_file:($federation_wait_file // ""),
      wait_file_required:$federation_wait_file_required,
      wait_file_required_met:$federation_wait_file_required_met,
      wait_capture_rc:$federation_wait_capture_rc,
      wait_summary_file:($federation_wait_summary_json // ""),
      wait_summary_printed:$federation_wait_print_summary_json,
      wait_summary_required:$federation_wait_summary_required,
      wait_summary_required_met:$federation_wait_summary_required_met,
      wait_summary_capture_rc:$federation_wait_summary_capture_rc,
      wait_summary_state:($federation_wait_summary_state // ""),
      wait_summary_status:($federation_wait_summary_status // ""),
      wait_summary_final_state:($federation_wait_summary_final_state // ""),
      wait_ready_failure_reasons:$federation_wait_failure_reasons,
      wait_ready_failure_reasons_csv:($federation_wait_failure_reasons_csv // ""),
      wait_readiness:{
        peer_sync_ready:$federation_wait_peer_sync_ready,
        issuer_sync_ready:$federation_wait_issuer_sync_ready,
        peer_health_ready:$federation_wait_peer_health_ready,
        cooling_retry_exceeded:$federation_wait_cooling_retry_exceeded
      },
      wait_observed:{
        peer_sync_age_sec:$federation_wait_peer_sync_age_sec,
        issuer_sync_age_sec:$federation_wait_issuer_sync_age_sec,
        peer_source_operator_count:$federation_wait_peer_source_operator_count,
        issuer_source_operator_count:$federation_wait_issuer_source_operator_count,
        configured_failing:$federation_wait_configured_failing,
        discovered_eligible:$federation_wait_discovered_eligible,
        cooling_retry_max_sec:$federation_wait_cooling_retry_max_sec
      },
      wait_timing:{
        attempts:$federation_wait_attempts,
        elapsed_sec:$federation_wait_elapsed_sec,
        remaining_sec:$federation_wait_remaining_sec
      },
      status_fail_on_not_ready:$federation_status_fail_on_not_ready,
      peer_count:$federation_peer_count,
      peer_directories_csv:($federation_peer_directories // ""),
      status_file:$federation_status_file,
      status_file_required:$federation_status_file_required,
      status_file_required_met:$federation_status_file_required_met,
      status_capture_rc:$federation_status_capture_rc,
      status_summary_file:($federation_status_summary_json // ""),
      status_summary_capture_rc:$federation_status_summary_capture_rc,
      status_summary_state:($federation_status_summary_state // ""),
      status_summary_required:$federation_status_summary_required,
      status_summary_required_met:$federation_status_summary_required_met,
      status_ready:$federation_status_ready,
      status_ready_failure_reasons:$federation_status_failure_reasons,
      status_ready_failure_reasons_csv:($federation_status_failure_reasons_csv // ""),
      status_readiness:{
        peer_sync_ready:$federation_status_peer_sync_ready,
        issuer_sync_ready:$federation_status_issuer_sync_ready,
        peer_health_ready:$federation_status_peer_health_ready,
        cooling_retry_exceeded:$federation_status_cooling_retry_exceeded
      },
      status_observed:{
        peer_sync_age_sec:$federation_status_peer_sync_age_sec,
        issuer_sync_age_sec:$federation_status_issuer_sync_age_sec,
        peer_source_operator_count:$federation_status_peer_source_operator_count,
        issuer_source_operator_count:$federation_status_issuer_source_operator_count,
        configured_failing:$federation_status_configured_failing,
        discovered_eligible:$federation_status_discovered_eligible,
        cooling_retry_max_sec:$federation_status_cooling_retry_max_sec
      }
    },
    invite_bootstrap:{
      state:($onboard_invite_state // ""),
      requested_count:$onboard_invite_count,
      requested_tier:$onboard_invite_tier,
      wait_sec:$onboard_invite_wait_sec,
      fail_open:$onboard_invite_fail_open,
      generated_count:$onboard_invite_generated_count,
      rc:$onboard_invite_rc,
      file:$onboard_invite_file
    },
    rollback:{
      enabled:$rollback_on_fail,
      verify_absent_enabled:$rollback_verify_absent,
      verify_absent_timeout_sec:$rollback_verify_timeout_sec,
      state:($rollback_state // ""),
      performed:$rollback_performed,
      trigger_step:($rollback_trigger_step // ""),
      trigger_rc:$rollback_trigger_rc,
      server_down_rc:$rollback_server_down_rc,
      absent_verify_state:($rollback_absent_verify_state // ""),
      absent_observed_count:$rollback_absent_observed_count
    },
    runtime_doctor:{
      state:($runtime_doctor_state // ""),
      rc:$runtime_doctor_rc,
      file:($runtime_doctor_file // ""),
      file_required:$runtime_doctor_file_required,
      file_required_met:$runtime_doctor_file_required_met,
      base_port:$runtime_doctor_base_port,
      client_iface:($runtime_doctor_client_iface // ""),
      exit_iface:($runtime_doctor_exit_iface // ""),
      vpn_iface:($runtime_doctor_vpn_iface // "")
    },
    incident_snapshot:{
      state:($incident_snapshot_state // ""),
      rc:$incident_snapshot_rc,
      bundle_dir:($incident_bundle_effective // ""),
      configured_bundle_dir:$incident_bundle_dir,
      timeout_sec:$incident_timeout_sec,
      include_docker_logs:$incident_include_docker_logs,
      docker_log_lines:$incident_docker_log_lines,
      attach_count:$incident_attach_count,
      attach_artifacts_csv:($incident_attach_list // ""),
      summary_json:($incident_summary_json // ""),
      report_md:($incident_report_md // ""),
      bundle_tar:($incident_bundle_tar // ""),
      bundle_tar_sha256_file:($incident_bundle_tar_sha // ""),
      attachment_manifest:($incident_attachment_manifest // ""),
      attachment_skipped:($incident_attachment_skipped // ""),
      attachment_manifest_count:$incident_attachment_manifest_count,
      attachment_skipped_count:$incident_attachment_skipped_count,
      artifact_state:($incident_artifact_state // ""),
      summary_required:$incident_summary_required,
      summary_required_met:$incident_summary_required_met,
      bundle_required:$incident_bundle_required,
      bundle_required_met:$incident_bundle_required_met,
      required_artifacts_met:$incident_required_artifacts_met,
      attachment_manifest_required:$incident_attachment_manifest_required,
      attachment_manifest_required_met:$incident_attachment_manifest_required_met,
      attachment_no_skips_required:$incident_attachment_no_skips_required,
      attachment_no_skips_required_met:$incident_attachment_no_skips_required_met,
      attach_min_count_required:$incident_attach_min_count,
      attach_min_count_required_met:$incident_attach_min_count_required_met,
      attachment_manifest_min_count_required:$incident_attachment_manifest_min_count,
      attachment_manifest_min_count_required_met:$incident_attachment_manifest_min_count_met,
      attachment_policy_failure_count:$incident_attachment_policy_failure_count,
      required_attachment_policy_met:$incident_required_attachment_policy_met,
      required_policies_met:$incident_required_policies_met
    },
    relay_policy:{
      verify_min_count:$verify_relay_min_count,
      verify_timeout_sec:$verify_relay_timeout_sec,
      observed_count:$relay_observed_count
    },
    requested_flags:{
      peer_identity_strict:($peer_identity_strict // ""),
      min_peer_operators:($min_peer_operators // ""),
      client_allowlist:($client_allowlist // ""),
      allow_anon_cred:($allow_anon_cred // ""),
      beta_profile:($beta_profile // ""),
      prod_profile:($prod_profile // "")
    },
    report_md:$report_md,
    summary_json:$summary_json
  }' >"$summary_json"

completed_steps_md="$(jq -r '.[]?' <<<"$completed_steps_json" 2>/dev/null | sed 's/^/- /')"
if [[ -z "$completed_steps_md" ]]; then
  completed_steps_md="- (none)"
fi
failure_line="none"
if [[ "$status" != "ok" ]]; then
  failure_line="${failure_step:-unknown} (rc=${failure_rc})"
fi
cat >"$report_md" <<EOF_REPORT
# Prod Operator Lifecycle Runbook Report

- action: ${action}
- mode: ${resolved_mode}
- status: ${status}
- started_at: ${started_at}
- finished_at: ${finished_at}
- duration_sec: ${duration_sec}
- failure: ${failure_line}
- summary_json: ${summary_json}

## Completed Steps
${completed_steps_md}

## Federation
- wait_state: ${federation_wait_state}
- require_configured_healthy: ${federation_require_configured_healthy}
- max_cooling_retry_sec: ${federation_max_cooling_retry_sec}
- max_peer_sync_age_sec: ${federation_max_peer_sync_age_sec}
- max_issuer_sync_age_sec: ${federation_max_issuer_sync_age_sec}
- min_peer_success_sources: ${federation_min_peer_success_sources}
- min_issuer_success_sources: ${federation_min_issuer_success_sources}
- min_peer_source_operators: ${federation_min_peer_source_operators}
- min_issuer_source_operators: ${federation_min_issuer_source_operators}
- wait_file: ${federation_wait_file}
- wait_file_required: ${federation_wait_file_required}
- wait_file_required_met: ${federation_wait_file_required_met}
- wait_capture_rc: ${federation_wait_capture_rc}
- wait_summary_state: ${federation_wait_summary_state}
- wait_summary_status: ${federation_wait_summary_status}
- wait_summary_final_state: ${federation_wait_summary_final_state}
- wait_summary_required: ${federation_wait_summary_required}
- wait_summary_required_met: ${federation_wait_summary_required_met}
- wait_summary_capture_rc: ${federation_wait_summary_capture_rc}
- wait_summary_file: ${federation_wait_summary_json}
- wait_ready_failure_reasons: ${federation_wait_failure_reasons_csv}
- wait_readiness_peer_sync_ready: ${federation_wait_peer_sync_ready}
- wait_readiness_issuer_sync_ready: ${federation_wait_issuer_sync_ready}
- wait_readiness_peer_health_ready: ${federation_wait_peer_health_ready}
- wait_readiness_cooling_retry_exceeded: ${federation_wait_cooling_retry_exceeded}
- wait_timing_attempts: ${federation_wait_attempts}
- wait_timing_elapsed_sec: ${federation_wait_elapsed_sec}
- wait_timing_remaining_sec: ${federation_wait_remaining_sec}
- status_fail_on_not_ready: ${federation_status_fail_on_not_ready}
- peer_count: ${effective_peer_count}
- status_capture_rc: ${federation_status_capture_rc}
- status_file: ${federation_status_file}
- status_file_required: ${federation_status_file_required}
- status_file_required_met: ${federation_status_file_required_met}
- status_summary_state: ${federation_status_summary_state}
- status_summary_capture_rc: ${federation_status_summary_capture_rc}
- status_summary_file: ${federation_status_summary_json}
- status_summary_required: ${federation_status_summary_required}
- status_summary_required_met: ${federation_status_summary_required_met}
- status_ready: ${federation_status_ready}
- status_ready_failure_reasons: ${federation_status_failure_reasons_csv}
- status_readiness_peer_sync_ready: ${federation_status_peer_sync_ready}
- status_readiness_issuer_sync_ready: ${federation_status_issuer_sync_ready}
- status_readiness_peer_health_ready: ${federation_status_peer_health_ready}
- status_readiness_cooling_retry_exceeded: ${federation_status_cooling_retry_exceeded}
- status_observed_peer_sync_age_sec: ${federation_status_peer_sync_age_sec}
- status_observed_issuer_sync_age_sec: ${federation_status_issuer_sync_age_sec}
- status_observed_peer_source_operator_count: ${federation_status_peer_source_operator_count}
- status_observed_issuer_source_operator_count: ${federation_status_issuer_source_operator_count}
- status_observed_configured_failing: ${federation_status_configured_failing}
- status_observed_discovered_eligible: ${federation_status_discovered_eligible}
- status_observed_cooling_retry_max_sec: ${federation_status_cooling_retry_max_sec}

## Invite Bootstrap
- state: ${onboard_invite_state}
- generated_count: ${onboard_invite_generated_count}
- rc: ${onboard_invite_rc}
- file: ${onboard_invite_file}

## Rollback
- state: ${rollback_state}
- performed: ${rollback_performed}
- trigger_step: ${rollback_trigger_step}
- trigger_rc: ${rollback_trigger_rc}
- server_down_rc: ${rollback_server_down_rc}
- absent_verify_state: ${rollback_absent_verify_state}
- absent_observed_count: ${rollback_absent_observed_count}

## Runtime Doctor
- state: ${runtime_doctor_state}
- rc: ${runtime_doctor_rc}
- file: ${runtime_doctor_file_effective}
- file_required: ${runtime_doctor_file_required}
- file_required_met: ${runtime_doctor_file_required_met}

## Incident Snapshot
- state: ${incident_snapshot_state}
- rc: ${incident_snapshot_rc}
- bundle_dir: ${incident_bundle_effective}
- artifact_state: ${incident_artifact_state}
- attach_count: ${incident_attach_count}
- attach_artifacts_csv: ${incident_attach_list}
- summary_json: ${incident_summary_json_effective}
- report_md: ${incident_report_md_effective}
- bundle_tar: ${incident_bundle_tar_effective}
- bundle_tar_sha256_file: ${incident_bundle_tar_sha_effective}
- attachment_manifest: ${incident_attachment_manifest_effective}
- attachment_skipped: ${incident_attachment_skipped_effective}
- summary_required: ${incident_summary_required}
- summary_required_met: ${incident_summary_required_met}
- bundle_required: ${incident_bundle_required}
- bundle_required_met: ${incident_bundle_required_met}
- required_artifacts_met: ${incident_required_artifacts_met}
- attachment_manifest_required: ${incident_attachment_manifest_required}
- attachment_manifest_required_met: ${incident_attachment_manifest_required_met}
- attachment_no_skips_required: ${incident_attachment_no_skips_required}
- attachment_no_skips_required_met: ${incident_attachment_no_skips_required_met}
- attach_min_count_required: ${incident_attach_min_count}
- attach_min_count_required_met: ${incident_attach_min_count_required_met}
- attachment_manifest_min_count_required: ${incident_attachment_manifest_min_count}
- attachment_manifest_min_count_required_met: ${incident_attachment_manifest_min_count_met}
- attachment_policy_failure_count: ${incident_attachment_policy_failure_count}
- required_attachment_policy_met: ${incident_required_attachment_policy_met}
- required_policies_met: ${incident_required_policies_met}
EOF_REPORT

echo "[prod-operator-lifecycle-runbook] action=$action mode=$resolved_mode status=$status"
echo "[prod-operator-lifecycle-runbook] summary_json=$summary_json"
echo "[prod-operator-lifecycle-runbook] report_md=$report_md"
if [[ "$federation_wait_summary_state" == "captured" ]]; then
  echo "[prod-operator-lifecycle-runbook] federation_wait_summary_json=$federation_wait_summary_json"
fi
if [[ -f "$federation_wait_file" ]]; then
  echo "[prod-operator-lifecycle-runbook] federation_wait_file=$federation_wait_file"
fi
if [[ "$federation_status_summary_state" == "captured" ]]; then
  echo "[prod-operator-lifecycle-runbook] federation_status_summary_json=$federation_status_summary_json"
fi
if [[ -n "$runtime_doctor_file_effective" && -f "$runtime_doctor_file_effective" ]]; then
  echo "[prod-operator-lifecycle-runbook] runtime_doctor_file=$runtime_doctor_file_effective"
fi
if [[ "$incident_snapshot_state" == captured* ]]; then
  if [[ -n "$incident_summary_json_effective" ]]; then
    echo "[prod-operator-lifecycle-runbook] incident_summary_json=$incident_summary_json_effective"
  fi
  if [[ -n "$incident_report_md_effective" ]]; then
    echo "[prod-operator-lifecycle-runbook] incident_report_md=$incident_report_md_effective"
  fi
  if [[ -n "$incident_bundle_tar_effective" ]]; then
    echo "[prod-operator-lifecycle-runbook] incident_bundle_tar=$incident_bundle_tar_effective"
  fi
fi
if [[ "$print_summary_json" == "1" ]]; then
  echo "[prod-operator-lifecycle-runbook] summary_json_payload:"
  cat "$summary_json"
fi

if [[ "$status" != "ok" ]]; then
  exit "$failure_rc"
fi
