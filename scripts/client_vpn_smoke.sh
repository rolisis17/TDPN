#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/client_vpn_smoke.sh \
    [--directory-urls URL[,URL...]] \
    [--bootstrap-directory URL] \
    [--discovery-wait-sec N] \
    [--issuer-url URL] \
    [--issuer-urls URL[,URL...]] \
    [--entry-url URL] \
    [--exit-url URL] \
    [--subject ID | --anon-cred TOKEN] \
    [--min-sources N] \
    [--min-operators N] \
    [--path-profile 1hop|2hop|3hop|speed|balanced|private] \
    [--distinct-operators [0|1]] \
    [--distinct-countries [0|1]] \
    [--exit-country CC] \
    [--exit-region REGION] \
    [--locality-soft-bias [0|1]] \
    [--country-bias N] \
    [--region-bias N] \
    [--region-prefix-bias N] \
    [--beta-profile [0|1]] \
    [--prod-profile [0|1]] \
    [--operator-floor-check [0|1]] \
    [--issuer-quorum-check [0|1]] \
    [--issuer-min-operators N] \
    [--interface IFACE] \
    [--proxy-addr HOST:PORT] \
    [--private-key-file PATH] \
    [--allowed-ips CIDR] \
    [--install-route [0|1]] \
    [--startup-sync-timeout-sec N] \
    [--ready-timeout-sec N] \
    [--mtls-ca-file PATH] \
    [--mtls-client-cert-file PATH] \
    [--mtls-client-key-file PATH] \
    [--run-preflight [0|1]] \
    [--defer-no-root [0|1]] \
    [--status-check [0|1]] \
    [--keep-up [0|1]] \
    [--record-result [0|1]] \
    [--pre-real-host-readiness [0|1]] \
    [--pre-real-host-readiness-summary-json PATH] \
    [--runtime-doctor [0|1]] \
    [--runtime-fix [0|1]] \
    [--runtime-fix-prune-wg-only-dir [0|1]] \
    [--trust-reset-on-key-mismatch [0|1]] \
    [--trust-reset-scope scoped|global] \
    [--runtime-base-port N] \
    [--runtime-client-iface IFACE] \
    [--runtime-exit-iface IFACE] \
    [--runtime-vpn-iface IFACE] \
    [--incident-snapshot-on-fail [0|1]] \
    [--incident-snapshot-timeout-sec N] \
    [--incident-bundle-dir PATH] \
    [--manual-validation-report [0|1]] \
    [--manual-validation-report-summary-json PATH] \
    [--manual-validation-report-md PATH] \
    [--public-ip-url URL] \
    [--country-url URL] \
    [--curl-timeout-sec N] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run a real host client-VPN smoke flow end-to-end and record the result into
  manual-validation status automatically.

Default behavior:
  If you do not supply a path profile or expert path-selection overrides, this
  wrapper defaults to the public `balanced` path profile.
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

first_csv_value() {
  local csv="$1"
  if [[ -z "$csv" ]]; then
    return 0
  fi
  printf '%s' "$csv" | cut -d',' -f1
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

prepare_log_dir() {
  local dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
  mkdir -p "$dir"
  printf '%s\n' "$dir"
}

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

append_opt() {
  local array_name="$1"
  local flag="$2"
  local value="${3:-}"
  if [[ -n "$value" ]]; then
    eval "$array_name+=(\"\$flag\" \"\$value\")"
  fi
}

easy_node_script="${CLIENT_VPN_SMOKE_EASY_NODE_SCRIPT:-$ROOT_DIR/scripts/easy_node.sh}"
incident_snapshot_attach_script="${CLIENT_VPN_SMOKE_INCIDENT_ATTACH_SCRIPT:-$ROOT_DIR/scripts/incident_snapshot_attach_artifacts.sh}"
curl_bin="${CLIENT_VPN_SMOKE_CURL_BIN:-curl}"
if [[ ! -x "$easy_node_script" ]]; then
  echo "missing easy_node helper script: $easy_node_script"
  exit 2
fi
if [[ ! -x "$incident_snapshot_attach_script" ]]; then
  echo "missing incident snapshot attach helper script: $incident_snapshot_attach_script"
  exit 2
fi
original_args=("$@")

directory_urls=""
bootstrap_directory=""
discovery_wait_sec=""
issuer_url=""
issuer_urls=""
entry_url=""
exit_url=""
subject=""
anon_cred=""
min_sources=""
min_operators=""
path_profile=""
distinct_operators=""
distinct_countries=""
exit_country=""
exit_region=""
locality_soft_bias=""
country_bias=""
region_bias=""
region_prefix_bias=""
beta_profile=""
prod_profile=""
operator_floor_check=""
issuer_quorum_check=""
issuer_min_operators=""
interface_name=""
proxy_addr=""
private_key_file=""
allowed_ips=""
install_route=""
startup_sync_timeout_sec=""
ready_timeout_sec=""
mtls_ca_file=""
mtls_client_cert_file=""
mtls_client_key_file=""

run_preflight="1"
defer_no_root="${CLIENT_VPN_SMOKE_DEFER_NO_ROOT:-0}"
status_check="1"
keep_up="0"
record_result="1"
pre_real_host_readiness_enabled="0"
pre_real_host_readiness_summary_json=""
runtime_doctor_enabled="1"
runtime_fix_on_non_ok="0"
runtime_fix_prune_wg_only_dir="1"
trust_reset_on_key_mismatch="0"
trust_reset_scope=""
runtime_base_port="${EASY_NODE_DOCTOR_WG_ONLY_BASE_PORT:-19280}"
runtime_client_iface="${EASY_NODE_DOCTOR_CLIENT_IFACE:-wgcstack0}"
runtime_exit_iface="${EASY_NODE_DOCTOR_EXIT_IFACE:-wgestack0}"
runtime_vpn_iface="${EASY_NODE_DOCTOR_VPN_IFACE:-wgvpn0}"
runtime_vpn_iface_explicit="0"
incident_snapshot_on_fail="1"
incident_snapshot_timeout_sec="8"
incident_bundle_dir=""
manual_validation_report_enabled="1"
manual_validation_report_summary_json=""
manual_validation_report_md=""
public_ip_url=""
country_url=""
curl_timeout_sec="10"
summary_json=""
print_summary_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --directory-urls) directory_urls="${2:-}"; shift 2 ;;
    --bootstrap-directory) bootstrap_directory="${2:-}"; shift 2 ;;
    --discovery-wait-sec) discovery_wait_sec="${2:-}"; shift 2 ;;
    --issuer-url) issuer_url="${2:-}"; shift 2 ;;
    --issuer-urls) issuer_urls="${2:-}"; shift 2 ;;
    --entry-url) entry_url="${2:-}"; shift 2 ;;
    --exit-url) exit_url="${2:-}"; shift 2 ;;
    --subject) subject="${2:-}"; shift 2 ;;
    --anon-cred) anon_cred="${2:-}"; shift 2 ;;
    --min-sources) min_sources="${2:-}"; shift 2 ;;
    --min-operators) min_operators="${2:-}"; shift 2 ;;
    --path-profile) path_profile="${2:-}"; shift 2 ;;
    --distinct-operators) distinct_operators="${2:-1}"; shift 2 ;;
    --distinct-countries) distinct_countries="${2:-1}"; shift 2 ;;
    --exit-country) exit_country="${2:-}"; shift 2 ;;
    --exit-region) exit_region="${2:-}"; shift 2 ;;
    --locality-soft-bias) locality_soft_bias="${2:-1}"; shift 2 ;;
    --country-bias) country_bias="${2:-}"; shift 2 ;;
    --region-bias) region_bias="${2:-}"; shift 2 ;;
    --region-prefix-bias) region_prefix_bias="${2:-}"; shift 2 ;;
    --beta-profile) beta_profile="${2:-1}"; shift 2 ;;
    --prod-profile) prod_profile="${2:-1}"; shift 2 ;;
    --operator-floor-check) operator_floor_check="${2:-1}"; shift 2 ;;
    --issuer-quorum-check) issuer_quorum_check="${2:-1}"; shift 2 ;;
    --issuer-min-operators) issuer_min_operators="${2:-}"; shift 2 ;;
    --interface) interface_name="${2:-}"; shift 2 ;;
    --proxy-addr) proxy_addr="${2:-}"; shift 2 ;;
    --private-key-file) private_key_file="${2:-}"; shift 2 ;;
    --allowed-ips) allowed_ips="${2:-}"; shift 2 ;;
    --install-route) install_route="${2:-1}"; shift 2 ;;
    --startup-sync-timeout-sec) startup_sync_timeout_sec="${2:-}"; shift 2 ;;
    --ready-timeout-sec) ready_timeout_sec="${2:-}"; shift 2 ;;
    --mtls-ca-file) mtls_ca_file="${2:-}"; shift 2 ;;
    --mtls-client-cert-file) mtls_client_cert_file="${2:-}"; shift 2 ;;
    --mtls-client-key-file) mtls_client_key_file="${2:-}"; shift 2 ;;
    --run-preflight)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_preflight="${2:-}"
        shift 2
      else
        run_preflight="1"
        shift
      fi
      ;;
    --defer-no-root)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        defer_no_root="${2:-}"
        shift 2
      else
        defer_no_root="1"
        shift
      fi
      ;;
    --status-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        status_check="${2:-}"
        shift 2
      else
        status_check="1"
        shift
      fi
      ;;
    --keep-up)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        keep_up="${2:-}"
        shift 2
      else
        keep_up="1"
        shift
      fi
      ;;
    --record-result)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        record_result="${2:-}"
        shift 2
      else
        record_result="1"
        shift
      fi
      ;;
    --pre-real-host-readiness)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        pre_real_host_readiness_enabled="${2:-}"
        shift 2
      else
        pre_real_host_readiness_enabled="1"
        shift
      fi
      ;;
    --pre-real-host-readiness-summary-json) pre_real_host_readiness_summary_json="${2:-}"; shift 2 ;;
    --runtime-doctor)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        runtime_doctor_enabled="${2:-}"
        shift 2
      else
        runtime_doctor_enabled="1"
        shift
      fi
      ;;
    --runtime-fix)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        runtime_fix_on_non_ok="${2:-}"
        shift 2
      else
        runtime_fix_on_non_ok="1"
        shift
      fi
      ;;
    --runtime-fix-prune-wg-only-dir)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        runtime_fix_prune_wg_only_dir="${2:-}"
        shift 2
      else
        runtime_fix_prune_wg_only_dir="1"
        shift
      fi
      ;;
    --trust-reset-on-key-mismatch)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        trust_reset_on_key_mismatch="${2:-}"
        shift 2
      else
        trust_reset_on_key_mismatch="1"
        shift
      fi
      ;;
    --trust-reset-scope) trust_reset_scope="${2:-}"; shift 2 ;;
    --runtime-base-port) runtime_base_port="${2:-}"; shift 2 ;;
    --runtime-client-iface) runtime_client_iface="${2:-}"; shift 2 ;;
    --runtime-exit-iface) runtime_exit_iface="${2:-}"; shift 2 ;;
    --runtime-vpn-iface)
      runtime_vpn_iface="${2:-}"
      runtime_vpn_iface_explicit="1"
      shift 2
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
    --incident-snapshot-timeout-sec) incident_snapshot_timeout_sec="${2:-}"; shift 2 ;;
    --incident-bundle-dir) incident_bundle_dir="${2:-}"; shift 2 ;;
    --manual-validation-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        manual_validation_report_enabled="${2:-}"
        shift 2
      else
        manual_validation_report_enabled="1"
        shift
      fi
      ;;
    --manual-validation-report-summary-json) manual_validation_report_summary_json="${2:-}"; shift 2 ;;
    --manual-validation-report-md) manual_validation_report_md="${2:-}"; shift 2 ;;
    --public-ip-url) public_ip_url="${2:-}"; shift 2 ;;
    --country-url) country_url="${2:-}"; shift 2 ;;
    --curl-timeout-sec) curl_timeout_sec="${2:-}"; shift 2 ;;
    --summary-json) summary_json="${2:-}"; shift 2 ;;
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

bool_arg_or_die "--run-preflight" "$run_preflight"
bool_arg_or_die "--defer-no-root" "$defer_no_root"
bool_arg_or_die "--status-check" "$status_check"
bool_arg_or_die "--keep-up" "$keep_up"
bool_arg_or_die "--record-result" "$record_result"
bool_arg_or_die "--pre-real-host-readiness" "$pre_real_host_readiness_enabled"
bool_arg_or_die "--runtime-doctor" "$runtime_doctor_enabled"
bool_arg_or_die "--runtime-fix" "$runtime_fix_on_non_ok"
bool_arg_or_die "--runtime-fix-prune-wg-only-dir" "$runtime_fix_prune_wg_only_dir"
bool_arg_or_die "--trust-reset-on-key-mismatch" "$trust_reset_on_key_mismatch"
bool_arg_or_die "--incident-snapshot-on-fail" "$incident_snapshot_on_fail"
bool_arg_or_die "--manual-validation-report" "$manual_validation_report_enabled"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
if ! [[ "$curl_timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "--curl-timeout-sec must be an integer"
  exit 2
fi
if ! [[ "$runtime_base_port" =~ ^[0-9]+$ ]]; then
  echo "--runtime-base-port must be an integer"
  exit 2
fi
if [[ -z "$runtime_client_iface" || -z "$runtime_exit_iface" ]]; then
  echo "--runtime-client-iface and --runtime-exit-iface must be non-empty"
  exit 2
fi
if ! [[ "$incident_snapshot_timeout_sec" =~ ^[0-9]+$ ]] || ((incident_snapshot_timeout_sec < 1)); then
  echo "--incident-snapshot-timeout-sec must be >= 1"
  exit 2
fi
if [[ "$runtime_vpn_iface_explicit" == "1" && -z "$runtime_vpn_iface" ]]; then
  echo "--runtime-vpn-iface must be non-empty"
  exit 2
fi
if [[ -n "$trust_reset_scope" ]]; then
  trust_reset_scope="$(trim "$trust_reset_scope" | tr '[:upper:]' '[:lower:]')"
  if [[ "$trust_reset_scope" != "scoped" && "$trust_reset_scope" != "global" ]]; then
    echo "--trust-reset-scope must be one of: scoped, global"
    exit 2
  fi
fi
if [[ "$runtime_vpn_iface_explicit" != "1" && -n "$interface_name" ]]; then
  runtime_vpn_iface="$interface_name"
fi
if [[ -z "$path_profile" && -z "$distinct_operators" && -z "$distinct_countries" && -z "$locality_soft_bias" && -z "$country_bias" && -z "$region_bias" && -z "$region_prefix_bias" ]]; then
  path_profile="balanced"
fi

log_dir="$(prepare_log_dir)"
timestamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/client_vpn_smoke_${timestamp}.json"
fi
if [[ -z "$pre_real_host_readiness_summary_json" ]]; then
  pre_real_host_readiness_summary_json="$log_dir/client_vpn_smoke_${timestamp}_pre_real_host_readiness.json"
fi
if [[ -z "$manual_validation_report_summary_json" ]]; then
  manual_validation_report_summary_json="$log_dir/manual_validation_readiness_summary.json"
fi
if [[ -z "$manual_validation_report_md" ]]; then
  manual_validation_report_md="$log_dir/manual_validation_readiness_report.md"
fi
mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$pre_real_host_readiness_summary_json")"
mkdir -p "$(dirname "$manual_validation_report_summary_json")" "$(dirname "$manual_validation_report_md")"
summary_log="$log_dir/client_vpn_smoke_${timestamp}.log"
: >"$summary_log"
pre_real_host_readiness_log="$log_dir/client_vpn_smoke_${timestamp}_pre_real_host_readiness.log"
runtime_doctor_before_log="$log_dir/client_vpn_smoke_${timestamp}_runtime_doctor_before.log"
runtime_doctor_before_json="$log_dir/client_vpn_smoke_${timestamp}_runtime_doctor_before.json"
runtime_fix_log="$log_dir/client_vpn_smoke_${timestamp}_runtime_fix.log"
runtime_fix_json="$log_dir/client_vpn_smoke_${timestamp}_runtime_fix.json"
runtime_doctor_after_log="$log_dir/client_vpn_smoke_${timestamp}_runtime_doctor_after.log"
runtime_doctor_after_json="$log_dir/client_vpn_smoke_${timestamp}_runtime_doctor_after.json"
trust_reset_log="$log_dir/client_vpn_smoke_${timestamp}_trust_reset.log"
up_retry_log="$log_dir/client_vpn_smoke_${timestamp}_up_retry.log"
incident_snapshot_log="$log_dir/client_vpn_smoke_${timestamp}_incident_snapshot.log"
incident_snapshot_refresh_log="$log_dir/client_vpn_smoke_${timestamp}_incident_snapshot_refresh.log"
manual_validation_report_log="$log_dir/client_vpn_smoke_${timestamp}_manual_validation_report.log"

declare -a preflight_cmd up_cmd down_cmd status_cmd
declare -a pre_real_host_readiness_cmd runtime_doctor_cmd runtime_fix_cmd
preflight_cmd=("$easy_node_script" "client-vpn-preflight")
up_cmd=("$easy_node_script" "client-vpn-up")
status_cmd=("$easy_node_script" "client-vpn-status")
down_cmd=("$easy_node_script" "client-vpn-down" "--force-iface-cleanup" "1")
pre_real_host_readiness_cmd=(
  "$easy_node_script" "pre-real-host-readiness"
  "--base-port" "$runtime_base_port"
  "--client-iface" "$runtime_client_iface"
  "--exit-iface" "$runtime_exit_iface"
  "--vpn-iface" "$runtime_vpn_iface"
  "--runtime-fix-prune-wg-only-dir" "$runtime_fix_prune_wg_only_dir"
  "--summary-json" "$pre_real_host_readiness_summary_json"
  "--manual-validation-report-summary-json" "$manual_validation_report_summary_json"
  "--manual-validation-report-md" "$manual_validation_report_md"
  "--print-summary-json" "1"
)
runtime_doctor_cmd=(
  "$easy_node_script" "runtime-doctor"
  "--base-port" "$runtime_base_port"
  "--client-iface" "$runtime_client_iface"
  "--exit-iface" "$runtime_exit_iface"
  "--vpn-iface" "$runtime_vpn_iface"
  "--show-json" "1"
)
runtime_fix_cmd=(
  "$easy_node_script" "runtime-fix"
  "--base-port" "$runtime_base_port"
  "--client-iface" "$runtime_client_iface"
  "--exit-iface" "$runtime_exit_iface"
  "--vpn-iface" "$runtime_vpn_iface"
  "--prune-wg-only-dir" "$runtime_fix_prune_wg_only_dir"
  "--show-json" "1"
)

append_opt preflight_cmd "--directory-urls" "$directory_urls"
append_opt preflight_cmd "--bootstrap-directory" "$bootstrap_directory"
append_opt preflight_cmd "--discovery-wait-sec" "$discovery_wait_sec"
append_opt preflight_cmd "--issuer-url" "$issuer_url"
append_opt preflight_cmd "--issuer-urls" "$issuer_urls"
append_opt preflight_cmd "--entry-url" "$entry_url"
append_opt preflight_cmd "--exit-url" "$exit_url"
append_opt preflight_cmd "--prod-profile" "$prod_profile"
append_opt preflight_cmd "--interface" "$interface_name"
append_opt preflight_cmd "--operator-floor-check" "$operator_floor_check"
append_opt preflight_cmd "--issuer-quorum-check" "$issuer_quorum_check"
append_opt preflight_cmd "--issuer-min-operators" "$issuer_min_operators"
append_opt preflight_cmd "--mtls-ca-file" "$mtls_ca_file"
append_opt preflight_cmd "--mtls-client-cert-file" "$mtls_client_cert_file"
append_opt preflight_cmd "--mtls-client-key-file" "$mtls_client_key_file"

append_opt up_cmd "--directory-urls" "$directory_urls"
append_opt up_cmd "--bootstrap-directory" "$bootstrap_directory"
append_opt up_cmd "--discovery-wait-sec" "$discovery_wait_sec"
append_opt up_cmd "--issuer-url" "$issuer_url"
append_opt up_cmd "--issuer-urls" "$issuer_urls"
append_opt up_cmd "--entry-url" "$entry_url"
append_opt up_cmd "--exit-url" "$exit_url"
append_opt up_cmd "--subject" "$subject"
append_opt up_cmd "--anon-cred" "$anon_cred"
append_opt up_cmd "--min-sources" "$min_sources"
append_opt up_cmd "--min-operators" "$min_operators"
append_opt up_cmd "--path-profile" "$path_profile"
append_opt up_cmd "--distinct-operators" "$distinct_operators"
append_opt up_cmd "--distinct-countries" "$distinct_countries"
append_opt up_cmd "--exit-country" "$exit_country"
append_opt up_cmd "--exit-region" "$exit_region"
append_opt up_cmd "--locality-soft-bias" "$locality_soft_bias"
append_opt up_cmd "--country-bias" "$country_bias"
append_opt up_cmd "--region-bias" "$region_bias"
append_opt up_cmd "--region-prefix-bias" "$region_prefix_bias"
append_opt up_cmd "--beta-profile" "$beta_profile"
append_opt up_cmd "--prod-profile" "$prod_profile"
append_opt up_cmd "--operator-floor-check" "$operator_floor_check"
append_opt up_cmd "--issuer-quorum-check" "$issuer_quorum_check"
append_opt up_cmd "--issuer-min-operators" "$issuer_min_operators"
append_opt up_cmd "--interface" "$interface_name"
append_opt up_cmd "--proxy-addr" "$proxy_addr"
append_opt up_cmd "--private-key-file" "$private_key_file"
append_opt up_cmd "--allowed-ips" "$allowed_ips"
append_opt up_cmd "--install-route" "$install_route"
append_opt up_cmd "--startup-sync-timeout-sec" "$startup_sync_timeout_sec"
append_opt up_cmd "--ready-timeout-sec" "$ready_timeout_sec"
append_opt up_cmd "--mtls-ca-file" "$mtls_ca_file"
append_opt up_cmd "--mtls-client-cert-file" "$mtls_client_cert_file"
append_opt up_cmd "--mtls-client-key-file" "$mtls_client_key_file"

append_opt down_cmd "--iface" "$interface_name"

stage="init"
up_succeeded="0"
status_output=""
public_ip_result=""
country_result=""
runtime_doctor_status_before=""
runtime_doctor_status_after=""
runtime_doctor_findings_before="0"
runtime_doctor_findings_after="0"
pre_real_host_readiness_status="skipped"
pre_real_host_readiness_machine_c_ready=""
pre_real_host_readiness_next_command=""
pre_real_host_readiness_readiness_status=""
pre_real_host_readiness_report_summary_json=""
pre_real_host_readiness_report_md=""
pre_real_host_readiness_blockers_json="[]"
runtime_fix_attempted="0"
runtime_fix_after_status=""
runtime_fix_actions_taken="0"
runtime_fix_actions_failed="0"
trust_reset_attempted="0"
trust_reset_status="skipped"
trust_reset_reason=""
up_retry_attempted="0"
up_retry_succeeded="0"
trust_reset_failure_note=""
smoke_status="fail"
notes=""
record_notes=""
result_stage=""
runtime_gate_failure_note=""
incident_snapshot_status="skipped"
incident_snapshot_bundle_dir=""
incident_snapshot_bundle_tar=""
incident_snapshot_summary_json=""
incident_snapshot_report_md=""
incident_snapshot_attachment_manifest=""
incident_snapshot_attachment_skipped=""
incident_snapshot_attachment_count="0"
incident_snapshot_requested_attachment_inputs_json="[]"
incident_snapshot_refresh_status="skipped"
manual_validation_report_status="skipped"
manual_validation_report_readiness_status=""
manual_validation_report_next_action_check_id=""
smoke_deferred_no_root="0"

extract_json_payload() {
  local prefix="$1"
  local text="$2"
  printf '%s\n' "$text" | awk -v p="$prefix" '$0 == "[" p "] summary_json_payload:" {flag=1; next} flag {print}'
}

extract_snapshot_output_value() {
  local key="$1"
  local text="$2"
  printf '%s\n' "$text" | sed -n "s/^${key}: //p" | head -n 1
}

persist_artifact_text() {
  local path="$1"
  local content="$2"
  [[ -z "$path" ]] && return 0
  if [[ -z "$content" ]]; then
    rm -f "$path" 2>/dev/null || true
  else
    printf '%s\n' "$content" >"$path"
  fi
}

append_existing_artifact() {
  local array_name="$1"
  local artifact_path="$2"
  if [[ -n "$artifact_path" && -e "$artifact_path" ]]; then
    eval "$array_name+=(\"\$artifact_path\")"
  fi
}

json_array_from_paths() {
  local path
  if [[ "$#" -eq 0 ]]; then
    printf '[]\n'
    return 0
  fi
  for path in "$@"; do
    printf '%s\n' "$path"
  done | jq -Rsc 'split("\n") | map(select(length > 0))'
}
run_and_capture() {
  local __var_name="$1"
  shift
  local tmp rc
  tmp="$(mktemp)"
  if "$@" >"$tmp" 2>&1; then
    printf '%s\n' "[$stage] command_ok: $(print_cmd "$@")" >>"$summary_log"
    cat "$tmp" >>"$summary_log"
    printf -v "$__var_name" '%s' "$(cat "$tmp")"
    rm -f "$tmp"
    return 0
  else
    rc=$?
    printf '%s\n' "[$stage] command_failed rc=$rc: $(print_cmd "$@")" >>"$summary_log"
    cat "$tmp" >>"$summary_log"
    printf -v "$__var_name" '%s' "$(cat "$tmp")"
    rm -f "$tmp"
    return "$rc"
  fi
}

output_indicates_no_root_requirement() {
  local text="$1"
  if [[ -z "$text" ]]; then
    return 1
  fi
  if printf '%s\n' "$text" | grep -Eqi 'requires root|run preflight with sudo|must be root|permission denied|operation not permitted'; then
    return 0
  fi
  return 1
}

defer_no_root_on_failure() {
  local failed_output="$1"
  local defer_note="$2"
  if [[ "$defer_no_root" != "1" ]]; then
    return 1
  fi
  if ! output_indicates_no_root_requirement "$failed_output"; then
    return 1
  fi
  smoke_deferred_no_root="1"
  result_stage="$stage"
  finish_and_record "skip" "$defer_note"
  return 0
}

attempt_up_retry_with_trust_reset() {
  local failed_up_output="$1"
  local trust_reset_output=""
  local retry_up_output=""
  local -a trust_reset_cmd=()

  trust_reset_attempted="0"
  trust_reset_status="skipped"
  trust_reset_reason=""
  up_retry_attempted="0"
  up_retry_succeeded="0"
  trust_reset_failure_note=""
  rm -f "$trust_reset_log" "$up_retry_log" 2>/dev/null || true

  if [[ "$trust_reset_on_key_mismatch" != "1" ]]; then
    return 1
  fi
  if ! printf '%s\n' "$failed_up_output" | rg -q 'directory key is not trusted'; then
    return 1
  fi

  trust_reset_attempted="1"
  trust_reset_reason="directory key is not trusted"
  trust_reset_cmd=("$easy_node_script" "client-vpn-trust-reset")
  append_opt trust_reset_cmd "--directory-urls" "$directory_urls"
  append_opt trust_reset_cmd "--bootstrap-directory" "$bootstrap_directory"
  append_opt trust_reset_cmd "--discovery-wait-sec" "$discovery_wait_sec"
  append_opt trust_reset_cmd "--trust-scope" "$trust_reset_scope"

  stage="trust-reset"
  if run_and_capture trust_reset_output "${trust_reset_cmd[@]}"; then
    trust_reset_status="ok"
  else
    trust_reset_status="fail"
    trust_reset_failure_note="client-vpn up failed and trust reset did not complete"
  fi
  persist_artifact_text "$trust_reset_log" "$trust_reset_output"
  if [[ "$trust_reset_status" != "ok" ]]; then
    return 1
  fi

  stage="up-retry"
  up_retry_attempted="1"
  if run_and_capture retry_up_output "${up_cmd[@]}"; then
    up_retry_succeeded="1"
    up_succeeded="1"
  else
    up_retry_succeeded="0"
    trust_reset_failure_note="client-vpn up failed after trust reset retry"
  fi
  persist_artifact_text "$up_retry_log" "$retry_up_output"
  if [[ "$up_retry_succeeded" != "1" ]]; then
    return 1
  fi
  return 0
}

cleanup_down() {
  if [[ "$keep_up" == "1" || "$up_succeeded" != "1" ]]; then
    return 0
  fi
  stage="cleanup"
  local cleanup_output=""
  run_and_capture cleanup_output "${down_cmd[@]}" || true
}

run_runtime_gate() {
  local doctor_output=""
  local doctor_json=""
  local doctor_status=""
  local doctor_findings="0"
  local fix_output=""
  local fix_json=""

  if [[ "$runtime_doctor_enabled" != "1" ]]; then
    return 0
  fi

  stage="runtime-doctor"
  if ! run_and_capture doctor_output "${runtime_doctor_cmd[@]}"; then
    :
  fi
  doctor_json="$(extract_json_payload "runtime-doctor" "$doctor_output")"
  persist_artifact_text "$runtime_doctor_before_log" "$doctor_output"
  persist_artifact_text "$runtime_doctor_before_json" "$doctor_json"
  if [[ -z "$doctor_json" ]]; then
    runtime_gate_failure_note="runtime-doctor did not emit JSON summary"
    return 1
  fi
  doctor_status="$(printf '%s\n' "$doctor_json" | jq -r '.status // ""')"
  doctor_findings="$(printf '%s\n' "$doctor_json" | jq -r '.summary.findings_total // 0')"
  runtime_doctor_status_before="$doctor_status"
  runtime_doctor_findings_before="$doctor_findings"
  runtime_doctor_status_after="$doctor_status"
  runtime_doctor_findings_after="$doctor_findings"

  if [[ "$doctor_status" == "OK" ]]; then
    return 0
  fi

  if [[ "$runtime_fix_on_non_ok" != "1" ]]; then
    runtime_gate_failure_note="runtime hygiene not ready (${doctor_status}); review runtime-doctor or rerun with --runtime-fix 1"
    return 1
  fi

  stage="runtime-fix"
  runtime_fix_attempted="1"
  if ! run_and_capture fix_output "${runtime_fix_cmd[@]}"; then
    :
  fi
  fix_json="$(extract_json_payload "runtime-fix" "$fix_output")"
  persist_artifact_text "$runtime_fix_log" "$fix_output"
  persist_artifact_text "$runtime_fix_json" "$fix_json"
  if [[ -n "$fix_json" ]]; then
    runtime_fix_after_status="$(printf '%s\n' "$fix_json" | jq -r '.doctor.after.status // ""')"
    runtime_fix_actions_taken="$(printf '%s\n' "$fix_json" | jq -r '(.actions.taken // []) | length')"
    runtime_fix_actions_failed="$(printf '%s\n' "$fix_json" | jq -r '(.actions.failed // []) | length')"
  fi

  stage="runtime-doctor"
  if ! run_and_capture doctor_output "${runtime_doctor_cmd[@]}"; then
    :
  fi
  doctor_json="$(extract_json_payload "runtime-doctor" "$doctor_output")"
  persist_artifact_text "$runtime_doctor_after_log" "$doctor_output"
  persist_artifact_text "$runtime_doctor_after_json" "$doctor_json"
  if [[ -z "$doctor_json" ]]; then
    runtime_gate_failure_note="runtime-doctor did not emit JSON summary after runtime-fix"
    return 1
  fi
  runtime_doctor_status_after="$(printf '%s\n' "$doctor_json" | jq -r '.status // ""')"
  runtime_doctor_findings_after="$(printf '%s\n' "$doctor_json" | jq -r '.summary.findings_total // 0')"
  if [[ "$runtime_doctor_status_after" != "OK" ]]; then
    runtime_gate_failure_note="runtime hygiene not ready after runtime-fix (${runtime_doctor_status_after})"
    return 1
  fi
  return 0
}

run_pre_real_host_readiness_gate() {
  local readiness_output=""
  local readiness_json=""
  local readiness_rc=0

  pre_real_host_readiness_status="skipped"
  pre_real_host_readiness_machine_c_ready=""
  pre_real_host_readiness_next_command=""
  pre_real_host_readiness_readiness_status=""
  pre_real_host_readiness_report_summary_json=""
  pre_real_host_readiness_report_md=""
  pre_real_host_readiness_blockers_json="[]"
  rm -f "$pre_real_host_readiness_log" 2>/dev/null || true

  if [[ "$pre_real_host_readiness_enabled" != "1" ]]; then
    return 0
  fi

  stage="pre-real-host-readiness"
  if run_and_capture readiness_output "${pre_real_host_readiness_cmd[@]}"; then
    readiness_rc=0
  else
    readiness_rc=$?
  fi
  persist_artifact_text "$pre_real_host_readiness_log" "$readiness_output"

  readiness_json="$(extract_json_payload "pre-real-host-readiness" "$readiness_output")"
  if [[ -z "$readiness_json" && -f "$pre_real_host_readiness_summary_json" ]] && jq -e . "$pre_real_host_readiness_summary_json" >/dev/null 2>&1; then
    readiness_json="$(cat "$pre_real_host_readiness_summary_json")"
  fi
  if [[ -z "$readiness_json" ]]; then
    pre_real_host_readiness_status="fail"
    runtime_gate_failure_note="pre-real-host readiness did not emit JSON summary"
    return 1
  fi

  pre_real_host_readiness_status="$(printf '%s\n' "$readiness_json" | jq -r '.status // "fail"' 2>/dev/null || printf 'fail')"
  pre_real_host_readiness_machine_c_ready="$(printf '%s\n' "$readiness_json" | jq -r '.machine_c_smoke_gate.ready // false' 2>/dev/null || printf 'false')"
  pre_real_host_readiness_next_command="$(printf '%s\n' "$readiness_json" | jq -r '.machine_c_smoke_gate.next_command // ""' 2>/dev/null || true)"
  pre_real_host_readiness_readiness_status="$(printf '%s\n' "$readiness_json" | jq -r '.manual_validation_report.readiness_status // ""' 2>/dev/null || true)"
  pre_real_host_readiness_report_summary_json="$(printf '%s\n' "$readiness_json" | jq -r '.manual_validation_report.summary_json // ""' 2>/dev/null || true)"
  pre_real_host_readiness_report_md="$(printf '%s\n' "$readiness_json" | jq -r '.manual_validation_report.report_md // ""' 2>/dev/null || true)"
  pre_real_host_readiness_blockers_json="$(printf '%s\n' "$readiness_json" | jq -c '.machine_c_smoke_gate.blockers // []' 2>/dev/null || printf '[]')"

  if [[ "$readiness_rc" -ne 0 || "$pre_real_host_readiness_machine_c_ready" != "true" ]]; then
    runtime_gate_failure_note="pre-real-host readiness gate blocked machine-C smoke"
    return 1
  fi

  return 0
}

run_incident_snapshot_on_fail() {
  local final_status="$1"
  local snapshot_output=""
  local local_directory_url=""
  local local_issuer_url=""
  local resolved_bundle_dir=""
  local artifact_path=""
  local -a incident_snapshot_cmd=()
  local -a incident_snapshot_attach_candidates=()
  local -a incident_snapshot_attached_artifacts=()

  incident_snapshot_status="skipped"
  incident_snapshot_bundle_dir=""
  incident_snapshot_bundle_tar=""
  incident_snapshot_summary_json=""
  incident_snapshot_report_md=""
  incident_snapshot_attachment_manifest=""
  incident_snapshot_attachment_skipped=""
  incident_snapshot_attachment_count="0"
  incident_snapshot_requested_attachment_inputs_json="[]"
  rm -f "$incident_snapshot_log" 2>/dev/null || true

  if [[ "$final_status" != "fail" || "$incident_snapshot_on_fail" != "1" ]]; then
    return 0
  fi

  if [[ -n "$bootstrap_directory" ]]; then
    local_directory_url="$bootstrap_directory"
  else
    local_directory_url="$(first_csv_value "$directory_urls")"
  fi
  if [[ -n "$issuer_url" ]]; then
    local_issuer_url="$issuer_url"
  else
    local_issuer_url="$(first_csv_value "$issuer_urls")"
  fi

  resolved_bundle_dir="$incident_bundle_dir"
  if [[ -z "$resolved_bundle_dir" ]]; then
    resolved_bundle_dir="$log_dir/client_vpn_smoke_${timestamp}_incident_snapshot"
  fi
  incident_snapshot_bundle_dir="$resolved_bundle_dir"

  incident_snapshot_attach_candidates=(
    "$summary_log"
    "$pre_real_host_readiness_log"
    "$pre_real_host_readiness_summary_json"
    "$pre_real_host_readiness_report_summary_json"
    "$pre_real_host_readiness_report_md"
    "$runtime_doctor_before_log"
    "$runtime_doctor_before_json"
    "$runtime_fix_log"
    "$runtime_fix_json"
    "$runtime_doctor_after_log"
    "$runtime_doctor_after_json"
    "$trust_reset_log"
    "$up_retry_log"
  )
  for artifact_path in "${incident_snapshot_attach_candidates[@]}"; do
    if [[ -f "$artifact_path" ]]; then
      incident_snapshot_attached_artifacts+=("$artifact_path")
    fi
  done
  incident_snapshot_requested_attachment_inputs_json="$(json_array_from_paths "${incident_snapshot_attached_artifacts[@]}")"

  incident_snapshot_cmd=(
    "$easy_node_script" incident-snapshot
    --bundle-dir "$resolved_bundle_dir"
    --mode client
    --timeout-sec "$incident_snapshot_timeout_sec"
  )
  if [[ -n "$local_directory_url" ]]; then
    incident_snapshot_cmd+=(--directory-url "$local_directory_url")
  fi
  if [[ -n "$local_issuer_url" ]]; then
    incident_snapshot_cmd+=(--issuer-url "$local_issuer_url")
  fi
  if [[ -n "$entry_url" ]]; then
    incident_snapshot_cmd+=(--entry-url "$entry_url")
  fi
  if [[ -n "$exit_url" ]]; then
    incident_snapshot_cmd+=(--exit-url "$exit_url")
  fi
  for artifact_path in "${incident_snapshot_attached_artifacts[@]}"; do
    incident_snapshot_cmd+=(--attach-artifact "$artifact_path")
  done

  stage="incident-snapshot"
  incident_snapshot_status="ok"
  if ! run_and_capture snapshot_output "${incident_snapshot_cmd[@]}"; then
    incident_snapshot_status="fail"
  fi
  persist_artifact_text "$incident_snapshot_log" "$snapshot_output"

  incident_snapshot_bundle_dir="$(extract_snapshot_output_value "bundle_dir" "$snapshot_output")"
  if [[ -z "$incident_snapshot_bundle_dir" ]]; then
    incident_snapshot_bundle_dir="$resolved_bundle_dir"
  fi
  incident_snapshot_bundle_tar="$(extract_snapshot_output_value "bundle_tar" "$snapshot_output")"
  incident_snapshot_summary_json="$(extract_snapshot_output_value "summary_json" "$snapshot_output")"
  incident_snapshot_report_md="$(extract_snapshot_output_value "report_md" "$snapshot_output")"

  if [[ -z "$incident_snapshot_bundle_tar" && -f "${incident_snapshot_bundle_dir}.tar.gz" ]]; then
    incident_snapshot_bundle_tar="${incident_snapshot_bundle_dir}.tar.gz"
  fi
  if [[ -z "$incident_snapshot_summary_json" && -f "$incident_snapshot_bundle_dir/incident_summary.json" ]]; then
    incident_snapshot_summary_json="$incident_snapshot_bundle_dir/incident_summary.json"
  fi
  if [[ -z "$incident_snapshot_report_md" && -f "$incident_snapshot_bundle_dir/incident_report.md" ]]; then
    incident_snapshot_report_md="$incident_snapshot_bundle_dir/incident_report.md"
  fi
  if [[ -f "$incident_snapshot_bundle_dir/attachments/manifest.tsv" ]]; then
    incident_snapshot_attachment_manifest="$incident_snapshot_bundle_dir/attachments/manifest.tsv"
    incident_snapshot_attachment_count="$(awk 'END {print NR+0}' "$incident_snapshot_attachment_manifest" 2>/dev/null)"
  fi
  if [[ -f "$incident_snapshot_bundle_dir/attachments/skipped.tsv" ]]; then
    incident_snapshot_attachment_skipped="$incident_snapshot_bundle_dir/attachments/skipped.tsv"
  fi
}

refresh_manual_validation_report() {
  local report_output=""
  local report_json=""
  local previous_stage="$stage"
  local -a overlay_artifacts=()
  local overlay_artifact=""
  local overlay_command=""

  manual_validation_report_status="skipped"
  manual_validation_report_readiness_status=""
  manual_validation_report_next_action_check_id=""
  rm -f "$manual_validation_report_log" 2>/dev/null || true

  if [[ "$record_result" != "1" || "$manual_validation_report_enabled" != "1" ]]; then
    return 0
  fi

  overlay_command="$(print_cmd "$0" "${original_args[@]}")"
  for overlay_artifact in \
    "$summary_log" \
    "$summary_json" \
    "$pre_real_host_readiness_log" \
    "$pre_real_host_readiness_summary_json" \
    "$pre_real_host_readiness_report_summary_json" \
    "$pre_real_host_readiness_report_md" \
    "$runtime_doctor_before_log" \
    "$runtime_doctor_before_json" \
    "$runtime_fix_log" \
    "$runtime_fix_json" \
    "$runtime_doctor_after_log" \
    "$runtime_doctor_after_json" \
    "$trust_reset_log" \
    "$up_retry_log" \
    "$incident_snapshot_log" \
    "$incident_snapshot_bundle_dir" \
    "$incident_snapshot_bundle_tar" \
    "$incident_snapshot_summary_json" \
    "$incident_snapshot_report_md" \
    "$incident_snapshot_attachment_manifest" \
    "$incident_snapshot_attachment_skipped"; do
    append_existing_artifact overlay_artifacts "$overlay_artifact"
  done

  stage="manual-validation-report"
  declare -a report_cmd=(
    "$easy_node_script" manual-validation-report
    --base-port "$runtime_base_port"
    --client-iface "$runtime_client_iface"
    --exit-iface "$runtime_exit_iface"
    --vpn-iface "$runtime_vpn_iface"
    --overlay-check-id machine_c_vpn_smoke
    --overlay-status "$smoke_status"
    --overlay-notes "$notes"
    --overlay-command "$overlay_command"
    --summary-json "$manual_validation_report_summary_json"
    --report-md "$manual_validation_report_md"
    --print-report 0
    --print-summary-json 1
  )
  for overlay_artifact in "${overlay_artifacts[@]}"; do
    report_cmd+=(--overlay-artifact "$overlay_artifact")
  done
  if run_and_capture report_output "${report_cmd[@]}"; then
    manual_validation_report_status="ok"
  else
    manual_validation_report_status="fail"
  fi
  persist_artifact_text "$manual_validation_report_log" "$report_output"

  report_json="$(extract_json_payload "manual-validation-report" "$report_output")"
  if [[ -z "$report_json" && -f "$manual_validation_report_summary_json" ]] && jq -e . "$manual_validation_report_summary_json" >/dev/null 2>&1; then
    report_json="$(cat "$manual_validation_report_summary_json")"
  fi
  if [[ -n "$report_json" ]]; then
    manual_validation_report_readiness_status="$(printf '%s\n' "$report_json" | jq -r '.report.readiness_status // ""' 2>/dev/null || true)"
    manual_validation_report_next_action_check_id="$(printf '%s\n' "$report_json" | jq -r '.summary.next_action_check_id // ""' 2>/dev/null || true)"
  fi
  stage="$previous_stage"
}

refresh_failed_incident_snapshot_attachments() {
  local previous_stage="$stage"
  local attach_output=""
  local -a attach_candidates=()
  local -a attach_artifacts=()
  local artifact_path=""
  local new_requested_json="[]"

  incident_snapshot_refresh_status="skipped"
  rm -f "$incident_snapshot_refresh_log" 2>/dev/null || true

  if [[ "$smoke_status" != "fail" || "$incident_snapshot_status" != "ok" ]]; then
    return 0
  fi
  if [[ -z "$incident_snapshot_bundle_dir" || ! -d "$incident_snapshot_bundle_dir" ]]; then
    return 0
  fi

  attach_candidates=(
    "$manual_validation_report_log"
    "$manual_validation_report_summary_json"
    "$manual_validation_report_md"
  )
  for artifact_path in "${attach_candidates[@]}"; do
    append_existing_artifact attach_artifacts "$artifact_path"
  done
  if [[ "${#attach_artifacts[@]}" -eq 0 ]]; then
    return 0
  fi

  stage="incident-snapshot-attach"
  declare -a attach_cmd=(
    "$incident_snapshot_attach_script"
    --bundle-dir "$incident_snapshot_bundle_dir"
    --print-summary-json 0
  )
  if [[ -n "$incident_snapshot_bundle_tar" ]]; then
    attach_cmd+=(--bundle-tar "$incident_snapshot_bundle_tar")
  fi
  if [[ -n "$incident_snapshot_summary_json" ]]; then
    attach_cmd+=(--summary-json "$incident_snapshot_summary_json")
  fi
  if [[ -n "$incident_snapshot_report_md" ]]; then
    attach_cmd+=(--report-md "$incident_snapshot_report_md")
  fi
  for artifact_path in "${attach_artifacts[@]}"; do
    attach_cmd+=(--attach-artifact "$artifact_path")
  done

  if run_and_capture attach_output "${attach_cmd[@]}"; then
    incident_snapshot_refresh_status="ok"
  else
    incident_snapshot_refresh_status="fail"
  fi
  persist_artifact_text "$incident_snapshot_refresh_log" "$attach_output"

  if [[ "$incident_snapshot_refresh_status" == "ok" ]]; then
    incident_snapshot_bundle_dir="$(extract_snapshot_output_value "bundle_dir" "$attach_output")"
    incident_snapshot_bundle_tar="$(extract_snapshot_output_value "bundle_tar" "$attach_output")"
    incident_snapshot_summary_json="$(extract_snapshot_output_value "summary_json" "$attach_output")"
    incident_snapshot_report_md="$(extract_snapshot_output_value "report_md" "$attach_output")"
    incident_snapshot_attachment_manifest="$(extract_snapshot_output_value "attachment_manifest" "$attach_output")"
    incident_snapshot_attachment_skipped="$(extract_snapshot_output_value "attachment_skipped" "$attach_output")"
    incident_snapshot_attachment_count="$(extract_snapshot_output_value "attachment_count" "$attach_output")"

    new_requested_json="$(json_array_from_paths "${attach_artifacts[@]}")"
    incident_snapshot_requested_attachment_inputs_json="$(
      jq -cn \
        --argjson current "${incident_snapshot_requested_attachment_inputs_json:-[]}" \
        --argjson extra "$new_requested_json" \
        '$current + $extra | map(select(type == "string" and length > 0)) | unique'
    )"
  fi

  stage="$previous_stage"
}

write_summary_json() {
  jq -n \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg status "$smoke_status" \
    --arg stage "$result_stage" \
    --arg notes "$notes" \
    --arg status_output "$status_output" \
    --arg public_ip_result "$public_ip_result" \
    --arg country_result "$country_result" \
    --arg pre_real_host_readiness_status "$pre_real_host_readiness_status" \
    --arg pre_real_host_readiness_summary_json "$pre_real_host_readiness_summary_json" \
    --arg pre_real_host_readiness_log "$pre_real_host_readiness_log" \
    --arg pre_real_host_readiness_machine_c_ready "$pre_real_host_readiness_machine_c_ready" \
    --argjson pre_real_host_readiness_blockers "$pre_real_host_readiness_blockers_json" \
    --arg pre_real_host_readiness_next_command "$pre_real_host_readiness_next_command" \
    --arg pre_real_host_readiness_readiness_status "$pre_real_host_readiness_readiness_status" \
    --arg pre_real_host_readiness_report_summary_json "$pre_real_host_readiness_report_summary_json" \
    --arg pre_real_host_readiness_report_md "$pre_real_host_readiness_report_md" \
    --arg runtime_doctor_status_before "$runtime_doctor_status_before" \
    --arg runtime_doctor_status_after "$runtime_doctor_status_after" \
    --arg runtime_doctor_findings_before "$runtime_doctor_findings_before" \
    --arg runtime_doctor_findings_after "$runtime_doctor_findings_after" \
    --arg runtime_fix_after_status "$runtime_fix_after_status" \
    --arg runtime_fix_actions_taken "$runtime_fix_actions_taken" \
    --arg runtime_fix_actions_failed "$runtime_fix_actions_failed" \
    --arg trust_reset_status "$trust_reset_status" \
    --arg trust_reset_reason "$trust_reset_reason" \
    --arg trust_reset_scope "$trust_reset_scope" \
    --arg trust_reset_log "$trust_reset_log" \
    --arg up_retry_log "$up_retry_log" \
    --arg runtime_doctor_before_log "$runtime_doctor_before_log" \
    --arg runtime_doctor_before_json "$runtime_doctor_before_json" \
    --arg runtime_fix_log "$runtime_fix_log" \
    --arg runtime_fix_json "$runtime_fix_json" \
    --arg runtime_doctor_after_log "$runtime_doctor_after_log" \
    --arg runtime_doctor_after_json "$runtime_doctor_after_json" \
    --arg incident_snapshot_status "$incident_snapshot_status" \
    --arg incident_snapshot_bundle_dir "$incident_snapshot_bundle_dir" \
    --arg incident_snapshot_bundle_tar "$incident_snapshot_bundle_tar" \
    --arg incident_snapshot_summary_json "$incident_snapshot_summary_json" \
    --arg incident_snapshot_report_md "$incident_snapshot_report_md" \
    --arg incident_snapshot_attachment_manifest "$incident_snapshot_attachment_manifest" \
    --arg incident_snapshot_attachment_skipped "$incident_snapshot_attachment_skipped" \
    --arg incident_snapshot_attachment_count "$incident_snapshot_attachment_count" \
    --arg incident_snapshot_log "$incident_snapshot_log" \
    --arg incident_snapshot_refresh_status "$incident_snapshot_refresh_status" \
    --arg incident_snapshot_refresh_log "$incident_snapshot_refresh_log" \
    --argjson incident_snapshot_requested_attachment_inputs "$incident_snapshot_requested_attachment_inputs_json" \
    --arg manual_validation_report_status "$manual_validation_report_status" \
    --arg manual_validation_report_summary_json "$manual_validation_report_summary_json" \
    --arg manual_validation_report_md "$manual_validation_report_md" \
    --arg manual_validation_report_readiness_status "$manual_validation_report_readiness_status" \
    --arg manual_validation_report_next_action_check_id "$manual_validation_report_next_action_check_id" \
    --arg manual_validation_report_log "$manual_validation_report_log" \
    --arg summary_log "$summary_log" \
    --arg summary_json "$summary_json" \
    --argjson keep_up "$keep_up" \
    --arg defer_no_root "$defer_no_root" \
    --arg smoke_deferred_no_root "$smoke_deferred_no_root" \
    --argjson pre_real_host_readiness_enabled "$pre_real_host_readiness_enabled" \
    --argjson runtime_doctor_enabled "$runtime_doctor_enabled" \
    --argjson runtime_fix_on_non_ok "$runtime_fix_on_non_ok" \
    --argjson runtime_fix_attempted "$runtime_fix_attempted" \
    --argjson runtime_fix_prune_wg_only_dir "$runtime_fix_prune_wg_only_dir" \
    --argjson trust_reset_on_key_mismatch "$trust_reset_on_key_mismatch" \
    --argjson trust_reset_attempted "$trust_reset_attempted" \
    --argjson up_retry_attempted "$up_retry_attempted" \
    --argjson up_retry_succeeded "$up_retry_succeeded" \
    --argjson incident_snapshot_on_fail "$incident_snapshot_on_fail" \
    --argjson manual_validation_report_enabled "$manual_validation_report_enabled" \
    '{
      version: 1,
      generated_at_utc: $generated_at_utc,
      status: $status,
      stage: $stage,
      notes: $notes,
      keep_up: ($keep_up == "1"),
      defer_no_root: ($defer_no_root == "1"),
      deferred_no_root: ($smoke_deferred_no_root == "1"),
      pre_real_host_readiness: {
        enabled: ($pre_real_host_readiness_enabled == 1),
        status: $pre_real_host_readiness_status,
        summary_json: (if ($pre_real_host_readiness_summary_json | length) > 0 then $pre_real_host_readiness_summary_json else "" end),
        log: (if ($pre_real_host_readiness_log | length) > 0 then $pre_real_host_readiness_log else "" end),
        machine_c_smoke_ready: (if $pre_real_host_readiness_machine_c_ready == "true" then true else false end),
        blockers: $pre_real_host_readiness_blockers,
        next_command: $pre_real_host_readiness_next_command,
        readiness_status: $pre_real_host_readiness_readiness_status,
        readiness_report_summary_json: (if ($pre_real_host_readiness_report_summary_json | length) > 0 then $pre_real_host_readiness_report_summary_json else "" end),
        readiness_report_md: (if ($pre_real_host_readiness_report_md | length) > 0 then $pre_real_host_readiness_report_md else "" end)
      },
      runtime_gate: {
        enabled: ($runtime_doctor_enabled == 1),
        auto_fix: ($runtime_fix_on_non_ok == 1),
        fix_attempted: ($runtime_fix_attempted == 1),
        fix_prune_wg_only_dir: ($runtime_fix_prune_wg_only_dir == 1),
        doctor_status_before: $runtime_doctor_status_before,
        doctor_findings_before: ($runtime_doctor_findings_before | tonumber),
        doctor_status_after: $runtime_doctor_status_after,
        doctor_findings_after: ($runtime_doctor_findings_after | tonumber),
        fix_after_status: $runtime_fix_after_status,
        fix_actions_taken: ($runtime_fix_actions_taken | tonumber),
        fix_actions_failed: ($runtime_fix_actions_failed | tonumber),
        artifacts: {
          doctor_before_log: (if ($runtime_doctor_before_log | length) > 0 then $runtime_doctor_before_log else "" end),
          doctor_before_json: (if ($runtime_doctor_before_json | length) > 0 then $runtime_doctor_before_json else "" end),
          fix_log: (if ($runtime_fix_log | length) > 0 then $runtime_fix_log else "" end),
          fix_json: (if ($runtime_fix_json | length) > 0 then $runtime_fix_json else "" end),
          doctor_after_log: (if ($runtime_doctor_after_log | length) > 0 then $runtime_doctor_after_log else "" end),
          doctor_after_json: (if ($runtime_doctor_after_json | length) > 0 then $runtime_doctor_after_json else "" end)
        }
      },
      trust_reset: {
        enabled_on_key_mismatch: ($trust_reset_on_key_mismatch == 1),
        scope: (if ($trust_reset_scope | length) > 0 then $trust_reset_scope else "" end),
        attempted: ($trust_reset_attempted == 1),
        status: $trust_reset_status,
        reason: $trust_reset_reason,
        retry_attempted: ($up_retry_attempted == 1),
        retry_succeeded: ($up_retry_succeeded == 1),
        artifacts: {
          trust_reset_log: (if ($trust_reset_log | length) > 0 then $trust_reset_log else "" end),
          up_retry_log: (if ($up_retry_log | length) > 0 then $up_retry_log else "" end)
        }
      },
      outputs: {
        status_output: $status_output,
        public_ip_result: $public_ip_result,
        country_result: $country_result
      },
      incident_snapshot: {
        enabled_on_fail: ($incident_snapshot_on_fail == 1),
        status: $incident_snapshot_status,
        bundle_dir: $incident_snapshot_bundle_dir,
        bundle_tar: $incident_snapshot_bundle_tar,
        summary_json: $incident_snapshot_summary_json,
        report_md: $incident_snapshot_report_md,
        attachment_manifest: $incident_snapshot_attachment_manifest,
        attachment_skipped: $incident_snapshot_attachment_skipped,
        attachment_count: ($incident_snapshot_attachment_count | tonumber),
        refresh_status: $incident_snapshot_refresh_status,
        refresh_log: (if ($incident_snapshot_refresh_log | length) > 0 then $incident_snapshot_refresh_log else "" end),
        requested_attachment_inputs: $incident_snapshot_requested_attachment_inputs,
        log: (if ($incident_snapshot_log | length) > 0 then $incident_snapshot_log else "" end)
      },
      manual_validation_report: {
        enabled: ($manual_validation_report_enabled == 1),
        status: $manual_validation_report_status,
        summary_json: (if ($manual_validation_report_summary_json | length) > 0 then $manual_validation_report_summary_json else "" end),
        report_md: (if ($manual_validation_report_md | length) > 0 then $manual_validation_report_md else "" end),
        readiness_status: $manual_validation_report_readiness_status,
        next_action_check_id: $manual_validation_report_next_action_check_id,
        log: (if ($manual_validation_report_log | length) > 0 then $manual_validation_report_log else "" end)
      },
      artifacts: {
        summary_log: $summary_log,
        summary_json: $summary_json
      }
    }' >"$summary_json"
}

finish_and_record() {
  local final_status="$1"
  local final_notes="$2"
  smoke_status="$final_status"
  notes="$final_notes"
  if [[ -z "$result_stage" ]]; then
    result_stage="$stage"
  fi
  run_incident_snapshot_on_fail "$smoke_status"
  write_summary_json
  refresh_manual_validation_report
  write_summary_json
  refresh_failed_incident_snapshot_attachments
  write_summary_json
  local -a record_cmd
  if [[ "$record_result" == "1" ]]; then
    record_cmd=(
      "$easy_node_script" manual-validation-record
      --check-id machine_c_vpn_smoke
      --status "$smoke_status"
      --notes "$notes"
      --artifact "$summary_log"
      --artifact "$summary_json"
      --command "$(print_cmd "$0" "${original_args[@]}")"
      --show-json 0
    )
    local runtime_artifact=""
    local -a record_cmd_artifacts=()
    for runtime_artifact in \
      "$pre_real_host_readiness_log" \
      "$pre_real_host_readiness_summary_json" \
      "$pre_real_host_readiness_report_summary_json" \
      "$pre_real_host_readiness_report_md" \
      "$runtime_doctor_before_log" \
      "$runtime_doctor_before_json" \
      "$runtime_fix_log" \
      "$runtime_fix_json" \
      "$runtime_doctor_after_log" \
      "$runtime_doctor_after_json" \
      "$trust_reset_log" \
      "$up_retry_log" \
      "$incident_snapshot_log" \
      "$incident_snapshot_bundle_dir" \
      "$incident_snapshot_bundle_tar" \
      "$incident_snapshot_summary_json" \
      "$incident_snapshot_report_md" \
      "$incident_snapshot_attachment_manifest" \
      "$incident_snapshot_attachment_skipped" \
      "$incident_snapshot_refresh_log" \
      "$manual_validation_report_log" \
      "$manual_validation_report_summary_json" \
      "$manual_validation_report_md"; do
      append_existing_artifact record_cmd_artifacts "$runtime_artifact"
    done
    for runtime_artifact in "${record_cmd_artifacts[@]}"; do
      record_cmd+=(--artifact "$runtime_artifact")
    done
    "${record_cmd[@]}" >>"$summary_log" 2>&1 || true
  fi
  echo "client-vpn-smoke: status=$smoke_status stage=$result_stage"
  echo "summary_log: $summary_log"
  echo "summary_json: $summary_json"
  if [[ "$print_summary_json" == "1" ]]; then
    cat "$summary_json"
  fi
}

if ! run_pre_real_host_readiness_gate; then
  result_stage="$stage"
  finish_and_record "fail" "$runtime_gate_failure_note"
  exit 1
fi

if ! run_runtime_gate; then
  result_stage="$stage"
  finish_and_record "fail" "$runtime_gate_failure_note"
  exit 1
fi

if [[ "$run_preflight" == "1" ]]; then
  stage="preflight"
  preflight_output=""
  if ! run_and_capture preflight_output "${preflight_cmd[@]}"; then
    if defer_no_root_on_failure "$preflight_output" "client-vpn smoke deferred: preflight requires root privileges"; then
      exit 0
    fi
    result_stage="$stage"
    finish_and_record "fail" "client-vpn preflight failed"
    exit 1
  fi
fi

stage="up"
up_output=""
if ! run_and_capture up_output "${up_cmd[@]}"; then
  if defer_no_root_on_failure "$up_output" "client-vpn smoke deferred: client-vpn up requires root privileges"; then
    exit 0
  fi
  if ! attempt_up_retry_with_trust_reset "$up_output"; then
    result_stage="$stage"
    finish_and_record "fail" "${trust_reset_failure_note:-client-vpn up failed}"
    exit 1
  fi
fi
up_succeeded="1"

if [[ "$status_check" == "1" ]]; then
  stage="status"
  if ! run_and_capture status_output "${status_cmd[@]}"; then
    result_stage="$stage"
    cleanup_down
    finish_and_record "fail" "client-vpn status check failed"
    exit 1
  fi
fi

if [[ -n "$public_ip_url" ]]; then
  stage="public-ip"
  if ! run_and_capture public_ip_result "$curl_bin" --silent --show-error --max-time "$curl_timeout_sec" "$public_ip_url"; then
    result_stage="$stage"
    cleanup_down
    finish_and_record "fail" "public IP check failed"
    exit 1
  fi
fi

if [[ -n "$country_url" ]]; then
  stage="country"
  if ! run_and_capture country_result "$curl_bin" --silent --show-error --max-time "$curl_timeout_sec" "$country_url"; then
    result_stage="$stage"
    cleanup_down
    finish_and_record "fail" "country check failed"
    exit 1
  fi
fi

cleanup_down
result_stage="complete"
finish_and_record "pass" "client-vpn smoke completed successfully"
exit 0
