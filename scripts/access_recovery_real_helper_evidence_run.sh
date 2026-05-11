#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_id="$(date -u +%Y%m%d_%H%M%S)"
reports_dir="${ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_REPORTS_DIR:-.easy-node-logs/access-recovery-pilot}"

base_url=""
path_id="helper-web"
code=""
code_file=""
cacert=""
client_cert=""
client_key=""
require_mtls="${ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_REQUIRE_MTLS:-0}"
config_json=""
deploy_pack_dir=""
host_install_evidence_mode="deploy-pack"
install_dir=""
systemd_unit_file=""
proxy_kind=""
proxy_config_file=""
service_name="gpm-access-bridge"
expect_helper_id=""
expect_org_id=""
expect_registry_id=""
provenance_private_key_file=""
provenance_org_id=""
provenance_org_name=""
provenance_key_id=""
provenance_lifetime_hours=""
trust_store=""
bundle_summary_json=""
provenance_out=""
verification_summary_json=""
roadmap_refresh="${ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_ROADMAP_REFRESH:-1}"
plan_only="${ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_PLAN_ONLY:-0}"
roadmap_summary_json=""
roadmap_report_md=""
summary_json=""
report_md=""
print_summary_json="${ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_PRINT_SUMMARY_JSON:-1}"
print_child_json="0"
allow_child_script_overrides="${ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_ALLOW_SCRIPT_OVERRIDES:-0}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/access_recovery_real_helper_evidence_run.sh \
    --base-url https://HELPER_PUBLIC_DNS \
    --config-json FILE \
    --deploy-pack-dir DIR \
    (--code CODE | --code-file FILE) \
    [--host-install-evidence-mode deploy-pack|installed-host] \
    [--install-dir DIR] \
    [--systemd-unit-file FILE] \
    [--proxy-kind caddy|nginx] \
    [--proxy-config-file FILE] \
    --provenance-private-key-file FILE \
    --provenance-org-id ORG_ID \
    --provenance-org-name ORG_NAME \
    --trust-store FILE \
    [--path-id helper-web] \
    [--cacert FILE] \
    [--client-cert FILE --client-key FILE] \
    [--require-mtls 0|1] \
    [--expect-helper-id ID] \
    [--expect-org-id ID] \
    [--expect-registry-id ID] \
    [--reports-dir DIR] \
    [--bundle-summary-json FILE] \
    [--provenance-out FILE] \
    [--verification-summary-json FILE] \
    [--roadmap-refresh 0|1] \
    [--plan-only 0|1] \
    [--roadmap-summary-json FILE] \
    [--roadmap-report-md FILE] \
    [--allow-child-script-overrides 0|1] \
    [--summary-json FILE] \
    [--report-md FILE] \
    [--print-summary-json 0|1] \
    [--print-child-json 0|1]

Purpose:
  Run the real public Access Recovery helper evidence flow as one operator-safe
  command:
  1. capture the HTTPS pilot evidence bundle with signed provenance
  2. verify it with trusted provenance and write the verifier receipt
  3. refresh roadmap readiness against that verifier receipt

Use --plan-only 1 to run the same strict preflight validation and emit the
planned child commands/artifacts without invoking host-install, bundle,
verifier, or roadmap child scripts.

This wrapper is intentionally stricter than local rehearsal helpers. It refuses
placeholder values, loopback/private-looking helper URLs, missing trust stores,
and unsigned provenance inputs before running the evidence tools.

Child script path overrides are disabled by default. Use
--allow-child-script-overrides 1 only for integration tests or diagnostics.
USAGE
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" =~ ^[A-Za-z]:[\\/] ]]; then
    if command -v wslpath >/dev/null 2>&1; then
      wslpath -u "$path"
    elif command -v cygpath >/dev/null 2>&1; then
      cygpath -u "$path"
    else
      printf '%s' "$path"
    fi
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1" >&2
    exit 2
  fi
}

require_value_or_die() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
    echo "$flag requires a value" >&2
    exit 2
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access recovery real helper evidence run failed: missing required command: $cmd" >&2
    exit 2
  fi
}

sha256_value() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return 1
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    return 1
  fi
}

value_looks_placeholder() {
  local value
  value="$(trim "${1:-}")"
  [[ -z "$value" ]] && return 0
  case "$value" in
    PATH|FILE|DIR|URL|HELPER_PUBLIC_DNS|PRIVATE_CODE_FILE|BRIDGE_SERVICE_CONFIG|BRIDGE_DEPLOY_PACK|INSTALL_DIR|SYSTEMD_UNIT_FILE|PROXY_KIND|PROXY_CONFIG_FILE|TRUST_STORE|ACCESS_RECOVERY_TRUST_STORE|PROVENANCE_PRIVATE_KEY_FILE|ORG_ID|ORG_NAME|REPLACE_WITH_*|"<"*">")
      return 0
      ;;
  esac
  if [[ "$value" == *HELPER_PUBLIC_DNS* || "$value" == *PRIVATE_CODE_FILE* || "$value" == *BRIDGE_SERVICE_CONFIG* || "$value" == *BRIDGE_DEPLOY_PACK* || "$value" == *INSTALL_DIR* || "$value" == *SYSTEMD_UNIT_FILE* || "$value" == *PROXY_CONFIG_FILE* || "$value" == *REPLACE_WITH_* || "$value" == *PROVENANCE_PRIVATE_KEY_FILE* || "$value" == *TRUST_STORE* ]]; then
    return 0
  fi
  return 1
}

url_authority() {
  local rest="${1:-}"
  rest="${rest#*://}"
  rest="${rest%%/*}"
  rest="${rest%%\?*}"
  rest="${rest%%#*}"
  printf '%s' "$rest"
}

normalize_host() {
  local host="${1:-}"
  host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
  while [[ "$host" == *. ]]; do
    host="${host%.}"
  done
  printf '%s' "$host"
}

url_host() {
  local rest
  rest="$(url_authority "$1")"
  rest="${rest##*@}"
  if [[ "$rest" == \[*\]* ]]; then
    rest="${rest#\[}"
    normalize_host "${rest%%\]*}"
  else
    rest="${rest%%:*}"
    normalize_host "$rest"
  fi
}

url_authority_has_userinfo() {
  local rest
  rest="$(url_authority "$1")"
  [[ "$rest" == *@* ]]
}

ipv4_mapped_host_to_ipv4() {
  local host="${1:-}" mapped="" high="" low=""
  if [[ "$host" == ::ffff:* ]]; then
    mapped="${host#::ffff:}"
  elif [[ "$host" == 0:0:0:0:0:ffff:* ]]; then
    mapped="${host#0:0:0:0:0:ffff:}"
  else
    return 1
  fi
  if [[ "$mapped" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    printf '%s' "$mapped"
    return 0
  fi
  if [[ "$mapped" =~ ^([0-9a-f]{1,4}):([0-9a-f]{1,4})$ ]]; then
    high=$((16#${BASH_REMATCH[1]}))
    low=$((16#${BASH_REMATCH[2]}))
    if ((high >= 0 && high <= 65535 && low >= 0 && low <= 65535)); then
      printf '%d.%d.%d.%d' "$(((high >> 8) & 255))" "$((high & 255))" "$(((low >> 8) & 255))" "$((low & 255))"
      return 0
    fi
  fi
  return 1
}

ipv6_host_is_private_or_reserved() {
  local host="${1:-}"
  [[ "$host" =~ ^(::|::1|0:0:0:0:0:0:0:1|fc[0-9a-f]|fd[0-9a-f]) ]] && return 0
  [[ "$host" =~ ^fe(8[0-9a-f]|9[0-9a-f]|a[0-9a-f]|b[0-9a-f])(:|$) ]] && return 0
  [[ "$host" =~ ^2001:0?db8(:|$) ]] && return 0
  return 1
}

host_looks_non_public_for_real_helper() {
  local host="$1" mapped_ipv4=""
  [[ -z "$host" ]] && return 0
  mapped_ipv4="$(ipv4_mapped_host_to_ipv4 "$host" 2>/dev/null || true)"
  if [[ -n "$mapped_ipv4" ]]; then
    host="$mapped_ipv4"
  fi
  case "$host" in
    localhost|*.localhost|*.local|*.lan|*.internal|*.test|*.invalid|*.example|*.example.com|*.example.net|*.example.org|home.arpa|*.home.arpa|*.ts.net|*.tailscale.net|ts.net|tailscale.net)
      return 0
      ;;
  esac
  if [[ "$host" == *:* ]]; then
    ipv6_host_is_private_or_reserved "$host"
    return $?
  fi
  case "$host" in
    127.*|10.*|192.168.*|169.254.*|0.*)
      return 0
      ;;
    100.*)
      local second="${host#100.}"
      second="${second%%.*}"
      if [[ "$second" =~ ^[0-9]+$ && "$second" -ge 64 && "$second" -le 127 ]]; then
        return 0
      fi
      ;;
    172.*)
      local second="${host#172.}"
      second="${second%%.*}"
      if [[ "$second" =~ ^[0-9]+$ && "$second" -ge 16 && "$second" -le 31 ]]; then
        return 0
      fi
      ;;
    ::1|0:0:0:0:0:0:0:1)
      return 0
      ;;
  esac
  if [[ "$host" =~ ^192\.0\.(0|2)\. || "$host" =~ ^192\.88\.99\. ]]; then
    return 0
  fi
  if [[ "$host" =~ ^198\.(1[89]|51\.100)\. || "$host" =~ ^203\.0\.113\. ]]; then
    return 0
  fi
  if [[ "$host" =~ ^(22[4-9]|23[0-9]|24[0-9]|25[0-5])\. ]]; then
    return 0
  fi
  [[ "$host" != *.* ]] && return 0
  return 1
}

json_file_or_null() {
  local file
  file="$(trim "${1:-}")"
  if [[ -n "$file" && -f "$file" ]]; then
    jq -c '.' "$file" 2>/dev/null || printf '%s' "null"
  else
    printf '%s' "null"
  fi
}

json_array_from_args() {
  if [[ $# -eq 0 ]]; then
    printf '%s' "[]"
  else
    printf '%s\n' "$@" | jq -R . | jq -s -c .
  fi
}

redacted_args_json() {
  local arg redact_next="0"
  local redacted=()
  for arg in "$@"; do
    if [[ "$redact_next" == "1" ]]; then
      redacted+=("<redacted>")
      redact_next="0"
    elif [[ "$arg" == "--code" ]]; then
      redacted+=("$arg")
      redact_next="1"
    else
      redacted+=("$arg")
    fi
  done
  json_array_from_args "${redacted[@]}"
}

planned_command_json() {
  local enabled="$1"
  local script="$2"
  local reason="$3"
  shift 3
  local args_json
  args_json="$(redacted_args_json "$@")"
  jq -c -n \
    --argjson enabled "$enabled" \
    --arg script "$script" \
    --arg reason "$reason" \
    --argjson args "$args_json" \
    '{
      enabled: $enabled,
      script: $script,
      args: $args,
      argv: ([$script] + $args)
    } + (if $reason == "" then {} else {reason: $reason} end)'
}

first_nonempty() {
  local value
  for value in "$@"; do
    if [[ -n "$(trim "${value:-}")" ]]; then
      printf '%s' "$value"
      return 0
    fi
  done
  printf '%s' ""
}

print_failure_log_tail() {
  local label="$1"
  local file="$2"
  if [[ -f "$file" ]]; then
    echo "$label failed; last log lines:" >&2
    tail -n 80 "$file" >&2 || true
  fi
}

validate_trusted_verifier_receipt() {
  local smoke_sha deployment_sha host_sha receipt_errors
  if [[ ! -f "$verification_summary_json" ]]; then
    echo "Trusted verifier receipt was not written: $verification_summary_json"
    return 1
  fi
  if ! jq -e 'type == "object"' "$verification_summary_json" >/dev/null 2>&1; then
    echo "Trusted verifier receipt is not valid JSON: $verification_summary_json"
    return 1
  fi
  smoke_sha="$(sha256_value "$bundle_service_smoke_summary_json" 2>/dev/null || true)"
  deployment_sha="$(sha256_value "$bundle_deployment_evidence_summary_json" 2>/dev/null || true)"
  host_sha="$(sha256_value "$bundle_host_install_check_summary_json" 2>/dev/null || true)"
  if [[ -z "$smoke_sha" || -z "$deployment_sha" || -z "$host_sha" ]]; then
    echo "Trusted verifier receipt cannot be bound because a child evidence summary hash is missing"
    return 1
  fi
  receipt_errors="$(jq -r \
    --arg verification_summary_json "$verification_summary_json" \
    --arg bundle_summary_json "$bundle_summary_json" \
    --arg provenance_out "$provenance_out" \
    --arg trust_store "$trust_store" \
    --arg base_url "$base_url" \
    --arg smoke_sha "$smoke_sha" \
    --arg deployment_sha "$deployment_sha" \
    --arg host_sha "$host_sha" \
    '
      [
        if (.schema.id // "") != "access_bridge_pilot_evidence_bundle_verify_summary" then "schema id is not access_bridge_pilot_evidence_bundle_verify_summary" else empty end,
        if (.schema.major // 0) != 1 then "schema major is not 1" else empty end,
        if (.schema.minor // -1) < 2 then "schema minor is too old for trusted handoff child-evidence semantics" else empty end,
        if (.status // "") != "pass" then "receipt status is not pass" else empty end,
        if (.rc // -1) != 0 then "receipt rc is not 0" else empty end,
        if (.pilot_handoff_ready // false) != true then "pilot_handoff_ready is not true" else empty end,
        if (.trusted_pilot_receipt_ready // false) != true then "trusted_pilot_receipt_ready is not true" else empty end,
        if (.pilot_handoff_criteria.ready // false) != true then "pilot_handoff_criteria.ready is not true" else empty end,
        if (.pilot_handoff_criteria.trusted_pilot_receipt_ready // false) != true then "pilot_handoff_criteria.trusted_pilot_receipt_ready is not true" else empty end,
        if (.pilot_handoff_criteria.require_trusted_provenance // false) != true then "trusted provenance was not required" else empty end,
        if (.pilot_handoff_criteria.provenance_checked // false) != true then "provenance was not checked" else empty end,
        if (.pilot_handoff_criteria.provenance_trusted // false) != true then "provenance was not trusted" else empty end,
        if (.pilot_handoff_criteria.provenance_status // "") != "pass" then "provenance status is not pass" else empty end,
        if (.pilot_handoff_criteria.provenance_source // "") != "trust_store" then "provenance source is not trust_store" else empty end,
        if (.pilot_handoff_criteria.provenance_evidence_scope // "") != "real_helper_https" then "provenance evidence_scope is not real_helper_https" else empty end,
        if (.pilot_handoff_criteria.summary_evidence_scope // "") != "real_helper_https" then "summary evidence_scope is not real_helper_https" else empty end,
        if (.pilot_handoff_criteria.bundled_child_evidence_semantic_ok // false) != true then "bundled child evidence semantic validation did not pass" else empty end,
        if (.pilot_handoff_criteria.source_helper_id_present // false) != true then "source helper id was not proven present" else empty end,
        if (.pilot_handoff_criteria.source_organization_id_present // false) != true then "source organization id was not proven present" else empty end,
        if (.pilot_handoff_criteria.source_registry_id_present // false) != true then "source registry id was not proven present" else empty end,
        if (.pilot_handoff_criteria.provenance_organization_matches_evidence // false) != true then "provenance organization did not match evidence organization" else empty end,
        if (.pilot_handoff_criteria.trusted_organization_matches_evidence // false) != true then "trusted organization did not match evidence organization" else empty end,
        if (.pilot_handoff_criteria.trust_store_sha256_present // false) != true then "trust store sha256 is missing" else empty end,
        if (.pilot_handoff_criteria.public_key_file_absent // false) != true then "public key file was accepted for trusted handoff" else empty end,
        if (.pilot_handoff_criteria.dev_trust_store_allowed // false) == true then "diagnostic dev trust-store override was used" else empty end,
        if (.inputs.summary_json // "") != $bundle_summary_json then "receipt summary_json does not match current bundle summary" else empty end,
        if (.inputs.provenance_json // "") != $provenance_out then "receipt provenance_json does not match current provenance sidecar" else empty end,
        if (.inputs.trust_store // "") != $trust_store then "receipt trust_store does not match requested trust store" else empty end,
        if ((.inputs.trust_store_sha256 // "") | test("^[A-Fa-f0-9]{64}$") | not) then "receipt trust_store_sha256 is missing or malformed" else empty end,
        if (.inputs.public_key_file // null) != null then "receipt includes a public_key_file" else empty end,
        if (.inputs.allow_dev_trust_store // false) == true then "receipt used allow_dev_trust_store" else empty end,
        if (.checks.summary_contract.enabled // false) != true then "summary contract check was not enabled" else empty end,
        if (.checks.summary_contract.status // "") != "pass" then "summary contract check did not pass" else empty end,
        if (.checks.tar_sha256.enabled // false) != true then "tar sha256 check was not enabled" else empty end,
        if (.checks.tar_sha256.checked // false) != true then "tar sha256 was not checked" else empty end,
        if (.checks.tar_sha256.status // "") != "pass" then "tar sha256 check did not pass" else empty end,
        if (.checks.manifest.enabled // false) != true then "manifest check was not enabled" else empty end,
        if (.checks.manifest.status // "") != "pass" then "manifest check did not pass" else empty end,
        if (.checks.provenance.enabled // false) != true then "provenance check was not enabled" else empty end,
        if (.checks.provenance.required_trusted // false) != true then "trusted provenance check was not required" else empty end,
        if (.checks.provenance.status // "") != "pass" then "provenance check did not pass" else empty end,
        if (.trusted_provenance.required // false) != true then "trusted_provenance.required is not true" else empty end,
        if (.trusted_provenance.checked // false) != true then "trusted_provenance.checked is not true" else empty end,
        if (.trusted_provenance.source // "") != "trust_store" then "trusted_provenance.source is not trust_store" else empty end,
        if (.trusted_provenance.trusted // false) != true then "trusted_provenance.trusted is not true" else empty end,
        if (.trusted_provenance.status // "") != "pass" then "trusted_provenance.status is not pass" else empty end,
        if (.trusted_provenance.evidence_scope // "") != "real_helper_https" then "trusted_provenance.evidence_scope is not real_helper_https" else empty end,
        if (.trusted_provenance.summary_evidence_scope // "") != "real_helper_https" then "trusted_provenance.summary_evidence_scope is not real_helper_https" else empty end,
        if (.evidence_binding.helper_id // "") == "" then "evidence binding helper_id is missing" else empty end,
        if (.evidence_binding.organization_id // "") == "" then "evidence binding organization_id is missing" else empty end,
        if (.evidence_binding.registry_id // "") == "" then "evidence binding registry_id is missing" else empty end,
        if (.trusted_provenance.organization_id // "") != (.evidence_binding.organization_id // "") then "trusted provenance organization_id does not match evidence binding organization_id" else empty end,
        if (.trusted_provenance.trusted_org_id // "") != (.evidence_binding.organization_id // "") then "trusted provenance trusted_org_id does not match evidence binding organization_id" else empty end,
        if (.evidence_binding.base_url // "") != $base_url then "evidence binding base_url does not match current run" else empty end,
        if (.evidence_binding.smoke_summary_sha256 // "") != $smoke_sha then "evidence binding smoke summary hash does not match current bundle output" else empty end,
        if (.evidence_binding.deployment_evidence_summary_sha256 // "") != $deployment_sha then "evidence binding deployment summary hash does not match current bundle output" else empty end,
        if (.evidence_binding.host_install_check_summary_sha256 // "") != $host_sha then "evidence binding host-install summary hash does not match current bundle output" else empty end,
        if (.artifacts.verification_summary_json // "") != $verification_summary_json then "receipt artifact path does not match requested verifier receipt" else empty end,
        if (.artifacts.source_summary_json // "") != $bundle_summary_json then "receipt source summary artifact does not match current bundle summary" else empty end,
        if (.artifacts.provenance_json // "") != $provenance_out then "receipt provenance artifact does not match current provenance sidecar" else empty end
      ] | .[]
    ' "$verification_summary_json")"
  if [[ -n "$receipt_errors" ]]; then
    printf '%s\n' "$receipt_errors"
    return 1
  fi
  return 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --base-url)
      require_value_or_die "$1" "${2:-}"
      base_url="$2"
      shift 2
      ;;
    --path-id)
      require_value_or_die "$1" "${2:-}"
      path_id="$2"
      shift 2
      ;;
    --code)
      require_value_or_die "$1" "${2:-}"
      code="$2"
      shift 2
      ;;
    --code-file)
      require_value_or_die "$1" "${2:-}"
      code_file="$2"
      shift 2
      ;;
    --cacert)
      require_value_or_die "$1" "${2:-}"
      cacert="$2"
      shift 2
      ;;
    --client-cert)
      require_value_or_die "$1" "${2:-}"
      client_cert="$2"
      shift 2
      ;;
    --client-key)
      require_value_or_die "$1" "${2:-}"
      client_key="$2"
      shift 2
      ;;
    --require-mtls)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_mtls="${2:-}"
        shift 2
      else
        require_mtls="1"
        shift
      fi
      ;;
    --config-json)
      require_value_or_die "$1" "${2:-}"
      config_json="$2"
      shift 2
      ;;
    --deploy-pack-dir)
      require_value_or_die "$1" "${2:-}"
      deploy_pack_dir="$2"
      shift 2
      ;;
    --host-install-evidence-mode|--evidence-mode)
      require_value_or_die "$1" "${2:-}"
      host_install_evidence_mode="$2"
      shift 2
      ;;
    --install-dir)
      require_value_or_die "$1" "${2:-}"
      install_dir="$2"
      shift 2
      ;;
    --systemd-unit-file)
      require_value_or_die "$1" "${2:-}"
      systemd_unit_file="$2"
      shift 2
      ;;
    --proxy-kind)
      require_value_or_die "$1" "${2:-}"
      proxy_kind="$2"
      shift 2
      ;;
    --proxy-config-file)
      require_value_or_die "$1" "${2:-}"
      proxy_config_file="$2"
      shift 2
      ;;
    --service-name)
      require_value_or_die "$1" "${2:-}"
      service_name="$2"
      shift 2
      ;;
    --expect-helper-id)
      require_value_or_die "$1" "${2:-}"
      expect_helper_id="$2"
      shift 2
      ;;
    --expect-org-id)
      require_value_or_die "$1" "${2:-}"
      expect_org_id="$2"
      shift 2
      ;;
    --expect-registry-id)
      require_value_or_die "$1" "${2:-}"
      expect_registry_id="$2"
      shift 2
      ;;
    --provenance-private-key-file)
      require_value_or_die "$1" "${2:-}"
      provenance_private_key_file="$2"
      shift 2
      ;;
    --provenance-org-id)
      require_value_or_die "$1" "${2:-}"
      provenance_org_id="$2"
      shift 2
      ;;
    --provenance-org-name)
      require_value_or_die "$1" "${2:-}"
      provenance_org_name="$2"
      shift 2
      ;;
    --provenance-key-id)
      require_value_or_die "$1" "${2:-}"
      provenance_key_id="$2"
      shift 2
      ;;
    --provenance-lifetime-hours)
      require_value_or_die "$1" "${2:-}"
      provenance_lifetime_hours="$2"
      shift 2
      ;;
    --trust-store)
      require_value_or_die "$1" "${2:-}"
      trust_store="$2"
      shift 2
      ;;
    --reports-dir)
      require_value_or_die "$1" "${2:-}"
      reports_dir="$2"
      shift 2
      ;;
    --bundle-summary-json)
      require_value_or_die "$1" "${2:-}"
      bundle_summary_json="$2"
      shift 2
      ;;
    --provenance-out)
      require_value_or_die "$1" "${2:-}"
      provenance_out="$2"
      shift 2
      ;;
    --verification-summary-json)
      require_value_or_die "$1" "${2:-}"
      verification_summary_json="$2"
      shift 2
      ;;
    --roadmap-refresh)
      require_value_or_die "$1" "${2:-}"
      roadmap_refresh="$2"
      shift 2
      ;;
    --plan-only|--preflight-only)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        plan_only="${2:-}"
        shift 2
      else
        plan_only="1"
        shift
      fi
      ;;
    --roadmap-summary-json)
      require_value_or_die "$1" "${2:-}"
      roadmap_summary_json="$2"
      shift 2
      ;;
    --roadmap-report-md)
      require_value_or_die "$1" "${2:-}"
      roadmap_report_md="$2"
      shift 2
      ;;
    --summary-json)
      require_value_or_die "$1" "${2:-}"
      summary_json="$2"
      shift 2
      ;;
    --report-md)
      require_value_or_die "$1" "${2:-}"
      report_md="$2"
      shift 2
      ;;
    --print-summary-json)
      require_value_or_die "$1" "${2:-}"
      print_summary_json="$2"
      shift 2
      ;;
    --print-child-json)
      require_value_or_die "$1" "${2:-}"
      print_child_json="$2"
      shift 2
      ;;
    --allow-child-script-overrides)
      require_value_or_die "$1" "${2:-}"
      bool_arg_or_die "$1" "$2"
      allow_child_script_overrides="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for cmd in awk date dirname jq mkdir tail; do
  need_cmd "$cmd"
done

bool_arg_or_die "--roadmap-refresh" "$roadmap_refresh"
bool_arg_or_die "--plan-only" "$plan_only"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--print-child-json" "$print_child_json"

reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

bundle_summary_json="$(abs_path "$(first_nonempty "$bundle_summary_json" "$reports_dir/access_bridge_pilot_evidence_${run_id}.json")")"
provenance_out="$(abs_path "$(first_nonempty "$provenance_out" "$reports_dir/access_bridge_pilot_evidence_${run_id}.provenance.json")")"
verification_summary_json="$(abs_path "$(first_nonempty "$verification_summary_json" "$reports_dir/access_bridge_pilot_evidence_verify_${run_id}.json")")"
roadmap_summary_json="$(abs_path "$(first_nonempty "$roadmap_summary_json" "$reports_dir/roadmap_progress_${run_id}.json")")"
roadmap_report_md="$(abs_path "$(first_nonempty "$roadmap_report_md" "$reports_dir/roadmap_progress_${run_id}.md")")"
summary_json="$(abs_path "$(first_nonempty "$summary_json" "$reports_dir/access_recovery_real_helper_evidence_run_${run_id}.json")")"
report_md="$(abs_path "$(first_nonempty "$report_md" "$reports_dir/access_recovery_real_helper_evidence_run_${run_id}.md")")"

bundle_log="$reports_dir/access_recovery_real_helper_evidence_run_${run_id}_bundle.log"
host_install_check_summary_json="$reports_dir/access_bridge_host_install_check_${run_id}.json"
host_install_check_log="$reports_dir/access_recovery_real_helper_evidence_run_${run_id}_host_install_check.log"
verify_log="$reports_dir/access_recovery_real_helper_evidence_run_${run_id}_verify.log"
roadmap_log="$reports_dir/access_recovery_real_helper_evidence_run_${run_id}_roadmap.log"
bundle_service_smoke_summary_json=""
bundle_deployment_evidence_summary_json=""
bundle_host_install_check_summary_json=""
planned_child_commands_json="{}"
planned_artifacts_json="{}"

config_json="$(abs_path "$config_json")"
deploy_pack_dir="$(abs_path "$deploy_pack_dir")"
if [[ -n "$install_dir" ]]; then
  install_dir="$(abs_path "$install_dir")"
fi
if [[ -n "$systemd_unit_file" ]]; then
  systemd_unit_file="$(abs_path "$systemd_unit_file")"
fi
if [[ -n "$proxy_config_file" ]]; then
  proxy_config_file="$(abs_path "$proxy_config_file")"
fi
code_file="$(abs_path "$code_file")"
cacert="$(abs_path "$cacert")"
client_cert="$(abs_path "$client_cert")"
client_key="$(abs_path "$client_key")"
provenance_private_key_file="$(abs_path "$provenance_private_key_file")"
trust_store="$(abs_path "$trust_store")"

write_summary() {
  local status="$1"
  local rc="$2"
  local stage="$3"
  local notes="$4"
  local generated_at_utc
  local host_install_obj bundle_obj verify_obj roadmap_obj pilot_ready roadmap_ready evidence_scope verifier_scope
  local code_present_json code_file_present_json
  local roadmap_refresh_json
  local plan_only_json
  generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  host_install_obj="$(json_file_or_null "$host_install_check_summary_json")"
  bundle_obj="$(json_file_or_null "$bundle_summary_json")"
  verify_obj="$(json_file_or_null "$verification_summary_json")"
  if [[ "$roadmap_refresh" == "1" ]]; then
    roadmap_obj="$(json_file_or_null "$roadmap_summary_json")"
  else
    roadmap_obj="null"
  fi
  pilot_ready="$(printf '%s\n' "$verify_obj" | jq -r 'if type == "object" then (.pilot_handoff_ready // false | tostring) else "false" end')"
  roadmap_ready="$(printf '%s\n' "$roadmap_obj" | jq -r 'if type == "object" then (.access_recovery_pilot_handoff_ready // false | tostring) else "false" end')"
  evidence_scope="$(printf '%s\n' "$bundle_obj" | jq -r 'if type == "object" then (.evidence_scope // "") else "" end')"
  verifier_scope="$(printf '%s\n' "$verify_obj" | jq -r 'if type == "object" then ((.details.evidence_scope // .trusted_provenance.evidence_scope // .evidence_scope // "") | tostring) else "" end')"
  if [[ -n "$code" ]]; then
    code_present_json="true"
  else
    code_present_json="false"
  fi
  if [[ -n "$code_file" ]]; then
    code_file_present_json="true"
  else
    code_file_present_json="false"
  fi
  if [[ "$roadmap_refresh" == "1" ]]; then
    roadmap_refresh_json="true"
  else
    roadmap_refresh_json="false"
  fi
  if [[ "$plan_only" == "1" ]]; then
    plan_only_json="true"
  else
    plan_only_json="false"
  fi
  mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg stage "$stage" \
    --arg notes "$notes" \
    --arg base_url "$base_url" \
    --arg path_id "$path_id" \
    --arg host_install_evidence_mode "$host_install_evidence_mode" \
    --arg install_dir "$install_dir" \
    --arg systemd_unit_file "$systemd_unit_file" \
    --arg proxy_kind "$proxy_kind" \
    --arg proxy_config_file "$proxy_config_file" \
    --arg reports_dir "$reports_dir" \
    --arg host_install_check_summary_json "$host_install_check_summary_json" \
    --arg host_install_check_log "$host_install_check_log" \
    --arg bundle_summary_json "$bundle_summary_json" \
    --arg bundle_service_smoke_summary_json "$bundle_service_smoke_summary_json" \
    --arg bundle_deployment_evidence_summary_json "$bundle_deployment_evidence_summary_json" \
    --arg bundle_host_install_check_summary_json "$bundle_host_install_check_summary_json" \
    --arg bundle_log "$bundle_log" \
    --arg provenance_json "$provenance_out" \
    --arg verification_summary_json "$verification_summary_json" \
    --arg verify_log "$verify_log" \
    --arg roadmap_summary_json "$roadmap_summary_json" \
    --arg roadmap_report_md "$roadmap_report_md" \
    --arg roadmap_log "$roadmap_log" \
    --arg summary_json "$summary_json" \
    --arg report_md "$report_md" \
    --arg evidence_scope "$evidence_scope" \
    --arg verifier_scope "$verifier_scope" \
    --arg require_mtls "$require_mtls" \
    --argjson code_present "$code_present_json" \
    --argjson code_file_present "$code_file_present_json" \
    --argjson plan_only "$plan_only_json" \
    --argjson pilot_handoff_ready "$pilot_ready" \
    --argjson roadmap_ready "$roadmap_ready" \
    --argjson roadmap_refresh "$roadmap_refresh_json" \
    --argjson host_install_check "$host_install_obj" \
    --argjson bundle "$bundle_obj" \
    --argjson verifier "$verify_obj" \
    --argjson roadmap "$roadmap_obj" \
    --argjson planned_child_commands "$planned_child_commands_json" \
    --argjson planned_artifacts "$planned_artifacts_json" \
    '{
      version: 1,
      schema: {id: "access_recovery_real_helper_evidence_run_summary", major: 1, minor: 3},
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      stage: $stage,
      notes: $notes,
      mode: {
        plan_only: $plan_only,
        child_execution_skipped: ($plan_only and $status == "pass" and $stage == "plan")
      },
      inputs: {
        base_url: $base_url,
        path_id: $path_id,
        host_install_evidence_mode: $host_install_evidence_mode,
        install_dir: (if $install_dir == "" then null else $install_dir end),
        systemd_unit_file: (if $systemd_unit_file == "" then null else $systemd_unit_file end),
        proxy_kind: (if $proxy_kind == "" then null else $proxy_kind end),
        proxy_config_file: (if $proxy_config_file == "" then null else $proxy_config_file end),
        code_present: $code_present,
        code_file_present: $code_file_present,
        require_mtls: ($require_mtls == "1"),
        roadmap_refresh: $roadmap_refresh
      },
      readiness: {
        evidence_scope: (if $evidence_scope == "" then null else $evidence_scope end),
        verifier_evidence_scope: (if $verifier_scope == "" then null else $verifier_scope end),
        trusted_verifier_pilot_handoff_ready: $pilot_handoff_ready,
        roadmap_access_recovery_pilot_handoff_ready: $roadmap_ready
      },
      child_summaries: {
        host_install_check: $host_install_check,
        bundle: $bundle,
        verifier: $verifier,
        roadmap: $roadmap
      },
      planned_child_commands: $planned_child_commands,
      planned_artifacts: $planned_artifacts,
      artifacts: {
        reports_dir: $reports_dir,
        host_install_check_summary_json: $host_install_check_summary_json,
        host_install_check_log: $host_install_check_log,
        bundle_summary_json: $bundle_summary_json,
        bundle_service_smoke_summary_json: (if $bundle_service_smoke_summary_json == "" then null else $bundle_service_smoke_summary_json end),
        bundle_deployment_evidence_summary_json: (if $bundle_deployment_evidence_summary_json == "" then null else $bundle_deployment_evidence_summary_json end),
        bundle_host_install_check_summary_json: (if $bundle_host_install_check_summary_json == "" then null else $bundle_host_install_check_summary_json end),
        bundle_log: $bundle_log,
        provenance_json: $provenance_json,
        verification_summary_json: $verification_summary_json,
        verify_log: $verify_log,
        roadmap_summary_json: $roadmap_summary_json,
        roadmap_report_md: $roadmap_report_md,
        roadmap_log: $roadmap_log,
        summary_json: $summary_json,
        report_md: $report_md
      }
    }' >"$summary_json"

  cat >"$report_md" <<REPORT
# Access Recovery Real Helper Evidence Run

- Status: ${status}
- Stage: ${stage}
- Notes: ${notes}
- Plan only: ${plan_only}
- Base URL: ${base_url}
- Host install check: ${host_install_check_summary_json}
- Bundle summary: ${bundle_summary_json}
- Verifier receipt: ${verification_summary_json}
- Roadmap summary: ${roadmap_summary_json}
- Summary JSON: ${summary_json}
REPORT

  if printf '%s\n' "$planned_child_commands_json" | jq -e 'type == "object" and length > 0' >/dev/null 2>&1; then
    {
      echo
      echo "## Planned Child Commands"
      printf '%s\n' "$planned_child_commands_json" | jq -r '
        to_entries[]
        | "- " + .key
          + (if (.value.enabled // true) == false then " (disabled" + (if (.value.reason // "") == "" then "" else ": " + .value.reason end) + ")" else "" end)
          + ": " + ((.value.argv // []) | map(@sh) | join(" "))
      '
    } >>"$report_md"
  fi

  if printf '%s\n' "$planned_artifacts_json" | jq -e 'type == "object" and length > 0' >/dev/null 2>&1; then
    {
      echo
      echo "## Planned Artifacts"
      printf '%s\n' "$planned_artifacts_json" | jq -r '
        to_entries[]
        | select((.value // "") != "")
        | "- " + .key + ": " + (.value | tostring)
      '
    } >>"$report_md"
  fi
}

fail_preflight() {
  local message="$1"
  write_summary "fail" 2 "preflight" "$message"
  echo "access-recovery-real-helper-evidence-run: status=fail stage=preflight" >&2
  echo "$message" >&2
  echo "summary_json: $summary_json" >&2
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit 2
}

if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  fail_preflight "missing required command: sha256sum or shasum"
fi

if value_looks_placeholder "$base_url"; then
  fail_preflight "--base-url must be a real public HTTPS helper URL"
fi
if [[ "$(printf '%s' "$base_url" | tr '[:upper:]' '[:lower:]')" != https://* ]]; then
  fail_preflight "--base-url must use https:// for real helper evidence"
fi
if url_authority_has_userinfo "$base_url"; then
  fail_preflight "--base-url must not include userinfo"
fi
host="$(url_host "$base_url")"
if host_looks_non_public_for_real_helper "$host"; then
  fail_preflight "--base-url host must look public-routable for real helper evidence: ${host:-<missing>}"
fi
if [[ -n "$code" && -n "$code_file" ]]; then
  fail_preflight "use either --code or --code-file, not both"
fi
if [[ -z "$code" && -z "$code_file" ]]; then
  fail_preflight "one of --code or --code-file is required"
fi
if [[ -n "$code" ]] && value_looks_placeholder "$code"; then
  fail_preflight "--code must be a real private access code, not an unreplaced placeholder"
fi
if [[ -n "$code_file" ]] && value_looks_placeholder "$code_file"; then
  fail_preflight "--code-file must point to a real private access code file, not an unreplaced placeholder"
fi
if [[ -n "$code_file" && ! -f "$code_file" ]]; then
  fail_preflight "--code-file not found: $code_file"
fi
if value_looks_placeholder "$config_json"; then
  fail_preflight "--config-json must point to a real bridge service config, not an unreplaced placeholder"
fi
if [[ ! -f "$config_json" ]]; then
  fail_preflight "--config-json not found: $config_json"
fi
if value_looks_placeholder "$deploy_pack_dir"; then
  fail_preflight "--deploy-pack-dir must point to a real bridge deploy pack directory, not an unreplaced placeholder"
fi
if [[ ! -d "$deploy_pack_dir" ]]; then
  fail_preflight "--deploy-pack-dir not found: $deploy_pack_dir"
fi
host_install_evidence_mode="$(printf '%s' "$host_install_evidence_mode" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
if [[ "$host_install_evidence_mode" != "deploy-pack" && "$host_install_evidence_mode" != "installed-host" ]]; then
  fail_preflight "--host-install-evidence-mode must be deploy-pack or installed-host"
fi
if [[ "$host_install_evidence_mode" == "installed-host" ]]; then
  if value_looks_placeholder "$install_dir"; then
    fail_preflight "--install-dir must point to the active installed bridge directory, not an unreplaced placeholder"
  fi
  if [[ ! -d "$install_dir" ]]; then
    fail_preflight "--install-dir not found: $install_dir"
  fi
  if value_looks_placeholder "$systemd_unit_file"; then
    fail_preflight "--systemd-unit-file must point to the active systemd unit, not an unreplaced placeholder"
  fi
  if [[ ! -f "$systemd_unit_file" ]]; then
    fail_preflight "--systemd-unit-file not found: $systemd_unit_file"
  fi
  if [[ "$proxy_kind" != "caddy" && "$proxy_kind" != "nginx" ]]; then
    fail_preflight "--proxy-kind must be caddy or nginx when --host-install-evidence-mode installed-host"
  fi
  if value_looks_placeholder "$proxy_config_file"; then
    fail_preflight "--proxy-config-file must point to the active proxy config, not an unreplaced placeholder"
  fi
  if [[ ! -f "$proxy_config_file" ]]; then
    fail_preflight "--proxy-config-file not found: $proxy_config_file"
  fi
elif [[ -n "$proxy_kind" && "$proxy_kind" != "caddy" && "$proxy_kind" != "nginx" ]]; then
  fail_preflight "--proxy-kind must be caddy or nginx"
fi
if value_looks_placeholder "$provenance_private_key_file" || [[ ! -f "$provenance_private_key_file" ]]; then
  fail_preflight "--provenance-private-key-file must point to a real signing key"
fi
if value_looks_placeholder "$provenance_org_id"; then
  fail_preflight "--provenance-org-id must be a real organization id"
fi
if value_looks_placeholder "$provenance_org_name"; then
  fail_preflight "--provenance-org-name must be a real organization name"
fi
if value_looks_placeholder "$trust_store" || [[ ! -f "$trust_store" ]]; then
  fail_preflight "--trust-store must point to a real trusted verifier trust store"
fi
if [[ -n "$cacert" && ! -f "$cacert" ]]; then
  fail_preflight "--cacert not found: $cacert"
fi
if [[ -n "$client_cert" && ! -f "$client_cert" ]]; then
  fail_preflight "--client-cert not found: $client_cert"
fi
if [[ -n "$client_key" && ! -f "$client_key" ]]; then
  fail_preflight "--client-key not found: $client_key"
fi
if [[ -n "$client_cert" && -z "$client_key" || -z "$client_cert" && -n "$client_key" ]]; then
  fail_preflight "--client-cert and --client-key must be supplied together"
fi
if [[ "$require_mtls" != "0" && "$require_mtls" != "1" ]]; then
  fail_preflight "--require-mtls must be 0 or 1"
fi
if [[ "$require_mtls" == "1" && ( -z "$client_cert" || -z "$client_key" ) ]]; then
  fail_preflight "--require-mtls 1 requires --client-cert and --client-key"
fi

if [[ "$allow_child_script_overrides" != "0" && "$allow_child_script_overrides" != "1" ]]; then
  fail_preflight "--allow-child-script-overrides must be 0 or 1"
fi
if [[ "$allow_child_script_overrides" != "1" ]]; then
  for override_var in \
    ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT \
    ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT \
    ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT \
    ROADMAP_PROGRESS_REPORT_SCRIPT; do
    if [[ -n "${!override_var:-}" ]]; then
      fail_preflight "${override_var} override is disabled for real helper evidence; pass --allow-child-script-overrides 1 only for integration tests or diagnostics"
    fi
  done
fi

host_install_check_script="${ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT:-$ROOT_DIR/scripts/access_bridge_host_install_check.sh}"
bundle_script="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT:-$ROOT_DIR/scripts/access_bridge_pilot_evidence_bundle.sh}"
verify_script="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT:-$ROOT_DIR/scripts/access_bridge_pilot_evidence_bundle_verify.sh}"
roadmap_script="${ROADMAP_PROGRESS_REPORT_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"
[[ -x "$host_install_check_script" ]] || fail_preflight "missing executable host install check script: $host_install_check_script"
[[ -x "$bundle_script" ]] || fail_preflight "missing executable bundle script: $bundle_script"
[[ -x "$verify_script" ]] || fail_preflight "missing executable verifier script: $verify_script"
if [[ "$roadmap_refresh" == "1" && ! -x "$roadmap_script" ]]; then
  fail_preflight "missing executable roadmap script: $roadmap_script"
fi

planned_bundle_dir="$reports_dir/access_bridge_pilot_evidence_bundle_${run_id}"
planned_bundle_service_smoke_summary_json="$planned_bundle_dir/access_bridge_service_smoke_summary.json"
planned_bundle_deployment_evidence_summary_json="$planned_bundle_dir/access_bridge_deployment_evidence_summary.json"
planned_bundle_host_install_check_summary_json="$planned_bundle_dir/access_bridge_host_install_check_summary.json"

host_install_check_args=(
  --evidence-mode "$host_install_evidence_mode"
  --deploy-pack-dir "$deploy_pack_dir"
  --service-name "$service_name"
  --config-json "$config_json"
  --expected-base-url "$base_url"
  --summary-json "$host_install_check_summary_json"
  --print-summary-json "$print_child_json"
)
if [[ "$host_install_evidence_mode" == "installed-host" ]]; then
  host_install_check_args+=(
    --install-dir "$install_dir"
    --systemd-unit-file "$systemd_unit_file"
    --proxy-kind "$proxy_kind"
    --proxy-config-file "$proxy_config_file"
  )
fi

bundle_args=(
  --base-url "$base_url"
  --path-id "$path_id"
  --config-json "$config_json"
  --deploy-pack-dir "$deploy_pack_dir"
  --service-name "$service_name"
  --host-install-evidence-mode "$host_install_evidence_mode"
  --bundle-dir "$planned_bundle_dir"
  --summary-json "$bundle_summary_json"
  --provenance-sign 1
  --provenance-private-key-file "$provenance_private_key_file"
  --provenance-org-id "$provenance_org_id"
  --provenance-org-name "$provenance_org_name"
  --provenance-out "$provenance_out"
  --require-https 1
  --require-public-host 1
  --require-mtls "$require_mtls"
  --expected-public-host "$host"
  --print-summary-json "$print_child_json"
)
if [[ "$host_install_evidence_mode" == "installed-host" ]]; then
  bundle_args+=(
    --install-dir "$install_dir"
    --systemd-unit-file "$systemd_unit_file"
    --proxy-kind "$proxy_kind"
    --proxy-config-file "$proxy_config_file"
  )
fi
if [[ -n "$code_file" ]]; then
  bundle_args+=(--code-file "$code_file")
else
  bundle_args+=(--code "$code")
fi
[[ -z "$cacert" ]] || bundle_args+=(--cacert "$cacert")
[[ -z "$client_cert" ]] || bundle_args+=(--client-cert "$client_cert")
[[ -z "$client_key" ]] || bundle_args+=(--client-key "$client_key")
[[ -z "$expect_helper_id" ]] || bundle_args+=(--expect-helper-id "$expect_helper_id")
[[ -z "$expect_org_id" ]] || bundle_args+=(--expect-org-id "$expect_org_id")
[[ -z "$expect_registry_id" ]] || bundle_args+=(--expect-registry-id "$expect_registry_id")
[[ -z "$provenance_key_id" ]] || bundle_args+=(--provenance-key-id "$provenance_key_id")
[[ -z "$provenance_lifetime_hours" ]] || bundle_args+=(--provenance-lifetime-hours "$provenance_lifetime_hours")

verify_args=(
  --summary-json "$bundle_summary_json"
  --provenance-json "$provenance_out"
  --trust-store "$trust_store"
  --require-trusted-provenance 1
  --verification-summary-json "$verification_summary_json"
  --print-verification-summary-json "$print_child_json"
)

planned_roadmap_args=(
  --refresh-manual-validation 0
  --refresh-single-machine-readiness 0
  --access-bridge-service-smoke-summary-json "$planned_bundle_service_smoke_summary_json"
  --access-bridge-deployment-evidence-summary-json "$planned_bundle_deployment_evidence_summary_json"
  --access-bridge-host-install-summary-json "$planned_bundle_host_install_check_summary_json"
  --access-bridge-pilot-evidence-bundle-verify-summary-json "$verification_summary_json"
  --summary-json "$roadmap_summary_json"
  --report-md "$roadmap_report_md"
  --print-summary-json 0
)

host_install_plan_json="$(planned_command_json true "$host_install_check_script" "" "${host_install_check_args[@]}")"
bundle_plan_json="$(planned_command_json true "$bundle_script" "" "${bundle_args[@]}")"
verify_plan_json="$(planned_command_json true "$verify_script" "" "${verify_args[@]}")"
if [[ "$roadmap_refresh" == "1" ]]; then
  roadmap_plan_json="$(planned_command_json true "$roadmap_script" "" "${planned_roadmap_args[@]}")"
else
  roadmap_plan_json="$(planned_command_json false "$roadmap_script" "roadmap_refresh disabled" "${planned_roadmap_args[@]}")"
fi
planned_child_commands_json="$(jq -c -n \
  --argjson host_install_check "$host_install_plan_json" \
  --argjson bundle "$bundle_plan_json" \
  --argjson verifier "$verify_plan_json" \
  --argjson roadmap "$roadmap_plan_json" \
  '{
    host_install_check: $host_install_check,
    bundle: $bundle,
    verifier: $verifier,
    roadmap: $roadmap
  }')"
planned_artifacts_json="$(jq -c -n \
  --arg reports_dir "$reports_dir" \
  --arg host_install_check_summary_json "$host_install_check_summary_json" \
  --arg host_install_check_log "$host_install_check_log" \
  --arg bundle_dir "$planned_bundle_dir" \
  --arg bundle_summary_json "$bundle_summary_json" \
  --arg bundle_service_smoke_summary_json "$planned_bundle_service_smoke_summary_json" \
  --arg bundle_deployment_evidence_summary_json "$planned_bundle_deployment_evidence_summary_json" \
  --arg bundle_host_install_check_summary_json "$planned_bundle_host_install_check_summary_json" \
  --arg bundle_log "$bundle_log" \
  --arg provenance_json "$provenance_out" \
  --arg verification_summary_json "$verification_summary_json" \
  --arg verify_log "$verify_log" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg roadmap_report_md "$roadmap_report_md" \
  --arg roadmap_log "$roadmap_log" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  '{
    reports_dir: $reports_dir,
    host_install_check_summary_json: $host_install_check_summary_json,
    host_install_check_log: $host_install_check_log,
    bundle_dir: $bundle_dir,
    bundle_summary_json: $bundle_summary_json,
    bundle_service_smoke_summary_json: $bundle_service_smoke_summary_json,
    bundle_deployment_evidence_summary_json: $bundle_deployment_evidence_summary_json,
    bundle_host_install_check_summary_json: $bundle_host_install_check_summary_json,
    bundle_log: $bundle_log,
    provenance_json: $provenance_json,
    verification_summary_json: $verification_summary_json,
    verify_log: $verify_log,
    roadmap_summary_json: $roadmap_summary_json,
    roadmap_report_md: $roadmap_report_md,
    roadmap_log: $roadmap_log,
    summary_json: $summary_json,
    report_md: $report_md
  }')"

if [[ "$plan_only" == "1" ]]; then
  write_summary "pass" 0 "plan" "Plan-only preflight passed; child execution skipped"
  echo "access-recovery-real-helper-evidence-run: status=pass stage=plan"
  echo "summary_json: $summary_json"
  echo "report_md: $report_md"
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit 0
fi

set +e
"$host_install_check_script" "${host_install_check_args[@]}" >"$host_install_check_log" 2>&1
host_install_check_rc=$?
set -e
if [[ "$host_install_check_rc" -ne 0 ]]; then
  write_summary "fail" "$host_install_check_rc" "host_install_check" "Access bridge host install check failed"
  print_failure_log_tail "host-install-check" "$host_install_check_log"
  echo "access-recovery-real-helper-evidence-run: status=fail stage=host_install_check"
  echo "summary_json: $summary_json"
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit "$host_install_check_rc"
fi

set +e
"$bundle_script" "${bundle_args[@]}" >"$bundle_log" 2>&1
bundle_rc=$?
set -e
if [[ "$bundle_rc" -ne 0 ]]; then
  write_summary "fail" "$bundle_rc" "bundle" "Access bridge pilot evidence bundle failed"
  print_failure_log_tail "bundle" "$bundle_log"
  echo "access-recovery-real-helper-evidence-run: status=fail stage=bundle"
  echo "summary_json: $summary_json"
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit "$bundle_rc"
fi
bundle_service_smoke_summary_json="$(abs_path "$(jq -r 'if (.artifacts.smoke_summary_json | type) == "string" then .artifacts.smoke_summary_json else "" end' "$bundle_summary_json" 2>/dev/null || printf '%s' "")")"
bundle_deployment_evidence_summary_json="$(abs_path "$(jq -r 'if (.artifacts.deployment_evidence_summary_json | type) == "string" then .artifacts.deployment_evidence_summary_json else "" end' "$bundle_summary_json" 2>/dev/null || printf '%s' "")")"
bundle_host_install_check_summary_json="$(abs_path "$(jq -r 'if (.artifacts.host_install_check_summary_json | type) == "string" then .artifacts.host_install_check_summary_json else "" end' "$bundle_summary_json" 2>/dev/null || printf '%s' "")")"
if [[ -z "$bundle_service_smoke_summary_json" || -z "$bundle_deployment_evidence_summary_json" || -z "$bundle_host_install_check_summary_json" ]]; then
  write_summary "fail" 1 "bundle" "Access bridge pilot evidence bundle summary is missing child evidence paths required for roadmap binding"
  echo "access-recovery-real-helper-evidence-run: status=fail stage=bundle"
  echo "summary_json: $summary_json"
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit 1
fi
if [[ ! -f "$bundle_service_smoke_summary_json" || ! -f "$bundle_deployment_evidence_summary_json" || ! -f "$bundle_host_install_check_summary_json" ]]; then
  write_summary "fail" 1 "bundle" "Access bridge pilot evidence bundle summary points to missing child evidence outputs required for trusted handoff"
  echo "access-recovery-real-helper-evidence-run: status=fail stage=bundle"
  echo "summary_json: $summary_json"
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit 1
fi

set +e
"$verify_script" "${verify_args[@]}" >"$verify_log" 2>&1
verify_rc=$?
set -e
if [[ "$verify_rc" -ne 0 ]]; then
  write_summary "fail" "$verify_rc" "verify" "Trusted pilot evidence verifier failed"
  print_failure_log_tail "verifier" "$verify_log"
  echo "access-recovery-real-helper-evidence-run: status=fail stage=verify"
  echo "summary_json: $summary_json"
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit "$verify_rc"
fi

verifier_ready="$(jq -r '.pilot_handoff_ready // false | tostring' "$verification_summary_json" 2>/dev/null || printf '%s' "false")"
if [[ "$verifier_ready" != "true" ]]; then
  write_summary "fail" 1 "verify" "Trusted verifier receipt did not mark pilot_handoff_ready=true"
  echo "access-recovery-real-helper-evidence-run: status=fail stage=verify"
  echo "summary_json: $summary_json"
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit 1
fi
if ! receipt_validation_errors="$(validate_trusted_verifier_receipt 2>&1)"; then
  write_summary "fail" 1 "verify" "Trusted verifier receipt did not prove current real helper HTTPS evidence binding"
  echo "trusted verifier receipt validation failed:" >&2
  printf '%s\n' "$receipt_validation_errors" >&2
  echo "access-recovery-real-helper-evidence-run: status=fail stage=verify"
  echo "summary_json: $summary_json"
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit 1
fi

if [[ "$roadmap_refresh" == "1" ]]; then
  roadmap_args=(
    --refresh-manual-validation 0
    --refresh-single-machine-readiness 0
    --access-bridge-service-smoke-summary-json "$bundle_service_smoke_summary_json"
    --access-bridge-deployment-evidence-summary-json "$bundle_deployment_evidence_summary_json"
    --access-bridge-host-install-summary-json "$bundle_host_install_check_summary_json"
    --access-bridge-pilot-evidence-bundle-verify-summary-json "$verification_summary_json"
    --summary-json "$roadmap_summary_json"
    --report-md "$roadmap_report_md"
    --print-summary-json 0
  )
  set +e
  "$roadmap_script" "${roadmap_args[@]}" >"$roadmap_log" 2>&1
  roadmap_rc=$?
  set -e
  if [[ "$roadmap_rc" -ne 0 ]]; then
    write_summary "fail" "$roadmap_rc" "roadmap" "Roadmap refresh failed after trusted evidence verification"
    print_failure_log_tail "roadmap" "$roadmap_log"
    echo "access-recovery-real-helper-evidence-run: status=fail stage=roadmap"
    echo "summary_json: $summary_json"
    [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
    exit "$roadmap_rc"
  fi
  roadmap_ready="$(jq -r '.access_recovery_pilot_handoff_ready // false | tostring' "$roadmap_summary_json" 2>/dev/null || printf '%s' "false")"
  if [[ "$roadmap_ready" != "true" ]]; then
    write_summary "fail" 1 "roadmap" "Roadmap did not mark Access Recovery pilot handoff ready"
    echo "access-recovery-real-helper-evidence-run: status=fail stage=roadmap"
    echo "summary_json: $summary_json"
    [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
    exit 1
  fi
fi

write_summary "pass" 0 "complete" "Real helper HTTPS evidence and trusted verifier receipt completed"
echo "access-recovery-real-helper-evidence-run: status=pass stage=complete"
echo "summary_json: $summary_json"
echo "verification_summary_json: $verification_summary_json"
if [[ "$roadmap_refresh" == "1" ]]; then
  echo "roadmap_summary_json: $roadmap_summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi
