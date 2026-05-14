#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
umask 077

base_url=""
path_id="helper-web"
code=""
code_file=""
cacert=""
client_cert=""
client_key=""
require_mtls="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_REQUIRE_MTLS:-0}"
config_json=""
deploy_pack_dir=""
host_install_evidence_mode="deploy-pack"
install_dir=""
systemd_unit_file=""
proxy_kind=""
proxy_config_file=""
service_name="gpm-access-bridge"
bundle_dir=""
summary_json=""
report_md=""
print_summary_json="1"
max_smoke_age_sec="${ACCESS_BRIDGE_DEPLOYMENT_EVIDENCE_MAX_SMOKE_AGE_SEC:-3600}"
require_https="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_REQUIRE_HTTPS:-1}"
require_public_host="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_REQUIRE_PUBLIC_HOST:-1}"
expected_public_host=""
expect_helper_id=""
expect_org_id=""
expect_registry_id=""
provenance_sign="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_PROVENANCE_SIGN:-0}"
provenance_private_key_file=""
provenance_org_id=""
provenance_org_name=""
provenance_key_id=""
provenance_lifetime_hours=""
provenance_out=""
service_smoke_script="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SERVICE_SMOKE_SCRIPT:-./scripts/access_bridge_service_smoke.sh}"
deployment_evidence_script="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_DEPLOYMENT_EVIDENCE_SCRIPT:-./scripts/access_bridge_deployment_evidence.sh}"
host_install_check_script="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_HOST_INSTALL_CHECK_SCRIPT:-./scripts/access_bridge_host_install_check.sh}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/access_bridge_pilot_evidence_bundle.sh \
    --base-url URL \
    --config-json FILE \
    --deploy-pack-dir DIR \
    (--code CODE | --code-file FILE) \
    [--host-install-evidence-mode deploy-pack|installed-host] \
    [--install-dir DIR] \
    [--systemd-unit-file FILE] \
    [--proxy-kind caddy|nginx] \
    [--proxy-config-file FILE] \
    [--path-id helper-web] \
    [--cacert FILE] \
    [--client-cert FILE --client-key FILE] \
    [--require-mtls 0|1] \
    [--service-name gpm-access-bridge] \
    [--bundle-dir DIR] \
    [--summary-json FILE] \
    [--report-md FILE] \
    [--require-https 0|1] \
    [--require-public-host 0|1] \
    [--expected-public-host HELPER_PUBLIC_DNS] \
    [--provenance-sign 0|1] \
    [--provenance-private-key-file FILE] \
    [--provenance-org-id ID] \
    [--provenance-org-name NAME] \
    [--provenance-key-id ID] \
    [--provenance-lifetime-hours HOURS] \
    [--provenance-out FILE] \
    [--print-summary-json 0|1]

Runs deployed bridge smoke, deployment evidence, and host-install evidence into one candidate pilot evidence bundle.
Non-loopback pilot targets must use HTTPS and a public-routable-looking host unless diagnostic overrides are set.
When --provenance-sign 1 is set, writes an external provenance sidecar after the tarball and checksum sidecar are finalized.
USAGE
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access bridge pilot evidence bundle failed: missing required command: $cmd" >&2
    exit 2
  fi
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

timestamp_file() {
  date -u +%Y%m%d_%H%M%S
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

path_is_inside_dir() {
  local path="$1"
  local dir="$2"
  [[ "$path" == "$dir" || "$path" == "$dir/"* ]]
}

canonical_path_or_abs() {
  local path
  path="$(abs_path "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
    return
  fi
  if command -v realpath >/dev/null 2>&1; then
    if realpath "$path" 2>/dev/null; then
      return
    fi
  fi
  if command -v readlink >/dev/null 2>&1; then
    if readlink -f "$path" 2>/dev/null; then
      return
    fi
  fi
  printf '%s' "$path"
}

path_looks_generated_demo_example_artifact() {
  local path="${1:-}" candidate
  local candidates=()
  [[ -z "$(trim "$path")" ]] && return 1
  candidates+=("$path" "$(canonical_path_or_abs "$path")")
  for candidate in "${candidates[@]}"; do
    candidate="${candidate//\\//}"
    candidate="$(printf '%s' "$candidate" | tr '[:upper:]' '[:lower:]')"
    candidate="${candidate%/}"
    case "$candidate" in
      */docs/examples|*/docs/examples/*|*/examples/access-recovery|*/examples/access-recovery/*|\
      */.easy-node-logs/access-recovery-demo*|\
      */.easy-node-logs/access_recovery_local_evidence*/access-recovery-demo|\
      */.easy-node-logs/access_recovery_local_evidence*/access-recovery-demo/*|\
      */generated-demo/*|*/generated-example/*|*/demo-bundle/*|*/demo-manifest.json|\
      *.example|*.example.*)
        return 0
        ;;
    esac
  done
  return 1
}

value_looks_generated_demo_identity() {
  local value
  value="$(trim "${1:-}")"
  [[ -z "$value" ]] && return 1
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    demo|demo-*|*-demo|helper-demo|freenews-demo|*generated-demo*|*generated_example*|example|example-*|*-example|helper-example|freenews-example|*generated-example*|*generated_example*)
      return 0
      ;;
  esac
  [[ "$value" =~ (^|[^a-z0-9])(demo|example)([^a-z0-9]|$) ]]
}

fail_pilot_demo_example_input() {
  local label="$1"
  local value="$2"
  echo "access bridge pilot evidence bundle failed: $label must not use generated demo/example artifacts for real helper HTTPS pilot handoff: $value" >&2
  exit 2
}

url_scheme() {
  local url="${1:-}"
  if [[ "$url" == *://* ]]; then
    printf '%s' "${url%%://*}" | tr '[:upper:]' '[:lower:]'
  fi
}

url_authority() {
  local rest="${1:-}"
  rest="${rest#*://}"
  rest="${rest%%/*}"
  rest="${rest%%\?*}"
  rest="${rest%%#*}"
  printf '%s' "$rest"
}

url_authority_has_userinfo() {
  local authority
  authority="$(url_authority "$1")"
  [[ "$authority" == *@* ]]
}

redact_url_userinfo() {
  local value="${1:-}" prefix rest authority suffix host_part
  if [[ "$value" == *"://"* ]]; then
    prefix="${value%%://*}://"
    rest="${value#*://}"
  else
    prefix=""
    rest="$value"
  fi
  authority="${rest%%/*}"
  authority="${authority%%\?*}"
  authority="${authority%%#*}"
  if [[ "$authority" != *@* ]]; then
    printf '%s' "$value"
  else
    suffix="${rest:${#authority}}"
    host_part="${authority##*@}"
    printf '%s[redacted]@%s%s' "$prefix" "$host_part" "$suffix"
  fi
}

reject_output_symlink_or_die() {
  local path="${1:-}"
  if [[ -n "$path" && -L "$path" ]]; then
    echo "access bridge pilot evidence bundle failed: refusing to write evidence output through symlink: $path" >&2
    exit 2
  fi
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

base_url_is_loopback() {
  local host
  host="$(url_host "$1")"
  [[ "$host" == "localhost" || "$host" == "::1" || "$host" =~ ^127\.[0-9]+\.[0-9]+\.[0-9]+$ || "$host" =~ ^::ffff:127\.[0-9]+\.[0-9]+\.[0-9]+$ || "$host" =~ ^0:0:0:0:0:ffff:127\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

ipv4_host_is_private_or_reserved() {
  local host="${1:-}"
  if [[ "$host" == 127.* || "$host" == 10.* || "$host" == 192.168.* || "$host" == 169.254.* || "$host" == 0.* ]]; then
    return 0
  fi
  if [[ "$host" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
    return 0
  fi
  if [[ "$host" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. ]]; then
    return 0
  fi
  if [[ "$host" =~ ^192\.0\.(0|2)\. || "$host" =~ ^192\.88\.99\. ]]; then
    return 0
  fi
  if [[ "$host" =~ ^198\.(1[89]|51\.100)\. || "$host" =~ ^203\.0\.113\. ]]; then
    return 0
  fi
  if [[ "$host" =~ ^(22[4-9]|23[0-9]|24[0-9]|25[0-5])\. ]]; then
    return 0
  fi
  return 1
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

base_url_host_is_private_or_reserved() {
  local host mapped_ipv4
  if url_authority_has_userinfo "$1"; then
    return 0
  fi
  host="$(url_host "$1")"
  if [[ -z "$host" || "$host" == "localhost" ]]; then
    return 0
  fi
  if [[ "$host" =~ (^|\.)(localhost|local|lan|internal|test|invalid|example)$ ]]; then
    return 0
  fi
  if [[ "$host" =~ (^|\.)example\.(com|net|org)$ ]]; then
    return 0
  fi
  if [[ "$host" == home.arpa || "$host" == *.home.arpa ]]; then
    return 0
  fi
  if [[ "$host" == ts.net || "$host" == *.ts.net || "$host" == tailscale.net || "$host" == *.tailscale.net ]]; then
    return 0
  fi
  if ipv4_host_is_private_or_reserved "$host"; then
    return 0
  fi
  if ipv6_host_is_private_or_reserved "$host"; then
    return 0
  fi
  mapped_ipv4="$(ipv4_mapped_host_to_ipv4 "$host" 2>/dev/null || true)"
  if [[ -n "$mapped_ipv4" ]] && ipv4_host_is_private_or_reserved "$mapped_ipv4"; then
    return 0
  fi
  return 1
}

json_string_or_empty() {
  local file="$1"
  local filter="$2"
  jq -r "$filter // \"\"" "$file" 2>/dev/null || true
}

sha256_tool=""
detect_sha256_tool() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256_tool="sha256sum"
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    sha256_tool="shasum"
    return
  fi
  echo "access bridge pilot evidence bundle failed: missing required command: sha256sum or shasum" >&2
  exit 2
}

sha256_value() {
  local file="$1"
  local line
  if [[ "$sha256_tool" == "sha256sum" ]]; then
    line="$(sha256sum "$file")"
  else
    line="$(shasum -a 256 "$file")"
  fi
  printf '%s' "${line%% *}"
}

write_sha256_line() {
  local file="$1"
  local label="$2"
  printf '%s  %s\n' "$(sha256_value "$file")" "$label"
}

deploy_pack_rel_path_is_secret() {
  local rel="$1"
  local lower
  lower="$(printf '%s' "$rel" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    bridge-code.txt|*/bridge-code.txt|\
    recovery.key|*/recovery.key|\
    .env|*/.env|\
    id_rsa|*/id_rsa|id_dsa|*/id_dsa|id_ecdsa|*/id_ecdsa|id_ed25519|*/id_ed25519|\
    *.key|*.pem|*.p8|*.pkcs8|*.p12|*.pfx|\
    *private-key*|*private_key*|*access-code*|*access_code*|*secret*|*credential*|\
    *token*|*password*|*passwd*|*auth*|*bearer*|*oauth*)
      return 0
      ;;
  esac
  return 1
}

deploy_pack_file_contains_private_key() {
  local file="$1"
  LC_ALL=C grep -aEq -- '-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----' "$file" 2>/dev/null
}

copy_public_deploy_pack() {
  local src="$1"
  local dst="$2"
  local skipped_file="$3"
  local file rel target

  rm -rf "$dst"
  mkdir -p "$dst"
  : >"$skipped_file"
  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    rel="${file#$src/}"
    if deploy_pack_rel_path_is_secret "$rel" || deploy_pack_file_contains_private_key "$file"; then
      printf '%s\n' "$rel" >>"$skipped_file"
      continue
    fi
    target="$dst/$rel"
    mkdir -p "$(dirname "$target")"
    cp -p "$file" "$target"
  done < <(find "$src" -type f -print | LC_ALL=C sort)
}

append_step() {
  local id="$1"
  local status="$2"
  local rc="$3"
  local summary="$4"
  local log="$5"
  jq -nc \
    --arg id "$id" \
    --arg status "$status" \
    --arg summary_json "$summary" \
    --arg log "$log" \
    --argjson rc "$rc" \
    '{id:$id,status:$status,rc:$rc,summary_json:$summary_json,log:$log}' >>"$steps_jsonl"
}

run_json_step() {
  local id="$1"
  local step_summary="$2"
  local step_log="$3"
  shift 3

  set +e
  "$@" >"$step_log" 2>&1
  local rc=$?
  set -e

  local status="missing"
  if [[ -f "$step_summary" ]]; then
    status="$(jq -r '.status // "unknown"' "$step_summary" 2>/dev/null || printf '%s' "invalid")"
  fi
  if [[ "$rc" -ne 0 && "$status" == "pass" ]]; then
    status="fail"
  fi
  append_step "$id" "$status" "$rc" "$step_summary" "$step_log"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url)
      base_url="${2:-}"
      shift 2
      ;;
    --path-id)
      path_id="${2:-}"
      shift 2
      ;;
    --code)
      code="${2:-}"
      shift 2
      ;;
    --code-file)
      code_file="${2:-}"
      shift 2
      ;;
    --cacert)
      cacert="${2:-}"
      shift 2
      ;;
    --client-cert)
      client_cert="${2:-}"
      shift 2
      ;;
    --client-key)
      client_key="${2:-}"
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
    --config-json|--config)
      config_json="${2:-}"
      shift 2
      ;;
    --deploy-pack-dir)
      deploy_pack_dir="${2:-}"
      shift 2
      ;;
    --host-install-evidence-mode|--evidence-mode)
      host_install_evidence_mode="${2:-}"
      shift 2
      ;;
    --install-dir)
      install_dir="${2:-}"
      shift 2
      ;;
    --systemd-unit-file)
      systemd_unit_file="${2:-}"
      shift 2
      ;;
    --proxy-kind)
      proxy_kind="${2:-}"
      shift 2
      ;;
    --proxy-config-file)
      proxy_config_file="${2:-}"
      shift 2
      ;;
    --service-name)
      service_name="${2:-}"
      shift 2
      ;;
    --bundle-dir)
      bundle_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --max-smoke-age-sec)
      max_smoke_age_sec="${2:-}"
      shift 2
      ;;
    --require-https)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_https="${2:-}"
        shift 2
      else
        require_https="1"
        shift
      fi
      ;;
    --require-public-host)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_public_host="${2:-}"
        shift 2
      else
        require_public_host="1"
        shift
      fi
      ;;
    --expected-public-host)
      expected_public_host="${2:-}"
      shift 2
      ;;
    --expect-helper-id)
      expect_helper_id="${2:-}"
      shift 2
      ;;
    --expect-org-id)
      expect_org_id="${2:-}"
      shift 2
      ;;
    --expect-registry-id)
      expect_registry_id="${2:-}"
      shift 2
      ;;
    --provenance-sign)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        provenance_sign="${2:-}"
        shift 2
      else
        provenance_sign="1"
        shift
      fi
      ;;
    --provenance-private-key-file)
      provenance_private_key_file="${2:-}"
      shift 2
      ;;
    --provenance-org-id)
      provenance_org_id="${2:-}"
      shift 2
      ;;
    --provenance-org-name)
      provenance_org_name="${2:-}"
      shift 2
      ;;
    --provenance-key-id)
      provenance_key_id="${2:-}"
      shift 2
      ;;
    --provenance-lifetime-hours)
      provenance_lifetime_hours="${2:-}"
      shift 2
      ;;
    --provenance-out)
      provenance_out="${2:-}"
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
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for cmd in bash basename cp date dirname find grep jq mktemp rm sed sort tar tr; do
  need_cmd "$cmd"
done
detect_sha256_tool
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--require-https" "$require_https"
bool_arg_or_die "--require-public-host" "$require_public_host"
bool_arg_or_die "--require-mtls" "$require_mtls"
bool_arg_or_die "--provenance-sign" "$provenance_sign"
if [[ ! "$max_smoke_age_sec" =~ ^[0-9]+$ ]]; then
  echo "access bridge pilot evidence bundle failed: --max-smoke-age-sec must be a non-negative integer" >&2
  exit 2
fi
if [[ -n "$provenance_lifetime_hours" && ( ! "$provenance_lifetime_hours" =~ ^[0-9]+$ || "$provenance_lifetime_hours" -le 0 ) ]]; then
  echo "access bridge pilot evidence bundle failed: --provenance-lifetime-hours must be a positive integer" >&2
  exit 2
fi

base_url="${base_url%/}"
path_id="$(trim "$path_id")"
service_name="$(trim "$service_name")"
host_install_evidence_mode="$(trim "$host_install_evidence_mode")"
if [[ -z "$base_url" ]]; then
  echo "access bridge pilot evidence bundle failed: --base-url is required" >&2
  exit 2
fi
if [[ "$require_public_host" == "1" ]] && url_authority_has_userinfo "$base_url"; then
  echo "access bridge pilot evidence bundle failed: --base-url must not include userinfo for pilot evidence targets (set --require-public-host 0 for diagnostics)" >&2
  exit 2
fi
if [[ -z "$path_id" ]]; then
  echo "access bridge pilot evidence bundle failed: --path-id is required" >&2
  exit 2
fi
if [[ -z "$config_json" ]]; then
  echo "access bridge pilot evidence bundle failed: --config-json is required" >&2
  exit 2
fi
if [[ -z "$deploy_pack_dir" ]]; then
  echo "access bridge pilot evidence bundle failed: --deploy-pack-dir is required" >&2
  exit 2
fi
if [[ "$host_install_evidence_mode" != "deploy-pack" && "$host_install_evidence_mode" != "installed-host" ]]; then
  echo "access bridge pilot evidence bundle failed: --host-install-evidence-mode must be deploy-pack or installed-host" >&2
  exit 2
fi
if [[ "$host_install_evidence_mode" == "installed-host" ]]; then
  if [[ -z "$install_dir" ]]; then
    echo "access bridge pilot evidence bundle failed: --install-dir is required when --host-install-evidence-mode installed-host" >&2
    exit 2
  fi
  if [[ -z "$systemd_unit_file" ]]; then
    echo "access bridge pilot evidence bundle failed: --systemd-unit-file is required when --host-install-evidence-mode installed-host" >&2
    exit 2
  fi
  if [[ "$proxy_kind" != "caddy" && "$proxy_kind" != "nginx" ]]; then
    echo "access bridge pilot evidence bundle failed: --proxy-kind must be caddy or nginx when --host-install-evidence-mode installed-host" >&2
    exit 2
  fi
  if [[ -z "$proxy_config_file" ]]; then
    echo "access bridge pilot evidence bundle failed: --proxy-config-file is required when --host-install-evidence-mode installed-host" >&2
    exit 2
  fi
elif [[ -n "$proxy_kind" && "$proxy_kind" != "caddy" && "$proxy_kind" != "nginx" ]]; then
  echo "access bridge pilot evidence bundle failed: --proxy-kind must be caddy or nginx" >&2
  exit 2
fi
if [[ -n "$code" && -n "$code_file" ]]; then
  echo "access bridge pilot evidence bundle failed: use either --code or --code-file, not both" >&2
  exit 2
fi
if [[ -z "$code" && -z "$code_file" ]]; then
  echo "access bridge pilot evidence bundle failed: --code or --code-file is required" >&2
  exit 2
fi
if [[ "$provenance_sign" == "1" ]]; then
  need_cmd go
  if [[ -z "$provenance_private_key_file" ]]; then
    echo "access bridge pilot evidence bundle failed: --provenance-private-key-file is required when --provenance-sign 1" >&2
    exit 2
  fi
  if [[ -z "$provenance_org_id" ]]; then
    echo "access bridge pilot evidence bundle failed: --provenance-org-id is required when --provenance-sign 1" >&2
    exit 2
  fi
  if [[ -z "$provenance_org_name" ]]; then
    echo "access bridge pilot evidence bundle failed: --provenance-org-name is required when --provenance-sign 1" >&2
    exit 2
  fi
fi
if [[ "$require_https" == "1" && "$(url_scheme "$base_url")" != "https" ]] && ! base_url_is_loopback "$base_url"; then
  echo "access bridge pilot evidence bundle failed: --base-url must use HTTPS for non-loopback pilot evidence targets (set --require-https 0 for diagnostics)" >&2
  exit 2
fi
if [[ "$require_public_host" == "1" ]] && ! base_url_is_loopback "$base_url" && base_url_host_is_private_or_reserved "$base_url"; then
  echo "access bridge pilot evidence bundle failed: --base-url host must look public-routable for non-loopback pilot evidence targets (set --require-public-host 0 for diagnostics)" >&2
  exit 2
fi
if [[ "$provenance_sign" != "1" && "$require_https" == "1" && "$require_public_host" == "1" ]] &&
  ! base_url_is_loopback "$base_url" &&
  [[ "$(url_scheme "$base_url")" == "https" ]] &&
  ! base_url_host_is_private_or_reserved "$base_url"; then
  echo "access bridge pilot evidence bundle failed: real helper HTTPS pilot handoff requires --provenance-sign 1" >&2
  exit 2
fi
real_helper_https_pilot_handoff="0"
if [[ "$provenance_sign" == "1" && "$require_https" == "1" && "$require_public_host" == "1" ]] &&
  ! base_url_is_loopback "$base_url" &&
  [[ "$(url_scheme "$base_url")" == "https" ]] &&
  ! base_url_host_is_private_or_reserved "$base_url"; then
  real_helper_https_pilot_handoff="1"
fi

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
if [[ ! -f "$config_json" ]]; then
  echo "access bridge pilot evidence bundle failed: config JSON not found: $config_json" >&2
  exit 2
fi
if [[ ! -d "$deploy_pack_dir" ]]; then
  echo "access bridge pilot evidence bundle failed: deploy pack dir not found: $deploy_pack_dir" >&2
  exit 2
fi
if [[ "$host_install_evidence_mode" == "installed-host" ]]; then
  if [[ ! -d "$install_dir" ]]; then
    echo "access bridge pilot evidence bundle failed: install dir not found: $install_dir" >&2
    exit 2
  fi
  if [[ ! -f "$systemd_unit_file" ]]; then
    echo "access bridge pilot evidence bundle failed: systemd unit file not found: $systemd_unit_file" >&2
    exit 2
  fi
  if [[ ! -f "$proxy_config_file" ]]; then
    echo "access bridge pilot evidence bundle failed: proxy config file not found: $proxy_config_file" >&2
    exit 2
  fi
fi
if [[ -n "$code_file" ]]; then
  code_file="$(abs_path "$code_file")"
  if [[ ! -f "$code_file" ]]; then
    echo "access bridge pilot evidence bundle failed: code file not found: $code_file" >&2
    exit 2
  fi
fi
if [[ -n "$cacert" ]]; then
  cacert="$(abs_path "$cacert")"
  if [[ ! -f "$cacert" ]]; then
    echo "access bridge pilot evidence bundle failed: cacert file not found: $cacert" >&2
    exit 2
  fi
fi
if [[ -n "$client_cert" ]]; then
  client_cert="$(abs_path "$client_cert")"
  if [[ ! -f "$client_cert" ]]; then
    echo "access bridge pilot evidence bundle failed: client cert file not found: $client_cert" >&2
    exit 2
  fi
fi
if [[ -n "$client_key" ]]; then
  client_key="$(abs_path "$client_key")"
  if [[ ! -f "$client_key" ]]; then
    echo "access bridge pilot evidence bundle failed: client key file not found: $client_key" >&2
    exit 2
  fi
fi
if { [[ -n "$client_cert" ]] && [[ -z "$client_key" ]]; } || { [[ -z "$client_cert" ]] && [[ -n "$client_key" ]]; }; then
  echo "access bridge pilot evidence bundle failed: --client-cert and --client-key must be supplied together" >&2
  exit 2
fi
if [[ "$require_mtls" == "1" && ( -z "$client_cert" || -z "$client_key" ) ]]; then
  echo "access bridge pilot evidence bundle failed: --require-mtls 1 requires --client-cert and --client-key" >&2
  exit 2
fi
if [[ "$provenance_sign" == "1" ]]; then
  provenance_private_key_file="$(abs_path "$provenance_private_key_file")"
  if [[ ! -f "$provenance_private_key_file" ]]; then
    echo "access bridge pilot evidence bundle failed: provenance private key file not found: $provenance_private_key_file" >&2
    exit 2
  fi
fi
if [[ "$real_helper_https_pilot_handoff" == "1" ]]; then
  if [[ -n "$code_file" ]] && path_looks_generated_demo_example_artifact "$code_file"; then
    fail_pilot_demo_example_input "--code-file" "$code_file"
  fi
  if path_looks_generated_demo_example_artifact "$config_json"; then
    fail_pilot_demo_example_input "--config-json" "$config_json"
  fi
  if path_looks_generated_demo_example_artifact "$deploy_pack_dir"; then
    fail_pilot_demo_example_input "--deploy-pack-dir" "$deploy_pack_dir"
  fi
  if path_looks_generated_demo_example_artifact "$provenance_private_key_file"; then
    fail_pilot_demo_example_input "--provenance-private-key-file" "$provenance_private_key_file"
  fi
  if [[ -n "$provenance_org_id" ]] && value_looks_generated_demo_identity "$provenance_org_id"; then
    echo "access bridge pilot evidence bundle failed: --provenance-org-id must not use a generated demo/example identity for real helper HTTPS pilot handoff" >&2
    exit 2
  fi
  if [[ -n "$provenance_org_name" ]] && value_looks_generated_demo_identity "$provenance_org_name"; then
    echo "access bridge pilot evidence bundle failed: --provenance-org-name must not use a generated demo/example identity for real helper HTTPS pilot handoff" >&2
    exit 2
  fi
fi

if [[ -z "$bundle_dir" ]]; then
  mkdir -p "$ROOT_DIR/.easy-node-logs"
  bundle_dir="$(mktemp -d "$ROOT_DIR/.easy-node-logs/access_bridge_pilot_evidence_bundle_$(timestamp_file).XXXXXX")"
else
  bundle_dir="$(abs_path "$bundle_dir")"
  if [[ -L "$bundle_dir" ]]; then
    echo "access bridge pilot evidence bundle failed: refusing to use symlink bundle dir: $bundle_dir" >&2
    exit 2
  fi
  if [[ -d "$bundle_dir" ]] && find "$bundle_dir" -mindepth 1 -print -quit | grep -q .; then
    echo "access bridge pilot evidence bundle failed: --bundle-dir already exists and is not empty: $bundle_dir" >&2
    exit 2
  fi
  mkdir -p "$bundle_dir"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$bundle_dir/access_bridge_pilot_evidence_bundle_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$report_md" ]]; then
  report_md="$bundle_dir/access_bridge_pilot_evidence_bundle_report.md"
else
  report_md="$(abs_path "$report_md")"
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
reject_output_symlink_or_die "$summary_json"
reject_output_symlink_or_die "$report_md"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT
steps_jsonl="$tmp_dir/steps.jsonl"
: >"$steps_jsonl"

effective_code_file="$code_file"
if [[ -n "$code" ]]; then
  effective_code_file="$tmp_dir/access-code.txt"
  printf '%s\n' "$code" >"$effective_code_file"
fi

if [[ -z "$expect_helper_id" ]]; then
  expect_helper_id="$(json_string_or_empty "$config_json" '.helper_id')"
fi
if [[ -z "$expect_org_id" ]]; then
  expect_org_id="$(json_string_or_empty "$config_json" '.organization_id')"
fi
if [[ -z "$expect_registry_id" ]]; then
  expect_registry_id="$(json_string_or_empty "$config_json" '.registry_id')"
fi
if [[ "$real_helper_https_pilot_handoff" == "1" ]]; then
  if [[ -n "$expect_helper_id" ]] && value_looks_generated_demo_identity "$expect_helper_id"; then
    echo "access bridge pilot evidence bundle failed: expected helper identity must not use a generated demo/example identity for real helper HTTPS pilot handoff" >&2
    exit 2
  fi
  if [[ -n "$expect_org_id" ]] && value_looks_generated_demo_identity "$expect_org_id"; then
    echo "access bridge pilot evidence bundle failed: expected organization identity must not use a generated demo/example identity for real helper HTTPS pilot handoff" >&2
    exit 2
  fi
  if [[ -n "$expect_registry_id" ]] && value_looks_generated_demo_identity "$expect_registry_id"; then
    echo "access bridge pilot evidence bundle failed: expected registry identity must not use a generated demo/example identity for real helper HTTPS pilot handoff" >&2
    exit 2
  fi
  if [[ -z "$expect_helper_id" || -z "$expect_org_id" || -z "$expect_registry_id" ]]; then
    echo "access bridge pilot evidence bundle failed: real helper HTTPS pilot handoff requires expected helper, organization, and registry identities" >&2
    exit 2
  fi
  if [[ "$provenance_org_id" != "$expect_org_id" ]]; then
    echo "access bridge pilot evidence bundle failed: --provenance-org-id must match expected organization identity for real helper HTTPS pilot handoff" >&2
    exit 2
  fi
  if [[ "$host_install_evidence_mode" != "installed-host" ]]; then
    echo "access bridge pilot evidence bundle failed: real helper HTTPS pilot handoff requires --host-install-evidence-mode installed-host" >&2
    exit 2
  fi
fi

config_copy="$bundle_dir/bridge-service-config.json"
deploy_pack_copy="$bundle_dir/bridge-deploy-pack"
deploy_pack_skipped_secrets="$bundle_dir/deploy-pack-skipped-secrets.txt"
cp "$config_json" "$config_copy"
copy_public_deploy_pack "$deploy_pack_dir" "$deploy_pack_copy" "$deploy_pack_skipped_secrets"

smoke_summary="$bundle_dir/access_bridge_service_smoke_summary.json"
smoke_log="$bundle_dir/access_bridge_service_smoke.log"
smoke_args=(
  bash "$service_smoke_script"
  --base-url "$base_url"
  --path-id "$path_id"
  --code-file "$effective_code_file"
  --summary-json "$smoke_summary"
  --abuse-message "pilot evidence bundle smoke"
  --require-mtls "$require_mtls"
)
if [[ -n "$cacert" ]]; then
  smoke_args+=(--cacert "$cacert")
fi
if [[ -n "$client_cert" ]]; then
  smoke_args+=(--client-cert "$client_cert" --client-key "$client_key")
fi
if [[ -n "$expect_helper_id" ]]; then
  smoke_args+=(--expect-helper-id "$expect_helper_id")
fi
if [[ -n "$expect_org_id" ]]; then
  smoke_args+=(--expect-org-id "$expect_org_id")
fi
if [[ -n "$expect_registry_id" ]]; then
  smoke_args+=(--expect-registry-id "$expect_registry_id")
fi
run_json_step "service_smoke" "$smoke_summary" "$smoke_log" "${smoke_args[@]}"

deployment_summary="$bundle_dir/access_bridge_deployment_evidence_summary.json"
deployment_log="$bundle_dir/access_bridge_deployment_evidence.log"
deployment_args=(
  env "ACCESS_BRIDGE_DEPLOYMENT_EVIDENCE_MAX_SMOKE_AGE_SEC=$max_smoke_age_sec"
  bash "$deployment_evidence_script"
  --smoke-summary-json "$smoke_summary"
  --config-json "$config_json"
  --deploy-pack-dir "$deploy_pack_dir"
  --service-name "$service_name"
  --summary-json "$deployment_summary"
  --print-summary-json 0
  --require-mtls "$require_mtls"
)
if [[ -n "$expect_helper_id" ]]; then
  deployment_args+=(--expect-helper-id "$expect_helper_id")
fi
if [[ -n "$expect_org_id" ]]; then
  deployment_args+=(--expect-org-id "$expect_org_id")
fi
if [[ -n "$expect_registry_id" ]]; then
  deployment_args+=(--expect-registry-id "$expect_registry_id")
fi
run_json_step "deployment_evidence" "$deployment_summary" "$deployment_log" "${deployment_args[@]}"

host_summary="$bundle_dir/access_bridge_host_install_check_summary.json"
host_log="$bundle_dir/access_bridge_host_install_check.log"
host_install_args=(
  bash "$host_install_check_script"
  --evidence-mode "$host_install_evidence_mode"
  --deploy-pack-dir "$deploy_pack_dir"
  --config-json "$config_json"
  --service-name "$service_name"
  --summary-json "$host_summary"
  --print-summary-json 0
)
if [[ "$host_install_evidence_mode" == "installed-host" ]]; then
  host_install_args+=(
    --install-dir "$install_dir"
    --systemd-unit-file "$systemd_unit_file"
    --proxy-kind "$proxy_kind"
    --proxy-config-file "$proxy_config_file"
    --expected-base-url "$base_url"
  )
fi
if [[ -n "$expected_public_host" ]]; then
  host_install_args+=(--expected-public-host "$expected_public_host")
elif [[ "$host_install_evidence_mode" != "installed-host" && "$require_public_host" == "1" ]] && ! base_url_host_is_private_or_reserved "$base_url"; then
  host_install_args+=(--expected-base-url "$base_url")
fi
run_json_step "host_install_check" "$host_summary" "$host_log" "${host_install_args[@]}"

smoke_summary_sha256=""
deployment_evidence_summary_sha256=""
host_install_check_summary_sha256=""
deployment_evidence_schema_major=""
deployment_evidence_schema_minor=""
deployment_evidence_smoke_summary_sha256=""
deployment_evidence_binding_smoke_summary_sha256=""
evidence_binding_status="pass"
evidence_binding_reason=""
if [[ -f "$smoke_summary" ]]; then
  smoke_summary_sha256="$(sha256_value "$smoke_summary")"
fi
if [[ -f "$deployment_summary" ]]; then
  deployment_evidence_summary_sha256="$(sha256_value "$deployment_summary")"
  deployment_evidence_schema_major="$(jq -r 'if (.schema.major | type) == "number" then (.schema.major | tostring) else "" end' "$deployment_summary" 2>/dev/null || true)"
  deployment_evidence_schema_minor="$(jq -r 'if (.schema.minor | type) == "number" then (.schema.minor | tostring) else "" end' "$deployment_summary" 2>/dev/null || true)"
  deployment_evidence_smoke_summary_sha256="$(json_string_or_empty "$deployment_summary" '.smoke.summary_sha256')"
  deployment_evidence_binding_smoke_summary_sha256="$(json_string_or_empty "$deployment_summary" '.evidence_binding.smoke_summary_sha256')"
fi
if [[ -f "$host_summary" ]]; then
  host_install_check_summary_sha256="$(sha256_value "$host_summary")"
fi
if [[ "$real_helper_https_pilot_handoff" == "1" ]]; then
  if [[ "$deployment_evidence_schema_major" != "1" || -z "$deployment_evidence_schema_minor" || "$deployment_evidence_schema_minor" -lt 6 ]]; then
    evidence_binding_status="fail"
    evidence_binding_reason="real helper HTTPS pilot handoff requires deployment evidence schema >= 1.6"
  elif [[ -z "$deployment_evidence_smoke_summary_sha256" || -z "$deployment_evidence_binding_smoke_summary_sha256" ]]; then
    evidence_binding_status="fail"
    evidence_binding_reason="real helper HTTPS pilot handoff requires deployment evidence embedded smoke summary hashes"
  fi
fi
if [[ "$evidence_binding_status" == "pass" && -n "$smoke_summary_sha256" ]]; then
  if [[ -n "$deployment_evidence_smoke_summary_sha256" && "$deployment_evidence_smoke_summary_sha256" != "$smoke_summary_sha256" ]]; then
    evidence_binding_status="fail"
    evidence_binding_reason="deployment evidence smoke summary hash does not match bundle smoke summary"
  elif [[ -n "$deployment_evidence_binding_smoke_summary_sha256" && "$deployment_evidence_binding_smoke_summary_sha256" != "$smoke_summary_sha256" ]]; then
    evidence_binding_status="fail"
    evidence_binding_reason="deployment evidence binding smoke summary hash does not match bundle smoke summary"
  fi
fi

raw_steps_json="$(jq -s '.' "$steps_jsonl")"
if [[ "$evidence_binding_status" == "fail" ]]; then
  steps_json="$(printf '%s' "$raw_steps_json" | jq --arg reason "$evidence_binding_reason" '
    map(
      if .id == "deployment_evidence" then
        . + {
          status: "fail",
          rc: (if ((.rc | type) == "number" and .rc != 0) then .rc else 1 end),
          evidence_binding_status: "fail",
          evidence_binding_reason: $reason
        }
      else .
      end
    )
  ')"
else
  steps_json="$raw_steps_json"
fi
fail_count="$(printf '%s' "$steps_json" | jq '[.[] | select(.status != "pass" or .rc != 0)] | length')"
transport_status="$(json_string_or_empty "$deployment_summary" '.transport.status')"
transport_https="$(jq -r 'if (.transport.https // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_tls_verified="$(jq -r 'if (.transport.tls_verified // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_ssl_verify_result="$(json_string_or_empty "$deployment_summary" '.transport.ssl_verify_result')"
transport_mtls_required="$(jq -r 'if (.transport.mtls_required // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_mtls_client_configured="$(jq -r 'if (.transport.mtls_client_certificate_configured // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_mtls_client_used="$(jq -r 'if (.transport.mtls_client_certificate_used // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_mtls_local_client_key_match="$(jq -r 'if (.transport.mtls_local_client_certificate_key_match // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_mtls_client_auth_eku="$(jq -r 'if (.transport.mtls_client_certificate_client_auth_eku // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_mtls_server_leaf_fetched="$(jq -r 'if (.transport.mtls_server_leaf_certificate_fetched // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_mtls_client_cert_der_sha256="$(json_string_or_empty "$deployment_summary" '.transport.mtls_client_certificate_der_sha256')"
transport_mtls_client_cert_public_key_sha256="$(json_string_or_empty "$deployment_summary" '.transport.mtls_client_certificate_public_key_sha256')"
transport_mtls_client_key_public_key_sha256="$(json_string_or_empty "$deployment_summary" '.transport.mtls_client_key_public_key_sha256')"
transport_mtls_server_leaf_der_sha256="$(json_string_or_empty "$deployment_summary" '.transport.mtls_server_leaf_certificate_der_sha256')"
transport_mtls_server_leaf_public_key_sha256="$(json_string_or_empty "$deployment_summary" '.transport.mtls_server_leaf_public_key_sha256')"
transport_mtls_client_der_distinct="$(jq -r 'if (.transport.mtls_client_certificate_der_fingerprint_distinct_from_server_leaf // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_mtls_client_pubkey_distinct="$(jq -r 'if (.transport.mtls_client_certificate_public_key_fingerprint_distinct_from_server_leaf // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_mtls_missing_client_rejected="$(jq -r 'if (.transport.mtls_missing_client_certificate_rejected // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_mtls_missing_client_same_endpoint="$(jq -r 'if (.transport.mtls_missing_client_certificate_same_endpoint // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_mtls_missing_client_rejection_signal="$(jq -r 'if (.transport.mtls_missing_client_certificate_rejection_signal // false) == true then "true" else "false" end' "$deployment_summary" 2>/dev/null || true)"
transport_mtls_missing_client_http="$(json_string_or_empty "$deployment_summary" '.transport.mtls_missing_client_certificate_health_http_status')"
transport_mtls_missing_client_rc="$(json_string_or_empty "$deployment_summary" '.transport.mtls_missing_client_certificate_health_curl_rc')"
transport_mtls_missing_client_error="$(json_string_or_empty "$deployment_summary" '.transport.mtls_missing_client_certificate_health_curl_error')"
transport_mtls_missing_client_effective_url="$(json_string_or_empty "$deployment_summary" '.transport.mtls_missing_client_certificate_health_effective_url')"
transport_mtls_missing_client_remote_ip="$(json_string_or_empty "$deployment_summary" '.transport.mtls_missing_client_certificate_health_remote_ip')"
transport_mtls_missing_client_remote_port="$(json_string_or_empty "$deployment_summary" '.transport.mtls_missing_client_certificate_health_remote_port')"
status="pass"
recommended_action_id="trusted_pilot_evidence_verify"
recommended_action="Run trusted bundle verification with --require-trusted-provenance 1 and --verification-summary-json before helper/operator handoff."
if [[ "$fail_count" != "0" ]]; then
  status="fail"
  first_failed_step="$(printf '%s' "$steps_json" | jq -r '[.[] | select(.status != "pass" or .rc != 0)][0].id // ""')"
  case "$first_failed_step" in
    service_smoke)
      recommended_action_id="fix_deployed_bridge_smoke"
      recommended_action="Fix the deployed bridge smoke failure, then rerun the pilot evidence bundle."
      ;;
    deployment_evidence)
      recommended_action_id="fix_access_bridge_deployment_evidence"
      recommended_action="Fix the deployment evidence mismatch or stale smoke result, then rerun the pilot evidence bundle."
      ;;
    host_install_check)
      recommended_action_id="fix_access_bridge_host_install"
      recommended_action="Fix the helper-host install checks, then rerun the pilot evidence bundle."
      ;;
    *)
      recommended_action_id="rerun_access_bridge_pilot_evidence_bundle"
      recommended_action="Inspect the bundle logs, fix the failed step, then rerun the pilot evidence bundle."
      ;;
  esac
fi

base_url_host="$(url_host "$base_url")"
base_url_display="$(redact_url_userinfo "$base_url")"
base_url_loopback="0"
if base_url_is_loopback "$base_url"; then
  base_url_loopback="1"
fi
base_url_private_or_reserved="0"
if base_url_host_is_private_or_reserved "$base_url"; then
  base_url_private_or_reserved="1"
fi
evidence_scope="incomplete"
if [[ "$status" == "pass" ]]; then
  if [[ "$base_url_loopback" == "1" ]]; then
    evidence_scope="local_rehearsal"
  elif [[ "$require_https" == "1" && "$require_public_host" == "1" ]]; then
    evidence_scope="real_helper_https"
  else
    evidence_scope="diagnostic"
  fi
fi
if [[ "$status" == "pass" && "$evidence_scope" == "real_helper_https" && "$provenance_sign" != "1" ]]; then
  recommended_action_id="sign_and_verify_access_bridge_pilot_evidence"
  recommended_action="Sign this real helper HTTPS bundle with provenance, then verify it with --require-trusted-provenance 1 and --verification-summary-json before operator handoff."
elif [[ "$status" == "pass" && "$evidence_scope" == "real_helper_https" && "$provenance_sign" == "1" ]]; then
  recommended_action_id="trusted_pilot_evidence_verify"
  recommended_action="Verify this signed real helper HTTPS bundle with --require-trusted-provenance 1 and --verification-summary-json before operator handoff."
elif [[ "$status" == "pass" && "$evidence_scope" != "real_helper_https" ]]; then
  recommended_action_id="capture_real_helper_https_evidence"
  recommended_action="Capture the same bundle against a public HTTPS helper host before operator handoff."
fi

bundle_tar="${bundle_dir}.tar.gz"
bundle_tar_sha256_file="${bundle_tar}.sha256"
manifest_sha256="$bundle_dir/manifest.sha256"
bundled_summary_json="$bundle_dir/access_bridge_pilot_evidence_bundle_summary.json"
if [[ "$provenance_sign" == "1" ]]; then
  if [[ -z "$provenance_out" ]]; then
    provenance_out="${bundle_tar}.provenance.json"
  else
    provenance_out="$(abs_path "$provenance_out")"
  fi
  if path_is_inside_dir "$provenance_out" "$bundle_dir"; then
    echo "access bridge pilot evidence bundle failed: --provenance-out must be outside the bundle directory so it is not included in the tar or manifest" >&2
    exit 2
  fi
  mkdir -p "$(dirname "$provenance_out")"
fi

cat >"$report_md" <<REPORT
# Access Bridge Pilot Evidence Bundle

- Status: ${status}
- Evidence scope: ${evidence_scope}
- Base URL: ${base_url_display}
- Path ID: ${path_id}
- Service name: ${service_name}
- Smoke summary: ${smoke_summary}
- Deployment evidence summary: ${deployment_summary}
- Host install summary: ${host_summary}
- Smoke summary SHA-256: ${smoke_summary_sha256}
- Deployment evidence summary SHA-256: ${deployment_evidence_summary_sha256}
- Host install summary SHA-256: ${host_install_check_summary_sha256}
- Deployment embedded smoke SHA-256: ${deployment_evidence_smoke_summary_sha256}

Next action: ${recommended_action}
REPORT

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --arg evidence_scope "$evidence_scope" \
  --arg bundle_dir "$bundle_dir" \
  --arg bundle_tar "$bundle_tar" \
  --arg bundle_tar_sha256_file "$bundle_tar_sha256_file" \
  --arg manifest_sha256 "$manifest_sha256" \
  --arg summary_json "$summary_json" \
  --arg bundled_summary_json "$bundled_summary_json" \
  --arg report_md "$report_md" \
  --arg base_url "$base_url_display" \
  --arg base_url_host "$base_url_host" \
  --arg base_url_loopback "$base_url_loopback" \
  --arg base_url_private_or_reserved "$base_url_private_or_reserved" \
  --arg require_https "$require_https" \
  --arg require_public_host "$require_public_host" \
  --arg require_mtls "$require_mtls" \
  --arg expected_public_host "$expected_public_host" \
  --arg transport_status "$transport_status" \
  --arg transport_https "$transport_https" \
  --arg transport_tls_verified "$transport_tls_verified" \
  --arg transport_ssl_verify_result "$transport_ssl_verify_result" \
  --arg transport_mtls_required "$transport_mtls_required" \
  --arg transport_mtls_client_configured "$transport_mtls_client_configured" \
  --arg transport_mtls_client_used "$transport_mtls_client_used" \
  --arg transport_mtls_local_client_key_match "$transport_mtls_local_client_key_match" \
  --arg transport_mtls_client_auth_eku "$transport_mtls_client_auth_eku" \
  --arg transport_mtls_server_leaf_fetched "$transport_mtls_server_leaf_fetched" \
  --arg transport_mtls_client_cert_der_sha256 "$transport_mtls_client_cert_der_sha256" \
  --arg transport_mtls_client_cert_public_key_sha256 "$transport_mtls_client_cert_public_key_sha256" \
  --arg transport_mtls_client_key_public_key_sha256 "$transport_mtls_client_key_public_key_sha256" \
  --arg transport_mtls_server_leaf_der_sha256 "$transport_mtls_server_leaf_der_sha256" \
  --arg transport_mtls_server_leaf_public_key_sha256 "$transport_mtls_server_leaf_public_key_sha256" \
  --arg transport_mtls_client_der_distinct "$transport_mtls_client_der_distinct" \
  --arg transport_mtls_client_pubkey_distinct "$transport_mtls_client_pubkey_distinct" \
  --arg transport_mtls_missing_client_rejected "$transport_mtls_missing_client_rejected" \
  --arg transport_mtls_missing_client_same_endpoint "$transport_mtls_missing_client_same_endpoint" \
  --arg transport_mtls_missing_client_rejection_signal "$transport_mtls_missing_client_rejection_signal" \
  --arg transport_mtls_missing_client_http "$transport_mtls_missing_client_http" \
  --arg transport_mtls_missing_client_rc "$transport_mtls_missing_client_rc" \
  --arg transport_mtls_missing_client_error "$transport_mtls_missing_client_error" \
  --arg transport_mtls_missing_client_effective_url "$transport_mtls_missing_client_effective_url" \
  --arg transport_mtls_missing_client_remote_ip "$transport_mtls_missing_client_remote_ip" \
  --arg transport_mtls_missing_client_remote_port "$transport_mtls_missing_client_remote_port" \
  --arg path_id "$path_id" \
  --arg service_name "$service_name" \
  --arg host_install_evidence_mode "$host_install_evidence_mode" \
  --arg install_dir "$install_dir" \
  --arg systemd_unit_file "$systemd_unit_file" \
  --arg proxy_kind "$proxy_kind" \
  --arg proxy_config_file "$proxy_config_file" \
  --arg config_json "$config_json" \
  --arg deploy_pack_dir "$deploy_pack_dir" \
  --arg config_copy "$config_copy" \
  --arg deploy_pack_copy "$deploy_pack_copy" \
  --arg deploy_pack_skipped_secrets "$deploy_pack_skipped_secrets" \
  --arg code_source "$(if [[ -n "$code_file" ]]; then printf '%s' "code_file"; else printf '%s' "inline_code_transient_file"; fi)" \
  --arg expect_helper_id "$expect_helper_id" \
  --arg expect_org_id "$expect_org_id" \
  --arg expect_registry_id "$expect_registry_id" \
  --arg smoke_summary "$smoke_summary" \
  --arg smoke_summary_sha256 "$smoke_summary_sha256" \
  --arg smoke_log "$smoke_log" \
  --arg deployment_summary "$deployment_summary" \
  --arg deployment_evidence_summary_sha256 "$deployment_evidence_summary_sha256" \
  --arg deployment_log "$deployment_log" \
  --arg host_summary "$host_summary" \
  --arg host_install_check_summary_sha256 "$host_install_check_summary_sha256" \
  --arg host_log "$host_log" \
  --arg deployment_evidence_schema_major "$deployment_evidence_schema_major" \
  --arg deployment_evidence_schema_minor "$deployment_evidence_schema_minor" \
  --arg deployment_evidence_smoke_summary_sha256 "$deployment_evidence_smoke_summary_sha256" \
  --arg deployment_evidence_binding_smoke_summary_sha256 "$deployment_evidence_binding_smoke_summary_sha256" \
  --arg evidence_binding_status "$evidence_binding_status" \
  --arg evidence_binding_reason "$evidence_binding_reason" \
  --arg provenance_sign "$provenance_sign" \
  --arg provenance_out "$provenance_out" \
  --arg provenance_key_id "$provenance_key_id" \
  --arg provenance_lifetime_hours "$provenance_lifetime_hours" \
  --arg recommended_action_id "$recommended_action_id" \
  --arg recommended_action "$recommended_action" \
  --argjson fail_count "$fail_count" \
  --argjson steps "$steps_json" \
  '{
    version: 1,
    schema: {
      id: "access_bridge_pilot_evidence_bundle_summary",
      major: 1,
      minor: 8
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    evidence_scope: $evidence_scope,
    pilot_handoff_ready: false,
    trusted_verifier_receipt_required: true,
    notes: (
      if $status != "pass" then "Access bridge pilot evidence bundle needs operator action"
      elif $evidence_scope == "real_helper_https" and ($provenance_sign == "1") then "Access bridge pilot evidence bundle passed real helper HTTPS checks with signed provenance; trusted verifier receipt is required before operator handoff"
      elif $evidence_scope == "real_helper_https" then "Access bridge pilot evidence bundle passed real helper HTTPS checks; signed provenance and trusted verifier receipt are required before operator handoff"
      elif $evidence_scope == "local_rehearsal" then "Access bridge pilot evidence bundle passed as local rehearsal evidence; capture real helper HTTPS evidence before operator handoff"
      else "Access bridge pilot evidence bundle passed as diagnostic evidence; capture real helper HTTPS evidence before operator handoff"
      end
    ),
    evidence_policy: {
      require_https: ($require_https == "1"),
      require_public_host: ($require_public_host == "1"),
      require_tls_verified: true,
      require_mtls: ($require_mtls == "1"),
      base_url_host: $base_url_host,
      base_url_loopback: ($base_url_loopback == "1"),
      base_url_private_or_reserved: ($base_url_private_or_reserved == "1")
    },
    inputs: {
      base_url: $base_url,
      path_id: $path_id,
      service_name: $service_name,
      host_install_evidence_mode: $host_install_evidence_mode,
      install_dir: (if $install_dir == "" then null else $install_dir end),
      systemd_unit_file: (if $systemd_unit_file == "" then null else $systemd_unit_file end),
      proxy_kind: (if $proxy_kind == "" then null else $proxy_kind end),
      proxy_config_file: (if $proxy_config_file == "" then null else $proxy_config_file end),
      config_json: $config_json,
      deploy_pack_dir: $deploy_pack_dir,
      expected_public_host: (if $expected_public_host == "" then null else $expected_public_host end),
      code_source: $code_source,
      access_code_redacted: true
    },
    expected_identity: {
      helper_id: $expect_helper_id,
      organization_id: $expect_org_id,
      registry_id: $expect_registry_id
    },
    summary: {
      steps_total: ($steps | length),
      steps_fail: $fail_count
    },
    evidence_binding: {
      status: $evidence_binding_status,
      reason: (if $evidence_binding_reason == "" then null else $evidence_binding_reason end),
      base_url: $base_url,
      helper_id: $expect_helper_id,
      organization_id: $expect_org_id,
      registry_id: $expect_registry_id,
      smoke_summary_json: $smoke_summary,
      smoke_summary_sha256: $smoke_summary_sha256,
      deployment_evidence_summary_json: $deployment_summary,
      deployment_evidence_summary_sha256: $deployment_evidence_summary_sha256,
      host_install_check_summary_json: $host_summary,
      host_install_check_summary_sha256: $host_install_check_summary_sha256,
      deployment_evidence_schema_major: (if $deployment_evidence_schema_major == "" then null else ($deployment_evidence_schema_major | tonumber) end),
      deployment_evidence_schema_minor: (if $deployment_evidence_schema_minor == "" then null else ($deployment_evidence_schema_minor | tonumber) end),
      deployment_evidence_smoke_summary_sha256: $deployment_evidence_smoke_summary_sha256,
      deployment_smoke_summary_sha256: $deployment_evidence_smoke_summary_sha256,
      deployment_evidence_binding_smoke_summary_sha256: $deployment_evidence_binding_smoke_summary_sha256,
      deployment_smoke_summary_sha256_matches_bundle: (
        $smoke_summary_sha256 != ""
        and $deployment_evidence_smoke_summary_sha256 != ""
        and $deployment_evidence_binding_smoke_summary_sha256 != ""
        and $deployment_evidence_smoke_summary_sha256 == $smoke_summary_sha256
        and $deployment_evidence_binding_smoke_summary_sha256 == $smoke_summary_sha256
      )
    },
    transport: {
      status: $transport_status,
      https: ($transport_https == "true"),
      tls_verified: ($transport_tls_verified == "true"),
      ssl_verify_result: $transport_ssl_verify_result,
      mtls_required: ($transport_mtls_required == "true"),
      mtls_client_certificate_configured: ($transport_mtls_client_configured == "true"),
      mtls_client_certificate_used: ($transport_mtls_client_used == "true"),
      mtls_local_client_certificate_key_match: ($transport_mtls_local_client_key_match == "true"),
      mtls_client_certificate_client_auth_eku: ($transport_mtls_client_auth_eku == "true"),
      mtls_server_leaf_certificate_fetched: ($transport_mtls_server_leaf_fetched == "true"),
      mtls_client_certificate_der_sha256: $transport_mtls_client_cert_der_sha256,
      mtls_client_certificate_public_key_sha256: $transport_mtls_client_cert_public_key_sha256,
      mtls_client_key_public_key_sha256: $transport_mtls_client_key_public_key_sha256,
      mtls_server_leaf_certificate_der_sha256: $transport_mtls_server_leaf_der_sha256,
      mtls_server_leaf_public_key_sha256: $transport_mtls_server_leaf_public_key_sha256,
      mtls_client_certificate_der_fingerprint_distinct_from_server_leaf: ($transport_mtls_client_der_distinct == "true"),
      mtls_client_certificate_public_key_fingerprint_distinct_from_server_leaf: ($transport_mtls_client_pubkey_distinct == "true"),
      mtls_missing_client_certificate_rejected: ($transport_mtls_missing_client_rejected == "true"),
      mtls_missing_client_certificate_same_endpoint: ($transport_mtls_missing_client_same_endpoint == "true"),
      mtls_missing_client_certificate_rejection_signal: ($transport_mtls_missing_client_rejection_signal == "true"),
      mtls_missing_client_certificate_health_http_status: $transport_mtls_missing_client_http,
      mtls_missing_client_certificate_health_curl_rc: (if $transport_mtls_missing_client_rc == "" then null else ($transport_mtls_missing_client_rc | tonumber) end),
      mtls_missing_client_certificate_health_curl_error: $transport_mtls_missing_client_error,
      mtls_missing_client_certificate_health_effective_url: $transport_mtls_missing_client_effective_url,
      mtls_missing_client_certificate_health_remote_ip: $transport_mtls_missing_client_remote_ip,
      mtls_missing_client_certificate_health_remote_port: $transport_mtls_missing_client_remote_port,
      deployment_evidence_summary_json: $deployment_summary,
      smoke_summary_json: $smoke_summary
    },
    steps: $steps,
    artifacts: {
      bundle_dir: $bundle_dir,
      bundle_tar: $bundle_tar,
      bundle_tar_sha256_file: $bundle_tar_sha256_file,
      manifest_sha256: $manifest_sha256,
      summary_json: $summary_json,
      bundled_summary_json: $bundled_summary_json,
      report_md: $report_md,
      smoke_summary_json: $smoke_summary,
      smoke_log: $smoke_log,
      deployment_evidence_summary_json: $deployment_summary,
      deployment_evidence_log: $deployment_log,
      host_install_check_summary_json: $host_summary,
      host_install_check_log: $host_log,
      provenance_json: $provenance_out,
      config_copy: $config_copy,
      deploy_pack_copy: $deploy_pack_copy,
      deploy_pack_skipped_secrets: $deploy_pack_skipped_secrets
    },
    provenance: {
      enabled: ($provenance_sign == "1"),
      sidecar_json: $provenance_out,
      key_id: $provenance_key_id,
      lifetime_hours: (
        if $provenance_lifetime_hours == "" then null
        else ($provenance_lifetime_hours | tonumber)
        end
      )
    },
    recommended_next_action: {
      id: $recommended_action_id,
      command: $recommended_action
    }
  }' >"$summary_json"
if [[ "$summary_json" != "$bundled_summary_json" ]]; then
  cp "$summary_json" "$bundled_summary_json"
fi

: >"$manifest_sha256"
manifest_entries=0
while IFS= read -r rel_file; do
  [[ -n "$rel_file" ]] || continue
  write_sha256_line "$bundle_dir/$rel_file" "$rel_file" >>"$manifest_sha256"
  manifest_entries=$((manifest_entries + 1))
done < <(
  cd "$bundle_dir"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort
)

tar -czf "$bundle_tar" -C "$(dirname "$bundle_dir")" "$(basename "$bundle_dir")"
write_sha256_line "$bundle_tar" "$(basename "$bundle_tar")" >"$bundle_tar_sha256_file"
bundle_tar_sha256="$(sha256_value "$bundle_tar")"

if [[ "$provenance_sign" == "1" ]]; then
  provenance_args=(
    go run ./cmd/gpmrecover provenance-sign
    --summary-json "$summary_json"
    --bundle-tar "$bundle_tar"
    --bundle-tar-sha256-file "$bundle_tar_sha256_file"
    --private-key-file "$provenance_private_key_file"
    --org-id "$provenance_org_id"
    --org-name "$provenance_org_name"
    --out "$provenance_out"
  )
  if [[ -n "$provenance_key_id" ]]; then
    provenance_args+=(--key-id "$provenance_key_id")
  fi
  if [[ -n "$provenance_lifetime_hours" ]]; then
    provenance_args+=(--lifetime-hours "$provenance_lifetime_hours")
  fi
  "${provenance_args[@]}"
fi

echo "access-bridge-pilot-evidence-bundle: status=$status"
echo "bundle_dir: $bundle_dir"
echo "manifest_sha256: $manifest_sha256 entries=$manifest_entries"
echo "bundle_tar: $bundle_tar"
echo "bundle_tar_sha256_file: $bundle_tar_sha256_file"
echo "bundle_tar_sha256: $bundle_tar_sha256"
if [[ "$provenance_sign" == "1" ]]; then
  echo "provenance_json: $provenance_out"
fi
echo "summary_json: $summary_json"
echo "report_md: $report_md"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" != "pass" ]]; then
  exit 1
fi
