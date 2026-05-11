#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

base_url=""
path_id="helper-web"
code=""
code_file=""
abuse_message="deployment evidence smoke"
smoke_summary_json=""
config_json=""
deploy_pack_dir=""
service_name="gpm-access-bridge"
expect_helper_id=""
expect_org_id=""
expect_registry_id=""
summary_json=""
print_summary_json="1"
max_smoke_age_sec="${ACCESS_BRIDGE_DEPLOYMENT_EVIDENCE_MAX_SMOKE_AGE_SEC:-3600}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/access_bridge_deployment_evidence.sh \
    (--base-url URL | --smoke-summary-json FILE) \
    [--path-id helper-web] \
    [(--code CODE | --code-file FILE) when using --base-url] \
    [--expect-helper-id ID] \
    [--expect-org-id ID] \
    [--expect-registry-id ID] \
    [--config-json FILE] \
    [--deploy-pack-dir DIR] \
    [--service-name gpm-access-bridge] \
    [--summary-json FILE] \
    [--print-summary-json [0|1]]

Collects operator-facing JSON deployment evidence for the Access Recovery bridge service.
USAGE
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access bridge deployment evidence failed: missing required command: $cmd" >&2
    exit 2
  fi
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

is_sha256_hex() {
  [[ "${1:-}" =~ ^[A-Fa-f0-9]{64}$ ]]
}

has_bridge_deploy_config_meta() {
  local value="${1:-}"
  [[ "$value" == *" "* || "$value" == *$'\t'* || "$value" == *$'\n'* || "$value" == *$'\r'* ]] && return 0
  [[ "$value" == *"{"* || "$value" == *"}"* || "$value" == *";"* || "$value" == *"\""* ]] && return 0
  [[ "$value" == *"'"* || "$value" == *"\`"* || "$value" == *'$'* || "$value" == *"("* || "$value" == *")"* ]] && return 0
  [[ "$value" == *"<"* || "$value" == *">"* || "$value" == *"|"* || "$value" == *"&"* || "$value" == *"#"* ]] && return 0
  return 1
}

is_ipv4_addr() {
  local value="${1:-}"
  local a b c d extra
  IFS=. read -r a b c d extra <<<"$value"
  [[ -z "${extra:-}" && "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ ]] || return 1
  ((a >= 0 && a <= 255 && b >= 0 && b <= 255 && c >= 0 && c <= 255 && d >= 0 && d <= 255))
}

normalize_bridge_host() {
  local host="${1:-}"
  host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
  while [[ "$host" == *. ]]; do
    host="${host%.}"
  done
  printf '%s' "$host"
}

is_private_or_reserved_ipv4_addr() {
  local host="${1:-}"
  is_ipv4_addr "$host" || return 1
  if [[ "$host" == 0.* || "$host" == 10.* || "$host" == 127.* || "$host" == 169.254.* || "$host" == 192.168.* ]]; then
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

is_loopback_host() {
  local host
  host="$(normalize_bridge_host "${1:-}")"
  if [[ "$host" == "localhost" || "$host" == "::1" ]]; then
    return 0
  fi
  is_ipv4_addr "$host" && [[ "$host" == 127.* ]]
}

split_host_port() {
  local value="${1:-}"
  local __host_var="$2"
  local __port_var="$3"
  local parsed_host="" parsed_port=""
  if [[ "$value" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
    parsed_host="${BASH_REMATCH[1]}"
    parsed_port="${BASH_REMATCH[2]}"
  elif [[ "$value" =~ ^([^:]+):([0-9]+)$ ]]; then
    parsed_host="${BASH_REMATCH[1]}"
    parsed_port="${BASH_REMATCH[2]}"
  else
    return 1
  fi
  [[ -n "$parsed_host" && "$parsed_port" =~ ^[0-9]+$ ]] || return 1
  ((parsed_port >= 1 && parsed_port <= 65535)) || return 1
  printf -v "$__host_var" '%s' "$parsed_host"
  printf -v "$__port_var" '%s' "$parsed_port"
}

is_loopback_listen_addr() {
  local value="${1:-}"
  local host="" port=""
  has_bridge_deploy_config_meta "$value" && return 1
  split_host_port "$value" host port || return 1
  is_loopback_host "$host"
}

is_bridge_public_host() {
  local raw="${1:-}"
  local host
  local label i ch
  local -a labels
  [[ "$raw" != *. ]] || return 1
  host="$(normalize_bridge_host "$raw")"
  [[ -n "$host" && ${#host} -le 253 ]] || return 1
  [[ "$host" != *"://"* && "$host" != *":"* && "$host" != *"/"* && "$host" != *"\\"* && "$host" != *@* ]] || return 1
  has_bridge_deploy_config_meta "$host" && return 1
  if is_ipv4_addr "$host"; then
    ! is_private_or_reserved_ipv4_addr "$host"
    return $?
  fi
  [[ "$host" == "localhost" || "$host" == *.localhost ]] && return 1
  [[ "$host" =~ (^|\.)(local|lan|internal|test|invalid|example)$ ]] && return 1
  [[ "$host" =~ (^|\.)example\.(com|net|org)$ ]] && return 1
  [[ "$host" == ts.net || "$host" == *.ts.net || "$host" == tailscale.net || "$host" == *.tailscale.net ]] && return 1
  IFS=. read -ra labels <<<"$host"
  ((${#labels[@]} >= 2)) || return 1
  for label in "${labels[@]}"; do
    [[ -n "$label" && ${#label} -le 63 ]] || return 1
    [[ "$label" != -* && "$label" != *- ]] || return 1
    for ((i = 0; i < ${#label}; i++)); do
      ch="${label:i:1}"
      [[ "$ch" =~ [A-Za-z0-9-] ]] || return 1
    done
  done
}

host_from_url() {
  local url="${1:-}"
  jq -nr --arg url "$url" '
    $url
    | sub("^https?://"; "")
    | split("/")[0]
    | sub(":[0-9]+$"; "")
    | sub("^\\["; "")
    | sub("\\]$"; "")
    | ascii_downcase
  ' 2>/dev/null || true
}

extract_caddy_site_host() {
  local file="$1"
  sed -nE 's/^[[:space:]]*([^[:space:]{}#]+)[[:space:]]*\{[[:space:]]*$/\1/p' "$file" 2>/dev/null | head -n 1
}

extract_caddy_reverse_proxy() {
  local file="$1"
  sed -nE 's/^[[:space:]]*reverse_proxy[[:space:]]+([^[:space:]{}#]+).*/\1/p' "$file" 2>/dev/null | head -n 1
}

extract_nginx_server_name() {
  local file="$1"
  sed -nE 's/^[[:space:]]*server_name[[:space:]]+([^[:space:];]+);.*/\1/p' "$file" 2>/dev/null | head -n 1
}

extract_nginx_proxy_pass() {
  local file="$1"
  sed -nE 's#^[[:space:]]*proxy_pass[[:space:]]+http://([^[:space:];]+);.*#\1#p' "$file" 2>/dev/null | head -n 1
}

smoke_age_seconds() {
  local generated_at="$1"
  local now
  now="$(timestamp_utc)"
  jq -nr --arg generated_at "$generated_at" --arg now "$now" '
    try (($now | fromdateiso8601) - ($generated_at | fromdateiso8601) | floor) catch empty
  '
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

json_string_or_empty() {
  local file="$1"
  local filter="$2"
  jq -r "$filter // \"\"" "$file" 2>/dev/null || true
}

sanitize_systemd_name() {
  local raw="${1:-}"
  local out=""
  local i ch
  for ((i = 0; i < ${#raw}; i++)); do
    ch="${raw:i:1}"
    if [[ "$ch" =~ [A-Za-z0-9._-] ]]; then
      out+="$ch"
    fi
  done
  if [[ -z "$out" ]]; then
    out="gpm-access-bridge"
  fi
  printf '%s' "$out"
}

file_sha256() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    printf '%s' ""
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print $NF}'
  else
    printf '%s' ""
  fi
}

env_file_value() {
  local file="$1"
  local key="$2"
  local line value
  line="$(grep -E "^${key}=" "$file" 2>/dev/null | tail -n 1 || true)"
  value="${line#*=}"
  value="${value%\"}"
  value="${value#\"}"
  printf '%s' "$value"
}

append_reason() {
  local existing="$1"
  local addition="$2"
  if [[ -z "$existing" ]]; then
    printf '%s' "$addition"
  else
    printf '%s; %s' "$existing" "$addition"
  fi
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
    --abuse-message)
      abuse_message="${2:-}"
      shift 2
      ;;
    --smoke-summary-json)
      smoke_summary_json="${2:-}"
      shift 2
      ;;
    --config-json|--config)
      config_json="${2:-}"
      shift 2
      ;;
    --deploy-pack-dir)
      deploy_pack_dir="${2:-}"
      shift 2
      ;;
    --service-name)
      service_name="${2:-}"
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

for cmd in bash date jq mktemp; do
  need_cmd "$cmd"
done
bool_arg_or_die "--print-summary-json" "$print_summary_json"
if [[ ! "$max_smoke_age_sec" =~ ^[0-9]+$ ]]; then
  echo "ACCESS_BRIDGE_DEPLOYMENT_EVIDENCE_MAX_SMOKE_AGE_SEC must be a non-negative integer" >&2
  exit 2
fi

base_url="${base_url%/}"
path_id="$(trim "$path_id")"
if [[ -z "$path_id" ]]; then
  echo "access bridge deployment evidence failed: --path-id is required" >&2
  exit 2
fi
if [[ -n "$base_url" && -n "$smoke_summary_json" ]]; then
  echo "access bridge deployment evidence failed: use only one of --base-url or --smoke-summary-json" >&2
  exit 2
fi
if [[ -z "$base_url" && -z "$smoke_summary_json" ]]; then
  echo "access bridge deployment evidence failed: --base-url or --smoke-summary-json is required" >&2
  exit 2
fi
if [[ -n "$code" && -n "$code_file" ]]; then
  echo "access bridge deployment evidence failed: use either --code or --code-file, not both" >&2
  exit 2
fi
if [[ -n "$code_file" ]]; then
  code_file="$(abs_path "$code_file")"
  if [[ ! -f "$code_file" ]]; then
    echo "access bridge deployment evidence failed: code file not found: $code_file" >&2
    exit 2
  fi
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

if [[ -z "$summary_json" ]]; then
  summary_json="$ROOT_DIR/.easy-node-logs/access_bridge_deployment_evidence_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

if [[ -n "$smoke_summary_json" ]]; then
  smoke_summary_json="$(abs_path "$smoke_summary_json")"
  if [[ ! -f "$smoke_summary_json" ]]; then
    echo "access bridge deployment evidence failed: smoke summary not found: $smoke_summary_json" >&2
    exit 2
  fi
else
  need_cmd curl
  smoke_summary_json="$tmp_dir/access_bridge_service_smoke_summary.json"
  smoke_args=(
    ./scripts/access_bridge_service_smoke.sh
    --base-url "$base_url"
    --path-id "$path_id"
    --summary-json "$smoke_summary_json"
    --abuse-message "$abuse_message"
  )
  if [[ -n "$code" ]]; then
    smoke_args+=(--code "$code")
  fi
  if [[ -n "$code_file" ]]; then
    smoke_args+=(--code-file "$code_file")
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
  set +e
  bash "${smoke_args[@]}" >"$tmp_dir/access_bridge_service_smoke.stdout.json" 2>"$tmp_dir/access_bridge_service_smoke.stderr.log"
  smoke_rc=$?
  set -e
  if [[ ! -f "$smoke_summary_json" ]]; then
    jq -n \
      --arg status "fail" \
      --arg notes "bridge service smoke did not produce a summary" \
      --arg base_url "$base_url" \
      --arg path_id "$path_id" \
      --arg stderr "$(cat "$tmp_dir/access_bridge_service_smoke.stderr.log")" \
      --argjson rc "$smoke_rc" \
      '{version:1,status:$status,notes:$notes,base_url:$base_url,path_id:$path_id,rc:$rc,stderr:$stderr}' >"$smoke_summary_json"
  fi
fi

smoke_status="$(json_string_or_empty "$smoke_summary_json" '.status')"
smoke_notes="$(json_string_or_empty "$smoke_summary_json" '.notes')"
smoke_schema_id="$(json_string_or_empty "$smoke_summary_json" '.schema.id')"
smoke_generated_at_utc="$(json_string_or_empty "$smoke_summary_json" '.generated_at_utc')"
smoke_age_sec="$(smoke_age_seconds "$smoke_generated_at_utc")"
smoke_auth_required="$(jq -r '.auth.required // false' "$smoke_summary_json" 2>/dev/null || true)"
smoke_missing_code_http="$(json_string_or_empty "$smoke_summary_json" '.auth.missing_code_http_status')"
smoke_wrong_code_http="$(json_string_or_empty "$smoke_summary_json" '.auth.wrong_code_http_status')"
smoke_valid_code_http="$(json_string_or_empty "$smoke_summary_json" '.auth.valid_code_http_status')"
smoke_bridge_http_status="$(json_string_or_empty "$smoke_summary_json" '.bridge.http_status')"
smoke_bridge_status="$(json_string_or_empty "$smoke_summary_json" '.bridge.status')"
smoke_bridge_security_headers_ok="$(jq -r 'if (.bridge.security_headers_ok // false) == true then "true" else "false" end' "$smoke_summary_json" 2>/dev/null || true)"
smoke_base_url="$(json_string_or_empty "$smoke_summary_json" '.base_url')"
smoke_base_host="$(host_from_url "$smoke_base_url")"
smoke_transport_scheme="$(json_string_or_empty "$smoke_summary_json" '.transport.base_url_scheme')"
smoke_transport_https="$(jq -r 'if (.transport.https // false) == true then "true" else "false" end' "$smoke_summary_json" 2>/dev/null || true)"
smoke_transport_loopback="$(jq -r 'if (.transport.loopback // false) == true then "true" else "false" end' "$smoke_summary_json" 2>/dev/null || true)"
smoke_transport_tls_checked="$(jq -r 'if (.transport.tls.checked // false) == true then "true" else "false" end' "$smoke_summary_json" 2>/dev/null || true)"
smoke_transport_tls_verified="$(jq -r 'if (.transport.tls.verified // false) == true then "true" else "false" end' "$smoke_summary_json" 2>/dev/null || true)"
smoke_transport_ssl_verify_result="$(json_string_or_empty "$smoke_summary_json" '.transport.tls.ssl_verify_result')"
smoke_transport_effective_url="$(json_string_or_empty "$smoke_summary_json" '.transport.health.effective_url')"
smoke_transport_remote_ip="$(json_string_or_empty "$smoke_summary_json" '.transport.health.remote_ip')"
smoke_transport_remote_port="$(json_string_or_empty "$smoke_summary_json" '.transport.health.remote_port')"
smoke_transport_http_version="$(json_string_or_empty "$smoke_summary_json" '.transport.health.http_version')"
smoke_transport_time_appconnect="$(json_string_or_empty "$smoke_summary_json" '.transport.health.time_appconnect_sec')"
smoke_transport_mtls_client_used="$(jq -r 'if (.transport.mtls.client_certificate_used // false) == true then "true" else "false" end' "$smoke_summary_json" 2>/dev/null || true)"
smoke_base_host_requires_proxy_match="false"
if [[ -n "$smoke_base_host" ]] && ! is_loopback_host "$smoke_base_host"; then
  smoke_base_host_requires_proxy_match="true"
fi
evidence_scope="local_rehearsal"
if [[ "$smoke_base_url" == https://* ]] && is_bridge_public_host "$smoke_base_host"; then
  evidence_scope="real_helper_https"
fi
transport_status="pass"
transport_reason=""
if [[ "$evidence_scope" == "real_helper_https" ]]; then
  if [[ "$smoke_transport_scheme" != "https" || "$smoke_transport_https" != "true" ]]; then
    transport_status="fail"
    transport_reason="$(append_reason "$transport_reason" "smoke summary did not prove HTTPS transport")"
  fi
  if [[ "$smoke_transport_tls_checked" != "true" || "$smoke_transport_tls_verified" != "true" || "$smoke_transport_ssl_verify_result" != "0" ]]; then
    transport_status="fail"
    transport_reason="$(append_reason "$transport_reason" "smoke summary did not prove verified TLS")"
  fi
fi
smoke_path_id="$(json_string_or_empty "$smoke_summary_json" '.path_id')"
actual_helper_id="$(json_string_or_empty "$smoke_summary_json" '.health.helper_id')"
actual_org_id="$(json_string_or_empty "$smoke_summary_json" '.health.organization_id')"
actual_registry_id="$(json_string_or_empty "$smoke_summary_json" '.health.registry_id')"
smoke_config_sha256="$(json_string_or_empty "$smoke_summary_json" '.health.config_sha256')"

smoke_evidence_status="pass"
smoke_evidence_reason=""
if [[ "$smoke_schema_id" != "access_bridge_service_smoke_summary" ]]; then
  smoke_evidence_status="fail"
  smoke_evidence_reason="$(append_reason "$smoke_evidence_reason" "smoke summary schema id missing or invalid")"
fi
if [[ -z "$smoke_age_sec" ]]; then
  smoke_evidence_status="fail"
  smoke_evidence_reason="$(append_reason "$smoke_evidence_reason" "smoke summary generated_at_utc missing or invalid")"
elif ((smoke_age_sec < -300)); then
  smoke_evidence_status="fail"
  smoke_evidence_reason="$(append_reason "$smoke_evidence_reason" "smoke summary generated_at_utc is in the future")"
elif ((smoke_age_sec > max_smoke_age_sec)); then
  smoke_evidence_status="fail"
  smoke_evidence_reason="$(append_reason "$smoke_evidence_reason" "smoke summary is stale")"
fi
if [[ "$smoke_auth_required" != "true" ]]; then
  smoke_evidence_status="fail"
  smoke_evidence_reason="$(append_reason "$smoke_evidence_reason" "smoke summary did not require access-code auth")"
elif [[ "$smoke_missing_code_http" != "401" || "$smoke_wrong_code_http" != "401" ]]; then
  smoke_evidence_status="fail"
  smoke_evidence_reason="$(append_reason "$smoke_evidence_reason" "smoke summary did not prove missing/wrong access-code rejection")"
elif [[ "$smoke_valid_code_http" != "200" ]]; then
  smoke_evidence_status="fail"
  smoke_evidence_reason="$(append_reason "$smoke_evidence_reason" "smoke summary did not prove valid access-code acceptance")"
fi
if [[ "$smoke_bridge_status" != "ok" || "$smoke_bridge_http_status" != "200" ]]; then
  smoke_evidence_status="fail"
  smoke_evidence_reason="$(append_reason "$smoke_evidence_reason" "smoke summary did not prove bridge health is ok over HTTP 200")"
fi
if [[ "$smoke_bridge_security_headers_ok" != "true" ]]; then
  smoke_evidence_status="fail"
  smoke_evidence_reason="$(append_reason "$smoke_evidence_reason" "smoke summary did not prove bridge security headers")"
fi
if ! { is_ipv4_addr "$smoke_base_host" && is_loopback_host "$smoke_base_host"; } && ! is_bridge_public_host "$smoke_base_host"; then
  smoke_evidence_status="fail"
  smoke_evidence_reason="$(append_reason "$smoke_evidence_reason" "smoke summary base_url host must be a safe public helper host")"
fi

config_status="skip"
config_exists="false"
config_valid="false"
config_helper_id=""
config_org_id=""
config_registry_id=""
config_sha256=""
config_allow_local_access_paths="false"
config_reason="not supplied"
if [[ -n "$config_json" ]]; then
  config_json="$(abs_path "$config_json")"
  config_status="pass"
  config_reason=""
  if [[ -f "$config_json" ]]; then
    config_exists="true"
    config_sha256="$(file_sha256 "$config_json")"
    if [[ -z "$config_sha256" ]]; then
      config_status="fail"
      config_reason="unable to compute config sha256"
    fi
    if jq -e . "$config_json" >/dev/null 2>&1; then
      config_valid="true"
      config_helper_id="$(json_string_or_empty "$config_json" '.helper_id')"
      config_org_id="$(json_string_or_empty "$config_json" '.organization_id')"
      config_registry_id="$(json_string_or_empty "$config_json" '.registry_id')"
      config_allow_local_access_paths="$(jq -r 'if has("allow_local_access_paths") then (.allow_local_access_paths | tostring) else "false" end' "$config_json")"
      if [[ -z "$expect_helper_id" ]]; then
        expect_helper_id="$config_helper_id"
      fi
      if [[ -z "$expect_org_id" ]]; then
        expect_org_id="$config_org_id"
      fi
      if [[ -z "$expect_registry_id" ]]; then
        expect_registry_id="$config_registry_id"
      fi
      if [[ -n "$expect_helper_id" && "$config_helper_id" != "$expect_helper_id" ]]; then
        config_status="fail"
        config_reason="config helper id mismatch"
      elif [[ -n "$expect_org_id" && "$config_org_id" != "$expect_org_id" ]]; then
        config_status="fail"
        config_reason="config organization id mismatch"
      elif [[ -n "$expect_registry_id" && "$config_registry_id" != "$expect_registry_id" ]]; then
        config_status="fail"
        config_reason="config registry id mismatch"
      elif [[ "$config_allow_local_access_paths" == "true" ]]; then
        config_status="fail"
        config_reason="config enables local diagnostic access paths"
      fi
    else
      config_status="fail"
      config_reason="config json is invalid"
    fi
  else
    config_status="fail"
    config_reason="config json is missing"
  fi
fi
if [[ "$config_status" == "pass" ]]; then
  if [[ -z "$smoke_config_sha256" ]]; then
    smoke_evidence_status="fail"
    smoke_evidence_reason="$(append_reason "$smoke_evidence_reason" "smoke summary did not include live config sha256")"
  elif [[ "$smoke_config_sha256" != "$config_sha256" ]]; then
    smoke_evidence_status="fail"
    smoke_evidence_reason="$(append_reason "$smoke_evidence_reason" "live config sha256 does not match supplied config")"
  fi
fi

identity_status="pass"
identity_reason=""
if [[ -n "$smoke_path_id" && "$smoke_path_id" != "$path_id" ]]; then
  identity_status="fail"
  identity_reason="smoke path id mismatch"
elif [[ -n "$expect_helper_id" && "$actual_helper_id" != "$expect_helper_id" ]]; then
  identity_status="fail"
  identity_reason="helper id mismatch"
elif [[ -n "$expect_org_id" && "$actual_org_id" != "$expect_org_id" ]]; then
  identity_status="fail"
  identity_reason="organization id mismatch"
elif [[ -n "$expect_registry_id" && "$actual_registry_id" != "$expect_registry_id" ]]; then
  identity_status="fail"
  identity_reason="registry id mismatch"
fi

deploy_status="skip"
deploy_exists="false"
deploy_reason="not supplied"
deploy_files_json='[]'
deploy_env_config_sha256=""
deploy_env_access_code_sha256=""
deploy_env_allow_unauth_local=""
deploy_env_allow_query_code=""
deploy_env_trust_proxy_headers=""
deploy_env_addr=""
deploy_caddy_site_host=""
deploy_caddy_reverse_proxy=""
deploy_nginx_server_name=""
deploy_nginx_proxy_pass=""
if [[ -n "$deploy_pack_dir" ]]; then
  deploy_pack_dir="$(abs_path "$deploy_pack_dir")"
  deploy_status="pass"
  deploy_reason=""
  service_name="$(sanitize_systemd_name "$service_name")"
  if [[ -d "$deploy_pack_dir" ]]; then
    deploy_exists="true"
  else
    deploy_status="fail"
    deploy_reason="deploy pack dir is missing"
  fi
  required_files=(
    "${service_name}.env"
    "run-${service_name}.sh"
    "${service_name}.service"
    "${service_name}.Caddyfile.example"
    "${service_name}.nginx.example.conf"
    "README.md"
  )
  deploy_jsonl="$tmp_dir/deploy_files.jsonl"
  : >"$deploy_jsonl"
  missing_files=0
  for rel in "${required_files[@]}"; do
    file_path="$deploy_pack_dir/$rel"
    exists=false
    sha256=""
    if [[ -f "$file_path" ]]; then
      exists=true
      sha256="$(file_sha256 "$file_path")"
      if [[ -z "$sha256" ]]; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "unable to compute deploy file sha256")"
      fi
    else
      missing_files=$((missing_files + 1))
    fi
    jq -nc --arg path "$file_path" --arg rel "$rel" --arg sha256 "$sha256" --argjson exists "$exists" \
      '{relative_path:$rel,path:$path,exists:$exists,sha256:$sha256}' >>"$deploy_jsonl"
  done
  deploy_files_json="$(jq -s '.' "$deploy_jsonl")"
  if ((missing_files > 0)); then
    deploy_status="fail"
    deploy_reason="$(append_reason "$deploy_reason" "deploy pack is missing required files")"
  fi
  if [[ "$deploy_exists" == "true" ]]; then
    env_file="$deploy_pack_dir/${service_name}.env"
    wrapper_file="$deploy_pack_dir/run-${service_name}.sh"
    unit_file="$deploy_pack_dir/${service_name}.service"
    caddy_file="$deploy_pack_dir/${service_name}.Caddyfile.example"
    nginx_file="$deploy_pack_dir/${service_name}.nginx.example.conf"
    if [[ -f "$env_file" ]]; then
      deploy_env_config_sha256="$(env_file_value "$env_file" "GPM_BRIDGE_CONFIG_SHA256")"
      deploy_env_access_code_sha256="$(env_file_value "$env_file" "GPM_BRIDGE_ACCESS_CODE_SHA256")"
      deploy_env_allow_unauth_local="$(env_file_value "$env_file" "GPM_BRIDGE_ALLOW_UNAUTH_LOCAL")"
      deploy_env_allow_query_code="$(env_file_value "$env_file" "GPM_BRIDGE_ALLOW_QUERY_CODE")"
      deploy_env_trust_proxy_headers="$(env_file_value "$env_file" "GPM_BRIDGE_TRUST_PROXY_HEADERS")"
      deploy_env_addr="$(env_file_value "$env_file" "GPM_BRIDGE_ADDR")"
      if [[ -z "$deploy_env_access_code_sha256" && "$deploy_env_allow_unauth_local" != "true" ]]; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "deploy env must include an access-code hash unless explicitly local unauthenticated")"
      elif [[ -n "$deploy_env_access_code_sha256" ]] && ! is_sha256_hex "$deploy_env_access_code_sha256"; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "deploy env access-code sha256 must be 64 hex characters")"
      fi
      if [[ "$deploy_env_allow_query_code" != "false" ]]; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "deploy env must keep query access codes disabled by default")"
      fi
      if [[ "$deploy_env_trust_proxy_headers" != "true" ]]; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "deploy env must trust loopback proxy headers for per-client rate limits")"
      fi
      if ! is_loopback_listen_addr "$deploy_env_addr"; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "deploy env bridge addr must be loopback host:port")"
      fi
      if [[ -n "$deploy_env_config_sha256" ]] && ! is_sha256_hex "$deploy_env_config_sha256"; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "deploy env config sha256 must be 64 hex characters")"
      elif [[ -n "$config_sha256" && "$deploy_env_config_sha256" != "$config_sha256" ]]; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "deploy env config sha256 does not match supplied config")"
      fi
    fi
    if [[ -f "$wrapper_file" ]]; then
      if ! grep -Fq -- '--allow-unauthenticated-local="${GPM_BRIDGE_ALLOW_UNAUTH_LOCAL}"' "$wrapper_file" ||
        ! grep -Fq -- '--allow-query-access-code="${GPM_BRIDGE_ALLOW_QUERY_CODE}"' "$wrapper_file" ||
        ! grep -Fq -- '--trust-proxy-headers="${GPM_BRIDGE_TRUST_PROXY_HEADERS}"' "$wrapper_file" ||
        ! grep -Fq -- '--redirect="${GPM_BRIDGE_REDIRECT}"' "$wrapper_file" ||
        ! grep -Fq -- '--config-sha256' "$wrapper_file"; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "deploy wrapper is missing hardened flag propagation")"
      fi
    fi
    if [[ -f "$unit_file" ]]; then
      if ! grep -q '^NoNewPrivileges=true$' "$unit_file" ||
        ! grep -q '^PrivateTmp=true$' "$unit_file" ||
        ! grep -q '^ProtectSystem=strict$' "$unit_file" ||
        ! grep -q '^LogsDirectory=gpm$' "$unit_file"; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "systemd unit is missing expected hardening directives")"
      fi
    fi
    if [[ -f "$caddy_file" ]]; then
      deploy_caddy_site_host="$(extract_caddy_site_host "$caddy_file")"
      deploy_caddy_reverse_proxy="$(extract_caddy_reverse_proxy "$caddy_file")"
      if ! is_bridge_public_host "$deploy_caddy_site_host"; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "Caddy example site host must be a safe bare public host")"
      elif [[ "$smoke_base_host_requires_proxy_match" == "true" && "$deploy_caddy_site_host" != "$smoke_base_host" ]]; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "Caddy example site host must match smoke base_url host")"
      fi
      if [[ -z "$deploy_env_addr" || "$deploy_caddy_reverse_proxy" != "$deploy_env_addr" ]]; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "Caddy example reverse_proxy must match GPM_BRIDGE_ADDR")"
      fi
      if ! grep -Fq 'header_up X-Forwarded-For {remote_host}' "$caddy_file"; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "Caddy example must overwrite X-Forwarded-For with remote host")"
      fi
    fi
    if [[ -f "$nginx_file" ]]; then
      deploy_nginx_server_name="$(extract_nginx_server_name "$nginx_file")"
      deploy_nginx_proxy_pass="$(extract_nginx_proxy_pass "$nginx_file")"
      if ! is_bridge_public_host "$deploy_nginx_server_name"; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "nginx example server_name must be a safe bare public host")"
      elif [[ "$smoke_base_host_requires_proxy_match" == "true" && "$deploy_nginx_server_name" != "$smoke_base_host" ]]; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "nginx example server_name must match smoke base_url host")"
      fi
      if [[ -z "$deploy_env_addr" || "$deploy_nginx_proxy_pass" != "$deploy_env_addr" ]]; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "nginx example proxy_pass must match GPM_BRIDGE_ADDR")"
      fi
      if ! grep -Fq 'proxy_set_header X-Forwarded-For $remote_addr;' "$nginx_file" ||
        grep -Fq '$proxy_add_x_forwarded_for' "$nginx_file"; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "nginx example must overwrite spoofable X-Forwarded-For")"
      fi
    fi
  fi
fi

status="pass"
recommended_action_id="record_operator_evidence"
recommended_action="Record this JSON with the deployment evidence bundle and proceed with operator handoff."
if [[ "$evidence_scope" != "real_helper_https" ]]; then
  recommended_action_id="capture_real_helper_https_evidence"
  recommended_action="Local deployment evidence passed; capture real helper HTTPS smoke, deployment, host-install, and trusted verifier evidence before operator handoff."
fi
if [[ "$smoke_status" != "pass" ]]; then
  status="fail"
  recommended_action_id="fix_deployed_bridge_smoke"
  recommended_action="Fix the deployed bridge service smoke failure, then rerun this evidence script."
elif [[ "$smoke_evidence_status" != "pass" ]]; then
  status="fail"
  recommended_action_id="refresh_deployed_bridge_smoke"
  recommended_action="Rerun access_bridge_service_smoke.sh with a valid access code so evidence includes fresh auth-negative checks."
elif [[ "$transport_status" != "pass" ]]; then
  status="fail"
  recommended_action_id="refresh_deployed_bridge_smoke"
  recommended_action="Rerun access_bridge_service_smoke.sh against the real HTTPS helper so evidence includes verified TLS transport facts."
elif [[ "$identity_status" != "pass" ]]; then
  status="fail"
  recommended_action_id="fix_bridge_identity"
  recommended_action="Confirm the deployed helper, organization, and registry identity, then rerun the smoke and evidence scripts."
elif [[ "$config_status" == "fail" ]]; then
  status="fail"
  recommended_action_id="stage_bridge_service_config"
  recommended_action="Stage the expected bridge-service config locally or update the supplied --config-json path, then rerun evidence collection."
elif [[ "$deploy_status" == "fail" ]]; then
  status="fail"
  recommended_action_id="stage_bridge_deploy_pack"
  recommended_action="Regenerate or restage the bridge deploy pack, then rerun evidence collection with the corrected --deploy-pack-dir."
fi

generated_at_utc="$(timestamp_utc)"
jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$status" \
  --arg summary_json "$summary_json" \
  --arg smoke_summary_json "$smoke_summary_json" \
  --arg smoke_status "$smoke_status" \
  --arg smoke_notes "$smoke_notes" \
  --arg smoke_schema_id "$smoke_schema_id" \
  --arg smoke_generated_at_utc "$smoke_generated_at_utc" \
  --arg smoke_age_sec "$smoke_age_sec" \
  --arg smoke_auth_required "$smoke_auth_required" \
  --arg smoke_missing_code_http "$smoke_missing_code_http" \
  --arg smoke_wrong_code_http "$smoke_wrong_code_http" \
  --arg smoke_valid_code_http "$smoke_valid_code_http" \
  --arg smoke_bridge_http_status "$smoke_bridge_http_status" \
  --arg smoke_bridge_status "$smoke_bridge_status" \
  --arg smoke_bridge_security_headers_ok "$smoke_bridge_security_headers_ok" \
  --arg smoke_config_sha256 "$smoke_config_sha256" \
  --arg smoke_evidence_status "$smoke_evidence_status" \
  --arg smoke_evidence_reason "$smoke_evidence_reason" \
  --arg smoke_base_url "$smoke_base_url" \
  --arg smoke_base_host "$smoke_base_host" \
  --arg smoke_transport_scheme "$smoke_transport_scheme" \
  --arg smoke_transport_https "$smoke_transport_https" \
  --arg smoke_transport_loopback "$smoke_transport_loopback" \
  --arg smoke_transport_tls_checked "$smoke_transport_tls_checked" \
  --arg smoke_transport_tls_verified "$smoke_transport_tls_verified" \
  --arg smoke_transport_ssl_verify_result "$smoke_transport_ssl_verify_result" \
  --arg smoke_transport_effective_url "$smoke_transport_effective_url" \
  --arg smoke_transport_remote_ip "$smoke_transport_remote_ip" \
  --arg smoke_transport_remote_port "$smoke_transport_remote_port" \
  --arg smoke_transport_http_version "$smoke_transport_http_version" \
  --arg smoke_transport_time_appconnect "$smoke_transport_time_appconnect" \
  --arg smoke_transport_mtls_client_used "$smoke_transport_mtls_client_used" \
  --arg transport_status "$transport_status" \
  --arg transport_reason "$transport_reason" \
  --arg evidence_scope "$evidence_scope" \
  --arg smoke_path_id "$smoke_path_id" \
  --arg expect_helper_id "$expect_helper_id" \
  --arg expect_org_id "$expect_org_id" \
  --arg expect_registry_id "$expect_registry_id" \
  --arg actual_helper_id "$actual_helper_id" \
  --arg actual_org_id "$actual_org_id" \
  --arg actual_registry_id "$actual_registry_id" \
  --arg identity_status "$identity_status" \
  --arg identity_reason "$identity_reason" \
  --arg config_json "$config_json" \
  --arg config_status "$config_status" \
  --arg config_reason "$config_reason" \
  --arg config_helper_id "$config_helper_id" \
  --arg config_org_id "$config_org_id" \
  --arg config_registry_id "$config_registry_id" \
  --arg config_sha256 "$config_sha256" \
  --arg config_allow_local_access_paths "$config_allow_local_access_paths" \
  --arg deploy_pack_dir "$deploy_pack_dir" \
  --arg service_name "$service_name" \
  --arg deploy_status "$deploy_status" \
  --arg deploy_reason "$deploy_reason" \
  --arg deploy_env_config_sha256 "$deploy_env_config_sha256" \
  --arg deploy_env_access_code_sha256 "$deploy_env_access_code_sha256" \
  --arg deploy_env_allow_unauth_local "$deploy_env_allow_unauth_local" \
  --arg deploy_env_allow_query_code "$deploy_env_allow_query_code" \
  --arg deploy_env_trust_proxy_headers "$deploy_env_trust_proxy_headers" \
  --arg deploy_env_addr "$deploy_env_addr" \
  --arg deploy_caddy_site_host "$deploy_caddy_site_host" \
  --arg deploy_caddy_reverse_proxy "$deploy_caddy_reverse_proxy" \
  --arg deploy_nginx_server_name "$deploy_nginx_server_name" \
  --arg deploy_nginx_proxy_pass "$deploy_nginx_proxy_pass" \
  --arg recommended_action_id "$recommended_action_id" \
  --arg recommended_action "$recommended_action" \
  --argjson config_exists "$config_exists" \
  --argjson config_valid "$config_valid" \
  --argjson deploy_exists "$deploy_exists" \
  --argjson deploy_files "$deploy_files_json" \
  '{
    version: 1,
    schema: {
      id: "access_bridge_deployment_evidence_summary",
      major: 1,
      minor: 2
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    evidence_scope: $evidence_scope,
    pilot_handoff_candidate: ($evidence_scope == "real_helper_https"),
    notes: (
      if $status != "pass" then
        "Access bridge deployment evidence needs operator action"
      elif $evidence_scope == "real_helper_https" then
        "Access bridge deployment evidence is ready for trusted bundle verification before operator handoff"
      else
        "Access bridge deployment evidence passed as local rehearsal; capture real helper HTTPS evidence before operator handoff"
      end
    ),
    inputs: {
      summary_json: $summary_json,
      smoke_summary_json: $smoke_summary_json,
      config_json: $config_json,
      deploy_pack_dir: $deploy_pack_dir,
      service_name: $service_name
    },
    smoke: {
      status: $smoke_status,
      notes: $smoke_notes,
      schema_id: $smoke_schema_id,
      generated_at_utc: $smoke_generated_at_utc,
      age_sec: (if $smoke_age_sec == "" then null else ($smoke_age_sec | tonumber) end),
      auth_required: ($smoke_auth_required == "true"),
      missing_code_http_status: $smoke_missing_code_http,
      wrong_code_http_status: $smoke_wrong_code_http,
      valid_code_http_status: $smoke_valid_code_http,
      bridge_http_status: $smoke_bridge_http_status,
      bridge_status: $smoke_bridge_status,
      bridge_security_headers_ok: ($smoke_bridge_security_headers_ok == "true"),
      config_sha256: $smoke_config_sha256,
      evidence_status: $smoke_evidence_status,
      evidence_reason: $smoke_evidence_reason,
      base_url: $smoke_base_url,
      base_host: $smoke_base_host,
      transport_https: ($smoke_transport_https == "true"),
      transport_tls_verified: ($smoke_transport_tls_verified == "true"),
      path_id: $smoke_path_id,
      summary_json: $smoke_summary_json
    },
    transport: {
      status: $transport_status,
      reason: $transport_reason,
      base_url_scheme: $smoke_transport_scheme,
      https: ($smoke_transport_https == "true"),
      loopback: ($smoke_transport_loopback == "true"),
      tls_checked: ($smoke_transport_tls_checked == "true"),
      tls_verified: ($smoke_transport_tls_verified == "true"),
      ssl_verify_result: $smoke_transport_ssl_verify_result,
      effective_url: $smoke_transport_effective_url,
      remote_ip: $smoke_transport_remote_ip,
      remote_port: $smoke_transport_remote_port,
      http_version: $smoke_transport_http_version,
      time_appconnect_sec: $smoke_transport_time_appconnect,
      mtls_client_certificate_used: ($smoke_transport_mtls_client_used == "true")
    },
    expected_identity: {
      helper_id: $expect_helper_id,
      organization_id: $expect_org_id,
      registry_id: $expect_registry_id
    },
    deployed_identity: {
      helper_id: $actual_helper_id,
      organization_id: $actual_org_id,
      registry_id: $actual_registry_id
    },
    identity_check: {
      status: $identity_status,
      reason: $identity_reason
    },
    local_files: {
      config: {
        supplied: ($config_json != ""),
        status: $config_status,
        reason: $config_reason,
        path: $config_json,
        exists: $config_exists,
        valid_json: $config_valid,
        sha256: $config_sha256,
        helper_id: $config_helper_id,
        organization_id: $config_org_id,
        registry_id: $config_registry_id,
        allow_local_access_paths: $config_allow_local_access_paths
      },
      deploy_pack: {
        supplied: ($deploy_pack_dir != ""),
        status: $deploy_status,
        reason: $deploy_reason,
        dir: $deploy_pack_dir,
        exists: $deploy_exists,
        env: {
          config_sha256: $deploy_env_config_sha256,
          access_code_sha256: $deploy_env_access_code_sha256,
          allow_unauthenticated_local: $deploy_env_allow_unauth_local,
          allow_query_code: $deploy_env_allow_query_code,
          trust_proxy_headers: $deploy_env_trust_proxy_headers,
          addr: $deploy_env_addr
        },
        proxy_examples: {
          caddy_site_host: $deploy_caddy_site_host,
          caddy_reverse_proxy: $deploy_caddy_reverse_proxy,
          nginx_server_name: $deploy_nginx_server_name,
          nginx_proxy_pass: $deploy_nginx_proxy_pass
        },
        required_files: $deploy_files
      }
    },
    recommended_next_action: {
      id: $recommended_action_id,
      command: $recommended_action
    }
  }' >"$summary_json"

echo "access-bridge-deployment-evidence: status=$status"
echo "summary_json: $summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" != "pass" ]]; then
  exit 1
fi
