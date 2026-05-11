#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

deploy_pack_dir=""
service_name="gpm-access-bridge"
config_json=""
summary_json=""
print_summary_json="1"

usage() {
  cat <<'USAGE'
Usage:
  scripts/access_bridge_host_install_check.sh \
    --deploy-pack-dir DIR \
    [--service-name gpm-access-bridge] \
    [--config-json FILE] \
    [--summary-json FILE] \
    [--print-summary-json 0|1]

Validates the staged/installed Access Recovery bridge host files:
env, wrapper, systemd unit, and Caddy/nginx proxy examples.
USAGE
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access bridge host install check failed: missing required command: $cmd" >&2
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
  else
    sha256sum "$file" | awk '{print $1}'
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

add_check() {
  local id="$1"
  local status="$2"
  local message="$3"
  jq -nc --arg id "$id" --arg status "$status" --arg message "$message" \
    '{id:$id,status:$status,message:$message}' >>"$checks_jsonl"
}

file_exists_check() {
  local id="$1"
  local file="$2"
  if [[ -f "$file" ]]; then
    add_check "$id" "pass" "$file exists"
  else
    add_check "$id" "fail" "$file is missing"
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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deploy-pack-dir)
      deploy_pack_dir="${2:-}"
      shift 2
      ;;
    --service-name)
      service_name="${2:-}"
      shift 2
      ;;
    --config-json|--config)
      config_json="${2:-}"
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

for cmd in bash date jq mktemp sha256sum; do
  need_cmd "$cmd"
done
bool_arg_or_die "--print-summary-json" "$print_summary_json"

if [[ -z "$deploy_pack_dir" ]]; then
  echo "access bridge host install check failed: --deploy-pack-dir is required" >&2
  exit 2
fi

deploy_pack_dir="$(abs_path "$deploy_pack_dir")"
service_name="$(sanitize_systemd_name "$service_name")"
if [[ -n "$config_json" ]]; then
  config_json="$(abs_path "$config_json")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$ROOT_DIR/.easy-node-logs/access_bridge_host_install_check_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT
checks_jsonl="$tmp_dir/checks.jsonl"
: >"$checks_jsonl"

env_file="$deploy_pack_dir/${service_name}.env"
wrapper_file="$deploy_pack_dir/run-${service_name}.sh"
unit_file="$deploy_pack_dir/${service_name}.service"
caddy_file="$deploy_pack_dir/${service_name}.Caddyfile.example"
nginx_file="$deploy_pack_dir/${service_name}.nginx.example.conf"

if [[ -d "$deploy_pack_dir" ]]; then
  add_check "deploy_pack_dir_exists" "pass" "deploy pack directory exists"
else
  add_check "deploy_pack_dir_exists" "fail" "deploy pack directory is missing"
fi
file_exists_check "env_file_exists" "$env_file"
file_exists_check "wrapper_file_exists" "$wrapper_file"
file_exists_check "systemd_unit_exists" "$unit_file"
file_exists_check "caddy_example_exists" "$caddy_file"
file_exists_check "nginx_example_exists" "$nginx_file"

expected_config_sha256=""
config_allow_local_access_paths=""
if [[ -n "$config_json" ]]; then
  if [[ -f "$config_json" ]]; then
    expected_config_sha256="$(file_sha256 "$config_json")"
    add_check "config_json_exists" "pass" "config JSON exists"
    if jq -e . "$config_json" >/dev/null 2>&1; then
      add_check "config_json_valid" "pass" "config JSON is valid"
      config_allow_local_access_paths="$(jq -r 'if has("allow_local_access_paths") then (.allow_local_access_paths | tostring) else "false" end' "$config_json")"
      if [[ "$config_allow_local_access_paths" == "true" ]]; then
        add_check "config_local_access_paths_disabled" "fail" "deployable config must not allow local diagnostic access paths"
      else
        add_check "config_local_access_paths_disabled" "pass" "deployable config does not allow local diagnostic access paths"
      fi
    else
      add_check "config_json_valid" "fail" "config JSON is invalid"
    fi
  else
    add_check "config_json_exists" "fail" "config JSON is missing"
  fi
fi

env_config_sha256=""
env_access_code_sha256=""
env_allow_unauth_local=""
env_allow_query_code=""
env_trust_proxy_headers=""
env_addr=""
env_rps=""
env_max_sources=""
caddy_site_host=""
caddy_reverse_proxy=""
nginx_server_name=""
nginx_proxy_pass=""
if [[ -f "$env_file" ]]; then
  env_config_sha256="$(env_file_value "$env_file" "GPM_BRIDGE_CONFIG_SHA256")"
  env_access_code_sha256="$(env_file_value "$env_file" "GPM_BRIDGE_ACCESS_CODE_SHA256")"
  env_allow_unauth_local="$(env_file_value "$env_file" "GPM_BRIDGE_ALLOW_UNAUTH_LOCAL")"
  env_allow_query_code="$(env_file_value "$env_file" "GPM_BRIDGE_ALLOW_QUERY_CODE")"
  env_trust_proxy_headers="$(env_file_value "$env_file" "GPM_BRIDGE_TRUST_PROXY_HEADERS")"
  env_addr="$(env_file_value "$env_file" "GPM_BRIDGE_ADDR")"
  env_rps="$(env_file_value "$env_file" "GPM_BRIDGE_RPS")"
  env_max_sources="$(env_file_value "$env_file" "GPM_BRIDGE_MAX_SOURCES")"

  if [[ -n "$env_config_sha256" ]] && ! is_sha256_hex "$env_config_sha256"; then
    add_check "config_sha256_matches" "fail" "env config sha256 is not 64 hex characters"
  elif [[ -n "$expected_config_sha256" && "$env_config_sha256" == "$expected_config_sha256" ]]; then
    add_check "config_sha256_matches" "pass" "env config sha256 matches supplied config"
  elif [[ -n "$expected_config_sha256" ]]; then
    add_check "config_sha256_matches" "fail" "env config sha256 does not match supplied config"
  else
    add_check "config_sha256_matches" "skip" "no config JSON supplied"
  fi

  if [[ -n "$env_access_code_sha256" ]] && ! is_sha256_hex "$env_access_code_sha256"; then
    add_check "access_code_gate_configured" "fail" "access-code hash is not 64 hex characters"
  elif [[ -n "$env_access_code_sha256" || "$env_allow_unauth_local" == "true" ]]; then
    add_check "access_code_gate_configured" "pass" "access-code hash is configured or unauthenticated local mode is explicit"
  else
    add_check "access_code_gate_configured" "fail" "access-code hash is missing"
  fi
  if [[ "$env_allow_query_code" == "false" ]]; then
    add_check "query_access_code_disabled" "pass" "query-string access codes disabled"
  else
    add_check "query_access_code_disabled" "fail" "query-string access codes must be disabled by default"
  fi
  if [[ "$env_trust_proxy_headers" == "true" ]]; then
    add_check "trusted_proxy_headers_enabled" "pass" "trusted proxy headers enabled"
  else
    add_check "trusted_proxy_headers_enabled" "fail" "trusted proxy headers should be enabled behind loopback proxy"
  fi
  if is_loopback_listen_addr "$env_addr"; then
    add_check "loopback_bind" "pass" "bridge service is configured for loopback bind"
  else
    add_check "loopback_bind" "fail" "bridge service should bind to loopback behind HTTPS proxy"
  fi
  if [[ "$env_rps" =~ ^[0-9]+$ && "$env_rps" -ge 1 && "$env_rps" -le 20 ]]; then
    add_check "rate_limit_configured" "pass" "bridge service rate limit is enabled"
  else
    add_check "rate_limit_configured" "fail" "GPM_BRIDGE_RPS must be an integer from 1 to 20 for pilot helper hosts"
  fi
  if [[ "$env_max_sources" =~ ^[0-9]+$ && "$env_max_sources" -ge 1 && "$env_max_sources" -le 100000 ]]; then
    add_check "rate_limit_source_cap_configured" "pass" "bridge service rate limit source cap is bounded"
  else
    add_check "rate_limit_source_cap_configured" "fail" "GPM_BRIDGE_MAX_SOURCES must be an integer from 1 to 100000 for pilot helper hosts"
  fi
fi

if [[ -f "$wrapper_file" ]]; then
  if grep -Fq -- '--allow-unauthenticated-local="${GPM_BRIDGE_ALLOW_UNAUTH_LOCAL}"' "$wrapper_file" &&
    grep -Fq -- '--allow-query-access-code="${GPM_BRIDGE_ALLOW_QUERY_CODE}"' "$wrapper_file" &&
    grep -Fq -- '--trust-proxy-headers="${GPM_BRIDGE_TRUST_PROXY_HEADERS}"' "$wrapper_file" &&
    grep -Fq -- '--redirect="${GPM_BRIDGE_REDIRECT}"' "$wrapper_file" &&
    grep -Fq -- '--config-sha256' "$wrapper_file"; then
    add_check "wrapper_hardened_flags" "pass" "wrapper propagates hardened flags"
  else
    add_check "wrapper_hardened_flags" "fail" "wrapper is missing hardened flag propagation"
  fi
fi

if [[ -f "$unit_file" ]]; then
  if grep -q '^NoNewPrivileges=true$' "$unit_file" &&
    grep -q '^PrivateTmp=true$' "$unit_file" &&
    grep -q '^ProtectSystem=strict$' "$unit_file" &&
    grep -q '^LogsDirectory=gpm$' "$unit_file"; then
    add_check "systemd_hardening" "pass" "systemd unit contains expected hardening"
  else
    add_check "systemd_hardening" "fail" "systemd unit is missing expected hardening"
  fi
fi

if [[ -f "$caddy_file" ]]; then
  caddy_site_host="$(extract_caddy_site_host "$caddy_file")"
  caddy_reverse_proxy="$(extract_caddy_reverse_proxy "$caddy_file")"
  if is_bridge_public_host "$caddy_site_host"; then
    add_check "caddy_public_host_valid" "pass" "Caddy site host is a safe bare public host"
  else
    add_check "caddy_public_host_valid" "fail" "Caddy site host must be a safe bare DNS name or IPv4 address"
  fi
  if [[ -n "$env_addr" && "$caddy_reverse_proxy" == "$env_addr" ]]; then
    add_check "caddy_reverse_proxy_target" "pass" "Caddy reverse_proxy target matches GPM_BRIDGE_ADDR"
  else
    add_check "caddy_reverse_proxy_target" "fail" "Caddy reverse_proxy target must match GPM_BRIDGE_ADDR"
  fi
  if grep -Fq 'header_up X-Forwarded-For {remote_host}' "$caddy_file"; then
    add_check "caddy_xff_overwrite" "pass" "Caddy overwrites X-Forwarded-For"
  else
    add_check "caddy_xff_overwrite" "fail" "Caddy must overwrite X-Forwarded-For"
  fi
fi

if [[ -f "$nginx_file" ]]; then
  nginx_server_name="$(extract_nginx_server_name "$nginx_file")"
  nginx_proxy_pass="$(extract_nginx_proxy_pass "$nginx_file")"
  if is_bridge_public_host "$nginx_server_name"; then
    add_check "nginx_public_host_valid" "pass" "nginx server_name is a safe bare public host"
  else
    add_check "nginx_public_host_valid" "fail" "nginx server_name must be a safe bare DNS name or IPv4 address"
  fi
  if [[ -n "$env_addr" && "$nginx_proxy_pass" == "$env_addr" ]]; then
    add_check "nginx_proxy_pass_target" "pass" "nginx proxy_pass target matches GPM_BRIDGE_ADDR"
  else
    add_check "nginx_proxy_pass_target" "fail" "nginx proxy_pass target must match GPM_BRIDGE_ADDR"
  fi
  if grep -Fq 'proxy_set_header X-Forwarded-For $remote_addr;' "$nginx_file" &&
    ! grep -Fq '$proxy_add_x_forwarded_for' "$nginx_file"; then
    add_check "nginx_xff_overwrite" "pass" "nginx overwrites X-Forwarded-For"
  else
    add_check "nginx_xff_overwrite" "fail" "nginx must overwrite spoofable X-Forwarded-For"
  fi
fi

checks_json="$(jq -s '.' "$checks_jsonl")"
fail_count="$(jq -s '[.[] | select(.status == "fail")] | length' "$checks_jsonl")"
status="pass"
recommended_action_id="record_host_install_evidence"
recommended_action="Record this JSON with helper-host install evidence."
if [[ "$fail_count" != "0" ]]; then
  status="fail"
  recommended_action_id="fix_bridge_host_install"
  recommended_action="Fix the failed host-install checks, then rerun this script."
fi

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --arg deploy_pack_dir "$deploy_pack_dir" \
  --arg service_name "$service_name" \
  --arg config_json "$config_json" \
  --arg expected_config_sha256 "$expected_config_sha256" \
  --arg config_allow_local_access_paths "$config_allow_local_access_paths" \
  --arg env_config_sha256 "$env_config_sha256" \
  --arg env_access_code_sha256 "$env_access_code_sha256" \
  --arg env_allow_unauth_local "$env_allow_unauth_local" \
  --arg env_allow_query_code "$env_allow_query_code" \
  --arg env_trust_proxy_headers "$env_trust_proxy_headers" \
  --arg env_addr "$env_addr" \
  --arg env_rps "$env_rps" \
  --arg env_max_sources "$env_max_sources" \
  --arg caddy_site_host "$caddy_site_host" \
  --arg caddy_reverse_proxy "$caddy_reverse_proxy" \
  --arg nginx_server_name "$nginx_server_name" \
  --arg nginx_proxy_pass "$nginx_proxy_pass" \
  --arg recommended_action_id "$recommended_action_id" \
  --arg recommended_action "$recommended_action" \
  --argjson fail_count "$fail_count" \
  --argjson checks "$checks_json" \
  '{
    version: 1,
    schema: {
      id: "access_bridge_host_install_check_summary",
      major: 1,
      minor: 3
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    notes: (if $status == "pass" then "Access bridge host install checks passed" else "Access bridge host install checks failed" end),
    inputs: {
      deploy_pack_dir: $deploy_pack_dir,
      service_name: $service_name,
      config_json: $config_json
    },
    observed: {
      expected_config_sha256: $expected_config_sha256,
      config_allow_local_access_paths: $config_allow_local_access_paths,
      env_config_sha256: $env_config_sha256,
      env_access_code_sha256: $env_access_code_sha256,
      env_allow_unauthenticated_local: $env_allow_unauth_local,
      env_allow_query_code: $env_allow_query_code,
      env_trust_proxy_headers: $env_trust_proxy_headers,
      env_addr: $env_addr,
      env_rps: $env_rps,
      env_max_sources: $env_max_sources,
      caddy_site_host: $caddy_site_host,
      caddy_reverse_proxy: $caddy_reverse_proxy,
      nginx_server_name: $nginx_server_name,
      nginx_proxy_pass: $nginx_proxy_pass
    },
    summary: {
      checks_total: ($checks | length),
      checks_fail: $fail_count
    },
    checks: $checks,
    recommended_next_action: {
      id: $recommended_action_id,
      command: $recommended_action
    }
  }' >"$summary_json"

echo "access-bridge-host-install-check: status=$status"
echo "summary_json: $summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" != "pass" ]]; then
  exit 1
fi
