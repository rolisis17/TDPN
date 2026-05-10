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
if [[ -n "$config_json" ]]; then
  if [[ -f "$config_json" ]]; then
    expected_config_sha256="$(file_sha256 "$config_json")"
    add_check "config_json_exists" "pass" "config JSON exists"
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
if [[ -f "$env_file" ]]; then
  env_config_sha256="$(env_file_value "$env_file" "GPM_BRIDGE_CONFIG_SHA256")"
  env_access_code_sha256="$(env_file_value "$env_file" "GPM_BRIDGE_ACCESS_CODE_SHA256")"
  env_allow_unauth_local="$(env_file_value "$env_file" "GPM_BRIDGE_ALLOW_UNAUTH_LOCAL")"
  env_allow_query_code="$(env_file_value "$env_file" "GPM_BRIDGE_ALLOW_QUERY_CODE")"
  env_trust_proxy_headers="$(env_file_value "$env_file" "GPM_BRIDGE_TRUST_PROXY_HEADERS")"
  env_addr="$(env_file_value "$env_file" "GPM_BRIDGE_ADDR")"

  if [[ -n "$expected_config_sha256" && "$env_config_sha256" == "$expected_config_sha256" ]]; then
    add_check "config_sha256_matches" "pass" "env config sha256 matches supplied config"
  elif [[ -n "$expected_config_sha256" ]]; then
    add_check "config_sha256_matches" "fail" "env config sha256 does not match supplied config"
  else
    add_check "config_sha256_matches" "skip" "no config JSON supplied"
  fi

  if [[ -n "$env_access_code_sha256" || "$env_allow_unauth_local" == "true" ]]; then
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
  if [[ "$env_addr" == 127.* || "$env_addr" == localhost:* || "$env_addr" == "[::1]:"* || "$env_addr" == "::1:"* ]]; then
    add_check "loopback_bind" "pass" "bridge service is configured for loopback bind"
  else
    add_check "loopback_bind" "fail" "bridge service should bind to loopback behind HTTPS proxy"
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
  if grep -Fq 'header_up X-Forwarded-For {remote_host}' "$caddy_file"; then
    add_check "caddy_xff_overwrite" "pass" "Caddy overwrites X-Forwarded-For"
  else
    add_check "caddy_xff_overwrite" "fail" "Caddy must overwrite X-Forwarded-For"
  fi
fi

if [[ -f "$nginx_file" ]]; then
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
  --arg env_config_sha256 "$env_config_sha256" \
  --arg env_access_code_sha256 "$env_access_code_sha256" \
  --arg env_allow_unauth_local "$env_allow_unauth_local" \
  --arg env_allow_query_code "$env_allow_query_code" \
  --arg env_trust_proxy_headers "$env_trust_proxy_headers" \
  --arg env_addr "$env_addr" \
  --arg recommended_action_id "$recommended_action_id" \
  --arg recommended_action "$recommended_action" \
  --argjson fail_count "$fail_count" \
  --argjson checks "$checks_json" \
  '{
    version: 1,
    schema: {
      id: "access_bridge_host_install_check_summary",
      major: 1,
      minor: 0
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
      env_config_sha256: $env_config_sha256,
      env_access_code_sha256: $env_access_code_sha256,
      env_allow_unauthenticated_local: $env_allow_unauth_local,
      env_allow_query_code: $env_allow_query_code,
      env_trust_proxy_headers: $env_trust_proxy_headers,
      env_addr: $env_addr
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
