#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

base_url=""
path_id="helper-web"
code=""
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

usage() {
  cat <<'USAGE'
Usage:
  scripts/access_bridge_deployment_evidence.sh \
    (--base-url URL | --smoke-summary-json FILE) \
    [--path-id helper-web] \
    [--code CODE] \
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
smoke_base_url="$(json_string_or_empty "$smoke_summary_json" '.base_url')"
smoke_path_id="$(json_string_or_empty "$smoke_summary_json" '.path_id')"
actual_helper_id="$(json_string_or_empty "$smoke_summary_json" '.health.helper_id')"
actual_org_id="$(json_string_or_empty "$smoke_summary_json" '.health.organization_id')"
actual_registry_id="$(json_string_or_empty "$smoke_summary_json" '.health.registry_id')"

config_status="skip"
config_exists="false"
config_valid="false"
config_helper_id=""
config_org_id=""
config_registry_id=""
config_sha256=""
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
deploy_env_allow_query_code=""
deploy_env_trust_proxy_headers=""
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
      deploy_env_allow_query_code="$(env_file_value "$env_file" "GPM_BRIDGE_ALLOW_QUERY_CODE")"
      deploy_env_trust_proxy_headers="$(env_file_value "$env_file" "GPM_BRIDGE_TRUST_PROXY_HEADERS")"
      if [[ "$deploy_env_allow_query_code" != "false" ]]; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "deploy env must keep query access codes disabled by default")"
      fi
      if [[ "$deploy_env_trust_proxy_headers" != "true" ]]; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "deploy env must trust loopback proxy headers for per-client rate limits")"
      fi
      if [[ -n "$config_sha256" && "$deploy_env_config_sha256" != "$config_sha256" ]]; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "deploy env config sha256 does not match supplied config")"
      fi
    fi
    if [[ -f "$wrapper_file" ]]; then
      if ! grep -Fq -- '--allow-query-access-code="${GPM_BRIDGE_ALLOW_QUERY_CODE}"' "$wrapper_file" ||
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
        ! grep -q '^ProtectSystem=strict$' "$unit_file"; then
        deploy_status="fail"
        deploy_reason="$(append_reason "$deploy_reason" "systemd unit is missing expected hardening directives")"
      fi
    fi
    if [[ -f "$caddy_file" ]] && ! grep -Fq 'header_up X-Forwarded-For {remote_host}' "$caddy_file"; then
      deploy_status="fail"
      deploy_reason="$(append_reason "$deploy_reason" "Caddy example must overwrite X-Forwarded-For with remote host")"
    fi
    if [[ -f "$nginx_file" ]]; then
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
if [[ "$smoke_status" != "pass" ]]; then
  status="fail"
  recommended_action_id="fix_deployed_bridge_smoke"
  recommended_action="Fix the deployed bridge service smoke failure, then rerun this evidence script."
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
  --arg smoke_base_url "$smoke_base_url" \
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
  --arg deploy_pack_dir "$deploy_pack_dir" \
  --arg service_name "$service_name" \
  --arg deploy_status "$deploy_status" \
  --arg deploy_reason "$deploy_reason" \
  --arg deploy_env_config_sha256 "$deploy_env_config_sha256" \
  --arg deploy_env_allow_query_code "$deploy_env_allow_query_code" \
  --arg deploy_env_trust_proxy_headers "$deploy_env_trust_proxy_headers" \
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
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    notes: (if $status == "pass" then "Access bridge deployment evidence is ready for operator handoff" else "Access bridge deployment evidence needs operator action" end),
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
      base_url: $smoke_base_url,
      path_id: $smoke_path_id,
      summary_json: $smoke_summary_json
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
        registry_id: $config_registry_id
      },
      deploy_pack: {
        supplied: ($deploy_pack_dir != ""),
        status: $deploy_status,
        reason: $deploy_reason,
        dir: $deploy_pack_dir,
        exists: $deploy_exists,
        env: {
          config_sha256: $deploy_env_config_sha256,
          allow_query_code: $deploy_env_allow_query_code,
          trust_proxy_headers: $deploy_env_trust_proxy_headers
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
