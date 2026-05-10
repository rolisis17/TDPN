#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

base_url=""
path_id="helper-web"
code=""
code_file=""
config_json=""
deploy_pack_dir=""
service_name="gpm-access-bridge"
bundle_dir=""
summary_json=""
report_md=""
print_summary_json="1"
max_smoke_age_sec="${ACCESS_BRIDGE_DEPLOYMENT_EVIDENCE_MAX_SMOKE_AGE_SEC:-3600}"
expect_helper_id=""
expect_org_id=""
expect_registry_id=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/access_bridge_pilot_evidence_bundle.sh \
    --base-url URL \
    --config-json FILE \
    --deploy-pack-dir DIR \
    (--code CODE | --code-file FILE) \
    [--path-id helper-web] \
    [--service-name gpm-access-bridge] \
    [--bundle-dir DIR] \
    [--summary-json FILE] \
    [--report-md FILE] \
    [--print-summary-json 0|1]

Runs deployed bridge smoke, deployment evidence, and host-install evidence into one operator handoff bundle.
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
    bridge-code.txt|*/bridge-code.txt|recovery.key|*/recovery.key|*.key|*private-key*|*access-code*|*secret*)
      return 0
      ;;
  esac
  return 1
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
    if deploy_pack_rel_path_is_secret "$rel"; then
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
if [[ ! "$max_smoke_age_sec" =~ ^[0-9]+$ ]]; then
  echo "access bridge pilot evidence bundle failed: --max-smoke-age-sec must be a non-negative integer" >&2
  exit 2
fi

base_url="${base_url%/}"
path_id="$(trim "$path_id")"
service_name="$(trim "$service_name")"
if [[ -z "$base_url" ]]; then
  echo "access bridge pilot evidence bundle failed: --base-url is required" >&2
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
if [[ -n "$code" && -n "$code_file" ]]; then
  echo "access bridge pilot evidence bundle failed: use either --code or --code-file, not both" >&2
  exit 2
fi
if [[ -z "$code" && -z "$code_file" ]]; then
  echo "access bridge pilot evidence bundle failed: --code or --code-file is required" >&2
  exit 2
fi

config_json="$(abs_path "$config_json")"
deploy_pack_dir="$(abs_path "$deploy_pack_dir")"
if [[ ! -f "$config_json" ]]; then
  echo "access bridge pilot evidence bundle failed: config JSON not found: $config_json" >&2
  exit 2
fi
if [[ ! -d "$deploy_pack_dir" ]]; then
  echo "access bridge pilot evidence bundle failed: deploy pack dir not found: $deploy_pack_dir" >&2
  exit 2
fi
if [[ -n "$code_file" ]]; then
  code_file="$(abs_path "$code_file")"
  if [[ ! -f "$code_file" ]]; then
    echo "access bridge pilot evidence bundle failed: code file not found: $code_file" >&2
    exit 2
  fi
fi

if [[ -z "$bundle_dir" ]]; then
  bundle_dir="$ROOT_DIR/.easy-node-logs/access_bridge_pilot_evidence_bundle_$(timestamp_file)"
else
  bundle_dir="$(abs_path "$bundle_dir")"
fi
mkdir -p "$bundle_dir"
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

config_copy="$bundle_dir/bridge-service-config.json"
deploy_pack_copy="$bundle_dir/bridge-deploy-pack"
deploy_pack_skipped_secrets="$bundle_dir/deploy-pack-skipped-secrets.txt"
cp "$config_json" "$config_copy"
copy_public_deploy_pack "$deploy_pack_dir" "$deploy_pack_copy" "$deploy_pack_skipped_secrets"

smoke_summary="$bundle_dir/access_bridge_service_smoke_summary.json"
smoke_log="$bundle_dir/access_bridge_service_smoke.log"
smoke_args=(
  bash ./scripts/access_bridge_service_smoke.sh
  --base-url "$base_url"
  --path-id "$path_id"
  --code-file "$effective_code_file"
  --summary-json "$smoke_summary"
  --abuse-message "pilot evidence bundle smoke"
)
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
  bash ./scripts/access_bridge_deployment_evidence.sh
  --smoke-summary-json "$smoke_summary"
  --config-json "$config_json"
  --deploy-pack-dir "$deploy_pack_dir"
  --service-name "$service_name"
  --summary-json "$deployment_summary"
  --print-summary-json 0
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
run_json_step "host_install_check" "$host_summary" "$host_log" \
  bash ./scripts/access_bridge_host_install_check.sh \
    --deploy-pack-dir "$deploy_pack_dir" \
    --config-json "$config_json" \
    --service-name "$service_name" \
    --summary-json "$host_summary" \
    --print-summary-json 0

steps_json="$(jq -s '.' "$steps_jsonl")"
fail_count="$(jq -s '[.[] | select(.status != "pass" or .rc != 0)] | length' "$steps_jsonl")"
status="pass"
recommended_action_id="record_access_bridge_pilot_evidence_bundle"
recommended_action="Record this bundle with pilot evidence and proceed with helper/operator handoff."
if [[ "$fail_count" != "0" ]]; then
  status="fail"
  first_failed_step="$(jq -rs '[.[] | select(.status != "pass" or .rc != 0)][0].id // ""' "$steps_jsonl")"
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

bundle_tar="${bundle_dir}.tar.gz"
bundle_tar_sha256_file="${bundle_tar}.sha256"
manifest_sha256="$bundle_dir/manifest.sha256"
bundled_summary_json="$bundle_dir/access_bridge_pilot_evidence_bundle_summary.json"

cat >"$report_md" <<REPORT
# Access Bridge Pilot Evidence Bundle

- Status: ${status}
- Base URL: ${base_url}
- Path ID: ${path_id}
- Service name: ${service_name}
- Smoke summary: ${smoke_summary}
- Deployment evidence summary: ${deployment_summary}
- Host install summary: ${host_summary}

Next action: ${recommended_action}
REPORT

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --arg bundle_dir "$bundle_dir" \
  --arg bundle_tar "$bundle_tar" \
  --arg bundle_tar_sha256_file "$bundle_tar_sha256_file" \
  --arg manifest_sha256 "$manifest_sha256" \
  --arg summary_json "$summary_json" \
  --arg bundled_summary_json "$bundled_summary_json" \
  --arg report_md "$report_md" \
  --arg base_url "$base_url" \
  --arg path_id "$path_id" \
  --arg service_name "$service_name" \
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
  --arg smoke_log "$smoke_log" \
  --arg deployment_summary "$deployment_summary" \
  --arg deployment_log "$deployment_log" \
  --arg host_summary "$host_summary" \
  --arg host_log "$host_log" \
  --arg recommended_action_id "$recommended_action_id" \
  --arg recommended_action "$recommended_action" \
  --argjson fail_count "$fail_count" \
  --argjson steps "$steps_json" \
  '{
    version: 1,
    schema: {
      id: "access_bridge_pilot_evidence_bundle_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    notes: (if $status == "pass" then "Access bridge pilot evidence bundle is ready for operator handoff" else "Access bridge pilot evidence bundle needs operator action" end),
    inputs: {
      base_url: $base_url,
      path_id: $path_id,
      service_name: $service_name,
      config_json: $config_json,
      deploy_pack_dir: $deploy_pack_dir,
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
      config_copy: $config_copy,
      deploy_pack_copy: $deploy_pack_copy,
      deploy_pack_skipped_secrets: $deploy_pack_skipped_secrets
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

echo "access-bridge-pilot-evidence-bundle: status=$status"
echo "bundle_dir: $bundle_dir"
echo "manifest_sha256: $manifest_sha256 entries=$manifest_entries"
echo "bundle_tar: $bundle_tar"
echo "bundle_tar_sha256_file: $bundle_tar_sha256_file"
echo "bundle_tar_sha256: $bundle_tar_sha256"
echo "summary_json: $summary_json"
echo "report_md: $report_md"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" != "pass" ]]; then
  exit 1
fi
