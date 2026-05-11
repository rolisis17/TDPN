#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
    [--summary-json PATH] \
    [--bundle-dir PATH] \
    [--bundle-tar PATH] \
    [--bundle-tar-sha256-file PATH] \
    [--check-tar-sha256 [0|1]] \
    [--check-manifest [0|1]] \
    [--provenance-json PATH] \
    [--check-provenance [0|1]] \
    [--require-trusted-provenance [0|1]] \
    [--trust-store PATH] \
    [--public-key-file PATH] \
    [--allow-dev-trust-store [0|1]] \
    [--summary-contract-check [0|1]] \
    [--verification-summary-json PATH] \
    [--print-verification-summary-json [0|1]] \
    [--show-details [0|1]]

Purpose:
  Verify Access Bridge pilot evidence bundle integrity artifacts:
  - tarball checksum sidecar (<bundle>.tar.gz.sha256)
  - in-bundle manifest.sha256
  - optional external provenance JSON sidecar
  - tar member safety before extraction (no absolute/parent paths, symlinks, or hardlinks)

Notes:
  - Provide at least one of --summary-json, --bundle-dir, or --bundle-tar.
  - --summary-json can auto-fill bundle_dir, bundle_tar, and checksum sidecar paths.
  - Provenance verification is checked by default only when --provenance-json is supplied.
    Use exactly one of --trust-store or --public-key-file when provenance is checked.
  - For pilot/operator handoff, use --require-trusted-provenance 1 with
    --trust-store and --verification-summary-json. This requires real_helper_https
    evidence scope, keeps summary/manifest/tar/provenance checks enabled, and
    writes the durable roadmap/operator receipt.
  - Strict pilot handoff mode rejects known local/demo trust-store paths unless
    --allow-dev-trust-store 1 is set for diagnostics.
  - Strict pilot handoff mode also rejects trust stores whose trusted-key source
    is marked as generated demo material unless --allow-dev-trust-store 1 is set.
  - Strict pilot handoff mode also requires the signed summary artifact paths
    to match the verified summary/tar/sidecar/provenance inputs and expected
    in-bundle evidence filenames.
  - Strict pilot handoff mode validates the bundled service-smoke,
    deployment-evidence, and host-install summaries semantically before it can
    emit pilot_handoff_ready=true.
  - When --summary-json is supplied, the summary contract is checked by default;
    set --summary-contract-check 0 only for raw artifact integrity inspection.
  - --verification-summary-json writes a machine-readable verifier result for
    roadmap/pilot gates; --print-verification-summary-json also prints it.
USAGE
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

json_string() {
  local file="$1"
  local filter="$2"
  jq -r "$filter // \"\"" "$file" 2>/dev/null || true
}

summary_artifact_string() {
  local file="$1"
  local field="$2"
  jq -r --arg field "$field" '.artifacts[$field] // ""' "$file" 2>/dev/null || true
}

validate_bundle_summary_contract() {
  local file="$1"
  local label="$2"
  local local_issues=0
  local summary_schema_id summary_status summary_rc summary_steps_total summary_steps_fail summary_steps_len summary_bad_step_count

  if [[ ! -f "$file" ]]; then
    echo "$label not found: $file"
    return 1
  fi
  if ! jq -e . "$file" >/dev/null 2>&1; then
    echo "$label JSON is not valid JSON: $file"
    return 1
  fi

  summary_schema_id="$(jq -r '.schema.id // ""' "$file")"
  summary_status="$(jq -r '.status // ""' "$file" | tr '[:upper:]' '[:lower:]')"
  summary_rc="$(jq -r 'if has("rc") then (.rc|tostring) else "" end' "$file")"
  summary_steps_total="$(jq -r 'if (.summary.steps_total|type) == "number" then .summary.steps_total else "" end' "$file")"
  summary_steps_fail="$(jq -r 'if (.summary.steps_fail|type) == "number" then .summary.steps_fail else "" end' "$file")"
  summary_steps_len="$(jq -r 'if (.steps|type) == "array" then (.steps|length|tostring) else "" end' "$file")"
  summary_bad_step_count="$(jq -r '[.steps[]? | select((.status // "" | ascii_downcase) != "pass" or (has("rc") and .rc != 0))] | length' "$file")"
  if [[ "$summary_schema_id" != "access_bridge_pilot_evidence_bundle_summary" ]]; then
    echo "$label schema mismatch: expected=access_bridge_pilot_evidence_bundle_summary actual=${summary_schema_id:-<missing>}"
    local_issues=$((local_issues + 1))
  fi
  if [[ "$summary_status" != "pass" ]]; then
    echo "$label status is not pass: ${summary_status:-<missing>}"
    local_issues=$((local_issues + 1))
  fi
  if [[ -n "$summary_rc" && "$summary_rc" != "0" ]]; then
    echo "$label rc is not 0: $summary_rc"
    local_issues=$((local_issues + 1))
  fi
  if [[ -z "$summary_steps_total" || "$summary_steps_total" -le 0 ]]; then
    echo "$label steps_total is missing or zero"
    local_issues=$((local_issues + 1))
  fi
  if [[ -z "$summary_steps_len" || "$summary_steps_len" -le 0 ]]; then
    echo "$label steps array is missing or empty"
    local_issues=$((local_issues + 1))
  elif [[ -n "$summary_steps_total" && "$summary_steps_len" != "$summary_steps_total" ]]; then
    echo "$label steps length does not match steps_total: steps_len=$summary_steps_len steps_total=$summary_steps_total"
    local_issues=$((local_issues + 1))
  fi
  if [[ "$summary_steps_fail" != "0" ]]; then
    echo "$label steps_fail is not 0: ${summary_steps_fail:-<missing>}"
    local_issues=$((local_issues + 1))
  fi
  if [[ "$summary_bad_step_count" != "0" ]]; then
    echo "$label contains failing step entries: $summary_bad_step_count"
    local_issues=$((local_issues + 1))
  fi

  ((local_issues == 0))
}

validate_trusted_summary_artifact_bindings() {
  local file="$1"
  local local_issues=0
  local summary_artifact_bundle_dir summary_artifact_summary_json summary_artifact_bundle_tar
  local summary_artifact_bundle_tar_sha256_file summary_artifact_provenance_json
  local expected_path actual_path field

  summary_artifact_bundle_dir="$(abs_path "$(summary_artifact_string "$file" "bundle_dir")")"
  summary_artifact_summary_json="$(abs_path "$(summary_artifact_string "$file" "summary_json")")"
  summary_artifact_bundle_tar="$(abs_path "$(summary_artifact_string "$file" "bundle_tar")")"
  summary_artifact_bundle_tar_sha256_file="$(abs_path "$(summary_artifact_string "$file" "bundle_tar_sha256_file")")"
  summary_artifact_provenance_json="$(abs_path "$(summary_artifact_string "$file" "provenance_json")")"

  if [[ -z "$summary_artifact_bundle_dir" ]]; then
    echo "trusted pilot provenance requires summary artifacts.bundle_dir"
    local_issues=$((local_issues + 1))
  elif [[ -n "$bundle_dir" && "$summary_artifact_bundle_dir" != "$bundle_dir" ]]; then
    echo "trusted pilot provenance requires summary artifacts.bundle_dir to match resolved bundle dir: summary=$summary_artifact_bundle_dir resolved=$bundle_dir"
    local_issues=$((local_issues + 1))
  fi
  if [[ -z "$summary_artifact_summary_json" ]]; then
    echo "trusted pilot provenance requires summary artifacts.summary_json"
    local_issues=$((local_issues + 1))
  elif [[ "$summary_artifact_summary_json" != "$summary_json" ]]; then
    echo "trusted pilot provenance requires summary artifacts.summary_json to match verified summary: summary=$summary_artifact_summary_json verified=$summary_json"
    local_issues=$((local_issues + 1))
  fi
  if [[ -z "$summary_artifact_bundle_tar" ]]; then
    echo "trusted pilot provenance requires summary artifacts.bundle_tar"
    local_issues=$((local_issues + 1))
  elif [[ "$summary_artifact_bundle_tar" != "$bundle_tar" ]]; then
    echo "trusted pilot provenance requires summary artifacts.bundle_tar to match verified tar: summary=$summary_artifact_bundle_tar verified=$bundle_tar"
    local_issues=$((local_issues + 1))
  fi
  if [[ -z "$summary_artifact_bundle_tar_sha256_file" ]]; then
    echo "trusted pilot provenance requires summary artifacts.bundle_tar_sha256_file"
    local_issues=$((local_issues + 1))
  elif [[ "$summary_artifact_bundle_tar_sha256_file" != "$bundle_tar_sha256_file" ]]; then
    echo "trusted pilot provenance requires summary artifacts.bundle_tar_sha256_file to match verified sidecar: summary=$summary_artifact_bundle_tar_sha256_file verified=$bundle_tar_sha256_file"
    local_issues=$((local_issues + 1))
  fi
  if [[ -z "$summary_artifact_provenance_json" ]]; then
    echo "trusted pilot provenance requires summary artifacts.provenance_json"
    local_issues=$((local_issues + 1))
  elif [[ "$summary_artifact_provenance_json" != "$provenance_json" ]]; then
    echo "trusted pilot provenance requires summary artifacts.provenance_json to match verified provenance: summary=$summary_artifact_provenance_json verified=$provenance_json"
    local_issues=$((local_issues + 1))
  fi

  if [[ -n "$summary_artifact_bundle_dir" ]]; then
    for field in \
      "bundled_summary_json:access_bridge_pilot_evidence_bundle_summary.json" \
      "manifest_sha256:manifest.sha256" \
      "smoke_summary_json:access_bridge_service_smoke_summary.json" \
      "deployment_evidence_summary_json:access_bridge_deployment_evidence_summary.json" \
      "host_install_check_summary_json:access_bridge_host_install_check_summary.json"
    do
      expected_path="$summary_artifact_bundle_dir/${field#*:}"
      actual_path="$(abs_path "$(summary_artifact_string "$file" "${field%%:*}")")"
      if [[ -z "$actual_path" ]]; then
        echo "trusted pilot provenance requires summary artifacts.${field%%:*}"
        local_issues=$((local_issues + 1))
      elif [[ "$actual_path" != "$expected_path" ]]; then
        echo "trusted pilot provenance requires summary artifacts.${field%%:*} to point inside the verified bundle: summary=$actual_path expected=$expected_path"
        local_issues=$((local_issues + 1))
      fi
    done
  fi

  ((local_issues == 0))
}

validate_trusted_bundled_evidence_semantics() {
  local bundle_root="$1"
  local source_summary="$2"
  local smoke_json deployment_json host_json semantic_errors
  local expected_base_url expected_helper_id expected_organization_id expected_registry_id

  smoke_json="$bundle_root/access_bridge_service_smoke_summary.json"
  deployment_json="$bundle_root/access_bridge_deployment_evidence_summary.json"
  host_json="$bundle_root/access_bridge_host_install_check_summary.json"

  for required_semantic_json in "$smoke_json" "$deployment_json" "$host_json"; do
    if [[ ! -f "$required_semantic_json" ]]; then
      echo "trusted pilot provenance requires bundled semantic evidence file: $(basename "$required_semantic_json")"
      return 1
    fi
    if ! jq -e . "$required_semantic_json" >/dev/null 2>&1; then
      echo "trusted pilot provenance bundled semantic evidence is not valid JSON: $required_semantic_json"
      return 1
    fi
  done

  expected_base_url="$(json_string "$source_summary" '.inputs.base_url')"
  expected_helper_id="$(json_string "$source_summary" '.expected_identity.helper_id')"
  expected_organization_id="$(json_string "$source_summary" '.expected_identity.organization_id')"
  expected_registry_id="$(json_string "$source_summary" '.expected_identity.registry_id')"

  semantic_errors="$(jq -nr \
    --slurpfile smoke "$smoke_json" \
    --slurpfile deployment "$deployment_json" \
    --slurpfile host "$host_json" \
    --arg expected_base_url "$expected_base_url" \
    --arg expected_helper_id "$expected_helper_id" \
    --arg expected_organization_id "$expected_organization_id" \
    --arg expected_registry_id "$expected_registry_id" '
      def lc($v):
        if ($v | type) == "string" then ($v | ascii_downcase) else "" end;
      def str_eq($v; $expected):
        (($v | type) == "string") and (($v | ascii_downcase) == $expected);
      def rc_ok($v):
        if ($v | has("rc")) then (($v.rc | type) == "number" and $v.rc == 0) else true end;
      def pass_status($v):
        lc($v.status) == "pass" and rc_ok($v);
      def schema_ok($v; $id; $minor):
        (($v.schema.id // "") == $id)
        and (($v.schema.major | type) == "number" and $v.schema.major == 1)
        and (($v.schema.minor | type) == "number" and $v.schema.minor >= $minor);
      def host_from_url($url):
        $url
        | sub("^[A-Za-z][A-Za-z0-9+.-]*://"; "")
        | split("/")[0]
        | split("?")[0]
        | split("#")[0]
        | sub("^.*@"; "")
        | if startswith("[") then sub("^\\["; "") | sub("\\].*$"; "") else sub(":[0-9]+$"; "") end
        | ascii_downcase
        | sub("\\.+$"; "");
      def normalize_remote_ip($ip):
        (($ip // "") | tostring | ascii_downcase | sub("^\\["; "") | sub("\\]$"; ""));
      def ipv4_public_routable($ip):
        normalize_remote_ip($ip) as $ip
        | ($ip | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))
          and (($ip | test("^0\\.")) | not)
          and (($ip | test("^10\\.")) | not)
          and (($ip | test("^127\\.")) | not)
          and (($ip | test("^169\\.254\\.")) | not)
          and (($ip | test("^172\\.(1[6-9]|2[0-9]|3[0-1])\\.")) | not)
          and (($ip | test("^192\\.168\\.")) | not)
          and (($ip | test("^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.")) | not)
          and (($ip | test("^192\\.0\\.(0|2)\\.")) | not)
          and (($ip | test("^192\\.88\\.99\\.")) | not)
          and (($ip | test("^198\\.(1[89]|51\\.100)\\.")) | not)
          and (($ip | test("^203\\.0\\.113\\.")) | not)
          and (($ip | test("^(22[4-9]|23[0-9]|24[0-9]|25[0-5])\\.")) | not);
      def remote_ip_public_routable($ip):
        normalize_remote_ip($ip) as $ip
        | if ($ip == "") then false
          elif ($ip | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")) then ipv4_public_routable($ip)
          elif ($ip | contains(":")) then
            ($ip != "::")
            and ($ip != "::1")
            and (($ip | test("^f[c-d][0-9a-f]*:")) | not)
            and (($ip | test("^fe[89ab][0-9a-f]*:")) | not)
            and (($ip | test("^ff[0-9a-f]*:")) | not)
            and (($ip | test("^2001:0?db8:")) | not)
            and (
              if ($ip | startswith("::ffff:")) then
                ipv4_public_routable($ip | sub("^::ffff:"; ""))
              elif ($ip | startswith("0:0:0:0:0:ffff:")) then
                ipv4_public_routable($ip | sub("^0:0:0:0:0:ffff:"; ""))
              else true
              end
            )
          else false
          end;
      def expected_host:
        host_from_url($expected_base_url);
      def required_host_check_ids:
        [
          "deploy_pack_dir_exists",
          "env_file_exists",
          "wrapper_file_exists",
          "systemd_unit_exists",
          "caddy_example_exists",
          "nginx_example_exists",
          "config_json_exists",
          "config_json_valid",
          "config_local_access_paths_disabled",
          "config_sha256_matches",
          "access_code_gate_configured",
          "query_access_code_disabled",
          "trusted_proxy_headers_enabled",
          "loopback_bind",
          "rate_limit_configured",
          "rate_limit_source_cap_configured",
          "wrapper_hardened_flags",
          "systemd_hardening",
          "caddy_xff_overwrite",
          "nginx_xff_overwrite",
          "caddy_public_host_valid",
          "caddy_public_host_matches_expected",
          "caddy_reverse_proxy_target",
          "nginx_public_host_valid",
          "nginx_public_host_matches_expected",
          "nginx_proxy_pass_target"
        ];
      def all_required_host_checks_pass($h):
        all(required_host_check_ids[]; . as $id | ([ $h.checks[]? | select((.id // "") == $id and lc(.status) == "pass") ] | length) == 1);
      def bounded_num_string($v; $min; $max):
        (($v | type) == "string")
        and ($v | test("^[0-9]+$"))
        and (($v | tonumber) >= $min)
        and (($v | tonumber) <= $max);
      ($smoke[0]) as $s
      | ($deployment[0]) as $d
      | ($host[0]) as $h
      | [
          if ($expected_base_url | test("^https://"; "i") | not) then "trusted pilot provenance requires summary inputs.base_url to be HTTPS" else empty end,
          if ($expected_helper_id == "") then "trusted pilot provenance requires non-empty expected_identity.helper_id" else empty end,
          if ($expected_organization_id == "") then "trusted pilot provenance requires non-empty expected_identity.organization_id" else empty end,
          if ($expected_registry_id == "") then "trusted pilot provenance requires non-empty expected_identity.registry_id" else empty end,
          if schema_ok($s; "access_bridge_service_smoke_summary"; 3) | not then "bundled service smoke summary schema is invalid or too old" else empty end,
          if pass_status($s) | not then "bundled service smoke summary status is not pass" else empty end,
          if (($s.base_url // "") != $expected_base_url) then "bundled service smoke base_url does not match bundle summary" else empty end,
          if ($s.transport.https != true) then "bundled service smoke did not prove HTTPS transport" else empty end,
          if ($s.transport.tls.checked != true or $s.transport.tls.verified != true or (($s.transport.tls.ssl_verify_result // "") != "0")) then "bundled service smoke did not prove verified TLS" else empty end,
          if remote_ip_public_routable($s.transport.health.remote_ip) | not then "bundled service smoke remote IP is missing, invalid, private, or reserved" else empty end,
          if str_eq($s.health.status; "ok") | not then "bundled service smoke health status is not ok" else empty end,
          if ($expected_helper_id != "" and (($s.health.helper_id // "") != $expected_helper_id)) then "bundled service smoke helper_id does not match expected identity" else empty end,
          if ($expected_organization_id != "" and (($s.health.organization_id // "") != $expected_organization_id)) then "bundled service smoke organization_id does not match expected identity" else empty end,
          if ($expected_registry_id != "" and (($s.health.registry_id // "") != $expected_registry_id)) then "bundled service smoke registry_id does not match expected identity" else empty end,
          if ($s.auth.required != true) then "bundled service smoke did not prove access-code auth is required" else empty end,
          if str_eq($s.auth.missing_code_http_status; "401") | not then "bundled service smoke missing-code check did not return 401" else empty end,
          if str_eq($s.auth.wrong_code_http_status; "401") | not then "bundled service smoke wrong-code check did not return 401" else empty end,
          if str_eq($s.auth.valid_code_http_status; "200") | not then "bundled service smoke valid-code check did not return 200" else empty end,
          if str_eq($s.bridge.http_status; "200") | not then "bundled service smoke bridge HTTP status is not 200" else empty end,
          if str_eq($s.bridge.status; "ok") | not then "bundled service smoke bridge status is not ok" else empty end,
          if ($s.bridge.security_headers_ok != true) then "bundled service smoke security headers check failed" else empty end,
          if str_eq($s.abuse.http_status; "202") | not then "bundled service smoke abuse endpoint status is not 202" else empty end,
          if schema_ok($d; "access_bridge_deployment_evidence_summary"; 2) | not then "bundled deployment evidence summary schema is invalid or too old" else empty end,
          if pass_status($d) | not then "bundled deployment evidence summary status is not pass" else empty end,
          if (($d.evidence_scope // "") != "real_helper_https") then "bundled deployment evidence scope is not real_helper_https" else empty end,
          if (($d.smoke.base_url // "") != $expected_base_url) then "bundled deployment evidence base_url does not match bundle summary" else empty end,
          if str_eq($d.smoke.status; "pass") | not then "bundled deployment evidence smoke status is not pass" else empty end,
          if str_eq($d.smoke.evidence_status; "pass") | not then "bundled deployment evidence smoke evidence_status is not pass" else empty end,
          if ($d.smoke.auth_required != true) then "bundled deployment evidence did not prove auth is required" else empty end,
          if str_eq($d.smoke.missing_code_http_status; "401") | not then "bundled deployment evidence missing-code check did not return 401" else empty end,
          if str_eq($d.smoke.wrong_code_http_status; "401") | not then "bundled deployment evidence wrong-code check did not return 401" else empty end,
          if str_eq($d.smoke.valid_code_http_status; "200") | not then "bundled deployment evidence valid-code check did not return 200" else empty end,
          if str_eq($d.smoke.bridge_http_status; "200") | not then "bundled deployment evidence bridge HTTP status is not 200" else empty end,
          if str_eq($d.smoke.bridge_status; "ok") | not then "bundled deployment evidence bridge status is not ok" else empty end,
          if ($d.smoke.bridge_security_headers_ok != true) then "bundled deployment evidence security headers check failed" else empty end,
          if str_eq($d.transport.status; "pass") | not then "bundled deployment evidence transport status is not pass" else empty end,
          if ($d.transport.https != true or $d.transport.tls_checked != true or $d.transport.tls_verified != true or (($d.transport.ssl_verify_result // "") != "0")) then "bundled deployment evidence did not prove verified HTTPS transport" else empty end,
          if remote_ip_public_routable($d.transport.remote_ip) | not then "bundled deployment evidence remote IP is missing, invalid, private, or reserved" else empty end,
          if normalize_remote_ip($d.transport.remote_ip) != normalize_remote_ip($s.transport.health.remote_ip) then "bundled deployment evidence remote IP does not match service smoke remote IP" else empty end,
          if str_eq($d.identity_check.status; "pass") | not then "bundled deployment evidence identity check is not pass" else empty end,
          if ($expected_helper_id != "" and (($d.expected_identity.helper_id // "") != $expected_helper_id or ($d.deployed_identity.helper_id // "") != $expected_helper_id)) then "bundled deployment evidence helper identity does not match expected" else empty end,
          if ($expected_organization_id != "" and (($d.expected_identity.organization_id // "") != $expected_organization_id or ($d.deployed_identity.organization_id // "") != $expected_organization_id)) then "bundled deployment evidence organization identity does not match expected" else empty end,
          if ($expected_registry_id != "" and (($d.expected_identity.registry_id // "") != $expected_registry_id or ($d.deployed_identity.registry_id // "") != $expected_registry_id)) then "bundled deployment evidence registry identity does not match expected" else empty end,
          if str_eq($d.local_files.config.status; "pass") | not then "bundled deployment evidence config file check is not pass" else empty end,
          if str_eq($d.local_files.config.allow_local_access_paths; "false") | not then "bundled deployment evidence allows local access paths" else empty end,
          if str_eq($d.local_files.deploy_pack.status; "pass") | not then "bundled deployment evidence deploy pack check is not pass" else empty end,
          if schema_ok($h; "access_bridge_host_install_check_summary"; 4) | not then "bundled host install check summary schema is invalid or too old" else empty end,
          if pass_status($h) | not then "bundled host install check summary status is not pass" else empty end,
          if (($h.inputs.expected_base_url // "") != $expected_base_url) then "bundled host install expected_base_url does not match bundle summary" else empty end,
          if (($h.observed.expected_public_host // "") != expected_host) then "bundled host install expected public host does not match bundle summary host" else empty end,
          if (($h.summary.checks_fail // -1) != 0) then "bundled host install check has failing checks" else empty end,
          if (($h.summary.checks_total // 0) < (required_host_check_ids | length)) then "bundled host install check is missing required checks" else empty end,
          if all_required_host_checks_pass($h) | not then "bundled host install required checks did not all pass" else empty end,
          if str_eq($h.observed.config_allow_local_access_paths; "false") | not then "bundled host install config allows local access paths" else empty end,
          if str_eq($h.observed.env_allow_unauthenticated_local; "false") | not then "bundled host install allows unauthenticated local access" else empty end,
          if str_eq($h.observed.env_allow_query_code; "false") | not then "bundled host install allows query access code" else empty end,
          if str_eq($h.observed.env_trust_proxy_headers; "true") | not then "bundled host install did not enable trusted proxy headers" else empty end,
          if bounded_num_string($h.observed.env_rps; 1; 20) | not then "bundled host install RPS is missing or outside pilot bounds" else empty end,
          if bounded_num_string($h.observed.env_max_sources; 1; 100000) | not then "bundled host install max-sources is missing or outside pilot bounds" else empty end
        ] | .[]
    ')"
  if [[ -n "$semantic_errors" ]]; then
    printf '%s\n' "$semantic_errors"
    return 1
  fi
  return 0
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
  echo "missing required command: sha256sum or shasum"
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
  printf '%s' "${line%% *}" | tr '[:upper:]' '[:lower:]'
}

sha256_value_or_empty() {
  local file="$1"
  if [[ -n "$file" && -f "$file" ]]; then
    sha256_value "$file"
  else
    printf '%s' ""
  fi
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

trust_store_path_is_dev() {
  local path="${1:-}"
  local canonical
  canonical="$(canonical_path_or_abs "$path")"
  path="${path//\\//}"
  canonical="${canonical//\\//}"
  for path in "$path" "$canonical"; do
    case "$path" in
      */.easy-node-logs/access-recovery-demo/*|*/docs/examples/*|*/examples/access-recovery/*)
        return 0
        ;;
    esac
  done
  return 1
}

trust_store_content_is_dev() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  jq -e '
    [
      .trusted_keys[]?
      | ((.source // "") | tostring | ascii_downcase)
      | select(
          contains("generated demo bundle")
          or contains("demo handoff")
          or contains("demo bundle")
        )
    ]
    | length > 0
  ' "$path" >/dev/null 2>&1
}

rel_path_is_safe() {
  local rel
  rel="$(trim "${1:-}")"
  while [[ "$rel" == ./* ]]; do
    rel="${rel#./}"
  done
  rel="${rel%/}"
  if [[ -z "$rel" || "$rel" == "." || "$rel" == /* ]]; then
    return 1
  fi
  if [[ "$rel" == *\\* || "$rel" =~ ^[A-Za-z]: || "$rel" == //* ]]; then
    return 1
  fi

  local part
  local -a parts=()
  local IFS='/'
  read -r -a parts <<<"$rel"
  for part in "${parts[@]}"; do
    if [[ -z "$part" || "$part" == "." || "$part" == ".." ]]; then
      return 1
    fi
  done
  return 0
}

validate_tar_members_safe() {
  local tarball="$1"
  local entries_file details_file entry line unsafe=0

  entries_file="$(mktemp)"
  details_file="$(mktemp)"
  if ! tar -tzf "$tarball" >"$entries_file"; then
    rm -f "$entries_file" "$details_file"
    echo "failed to list bundle tar members: $tarball"
    return 1
  fi
  if ! tar -tvzf "$tarball" >"$details_file"; then
    rm -f "$entries_file" "$details_file"
    echo "failed to inspect bundle tar member metadata: $tarball"
    return 1
  fi

  while IFS= read -r entry || [[ -n "${entry:-}" ]]; do
    if ! rel_path_is_safe "$entry"; then
      echo "unsafe bundle tar member path: ${entry:-<empty>}"
      unsafe=1
    fi
  done <"$entries_file"

  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    case "${line:0:1}" in
      l|h)
        echo "unsafe bundle tar link member: $line"
        unsafe=1
        ;;
    esac
  done <"$details_file"

  rm -f "$entries_file" "$details_file"
  return "$unsafe"
}

summary_json=""
bundle_dir=""
bundle_tar=""
bundle_tar_sha256_file=""
check_tar_sha256="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_CHECK_TAR_SHA256:-1}"
check_manifest="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_CHECK_MANIFEST:-1}"
check_provenance="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_CHECK_PROVENANCE:-}"
require_trusted_provenance="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_REQUIRE_TRUSTED_PROVENANCE:-0}"
provenance_json=""
trust_store=""
public_key_file=""
allow_dev_trust_store="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_ALLOW_DEV_TRUST_STORE:-0}"
summary_contract_check="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SUMMARY_CONTRACT_CHECK:-1}"
verification_summary_json="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_VERIFICATION_SUMMARY_JSON:-}"
print_verification_summary_json="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_PRINT_VERIFICATION_SUMMARY_JSON:-0}"
show_details="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SHOW_DETAILS:-0}"
bundle_dir_explicit=0
bundle_tar_explicit=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --bundle-dir)
      bundle_dir="${2:-}"
      bundle_dir_explicit=1
      shift 2
      ;;
    --bundle-tar)
      bundle_tar="${2:-}"
      bundle_tar_explicit=1
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
    --provenance-json)
      provenance_json="${2:-}"
      shift 2
      ;;
    --check-provenance)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        check_provenance="${2:-}"
        shift 2
      else
        check_provenance="1"
        shift
      fi
      ;;
    --require-trusted-provenance)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_trusted_provenance="${2:-}"
        shift 2
      else
        require_trusted_provenance="1"
        shift
      fi
      ;;
    --trust-store)
      trust_store="${2:-}"
      shift 2
      ;;
    --public-key-file)
      public_key_file="${2:-}"
      shift 2
      ;;
    --allow-dev-trust-store)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_dev_trust_store="${2:-}"
        shift 2
      else
        allow_dev_trust_store="1"
        shift
      fi
      ;;
    --summary-contract-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        summary_contract_check="${2:-}"
        shift 2
      else
        summary_contract_check="1"
        shift
      fi
      ;;
    --verification-summary-json)
      verification_summary_json="${2:-}"
      shift 2
      ;;
    --print-verification-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_verification_summary_json="${2:-}"
        shift 2
      else
        print_verification_summary_json="1"
        shift
      fi
      ;;
    --show-details)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_details="${2:-}"
        shift 2
      else
        show_details="1"
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

for cmd in bash basename cmp date dirname find grep head jq mkdir mktemp sed sort tar tr; do
  need_cmd "$cmd"
done
detect_sha256_tool
if [[ -z "$check_provenance" ]]; then
  if [[ "$require_trusted_provenance" == "1" || -n "$provenance_json" ]]; then
    check_provenance="1"
  else
    check_provenance="0"
  fi
fi
bool_or_die "--check-tar-sha256" "$check_tar_sha256"
bool_or_die "--check-manifest" "$check_manifest"
bool_or_die "--check-provenance" "$check_provenance"
bool_or_die "--require-trusted-provenance" "$require_trusted_provenance"
bool_or_die "--allow-dev-trust-store" "$allow_dev_trust_store"
bool_or_die "--summary-contract-check" "$summary_contract_check"
bool_or_die "--print-verification-summary-json" "$print_verification_summary_json"
bool_or_die "--show-details" "$show_details"
if [[ "$require_trusted_provenance" == "1" ]]; then
  if [[ "$check_provenance" != "1" ]]; then
    echo "--require-trusted-provenance requires --check-provenance 1"
    exit 2
  fi
  if [[ -z "$(trim "$verification_summary_json")" ]]; then
    echo "--require-trusted-provenance requires --verification-summary-json"
    exit 2
  fi
  if [[ "$check_tar_sha256" != "1" || "$check_manifest" != "1" || "$summary_contract_check" != "1" ]]; then
    echo "--require-trusted-provenance requires tar checksum, manifest, and summary contract checks to remain enabled"
    exit 2
  fi
fi

summary_json="$(abs_path "$summary_json")"
bundle_dir="$(abs_path "$bundle_dir")"
bundle_tar="$(abs_path "$bundle_tar")"
bundle_tar_sha256_file="$(abs_path "$bundle_tar_sha256_file")"
provenance_json="$(abs_path "$provenance_json")"
trust_store="$(abs_path "$trust_store")"
public_key_file="$(abs_path "$public_key_file")"
verification_summary_json="$(abs_path "$verification_summary_json")"

if [[ -n "$summary_json" ]]; then
  if [[ ! -f "$summary_json" ]]; then
    echo "summary JSON not found: $summary_json"
    exit 1
  fi
  if [[ -z "$bundle_dir" ]]; then
    bundle_dir="$(abs_path "$(json_string "$summary_json" '.artifacts.bundle_dir')")"
  fi
  if [[ -z "$bundle_tar" ]]; then
    bundle_tar="$(abs_path "$(json_string "$summary_json" '.artifacts.bundle_tar')")"
  fi
  if [[ -z "$bundle_tar_sha256_file" ]]; then
    bundle_tar_sha256_file="$(abs_path "$(json_string "$summary_json" '.artifacts.bundle_tar_sha256_file')")"
  fi
  if [[ -z "$provenance_json" && "$check_provenance" == "1" ]]; then
    provenance_json="$(abs_path "$(json_string "$summary_json" '.artifacts.provenance_json')")"
  fi
fi

if [[ -z "$bundle_tar" && -n "$bundle_dir" && "$bundle_dir_explicit" != "1" && -f "${bundle_dir}.tar.gz" ]]; then
  bundle_tar="${bundle_dir}.tar.gz"
fi
if [[ -z "$bundle_tar_sha256_file" && -n "$bundle_tar" ]]; then
  bundle_tar_sha256_file="${bundle_tar}.sha256"
fi

if [[ -z "$summary_json" && -z "$bundle_dir" && -z "$bundle_tar" ]]; then
  echo "missing required input: provide --summary-json, --bundle-dir, and/or --bundle-tar"
  exit 2
fi
if [[ "$check_tar_sha256" == "0" && "$check_manifest" == "0" && "$check_provenance" == "0" && ( -z "$summary_json" || "$summary_contract_check" == "0" ) ]]; then
  echo "no checks enabled (set --check-tar-sha256=1, --check-manifest=1, --check-provenance=1, and/or --summary-contract-check=1 with --summary-json)"
  exit 2
fi

tmp_extract_dir=""
cleanup() {
  if [[ -n "$tmp_extract_dir" && -d "$tmp_extract_dir" ]]; then
    rm -rf "$tmp_extract_dir"
  fi
}
trap cleanup EXIT

issues=0
summary_evidence_scope=""
provenance_verify_checked="false"
provenance_verify_status="skipped"
provenance_verify_rc_json="null"
provenance_trusted="false"
provenance_key_id=""
provenance_organization_id=""
provenance_organization_name=""
provenance_trusted_org_id=""
provenance_trusted_org_name=""
provenance_evidence_scope=""
provenance_bundle_tar_name=""
provenance_expires_at_utc=""
tar_sha256_checked="0"
bundled_child_evidence_semantic_ok="false"

write_verification_summary() {
  local status="$1"
  local rc="$2"
  local notes="$3"
  local generated_at_utc check_tar_sha256_json tar_sha256_checked_json check_manifest_json check_provenance_json require_trusted_json
  local summary_contract_check_json provenance_checked_json provenance_trusted_json provenance_source
  local allow_dev_trust_store_json trust_store_sha256 bundled_child_evidence_semantic_ok_json
  local source_summary_sha256 source_base_url source_helper_id source_organization_id source_registry_id
  local source_smoke_summary_json source_deployment_summary_json source_host_summary_json
  local source_smoke_summary_sha256 source_deployment_summary_sha256 source_host_summary_sha256
  local bundled_source_summary_json bundled_smoke_summary_json bundled_deployment_summary_json bundled_host_summary_json

  [[ -n "$verification_summary_json" ]] || return 0

  mkdir -p "$(dirname "$verification_summary_json")"
  generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  check_tar_sha256_json="$( [[ "$check_tar_sha256" == "1" ]] && printf 'true' || printf 'false' )"
  tar_sha256_checked_json="$( [[ "$tar_sha256_checked" == "1" ]] && printf 'true' || printf 'false' )"
  check_manifest_json="$( [[ "$check_manifest" == "1" ]] && printf 'true' || printf 'false' )"
  check_provenance_json="$( [[ "$check_provenance" == "1" ]] && printf 'true' || printf 'false' )"
  require_trusted_json="$( [[ "$require_trusted_provenance" == "1" ]] && printf 'true' || printf 'false' )"
  allow_dev_trust_store_json="$( [[ "$allow_dev_trust_store" == "1" ]] && printf 'true' || printf 'false' )"
  summary_contract_check_json="$( [[ "$summary_contract_check" == "1" ]] && printf 'true' || printf 'false' )"
  bundled_child_evidence_semantic_ok_json="$( [[ "$bundled_child_evidence_semantic_ok" == "true" ]] && printf 'true' || printf 'false' )"
  provenance_checked_json="$( [[ "$provenance_verify_checked" == "true" ]] && printf 'true' || printf 'false' )"
  provenance_trusted_json="$( [[ "$provenance_trusted" == "true" ]] && printf 'true' || printf 'false' )"
  provenance_source="none"
  if [[ -n "$trust_store" ]]; then
    provenance_source="trust_store"
  elif [[ -n "$public_key_file" ]]; then
    provenance_source="public_key_file"
  fi
  source_summary_sha256=""
  source_base_url=""
  source_helper_id=""
  source_organization_id=""
  source_registry_id=""
  source_smoke_summary_json=""
  source_deployment_summary_json=""
  source_host_summary_json=""
  source_smoke_summary_sha256=""
  source_deployment_summary_sha256=""
  source_host_summary_sha256=""
  trust_store_sha256="$(sha256_value_or_empty "$trust_store")"
  bundled_source_summary_json=""
  bundled_smoke_summary_json=""
  bundled_deployment_summary_json=""
  bundled_host_summary_json=""
  if [[ -n "$manifest_bundle_dir" && -d "$manifest_bundle_dir" ]]; then
    bundled_source_summary_json="$manifest_bundle_dir/access_bridge_pilot_evidence_bundle_summary.json"
    bundled_smoke_summary_json="$manifest_bundle_dir/access_bridge_service_smoke_summary.json"
    bundled_deployment_summary_json="$manifest_bundle_dir/access_bridge_deployment_evidence_summary.json"
    bundled_host_summary_json="$manifest_bundle_dir/access_bridge_host_install_check_summary.json"
  fi
  if [[ -n "$summary_json" && -f "$summary_json" ]]; then
    if [[ -f "$bundled_source_summary_json" ]]; then
      source_summary_sha256="$(sha256_value_or_empty "$bundled_source_summary_json")"
    else
      source_summary_sha256="$(sha256_value_or_empty "$summary_json")"
    fi
    source_base_url="$(json_string "$summary_json" '.inputs.base_url')"
    source_helper_id="$(json_string "$summary_json" '.expected_identity.helper_id')"
    source_organization_id="$(json_string "$summary_json" '.expected_identity.organization_id')"
    source_registry_id="$(json_string "$summary_json" '.expected_identity.registry_id')"
    if [[ -f "$bundled_smoke_summary_json" ]]; then
      source_smoke_summary_json="$bundled_smoke_summary_json"
    else
      source_smoke_summary_json="$(abs_path "$(json_string "$summary_json" '.artifacts.smoke_summary_json')")"
    fi
    if [[ -f "$bundled_deployment_summary_json" ]]; then
      source_deployment_summary_json="$bundled_deployment_summary_json"
    else
      source_deployment_summary_json="$(abs_path "$(json_string "$summary_json" '.artifacts.deployment_evidence_summary_json')")"
    fi
    if [[ -f "$bundled_host_summary_json" ]]; then
      source_host_summary_json="$bundled_host_summary_json"
    else
      source_host_summary_json="$(abs_path "$(json_string "$summary_json" '.artifacts.host_install_check_summary_json')")"
    fi
    source_smoke_summary_sha256="$(sha256_value_or_empty "$source_smoke_summary_json")"
    source_deployment_summary_sha256="$(sha256_value_or_empty "$source_deployment_summary_json")"
    source_host_summary_sha256="$(sha256_value_or_empty "$source_host_summary_json")"
  fi

  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg notes "$notes" \
    --arg summary_json "$summary_json" \
    --arg bundle_dir "$bundle_dir" \
    --arg manifest_bundle_dir "$manifest_bundle_dir" \
    --arg bundle_tar "$bundle_tar" \
    --arg bundle_tar_sha256_file "$bundle_tar_sha256_file" \
    --arg provenance_json "$provenance_json" \
    --arg trust_store "$trust_store" \
    --arg public_key_file "$public_key_file" \
    --arg trust_store_sha256 "$trust_store_sha256" \
    --arg summary_evidence_scope "$summary_evidence_scope" \
    --argjson bundled_child_evidence_semantic_ok "$bundled_child_evidence_semantic_ok_json" \
    --argjson check_tar_sha256 "$check_tar_sha256_json" \
    --argjson tar_sha256_checked "$tar_sha256_checked_json" \
    --argjson check_manifest "$check_manifest_json" \
    --argjson check_provenance "$check_provenance_json" \
    --argjson require_trusted_provenance "$require_trusted_json" \
    --argjson allow_dev_trust_store "$allow_dev_trust_store_json" \
    --argjson summary_contract_check "$summary_contract_check_json" \
    --argjson provenance_checked "$provenance_checked_json" \
    --arg provenance_status "$provenance_verify_status" \
    --argjson provenance_rc "$provenance_verify_rc_json" \
    --argjson provenance_trusted "$provenance_trusted_json" \
    --arg provenance_key_id "$provenance_key_id" \
    --arg provenance_organization_id "$provenance_organization_id" \
    --arg provenance_organization_name "$provenance_organization_name" \
    --arg provenance_trusted_org_id "$provenance_trusted_org_id" \
    --arg provenance_trusted_org_name "$provenance_trusted_org_name" \
    --arg provenance_evidence_scope "$provenance_evidence_scope" \
    --arg provenance_bundle_tar_name "$provenance_bundle_tar_name" \
    --arg provenance_expires_at_utc "$provenance_expires_at_utc" \
    --arg provenance_source "$provenance_source" \
    --arg source_summary_sha256 "$source_summary_sha256" \
    --arg source_base_url "$source_base_url" \
    --arg source_helper_id "$source_helper_id" \
    --arg source_organization_id "$source_organization_id" \
    --arg source_registry_id "$source_registry_id" \
    --arg source_smoke_summary_json "$source_smoke_summary_json" \
    --arg source_deployment_summary_json "$source_deployment_summary_json" \
    --arg source_host_summary_json "$source_host_summary_json" \
    --arg source_smoke_summary_sha256 "$source_smoke_summary_sha256" \
    --arg source_deployment_summary_sha256 "$source_deployment_summary_sha256" \
    --arg source_host_summary_sha256 "$source_host_summary_sha256" \
    --arg verification_summary_json "$verification_summary_json" '
      def null_if_empty($v):
        if ($v | type) == "string" and ($v | length) > 0 then $v else null end;
      def trusted_pilot_receipt_ready:
        $status == "pass"
        and $require_trusted_provenance
        and $provenance_checked
        and $provenance_trusted
        and $provenance_status == "pass"
        and $provenance_source == "trust_store"
        and $provenance_evidence_scope == "real_helper_https"
        and $summary_evidence_scope == "real_helper_https"
        and $bundled_child_evidence_semantic_ok
        and $tar_sha256_checked
        and $trust_store != ""
        and $public_key_file == ""
        and ($allow_dev_trust_store | not)
        and $source_helper_id != ""
        and $source_organization_id != ""
        and $source_registry_id != ""
        and $provenance_organization_id == $source_organization_id
        and $provenance_trusted_org_id == $source_organization_id;
      def pilot_handoff_ready:
        trusted_pilot_receipt_ready;
      {
        version: 1,
        schema: {
          id: "access_bridge_pilot_evidence_bundle_verify_summary",
          major: 1,
          minor: 2
        },
        generated_at_utc: $generated_at_utc,
        status: $status,
        rc: $rc,
        pilot_handoff_ready: pilot_handoff_ready,
        trusted_pilot_receipt_ready: trusted_pilot_receipt_ready,
        pilot_handoff_criteria: {
          ready: pilot_handoff_ready,
          trusted_pilot_receipt_ready: trusted_pilot_receipt_ready,
          require_trusted_provenance: $require_trusted_provenance,
          provenance_checked: $provenance_checked,
          provenance_trusted: $provenance_trusted,
          provenance_status: $provenance_status,
          provenance_source: $provenance_source,
          provenance_evidence_scope: null_if_empty($provenance_evidence_scope),
          summary_evidence_scope: null_if_empty($summary_evidence_scope),
          source_helper_id_present: ($source_helper_id != ""),
          source_organization_id_present: ($source_organization_id != ""),
          source_registry_id_present: ($source_registry_id != ""),
          provenance_organization_matches_evidence: ($provenance_organization_id != "" and $source_organization_id != "" and $provenance_organization_id == $source_organization_id),
          trusted_organization_matches_evidence: ($provenance_trusted_org_id != "" and $source_organization_id != "" and $provenance_trusted_org_id == $source_organization_id),
          bundled_child_evidence_semantic_ok: $bundled_child_evidence_semantic_ok,
          trust_store_present: ($trust_store != ""),
          trust_store_sha256_present: ($trust_store_sha256 != ""),
          public_key_file_absent: ($public_key_file == ""),
          dev_trust_store_allowed: $allow_dev_trust_store
        },
        notes: $notes,
        inputs: {
          summary_json: null_if_empty($summary_json),
          bundle_dir: null_if_empty($bundle_dir),
          bundle_tar: null_if_empty($bundle_tar),
          bundle_tar_sha256_file: null_if_empty($bundle_tar_sha256_file),
          provenance_json: null_if_empty($provenance_json),
          trust_store: null_if_empty($trust_store),
          trust_store_sha256: null_if_empty($trust_store_sha256),
          public_key_file: null_if_empty($public_key_file),
          allow_dev_trust_store: $allow_dev_trust_store
        },
        checks: {
          summary_contract: {
            enabled: $summary_contract_check,
            status: (if $summary_contract_check then $status else "skipped" end)
          },
          tar_sha256: {
            enabled: $check_tar_sha256,
            checked: $tar_sha256_checked,
            status: (if ($check_tar_sha256 | not) then "skipped" elif $tar_sha256_checked then $status elif $status == "pass" then "skipped" else $status end)
          },
          manifest: {
            enabled: $check_manifest,
            status: (if $check_manifest then $status else "skipped" end)
          },
          provenance: {
            enabled: $check_provenance,
            required_trusted: $require_trusted_provenance,
            status: $provenance_status
          }
        },
        trusted_provenance: {
          required: $require_trusted_provenance,
          checked: $provenance_checked,
          source: $provenance_source,
          trusted: $provenance_trusted,
          status: $provenance_status,
          rc: $provenance_rc,
          key_id: null_if_empty($provenance_key_id),
          organization_id: null_if_empty($provenance_organization_id),
          organization_name: null_if_empty($provenance_organization_name),
          trusted_org_id: null_if_empty($provenance_trusted_org_id),
          trusted_org_name: null_if_empty($provenance_trusted_org_name),
          evidence_scope: null_if_empty($provenance_evidence_scope),
          summary_evidence_scope: null_if_empty($summary_evidence_scope),
          bundle_tar_name: null_if_empty($provenance_bundle_tar_name),
          expires_at_utc: null_if_empty($provenance_expires_at_utc)
        },
        evidence_binding: {
          source_summary_sha256: null_if_empty($source_summary_sha256),
          base_url: null_if_empty($source_base_url),
          helper_id: null_if_empty($source_helper_id),
          organization_id: null_if_empty($source_organization_id),
          registry_id: null_if_empty($source_registry_id),
          smoke_summary_json: null_if_empty($source_smoke_summary_json),
          smoke_summary_sha256: null_if_empty($source_smoke_summary_sha256),
          deployment_evidence_summary_json: null_if_empty($source_deployment_summary_json),
          deployment_evidence_summary_sha256: null_if_empty($source_deployment_summary_sha256),
          host_install_check_summary_json: null_if_empty($source_host_summary_json),
          host_install_check_summary_sha256: null_if_empty($source_host_summary_sha256)
        },
        artifacts: {
          verification_summary_json: null_if_empty($verification_summary_json),
          source_summary_json: null_if_empty($summary_json),
          bundle_dir: null_if_empty(if $manifest_bundle_dir != "" then $manifest_bundle_dir else $bundle_dir end),
          bundle_tar: null_if_empty($bundle_tar),
          bundle_tar_sha256_file: null_if_empty($bundle_tar_sha256_file),
          provenance_json: null_if_empty($provenance_json)
        }
      }
    ' >"$verification_summary_json"

  if [[ "$print_verification_summary_json" == "1" ]]; then
    cat "$verification_summary_json"
  fi
}

if [[ -n "$summary_json" && "$summary_contract_check" == "1" ]]; then
  summary_evidence_scope="$(json_string "$summary_json" '.evidence_scope')"
  if ! validate_bundle_summary_contract "$summary_json" "external bundle summary"; then
    issues=$((issues + 1))
  fi
  if [[ "$require_trusted_provenance" == "1" && "$summary_evidence_scope" != "real_helper_https" ]]; then
    echo "trusted pilot provenance requires external summary evidence_scope=real_helper_https: actual=${summary_evidence_scope:-<missing>}"
    issues=$((issues + 1))
  fi
  if [[ "$require_trusted_provenance" == "1" ]]; then
    summary_provenance_enabled="$(jq -r 'if (.provenance.enabled // false) == true then "true" else "false" end' "$summary_json" 2>/dev/null || printf '%s' "false")"
    summary_provenance_sidecar="$(json_string "$summary_json" '.provenance.sidecar_json')"
    summary_artifact_provenance="$(json_string "$summary_json" '.artifacts.provenance_json')"
    if [[ "$summary_provenance_enabled" != "true" ]]; then
      echo "trusted pilot provenance requires external summary provenance.enabled=true"
      issues=$((issues + 1))
    fi
    if [[ -z "$summary_provenance_sidecar" ]]; then
      echo "trusted pilot provenance requires external summary provenance.sidecar_json"
      issues=$((issues + 1))
    fi
    if [[ -z "$summary_artifact_provenance" ]]; then
      echo "trusted pilot provenance requires external summary artifacts.provenance_json"
      issues=$((issues + 1))
    fi
    if [[ -n "$summary_provenance_sidecar" && -n "$summary_artifact_provenance" ]]; then
      summary_provenance_sidecar_abs="$(abs_path "$summary_provenance_sidecar")"
      summary_artifact_provenance_abs="$(abs_path "$summary_artifact_provenance")"
      if [[ "$summary_provenance_sidecar_abs" != "$summary_artifact_provenance_abs" ]]; then
        echo "trusted pilot provenance requires matching summary provenance paths: provenance.sidecar_json=$summary_provenance_sidecar artifacts.provenance_json=$summary_artifact_provenance"
        issues=$((issues + 1))
      fi
    fi
    if ! validate_trusted_summary_artifact_bindings "$summary_json"; then
      issues=$((issues + 1))
    fi
  fi
fi
bundle_tar_safe=0

if [[ -n "$bundle_dir" && ! -d "$bundle_dir" ]]; then
  echo "bundle dir not found: $bundle_dir"
  issues=$((issues + 1))
fi

if [[ -n "$bundle_tar" ]]; then
  if [[ ! -f "$bundle_tar" ]]; then
    echo "bundle tar not found: $bundle_tar"
    issues=$((issues + 1))
  elif ! validate_tar_members_safe "$bundle_tar"; then
    echo "refusing unsafe bundle tar: $bundle_tar"
    issues=$((issues + 1))
  else
    bundle_tar_safe=1
    if [[ "$show_details" == "1" ]]; then
      echo "bundle tar members safe: $bundle_tar"
    fi
  fi
elif [[ "$bundle_tar_explicit" == "1" || ( "$check_tar_sha256" == "1" && "$bundle_dir_explicit" != "1" ) ]]; then
  echo "tarball checksum check requested but bundle tar is not resolved"
  issues=$((issues + 1))
fi

if [[ "$check_tar_sha256" == "1" && -n "$bundle_tar" && -f "$bundle_tar" ]]; then
  if [[ -z "$bundle_tar_sha256_file" || ! -f "$bundle_tar_sha256_file" ]]; then
    echo "bundle tar checksum sidecar not found: $bundle_tar_sha256_file"
    issues=$((issues + 1))
  else
    line="$(head -n1 "$bundle_tar_sha256_file" || true)"
    if [[ "$line" =~ ^([A-Fa-f0-9]{64})[[:space:]][[:space:]](.+)$ ]]; then
      expected="${BASH_REMATCH[1],,}"
      sidecar_tar_name="${BASH_REMATCH[2]}"
      expected_tar_name="$(basename "$bundle_tar")"
      actual="$(sha256_value "$bundle_tar")"
      if [[ "$sidecar_tar_name" != "$expected_tar_name" ]]; then
        echo "bundle tar checksum sidecar filename mismatch: expected=$expected_tar_name actual=$sidecar_tar_name"
        issues=$((issues + 1))
      elif [[ "$actual" != "$expected" ]]; then
        echo "bundle tar checksum mismatch: expected=$expected actual=$actual"
        issues=$((issues + 1))
      else
        tar_sha256_checked=1
        if [[ "$show_details" == "1" ]]; then
          echo "bundle tar checksum ok: $bundle_tar"
        fi
      fi
    else
      echo "invalid bundle tar checksum sidecar format: $bundle_tar_sha256_file"
      issues=$((issues + 1))
    fi
  fi
fi

if [[ "$require_trusted_provenance" == "1" && "$tar_sha256_checked" != "1" ]]; then
  echo "trusted pilot provenance requires verified bundle tar checksum"
  issues=$((issues + 1))
fi

manifest_bundle_dir=""
if [[ "$check_manifest" == "1" && "$bundle_tar_safe" == "1" ]]; then
  tmp_extract_dir="$(mktemp -d)"
  if ! tar -xzf "$bundle_tar" -C "$tmp_extract_dir"; then
    echo "failed to extract bundle tar for manifest validation: $bundle_tar"
    issues=$((issues + 1))
  else
    extracted_dir=""
    extracted_top_level_count=0
    extracted_top_level_bad=0
    while IFS= read -r entry; do
      [[ -n "$entry" ]] || continue
      extracted_top_level_count=$((extracted_top_level_count + 1))
      if [[ -d "$entry" && ! -L "$entry" && -z "$extracted_dir" ]]; then
        extracted_dir="$entry"
      else
        extracted_top_level_bad=1
      fi
    done < <(find "$tmp_extract_dir" -mindepth 1 -maxdepth 1 -print | LC_ALL=C sort)
    if ((extracted_top_level_count != 1 || extracted_top_level_bad != 0 || ${#extracted_dir} == 0)); then
      echo "bundle tar must contain exactly one top-level bundle directory and no sibling files: $bundle_tar"
      issues=$((issues + 1))
    else
      manifest_bundle_dir="$extracted_dir"
    fi
  fi
elif [[ "$check_manifest" == "1" ]]; then
  manifest_bundle_dir="$bundle_dir"
fi

if [[ "$check_manifest" == "1" && -n "$manifest_bundle_dir" && -d "$manifest_bundle_dir" ]]; then
  manifest_file="$manifest_bundle_dir/manifest.sha256"
  bundled_summary_json="$manifest_bundle_dir/access_bridge_pilot_evidence_bundle_summary.json"
  if [[ ! -f "$bundled_summary_json" ]]; then
    echo "bundled summary not found: $bundled_summary_json"
    issues=$((issues + 1))
  else
    if ! validate_bundle_summary_contract "$bundled_summary_json" "bundled bundle summary"; then
      issues=$((issues + 1))
    fi
    if [[ -n "$summary_json" && -f "$summary_json" ]] && ! cmp -s "$summary_json" "$bundled_summary_json"; then
      echo "external summary does not match bundled summary: external=$summary_json bundled=$bundled_summary_json"
      issues=$((issues + 1))
    elif [[ "$show_details" == "1" ]]; then
      echo "bundled summary ok: $bundled_summary_json"
    fi
  fi
  if [[ ! -f "$manifest_file" ]]; then
    echo "manifest not found: $manifest_file"
    issues=$((issues + 1))
  else
    declare -A manifest_seen=()
    manifest_count=0
    while IFS= read -r link_path; do
      [[ -n "$link_path" ]] || continue
      echo "unsafe bundle dir link member: ${link_path#$manifest_bundle_dir/}"
      issues=$((issues + 1))
    done < <(find "$manifest_bundle_dir" -type l -print)

    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "$line" ]] && continue
      if [[ "$line" =~ ^([A-Fa-f0-9]{64})[[:space:]][[:space:]](.+)$ ]]; then
        expected="${BASH_REMATCH[1],,}"
        rel_path="${BASH_REMATCH[2]}"
        if ! rel_path_is_safe "$rel_path" || [[ "$rel_path" == "manifest.sha256" ]]; then
          echo "unsafe manifest entry path: $rel_path"
          issues=$((issues + 1))
          continue
        fi
        if [[ -n "${manifest_seen[$rel_path]+x}" ]]; then
          echo "duplicate manifest entry: $rel_path"
          issues=$((issues + 1))
          continue
        fi
        manifest_seen["$rel_path"]=1
        manifest_count=$((manifest_count + 1))
        file_path="$manifest_bundle_dir/$rel_path"
        if [[ -L "$file_path" ]]; then
          echo "manifest entry is a link: $rel_path"
          issues=$((issues + 1))
          continue
        fi
        if [[ ! -f "$file_path" ]]; then
          echo "manifest entry missing file: $rel_path"
          issues=$((issues + 1))
          continue
        fi
        actual="$(sha256_value "$file_path")"
        if [[ "$actual" != "$expected" ]]; then
          echo "manifest checksum mismatch: $rel_path expected=$expected actual=$actual"
          issues=$((issues + 1))
        elif [[ "$show_details" == "1" ]]; then
          echo "manifest checksum ok: $rel_path"
        fi
      else
        echo "invalid manifest line format: $line"
        issues=$((issues + 1))
      fi
    done <"$manifest_file"

    if ((manifest_count == 0)); then
      echo "manifest has no entries: $manifest_file"
      issues=$((issues + 1))
    fi

    while IFS= read -r file_path; do
      [[ -n "$file_path" ]] || continue
      rel_path="${file_path#$manifest_bundle_dir/}"
      [[ "$rel_path" != "manifest.sha256" ]] || continue
      if [[ -z "${manifest_seen[$rel_path]+x}" ]]; then
        echo "bundle file missing from manifest: $rel_path"
        issues=$((issues + 1))
      fi
    done < <(find "$manifest_bundle_dir" -type f -print | LC_ALL=C sort)
  fi
elif [[ "$check_manifest" == "1" ]]; then
  echo "manifest check requested but bundle dir is not resolved"
  issues=$((issues + 1))
fi

if [[ "$require_trusted_provenance" == "1" ]]; then
  if [[ -z "$manifest_bundle_dir" || ! -d "$manifest_bundle_dir" ]]; then
    echo "trusted pilot provenance requires a verified bundle directory for evidence binding"
    issues=$((issues + 1))
  else
    for required_binding_file in \
      access_bridge_pilot_evidence_bundle_summary.json \
      access_bridge_service_smoke_summary.json \
      access_bridge_deployment_evidence_summary.json \
      access_bridge_host_install_check_summary.json
    do
      if [[ ! -f "$manifest_bundle_dir/$required_binding_file" ]]; then
        echo "trusted pilot provenance requires bundled evidence binding file: $required_binding_file"
        issues=$((issues + 1))
      fi
    done
    if [[ -n "$summary_json" && -f "$summary_json" ]]; then
      if validate_trusted_bundled_evidence_semantics "$manifest_bundle_dir" "$summary_json"; then
        bundled_child_evidence_semantic_ok="true"
      else
        issues=$((issues + 1))
      fi
    else
      echo "trusted pilot provenance requires summary JSON for bundled evidence semantic validation"
      issues=$((issues + 1))
    fi
  fi
fi

if [[ "$check_provenance" == "1" ]]; then
  if ! command -v go >/dev/null 2>&1; then
    echo "missing required command for provenance verification: go"
    issues=$((issues + 1))
  fi
  if [[ -z "$provenance_json" ]]; then
    echo "provenance check requested but provenance JSON is not resolved"
    issues=$((issues + 1))
  elif [[ ! -f "$provenance_json" ]]; then
    echo "provenance JSON not found: $provenance_json"
    issues=$((issues + 1))
  fi
  if [[ -z "$summary_json" || ! -f "$summary_json" ]]; then
    echo "provenance check requires --summary-json"
    issues=$((issues + 1))
  fi
  if [[ -z "$bundle_tar" || ! -f "$bundle_tar" ]]; then
    echo "provenance check requires --bundle-tar"
    issues=$((issues + 1))
  fi
  if [[ -z "$bundle_tar_sha256_file" || ! -f "$bundle_tar_sha256_file" ]]; then
    echo "provenance check requires --bundle-tar-sha256-file"
    issues=$((issues + 1))
  fi
  if [[ "$require_trusted_provenance" == "1" ]]; then
    if [[ -n "$public_key_file" ]]; then
      echo "trusted pilot provenance requires --trust-store and does not accept --public-key-file"
      issues=$((issues + 1))
    fi
    if [[ -z "$trust_store" ]]; then
      echo "trusted pilot provenance requires --trust-store"
      issues=$((issues + 1))
    elif [[ ! -f "$trust_store" ]]; then
      echo "trust store not found: $trust_store"
      issues=$((issues + 1))
    elif [[ "$allow_dev_trust_store" != "1" ]] && trust_store_path_is_dev "$trust_store"; then
      echo "trusted pilot provenance rejects local/demo trust-store paths: $trust_store (set --allow-dev-trust-store 1 only for diagnostics)"
      issues=$((issues + 1))
    elif [[ "$allow_dev_trust_store" != "1" ]] && trust_store_content_is_dev "$trust_store"; then
      echo "trusted pilot provenance rejects demo-marked trust-store contents: $trust_store (set --allow-dev-trust-store 1 only for diagnostics)"
      issues=$((issues + 1))
    fi
  else
    if [[ -n "$trust_store" && -n "$public_key_file" ]]; then
      echo "provenance check requires exactly one of --trust-store or --public-key-file, not both"
      issues=$((issues + 1))
    elif [[ -z "$trust_store" && -z "$public_key_file" ]]; then
      echo "provenance check requires --trust-store or --public-key-file"
      issues=$((issues + 1))
    elif [[ -n "$trust_store" && ! -f "$trust_store" ]]; then
      echo "trust store not found: $trust_store"
      issues=$((issues + 1))
    elif [[ -n "$public_key_file" && ! -f "$public_key_file" ]]; then
      echo "public key file not found: $public_key_file"
      issues=$((issues + 1))
    fi
  fi

  if ((issues == 0)); then
    provenance_verify_args=(
      go run ./cmd/gpmrecover provenance-verify
      --provenance "$provenance_json"
      --summary-json "$summary_json"
      --bundle-tar "$bundle_tar"
      --bundle-tar-sha256-file "$bundle_tar_sha256_file"
    )
    if [[ -n "$trust_store" ]]; then
      provenance_verify_args+=(--trust-store "$trust_store")
    else
      provenance_verify_args+=(--public-key-file "$public_key_file")
    fi
    provenance_verify_log="$(mktemp)"
    provenance_verify_checked="true"
    set +e
    "${provenance_verify_args[@]}" >"$provenance_verify_log" 2>&1
    provenance_verify_rc=$?
    provenance_verify_rc_json="$provenance_verify_rc"
    set -e
    if [[ "$provenance_verify_rc" -ne 0 ]]; then
      provenance_verify_status="fail"
      echo "provenance verification failed: $provenance_json"
      sed 's/^/  /' "$provenance_verify_log"
      issues=$((issues + 1))
    else
      provenance_verify_status="pass"
      provenance_trusted="$(jq -r 'if (.trusted // false) == true then "true" else "false" end' "$provenance_verify_log" 2>/dev/null || printf '%s' "false")"
      provenance_evidence_scope="$(jq -r '.evidence_scope // ""' "$provenance_verify_log" 2>/dev/null || true)"
      provenance_key_id="$(jq -r '.key_id // ""' "$provenance_verify_log" 2>/dev/null || true)"
      provenance_organization_id="$(jq -r '.organization_id // ""' "$provenance_verify_log" 2>/dev/null || true)"
      provenance_organization_name="$(jq -r '.organization_name // ""' "$provenance_verify_log" 2>/dev/null || true)"
      provenance_trusted_org_id="$(jq -r '.trusted_org_id // ""' "$provenance_verify_log" 2>/dev/null || true)"
      provenance_trusted_org_name="$(jq -r '.trusted_org_name // ""' "$provenance_verify_log" 2>/dev/null || true)"
      provenance_bundle_tar_name="$(jq -r '.bundle_tar_name // ""' "$provenance_verify_log" 2>/dev/null || true)"
      provenance_expires_at_utc="$(jq -r '.expires_at_utc // ""' "$provenance_verify_log" 2>/dev/null || true)"
      if [[ -n "$summary_evidence_scope" && -n "$provenance_evidence_scope" && "$summary_evidence_scope" != "$provenance_evidence_scope" ]]; then
        echo "provenance evidence_scope does not match summary: summary=$summary_evidence_scope provenance=$provenance_evidence_scope"
        issues=$((issues + 1))
      fi
      if [[ "$require_trusted_provenance" == "1" ]]; then
        summary_expected_organization_id="$(json_string "$summary_json" '.expected_identity.organization_id')"
        if [[ "$provenance_trusted" != "true" ]]; then
          echo "trusted pilot provenance requires trust-store verified provenance"
          issues=$((issues + 1))
        fi
        if [[ "$provenance_evidence_scope" != "real_helper_https" ]]; then
          echo "trusted pilot provenance requires provenance evidence_scope=real_helper_https: actual=${provenance_evidence_scope:-<missing>}"
          issues=$((issues + 1))
        fi
        if [[ -z "$summary_expected_organization_id" ]]; then
          echo "trusted pilot provenance requires non-empty expected_identity.organization_id"
          issues=$((issues + 1))
        else
          if [[ "$provenance_organization_id" != "$summary_expected_organization_id" ]]; then
            echo "trusted pilot provenance organization_id must match evidence organization_id: evidence=$summary_expected_organization_id provenance=${provenance_organization_id:-<missing>}"
            issues=$((issues + 1))
          fi
          if [[ "$provenance_trusted_org_id" != "$summary_expected_organization_id" ]]; then
            echo "trusted pilot provenance trusted_org_id must match evidence organization_id: evidence=$summary_expected_organization_id trusted_org=${provenance_trusted_org_id:-<missing>}"
            issues=$((issues + 1))
          fi
        fi
      fi
      if [[ "$show_details" == "1" ]]; then
        echo "provenance verification ok: $provenance_json"
      fi
    fi
    rm -f "$provenance_verify_log"
  fi
fi

if ((issues > 0)); then
  write_verification_summary "fail" 1 "Access Bridge pilot evidence bundle verification failed"
  echo "[access-bridge-pilot-evidence-bundle-verify] failed (issues=$issues)"
  exit 1
fi

write_verification_summary "pass" 0 "Access Bridge pilot evidence bundle verification passed"
echo "[access-bridge-pilot-evidence-bundle-verify] ok"
if [[ -n "$summary_json" ]]; then
  echo "[access-bridge-pilot-evidence-bundle-verify] summary_json=$summary_json"
fi
if [[ -n "$manifest_bundle_dir" ]]; then
  echo "[access-bridge-pilot-evidence-bundle-verify] bundle_dir=$manifest_bundle_dir"
fi
if [[ -n "$bundle_tar" ]]; then
  echo "[access-bridge-pilot-evidence-bundle-verify] bundle_tar=$bundle_tar"
fi
if [[ "$check_provenance" == "1" && -n "$provenance_json" ]]; then
  echo "[access-bridge-pilot-evidence-bundle-verify] provenance_json=$provenance_json"
fi
