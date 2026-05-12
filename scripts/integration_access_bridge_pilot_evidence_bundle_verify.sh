#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in awk bash cat chmod cp find go grep jq mkdir mktemp sed sha256sum tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access bridge pilot evidence bundle verifier integration failed: missing required command: $cmd"
    exit 2
  fi
done

PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "access bridge pilot evidence bundle verifier integration failed: missing required command: python3 or python"
    exit 2
  fi
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

BUNDLE_DIR="$TMP_DIR/access_bridge_pilot_evidence_bundle"
SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_summary.json"
BUNDLE_TAR="${BUNDLE_DIR}.tar.gz"
BUNDLE_TAR_SHA256_FILE="${BUNDLE_TAR}.sha256"
PROVENANCE_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle.provenance.json"
VERIFY_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_verify_summary.json"
BAD_PROVENANCE_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_bad.provenance.json"
LOCAL_SCOPE_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_local_scope_summary.json"
LOCAL_SCOPE_PROVENANCE_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_local_scope.provenance.json"
NO_PROVENANCE_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_no_provenance_summary.json"
UNSIGNED_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_unsigned_summary.json"
MISMATCHED_PROVENANCE_PATH_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_mismatched_provenance_path_summary.json"
PRIVATE_KEY_FILE="$TMP_DIR/provenance-private.key"
PUBLIC_KEY_FILE="$TMP_DIR/provenance-public.key"
TRUST_STORE="$TMP_DIR/provenance-trust-store.json"
OTHER_PRIVATE_KEY_FILE="$TMP_DIR/other-provenance-private.key"
OTHER_PUBLIC_KEY_FILE="$TMP_DIR/other-provenance-public.key"
OTHER_TRUST_STORE="$TMP_DIR/other-provenance-trust-store.json"
OTHER_PROVENANCE_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_other_org.provenance.json"
DEMO_TRUST_STORE="$TMP_DIR/.easy-node-logs/access-recovery-demo/recovery-trust.json"
DEMO_MARKED_TRUST_STORE="$TMP_DIR/copied-demo-marker-trust-store.json"
DEMO_ID_TRUST_STORE="$TMP_DIR/copied-demo-id-trust-store.json"
mkdir -p "$BUNDLE_DIR/bridge-deploy-pack"
mkdir -p "$(dirname "$DEMO_TRUST_STORE")"
go run ./cmd/gpmrecover gen --private-key-out "$PRIVATE_KEY_FILE" --public-key-out "$PUBLIC_KEY_FILE" >/dev/null
go run ./cmd/gpmrecover trust-add --trust-store "$TRUST_STORE" --org-id pilot-org --org-name "Pilot Org" --public-key-file "$PUBLIC_KEY_FILE" >/dev/null
go run ./cmd/gpmrecover gen --private-key-out "$OTHER_PRIVATE_KEY_FILE" --public-key-out "$OTHER_PUBLIC_KEY_FILE" >/dev/null
go run ./cmd/gpmrecover trust-add --trust-store "$OTHER_TRUST_STORE" --org-id other-org --org-name "Other Org" --public-key-file "$OTHER_PUBLIC_KEY_FILE" >/dev/null
cp "$TRUST_STORE" "$DEMO_TRUST_STORE"
jq '.trusted_keys[0].source = "generated demo bundle"' "$TRUST_STORE" >"$DEMO_MARKED_TRUST_STORE"
jq '.trusted_keys[0].source = "" | .trusted_keys[0].org_id = "freenews-demo" | .trusted_keys[0].name = "FreeNews Demo"' "$TRUST_STORE" >"$DEMO_ID_TRUST_STORE"
NOW_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg generated_at_utc "$NOW_UTC" \
  '{
    version: 1,
    schema: {id: "access_bridge_service_smoke_summary", major: 1, minor: 6},
    generated_at_utc: $generated_at_utc,
    status: "pass",
    notes: "Access bridge service smoke passed",
    base_url: "https://recovery-helper.gpm-pilot.net",
    path_id: "helper-web",
    transport: {
      base_url_scheme: "https",
      base_url_host: "recovery-helper.gpm-pilot.net",
      base_url_port: "443",
      loopback: false,
      https: true,
      health: {effective_url: "https://recovery-helper.gpm-pilot.net/health", remote_ip: "8.8.8.8", remote_port: "443", http_version: "2", time_connect_sec: "0.01", time_appconnect_sec: "0.02", curl_error: ""},
      tls: {checked: true, verified: true, ssl_verify_result: "0"},
      mtls: {
        required: false,
        client_certificate_configured: false,
        client_certificate_used: false,
        local_client_certificate_key_match: "skipped",
        client_certificate_client_auth_eku: "skipped",
        server_leaf_certificate_fetched: "skipped",
        client_certificate_der_sha256: null,
        client_certificate_public_key_sha256: null,
        client_key_public_key_sha256: null,
        server_leaf_certificate_der_sha256: null,
        server_leaf_public_key_sha256: null,
        client_certificate_der_fingerprint_distinct_from_server_leaf: "skipped",
        client_certificate_public_key_fingerprint_distinct_from_server_leaf: "skipped",
        missing_client_certificate_rejected: false,
        missing_client_certificate_same_endpoint: false,
        missing_client_certificate_rejection_signal: false,
        missing_client_certificate_health_http_status: "skipped",
        missing_client_certificate_health_curl_rc: null,
        missing_client_certificate_health_curl_error: "",
        missing_client_certificate_health_effective_url: "",
        missing_client_certificate_health_remote_ip: "",
        missing_client_certificate_health_remote_port: ""
      }
    },
    health: {http_status: "200", status: "ok", helper_id: "helper-pilot", organization_id: "pilot-org", registry_id: "registry-pilot", config_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    auth: {required: true, missing_code_http_status: "401", wrong_code_http_status: "401", valid_code_http_status: "200"},
    bridge: {http_status: "200", status: "ok", security_headers_ok: true},
    abuse: {http_status: "202"}
  }' >"$BUNDLE_DIR/access_bridge_service_smoke_summary.json"
ORIGINAL_SMOKE_SUMMARY_COPY="$TMP_DIR/original_access_bridge_service_smoke_summary.json"
cp "$BUNDLE_DIR/access_bridge_service_smoke_summary.json" "$ORIGINAL_SMOKE_SUMMARY_COPY"
printf '%s\n' 'smoke ok' >"$BUNDLE_DIR/access_bridge_service_smoke.log"
SMOKE_SUMMARY_SHA256="$(sha256sum "$BUNDLE_DIR/access_bridge_service_smoke_summary.json" | awk '{print $1}')"
jq -n \
  --arg generated_at_utc "$NOW_UTC" \
  --arg smoke_summary_sha256 "$SMOKE_SUMMARY_SHA256" \
  '{
    version: 1,
    schema: {id: "access_bridge_deployment_evidence_summary", major: 1, minor: 6},
    generated_at_utc: $generated_at_utc,
    status: "pass",
    evidence_scope: "real_helper_https",
    pilot_handoff_candidate: true,
    notes: "Access bridge deployment evidence is ready for trusted bundle verification before operator handoff",
    smoke: {
      status: "pass",
      schema_id: "access_bridge_service_smoke_summary",
      generated_at_utc: $generated_at_utc,
      summary_sha256: $smoke_summary_sha256,
      auth_required: true,
      missing_code_http_status: "401",
      wrong_code_http_status: "401",
      valid_code_http_status: "200",
      bridge_http_status: "200",
      bridge_status: "ok",
      bridge_security_headers_ok: true,
      evidence_status: "pass",
      base_url: "https://recovery-helper.gpm-pilot.net",
      base_host: "recovery-helper.gpm-pilot.net",
      transport_https: true,
      transport_tls_verified: true,
      transport_mtls_required: false,
      transport_mtls_client_certificate_configured: false,
      transport_mtls_client_certificate_used: false,
      transport_mtls_local_client_certificate_key_match: false,
      transport_mtls_client_certificate_client_auth_eku: false,
      transport_mtls_server_leaf_certificate_fetched: false,
      transport_mtls_client_certificate_der_sha256: "",
      transport_mtls_client_certificate_public_key_sha256: "",
      transport_mtls_client_key_public_key_sha256: "",
      transport_mtls_server_leaf_certificate_der_sha256: "",
      transport_mtls_server_leaf_public_key_sha256: "",
      transport_mtls_client_certificate_der_fingerprint_distinct_from_server_leaf: false,
      transport_mtls_client_certificate_public_key_fingerprint_distinct_from_server_leaf: false,
      transport_mtls_missing_client_certificate_rejected: false,
      transport_mtls_missing_client_certificate_same_endpoint: false,
      transport_mtls_missing_client_certificate_rejection_signal: false,
      path_id: "helper-web",
      config_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    transport: {
      status: "pass",
      base_url_scheme: "https",
      https: true,
      loopback: false,
      tls_checked: true,
      tls_verified: true,
      ssl_verify_result: "0",
      effective_url: "https://recovery-helper.gpm-pilot.net/health",
      remote_ip: "8.8.8.8",
      remote_port: "443",
      http_version: "2",
      time_appconnect_sec: "0.02",
      mtls_required: false,
      mtls_client_certificate_configured: false,
      mtls_client_certificate_used: false,
      mtls_local_client_certificate_key_match: false,
      mtls_client_certificate_client_auth_eku: false,
      mtls_server_leaf_certificate_fetched: false,
      mtls_client_certificate_der_sha256: "",
      mtls_client_certificate_public_key_sha256: "",
      mtls_client_key_public_key_sha256: "",
      mtls_server_leaf_certificate_der_sha256: "",
      mtls_server_leaf_public_key_sha256: "",
      mtls_client_certificate_der_fingerprint_distinct_from_server_leaf: false,
      mtls_client_certificate_public_key_fingerprint_distinct_from_server_leaf: false,
      mtls_missing_client_certificate_rejected: false,
      mtls_missing_client_certificate_same_endpoint: false,
      mtls_missing_client_certificate_rejection_signal: false
    },
    expected_identity: {helper_id: "helper-pilot", organization_id: "pilot-org", registry_id: "registry-pilot"},
    deployed_identity: {helper_id: "helper-pilot", organization_id: "pilot-org", registry_id: "registry-pilot"},
    identity_check: {status: "pass"},
    local_files: {
      config: {supplied: true, status: "pass", valid_json: true, sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", helper_id: "helper-pilot", organization_id: "pilot-org", registry_id: "registry-pilot", allow_local_access_paths: "false"},
      deploy_pack: {supplied: true, status: "pass", exists: true, env: {allow_unauthenticated_local: "false", allow_query_code: "false", trust_proxy_headers: "true", addr: "127.0.0.1:8791"}}
    },
    evidence_binding: {
      smoke_summary_sha256: $smoke_summary_sha256
    }
  }' >"$BUNDLE_DIR/access_bridge_deployment_evidence_summary.json"
jq -n \
  --arg generated_at_utc "$NOW_UTC" \
  '[
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
  ] as $ids
  | {
      version: 1,
      schema: {id: "access_bridge_host_install_check_summary", major: 1, minor: 4},
      generated_at_utc: $generated_at_utc,
      status: "pass",
      notes: "Access bridge host install checks passed",
      inputs: {deploy_pack_dir: "bridge-deploy-pack", service_name: "gpm-access-bridge", config_json: "bridge-service-config.json", expected_base_url: "https://recovery-helper.gpm-pilot.net", expected_public_host: "recovery-helper.gpm-pilot.net"},
      observed: {
        expected_public_host: "recovery-helper.gpm-pilot.net",
        expected_config_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        config_allow_local_access_paths: "false",
        env_config_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        env_access_code_sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        env_allow_unauthenticated_local: "false",
        env_allow_query_code: "false",
        env_trust_proxy_headers: "true",
        env_addr: "127.0.0.1:8791",
        env_rps: "5",
        env_max_sources: "1024",
        caddy_site_host: "recovery-helper.gpm-pilot.net",
        caddy_reverse_proxy: "127.0.0.1:8791",
        nginx_server_name: "recovery-helper.gpm-pilot.net",
        nginx_proxy_pass: "127.0.0.1:8791"
      },
      summary: {checks_total: ($ids | length), checks_fail: 0},
      checks: ($ids | map({id: ., status: "pass", message: "ok"}))
    }' >"$BUNDLE_DIR/access_bridge_host_install_check_summary.json"
printf '%s\n' 'GPM_BRIDGE_ALLOW_QUERY_CODE="false"' >"$BUNDLE_DIR/bridge-deploy-pack/gpm-access-bridge.env"
printf '%s\n' '{"helper_id":"helper-pilot"}' >"$BUNDLE_DIR/bridge-service-config.json"
DEPLOYMENT_SUMMARY_SHA256="$(sha256sum "$BUNDLE_DIR/access_bridge_deployment_evidence_summary.json" | awk '{print $1}')"
HOST_SUMMARY_SHA256="$(sha256sum "$BUNDLE_DIR/access_bridge_host_install_check_summary.json" | awk '{print $1}')"

jq -n \
  --arg generated_at_utc "$NOW_UTC" \
  --arg bundle_dir "$BUNDLE_DIR" \
  --arg bundle_tar "$BUNDLE_TAR" \
  --arg bundle_tar_sha256_file "$BUNDLE_TAR_SHA256_FILE" \
  --arg manifest_sha256 "$BUNDLE_DIR/manifest.sha256" \
  --arg summary_json "$SUMMARY_JSON" \
  --arg bundled_summary_json "$BUNDLE_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$PROVENANCE_JSON" \
  --arg smoke_summary_json "$BUNDLE_DIR/access_bridge_service_smoke_summary.json" \
  --arg deployment_summary_json "$BUNDLE_DIR/access_bridge_deployment_evidence_summary.json" \
  --arg host_summary_json "$BUNDLE_DIR/access_bridge_host_install_check_summary.json" \
  '{
    version: 1,
    schema: {id: "access_bridge_pilot_evidence_bundle_summary", major: 1, minor: 8},
    generated_at_utc: $generated_at_utc,
    status: "pass",
    rc: 0,
    evidence_scope: "real_helper_https",
    summary: {
      steps_total: 3,
      steps_fail: 0
    },
    steps: [
      {id: "service_smoke", status: "pass", rc: 0},
      {id: "deployment_evidence", status: "pass", rc: 0},
      {id: "host_install_check", status: "pass", rc: 0}
    ],
    inputs: {
      base_url: "https://recovery-helper.gpm-pilot.net"
    },
    expected_identity: {
      helper_id: "helper-pilot",
      organization_id: "pilot-org",
      registry_id: "registry-pilot"
    },
    artifacts: {
      bundle_dir: $bundle_dir,
      bundle_tar: $bundle_tar,
      bundle_tar_sha256_file: $bundle_tar_sha256_file,
      manifest_sha256: $manifest_sha256,
      summary_json: $summary_json,
      bundled_summary_json: $bundled_summary_json,
      smoke_summary_json: $smoke_summary_json,
      deployment_evidence_summary_json: $deployment_summary_json,
      host_install_check_summary_json: $host_summary_json,
      provenance_json: $provenance_json
    },
    provenance: {
      enabled: true,
      sidecar_json: $provenance_json,
      key_id: "",
      lifetime_hours: null
    }
  }' >"$SUMMARY_JSON"
cp "$SUMMARY_JSON" "$BUNDLE_DIR/access_bridge_pilot_evidence_bundle_summary.json"

(
  cd "$BUNDLE_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$BUNDLE_DIR/manifest.sha256"

tar -czf "$BUNDLE_TAR" -C "$TMP_DIR" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$BUNDLE_TAR" | awk '{print $1}')" "$(basename "$BUNDLE_TAR")" >"$BUNDLE_TAR_SHA256_FILE"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$SUMMARY_JSON" \
  --bundle-tar "$BUNDLE_TAR" \
  --bundle-tar-sha256-file "$BUNDLE_TAR_SHA256_FILE" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$PROVENANCE_JSON" >/dev/null

bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --summary-json "$SUMMARY_JSON" >"$TMP_DIR/verify-summary.log"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-dir "$BUNDLE_DIR" >"$TMP_DIR/verify-dir.log"
DIR_VERIFY_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_verify_dir_summary.json"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --bundle-dir "$BUNDLE_DIR" \
  --verification-summary-json "$DIR_VERIFY_SUMMARY_JSON" >"$TMP_DIR/verify-dir-summary.log"
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .pilot_handoff_ready == false
  and .handoff_authority == false
  and .authority_level == "integrity_only"
  and .integrity_only == true
  and (.status_meaning | contains("not pilot handoff authority"))
  and .checks.tar_sha256.enabled == false
  and .checks.tar_sha256.checked == false
  and .checks.tar_sha256.status == "skipped"
  and .checks.tar_sha256.skipped_reason == "bundle_dir_only_no_tar"
  and .checks.manifest.enabled == true
  and .checks.manifest.status == "pass"
' "$DIR_VERIFY_SUMMARY_JSON" >/dev/null; then
  echo "access bridge pilot evidence bundle verifier integration failed: bundle-dir receipt implied tar checksum was verified"
  cat "$DIR_VERIFY_SUMMARY_JSON"
  exit 1
fi
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$BUNDLE_TAR" >"$TMP_DIR/verify-tar.log"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --public-key-file "$PUBLIC_KEY_FILE" >"$TMP_DIR/verify-provenance-public-key.log"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --trust-store "$TRUST_STORE" >"$TMP_DIR/verify-provenance-trust-store.log"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --trust-store "$TRUST_STORE" \
  --public-key-file "$PUBLIC_KEY_FILE" >"$TMP_DIR/verify-provenance-dual-key-source.log" 2>&1
dual_key_source_rc=$?
set -e
if [[ "$dual_key_source_rc" -eq 0 ]] || ! grep -Fq 'provenance check requires exactly one of --trust-store or --public-key-file' "$TMP_DIR/verify-provenance-dual-key-source.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: provenance verification accepted dual key sources"
  cat "$TMP_DIR/verify-provenance-dual-key-source.log"
  exit 1
fi
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" >"$TMP_DIR/verify-provenance-trusted-policy-receipt-required.log" 2>&1
trusted_policy_receipt_required_rc=$?
set -e
if [[ "$trusted_policy_receipt_required_rc" -eq 0 ]] || ! grep -Fq -- '--require-trusted-provenance requires --verification-summary-json' "$TMP_DIR/verify-provenance-trusted-policy-receipt-required.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted handoff without verifier receipt"
  cat "$TMP_DIR/verify-provenance-trusted-policy-receipt-required.log"
  exit 1
fi

OLD_BUNDLE_SCHEMA_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_old_schema_summary.json"
jq '.schema.minor = 7' "$SUMMARY_JSON" >"$OLD_BUNDLE_SCHEMA_SUMMARY_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$OLD_BUNDLE_SCHEMA_SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/verify-old-bundle-schema-summary.json" >"$TMP_DIR/verify-old-bundle-schema.log" 2>&1
old_bundle_schema_rc=$?
set -e
if [[ "$old_bundle_schema_rc" -eq 0 ]] ||
  ! grep -Fq 'external bundle summary schema minor is too old' "$TMP_DIR/verify-old-bundle-schema.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted old bundle summary schema"
  cat "$TMP_DIR/verify-old-bundle-schema.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$VERIFY_SUMMARY_JSON" \
  --print-verification-summary-json 1 >"$TMP_DIR/verify-provenance-trusted-policy-explicit.log" 2>&1
trusted_policy_explicit_rc=$?
set -e
if [[ "$trusted_policy_explicit_rc" -eq 0 ]] ||
  ! grep -Fq 'trusted pilot handoff criteria not ready' "$TMP_DIR/verify-provenance-trusted-policy-explicit.log" ||
  ! jq -e '
  .schema.id == "access_bridge_pilot_evidence_bundle_verify_summary"
  and .schema.minor == 6
  and .status == "fail"
  and .rc == 1
  and .pilot_handoff_ready == false
  and .trusted_pilot_receipt_ready == false
  and .handoff_authority == false
  and .authority_level == "trusted_non_handoff"
  and .integrity_only == true
  and (.status_meaning | contains("not pilot handoff authority"))
  and .pilot_handoff_criteria.ready == false
  and .pilot_handoff_criteria.trusted_pilot_receipt_ready == false
  and .pilot_handoff_criteria.bundled_child_evidence_semantic_ok == true
  and .pilot_handoff_criteria.deployment_smoke_summary_sha256_matches_bundle == true
  and .pilot_handoff_criteria.evidence_freshness_checked == true
  and .pilot_handoff_criteria.evidence_freshness_ok == true
  and .pilot_handoff_criteria.evidence_max_age_sec == 604800
  and .pilot_handoff_criteria.installed_host_evidence_present == false
  and .pilot_handoff_criteria.trust_store_sha256_present == true
  and .pilot_handoff_criteria.non_handoff_receipt_allowed == false
  and .checks.summary_contract.enabled == true
  and .checks.tar_sha256.enabled == true
  and .checks.tar_sha256.checked == true
  and .checks.manifest.enabled == true
  and .checks.provenance.enabled == true
  and .trusted_provenance.required == true
  and .trusted_provenance.checked == true
  and .trusted_provenance.source == "trust_store"
  and .trusted_provenance.trusted == true
  and .trusted_provenance.organization_id == "pilot-org"
  and .trusted_provenance.trusted_org_id == "pilot-org"
  and .trusted_provenance.evidence_scope == "real_helper_https"
  and .trusted_provenance.summary_evidence_scope == "real_helper_https"
  and .pilot_handoff_criteria.source_helper_id_present == true
  and .pilot_handoff_criteria.source_organization_id_present == true
  and .pilot_handoff_criteria.source_registry_id_present == true
  and .pilot_handoff_criteria.provenance_organization_matches_evidence == true
  and .pilot_handoff_criteria.trusted_organization_matches_evidence == true
  and (.inputs.trust_store_sha256 | type == "string" and length == 64)
  and .evidence_binding.base_url == "https://recovery-helper.gpm-pilot.net"
  and .evidence_binding.helper_id == "helper-pilot"
  and .evidence_binding.organization_id == "pilot-org"
  and .evidence_binding.registry_id == "registry-pilot"
  and .evidence_binding.smoke_summary_sha256 == "'"$SMOKE_SUMMARY_SHA256"'"
  and .evidence_binding.deployment_smoke_summary_sha256 == "'"$SMOKE_SUMMARY_SHA256"'"
  and .evidence_binding.deployment_evidence_binding_smoke_summary_sha256 == "'"$SMOKE_SUMMARY_SHA256"'"
  and .evidence_binding.deployment_evidence_summary_sha256 == "'"$DEPLOYMENT_SUMMARY_SHA256"'"
  and .evidence_binding.host_install_check_summary_sha256 == "'"$HOST_SUMMARY_SHA256"'"
  and .evidence_binding.host_install_evidence_mode == "deploy-pack"
  and .evidence_freshness.checked == true
  and .evidence_freshness.ok == true
  and .evidence_freshness.max_age_sec == 604800
  and ([.evidence_freshness.details[]? | select(.status == "ok")] | length) == 5
  and .inputs.allow_non_handoff_receipt == false
  and .artifacts.verification_summary_json == "'"$VERIFY_SUMMARY_JSON"'"
  and .artifacts.provenance_json == "'"$PROVENANCE_JSON"'"
' "$VERIFY_SUMMARY_JSON" >/dev/null; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted non-handoff-ready receipt"
  cat "$TMP_DIR/verify-provenance-trusted-policy-explicit.log"
  cat "$VERIFY_SUMMARY_JSON"
  exit 1
fi

SMOKE_HASH_MISMATCH_DIR="$TMP_DIR/access_bridge_pilot_evidence_bundle_smoke_hash_mismatch"
SMOKE_HASH_MISMATCH_SUMMARY="$TMP_DIR/access_bridge_pilot_evidence_bundle_smoke_hash_mismatch_summary.json"
SMOKE_HASH_MISMATCH_TAR="$TMP_DIR/access_bridge_pilot_evidence_bundle_smoke_hash_mismatch.tar.gz"
SMOKE_HASH_MISMATCH_SHA="$SMOKE_HASH_MISMATCH_TAR.sha256"
SMOKE_HASH_MISMATCH_PROVENANCE="$TMP_DIR/access_bridge_pilot_evidence_bundle_smoke_hash_mismatch.provenance.json"
SMOKE_HASH_MISMATCH_VERIFY_SUMMARY="$TMP_DIR/access_bridge_pilot_evidence_bundle_smoke_hash_mismatch_verify_summary.json"
cp -R "$BUNDLE_DIR" "$SMOKE_HASH_MISMATCH_DIR"
jq '.notes = "Access bridge service smoke passed after regenerated receipt"' \
  "$SMOKE_HASH_MISMATCH_DIR/access_bridge_service_smoke_summary.json" \
  >"$SMOKE_HASH_MISMATCH_DIR/access_bridge_service_smoke_summary.json.tmp"
mv "$SMOKE_HASH_MISMATCH_DIR/access_bridge_service_smoke_summary.json.tmp" "$SMOKE_HASH_MISMATCH_DIR/access_bridge_service_smoke_summary.json"
jq \
  --arg bundle_dir "$SMOKE_HASH_MISMATCH_DIR" \
  --arg bundle_tar "$SMOKE_HASH_MISMATCH_TAR" \
  --arg bundle_tar_sha256_file "$SMOKE_HASH_MISMATCH_SHA" \
  --arg manifest_sha256 "$SMOKE_HASH_MISMATCH_DIR/manifest.sha256" \
  --arg summary_json "$SMOKE_HASH_MISMATCH_SUMMARY" \
  --arg bundled_summary_json "$SMOKE_HASH_MISMATCH_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$SMOKE_HASH_MISMATCH_PROVENANCE" \
  --arg smoke_summary_json "$SMOKE_HASH_MISMATCH_DIR/access_bridge_service_smoke_summary.json" \
  --arg deployment_summary_json "$SMOKE_HASH_MISMATCH_DIR/access_bridge_deployment_evidence_summary.json" \
  --arg host_summary_json "$SMOKE_HASH_MISMATCH_DIR/access_bridge_host_install_check_summary.json" \
  '.artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256
    | .artifacts.summary_json = $summary_json
    | .artifacts.bundled_summary_json = $bundled_summary_json
    | .artifacts.provenance_json = $provenance_json
    | .artifacts.smoke_summary_json = $smoke_summary_json
    | .artifacts.deployment_evidence_summary_json = $deployment_summary_json
    | .artifacts.host_install_check_summary_json = $host_summary_json
    | .provenance.sidecar_json = $provenance_json' \
  "$SUMMARY_JSON" >"$SMOKE_HASH_MISMATCH_SUMMARY"
cp "$SMOKE_HASH_MISMATCH_SUMMARY" "$SMOKE_HASH_MISMATCH_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$SMOKE_HASH_MISMATCH_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$SMOKE_HASH_MISMATCH_DIR/manifest.sha256"
tar -czf "$SMOKE_HASH_MISMATCH_TAR" -C "$TMP_DIR" "$(basename "$SMOKE_HASH_MISMATCH_DIR")"
printf '%s  %s\n' "$(sha256sum "$SMOKE_HASH_MISMATCH_TAR" | awk '{print $1}')" "$(basename "$SMOKE_HASH_MISMATCH_TAR")" >"$SMOKE_HASH_MISMATCH_SHA"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$SMOKE_HASH_MISMATCH_SUMMARY" \
  --bundle-tar "$SMOKE_HASH_MISMATCH_TAR" \
  --bundle-tar-sha256-file "$SMOKE_HASH_MISMATCH_SHA" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$SMOKE_HASH_MISMATCH_PROVENANCE" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SMOKE_HASH_MISMATCH_SUMMARY" \
  --provenance-json "$SMOKE_HASH_MISMATCH_PROVENANCE" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$SMOKE_HASH_MISMATCH_VERIFY_SUMMARY" >"$TMP_DIR/trusted-policy-smoke-hash-mismatch.log" 2>&1
smoke_hash_mismatch_rc=$?
set -e
if [[ "$smoke_hash_mismatch_rc" -eq 0 ]] ||
  ! grep -Fq 'bundled deployment evidence smoke summary hash does not match bundled smoke summary' "$TMP_DIR/trusted-policy-smoke-hash-mismatch.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted verifier accepted deployment/smoke hash mismatch"
  cat "$TMP_DIR/trusted-policy-smoke-hash-mismatch.log"
  exit 1
fi

STALE_ROOT="$TMP_DIR/stale-evidence-root"
STALE_DIR="$STALE_ROOT/$(basename "$BUNDLE_DIR")"
STALE_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_stale_summary.json"
STALE_TAR="$TMP_DIR/access_bridge_pilot_evidence_bundle_stale.tar.gz"
STALE_SHA="${STALE_TAR}.sha256"
STALE_PROVENANCE_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_stale.provenance.json"
STALE_VERIFY_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_stale_verify_summary.json"
STALE_UTC="2000-01-01T00:00:00Z"
mkdir -p "$STALE_ROOT"
cp -R "$BUNDLE_DIR" "$STALE_DIR"
for stale_json in \
  "$STALE_DIR/access_bridge_service_smoke_summary.json" \
  "$STALE_DIR/access_bridge_host_install_check_summary.json"
do
  jq --arg stale_utc "$STALE_UTC" '.generated_at_utc = $stale_utc' "$stale_json" >"$stale_json.tmp"
  mv "$stale_json.tmp" "$stale_json"
done
jq --arg stale_utc "$STALE_UTC" '.generated_at_utc = $stale_utc | .smoke.generated_at_utc = $stale_utc' \
  "$STALE_DIR/access_bridge_deployment_evidence_summary.json" >"$STALE_DIR/access_bridge_deployment_evidence_summary.json.tmp"
mv "$STALE_DIR/access_bridge_deployment_evidence_summary.json.tmp" "$STALE_DIR/access_bridge_deployment_evidence_summary.json"
jq \
  --arg stale_utc "$STALE_UTC" \
  --arg bundle_dir "$STALE_DIR" \
  --arg bundle_tar "$STALE_TAR" \
  --arg bundle_tar_sha256_file "$STALE_SHA" \
  --arg manifest_sha256 "$STALE_DIR/manifest.sha256" \
  --arg summary_json "$STALE_SUMMARY_JSON" \
  --arg bundled_summary_json "$STALE_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$STALE_PROVENANCE_JSON" \
  --arg smoke_summary_json "$STALE_DIR/access_bridge_service_smoke_summary.json" \
  --arg deployment_summary_json "$STALE_DIR/access_bridge_deployment_evidence_summary.json" \
  --arg host_summary_json "$STALE_DIR/access_bridge_host_install_check_summary.json" \
  '.generated_at_utc = $stale_utc
    | .artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256
    | .artifacts.summary_json = $summary_json
    | .artifacts.bundled_summary_json = $bundled_summary_json
    | .artifacts.smoke_summary_json = $smoke_summary_json
    | .artifacts.deployment_evidence_summary_json = $deployment_summary_json
    | .artifacts.host_install_check_summary_json = $host_summary_json
    | .artifacts.provenance_json = $provenance_json
    | .provenance.sidecar_json = $provenance_json' \
  "$SUMMARY_JSON" >"$STALE_SUMMARY_JSON"
cp "$STALE_SUMMARY_JSON" "$STALE_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$STALE_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$STALE_DIR/manifest.sha256"
tar -czf "$STALE_TAR" -C "$STALE_ROOT" "$(basename "$STALE_DIR")"
printf '%s  %s\n' "$(sha256sum "$STALE_TAR" | awk '{print $1}')" "$(basename "$STALE_TAR")" >"$STALE_SHA"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$STALE_SUMMARY_JSON" \
  --bundle-tar "$STALE_TAR" \
  --bundle-tar-sha256-file "$STALE_SHA" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$STALE_PROVENANCE_JSON" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$STALE_SUMMARY_JSON" \
  --provenance-json "$STALE_PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$STALE_VERIFY_SUMMARY_JSON" \
  --print-verification-summary-json 1 >"$TMP_DIR/verify-stale-trusted-policy.log" 2>&1
stale_verify_rc=$?
set -e
if [[ "$stale_verify_rc" -eq 0 ]] ||
  ! jq -e '
    .status == "fail"
    and .pilot_handoff_ready == false
    and .pilot_handoff_criteria.evidence_freshness_checked == true
    and .pilot_handoff_criteria.evidence_freshness_ok == false
    and .checks.evidence_freshness.status == "fail"
    and ([.evidence_freshness.details[]? | select(.stale == true and .status == "fail")] | length) >= 4
  ' "$STALE_VERIFY_SUMMARY_JSON" >/dev/null; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted verifier accepted stale bundled evidence"
  cat "$TMP_DIR/verify-stale-trusted-policy.log"
  if [[ -f "$STALE_VERIFY_SUMMARY_JSON" ]]; then
    cat "$STALE_VERIFY_SUMMARY_JSON"
  fi
  exit 1
fi

MTLS_REQUIRED_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_mtls_required_missing_proof_summary.json"
MTLS_REQUIRED_PROVENANCE_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_mtls_required_missing_proof.provenance.json"
MTLS_REQUIRED_VERIFY_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_mtls_required_missing_proof_verify_summary.json"
jq '.schema.minor = 8 | .evidence_policy.require_mtls = true' "$SUMMARY_JSON" >"$MTLS_REQUIRED_SUMMARY_JSON"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$MTLS_REQUIRED_SUMMARY_JSON" \
  --bundle-tar "$BUNDLE_TAR" \
  --bundle-tar-sha256-file "$BUNDLE_TAR_SHA256_FILE" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$MTLS_REQUIRED_PROVENANCE_JSON" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$MTLS_REQUIRED_SUMMARY_JSON" \
  --provenance-json "$MTLS_REQUIRED_PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$MTLS_REQUIRED_VERIFY_SUMMARY_JSON" \
  --print-verification-summary-json 1 >"$TMP_DIR/verify-mtls-required-missing-proof.log" 2>&1
mtls_required_missing_proof_rc=$?
set -e
if [[ "$mtls_required_missing_proof_rc" -eq 0 ]] ||
  ! grep -Eq -- 'did not prove mTLS client certificate/key match|did not prove mTLS clientAuth EKU|did not fetch the mTLS server leaf certificate|did not prove no-client-certificate rejection|did not prove a client-certificate rejection signal' "$TMP_DIR/verify-mtls-required-missing-proof.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted verifier accepted require-mtls summary without mTLS proof"
  cat "$TMP_DIR/verify-mtls-required-missing-proof.log"
  if [[ -f "$MTLS_REQUIRED_VERIFY_SUMMARY_JSON" ]]; then
    cat "$MTLS_REQUIRED_VERIFY_SUMMARY_JSON"
  fi
  exit 1
fi

MTLS_SUCCESS_NO_CLIENT_ROOT="$TMP_DIR/mtls-success-no-client-root"
MTLS_SUCCESS_NO_CLIENT_DIR="$MTLS_SUCCESS_NO_CLIENT_ROOT/$(basename "$BUNDLE_DIR")"
MTLS_SUCCESS_NO_CLIENT_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_mtls_success_no_client_summary.json"
MTLS_SUCCESS_NO_CLIENT_TAR="$TMP_DIR/mtls-success-no-client.tar.gz"
MTLS_SUCCESS_NO_CLIENT_SHA="${MTLS_SUCCESS_NO_CLIENT_TAR}.sha256"
MTLS_SUCCESS_NO_CLIENT_PROVENANCE_JSON="$TMP_DIR/mtls-success-no-client.provenance.json"
MTLS_SUCCESS_NO_CLIENT_VERIFY_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_mtls_success_no_client_verify_summary.json"
mkdir -p "$MTLS_SUCCESS_NO_CLIENT_ROOT"
cp -R "$BUNDLE_DIR" "$MTLS_SUCCESS_NO_CLIENT_DIR"
jq '
  .transport.mtls.required = true
  | .transport.mtls.client_certificate_configured = true
  | .transport.mtls.client_certificate_used = true
  | .transport.mtls.local_client_certificate_key_match = true
  | .transport.mtls.client_certificate_client_auth_eku = true
  | .transport.mtls.server_leaf_certificate_fetched = true
  | .transport.mtls.client_certificate_der_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
  | .transport.mtls.client_certificate_public_key_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
  | .transport.mtls.client_key_public_key_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
  | .transport.mtls.server_leaf_certificate_der_sha256 = "3333333333333333333333333333333333333333333333333333333333333333"
  | .transport.mtls.server_leaf_public_key_sha256 = "4444444444444444444444444444444444444444444444444444444444444444"
  | .transport.mtls.client_certificate_der_fingerprint_distinct_from_server_leaf = true
  | .transport.mtls.client_certificate_public_key_fingerprint_distinct_from_server_leaf = true
  | .transport.mtls.missing_client_certificate_rejected = true
  | .transport.mtls.missing_client_certificate_same_endpoint = true
  | .transport.mtls.missing_client_certificate_rejection_signal = true
  | .transport.mtls.missing_client_certificate_health_http_status = "200"
' "$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_service_smoke_summary.json" >"$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_service_smoke_summary.json.tmp"
mv "$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_service_smoke_summary.json.tmp" "$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_service_smoke_summary.json"
jq '
  .smoke.transport_mtls_required = true
  | .smoke.transport_mtls_client_certificate_configured = true
  | .smoke.transport_mtls_client_certificate_used = true
  | .smoke.transport_mtls_local_client_certificate_key_match = true
  | .smoke.transport_mtls_client_certificate_client_auth_eku = true
  | .smoke.transport_mtls_server_leaf_certificate_fetched = true
  | .smoke.transport_mtls_client_certificate_der_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
  | .smoke.transport_mtls_client_certificate_public_key_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
  | .smoke.transport_mtls_client_key_public_key_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
  | .smoke.transport_mtls_server_leaf_certificate_der_sha256 = "3333333333333333333333333333333333333333333333333333333333333333"
  | .smoke.transport_mtls_server_leaf_public_key_sha256 = "4444444444444444444444444444444444444444444444444444444444444444"
  | .smoke.transport_mtls_client_certificate_der_fingerprint_distinct_from_server_leaf = true
  | .smoke.transport_mtls_client_certificate_public_key_fingerprint_distinct_from_server_leaf = true
  | .smoke.transport_mtls_missing_client_certificate_rejected = true
  | .smoke.transport_mtls_missing_client_certificate_same_endpoint = true
  | .smoke.transport_mtls_missing_client_certificate_rejection_signal = true
  | .smoke.transport_mtls_missing_client_certificate_health_http_status = "200"
  | .transport.mtls_required = true
  | .transport.mtls_client_certificate_configured = true
  | .transport.mtls_client_certificate_used = true
  | .transport.mtls_local_client_certificate_key_match = true
  | .transport.mtls_client_certificate_client_auth_eku = true
  | .transport.mtls_server_leaf_certificate_fetched = true
  | .transport.mtls_client_certificate_der_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
  | .transport.mtls_client_certificate_public_key_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
  | .transport.mtls_client_key_public_key_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
  | .transport.mtls_server_leaf_certificate_der_sha256 = "3333333333333333333333333333333333333333333333333333333333333333"
  | .transport.mtls_server_leaf_public_key_sha256 = "4444444444444444444444444444444444444444444444444444444444444444"
  | .transport.mtls_client_certificate_der_fingerprint_distinct_from_server_leaf = true
  | .transport.mtls_client_certificate_public_key_fingerprint_distinct_from_server_leaf = true
  | .transport.mtls_missing_client_certificate_rejected = true
  | .transport.mtls_missing_client_certificate_same_endpoint = true
  | .transport.mtls_missing_client_certificate_rejection_signal = true
  | .transport.mtls_missing_client_certificate_health_http_status = "200"
' "$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_deployment_evidence_summary.json" >"$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_deployment_evidence_summary.json.tmp"
mv "$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_deployment_evidence_summary.json.tmp" "$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_deployment_evidence_summary.json"
jq \
  --arg bundle_dir "$MTLS_SUCCESS_NO_CLIENT_DIR" \
  --arg bundle_tar "$MTLS_SUCCESS_NO_CLIENT_TAR" \
  --arg bundle_tar_sha256_file "$MTLS_SUCCESS_NO_CLIENT_SHA" \
  --arg manifest_sha256 "$MTLS_SUCCESS_NO_CLIENT_DIR/manifest.sha256" \
  --arg summary_json "$MTLS_SUCCESS_NO_CLIENT_SUMMARY_JSON" \
  --arg bundled_summary_json "$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$MTLS_SUCCESS_NO_CLIENT_PROVENANCE_JSON" \
  --arg smoke_summary_json "$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_service_smoke_summary.json" \
  --arg deployment_summary_json "$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_deployment_evidence_summary.json" \
  --arg host_summary_json "$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_host_install_check_summary.json" \
  '.schema.minor = 8
    | .evidence_policy.require_mtls = true
    | .artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256
    | .artifacts.summary_json = $summary_json
    | .artifacts.bundled_summary_json = $bundled_summary_json
    | .artifacts.provenance_json = $provenance_json
    | .artifacts.smoke_summary_json = $smoke_summary_json
    | .artifacts.deployment_evidence_summary_json = $deployment_summary_json
    | .artifacts.host_install_check_summary_json = $host_summary_json
    | .provenance.sidecar_json = $provenance_json' \
  "$SUMMARY_JSON" >"$MTLS_SUCCESS_NO_CLIENT_SUMMARY_JSON"
cp "$MTLS_SUCCESS_NO_CLIENT_SUMMARY_JSON" "$MTLS_SUCCESS_NO_CLIENT_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$MTLS_SUCCESS_NO_CLIENT_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$MTLS_SUCCESS_NO_CLIENT_DIR/manifest.sha256"
tar -czf "$MTLS_SUCCESS_NO_CLIENT_TAR" -C "$MTLS_SUCCESS_NO_CLIENT_ROOT" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$MTLS_SUCCESS_NO_CLIENT_TAR" | awk '{print $1}')" "$(basename "$MTLS_SUCCESS_NO_CLIENT_TAR")" >"$MTLS_SUCCESS_NO_CLIENT_SHA"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$MTLS_SUCCESS_NO_CLIENT_SUMMARY_JSON" \
  --bundle-tar "$MTLS_SUCCESS_NO_CLIENT_TAR" \
  --bundle-tar-sha256-file "$MTLS_SUCCESS_NO_CLIENT_SHA" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$MTLS_SUCCESS_NO_CLIENT_PROVENANCE_JSON" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$MTLS_SUCCESS_NO_CLIENT_SUMMARY_JSON" \
  --provenance-json "$MTLS_SUCCESS_NO_CLIENT_PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$MTLS_SUCCESS_NO_CLIENT_VERIFY_SUMMARY_JSON" \
  --print-verification-summary-json 1 >"$TMP_DIR/verify-mtls-success-no-client.log" 2>&1
mtls_success_no_client_rc=$?
set -e
if [[ "$mtls_success_no_client_rc" -eq 0 ]] ||
  ! grep -Fq 'bundled service smoke mTLS no-client-certificate probe returned a successful HTTP status' "$TMP_DIR/verify-mtls-success-no-client.log" ||
  ! grep -Fq 'bundled deployment evidence mTLS no-client-certificate probe returned a successful HTTP status' "$TMP_DIR/verify-mtls-success-no-client.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted verifier accepted require-mtls summary with successful no-client-certificate probe status"
  cat "$TMP_DIR/verify-mtls-success-no-client.log"
  if [[ -f "$MTLS_SUCCESS_NO_CLIENT_VERIFY_SUMMARY_JSON" ]]; then
    cat "$MTLS_SUCCESS_NO_CLIENT_VERIFY_SUMMARY_JSON"
  fi
  exit 1
fi

MTLS_MISSING_DER_ROOT="$TMP_DIR/mtls-missing-der-root"
MTLS_MISSING_DER_DIR="$MTLS_MISSING_DER_ROOT/$(basename "$BUNDLE_DIR")"
MTLS_MISSING_DER_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_mtls_missing_der_summary.json"
MTLS_MISSING_DER_TAR="$TMP_DIR/mtls-missing-der.tar.gz"
MTLS_MISSING_DER_SHA="${MTLS_MISSING_DER_TAR}.sha256"
MTLS_MISSING_DER_PROVENANCE_JSON="$TMP_DIR/mtls-missing-der.provenance.json"
MTLS_MISSING_DER_VERIFY_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_mtls_missing_der_verify_summary.json"
mkdir -p "$MTLS_MISSING_DER_ROOT"
cp -R "$MTLS_SUCCESS_NO_CLIENT_DIR" "$MTLS_MISSING_DER_DIR"
jq '
  .transport.mtls.client_certificate_der_sha256 = null
  | .transport.mtls.missing_client_certificate_health_http_status = "401"
' "$MTLS_MISSING_DER_DIR/access_bridge_service_smoke_summary.json" >"$MTLS_MISSING_DER_DIR/access_bridge_service_smoke_summary.json.tmp"
mv "$MTLS_MISSING_DER_DIR/access_bridge_service_smoke_summary.json.tmp" "$MTLS_MISSING_DER_DIR/access_bridge_service_smoke_summary.json"
jq '
  .smoke.transport_mtls_client_certificate_der_sha256 = ""
  | .smoke.transport_mtls_missing_client_certificate_health_http_status = "401"
  | .transport.mtls_client_certificate_der_sha256 = ""
  | .transport.mtls_missing_client_certificate_health_http_status = "401"
' "$MTLS_MISSING_DER_DIR/access_bridge_deployment_evidence_summary.json" >"$MTLS_MISSING_DER_DIR/access_bridge_deployment_evidence_summary.json.tmp"
mv "$MTLS_MISSING_DER_DIR/access_bridge_deployment_evidence_summary.json.tmp" "$MTLS_MISSING_DER_DIR/access_bridge_deployment_evidence_summary.json"
jq \
  --arg bundle_dir "$MTLS_MISSING_DER_DIR" \
  --arg bundle_tar "$MTLS_MISSING_DER_TAR" \
  --arg bundle_tar_sha256_file "$MTLS_MISSING_DER_SHA" \
  --arg manifest_sha256 "$MTLS_MISSING_DER_DIR/manifest.sha256" \
  --arg summary_json "$MTLS_MISSING_DER_SUMMARY_JSON" \
  --arg bundled_summary_json "$MTLS_MISSING_DER_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$MTLS_MISSING_DER_PROVENANCE_JSON" \
  --arg smoke_summary_json "$MTLS_MISSING_DER_DIR/access_bridge_service_smoke_summary.json" \
  --arg deployment_summary_json "$MTLS_MISSING_DER_DIR/access_bridge_deployment_evidence_summary.json" \
  --arg host_summary_json "$MTLS_MISSING_DER_DIR/access_bridge_host_install_check_summary.json" \
  '.artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256
    | .artifacts.summary_json = $summary_json
    | .artifacts.bundled_summary_json = $bundled_summary_json
    | .artifacts.provenance_json = $provenance_json
    | .artifacts.smoke_summary_json = $smoke_summary_json
    | .artifacts.deployment_evidence_summary_json = $deployment_summary_json
    | .artifacts.host_install_check_summary_json = $host_summary_json
    | .provenance.sidecar_json = $provenance_json' \
  "$MTLS_SUCCESS_NO_CLIENT_SUMMARY_JSON" >"$MTLS_MISSING_DER_SUMMARY_JSON"
cp "$MTLS_MISSING_DER_SUMMARY_JSON" "$MTLS_MISSING_DER_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$MTLS_MISSING_DER_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$MTLS_MISSING_DER_DIR/manifest.sha256"
tar -czf "$MTLS_MISSING_DER_TAR" -C "$MTLS_MISSING_DER_ROOT" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$MTLS_MISSING_DER_TAR" | awk '{print $1}')" "$(basename "$MTLS_MISSING_DER_TAR")" >"$MTLS_MISSING_DER_SHA"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$MTLS_MISSING_DER_SUMMARY_JSON" \
  --bundle-tar "$MTLS_MISSING_DER_TAR" \
  --bundle-tar-sha256-file "$MTLS_MISSING_DER_SHA" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$MTLS_MISSING_DER_PROVENANCE_JSON" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$MTLS_MISSING_DER_SUMMARY_JSON" \
  --provenance-json "$MTLS_MISSING_DER_PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$MTLS_MISSING_DER_VERIFY_SUMMARY_JSON" \
  --print-verification-summary-json 1 >"$TMP_DIR/verify-mtls-missing-der.log" 2>&1
mtls_missing_der_rc=$?
set -e
if [[ "$mtls_missing_der_rc" -eq 0 ]] ||
  ! grep -Fq 'bundled service smoke mTLS client certificate/key fingerprints are missing or mismatched' "$TMP_DIR/verify-mtls-missing-der.log" ||
  ! grep -Fq 'bundled deployment evidence mTLS client certificate/key fingerprints are missing or mismatched' "$TMP_DIR/verify-mtls-missing-der.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted verifier accepted require-mtls summary with missing client certificate DER fingerprint"
  cat "$TMP_DIR/verify-mtls-missing-der.log"
  if [[ -f "$MTLS_MISSING_DER_VERIFY_SUMMARY_JSON" ]]; then
    cat "$MTLS_MISSING_DER_VERIFY_SUMMARY_JSON"
  fi
  exit 1
fi

INSTALLED_HOST_ROOT="$TMP_DIR/installed-host-root"
INSTALLED_HOST_DIR="$INSTALLED_HOST_ROOT/$(basename "$BUNDLE_DIR")"
INSTALLED_HOST_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_installed_host_summary.json"
INSTALLED_HOST_TAR="$TMP_DIR/installed-host.tar.gz"
INSTALLED_HOST_SHA="${INSTALLED_HOST_TAR}.sha256"
INSTALLED_HOST_PROVENANCE_JSON="$TMP_DIR/installed-host.provenance.json"
INSTALLED_HOST_VERIFY_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_installed_host_verify_summary.json"
mkdir -p "$INSTALLED_HOST_ROOT"
cp -R "$BUNDLE_DIR" "$INSTALLED_HOST_DIR"
jq '
  .schema.minor = 8
  | .inputs.evidence_mode = "installed-host"
  | .inputs.installed_host_mode = true
  | .inputs.install_dir = "/etc/gpm/access-bridge"
  | .inputs.systemd_unit_file = "/etc/systemd/system/gpm-access-bridge.service"
  | .inputs.proxy_kind = "caddy"
  | .inputs.proxy_config_file = "/etc/caddy/Caddyfile.d/gpm-access-bridge.caddy"
  | .inputs.expected_base_url = "https://recovery-helper.gpm-pilot.net"
  | .inputs.expected_public_host = "recovery-helper.gpm-pilot.net"
  | .observed.evidence_mode = "installed-host"
  | .observed.installed_host_mode = true
  | .observed.expected_public_host = "recovery-helper.gpm-pilot.net"
  | .observed.active_env_file = "/etc/gpm/access-bridge/gpm-access-bridge.env"
  | .observed.active_wrapper_file = "/etc/gpm/access-bridge/run-gpm-access-bridge.sh"
  | .observed.active_systemd_unit_file = "/etc/systemd/system/gpm-access-bridge.service"
  | .observed.active_proxy_kind = "caddy"
  | .observed.active_proxy_config_file = "/etc/caddy/Caddyfile.d/gpm-access-bridge.caddy"
  | .observed.active_proxy_public_host = "recovery-helper.gpm-pilot.net"
  | .observed.active_proxy_target = "127.0.0.1:8791"
  | .observed.active_proxy_is_deploy_pack_example = false
  | .observed.systemd_environment_file = "/etc/gpm/access-bridge/gpm-access-bridge.env"
  | .observed.systemd_exec_start = "/etc/gpm/access-bridge/run-gpm-access-bridge.sh"
  | .observed.caddy_site_host = "recovery-helper.gpm-pilot.net"
  | .observed.caddy_reverse_proxy = "127.0.0.1:8791"
  | .summary.evidence_mode = "installed-host"
  | .summary.installed_host_mode = true
  | .summary.active_env_file = "/etc/gpm/access-bridge/gpm-access-bridge.env"
  | .summary.active_wrapper_file = "/etc/gpm/access-bridge/run-gpm-access-bridge.sh"
  | .summary.active_systemd_unit_file = "/etc/systemd/system/gpm-access-bridge.service"
  | .summary.active_proxy_kind = "caddy"
  | .summary.active_proxy_config_file = "/etc/caddy/Caddyfile.d/gpm-access-bridge.caddy"
  | .summary.active_proxy_public_host = "recovery-helper.gpm-pilot.net"
  | .summary.active_proxy_target = "127.0.0.1:8791"
  | .summary.active_proxy_is_deploy_pack_example = false
  | .summary.systemd_environment_file = "/etc/gpm/access-bridge/gpm-access-bridge.env"
  | .summary.systemd_exec_start = "/etc/gpm/access-bridge/run-gpm-access-bridge.sh"
  | .checks += [
      {"id": "install_dir_exists", "status": "pass", "message": "install directory exists"},
      {"id": "active_env_file_exists", "status": "pass", "message": "active env file exists"},
      {"id": "active_wrapper_file_exists", "status": "pass", "message": "active wrapper exists"},
      {"id": "active_systemd_unit_exists", "status": "pass", "message": "active systemd unit exists"},
      {"id": "active_proxy_config_exists", "status": "pass", "message": "active proxy config exists"},
      {"id": "systemd_environment_file_matches_active_env", "status": "pass", "message": "systemd EnvironmentFile matches active env"},
      {"id": "systemd_exec_start_matches_active_wrapper", "status": "pass", "message": "systemd ExecStart matches active wrapper"},
      {"id": "active_proxy_not_deploy_pack_example", "status": "pass", "message": "active proxy config is not a deploy-pack example"},
      {"id": "active_proxy_public_host_valid", "status": "pass", "message": "active proxy public host is valid"},
      {"id": "active_proxy_public_host_matches_expected", "status": "pass", "message": "active proxy public host matches expected host"},
      {"id": "active_proxy_target_matches_env_addr", "status": "pass", "message": "active proxy target matches bridge addr"},
      {"id": "active_proxy_xff_overwrite", "status": "pass", "message": "active proxy overwrites X-Forwarded-For"}
    ]
  | .summary.checks_total = (.checks | length)
' "$INSTALLED_HOST_DIR/access_bridge_host_install_check_summary.json" >"$INSTALLED_HOST_DIR/access_bridge_host_install_check_summary.json.tmp"
mv "$INSTALLED_HOST_DIR/access_bridge_host_install_check_summary.json.tmp" "$INSTALLED_HOST_DIR/access_bridge_host_install_check_summary.json"
INSTALLED_HOST_SUMMARY_SHA256="$(sha256sum "$INSTALLED_HOST_DIR/access_bridge_host_install_check_summary.json" | awk '{print $1}')"
jq \
  --arg bundle_dir "$INSTALLED_HOST_DIR" \
  --arg bundle_tar "$INSTALLED_HOST_TAR" \
  --arg bundle_tar_sha256_file "$INSTALLED_HOST_SHA" \
  --arg manifest_sha256 "$INSTALLED_HOST_DIR/manifest.sha256" \
  --arg summary_json "$INSTALLED_HOST_SUMMARY_JSON" \
  --arg bundled_summary_json "$INSTALLED_HOST_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$INSTALLED_HOST_PROVENANCE_JSON" \
  --arg smoke_summary_json "$INSTALLED_HOST_DIR/access_bridge_service_smoke_summary.json" \
  --arg deployment_summary_json "$INSTALLED_HOST_DIR/access_bridge_deployment_evidence_summary.json" \
  --arg host_summary_json "$INSTALLED_HOST_DIR/access_bridge_host_install_check_summary.json" \
  '.artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256
    | .artifacts.summary_json = $summary_json
    | .artifacts.bundled_summary_json = $bundled_summary_json
    | .artifacts.smoke_summary_json = $smoke_summary_json
    | .artifacts.deployment_evidence_summary_json = $deployment_summary_json
    | .artifacts.host_install_check_summary_json = $host_summary_json
    | .artifacts.provenance_json = $provenance_json
    | .provenance.sidecar_json = $provenance_json' \
  "$SUMMARY_JSON" >"$INSTALLED_HOST_SUMMARY_JSON"
cp "$INSTALLED_HOST_SUMMARY_JSON" "$INSTALLED_HOST_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$INSTALLED_HOST_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$INSTALLED_HOST_DIR/manifest.sha256"
tar -czf "$INSTALLED_HOST_TAR" -C "$INSTALLED_HOST_ROOT" "$(basename "$INSTALLED_HOST_DIR")"
printf '%s  %s\n' "$(sha256sum "$INSTALLED_HOST_TAR" | awk '{print $1}')" "$(basename "$INSTALLED_HOST_TAR")" >"$INSTALLED_HOST_SHA"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$INSTALLED_HOST_SUMMARY_JSON" \
  --bundle-tar "$INSTALLED_HOST_TAR" \
  --bundle-tar-sha256-file "$INSTALLED_HOST_SHA" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$INSTALLED_HOST_PROVENANCE_JSON" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$INSTALLED_HOST_SUMMARY_JSON" \
  --provenance-json "$INSTALLED_HOST_PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$INSTALLED_HOST_VERIFY_SUMMARY_JSON" \
  --print-verification-summary-json 1 >"$TMP_DIR/verify-installed-host-trusted-policy-explicit.log" 2>&1
installed_host_verify_rc=$?
set -e
if [[ "$installed_host_verify_rc" -ne 0 ]]; then
  echo "access bridge pilot evidence bundle verifier integration failed: installed-host verifier command failed"
  cat "$TMP_DIR/verify-installed-host-trusted-policy-explicit.log"
  if [[ -f "$INSTALLED_HOST_VERIFY_SUMMARY_JSON" ]]; then
    cat "$INSTALLED_HOST_VERIFY_SUMMARY_JSON"
  fi
  exit 1
fi
if ! jq -e \
  --arg host_summary_sha256 "$INSTALLED_HOST_SUMMARY_SHA256" '
    .status == "pass"
    and .rc == 0
    and .pilot_handoff_ready == true
    and .handoff_authority == true
    and .authority_level == "pilot_handoff"
    and .integrity_only == false
    and .status_meaning == "trusted pilot handoff authority"
    and .pilot_handoff_criteria.bundled_child_evidence_semantic_ok == true
    and .pilot_handoff_criteria.deployment_smoke_summary_sha256_matches_bundle == true
    and .pilot_handoff_criteria.evidence_freshness_ok == true
    and .pilot_handoff_criteria.installed_host_evidence_present == true
    and .evidence_freshness.ok == true
    and .evidence_binding.deployment_smoke_summary_sha256 == "'"$SMOKE_SUMMARY_SHA256"'"
    and .evidence_binding.deployment_evidence_binding_smoke_summary_sha256 == "'"$SMOKE_SUMMARY_SHA256"'"
    and .evidence_binding.host_install_check_summary_sha256 == $host_summary_sha256
    and .evidence_binding.host_install_evidence_mode == "installed-host"
  ' "$INSTALLED_HOST_VERIFY_SUMMARY_JSON" >/dev/null; then
  echo "access bridge pilot evidence bundle verifier integration failed: installed-host evidence was not accepted"
  cat "$INSTALLED_HOST_VERIFY_SUMMARY_JSON"
  exit 1
fi

for generated_identity_case in \
  "helper|helper-demo|trusted pilot provenance rejects generated demo/example expected_identity.helper_id" \
  "registry|registry-example|trusted pilot provenance rejects generated demo/example expected_identity.registry_id"
do
  IFS='|' read -r generated_identity_field generated_identity_value generated_identity_message <<<"$generated_identity_case"
  GENERATED_IDENTITY_ROOT="$TMP_DIR/generated-identity-${generated_identity_field}-root"
  GENERATED_IDENTITY_DIR="$GENERATED_IDENTITY_ROOT/$(basename "$BUNDLE_DIR")"
  GENERATED_IDENTITY_SUMMARY="$TMP_DIR/generated-identity-${generated_identity_field}-summary.json"
  GENERATED_IDENTITY_TAR="$TMP_DIR/generated-identity-${generated_identity_field}.tar.gz"
  GENERATED_IDENTITY_SHA="${GENERATED_IDENTITY_TAR}.sha256"
  GENERATED_IDENTITY_PROVENANCE="$TMP_DIR/generated-identity-${generated_identity_field}.provenance.json"
  GENERATED_IDENTITY_VERIFY_SUMMARY="$TMP_DIR/generated-identity-${generated_identity_field}-verify-summary.json"
  mkdir -p "$GENERATED_IDENTITY_ROOT"
  cp -R "$INSTALLED_HOST_DIR" "$GENERATED_IDENTITY_DIR"
  case "$generated_identity_field" in
    helper)
      jq --arg value "$generated_identity_value" '.health.helper_id = $value' \
        "$GENERATED_IDENTITY_DIR/access_bridge_service_smoke_summary.json" >"$GENERATED_IDENTITY_DIR/access_bridge_service_smoke_summary.json.tmp"
      mv "$GENERATED_IDENTITY_DIR/access_bridge_service_smoke_summary.json.tmp" "$GENERATED_IDENTITY_DIR/access_bridge_service_smoke_summary.json"
      jq --arg value "$generated_identity_value" '
        .expected_identity.helper_id = $value
        | .deployed_identity.helper_id = $value
        | .local_files.config.helper_id = $value
      ' "$GENERATED_IDENTITY_DIR/access_bridge_deployment_evidence_summary.json" >"$GENERATED_IDENTITY_DIR/access_bridge_deployment_evidence_summary.json.tmp"
      mv "$GENERATED_IDENTITY_DIR/access_bridge_deployment_evidence_summary.json.tmp" "$GENERATED_IDENTITY_DIR/access_bridge_deployment_evidence_summary.json"
      jq \
        --arg value "$generated_identity_value" \
        --arg bundle_dir "$GENERATED_IDENTITY_DIR" \
        --arg bundle_tar "$GENERATED_IDENTITY_TAR" \
        --arg bundle_tar_sha256_file "$GENERATED_IDENTITY_SHA" \
        --arg manifest_sha256 "$GENERATED_IDENTITY_DIR/manifest.sha256" \
        --arg summary_json "$GENERATED_IDENTITY_SUMMARY" \
        --arg bundled_summary_json "$GENERATED_IDENTITY_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
        --arg provenance_json "$GENERATED_IDENTITY_PROVENANCE" \
        --arg smoke_summary_json "$GENERATED_IDENTITY_DIR/access_bridge_service_smoke_summary.json" \
        --arg deployment_summary_json "$GENERATED_IDENTITY_DIR/access_bridge_deployment_evidence_summary.json" \
        --arg host_summary_json "$GENERATED_IDENTITY_DIR/access_bridge_host_install_check_summary.json" \
        '.expected_identity.helper_id = $value
          | .artifacts.bundle_dir = $bundle_dir
          | .artifacts.bundle_tar = $bundle_tar
          | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
          | .artifacts.manifest_sha256 = $manifest_sha256
          | .artifacts.summary_json = $summary_json
          | .artifacts.bundled_summary_json = $bundled_summary_json
          | .artifacts.provenance_json = $provenance_json
          | .provenance.sidecar_json = $provenance_json
          | .artifacts.smoke_summary_json = $smoke_summary_json
          | .artifacts.deployment_evidence_summary_json = $deployment_summary_json
          | .artifacts.host_install_check_summary_json = $host_summary_json' \
        "$INSTALLED_HOST_SUMMARY_JSON" >"$GENERATED_IDENTITY_SUMMARY"
      ;;
    registry)
      jq --arg value "$generated_identity_value" '.health.registry_id = $value' \
        "$GENERATED_IDENTITY_DIR/access_bridge_service_smoke_summary.json" >"$GENERATED_IDENTITY_DIR/access_bridge_service_smoke_summary.json.tmp"
      mv "$GENERATED_IDENTITY_DIR/access_bridge_service_smoke_summary.json.tmp" "$GENERATED_IDENTITY_DIR/access_bridge_service_smoke_summary.json"
      jq --arg value "$generated_identity_value" '
        .expected_identity.registry_id = $value
        | .deployed_identity.registry_id = $value
        | .local_files.config.registry_id = $value
      ' "$GENERATED_IDENTITY_DIR/access_bridge_deployment_evidence_summary.json" >"$GENERATED_IDENTITY_DIR/access_bridge_deployment_evidence_summary.json.tmp"
      mv "$GENERATED_IDENTITY_DIR/access_bridge_deployment_evidence_summary.json.tmp" "$GENERATED_IDENTITY_DIR/access_bridge_deployment_evidence_summary.json"
      jq \
        --arg value "$generated_identity_value" \
        --arg bundle_dir "$GENERATED_IDENTITY_DIR" \
        --arg bundle_tar "$GENERATED_IDENTITY_TAR" \
        --arg bundle_tar_sha256_file "$GENERATED_IDENTITY_SHA" \
        --arg manifest_sha256 "$GENERATED_IDENTITY_DIR/manifest.sha256" \
        --arg summary_json "$GENERATED_IDENTITY_SUMMARY" \
        --arg bundled_summary_json "$GENERATED_IDENTITY_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
        --arg provenance_json "$GENERATED_IDENTITY_PROVENANCE" \
        --arg smoke_summary_json "$GENERATED_IDENTITY_DIR/access_bridge_service_smoke_summary.json" \
        --arg deployment_summary_json "$GENERATED_IDENTITY_DIR/access_bridge_deployment_evidence_summary.json" \
        --arg host_summary_json "$GENERATED_IDENTITY_DIR/access_bridge_host_install_check_summary.json" \
        '.expected_identity.registry_id = $value
          | .artifacts.bundle_dir = $bundle_dir
          | .artifacts.bundle_tar = $bundle_tar
          | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
          | .artifacts.manifest_sha256 = $manifest_sha256
          | .artifacts.summary_json = $summary_json
          | .artifacts.bundled_summary_json = $bundled_summary_json
          | .artifacts.provenance_json = $provenance_json
          | .provenance.sidecar_json = $provenance_json
          | .artifacts.smoke_summary_json = $smoke_summary_json
          | .artifacts.deployment_evidence_summary_json = $deployment_summary_json
          | .artifacts.host_install_check_summary_json = $host_summary_json' \
        "$INSTALLED_HOST_SUMMARY_JSON" >"$GENERATED_IDENTITY_SUMMARY"
      ;;
    *)
      echo "unknown generated identity field: $generated_identity_field"
      exit 2
      ;;
  esac
  cp "$GENERATED_IDENTITY_SUMMARY" "$GENERATED_IDENTITY_DIR/access_bridge_pilot_evidence_bundle_summary.json"
  (
    cd "$GENERATED_IDENTITY_DIR"
    find . -type f -print \
      | sed 's|^\./||' \
      | grep -v '^manifest\.sha256$' \
      | LC_ALL=C sort \
      | while IFS= read -r rel; do
          sha256sum "$rel"
        done
  ) >"$GENERATED_IDENTITY_DIR/manifest.sha256"
  tar -czf "$GENERATED_IDENTITY_TAR" -C "$GENERATED_IDENTITY_ROOT" "$(basename "$GENERATED_IDENTITY_DIR")"
  printf '%s  %s\n' "$(sha256sum "$GENERATED_IDENTITY_TAR" | awk '{print $1}')" "$(basename "$GENERATED_IDENTITY_TAR")" >"$GENERATED_IDENTITY_SHA"
  go run ./cmd/gpmrecover provenance-sign \
    --summary-json "$GENERATED_IDENTITY_SUMMARY" \
    --bundle-tar "$GENERATED_IDENTITY_TAR" \
    --bundle-tar-sha256-file "$GENERATED_IDENTITY_SHA" \
    --private-key-file "$PRIVATE_KEY_FILE" \
    --org-id pilot-org \
    --org-name "Pilot Org" \
    --out "$GENERATED_IDENTITY_PROVENANCE" >/dev/null
  set +e
  bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
    --summary-json "$GENERATED_IDENTITY_SUMMARY" \
    --provenance-json "$GENERATED_IDENTITY_PROVENANCE" \
    --require-trusted-provenance 1 \
    --trust-store "$TRUST_STORE" \
    --verification-summary-json "$GENERATED_IDENTITY_VERIFY_SUMMARY" \
    --print-verification-summary-json 0 >"$TMP_DIR/verify-generated-identity-${generated_identity_field}.log" 2>&1
  generated_identity_rc=$?
  set -e
  if [[ "$generated_identity_rc" -eq 0 ]] || ! grep -Fq "$generated_identity_message" "$TMP_DIR/verify-generated-identity-${generated_identity_field}.log"; then
    echo "access bridge pilot evidence bundle verifier integration failed: generated identity was accepted: $generated_identity_field"
    cat "$TMP_DIR/verify-generated-identity-${generated_identity_field}.log"
    if [[ -f "$GENERATED_IDENTITY_VERIFY_SUMMARY" ]]; then
      cat "$GENERATED_IDENTITY_VERIFY_SUMMARY"
    fi
    exit 1
  fi
done

BAD_PROXY_TARGET_ROOT="$TMP_DIR/installed-host-bad-proxy-target-root"
BAD_PROXY_TARGET_DIR="$BAD_PROXY_TARGET_ROOT/$(basename "$BUNDLE_DIR")"
BAD_PROXY_TARGET_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_bad_proxy_target_summary.json"
BAD_PROXY_TARGET_TAR="$TMP_DIR/installed-host-bad-proxy-target.tar.gz"
BAD_PROXY_TARGET_SHA="${BAD_PROXY_TARGET_TAR}.sha256"
BAD_PROXY_TARGET_PROVENANCE_JSON="$TMP_DIR/installed-host-bad-proxy-target.provenance.json"
BAD_PROXY_TARGET_VERIFY_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_bad_proxy_target_verify_summary.json"
mkdir -p "$BAD_PROXY_TARGET_ROOT"
cp -R "$INSTALLED_HOST_DIR" "$BAD_PROXY_TARGET_DIR"
jq '.observed.active_proxy_target = "127.0.0.1:9999" | .summary.active_proxy_target = "127.0.0.1:9999"' \
  "$BAD_PROXY_TARGET_DIR/access_bridge_host_install_check_summary.json" >"$BAD_PROXY_TARGET_DIR/access_bridge_host_install_check_summary.json.tmp"
mv "$BAD_PROXY_TARGET_DIR/access_bridge_host_install_check_summary.json.tmp" "$BAD_PROXY_TARGET_DIR/access_bridge_host_install_check_summary.json"
jq \
  --arg bundle_dir "$BAD_PROXY_TARGET_DIR" \
  --arg bundle_tar "$BAD_PROXY_TARGET_TAR" \
  --arg bundle_tar_sha256_file "$BAD_PROXY_TARGET_SHA" \
  --arg manifest_sha256 "$BAD_PROXY_TARGET_DIR/manifest.sha256" \
  --arg summary_json "$BAD_PROXY_TARGET_SUMMARY_JSON" \
  --arg bundled_summary_json "$BAD_PROXY_TARGET_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$BAD_PROXY_TARGET_PROVENANCE_JSON" \
  --arg smoke_summary_json "$BAD_PROXY_TARGET_DIR/access_bridge_service_smoke_summary.json" \
  --arg deployment_summary_json "$BAD_PROXY_TARGET_DIR/access_bridge_deployment_evidence_summary.json" \
  --arg host_summary_json "$BAD_PROXY_TARGET_DIR/access_bridge_host_install_check_summary.json" \
  '.artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256
    | .artifacts.summary_json = $summary_json
    | .artifacts.bundled_summary_json = $bundled_summary_json
    | .artifacts.smoke_summary_json = $smoke_summary_json
    | .artifacts.deployment_evidence_summary_json = $deployment_summary_json
    | .artifacts.host_install_check_summary_json = $host_summary_json
    | .artifacts.provenance_json = $provenance_json
    | .provenance.sidecar_json = $provenance_json' \
  "$INSTALLED_HOST_SUMMARY_JSON" >"$BAD_PROXY_TARGET_SUMMARY_JSON"
cp "$BAD_PROXY_TARGET_SUMMARY_JSON" "$BAD_PROXY_TARGET_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$BAD_PROXY_TARGET_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$BAD_PROXY_TARGET_DIR/manifest.sha256"
tar -czf "$BAD_PROXY_TARGET_TAR" -C "$BAD_PROXY_TARGET_ROOT" "$(basename "$BAD_PROXY_TARGET_DIR")"
printf '%s  %s\n' "$(sha256sum "$BAD_PROXY_TARGET_TAR" | awk '{print $1}')" "$(basename "$BAD_PROXY_TARGET_TAR")" >"$BAD_PROXY_TARGET_SHA"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$BAD_PROXY_TARGET_SUMMARY_JSON" \
  --bundle-tar "$BAD_PROXY_TARGET_TAR" \
  --bundle-tar-sha256-file "$BAD_PROXY_TARGET_SHA" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$BAD_PROXY_TARGET_PROVENANCE_JSON" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$BAD_PROXY_TARGET_SUMMARY_JSON" \
  --provenance-json "$BAD_PROXY_TARGET_PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$BAD_PROXY_TARGET_VERIFY_SUMMARY_JSON" \
  --print-verification-summary-json 0 >"$TMP_DIR/verify-installed-host-bad-proxy-target.log" 2>&1
bad_proxy_target_rc=$?
set -e
if [[ "$bad_proxy_target_rc" -eq 0 ]] || ! grep -Fq 'active proxy target does not match env bridge address' "$TMP_DIR/verify-installed-host-bad-proxy-target.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: installed-host active proxy/env mismatch was accepted"
  cat "$TMP_DIR/verify-installed-host-bad-proxy-target.log"
  if [[ -f "$BAD_PROXY_TARGET_VERIFY_SUMMARY_JSON" ]]; then
    cat "$BAD_PROXY_TARGET_VERIFY_SUMMARY_JSON"
  fi
  exit 1
fi

OTHER_ORG_ROOT="$TMP_DIR/other-org-root"
OTHER_ORG_DIR="$OTHER_ORG_ROOT/$(basename "$BUNDLE_DIR")"
OTHER_ORG_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_other_org_summary.json"
OTHER_ORG_TAR="$TMP_DIR/other-org.tar.gz"
OTHER_ORG_SHA="${OTHER_ORG_TAR}.sha256"
mkdir -p "$OTHER_ORG_ROOT"
cp -R "$BUNDLE_DIR" "$OTHER_ORG_DIR"
jq \
  --arg bundle_dir "$OTHER_ORG_DIR" \
  --arg bundle_tar "$OTHER_ORG_TAR" \
  --arg bundle_tar_sha256_file "$OTHER_ORG_SHA" \
  --arg manifest_sha256 "$OTHER_ORG_DIR/manifest.sha256" \
  --arg summary_json "$OTHER_ORG_SUMMARY_JSON" \
  --arg bundled_summary_json "$OTHER_ORG_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$OTHER_PROVENANCE_JSON" \
  --arg smoke_summary_json "$OTHER_ORG_DIR/access_bridge_service_smoke_summary.json" \
  --arg deployment_summary_json "$OTHER_ORG_DIR/access_bridge_deployment_evidence_summary.json" \
  --arg host_summary_json "$OTHER_ORG_DIR/access_bridge_host_install_check_summary.json" \
  '.artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256
    | .artifacts.summary_json = $summary_json
    | .artifacts.bundled_summary_json = $bundled_summary_json
    | .artifacts.provenance_json = $provenance_json
    | .provenance.sidecar_json = $provenance_json
    | .artifacts.smoke_summary_json = $smoke_summary_json
    | .artifacts.deployment_evidence_summary_json = $deployment_summary_json
    | .artifacts.host_install_check_summary_json = $host_summary_json' \
  "$SUMMARY_JSON" >"$OTHER_ORG_SUMMARY_JSON"
cp "$OTHER_ORG_SUMMARY_JSON" "$OTHER_ORG_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$OTHER_ORG_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$OTHER_ORG_DIR/manifest.sha256"
tar -czf "$OTHER_ORG_TAR" -C "$OTHER_ORG_ROOT" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$OTHER_ORG_TAR" | awk '{print $1}')" "$(basename "$OTHER_ORG_TAR")" >"$OTHER_ORG_SHA"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$OTHER_ORG_SUMMARY_JSON" \
  --bundle-tar "$OTHER_ORG_TAR" \
  --bundle-tar-sha256-file "$OTHER_ORG_SHA" \
  --private-key-file "$OTHER_PRIVATE_KEY_FILE" \
  --org-id other-org \
  --org-name "Other Org" \
  --out "$OTHER_PROVENANCE_JSON" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$OTHER_ORG_SUMMARY_JSON" \
  --provenance-json "$OTHER_PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$OTHER_TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/trusted-policy-other-org-summary.json" >"$TMP_DIR/trusted-policy-other-org.log" 2>&1
other_org_rc=$?
set -e
if [[ "$other_org_rc" -eq 0 ]] || ! grep -Fq 'trusted pilot provenance organization_id must match evidence organization_id' "$TMP_DIR/trusted-policy-other-org.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted provenance from a different trusted organization"
  cat "$TMP_DIR/trusted-policy-other-org.log"
  exit 1
fi

MISSING_ORG_ROOT="$TMP_DIR/missing-org-root"
MISSING_ORG_DIR="$MISSING_ORG_ROOT/$(basename "$BUNDLE_DIR")"
MISSING_ORG_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_missing_org_summary.json"
MISSING_ORG_PROVENANCE_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_missing_org.provenance.json"
MISSING_ORG_TAR="$TMP_DIR/missing-org.tar.gz"
MISSING_ORG_SHA="${MISSING_ORG_TAR}.sha256"
mkdir -p "$MISSING_ORG_ROOT"
cp -R "$BUNDLE_DIR" "$MISSING_ORG_DIR"
jq \
  --arg bundle_dir "$MISSING_ORG_DIR" \
  --arg bundle_tar "$MISSING_ORG_TAR" \
  --arg bundle_tar_sha256_file "$MISSING_ORG_SHA" \
  --arg manifest_sha256 "$MISSING_ORG_DIR/manifest.sha256" \
  --arg summary_json "$MISSING_ORG_SUMMARY_JSON" \
  --arg bundled_summary_json "$MISSING_ORG_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$MISSING_ORG_PROVENANCE_JSON" \
  --arg smoke_summary_json "$MISSING_ORG_DIR/access_bridge_service_smoke_summary.json" \
  --arg deployment_summary_json "$MISSING_ORG_DIR/access_bridge_deployment_evidence_summary.json" \
  --arg host_summary_json "$MISSING_ORG_DIR/access_bridge_host_install_check_summary.json" \
  '.artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256
    | .expected_identity.organization_id = ""
    | .artifacts.summary_json = $summary_json
    | .artifacts.bundled_summary_json = $bundled_summary_json
    | .artifacts.provenance_json = $provenance_json
    | .provenance.sidecar_json = $provenance_json
    | .artifacts.smoke_summary_json = $smoke_summary_json
    | .artifacts.deployment_evidence_summary_json = $deployment_summary_json
    | .artifacts.host_install_check_summary_json = $host_summary_json' \
  "$SUMMARY_JSON" >"$MISSING_ORG_SUMMARY_JSON"
cp "$MISSING_ORG_SUMMARY_JSON" "$MISSING_ORG_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$MISSING_ORG_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$MISSING_ORG_DIR/manifest.sha256"
tar -czf "$MISSING_ORG_TAR" -C "$MISSING_ORG_ROOT" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$MISSING_ORG_TAR" | awk '{print $1}')" "$(basename "$MISSING_ORG_TAR")" >"$MISSING_ORG_SHA"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$MISSING_ORG_SUMMARY_JSON" \
  --bundle-tar "$MISSING_ORG_TAR" \
  --bundle-tar-sha256-file "$MISSING_ORG_SHA" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$MISSING_ORG_PROVENANCE_JSON" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$MISSING_ORG_SUMMARY_JSON" \
  --provenance-json "$MISSING_ORG_PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/trusted-policy-missing-org-summary.json" >"$TMP_DIR/trusted-policy-missing-org.log" 2>&1
missing_org_rc=$?
set -e
if [[ "$missing_org_rc" -eq 0 ]] || ! grep -Fq 'trusted pilot provenance requires non-empty expected_identity.organization_id' "$TMP_DIR/trusted-policy-missing-org.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted missing expected organization identity"
  cat "$TMP_DIR/trusted-policy-missing-org.log"
  exit 1
fi

SEMANTIC_BAD_ROOT="$TMP_DIR/semantic-bad-root"
SEMANTIC_BAD_DIR="$SEMANTIC_BAD_ROOT/$(basename "$BUNDLE_DIR")"
SEMANTIC_BAD_SUMMARY="$TMP_DIR/semantic-bad-summary.json"
SEMANTIC_BAD_TAR="$TMP_DIR/semantic-bad.tar.gz"
SEMANTIC_BAD_SHA="${SEMANTIC_BAD_TAR}.sha256"
SEMANTIC_BAD_PROVENANCE="$TMP_DIR/semantic-bad.provenance.json"
mkdir -p "$SEMANTIC_BAD_ROOT"
cp -R "$BUNDLE_DIR" "$SEMANTIC_BAD_DIR"
jq '.auth.required = false' "$SEMANTIC_BAD_DIR/access_bridge_service_smoke_summary.json" >"$SEMANTIC_BAD_DIR/access_bridge_service_smoke_summary.json.tmp"
mv "$SEMANTIC_BAD_DIR/access_bridge_service_smoke_summary.json.tmp" "$SEMANTIC_BAD_DIR/access_bridge_service_smoke_summary.json"
jq \
  --arg bundle_dir "$SEMANTIC_BAD_DIR" \
  --arg bundle_tar "$SEMANTIC_BAD_TAR" \
  --arg bundle_tar_sha256_file "$SEMANTIC_BAD_SHA" \
  --arg manifest_sha256 "$SEMANTIC_BAD_DIR/manifest.sha256" \
  --arg summary_json "$SEMANTIC_BAD_SUMMARY" \
  --arg bundled_summary_json "$SEMANTIC_BAD_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$SEMANTIC_BAD_PROVENANCE" \
  --arg smoke_summary_json "$SEMANTIC_BAD_DIR/access_bridge_service_smoke_summary.json" \
  --arg deployment_summary_json "$SEMANTIC_BAD_DIR/access_bridge_deployment_evidence_summary.json" \
  --arg host_summary_json "$SEMANTIC_BAD_DIR/access_bridge_host_install_check_summary.json" \
  '.artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256
    | .artifacts.summary_json = $summary_json
    | .artifacts.bundled_summary_json = $bundled_summary_json
    | .artifacts.provenance_json = $provenance_json
    | .provenance.sidecar_json = $provenance_json
    | .artifacts.smoke_summary_json = $smoke_summary_json
    | .artifacts.deployment_evidence_summary_json = $deployment_summary_json
    | .artifacts.host_install_check_summary_json = $host_summary_json' \
  "$SUMMARY_JSON" >"$SEMANTIC_BAD_SUMMARY"
cp "$SEMANTIC_BAD_SUMMARY" "$SEMANTIC_BAD_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$SEMANTIC_BAD_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$SEMANTIC_BAD_DIR/manifest.sha256"
tar -czf "$SEMANTIC_BAD_TAR" -C "$SEMANTIC_BAD_ROOT" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$SEMANTIC_BAD_TAR" | awk '{print $1}')" "$(basename "$SEMANTIC_BAD_TAR")" >"$SEMANTIC_BAD_SHA"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$SEMANTIC_BAD_SUMMARY" \
  --bundle-tar "$SEMANTIC_BAD_TAR" \
  --bundle-tar-sha256-file "$SEMANTIC_BAD_SHA" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$SEMANTIC_BAD_PROVENANCE" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SEMANTIC_BAD_SUMMARY" \
  --provenance-json "$SEMANTIC_BAD_PROVENANCE" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/trusted-policy-semantic-bad-summary.json" >"$TMP_DIR/trusted-policy-semantic-bad.log" 2>&1
semantic_bad_rc=$?
set -e
if [[ "$semantic_bad_rc" -eq 0 ]] || ! grep -Fq 'bundled service smoke did not prove access-code auth is required' "$TMP_DIR/trusted-policy-semantic-bad.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted semantically incomplete bundled child evidence"
  cat "$TMP_DIR/trusted-policy-semantic-bad.log"
  exit 1
fi

PRIVATE_REMOTE_IP_ROOT="$TMP_DIR/private-remote-ip-root"
PRIVATE_REMOTE_IP_DIR="$PRIVATE_REMOTE_IP_ROOT/$(basename "$BUNDLE_DIR")"
PRIVATE_REMOTE_IP_SUMMARY="$TMP_DIR/private-remote-ip-summary.json"
PRIVATE_REMOTE_IP_TAR="$TMP_DIR/private-remote-ip.tar.gz"
PRIVATE_REMOTE_IP_SHA="${PRIVATE_REMOTE_IP_TAR}.sha256"
PRIVATE_REMOTE_IP_PROVENANCE="$TMP_DIR/private-remote-ip.provenance.json"
mkdir -p "$PRIVATE_REMOTE_IP_ROOT"
cp -R "$BUNDLE_DIR" "$PRIVATE_REMOTE_IP_DIR"
jq '.transport.health.remote_ip = "10.0.0.8"' \
  "$PRIVATE_REMOTE_IP_DIR/access_bridge_service_smoke_summary.json" >"$PRIVATE_REMOTE_IP_DIR/access_bridge_service_smoke_summary.json.tmp"
mv "$PRIVATE_REMOTE_IP_DIR/access_bridge_service_smoke_summary.json.tmp" "$PRIVATE_REMOTE_IP_DIR/access_bridge_service_smoke_summary.json"
jq '.transport.remote_ip = "10.0.0.8"' \
  "$PRIVATE_REMOTE_IP_DIR/access_bridge_deployment_evidence_summary.json" >"$PRIVATE_REMOTE_IP_DIR/access_bridge_deployment_evidence_summary.json.tmp"
mv "$PRIVATE_REMOTE_IP_DIR/access_bridge_deployment_evidence_summary.json.tmp" "$PRIVATE_REMOTE_IP_DIR/access_bridge_deployment_evidence_summary.json"
jq \
  --arg bundle_dir "$PRIVATE_REMOTE_IP_DIR" \
  --arg bundle_tar "$PRIVATE_REMOTE_IP_TAR" \
  --arg bundle_tar_sha256_file "$PRIVATE_REMOTE_IP_SHA" \
  --arg manifest_sha256 "$PRIVATE_REMOTE_IP_DIR/manifest.sha256" \
  --arg summary_json "$PRIVATE_REMOTE_IP_SUMMARY" \
  --arg bundled_summary_json "$PRIVATE_REMOTE_IP_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$PRIVATE_REMOTE_IP_PROVENANCE" \
  --arg smoke_summary_json "$PRIVATE_REMOTE_IP_DIR/access_bridge_service_smoke_summary.json" \
  --arg deployment_summary_json "$PRIVATE_REMOTE_IP_DIR/access_bridge_deployment_evidence_summary.json" \
  --arg host_summary_json "$PRIVATE_REMOTE_IP_DIR/access_bridge_host_install_check_summary.json" \
  '.artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256
    | .artifacts.summary_json = $summary_json
    | .artifacts.bundled_summary_json = $bundled_summary_json
    | .artifacts.provenance_json = $provenance_json
    | .provenance.sidecar_json = $provenance_json
    | .artifacts.smoke_summary_json = $smoke_summary_json
    | .artifacts.deployment_evidence_summary_json = $deployment_summary_json
    | .artifacts.host_install_check_summary_json = $host_summary_json' \
  "$SUMMARY_JSON" >"$PRIVATE_REMOTE_IP_SUMMARY"
cp "$PRIVATE_REMOTE_IP_SUMMARY" "$PRIVATE_REMOTE_IP_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$PRIVATE_REMOTE_IP_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$PRIVATE_REMOTE_IP_DIR/manifest.sha256"
tar -czf "$PRIVATE_REMOTE_IP_TAR" -C "$PRIVATE_REMOTE_IP_ROOT" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$PRIVATE_REMOTE_IP_TAR" | awk '{print $1}')" "$(basename "$PRIVATE_REMOTE_IP_TAR")" >"$PRIVATE_REMOTE_IP_SHA"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$PRIVATE_REMOTE_IP_SUMMARY" \
  --bundle-tar "$PRIVATE_REMOTE_IP_TAR" \
  --bundle-tar-sha256-file "$PRIVATE_REMOTE_IP_SHA" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$PRIVATE_REMOTE_IP_PROVENANCE" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$PRIVATE_REMOTE_IP_SUMMARY" \
  --provenance-json "$PRIVATE_REMOTE_IP_PROVENANCE" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/trusted-policy-private-remote-ip-summary.json" >"$TMP_DIR/trusted-policy-private-remote-ip.log" 2>&1
private_remote_ip_rc=$?
set -e
if [[ "$private_remote_ip_rc" -eq 0 ]] || ! grep -Fq 'bundled service smoke remote IP is missing, invalid, private, or reserved' "$TMP_DIR/trusted-policy-private-remote-ip.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted private remote IP bundled evidence"
  cat "$TMP_DIR/trusted-policy-private-remote-ip.log"
  exit 1
fi

MISMATCHED_ARTIFACT_POINTER_ROOT="$TMP_DIR/mismatched-artifact-pointer-root"
MISMATCHED_ARTIFACT_POINTER_DIR="$MISMATCHED_ARTIFACT_POINTER_ROOT/$(basename "$BUNDLE_DIR")"
MISMATCHED_ARTIFACT_POINTER_SUMMARY="$TMP_DIR/mismatched-artifact-pointer-summary.json"
MISMATCHED_ARTIFACT_POINTER_TAR="$TMP_DIR/mismatched-artifact-pointer.tar.gz"
MISMATCHED_ARTIFACT_POINTER_SHA="${MISMATCHED_ARTIFACT_POINTER_TAR}.sha256"
MISMATCHED_ARTIFACT_POINTER_PROVENANCE="$TMP_DIR/mismatched-artifact-pointer.provenance.json"
MISMATCHED_ARTIFACT_POINTER_OTHER_SMOKE="$TMP_DIR/other-smoke-summary.json"
mkdir -p "$MISMATCHED_ARTIFACT_POINTER_ROOT"
cp -R "$BUNDLE_DIR" "$MISMATCHED_ARTIFACT_POINTER_DIR"
printf '%s\n' '{"status":"pass","outside_bundle":true}' >"$MISMATCHED_ARTIFACT_POINTER_OTHER_SMOKE"
jq \
  --arg bundle_dir "$MISMATCHED_ARTIFACT_POINTER_DIR" \
  --arg bundle_tar "$MISMATCHED_ARTIFACT_POINTER_TAR" \
  --arg bundle_tar_sha256_file "$MISMATCHED_ARTIFACT_POINTER_SHA" \
  --arg manifest_sha256 "$MISMATCHED_ARTIFACT_POINTER_DIR/manifest.sha256" \
  --arg summary_json "$MISMATCHED_ARTIFACT_POINTER_SUMMARY" \
  --arg bundled_summary_json "$MISMATCHED_ARTIFACT_POINTER_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$MISMATCHED_ARTIFACT_POINTER_PROVENANCE" \
  --arg other_smoke "$MISMATCHED_ARTIFACT_POINTER_OTHER_SMOKE" \
  '.artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256
    | .artifacts.summary_json = $summary_json
    | .artifacts.bundled_summary_json = $bundled_summary_json
    | .artifacts.provenance_json = $provenance_json
    | .provenance.sidecar_json = $provenance_json
    | .artifacts.smoke_summary_json = $other_smoke' \
  "$SUMMARY_JSON" >"$MISMATCHED_ARTIFACT_POINTER_SUMMARY"
cp "$MISMATCHED_ARTIFACT_POINTER_SUMMARY" "$MISMATCHED_ARTIFACT_POINTER_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$MISMATCHED_ARTIFACT_POINTER_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$MISMATCHED_ARTIFACT_POINTER_DIR/manifest.sha256"
tar -czf "$MISMATCHED_ARTIFACT_POINTER_TAR" -C "$MISMATCHED_ARTIFACT_POINTER_ROOT" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$MISMATCHED_ARTIFACT_POINTER_TAR" | awk '{print $1}')" "$(basename "$MISMATCHED_ARTIFACT_POINTER_TAR")" >"$MISMATCHED_ARTIFACT_POINTER_SHA"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$MISMATCHED_ARTIFACT_POINTER_SUMMARY" \
  --bundle-tar "$MISMATCHED_ARTIFACT_POINTER_TAR" \
  --bundle-tar-sha256-file "$MISMATCHED_ARTIFACT_POINTER_SHA" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$MISMATCHED_ARTIFACT_POINTER_PROVENANCE" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$MISMATCHED_ARTIFACT_POINTER_SUMMARY" \
  --provenance-json "$MISMATCHED_ARTIFACT_POINTER_PROVENANCE" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/trusted-policy-mismatched-artifact-pointer-summary.json" >"$TMP_DIR/trusted-policy-mismatched-artifact-pointer.log" 2>&1
mismatched_artifact_pointer_rc=$?
set -e
if [[ "$mismatched_artifact_pointer_rc" -eq 0 ]] || ! grep -Fq 'artifacts.smoke_summary_json to point inside the verified bundle' "$TMP_DIR/trusted-policy-mismatched-artifact-pointer.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted signed summary with mismatched artifact pointer"
  cat "$TMP_DIR/trusted-policy-mismatched-artifact-pointer.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$DEMO_TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/verify-provenance-demo-trust-store-summary.json" >"$TMP_DIR/verify-provenance-demo-trust-store.log" 2>&1
demo_trust_store_rc=$?
set -e
if [[ "$demo_trust_store_rc" -eq 0 ]] || ! grep -Fq 'rejects local/demo trust-store paths' "$TMP_DIR/verify-provenance-demo-trust-store.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted demo trust store"
  cat "$TMP_DIR/verify-provenance-demo-trust-store.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$DEMO_MARKED_TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/verify-provenance-demo-marked-trust-store-summary.json" >"$TMP_DIR/verify-provenance-demo-marked-trust-store.log" 2>&1
demo_marked_trust_store_rc=$?
set -e
if [[ "$demo_marked_trust_store_rc" -eq 0 ]] || ! grep -Fq 'rejects demo-marked trust-store contents' "$TMP_DIR/verify-provenance-demo-marked-trust-store.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted copied demo-marked trust store"
  cat "$TMP_DIR/verify-provenance-demo-marked-trust-store.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$DEMO_ID_TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/verify-provenance-demo-id-trust-store-summary.json" >"$TMP_DIR/verify-provenance-demo-id-trust-store.log" 2>&1
demo_id_trust_store_rc=$?
set -e
if [[ "$demo_id_trust_store_rc" -eq 0 ]] || ! grep -Fq 'rejects demo-marked trust-store contents' "$TMP_DIR/verify-provenance-demo-id-trust-store.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted copied demo identity trust store"
  cat "$TMP_DIR/verify-provenance-demo-id-trust-store.log"
  exit 1
fi

DEMO_VERIFY_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_verify_demo_trust_store_summary.json"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$DEMO_TRUST_STORE" \
  --allow-dev-trust-store 1 \
  --allow-non-handoff-receipt 1 \
  --verification-summary-json "$DEMO_VERIFY_SUMMARY_JSON" >"$TMP_DIR/verify-provenance-demo-trust-store-allowed.log"
if ! jq -e '
  .status == "pass"
  and .pilot_handoff_ready == false
  and .trusted_pilot_receipt_ready == false
  and .handoff_authority == false
  and .authority_level == "diagnostic_integrity_only"
  and .integrity_only == true
  and .pilot_handoff_criteria.ready == false
  and .pilot_handoff_criteria.dev_trust_store_allowed == true
  and .pilot_handoff_criteria.non_handoff_receipt_allowed == true
  and .inputs.allow_dev_trust_store == true
  and .inputs.allow_non_handoff_receipt == true
' "$DEMO_VERIFY_SUMMARY_JSON" >/dev/null; then
  echo "access bridge pilot evidence bundle verifier integration failed: diagnostic dev trust-store override produced unsafe readiness semantics"
  cat "$DEMO_VERIFY_SUMMARY_JSON"
  exit 1
fi

TAMPERED_LOOSE_VERIFY_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_verify_tampered_loose_summary.json"
printf '%s\n' '{"status":"pass","tampered_loose_file":true}' >"$BUNDLE_DIR/access_bridge_service_smoke_summary.json"
TAMPERED_LOOSE_SMOKE_SUMMARY_SHA256="$(sha256sum "$BUNDLE_DIR/access_bridge_service_smoke_summary.json" | awk '{print $1}')"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --allow-non-handoff-receipt 1 \
  --verification-summary-json "$TAMPERED_LOOSE_VERIFY_SUMMARY_JSON" >"$TMP_DIR/verify-provenance-trusted-policy-tampered-loose.log"
cp "$ORIGINAL_SMOKE_SUMMARY_COPY" "$BUNDLE_DIR/access_bridge_service_smoke_summary.json"
if ! jq -e --arg original_sha "$SMOKE_SUMMARY_SHA256" --arg loose_sha "$TAMPERED_LOOSE_SMOKE_SUMMARY_SHA256" '
  .status == "pass"
  and .pilot_handoff_ready == false
  and .trusted_pilot_receipt_ready == false
  and .handoff_authority == false
  and .authority_level == "trusted_non_handoff_diagnostic"
  and .integrity_only == true
  and .pilot_handoff_criteria.non_handoff_receipt_allowed == true
  and .pilot_handoff_criteria.installed_host_evidence_present == false
  and .evidence_binding.smoke_summary_sha256 == $original_sha
  and .evidence_binding.smoke_summary_sha256 != $loose_sha
  and (.evidence_binding.smoke_summary_json | contains("/access_bridge_pilot_evidence_bundle/access_bridge_service_smoke_summary.json"))
' "$TAMPERED_LOOSE_VERIFY_SUMMARY_JSON" >/dev/null; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted receipt did not bind to verified bundle contents"
  cat "$TAMPERED_LOOSE_VERIFY_SUMMARY_JSON"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --require-trusted-provenance 1 \
  --check-provenance 0 \
  --trust-store "$TRUST_STORE" >"$TMP_DIR/trusted-policy-check-provenance-disabled.log" 2>&1
trusted_check_disabled_rc=$?
set -e
if [[ "$trusted_check_disabled_rc" -eq 0 ]] || ! grep -Fq -- '--require-trusted-provenance requires --check-provenance 1' "$TMP_DIR/trusted-policy-check-provenance-disabled.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted disabled provenance check"
  cat "$TMP_DIR/trusted-policy-check-provenance-disabled.log"
  exit 1
fi

jq 'del(.artifacts.provenance_json)' "$SUMMARY_JSON" >"$NO_PROVENANCE_SUMMARY_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$NO_PROVENANCE_SUMMARY_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/trusted-policy-missing-provenance-summary.json" >"$TMP_DIR/trusted-policy-missing-provenance.log" 2>&1
missing_provenance_rc=$?
set -e
if [[ "$missing_provenance_rc" -eq 0 ]] || ! grep -Fq 'trusted pilot provenance requires external summary artifacts.provenance_json' "$TMP_DIR/trusted-policy-missing-provenance.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted missing provenance"
  cat "$TMP_DIR/trusted-policy-missing-provenance.log"
  exit 1
fi

jq '.provenance.enabled = false' "$SUMMARY_JSON" >"$UNSIGNED_SUMMARY_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$UNSIGNED_SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/trusted-policy-unsigned-summary-summary.json" >"$TMP_DIR/trusted-policy-unsigned-summary.log" 2>&1
unsigned_summary_rc=$?
set -e
if [[ "$unsigned_summary_rc" -eq 0 ]] || ! grep -Fq 'trusted pilot provenance requires external summary provenance.enabled=true' "$TMP_DIR/trusted-policy-unsigned-summary.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted unsigned summary metadata"
  cat "$TMP_DIR/trusted-policy-unsigned-summary.log"
  exit 1
fi

jq --arg other_provenance "$TMP_DIR/other.provenance.json" '.provenance.sidecar_json = $other_provenance' "$SUMMARY_JSON" >"$MISMATCHED_PROVENANCE_PATH_SUMMARY_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$MISMATCHED_PROVENANCE_PATH_SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/trusted-policy-mismatched-provenance-path-summary.json" >"$TMP_DIR/trusted-policy-mismatched-provenance-path.log" 2>&1
mismatched_provenance_path_rc=$?
set -e
if [[ "$mismatched_provenance_path_rc" -eq 0 ]] || ! grep -Fq 'trusted pilot provenance requires matching summary provenance paths' "$TMP_DIR/trusted-policy-mismatched-provenance-path.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted mismatched provenance path metadata"
  cat "$TMP_DIR/trusted-policy-mismatched-provenance-path.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --public-key-file "$PUBLIC_KEY_FILE" \
  --verification-summary-json "$TMP_DIR/trusted-policy-public-key-summary.json" >"$TMP_DIR/trusted-policy-public-key.log" 2>&1
trusted_public_key_rc=$?
set -e
if [[ "$trusted_public_key_rc" -eq 0 ]] || ! grep -Fq 'does not accept --public-key-file' "$TMP_DIR/trusted-policy-public-key.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted raw public key verification"
  cat "$TMP_DIR/trusted-policy-public-key.log"
  exit 1
fi

jq --arg provenance_json "$LOCAL_SCOPE_PROVENANCE_JSON" '.evidence_scope = "local_rehearsal" | .artifacts.provenance_json = $provenance_json' "$SUMMARY_JSON" >"$LOCAL_SCOPE_SUMMARY_JSON"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$LOCAL_SCOPE_SUMMARY_JSON" \
  --bundle-tar "$BUNDLE_TAR" \
  --bundle-tar-sha256-file "$BUNDLE_TAR_SHA256_FILE" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$LOCAL_SCOPE_PROVENANCE_JSON" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$LOCAL_SCOPE_SUMMARY_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" \
  --verification-summary-json "$TMP_DIR/trusted-policy-local-scope-summary.json" >"$TMP_DIR/trusted-policy-local-scope.log" 2>&1
local_scope_rc=$?
set -e
if [[ "$local_scope_rc" -eq 0 ]] || ! grep -Fq 'evidence_scope=real_helper_https' "$TMP_DIR/trusted-policy-local-scope.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted local evidence scope"
  cat "$TMP_DIR/trusted-policy-local-scope.log"
  exit 1
fi

jq '.subject.summary_json_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"' "$PROVENANCE_JSON" >"$BAD_PROVENANCE_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$BAD_PROVENANCE_JSON" \
  --public-key-file "$PUBLIC_KEY_FILE" >"$TMP_DIR/bad-provenance.log" 2>&1
bad_provenance_rc=$?
set -e
if [[ "$bad_provenance_rc" -eq 0 ]] || ! grep -Fq 'provenance verification failed' "$TMP_DIR/bad-provenance.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: bad provenance was not rejected"
  cat "$TMP_DIR/bad-provenance.log"
  exit 1
fi

MISMATCH_ROOT="$TMP_DIR/bundled-summary-mismatch-root"
MISMATCH_DIR="$MISMATCH_ROOT/$(basename "$BUNDLE_DIR")"
MISMATCH_TAR="$TMP_DIR/bundled-summary-mismatch.tar.gz"
MISMATCH_SHA="${MISMATCH_TAR}.sha256"
MISMATCH_EXTERNAL_SUMMARY="$TMP_DIR/bundled-summary-mismatch-external.json"
mkdir -p "$MISMATCH_ROOT"
cp -R "$BUNDLE_DIR" "$MISMATCH_DIR"
jq '.status = "fail" | .rc = 1 | .summary.steps_fail = 1 | .steps[0].status = "fail" | .steps[0].rc = 1' \
  "$MISMATCH_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  >"$MISMATCH_DIR/access_bridge_pilot_evidence_bundle_summary.json.tmp"
mv "$MISMATCH_DIR/access_bridge_pilot_evidence_bundle_summary.json.tmp" "$MISMATCH_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$MISMATCH_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$MISMATCH_DIR/manifest.sha256"
tar -czf "$MISMATCH_TAR" -C "$MISMATCH_ROOT" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$MISMATCH_TAR" | awk '{print $1}')" "$(basename "$MISMATCH_TAR")" >"$MISMATCH_SHA"
jq \
  --arg bundle_dir "$MISMATCH_DIR" \
  --arg bundle_tar "$MISMATCH_TAR" \
  --arg bundle_tar_sha256_file "$MISMATCH_SHA" \
  --arg manifest_sha256 "$MISMATCH_DIR/manifest.sha256" \
  '.artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256' \
  "$SUMMARY_JSON" >"$MISMATCH_EXTERNAL_SUMMARY"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --summary-json "$MISMATCH_EXTERNAL_SUMMARY" >"$TMP_DIR/bundled-summary-mismatch.log" 2>&1
bundled_summary_mismatch_rc=$?
set -e
if [[ "$bundled_summary_mismatch_rc" -eq 0 ]] ||
  ! grep -Eq 'bundled bundle summary status is not pass|external summary does not match bundled summary' "$TMP_DIR/bundled-summary-mismatch.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: mismatched failing bundled summary was not rejected"
  cat "$TMP_DIR/bundled-summary-mismatch.log"
  exit 1
fi

BAD_SUMMARY_JSON="$TMP_DIR/bad_bundle_summary_contract.json"
jq '.status = "fail" | .rc = 1 | .summary.steps_fail = 1 | .steps[0].status = "fail" | .steps[0].rc = 1' "$SUMMARY_JSON" >"$BAD_SUMMARY_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --summary-json "$BAD_SUMMARY_JSON" --check-tar-sha256 0 --check-manifest 0 >"$TMP_DIR/bad-summary-contract.log" 2>&1
bad_summary_contract_rc=$?
set -e
if [[ "$bad_summary_contract_rc" -eq 0 ]] || ! grep -Fq 'bundle summary status is not pass' "$TMP_DIR/bad-summary-contract.log" || ! grep -Fq 'bundle summary steps_fail is not 0' "$TMP_DIR/bad-summary-contract.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: bad summary contract was not rejected"
  cat "$TMP_DIR/bad-summary-contract.log"
  exit 1
fi

MISSING_STEPS_SUMMARY_JSON="$TMP_DIR/missing_steps_bundle_summary_contract.json"
jq 'del(.steps)' "$SUMMARY_JSON" >"$MISSING_STEPS_SUMMARY_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --summary-json "$MISSING_STEPS_SUMMARY_JSON" --check-tar-sha256 0 --check-manifest 0 >"$TMP_DIR/missing-steps-summary-contract.log" 2>&1
missing_steps_summary_contract_rc=$?
set -e
if [[ "$missing_steps_summary_contract_rc" -eq 0 ]] || ! grep -Fq 'bundle summary steps array is missing or empty' "$TMP_DIR/missing-steps-summary-contract.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: missing summary steps array was not rejected"
  cat "$TMP_DIR/missing-steps-summary-contract.log"
  exit 1
fi

MANIFEST_UNSAFE_DIR="$TMP_DIR/manifest-unsafe-bundle"
cp -R "$BUNDLE_DIR" "$MANIFEST_UNSAFE_DIR"
printf '%s  %s\n' "$(sha256sum "$MANIFEST_UNSAFE_DIR/access_bridge_service_smoke.log" | awk '{print $1}')" '..\escape.txt' >>"$MANIFEST_UNSAFE_DIR/manifest.sha256"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-dir "$MANIFEST_UNSAFE_DIR" --check-tar-sha256 0 >"$TMP_DIR/unsafe-manifest-path.log" 2>&1
unsafe_manifest_path_rc=$?
set -e
if [[ "$unsafe_manifest_path_rc" -eq 0 ]] || ! grep -Fq 'unsafe manifest entry path' "$TMP_DIR/unsafe-manifest-path.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: unsafe manifest path was not rejected"
  cat "$TMP_DIR/unsafe-manifest-path.log"
  exit 1
fi

EXTRA_TOP_LEVEL_ROOT="$TMP_DIR/extra-top-level-root"
EXTRA_TOP_LEVEL_DIR="$EXTRA_TOP_LEVEL_ROOT/$(basename "$BUNDLE_DIR")"
EXTRA_TOP_LEVEL_TAR="$TMP_DIR/extra-top-level.tar.gz"
EXTRA_TOP_LEVEL_SHA="${EXTRA_TOP_LEVEL_TAR}.sha256"
mkdir -p "$EXTRA_TOP_LEVEL_ROOT"
cp -R "$BUNDLE_DIR" "$EXTRA_TOP_LEVEL_DIR"
printf '%s\n' 'unmanifested sibling data' >"$EXTRA_TOP_LEVEL_ROOT/extra-secret.txt"
tar -czf "$EXTRA_TOP_LEVEL_TAR" -C "$EXTRA_TOP_LEVEL_ROOT" "$(basename "$BUNDLE_DIR")" "extra-secret.txt"
printf '%s  %s\n' "$(sha256sum "$EXTRA_TOP_LEVEL_TAR" | awk '{print $1}')" "$(basename "$EXTRA_TOP_LEVEL_TAR")" >"$EXTRA_TOP_LEVEL_SHA"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$EXTRA_TOP_LEVEL_TAR" --bundle-tar-sha256-file "$EXTRA_TOP_LEVEL_SHA" >"$TMP_DIR/extra-top-level.log" 2>&1
extra_top_level_rc=$?
set -e
if [[ "$extra_top_level_rc" -eq 0 ]] || ! grep -Fq 'exactly one top-level bundle directory' "$TMP_DIR/extra-top-level.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: extra top-level tar member was not rejected"
  cat "$TMP_DIR/extra-top-level.log"
  exit 1
fi

TAR_TAMPER_ROOT="$TMP_DIR/tar-tamper-root"
TAR_TAMPER_DIR="$TAR_TAMPER_ROOT/$(basename "$BUNDLE_DIR")"
TAR_TAMPER="$TMP_DIR/tar-tamper.tar.gz"
TAR_TAMPER_SHA="${TAR_TAMPER}.sha256"
TAR_TAMPER_SUMMARY="$TMP_DIR/tar-tamper-summary.json"
mkdir -p "$TAR_TAMPER_ROOT"
cp -R "$BUNDLE_DIR" "$TAR_TAMPER_DIR"
printf '%s\n' 'tampered only inside tar' >>"$TAR_TAMPER_DIR/access_bridge_service_smoke.log"
tar -czf "$TAR_TAMPER" -C "$TAR_TAMPER_ROOT" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$TAR_TAMPER" | awk '{print $1}')" "$(basename "$TAR_TAMPER")" >"$TAR_TAMPER_SHA"
jq \
  --arg bundle_tar "$TAR_TAMPER" \
  --arg bundle_tar_sha256_file "$TAR_TAMPER_SHA" \
  '.artifacts.bundle_tar = $bundle_tar | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file' \
  "$SUMMARY_JSON" >"$TAR_TAMPER_SUMMARY"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --summary-json "$TAR_TAMPER_SUMMARY" >"$TMP_DIR/tar-tamper.log" 2>&1
tar_tamper_rc=$?
set -e
if [[ "$tar_tamper_rc" -eq 0 ]] || ! grep -Fq 'manifest checksum mismatch' "$TMP_DIR/tar-tamper.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: tar-only tamper was not rejected"
  cat "$TMP_DIR/tar-tamper.log"
  exit 1
fi

printf '%s\n' 'tampered' >>"$BUNDLE_DIR/access_bridge_service_smoke.log"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-dir "$BUNDLE_DIR" --check-tar-sha256 0 >"$TMP_DIR/tamper.log" 2>&1
tamper_rc=$?
set -e
if [[ "$tamper_rc" -eq 0 ]] || ! grep -Fq 'manifest checksum mismatch' "$TMP_DIR/tamper.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: manifest tamper was not rejected"
  cat "$TMP_DIR/tamper.log"
  exit 1
fi

BAD_SHA="$TMP_DIR/bad.tar.gz.sha256"
printf '%064d  %s\n' 0 "$(basename "$BUNDLE_TAR")" >"$BAD_SHA"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$BUNDLE_TAR" --bundle-tar-sha256-file "$BAD_SHA" --check-manifest 0 >"$TMP_DIR/bad-sha.log" 2>&1
bad_sha_rc=$?
set -e
if [[ "$bad_sha_rc" -eq 0 ]] || ! grep -Fq 'bundle tar checksum mismatch' "$TMP_DIR/bad-sha.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: tar checksum mismatch was not rejected"
  cat "$TMP_DIR/bad-sha.log"
  exit 1
fi

WRONG_SHA_NAME="$TMP_DIR/wrong-name.tar.gz.sha256"
printf '%s  %s\n' "$(sha256sum "$BUNDLE_TAR" | awk '{print $1}')" "wrong-bundle-name.tar.gz" >"$WRONG_SHA_NAME"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$BUNDLE_TAR" --bundle-tar-sha256-file "$WRONG_SHA_NAME" --check-manifest 0 >"$TMP_DIR/wrong-sha-name.log" 2>&1
wrong_sha_name_rc=$?
set -e
if [[ "$wrong_sha_name_rc" -eq 0 ]] || ! grep -Fq 'bundle tar checksum sidecar filename mismatch' "$TMP_DIR/wrong-sha-name.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: tar checksum sidecar filename mismatch was not rejected"
  cat "$TMP_DIR/wrong-sha-name.log"
  exit 1
fi

UNSAFE_TAR="$TMP_DIR/unsafe-path.tar.gz"
UNSAFE_SHA="${UNSAFE_TAR}.sha256"
WINDOWS_UNSAFE_TAR="$TMP_DIR/windows-unsafe-path.tar.gz"
WINDOWS_UNSAFE_SHA="${WINDOWS_UNSAFE_TAR}.sha256"
LINK_TAR="$TMP_DIR/unsafe-link.tar.gz"
LINK_SHA="${LINK_TAR}.sha256"
"$PYTHON_BIN" - "$UNSAFE_TAR" "$WINDOWS_UNSAFE_TAR" "$LINK_TAR" <<'PY'
import io
import sys
import tarfile

unsafe_tar, windows_unsafe_tar, link_tar = sys.argv[1], sys.argv[2], sys.argv[3]

with tarfile.open(unsafe_tar, "w:gz") as tf:
    payload = b"escape\n"
    info = tarfile.TarInfo("../escape.txt")
    info.size = len(payload)
    tf.addfile(info, io.BytesIO(payload))

with tarfile.open(windows_unsafe_tar, "w:gz") as tf:
    for name in ("C:/escape.txt", r"bundle\evil.txt"):
        payload = b"windows escape\n"
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

with tarfile.open(link_tar, "w:gz") as tf:
    payload = b"target\n"
    info = tarfile.TarInfo("bundle/target.txt")
    info.size = len(payload)
    tf.addfile(info, io.BytesIO(payload))
    link = tarfile.TarInfo("bundle/link.txt")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    tf.addfile(link)
PY
printf '%s  %s\n' "$(sha256sum "$UNSAFE_TAR" | awk '{print $1}')" "$(basename "$UNSAFE_TAR")" >"$UNSAFE_SHA"
printf '%s  %s\n' "$(sha256sum "$WINDOWS_UNSAFE_TAR" | awk '{print $1}')" "$(basename "$WINDOWS_UNSAFE_TAR")" >"$WINDOWS_UNSAFE_SHA"
printf '%s  %s\n' "$(sha256sum "$LINK_TAR" | awk '{print $1}')" "$(basename "$LINK_TAR")" >"$LINK_SHA"

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$UNSAFE_TAR" --bundle-tar-sha256-file "$UNSAFE_SHA" --check-manifest 0 >"$TMP_DIR/unsafe-path.log" 2>&1
unsafe_path_rc=$?
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$WINDOWS_UNSAFE_TAR" --bundle-tar-sha256-file "$WINDOWS_UNSAFE_SHA" --check-manifest 0 >"$TMP_DIR/windows-unsafe-path.log" 2>&1
windows_unsafe_path_rc=$?
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$LINK_TAR" --bundle-tar-sha256-file "$LINK_SHA" --check-manifest 0 >"$TMP_DIR/unsafe-link.log" 2>&1
unsafe_link_rc=$?
set -e
if [[ "$unsafe_path_rc" -eq 0 ]] || ! grep -Fq 'unsafe bundle tar member path' "$TMP_DIR/unsafe-path.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: unsafe tar path was not rejected"
  cat "$TMP_DIR/unsafe-path.log"
  exit 1
fi
if [[ "$windows_unsafe_path_rc" -eq 0 ]] || ! grep -Fq 'unsafe bundle tar member path' "$TMP_DIR/windows-unsafe-path.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: Windows-style unsafe tar path was not rejected"
  cat "$TMP_DIR/windows-unsafe-path.log"
  exit 1
fi
if [[ "$unsafe_link_rc" -eq 0 ]] || ! grep -Fq 'unsafe bundle tar link member' "$TMP_DIR/unsafe-link.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: unsafe tar link was not rejected"
  cat "$TMP_DIR/unsafe-link.log"
  exit 1
fi

echo "access bridge pilot evidence bundle verifier integration check ok"
