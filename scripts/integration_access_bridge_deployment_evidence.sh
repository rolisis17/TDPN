#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash cp date go jq mktemp sed sha256sum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access bridge deployment evidence integration failed: missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

BUNDLE_DIR="$TMP_DIR/access-recovery-demo"
SERVICE_CONFIG="$TMP_DIR/bridge-service-config.json"
DEPLOY_DIR="$TMP_DIR/bridge-deploy"
CODE_FILE="$TMP_DIR/bridge-code.txt"
CODE_HASH_JSON="$TMP_DIR/bridge-code-hash.json"
SMOKE_SUMMARY="$TMP_DIR/access_bridge_service_smoke_summary.json"
SUMMARY_JSON="$TMP_DIR/access_bridge_deployment_evidence_summary.json"
RUN_LOG="$TMP_DIR/run.log"

go run ./cmd/gpmrecover demo-bundle \
  --out-dir "$BUNDLE_DIR" \
  --org-id evidence-org \
  --org-name "Evidence Org" \
  --base-url https://evidence.gpm-pilot.net \
  --helper-id helper-evidence \
  --helper-name "Evidence Helper" \
  --helper-url https://helper.gpm-pilot.net/evidence/bootstrap \
  --helper-contact mailto:helper-evidence@example.com \
  >"$TMP_DIR/demo-bundle.stdout.json"

trust_store="$(jq -r '.files.trust_store' "$BUNDLE_DIR/demo-manifest.json")"
bridge_invite="$(jq -r '.files.bridge_invite_signed' "$BUNDLE_DIR/demo-manifest.json")"
signed_registry="$(jq -r '.files.bridge_helper_registry_signed' "$BUNDLE_DIR/demo-manifest.json")"

go run ./cmd/gpmrecover bridge-service-config \
  --invite "$bridge_invite" \
  --trust-store "$trust_store" \
  --signed-helper-registry "$signed_registry" \
  --out "$SERVICE_CONFIG" >/dev/null

registry_id="$(jq -r '.registry_id' "$SERVICE_CONFIG")"
config_sha256="$(sha256sum "$SERVICE_CONFIG" | awk '{print $1}')"
go run ./cmd/gpmrecover bridge-service-code-generate --code-out "$CODE_FILE" --hash-out "$CODE_HASH_JSON" >/dev/null
code_hash="$(jq -r '.sha256' "$CODE_HASH_JSON")"

go run ./cmd/gpmrecover bridge-service-deploy-pack \
  --out-dir "$DEPLOY_DIR" \
  --service-name gpm-access-bridge-evidence \
  --install-dir /etc/gpm/access-bridge-evidence \
  --config /etc/gpm/access-bridge-evidence/bridge-service-config.json \
  --config-sha256 "$config_sha256" \
  --access-code-sha256 "$code_hash" \
  >/dev/null

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg registry_id "$registry_id" \
  --arg config_sha256 "$config_sha256" \
  '{
    version: 1,
    schema: {
      id: "access_bridge_service_smoke_summary",
      major: 1,
      minor: 1
    },
    generated_at_utc: $generated_at_utc,
    status: "pass",
    notes: "bridge service smoke passed",
    base_url: "https://recovery-helper.gpm-pilot.net",
    path_id: "helper-web",
    health: {
      http_status: "200",
      status: "ok",
      helper_id: "helper-evidence",
      organization_id: "evidence-org",
      registry_id: $registry_id,
      config_sha256: $config_sha256
    },
    bridge: {
      http_status: "200",
      status: "ok",
      security_headers_ok: true
    },
    auth: {
      required: true,
      missing_code_http_status: "401",
      wrong_code_http_status: "401",
      valid_code_http_status: "200"
    },
    abuse: {
      http_status: "202"
    }
  }' >"$SMOKE_SUMMARY"

./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json "$SMOKE_SUMMARY" \
  --expect-helper-id helper-evidence \
  --expect-org-id evidence-org \
  --expect-registry-id "$registry_id" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$DEPLOY_DIR" \
  --service-name gpm-access-bridge-evidence \
  --summary-json "$SUMMARY_JSON" \
  --print-summary-json 1 >"$RUN_LOG"

if [[ ! -f "$SUMMARY_JSON" ]]; then
  echo "access bridge deployment evidence integration failed: summary missing"
  cat "$RUN_LOG"
  exit 1
fi

if ! jq -e \
  --arg smoke_summary "$SMOKE_SUMMARY" \
  --arg config_json "$SERVICE_CONFIG" \
  --arg deploy_dir "$DEPLOY_DIR" \
  --arg registry_id "$registry_id" \
  --arg config_sha256 "$config_sha256" \
  '
    .schema.id == "access_bridge_deployment_evidence_summary"
    and .status == "pass"
    and .smoke.status == "pass"
    and .smoke.schema_id == "access_bridge_service_smoke_summary"
    and .smoke.evidence_status == "pass"
    and .smoke.auth_required == true
    and .smoke.missing_code_http_status == "401"
    and .smoke.wrong_code_http_status == "401"
    and .smoke.valid_code_http_status == "200"
    and .smoke.bridge_http_status == "200"
    and .smoke.bridge_status == "ok"
    and .smoke.bridge_security_headers_ok == true
    and .smoke.base_host == "recovery-helper.gpm-pilot.net"
    and .smoke.config_sha256 == $config_sha256
    and .smoke.summary_json == $smoke_summary
    and .expected_identity.helper_id == "helper-evidence"
    and .expected_identity.organization_id == "evidence-org"
    and .expected_identity.registry_id == $registry_id
    and .deployed_identity.helper_id == "helper-evidence"
    and .deployed_identity.organization_id == "evidence-org"
    and .deployed_identity.registry_id == $registry_id
    and .identity_check.status == "pass"
    and .local_files.config.status == "pass"
    and .local_files.config.path == $config_json
    and .local_files.config.exists == true
    and .local_files.config.valid_json == true
    and .local_files.config.sha256 == $config_sha256
    and .local_files.config.allow_local_access_paths == "false"
    and .local_files.deploy_pack.status == "pass"
    and .local_files.deploy_pack.dir == $deploy_dir
    and .local_files.deploy_pack.exists == true
    and .local_files.deploy_pack.env.config_sha256 == $config_sha256
    and (.local_files.deploy_pack.env.access_code_sha256 | length == 64)
    and .local_files.deploy_pack.env.allow_query_code == "false"
    and .local_files.deploy_pack.env.trust_proxy_headers == "true"
    and .local_files.deploy_pack.env.addr == "127.0.0.1:18980"
    and .local_files.deploy_pack.proxy_examples.caddy_site_host == "recovery-helper.gpm-pilot.net"
    and .local_files.deploy_pack.proxy_examples.caddy_reverse_proxy == "127.0.0.1:18980"
    and .local_files.deploy_pack.proxy_examples.nginx_server_name == "recovery-helper.gpm-pilot.net"
    and .local_files.deploy_pack.proxy_examples.nginx_proxy_pass == "127.0.0.1:18980"
    and (.local_files.deploy_pack.required_files | length == 6)
    and ([.local_files.deploy_pack.required_files[].sha256 | length == 64] | all)
    and ([.local_files.deploy_pack.required_files[].exists] | all)
    and .recommended_next_action.id == "record_operator_evidence"
  ' "$SUMMARY_JSON" >/dev/null; then
  echo "access bridge deployment evidence integration failed: pass summary contract mismatch"
  cat "$SUMMARY_JSON"
  exit 1
fi

BAD_LOCAL_CONFIG="$TMP_DIR/bridge-service-config-local-diagnostic.json"
jq '.allow_local_access_paths = true' "$SERVICE_CONFIG" >"$BAD_LOCAL_CONFIG"
bad_local_config_sha256="$(sha256sum "$BAD_LOCAL_CONFIG" | awk '{print $1}')"
BAD_LOCAL_CONFIG_SMOKE="$TMP_DIR/access_bridge_service_smoke_local_diagnostic_config.json"
jq --arg config_sha256 "$bad_local_config_sha256" '.health.config_sha256 = $config_sha256' "$SMOKE_SUMMARY" >"$BAD_LOCAL_CONFIG_SMOKE"
BAD_LOCAL_CONFIG_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_local_diagnostic_config.json"
set +e
./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json "$BAD_LOCAL_CONFIG_SMOKE" \
  --config-json "$BAD_LOCAL_CONFIG" \
  --summary-json "$BAD_LOCAL_CONFIG_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/bad-local-config.log" 2>&1
bad_local_config_rc=$?
set -e
if [[ "$bad_local_config_rc" -eq 0 ]]; then
  echo "access bridge deployment evidence integration failed: local-diagnostic service config should fail"
  cat "$BAD_LOCAL_CONFIG_SUMMARY"
  exit 1
fi
if ! jq -e \
  '
    .status == "fail"
    and .local_files.config.status == "fail"
    and .local_files.config.allow_local_access_paths == "true"
    and (.local_files.config.reason | contains("local diagnostic access paths"))
    and .recommended_next_action.id == "stage_bridge_service_config"
  ' "$BAD_LOCAL_CONFIG_SUMMARY" >/dev/null; then
  echo "access bridge deployment evidence integration failed: local-diagnostic service config summary mismatch"
  cat "$BAD_LOCAL_CONFIG_SUMMARY"
  exit 1
fi

bad_public_hosts=(
  "localhost"
  "10.0.0.8"
  "100.64.0.1"
  "169.254.1.1"
  "192.0.0.10"
  "192.0.2.10"
  "224.0.0.1"
  "helper.local"
  "helper.lan"
  "helper.internal"
  "helper.test"
  "helper.invalid"
  "helper.example"
  "helper"
  "com"
  "example.com"
  "example.net"
  "example.org"
  "user@public.tdpn.net"
  "public.tdpn.net."
)
bad_public_host_index=0
for bad_public_host in "${bad_public_hosts[@]}"; do
  bad_public_host_index=$((bad_public_host_index + 1))
  BAD_PUBLIC_HOST_DEPLOY_DIR="$TMP_DIR/bad-public-host-deploy-$bad_public_host_index"
  cp -R "$DEPLOY_DIR" "$BAD_PUBLIC_HOST_DEPLOY_DIR"
  sed -i "s/^recovery-helper.gpm-pilot.net {/$bad_public_host {/" "$BAD_PUBLIC_HOST_DEPLOY_DIR/gpm-access-bridge-evidence.Caddyfile.example"
  sed -i "s/server_name recovery-helper.gpm-pilot.net;/server_name $bad_public_host;/" "$BAD_PUBLIC_HOST_DEPLOY_DIR/gpm-access-bridge-evidence.nginx.example.conf"
  BAD_PUBLIC_HOST_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_bad_public_host_$bad_public_host_index.json"
  set +e
  ./scripts/access_bridge_deployment_evidence.sh \
    --smoke-summary-json "$SMOKE_SUMMARY" \
    --config-json "$SERVICE_CONFIG" \
    --deploy-pack-dir "$BAD_PUBLIC_HOST_DEPLOY_DIR" \
    --service-name gpm-access-bridge-evidence \
    --summary-json "$BAD_PUBLIC_HOST_SUMMARY" \
    --print-summary-json 0 >"$TMP_DIR/bad-public-host-$bad_public_host_index.log" 2>&1
  bad_public_host_rc=$?
  set -e
  if [[ "$bad_public_host_rc" -eq 0 ]]; then
    echo "access bridge deployment evidence integration failed: unsafe proxy public host should fail: $bad_public_host"
    cat "$BAD_PUBLIC_HOST_SUMMARY"
    exit 1
  fi
  if ! jq -e \
    --arg host "$bad_public_host" \
    '
      .status == "fail"
      and .local_files.deploy_pack.status == "fail"
      and .local_files.deploy_pack.proxy_examples.caddy_site_host == $host
      and .local_files.deploy_pack.proxy_examples.nginx_server_name == $host
      and (.local_files.deploy_pack.reason | contains("safe bare public host"))
      and .recommended_next_action.id == "stage_bridge_deploy_pack"
    ' "$BAD_PUBLIC_HOST_SUMMARY" >/dev/null; then
    echo "access bridge deployment evidence integration failed: unsafe proxy public host summary mismatch: $bad_public_host"
    cat "$BAD_PUBLIC_HOST_SUMMARY"
    exit 1
  fi
done

bad_smoke_base_urls=(
  "https://localhost"
  "https://10.0.0.8"
  "https://100.64.0.1"
  "https://169.254.1.1"
  "https://192.0.0.10"
  "https://192.0.2.10"
  "https://224.0.0.1"
  "https://helper.local"
  "https://helper.lan"
  "https://helper.internal"
  "https://helper.test"
  "https://helper.invalid"
  "https://helper.example"
  "https://helper"
  "https://com"
  "https://example.com"
  "https://example.net"
  "https://example.org"
  "https://user:pass@public.tdpn.net"
  "https://public.tdpn.net."
  "https://[::ffff:10.0.0.8]"
)
bad_smoke_index=0
for bad_smoke_base_url in "${bad_smoke_base_urls[@]}"; do
  bad_smoke_index=$((bad_smoke_index + 1))
  BAD_SMOKE_PUBLIC_HOST_SUMMARY="$TMP_DIR/access_bridge_service_smoke_bad_public_host_$bad_smoke_index.json"
  jq --arg base_url "$bad_smoke_base_url" '.base_url = $base_url' "$SMOKE_SUMMARY" >"$BAD_SMOKE_PUBLIC_HOST_SUMMARY"
  BAD_SMOKE_EVIDENCE_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_bad_smoke_public_host_$bad_smoke_index.json"
  set +e
  ./scripts/access_bridge_deployment_evidence.sh \
    --smoke-summary-json "$BAD_SMOKE_PUBLIC_HOST_SUMMARY" \
    --summary-json "$BAD_SMOKE_EVIDENCE_SUMMARY" \
    --print-summary-json 0 >"$TMP_DIR/bad-smoke-public-host-$bad_smoke_index.log" 2>&1
  bad_smoke_public_host_rc=$?
  set -e
  if [[ "$bad_smoke_public_host_rc" -eq 0 ]]; then
    echo "access bridge deployment evidence integration failed: unsafe smoke base_url host should fail: $bad_smoke_base_url"
    cat "$BAD_SMOKE_EVIDENCE_SUMMARY"
    exit 1
  fi
  if ! jq -e \
    '
      .status == "fail"
      and .smoke.evidence_status == "fail"
      and (.smoke.evidence_reason | contains("safe public helper host"))
      and .recommended_next_action.id == "refresh_deployed_bridge_smoke"
    ' "$BAD_SMOKE_EVIDENCE_SUMMARY" >/dev/null; then
    echo "access bridge deployment evidence integration failed: unsafe smoke base_url summary mismatch: $bad_smoke_base_url"
    cat "$BAD_SMOKE_EVIDENCE_SUMMARY"
    exit 1
  fi
done

NO_HEADERS_SMOKE_SUMMARY="$TMP_DIR/access_bridge_service_smoke_no_headers_summary.json"
jq '.bridge.security_headers_ok = false' "$SMOKE_SUMMARY" >"$NO_HEADERS_SMOKE_SUMMARY"
NO_HEADERS_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_no_headers_summary.json"
set +e
./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json "$NO_HEADERS_SMOKE_SUMMARY" \
  --summary-json "$NO_HEADERS_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/no-headers.log" 2>&1
no_headers_rc=$?
set -e
if [[ "$no_headers_rc" -eq 0 ]]; then
  echo "access bridge deployment evidence integration failed: missing security headers should fail"
  cat "$NO_HEADERS_SUMMARY"
  exit 1
fi
if ! jq -e '.status == "fail" and .smoke.evidence_status == "fail" and .smoke.bridge_security_headers_ok == false and (.smoke.evidence_reason | contains("security headers")) and .recommended_next_action.id == "refresh_deployed_bridge_smoke"' "$NO_HEADERS_SUMMARY" >/dev/null; then
  echo "access bridge deployment evidence integration failed: security headers summary mismatch"
  cat "$NO_HEADERS_SUMMARY"
  exit 1
fi

BAD_VALID_CODE_SMOKE_SUMMARY="$TMP_DIR/access_bridge_service_smoke_bad_valid_code_summary.json"
jq '.auth.valid_code_http_status = "500"' "$SMOKE_SUMMARY" >"$BAD_VALID_CODE_SMOKE_SUMMARY"
BAD_VALID_CODE_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_bad_valid_code_summary.json"
set +e
./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json "$BAD_VALID_CODE_SMOKE_SUMMARY" \
  --summary-json "$BAD_VALID_CODE_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/bad-valid-code.log" 2>&1
bad_valid_code_rc=$?
set -e
if [[ "$bad_valid_code_rc" -eq 0 ]]; then
  echo "access bridge deployment evidence integration failed: valid access-code non-200 should fail"
  cat "$BAD_VALID_CODE_SUMMARY"
  exit 1
fi
if ! jq -e '.status == "fail" and .smoke.evidence_status == "fail" and .smoke.valid_code_http_status == "500" and (.smoke.evidence_reason | contains("valid access-code acceptance")) and .recommended_next_action.id == "refresh_deployed_bridge_smoke"' "$BAD_VALID_CODE_SUMMARY" >/dev/null; then
  echo "access bridge deployment evidence integration failed: bad valid-code summary mismatch"
  cat "$BAD_VALID_CODE_SUMMARY"
  exit 1
fi

STALE_SMOKE_SUMMARY="$TMP_DIR/access_bridge_service_smoke_stale_summary.json"
jq '.generated_at_utc = "2000-01-01T00:00:00Z"' "$SMOKE_SUMMARY" >"$STALE_SMOKE_SUMMARY"
STALE_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_stale_summary.json"
set +e
./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json "$STALE_SMOKE_SUMMARY" \
  --summary-json "$STALE_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/stale.log" 2>&1
stale_rc=$?
set -e
if [[ "$stale_rc" -eq 0 ]]; then
  echo "access bridge deployment evidence integration failed: stale smoke summary should fail"
  cat "$STALE_SUMMARY"
  exit 1
fi
if ! jq -e '.status == "fail" and .smoke.evidence_status == "fail" and .recommended_next_action.id == "refresh_deployed_bridge_smoke"' "$STALE_SUMMARY" >/dev/null; then
  echo "access bridge deployment evidence integration failed: stale smoke summary contract mismatch"
  cat "$STALE_SUMMARY"
  exit 1
fi

MISMATCH_SMOKE_SUMMARY="$TMP_DIR/access_bridge_service_smoke_config_mismatch_summary.json"
jq '.health.config_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$SMOKE_SUMMARY" >"$MISMATCH_SMOKE_SUMMARY"
MISMATCH_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_config_mismatch_summary.json"
set +e
./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json "$MISMATCH_SMOKE_SUMMARY" \
  --config-json "$SERVICE_CONFIG" \
  --summary-json "$MISMATCH_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/config-mismatch.log" 2>&1
mismatch_rc=$?
set -e
if [[ "$mismatch_rc" -eq 0 ]]; then
  echo "access bridge deployment evidence integration failed: live/staged config sha mismatch should fail"
  cat "$MISMATCH_SUMMARY"
  exit 1
fi
if ! jq -e '.status == "fail" and .smoke.evidence_status == "fail" and (.smoke.evidence_reason | contains("live config sha256 does not match supplied config")) and .recommended_next_action.id == "refresh_deployed_bridge_smoke"' "$MISMATCH_SUMMARY" >/dev/null; then
  echo "access bridge deployment evidence integration failed: config mismatch summary contract mismatch"
  cat "$MISMATCH_SUMMARY"
  exit 1
fi

BAD_HASH_DEPLOY_DIR="$TMP_DIR/bad-hash-deploy"
cp -R "$DEPLOY_DIR" "$BAD_HASH_DEPLOY_DIR"
sed -i 's/GPM_BRIDGE_ACCESS_CODE_SHA256="[^"]*"/GPM_BRIDGE_ACCESS_CODE_SHA256="short"/' "$BAD_HASH_DEPLOY_DIR/gpm-access-bridge-evidence.env"
BAD_HASH_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_bad_hash_summary.json"
set +e
./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json "$SMOKE_SUMMARY" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$BAD_HASH_DEPLOY_DIR" \
  --service-name gpm-access-bridge-evidence \
  --summary-json "$BAD_HASH_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/bad-hash.log" 2>&1
bad_hash_rc=$?
set -e
if [[ "$bad_hash_rc" -eq 0 ]]; then
  echo "access bridge deployment evidence integration failed: malformed deploy hash should fail"
  cat "$BAD_HASH_SUMMARY"
  exit 1
fi
if ! jq -e '.status == "fail" and .local_files.deploy_pack.status == "fail" and .recommended_next_action.id == "stage_bridge_deploy_pack"' "$BAD_HASH_SUMMARY" >/dev/null; then
  echo "access bridge deployment evidence integration failed: malformed deploy hash summary mismatch"
  cat "$BAD_HASH_SUMMARY"
  exit 1
fi

BAD_ADDR_DEPLOY_DIR="$TMP_DIR/bad-addr-deploy"
cp -R "$DEPLOY_DIR" "$BAD_ADDR_DEPLOY_DIR"
sed -i 's/GPM_BRIDGE_ADDR="127.0.0.1:18980"/GPM_BRIDGE_ADDR="127.evil.example:18980"/' "$BAD_ADDR_DEPLOY_DIR/gpm-access-bridge-evidence.env"
BAD_ADDR_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_bad_addr_summary.json"
set +e
./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json "$SMOKE_SUMMARY" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$BAD_ADDR_DEPLOY_DIR" \
  --service-name gpm-access-bridge-evidence \
  --summary-json "$BAD_ADDR_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/bad-addr.log" 2>&1
bad_addr_rc=$?
set -e
if [[ "$bad_addr_rc" -eq 0 ]]; then
  echo "access bridge deployment evidence integration failed: non-loopback deploy addr should fail"
  cat "$BAD_ADDR_SUMMARY"
  exit 1
fi
if ! jq -e '.status == "fail" and .local_files.deploy_pack.status == "fail" and .local_files.deploy_pack.env.addr == "127.evil.example:18980" and (.local_files.deploy_pack.reason | contains("loopback host:port")) and .recommended_next_action.id == "stage_bridge_deploy_pack"' "$BAD_ADDR_SUMMARY" >/dev/null; then
  echo "access bridge deployment evidence integration failed: bad deploy addr summary mismatch"
  cat "$BAD_ADDR_SUMMARY"
  exit 1
fi

BAD_CADDY_DEPLOY_DIR="$TMP_DIR/bad-caddy-deploy"
cp -R "$DEPLOY_DIR" "$BAD_CADDY_DEPLOY_DIR"
sed -i 's/reverse_proxy 127.0.0.1:18980/reverse_proxy evil.example:80/' "$BAD_CADDY_DEPLOY_DIR/gpm-access-bridge-evidence.Caddyfile.example"
BAD_CADDY_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_bad_caddy_summary.json"
set +e
./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json "$SMOKE_SUMMARY" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$BAD_CADDY_DEPLOY_DIR" \
  --service-name gpm-access-bridge-evidence \
  --summary-json "$BAD_CADDY_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/bad-caddy.log" 2>&1
bad_caddy_rc=$?
set -e
if [[ "$bad_caddy_rc" -eq 0 ]]; then
  echo "access bridge deployment evidence integration failed: mismatched Caddy reverse_proxy should fail"
  cat "$BAD_CADDY_SUMMARY"
  exit 1
fi
if ! jq -e '.status == "fail" and .local_files.deploy_pack.status == "fail" and .local_files.deploy_pack.proxy_examples.caddy_reverse_proxy == "evil.example:80" and (.local_files.deploy_pack.reason | contains("Caddy example reverse_proxy")) and .recommended_next_action.id == "stage_bridge_deploy_pack"' "$BAD_CADDY_SUMMARY" >/dev/null; then
  echo "access bridge deployment evidence integration failed: bad Caddy target summary mismatch"
  cat "$BAD_CADDY_SUMMARY"
  exit 1
fi

BAD_NGINX_DEPLOY_DIR="$TMP_DIR/bad-nginx-deploy"
cp -R "$DEPLOY_DIR" "$BAD_NGINX_DEPLOY_DIR"
sed -i 's#proxy_pass http://127.0.0.1:18980;#proxy_pass http://evil.example:80;#' "$BAD_NGINX_DEPLOY_DIR/gpm-access-bridge-evidence.nginx.example.conf"
BAD_NGINX_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_bad_nginx_summary.json"
set +e
./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json "$SMOKE_SUMMARY" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$BAD_NGINX_DEPLOY_DIR" \
  --service-name gpm-access-bridge-evidence \
  --summary-json "$BAD_NGINX_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/bad-nginx.log" 2>&1
bad_nginx_rc=$?
set -e
if [[ "$bad_nginx_rc" -eq 0 ]]; then
  echo "access bridge deployment evidence integration failed: mismatched nginx proxy_pass should fail"
  cat "$BAD_NGINX_SUMMARY"
  exit 1
fi
if ! jq -e '.status == "fail" and .local_files.deploy_pack.status == "fail" and .local_files.deploy_pack.proxy_examples.nginx_proxy_pass == "evil.example:80" and (.local_files.deploy_pack.reason | contains("nginx example proxy_pass")) and .recommended_next_action.id == "stage_bridge_deploy_pack"' "$BAD_NGINX_SUMMARY" >/dev/null; then
  echo "access bridge deployment evidence integration failed: bad nginx target summary mismatch"
  cat "$BAD_NGINX_SUMMARY"
  exit 1
fi

BAD_SERVER_NAME_DEPLOY_DIR="$TMP_DIR/bad-server-name-deploy"
cp -R "$DEPLOY_DIR" "$BAD_SERVER_NAME_DEPLOY_DIR"
sed -i 's/server_name recovery-helper.gpm-pilot.net;/server_name other.public.tdpn.net;/' "$BAD_SERVER_NAME_DEPLOY_DIR/gpm-access-bridge-evidence.nginx.example.conf"
BAD_SERVER_NAME_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_bad_server_name_summary.json"
set +e
./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json "$SMOKE_SUMMARY" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$BAD_SERVER_NAME_DEPLOY_DIR" \
  --service-name gpm-access-bridge-evidence \
  --summary-json "$BAD_SERVER_NAME_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/bad-server-name.log" 2>&1
bad_server_name_rc=$?
set -e
if [[ "$bad_server_name_rc" -eq 0 ]]; then
  echo "access bridge deployment evidence integration failed: nginx server_name mismatch should fail"
  cat "$BAD_SERVER_NAME_SUMMARY"
  exit 1
fi
if ! jq -e '.status == "fail" and .local_files.deploy_pack.status == "fail" and .local_files.deploy_pack.proxy_examples.nginx_server_name == "other.public.tdpn.net" and (.local_files.deploy_pack.reason | contains("server_name must match smoke base_url host")) and .recommended_next_action.id == "stage_bridge_deploy_pack"' "$BAD_SERVER_NAME_SUMMARY" >/dev/null; then
  echo "access bridge deployment evidence integration failed: bad nginx server_name summary mismatch"
  cat "$BAD_SERVER_NAME_SUMMARY"
  exit 1
fi

FAIL_SUMMARY="$TMP_DIR/access_bridge_deployment_evidence_fail_summary.json"
set +e
./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json "$SMOKE_SUMMARY" \
  --expect-helper-id wrong-helper \
  --summary-json "$FAIL_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/fail.log" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -eq 0 ]]; then
  echo "access bridge deployment evidence integration failed: mismatch should fail"
  cat "$FAIL_SUMMARY"
  exit 1
fi
if ! jq -e '.status == "fail" and .identity_check.status == "fail" and .recommended_next_action.id == "fix_bridge_identity"' "$FAIL_SUMMARY" >/dev/null; then
  echo "access bridge deployment evidence integration failed: mismatch summary contract mismatch"
  cat "$FAIL_SUMMARY"
  exit 1
fi

echo "access bridge deployment evidence integration check ok"
