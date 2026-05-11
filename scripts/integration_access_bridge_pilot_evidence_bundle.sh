#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in awk bash cat chmod curl go jq mkdir mktemp rg sha256sum tar tr; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access bridge pilot evidence bundle integration failed: missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
BRIDGE_PID=""
cleanup() {
  if [[ -n "$BRIDGE_PID" ]]; then
    kill "$BRIDGE_PID" >/dev/null 2>&1 || true
    wait "$BRIDGE_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

BUNDLE_DIR="$TMP_DIR/access-recovery-demo"
PORT="${ACCESS_BRIDGE_TEST_PORT:-19791}"
BASE_URL="http://127.0.0.1:${PORT}"
CODE_FILE="$TMP_DIR/bridge-code.txt"
CODE_HASH_JSON="$TMP_DIR/bridge-code-hash.json"
SERVICE_CONFIG="$TMP_DIR/bridge-service-config.json"
DEPLOY_PACK="$TMP_DIR/bridge-deploy-pack"
ABUSE_LOG="$TMP_DIR/bridge-abuse.jsonl"
SERVER_LOG="$TMP_DIR/bridge-service.log"
EVIDENCE_BUNDLE="$TMP_DIR/pilot-evidence-bundle"
SUMMARY_JSON="$TMP_DIR/pilot-evidence-summary.json"
REPORT_MD="$TMP_DIR/pilot-evidence-report.md"
PROVENANCE_JSON="$TMP_DIR/pilot-evidence-bundle.provenance.json"
PROVENANCE_PRIVATE_KEY="$TMP_DIR/provenance-private.key"
PROVENANCE_PUBLIC_KEY="$TMP_DIR/provenance-public.key"
PILOT_PUBLIC_HOST="helper.gpm-pilot.net"

go run ./cmd/gpmrecover gen --private-key-out "$PROVENANCE_PRIVATE_KEY" --public-key-out "$PROVENANCE_PUBLIC_KEY" >/dev/null
PROVENANCE_KEY_ID="$(go run ./cmd/gpmrecover inspect-key --private-key-file "$PROVENANCE_PRIVATE_KEY" | jq -r '.key_id')"

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url http://bridge.example \
  --path-id helper-web \
  --code test-code \
  --config-json "$TMP_DIR/missing-config.json" \
  --deploy-pack-dir "$TMP_DIR/missing-deploy-pack" \
  --print-summary-json 0 >"$TMP_DIR/public-http-pilot-bundle.log" 2>&1
public_http_rc=$?
set -e
if [[ "$public_http_rc" -eq 0 ]] ||
  ! grep -Fq -- '--base-url must use HTTPS for non-loopback pilot evidence targets' "$TMP_DIR/public-http-pilot-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: public HTTP base URL was not rejected"
  cat "$TMP_DIR/public-http-pilot-bundle.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url https://192.168.50.10 \
  --path-id helper-web \
  --code test-code \
  --config-json "$TMP_DIR/missing-config.json" \
  --deploy-pack-dir "$TMP_DIR/missing-deploy-pack" \
  --print-summary-json 0 >"$TMP_DIR/private-https-pilot-bundle.log" 2>&1
private_https_rc=$?
set -e
if [[ "$private_https_rc" -eq 0 ]] ||
  ! grep -Fq -- '--base-url host must look public-routable for non-loopback pilot evidence targets' "$TMP_DIR/private-https-pilot-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: private HTTPS base URL was not rejected"
  cat "$TMP_DIR/private-https-pilot-bundle.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url 'https://[::ffff:0a00:0008]' \
  --path-id helper-web \
  --code test-code \
  --config-json "$TMP_DIR/missing-config.json" \
  --deploy-pack-dir "$TMP_DIR/missing-deploy-pack" \
  --print-summary-json 0 >"$TMP_DIR/ipv4-mapped-private-https-pilot-bundle.log" 2>&1
ipv4_mapped_private_https_rc=$?
set -e
if [[ "$ipv4_mapped_private_https_rc" -eq 0 ]] ||
  ! grep -Fq -- '--base-url host must look public-routable for non-loopback pilot evidence targets' "$TMP_DIR/ipv4-mapped-private-https-pilot-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: IPv4-mapped private HTTPS base URL was not rejected"
  cat "$TMP_DIR/ipv4-mapped-private-https-pilot-bundle.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url https://helper.tailnet.ts.net \
  --path-id helper-web \
  --code test-code \
  --config-json "$TMP_DIR/missing-config.json" \
  --deploy-pack-dir "$TMP_DIR/missing-deploy-pack" \
  --print-summary-json 0 >"$TMP_DIR/overlay-https-pilot-bundle.log" 2>&1
overlay_https_rc=$?
set -e
if [[ "$overlay_https_rc" -eq 0 ]] ||
  ! grep -Fq -- '--base-url host must look public-routable for non-loopback pilot evidence targets' "$TMP_DIR/overlay-https-pilot-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: overlay HTTPS base URL was not rejected"
  cat "$TMP_DIR/overlay-https-pilot-bundle.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url https://helper.home.arpa \
  --path-id helper-web \
  --code test-code \
  --config-json "$TMP_DIR/missing-config.json" \
  --deploy-pack-dir "$TMP_DIR/missing-deploy-pack" \
  --print-summary-json 0 >"$TMP_DIR/home-arpa-https-pilot-bundle.log" 2>&1
home_arpa_https_rc=$?
set -e
if [[ "$home_arpa_https_rc" -eq 0 ]] ||
  ! grep -Fq -- '--base-url host must look public-routable for non-loopback pilot evidence targets' "$TMP_DIR/home-arpa-https-pilot-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: home.arpa HTTPS base URL was not rejected"
  cat "$TMP_DIR/home-arpa-https-pilot-bundle.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url http://127.evil.example \
  --path-id helper-web \
  --code test-code \
  --config-json "$TMP_DIR/missing-config.json" \
  --deploy-pack-dir "$TMP_DIR/missing-deploy-pack" \
  --print-summary-json 0 >"$TMP_DIR/loopback-looking-dns-http-pilot-bundle.log" 2>&1
loopback_dns_http_rc=$?
set -e
if [[ "$loopback_dns_http_rc" -eq 0 ]] ||
  ! grep -Fq -- '--base-url must use HTTPS for non-loopback pilot evidence targets' "$TMP_DIR/loopback-looking-dns-http-pilot-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: 127.* DNS name was incorrectly treated as loopback for HTTP"
  cat "$TMP_DIR/loopback-looking-dns-http-pilot-bundle.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url https://127.evil.example \
  --path-id helper-web \
  --code test-code \
  --config-json "$TMP_DIR/missing-config.json" \
  --deploy-pack-dir "$TMP_DIR/missing-deploy-pack" \
  --print-summary-json 0 >"$TMP_DIR/loopback-looking-dns-https-pilot-bundle.log" 2>&1
loopback_dns_https_rc=$?
set -e
if [[ "$loopback_dns_https_rc" -eq 0 ]] ||
  ! grep -Fq -- '--base-url host must look public-routable for non-loopback pilot evidence targets' "$TMP_DIR/loopback-looking-dns-https-pilot-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: 127.* DNS name was incorrectly treated as loopback for HTTPS"
  cat "$TMP_DIR/loopback-looking-dns-https-pilot-bundle.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url https://recovery-helper.gpm-pilot.net \
  --path-id helper-web \
  --code test-code \
  --config-json "$TMP_DIR/missing-config.json" \
  --deploy-pack-dir "$TMP_DIR/missing-deploy-pack" \
  --print-summary-json 0 >"$TMP_DIR/public-https-unsigned-pilot-bundle.log" 2>&1
public_https_unsigned_rc=$?
set -e
if [[ "$public_https_unsigned_rc" -eq 0 ]] ||
  ! grep -Fq -- 'real helper HTTPS pilot handoff requires --provenance-sign 1' "$TMP_DIR/public-https-unsigned-pilot-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: unsigned public HTTPS handoff was not rejected"
  cat "$TMP_DIR/public-https-unsigned-pilot-bundle.log"
  exit 1
fi

go run ./cmd/gpmrecover demo-bundle \
  --out-dir "$BUNDLE_DIR" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --base-url https://pilot.gpm-pilot.net \
  --helper-id helper-pilot \
  --helper-name "Pilot Helper" \
  --helper-url https://helper.gpm-pilot.net/pilot/bootstrap \
  --helper-contact https://helper-pilot.gpm-pilot.net/contact \
  >"$TMP_DIR/demo-bundle.stdout.json"

trust_store="$(jq -r '.files.trust_store' "$BUNDLE_DIR/demo-manifest.json")"
bridge_invite="$(jq -r '.files.bridge_invite_signed' "$BUNDLE_DIR/demo-manifest.json")"
signed_registry="$(jq -r '.files.bridge_helper_registry_signed' "$BUNDLE_DIR/demo-manifest.json")"

go run ./cmd/gpmrecover bridge-service-config \
  --invite "$bridge_invite" \
  --trust-store "$trust_store" \
  --signed-helper-registry "$signed_registry" \
  --out "$SERVICE_CONFIG" >/dev/null
config_sha256="$(sha256sum "$SERVICE_CONFIG" | awk '{print $1}')"
registry_id="$(jq -r '.registry_id' "$SERVICE_CONFIG")"
go run ./cmd/gpmrecover bridge-service-code-generate --code-out "$CODE_FILE" --hash-out "$CODE_HASH_JSON" >/dev/null
code_value="$(tr -d '\r\n' <"$CODE_FILE")"
code_hash="$(jq -r '.sha256' "$CODE_HASH_JSON")"

go run ./cmd/gpmrecover bridge-service-deploy-pack \
  --out-dir "$DEPLOY_PACK" \
  --service-name gpm-access-bridge-pilot \
  --public-host "$PILOT_PUBLIC_HOST" \
  --install-dir /etc/gpm/access-bridge-pilot \
  --config /etc/gpm/access-bridge-pilot/bridge-service-config.json \
  --config-sha256 "$config_sha256" \
  --access-code-sha256 "$code_hash" >/dev/null
printf '%s\n' 'should-not-copy-private-key' >"$DEPLOY_PACK/recovery.key"
printf '%s\n' "$code_value" >"$DEPLOY_PACK/bridge-code.txt"

go run ./cmd/gpmrecover bridge-service-serve \
  --config "$SERVICE_CONFIG" \
  --config-sha256 "$config_sha256" \
  --addr "127.0.0.1:${PORT}" \
  --rps 20 \
  --abuse-log "$ABUSE_LOG" \
  --access-code-sha256 "$code_hash" \
  >"$SERVER_LOG" 2>&1 &
BRIDGE_PID=$!

for _ in $(seq 1 60); do
  if curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$BRIDGE_PID" >/dev/null 2>&1; then
    echo "access bridge pilot evidence bundle integration failed: server exited early"
    cat "$SERVER_LOG"
    exit 1
  fi
  sleep 0.5
done

if ! curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
  echo "access bridge pilot evidence bundle integration failed: health did not become ready"
  cat "$SERVER_LOG"
  exit 1
fi

bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url "$BASE_URL" \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$DEPLOY_PACK" \
  --service-name gpm-access-bridge-pilot \
  --expected-public-host "$PILOT_PUBLIC_HOST" \
  --bundle-dir "$EVIDENCE_BUNDLE" \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --provenance-sign 1 \
  --provenance-private-key-file "$PROVENANCE_PRIVATE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --provenance-key-id "$PROVENANCE_KEY_ID" \
  --provenance-lifetime-hours 24 \
  --provenance-out "$PROVENANCE_JSON" \
  --print-summary-json 1 >"$TMP_DIR/pilot-bundle.log"

if [[ ! -f "$SUMMARY_JSON" || ! -f "$REPORT_MD" ]]; then
  echo "access bridge pilot evidence bundle integration failed: summary/report missing"
  cat "$TMP_DIR/pilot-bundle.log"
  exit 1
fi

if ! jq -e \
  --arg bundle_dir "$EVIDENCE_BUNDLE" \
  --arg base_url "$BASE_URL" \
  --arg registry_id "$registry_id" \
  --arg provenance_json "$PROVENANCE_JSON" \
  --arg pilot_public_host "$PILOT_PUBLIC_HOST" \
  '
    .schema.id == "access_bridge_pilot_evidence_bundle_summary"
    and .schema.minor >= 3
    and .status == "pass"
    and .evidence_scope == "local_rehearsal"
    and .pilot_handoff_ready == false
    and .trusted_verifier_receipt_required == true
    and (.notes | contains("local rehearsal evidence"))
    and .evidence_policy.require_https == true
    and .evidence_policy.require_public_host == true
    and .evidence_policy.require_tls_verified == true
    and .evidence_policy.base_url_loopback == true
    and .evidence_policy.base_url_private_or_reserved == true
    and .transport.status == "pass"
    and .transport.https == false
    and .transport.tls_verified == false
    and .transport.smoke_summary_json == .artifacts.smoke_summary_json
    and .inputs.base_url == $base_url
    and .inputs.expected_public_host == $pilot_public_host
    and .inputs.access_code_redacted == true
    and .expected_identity.helper_id == "helper-pilot"
    and .expected_identity.organization_id == "pilot-org"
    and .expected_identity.registry_id == $registry_id
    and .summary.steps_total == 3
    and .summary.steps_fail == 0
    and ([.steps[].status] | all(. == "pass"))
    and .artifacts.bundle_dir == $bundle_dir
    and (.artifacts.smoke_summary_json | length > 0)
    and (.artifacts.deployment_evidence_summary_json | length > 0)
    and (.artifacts.host_install_check_summary_json | length > 0)
    and (.artifacts.manifest_sha256 | length > 0)
    and (.artifacts.bundle_tar | length > 0)
    and (.artifacts.bundle_tar_sha256_file | length > 0)
    and (.artifacts.bundled_summary_json | length > 0)
    and (.artifacts.deploy_pack_skipped_secrets | length > 0)
    and .artifacts.provenance_json == $provenance_json
    and .provenance.enabled == true
    and .provenance.sidecar_json == $provenance_json
    and .provenance.key_id == "'"$PROVENANCE_KEY_ID"'"
    and .provenance.lifetime_hours == 24
    and .recommended_next_action.id == "capture_real_helper_https_evidence"
  ' "$SUMMARY_JSON" >/dev/null; then
  echo "access bridge pilot evidence bundle integration failed: pass summary contract mismatch"
  cat "$SUMMARY_JSON"
  exit 1
fi

HOST_INSTALL_SUMMARY="$(jq -r '.artifacts.host_install_check_summary_json' "$SUMMARY_JSON")"
if ! jq -e \
  --arg pilot_public_host "$PILOT_PUBLIC_HOST" \
  '
    .schema.id == "access_bridge_host_install_check_summary"
    and .schema.minor >= 4
    and .status == "pass"
    and .observed.expected_public_host == $pilot_public_host
    and .summary.checks_total >= 26
    and (([.checks[] | select(.id == "caddy_public_host_matches_expected" and .status == "pass")] | length) == 1)
    and (([.checks[] | select(.id == "nginx_public_host_matches_expected" and .status == "pass")] | length) == 1)
  ' "$HOST_INSTALL_SUMMARY" >/dev/null; then
  echo "access bridge pilot evidence bundle integration failed: expected public host install summary mismatch"
  cat "$HOST_INSTALL_SUMMARY"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url "https://public.example@127.0.0.1:19820" \
  --path-id helper-web >"$TMP_DIR/pilot-bundle-userinfo-url.log" 2>&1
userinfo_url_rc=$?
set -e
if [[ "$userinfo_url_rc" -eq 0 ]] || ! grep -Fq -- "--base-url must not include userinfo" "$TMP_DIR/pilot-bundle-userinfo-url.log"; then
  echo "access bridge pilot evidence bundle integration failed: userinfo URL was not rejected before pilot evidence classification"
  cat "$TMP_DIR/pilot-bundle-userinfo-url.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url "https://[2001:db8::1]:19820" \
  --path-id helper-web \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$DEPLOY_PACK" \
  --code-file "$CODE_FILE" >"$TMP_DIR/pilot-bundle-doc-ipv6-url.log" 2>&1
doc_ipv6_url_rc=$?
set -e
if [[ "$doc_ipv6_url_rc" -eq 0 ]] || ! grep -Fq -- "--base-url host must look public-routable" "$TMP_DIR/pilot-bundle-doc-ipv6-url.log"; then
  echo "access bridge pilot evidence bundle integration failed: documentation IPv6 URL was not rejected as non-public"
  cat "$TMP_DIR/pilot-bundle-doc-ipv6-url.log"
  exit 1
fi

non_public_ipv6_urls=(
  "https://[fe90::1]:19820"
  "https://[fea0::1]:19820"
  "https://[febf::1]:19820"
  "https://[2001:0db8::1]:19820"
)
non_public_ipv6_index=0
for non_public_ipv6_url in "${non_public_ipv6_urls[@]}"; do
  non_public_ipv6_index=$((non_public_ipv6_index + 1))
  set +e
  bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
    --base-url "$non_public_ipv6_url" \
    --path-id helper-web \
    --config-json "$SERVICE_CONFIG" \
    --deploy-pack-dir "$DEPLOY_PACK" \
    --code-file "$CODE_FILE" >"$TMP_DIR/pilot-bundle-non-public-ipv6-$non_public_ipv6_index.log" 2>&1
  non_public_ipv6_rc=$?
  set -e
  if [[ "$non_public_ipv6_rc" -eq 0 ]] || ! grep -Fq -- "--base-url host must look public-routable" "$TMP_DIR/pilot-bundle-non-public-ipv6-$non_public_ipv6_index.log"; then
    echo "access bridge pilot evidence bundle integration failed: non-public IPv6 URL was not rejected: $non_public_ipv6_url"
    cat "$TMP_DIR/pilot-bundle-non-public-ipv6-$non_public_ipv6_index.log"
    exit 1
  fi
done

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url "https://[2606:4700:4700::1111]:19820" \
  --path-id helper-web \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$DEPLOY_PACK" \
  --code-file "$CODE_FILE" >"$TMP_DIR/pilot-bundle-public-ipv6-url.log" 2>&1
public_ipv6_url_rc=$?
set -e
if [[ "$public_ipv6_url_rc" -eq 0 ]] ||
  grep -Fq -- "--base-url host must look public-routable" "$TMP_DIR/pilot-bundle-public-ipv6-url.log" ||
  ! grep -Fq -- "real helper HTTPS pilot handoff requires --provenance-sign 1" "$TMP_DIR/pilot-bundle-public-ipv6-url.log"; then
  echo "access bridge pilot evidence bundle integration failed: public IPv6 URL did not advance past public-host classification"
  cat "$TMP_DIR/pilot-bundle-public-ipv6-url.log"
  exit 1
fi

if [[ ! -f "$EVIDENCE_BUNDLE/access_bridge_service_smoke_summary.json" ||
  ! -f "$EVIDENCE_BUNDLE/access_bridge_deployment_evidence_summary.json" ||
  ! -f "$EVIDENCE_BUNDLE/access_bridge_host_install_check_summary.json" ||
  ! -f "$EVIDENCE_BUNDLE/bridge-service-config.json" ||
  ! -f "$EVIDENCE_BUNDLE/bridge-deploy-pack/gpm-access-bridge-pilot.env" ||
  ! -f "$EVIDENCE_BUNDLE/manifest.sha256" ||
  ! -f "${EVIDENCE_BUNDLE}.tar.gz" ||
  ! -f "${EVIDENCE_BUNDLE}.tar.gz.sha256" ||
  ! -f "$PROVENANCE_JSON" ]]; then
  echo "access bridge pilot evidence bundle integration failed: expected bundle artifacts missing"
  find "$EVIDENCE_BUNDLE" -maxdepth 3 -type f -print | sort
  exit 1
fi

if ! jq -e \
  --arg summary_sha256 "$(sha256sum "$SUMMARY_JSON" | awk '{print $1}')" \
  --arg bundle_tar_sha256 "$(sha256sum "${EVIDENCE_BUNDLE}.tar.gz" | awk '{print $1}')" \
  --arg bundle_tar_sha256_file_sha256 "$(sha256sum "${EVIDENCE_BUNDLE}.tar.gz.sha256" | awk '{print $1}')" \
  --arg key_id "$PROVENANCE_KEY_ID" \
  --arg bundle_tar_name "$(basename "${EVIDENCE_BUNDLE}.tar.gz")" \
  '.schema_version == 1
    and .organization.org_id == "pilot-org"
    and .organization.name == "Pilot Org"
    and .subject.kind == "access_bridge_pilot_evidence_bundle"
    and .subject.evidence_scope == "local_rehearsal"
    and .subject.summary_json_sha256 == $summary_sha256
    and .subject.bundle_tar_sha256 == $bundle_tar_sha256
    and .subject.bundle_tar_sha256_sidecar_sha256 == $bundle_tar_sha256_file_sha256
    and .subject.bundle_tar_name == $bundle_tar_name
    and .signature.alg == "ed25519"
    and .signature.key_id == $key_id
    and (.signature.sig | length) > 0' \
  "$PROVENANCE_JSON" >/dev/null; then
  echo "access bridge pilot evidence bundle integration failed: provenance sidecar contract mismatch"
  cat "$PROVENANCE_JSON"
  exit 1
fi

bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --public-key-file "$PROVENANCE_PUBLIC_KEY" \
  --show-details 1 >"$TMP_DIR/pilot-bundle-verify.log"

if ! tar -tzf "${EVIDENCE_BUNDLE}.tar.gz" | grep -Fq "$(basename "$EVIDENCE_BUNDLE")/manifest.sha256"; then
  echo "access bridge pilot evidence bundle integration failed: tar missing manifest"
  tar -tzf "${EVIDENCE_BUNDLE}.tar.gz"
  exit 1
fi
if tar -tzf "${EVIDENCE_BUNDLE}.tar.gz" | grep -Fq "$(basename "$PROVENANCE_JSON")"; then
  echo "access bridge pilot evidence bundle integration failed: provenance sidecar was included in evidence tar"
  tar -tzf "${EVIDENCE_BUNDLE}.tar.gz"
  exit 1
fi
if grep -Fq "$(basename "$PROVENANCE_JSON")" "$EVIDENCE_BUNDLE/manifest.sha256"; then
  echo "access bridge pilot evidence bundle integration failed: provenance sidecar was included in manifest"
  cat "$EVIDENCE_BUNDLE/manifest.sha256"
  exit 1
fi

if rg -Fq -- "$code_value" "$EVIDENCE_BUNDLE" "$SUMMARY_JSON" "$REPORT_MD"; then
  echo "access bridge pilot evidence bundle integration failed: plaintext access code leaked into evidence"
  exit 1
fi
if find "$EVIDENCE_BUNDLE" -type f -name 'bridge-code.txt' -print -quit | grep -q .; then
  echo "access bridge pilot evidence bundle integration failed: code file copied into evidence bundle"
  exit 1
fi
if find "$EVIDENCE_BUNDLE" -type f -name 'recovery.key' -print -quit | grep -q .; then
  echo "access bridge pilot evidence bundle integration failed: recovery private key copied into evidence bundle"
  exit 1
fi
if tar -tzf "${EVIDENCE_BUNDLE}.tar.gz" | grep -Eq '(^|/)(bridge-code\.txt|recovery\.key)$'; then
  echo "access bridge pilot evidence bundle integration failed: secret file copied into evidence tar"
  tar -tzf "${EVIDENCE_BUNDLE}.tar.gz"
  exit 1
fi
if ! grep -Fxq 'recovery.key' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt" ||
  ! grep -Fxq 'bridge-code.txt' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt"; then
  echo "access bridge pilot evidence bundle integration failed: skipped secret list mismatch"
  cat "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt"
  exit 1
fi

BAD_DEPLOY_PACK="$TMP_DIR/bad-deploy-pack"
cp -R "$DEPLOY_PACK" "$BAD_DEPLOY_PACK"
sed -i 's/GPM_BRIDGE_ALLOW_QUERY_CODE="false"/GPM_BRIDGE_ALLOW_QUERY_CODE="true"/' "$BAD_DEPLOY_PACK/gpm-access-bridge-pilot.env"
BAD_SUMMARY="$TMP_DIR/pilot-evidence-bad-summary.json"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url "$BASE_URL" \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$BAD_DEPLOY_PACK" \
  --service-name gpm-access-bridge-pilot \
  --bundle-dir "$TMP_DIR/bad-pilot-evidence-bundle" \
  --summary-json "$BAD_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/bad-pilot-bundle.log" 2>&1
bad_rc=$?
set -e
if [[ "$bad_rc" -eq 0 ]]; then
  echo "access bridge pilot evidence bundle integration failed: bad deploy pack should fail"
  cat "$BAD_SUMMARY"
  exit 1
fi
if ! jq -e '.status == "fail" and .recommended_next_action.id == "fix_access_bridge_deployment_evidence"' "$BAD_SUMMARY" >/dev/null; then
  echo "access bridge pilot evidence bundle integration failed: bad deploy summary mismatch"
  cat "$BAD_SUMMARY"
  exit 1
fi

echo "access bridge pilot evidence bundle integration check ok"
