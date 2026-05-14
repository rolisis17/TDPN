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
SYMLINK_OUTPUT_TESTS_ENABLED="0"

SYMLINK_PROBE_TARGET="$TMP_DIR/symlink-output-probe-target"
SYMLINK_PROBE_LINK="$TMP_DIR/symlink-output-probe-link"
printf '%s\n' 'probe' >"$SYMLINK_PROBE_TARGET"
if command -v ln >/dev/null 2>&1 &&
  ln -s "$SYMLINK_PROBE_TARGET" "$SYMLINK_PROBE_LINK" 2>/dev/null &&
  [[ -L "$SYMLINK_PROBE_LINK" ]]; then
  SYMLINK_OUTPUT_TESTS_ENABLED="1"
fi
rm -f "$SYMLINK_PROBE_LINK"

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
cat >"$DEPLOY_PACK/operator.pem" <<'EOF_OPERATOR_PEM'
-----BEGIN PRIVATE KEY-----
not-a-real-key-but-private-key-material-for-filter-test
-----END PRIVATE KEY-----
EOF_OPERATOR_PEM
mkdir -p "$DEPLOY_PACK/keys"
cat >"$DEPLOY_PACK/keys/id_ed25519" <<'EOF_OPENSSH_KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
not-a-real-openssh-key-but-private-key-material-for-filter-test
-----END OPENSSH PRIVATE KEY-----
EOF_OPENSSH_KEY
printf '%s\n' 'DOTENV_SECRET=should-not-copy' >"$DEPLOY_PACK/.env"
printf '%s\n' 'token should not copy' >"$DEPLOY_PACK/api-token.txt"
printf '%s\n' 'password should not copy' >"$DEPLOY_PACK/db-password.txt"
printf '%s\n' 'passwd should not copy' >"$DEPLOY_PACK/shadow.passwd"
printf '%s\n' 'auth should not copy' >"$DEPLOY_PACK/auth-header.txt"
printf '%s\n' 'bearer should not copy' >"$DEPLOY_PACK/bearer-creds.txt"
printf '%s\n' 'oauth should not copy' >"$DEPLOY_PACK/oauth-client.json"

STALE_BUNDLE_DIR="$TMP_DIR/stale-pilot-evidence-bundle"
mkdir -p "$STALE_BUNDLE_DIR"
printf '%s\n' 'old-demo-artifact' >"$STALE_BUNDLE_DIR/old-demo-artifact.txt"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url "$BASE_URL" \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$DEPLOY_PACK" \
  --service-name gpm-access-bridge-pilot \
  --bundle-dir "$STALE_BUNDLE_DIR" \
  --summary-json "$TMP_DIR/stale-pilot-evidence-summary.json" \
  --provenance-sign 1 \
  --provenance-private-key-file "$PROVENANCE_PRIVATE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --provenance-key-id "$PROVENANCE_KEY_ID" \
  --provenance-out "$TMP_DIR/stale-pilot-evidence.provenance.json" \
  --print-summary-json 0 >"$TMP_DIR/stale-pilot-evidence-bundle.log" 2>&1
stale_bundle_dir_rc=$?
set -e
if [[ "$stale_bundle_dir_rc" -eq 0 ]] ||
  ! grep -Fq -- '--bundle-dir already exists and is not empty' "$TMP_DIR/stale-pilot-evidence-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: stale explicit bundle dir was not rejected"
  cat "$TMP_DIR/stale-pilot-evidence-bundle.log"
  exit 1
fi

if [[ "$SYMLINK_OUTPUT_TESTS_ENABLED" != "1" ]]; then
  echo "[access-bridge-pilot-evidence-bundle] output symlink rejection skipped (symlink unsupported in current environment)"
else
  SYMLINK_OUTPUT_TARGET="$TMP_DIR/symlink-output-target"
  printf '%s\n' 'do-not-overwrite-through-symlink' >"$SYMLINK_OUTPUT_TARGET"

  SYMLINK_TAR_BUNDLE_DIR="$TMP_DIR/symlink-tar-pilot-evidence-bundle"
  ln -s "$SYMLINK_OUTPUT_TARGET" "${SYMLINK_TAR_BUNDLE_DIR}.tar.gz"
  set +e
  bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
    --base-url "$BASE_URL" \
    --path-id helper-web \
    --code-file "$CODE_FILE" \
    --config-json "$SERVICE_CONFIG" \
    --deploy-pack-dir "$DEPLOY_PACK" \
    --service-name gpm-access-bridge-pilot \
    --bundle-dir "$SYMLINK_TAR_BUNDLE_DIR" \
    --summary-json "$TMP_DIR/symlink-tar-pilot-evidence-summary.json" \
    --print-summary-json 0 >"$TMP_DIR/symlink-tar-pilot-evidence-bundle.log" 2>&1
  symlink_tar_rc=$?
  set -e
  if [[ "$symlink_tar_rc" -eq 0 ]] ||
    ! grep -Fq -- 'refusing to write evidence output through symlink' "$TMP_DIR/symlink-tar-pilot-evidence-bundle.log"; then
    echo "access bridge pilot evidence bundle integration failed: symlinked bundle tar sidecar was not rejected"
    cat "$TMP_DIR/symlink-tar-pilot-evidence-bundle.log"
    exit 1
  fi

  SYMLINK_SHA_BUNDLE_DIR="$TMP_DIR/symlink-sha-pilot-evidence-bundle"
  ln -s "$SYMLINK_OUTPUT_TARGET" "${SYMLINK_SHA_BUNDLE_DIR}.tar.gz.sha256"
  set +e
  bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
    --base-url "$BASE_URL" \
    --path-id helper-web \
    --code-file "$CODE_FILE" \
    --config-json "$SERVICE_CONFIG" \
    --deploy-pack-dir "$DEPLOY_PACK" \
    --service-name gpm-access-bridge-pilot \
    --bundle-dir "$SYMLINK_SHA_BUNDLE_DIR" \
    --summary-json "$TMP_DIR/symlink-sha-pilot-evidence-summary.json" \
    --print-summary-json 0 >"$TMP_DIR/symlink-sha-pilot-evidence-bundle.log" 2>&1
  symlink_sha_rc=$?
  set -e
  if [[ "$symlink_sha_rc" -eq 0 ]] ||
    ! grep -Fq -- 'refusing to write evidence output through symlink' "$TMP_DIR/symlink-sha-pilot-evidence-bundle.log"; then
    echo "access bridge pilot evidence bundle integration failed: symlinked bundle checksum sidecar was not rejected"
    cat "$TMP_DIR/symlink-sha-pilot-evidence-bundle.log"
    exit 1
  fi

  SYMLINK_PROVENANCE_BUNDLE_DIR="$TMP_DIR/symlink-provenance-pilot-evidence-bundle"
  SYMLINK_PROVENANCE_OUT="$TMP_DIR/symlink-provenance-pilot-evidence.provenance.json"
  ln -s "$SYMLINK_OUTPUT_TARGET" "$SYMLINK_PROVENANCE_OUT"
  set +e
  bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
    --base-url "$BASE_URL" \
    --path-id helper-web \
    --code-file "$CODE_FILE" \
    --config-json "$SERVICE_CONFIG" \
    --deploy-pack-dir "$DEPLOY_PACK" \
    --service-name gpm-access-bridge-pilot \
    --bundle-dir "$SYMLINK_PROVENANCE_BUNDLE_DIR" \
    --summary-json "$TMP_DIR/symlink-provenance-pilot-evidence-summary.json" \
    --provenance-sign 1 \
    --provenance-private-key-file "$PROVENANCE_PRIVATE_KEY" \
    --provenance-org-id pilot-org \
    --provenance-org-name "Pilot Org" \
    --provenance-key-id "$PROVENANCE_KEY_ID" \
    --provenance-out "$SYMLINK_PROVENANCE_OUT" \
    --print-summary-json 0 >"$TMP_DIR/symlink-provenance-pilot-evidence-bundle.log" 2>&1
  symlink_provenance_rc=$?
  set -e
  if [[ "$symlink_provenance_rc" -eq 0 ]] ||
    ! grep -Fq -- 'refusing to write evidence output through symlink' "$TMP_DIR/symlink-provenance-pilot-evidence-bundle.log"; then
    echo "access bridge pilot evidence bundle integration failed: symlinked provenance sidecar was not rejected"
    cat "$TMP_DIR/symlink-provenance-pilot-evidence-bundle.log"
    exit 1
  fi

  if [[ "$(cat "$SYMLINK_OUTPUT_TARGET")" != "do-not-overwrite-through-symlink" ]]; then
    echo "access bridge pilot evidence bundle integration failed: symlink target was modified"
    cat "$SYMLINK_OUTPUT_TARGET"
    exit 1
  fi
fi

DEMO_PATH_DIR="$TMP_DIR/generated-demo"
mkdir -p "$DEMO_PATH_DIR"
DEMO_PATH_CONFIG="$DEMO_PATH_DIR/generated-demo-config.json"
cp "$SERVICE_CONFIG" "$DEMO_PATH_CONFIG"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url https://recovery-helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$DEMO_PATH_CONFIG" \
  --deploy-pack-dir "$DEPLOY_PACK" \
  --service-name gpm-access-bridge-pilot \
  --expect-registry-id registry-pilot \
  --provenance-sign 1 \
  --provenance-private-key-file "$PROVENANCE_PRIVATE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --provenance-key-id "$PROVENANCE_KEY_ID" \
  --provenance-out "$TMP_DIR/demo-path-pilot-evidence.provenance.json" \
  --print-summary-json 0 >"$TMP_DIR/demo-path-pilot-evidence-bundle.log" 2>&1
demo_path_bundle_rc=$?
set -e
if [[ "$demo_path_bundle_rc" -eq 0 ]] ||
  ! grep -Fq -- '--config-json must not use generated demo/example artifacts for real helper HTTPS pilot handoff' "$TMP_DIR/demo-path-pilot-evidence-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: demo/example config path was not rejected for real helper HTTPS pilot handoff"
  cat "$TMP_DIR/demo-path-pilot-evidence-bundle.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url https://recovery-helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$DEPLOY_PACK" \
  --service-name gpm-access-bridge-pilot \
  --expect-helper-id helper-pilot \
  --expect-org-id pilot-org \
  --expect-registry-id registry-pilot \
  --provenance-sign 1 \
  --provenance-private-key-file "$PROVENANCE_PRIVATE_KEY" \
  --provenance-org-id freenews-demo \
  --provenance-org-name "Pilot Org" \
  --provenance-key-id "$PROVENANCE_KEY_ID" \
  --provenance-out "$TMP_DIR/demo-provenance-id-pilot-evidence.provenance.json" \
  --print-summary-json 0 >"$TMP_DIR/demo-provenance-id-pilot-evidence-bundle.log" 2>&1
demo_provenance_id_bundle_rc=$?
set -e
if [[ "$demo_provenance_id_bundle_rc" -eq 0 ]] ||
  ! grep -Fq -- '--provenance-org-id must not use a generated demo/example identity for real helper HTTPS pilot handoff' "$TMP_DIR/demo-provenance-id-pilot-evidence-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: demo provenance org id was not rejected for real helper HTTPS pilot handoff"
  cat "$TMP_DIR/demo-provenance-id-pilot-evidence-bundle.log"
  exit 1
fi

DEMO_HELPER_CONFIG="$TMP_DIR/demo-helper-config.json"
jq '.helper_id = "helper-demo"' "$SERVICE_CONFIG" >"$DEMO_HELPER_CONFIG"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url https://recovery-helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$DEMO_HELPER_CONFIG" \
  --deploy-pack-dir "$DEPLOY_PACK" \
  --service-name gpm-access-bridge-pilot \
  --provenance-sign 1 \
  --provenance-private-key-file "$PROVENANCE_PRIVATE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --provenance-key-id "$PROVENANCE_KEY_ID" \
  --provenance-out "$TMP_DIR/demo-helper-config-pilot-evidence.provenance.json" \
  --print-summary-json 0 >"$TMP_DIR/demo-helper-config-pilot-evidence-bundle.log" 2>&1
demo_helper_config_bundle_rc=$?
set -e
if [[ "$demo_helper_config_bundle_rc" -eq 0 ]] ||
  ! grep -Fq -- 'expected helper identity must not use a generated demo/example identity for real helper HTTPS pilot handoff' "$TMP_DIR/demo-helper-config-pilot-evidence-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: config-inferred demo helper id was not rejected for real helper HTTPS pilot handoff"
  cat "$TMP_DIR/demo-helper-config-pilot-evidence-bundle.log"
  exit 1
fi

MISSING_HELPER_CONFIG="$TMP_DIR/missing-helper-config.json"
jq 'del(.helper_id)' "$SERVICE_CONFIG" >"$MISSING_HELPER_CONFIG"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url https://recovery-helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
	  --config-json "$MISSING_HELPER_CONFIG" \
	  --deploy-pack-dir "$DEPLOY_PACK" \
	  --service-name gpm-access-bridge-pilot \
	  --expect-registry-id registry-pilot \
	  --provenance-sign 1 \
  --provenance-private-key-file "$PROVENANCE_PRIVATE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --provenance-key-id "$PROVENANCE_KEY_ID" \
  --provenance-out "$TMP_DIR/missing-helper-config-pilot-evidence.provenance.json" \
  --print-summary-json 0 >"$TMP_DIR/missing-helper-config-pilot-evidence-bundle.log" 2>&1
missing_helper_config_bundle_rc=$?
set -e
if [[ "$missing_helper_config_bundle_rc" -eq 0 ]] ||
  ! grep -Fq -- 'real helper HTTPS pilot handoff requires expected helper, organization, and registry identities' "$TMP_DIR/missing-helper-config-pilot-evidence-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: missing helper id was not rejected for real helper HTTPS pilot handoff"
  cat "$TMP_DIR/missing-helper-config-pilot-evidence-bundle.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url https://recovery-helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
	  --config-json "$SERVICE_CONFIG" \
	  --deploy-pack-dir "$DEPLOY_PACK" \
	  --service-name gpm-access-bridge-pilot \
	  --expect-helper-id helper-pilot \
	  --expect-org-id pilot-org \
	  --expect-registry-id registry-pilot \
	  --provenance-sign 1 \
  --provenance-private-key-file "$PROVENANCE_PRIVATE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --provenance-key-id "$PROVENANCE_KEY_ID" \
  --provenance-out "$TMP_DIR/deploy-pack-mode-pilot-evidence.provenance.json" \
  --print-summary-json 0 >"$TMP_DIR/deploy-pack-mode-pilot-evidence-bundle.log" 2>&1
deploy_pack_mode_bundle_rc=$?
set -e
if [[ "$deploy_pack_mode_bundle_rc" -eq 0 ]] ||
  ! grep -Fq -- 'real helper HTTPS pilot handoff requires --host-install-evidence-mode installed-host' "$TMP_DIR/deploy-pack-mode-pilot-evidence-bundle.log"; then
  echo "access bridge pilot evidence bundle integration failed: deploy-pack host evidence was not rejected for real helper HTTPS pilot handoff"
  cat "$TMP_DIR/deploy-pack-mode-pilot-evidence-bundle.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url "$BASE_URL" \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$DEPLOY_PACK" \
  --service-name gpm-access-bridge-pilot \
  --require-mtls 1 \
  --bundle-dir "$TMP_DIR/pilot-evidence-bundle-require-mtls-no-cert" \
  --summary-json "$TMP_DIR/pilot-evidence-bundle-require-mtls-no-cert.json" \
  --provenance-sign 1 \
  --provenance-private-key-file "$PROVENANCE_PRIVATE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --provenance-key-id "$PROVENANCE_KEY_ID" \
  --provenance-out "$TMP_DIR/pilot-evidence-bundle-require-mtls-no-cert.provenance.json" \
  --print-summary-json 0 >"$TMP_DIR/pilot-bundle-require-mtls-no-cert.log" 2>&1
require_mtls_no_cert_rc=$?
set -e
if [[ "$require_mtls_no_cert_rc" -eq 0 ]] ||
  ! grep -Fq -- '--require-mtls 1 requires --client-cert and --client-key' "$TMP_DIR/pilot-bundle-require-mtls-no-cert.log"; then
  echo "access bridge pilot evidence bundle integration failed: require-mtls without client cert was not rejected"
  cat "$TMP_DIR/pilot-bundle-require-mtls-no-cert.log"
  exit 1
fi

FAKE_SMOKE_SCRIPT="$TMP_DIR/fake_access_bridge_service_smoke.sh"
FAKE_DEPLOYMENT_SCRIPT="$TMP_DIR/fake_access_bridge_deployment_evidence.sh"
FAKE_HOST_SCRIPT="$TMP_DIR/fake_access_bridge_host_install_check.sh"
cat >"$FAKE_SMOKE_SCRIPT" <<'EOF_FAKE_SMOKE'
#!/usr/bin/env bash
set -euo pipefail
summary_json=""
base_url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --base-url)
      base_url="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$summary_json")"
jq -n --arg base_url "$base_url" '{
  schema:{id:"access_bridge_service_smoke_summary",major:1,minor:6},
  status:"pass",
  base_url:$base_url,
  path_id:"helper-web",
  auth:{required:true},
  health:{status:"ok",helper_id:"helper-pilot",organization_id:"pilot-org",registry_id:"registry-pilot",config_sha256:"fake-config-sha"},
  transport:{https:true,tls_verified:true,ssl_verify_result:"0"}
}' >"$summary_json"
EOF_FAKE_SMOKE
chmod +x "$FAKE_SMOKE_SCRIPT"

cat >"$FAKE_DEPLOYMENT_SCRIPT" <<'EOF_FAKE_DEPLOYMENT'
#!/usr/bin/env bash
set -euo pipefail
summary_json=""
smoke_summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --smoke-summary-json)
      smoke_summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$summary_json")"
smoke_sha="$(sha256sum "$smoke_summary_json" | awk '{print $1}')"
minor=6
embedded_sha="$smoke_sha"
binding_sha="$smoke_sha"
if [[ "${FAKE_DEPLOYMENT_EVIDENCE_MODE:-}" == "old-schema" ]]; then
  minor=5
elif [[ "${FAKE_DEPLOYMENT_EVIDENCE_MODE:-}" == "mismatch" ]]; then
  embedded_sha="0000000000000000000000000000000000000000000000000000000000000000"
  binding_sha="$embedded_sha"
fi
jq -n \
  --argjson minor "$minor" \
  --arg smoke_summary_json "$smoke_summary_json" \
  --arg smoke_sha "$embedded_sha" \
  --arg binding_sha "$binding_sha" \
  '{
    schema:{id:"access_bridge_deployment_evidence_summary",major:1,minor:$minor},
    status:"pass",
    evidence_scope:"real_helper_https",
    smoke:{summary_json:$smoke_summary_json,summary_sha256:$smoke_sha},
    evidence_binding:{smoke_summary_json:$smoke_summary_json,smoke_summary_sha256:$binding_sha},
    transport:{status:"pass",https:true,tls_verified:true,ssl_verify_result:"0"}
  }' >"$summary_json"
EOF_FAKE_DEPLOYMENT
chmod +x "$FAKE_DEPLOYMENT_SCRIPT"

cat >"$FAKE_HOST_SCRIPT" <<'EOF_FAKE_HOST'
#!/usr/bin/env bash
set -euo pipefail
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$summary_json")"
jq -n '{
  schema:{id:"access_bridge_host_install_check_summary",major:1,minor:4},
  status:"pass",
  inputs:{evidence_mode:"installed-host",installed_host_mode:true},
  observed:{evidence_mode:"installed-host",installed_host_mode:true},
  summary:{evidence_mode:"installed-host",installed_host_mode:true,checks_total:1},
  checks:[{id:"fake_installed_host",status:"pass"}]
}' >"$summary_json"
EOF_FAKE_HOST
chmod +x "$FAKE_HOST_SCRIPT"

FAKE_INSTALL_DIR="$TMP_DIR/fake-installed-host"
FAKE_SYSTEMD_UNIT="$TMP_DIR/fake-gpm-access-bridge.service"
FAKE_PROXY_CONFIG="$TMP_DIR/fake-Caddyfile"
mkdir -p "$FAKE_INSTALL_DIR"
printf '%s\n' '[Service]' >"$FAKE_SYSTEMD_UNIT"
printf '%s\n' 'recovery-helper.gpm-pilot.net { reverse_proxy 127.0.0.1:19791 }' >"$FAKE_PROXY_CONFIG"

set +e
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SERVICE_SMOKE_SCRIPT="$FAKE_SMOKE_SCRIPT" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_DEPLOYMENT_EVIDENCE_SCRIPT="$FAKE_DEPLOYMENT_SCRIPT" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_SCRIPT" \
FAKE_DEPLOYMENT_EVIDENCE_MODE=old-schema \
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url https://recovery-helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$DEPLOY_PACK" \
  --host-install-evidence-mode installed-host \
  --install-dir "$FAKE_INSTALL_DIR" \
  --systemd-unit-file "$FAKE_SYSTEMD_UNIT" \
  --proxy-kind caddy \
  --proxy-config-file "$FAKE_PROXY_CONFIG" \
  --service-name gpm-access-bridge-pilot \
  --expect-helper-id helper-pilot \
  --expect-org-id pilot-org \
  --expect-registry-id registry-pilot \
  --bundle-dir "$TMP_DIR/old-schema-pilot-evidence-bundle" \
  --summary-json "$TMP_DIR/old-schema-pilot-evidence-summary.json" \
  --provenance-sign 1 \
  --provenance-private-key-file "$PROVENANCE_PRIVATE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --provenance-key-id "$PROVENANCE_KEY_ID" \
  --provenance-out "$TMP_DIR/old-schema-pilot-evidence.provenance.json" \
  --print-summary-json 0 >"$TMP_DIR/old-schema-pilot-evidence-bundle.log" 2>&1
old_schema_bundle_rc=$?
set -e
if [[ "$old_schema_bundle_rc" -eq 0 ]] ||
  ! jq -e '.status == "fail"
    and .evidence_binding.status == "fail"
    and (.evidence_binding.reason | contains("schema >= 1.6"))
    and ([.steps[] | select(.id == "deployment_evidence" and .status == "fail" and (.evidence_binding_reason | contains("schema >= 1.6")))] | length) == 1' \
    "$TMP_DIR/old-schema-pilot-evidence-summary.json" >/dev/null; then
  echo "access bridge pilot evidence bundle integration failed: old deployment evidence schema was not rejected for real helper HTTPS handoff"
  cat "$TMP_DIR/old-schema-pilot-evidence-bundle.log"
  cat "$TMP_DIR/old-schema-pilot-evidence-summary.json"
  exit 1
fi

set +e
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SERVICE_SMOKE_SCRIPT="$FAKE_SMOKE_SCRIPT" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_DEPLOYMENT_EVIDENCE_SCRIPT="$FAKE_DEPLOYMENT_SCRIPT" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_SCRIPT" \
FAKE_DEPLOYMENT_EVIDENCE_MODE=mismatch \
bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url https://recovery-helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$DEPLOY_PACK" \
  --host-install-evidence-mode installed-host \
  --install-dir "$FAKE_INSTALL_DIR" \
  --systemd-unit-file "$FAKE_SYSTEMD_UNIT" \
  --proxy-kind caddy \
  --proxy-config-file "$FAKE_PROXY_CONFIG" \
  --service-name gpm-access-bridge-pilot \
  --expect-helper-id helper-pilot \
  --expect-org-id pilot-org \
  --expect-registry-id registry-pilot \
  --bundle-dir "$TMP_DIR/mismatch-pilot-evidence-bundle" \
  --summary-json "$TMP_DIR/mismatch-pilot-evidence-summary.json" \
  --provenance-sign 1 \
  --provenance-private-key-file "$PROVENANCE_PRIVATE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --provenance-key-id "$PROVENANCE_KEY_ID" \
  --provenance-out "$TMP_DIR/mismatch-pilot-evidence.provenance.json" \
  --print-summary-json 0 >"$TMP_DIR/mismatch-pilot-evidence-bundle.log" 2>&1
mismatch_bundle_rc=$?
set -e
if [[ "$mismatch_bundle_rc" -eq 0 ]] ||
  ! jq -e '.status == "fail"
    and .evidence_binding.status == "fail"
    and .evidence_binding.deployment_smoke_summary_sha256_matches_bundle == false
    and (.evidence_binding.reason | contains("does not match bundle smoke summary"))
    and ([.steps[] | select(.id == "deployment_evidence" and .status == "fail" and (.evidence_binding_reason | contains("does not match bundle smoke summary")))] | length) == 1' \
    "$TMP_DIR/mismatch-pilot-evidence-summary.json" >/dev/null; then
  echo "access bridge pilot evidence bundle integration failed: deployment evidence smoke hash mismatch was not rejected"
  cat "$TMP_DIR/mismatch-pilot-evidence-bundle.log"
  cat "$TMP_DIR/mismatch-pilot-evidence-summary.json"
  exit 1
fi

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
  --arg smoke_summary_sha256 "$(sha256sum "$EVIDENCE_BUNDLE/access_bridge_service_smoke_summary.json" | awk '{print $1}')" \
  --arg deployment_evidence_summary_sha256 "$(sha256sum "$EVIDENCE_BUNDLE/access_bridge_deployment_evidence_summary.json" | awk '{print $1}')" \
  --arg host_install_check_summary_sha256 "$(sha256sum "$EVIDENCE_BUNDLE/access_bridge_host_install_check_summary.json" | awk '{print $1}')" \
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
    and .evidence_policy.require_mtls == false
    and .evidence_policy.base_url_loopback == true
    and .evidence_policy.base_url_private_or_reserved == true
    and .transport.status == "pass"
    and .transport.https == false
    and .transport.tls_verified == false
    and .transport.mtls_required == false
    and .transport.mtls_client_certificate_used == false
    and .transport.mtls_local_client_certificate_key_match == false
    and .transport.mtls_client_certificate_client_auth_eku == false
    and .transport.mtls_server_leaf_certificate_fetched == false
    and .transport.mtls_client_certificate_der_fingerprint_distinct_from_server_leaf == false
    and .transport.mtls_client_certificate_public_key_fingerprint_distinct_from_server_leaf == false
    and .transport.mtls_missing_client_certificate_rejected == false
    and .transport.mtls_missing_client_certificate_health_http_status == "skipped"
    and .transport.mtls_missing_client_certificate_health_curl_rc == null
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
    and .evidence_binding.status == "pass"
    and .evidence_binding.reason == null
    and .evidence_binding.base_url == $base_url
    and .evidence_binding.helper_id == "helper-pilot"
    and .evidence_binding.organization_id == "pilot-org"
    and .evidence_binding.registry_id == $registry_id
    and .evidence_binding.smoke_summary_json == .artifacts.smoke_summary_json
    and .evidence_binding.smoke_summary_sha256 == $smoke_summary_sha256
    and .evidence_binding.deployment_evidence_summary_json == .artifacts.deployment_evidence_summary_json
    and .evidence_binding.deployment_evidence_summary_sha256 == $deployment_evidence_summary_sha256
    and .evidence_binding.host_install_check_summary_json == .artifacts.host_install_check_summary_json
    and .evidence_binding.host_install_check_summary_sha256 == $host_install_check_summary_sha256
    and .evidence_binding.deployment_evidence_schema_major == 1
    and .evidence_binding.deployment_evidence_schema_minor >= 6
    and .evidence_binding.deployment_evidence_smoke_summary_sha256 == $smoke_summary_sha256
    and .evidence_binding.deployment_smoke_summary_sha256 == $smoke_summary_sha256
    and .evidence_binding.deployment_evidence_binding_smoke_summary_sha256 == $smoke_summary_sha256
    and .evidence_binding.deployment_smoke_summary_sha256_matches_bundle == true
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
if grep -Fq -- "public.example@" "$TMP_DIR/pilot-bundle-userinfo-url.log"; then
  echo "access bridge pilot evidence bundle integration failed: userinfo URL leaked into rejection log"
  cat "$TMP_DIR/pilot-bundle-userinfo-url.log"
  exit 1
fi

userinfo_edge_index=0
for userinfo_edge_case in \
  "https://token@|token@" \
  " https://token@helper.gpm-pilot.net|token@" \
  "https://to ken@helper.gpm-pilot.net|to ken@"; do
  userinfo_edge_index=$((userinfo_edge_index + 1))
  IFS='|' read -r userinfo_edge_url userinfo_edge_secret <<<"$userinfo_edge_case"
  set +e
  bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
    --base-url "$userinfo_edge_url" \
    --path-id helper-web \
    --config-json "$SERVICE_CONFIG" \
    --deploy-pack-dir "$DEPLOY_PACK" \
    --code-file "$CODE_FILE" >"$TMP_DIR/pilot-bundle-userinfo-edge-$userinfo_edge_index.log" 2>&1
  userinfo_edge_rc=$?
  set -e
  if [[ "$userinfo_edge_rc" -eq 0 ]] ||
    ! grep -Fq -- "--base-url must not include userinfo" "$TMP_DIR/pilot-bundle-userinfo-edge-$userinfo_edge_index.log"; then
    echo "access bridge pilot evidence bundle integration failed: userinfo edge URL was not rejected before pilot evidence classification"
    cat "$TMP_DIR/pilot-bundle-userinfo-edge-$userinfo_edge_index.log"
    exit 1
  fi
  if grep -Fq -- "$userinfo_edge_secret" "$TMP_DIR/pilot-bundle-userinfo-edge-$userinfo_edge_index.log"; then
    echo "access bridge pilot evidence bundle integration failed: userinfo edge URL leaked into rejection log"
    cat "$TMP_DIR/pilot-bundle-userinfo-edge-$userinfo_edge_index.log"
    exit 1
  fi
done

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
if find "$EVIDENCE_BUNDLE" -type f \( \
  -name '.env' -o \
  -name '*token*' -o \
  -name '*password*' -o \
  -name '*passwd*' -o \
  -name '*auth*' -o \
  -name '*bearer*' -o \
  -name '*oauth*' -o \
  -name 'operator.pem' -o \
  -name 'id_ed25519' \
  \) -print -quit | grep -q .; then
  echo "access bridge pilot evidence bundle integration failed: sensitive deploy-pack file copied into evidence bundle"
  find "$EVIDENCE_BUNDLE" -type f \( \
    -name '.env' -o \
    -name '*token*' -o \
    -name '*password*' -o \
    -name '*passwd*' -o \
    -name '*auth*' -o \
    -name '*bearer*' -o \
    -name '*oauth*' -o \
    -name 'operator.pem' -o \
    -name 'id_ed25519' \
    \) -print
  exit 1
fi
if tar -tzf "${EVIDENCE_BUNDLE}.tar.gz" | grep -Eq '(^|/)(bridge-code\.txt|recovery\.key|operator\.pem|id_ed25519|\.env|api-token\.txt|db-password\.txt|shadow\.passwd|auth-header\.txt|bearer-creds\.txt|oauth-client\.json)$'; then
  echo "access bridge pilot evidence bundle integration failed: secret file copied into evidence tar"
  tar -tzf "${EVIDENCE_BUNDLE}.tar.gz"
  exit 1
fi
if ! grep -Fxq 'recovery.key' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt" ||
  ! grep -Fxq 'bridge-code.txt' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt" ||
  ! grep -Fxq 'operator.pem' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt" ||
  ! grep -Fxq 'keys/id_ed25519' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt" ||
  ! grep -Fxq '.env' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt" ||
  ! grep -Fxq 'api-token.txt' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt" ||
  ! grep -Fxq 'db-password.txt' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt" ||
  ! grep -Fxq 'shadow.passwd' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt" ||
  ! grep -Fxq 'auth-header.txt' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt" ||
  ! grep -Fxq 'bearer-creds.txt' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt" ||
  ! grep -Fxq 'oauth-client.json' "$EVIDENCE_BUNDLE/deploy-pack-skipped-secrets.txt"; then
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
