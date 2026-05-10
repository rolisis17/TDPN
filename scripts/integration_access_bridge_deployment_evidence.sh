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
  --base-url https://evidence.example \
  --helper-id helper-evidence \
  --helper-name "Evidence Helper" \
  --helper-url https://helper.example/evidence/bootstrap \
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
    base_url: "https://bridge.example",
    path_id: "helper-web",
    health: {
      http_status: "200",
      status: "ok",
      helper_id: "helper-evidence",
      organization_id: "evidence-org",
      registry_id: $registry_id
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
    and .local_files.deploy_pack.status == "pass"
    and .local_files.deploy_pack.dir == $deploy_dir
    and .local_files.deploy_pack.exists == true
    and .local_files.deploy_pack.env.config_sha256 == $config_sha256
    and (.local_files.deploy_pack.env.access_code_sha256 | length == 64)
    and .local_files.deploy_pack.env.allow_query_code == "false"
    and .local_files.deploy_pack.env.trust_proxy_headers == "true"
    and (.local_files.deploy_pack.required_files | length == 6)
    and ([.local_files.deploy_pack.required_files[].sha256 | length == 64] | all)
    and ([.local_files.deploy_pack.required_files[].exists] | all)
    and .recommended_next_action.id == "record_operator_evidence"
  ' "$SUMMARY_JSON" >/dev/null; then
  echo "access bridge deployment evidence integration failed: pass summary contract mismatch"
  cat "$SUMMARY_JSON"
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
