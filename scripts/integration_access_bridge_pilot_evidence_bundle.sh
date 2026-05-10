#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash curl go jq mktemp rg sha256sum tr; do
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

go run ./cmd/gpmrecover demo-bundle \
  --out-dir "$BUNDLE_DIR" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --base-url https://pilot.example \
  --helper-id helper-pilot \
  --helper-name "Pilot Helper" \
  --helper-url https://helper.example/pilot/bootstrap \
  --helper-contact mailto:helper-pilot@example.com \
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
  --install-dir /etc/gpm/access-bridge-pilot \
  --config /etc/gpm/access-bridge-pilot/bridge-service-config.json \
  --config-sha256 "$config_sha256" \
  --access-code-sha256 "$code_hash" >/dev/null

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
  --bundle-dir "$EVIDENCE_BUNDLE" \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
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
  '
    .schema.id == "access_bridge_pilot_evidence_bundle_summary"
    and .status == "pass"
    and .inputs.base_url == $base_url
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
    and .recommended_next_action.id == "record_access_bridge_pilot_evidence_bundle"
  ' "$SUMMARY_JSON" >/dev/null; then
  echo "access bridge pilot evidence bundle integration failed: pass summary contract mismatch"
  cat "$SUMMARY_JSON"
  exit 1
fi

if [[ ! -f "$EVIDENCE_BUNDLE/access_bridge_service_smoke_summary.json" ||
  ! -f "$EVIDENCE_BUNDLE/access_bridge_deployment_evidence_summary.json" ||
  ! -f "$EVIDENCE_BUNDLE/access_bridge_host_install_check_summary.json" ||
  ! -f "$EVIDENCE_BUNDLE/bridge-service-config.json" ||
  ! -f "$EVIDENCE_BUNDLE/bridge-deploy-pack/gpm-access-bridge-pilot.env" ]]; then
  echo "access bridge pilot evidence bundle integration failed: expected bundle artifacts missing"
  find "$EVIDENCE_BUNDLE" -maxdepth 3 -type f -print | sort
  exit 1
fi

if rg -Fq "$code_value" "$EVIDENCE_BUNDLE" "$SUMMARY_JSON" "$REPORT_MD"; then
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
