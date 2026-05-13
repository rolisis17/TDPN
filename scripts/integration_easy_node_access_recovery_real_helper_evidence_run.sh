#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash chmod grep jq mktemp sed sha256sum wc; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "easy node access recovery real helper evidence run integration failed: missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
FAKE_HOST_CHECK="$TMP_DIR/fake_access_bridge_host_install_check.sh"
FAKE_BUNDLE="$TMP_DIR/fake_access_bridge_pilot_evidence_bundle.sh"
FAKE_OLD_DEPLOYMENT_BUNDLE="$TMP_DIR/fake_access_bridge_pilot_evidence_bundle_old_deployment.sh"
FAKE_VERIFY="$TMP_DIR/fake_access_bridge_pilot_evidence_bundle_verify.sh"
FAKE_ROADMAP="$TMP_DIR/fake_roadmap_progress_report.sh"
HELP_OUT="$TMP_DIR/help.txt"
REPORTS_DIR="$TMP_DIR/reports"
CONFIG_JSON="$TMP_DIR/bridge-service-config.json"
CONFIG_INFERRED_HELPER_DEMO_JSON="$TMP_DIR/bridge-service-config-helper-demo.json"
CONFIG_INFERRED_ORG_DEMO_JSON="$TMP_DIR/bridge-service-config-org-demo.json"
CONFIG_INFERRED_REGISTRY_DEMO_JSON="$TMP_DIR/bridge-service-config-registry-demo.json"
DEPLOY_PACK_DIR="$TMP_DIR/deploy-pack"
INSTALL_DIR="$TMP_DIR/installed-host"
SYSTEMD_UNIT_FILE="$TMP_DIR/gpm-access-bridge.service"
PROXY_CONFIG_FILE="$TMP_DIR/gpm-access-bridge.caddy"
CODE_FILE="$TMP_DIR/code.txt"
TRUST_STORE="$TMP_DIR/trust-store.json"
PROVENANCE_KEY="$TMP_DIR/provenance.key"
GENERATED_DEMO_DIR="$TMP_DIR/generated-demo/artifacts"
GENERATED_DEMO_CODE_FILE="$GENERATED_DEMO_DIR/code.txt"
GENERATED_DEMO_CONFIG_JSON="$GENERATED_DEMO_DIR/bridge-service-config.json"
GENERATED_DEMO_DEPLOY_PACK_DIR="$GENERATED_DEMO_DIR/deploy-pack"
GENERATED_DEMO_TRUST_STORE="$GENERATED_DEMO_DIR/trust-store.json"
GENERATED_DEMO_PROVENANCE_KEY="$GENERATED_DEMO_DIR/provenance.key"
DEMO_MARKED_TRUST_STORE="$TMP_DIR/demo-marked-trust-store.json"
DEMO_ID_TRUST_STORE="$TMP_DIR/demo-id-trust-store.json"
INSTALLED_HOST_ARGS=(
  --host-install-evidence-mode installed-host
  --install-dir "$INSTALL_DIR"
  --systemd-unit-file "$SYSTEMD_UNIT_FILE"
  --proxy-kind caddy
  --proxy-config-file "$PROXY_CONFIG_FILE"
)

mkdir -p "$DEPLOY_PACK_DIR" "$INSTALL_DIR" "$REPORTS_DIR" "$GENERATED_DEMO_DEPLOY_PACK_DIR"
printf '%s\n' '{"status":"pass"}' >"$CONFIG_JSON"
printf '%s\n' '{"helper_id":"helper-demo","organization_id":"pilot-org","registry_id":"registry-pilot","status":"pass"}' >"$CONFIG_INFERRED_HELPER_DEMO_JSON"
printf '%s\n' '{"helper_id":"helper-pilot","organization_id":"freenews-demo","registry_id":"registry-pilot","status":"pass"}' >"$CONFIG_INFERRED_ORG_DEMO_JSON"
printf '%s\n' '{"helper_id":"helper-pilot","organization_id":"pilot-org","registry_id":"registry-demo","status":"pass"}' >"$CONFIG_INFERRED_REGISTRY_DEMO_JSON"
printf '%s\n' '[Service]' 'EnvironmentFile='"$INSTALL_DIR/gpm-access-bridge.env" 'ExecStart='"$INSTALL_DIR/run-gpm-access-bridge.sh" >"$SYSTEMD_UNIT_FILE"
printf '%s\n' 'helper.gpm-pilot.net {' '  reverse_proxy 127.0.0.1:8791 {' '    header_up X-Forwarded-For {remote_host}' '  }' '}' >"$PROXY_CONFIG_FILE"
printf '%s\n' 'test-access-code' >"$CODE_FILE"
printf '%s\n' '{"version":1,"keys":[]}' >"$TRUST_STORE"
printf '%s\n' 'test-provenance-key' >"$PROVENANCE_KEY"
printf '%s\n' '{"status":"pass"}' >"$GENERATED_DEMO_CONFIG_JSON"
printf '%s\n' 'generated-demo-access-code' >"$GENERATED_DEMO_CODE_FILE"
printf '%s\n' '{"version":1,"keys":[]}' >"$GENERATED_DEMO_TRUST_STORE"
printf '%s\n' 'generated-demo-provenance-key' >"$GENERATED_DEMO_PROVENANCE_KEY"
printf '%s\n' '{"version":1,"keys":[{"source":"generated demo bundle"}]}' >"$DEMO_MARKED_TRUST_STORE"
printf '%s\n' '{"version":1,"keys":[{"org_id":"freenews-demo","name":"FreeNews Demo"}]}' >"$DEMO_ID_TRUST_STORE"

cat >"$FAKE_HOST_CHECK" <<'EOF_FAKE_HOST_CHECK'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE:?}"
summary_json=""
{
  printf 'host-check'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
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
cat >"$summary_json" <<JSON
{
  "version": 1,
  "schema": {"id": "access_bridge_host_install_check_summary", "major": 1, "minor": 4},
  "status": "pass",
  "rc": 0,
  "observed": {
    "expected_public_host": "helper.gpm-pilot.net",
    "caddy_site_host": "helper.gpm-pilot.net",
    "nginx_server_name": "helper.gpm-pilot.net"
  }
}
JSON
exit "${FAKE_ACCESS_RECOVERY_REAL_HELPER_HOST_CHECK_RC:-0}"
EOF_FAKE_HOST_CHECK
chmod +x "$FAKE_HOST_CHECK"

cat >"$FAKE_BUNDLE" <<'EOF_FAKE_BUNDLE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE:?}"
summary_json=""
provenance_out=""
base_url=""
deployment_schema_minor="${FAKE_ACCESS_RECOVERY_REAL_HELPER_DEPLOYMENT_SCHEMA_MINOR:-6}"
sha256_value() {
  sha256sum "$1" | awk '{print $1}'
}
{
  printf 'bundle'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --provenance-out)
      provenance_out="${2:-}"
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
bundle_dir="$(dirname "$summary_json")/bundle"
mkdir -p "$bundle_dir"
cat >"$bundle_dir/access_bridge_service_smoke_summary.json" <<JSON
{
  "schema": {"id": "access_bridge_service_smoke_summary", "major": 1, "minor": 6},
  "status": "pass",
  "details": {
    "base_url": "$base_url",
    "helper_id": "helper-pilot",
    "organization_id": "freenews-demo",
    "registry_id": "registry-pilot"
  }
}
JSON
smoke_sha="$(sha256_value "$bundle_dir/access_bridge_service_smoke_summary.json")"
cat >"$bundle_dir/access_bridge_deployment_evidence_summary.json" <<JSON
{
  "schema": {"id": "access_bridge_deployment_evidence_summary", "major": 1, "minor": $deployment_schema_minor},
  "status": "pass",
  "smoke": {
    "summary_sha256": "$smoke_sha"
  },
  "evidence_binding": {
    "smoke_summary_sha256": "$smoke_sha"
  },
  "details": {
    "base_url": "$base_url",
    "helper_id": "helper-pilot",
    "organization_id": "freenews-demo",
    "registry_id": "registry-pilot"
  }
}
JSON
cat >"$bundle_dir/access_bridge_host_install_check_summary.json" <<JSON
{
  "status": "pass",
  "details": {
    "base_url": "$base_url",
    "helper_id": "helper-pilot",
    "organization_id": "freenews-demo",
    "registry_id": "registry-pilot"
  }
}
JSON
cat >"$summary_json" <<JSON
{
  "version": 1,
  "schema": {"id": "access_bridge_pilot_evidence_bundle_summary", "major": 1, "minor": 2},
  "status": "pass",
  "rc": 0,
  "evidence_scope": "real_helper_https",
  "pilot_handoff_ready": false,
  "inputs": {
    "base_url": "$base_url"
  },
  "artifacts": {
    "smoke_summary_json": "$bundle_dir/access_bridge_service_smoke_summary.json",
    "deployment_evidence_summary_json": "$bundle_dir/access_bridge_deployment_evidence_summary.json",
    "host_install_check_summary_json": "$bundle_dir/access_bridge_host_install_check_summary.json",
    "bundle_dir": "$bundle_dir",
    "bundle_tar": "$(dirname "$summary_json")/bundle.tar.gz",
    "bundle_tar_sha256_file": "$(dirname "$summary_json")/bundle.tar.gz.sha256",
    "provenance_json": "$provenance_out"
  },
  "provenance": {
    "enabled": true,
    "sidecar_json": "$provenance_out"
  }
}
JSON
cat >"$provenance_out" <<JSON
{"status":"pass","evidence_scope":"real_helper_https"}
JSON
exit "${FAKE_ACCESS_RECOVERY_REAL_HELPER_BUNDLE_RC:-0}"
EOF_FAKE_BUNDLE
chmod +x "$FAKE_BUNDLE"

cat >"$FAKE_OLD_DEPLOYMENT_BUNDLE" <<EOF_FAKE_OLD_DEPLOYMENT_BUNDLE
#!/usr/bin/env bash
set -euo pipefail
summary_json=""
args=("\$@")
idx=0
while [[ "\$idx" -lt "\${#args[@]}" ]]; do
  case "\${args[\$idx]}" in
    --summary-json)
      summary_json="\${args[\$((idx + 1))]:-}"
      idx=\$((idx + 2))
      ;;
    *)
      idx=\$((idx + 1))
      ;;
  esac
done
"$FAKE_BUNDLE" "\${args[@]}"
deployment_summary_json="\$(dirname "\$summary_json")/bundle/access_bridge_deployment_evidence_summary.json"
tmp_json="\${deployment_summary_json}.tmp"
jq '.schema.minor = 5' "\$deployment_summary_json" >"\$tmp_json"
mv "\$tmp_json" "\$deployment_summary_json"
EOF_FAKE_OLD_DEPLOYMENT_BUNDLE
chmod +x "$FAKE_OLD_DEPLOYMENT_BUNDLE"

cat >"$FAKE_VERIFY" <<'EOF_FAKE_VERIFY'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE:?}"
verification_summary_json=""
summary_json=""
provenance_json=""
trust_store=""
pilot_handoff_ready="${FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_READY:-true}"
trusted_provenance="${FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_TRUSTED:-true}"
binding_mode="${FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_BINDING_MODE:-match}"
identity_mode="${FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_IDENTITY_MODE:-match}"
schema_minor="${FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_SCHEMA_MINOR:-6}"
sha256_value() {
  sha256sum "$1" | awk '{print $1}'
}
{
  printf 'verify'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verification-summary-json)
      verification_summary_json="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --provenance-json)
      provenance_json="${2:-}"
      shift 2
      ;;
    --trust-store)
      trust_store="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$verification_summary_json")"
smoke_summary_json="$(jq -r '.artifacts.smoke_summary_json // ""' "$summary_json")"
deployment_summary_json="$(jq -r '.artifacts.deployment_evidence_summary_json // ""' "$summary_json")"
host_summary_json="$(jq -r '.artifacts.host_install_check_summary_json // ""' "$summary_json")"
base_url="$(jq -r '.inputs.base_url // ""' "$summary_json")"
smoke_sha="$(sha256_value "$smoke_summary_json")"
deployment_sha="$(sha256_value "$deployment_summary_json")"
host_sha="$(sha256_value "$host_summary_json")"
deployment_smoke_sha="$(jq -r '.smoke.summary_sha256 // ""' "$deployment_summary_json")"
deployment_binding_smoke_sha="$(jq -r '.evidence_binding.smoke_summary_sha256 // ""' "$deployment_summary_json")"
helper_id="$(jq -r '.details.helper_id // ""' "$smoke_summary_json")"
organization_id="$(jq -r '.details.organization_id // ""' "$smoke_summary_json")"
registry_id="$(jq -r '.details.registry_id // ""' "$smoke_summary_json")"
provenance_org_id="$organization_id"
trusted_org_id="$organization_id"
if [[ "$binding_mode" == "mismatch" ]]; then
  smoke_sha="0000000000000000000000000000000000000000000000000000000000000000"
elif [[ "$binding_mode" == "deployment_smoke_mismatch" ]]; then
  deployment_smoke_sha="1111111111111111111111111111111111111111111111111111111111111111"
  deployment_binding_smoke_sha="2222222222222222222222222222222222222222222222222222222222222222"
fi
case "$identity_mode" in
  match)
    ;;
  missing_helper)
    helper_id=""
    ;;
  missing_organization)
    organization_id=""
    ;;
  missing_registry)
    registry_id=""
    ;;
  provenance_org_mismatch)
    provenance_org_id="different-provenance-org"
    ;;
  trusted_org_mismatch)
    trusted_org_id="different-trusted-org"
    ;;
  *)
    echo "unknown fake identity mode: $identity_mode" >&2
    exit 2
    ;;
esac
trust_store_sha="$(sha256_value "$trust_store")"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg verification_summary_json "$verification_summary_json" \
  --arg summary_json "$summary_json" \
  --arg provenance_json "$provenance_json" \
  --arg trust_store "$trust_store" \
  --arg trust_store_sha "$trust_store_sha" \
  --arg base_url "$base_url" \
  --arg smoke_summary_json "$smoke_summary_json" \
  --arg smoke_sha "$smoke_sha" \
  --arg deployment_summary_json "$deployment_summary_json" \
  --arg deployment_sha "$deployment_sha" \
  --arg deployment_smoke_sha "$deployment_smoke_sha" \
  --arg deployment_binding_smoke_sha "$deployment_binding_smoke_sha" \
  --arg host_summary_json "$host_summary_json" \
  --arg host_sha "$host_sha" \
  --arg helper_id "$helper_id" \
  --arg organization_id "$organization_id" \
  --arg registry_id "$registry_id" \
  --arg provenance_org_id "$provenance_org_id" \
  --arg trusted_org_id "$trusted_org_id" \
  --argjson schema_minor "$schema_minor" \
  --argjson pilot_handoff_ready "$pilot_handoff_ready" \
  --argjson trusted_provenance "$trusted_provenance" \
  '($pilot_handoff_ready and $trusted_provenance) as $authority_ready
  | {
    version: 1,
    schema: {"id": "access_bridge_pilot_evidence_bundle_verify_summary", "major": 1, "minor": $schema_minor},
    generated_at_utc: $generated_at_utc,
    status: "pass",
    rc: 0,
    pilot_handoff_ready: $authority_ready,
    trusted_pilot_receipt_ready: $authority_ready,
    handoff_authority: $authority_ready,
    authority_level: (if $authority_ready then "pilot_handoff" else "trusted_non_handoff" end),
    integrity_only: ($authority_ready | not),
    status_meaning: (if $authority_ready then "trusted pilot handoff authority" else "trusted verification did not satisfy pilot handoff criteria; not pilot handoff authority" end),
    pilot_handoff_criteria: {
      ready: $authority_ready,
      trusted_pilot_receipt_ready: $authority_ready,
      require_trusted_provenance: true,
      provenance_checked: true,
      provenance_trusted: $trusted_provenance,
      provenance_status: "pass",
      provenance_source: "trust_store",
      provenance_evidence_scope: "real_helper_https",
      summary_evidence_scope: "real_helper_https",
      source_helper_id_present: ($helper_id != ""),
      source_organization_id_present: ($organization_id != ""),
      source_registry_id_present: ($registry_id != ""),
      provenance_organization_matches_evidence: ($provenance_org_id != "" and $organization_id != "" and $provenance_org_id == $organization_id),
      trusted_organization_matches_evidence: ($trusted_org_id != "" and $organization_id != "" and $trusted_org_id == $organization_id),
      bundled_child_evidence_semantic_ok: true,
      deployment_smoke_summary_sha256_matches_bundle: ($deployment_smoke_sha != "" and $deployment_binding_smoke_sha != "" and $deployment_smoke_sha == $smoke_sha and $deployment_binding_smoke_sha == $smoke_sha),
      evidence_freshness_checked: true,
      evidence_freshness_ok: true,
      evidence_max_age_sec: 604800,
      installed_host_evidence_present: true,
      trust_store_present: true,
      trust_store_sha256_present: true,
      public_key_file_absent: true,
      dev_trust_store_allowed: false
    },
    inputs: {
      summary_json: $summary_json,
      provenance_json: $provenance_json,
      trust_store: $trust_store,
      trust_store_sha256: $trust_store_sha,
      public_key_file: null,
      allow_dev_trust_store: false
    },
    checks: {
      summary_contract: {enabled: true, status: "pass"},
      tar_sha256: {enabled: true, checked: true, status: "pass"},
      manifest: {enabled: true, status: "pass"},
      provenance: {enabled: true, required_trusted: true, status: "pass"},
      evidence_freshness: {checked: true, required_trusted: true, status: "pass"}
    },
    evidence_freshness: {
      checked: true,
      ok: true,
      max_age_sec: 604800,
      details: []
    },
    trusted_provenance: {
      required: true,
      checked: true,
      source: "trust_store",
      trusted: $trusted_provenance,
      status: "pass",
      organization_id: $provenance_org_id,
      trusted_org_id: $trusted_org_id,
      evidence_scope: "real_helper_https",
      summary_evidence_scope: "real_helper_https"
    },
    evidence_binding: {
      base_url: $base_url,
      helper_id: $helper_id,
      organization_id: $organization_id,
      registry_id: $registry_id,
      smoke_summary_json: $smoke_summary_json,
      smoke_summary_sha256: $smoke_sha,
      deployment_smoke_summary_sha256: $deployment_smoke_sha,
      deployment_evidence_binding_smoke_summary_sha256: $deployment_binding_smoke_sha,
      deployment_evidence_summary_json: $deployment_summary_json,
      deployment_evidence_summary_sha256: $deployment_sha,
      host_install_check_summary_json: $host_summary_json,
      host_install_check_summary_sha256: $host_sha,
      host_install_evidence_mode: "installed-host"
    },
    artifacts: {
      verification_summary_json: $verification_summary_json,
      source_summary_json: $summary_json,
      provenance_json: $provenance_json
    }
  }' >"$verification_summary_json"
exit "${FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_RC:-0}"
EOF_FAKE_VERIFY
chmod +x "$FAKE_VERIFY"

cat >"$FAKE_ROADMAP" <<'EOF_FAKE_ROADMAP'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE:?}"
summary_json=""
report_md=""
roadmap_ready="${FAKE_ACCESS_RECOVERY_REAL_HELPER_ROADMAP_READY:-true}"
{
  printf 'roadmap'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
cat >"$summary_json" <<JSON
{
  "version": 1,
  "current_roadmap_track": "access_recovery",
  "access_recovery_pilot_handoff_ready": $roadmap_ready,
  "access_recovery_track": {
    "status": "pilot-evidence-ready",
    "pilot_handoff_ready": $roadmap_ready,
    "evidence_scope": "real_helper_https"
  }
}
JSON
printf '%s\n' '# fake roadmap' >"$report_md"
exit "${FAKE_ACCESS_RECOVERY_REAL_HELPER_ROADMAP_RC:-0}"
EOF_FAKE_ROADMAP
chmod +x "$FAKE_ROADMAP"

./scripts/easy_node.sh help >"$HELP_OUT"
if ! grep -Fq -- './scripts/easy_node.sh access-recovery-real-helper-evidence-run' "$HELP_OUT"; then
  echo "easy_node help missing access-recovery-real-helper-evidence-run command"
  cat "$HELP_OUT"
  exit 1
fi
if ! grep -Fq -- './scripts/easy_node.sh access-bridge-host-install-check' "$HELP_OUT"; then
  echo "easy_node help missing access-bridge-host-install-check command"
  cat "$HELP_OUT"
  exit 1
fi
if ! ./scripts/easy_node.sh help --expert | grep -Fq -- 'access-recovery-real-helper-evidence-run runs the real public helper HTTPS evidence flow'; then
  echo "easy_node expert help missing real helper evidence run note"
  exit 1
fi
if ! ./scripts/easy_node.sh help --expert | grep -Fq -- 'Use --roadmap-refresh 0 for diagnostics/verifier-only runs; those stop at verifier_ready and skip the roadmap status roll-up. The trusted verifier receipt remains the handoff authority'; then
  echo "easy_node expert help missing real helper roadmap-refresh 0 verifier-ready semantics"
  exit 1
fi
if ! ./scripts/easy_node.sh help --expert | grep -Fq -- 'access-bridge-host-install-check records host-install evidence directly'; then
  echo "easy_node expert help missing host-install check note"
  exit 1
fi

echo "[easy-node-access-recovery-real-helper-evidence-run] child script overrides are diagnostic-only"
: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --summary-json "$TMP_DIR/override-block-summary.json" \
  --print-summary-json 0 >"$TMP_DIR/override-block.log" 2>&1
override_block_rc=$?
set -e
if [[ "$override_block_rc" -ne 2 ]] || ! grep -Fq "override is disabled for real helper evidence" "$TMP_DIR/override-block.log"; then
  echo "expected child script overrides to fail closed unless explicitly allowed"
  cat "$TMP_DIR/override-block.log"
  exit 1
fi
if [[ -s "$CAPTURE" ]]; then
  echo "blocked child script override should not invoke fake child scripts"
  cat "$CAPTURE"
  exit 1
fi

for bundle_child_override_var in \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SERVICE_SMOKE_SCRIPT \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_DEPLOYMENT_EVIDENCE_SCRIPT \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_HOST_INSTALL_CHECK_SCRIPT; do
  echo "[easy-node-access-recovery-real-helper-evidence-run] bundle child override is diagnostic-only: $bundle_child_override_var"
  : >"$CAPTURE"
  set +e
  env \
    ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
    "$bundle_child_override_var=$FAKE_HOST_CHECK" \
    ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
    ./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
      --base-url https://helper.gpm-pilot.net \
      --path-id helper-web \
      --code-file "$CODE_FILE" \
      --config-json "$CONFIG_JSON" \
      --deploy-pack-dir "$DEPLOY_PACK_DIR" \
      "${INSTALLED_HOST_ARGS[@]}" \
      --provenance-private-key-file "$PROVENANCE_KEY" \
      --provenance-org-id pilot-org \
      --provenance-org-name "Pilot Org" \
      --trust-store "$TRUST_STORE" \
      --summary-json "$TMP_DIR/bundle-child-override-block-${bundle_child_override_var}.json" \
      --print-summary-json 0 >"$TMP_DIR/bundle-child-override-block-${bundle_child_override_var}.log" 2>&1
  bundle_child_override_block_rc=$?
  set -e
  if [[ "$bundle_child_override_block_rc" -ne 2 ]] ||
    ! grep -Fq "${bundle_child_override_var} override is disabled for real helper evidence" "$TMP_DIR/bundle-child-override-block-${bundle_child_override_var}.log"; then
    echo "expected bundle child script override to fail closed unless explicitly allowed: $bundle_child_override_var"
    cat "$TMP_DIR/bundle-child-override-block-${bundle_child_override_var}.log"
    exit 1
  fi
  if [[ -s "$CAPTURE" ]]; then
    echo "blocked bundle child script override should not invoke fake child scripts: $bundle_child_override_var"
    cat "$CAPTURE"
    exit 1
  fi
done

export ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_ALLOW_SCRIPT_OVERRIDES=1

set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url "https://token@helper.gpm-pilot.net" \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --summary-json "$TMP_DIR/userinfo-url-summary.json" \
  --print-summary-json 0 >"$TMP_DIR/userinfo-url.log" 2>&1
userinfo_url_rc=$?
set -e
if [[ "$userinfo_url_rc" -ne 2 ]] ||
  ! grep -Fq -- "--base-url must not include userinfo" "$TMP_DIR/userinfo-url.log"; then
  echo "expected userinfo real-helper URL to fail preflight"
  cat "$TMP_DIR/userinfo-url.log"
  exit 1
fi
if grep -Fq -- "token@helper" "$TMP_DIR/userinfo-url.log"; then
  echo "userinfo real-helper URL leaked into preflight log"
  cat "$TMP_DIR/userinfo-url.log"
  exit 1
fi

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code "test-access-code" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --summary-json "$TMP_DIR/live-inline-code-summary.json" \
  --print-summary-json 0 >"$TMP_DIR/live-inline-code.log" 2>&1
live_inline_code_rc=$?
set -e
if [[ "$live_inline_code_rc" -ne 2 ]] ||
  ! grep -Fq -- "live real-helper pilot handoff requires --code-file; inline --code is not allowed for live evidence runs" "$TMP_DIR/live-inline-code.log"; then
  echo "expected live inline --code to fail preflight"
  cat "$TMP_DIR/live-inline-code.log"
  exit 1
fi
if [[ -s "$CAPTURE" ]]; then
  echo "live inline --code preflight should not invoke child scripts"
  cat "$CAPTURE"
  exit 1
fi
jq -e '
  .status == "fail"
  and .rc == 2
  and .stage == "preflight"
  and .mode.plan_only == false
  and .inputs.code_present == true
  and .inputs.code_file_present == false
' "$TMP_DIR/live-inline-code-summary.json" >/dev/null

bad_real_helper_urls=(
  "https://198.51.100.10"
  "https://203.0.113.10"
  "https://192.0.2.10"
  "https://224.0.0.1"
  "https://[::ffff:10.0.0.8]"
  "https://[::ffff:0a00:0008]"
  "https://home.arpa"
  "https://helper.home.arpa"
  "https://helper.tailnet.ts.net"
  "https://ts.net"
  "https://tailscale.net"
  "https://[2001:db8::1]"
  "https://[2001:0db8::1]"
  "https://[fe90::1]"
  "https://[fea0::1]"
  "https://[febf::1]"
)
bad_real_helper_index=0
for bad_url in "${bad_real_helper_urls[@]}"; do
  bad_real_helper_index=$((bad_real_helper_index + 1))
  : >"$CAPTURE"
  set +e
  ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
  ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
  ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
  ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
  ./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
    --base-url "$bad_url" \
    --code-file "$CODE_FILE" \
    --config-json "$CONFIG_JSON" \
    --deploy-pack-dir "$DEPLOY_PACK_DIR" \
    --provenance-private-key-file "$PROVENANCE_KEY" \
    --provenance-org-id pilot-org \
    --provenance-org-name "Pilot Org" \
    --trust-store "$TRUST_STORE" \
    --summary-json "$TMP_DIR/bad-url-$bad_real_helper_index-summary.json" \
    --print-summary-json 0 >"$TMP_DIR/bad-url-$bad_real_helper_index.log" 2>&1
  bad_url_rc=$?
  set -e
  if [[ "$bad_url_rc" -ne 2 ]] ||
    ! grep -Fq -- "--base-url host must look public-routable for real helper evidence" "$TMP_DIR/bad-url-$bad_real_helper_index.log"; then
    echo "expected non-public real-helper URL to fail preflight: $bad_url"
    cat "$TMP_DIR/bad-url-$bad_real_helper_index.log"
    exit 1
  fi
  if [[ -s "$CAPTURE" ]]; then
    echo "non-public real-helper URL should not invoke child scripts: $bad_url"
    cat "$CAPTURE"
    exit 1
  fi
done

echo "[easy-node-access-recovery-real-helper-evidence-run] plan-only validates and emits planned commands without invoking children"
: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --plan-only \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/plan-only-summary.json" \
  --report-md "$TMP_DIR/plan-only-report.md" \
  --print-summary-json 0
if [[ -s "$CAPTURE" ]]; then
  echo "plan-only should not invoke child scripts"
  cat "$CAPTURE"
  exit 1
fi
jq -e '
  .schema.id == "access_recovery_real_helper_evidence_run_summary"
  and .schema.major == 1
  and .schema.minor == 6
  and .status == "skipped"
  and .status != "pass"
  and .rc == 0
  and .stage == "plan"
  and .mode.plan_only == true
  and .mode.child_execution_skipped == true
  and .mode.evidence_generated == false
  and .mode.evidence_status == "planned_non_evidence"
  and .inputs.host_install_evidence_mode == "deploy-pack"
  and .child_summaries.host_install_check == null
  and .child_summaries.bundle == null
  and .child_summaries.verifier == null
  and .child_summaries.roadmap == null
  and .planned_child_commands.host_install_check.enabled == true
  and .planned_child_commands.bundle.enabled == true
  and .planned_child_commands.verifier.enabled == true
  and .planned_child_commands.roadmap.enabled == true
  and .inputs.require_mtls == false
  and (.planned_child_commands.bundle.args | index("--bundle-dir") != null)
  and (.planned_child_commands.bundle.args | index("--require-mtls") != null)
  and (.planned_child_commands.bundle.args | index("0") != null)
  and (.planned_child_commands.bundle.args | index("--code-file") != null)
  and (.planned_artifacts.bundle_service_smoke_summary_json | endswith("/access_bridge_service_smoke_summary.json"))
  and (.planned_artifacts.verification_summary_json | endswith(".json"))
' "$TMP_DIR/plan-only-summary.json" >/dev/null
if ! grep -Fq -- "Planned Child Commands" "$TMP_DIR/plan-only-report.md" ||
  ! grep -Fq -- "Planned Artifacts" "$TMP_DIR/plan-only-report.md"; then
  echo "plan-only report missing planned commands/artifacts"
  cat "$TMP_DIR/plan-only-report.md"
  exit 1
fi

: >"$CAPTURE"
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --plan-only \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code "test-access-code" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/plan-only-inline-code-summary.json" \
  --report-md "$TMP_DIR/plan-only-inline-code-report.md" \
  --print-summary-json 0 >"$TMP_DIR/plan-only-inline-code.log" 2>&1
if [[ -s "$CAPTURE" ]]; then
  echo "plan-only inline code should not invoke child scripts"
  cat "$CAPTURE"
  exit 1
fi
jq -e '
  .status == "skipped"
  and .stage == "plan"
  and .mode.plan_only == true
  and .inputs.code_present == true
  and .inputs.code_file_present == false
  and (.planned_child_commands.bundle.args | index("--code") != null)
  and (.planned_child_commands.bundle.args | index("<redacted>") != null)
' "$TMP_DIR/plan-only-inline-code-summary.json" >/dev/null
if grep -Fq -- "test-access-code" "$TMP_DIR/plan-only-inline-code-summary.json" ||
  grep -Fq -- "test-access-code" "$TMP_DIR/plan-only-inline-code-report.md" ||
  grep -Fq -- "test-access-code" "$TMP_DIR/plan-only-inline-code.log"; then
  echo "plan-only inline code leaked into summary, report, or log"
  cat "$TMP_DIR/plan-only-inline-code-summary.json"
  cat "$TMP_DIR/plan-only-inline-code-report.md"
  cat "$TMP_DIR/plan-only-inline-code.log"
  exit 1
fi

: >"$CAPTURE"
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --plan-only \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  --host-install-evidence-mode installed-host \
  --install-dir "$INSTALL_DIR" \
  --systemd-unit-file "$SYSTEMD_UNIT_FILE" \
  --proxy-kind caddy \
  --proxy-config-file "$PROXY_CONFIG_FILE" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/plan-only-installed-host-summary.json" \
  --print-summary-json 0
if [[ -s "$CAPTURE" ]]; then
  echo "installed-host plan-only should not invoke child scripts"
  cat "$CAPTURE"
  exit 1
fi
jq -e \
  --arg install_dir "$INSTALL_DIR" \
  --arg systemd_unit_file "$SYSTEMD_UNIT_FILE" \
  --arg proxy_config_file "$PROXY_CONFIG_FILE" '
  .schema.id == "access_recovery_real_helper_evidence_run_summary"
  and .schema.major == 1
  and .schema.minor == 6
  and .status == "skipped"
  and .status != "pass"
  and .rc == 0
  and .stage == "plan"
  and .mode.plan_only == true
  and .mode.child_execution_skipped == true
  and .mode.evidence_generated == false
  and .mode.evidence_status == "planned_non_evidence"
  and .inputs.host_install_evidence_mode == "installed-host"
  and (.planned_child_commands.host_install_check.args | index("--evidence-mode") != null)
  and (.planned_child_commands.host_install_check.args | index("installed-host") != null)
  and (.planned_child_commands.host_install_check.args | index("--install-dir") != null)
  and (.planned_child_commands.host_install_check.args | index($install_dir) != null)
  and (.planned_child_commands.host_install_check.args | index("--systemd-unit-file") != null)
  and (.planned_child_commands.host_install_check.args | index($systemd_unit_file) != null)
  and (.planned_child_commands.host_install_check.args | index("--proxy-kind") != null)
  and (.planned_child_commands.host_install_check.args | index("caddy") != null)
  and (.planned_child_commands.host_install_check.args | index("--proxy-config-file") != null)
  and (.planned_child_commands.host_install_check.args | index($proxy_config_file) != null)
  and (.planned_child_commands.bundle.args | index("--host-install-evidence-mode") != null)
  and (.planned_child_commands.bundle.args | index("installed-host") != null)
  and (.planned_child_commands.bundle.args | index("--install-dir") != null)
  and (.planned_child_commands.bundle.args | index($install_dir) != null)
' "$TMP_DIR/plan-only-installed-host-summary.json" >/dev/null

: >"$CAPTURE"
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --plan-only \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$GENERATED_DEMO_CODE_FILE" \
  --config-json "$GENERATED_DEMO_CONFIG_JSON" \
  --deploy-pack-dir "$GENERATED_DEMO_DEPLOY_PACK_DIR" \
  --provenance-private-key-file "$GENERATED_DEMO_PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$GENERATED_DEMO_TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/plan-only-generated-demo-paths-summary.json" \
  --print-summary-json 0
if [[ -s "$CAPTURE" ]]; then
  echo "plan-only generated demo/example paths should not invoke child scripts"
  cat "$CAPTURE"
  exit 1
fi
jq -e '
  .status == "skipped"
  and .rc == 0
  and .stage == "plan"
  and .mode.plan_only == true
  and .mode.evidence_status == "planned_non_evidence"
  and .inputs.host_install_evidence_mode == "deploy-pack"
' "$TMP_DIR/plan-only-generated-demo-paths-summary.json" >/dev/null

plan_only_reject_cases=(
  "private-url|--base-url|https://10.1.2.3|--base-url host must look public-routable for real helper evidence"
  "placeholder-url|--base-url|https://HELPER_PUBLIC_DNS|--base-url must be a real public HTTPS helper URL"
  "placeholder-code-file|--code-file|PRIVATE_CODE_FILE|--code-file must point to a real private access code file, not an unreplaced placeholder"
)
plan_only_reject_index=0
for plan_only_case in "${plan_only_reject_cases[@]}"; do
  plan_only_reject_index=$((plan_only_reject_index + 1))
  IFS='|' read -r plan_only_name plan_only_flag plan_only_value plan_only_expected_message <<<"$plan_only_case"
  : >"$CAPTURE"
  plan_only_base_url="https://helper.gpm-pilot.net"
  plan_only_code_file="$CODE_FILE"
  case "$plan_only_flag" in
    --base-url)
      plan_only_base_url="$plan_only_value"
      ;;
    --code-file)
      plan_only_code_file="$plan_only_value"
      ;;
    *)
      echo "unknown plan-only reject case flag: $plan_only_flag"
      exit 1
      ;;
  esac
  set +e
  ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
  ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
  ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
  ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
  ./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
    --plan-only \
    --base-url "$plan_only_base_url" \
    --code-file "$plan_only_code_file" \
    --config-json "$CONFIG_JSON" \
    --deploy-pack-dir "$DEPLOY_PACK_DIR" \
    --provenance-private-key-file "$PROVENANCE_KEY" \
    --provenance-org-id pilot-org \
    --provenance-org-name "Pilot Org" \
    --trust-store "$TRUST_STORE" \
    --summary-json "$TMP_DIR/plan-only-reject-$plan_only_reject_index-summary.json" \
    --print-summary-json 0 >"$TMP_DIR/plan-only-reject-$plan_only_reject_index.log" 2>&1
  plan_only_reject_rc=$?
  set -e
  if [[ "$plan_only_reject_rc" -ne 2 ]] ||
    ! grep -Fq -- "$plan_only_expected_message" "$TMP_DIR/plan-only-reject-$plan_only_reject_index.log"; then
    echo "expected plan-only reject case to fail preflight: $plan_only_name"
    cat "$TMP_DIR/plan-only-reject-$plan_only_reject_index.log"
    exit 1
  fi
  if [[ -s "$CAPTURE" ]]; then
    echo "plan-only reject case should not invoke child scripts: $plan_only_name"
    cat "$CAPTURE"
    exit 1
  fi
done

live_generated_demo_path_cases=(
  "code-file|--code-file|$GENERATED_DEMO_CODE_FILE|--code-file must not point to a generated demo/example artifact path for live pilot handoff"
  "config-json|--config-json|$GENERATED_DEMO_CONFIG_JSON|--config-json must not point to a generated demo/example artifact path for live pilot handoff"
  "deploy-pack-dir|--deploy-pack-dir|$GENERATED_DEMO_DEPLOY_PACK_DIR|--deploy-pack-dir must not point to a generated demo/example artifact path for live pilot handoff"
  "provenance-private-key-file|--provenance-private-key-file|$GENERATED_DEMO_PROVENANCE_KEY|--provenance-private-key-file must not point to a generated demo/example artifact path for live pilot handoff"
  "trust-store|--trust-store|$GENERATED_DEMO_TRUST_STORE|--trust-store must not point to a generated demo/example artifact path for live pilot handoff"
)
live_generated_demo_path_index=0
for live_generated_demo_path_case in "${live_generated_demo_path_cases[@]}"; do
  live_generated_demo_path_index=$((live_generated_demo_path_index + 1))
  IFS='|' read -r generated_demo_name generated_demo_flag generated_demo_value generated_demo_expected_message <<<"$live_generated_demo_path_case"
  : >"$CAPTURE"
  live_code_file="$CODE_FILE"
  live_config_json="$CONFIG_JSON"
  live_deploy_pack_dir="$DEPLOY_PACK_DIR"
  live_provenance_key="$PROVENANCE_KEY"
  live_trust_store="$TRUST_STORE"
  case "$generated_demo_flag" in
    --code-file)
      live_code_file="$generated_demo_value"
      ;;
    --config-json)
      live_config_json="$generated_demo_value"
      ;;
    --deploy-pack-dir)
      live_deploy_pack_dir="$generated_demo_value"
      ;;
    --provenance-private-key-file)
      live_provenance_key="$generated_demo_value"
      ;;
    --trust-store)
      live_trust_store="$generated_demo_value"
      ;;
    *)
      echo "unknown live generated demo path case flag: $generated_demo_flag"
      exit 1
      ;;
  esac
  set +e
  ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
  ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
  ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
  ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
  ./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
    --base-url https://helper.gpm-pilot.net \
    --path-id helper-web \
    --code-file "$live_code_file" \
    --config-json "$live_config_json" \
    --deploy-pack-dir "$live_deploy_pack_dir" \
    "${INSTALLED_HOST_ARGS[@]}" \
    --provenance-private-key-file "$live_provenance_key" \
    --provenance-org-id pilot-org \
    --provenance-org-name "Pilot Org" \
    --trust-store "$live_trust_store" \
    --summary-json "$TMP_DIR/live-generated-demo-path-$live_generated_demo_path_index-summary.json" \
    --print-summary-json 0 >"$TMP_DIR/live-generated-demo-path-$live_generated_demo_path_index.log" 2>&1
  live_generated_demo_path_rc=$?
  set -e
  if [[ "$live_generated_demo_path_rc" -ne 2 ]] ||
    ! grep -Fq -- "$generated_demo_expected_message" "$TMP_DIR/live-generated-demo-path-$live_generated_demo_path_index.log"; then
    echo "expected live generated demo/example path to fail preflight: $generated_demo_name"
    cat "$TMP_DIR/live-generated-demo-path-$live_generated_demo_path_index.log"
    exit 1
  fi
  if [[ -s "$CAPTURE" ]]; then
    echo "live generated demo/example path should not invoke child scripts: $generated_demo_name"
    cat "$CAPTURE"
    exit 1
  fi
  jq -e '.status == "fail" and .rc == 2 and .stage == "preflight" and .mode.plan_only == false' "$TMP_DIR/live-generated-demo-path-$live_generated_demo_path_index-summary.json" >/dev/null
done

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$DEMO_MARKED_TRUST_STORE" \
  --summary-json "$TMP_DIR/live-demo-marked-trust-store-summary.json" \
  --print-summary-json 0 >"$TMP_DIR/live-demo-marked-trust-store.log" 2>&1
live_demo_marked_trust_store_rc=$?
set -e
if [[ "$live_demo_marked_trust_store_rc" -ne 2 ]] ||
  ! grep -Fq -- "--trust-store must not contain generated demo/example trust entries for live pilot handoff" "$TMP_DIR/live-demo-marked-trust-store.log"; then
  echo "expected live demo-marked trust store contents to fail preflight"
  cat "$TMP_DIR/live-demo-marked-trust-store.log"
  exit 1
fi
if [[ -s "$CAPTURE" ]]; then
  echo "live demo-marked trust store should not invoke child scripts"
  cat "$CAPTURE"
  exit 1
fi

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$DEMO_ID_TRUST_STORE" \
  --summary-json "$TMP_DIR/live-demo-id-trust-store-summary.json" \
  --print-summary-json 0 >"$TMP_DIR/live-demo-id-trust-store.log" 2>&1
live_demo_id_trust_store_rc=$?
set -e
if [[ "$live_demo_id_trust_store_rc" -ne 2 ]] ||
  ! grep -Fq -- "--trust-store must not contain generated demo/example trust entries for live pilot handoff" "$TMP_DIR/live-demo-id-trust-store.log"; then
  echo "expected live demo-identity trust store contents to fail preflight"
  cat "$TMP_DIR/live-demo-id-trust-store.log"
  exit 1
fi
if [[ -s "$CAPTURE" ]]; then
  echo "live demo-identity trust store should not invoke child scripts"
  cat "$CAPTURE"
  exit 1
fi

for demo_identity_case in \
  "helper|--expect-helper-id|helper-demo|--expect-helper-id must not use a generated demo/example identity for live pilot handoff" \
  "org|--expect-org-id|freenews-demo|--expect-org-id must not use a generated demo/example identity for live pilot handoff" \
  "registry|--expect-registry-id|registry-demo|--expect-registry-id must not use a generated demo/example identity for live pilot handoff" \
  "helper-example|--expect-helper-id|helper-example|--expect-helper-id must not use a generated demo/example identity for live pilot handoff" \
  "org-example|--expect-org-id|org-example|--expect-org-id must not use a generated demo/example identity for live pilot handoff" \
  "registry-example|--expect-registry-id|registry-example|--expect-registry-id must not use a generated demo/example identity for live pilot handoff"
do
  IFS='|' read -r demo_identity_name demo_identity_flag demo_identity_value demo_identity_message <<<"$demo_identity_case"
  : >"$CAPTURE"
  set +e
  ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
  ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
  ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
  ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
  ./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
    --base-url https://helper.gpm-pilot.net \
    --path-id helper-web \
    --code-file "$CODE_FILE" \
    --config-json "$CONFIG_JSON" \
    --deploy-pack-dir "$DEPLOY_PACK_DIR" \
    "${INSTALLED_HOST_ARGS[@]}" \
    "$demo_identity_flag" "$demo_identity_value" \
    --provenance-private-key-file "$PROVENANCE_KEY" \
    --provenance-org-id pilot-org \
    --provenance-org-name "Pilot Org" \
    --trust-store "$TRUST_STORE" \
    --summary-json "$TMP_DIR/live-demo-identity-$demo_identity_name-summary.json" \
    --print-summary-json 0 >"$TMP_DIR/live-demo-identity-$demo_identity_name.log" 2>&1
  demo_identity_rc=$?
  set -e
  if [[ "$demo_identity_rc" -ne 2 ]] ||
    ! grep -Fq -- "$demo_identity_message" "$TMP_DIR/live-demo-identity-$demo_identity_name.log"; then
    echo "expected live demo identity to fail preflight: $demo_identity_name"
    cat "$TMP_DIR/live-demo-identity-$demo_identity_name.log"
    exit 1
  fi
  if [[ -s "$CAPTURE" ]]; then
    echo "live demo identity should not invoke child scripts: $demo_identity_name"
    cat "$CAPTURE"
    exit 1
  fi
done

for inferred_demo_identity_case in \
  "helper|$CONFIG_INFERRED_HELPER_DEMO_JSON|--config-json helper_id must not use a generated demo/example identity for live pilot handoff" \
  "org|$CONFIG_INFERRED_ORG_DEMO_JSON|--config-json organization_id must not use a generated demo/example identity for live pilot handoff" \
  "registry|$CONFIG_INFERRED_REGISTRY_DEMO_JSON|--config-json registry_id must not use a generated demo/example identity for live pilot handoff"
do
  IFS='|' read -r inferred_demo_identity_name inferred_demo_identity_config inferred_demo_identity_message <<<"$inferred_demo_identity_case"
  : >"$CAPTURE"
  set +e
  ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
  ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
  ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
  ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
  ./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
    --base-url https://helper.gpm-pilot.net \
    --path-id helper-web \
    --code-file "$CODE_FILE" \
    --config-json "$inferred_demo_identity_config" \
    --deploy-pack-dir "$DEPLOY_PACK_DIR" \
    "${INSTALLED_HOST_ARGS[@]}" \
    --provenance-private-key-file "$PROVENANCE_KEY" \
    --provenance-org-id pilot-org \
    --provenance-org-name "Pilot Org" \
    --trust-store "$TRUST_STORE" \
    --summary-json "$TMP_DIR/live-inferred-demo-identity-$inferred_demo_identity_name-summary.json" \
    --print-summary-json 0 >"$TMP_DIR/live-inferred-demo-identity-$inferred_demo_identity_name.log" 2>&1
  inferred_demo_identity_rc=$?
  set -e
  if [[ "$inferred_demo_identity_rc" -ne 2 ]] ||
    ! grep -Fq -- "$inferred_demo_identity_message" "$TMP_DIR/live-inferred-demo-identity-$inferred_demo_identity_name.log"; then
    echo "expected live inferred demo identity to fail preflight: $inferred_demo_identity_name"
    cat "$TMP_DIR/live-inferred-demo-identity-$inferred_demo_identity_name.log"
    exit 1
  fi
  if [[ -s "$CAPTURE" ]]; then
    echo "live inferred demo identity should not invoke child scripts: $inferred_demo_identity_name"
    cat "$CAPTURE"
    exit 1
  fi
done

for provenance_demo_identity_case in \
  "provenance-org-id|freenews-demo|Pilot Org|--provenance-org-id must not use a generated demo/example identity for live pilot handoff" \
  "provenance-org-name|pilot-org|FreeNews Demo|--provenance-org-name must not use a generated demo/example identity for live pilot handoff"
do
  IFS='|' read -r provenance_demo_identity_name provenance_demo_org_id provenance_demo_org_name provenance_demo_identity_message <<<"$provenance_demo_identity_case"
  : >"$CAPTURE"
  set +e
  ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
  ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
  ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
  ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
  ./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
    --base-url https://helper.gpm-pilot.net \
    --path-id helper-web \
    --code-file "$CODE_FILE" \
    --config-json "$CONFIG_JSON" \
    --deploy-pack-dir "$DEPLOY_PACK_DIR" \
    "${INSTALLED_HOST_ARGS[@]}" \
    --provenance-private-key-file "$PROVENANCE_KEY" \
    --provenance-org-id "$provenance_demo_org_id" \
    --provenance-org-name "$provenance_demo_org_name" \
    --trust-store "$TRUST_STORE" \
    --summary-json "$TMP_DIR/live-demo-provenance-identity-$provenance_demo_identity_name-summary.json" \
    --print-summary-json 0 >"$TMP_DIR/live-demo-provenance-identity-$provenance_demo_identity_name.log" 2>&1
  provenance_demo_identity_rc=$?
  set -e
  if [[ "$provenance_demo_identity_rc" -ne 2 ]] ||
    ! grep -Fq -- "$provenance_demo_identity_message" "$TMP_DIR/live-demo-provenance-identity-$provenance_demo_identity_name.log"; then
    echo "expected live demo provenance identity to fail preflight: $provenance_demo_identity_name"
    cat "$TMP_DIR/live-demo-provenance-identity-$provenance_demo_identity_name.log"
    exit 1
  fi
  if [[ -s "$CAPTURE" ]]; then
    echo "live demo provenance identity should not invoke child scripts: $provenance_demo_identity_name"
    cat "$CAPTURE"
    exit 1
  fi
done

echo "[easy-node-access-recovery-real-helper-evidence-run] live handoff requires installed-host evidence mode"
: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --summary-json "$TMP_DIR/live-default-deploy-pack-summary.json" \
  --print-summary-json 0 >"$TMP_DIR/live-default-deploy-pack.log" 2>&1
live_default_deploy_pack_rc=$?
set -e
if [[ "$live_default_deploy_pack_rc" -ne 2 ]] ||
  ! grep -Fq -- "live real-helper pilot handoff requires --host-install-evidence-mode installed-host" "$TMP_DIR/live-default-deploy-pack.log"; then
  echo "expected live default deploy-pack mode to fail closed"
  cat "$TMP_DIR/live-default-deploy-pack.log"
  exit 1
fi
if [[ -s "$CAPTURE" ]]; then
  echo "live default deploy-pack preflight should not invoke child scripts"
  cat "$CAPTURE"
  exit 1
fi
jq -e '
  .status == "fail"
  and .rc == 2
  and .stage == "preflight"
  and .mode.plan_only == false
  and .inputs.host_install_evidence_mode == "deploy-pack"
' "$TMP_DIR/live-default-deploy-pack-summary.json" >/dev/null

echo "[easy-node-access-recovery-real-helper-evidence-run] live handoff rejects demo/example artifacts"
DEMO_ARTIFACT_DIR="$TMP_DIR/.easy-node-logs/access-recovery-demo"
DEMO_CODE_FILE="$DEMO_ARTIFACT_DIR/bridge-code.txt"
DEMO_CONFIG_JSON="$DEMO_ARTIFACT_DIR/bridge-service-config.json"
DEMO_DEPLOY_PACK_DIR="$DEMO_ARTIFACT_DIR/bridge-deploy"
DEMO_TRUST_STORE="$DEMO_ARTIFACT_DIR/recovery-trust.json"
mkdir -p "$DEMO_DEPLOY_PACK_DIR"
printf '%s\n' 'demo-access-code' >"$DEMO_CODE_FILE"
printf '%s\n' '{"status":"pass"}' >"$DEMO_CONFIG_JSON"
printf '%s\n' '{"version":1,"keys":[]}' >"$DEMO_TRUST_STORE"

demo_artifact_cases=(
  "code-file|$DEMO_CODE_FILE|--code-file must not point to a generated demo/example artifact path for live pilot handoff"
  "config-json|$DEMO_CONFIG_JSON|--config-json must not point to a generated demo/example artifact path for live pilot handoff"
  "deploy-pack-dir|$DEMO_DEPLOY_PACK_DIR|--deploy-pack-dir must not point to a generated demo/example artifact path for live pilot handoff"
  "trust-store|$DEMO_TRUST_STORE|--trust-store must not point to a generated demo/example artifact path for live pilot handoff"
)
demo_artifact_index=0
for demo_artifact_case in "${demo_artifact_cases[@]}"; do
  demo_artifact_index=$((demo_artifact_index + 1))
  IFS='|' read -r demo_artifact_flag demo_artifact_value demo_artifact_expected_message <<<"$demo_artifact_case"
  demo_code_file="$CODE_FILE"
  demo_config_json="$CONFIG_JSON"
  demo_deploy_pack_dir="$DEPLOY_PACK_DIR"
  demo_trust_store="$TRUST_STORE"
  case "$demo_artifact_flag" in
    code-file)
      demo_code_file="$demo_artifact_value"
      ;;
    config-json)
      demo_config_json="$demo_artifact_value"
      ;;
    deploy-pack-dir)
      demo_deploy_pack_dir="$demo_artifact_value"
      ;;
    trust-store)
      demo_trust_store="$demo_artifact_value"
      ;;
    *)
      echo "unknown demo artifact integration case: $demo_artifact_flag"
      exit 1
      ;;
  esac
  : >"$CAPTURE"
  set +e
  ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
  ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
  ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
  ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
  ./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
    --base-url https://helper.gpm-pilot.net \
    --path-id helper-web \
    --code-file "$demo_code_file" \
    --config-json "$demo_config_json" \
    --deploy-pack-dir "$demo_deploy_pack_dir" \
    "${INSTALLED_HOST_ARGS[@]}" \
    --provenance-private-key-file "$PROVENANCE_KEY" \
    --provenance-org-id pilot-org \
    --provenance-org-name "Pilot Org" \
    --trust-store "$demo_trust_store" \
    --summary-json "$TMP_DIR/live-demo-artifact-$demo_artifact_index-summary.json" \
    --print-summary-json 0 >"$TMP_DIR/live-demo-artifact-$demo_artifact_index.log" 2>&1
  demo_artifact_rc=$?
  set -e
  if [[ "$demo_artifact_rc" -ne 2 ]] ||
    ! grep -Fq -- "$demo_artifact_expected_message" "$TMP_DIR/live-demo-artifact-$demo_artifact_index.log"; then
    echo "expected live demo artifact case to fail preflight: $demo_artifact_flag"
    cat "$TMP_DIR/live-demo-artifact-$demo_artifact_index.log"
    exit 1
  fi
  if [[ -s "$CAPTURE" ]]; then
    echo "live demo artifact preflight should not invoke child scripts: $demo_artifact_flag"
    cat "$CAPTURE"
    exit 1
  fi
  jq -e '
    .status == "fail"
    and .rc == 2
    and .stage == "preflight"
    and .mode.plan_only == false
  ' "$TMP_DIR/live-demo-artifact-$demo_artifact_index-summary.json" >/dev/null
done

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url "https://[2606:4700:4700::1111]" \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --roadmap-refresh 0 \
  --summary-json "$TMP_DIR/public-ipv6-summary.json" \
  --print-summary-json 0
public_ipv6_rc=$?
set -e
if [[ "$public_ipv6_rc" -ne 0 ]]; then
  echo "expected public IPv6 real-helper URL to pass, got rc $public_ipv6_rc"
  [[ -f "$TMP_DIR/public-ipv6-summary.json" ]] && cat "$TMP_DIR/public-ipv6-summary.json"
  if [[ -d "$REPORTS_DIR" ]]; then
    find "$REPORTS_DIR" -maxdepth 1 -name 'access_bridge_pilot_evidence_verify_*.json' -print -exec cat {} \;
  fi
  cat "$CAPTURE"
  exit 1
fi
if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "3" ]]; then
  echo "expected public IPv6 real-helper URL to invoke host-check, bundle, and verify"
  cat "$CAPTURE"
  exit 1
fi
jq -e '
  .status == "pass"
  and .inputs.base_url == "https://[2606:4700:4700::1111]"
  and .inputs.host_install_evidence_mode == "installed-host"
' "$TMP_DIR/public-ipv6-summary.json" >/dev/null

placeholder_input_cases=(
  "code-file|PRIVATE_CODE_FILE|--code-file must point to a real private access code file, not an unreplaced placeholder"
  "config-json|BRIDGE_SERVICE_CONFIG|--config-json must point to a real bridge service config, not an unreplaced placeholder"
  "deploy-pack-dir|BRIDGE_DEPLOY_PACK|--deploy-pack-dir must point to a real bridge deploy pack directory, not an unreplaced placeholder"
)
placeholder_input_index=0
for placeholder_case in "${placeholder_input_cases[@]}"; do
  placeholder_input_index=$((placeholder_input_index + 1))
  IFS='|' read -r placeholder_flag placeholder_value expected_message <<<"$placeholder_case"
  : >"$CAPTURE"
  case "$placeholder_flag" in
    code-file)
      placeholder_code_file="$placeholder_value"
      placeholder_config_json="$CONFIG_JSON"
      placeholder_deploy_pack_dir="$DEPLOY_PACK_DIR"
      ;;
    config-json)
      placeholder_code_file="$CODE_FILE"
      placeholder_config_json="$placeholder_value"
      placeholder_deploy_pack_dir="$DEPLOY_PACK_DIR"
      ;;
    deploy-pack-dir)
      placeholder_code_file="$CODE_FILE"
      placeholder_config_json="$CONFIG_JSON"
      placeholder_deploy_pack_dir="$placeholder_value"
      ;;
    *)
      echo "unknown placeholder integration case: $placeholder_flag"
      exit 1
      ;;
  esac
  set +e
  ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
  ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
  ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
  ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
  ./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
    --base-url https://helper.gpm-pilot.net \
    --code-file "$placeholder_code_file" \
    --config-json "$placeholder_config_json" \
    --deploy-pack-dir "$placeholder_deploy_pack_dir" \
    --provenance-private-key-file "$PROVENANCE_KEY" \
    --provenance-org-id pilot-org \
    --provenance-org-name "Pilot Org" \
    --trust-store "$TRUST_STORE" \
    --summary-json "$TMP_DIR/placeholder-input-$placeholder_input_index-summary.json" \
    --print-summary-json 0 >"$TMP_DIR/placeholder-input-$placeholder_input_index.log" 2>&1
  placeholder_input_rc=$?
  set -e
  if [[ "$placeholder_input_rc" -ne 2 ]] ||
    ! grep -Fq -- "$expected_message" "$TMP_DIR/placeholder-input-$placeholder_input_index.log"; then
    echo "expected placeholder $placeholder_flag to fail preflight clearly"
    cat "$TMP_DIR/placeholder-input-$placeholder_input_index.log"
    exit 1
  fi
  if [[ -s "$CAPTURE" ]]; then
    echo "placeholder $placeholder_flag should not invoke child scripts"
    cat "$CAPTURE"
    exit 1
  fi
done

: >"$CAPTURE"
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/run-summary.json" \
  --report-md "$TMP_DIR/run-report.md" \
  --print-summary-json 0

if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "4" ]]; then
  echo "expected host-check, bundle, verifier, and roadmap invocations"
  cat "$CAPTURE"
  exit 1
fi

host_check_line="$(sed -n '1p' "$CAPTURE")"
for token in \
  $'\t--evidence-mode\tinstalled-host' \
  $'\t--deploy-pack-dir\t'"$DEPLOY_PACK_DIR" \
  $'\t--install-dir\t'"$INSTALL_DIR" \
  $'\t--systemd-unit-file\t'"$SYSTEMD_UNIT_FILE" \
  $'\t--proxy-kind\tcaddy' \
  $'\t--proxy-config-file\t'"$PROXY_CONFIG_FILE" \
  $'\t--config-json\t'"$CONFIG_JSON" \
  $'\t--expected-base-url\thttps://helper.gpm-pilot.net'
do
  if [[ "$host_check_line" != *"$token"* ]]; then
    echo "missing forwarded host-check token: $token"
    echo "$host_check_line"
    exit 1
  fi
done

bundle_line="$(sed -n '2p' "$CAPTURE")"
for token in \
  $'\t--base-url\thttps://helper.gpm-pilot.net' \
  $'\t--path-id\thelper-web' \
  $'\t--require-https\t1' \
  $'\t--require-public-host\t1' \
  $'\t--require-mtls\t0' \
  $'\t--expected-public-host\thelper.gpm-pilot.net' \
  $'\t--host-install-evidence-mode\tinstalled-host' \
  $'\t--install-dir\t'"$INSTALL_DIR" \
  $'\t--systemd-unit-file\t'"$SYSTEMD_UNIT_FILE" \
  $'\t--proxy-kind\tcaddy' \
  $'\t--proxy-config-file\t'"$PROXY_CONFIG_FILE" \
  $'\t--provenance-sign\t1' \
  $'\t--provenance-private-key-file\t'"$PROVENANCE_KEY" \
  $'\t--provenance-org-id\tpilot-org' \
  $'\t--provenance-org-name\tPilot Org'
do
  if [[ "$bundle_line" != *"$token"* ]]; then
    echo "missing forwarded bundle token: $token"
    echo "$bundle_line"
    exit 1
  fi
done

verify_line="$(sed -n '3p' "$CAPTURE")"
for token in \
  $'\t--provenance-json\t' \
  $'\t--trust-store\t'"$TRUST_STORE" \
  $'\t--require-trusted-provenance\t1' \
  $'\t--verification-summary-json\t'
do
  if [[ "$verify_line" != *"$token"* ]]; then
    echo "missing forwarded verifier token: $token"
    echo "$verify_line"
    exit 1
  fi
done

roadmap_line="$(sed -n '4p' "$CAPTURE")"
for token in \
  $'\t--access-bridge-service-smoke-summary-json\t'"$REPORTS_DIR/bundle/access_bridge_service_smoke_summary.json" \
  $'\t--access-bridge-deployment-evidence-summary-json\t'"$REPORTS_DIR/bundle/access_bridge_deployment_evidence_summary.json" \
  $'\t--access-bridge-host-install-summary-json\t'"$REPORTS_DIR/bundle/access_bridge_host_install_check_summary.json" \
  $'\t--access-bridge-pilot-evidence-bundle-verify-summary-json\t'
do
  if [[ "$roadmap_line" != *"$token"* ]]; then
    echo "missing forwarded roadmap token: $token"
    echo "$roadmap_line"
    exit 1
  fi
done

if ! jq -e '
  .schema.id == "access_recovery_real_helper_evidence_run_summary"
  and .schema.major == 1
  and .schema.minor == 6
  and .status == "pass"
  and .stage == "complete"
  and .mode.plan_only == false
  and .mode.child_execution_skipped == false
  and .mode.evidence_generated == true
  and .mode.evidence_status == "collected"
  and .inputs.host_install_evidence_mode == "installed-host"
  and .child_summaries.host_install_check.status == "pass"
  and .child_summaries.verifier.schema.minor == 6
  and .child_summaries.verifier.handoff_authority == true
  and .child_summaries.verifier.authority_level == "pilot_handoff"
  and .child_summaries.verifier.integrity_only == false
  and .readiness.verifier_ready == true
  and .readiness.handoff_authority_ready == true
  and .readiness.verifier_authority_level == "pilot_handoff"
  and .readiness.verifier_integrity_only == false
  and .readiness.roadmap_ready == true
  and .readiness.roadmap_status_synced == true
  and .readiness.handoff_complete == true
  and .readiness.status_rollup_complete == true
  and .readiness.trusted_verifier_pilot_handoff_ready == true
  and .readiness.roadmap_access_recovery_pilot_handoff_ready == true
' "$TMP_DIR/run-summary.json" >/dev/null; then
  echo "expected real helper evidence run summary to record complete trusted handoff"
  cat "$TMP_DIR/run-summary.json"
  exit 1
fi

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_SCHEMA_MINOR=5 \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/verifier-schema-minor-5-summary.json" \
  --print-summary-json 0 >"$TMP_DIR/verifier-schema-minor-5.log" 2>&1
verifier_schema_minor_5_rc=$?
set -e
if [[ "$verifier_schema_minor_5_rc" -eq 0 ]]; then
  echo "expected verifier receipt schema minor 5 to fail"
  cat "$TMP_DIR/verifier-schema-minor-5-summary.json"
  exit 1
fi
if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "3" ]]; then
  echo "expected host-check, bundle, and verifier only when verifier receipt schema is too old"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -Fq -- "Trusted verifier receipt did not prove current real helper HTTPS evidence binding" "$TMP_DIR/verifier-schema-minor-5-summary.json"; then
  echo "expected verifier schema minor failure summary note"
  cat "$TMP_DIR/verifier-schema-minor-5-summary.json"
  exit 1
fi
if ! grep -Fq -- "schema minor is too old for current smoke/deployment evidence binding semantics" "$TMP_DIR/verifier-schema-minor-5.log"; then
  echo "expected verifier schema minor floor validation error"
  cat "$TMP_DIR/verifier-schema-minor-5.log"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .stage == "verify"
  and .child_summaries.verifier.schema.minor == 5
  and .readiness.verifier_claimed_pilot_handoff_ready == true
  and .readiness.trusted_verifier_pilot_handoff_ready == false
  and .readiness.handoff_authority_ready == false
  and .readiness.handoff_complete == false
  and .readiness.handoff_authority_complete == false
' "$TMP_DIR/verifier-schema-minor-5-summary.json" >/dev/null; then
  echo "expected verifier schema minor 5 summary to mark trusted handoff unavailable"
  cat "$TMP_DIR/verifier-schema-minor-5-summary.json"
  exit 1
fi

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_OLD_DEPLOYMENT_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/deployment-schema-minor-5-summary.json" \
  --print-summary-json 0 >"$TMP_DIR/deployment-schema-minor-5.log" 2>&1
deployment_schema_minor_5_rc=$?
set -e
if [[ "$deployment_schema_minor_5_rc" -eq 0 ]]; then
  echo "expected bundled deployment evidence schema minor 5 to fail"
  cat "$TMP_DIR/deployment-schema-minor-5-summary.json"
  exit 1
fi
if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "2" ]]; then
  echo "expected host-check and bundle only when bundled deployment evidence schema is too old"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -Fq -- "Access bridge pilot evidence bundle child evidence failed current schema and smoke/deployment binding validation" "$TMP_DIR/deployment-schema-minor-5-summary.json"; then
  echo "expected deployment schema failure summary note"
  cat "$TMP_DIR/deployment-schema-minor-5-summary.json"
  exit 1
fi
if ! grep -Fq -- "bundled deployment evidence summary schema minor is too old for current smoke hash binding semantics" "$TMP_DIR/deployment-schema-minor-5.log"; then
  echo "expected deployment schema floor validation error"
  cat "$TMP_DIR/deployment-schema-minor-5.log"
  exit 1
fi
jq -e '
  .status == "fail"
  and .stage == "bundle"
  and .child_summaries.verifier == null
  and .readiness.verifier_claimed_pilot_handoff_ready == false
  and .readiness.trusted_verifier_pilot_handoff_ready == false
  and .readiness.handoff_authority_ready == false
  and .readiness.handoff_complete == false
' "$TMP_DIR/deployment-schema-minor-5-summary.json" >/dev/null

: >"$CAPTURE"
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  --host-install-evidence-mode installed-host \
  --install-dir "$INSTALL_DIR" \
  --systemd-unit-file "$SYSTEMD_UNIT_FILE" \
  --proxy-kind caddy \
  --proxy-config-file "$PROXY_CONFIG_FILE" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/installed-host-run-summary.json" \
  --print-summary-json 0

if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "4" ]]; then
  echo "expected installed-host host-check, bundle, verifier, and roadmap invocations"
  cat "$CAPTURE"
  exit 1
fi
installed_host_check_line="$(sed -n '1p' "$CAPTURE")"
for token in \
  $'\t--evidence-mode\tinstalled-host' \
  $'\t--install-dir\t'"$INSTALL_DIR" \
  $'\t--systemd-unit-file\t'"$SYSTEMD_UNIT_FILE" \
  $'\t--proxy-kind\tcaddy' \
  $'\t--proxy-config-file\t'"$PROXY_CONFIG_FILE"
do
  if [[ "$installed_host_check_line" != *"$token"* ]]; then
    echo "missing forwarded installed-host host-check token: $token"
    echo "$installed_host_check_line"
    exit 1
  fi
done
installed_bundle_line="$(sed -n '2p' "$CAPTURE")"
for token in \
  $'\t--host-install-evidence-mode\tinstalled-host' \
  $'\t--install-dir\t'"$INSTALL_DIR" \
  $'\t--systemd-unit-file\t'"$SYSTEMD_UNIT_FILE" \
  $'\t--proxy-kind\tcaddy' \
  $'\t--proxy-config-file\t'"$PROXY_CONFIG_FILE"
do
  if [[ "$installed_bundle_line" != *"$token"* ]]; then
    echo "missing forwarded installed-host bundle token: $token"
    echo "$installed_bundle_line"
    exit 1
  fi
done
jq -e '
  .status == "pass"
  and .stage == "complete"
  and .inputs.host_install_evidence_mode == "installed-host"
' "$TMP_DIR/installed-host-run-summary.json" >/dev/null

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_READY=false \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/verifier-not-ready-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
verifier_not_ready_rc=$?
set -e
if [[ "$verifier_not_ready_rc" -eq 0 ]]; then
  echo "expected verifier pilot_handoff_ready=false to fail"
  cat "$TMP_DIR/verifier-not-ready-summary.json"
  exit 1
fi
if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "3" ]]; then
  echo "expected host-check, bundle, and verifier only when verifier is not ready"
  cat "$CAPTURE"
  exit 1
fi
jq -e '.status == "fail" and .stage == "verify" and .readiness.trusted_verifier_pilot_handoff_ready == false' "$TMP_DIR/verifier-not-ready-summary.json" >/dev/null

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_TRUSTED=false \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/verifier-untrusted-summary.json" \
  --print-summary-json 0 >"$TMP_DIR/verifier-untrusted.log" 2>&1
verifier_untrusted_rc=$?
set -e
if [[ "$verifier_untrusted_rc" -eq 0 ]]; then
  echo "expected untrusted verifier receipt to fail"
  cat "$TMP_DIR/verifier-untrusted-summary.json"
  exit 1
fi
if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "3" ]]; then
  echo "expected host-check, bundle, and verifier only when trusted provenance is false"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -Fq -- "Trusted verifier receipt did not mark pilot_handoff_ready=true" "$TMP_DIR/verifier-untrusted-summary.json"; then
  echo "expected untrusted verifier failure summary note"
  cat "$TMP_DIR/verifier-untrusted-summary.json"
  exit 1
fi

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_BINDING_MODE=mismatch \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/verifier-binding-mismatch-summary.json" \
  --print-summary-json 0 >"$TMP_DIR/verifier-binding-mismatch.log" 2>&1
verifier_binding_mismatch_rc=$?
set -e
if [[ "$verifier_binding_mismatch_rc" -eq 0 ]]; then
  echo "expected mismatched verifier evidence binding to fail"
  cat "$TMP_DIR/verifier-binding-mismatch-summary.json"
  exit 1
fi
if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "3" ]]; then
  echo "expected host-check, bundle, and verifier only when evidence binding mismatches"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -Fq -- "Trusted verifier receipt did not prove current real helper HTTPS evidence binding" "$TMP_DIR/verifier-binding-mismatch-summary.json"; then
  echo "expected binding mismatch failure summary note"
  cat "$TMP_DIR/verifier-binding-mismatch-summary.json"
  exit 1
fi
jq -e '
  .status == "fail"
  and .stage == "verify"
  and .readiness.verifier_claimed_pilot_handoff_ready == true
  and .readiness.trusted_verifier_pilot_handoff_ready == false
  and .readiness.handoff_authority_ready == false
  and .readiness.handoff_complete == false
  and .readiness.handoff_authority_complete == false
' "$TMP_DIR/verifier-binding-mismatch-summary.json" >/dev/null

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_BINDING_MODE=deployment_smoke_mismatch \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/verifier-deployment-smoke-binding-mismatch-summary.json" \
  --print-summary-json 0 >"$TMP_DIR/verifier-deployment-smoke-binding-mismatch.log" 2>&1
verifier_deployment_smoke_binding_mismatch_rc=$?
set -e
if [[ "$verifier_deployment_smoke_binding_mismatch_rc" -eq 0 ]]; then
  echo "expected mismatched verifier deployment smoke evidence binding to fail"
  cat "$TMP_DIR/verifier-deployment-smoke-binding-mismatch-summary.json"
  exit 1
fi
if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "3" ]]; then
  echo "expected host-check, bundle, and verifier only when deployment smoke binding mismatches"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -Fq -- "deployment smoke summary hash was not proven to match bundled smoke summary" "$TMP_DIR/verifier-deployment-smoke-binding-mismatch.log"; then
  echo "expected deployment smoke binding verifier validation error"
  cat "$TMP_DIR/verifier-deployment-smoke-binding-mismatch.log"
  exit 1
fi
jq -e '
  .status == "fail"
  and .stage == "verify"
  and .child_summaries.verifier.pilot_handoff_criteria.deployment_smoke_summary_sha256_matches_bundle == false
  and .readiness.verifier_claimed_pilot_handoff_ready == true
  and .readiness.trusted_verifier_pilot_handoff_ready == false
  and .readiness.handoff_authority_ready == false
  and .readiness.handoff_complete == false
  and .readiness.handoff_authority_complete == false
' "$TMP_DIR/verifier-deployment-smoke-binding-mismatch-summary.json" >/dev/null

for identity_mode in \
  missing_helper \
  missing_organization \
  missing_registry \
  provenance_org_mismatch \
  trusted_org_mismatch
do
  : >"$CAPTURE"
  set +e
  ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
  ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
  ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
  ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
  ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
  FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_IDENTITY_MODE="$identity_mode" \
  ./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
    --base-url https://helper.gpm-pilot.net \
    --path-id helper-web \
    --code-file "$CODE_FILE" \
    --config-json "$CONFIG_JSON" \
    --deploy-pack-dir "$DEPLOY_PACK_DIR" \
    "${INSTALLED_HOST_ARGS[@]}" \
    --provenance-private-key-file "$PROVENANCE_KEY" \
    --provenance-org-id pilot-org \
    --provenance-org-name "Pilot Org" \
    --trust-store "$TRUST_STORE" \
    --reports-dir "$REPORTS_DIR" \
    --summary-json "$TMP_DIR/verifier-${identity_mode}-summary.json" \
    --print-summary-json 0 >"$TMP_DIR/verifier-${identity_mode}.log" 2>&1
  verifier_identity_rc=$?
  set -e
  if [[ "$verifier_identity_rc" -eq 0 ]]; then
    echo "expected verifier identity/org mode $identity_mode to fail"
    cat "$TMP_DIR/verifier-${identity_mode}-summary.json"
    exit 1
  fi
  if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "3" ]]; then
    echo "expected host-check, bundle, and verifier only for identity/org mode $identity_mode"
    cat "$CAPTURE"
    exit 1
  fi
  if ! grep -Fq -- "Trusted verifier receipt did not prove current real helper HTTPS evidence binding" "$TMP_DIR/verifier-${identity_mode}-summary.json"; then
    echo "expected identity/org failure summary note for $identity_mode"
    cat "$TMP_DIR/verifier-${identity_mode}-summary.json"
    exit 1
  fi
  jq -e '
    .status == "fail"
    and .stage == "verify"
    and .child_summaries.verifier.pilot_handoff_ready == true
    and .readiness.verifier_claimed_pilot_handoff_ready == true
    and .readiness.trusted_verifier_pilot_handoff_ready == false
    and .readiness.handoff_authority_ready == false
    and .readiness.handoff_complete == false
    and .readiness.handoff_authority_complete == false
  ' "$TMP_DIR/verifier-${identity_mode}-summary.json" >/dev/null
done

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
FAKE_ACCESS_RECOVERY_REAL_HELPER_ROADMAP_READY=false \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/roadmap-not-ready-summary.json" \
  --print-summary-json 0 >/dev/null
roadmap_not_ready_rc=$?
set -e
if [[ "$roadmap_not_ready_rc" -eq 0 ]]; then
  echo "expected roadmap access_recovery_pilot_handoff_ready=false to fail closed"
  cat "$TMP_DIR/roadmap-not-ready-summary.json"
  exit 1
fi
if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "4" ]]; then
  echo "expected host-check, bundle, verifier, and roadmap when roadmap is not ready"
  cat "$CAPTURE"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .stage == "status_refresh_mismatch"
  and .mode.evidence_generated == true
  and .mode.evidence_status == "collected_status_refresh_mismatch"
  and .readiness.handoff_authority_ready == true
  and .readiness.handoff_complete == true
  and .readiness.status_rollup_complete == false
  and .readiness.roadmap_status_synced == false
  and .readiness.trusted_verifier_pilot_handoff_ready == true
  and .readiness.roadmap_access_recovery_pilot_handoff_ready == false
' "$TMP_DIR/roadmap-not-ready-summary.json" >/dev/null; then
  echo "expected roadmap access_recovery_pilot_handoff_ready=false to preserve verifier authority but fail closed"
  cat "$TMP_DIR/roadmap-not-ready-summary.json"
  exit 1
fi

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
FAKE_ACCESS_RECOVERY_REAL_HELPER_ROADMAP_RC=7 \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/roadmap-refresh-failed-summary.json" \
  --print-summary-json 0 >/dev/null
roadmap_refresh_failed_rc=$?
set -e
if [[ "$roadmap_refresh_failed_rc" -eq 0 ]]; then
  echo "expected roadmap refresh command failure to fail closed"
  cat "$TMP_DIR/roadmap-refresh-failed-summary.json"
  exit 1
fi
if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "4" ]]; then
  echo "expected host-check, bundle, verifier, and roadmap when roadmap refresh fails"
  cat "$CAPTURE"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .stage == "status_refresh_failed"
  and .mode.evidence_generated == true
  and .mode.evidence_status == "collected_status_refresh_failed"
  and .readiness.handoff_authority_ready == true
  and .readiness.handoff_complete == true
  and .readiness.status_rollup_complete == false
  and .readiness.roadmap_status_synced == false
  and .readiness.trusted_verifier_pilot_handoff_ready == true
  and .readiness.roadmap_access_recovery_pilot_handoff_ready == true
' "$TMP_DIR/roadmap-refresh-failed-summary.json" >/dev/null; then
  echo "expected roadmap refresh command failure to preserve verifier authority but fail closed"
  cat "$TMP_DIR/roadmap-refresh-failed-summary.json"
  exit 1
fi

: >"$CAPTURE"
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://helper.gpm-pilot.net \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  "${INSTALLED_HOST_ARGS[@]}" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --roadmap-refresh 0 \
  --summary-json "$TMP_DIR/no-roadmap-refresh-summary.json" \
  --print-summary-json 0
if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "3" ]]; then
  echo "expected no roadmap invocation when --roadmap-refresh 0"
  cat "$CAPTURE"
  exit 1
fi
jq -e '
  .status == "pass"
  and .stage == "verifier_ready"
  and .mode.evidence_generated == true
  and .mode.evidence_status == "verifier_ready"
  and .inputs.roadmap_refresh == false
  and .readiness.verifier_ready == true
  and .readiness.handoff_authority_ready == true
  and .readiness.roadmap_ready == false
  and .readiness.roadmap_status_synced == false
  and .readiness.handoff_complete == true
  and .readiness.status_rollup_complete == false
  and .readiness.trusted_verifier_pilot_handoff_ready == true
  and .readiness.roadmap_access_recovery_pilot_handoff_ready == false
  and .child_summaries.roadmap == null
' "$TMP_DIR/no-roadmap-refresh-summary.json" >/dev/null

: >"$CAPTURE"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$ROOT_DIR/scripts/access_recovery_real_helper_evidence_run.sh" \
ACCESS_BRIDGE_HOST_INSTALL_CHECK_SCRIPT="$FAKE_HOST_CHECK" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_BUNDLE" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
ACCESS_RECOVERY_REAL_HELPER_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-real-helper-evidence-run \
  --base-url https://HELPER_PUBLIC_DNS \
  --code-file "$CODE_FILE" \
  --config-json "$CONFIG_JSON" \
  --deploy-pack-dir "$DEPLOY_PACK_DIR" \
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id pilot-org \
  --provenance-org-name "Pilot Org" \
  --trust-store "$TRUST_STORE" \
  --summary-json "$TMP_DIR/placeholder-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
rc=$?
set -e
if [[ "$rc" -ne 2 ]]; then
  echo "expected placeholder base-url preflight rc=2, got $rc"
  exit 1
fi
if [[ -s "$CAPTURE" ]]; then
  echo "placeholder preflight should not invoke child scripts"
  cat "$CAPTURE"
  exit 1
fi

echo "easy node access recovery real helper evidence run integration check ok"
