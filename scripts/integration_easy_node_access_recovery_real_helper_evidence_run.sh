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
FAKE_VERIFY="$TMP_DIR/fake_access_bridge_pilot_evidence_bundle_verify.sh"
FAKE_ROADMAP="$TMP_DIR/fake_roadmap_progress_report.sh"
HELP_OUT="$TMP_DIR/help.txt"
REPORTS_DIR="$TMP_DIR/reports"
CONFIG_JSON="$TMP_DIR/bridge-service-config.json"
DEPLOY_PACK_DIR="$TMP_DIR/deploy-pack"
CODE_FILE="$TMP_DIR/code.txt"
TRUST_STORE="$TMP_DIR/trust-store.json"
PROVENANCE_KEY="$TMP_DIR/provenance.key"

mkdir -p "$DEPLOY_PACK_DIR" "$REPORTS_DIR"
printf '%s\n' '{"status":"pass"}' >"$CONFIG_JSON"
printf '%s\n' 'test-access-code' >"$CODE_FILE"
printf '%s\n' '{"version":1,"keys":[]}' >"$TRUST_STORE"
printf '%s\n' 'test-provenance-key' >"$PROVENANCE_KEY"

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
  "status": "pass",
  "details": {
    "base_url": "$base_url",
    "helper_id": "helper-pilot",
    "organization_id": "freenews-demo",
    "registry_id": "registry-pilot"
  }
}
JSON
cat >"$bundle_dir/access_bridge_deployment_evidence_summary.json" <<JSON
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
if [[ "$binding_mode" == "mismatch" ]]; then
  smoke_sha="0000000000000000000000000000000000000000000000000000000000000000"
fi
trust_store_sha="$(sha256_value "$trust_store")"
jq -n \
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
  --arg host_summary_json "$host_summary_json" \
  --arg host_sha "$host_sha" \
  --argjson pilot_handoff_ready "$pilot_handoff_ready" \
  --argjson trusted_provenance "$trusted_provenance" \
  '{
    version: 1,
    schema: {"id": "access_bridge_pilot_evidence_bundle_verify_summary", "major": 1, "minor": 2},
    status: "pass",
    rc: 0,
    pilot_handoff_ready: $pilot_handoff_ready,
    trusted_pilot_receipt_ready: ($pilot_handoff_ready and $trusted_provenance),
    pilot_handoff_criteria: {
      ready: ($pilot_handoff_ready and $trusted_provenance),
      trusted_pilot_receipt_ready: ($pilot_handoff_ready and $trusted_provenance),
      require_trusted_provenance: true,
      provenance_checked: true,
      provenance_trusted: $trusted_provenance,
      provenance_status: "pass",
      provenance_source: "trust_store",
      provenance_evidence_scope: "real_helper_https",
      summary_evidence_scope: "real_helper_https",
      bundled_child_evidence_semantic_ok: true,
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
      provenance: {enabled: true, required_trusted: true, status: "pass"}
    },
    trusted_provenance: {
      required: true,
      checked: true,
      source: "trust_store",
      trusted: $trusted_provenance,
      status: "pass",
      evidence_scope: "real_helper_https",
      summary_evidence_scope: "real_helper_https"
    },
    evidence_binding: {
      base_url: $base_url,
      smoke_summary_json: $smoke_summary_json,
      smoke_summary_sha256: $smoke_sha,
      deployment_evidence_summary_json: $deployment_summary_json,
      deployment_evidence_summary_sha256: $deployment_sha,
      host_install_check_summary_json: $host_summary_json,
      host_install_check_summary_sha256: $host_sha
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
if ! ./scripts/easy_node.sh help --expert | grep -Fq -- 'access-recovery-real-helper-evidence-run runs the real public helper HTTPS evidence flow'; then
  echo "easy_node expert help missing real helper evidence run note"
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
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id freenews-demo \
  --provenance-org-name "FreeNews Demo" \
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
  --provenance-org-id freenews-demo \
  --provenance-org-name "FreeNews Demo" \
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
    --provenance-org-id freenews-demo \
    --provenance-org-name "FreeNews Demo" \
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
  --provenance-org-id freenews-demo \
  --provenance-org-name "FreeNews Demo" \
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
  .status == "pass"
  and .stage == "plan"
  and .mode.plan_only == true
  and .mode.child_execution_skipped == true
  and .child_summaries.host_install_check == null
  and .child_summaries.bundle == null
  and .child_summaries.verifier == null
  and .child_summaries.roadmap == null
  and .planned_child_commands.host_install_check.enabled == true
  and .planned_child_commands.bundle.enabled == true
  and .planned_child_commands.verifier.enabled == true
  and .planned_child_commands.roadmap.enabled == true
  and (.planned_child_commands.bundle.args | index("--bundle-dir") != null)
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
    --provenance-org-id freenews-demo \
    --provenance-org-name "FreeNews Demo" \
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

: >"$CAPTURE"
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
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id freenews-demo \
  --provenance-org-name "FreeNews Demo" \
  --trust-store "$TRUST_STORE" \
  --roadmap-refresh 0 \
  --summary-json "$TMP_DIR/public-ipv6-summary.json" \
  --print-summary-json 0
if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "3" ]]; then
  echo "expected public IPv6 real-helper URL to invoke host-check, bundle, and verify"
  cat "$CAPTURE"
  exit 1
fi
jq -e '.status == "pass" and .inputs.base_url == "https://[2606:4700:4700::1111]"' "$TMP_DIR/public-ipv6-summary.json" >/dev/null

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
    --provenance-org-id freenews-demo \
    --provenance-org-name "FreeNews Demo" \
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
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id freenews-demo \
  --provenance-org-name "FreeNews Demo" \
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
  $'\t--deploy-pack-dir\t'"$DEPLOY_PACK_DIR" \
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
  $'\t--expected-public-host\thelper.gpm-pilot.net' \
  $'\t--provenance-sign\t1' \
  $'\t--provenance-private-key-file\t'"$PROVENANCE_KEY" \
  $'\t--provenance-org-id\tfreenews-demo' \
  $'\t--provenance-org-name\tFreeNews Demo'
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

jq -e '
  .schema.id == "access_recovery_real_helper_evidence_run_summary"
  and .status == "pass"
  and .stage == "complete"
  and .child_summaries.host_install_check.status == "pass"
  and (.artifacts.bundle_service_smoke_summary_json | endswith("/bundle/access_bridge_service_smoke_summary.json"))
  and (.artifacts.bundle_deployment_evidence_summary_json | endswith("/bundle/access_bridge_deployment_evidence_summary.json"))
  and (.artifacts.bundle_host_install_check_summary_json | endswith("/bundle/access_bridge_host_install_check_summary.json"))
  and .readiness.trusted_verifier_pilot_handoff_ready == true
  and .readiness.roadmap_access_recovery_pilot_handoff_ready == true
' "$TMP_DIR/run-summary.json" >/dev/null

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
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id freenews-demo \
  --provenance-org-name "FreeNews Demo" \
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
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id freenews-demo \
  --provenance-org-name "FreeNews Demo" \
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
if ! grep -Fq -- "Trusted verifier receipt did not prove current real helper HTTPS evidence binding" "$TMP_DIR/verifier-untrusted-summary.json"; then
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
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id freenews-demo \
  --provenance-org-name "FreeNews Demo" \
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
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id freenews-demo \
  --provenance-org-name "FreeNews Demo" \
  --trust-store "$TRUST_STORE" \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$TMP_DIR/roadmap-not-ready-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
roadmap_not_ready_rc=$?
set -e
if [[ "$roadmap_not_ready_rc" -eq 0 ]]; then
  echo "expected roadmap access_recovery_pilot_handoff_ready=false to fail"
  cat "$TMP_DIR/roadmap-not-ready-summary.json"
  exit 1
fi
if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "4" ]]; then
  echo "expected host-check, bundle, verifier, and roadmap when roadmap is not ready"
  cat "$CAPTURE"
  exit 1
fi
jq -e '.status == "fail" and .stage == "roadmap" and .readiness.trusted_verifier_pilot_handoff_ready == true and .readiness.roadmap_access_recovery_pilot_handoff_ready == false' "$TMP_DIR/roadmap-not-ready-summary.json" >/dev/null

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
  --provenance-private-key-file "$PROVENANCE_KEY" \
  --provenance-org-id freenews-demo \
  --provenance-org-name "FreeNews Demo" \
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
jq -e '.status == "pass" and .stage == "complete" and .inputs.roadmap_refresh == false and .readiness.trusted_verifier_pilot_handoff_ready == true and .readiness.roadmap_access_recovery_pilot_handoff_ready == false and .child_summaries.roadmap == null' "$TMP_DIR/no-roadmap-refresh-summary.json" >/dev/null

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
  --provenance-org-id freenews-demo \
  --provenance-org-name "FreeNews Demo" \
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
