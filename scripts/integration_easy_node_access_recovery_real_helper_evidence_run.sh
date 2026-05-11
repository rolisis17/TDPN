#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash chmod grep jq mktemp sed wc; do
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
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$summary_json")"
cat >"$summary_json" <<JSON
{
  "version": 1,
  "schema": {"id": "access_bridge_pilot_evidence_bundle_summary", "major": 1, "minor": 2},
  "status": "pass",
  "rc": 0,
  "evidence_scope": "real_helper_https",
  "pilot_handoff_ready": false,
  "artifacts": {
    "smoke_summary_json": "$(dirname "$summary_json")/bundle/access_bridge_service_smoke_summary.json",
    "deployment_evidence_summary_json": "$(dirname "$summary_json")/bundle/access_bridge_deployment_evidence_summary.json",
    "host_install_check_summary_json": "$(dirname "$summary_json")/bundle/access_bridge_host_install_check_summary.json",
    "bundle_dir": "$(dirname "$summary_json")/bundle",
    "bundle_tar": "$(dirname "$summary_json")/bundle.tar.gz",
    "bundle_tar_sha256_file": "$(dirname "$summary_json")/bundle.tar.gz.sha256"
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
pilot_handoff_ready="${FAKE_ACCESS_RECOVERY_REAL_HELPER_VERIFY_READY:-true}"
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
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$verification_summary_json")"
cat >"$verification_summary_json" <<JSON
{
  "version": 1,
  "schema": {"id": "access_bridge_pilot_evidence_bundle_verification_summary", "major": 1, "minor": 0},
  "status": "pass",
  "rc": 0,
  "pilot_handoff_ready": $pilot_handoff_ready,
  "details": {
    "evidence_scope": "real_helper_https",
    "summary_evidence_scope": "real_helper_https"
  },
  "trusted_provenance": {
    "ok": true,
    "evidence_scope": "real_helper_https",
    "summary_evidence_scope": "real_helper_https"
  }
}
JSON
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
