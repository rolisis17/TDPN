#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp rg tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
WIN_PATH_DIR=""
cleanup() {
  rm -rf "$TMP_DIR"
  if [[ -n "$WIN_PATH_DIR" && "$WIN_PATH_DIR" == "$ROOT_DIR/.easy-node-logs/"* ]]; then
    rm -rf "$WIN_PATH_DIR"
  fi
}
trap cleanup EXIT

FAKE_GATE="$TMP_DIR/fake_prod_gate.sh"
cat >"$FAKE_GATE" <<'EOF_FAKE_GATE'
#!/usr/bin/env bash
set -euo pipefail

report_file=""
wg_validate_summary=""
wg_soak_summary=""
gate_summary=""
step_logs_dir="${FAKE_GATE_STEP_LOGS_DIR:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-file)
      report_file="${2:-}"
      shift 2
      ;;
    --wg-validate-summary-json)
      wg_validate_summary="${2:-}"
      shift 2
      ;;
    --wg-soak-summary-json)
      wg_soak_summary="${2:-}"
      shift 2
      ;;
    --gate-summary-json)
      gate_summary="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

echo "fake gate leak probe --subject inv-secret-leak --anon-cred anon-secret-123 TOKEN=token-secret-456 Authorization: Bearer bearer-secret-789 X-Admin-Token: admin-secret-000 url=http://gate-user-secret@gate-a:8081?auth_token=gate-auth-query-secret&admin_token=gate-admin-query-secret#access_token=gate-fragment-secret"

if [[ -n "$step_logs_dir" ]]; then
  mkdir -p "$step_logs_dir"
  echo "fake copied step log --subject inv-step-secret --anon-cred anon-step-secret TOKEN=step-token-secret Authorization: Bearer step-bearer-secret X-Admin-Token: step-admin-secret url=http://step-user-secret@step-a:8081?invite_key=step-invite-query-secret&anon_cred=step-anon-query-secret&subject=step-subject-query-secret#key=step-fragment-secret" >"$step_logs_dir/fake_step.log"
fi

if [[ -n "$report_file" ]]; then
  mkdir -p "$(dirname "$report_file")"
  printf '[prod-gate] fake gate\n' >"$report_file"
fi
if [[ -n "$wg_validate_summary" ]]; then
  mkdir -p "$(dirname "$wg_validate_summary")"
  cat >"$wg_validate_summary" <<'EOF_VALIDATE'
{"status":"ok","failed_step":""}
EOF_VALIDATE
fi
if [[ -n "$wg_soak_summary" ]]; then
  mkdir -p "$(dirname "$wg_soak_summary")"
  cat >"$wg_soak_summary" <<'EOF_SOAK'
{"status":"ok","rounds_failed":0}
EOF_SOAK
fi
if [[ -n "$gate_summary" ]]; then
  mkdir -p "$(dirname "$gate_summary")"
  jq -n --arg step_logs "$step_logs_dir" '{"status":"ok","failed_step":"","step_logs":$step_logs}' >"$gate_summary"
fi
exit 0
EOF_FAKE_GATE
chmod +x "$FAKE_GATE"

BUNDLE_DIR="$TMP_DIR/prod_bundle_ok"
echo "[prod-gate-bundle-verify] generate baseline bundle"
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_GATE" \
FAKE_GATE_STEP_LOGS_DIR="$TMP_DIR/fake_gate_step_logs" \
./scripts/prod_gate_bundle.sh --bundle-dir "$BUNDLE_DIR" >/tmp/integration_prod_gate_bundle_verify_bundle.log 2>&1

if [[ ! -f "${BUNDLE_DIR}.tar.gz" || ! -f "${BUNDLE_DIR}.tar.gz.sha256" || ! -f "$BUNDLE_DIR/manifest.sha256" ]]; then
  echo "baseline bundle generation failed: expected artifacts are missing"
  ls -la "$TMP_DIR"
  cat /tmp/integration_prod_gate_bundle_verify_bundle.log
  exit 1
fi
if rg -q 'inv-secret-leak|anon-secret-123|token-secret-456|bearer-secret-789|admin-secret-000|gate-user-secret|gate-auth-query-secret|gate-admin-query-secret|gate-fragment-secret' /tmp/integration_prod_gate_bundle_verify_bundle.log "$BUNDLE_DIR/prod_gate_bundle.log"; then
  echo "baseline bundle log leaked sensitive fake gate output"
  cat /tmp/integration_prod_gate_bundle_verify_bundle.log
  cat "$BUNDLE_DIR/prod_gate_bundle.log"
  exit 1
fi
if ! rg -q '\[redacted-invite\]|\[redacted\]' /tmp/integration_prod_gate_bundle_verify_bundle.log "$BUNDLE_DIR/prod_gate_bundle.log"; then
  echo "baseline bundle log did not show redacted fake gate output"
  cat /tmp/integration_prod_gate_bundle_verify_bundle.log
  cat "$BUNDLE_DIR/prod_gate_bundle.log"
  exit 1
fi
if rg -q 'inv-step-secret|anon-step-secret|step-token-secret|step-bearer-secret|step-admin-secret|step-user-secret|step-invite-query-secret|step-anon-query-secret|step-subject-query-secret|step-fragment-secret' "$BUNDLE_DIR/step_logs/fake_step.log"; then
  echo "baseline copied step log leaked sensitive fake gate output"
  cat "$BUNDLE_DIR/step_logs/fake_step.log"
  exit 1
fi
if ! rg -q '\[redacted-invite\]|\[redacted\]' "$BUNDLE_DIR/step_logs/fake_step.log"; then
  echo "baseline copied step log did not show redacted fake gate output"
  cat "$BUNDLE_DIR/step_logs/fake_step.log"
  exit 1
fi
if tar -xOzf "${BUNDLE_DIR}.tar.gz" | rg -a -q 'inv-secret-leak|anon-secret-123|token-secret-456|bearer-secret-789|admin-secret-000|gate-user-secret|gate-auth-query-secret|gate-admin-query-secret|gate-fragment-secret|inv-step-secret|anon-step-secret|step-token-secret|step-bearer-secret|step-admin-secret|step-user-secret|step-invite-query-secret|step-anon-query-secret|step-subject-query-secret|step-fragment-secret'; then
  echo "baseline bundle tar leaked sensitive fake gate output"
  exit 1
fi

if command -v wslpath >/dev/null 2>&1; then
  WIN_PATH_DIR="$ROOT_DIR/.easy-node-logs/prod_gate_bundle_windows_path_test_$$"
  WIN_BUNDLE_UNIX="$WIN_PATH_DIR/prod_bundle_windows"
  mkdir -p "$WIN_PATH_DIR"

  echo "[prod-gate-bundle-verify] prod-gate-bundle Windows absolute bundle path"
  THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_GATE" \
  FAKE_GATE_STEP_LOGS_DIR="$TMP_DIR/fake_gate_step_logs_windows" \
  ./scripts/prod_gate_bundle.sh --bundle-dir "$(wslpath -w "$WIN_BUNDLE_UNIX")" >/tmp/integration_prod_gate_bundle_verify_windows_bundle.log 2>&1

  if [[ ! -f "${WIN_BUNDLE_UNIX}.tar.gz" || ! -f "${WIN_BUNDLE_UNIX}.tar.gz.sha256" || ! -f "$WIN_BUNDLE_UNIX/manifest.sha256" ]]; then
    echo "prod-gate-bundle did not normalize Windows absolute bundle path"
    ls -la "$WIN_PATH_DIR"
    cat /tmp/integration_prod_gate_bundle_verify_windows_bundle.log
    exit 1
  fi
  if find "$ROOT_DIR" -maxdepth 1 \( -name 'C*prod_bundle_windows' -o -name 'C*prod_bundle_windows.tar.gz' -o -name 'C*prod_bundle_windows.tar.gz.sha256' \) | rg -q .; then
    echo "prod-gate-bundle created repo-local artifacts from Windows absolute paths"
    find "$ROOT_DIR" -maxdepth 1 \( -name 'C*prod_bundle_windows' -o -name 'C*prod_bundle_windows.tar.gz' -o -name 'C*prod_bundle_windows.tar.gz.sha256' \)
    exit 1
  fi

  WIN_RUN_REPORT="$WIN_PATH_DIR/prod_bundle_windows_run_report.json"
  cat >"$WIN_RUN_REPORT" <<EOF_WIN_RUN_REPORT
{
  "bundle_dir": "$(wslpath -w "$WIN_BUNDLE_UNIX")",
  "bundle_tar": "$(wslpath -w "${WIN_BUNDLE_UNIX}.tar.gz")",
  "bundle_tar_sha256_file": "$(wslpath -w "${WIN_BUNDLE_UNIX}.tar.gz.sha256")",
  "gate_summary_json": "$(wslpath -w "$WIN_BUNDLE_UNIX/prod_gate_summary.json")"
}
EOF_WIN_RUN_REPORT

  ./scripts/prod_gate_bundle_verify.sh --bundle-dir "$(wslpath -w "$WIN_BUNDLE_UNIX")" >/tmp/integration_prod_gate_bundle_verify_windows_dir.log 2>&1
  ./scripts/prod_gate_bundle_verify.sh --bundle-tar "$(wslpath -w "${WIN_BUNDLE_UNIX}.tar.gz")" >/tmp/integration_prod_gate_bundle_verify_windows_tar.log 2>&1
  ./scripts/prod_gate_bundle_verify.sh --run-report-json "$(wslpath -w "$WIN_RUN_REPORT")" >/tmp/integration_prod_gate_bundle_verify_windows_report.log 2>&1
fi

RUN_REPORT="$BUNDLE_DIR/prod_bundle_run_report.json"
cat >"$RUN_REPORT" <<EOF_RUN_REPORT
{
  "bundle_dir": "$BUNDLE_DIR",
  "bundle_tar": "${BUNDLE_DIR}.tar.gz",
  "bundle_tar_sha256_file": "${BUNDLE_DIR}.tar.gz.sha256",
  "gate_summary_json": "$BUNDLE_DIR/prod_gate_summary.json"
}
EOF_RUN_REPORT

echo "[prod-gate-bundle-verify] verify by run-report"
./scripts/prod_gate_bundle_verify.sh --run-report-json "$RUN_REPORT" >/tmp/integration_prod_gate_bundle_verify_report.log 2>&1

echo "[prod-gate-bundle-verify] verify by bundle-dir"
./scripts/prod_gate_bundle_verify.sh --bundle-dir "$BUNDLE_DIR" >/tmp/integration_prod_gate_bundle_verify_dir.log 2>&1

echo "[prod-gate-bundle-verify] verify by bundle-tar"
./scripts/prod_gate_bundle_verify.sh --bundle-tar "${BUNDLE_DIR}.tar.gz" >/tmp/integration_prod_gate_bundle_verify_tar.log 2>&1

echo "[prod-gate-bundle-verify] run-report missing file"
set +e
./scripts/prod_gate_bundle_verify.sh --run-report-json "$TMP_DIR/does_not_exist.json" >/tmp/integration_prod_gate_bundle_verify_missing_report.log 2>&1
missing_report_rc=$?
set -e
if [[ "$missing_report_rc" -eq 0 ]]; then
  echo "expected non-zero rc for missing run report JSON"
  cat /tmp/integration_prod_gate_bundle_verify_missing_report.log
  exit 1
fi
if ! rg -q 'run report JSON file not found' /tmp/integration_prod_gate_bundle_verify_missing_report.log; then
  echo "expected run report missing-file signal not found"
  cat /tmp/integration_prod_gate_bundle_verify_missing_report.log
  exit 1
fi

echo "[prod-gate-bundle-verify] detect manifest tamper"
TAMPER_DIR="$TMP_DIR/prod_bundle_tamper"
cp -a "$BUNDLE_DIR" "$TAMPER_DIR"
printf 'tamper\n' >>"$TAMPER_DIR/prod_gate.log"
set +e
./scripts/prod_gate_bundle_verify.sh --bundle-dir "$TAMPER_DIR" >/tmp/integration_prod_gate_bundle_verify_tamper.log 2>&1
tamper_rc=$?
set -e
if [[ "$tamper_rc" -eq 0 ]]; then
  echo "expected non-zero rc for tampered manifest payload"
  cat /tmp/integration_prod_gate_bundle_verify_tamper.log
  exit 1
fi
if ! rg -q 'manifest checksum mismatch' /tmp/integration_prod_gate_bundle_verify_tamper.log; then
  echo "expected manifest mismatch signal not found"
  cat /tmp/integration_prod_gate_bundle_verify_tamper.log
  exit 1
fi

echo "[prod-gate-bundle-verify] detect tar checksum tamper"
TAMPER_TAR="$TMP_DIR/prod_bundle_tamper.tar.gz"
cp "${BUNDLE_DIR}.tar.gz" "$TAMPER_TAR"
cp "${BUNDLE_DIR}.tar.gz.sha256" "${TAMPER_TAR}.sha256"
printf 'X' >>"$TAMPER_TAR"
set +e
./scripts/prod_gate_bundle_verify.sh --bundle-tar "$TAMPER_TAR" >/tmp/integration_prod_gate_bundle_verify_tamper_tar.log 2>&1
tamper_tar_rc=$?
set -e
if [[ "$tamper_tar_rc" -eq 0 ]]; then
  echo "expected non-zero rc for tampered tar checksum"
  cat /tmp/integration_prod_gate_bundle_verify_tamper_tar.log
  exit 1
fi
if ! rg -q 'tarball checksum mismatch' /tmp/integration_prod_gate_bundle_verify_tamper_tar.log; then
  echo "expected tar checksum mismatch signal not found"
  cat /tmp/integration_prod_gate_bundle_verify_tamper_tar.log
  exit 1
fi

echo "[prod-gate-bundle-verify] easy_node forwarding"
FAKE_VERIFY="$TMP_DIR/fake_verify.sh"
VERIFY_CAPTURE="$TMP_DIR/verify_capture.log"
cat >"$FAKE_VERIFY" <<'EOF_FAKE_VERIFY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${VERIFY_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_VERIFY
chmod +x "$FAKE_VERIFY"

VERIFY_CAPTURE_FILE="$VERIFY_CAPTURE" \
THREE_MACHINE_PROD_GATE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
./scripts/easy_node.sh prod-gate-bundle-verify \
  --run-report-json /tmp/bundle_dir/prod_bundle_run_report.json \
  --bundle-dir /tmp/bundle_dir \
  --bundle-tar /tmp/bundle.tar.gz \
  --show-details 1 >/tmp/integration_prod_gate_bundle_verify_easy_node.log 2>&1

if ! rg -q -- '--run-report-json /tmp/bundle_dir/prod_bundle_run_report.json' "$VERIFY_CAPTURE"; then
  echo "easy_node bundle-verify forwarding failed: missing --run-report-json"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--bundle-dir /tmp/bundle_dir' "$VERIFY_CAPTURE"; then
  echo "easy_node bundle-verify forwarding failed: missing --bundle-dir"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--bundle-tar /tmp/bundle.tar.gz' "$VERIFY_CAPTURE"; then
  echo "easy_node bundle-verify forwarding failed: missing --bundle-tar"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-details 1' "$VERIFY_CAPTURE"; then
  echo "easy_node bundle-verify forwarding failed: missing --show-details"
  cat "$VERIFY_CAPTURE"
  exit 1
fi

echo "[prod-gate-bundle-verify] prod gate command redaction"
FAKE_GATE_HELPER="$TMP_DIR/fake_prod_gate_helper.sh"
cat >"$FAKE_GATE_HELPER" <<'EOF_FAKE_GATE_HELPER'
#!/usr/bin/env bash
set -euo pipefail
printf 'fake helper args: %s\n' "$*"
exit 0
EOF_FAKE_GATE_HELPER
chmod +x "$FAKE_GATE_HELPER"
PROD_GATE_REDACTION_REPORT="$TMP_DIR/prod_gate_redaction.log"
PROD_GATE_REDACTION_SUMMARY="$TMP_DIR/prod_gate_redaction_summary.json"
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_HELPER" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_HELPER" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_HELPER" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_HELPER" \
THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT=1 \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a "http://gate-dir-user-secret@dir-a:8081?auth_token=gate-dir-auth-secret#access_token=gate-dir-fragment-secret" \
  --directory-b "http://dir-b:8081?admin_token=gate-dir-admin-secret#token=gate-dir-admin-fragment-secret" \
  --issuer-url "http://issuer-a:8082?bearer=gate-issuer-bearer-secret#authorization=gate-issuer-fragment-secret" \
  --entry-url "http://entry-a:8083?invite_key=gate-entry-invite-secret#key=gate-entry-fragment-secret" \
  --exit-url "http://exit-a:8084?anon_cred=gate-exit-anon-secret&subject=gate-exit-subject-secret#subject=gate-exit-fragment-secret" \
  --subject inv-gate-redaction-secret \
  --control-require-issuer-quorum 0 \
  --skip-control-soak 1 \
  --skip-wg 1 \
  --report-file "$PROD_GATE_REDACTION_REPORT" \
  --gate-summary-json "$PROD_GATE_REDACTION_SUMMARY" >/tmp/integration_prod_gate_command_redaction.log 2>&1

if rg -q 'gate-dir-user-secret|gate-dir-auth-secret|gate-dir-fragment-secret|gate-dir-admin-secret|gate-dir-admin-fragment-secret|gate-issuer-bearer-secret|gate-issuer-fragment-secret|gate-entry-invite-secret|gate-entry-fragment-secret|gate-exit-anon-secret|gate-exit-subject-secret|gate-exit-fragment-secret|inv-gate-redaction-secret' "$PROD_GATE_REDACTION_REPORT" /tmp/integration_prod_gate_command_redaction.log "$PROD_GATE_REDACTION_SUMMARY"; then
  echo "prod gate command/report leaked URL credentials"
  cat /tmp/integration_prod_gate_command_redaction.log
  cat "$PROD_GATE_REDACTION_REPORT"
  cat "$PROD_GATE_REDACTION_SUMMARY"
  exit 1
fi
if ! rg -q '\[redacted\]|\[redacted-invite\]' "$PROD_GATE_REDACTION_REPORT" /tmp/integration_prod_gate_command_redaction.log; then
  echo "prod gate redaction markers missing from command/report output"
  cat /tmp/integration_prod_gate_command_redaction.log
  cat "$PROD_GATE_REDACTION_REPORT"
  exit 1
fi

echo "prod gate bundle verify integration ok"
