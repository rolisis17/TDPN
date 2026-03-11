#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp rg tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
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
  cat >"$gate_summary" <<'EOF_GATE'
{"status":"ok","failed_step":"","step_logs":""}
EOF_GATE
fi
exit 0
EOF_FAKE_GATE
chmod +x "$FAKE_GATE"

BUNDLE_DIR="$TMP_DIR/prod_bundle_ok"
echo "[prod-gate-bundle-verify] generate baseline bundle"
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_GATE" \
./scripts/prod_gate_bundle.sh --bundle-dir "$BUNDLE_DIR" >/tmp/integration_prod_gate_bundle_verify_bundle.log 2>&1

if [[ ! -f "${BUNDLE_DIR}.tar.gz" || ! -f "${BUNDLE_DIR}.tar.gz.sha256" || ! -f "$BUNDLE_DIR/manifest.sha256" ]]; then
  echo "baseline bundle generation failed: expected artifacts are missing"
  ls -la "$TMP_DIR"
  cat /tmp/integration_prod_gate_bundle_verify_bundle.log
  exit 1
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

echo "prod gate bundle verify integration ok"
