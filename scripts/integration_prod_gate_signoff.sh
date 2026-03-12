#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp rg; do
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

FAKE_VERIFY="$TMP_DIR/fake_verify.sh"
FAKE_CHECK="$TMP_DIR/fake_check.sh"
VERIFY_CAPTURE="$TMP_DIR/verify_args.log"
CHECK_CAPTURE="$TMP_DIR/check_args.log"

cat >"$FAKE_VERIFY" <<'EOF_FAKE_VERIFY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${VERIFY_CAPTURE_FILE:?}"
exit "${FAKE_VERIFY_RC:-0}"
EOF_FAKE_VERIFY
chmod +x "$FAKE_VERIFY"

cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CHECK_CAPTURE_FILE:?}"
exit "${FAKE_CHECK_RC:-0}"
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

echo "[prod-gate-signoff] success path"
: >"$VERIFY_CAPTURE"
: >"$CHECK_CAPTURE"
VERIFY_CAPTURE_FILE="$VERIFY_CAPTURE" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
FAKE_VERIFY_RC=0 \
FAKE_CHECK_RC=0 \
THREE_MACHINE_PROD_GATE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
THREE_MACHINE_PROD_GATE_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/easy_node.sh prod-gate-signoff \
  --run-report-json /tmp/prod_bundle/prod_bundle_run_report.json \
  --bundle-dir /tmp/prod_bundle \
  --bundle-tar /tmp/prod_bundle.tar.gz \
  --bundle-tar-sha256-file /tmp/prod_bundle.tar.gz.sha256 \
  --check-tar-sha256 1 \
  --check-manifest 1 \
  --show-integrity-details 1 \
  --gate-summary-json /tmp/prod_bundle/prod_gate_summary.json \
  --require-full-sequence 0 \
  --require-wg-validate-ok 1 \
  --require-wg-soak-ok 0 \
  --require-preflight-ok 1 \
  --require-bundle-ok 1 \
  --require-integrity-ok 1 \
  --require-signoff-ok 1 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
  --require-wg-validate-udp-source 1 \
  --require-wg-validate-strict-distinct 1 \
  --require-wg-soak-diversity-pass 1 \
  --min-wg-soak-selection-lines 12 \
  --min-wg-soak-entry-operators 2 \
  --min-wg-soak-exit-operators 2 \
  --min-wg-soak-cross-operator-pairs 2 \
  --max-wg-soak-failed-rounds 3 \
  --show-json 1 >/tmp/integration_prod_gate_signoff_success.log 2>&1

if ! rg -q -- '--run-report-json /tmp/prod_bundle/prod_bundle_run_report.json' "$VERIFY_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: verify missing --run-report-json"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--bundle-dir /tmp/prod_bundle' "$VERIFY_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: verify missing --bundle-dir"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--bundle-tar /tmp/prod_bundle.tar.gz' "$VERIFY_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: verify missing --bundle-tar"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--bundle-tar-sha256-file /tmp/prod_bundle.tar.gz.sha256' "$VERIFY_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: verify missing --bundle-tar-sha256-file"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-details 1' "$VERIFY_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: verify missing --show-details"
  cat "$VERIFY_CAPTURE"
  exit 1
fi

if ! rg -q -- '--run-report-json /tmp/prod_bundle/prod_bundle_run_report.json' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --run-report-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--bundle-dir /tmp/prod_bundle' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --bundle-dir"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--gate-summary-json /tmp/prod_bundle/prod_gate_summary.json' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --gate-summary-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-full-sequence 0' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --require-full-sequence"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-ok 1' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --require-wg-validate-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-soak-ok 0' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --require-wg-soak-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-wg-soak-failed-rounds 3' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --max-wg-soak-failed-rounds"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-preflight-ok 1' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --require-preflight-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-bundle-ok 1' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --require-bundle-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-integrity-ok 1' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --require-integrity-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-signoff-ok 1' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --require-signoff-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 1' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --require-incident-snapshot-on-fail"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 1' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --require-incident-snapshot-artifacts"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-udp-source 1' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --require-wg-validate-udp-source"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-strict-distinct 1' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --require-wg-validate-strict-distinct"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-soak-diversity-pass 1' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --require-wg-soak-diversity-pass"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-selection-lines 12' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --min-wg-soak-selection-lines"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-entry-operators 2' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --min-wg-soak-entry-operators"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-exit-operators 2' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --min-wg-soak-exit-operators"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-cross-operator-pairs 2' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --min-wg-soak-cross-operator-pairs"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$CHECK_CAPTURE"; then
  echo "prod-gate-signoff forwarding failed: check missing --show-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi

echo "[prod-gate-signoff] verify fail-close path"
: >"$VERIFY_CAPTURE"
: >"$CHECK_CAPTURE"
set +e
VERIFY_CAPTURE_FILE="$VERIFY_CAPTURE" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
FAKE_VERIFY_RC=17 \
FAKE_CHECK_RC=0 \
THREE_MACHINE_PROD_GATE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
THREE_MACHINE_PROD_GATE_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/easy_node.sh prod-gate-signoff \
  --run-report-json /tmp/prod_bundle/prod_bundle_run_report.json >/tmp/integration_prod_gate_signoff_verify_fail.log 2>&1
verify_fail_rc=$?
set -e
if [[ "$verify_fail_rc" -ne 17 ]]; then
  echo "prod-gate-signoff verify fail-close failed: expected rc=17 (got $verify_fail_rc)"
  cat /tmp/integration_prod_gate_signoff_verify_fail.log
  exit 1
fi
if [[ -s "$CHECK_CAPTURE" ]]; then
  echo "prod-gate-signoff verify fail-close failed: check step should not run"
  cat "$CHECK_CAPTURE"
  cat /tmp/integration_prod_gate_signoff_verify_fail.log
  exit 1
fi

echo "[prod-gate-signoff] check fail-close path"
: >"$VERIFY_CAPTURE"
: >"$CHECK_CAPTURE"
set +e
VERIFY_CAPTURE_FILE="$VERIFY_CAPTURE" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
FAKE_VERIFY_RC=0 \
FAKE_CHECK_RC=19 \
THREE_MACHINE_PROD_GATE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
THREE_MACHINE_PROD_GATE_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/easy_node.sh prod-gate-signoff \
  --run-report-json /tmp/prod_bundle/prod_bundle_run_report.json >/tmp/integration_prod_gate_signoff_check_fail.log 2>&1
check_fail_rc=$?
set -e
if [[ "$check_fail_rc" -ne 19 ]]; then
  echo "prod-gate-signoff check fail-close failed: expected rc=19 (got $check_fail_rc)"
  cat /tmp/integration_prod_gate_signoff_check_fail.log
  exit 1
fi
if [[ ! -s "$CHECK_CAPTURE" ]]; then
  echo "prod-gate-signoff check fail-close failed: check step did not run"
  cat /tmp/integration_prod_gate_signoff_check_fail.log
  exit 1
fi

echo "prod gate signoff integration ok"
