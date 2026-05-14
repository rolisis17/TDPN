#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp rg; do
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

SUMMARY_JSON="$TMP_DIR/gpm_wallet_auth_evidence_summary.json"
REPORT_MD="$TMP_DIR/gpm_wallet_auth_evidence_report.md"
REPORTS_DIR="$TMP_DIR/reports"
RUN_LOG="$TMP_DIR/run.log"

echo "[gpm-wallet-auth-evidence] evidence runner"
./scripts/gpm_wallet_auth_evidence.sh \
  --reports-dir "$REPORTS_DIR" \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --check-timeout-sec 300 \
  --print-summary-json 1 >"$RUN_LOG"

if [[ ! -f "$SUMMARY_JSON" || ! -f "$REPORT_MD" ]]; then
  echo "expected wallet-auth evidence artifacts were not created"
  ls -la "$TMP_DIR"
  cat "$RUN_LOG"
  exit 1
fi

if ! jq -e '
  .schema.id == "gpm_wallet_auth_evidence_summary"
  and .schema.major == 1
  and .status == "pass"
  and .rc == 0
  and .summary.checks_total == 5
  and .summary.checks_failed == 0
  and .evidence.keplr_wallet_extension_alias_pubkey_types == true
  and .evidence.leap_wallet_extension_alias_pubkey_types == true
  and .evidence.secp256k1_wallet_binding == true
  and .evidence.mismatched_wallet_rejection == true
  and .evidence.admin_elevation_rejection == true
  and .evidence.chain_id_hrp_binding == true
  and .evidence.wallet_extension_source_policy == true
  and .evidence.portal_wallet_extension_contract == true
  and .evidence.no_vacuous_go_test_evidence == true
  and .evidence.real_browser_extension_beta_evidence == false
  and .release_evidence.real_browser_extension_beta_evidence.status == "pending"
  and .release_evidence.real_browser_extension_beta_evidence.required_for_release == true
  and .release_evidence.real_browser_extension_beta_evidence.keplr_installed_extension_evidence == false
  and .release_evidence.real_browser_extension_beta_evidence.leap_installed_extension_evidence == false
  and (.checks | length == 5)
  and (.checks | all(.no_tests_detected == false))
' "$SUMMARY_JSON" >/dev/null; then
  echo "wallet-auth evidence summary missing expected pass contract"
  cat "$SUMMARY_JSON"
  exit 1
fi

for check_id in \
  local_wallet_crypto_contracts \
  strict_signature_metadata_contracts \
  wallet_extension_source_policy \
  local_control_api_wallet_session_contract \
  web_portal_wallet_extension_contract; do
  log_path="$(jq -r --arg check_id "$check_id" '.checks[] | select(.id == $check_id) | .log_path' "$SUMMARY_JSON")"
  if [[ -z "$log_path" || ! -f "$log_path" ]]; then
    echo "missing per-check log for $check_id: $log_path"
    cat "$SUMMARY_JSON"
    exit 1
  fi
done

if ! rg -q 'Real browser-extension beta evidence' "$REPORT_MD"; then
  echo "wallet-auth report should preserve real-extension scope note"
  cat "$REPORT_MD"
  exit 1
fi

echo "[gpm-wallet-auth-evidence] easy_node forwarding"
FAKE_SCRIPT="$TMP_DIR/fake_gpm_wallet_auth_evidence.sh"
CAPTURE="$TMP_DIR/easy_node_capture.log"
cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CAPTURE_FILE:?}"
EOF_FAKE
chmod +x "$FAKE_SCRIPT"

CAPTURE_FILE="$CAPTURE" \
GPM_WALLET_AUTH_EVIDENCE_SCRIPT="$FAKE_SCRIPT" \
./scripts/easy_node.sh gpm-wallet-auth-evidence \
  --reports-dir /tmp/wallet-auth-reports \
  --summary-json /tmp/wallet-auth-summary.json \
  --report-md /tmp/wallet-auth-report.md \
  --check-timeout-sec 123 \
  --print-summary-json 1 >/tmp/integration_gpm_wallet_auth_evidence_easy_node.log 2>&1

for expected in \
  '--reports-dir /tmp/wallet-auth-reports' \
  '--summary-json /tmp/wallet-auth-summary.json' \
  '--report-md /tmp/wallet-auth-report.md' \
  '--check-timeout-sec 123' \
  '--print-summary-json 1'; do
  if ! grep -F -- "$expected" "$CAPTURE" >/dev/null; then
    echo "easy_node wallet-auth evidence forwarding missing: $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

echo "gpm wallet auth evidence integration ok"
