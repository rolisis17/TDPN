#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod grep tail cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
HELP_OUT="$TMP_DIR/help.txt"
STDOUT_OUT="$TMP_DIR/stdout.txt"
FAKE_SCRIPT="$TMP_DIR/fake_roadmap_progress_report.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ROADMAP_PROGRESS_REPORT_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake roadmap progress report: $*"
exit "${FAKE_ROADMAP_PROGRESS_REPORT_RC:-0}"
EOF_FAKE
chmod +x "$FAKE_SCRIPT"

assert_token() {
  local line="$1"
  local token="$2"
  local message="$3"
  if [[ "$line" != *"$token"* ]]; then
    echo "$message"
    echo "line: $line"
    echo "capture:"
    cat "$CAPTURE"
    exit 1
  fi
}

echo "[easy-node-roadmap-progress-report] help contract"
./scripts/easy_node.sh help --expert >"$HELP_OUT"
for token in \
  './scripts/easy_node.sh roadmap-progress-report' \
  '--phase6-cosmos-l1-summary-json PATH' \
  '--phase7-mainnet-cutover-summary-json PATH' \
  '--blockchain-mainnet-activation-gate-summary-json PATH' \
  '--blockchain-bootstrap-governance-graduation-gate-summary-json PATH' \
  '--gpm-wallet-auth-evidence-summary-json PATH' \
  '--access-bridge-service-smoke-summary-json PATH' \
  '--access-bridge-deployment-evidence-summary-json PATH' \
  '--access-bridge-host-install-summary-json PATH' \
  '--access-bridge-pilot-evidence-bundle-verify-summary-json PATH' \
  '--require-access-recovery-evidence [0|1]' \
  'Access Recovery track status' \
  'Cosmos-first blockchain-track policy signal'
do
  if ! grep -F -- "$token" "$HELP_OUT" >/dev/null 2>&1; then
    echo "easy_node help missing roadmap-progress-report token: $token"
    cat "$HELP_OUT"
    exit 1
  fi
done

echo "[easy-node-roadmap-progress-report] env override + forwarding contract"
: >"$CAPTURE"
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_PROGRESS_REPORT_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh roadmap-progress-report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json .easy-node-logs/manual_validation_readiness_summary.json \
  --manual-validation-report-md .easy-node-logs/manual_validation_readiness_report.md \
  --profile-compare-signoff-summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json \
  --single-machine-summary-json .easy-node-logs/single_machine_prod_readiness_summary.json \
  --vpn-rc-resilience-summary-json .easy-node-logs/vpn_rc_resilience_summary.json \
  --phase2-linux-prod-candidate-summary-json .easy-node-logs/phase2_linux_prod_candidate_summary.json \
  --phase3-windows-client-beta-summary-json .easy-node-logs/phase3_windows_client_beta_summary.json \
  --phase4-windows-full-parity-summary-json .easy-node-logs/phase4_windows_full_parity_summary.json \
  --phase5-settlement-layer-summary-json .easy-node-logs/phase5_settlement_layer_summary.json \
  --phase6-cosmos-l1-summary-json .easy-node-logs/phase6_cosmos_l1_summary.json \
  --phase7-mainnet-cutover-summary-json .easy-node-logs/phase7_mainnet_cutover_summary.json \
  --blockchain-mainnet-activation-gate-summary-json .easy-node-logs/blockchain_mainnet_activation_gate_summary.json \
  --blockchain-bootstrap-governance-graduation-gate-summary-json .easy-node-logs/blockchain_bootstrap_governance_graduation_gate_summary.json \
  --gpm-wallet-auth-evidence-summary-json .easy-node-logs/gpm_wallet_auth_evidence_summary.json \
  --access-bridge-service-smoke-summary-json .easy-node-logs/access_bridge_service_smoke_summary.json \
  --access-bridge-deployment-evidence-summary-json .easy-node-logs/access_bridge_deployment_evidence_summary.json \
  --access-bridge-host-install-summary-json .easy-node-logs/access_bridge_host_install_summary.json \
  --access-bridge-pilot-evidence-bundle-verify-summary-json .easy-node-logs/access_bridge_pilot_evidence_bundle_verify_summary.json \
  --require-access-recovery-evidence 1 \
  --summary-json .easy-node-logs/roadmap_progress_summary.json \
  --report-md .easy-node-logs/roadmap_progress_report.md \
  --print-report 0 \
  --print-summary-json 1 >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi

assert_token "$line" $'\t--refresh-manual-validation\t0' "missing --refresh-manual-validation forwarding"
assert_token "$line" $'\t--refresh-single-machine-readiness\t0' "missing --refresh-single-machine-readiness forwarding"
assert_token "$line" $'\t--manual-validation-summary-json\t.easy-node-logs/manual_validation_readiness_summary.json' "missing --manual-validation-summary-json forwarding"
assert_token "$line" $'\t--phase6-cosmos-l1-summary-json\t.easy-node-logs/phase6_cosmos_l1_summary.json' "missing --phase6-cosmos-l1-summary-json forwarding"
assert_token "$line" $'\t--phase7-mainnet-cutover-summary-json\t.easy-node-logs/phase7_mainnet_cutover_summary.json' "missing --phase7-mainnet-cutover-summary-json forwarding"
assert_token "$line" $'\t--blockchain-mainnet-activation-gate-summary-json\t.easy-node-logs/blockchain_mainnet_activation_gate_summary.json' "missing --blockchain-mainnet-activation-gate-summary-json forwarding"
assert_token "$line" $'\t--blockchain-bootstrap-governance-graduation-gate-summary-json\t.easy-node-logs/blockchain_bootstrap_governance_graduation_gate_summary.json' "missing --blockchain-bootstrap-governance-graduation-gate-summary-json forwarding"
assert_token "$line" $'\t--gpm-wallet-auth-evidence-summary-json\t.easy-node-logs/gpm_wallet_auth_evidence_summary.json' "missing --gpm-wallet-auth-evidence-summary-json forwarding"
assert_token "$line" $'\t--access-bridge-service-smoke-summary-json\t.easy-node-logs/access_bridge_service_smoke_summary.json' "missing --access-bridge-service-smoke-summary-json forwarding"
assert_token "$line" $'\t--access-bridge-deployment-evidence-summary-json\t.easy-node-logs/access_bridge_deployment_evidence_summary.json' "missing --access-bridge-deployment-evidence-summary-json forwarding"
assert_token "$line" $'\t--access-bridge-host-install-summary-json\t.easy-node-logs/access_bridge_host_install_summary.json' "missing --access-bridge-host-install-summary-json forwarding"
assert_token "$line" $'\t--access-bridge-pilot-evidence-bundle-verify-summary-json\t.easy-node-logs/access_bridge_pilot_evidence_bundle_verify_summary.json' "missing --access-bridge-pilot-evidence-bundle-verify-summary-json forwarding"
assert_token "$line" $'\t--require-access-recovery-evidence\t1' "missing --require-access-recovery-evidence forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/roadmap_progress_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--report-md\t.easy-node-logs/roadmap_progress_report.md' "missing --report-md forwarding"
assert_token "$line" $'\t--print-report\t0' "missing --print-report forwarding"
assert_token "$line" $'\t--print-summary-json\t1' "missing --print-summary-json forwarding"

if ! grep -Fq "fake roadmap progress report:" "$STDOUT_OUT"; then
  echo "expected fake roadmap progress output"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "integration easy_node roadmap progress report ok"
