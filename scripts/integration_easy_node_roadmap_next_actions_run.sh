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
EXPERT_HELP_OUT="$TMP_DIR/help_expert.txt"
STDOUT_OUT="$TMP_DIR/stdout.txt"
STDERR_OUT="$TMP_DIR/stderr.txt"
FAKE_SCRIPT="$TMP_DIR/fake_roadmap_next_actions_run.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ROADMAP_NEXT_ACTIONS_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake roadmap next actions run: $*"
exit "${FAKE_ROADMAP_NEXT_ACTIONS_RUN_RC:-0}"
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

echo "[easy-node-roadmap-next-actions] help contract"
./scripts/easy_node.sh help >"$HELP_OUT"
for token in \
  './scripts/easy_node.sh roadmap-next-actions-run' \
  '--max-actions N' \
  '--action-timeout-sec N' \
  '--parallel [0|1]' \
  '--local-only [0|1]' \
  '--allow-profile-default-gate-unreachable [0|1]' \
  '--profile-default-gate-subject ID' \
  '--access-recovery-helper-public-dns HOST' \
  '--access-recovery-helper-id ID' \
  '--access-recovery-org-id ID' \
  '--access-recovery-org-name NAME' \
  '--access-recovery-private-code-file PATH' \
  '--access-recovery-bridge-service-config PATH' \
  '--access-recovery-bridge-deploy-pack DIR' \
  '--access-recovery-provenance-private-key-file PATH' \
  '--access-recovery-reports-dir DIR' \
  '--access-recovery-install-dir DIR' \
  '--access-recovery-systemd-unit-file PATH' \
  '--access-recovery-proxy-kind caddy|nginx|none' \
  '--access-recovery-proxy-config-file PATH' \
  '--access-recovery-trust-store PATH' \
  '--access-recovery-mtls-ca PATH' \
  '--access-recovery-mtls-client-cert PATH' \
  '--access-recovery-mtls-client-key PATH' \
  '--include-id ID' \
  '--exclude-id ID' \
  '--include-id-prefix PREFIX' \
  '--exclude-id-prefix PREFIX' \
  '--include-id-suffix SUFFIX' \
  '--exclude-id-suffix SUFFIX' \
  '[roadmap_next_actions_run args...]'
do
  if ! grep -F -- "$token" "$HELP_OUT" >/dev/null 2>&1; then
    echo "easy_node help missing roadmap-next-actions-run token: $token"
    cat "$HELP_OUT"
    exit 1
  fi
done

./scripts/easy_node.sh help --expert >"$EXPERT_HELP_OUT"
for token in \
  './scripts/easy_node.sh roadmap-next-actions-run' \
  '--access-recovery-helper-public-dns HOST' \
  '--access-recovery-bridge-deploy-pack DIR' \
  '--access-recovery-proxy-kind caddy|nginx|none' \
  '--access-recovery-mtls-client-key PATH' \
  'Access Recovery operator input overrides for helper/org/code/config/deploy/provenance/reports/install/proxy fields'
do
  if ! grep -F -- "$token" "$EXPERT_HELP_OUT" >/dev/null 2>&1; then
    echo "easy_node expert help missing roadmap-next-actions-run token: $token"
    cat "$EXPERT_HELP_OUT"
    exit 1
  fi
done

echo "[easy-node-roadmap-next-actions] env override + forwarding contract"
: >"$CAPTURE"
ROADMAP_NEXT_ACTIONS_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_NEXT_ACTIONS_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh roadmap-next-actions-run \
  --max-actions 2 \
  --action-timeout-sec 9 \
  --parallel 1 \
  --local-only 1 \
  --allow-profile-default-gate-unreachable 1 \
  --profile-default-gate-subject inv-forwarded-subject \
  --access-recovery-helper-public-dns helper-pilot.gpm.net \
  --access-recovery-helper-id helper-pilot \
  --access-recovery-org-id pilot-org \
  --access-recovery-org-name "Pilot Org" \
  --access-recovery-private-code-file .easy-node-logs/operator/private-code.txt \
  --access-recovery-bridge-service-config .easy-node-logs/operator/bridge-service-config.json \
  --access-recovery-bridge-deploy-pack .easy-node-logs/operator/bridge-deploy-pack \
  --access-recovery-provenance-private-key-file .easy-node-logs/operator/provenance.key \
  --access-recovery-reports-dir .easy-node-logs/operator/access-recovery-reports \
  --access-recovery-install-dir /srv/gpm/access-bridge \
  --access-recovery-systemd-unit-file /etc/systemd/system/gpm-access-bridge.service \
  --access-recovery-proxy-kind caddy \
  --access-recovery-proxy-config-file /etc/caddy/Caddyfile.d/gpm-access-bridge.caddy \
  --access-recovery-trust-store .easy-node-logs/operator-trust/recovery-trust.json \
  --access-recovery-mtls-ca .easy-node-logs/operator-mtls/ca.pem \
  --access-recovery-mtls-client-cert .easy-node-logs/operator-mtls/client.pem \
  --access-recovery-mtls-client-key .easy-node-logs/operator-mtls/client.key \
  --include-id blockchain_mainnet_activation_refresh_evidence \
  --exclude-id profile_default_gate \
  --include-id-prefix blockchain_ \
  --exclude-id-prefix profile_ \
  --include-id-suffix _evidence_pack \
  --exclude-id-suffix _cycle \
  --reports-dir .easy-node-logs/roadmap_next_actions_contract \
  --summary-json .easy-node-logs/roadmap_next_actions_contract_summary.json \
  --print-summary-json 1 >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--max-actions\t2' "missing --max-actions forwarding"
assert_token "$line" $'\t--action-timeout-sec\t9' "missing --action-timeout-sec forwarding"
assert_token "$line" $'\t--parallel\t1' "missing --parallel forwarding"
assert_token "$line" $'\t--local-only\t1' "missing --local-only forwarding"
assert_token "$line" $'\t--allow-profile-default-gate-unreachable\t1' "missing --allow-profile-default-gate-unreachable forwarding"
assert_token "$line" $'\t--profile-default-gate-subject\tinv-forwarded-subject' "missing --profile-default-gate-subject forwarding"
assert_token "$line" $'\t--access-recovery-helper-public-dns\thelper-pilot.gpm.net' "missing --access-recovery-helper-public-dns forwarding"
assert_token "$line" $'\t--access-recovery-helper-id\thelper-pilot' "missing --access-recovery-helper-id forwarding"
assert_token "$line" $'\t--access-recovery-org-id\tpilot-org' "missing --access-recovery-org-id forwarding"
assert_token "$line" $'\t--access-recovery-org-name\tPilot Org' "missing --access-recovery-org-name forwarding"
assert_token "$line" $'\t--access-recovery-private-code-file\t.easy-node-logs/operator/private-code.txt' "missing --access-recovery-private-code-file forwarding"
assert_token "$line" $'\t--access-recovery-bridge-service-config\t.easy-node-logs/operator/bridge-service-config.json' "missing --access-recovery-bridge-service-config forwarding"
assert_token "$line" $'\t--access-recovery-bridge-deploy-pack\t.easy-node-logs/operator/bridge-deploy-pack' "missing --access-recovery-bridge-deploy-pack forwarding"
assert_token "$line" $'\t--access-recovery-provenance-private-key-file\t.easy-node-logs/operator/provenance.key' "missing --access-recovery-provenance-private-key-file forwarding"
assert_token "$line" $'\t--access-recovery-reports-dir\t.easy-node-logs/operator/access-recovery-reports' "missing --access-recovery-reports-dir forwarding"
assert_token "$line" $'\t--access-recovery-install-dir\t/srv/gpm/access-bridge' "missing --access-recovery-install-dir forwarding"
assert_token "$line" $'\t--access-recovery-systemd-unit-file\t/etc/systemd/system/gpm-access-bridge.service' "missing --access-recovery-systemd-unit-file forwarding"
assert_token "$line" $'\t--access-recovery-proxy-kind\tcaddy' "missing --access-recovery-proxy-kind forwarding"
assert_token "$line" $'\t--access-recovery-proxy-config-file\t/etc/caddy/Caddyfile.d/gpm-access-bridge.caddy' "missing --access-recovery-proxy-config-file forwarding"
assert_token "$line" $'\t--access-recovery-trust-store\t.easy-node-logs/operator-trust/recovery-trust.json' "missing --access-recovery-trust-store forwarding"
assert_token "$line" $'\t--access-recovery-mtls-ca\t.easy-node-logs/operator-mtls/ca.pem' "missing --access-recovery-mtls-ca forwarding"
assert_token "$line" $'\t--access-recovery-mtls-client-cert\t.easy-node-logs/operator-mtls/client.pem' "missing --access-recovery-mtls-client-cert forwarding"
assert_token "$line" $'\t--access-recovery-mtls-client-key\t.easy-node-logs/operator-mtls/client.key' "missing --access-recovery-mtls-client-key forwarding"
assert_token "$line" $'\t--include-id\tblockchain_mainnet_activation_refresh_evidence' "missing --include-id forwarding"
assert_token "$line" $'\t--exclude-id\tprofile_default_gate' "missing --exclude-id forwarding"
assert_token "$line" $'\t--include-id-prefix\tblockchain_' "missing --include-id-prefix forwarding"
assert_token "$line" $'\t--exclude-id-prefix\tprofile_' "missing --exclude-id-prefix forwarding"
assert_token "$line" $'\t--include-id-suffix\t_evidence_pack' "missing --include-id-suffix forwarding"
assert_token "$line" $'\t--exclude-id-suffix\t_cycle' "missing --exclude-id-suffix forwarding"
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/roadmap_next_actions_contract' "missing --reports-dir forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/roadmap_next_actions_contract_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--print-summary-json\t1' "missing --print-summary-json forwarding"

if ! grep -F -- 'fake roadmap next actions run:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-next-actions] output + exit semantics contract"
set +e
ROADMAP_NEXT_ACTIONS_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_NEXT_ACTIONS_CAPTURE_FILE="$CAPTURE" \
FAKE_ROADMAP_NEXT_ACTIONS_RUN_RC=7 \
./scripts/easy_node.sh roadmap-next-actions-run --sample-arg boom >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 7 ]]; then
  echo "expected easy_node wrapper to return fake script exit code 7, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake roadmap next actions run: --sample-arg boom' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "easy node roadmap next-actions run integration check ok"
