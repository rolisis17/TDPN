#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET="scripts/easy_node.sh"

for cmd in rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

if [[ ! -f "$TARGET" ]]; then
  echo "missing script: $TARGET"
  exit 1
fi

check_pattern() {
  local pattern="$1"
  local message="$2"
  if ! rg -q -- "$pattern" "$TARGET"; then
    echo "$message"
    exit 1
  fi
}

echo "[client-vpn-trust-scope] helper wiring"
check_pattern '^default_client_vpn_trust_file_for_directory_urls\(\)' \
  "missing default_client_vpn_trust_file_for_directory_urls helper"
check_pattern '^print_client_vpn_trust_mismatch_hint\(\)' \
  "missing print_client_vpn_trust_mismatch_hint helper"
check_pattern '^seed_client_vpn_trust_file_if_empty\(\)' \
  "missing seed_client_vpn_trust_file_if_empty helper"

echo "[client-vpn-trust-scope] client-vpn-up trust scope behavior"
check_pattern 'local trust_scope_mode="\$\{EASY_NODE_CLIENT_VPN_TRUST_SCOPE:-scoped\}"' \
  "client-vpn-up missing EASY_NODE_CLIENT_VPN_TRUST_SCOPE default wiring"
check_pattern 'client-vpn-up requires EASY_NODE_CLIENT_VPN_TRUST_SCOPE to be one of: scoped, global' \
  "client-vpn-up missing trust scope validation message"
check_pattern 'trusted_keys_file="\$\(default_client_vpn_trust_file_for_directory_urls "\$directory_urls" "\$trust_scope_mode"\)"' \
  "client-vpn-up missing scoped trust-file resolution"
check_pattern 'seed_client_vpn_trust_file_if_empty "\$trusted_keys_file" "\$directory_urls"' \
  "client-vpn-up missing first-run trust seed for multi-directory strict mode"
check_pattern 'CLIENT_VPN_TRUST_SCOPE=\$trust_scope_mode' \
  "client-vpn-up state file missing trust scope record"
check_pattern 'echo "  trust_scope: \$trust_scope_mode"' \
  "client-vpn-up output missing trust scope"
check_pattern 'print_client_vpn_trust_mismatch_hint "\$log_file" "\$trusted_keys_file" "\$trust_scope_mode"' \
  "client-vpn-up missing trust mismatch hint invocation"

echo "[client-vpn-trust-scope] client-vpn-status visibility"
check_pattern 'trust_scope="\$\(identity_value "\$state_file" "CLIENT_VPN_TRUST_SCOPE"\)"' \
  "client-vpn-status missing trust scope state read"
check_pattern 'echo "  trust_scope: \$\{trust_scope:-unknown\}"' \
  "client-vpn-status missing trust scope output"

echo "[client-vpn-trust-scope] trust mismatch diagnostics"
check_pattern 'directory trust pin mismatch detected\.' \
  "trust mismatch helper missing key mismatch diagnostic message"
check_pattern 'EASY_NODE_CLIENT_VPN_TRUST_SCOPE=scoped' \
  "trust mismatch helper missing scoped-mode remediation hint"

echo "client-vpn trust scope wiring integration check ok"
