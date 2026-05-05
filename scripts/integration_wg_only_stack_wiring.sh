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

echo "[wg-only-stack-wiring] stack-local trust file wiring"
check_pattern 'EASY_NODE_WG_ONLY_STACK_KEY_DIR' \
  "wg-only stack wiring missing overrideable private key directory"
check_pattern 'key_dir="\$DEPLOY_DIR/data/wg_only"' \
  "wg-only stack wiring missing repo-local key directory fallback"
check_pattern 'XDG_STATE_HOME.*privacynode/wg_only' \
  "wg-only stack wiring missing Windows-mount state key directory fallback"
check_pattern 'directory_url="http://localhost:\$\{dir_port\}"' \
  "wg-only stack wiring missing strict-safe localhost directory URL"
check_pattern 'issuer_url="http://localhost:\$\{issuer_port\}"' \
  "wg-only stack wiring missing strict-safe localhost issuer URL"
check_pattern 'wg_only_trust_file="\$key_dir/trusted_directory_keys_\$\{base_port\}\.txt"' \
  "wg-only stack wiring missing stack-local client trust file path"
check_pattern 'entry_directory_trust_file="\$key_dir/entry_trusted_directory_keys_\$\{base_port\}\.txt"' \
  "wg-only stack wiring missing stack-local entry trust file path"
check_pattern '"DIRECTORY_TRUSTED_KEYS_FILE=\$\{wg_only_trust_file\}"' \
  "wg-only stack wiring missing DIRECTORY_TRUSTED_KEYS_FILE env export"
check_pattern '"ENTRY_DIRECTORY_TRUSTED_KEYS_FILE=\$\{entry_directory_trust_file\}"' \
  "wg-only stack wiring missing ENTRY_DIRECTORY_TRUSTED_KEYS_FILE env export"
check_pattern 'directory_trust_tofu="0"' \
  "wg-only stack wiring missing strict pinned directory trust switch"
check_pattern 'entry_directory_trust_tofu="0"' \
  "wg-only stack wiring missing strict pinned entry-directory trust switch"
check_pattern '"ENTRY_BETA_STRICT=0"' \
  "wg-only stack wiring must keep local loopback entry out of beta strict route/middle enforcement"
check_pattern '"DIRECTORY_TRUST_TOFU=\$\{directory_trust_tofu\}"' \
  "wg-only stack wiring missing DIRECTORY_TRUST_TOFU env export"
check_pattern '"ENTRY_DIRECTORY_TRUST_TOFU=\$\{entry_directory_trust_tofu\}"' \
  "wg-only stack wiring missing ENTRY_DIRECTORY_TRUST_TOFU env export"
check_pattern 'ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE=\$\{entry_route_assertion_key_file\}' \
  "wg-only stack wiring missing strict entry route assertion key file"
check_pattern 'EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS=\$\{entry_route_assertion_pubkey\}' \
  "wg-only stack wiring missing strict exit route assertion trust"
check_pattern 'EXIT_RELAY_ID=exit-wg-only-\$\{base_port\}' \
  "wg-only stack wiring missing strict exit relay id"
check_pattern '"ENTRY_OPERATOR_ID=op-entry"' \
  "wg-only stack wiring missing explicit entry operator id"
check_pattern '"EXIT_OPERATOR_ID=op-exit"' \
  "wg-only stack wiring missing explicit exit operator id"
check_pattern 'client wireguard runtime ready:|client wg-kernel proxy listening:' \
  "wg-only stack selftest missing proxy-ready log recognition"
check_pattern 'beta_strict=false' \
  "wg-only stack selftest missing non-strict live-WG log recognition"
check_pattern 'rm -f "\$wg_only_trust_file" "\$entry_directory_trust_file"' \
  "wg-only stack wiring missing trust file reset on forced cleanup"
check_pattern 'WG_ONLY_DIRECTORY_TRUST_FILE=\$wg_only_trust_file' \
  "wg-only stack state missing directory trust file record"
check_pattern 'WG_ONLY_ENTRY_DIRECTORY_TRUST_FILE=\$entry_directory_trust_file' \
  "wg-only stack state missing entry directory trust file record"
check_pattern 'WG_ONLY_KEY_DIR=\$key_dir' \
  "wg-only stack state missing key directory record"
check_pattern 'WG_ONLY_CLIENT_WG_PRIVATE_KEY_PATH=\$client_key_file' \
  "wg-only stack state missing client WireGuard key record"
check_pattern 'WG_ONLY_CLIENT_WG_INTERFACE=\$client_iface' \
  "wg-only stack state missing client WireGuard interface record"
check_pattern 'WG_ONLY_CLIENT_WG_PROXY_ADDR=127\.0\.0\.1:\$\{proxy_port\}' \
  "wg-only stack state missing client WireGuard proxy record"
check_pattern 'WG_ONLY_CLIENT_STARTUP_SYNC_TIMEOUT_SEC=8' \
  "wg-only stack state missing client startup sync timeout record"

echo "wg-only stack wiring integration check ok"
