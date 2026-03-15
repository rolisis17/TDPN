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
check_pattern 'wg_only_trust_file="\$key_dir/trusted_directory_keys_\$\{base_port\}\.txt"' \
  "wg-only stack wiring missing stack-local client trust file path"
check_pattern 'entry_directory_trust_file="\$key_dir/entry_trusted_directory_keys_\$\{base_port\}\.txt"' \
  "wg-only stack wiring missing stack-local entry trust file path"
check_pattern '"DIRECTORY_TRUSTED_KEYS_FILE=\$\{wg_only_trust_file\}"' \
  "wg-only stack wiring missing DIRECTORY_TRUSTED_KEYS_FILE env export"
check_pattern '"ENTRY_DIRECTORY_TRUSTED_KEYS_FILE=\$\{entry_directory_trust_file\}"' \
  "wg-only stack wiring missing ENTRY_DIRECTORY_TRUSTED_KEYS_FILE env export"
check_pattern '"DIRECTORY_TRUST_TOFU=1"' \
  "wg-only stack wiring missing explicit DIRECTORY_TRUST_TOFU=1"
check_pattern '"ENTRY_DIRECTORY_TRUST_TOFU=1"' \
  "wg-only stack wiring missing explicit ENTRY_DIRECTORY_TRUST_TOFU=1"
check_pattern 'rm -f "\$wg_only_trust_file" "\$entry_directory_trust_file"' \
  "wg-only stack wiring missing trust file reset on forced cleanup"
check_pattern 'WG_ONLY_DIRECTORY_TRUST_FILE=\$wg_only_trust_file' \
  "wg-only stack state missing directory trust file record"
check_pattern 'WG_ONLY_ENTRY_DIRECTORY_TRUST_FILE=\$entry_directory_trust_file' \
  "wg-only stack state missing entry directory trust file record"

echo "wg-only stack wiring integration check ok"
