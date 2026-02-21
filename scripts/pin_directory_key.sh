#!/usr/bin/env bash
set -euo pipefail

DIRECTORY_URL="${DIRECTORY_URL:-http://127.0.0.1:8081}"
TRUST_FILE="${DIRECTORY_TRUSTED_KEYS_FILE:-data/trusted_directory_keys.txt}"

key=$(curl -sS "$DIRECTORY_URL/v1/pubkey" | sed -n 's/.*"pub_key":"\([^"]*\)".*/\1/p')
if [[ -z "$key" ]]; then
  echo "failed to fetch directory pubkey from $DIRECTORY_URL"
  exit 1
fi

mkdir -p "$(dirname "$TRUST_FILE")"
touch "$TRUST_FILE"
if rg -qx "$key" "$TRUST_FILE"; then
  echo "key already pinned in $TRUST_FILE"
  exit 0
fi

echo "$key" >> "$TRUST_FILE"
echo "pinned key to $TRUST_FILE"
