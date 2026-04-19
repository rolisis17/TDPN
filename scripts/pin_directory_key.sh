#!/usr/bin/env bash
set -euo pipefail

DIRECTORY_URL="${DIRECTORY_URL:-http://127.0.0.1:8081}"
TRUST_FILE="${DIRECTORY_TRUSTED_KEYS_FILE:-data/trusted_directory_keys.txt}"
DIRECTORY_URL="${DIRECTORY_URL%/}"

url_scheme() {
  local url="$1"
  if [[ "$url" != *"://"* ]]; then
    echo ""
    return
  fi
  printf '%s' "${url%%://*}" | tr '[:upper:]' '[:lower:]'
}

url_host() {
  local url="$1"
  local authority rest
  rest="${url#*://}"
  authority="${rest%%/*}"
  if [[ "$authority" == *"@"* ]]; then
    authority="${authority##*@}"
  fi
  if [[ "$authority" =~ ^\[([^]]+)\](:[0-9]+)?$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return
  fi
  printf '%s' "${authority%%:*}"
}

is_loopback_host() {
  local host
  host="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  [[ "$host" == "localhost" || "$host" == "127."* || "$host" == "::1" ]]
}

scheme="$(url_scheme "$DIRECTORY_URL")"
host="$(url_host "$DIRECTORY_URL")"
if [[ -z "$scheme" || -z "$host" ]]; then
  echo "DIRECTORY_URL must be an absolute http(s) URL, got: $DIRECTORY_URL"
  exit 1
fi
if [[ "$scheme" != "http" && "$scheme" != "https" ]]; then
  echo "DIRECTORY_URL scheme must be http or https, got: $scheme"
  exit 1
fi
if [[ "$scheme" == "http" ]] && ! is_loopback_host "$host"; then
  echo "refusing to pin from non-loopback http URL: $DIRECTORY_URL"
  echo "use https:// for non-loopback hosts"
  exit 1
fi

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
