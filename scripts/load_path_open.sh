#!/usr/bin/env bash
set -euo pipefail

ENTRY_URL="${ENTRY_URL:-http://127.0.0.1:8083}"
TOKEN="${TOKEN:-}"
TOKEN_PROOF="${TOKEN_PROOF:-}"
TOKEN_PROOF_NONCE="${TOKEN_PROOF_NONCE:-}"
EXIT_ID="${EXIT_ID:-exit-local-1}"
CLIENT_PUB="${CLIENT_WG_PUBLIC_KEY:-}"
REQS="${REQS:-200}"
CONCURRENCY="${CONCURRENCY:-20}"

if ! [[ "$REQS" =~ ^[1-9][0-9]*$ ]] || ((REQS > 10000)); then
  echo "REQS must be an integer in 1..10000"
  exit 1
fi
if ! [[ "$CONCURRENCY" =~ ^[1-9][0-9]*$ ]] || ((CONCURRENCY > 256)); then
  echo "CONCURRENCY must be an integer in 1..256"
  exit 1
fi
if ((CONCURRENCY > REQS)); then
  CONCURRENCY="$REQS"
fi

extract_host_from_url() {
  local value="$1"
  value="${value#http://}"
  value="${value#https://}"
  value="${value%%/*}"
  if [[ "$value" == \[*\]* ]]; then
    printf '%s\n' "${value%%]*}]"
    return
  fi
  local colon_count
  colon_count="$(printf '%s' "$value" | awk -F: '{print NF-1}')"
  if [[ "$colon_count" == "1" ]]; then
    local maybe_port="${value##*:}"
    if [[ "$maybe_port" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "${value%:*}"
      return
    fi
  fi
  printf '%s\n' "$value"
}

host_is_loopback() {
  local host="$1"
  host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
  host="${host#[}"
  host="${host%]}"
  case "$host" in
    "localhost"|"ip6-localhost"|"::1"|127.*|::ffff:127.*)
      return 0
      ;;
  esac
  return 1
}

host_resolves_to_loopback_only() {
  local host="$1"
  local host_ips ip resolved_any
  host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
  host="${host#[}"
  host="${host%]}"
  case "$host" in
    ""|localhost|ip6-localhost|::1|127.*|::|0.0.0.0)
      return 0
      ;;
  esac
  if host_is_loopback "$host"; then
    return 0
  fi
  if ! command -v getent >/dev/null 2>&1; then
    return 1
  fi
  host_ips="$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u || true)"
  if [[ -z "$host_ips" ]]; then
    return 1
  fi
  resolved_any=0
  while IFS= read -r ip; do
    ip="$(printf '%s' "$ip" | tr '[:upper:]' '[:lower:]')"
    if [[ -z "$ip" ]]; then
      continue
    fi
    resolved_any=1
    if ! host_is_loopback "$ip"; then
      return 1
    fi
  done <<<"$host_ips"
  if [[ "$resolved_any" -ne 1 ]]; then
    return 1
  fi
  return 0
}

require_secure_entry_url() {
  local raw="$1"
  if [[ "$raw" == https://* ]]; then
    return 0
  fi
  if [[ "$raw" == http://* ]] && host_resolves_to_loopback_only "$(extract_host_from_url "$raw")"; then
    return 0
  fi
  echo "ENTRY_URL must use https:// for remote hosts (http:// is allowed only for loopback)"
  return 1
}

if [[ -z "$TOKEN" ]]; then
  echo "TOKEN is required"
  exit 1
fi
if [[ -z "$TOKEN_PROOF" ]]; then
  echo "TOKEN_PROOF is required"
  exit 1
fi
if [[ -z "$TOKEN_PROOF_NONCE" ]]; then
  echo "TOKEN_PROOF_NONCE is required"
  exit 1
fi
if [[ -z "$CLIENT_PUB" ]]; then
  echo "CLIENT_WG_PUBLIC_KEY is required"
  exit 1
fi
if ! require_secure_entry_url "$ENTRY_URL"; then
  exit 1
fi

old_umask="$(umask)"
umask 077
TMP_DIR="$(mktemp -d /tmp/path_open_load.XXXXXX)"
umask "$old_umask"
PAYLOAD_FILE="${TMP_DIR}/path_open_payload.json"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat >"$PAYLOAD_FILE" <<JSON
{"exit_id":"$EXIT_ID","token":"$TOKEN","token_proof":"$TOKEN_PROOF","token_proof_nonce":"$TOKEN_PROOF_NONCE","client_inner_pub":"$CLIENT_PUB","transport":"wireguard-udp","requested_mtu":1280,"requested_region":"local"}
JSON
chmod 600 "$PAYLOAD_FILE"

export ENTRY_URL PAYLOAD_FILE TMP_DIR

status_codes_file="${TMP_DIR}/path_open_status_codes.txt"
seq "$REQS" | xargs -P "$CONCURRENCY" -I{} \
  curl -sS --output "${TMP_DIR}/path_open_{}.json" --write-out "%{http_code}\n" \
    -H "Content-Type: application/json" \
    -X POST "$ENTRY_URL/v1/path/open" \
    --data @"$PAYLOAD_FILE" >"$status_codes_file"

ok="$(rg -c '^200$' "$status_codes_file" 2>/dev/null || printf '%s' "0")"
echo "completed requests=$REQS http200=$ok"
