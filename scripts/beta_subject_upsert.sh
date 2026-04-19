#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/beta_subject_upsert.sh \
    --issuer-url URL \
    [--admin-token TOKEN] \
    [--admin-token-file FILE] \
    [--admin-key-file FILE --admin-key-id ID] \
    --subject ID \
    [--kind client|relay-exit] \
    [--tier 1|2|3] \
    [--reputation 0..1] \
    [--bond FLOAT] \
    [--stake FLOAT] \
    [--mtls-ca-file FILE] \
    [--mtls-cert-file FILE] \
    [--mtls-key-file FILE]

Purpose:
  Upsert one issuer subject profile for closed-beta allowlist control.
USAGE
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing dependency: $1"
    exit 2
  fi
}

is_https_url() {
  local raw="$1"
  [[ "$raw" == https://* ]]
}

url_host() {
  local raw="$1"
  local authority="${raw#*://}"
  authority="${authority%%/*}"
  authority="${authority##*@}"
  if [[ "$authority" == \[* ]]; then
    authority="${authority#\[}"
    authority="${authority%%]*}"
    printf '%s' "$authority"
    return
  fi
  printf '%s' "${authority%%:*}"
}

is_loopback_host() {
  local host
  host="$(trim "$1")"
  host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
  [[ "$host" == "localhost" || "$host" == "127.0.0.1" || "$host" == "::1" ]]
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

ensure_url_scheme() {
  local raw="$1"
  local scheme="$2"
  raw="$(trim "$raw")"
  if [[ "$raw" == "$scheme://"* ]]; then
    echo "$raw"
    return
  fi
  if [[ "$raw" == http://* || "$raw" == https://* ]]; then
    echo "${scheme}://${raw#*://}"
    return
  fi
  echo "${scheme}://${raw}"
}

issuer_url="${ISSUER_URL:-http://127.0.0.1:8082}"
admin_token="${ISSUER_ADMIN_TOKEN:-}"
admin_token_file="${ISSUER_ADMIN_TOKEN_FILE:-}"
admin_key_file="${ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL:-}"
admin_key_id="${ISSUER_ADMIN_SIGNING_KEY_ID:-}"
subject=""
kind="client"
tier="1"
reputation="0"
bond="0"
stake="0"
mtls_ca_file="${EASY_NODE_MTLS_CA_FILE_LOCAL:-}"
mtls_cert_file="${EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL:-}"
mtls_key_file="${EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --issuer-url)
      issuer_url="${2:-}"
      shift 2
      ;;
    --admin-token)
      admin_token="${2:-}"
      shift 2
      ;;
    --admin-token-file)
      admin_token_file="${2:-}"
      shift 2
      ;;
    --admin-key-file)
      admin_key_file="${2:-}"
      shift 2
      ;;
    --admin-key-id)
      admin_key_id="${2:-}"
      shift 2
      ;;
    --subject)
      subject="${2:-}"
      shift 2
      ;;
    --kind)
      kind="${2:-}"
      shift 2
      ;;
    --tier)
      tier="${2:-}"
      shift 2
      ;;
    --reputation)
      reputation="${2:-}"
      shift 2
      ;;
    --bond)
      bond="${2:-}"
      shift 2
      ;;
    --stake)
      stake="${2:-}"
      shift 2
      ;;
    --mtls-ca-file)
      mtls_ca_file="${2:-}"
      shift 2
      ;;
    --mtls-cert-file)
      mtls_cert_file="${2:-}"
      shift 2
      ;;
    --mtls-key-file)
      mtls_key_file="${2:-}"
      shift 2
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

issuer_url="$(trim "${issuer_url%/}")"
if [[ "$issuer_url" != http://* && "$issuer_url" != https://* ]]; then
  host_name="$(url_host "https://${issuer_url}")"
  if is_loopback_host "$host_name"; then
    issuer_url="$(ensure_url_scheme "$issuer_url" "http")"
  else
    issuer_url="$(ensure_url_scheme "$issuer_url" "https")"
  fi
fi
if [[ "$issuer_url" == http://* ]]; then
  host_name="$(url_host "$issuer_url")"
  if ! is_loopback_host "$host_name"; then
    issuer_url="${issuer_url/http:\/\//https://}"
  fi
fi

if [[ -z "$subject" ]]; then
  echo "--subject is required"
  usage
  exit 2
fi
if [[ -n "$admin_token" && -n "$admin_token_file" ]]; then
  echo "use either --admin-token OR --admin-token-file"
  exit 2
fi
if [[ -n "$admin_token_file" ]]; then
  if [[ ! -f "$admin_token_file" ]]; then
    echo "admin token file not found: $admin_token_file"
    exit 2
  fi
  admin_token="$(tr -d '\r' <"$admin_token_file" | sed -n '1p' | xargs)"
fi
if [[ -n "$admin_token" && ( -n "$admin_key_file" || -n "$admin_key_id" ) ]]; then
  echo "use either --admin-token/--admin-token-file OR --admin-key-file/--admin-key-id"
  exit 2
fi
if [[ -z "$admin_token" ]]; then
  if [[ -z "$admin_key_file" || -z "$admin_key_id" ]]; then
    echo "admin auth is required: provide --admin-token, --admin-token-file, or --admin-key-file + --admin-key-id"
    usage
    exit 2
  fi
fi
if [[ "$kind" != "client" && "$kind" != "relay-exit" ]]; then
  echo "--kind must be client or relay-exit"
  exit 2
fi
if [[ "$tier" != "1" && "$tier" != "2" && "$tier" != "3" ]]; then
  echo "--tier must be 1, 2, or 3"
  exit 2
fi

if is_https_url "$issuer_url"; then
  host_name="$(url_host "$issuer_url")"
  if is_loopback_host "$host_name"; then
    if [[ -z "$mtls_ca_file" ]]; then
      mtls_ca_file="$ROOT_DIR/deploy/tls/ca.crt"
    fi
    if [[ -z "$mtls_cert_file" ]]; then
      mtls_cert_file="$ROOT_DIR/deploy/tls/client.crt"
    fi
    if [[ -z "$mtls_key_file" ]]; then
      mtls_key_file="$ROOT_DIR/deploy/tls/client.key"
    fi
  else
    if [[ -z "$mtls_ca_file" || -z "$mtls_cert_file" || -z "$mtls_key_file" ]]; then
      echo "non-loopback https issuer requires explicit --mtls-ca-file, --mtls-cert-file, and --mtls-key-file"
      exit 2
    fi
  fi
fi

need_cmd curl
need_cmd jq
need_cmd go

payload="$(cat <<EOF
{"subject":"${subject}","kind":"${kind}","tier":${tier},"reputation":${reputation},"bond":${bond},"stake":${stake}}
EOF
)"

request_upsert="${issuer_url}/v1/admin/subject/upsert"
request_get="${issuer_url}/v1/admin/subject/get?subject=${subject}"

build_header_config_file() {
  local method="$1"
  local url="$2"
  local body_file="$3"
  local out_var="$4"
  local cfg_file
  cfg_file="$(mktemp)"
  chmod 600 "$cfg_file"
  if [[ -n "$admin_token" ]]; then
    printf 'header = "X-Admin-Token: %s"\n' "$admin_token" >>"$cfg_file"
  else
    local sign_json
    local -a sign_cmd=(
      go run ./cmd/adminsig sign
      --private-key-file "$admin_key_file"
      --key-id "$admin_key_id"
      --method "$method"
      --url "$url"
    )
    if [[ -n "$body_file" ]]; then
      sign_cmd+=(--body-file "$body_file")
    fi
    sign_json="$(
      cd "$ROOT_DIR"
      "${sign_cmd[@]}"
    )"
    local h_key_id h_ts h_nonce h_sig
    h_key_id="$(printf '%s\n' "$sign_json" | jq -r '.headers["X-Admin-Key-Id"]')"
    h_ts="$(printf '%s\n' "$sign_json" | jq -r '.headers["X-Admin-Timestamp"]')"
    h_nonce="$(printf '%s\n' "$sign_json" | jq -r '.headers["X-Admin-Nonce"]')"
    h_sig="$(printf '%s\n' "$sign_json" | jq -r '.headers["X-Admin-Signature"]')"
    if [[ -z "$h_key_id" || -z "$h_ts" || -z "$h_nonce" || -z "$h_sig" || "$h_key_id" == "null" || "$h_sig" == "null" ]]; then
      echo "failed to generate signed admin headers" >&2
      exit 1
    fi
    printf 'header = "X-Admin-Key-Id: %s"\n' "$h_key_id" >>"$cfg_file"
    printf 'header = "X-Admin-Timestamp: %s"\n' "$h_ts" >>"$cfg_file"
    printf 'header = "X-Admin-Nonce: %s"\n' "$h_nonce" >>"$cfg_file"
    printf 'header = "X-Admin-Signature: %s"\n' "$h_sig" >>"$cfg_file"
  fi
  local -n _cfg_out="$out_var"
  _cfg_out="$cfg_file"
}

build_tls_args() {
  local out_var="$1"
  local -a out=()
  if is_https_url "$issuer_url"; then
    if [[ -n "$mtls_ca_file" ]]; then
      out+=(--cacert "$mtls_ca_file")
    fi
    if [[ -n "$mtls_cert_file" && -n "$mtls_key_file" ]]; then
      out+=(--cert "$mtls_cert_file" --key "$mtls_key_file")
    fi
  fi
  local -n _tls_out="$out_var"
  _tls_out=("${out[@]}")
}

tmp_body_file="$(mktemp)"
printf '%s' "$payload" >"$tmp_body_file"
declare -a tls_args
local_upsert_header_cfg=""
local_get_header_cfg=""
build_header_config_file "POST" "$request_upsert" "$tmp_body_file" local_upsert_header_cfg
build_header_config_file "GET" "$request_get" "" local_get_header_cfg
trap 'rm -f "$tmp_body_file" "$local_upsert_header_cfg" "$local_get_header_cfg"' EXIT
build_tls_args tls_args

echo "upserting subject profile: subject=${subject} kind=${kind} tier=${tier}"
curl -fsS -X POST "$request_upsert" \
  --connect-timeout 4 \
  --max-time 12 \
  "${tls_args[@]}" \
  --config "$local_upsert_header_cfg" \
  -H "Content-Type: application/json" \
  --data "$payload"
echo
echo "reading back subject profile:"
curl -fsS "$request_get" \
  --connect-timeout 4 \
  --max-time 12 \
  "${tls_args[@]}" \
  --config "$local_get_header_cfg"
echo
