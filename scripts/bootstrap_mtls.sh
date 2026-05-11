#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/bootstrap_mtls.sh [--out-dir DIR] [--public-host HOST] [--san HOST] [--days N] [--rotate-leaf [0|1]] [--rotate-ca [0|1]]

Outputs:
  <out-dir>/ca.crt
  <out-dir>/ca.key
  <out-dir>/node.crt
  <out-dir>/node.key
  <out-dir>/client.crt
  <out-dir>/client.key

Notes:
  - node cert is usable for directory/issuer/entry-exit roles and includes DNS/IP SANs.
  - --public-host/--san values must be bare DNS names or IP addresses, not URLs or host:port strings.
  - client cert is for control-plane clients (client role/admin tooling).
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing dependency: $1"
    exit 2
  fi
}

trim() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  printf '%s' "$v"
}

is_ipv4() {
  local host="$1"
  [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.
  local -a octets=()
  local octet
  read -r -a octets <<<"$host"
  [[ "${#octets[@]}" == "4" ]] || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
}

is_ipv6() {
  local host="$1"
  [[ "$host" == *:* && "$host" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
  [[ "$host" != *:::* ]] || return 1
  [[ "$host" != :* || "$host" == ::* ]] || return 1
  [[ "$host" != *: || "$host" == *:: ]] || return 1

  local without_double="${host//::/}"
  local double_count=$(((${#host} - ${#without_double}) / 2))
  ((double_count <= 1)) || return 1

  local IFS=:
  local -a parts=()
  local part
  local non_empty_parts=0
  read -r -a parts <<<"$host"
  for part in "${parts[@]}"; do
    [[ -z "$part" ]] && continue
    [[ "$part" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    non_empty_parts=$((non_empty_parts + 1))
  done
  if ((double_count == 0)); then
    ((non_empty_parts == 8))
  else
    ((non_empty_parts < 8))
  fi
}

normalize_san_value() {
  local raw="$1"
  local value
  value="$(trim "$raw")"
  if [[ -z "$value" ]]; then
    echo "invalid SAN/public-host: value must not be empty" >&2
    return 1
  fi
  if [[ "$value" == -* ]]; then
    echo "invalid SAN/public-host '$value': value must not look like an option" >&2
    return 1
  fi
  if [[ "$value" =~ [[:space:]] ]]; then
    echo "invalid SAN/public-host '$value': whitespace is not allowed" >&2
    return 1
  fi
  if [[ "$value" == *"://"* || "$value" == */* ]]; then
    echo "invalid SAN/public-host '$value': use a host or IP address, not a URL or path" >&2
    return 1
  fi
  if [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    if ! is_ipv4 "$value"; then
      echo "invalid IPv4 SAN/public-host '$value': octets must be in range 0..255" >&2
      return 1
    fi
    printf '%s' "$value"
    return 0
  fi
  if [[ "$value" == *:* ]]; then
    if ! is_ipv6 "$value"; then
      echo "invalid IPv6 SAN/public-host '$value': use a bare IPv6 address without brackets or port" >&2
      return 1
    fi
    printf '%s' "$value"
    return 0
  fi
  if ((${#value} > 253)); then
    echo "invalid DNS SAN/public-host '$value': host name is too long" >&2
    return 1
  fi
  if [[ "$value" == .* || "$value" == *. || "$value" == *..* ]]; then
    echo "invalid DNS SAN/public-host '$value': DNS labels must not be empty" >&2
    return 1
  fi
  local IFS=.
  local -a labels=()
  local label
  read -r -a labels <<<"$value"
  for label in "${labels[@]}"; do
    if [[ -z "$label" || ${#label} -gt 63 ]]; then
      echo "invalid DNS SAN/public-host '$value': DNS labels must be 1..63 characters" >&2
      return 1
    fi
    if ! [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]; then
      echo "invalid DNS SAN/public-host '$value': DNS labels may only contain letters, digits, and hyphens" >&2
      return 1
    fi
  done
  printf '%s' "$value"
}

add_unique() {
  local value="$1"
  local -n arr_ref="$2"
  local item
  for item in "${arr_ref[@]}"; do
    if [[ "$item" == "$value" ]]; then
      return
    fi
  done
  arr_ref+=("$value")
}

write_san_config() {
  local path="$1"
  shift
  local sans=("$@")
  local dns_i=0
  local ip_i=0
  {
    echo "[req]"
    echo "default_bits = 2048"
    echo "prompt = no"
    echo "default_md = sha256"
    echo "distinguished_name = dn"
    echo "req_extensions = req_ext"
    echo ""
    echo "[dn]"
    echo "CN = privacynode-node"
    echo ""
    echo "[req_ext]"
    echo "subjectAltName = @alt_names"
    echo "extendedKeyUsage = serverAuth"
    echo ""
    echo "[alt_names]"
    local san
    for san in "${sans[@]}"; do
      if is_ipv4 "$san" || is_ipv6 "$san"; then
        ip_i=$((ip_i + 1))
        echo "IP.${ip_i} = ${san}"
      else
        dns_i=$((dns_i + 1))
        echo "DNS.${dns_i} = ${san}"
      fi
    done
  } >"$path"
}

cert_has_san() {
  local cert="$1"
  local san="$2"
  local san_text
  san_text="$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null || true)"
  if [[ -z "$san_text" ]]; then
    return 1
  fi
  local want_a
  local want_b=""
  if is_ipv4 "$san" || is_ipv6 "$san"; then
    want_a="IP Address:${san}"
    want_b="IP:${san}"
  else
    want_a="DNS:${san}"
  fi
  local line
  local entry
  local IFS=,
  local -a entries=()
  while IFS= read -r line; do
    read -r -a entries <<<"$line"
    for entry in "${entries[@]}"; do
      entry="$(trim "$entry")"
      if [[ "$entry" == "$want_a" || ( -n "$want_b" && "$entry" == "$want_b" ) ]]; then
        return 0
      fi
    done
  done <<<"$san_text"
  return 1
}

cert_has_all_sans() {
  local cert="$1"
  shift
  local san
  for san in "$@"; do
    cert_has_san "$cert" "$san" || return 1
  done
}

cert_verifies_with_purpose() {
  local ca="$1"
  local cert="$2"
  local purpose="$3"
  openssl verify -purpose "$purpose" -CAfile "$ca" "$cert" >/dev/null 2>&1
}

out_dir="deploy/tls"
days="365"
rotate_leaf="0"
rotate_ca="0"
declare -a san_hosts=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      out_dir="${2:-}"
      if [[ -z "$(trim "$out_dir")" ]]; then
        echo "missing value for --out-dir"
        exit 2
      fi
      shift 2
      ;;
    --public-host|--san)
      if [[ -z "${2:-}" ]]; then
        echo "missing value for $1"
        exit 2
      fi
      if ! san_value="$(normalize_san_value "${2:-}")"; then
        exit 2
      fi
      add_unique "$san_value" san_hosts
      shift 2
      ;;
    --days)
      days="${2:-}"
      if [[ -z "$days" ]]; then
        echo "missing value for --days"
        exit 2
      fi
      shift 2
      ;;
    --rotate-leaf)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        rotate_leaf="${2:-}"
        shift 2
      else
        rotate_leaf="1"
        shift
      fi
      ;;
    --rotate-ca)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        rotate_ca="${2:-}"
        shift 2
      else
        rotate_ca="1"
        shift
      fi
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

need_cmd openssl
if ! [[ "$days" =~ ^[0-9]+$ ]] || ((days < 1)); then
  echo "--days must be >=1"
  exit 2
fi

umask 077

mkdir -p "$out_dir"
ca_key="$out_dir/ca.key"
ca_crt="$out_dir/ca.crt"
ca_srl="$out_dir/ca.srl"
node_key="$out_dir/node.key"
node_csr="$out_dir/node.csr"
node_crt="$out_dir/node.crt"
client_key="$out_dir/client.key"
client_csr="$out_dir/client.csr"
client_crt="$out_dir/client.crt"
san_cfg="$out_dir/node_san.cnf"
client_cfg="$out_dir/client_ext.cnf"
ca_regenerated="0"

if [[ "$rotate_ca" == "1" ]]; then
  rm -f "$ca_key" "$ca_crt" "$ca_srl"
  rotate_leaf="1"
fi
if [[ "$rotate_leaf" == "1" ]]; then
  rm -f "$node_key" "$node_csr" "$node_crt" "$client_key" "$client_csr" "$client_crt"
fi

if [[ ! -f "$ca_key" || ! -f "$ca_crt" ]]; then
  openssl genrsa -out "$ca_key" 4096 >/dev/null 2>&1
  openssl req -x509 -new -nodes -key "$ca_key" -sha256 -days "$days" \
    -subj "/CN=privacynode-local-ca" \
    -out "$ca_crt" >/dev/null 2>&1
  ca_regenerated="1"
fi
if [[ "$ca_regenerated" == "1" ]]; then
  rm -f "$node_csr" "$node_crt" "$client_csr" "$client_crt"
fi

add_unique "localhost" san_hosts
add_unique "127.0.0.1" san_hosts
add_unique "directory" san_hosts
add_unique "issuer" san_hosts
add_unique "entry-exit" san_hosts
write_san_config "$san_cfg" "${san_hosts[@]}"
if [[ -f "$node_crt" ]] && ! cert_has_all_sans "$node_crt" "${san_hosts[@]}"; then
  echo "mTLS node certificate SANs changed; regenerating node certificate" >&2
  rm -f "$node_csr" "$node_crt"
fi
if [[ -f "$node_crt" ]] && cert_verifies_with_purpose "$ca_crt" "$node_crt" "sslclient"; then
  echo "mTLS node certificate usage changed to server-only; regenerating node certificate" >&2
  rm -f "$node_csr" "$node_crt"
fi

if [[ ! -f "$node_key" || ! -f "$node_crt" ]]; then
  openssl genrsa -out "$node_key" 2048 >/dev/null 2>&1
  openssl req -new -key "$node_key" -out "$node_csr" -config "$san_cfg" >/dev/null 2>&1
  openssl x509 -req -in "$node_csr" -CA "$ca_crt" -CAkey "$ca_key" -CAcreateserial \
    -out "$node_crt" -days "$days" -sha256 -extfile "$san_cfg" -extensions req_ext >/dev/null 2>&1
fi

cat >"$client_cfg" <<'EOF_CFG'
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = privacynode-client

[req_ext]
extendedKeyUsage = clientAuth
EOF_CFG

if [[ ! -f "$client_key" || ! -f "$client_crt" ]]; then
  openssl genrsa -out "$client_key" 2048 >/dev/null 2>&1
  openssl req -new -key "$client_key" -out "$client_csr" -config "$client_cfg" >/dev/null 2>&1
  openssl x509 -req -in "$client_csr" -CA "$ca_crt" -CAkey "$ca_key" -CAcreateserial \
    -out "$client_crt" -days "$days" -sha256 -extfile "$client_cfg" -extensions req_ext >/dev/null 2>&1
fi

chmod 600 "$ca_key" "$node_key" "$client_key" 2>/dev/null || true
chmod 644 "$ca_crt" "$node_crt" "$client_crt" "$san_cfg" "$client_cfg" 2>/dev/null || true
rm -f "$node_csr" "$client_csr"

echo "mTLS material ready:"
echo "  out_dir: $out_dir"
echo "  ca:      $ca_crt"
echo "  node:    $node_crt (key: $node_key)"
echo "  client:  $client_crt (key: $client_key)"
