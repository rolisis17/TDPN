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
  [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_ipv6() {
  local host="$1"
  [[ "$host" == *:* ]]
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
    echo "extendedKeyUsage = serverAuth,clientAuth"
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

out_dir="deploy/tls"
days="365"
rotate_leaf="0"
rotate_ca="0"
declare -a san_hosts=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      out_dir="${2:-}"
      shift 2
      ;;
    --public-host|--san)
      if [[ -z "${2:-}" ]]; then
        echo "missing value for $1"
        exit 2
      fi
      add_unique "$(trim "${2:-}")" san_hosts
      shift 2
      ;;
    --days)
      days="${2:-}"
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
fi

add_unique "localhost" san_hosts
add_unique "127.0.0.1" san_hosts
add_unique "directory" san_hosts
add_unique "issuer" san_hosts
add_unique "entry-exit" san_hosts
write_san_config "$san_cfg" "${san_hosts[@]}"

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
