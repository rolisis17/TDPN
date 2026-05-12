#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_mtls_bundle_verify.sh --bundle-dir DIR --host HOST [options]

Options:
  --bundle-dir DIR            Host-specific server bundle directory.
  --host HOST                 Expected DNS name or IP covered by node.crt SAN. Repeatable.
  --public-host HOST          Alias for --host.
  --days-min N                Minimum certificate validity window. Default: 14.
  --allow-ca-key 0|1          Allow ca.key inside the server bundle. Default: 0.
  --require-client-material 0|1
                              Require and verify client.crt/client.key in the bundle.
                              Default: 0.
  --summary-json PATH         Summary JSON path. Default: <bundle-dir>/prod_mtls_bundle_verify_summary.json.
  --print-summary-json 0|1    Print summary JSON after writing it. Default: 0.

Notes:
  This command is non-disruptive. It only verifies staged mTLS material and is
  designed for host-specific server bundles that contain ca.crt, node.crt, and
  node.key, but intentionally do not contain ca.key.
USAGE
}

trim() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  printf '%s' "$v"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing dependency: $1" >&2
    exit 2
  fi
}

normalize_bool_01() {
  local value
  value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$value" in
    0|false|no|n)
      printf '0'
      ;;
    1|true|yes|y)
      printf '1'
      ;;
    *)
      return 1
      ;;
  esac
}

json_bool() {
  if [[ "${1:-0}" == "1" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

make_abs_path() {
  local path="$1"
  if [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s/%s' "$ROOT_DIR" "$path"
  fi
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

normalize_host_value() {
  local raw="$1"
  local value
  value="$(trim "$raw")"
  if [[ -z "$value" ]]; then
    echo "invalid mTLS host: value must not be empty" >&2
    return 1
  fi
  if [[ "$value" == -* ]]; then
    echo "invalid mTLS host '$value': value must not look like an option" >&2
    return 1
  fi
  if [[ "$value" =~ [[:space:]] ]]; then
    echo "invalid mTLS host '$value': whitespace is not allowed" >&2
    return 1
  fi
  if [[ "$value" == *"://"* || "$value" == */* ]]; then
    echo "invalid mTLS host '$value': use a bare host or IP address, not a URL or path" >&2
    return 1
  fi
  if [[ "$value" == \[* || "$value" == *\] ]]; then
    echo "invalid mTLS host '$value': use a bare IPv6 address without brackets or port" >&2
    return 1
  fi
  if [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    if ! is_ipv4 "$value"; then
      echo "invalid IPv4 mTLS host '$value': octets must be in range 0..255" >&2
      return 1
    fi
    printf '%s' "$value"
    return 0
  fi
  if [[ "$value" == *:* ]]; then
    local maybe_port="${value##*:}"
    local host_part="${value%:*}"
    if [[ "$host_part" != *:* && "$maybe_port" =~ ^[0-9]+$ ]]; then
      echo "invalid mTLS host '$value': use a bare host or IP address, not host:port" >&2
      return 1
    fi
  fi
  if [[ "$value" == *:* ]]; then
    if ! is_ipv6 "$value"; then
      echo "invalid IPv6 mTLS host '$value': use a bare IPv6 address without brackets or port" >&2
      return 1
    fi
    printf '%s' "$value"
    return 0
  fi
  if ((${#value} > 253)); then
    echo "invalid DNS mTLS host '$value': host name is too long" >&2
    return 1
  fi
  if [[ "$value" == .* || "$value" == *. || "$value" == *..* ]]; then
    echo "invalid DNS mTLS host '$value': DNS labels must not be empty" >&2
    return 1
  fi
  local IFS=.
  local -a labels=()
  local label
  read -r -a labels <<<"$value"
  for label in "${labels[@]}"; do
    if [[ -z "$label" || ${#label} -gt 63 ]]; then
      echo "invalid DNS mTLS host '$value': DNS labels must be 1..63 characters" >&2
      return 1
    fi
    if ! [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]; then
      echo "invalid DNS mTLS host '$value': DNS labels may only contain letters, digits, and hyphens" >&2
      return 1
    fi
  done
  printf '%s' "$value"
}

json_array_from_values() {
  if (($# == 0)); then
    printf '[]'
    return
  fi
  printf '%s\n' "$@" | jq -R . | jq -s .
}

cert_public_key_fingerprint() {
  local cert_file="$1"
  local fingerprint
  fingerprint="$(openssl x509 -in "$cert_file" -pubkey -noout 2>/dev/null |
    openssl pkey -pubin -outform DER 2>/dev/null |
    openssl dgst -sha256 -r 2>/dev/null |
    awk '{print $1}')" || return 1
  [[ -n "$fingerprint" ]] || return 1
  echo "$fingerprint"
}

cert_identity_fingerprint() {
  local cert_file="$1"
  local fingerprint
  fingerprint="$(openssl x509 -in "$cert_file" -outform DER 2>/dev/null |
    openssl dgst -sha256 -r 2>/dev/null |
    awk '{print $1}')" || return 1
  [[ -n "$fingerprint" ]] || return 1
  echo "$fingerprint"
}

private_key_public_fingerprint() {
  local key_file="$1"
  local fingerprint
  fingerprint="$(openssl pkey -in "$key_file" -pubout -outform DER 2>/dev/null |
    openssl dgst -sha256 -r 2>/dev/null |
    awk '{print $1}')" || return 1
  [[ -n "$fingerprint" ]] || return 1
  echo "$fingerprint"
}

cert_matches_private_key() {
  local cert_file="$1"
  local key_file="$2"
  local cert_fp key_fp
  cert_fp="$(cert_public_key_fingerprint "$cert_file")" || return 1
  key_fp="$(private_key_public_fingerprint "$key_file")" || return 1
  [[ "$cert_fp" == "$key_fp" ]]
}

canonical_file_identity() {
  local file="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$file" 2>/dev/null && return 0
  fi
  if command -v readlink >/dev/null 2>&1; then
    readlink -f "$file" 2>/dev/null && return 0
  fi
  return 1
}

files_are_same_path() {
  local left="$1"
  local right="$2"
  local left_identity right_identity
  left_identity="$(canonical_file_identity "$left")" || return 1
  right_identity="$(canonical_file_identity "$right")" || return 1
  [[ "$left_identity" == "$right_identity" ]]
}

cert_verifies_with_ca() {
  local ca_file="$1"
  local cert_file="$2"
  openssl verify -CAfile "$ca_file" "$cert_file" >/dev/null 2>&1
}

cert_verifies_with_purpose() {
  local ca_file="$1"
  local cert_file="$2"
  local purpose="$3"
  openssl verify -CAfile "$ca_file" -purpose "$purpose" "$cert_file" >/dev/null 2>&1
}

cert_valid_for_host() {
  local ca_file="$1"
  local cert_file="$2"
  local host="$3"
  if is_ipv4 "$host" || is_ipv6 "$host"; then
    openssl verify -CAfile "$ca_file" -verify_ip "$host" "$cert_file" >/dev/null 2>&1
  else
    openssl verify -CAfile "$ca_file" -verify_hostname "$host" "$cert_file" >/dev/null 2>&1
  fi
}

cert_not_expiring() {
  local cert_file="$1"
  local days_min="$2"
  local seconds
  seconds=$((10#$days_min * 86400))
  openssl x509 -checkend "$seconds" -noout -in "$cert_file" >/dev/null 2>&1
}

bundle_dir=""
days_min="14"
allow_ca_key="0"
require_client_material="0"
summary_json=""
print_summary_json="0"
declare -a expected_hosts=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      bundle_dir="${2:-}"
      if [[ -z "$(trim "$bundle_dir")" ]]; then
        echo "missing value for --bundle-dir" >&2
        exit 2
      fi
      shift 2
      ;;
    --host|--public-host)
      if [[ -z "${2:-}" ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      host_value="$(normalize_host_value "$2")" || exit 2
      expected_hosts+=("$host_value")
      shift 2
      ;;
    --days-min)
      days_min="${2:-}"
      if ! [[ "$days_min" =~ ^[0-9]+$ ]] || ((days_min < 1)); then
        echo "prod-mtls-bundle-verify requires --days-min >= 1" >&2
        exit 2
      fi
      shift 2
      ;;
    --allow-ca-key)
      if ! allow_ca_key="$(normalize_bool_01 "${2:-}")"; then
        echo "prod-mtls-bundle-verify requires --allow-ca-key to be 0 or 1" >&2
        exit 2
      fi
      shift 2
      ;;
    --require-client-material)
      if ! require_client_material="$(normalize_bool_01 "${2:-}")"; then
        echo "prod-mtls-bundle-verify requires --require-client-material to be 0 or 1" >&2
        exit 2
      fi
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      if [[ -z "$(trim "$summary_json")" ]]; then
        echo "missing value for --summary-json" >&2
        exit 2
      fi
      shift 2
      ;;
    --print-summary-json)
      if ! print_summary_json="$(normalize_bool_01 "${2:-}")"; then
        echo "prod-mtls-bundle-verify requires --print-summary-json to be 0 or 1" >&2
        exit 2
      fi
      shift 2
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg for prod-mtls-bundle-verify: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$bundle_dir" ]]; then
  echo "prod-mtls-bundle-verify requires --bundle-dir" >&2
  exit 2
fi
if ((${#expected_hosts[@]} == 0)); then
  echo "prod-mtls-bundle-verify requires at least one --host" >&2
  exit 2
fi

need_cmd jq
need_cmd openssl

bundle_dir="$(make_abs_path "$bundle_dir")"
bundle_dir_exists_initial="0"
if [[ -d "$bundle_dir" ]]; then
  bundle_dir_exists_initial="1"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$bundle_dir/prod_mtls_bundle_verify_summary.json"
else
  summary_json="$(make_abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

ca_file="$bundle_dir/ca.crt"
cert_file="$bundle_dir/node.crt"
key_file="$bundle_dir/node.key"
client_cert_file="$bundle_dir/client.crt"
client_key_file="$bundle_dir/client.key"
ca_key_file="$bundle_dir/ca.key"
checks_file="$(mktemp)"
blockers_file="$(mktemp)"
trap 'rm -f "$checks_file" "$blockers_file"' EXIT
: >"$checks_file"
: >"$blockers_file"

failures=0
checks_total=0

record_check() {
  local id="$1"
  local status="$2"
  local message="$3"
  checks_total=$((checks_total + 1))
  jq -n --arg id "$id" --arg status "$status" --arg message "$message" \
    '{id:$id,status:$status,message:$message}' >>"$checks_file"
  if [[ "$status" != "ok" ]]; then
    failures=$((failures + 1))
    jq -n --arg code "$id" --arg message "$message" '{code:$code,message:$message}' >>"$blockers_file"
  fi
}

if [[ "$bundle_dir_exists_initial" == "1" ]]; then
  record_check "bundle_dir_exists" "ok" "bundle directory exists: $bundle_dir"
else
  record_check "bundle_dir_exists" "fail" "bundle directory does not exist: $bundle_dir"
fi

for required_file in "$ca_file" "$cert_file" "$key_file"; do
  if [[ -s "$required_file" ]]; then
    record_check "file_exists_$(basename "$required_file")" "ok" "required file exists: $required_file"
  else
    record_check "file_exists_$(basename "$required_file")" "fail" "required file missing or empty: $required_file"
  fi
done

if [[ -e "$ca_key_file" && "$allow_ca_key" != "1" ]]; then
  record_check "ca_key_absent" "fail" "server bundle must not include CA private key: $ca_key_file"
elif [[ -e "$ca_key_file" ]]; then
  record_check "ca_key_absent" "ok" "CA private key present but explicitly allowed: $ca_key_file"
else
  record_check "ca_key_absent" "ok" "CA private key is absent from server bundle"
fi

if [[ -s "$ca_file" && -s "$cert_file" ]]; then
  if cert_verifies_with_ca "$ca_file" "$cert_file"; then
    record_check "node_cert_chain" "ok" "node certificate verifies against CA"
  else
    record_check "node_cert_chain" "fail" "node certificate does not verify against CA"
  fi
  if cert_verifies_with_purpose "$ca_file" "$cert_file" "sslserver"; then
    record_check "node_cert_server_auth" "ok" "node certificate allows server authentication"
  else
    record_check "node_cert_server_auth" "fail" "node certificate missing serverAuth usage"
  fi
  if cert_not_expiring "$cert_file" "$days_min"; then
    record_check "node_cert_expiry" "ok" "node certificate remains valid for at least ${days_min} day(s)"
  else
    record_check "node_cert_expiry" "fail" "node certificate expires before ${days_min} day(s)"
  fi
else
  record_check "node_cert_chain" "fail" "cannot verify certificate chain because ca.crt or node.crt is missing"
  record_check "node_cert_server_auth" "fail" "cannot verify serverAuth usage because ca.crt or node.crt is missing"
  record_check "node_cert_expiry" "fail" "cannot verify expiry because node.crt is missing"
fi

if [[ -s "$cert_file" && -s "$key_file" ]]; then
  if cert_matches_private_key "$cert_file" "$key_file"; then
    record_check "node_cert_key_match" "ok" "node certificate matches node private key"
  else
    record_check "node_cert_key_match" "fail" "node certificate does not match node private key"
  fi
else
  record_check "node_cert_key_match" "fail" "cannot verify key match because node.crt or node.key is missing"
fi

if [[ -s "$ca_file" && -s "$cert_file" ]]; then
  for expected_host in "${expected_hosts[@]}"; do
    if cert_valid_for_host "$ca_file" "$cert_file" "$expected_host"; then
      record_check "node_cert_san_${expected_host}" "ok" "node certificate SAN covers expected host: $expected_host"
    else
      record_check "node_cert_san_${expected_host}" "fail" "node certificate SAN does not cover expected host: $expected_host"
    fi
  done
else
  for expected_host in "${expected_hosts[@]}"; do
    record_check "node_cert_san_${expected_host}" "fail" "cannot verify SAN for $expected_host because ca.crt or node.crt is missing"
  done
fi

client_cert_present="0"
client_key_present="0"
if [[ -s "$client_cert_file" ]]; then
  client_cert_present="1"
fi
if [[ -s "$client_key_file" ]]; then
  client_key_present="1"
fi

if [[ "$require_client_material" == "1" || "$client_cert_present" == "1" || "$client_key_present" == "1" ]]; then
  if [[ "$client_cert_present" == "1" ]]; then
    record_check "file_exists_client.crt" "ok" "client certificate exists: $client_cert_file"
  else
    record_check "file_exists_client.crt" "fail" "client certificate missing or empty: $client_cert_file"
  fi
  if [[ "$client_key_present" == "1" ]]; then
    record_check "file_exists_client.key" "ok" "client private key exists: $client_key_file"
  else
    record_check "file_exists_client.key" "fail" "client private key missing or empty: $client_key_file"
  fi

  if [[ -s "$ca_file" && "$client_cert_present" == "1" ]]; then
    if cert_verifies_with_ca "$ca_file" "$client_cert_file"; then
      record_check "client_cert_chain" "ok" "client certificate verifies against CA"
    else
      record_check "client_cert_chain" "fail" "client certificate does not verify against CA"
    fi
    if cert_verifies_with_purpose "$ca_file" "$client_cert_file" "sslclient"; then
      record_check "client_cert_client_auth" "ok" "client certificate allows client authentication"
    else
      record_check "client_cert_client_auth" "fail" "client certificate missing clientAuth usage"
    fi
    if cert_not_expiring "$client_cert_file" "$days_min"; then
      record_check "client_cert_expiry" "ok" "client certificate remains valid for at least ${days_min} day(s)"
    else
      record_check "client_cert_expiry" "fail" "client certificate expires before ${days_min} day(s)"
    fi
  else
    record_check "client_cert_chain" "fail" "cannot verify client certificate chain because ca.crt or client.crt is missing"
    record_check "client_cert_client_auth" "fail" "cannot verify clientAuth usage because ca.crt or client.crt is missing"
    record_check "client_cert_expiry" "fail" "cannot verify client certificate expiry because client.crt is missing"
  fi

  if [[ "$client_cert_present" == "1" && "$client_key_present" == "1" ]]; then
    if cert_matches_private_key "$client_cert_file" "$client_key_file"; then
      record_check "client_cert_key_match" "ok" "client certificate matches client private key"
    else
      record_check "client_cert_key_match" "fail" "client certificate does not match client private key"
    fi
  else
    record_check "client_cert_key_match" "fail" "cannot verify client key match because client.crt or client.key is missing"
  fi

  if [[ "$client_cert_present" == "1" && -s "$cert_file" ]]; then
    if files_are_same_path "$client_cert_file" "$cert_file"; then
      record_check "client_cert_path_distinct_from_node_cert" "fail" "client certificate path resolves to node certificate path"
    else
      record_check "client_cert_path_distinct_from_node_cert" "ok" "client certificate path is distinct from node certificate path"
    fi

    node_cert_identity_fp=""
    client_cert_identity_fp=""
    if node_cert_identity_fp="$(cert_identity_fingerprint "$cert_file")" &&
      client_cert_identity_fp="$(cert_identity_fingerprint "$client_cert_file")"; then
      if [[ "$client_cert_identity_fp" == "$node_cert_identity_fp" ]]; then
        record_check "client_cert_identity_distinct_from_node_cert" "fail" "client certificate is identical to node certificate"
      else
        record_check "client_cert_identity_distinct_from_node_cert" "ok" "client certificate identity is distinct from node certificate"
      fi
    else
      record_check "client_cert_identity_distinct_from_node_cert" "fail" "cannot compare client and node certificate identities"
    fi

    node_cert_pubkey_fp=""
    client_cert_pubkey_fp=""
    if node_cert_pubkey_fp="$(cert_public_key_fingerprint "$cert_file")" &&
      client_cert_pubkey_fp="$(cert_public_key_fingerprint "$client_cert_file")"; then
      if [[ "$client_cert_pubkey_fp" == "$node_cert_pubkey_fp" ]]; then
        record_check "client_cert_public_key_distinct_from_node_cert" "fail" "client certificate uses the same public key as node certificate"
      else
        record_check "client_cert_public_key_distinct_from_node_cert" "ok" "client certificate public key is distinct from node certificate"
      fi
    else
      record_check "client_cert_public_key_distinct_from_node_cert" "fail" "cannot compare client and node certificate public keys"
    fi
  else
    record_check "client_cert_path_distinct_from_node_cert" "fail" "cannot compare client and node certificate paths because client.crt or node.crt is missing"
    record_check "client_cert_identity_distinct_from_node_cert" "fail" "cannot compare client and node certificate identities because client.crt or node.crt is missing"
    record_check "client_cert_public_key_distinct_from_node_cert" "fail" "cannot compare client and node certificate public keys because client.crt or node.crt is missing"
  fi

  if [[ "$client_key_present" == "1" && -s "$key_file" ]]; then
    if files_are_same_path "$client_key_file" "$key_file"; then
      record_check "client_key_path_distinct_from_node_key" "fail" "client private key path resolves to node private key path"
    else
      record_check "client_key_path_distinct_from_node_key" "ok" "client private key path is distinct from node private key path"
    fi

    node_key_pubkey_fp=""
    client_key_pubkey_fp=""
    if node_key_pubkey_fp="$(private_key_public_fingerprint "$key_file")" &&
      client_key_pubkey_fp="$(private_key_public_fingerprint "$client_key_file")"; then
      if [[ "$client_key_pubkey_fp" == "$node_key_pubkey_fp" ]]; then
        record_check "client_key_identity_distinct_from_node_key" "fail" "client private key is the same key material as node private key"
      else
        record_check "client_key_identity_distinct_from_node_key" "ok" "client private key material is distinct from node private key"
      fi
    else
      record_check "client_key_identity_distinct_from_node_key" "fail" "cannot compare client and node private key identities"
    fi
  else
    record_check "client_key_path_distinct_from_node_key" "fail" "cannot compare client and node private key paths because client.key or node.key is missing"
    record_check "client_key_identity_distinct_from_node_key" "fail" "cannot compare client and node private key identities because client.key or node.key is missing"
  fi
else
  record_check "client_material_optional" "ok" "client.crt/client.key are optional for this verification mode"
fi

status="pass"
if ((failures > 0)); then
  status="fail"
fi

checks_json="$(jq -s '.' "$checks_file")"
blockers_json="$(jq -s '.' "$blockers_file")"
hosts_json="$(json_array_from_values "${expected_hosts[@]}")"
days_min_num=$((10#$days_min))

jq -n \
  --argjson version 1 \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$status" \
  --arg bundle_dir "$bundle_dir" \
  --arg ca_file "$ca_file" \
  --arg cert_file "$cert_file" \
  --arg key_file "$key_file" \
  --arg client_cert_file "$client_cert_file" \
  --arg client_key_file "$client_key_file" \
  --arg ca_key_file "$ca_key_file" \
  --arg summary_json "$summary_json" \
  --argjson expected_hosts "$hosts_json" \
  --argjson days_min "$days_min_num" \
  --argjson allow_ca_key "$(json_bool "$allow_ca_key")" \
  --argjson require_client_material "$(json_bool "$require_client_material")" \
  --argjson checks_total "$checks_total" \
  --argjson failures "$failures" \
  --argjson checks "$checks_json" \
  --argjson blockers "$blockers_json" \
  '{
    version: $version,
    schema: {id: "prod_mtls_bundle_verify_summary", major: 1, minor: 0},
    generated_at_utc: $generated_at_utc,
    status: $status,
    inputs: {
      bundle_dir: $bundle_dir,
      expected_hosts: $expected_hosts,
      days_min: $days_min,
      allow_ca_key: $allow_ca_key,
      require_client_material: $require_client_material
    },
    checks_total: $checks_total,
    failures: $failures,
    checks: $checks,
    blockers: $blockers,
    artifacts: {
      ca_file: $ca_file,
      node_cert_file: $cert_file,
      node_key_file: $key_file,
      client_cert_file: $client_cert_file,
      client_key_file: $client_key_file,
      forbidden_ca_key_file: $ca_key_file,
      summary_json: $summary_json
    },
    next_env_hint: {
      MTLS_ENABLE: "1",
      MTLS_REQUIRE_CLIENT_CERT: "1",
      MTLS_MIN_VERSION: "1.3",
      MTLS_CA_FILE: "/app/tls/ca.crt",
      MTLS_SERVER_CERT_FILE: "/app/tls/node.crt",
      MTLS_SERVER_KEY_FILE: "/app/tls/node.key",
      MTLS_CLIENT_CERT_FILE: "/app/tls/client.crt",
      MTLS_CLIENT_KEY_FILE: "/app/tls/client.key"
    }
  }' >"$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

echo "prod-mtls-bundle-verify: status=${status} checks=${checks_total} failures=${failures}"
echo "summary_json: $summary_json"

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 1
