#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_mtls_bundle_stage.sh --bundle-dir DIR --host HOST [options]

Options:
  --bundle-dir DIR            Host-specific server bundle directory.
  --host HOST                 Expected DNS name or IP covered by node.crt SAN. Repeatable.
  --public-host HOST          Alias for --host.
  --target-dir DIR            Target TLS directory. Default: deploy/tls.
  --client-bundle-dir DIR     Directory containing client.crt/client.key for local tools.
  --client-cert-file PATH     Client cert to stage as target client.crt.
  --client-key-file PATH      Client key to stage as target client.key.
  --copy-client auto|0|1      Copy client material. Default: auto.
  --backup-dir DIR            Backup directory. Default: .easy-node-logs/prod_mtls_bundle_stage_<timestamp>_backup.
  --summary-json PATH         Summary JSON path. Default: <target-dir>/prod_mtls_bundle_stage_summary.json.
  --print-summary-json 0|1    Print summary JSON after writing it. Default: 0.

Notes:
  This command stages already-issued leaf material. It copies ca.crt, node.crt,
  and node.key into the target TLS directory, backs up replaced files, removes
  any staged ca.key from the target, and does not restart services.
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

json_array_from_values() {
  if (($# == 0)); then
    printf '[]'
    return
  fi
  printf '%s\n' "$@" | jq -R . | jq -s .
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

append_copy_record() {
  local name="$1"
  local src="$2"
  local dst="$3"
  jq -n --arg name "$name" --arg src "$src" --arg dst "$dst" \
    '{name:$name,src:$src,dst:$dst}' >>"$copied_file"
}

timestamp="$(date -u +%Y%m%d_%H%M%S)"
bundle_dir=""
target_dir="deploy/tls"
client_bundle_dir=""
client_cert_file=""
client_key_file=""
copy_client="auto"
backup_dir=""
summary_json=""
print_summary_json="0"
declare -a hosts=()

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
      hosts+=("$host_value")
      shift 2
      ;;
    --target-dir)
      target_dir="${2:-}"
      if [[ -z "$(trim "$target_dir")" ]]; then
        echo "missing value for --target-dir" >&2
        exit 2
      fi
      shift 2
      ;;
    --client-bundle-dir)
      client_bundle_dir="${2:-}"
      if [[ -z "$(trim "$client_bundle_dir")" ]]; then
        echo "missing value for --client-bundle-dir" >&2
        exit 2
      fi
      shift 2
      ;;
    --client-cert-file)
      client_cert_file="${2:-}"
      if [[ -z "$(trim "$client_cert_file")" ]]; then
        echo "missing value for --client-cert-file" >&2
        exit 2
      fi
      shift 2
      ;;
    --client-key-file)
      client_key_file="${2:-}"
      if [[ -z "$(trim "$client_key_file")" ]]; then
        echo "missing value for --client-key-file" >&2
        exit 2
      fi
      shift 2
      ;;
    --copy-client)
      copy_client="$(printf '%s' "${2:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
      if [[ "$copy_client" != "auto" ]]; then
        copy_client="$(normalize_bool_01 "$copy_client")" || {
          echo "prod-mtls-bundle-stage requires --copy-client auto|0|1" >&2
          exit 2
        }
      fi
      shift 2
      ;;
    --backup-dir)
      backup_dir="${2:-}"
      if [[ -z "$(trim "$backup_dir")" ]]; then
        echo "missing value for --backup-dir" >&2
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
        echo "prod-mtls-bundle-stage requires --print-summary-json to be 0 or 1" >&2
        exit 2
      fi
      shift 2
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg for prod-mtls-bundle-stage: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$bundle_dir" ]]; then
  echo "prod-mtls-bundle-stage requires --bundle-dir" >&2
  exit 2
fi
if ((${#hosts[@]} == 0)); then
  echo "prod-mtls-bundle-stage requires at least one --host" >&2
  exit 2
fi
if { [[ -n "$client_cert_file" ]] && [[ -z "$client_key_file" ]]; } || { [[ -z "$client_cert_file" ]] && [[ -n "$client_key_file" ]]; }; then
  echo "prod-mtls-bundle-stage requires --client-cert-file and --client-key-file together" >&2
  exit 2
fi

need_cmd jq
need_cmd openssl

bundle_dir="$(make_abs_path "$bundle_dir")"
target_dir="$(make_abs_path "$target_dir")"
if [[ -n "$client_bundle_dir" ]]; then
  client_bundle_dir="$(make_abs_path "$client_bundle_dir")"
fi
if [[ -n "$client_cert_file" ]]; then
  client_cert_file="$(make_abs_path "$client_cert_file")"
  client_key_file="$(make_abs_path "$client_key_file")"
fi
if [[ -z "$backup_dir" ]]; then
  backup_dir="$ROOT_DIR/.easy-node-logs/prod_mtls_bundle_stage_${timestamp}_backup"
else
  backup_dir="$(make_abs_path "$backup_dir")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$target_dir/prod_mtls_bundle_stage_summary.json"
else
  summary_json="$(make_abs_path "$summary_json")"
fi

verify_json="$(dirname "$summary_json")/prod_mtls_bundle_stage_source_verify_${timestamp}.json"
mkdir -p "$(dirname "$summary_json")"

verify_args=(--bundle-dir "$bundle_dir" --summary-json "$verify_json")
for host in "${hosts[@]}"; do
  verify_args+=(--host "$host")
done
if ! "$ROOT_DIR/scripts/prod_mtls_bundle_verify.sh" "${verify_args[@]}" >/dev/null; then
  echo "prod-mtls-bundle-stage refused source bundle; inspect $verify_json" >&2
  exit 1
fi

source_client_cert=""
source_client_key=""
if [[ -n "$client_cert_file" ]]; then
  source_client_cert="$client_cert_file"
  source_client_key="$client_key_file"
elif [[ -n "$client_bundle_dir" ]]; then
  source_client_cert="$client_bundle_dir/client.crt"
  source_client_key="$client_bundle_dir/client.key"
else
  candidate_client_dir="$(cd "$bundle_dir/../.." 2>/dev/null && pwd || true)"
  if [[ -n "$candidate_client_dir" ]]; then
    source_client_cert="$candidate_client_dir/client.crt"
    source_client_key="$candidate_client_dir/client.key"
  fi
fi

client_copied="0"
if [[ "$copy_client" == "1" || ( "$copy_client" == "auto" && -s "$source_client_cert" && -s "$source_client_key" ) ]]; then
  if [[ ! -s "$source_client_cert" || ! -s "$source_client_key" ]]; then
    echo "prod-mtls-bundle-stage requires readable client.crt/client.key when --copy-client 1 is set" >&2
    exit 2
  fi
  client_copied="1"
fi

mkdir -p "$target_dir" "$backup_dir"
copied_file="$(mktemp)"
removed_file="$(mktemp)"
trap 'rm -f "$copied_file" "$removed_file"' EXIT
: >"$copied_file"
: >"$removed_file"

backup_existing() {
  local path="$1"
  if [[ -e "$path" ]]; then
    cp -p "$path" "$backup_dir/$(basename "$path")"
  fi
}

stage_file() {
  local name="$1"
  local src="$2"
  local dst="$target_dir/$name"
  if [[ ! -s "$src" ]]; then
    echo "prod-mtls-bundle-stage missing source file: $src" >&2
    exit 1
  fi
  backup_existing "$dst"
  cp "$src" "$dst"
  append_copy_record "$name" "$src" "$dst"
}

stage_file "ca.crt" "$bundle_dir/ca.crt"
stage_file "node.crt" "$bundle_dir/node.crt"
stage_file "node.key" "$bundle_dir/node.key"
if [[ "$client_copied" == "1" ]]; then
  stage_file "client.crt" "$source_client_cert"
  stage_file "client.key" "$source_client_key"
fi

if [[ -e "$target_dir/ca.key" ]]; then
  backup_existing "$target_dir/ca.key"
  rm -f "$target_dir/ca.key"
  jq -n --arg path "$target_dir/ca.key" '{path:$path,reason:"server leaf staging removes CA private key"}' >>"$removed_file"
fi

chmod 644 "$target_dir/ca.crt" "$target_dir/node.crt" 2>/dev/null || true
chmod 600 "$target_dir/node.key" 2>/dev/null || true
if [[ "$client_copied" == "1" ]]; then
  chmod 644 "$target_dir/client.crt" 2>/dev/null || true
  chmod 600 "$target_dir/client.key" 2>/dev/null || true
fi

target_verify_json="$(dirname "$summary_json")/prod_mtls_bundle_stage_target_verify_${timestamp}.json"
target_verify_args=(--bundle-dir "$target_dir" --summary-json "$target_verify_json")
if [[ "$client_copied" == "1" ]]; then
  target_verify_args+=(--require-client-material 1)
fi
for host in "${hosts[@]}"; do
  target_verify_args+=(--host "$host")
done
if ! "$ROOT_DIR/scripts/prod_mtls_bundle_verify.sh" "${target_verify_args[@]}" >/dev/null; then
  echo "prod-mtls-bundle-stage target verification failed; inspect $target_verify_json" >&2
  exit 1
fi

copied_json="$(jq -s '.' "$copied_file")"
removed_json="$(jq -s '.' "$removed_file")"
hosts_json="$(json_array_from_values "${hosts[@]}")"

jq -n \
  --argjson version 1 \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "pass" \
  --arg bundle_dir "$bundle_dir" \
  --arg target_dir "$target_dir" \
  --arg backup_dir "$backup_dir" \
  --arg summary_json "$summary_json" \
  --arg source_verify_json "$verify_json" \
  --arg target_verify_json "$target_verify_json" \
  --argjson expected_hosts "$hosts_json" \
  --argjson client_copied "$(json_bool "$client_copied")" \
  --argjson copied_files "$copied_json" \
  --argjson removed_files "$removed_json" \
  '{
    version: $version,
    schema: {id: "prod_mtls_bundle_stage_summary", major: 1, minor: 0},
    generated_at_utc: $generated_at_utc,
    status: $status,
    non_disruptive: true,
    restarted_services: false,
    inputs: {
      bundle_dir: $bundle_dir,
      target_dir: $target_dir,
      expected_hosts: $expected_hosts
    },
    client_material_copied: $client_copied,
    copied_files: $copied_files,
    removed_files: $removed_files,
    artifacts: {
      backup_dir: $backup_dir,
      source_verify_json: $source_verify_json,
      target_verify_json: $target_verify_json,
      summary_json: $summary_json
    },
    next_command_hint: "EASY_NODE_PROD_MTLS_MODE=staged ./scripts/easy_node.sh server-up --prod-profile 1 ..."
  }' >"$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

echo "prod-mtls-bundle-stage: status=pass target_dir=$target_dir client_copied=$([[ "$client_copied" == "1" ]] && echo true || echo false)"
echo "summary_json: $summary_json"
