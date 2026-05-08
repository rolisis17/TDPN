#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_mtls_prep.sh --authority-host HOST --provider-host HOST [options]

Options:
  --authority-host HOST        Public DNS name or IP for the authority node.
  --public-host HOST           Alias for --authority-host.
  --provider-host HOST         Public DNS name or IP for a provider node. Repeatable.
  --peer-host HOST             Alias for --provider-host.
  --san HOST                   Extra SAN to include in the node certificate. Repeatable.
  --out-dir DIR                Preparation artifact directory.
  --tls-out-dir DIR            Certificate output directory. Defaults to <out-dir>/tls.
  --days N                     Certificate validity days. Default: 365.
  --generate-certs 0|1         Generate bootstrap mTLS material. Default: 1.
  --allow-private-hosts 0|1    Allow private/Tailscale hosts for rehearsal-only bundles. Default: 0.
  --summary-json PATH          Summary JSON path. Default: <out-dir>/prod_mtls_prep_summary.json.
  --report-md PATH             Markdown report path. Default: <out-dir>/prod_mtls_prep_report.md.
  --print-summary-json 0|1     Print summary JSON after writing it. Default: 0.

Notes:
  This command is non-disruptive: it does not edit deploy/.env.easy.*,
  does not write deploy/tls unless you explicitly point --tls-out-dir there,
  and does not restart running servers.
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
  if [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    if ! is_ipv4 "$value"; then
      echo "invalid IPv4 mTLS host '$value': octets must be in range 0..255" >&2
      return 1
    fi
    printf '%s' "$value"
    return 0
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

make_abs_path() {
  local path="$1"
  if [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s/%s' "$ROOT_DIR" "$path"
  fi
}

ipv4_private_or_loopback() {
  local host="$1"
  is_ipv4 "$host" || return 1
  local IFS=.
  local -a octets=()
  read -r -a octets <<<"$host"
  local o1=$((10#${octets[0]}))
  local o2=$((10#${octets[1]}))
  case "$o1" in
    0|10|127)
      return 0
      ;;
    169)
      ((o2 == 254)) && return 0
      ;;
    172)
      ((o2 >= 16 && o2 <= 31)) && return 0
      ;;
    192)
      ((o2 == 168)) && return 0
      ;;
    100)
      ((o2 >= 64 && o2 <= 127)) && return 0
      ;;
  esac
  return 1
}

host_is_private_or_loopback() {
  local host
  host="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  if is_ipv4 "$host"; then
    ipv4_private_or_loopback "$host"
    return
  fi
  if is_ipv6 "$host"; then
    case "$host" in
      ::|::1|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1|fc*|fd*|fe80:*)
        return 0
        ;;
    esac
    return 1
  fi
  [[ "$host" == "localhost" || "$host" == *.localhost || "$host" == *.local ]]
}

url_host_literal() {
  local host="$1"
  if is_ipv6 "$host"; then
    printf '[%s]' "$host"
  else
    printf '%s' "$host"
  fi
}

json_bool() {
  if [[ "${1:-0}" == "1" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

json_array_from_values() {
  if (($# == 0)); then
    printf '[]'
    return
  fi
  printf '%s\n' "$@" | jq -R . | jq -s .
}

timestamp="$(date -u +%Y%m%d_%H%M%S)"
authority_host=""
days="365"
out_dir=".easy-node-logs/prod_mtls_prep_${timestamp}"
tls_out_dir=""
summary_json=""
report_md=""
generate_certs="1"
allow_private_hosts="0"
print_summary_json="0"
declare -a provider_hosts=()
declare -a extra_sans=()
declare -a all_sans=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --authority-host|--public-host)
      if [[ -z "${2:-}" ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      authority_host="$(normalize_host_value "$2")" || exit 2
      shift 2
      ;;
    --provider-host|--peer-host)
      if [[ -z "${2:-}" ]]; then
        echo "missing value for $1" >&2
        exit 2
      fi
      provider_host="$(normalize_host_value "$2")" || exit 2
      add_unique "$provider_host" provider_hosts
      shift 2
      ;;
    --san)
      if [[ -z "${2:-}" ]]; then
        echo "missing value for --san" >&2
        exit 2
      fi
      san_value="$(normalize_host_value "$2")" || exit 2
      add_unique "$san_value" extra_sans
      shift 2
      ;;
    --out-dir)
      out_dir="${2:-}"
      if [[ -z "$(trim "$out_dir")" ]]; then
        echo "missing value for --out-dir" >&2
        exit 2
      fi
      shift 2
      ;;
    --tls-out-dir)
      tls_out_dir="${2:-}"
      if [[ -z "$(trim "$tls_out_dir")" ]]; then
        echo "missing value for --tls-out-dir" >&2
        exit 2
      fi
      shift 2
      ;;
    --days)
      days="${2:-}"
      if ! [[ "$days" =~ ^[0-9]+$ ]] || ((days < 1)); then
        echo "prod-mtls-prep requires --days >= 1" >&2
        exit 2
      fi
      shift 2
      ;;
    --generate-certs)
      if ! generate_certs="$(normalize_bool_01 "${2:-}")"; then
        echo "prod-mtls-prep requires --generate-certs to be 0 or 1" >&2
        exit 2
      fi
      shift 2
      ;;
    --allow-private-hosts)
      if ! allow_private_hosts="$(normalize_bool_01 "${2:-}")"; then
        echo "prod-mtls-prep requires --allow-private-hosts to be 0 or 1" >&2
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
    --report-md)
      report_md="${2:-}"
      if [[ -z "$(trim "$report_md")" ]]; then
        echo "missing value for --report-md" >&2
        exit 2
      fi
      shift 2
      ;;
    --print-summary-json)
      if ! print_summary_json="$(normalize_bool_01 "${2:-}")"; then
        echo "prod-mtls-prep requires --print-summary-json to be 0 or 1" >&2
        exit 2
      fi
      shift 2
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg for prod-mtls-prep: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$authority_host" ]]; then
  echo "prod-mtls-prep requires --authority-host" >&2
  exit 2
fi
if ((${#provider_hosts[@]} == 0)); then
  echo "prod-mtls-prep requires at least one --provider-host" >&2
  exit 2
fi

need_cmd jq
need_cmd openssl

out_dir="$(make_abs_path "$out_dir")"
if [[ -z "$tls_out_dir" ]]; then
  tls_out_dir="$out_dir/tls"
else
  tls_out_dir="$(make_abs_path "$tls_out_dir")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$out_dir/prod_mtls_prep_summary.json"
else
  summary_json="$(make_abs_path "$summary_json")"
fi
if [[ -z "$report_md" ]]; then
  report_md="$out_dir/prod_mtls_prep_report.md"
else
  report_md="$(make_abs_path "$report_md")"
fi

mkdir -p "$out_dir" "$(dirname "$summary_json")" "$(dirname "$report_md")"

add_unique "$authority_host" all_sans
for provider_host in "${provider_hosts[@]}"; do
  add_unique "$provider_host" all_sans
done
for san_value in "${extra_sans[@]}"; do
  add_unique "$san_value" all_sans
done

status="pass"
notes="production mTLS preparation completed"
prod_ready="1"
rehearsal_only="0"
private_count=0
cert_generation_status="skipped"
bootstrap_log="$out_dir/bootstrap_mtls.log"
declare -a blockers=()

host_records_file="$(mktemp)"
blockers_file="$(mktemp)"
generated_files_file="$(mktemp)"
trap 'rm -f "$host_records_file" "$blockers_file" "$generated_files_file"' EXIT
: >"$host_records_file"
: >"$blockers_file"
: >"$generated_files_file"

append_host_record() {
  local role="$1"
  local host="$2"
  local private_flag="0"
  if host_is_private_or_loopback "$host"; then
    private_flag="1"
    private_count=$((private_count + 1))
  fi
  jq -n \
    --arg role "$role" \
    --arg host "$host" \
    --argjson private_or_loopback "$(json_bool "$private_flag")" \
    '{role:$role,host:$host,private_or_loopback:$private_or_loopback}' >>"$host_records_file"
}

append_blocker() {
  local code="$1"
  local message="$2"
  blockers+=("$message")
  jq -n --arg code "$code" --arg message "$message" '{code:$code,message:$message}' >>"$blockers_file"
}

append_host_record "authority" "$authority_host"
for provider_host in "${provider_hosts[@]}"; do
  append_host_record "provider" "$provider_host"
done
for san_value in "${extra_sans[@]}"; do
  append_host_record "extra-san" "$san_value"
done

if ((private_count > 0)); then
  if [[ "$allow_private_hosts" == "1" ]]; then
    prod_ready="0"
    rehearsal_only="1"
    notes="mTLS rehearsal bundle generated for private/Tailscale hosts; true prod still needs public HTTPS hosts"
    append_blocker "rehearsal_only_private_hosts" "private, loopback, link-local, .local, or Tailscale/CGNAT hosts were explicitly allowed for rehearsal only; replace them with public DNS/IPs before true production signoff"
  else
    status="fail"
    prod_ready="0"
    append_blocker "private_or_loopback_host" "private, loopback, link-local, .local, or Tailscale/CGNAT hosts are not accepted for true production mTLS prep; rerun with public DNS/IPs or add --allow-private-hosts 1 for rehearsal only"
    notes="production mTLS preparation blocked by non-public hosts"
  fi
fi

if [[ "$status" == "pass" && "$generate_certs" == "0" ]]; then
  prod_ready="0"
  cert_generation_status="skipped"
  append_blocker "cert_generation_skipped" "certificate generation was skipped by --generate-certs 0"
elif [[ "$status" == "pass" && "$generate_certs" == "1" ]]; then
  mtls_cmd=("$ROOT_DIR/scripts/bootstrap_mtls.sh" --out-dir "$tls_out_dir" --public-host "$authority_host" --days "$days")
  for provider_host in "${provider_hosts[@]}"; do
    mtls_cmd+=(--san "$provider_host")
  done
  for san_value in "${extra_sans[@]}"; do
    mtls_cmd+=(--san "$san_value")
  done
  if "${mtls_cmd[@]}" >"$bootstrap_log" 2>&1; then
    cert_generation_status="ok"
    for file_name in ca.crt ca.key node.crt node.key client.crt client.key; do
      jq -n --arg name "$file_name" --arg path "$tls_out_dir/$file_name" '{name:$name,path:$path,exists:true}' >>"$generated_files_file"
    done
  else
    status="fail"
    prod_ready="0"
    cert_generation_status="fail"
    append_blocker "bootstrap_mtls_failed" "bootstrap_mtls failed; inspect $bootstrap_log"
  fi
fi

authority_url_host="$(url_host_literal "$authority_host")"
primary_provider_host="${provider_hosts[0]}"
primary_provider_url_host="$(url_host_literal "$primary_provider_host")"
provider_directory_urls=()
for provider_host in "${provider_hosts[@]}"; do
  provider_directory_urls+=("https://$(url_host_literal "$provider_host"):8081")
done
provider_directory_csv="$(IFS=,; printf '%s' "${provider_directory_urls[*]}")"

authority_server_cmd="EASY_NODE_PROD_ISSUER_TRUSTED_KEYS_FILE=/path/to/issuer_trust_keys.txt COSMOS_SETTLEMENT_ENDPOINT=https://SETTLEMENT_ENDPOINT ./scripts/easy_node.sh server-up --mode authority --public-host ${authority_host} --peer-directories ${provider_directory_csv} --prod-profile 1"
provider_server_cmd="EASY_NODE_PROD_ISSUER_TRUSTED_KEYS_FILE=/path/to/issuer_trust_keys.txt COSMOS_SETTLEMENT_ENDPOINT=https://SETTLEMENT_ENDPOINT ./scripts/easy_node.sh server-up --mode provider --public-host ${primary_provider_host} --authority-directory https://${authority_url_host}:8081 --authority-issuer https://${authority_url_host}:8082 --peer-directories https://${authority_url_host}:8081 --prod-profile 1"
prod_preflight_cmd="./scripts/easy_node.sh prod-preflight --days-min 14 --check-live 1 --timeout-sec 12"
client_smoke_cmd="sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory https://${authority_url_host}:8081 --directory-urls https://${authority_url_host}:8081,https://${primary_provider_url_host}:8081 --issuer-url https://${authority_url_host}:8082 --entry-url https://${authority_url_host}:8083 --exit-url https://${authority_url_host}:8084 --subject INVITE_KEY --path-profile balanced --prod-profile 1 --interface wgvpn0 --install-route 1 --pre-real-host-readiness 1 --runtime-fix 1 --mtls-ca-file deploy/tls/ca.crt --mtls-client-cert-file deploy/tls/client.crt --mtls-client-key-file deploy/tls/client.key --print-summary-json 1"
signoff_cmd="sudo ./scripts/easy_node.sh three-machine-prod-signoff --bundle-dir .easy-node-logs/prod_gate_bundle --directory-a https://${authority_url_host}:8081 --directory-b https://${primary_provider_url_host}:8081 --bootstrap-directory https://${authority_url_host}:8081 --issuer-url https://${authority_url_host}:8082 --entry-url https://${authority_url_host}:8083 --exit-url https://${authority_url_host}:8084 --subject INVITE_KEY --min-sources 2 --min-operators 2 --path-profile balanced --prod-profile 1 --pre-real-host-readiness 1 --runtime-fix 1 --record-result 1 --manual-validation-report 1 --print-summary-json 1"
beta_lab_cmd="./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --directory-urls http://A_HOST:8081,http://B_HOST:8081 --issuer-url http://A_HOST:8082 --entry-url http://A_HOST:8083 --exit-url http://A_HOST:8084 --subject INVITE_KEY --path-profile balanced --beta-profile 1 --prod-profile 0 --allow-insecure-remote-http 1"

write_report() {
  {
    echo "# Production mTLS Preparation"
    echo
    echo "- status: ${status}"
    echo "- prod_ready: $([[ "$prod_ready" == "1" ]] && echo "true" || echo "false")"
    echo "- rehearsal_only: $([[ "$rehearsal_only" == "1" ]] && echo "true" || echo "false")"
    echo "- cert_generation: ${cert_generation_status}"
    echo "- non_disruptive: true"
    echo
    echo "This command did not edit deploy/.env.easy.*, did not write deploy/tls unless explicitly requested, and did not restart Docker."
    echo "The current beta HTTP lab can keep using --prod-profile 0 with --allow-insecure-remote-http 1."
    echo
    echo "## Hosts"
    echo
    echo "| role | host | private_or_loopback |"
    echo "| --- | --- | --- |"
    jq -r '. | "| \(.role) | \(.host) | \(.private_or_loopback) |"' "$host_records_file"
    echo
    if ((${#blockers[@]} > 0)); then
      echo "## Blockers"
      echo
      local blocker
      for blocker in "${blockers[@]}"; do
        echo "- ${blocker}"
      done
      echo
    fi
    echo "## Artifacts"
    echo
    echo "- tls_dir: ${tls_out_dir}"
    echo "- bootstrap_log: ${bootstrap_log}"
    echo "- summary_json: ${summary_json}"
    echo "- report_md: ${report_md}"
    echo
    echo "## Later Cutover Commands"
    echo
    echo '```bash'
    echo "# Authority"
    echo "$authority_server_cmd"
    echo
    echo "# Provider"
    echo "$provider_server_cmd"
    echo
    echo "# On each prod-profile server after server-up"
    echo "$prod_preflight_cmd"
    echo
    echo "# Machine C client smoke after HTTPS/mTLS is live"
    echo "$client_smoke_cmd"
    echo
    echo "# Machine C final production signoff"
    echo "$signoff_cmd"
    echo '```'
    echo
    echo "## Current Beta Lab"
    echo
    echo '```bash'
    echo "$beta_lab_cmd"
    echo '```'
  } >"$report_md"
}

write_summary() {
  local hosts_json blockers_json generated_files_json
  hosts_json="$(jq -s '.' "$host_records_file")"
  blockers_json="$(jq -s '.' "$blockers_file")"
  generated_files_json="$(jq -s '.' "$generated_files_file")"
  local days_num
  days_num=$((10#$days))
  jq -n \
    --argjson version 1 \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg status "$status" \
    --arg notes "$notes" \
    --argjson prod_ready "$(json_bool "$prod_ready")" \
    --argjson rehearsal_only "$(json_bool "$rehearsal_only")" \
    --argjson non_disruptive true \
    --argjson beta_http_unchanged true \
    --arg authority_host "$authority_host" \
    --argjson provider_hosts "$(json_array_from_values "${provider_hosts[@]}")" \
    --argjson extra_sans "$(json_array_from_values "${extra_sans[@]}")" \
    --argjson days "$days_num" \
    --argjson generate_certs "$(json_bool "$generate_certs")" \
    --argjson allow_private_hosts "$(json_bool "$allow_private_hosts")" \
    --arg cert_generation_status "$cert_generation_status" \
    --arg out_dir "$out_dir" \
    --arg tls_dir "$tls_out_dir" \
    --arg bootstrap_log "$bootstrap_log" \
    --arg summary_json "$summary_json" \
    --arg report_md "$report_md" \
    --arg authority_server "$authority_server_cmd" \
    --arg provider_server "$provider_server_cmd" \
    --arg prod_preflight "$prod_preflight_cmd" \
    --arg client_smoke "$client_smoke_cmd" \
    --arg signoff "$signoff_cmd" \
    --arg beta_lab "$beta_lab_cmd" \
    --argjson hosts "$hosts_json" \
    --argjson blockers "$blockers_json" \
    --argjson generated_files "$generated_files_json" \
    '{
      version: $version,
      schema: {id: "prod_mtls_prep_summary", major: 1, minor: 0},
      generated_at_utc: $generated_at_utc,
      status: $status,
      notes: $notes,
      prod_ready: $prod_ready,
      rehearsal_only: $rehearsal_only,
      non_disruptive: $non_disruptive,
      beta_http_unchanged: $beta_http_unchanged,
      inputs: {
        authority_host: $authority_host,
        provider_hosts: $provider_hosts,
        extra_sans: $extra_sans,
        days: $days,
        generate_certs: $generate_certs,
        allow_private_hosts: $allow_private_hosts
      },
      hosts: $hosts,
      blockers: $blockers,
      certificate_generation: {
        status: $cert_generation_status,
        generated_files: $generated_files
      },
      artifacts: {
        out_dir: $out_dir,
        tls_dir: $tls_dir,
        bootstrap_log: $bootstrap_log,
        summary_json: $summary_json,
        report_md: $report_md
      },
      next_commands: {
        authority_server_up: $authority_server,
        provider_server_up: $provider_server,
        prod_preflight: $prod_preflight,
        client_vpn_smoke: $client_smoke,
        three_machine_prod_signoff: $signoff,
        current_beta_http_smoke: $beta_lab
      }
    }' >"$summary_json"
}

write_report
write_summary

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" == "pass" ]]; then
  echo "prod-mtls-prep: status=pass prod_ready=$([[ "$prod_ready" == "1" ]] && echo "true" || echo "false") rehearsal_only=$([[ "$rehearsal_only" == "1" ]] && echo "true" || echo "false")"
  echo "summary_json: $summary_json"
  echo "report_md: $report_md"
  exit 0
fi

echo "prod-mtls-prep: status=fail prod_ready=false"
echo "summary_json: $summary_json"
echo "report_md: $report_md"
exit 1
