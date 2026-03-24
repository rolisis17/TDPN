#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
EASY_NODE_SH="${EASY_NODE_SH:-./scripts/easy_node.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/integration_3machine_beta_validate.sh \
    [--directory-a URL] \
    [--directory-b URL] \
    [--bootstrap-directory URL] \
    [--discovery-wait-sec N] \
    [--issuer-url URL] \
    [--issuer-a-url URL] \
    [--issuer-b-url URL] \
    [--entry-url URL] \
    [--exit-url URL] \
    [--subject ID] \
    [--anon-cred TOKEN] \
    [--min-sources N] \
    [--min-operators N] \
    [--federation-timeout-sec N] \
    [--timeout-sec N] \
    [--client-min-selection-lines N] \
    [--client-min-entry-operators N] \
    [--client-min-exit-operators N] \
    [--client-require-cross-operator-pair [0|1]] \
    [--exit-country CC] \
    [--exit-region REGION] \
    [--path-profile speed|balanced|private] \
    [--distinct-operators [0|1]] \
    [--distinct-countries [0|1]] \
    [--locality-soft-bias [0|1]] \
    [--country-bias N] \
    [--region-bias N] \
    [--region-prefix-bias N] \
    [--require-issuer-quorum [0|1]] \
    [--beta-profile [0|1]] \
    [--prod-profile [0|1]]

Purpose:
  Run from machine C (client host) to validate a 3-machine beta setup:
  - machine A: directory+issuer+entry+exit
  - machine B: directory+issuer+entry+exit (federated with A)
  - machine C: client-only validation runner
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim_url() {
  local value="$1"
  while [[ "$value" == */ ]]; do
    value="${value%/}"
  done
  echo "$value"
}

normalize_path_profile() {
  local profile
  profile="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$profile" in
    speed|fast)
      printf '%s\n' "fast"
      ;;
    balanced)
      printf '%s\n' "balanced"
      ;;
    private|privacy)
      printf '%s\n' "privacy"
      ;;
    "")
      printf '%s\n' ""
      ;;
    *)
      return 1
      ;;
  esac
}

path_profile_values() {
  local profile
  profile="$(normalize_path_profile "${1:-}")" || return 1
  case "$profile" in
    fast)
      # distinct_operators|distinct_countries|locality_soft_bias|country_bias|region_bias|region_prefix_bias
      printf '%s\n' "1|0|1|1.80|1.35|1.15"
      ;;
    privacy)
      printf '%s\n' "1|1|0|1.60|1.25|1.10"
      ;;
    balanced|"")
      printf '%s\n' "1|0|1|1.50|1.25|1.10"
      ;;
    *)
      return 1
      ;;
  esac
}

url_scheme_from_url() {
  local value="$1"
  if [[ "$value" == https://* ]]; then
    echo "https"
  else
    echo "http"
  fi
}

hostport_from_url() {
  local value="$1"
  value="${value#http://}"
  value="${value#https://}"
  value="${value%%/*}"
  echo "$value"
}

host_from_hostport() {
  local value="$1"
  if [[ "$value" == \[*\]* ]]; then
    echo "${value%%]*}]"
    return
  fi
  local colon_count
  colon_count="$(printf '%s' "$value" | awk -F: '{print NF-1}')"
  if [[ "$colon_count" == "1" ]]; then
    local maybe_port="${value##*:}"
    if [[ "$maybe_port" =~ ^[0-9]+$ ]]; then
      echo "${value%:*}"
      return
    fi
  fi
  echo "$value"
}

host_from_url() {
  host_from_hostport "$(hostport_from_url "$1")"
}

normalize_host_for_endpoint() {
  local host="$1"
  if [[ "$host" == \[*\] ]]; then
    echo "$host"
    return
  fi
  if [[ "$host" == *:* ]]; then
    echo "[$host]"
    return
  fi
  echo "$host"
}

url_from_host_port() {
  local host="$1"
  local port="$2"
  local scheme="${3:-http}"
  printf '%s://%s:%s' "$scheme" "$(normalize_host_for_endpoint "$host")" "$port"
}

discover_directory_urls() {
  local bootstrap_url="$1"
  local wait_sec="${2:-12}"
  local min_hosts="${3:-2}"
  local seed_host
  local seed_scheme
  bootstrap_url="$(trim_url "$bootstrap_url")"
  seed_scheme="$(url_scheme_from_url "$bootstrap_url")"
  seed_host="$(host_from_url "$bootstrap_url")"

  declare -A seen_hosts=()
  if [[ -n "$seed_host" ]]; then
    seen_hosts["$seed_host"]=1
  fi

  local i payload relay_urls peer_urls endpoint_values u h count
  for ((i = 1; i <= wait_sec; i++)); do
    payload="$(curl -fsS --connect-timeout 2 --max-time 4 "${bootstrap_url}/v1/relays" 2>/dev/null || true)"
    relay_urls="$(printf '%s\n' "$payload" | rg -o '"control_url":"https?://[^"]+"' || true)"
    endpoint_values="$(printf '%s\n' "$payload" | rg -o '"endpoint":"[^"]+"' || true)"
    while IFS= read -r u; do
      u="$(printf '%s' "$u" | sed -E 's/^"control_url":"(https?:\/\/[^"]+)"$/\1/')"
      h="$(host_from_url "$u")"
      if [[ -n "$h" ]]; then
        seen_hosts["$h"]=1
      fi
    done <<<"$relay_urls"
    while IFS= read -r u; do
      u="$(printf '%s' "$u" | sed -E 's/^"endpoint":"([^"]+)"$/\1/')"
      h="$(host_from_hostport "$u")"
      if [[ -n "$h" ]]; then
        seen_hosts["$h"]=1
      fi
    done <<<"$endpoint_values"

    payload="$(curl -fsS --connect-timeout 2 --max-time 4 "${bootstrap_url}/v1/peers" 2>/dev/null || true)"
    peer_urls="$(printf '%s\n' "$payload" | rg -o '"url":"https?://[^"]+"' || true)"
    while IFS= read -r u; do
      u="$(printf '%s' "$u" | sed -E 's/^"url":"(https?:\/\/[^"]+)"$/\1/')"
      h="$(host_from_url "$u")"
      if [[ -n "$h" ]]; then
        seen_hosts["$h"]=1
      fi
    done <<<"$peer_urls"

    count="${#seen_hosts[@]}"
    if ((count >= min_hosts)); then
      break
    fi
    sleep 1
  done

  local out=()
  if [[ -n "$seed_host" ]]; then
    out+=("$(url_from_host_port "$seed_host" 8081 "$seed_scheme")")
    unset 'seen_hosts[$seed_host]'
  fi
  local sorted_hosts
  sorted_hosts="$(printf '%s\n' "${!seen_hosts[@]}" | awk 'NF > 0' | sort -u)"
  while IFS= read -r h; do
    [[ -z "$h" ]] && continue
    out+=("$(url_from_host_port "$h" 8081 "$seed_scheme")")
  done <<<"$sorted_hosts"

  local joined=""
  local item
  for item in "${out[@]}"; do
    if [[ -n "$joined" ]]; then
      joined+=","
    fi
    joined+="$item"
  done
  echo "$joined"
}

looks_loopback() {
  local value="$1"
  [[ "$value" == *"127.0.0.1"* || "$value" == *"localhost"* ]]
}

host_is_loopback() {
  local host="${1:-}"
  host="${host#[}"
  host="${host%]}"
  case "$host" in
    127.0.0.1|localhost|::1)
      return 0
      ;;
  esac
  return 1
}

rewrite_loopback_url_for_docker() {
  local raw="$1"
  local docker_host="${2:-host.docker.internal}"
  local scheme hostport host port

  scheme="$(url_scheme_from_url "$raw")"
  hostport="$(hostport_from_url "$raw")"
  host="$(host_from_hostport "$hostport")"
  if ! host_is_loopback "$host"; then
    printf '%s\n' "$raw"
    return 0
  fi

  if [[ "$hostport" == \[*\]:* ]]; then
    port="${hostport##*]:}"
  elif [[ "$hostport" == *:* ]]; then
    port="${hostport##*:}"
  else
    printf '%s\n' "$raw"
    return 0
  fi

  printf '%s://%s:%s\n' "$scheme" "$docker_host" "$port"
}

rewrite_url_csv_for_docker() {
  local csv="$1"
  local docker_host="${2:-host.docker.internal}"
  local item rewritten joined=""
  IFS=',' read -r -a items <<<"$csv"
  for item in "${items[@]}"; do
    item="${item//[[:space:]]/}"
    [[ -z "$item" ]] && continue
    rewritten="$(rewrite_loopback_url_for_docker "$item" "$docker_host")"
    if [[ -n "$joined" ]]; then
      joined+=","
    fi
    joined+="$rewritten"
  done
  printf '%s\n' "$joined"
}

wait_http_ok() {
  local url="$1"
  local name="$2"
  local attempts="$3"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS --connect-timeout 2 --max-time 4 "$url" >/dev/null 2>&1; then
      echo "[health] $name ok ($url)"
      return 0
    fi
    if ((i == 1 || i % 5 == 0)); then
      echo "[health] waiting for $name ($url) attempt=$i/$attempts"
    fi
    sleep 1
  done
  echo "$name did not become healthy at $url"
  return 1
}

unique_operator_count() {
  local base_url
  base_url="$(trim_url "$1")"
  local payload
  payload="$(curl -fsS "${base_url}/v1/relays" 2>/dev/null || true)"
  if [[ -z "$payload" ]]; then
    echo "0"
    return
  fi
  local matches
  matches="$(printf '%s\n' "$payload" | rg -o '"(operator_id|operator|origin_operator)":"[^"]+"' || true)"
  local count
  count="$(
    printf '%s\n' "$matches" |
      sed -E 's/^"(operator_id|operator|origin_operator)":"([^"]+)"$/\2/' |
      awk 'NF > 0' |
      sort -u |
      wc -l |
      tr -d ' '
  )"
  if [[ -z "$count" ]]; then
    count="0"
  fi
  echo "$count"
}

extract_operators() {
  local payload="$1"
  local matches
  matches="$(printf '%s\n' "$payload" | rg -o '"(operator_id|operator|origin_operator)":"[^"]+"' || true)"
  printf '%s\n' "$matches" |
    sed -E 's/^"(operator_id|operator|origin_operator)":"([^"]+)"$/\2/' |
    awk 'NF > 0' |
    sort -u
}

extract_role_operators() {
  local payload="$1"
  local role="$2"
  local matches
  matches="$(printf '%s\n' "$payload" | rg -o "\"role\":\"${role}\"[^\\}]*\"operator_id\":\"[^\"]+\"" || true)"
  printf '%s\n' "$matches" |
    rg -o '"operator_id":"[^"]+"' |
    sed -E 's/^"operator_id":"([^"]+)"$/\1/' |
    awk 'NF > 0' |
    sort -u
}

role_operator_count() {
  local payload="$1"
  local role="$2"
  local count
  count="$(
    extract_role_operators "$payload" "$role" |
      wc -l |
      tr -d ' '
  )"
  if [[ -z "$count" ]]; then
    count="0"
  fi
  echo "$count"
}

issuer_id_from_pubkeys_payload() {
  local payload="$1"
  printf '%s\n' "$payload" |
    rg -o '"issuer":"[^"]+"' |
    head -n 1 |
    sed -E 's/^"issuer":"([^"]+)"$/\1/'
}

issuer_payload_has_keys() {
  local payload="$1"
  if printf '%s\n' "$payload" | rg -q '"pub_keys"[[:space:]]*:[[:space:]]*\[[[:space:]]*"'; then
    echo "1"
  else
    echo "0"
  fi
}

issuer_pubkeys_from_payload() {
  local payload="$1"
  printf '%s\n' "$payload" |
    rg -o '"pub_keys"[[:space:]]*:[[:space:]]*\[[^]]*\]' |
    sed -E 's/^.*\[(.*)\].*$/\1/' |
    tr ',' '\n' |
    sed -E 's/^[[:space:]]*"([^"]+)"[[:space:]]*$/\1/' |
    awk 'NF > 0' |
    sort -u
}

directory_a=""
directory_b=""
issuer_url=""
issuer_a_url=""
issuer_b_url=""
entry_url=""
exit_url=""
client_subject=""
client_anon_cred=""
bootstrap_directory=""
discovery_wait_sec="${THREE_MACHINE_DISCOVERY_WAIT_SEC:-12}"
bootstrap_discovered=""
bootstrap_host=""
min_sources="2"
min_operators="2"
federation_timeout_sec="90"
client_timeout_sec="45"
client_min_selection_lines="${THREE_MACHINE_CLIENT_MIN_SELECTION_LINES:-0}"
client_min_entry_operators="${THREE_MACHINE_CLIENT_MIN_ENTRY_OPERATORS:-0}"
client_min_exit_operators="${THREE_MACHINE_CLIENT_MIN_EXIT_OPERATORS:-0}"
client_require_cross_operator_pair="${THREE_MACHINE_CLIENT_REQUIRE_CROSS_OPERATOR_PAIR:-}"
health_attempts="${THREE_MACHINE_HEALTH_ATTEMPTS:-12}"
exit_country=""
exit_region=""
path_profile="${THREE_MACHINE_PATH_PROFILE:-}"
beta_profile="${THREE_MACHINE_BETA_PROFILE:-1}"
prod_profile="${THREE_MACHINE_PROD_PROFILE:-0}"
distinct_operators="${THREE_MACHINE_DISTINCT_OPERATORS:-}"
distinct_countries="${THREE_MACHINE_DISTINCT_COUNTRIES:-0}"
locality_soft_bias="${THREE_MACHINE_LOCALITY_SOFT_BIAS:-0}"
locality_country_bias="${THREE_MACHINE_COUNTRY_BIAS:-1.60}"
locality_region_bias="${THREE_MACHINE_REGION_BIAS:-1.25}"
locality_region_prefix_bias="${THREE_MACHINE_REGION_PREFIX_BIAS:-1.10}"
require_issuer_quorum="${THREE_MACHINE_REQUIRE_ISSUER_QUORUM:-}"
path_profile_set=0
distinct_operators_set=0
distinct_countries_set=0
locality_soft_bias_set=0
locality_country_bias_set=0
locality_region_bias_set=0
locality_region_prefix_bias_set=0

if [[ -n "${THREE_MACHINE_PATH_PROFILE+x}" ]]; then
  path_profile_set=1
fi
if [[ -n "${THREE_MACHINE_DISTINCT_OPERATORS+x}" ]]; then
  distinct_operators_set=1
fi
if [[ -n "${THREE_MACHINE_DISTINCT_COUNTRIES+x}" ]]; then
  distinct_countries_set=1
fi
if [[ -n "${THREE_MACHINE_LOCALITY_SOFT_BIAS+x}" ]]; then
  locality_soft_bias_set=1
fi
if [[ -n "${THREE_MACHINE_COUNTRY_BIAS+x}" ]]; then
  locality_country_bias_set=1
fi
if [[ -n "${THREE_MACHINE_REGION_BIAS+x}" ]]; then
  locality_region_bias_set=1
fi
if [[ -n "${THREE_MACHINE_REGION_PREFIX_BIAS+x}" ]]; then
  locality_region_prefix_bias_set=1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --directory-a)
      directory_a="${2:-}"
      shift 2
      ;;
    --directory-b)
      directory_b="${2:-}"
      shift 2
      ;;
    --bootstrap-directory)
      bootstrap_directory="${2:-}"
      shift 2
      ;;
    --discovery-wait-sec)
      discovery_wait_sec="${2:-}"
      shift 2
      ;;
    --issuer-url)
      issuer_url="${2:-}"
      shift 2
      ;;
    --issuer-a-url)
      issuer_a_url="${2:-}"
      shift 2
      ;;
    --issuer-b-url)
      issuer_b_url="${2:-}"
      shift 2
      ;;
    --entry-url)
      entry_url="${2:-}"
      shift 2
      ;;
    --exit-url)
      exit_url="${2:-}"
      shift 2
      ;;
    --min-sources)
      min_sources="${2:-}"
      shift 2
      ;;
    --subject)
      client_subject="${2:-}"
      shift 2
      ;;
    --anon-cred)
      client_anon_cred="${2:-}"
      shift 2
      ;;
    --min-operators)
      min_operators="${2:-}"
      shift 2
      ;;
    --federation-timeout-sec)
      federation_timeout_sec="${2:-}"
      shift 2
      ;;
    --timeout-sec)
      client_timeout_sec="${2:-}"
      shift 2
      ;;
    --client-min-selection-lines)
      client_min_selection_lines="${2:-}"
      shift 2
      ;;
    --client-min-entry-operators)
      client_min_entry_operators="${2:-}"
      shift 2
      ;;
    --client-min-exit-operators)
      client_min_exit_operators="${2:-}"
      shift 2
      ;;
    --client-require-cross-operator-pair)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        client_require_cross_operator_pair="${2:-}"
        shift 2
      else
        client_require_cross_operator_pair="1"
        shift
      fi
      ;;
    --exit-country)
      exit_country="${2:-}"
      shift 2
      ;;
    --exit-region)
      exit_region="${2:-}"
      shift 2
      ;;
    --path-profile)
      path_profile="${2:-}"
      path_profile_set=1
      shift 2
      ;;
    --distinct-operators)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        distinct_operators="${2:-}"
        distinct_operators_set=1
        shift 2
      else
        distinct_operators="1"
        distinct_operators_set=1
        shift
      fi
      ;;
    --distinct-countries)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        distinct_countries="${2:-}"
        distinct_countries_set=1
        shift 2
      else
        distinct_countries="1"
        distinct_countries_set=1
        shift
      fi
      ;;
    --locality-soft-bias)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        locality_soft_bias="${2:-}"
        locality_soft_bias_set=1
        shift 2
      else
        locality_soft_bias="1"
        locality_soft_bias_set=1
        shift
      fi
      ;;
    --country-bias)
      locality_country_bias="${2:-}"
      locality_country_bias_set=1
      shift 2
      ;;
    --region-bias)
      locality_region_bias="${2:-}"
      locality_region_bias_set=1
      shift 2
      ;;
    --region-prefix-bias)
      locality_region_prefix_bias="${2:-}"
      locality_region_prefix_bias_set=1
      shift 2
      ;;
    --beta-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        beta_profile="${2:-}"
        shift 2
      else
        beta_profile="1"
        shift
      fi
      ;;
    --prod-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        prod_profile="${2:-}"
        shift 2
      else
        prod_profile="1"
        shift
      fi
      ;;
    --require-issuer-quorum)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        require_issuer_quorum="${2:-}"
        shift 2
      else
        require_issuer_quorum="1"
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

normalized_path_profile="$(normalize_path_profile "$path_profile")" || {
  echo "--path-profile must be one of: speed, balanced, private (legacy aliases: fast, privacy)"
  exit 2
}
if [[ -z "$normalized_path_profile" && "$beta_profile" == "1" \
      && "$path_profile_set" -eq 0 \
      && "$distinct_operators_set" -eq 0 \
      && "$distinct_countries_set" -eq 0 \
      && "$locality_soft_bias_set" -eq 0 \
      && "$locality_country_bias_set" -eq 0 \
      && "$locality_region_bias_set" -eq 0 \
      && "$locality_region_prefix_bias_set" -eq 0 ]]; then
  normalized_path_profile="balanced"
  path_profile="balanced"
fi
if [[ -n "$normalized_path_profile" ]]; then
  profile_values="$(path_profile_values "$normalized_path_profile")"
  IFS='|' read -r profile_distinct profile_distinct_countries profile_locality_soft profile_country_bias profile_region_bias profile_region_prefix_bias <<<"$profile_values"
  if [[ "$distinct_operators_set" -eq 0 ]]; then
    distinct_operators="$profile_distinct"
  fi
  if [[ "$distinct_countries_set" -eq 0 ]]; then
    distinct_countries="$profile_distinct_countries"
  fi
  if [[ "$locality_soft_bias_set" -eq 0 ]]; then
    locality_soft_bias="$profile_locality_soft"
  fi
  if [[ "$locality_country_bias_set" -eq 0 ]]; then
    locality_country_bias="$profile_country_bias"
  fi
  if [[ "$locality_region_bias_set" -eq 0 ]]; then
    locality_region_bias="$profile_region_bias"
  fi
  if [[ "$locality_region_prefix_bias_set" -eq 0 ]]; then
    locality_region_prefix_bias="$profile_region_prefix_bias"
  fi
fi

if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
  echo "--beta-profile must be 0 or 1"
  exit 2
fi
if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
  echo "--prod-profile must be 0 or 1"
  exit 2
fi
if [[ -n "$distinct_operators" && "$distinct_operators" != "0" && "$distinct_operators" != "1" ]]; then
  echo "--distinct-operators must be 0 or 1"
  exit 2
fi
if [[ "$distinct_countries" != "0" && "$distinct_countries" != "1" ]]; then
  echo "--distinct-countries must be 0 or 1"
  exit 2
fi
if [[ "$locality_soft_bias" != "0" && "$locality_soft_bias" != "1" ]]; then
  echo "--locality-soft-bias must be 0 or 1"
  exit 2
fi
if [[ -n "$require_issuer_quorum" && "$require_issuer_quorum" != "0" && "$require_issuer_quorum" != "1" ]]; then
  echo "--require-issuer-quorum must be 0 or 1"
  exit 2
fi
if [[ -n "$client_require_cross_operator_pair" && "$client_require_cross_operator_pair" != "0" && "$client_require_cross_operator_pair" != "1" ]]; then
  echo "--client-require-cross-operator-pair must be 0 or 1"
  exit 2
fi
if ! [[ "$locality_country_bias" =~ ^[0-9]+([.][0-9]+)?$ && "$locality_region_bias" =~ ^[0-9]+([.][0-9]+)?$ && "$locality_region_prefix_bias" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "--country-bias, --region-bias and --region-prefix-bias must be numeric"
  exit 2
fi
if [[ -n "$client_subject" && -n "$client_anon_cred" ]]; then
  echo "set only one of --subject or --anon-cred"
  exit 2
fi

if ! [[ "$min_sources" =~ ^[0-9]+$ && "$min_operators" =~ ^[0-9]+$ && "$federation_timeout_sec" =~ ^[0-9]+$ && "$client_timeout_sec" =~ ^[0-9]+$ && "$discovery_wait_sec" =~ ^[0-9]+$ && "$client_min_selection_lines" =~ ^[0-9]+$ && "$client_min_entry_operators" =~ ^[0-9]+$ && "$client_min_exit_operators" =~ ^[0-9]+$ ]]; then
  echo "--min-sources, --min-operators, --federation-timeout-sec, --timeout-sec, --discovery-wait-sec and client diversity thresholds must be numeric"
  exit 2
fi

if [[ "$prod_profile" == "1" ]]; then
  beta_profile="1"
fi

if [[ -z "$distinct_operators" ]]; then
  if [[ "$beta_profile" == "1" ]]; then
    distinct_operators="1"
  else
    distinct_operators="0"
  fi
fi
if [[ -z "$require_issuer_quorum" ]]; then
  if [[ "$beta_profile" == "1" ]]; then
    require_issuer_quorum="1"
  else
    require_issuer_quorum="0"
  fi
fi
if [[ -z "$client_require_cross_operator_pair" ]]; then
  if [[ "$beta_profile" == "1" && "$distinct_operators" == "1" ]]; then
    client_require_cross_operator_pair="1"
  else
    client_require_cross_operator_pair="0"
  fi
fi

if [[ "$beta_profile" == "1" ]]; then
  if ((min_sources < 2)); then
    min_sources="2"
  fi
  if ((min_operators < 2)); then
    min_operators="2"
  fi
  if ((client_min_selection_lines < 8)); then
    client_min_selection_lines="8"
  fi
  if [[ "$distinct_operators" == "1" ]]; then
    if ((client_min_entry_operators < 2)); then
      client_min_entry_operators="2"
    fi
    if ((client_min_exit_operators < 2)); then
      client_min_exit_operators="2"
    fi
  fi
fi
if ((client_min_selection_lines < 1)); then
  client_min_selection_lines="1"
fi
if ((client_min_entry_operators < 1)); then
  client_min_entry_operators="1"
fi
if ((client_min_exit_operators < 1)); then
  client_min_exit_operators="1"
fi

echo "[client-diversity] thresholds selection_lines>=$client_min_selection_lines entry_ops>=$client_min_entry_operators exit_ops>=$client_min_exit_operators cross_operator_pair=$client_require_cross_operator_pair"

if [[ -n "$bootstrap_directory" ]]; then
  bootstrap_scheme=""
  bootstrap_directory="$(trim_url "$bootstrap_directory")"
  bootstrap_scheme="$(url_scheme_from_url "$bootstrap_directory")"
  bootstrap_discovered="$(discover_directory_urls "$bootstrap_directory" "$discovery_wait_sec" "$min_sources")"
  if [[ -z "$directory_a" ]]; then
    directory_a="$(printf '%s' "$bootstrap_discovered" | cut -d',' -f1)"
  fi
  if [[ -z "$directory_b" ]]; then
    directory_b="$(printf '%s' "$bootstrap_discovered" | cut -d',' -f2)"
    if [[ "$directory_b" == "$directory_a" ]]; then
      directory_b=""
    fi
  fi
  bootstrap_host="$(host_from_url "$bootstrap_directory")"
  if [[ -z "$issuer_url" && -n "$bootstrap_host" ]]; then
    issuer_url="$(url_from_host_port "$bootstrap_host" 8082 "$bootstrap_scheme")"
  fi
  if [[ -z "$entry_url" && -n "$bootstrap_host" ]]; then
    entry_url="$(url_from_host_port "$bootstrap_host" 8083 "$bootstrap_scheme")"
  fi
  if [[ -z "$exit_url" && -n "$bootstrap_host" ]]; then
    exit_url="$(url_from_host_port "$bootstrap_host" 8084 "$bootstrap_scheme")"
  fi
fi

if [[ -z "$directory_a" || -z "$directory_b" || -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" ]]; then
  echo "missing required endpoint URLs"
  echo "provide explicit directory/issuer/entry/exit URLs"
  echo "or provide --bootstrap-directory with reachable peers."
  usage
  exit 2
fi

need_cmd curl
need_cmd rg
need_cmd timeout
need_cmd docker
if [[ ! -x "$EASY_NODE_SH" ]]; then
  echo "client launcher script not executable: $EASY_NODE_SH"
  exit 2
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "missing required dependency: docker compose plugin"
  exit 2
fi

directory_a="$(trim_url "$directory_a")"
directory_b="$(trim_url "$directory_b")"
issuer_url="$(trim_url "$issuer_url")"
issuer_a_url="$(trim_url "$issuer_a_url")"
issuer_b_url="$(trim_url "$issuer_b_url")"
entry_url="$(trim_url "$entry_url")"
exit_url="$(trim_url "$exit_url")"

if [[ -z "$issuer_a_url" ]]; then
  issuer_a_url="$(url_from_host_port "$(host_from_url "$directory_a")" 8082 "$(url_scheme_from_url "$directory_a")")"
fi
if [[ -z "$issuer_b_url" ]]; then
  issuer_b_url="$(url_from_host_port "$(host_from_url "$directory_b")" 8082 "$(url_scheme_from_url "$directory_b")")"
fi

for endpoint in "$directory_a" "$directory_b" "$issuer_url" "$issuer_a_url" "$issuer_b_url" "$entry_url" "$exit_url"; do
  if looks_loopback "$endpoint"; then
    echo "warning: loopback URL detected: $endpoint"
    echo "         for real 3-machine tests, use reachable public/private hostnames."
  fi
done

wait_http_ok "${directory_a}/v1/relays" "directory A" "$health_attempts"
wait_http_ok "${directory_b}/v1/relays" "directory B" "$health_attempts"
wait_http_ok "${issuer_url}/v1/pubkeys" "issuer" "$health_attempts"
wait_http_ok "${entry_url}/v1/health" "entry" "$health_attempts"
wait_http_ok "${exit_url}/v1/health" "exit" "$health_attempts"

federated=0
echo "[federation] waiting for operator floor: min_operators=$min_operators timeout=${federation_timeout_sec}s"
for _ in $(seq 1 "$federation_timeout_sec"); do
  a_ops="$(unique_operator_count "$directory_a")"
  b_ops="$(unique_operator_count "$directory_b")"
  if (( _ == 1 || _ % 10 == 0 )); then
    echo "[federation] progress second=$_/$federation_timeout_sec a_ops=$a_ops b_ops=$b_ops"
  fi
  if [[ "$a_ops" =~ ^[0-9]+$ ]] && [[ "$b_ops" =~ ^[0-9]+$ ]] && ((a_ops >= min_operators)) && ((b_ops >= min_operators)); then
    federated=1
    break
  fi
  sleep 1
done

if [[ "$federated" -ne 1 ]]; then
  echo "federation check failed: operator floor not reached on both directories"
  echo "required min operators per directory: $min_operators"
  a_ops="$(unique_operator_count "$directory_a")"
  b_ops="$(unique_operator_count "$directory_b")"
  echo "directory A operators: $a_ops"
  echo "directory B operators: $b_ops"
  echo "--- directory A relays ---"
  a_payload="$(curl -fsS "${directory_a}/v1/relays" || true)"
  printf '%s\n' "$a_payload"
  echo "--- directory A operator ids ---"
  extract_operators "$a_payload" || true
  echo
  echo "--- directory B relays ---"
  b_payload="$(curl -fsS "${directory_b}/v1/relays" || true)"
  printf '%s\n' "$b_payload"
  echo "--- directory B operator ids ---"
  extract_operators "$b_payload" || true
  if [[ "$a_ops" =~ ^[0-9]+$ ]] && [[ "$b_ops" =~ ^[0-9]+$ ]] && ((a_ops >= 1)) && ((b_ops >= 1)); then
    echo "hint: if both lists show the same operator id, set unique DIRECTORY_OPERATOR_ID per machine."
  fi
  echo
  exit 1
fi

if [[ "$distinct_operators" == "1" ]]; then
  combined_relays="$(printf '%s\n%s\n' "$(curl -fsS "${directory_a}/v1/relays" || true)" "$(curl -fsS "${directory_b}/v1/relays" || true)")"
  entry_ops="$(role_operator_count "$combined_relays" "entry")"
  exit_ops="$(role_operator_count "$combined_relays" "exit")"
  if [[ "$entry_ops" =~ ^[0-9]+$ ]] && [[ "$exit_ops" =~ ^[0-9]+$ ]] && ((entry_ops < 2 || exit_ops < 2)); then
    echo "distinct-operator preflight failed: insufficient role operator diversity"
    echo "required: entry_ops>=2 and exit_ops>=2 across both directories"
    echo "observed: entry_ops=$entry_ops exit_ops=$exit_ops"
    echo "--- entry operators ---"
    extract_role_operators "$combined_relays" "entry" || true
    echo "--- exit operators ---"
    extract_role_operators "$combined_relays" "exit" || true
    exit 1
  fi
fi

if [[ "$require_issuer_quorum" == "1" ]]; then
  wait_http_ok "${issuer_a_url}/v1/pubkeys" "issuer A" "$health_attempts"
  wait_http_ok "${issuer_b_url}/v1/pubkeys" "issuer B" "$health_attempts"

  issuer_quorum_ok=0
  echo "[issuer-quorum] waiting for issuer identity+key floor: min_operators=$min_operators min_distinct_keys=2 timeout=${federation_timeout_sec}s"
  for _ in $(seq 1 "$federation_timeout_sec"); do
    issuer_a_payload="$(curl -fsS "${issuer_a_url}/v1/pubkeys" 2>/dev/null || true)"
    issuer_b_payload="$(curl -fsS "${issuer_b_url}/v1/pubkeys" 2>/dev/null || true)"
    issuer_a_id="$(issuer_id_from_pubkeys_payload "$issuer_a_payload")"
    issuer_b_id="$(issuer_id_from_pubkeys_payload "$issuer_b_payload")"
    issuer_a_keys="$(issuer_payload_has_keys "$issuer_a_payload")"
    issuer_b_keys="$(issuer_payload_has_keys "$issuer_b_payload")"
    issuer_key_count="$(
      printf '%s\n%s\n' "$(issuer_pubkeys_from_payload "$issuer_a_payload")" "$(issuer_pubkeys_from_payload "$issuer_b_payload")" |
        awk 'NF > 0' |
        sort -u |
        wc -l |
        tr -d ' '
    )"
    issuer_ops="$(
      printf '%s\n%s\n' "$issuer_a_id" "$issuer_b_id" |
        awk 'NF > 0' |
        sort -u |
        wc -l |
        tr -d ' '
    )"
    if (( _ == 1 || _ % 10 == 0 )); then
      echo "[issuer-quorum] progress second=$_/$federation_timeout_sec issuer_ops=${issuer_ops:-0} issuer_keys=${issuer_key_count:-0} a_keys=$issuer_a_keys b_keys=$issuer_b_keys a_id=${issuer_a_id:-<none>} b_id=${issuer_b_id:-<none>}"
    fi
    if [[ "$issuer_a_keys" == "1" && "$issuer_b_keys" == "1" ]] &&
      [[ "$issuer_ops" =~ ^[0-9]+$ ]] &&
      [[ "$issuer_key_count" =~ ^[0-9]+$ ]] &&
      ((issuer_ops >= min_operators)) &&
      ((issuer_key_count >= 2)); then
      issuer_quorum_ok=1
      break
    fi
    sleep 1
  done

  if [[ "$issuer_quorum_ok" -ne 1 ]]; then
    echo "issuer quorum check failed: identity/key floor not reached on issuer feeds"
    echo "required min issuer operators: $min_operators"
    echo "required min distinct issuer keys: 2"
    echo "observed issuer operators: ${issuer_ops:-0}"
    echo "observed distinct issuer keys: ${issuer_key_count:-0}"
    echo "issuer A url: $issuer_a_url id=${issuer_a_id:-<none>} has_keys=${issuer_a_keys:-0}"
    echo "issuer B url: $issuer_b_url id=${issuer_b_id:-<none>} has_keys=${issuer_b_keys:-0}"
    echo "--- issuer A payload ---"
    printf '%s\n' "${issuer_a_payload:-}"
    echo "--- issuer B payload ---"
    printf '%s\n' "${issuer_b_payload:-}"
    if [[ "${issuer_a_id:-}" == "${issuer_b_id:-}" ]]; then
      echo "hint: machine A and B are sharing the same ISSUER_ID; set unique ISSUER_ID/--issuer-id per server."
    fi
    if [[ "${issuer_key_count:-0}" =~ ^[0-9]+$ ]] && ((issuer_key_count < 2)); then
      echo "hint: machine A and B appear to share issuer key material; regenerate issuer data on one machine and restart server-up."
    fi
    exit 1
  fi
fi

client_cmd=(
  "$EASY_NODE_SH" client-test
  --directory-urls "${directory_a},${directory_b}"
  --issuer-url "$issuer_url"
  --entry-url "$entry_url"
  --exit-url "$exit_url"
  --min-sources "$min_sources"
  --timeout-sec "$client_timeout_sec"
  --distinct-operators "$distinct_operators"
  --distinct-countries "$distinct_countries"
  --locality-soft-bias "$locality_soft_bias"
  --country-bias "$locality_country_bias"
  --region-bias "$locality_region_bias"
  --region-prefix-bias "$locality_region_prefix_bias"
  --min-selection-lines "$client_min_selection_lines"
  --min-entry-operators "$client_min_entry_operators"
  --min-exit-operators "$client_min_exit_operators"
  --require-cross-operator-pair "$client_require_cross_operator_pair"
  --beta-profile "$beta_profile"
  --prod-profile "$prod_profile"
)
if [[ -n "$client_subject" ]]; then
  client_cmd+=(--subject "$client_subject")
fi
if [[ -n "$client_anon_cred" ]]; then
  client_cmd+=(--anon-cred "$client_anon_cred")
fi
if [[ -n "$exit_country" ]]; then
  client_cmd+=(--exit-country "$exit_country")
fi
if [[ -n "$exit_region" ]]; then
  client_cmd+=(--exit-region "$exit_region")
fi

docker_host_alias="${THREE_MACHINE_DOCKER_HOST_ALIAS:-host.docker.internal}"
rewrite_loopback_for_docker="${THREE_MACHINE_VALIDATE_REWRITE_LOOPBACK_FOR_DOCKER:-1}"
if [[ "$rewrite_loopback_for_docker" != "0" && "$rewrite_loopback_for_docker" != "1" ]]; then
  echo "THREE_MACHINE_VALIDATE_REWRITE_LOOPBACK_FOR_DOCKER must be 0 or 1"
  exit 2
fi

client_directory_urls="${directory_a},${directory_b}"
container_directory_urls="$client_directory_urls"
container_issuer_url="$issuer_url"
container_entry_url="$entry_url"
container_exit_url="$exit_url"
if [[ "$rewrite_loopback_for_docker" == "1" ]]; then
  container_directory_urls="$(rewrite_url_csv_for_docker "$client_directory_urls" "$docker_host_alias")"
  container_issuer_url="$(rewrite_loopback_url_for_docker "$issuer_url" "$docker_host_alias")"
  container_entry_url="$(rewrite_loopback_url_for_docker "$entry_url" "$docker_host_alias")"
  container_exit_url="$(rewrite_loopback_url_for_docker "$exit_url" "$docker_host_alias")"
fi

if [[ "$container_directory_urls" != "$client_directory_urls" || "$container_issuer_url" != "$issuer_url" || "$container_entry_url" != "$entry_url" || "$container_exit_url" != "$exit_url" ]]; then
  echo "[client-test] docker endpoint rewrite enabled host_alias=$docker_host_alias"
  echo "[client-test] host_urls directory_urls=$client_directory_urls issuer=$issuer_url entry=$entry_url exit=$exit_url"
  echo "[client-test] container_urls directory_urls=$container_directory_urls issuer=$container_issuer_url entry=$container_entry_url exit=$container_exit_url"
fi

env \
  "EASY_NODE_CLIENT_TEST_CONTAINER_DIRECTORY_URLS=$container_directory_urls" \
  "EASY_NODE_CLIENT_TEST_CONTAINER_ISSUER_URL=$container_issuer_url" \
  "EASY_NODE_CLIENT_TEST_CONTAINER_ENTRY_URL=$container_entry_url" \
  "EASY_NODE_CLIENT_TEST_CONTAINER_EXIT_URL=$container_exit_url" \
  "${client_cmd[@]}"

echo "3-machine beta validation check ok"
