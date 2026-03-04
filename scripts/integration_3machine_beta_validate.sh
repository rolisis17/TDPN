#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

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
    [--distinct-operators [0|1]] \
    [--require-issuer-quorum [0|1]] \
    [--beta-profile [0|1]]

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
  printf 'http://%s:%s' "$(normalize_host_for_endpoint "$host")" "$port"
}

discover_directory_urls() {
  local bootstrap_url="$1"
  local wait_sec="${2:-12}"
  local min_hosts="${3:-2}"
  local seed_host
  bootstrap_url="$(trim_url "$bootstrap_url")"
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
    out+=("$(url_from_host_port "$seed_host" 8081)")
    unset 'seen_hosts[$seed_host]'
  fi
  local sorted_hosts
  sorted_hosts="$(printf '%s\n' "${!seen_hosts[@]}" | awk 'NF > 0' | sort -u)"
  while IFS= read -r h; do
    [[ -z "$h" ]] && continue
    out+=("$(url_from_host_port "$h" 8081)")
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
beta_profile="${THREE_MACHINE_BETA_PROFILE:-1}"
distinct_operators="${THREE_MACHINE_DISTINCT_OPERATORS:-}"
require_issuer_quorum="${THREE_MACHINE_REQUIRE_ISSUER_QUORUM:-}"

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
    --distinct-operators)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        distinct_operators="${2:-}"
        shift 2
      else
        distinct_operators="1"
        shift
      fi
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

if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
  echo "--beta-profile must be 0 or 1"
  exit 2
fi
if [[ -n "$distinct_operators" && "$distinct_operators" != "0" && "$distinct_operators" != "1" ]]; then
  echo "--distinct-operators must be 0 or 1"
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

if ! [[ "$min_sources" =~ ^[0-9]+$ && "$min_operators" =~ ^[0-9]+$ && "$federation_timeout_sec" =~ ^[0-9]+$ && "$client_timeout_sec" =~ ^[0-9]+$ && "$discovery_wait_sec" =~ ^[0-9]+$ && "$client_min_selection_lines" =~ ^[0-9]+$ && "$client_min_entry_operators" =~ ^[0-9]+$ && "$client_min_exit_operators" =~ ^[0-9]+$ ]]; then
  echo "--min-sources, --min-operators, --federation-timeout-sec, --timeout-sec, --discovery-wait-sec and client diversity thresholds must be numeric"
  exit 2
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
  bootstrap_directory="$(trim_url "$bootstrap_directory")"
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
    issuer_url="$(url_from_host_port "$bootstrap_host" 8082)"
  fi
  if [[ -z "$entry_url" && -n "$bootstrap_host" ]]; then
    entry_url="$(url_from_host_port "$bootstrap_host" 8083)"
  fi
  if [[ -z "$exit_url" && -n "$bootstrap_host" ]]; then
    exit_url="$(url_from_host_port "$bootstrap_host" 8084)"
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
  issuer_a_url="$(url_from_host_port "$(host_from_url "$directory_a")" 8082)"
fi
if [[ -z "$issuer_b_url" ]]; then
  issuer_b_url="$(url_from_host_port "$(host_from_url "$directory_b")" 8082)"
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
  ./scripts/easy_node.sh client-test
  --directory-urls "${directory_a},${directory_b}"
  --issuer-url "$issuer_url"
  --entry-url "$entry_url"
  --exit-url "$exit_url"
  --min-sources "$min_sources"
  --timeout-sec "$client_timeout_sec"
  --distinct-operators "$distinct_operators"
  --min-selection-lines "$client_min_selection_lines"
  --min-entry-operators "$client_min_entry_operators"
  --min-exit-operators "$client_min_exit_operators"
  --require-cross-operator-pair "$client_require_cross_operator_pair"
  --beta-profile "$beta_profile"
)
if [[ -n "$exit_country" ]]; then
  client_cmd+=(--exit-country "$exit_country")
fi
if [[ -n "$exit_region" ]]; then
  client_cmd+=(--exit-region "$exit_region")
fi

"${client_cmd[@]}"

echo "3-machine beta validation check ok"
