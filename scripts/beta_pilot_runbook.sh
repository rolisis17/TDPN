#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/beta_pilot_runbook.sh \
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
    [--rounds N] \
    [--pause-sec N] \
    [--min-sources N] \
    [--min-operators N] \
    [--federation-timeout-sec N] \
    [--timeout-sec N] \
    [--client-min-selection-lines N] \
    [--client-min-entry-operators N] \
    [--client-min-exit-operators N] \
    [--client-require-cross-operator-pair [0|1]] \
    [--distinct-operators [0|1]] \
    [--require-issuer-quorum [0|1]] \
    [--beta-profile [0|1]] \
    [--prod-profile [0|1]] \
    [--bundle-dir PATH]

Purpose:
  Single-command closed-beta pilot run from machine C:
  1) run one strict validation pass,
  2) run multi-round soak,
  3) capture endpoint snapshots and produce a .tar.gz report bundle.
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

snapshot_url() {
  local output_path="$1"
  local url="$2"
  if [[ -z "$url" ]]; then
    return 0
  fi
  if curl -fsS --connect-timeout 4 --max-time 10 "$url" >"$output_path"; then
    echo "[snapshot] ok $url"
  else
    echo "[snapshot] failed $url" | tee -a "$output_path"
  fi
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
rounds="${THREE_MACHINE_SOAK_ROUNDS:-10}"
pause_sec="${THREE_MACHINE_SOAK_PAUSE_SEC:-5}"
min_sources="2"
min_operators="2"
federation_timeout_sec="90"
client_timeout_sec="45"
client_min_selection_lines="${THREE_MACHINE_CLIENT_MIN_SELECTION_LINES:-0}"
client_min_entry_operators="${THREE_MACHINE_CLIENT_MIN_ENTRY_OPERATORS:-0}"
client_min_exit_operators="${THREE_MACHINE_CLIENT_MIN_EXIT_OPERATORS:-0}"
client_require_cross_operator_pair="${THREE_MACHINE_CLIENT_REQUIRE_CROSS_OPERATOR_PAIR:-}"
beta_profile="${THREE_MACHINE_BETA_PROFILE:-1}"
prod_profile="${THREE_MACHINE_PROD_PROFILE:-0}"
distinct_operators="${THREE_MACHINE_DISTINCT_OPERATORS:-}"
require_issuer_quorum="${THREE_MACHINE_REQUIRE_ISSUER_QUORUM:-}"
bundle_dir=""

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
    --subject)
      client_subject="${2:-}"
      shift 2
      ;;
    --anon-cred)
      client_anon_cred="${2:-}"
      shift 2
      ;;
    --rounds)
      rounds="${2:-}"
      shift 2
      ;;
    --pause-sec)
      pause_sec="${2:-}"
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
    --bundle-dir)
      bundle_dir="${2:-}"
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
if [[ -n "$require_issuer_quorum" && "$require_issuer_quorum" != "0" && "$require_issuer_quorum" != "1" ]]; then
  echo "--require-issuer-quorum must be 0 or 1"
  exit 2
fi
if [[ -n "$client_require_cross_operator_pair" && "$client_require_cross_operator_pair" != "0" && "$client_require_cross_operator_pair" != "1" ]]; then
  echo "--client-require-cross-operator-pair must be 0 or 1"
  exit 2
fi
if [[ -n "$client_subject" && -n "$client_anon_cred" ]]; then
  echo "set only one of --subject or --anon-cred"
  exit 2
fi
if ! [[ "$rounds" =~ ^[0-9]+$ && "$pause_sec" =~ ^[0-9]+$ && "$min_sources" =~ ^[0-9]+$ && "$min_operators" =~ ^[0-9]+$ && "$federation_timeout_sec" =~ ^[0-9]+$ && "$client_timeout_sec" =~ ^[0-9]+$ && "$discovery_wait_sec" =~ ^[0-9]+$ && "$client_min_selection_lines" =~ ^[0-9]+$ && "$client_min_entry_operators" =~ ^[0-9]+$ && "$client_min_exit_operators" =~ ^[0-9]+$ ]]; then
  echo "numeric arguments must be integers"
  exit 2
fi
if ((rounds < 1)); then
  echo "--rounds must be >= 1"
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

need_cmd bash
need_cmd curl
need_cmd rg
need_cmd tar
need_cmd date
need_cmd tee
need_cmd timeout

directory_a="$(trim_url "$directory_a")"
directory_b="$(trim_url "$directory_b")"
issuer_url="$(trim_url "$issuer_url")"
issuer_a_url="$(trim_url "$issuer_a_url")"
issuer_b_url="$(trim_url "$issuer_b_url")"
entry_url="$(trim_url "$entry_url")"
exit_url="$(trim_url "$exit_url")"
bootstrap_directory="$(trim_url "$bootstrap_directory")"

if [[ -n "$bootstrap_directory" ]]; then
  bootstrap_scheme=""
  discovered_urls="$(discover_directory_urls "$bootstrap_directory" "$discovery_wait_sec" "$min_sources")"
  bootstrap_scheme="$(url_scheme_from_url "$bootstrap_directory")"
  if [[ -z "$directory_a" ]]; then
    directory_a="$(printf '%s' "$discovered_urls" | cut -d',' -f1)"
  fi
  if [[ -z "$directory_b" ]]; then
    directory_b="$(printf '%s' "$discovered_urls" | cut -d',' -f2)"
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
  echo "set explicit URLs or pass --bootstrap-directory"
  exit 2
fi

if [[ "$require_issuer_quorum" == "1" ]]; then
  if [[ -z "$issuer_a_url" ]]; then
    issuer_a_url="$(url_from_host_port "$(host_from_url "$directory_a")" 8082 "$(url_scheme_from_url "$directory_a")")"
  fi
  if [[ -z "$issuer_b_url" ]]; then
    issuer_b_url="$(url_from_host_port "$(host_from_url "$directory_b")" 8082 "$(url_scheme_from_url "$directory_b")")"
  fi
fi

if [[ -z "$bundle_dir" ]]; then
  bundle_dir="$(default_log_dir)/pilot_bundle_$(date +%Y%m%d_%H%M%S)"
fi
mkdir -p "$bundle_dir"
bundle_dir="$(cd "$bundle_dir" && pwd)"

main_log="$bundle_dir/runbook.log"
exec > >(tee -a "$main_log") 2>&1

echo "[pilot-runbook] started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[pilot-runbook] bundle_dir=$bundle_dir"
echo "[pilot-runbook] beta_profile=$beta_profile prod_profile=$prod_profile rounds=$rounds pause_sec=$pause_sec distinct_operators=$distinct_operators require_issuer_quorum=$require_issuer_quorum"
echo "[pilot-runbook] directory_a=$directory_a directory_b=$directory_b issuer_url=$issuer_url entry_url=$entry_url exit_url=$exit_url"
if [[ -n "$issuer_a_url" || -n "$issuer_b_url" ]]; then
  echo "[pilot-runbook] issuer_a_url=$issuer_a_url issuer_b_url=$issuer_b_url"
fi

cat >"$bundle_dir/metadata.txt" <<EOF
started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
bundle_dir=$bundle_dir
beta_profile=$beta_profile
prod_profile=$prod_profile
distinct_operators=$distinct_operators
require_issuer_quorum=$require_issuer_quorum
directory_a=$directory_a
directory_b=$directory_b
issuer_url=$issuer_url
issuer_a_url=$issuer_a_url
issuer_b_url=$issuer_b_url
entry_url=$entry_url
exit_url=$exit_url
subject=$client_subject
anon_cred_set=$([[ -n "$client_anon_cred" ]] && echo 1 || echo 0)
EOF

validate_cmd=(
  "$ROOT_DIR/scripts/integration_3machine_beta_validate.sh"
  --directory-a "$directory_a"
  --directory-b "$directory_b"
  --issuer-url "$issuer_url"
  --entry-url "$entry_url"
  --exit-url "$exit_url"
  --min-sources "$min_sources"
  --min-operators "$min_operators"
  --federation-timeout-sec "$federation_timeout_sec"
  --timeout-sec "$client_timeout_sec"
  --client-min-selection-lines "$client_min_selection_lines"
  --client-min-entry-operators "$client_min_entry_operators"
  --client-min-exit-operators "$client_min_exit_operators"
  --client-require-cross-operator-pair "$client_require_cross_operator_pair"
  --distinct-operators "$distinct_operators"
  --require-issuer-quorum "$require_issuer_quorum"
  --beta-profile "$beta_profile"
  --prod-profile "$prod_profile"
)
if [[ -n "$issuer_a_url" ]]; then
  validate_cmd+=(--issuer-a-url "$issuer_a_url")
fi
if [[ -n "$issuer_b_url" ]]; then
  validate_cmd+=(--issuer-b-url "$issuer_b_url")
fi
if [[ -n "$client_subject" ]]; then
  validate_cmd+=(--subject "$client_subject")
fi
if [[ -n "$client_anon_cred" ]]; then
  validate_cmd+=(--anon-cred "$client_anon_cred")
fi

validate_log="$bundle_dir/validate.log"
echo "[pilot-runbook] running strict validation"
set +e
"${validate_cmd[@]}" 2>&1 | tee "$validate_log"
validate_rc=${PIPESTATUS[0]}
set -e
if [[ "$validate_rc" -ne 0 ]]; then
  echo "[pilot-runbook] validation failed rc=$validate_rc"
  exit "$validate_rc"
fi
echo "[pilot-runbook] validation ok"

soak_log="$bundle_dir/soak.log"
soak_cmd=(
  "$ROOT_DIR/scripts/integration_3machine_beta_soak.sh"
  --directory-a "$directory_a"
  --directory-b "$directory_b"
  --issuer-url "$issuer_url"
  --entry-url "$entry_url"
  --exit-url "$exit_url"
  --rounds "$rounds"
  --pause-sec "$pause_sec"
  --min-sources "$min_sources"
  --min-operators "$min_operators"
  --federation-timeout-sec "$federation_timeout_sec"
  --timeout-sec "$client_timeout_sec"
  --client-min-selection-lines "$client_min_selection_lines"
  --client-min-entry-operators "$client_min_entry_operators"
  --client-min-exit-operators "$client_min_exit_operators"
  --client-require-cross-operator-pair "$client_require_cross_operator_pair"
  --distinct-operators "$distinct_operators"
  --require-issuer-quorum "$require_issuer_quorum"
  --beta-profile "$beta_profile"
  --prod-profile "$prod_profile"
  --report-file "$soak_log"
)
if [[ -n "$issuer_a_url" ]]; then
  soak_cmd+=(--issuer-a-url "$issuer_a_url")
fi
if [[ -n "$issuer_b_url" ]]; then
  soak_cmd+=(--issuer-b-url "$issuer_b_url")
fi
if [[ -n "$client_subject" ]]; then
  soak_cmd+=(--subject "$client_subject")
fi
if [[ -n "$client_anon_cred" ]]; then
  soak_cmd+=(--anon-cred "$client_anon_cred")
fi

echo "[pilot-runbook] running soak rounds"
set +e
"${soak_cmd[@]}"
soak_rc=$?
set -e
if [[ "$soak_rc" -ne 0 ]]; then
  echo "[pilot-runbook] soak failed rc=$soak_rc"
  exit "$soak_rc"
fi
echo "[pilot-runbook] soak ok"

mkdir -p "$bundle_dir/snapshots"
snapshot_url "$bundle_dir/snapshots/directory_a_relays.json" "${directory_a}/v1/relays"
snapshot_url "$bundle_dir/snapshots/directory_b_relays.json" "${directory_b}/v1/relays"
snapshot_url "$bundle_dir/snapshots/directory_a_peers.json" "${directory_a}/v1/peers"
snapshot_url "$bundle_dir/snapshots/directory_b_peers.json" "${directory_b}/v1/peers"
snapshot_url "$bundle_dir/snapshots/issuer_pubkeys.json" "${issuer_url}/v1/pubkeys"
snapshot_url "$bundle_dir/snapshots/entry_health.json" "${entry_url}/v1/health"
snapshot_url "$bundle_dir/snapshots/exit_health.json" "${exit_url}/v1/health"
if [[ -n "$issuer_a_url" ]]; then
  snapshot_url "$bundle_dir/snapshots/issuer_a_pubkeys.json" "${issuer_a_url}/v1/pubkeys"
fi
if [[ -n "$issuer_b_url" ]]; then
  snapshot_url "$bundle_dir/snapshots/issuer_b_pubkeys.json" "${issuer_b_url}/v1/pubkeys"
fi

bundle_tar="${bundle_dir}.tar.gz"
tar -czf "$bundle_tar" -C "$(dirname "$bundle_dir")" "$(basename "$bundle_dir")"
echo "[pilot-runbook] report bundle ready: $bundle_tar"
echo "[pilot-runbook] done"
