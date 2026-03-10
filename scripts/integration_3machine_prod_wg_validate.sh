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
  sudo ./scripts/integration_3machine_prod_wg_validate.sh \
    [--directory-a URL] \
    [--directory-b URL] \
    [--bootstrap-directory URL] \
    [--discovery-wait-sec N] \
    [--issuer-url URL] \
    [--entry-url URL] \
    [--exit-url URL] \
    [--exit-a-url URL] \
    [--exit-b-url URL] \
    [--subject ID] \
    [--anon-cred TOKEN] \
    [--min-sources N] \
    [--min-operators N] \
    [--federation-timeout-sec N] \
    [--control-timeout-sec N] \
    [--client-timeout-sec N] \
    [--wg-session-sec N] \
    [--client-iface IFACE] \
    [--client-proxy-addr HOST:PORT] \
    [--client-inner-source udp|synthetic] \
    [--inject-attempts N] \
    [--strict-distinct [0|1]] \
    [--skip-control-plane-check [0|1]] \
    [--mtls-ca-file PATH] \
    [--mtls-client-cert-file PATH] \
    [--mtls-client-key-file PATH] \
    [--summary-json PATH] \
    [--report-file PATH]

Purpose:
  Run from machine C (Linux root) to validate real cross-machine
  production-profile WireGuard dataplane over a live network.
  This runs a real client role (`go run ./cmd/node --client`) with:
  - PROD_STRICT_MODE=1 + BETA_STRICT_MODE=1
  - command WG backend + kernel proxy + live WG mode
  - mTLS enabled
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

wait_http_ok() {
  local url="$1"
  local name="$2"
  local attempts="$3"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS --connect-timeout 2 --max-time 5 "$url" >/dev/null 2>&1; then
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

metric_int_field() {
  local payload="$1"
  local field="$2"
  local value
  value="$(printf '%s\n' "$payload" | rg -o "\"${field}\"[[:space:]]*:[[:space:]]*[0-9]+" | head -n1 | sed -E 's/.*:[[:space:]]*([0-9]+)$/\1/' || true)"
  if [[ -z "$value" || ! "$value" =~ ^[0-9]+$ ]]; then
    echo "0"
    return
  fi
  echo "$value"
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

looks_loopback() {
  local value="$1"
  [[ "$value" == *"127.0.0.1"* || "$value" == *"localhost"* ]]
}

assert_port_free_udp() {
  local addr="$1"
  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi
  local port="${addr##*:}"
  if [[ ! "$port" =~ ^[0-9]+$ ]]; then
    return 0
  fi
  local matches
  matches="$(ss -H -lun | awk -v p=":$port" '$5 ~ p"$" || $5 ~ p"[^0-9]" {print}')"
  if [[ -n "$matches" ]]; then
    echo "preflight failed: client proxy port ${port}/udp already in use"
    echo "$matches"
    exit 1
  fi
}

directory_a=""
directory_b=""
bootstrap_directory=""
discovery_wait_sec="${THREE_MACHINE_DISCOVERY_WAIT_SEC:-12}"
issuer_url=""
entry_url=""
exit_url=""
exit_a_url=""
exit_b_url=""
client_subject="${CLIENT_SUBJECT:-}"
client_anon_cred="${CLIENT_ANON_CRED:-}"
min_sources="2"
min_operators="2"
federation_timeout_sec="90"
control_timeout_sec="50"
client_timeout_sec="120"
wg_session_sec="45"
client_iface="${CLIENT_IFACE:-wgcprod0}"
client_proxy_addr="${CLIENT_PROXY_ADDR:-127.0.0.1:57990}"
client_inner_source="${THREE_MACHINE_PROD_WG_CLIENT_INNER_SOURCE:-udp}"
inject_attempts="8"
strict_distinct="${CLIENT_REQUIRE_DISTINCT_OPERATORS:-1}"
skip_control_plane_check="0"
mtls_ca_file="${MTLS_CA_FILE:-$ROOT_DIR/deploy/tls/ca.crt}"
mtls_client_cert_file="${MTLS_CLIENT_CERT_FILE:-$ROOT_DIR/deploy/tls/client.crt}"
mtls_client_key_file="${MTLS_CLIENT_KEY_FILE:-$ROOT_DIR/deploy/tls/client.key}"
summary_json="${THREE_MACHINE_PROD_WG_VALIDATE_SUMMARY_JSON:-}"
report_file=""

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
    --entry-url)
      entry_url="${2:-}"
      shift 2
      ;;
    --exit-url)
      exit_url="${2:-}"
      shift 2
      ;;
    --exit-a-url)
      exit_a_url="${2:-}"
      shift 2
      ;;
    --exit-b-url)
      exit_b_url="${2:-}"
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
    --control-timeout-sec)
      control_timeout_sec="${2:-}"
      shift 2
      ;;
    --client-timeout-sec)
      client_timeout_sec="${2:-}"
      shift 2
      ;;
    --wg-session-sec)
      wg_session_sec="${2:-}"
      shift 2
      ;;
    --client-iface)
      client_iface="${2:-}"
      shift 2
      ;;
    --client-proxy-addr)
      client_proxy_addr="${2:-}"
      shift 2
      ;;
    --client-inner-source)
      client_inner_source="${2:-}"
      shift 2
      ;;
    --inject-attempts)
      inject_attempts="${2:-}"
      shift 2
      ;;
    --strict-distinct)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        strict_distinct="${2:-}"
        shift 2
      else
        strict_distinct="1"
        shift
      fi
      ;;
    --skip-control-plane-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        skip_control_plane_check="${2:-}"
        shift 2
      else
        skip_control_plane_check="1"
        shift
      fi
      ;;
    --mtls-ca-file)
      mtls_ca_file="${2:-}"
      shift 2
      ;;
    --mtls-client-cert-file)
      mtls_client_cert_file="${2:-}"
      shift 2
      ;;
    --mtls-client-key-file)
      mtls_client_key_file="${2:-}"
      shift 2
      ;;
    --report-file)
      report_file="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
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

if [[ -n "$client_subject" && -n "$client_anon_cred" ]]; then
  echo "set only one of --subject or --anon-cred"
  exit 2
fi
if [[ "$strict_distinct" != "0" && "$strict_distinct" != "1" ]]; then
  echo "--strict-distinct must be 0 or 1"
  exit 2
fi
if [[ "$client_inner_source" != "udp" && "$client_inner_source" != "synthetic" ]]; then
  echo "--client-inner-source must be udp or synthetic"
  exit 2
fi
if [[ "$skip_control_plane_check" != "0" && "$skip_control_plane_check" != "1" ]]; then
  echo "--skip-control-plane-check must be 0 or 1"
  exit 2
fi
if ! [[ "$discovery_wait_sec" =~ ^[0-9]+$ && "$min_sources" =~ ^[0-9]+$ && "$min_operators" =~ ^[0-9]+$ && "$federation_timeout_sec" =~ ^[0-9]+$ && "$control_timeout_sec" =~ ^[0-9]+$ && "$client_timeout_sec" =~ ^[0-9]+$ && "$wg_session_sec" =~ ^[0-9]+$ && "$inject_attempts" =~ ^[0-9]+$ ]]; then
  echo "numeric options must be integers"
  exit 2
fi
if ((client_timeout_sec < 40)); then
  echo "--client-timeout-sec must be >= 40"
  exit 2
fi
if ((wg_session_sec < 10)); then
  echo "--wg-session-sec must be >= 10"
  exit 2
fi
if ((inject_attempts < 1)); then
  echo "--inject-attempts must be >= 1"
  exit 2
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this script requires Linux (wireguard kernel interface support)"
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: sudo ./scripts/integration_3machine_prod_wg_validate.sh"
  exit 2
fi

for cmd in go wg ip curl rg timeout perl awk sed; do
  need_cmd "$cmd"
done
if ! command -v docker >/dev/null 2>&1; then
  echo "missing required command: docker"
  exit 2
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "missing required dependency: docker compose plugin"
  exit 2
fi

if [[ -z "$report_file" ]]; then
  report_file="$(default_log_dir)/privacynode_3machine_prod_wg_validate_$(date +%Y%m%d_%H%M%S).log"
fi
mkdir -p "$(dirname "$report_file")"
exec > >(tee -a "$report_file") 2>&1

echo "[3machine-prod-wg] started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[3machine-prod-wg] report: $report_file"
echo "[3machine-prod-wg] client_inner_source=$client_inner_source"
if [[ -z "$summary_json" ]]; then
  summary_json="${report_file%.log}.summary.json"
fi
echo "[3machine-prod-wg] summary_json=$summary_json"

validate_started_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
validate_status="fail"
validate_failed_step=""
summary_written="0"
node_pid=""
client_key_dir=""
client_log=""
baseline_accepted_a="0"
baseline_accepted_b="0"
latest_accepted_a="0"
latest_accepted_b="0"
selection_lines="0"
client_uplink_summary_observed="0"
hs="0"
rx="0"
tx="0"
exit_wg_pub=""

fail_step() {
  local step="$1"
  shift
  validate_failed_step="$step"
  echo "$*"
  exit 1
}

cleanup_resources() {
  if [[ -n "${node_pid:-}" ]]; then
    kill "$node_pid" >/dev/null 2>&1 || true
    wait "$node_pid" >/dev/null 2>&1 || true
  fi
  ip link delete "$client_iface" >/dev/null 2>&1 || true
  if [[ -n "${client_key_dir:-}" ]]; then
    rm -rf "$client_key_dir"
  fi
}

write_summary_once() {
  local finished_at_utc delta_a delta_b delta_total
  if [[ "$summary_written" == "1" ]]; then
    return
  fi
  mkdir -p "$(dirname "$summary_json")"
  finished_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  delta_a=$((latest_accepted_a - baseline_accepted_a))
  delta_b=$((latest_accepted_b - baseline_accepted_b))
  delta_total=$((delta_a + delta_b))
  if [[ "$delta_a" -lt 0 ]]; then
    delta_a=0
  fi
  if [[ "$delta_b" -lt 0 ]]; then
    delta_b=0
  fi
  if [[ "$delta_total" -lt 0 ]]; then
    delta_total=0
  fi

  {
    echo "{"
    echo "  \"status\": \"$(json_escape "$validate_status")\","
    echo "  \"failed_step\": \"$(json_escape "$validate_failed_step")\","
    echo "  \"started_at_utc\": \"$(json_escape "$validate_started_at_utc")\","
    echo "  \"finished_at_utc\": \"$(json_escape "$finished_at_utc")\","
    echo "  \"report_file\": \"$(json_escape "$report_file")\","
    echo "  \"summary_json\": \"$(json_escape "$summary_json")\","
    echo "  \"client_log\": \"$(json_escape "$client_log")\","
    echo "  \"directory_a\": \"$(json_escape "$directory_a")\","
    echo "  \"directory_b\": \"$(json_escape "$directory_b")\","
    echo "  \"issuer_url\": \"$(json_escape "$issuer_url")\","
    echo "  \"entry_url\": \"$(json_escape "$entry_url")\","
    echo "  \"exit_url\": \"$(json_escape "$exit_url")\","
    echo "  \"exit_a_url\": \"$(json_escape "$exit_a_url")\","
    echo "  \"exit_b_url\": \"$(json_escape "$exit_b_url")\","
    echo "  \"strict_distinct\": $strict_distinct,"
    echo "  \"client_inner_source\": \"$(json_escape "$client_inner_source")\","
    echo "  \"control_plane_check_skipped\": $skip_control_plane_check,"
    echo "  \"baseline\": {"
    echo "    \"exit_a_accepted_packets\": $baseline_accepted_a,"
    echo "    \"exit_b_accepted_packets\": $baseline_accepted_b"
    echo "  },"
    echo "  \"latest\": {"
    echo "    \"exit_a_accepted_packets\": $latest_accepted_a,"
    echo "    \"exit_b_accepted_packets\": $latest_accepted_b"
    echo "  },"
    echo "  \"deltas\": {"
    echo "    \"exit_a_accepted_packets\": $delta_a,"
    echo "    \"exit_b_accepted_packets\": $delta_b,"
    echo "    \"accepted_packets_total\": $delta_total"
    echo "  },"
    echo "  \"wireguard\": {"
    echo "    \"client_iface\": \"$(json_escape "$client_iface")\","
    echo "    \"client_proxy_addr\": \"$(json_escape "$client_proxy_addr")\","
    echo "    \"exit_peer_pubkey\": \"$(json_escape "$exit_wg_pub")\","
    echo "    \"handshake_epoch\": $hs,"
    echo "    \"rx_bytes\": $rx,"
    echo "    \"tx_bytes\": $tx"
    echo "  },"
    echo "  \"selection_summary_lines\": $selection_lines,"
    echo "  \"client_uplink_summary_observed\": $client_uplink_summary_observed"
    echo "}"
  } >"$summary_json"

  summary_written="1"
}

on_exit_3machine_prod_wg() {
  local rc=$?
  if [[ "$rc" -eq 0 ]]; then
    validate_status="ok"
  else
    validate_status="fail"
    if [[ -z "$validate_failed_step" ]]; then
      validate_failed_step="runtime"
    fi
  fi
  write_summary_once
  cleanup_resources
  return "$rc"
}
trap 'on_exit_3machine_prod_wg' EXIT

directory_a="$(trim_url "$directory_a")"
directory_b="$(trim_url "$directory_b")"
bootstrap_directory="$(trim_url "$bootstrap_directory")"
issuer_url="$(trim_url "$issuer_url")"
entry_url="$(trim_url "$entry_url")"
exit_url="$(trim_url "$exit_url")"
exit_a_url="$(trim_url "$exit_a_url")"
exit_b_url="$(trim_url "$exit_b_url")"

if [[ -n "$bootstrap_directory" ]]; then
  bootstrap_scheme="$(url_scheme_from_url "$bootstrap_directory")"
  discovered="$(discover_directory_urls "$bootstrap_directory" "$discovery_wait_sec" "$min_sources")"
  if [[ -z "$directory_a" ]]; then
    directory_a="$(printf '%s' "$discovered" | cut -d',' -f1)"
  fi
  if [[ -z "$directory_b" ]]; then
    directory_b="$(printf '%s' "$discovered" | cut -d',' -f2)"
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
  fail_step "config_endpoints" "missing required endpoints (set --directory-a/--directory-b/--issuer-url/--entry-url/--exit-url or use --bootstrap-directory)"
fi

if [[ -z "$exit_a_url" ]]; then
  exit_a_url="$(url_from_host_port "$(host_from_url "$directory_a")" 8084 "$(url_scheme_from_url "$directory_a")")"
fi
if [[ -z "$exit_b_url" ]]; then
  exit_b_url="$(url_from_host_port "$(host_from_url "$directory_b")" 8084 "$(url_scheme_from_url "$directory_b")")"
fi

for f in "$mtls_ca_file" "$mtls_client_cert_file" "$mtls_client_key_file"; do
  if [[ ! -f "$f" ]]; then
    fail_step "config_mtls" "missing mTLS file: $f"
  fi
done

for endpoint in "$directory_a" "$directory_b" "$issuer_url" "$entry_url" "$exit_url" "$exit_a_url" "$exit_b_url"; do
  if looks_loopback "$endpoint"; then
    echo "warning: loopback URL detected: $endpoint"
    echo "         for real cross-machine validation use reachable A/B endpoints."
  fi
done

wait_http_ok "${directory_a}/v1/relays" "directory A" 20 || fail_step "control_plane_health" "directory A did not become healthy at ${directory_a}/v1/relays"
wait_http_ok "${directory_b}/v1/relays" "directory B" 20 || fail_step "control_plane_health" "directory B did not become healthy at ${directory_b}/v1/relays"
wait_http_ok "${issuer_url}/v1/pubkeys" "issuer" 20 || fail_step "control_plane_health" "issuer did not become healthy at ${issuer_url}/v1/pubkeys"
wait_http_ok "${entry_url}/v1/health" "entry" 20 || fail_step "control_plane_health" "entry did not become healthy at ${entry_url}/v1/health"
wait_http_ok "${exit_url}/v1/health" "exit" 20 || fail_step "control_plane_health" "exit did not become healthy at ${exit_url}/v1/health"
wait_http_ok "${exit_a_url}/v1/metrics" "exit A metrics" 20 || fail_step "control_plane_health" "exit A metrics did not become healthy at ${exit_a_url}/v1/metrics"
wait_http_ok "${exit_b_url}/v1/metrics" "exit B metrics" 20 || fail_step "control_plane_health" "exit B metrics did not become healthy at ${exit_b_url}/v1/metrics"

baseline_metrics_a="$(curl -fsS "${exit_a_url}/v1/metrics" 2>/dev/null || true)"
baseline_metrics_b="$(curl -fsS "${exit_b_url}/v1/metrics" 2>/dev/null || true)"
baseline_accepted_a="$(metric_int_field "$baseline_metrics_a" "accepted_packets")"
baseline_accepted_b="$(metric_int_field "$baseline_metrics_b" "accepted_packets")"
echo "[3machine-prod-wg] baseline accepted_packets: exit_a=$baseline_accepted_a exit_b=$baseline_accepted_b"

if [[ "$skip_control_plane_check" == "0" ]]; then
  echo "[3machine-prod-wg] running control-plane precheck via integration_3machine_beta_validate.sh"
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
    --timeout-sec "$control_timeout_sec"
    --client-min-selection-lines 1
    --client-min-entry-operators 1
    --client-min-exit-operators 1
    --client-require-cross-operator-pair 0
    --distinct-operators "$strict_distinct"
    --require-issuer-quorum 1
    --beta-profile 1
    --prod-profile 1
  )
  if [[ -n "$client_subject" ]]; then
    validate_cmd+=(--subject "$client_subject")
  fi
  if [[ -n "$client_anon_cred" ]]; then
    validate_cmd+=(--anon-cred "$client_anon_cred")
  fi
  if ! "${validate_cmd[@]}"; then
    fail_step "control_plane_precheck" "control-plane precheck failed"
  fi
fi

client_log="$(dirname "$report_file")/privacynode_3machine_prod_wg_client_$(date +%Y%m%d_%H%M%S).log"
client_key_dir="$(mktemp -d)"
client_key_file="$client_key_dir/client.key"
client_pub_file="$client_key_dir/client.pub"

assert_port_free_udp "$client_proxy_addr"
ip link delete "$client_iface" >/dev/null 2>&1 || true
if ! ip link add dev "$client_iface" type wireguard >/dev/null 2>&1; then
  fail_step "wg_interface_create" "failed to create wireguard interface $client_iface"
fi

wg genkey >"$client_key_file"
chmod 600 "$client_key_file"
wg pubkey <"$client_key_file" >"$client_pub_file"
client_wg_pub="$(tr -d '\r\n' <"$client_pub_file")"
if [[ -z "$client_wg_pub" ]]; then
  fail_step "wg_client_key" "failed to derive client WG public key"
fi

rm -f "$client_log"
echo "[3machine-prod-wg] launching real client role (log=$client_log)"
env \
  DATA_PLANE_MODE=opaque \
  DIRECTORY_URLS="${directory_a},${directory_b}" \
  DIRECTORY_MIN_SOURCES="$min_sources" \
  CLIENT_DIRECTORY_MIN_OPERATORS="$min_operators" \
  DIRECTORY_TRUST_STRICT=1 \
  DIRECTORY_TRUST_TOFU=0 \
  ISSUER_URL="$issuer_url" \
  ENTRY_URL="$entry_url" \
  EXIT_CONTROL_URL="$exit_url" \
  CLIENT_SUBJECT="$client_subject" \
  CLIENT_ANON_CRED="$client_anon_cred" \
  CLIENT_REQUIRE_DISTINCT_OPERATORS="$strict_distinct" \
  CLIENT_WG_BACKEND=command \
  CLIENT_WG_INTERFACE="$client_iface" \
  CLIENT_WG_PRIVATE_KEY_PATH="$client_key_file" \
  CLIENT_WG_PUBLIC_KEY="$client_wg_pub" \
  CLIENT_WG_ALLOWED_IPS=0.0.0.0/0 \
  CLIENT_WG_INSTALL_ROUTE=0 \
  CLIENT_WG_KERNEL_PROXY=1 \
  CLIENT_WG_PROXY_ADDR="$client_proxy_addr" \
  CLIENT_INNER_SOURCE="$client_inner_source" \
  CLIENT_DISABLE_SYNTHETIC_FALLBACK=1 \
  CLIENT_LIVE_WG_MODE=1 \
  CLIENT_OPAQUE_SESSION_SEC="$wg_session_sec" \
  CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS=12000 \
  CLIENT_BOOTSTRAP_INTERVAL_SEC=2 \
  CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC=4 \
  CLIENT_BOOTSTRAP_JITTER_PCT=10 \
  CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC=0 \
  CLIENT_STARTUP_SYNC_TIMEOUT_SEC=15 \
  CLIENT_PATH_OPEN_MAX_ATTEMPTS=4 \
  BETA_STRICT_MODE=1 \
  PROD_STRICT_MODE=1 \
  MTLS_ENABLE=1 \
  MTLS_CA_FILE="$mtls_ca_file" \
  MTLS_CLIENT_CERT_FILE="$mtls_client_cert_file" \
  MTLS_CLIENT_KEY_FILE="$mtls_client_key_file" \
  MTLS_CERT_FILE="$mtls_client_cert_file" \
  MTLS_KEY_FILE="$mtls_client_key_file" \
  timeout "${client_timeout_sec}s" go run ./cmd/node --client >"$client_log" 2>&1 &
node_pid=$!

ready=0
for _ in $(seq 1 300); do
  if ! kill -0 "$node_pid" >/dev/null 2>&1; then
    cat "$client_log"
    fail_step "client_startup" "client process exited before session setup"
  fi
  if rg -q "client received wg-session config:" "$client_log"; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ "$ready" -ne 1 ]]; then
  cat "$client_log"
  fail_step "client_session_config" "client did not reach wg session config stage"
fi

exit_wg_pub="$(rg -o 'exit_pub=[^ ]+' "$client_log" | tail -n 1 | sed -E 's/^exit_pub=//' | tr -d '\r\n')"
if [[ -z "$exit_wg_pub" ]]; then
  cat "$client_log"
  fail_step "wg_peer_parse" "unable to parse exit wg public key from client log"
fi

peer_ok=0
for _ in $(seq 1 120); do
  if wg show "$client_iface" peers | grep -Fqx -- "$exit_wg_pub"; then
    peer_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$peer_ok" -ne 1 ]]; then
  wg show "$client_iface" || true
  cat "$client_log"
  fail_step "wg_peer_check" "client interface missing expected exit peer $exit_wg_pub"
fi

endpoint_ok=0
for _ in $(seq 1 120); do
  if wg show "$client_iface" endpoints | awk -v key="$exit_wg_pub" -v ep="$client_proxy_addr" '
    $1 == key && $2 == ep { found = 1 }
    END { exit(found ? 0 : 1) }
  '; then
    endpoint_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$endpoint_ok" -ne 1 ]]; then
  wg show "$client_iface" endpoints || true
  cat "$client_log"
  fail_step "wg_endpoint_check" "client interface endpoint was not set to proxy addr $client_proxy_addr"
fi

for _ in $(seq 1 "$inject_attempts"); do
  perl -MIO::Socket::INET -e '
    my $target = shift @ARGV;
    my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or exit 1;
    my $pkt = pack("C4", 4, 0, 0, 0) . ("\0" x 28);
    print {$sock} $pkt or exit 1;
  ' "$client_proxy_addr"
  sleep 0.1
done

hs_ok=0
for _ in $(seq 1 180); do
  hs="$(wg show "$client_iface" latest-handshakes | awk -v key="$exit_wg_pub" '$1 == key { print $2 }')"
  rx="$(wg show "$client_iface" transfer | awk -v key="$exit_wg_pub" '$1 == key { print $2 }')"
  tx="$(wg show "$client_iface" transfer | awk -v key="$exit_wg_pub" '$1 == key { print $3 }')"
  if [[ "${hs:-0}" -gt 0 ]] && { [[ "${rx:-0}" -gt 0 ]] || [[ "${tx:-0}" -gt 0 ]]; }; then
    hs_ok=1
    break
  fi
  sleep 0.25
done
if [[ "$hs_ok" -ne 1 ]]; then
  wg show "$client_iface" latest-handshakes || true
  wg show "$client_iface" transfer || true
  cat "$client_log"
  fail_step "wg_handshake" "wireguard handshake/transfer did not become active on client iface"
fi

selected_ok=0
for _ in $(seq 1 120); do
  if rg -q "client selected entry=.* entry_op=.* exit=.* exit_op=.*" "$client_log"; then
    selected_ok=1
    break
  fi
  sleep 0.25
done
if [[ "$selected_ok" -ne 1 ]]; then
  cat "$client_log"
  fail_step "selection_summary" "client did not emit selection summary lines"
fi

if [[ "$strict_distinct" == "1" ]]; then
  if rg 'client selected entry=' "$client_log" | awk '
      {
        entry_op = ""; exit_op = "";
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^entry_op=/) entry_op = substr($i, 10);
          if ($i ~ /^exit_op=/) exit_op = substr($i, 9);
        }
        if (entry_op != "" && exit_op != "" && entry_op == exit_op) {
          bad = 1;
        }
      }
      END { exit(bad ? 0 : 1) }
    '; then
    echo "strict distinct check failed: found same operator for entry and exit"
    rg 'client selected entry=' "$client_log" || true
    fail_step "selection_distinct" "strict distinct check failed: found same operator for entry and exit"
  fi
fi

metrics_ok=0
latest_metrics_a=""
latest_metrics_b=""
latest_accepted_a="$baseline_accepted_a"
latest_accepted_b="$baseline_accepted_b"
for _ in $(seq 1 180); do
  latest_metrics_a="$(curl -fsS "${exit_a_url}/v1/metrics" 2>/dev/null || true)"
  latest_metrics_b="$(curl -fsS "${exit_b_url}/v1/metrics" 2>/dev/null || true)"
  latest_accepted_a="$(metric_int_field "$latest_metrics_a" "accepted_packets")"
  latest_accepted_b="$(metric_int_field "$latest_metrics_b" "accepted_packets")"
  if ((latest_accepted_a > baseline_accepted_a || latest_accepted_b > baseline_accepted_b)); then
    metrics_ok=1
    break
  fi
  sleep 0.25
done
if [[ "$metrics_ok" -ne 1 ]]; then
  echo "exit metrics did not advance accepted_packets on A or B"
  echo "baseline: exit_a=${baseline_accepted_a} exit_b=${baseline_accepted_b}"
  echo "latest:   exit_a=${latest_accepted_a} exit_b=${latest_accepted_b}"
  echo "exit A metrics: $latest_metrics_a"
  echo "exit B metrics: $latest_metrics_b"
  cat "$client_log"
  fail_step "dataplane_metrics" "exit metrics did not advance accepted_packets on A or B"
fi

if rg -q "client wg-kernel proxy uplink packets=[1-9][0-9]*" "$client_log"; then
  client_uplink_summary_observed="1"
  echo "[3machine-prod-wg] client uplink summary observed"
else
  client_uplink_summary_observed="0"
  echo "[3machine-prod-wg] note: client uplink summary log not observed before completion (metrics/handshake still verified)"
fi

selection_lines="$(rg -c 'client selected entry=' "$client_log" || true)"
if [[ -z "$selection_lines" || ! "$selection_lines" =~ ^[0-9]+$ ]]; then
  selection_lines="0"
fi

echo "[3machine-prod-wg] client log: $client_log"
echo "[3machine-prod-wg] key selection lines:"
rg 'client selected entry=' "$client_log" || true
delta_a=$((latest_accepted_a - baseline_accepted_a))
delta_b=$((latest_accepted_b - baseline_accepted_b))
delta_total=$((delta_a + delta_b))
echo "[3machine-prod-wg] dataplane-summary handshake_epoch=${hs:-0} rx_bytes=${rx:-0} tx_bytes=${tx:-0} exit_a_accepted_packets=${latest_accepted_a} exit_b_accepted_packets=${latest_accepted_b} accepted_delta_a=${delta_a} accepted_delta_b=${delta_b} accepted_delta_total=${delta_total}"
echo "[3machine-prod-wg] success"
echo "[3machine-prod-wg] summary: $summary_json"
validate_status="ok"
