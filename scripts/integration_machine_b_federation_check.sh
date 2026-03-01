#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT_DIR/deploy"
SERVER_ENV_FILE="$DEPLOY_DIR/.env.easy.server"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/integration_machine_b_federation_check.sh \
    --peer-directory-a URL \
    [--public-host HOST] \
    [--min-operators N] \
    [--federation-timeout-sec N] \
    [--report-file PATH]

Purpose:
  Run on machine B (server+federation host). Validates:
  - local docker services are running
  - local endpoints are healthy
  - machine A directory is reachable
  - machine B directory converges to at least N distinct operators
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

compose_server() {
  if [[ -f "$SERVER_ENV_FILE" ]]; then
    (cd "$DEPLOY_DIR" && docker compose --env-file "$SERVER_ENV_FILE" "$@")
  else
    (cd "$DEPLOY_DIR" && docker compose "$@")
  fi
}

wait_http_ok() {
  local url="$1"
  local name="$2"
  local attempts="${3:-30}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "$name did not become healthy at $url"
  return 1
}

trim_url() {
  local value="$1"
  while [[ "$value" == */ ]]; do
    value="${value%/}"
  done
  echo "$value"
}

extract_operators() {
  local payload="$1"
  local matches
  matches="$(printf '%s\n' "$payload" | rg -o '"operator":"[^"]+"' || true)"
  printf '%s\n' "$matches" |
    sed -E 's/^"operator":"([^"]+)"$/\1/' |
    awk 'NF > 0' |
    sort -u
}

operator_count_from_url() {
  local base_url
  base_url="$(trim_url "$1")"
  local payload
  payload="$(curl -fsS "${base_url}/v1/relays" 2>/dev/null || true)"
  if [[ -z "$payload" ]]; then
    echo "0"
    return
  fi
  local count
  count="$(extract_operators "$payload" | wc -l | tr -d ' ')"
  if [[ -z "$count" ]]; then
    count="0"
  fi
  echo "$count"
}

peer_directory_a=""
public_host=""
min_operators="2"
federation_timeout_sec="90"
report_file=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --peer-directory-a)
      peer_directory_a="${2:-}"
      shift 2
      ;;
    --public-host)
      public_host="${2:-}"
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
    --report-file)
      report_file="${2:-}"
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

if [[ -z "$peer_directory_a" ]]; then
  echo "missing required argument: --peer-directory-a URL"
  usage
  exit 2
fi

if [[ -z "$report_file" ]]; then
  report_file="/tmp/privacynode_machine_b_test_$(date +%Y%m%d_%H%M%S).log"
fi
mkdir -p "$(dirname "$report_file")"
exec > >(tee -a "$report_file") 2>&1

echo "[machine-b-test] started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[machine-b-test] report: $report_file"

need_cmd docker
need_cmd curl
need_cmd rg
if ! docker compose version >/dev/null 2>&1; then
  echo "missing required dependency: docker compose plugin"
  exit 2
fi

peer_directory_a="$(trim_url "$peer_directory_a")"

running_services="$(compose_server ps --services --status running | tr -d '\r')"
for svc in directory issuer entry-exit; do
  if ! printf '%s\n' "$running_services" | rg -qx "$svc"; then
    echo "required service is not running: $svc"
    echo "running services:"
    printf '%s\n' "$running_services"
    compose_server ps || true
    exit 1
  fi
done

wait_http_ok "http://127.0.0.1:8081/v1/relays" "local directory" 30
wait_http_ok "http://127.0.0.1:8082/v1/pubkeys" "local issuer" 30
wait_http_ok "http://127.0.0.1:8083/v1/health" "local entry" 30
wait_http_ok "http://127.0.0.1:8084/v1/health" "local exit" 30
wait_http_ok "${peer_directory_a}/v1/relays" "peer directory A" 30

if [[ -n "$public_host" ]]; then
  wait_http_ok "http://${public_host}:8081/v1/relays" "public directory" 20
  wait_http_ok "http://${public_host}:8082/v1/pubkeys" "public issuer" 20
  wait_http_ok "http://${public_host}:8083/v1/health" "public entry" 20
  wait_http_ok "http://${public_host}:8084/v1/health" "public exit" 20
fi

federated=0
for _ in $(seq 1 "$federation_timeout_sec"); do
  count_local="$(operator_count_from_url "http://127.0.0.1:8081")"
  if [[ "$count_local" =~ ^[0-9]+$ ]] && ((count_local >= min_operators)); then
    federated=1
    break
  fi
  sleep 1
done

if [[ "$federated" -ne 1 ]]; then
  echo "federation operator floor not reached on machine B directory"
  echo "required min operators: $min_operators"
  echo "observed operators: $(operator_count_from_url "http://127.0.0.1:8081")"
  echo "--- machine B relays ---"
  payload="$(curl -fsS "http://127.0.0.1:8081/v1/relays" 2>/dev/null || true)"
  printf '%s\n' "$payload"
  echo "--- machine B operator ids ---"
  extract_operators "$payload" || true
  exit 1
fi

echo "[machine-b-test] local operator count: $(operator_count_from_url "http://127.0.0.1:8081")"
echo "[machine-b-test] ok"
echo "[machine-b-test] report saved: $report_file"
