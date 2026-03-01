#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT_DIR/deploy"
SERVER_ENV_FILE="$DEPLOY_DIR/.env.easy.server"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/integration_machine_a_server_check.sh [--public-host HOST] [--report-file PATH]

Purpose:
  Run on machine A (server host). Validates:
  - docker services are running (directory, issuer, entry-exit)
  - local health/control endpoints respond
  - directory publishes both entry and exit relay descriptors
  - optional public-host health checks from this machine
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

public_host=""
report_file=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-host)
      public_host="${2:-}"
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

if [[ -z "$report_file" ]]; then
  report_file="/tmp/privacynode_machine_a_test_$(date +%Y%m%d_%H%M%S).log"
fi
mkdir -p "$(dirname "$report_file")"
exec > >(tee -a "$report_file") 2>&1

echo "[machine-a-test] started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[machine-a-test] report: $report_file"

need_cmd docker
need_cmd curl
need_cmd rg
if ! docker compose version >/dev/null 2>&1; then
  echo "missing required dependency: docker compose plugin"
  exit 2
fi

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

relay_payload="$(curl -fsS "http://127.0.0.1:8081/v1/relays")"
if ! printf '%s\n' "$relay_payload" | rg -q '"role":"entry"'; then
  echo "directory relay list missing entry descriptor"
  printf '%s\n' "$relay_payload"
  exit 1
fi
if ! printf '%s\n' "$relay_payload" | rg -q '"role":"exit"'; then
  echo "directory relay list missing exit descriptor"
  printf '%s\n' "$relay_payload"
  exit 1
fi

if [[ -n "$public_host" ]]; then
  wait_http_ok "http://${public_host}:8081/v1/relays" "public directory" 20
  wait_http_ok "http://${public_host}:8082/v1/pubkeys" "public issuer" 20
  wait_http_ok "http://${public_host}:8083/v1/health" "public entry" 20
  wait_http_ok "http://${public_host}:8084/v1/health" "public exit" 20
fi

echo "[machine-a-test] ok"
echo "[machine-a-test] report saved: $report_file"
