#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT_DIR/deploy"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/run_local_demo.sh [all|up|smoke|status|logs|down]

Commands:
  all     Start stack, wait healthy, run demo client smoke test (default)
  up      Start stack and wait healthy
  smoke   Run demo client smoke test against running stack
  status  Show docker compose service status
  logs    Show recent service logs
  down    Stop stack
EOF
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 1
  fi
}

compose() {
  (cd "$DEPLOY_DIR" && docker compose "$@")
}

wait_http_ok() {
  local url="$1"
  local name="$2"
  for _ in $(seq 1 40); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "$name did not become healthy at $url"
  return 1
}

start_stack() {
  compose up -d --build directory issuer entry-exit
  wait_http_ok "http://127.0.0.1:8081/v1/relays" "directory" || { compose logs directory; exit 1; }
  wait_http_ok "http://127.0.0.1:8082/v1/pubkeys" "issuer" || { compose logs issuer; exit 1; }
  wait_http_ok "http://127.0.0.1:8083/v1/health" "entry" || { compose logs entry-exit; exit 1; }
  wait_http_ok "http://127.0.0.1:8084/v1/health" "exit" || { compose logs entry-exit; exit 1; }
  echo "local demo stack is healthy"
}

smoke_test() {
  local out="/tmp/run_local_demo_client.log"
  rm -f "$out"
  (cd "$DEPLOY_DIR" && docker compose --profile demo build client-demo >/dev/null)
  (cd "$DEPLOY_DIR" && timeout 25s docker compose --profile demo run --rm client-demo >"$out" 2>&1) || true
  if ! rg -q 'client selected entry=' "$out"; then
    echo "demo client bootstrap failed"
    cat "$out"
    compose logs directory issuer entry-exit
    exit 1
  fi
  echo "demo client smoke check ok"
}

main() {
  need_cmd docker
  need_cmd curl
  need_cmd rg

  local cmd="${1:-all}"
  case "$cmd" in
    all)
      start_stack
      smoke_test
      ;;
    up)
      start_stack
      ;;
    smoke)
      smoke_test
      ;;
    status)
      compose ps
      ;;
    logs)
      compose logs --tail=120 directory issuer entry-exit
      ;;
    down)
      compose down --remove-orphans
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      usage
      exit 2
      ;;
  esac
}

main "$@"
