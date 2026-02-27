#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT_DIR/deploy"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed; install Docker Engine + Docker Compose plugin first"
  exit 1
fi

cd "$DEPLOY_DIR"

docker compose down --remove-orphans >/tmp/docker_stack_down.log 2>&1 || true
docker compose up -d --build directory issuer entry-exit >/tmp/docker_stack_up.log 2>&1
docker compose --profile demo build client-demo >/tmp/docker_stack_client_build.log 2>&1

cleanup() {
  docker compose down --remove-orphans >/tmp/docker_stack_down.log 2>&1 || true
}
trap cleanup EXIT

wait_http_ok() {
  local url="$1"
  for _ in $(seq 1 30); do
    if curl -sS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

if ! wait_http_ok "http://127.0.0.1:8081/v1/relays"; then
  echo "directory did not become healthy"
  docker compose logs directory
  exit 1
fi
if ! wait_http_ok "http://127.0.0.1:8082/v1/pubkeys"; then
  echo "issuer did not become healthy"
  docker compose logs issuer
  exit 1
fi
if ! wait_http_ok "http://127.0.0.1:8083/v1/health"; then
  echo "entry did not become healthy"
  docker compose logs entry-exit
  exit 1
fi
if ! wait_http_ok "http://127.0.0.1:8084/v1/health"; then
  echo "exit did not become healthy"
  docker compose logs entry-exit
  exit 1
fi

# Run the demo client inside the compose network so service DNS names resolve.
timeout 20s docker compose --profile demo run --rm client-demo >/tmp/docker_stack_client.log 2>&1 || true
if ! rg -q 'client selected entry=' /tmp/docker_stack_client.log; then
  echo "docker stack client bootstrap failed"
  cat /tmp/docker_stack_client.log
  docker compose logs directory issuer entry-exit
  exit 1
fi

echo "docker stack integration check ok"
