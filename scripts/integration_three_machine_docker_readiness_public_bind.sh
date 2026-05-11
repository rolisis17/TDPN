#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in awk rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

entry_exit_override_block="$(
  awk '
    /  entry-exit:/ {capture=1}
    capture {print}
    capture && /    volumes:/ {exit}
  ' scripts/three_machine_docker_readiness.sh
)"

for required_env in \
  'ENTRY_ALLOW_DANGEROUS_INSECURE_PUBLIC_BIND: "1"' \
  'EXIT_ALLOW_DANGEROUS_INSECURE_PUBLIC_BIND: "1"' \
  'ENTRY_ALLOW_INSECURE_CONTROL_URL_HTTP: "1"' \
  'EXIT_ALLOW_INSECURE_CONTROL_URL_HTTP: "1"'; do
  if ! printf '%s\n' "$entry_exit_override_block" | rg -F -- "$required_env" >/dev/null; then
    echo "three-machine docker readiness override missing required lab public-bind env: $required_env"
    printf '%s\n' "$entry_exit_override_block"
    exit 1
  fi
done

echo "three-machine docker readiness public-bind integration ok"
