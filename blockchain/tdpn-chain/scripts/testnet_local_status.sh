#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TESTNET_DIR="$ROOT_DIR/.tdpn-testnet"
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: scripts/testnet_local_status.sh [options]

Options:
  --testnet-dir <path>    Testnet root directory (default: ./.tdpn-testnet)
  --dry-run               Print status file locations only
  -h, --help              Show help
EOF
}

need_value() {
  local flag="$1"
  local value="${2:-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    echo "missing value for ${flag}" >&2
    usage
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --testnet-dir)
      need_value "$1" "${2:-}"
      TESTNET_DIR="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ ! -f "$TESTNET_DIR/manifest.env" ]]; then
  echo "missing manifest: $TESTNET_DIR/manifest.env (run scripts/testnet_local_init.sh first)" >&2
  exit 1
fi

source "$TESTNET_DIR/manifest.env"
NODE_COUNT="${NODE_COUNT:-0}"
if ! [[ "$NODE_COUNT" =~ ^[0-9]+$ ]] || [[ "$NODE_COUNT" -lt 1 ]]; then
  echo "invalid NODE_COUNT in manifest: $NODE_COUNT" >&2
  exit 1
fi

running=0
stopped=0

status_node() {
  local node_dir="$1"
  local config_file="$node_dir/node.env"
  if [[ ! -f "$config_file" ]]; then
    echo "missing node config: $config_file" >&2
    exit 1
  fi
  source "$config_file"

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[dry-run] ${NODE_ID}: pid=${PID_FILE} log=${LOG_FILE} grpc=${GRPC_LISTEN} settlement=${SETTLEMENT_HTTP_LISTEN}"
    return 0
  fi

  if [[ ! -f "$PID_FILE" ]]; then
    echo "${NODE_ID}: stopped (no pid file) grpc=${GRPC_LISTEN} settlement=${SETTLEMENT_HTTP_LISTEN}"
    stopped=$((stopped + 1))
    return 0
  fi

  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "${NODE_ID}: running pid=${pid} grpc=${GRPC_LISTEN} settlement=${SETTLEMENT_HTTP_LISTEN} log=${LOG_FILE}"
    running=$((running + 1))
    return 0
  fi

  echo "${NODE_ID}: stopped (stale pid file) grpc=${GRPC_LISTEN} settlement=${SETTLEMENT_HTTP_LISTEN}"
  stopped=$((stopped + 1))
}

for i in $(seq 1 "$NODE_COUNT"); do
  status_node "$TESTNET_DIR/node${i}"
done

if [[ "$DRY_RUN" == "1" ]]; then
  echo "[dry-run] status complete for ${NODE_COUNT} node(s)"
  exit 0
fi

echo "summary: running=${running} stopped=${stopped} total=${NODE_COUNT}"
