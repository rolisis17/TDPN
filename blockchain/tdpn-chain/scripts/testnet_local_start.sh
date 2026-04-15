#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TESTNET_DIR="$ROOT_DIR/.tdpn-testnet"
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: scripts/testnet_local_start.sh [options]

Options:
  --testnet-dir <path>    Testnet root directory (default: ./.tdpn-testnet)
  --dry-run               Print launch plan and commands without starting nodes
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

start_node() {
  local node_dir="$1"
  local config_file="$node_dir/node.env"
  if [[ ! -f "$config_file" ]]; then
    echo "missing node config: $config_file" >&2
    exit 1
  fi

  source "$config_file"

  local pid_file="${PID_FILE}"
  local log_file="${LOG_FILE}"

  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      echo "${NODE_ID} already running (pid=${pid})"
      return 0
    fi
    rm -f "$pid_file"
  fi

  local cmd=(
    go run ./cmd/tdpnd
    --grpc-listen "$GRPC_LISTEN"
    --settlement-http-listen "$SETTLEMENT_HTTP_LISTEN"
    --state-dir "$STATE_DIR"
  )

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[dry-run] ${NODE_ID}: ${cmd[*]}"
    echo "[dry-run] ${NODE_ID}: log=$log_file pid=$pid_file"
    return 0
  fi

  mkdir -p "$node_dir" "$STATE_DIR"
  : > "$log_file"
  nohup "${cmd[@]}" >>"$log_file" 2>&1 &
  local pid=$!
  echo "$pid" > "$pid_file"
  echo "${NODE_ID} started (pid=${pid}, grpc=${GRPC_LISTEN}, settlement=${SETTLEMENT_HTTP_LISTEN})"
}

for i in $(seq 1 "$NODE_COUNT"); do
  start_node "$TESTNET_DIR/node${i}"
done

echo "testnet start complete"
