#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TESTNET_DIR="$ROOT_DIR/.tdpn-testnet"
DRY_RUN=0
WAIT_SECONDS=10

usage() {
  cat <<'EOF'
Usage: scripts/testnet_local_stop.sh [options]

Options:
  --testnet-dir <path>    Testnet root directory (default: ./.tdpn-testnet)
  --wait-seconds <n>      Seconds to wait for graceful stop before SIGKILL (default: 10)
  --dry-run               Print stop actions without sending signals
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
    --wait-seconds)
      need_value "$1" "${2:-}"
      WAIT_SECONDS="$2"
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

if ! [[ "$WAIT_SECONDS" =~ ^[0-9]+$ ]]; then
  echo "--wait-seconds must be an integer >= 0" >&2
  exit 2
fi

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

stop_node() {
  local node_dir="$1"
  local config_file="$node_dir/node.env"
  if [[ ! -f "$config_file" ]]; then
    echo "missing node config: $config_file" >&2
    exit 1
  fi
  source "$config_file"

  local pid_file="${PID_FILE}"
  if [[ ! -f "$pid_file" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "[dry-run] ${NODE_ID}: no pid file ($pid_file); no signal needed"
      return 0
    fi
    echo "${NODE_ID} not running (no pid file)"
    return 0
  fi

  local pid
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ -z "$pid" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "[dry-run] ${NODE_ID}: empty pid file ($pid_file); would remove stale file"
      return 0
    fi
    rm -f "$pid_file"
    echo "${NODE_ID} stale pid file removed"
    return 0
  fi

  if ! kill -0 "$pid" 2>/dev/null; then
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "[dry-run] ${NODE_ID}: pid ${pid} is not alive; would remove stale pid file"
      return 0
    fi
    rm -f "$pid_file"
    echo "${NODE_ID} stale pid ${pid} removed"
    return 0
  fi

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[dry-run] ${NODE_ID}: kill -TERM ${pid}; wait ${WAIT_SECONDS}s; optional kill -KILL ${pid}"
    return 0
  fi

  kill "$pid" 2>/dev/null || true
  local elapsed=0
  while kill -0 "$pid" 2>/dev/null; do
    if (( elapsed >= WAIT_SECONDS )); then
      echo "${NODE_ID} did not exit after ${WAIT_SECONDS}s; sending SIGKILL"
      kill -9 "$pid" 2>/dev/null || true
      break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  rm -f "$pid_file"
  echo "${NODE_ID} stopped"
}

for i in $(seq 1 "$NODE_COUNT"); do
  stop_node "$TESTNET_DIR/node${i}"
done

echo "testnet stop complete"
