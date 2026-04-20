#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TESTNET_DIR="$ROOT_DIR/.tdpn-testnet"
RUNTIME_MODE_OVERRIDE=""
DRY_RUN=0
WAIT_SECONDS=10

usage() {
  cat <<'EOF'
Usage: scripts/testnet_local_stop.sh [options]

Options:
  --testnet-dir <path>    Testnet root directory (default: ./.tdpn-testnet)
  --runtime-mode <mode>   Runtime mode override: scaffold or comet
  --wait-seconds <n>      Seconds to wait for graceful stop before SIGKILL (default: 10)
  --dry-run               Print stop actions without sending signals
  -h, --help              Show help
EOF
}

normalize_runtime_mode() {
  local mode
  mode="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$mode" in
    scaffold|comet)
      printf '%s' "$mode"
      ;;
    *)
      echo "--runtime-mode must be scaffold or comet (got: $1)" >&2
      usage
      exit 2
      ;;
  esac
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

read_env_value() {
  local file="$1"
  local key="$2"
  awk -F= -v wanted="$key" '
    $1 == wanted {
      sub(/^[^=]+=/, "", $0)
      print
      exit
    }
  ' "$file"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --testnet-dir)
      need_value "$1" "${2:-}"
      TESTNET_DIR="$2"
      shift 2
      ;;
    --runtime-mode)
      need_value "$1" "${2:-}"
      RUNTIME_MODE_OVERRIDE="$(normalize_runtime_mode "$2")"
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
TESTNET_RUNTIME_MODE="$(normalize_runtime_mode "${RUNTIME_MODE:-scaffold}")"
if ! [[ "$NODE_COUNT" =~ ^[0-9]+$ ]] || [[ "$NODE_COUNT" -lt 1 ]]; then
  echo "invalid NODE_COUNT in manifest: $NODE_COUNT" >&2
  exit 1
fi

if [[ -n "$RUNTIME_MODE_OVERRIDE" ]]; then
  if [[ "$RUNTIME_MODE_OVERRIDE" != "$TESTNET_RUNTIME_MODE" ]]; then
    echo "runtime mode override (${RUNTIME_MODE_OVERRIDE}) does not match manifest (${TESTNET_RUNTIME_MODE})" >&2
    exit 1
  fi
fi

stop_node() {
  local node_dir="$1"
  local expected_node_index="$2"
  local config_file="$node_dir/node.env"
  if [[ ! -f "$config_file" ]]; then
    echo "missing node config: $config_file" >&2
    exit 1
  fi

  local file_runtime_mode
  file_runtime_mode="$(read_env_value "$config_file" RUNTIME_MODE)"
  if [[ -n "$file_runtime_mode" ]]; then
    file_runtime_mode="$(normalize_runtime_mode "$file_runtime_mode")"
    if [[ "$file_runtime_mode" != "$TESTNET_RUNTIME_MODE" ]]; then
      echo "runtime mode in $config_file (${file_runtime_mode}) does not match manifest (${TESTNET_RUNTIME_MODE})" >&2
      exit 1
    fi
  fi

  local file_node_index
  file_node_index="$(read_env_value "$config_file" NODE_INDEX)"
  if [[ -n "$file_node_index" && "$file_node_index" != "$expected_node_index" ]]; then
    echo "node index in $config_file (${file_node_index}) does not match expected node (${expected_node_index})" >&2
    exit 1
  fi

  source "$config_file"
  local runtime_mode
  runtime_mode="$(normalize_runtime_mode "${RUNTIME_MODE:-$TESTNET_RUNTIME_MODE}")"

  local pid_file="${PID_FILE}"
  if [[ ! -f "$pid_file" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "[dry-run] ${NODE_ID}: mode=${runtime_mode} no pid file ($pid_file); no signal needed"
      return 0
    fi
    echo "${NODE_ID} not running (mode=${runtime_mode}, no pid file)"
    return 0
  fi

  local pid
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ -z "$pid" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "[dry-run] ${NODE_ID}: mode=${runtime_mode} empty pid file ($pid_file); would remove stale file"
      return 0
    fi
    rm -f "$pid_file"
    echo "${NODE_ID} stale pid file removed (mode=${runtime_mode})"
    return 0
  fi

  if ! kill -0 "$pid" 2>/dev/null; then
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "[dry-run] ${NODE_ID}: mode=${runtime_mode} pid ${pid} is not alive; would remove stale pid file"
      return 0
    fi
    rm -f "$pid_file"
    echo "${NODE_ID} stale pid ${pid} removed (mode=${runtime_mode})"
    return 0
  fi

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[dry-run] ${NODE_ID}: mode=${runtime_mode} kill -TERM ${pid}; wait ${WAIT_SECONDS}s; optional kill -KILL ${pid}"
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
  echo "${NODE_ID} stopped (mode=${runtime_mode})"
}

for i in $(seq 1 "$NODE_COUNT"); do
  stop_node "$TESTNET_DIR/node${i}" "$i"
done

echo "testnet stop complete"
