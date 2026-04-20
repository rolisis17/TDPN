#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TESTNET_DIR="$ROOT_DIR/.tdpn-testnet"
RUNTIME_MODE_OVERRIDE=""
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: scripts/testnet_local_status.sh [options]

Options:
  --testnet-dir <path>    Testnet root directory (default: ./.tdpn-testnet)
  --runtime-mode <mode>   Runtime mode override: scaffold or comet
  --dry-run               Print status file locations only
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

running=0
stopped=0

status_node() {
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
  local node_index="${NODE_INDEX:-$expected_node_index}"
  local comet_home_dir=""
  local comet_p2p_listen=""
  local comet_rpc_listen=""
  if [[ "$runtime_mode" == "comet" ]]; then
    local expected_comet_home_dir="$node_dir/comet-home"
    local expected_comet_p2p_listen="tcp://$HOST:$((BASE_GRPC_PORT + NODE_COUNT + node_index - 1))"
    local expected_comet_rpc_listen="tcp://$HOST:$((BASE_SETTLEMENT_PORT + NODE_COUNT + node_index - 1))"

    comet_home_dir="${COMET_HOME_DIR:-$expected_comet_home_dir}"
    comet_p2p_listen="${COMET_P2P_LISTEN:-$expected_comet_p2p_listen}"
    comet_rpc_listen="${COMET_RPC_LISTEN:-$expected_comet_rpc_listen}"

    if [[ "$comet_home_dir" != "$expected_comet_home_dir" ]]; then
      echo "comet home in $config_file (${comet_home_dir}) does not match expected path (${expected_comet_home_dir})" >&2
      exit 1
    fi
    if [[ "$comet_p2p_listen" != "$expected_comet_p2p_listen" ]]; then
      echo "comet p2p listen in $config_file (${comet_p2p_listen}) does not match expected value (${expected_comet_p2p_listen})" >&2
      exit 1
    fi
    if [[ "$comet_rpc_listen" != "$expected_comet_rpc_listen" ]]; then
      echo "comet rpc listen in $config_file (${comet_rpc_listen}) does not match expected value (${expected_comet_rpc_listen})" >&2
      exit 1
    fi
  fi

  if [[ "$DRY_RUN" == "1" ]]; then
    if [[ "$runtime_mode" == "comet" ]]; then
      echo "[dry-run] ${NODE_ID}: mode=${runtime_mode} pid=${PID_FILE} log=${LOG_FILE} grpc=${GRPC_LISTEN} settlement=${SETTLEMENT_HTTP_LISTEN} comet-p2p=${comet_p2p_listen} comet-rpc=${comet_rpc_listen} home=${comet_home_dir}"
    else
      echo "[dry-run] ${NODE_ID}: mode=${runtime_mode} pid=${PID_FILE} log=${LOG_FILE} grpc=${GRPC_LISTEN} settlement=${SETTLEMENT_HTTP_LISTEN}"
    fi
    return 0
  fi

  if [[ ! -f "$PID_FILE" ]]; then
    if [[ "$runtime_mode" == "comet" ]]; then
      echo "${NODE_ID}: stopped (mode=${runtime_mode}, no pid file) grpc=${GRPC_LISTEN} settlement=${SETTLEMENT_HTTP_LISTEN} comet-p2p=${comet_p2p_listen} comet-rpc=${comet_rpc_listen} home=${comet_home_dir}"
    else
      echo "${NODE_ID}: stopped (mode=${runtime_mode}, no pid file) grpc=${GRPC_LISTEN} settlement=${SETTLEMENT_HTTP_LISTEN}"
    fi
    stopped=$((stopped + 1))
    return 0
  fi

  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    if [[ "$runtime_mode" == "comet" ]]; then
      echo "${NODE_ID}: running mode=${runtime_mode} pid=${pid} grpc=${GRPC_LISTEN} settlement=${SETTLEMENT_HTTP_LISTEN} comet-p2p=${comet_p2p_listen} comet-rpc=${comet_rpc_listen} home=${comet_home_dir} log=${LOG_FILE}"
    else
      echo "${NODE_ID}: running mode=${runtime_mode} pid=${pid} grpc=${GRPC_LISTEN} settlement=${SETTLEMENT_HTTP_LISTEN} log=${LOG_FILE}"
    fi
    running=$((running + 1))
    return 0
  fi

  if [[ "$runtime_mode" == "comet" ]]; then
    echo "${NODE_ID}: stopped (mode=${runtime_mode}, stale pid file) grpc=${GRPC_LISTEN} settlement=${SETTLEMENT_HTTP_LISTEN} comet-p2p=${comet_p2p_listen} comet-rpc=${comet_rpc_listen} home=${comet_home_dir}"
  else
    echo "${NODE_ID}: stopped (mode=${runtime_mode}, stale pid file) grpc=${GRPC_LISTEN} settlement=${SETTLEMENT_HTTP_LISTEN}"
  fi
  stopped=$((stopped + 1))
}

for i in $(seq 1 "$NODE_COUNT"); do
  status_node "$TESTNET_DIR/node${i}" "$i"
done

if [[ "$DRY_RUN" == "1" ]]; then
  echo "[dry-run] status complete for ${NODE_COUNT} node(s)"
  exit 0
fi

echo "summary: running=${running} stopped=${stopped} total=${NODE_COUNT}"
