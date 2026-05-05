#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TESTNET_DIR="$ROOT_DIR/.tdpn-testnet"
NODE_COUNT=3
BASE_GRPC_PORT=19090
BASE_SETTLEMENT_PORT=18080
HOST="127.0.0.1"
RUNTIME_MODE="scaffold"
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: scripts/testnet_local_init.sh [options]

Options:
  --testnet-dir <path>        Testnet root directory (default: ./.tdpn-testnet)
  --node-count <n>            Number of nodes (default: 3)
  --base-grpc-port <port>     Base gRPC port; node i uses base+(i-1) (default: 19090)
  --base-settlement-port <p>  Base settlement port; node i uses base+(i-1) (default: 18080)
  --host <addr>               Bind host for generated listen addresses (default: 127.0.0.1)
  --runtime-mode <mode>       Runtime mode: scaffold or comet (default: scaffold)
  --dry-run                   Print actions without writing files
  -h, --help                  Show help
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

write_env_assignment() {
  local key="$1"
  local value="$2"
  printf '%s=%q\n' "$key" "$value"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --testnet-dir)
      need_value "$1" "${2:-}"
      TESTNET_DIR="$2"
      shift 2
      ;;
    --node-count)
      need_value "$1" "${2:-}"
      NODE_COUNT="$2"
      shift 2
      ;;
    --base-grpc-port)
      need_value "$1" "${2:-}"
      BASE_GRPC_PORT="$2"
      shift 2
      ;;
    --base-settlement-port)
      need_value "$1" "${2:-}"
      BASE_SETTLEMENT_PORT="$2"
      shift 2
      ;;
    --host)
      need_value "$1" "${2:-}"
      HOST="$2"
      shift 2
      ;;
    --runtime-mode)
      need_value "$1" "${2:-}"
      RUNTIME_MODE="$(normalize_runtime_mode "$2")"
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

if ! [[ "$NODE_COUNT" =~ ^[0-9]+$ ]] || [[ "$NODE_COUNT" -lt 1 ]]; then
  echo "--node-count must be an integer >= 1" >&2
  exit 2
fi
if ! [[ "$BASE_GRPC_PORT" =~ ^[0-9]+$ ]] || [[ "$BASE_GRPC_PORT" -lt 1 ]] || [[ "$BASE_GRPC_PORT" -gt 65535 ]]; then
  echo "--base-grpc-port must be an integer in [1, 65535]" >&2
  exit 2
fi
if ! [[ "$BASE_SETTLEMENT_PORT" =~ ^[0-9]+$ ]] || [[ "$BASE_SETTLEMENT_PORT" -lt 1 ]] || [[ "$BASE_SETTLEMENT_PORT" -gt 65535 ]]; then
  echo "--base-settlement-port must be an integer in [1, 65535]" >&2
  exit 2
fi

if (( BASE_GRPC_PORT + NODE_COUNT - 1 > 65535 )); then
  echo "grpc port range exceeds 65535 for node-count=${NODE_COUNT}" >&2
  exit 2
fi
if (( BASE_SETTLEMENT_PORT + NODE_COUNT - 1 > 65535 )); then
  echo "settlement port range exceeds 65535 for node-count=${NODE_COUNT}" >&2
  exit 2
fi
if (( BASE_GRPC_PORT + (2 * NODE_COUNT) - 1 > 65535 )); then
  echo "comet p2p port range exceeds 65535 for node-count=${NODE_COUNT}" >&2
  exit 2
fi
if (( BASE_SETTLEMENT_PORT + (2 * NODE_COUNT) - 1 > 65535 )); then
  echo "comet rpc port range exceeds 65535 for node-count=${NODE_COUNT}" >&2
  exit 2
fi

RUNTIME_MODE="$(normalize_runtime_mode "$RUNTIME_MODE")"

MANIFEST="$TESTNET_DIR/manifest.env"

if [[ "$DRY_RUN" == "1" ]]; then
  echo "[dry-run] mkdir -p \"$TESTNET_DIR\""
  echo "[dry-run] write $MANIFEST"
else
  mkdir -p "$TESTNET_DIR"
  {
    write_env_assignment TESTNET_DIR "$TESTNET_DIR"
    write_env_assignment NODE_COUNT "$NODE_COUNT"
    write_env_assignment BASE_GRPC_PORT "$BASE_GRPC_PORT"
    write_env_assignment BASE_SETTLEMENT_PORT "$BASE_SETTLEMENT_PORT"
    write_env_assignment HOST "$HOST"
    write_env_assignment RUNTIME_MODE "$RUNTIME_MODE"
  } > "$MANIFEST"
fi

for i in $(seq 1 "$NODE_COUNT"); do
  NODE_DIR="$TESTNET_DIR/node${i}"
  GRPC_PORT=$((BASE_GRPC_PORT + i - 1))
  SETTLEMENT_PORT=$((BASE_SETTLEMENT_PORT + i - 1))
  COMET_P2P_PORT=$((BASE_GRPC_PORT + NODE_COUNT + i - 1))
  COMET_RPC_PORT=$((BASE_SETTLEMENT_PORT + NODE_COUNT + i - 1))
  STATE_DIR="$NODE_DIR/state"
  COMET_HOME_DIR="$NODE_DIR/comet-home"
  LOG_FILE="$NODE_DIR/tdpnd.log"
  PID_FILE="$NODE_DIR/tdpnd.pid"
  CONFIG_FILE="$NODE_DIR/node.env"

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[dry-run] mkdir -p \"$STATE_DIR\""
    if [[ "$RUNTIME_MODE" == "comet" ]]; then
      echo "[dry-run] mkdir -p \"$COMET_HOME_DIR\""
    fi
    echo "[dry-run] rm -f \"$PID_FILE\""
    echo "[dry-run] write $CONFIG_FILE"
  else
    mkdir -p "$STATE_DIR"
    if [[ "$RUNTIME_MODE" == "comet" ]]; then
      mkdir -p "$COMET_HOME_DIR"
    fi
    rm -f "$PID_FILE"
    {
      write_env_assignment NODE_ID "node${i}"
      write_env_assignment NODE_INDEX "$i"
      write_env_assignment NODE_DIR "$NODE_DIR"
      write_env_assignment RUNTIME_MODE "$RUNTIME_MODE"
      write_env_assignment GRPC_LISTEN "$HOST:$GRPC_PORT"
      write_env_assignment SETTLEMENT_HTTP_LISTEN "$HOST:$SETTLEMENT_PORT"
      if [[ "$RUNTIME_MODE" == "comet" ]]; then
        write_env_assignment COMET_P2P_LISTEN "tcp://$HOST:$COMET_P2P_PORT"
        write_env_assignment COMET_RPC_LISTEN "tcp://$HOST:$COMET_RPC_PORT"
        write_env_assignment COMET_PROXY_APP "tdpn-local-${i}"
        write_env_assignment STATE_DIR "$STATE_DIR"
        write_env_assignment COMET_HOME_DIR "$COMET_HOME_DIR"
      else
        write_env_assignment STATE_DIR "$STATE_DIR"
      fi
      write_env_assignment LOG_FILE "$LOG_FILE"
      write_env_assignment PID_FILE "$PID_FILE"
    } > "$CONFIG_FILE"
  fi
done

echo "testnet initialized at $TESTNET_DIR with $NODE_COUNT node(s)"
