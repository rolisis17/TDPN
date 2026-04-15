#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TESTNET_DIR="$ROOT_DIR/.tdpn-testnet"
NODE_COUNT=3
BASE_GRPC_PORT=19090
BASE_SETTLEMENT_PORT=18080
HOST="127.0.0.1"
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
  --dry-run                   Print actions without writing files
  -h, --help                  Show help
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

MANIFEST="$TESTNET_DIR/manifest.env"

if [[ "$DRY_RUN" == "1" ]]; then
  echo "[dry-run] mkdir -p \"$TESTNET_DIR\""
  echo "[dry-run] write $MANIFEST"
else
  mkdir -p "$TESTNET_DIR"
  cat > "$MANIFEST" <<EOF
TESTNET_DIR=$TESTNET_DIR
NODE_COUNT=$NODE_COUNT
BASE_GRPC_PORT=$BASE_GRPC_PORT
BASE_SETTLEMENT_PORT=$BASE_SETTLEMENT_PORT
HOST=$HOST
EOF
fi

for i in $(seq 1 "$NODE_COUNT"); do
  NODE_DIR="$TESTNET_DIR/node${i}"
  GRPC_PORT=$((BASE_GRPC_PORT + i - 1))
  SETTLEMENT_PORT=$((BASE_SETTLEMENT_PORT + i - 1))
  STATE_DIR="$NODE_DIR/state"
  LOG_FILE="$NODE_DIR/tdpnd.log"
  PID_FILE="$NODE_DIR/tdpnd.pid"
  CONFIG_FILE="$NODE_DIR/node.env"

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[dry-run] mkdir -p \"$STATE_DIR\""
    echo "[dry-run] rm -f \"$PID_FILE\""
    echo "[dry-run] write $CONFIG_FILE"
  else
    mkdir -p "$STATE_DIR"
    rm -f "$PID_FILE"
    cat > "$CONFIG_FILE" <<EOF
NODE_ID=node${i}
NODE_INDEX=$i
NODE_DIR=$NODE_DIR
GRPC_LISTEN=$HOST:$GRPC_PORT
SETTLEMENT_HTTP_LISTEN=$HOST:$SETTLEMENT_PORT
STATE_DIR=$STATE_DIR
LOG_FILE=$LOG_FILE
PID_FILE=$PID_FILE
EOF
  fi
done

echo "testnet initialized at $TESTNET_DIR with $NODE_COUNT node(s)"
