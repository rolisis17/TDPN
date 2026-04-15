#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

SETTLEMENT_HTTP_LISTEN="127.0.0.1:8080"
GRPC_LISTEN=""
SETTLEMENT_HTTP_AUTH_TOKEN=""
STATE_DIR=""
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: scripts/cosmos_bridge_local_stack.sh [options]

Options:
  --settlement-http-listen <host:port>   Settlement bridge listen address (default: 127.0.0.1:8080)
  --grpc-listen <host:port>              Optional gRPC listen address
  --auth-token <token>                   Optional settlement bridge bearer auth token
  --settlement-http-auth-token <token>   Alias of --auth-token
  --state-dir <path>                     Optional tdpnd state-dir for file-backed module stores
  --dry-run                              Print env + command contract only; do not start runtime
  -h, --help                             Show this help text
EOF
}

need_value() {
  local flag="$1"
  local value="${2:-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    echo "missing value for ${flag}"
    usage
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --settlement-http-listen)
      need_value "$1" "${2:-}"
      SETTLEMENT_HTTP_LISTEN="$2"
      shift 2
      ;;
    --grpc-listen)
      need_value "$1" "${2:-}"
      GRPC_LISTEN="$2"
      shift 2
      ;;
    --auth-token|--settlement-http-auth-token)
      need_value "$1" "${2:-}"
      SETTLEMENT_HTTP_AUTH_TOKEN="$2"
      shift 2
      ;;
    --state-dir)
      need_value "$1" "${2:-}"
      STATE_DIR="$2"
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
      echo "unknown option: $1"
      usage
      exit 2
      ;;
  esac
done

SETTLEMENT_ENDPOINT="http://${SETTLEMENT_HTTP_LISTEN}"

CMD=(go run ./blockchain/tdpn-chain/cmd/tdpnd --settlement-http-listen "${SETTLEMENT_HTTP_LISTEN}")
if [[ -n "${GRPC_LISTEN}" ]]; then
  CMD+=(--grpc-listen "${GRPC_LISTEN}")
fi
if [[ -n "${SETTLEMENT_HTTP_AUTH_TOKEN}" ]]; then
  CMD+=(--settlement-http-auth-token "${SETTLEMENT_HTTP_AUTH_TOKEN}")
fi
if [[ -n "${STATE_DIR}" ]]; then
  CMD+=(--state-dir "${STATE_DIR}")
fi

echo "[cosmos-bridge-local-stack] issuer/exit env wiring:"
echo "export SETTLEMENT_CHAIN_ADAPTER=cosmos"
echo "export COSMOS_SETTLEMENT_ENDPOINT=${SETTLEMENT_ENDPOINT}"
if [[ -n "${SETTLEMENT_HTTP_AUTH_TOKEN}" ]]; then
  printf 'export COSMOS_SETTLEMENT_API_KEY=%q\n' "${SETTLEMENT_HTTP_AUTH_TOKEN}"
fi
if [[ -n "${STATE_DIR}" ]]; then
  printf 'export TDPN_CHAIN_STATE_DIR=%q\n' "${STATE_DIR}"
fi

echo
echo "[cosmos-bridge-local-stack] tdpnd command:"
printf '%q ' "${CMD[@]}"
printf '\n'

if [[ "${DRY_RUN}" == "1" ]]; then
  echo
  echo "[cosmos-bridge-local-stack] dry-run mode: command not started."
  exit 0
fi

echo
echo "[cosmos-bridge-local-stack] starting runtime (Ctrl+C to stop)"
exec "${CMD[@]}"
