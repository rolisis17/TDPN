#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

SETTLEMENT_HTTP_LISTEN="127.0.0.1:8080"
GRPC_LISTEN=""
SETTLEMENT_HTTP_AUTH_TOKEN=""
SETTLEMENT_HTTP_AUTH_TOKEN_FILE=""
SETTLEMENT_HTTP_AUTH_TOKEN_FILE_EPHEMERAL=0
STATE_DIR=""
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: scripts/cosmos_bridge_local_stack.sh [options]

Options:
  --settlement-http-listen <host:port>   Settlement bridge listen address (default: 127.0.0.1:8080)
  --grpc-listen <host:port>              Optional gRPC listen address
  --auth-token <token>                   Optional settlement bridge bearer auth token
  --auth-token-file <path>               Optional file containing settlement bridge bearer auth token
  --settlement-http-auth-token <token>   Alias of --auth-token
  --settlement-http-auth-token-file <path> Alias of --auth-token-file
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
    --auth-token-file|--settlement-http-auth-token-file)
      need_value "$1" "${2:-}"
      SETTLEMENT_HTTP_AUTH_TOKEN_FILE="$2"
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

if [[ -n "${SETTLEMENT_HTTP_AUTH_TOKEN}" && -n "${SETTLEMENT_HTTP_AUTH_TOKEN_FILE}" ]]; then
  echo "set only one of --auth-token or --auth-token-file"
  exit 2
fi
if [[ -n "${SETTLEMENT_HTTP_AUTH_TOKEN_FILE}" && ! -f "${SETTLEMENT_HTTP_AUTH_TOKEN_FILE}" ]]; then
  echo "auth token file not found: ${SETTLEMENT_HTTP_AUTH_TOKEN_FILE}"
  exit 2
fi
if [[ -n "${SETTLEMENT_HTTP_AUTH_TOKEN}" && -z "${SETTLEMENT_HTTP_AUTH_TOKEN_FILE}" ]]; then
  SETTLEMENT_HTTP_AUTH_TOKEN_FILE="$(mktemp)"
  chmod 600 "${SETTLEMENT_HTTP_AUTH_TOKEN_FILE}"
  printf '%s' "${SETTLEMENT_HTTP_AUTH_TOKEN}" >"${SETTLEMENT_HTTP_AUTH_TOKEN_FILE}"
  SETTLEMENT_HTTP_AUTH_TOKEN=""
  SETTLEMENT_HTTP_AUTH_TOKEN_FILE_EPHEMERAL=1
fi

SETTLEMENT_ENDPOINT="http://${SETTLEMENT_HTTP_LISTEN}"

CMD=(go run ./blockchain/tdpn-chain/cmd/tdpnd --settlement-http-listen "${SETTLEMENT_HTTP_LISTEN}")
if [[ -n "${GRPC_LISTEN}" ]]; then
  CMD+=(--grpc-listen "${GRPC_LISTEN}")
fi
if [[ -n "${SETTLEMENT_HTTP_AUTH_TOKEN_FILE}" ]]; then
  CMD+=(--settlement-http-auth-token-file "${SETTLEMENT_HTTP_AUTH_TOKEN_FILE}")
fi
if [[ -n "${STATE_DIR}" ]]; then
  CMD+=(--state-dir "${STATE_DIR}")
fi

print_redacted_cmd() {
  local -a raw=("$@")
  local -a safe=()
  local redact_next="0"
  local arg
  for arg in "${raw[@]}"; do
    if [[ "$redact_next" == "1" ]]; then
      safe+=("[redacted]")
      redact_next="0"
      continue
    fi
    safe+=("$arg")
    if [[ "$arg" == "--settlement-http-auth-token" ]]; then
      redact_next="1"
    fi
  done
  printf '%q ' "${safe[@]}"
  printf '\n'
}

echo "[cosmos-bridge-local-stack] issuer/exit env wiring:"
echo "export SETTLEMENT_CHAIN_ADAPTER=cosmos"
echo "export COSMOS_SETTLEMENT_ENDPOINT=${SETTLEMENT_ENDPOINT}"
if [[ -n "${SETTLEMENT_HTTP_AUTH_TOKEN}" ]]; then
  echo "export COSMOS_SETTLEMENT_API_KEY=[redacted]"
elif [[ -n "${SETTLEMENT_HTTP_AUTH_TOKEN_FILE}" ]]; then
  printf 'export COSMOS_SETTLEMENT_API_KEY="$(head -n1 %q)"\n' "${SETTLEMENT_HTTP_AUTH_TOKEN_FILE}"
fi
if [[ -n "${STATE_DIR}" ]]; then
  printf 'export TDPN_CHAIN_STATE_DIR=%q\n' "${STATE_DIR}"
fi

echo
echo "[cosmos-bridge-local-stack] tdpnd command:"
print_redacted_cmd "${CMD[@]}"

if [[ "${DRY_RUN}" == "1" ]]; then
  if [[ "${SETTLEMENT_HTTP_AUTH_TOKEN_FILE_EPHEMERAL}" == "1" ]]; then
    rm -f "${SETTLEMENT_HTTP_AUTH_TOKEN_FILE}"
  fi
  echo
  echo "[cosmos-bridge-local-stack] dry-run mode: command not started."
  exit 0
fi

echo
echo "[cosmos-bridge-local-stack] starting runtime (Ctrl+C to stop)"
exec "${CMD[@]}"
