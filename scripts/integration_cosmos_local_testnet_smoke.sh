#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

CHAIN_DIR="$ROOT_DIR/blockchain/tdpn-chain"
INIT_SCRIPT="$CHAIN_DIR/scripts/testnet_local_init.sh"
START_SCRIPT="$CHAIN_DIR/scripts/testnet_local_start.sh"
STATUS_SCRIPT="$CHAIN_DIR/scripts/testnet_local_status.sh"
STOP_SCRIPT="$CHAIN_DIR/scripts/testnet_local_stop.sh"

for script in "$INIT_SCRIPT" "$START_SCRIPT" "$STATUS_SCRIPT" "$STOP_SCRIPT"; do
  if [[ ! -x "$script" ]]; then
    echo "missing executable local testnet script: $script"
    exit 1
  fi
done

NODE_COUNT="${LOCAL_TESTNET_SMOKE_NODE_COUNT:-2}"
BASE_GRPC_PORT="${LOCAL_TESTNET_SMOKE_BASE_GRPC_PORT:-29090}"
BASE_SETTLEMENT_PORT="${LOCAL_TESTNET_SMOKE_BASE_SETTLEMENT_PORT:-28080}"
HOST="${LOCAL_TESTNET_SMOKE_HOST:-127.0.0.1}"
START_WAIT_SECONDS="${LOCAL_TESTNET_SMOKE_START_WAIT_SECONDS:-40}"
STOP_WAIT_SECONDS="${LOCAL_TESTNET_SMOKE_STOP_WAIT_SECONDS:-20}"
STOP_GRACE_SECONDS="${LOCAL_TESTNET_SMOKE_STOP_GRACE_SECONDS:-10}"
RUNTIME_MODE_SPEC="${LOCAL_TESTNET_SMOKE_RUNTIME_MODE:-${LOCAL_TESTNET_SMOKE_RUNTIME_MODES:-scaffold}}"

if ! [[ "$NODE_COUNT" =~ ^[0-9]+$ ]] || (( NODE_COUNT < 2 || NODE_COUNT > 3 )); then
  echo "LOCAL_TESTNET_SMOKE_NODE_COUNT must be 2 or 3 (got: $NODE_COUNT)"
  exit 2
fi
if ! [[ "$BASE_GRPC_PORT" =~ ^[0-9]+$ ]] || (( BASE_GRPC_PORT < 1 || BASE_GRPC_PORT > 65535 )); then
  echo "LOCAL_TESTNET_SMOKE_BASE_GRPC_PORT must be in [1,65535] (got: $BASE_GRPC_PORT)"
  exit 2
fi
if ! [[ "$BASE_SETTLEMENT_PORT" =~ ^[0-9]+$ ]] || (( BASE_SETTLEMENT_PORT < 1 || BASE_SETTLEMENT_PORT > 65535 )); then
  echo "LOCAL_TESTNET_SMOKE_BASE_SETTLEMENT_PORT must be in [1,65535] (got: $BASE_SETTLEMENT_PORT)"
  exit 2
fi
if (( BASE_GRPC_PORT + NODE_COUNT - 1 > 65535 )); then
  echo "gRPC port range exceeds 65535 (base=$BASE_GRPC_PORT node_count=$NODE_COUNT)"
  exit 2
fi
if (( BASE_SETTLEMENT_PORT + NODE_COUNT - 1 > 65535 )); then
  echo "settlement port range exceeds 65535 (base=$BASE_SETTLEMENT_PORT node_count=$NODE_COUNT)"
  exit 2
fi

normalize_runtime_mode() {
  local mode
  mode="$(printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
  case "$mode" in
    scaffold|comet)
      printf '%s' "$mode"
      ;;
    *)
      echo "LOCAL_TESTNET_SMOKE_RUNTIME_MODE must be scaffold, comet, or both (got: $1)"
      exit 2
      ;;
  esac
}

runtime_modes=()
runtime_mode_spec_lower="$(printf '%s' "$RUNTIME_MODE_SPEC" | tr '[:upper:]' '[:lower:]')"
case "$runtime_mode_spec_lower" in
  scaffold)
    runtime_modes=(scaffold)
    ;;
  comet)
    runtime_modes=(comet)
    ;;
  both|all)
    runtime_modes=(scaffold comet)
    ;;
  *)
    IFS=',' read -r -a runtime_modes <<< "$RUNTIME_MODE_SPEC"
    ;;
esac

validated_runtime_modes=()
for runtime_mode in "${runtime_modes[@]}"; do
  if [[ -z "${runtime_mode// }" ]]; then
    continue
  fi
  validated_runtime_modes+=("$(normalize_runtime_mode "$runtime_mode")")
done

if [[ "${#validated_runtime_modes[@]}" -eq 0 ]]; then
  echo "LOCAL_TESTNET_SMOKE_RUNTIME_MODE resolved to no runnable modes (got: $RUNTIME_MODE_SPEC)"
  exit 2
fi

runtime_modes=("${validated_runtime_modes[@]}")

port_in_use() {
  local host="$1"
  local port="$2"
  (echo >/dev/tcp/"$host"/"$port") >/dev/null 2>&1
}

for i in $(seq 0 $((NODE_COUNT - 1))); do
  grpc_port=$((BASE_GRPC_PORT + i))
  settlement_port=$((BASE_SETTLEMENT_PORT + i))
  if port_in_use "$HOST" "$grpc_port"; then
    echo "gRPC port already in use for smoke test: $HOST:$grpc_port"
    echo "override with LOCAL_TESTNET_SMOKE_BASE_GRPC_PORT"
    exit 1
  fi
  if port_in_use "$HOST" "$settlement_port"; then
    echo "settlement port already in use for smoke test: $HOST:$settlement_port"
    echo "override with LOCAL_TESTNET_SMOKE_BASE_SETTLEMENT_PORT"
    exit 1
  fi
done

log_paths() {
  if [[ -d "$WORK_TESTNET_DIR" ]]; then
    find "$WORK_TESTNET_DIR" -maxdepth 2 -type f -name '*.log' -print 2>/dev/null || true
  fi
}

print_node_logs() {
  local log_file
  while IFS= read -r log_file; do
    [[ -z "$log_file" ]] && continue
    echo "--- node log: $log_file ---"
    tail -n 200 "$log_file" || true
  done < <(log_paths)
}

run_step() {
  local name="$1"
  shift
  local out_file="$TMP_DIR/${name}.out"
  set +e
  "$@" >"$out_file" 2>&1
  local rc=$?
  set -e
  if (( rc != 0 )); then
    echo "local testnet smoke step failed: $name (rc=$rc)"
    cat "$out_file"
    print_node_logs
    exit "$rc"
  fi
}

extract_summary_field() {
  local status_output_file="$1"
  local field="$2"
  awk -v f="$field" '
    /^summary:/ {
      for (i = 1; i <= NF; i++) {
        if ($i ~ ("^" f "=")) {
          gsub("^" f "=", "", $i)
          gsub(/[^0-9]/, "", $i)
          print $i
          exit
        }
      }
    }
  ' "$status_output_file"
}

wait_for_counts() {
  local expected_running="$1"
  local expected_stopped="$2"
  local timeout_seconds="$3"
  local label="$4"
  local attempts=$((timeout_seconds * 2))
  local status_file="$TMP_DIR/status_${label}.out"
  local running stopped

  for _ in $(seq 1 "$attempts"); do
    if ! "$STATUS_SCRIPT" --testnet-dir "$WORK_TESTNET_DIR" >"$status_file" 2>&1; then
      sleep 0.5
      continue
    fi

    running="$(extract_summary_field "$status_file" "running" || true)"
    stopped="$(extract_summary_field "$status_file" "stopped" || true)"
    if [[ "$running" == "$expected_running" && "$stopped" == "$expected_stopped" ]]; then
      return 0
    fi
    sleep 0.5
  done

  echo "local testnet smoke status assertion failed for ${label}: expected running=${expected_running} stopped=${expected_stopped}"
  if [[ -f "$status_file" ]]; then
    cat "$status_file"
  fi
  print_node_logs
  return 1
}

run_mode_smoke() (
  set -euo pipefail
  local runtime_mode="$1"

  TMP_DIR="$(mktemp -d -t cosmos-local-testnet-smoke.XXXXXX)"
  WORK_TESTNET_DIR="$TMP_DIR/testnet"

  cleanup() {
    set +e
    if [[ -f "$WORK_TESTNET_DIR/manifest.env" ]]; then
      "$STOP_SCRIPT" --testnet-dir "$WORK_TESTNET_DIR" --runtime-mode "$runtime_mode" --wait-seconds "$STOP_GRACE_SECONDS" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP_DIR"
    set -e
  }
  trap cleanup EXIT

  run_step init "$INIT_SCRIPT" \
    --testnet-dir "$WORK_TESTNET_DIR" \
    --node-count "$NODE_COUNT" \
    --base-grpc-port "$BASE_GRPC_PORT" \
    --base-settlement-port "$BASE_SETTLEMENT_PORT" \
    --host "$HOST" \
    --runtime-mode "$runtime_mode"

  run_step start "$START_SCRIPT" --testnet-dir "$WORK_TESTNET_DIR" --runtime-mode "$runtime_mode"
  wait_for_counts "$NODE_COUNT" "0" "$START_WAIT_SECONDS" "running_${runtime_mode}"

  run_step stop "$STOP_SCRIPT" --testnet-dir "$WORK_TESTNET_DIR" --runtime-mode "$runtime_mode" --wait-seconds "$STOP_GRACE_SECONDS"
  wait_for_counts "0" "$NODE_COUNT" "$STOP_WAIT_SECONDS" "stopped_${runtime_mode}"

  echo "cosmos local testnet smoke integration check ok (${runtime_mode})"
)

for runtime_mode in "${runtime_modes[@]}"; do
  run_mode_smoke "$runtime_mode"
done

echo "cosmos local testnet smoke integration check ok for mode(s): ${runtime_modes[*]}"
