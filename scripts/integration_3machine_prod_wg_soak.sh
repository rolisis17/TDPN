#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

usage() {
  cat <<'USAGE'
Usage:
  sudo ./scripts/integration_3machine_prod_wg_soak.sh \
    [--rounds N] \
    [--pause-sec N] \
    [--fault-every N] \
    [--fault-command CMD] \
    [--continue-on-fail [0|1]] \
    [--report-file PATH] \
    [validate args...]

Purpose:
  Repeatedly run real cross-machine production-profile WG dataplane validation.
  Additional arguments are passed through to:
    ./scripts/integration_3machine_prod_wg_validate.sh

Examples:
  sudo ./scripts/integration_3machine_prod_wg_soak.sh \
    --rounds 12 --pause-sec 10 \
    --directory-a https://A:8081 --directory-b https://B:8081 \
    --issuer-url https://A:8082 --entry-url https://A:8083 --exit-url https://A:8084 \
    --subject inv-abc123

  sudo ./scripts/integration_3machine_prod_wg_soak.sh \
    --rounds 20 --fault-every 5 \
    --fault-command "ssh user@B 'cd /repo && ./scripts/easy_node.sh server-up --mode provider --prod-profile 1 --beta-profile 1 --public-host B'"
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

rounds="${THREE_MACHINE_PROD_WG_SOAK_ROUNDS:-10}"
pause_sec="${THREE_MACHINE_PROD_WG_SOAK_PAUSE_SEC:-8}"
fault_every="${THREE_MACHINE_PROD_WG_SOAK_FAULT_EVERY:-0}"
fault_command="${THREE_MACHINE_PROD_WG_SOAK_FAULT_COMMAND:-}"
continue_on_fail="${THREE_MACHINE_PROD_WG_SOAK_CONTINUE_ON_FAIL:-0}"
report_file=""
validate_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rounds)
      rounds="${2:-}"
      shift 2
      ;;
    --pause-sec)
      pause_sec="${2:-}"
      shift 2
      ;;
    --fault-every)
      fault_every="${2:-}"
      shift 2
      ;;
    --fault-command)
      fault_command="${2:-}"
      shift 2
      ;;
    --continue-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        continue_on_fail="${2:-}"
        shift 2
      else
        continue_on_fail="1"
        shift
      fi
      ;;
    --report-file)
      report_file="${2:-}"
      shift 2
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      validate_args+=("$1")
      shift
      ;;
  esac
done

if ! [[ "$rounds" =~ ^[0-9]+$ && "$pause_sec" =~ ^[0-9]+$ && "$fault_every" =~ ^[0-9]+$ ]]; then
  echo "--rounds, --pause-sec and --fault-every must be integers"
  exit 2
fi
if ((rounds < 1)); then
  echo "--rounds must be >= 1"
  exit 2
fi
if [[ "$continue_on_fail" != "0" && "$continue_on_fail" != "1" ]]; then
  echo "--continue-on-fail must be 0 or 1"
  exit 2
fi
if ((fault_every > 0)) && [[ -z "$(trim "$fault_command")" ]]; then
  echo "--fault-command is required when --fault-every > 0"
  exit 2
fi

need_cmd bash
need_cmd date
need_cmd timeout
need_cmd tee

validate_script="$ROOT_DIR/scripts/integration_3machine_prod_wg_validate.sh"
if [[ ! -x "$validate_script" ]]; then
  echo "validate script not executable: $validate_script"
  exit 2
fi

if [[ -z "$report_file" ]]; then
  report_file="$(default_log_dir)/privacynode_3machine_prod_wg_soak_$(date +%Y%m%d_%H%M%S).log"
fi
mkdir -p "$(dirname "$report_file")"
exec > >(tee -a "$report_file") 2>&1

echo "[3machine-prod-wg-soak] started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[3machine-prod-wg-soak] report: $report_file"
echo "[3machine-prod-wg-soak] rounds=$rounds pause_sec=$pause_sec fault_every=$fault_every continue_on_fail=$continue_on_fail"

passed=0
failed=0

for round in $(seq 1 "$rounds"); do
  echo
  echo "[3machine-prod-wg-soak] round=$round/$rounds"

  if ((fault_every > 0)) && ((round > 1)) && (((round - 1) % fault_every == 0)); then
    echo "[3machine-prod-wg-soak] injecting fault (round=$round): $fault_command"
    set +e
    bash -lc "$fault_command"
    fault_rc=$?
    set -e
    if [[ "$fault_rc" -ne 0 ]]; then
      echo "[3machine-prod-wg-soak] fault command failed rc=$fault_rc"
      if [[ "$continue_on_fail" == "0" ]]; then
        exit 1
      fi
    fi
  fi

  round_log="$(dirname "$report_file")/privacynode_3machine_prod_wg_round_${round}_$(date +%Y%m%d_%H%M%S).log"
  cmd=(
    "$validate_script"
    --report-file "$round_log"
    "${validate_args[@]}"
  )

  set +e
  "${cmd[@]}"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    passed=$((passed + 1))
    echo "[3machine-prod-wg-soak] round=$round result=ok log=$round_log"
  else
    failed=$((failed + 1))
    echo "[3machine-prod-wg-soak] round=$round result=fail rc=$rc log=$round_log"
    if [[ "$continue_on_fail" == "0" ]]; then
      echo "[3machine-prod-wg-soak] stopping on first failure"
      break
    fi
  fi

  if ((round < rounds)); then
    sleep "$pause_sec"
  fi
done

echo
echo "[3machine-prod-wg-soak] summary passed=$passed failed=$failed total=$rounds"
if ((failed > 0)); then
  exit 1
fi
echo "[3machine-prod-wg-soak] ok"

