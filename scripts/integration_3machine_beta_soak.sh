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
  ./scripts/integration_3machine_beta_soak.sh \
    [--directory-a URL] \
    [--directory-b URL] \
    [--bootstrap-directory URL] \
    [--discovery-wait-sec N] \
    [--issuer-url URL] \
    [--entry-url URL] \
    [--exit-url URL] \
    [--rounds N] \
    [--pause-sec N] \
    [--fault-every N] \
    [--fault-command CMD] \
    [--continue-on-fail [0|1]] \
    [--min-sources N] \
    [--min-operators N] \
    [--federation-timeout-sec N] \
    [--timeout-sec N] \
    [--exit-country CC] \
    [--exit-region REGION] \
    [--distinct-operators [0|1]] \
    [--beta-profile [0|1]] \
    [--report-file PATH]

Purpose:
  Run repeated 3-machine beta validation rounds from machine C.
  Optional fault injection can run a shell command every N rounds
  (for example: restart one server role over ssh).
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim_url() {
  local value="$1"
  while [[ "$value" == */ ]]; do
    value="${value%/}"
  done
  echo "$value"
}

directory_a=""
directory_b=""
issuer_url=""
entry_url=""
exit_url=""
bootstrap_directory=""
discovery_wait_sec="${THREE_MACHINE_DISCOVERY_WAIT_SEC:-12}"
rounds="${THREE_MACHINE_SOAK_ROUNDS:-12}"
pause_sec="${THREE_MACHINE_SOAK_PAUSE_SEC:-5}"
fault_every="${THREE_MACHINE_SOAK_FAULT_EVERY:-0}"
fault_command="${THREE_MACHINE_SOAK_FAULT_COMMAND:-}"
continue_on_fail="${THREE_MACHINE_SOAK_CONTINUE_ON_FAIL:-0}"
min_sources="2"
min_operators="2"
federation_timeout_sec="90"
client_timeout_sec="45"
exit_country=""
exit_region=""
beta_profile="${THREE_MACHINE_BETA_PROFILE:-1}"
distinct_operators="${THREE_MACHINE_DISTINCT_OPERATORS:-}"
report_file=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --directory-a)
      directory_a="${2:-}"
      shift 2
      ;;
    --directory-b)
      directory_b="${2:-}"
      shift 2
      ;;
    --issuer-url)
      issuer_url="${2:-}"
      shift 2
      ;;
    --bootstrap-directory)
      bootstrap_directory="${2:-}"
      shift 2
      ;;
    --discovery-wait-sec)
      discovery_wait_sec="${2:-}"
      shift 2
      ;;
    --entry-url)
      entry_url="${2:-}"
      shift 2
      ;;
    --exit-url)
      exit_url="${2:-}"
      shift 2
      ;;
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
    --min-sources)
      min_sources="${2:-}"
      shift 2
      ;;
    --min-operators)
      min_operators="${2:-}"
      shift 2
      ;;
    --federation-timeout-sec)
      federation_timeout_sec="${2:-}"
      shift 2
      ;;
    --timeout-sec)
      client_timeout_sec="${2:-}"
      shift 2
      ;;
    --exit-country)
      exit_country="${2:-}"
      shift 2
      ;;
    --exit-region)
      exit_region="${2:-}"
      shift 2
      ;;
    --distinct-operators)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        distinct_operators="${2:-}"
        shift 2
      else
        distinct_operators="1"
        shift
      fi
      ;;
    --beta-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        beta_profile="${2:-}"
        shift 2
      else
        beta_profile="1"
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
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

if [[ "$continue_on_fail" != "0" && "$continue_on_fail" != "1" ]]; then
  echo "--continue-on-fail must be 0 or 1"
  exit 2
fi
if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
  echo "--beta-profile must be 0 or 1"
  exit 2
fi
if [[ -n "$distinct_operators" && "$distinct_operators" != "0" && "$distinct_operators" != "1" ]]; then
  echo "--distinct-operators must be 0 or 1"
  exit 2
fi
if ! [[ "$rounds" =~ ^[0-9]+$ && "$pause_sec" =~ ^[0-9]+$ && "$fault_every" =~ ^[0-9]+$ && "$min_sources" =~ ^[0-9]+$ && "$min_operators" =~ ^[0-9]+$ && "$federation_timeout_sec" =~ ^[0-9]+$ && "$client_timeout_sec" =~ ^[0-9]+$ && "$discovery_wait_sec" =~ ^[0-9]+$ ]]; then
  echo "numeric arguments must be integers"
  exit 2
fi
if ((rounds < 1)); then
  echo "--rounds must be >= 1"
  exit 2
fi
if ((fault_every > 0)) && [[ -z "$fault_command" ]]; then
  echo "--fault-command is required when --fault-every is greater than 0"
  exit 2
fi

if [[ -z "$distinct_operators" ]]; then
  if [[ "$beta_profile" == "1" ]]; then
    distinct_operators="1"
  else
    distinct_operators="0"
  fi
fi

if [[ "$beta_profile" == "1" ]]; then
  if ((min_sources < 2)); then
    min_sources="2"
  fi
  if ((min_operators < 2)); then
    min_operators="2"
  fi
fi

need_cmd bash
need_cmd date
need_cmd timeout
need_cmd tee

directory_a="$(trim_url "$directory_a")"
directory_b="$(trim_url "$directory_b")"
issuer_url="$(trim_url "$issuer_url")"
entry_url="$(trim_url "$entry_url")"
exit_url="$(trim_url "$exit_url")"
bootstrap_directory="$(trim_url "$bootstrap_directory")"

if [[ -z "$bootstrap_directory" && ( -z "$directory_a" || -z "$directory_b" || -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" ) ]]; then
  echo "either provide explicit directory/issuer/entry/exit URLs or set --bootstrap-directory"
  usage
  exit 2
fi

if [[ -z "$report_file" ]]; then
  report_file="$(default_log_dir)/privacynode_3machine_soak_$(date +%Y%m%d_%H%M%S).log"
fi
mkdir -p "$(dirname "$report_file")"
exec > >(tee -a "$report_file") 2>&1

echo "[3machine-soak] started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[3machine-soak] report: $report_file"
echo "[3machine-soak] rounds=$rounds pause_sec=$pause_sec beta_profile=$beta_profile distinct_operators=$distinct_operators"

passed=0
failed=0

for round in $(seq 1 "$rounds"); do
  echo
  echo "[3machine-soak] round=$round/$rounds"

  if ((fault_every > 0)) && ((round > 1)) && (((round - 1) % fault_every == 0)); then
    echo "[3machine-soak] injecting fault (round=$round): $fault_command"
    set +e
    bash -lc "$fault_command"
    fault_rc=$?
    set -e
    if [[ "$fault_rc" -ne 0 ]]; then
      echo "[3machine-soak] fault command failed rc=$fault_rc"
      if [[ "$continue_on_fail" == "0" ]]; then
        exit 1
      fi
    fi
  fi

  cmd=(
    "$ROOT_DIR/scripts/integration_3machine_beta_validate.sh"
    --min-sources "$min_sources"
    --min-operators "$min_operators"
    --federation-timeout-sec "$federation_timeout_sec"
    --timeout-sec "$client_timeout_sec"
    --distinct-operators "$distinct_operators"
    --beta-profile "$beta_profile"
  )
  if [[ -n "$directory_a" ]]; then
    cmd+=(--directory-a "$directory_a")
  fi
  if [[ -n "$directory_b" ]]; then
    cmd+=(--directory-b "$directory_b")
  fi
  if [[ -n "$bootstrap_directory" ]]; then
    cmd+=(--bootstrap-directory "$bootstrap_directory" --discovery-wait-sec "$discovery_wait_sec")
  fi
  if [[ -n "$issuer_url" ]]; then
    cmd+=(--issuer-url "$issuer_url")
  fi
  if [[ -n "$entry_url" ]]; then
    cmd+=(--entry-url "$entry_url")
  fi
  if [[ -n "$exit_url" ]]; then
    cmd+=(--exit-url "$exit_url")
  fi
  if [[ -n "$exit_country" ]]; then
    cmd+=(--exit-country "$exit_country")
  fi
  if [[ -n "$exit_region" ]]; then
    cmd+=(--exit-region "$exit_region")
  fi

  set +e
  "${cmd[@]}"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    passed=$((passed + 1))
    echo "[3machine-soak] round=$round result=ok"
  else
    failed=$((failed + 1))
    echo "[3machine-soak] round=$round result=fail rc=$rc"
    if [[ "$continue_on_fail" == "0" ]]; then
      echo "[3machine-soak] stopping on first failure"
      break
    fi
  fi

  if ((round < rounds)); then
    sleep "$pause_sec"
  fi
done

echo
echo "[3machine-soak] summary passed=$passed failed=$failed total=$rounds"
if ((failed > 0)); then
  exit 1
fi
echo "[3machine-soak] ok"
