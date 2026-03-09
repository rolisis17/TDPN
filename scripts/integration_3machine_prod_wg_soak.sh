#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VALIDATE_SCRIPT="${THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_prod_wg_validate.sh}"

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
    [--max-consecutive-failures N] \
    [--report-file PATH] \
    [--summary-json PATH] \
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

classify_round_failure() {
  local round_log="$1"
  local dataplane_reason="$2"

  if [[ "$dataplane_reason" == "missing_summary" ]]; then
    echo "dataplane_summary_missing"
    return
  fi
  if [[ "$dataplane_reason" == "no_progress" ]]; then
    echo "dataplane_no_progress"
    return
  fi

  if [[ -f "$round_log" ]]; then
    if rg -q 'issuer quorum check failed|issuer operator floor not met|missing issuer identity|issuer feed missing|require-issuer-quorum' "$round_log"; then
      echo "issuer_quorum"
      return
    fi
    if rg -q 'operator floor not met|entry operator floor not met|exit operator floor not met|distinct-operator|strict distinct check failed' "$round_log"; then
      echo "operator_floor"
      return
    fi
    if rg -q 'did not become healthy|missing required endpoints|connection refused|No route to host|network is unreachable|TLS handshake timeout' "$round_log"; then
      echo "endpoint_connectivity"
      return
    fi
    if rg -q 'did not reach wg session config stage|handshake/transfer did not become active|missing expected exit peer|endpoint was not set to proxy addr|exit metrics did not advance accepted_packets|client process exited before session setup' "$round_log"; then
      echo "wg_dataplane_stall"
      return
    fi
    if rg -q 'requires root|run as root|root privileges|permission denied' "$round_log"; then
      echo "permissions"
      return
    fi
    if rg -q 'timeout|timed out' "$round_log"; then
      echo "timeout"
      return
    fi
  fi

  echo "unknown"
}

failure_reason_line() {
  local round_log="$1"
  if [[ ! -f "$round_log" ]]; then
    return
  fi
  rg -n 'failed|did not|missing|error|refused|unreachable|timeout|stopping' "$round_log" |
    tail -n 1 |
    sed -E 's/^[0-9]+://' || true
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

rounds="${THREE_MACHINE_PROD_WG_SOAK_ROUNDS:-10}"
pause_sec="${THREE_MACHINE_PROD_WG_SOAK_PAUSE_SEC:-8}"
fault_every="${THREE_MACHINE_PROD_WG_SOAK_FAULT_EVERY:-0}"
fault_command="${THREE_MACHINE_PROD_WG_SOAK_FAULT_COMMAND:-}"
continue_on_fail="${THREE_MACHINE_PROD_WG_SOAK_CONTINUE_ON_FAIL:-0}"
max_consecutive_failures="${THREE_MACHINE_PROD_WG_SOAK_MAX_CONSECUTIVE_FAILURES:-2}"
report_file=""
summary_json=""
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
    --max-consecutive-failures)
      max_consecutive_failures="${2:-}"
      shift 2
      ;;
    --report-file)
      report_file="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
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

if ! [[ "$rounds" =~ ^[0-9]+$ && "$pause_sec" =~ ^[0-9]+$ && "$fault_every" =~ ^[0-9]+$ && "$max_consecutive_failures" =~ ^[0-9]+$ ]]; then
  echo "--rounds, --pause-sec, --fault-every and --max-consecutive-failures must be integers"
  exit 2
fi
if ((rounds < 1)); then
  echo "--rounds must be >= 1"
  exit 2
fi
if ((max_consecutive_failures < 1)); then
  echo "--max-consecutive-failures must be >= 1"
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
need_cmd rg

if [[ ! -x "$VALIDATE_SCRIPT" ]]; then
  echo "validate script not executable: $VALIDATE_SCRIPT"
  exit 2
fi

if [[ -z "$report_file" ]]; then
  report_file="$(default_log_dir)/privacynode_3machine_prod_wg_soak_$(date +%Y%m%d_%H%M%S).log"
fi
if [[ -z "$summary_json" && -n "${THREE_MACHINE_PROD_WG_SOAK_SUMMARY_JSON:-}" ]]; then
  summary_json="${THREE_MACHINE_PROD_WG_SOAK_SUMMARY_JSON}"
fi
mkdir -p "$(dirname "$report_file")"
exec > >(tee -a "$report_file") 2>&1

echo "[3machine-prod-wg-soak] started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[3machine-prod-wg-soak] report: $report_file"
echo "[3machine-prod-wg-soak] rounds=$rounds pause_sec=$pause_sec fault_every=$fault_every continue_on_fail=$continue_on_fail max_consecutive_failures=$max_consecutive_failures"

passed=0
failed=0
consecutive_failures=0
max_seen_consecutive_failures=0
declare -A failure_class_counts=()

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
    "$VALIDATE_SCRIPT"
    --report-file "$round_log"
    "${validate_args[@]}"
  )

  set +e
  "${cmd[@]}"
  rc=$?
  set -e
  dataplane_fail_reason=""
  dataplane_delta_total=0
  if [[ "$rc" -eq 0 ]]; then
    if rg -q '\[3machine-prod-wg\] dataplane-summary .*accepted_delta_total=' "$round_log"; then
      dataplane_delta_total="$(rg -o 'accepted_delta_total=[0-9]+' "$round_log" | tail -n1 | sed -E 's/^accepted_delta_total=//' || true)"
      if [[ -z "$dataplane_delta_total" || ! "$dataplane_delta_total" =~ ^[0-9]+$ ]]; then
        dataplane_delta_total=0
      fi
      if ((dataplane_delta_total < 1)); then
        echo "[3machine-prod-wg-soak] round=$round dataplane summary reported non-positive accepted delta: $dataplane_delta_total"
        dataplane_fail_reason="no_progress"
        rc=1
      fi
    else
      echo "[3machine-prod-wg-soak] round=$round missing dataplane summary marker"
      dataplane_fail_reason="missing_summary"
      rc=1
    fi
  fi

  if [[ "$rc" -eq 0 ]]; then
    passed=$((passed + 1))
    consecutive_failures=0
    echo "[3machine-prod-wg-soak] round=$round result=ok accepted_delta_total=$dataplane_delta_total log=$round_log"
  else
    failed=$((failed + 1))
    consecutive_failures=$((consecutive_failures + 1))
    if ((consecutive_failures > max_seen_consecutive_failures)); then
      max_seen_consecutive_failures=$consecutive_failures
    fi
    failure_class="$(classify_round_failure "$round_log" "$dataplane_fail_reason")"
    failure_class_counts["$failure_class"]=$(( ${failure_class_counts[$failure_class]:-0} + 1 ))
    reason_line="$(failure_reason_line "$round_log")"
    if [[ -n "$reason_line" ]]; then
      echo "[3machine-prod-wg-soak] round=$round result=fail rc=$rc class=$failure_class reason=$(printf '%s' "$reason_line" | sed -E 's/[[:space:]]+/ /g') log=$round_log"
    else
      echo "[3machine-prod-wg-soak] round=$round result=fail rc=$rc class=$failure_class log=$round_log"
    fi
    if [[ "$continue_on_fail" == "0" ]]; then
      echo "[3machine-prod-wg-soak] stopping on first failure"
      break
    fi
    if ((consecutive_failures >= max_consecutive_failures)); then
      echo "[3machine-prod-wg-soak] stopping: sustained failure threshold reached (consecutive_failures=$consecutive_failures, limit=$max_consecutive_failures)"
      break
    fi
  fi

  if ((round < rounds)); then
    sleep "$pause_sec"
  fi
done

echo
echo "[3machine-prod-wg-soak] summary passed=$passed failed=$failed total=$rounds max_consecutive_failures_seen=$max_seen_consecutive_failures"
if ((failed > 0)); then
  for class in "${!failure_class_counts[@]}"; do
    echo "[3machine-prod-wg-soak] failure_class ${class}=${failure_class_counts[$class]}"
  done | sort
fi
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  {
    echo "{"
    if ((failed > 0)); then
      echo "  \"status\": \"fail\","
    else
      echo "  \"status\": \"ok\","
    fi
    echo "  \"rounds_requested\": $rounds,"
    echo "  \"rounds_passed\": $passed,"
    echo "  \"rounds_failed\": $failed,"
    echo "  \"max_consecutive_failures_seen\": $max_seen_consecutive_failures,"
    echo "  \"max_consecutive_failures_limit\": $max_consecutive_failures,"
    echo "  \"report_file\": \"$(json_escape "$report_file")\","
    echo "  \"summary_generated_at_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"failure_classes\": {"
    if ((failed > 0)); then
      mapfile -t sorted_classes < <(printf '%s\n' "${!failure_class_counts[@]}" | sort)
      for idx in "${!sorted_classes[@]}"; do
        class="${sorted_classes[$idx]}"
        [[ -z "$class" ]] && continue
        count="${failure_class_counts[$class]:-0}"
        if ((idx + 1 < ${#sorted_classes[@]})); then
          printf '    "%s": %s,\n' "$(json_escape "$class")" "$count"
        else
          printf '    "%s": %s\n' "$(json_escape "$class")" "$count"
        fi
      done
    fi
    echo "  }"
    echo "}"
  } >"$summary_json"
  echo "[3machine-prod-wg-soak] summary_json=$summary_json"
fi
if ((failed > 0)); then
  exit 1
fi
echo "[3machine-prod-wg-soak] ok"
