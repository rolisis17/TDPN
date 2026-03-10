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
    [--max-round-duration-sec N] \
    [--max-recovery-sec N] \
    [--max-failure-class CLASS=N] \
    [--disallow-unknown-failure-class [0|1]] \
    [--min-selection-lines N] \
    [--min-entry-operators N] \
    [--min-exit-operators N] \
    [--min-cross-operator-pairs N] \
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

  sudo ./scripts/integration_3machine_prod_wg_soak.sh \
    --rounds 12 --pause-sec 8 \
    --max-round-duration-sec 90 \
    --max-recovery-sec 120 \
    --max-failure-class endpoint_connectivity=2 \
    --max-failure-class timeout=1 \
    --disallow-unknown-failure-class 1 \
    --min-selection-lines 8 \
    --min-entry-operators 2 \
    --min-exit-operators 2 \
    --min-cross-operator-pairs 2
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
  if [[ "$dataplane_reason" == "round_duration_slo" ]]; then
    echo "round_duration_slo"
    return
  fi
  if [[ "$dataplane_reason" == "recovery_slo" ]]; then
    echo "recovery_slo"
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

valid_failure_class_name() {
  local class="$1"
  [[ "$class" =~ ^[A-Za-z0-9_.-]+$ ]]
}

selection_tuples_from_log() {
  local round_log="$1"
  if [[ ! -f "$round_log" ]]; then
    return
  fi
  awk '
    /client selected entry=/ {
      entry_op = ""; exit_op = "";
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^entry_op=/) {
          entry_op = substr($i, 10);
        } else if ($i ~ /^exit_op=/) {
          exit_op = substr($i, 9);
        }
      }
      if (entry_op != "" && exit_op != "") {
        print entry_op, exit_op;
      }
    }
  ' "$round_log"
}

rounds="${THREE_MACHINE_PROD_WG_SOAK_ROUNDS:-10}"
pause_sec="${THREE_MACHINE_PROD_WG_SOAK_PAUSE_SEC:-8}"
fault_every="${THREE_MACHINE_PROD_WG_SOAK_FAULT_EVERY:-0}"
fault_command="${THREE_MACHINE_PROD_WG_SOAK_FAULT_COMMAND:-}"
continue_on_fail="${THREE_MACHINE_PROD_WG_SOAK_CONTINUE_ON_FAIL:-0}"
max_consecutive_failures="${THREE_MACHINE_PROD_WG_SOAK_MAX_CONSECUTIVE_FAILURES:-2}"
max_round_duration_sec="${THREE_MACHINE_PROD_WG_SOAK_MAX_ROUND_DURATION_SEC:-0}"
max_recovery_sec="${THREE_MACHINE_PROD_WG_SOAK_MAX_RECOVERY_SEC:-0}"
disallow_unknown_failure_class="${THREE_MACHINE_PROD_WG_SOAK_DISALLOW_UNKNOWN_FAILURE_CLASS:-0}"
max_failure_class_env="${THREE_MACHINE_PROD_WG_SOAK_MAX_FAILURE_CLASS:-}"
min_selection_lines="${THREE_MACHINE_PROD_WG_SOAK_MIN_SELECTION_LINES:-0}"
min_entry_operators="${THREE_MACHINE_PROD_WG_SOAK_MIN_ENTRY_OPERATORS:-0}"
min_exit_operators="${THREE_MACHINE_PROD_WG_SOAK_MIN_EXIT_OPERATORS:-0}"
min_cross_operator_pairs="${THREE_MACHINE_PROD_WG_SOAK_MIN_CROSS_OPERATOR_PAIRS:-0}"
declare -a max_failure_class_specs=()
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
    --max-round-duration-sec)
      max_round_duration_sec="${2:-}"
      shift 2
      ;;
    --max-recovery-sec)
      max_recovery_sec="${2:-}"
      shift 2
      ;;
    --max-failure-class)
      max_failure_class_specs+=("${2:-}")
      shift 2
      ;;
    --disallow-unknown-failure-class)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        disallow_unknown_failure_class="${2:-}"
        shift 2
      else
        disallow_unknown_failure_class="1"
        shift
      fi
      ;;
    --min-selection-lines)
      min_selection_lines="${2:-}"
      shift 2
      ;;
    --min-entry-operators)
      min_entry_operators="${2:-}"
      shift 2
      ;;
    --min-exit-operators)
      min_exit_operators="${2:-}"
      shift 2
      ;;
    --min-cross-operator-pairs)
      min_cross_operator_pairs="${2:-}"
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

if [[ -n "$(trim "$max_failure_class_env")" ]]; then
  IFS=',' read -r -a env_specs <<<"$max_failure_class_env"
  for spec in "${env_specs[@]}"; do
    spec="$(trim "$spec")"
    [[ -z "$spec" ]] && continue
    max_failure_class_specs+=("$spec")
  done
fi

if ! [[ "$rounds" =~ ^[0-9]+$ && "$pause_sec" =~ ^[0-9]+$ && "$fault_every" =~ ^[0-9]+$ && "$max_consecutive_failures" =~ ^[0-9]+$ && "$max_round_duration_sec" =~ ^[0-9]+$ && "$max_recovery_sec" =~ ^[0-9]+$ && "$min_selection_lines" =~ ^[0-9]+$ && "$min_entry_operators" =~ ^[0-9]+$ && "$min_exit_operators" =~ ^[0-9]+$ && "$min_cross_operator_pairs" =~ ^[0-9]+$ ]]; then
  echo "--rounds, --pause-sec, --fault-every, --max-consecutive-failures, --max-round-duration-sec, --max-recovery-sec, and diversity thresholds must be integers"
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
if [[ "$disallow_unknown_failure_class" != "0" && "$disallow_unknown_failure_class" != "1" ]]; then
  echo "--disallow-unknown-failure-class must be 0 or 1"
  exit 2
fi
if ((fault_every > 0)) && [[ -z "$(trim "$fault_command")" ]]; then
  echo "--fault-command is required when --fault-every > 0"
  exit 2
fi

declare -A failure_class_limits=()
for spec in "${max_failure_class_specs[@]}"; do
  spec="$(trim "$spec")"
  [[ -z "$spec" ]] && continue
  if [[ ! "$spec" =~ ^[^=]+=[0-9]+$ ]]; then
    echo "--max-failure-class must use CLASS=N format (invalid: $spec)"
    exit 2
  fi
  class="${spec%%=*}"
  limit="${spec##*=}"
  class="$(trim "$class")"
  if ! valid_failure_class_name "$class"; then
    echo "invalid failure class name in --max-failure-class: $class"
    exit 2
  fi
  if [[ -z "$limit" || ! "$limit" =~ ^[0-9]+$ ]]; then
    echo "invalid failure class limit in --max-failure-class: $spec"
    exit 2
  fi
  failure_class_limits["$class"]="$limit"
done

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
echo "[3machine-prod-wg-soak] rounds=$rounds pause_sec=$pause_sec fault_every=$fault_every continue_on_fail=$continue_on_fail max_consecutive_failures=$max_consecutive_failures max_round_duration_sec=$max_round_duration_sec max_recovery_sec=$max_recovery_sec disallow_unknown_failure_class=$disallow_unknown_failure_class"
echo "[3machine-prod-wg-soak] diversity_thresholds min_selection_lines=$min_selection_lines min_entry_operators=$min_entry_operators min_exit_operators=$min_exit_operators min_cross_operator_pairs=$min_cross_operator_pairs"
if ((${#failure_class_limits[@]} > 0)); then
  while IFS= read -r class; do
    [[ -z "$class" ]] && continue
    echo "[3machine-prod-wg-soak] failure_class_limit ${class}=${failure_class_limits[$class]}"
  done < <(printf '%s\n' "${!failure_class_limits[@]}" | sort)
fi

passed=0
failed=0
consecutive_failures=0
max_seen_consecutive_failures=0
round_duration_sec_max=0
recovery_incident_open=0
recovery_incident_started_ts=0
recovery_incidents=0
recovery_sec_total=0
recovery_sec_max=0
recovery_slo_violations=0
declare -A failure_class_counts=()
declare -A failure_class_limit_violations=()
declare -A seen_entry_operators=()
declare -A seen_exit_operators=()
declare -A seen_cross_operator_pairs=()
selection_lines_total=0

for round in $(seq 1 "$rounds"); do
  echo
  echo "[3machine-prod-wg-soak] round=$round/$rounds"
  round_started_ts="$(date +%s)"

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

  round_finished_ts="$(date +%s)"
  round_duration_sec=$((round_finished_ts - round_started_ts))
  if ((round_duration_sec > round_duration_sec_max)); then
    round_duration_sec_max=$round_duration_sec
  fi
  if ((max_round_duration_sec > 0)) && ((round_duration_sec > max_round_duration_sec)); then
    echo "[3machine-prod-wg-soak] round=$round exceeded max round duration: observed=${round_duration_sec}s limit=${max_round_duration_sec}s"
    if [[ "$rc" -eq 0 ]]; then
      dataplane_fail_reason="round_duration_slo"
      rc=1
    fi
  fi

  if [[ "$rc" -ne 0 ]]; then
    if [[ "$recovery_incident_open" -eq 0 ]]; then
      recovery_incident_open=1
      recovery_incident_started_ts="$round_started_ts"
    fi
  else
    if [[ "$recovery_incident_open" -eq 1 ]]; then
      recovery_sec=$((round_finished_ts - recovery_incident_started_ts))
      recovery_incident_open=0
      recovery_incidents=$((recovery_incidents + 1))
      recovery_sec_total=$((recovery_sec_total + recovery_sec))
      if ((recovery_sec > recovery_sec_max)); then
        recovery_sec_max=$recovery_sec
      fi
      if ((max_recovery_sec > 0)) && ((recovery_sec > max_recovery_sec)); then
        recovery_slo_violations=$((recovery_slo_violations + 1))
        echo "[3machine-prod-wg-soak] round=$round recovery SLO exceeded: observed=${recovery_sec}s limit=${max_recovery_sec}s"
        dataplane_fail_reason="recovery_slo"
        rc=1
      fi
    fi
  fi

  if [[ "$rc" -eq 0 ]]; then
    round_selection_lines=0
    while read -r entry_op exit_op; do
      [[ -z "$entry_op" || -z "$exit_op" ]] && continue
      seen_entry_operators["$entry_op"]=1
      seen_exit_operators["$exit_op"]=1
      seen_cross_operator_pairs["${entry_op}|${exit_op}"]=1
      selection_lines_total=$((selection_lines_total + 1))
      round_selection_lines=$((round_selection_lines + 1))
    done < <(selection_tuples_from_log "$round_log")
    passed=$((passed + 1))
    consecutive_failures=0
    echo "[3machine-prod-wg-soak] round=$round result=ok accepted_delta_total=$dataplane_delta_total selection_lines=$round_selection_lines duration_sec=$round_duration_sec log=$round_log"
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
      echo "[3machine-prod-wg-soak] round=$round result=fail rc=$rc class=$failure_class duration_sec=$round_duration_sec reason=$(printf '%s' "$reason_line" | sed -E 's/[[:space:]]+/ /g') log=$round_log"
    else
      echo "[3machine-prod-wg-soak] round=$round result=fail rc=$rc class=$failure_class duration_sec=$round_duration_sec log=$round_log"
    fi
    if [[ "$disallow_unknown_failure_class" == "1" && "$failure_class" == "unknown" ]]; then
      echo "[3machine-prod-wg-soak] stopping: disallowed unknown failure class encountered"
      break
    fi
    class_limit="${failure_class_limits[$failure_class]:-}"
    if [[ -n "$class_limit" ]] && (( failure_class_counts["$failure_class"] > class_limit )); then
      failure_class_limit_violations["$failure_class"]=$(( ${failure_class_limit_violations[$failure_class]:-0} + 1 ))
      echo "[3machine-prod-wg-soak] stopping: failure class limit exceeded class=$failure_class observed=${failure_class_counts[$failure_class]} limit=$class_limit"
      break
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

recovery_sec_avg=0
if ((recovery_incidents > 0)); then
  recovery_sec_avg=$((recovery_sec_total / recovery_incidents))
fi
class_limit_violation_total=0
for class in "${!failure_class_limit_violations[@]}"; do
  class_limit_violation_total=$((class_limit_violation_total + failure_class_limit_violations[$class]))
done

entry_operator_count=${#seen_entry_operators[@]}
exit_operator_count=${#seen_exit_operators[@]}
cross_operator_pair_count=${#seen_cross_operator_pairs[@]}
diversity_failed=0
if ((selection_lines_total < min_selection_lines)); then
  diversity_failed=1
  echo "[3machine-prod-wg-soak] diversity threshold not met: selection_lines_total=$selection_lines_total < min_selection_lines=$min_selection_lines"
fi
if ((entry_operator_count < min_entry_operators)); then
  diversity_failed=1
  echo "[3machine-prod-wg-soak] diversity threshold not met: entry_operator_count=$entry_operator_count < min_entry_operators=$min_entry_operators"
fi
if ((exit_operator_count < min_exit_operators)); then
  diversity_failed=1
  echo "[3machine-prod-wg-soak] diversity threshold not met: exit_operator_count=$exit_operator_count < min_exit_operators=$min_exit_operators"
fi
if ((cross_operator_pair_count < min_cross_operator_pairs)); then
  diversity_failed=1
  echo "[3machine-prod-wg-soak] diversity threshold not met: cross_operator_pair_count=$cross_operator_pair_count < min_cross_operator_pairs=$min_cross_operator_pairs"
fi
if ((diversity_failed > 0)); then
  failure_class_counts["diversity_threshold"]=$(( ${failure_class_counts["diversity_threshold"]:-0} + 1 ))
  failed=$((failed + 1))
fi

echo
echo "[3machine-prod-wg-soak] summary passed=$passed failed=$failed total=$rounds max_consecutive_failures_seen=$max_seen_consecutive_failures"
echo "[3machine-prod-wg-soak] slo_summary max_round_duration_seen=${round_duration_sec_max}s max_round_duration_limit=${max_round_duration_sec}s recovery_incidents=$recovery_incidents recovery_sec_avg=${recovery_sec_avg}s recovery_sec_max=${recovery_sec_max}s recovery_sec_limit=${max_recovery_sec}s recovery_slo_violations=$recovery_slo_violations recovery_incident_open=$recovery_incident_open"
echo "[3machine-prod-wg-soak] diversity_summary selection_lines_total=$selection_lines_total entry_operator_count=$entry_operator_count exit_operator_count=$exit_operator_count cross_operator_pair_count=$cross_operator_pair_count diversity_failed=$diversity_failed"
if ((failed > 0)); then
  for class in "${!failure_class_counts[@]}"; do
    echo "[3machine-prod-wg-soak] failure_class ${class}=${failure_class_counts[$class]}"
  done | sort
fi
if ((${#failure_class_limits[@]} > 0)); then
  while IFS= read -r class; do
    [[ -z "$class" ]] && continue
    observed="${failure_class_counts[$class]:-0}"
    violations="${failure_class_limit_violations[$class]:-0}"
    echo "[3machine-prod-wg-soak] failure_class_limit ${class}=${failure_class_limits[$class]} observed=$observed violations=$violations"
  done < <(printf '%s\n' "${!failure_class_limits[@]}" | sort)
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
    echo "  \"max_round_duration_seen_sec\": $round_duration_sec_max,"
    echo "  \"max_round_duration_limit_sec\": $max_round_duration_sec,"
    echo "  \"max_recovery_limit_sec\": $max_recovery_sec,"
    echo "  \"recovery_incidents\": $recovery_incidents,"
    echo "  \"recovery_incident_open\": $recovery_incident_open,"
    echo "  \"recovery_sec_avg\": $recovery_sec_avg,"
    echo "  \"recovery_sec_max\": $recovery_sec_max,"
    echo "  \"recovery_slo_violations\": $recovery_slo_violations,"
    echo "  \"selection_lines_total\": $selection_lines_total,"
    echo "  \"selection_entry_operators\": $entry_operator_count,"
    echo "  \"selection_exit_operators\": $exit_operator_count,"
    echo "  \"selection_cross_operator_pairs\": $cross_operator_pair_count,"
    echo "  \"selection_min_lines\": $min_selection_lines,"
    echo "  \"selection_min_entry_operators\": $min_entry_operators,"
    echo "  \"selection_min_exit_operators\": $min_exit_operators,"
    echo "  \"selection_min_cross_operator_pairs\": $min_cross_operator_pairs,"
    echo "  \"selection_diversity_failed\": $diversity_failed,"
    echo "  \"disallow_unknown_failure_class\": $disallow_unknown_failure_class,"
    echo "  \"failure_class_limit_violations_total\": $class_limit_violation_total,"
    echo "  \"report_file\": \"$(json_escape "$report_file")\","
    echo "  \"summary_generated_at_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"failure_class_limits\": {"
    if ((${#failure_class_limits[@]} > 0)); then
      mapfile -t sorted_limits < <(printf '%s\n' "${!failure_class_limits[@]}" | sort)
      for idx in "${!sorted_limits[@]}"; do
        class="${sorted_limits[$idx]}"
        [[ -z "$class" ]] && continue
        count="${failure_class_limits[$class]:-0}"
        if ((idx + 1 < ${#sorted_limits[@]})); then
          printf '    "%s": %s,\n' "$(json_escape "$class")" "$count"
        else
          printf '    "%s": %s\n' "$(json_escape "$class")" "$count"
        fi
      done
    fi
    echo "  },"
    echo "  \"failure_class_limit_violations\": {"
    if ((class_limit_violation_total > 0)); then
      mapfile -t sorted_violations < <(printf '%s\n' "${!failure_class_limit_violations[@]}" | sort)
      for idx in "${!sorted_violations[@]}"; do
        class="${sorted_violations[$idx]}"
        [[ -z "$class" ]] && continue
        count="${failure_class_limit_violations[$class]:-0}"
        if ((idx + 1 < ${#sorted_violations[@]})); then
          printf '    "%s": %s,\n' "$(json_escape "$class")" "$count"
        else
          printf '    "%s": %s\n' "$(json_escape "$class")" "$count"
        fi
      done
    fi
    echo "  },"
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
