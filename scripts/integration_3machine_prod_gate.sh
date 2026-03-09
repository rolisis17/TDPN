#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BETA_VALIDATE_SCRIPT="${THREE_MACHINE_BETA_VALIDATE_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_beta_validate.sh}"
BETA_SOAK_SCRIPT="${THREE_MACHINE_BETA_SOAK_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_beta_soak.sh}"
PROD_WG_VALIDATE_SCRIPT="${THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_prod_wg_validate.sh}"
PROD_WG_SOAK_SCRIPT="${THREE_MACHINE_PROD_WG_SOAK_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_prod_wg_soak.sh}"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/integration_3machine_prod_gate.sh \
    [--directory-a URL] \
    [--directory-b URL] \
    [--bootstrap-directory URL] \
    [--discovery-wait-sec N] \
    [--issuer-url URL] \
    [--entry-url URL] \
    [--exit-url URL] \
    [--subject ID] \
    [--anon-cred TOKEN] \
    [--min-sources N] \
    [--min-operators N] \
    [--federation-timeout-sec N] \
    [--control-timeout-sec N] \
    [--control-soak-rounds N] \
    [--control-soak-pause-sec N] \
    [--wg-client-timeout-sec N] \
    [--wg-session-sec N] \
    [--wg-soak-rounds N] \
    [--wg-soak-pause-sec N] \
    [--wg-max-consecutive-failures N] \
    [--wg-soak-summary-json PATH] \
    [--gate-summary-json PATH] \
    [--fault-every N] \
    [--fault-command CMD] \
    [--continue-on-fail [0|1]] \
    [--strict-distinct [0|1]] \
    [--skip-control-soak [0|1]] \
    [--skip-wg [0|1]] \
    [--skip-wg-soak [0|1]] \
    [--mtls-ca-file PATH] \
    [--mtls-client-cert-file PATH] \
    [--mtls-client-key-file PATH] \
    [--report-file PATH]

Purpose:
  Production-grade 3-machine sequence runner from machine C:
    1) strict control-plane validate
    2) control-plane soak
    3) real WG production dataplane validate (Linux root)
    4) real WG production dataplane soak

Notes:
  - If --skip-wg=0 (default), run with sudo/root on Linux.
  - Endpoint args can be explicit A/B URLs or one bootstrap directory URL.
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

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

json_number_field() {
  local file="$1"
  local key="$2"
  sed -nE "s/^[[:space:]]*\"${key}\":[[:space:]]*([0-9]+).*/\1/p" "$file" | head -n1
}

json_string_field() {
  local file="$1"
  local key="$2"
  sed -nE "s/^[[:space:]]*\"${key}\":[[:space:]]*\"([^\"]*)\".*/\1/p" "$file" | head -n1
}

wg_soak_top_failure_class_count() {
  local summary_file="$1"
  local top_class="none"
  local top_count=0
  local class_name class_count

  if [[ -z "$summary_file" || ! -s "$summary_file" ]]; then
    echo "${top_class}|${top_count}"
    return
  fi

  while read -r class_name class_count; do
    [[ -z "$class_name" || -z "$class_count" ]] && continue
    if ((class_count > top_count)); then
      top_count="$class_count"
      top_class="$class_name"
    fi
  done < <(sed -n '/"failure_classes"[[:space:]]*:[[:space:]]*{/,/^[[:space:]]*}/p' "$summary_file" | sed -nE 's/^[[:space:]]*"([^"]+)"[[:space:]]*:[[:space:]]*([0-9]+).*/\1 \2/p')

  echo "${top_class}|${top_count}"
}

print_wg_soak_summary_compact() {
  local summary_file="$1"
  local strict_missing="${2:-0}"
  local status rounds_requested rounds_passed rounds_failed max_seen max_limit
  local top_class_count top_class top_count

  if [[ -z "$summary_file" || ! -s "$summary_file" ]]; then
    if [[ "$strict_missing" == "1" ]]; then
      echo "[prod-gate] wg_soak_summary missing or empty: ${summary_file:-<unset>}"
    fi
    return
  fi

  status="$(json_string_field "$summary_file" "status")"
  rounds_requested="$(json_number_field "$summary_file" "rounds_requested")"
  rounds_passed="$(json_number_field "$summary_file" "rounds_passed")"
  rounds_failed="$(json_number_field "$summary_file" "rounds_failed")"
  max_seen="$(json_number_field "$summary_file" "max_consecutive_failures_seen")"
  max_limit="$(json_number_field "$summary_file" "max_consecutive_failures_limit")"
  top_class_count="$(wg_soak_top_failure_class_count "$summary_file")"
  top_class="${top_class_count%%|*}"
  top_count="${top_class_count##*|}"

  echo "[prod-gate] wg_soak_summary status=${status:-unknown} rounds=${rounds_passed:-0}/${rounds_requested:-0} failed=${rounds_failed:-0} max_consecutive_failures=${max_seen:-0}/${max_limit:-0} top_failure_class=${top_class} top_failure_count=${top_count} summary_json=$summary_file"
}

set_step_status() {
  local step_name="$1"
  local status="$2"
  case "$step_name" in
    control_validate) step_control_validate="$status" ;;
    control_soak) step_control_soak="$status" ;;
    prod_wg_validate) step_prod_wg_validate="$status" ;;
    prod_wg_soak) step_prod_wg_soak="$status" ;;
  esac
}

run_step() {
  local step_name="$1"
  local step_log="$2"
  shift 2
  local -a cmd=("$@")
  mkdir -p "$(dirname "$step_log")"
  set_step_status "$step_name" "in_progress"
  echo
  echo "[prod-gate] step=$step_name"
  echo "[prod-gate] log=$step_log"
  echo "[prod-gate] cmd=${cmd[*]}"
  set +e
  "${cmd[@]}" > >(tee -a "$step_log") 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    set_step_status "$step_name" "failed"
    gate_failed_step="$step_name"
    gate_failed_rc="$rc"
    echo "[prod-gate] step=$step_name failed rc=$rc (log=$step_log)"
    exit "$rc"
  fi
  set_step_status "$step_name" "ok"
  echo "[prod-gate] step=$step_name ok"
}

directory_a=""
directory_b=""
bootstrap_directory=""
discovery_wait_sec="${THREE_MACHINE_DISCOVERY_WAIT_SEC:-20}"
issuer_url=""
entry_url=""
exit_url=""
client_subject=""
client_anon_cred=""
min_sources="${THREE_MACHINE_MIN_SOURCES:-2}"
min_operators="${THREE_MACHINE_MIN_OPERATORS:-2}"
federation_timeout_sec="${THREE_MACHINE_FEDERATION_TIMEOUT_SEC:-90}"
control_timeout_sec="${THREE_MACHINE_PROD_GATE_CONTROL_TIMEOUT_SEC:-50}"
control_soak_rounds="${THREE_MACHINE_PROD_GATE_CONTROL_SOAK_ROUNDS:-10}"
control_soak_pause_sec="${THREE_MACHINE_PROD_GATE_CONTROL_SOAK_PAUSE_SEC:-5}"
wg_client_timeout_sec="${THREE_MACHINE_PROD_GATE_WG_CLIENT_TIMEOUT_SEC:-120}"
wg_session_sec="${THREE_MACHINE_PROD_GATE_WG_SESSION_SEC:-45}"
wg_soak_rounds="${THREE_MACHINE_PROD_GATE_WG_SOAK_ROUNDS:-10}"
wg_soak_pause_sec="${THREE_MACHINE_PROD_GATE_WG_SOAK_PAUSE_SEC:-8}"
wg_max_consecutive_failures="${THREE_MACHINE_PROD_GATE_WG_MAX_CONSECUTIVE_FAILURES:-2}"
wg_soak_summary_json="${THREE_MACHINE_PROD_GATE_WG_SOAK_SUMMARY_JSON:-}"
gate_summary_json="${THREE_MACHINE_PROD_GATE_SUMMARY_JSON:-}"
fault_every="${THREE_MACHINE_PROD_GATE_FAULT_EVERY:-0}"
fault_command="${THREE_MACHINE_PROD_GATE_FAULT_COMMAND:-}"
continue_on_fail="${THREE_MACHINE_PROD_GATE_CONTINUE_ON_FAIL:-0}"
strict_distinct="${THREE_MACHINE_DISTINCT_OPERATORS:-1}"
skip_control_soak="${THREE_MACHINE_PROD_GATE_SKIP_CONTROL_SOAK:-0}"
skip_wg="${THREE_MACHINE_PROD_GATE_SKIP_WG:-0}"
skip_wg_soak="${THREE_MACHINE_PROD_GATE_SKIP_WG_SOAK:-0}"
allow_non_root="${THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT:-0}"
mtls_ca_file="${THREE_MACHINE_PROD_GATE_MTLS_CA_FILE:-deploy/tls/ca.crt}"
mtls_client_cert_file="${THREE_MACHINE_PROD_GATE_MTLS_CLIENT_CERT_FILE:-deploy/tls/client.crt}"
mtls_client_key_file="${THREE_MACHINE_PROD_GATE_MTLS_CLIENT_KEY_FILE:-deploy/tls/client.key}"
report_file=""
wg_soak_step_started="0"
wg_soak_summary_emitted="0"
gate_summary_written="0"
gate_failed_step=""
gate_failed_rc="0"
gate_exit_rc="0"
gate_started_at_utc=""
step_control_validate="pending"
step_control_soak="pending"
step_prod_wg_validate="pending"
step_prod_wg_soak="pending"

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
    --bootstrap-directory)
      bootstrap_directory="${2:-}"
      shift 2
      ;;
    --discovery-wait-sec)
      discovery_wait_sec="${2:-}"
      shift 2
      ;;
    --issuer-url)
      issuer_url="${2:-}"
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
    --subject)
      client_subject="${2:-}"
      shift 2
      ;;
    --anon-cred)
      client_anon_cred="${2:-}"
      shift 2
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
    --control-timeout-sec)
      control_timeout_sec="${2:-}"
      shift 2
      ;;
    --control-soak-rounds)
      control_soak_rounds="${2:-}"
      shift 2
      ;;
    --control-soak-pause-sec)
      control_soak_pause_sec="${2:-}"
      shift 2
      ;;
    --wg-client-timeout-sec)
      wg_client_timeout_sec="${2:-}"
      shift 2
      ;;
    --wg-session-sec)
      wg_session_sec="${2:-}"
      shift 2
      ;;
    --wg-soak-rounds)
      wg_soak_rounds="${2:-}"
      shift 2
      ;;
    --wg-soak-pause-sec)
      wg_soak_pause_sec="${2:-}"
      shift 2
      ;;
    --wg-max-consecutive-failures)
      wg_max_consecutive_failures="${2:-}"
      shift 2
      ;;
    --wg-soak-summary-json)
      wg_soak_summary_json="${2:-}"
      shift 2
      ;;
    --gate-summary-json|--summary-json)
      gate_summary_json="${2:-}"
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
    --strict-distinct)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        strict_distinct="${2:-}"
        shift 2
      else
        strict_distinct="1"
        shift
      fi
      ;;
    --skip-control-soak)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        skip_control_soak="${2:-}"
        shift 2
      else
        skip_control_soak="1"
        shift
      fi
      ;;
    --skip-wg)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        skip_wg="${2:-}"
        shift 2
      else
        skip_wg="1"
        shift
      fi
      ;;
    --skip-wg-soak)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        skip_wg_soak="${2:-}"
        shift 2
      else
        skip_wg_soak="1"
        shift
      fi
      ;;
    --mtls-ca-file)
      mtls_ca_file="${2:-}"
      shift 2
      ;;
    --mtls-client-cert-file)
      mtls_client_cert_file="${2:-}"
      shift 2
      ;;
    --mtls-client-key-file)
      mtls_client_key_file="${2:-}"
      shift 2
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
      echo "unknown arg: $1"
      usage
      exit 2
      ;;
  esac
done

for script in "$BETA_VALIDATE_SCRIPT" "$BETA_SOAK_SCRIPT" "$PROD_WG_VALIDATE_SCRIPT" "$PROD_WG_SOAK_SCRIPT"; do
  if [[ ! -x "$script" ]]; then
    echo "missing executable helper: $script"
    exit 2
  fi
done

for cmd in bash date tee; do
  need_cmd "$cmd"
done

if ! [[ "$min_sources" =~ ^[0-9]+$ && "$min_operators" =~ ^[0-9]+$ && "$federation_timeout_sec" =~ ^[0-9]+$ && "$control_timeout_sec" =~ ^[0-9]+$ && "$control_soak_rounds" =~ ^[0-9]+$ && "$control_soak_pause_sec" =~ ^[0-9]+$ && "$wg_client_timeout_sec" =~ ^[0-9]+$ && "$wg_session_sec" =~ ^[0-9]+$ && "$wg_soak_rounds" =~ ^[0-9]+$ && "$wg_soak_pause_sec" =~ ^[0-9]+$ && "$wg_max_consecutive_failures" =~ ^[0-9]+$ && "$fault_every" =~ ^[0-9]+$ && "$discovery_wait_sec" =~ ^[0-9]+$ ]]; then
  echo "numeric args are invalid"
  exit 2
fi
if ((wg_max_consecutive_failures < 1)); then
  echo "--wg-max-consecutive-failures must be >= 1"
  exit 2
fi

if [[ "$strict_distinct" != "0" && "$strict_distinct" != "1" ]]; then
  echo "--strict-distinct must be 0 or 1"
  exit 2
fi
if [[ "$continue_on_fail" != "0" && "$continue_on_fail" != "1" ]]; then
  echo "--continue-on-fail must be 0 or 1"
  exit 2
fi
for flag in "$skip_control_soak" "$skip_wg" "$skip_wg_soak"; do
  if [[ "$flag" != "0" && "$flag" != "1" ]]; then
    echo "skip flags must be 0 or 1"
    exit 2
  fi
done
if [[ "$allow_non_root" != "0" && "$allow_non_root" != "1" ]]; then
  echo "THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT must be 0 or 1"
  exit 2
fi
if ((fault_every > 0)) && [[ -z "$(trim "$fault_command")" ]]; then
  echo "--fault-command is required when --fault-every > 0"
  exit 2
fi

if [[ -z "$report_file" ]]; then
  report_file="$(default_log_dir)/privacynode_3machine_prod_gate_$(date +%Y%m%d_%H%M%S).log"
fi
mkdir -p "$(dirname "$report_file")"
exec > >(tee -a "$report_file") 2>&1

run_id="$(date +%Y%m%d_%H%M%S)"
step_dir="$(default_log_dir)/prod_gate_steps_${run_id}"
mkdir -p "$step_dir"

echo "[prod-gate] started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[prod-gate] report: $report_file"
echo "[prod-gate] step_logs: $step_dir"
echo "[prod-gate] strict_distinct=$strict_distinct skip_control_soak=$skip_control_soak skip_wg=$skip_wg skip_wg_soak=$skip_wg_soak wg_max_consecutive_failures=$wg_max_consecutive_failures"
gate_started_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [[ -z "$wg_soak_summary_json" ]]; then
  wg_soak_summary_json="$step_dir/04_prod_wg_soak.summary.json"
fi
echo "[prod-gate] wg_soak_summary_json=$wg_soak_summary_json"
if [[ -z "$gate_summary_json" ]]; then
  gate_summary_json="$step_dir/prod_gate_summary.json"
fi
echo "[prod-gate] gate_summary_json=$gate_summary_json"

emit_wg_soak_summary_once() {
  local strict_missing="${1:-0}"
  if [[ "$wg_soak_summary_emitted" == "1" ]]; then
    return
  fi
  print_wg_soak_summary_compact "$wg_soak_summary_json" "$strict_missing"
  wg_soak_summary_emitted="1"
}

write_gate_summary_once() {
  local finished_at_utc gate_status
  local wg_status="" wg_rounds_passed="0" wg_rounds_failed="0" wg_top_class="none" wg_top_count="0"
  local wg_top_pair

  if [[ "$gate_summary_written" == "1" ]]; then
    return
  fi
  mkdir -p "$(dirname "$gate_summary_json")"
  finished_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "$gate_exit_rc" -ne 0 || -n "$gate_failed_step" ]]; then
    gate_status="fail"
  else
    gate_status="ok"
  fi
  if [[ -s "$wg_soak_summary_json" ]]; then
    wg_status="$(json_string_field "$wg_soak_summary_json" "status")"
    wg_rounds_passed="$(json_number_field "$wg_soak_summary_json" "rounds_passed")"
    wg_rounds_failed="$(json_number_field "$wg_soak_summary_json" "rounds_failed")"
    [[ -z "$wg_rounds_passed" || ! "$wg_rounds_passed" =~ ^[0-9]+$ ]] && wg_rounds_passed="0"
    [[ -z "$wg_rounds_failed" || ! "$wg_rounds_failed" =~ ^[0-9]+$ ]] && wg_rounds_failed="0"
    wg_top_pair="$(wg_soak_top_failure_class_count "$wg_soak_summary_json")"
    wg_top_class="${wg_top_pair%%|*}"
    wg_top_count="${wg_top_pair##*|}"
  fi

  {
    echo "{"
    echo "  \"status\": \"$(json_escape "$gate_status")\","
    echo "  \"failed_step\": \"$(json_escape "$gate_failed_step")\","
    echo "  \"failed_rc\": $gate_failed_rc,"
    echo "  \"started_at_utc\": \"$(json_escape "$gate_started_at_utc")\","
    echo "  \"finished_at_utc\": \"$(json_escape "$finished_at_utc")\","
    echo "  \"report_file\": \"$(json_escape "$report_file")\","
    echo "  \"step_logs\": \"$(json_escape "$step_dir")\","
    echo "  \"steps\": {"
    echo "    \"control_validate\": \"$(json_escape "$step_control_validate")\","
    echo "    \"control_soak\": \"$(json_escape "$step_control_soak")\","
    echo "    \"prod_wg_validate\": \"$(json_escape "$step_prod_wg_validate")\","
    echo "    \"prod_wg_soak\": \"$(json_escape "$step_prod_wg_soak")\""
    echo "  },"
    echo "  \"wg_soak_summary_json\": \"$(json_escape "$wg_soak_summary_json")\","
    echo "  \"wg_soak_status\": \"$(json_escape "$wg_status")\","
    echo "  \"wg_soak_rounds_passed\": $wg_rounds_passed,"
    echo "  \"wg_soak_rounds_failed\": $wg_rounds_failed,"
    echo "  \"wg_soak_top_failure_class\": \"$(json_escape "$wg_top_class")\","
    echo "  \"wg_soak_top_failure_count\": $wg_top_count"
    echo "}"
  } >"$gate_summary_json"

  gate_summary_written="1"
}

on_exit_prod_gate() {
  local rc=$?
  gate_exit_rc="$rc"
  if [[ "$rc" -ne 0 && "$gate_failed_rc" == "0" ]]; then
    gate_failed_rc="$rc"
  fi
  if [[ "$rc" -ne 0 ]]; then
    if [[ "$skip_wg" == "0" && "$skip_wg_soak" == "0" ]]; then
      if [[ "$wg_soak_step_started" == "1" || -s "$wg_soak_summary_json" ]]; then
        emit_wg_soak_summary_once 0
      fi
    fi
  fi
  write_gate_summary_once
  echo "[prod-gate] gate_summary_json=$gate_summary_json"
  return "$rc"
}
trap 'on_exit_prod_gate' EXIT

declare -a common_args=()
if [[ -n "$bootstrap_directory" ]]; then
  common_args+=(--bootstrap-directory "$bootstrap_directory")
  common_args+=(--discovery-wait-sec "$discovery_wait_sec")
else
  if [[ -n "$directory_a" ]]; then
    common_args+=(--directory-a "$directory_a")
  fi
  if [[ -n "$directory_b" ]]; then
    common_args+=(--directory-b "$directory_b")
  fi
fi
if [[ -n "$issuer_url" ]]; then
  common_args+=(--issuer-url "$issuer_url")
fi
if [[ -n "$entry_url" ]]; then
  common_args+=(--entry-url "$entry_url")
fi
if [[ -n "$exit_url" ]]; then
  common_args+=(--exit-url "$exit_url")
fi
if [[ -n "$client_subject" ]]; then
  common_args+=(--subject "$client_subject")
fi
if [[ -n "$client_anon_cred" ]]; then
  common_args+=(--anon-cred "$client_anon_cred")
fi

run_step "control_validate" "$step_dir/01_control_validate.log" \
  "$BETA_VALIDATE_SCRIPT" \
  "${common_args[@]}" \
  --min-sources "$min_sources" \
  --min-operators "$min_operators" \
  --federation-timeout-sec "$federation_timeout_sec" \
  --timeout-sec "$control_timeout_sec" \
  --client-min-selection-lines 8 \
  --client-min-entry-operators 2 \
  --client-min-exit-operators 2 \
  --client-require-cross-operator-pair 1 \
  --distinct-operators "$strict_distinct" \
  --require-issuer-quorum 1 \
  --beta-profile 1 \
  --prod-profile 1

if [[ "$skip_control_soak" == "0" ]]; then
  run_step "control_soak" "$step_dir/02_control_soak.log" \
    "$BETA_SOAK_SCRIPT" \
    "${common_args[@]}" \
    --rounds "$control_soak_rounds" \
    --pause-sec "$control_soak_pause_sec" \
    --min-sources "$min_sources" \
    --min-operators "$min_operators" \
    --federation-timeout-sec "$federation_timeout_sec" \
    --timeout-sec "$control_timeout_sec" \
    --client-min-selection-lines 8 \
    --client-min-entry-operators 2 \
    --client-min-exit-operators 2 \
    --client-require-cross-operator-pair 1 \
    --distinct-operators "$strict_distinct" \
    --require-issuer-quorum 1 \
    --beta-profile 1 \
    --prod-profile 1 \
    --report-file "$step_dir/02_control_soak.log"
else
  echo "[prod-gate] step=control_soak skipped (--skip-control-soak=1)"
  set_step_status "control_soak" "skipped"
fi

if [[ "$skip_wg" == "0" ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 && "$allow_non_root" != "1" ]]; then
    echo "real WG steps require root privileges; re-run with sudo or pass --skip-wg 1"
    exit 1
  fi
  run_step "prod_wg_validate" "$step_dir/03_prod_wg_validate.log" \
    "$PROD_WG_VALIDATE_SCRIPT" \
    "${common_args[@]}" \
    --min-sources "$min_sources" \
    --min-operators "$min_operators" \
    --federation-timeout-sec "$federation_timeout_sec" \
    --control-timeout-sec "$control_timeout_sec" \
    --client-timeout-sec "$wg_client_timeout_sec" \
    --wg-session-sec "$wg_session_sec" \
    --strict-distinct "$strict_distinct" \
    --skip-control-plane-check 1 \
    --mtls-ca-file "$mtls_ca_file" \
    --mtls-client-cert-file "$mtls_client_cert_file" \
    --mtls-client-key-file "$mtls_client_key_file" \
    --report-file "$step_dir/03_prod_wg_validate.log"

  if [[ "$skip_wg_soak" == "0" ]]; then
    wg_soak_step_started="1"
    declare -a wg_soak_args=(
      "$PROD_WG_SOAK_SCRIPT"
      --rounds "$wg_soak_rounds"
      --pause-sec "$wg_soak_pause_sec"
      --max-consecutive-failures "$wg_max_consecutive_failures"
      --summary-json "$wg_soak_summary_json"
      --fault-every "$fault_every"
      --continue-on-fail "$continue_on_fail"
      --report-file "$step_dir/04_prod_wg_soak.log"
      "${common_args[@]}"
      --min-sources "$min_sources"
      --min-operators "$min_operators"
      --federation-timeout-sec "$federation_timeout_sec"
      --control-timeout-sec "$control_timeout_sec"
      --client-timeout-sec "$wg_client_timeout_sec"
      --wg-session-sec "$wg_session_sec"
      --strict-distinct "$strict_distinct"
      --skip-control-plane-check 1
      --mtls-ca-file "$mtls_ca_file"
      --mtls-client-cert-file "$mtls_client_cert_file"
      --mtls-client-key-file "$mtls_client_key_file"
    )
    if [[ -n "$(trim "$fault_command")" ]]; then
      wg_soak_args+=(--fault-command "$fault_command")
    fi
    run_step "prod_wg_soak" "$step_dir/04_prod_wg_soak.log" "${wg_soak_args[@]}"
    emit_wg_soak_summary_once 1
  else
    echo "[prod-gate] step=prod_wg_soak skipped (--skip-wg-soak=1)"
    set_step_status "prod_wg_soak" "skipped"
  fi
else
  echo "[prod-gate] WG steps skipped (--skip-wg=1)"
  set_step_status "prod_wg_validate" "skipped"
  set_step_status "prod_wg_soak" "skipped"
fi

echo
echo "[prod-gate] completed successfully"
echo "[prod-gate] summary_report=$report_file"
echo "[prod-gate] step_logs=$step_dir"
