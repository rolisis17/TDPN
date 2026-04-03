#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/wg_only_stack_selftest_record.sh \
    [wg-only-stack-selftest args...] \
    [--record-result [0|1]] \
    [--manual-validation-report [0|1]] \
    [--manual-validation-report-summary-json PATH] \
    [--manual-validation-report-md PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run the Linux root WG-only stack selftest and record the result into
  manual-validation status automatically.
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

abs_path() {
  local path="$1"
  path="$(trim "$path")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" = /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

prepare_log_dir() {
  local dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
  mkdir -p "$dir"
  printf '%s\n' "$dir"
}

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

append_existing_artifact() {
  local array_name="$1"
  local path="$2"
  [[ -z "$path" ]] && return 0
  if [[ -e "$path" ]]; then
    eval "$array_name+=(\"\$path\")"
  fi
}

validate_manual_validation_summary_payload() {
  local payload="$1"
  local schema_id=""
  local schema_major=""
  local readiness_status=""

  if [[ -z "$payload" ]]; then
    return 1
  fi
  if ! jq -e . >/dev/null 2>&1 <<<"$payload"; then
    return 1
  fi

  schema_id="$(printf '%s\n' "$payload" | jq -r '.schema.id // ""' 2>/dev/null || true)"
  if [[ -n "$schema_id" && "$schema_id" != "manual_validation_readiness_summary" ]]; then
    return 1
  fi
  schema_major="$(printf '%s\n' "$payload" | jq -r '.schema.major // ""' 2>/dev/null || true)"
  if [[ -n "$schema_major" ]]; then
    if [[ ! "$schema_major" =~ ^[0-9]+$ ]] || (( schema_major > 1 )); then
      return 1
    fi
  fi

  readiness_status="$(printf '%s\n' "$payload" | jq -r 'if (.report.readiness_status | type) == "string" then .report.readiness_status else "" end' 2>/dev/null || true)"
  if [[ -z "$readiness_status" ]]; then
    return 1
  fi
  if ! printf '%s\n' "$payload" | jq -e '(.summary | type) == "object"' >/dev/null 2>&1; then
    return 1
  fi

  return 0
}

extract_json_payload() {
  local prefix="$1"
  local text="$2"
  printf '%s\n' "$text" | awk -v p="$prefix" '$0 == "[" p "] summary_json_payload:" {flag=1; next} flag {print}'
}

persist_artifact_text() {
  local path="$1"
  local content="$2"
  local tmp=""
  [[ -z "$path" ]] && return 0
  if [[ -z "$content" ]]; then
    rm -f "$path" 2>/dev/null || true
  else
    mkdir -p "$(dirname "$path")"
    tmp="$(mktemp "${path}.tmp.XXXXXX")"
    printf '%s\n' "$content" >"$tmp"
    mv -f "$tmp" "$path"
  fi
}

run_and_capture() {
  local __var_name="$1"
  shift
  local tmp rc
  tmp="$(mktemp)"
  if "$@" >"$tmp" 2>&1; then
    printf '%s\n' "[$stage] command_ok: $(print_cmd "$@")" >>"$summary_log"
    cat "$tmp" >>"$summary_log"
    printf -v "$__var_name" '%s' "$(cat "$tmp")"
    rm -f "$tmp"
    return 0
  else
    rc=$?
    printf '%s\n' "[$stage] command_failed rc=$rc: $(print_cmd "$@")" >>"$summary_log"
    cat "$tmp" >>"$summary_log"
    printf -v "$__var_name" '%s' "$(cat "$tmp")"
    rm -f "$tmp"
    return "$rc"
  fi
}

easy_node_script="${WG_ONLY_STACK_SELFTEST_RECORD_EASY_NODE_SCRIPT:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$easy_node_script" ]]; then
  echo "missing easy_node helper script: $easy_node_script"
  exit 2
fi

original_args=("$@")
record_result="1"
manual_validation_report_enabled="1"
manual_validation_report_summary_json=""
manual_validation_report_md=""
summary_json=""
print_summary_json="0"

base_port="${EASY_NODE_DOCTOR_WG_ONLY_BASE_PORT:-19280}"
client_iface="${EASY_NODE_DOCTOR_CLIENT_IFACE:-wgcstack0}"
exit_iface="${EASY_NODE_DOCTOR_EXIT_IFACE:-wgestack0}"
strict_beta="1"
declare -a selftest_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict-beta)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        strict_beta="${2:-}"
        selftest_args+=("$1" "$strict_beta")
        shift 2
      else
        strict_beta="1"
        selftest_args+=("$1" "$strict_beta")
        shift
      fi
      ;;
    --base-port)
      base_port="${2:-}"
      selftest_args+=("$1" "$base_port")
      shift 2
      ;;
    --timeout-sec|--min-selection-lines|--client-iface|--exit-iface)
      if [[ "$1" == "--client-iface" ]]; then
        client_iface="${2:-}"
      elif [[ "$1" == "--exit-iface" ]]; then
        exit_iface="${2:-}"
      fi
      selftest_args+=("$1" "${2:-}")
      shift 2
      ;;
    --force-iface-reset|--cleanup-ifaces|--keep-stack)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        selftest_args+=("$1" "${2:-}")
        shift 2
      else
        selftest_args+=("$1" "1")
        shift
      fi
      ;;
    --record-result)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        record_result="${2:-}"
        shift 2
      else
        record_result="1"
        shift
      fi
      ;;
    --manual-validation-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        manual_validation_report_enabled="${2:-}"
        shift 2
      else
        manual_validation_report_enabled="1"
        shift
      fi
      ;;
    --manual-validation-report-summary-json)
      manual_validation_report_summary_json="${2:-}"
      shift 2
      ;;
    --manual-validation-report-md)
      manual_validation_report_md="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
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

bool_arg_or_die "--record-result" "$record_result"
bool_arg_or_die "--manual-validation-report" "$manual_validation_report_enabled"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
if [[ "$strict_beta" != "0" && "$strict_beta" != "1" ]]; then
  echo "--strict-beta must be 0 or 1"
  exit 2
fi
if ! [[ "$base_port" =~ ^[0-9]+$ ]]; then
  echo "--base-port must be an integer"
  exit 2
fi
if [[ -z "$client_iface" || -z "$exit_iface" ]]; then
  echo "--client-iface and --exit-iface must be non-empty"
  exit 2
fi

log_dir="$(prepare_log_dir)"
timestamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/wg_only_stack_selftest_record_${timestamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$manual_validation_report_summary_json" ]]; then
  manual_validation_report_summary_json="$log_dir/manual_validation_readiness_summary.json"
else
  manual_validation_report_summary_json="$(abs_path "$manual_validation_report_summary_json")"
fi
if [[ -z "$manual_validation_report_md" ]]; then
  manual_validation_report_md="$log_dir/manual_validation_readiness_report.md"
else
  manual_validation_report_md="$(abs_path "$manual_validation_report_md")"
fi

mkdir -p "$(dirname "$summary_json")" "$(dirname "$manual_validation_report_summary_json")" "$(dirname "$manual_validation_report_md")"
summary_log="$log_dir/wg_only_stack_selftest_record_${timestamp}.log"
manual_validation_report_log="$log_dir/wg_only_stack_selftest_record_${timestamp}_manual_validation_report.log"
: >"$summary_log"

stage="selftest"
selftest_status="fail"
selftest_rc=1
notes=""
manual_validation_report_status="skipped"
manual_validation_report_readiness_status=""
manual_validation_report_next_action_check_id=""

declare -a selftest_cmd
selftest_cmd=("$easy_node_script" "wg-only-stack-selftest" "${selftest_args[@]}")

write_summary_json() {
  local summary_tmp=""
  summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
  jq -n \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg status "$selftest_status" \
    --arg notes "$notes" \
    --arg command "$(print_cmd "$0" "${original_args[@]}")" \
    --arg summary_log "$summary_log" \
    --arg summary_json "$summary_json" \
    --arg base_port "$base_port" \
    --arg client_iface "$client_iface" \
    --arg exit_iface "$exit_iface" \
    --arg strict_beta "$strict_beta" \
    --argjson selftest_rc "$selftest_rc" \
    --arg manual_validation_report_summary_json "$manual_validation_report_summary_json" \
    --arg manual_validation_report_md "$manual_validation_report_md" \
    --arg manual_validation_report_status "$manual_validation_report_status" \
    --arg manual_validation_report_readiness_status "$manual_validation_report_readiness_status" \
    --arg manual_validation_report_next_action_check_id "$manual_validation_report_next_action_check_id" \
    --arg manual_validation_report_log "$manual_validation_report_log" \
    --argjson manual_validation_report_enabled "$manual_validation_report_enabled" \
    '{
      version: 1,
      schema: {
        id: "wg_only_stack_selftest_record_summary",
        major: 1,
        minor: 0
      },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $selftest_rc,
      notes: $notes,
      command: $command,
      selftest: {
        strict_beta: ($strict_beta == "1"),
        base_port: ($base_port | tonumber),
        client_iface: $client_iface,
        exit_iface: $exit_iface
      },
      manual_validation_report: {
        enabled: ($manual_validation_report_enabled == 1),
        status: $manual_validation_report_status,
        summary_json: $manual_validation_report_summary_json,
        report_md: $manual_validation_report_md,
        readiness_status: $manual_validation_report_readiness_status,
        next_action_check_id: $manual_validation_report_next_action_check_id,
        log: $manual_validation_report_log
      },
      artifacts: {
        summary_log: $summary_log,
        summary_json: $summary_json
      }
    }' >"$summary_tmp"
  mv -f "$summary_tmp" "$summary_json"
}

refresh_manual_validation_report() {
  local report_output=""
  local report_json=""
  local -a report_cmd=()

  if [[ "$manual_validation_report_enabled" != "1" ]]; then
    return 0
  fi

  report_cmd=(
    "$easy_node_script" manual-validation-report
    --base-port "$base_port"
    --client-iface "$client_iface"
    --exit-iface "$exit_iface"
    --overlay-check-id "wg_only_stack_selftest"
    --overlay-status "$selftest_status"
    --overlay-notes "$notes"
    --overlay-command "$(print_cmd "$0" "${original_args[@]}")"
    --overlay-artifact "$summary_log"
    --overlay-artifact "$summary_json"
    --summary-json "$manual_validation_report_summary_json"
    --report-md "$manual_validation_report_md"
    --print-report 0
    --print-summary-json 0
  )

  stage="manual-validation-report"
  if run_and_capture report_output "${report_cmd[@]}"; then
    manual_validation_report_status="ok"
  else
    manual_validation_report_status="fail"
  fi
  persist_artifact_text "$manual_validation_report_log" "$report_output"

  report_json="$(extract_json_payload "manual-validation-report" "$report_output")"
  if [[ -z "$report_json" && -f "$manual_validation_report_summary_json" ]] && jq -e . "$manual_validation_report_summary_json" >/dev/null 2>&1; then
    report_json="$(cat "$manual_validation_report_summary_json")"
  fi
  if validate_manual_validation_summary_payload "$report_json"; then
    manual_validation_report_readiness_status="$(jq -r '.report.readiness_status // ""' <<<"$report_json")"
    manual_validation_report_next_action_check_id="$(jq -r '.summary.next_action_check_id // ""' <<<"$report_json")"
  else
    manual_validation_report_status="fail"
    manual_validation_report_readiness_status=""
    manual_validation_report_next_action_check_id=""
    printf '%s\n' "[$stage] summary_payload_invalid_or_incompatible schema check failed" >>"$summary_log"
  fi
}

record_receipt() {
  local -a record_cmd=()
  local receipt_artifact=""
  local status="$1"
  shift

  record_cmd=(
    "$easy_node_script" manual-validation-record
    --check-id "wg_only_stack_selftest"
    --status "$status"
    --notes "$notes"
    --command "$(print_cmd "$0" "${original_args[@]}")"
    --show-json 0
  )
  for receipt_artifact in "$@"; do
    record_cmd+=(--artifact "$receipt_artifact")
  done
  "${record_cmd[@]}" >>"$summary_log" 2>&1 || true
}

selftest_output=""
if run_and_capture selftest_output "${selftest_cmd[@]}"; then
  selftest_rc=0
  selftest_status="pass"
  notes="WG-only stack selftest passed"
else
  selftest_rc=$?
  selftest_status="fail"
  notes="WG-only stack selftest failed"
fi

write_summary_json
refresh_manual_validation_report
write_summary_json

declare -a receipt_artifacts=()
append_existing_artifact receipt_artifacts "$summary_log"
append_existing_artifact receipt_artifacts "$summary_json"
append_existing_artifact receipt_artifacts "$manual_validation_report_log"
append_existing_artifact receipt_artifacts "$manual_validation_report_summary_json"
append_existing_artifact receipt_artifacts "$manual_validation_report_md"

if [[ "$record_result" == "1" ]]; then
  record_receipt "$selftest_status" "${receipt_artifacts[@]}"
fi

echo "wg-only-stack-selftest-record: status=$selftest_status"
echo "summary_log: $summary_log"
echo "summary_json: $summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$selftest_rc"
