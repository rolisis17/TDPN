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
  ./scripts/runtime_fix_record.sh \
    [runtime-fix args...] \
    [--record-result [0|1]] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run runtime-fix, keep a durable summary/log artifact, and record the runtime
  hygiene result into manual-validation status automatically.
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

extract_json_payload() {
  local prefix="$1"
  local text="$2"
  printf '%s\n' "$text" | awk -v p="$prefix" '$0 == "[" p "] summary_json_payload:" {flag=1; next} flag {print}'
}

append_existing_artifact() {
  local array_name="$1"
  local path="$2"
  [[ -z "$path" ]] && return 0
  if [[ -e "$path" ]]; then
    eval "$array_name+=(\"\$path\")"
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

easy_node_script="${RUNTIME_FIX_RECORD_EASY_NODE_SCRIPT:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$easy_node_script" ]]; then
  echo "missing easy_node helper script: $easy_node_script"
  exit 2
fi

original_args=("$@")
record_result="1"
summary_json=""
print_summary_json="0"
base_port="${EASY_NODE_DOCTOR_WG_ONLY_BASE_PORT:-19280}"
client_iface="${EASY_NODE_DOCTOR_CLIENT_IFACE:-wgcstack0}"
exit_iface="${EASY_NODE_DOCTOR_EXIT_IFACE:-wgestack0}"
vpn_iface="${EASY_NODE_DOCTOR_VPN_IFACE:-wgvpn0}"
prune_wg_only_dir="0"
manual_validation_report_enabled="1"
manual_validation_report_summary_json=""
manual_validation_report_md=""
declare -a fix_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-port)
      base_port="${2:-}"
      fix_args+=("$1" "$base_port")
      shift 2
      ;;
    --client-iface)
      client_iface="${2:-}"
      fix_args+=("$1" "$client_iface")
      shift 2
      ;;
    --exit-iface)
      exit_iface="${2:-}"
      fix_args+=("$1" "$exit_iface")
      shift 2
      ;;
    --vpn-iface)
      vpn_iface="${2:-}"
      fix_args+=("$1" "$vpn_iface")
      shift 2
      ;;
    --prune-wg-only-dir)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        prune_wg_only_dir="${2:-}"
        fix_args+=("$1" "$prune_wg_only_dir")
        shift 2
      else
        prune_wg_only_dir="1"
        fix_args+=("$1" "$prune_wg_only_dir")
        shift
      fi
      ;;
    --manual-validation-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        manual_validation_report_enabled="${2:-}"
        fix_args+=("$1" "$manual_validation_report_enabled")
        shift 2
      else
        manual_validation_report_enabled="1"
        fix_args+=("$1" "$manual_validation_report_enabled")
        shift
      fi
      ;;
    --manual-validation-report-summary-json)
      manual_validation_report_summary_json="${2:-}"
      fix_args+=("$1" "$manual_validation_report_summary_json")
      shift 2
      ;;
    --manual-validation-report-md)
      manual_validation_report_md="${2:-}"
      fix_args+=("$1" "$manual_validation_report_md")
      shift 2
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
bool_arg_or_die "--print-summary-json" "$print_summary_json"
if [[ "$manual_validation_report_enabled" != "0" && "$manual_validation_report_enabled" != "1" ]]; then
  echo "--manual-validation-report must be 0 or 1"
  exit 2
fi
if ! [[ "$base_port" =~ ^[0-9]+$ ]]; then
  echo "--base-port must be an integer"
  exit 2
fi
if [[ -z "$client_iface" || -z "$exit_iface" || -z "$vpn_iface" ]]; then
  echo "--client-iface, --exit-iface, and --vpn-iface must be non-empty"
  exit 2
fi

log_dir="$(prepare_log_dir)"
timestamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/runtime_fix_record_${timestamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -n "$manual_validation_report_summary_json" ]]; then
  manual_validation_report_summary_json="$(abs_path "$manual_validation_report_summary_json")"
fi
if [[ -n "$manual_validation_report_md" ]]; then
  manual_validation_report_md="$(abs_path "$manual_validation_report_md")"
fi
mkdir -p "$(dirname "$summary_json")"
summary_log="$log_dir/runtime_fix_record_${timestamp}.log"
: >"$summary_log"

runtime_fix_status="fail"
runtime_fix_rc=1
notes=""
runtime_fix_json='{}'
runtime_fix_output=""
runtime_fix_after_status="UNKNOWN"
runtime_fix_after_findings="0"
runtime_fix_before_status="UNKNOWN"
runtime_fix_before_findings="0"
actions_taken_count="0"
actions_skipped_count="0"
actions_failed_count="0"
manual_validation_report_status="skipped"
manual_validation_report_summary_path=""
manual_validation_report_md_path=""
manual_validation_report_log_path=""
manual_validation_report_readiness_status=""
manual_validation_report_next_action_check_id=""

write_summary_json() {
  local summary_tmp=""
  summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
  jq -n \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg status "$runtime_fix_status" \
    --arg notes "$notes" \
    --arg command "$(print_cmd "$0" "${original_args[@]}")" \
    --arg summary_log "$summary_log" \
    --arg summary_json "$summary_json" \
    --arg base_port "$base_port" \
    --arg client_iface "$client_iface" \
    --arg exit_iface "$exit_iface" \
    --arg vpn_iface "$vpn_iface" \
    --arg prune_wg_only_dir "$prune_wg_only_dir" \
    --argjson runtime_fix_rc "$runtime_fix_rc" \
    --arg runtime_fix_after_status "$runtime_fix_after_status" \
    --argjson runtime_fix_after_findings "$runtime_fix_after_findings" \
    --arg runtime_fix_before_status "$runtime_fix_before_status" \
    --argjson runtime_fix_before_findings "$runtime_fix_before_findings" \
    --argjson actions_taken_count "$actions_taken_count" \
    --argjson actions_skipped_count "$actions_skipped_count" \
    --argjson actions_failed_count "$actions_failed_count" \
    --argjson runtime_fix "$runtime_fix_json" \
    --arg manual_validation_report_status "$manual_validation_report_status" \
    --arg manual_validation_report_summary_json "$manual_validation_report_summary_path" \
    --arg manual_validation_report_md "$manual_validation_report_md_path" \
    --arg manual_validation_report_log "$manual_validation_report_log_path" \
    --arg manual_validation_report_readiness_status "$manual_validation_report_readiness_status" \
    --arg manual_validation_report_next_action_check_id "$manual_validation_report_next_action_check_id" \
    --argjson manual_validation_report_enabled "$manual_validation_report_enabled" \
    '{
      version: 1,
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $runtime_fix_rc,
      notes: $notes,
      command: $command,
      runtime_fix: {
        base_port: ($base_port | tonumber),
        client_iface: $client_iface,
        exit_iface: $exit_iface,
        vpn_iface: $vpn_iface,
        prune_wg_only_dir: ($prune_wg_only_dir == "1"),
        before_status: $runtime_fix_before_status,
        before_findings: $runtime_fix_before_findings,
        after_status: $runtime_fix_after_status,
        after_findings: $runtime_fix_after_findings,
        actions_taken_count: $actions_taken_count,
        actions_skipped_count: $actions_skipped_count,
        actions_failed_count: $actions_failed_count,
        summary: $runtime_fix
      },
      manual_validation_report: {
        enabled: ($manual_validation_report_enabled == 1),
        status: $manual_validation_report_status,
        summary_json: $manual_validation_report_summary_json,
        report_md: $manual_validation_report_md,
        log: $manual_validation_report_log,
        readiness_status: $manual_validation_report_readiness_status,
        next_action_check_id: $manual_validation_report_next_action_check_id
      },
      artifacts: {
        summary_log: $summary_log,
        summary_json: $summary_json
      }
    }' >"$summary_tmp"
  mv -f "$summary_tmp" "$summary_json"
}

record_receipt() {
  local -a record_cmd=()
  local receipt_artifact=""

  record_cmd=(
    "$easy_node_script" manual-validation-record
    --check-id "runtime_hygiene"
    --status "$runtime_fix_status"
    --notes "$notes"
    --command "$(print_cmd "$0" "${original_args[@]}")"
    --show-json 0
  )
  for receipt_artifact in "$@"; do
    record_cmd+=(--artifact "$receipt_artifact")
  done
  "${record_cmd[@]}" >>"$summary_log" 2>&1 || true
}

stage="runtime-fix"
declare -a fix_cmd
fix_cmd=(
  "$easy_node_script" runtime-fix
  --base-port "$base_port"
  --client-iface "$client_iface"
  --exit-iface "$exit_iface"
  --vpn-iface "$vpn_iface"
  --prune-wg-only-dir "$prune_wg_only_dir"
  --manual-validation-report "$manual_validation_report_enabled"
)
if [[ -n "$manual_validation_report_summary_json" ]]; then
  fix_cmd+=(--manual-validation-report-summary-json "$manual_validation_report_summary_json")
fi
if [[ -n "$manual_validation_report_md" ]]; then
  fix_cmd+=(--manual-validation-report-md "$manual_validation_report_md")
fi
fix_cmd+=(--show-json 1)
if ((${#fix_args[@]} > 0)); then
  :
fi

if run_and_capture runtime_fix_output "${fix_cmd[@]}"; then
  runtime_fix_rc=0
else
  runtime_fix_rc=$?
fi

runtime_fix_json="$(extract_json_payload "runtime-fix" "$runtime_fix_output")"
if [[ -z "$runtime_fix_json" ]] || ! jq -e . >/dev/null 2>&1 <<<"$runtime_fix_json"; then
  notes="runtime-fix did not emit a usable JSON summary"
  runtime_fix_status="fail"
  write_summary_json
  echo "runtime-fix-record: status=fail"
  echo "summary_log: $summary_log"
  echo "summary_json: $summary_json"
  if [[ "$print_summary_json" == "1" ]]; then
    cat "$summary_json"
  fi
  exit 1
fi

runtime_fix_before_status="$(jq -r '.doctor.before.status // "UNKNOWN"' <<<"$runtime_fix_json")"
runtime_fix_before_findings="$(jq -r '.doctor.before.summary.findings_total // 0' <<<"$runtime_fix_json")"
runtime_fix_after_status="$(jq -r '.doctor.after.status // "UNKNOWN"' <<<"$runtime_fix_json")"
runtime_fix_after_findings="$(jq -r '.doctor.after.summary.findings_total // 0' <<<"$runtime_fix_json")"
actions_taken_count="$(jq -r '(.actions.taken // []) | length' <<<"$runtime_fix_json")"
actions_skipped_count="$(jq -r '(.actions.skipped // []) | length' <<<"$runtime_fix_json")"
actions_failed_count="$(jq -r '(.actions.failed // []) | length' <<<"$runtime_fix_json")"
manual_validation_report_status="$(jq -r '.manual_validation_report.status // "skipped"' <<<"$runtime_fix_json")"
manual_validation_report_summary_path="$(jq -r '.manual_validation_report.summary_json // ""' <<<"$runtime_fix_json")"
manual_validation_report_md_path="$(jq -r '.manual_validation_report.report_md // ""' <<<"$runtime_fix_json")"
manual_validation_report_log_path="$(jq -r '.manual_validation_report.log // ""' <<<"$runtime_fix_json")"
manual_validation_report_readiness_status="$(jq -r '.manual_validation_report.summary.report.readiness_status // ""' <<<"$runtime_fix_json")"
manual_validation_report_next_action_check_id="$(jq -r '.manual_validation_report.summary.summary.next_action_check_id // ""' <<<"$runtime_fix_json")"

case "$runtime_fix_after_status" in
  OK)
    runtime_fix_status="pass"
    notes="Runtime hygiene clean after runtime-fix (findings=${runtime_fix_after_findings}, actions_taken=${actions_taken_count})"
    ;;
  WARN)
    runtime_fix_status="warn"
    notes="Runtime hygiene still has warnings after runtime-fix (findings=${runtime_fix_after_findings}, actions_taken=${actions_taken_count}, actions_skipped=${actions_skipped_count})"
    ;;
  FAIL)
    runtime_fix_status="fail"
    notes="Runtime hygiene still failing after runtime-fix (findings=${runtime_fix_after_findings}, actions_failed=${actions_failed_count})"
    ;;
  *)
    runtime_fix_status="fail"
    notes="Runtime hygiene status unknown after runtime-fix (after_status=${runtime_fix_after_status})"
    ;;
esac
if [[ "$runtime_fix_rc" -ne 0 && "$runtime_fix_status" == "pass" ]]; then
  runtime_fix_status="fail"
  notes="runtime-fix exited non-zero unexpectedly (rc=${runtime_fix_rc})"
fi

write_summary_json

declare -a receipt_artifacts=()
append_existing_artifact receipt_artifacts "$summary_log"
append_existing_artifact receipt_artifacts "$summary_json"
append_existing_artifact receipt_artifacts "$manual_validation_report_log_path"
append_existing_artifact receipt_artifacts "$manual_validation_report_summary_path"
append_existing_artifact receipt_artifacts "$manual_validation_report_md_path"

if [[ "$record_result" == "1" ]]; then
  record_receipt "${receipt_artifacts[@]}"
fi

echo "runtime-fix-record: status=$runtime_fix_status"
echo "summary_log: $summary_log"
echo "summary_json: $summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$runtime_fix_status" == "fail" ]]; then
  exit 1
fi
exit 0
