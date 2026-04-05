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
  ./scripts/three_machine_prod_signoff.sh \
    [three-machine-prod-bundle args...] \
    [--bundle-dir PATH] \
    [--run-report-json PATH] \
    [--record-result [0|1]] \
    [--pre-real-host-readiness [0|1]] \
    [--pre-real-host-readiness-summary-json PATH] \
    [--runtime-doctor [0|1]] \
    [--runtime-fix [0|1]] \
    [--runtime-fix-prune-wg-only-dir [0|1]] \
    [--runtime-base-port N] \
    [--runtime-client-iface IFACE] \
    [--runtime-exit-iface IFACE] \
    [--runtime-vpn-iface IFACE] \
    [--manual-validation-report [0|1]] \
    [--manual-validation-report-summary-json PATH] \
    [--manual-validation-report-md PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run the strict true 3-machine production bundle/signoff flow as one command
  and record the result into manual-validation status automatically.
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

easy_node_script="${THREE_MACHINE_PROD_SIGNOFF_EASY_NODE_SCRIPT:-$ROOT_DIR/scripts/easy_node.sh}"
incident_snapshot_attach_script="${THREE_MACHINE_PROD_SIGNOFF_INCIDENT_ATTACH_SCRIPT:-$ROOT_DIR/scripts/incident_snapshot_attach_artifacts.sh}"
if [[ ! -x "$easy_node_script" ]]; then
  echo "missing easy_node helper script: $easy_node_script"
  exit 2
fi
if [[ ! -x "$incident_snapshot_attach_script" ]]; then
  echo "missing incident snapshot attach helper script: $incident_snapshot_attach_script"
  exit 2
fi

original_args=("$@")
bundle_dir=""
run_report_json=""
summary_json=""
print_summary_json="0"
record_result="1"
pre_real_host_readiness_enabled="0"
pre_real_host_readiness_summary_json=""
runtime_doctor_enabled="1"
runtime_fix_on_non_ok="0"
runtime_fix_prune_wg_only_dir="1"
runtime_base_port="${EASY_NODE_DOCTOR_WG_ONLY_BASE_PORT:-19280}"
runtime_client_iface="${EASY_NODE_DOCTOR_CLIENT_IFACE:-wgcstack0}"
runtime_exit_iface="${EASY_NODE_DOCTOR_EXIT_IFACE:-wgestack0}"
runtime_vpn_iface="${EASY_NODE_DOCTOR_VPN_IFACE:-wgvpn0}"
manual_validation_report_enabled="1"
manual_validation_report_summary_json=""
manual_validation_report_md=""
signoff_check_explicit="0"
signoff_check_value="1"
declare -a bundle_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      bundle_dir="${2:-}"
      shift 2
      ;;
    --run-report-json)
      run_report_json="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
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
    --pre-real-host-readiness)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        pre_real_host_readiness_enabled="${2:-}"
        shift 2
      else
        pre_real_host_readiness_enabled="1"
        shift
      fi
      ;;
    --pre-real-host-readiness-summary-json)
      pre_real_host_readiness_summary_json="${2:-}"
      shift 2
      ;;
    --runtime-doctor)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        runtime_doctor_enabled="${2:-}"
        shift 2
      else
        runtime_doctor_enabled="1"
        shift
      fi
      ;;
    --runtime-fix)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        runtime_fix_on_non_ok="${2:-}"
        shift 2
      else
        runtime_fix_on_non_ok="1"
        shift
      fi
      ;;
    --runtime-fix-prune-wg-only-dir)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        runtime_fix_prune_wg_only_dir="${2:-}"
        shift 2
      else
        runtime_fix_prune_wg_only_dir="1"
        shift
      fi
      ;;
    --runtime-base-port)
      runtime_base_port="${2:-}"
      shift 2
      ;;
    --runtime-client-iface)
      runtime_client_iface="${2:-}"
      shift 2
      ;;
    --runtime-exit-iface)
      runtime_exit_iface="${2:-}"
      shift 2
      ;;
    --runtime-vpn-iface)
      runtime_vpn_iface="${2:-}"
      shift 2
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
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    --signoff-check)
      signoff_check_explicit="1"
      bundle_args+=("$1")
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_check_value="${2:-}"
        bundle_args+=("${2:-}")
        shift 2
      else
        signoff_check_value="1"
        shift
      fi
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      bundle_args+=("$1")
      shift
      ;;
  esac
done

bool_arg_or_die "--record-result" "$record_result"
bool_arg_or_die "--pre-real-host-readiness" "$pre_real_host_readiness_enabled"
bool_arg_or_die "--runtime-doctor" "$runtime_doctor_enabled"
bool_arg_or_die "--runtime-fix" "$runtime_fix_on_non_ok"
bool_arg_or_die "--runtime-fix-prune-wg-only-dir" "$runtime_fix_prune_wg_only_dir"
bool_arg_or_die "--manual-validation-report" "$manual_validation_report_enabled"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
if [[ "$signoff_check_value" != "1" ]]; then
  echo "three-machine-prod-signoff requires --signoff-check 1"
  exit 2
fi
if ! [[ "$runtime_base_port" =~ ^[0-9]+$ ]]; then
  echo "--runtime-base-port must be an integer"
  exit 2
fi
if [[ -z "$runtime_client_iface" || -z "$runtime_exit_iface" || -z "$runtime_vpn_iface" ]]; then
  echo "--runtime-client-iface, --runtime-exit-iface, and --runtime-vpn-iface must be non-empty"
  exit 2
fi

log_dir="$(prepare_log_dir)"
timestamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$bundle_dir" ]]; then
  bundle_dir="$log_dir/prod_gate_bundle_${timestamp}"
else
  bundle_dir="$(abs_path "$bundle_dir")"
fi
if [[ -z "$run_report_json" ]]; then
  run_report_json="$bundle_dir/prod_bundle_run_report.json"
else
  run_report_json="$(abs_path "$run_report_json")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/three_machine_prod_signoff_${timestamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$pre_real_host_readiness_summary_json" ]]; then
  pre_real_host_readiness_summary_json="$log_dir/three_machine_prod_signoff_${timestamp}_pre_real_host_readiness.json"
else
  pre_real_host_readiness_summary_json="$(abs_path "$pre_real_host_readiness_summary_json")"
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

mkdir -p "$(dirname "$summary_json")" "$(dirname "$pre_real_host_readiness_summary_json")" "$(dirname "$run_report_json")" "$(dirname "$manual_validation_report_summary_json")" "$(dirname "$manual_validation_report_md")" "$bundle_dir"
summary_log="$log_dir/three_machine_prod_signoff_${timestamp}.log"
: >"$summary_log"
pre_real_host_readiness_log="$log_dir/three_machine_prod_signoff_${timestamp}_pre_real_host_readiness.log"
runtime_doctor_before_log="$log_dir/three_machine_prod_signoff_${timestamp}_runtime_doctor_before.log"
runtime_doctor_before_json="$log_dir/three_machine_prod_signoff_${timestamp}_runtime_doctor_before.json"
runtime_fix_log="$log_dir/three_machine_prod_signoff_${timestamp}_runtime_fix.log"
runtime_fix_json="$log_dir/three_machine_prod_signoff_${timestamp}_runtime_fix.json"
runtime_doctor_after_log="$log_dir/three_machine_prod_signoff_${timestamp}_runtime_doctor_after.log"
runtime_doctor_after_json="$log_dir/three_machine_prod_signoff_${timestamp}_runtime_doctor_after.json"
manual_validation_report_log="$log_dir/three_machine_prod_signoff_${timestamp}_manual_validation_report.log"
incident_snapshot_refresh_log="$log_dir/three_machine_prod_signoff_${timestamp}_incident_snapshot_refresh.log"

declare -a bundle_cmd pre_real_host_readiness_cmd runtime_doctor_cmd runtime_fix_cmd
bundle_cmd=(
  "$easy_node_script" "three-machine-prod-bundle"
  "--bundle-dir" "$bundle_dir"
  "--run-report-json" "$run_report_json"
)
pre_real_host_readiness_cmd=(
  "$easy_node_script" "pre-real-host-readiness"
  "--base-port" "$runtime_base_port"
  "--client-iface" "$runtime_client_iface"
  "--exit-iface" "$runtime_exit_iface"
  "--vpn-iface" "$runtime_vpn_iface"
  "--runtime-fix-prune-wg-only-dir" "$runtime_fix_prune_wg_only_dir"
  "--summary-json" "$pre_real_host_readiness_summary_json"
  "--manual-validation-report-summary-json" "$manual_validation_report_summary_json"
  "--manual-validation-report-md" "$manual_validation_report_md"
  "--print-summary-json" "1"
)
runtime_doctor_cmd=(
  "$easy_node_script" "runtime-doctor"
  "--base-port" "$runtime_base_port"
  "--client-iface" "$runtime_client_iface"
  "--exit-iface" "$runtime_exit_iface"
  "--vpn-iface" "$runtime_vpn_iface"
  "--show-json" "1"
)
runtime_fix_cmd=(
  "$easy_node_script" "runtime-fix"
  "--base-port" "$runtime_base_port"
  "--client-iface" "$runtime_client_iface"
  "--exit-iface" "$runtime_exit_iface"
  "--vpn-iface" "$runtime_vpn_iface"
  "--prune-wg-only-dir" "$runtime_fix_prune_wg_only_dir"
  "--show-json" "1"
)
if [[ "$signoff_check_explicit" != "1" ]]; then
  bundle_cmd+=("--signoff-check" "1")
fi
bundle_cmd+=("${bundle_args[@]}")

stage="bundle"
result_stage="bundle"
signoff_status="fail"
notes=""
bundle_output=""
run_report_status=""
run_report_final_rc=""
bundle_tar=""
gate_summary_json=""
wg_validate_summary_json=""
wg_soak_summary_json=""
incident_snapshot_status=""
incident_snapshot_summary_json=""
incident_snapshot_report_md=""
incident_snapshot_bundle_dir=""
incident_snapshot_bundle_tar=""
incident_snapshot_attachment_manifest=""
incident_snapshot_attachment_skipped=""
incident_snapshot_attachment_count="0"
incident_snapshot_refresh_status="skipped"
runtime_doctor_status_before=""
runtime_doctor_status_after=""
runtime_doctor_findings_before="0"
runtime_doctor_findings_after="0"
pre_real_host_readiness_status="skipped"
pre_real_host_readiness_machine_c_ready=""
pre_real_host_readiness_next_command=""
pre_real_host_readiness_readiness_status=""
pre_real_host_readiness_report_summary_json=""
pre_real_host_readiness_report_md=""
pre_real_host_readiness_blockers_json="[]"
runtime_fix_attempted="0"
runtime_fix_after_status=""
runtime_fix_actions_taken="0"
runtime_fix_actions_failed="0"
runtime_gate_failure_note=""
manual_validation_report_status="skipped"
manual_validation_report_readiness_status=""
manual_validation_report_next_action_check_id=""

extract_json_payload() {
  local prefix="$1"
  local text="$2"
  printf '%s\n' "$text" | awk -v p="$prefix" '$0 == "[" p "] summary_json_payload:" {flag=1; next} flag {print}'
}

persist_artifact_text() {
  local path="$1"
  local content="$2"
  [[ -z "$path" ]] && return 0
  if [[ -z "$content" ]]; then
    rm -f "$path" 2>/dev/null || true
  else
    printf '%s\n' "$content" >"$path"
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

run_runtime_gate() {
  local doctor_output=""
  local doctor_json=""
  local doctor_status=""
  local doctor_findings="0"
  local fix_output=""
  local fix_json=""

  if [[ "$runtime_doctor_enabled" != "1" ]]; then
    return 0
  fi

  stage="runtime-doctor"
  if ! run_and_capture doctor_output "${runtime_doctor_cmd[@]}"; then
    :
  fi
  doctor_json="$(extract_json_payload "runtime-doctor" "$doctor_output")"
  persist_artifact_text "$runtime_doctor_before_log" "$doctor_output"
  persist_artifact_text "$runtime_doctor_before_json" "$doctor_json"
  if [[ -z "$doctor_json" ]]; then
    runtime_gate_failure_note="runtime-doctor did not emit JSON summary"
    return 1
  fi
  doctor_status="$(printf '%s\n' "$doctor_json" | jq -r '.status // ""')"
  doctor_findings="$(printf '%s\n' "$doctor_json" | jq -r '.summary.findings_total // 0')"
  runtime_doctor_status_before="$doctor_status"
  runtime_doctor_findings_before="$doctor_findings"
  runtime_doctor_status_after="$doctor_status"
  runtime_doctor_findings_after="$doctor_findings"

  if [[ "$doctor_status" == "OK" ]]; then
    return 0
  fi

  if [[ "$runtime_fix_on_non_ok" != "1" ]]; then
    runtime_gate_failure_note="runtime hygiene not ready (${doctor_status}); review runtime-doctor or rerun with --runtime-fix 1"
    return 1
  fi

  stage="runtime-fix"
  runtime_fix_attempted="1"
  if ! run_and_capture fix_output "${runtime_fix_cmd[@]}"; then
    :
  fi
  fix_json="$(extract_json_payload "runtime-fix" "$fix_output")"
  persist_artifact_text "$runtime_fix_log" "$fix_output"
  persist_artifact_text "$runtime_fix_json" "$fix_json"
  if [[ -n "$fix_json" ]]; then
    runtime_fix_after_status="$(printf '%s\n' "$fix_json" | jq -r '.doctor.after.status // ""')"
    runtime_fix_actions_taken="$(printf '%s\n' "$fix_json" | jq -r '(.actions.taken // []) | length')"
    runtime_fix_actions_failed="$(printf '%s\n' "$fix_json" | jq -r '(.actions.failed // []) | length')"
  fi

  stage="runtime-doctor"
  if ! run_and_capture doctor_output "${runtime_doctor_cmd[@]}"; then
    :
  fi
  doctor_json="$(extract_json_payload "runtime-doctor" "$doctor_output")"
  persist_artifact_text "$runtime_doctor_after_log" "$doctor_output"
  persist_artifact_text "$runtime_doctor_after_json" "$doctor_json"
  if [[ -z "$doctor_json" ]]; then
    runtime_gate_failure_note="runtime-doctor did not emit JSON summary after runtime-fix"
    return 1
  fi
  runtime_doctor_status_after="$(printf '%s\n' "$doctor_json" | jq -r '.status // ""')"
  runtime_doctor_findings_after="$(printf '%s\n' "$doctor_json" | jq -r '.summary.findings_total // 0')"
  if [[ "$runtime_doctor_status_after" != "OK" ]]; then
    runtime_gate_failure_note="runtime hygiene not ready after runtime-fix (${runtime_doctor_status_after})"
    return 1
  fi
  return 0
}

run_pre_real_host_readiness_gate() {
  local readiness_output=""
  local readiness_json=""
  local readiness_rc=0

  pre_real_host_readiness_status="skipped"
  pre_real_host_readiness_machine_c_ready=""
  pre_real_host_readiness_next_command=""
  pre_real_host_readiness_readiness_status=""
  pre_real_host_readiness_report_summary_json=""
  pre_real_host_readiness_report_md=""
  pre_real_host_readiness_blockers_json="[]"
  rm -f "$pre_real_host_readiness_log" 2>/dev/null || true

  if [[ "$pre_real_host_readiness_enabled" != "1" ]]; then
    return 0
  fi

  stage="pre-real-host-readiness"
  if run_and_capture readiness_output "${pre_real_host_readiness_cmd[@]}"; then
    readiness_rc=0
  else
    readiness_rc=$?
  fi
  persist_artifact_text "$pre_real_host_readiness_log" "$readiness_output"

  readiness_json="$(extract_json_payload "pre-real-host-readiness" "$readiness_output")"
  if [[ -z "$readiness_json" && -f "$pre_real_host_readiness_summary_json" ]] && jq -e . "$pre_real_host_readiness_summary_json" >/dev/null 2>&1; then
    readiness_json="$(cat "$pre_real_host_readiness_summary_json")"
  fi
  if [[ -z "$readiness_json" ]]; then
    pre_real_host_readiness_status="fail"
    runtime_gate_failure_note="pre-real-host readiness did not emit JSON summary"
    return 1
  fi

  pre_real_host_readiness_status="$(printf '%s\n' "$readiness_json" | jq -r '.status // "fail"' 2>/dev/null || printf 'fail')"
  pre_real_host_readiness_machine_c_ready="$(printf '%s\n' "$readiness_json" | jq -r '.machine_c_smoke_gate.ready // false' 2>/dev/null || printf 'false')"
  pre_real_host_readiness_next_command="$(printf '%s\n' "$readiness_json" | jq -r '.machine_c_smoke_gate.next_command // ""' 2>/dev/null || true)"
  pre_real_host_readiness_readiness_status="$(printf '%s\n' "$readiness_json" | jq -r '.manual_validation_report.readiness_status // ""' 2>/dev/null || true)"
  pre_real_host_readiness_report_summary_json="$(printf '%s\n' "$readiness_json" | jq -r '.manual_validation_report.summary_json // ""' 2>/dev/null || true)"
  pre_real_host_readiness_report_md="$(printf '%s\n' "$readiness_json" | jq -r '.manual_validation_report.report_md // ""' 2>/dev/null || true)"
  pre_real_host_readiness_blockers_json="$(printf '%s\n' "$readiness_json" | jq -c '.machine_c_smoke_gate.blockers // []' 2>/dev/null || printf '[]')"

  if [[ "$readiness_rc" -ne 0 || "$pre_real_host_readiness_machine_c_ready" != "true" ]]; then
    runtime_gate_failure_note="pre-real-host readiness gate blocked three-machine signoff"
    return 1
  fi

  return 0
}

refresh_manual_validation_report() {
  local report_output=""
  local report_json=""
  local previous_stage="$stage"
  local -a overlay_artifacts=()
  local overlay_artifact=""
  local overlay_command=""

  manual_validation_report_status="skipped"
  manual_validation_report_readiness_status=""
  manual_validation_report_next_action_check_id=""
  rm -f "$manual_validation_report_log" 2>/dev/null || true

  if [[ "$record_result" != "1" || "$manual_validation_report_enabled" != "1" ]]; then
    return 0
  fi

  overlay_command="$(print_cmd "$0" "${original_args[@]}")"
  for overlay_artifact in \
    "$summary_log" \
    "$summary_json" \
    "$pre_real_host_readiness_log" \
    "$pre_real_host_readiness_summary_json" \
    "$pre_real_host_readiness_report_summary_json" \
    "$pre_real_host_readiness_report_md" \
    "$run_report_json" \
    "$bundle_dir" \
    "$bundle_tar" \
    "$gate_summary_json" \
    "$wg_validate_summary_json" \
    "$wg_soak_summary_json" \
    "$incident_snapshot_bundle_dir" \
    "$incident_snapshot_bundle_tar" \
    "$incident_snapshot_summary_json" \
    "$incident_snapshot_report_md" \
    "$incident_snapshot_attachment_manifest" \
    "$incident_snapshot_attachment_skipped" \
    "$runtime_doctor_before_log" \
    "$runtime_doctor_before_json" \
    "$runtime_fix_log" \
    "$runtime_fix_json" \
    "$runtime_doctor_after_log" \
    "$runtime_doctor_after_json"; do
    append_existing_artifact overlay_artifacts "$overlay_artifact"
  done

  stage="manual-validation-report"
  declare -a report_cmd=(
    "$easy_node_script" manual-validation-report
    --base-port "$runtime_base_port"
    --client-iface "$runtime_client_iface"
    --exit-iface "$runtime_exit_iface"
    --vpn-iface "$runtime_vpn_iface"
    --overlay-check-id three_machine_prod_signoff
    --overlay-status "$signoff_status"
    --overlay-notes "$notes"
    --overlay-command "$overlay_command"
    --summary-json "$manual_validation_report_summary_json"
    --report-md "$manual_validation_report_md"
    --print-report 0
    --print-summary-json 1
  )
  for overlay_artifact in "${overlay_artifacts[@]}"; do
    report_cmd+=(--overlay-artifact "$overlay_artifact")
  done
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
    manual_validation_report_readiness_status="$(printf '%s\n' "$report_json" | jq -r '.report.readiness_status // ""' 2>/dev/null || true)"
    manual_validation_report_next_action_check_id="$(printf '%s\n' "$report_json" | jq -r '.summary.next_action_check_id // ""' 2>/dev/null || true)"
  else
    manual_validation_report_status="fail"
    manual_validation_report_readiness_status=""
    manual_validation_report_next_action_check_id=""
    printf '%s\n' "[$stage] summary_payload_invalid_or_incompatible schema check failed" >>"$summary_log"
  fi
  stage="$previous_stage"
}

refresh_failed_incident_snapshot_attachments() {
  local previous_stage="$stage"
  local attach_output=""
  local -a attach_candidates=()
  local -a attach_artifacts=()
  local artifact=""

  incident_snapshot_refresh_status="skipped"
  rm -f "$incident_snapshot_refresh_log" 2>/dev/null || true

  if [[ "$signoff_status" != "fail" || "$incident_snapshot_status" != "ok" ]]; then
    return 0
  fi
  if [[ -z "$incident_snapshot_bundle_dir" || ! -d "$incident_snapshot_bundle_dir" ]]; then
    return 0
  fi

  attach_candidates=(
    "$manual_validation_report_log"
    "$manual_validation_report_summary_json"
    "$manual_validation_report_md"
    "$pre_real_host_readiness_log"
    "$pre_real_host_readiness_summary_json"
    "$pre_real_host_readiness_report_summary_json"
    "$pre_real_host_readiness_report_md"
  )
  for artifact in "${attach_candidates[@]}"; do
    append_existing_artifact attach_artifacts "$artifact"
  done
  if [[ "${#attach_artifacts[@]}" -eq 0 ]]; then
    return 0
  fi

  stage="incident-snapshot-attach"
  declare -a attach_cmd=(
    "$incident_snapshot_attach_script"
    --bundle-dir "$incident_snapshot_bundle_dir"
    --print-summary-json 0
  )
  if [[ -n "$incident_snapshot_bundle_tar" ]]; then
    attach_cmd+=(--bundle-tar "$incident_snapshot_bundle_tar")
  fi
  if [[ -n "$incident_snapshot_summary_json" ]]; then
    attach_cmd+=(--summary-json "$incident_snapshot_summary_json")
  fi
  if [[ -n "$incident_snapshot_report_md" ]]; then
    attach_cmd+=(--report-md "$incident_snapshot_report_md")
  fi
  for artifact in "${attach_artifacts[@]}"; do
    attach_cmd+=(--attach-artifact "$artifact")
  done

  if run_and_capture attach_output "${attach_cmd[@]}"; then
    incident_snapshot_refresh_status="ok"
  else
    incident_snapshot_refresh_status="fail"
  fi
  persist_artifact_text "$incident_snapshot_refresh_log" "$attach_output"

  if [[ "$incident_snapshot_refresh_status" == "ok" ]]; then
    incident_snapshot_bundle_dir="$(sed -n 's/^bundle_dir: //p' <<<"$attach_output" | tail -n 1)"
    incident_snapshot_bundle_tar="$(sed -n 's/^bundle_tar: //p' <<<"$attach_output" | tail -n 1)"
    incident_snapshot_summary_json="$(sed -n 's/^summary_json: //p' <<<"$attach_output" | tail -n 1)"
    incident_snapshot_report_md="$(sed -n 's/^report_md: //p' <<<"$attach_output" | tail -n 1)"
    incident_snapshot_attachment_manifest="$(sed -n 's/^attachment_manifest: //p' <<<"$attach_output" | tail -n 1)"
    incident_snapshot_attachment_skipped="$(sed -n 's/^attachment_skipped: //p' <<<"$attach_output" | tail -n 1)"
    incident_snapshot_attachment_count="$(sed -n 's/^attachment_count: //p' <<<"$attach_output" | tail -n 1)"
  fi

  stage="$previous_stage"
}

record_receipt() {
  local status_value="$1"
  local notes_value="$2"
  shift 2
  local -a artifacts=("$@")
  local -a record_cmd
  record_cmd=(
    "$easy_node_script" manual-validation-record
    --check-id three_machine_prod_signoff
    --status "$status_value"
    --notes "$notes_value"
    --command "$(print_cmd "$0" "${original_args[@]}")"
    --show-json 0
  )
  local artifact
  for artifact in "${artifacts[@]}"; do
    record_cmd+=(--artifact "$artifact")
  done
  for artifact in \
    "$runtime_doctor_before_log" \
    "$runtime_doctor_before_json" \
    "$runtime_fix_log" \
    "$runtime_fix_json" \
    "$runtime_doctor_after_log" \
    "$runtime_doctor_after_json"; do
    if [[ -f "$artifact" ]]; then
      record_cmd+=(--artifact "$artifact")
    fi
  done
  "${record_cmd[@]}" >>"$summary_log" 2>&1 || true
}

write_summary_json() {
  jq -n \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg status "$signoff_status" \
    --arg stage "$result_stage" \
    --arg notes "$notes" \
    --arg bundle_dir "$bundle_dir" \
    --arg run_report_json "$run_report_json" \
    --arg run_report_status "$run_report_status" \
    --arg run_report_final_rc "$run_report_final_rc" \
    --arg bundle_tar "$bundle_tar" \
    --arg gate_summary_json "$gate_summary_json" \
    --arg wg_validate_summary_json "$wg_validate_summary_json" \
    --arg wg_soak_summary_json "$wg_soak_summary_json" \
    --arg pre_real_host_readiness_status "$pre_real_host_readiness_status" \
    --arg pre_real_host_readiness_summary_json "$pre_real_host_readiness_summary_json" \
    --arg pre_real_host_readiness_log "$pre_real_host_readiness_log" \
    --arg pre_real_host_readiness_machine_c_ready "$pre_real_host_readiness_machine_c_ready" \
    --argjson pre_real_host_readiness_blockers "$pre_real_host_readiness_blockers_json" \
    --arg pre_real_host_readiness_next_command "$pre_real_host_readiness_next_command" \
    --arg pre_real_host_readiness_readiness_status "$pre_real_host_readiness_readiness_status" \
    --arg pre_real_host_readiness_report_summary_json "$pre_real_host_readiness_report_summary_json" \
    --arg pre_real_host_readiness_report_md "$pre_real_host_readiness_report_md" \
    --arg incident_snapshot_status "$incident_snapshot_status" \
    --arg incident_snapshot_bundle_dir "$incident_snapshot_bundle_dir" \
    --arg incident_snapshot_bundle_tar "$incident_snapshot_bundle_tar" \
    --arg incident_snapshot_summary_json "$incident_snapshot_summary_json" \
    --arg incident_snapshot_report_md "$incident_snapshot_report_md" \
    --arg incident_snapshot_attachment_manifest "$incident_snapshot_attachment_manifest" \
    --arg incident_snapshot_attachment_skipped "$incident_snapshot_attachment_skipped" \
    --arg incident_snapshot_attachment_count "$incident_snapshot_attachment_count" \
    --arg incident_snapshot_refresh_status "$incident_snapshot_refresh_status" \
    --arg incident_snapshot_refresh_log "$incident_snapshot_refresh_log" \
    --arg runtime_doctor_status_before "$runtime_doctor_status_before" \
    --arg runtime_doctor_status_after "$runtime_doctor_status_after" \
    --arg runtime_doctor_findings_before "$runtime_doctor_findings_before" \
    --arg runtime_doctor_findings_after "$runtime_doctor_findings_after" \
    --arg runtime_fix_after_status "$runtime_fix_after_status" \
    --arg runtime_fix_actions_taken "$runtime_fix_actions_taken" \
    --arg runtime_fix_actions_failed "$runtime_fix_actions_failed" \
    --arg runtime_doctor_before_log "$runtime_doctor_before_log" \
    --arg runtime_doctor_before_json "$runtime_doctor_before_json" \
    --arg runtime_fix_log "$runtime_fix_log" \
    --arg runtime_fix_json "$runtime_fix_json" \
    --arg runtime_doctor_after_log "$runtime_doctor_after_log" \
    --arg runtime_doctor_after_json "$runtime_doctor_after_json" \
    --arg manual_validation_report_status "$manual_validation_report_status" \
    --arg manual_validation_report_summary_json "$manual_validation_report_summary_json" \
    --arg manual_validation_report_md "$manual_validation_report_md" \
    --arg manual_validation_report_readiness_status "$manual_validation_report_readiness_status" \
    --arg manual_validation_report_next_action_check_id "$manual_validation_report_next_action_check_id" \
    --arg manual_validation_report_log "$manual_validation_report_log" \
    --arg summary_log "$summary_log" \
    --arg summary_json "$summary_json" \
    --argjson pre_real_host_readiness_enabled "$pre_real_host_readiness_enabled" \
    --argjson runtime_doctor_enabled "$runtime_doctor_enabled" \
    --argjson runtime_fix_on_non_ok "$runtime_fix_on_non_ok" \
    --argjson runtime_fix_attempted "$runtime_fix_attempted" \
    --argjson runtime_fix_prune_wg_only_dir "$runtime_fix_prune_wg_only_dir" \
    --argjson manual_validation_report_enabled "$manual_validation_report_enabled" \
    '{
      version: 1,
      generated_at_utc: $generated_at_utc,
      status: $status,
      stage: $stage,
      notes: $notes,
      pre_real_host_readiness: {
        enabled: ($pre_real_host_readiness_enabled == 1),
        status: $pre_real_host_readiness_status,
        summary_json: (if ($pre_real_host_readiness_summary_json | length) > 0 then $pre_real_host_readiness_summary_json else "" end),
        log: (if ($pre_real_host_readiness_log | length) > 0 then $pre_real_host_readiness_log else "" end),
        machine_c_smoke_ready: (if $pre_real_host_readiness_machine_c_ready == "true" then true else false end),
        blockers: $pre_real_host_readiness_blockers,
        next_command: $pre_real_host_readiness_next_command,
        readiness_status: $pre_real_host_readiness_readiness_status,
        readiness_report_summary_json: (if ($pre_real_host_readiness_report_summary_json | length) > 0 then $pre_real_host_readiness_report_summary_json else "" end),
        readiness_report_md: (if ($pre_real_host_readiness_report_md | length) > 0 then $pre_real_host_readiness_report_md else "" end)
      },
      runtime_gate: {
        enabled: ($runtime_doctor_enabled == 1),
        auto_fix: ($runtime_fix_on_non_ok == 1),
        fix_attempted: ($runtime_fix_attempted == 1),
        fix_prune_wg_only_dir: ($runtime_fix_prune_wg_only_dir == 1),
        doctor_status_before: $runtime_doctor_status_before,
        doctor_findings_before: ($runtime_doctor_findings_before | tonumber),
        doctor_status_after: $runtime_doctor_status_after,
        doctor_findings_after: ($runtime_doctor_findings_after | tonumber),
        fix_after_status: $runtime_fix_after_status,
        fix_actions_taken: ($runtime_fix_actions_taken | tonumber),
        fix_actions_failed: ($runtime_fix_actions_failed | tonumber),
        artifacts: {
          doctor_before_log: (if ($runtime_doctor_before_log | length) > 0 then $runtime_doctor_before_log else "" end),
          doctor_before_json: (if ($runtime_doctor_before_json | length) > 0 then $runtime_doctor_before_json else "" end),
          fix_log: (if ($runtime_fix_log | length) > 0 then $runtime_fix_log else "" end),
          fix_json: (if ($runtime_fix_json | length) > 0 then $runtime_fix_json else "" end),
          doctor_after_log: (if ($runtime_doctor_after_log | length) > 0 then $runtime_doctor_after_log else "" end),
          doctor_after_json: (if ($runtime_doctor_after_json | length) > 0 then $runtime_doctor_after_json else "" end)
        }
      },
      outputs: {
        bundle_dir: $bundle_dir,
        run_report_json: $run_report_json,
        run_report_status: $run_report_status,
        run_report_final_rc: $run_report_final_rc,
        bundle_tar: $bundle_tar,
        gate_summary_json: $gate_summary_json,
        wg_validate_summary_json: $wg_validate_summary_json,
        wg_soak_summary_json: $wg_soak_summary_json
      },
      incident_snapshot: {
        status: $incident_snapshot_status,
        bundle_dir: $incident_snapshot_bundle_dir,
        bundle_tar: $incident_snapshot_bundle_tar,
        summary_json: $incident_snapshot_summary_json,
        report_md: $incident_snapshot_report_md,
        attachment_manifest: $incident_snapshot_attachment_manifest,
        attachment_skipped: $incident_snapshot_attachment_skipped,
        attachment_count: ($incident_snapshot_attachment_count | tonumber),
        refresh_status: $incident_snapshot_refresh_status,
        refresh_log: (if ($incident_snapshot_refresh_log | length) > 0 then $incident_snapshot_refresh_log else "" end)
      },
      manual_validation_report: {
        enabled: ($manual_validation_report_enabled == 1),
        status: $manual_validation_report_status,
        summary_json: (if ($manual_validation_report_summary_json | length) > 0 then $manual_validation_report_summary_json else "" end),
        report_md: (if ($manual_validation_report_md | length) > 0 then $manual_validation_report_md else "" end),
        readiness_status: $manual_validation_report_readiness_status,
        next_action_check_id: $manual_validation_report_next_action_check_id,
        log: (if ($manual_validation_report_log | length) > 0 then $manual_validation_report_log else "" end)
      },
      artifacts: {
        summary_log: $summary_log,
        summary_json: $summary_json
      }
    }' >"$summary_json"
}

if ! run_pre_real_host_readiness_gate; then
  result_stage="$stage"
  signoff_status="fail"
  notes="$runtime_gate_failure_note"
  write_summary_json
  refresh_manual_validation_report
  write_summary_json
  declare -a readiness_gate_receipt_artifacts=()
  append_existing_artifact readiness_gate_receipt_artifacts "$summary_log"
  append_existing_artifact readiness_gate_receipt_artifacts "$summary_json"
  append_existing_artifact readiness_gate_receipt_artifacts "$pre_real_host_readiness_log"
  append_existing_artifact readiness_gate_receipt_artifacts "$pre_real_host_readiness_summary_json"
  append_existing_artifact readiness_gate_receipt_artifacts "$pre_real_host_readiness_report_summary_json"
  append_existing_artifact readiness_gate_receipt_artifacts "$pre_real_host_readiness_report_md"
  append_existing_artifact readiness_gate_receipt_artifacts "$manual_validation_report_log"
  append_existing_artifact readiness_gate_receipt_artifacts "$manual_validation_report_summary_json"
  append_existing_artifact readiness_gate_receipt_artifacts "$manual_validation_report_md"
  if [[ "$record_result" == "1" ]]; then
    record_receipt "$signoff_status" "$notes" "${readiness_gate_receipt_artifacts[@]}"
  fi
  echo "three-machine-prod-signoff: status=$signoff_status stage=$result_stage"
  echo "summary_log: $summary_log"
  echo "summary_json: $summary_json"
  if [[ "$print_summary_json" == "1" ]]; then
    cat "$summary_json"
  fi
  exit 1
fi

if ! run_runtime_gate; then
  result_stage="$stage"
  signoff_status="fail"
  notes="$runtime_gate_failure_note"
  write_summary_json
  refresh_manual_validation_report
  write_summary_json
  declare -a preflight_receipt_artifacts=()
  append_existing_artifact preflight_receipt_artifacts "$summary_log"
  append_existing_artifact preflight_receipt_artifacts "$summary_json"
  append_existing_artifact preflight_receipt_artifacts "$pre_real_host_readiness_log"
  append_existing_artifact preflight_receipt_artifacts "$pre_real_host_readiness_summary_json"
  append_existing_artifact preflight_receipt_artifacts "$pre_real_host_readiness_report_summary_json"
  append_existing_artifact preflight_receipt_artifacts "$pre_real_host_readiness_report_md"
  append_existing_artifact preflight_receipt_artifacts "$run_report_json"
  append_existing_artifact preflight_receipt_artifacts "$bundle_dir"
  append_existing_artifact preflight_receipt_artifacts "$manual_validation_report_log"
  append_existing_artifact preflight_receipt_artifacts "$manual_validation_report_summary_json"
  append_existing_artifact preflight_receipt_artifacts "$manual_validation_report_md"
  if [[ "$record_result" == "1" ]]; then
    record_receipt "$signoff_status" "$notes" "${preflight_receipt_artifacts[@]}"
  fi
  echo "three-machine-prod-signoff: status=$signoff_status stage=$result_stage"
  echo "summary_log: $summary_log"
  echo "summary_json: $summary_json"
  if [[ "$print_summary_json" == "1" ]]; then
    cat "$summary_json"
  fi
  exit 1
fi

declare -a incident_snapshot_attach_candidates=(
  "$pre_real_host_readiness_log"
  "$pre_real_host_readiness_summary_json"
  "$pre_real_host_readiness_report_summary_json"
  "$pre_real_host_readiness_report_md"
  "$runtime_doctor_before_log"
  "$runtime_doctor_before_json"
  "$runtime_fix_log"
  "$runtime_fix_json"
  "$runtime_doctor_after_log"
  "$runtime_doctor_after_json"
)
for artifact in "${incident_snapshot_attach_candidates[@]}"; do
  [[ -f "$artifact" ]] || continue
  bundle_cmd+=("--incident-snapshot-attach-artifact" "$artifact")
done

stage="bundle"
if run_and_capture bundle_output "${bundle_cmd[@]}"; then
  bundle_rc=0
else
  bundle_rc=$?
fi

if [[ -f "$run_report_json" ]] && jq -e . "$run_report_json" >/dev/null 2>&1; then
  run_report_status="$(jq -r '.status // ""' "$run_report_json")"
  run_report_final_rc="$(jq -r '.final_rc // ""' "$run_report_json")"
  bundle_tar="$(jq -r '.bundle_tar // ""' "$run_report_json")"
  gate_summary_json="$(jq -r '.gate_summary_json // ""' "$run_report_json")"
  wg_validate_summary_json="$(jq -r '.wg_validate_summary_json // ""' "$run_report_json")"
  wg_soak_summary_json="$(jq -r '.wg_soak_summary_json // ""' "$run_report_json")"
  incident_snapshot_status="$(jq -r '.incident_snapshot.status // ""' "$run_report_json")"
  incident_snapshot_summary_json="$(jq -r '.incident_snapshot.summary_json // ""' "$run_report_json")"
  incident_snapshot_report_md="$(jq -r '.incident_snapshot.report_md // ""' "$run_report_json")"
  incident_snapshot_bundle_dir="$(jq -r '.incident_snapshot.bundle_dir // ""' "$run_report_json")"
  incident_snapshot_bundle_tar="$(jq -r '.incident_snapshot.bundle_tar // ""' "$run_report_json")"
  incident_snapshot_attachment_manifest="$(jq -r '.incident_snapshot.attachment_manifest // ""' "$run_report_json")"
  incident_snapshot_attachment_skipped="$(jq -r '.incident_snapshot.attachment_skipped // ""' "$run_report_json")"
  incident_snapshot_attachment_count="$(jq -r '.incident_snapshot.attachment_count // 0' "$run_report_json")"
fi

if [[ "${bundle_rc:-1}" == "0" ]]; then
  signoff_status="pass"
  notes="three-machine production signoff completed successfully"
else
  signoff_status="fail"
  notes="three-machine production signoff failed"
fi

write_summary_json
refresh_manual_validation_report
write_summary_json
refresh_failed_incident_snapshot_attachments
write_summary_json
declare -a receipt_artifacts
append_existing_artifact receipt_artifacts "$summary_log"
append_existing_artifact receipt_artifacts "$summary_json"
append_existing_artifact receipt_artifacts "$pre_real_host_readiness_log"
append_existing_artifact receipt_artifacts "$pre_real_host_readiness_summary_json"
append_existing_artifact receipt_artifacts "$pre_real_host_readiness_report_summary_json"
append_existing_artifact receipt_artifacts "$pre_real_host_readiness_report_md"
append_existing_artifact receipt_artifacts "$run_report_json"
append_existing_artifact receipt_artifacts "$bundle_dir"
append_existing_artifact receipt_artifacts "$bundle_tar"
append_existing_artifact receipt_artifacts "$gate_summary_json"
append_existing_artifact receipt_artifacts "$wg_validate_summary_json"
append_existing_artifact receipt_artifacts "$wg_soak_summary_json"
append_existing_artifact receipt_artifacts "$incident_snapshot_bundle_dir"
append_existing_artifact receipt_artifacts "$incident_snapshot_bundle_tar"
append_existing_artifact receipt_artifacts "$incident_snapshot_summary_json"
append_existing_artifact receipt_artifacts "$incident_snapshot_report_md"
append_existing_artifact receipt_artifacts "$incident_snapshot_attachment_manifest"
append_existing_artifact receipt_artifacts "$incident_snapshot_attachment_skipped"
append_existing_artifact receipt_artifacts "$incident_snapshot_refresh_log"
append_existing_artifact receipt_artifacts "$manual_validation_report_log"
append_existing_artifact receipt_artifacts "$manual_validation_report_summary_json"
append_existing_artifact receipt_artifacts "$manual_validation_report_md"

if [[ "$record_result" == "1" ]]; then
  record_receipt "$signoff_status" "$notes" "${receipt_artifacts[@]}"
fi

echo "three-machine-prod-signoff: status=$signoff_status stage=$result_stage"
echo "summary_log: $summary_log"
echo "summary_json: $summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "${bundle_rc:-1}" == "0" ]]; then
  exit 0
fi
exit "${bundle_rc:-1}"
