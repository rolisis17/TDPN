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
  ./scripts/pre_real_host_readiness.sh \
    [--base-port N] \
    [--client-iface IFACE] \
    [--exit-iface IFACE] \
    [--vpn-iface IFACE] \
    [--runtime-fix-prune-wg-only-dir [0|1]] \
    [--strict-beta [0|1]] \
    [--timeout-sec N] \
    [--min-selection-lines N] \
    [--force-iface-reset [0|1]] \
    [--cleanup-ifaces [0|1]] \
    [--keep-stack [0|1]] \
    [--manual-validation-report-summary-json PATH] \
    [--manual-validation-report-md PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run the pre-machine-C readiness sweep in one command:
    1) runtime-fix-record
    2) wg-only-stack-selftest-record
    3) manual-validation-report refresh

Notes:
  - This wrapper focuses on whether machine-C VPN smoke is the next safe step.
  - Overall readiness can still be NOT_READY afterward because the real machine-C
    smoke and final 3-machine signoff are still pending.
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
  elif [[ "$path" == /* ]]; then
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

json_array_from_values() {
  local value
  if [[ "$#" -eq 0 ]]; then
    printf '[]\n'
    return 0
  fi
  for value in "$@"; do
    printf '%s\n' "$value"
  done | jq -Rsc 'split("\n") | map(select(length > 0))'
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

append_existing_artifact() {
  local array_name="$1"
  local path="$2"
  [[ -z "$path" ]] && return 0
  if [[ -e "$path" ]]; then
    eval "$array_name+=(\"\$path\")"
  fi
}

default_machine_c_command() {
  local vpn_iface="$1"
  printf 'sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface %s --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country' "$vpn_iface"
}

easy_node_script="${PRE_REAL_HOST_READINESS_EASY_NODE_SCRIPT:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$easy_node_script" ]]; then
  echo "missing easy_node helper script: $easy_node_script"
  exit 2
fi

original_args=("$@")
base_port="${EASY_NODE_DOCTOR_WG_ONLY_BASE_PORT:-19280}"
client_iface="${EASY_NODE_DOCTOR_CLIENT_IFACE:-wgcstack0}"
exit_iface="${EASY_NODE_DOCTOR_EXIT_IFACE:-wgestack0}"
vpn_iface="${EASY_NODE_DOCTOR_VPN_IFACE:-wgvpn0}"
runtime_fix_prune_wg_only_dir="1"
strict_beta="1"
timeout_sec=""
min_selection_lines=""
force_iface_reset=""
cleanup_ifaces=""
keep_stack=""
manual_validation_report_summary_json=""
manual_validation_report_md=""
summary_json=""
print_summary_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-port)
      base_port="${2:-}"
      shift 2
      ;;
    --client-iface)
      client_iface="${2:-}"
      shift 2
      ;;
    --exit-iface)
      exit_iface="${2:-}"
      shift 2
      ;;
    --vpn-iface)
      vpn_iface="${2:-}"
      shift 2
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
    --strict-beta)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        strict_beta="${2:-}"
        shift 2
      else
        strict_beta="1"
        shift
      fi
      ;;
    --timeout-sec)
      timeout_sec="${2:-}"
      shift 2
      ;;
    --min-selection-lines)
      min_selection_lines="${2:-}"
      shift 2
      ;;
    --force-iface-reset)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        force_iface_reset="${2:-}"
        shift 2
      else
        force_iface_reset="1"
        shift
      fi
      ;;
    --cleanup-ifaces)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        cleanup_ifaces="${2:-}"
        shift 2
      else
        cleanup_ifaces="1"
        shift
      fi
      ;;
    --keep-stack)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        keep_stack="${2:-}"
        shift 2
      else
        keep_stack="1"
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

bool_arg_or_die "--runtime-fix-prune-wg-only-dir" "$runtime_fix_prune_wg_only_dir"
bool_arg_or_die "--strict-beta" "$strict_beta"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
if ! [[ "$base_port" =~ ^[0-9]+$ ]]; then
  echo "--base-port must be an integer"
  exit 2
fi
if [[ -n "$timeout_sec" ]] && ! [[ "$timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "--timeout-sec must be an integer"
  exit 2
fi
if [[ -n "$min_selection_lines" ]] && ! [[ "$min_selection_lines" =~ ^[0-9]+$ ]]; then
  echo "--min-selection-lines must be an integer"
  exit 2
fi
if [[ -z "$client_iface" || -z "$exit_iface" || -z "$vpn_iface" ]]; then
  echo "--client-iface, --exit-iface, and --vpn-iface must be non-empty"
  exit 2
fi

log_dir="$(prepare_log_dir)"
timestamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/pre_real_host_readiness_${timestamp}.json"
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
summary_log="$log_dir/pre_real_host_readiness_${timestamp}.log"
: >"$summary_log"
runtime_fix_log="$log_dir/pre_real_host_readiness_${timestamp}_runtime_fix.log"
runtime_fix_json="$log_dir/pre_real_host_readiness_${timestamp}_runtime_fix.json"
wg_only_log="$log_dir/pre_real_host_readiness_${timestamp}_wg_only_stack_selftest_record.log"
wg_only_summary_json="$log_dir/pre_real_host_readiness_${timestamp}_wg_only_stack_selftest_record.json"
manual_validation_report_log="$log_dir/pre_real_host_readiness_${timestamp}_manual_validation_report.log"

stage="runtime-fix-record"
status="fail"
result_stage="runtime_fix"
notes=""
manual_validation_report_status="skipped"
manual_validation_report_readiness_status=""
manual_validation_report_next_action_check_id=""
manual_validation_report_next_action_command=""
runtime_fix_rc=1
runtime_fix_after_status=""
runtime_fix_actions_taken="0"
runtime_fix_actions_failed="0"
wg_only_rc=""
wg_only_status="skipped"
wg_only_recorded_at=""
wg_only_notes=""

runtime_fix_output=""
runtime_fix_cmd=(
  "$easy_node_script" runtime-fix-record
  --base-port "$base_port"
  --client-iface "$client_iface"
  --exit-iface "$exit_iface"
  --vpn-iface "$vpn_iface"
  --prune-wg-only-dir "$runtime_fix_prune_wg_only_dir"
  --record-result 1
  --manual-validation-report-summary-json "$manual_validation_report_summary_json"
  --manual-validation-report-md "$manual_validation_report_md"
  --summary-json "$runtime_fix_json"
  --print-summary-json 1
)

wg_only_cmd=(
  "$easy_node_script" wg-only-stack-selftest-record
  --base-port "$base_port"
  --client-iface "$client_iface"
  --exit-iface "$exit_iface"
  --strict-beta "$strict_beta"
  --record-result 1
  --manual-validation-report 0
  --summary-json "$wg_only_summary_json"
  --print-summary-json 1
)
if [[ -n "$timeout_sec" ]]; then
  wg_only_cmd+=(--timeout-sec "$timeout_sec")
fi
if [[ -n "$min_selection_lines" ]]; then
  wg_only_cmd+=(--min-selection-lines "$min_selection_lines")
fi
if [[ -n "$force_iface_reset" ]]; then
  wg_only_cmd+=(--force-iface-reset "$force_iface_reset")
fi
if [[ -n "$cleanup_ifaces" ]]; then
  wg_only_cmd+=(--cleanup-ifaces "$cleanup_ifaces")
fi
if [[ -n "$keep_stack" ]]; then
  wg_only_cmd+=(--keep-stack "$keep_stack")
fi

manual_validation_report_cmd=(
  "$easy_node_script" manual-validation-report
  --base-port "$base_port"
  --client-iface "$client_iface"
  --exit-iface "$exit_iface"
  --vpn-iface "$vpn_iface"
  --summary-json "$manual_validation_report_summary_json"
  --report-md "$manual_validation_report_md"
  --print-report 0
  --print-summary-json 1
)

if run_and_capture runtime_fix_output "${runtime_fix_cmd[@]}"; then
  runtime_fix_rc=0
else
  runtime_fix_rc=$?
fi
persist_artifact_text "$runtime_fix_log" "$runtime_fix_output"
runtime_fix_json_payload=""
if [[ -f "$runtime_fix_json" ]] && jq -e . "$runtime_fix_json" >/dev/null 2>&1; then
  runtime_fix_json_payload="$(cat "$runtime_fix_json")"
fi
if [[ -n "$runtime_fix_json_payload" ]]; then
  runtime_fix_after_status="$(printf '%s\n' "$runtime_fix_json_payload" | jq -r '.runtime_fix.after_status // ""' 2>/dev/null || true)"
  runtime_fix_actions_taken="$(printf '%s\n' "$runtime_fix_json_payload" | jq -r '.runtime_fix.actions_taken_count // 0' 2>/dev/null || printf '0')"
  runtime_fix_actions_failed="$(printf '%s\n' "$runtime_fix_json_payload" | jq -r '.runtime_fix.actions_failed_count // 0' 2>/dev/null || printf '0')"
fi

wg_only_output=""
wg_only_json_payload=""
if [[ -n "$runtime_fix_json_payload" && "$runtime_fix_rc" -eq 0 && "$runtime_fix_after_status" == "OK" ]]; then
  stage="wg-only-stack-selftest-record"
  if run_and_capture wg_only_output "${wg_only_cmd[@]}"; then
    wg_only_rc=0
  else
    wg_only_rc=$?
  fi
  wg_only_json_payload="$(extract_json_payload "wg-only-stack-selftest-record" "$wg_only_output")"
  if [[ -z "$wg_only_json_payload" && -f "$wg_only_summary_json" ]] && jq -e . "$wg_only_summary_json" >/dev/null 2>&1; then
    wg_only_json_payload="$(cat "$wg_only_summary_json")"
  fi
  persist_artifact_text "$wg_only_log" "$wg_only_output"
  if [[ -n "$wg_only_json_payload" ]]; then
    wg_only_status="$(printf '%s\n' "$wg_only_json_payload" | jq -r '.status // ""' 2>/dev/null || true)"
    wg_only_recorded_at="$(printf '%s\n' "$wg_only_json_payload" | jq -r '.recorded_at_utc // ""' 2>/dev/null || true)"
    wg_only_notes="$(printf '%s\n' "$wg_only_json_payload" | jq -r '.notes // ""' 2>/dev/null || true)"
  fi
else
  wg_only_status="skipped"
fi

report_output=""
report_json_payload=""
stage="manual-validation-report"
if run_and_capture report_output "${manual_validation_report_cmd[@]}"; then
  manual_validation_report_status="ok"
else
  manual_validation_report_status="fail"
fi
persist_artifact_text "$manual_validation_report_log" "$report_output"
report_json_payload="$(extract_json_payload "manual-validation-report" "$report_output")"
if [[ -z "$report_json_payload" && -f "$manual_validation_report_summary_json" ]] && jq -e . "$manual_validation_report_summary_json" >/dev/null 2>&1; then
  report_json_payload="$(cat "$manual_validation_report_summary_json")"
fi
if [[ -n "$report_json_payload" ]]; then
  manual_validation_report_readiness_status="$(printf '%s\n' "$report_json_payload" | jq -r '.report.readiness_status // ""' 2>/dev/null || true)"
  manual_validation_report_next_action_check_id="$(printf '%s\n' "$report_json_payload" | jq -r '.summary.next_action_check_id // ""' 2>/dev/null || true)"
  manual_validation_report_next_action_command="$(printf '%s\n' "$report_json_payload" | jq -r '.summary.pre_machine_c_gate.next_command // .summary.next_action_command // ""' 2>/dev/null || true)"
fi

blockers=()
if [[ "$runtime_fix_rc" -ne 0 || "$runtime_fix_after_status" != "OK" ]]; then
  blockers+=("runtime_hygiene")
fi
if [[ "$wg_only_status" != "pass" ]]; then
  blockers+=("wg_only_stack_selftest")
fi

machine_c_smoke_ready="0"
machine_c_smoke_command="$(default_machine_c_command "$vpn_iface")"
if [[ ${#blockers[@]} -eq 0 ]]; then
  machine_c_smoke_ready="1"
  if [[ "$manual_validation_report_next_action_check_id" == "machine_c_vpn_smoke" && -n "$manual_validation_report_next_action_command" ]]; then
    machine_c_smoke_command="$manual_validation_report_next_action_command"
  fi
fi

if [[ "$manual_validation_report_status" != "ok" ]]; then
  status="fail"
  result_stage="manual_validation_report"
  notes="manual-validation-report did not produce a usable readiness artifact"
elif [[ "$machine_c_smoke_ready" == "1" ]]; then
  status="pass"
  result_stage="complete"
  notes="runtime hygiene is OK and WG-only host validation passed; machine-C VPN smoke is the next safe step"
elif [[ "$runtime_fix_rc" -ne 0 || "$runtime_fix_after_status" != "OK" ]]; then
  status="fail"
  result_stage="runtime_fix"
  notes="runtime-fix-record did not clear runtime hygiene; machine-C smoke should stay blocked"
else
  status="fail"
  result_stage="wg_only_stack_selftest"
  notes="WG-only host validation did not pass; machine-C smoke should stay blocked"
fi

blockers_json="$(json_array_from_values "${blockers[@]:-}")"
summary_payload="$(
  jq -n \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg status "$status" \
    --arg stage "$result_stage" \
    --arg notes "$notes" \
    --arg summary_log "$summary_log" \
    --arg summary_json "$summary_json" \
    --arg manual_validation_report_summary_json "$manual_validation_report_summary_json" \
    --arg manual_validation_report_md "$manual_validation_report_md" \
    --arg machine_c_smoke_command "$machine_c_smoke_command" \
    --arg runtime_fix_log "$runtime_fix_log" \
    --arg runtime_fix_json "$runtime_fix_json" \
    --arg wg_only_log "$wg_only_log" \
    --arg wg_only_summary_json "$wg_only_summary_json" \
    --arg manual_validation_report_log "$manual_validation_report_log" \
    --arg runtime_fix_after_status "$runtime_fix_after_status" \
    --arg runtime_fix_rc "$runtime_fix_rc" \
    --arg runtime_fix_actions_taken "$runtime_fix_actions_taken" \
    --arg runtime_fix_actions_failed "$runtime_fix_actions_failed" \
    --arg wg_only_rc "${wg_only_rc:-}" \
    --arg wg_only_status "$wg_only_status" \
    --arg wg_only_recorded_at "$wg_only_recorded_at" \
    --arg wg_only_notes "$wg_only_notes" \
    --arg manual_validation_report_status "$manual_validation_report_status" \
    --arg manual_validation_report_readiness_status "$manual_validation_report_readiness_status" \
    --arg manual_validation_report_next_action_check_id "$manual_validation_report_next_action_check_id" \
    --arg manual_validation_report_next_action_command "$manual_validation_report_next_action_command" \
    --argjson machine_c_smoke_ready "$machine_c_smoke_ready" \
    --argjson blockers "$blockers_json" \
    --argjson print_summary_json "$print_summary_json" \
    --argjson base_port "$base_port" \
    --arg client_iface "$client_iface" \
    --arg exit_iface "$exit_iface" \
    --arg vpn_iface "$vpn_iface" \
    --argjson runtime_fix_prune_wg_only_dir "$runtime_fix_prune_wg_only_dir" \
    --argjson strict_beta "$strict_beta" \
    --arg timeout_sec "$timeout_sec" \
    --arg min_selection_lines "$min_selection_lines" \
    --arg force_iface_reset "$force_iface_reset" \
    --arg cleanup_ifaces "$cleanup_ifaces" \
    --arg keep_stack "$keep_stack" \
    'def boolstr($v): ($v == 1);
     {
       version: 1,
       generated_at_utc: $generated_at_utc,
       status: $status,
       stage: $stage,
       notes: $notes,
       summary_log: $summary_log,
       summary_json: $summary_json,
       inputs: {
         base_port: $base_port,
         client_iface: $client_iface,
         exit_iface: $exit_iface,
         vpn_iface: $vpn_iface,
         runtime_fix_prune_wg_only_dir: boolstr($runtime_fix_prune_wg_only_dir),
         strict_beta: boolstr($strict_beta),
         timeout_sec: (if ($timeout_sec | length) > 0 then ($timeout_sec | tonumber) else null end),
         min_selection_lines: (if ($min_selection_lines | length) > 0 then ($min_selection_lines | tonumber) else null end),
         force_iface_reset: (if ($force_iface_reset | length) > 0 then ($force_iface_reset == "1") else null end),
         cleanup_ifaces: (if ($cleanup_ifaces | length) > 0 then ($cleanup_ifaces == "1") else null end),
         keep_stack: (if ($keep_stack | length) > 0 then ($keep_stack == "1") else null end),
         command: ("./scripts/pre_real_host_readiness.sh " + ([
           "--base-port " + ($base_port|tostring),
           "--client-iface " + $client_iface,
           "--exit-iface " + $exit_iface,
           "--vpn-iface " + $vpn_iface,
           "--runtime-fix-prune-wg-only-dir " + (if boolstr($runtime_fix_prune_wg_only_dir) then "1" else "0" end),
           "--strict-beta " + (if boolstr($strict_beta) then "1" else "0" end)
         ] | join(" ")))
       },
       runtime_fix: {
         rc: ($runtime_fix_rc | tonumber),
         status: (if ($runtime_fix_rc | tonumber) == 0 and $runtime_fix_after_status == "OK" then "ok" else "fail" end),
         log: $runtime_fix_log,
         summary_json: $runtime_fix_json,
         after_status: $runtime_fix_after_status,
         actions_taken: ($runtime_fix_actions_taken | tonumber),
         actions_failed: ($runtime_fix_actions_failed | tonumber)
       },
       wg_only_stack_selftest: {
         rc: (if ($wg_only_rc | length) > 0 then ($wg_only_rc | tonumber) else null end),
         status: $wg_only_status,
         log: $wg_only_log,
         summary_json: $wg_only_summary_json,
         recorded_at_utc: $wg_only_recorded_at,
         notes: $wg_only_notes
       },
       manual_validation_report: {
         status: $manual_validation_report_status,
         summary_json: $manual_validation_report_summary_json,
         report_md: $manual_validation_report_md,
         log: $manual_validation_report_log,
         readiness_status: $manual_validation_report_readiness_status,
         next_action_check_id: $manual_validation_report_next_action_check_id,
         next_action_command: $manual_validation_report_next_action_command
       },
       machine_c_smoke_gate: {
         ready: boolstr($machine_c_smoke_ready),
         blockers: $blockers,
         next_command: $machine_c_smoke_command
       }
     }'
)"
printf '%s\n' "$summary_payload" >"$summary_json"

echo "[pre-real-host-readiness] status=$(printf '%s' "$status" | tr '[:lower:]' '[:upper:]') stage=$result_stage"
echo "[pre-real-host-readiness] machine_c_smoke_ready=$(if [[ "$machine_c_smoke_ready" == "1" ]]; then printf 'true'; else printf 'false'; fi)"
echo "[pre-real-host-readiness] blockers=$(printf '%s\n' "$blockers_json" | jq -r 'if length == 0 then "none" else join(",") end')"
echo "[pre-real-host-readiness] manual_validation_readiness_status=${manual_validation_report_readiness_status:-unknown}"
echo "[pre-real-host-readiness] next_machine_c_command=$machine_c_smoke_command"
echo "[pre-real-host-readiness] summary_json=$summary_json"
echo "[pre-real-host-readiness] summary_log=$summary_log"
if [[ "$manual_validation_report_status" == "ok" ]]; then
  echo "[pre-real-host-readiness] readiness_report_json=$manual_validation_report_summary_json"
  echo "[pre-real-host-readiness] readiness_report_md=$manual_validation_report_md"
fi
if [[ "$print_summary_json" == "1" ]]; then
  echo "[pre-real-host-readiness] summary_json_payload:"
  cat "$summary_json"
fi

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 1
