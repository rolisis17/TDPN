#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in awk jq mktemp tr; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/three_machine_docker_readiness_record.sh \
    [three-machine-docker-readiness args...] \
    [--record-result [0|1]] \
    [--manual-validation-report [0|1]] \
    [--manual-validation-report-summary-json PATH] \
    [--manual-validation-report-md PATH] \
    [--rehearsal-summary-json PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run one-host dockerized 3-machine rehearsal and record its result into
  manual-validation receipts automatically.
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
  elif [[ "$path" =~ ^[A-Za-z]:[\\/].* ]]; then
    if command -v cygpath >/dev/null 2>&1; then
      cygpath -u "$path"
    else
      local drive="${path:0:1}"
      local tail="${path:2}"
      tail="${tail//\\//}"
      printf '/mnt/%s/%s' "${drive,,}" "${tail#/}"
    fi
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
  local redact_next=0
  for arg in "$@"; do
    if ((redact_next)); then
      printf '%q ' "[REDACTED]"
      redact_next=0
      continue
    fi
    case "$arg" in
      --subject|--anon-cred|--campaign-subject|--campaign-anon-cred|--key|--invite-key|--token|--auth-token|--admin-token|--authorization|--bearer|--password|--secret|--api-key)
        printf '%q ' "$arg"
        redact_next=1
        continue
        ;;
      --subject=*|--anon-cred=*|--campaign-subject=*|--campaign-anon-cred=*|--key=*|--invite-key=*|--token=*|--auth-token=*|--admin-token=*|--authorization=*|--bearer=*|--password=*|--secret=*|--api-key=*)
        printf '%q ' "${arg%%=*}=[REDACTED]"
        continue
        ;;
    esac
    printf '%q ' "$arg"
  done
  printf '\n'
}

redact_sensitive_output() {
  sed -E '
s/(--(subject|anon-cred|campaign-subject|campaign-anon-cred|key|invite-key|token|auth-token|admin-token|authorization|bearer|password|secret|api-key)(=|[[:space:]]+))[^[:space:]]+/\1[REDACTED]/g
s/((SUBJECT|ANON_CRED|INVITE_KEY|TOKEN|AUTH_TOKEN|ADMIN_TOKEN|AUTHORIZATION|BEARER|PASSWORD|SECRET|API_KEY)=)[^[:space:]]+/\1[REDACTED]/g
s/((Authorization|X-Admin-Token):[[:space:]]*(Bearer[[:space:]]*)?)[^[:space:]]+/\1[REDACTED]/Ig
s/inv-[A-Za-z0-9._:-]+/[REDACTED_INVITE]/g
'
}

redact_sensitive_text() {
  printf '%s\n' "${1:-}" | redact_sensitive_output
}

safe_append_to_array() {
  local array_name="$1"
  shift
  if [[ ! "$array_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    return 1
  fi
  local -n target_array="$array_name"
  target_array+=("$@")
}

append_existing_artifact() {
  local array_name="$1"
  local path="$2"
  [[ -z "$path" ]] && return 0
  if [[ -e "$path" ]]; then
    safe_append_to_array "$array_name" "$path" || return 1
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
    redact_sensitive_text "$content" >"$tmp"
    mv -f "$tmp" "$path"
  fi
}

run_and_capture() {
  local __var_name="$1"
  shift
  local output rc
  if output="$("$@" 2>&1)"; then
    printf '%s\n' "[$stage] command_ok: $(print_cmd "$@")" >>"$summary_log"
    redact_sensitive_text "$output" >>"$summary_log"
    printf -v "$__var_name" '%s' "$output"
    return 0
  else
    rc=$?
    printf '%s\n' "[$stage] command_failed rc=$rc: $(print_cmd "$@")" >>"$summary_log"
    redact_sensitive_text "$output" >>"$summary_log"
    printf -v "$__var_name" '%s' "$output"
    return "$rc"
  fi
}

easy_node_script="${THREE_MACHINE_DOCKER_READINESS_RECORD_EASY_NODE_SCRIPT:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$easy_node_script" ]]; then
  echo "missing easy_node helper script: $easy_node_script"
  exit 2
fi

original_args=("$@")
record_result="1"
manual_validation_report_enabled="1"
manual_validation_report_summary_json=""
manual_validation_report_md=""
rehearsal_summary_json=""
summary_json=""
print_summary_json="0"
declare -a rehearsal_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
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
    --rehearsal-summary-json)
      rehearsal_summary_json="${2:-}"
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
      rehearsal_args+=("$1")
      shift
      ;;
  esac
done

bool_arg_or_die "--record-result" "$record_result"
bool_arg_or_die "--manual-validation-report" "$manual_validation_report_enabled"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

log_dir="$(prepare_log_dir)"
timestamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/three_machine_docker_readiness_record_${timestamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$rehearsal_summary_json" ]]; then
  rehearsal_summary_json="$log_dir/three_machine_docker_readiness_record_${timestamp}_rehearsal.json"
else
  rehearsal_summary_json="$(abs_path "$rehearsal_summary_json")"
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

mkdir -p "$(dirname "$summary_json")" "$(dirname "$rehearsal_summary_json")" "$(dirname "$manual_validation_report_summary_json")" "$(dirname "$manual_validation_report_md")"
summary_log="$log_dir/three_machine_docker_readiness_record_${timestamp}.log"
manual_validation_report_log="$log_dir/three_machine_docker_readiness_record_${timestamp}_manual_validation_report.log"
manual_validation_record_log="$log_dir/three_machine_docker_readiness_record_${timestamp}_manual_validation_record.log"
: >"$summary_log"

stage="rehearsal"
rehearsal_status="fail"
rehearsal_rc=1
record_status="fail"
record_rc=1
notes=""
rehearsal_json='{}'
rehearsal_log_path=""
manual_validation_report_status="skipped"
manual_validation_report_rc=0
manual_validation_report_ran="0"
manual_validation_report_readiness_status=""
manual_validation_report_next_action_check_id=""
manual_validation_report_written_summary_json="0"
manual_validation_report_written_report_md="0"
receipt_status="skipped"
receipt_rc=0
receipt_ran="0"
receipt_written="0"
receipt_json_path=""

write_summary_json() {
  local summary_tmp=""
  summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
  jq -n \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg status "$record_status" \
    --arg rehearsal_status "$rehearsal_status" \
    --arg notes "$notes" \
    --arg command "$(print_cmd "$0" "${original_args[@]}")" \
    --arg summary_log "$summary_log" \
    --arg summary_json "$summary_json" \
    --arg rehearsal_summary_json "$rehearsal_summary_json" \
    --arg rehearsal_log "$rehearsal_log_path" \
    --argjson record_rc "$record_rc" \
    --argjson rehearsal_rc "$rehearsal_rc" \
    --argjson rehearsal "$rehearsal_json" \
    --arg manual_validation_report_summary_json "$manual_validation_report_summary_json" \
    --arg manual_validation_report_md "$manual_validation_report_md" \
    --arg manual_validation_report_status "$manual_validation_report_status" \
    --argjson manual_validation_report_rc "$manual_validation_report_rc" \
    --argjson manual_validation_report_ran "$manual_validation_report_ran" \
    --arg manual_validation_report_readiness_status "$manual_validation_report_readiness_status" \
    --arg manual_validation_report_next_action_check_id "$manual_validation_report_next_action_check_id" \
    --arg manual_validation_report_log "$manual_validation_report_log" \
    --argjson manual_validation_report_enabled "$manual_validation_report_enabled" \
    --argjson manual_validation_report_written_summary_json "$manual_validation_report_written_summary_json" \
    --argjson manual_validation_report_written_report_md "$manual_validation_report_written_report_md" \
    --argjson record_result "$record_result" \
    --argjson receipt_ran "$receipt_ran" \
    --arg receipt_status "$receipt_status" \
    --argjson receipt_rc "$receipt_rc" \
    --argjson receipt_written "$receipt_written" \
    --arg receipt_json_path "$receipt_json_path" \
    --arg manual_validation_record_log "$manual_validation_record_log" \
    '{
      version: 1,
      schema: {
        id: "three_machine_docker_readiness_record_summary",
        major: 1,
        minor: 1
      },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $record_rc,
      notes: $notes,
      command: $command,
      rehearsal: {
        status: $rehearsal_status,
        rc: $rehearsal_rc,
        summary_json: $rehearsal_summary_json,
        summary_log: $rehearsal_log,
        summary: $rehearsal
      },
      manual_validation_report: {
        enabled: ($manual_validation_report_enabled == 1),
        ran: ($manual_validation_report_ran == 1),
        status: $manual_validation_report_status,
        rc: $manual_validation_report_rc,
        summary_json: $manual_validation_report_summary_json,
        report_md: $manual_validation_report_md,
        log: $manual_validation_report_log,
        readiness_status: $manual_validation_report_readiness_status,
        next_action_check_id: $manual_validation_report_next_action_check_id,
        written_summary_json: ($manual_validation_report_written_summary_json == 1),
        written_report_md: ($manual_validation_report_written_report_md == 1)
      },
      manual_validation_record: {
        enabled: ($record_result == 1),
        ran: ($receipt_ran == 1),
        status: $receipt_status,
        rc: $receipt_rc,
        check_id: "three_machine_docker_readiness",
        log: $manual_validation_record_log,
        written_receipt: ($receipt_written == 1),
        receipt_json: $receipt_json_path
      },
      artifacts: {
        summary_log: $summary_log,
        summary_json: $summary_json,
        rehearsal_summary_json: $rehearsal_summary_json,
        rehearsal_log: $rehearsal_log,
        manual_validation_report_summary_json: $manual_validation_report_summary_json,
        manual_validation_report_md: $manual_validation_report_md,
        manual_validation_report_log: $manual_validation_report_log,
        manual_validation_record_log: $manual_validation_record_log
      }
    }' >"$summary_tmp"
  mv -f "$summary_tmp" "$summary_json"
}

refresh_manual_validation_report() {
  local report_output=""
  local report_json=""
  local report_compatible="0"
  local -a report_cmd=()

  if [[ "$manual_validation_report_enabled" != "1" ]]; then
    return 0
  fi

  manual_validation_report_ran="1"
  rm -f "$manual_validation_report_summary_json" "$manual_validation_report_md" 2>/dev/null || true
  report_cmd=(
    "$easy_node_script" manual-validation-report
    --overlay-check-id "three_machine_docker_readiness"
    --overlay-status "$rehearsal_status"
    --overlay-notes "$notes"
    --overlay-command "$(print_cmd "$0" "${original_args[@]}")"
    --overlay-artifact "$summary_log"
    --overlay-artifact "$summary_json"
    --overlay-artifact "$rehearsal_summary_json"
    --summary-json "$manual_validation_report_summary_json"
    --report-md "$manual_validation_report_md"
    --print-report 0
    --print-summary-json 0
  )

  stage="manual-validation-report"
  if run_and_capture report_output "${report_cmd[@]}"; then
    manual_validation_report_status="ok"
    manual_validation_report_rc=0
  else
    manual_validation_report_rc=$?
    manual_validation_report_status="fail"
  fi
  persist_artifact_text "$manual_validation_report_log" "$report_output"

  if [[ -f "$manual_validation_report_summary_json" ]] && jq -e . "$manual_validation_report_summary_json" >/dev/null 2>&1; then
    manual_validation_report_written_summary_json="1"
  else
    manual_validation_report_written_summary_json="0"
  fi
  if [[ -f "$manual_validation_report_md" ]]; then
    manual_validation_report_written_report_md="1"
  else
    manual_validation_report_written_report_md="0"
  fi

  report_json="$(extract_json_payload "manual-validation-report" "$report_output")"
  if [[ -z "$report_json" && -f "$manual_validation_report_summary_json" ]] && jq -e . "$manual_validation_report_summary_json" >/dev/null 2>&1; then
    report_json="$(cat "$manual_validation_report_summary_json")"
  fi
  if validate_manual_validation_summary_payload "$report_json"; then
    report_compatible="1"
    manual_validation_report_readiness_status="$(jq -r '.report.readiness_status // ""' <<<"$report_json")"
    manual_validation_report_next_action_check_id="$(jq -r '.summary.next_action_check_id // ""' <<<"$report_json")"
  else
    manual_validation_report_readiness_status=""
    manual_validation_report_next_action_check_id=""
  fi

  if [[ "$report_compatible" != "1" ]]; then
    if [[ "$manual_validation_report_status" == "ok" ]]; then
      manual_validation_report_status="fail"
      if [[ "$manual_validation_report_rc" -eq 0 ]]; then
        manual_validation_report_rc=1
      fi
    fi
    printf '%s\n' "[$stage] summary_payload_invalid_or_incompatible schema check failed" >>"$summary_log"
  fi
}

record_receipt() {
  local -a record_cmd=()
  local record_output=""
  local record_receipt_json=""
  local receipt_artifact=""

  receipt_ran="1"
  record_cmd=(
    "$easy_node_script" manual-validation-record
    --check-id "three_machine_docker_readiness"
    --status "$record_status"
    --notes "$notes"
    --command "$(print_cmd "$0" "${original_args[@]}")"
    --show-json 0
  )
  for receipt_artifact in "$@"; do
    record_cmd+=(--artifact "$receipt_artifact")
  done
  if run_and_capture record_output "${record_cmd[@]}"; then
    receipt_status="ok"
    receipt_rc=0
  else
    receipt_rc=$?
    receipt_status="fail"
  fi
  persist_artifact_text "$manual_validation_record_log" "$record_output"

  record_receipt_json="$(printf '%s\n' "$record_output" | awk -F'=' '/^\[manual-validation-record\] receipt_json=/{print $2; exit}' | tr -d '\r')"
  receipt_json_path="$(trim "$record_receipt_json")"
  if [[ -n "$receipt_json_path" && -f "$receipt_json_path" ]]; then
    receipt_written="1"
  else
    receipt_written="0"
  fi
}

declare -a rehearsal_cmd=()
rehearsal_cmd=(
  "$easy_node_script" three-machine-docker-readiness
  "${rehearsal_args[@]}"
  --summary-json "$rehearsal_summary_json"
  --print-summary-json 0
)

rehearsal_output=""
if run_and_capture rehearsal_output "${rehearsal_cmd[@]}"; then
  rehearsal_rc=0
else
  rehearsal_rc=$?
fi

if [[ -f "$rehearsal_summary_json" ]] && jq -e . "$rehearsal_summary_json" >/dev/null 2>&1; then
  rehearsal_json="$(cat "$rehearsal_summary_json")"
  rehearsal_log_path="$(jq -r '.artifacts.summary_log // ""' <<<"$rehearsal_json")"
else
  notes="three-machine-docker-readiness did not emit a usable JSON summary"
  rehearsal_status="fail"
  record_status="fail"
  record_rc=1
  write_summary_json
  echo "three-machine-docker-readiness-record: status=fail"
  echo "summary_log: $summary_log"
  echo "summary_json: $summary_json"
  if [[ "$print_summary_json" == "1" ]]; then
    cat "$summary_json"
  fi
  exit 1
fi

if [[ "$rehearsal_rc" -eq 0 && "$(jq -r '.status // ""' <<<"$rehearsal_json")" == "pass" ]]; then
  rehearsal_status="pass"
  notes="$(jq -r '.notes // ""' <<<"$rehearsal_json")"
  if [[ -z "$notes" ]]; then
    notes="Docker 3-machine rehearsal passed"
  fi
else
  rehearsal_status="fail"
  notes="$(jq -r '.notes // ""' <<<"$rehearsal_json")"
  if [[ -z "$notes" ]]; then
    notes="Docker 3-machine rehearsal failed"
  fi
fi

record_status="$rehearsal_status"
record_rc="$rehearsal_rc"
if [[ "$record_status" != "pass" && "$record_rc" -eq 0 ]]; then
  record_rc=1
fi

write_summary_json
refresh_manual_validation_report
if [[ "$rehearsal_status" == "pass" && "$manual_validation_report_enabled" == "1" ]]; then
  manual_validation_report_gate_failure=""
  if [[ "$manual_validation_report_status" != "ok" || "$manual_validation_report_rc" -ne 0 ]]; then
    manual_validation_report_gate_failure="manual-validation report failed or emitted incompatible summary"
  elif [[ "$manual_validation_report_written_summary_json" != "1" || "$manual_validation_report_written_report_md" != "1" ]]; then
    manual_validation_report_gate_failure="manual-validation report artifact missing"
  fi
fi
if [[ -n "${manual_validation_report_gate_failure:-}" ]]; then
  record_status="fail"
  record_rc=1
  if [[ -n "$notes" ]]; then
    notes="$notes; $manual_validation_report_gate_failure"
  else
    notes="$manual_validation_report_gate_failure"
  fi
fi
write_summary_json

declare -a receipt_artifacts=()
append_existing_artifact receipt_artifacts "$summary_log"
append_existing_artifact receipt_artifacts "$summary_json"
append_existing_artifact receipt_artifacts "$rehearsal_summary_json"
append_existing_artifact receipt_artifacts "$rehearsal_log_path"
append_existing_artifact receipt_artifacts "$manual_validation_report_log"
append_existing_artifact receipt_artifacts "$manual_validation_report_summary_json"
append_existing_artifact receipt_artifacts "$manual_validation_report_md"

if [[ "$record_result" == "1" ]]; then
  record_receipt "${receipt_artifacts[@]}"
fi

if [[ "$record_result" == "1" ]]; then
  if [[ "$receipt_status" != "ok" || "$receipt_rc" -ne 0 || "$receipt_written" != "1" ]]; then
    record_status="fail"
    record_rc=1
    if [[ "$notes" != *"manual-validation record failed"* && "$notes" != *"manual-validation receipt missing"* ]]; then
      if [[ "$receipt_status" != "ok" || "$receipt_rc" -ne 0 ]]; then
        if [[ -n "$notes" ]]; then
          notes="$notes; manual-validation record failed"
        else
          notes="manual-validation record failed"
        fi
      else
        if [[ -n "$notes" ]]; then
          notes="$notes; manual-validation receipt missing"
        else
          notes="manual-validation receipt missing"
        fi
      fi
    fi
  fi
fi

write_summary_json

echo "three-machine-docker-readiness-record: status=$record_status"
echo "summary_log: $summary_log"
echo "summary_json: $summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$record_status" != "pass" ]]; then
  exit 1
fi
exit 0
