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
  ./scripts/three_machine_docker_profile_matrix_record.sh \
    [three-machine-docker-profile-matrix args...] \
    [--run-matrix [0|1]] \
    [--record-result [0|1]] \
    [--manual-validation-report [0|1]] \
    [--manual-validation-report-summary-json PATH] \
    [--manual-validation-report-md PATH] \
    [--matrix-summary-json PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run docker 3-machine profile matrix rehearsal and record the result into
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

resolve_matrix_dry_run_mode() {
  local dry_run_mode="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_DRY_RUN:-0}"
  local idx=0
  local arg=""
  local next=""
  if [[ "$dry_run_mode" != "0" && "$dry_run_mode" != "1" ]]; then
    dry_run_mode="0"
  fi
  while (( idx < ${#matrix_args[@]} )); do
    arg="${matrix_args[$idx]}"
    if [[ "$arg" == "--dry-run" ]]; then
      if (( idx + 1 < ${#matrix_args[@]} )); then
        next="${matrix_args[$((idx + 1))]}"
        if [[ "$next" == "0" || "$next" == "1" ]]; then
          dry_run_mode="$next"
          idx=$((idx + 2))
          continue
        fi
      fi
      dry_run_mode="1"
      idx=$((idx + 1))
      continue
    fi
    idx=$((idx + 1))
  done
  printf '%s\n' "$dry_run_mode"
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

matrix_script="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MATRIX_SCRIPT:-$ROOT_DIR/scripts/three_machine_docker_profile_matrix.sh}"
manual_validation_record_script="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MANUAL_VALIDATION_RECORD_SCRIPT:-$ROOT_DIR/scripts/manual_validation_record.sh}"
manual_validation_report_script="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_MANUAL_VALIDATION_REPORT_SCRIPT:-$ROOT_DIR/scripts/manual_validation_report.sh}"
if [[ ! -x "$matrix_script" ]]; then
  echo "missing executable matrix script: $matrix_script"
  exit 2
fi
if [[ ! -x "$manual_validation_record_script" ]]; then
  echo "missing executable manual validation record script: $manual_validation_record_script"
  exit 2
fi
if [[ ! -x "$manual_validation_report_script" ]]; then
  echo "missing executable manual validation report script: $manual_validation_report_script"
  exit 2
fi

original_args=("$@")
run_matrix="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_RUN_MATRIX:-1}"
record_result="1"
manual_validation_report_enabled="1"
manual_validation_report_summary_json=""
manual_validation_report_md=""
matrix_summary_json=""
summary_json=""
print_summary_json="0"
declare -a matrix_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-matrix)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_matrix="${2:-}"
        shift 2
      else
        run_matrix="1"
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
    --matrix-summary-json)
      matrix_summary_json="${2:-}"
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
      matrix_args+=("$1")
      shift
      ;;
  esac
done

bool_arg_or_die "--run-matrix" "$run_matrix"
bool_arg_or_die "--record-result" "$record_result"
bool_arg_or_die "--manual-validation-report" "$manual_validation_report_enabled"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

log_dir="$(prepare_log_dir)"
timestamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/three_machine_docker_profile_matrix_record_${timestamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$matrix_summary_json" ]]; then
  matrix_summary_json="$log_dir/three_machine_docker_profile_matrix_record_${timestamp}_matrix.json"
else
  matrix_summary_json="$(abs_path "$matrix_summary_json")"
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

mkdir -p "$(dirname "$summary_json")" "$(dirname "$matrix_summary_json")" "$(dirname "$manual_validation_report_summary_json")" "$(dirname "$manual_validation_report_md")"
summary_log="$log_dir/three_machine_docker_profile_matrix_record_${timestamp}.log"
matrix_log="$log_dir/three_machine_docker_profile_matrix_record_${timestamp}_matrix.log"
manual_validation_report_log="$log_dir/three_machine_docker_profile_matrix_record_${timestamp}_manual_validation_report.log"
manual_validation_record_log="$log_dir/three_machine_docker_profile_matrix_record_${timestamp}_manual_validation_record.log"
: >"$summary_log"

stage="matrix"
matrix_status="fail"
matrix_rc=1
matrix_command_rc=1
matrix_summary_rc=""
notes=""
matrix_json='{}'
matrix_log_path=""
matrix_summary_valid="0"
matrix_summary_status=""
matrix_dry_run_mode="0"
matrix_ran="0"

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
    --arg status "$matrix_status" \
    --arg notes "$notes" \
    --arg command "$(print_cmd "$0" "${original_args[@]}")" \
    --argjson run_matrix "$run_matrix" \
    --arg summary_log "$summary_log" \
    --arg summary_json "$summary_json" \
    --arg matrix_summary_json "$matrix_summary_json" \
    --arg matrix_log "$matrix_log" \
    --arg matrix_log_from_summary "$matrix_log_path" \
    --argjson matrix_rc "$matrix_rc" \
    --argjson matrix_command_rc "$matrix_command_rc" \
    --arg matrix_summary_rc "$matrix_summary_rc" \
    --arg matrix_summary_status "$matrix_summary_status" \
    --argjson matrix_summary_valid "$matrix_summary_valid" \
    --argjson matrix_dry_run_mode "$matrix_dry_run_mode" \
    --argjson matrix_ran "$matrix_ran" \
    --argjson matrix "$matrix_json" \
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
        id: "three_machine_docker_profile_matrix_record_summary",
        major: 1,
        minor: 0
      },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $matrix_rc,
      notes: $notes,
      command: $command,
      inputs: {
        run_matrix: ($run_matrix == 1)
      },
      stages: {
        matrix: {
          ran: ($matrix_ran == 1),
          status: $status,
          rc: $matrix_rc,
          command_rc: $matrix_command_rc,
          summary_rc: (
            if ($matrix_summary_rc | length) > 0 and ($matrix_summary_rc | test("^[0-9]+$")) then
              ($matrix_summary_rc | tonumber)
            else
              null
            end
          ),
          summary_status: $matrix_summary_status,
          summary_valid: ($matrix_summary_valid == 1),
          dry_run: ($matrix_dry_run_mode == 1),
          summary_json: $matrix_summary_json,
          log: $matrix_log,
          matrix_log: $matrix_log_from_summary,
          summary: $matrix
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
        }
      },
      artifacts: {
        summary_log: $summary_log,
        summary_json: $summary_json,
        matrix_summary_json: $matrix_summary_json,
        matrix_log: $matrix_log,
        matrix_log_from_summary: $matrix_log_from_summary,
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
  local -a report_cmd=()
  local report_compatible="0"

  if [[ "$manual_validation_report_enabled" != "1" ]]; then
    return 0
  fi

  manual_validation_report_ran="1"
  report_cmd=(
    "$manual_validation_report_script"
    --overlay-check-id "three_machine_docker_readiness"
    --overlay-status "$matrix_status"
    --overlay-notes "$notes"
    --overlay-command "$(print_cmd "$0" "${original_args[@]}")"
    --overlay-artifact "$summary_log"
    --overlay-artifact "$summary_json"
    --overlay-artifact "$matrix_summary_json"
    --overlay-artifact "$matrix_log"
    --summary-json "$manual_validation_report_summary_json"
    --report-md "$manual_validation_report_md"
    --print-report 0
    --print-summary-json 0
  )
  if [[ -n "$matrix_log_path" ]]; then
    report_cmd+=(--overlay-artifact "$matrix_log_path")
  fi

  stage="manual-validation-report"
  if run_and_capture report_output "${report_cmd[@]}"; then
    manual_validation_report_status="ok"
    manual_validation_report_rc=0
  else
    manual_validation_report_status="fail"
    manual_validation_report_rc=$?
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
  if [[ -z "$report_json" && "$manual_validation_report_written_summary_json" == "1" ]]; then
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
  local record_output=""
  local record_receipt_json=""
  local -a record_cmd=()
  local receipt_artifact=""

  receipt_ran="1"
  stage="manual-validation-record"
  record_cmd=(
    "$manual_validation_record_script"
    --check-id "three_machine_docker_readiness"
    --status "$matrix_status"
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
    receipt_status="fail"
    receipt_rc=$?
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

declare -a matrix_cmd=()
matrix_cmd=(
  "$matrix_script"
  "${matrix_args[@]}"
  --summary-json "$matrix_summary_json"
  --print-summary-json 0
)

matrix_output=""
if [[ "$run_matrix" == "1" ]]; then
  matrix_ran="1"
  if run_and_capture matrix_output "${matrix_cmd[@]}"; then
    matrix_command_rc=0
  else
    matrix_command_rc=$?
  fi
  persist_artifact_text "$matrix_log" "$matrix_output"
else
  matrix_ran="0"
  matrix_command_rc=0
  matrix_output="matrix stage skipped (--run-matrix 0); reusing summary artifact if present"
  persist_artifact_text "$matrix_log" "$matrix_output"
fi
matrix_rc="$matrix_command_rc"
matrix_dry_run_mode="$(resolve_matrix_dry_run_mode)"

if [[ -f "$matrix_summary_json" ]] && jq -e . "$matrix_summary_json" >/dev/null 2>&1; then
  matrix_summary_valid="1"
  matrix_json="$(cat "$matrix_summary_json")"
  matrix_summary_status="$(jq -r '.status // ""' <<<"$matrix_json")"
  matrix_summary_rc="$(jq -r '.rc // ""' <<<"$matrix_json")"
  matrix_log_path="$(jq -r '.artifacts.matrix_log // ""' <<<"$matrix_json")"
  if [[ -z "$matrix_log_path" ]]; then
    matrix_log_path="$(jq -r '.artifacts.summary_log // ""' <<<"$matrix_json")"
  fi
  if [[ "$matrix_summary_rc" =~ ^[0-9]+$ ]]; then
    matrix_rc="$matrix_summary_rc"
  fi
else
  matrix_summary_valid="0"
  matrix_json='{}'
  matrix_summary_status="missing"
fi

if [[ "$matrix_summary_valid" == "1" ]]; then
  if [[ "$matrix_command_rc" -eq 0 && "$matrix_summary_status" == "pass" ]]; then
    matrix_status="pass"
  else
    matrix_status="fail"
  fi
  notes="$(jq -r '.notes // ""' <<<"$matrix_json")"
  if [[ -z "$notes" ]]; then
    if [[ "$matrix_status" == "pass" ]]; then
      notes="Docker 3-machine profile matrix rehearsal passed"
    else
      notes="Docker 3-machine profile matrix rehearsal failed"
    fi
  fi
else
  if [[ "$run_matrix" == "0" ]]; then
    matrix_status="fail"
    if [[ "$matrix_rc" -eq 0 ]]; then
      matrix_rc=1
    fi
    notes="run-matrix disabled (--run-matrix 0) but matrix summary JSON is missing or unusable"
  elif [[ "$matrix_command_rc" -eq 0 && "$matrix_dry_run_mode" == "1" ]]; then
    matrix_status="pass"
    matrix_rc=0
    matrix_summary_status="dry-run-no-summary"
    notes="three-machine-docker-profile-matrix dry-run completed (summary JSON intentionally absent)"
  else
    matrix_status="fail"
    if [[ "$matrix_rc" -eq 0 ]]; then
      matrix_rc=1
    fi
    notes="three-machine-docker-profile-matrix did not emit a usable JSON summary"
  fi
fi

write_summary_json
refresh_manual_validation_report
write_summary_json

declare -a receipt_artifacts=()
append_existing_artifact receipt_artifacts "$summary_log"
append_existing_artifact receipt_artifacts "$summary_json"
append_existing_artifact receipt_artifacts "$matrix_summary_json"
append_existing_artifact receipt_artifacts "$matrix_log"
append_existing_artifact receipt_artifacts "$matrix_log_path"
append_existing_artifact receipt_artifacts "$manual_validation_report_log"
append_existing_artifact receipt_artifacts "$manual_validation_report_summary_json"
append_existing_artifact receipt_artifacts "$manual_validation_report_md"

if [[ "$record_result" == "1" ]]; then
  record_receipt "${receipt_artifacts[@]}"
fi

write_summary_json

echo "three-machine-docker-profile-matrix-record: status=$matrix_status"
echo "summary_log: $summary_log"
echo "summary_json: $summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$matrix_status" != "pass" ]]; then
  exit 1
fi
exit 0
