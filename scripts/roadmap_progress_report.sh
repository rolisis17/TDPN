#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_progress_report.sh \
    [--refresh-manual-validation [0|1]] \
    [--refresh-single-machine-readiness [0|1]] \
    [--manual-refresh-timeout-sec N] \
    [--single-machine-refresh-timeout-sec N] \
    [--manual-validation-summary-json PATH] \
    [--manual-validation-report-md PATH] \
    [--profile-compare-signoff-summary-json PATH] \
    [--single-machine-summary-json PATH] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-report [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Generate one concise roadmap progress handoff (JSON + markdown) from current
  manual-validation readiness state, with optional one-host readiness refresh.

Notes:
  - This does not replace real machine-C and true 3-machine production signoff.
  - Blockchain/payment track is intentionally reported as deferred per VPN-first roadmap.
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

json_file_valid_01() {
  local path="$1"
  if [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

manual_validation_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    (.summary | type == "object")
    and (.report | type == "object")
    and ((.report.readiness_status // "") | type == "string")
    and (
      .schema == null
      or (
        (.schema | type == "object")
        and ((.schema.id // "") == "manual_validation_readiness_summary")
        and ((.schema.major // 0) | type == "number")
        and ((.schema.major // 0) >= 1)
        and ((.schema.major // 0) <= 1)
        and (((.schema.major // 0) | floor) == (.schema.major // 0))
      )
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

single_machine_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    ((.status // "") | type == "string")
    and (.summary | type == "object")
    and (
      .schema == null
      or (
        (.schema | type == "object")
        and ((.schema.id // "") == "single_machine_prod_readiness_summary")
        and ((.schema.major // 0) | type == "number")
        and ((.schema.major // 0) >= 1)
        and ((.schema.major // 0) <= 1)
        and (((.schema.major // 0) | floor) == (.schema.major // 0))
      )
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

single_machine_refresh_transient_non_blocking_01() {
  local refresh_log="$1"
  local summary_path="$2"

  if [[ ! -f "$refresh_log" ]]; then
    printf '0'
    return
  fi
  if ! rg -qi \
    'server misbehaving|temporary failure in name resolution|tls handshake timeout|i/o timeout|context deadline exceeded|connection reset by peer|failed to do request|request canceled while waiting for connection' \
    "$refresh_log"; then
    printf '0'
    return
  fi
  if [[ "$(single_machine_summary_usable_01 "$summary_path")" != "1" ]]; then
    printf '0'
    return
  fi

  if jq -e '
    def arr_or_empty(v): if (v | type) == "array" then v else [] end;
    (
      (arr_or_empty(.summary.critical_failed_steps) | length) > 0
      and (
        (arr_or_empty(.summary.critical_failed_steps)
          | map((.step_id // "") | tostring)
          | unique
        ) == ["three_machine_docker_readiness"]
      )
      and ((arr_or_empty(.summary.pending_local_checks) | length) == 0)
    )
    or
    (
      ((.status // "") | tostring) == "fail"
      and (((.summary.three_machine_docker_readiness.status // "") | tostring) == "fail")
      and ((arr_or_empty(.summary.pending_local_checks) | length) == 0)
    )
  ' "$summary_path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

restore_json_snapshot() {
  local snapshot_path="$1"
  local target_path="$2"
  local restore_tmp=""
  if [[ ! -f "$snapshot_path" ]]; then
    return 1
  fi
  if ! jq -e . "$snapshot_path" >/dev/null 2>&1; then
    return 1
  fi
  mkdir -p "$(dirname "$target_path")"
  restore_tmp="$(mktemp "${target_path}.restore.tmp.XXXXXX")"
  cp "$snapshot_path" "$restore_tmp"
  if ! jq -e . "$restore_tmp" >/dev/null 2>&1; then
    rm -f "$restore_tmp"
    return 1
  fi
  mv -f "$restore_tmp" "$target_path"
}

refresh_manual_validation="1"
refresh_single_machine_readiness="0"
manual_refresh_timeout_sec="${ROADMAP_PROGRESS_MANUAL_REFRESH_TIMEOUT_SEC:-900}"
# Full single-machine refresh can include ci_local + beta_preflight + deep_test_suite.
# Keep default high enough to avoid false fail-close timeouts on healthy hosts.
single_machine_refresh_timeout_sec="${ROADMAP_PROGRESS_SINGLE_MACHINE_REFRESH_TIMEOUT_SEC:-7200}"
print_report="1"
print_summary_json="1"

summary_json="$ROOT_DIR/.easy-node-logs/roadmap_progress_summary.json"
report_md="$ROOT_DIR/.easy-node-logs/roadmap_progress_report.md"
manual_validation_summary_json="$ROOT_DIR/.easy-node-logs/manual_validation_readiness_summary.json"
manual_validation_report_md="$ROOT_DIR/.easy-node-logs/manual_validation_readiness_report.md"
profile_compare_signoff_summary_json="$ROOT_DIR/.easy-node-logs/profile_compare_campaign_signoff_summary.json"
single_machine_summary_json="$ROOT_DIR/.easy-node-logs/single_machine_prod_readiness_latest.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --refresh-manual-validation)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_manual_validation="${2:-}"
        shift 2
      else
        refresh_manual_validation="1"
        shift
      fi
      ;;
    --refresh-single-machine-readiness)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_single_machine_readiness="${2:-}"
        shift 2
      else
        refresh_single_machine_readiness="1"
        shift
      fi
      ;;
    --manual-validation-summary-json)
      manual_validation_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --manual-refresh-timeout-sec)
      manual_refresh_timeout_sec="${2:-}"
      shift 2
      ;;
    --single-machine-refresh-timeout-sec)
      single_machine_refresh_timeout_sec="${2:-}"
      shift 2
      ;;
    --manual-validation-report-md)
      manual_validation_report_md="$(abs_path "${2:-}")"
      shift 2
      ;;
    --profile-compare-signoff-summary-json)
      profile_compare_signoff_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --single-machine-summary-json)
      single_machine_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --summary-json)
      summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --report-md)
      report_md="$(abs_path "${2:-}")"
      shift 2
      ;;
    --print-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_report="${2:-}"
        shift 2
      else
        print_report="1"
        shift
      fi
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

for cmd in jq date mktemp rg; do
  need_cmd "$cmd"
done

bool_arg_or_die "--refresh-manual-validation" "$refresh_manual_validation"
bool_arg_or_die "--refresh-single-machine-readiness" "$refresh_single_machine_readiness"
bool_arg_or_die "--print-report" "$print_report"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
if ! [[ "$manual_refresh_timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "--manual-refresh-timeout-sec must be an integer >= 0"
  exit 2
fi
if ! [[ "$single_machine_refresh_timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "--single-machine-refresh-timeout-sec must be an integer >= 0"
  exit 2
fi

run_with_optional_timeout() {
  local timeout_sec="$1"
  shift
  if [[ "$timeout_sec" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    timeout "${timeout_sec}s" "$@"
  else
    "$@"
  fi
}

manual_validation_report_script="${ROADMAP_PROGRESS_MANUAL_VALIDATION_REPORT_SCRIPT:-$ROOT_DIR/scripts/manual_validation_report.sh}"
single_machine_script="${ROADMAP_PROGRESS_SINGLE_MACHINE_SCRIPT:-$ROOT_DIR/scripts/single_machine_prod_readiness.sh}"
product_roadmap_doc="${ROADMAP_PROGRESS_PRODUCT_ROADMAP_DOC:-$ROOT_DIR/docs/product-roadmap.md}"

mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$report_md")"
mkdir -p "$(dirname "$manual_validation_summary_json")"
mkdir -p "$(dirname "$manual_validation_report_md")"
mkdir -p "$(dirname "$single_machine_summary_json")"

log_dir="$ROOT_DIR/.easy-node-logs"
mkdir -p "$log_dir"
ts="$(date +%Y%m%d_%H%M%S)"
manual_refresh_log="$log_dir/roadmap_progress_manual_validation_${ts}.log"
single_machine_refresh_log="$log_dir/roadmap_progress_single_machine_${ts}.log"

manual_refresh_status="skip"
manual_refresh_rc=0
manual_refresh_timed_out="false"
manual_refresh_duration_sec=0
single_machine_refresh_status="skip"
single_machine_refresh_rc=0
single_machine_refresh_timed_out="false"
single_machine_refresh_duration_sec=0
single_machine_refresh_non_blocking_transient="false"
single_machine_refresh_non_blocking_reason=""

manual_summary_snapshot=""
manual_summary_snapshot_valid="false"
manual_summary_restored="false"
manual_summary_valid_after_run="false"
single_machine_summary_snapshot=""
single_machine_summary_snapshot_valid="false"
single_machine_summary_restored="false"
single_machine_summary_valid_after_run="false"

if [[ "$(manual_validation_summary_usable_01 "$manual_validation_summary_json")" == "1" ]]; then
  manual_summary_snapshot="$(mktemp "$log_dir/roadmap_progress_manual_validation_snapshot_${ts}_XXXXXX.json")"
  cp "$manual_validation_summary_json" "$manual_summary_snapshot"
  manual_summary_snapshot_valid="true"
fi
if [[ "$(single_machine_summary_usable_01 "$single_machine_summary_json")" == "1" ]]; then
  single_machine_summary_snapshot="$(mktemp "$log_dir/roadmap_progress_single_machine_snapshot_${ts}_XXXXXX.json")"
  cp "$single_machine_summary_json" "$single_machine_summary_snapshot"
  single_machine_summary_snapshot_valid="true"
fi

if [[ "$refresh_single_machine_readiness" == "1" ]]; then
  single_machine_refresh_status="fail"
  single_machine_refresh_timed_out="false"
  single_machine_started_at="$(date +%s)"
  if [[ "$single_machine_refresh_timeout_sec" -gt 0 ]] && ! command -v timeout >/dev/null 2>&1; then
    echo "[roadmap-progress-report] warn=timeout command not found; running single-machine refresh without timeout guard"
  fi
  echo "[roadmap-progress-report] refresh_step=single_machine_prod_readiness status=running timeout_sec=$single_machine_refresh_timeout_sec log=$single_machine_refresh_log"
  set +e
  run_with_optional_timeout "$single_machine_refresh_timeout_sec" "$single_machine_script" \
    --summary-json "$single_machine_summary_json" \
    --manual-validation-report-summary-json "$manual_validation_summary_json" \
    --manual-validation-report-md "$manual_validation_report_md" \
    --print-summary-json 0 >"$single_machine_refresh_log" 2>&1
  single_machine_refresh_rc=$?
  set -e
  single_machine_refresh_duration_sec="$(( $(date +%s) - single_machine_started_at ))"
  if [[ "$single_machine_refresh_rc" -eq 124 ]]; then
    single_machine_refresh_timed_out="true"
  fi
  if [[ "$single_machine_refresh_rc" -eq 0 ]]; then
    single_machine_refresh_status="pass"
  fi
  single_machine_summary_valid_after_run="false"
  if [[ "$(single_machine_summary_usable_01 "$single_machine_summary_json")" == "1" ]]; then
    single_machine_summary_valid_after_run="true"
  fi
  if [[ "$single_machine_refresh_status" == "pass" && "$single_machine_summary_valid_after_run" != "true" ]]; then
    single_machine_refresh_status="fail"
    if [[ "$single_machine_refresh_rc" -eq 0 ]]; then
      single_machine_refresh_rc=3
    fi
  fi
  if [[ "$single_machine_summary_valid_after_run" != "true" && "$single_machine_summary_snapshot_valid" == "true" ]]; then
    if restore_json_snapshot "$single_machine_summary_snapshot" "$single_machine_summary_json"; then
      single_machine_summary_restored="true"
      single_machine_summary_valid_after_run="true"
    fi
  fi
  if [[ "$single_machine_refresh_status" == "fail" && "$single_machine_refresh_timed_out" != "true" ]]; then
    if [[ "$(single_machine_refresh_transient_non_blocking_01 "$single_machine_refresh_log" "$single_machine_summary_json")" == "1" ]]; then
      single_machine_refresh_status="warn"
      single_machine_refresh_non_blocking_transient="true"
      single_machine_refresh_non_blocking_reason="Transient docker registry/network failure during single-machine docker rehearsal; latest usable summary retained."
    fi
  fi
  echo "[roadmap-progress-report] refresh_step=single_machine_prod_readiness status=$single_machine_refresh_status rc=$single_machine_refresh_rc timed_out=$single_machine_refresh_timed_out duration_sec=$single_machine_refresh_duration_sec log=$single_machine_refresh_log"
fi
if [[ "$refresh_single_machine_readiness" != "1" ]]; then
  if [[ "$(single_machine_summary_usable_01 "$single_machine_summary_json")" == "1" ]]; then
    single_machine_summary_valid_after_run="true"
  fi
fi

if [[ "$refresh_manual_validation" == "1" ]]; then
  manual_refresh_status="fail"
  manual_refresh_timed_out="false"
  manual_started_at="$(date +%s)"
  if [[ "$manual_refresh_timeout_sec" -gt 0 ]] && ! command -v timeout >/dev/null 2>&1; then
    echo "[roadmap-progress-report] warn=timeout command not found; running manual-validation refresh without timeout guard"
  fi
  echo "[roadmap-progress-report] refresh_step=manual_validation_report status=running timeout_sec=$manual_refresh_timeout_sec log=$manual_refresh_log"
  set +e
  run_with_optional_timeout "$manual_refresh_timeout_sec" "$manual_validation_report_script" \
    --profile-compare-signoff-summary-json "$profile_compare_signoff_summary_json" \
    --summary-json "$manual_validation_summary_json" \
    --report-md "$manual_validation_report_md" \
    --print-report 0 \
    --print-summary-json 0 >"$manual_refresh_log" 2>&1
  manual_refresh_rc=$?
  set -e
  manual_refresh_duration_sec="$(( $(date +%s) - manual_started_at ))"
  if [[ "$manual_refresh_rc" -eq 124 ]]; then
    manual_refresh_timed_out="true"
  fi
  if [[ "$manual_refresh_rc" -eq 0 ]]; then
    manual_refresh_status="pass"
  fi
  manual_summary_valid_after_run="false"
  if [[ "$(manual_validation_summary_usable_01 "$manual_validation_summary_json")" == "1" ]]; then
    manual_summary_valid_after_run="true"
  fi
  if [[ "$manual_refresh_status" == "pass" && "$manual_summary_valid_after_run" != "true" ]]; then
    manual_refresh_status="fail"
    if [[ "$manual_refresh_rc" -eq 0 ]]; then
      manual_refresh_rc=3
    fi
  fi
  if [[ "$manual_summary_valid_after_run" != "true" && "$manual_summary_snapshot_valid" == "true" ]]; then
    if restore_json_snapshot "$manual_summary_snapshot" "$manual_validation_summary_json"; then
      manual_summary_restored="true"
      manual_summary_valid_after_run="true"
    fi
  fi
  echo "[roadmap-progress-report] refresh_step=manual_validation_report status=$manual_refresh_status rc=$manual_refresh_rc timed_out=$manual_refresh_timed_out duration_sec=$manual_refresh_duration_sec log=$manual_refresh_log"
fi
if [[ "$refresh_manual_validation" != "1" ]]; then
  if [[ "$(manual_validation_summary_usable_01 "$manual_validation_summary_json")" == "1" ]]; then
    manual_summary_valid_after_run="true"
  fi
fi

if [[ ! -f "$manual_validation_summary_json" ]]; then
  echo "manual-validation summary JSON not found: $manual_validation_summary_json"
  exit 1
fi
if [[ "$(manual_validation_summary_usable_01 "$manual_validation_summary_json")" != "1" ]]; then
  echo "manual-validation summary JSON is missing required fields or uses an incompatible schema: $manual_validation_summary_json"
  exit 1
fi

readiness_status="$(jq -r '.report.readiness_status // "UNKNOWN"' "$manual_validation_summary_json")"
roadmap_stage="$(jq -r '.summary.roadmap_stage // "UNKNOWN"' "$manual_validation_summary_json")"
single_machine_ready_json="$(jq -r '.summary.single_machine_ready // false' "$manual_validation_summary_json")"
real_host_gate_ready_json="$(jq -r '.summary.real_host_gate.ready // false' "$manual_validation_summary_json")"
machine_c_smoke_ready_json="$(jq -r '.summary.pre_machine_c_gate.ready // false' "$manual_validation_summary_json")"

next_action_check_id="$(jq -r '.summary.next_action_check_id // ""' "$manual_validation_summary_json")"
next_action_label="$(
  jq -r --arg id "$next_action_check_id" '
    ((.checks // []) | if type == "array" then . else [] end) as $checks
    |
    (.summary.next_action_label // "" | tostring) as $next_label
    | if $next_label != "" then
        $next_label
      elif ($id | length) > 0 then
        ([$checks[] | select((.check_id // "") == $id) | .label][0] // "")
      else
        ""
      end
  ' "$manual_validation_summary_json"
)"
next_action_command="$(
  jq -r --arg id "$next_action_check_id" '
    ((.checks // []) | if type == "array" then . else [] end) as $checks
    |
    (.summary.next_action_command // "" | tostring) as $next_command
    | if $next_command != "" then
        $next_command
      elif ($id | length) > 0 then
        ([$checks[] | select((.check_id // "") == $id) | .command][0] // "")
      else
        ""
      end
  ' "$manual_validation_summary_json"
)"

blocking_check_ids_json="$(jq -c '
  (
    ((.summary.blocking_check_ids // []) | if type == "array" then . else [] end) as $blocking_ids
    | [
        $blocking_ids[] as $id
        | (.checks[]? | select(.check_id == $id) | .status) as $status
        | select(($status // "pending") != "pass" and ($status // "pending") != "skip")
        | $id
      ]
    | unique
  ) as $filtered
  | if ($filtered | length) > 0 then
      $filtered
    else
      [
        .checks[]?
        | select((.status // "") != "pass" and (.status // "") != "skip")
        | .check_id
      ]
      | unique
    end
' "$manual_validation_summary_json")"
optional_check_ids_json="$(jq -c '(.summary.optional_check_ids // []) | if type == "array" then . else [] end' "$manual_validation_summary_json")"
pending_real_host_checks_json="$(jq -c '
  . as $root
  | ((.checks // []) | if type == "array" then . else [] end) as $checks
  | (
      [
        $checks[]
        | select((.check_id == "machine_c_vpn_smoke" or .check_id == "three_machine_prod_signoff") and (.status != "pass" and .status != "skip"))
        | {
            check_id: .check_id,
            label: .label,
            status: .status,
            command: .command,
            notes: .notes
          }
      ]
    ) as $from_checks
  | if ($from_checks | length) > 0 then
      $from_checks
    else
      ((.summary.real_host_gate.blockers // []) | if type == "array" then . else [] end) as $blockers
      | [
          $blockers[]
          | select(. == "machine_c_vpn_smoke" or . == "three_machine_prod_signoff")
          | {
              check_id: .,
              label: (if . == "machine_c_vpn_smoke" then "Machine C VPN smoke test" else "True 3-machine production signoff" end),
              status: "pending",
              command: (
                if . == "machine_c_vpn_smoke" then
                  ($root.summary.real_host_gate.next_command // $root.summary.next_action_command // "")
                else
                  (
                    [ $checks[] | select(.check_id == "three_machine_prod_signoff") | .command ][0]
                    // ""
                  )
                end
              ),
              notes: ""
            }
        ]
    end
' "$manual_validation_summary_json")"
pending_real_host_check_count="$(printf '%s\n' "$pending_real_host_checks_json" | jq -r 'length')"
docker_rehearsal_ready_json="$(
  jq -r '
    (([.checks[]? | select(.check_id == "three_machine_docker_readiness") | (.status // "pending")][0]) // (.summary.docker_rehearsal_gate.status // "pending")) as $status
    | ($status == "pass" or $status == "skip")
  ' "$manual_validation_summary_json"
)"
vpn_rc_done_for_phase="false"
if [[ "$single_machine_ready_json" == "true" && "$docker_rehearsal_ready_json" == "true" && "$pending_real_host_check_count" -gt 0 ]]; then
  vpn_rc_done_for_phase="true"
fi

profile_default_gate_status="$(jq -r '.summary.profile_default_gate.status // "pending"' "$manual_validation_summary_json")"
docker_rehearsal_status="$(jq -r '.summary.docker_rehearsal_gate.status // "pending"' "$manual_validation_summary_json")"
real_wg_privileged_status="$(jq -r '.summary.real_wg_privileged_gate.status // "pending"' "$manual_validation_summary_json")"

counts_total="$(jq -r '.summary.total_checks // 0' "$manual_validation_summary_json")"
counts_pass="$(jq -r '.summary.pass_checks // 0' "$manual_validation_summary_json")"
counts_warn="$(jq -r '.summary.warn_checks // 0' "$manual_validation_summary_json")"
counts_fail="$(jq -r '.summary.fail_checks // 0' "$manual_validation_summary_json")"
counts_pending="$(jq -r '.summary.pending_checks // 0' "$manual_validation_summary_json")"

next_actions_json="$(jq -c --arg next_action_check_id "$next_action_check_id" --arg next_action_label "$next_action_label" --arg next_action_command "$next_action_command" '
  def unique_commands_preserve_order:
    reduce .[] as $item (
      [];
      if ($item.command // "") == "" then
        .
      elif any(.[]; (.command // "") == ($item.command // "")) then
        .
      else
        . + [$item]
      end
    );
  [
    (if ($next_action_command // "") != "" then {
      id: (if ($next_action_check_id // "") != "" then $next_action_check_id else "next_action" end),
      label: (if ($next_action_label // "") != "" then $next_action_label elif ($next_action_check_id // "") != "" then $next_action_check_id else "Next action" end),
      command: $next_action_command,
      reason: "primary roadmap gate"
    } else empty end),
    (if ((.summary.profile_default_gate.status // "pending") != "pass" and (.summary.profile_default_gate.status // "pending") != "skip" and ((.summary.profile_default_gate.next_command // .summary.profile_default_gate.command // "") != "")) then {
      id: "profile_default_gate",
      label: "Profile default decision gate",
      command: (.summary.profile_default_gate.next_command // .summary.profile_default_gate.command // ""),
      reason: "non-blocking profile default decision"
    } else empty end),
    (if ((.summary.docker_rehearsal_gate.status // "pending") != "pass" and (.summary.docker_rehearsal_gate.status // "pending") != "skip" and ((.summary.docker_rehearsal_gate.next_command // .summary.docker_rehearsal_gate.command // "") != "")) then {
      id: "three_machine_docker_readiness",
      label: "One-host docker 3-machine rehearsal",
      command: (.summary.docker_rehearsal_gate.next_command // .summary.docker_rehearsal_gate.command // ""),
      reason: "one-host confidence gate"
    } else empty end),
    (if ((.summary.real_wg_privileged_gate.status // "pending") != "pass" and (.summary.real_wg_privileged_gate.status // "pending") != "skip" and ((.summary.real_wg_privileged_gate.next_command // .summary.real_wg_privileged_gate.command // "") != "")) then {
      id: "real_wg_privileged_matrix",
      label: "Linux root real-WG privileged matrix",
      command: (.summary.real_wg_privileged_gate.next_command // .summary.real_wg_privileged_gate.command // ""),
      reason: "one-host dataplane confidence gate"
    } else empty end)
  ]
  | unique_commands_preserve_order
' "$manual_validation_summary_json")"

blockchain_track_status="deferred"
blockchain_track_policy="VPN-first roadmap"
blockchain_track_recommendation="Keep blockchain off critical VPN dataplane path this week; evaluate Solana sidecar settlement after VPN production signoff."
if [[ ! -f "$product_roadmap_doc" ]]; then
  blockchain_track_policy="roadmap file missing"
fi

final_status="ok"
final_rc=0
notes="Roadmap gates are healthy."
if [[ "$manual_refresh_timed_out" == "true" || "$single_machine_refresh_timed_out" == "true" ]]; then
  final_status="fail"
  final_rc=1
  notes="One or more requested refresh steps timed out; inspect refresh logs."
elif [[ "$manual_refresh_status" == "fail" || "$single_machine_refresh_status" == "fail" ]]; then
  final_status="fail"
  final_rc=1
  notes="One or more requested refresh steps failed; inspect refresh logs."
elif [[ "$manual_refresh_status" == "warn" || "$single_machine_refresh_status" == "warn" ]]; then
  final_status="warn"
  notes="One or more requested refresh steps reported non-blocking transient warnings; latest usable summaries were retained."
elif [[ "$readiness_status" != "READY" ]]; then
  final_status="warn"
  notes="VPN production signoff is still pending external real-host gates."
fi

summary_payload="$(jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --arg notes "$notes" \
  --arg readiness_status "$readiness_status" \
  --arg roadmap_stage "$roadmap_stage" \
  --arg next_action_check_id "$next_action_check_id" \
  --arg next_action_label "$next_action_label" \
  --arg next_action_command "$next_action_command" \
  --argjson single_machine_ready "$single_machine_ready_json" \
  --argjson real_host_gate_ready "$real_host_gate_ready_json" \
  --argjson machine_c_smoke_ready "$machine_c_smoke_ready_json" \
  --argjson vpn_rc_done_for_phase "$vpn_rc_done_for_phase" \
  --arg profile_default_gate_status "$profile_default_gate_status" \
  --arg docker_rehearsal_status "$docker_rehearsal_status" \
  --arg real_wg_privileged_status "$real_wg_privileged_status" \
  --argjson total_checks "$counts_total" \
  --argjson pass_checks "$counts_pass" \
  --argjson warn_checks "$counts_warn" \
  --argjson fail_checks "$counts_fail" \
  --argjson pending_checks "$counts_pending" \
  --argjson blocking_check_ids "$blocking_check_ids_json" \
  --argjson optional_check_ids "$optional_check_ids_json" \
  --argjson pending_real_host_checks "$pending_real_host_checks_json" \
  --argjson next_actions "$next_actions_json" \
  --arg blockchain_track_status "$blockchain_track_status" \
  --arg blockchain_track_policy "$blockchain_track_policy" \
  --arg blockchain_track_recommendation "$blockchain_track_recommendation" \
  --arg refresh_manual_validation_status "$manual_refresh_status" \
  --argjson refresh_manual_validation_rc "$manual_refresh_rc" \
  --argjson refresh_manual_validation_timed_out "$manual_refresh_timed_out" \
  --argjson refresh_manual_validation_timeout_sec "$manual_refresh_timeout_sec" \
  --argjson refresh_manual_validation_duration_sec "$manual_refresh_duration_sec" \
  --arg refresh_manual_validation_log "$manual_refresh_log" \
  --argjson refresh_manual_validation_summary_valid_after_run "$manual_summary_valid_after_run" \
  --argjson refresh_manual_validation_summary_restored_from_snapshot "$manual_summary_restored" \
  --arg refresh_single_machine_status "$single_machine_refresh_status" \
  --argjson refresh_single_machine_rc "$single_machine_refresh_rc" \
  --argjson refresh_single_machine_timed_out "$single_machine_refresh_timed_out" \
  --argjson refresh_single_machine_timeout_sec "$single_machine_refresh_timeout_sec" \
  --argjson refresh_single_machine_duration_sec "$single_machine_refresh_duration_sec" \
  --arg refresh_single_machine_log "$single_machine_refresh_log" \
  --argjson refresh_single_machine_summary_valid_after_run "$single_machine_summary_valid_after_run" \
  --argjson refresh_single_machine_summary_restored_from_snapshot "$single_machine_summary_restored" \
  --argjson refresh_single_machine_non_blocking_transient "$single_machine_refresh_non_blocking_transient" \
  --arg refresh_single_machine_non_blocking_reason "$single_machine_refresh_non_blocking_reason" \
  --arg manual_validation_summary_json "$manual_validation_summary_json" \
  --arg manual_validation_report_md "$manual_validation_report_md" \
  --arg single_machine_summary_json "$single_machine_summary_json" \
  --arg summary_json_path "$summary_json" \
  --arg report_md_path "$report_md" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: (if $status == "fail" then 1 else 0 end),
    notes: $notes,
    vpn_track: {
      readiness_status: $readiness_status,
      roadmap_stage: $roadmap_stage,
      single_machine_ready: $single_machine_ready,
      machine_c_smoke_ready: $machine_c_smoke_ready,
      real_host_gate_ready: $real_host_gate_ready,
      vpn_rc_done_for_phase: $vpn_rc_done_for_phase,
      counts: {
        total_checks: $total_checks,
        pass_checks: $pass_checks,
        warn_checks: $warn_checks,
        fail_checks: $fail_checks,
        pending_checks: $pending_checks
      },
      blocking_check_ids: $blocking_check_ids,
      optional_check_ids: $optional_check_ids,
      pending_real_host_checks: $pending_real_host_checks,
      next_action: {
        check_id: $next_action_check_id,
        label: $next_action_label,
        command: $next_action_command
      },
      optional_gate_status: {
        profile_default_gate: $profile_default_gate_status,
        docker_rehearsal_gate: $docker_rehearsal_status,
        real_wg_privileged_gate: $real_wg_privileged_status
      }
    },
    blockchain_track: {
      status: $blockchain_track_status,
      policy: $blockchain_track_policy,
      recommendation: $blockchain_track_recommendation
    },
    refresh: {
      manual_validation_report: {
        enabled: ($refresh_manual_validation_status != "skip"),
        status: $refresh_manual_validation_status,
        rc: $refresh_manual_validation_rc,
        timed_out: $refresh_manual_validation_timed_out,
        timeout_sec: $refresh_manual_validation_timeout_sec,
        duration_sec: $refresh_manual_validation_duration_sec,
        log: $refresh_manual_validation_log,
        summary_valid_after_run: $refresh_manual_validation_summary_valid_after_run,
        summary_restored_from_snapshot: $refresh_manual_validation_summary_restored_from_snapshot
      },
      single_machine_prod_readiness: {
        enabled: ($refresh_single_machine_status != "skip"),
        status: $refresh_single_machine_status,
        rc: $refresh_single_machine_rc,
        timed_out: $refresh_single_machine_timed_out,
        timeout_sec: $refresh_single_machine_timeout_sec,
        duration_sec: $refresh_single_machine_duration_sec,
        log: $refresh_single_machine_log,
        summary_valid_after_run: $refresh_single_machine_summary_valid_after_run,
        summary_restored_from_snapshot: $refresh_single_machine_summary_restored_from_snapshot,
        non_blocking_transient: $refresh_single_machine_non_blocking_transient,
        non_blocking_reason: $refresh_single_machine_non_blocking_reason
      }
    },
    next_actions: $next_actions,
    artifacts: {
      manual_validation_summary_json: $manual_validation_summary_json,
      manual_validation_report_md: $manual_validation_report_md,
      single_machine_summary_json: $single_machine_summary_json,
      summary_json: $summary_json_path,
      report_md: $report_md_path
    }
  }')"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
printf '%s\n' "$summary_payload" >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

next_actions_md="$(printf '%s\n' "$next_actions_json" | jq -r 'if length == 0 then "- none" else .[] | "- `\(.id)`: `\(.command)` (\(.reason))" end')"
pending_real_host_checks_md="$(printf '%s\n' "$pending_real_host_checks_json" | jq -r '
  if length == 0 then
    "- none"
  else
    .[]
    | "- `\(.check_id)`: `\(.status // "")` - \(.label // "") - command: `\(.command // "")`"
      + (if (.notes // "") != "" then " - notes: \(.notes)" else "" end)
  end
')"

report_tmp="$(mktemp "${report_md}.tmp.XXXXXX")"
cat >"$report_tmp" <<EOF_MD
# Roadmap Progress Report

- Generated at (UTC): $(jq -r '.generated_at_utc' "$summary_json")
- Status: $(jq -r '.status' "$summary_json")
- Notes: $(jq -r '.notes' "$summary_json")

## VPN Track

- Readiness: $(jq -r '.vpn_track.readiness_status' "$summary_json")
- Roadmap stage: $(jq -r '.vpn_track.roadmap_stage' "$summary_json")
- Single-machine ready: $(jq -r '.vpn_track.single_machine_ready' "$summary_json")
- Machine-C smoke ready: $(jq -r '.vpn_track.machine_c_smoke_ready' "$summary_json")
- Real-host gate ready: $(jq -r '.vpn_track.real_host_gate_ready' "$summary_json")
- VPN RC done for phase: \`$(jq -r '.vpn_track.vpn_rc_done_for_phase' "$summary_json")\`
- Checks: total=$(jq -r '.vpn_track.counts.total_checks' "$summary_json"), pass=$(jq -r '.vpn_track.counts.pass_checks' "$summary_json"), warn=$(jq -r '.vpn_track.counts.warn_checks' "$summary_json"), fail=$(jq -r '.vpn_track.counts.fail_checks' "$summary_json"), pending=$(jq -r '.vpn_track.counts.pending_checks' "$summary_json")
- Blocking checks: $(jq -r '(.vpn_track.blocking_check_ids // []) | if length == 0 then "none" else join(",") end' "$summary_json")
- Pending real-host checks: $(jq -r '(.vpn_track.pending_real_host_checks // []) | if length == 0 then "none" else map(.check_id) | join(",") end' "$summary_json")
- Optional gate status: profile=$(jq -r '.vpn_track.optional_gate_status.profile_default_gate' "$summary_json"), docker-rehearsal=$(jq -r '.vpn_track.optional_gate_status.docker_rehearsal_gate' "$summary_json"), real-wg=$(jq -r '.vpn_track.optional_gate_status.real_wg_privileged_gate' "$summary_json")
- Primary next action: $(jq -r '.vpn_track.next_action.command // ""' "$summary_json")

## Pending Real-Host Checks

$pending_real_host_checks_md

## Blockchain Track

- Status: $(jq -r '.blockchain_track.status' "$summary_json")
- Policy: $(jq -r '.blockchain_track.policy' "$summary_json")
- Recommendation: $(jq -r '.blockchain_track.recommendation' "$summary_json")

## Next Actions

$next_actions_md

## Refresh Steps

- Manual validation refresh: $(jq -r '.refresh.manual_validation_report.status' "$summary_json") (rc=$(jq -r '.refresh.manual_validation_report.rc' "$summary_json"))
- Manual validation refresh timeout: $(jq -r '.refresh.manual_validation_report.timed_out' "$summary_json") (limit=$(jq -r '.refresh.manual_validation_report.timeout_sec' "$summary_json")s, duration=$(jq -r '.refresh.manual_validation_report.duration_sec' "$summary_json")s)
- Single-machine refresh: $(jq -r '.refresh.single_machine_prod_readiness.status' "$summary_json") (rc=$(jq -r '.refresh.single_machine_prod_readiness.rc' "$summary_json"))
- Single-machine refresh timeout: $(jq -r '.refresh.single_machine_prod_readiness.timed_out' "$summary_json") (limit=$(jq -r '.refresh.single_machine_prod_readiness.timeout_sec' "$summary_json")s, duration=$(jq -r '.refresh.single_machine_prod_readiness.duration_sec' "$summary_json")s)
- Single-machine refresh non-blocking transient: $(jq -r '.refresh.single_machine_prod_readiness.non_blocking_transient' "$summary_json")
- Single-machine refresh warning reason: $(jq -r '.refresh.single_machine_prod_readiness.non_blocking_reason // ""' "$summary_json")

## Artifacts

- Summary JSON: $(jq -r '.artifacts.summary_json' "$summary_json")
- Report Markdown: $(jq -r '.artifacts.report_md' "$summary_json")
- Manual validation summary: $(jq -r '.artifacts.manual_validation_summary_json' "$summary_json")
- Manual validation report: $(jq -r '.artifacts.manual_validation_report_md' "$summary_json")
- Single-machine summary: $(jq -r '.artifacts.single_machine_summary_json' "$summary_json")
EOF_MD
mv -f "$report_tmp" "$report_md"

echo "[roadmap-progress-report] status=$final_status rc=$final_rc"
echo "[roadmap-progress-report] readiness_status=$readiness_status"
echo "[roadmap-progress-report] roadmap_stage=$roadmap_stage"
echo "[roadmap-progress-report] next_action_check_id=${next_action_check_id:-}"
echo "[roadmap-progress-report] next_action_command=${next_action_command:-}"
echo "[roadmap-progress-report] manual_validation_refresh_status=$manual_refresh_status rc=$manual_refresh_rc"
echo "[roadmap-progress-report] single_machine_refresh_status=$single_machine_refresh_status rc=$single_machine_refresh_rc"
echo "[roadmap-progress-report] single_machine_refresh_non_blocking_transient=$single_machine_refresh_non_blocking_transient reason=$single_machine_refresh_non_blocking_reason"
echo "[roadmap-progress-report] manual_validation_summary_valid_after_run=$manual_summary_valid_after_run restored_from_snapshot=$manual_summary_restored"
echo "[roadmap-progress-report] single_machine_summary_valid_after_run=$single_machine_summary_valid_after_run restored_from_snapshot=$single_machine_summary_restored"
echo "[roadmap-progress-report] summary_json=$summary_json"
echo "[roadmap-progress-report] report_md=$report_md"

if [[ "$print_report" == "1" ]]; then
  echo "[roadmap-progress-report] report_markdown:"
  cat "$report_md"
fi
if [[ "$print_summary_json" == "1" ]]; then
  echo "[roadmap-progress-report] summary_json_payload:"
  cat "$summary_json"
fi

if [[ -n "$manual_summary_snapshot" ]]; then
  rm -f "$manual_summary_snapshot" 2>/dev/null || true
fi
if [[ -n "$single_machine_summary_snapshot" ]]; then
  rm -f "$single_machine_summary_snapshot" 2>/dev/null || true
fi

exit "$final_rc"
