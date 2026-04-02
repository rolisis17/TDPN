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

for cmd in jq date mktemp; do
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
  echo "[roadmap-progress-report] refresh_step=single_machine_prod_readiness status=$single_machine_refresh_status rc=$single_machine_refresh_rc timed_out=$single_machine_refresh_timed_out duration_sec=$single_machine_refresh_duration_sec log=$single_machine_refresh_log"
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
  echo "[roadmap-progress-report] refresh_step=manual_validation_report status=$manual_refresh_status rc=$manual_refresh_rc timed_out=$manual_refresh_timed_out duration_sec=$manual_refresh_duration_sec log=$manual_refresh_log"
fi

if [[ ! -f "$manual_validation_summary_json" ]]; then
  echo "manual-validation summary JSON not found: $manual_validation_summary_json"
  exit 1
fi
if ! jq -e . "$manual_validation_summary_json" >/dev/null 2>&1; then
  echo "manual-validation summary JSON is invalid: $manual_validation_summary_json"
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
  [
    .checks[]?
    | select((.check_id == "machine_c_vpn_smoke" or .check_id == "three_machine_prod_signoff") and (.status != "pass" and .status != "skip"))
    | {
        check_id: .check_id,
        label: .label,
        status: .status,
        command: .command,
        notes: .notes
      }
  ]
' "$manual_validation_summary_json")"
pending_real_host_check_count="$(printf '%s\n' "$pending_real_host_checks_json" | jq -r 'length')"
docker_rehearsal_ready_json="$(jq -r '([.checks[]? | select(.check_id == "three_machine_docker_readiness") | (.status // "pending")][0] // "pending") == "pass"' "$manual_validation_summary_json")"
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
  [
    (if ($next_action_command // "") != "" then {
      id: (if ($next_action_check_id // "") != "" then $next_action_check_id else "next_action" end),
      label: (if ($next_action_label // "") != "" then $next_action_label elif ($next_action_check_id // "") != "" then $next_action_check_id else "Next action" end),
      command: $next_action_command,
      reason: "primary roadmap gate"
    } else empty end),
    (if ((.summary.profile_default_gate.status // "pending") != "pass" and ((.summary.profile_default_gate.next_command // .summary.profile_default_gate.command // "") != "")) then {
      id: "profile_default_gate",
      label: "Profile default decision gate",
      command: (.summary.profile_default_gate.next_command // .summary.profile_default_gate.command // ""),
      reason: "non-blocking profile default decision"
    } else empty end),
    (if ((.summary.docker_rehearsal_gate.status // "pending") != "pass" and ((.summary.docker_rehearsal_gate.next_command // .summary.docker_rehearsal_gate.command // "") != "")) then {
      id: "three_machine_docker_readiness",
      label: "One-host docker 3-machine rehearsal",
      command: (.summary.docker_rehearsal_gate.next_command // .summary.docker_rehearsal_gate.command // ""),
      reason: "one-host confidence gate"
    } else empty end),
    (if ((.summary.real_wg_privileged_gate.status // "pending") != "pass" and ((.summary.real_wg_privileged_gate.next_command // .summary.real_wg_privileged_gate.command // "") != "")) then {
      id: "real_wg_privileged_matrix",
      label: "Linux root real-WG privileged matrix",
      command: (.summary.real_wg_privileged_gate.next_command // .summary.real_wg_privileged_gate.command // ""),
      reason: "one-host dataplane confidence gate"
    } else empty end)
  ]
  | unique_by(.command)
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
  --arg refresh_single_machine_status "$single_machine_refresh_status" \
  --argjson refresh_single_machine_rc "$single_machine_refresh_rc" \
  --argjson refresh_single_machine_timed_out "$single_machine_refresh_timed_out" \
  --argjson refresh_single_machine_timeout_sec "$single_machine_refresh_timeout_sec" \
  --argjson refresh_single_machine_duration_sec "$single_machine_refresh_duration_sec" \
  --arg refresh_single_machine_log "$single_machine_refresh_log" \
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
        log: $refresh_manual_validation_log
      },
      single_machine_prod_readiness: {
        enabled: ($refresh_single_machine_status != "skip"),
        status: $refresh_single_machine_status,
        rc: $refresh_single_machine_rc,
        timed_out: $refresh_single_machine_timed_out,
        timeout_sec: $refresh_single_machine_timeout_sec,
        duration_sec: $refresh_single_machine_duration_sec,
        log: $refresh_single_machine_log
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

exit "$final_rc"
