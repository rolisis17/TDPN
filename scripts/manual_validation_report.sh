#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/manual_validation_report.sh \
    [--base-port N] \
    [--client-iface IFACE] \
    [--exit-iface IFACE] \
    [--vpn-iface IFACE] \
    [--status-timeout-sec N] \
    [--profile-compare-signoff-summary-json PATH] \
    [--overlay-check-id CHECK_ID] \
    [--overlay-status pass|fail|warn|pending|skip] \
    [--overlay-notes TEXT] \
    [--overlay-command TEXT] \
    [--overlay-artifact PATH]... \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-report [0|1]] \
    [--print-summary-json [0|1]] \
    [--fail-on-not-ready [0|1]]

Purpose:
  Build one shareable readiness report from manual-validation-status.

Outputs:
  1) machine-readable summary JSON
  2) concise markdown readiness report
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
    return
  fi
  if [[ "$path" == /* ]]; then
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

run_with_optional_timeout() {
  local timeout_sec="$1"
  shift
  if [[ "$timeout_sec" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    timeout "${timeout_sec}s" "$@"
  else
    "$@"
  fi
}

extract_json_payload() {
  local log_file="$1"
  awk '/^\[manual-validation-status\] summary_json_payload:/{flag=1; next} flag{print}' "$log_file"
}

md_escape() {
  local value="$1"
  value="${value//|/\\|}"
  value="${value//$'\n'/ }"
  printf '%s' "$value"
}

base_port="${EASY_NODE_DOCTOR_WG_ONLY_BASE_PORT:-19280}"
client_iface="${EASY_NODE_DOCTOR_CLIENT_IFACE:-wgcstack0}"
exit_iface="${EASY_NODE_DOCTOR_EXIT_IFACE:-wgestack0}"
vpn_iface="${EASY_NODE_DOCTOR_VPN_IFACE:-wgvpn0}"
status_timeout_sec="${MANUAL_VALIDATION_REPORT_STATUS_TIMEOUT_SEC:-180}"
profile_compare_signoff_summary_json="${MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON:-}"
overlay_check_id=""
overlay_status=""
overlay_notes=""
overlay_command=""
declare -a overlay_artifacts=()
summary_json=""
report_md=""
print_report="${MANUAL_VALIDATION_REPORT_PRINT_REPORT:-1}"
print_summary_json="${MANUAL_VALIDATION_REPORT_PRINT_SUMMARY_JSON:-0}"
fail_on_not_ready="${MANUAL_VALIDATION_REPORT_FAIL_ON_NOT_READY:-0}"

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
    --status-timeout-sec)
      status_timeout_sec="${2:-}"
      shift 2
      ;;
    --profile-compare-signoff-summary-json)
      profile_compare_signoff_summary_json="${2:-}"
      shift 2
      ;;
    --overlay-check-id)
      overlay_check_id="${2:-}"
      shift 2
      ;;
    --overlay-status)
      overlay_status="${2:-}"
      shift 2
      ;;
    --overlay-notes)
      overlay_notes="${2:-}"
      shift 2
      ;;
    --overlay-command)
      overlay_command="${2:-}"
      shift 2
      ;;
    --overlay-artifact)
      overlay_artifacts+=("$(abs_path "${2:-}")")
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
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
    --fail-on-not-ready)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_not_ready="${2:-}"
        shift 2
      else
        fail_on_not_ready="1"
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

for cmd in jq date awk mktemp; do
  need_cmd "$cmd"
done

bool_arg_or_die "--print-report" "$print_report"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--fail-on-not-ready" "$fail_on_not_ready"
if ! [[ "$status_timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "--status-timeout-sec must be an integer >= 0"
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
if [[ -n "$profile_compare_signoff_summary_json" ]]; then
  profile_compare_signoff_summary_json="$(abs_path "$profile_compare_signoff_summary_json")"
fi

status_script="${MANUAL_VALIDATION_STATUS_SCRIPT:-$ROOT_DIR/scripts/manual_validation_status.sh}"
if [[ ! -x "$status_script" ]]; then
  echo "missing manual validation status script: $status_script"
  exit 2
fi

summary_json="$(abs_path "${summary_json:-$ROOT_DIR/.easy-node-logs/manual_validation_readiness_summary.json}")"
report_md="$(abs_path "${report_md:-$ROOT_DIR/.easy-node-logs/manual_validation_readiness_report.md}")"
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

status_log="$(mktemp)"
status_rc=0
status_timed_out="false"
status_timeout_guard_available="false"
status_payload_synthesized="false"
if command -v timeout >/dev/null 2>&1; then
  status_timeout_guard_available="true"
fi
if [[ "$status_timeout_sec" -gt 0 && "$status_timeout_guard_available" != "true" ]]; then
  echo "[manual-validation-report] warn=timeout command not found; running manual-validation-status without timeout guard"
fi
declare -a status_cmd=(
  "$status_script"
  --base-port "$base_port"
  --client-iface "$client_iface"
  --exit-iface "$exit_iface"
  --vpn-iface "$vpn_iface"
  --show-json 1
)
if [[ -n "$profile_compare_signoff_summary_json" ]]; then
  status_cmd+=(--profile-compare-signoff-summary-json "$profile_compare_signoff_summary_json")
fi
if [[ -n "$overlay_check_id" ]]; then
  status_cmd+=(--overlay-check-id "$overlay_check_id" --overlay-status "$overlay_status")
  if [[ -n "$overlay_notes" ]]; then
    status_cmd+=(--overlay-notes "$overlay_notes")
  fi
  if [[ -n "$overlay_command" ]]; then
    status_cmd+=(--overlay-command "$overlay_command")
  fi
  overlay_artifact=""
  for overlay_artifact in "${overlay_artifacts[@]}"; do
    status_cmd+=(--overlay-artifact "$overlay_artifact")
  done
fi
if run_with_optional_timeout "$status_timeout_sec" "${status_cmd[@]}" >"$status_log" 2>&1; then
  status_rc=0
else
  status_rc=$?
fi
if [[ "$status_rc" -eq 124 ]]; then
  status_timed_out="true"
fi
status_json_payload="$(extract_json_payload "$status_log")"
if [[ -z "$status_json_payload" ]]; then
  if [[ "$status_timed_out" == "true" ]]; then
    status_json_payload="$(
      jq -n \
        --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson timeout_sec "$status_timeout_sec" \
        --arg profile_summary_json "${profile_compare_signoff_summary_json:-$ROOT_DIR/.easy-node-logs/profile_compare_campaign_signoff_summary.json}" \
        '{
          version: 1,
          generated_at_utc: $generated_at_utc,
          state_dir: "",
          status_json: "",
          runtime_doctor_exit_code: 1,
          runtime_doctor: {
            version: 1,
            generated_at_utc: $generated_at_utc,
            status: "FAIL",
            summary: { findings_total: 1, warnings_total: 0, failures_total: 1 },
            findings: [
              {
                severity: "FAIL",
                code: "manual_validation_status_timeout",
                message: ("manual-validation-status timed out after " + ($timeout_sec | tostring) + "s"),
                remediation: "rerun ./scripts/manual_validation_report.sh after resolving host load/lock contention"
              }
            ]
          },
          checks: [],
          summary: {
            total_checks: 0,
            pass_checks: 0,
            warn_checks: 0,
            fail_checks: 1,
            pending_checks: 0,
            next_action_check_id: "manual_validation_status_timeout",
            next_action_label: "Manual validation status timeout",
            next_action_command: "sudo ./scripts/easy_node.sh manual-validation-status --show-json 1",
            next_action_remediations: ["rerun ./scripts/manual_validation_report.sh after resolving host load/lock contention"],
            pre_machine_c_gate: {
              ready: false,
              blockers: ["manual_validation_status_timeout"],
              next_check_id: "machine_c_vpn_smoke",
              next_label: "Machine C VPN smoke test",
              next_command: "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
            },
            local_gate: {
              ready: false,
              check_ids: [],
              blockers: ["manual_validation_status_timeout"],
              next_check_id: "manual_validation_status_timeout"
            },
            real_host_gate: {
              ready: false,
              check_ids: ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
              blockers: ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
              next_check_id: "machine_c_vpn_smoke",
              next_label: "Machine C VPN smoke test",
              next_command: "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
            },
            profile_default_gate: {
              enabled: true,
              summary_json: $profile_summary_json,
              available: false,
              valid_json: false,
              status: "pending",
              notes: "profile compare campaign signoff status unavailable due manual-validation-status timeout",
              decision: "",
              recommended_profile: "",
              trend_source: "",
              final_rc: 0,
              failure_stage: "",
              non_root_refresh_blocked: false,
              stale_non_refreshed: false,
              refresh_campaign: false,
              next_command: "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
              artifacts: {
                campaign_summary_json: "",
                campaign_report_md: "",
                campaign_check_summary_json: ""
              }
            },
            profile_default_ready: false,
            docker_rehearsal_gate: {
              check_id: "three_machine_docker_readiness",
              status: "pending",
              notes: "status unavailable due manual-validation-status timeout",
              command: "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1",
              next_command: "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1",
              ready: false
            },
            real_wg_privileged_gate: {
              check_id: "real_wg_privileged_matrix",
              status: "pending",
              notes: "status unavailable due manual-validation-status timeout",
              command: "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1",
              next_command: "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1",
              ready: false
            },
            single_machine_ready: false,
            roadmap_stage: "BLOCKED_LOCAL",
            latest_failed_incident: null
          }
        }'
    )"
    status_payload_synthesized="true"
  else
    echo "manual-validation-report failed: manual-validation-status did not emit JSON summary"
    cat "$status_log"
    rm -f "$status_log"
    exit 1
  fi
fi
if ! printf '%s\n' "$status_json_payload" | jq -e . >/dev/null 2>&1; then
  if [[ "$status_timed_out" == "true" ]]; then
    status_json_payload="$(
      jq -n \
        --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson timeout_sec "$status_timeout_sec" \
        '{
          version: 1,
          generated_at_utc: $generated_at_utc,
          runtime_doctor: {
            status: "FAIL",
            summary: { findings_total: 1, warnings_total: 0, failures_total: 1 },
            findings: [
              {
                severity: "FAIL",
                code: "manual_validation_status_timeout_invalid_json",
                message: ("manual-validation-status timed out after " + ($timeout_sec | tostring) + "s and emitted invalid JSON payload"),
                remediation: "rerun ./scripts/manual_validation_report.sh after resolving host load/lock contention"
              }
            ]
          },
          checks: [],
          summary: {
            total_checks: 0,
            pass_checks: 0,
            warn_checks: 0,
            fail_checks: 1,
            pending_checks: 0,
            next_action_check_id: "manual_validation_status_timeout_invalid_json",
            next_action_label: "Manual validation status timeout (invalid payload)",
            next_action_command: "sudo ./scripts/easy_node.sh manual-validation-status --show-json 1",
            next_action_remediations: ["rerun ./scripts/manual_validation_report.sh after resolving host load/lock contention"],
            pre_machine_c_gate: { ready: false, blockers: ["manual_validation_status_timeout_invalid_json"], next_check_id: "machine_c_vpn_smoke", next_label: "Machine C VPN smoke test", next_command: "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country" },
            local_gate: { ready: false, check_ids: [], blockers: ["manual_validation_status_timeout_invalid_json"], next_check_id: "manual_validation_status_timeout_invalid_json" },
            real_host_gate: { ready: false, check_ids: ["machine_c_vpn_smoke", "three_machine_prod_signoff"], blockers: ["machine_c_vpn_smoke", "three_machine_prod_signoff"], next_check_id: "machine_c_vpn_smoke", next_label: "Machine C VPN smoke test", next_command: "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country" },
            profile_default_gate: { enabled: true, available: false, valid_json: false, status: "pending", notes: "profile compare campaign signoff status unavailable due manual-validation-status timeout", next_command: "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1" },
            profile_default_ready: false,
            docker_rehearsal_gate: { check_id: "three_machine_docker_readiness", status: "pending", notes: "status unavailable due manual-validation-status timeout", command: "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1", next_command: "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1", ready: false },
            real_wg_privileged_gate: { check_id: "real_wg_privileged_matrix", status: "pending", notes: "status unavailable due manual-validation-status timeout", command: "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1", next_command: "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1", ready: false },
            single_machine_ready: false,
            roadmap_stage: "BLOCKED_LOCAL",
            latest_failed_incident: null
          }
        }'
    )"
    status_payload_synthesized="true"
  else
    echo "manual-validation-report failed: manual-validation-status emitted invalid JSON summary"
    cat "$status_log"
    rm -f "$status_log"
    exit 1
  fi
fi
rm -f "$status_log"

ready_json="false"
readiness_status="NOT_READY"
if printf '%s\n' "$status_json_payload" | jq -e '(.summary.next_action_check_id // "") == ""' >/dev/null 2>&1; then
  ready_json="true"
  readiness_status="READY"
fi

report_json="$(
  printf '%s\n' "$status_json_payload" | jq \
    --arg summary_json "$summary_json" \
    --arg report_md "$report_md" \
    --arg readiness_status "$readiness_status" \
    --argjson ready "$ready_json" \
    --argjson source_status_exit_code "$status_rc" \
    --argjson source_status_timed_out "$status_timed_out" \
    --argjson source_status_timeout_sec "$status_timeout_sec" \
    --argjson source_status_timeout_guard_available "$status_timeout_guard_available" \
    --argjson source_status_payload_synthesized "$status_payload_synthesized" \
    '.schema = {
      id: "manual_validation_readiness_summary",
      major: 1,
      minor: 0
    }
    | .report = {
      readiness_status: $readiness_status,
      ready: $ready,
      summary_json: $summary_json,
      report_md: $report_md,
      source_status_exit_code: $source_status_exit_code,
      source_status_timed_out: $source_status_timed_out,
      source_status_timeout_sec: $source_status_timeout_sec,
      source_status_timeout_guard_available: $source_status_timeout_guard_available,
      source_status_payload_synthesized: $source_status_payload_synthesized
    }'
)"
summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
printf '%s\n' "$report_json" >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

summary_total="$(printf '%s\n' "$report_json" | jq -r '.summary.total_checks // 0')"
summary_pass="$(printf '%s\n' "$report_json" | jq -r '.summary.pass_checks // 0')"
summary_warn="$(printf '%s\n' "$report_json" | jq -r '.summary.warn_checks // 0')"
summary_fail="$(printf '%s\n' "$report_json" | jq -r '.summary.fail_checks // 0')"
summary_pending="$(printf '%s\n' "$report_json" | jq -r '.summary.pending_checks // 0')"
next_action_check_id="$(printf '%s\n' "$report_json" | jq -r '.summary.next_action_check_id // ""')"
next_action_label="$(printf '%s\n' "$report_json" | jq -r '.summary.next_action_label // ""')"
next_action_command="$(printf '%s\n' "$report_json" | jq -r '.summary.next_action_command // ""')"
next_action_remediations_json="$(printf '%s\n' "$report_json" | jq -c '.summary.next_action_remediations // []')"
next_action_remediations_csv="$(printf '%s\n' "$next_action_remediations_json" | jq -r 'if length == 0 then "" else join(" || ") end')"
machine_c_smoke_ready="$(printf '%s\n' "$report_json" | jq -r '.summary.pre_machine_c_gate.ready // false')"
machine_c_smoke_blockers="$(printf '%s\n' "$report_json" | jq -r '(.summary.pre_machine_c_gate.blockers // []) | if length == 0 then "none" else join(",") end')"
machine_c_smoke_next_command="$(printf '%s\n' "$report_json" | jq -r '.summary.pre_machine_c_gate.next_command // ""')"
single_machine_ready="$(printf '%s\n' "$report_json" | jq -r '.summary.single_machine_ready // false')"
roadmap_stage="$(printf '%s\n' "$report_json" | jq -r '.summary.roadmap_stage // ""')"
real_host_gate_ready="$(printf '%s\n' "$report_json" | jq -r '.summary.real_host_gate.ready // false')"
real_host_gate_blockers="$(printf '%s\n' "$report_json" | jq -r '(.summary.real_host_gate.blockers // []) | if length == 0 then "none" else join(",") end')"
real_host_gate_next_command="$(printf '%s\n' "$report_json" | jq -r '.summary.real_host_gate.next_command // ""')"
profile_default_gate_status="$(printf '%s\n' "$report_json" | jq -r '.summary.profile_default_gate.status // ""')"
profile_default_gate_available="$(printf '%s\n' "$report_json" | jq -r '.summary.profile_default_gate.available // false')"
profile_default_gate_decision="$(printf '%s\n' "$report_json" | jq -r '.summary.profile_default_gate.decision // ""')"
profile_default_gate_recommended_profile="$(printf '%s\n' "$report_json" | jq -r '.summary.profile_default_gate.recommended_profile // ""')"
profile_default_gate_summary_json="$(printf '%s\n' "$report_json" | jq -r '.summary.profile_default_gate.summary_json // ""')"
profile_default_gate_next_command="$(printf '%s\n' "$report_json" | jq -r '.summary.profile_default_gate.next_command // ""')"
profile_default_gate_notes="$(printf '%s\n' "$report_json" | jq -r '.summary.profile_default_gate.notes // ""')"
docker_rehearsal_status="$(printf '%s\n' "$report_json" | jq -r '.summary.docker_rehearsal_gate.status // ""')"
docker_rehearsal_ready="$(printf '%s\n' "$report_json" | jq -r '.summary.docker_rehearsal_gate.ready // false')"
docker_rehearsal_command="$(printf '%s\n' "$report_json" | jq -r '.summary.docker_rehearsal_gate.command // ""')"
docker_rehearsal_notes="$(printf '%s\n' "$report_json" | jq -r '.summary.docker_rehearsal_gate.notes // ""')"
real_wg_privileged_status="$(printf '%s\n' "$report_json" | jq -r '.summary.real_wg_privileged_gate.status // ""')"
real_wg_privileged_ready="$(printf '%s\n' "$report_json" | jq -r '.summary.real_wg_privileged_gate.ready // false')"
real_wg_privileged_command="$(printf '%s\n' "$report_json" | jq -r '.summary.real_wg_privileged_gate.command // ""')"
real_wg_privileged_notes="$(printf '%s\n' "$report_json" | jq -r '.summary.real_wg_privileged_gate.notes // ""')"
latest_failed_incident_check_id="$(printf '%s\n' "$report_json" | jq -r '.summary.latest_failed_incident.check_id // ""')"
latest_failed_incident_summary_json="$(printf '%s\n' "$report_json" | jq -r '.summary.latest_failed_incident.summary_json.path // ""')"
latest_failed_incident_report_md="$(printf '%s\n' "$report_json" | jq -r '.summary.latest_failed_incident.report_md.path // ""')"
latest_failed_incident_bundle_dir="$(printf '%s\n' "$report_json" | jq -r '.summary.latest_failed_incident.bundle_dir.path // ""')"
latest_failed_incident_attachment_manifest="$(printf '%s\n' "$report_json" | jq -r '.summary.latest_failed_incident.attachment_manifest.path // ""')"
latest_failed_incident_attachment_count="$(printf '%s\n' "$report_json" | jq -r '.summary.latest_failed_incident.attachment_count // 0')"
latest_failed_incident_readiness_report_summary_attachment="$(printf '%s\n' "$report_json" | jq -r '.summary.latest_failed_incident.readiness_report_summary_attachment.bundle_path // ""')"
latest_failed_incident_readiness_report_md_attachment="$(printf '%s\n' "$report_json" | jq -r '.summary.latest_failed_incident.readiness_report_md_attachment.bundle_path // ""')"
latest_failed_incident_readiness_report_log_attachment="$(printf '%s\n' "$report_json" | jq -r '.summary.latest_failed_incident.readiness_report_log_attachment.bundle_path // ""')"

runtime_findings_md="$(printf '%s\n' "$report_json" | jq -r '
  if (.runtime_doctor.findings // [] | length) == 0 then
    "- None"
  else
    (.runtime_doctor.findings // [])
    | map("- [\(.severity // "INFO")] `\(.code // "unknown")`: \(.message // "")" +
          (if (.remediation // "") | length > 0 then " | remediation: `\(.remediation)`" else "" end))
    | join("\n")
  end
')"

checks_table_md="$(printf '%s\n' "$report_json" | jq -r '
  ["| Check | Status | Recorded At | Notes |", "|---|---|---|---|"] +
  [(.checks[]
    | "| \(.label | gsub("\\|"; "\\\\|")) (`\(.check_id)`) | \(.status | ascii_upcase) | \((.recorded_at_utc // "") | gsub("\\|"; "\\\\|")) | \((.notes // "") | gsub("\\|"; "\\\\|") | gsub("\\n"; " ")) |")]
  | join("\n")
')"

incident_checks_md="$(printf '%s\n' "$report_json" | jq -r '
  [
    .checks[]
    | select(.incident_handoff.available == true)
    | "- `\(.check_id)`: summary=`\(.incident_handoff.summary_json.path // "")` report=`\(.incident_handoff.report_md.path // "")` bundle=`\(.incident_handoff.bundle_dir.path // "")` attachment_manifest=`\(.incident_handoff.attachment_manifest.path // "")` readiness_summary_attachment=`\(.incident_handoff.readiness_report_summary_attachment.bundle_path // "")` readiness_report_attachment=`\(.incident_handoff.readiness_report_md_attachment.bundle_path // "")`"
  ] | if length == 0 then "- None" else join("\n") end
')"

report_md_tmp="$(mktemp "${report_md}.tmp.XXXXXX")"
{
  printf '# Manual Validation Readiness Report\n\n'
  printf -- '- Generated at (UTC): `%s`\n' "$(printf '%s\n' "$report_json" | jq -r '.generated_at_utc // ""')"
  printf -- '- Readiness: `%s`\n' "$readiness_status"
  printf -- '- State dir: `%s`\n' "$(printf '%s\n' "$report_json" | jq -r '.state_dir // ""')"
  printf -- '- Status JSON path: `%s`\n' "$(printf '%s\n' "$report_json" | jq -r '.status_json // ""')"
  printf -- '- Report JSON path: `%s`\n' "$summary_json"
  printf -- '- Report markdown path: `%s`\n' "$report_md"
  printf '\n## Summary\n\n'
  printf -- '- Total checks: `%s`\n' "$summary_total"
  printf -- '- Passed: `%s`\n' "$summary_pass"
  printf -- '- Warnings: `%s`\n' "$summary_warn"
  printf -- '- Failed: `%s`\n' "$summary_fail"
  printf -- '- Pending: `%s`\n' "$summary_pending"
  printf '\n## Roadmap Stage\n\n'
  if [[ -n "$roadmap_stage" ]]; then
    printf -- '- Stage: `%s`\n' "$roadmap_stage"
  fi
  printf -- '- Single-machine gate ready: `%s`\n' "$single_machine_ready"
  printf -- '- Real-host gate ready: `%s`\n' "$real_host_gate_ready"
  printf -- '- Real-host blockers: `%s`\n' "$real_host_gate_blockers"
  if [[ -n "$real_host_gate_next_command" ]]; then
    printf -- '- Next real-host command: `%s`\n' "$real_host_gate_next_command"
  fi
  printf '\n## Pre-Machine-C Gate\n\n'
  printf -- '- Machine C smoke ready: `%s`\n' "$machine_c_smoke_ready"
  printf -- '- Blockers: `%s`\n' "$machine_c_smoke_blockers"
  if [[ -n "$machine_c_smoke_next_command" ]]; then
    printf -- '- Next machine-C smoke command: `%s`\n' "$machine_c_smoke_next_command"
  fi
  printf '\n## Profile Default Gate\n\n'
  if [[ -n "$profile_default_gate_status" ]]; then
    printf -- '- Status: `%s`\n' "$profile_default_gate_status"
  fi
  printf -- '- Summary available: `%s`\n' "$profile_default_gate_available"
  if [[ -n "$profile_default_gate_decision" ]]; then
    printf -- '- Decision: `%s`\n' "$profile_default_gate_decision"
  fi
  if [[ -n "$profile_default_gate_recommended_profile" ]]; then
    printf -- '- Recommended profile: `%s`\n' "$profile_default_gate_recommended_profile"
  fi
  if [[ -n "$profile_default_gate_notes" ]]; then
    printf -- '- Notes: `%s`\n' "$profile_default_gate_notes"
  fi
  if [[ -n "$profile_default_gate_summary_json" ]]; then
    printf -- '- Summary JSON: `%s`\n' "$profile_default_gate_summary_json"
  fi
  if [[ -n "$profile_default_gate_next_command" ]]; then
    printf -- '- Next profile signoff command: `%s`\n' "$profile_default_gate_next_command"
  fi
  printf '\n## Docker Rehearsal (Optional)\n\n'
  if [[ -n "$docker_rehearsal_status" ]]; then
    printf -- '- Status: `%s`\n' "$docker_rehearsal_status"
  fi
  printf -- '- Ready: `%s`\n' "$docker_rehearsal_ready"
  if [[ -n "$docker_rehearsal_notes" ]]; then
    printf -- '- Notes: `%s`\n' "$docker_rehearsal_notes"
  fi
  if [[ -n "$docker_rehearsal_command" ]]; then
    printf -- '- Command: `%s`\n' "$docker_rehearsal_command"
  fi
  printf '\n## Real-WG Matrix (Optional)\n\n'
  if [[ -n "$real_wg_privileged_status" ]]; then
    printf -- '- Status: `%s`\n' "$real_wg_privileged_status"
  fi
  printf -- '- Ready: `%s`\n' "$real_wg_privileged_ready"
  if [[ -n "$real_wg_privileged_notes" ]]; then
    printf -- '- Notes: `%s`\n' "$real_wg_privileged_notes"
  fi
  if [[ -n "$real_wg_privileged_command" ]]; then
    printf -- '- Command: `%s`\n' "$real_wg_privileged_command"
  fi
  printf '\n## Next Action\n\n'
  if [[ -n "$next_action_check_id" ]]; then
    printf -- '- Check: `%s` (`%s`)\n' "$next_action_label" "$next_action_check_id"
    printf -- '- Command: `%s`\n' "$next_action_command"
    printf '%s\n' "$next_action_remediations_json" | jq -r '.[]? | "- Remediation: `\(.)`"'
  else
    printf -- '- None. Current readiness is `%s`.\n' "$readiness_status"
  fi
  printf '\n## Checks\n\n%s\n' "$checks_table_md"
  printf '\n## Runtime Findings\n\n%s\n' "$runtime_findings_md"
  printf '\n## Incident Handoff By Check\n\n%s\n' "$incident_checks_md"
  printf '\n## Latest Failed Incident\n\n'
  if [[ -n "$latest_failed_incident_check_id" ]]; then
    printf -- '- Check: `%s`\n' "$latest_failed_incident_check_id"
    printf -- '- Summary JSON: `%s`\n' "$latest_failed_incident_summary_json"
    printf -- '- Report markdown: `%s`\n' "$latest_failed_incident_report_md"
    printf -- '- Bundle dir: `%s`\n' "$latest_failed_incident_bundle_dir"
    printf -- '- Attachment manifest: `%s`\n' "$latest_failed_incident_attachment_manifest"
    printf -- '- Attachment count: `%s`\n' "$latest_failed_incident_attachment_count"
    if [[ -n "$latest_failed_incident_readiness_report_summary_attachment" ]]; then
      printf -- '- Readiness summary attachment: `%s`\n' "$latest_failed_incident_readiness_report_summary_attachment"
    fi
    if [[ -n "$latest_failed_incident_readiness_report_md_attachment" ]]; then
      printf -- '- Readiness report attachment: `%s`\n' "$latest_failed_incident_readiness_report_md_attachment"
    fi
    if [[ -n "$latest_failed_incident_readiness_report_log_attachment" ]]; then
      printf -- '- Readiness report log attachment: `%s`\n' "$latest_failed_incident_readiness_report_log_attachment"
    fi
  else
    printf -- '- None recorded.\n'
  fi
} >"$report_md_tmp"

mv -f "$report_md_tmp" "$report_md"

echo "[manual-validation-report] readiness_status=$readiness_status total=$summary_total pass=$summary_pass warn=$summary_warn fail=$summary_fail pending=$summary_pending"
echo "[manual-validation-report] summary_json=$summary_json"
echo "[manual-validation-report] report_md=$report_md"
echo "[manual-validation-report] source_status_exit_code=$status_rc"
echo "[manual-validation-report] source_status_timed_out=$status_timed_out"
echo "[manual-validation-report] source_status_timeout_sec=$status_timeout_sec"
echo "[manual-validation-report] source_status_timeout_guard_available=$status_timeout_guard_available"
echo "[manual-validation-report] source_status_payload_synthesized=$status_payload_synthesized"
echo "[manual-validation-report] machine_c_smoke_ready=$machine_c_smoke_ready"
echo "[manual-validation-report] machine_c_smoke_blockers=$machine_c_smoke_blockers"
if [[ -n "$machine_c_smoke_next_command" ]]; then
  echo "[manual-validation-report] machine_c_smoke_next_command=$machine_c_smoke_next_command"
fi
echo "[manual-validation-report] single_machine_ready=$single_machine_ready"
if [[ -n "$roadmap_stage" ]]; then
  echo "[manual-validation-report] roadmap_stage=$roadmap_stage"
fi
echo "[manual-validation-report] real_host_gate_ready=$real_host_gate_ready"
echo "[manual-validation-report] real_host_gate_blockers=$real_host_gate_blockers"
if [[ -n "$real_host_gate_next_command" ]]; then
  echo "[manual-validation-report] real_host_gate_next_command=$real_host_gate_next_command"
fi
if [[ -n "$profile_default_gate_status" ]]; then
  echo "[manual-validation-report] profile_default_gate_status=$profile_default_gate_status"
fi
echo "[manual-validation-report] profile_default_gate_available=$profile_default_gate_available"
if [[ -n "$profile_default_gate_decision" ]]; then
  echo "[manual-validation-report] profile_default_gate_decision=$profile_default_gate_decision"
fi
if [[ -n "$profile_default_gate_recommended_profile" ]]; then
  echo "[manual-validation-report] profile_default_gate_recommended_profile=$profile_default_gate_recommended_profile"
fi
if [[ -n "$profile_default_gate_summary_json" ]]; then
  echo "[manual-validation-report] profile_default_gate_summary_json=$profile_default_gate_summary_json"
fi
if [[ -n "$profile_default_gate_next_command" ]]; then
  echo "[manual-validation-report] profile_default_gate_next_command=$profile_default_gate_next_command"
fi
if [[ -n "$docker_rehearsal_status" ]]; then
  echo "[manual-validation-report] docker_rehearsal_status=$docker_rehearsal_status"
fi
echo "[manual-validation-report] docker_rehearsal_ready=$docker_rehearsal_ready"
if [[ -n "$docker_rehearsal_command" ]]; then
  echo "[manual-validation-report] docker_rehearsal_command=$docker_rehearsal_command"
fi
if [[ -n "$real_wg_privileged_status" ]]; then
  echo "[manual-validation-report] real_wg_privileged_status=$real_wg_privileged_status"
fi
echo "[manual-validation-report] real_wg_privileged_ready=$real_wg_privileged_ready"
if [[ -n "$real_wg_privileged_command" ]]; then
  echo "[manual-validation-report] real_wg_privileged_command=$real_wg_privileged_command"
fi
if [[ -n "$next_action_check_id" ]]; then
  echo "[manual-validation-report] next_action_check_id=$next_action_check_id"
  echo "[manual-validation-report] next_action_command=$next_action_command"
fi
if [[ -n "$next_action_remediations_csv" ]]; then
  echo "[manual-validation-report] next_action_remediations=$next_action_remediations_csv"
fi
if [[ -n "$latest_failed_incident_check_id" ]]; then
  echo "[manual-validation-report] latest_failed_incident_check_id=$latest_failed_incident_check_id"
  echo "[manual-validation-report] latest_failed_incident_summary_json=$latest_failed_incident_summary_json"
  echo "[manual-validation-report] latest_failed_incident_report_md=$latest_failed_incident_report_md"
  echo "[manual-validation-report] latest_failed_incident_bundle_dir=$latest_failed_incident_bundle_dir"
  if [[ -n "$latest_failed_incident_readiness_report_summary_attachment" ]]; then
    echo "[manual-validation-report] latest_failed_incident_readiness_report_summary_attachment=$latest_failed_incident_readiness_report_summary_attachment"
  fi
  if [[ -n "$latest_failed_incident_readiness_report_md_attachment" ]]; then
    echo "[manual-validation-report] latest_failed_incident_readiness_report_md_attachment=$latest_failed_incident_readiness_report_md_attachment"
  fi
fi

if [[ "$print_report" == "1" ]]; then
  echo "[manual-validation-report] report_markdown:"
  cat "$report_md"
fi
if [[ "$print_summary_json" == "1" ]]; then
  echo "[manual-validation-report] summary_json_payload:"
  printf '%s\n' "$report_json"
fi

if [[ "$status_timed_out" == "true" ]]; then
  echo "manual-validation-report: manual-validation-status timed out after ${status_timeout_sec}s"
  exit 1
fi

if [[ "$fail_on_not_ready" == "1" && "$readiness_status" != "READY" ]]; then
  echo "manual-validation-report: readiness is NOT_READY"
  exit 1
fi
