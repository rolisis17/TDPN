#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/vpn_rc_matrix_path.sh \
    [--reports-dir DIR] \
    [--matrix-summary-json PATH] \
    [--matrix-report-md PATH] \
    [--signoff-summary-json PATH] \
    [--roadmap-summary-json PATH] \
    [--roadmap-report-md PATH] \
    [--summary-json PATH] \
    [--campaign-execution-mode docker|local] \
    [--campaign-bootstrap-directory URL] \
    [--campaign-discovery-wait-sec N] \
    [--signoff-refresh-campaign [0|1]] \
    [--signoff-fail-on-no-go [0|1]] \
    [--roadmap-refresh-manual-validation [0|1]] \
    [--roadmap-refresh-single-machine-readiness [0|1]] \
    [--print-report [0|1]] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]]

Purpose:
  Run the RC profile-default decision chain in one command:
    1) profile-compare-docker-matrix (campaign refresh)
    2) profile-compare-campaign-signoff (fail-closed policy gate)
    3) roadmap-progress-report handoff generation

Notes:
  - Uses one shared reports directory across matrix + signoff + roadmap handoff.
  - Fail-close policy is explicit via --signoff-fail-on-no-go (default: 1).
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

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

run_step() {
  local name="$1"
  shift
  local rc=0
  local reason=""
  echo "[vpn-rc-matrix-path] step=$name status=running"
  set +e
  "$@"
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "[vpn-rc-matrix-path] step=$name status=pass rc=0"
    reason=""
  else
    reason="command-failed"
    echo "[vpn-rc-matrix-path] step=$name status=fail rc=$rc reason=$reason"
  fi
  RUN_STEP_REASON="$reason"
  return "$rc"
}

need_cmd jq

reports_dir="${VPN_RC_MATRIX_PATH_REPORTS_DIR:-}"
matrix_summary_json="${VPN_RC_MATRIX_PATH_MATRIX_SUMMARY_JSON:-}"
matrix_report_md="${VPN_RC_MATRIX_PATH_MATRIX_REPORT_MD:-}"
signoff_summary_json="${VPN_RC_MATRIX_PATH_SIGNOFF_SUMMARY_JSON:-}"
roadmap_summary_json="${VPN_RC_MATRIX_PATH_ROADMAP_SUMMARY_JSON:-}"
roadmap_report_md="${VPN_RC_MATRIX_PATH_ROADMAP_REPORT_MD:-}"
summary_json="${VPN_RC_MATRIX_PATH_SUMMARY_JSON:-}"
campaign_execution_mode="${VPN_RC_MATRIX_PATH_CAMPAIGN_EXECUTION_MODE:-docker}"
campaign_bootstrap_directory="${VPN_RC_MATRIX_PATH_CAMPAIGN_BOOTSTRAP_DIRECTORY:-}"
campaign_discovery_wait_sec="${VPN_RC_MATRIX_PATH_CAMPAIGN_DISCOVERY_WAIT_SEC:-20}"
signoff_refresh_campaign="${VPN_RC_MATRIX_PATH_SIGNOFF_REFRESH_CAMPAIGN:-0}"
signoff_fail_on_no_go="${VPN_RC_MATRIX_PATH_SIGNOFF_FAIL_ON_NO_GO:-1}"
roadmap_refresh_manual_validation="${VPN_RC_MATRIX_PATH_ROADMAP_REFRESH_MANUAL_VALIDATION:-1}"
roadmap_refresh_single_machine_readiness="${VPN_RC_MATRIX_PATH_ROADMAP_REFRESH_SINGLE_MACHINE_READINESS:-0}"
print_report="${VPN_RC_MATRIX_PATH_PRINT_REPORT:-1}"
print_summary_json="${VPN_RC_MATRIX_PATH_PRINT_SUMMARY_JSON:-1}"
dry_run="${VPN_RC_MATRIX_PATH_DRY_RUN:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --matrix-summary-json)
      matrix_summary_json="${2:-}"
      shift 2
      ;;
    --matrix-report-md)
      matrix_report_md="${2:-}"
      shift 2
      ;;
    --signoff-summary-json)
      signoff_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-summary-json)
      roadmap_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-report-md)
      roadmap_report_md="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --campaign-execution-mode)
      campaign_execution_mode="${2:-}"
      shift 2
      ;;
    --campaign-bootstrap-directory)
      campaign_bootstrap_directory="${2:-}"
      shift 2
      ;;
    --campaign-discovery-wait-sec)
      campaign_discovery_wait_sec="${2:-}"
      shift 2
      ;;
    --signoff-refresh-campaign)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_refresh_campaign="${2:-}"
        shift 2
      else
        signoff_refresh_campaign="1"
        shift
      fi
      ;;
    --signoff-fail-on-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_fail_on_no_go="${2:-}"
        shift 2
      else
        signoff_fail_on_no_go="1"
        shift
      fi
      ;;
    --roadmap-refresh-manual-validation)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        roadmap_refresh_manual_validation="${2:-}"
        shift 2
      else
        roadmap_refresh_manual_validation="1"
        shift
      fi
      ;;
    --roadmap-refresh-single-machine-readiness)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        roadmap_refresh_single_machine_readiness="${2:-}"
        shift 2
      else
        roadmap_refresh_single_machine_readiness="1"
        shift
      fi
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
    --dry-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dry_run="${2:-}"
        shift 2
      else
        dry_run="1"
        shift
      fi
      ;;
    -h|--help)
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

bool_arg_or_die "--signoff-refresh-campaign" "$signoff_refresh_campaign"
bool_arg_or_die "--signoff-fail-on-no-go" "$signoff_fail_on_no_go"
bool_arg_or_die "--roadmap-refresh-manual-validation" "$roadmap_refresh_manual_validation"
bool_arg_or_die "--roadmap-refresh-single-machine-readiness" "$roadmap_refresh_single_machine_readiness"
bool_arg_or_die "--print-report" "$print_report"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--dry-run" "$dry_run"

if [[ "$campaign_execution_mode" != "docker" && "$campaign_execution_mode" != "local" ]]; then
  echo "--campaign-execution-mode must be docker or local"
  exit 2
fi
if [[ -n "$campaign_discovery_wait_sec" && ! "$campaign_discovery_wait_sec" =~ ^[0-9]+$ ]]; then
  echo "--campaign-discovery-wait-sec must be an integer"
  exit 2
fi

matrix_script="${VPN_RC_MATRIX_PATH_MATRIX_SCRIPT:-$ROOT_DIR/scripts/profile_compare_docker_matrix.sh}"
signoff_script="${VPN_RC_MATRIX_PATH_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign_signoff.sh}"
roadmap_script="${VPN_RC_MATRIX_PATH_ROADMAP_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"

RUN_STEP_REASON=""

if [[ ! -x "$matrix_script" ]]; then
  echo "missing executable matrix script: $matrix_script"
  exit 2
fi
if [[ ! -x "$signoff_script" ]]; then
  echo "missing executable signoff script: $signoff_script"
  exit 2
fi
if [[ ! -x "$roadmap_script" ]]; then
  echo "missing executable roadmap script: $roadmap_script"
  exit 2
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/vpn_rc_matrix_${run_stamp}"
fi
reports_dir="$(abs_path "$reports_dir")"

if [[ -n "$matrix_summary_json" ]]; then
  matrix_summary_json="$(abs_path "$matrix_summary_json")"
else
  matrix_summary_json="$reports_dir/profile_compare_docker_matrix_summary.json"
fi
if [[ -n "$matrix_report_md" ]]; then
  matrix_report_md="$(abs_path "$matrix_report_md")"
else
  matrix_report_md="$reports_dir/profile_compare_docker_matrix_report.md"
fi
if [[ -n "$signoff_summary_json" ]]; then
  signoff_summary_json="$(abs_path "$signoff_summary_json")"
else
  signoff_summary_json="$reports_dir/profile_compare_campaign_signoff_summary.json"
fi
if [[ -n "$roadmap_summary_json" ]]; then
  roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
else
  roadmap_summary_json="$reports_dir/vpn_rc_matrix_roadmap_summary.json"
fi
if [[ -n "$roadmap_report_md" ]]; then
  roadmap_report_md="$(abs_path "$roadmap_report_md")"
else
  roadmap_report_md="$reports_dir/vpn_rc_matrix_roadmap_report.md"
fi
if [[ -n "$summary_json" ]]; then
  summary_json="$(abs_path "$summary_json")"
else
  summary_json="$reports_dir/vpn_rc_matrix_path_summary.json"
fi

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$matrix_summary_json")" "$(dirname "$matrix_report_md")"
mkdir -p "$(dirname "$signoff_summary_json")" "$(dirname "$roadmap_summary_json")" "$(dirname "$roadmap_report_md")"
mkdir -p "$(dirname "$summary_json")"

matrix_cmd=(
  "$matrix_script"
  --reports-dir "$reports_dir"
  --summary-json "$matrix_summary_json"
  --report-md "$matrix_report_md"
  --execution-mode "$campaign_execution_mode"
  --print-summary-json 0
)
if [[ -n "$campaign_bootstrap_directory" ]]; then
  matrix_cmd+=(--bootstrap-directory "$campaign_bootstrap_directory")
fi
if [[ -n "$campaign_discovery_wait_sec" ]]; then
  matrix_cmd+=(--discovery-wait-sec "$campaign_discovery_wait_sec")
fi

signoff_cmd=(
  "$signoff_script"
  --reports-dir "$reports_dir"
  --campaign-summary-json "$matrix_summary_json"
  --campaign-report-md "$matrix_report_md"
  --refresh-campaign "$signoff_refresh_campaign"
  --fail-on-no-go "$signoff_fail_on_no_go"
  --allow-summary-overwrite 0
  --campaign-execution-mode "$campaign_execution_mode"
  --summary-json "$signoff_summary_json"
  --show-json 0
  --print-summary-json 0
)
if [[ -n "$campaign_bootstrap_directory" ]]; then
  signoff_cmd+=(--campaign-bootstrap-directory "$campaign_bootstrap_directory")
fi
if [[ -n "$campaign_discovery_wait_sec" ]]; then
  signoff_cmd+=(--campaign-discovery-wait-sec "$campaign_discovery_wait_sec")
fi

roadmap_cmd=(
  "$roadmap_script"
  --refresh-manual-validation "$roadmap_refresh_manual_validation"
  --refresh-single-machine-readiness "$roadmap_refresh_single_machine_readiness"
  --profile-compare-signoff-summary-json "$signoff_summary_json"
  --summary-json "$roadmap_summary_json"
  --report-md "$roadmap_report_md"
  --print-report "$print_report"
  --print-summary-json 0
)

if [[ "$dry_run" == "1" ]]; then
  echo "[vpn-rc-matrix-path] dry-run=1"
  printf '[vpn-rc-matrix-path] matrix_cmd: '
  print_cmd "${matrix_cmd[@]}"
  printf '[vpn-rc-matrix-path] signoff_cmd: '
  print_cmd "${signoff_cmd[@]}"
  printf '[vpn-rc-matrix-path] roadmap_cmd: '
  print_cmd "${roadmap_cmd[@]}"
  echo "[vpn-rc-matrix-path] reports_dir=$reports_dir"
  echo "[vpn-rc-matrix-path] matrix_summary_json=$matrix_summary_json"
  echo "[vpn-rc-matrix-path] matrix_report_md=$matrix_report_md"
  echo "[vpn-rc-matrix-path] signoff_summary_json=$signoff_summary_json"
  echo "[vpn-rc-matrix-path] roadmap_summary_json=$roadmap_summary_json"
  echo "[vpn-rc-matrix-path] roadmap_report_md=$roadmap_report_md"
  echo "[vpn-rc-matrix-path] summary_json=$summary_json"
  exit 0
fi

matrix_rc=0
signoff_rc=0
roadmap_rc=0
matrix_reason=""
signoff_reason=""
roadmap_reason=""

if run_step "profile_compare_docker_matrix" "${matrix_cmd[@]}"; then
  :
else
  matrix_rc=$?
  matrix_reason="$RUN_STEP_REASON"
fi

if run_step "profile_compare_campaign_signoff" "${signoff_cmd[@]}"; then
  :
else
  signoff_rc=$?
  signoff_reason="$RUN_STEP_REASON"
fi

if run_step "roadmap_progress_report" "${roadmap_cmd[@]}"; then
  :
else
  roadmap_rc=$?
  roadmap_reason="$RUN_STEP_REASON"
fi

final_rc=0
if (( matrix_rc != 0 )); then
  final_rc=$matrix_rc
fi
if (( signoff_rc != 0 && final_rc == 0 )); then
  final_rc=$signoff_rc
fi
if (( roadmap_rc != 0 && final_rc == 0 )); then
  final_rc=$roadmap_rc
fi

final_status="pass"
if (( final_rc != 0 )); then
  final_status="fail"
fi

matrix_status="pass"
if (( matrix_rc != 0 )); then
  matrix_status="fail"
fi
signoff_status="pass"
if (( signoff_rc != 0 )); then
  signoff_status="fail"
fi
roadmap_status="pass"
if (( roadmap_rc != 0 )); then
  roadmap_status="fail"
fi

signoff_decision=""
signoff_go=false
signoff_summary_status=""
signoff_summary_final_rc="null"
signoff_failure_stage=""
if [[ -f "$signoff_summary_json" ]] && jq -e . "$signoff_summary_json" >/dev/null 2>&1; then
  signoff_decision="$(jq -r '.decision.decision // ""' "$signoff_summary_json" 2>/dev/null || true)"
  signoff_summary_status="$(jq -r '.status // ""' "$signoff_summary_json" 2>/dev/null || true)"
  signoff_summary_final_rc="$(jq -r 'if (.final_rc | type) == "number" then .final_rc else "null" end' "$signoff_summary_json" 2>/dev/null || true)"
  signoff_failure_stage="$(jq -r '.failure_stage // ""' "$signoff_summary_json" 2>/dev/null || true)"
  if [[ "$signoff_decision" == "GO" ]]; then
    signoff_go=true
  fi
fi

roadmap_stage=""
readiness_status=""
next_action_command=""
if [[ -f "$roadmap_summary_json" ]] && jq -e . "$roadmap_summary_json" >/dev/null 2>&1; then
  roadmap_stage="$(jq -r '.vpn_track.roadmap_stage // ""' "$roadmap_summary_json" 2>/dev/null || true)"
  readiness_status="$(jq -r '.vpn_track.readiness_status // ""' "$roadmap_summary_json" 2>/dev/null || true)"
  next_action_command="$(jq -r '.vpn_track.next_action.command // ""' "$roadmap_summary_json" 2>/dev/null || true)"
fi

matrix_failure_kind="none"
signoff_failure_kind="none"
roadmap_failure_kind="none"
if (( matrix_rc != 0 )); then
  matrix_failure_kind="execution_failure"
fi
if (( signoff_rc != 0 )); then
  if [[ "$signoff_decision" == "NO-GO" ]]; then
    signoff_failure_kind="policy_no_go"
    signoff_reason="policy-no-go"
  else
    signoff_failure_kind="execution_failure"
  fi
fi
if (( roadmap_rc != 0 )); then
  roadmap_failure_kind="execution_failure"
fi

final_failure_stage="none"
final_failure_kind="none"
if (( matrix_rc != 0 )); then
  final_failure_stage="profile_compare_docker_matrix"
  final_failure_kind="$matrix_failure_kind"
elif (( signoff_rc != 0 )); then
  final_failure_stage="profile_compare_campaign_signoff"
  final_failure_kind="$signoff_failure_kind"
elif (( roadmap_rc != 0 )); then
  final_failure_stage="roadmap_progress_report"
  final_failure_kind="$roadmap_failure_kind"
fi

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg final_status "$final_status" \
  --argjson final_rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg matrix_summary_json "$matrix_summary_json" \
  --arg matrix_report_md "$matrix_report_md" \
  --arg signoff_summary_json "$signoff_summary_json" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg roadmap_report_md "$roadmap_report_md" \
  --arg summary_json "$summary_json" \
  --arg campaign_execution_mode "$campaign_execution_mode" \
  --arg campaign_bootstrap_directory "$campaign_bootstrap_directory" \
  --arg campaign_discovery_wait_sec "$campaign_discovery_wait_sec" \
  --arg signoff_decision "$signoff_decision" \
  --argjson signoff_go "$signoff_go" \
  --arg signoff_summary_status "$signoff_summary_status" \
  --argjson signoff_summary_final_rc "$signoff_summary_final_rc" \
  --arg signoff_failure_stage "$signoff_failure_stage" \
  --arg roadmap_stage "$roadmap_stage" \
  --arg readiness_status "$readiness_status" \
  --arg next_action_command "$next_action_command" \
  --argjson matrix_rc "$matrix_rc" \
  --arg matrix_status "$matrix_status" \
  --arg matrix_reason "$matrix_reason" \
  --arg matrix_failure_kind "$matrix_failure_kind" \
  --argjson signoff_rc "$signoff_rc" \
  --arg signoff_status "$signoff_status" \
  --arg signoff_reason "$signoff_reason" \
  --arg signoff_failure_kind "$signoff_failure_kind" \
  --argjson roadmap_rc "$roadmap_rc" \
  --arg roadmap_status "$roadmap_status" \
  --arg roadmap_reason "$roadmap_reason" \
  --arg roadmap_failure_kind "$roadmap_failure_kind" \
  --arg signoff_refresh_campaign "$signoff_refresh_campaign" \
  --arg signoff_fail_on_no_go "$signoff_fail_on_no_go" \
  --arg roadmap_refresh_manual_validation "$roadmap_refresh_manual_validation" \
  --arg roadmap_refresh_single_machine_readiness "$roadmap_refresh_single_machine_readiness" \
  --arg print_report "$print_report" \
  --arg print_summary_json "$print_summary_json" \
  --arg final_failure_stage "$final_failure_stage" \
  --arg final_failure_kind "$final_failure_kind" \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    status: $final_status,
    rc: $final_rc,
    policy: {
      signoff_refresh_campaign: ($signoff_refresh_campaign == "1"),
      signoff_fail_on_no_go: ($signoff_fail_on_no_go == "1"),
      fail_closed_signoff: ($signoff_fail_on_no_go == "1")
    },
    inputs: {
      campaign_execution_mode: $campaign_execution_mode,
      campaign_bootstrap_directory: (if $campaign_bootstrap_directory == "" then null else $campaign_bootstrap_directory end),
      campaign_discovery_wait_sec: (if $campaign_discovery_wait_sec == "" then null else ($campaign_discovery_wait_sec | tonumber) end),
      roadmap_refresh_manual_validation: ($roadmap_refresh_manual_validation == "1"),
      roadmap_refresh_single_machine_readiness: ($roadmap_refresh_single_machine_readiness == "1")
    },
    steps: {
      profile_compare_docker_matrix: {
        status: $matrix_status,
        rc: $matrix_rc,
        reason: (if $matrix_reason == "" then null else $matrix_reason end),
        failure_semantics: {
          kind: $matrix_failure_kind,
          policy_no_go: ($matrix_failure_kind == "policy_no_go"),
          execution_failure: ($matrix_failure_kind == "execution_failure")
        }
      },
      profile_compare_campaign_signoff: {
        status: $signoff_status,
        rc: $signoff_rc,
        reason: (if $signoff_reason == "" then null else $signoff_reason end),
        decision: $signoff_decision,
        go: $signoff_go,
        summary_status: (if $signoff_summary_status == "" then null else $signoff_summary_status end),
        summary_final_rc: $signoff_summary_final_rc,
        summary_failure_stage: (if $signoff_failure_stage == "" then null else $signoff_failure_stage end),
        failure_semantics: {
          kind: $signoff_failure_kind,
          policy_no_go: ($signoff_failure_kind == "policy_no_go"),
          execution_failure: ($signoff_failure_kind == "execution_failure")
        }
      },
      roadmap_progress_report: {
        status: $roadmap_status,
        rc: $roadmap_rc,
        reason: (if $roadmap_reason == "" then null else $roadmap_reason end),
        failure_semantics: {
          kind: $roadmap_failure_kind,
          policy_no_go: ($roadmap_failure_kind == "policy_no_go"),
          execution_failure: ($roadmap_failure_kind == "execution_failure")
        },
        roadmap_stage: $roadmap_stage,
        readiness_status: $readiness_status,
        next_action_command: $next_action_command
      }
    },
    failure: {
      stage: (if $final_failure_stage == "none" then null else $final_failure_stage end),
      kind: $final_failure_kind,
      policy_no_go: ($final_failure_kind == "policy_no_go"),
      execution_failure: ($final_failure_kind == "execution_failure")
    },
    policy_outcome: {
      fail_closed_no_go: ($final_failure_kind == "policy_no_go"),
      signoff_decision: (if $signoff_decision == "" then null else $signoff_decision end),
      signoff_go: $signoff_go
    },
    outputs: {
      print_report: ($print_report == "1"),
      print_summary_json: ($print_summary_json == "1")
    },
    artifacts: {
      reports_dir: $reports_dir,
      matrix_summary_json: $matrix_summary_json,
      matrix_report_md: $matrix_report_md,
      signoff_summary_json: $signoff_summary_json,
      roadmap_summary_json: $roadmap_summary_json,
      roadmap_report_md: $roadmap_report_md,
      summary_json: $summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[vpn-rc-matrix-path] status=$final_status rc=$final_rc"
echo "[vpn-rc-matrix-path] signoff_fail_on_no_go=$signoff_fail_on_no_go signoff_decision=${signoff_decision:-unknown}"
echo "[vpn-rc-matrix-path] failure_stage=${final_failure_stage:-none} failure_kind=${final_failure_kind:-none}"
echo "[vpn-rc-matrix-path] reports_dir=$reports_dir"
echo "[vpn-rc-matrix-path] matrix_summary_json=$matrix_summary_json"
echo "[vpn-rc-matrix-path] signoff_summary_json=$signoff_summary_json"
echo "[vpn-rc-matrix-path] roadmap_summary_json=$roadmap_summary_json"
echo "[vpn-rc-matrix-path] roadmap_report_md=$roadmap_report_md"
echo "[vpn-rc-matrix-path] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
