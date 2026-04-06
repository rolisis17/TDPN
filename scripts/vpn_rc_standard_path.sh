#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/vpn_rc_standard_path.sh \
    [--run-profile-compare-campaign-signoff auto|0|1] \
    [--profile-compare-campaign-signoff-refresh-campaign 0|1] \
    [--single-machine-summary-json PATH] \
    [--roadmap-summary-json PATH] \
    [--roadmap-report-md PATH] \
    [--print-report [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Run the locked VPN RC one-host execution path in one command:
    1) single-machine-prod-readiness (strict defaults + docker rehearsal)
    2) roadmap-progress-report refresh based on that output
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

tri_state_or_die() {
  local name="$1"
  local value="$2"
  case "$value" in
    auto|0|1) ;;
    *)
      echo "$name must be one of: auto, 0, 1"
      exit 2
      ;;
  esac
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

run_step() {
  local name="$1"
  shift
  local rc=0
  echo "[vpn-rc-standard-path] step=$name status=running"
  set +e
  "$@"
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "[vpn-rc-standard-path] step=$name status=pass rc=0"
  else
    echo "[vpn-rc-standard-path] step=$name status=fail rc=$rc"
  fi
  return "$rc"
}

run_profile_compare_campaign_signoff="auto"
profile_compare_campaign_signoff_refresh_campaign="0"
single_machine_summary_json="$ROOT_DIR/.easy-node-logs/vpn_rc_single_machine_summary.json"
roadmap_summary_json="$ROOT_DIR/.easy-node-logs/vpn_rc_roadmap_summary.json"
roadmap_report_md="$ROOT_DIR/.easy-node-logs/vpn_rc_roadmap_report.md"
print_report="1"
print_summary_json="1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-profile-compare-campaign-signoff)
      run_profile_compare_campaign_signoff="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-refresh-campaign)
      profile_compare_campaign_signoff_refresh_campaign="${2:-}"
      shift 2
      ;;
    --single-machine-summary-json)
      single_machine_summary_json="${2:-}"
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
    --print-report)
      print_report="${2:-1}"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
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

tri_state_or_die "--run-profile-compare-campaign-signoff" "$run_profile_compare_campaign_signoff"
bool_arg_or_die "--profile-compare-campaign-signoff-refresh-campaign" "$profile_compare_campaign_signoff_refresh_campaign"
bool_arg_or_die "--print-report" "$print_report"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

need_cmd jq

single_machine_summary_json="$(abs_path "$single_machine_summary_json")"
roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
roadmap_report_md="$(abs_path "$roadmap_report_md")"

mkdir -p "$(dirname "$single_machine_summary_json")"
mkdir -p "$(dirname "$roadmap_summary_json")"
mkdir -p "$(dirname "$roadmap_report_md")"

single_machine_script="${VPN_RC_STANDARD_PATH_SINGLE_MACHINE_SCRIPT:-$ROOT_DIR/scripts/single_machine_prod_readiness.sh}"
roadmap_progress_script="${VPN_RC_STANDARD_PATH_ROADMAP_PROGRESS_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"

single_machine_args=(
  --run-ci-local 1
  --run-beta-preflight 1
  --run-deep-suite 1
  --run-runtime-fix-record 1
  --run-three-machine-docker-readiness 1
  --three-machine-docker-readiness-run-validate 1
  --three-machine-docker-readiness-run-soak 1
  --three-machine-docker-readiness-soak-rounds 6
  --three-machine-docker-readiness-soak-pause-sec 3
  --three-machine-docker-readiness-path-profile balanced
  --three-machine-docker-readiness-keep-stacks 0
  --run-profile-compare-campaign-signoff "$run_profile_compare_campaign_signoff"
  --profile-compare-campaign-signoff-refresh-campaign "$profile_compare_campaign_signoff_refresh_campaign"
  --summary-json "$single_machine_summary_json"
  --print-summary-json 0
)

roadmap_args=(
  --refresh-manual-validation 1
  --refresh-single-machine-readiness 0
  --single-machine-summary-json "$single_machine_summary_json"
  --summary-json "$roadmap_summary_json"
  --report-md "$roadmap_report_md"
  --print-report "$print_report"
  --print-summary-json 0
)

single_machine_rc=0
roadmap_rc=0
if run_step "single_machine_prod_readiness" "$single_machine_script" "${single_machine_args[@]}"; then
  :
else
  single_machine_rc=$?
fi

if run_step "roadmap_progress_report" "$roadmap_progress_script" "${roadmap_args[@]}"; then
  :
else
  roadmap_rc=$?
fi

final_rc=0
if (( single_machine_rc != 0 )); then
  final_rc=$single_machine_rc
fi
if (( roadmap_rc != 0 && final_rc == 0 )); then
  final_rc=$roadmap_rc
fi

final_status="pass"
if (( final_rc != 0 )); then
  final_status="fail"
fi

roadmap_stage=""
readiness_status=""
next_action_check_id=""
next_action_command=""
if [[ -f "$roadmap_summary_json" ]] && jq -e . "$roadmap_summary_json" >/dev/null 2>&1; then
  roadmap_stage="$(jq -r '.summary.roadmap_stage // ""' "$roadmap_summary_json" 2>/dev/null || true)"
  readiness_status="$(jq -r '.report.readiness_status // ""' "$roadmap_summary_json" 2>/dev/null || true)"
  next_action_check_id="$(jq -r '.summary.next_action_check_id // ""' "$roadmap_summary_json" 2>/dev/null || true)"
  next_action_command="$(jq -r '.summary.next_action_command // ""' "$roadmap_summary_json" 2>/dev/null || true)"
fi

echo "[vpn-rc-standard-path] status=$final_status rc=$final_rc"
echo "[vpn-rc-standard-path] single_machine_summary_json=$single_machine_summary_json"
echo "[vpn-rc-standard-path] roadmap_summary_json=$roadmap_summary_json"
echo "[vpn-rc-standard-path] roadmap_report_md=$roadmap_report_md"
echo "[vpn-rc-standard-path] roadmap_stage=${roadmap_stage:-}"
echo "[vpn-rc-standard-path] readiness_status=${readiness_status:-}"
echo "[vpn-rc-standard-path] next_action_check_id=${next_action_check_id:-}"
echo "[vpn-rc-standard-path] next_action_command=${next_action_command:-}"

if [[ "$print_summary_json" == "1" ]]; then
  jq -n \
    --arg final_status "$final_status" \
    --argjson final_rc "$final_rc" \
    --argjson single_machine_rc "$single_machine_rc" \
    --argjson roadmap_rc "$roadmap_rc" \
    --arg run_profile_compare_campaign_signoff "$run_profile_compare_campaign_signoff" \
    --argjson profile_compare_campaign_signoff_refresh_campaign "$profile_compare_campaign_signoff_refresh_campaign" \
    --arg single_machine_summary_json "$single_machine_summary_json" \
    --arg roadmap_summary_json "$roadmap_summary_json" \
    --arg roadmap_report_md "$roadmap_report_md" \
    --arg roadmap_stage "${roadmap_stage:-}" \
    --arg readiness_status "${readiness_status:-}" \
    --arg next_action_check_id "${next_action_check_id:-}" \
    --arg next_action_command "${next_action_command:-}" \
    --argjson print_report "$print_report" \
    --argjson print_summary_json "$print_summary_json" \
    '{
      version: 1,
      status: $final_status,
      rc: $final_rc,
      profile_default_gate: {
        run_profile_compare_campaign_signoff: $run_profile_compare_campaign_signoff,
        refresh_campaign: $profile_compare_campaign_signoff_refresh_campaign
      },
      steps: {
        single_machine_prod_readiness: {rc: $single_machine_rc},
        roadmap_progress_report: {rc: $roadmap_rc}
      },
      roadmap: {
        stage: $roadmap_stage,
        readiness_status: $readiness_status,
        next_action_check_id: $next_action_check_id,
        next_action_command: $next_action_command
      },
      outputs: {
        print_report: $print_report,
        print_summary_json: $print_summary_json
      },
      artifacts: {
        single_machine_summary_json: $single_machine_summary_json,
        roadmap_summary_json: $roadmap_summary_json,
        roadmap_report_md: $roadmap_report_md
      }
    }'
fi

exit "$final_rc"
