#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/ci_phase2_linux_prod_candidate.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--run-release-integrity [0|1]] \
    [--run-release-sbom [0|1]] \
    [--run-release-tag-verify [0|1]] \
    [--run-release-policy-gate [0|1]] \
    [--run-prod-key-rotation-runbook [0|1]] \
    [--run-prod-upgrade-runbook [0|1]] \
    [--run-prod-operator-lifecycle-runbook [0|1]] \
    [--run-prod-pilot-runbook [0|1]] \
    [--run-prod-pilot-cohort-runbook [0|1]] \
    [--run-prod-pilot-cohort-signoff [0|1]] \
    [--run-prod-pilot-cohort-quick-signoff [0|1]] \
    [--run-phase2-linux-prod-candidate-signoff [0|1]] \
    [--run-phase2-linux-prod-candidate-handoff-check [0|1]] \
    [--run-phase2-linux-prod-candidate-handoff-run [0|1]] \
    [--run-roadmap-progress-phase2-handoff [0|1]]

Purpose:
  Run a focused Phase-2 Linux production-candidate CI gate around release and
  production contract/integration checks:
    1) integration_release_integrity.sh
    2) integration_release_sbom.sh
    3) integration_release_tag_verify.sh
    4) integration_release_policy_gate.sh
    5) integration_prod_key_rotation_runbook.sh
    6) integration_prod_upgrade_runbook.sh
    7) integration_prod_operator_lifecycle_runbook.sh
    8) integration_prod_pilot_runbook.sh
    9) integration_prod_pilot_cohort_runbook.sh
   10) integration_prod_pilot_cohort_signoff.sh
   11) integration_prod_pilot_cohort_quick_signoff.sh
   12) integration_phase2_linux_prod_candidate_signoff.sh
   13) integration_phase2_linux_prod_candidate_handoff_check.sh
   14) integration_phase2_linux_prod_candidate_handoff_run.sh
   15) integration_roadmap_progress_phase2_handoff.sh

Dry-run mode:
  --dry-run 1 skips stage execution, records deterministic skip accounting,
  and still emits the runner summary JSON.
USAGE
}

trim() {
  local value="${1:-}"
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
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
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
  local label="$1"
  shift
  local rc=0
  echo "[ci-phase2-linux-prod-candidate] step=${label} status=running"
  set +e
  "$@"
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "[ci-phase2-linux-prod-candidate] step=${label} status=pass rc=0"
  else
    echo "[ci-phase2-linux-prod-candidate] step=${label} status=fail rc=${rc}"
  fi
  return "$rc"
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${CI_PHASE2_LINUX_PROD_CANDIDATE_REPORTS_DIR:-}"
summary_json="${CI_PHASE2_LINUX_PROD_CANDIDATE_SUMMARY_JSON:-}"
print_summary_json="${CI_PHASE2_LINUX_PROD_CANDIDATE_PRINT_SUMMARY_JSON:-1}"
dry_run="${CI_PHASE2_LINUX_PROD_CANDIDATE_DRY_RUN:-0}"

run_release_integrity="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_RELEASE_INTEGRITY:-1}"
run_release_sbom="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_RELEASE_SBOM:-1}"
run_release_tag_verify="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_RELEASE_TAG_VERIFY:-1}"
run_release_policy_gate="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_RELEASE_POLICY_GATE:-1}"
run_prod_key_rotation_runbook="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_PROD_KEY_ROTATION_RUNBOOK:-1}"
run_prod_upgrade_runbook="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_PROD_UPGRADE_RUNBOOK:-1}"
run_prod_operator_lifecycle_runbook="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_PROD_OPERATOR_LIFECYCLE_RUNBOOK:-1}"
run_prod_pilot_runbook="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_PROD_PILOT_RUNBOOK:-1}"
run_prod_pilot_cohort_runbook="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_PROD_PILOT_COHORT_RUNBOOK:-1}"
run_prod_pilot_cohort_signoff="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_PROD_PILOT_COHORT_SIGNOFF:-1}"
run_prod_pilot_cohort_quick_signoff="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_PROD_PILOT_COHORT_QUICK_SIGNOFF:-1}"
run_phase2_linux_prod_candidate_signoff="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_PHASE2_LINUX_PROD_CANDIDATE_SIGNOFF:-1}"
run_phase2_linux_prod_candidate_handoff_check="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK:-1}"
run_phase2_linux_prod_candidate_handoff_run="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN:-1}"
run_roadmap_progress_phase2_handoff="${CI_PHASE2_LINUX_PROD_CANDIDATE_RUN_ROADMAP_PROGRESS_PHASE2_HANDOFF:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
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
    --dry-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dry_run="${2:-}"
        shift 2
      else
        dry_run="1"
        shift
      fi
      ;;
    --run-release-integrity)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_release_integrity="${2:-}"
        shift 2
      else
        run_release_integrity="1"
        shift
      fi
      ;;
    --run-release-sbom)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_release_sbom="${2:-}"
        shift 2
      else
        run_release_sbom="1"
        shift
      fi
      ;;
    --run-release-tag-verify)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_release_tag_verify="${2:-}"
        shift 2
      else
        run_release_tag_verify="1"
        shift
      fi
      ;;
    --run-release-policy-gate)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_release_policy_gate="${2:-}"
        shift 2
      else
        run_release_policy_gate="1"
        shift
      fi
      ;;
    --run-prod-key-rotation-runbook)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_prod_key_rotation_runbook="${2:-}"
        shift 2
      else
        run_prod_key_rotation_runbook="1"
        shift
      fi
      ;;
    --run-prod-upgrade-runbook)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_prod_upgrade_runbook="${2:-}"
        shift 2
      else
        run_prod_upgrade_runbook="1"
        shift
      fi
      ;;
    --run-prod-operator-lifecycle-runbook)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_prod_operator_lifecycle_runbook="${2:-}"
        shift 2
      else
        run_prod_operator_lifecycle_runbook="1"
        shift
      fi
      ;;
    --run-prod-pilot-runbook)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_prod_pilot_runbook="${2:-}"
        shift 2
      else
        run_prod_pilot_runbook="1"
        shift
      fi
      ;;
    --run-prod-pilot-cohort-runbook)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_prod_pilot_cohort_runbook="${2:-}"
        shift 2
      else
        run_prod_pilot_cohort_runbook="1"
        shift
      fi
      ;;
    --run-prod-pilot-cohort-signoff)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_prod_pilot_cohort_signoff="${2:-}"
        shift 2
      else
        run_prod_pilot_cohort_signoff="1"
        shift
      fi
      ;;
    --run-prod-pilot-cohort-quick-signoff)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_prod_pilot_cohort_quick_signoff="${2:-}"
        shift 2
      else
        run_prod_pilot_cohort_quick_signoff="1"
        shift
      fi
      ;;
    --run-phase2-linux-prod-candidate-signoff)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase2_linux_prod_candidate_signoff="${2:-}"
        shift 2
      else
        run_phase2_linux_prod_candidate_signoff="1"
        shift
      fi
      ;;
    --run-phase2-linux-prod-candidate-handoff-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase2_linux_prod_candidate_handoff_check="${2:-}"
        shift 2
      else
        run_phase2_linux_prod_candidate_handoff_check="1"
        shift
      fi
      ;;
    --run-phase2-linux-prod-candidate-handoff-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase2_linux_prod_candidate_handoff_run="${2:-}"
        shift 2
      else
        run_phase2_linux_prod_candidate_handoff_run="1"
        shift
      fi
      ;;
    --run-roadmap-progress-phase2-handoff)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_roadmap_progress_phase2_handoff="${2:-}"
        shift 2
      else
        run_roadmap_progress_phase2_handoff="1"
        shift
      fi
      ;;
    -h|--help)
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

bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--dry-run" "$dry_run"
bool_arg_or_die "--run-release-integrity" "$run_release_integrity"
bool_arg_or_die "--run-release-sbom" "$run_release_sbom"
bool_arg_or_die "--run-release-tag-verify" "$run_release_tag_verify"
bool_arg_or_die "--run-release-policy-gate" "$run_release_policy_gate"
bool_arg_or_die "--run-prod-key-rotation-runbook" "$run_prod_key_rotation_runbook"
bool_arg_or_die "--run-prod-upgrade-runbook" "$run_prod_upgrade_runbook"
bool_arg_or_die "--run-prod-operator-lifecycle-runbook" "$run_prod_operator_lifecycle_runbook"
bool_arg_or_die "--run-prod-pilot-runbook" "$run_prod_pilot_runbook"
bool_arg_or_die "--run-prod-pilot-cohort-runbook" "$run_prod_pilot_cohort_runbook"
bool_arg_or_die "--run-prod-pilot-cohort-signoff" "$run_prod_pilot_cohort_signoff"
bool_arg_or_die "--run-prod-pilot-cohort-quick-signoff" "$run_prod_pilot_cohort_quick_signoff"
bool_arg_or_die "--run-phase2-linux-prod-candidate-signoff" "$run_phase2_linux_prod_candidate_signoff"
bool_arg_or_die "--run-phase2-linux-prod-candidate-handoff-check" "$run_phase2_linux_prod_candidate_handoff_check"
bool_arg_or_die "--run-phase2-linux-prod-candidate-handoff-run" "$run_phase2_linux_prod_candidate_handoff_run"
bool_arg_or_die "--run-roadmap-progress-phase2-handoff" "$run_roadmap_progress_phase2_handoff"

release_integrity_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_RELEASE_INTEGRITY_SCRIPT:-$ROOT_DIR/scripts/integration_release_integrity.sh}"
release_sbom_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_RELEASE_SBOM_SCRIPT:-$ROOT_DIR/scripts/integration_release_sbom.sh}"
release_tag_verify_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_RELEASE_TAG_VERIFY_SCRIPT:-$ROOT_DIR/scripts/integration_release_tag_verify.sh}"
release_policy_gate_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_RELEASE_POLICY_GATE_SCRIPT:-$ROOT_DIR/scripts/integration_release_policy_gate.sh}"
prod_key_rotation_runbook_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_PROD_KEY_ROTATION_RUNBOOK_SCRIPT:-$ROOT_DIR/scripts/integration_prod_key_rotation_runbook.sh}"
prod_upgrade_runbook_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_PROD_UPGRADE_RUNBOOK_SCRIPT:-$ROOT_DIR/scripts/integration_prod_upgrade_runbook.sh}"
prod_operator_lifecycle_runbook_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_PROD_OPERATOR_LIFECYCLE_RUNBOOK_SCRIPT:-$ROOT_DIR/scripts/integration_prod_operator_lifecycle_runbook.sh}"
prod_pilot_runbook_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_PROD_PILOT_RUNBOOK_SCRIPT:-$ROOT_DIR/scripts/integration_prod_pilot_runbook.sh}"
prod_pilot_cohort_runbook_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_PROD_PILOT_COHORT_RUNBOOK_SCRIPT:-$ROOT_DIR/scripts/integration_prod_pilot_cohort_runbook.sh}"
prod_pilot_cohort_signoff_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_PROD_PILOT_COHORT_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/integration_prod_pilot_cohort_signoff.sh}"
prod_pilot_cohort_quick_signoff_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_PROD_PILOT_COHORT_QUICK_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/integration_prod_pilot_cohort_quick_signoff.sh}"
phase2_linux_prod_candidate_signoff_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_PHASE2_LINUX_PROD_CANDIDATE_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/integration_phase2_linux_prod_candidate_signoff.sh}"
phase2_linux_prod_candidate_handoff_check_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/integration_phase2_linux_prod_candidate_handoff_check.sh}"
phase2_linux_prod_candidate_handoff_run_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/integration_phase2_linux_prod_candidate_handoff_run.sh}"
roadmap_progress_phase2_handoff_script="${CI_PHASE2_LINUX_PROD_CANDIDATE_ROADMAP_PROGRESS_PHASE2_HANDOFF_SCRIPT:-$ROOT_DIR/scripts/integration_roadmap_progress_phase2_handoff.sh}"

stage_ids=(
  "release_integrity"
  "release_sbom"
  "release_tag_verify"
  "release_policy_gate"
  "prod_key_rotation_runbook"
  "prod_upgrade_runbook"
  "prod_operator_lifecycle_runbook"
  "prod_pilot_runbook"
  "prod_pilot_cohort_runbook"
  "prod_pilot_cohort_signoff"
  "prod_pilot_cohort_quick_signoff"
  "phase2_linux_prod_candidate_signoff"
  "phase2_linux_prod_candidate_handoff_check"
  "phase2_linux_prod_candidate_handoff_run"
  "roadmap_progress_phase2_handoff"
)

declare -A stage_script=(
  ["release_integrity"]="$release_integrity_script"
  ["release_sbom"]="$release_sbom_script"
  ["release_tag_verify"]="$release_tag_verify_script"
  ["release_policy_gate"]="$release_policy_gate_script"
  ["prod_key_rotation_runbook"]="$prod_key_rotation_runbook_script"
  ["prod_upgrade_runbook"]="$prod_upgrade_runbook_script"
  ["prod_operator_lifecycle_runbook"]="$prod_operator_lifecycle_runbook_script"
  ["prod_pilot_runbook"]="$prod_pilot_runbook_script"
  ["prod_pilot_cohort_runbook"]="$prod_pilot_cohort_runbook_script"
  ["prod_pilot_cohort_signoff"]="$prod_pilot_cohort_signoff_script"
  ["prod_pilot_cohort_quick_signoff"]="$prod_pilot_cohort_quick_signoff_script"
  ["phase2_linux_prod_candidate_signoff"]="$phase2_linux_prod_candidate_signoff_script"
  ["phase2_linux_prod_candidate_handoff_check"]="$phase2_linux_prod_candidate_handoff_check_script"
  ["phase2_linux_prod_candidate_handoff_run"]="$phase2_linux_prod_candidate_handoff_run_script"
  ["roadmap_progress_phase2_handoff"]="$roadmap_progress_phase2_handoff_script"
)

declare -A stage_enabled=(
  ["release_integrity"]="$run_release_integrity"
  ["release_sbom"]="$run_release_sbom"
  ["release_tag_verify"]="$run_release_tag_verify"
  ["release_policy_gate"]="$run_release_policy_gate"
  ["prod_key_rotation_runbook"]="$run_prod_key_rotation_runbook"
  ["prod_upgrade_runbook"]="$run_prod_upgrade_runbook"
  ["prod_operator_lifecycle_runbook"]="$run_prod_operator_lifecycle_runbook"
  ["prod_pilot_runbook"]="$run_prod_pilot_runbook"
  ["prod_pilot_cohort_runbook"]="$run_prod_pilot_cohort_runbook"
  ["prod_pilot_cohort_signoff"]="$run_prod_pilot_cohort_signoff"
  ["prod_pilot_cohort_quick_signoff"]="$run_prod_pilot_cohort_quick_signoff"
  ["phase2_linux_prod_candidate_signoff"]="$run_phase2_linux_prod_candidate_signoff"
  ["phase2_linux_prod_candidate_handoff_check"]="$run_phase2_linux_prod_candidate_handoff_check"
  ["phase2_linux_prod_candidate_handoff_run"]="$run_phase2_linux_prod_candidate_handoff_run"
  ["roadmap_progress_phase2_handoff"]="$run_roadmap_progress_phase2_handoff"
)

for stage_id in "${stage_ids[@]}"; do
  if [[ "${stage_enabled[$stage_id]}" == "1" && ! -x "${stage_script[$stage_id]}" ]]; then
    echo "missing executable stage script: ${stage_script[$stage_id]}"
    exit 2
  fi
done

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/ci_phase2_linux_prod_candidate_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/ci_phase2_linux_prod_candidate_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$summary_json")"

declare -A stage_status
declare -A stage_rc
declare -A stage_command
declare -A stage_reason

final_rc=0

for stage_id in "${stage_ids[@]}"; do
  script="${stage_script[$stage_id]}"
  enabled="${stage_enabled[$stage_id]}"

  stage_status["$stage_id"]="skip"
  stage_rc["$stage_id"]=0
  stage_command["$stage_id"]=""
  stage_reason["$stage_id"]=""

  if [[ "$enabled" == "1" ]]; then
    stage_command["$stage_id"]="$(print_cmd "$script")"
    if [[ "$dry_run" == "1" ]]; then
      stage_reason["$stage_id"]="dry-run"
      echo "[ci-phase2-linux-prod-candidate] step=${stage_id} status=skip reason=dry-run"
    elif run_step "$stage_id" "$script"; then
      stage_status["$stage_id"]="pass"
      stage_rc["$stage_id"]=0
    else
      step_rc=$?
      stage_status["$stage_id"]="fail"
      stage_rc["$stage_id"]=$step_rc
      if (( final_rc == 0 )); then
        final_rc=$step_rc
      fi
    fi
  else
    echo "[ci-phase2-linux-prod-candidate] step=${stage_id} status=skip reason=disabled"
    stage_reason["$stage_id"]="disabled"
  fi
done

final_status="pass"
if (( final_rc != 0 )); then
  final_status="fail"
fi

steps_json='{}'
for stage_id in "${stage_ids[@]}"; do
  stage_entry="$(
    jq -n \
      --arg enabled "${stage_enabled[$stage_id]}" \
      --arg status "${stage_status[$stage_id]}" \
      --argjson rc "${stage_rc[$stage_id]}" \
      --arg command "${stage_command[$stage_id]}" \
      --arg reason "${stage_reason[$stage_id]}" \
      '{
        enabled: ($enabled == "1"),
        status: $status,
        rc: $rc,
        command: (if $command == "" then null else $command end),
        reason: (if $reason == "" then null else $reason end),
        artifacts: {}
      }'
  )"
  steps_json="$(
    jq -n \
      --argjson base "$steps_json" \
      --arg key "$stage_id" \
      --argjson val "$stage_entry" \
      '$base + {($key): $val}'
  )"
done

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg dry_run "$dry_run" \
  --arg print_summary_json "$print_summary_json" \
  --arg run_release_integrity "$run_release_integrity" \
  --arg run_release_sbom "$run_release_sbom" \
  --arg run_release_tag_verify "$run_release_tag_verify" \
  --arg run_release_policy_gate "$run_release_policy_gate" \
  --arg run_prod_key_rotation_runbook "$run_prod_key_rotation_runbook" \
  --arg run_prod_upgrade_runbook "$run_prod_upgrade_runbook" \
  --arg run_prod_operator_lifecycle_runbook "$run_prod_operator_lifecycle_runbook" \
  --arg run_prod_pilot_runbook "$run_prod_pilot_runbook" \
  --arg run_prod_pilot_cohort_runbook "$run_prod_pilot_cohort_runbook" \
  --arg run_prod_pilot_cohort_signoff "$run_prod_pilot_cohort_signoff" \
  --arg run_prod_pilot_cohort_quick_signoff "$run_prod_pilot_cohort_quick_signoff" \
  --arg run_phase2_linux_prod_candidate_signoff "$run_phase2_linux_prod_candidate_signoff" \
  --arg run_phase2_linux_prod_candidate_handoff_check "$run_phase2_linux_prod_candidate_handoff_check" \
  --arg run_phase2_linux_prod_candidate_handoff_run "$run_phase2_linux_prod_candidate_handoff_run" \
  --arg run_roadmap_progress_phase2_handoff "$run_roadmap_progress_phase2_handoff" \
  --argjson steps "$steps_json" \
  '{
    version: 1,
    schema: {
      id: "ci_phase2_linux_prod_candidate_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    inputs: {
      dry_run: ($dry_run == "1"),
      print_summary_json: ($print_summary_json == "1"),
      run_release_integrity: ($run_release_integrity == "1"),
      run_release_sbom: ($run_release_sbom == "1"),
      run_release_tag_verify: ($run_release_tag_verify == "1"),
      run_release_policy_gate: ($run_release_policy_gate == "1"),
      run_prod_key_rotation_runbook: ($run_prod_key_rotation_runbook == "1"),
      run_prod_upgrade_runbook: ($run_prod_upgrade_runbook == "1"),
      run_prod_operator_lifecycle_runbook: ($run_prod_operator_lifecycle_runbook == "1"),
      run_prod_pilot_runbook: ($run_prod_pilot_runbook == "1"),
      run_prod_pilot_cohort_runbook: ($run_prod_pilot_cohort_runbook == "1"),
      run_prod_pilot_cohort_signoff: ($run_prod_pilot_cohort_signoff == "1"),
      run_prod_pilot_cohort_quick_signoff: ($run_prod_pilot_cohort_quick_signoff == "1"),
      run_phase2_linux_prod_candidate_signoff: ($run_phase2_linux_prod_candidate_signoff == "1"),
      run_phase2_linux_prod_candidate_handoff_check: ($run_phase2_linux_prod_candidate_handoff_check == "1"),
      run_phase2_linux_prod_candidate_handoff_run: ($run_phase2_linux_prod_candidate_handoff_run == "1"),
      run_roadmap_progress_phase2_handoff: ($run_roadmap_progress_phase2_handoff == "1")
    },
    steps: $steps,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[ci-phase2-linux-prod-candidate] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[ci-phase2-linux-prod-candidate] reports_dir=$reports_dir"
echo "[ci-phase2-linux-prod-candidate] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
