#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase1_resilience_handoff_run.sh \
    [--reports-dir DIR] \
    [--ci-summary-json PATH] \
    [--handoff-summary-json PATH] \
    [--summary-json PATH] \
    [--allow-policy-no-go [0|1]] \
    [--resume [0|1]] \
    [--refresh-from-ci-summary [0|1]] \
    [--run-ci-phase1-resilience [0|1]] \
    [--run-phase1-resilience-handoff-check [0|1]] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--ci-<arg> ...] \
    [--handoff-<arg> ...]

Purpose:
  One-command Phase-1 resilience + handoff check runner:
    1) ci_phase1_resilience.sh
    2) phase1_resilience_handoff_check(.sh)

Notes:
  - Wrapper-owned flags are reserved; stage pass-through uses prefixes:
      --ci-...       -> forwarded to ci_phase1_resilience.sh
      --handoff-...  -> forwarded to phase1_resilience_handoff_check(.sh)
  - Dry-run forwards --dry-run 1 to ci_phase1_resilience only.
    Handoff check still executes against generated summaries.
  - Resume mode (--resume 1) reuses pass summaries for ci + handoff-check
    stages when available in the same reports directory.
  - Refresh mode (--refresh-from-ci-summary 1) skips ci stage and runs only
    handoff-check against an existing ci summary artifact.
  - Summary contract checks are always enforced (including dry-run).
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

json_file_valid() {
  local path="$1"
  [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1
}

ci_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    type == "object"
    and (.schema | type) == "object"
    and (.schema.id // "") == "ci_phase1_resilience_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) | floor) == (.schema.major // 0)
    and (.status | type) == "string"
    and (.rc | type) == "number"
  ' "$path" >/dev/null 2>&1
}

handoff_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    type == "object"
    and (.status | type) == "string"
    and (.rc | type) == "number"
  ' "$path" >/dev/null 2>&1
}

summary_pass_contract_valid() {
  local path="$1"
  local contract_fn="$2"
  if ! "$contract_fn" "$path"; then
    return 1
  fi
  jq -e '
    (.status | type) == "string"
    and .status == "pass"
    and (.rc | type) == "number"
    and .rc == 0
  ' "$path" >/dev/null 2>&1
}

run_step_capture() {
  local step="$1"
  local log_path="$2"
  shift 2
  local rc=0
  echo "[phase1-resilience-handoff-run] step=$step status=running"
  set +e
  "$@" >"$log_path" 2>&1
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "[phase1-resilience-handoff-run] step=$step status=pass rc=0"
  else
    echo "[phase1-resilience-handoff-run] step=$step status=fail rc=$rc"
  fi
  return "$rc"
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${PHASE1_RESILIENCE_HANDOFF_RUN_REPORTS_DIR:-}"
ci_summary_json="${PHASE1_RESILIENCE_HANDOFF_RUN_CI_SUMMARY_JSON:-}"
handoff_summary_json="${PHASE1_RESILIENCE_HANDOFF_RUN_HANDOFF_SUMMARY_JSON:-}"
summary_json="${PHASE1_RESILIENCE_HANDOFF_RUN_SUMMARY_JSON:-}"
print_summary_json="${PHASE1_RESILIENCE_HANDOFF_RUN_PRINT_SUMMARY_JSON:-1}"
allow_policy_no_go="${PHASE1_RESILIENCE_HANDOFF_RUN_ALLOW_POLICY_NO_GO:-0}"
resume="${PHASE1_RESILIENCE_HANDOFF_RUN_RESUME:-0}"
dry_run="${PHASE1_RESILIENCE_HANDOFF_RUN_DRY_RUN:-0}"
run_ci_phase1_resilience="${PHASE1_RESILIENCE_HANDOFF_RUN_RUN_CI_PHASE1_RESILIENCE:-1}"
run_phase1_resilience_handoff_check="${PHASE1_RESILIENCE_HANDOFF_RUN_RUN_PHASE1_RESILIENCE_HANDOFF_CHECK:-1}"
refresh_from_ci_summary="${PHASE1_RESILIENCE_HANDOFF_RUN_REFRESH_FROM_CI_SUMMARY:-0}"

declare -a ci_passthrough_args=()
declare -a handoff_passthrough_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --ci-summary-json)
      ci_summary_json="${2:-}"
      shift 2
      ;;
    --handoff-summary-json)
      handoff_summary_json="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --allow-policy-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_policy_no_go="${2:-}"
        shift 2
      else
        allow_policy_no_go="1"
        shift
      fi
      ;;
    --resume)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        resume="${2:-}"
        shift 2
      else
        resume="1"
        shift
      fi
      ;;
    --run-ci-phase1-resilience)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_ci_phase1_resilience="${2:-}"
        shift 2
      else
        run_ci_phase1_resilience="1"
        shift
      fi
      ;;
    --refresh-from-ci-summary)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_from_ci_summary="${2:-}"
        shift 2
      else
        refresh_from_ci_summary="1"
        shift
      fi
      ;;
    --run-phase1-resilience-handoff-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase1_resilience_handoff_check="${2:-}"
        shift 2
      else
        run_phase1_resilience_handoff_check="1"
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
    --ci-*)
      forwarded_flag="--${1#--ci-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid ci-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        ci_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        ci_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    --handoff-*)
      forwarded_flag="--${1#--handoff-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid handoff-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        handoff_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        handoff_passthrough_args+=("$forwarded_flag")
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

bool_arg_or_die "--run-ci-phase1-resilience" "$run_ci_phase1_resilience"
bool_arg_or_die "--run-phase1-resilience-handoff-check" "$run_phase1_resilience_handoff_check"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--allow-policy-no-go" "$allow_policy_no_go"
bool_arg_or_die "--resume" "$resume"
bool_arg_or_die "--dry-run" "$dry_run"
bool_arg_or_die "--refresh-from-ci-summary" "$refresh_from_ci_summary"

if [[ "$refresh_from_ci_summary" == "1" ]]; then
  if [[ "$run_ci_phase1_resilience" == "1" ]]; then
    run_ci_phase1_resilience="0"
    echo "[phase1-resilience-handoff-run] refresh-from-ci-summary enabled; forcing run-ci-phase1-resilience=0"
  fi
  if [[ "$run_phase1_resilience_handoff_check" != "1" ]]; then
    echo "--refresh-from-ci-summary requires --run-phase1-resilience-handoff-check 1"
    exit 2
  fi
fi

ci_script="${PHASE1_RESILIENCE_HANDOFF_RUN_CI_SCRIPT:-$ROOT_DIR/scripts/ci_phase1_resilience.sh}"
handoff_check_script="${PHASE1_RESILIENCE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT:-}"
if [[ -z "$handoff_check_script" ]]; then
  if [[ -x "$ROOT_DIR/scripts/phase1_resilience_handoff_check.sh" ]]; then
    handoff_check_script="$ROOT_DIR/scripts/phase1_resilience_handoff_check.sh"
  elif [[ -x "$ROOT_DIR/scripts/phase1_resilience_handoff_check" ]]; then
    handoff_check_script="$ROOT_DIR/scripts/phase1_resilience_handoff_check"
  else
    handoff_check_script="$ROOT_DIR/scripts/phase1_resilience_handoff_check.sh"
  fi
fi

if [[ "$run_ci_phase1_resilience" == "1" && ! -x "$ci_script" ]]; then
  echo "missing executable stage script: $ci_script"
  exit 2
fi
if [[ "$run_phase1_resilience_handoff_check" == "1" && ! -x "$handoff_check_script" ]]; then
  echo "missing executable stage script: $handoff_check_script"
  exit 2
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/phase1_resilience_handoff_run_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$ci_summary_json" ]]; then
  ci_summary_json="$reports_dir/ci_phase1_resilience_summary.json"
else
  ci_summary_json="$(abs_path "$ci_summary_json")"
fi
if [[ -z "$handoff_summary_json" ]]; then
  handoff_summary_json="$reports_dir/phase1_resilience_handoff_check_summary.json"
else
  handoff_summary_json="$(abs_path "$handoff_summary_json")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/phase1_resilience_handoff_run_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi

ci_reports_dir="$reports_dir/ci_phase1_resilience"
ci_log="$reports_dir/ci_phase1_resilience.log"
handoff_log="$reports_dir/phase1_resilience_handoff_check.log"

mkdir -p "$reports_dir"
mkdir -p "$ci_reports_dir"
mkdir -p "$(dirname "$ci_summary_json")" "$(dirname "$handoff_summary_json")" "$(dirname "$summary_json")"

if [[ "$refresh_from_ci_summary" == "1" ]]; then
  if ! ci_summary_contract_valid "$ci_summary_json"; then
    echo "refresh-from-ci-summary requires an existing valid ci summary: $ci_summary_json"
    exit 2
  fi
  if [[ "$resume" == "1" ]]; then
    echo "[phase1-resilience-handoff-run] refresh-from-ci-summary enabled; ignoring resume for handoff-check stage"
  fi
fi

ci_cmd=(
  "$ci_script"
  --reports-dir "$ci_reports_dir"
  --summary-json "$ci_summary_json"
  --print-summary-json 0
)
if [[ "$allow_policy_no_go" == "1" ]]; then
  ci_cmd+=(--allow-policy-no-go 1)
fi
if [[ "$dry_run" == "1" ]]; then
  ci_cmd+=(--dry-run 1)
fi
if [[ ${#ci_passthrough_args[@]} -gt 0 ]]; then
  ci_cmd+=("${ci_passthrough_args[@]}")
fi

handoff_cmd=(
  "$handoff_check_script"
  --ci-phase1-summary-json "$ci_summary_json"
  --summary-json "$handoff_summary_json"
  --show-json 0
)
if [[ "$dry_run" == "1" ]]; then
  # ci_phase1 dry-run skips runtime-only stages by design; avoid false gate
  # failures from an intentionally skipped churn-guard stage.
  handoff_cmd+=(--require-session-churn-guard-ok 0)
fi
if [[ ${#handoff_passthrough_args[@]} -gt 0 ]]; then
  handoff_cmd+=("${handoff_passthrough_args[@]}")
fi

ci_status="skip"
ci_rc=0
ci_command_rc=0
ci_contract_valid="null"
ci_contract_error=""
ci_command=""
ci_reused_artifact="false"

handoff_status="skip"
handoff_rc=0
handoff_command_rc=0
handoff_contract_valid="null"
handoff_contract_error=""
handoff_command=""
handoff_reused_artifact="false"

if [[ "$run_ci_phase1_resilience" == "1" ]]; then
  ci_command="$(print_cmd "${ci_cmd[@]}")"
  if [[ "$resume" == "1" ]] && summary_pass_contract_valid "$ci_summary_json" ci_summary_contract_valid; then
    echo "[phase1-resilience-handoff-run] step=ci_phase1_resilience status=pass rc=0 reason=resume-artifact-pass"
    ci_status="pass"
    ci_rc=0
    ci_command_rc=0
    ci_contract_valid="true"
    ci_contract_error=""
    ci_reused_artifact="true"
  else
    if run_step_capture "ci_phase1_resilience" "$ci_log" "${ci_cmd[@]}"; then
      ci_command_rc=0
    else
      ci_command_rc=$?
    fi
    if ci_summary_contract_valid "$ci_summary_json"; then
      ci_contract_valid="true"
      ci_contract_error=""
    else
      ci_contract_valid="false"
      ci_contract_error="missing_or_invalid_ci_phase1_summary_contract"
    fi
    if (( ci_command_rc == 0 )) && [[ "$ci_contract_valid" == "true" ]]; then
      ci_status="pass"
      ci_rc=0
    elif (( ci_command_rc != 0 )); then
      ci_status="fail"
      ci_rc=$ci_command_rc
    else
      ci_status="fail"
      ci_rc=3
    fi
  fi
else
  if [[ "$refresh_from_ci_summary" == "1" ]]; then
    echo "[phase1-resilience-handoff-run] step=ci_phase1_resilience status=skip reason=refresh-from-ci-summary"
  else
    echo "[phase1-resilience-handoff-run] step=ci_phase1_resilience status=skip reason=disabled"
  fi
fi

if [[ "$run_phase1_resilience_handoff_check" == "1" ]]; then
  handoff_command="$(print_cmd "${handoff_cmd[@]}")"
  if [[ "$resume" == "1" && "$refresh_from_ci_summary" != "1" ]] && summary_pass_contract_valid "$handoff_summary_json" handoff_summary_contract_valid; then
    echo "[phase1-resilience-handoff-run] step=phase1_resilience_handoff_check status=pass rc=0 reason=resume-artifact-pass"
    handoff_status="pass"
    handoff_rc=0
    handoff_command_rc=0
    handoff_contract_valid="true"
    handoff_contract_error=""
    handoff_reused_artifact="true"
  else
    if run_step_capture "phase1_resilience_handoff_check" "$handoff_log" "${handoff_cmd[@]}"; then
      handoff_command_rc=0
    else
      handoff_command_rc=$?
    fi
    if handoff_summary_contract_valid "$handoff_summary_json"; then
      handoff_contract_valid="true"
      handoff_contract_error=""
    else
      handoff_contract_valid="false"
      handoff_contract_error="missing_or_invalid_handoff_check_summary_contract"
    fi
    if (( handoff_command_rc == 0 )) && [[ "$handoff_contract_valid" == "true" ]]; then
      handoff_status="pass"
      handoff_rc=0
    elif (( handoff_command_rc != 0 )); then
      handoff_status="fail"
      handoff_rc=$handoff_command_rc
    else
      handoff_status="fail"
      handoff_rc=3
    fi
  fi
else
  echo "[phase1-resilience-handoff-run] step=phase1_resilience_handoff_check status=skip reason=disabled"
fi

final_rc=0
if [[ "$run_ci_phase1_resilience" == "1" ]] && (( ci_rc != 0 )) && (( final_rc == 0 )); then
  final_rc=$ci_rc
fi
if [[ "$run_phase1_resilience_handoff_check" == "1" ]] && (( handoff_rc != 0 )) && (( final_rc == 0 )); then
  final_rc=$handoff_rc
fi

final_status="pass"
if (( final_rc != 0 )); then
  final_status="fail"
fi

ci_summary_exists="false"
if [[ -f "$ci_summary_json" ]]; then
  ci_summary_exists="true"
fi
handoff_summary_exists="false"
if [[ -f "$handoff_summary_json" ]]; then
  handoff_summary_exists="true"
fi

ci_passthrough_json="$(printf '%s\n' "${ci_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
handoff_passthrough_json="$(printf '%s\n' "${handoff_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg allow_policy_no_go "$allow_policy_no_go" \
  --arg resume "$resume" \
  --arg dry_run "$dry_run" \
  --arg refresh_from_ci_summary "$refresh_from_ci_summary" \
  --arg print_summary_json "$print_summary_json" \
  --arg run_ci_phase1_resilience "$run_ci_phase1_resilience" \
  --arg run_phase1_resilience_handoff_check "$run_phase1_resilience_handoff_check" \
  --argjson ci_passthrough_args "$ci_passthrough_json" \
  --argjson handoff_passthrough_args "$handoff_passthrough_json" \
  --arg ci_status "$ci_status" \
  --argjson ci_rc "$ci_rc" \
  --argjson ci_command_rc "$ci_command_rc" \
  --arg ci_command "$ci_command" \
  --arg ci_contract_valid "$ci_contract_valid" \
  --arg ci_contract_error "$ci_contract_error" \
  --arg ci_summary_json "$ci_summary_json" \
  --arg ci_summary_exists "$ci_summary_exists" \
  --arg ci_log "$ci_log" \
  --arg ci_reused_artifact "$ci_reused_artifact" \
  --arg handoff_status "$handoff_status" \
  --argjson handoff_rc "$handoff_rc" \
  --argjson handoff_command_rc "$handoff_command_rc" \
  --arg handoff_command "$handoff_command" \
  --arg handoff_contract_valid "$handoff_contract_valid" \
  --arg handoff_contract_error "$handoff_contract_error" \
  --arg handoff_summary_json "$handoff_summary_json" \
  --arg handoff_summary_exists "$handoff_summary_exists" \
  --arg handoff_log "$handoff_log" \
  --arg handoff_reused_artifact "$handoff_reused_artifact" \
  '{
    version: 1,
    schema: {
      id: "phase1_resilience_handoff_run_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    automation: {
      track: "non_blockchain",
      requires_sudo: false,
      requires_github: false,
      automatable_without_sudo_or_github: true
    },
    inputs: {
      allow_policy_no_go: ($allow_policy_no_go == "1"),
      resume: ($resume == "1"),
      dry_run: ($dry_run == "1"),
      refresh_from_ci_summary: ($refresh_from_ci_summary == "1"),
      print_summary_json: ($print_summary_json == "1"),
      run_ci_phase1_resilience: ($run_ci_phase1_resilience == "1"),
      run_phase1_resilience_handoff_check: ($run_phase1_resilience_handoff_check == "1"),
      ci_passthrough_args: $ci_passthrough_args,
      handoff_passthrough_args: $handoff_passthrough_args
    },
    steps: {
      ci_phase1_resilience: {
        enabled: ($run_ci_phase1_resilience == "1"),
        status: $ci_status,
        rc: $ci_rc,
        command_rc: $ci_command_rc,
        command: (if $ci_command == "" then null else $ci_command end),
        reused_artifact: ($ci_reused_artifact == "true"),
        contract_valid: (
          if $ci_contract_valid == "null" then null
          else ($ci_contract_valid == "true")
          end
        ),
        contract_error: (if $ci_contract_error == "" then null else $ci_contract_error end),
        artifacts: {
          summary_json: $ci_summary_json,
          summary_exists: ($ci_summary_exists == "true"),
          log: $ci_log
        }
      },
      phase1_resilience_handoff_check: {
        enabled: ($run_phase1_resilience_handoff_check == "1"),
        status: $handoff_status,
        rc: $handoff_rc,
        command_rc: $handoff_command_rc,
        command: (if $handoff_command == "" then null else $handoff_command end),
        reused_artifact: ($handoff_reused_artifact == "true"),
        contract_valid: (
          if $handoff_contract_valid == "null" then null
          else ($handoff_contract_valid == "true")
          end
        ),
        contract_error: (if $handoff_contract_error == "" then null else $handoff_contract_error end),
        artifacts: {
          summary_json: $handoff_summary_json,
          summary_exists: ($handoff_summary_exists == "true"),
          log: $handoff_log
        }
      }
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      ci_summary_json: $ci_summary_json,
      handoff_summary_json: $handoff_summary_json,
      ci_log: $ci_log,
      handoff_log: $handoff_log
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[phase1-resilience-handoff-run] status=$final_status rc=$final_rc dry_run=$dry_run refresh_from_ci_summary=$refresh_from_ci_summary"
echo "[phase1-resilience-handoff-run] reports_dir=$reports_dir"
echo "[phase1-resilience-handoff-run] ci_summary_json=$ci_summary_json"
echo "[phase1-resilience-handoff-run] handoff_summary_json=$handoff_summary_json"
echo "[phase1-resilience-handoff-run] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
