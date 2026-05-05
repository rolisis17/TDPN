#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase2_linux_prod_candidate_run.sh \
    [--reports-dir DIR] \
    [--ci-summary-json PATH] \
    [--check-summary-json PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--ci-<arg> ...] \
    [--check-<arg> ...]

Purpose:
  One-command Phase-2 Linux production-candidate runner:
    1) ci_phase2_linux_prod_candidate.sh
    2) phase2_linux_prod_candidate_check.sh

Notes:
  - Wrapper-owned flags are reserved; stage pass-through uses prefixes:
      --ci-...     -> forwarded to ci_phase2_linux_prod_candidate.sh
      --check-...  -> forwarded to phase2_linux_prod_candidate_check.sh
  - Dry-run forwards --dry-run 1 to ci_phase2 only.
    The checker still runs against the generated CI summary.
  - The checker receives --show-json 0 by default unless explicitly supplied
    via a --check-show-json flag.
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
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (
      (.schema.id // "") == "ci_phase2_linux_prod_candidate_summary"
      or (.schema.id // "") == "ci_phase2_summary"
    )
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) | floor) == (.schema.major // 0)
    and (.status | type) == "string"
    and (.rc | type) == "number"
    and (((.status == "pass") and (.rc == 0)) or ((.status != "pass") and (.rc != 0)))
  ' "$path" >/dev/null 2>&1
}

check_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    type == "object"
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (.schema.id // "") == "phase2_linux_prod_candidate_check_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) | floor) == (.schema.major // 0)
    and (.status | type) == "string"
    and (.rc | type) == "number"
    and (((.status == "pass") and (.rc == 0)) or ((.status != "pass") and (.rc != 0)))
  ' "$path" >/dev/null 2>&1
}

run_step_capture() {
  local label="$1"
  local log_path="$2"
  shift 2
  local rc=0
  echo "[phase2-linux-prod-candidate-run] step=$label status=running"
  set +e
  "$@" >"$log_path" 2>&1
  rc=$?
  if (( rc == 0 )); then
    echo "[phase2-linux-prod-candidate-run] step=$label status=pass rc=0"
  else
    echo "[phase2-linux-prod-candidate-run] step=$label status=fail rc=$rc"
  fi
  return "$rc"
}

array_has_arg() {
  local needle="$1"
  shift
  local arg
  for arg in "$@"; do
    if [[ "$arg" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${PHASE2_LINUX_PROD_CANDIDATE_RUN_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
ci_summary_json="${PHASE2_LINUX_PROD_CANDIDATE_RUN_CI_SUMMARY_JSON:-$reports_dir/phase2_linux_prod_candidate_ci_summary.json}"
check_summary_json="${PHASE2_LINUX_PROD_CANDIDATE_RUN_CHECK_SUMMARY_JSON:-$reports_dir/phase2_linux_prod_candidate_check_summary.json}"
summary_json="${PHASE2_LINUX_PROD_CANDIDATE_RUN_SUMMARY_JSON:-$reports_dir/phase2_linux_prod_candidate_run_summary.json}"
print_summary_json="${PHASE2_LINUX_PROD_CANDIDATE_RUN_PRINT_SUMMARY_JSON:-1}"
dry_run="${PHASE2_LINUX_PROD_CANDIDATE_RUN_DRY_RUN:-0}"

declare -a ci_passthrough_args=()
declare -a check_passthrough_args=()

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
    --check-summary-json)
      check_summary_json="${2:-}"
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
    --ci-summary-json|--check-summary-json)
      echo "reserved wrapper arg: $1"
      exit 2
      ;;
    --ci-dry-run)
      echo "reserved wrapper arg: --ci-dry-run; use --dry-run"
      exit 2
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
    --check-*)
      forwarded_flag="--${1#--check-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid check-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        check_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        check_passthrough_args+=("$forwarded_flag")
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

bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--dry-run" "$dry_run"

reports_dir="$(abs_path "$reports_dir")"
ci_summary_json="$(abs_path "$ci_summary_json")"
check_summary_json="$(abs_path "$check_summary_json")"
summary_json="$(abs_path "$summary_json")"

mkdir -p "$reports_dir" "$(dirname "$ci_summary_json")" "$(dirname "$check_summary_json")" "$(dirname "$summary_json")"

ci_script="${PHASE2_LINUX_PROD_CANDIDATE_RUN_CI_SCRIPT:-$ROOT_DIR/scripts/ci_phase2_linux_prod_candidate.sh}"
check_script="${PHASE2_LINUX_PROD_CANDIDATE_RUN_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_check.sh}"

if [[ ! -x "$ci_script" ]]; then
  echo "missing executable stage script: $ci_script"
  exit 2
fi
if [[ ! -x "$check_script" ]]; then
  echo "missing executable stage script: $check_script"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ci_log="$TMP_DIR/ci_phase2.log"
check_log="$TMP_DIR/check.log"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

declare ci_command_rc=0
declare check_command_rc=0
declare ci_contract_valid=0
declare check_contract_valid=0
declare ci_status="skipped"
declare check_status="skipped"
declare ci_rc=0
declare check_rc=0
declare ci_contract_error=""
declare check_contract_error=""
declare ci_command=""
declare check_command=""

ci_command_args=("$ci_script")
if [[ "$dry_run" == "1" ]]; then
  ci_command_args+=(--dry-run 1)
fi
ci_command_args+=(--summary-json "$ci_summary_json")
if ((${#ci_passthrough_args[@]} > 0)); then
  ci_command_args+=("${ci_passthrough_args[@]}")
fi
ci_command="$(print_cmd "${ci_command_args[@]}")"
set +e
run_step_capture "ci_phase2" "$ci_log" "${ci_command_args[@]}"
ci_command_rc=$?
set -e
if ci_summary_contract_valid "$ci_summary_json"; then
  ci_contract_valid=1
  ci_status="$(jq -r '.status // "fail"' "$ci_summary_json" 2>/dev/null || echo "fail")"
  ci_rc="$(jq -r '.rc // 0' "$ci_summary_json" 2>/dev/null || echo 0)"
  if [[ "$ci_command_rc" -ne 0 ]]; then
    ci_status="fail"
    ci_rc="$ci_command_rc"
  fi
else
  ci_contract_valid=0
  ci_contract_error="missing or invalid ci_phase2 summary contract"
  ci_status="fail"
  if [[ "$ci_command_rc" -ne 0 ]]; then
    ci_rc="$ci_command_rc"
  else
    ci_rc=3
  fi
fi

check_command_args=("$check_script" --ci-phase2-summary-json "$ci_summary_json" --summary-json "$check_summary_json")
if ((${#check_passthrough_args[@]} > 0)); then
  check_command_args+=("${check_passthrough_args[@]}")
fi
if ! array_has_arg "--show-json" "${check_command_args[@]:1}"; then
  check_command_args+=(--show-json 0)
fi
if [[ "$dry_run" == "1" ]]; then
  if ! array_has_arg "--require-release-integrity-ok" "${check_command_args[@]:1}"; then
    check_command_args+=(--require-release-integrity-ok 0)
  fi
  if ! array_has_arg "--require-release-policy-ok" "${check_command_args[@]:1}"; then
    check_command_args+=(--require-release-policy-ok 0)
  fi
  if ! array_has_arg "--require-operator-lifecycle-ok" "${check_command_args[@]:1}"; then
    check_command_args+=(--require-operator-lifecycle-ok 0)
  fi
  if ! array_has_arg "--require-pilot-signoff-ok" "${check_command_args[@]:1}"; then
    check_command_args+=(--require-pilot-signoff-ok 0)
  fi
fi
check_command="$(print_cmd "${check_command_args[@]}")"
set +e
run_step_capture "phase2_linux_prod_candidate_check" "$check_log" "${check_command_args[@]}"
check_command_rc=$?
set -e
if check_summary_contract_valid "$check_summary_json"; then
  check_contract_valid=1
  check_status="$(jq -r '.status // "fail"' "$check_summary_json" 2>/dev/null || echo "fail")"
  check_rc="$(jq -r '.rc // 0' "$check_summary_json" 2>/dev/null || echo 0)"
  if [[ "$check_command_rc" -ne 0 ]]; then
    check_status="fail"
    check_rc="$check_command_rc"
  fi
else
  check_contract_valid=0
  check_contract_error="missing or invalid phase2 Linux prod-candidate check summary contract"
  check_status="fail"
  if [[ "$check_command_rc" -ne 0 ]]; then
    check_rc="$check_command_rc"
  else
    check_rc=3
  fi
fi

final_status="pass"
final_rc=0
if [[ "$ci_status" != "pass" ]]; then
  final_status="fail"
  final_rc="$ci_rc"
elif [[ "$check_status" != "pass" ]]; then
  final_status="fail"
  final_rc="$check_rc"
fi

if [[ "$ci_status" != "pass" || "$check_status" != "pass" ]]; then
  final_status="fail"
fi
if [[ "$final_status" != "pass" && "$final_rc" -eq 0 ]]; then
  final_rc=1
fi

decision_reason_details_json='[]'
decision_warning_details_json='[]'

append_decision_reason() {
  local code="$1"
  local step="$2"
  local message="$3"
  local status="$4"
  local rc="$5"
  decision_reason_details_json="$(
    jq -cn \
      --argjson arr "$decision_reason_details_json" \
      --arg code "$code" \
      --arg step "$step" \
      --arg message "$message" \
      --arg status "$status" \
      --argjson rc "$rc" \
      '$arr + [{
        code: $code,
        step: $step,
        message: $message,
        status: $status,
        rc: $rc
      }]'
  )"
}

if [[ "$ci_contract_valid" != "1" ]]; then
  append_decision_reason \
    "ci_summary_contract_invalid" \
    "ci_phase2" \
    "ci phase2 summary contract is invalid or missing" \
    "$ci_status" \
    "$ci_rc"
fi
if [[ "$ci_status" != "pass" ]]; then
  append_decision_reason \
    "ci_step_not_pass" \
    "ci_phase2" \
    "ci phase2 step did not pass" \
    "$ci_status" \
    "$ci_rc"
fi
if [[ "$check_contract_valid" != "1" ]]; then
  append_decision_reason \
    "check_summary_contract_invalid" \
    "phase2_linux_prod_candidate_check" \
    "phase2 check summary contract is invalid or missing" \
    "$check_status" \
    "$check_rc"
fi
if [[ "$check_status" != "pass" ]]; then
  append_decision_reason \
    "check_step_not_pass" \
    "phase2_linux_prod_candidate_check" \
    "phase2 check step did not pass" \
    "$check_status" \
    "$check_rc"
fi

decision_reasons_json="$(
  jq -cn --argjson details "$decision_reason_details_json" '[ $details[] | .message ]'
)"
decision_warnings_json="$(
  jq -cn --argjson details "$decision_warning_details_json" '[ $details[] | .message ]'
)"

ci_summary_exists="0"
check_summary_exists="0"
if [[ -f "$ci_summary_json" ]]; then
  ci_summary_exists="1"
fi
if [[ -f "$check_summary_json" ]]; then
  check_summary_exists="1"
fi

summary_tmp="$(mktemp)"
jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg ci_summary_json "$ci_summary_json" \
  --arg check_summary_json "$check_summary_json" \
  --arg dry_run "$dry_run" \
  --arg print_summary_json "$print_summary_json" \
  --arg ci_command "$ci_command" \
  --arg check_command "$check_command" \
  --arg ci_status "$ci_status" \
  --arg check_status "$check_status" \
  --argjson ci_command_rc "$ci_command_rc" \
  --argjson check_command_rc "$check_command_rc" \
  --argjson ci_rc "$ci_rc" \
  --argjson check_rc "$check_rc" \
  --argjson ci_contract_valid "$ci_contract_valid" \
  --argjson check_contract_valid "$check_contract_valid" \
  --arg ci_contract_error "$ci_contract_error" \
  --arg check_contract_error "$check_contract_error" \
  --argjson ci_summary_exists "$ci_summary_exists" \
  --argjson check_summary_exists "$check_summary_exists" \
  --argjson decision_reasons "$decision_reasons_json" \
  --argjson decision_reason_details "$decision_reason_details_json" \
  --argjson decision_warnings "$decision_warnings_json" \
  --argjson decision_warning_details "$decision_warning_details_json" \
  '{
    version: 1,
    schema: {
      id: "phase2_linux_prod_candidate_run_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    metadata: {
      contract: "phase2-linux-production-candidate",
      runner_script: "phase2_linux_prod_candidate_run.sh"
    },
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      dry_run: ($dry_run == "1"),
      print_summary_json: ($print_summary_json == "1")
    },
    steps: {
      ci_phase2: {
        enabled: true,
        status: $ci_status,
        rc: $ci_rc,
        command_rc: $ci_command_rc,
        command: (if $ci_command == "" then null else $ci_command end),
        contract_valid: ($ci_contract_valid == 1),
        contract_error: (if $ci_contract_error == "" then null else $ci_contract_error end),
        artifacts: {
          summary_json: $ci_summary_json,
          summary_exists: ($ci_summary_exists == 1)
        }
      },
      phase2_linux_prod_candidate_check: {
        enabled: true,
        status: $check_status,
        rc: $check_rc,
        command_rc: $check_command_rc,
        command: (if $check_command == "" then null else $check_command end),
        contract_valid: ($check_contract_valid == 1),
        contract_error: (if $check_contract_error == "" then null else $check_contract_error end),
        artifacts: {
          summary_json: $check_summary_json,
          summary_exists: ($check_summary_exists == 1)
        }
      }
    },
    decision: {
      pass: ($status == "pass"),
      reasons: $decision_reasons,
      reason_details: $decision_reason_details,
      reason_codes: ($decision_reason_details | map(.code) | unique),
      warnings: $decision_warnings,
      warning_details: $decision_warning_details,
      warning_codes: ($decision_warning_details | map(.code) | unique)
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      ci_summary_json: $ci_summary_json,
      check_summary_json: $check_summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[phase2-linux-prod-candidate-run] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[phase2-linux-prod-candidate-run] reports_dir=$reports_dir"
echo "[phase2-linux-prod-candidate-run] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
