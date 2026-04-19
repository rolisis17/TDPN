#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase6_cosmos_l1_build_testnet_suite.sh \
    [--reports-dir DIR] \
    [--ci-summary-json PATH] \
    [--run-summary-json PATH] \
    [--handoff-run-summary-json PATH] \
    [--summary-json PATH] \
    [--run-ci-phase6-cosmos-l1-build-testnet [0|1]] \
    [--run-phase6-cosmos-l1-build-testnet-run [0|1]] \
    [--run-phase6-cosmos-l1-build-testnet-handoff-run [0|1]] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--ci-<arg> ...] \
    [--run-<arg> ...] \
    [--handoff-run-<arg> ...]

Purpose:
  Top-level Phase-6 Cosmos L1 build/testnet suite:
    1) ci_phase6_cosmos_l1_build_testnet.sh
    2) phase6_cosmos_l1_build_testnet_run.sh
    3) phase6_cosmos_l1_build_testnet_handoff_run.sh

Notes:
  - Child summaries are validated fail-closed against expected schema contracts.
  - Dry-run forwards --dry-run 1 to each enabled wrapper stage.
  - Stage pass-through uses reserved prefixes:
      --ci-...           -> ci_phase6_cosmos_l1_build_testnet.sh
      --run-...          -> phase6_cosmos_l1_build_testnet_run.sh
      --handoff-run-...  -> phase6_cosmos_l1_build_testnet_handoff_run.sh
  - When suite run stage is enabled, the handoff-run stage defaults to
    --run-phase6-cosmos-l1-build-testnet-run 0 unless explicitly overridden,
    avoiding duplicate nested run execution.
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
    and (.schema.id // "") == "ci_phase6_cosmos_l1_build_testnet_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) | floor) == (.schema.major // 0)
    and (.status | type) == "string"
    and (.rc | type) == "number"
    and (((.status == "pass") and (.rc == 0)) or ((.status != "pass") and (.rc != 0)))
  ' "$path" >/dev/null 2>&1
}

run_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    type == "object"
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (.schema.id // "") == "phase6_cosmos_l1_build_testnet_run_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) | floor) == (.schema.major // 0)
    and (.status | type) == "string"
    and (.rc | type) == "number"
    and (.steps.ci_phase6_cosmos_l1_build_testnet | type) == "object"
    and (.steps.phase6_cosmos_l1_build_testnet_check | type) == "object"
    and ((.steps.ci_phase6_cosmos_l1_build_testnet.status | type) == "string")
    and ((.steps.ci_phase6_cosmos_l1_build_testnet.rc | type) == "number")
    and ((.steps.ci_phase6_cosmos_l1_build_testnet.command_rc | type) == "number")
    and ((.steps.ci_phase6_cosmos_l1_build_testnet.contract_valid | type) == "boolean")
    and ((.steps.phase6_cosmos_l1_build_testnet_check.status | type) == "string")
    and ((.steps.phase6_cosmos_l1_build_testnet_check.rc | type) == "number")
    and ((.steps.phase6_cosmos_l1_build_testnet_check.command_rc | type) == "number")
    and ((.steps.phase6_cosmos_l1_build_testnet_check.contract_valid | type) == "boolean")
    and (
      (.status == "pass" and .rc == 0)
      or (.status == "fail" and .rc != 0)
    )
  ' "$path" >/dev/null 2>&1
}

handoff_run_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    type == "object"
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (.schema.id // "") == "phase6_cosmos_l1_build_testnet_handoff_run_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) | floor) == (.schema.major // 0)
    and (.status | type) == "string"
    and (.rc | type) == "number"
    and (.steps.phase6_cosmos_l1_build_testnet_run | type) == "object"
    and (.steps.phase6_cosmos_l1_build_testnet_handoff_check | type) == "object"
    and ((.steps.phase6_cosmos_l1_build_testnet_run.status | type) == "string")
    and ((.steps.phase6_cosmos_l1_build_testnet_run.rc | type) == "number")
    and ((.steps.phase6_cosmos_l1_build_testnet_run.command_rc | type) == "number")
    and ((.steps.phase6_cosmos_l1_build_testnet_run.contract_valid | type) == "boolean")
    and ((.steps.phase6_cosmos_l1_build_testnet_handoff_check.status | type) == "string")
    and ((.steps.phase6_cosmos_l1_build_testnet_handoff_check.rc | type) == "number")
    and ((.steps.phase6_cosmos_l1_build_testnet_handoff_check.command_rc | type) == "number")
    and ((.steps.phase6_cosmos_l1_build_testnet_handoff_check.contract_valid | type) == "boolean")
    and (
      (.status == "pass" and .rc == 0)
      or (.status == "fail" and .rc != 0)
    )
  ' "$path" >/dev/null 2>&1
}

run_stage_capture() {
  local label="$1"
  local log_path="$2"
  shift 2
  local rc=0
  echo "[phase6-cosmos-l1-build-testnet-suite] stage=$label status=running"
  set +e
  "$@" >"$log_path" 2>&1
  rc=$?
  if (( rc == 0 )); then
    echo "[phase6-cosmos-l1-build-testnet-suite] stage=$label status=pass rc=0"
  else
    echo "[phase6-cosmos-l1-build-testnet-suite] stage=$label status=fail rc=$rc"
  fi
  return "$rc"
}

need_cmd jq
need_cmd date
need_cmd mktemp
need_cmd cp

reports_dir="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
ci_summary_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_CI_SUMMARY_JSON:-$reports_dir/phase6_cosmos_l1_build_testnet_ci_summary.json}"
run_summary_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_RUN_SUMMARY_JSON:-$reports_dir/phase6_cosmos_l1_build_testnet_run_summary.json}"
handoff_run_summary_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_HANDOFF_RUN_SUMMARY_JSON:-$reports_dir/phase6_cosmos_l1_build_testnet_handoff_run_summary.json}"
summary_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_SUMMARY_JSON:-$reports_dir/phase6_cosmos_l1_build_testnet_suite_summary.json}"
canonical_summary_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase6_cosmos_l1_build_testnet_suite_summary.json}"
print_summary_json="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_PRINT_SUMMARY_JSON:-1}"
dry_run="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_DRY_RUN:-0}"
run_ci_phase6_cosmos_l1_build_testnet="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_RUN_CI_PHASE6_COSMOS_L1_BUILD_TESTNET:-1}"
run_phase6_cosmos_l1_build_testnet_run="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_RUN_PHASE6_COSMOS_L1_BUILD_TESTNET_RUN:-1}"
run_phase6_cosmos_l1_build_testnet_handoff_run="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_RUN_PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN:-1}"

declare -a ci_passthrough_args=()
declare -a run_passthrough_args=()
declare -a handoff_run_passthrough_args=()

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
    --run-summary-json)
      run_summary_json="${2:-}"
      shift 2
      ;;
    --handoff-run-summary-json)
      handoff_run_summary_json="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --run-ci-phase6-cosmos-l1-build-testnet)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_ci_phase6_cosmos_l1_build_testnet="${2:-}"
        shift 2
      else
        run_ci_phase6_cosmos_l1_build_testnet="1"
        shift
      fi
      ;;
    --run-phase6-cosmos-l1-build-testnet-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase6_cosmos_l1_build_testnet_run="${2:-}"
        shift 2
      else
        run_phase6_cosmos_l1_build_testnet_run="1"
        shift
      fi
      ;;
    --run-phase6-cosmos-l1-build-testnet-handoff-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase6_cosmos_l1_build_testnet_handoff_run="${2:-}"
        shift 2
      else
        run_phase6_cosmos_l1_build_testnet_handoff_run="1"
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
    --run-*)
      forwarded_flag="--${1#--run-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid run-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        run_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        run_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    --handoff-run-*)
      forwarded_flag="--${1#--handoff-run-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid handoff-run-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        handoff_run_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        handoff_run_passthrough_args+=("$forwarded_flag")
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

bool_arg_or_die "--run-ci-phase6-cosmos-l1-build-testnet" "$run_ci_phase6_cosmos_l1_build_testnet"
bool_arg_or_die "--run-phase6-cosmos-l1-build-testnet-run" "$run_phase6_cosmos_l1_build_testnet_run"
bool_arg_or_die "--run-phase6-cosmos-l1-build-testnet-handoff-run" "$run_phase6_cosmos_l1_build_testnet_handoff_run"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--dry-run" "$dry_run"

reports_dir="$(abs_path "$reports_dir")"
ci_summary_json="$(abs_path "$ci_summary_json")"
run_summary_json="$(abs_path "$run_summary_json")"
handoff_run_summary_json="$(abs_path "$handoff_run_summary_json")"
summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"

mkdir -p "$reports_dir" \
  "$(dirname "$ci_summary_json")" \
  "$(dirname "$run_summary_json")" \
  "$(dirname "$handoff_run_summary_json")" \
  "$(dirname "$summary_json")" \
  "$(dirname "$canonical_summary_json")"

ci_script="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_CI_SCRIPT:-$ROOT_DIR/scripts/ci_phase6_cosmos_l1_build_testnet.sh}"
run_script="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_RUN_SCRIPT:-$ROOT_DIR/scripts/phase6_cosmos_l1_build_testnet_run.sh}"
handoff_run_script="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/phase6_cosmos_l1_build_testnet_handoff_run.sh}"

if [[ "$run_ci_phase6_cosmos_l1_build_testnet" == "1" && ! -x "$ci_script" ]]; then
  echo "missing executable stage script: $ci_script"
  exit 2
fi
if [[ "$run_phase6_cosmos_l1_build_testnet_run" == "1" && ! -x "$run_script" ]]; then
  echo "missing executable stage script: $run_script"
  exit 2
fi
if [[ "$run_phase6_cosmos_l1_build_testnet_handoff_run" == "1" && ! -x "$handoff_run_script" ]]; then
  echo "missing executable stage script: $handoff_run_script"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ci_log="$TMP_DIR/ci_phase6.log"
run_log="$TMP_DIR/phase6_run.log"
handoff_run_log="$TMP_DIR/phase6_handoff_run.log"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

declare ci_command_rc=0
declare run_command_rc=0
declare handoff_run_command_rc=0
declare ci_contract_valid=0
declare run_contract_valid=0
declare handoff_run_contract_valid=0
declare ci_status="skipped"
declare run_status="skipped"
declare handoff_run_status="skipped"
declare ci_rc=0
declare run_rc=0
declare handoff_run_rc=0
declare ci_contract_error=""
declare run_contract_error=""
declare handoff_run_contract_error=""
declare ci_command=""
declare run_command=""
declare handoff_run_command=""

declare -a ci_cmd=(
  "$ci_script"
  --reports-dir "$reports_dir"
  --summary-json "$ci_summary_json"
)
if [[ "$dry_run" == "1" ]]; then
  ci_cmd+=(--dry-run 1)
fi
if ((${#ci_passthrough_args[@]} > 0)); then
  ci_cmd+=("${ci_passthrough_args[@]}")
fi
ci_command="$(print_cmd "${ci_cmd[@]}")"

if [[ "$run_ci_phase6_cosmos_l1_build_testnet" == "1" ]]; then
  set +e
  run_stage_capture "ci_phase6_cosmos_l1_build_testnet" "$ci_log" "${ci_cmd[@]}"
  ci_command_rc=$?
  set -e
  if ci_summary_contract_valid "$ci_summary_json"; then
    ci_contract_valid=1
    ci_status="$(jq -r '.status // "fail"' "$ci_summary_json" 2>/dev/null || echo fail)"
    ci_rc="$(jq -r '.rc // 0' "$ci_summary_json" 2>/dev/null || echo 0)"
    if [[ "$ci_command_rc" -ne 0 ]]; then
      ci_status="fail"
      ci_rc="$ci_command_rc"
    fi
  else
    ci_contract_valid=0
    ci_contract_error="missing or invalid ci_phase6 summary contract"
    ci_status="fail"
    if [[ "$ci_command_rc" -ne 0 ]]; then
      ci_rc="$ci_command_rc"
    else
      ci_rc=3
    fi
  fi
else
  echo "[phase6-cosmos-l1-build-testnet-suite] stage=ci_phase6_cosmos_l1_build_testnet status=skipped reason=disabled"
fi

declare -a run_cmd=(
  "$run_script"
  --reports-dir "$reports_dir"
  --ci-summary-json "$ci_summary_json"
  --summary-json "$run_summary_json"
)
if [[ "$dry_run" == "1" ]]; then
  run_cmd+=(--dry-run 1)
fi
if ((${#run_passthrough_args[@]} > 0)); then
  run_cmd+=("${run_passthrough_args[@]}")
fi
run_command="$(print_cmd "${run_cmd[@]}")"

if [[ "$run_phase6_cosmos_l1_build_testnet_run" == "1" ]]; then
  set +e
  run_stage_capture "phase6_cosmos_l1_build_testnet_run" "$run_log" "${run_cmd[@]}"
  run_command_rc=$?
  set -e
  if run_summary_contract_valid "$run_summary_json"; then
    run_contract_valid=1
    run_status="$(jq -r '.status // "fail"' "$run_summary_json" 2>/dev/null || echo fail)"
    run_rc="$(jq -r '.rc // 0' "$run_summary_json" 2>/dev/null || echo 0)"
    if [[ "$run_command_rc" -ne 0 ]]; then
      run_status="fail"
      run_rc="$run_command_rc"
    fi
  else
    run_contract_valid=0
    run_contract_error="missing or invalid phase6 cosmos l1 build testnet run summary contract"
    run_status="fail"
    if [[ "$run_command_rc" -ne 0 ]]; then
      run_rc="$run_command_rc"
    else
      run_rc=3
    fi
  fi
else
  echo "[phase6-cosmos-l1-build-testnet-suite] stage=phase6_cosmos_l1_build_testnet_run status=skipped reason=disabled"
fi

declare -a handoff_run_cmd=(
  "$handoff_run_script"
  --reports-dir "$reports_dir"
  --run-summary-json "$run_summary_json"
  --summary-json "$handoff_run_summary_json"
)
if [[ "$dry_run" == "1" ]]; then
  handoff_run_cmd+=(--dry-run 1)
fi

if [[ "$run_phase6_cosmos_l1_build_testnet_run" == "1" ]] \
  && ! array_has_arg "--run-phase6-cosmos-l1-build-testnet-run" "${handoff_run_passthrough_args[@]}"; then
  handoff_run_cmd+=(--run-phase6-cosmos-l1-build-testnet-run 0)
fi

if ((${#handoff_run_passthrough_args[@]} > 0)); then
  handoff_run_cmd+=("${handoff_run_passthrough_args[@]}")
fi
handoff_run_command="$(print_cmd "${handoff_run_cmd[@]}")"

if [[ "$run_phase6_cosmos_l1_build_testnet_handoff_run" == "1" ]]; then
  set +e
  run_stage_capture "phase6_cosmos_l1_build_testnet_handoff_run" "$handoff_run_log" "${handoff_run_cmd[@]}"
  handoff_run_command_rc=$?
  set -e
  if handoff_run_summary_contract_valid "$handoff_run_summary_json"; then
    handoff_run_contract_valid=1
    handoff_run_status="$(jq -r '.status // "fail"' "$handoff_run_summary_json" 2>/dev/null || echo fail)"
    handoff_run_rc="$(jq -r '.rc // 0' "$handoff_run_summary_json" 2>/dev/null || echo 0)"
    if [[ "$handoff_run_command_rc" -ne 0 ]]; then
      handoff_run_status="fail"
      handoff_run_rc="$handoff_run_command_rc"
    fi
  else
    handoff_run_contract_valid=0
    handoff_run_contract_error="missing or invalid phase6 cosmos l1 build testnet handoff run summary contract"
    handoff_run_status="fail"
    if [[ "$handoff_run_command_rc" -ne 0 ]]; then
      handoff_run_rc="$handoff_run_command_rc"
    else
      handoff_run_rc=3
    fi
  fi
else
  echo "[phase6-cosmos-l1-build-testnet-suite] stage=phase6_cosmos_l1_build_testnet_handoff_run status=skipped reason=disabled"
fi

final_rc=0
if [[ "$run_ci_phase6_cosmos_l1_build_testnet" == "1" ]] && (( ci_rc != 0 )) && (( final_rc == 0 )); then
  final_rc="$ci_rc"
fi
if [[ "$run_phase6_cosmos_l1_build_testnet_run" == "1" ]] && (( run_rc != 0 )) && (( final_rc == 0 )); then
  final_rc="$run_rc"
fi
if [[ "$run_phase6_cosmos_l1_build_testnet_handoff_run" == "1" ]] && (( handoff_run_rc != 0 )) && (( final_rc == 0 )); then
  final_rc="$handoff_run_rc"
fi

final_status="pass"
if (( final_rc != 0 )); then
  final_status="fail"
fi

ci_summary_exists="false"
run_summary_exists="false"
handoff_run_summary_exists="false"
if [[ -f "$ci_summary_json" ]]; then
  ci_summary_exists="true"
fi
if [[ -f "$run_summary_json" ]]; then
  run_summary_exists="true"
fi
if [[ -f "$handoff_run_summary_json" ]]; then
  handoff_run_summary_exists="true"
fi

ci_passthrough_json="$(printf '%s\n' "${ci_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
run_passthrough_json="$(printf '%s\n' "${run_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
handoff_run_passthrough_json="$(printf '%s\n' "${handoff_run_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg ci_summary_json "$ci_summary_json" \
  --arg run_summary_json "$run_summary_json" \
  --arg handoff_run_summary_json "$handoff_run_summary_json" \
  --argjson dry_run "$dry_run" \
  --argjson print_summary_json "$print_summary_json" \
  --argjson run_ci_phase6_cosmos_l1_build_testnet "$run_ci_phase6_cosmos_l1_build_testnet" \
  --argjson run_phase6_cosmos_l1_build_testnet_run "$run_phase6_cosmos_l1_build_testnet_run" \
  --argjson run_phase6_cosmos_l1_build_testnet_handoff_run "$run_phase6_cosmos_l1_build_testnet_handoff_run" \
  --argjson ci_passthrough_args "$ci_passthrough_json" \
  --argjson run_passthrough_args "$run_passthrough_json" \
  --argjson handoff_run_passthrough_args "$handoff_run_passthrough_json" \
  --arg ci_status "$ci_status" \
  --argjson ci_rc "$ci_rc" \
  --argjson ci_command_rc "$ci_command_rc" \
  --arg ci_command "$ci_command" \
  --arg ci_contract_valid "$ci_contract_valid" \
  --arg ci_contract_error "$ci_contract_error" \
  --arg ci_summary_exists "$ci_summary_exists" \
  --arg ci_log "$ci_log" \
  --arg run_status "$run_status" \
  --argjson run_rc "$run_rc" \
  --argjson run_command_rc "$run_command_rc" \
  --arg run_command "$run_command" \
  --arg run_contract_valid "$run_contract_valid" \
  --arg run_contract_error "$run_contract_error" \
  --arg run_summary_exists "$run_summary_exists" \
  --arg run_log "$run_log" \
  --arg handoff_run_status "$handoff_run_status" \
  --argjson handoff_run_rc "$handoff_run_rc" \
  --argjson handoff_run_command_rc "$handoff_run_command_rc" \
  --arg handoff_run_command "$handoff_run_command" \
  --arg handoff_run_contract_valid "$handoff_run_contract_valid" \
  --arg handoff_run_contract_error "$handoff_run_contract_error" \
  --arg handoff_run_summary_exists "$handoff_run_summary_exists" \
  --arg handoff_run_log "$handoff_run_log" \
  '{
    version: 1,
    schema: {
      id: "phase6_cosmos_l1_build_testnet_suite_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    metadata: {
      contract: "phase6-cosmos-l1-build-testnet",
      runner_script: "phase6_cosmos_l1_build_testnet_suite.sh"
    },
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      dry_run: ($dry_run == 1),
      print_summary_json: ($print_summary_json == 1),
      run_ci_phase6_cosmos_l1_build_testnet: ($run_ci_phase6_cosmos_l1_build_testnet == 1),
      run_phase6_cosmos_l1_build_testnet_run: ($run_phase6_cosmos_l1_build_testnet_run == 1),
      run_phase6_cosmos_l1_build_testnet_handoff_run: ($run_phase6_cosmos_l1_build_testnet_handoff_run == 1),
      ci_passthrough_args: $ci_passthrough_args,
      run_passthrough_args: $run_passthrough_args,
      handoff_run_passthrough_args: $handoff_run_passthrough_args
    },
    steps: {
      ci_phase6_cosmos_l1_build_testnet: {
        enabled: ($run_ci_phase6_cosmos_l1_build_testnet == 1),
        status: $ci_status,
        rc: $ci_rc,
        command_rc: $ci_command_rc,
        command: (if $ci_command == "" then null else $ci_command end),
        contract_valid: ($ci_contract_valid == "1"),
        contract_error: (if $ci_contract_error == "" then null else $ci_contract_error end),
        artifacts: {
          summary_json: $ci_summary_json,
          summary_exists: ($ci_summary_exists == "true"),
          log: $ci_log
        }
      },
      phase6_cosmos_l1_build_testnet_run: {
        enabled: ($run_phase6_cosmos_l1_build_testnet_run == 1),
        status: $run_status,
        rc: $run_rc,
        command_rc: $run_command_rc,
        command: (if $run_command == "" then null else $run_command end),
        contract_valid: ($run_contract_valid == "1"),
        contract_error: (if $run_contract_error == "" then null else $run_contract_error end),
        artifacts: {
          summary_json: $run_summary_json,
          summary_exists: ($run_summary_exists == "true"),
          log: $run_log
        }
      },
      phase6_cosmos_l1_build_testnet_handoff_run: {
        enabled: ($run_phase6_cosmos_l1_build_testnet_handoff_run == 1),
        status: $handoff_run_status,
        rc: $handoff_run_rc,
        command_rc: $handoff_run_command_rc,
        command: (if $handoff_run_command == "" then null else $handoff_run_command end),
        contract_valid: ($handoff_run_contract_valid == "1"),
        contract_error: (if $handoff_run_contract_error == "" then null else $handoff_run_contract_error end),
        artifacts: {
          summary_json: $handoff_run_summary_json,
          summary_exists: ($handoff_run_summary_exists == "true"),
          log: $handoff_run_log
        }
      }
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json,
      ci_summary_json: $ci_summary_json,
      run_summary_json: $run_summary_json,
      handoff_run_summary_json: $handoff_run_summary_json,
      ci_log: $ci_log,
      run_log: $run_log,
      handoff_run_log: $handoff_run_log
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"
if [[ "$summary_json" != "$canonical_summary_json" ]]; then
  canonical_tmp="$(mktemp "${canonical_summary_json}.tmp.XXXXXX")"
  cp "$summary_json" "$canonical_tmp"
  mv -f "$canonical_tmp" "$canonical_summary_json"
fi

echo "[phase6-cosmos-l1-build-testnet-suite] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[phase6-cosmos-l1-build-testnet-suite] reports_dir=$reports_dir"
echo "[phase6-cosmos-l1-build-testnet-suite] summary_json=$summary_json"
echo "[phase6-cosmos-l1-build-testnet-suite] canonical_summary_json=$canonical_summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
