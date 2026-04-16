#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase7_mainnet_cutover_run.sh \
    [--reports-dir DIR] \
    [--check-summary-json PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--check-<arg> ...]

Purpose:
  One-command Phase-7 mainnet cutover runner:
    1) phase7_mainnet_cutover_check.sh

Notes:
  - Wrapper-owned flags are reserved; checker pass-through uses --check-...
  - Dry-run still runs the checker.
  - Dry-run relaxes manual gating requirements to 0 unless explicitly set:
      --require-rollback-path-ready
      --require-operator-approval-ok
    Compatibility aliases are also honored when explicitly supplied:
      --require-rollback-ready
      --require-operator-approval
  - The checker receives --show-json 0 by default unless explicitly supplied
    via --check-show-json.
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

is_reserved_check_passthrough_arg() {
  local forwarded_flag="$1"
  case "$forwarded_flag" in
    --reports-dir|--check-summary-json|--summary-json|--print-summary-json|--dry-run)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

json_file_valid() {
  local path="$1"
  [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1
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
    and (.schema.id // "") == "phase7_mainnet_cutover_check_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) | floor) == (.schema.major // 0)
    and (.status | type) == "string"
    and (.rc | type) == "number"
    and (
      ((.status == "pass") and (.rc == 0))
      or ((.status != "pass") and (.rc != 0))
    )
  ' "$path" >/dev/null 2>&1
}

extract_check_signal_json() {
  local path="$1"
  local signal_key="$2"
  jq -c --arg signal_key "$signal_key" '.signals[$signal_key] // null' "$path" 2>/dev/null || printf 'null'
}

run_step_capture() {
  local label="$1"
  local log_path="$2"
  shift 2
  local rc=0
  echo "[phase7-mainnet-cutover-run] step=$label status=running"
  set +e
  "$@" >"$log_path" 2>&1
  rc=$?
  if (( rc == 0 )); then
    echo "[phase7-mainnet-cutover-run] step=$label status=pass rc=0"
  else
    echo "[phase7-mainnet-cutover-run] step=$label status=fail rc=$rc"
  fi
  return "$rc"
}

need_cmd jq
need_cmd date
need_cmd mktemp
need_cmd cp

reports_dir="${PHASE7_MAINNET_CUTOVER_RUN_REPORTS_DIR:-}"
check_summary_json="${PHASE7_MAINNET_CUTOVER_RUN_CHECK_SUMMARY_JSON:-}"
summary_json="${PHASE7_MAINNET_CUTOVER_RUN_SUMMARY_JSON:-}"
canonical_summary_json="${PHASE7_MAINNET_CUTOVER_RUN_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase7_mainnet_cutover_run_summary.json}"
print_summary_json="${PHASE7_MAINNET_CUTOVER_RUN_PRINT_SUMMARY_JSON:-1}"
dry_run="${PHASE7_MAINNET_CUTOVER_RUN_DRY_RUN:-0}"

declare -a check_passthrough_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
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
    --check-*)
      forwarded_flag="--${1#--check-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid check-prefixed arg: $1"
        exit 2
      fi
      if is_reserved_check_passthrough_arg "$forwarded_flag"; then
        echo "reserved wrapper arg via --check- prefix: $1"
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

if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs"
fi
reports_dir="$(abs_path "$reports_dir")"
if [[ -z "$check_summary_json" ]]; then
  check_summary_json="$reports_dir/phase7_mainnet_cutover_check_summary.json"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/phase7_mainnet_cutover_run_summary.json"
fi
check_summary_json="$(abs_path "$check_summary_json")"
summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"

mkdir -p "$reports_dir" "$(dirname "$check_summary_json")" "$(dirname "$summary_json")" "$(dirname "$canonical_summary_json")"

check_script="${PHASE7_MAINNET_CUTOVER_RUN_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase7_mainnet_cutover_check.sh}"
if [[ ! -x "$check_script" ]]; then
  echo "missing executable stage script: $check_script"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

check_log="$TMP_DIR/check.log"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

declare check_command_rc=0
declare check_contract_valid=0
declare check_status="skipped"
declare check_rc=0
declare check_contract_error=""
declare check_command=""
declare signal_module_tx_surface_ok="null"
declare signal_tdpnd_grpc_live_smoke_ok="null"
declare signal_tdpnd_grpc_auth_live_smoke_ok="null"
declare signal_tdpnd_comet_runtime_smoke_ok="null"
declare signal_dual_write_parity_ok="null"
declare signal_mainnet_activation_gate_go="null"
declare signal_cosmos_module_coverage_floor_ok="null"
declare signal_cosmos_keeper_coverage_floor_ok="null"
declare signal_cosmos_app_coverage_floor_ok="null"
declare signal_rollback_path_ready="null"
declare signal_operator_approval_ok="null"

check_command_args=("$check_script" --summary-json "$check_summary_json")
if ((${#check_passthrough_args[@]} > 0)); then
  check_command_args+=("${check_passthrough_args[@]}")
fi
if ! array_has_arg "--show-json" "${check_command_args[@]:1}"; then
  check_command_args+=(--show-json 0)
fi
if [[ "$dry_run" == "1" ]]; then
  if ! array_has_arg "--require-rollback-path-ready" "${check_command_args[@]:1}" \
    && ! array_has_arg "--require-rollback-ready" "${check_command_args[@]:1}"; then
    check_command_args+=(--require-rollback-path-ready 0)
  fi
  if ! array_has_arg "--require-operator-approval-ok" "${check_command_args[@]:1}" \
    && ! array_has_arg "--require-operator-approval" "${check_command_args[@]:1}"; then
    check_command_args+=(--require-operator-approval-ok 0)
  fi
fi
check_command="$(print_cmd "${check_command_args[@]}")"

set +e
run_step_capture "phase7_mainnet_cutover_check" "$check_log" "${check_command_args[@]}"
check_command_rc=$?
set -e
if check_summary_contract_valid "$check_summary_json"; then
  check_contract_valid=1
  check_status="$(jq -r '.status // "fail"' "$check_summary_json" 2>/dev/null || echo fail)"
  check_rc="$(jq -r '.rc // 0' "$check_summary_json" 2>/dev/null || echo 0)"
  signal_module_tx_surface_ok="$(extract_check_signal_json "$check_summary_json" "module_tx_surface_ok")"
  signal_tdpnd_grpc_live_smoke_ok="$(extract_check_signal_json "$check_summary_json" "tdpnd_grpc_live_smoke_ok")"
  signal_tdpnd_grpc_auth_live_smoke_ok="$(extract_check_signal_json "$check_summary_json" "tdpnd_grpc_auth_live_smoke_ok")"
  signal_tdpnd_comet_runtime_smoke_ok="$(extract_check_signal_json "$check_summary_json" "tdpnd_comet_runtime_smoke_ok")"
  signal_dual_write_parity_ok="$(extract_check_signal_json "$check_summary_json" "dual_write_parity_ok")"
  signal_mainnet_activation_gate_go="$(extract_check_signal_json "$check_summary_json" "mainnet_activation_gate_go")"
  signal_cosmos_module_coverage_floor_ok="$(extract_check_signal_json "$check_summary_json" "cosmos_module_coverage_floor_ok")"
  signal_cosmos_keeper_coverage_floor_ok="$(extract_check_signal_json "$check_summary_json" "cosmos_keeper_coverage_floor_ok")"
  signal_cosmos_app_coverage_floor_ok="$(extract_check_signal_json "$check_summary_json" "cosmos_app_coverage_floor_ok")"
  signal_rollback_path_ready="$(extract_check_signal_json "$check_summary_json" "rollback_path_ready")"
  signal_operator_approval_ok="$(extract_check_signal_json "$check_summary_json" "operator_approval_ok")"
  if [[ "$check_command_rc" -ne 0 ]]; then
    check_status="fail"
    check_rc="$check_command_rc"
  fi
else
  check_contract_valid=0
  check_contract_error="missing or invalid phase7 mainnet cutover check summary contract"
  check_status="fail"
  if [[ "$check_command_rc" -ne 0 ]]; then
    check_rc="$check_command_rc"
  else
    check_rc=3
  fi
fi

final_status="pass"
final_rc=0
if [[ "$check_status" != "pass" ]]; then
  final_status="fail"
  final_rc="$check_rc"
fi

check_summary_exists="0"
if [[ -f "$check_summary_json" ]]; then
  check_summary_exists="1"
fi

check_passthrough_json="$(printf '%s\n' "${check_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg check_summary_json "$check_summary_json" \
  --argjson dry_run "$dry_run" \
  --argjson print_summary_json "$print_summary_json" \
  --argjson check_passthrough_args "$check_passthrough_json" \
  --arg check_command "$check_command" \
  --arg check_status "$check_status" \
  --argjson check_command_rc "$check_command_rc" \
  --argjson check_rc "$check_rc" \
  --argjson check_contract_valid "$check_contract_valid" \
  --arg check_contract_error "$check_contract_error" \
  --argjson check_summary_exists "$check_summary_exists" \
  --argjson signal_module_tx_surface_ok "$signal_module_tx_surface_ok" \
  --argjson signal_tdpnd_grpc_live_smoke_ok "$signal_tdpnd_grpc_live_smoke_ok" \
  --argjson signal_tdpnd_grpc_auth_live_smoke_ok "$signal_tdpnd_grpc_auth_live_smoke_ok" \
  --argjson signal_tdpnd_comet_runtime_smoke_ok "$signal_tdpnd_comet_runtime_smoke_ok" \
  --argjson signal_dual_write_parity_ok "$signal_dual_write_parity_ok" \
  --argjson signal_mainnet_activation_gate_go "$signal_mainnet_activation_gate_go" \
  --argjson signal_cosmos_module_coverage_floor_ok "$signal_cosmos_module_coverage_floor_ok" \
  --argjson signal_cosmos_keeper_coverage_floor_ok "$signal_cosmos_keeper_coverage_floor_ok" \
  --argjson signal_cosmos_app_coverage_floor_ok "$signal_cosmos_app_coverage_floor_ok" \
  --argjson signal_rollback_path_ready "$signal_rollback_path_ready" \
  --argjson signal_operator_approval_ok "$signal_operator_approval_ok" \
  --arg check_log "$check_log" \
  '{
    version: 1,
    schema: {
      id: "phase7_mainnet_cutover_run_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    metadata: {
      contract: "phase7-mainnet-cutover",
      runner_script: "phase7_mainnet_cutover_run.sh"
    },
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      dry_run: ($dry_run == 1),
      print_summary_json: ($print_summary_json == 1),
      check_passthrough_args: $check_passthrough_args
    },
    steps: {
      phase7_mainnet_cutover_check: {
        enabled: true,
        status: $check_status,
        rc: $check_rc,
        command_rc: $check_command_rc,
        command: (if $check_command == "" then null else $check_command end),
        contract_valid: ($check_contract_valid == 1),
        contract_error: (if $check_contract_error == "" then null else $check_contract_error end),
        signal_snapshot: {
          module_tx_surface_ok: $signal_module_tx_surface_ok,
          tdpnd_grpc_live_smoke_ok: $signal_tdpnd_grpc_live_smoke_ok,
          tdpnd_grpc_auth_live_smoke_ok: $signal_tdpnd_grpc_auth_live_smoke_ok,
          tdpnd_comet_runtime_smoke_ok: $signal_tdpnd_comet_runtime_smoke_ok,
          dual_write_parity_ok: $signal_dual_write_parity_ok,
          mainnet_activation_gate_go: $signal_mainnet_activation_gate_go,
          cosmos_module_coverage_floor_ok: $signal_cosmos_module_coverage_floor_ok,
          cosmos_keeper_coverage_floor_ok: $signal_cosmos_keeper_coverage_floor_ok,
          cosmos_app_coverage_floor_ok: $signal_cosmos_app_coverage_floor_ok,
          rollback_path_ready: $signal_rollback_path_ready,
          operator_approval_ok: $signal_operator_approval_ok
        },
        artifacts: {
          summary_json: $check_summary_json,
          summary_exists: ($check_summary_exists == 1),
          log: $check_log
        }
      }
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json,
      check_summary_json: $check_summary_json,
      check_log: $check_log
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"
if [[ "$summary_json" != "$canonical_summary_json" ]]; then
  canonical_tmp="$(mktemp "${canonical_summary_json}.tmp.XXXXXX")"
  cp "$summary_json" "$canonical_tmp"
  mv -f "$canonical_tmp" "$canonical_summary_json"
fi

echo "[phase7-mainnet-cutover-run] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[phase7-mainnet-cutover-run] reports_dir=$reports_dir"
echo "[phase7-mainnet-cutover-run] check_summary_json=$check_summary_json"
echo "[phase7-mainnet-cutover-run] summary_json=$summary_json"
echo "[phase7-mainnet-cutover-run] canonical_summary_json=$canonical_summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
