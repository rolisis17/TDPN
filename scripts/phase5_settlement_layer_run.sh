#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase5_settlement_layer_run.sh \
    [--reports-dir DIR] \
    [--ci-summary-json PATH] \
    [--check-summary-json PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--ci-<arg> ...] \
    [--check-<arg> ...]

Purpose:
  One-command Phase-5 settlement layer runner:
    1) ci_phase5_settlement_layer.sh
    2) phase5_settlement_layer_check.sh

Notes:
  - Wrapper-owned flags are reserved; stage pass-through uses prefixes:
      --ci-...     -> forwarded to ci_phase5_settlement_layer.sh
      --check-...  -> forwarded to phase5_settlement_layer_check.sh
  - Dry-run forwards --dry-run 1 to ci_phase5 only.
    The checker still runs against the generated CI summary.
  - Dry-run relaxes checker requirements to 0 unless explicitly supplied.
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

resolve_issuer_sponsor_api_live_smoke_signal() {
  local check_summary_json="$1"
  local resolved_tuple=""
  if ! json_file_valid "$check_summary_json"; then
    printf '%s\n' "null|missing|unresolved|0"
    return
  fi

  resolved_tuple="$(
    jq -r '
      if (.signals.issuer_sponsor_api_live_smoke_ok? | type) == "boolean" then
        [
          (.signals.issuer_sponsor_api_live_smoke_ok | tostring),
          (if .signals.issuer_sponsor_api_live_smoke_ok then "pass" else "fail" end),
          "phase5_settlement_layer_check_summary.signals.issuer_sponsor_api_live_smoke_ok",
          "1"
        ]
      elif (.stages.issuer_sponsor_api_live_smoke.ok? | type) == "boolean" then
        [
          (.stages.issuer_sponsor_api_live_smoke.ok | tostring),
          (
            if (.stages.issuer_sponsor_api_live_smoke.status? | type) == "string"
              and (.stages.issuer_sponsor_api_live_smoke.status | length) > 0
            then .stages.issuer_sponsor_api_live_smoke.status
            else (if .stages.issuer_sponsor_api_live_smoke.ok then "pass" else "fail" end)
            end
          ),
          "phase5_settlement_layer_check_summary.stages.issuer_sponsor_api_live_smoke.ok",
          (
            if (.stages.issuer_sponsor_api_live_smoke.resolved? | type) == "boolean"
            then (if .stages.issuer_sponsor_api_live_smoke.resolved then "1" else "0" end)
            else "1"
            end
          )
        ]
      elif (.stages.issuer_sponsor_api_live_smoke.status? | type) == "string"
        and (.stages.issuer_sponsor_api_live_smoke.status | length) > 0 then
        [
          (
            (.stages.issuer_sponsor_api_live_smoke.status | ascii_downcase) as $s
            | if ($s == "pass" or $s == "ok" or $s == "true" or $s == "passed" or $s == "success" or $s == "succeeded")
              then "true"
              elif ($s == "fail" or $s == "false" or $s == "error" or $s == "failed" or $s == "blocked" or $s == "warn" or $s == "warning" or $s == "skip" or $s == "skipped" or $s == "invalid" or $s == "missing" or $s == "unresolved")
              then "false"
              else "null"
              end
          ),
          .stages.issuer_sponsor_api_live_smoke.status,
          "phase5_settlement_layer_check_summary.stages.issuer_sponsor_api_live_smoke.status",
          (
            if (.stages.issuer_sponsor_api_live_smoke.resolved? | type) == "boolean"
            then (if .stages.issuer_sponsor_api_live_smoke.resolved then "1" else "0" end)
            else "1"
            end
          )
        ]
      elif (.stages.issuer_sponsor_api_live_smoke.resolved? | type) == "boolean" then
        [
          "null",
          "missing",
          "phase5_settlement_layer_check_summary.stages.issuer_sponsor_api_live_smoke.resolved",
          (if .stages.issuer_sponsor_api_live_smoke.resolved then "1" else "0" end)
        ]
      else
        ["null", "missing", "unresolved", "0"]
      end | join("|")
    ' "$check_summary_json" 2>/dev/null || true
  )"

  if [[ -z "$resolved_tuple" ]]; then
    printf '%s\n' "null|missing|unresolved|0"
  else
    printf '%s\n' "$resolved_tuple"
  fi
}

resolve_settlement_dual_asset_parity_signal() {
  local check_summary_json="$1"
  local resolved_tuple=""
  if ! json_file_valid "$check_summary_json"; then
    printf '%s\n' "null|missing|unresolved|0"
    return
  fi

  resolved_tuple="$(
    jq -r '
      if (.signals.settlement_dual_asset_parity_ok? | type) == "boolean" then
        [
          (.signals.settlement_dual_asset_parity_ok | tostring),
          (if .signals.settlement_dual_asset_parity_ok then "pass" else "fail" end),
          "phase5_settlement_layer_check_summary.signals.settlement_dual_asset_parity_ok",
          "1"
        ]
      elif (.stages.settlement_dual_asset_parity.ok? | type) == "boolean" then
        [
          (.stages.settlement_dual_asset_parity.ok | tostring),
          (
            if (.stages.settlement_dual_asset_parity.status? | type) == "string"
              and (.stages.settlement_dual_asset_parity.status | length) > 0
            then .stages.settlement_dual_asset_parity.status
            else (if .stages.settlement_dual_asset_parity.ok then "pass" else "fail" end)
            end
          ),
          "phase5_settlement_layer_check_summary.stages.settlement_dual_asset_parity.ok",
          (
            if (.stages.settlement_dual_asset_parity.resolved? | type) == "boolean"
            then (if .stages.settlement_dual_asset_parity.resolved then "1" else "0" end)
            else "1"
            end
          )
        ]
      elif (.stages.settlement_dual_asset_parity.status? | type) == "string"
        and (.stages.settlement_dual_asset_parity.status | length) > 0 then
        [
          (
            (.stages.settlement_dual_asset_parity.status | ascii_downcase) as $s
            | if ($s == "pass" or $s == "ok" or $s == "true" or $s == "passed" or $s == "success" or $s == "succeeded")
              then "true"
              elif ($s == "fail" or $s == "false" or $s == "error" or $s == "failed" or $s == "blocked" or $s == "warn" or $s == "warning" or $s == "skip" or $s == "skipped" or $s == "invalid" or $s == "missing" or $s == "unresolved")
              then "false"
              else "null"
              end
          ),
          .stages.settlement_dual_asset_parity.status,
          "phase5_settlement_layer_check_summary.stages.settlement_dual_asset_parity.status",
          (
            if (.stages.settlement_dual_asset_parity.resolved? | type) == "boolean"
            then (if .stages.settlement_dual_asset_parity.resolved then "1" else "0" end)
            else "1"
            end
          )
        ]
      elif (.stages.settlement_dual_asset_parity.resolved? | type) == "boolean" then
        [
          "null",
          "missing",
          "phase5_settlement_layer_check_summary.stages.settlement_dual_asset_parity.resolved",
          (if .stages.settlement_dual_asset_parity.resolved then "1" else "0" end)
        ]
      else
        ["null", "missing", "unresolved", "0"]
      end | join("|")
    ' "$check_summary_json" 2>/dev/null || true
  )"

  if [[ -z "$resolved_tuple" ]]; then
    printf '%s\n' "null|missing|unresolved|0"
  else
    printf '%s\n' "$resolved_tuple"
  fi
}

resolve_issuer_admin_blockchain_handlers_coverage_signal() {
  local check_summary_json="$1"
  local resolved_tuple=""
  if ! json_file_valid "$check_summary_json"; then
    printf '%s\n' "null|missing|unresolved|0"
    return
  fi

  resolved_tuple="$(
    jq -r '
      if (.signals.issuer_admin_blockchain_handlers_coverage_ok? | type) == "boolean" then
        [
          (.signals.issuer_admin_blockchain_handlers_coverage_ok | tostring),
          (if .signals.issuer_admin_blockchain_handlers_coverage_ok then "pass" else "fail" end),
          "phase5_settlement_layer_check_summary.signals.issuer_admin_blockchain_handlers_coverage_ok",
          "1"
        ]
      elif (.stages.issuer_admin_blockchain_handlers_coverage.ok? | type) == "boolean" then
        [
          (.stages.issuer_admin_blockchain_handlers_coverage.ok | tostring),
          (
            if (.stages.issuer_admin_blockchain_handlers_coverage.status? | type) == "string"
              and (.stages.issuer_admin_blockchain_handlers_coverage.status | length) > 0
            then .stages.issuer_admin_blockchain_handlers_coverage.status
            else (if .stages.issuer_admin_blockchain_handlers_coverage.ok then "pass" else "fail" end)
            end
          ),
          "phase5_settlement_layer_check_summary.stages.issuer_admin_blockchain_handlers_coverage.ok",
          (
            if (.stages.issuer_admin_blockchain_handlers_coverage.resolved? | type) == "boolean"
            then (if .stages.issuer_admin_blockchain_handlers_coverage.resolved then "1" else "0" end)
            else "1"
            end
          )
        ]
      elif (.stages.issuer_admin_blockchain_handlers_coverage.status? | type) == "string"
        and (.stages.issuer_admin_blockchain_handlers_coverage.status | length) > 0 then
        [
          (
            (.stages.issuer_admin_blockchain_handlers_coverage.status | ascii_downcase) as $s
            | if ($s == "pass" or $s == "ok" or $s == "true" or $s == "passed" or $s == "success" or $s == "succeeded")
              then "true"
              elif ($s == "fail" or $s == "false" or $s == "error" or $s == "failed" or $s == "blocked" or $s == "warn" or $s == "warning" or $s == "skip" or $s == "skipped" or $s == "invalid" or $s == "missing" or $s == "unresolved")
              then "false"
              else "null"
              end
          ),
          .stages.issuer_admin_blockchain_handlers_coverage.status,
          "phase5_settlement_layer_check_summary.stages.issuer_admin_blockchain_handlers_coverage.status",
          (
            if (.stages.issuer_admin_blockchain_handlers_coverage.resolved? | type) == "boolean"
            then (if .stages.issuer_admin_blockchain_handlers_coverage.resolved then "1" else "0" end)
            else "1"
            end
          )
        ]
      elif (.stages.issuer_admin_blockchain_handlers_coverage.resolved? | type) == "boolean" then
        [
          "null",
          "missing",
          "phase5_settlement_layer_check_summary.stages.issuer_admin_blockchain_handlers_coverage.resolved",
          (if .stages.issuer_admin_blockchain_handlers_coverage.resolved then "1" else "0" end)
        ]
      else
        ["null", "missing", "unresolved", "0"]
      end | join("|")
    ' "$check_summary_json" 2>/dev/null || true
  )"

  if [[ -z "$resolved_tuple" ]]; then
    printf '%s\n' "null|missing|unresolved|0"
  else
    printf '%s\n' "$resolved_tuple"
  fi
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
    and (.schema.id // "") == "ci_phase5_settlement_layer_summary"
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
    and (.schema.id // "") == "phase5_settlement_layer_check_summary"
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
  echo "[phase5-settlement-layer-run] step=$label status=running"
  set +e
  "$@" >"$log_path" 2>&1
  rc=$?
  if (( rc == 0 )); then
    echo "[phase5-settlement-layer-run] step=$label status=pass rc=0"
  else
    echo "[phase5-settlement-layer-run] step=$label status=fail rc=$rc"
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

checker_flag_to_canonical() {
  local flag="$1"
  case "$flag" in
    --require-windows-server-packaging-ok)
      printf '%s' "--require-settlement-failsoft-ok"
      ;;
    --require-windows-role-runbooks-ok)
      printf '%s' "--require-settlement-acceptance-ok"
      ;;
    --require-cross-platform-interop-ok)
      printf '%s' "--require-settlement-bridge-smoke-ok"
      ;;
    --require-role-combination-validation-ok)
      printf '%s' "--require-settlement-state-persistence-ok"
      ;;
    --require-settlement-dual-asset-ok)
      printf '%s' "--require-settlement-dual-asset-parity-ok"
      ;;
    *)
      printf '%s' "$flag"
      ;;
  esac
}

checker_flag_to_legacy() {
  local flag="$1"
  case "$flag" in
    --require-settlement-failsoft-ok)
      printf '%s' "--require-windows-server-packaging-ok"
      ;;
    --require-settlement-acceptance-ok)
      printf '%s' "--require-windows-role-runbooks-ok"
      ;;
    --require-settlement-bridge-smoke-ok)
      printf '%s' "--require-cross-platform-interop-ok"
      ;;
    --require-settlement-state-persistence-ok)
      printf '%s' "--require-role-combination-validation-ok"
      ;;
    --require-settlement-dual-asset-parity-ok)
      printf '%s' "--require-settlement-dual-asset-ok"
      ;;
    *)
      printf '%s' "$flag"
      ;;
  esac
}

array_has_checker_flag() {
  local flag="$1"
  shift
  local canonical legacy arg
  canonical="$(checker_flag_to_canonical "$flag")"
  legacy="$(checker_flag_to_legacy "$canonical")"
  for arg in "$@"; do
    if [[ "$arg" == "$canonical" || "$arg" == "$legacy" ]]; then
      return 0
    fi
  done
  return 1
}

detect_checker_canonical_flags() {
  local script_path="$1"
  local help_output
  set +e
  help_output="$("$script_path" --help 2>&1)"
  set -e
  if [[ "$help_output" == *"--require-settlement-failsoft-ok"* ]] || [[ "$help_output" == *"--require-settlement-acceptance-ok"* ]] || [[ "$help_output" == *"--require-settlement-bridge-smoke-ok"* ]] || [[ "$help_output" == *"--require-settlement-state-persistence-ok"* ]] || [[ "$help_output" == *"--require-settlement-dual-asset-parity-ok"* ]]; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

detect_checker_issuer_sponsor_requirement_flag() {
  local script_path="$1"
  local help_output
  set +e
  help_output="$("$script_path" --help 2>&1)"
  set -e
  if [[ "$help_output" == *"--require-issuer-sponsor-api-live-smoke-ok"* ]]; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

detect_checker_issuer_admin_blockchain_handlers_coverage_requirement_flag() {
  local script_path="$1"
  local help_output
  set +e
  help_output="$("$script_path" --help 2>&1)"
  set -e
  if [[ "$help_output" == *"--require-issuer-admin-blockchain-handlers-coverage-ok"* ]]; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

detect_checker_dual_asset_requirement_flag() {
  local script_path="$1"
  local help_output
  set +e
  help_output="$("$script_path" --help 2>&1)"
  set -e
  if [[ "$help_output" == *"--require-settlement-dual-asset-parity-ok"* ]] || [[ "$help_output" == *"--require-settlement-dual-asset-ok"* ]]; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

adapt_checker_flags_for_script() {
  local supports_canonical="$1"
  shift
  local token out=()
  for token in "$@"; do
    if [[ "$token" == --require-* ]]; then
      local canonical
      canonical="$(checker_flag_to_canonical "$token")"
      if [[ "$supports_canonical" == "1" ]]; then
        out+=("$canonical")
      else
        out+=("$(checker_flag_to_legacy "$canonical")")
      fi
    else
      out+=("$token")
    fi
  done
  printf '%s\n' "${out[@]}"
}

need_cmd jq
need_cmd date
need_cmd mktemp
need_cmd cp

reports_dir="${PHASE5_SETTLEMENT_LAYER_RUN_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
ci_summary_json="${PHASE5_SETTLEMENT_LAYER_RUN_CI_SUMMARY_JSON:-$reports_dir/phase5_settlement_layer_ci_summary.json}"
check_summary_json="${PHASE5_SETTLEMENT_LAYER_RUN_CHECK_SUMMARY_JSON:-$reports_dir/phase5_settlement_layer_check_summary.json}"
summary_json="${PHASE5_SETTLEMENT_LAYER_RUN_SUMMARY_JSON:-$reports_dir/phase5_settlement_layer_run_summary.json}"
canonical_summary_json="${PHASE5_SETTLEMENT_LAYER_RUN_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase5_settlement_layer_run_summary.json}"
print_summary_json="${PHASE5_SETTLEMENT_LAYER_RUN_PRINT_SUMMARY_JSON:-1}"
dry_run="${PHASE5_SETTLEMENT_LAYER_RUN_DRY_RUN:-0}"

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
canonical_summary_json="$(abs_path "$canonical_summary_json")"

mkdir -p "$reports_dir" "$(dirname "$ci_summary_json")" "$(dirname "$check_summary_json")" "$(dirname "$summary_json")" "$(dirname "$canonical_summary_json")"

ci_script="${PHASE5_SETTLEMENT_LAYER_RUN_CI_SCRIPT:-$ROOT_DIR/scripts/ci_phase5_settlement_layer.sh}"
check_script="${PHASE5_SETTLEMENT_LAYER_RUN_CHECK_SCRIPT:-$ROOT_DIR/scripts/phase5_settlement_layer_check.sh}"

if [[ ! -x "$ci_script" ]]; then
  echo "missing executable stage script: $ci_script"
  exit 2
fi
if [[ ! -x "$check_script" ]]; then
  echo "missing executable stage script: $check_script"
  exit 2
fi

check_script_supports_canonical_flags="$(detect_checker_canonical_flags "$check_script")"
check_script_supports_issuer_sponsor_requirement_flag="$(detect_checker_issuer_sponsor_requirement_flag "$check_script")"
check_script_supports_dual_asset_requirement_flag="$(detect_checker_dual_asset_requirement_flag "$check_script")"
check_script_supports_issuer_admin_blockchain_handlers_coverage_requirement_flag="$(detect_checker_issuer_admin_blockchain_handlers_coverage_requirement_flag "$check_script")"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ci_log="$TMP_DIR/ci_phase5.log"
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
declare settlement_dual_asset_parity_ok="null"
declare settlement_dual_asset_parity_status="missing"
declare settlement_dual_asset_parity_source="unresolved"
declare settlement_dual_asset_parity_resolved="0"
declare issuer_sponsor_api_live_smoke_ok="null"
declare issuer_sponsor_api_live_smoke_status="missing"
declare issuer_sponsor_api_live_smoke_source="unresolved"
declare issuer_sponsor_api_live_smoke_resolved="0"
declare issuer_admin_blockchain_handlers_coverage_ok="null"
declare issuer_admin_blockchain_handlers_coverage_status="missing"
declare issuer_admin_blockchain_handlers_coverage_source="unresolved"
declare issuer_admin_blockchain_handlers_coverage_resolved="0"

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
run_step_capture "ci_phase5" "$ci_log" "${ci_command_args[@]}"
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
  ci_contract_error="missing or invalid ci_phase5 summary contract"
  ci_status="fail"
  if [[ "$ci_command_rc" -ne 0 ]]; then
    ci_rc="$ci_command_rc"
  else
    ci_rc=3
  fi
fi

normalized_check_passthrough_args=()
if ((${#check_passthrough_args[@]} > 0)); then
  idx=0
  while (( idx < ${#check_passthrough_args[@]} )); do
    token="${check_passthrough_args[$idx]}"
    if [[ "$token" == --require-* ]]; then
      normalized_check_passthrough_args+=("$(checker_flag_to_canonical "$token")")
    else
      normalized_check_passthrough_args+=("$token")
    fi
    ((idx += 1))
  done
fi

check_command_args=("$check_script" --ci-phase5-summary-json "$ci_summary_json" --summary-json "$check_summary_json")
if ((${#normalized_check_passthrough_args[@]} > 0)); then
  mapfile -t adapted_check_passthrough_args < <(adapt_checker_flags_for_script "$check_script_supports_canonical_flags" "${normalized_check_passthrough_args[@]}")
  check_command_args+=("${adapted_check_passthrough_args[@]}")
fi
if ! array_has_arg "--show-json" "${check_command_args[@]:1}"; then
  check_command_args+=(--show-json 0)
fi
if [[ "$dry_run" == "1" ]]; then
  if ! array_has_checker_flag "--require-settlement-failsoft-ok" "${check_command_args[@]:1}"; then
    if [[ "$check_script_supports_canonical_flags" == "1" ]]; then
      check_command_args+=(--require-settlement-failsoft-ok 0)
    else
      check_command_args+=(--require-windows-server-packaging-ok 0)
    fi
  fi
  if ! array_has_checker_flag "--require-settlement-acceptance-ok" "${check_command_args[@]:1}"; then
    if [[ "$check_script_supports_canonical_flags" == "1" ]]; then
      check_command_args+=(--require-settlement-acceptance-ok 0)
    else
      check_command_args+=(--require-windows-role-runbooks-ok 0)
    fi
  fi
  if ! array_has_checker_flag "--require-settlement-bridge-smoke-ok" "${check_command_args[@]:1}"; then
    if [[ "$check_script_supports_canonical_flags" == "1" ]]; then
      check_command_args+=(--require-settlement-bridge-smoke-ok 0)
    else
      check_command_args+=(--require-cross-platform-interop-ok 0)
    fi
  fi
  if ! array_has_checker_flag "--require-settlement-state-persistence-ok" "${check_command_args[@]:1}"; then
    if [[ "$check_script_supports_canonical_flags" == "1" ]]; then
      check_command_args+=(--require-settlement-state-persistence-ok 0)
    else
      check_command_args+=(--require-role-combination-validation-ok 0)
    fi
  fi
  if [[ "$check_script_supports_dual_asset_requirement_flag" == "1" ]] \
    && ! array_has_checker_flag "--require-settlement-dual-asset-parity-ok" "${check_command_args[@]:1}"; then
    check_command_args+=(--require-settlement-dual-asset-parity-ok 0)
  fi
  if [[ "$check_script_supports_issuer_sponsor_requirement_flag" == "1" ]] \
    && ! array_has_checker_flag "--require-issuer-sponsor-api-live-smoke-ok" "${check_command_args[@]:1}"; then
    check_command_args+=(--require-issuer-sponsor-api-live-smoke-ok 0)
  fi
  if [[ "$check_script_supports_issuer_admin_blockchain_handlers_coverage_requirement_flag" == "1" ]] \
    && ! array_has_checker_flag "--require-issuer-admin-blockchain-handlers-coverage-ok" "${check_command_args[@]:1}"; then
    check_command_args+=(--require-issuer-admin-blockchain-handlers-coverage-ok 0)
  fi
fi
check_command="$(print_cmd "${check_command_args[@]}")"
set +e
run_step_capture "phase5_settlement_layer_check" "$check_log" "${check_command_args[@]}"
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
  check_contract_error="missing or invalid phase5 settlement layer check summary contract"
  check_status="fail"
  if [[ "$check_command_rc" -ne 0 ]]; then
    check_rc="$check_command_rc"
  else
    check_rc=3
  fi
fi
if json_file_valid "$check_summary_json"; then
  settlement_dual_asset_parity_pair="$(resolve_settlement_dual_asset_parity_signal "$check_summary_json")"
  settlement_dual_asset_parity_ok="${settlement_dual_asset_parity_pair%%|*}"
  settlement_dual_asset_parity_pair="${settlement_dual_asset_parity_pair#*|}"
  settlement_dual_asset_parity_status="${settlement_dual_asset_parity_pair%%|*}"
  settlement_dual_asset_parity_pair="${settlement_dual_asset_parity_pair#*|}"
  settlement_dual_asset_parity_source="${settlement_dual_asset_parity_pair%%|*}"
  settlement_dual_asset_parity_resolved="${settlement_dual_asset_parity_pair##*|}"
  issuer_sponsor_api_live_smoke_pair="$(resolve_issuer_sponsor_api_live_smoke_signal "$check_summary_json")"
  issuer_sponsor_api_live_smoke_ok="${issuer_sponsor_api_live_smoke_pair%%|*}"
  issuer_sponsor_api_live_smoke_pair="${issuer_sponsor_api_live_smoke_pair#*|}"
  issuer_sponsor_api_live_smoke_status="${issuer_sponsor_api_live_smoke_pair%%|*}"
  issuer_sponsor_api_live_smoke_pair="${issuer_sponsor_api_live_smoke_pair#*|}"
  issuer_sponsor_api_live_smoke_source="${issuer_sponsor_api_live_smoke_pair%%|*}"
  issuer_sponsor_api_live_smoke_resolved="${issuer_sponsor_api_live_smoke_pair##*|}"
  issuer_admin_blockchain_handlers_coverage_pair="$(resolve_issuer_admin_blockchain_handlers_coverage_signal "$check_summary_json")"
  issuer_admin_blockchain_handlers_coverage_ok="${issuer_admin_blockchain_handlers_coverage_pair%%|*}"
  issuer_admin_blockchain_handlers_coverage_pair="${issuer_admin_blockchain_handlers_coverage_pair#*|}"
  issuer_admin_blockchain_handlers_coverage_status="${issuer_admin_blockchain_handlers_coverage_pair%%|*}"
  issuer_admin_blockchain_handlers_coverage_pair="${issuer_admin_blockchain_handlers_coverage_pair#*|}"
  issuer_admin_blockchain_handlers_coverage_source="${issuer_admin_blockchain_handlers_coverage_pair%%|*}"
  issuer_admin_blockchain_handlers_coverage_resolved="${issuer_admin_blockchain_handlers_coverage_pair##*|}"
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
  --arg canonical_summary_json "$canonical_summary_json" \
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
  --argjson settlement_dual_asset_parity_ok "$settlement_dual_asset_parity_ok" \
  --arg settlement_dual_asset_parity_status "$settlement_dual_asset_parity_status" \
  --arg settlement_dual_asset_parity_source "$settlement_dual_asset_parity_source" \
  --argjson settlement_dual_asset_parity_resolved "$settlement_dual_asset_parity_resolved" \
  --argjson issuer_sponsor_api_live_smoke_ok "$issuer_sponsor_api_live_smoke_ok" \
  --arg issuer_sponsor_api_live_smoke_status "$issuer_sponsor_api_live_smoke_status" \
  --arg issuer_sponsor_api_live_smoke_source "$issuer_sponsor_api_live_smoke_source" \
  --argjson issuer_sponsor_api_live_smoke_resolved "$issuer_sponsor_api_live_smoke_resolved" \
  --argjson issuer_admin_blockchain_handlers_coverage_ok "$issuer_admin_blockchain_handlers_coverage_ok" \
  --arg issuer_admin_blockchain_handlers_coverage_status "$issuer_admin_blockchain_handlers_coverage_status" \
  --arg issuer_admin_blockchain_handlers_coverage_source "$issuer_admin_blockchain_handlers_coverage_source" \
  --argjson issuer_admin_blockchain_handlers_coverage_resolved "$issuer_admin_blockchain_handlers_coverage_resolved" \
  '{
    version: 1,
    schema: {
      id: "phase5_settlement_layer_run_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    metadata: {
      contract: "phase5-settlement-layer",
      runner_script: "phase5_settlement_layer_run.sh"
    },
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      dry_run: ($dry_run == "1"),
      print_summary_json: ($print_summary_json == "1")
    },
    signals: {
      settlement_dual_asset_parity_ok: $settlement_dual_asset_parity_ok,
      settlement_dual_asset_parity_status: $settlement_dual_asset_parity_status,
      settlement_dual_asset_parity_resolved: ($settlement_dual_asset_parity_resolved == 1),
      issuer_sponsor_api_live_smoke_ok: $issuer_sponsor_api_live_smoke_ok,
      issuer_sponsor_api_live_smoke_status: $issuer_sponsor_api_live_smoke_status,
      issuer_sponsor_api_live_smoke_resolved: ($issuer_sponsor_api_live_smoke_resolved == 1),
      issuer_admin_blockchain_handlers_coverage_ok: $issuer_admin_blockchain_handlers_coverage_ok,
      issuer_admin_blockchain_handlers_coverage_status: $issuer_admin_blockchain_handlers_coverage_status,
      issuer_admin_blockchain_handlers_coverage_resolved: ($issuer_admin_blockchain_handlers_coverage_resolved == 1),
      issuer_admin_blockchain_handlers_coverage: {
        status: $issuer_admin_blockchain_handlers_coverage_status,
        ok: $issuer_admin_blockchain_handlers_coverage_ok,
        source: $issuer_admin_blockchain_handlers_coverage_source,
        source_path: $check_summary_json,
        source_fallback: false
      },
      sources: {
        settlement_dual_asset_parity_ok: $settlement_dual_asset_parity_source,
        issuer_sponsor_api_live_smoke_ok: $issuer_sponsor_api_live_smoke_source,
        issuer_admin_blockchain_handlers_coverage_ok: $issuer_admin_blockchain_handlers_coverage_source
      }
    },
    steps: {
      ci_phase5_settlement_layer: {
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
      phase5_settlement_layer_check: {
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
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json,
      ci_summary_json: $ci_summary_json,
      check_summary_json: $check_summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"
if [[ "$summary_json" != "$canonical_summary_json" ]]; then
  canonical_tmp="$(mktemp "${canonical_summary_json}.tmp.XXXXXX")"
  cp "$summary_json" "$canonical_tmp"
  mv -f "$canonical_tmp" "$canonical_summary_json"
fi

echo "[phase5-settlement-layer-run] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[phase5-settlement-layer-run] reports_dir=$reports_dir"
echo "[phase5-settlement-layer-run] summary_json=$summary_json"
echo "[phase5-settlement-layer-run] canonical_summary_json=$canonical_summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
