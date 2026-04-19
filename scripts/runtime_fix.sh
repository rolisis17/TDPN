#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/runtime_fix.sh \
    [--base-port N] \
    [--client-iface IFACE] \
    [--exit-iface IFACE] \
    [--vpn-iface IFACE] \
    [--prune-wg-only-dir [0|1]] \
    [--manual-validation-report [0|1]] \
    [--manual-validation-report-summary-json PATH] \
    [--manual-validation-report-md PATH] \
    [--show-json [0|1]]

Purpose:
  Apply safe runtime cleanup actions from runtime-doctor findings before manual
  WG-only/client-VPN/3-machine validation.

What it can clean:
  - stale wg-only stack state / interfaces / busy default ports
  - stale client-vpn state / interface
  - stale deploy-client-demo-run-* containers and deploy_default network
  - repo/runtime ownership drift for env/state/log paths when running as root
  - optional wg-only runtime dir prune after stack cleanup

Notes:
  - Ownership repairs are only attempted when a safe non-root target owner is known.
  - WG-only, client-VPN, and ownership cleanup requires root; non-root runs report skips.
  - Under sudo, runtime-doctor checks are evaluated as SUDO_USER when possible so
    user-level writability drift is still detected before remediation.
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

effective_uid() {
  if [[ -n "${EASY_NODE_RUNTIME_FIX_EUID:-}" ]]; then
    printf '%s\n' "${EASY_NODE_RUNTIME_FIX_EUID}"
    return
  fi
  if [[ -n "${EUID:-}" ]]; then
    printf '%s\n' "${EUID}"
    return
  fi
  id -u
}

preferred_target_user() {
  if [[ -n "${EASY_NODE_RUNTIME_FIX_TARGET_USER:-}" ]]; then
    printf '%s\n' "${EASY_NODE_RUNTIME_FIX_TARGET_USER}"
    return
  fi
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER:-}" != "root" ]]; then
    printf '%s\n' "${SUDO_USER}"
    return
  fi
  if [[ "$(effective_uid)" != "0" ]]; then
    id -un
    return
  fi
  printf '%s\n' ""
}

preferred_target_group() {
  local user="${1:-}"
  if [[ -n "${EASY_NODE_RUNTIME_FIX_TARGET_GROUP:-}" ]]; then
    printf '%s\n' "${EASY_NODE_RUNTIME_FIX_TARGET_GROUP}"
    return
  fi
  if [[ -n "$user" ]] && id -gn "$user" >/dev/null 2>&1; then
    id -gn "$user"
    return
  fi
  if [[ -n "${SUDO_GID:-}" ]]; then
    printf '%s\n' "${SUDO_GID}"
    return
  fi
  if [[ "$(effective_uid)" != "0" ]]; then
    id -gn
    return
  fi
  printf '%s\n' ""
}

validate_iface_or_die() {
  local name="$1"
  local value="$2"
  if [[ -z "$value" || ! "$value" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
    echo "$name contains invalid characters"
    exit 2
  fi
}

resolve_user_home() {
  local user="$1"
  local home=""
  if [[ -n "$user" ]]; then
    home="$(getent passwd "$user" 2>/dev/null | awk -F: 'NR==1{print $6}')"
  fi
  if [[ -z "$home" ]]; then
    home="${HOME:-}"
  fi
  printf '%s\n' "$home"
}

runtime_fix_default_mutable_allowlist() {
  local owner_user="$1"
  local owner_home
  owner_home="$(resolve_user_home "$owner_user")"
  local client_vpn_default="$ROOT_DIR/deploy/data/client_vpn"
  if [[ "$ROOT_DIR" == /mnt/* ]]; then
    if [[ -n "$owner_home" ]]; then
      client_vpn_default="$owner_home/.local/state/privacynode/client_vpn"
    else
      client_vpn_default="/tmp/privacynode_client_vpn"
    fi
  fi
  printf '%s\n' "$ROOT_DIR/deploy,$ROOT_DIR/.easy-node-logs,$ROOT_DIR/deploy/data/wg_only,$ROOT_DIR/deploy/data/client_vpn,$client_vpn_default"
}

json_escape() {
  jq -Rn --arg v "$1" '$v'
}

extract_json_payload() {
  local log_file="$1"
  awk '/^\[runtime-doctor\] summary_json_payload:/{flag=1; next} flag{print}' "$log_file"
}

validate_manual_validation_summary_payload() {
  local payload="$1"
  local schema_id=""
  local schema_major=""
  local readiness_status=""

  if [[ -z "$payload" ]]; then
    return 1
  fi
  if ! jq -e . >/dev/null 2>&1 <<<"$payload"; then
    return 1
  fi

  schema_id="$(printf '%s\n' "$payload" | jq -r '.schema.id // ""' 2>/dev/null || true)"
  if [[ -n "$schema_id" && "$schema_id" != "manual_validation_readiness_summary" ]]; then
    return 1
  fi
  schema_major="$(printf '%s\n' "$payload" | jq -r '.schema.major // ""' 2>/dev/null || true)"
  if [[ -n "$schema_major" ]]; then
    if [[ ! "$schema_major" =~ ^[0-9]+$ ]] || (( schema_major > 1 )); then
      return 1
    fi
  fi

  readiness_status="$(printf '%s\n' "$payload" | jq -r 'if (.report.readiness_status | type) == "string" then .report.readiness_status else "" end' 2>/dev/null || true)"
  if [[ -z "$readiness_status" ]]; then
    return 1
  fi
  if ! printf '%s\n' "$payload" | jq -e '(.summary | type) == "object"' >/dev/null 2>&1; then
    return 1
  fi

  return 0
}

canonicalize_existing_path() {
  local path="$1"
  if [[ -d "$path" ]]; then
    (cd "$path" >/dev/null 2>&1 && pwd -P)
    return
  fi
  if [[ -e "$path" ]]; then
    local parent base parent_canon
    parent="$(dirname "$path")"
    base="$(basename "$path")"
    parent_canon="$(canonicalize_existing_path "$parent" 2>/dev/null || true)"
    if [[ -z "$parent_canon" ]]; then
      return 1
    fi
    printf '%s/%s\n' "$parent_canon" "$base"
    return
  fi
  return 1
}

canonicalize_nearest_existing_dir() {
  local path="$1"
  local probe="$path"
  while [[ ! -e "$probe" ]]; do
    local next
    next="$(dirname "$probe")"
    if [[ "$next" == "$probe" ]]; then
      return 1
    fi
    probe="$next"
  done
  if [[ -d "$probe" ]]; then
    canonicalize_existing_path "$probe"
  else
    canonicalize_existing_path "$(dirname "$probe")"
  fi
}

canonicalize_path_with_parents() {
  local path="$1"
  if [[ -e "$path" ]]; then
    canonicalize_existing_path "$path"
    return
  fi
  local parent base parent_canon
  parent="$(dirname "$path")"
  base="$(basename "$path")"
  parent_canon="$(canonicalize_existing_path "$parent" 2>/dev/null || true)"
  if [[ -z "$parent_canon" ]]; then
    parent_canon="$(canonicalize_nearest_existing_dir "$parent" 2>/dev/null || true)"
  fi
  if [[ -z "$parent_canon" ]]; then
    return 1
  fi
  if [[ "$parent_canon" == "/" ]]; then
    printf '/%s\n' "$base"
  else
    printf '%s/%s\n' "$parent_canon" "$base"
  fi
}

path_is_within() {
  local path="$1"
  local base="$2"
  [[ "$path" == "$base" || "$path" == "$base/"* ]]
}

path_has_invalid_segments() {
  local path="$1"
  local normalized="${path#/}"
  local segment
  local -a segments=()
  local IFS='/'
  read -r -a segments <<<"$normalized"
  for segment in "${segments[@]}"; do
    if [[ -z "$segment" || "$segment" == "." || "$segment" == ".." ]]; then
      return 0
    fi
  done
  return 1
}

path_allowed_by_prefixes() {
  local target="$1"
  local prefix_list="$2"
  local target_canon
  target_canon="$(canonicalize_path_with_parents "$target" 2>/dev/null || true)"
  if [[ -z "$target_canon" ]]; then
    return 1
  fi

  local prefix trimmed prefix_canon
  local -a prefixes=()
  local IFS=','
  read -r -a prefixes <<<"$prefix_list"
  for prefix in "${prefixes[@]}"; do
    trimmed="$(trim "$prefix")"
    if [[ -z "$trimmed" ]]; then
      continue
    fi
    if [[ "$trimmed" != /* ]]; then
      continue
    fi
    if path_has_invalid_segments "$trimmed"; then
      continue
    fi
    prefix_canon="$(canonicalize_path_with_parents "$trimmed" 2>/dev/null || true)"
    if [[ -z "$prefix_canon" ]]; then
      continue
    fi
    if path_is_within "$target_canon" "$prefix_canon"; then
      return 0
    fi
  done
  return 1
}

validate_mutable_target_path() {
  local path="$1"
  local allowlist="$2"
  if [[ -z "$path" ]]; then
    echo "mutable path refused: empty path"
    return 1
  fi
  if [[ "$path" != /* ]]; then
    echo "mutable path refused: path must be absolute: $path"
    return 1
  fi
  if path_has_invalid_segments "$path"; then
    echo "mutable path refused: path contains invalid segment: $path"
    return 1
  fi
  if ! path_allowed_by_prefixes "$path" "$allowlist"; then
    echo "mutable path refused: path is outside allowlist ($allowlist): $path"
    return 1
  fi
  return 0
}

validate_wg_only_prune_target() {
  local path="$1"
  local allowlist="$2"
  if [[ -z "$path" ]]; then
    echo "wg-only prune refused: empty path"
    return 1
  fi
  if [[ "$path" != /* ]]; then
    echo "wg-only prune refused: path must be absolute: $path"
    return 1
  fi
  if path_has_invalid_segments "$path"; then
    echo "wg-only prune refused: path contains invalid segment: $path"
    return 1
  fi
  if ! path_allowed_by_prefixes "$path" "$allowlist"; then
    echo "wg-only prune refused: path is outside allowlist ($allowlist): $path"
    return 1
  fi
  return 0
}

show_json="0"
prune_wg_only_dir="0"
manual_validation_report_enabled="${RUNTIME_FIX_MANUAL_VALIDATION_REPORT:-1}"
manual_validation_report_summary_json=""
manual_validation_report_md=""
base_port="${EASY_NODE_DOCTOR_WG_ONLY_BASE_PORT:-19280}"
client_iface="${EASY_NODE_DOCTOR_CLIENT_IFACE:-wgcstack0}"
exit_iface="${EASY_NODE_DOCTOR_EXIT_IFACE:-wgestack0}"
vpn_iface="${EASY_NODE_DOCTOR_VPN_IFACE:-wgvpn0}"
wg_only_prune_allowlist="${EASY_NODE_RUNTIME_FIX_WG_ONLY_PRUNE_ALLOWLIST:-$ROOT_DIR/deploy/data/wg_only}"

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
    --prune-wg-only-dir)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        prune_wg_only_dir="${2:-}"
        shift 2
      else
        prune_wg_only_dir="1"
        shift
      fi
      ;;
    --manual-validation-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        manual_validation_report_enabled="${2:-}"
        shift 2
      else
        manual_validation_report_enabled="1"
        shift
      fi
      ;;
    --manual-validation-report-summary-json)
      manual_validation_report_summary_json="${2:-}"
      shift 2
      ;;
    --manual-validation-report-md)
      manual_validation_report_md="${2:-}"
      shift 2
      ;;
    --show-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_json="${2:-}"
        shift 2
      else
        show_json="1"
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

bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--prune-wg-only-dir" "$prune_wg_only_dir"
bool_arg_or_die "--manual-validation-report" "$manual_validation_report_enabled"
if ! [[ "$base_port" =~ ^[0-9]+$ ]]; then
  echo "--base-port must be an integer"
  exit 2
fi
if [[ -z "$client_iface" || -z "$exit_iface" || -z "$vpn_iface" ]]; then
  echo "--client-iface, --exit-iface, and --vpn-iface must be non-empty"
  exit 2
fi
validate_iface_or_die "--client-iface" "$client_iface"
validate_iface_or_die "--exit-iface" "$exit_iface"
validate_iface_or_die "--vpn-iface" "$vpn_iface"

if [[ "$(effective_uid)" == "0" ]]; then
  doctor_script="$ROOT_DIR/scripts/runtime_doctor.sh"
  easy_node_script="$ROOT_DIR/scripts/easy_node.sh"
  manual_validation_report_script="$ROOT_DIR/scripts/manual_validation_report.sh"
else
  doctor_script="${RUNTIME_DOCTOR_SCRIPT:-$ROOT_DIR/scripts/runtime_doctor.sh}"
  easy_node_script="${EASY_NODE_RUNTIME_FIX_EASY_NODE_SCRIPT:-$ROOT_DIR/scripts/easy_node.sh}"
  manual_validation_report_script="${MANUAL_VALIDATION_REPORT_SCRIPT:-$ROOT_DIR/scripts/manual_validation_report.sh}"
fi
if [[ ! -x "$doctor_script" ]]; then
  echo "missing runtime doctor script: $doctor_script"
  exit 2
fi
if [[ ! -x "$easy_node_script" ]]; then
  echo "missing easy_node helper script: $easy_node_script"
  exit 2
fi
if [[ "$manual_validation_report_enabled" == "1" && ! -x "$manual_validation_report_script" ]]; then
  echo "missing manual validation report script: $manual_validation_report_script"
  exit 2
fi

if [[ "$manual_validation_report_enabled" == "1" && -z "$manual_validation_report_summary_json" ]]; then
  manual_validation_report_summary_json="$ROOT_DIR/.easy-node-logs/manual_validation_readiness_summary.json"
fi
if [[ "$manual_validation_report_enabled" == "1" && -z "$manual_validation_report_md" ]]; then
  manual_validation_report_md="$ROOT_DIR/.easy-node-logs/manual_validation_readiness_report.md"
fi

declare -a actions_taken=()
declare -a actions_skipped=()
declare -a actions_failed=()

manual_validation_report_status="skipped"
manual_validation_report_log=""
manual_validation_report_json=""
manual_validation_report_validation_error=""

run_doctor() {
  local log_file
  log_file="$(mktemp)"
  local rc=0
  local -a doctor_cmd=(
    "$doctor_script"
    --base-port "$base_port"
    --client-iface "$client_iface"
    --exit-iface "$exit_iface"
    --vpn-iface "$vpn_iface"
    --show-json 1
  )
  if [[ "$(effective_uid)" == "0" && -n "${SUDO_USER:-}" && "${SUDO_USER:-}" != "root" ]]; then
    local sudo_user_home
    sudo_user_home="$(resolve_user_home "$SUDO_USER")"
    local -a clean_env=(
      env -i
      PATH="$PATH"
      HOME="$sudo_user_home"
      USER="$SUDO_USER"
      LOGNAME="$SUDO_USER"
    )
    if command -v runuser >/dev/null 2>&1; then
      if runuser -u "$SUDO_USER" -- "${clean_env[@]}" "${doctor_cmd[@]}" >"$log_file" 2>&1; then
        rc=0
      else
        rc=$?
      fi
    elif command -v sudo >/dev/null 2>&1; then
      if sudo -u "$SUDO_USER" "${clean_env[@]}" "${doctor_cmd[@]}" >"$log_file" 2>&1; then
        rc=0
      else
        rc=$?
      fi
    else
      if "${doctor_cmd[@]}" >"$log_file" 2>&1; then
        rc=0
      else
        rc=$?
      fi
    fi
  else
    if "${doctor_cmd[@]}" >"$log_file" 2>&1; then
      rc=0
    else
      rc=$?
    fi
  fi
  local json
  json="$(extract_json_payload "$log_file")"
  if [[ -z "$json" ]]; then
    echo "runtime-fix failed: runtime-doctor did not emit JSON summary"
    cat "$log_file"
    rm -f "$log_file"
    exit 1
  fi
  rm -f "$log_file"
  printf '%s' "$json"
  return "$rc"
}

json_has_code() {
  local json="$1"
  local expr="$2"
  printf '%s\n' "$json" | jq -e "$expr" >/dev/null 2>&1
}

repair_ownership_path() {
  local action_name="$1"
  local path="$2"
  local recursive="${3:-0}"
  local chmod_mode="${4:-}"
  local create_dir="${5:-0}"

  if [[ "$current_uid" != "$root_required_uid" ]]; then
    actions_skipped+=("${action_name} (root required)")
    echo "[runtime-fix] action_skipped=${action_name} (root required)"
    return
  fi
  if [[ -z "$target_owner_spec" ]]; then
    actions_skipped+=("${action_name} (target owner unavailable)")
    echo "[runtime-fix] action_skipped=${action_name} (target owner unavailable)"
    return
  fi
  if ! validate_mutable_target_path "$path" "$mutable_path_allowlist"; then
    actions_failed+=("$action_name")
    echo "[runtime-fix] action_failed=${action_name} path=$path reason=unsafe_path"
    return
  fi
  if [[ "$create_dir" == "1" ]]; then
    mkdir -p "$path" >/dev/null 2>&1 || true
  fi
  if [[ ! -e "$path" ]]; then
    actions_failed+=("$action_name")
    echo "[runtime-fix] action_failed=${action_name} path=$path reason=missing"
    return
  fi

  local rc=0
  if [[ "$recursive" == "1" ]]; then
    chown -R "$target_owner_spec" "$path" >/dev/null 2>&1 || rc=$?
  else
    chown "$target_owner_spec" "$path" >/dev/null 2>&1 || rc=$?
  fi
  if [[ "$rc" -eq 0 && -n "$chmod_mode" ]]; then
    chmod "$chmod_mode" "$path" >/dev/null 2>&1 || rc=$?
  fi

  if [[ "$rc" -eq 0 ]]; then
    actions_taken+=("$action_name")
    echo "[runtime-fix] action=${action_name} path=$path owner=$target_owner_spec"
  else
    actions_failed+=("$action_name")
    echo "[runtime-fix] action_failed=${action_name} path=$path owner=$target_owner_spec"
  fi
}

before_doctor_rc=0
before_json="$(
  if run_doctor; then
    :
  else
    before_doctor_rc=$?
  fi
)"
before_status="$(printf '%s\n' "$before_json" | jq -r '.status // "UNKNOWN"')"
before_findings_total="$(printf '%s\n' "$before_json" | jq -r '.summary.findings_total // 0')"
client_env_file="$(printf '%s\n' "$before_json" | jq -r '.paths.client_env_file // ""')"
authority_env_file="$(printf '%s\n' "$before_json" | jq -r '.paths.authority_env_file // ""')"
provider_env_file="$(printf '%s\n' "$before_json" | jq -r '.paths.provider_env_file // ""')"
wg_only_dir="$(printf '%s\n' "$before_json" | jq -r '.paths.wg_only_dir // ""')"
client_vpn_key_dir="$(printf '%s\n' "$before_json" | jq -r '.paths.client_vpn_key_dir // ""')"
log_dir="$(printf '%s\n' "$before_json" | jq -r '.paths.log_dir // ""')"

echo "[runtime-fix] before_status=$before_status findings=$before_findings_total"

root_required_uid="0"
current_uid="$(effective_uid)"
target_owner_user="$(preferred_target_user)"
target_owner_group="$(preferred_target_group "$target_owner_user")"
if [[ -n "$target_owner_user" && -n "$target_owner_group" ]]; then
  target_owner_spec="${target_owner_user}:${target_owner_group}"
else
  target_owner_spec=""
fi
if [[ "$current_uid" == "$root_required_uid" ]]; then
  mutable_path_allowlist="$(runtime_fix_default_mutable_allowlist "$target_owner_user")"
else
  mutable_path_allowlist="${EASY_NODE_RUNTIME_FIX_MUTABLE_PATH_ALLOWLIST:-$(runtime_fix_default_mutable_allowlist "$target_owner_user")}"
fi

if json_has_code "$before_json" '[.findings[].code | select(. == "wg_only_state_stale" or . == "wg_only_client_iface_present" or . == "wg_only_exit_iface_present" or startswith("wg_only_port_busy_"))] | length > 0'; then
  if [[ "$current_uid" == "$root_required_uid" ]]; then
    if "$easy_node_script" wg-only-stack-down --force-iface-cleanup 1 --base-port "$base_port" --client-iface "$client_iface" --exit-iface "$exit_iface" >/dev/null 2>&1; then
      actions_taken+=("wg-only cleanup")
      echo "[runtime-fix] action=wg-only cleanup"
    else
      actions_failed+=("wg-only cleanup")
      echo "[runtime-fix] action_failed=wg-only cleanup"
    fi
  else
    actions_skipped+=("wg-only cleanup (root required)")
    echo "[runtime-fix] action_skipped=wg-only cleanup (root required)"
  fi
fi

if json_has_code "$before_json" '[.findings[].code | select(. == "client_vpn_state_stale" or . == "client_vpn_iface_present")] | length > 0'; then
  if [[ "$current_uid" == "$root_required_uid" ]]; then
    if "$easy_node_script" client-vpn-down --force-iface-cleanup 1 --iface "$vpn_iface" --keep-key 1 >/dev/null 2>&1; then
      actions_taken+=("client-vpn cleanup")
      echo "[runtime-fix] action=client-vpn cleanup"
    else
      actions_failed+=("client-vpn cleanup")
      echo "[runtime-fix] action_failed=client-vpn cleanup"
    fi
  else
    actions_skipped+=("client-vpn cleanup (root required)")
    echo "[runtime-fix] action_skipped=client-vpn cleanup (root required)"
  fi
fi

if json_has_code "$before_json" '[.findings[].code | select(. == "stale_client_demo_containers")] | length > 0'; then
  stale_demo_ids=()
  if command -v docker >/dev/null 2>&1; then
    mapfile -t stale_demo_ids < <(docker ps -aq --filter 'name=^deploy-client-demo-run-' 2>/dev/null || true)
  fi
  if (( ${#stale_demo_ids[@]} > 0 )); then
    if docker rm -f "${stale_demo_ids[@]}" >/dev/null 2>&1; then
      actions_taken+=("demo container cleanup")
      echo "[runtime-fix] action=demo container cleanup ids=${stale_demo_ids[*]}"
    else
      actions_failed+=("demo container cleanup")
      echo "[runtime-fix] action_failed=demo container cleanup ids=${stale_demo_ids[*]}"
    fi
  fi
  if command -v docker >/dev/null 2>&1 && docker network inspect deploy_default >/dev/null 2>&1; then
    if docker network rm deploy_default >/dev/null 2>&1; then
      actions_taken+=("demo network cleanup")
      echo "[runtime-fix] action=demo network cleanup"
    else
      actions_failed+=("demo network cleanup")
      echo "[runtime-fix] action_failed=demo network cleanup"
    fi
  fi
fi

if json_has_code "$before_json" '[.findings[].code | select(. == "client_env_file_not_writable")] | length > 0'; then
  repair_ownership_path "client env ownership repair" "$client_env_file" 0 "" 0
fi

if json_has_code "$before_json" '[.findings[].code | select(. == "authority_env_file_not_writable")] | length > 0'; then
  repair_ownership_path "authority env ownership repair" "$authority_env_file" 0 "" 0
fi

if json_has_code "$before_json" '[.findings[].code | select(. == "provider_env_file_not_writable")] | length > 0'; then
  repair_ownership_path "provider env ownership repair" "$provider_env_file" 0 "" 0
fi

if json_has_code "$before_json" '[.findings[].code | select(. == "client_vpn_key_dir_not_writable")] | length > 0'; then
  repair_ownership_path "client-vpn key dir ownership repair" "$client_vpn_key_dir" 1 "700" 1
fi

if json_has_code "$before_json" '[.findings[].code | select(. == "log_dir_not_writable")] | length > 0'; then
  repair_ownership_path "log dir ownership repair" "$log_dir" 0 "700" 1
fi

if json_has_code "$before_json" '[.findings[].code | select(. == "wg_only_dir_not_writable")] | length > 0'; then
  if [[ "$prune_wg_only_dir" == "1" ]]; then
    if [[ "$current_uid" == "$root_required_uid" ]]; then
      if validate_wg_only_prune_target "$wg_only_dir" "$wg_only_prune_allowlist"; then
        if rm -rf "$wg_only_dir"; then
          actions_taken+=("wg-only runtime dir prune")
          echo "[runtime-fix] action=wg-only runtime dir prune path=$wg_only_dir"
          if [[ -n "$target_owner_spec" ]]; then
            repair_ownership_path "wg-only runtime dir ownership repair" "$wg_only_dir" 1 "700" 1
          fi
        else
          actions_failed+=("wg-only runtime dir prune")
          echo "[runtime-fix] action_failed=wg-only runtime dir prune path=$wg_only_dir"
        fi
      else
        actions_failed+=("wg-only runtime dir prune")
        echo "[runtime-fix] action_failed=wg-only runtime dir prune path=$wg_only_dir reason=unsafe_path"
      fi
    else
      actions_skipped+=("wg-only runtime dir prune (root required)")
      echo "[runtime-fix] action_skipped=wg-only runtime dir prune (root required)"
    fi
  else
    repair_ownership_path "wg-only runtime dir ownership repair" "$wg_only_dir" 1 "" 1
  fi
fi

after_doctor_rc=0
after_json="$(
  if run_doctor; then
    :
  else
    after_doctor_rc=$?
  fi
)"
after_status="$(printf '%s\n' "$after_json" | jq -r '.status // "UNKNOWN"')"
after_findings_total="$(printf '%s\n' "$after_json" | jq -r '.summary.findings_total // 0')"

echo "[runtime-fix] after_status=$after_status findings=$after_findings_total actions_taken=${#actions_taken[@]} actions_skipped=${#actions_skipped[@]} actions_failed=${#actions_failed[@]}"
echo "[runtime-fix] mutable_path_allowlist=$mutable_path_allowlist"
if ((${#actions_taken[@]} == 0 && ${#actions_skipped[@]} == 0 && ${#actions_failed[@]} == 0)); then
  echo "[runtime-fix] no cleanup actions were needed"
fi

if [[ "$manual_validation_report_enabled" == "1" ]]; then
  manual_validation_report_log="$(mktemp)"
  if "$manual_validation_report_script" \
    --base-port "$base_port" \
    --client-iface "$client_iface" \
    --exit-iface "$exit_iface" \
    --vpn-iface "$vpn_iface" \
    --summary-json "$manual_validation_report_summary_json" \
    --report-md "$manual_validation_report_md" \
    --print-report 0 \
    --print-summary-json 1 >"$manual_validation_report_log" 2>&1; then
    manual_validation_report_status="ok"
  else
    manual_validation_report_status="failed"
  fi
  manual_validation_report_json="$(awk '/^\[manual-validation-report\] summary_json_payload:/{flag=1; next} flag{print}' "$manual_validation_report_log")"
  if [[ -z "$manual_validation_report_json" && -f "$manual_validation_report_summary_json" ]] && jq -e . "$manual_validation_report_summary_json" >/dev/null 2>&1; then
    manual_validation_report_json="$(cat "$manual_validation_report_summary_json")"
  fi
  if ! validate_manual_validation_summary_payload "$manual_validation_report_json"; then
    manual_validation_report_status="failed"
    manual_validation_report_json=""
    manual_validation_report_validation_error="summary_payload_invalid_or_incompatible"
  fi
  echo "[runtime-fix] manual_validation_report_status=$manual_validation_report_status"
  echo "[runtime-fix] manual_validation_report_validation_error=$manual_validation_report_validation_error"
  echo "[runtime-fix] manual_validation_report_summary_json=$manual_validation_report_summary_json"
  echo "[runtime-fix] manual_validation_report_md=$manual_validation_report_md"
  echo "[runtime-fix] manual_validation_report_log=$manual_validation_report_log"
fi

if [[ "$show_json" == "1" ]]; then
  summary_json="$(
    jq -n \
      --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --argjson before "$before_json" \
      --argjson after "$after_json" \
      --argjson base_port "$base_port" \
      --arg client_iface "$client_iface" \
      --arg exit_iface "$exit_iface" \
      --arg vpn_iface "$vpn_iface" \
      --arg wg_only_prune_allowlist "$wg_only_prune_allowlist" \
      --arg mutable_path_allowlist "$mutable_path_allowlist" \
      --argjson prune_wg_only_dir "$prune_wg_only_dir" \
      --argjson root_uid "$current_uid" \
      --arg target_owner_user "$target_owner_user" \
      --arg target_owner_group "$target_owner_group" \
      --arg target_owner_spec "$target_owner_spec" \
      --arg manual_validation_report_status "$manual_validation_report_status" \
      --arg manual_validation_report_validation_error "$manual_validation_report_validation_error" \
      --arg manual_validation_report_summary_json "$manual_validation_report_summary_json" \
      --arg manual_validation_report_md "$manual_validation_report_md" \
      --arg manual_validation_report_log "$manual_validation_report_log" \
      --argjson manual_validation_report_json "${manual_validation_report_json:-null}" \
      --argjson before_doctor_rc "$before_doctor_rc" \
      --argjson after_doctor_rc "$after_doctor_rc" \
      --argjson actions_taken "$(printf '%s\n' "${actions_taken[@]:-}" | jq -Rn '[inputs | select(length > 0)]')" \
      --argjson actions_skipped "$(printf '%s\n' "${actions_skipped[@]:-}" | jq -Rn '[inputs | select(length > 0)]')" \
      --argjson actions_failed "$(printf '%s\n' "${actions_failed[@]:-}" | jq -Rn '[inputs | select(length > 0)]')" \
      '{
        version: 1,
        generated_at_utc: $generated_at_utc,
        inputs: {
          base_port: $base_port,
          client_iface: $client_iface,
          exit_iface: $exit_iface,
          vpn_iface: $vpn_iface,
          wg_only_prune_allowlist: $wg_only_prune_allowlist,
          mutable_path_allowlist: $mutable_path_allowlist,
          prune_wg_only_dir: ($prune_wg_only_dir == 1),
          effective_uid: $root_uid,
          target_owner_user: $target_owner_user,
          target_owner_group: $target_owner_group,
          target_owner_spec: $target_owner_spec
        },
        doctor: {
          before_rc: $before_doctor_rc,
          after_rc: $after_doctor_rc,
          before: $before,
          after: $after
        },
        manual_validation_report: {
          enabled: ($manual_validation_report_status != "skipped"),
          status: $manual_validation_report_status,
          validation_error: $manual_validation_report_validation_error,
          summary_json: $manual_validation_report_summary_json,
          report_md: $manual_validation_report_md,
          log: $manual_validation_report_log,
          summary: (if ($manual_validation_report_json | type) == "object" then $manual_validation_report_json else null end)
        },
        actions: {
          taken: $actions_taken,
          skipped: $actions_skipped,
          failed: $actions_failed
        }
      }'
  )"
  echo "[runtime-fix] summary_json_payload:"
  printf '%s\n' "$summary_json"
fi

if ((${#actions_failed[@]} > 0)); then
  exit 1
fi
if [[ "$after_status" == "FAIL" ]]; then
  exit 1
fi
exit 0
