#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DESKTOP_DIR="$ROOT_DIR/apps/desktop"

DOCTOR_SCRIPT_DEFAULT="$ROOT_DIR/scripts/linux/desktop_doctor.sh"
NATIVE_BOOTSTRAP_SCRIPT_DEFAULT="$ROOT_DIR/scripts/linux/desktop_native_bootstrap.sh"

show_usage() {
  cat <<'USAGE'
TDPN/GPM desktop packaged-run scaffold (linux)

Usage:
  ./scripts/linux/desktop_packaged_run.sh [options]

Options:
  --desktop-executable-path PATH    Explicit packaged executable path to launch.
  --install-missing                 Enable prerequisite auto-remediation.
  --no-install-missing              Disable prerequisite auto-remediation.
  --dry-run                         Print intended actions without launching desktop.
  --api-addr HOST:PORT              Local control API address (default: 127.0.0.1:8095).
  --summary-json PATH               Summary JSON output path.
  --print-summary-json 0|1          Print summary JSON payload to stdout.
  --doctor-summary-json PATH        Forwarded to desktop_doctor.sh summary output path.
  --print-doctor-summary-json 0|1   Forwarded to desktop_doctor.sh summary-json print toggle.
  --help                            Show this help message.

Notes:
  - Auto-remediation is enabled by default.
  - Env overrides: GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING, TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING.
  - Runs scripts/linux/desktop_doctor.sh first (check or fix mode).
  - Prefers packaged executable path (explicit or auto-discovered).
  - If scripts/linux/desktop_native_bootstrap.sh exists, delegates launch to it.
  - If native bootstrap is absent, uses scaffold fallback:
      packaged executable (if found) or `npm run tauri -- dev` from apps/desktop.
USAGE
}

log_step() {
  printf '[desktop-packaged-run] %s\n' "$1"
}

to_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

desktop_executable_path=""
install_missing_cli=""
install_missing_effective="1"
dry_run="0"
api_addr="127.0.0.1:8095"
summary_json="$ROOT_DIR/.easy-node-logs/desktop_packaged_run_linux_summary.json"
print_summary_json="0"
doctor_summary_json=""
print_doctor_summary_json=""
resolved_desktop_executable_path=""
resolved_desktop_executable_source="none"
failure_stage=""
doctor_status="skip"
doctor_rc="0"
bootstrap_status="skip"
bootstrap_rc="0"
final_status=""
final_rc=""
summary_emitted="0"
emit_summary_on_exit="1"

json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

json_bool() {
  if [[ "${1:-0}" == "1" ]]; then
    printf '%s' "true"
    return
  fi
  printf '%s' "false"
}

write_summary_json() {
  if [[ "$emit_summary_on_exit" != "1" ]]; then
    return
  fi
  if [[ "$summary_emitted" == "1" ]]; then
    return
  fi
  summary_emitted="1"

  local generated_at_utc
  generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local summary_dir
  summary_dir="$(dirname "$summary_json")"
  if [[ -n "$summary_dir" ]]; then
    mkdir -p "$summary_dir" >/dev/null 2>&1 || true
  fi

  if ! cat >"$summary_json" <<EOF
{
  "version": 1,
  "generated_at_utc": "$(json_escape "$generated_at_utc")",
  "status": "$(json_escape "$final_status")",
  "rc": ${final_rc},
  "platform": "linux",
  "mode": "desktop_packaged_run_scaffold",
  "dry_run": $(json_bool "$dry_run"),
  "install_missing_intent": $(json_bool "$install_missing_effective"),
  "api_addr": "$(json_escape "$api_addr")",
  "resolved_desktop_executable_path": "$(json_escape "$resolved_desktop_executable_path")",
  "resolved_desktop_executable_source": "$(json_escape "$resolved_desktop_executable_source")",
  "failure_stage": "$(json_escape "$failure_stage")",
  "doctor": {
    "status": "$(json_escape "$doctor_status")",
    "rc": ${doctor_rc}
  },
  "bootstrap": {
    "status": "$(json_escape "$bootstrap_status")",
    "rc": ${bootstrap_rc}
  },
  "doctor_summary_json_forwarded": "$(json_escape "$doctor_summary_json")"
}
EOF
  then
    printf 'desktop packaged-run warning: failed to write summary json: %s\n' "$summary_json" >&2
    return
  fi

  log_step "summary_json=$summary_json"
  if [[ "$print_summary_json" == "1" ]]; then
    log_step "summary_json_payload:"
    cat "$summary_json"
  fi
}

finish_with_status() {
  local rc="$1"
  if [[ -z "$final_rc" ]]; then
    final_rc="$rc"
  fi
  if [[ -z "$final_status" ]]; then
    if [[ "$final_rc" -eq 0 ]]; then
      final_status="pass"
    else
      final_status="fail"
    fi
  fi
  if [[ -n "$failure_stage" && "$final_rc" -eq 0 ]]; then
    failure_stage=""
  fi
  write_summary_json
  exit "$final_rc"
}

on_exit_emit_summary() {
  local rc="$1"
  if [[ -n "$final_rc" ]]; then
    return
  fi
  final_rc="$rc"
  if [[ "$rc" -eq 0 ]]; then
    final_status="pass"
  else
    final_status="fail"
    if [[ -z "$failure_stage" ]]; then
      failure_stage="runtime"
    fi
  fi
  write_summary_json
}

fail() {
  local message="$1"
  local stage="${2:-runtime}"
  failure_stage="$stage"
  printf 'desktop packaged-run failed: %s\n' "$message" >&2
  finish_with_status 1
}

trap 'on_exit_emit_summary $?' EXIT

parse_bool_token() {
  local token="${1:-}"
  token="${token#"${token%%[![:space:]]*}"}"
  token="${token%"${token##*[![:space:]]}"}"
  token="${token#\$}"
  token="$(to_lower "$token")"

  case "$token" in
    1|true|yes|on)
      printf '%s\n' "1"
      return 0
      ;;
    0|false|no|off)
      printf '%s\n' "0"
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

resolve_install_missing_env_override() {
  local env_name
  local raw_value
  local parsed_value

  for env_name in GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING; do
    raw_value="${!env_name:-}"
    if parsed_value="$(parse_bool_token "$raw_value")"; then
      printf '%s\n' "$parsed_value"
      return 0
    fi
  done

  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --desktop-executable-path)
      if [[ $# -lt 2 ]]; then
        fail "--desktop-executable-path requires a value" "parse_args"
      fi
      desktop_executable_path="$2"
      shift 2
      ;;
    --install-missing)
      install_missing_cli="1"
      shift
      ;;
    --no-install-missing)
      install_missing_cli="0"
      shift
      ;;
    --dry-run)
      dry_run="1"
      shift
      ;;
    --api-addr)
      if [[ $# -lt 2 ]]; then
        fail "--api-addr requires a value" "parse_args"
      fi
      api_addr="$2"
      shift 2
      ;;
    --summary-json)
      if [[ $# -lt 2 ]]; then
        fail "--summary-json requires a value" "parse_args"
      fi
      summary_json="$2"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -lt 2 ]]; then
        fail "--print-summary-json requires a value (0|1)" "parse_args"
      fi
      print_summary_json="$2"
      shift 2
      ;;
    --doctor-summary-json)
      if [[ $# -lt 2 ]]; then
        fail "--doctor-summary-json requires a value" "parse_args"
      fi
      doctor_summary_json="$2"
      shift 2
      ;;
    --print-doctor-summary-json)
      if [[ $# -lt 2 ]]; then
        fail "--print-doctor-summary-json requires a value (0|1)" "parse_args"
      fi
      print_doctor_summary_json="$2"
      shift 2
      ;;
    -h|--help)
      emit_summary_on_exit="0"
      show_usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1" "parse_args"
      ;;
  esac
done

if [[ -n "$install_missing_cli" ]]; then
  install_missing_effective="$install_missing_cli"
else
  if env_install_missing="$(resolve_install_missing_env_override)"; then
    install_missing_effective="$env_install_missing"
  fi
fi

if [[ "$print_summary_json" != "0" && "$print_summary_json" != "1" ]]; then
  fail "--print-summary-json must be 0 or 1" "parse_args"
fi

if [[ -n "$print_doctor_summary_json" && "$print_doctor_summary_json" != "0" && "$print_doctor_summary_json" != "1" ]]; then
  fail "--print-doctor-summary-json must be 0 or 1" "parse_args"
fi

resolve_auto_packaged_executable() {
  local env_name
  for env_name in GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE GPM_DESKTOP_PACKAGED_EXE TDPN_DESKTOP_PACKAGED_EXE; do
    local value="${!env_name:-}"
    if [[ -z "$value" ]]; then
      continue
    fi
    if [[ -f "$value" ]]; then
      resolved_desktop_executable_source="env"
      printf '%s\n' "$value"
      return 0
    fi
    log_step "warning: env override $env_name points to a missing file: $value"
  done

  local release_root="$DESKTOP_DIR/src-tauri/target/release"
  local candidate
  local candidates=(
    "$release_root/global-private-mesh-desktop"
    "$release_root/Global Private Mesh Desktop"
    "$release_root/gpm-desktop"
    "$release_root/tdpn-desktop"
    "$release_root/GPM Desktop"
    "$release_root/TDPN Desktop"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -f "$candidate" ]]; then
      resolved_desktop_executable_source="release"
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  local appimage_candidates=(
    "$release_root/bundle/appimage/Global Private Mesh Desktop.AppImage"
    "$release_root/bundle/appimage/global-private-mesh-desktop.AppImage"
    "$release_root/bundle/appimage/global-private-mesh-desktop.appimage"
    "$release_root/bundle/appimage/GPM Desktop.AppImage"
    "$release_root/bundle/appimage/gpm-desktop.AppImage"
    "$release_root/bundle/appimage/gpm-desktop.appimage"
    "$release_root/bundle/appimage/TDPN Desktop.AppImage"
    "$release_root/bundle/appimage/tdpn-desktop.AppImage"
    "$release_root/bundle/appimage/tdpn-desktop.appimage"
  )
  for candidate in "${appimage_candidates[@]}"; do
    if [[ -f "$candidate" ]]; then
      resolved_desktop_executable_source="appimage"
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  local appimage
  local appimage_glob
  for appimage_glob in "*.AppImage" "*.appimage"; do
    for appimage in "$release_root"/bundle/appimage/$appimage_glob; do
      if [[ -f "$appimage" ]]; then
        resolved_desktop_executable_source="appimage"
        printf '%s\n' "$appimage"
        return 0
      fi
    done
  done

  return 1
}

run_doctor_first() {
  local doctor_script="${DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST:-${DESKTOP_LINUX_DOCTOR_SCRIPT:-$DOCTOR_SCRIPT_DEFAULT}}"
  if [[ ! -f "$doctor_script" ]]; then
    fail "missing doctor script: $doctor_script (expected scripts/linux/desktop_doctor.sh)" "doctor"
  fi

  local doctor_args=()
  if [[ "$install_missing_effective" == "1" ]]; then
    doctor_args+=(--mode fix --install-missing)
  else
    doctor_args+=(--mode check)
  fi
  if [[ "$dry_run" == "1" ]]; then
    doctor_args+=(--dry-run)
  fi
  if [[ -n "$doctor_summary_json" ]]; then
    doctor_args+=(--summary-json "$doctor_summary_json")
  fi
  if [[ -n "$print_doctor_summary_json" ]]; then
    doctor_args+=(--print-summary-json "$print_doctor_summary_json")
  fi

  log_step "doctor-start mode=$([[ "$install_missing_effective" == "1" ]] && printf '%s' 'fix' || printf '%s' 'check') dry_run=$dry_run script=$doctor_script"
  doctor_status="running"
  failure_stage="doctor"
  if bash "$doctor_script" "${doctor_args[@]}"; then
    doctor_rc="0"
    doctor_status="pass"
    log_step "doctor-finish status=ok"
    failure_stage=""
    return 0
  fi
  doctor_rc=$?
  if [[ "$doctor_rc" -ne 0 ]]; then
    doctor_status="fail"
    return "$doctor_rc"
  fi
  doctor_status="fail"
  return 1
}

if ! run_doctor_first; then
  finish_with_status "$doctor_rc"
fi

resolved_desktop_executable_path="$desktop_executable_path"
if [[ -n "$resolved_desktop_executable_path" ]]; then
  resolved_desktop_executable_source="override"
  if [[ ! -f "$resolved_desktop_executable_path" ]]; then
    fail "desktop executable override was not found: $resolved_desktop_executable_path" "desktop_executable_override"
  fi
else
  if auto_path="$(resolve_auto_packaged_executable)"; then
    resolved_desktop_executable_path="$auto_path"
    log_step "packaged executable auto-discovered: $resolved_desktop_executable_path"
  fi
fi

if [[ -n "$resolved_desktop_executable_path" ]]; then
  export GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE="$resolved_desktop_executable_path"
  export GPM_DESKTOP_PACKAGED_EXE="$resolved_desktop_executable_path"
  export TDPN_DESKTOP_PACKAGED_EXE="$resolved_desktop_executable_path"
fi
export GPM_LOCAL_API_ADDR="$api_addr"
export TDPN_LOCAL_API_ADDR="$api_addr"

native_bootstrap_script="${DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST:-${DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT:-$NATIVE_BOOTSTRAP_SCRIPT_DEFAULT}}"
if [[ -f "$native_bootstrap_script" ]]; then
  native_bootstrap_args=(
    --mode run-full
    --desktop-launch-strategy auto
    --api-addr "$api_addr"
  )
  if [[ "$install_missing_effective" == "1" ]]; then
    native_bootstrap_args+=(--install-missing)
  fi
  if [[ "$dry_run" == "1" ]]; then
    native_bootstrap_args+=(--dry-run)
  fi
  if [[ -n "$resolved_desktop_executable_path" ]]; then
    native_bootstrap_args+=(--desktop-launch-strategy packaged --desktop-executable-override-path "$resolved_desktop_executable_path")
  fi
  log_step "launching via native bootstrap script: $native_bootstrap_script"
  bootstrap_status="running"
  failure_stage="bootstrap"
  if bash "$native_bootstrap_script" "${native_bootstrap_args[@]}"; then
    bootstrap_rc="0"
    bootstrap_status="pass"
    failure_stage=""
    finish_with_status 0
  fi
  bootstrap_rc=$?
  bootstrap_status="fail"
  finish_with_status "$bootstrap_rc"
fi

if [[ -n "$resolved_desktop_executable_path" ]]; then
  if [[ "$dry_run" == "1" ]]; then
    log_step "dry-run: would launch packaged executable: $resolved_desktop_executable_path"
    finish_with_status 0
  fi
  if [[ ! -x "$resolved_desktop_executable_path" ]]; then
    fail "packaged executable is not executable: $resolved_desktop_executable_path" "packaged_executable"
  fi
  log_step "launching packaged executable directly (native bootstrap not found): $resolved_desktop_executable_path"
  failure_stage="packaged_executable"
  if "$resolved_desktop_executable_path"; then
    failure_stage=""
    finish_with_status 0
  fi
  finish_with_status $?
fi

if [[ ! -d "$DESKTOP_DIR" || ! -f "$DESKTOP_DIR/package.json" ]]; then
  fail "desktop project directory missing package.json: $DESKTOP_DIR" "fallback_launch"
fi

if [[ "$dry_run" == "1" ]]; then
  log_step "scaffold-note: native bootstrap not found; fallback is npm run tauri -- dev"
  log_step "dry-run: would run in $DESKTOP_DIR: npm run tauri -- dev"
  finish_with_status 0
fi

if ! command -v npm >/dev/null 2>&1; then
  fail "npm is required for fallback launch but was not found on PATH" "fallback_launch"
fi

log_step "scaffold-note: native bootstrap not found; running fallback command from apps/desktop"
failure_stage="fallback_launch"
if (
  cd "$DESKTOP_DIR"
  npm run tauri -- dev
); then
  failure_stage=""
  finish_with_status 0
fi
finish_with_status $?
