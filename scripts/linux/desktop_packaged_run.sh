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
  --install-missing                 Run doctor in fix mode with install-missing enabled.
  --dry-run                         Print intended actions without launching desktop.
  --api-addr HOST:PORT              Local control API address (default: 127.0.0.1:8095).
  --doctor-summary-json PATH        Forwarded to desktop_doctor.sh summary output path.
  --print-doctor-summary-json 0|1   Forwarded to desktop_doctor.sh summary-json print toggle.
  --help                            Show this help message.

Notes:
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

fail() {
  printf 'desktop packaged-run failed: %s\n' "$1" >&2
  exit 1
}

to_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

desktop_executable_path=""
install_missing="0"
dry_run="0"
api_addr="127.0.0.1:8095"
doctor_summary_json=""
print_doctor_summary_json=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --desktop-executable-path)
      if [[ $# -lt 2 ]]; then
        fail "--desktop-executable-path requires a value"
      fi
      desktop_executable_path="$2"
      shift 2
      ;;
    --install-missing)
      install_missing="1"
      shift
      ;;
    --dry-run)
      dry_run="1"
      shift
      ;;
    --api-addr)
      if [[ $# -lt 2 ]]; then
        fail "--api-addr requires a value"
      fi
      api_addr="$2"
      shift 2
      ;;
    --doctor-summary-json)
      if [[ $# -lt 2 ]]; then
        fail "--doctor-summary-json requires a value"
      fi
      doctor_summary_json="$2"
      shift 2
      ;;
    --print-doctor-summary-json)
      if [[ $# -lt 2 ]]; then
        fail "--print-doctor-summary-json requires a value (0|1)"
      fi
      print_doctor_summary_json="$2"
      shift 2
      ;;
    -h|--help)
      show_usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

if [[ -n "$print_doctor_summary_json" && "$print_doctor_summary_json" != "0" && "$print_doctor_summary_json" != "1" ]]; then
  fail "--print-doctor-summary-json must be 0 or 1"
fi

resolve_auto_packaged_executable() {
  local env_name
  for env_name in GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE GPM_DESKTOP_PACKAGED_EXE TDPN_DESKTOP_PACKAGED_EXE; do
    local value="${!env_name:-}"
    if [[ -z "$value" ]]; then
      continue
    fi
    if [[ -f "$value" ]]; then
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
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  local appimage
  local appimage_glob
  for appimage_glob in "*.AppImage" "*.appimage"; do
    for appimage in "$release_root"/bundle/appimage/$appimage_glob; do
      if [[ -f "$appimage" ]]; then
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
    fail "missing doctor script: $doctor_script (expected scripts/linux/desktop_doctor.sh)"
  fi

  local doctor_args=()
  if [[ "$install_missing" == "1" ]]; then
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

  log_step "doctor-start mode=$([[ "$install_missing" == "1" ]] && printf '%s' 'fix' || printf '%s' 'check') dry_run=$dry_run script=$doctor_script"
  bash "$doctor_script" "${doctor_args[@]}"
  log_step "doctor-finish status=ok"
}

run_doctor_first

resolved_desktop_executable_path="$desktop_executable_path"
if [[ -n "$resolved_desktop_executable_path" ]]; then
  if [[ ! -f "$resolved_desktop_executable_path" ]]; then
    fail "desktop executable override was not found: $resolved_desktop_executable_path"
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
  if [[ "$dry_run" == "1" ]]; then
    native_bootstrap_args+=(--dry-run)
  fi
  if [[ -n "$resolved_desktop_executable_path" ]]; then
    native_bootstrap_args+=(--desktop-launch-strategy packaged --desktop-executable-override-path "$resolved_desktop_executable_path")
  fi
  log_step "launching via native bootstrap script: $native_bootstrap_script"
  bash "$native_bootstrap_script" "${native_bootstrap_args[@]}"
  exit $?
fi

if [[ -n "$resolved_desktop_executable_path" ]]; then
  if [[ "$dry_run" == "1" ]]; then
    log_step "dry-run: would launch packaged executable: $resolved_desktop_executable_path"
    exit 0
  fi
  if [[ ! -x "$resolved_desktop_executable_path" ]]; then
    fail "packaged executable is not executable: $resolved_desktop_executable_path"
  fi
  log_step "launching packaged executable directly (native bootstrap not found): $resolved_desktop_executable_path"
  "$resolved_desktop_executable_path"
  exit $?
fi

if [[ ! -d "$DESKTOP_DIR" || ! -f "$DESKTOP_DIR/package.json" ]]; then
  fail "desktop project directory missing package.json: $DESKTOP_DIR"
fi

if [[ "$dry_run" == "1" ]]; then
  log_step "scaffold-note: native bootstrap not found; fallback is npm run tauri -- dev"
  log_step "dry-run: would run in $DESKTOP_DIR: npm run tauri -- dev"
  exit 0
fi

if ! command -v npm >/dev/null 2>&1; then
  fail "npm is required for fallback launch but was not found on PATH"
fi

log_step "scaffold-note: native bootstrap not found; running fallback command from apps/desktop"
(
  cd "$DESKTOP_DIR"
  npm run tauri -- dev
)
