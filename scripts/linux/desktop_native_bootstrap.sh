#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DESKTOP_DIR="$ROOT_DIR/apps/desktop"
DOCTOR_SCRIPT="$ROOT_DIR/scripts/linux/desktop_doctor.sh"

MODE="bootstrap"
DESKTOP_LAUNCH_STRATEGY="auto"
DESKTOP_EXECUTABLE_OVERRIDE_PATH=""
INSTALL_MISSING="0"
DRY_RUN="0"
API_ADDR="127.0.0.1:8095"
API_HEALTH_TIMEOUT_SEC="25"
FORCE_NPM_INSTALL="0"
SUMMARY_JSON_PATH=""
PRINT_SUMMARY_JSON="0"

RESOLVED_DESKTOP_STRATEGY=""
RESOLVED_DESKTOP_EXECUTABLE_PATH=""
RESOLVED_DESKTOP_EXECUTABLE_SOURCE=""
API_BG_PID=""
API_HEALTH_ENDPOINT=""
SUMMARY_STATUS="ok"
SUMMARY_ERROR=""
RECOMMENDED_COMMANDS=()
NATIVE_DESKTOP_PREREQS_ASSERTED="0"
RUNTIME_TOOLCHAIN_PREREQS_ASSERTED="0"

log() {
  echo "[desktop-native-bootstrap] $*"
}

die() {
  echo "[desktop-native-bootstrap] error: $*" >&2
  SUMMARY_ERROR="$*"
  exit 1
}

json_escape() {
  local value="${1-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

json_bool() {
  if [[ "${1:-0}" == "1" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

json_array_from_values() {
  local output="["
  local first="1"
  local value
  for value in "$@"; do
    if [[ "$first" == "0" ]]; then
      output+=", "
    fi
    first="0"
    output+="\"$(json_escape "$value")\""
  done
  output+="]"
  printf '%s' "$output"
}

write_summary_json_file() {
  local path="$1"
  local payload="$2"
  [[ -z "$path" ]] && return 0
  local parent_dir
  parent_dir="$(dirname "$path")"
  mkdir -p "$parent_dir"
  printf '%s\n' "$payload" >"$path"
  log "summary json written: $path"
}

show_usage() {
  cat <<'USAGE'
Linux desktop native bootstrap scaffold

Usage:
  ./scripts/linux/desktop_native_bootstrap.sh [options]

Options:
  --mode MODE                                 One of: check, bootstrap, run-api, run-desktop, run-full
  --desktop-launch-strategy STRATEGY          One of: dev, packaged, auto (default: auto)
  --desktop-executable-override-path PATH     Explicit packaged executable path for packaged launch
  --install-missing                           Ask desktop_doctor to attempt remediation (fix mode)
  --dry-run                                   Print actions without executing
  --api-addr HOST:PORT                        Local API bind/health address (default: 127.0.0.1:8095)
  --api-health-timeout-sec N                  Local API health wait timeout in seconds for run-full (default: 25)
  --force-npm-install                         Force npm install before desktop dev launch
  --summary-json PATH                         Write run summary JSON to PATH
  --print-summary-json 0|1                    Print summary JSON to stdout (default: 0)
  --help, -h                                  Show this help

Modes:
  check        Run linux desktop_doctor in check mode (or fix when --install-missing is set)
  bootstrap    Run linux desktop_doctor in check/fix mode according to --install-missing
  run-api      Run local API from repo root: go run ./cmd/node --local-api
  run-desktop  Launch desktop only (dev or packaged strategy)
  run-full     Start local API in background, wait for health, then launch desktop

Notes:
  - This is a scaffold and expects scripts/linux/desktop_doctor.sh for non-dry-run check/bootstrap.
  - Desktop dev launch modes fail early when Linux native desktop prerequisites are missing.
  - In --dry-run, missing doctor script is reported but does not fail to keep integration guardrails stable.
USAGE
}

render_cmd() {
  printf '%q ' "$@"
}

require_command() {
  local command_name="$1"
  local install_hint="$2"
  if command -v "$command_name" >/dev/null 2>&1; then
    return
  fi
  die "required command '$command_name' was not found on PATH.
- install hint: $install_hint"
}

runtime_tool_label() {
  local tool_name="$1"
  case "$tool_name" in
    go)
      printf '%s' "Go toolchain command 'go' is missing"
      ;;
    node)
      printf '%s' "Node.js command 'node' is missing"
      ;;
    npm)
      printf '%s' "npm command 'npm' is missing"
      ;;
    rustc)
      printf '%s' "Rust compiler command 'rustc' is missing"
      ;;
    cargo)
      printf '%s' "Cargo command 'cargo' is missing"
      ;;
    curl)
      printf '%s' "curl command 'curl' is missing"
      ;;
    *)
      printf '%s' "$tool_name command is missing"
      ;;
  esac
}

runtime_tool_install_hint() {
  local tool_name="$1"
  case "$tool_name" in
    go)
      printf '%s' "Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y golang-go"
      ;;
    node)
      printf '%s' "Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y nodejs"
      ;;
    npm)
      printf '%s' "Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y npm"
      ;;
    rustc|cargo)
      printf '%s' "Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y rustc cargo"
      ;;
    curl)
      printf '%s' "Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y curl"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

build_linux_desktop_first_run_distro_hints() {
  local sudo_prefix=""
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    sudo_prefix="sudo "
  fi

  cat <<EOF
- Debian/Ubuntu: ${sudo_prefix}apt-get update && ${sudo_prefix}apt-get install -y golang-go nodejs npm rustc cargo pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev
- Fedora/RHEL: ${sudo_prefix}dnf install -y golang nodejs npm rust cargo pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel libsoup3-devel javascriptcoregtk4.1-devel
- Arch: ${sudo_prefix}pacman -Syu --needed go nodejs npm rust pkgconf gtk3 webkit2gtk-4.1 libsoup3
- openSUSE: ${sudo_prefix}zypper install -y go nodejs npm rust pkgconf-pkg-config gtk3-devel webkit2gtk3-devel libsoup-3_0-devel javascriptcoregtk-4_1-devel
EOF
}

assert_runtime_toolchain_prerequisites_for_dev() {
  if [[ "$RUNTIME_TOOLCHAIN_PREREQS_ASSERTED" == "1" ]]; then
    return 0
  fi

  local missing_lines=()
  local tool_name
  for tool_name in node npm rustc cargo; do
    if ! command -v "$tool_name" >/dev/null 2>&1; then
      missing_lines+=("$(runtime_tool_label "$tool_name")")
    fi
  done

  if [[ "${#missing_lines[@]}" -eq 0 ]]; then
    RUNTIME_TOOLCHAIN_PREREQS_ASSERTED="1"
    return 0
  fi

  local guidance_lines=()
  guidance_lines+=("missing Linux runtime prerequisites for desktop dev launch:")
  local line
  for line in "${missing_lines[@]}"; do
    guidance_lines+=("- $line")
  done
  guidance_lines+=("- run ./scripts/linux/desktop_doctor.sh --mode check --print-summary-json 1")
  guidance_lines+=("- run ./scripts/linux/desktop_doctor.sh --mode fix --install-missing")

  while IFS= read -r line; do
    guidance_lines+=("$line")
  done < <(build_linux_desktop_first_run_distro_hints)

  die "$(printf '%s\n' "${guidance_lines[@]}")"
}

assert_go_runtime_prerequisite_for_api() {
  if command -v go >/dev/null 2>&1; then
    return 0
  fi

  local guidance_lines=()
  guidance_lines+=("missing Go runtime prerequisite for local API startup:")
  guidance_lines+=("- $(runtime_tool_label go)")
  guidance_lines+=("- run ./scripts/linux/desktop_doctor.sh --mode check --print-summary-json 1")
  guidance_lines+=("- run ./scripts/linux/desktop_doctor.sh --mode fix --install-missing")
  guidance_lines+=("- $(runtime_tool_install_hint go)")
  while IFS= read -r line; do
    guidance_lines+=("$line")
  done < <(build_linux_desktop_first_run_distro_hints)

  die "$(printf '%s\n' "${guidance_lines[@]}")"
}

absolute_path() {
  local candidate="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$candidate"
    return
  fi

  local parent_dir
  parent_dir="$(cd "$(dirname "$candidate")" && pwd)"
  printf '%s/%s\n' "$parent_dir" "$(basename "$candidate")"
}

pkg_config_module_exists() {
  local module_name="$1"
  pkg-config --exists "$module_name" >/dev/null 2>&1
}

assert_native_desktop_prerequisites_for_dev() {
  if [[ "$NATIVE_DESKTOP_PREREQS_ASSERTED" == "1" ]]; then
    return 0
  fi

  assert_runtime_toolchain_prerequisites_for_dev

  local missing_lines=()
  local pkg_config_missing="0"

  if ! command -v pkg-config >/dev/null 2>&1; then
    pkg_config_missing="1"
    missing_lines+=("pkg-config command is missing")
  fi

  if [[ "$pkg_config_missing" == "1" ]]; then
    missing_lines+=("GTK3 development files could not be validated without pkg-config")
    missing_lines+=("WebKit2GTK development files could not be validated without pkg-config")
    missing_lines+=("libsoup3 development files could not be validated without pkg-config")
    missing_lines+=("javascriptcoregtk development files could not be validated without pkg-config")
  else
    if ! pkg_config_module_exists "gtk+-3.0"; then
      missing_lines+=("GTK3 development files are missing (pkg-config module: gtk+-3.0)")
    fi

    if ! pkg_config_module_exists "webkit2gtk-4.1" && ! pkg_config_module_exists "webkit2gtk-4.0"; then
      missing_lines+=("WebKit2GTK development files are missing (pkg-config module: webkit2gtk-4.1 or webkit2gtk-4.0)")
    fi

    if ! pkg_config_module_exists "libsoup-3.0"; then
      missing_lines+=("libsoup3 development files are missing (pkg-config module: libsoup-3.0)")
    fi

    if ! pkg_config_module_exists "javascriptcoregtk-4.1" && ! pkg_config_module_exists "javascriptcoregtk-4.0"; then
      missing_lines+=("javascriptcoregtk development files are missing (pkg-config module: javascriptcoregtk-4.1 or javascriptcoregtk-4.0)")
    fi
  fi

  if [[ "${#missing_lines[@]}" -eq 0 ]]; then
    NATIVE_DESKTOP_PREREQS_ASSERTED="1"
    return 0
  fi

  local install_prefix=""
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    install_prefix="sudo "
  fi

  local hint_lines=()
  hint_lines+=("missing native Linux desktop prerequisites required for Tauri dev mode:")
  local line
  for line in "${missing_lines[@]}"; do
    hint_lines+=("- $line")
  done
  hint_lines+=("- run ./scripts/linux/desktop_doctor.sh --mode check --print-summary-json 1")
  hint_lines+=("- run ./scripts/linux/desktop_doctor.sh --mode fix --install-missing")
  hint_lines+=("- apt hint: ${install_prefix}apt-get install -y pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev")

  if command -v dnf >/dev/null 2>&1; then
    hint_lines+=("- dnf hint: ${install_prefix}dnf install -y pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel libsoup3-devel javascriptcoregtk4.1-devel")
  elif command -v pacman >/dev/null 2>&1; then
    hint_lines+=("- pacman hint: ${install_prefix}pacman -Sy --needed pkgconf gtk3 webkit2gtk-4.1 libsoup3")
  elif command -v zypper >/dev/null 2>&1; then
    hint_lines+=("- zypper hint: ${install_prefix}zypper install -y pkgconf-pkg-config gtk3-devel webkit2gtk3-devel libsoup-3_0-devel javascriptcoregtk-4_1-devel")
  fi

  die "$(printf '%s\n' "${hint_lines[@]}")"
}

cleanup_background_api() {
  if [[ -z "$API_BG_PID" ]]; then
    return
  fi
  if kill -0 "$API_BG_PID" >/dev/null 2>&1; then
    kill "$API_BG_PID" >/dev/null 2>&1 || true
    wait "$API_BG_PID" >/dev/null 2>&1 || true
    log "stopped local API background process pid=$API_BG_PID"
  fi
}

build_recommended_commands() {
  RECOMMENDED_COMMANDS=(
    "./scripts/linux/desktop_doctor.sh --mode check --print-summary-json 1"
    "./scripts/linux/desktop_doctor.sh --mode fix --install-missing"
    "Debian/Ubuntu: sudo apt-get update && sudo apt-get install -y golang-go nodejs npm rustc cargo pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev"
    "Fedora/RHEL: sudo dnf install -y golang nodejs npm rust cargo pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel libsoup3-devel javascriptcoregtk4.1-devel"
    "Arch: sudo pacman -Syu --needed go nodejs npm rust pkgconf gtk3 webkit2gtk-4.1 libsoup3"
    "openSUSE: sudo zypper install -y go nodejs npm rust pkgconf-pkg-config gtk3-devel webkit2gtk3-devel libsoup-3_0-devel javascriptcoregtk-4_1-devel"
    "sudo apt-get install -y pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev"
    "sudo dnf install -y pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel libsoup3-devel javascriptcoregtk4.1-devel"
    "sudo pacman -Sy --needed pkgconf gtk3 webkit2gtk-4.1 libsoup3"
    "sudo zypper install -y pkgconf-pkg-config gtk3-devel webkit2gtk3-devel libsoup-3_0-devel javascriptcoregtk-4_1-devel"
    "./scripts/linux/desktop_native_bootstrap.sh --mode bootstrap --install-missing --print-summary-json 1"
    "./scripts/linux/desktop_native_bootstrap.sh --mode run-api --api-addr $API_ADDR"
    "./scripts/linux/desktop_native_bootstrap.sh --mode run-desktop --desktop-launch-strategy auto"
    "./scripts/linux/desktop_native_bootstrap.sh --mode run-full --desktop-launch-strategy auto --api-addr $API_ADDR"
    "./scripts/linux/desktop_one_click.sh"
  )
}

emit_recommended_guidance() {
  build_recommended_commands
  log "recommended remediation commands:"
  local cmd
  for cmd in "${RECOMMENDED_COMMANDS[@]}"; do
    echo "  - $cmd"
  done
}

emit_summary_payload() {
  local exit_code="$1"
  if [[ "$PRINT_SUMMARY_JSON" != "1" && -z "$SUMMARY_JSON_PATH" ]]; then
    return 0
  fi

  local status="$SUMMARY_STATUS"
  if [[ "$exit_code" -ne 0 ]]; then
    status="error"
    if [[ -z "$SUMMARY_ERROR" ]]; then
      SUMMARY_ERROR="command failed with exit code $exit_code"
    fi
  fi

  build_recommended_commands

  local generated_at_utc
  generated_at_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  local recommended_commands_json
  recommended_commands_json="$(json_array_from_values "${RECOMMENDED_COMMANDS[@]}")"

  local summary_json_payload
  summary_json_payload=$(
    cat <<EOF
{
  "version": 1,
  "generated_at_utc": "$(json_escape "$generated_at_utc")",
  "status": "$(json_escape "$status")",
  "mode": "$(json_escape "$MODE")",
  "dry_run": $(json_bool "$DRY_RUN"),
  "install_missing": $(json_bool "$INSTALL_MISSING"),
  "desktop_launch_strategy": "$(json_escape "$DESKTOP_LAUNCH_STRATEGY")",
  "resolved_desktop_launch_strategy": "$(json_escape "$RESOLVED_DESKTOP_STRATEGY")",
  "resolved_desktop_executable_path": "$(json_escape "$RESOLVED_DESKTOP_EXECUTABLE_PATH")",
  "resolved_desktop_executable_source": "$(json_escape "$RESOLVED_DESKTOP_EXECUTABLE_SOURCE")",
  "api_addr": "$(json_escape "$API_ADDR")",
  "api_health_timeout_sec": $API_HEALTH_TIMEOUT_SEC,
  "error": "$(json_escape "$SUMMARY_ERROR")",
  "notes": "Linux desktop native bootstrap scaffold helper.",
  "recommended_commands": $recommended_commands_json
}
EOF
  )

  if [[ -n "$SUMMARY_JSON_PATH" ]]; then
    write_summary_json_file "$SUMMARY_JSON_PATH" "$summary_json_payload"
  fi
  if [[ "$PRINT_SUMMARY_JSON" == "1" ]]; then
    printf '%s\n' "$summary_json_payload"
  fi
}

on_exit() {
  local exit_code=$?
  emit_recommended_guidance
  emit_summary_payload "$exit_code"
  return "$exit_code"
}

trap on_exit EXIT

resolve_local_api_health_endpoint() {
  local addr="$1"
  local host=""
  local port=""

  if [[ "$addr" =~ ^\[([^][]+)\]:([0-9]{1,5})$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  elif [[ "$addr" =~ ^([^:]+):([0-9]{1,5})$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  else
    die "--api-addr must be host:port (or [host]:port for IPv6)"
  fi

  if ((10#$port < 1 || 10#$port > 65535)); then
    die "--api-addr port must be in 1..65535"
  fi

  local normalized_host
  normalized_host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
  case "$normalized_host" in
    127.0.0.1|localhost|::1) ;;
    *)
      die "--api-addr must target loopback only (allowed hosts: 127.0.0.1, localhost, ::1)"
      ;;
  esac

  API_HEALTH_ENDPOINT="http://$addr/v1/health"
}

find_packaged_desktop_executable() {
  local override_path="$1"
  if [[ -n "$override_path" ]]; then
    if [[ ! -f "$override_path" ]]; then
      die "desktop executable override was not found: $override_path
- pass --desktop-executable-override-path with a valid packaged desktop executable
- for local builds, check apps/desktop/src-tauri/target/release"
    fi
    RESOLVED_DESKTOP_EXECUTABLE_SOURCE="override-path"
    RESOLVED_DESKTOP_EXECUTABLE_PATH="$(absolute_path "$override_path")"
    return 0
  fi

  local env_name=""
  for env_name in GPM_DESKTOP_PACKAGED_EXE GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE TDPN_DESKTOP_PACKAGED_EXE; do
    local env_value="${!env_name:-}"
    if [[ -z "$env_value" ]]; then
      continue
    fi
    if [[ -f "$env_value" ]]; then
      RESOLVED_DESKTOP_EXECUTABLE_SOURCE="env-override:$env_name"
      RESOLVED_DESKTOP_EXECUTABLE_PATH="$(absolute_path "$env_value")"
      return 0
    fi
    log "warning: env override $env_name points to a missing file: $env_value"
  done

  local release_roots=(
    "$DESKTOP_DIR/src-tauri/target/release"
    "$DESKTOP_DIR/target/release"
  )
  local binary_names=(
    "global-private-mesh-desktop"
    "Global Private Mesh Desktop"
    "gpm-desktop"
    "tdpn-desktop"
    "GPM Desktop"
    "TDPN Desktop"
  )

  local release_root=""
  local binary_name=""
  local candidate=""
  for release_root in "${release_roots[@]}"; do
    for binary_name in "${binary_names[@]}"; do
      candidate="$release_root/$binary_name"
      if [[ -f "$candidate" ]]; then
        RESOLVED_DESKTOP_EXECUTABLE_SOURCE="packaged-default"
        RESOLVED_DESKTOP_EXECUTABLE_PATH="$(absolute_path "$candidate")"
        return 0
      fi
    done
  done

  local appimage_names=(
    "Global Private Mesh Desktop.AppImage"
    "global-private-mesh-desktop.AppImage"
    "global-private-mesh-desktop.appimage"
    "GPM Desktop.AppImage"
    "gpm-desktop.AppImage"
    "gpm-desktop.appimage"
    "TDPN Desktop.AppImage"
    "tdpn-desktop.AppImage"
    "tdpn-desktop.appimage"
  )
  local appimage=""
  local appimage_name=""
  for release_root in "${release_roots[@]}"; do
    for appimage_name in "${appimage_names[@]}"; do
      appimage="$release_root/bundle/appimage/$appimage_name"
      if [[ -f "$appimage" ]]; then
        RESOLVED_DESKTOP_EXECUTABLE_SOURCE="packaged-default"
        RESOLVED_DESKTOP_EXECUTABLE_PATH="$(absolute_path "$appimage")"
        return 0
      fi
    done
  done

  shopt -s nullglob
  local appimage_candidates=(
    "$DESKTOP_DIR/src-tauri/target/release/bundle/appimage/"*.AppImage
    "$DESKTOP_DIR/src-tauri/target/release/bundle/appimage/"*.appimage
    "$DESKTOP_DIR/target/release/bundle/appimage/"*.AppImage
    "$DESKTOP_DIR/target/release/bundle/appimage/"*.appimage
  )
  shopt -u nullglob

  for appimage in "${appimage_candidates[@]}"; do
    if [[ -f "$appimage" ]]; then
      absolute_path "$appimage"
      return 0
    fi
  done

  return 1
}

resolve_desktop_launch_plan() {
  RESOLVED_DESKTOP_STRATEGY=""
  RESOLVED_DESKTOP_EXECUTABLE_PATH=""
  RESOLVED_DESKTOP_EXECUTABLE_SOURCE=""

  case "$DESKTOP_LAUNCH_STRATEGY" in
    dev)
      RESOLVED_DESKTOP_STRATEGY="dev"
      RESOLVED_DESKTOP_EXECUTABLE_SOURCE="dev"
      return
      ;;
    packaged|auto) ;;
    *)
      die "invalid --desktop-launch-strategy '$DESKTOP_LAUNCH_STRATEGY' (allowed: dev, packaged, auto)"
      ;;
  esac

  if find_packaged_desktop_executable "$DESKTOP_EXECUTABLE_OVERRIDE_PATH"; then
    RESOLVED_DESKTOP_STRATEGY="packaged"
    return
  fi

  if [[ "$DESKTOP_LAUNCH_STRATEGY" == "packaged" ]]; then
    die "packaged desktop launch was requested, but no packaged executable was found.
- build desktop artifacts first, then rerun with --desktop-launch-strategy packaged
- or pass --desktop-executable-override-path with a valid executable"
  fi

  RESOLVED_DESKTOP_STRATEGY="dev"
  RESOLVED_DESKTOP_EXECUTABLE_SOURCE="auto-fallback-dev"
}

run_linux_desktop_doctor() {
  local doctor_mode="check"
  local doctor_args=("--mode" "check")

  if [[ "$INSTALL_MISSING" == "1" ]]; then
    doctor_mode="fix"
    doctor_args=("--mode" "fix" "--install-missing")
  fi
  if [[ "$DRY_RUN" == "1" ]]; then
    doctor_args+=("--dry-run")
  fi

  if [[ ! -f "$DOCTOR_SCRIPT" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
      log "dry-run doctor call skipped because script is not present: $DOCTOR_SCRIPT"
      log "dry-run: would run $(render_cmd bash "$DOCTOR_SCRIPT" "${doctor_args[@]}")"
      return 0
    fi
    die "linux desktop doctor script was not found: $DOCTOR_SCRIPT
- add scripts/linux/desktop_doctor.sh before using check/bootstrap without --dry-run"
  fi

  log "running linux desktop_doctor mode=$doctor_mode"
  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run: $(render_cmd bash "$DOCTOR_SCRIPT" "${doctor_args[@]}")"
    return 0
  fi
  bash "$DOCTOR_SCRIPT" "${doctor_args[@]}"
}

run_local_api_foreground() {
  resolve_local_api_health_endpoint "$API_ADDR"
  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run: would run local API from repo root: go run ./cmd/node --local-api"
    return 0
  fi

  assert_go_runtime_prerequisite_for_api
  pushd "$ROOT_DIR" >/dev/null
  go run ./cmd/node --local-api
  popd >/dev/null
}

run_desktop_dev() {
  if [[ ! -f "$DESKTOP_DIR/package.json" ]]; then
    die "desktop package.json was not found: $DESKTOP_DIR/package.json"
  fi

  local should_install="0"
  if [[ "$FORCE_NPM_INSTALL" == "1" || ! -d "$DESKTOP_DIR/node_modules" ]]; then
    should_install="1"
  fi

  if [[ "$DRY_RUN" == "1" ]]; then
    if [[ "$should_install" == "1" ]]; then
      log "dry-run: would run in $DESKTOP_DIR -> npm install"
    else
      log "dry-run: npm install skipped because node_modules exists"
    fi
    log "dry-run: native Linux desktop prerequisite enforcement is skipped (run desktop_doctor check to validate)"
    log "dry-run: would run in $DESKTOP_DIR -> npm run tauri -- dev"
    return 0
  fi

  assert_native_desktop_prerequisites_for_dev
  require_command npm "install Node.js/npm and ensure npm is on PATH"
  pushd "$DESKTOP_DIR" >/dev/null
  if [[ "$should_install" == "1" ]]; then
    log "running npm install"
    npm install
  else
    log "npm install skipped (node_modules exists)"
  fi

  log "running npm run tauri -- dev"
  npm run tauri -- dev
  popd >/dev/null
}

run_desktop_packaged() {
  local executable_path="$RESOLVED_DESKTOP_EXECUTABLE_PATH"
  if [[ -z "$executable_path" ]]; then
    die "packaged launch selected but no executable path was resolved"
  fi

  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run: would launch packaged desktop executable: $executable_path"
    return 0
  fi

  if [[ ! -f "$executable_path" ]]; then
    die "packaged desktop executable was not found: $executable_path"
  fi
  if [[ ! -x "$executable_path" ]]; then
    log "packaged executable is not marked executable; applying chmod +x"
    chmod +x "$executable_path"
  fi

  log "launching packaged desktop executable: $executable_path"
  "$executable_path"
}

wait_for_local_api_health() {
  local timeout_sec="${1:-25}"
  local start_sec
  start_sec="$(date +%s)"

  while true; do
    local payload=""
    payload="$(curl -fsS --max-time 3 "$API_HEALTH_ENDPOINT" 2>/dev/null || true)"
    if [[ -n "$payload" ]] && printf '%s' "$payload" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
      log "local API health check passed: $API_HEALTH_ENDPOINT"
      return 0
    fi

    local now_sec
    now_sec="$(date +%s)"
    if (( now_sec - start_sec >= timeout_sec )); then
      return 1
    fi
    sleep 1
  done
}

run_desktop_by_plan() {
  case "$RESOLVED_DESKTOP_STRATEGY" in
    packaged)
      run_desktop_packaged
      ;;
    dev)
      run_desktop_dev
      ;;
    *)
      die "unsupported resolved desktop launch strategy: $RESOLVED_DESKTOP_STRATEGY"
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      if [[ $# -lt 2 ]]; then
        die "--mode requires a value"
      fi
      MODE="$2"
      shift 2
      ;;
    --desktop-launch-strategy)
      if [[ $# -lt 2 ]]; then
        die "--desktop-launch-strategy requires a value"
      fi
      DESKTOP_LAUNCH_STRATEGY="$2"
      shift 2
      ;;
    --desktop-executable-override-path)
      if [[ $# -lt 2 ]]; then
        die "--desktop-executable-override-path requires a value"
      fi
      DESKTOP_EXECUTABLE_OVERRIDE_PATH="$2"
      shift 2
      ;;
    --install-missing)
      INSTALL_MISSING="1"
      shift
      ;;
    --dry-run)
      DRY_RUN="1"
      shift
      ;;
    --api-addr)
      if [[ $# -lt 2 ]]; then
        die "--api-addr requires a value"
      fi
      API_ADDR="$2"
      shift 2
      ;;
    --api-health-timeout-sec)
      if [[ $# -lt 2 ]]; then
        die "--api-health-timeout-sec requires a value"
      fi
      API_HEALTH_TIMEOUT_SEC="$2"
      shift 2
      ;;
    --force-npm-install)
      FORCE_NPM_INSTALL="1"
      shift
      ;;
    --summary-json)
      if [[ $# -lt 2 ]]; then
        die "--summary-json requires a value"
      fi
      SUMMARY_JSON_PATH="$2"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -lt 2 ]]; then
        die "--print-summary-json requires 0 or 1"
      fi
      PRINT_SUMMARY_JSON="$2"
      shift 2
      ;;
    --help|-h)
      show_usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

case "$MODE" in
  check|bootstrap|run-api|run-desktop|run-full) ;;
  *)
    die "invalid --mode '$MODE' (allowed: check, bootstrap, run-api, run-desktop, run-full)"
    ;;
esac

case "$DESKTOP_LAUNCH_STRATEGY" in
  dev|packaged|auto) ;;
  *)
    die "invalid --desktop-launch-strategy '$DESKTOP_LAUNCH_STRATEGY' (allowed: dev, packaged, auto)"
    ;;
esac

case "$PRINT_SUMMARY_JSON" in
  0|1) ;;
  *)
    die "invalid --print-summary-json value: $PRINT_SUMMARY_JSON (expected 0|1)"
    ;;
esac

if ! [[ "$API_HEALTH_TIMEOUT_SEC" =~ ^[0-9]+$ ]]; then
  die "invalid --api-health-timeout-sec value: $API_HEALTH_TIMEOUT_SEC (expected positive integer seconds)"
fi
if ((10#$API_HEALTH_TIMEOUT_SEC < 1 || 10#$API_HEALTH_TIMEOUT_SEC > 600)); then
  die "invalid --api-health-timeout-sec value: $API_HEALTH_TIMEOUT_SEC (allowed range: 1..600)"
fi

log "mode=$MODE"
log "desktop_launch_strategy=$DESKTOP_LAUNCH_STRATEGY"
if [[ -n "$DESKTOP_EXECUTABLE_OVERRIDE_PATH" ]]; then
  log "desktop_executable_override_path=$DESKTOP_EXECUTABLE_OVERRIDE_PATH"
fi
log "api_addr=$API_ADDR"
log "api_health_timeout_sec=$API_HEALTH_TIMEOUT_SEC"
log "repo_root=$ROOT_DIR"

if [[ "$MODE" == "check" || "$MODE" == "bootstrap" ]]; then
  run_linux_desktop_doctor
  log "$MODE completed"
  exit 0
fi

if [[ "$MODE" == "run-api" ]]; then
  run_local_api_foreground
  exit 0
fi

resolve_desktop_launch_plan
log "desktop launch resolved: strategy=$RESOLVED_DESKTOP_STRATEGY source=$RESOLVED_DESKTOP_EXECUTABLE_SOURCE"
if [[ -n "$RESOLVED_DESKTOP_EXECUTABLE_PATH" ]]; then
  log "desktop executable path: $RESOLVED_DESKTOP_EXECUTABLE_PATH"
fi

if [[ "$MODE" == "run-desktop" ]]; then
  run_desktop_by_plan
  exit 0
fi

  if [[ "$MODE" == "run-full" ]]; then
    resolve_local_api_health_endpoint "$API_ADDR"

    if [[ "$RESOLVED_DESKTOP_STRATEGY" == "dev" && "$DRY_RUN" != "1" ]]; then
      log "validating native Linux desktop prerequisites for dev launch"
      assert_native_desktop_prerequisites_for_dev
    fi

    if [[ "$DRY_RUN" != "1" ]]; then
      assert_go_runtime_prerequisite_for_api
    fi

    if [[ "$DRY_RUN" == "1" ]]; then
      log "dry-run: would start local API in background from repo root: go run ./cmd/node --local-api"
      log "dry-run: would wait for health endpoint: $API_HEALTH_ENDPOINT (timeout=${API_HEALTH_TIMEOUT_SEC}s)"
      run_desktop_by_plan
      exit 0
    fi

    require_command curl "$(runtime_tool_install_hint curl)"

  trap cleanup_background_api EXIT
  (
    cd "$ROOT_DIR"
    go run ./cmd/node --local-api
  ) &
  API_BG_PID="$!"
  log "started local API background process pid=$API_BG_PID"

  if ! wait_for_local_api_health "$API_HEALTH_TIMEOUT_SEC"; then
    die "local API health check timed out: $API_HEALTH_ENDPOINT
- verify go run ./cmd/node --local-api starts cleanly
- verify port and loopback bind in --api-addr
- rerun with a longer health timeout, e.g. --api-health-timeout-sec 60 (current=${API_HEALTH_TIMEOUT_SEC})"
  fi

  run_desktop_by_plan
  exit 0
fi

die "unsupported mode: $MODE"
