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
FORCE_NPM_INSTALL="0"

RESOLVED_DESKTOP_STRATEGY=""
RESOLVED_DESKTOP_EXECUTABLE_PATH=""
RESOLVED_DESKTOP_EXECUTABLE_SOURCE=""
API_BG_PID=""
API_HEALTH_ENDPOINT=""

log() {
  echo "[desktop-native-bootstrap] $*"
}

die() {
  echo "[desktop-native-bootstrap] error: $*" >&2
  exit 1
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
  --force-npm-install                         Force npm install before desktop dev launch
  --help, -h                                  Show this help

Modes:
  check        Run linux desktop_doctor in check mode (or fix when --install-missing is set)
  bootstrap    Run linux desktop_doctor in check/fix mode according to --install-missing
  run-api      Run local API from repo root: go run ./cmd/node --local-api
  run-desktop  Launch desktop only (dev or packaged strategy)
  run-full     Start local API in background, wait for health, then launch desktop

Notes:
  - This is a scaffold and expects scripts/linux/desktop_doctor.sh for non-dry-run check/bootstrap.
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
    absolute_path "$override_path"
    return 0
  fi

  local candidate=""
  local static_candidates=(
    "$DESKTOP_DIR/src-tauri/target/release/tdpn-desktop"
    "$DESKTOP_DIR/target/release/tdpn-desktop"
  )
  for candidate in "${static_candidates[@]}"; do
    if [[ -f "$candidate" ]]; then
      absolute_path "$candidate"
      return 0
    fi
  done

  local appimage=""
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

  local packaged_path=""
  if packaged_path="$(find_packaged_desktop_executable "$DESKTOP_EXECUTABLE_OVERRIDE_PATH")"; then
    RESOLVED_DESKTOP_STRATEGY="packaged"
    RESOLVED_DESKTOP_EXECUTABLE_PATH="$packaged_path"
    if [[ -n "$DESKTOP_EXECUTABLE_OVERRIDE_PATH" ]]; then
      RESOLVED_DESKTOP_EXECUTABLE_SOURCE="override"
    else
      RESOLVED_DESKTOP_EXECUTABLE_SOURCE="packaged-default"
    fi
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

  require_command go "install Go and ensure 'go' is on PATH"
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
    log "dry-run: would run in $DESKTOP_DIR -> npm run tauri -- dev"
    return 0
  fi

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
    --force-npm-install)
      FORCE_NPM_INSTALL="1"
      shift
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

log "mode=$MODE"
log "desktop_launch_strategy=$DESKTOP_LAUNCH_STRATEGY"
if [[ -n "$DESKTOP_EXECUTABLE_OVERRIDE_PATH" ]]; then
  log "desktop_executable_override_path=$DESKTOP_EXECUTABLE_OVERRIDE_PATH"
fi
log "api_addr=$API_ADDR"
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
  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run: would start local API in background from repo root: go run ./cmd/node --local-api"
    log "dry-run: would wait for health endpoint: $API_HEALTH_ENDPOINT"
    run_desktop_by_plan
    exit 0
  fi

  require_command go "install Go and ensure 'go' is on PATH"
  require_command curl "install curl and ensure it is on PATH"

  trap cleanup_background_api EXIT
  (
    cd "$ROOT_DIR"
    go run ./cmd/node --local-api
  ) &
  API_BG_PID="$!"
  log "started local API background process pid=$API_BG_PID"

  if ! wait_for_local_api_health 25; then
    die "local API health check timed out: $API_HEALTH_ENDPOINT
- verify go run ./cmd/node --local-api starts cleanly
- verify port and loopback bind in --api-addr"
  fi

  run_desktop_by_plan
  exit 0
fi

die "unsupported mode: $MODE"
