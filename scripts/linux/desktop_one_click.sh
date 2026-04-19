#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BOOTSTRAP_SCRIPT="$ROOT_DIR/scripts/linux/desktop_native_bootstrap.sh"

DESKTOP_LAUNCH_STRATEGY="auto"
DESKTOP_EXECUTABLE_OVERRIDE_PATH=""
INSTALL_MISSING="0"
DRY_RUN="0"
API_ADDR="127.0.0.1:8095"
FORCE_NPM_INSTALL="0"

log() {
  echo "[desktop-one-click] $*"
}

die() {
  echo "[desktop-one-click] error: $*" >&2
  exit 1
}

show_usage() {
  cat <<'USAGE'
Linux desktop one-click scaffold

Usage:
  ./scripts/linux/desktop_one_click.sh [options]

Options:
  --desktop-launch-strategy STRATEGY          One of: dev, packaged, auto (default: auto)
  --desktop-executable-override-path PATH     Explicit packaged executable path for packaged launch
  --install-missing                           Ask desktop_doctor/bootstrap to attempt remediation
  --dry-run                                   Print actions without executing
  --api-addr HOST:PORT                        Local API bind/health address (default: 127.0.0.1:8095)
  --force-npm-install                         Force npm install before desktop dev launch
  --help, -h                                  Show this help

Behavior:
  1) Runs desktop_native_bootstrap.sh in bootstrap mode.
  2) Runs desktop_native_bootstrap.sh in run-full mode.
USAGE
}

if [[ ! -f "$BOOTSTRAP_SCRIPT" ]]; then
  die "missing bootstrap script: $BOOTSTRAP_SCRIPT"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
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

case "$DESKTOP_LAUNCH_STRATEGY" in
  dev|packaged|auto) ;;
  *)
    die "invalid --desktop-launch-strategy '$DESKTOP_LAUNCH_STRATEGY' (allowed: dev, packaged, auto)"
    ;;
esac

bootstrap_args=(
  --mode bootstrap
  --desktop-launch-strategy "$DESKTOP_LAUNCH_STRATEGY"
  --api-addr "$API_ADDR"
)

run_full_args=(
  --mode run-full
  --desktop-launch-strategy "$DESKTOP_LAUNCH_STRATEGY"
  --api-addr "$API_ADDR"
)

if [[ "$INSTALL_MISSING" == "1" ]]; then
  bootstrap_args+=(--install-missing)
fi
if [[ "$DRY_RUN" == "1" ]]; then
  bootstrap_args+=(--dry-run)
  run_full_args+=(--dry-run)
fi
if [[ "$FORCE_NPM_INSTALL" == "1" ]]; then
  run_full_args+=(--force-npm-install)
fi
if [[ -n "$DESKTOP_EXECUTABLE_OVERRIDE_PATH" ]]; then
  bootstrap_args+=(--desktop-executable-override-path "$DESKTOP_EXECUTABLE_OVERRIDE_PATH")
  run_full_args+=(--desktop-executable-override-path "$DESKTOP_EXECUTABLE_OVERRIDE_PATH")
fi

log "running bootstrap phase"
bash "$BOOTSTRAP_SCRIPT" "${bootstrap_args[@]}"

log "running full desktop launch phase"
bash "$BOOTSTRAP_SCRIPT" "${run_full_args[@]}"

