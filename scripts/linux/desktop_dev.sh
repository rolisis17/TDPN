#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BOOTSTRAP_SCRIPT="${DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT:-$ROOT_DIR/scripts/linux/desktop_native_bootstrap.sh}"

INSTALL_MISSING_SPECIFIED=0
NO_INSTALL_MISSING_SPECIFIED=0
DRY_RUN=0
FORCE_NPM_INSTALL=0
FORWARDED_ARGS=()

usage() {
  cat <<'USAGE'
Linux desktop dev launcher scaffold

Usage:
  ./scripts/linux/desktop_dev.sh [options] [desktop_native_bootstrap args...]

Options:
  --install-missing        Explicitly enable dependency remediation
  --no-install-missing     Explicitly disable dependency remediation
  --dry-run                Run bootstrap in dry-run mode
  --force-npm-install      Force npm install before desktop dev launch
  --help, -h               Show this help

Notes:
  - Default remediation intent is enabled unless env override disables it.
  - Env override order: GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING, then
    TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING.
  - Launches desktop_native_bootstrap with:
      --mode run-desktop --desktop-launch-strategy dev
USAGE
}

parse_nullable_bool() {
  local raw="${1:-}"
  if [[ -z "$raw" ]]; then
    printf '%s\n' ""
    return 0
  fi

  raw="${raw#\$}"
  raw="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
  case "$raw" in
    1|true|yes|on)
      printf '%s\n' "1"
      ;;
    0|false|no|off)
      printf '%s\n' "0"
      ;;
    *)
      printf '%s\n' ""
      ;;
  esac
}

get_auto_install_missing_env_override() {
  local raw=""
  local parsed=""

  raw="${GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING:-}"
  parsed="$(parse_nullable_bool "$raw")"
  if [[ -n "$parsed" ]]; then
    printf '%s\n' "$parsed"
    return 0
  fi

  raw="${TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING:-}"
  parsed="$(parse_nullable_bool "$raw")"
  if [[ -n "$parsed" ]]; then
    printf '%s\n' "$parsed"
    return 0
  fi

  printf '%s\n' ""
}

while (($#)); do
  case "$1" in
    --install-missing)
      INSTALL_MISSING_SPECIFIED=1
      ;;
    --no-install-missing)
      NO_INSTALL_MISSING_SPECIFIED=1
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    --force-npm-install)
      FORCE_NPM_INSTALL=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      FORWARDED_ARGS+=("$1")
      ;;
  esac
  shift
done

if [[ "$INSTALL_MISSING_SPECIFIED" == "1" && "$NO_INSTALL_MISSING_SPECIFIED" == "1" ]]; then
  echo "conflicting install intent: specify only one of --install-missing or --no-install-missing" >&2
  exit 2
fi

if [[ ! -x "$BOOTSTRAP_SCRIPT" ]]; then
  echo "missing bootstrap script: $BOOTSTRAP_SCRIPT" >&2
  exit 2
fi

INSTALL_MISSING_INTENT=1
AUTO_INSTALL_ENV="$(get_auto_install_missing_env_override)"
if [[ -n "$AUTO_INSTALL_ENV" ]]; then
  INSTALL_MISSING_INTENT="$AUTO_INSTALL_ENV"
fi
if [[ "$INSTALL_MISSING_SPECIFIED" == "1" ]]; then
  INSTALL_MISSING_INTENT=1
elif [[ "$NO_INSTALL_MISSING_SPECIFIED" == "1" ]]; then
  INSTALL_MISSING_INTENT=0
fi

INVOKE_ARGS=(
  --mode run-desktop
  --desktop-launch-strategy dev
)
if [[ "$INSTALL_MISSING_INTENT" == "1" ]]; then
  INVOKE_ARGS+=(--install-missing)
fi
if [[ "$DRY_RUN" == "1" ]]; then
  INVOKE_ARGS+=(--dry-run)
fi
if [[ "$FORCE_NPM_INSTALL" == "1" ]]; then
  INVOKE_ARGS+=(--force-npm-install)
fi
INVOKE_ARGS+=("${FORWARDED_ARGS[@]}")

"$BOOTSTRAP_SCRIPT" "${INVOKE_ARGS[@]}"
