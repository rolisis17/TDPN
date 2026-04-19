#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DESKTOP_DIR="$ROOT_DIR/apps/desktop"
DOCTOR_SCRIPT="$ROOT_DIR/scripts/linux/desktop_doctor.sh"
DOCTOR_FIX_COMMAND="./scripts/linux/desktop_doctor.sh --mode fix --install-missing"
BUILD_REQUIRED_TOOLS=(node npm rustc cargo git bash)
MISSING_BUILD_TOOLS=()

show_usage() {
  cat <<'USAGE'
GPM desktop release bundle scaffold (non-production signing flow)

Usage:
  ./scripts/linux/desktop_release_bundle.sh [--help] [--channel stable|beta|canary] [--update-feed-url URL] [--signing-identity ID] [--signing-cert-path PATH] [--signing-cert-password VALUE] [--install-missing] [--skip-build] [-- <tauri args>]

Examples:
  ./scripts/linux/desktop_release_bundle.sh
  ./scripts/linux/desktop_release_bundle.sh --channel beta --update-feed-url https://updates.example.invalid/gpm/beta.json
  ./scripts/linux/desktop_release_bundle.sh --install-missing
  ./scripts/linux/desktop_release_bundle.sh --channel canary -- --bundles appimage

Notes:
  - This is scaffold-only and does not implement production signing/secret handling.
  - Tauri build runs from apps/desktop via: npm run tauri -- build ...
  - If build prerequisites are missing, --install-missing runs linux desktop_doctor in fix mode.
  - Sets GPM_DESKTOP_* vars (and TDPN_DESKTOP_* compatibility vars) for this process.
  - Validates update feed URL and signing placeholder input consistency before invoking build.
USAGE
}

tool_install_hint() {
  local tool_name="$1"
  case "$tool_name" in
    node)
      printf '%s' "install Node.js LTS"
      ;;
    npm)
      printf '%s' "install Node.js LTS so npm is on PATH"
      ;;
    rustc|cargo)
      printf '%s' "install Rust with rustup"
      ;;
    git)
      printf '%s' "install Git"
      ;;
    bash)
      printf '%s' "install bash (GNU bash package)"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

collect_missing_build_tools() {
  MISSING_BUILD_TOOLS=()
  local tool_name
  for tool_name in "${BUILD_REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool_name" >/dev/null 2>&1; then
      MISSING_BUILD_TOOLS+=("$tool_name")
    fi
  done
}

print_missing_build_tool_hints() {
  local tool_name
  local install_hint
  for tool_name in "${MISSING_BUILD_TOOLS[@]}"; do
    install_hint="$(tool_install_hint "$tool_name")"
    echo "desktop release bundle prerequisite missing: $tool_name" >&2
    if [[ -n "$install_hint" ]]; then
      echo "  install hint: $install_hint" >&2
    fi
  done
  echo "  remediation hint: $DOCTOR_FIX_COMMAND" >&2
}

run_doctor_missing_tools_remediation() {
  if [[ ! -f "$DOCTOR_SCRIPT" ]]; then
    echo "desktop release bundle remediation helper not found: $DOCTOR_SCRIPT" >&2
    return 1
  fi
  echo "[desktop-release-bundle] running remediation: $DOCTOR_FIX_COMMAND"
  bash "$DOCTOR_SCRIPT" --mode fix --install-missing
}

to_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

extract_url_host() {
  local url="$1"
  local authority="${url#*://}"
  authority="${authority%%/*}"
  authority="${authority##*@}"

  if [[ "$authority" == \[* ]]; then
    local bracketed="${authority#\[}"
    printf '%s' "${bracketed%%]*}"
    return
  fi

  printf '%s' "${authority%%:*}"
}

validate_update_feed_url() {
  local candidate="$1"
  if [[ -z "$candidate" ]]; then
    return 0
  fi

  if [[ ! "$candidate" =~ ^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/]+) ]]; then
    echo "invalid --update-feed-url '$candidate' (expected absolute URL like https://updates.example.invalid/gpm/beta.json)" >&2
    exit 2
  fi

  local scheme_raw="${BASH_REMATCH[1]}"
  local scheme
  scheme="$(to_lower "$scheme_raw")"
  if [[ "$scheme" != "http" && "$scheme" != "https" ]]; then
    echo "invalid --update-feed-url '$candidate' (allowed schemes: http, https)" >&2
    exit 2
  fi

  local host_raw
  host_raw="$(extract_url_host "$candidate")"
  if [[ -z "$host_raw" ]]; then
    echo "invalid --update-feed-url '$candidate' (missing host)" >&2
    exit 2
  fi

  local host
  host="$(to_lower "$host_raw")"
  local is_local_host="0"
  if [[ "$host" == "localhost" || "$host" == "127.0.0.1" || "$host" == "::1" ]]; then
    is_local_host="1"
  fi

  if [[ "$is_local_host" == "0" && "$scheme" != "https" ]]; then
    echo "invalid --update-feed-url '$candidate' (non-local update feeds must use https)" >&2
    exit 2
  fi
}

validate_signing_placeholders() {
  local identity="$1"
  local cert_path="$2"
  local cert_password="$3"

  if [[ -n "$cert_password" && -z "$cert_path" ]]; then
    echo "-SigningCertPassword requires -SigningCertPath." >&2
    exit 2
  fi
  if [[ -n "$cert_path" && ! -f "$cert_path" ]]; then
    echo "signing certificate file was not found: $cert_path" >&2
    exit 2
  fi
  if [[ -n "$identity" && -n "$cert_path" ]]; then
    echo "warning: both --signing-identity and --signing-cert-path were provided; this scaffold only forwards placeholders." >&2
  fi
}

ensure_tauri_icon_scaffold() {
  local icon_path="$DESKTOP_DIR/src-tauri/icons/icon.ico"
  if [[ -f "$icon_path" ]]; then
    return 0
  fi
  if [[ -e "$icon_path" ]]; then
    echo "desktop release bundle icon scaffold failed: path exists but is not a regular file: $icon_path" >&2
    exit 1
  fi

  mkdir -p "$(dirname "$icon_path")"

  # Minimal valid 1x1 32-bit ICO (ICONDIR + ICONDIRENTRY + BMP payload).
  printf '\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x20\x00\x30\x00\x00\x00\x16\x00\x00\x00\x28\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x01\x00\x20\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\x00\x00\x00\x00' >"$icon_path"

  echo "[desktop-release-bundle] icon_scaffold=created path=$icon_path"
}

declare -A SAVED_ENV_PRESENT=()
declare -A SAVED_ENV_VALUE=()
SCOPED_ENV_NAMES=(
  "GPM_DESKTOP_UPDATE_CHANNEL"
  "TDPN_DESKTOP_UPDATE_CHANNEL"
  "GPM_DESKTOP_UPDATE_FEED_URL"
  "TDPN_DESKTOP_UPDATE_FEED_URL"
  "GPM_DESKTOP_SIGNING_IDENTITY"
  "TDPN_DESKTOP_SIGNING_IDENTITY"
  "GPM_DESKTOP_SIGNING_CERT_PATH"
  "TDPN_DESKTOP_SIGNING_CERT_PATH"
  "GPM_DESKTOP_SIGNING_CERT_PASSWORD"
  "TDPN_DESKTOP_SIGNING_CERT_PASSWORD"
)

save_scoped_env() {
  local name
  for name in "${SCOPED_ENV_NAMES[@]}"; do
    if [[ "${!name+x}" == "x" ]]; then
      SAVED_ENV_PRESENT["$name"]="1"
      SAVED_ENV_VALUE["$name"]="${!name}"
    else
      SAVED_ENV_PRESENT["$name"]="0"
      SAVED_ENV_VALUE["$name"]=""
    fi
  done
}

restore_scoped_env() {
  local name
  for name in "${SCOPED_ENV_NAMES[@]}"; do
    if [[ "${SAVED_ENV_PRESENT[$name]:-0}" == "1" ]]; then
      export "$name=${SAVED_ENV_VALUE[$name]}"
    else
      unset "$name"
    fi
  done
}

channel="stable"
update_feed_url=""
signing_identity=""
signing_cert_path=""
signing_cert_password=""
install_missing="0"
skip_build="0"
tauri_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_usage
      exit 0
      ;;
    --channel)
      if [[ $# -lt 2 ]]; then
        echo "--channel requires a value" >&2
        exit 2
      fi
      channel="$2"
      shift 2
      ;;
    --update-feed-url)
      if [[ $# -lt 2 ]]; then
        echo "--update-feed-url requires a value" >&2
        exit 2
      fi
      update_feed_url="$2"
      shift 2
      ;;
    --signing-identity)
      if [[ $# -lt 2 ]]; then
        echo "--signing-identity requires a value" >&2
        exit 2
      fi
      signing_identity="$2"
      shift 2
      ;;
    --signing-cert-path)
      if [[ $# -lt 2 ]]; then
        echo "--signing-cert-path requires a value" >&2
        exit 2
      fi
      signing_cert_path="$2"
      shift 2
      ;;
    --signing-cert-password)
      if [[ $# -lt 2 ]]; then
        echo "--signing-cert-password requires a value" >&2
        exit 2
      fi
      signing_cert_password="$2"
      shift 2
      ;;
    --install-missing)
      install_missing="1"
      shift
      ;;
    --skip-build)
      skip_build="1"
      shift
      ;;
    --)
      shift
      tauri_args=("$@")
      break
      ;;
    *)
      echo "unknown argument: $1" >&2
      show_usage
      exit 2
      ;;
  esac
done

case "$channel" in
  stable|beta|canary) ;;
  *)
    echo "invalid --channel '$channel' (allowed: stable, beta, canary)" >&2
    exit 2
    ;;
esac

if [[ ! -f "$DESKTOP_DIR/package.json" ]]; then
  echo "apps/desktop/package.json not found at expected path: $DESKTOP_DIR" >&2
  exit 1
fi

validate_update_feed_url "$update_feed_url"
validate_signing_placeholders "$signing_identity" "$signing_cert_path" "$signing_cert_password"

save_scoped_env
trap restore_scoped_env EXIT

export GPM_DESKTOP_UPDATE_CHANNEL="$channel"
export TDPN_DESKTOP_UPDATE_CHANNEL="$channel"
if [[ -n "$update_feed_url" ]]; then
  export GPM_DESKTOP_UPDATE_FEED_URL="$update_feed_url"
  export TDPN_DESKTOP_UPDATE_FEED_URL="$update_feed_url"
else
  unset GPM_DESKTOP_UPDATE_FEED_URL
  unset TDPN_DESKTOP_UPDATE_FEED_URL
fi

if [[ -n "$signing_identity" ]]; then
  export GPM_DESKTOP_SIGNING_IDENTITY="$signing_identity"
  export TDPN_DESKTOP_SIGNING_IDENTITY="$signing_identity"
else
  unset GPM_DESKTOP_SIGNING_IDENTITY
  unset TDPN_DESKTOP_SIGNING_IDENTITY
fi

if [[ -n "$signing_cert_path" ]]; then
  export GPM_DESKTOP_SIGNING_CERT_PATH="$signing_cert_path"
  export TDPN_DESKTOP_SIGNING_CERT_PATH="$signing_cert_path"
else
  unset GPM_DESKTOP_SIGNING_CERT_PATH
  unset TDPN_DESKTOP_SIGNING_CERT_PATH
fi

if [[ -n "$signing_cert_password" ]]; then
  export GPM_DESKTOP_SIGNING_CERT_PASSWORD="$signing_cert_password"
  export TDPN_DESKTOP_SIGNING_CERT_PASSWORD="$signing_cert_password"
else
  unset GPM_DESKTOP_SIGNING_CERT_PASSWORD
  unset TDPN_DESKTOP_SIGNING_CERT_PASSWORD
fi

echo "[desktop-release-bundle] mode=scaffold-non-production"
echo "[desktop-release-bundle] channel=$TDPN_DESKTOP_UPDATE_CHANNEL"
if [[ -n "${TDPN_DESKTOP_UPDATE_FEED_URL:-}" ]]; then
  echo "[desktop-release-bundle] update_feed=$TDPN_DESKTOP_UPDATE_FEED_URL"
else
  echo "[desktop-release-bundle] update_feed=(not set)"
fi
if [[ -n "${TDPN_DESKTOP_SIGNING_IDENTITY:-}" || -n "${TDPN_DESKTOP_SIGNING_CERT_PATH:-}" || -n "${TDPN_DESKTOP_SIGNING_CERT_PASSWORD:-}" ]]; then
  echo "[desktop-release-bundle] signing_placeholders=provided (scaffold-only)"
else
  echo "[desktop-release-bundle] signing_placeholders=not provided"
fi

if [[ "$skip_build" == "1" ]]; then
  echo "[desktop-release-bundle] build skipped by --skip-build"
  exit 0
fi

collect_missing_build_tools
if [[ "${#MISSING_BUILD_TOOLS[@]}" -gt 0 ]]; then
  echo "[desktop-release-bundle] missing build tools detected: ${MISSING_BUILD_TOOLS[*]}" >&2
  if [[ "$install_missing" == "1" ]]; then
    if ! run_doctor_missing_tools_remediation; then
      print_missing_build_tool_hints
      exit 1
    fi
    collect_missing_build_tools
  fi
fi

if [[ "${#MISSING_BUILD_TOOLS[@]}" -gt 0 ]]; then
  print_missing_build_tool_hints
  exit 1
fi

ensure_tauri_icon_scaffold

pushd "$DESKTOP_DIR" >/dev/null
npm_args=("run" "tauri" "--" "build")
if [[ "${#tauri_args[@]}" -gt 0 ]]; then
  npm_args+=("${tauri_args[@]}")
fi

echo "[desktop-release-bundle] running: npm ${npm_args[*]}"
npm "${npm_args[@]}"
popd >/dev/null

echo "[desktop-release-bundle] status=ok"
echo "[desktop-release-bundle] artifact_hint=$DESKTOP_DIR/src-tauri/target/release/bundle"
echo "[desktop-release-bundle] note=this is scaffold-only and not a production signing/release pipeline"
