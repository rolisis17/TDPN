#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DESKTOP_DIR="$ROOT_DIR/apps/desktop"

show_usage() {
  cat <<'USAGE'
TDPN desktop release bundle scaffold (non-production signing flow)

Usage:
  ./scripts/linux/desktop_release_bundle.sh [--help] [--channel stable|beta|canary] [--update-feed-url URL] [--signing-identity ID] [--signing-cert-path PATH] [--signing-cert-password VALUE] [--skip-build] [-- <tauri args>]

Examples:
  ./scripts/linux/desktop_release_bundle.sh
  ./scripts/linux/desktop_release_bundle.sh --channel beta --update-feed-url https://updates.example.invalid/tdpn/beta.json
  ./scripts/linux/desktop_release_bundle.sh --channel canary -- --bundles appimage

Notes:
  - This is scaffold-only and does not implement production signing/secret handling.
  - Tauri build runs from apps/desktop via: npm run tauri -- build ...
  - Sets TDPN_DESKTOP_UPDATE_CHANNEL and optional TDPN_DESKTOP_UPDATE_FEED_URL for this process.
  - Validates update feed URL and signing placeholder input consistency before invoking build.
USAGE
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
    echo "invalid --update-feed-url '$candidate' (expected absolute URL like https://updates.example.invalid/tdpn/beta.json)" >&2
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

declare -A SAVED_ENV_PRESENT=()
declare -A SAVED_ENV_VALUE=()
SCOPED_ENV_NAMES=(
  "TDPN_DESKTOP_UPDATE_CHANNEL"
  "TDPN_DESKTOP_UPDATE_FEED_URL"
  "TDPN_DESKTOP_SIGNING_IDENTITY"
  "TDPN_DESKTOP_SIGNING_CERT_PATH"
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

export TDPN_DESKTOP_UPDATE_CHANNEL="$channel"
if [[ -n "$update_feed_url" ]]; then
  export TDPN_DESKTOP_UPDATE_FEED_URL="$update_feed_url"
else
  unset TDPN_DESKTOP_UPDATE_FEED_URL
fi

if [[ -n "$signing_identity" ]]; then
  export TDPN_DESKTOP_SIGNING_IDENTITY="$signing_identity"
else
  unset TDPN_DESKTOP_SIGNING_IDENTITY
fi

if [[ -n "$signing_cert_path" ]]; then
  export TDPN_DESKTOP_SIGNING_CERT_PATH="$signing_cert_path"
else
  unset TDPN_DESKTOP_SIGNING_CERT_PATH
fi

if [[ -n "$signing_cert_password" ]]; then
  export TDPN_DESKTOP_SIGNING_CERT_PASSWORD="$signing_cert_password"
else
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

if ! command -v npm >/dev/null 2>&1; then
  echo "npm was not found in PATH. Install Node.js/npm first." >&2
  exit 1
fi

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
