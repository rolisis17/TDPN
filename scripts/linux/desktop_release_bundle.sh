#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DESKTOP_DIR="$ROOT_DIR/apps/desktop"
BUNDLE_ROOT="$DESKTOP_DIR/src-tauri/target/release/bundle"
DEFAULT_SUMMARY_JSON="$ROOT_DIR/.easy-node-logs/desktop_release_bundle_linux_summary.json"
DOCTOR_SCRIPT="$ROOT_DIR/scripts/linux/desktop_doctor.sh"
DOCTOR_FIX_COMMAND="./scripts/linux/desktop_doctor.sh --mode fix --install-missing"
BUILD_REQUIRED_TOOLS=(node npm rustc cargo git bash)
MISSING_BUILD_TOOLS=()
SCANNED_ARTIFACTS_JSON="[]"
SCANNED_ARTIFACTS_BY_KIND_JSON='{"appimage":[],"deb":[],"rpm":[],"tarball":[],"sig":[],"file":[]}'
SCANNED_ADMIN_ARTIFACT_COUNT=0
SCANNED_ADMIN_ARTIFACTS_JSON="[]"
BUNDLE_ARTIFACT_MARKER=""

show_usage() {
  cat <<'USAGE'
GPM desktop release bundle scaffold (non-production signing flow)

Usage:
  ./scripts/linux/desktop_release_bundle.sh [--help] [--channel stable|beta|canary] [--update-feed-url URL] [--signing-identity ID] [--signing-cert-path PATH] [--signing-cert-password VALUE] [--install-missing] [--skip-build] [--summary-json PATH] [--print-summary-json [0|1]] [-- <tauri args>]

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

bool_to_json() {
  local raw="$1"
  if [[ "$raw" == "1" ]]; then
    printf '%s' "true"
  else
    printf '%s' "false"
  fi
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

json_array_from_entries() {
  local array_name="$1"
  local -n array_ref="$array_name"
  local json="["
  local index
  for index in "${!array_ref[@]}"; do
    if [[ "$index" -gt 0 ]]; then
      json+=","
    fi
    json+="${array_ref[$index]}"
  done
  json+="]"
  printf '%s' "$json"
}

artifact_extension_and_kind() {
  local artifact_name="$1"
  local artifact_name_lower
  artifact_name_lower="$(to_lower "$artifact_name")"

  local extension=""
  if [[ "$artifact_name_lower" == *.tar.gz ]]; then
    extension=".tar.gz"
  elif [[ "$artifact_name" == *.* && "$artifact_name" != .* ]]; then
    extension=".${artifact_name_lower##*.}"
  fi

  local kind="file"
  case "$extension" in
    .appimage)
      kind="appimage"
      ;;
    .deb)
      kind="deb"
      ;;
    .rpm)
      kind="rpm"
      ;;
    .tar.gz)
      kind="tarball"
      ;;
    .sig)
      kind="sig"
      ;;
    *)
      kind="file"
      ;;
  esac

  printf '%s\t%s' "$extension" "$kind"
}

sha256_for_file() {
  local target_file="$1"
  local digest_output=""

  if command -v sha256sum >/dev/null 2>&1; then
    digest_output="$(sha256sum "$target_file" 2>/dev/null || true)"
    if [[ -n "$digest_output" ]]; then
      printf '%s' "${digest_output%% *}"
      return
    fi
  fi

  if command -v shasum >/dev/null 2>&1; then
    digest_output="$(shasum -a 256 "$target_file" 2>/dev/null || true)"
    if [[ -n "$digest_output" ]]; then
      printf '%s' "${digest_output%% *}"
      return
    fi
  fi

  if command -v openssl >/dev/null 2>&1; then
    digest_output="$(openssl dgst -sha256 "$target_file" 2>/dev/null || true)"
    if [[ "$digest_output" == *"= "* ]]; then
      printf '%s' "${digest_output##*= }"
      return
    fi
  fi

  printf '%s' ""
}

size_bytes_for_file() {
  local target_file="$1"
  local size_value=""
  if size_value="$(stat -c %s "$target_file" 2>/dev/null)"; then
    printf '%s' "$size_value"
    return
  fi

  size_value="$(wc -c <"$target_file" 2>/dev/null || true)"
  size_value="${size_value//[[:space:]]/}"
  if [[ -n "$size_value" ]]; then
    printf '%s' "$size_value"
    return
  fi

  printf '%s' "0"
}

is_admin_console_artifact_path() {
  local value="$1"
  local normalized
  normalized="$(to_lower "$value")"
  local tokenized="${normalized// /-}"
  tokenized="${tokenized//_/-}"

  [[ "$tokenized" == *admin-console* || "$tokenized" == *gpm-admin* || "$normalized" == *tauri.admin-console.conf.json* ]]
}

scan_release_bundle_artifacts() {
  local bundle_root_path="$1"

  local artifacts_entries=()
  local admin_artifact_entries=()
  local appimage_entries=()
  local deb_entries=()
  local rpm_entries=()
  local tarball_entries=()
  local sig_entries=()
  local file_entries=()

  if [[ -d "$bundle_root_path" ]]; then
    local had_globstar="0"
    local had_nullglob="0"
    if shopt -q globstar; then
      had_globstar="1"
    fi
    if shopt -q nullglob; then
      had_nullglob="1"
    fi

    shopt -s globstar nullglob
    local artifact_path
    for artifact_path in "$bundle_root_path"/**; do
      if [[ ! -f "$artifact_path" ]]; then
        continue
      fi

      local artifact_name
      artifact_name="${artifact_path##*/}"
      local artifact_path_lower
      artifact_path_lower="$(to_lower "$artifact_path")"

      local extension_kind
      extension_kind="$(artifact_extension_and_kind "$artifact_name")"
      local artifact_extension="${extension_kind%%$'\t'*}"
      local artifact_kind="${extension_kind##*$'\t'}"

      local artifact_size_bytes
      artifact_size_bytes="$(size_bytes_for_file "$artifact_path")"

      local artifact_sha256
      artifact_sha256="$(sha256_for_file "$artifact_path")"

      local artifact_path_json
      artifact_path_json="\"$(json_escape "$artifact_path")\""
      local artifact_name_json
      artifact_name_json="\"$(json_escape "$artifact_name")\""
      local artifact_extension_json
      artifact_extension_json="\"$(json_escape "$artifact_extension")\""
      local artifact_kind_json
      artifact_kind_json="\"$(json_escape "$artifact_kind")\""
      local artifact_sha256_json
      artifact_sha256_json="\"$(json_escape "$artifact_sha256")\""

      if is_admin_console_artifact_path "$artifact_path_lower"; then
        admin_artifact_entries+=("$artifact_path_json")
      fi

      if [[ -n "${BUNDLE_ARTIFACT_MARKER:-}" && -f "$BUNDLE_ARTIFACT_MARKER" && ! "$artifact_path" -nt "$BUNDLE_ARTIFACT_MARKER" ]]; then
        continue
      fi

      artifacts_entries+=("{\"path\":$artifact_path_json,\"name\":$artifact_name_json,\"extension\":$artifact_extension_json,\"kind\":$artifact_kind_json,\"size_bytes\":$artifact_size_bytes,\"sha256\":$artifact_sha256_json}")

      case "$artifact_kind" in
        appimage)
          appimage_entries+=("$artifact_path_json")
          ;;
        deb)
          deb_entries+=("$artifact_path_json")
          ;;
        rpm)
          rpm_entries+=("$artifact_path_json")
          ;;
        tarball)
          tarball_entries+=("$artifact_path_json")
          ;;
        sig)
          sig_entries+=("$artifact_path_json")
          ;;
        *)
          file_entries+=("$artifact_path_json")
          ;;
      esac
    done

    if [[ "$had_globstar" == "0" ]]; then
      shopt -u globstar
    fi
    if [[ "$had_nullglob" == "0" ]]; then
      shopt -u nullglob
    fi
  fi

  SCANNED_ARTIFACTS_COUNT="${#artifacts_entries[@]}"
  SCANNED_ARTIFACTS_JSON="$(json_array_from_entries artifacts_entries)"
  SCANNED_ARTIFACTS_BY_KIND_JSON="{\"appimage\":$(json_array_from_entries appimage_entries),\"deb\":$(json_array_from_entries deb_entries),\"rpm\":$(json_array_from_entries rpm_entries),\"tarball\":$(json_array_from_entries tarball_entries),\"sig\":$(json_array_from_entries sig_entries),\"file\":$(json_array_from_entries file_entries)}"
  SCANNED_ADMIN_ARTIFACT_COUNT="${#admin_artifact_entries[@]}"
  SCANNED_ADMIN_ARTIFACTS_JSON="$(json_array_from_entries admin_artifact_entries)"
}

assert_no_public_admin_artifacts() {
  if [[ "${SCANNED_ADMIN_ARTIFACT_COUNT:-0}" -gt 0 ]]; then
    echo "public desktop release bundle refuses Admin Console artifacts in shared bundle output; clean the bundle directory or use the separate Admin Console release bundle" >&2
    echo "admin artifact paths: $SCANNED_ADMIN_ARTIFACTS_JSON" >&2
    exit 1
  fi
}

assert_release_bundle_artifacts_present() {
  scan_release_bundle_artifacts "$BUNDLE_ROOT"
  assert_no_public_admin_artifacts
  if [[ "${SCANNED_ARTIFACTS_COUNT:-0}" -eq 0 ]]; then
    echo "desktop release bundle build produced no artifacts under $BUNDLE_ROOT" >&2
    exit 1
  fi
}

emit_success_summary_json() {
  local generated_at_utc
  generated_at_utc="$(printf '%(%Y-%m-%dT%H:%M:%SZ)T' -1)"
  scan_release_bundle_artifacts "$BUNDLE_ROOT"
  assert_no_public_admin_artifacts
  local artifact_validation_status="unsigned_scaffold_artifacts"
  local release_ready="0"
  if [[ "${SCANNED_ARTIFACTS_COUNT:-0}" -eq 0 ]]; then
    if [[ "$skip_build" == "1" ]]; then
      artifact_validation_status="skipped_no_artifacts"
    else
      artifact_validation_status="missing"
    fi
  fi

  local summary_dir="$summary_json"
  if [[ "$summary_dir" == */* ]]; then
    summary_dir="${summary_json%/*}"
    if [[ ! -d "$summary_dir" ]]; then
      mkdir -p "$summary_dir"
    fi
  fi

  local payload
  payload="$(printf '%s\n' \
    '{' \
    '  "version": 1,' \
    "  \"generated_at_utc\": \"$(json_escape "$generated_at_utc")\"," \
    '  "status": "ok",' \
    '  "rc": 0,' \
    '  "platform": "linux",' \
    '  "mode": "desktop_release_bundle_scaffold",' \
    "  \"channel\": \"$(json_escape "$channel")\"," \
    "  \"update_feed_url\": \"$(json_escape "$update_feed_url")\"," \
    "  \"skip_build\": $(bool_to_json "$skip_build")," \
    "  \"install_missing_requested\": $(bool_to_json "$install_missing")," \
    "  \"bundle_root\": \"$(json_escape "$BUNDLE_ROOT")\"," \
    "  \"artifact_hint\": \"$(json_escape "$BUNDLE_ROOT")\"," \
    "  \"artifact_count\": ${SCANNED_ARTIFACTS_COUNT:-0}," \
    "  \"artifact_validation_status\": \"$(json_escape "$artifact_validation_status")\"," \
    "  \"release_ready\": $(bool_to_json "$release_ready")," \
    "  \"artifacts\": $SCANNED_ARTIFACTS_JSON," \
    "  \"artifacts_by_kind\": $SCANNED_ARTIFACTS_BY_KIND_JSON" \
    '}')"

  printf '%s\n' "$payload" >"$summary_json"
  echo "[desktop-release-bundle] summary_json=$summary_json"
  if [[ "$print_summary_json" == "1" ]]; then
    echo "[desktop-release-bundle] summary_json_payload:"
    printf '%s\n' "$payload"
  fi
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
  if [[ "$candidate" == *"?"* || "$candidate" == *"#"* ]]; then
    echo "invalid --update-feed-url '$candidate' (query/fragment is not allowed)" >&2
    exit 2
  fi
  local authority="${candidate#*://}"
  authority="${authority%%/*}"
  if [[ "$authority" == *"@"* ]]; then
    echo "invalid --update-feed-url '$candidate' (userinfo is not allowed)" >&2
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

assert_public_tauri_args() {
  local expect_features_value="0"
  local expect_config_value="0"
  local arg
  local normalized

  for arg in "$@"; do
    normalized="$(printf '%s' "$arg" | tr '[:upper:]' '[:lower:]')"
    normalized="${normalized#"${normalized%%[![:space:]]*}"}"
    normalized="${normalized%"${normalized##*[![:space:]]}"}"
    if [[ -z "$normalized" ]]; then
      if [[ "$expect_config_value" == "1" || "$expect_features_value" == "1" ]]; then
        echo "public desktop release bundle refuses empty --features/--config value" >&2
        exit 1
      fi
      continue
    fi
    if [[ "$normalized" == "--" ]]; then
      continue
    fi
    if [[ "$expect_config_value" == "1" ]]; then
      if [[ "$normalized" == --* ]]; then
        echo "public desktop release bundle refuses missing or flag-like --config value" >&2
        exit 1
      fi
      if [[ "$normalized" == *tauri.admin-console.conf.json* || "$normalized" == *admin-console* ]]; then
        echo "public desktop release bundle refuses Admin Console Tauri config; use the separate Admin Console build command instead" >&2
        exit 1
      fi
      expect_config_value="0"
      continue
    fi
    if [[ "$expect_features_value" == "1" ]]; then
      if [[ "$normalized" == --* ]]; then
        echo "public desktop release bundle refuses missing or flag-like --features value" >&2
        exit 1
      fi
      if [[ "$normalized" =~ (^|,|[[:space:]])admin-console($|,|[[:space:]]) ]]; then
        echo "public desktop release bundle refuses admin-console feature flags; use the separate Admin Console build command instead" >&2
        exit 1
      fi
      expect_features_value="0"
      continue
    fi
    case "$normalized" in
      --all-features)
        echo "public desktop release bundle refuses --all-features because it can include admin-console; use the separate Admin Console build command instead" >&2
        exit 1
        ;;
      --features)
        expect_features_value="1"
        ;;
      --features=*)
        if [[ "$normalized" == "--features=" ]]; then
          echo "public desktop release bundle refuses empty --features value" >&2
          exit 1
        fi
        if [[ "$normalized" == *admin-console* ]]; then
          echo "public desktop release bundle refuses admin-console feature flags; use the separate Admin Console build command instead" >&2
          exit 1
        fi
        ;;
      --config)
        expect_config_value="1"
        ;;
      --config=*)
        if [[ "$normalized" == "--config=" ]]; then
          echo "public desktop release bundle refuses empty --config value" >&2
          exit 1
        fi
        if [[ "$normalized" == *tauri.admin-console.conf.json* || "$normalized" == *admin-console* ]]; then
          echo "public desktop release bundle refuses Admin Console Tauri config; use the separate Admin Console build command instead" >&2
          exit 1
        fi
        ;;
      *tauri.admin-console.conf.json*|*admin-console*)
        echo "public desktop release bundle refuses Admin Console Tauri config; use the separate Admin Console build command instead" >&2
        exit 1
        ;;
    esac
  done
  if [[ "$expect_config_value" == "1" ]]; then
    echo "public desktop release bundle refuses missing --config value" >&2
    exit 1
  fi
  if [[ "$expect_features_value" == "1" ]]; then
    echo "public desktop release bundle refuses missing --features value" >&2
    exit 1
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
  "GPM_DESKTOP_ADMIN_CONSOLE"
  "GPM_DESKTOP_BUILD_ADMIN_CONSOLE"
  "TDPN_DESKTOP_ADMIN_CONSOLE"
  "VITE_GPM_ADMIN_CONSOLE"
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

cleanup_release_bundle() {
  if [[ -n "${BUNDLE_ARTIFACT_MARKER:-}" ]]; then
    rm -f "$BUNDLE_ARTIFACT_MARKER"
  fi
  restore_scoped_env
}

channel="stable"
update_feed_url=""
signing_identity=""
signing_cert_path=""
signing_cert_password=""
install_missing="0"
skip_build="0"
summary_json="$DEFAULT_SUMMARY_JSON"
print_summary_json="0"
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
    --summary-json)
      if [[ $# -lt 2 ]]; then
        echo "--summary-json requires a value" >&2
        exit 2
      fi
      summary_json="$2"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -lt 2 ]]; then
        echo "--print-summary-json requires a value (0 or 1)" >&2
        exit 2
      fi
      print_summary_json="$2"
      shift 2
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

case "$print_summary_json" in
  0|1) ;;
  *)
    echo "invalid --print-summary-json '$print_summary_json' (allowed: 0, 1)" >&2
    exit 2
    ;;
esac

if [[ ! -f "$DESKTOP_DIR/package.json" ]]; then
  echo "apps/desktop/package.json not found at expected path: $DESKTOP_DIR" >&2
  exit 1
fi

validate_update_feed_url "$update_feed_url"
validate_signing_placeholders "$signing_identity" "$signing_cert_path" "$signing_cert_password"
assert_public_tauri_args "${tauri_args[@]}"

save_scoped_env
trap cleanup_release_bundle EXIT

export GPM_DESKTOP_UPDATE_CHANNEL="$channel"
export TDPN_DESKTOP_UPDATE_CHANNEL="$channel"
export GPM_DESKTOP_ADMIN_CONSOLE="0"
export GPM_DESKTOP_BUILD_ADMIN_CONSOLE="0"
export TDPN_DESKTOP_ADMIN_CONSOLE="0"
export VITE_GPM_ADMIN_CONSOLE="0"
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
  emit_success_summary_json
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

BUNDLE_ARTIFACT_MARKER="$(mktemp)"
touch "$BUNDLE_ARTIFACT_MARKER"

pushd "$DESKTOP_DIR" >/dev/null
npm_args=("run" "tauri" "--" "build")
if [[ "${#tauri_args[@]}" -gt 0 ]]; then
  npm_args+=("${tauri_args[@]}")
fi

echo "[desktop-release-bundle] running: npm ${npm_args[*]}"
npm "${npm_args[@]}"
popd >/dev/null

assert_release_bundle_artifacts_present

echo "[desktop-release-bundle] status=ok"
echo "[desktop-release-bundle] artifact_hint=$DESKTOP_DIR/src-tauri/target/release/bundle"
echo "[desktop-release-bundle] note=this is scaffold-only and not a production signing/release pipeline"
emit_success_summary_json
