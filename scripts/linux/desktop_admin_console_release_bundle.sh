#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DESKTOP_DIR="$ROOT_DIR/apps/desktop"
ADMIN_TAURI_CONFIG="$DESKTOP_DIR/src-tauri/tauri.admin-console.conf.json"
ADMIN_FEATURE="admin-console"
ADMIN_BUNDLE_ROOT="$DESKTOP_DIR/src-tauri/target/release/bundle"

show_usage() {
  cat <<'USAGE'
GPM Linux Admin Console release bundle scaffold

Usage:
  ./scripts/linux/desktop_admin_console_release_bundle.sh [--help] [--skip-build] [-- <tauri args>]

Notes:
  - Linux-first Admin Console artifact only.
  - Sets GPM_DESKTOP_ADMIN_CONSOLE=1 and GPM_DESKTOP_BUILD_ADMIN_CONSOLE=1.
  - Builds the renderer in admin-console mode before invoking Tauri.
  - Invokes Tauri with --features admin-console and the dedicated Admin Console config.
  - Refuses public-app mode flags and refuses attempts to remove the admin-console feature.
USAGE
}

to_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

assert_admin_tauri_args() {
  local expect_features_value="0"
  local saw_user_features="0"
  local arg
  local normalized

  for arg in "$@"; do
    normalized="$(to_lower "$arg")"
    normalized="${normalized#"${normalized%%[![:space:]]*}"}"
    normalized="${normalized%"${normalized##*[![:space:]]}"}"
    if [[ -z "$normalized" || "$normalized" == "--" ]]; then
      continue
    fi
    if [[ "$expect_features_value" == "1" ]]; then
      saw_user_features="1"
      if [[ ! "$normalized" =~ (^|,|[[:space:]])admin-console($|,|[[:space:]]) ]]; then
        echo "admin console release bundle refuses missing admin-console feature; pass --features admin-console or omit --features" >&2
        exit 1
      fi
      expect_features_value="0"
      continue
    fi
    case "$normalized" in
      --all-features)
        saw_user_features="1"
        ;;
      --features)
        expect_features_value="1"
        ;;
      --features=*)
        saw_user_features="1"
        if [[ "$normalized" != *admin-console* ]]; then
          echo "admin console release bundle refuses missing admin-console feature; pass --features admin-console or omit --features" >&2
          exit 1
        fi
        ;;
      --config|--config=*)
        echo "admin console release bundle refuses custom Tauri config; use the dedicated Admin Console config" >&2
        exit 1
        ;;
    esac
  done

  if [[ "$expect_features_value" == "1" ]]; then
    echo "admin console release bundle refuses empty --features value; admin-console is required" >&2
    exit 1
  fi

  # Marker for guardrails: default script path always supplies --features admin-console.
  if [[ "$saw_user_features" == "0" ]]; then
    return 0
  fi
}

assert_admin_config_identity() {
  if [[ ! -f "$ADMIN_TAURI_CONFIG" ]]; then
    echo "admin console release bundle failed: missing Admin Console Tauri config: $ADMIN_TAURI_CONFIG" >&2
    exit 1
  fi
  for marker in \
    '"productName": "GPM Admin Console"' \
    '"mainBinaryName": "gpm-admin-console"' \
    '"identifier": "com.gpm.admin-console"' \
    '"title": "GPM Admin Console"' \
    '"beforeBuildCommand": "npm run build:admin-console"'
  do
    if ! grep -Fq -- "$marker" "$ADMIN_TAURI_CONFIG"; then
      echo "admin console release bundle failed: missing Admin Console config marker: $marker" >&2
      exit 1
    fi
  done
}

assert_admin_release_artifacts_present() {
  local artifact_count=0
  if [[ -d "$ADMIN_BUNDLE_ROOT" ]]; then
    while IFS= read -r -d '' _artifact_path; do
      artifact_count=$((artifact_count + 1))
    done < <(find "$ADMIN_BUNDLE_ROOT" -type f -print0)
  fi
  if [[ "$artifact_count" -eq 0 ]]; then
    echo "admin console release bundle build produced no artifacts under $ADMIN_BUNDLE_ROOT" >&2
    exit 1
  fi
}

admin_release_artifact_count() {
  local artifact_count=0
  if [[ -d "$ADMIN_BUNDLE_ROOT" ]]; then
    while IFS= read -r -d '' _artifact_path; do
      artifact_count=$((artifact_count + 1))
    done < <(find "$ADMIN_BUNDLE_ROOT" -type f -print0)
  fi
  printf '%s' "$artifact_count"
}

skip_build="0"
tauri_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_usage
      exit 0
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

if [[ ! -f "$DESKTOP_DIR/package.json" ]]; then
  echo "apps/desktop/package.json not found at expected path: $DESKTOP_DIR" >&2
  exit 1
fi

assert_admin_config_identity
assert_admin_tauri_args "${tauri_args[@]}"

export GPM_DESKTOP_ADMIN_CONSOLE="1"
export GPM_DESKTOP_BUILD_ADMIN_CONSOLE="1"
export VITE_GPM_ADMIN_CONSOLE="1"
export TDPN_DESKTOP_ADMIN_CONSOLE="1"

echo "[desktop-admin-console-release-bundle] mode=linux-admin-console"
echo "[desktop-admin-console-release-bundle] config=$ADMIN_TAURI_CONFIG"
echo "[desktop-admin-console-release-bundle] feature=$ADMIN_FEATURE"

if [[ "$skip_build" == "1" ]]; then
  echo "[desktop-admin-console-release-bundle] build skipped by --skip-build"
  artifact_count="$(admin_release_artifact_count)"
  if [[ "$artifact_count" -gt 0 ]]; then
    echo "[desktop-admin-console-release-bundle] artifact_count=$artifact_count"
    echo "[desktop-admin-console-release-bundle] artifact_validation_status=unsigned_scaffold_artifacts"
    echo "[desktop-admin-console-release-bundle] release_ready=false"
  else
    echo "[desktop-admin-console-release-bundle] artifact_count=0"
    echo "[desktop-admin-console-release-bundle] artifact_validation_status=skipped_no_artifacts"
    echo "[desktop-admin-console-release-bundle] release_ready=false"
  fi
  exit 0
fi

pushd "$DESKTOP_DIR" >/dev/null
echo "[desktop-admin-console-release-bundle] running: npm run build:admin-console"
npm run build:admin-console

npm_args=(
  "run" "tauri" "--" "build"
  "--features" "$ADMIN_FEATURE"
  "--config" "src-tauri/tauri.admin-console.conf.json"
)
if [[ "${#tauri_args[@]}" -gt 0 ]]; then
  npm_args+=("${tauri_args[@]}")
fi

echo "[desktop-admin-console-release-bundle] running: npm ${npm_args[*]}"
npm "${npm_args[@]}"
popd >/dev/null

assert_admin_release_artifacts_present
artifact_count="$(admin_release_artifact_count)"

echo "[desktop-admin-console-release-bundle] status=ok"
echo "[desktop-admin-console-release-bundle] artifact_count=$artifact_count"
echo "[desktop-admin-console-release-bundle] artifact_validation_status=unsigned_scaffold_artifacts"
echo "[desktop-admin-console-release-bundle] release_ready=false"
