#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE_ROOT="$ROOT_DIR/apps/desktop/src-tauri/target/release/bundle"
RELEASE_BUNDLE_SCRIPT="$ROOT_DIR/scripts/linux/desktop_release_bundle.sh"
DEFAULT_SUMMARY_JSON="$ROOT_DIR/.easy-node-logs/desktop_installer_linux_summary.json"

installer_path=""
installer_type="auto"
build_if_missing="0"
install_missing="0"
channel="stable"
dry_run="0"
summary_json="$DEFAULT_SUMMARY_JSON"
print_summary_json="0"
launch_after_install="1"
installed_executable=""

status="fail"
rc="1"
failure_stage=""
resolved_installer_path=""
resolved_installer_type=""
installer_source=""
resolved_installed_executable=""
build_triggered="0"
summary_payload=""
launch_attempted="0"
launch_status="not_attempted"
launch_command=""
launch_command_source=""
launch_warning=""

log() {
  echo "[desktop-installer-linux] $*"
}

show_usage() {
  cat <<'USAGE'
GPM Linux desktop installer scaffold (non-production helper)

Usage:
  ./scripts/linux/desktop_installer.sh [options]

Options:
  --installer-path PATH                 Explicit installer artifact path.
  --installer-type TYPE                 One of: auto, appimage, deb, rpm (default: auto).
  --build-if-missing                    If no artifact is found, run desktop_release_bundle.sh then retry.
  --install-missing                     Forward to desktop_release_bundle.sh when build is triggered.
  --channel CHANNEL                     One of: stable, beta, canary (default: stable).
  --dry-run                             Print would-run installer command(s) only.
  --launch-after-install [0|1]          Attempt post-install desktop launch (default: 1, omitted value means 1).
  --installed-executable PATH           Optional installed desktop executable override for launch attempts.
  --summary-json PATH                   Summary output path (default: .easy-node-logs/desktop_installer_linux_summary.json).
  --print-summary-json [0|1]            Print summary JSON payload to stdout (default: 0, omitted value means 1).
  --help                                Show help.

Behavior:
  - Discovers artifacts under: apps/desktop/src-tauri/target/release/bundle
    appimage: *.AppImage
    deb:      *.deb
    rpm:      *.rpm
  - Auto selection preference: appimage -> deb -> rpm
  - AppImage install mode: chmod +x and execute artifact directly (existing behavior preserved).
  - DEB install mode: apt/apt-get install ./artifact (fallback: dpkg -i ./artifact; sudo when not root).
  - RPM install mode: dnf/yum/zypper install ./artifact (fallback: rpm -i ./artifact; sudo when not root).
  - Post-install launch (deb/rpm): override path first, then gpm-desktop/global-private-mesh-desktop; missing executable is non-fatal.
  - Scaffold only; this is not a production installer/updater pipeline.
USAGE
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

ensure_summary_parent_dir() {
  local parent_dir
  parent_dir="$(dirname "$summary_json")"
  mkdir -p "$parent_dir"
}

write_summary_json() {
  local generated_at_utc
  generated_at_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  summary_payload=$(
    cat <<EOF
{
  "version": 1,
  "generated_at_utc": "$(json_escape "$generated_at_utc")",
  "status": "$(json_escape "$status")",
  "rc": $rc,
  "platform": "linux",
  "mode": "desktop_installer_scaffold",
  "channel": "$(json_escape "$channel")",
  "installer_path": "$(json_escape "$resolved_installer_path")",
  "installer_type": "$(json_escape "$resolved_installer_type")",
  "installer_source": "$(json_escape "$installer_source")",
  "dry_run": $(json_bool "$dry_run"),
  "launch_after_install": $(json_bool "$launch_after_install"),
  "installed_executable": "$(json_escape "$resolved_installed_executable")",
  "launch_attempted": $(json_bool "$launch_attempted"),
  "launch_status": "$(json_escape "$launch_status")",
  "launch_command": "$(json_escape "$launch_command")",
  "launch_command_source": "$(json_escape "$launch_command_source")",
  "launch_warning": "$(json_escape "$launch_warning")",
  "build_if_missing": $(json_bool "$build_if_missing"),
  "build_triggered": $(json_bool "$build_triggered"),
  "failure_stage": "$(json_escape "$failure_stage")"
}
EOF
  )

  ensure_summary_parent_dir
  printf '%s\n' "$summary_payload" >"$summary_json"
  log "summary_json=$summary_json"
  if [[ "$print_summary_json" == "1" ]]; then
    log "summary_json_payload:"
    printf '%s\n' "$summary_payload"
  fi
}

finish() {
  rc="$1"
  if [[ "$rc" == "0" ]]; then
    status="ok"
  else
    status="fail"
  fi
  write_summary_json
  exit "$rc"
}

fail() {
  local stage="$1"
  local message="$2"
  failure_stage="$stage"
  echo "[desktop-installer-linux] error: $message" >&2
  finish 1
}

resolve_absolute_path() {
  local candidate="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$candidate"
    return
  fi
  local path_dir
  local path_base
  path_dir="$(dirname "$candidate")"
  path_base="$(basename "$candidate")"
  (
    cd "$path_dir"
    printf '%s/%s\n' "$(pwd)" "$path_base"
  )
}

infer_type_from_path() {
  local candidate="$1"
  case "$candidate" in
    *.AppImage)
      printf '%s' "appimage"
      ;;
    *.deb)
      printf '%s' "deb"
      ;;
    *.rpm)
      printf '%s' "rpm"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

validate_path_matches_type() {
  local candidate="$1"
  local expected_type="$2"
  case "$expected_type" in
    appimage)
      [[ "$candidate" == *.AppImage ]]
      ;;
    deb)
      [[ "$candidate" == *.deb ]]
      ;;
    rpm)
      [[ "$candidate" == *.rpm ]]
      ;;
    *)
      return 1
      ;;
  esac
}

discover_first_artifact_by_type() {
  local artifact_kind="$1"
  local name_pattern=""
  case "$artifact_kind" in
    appimage)
      name_pattern="*.AppImage"
      ;;
    deb)
      name_pattern="*.deb"
      ;;
    rpm)
      name_pattern="*.rpm"
      ;;
    *)
      return 0
      ;;
  esac

  if [[ ! -d "$BUNDLE_ROOT" ]]; then
    return 0
  fi

  local first_match=""
  first_match="$(find "$BUNDLE_ROOT" -type f -name "$name_pattern" 2>/dev/null | sort | head -n 1 || true)"
  if [[ -n "$first_match" ]]; then
    printf '%s' "$first_match"
  fi
}

resolve_from_discovery() {
  local found_path=""
  if [[ "$installer_type" == "auto" ]]; then
    found_path="$(discover_first_artifact_by_type "appimage")"
    if [[ -n "$found_path" ]]; then
      resolved_installer_path="$found_path"
      resolved_installer_type="appimage"
      installer_source="discovered"
      return 0
    fi
    found_path="$(discover_first_artifact_by_type "deb")"
    if [[ -n "$found_path" ]]; then
      resolved_installer_path="$found_path"
      resolved_installer_type="deb"
      installer_source="discovered"
      return 0
    fi
    found_path="$(discover_first_artifact_by_type "rpm")"
    if [[ -n "$found_path" ]]; then
      resolved_installer_path="$found_path"
      resolved_installer_type="rpm"
      installer_source="discovered"
      return 0
    fi
    return 1
  fi

  found_path="$(discover_first_artifact_by_type "$installer_type")"
  if [[ -n "$found_path" ]]; then
    resolved_installer_path="$found_path"
    resolved_installer_type="$installer_type"
    installer_source="discovered"
    return 0
  fi
  return 1
}

maybe_build_missing_artifacts() {
  if [[ "$build_if_missing" != "1" ]]; then
    return 0
  fi

  if [[ ! -f "$RELEASE_BUNDLE_SCRIPT" ]]; then
    fail "build" "missing build helper: $RELEASE_BUNDLE_SCRIPT"
  fi

  build_triggered="1"
  local build_cmd=(bash "$RELEASE_BUNDLE_SCRIPT" --channel "$channel")
  if [[ "$install_missing" == "1" ]]; then
    build_cmd+=(--install-missing)
  fi

  if [[ "$dry_run" == "1" ]]; then
    log "dry-run would run build helper: ${build_cmd[*]}"
    return 0
  fi

  log "running build helper: ${build_cmd[*]}"
  if ! "${build_cmd[@]}"; then
    fail "build" "desktop release bundle helper failed"
  fi
}

normalize_installed_executable_override() {
  if [[ -z "$installed_executable" ]]; then
    resolved_installed_executable=""
    return 0
  fi

  if [[ "$installed_executable" == */* ]]; then
    if [[ -e "$installed_executable" ]]; then
      resolved_installed_executable="$(resolve_absolute_path "$installed_executable")"
      return 0
    fi
    if [[ "$installed_executable" == /* ]]; then
      resolved_installed_executable="$installed_executable"
    else
      resolved_installed_executable="$ROOT_DIR/$installed_executable"
    fi
    return 0
  fi

  resolved_installed_executable="$installed_executable"
}

resolve_launch_candidate() {
  local candidate="$1"
  local candidate_source="$2"

  if [[ -z "$candidate" ]]; then
    return 1
  fi

  if [[ "$candidate" == */* ]]; then
    if [[ ! -f "$candidate" ]]; then
      return 1
    fi
    launch_command="$(resolve_absolute_path "$candidate")"
    launch_command_source="$candidate_source"
    return 0
  fi

  local command_path
  command_path="$(command -v "$candidate" 2>/dev/null || true)"
  if [[ -z "$command_path" ]]; then
    return 1
  fi
  launch_command="$command_path"
  launch_command_source="$candidate_source"
  return 0
}

resolve_post_install_launch_command() {
  launch_command=""
  launch_command_source=""

  if [[ -n "$resolved_installed_executable" ]]; then
    if resolve_launch_candidate "$resolved_installed_executable" "installed_executable_override"; then
      return 0
    fi
  fi

  if resolve_launch_candidate "gpm-desktop" "command_name:gpm-desktop"; then
    return 0
  fi
  if resolve_launch_candidate "global-private-mesh-desktop" "command_name:global-private-mesh-desktop"; then
    return 0
  fi

  return 1
}

maybe_launch_after_install_for_package() {
  local package_kind="$1"

  if [[ "$launch_after_install" != "1" ]]; then
    launch_status="disabled"
    return 0
  fi

  if ! resolve_post_install_launch_command; then
    launch_status="not_found"
    launch_warning="post-install launch skipped; executable not found (checked --installed-executable, gpm-desktop, global-private-mesh-desktop)"
    if [[ "$dry_run" == "1" ]]; then
      log "dry-run would run launch command: <unresolved> (source=auto-discovery type=$package_kind)"
    fi
    log "warning: $launch_warning"
    return 0
  fi

  launch_attempted="1"
  if [[ "$dry_run" == "1" ]]; then
    launch_status="would_run"
    log "dry-run would run launch command: \"$launch_command\" (source=$launch_command_source type=$package_kind)"
    return 0
  fi

  log "running post-install launch command: \"$launch_command\" (source=$launch_command_source type=$package_kind)"
  if "$launch_command" >/dev/null 2>&1 & then
    local launch_pid="$!"
    launch_status="started"
    log "post-install launch started pid=$launch_pid"
    return 0
  fi

  local launch_rc="$?"
  launch_status="failed"
  launch_warning="post-install launch command failed (rc=$launch_rc); install succeeded but launch did not start"
  log "warning: $launch_warning"
  return 0
}

execute_installer() {
  case "$resolved_installer_type" in
    appimage)
      launch_command="$resolved_installer_path"
      launch_command_source="appimage_artifact"
      launch_attempted="1"
      if [[ "$dry_run" == "1" ]]; then
        log "dry-run would run: chmod +x \"$resolved_installer_path\""
        log "dry-run would run: \"$resolved_installer_path\""
        log "dry-run would run launch command: \"$resolved_installer_path\" (source=$launch_command_source type=appimage)"
        launch_status="would_run"
        return 0
      fi
      chmod +x "$resolved_installer_path"
      log "running installer: $resolved_installer_path"
      if "$resolved_installer_path"; then
        launch_status="ok"
      else
        local appimage_rc="$?"
        launch_status="failed"
        launch_warning="appimage execution failed (rc=$appimage_rc)"
        return 1
      fi
      ;;
    deb)
      local artifact_dir
      local artifact_name
      local local_artifact_ref
      artifact_dir="$(dirname "$resolved_installer_path")"
      artifact_name="$(basename "$resolved_installer_path")"
      local_artifact_ref="./$artifact_name"

      local deb_cmd=()
      if command -v apt >/dev/null 2>&1; then
        deb_cmd=(apt install -y "$local_artifact_ref")
      elif command -v apt-get >/dev/null 2>&1; then
        deb_cmd=(apt-get install -y "$local_artifact_ref")
      elif command -v dpkg >/dev/null 2>&1; then
        deb_cmd=(dpkg -i "$local_artifact_ref")
      else
        fail "install" "no supported DEB installer command found (apt, apt-get, dpkg); remediation hint: install apt/dpkg toolchain or use --installer-type appimage"
      fi

      if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        if command -v sudo >/dev/null 2>&1; then
          deb_cmd=(sudo "${deb_cmd[@]}")
        else
          fail "install" "non-root DEB install requires sudo; remediation hint: install sudo, re-run as root, or use --installer-type appimage"
        fi
      fi
      if [[ "$dry_run" == "1" ]]; then
        log "dry-run would run: (cd \"$artifact_dir\" && ${deb_cmd[*]})"
      else
        log "running installer: (cd \"$artifact_dir\" && ${deb_cmd[*]})"
        (
          cd "$artifact_dir"
          "${deb_cmd[@]}"
        )
      fi
      maybe_launch_after_install_for_package "deb"
      ;;
    rpm)
      local artifact_dir
      local artifact_name
      local local_artifact_ref
      artifact_dir="$(dirname "$resolved_installer_path")"
      artifact_name="$(basename "$resolved_installer_path")"
      local_artifact_ref="./$artifact_name"

      local rpm_cmd=()
      if command -v dnf >/dev/null 2>&1; then
        rpm_cmd=(dnf install -y "$local_artifact_ref")
      elif command -v yum >/dev/null 2>&1; then
        rpm_cmd=(yum install -y "$local_artifact_ref")
      elif command -v zypper >/dev/null 2>&1; then
        rpm_cmd=(zypper --non-interactive install "$local_artifact_ref")
      elif command -v rpm >/dev/null 2>&1; then
        rpm_cmd=(rpm -i "$local_artifact_ref")
      else
        fail "install" "no supported RPM installer command found (dnf, yum, zypper, rpm); remediation hint: install rpm toolchain or use --installer-type appimage"
      fi

      if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        if command -v sudo >/dev/null 2>&1; then
          rpm_cmd=(sudo "${rpm_cmd[@]}")
        else
          fail "install" "non-root RPM install requires sudo; remediation hint: install sudo, re-run as root, or use --installer-type appimage"
        fi
      fi
      if [[ "$dry_run" == "1" ]]; then
        log "dry-run would run: (cd \"$artifact_dir\" && ${rpm_cmd[*]})"
      else
        log "running installer: (cd \"$artifact_dir\" && ${rpm_cmd[*]})"
        (
          cd "$artifact_dir"
          "${rpm_cmd[@]}"
        )
      fi
      maybe_launch_after_install_for_package "rpm"
      ;;
    *)
      fail "resolve" "unsupported installer type: $resolved_installer_type"
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --installer-path)
      if [[ $# -lt 2 ]]; then
        fail "args" "--installer-path requires a value"
      fi
      installer_path="$2"
      shift 2
      ;;
    --installer-type)
      if [[ $# -lt 2 ]]; then
        fail "args" "--installer-type requires a value"
      fi
      installer_type="$2"
      shift 2
      ;;
    --build-if-missing)
      build_if_missing="1"
      shift
      ;;
    --install-missing)
      install_missing="1"
      shift
      ;;
    --channel)
      if [[ $# -lt 2 ]]; then
        fail "args" "--channel requires a value"
      fi
      channel="$2"
      shift 2
      ;;
    --dry-run)
      dry_run="1"
      shift
      ;;
    --launch-after-install)
      if [[ $# -ge 2 && ( "$2" == "0" || "$2" == "1" ) ]]; then
        launch_after_install="$2"
        shift 2
      elif [[ $# -ge 2 && "$2" != --* ]]; then
        fail "args" "invalid --launch-after-install '$2' (allowed: 0, 1)"
      else
        launch_after_install="1"
        shift
      fi
      ;;
    --installed-executable)
      if [[ $# -lt 2 ]]; then
        fail "args" "--installed-executable requires a value"
      fi
      if [[ -z "$2" ]]; then
        fail "args" "--installed-executable requires a non-empty value"
      fi
      installed_executable="$2"
      shift 2
      ;;
    --summary-json)
      if [[ $# -lt 2 ]]; then
        fail "args" "--summary-json requires a value"
      fi
      summary_json="$2"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "$2" == "0" || "$2" == "1" ) ]]; then
        print_summary_json="$2"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    --help|-h)
      show_usage
      exit 0
      ;;
    *)
      show_usage >&2
      fail "args" "unknown argument: $1"
      ;;
  esac
done

case "$installer_type" in
  auto|appimage|deb|rpm) ;;
  *)
    fail "args" "invalid --installer-type '$installer_type' (allowed: auto, appimage, deb, rpm)"
    ;;
esac

case "$channel" in
  stable|beta|canary) ;;
  *)
    fail "args" "invalid --channel '$channel' (allowed: stable, beta, canary)"
    ;;
esac

case "$print_summary_json" in
  0|1) ;;
  *)
    fail "args" "invalid --print-summary-json '$print_summary_json' (allowed: 0, 1)"
    ;;
esac

case "$launch_after_install" in
  0|1) ;;
  *)
    fail "args" "invalid --launch-after-install '$launch_after_install' (allowed: 0, 1)"
    ;;
esac

normalize_installed_executable_override

if [[ -n "$installer_path" ]]; then
  if [[ ! -f "$installer_path" ]]; then
    fail "resolve" "installer path does not exist: $installer_path"
  fi
  resolved_installer_path="$(resolve_absolute_path "$installer_path")"
  installer_source="explicit"

  if [[ "$installer_type" == "auto" ]]; then
    resolved_installer_type="$(infer_type_from_path "$resolved_installer_path")"
    if [[ -z "$resolved_installer_type" ]]; then
      fail "resolve" "unable to infer installer type from explicit path '$resolved_installer_path'; use --installer-type"
    fi
  else
    if ! validate_path_matches_type "$resolved_installer_path" "$installer_type"; then
      fail "resolve" "explicit installer path does not match --installer-type '$installer_type': $resolved_installer_path"
    fi
    resolved_installer_type="$installer_type"
  fi
else
  if ! resolve_from_discovery; then
    maybe_build_missing_artifacts
    if ! resolve_from_discovery; then
      fail "discover" "no installer artifact found under $BUNDLE_ROOT (type=$installer_type)"
    fi
    if [[ "$build_triggered" == "1" ]]; then
      installer_source="discovered_after_build"
    fi
  fi
  resolved_installer_path="$(resolve_absolute_path "$resolved_installer_path")"
fi

log "mode=scaffold-non-production"
log "channel=$channel"
log "installer_type=$resolved_installer_type"
log "installer_path=$resolved_installer_path"
log "installer_source=$installer_source"
log "launch_after_install=$launch_after_install"
if [[ -n "$resolved_installed_executable" ]]; then
  log "installed_executable=$resolved_installed_executable"
fi
log "build_if_missing=$build_if_missing build_triggered=$build_triggered dry_run=$dry_run"

if ! execute_installer; then
  fail "install" "installer command failed"
fi

failure_stage=""
finish 0
