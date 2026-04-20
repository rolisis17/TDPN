#!/usr/bin/env bash
set -euo pipefail

show_usage() {
  cat <<'USAGE'
GPM Linux desktop doctor scaffold (non-production helper)

Usage:
  ./scripts/linux/desktop_doctor.sh [--mode check|fix] [--install-missing] [--dry-run] [--summary-json PATH] [--print-summary-json 0|1] [--help]
  ./scripts/linux/desktop_doctor.sh check [--dry-run] [--summary-json PATH]
  ./scripts/linux/desktop_doctor.sh fix [--install-missing] [--dry-run] [--summary-json PATH]

Modes:
  check  Report prerequisite tool/native dependency availability (scaffold, non-production).
  fix    Optionally attempt package-manager remediation (apt-get/dnf/pacman/zypper) for missing tools/native dependencies when --install-missing is provided.

Flags:
  --mode check|fix         Explicit mode selector.
  --install-missing        In fix mode, attempt package-manager install for missing dependencies when a supported manager exists.
  --dry-run                Print intended remediation actions without executing package-manager commands.
  --summary-json PATH      Write a summary JSON object to PATH.
  --print-summary-json 0|1 Print summary JSON to stdout (default: 0).
  --help                   Show this help text.
USAGE
}

log() {
  echo "[desktop-doctor-linux] $*"
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

add_unique() {
  local value="$1"
  shift
  local existing
  for existing in "$@"; do
    if [[ "$existing" == "$value" ]]; then
      return 1
    fi
  done
  return 0
}

tool_is_missing() {
  local needle="$1"
  local item
  for item in "${MISSING_TOOLS[@]}"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

native_dep_is_missing() {
  local needle="$1"
  local item
  for item in "${MISSING_NATIVE_DEPS[@]}"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

native_dep_label() {
  local key="$1"
  case "$key" in
    pkg_config)
      printf '%s' "pkg-config"
      ;;
    gtk3)
      printf '%s' "gtk+-3.0 (GTK3 dev files)"
      ;;
    webkit2gtk)
      printf '%s' "webkit2gtk-4.1/4.0 (WebKit2GTK dev files)"
      ;;
    libsoup3)
      printf '%s' "libsoup-3.0 (libsoup3 dev files)"
      ;;
    javascriptcoregtk)
      printf '%s' "javascriptcoregtk-4.1/4.0 (javascriptcoregtk dev files)"
      ;;
    *)
      printf '%s' "$key"
      ;;
  esac
}

pkg_config_module_exists() {
  local module_name="$1"
  pkg-config --exists "$module_name" >/dev/null 2>&1
}

collect_tool_report() {
  MISSING_TOOLS=()
  local tool
  for tool in "${TOOLS[@]}"; do
    local path=""
    if path="$(command -v "$tool" 2>/dev/null)"; then
      TOOL_PATHS["$tool"]="$path"
    else
      TOOL_PATHS["$tool"]=""
      MISSING_TOOLS+=("$tool")
    fi
  done
}

collect_native_dependency_report() {
  MISSING_NATIVE_DEPS=()

  local key
  for key in "${NATIVE_DEPENDENCY_KEYS[@]}"; do
    NATIVE_DEP_FOUND["$key"]="0"
    NATIVE_DEP_DETAIL["$key"]=""
  done

  local pkg_config_path=""
  if pkg_config_path="$(command -v pkg-config 2>/dev/null)"; then
    NATIVE_DEP_FOUND["pkg_config"]="1"
    NATIVE_DEP_DETAIL["pkg_config"]="$pkg_config_path"
  else
    NATIVE_DEP_DETAIL["pkg_config"]="pkg-config command not found on PATH"
    MISSING_NATIVE_DEPS+=("pkg_config")
  fi

  if [[ "${NATIVE_DEP_FOUND["pkg_config"]}" != "1" ]]; then
    NATIVE_DEP_DETAIL["gtk3"]="cannot validate gtk+-3.0 without pkg-config"
    NATIVE_DEP_DETAIL["webkit2gtk"]="cannot validate webkit2gtk-4.1/4.0 without pkg-config"
    NATIVE_DEP_DETAIL["libsoup3"]="cannot validate libsoup-3.0 without pkg-config"
    NATIVE_DEP_DETAIL["javascriptcoregtk"]="cannot validate javascriptcoregtk-4.1/4.0 without pkg-config"
    MISSING_NATIVE_DEPS+=("gtk3" "webkit2gtk" "libsoup3" "javascriptcoregtk")
    return 0
  fi

  if pkg_config_module_exists "gtk+-3.0"; then
    NATIVE_DEP_FOUND["gtk3"]="1"
    NATIVE_DEP_DETAIL["gtk3"]="gtk+-3.0"
  else
    NATIVE_DEP_DETAIL["gtk3"]="missing pkg-config module gtk+-3.0"
    MISSING_NATIVE_DEPS+=("gtk3")
  fi

  local webkit_module=""
  if pkg_config_module_exists "webkit2gtk-4.1"; then
    webkit_module="webkit2gtk-4.1"
  elif pkg_config_module_exists "webkit2gtk-4.0"; then
    webkit_module="webkit2gtk-4.0"
  fi
  if [[ -n "$webkit_module" ]]; then
    NATIVE_DEP_FOUND["webkit2gtk"]="1"
    NATIVE_DEP_DETAIL["webkit2gtk"]="$webkit_module"
  else
    NATIVE_DEP_DETAIL["webkit2gtk"]="missing pkg-config module webkit2gtk-4.1 or webkit2gtk-4.0"
    MISSING_NATIVE_DEPS+=("webkit2gtk")
  fi

  if pkg_config_module_exists "libsoup-3.0"; then
    NATIVE_DEP_FOUND["libsoup3"]="1"
    NATIVE_DEP_DETAIL["libsoup3"]="libsoup-3.0"
  else
    NATIVE_DEP_DETAIL["libsoup3"]="missing pkg-config module libsoup-3.0"
    MISSING_NATIVE_DEPS+=("libsoup3")
  fi

  local javascriptcore_module=""
  if pkg_config_module_exists "javascriptcoregtk-4.1"; then
    javascriptcore_module="javascriptcoregtk-4.1"
  elif pkg_config_module_exists "javascriptcoregtk-4.0"; then
    javascriptcore_module="javascriptcoregtk-4.0"
  fi
  if [[ -n "$javascriptcore_module" ]]; then
    NATIVE_DEP_FOUND["javascriptcoregtk"]="1"
    NATIVE_DEP_DETAIL["javascriptcoregtk"]="$javascriptcore_module"
  else
    NATIVE_DEP_DETAIL["javascriptcoregtk"]="missing pkg-config module javascriptcoregtk-4.1 or javascriptcoregtk-4.0"
    MISSING_NATIVE_DEPS+=("javascriptcoregtk")
  fi
}

build_apt_packages() {
  APT_PACKAGES=()

  if tool_is_missing "go"; then
    APT_PACKAGES+=("golang-go")
  fi

  if tool_is_missing "node" || tool_is_missing "npm"; then
    if add_unique "nodejs" "${APT_PACKAGES[@]}"; then
      APT_PACKAGES+=("nodejs")
    fi
    if add_unique "npm" "${APT_PACKAGES[@]}"; then
      APT_PACKAGES+=("npm")
    fi
  fi

  if tool_is_missing "rustc" || tool_is_missing "cargo"; then
    if add_unique "rustc" "${APT_PACKAGES[@]}"; then
      APT_PACKAGES+=("rustc")
    fi
    if add_unique "cargo" "${APT_PACKAGES[@]}"; then
      APT_PACKAGES+=("cargo")
    fi
  fi

  if tool_is_missing "git"; then
    if add_unique "git" "${APT_PACKAGES[@]}"; then
      APT_PACKAGES+=("git")
    fi
  fi

  if tool_is_missing "bash"; then
    if add_unique "bash" "${APT_PACKAGES[@]}"; then
      APT_PACKAGES+=("bash")
    fi
  fi

  if native_dep_is_missing "pkg_config"; then
    if add_unique "pkg-config" "${APT_PACKAGES[@]}"; then
      APT_PACKAGES+=("pkg-config")
    fi
  fi

  if native_dep_is_missing "gtk3"; then
    if add_unique "libgtk-3-dev" "${APT_PACKAGES[@]}"; then
      APT_PACKAGES+=("libgtk-3-dev")
    fi
  fi

  if native_dep_is_missing "webkit2gtk"; then
    if add_unique "libwebkit2gtk-4.1-dev" "${APT_PACKAGES[@]}"; then
      APT_PACKAGES+=("libwebkit2gtk-4.1-dev")
    fi
  fi

  if native_dep_is_missing "libsoup3"; then
    if add_unique "libsoup-3.0-dev" "${APT_PACKAGES[@]}"; then
      APT_PACKAGES+=("libsoup-3.0-dev")
    fi
  fi

  if native_dep_is_missing "javascriptcoregtk"; then
    if add_unique "libjavascriptcoregtk-4.1-dev" "${APT_PACKAGES[@]}"; then
      APT_PACKAGES+=("libjavascriptcoregtk-4.1-dev")
    fi
  fi
}

build_dnf_packages() {
  DNF_PACKAGES=()

  if tool_is_missing "go"; then
    DNF_PACKAGES+=("golang")
  fi
  if tool_is_missing "node" || tool_is_missing "npm"; then
    if add_unique "nodejs" "${DNF_PACKAGES[@]}"; then
      DNF_PACKAGES+=("nodejs")
    fi
    if add_unique "npm" "${DNF_PACKAGES[@]}"; then
      DNF_PACKAGES+=("npm")
    fi
  fi
  if tool_is_missing "rustc" || tool_is_missing "cargo"; then
    if add_unique "rust" "${DNF_PACKAGES[@]}"; then
      DNF_PACKAGES+=("rust")
    fi
    if add_unique "cargo" "${DNF_PACKAGES[@]}"; then
      DNF_PACKAGES+=("cargo")
    fi
  fi
  if tool_is_missing "git"; then
    if add_unique "git" "${DNF_PACKAGES[@]}"; then
      DNF_PACKAGES+=("git")
    fi
  fi
  if tool_is_missing "bash"; then
    if add_unique "bash" "${DNF_PACKAGES[@]}"; then
      DNF_PACKAGES+=("bash")
    fi
  fi
  if native_dep_is_missing "pkg_config"; then
    if add_unique "pkgconf-pkg-config" "${DNF_PACKAGES[@]}"; then
      DNF_PACKAGES+=("pkgconf-pkg-config")
    fi
  fi
  if native_dep_is_missing "gtk3"; then
    if add_unique "gtk3-devel" "${DNF_PACKAGES[@]}"; then
      DNF_PACKAGES+=("gtk3-devel")
    fi
  fi
  if native_dep_is_missing "webkit2gtk"; then
    if add_unique "webkit2gtk4.1-devel" "${DNF_PACKAGES[@]}"; then
      DNF_PACKAGES+=("webkit2gtk4.1-devel")
    fi
  fi
  if native_dep_is_missing "libsoup3"; then
    if add_unique "libsoup3-devel" "${DNF_PACKAGES[@]}"; then
      DNF_PACKAGES+=("libsoup3-devel")
    fi
  fi
  if native_dep_is_missing "javascriptcoregtk"; then
    if add_unique "javascriptcoregtk4.1-devel" "${DNF_PACKAGES[@]}"; then
      DNF_PACKAGES+=("javascriptcoregtk4.1-devel")
    fi
  fi
}

build_pacman_packages() {
  PACMAN_PACKAGES=()

  if tool_is_missing "go"; then
    PACMAN_PACKAGES+=("go")
  fi
  if tool_is_missing "node" || tool_is_missing "npm"; then
    if add_unique "nodejs" "${PACMAN_PACKAGES[@]}"; then
      PACMAN_PACKAGES+=("nodejs")
    fi
    if add_unique "npm" "${PACMAN_PACKAGES[@]}"; then
      PACMAN_PACKAGES+=("npm")
    fi
  fi
  if tool_is_missing "rustc" || tool_is_missing "cargo"; then
    if add_unique "rust" "${PACMAN_PACKAGES[@]}"; then
      PACMAN_PACKAGES+=("rust")
    fi
  fi
  if tool_is_missing "git"; then
    if add_unique "git" "${PACMAN_PACKAGES[@]}"; then
      PACMAN_PACKAGES+=("git")
    fi
  fi
  if tool_is_missing "bash"; then
    if add_unique "bash" "${PACMAN_PACKAGES[@]}"; then
      PACMAN_PACKAGES+=("bash")
    fi
  fi
  if native_dep_is_missing "pkg_config"; then
    if add_unique "pkgconf" "${PACMAN_PACKAGES[@]}"; then
      PACMAN_PACKAGES+=("pkgconf")
    fi
  fi
  if native_dep_is_missing "gtk3"; then
    if add_unique "gtk3" "${PACMAN_PACKAGES[@]}"; then
      PACMAN_PACKAGES+=("gtk3")
    fi
  fi
  if native_dep_is_missing "webkit2gtk"; then
    if add_unique "webkit2gtk-4.1" "${PACMAN_PACKAGES[@]}"; then
      PACMAN_PACKAGES+=("webkit2gtk-4.1")
    fi
  fi
  if native_dep_is_missing "libsoup3"; then
    if add_unique "libsoup3" "${PACMAN_PACKAGES[@]}"; then
      PACMAN_PACKAGES+=("libsoup3")
    fi
  fi
  if native_dep_is_missing "javascriptcoregtk"; then
    if add_unique "webkit2gtk-4.1" "${PACMAN_PACKAGES[@]}"; then
      PACMAN_PACKAGES+=("webkit2gtk-4.1")
    fi
  fi
}

build_zypper_packages() {
  ZYPPER_PACKAGES=()

  if tool_is_missing "go"; then
    ZYPPER_PACKAGES+=("go")
  fi
  if tool_is_missing "node" || tool_is_missing "npm"; then
    if add_unique "nodejs20" "${ZYPPER_PACKAGES[@]}"; then
      ZYPPER_PACKAGES+=("nodejs20")
    fi
    if add_unique "npm20" "${ZYPPER_PACKAGES[@]}"; then
      ZYPPER_PACKAGES+=("npm20")
    fi
  fi
  if tool_is_missing "rustc" || tool_is_missing "cargo"; then
    if add_unique "rust" "${ZYPPER_PACKAGES[@]}"; then
      ZYPPER_PACKAGES+=("rust")
    fi
    if add_unique "cargo" "${ZYPPER_PACKAGES[@]}"; then
      ZYPPER_PACKAGES+=("cargo")
    fi
  fi
  if tool_is_missing "git"; then
    if add_unique "git" "${ZYPPER_PACKAGES[@]}"; then
      ZYPPER_PACKAGES+=("git")
    fi
  fi
  if tool_is_missing "bash"; then
    if add_unique "bash" "${ZYPPER_PACKAGES[@]}"; then
      ZYPPER_PACKAGES+=("bash")
    fi
  fi
  if native_dep_is_missing "pkg_config"; then
    if add_unique "pkgconf-pkg-config" "${ZYPPER_PACKAGES[@]}"; then
      ZYPPER_PACKAGES+=("pkgconf-pkg-config")
    fi
  fi
  if native_dep_is_missing "gtk3"; then
    if add_unique "gtk3-devel" "${ZYPPER_PACKAGES[@]}"; then
      ZYPPER_PACKAGES+=("gtk3-devel")
    fi
  fi
  if native_dep_is_missing "webkit2gtk"; then
    if add_unique "webkit2gtk3-devel" "${ZYPPER_PACKAGES[@]}"; then
      ZYPPER_PACKAGES+=("webkit2gtk3-devel")
    fi
  fi
  if native_dep_is_missing "libsoup3"; then
    if add_unique "libsoup-3_0-devel" "${ZYPPER_PACKAGES[@]}"; then
      ZYPPER_PACKAGES+=("libsoup-3_0-devel")
    fi
  fi
  if native_dep_is_missing "javascriptcoregtk"; then
    if add_unique "javascriptcoregtk-4_1-devel" "${ZYPPER_PACKAGES[@]}"; then
      ZYPPER_PACKAGES+=("javascriptcoregtk-4_1-devel")
    fi
  fi
}

select_package_manager() {
  package_manager_selected=""
  if [[ "$apt_get_available" == "1" ]]; then
    package_manager_selected="apt-get"
  elif [[ "$dnf_available" == "1" ]]; then
    package_manager_selected="dnf"
  elif [[ "$pacman_available" == "1" ]]; then
    package_manager_selected="pacman"
  elif [[ "$zypper_available" == "1" ]]; then
    package_manager_selected="zypper"
  fi
}

build_selected_remediation_packages() {
  REMEDIATION_PACKAGES=()
  case "$package_manager_selected" in
    apt-get)
      REMEDIATION_PACKAGES=("${APT_PACKAGES[@]}")
      ;;
    dnf)
      build_dnf_packages
      REMEDIATION_PACKAGES=("${DNF_PACKAGES[@]}")
      ;;
    pacman)
      build_pacman_packages
      REMEDIATION_PACKAGES=("${PACMAN_PACKAGES[@]}")
      ;;
    zypper)
      build_zypper_packages
      REMEDIATION_PACKAGES=("${ZYPPER_PACKAGES[@]}")
      ;;
    *)
      REMEDIATION_PACKAGES=()
      ;;
  esac
}

build_recommended_commands() {
  RECOMMENDED_COMMANDS=()

  local apt_prefix=""
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    apt_prefix="sudo "
  fi

  if [[ "${#APT_PACKAGES[@]}" -gt 0 ]]; then
    if [[ "$apt_get_available" == "1" ]]; then
      RECOMMENDED_COMMANDS+=("${apt_prefix}apt-get update")
      RECOMMENDED_COMMANDS+=("${apt_prefix}apt-get install -y ${APT_PACKAGES[*]}")
    elif [[ "$dnf_available" == "1" ]]; then
      build_dnf_packages
      if [[ "${#DNF_PACKAGES[@]}" -gt 0 ]]; then
        RECOMMENDED_COMMANDS+=("${apt_prefix}dnf install -y ${DNF_PACKAGES[*]}")
      fi
    elif [[ "$pacman_available" == "1" ]]; then
      build_pacman_packages
      if [[ "${#PACMAN_PACKAGES[@]}" -gt 0 ]]; then
        RECOMMENDED_COMMANDS+=("${apt_prefix}pacman -Sy --needed ${PACMAN_PACKAGES[*]}")
      fi
    elif [[ "$zypper_available" == "1" ]]; then
      build_zypper_packages
      if [[ "${#ZYPPER_PACKAGES[@]}" -gt 0 ]]; then
        RECOMMENDED_COMMANDS+=("${apt_prefix}zypper install -y ${ZYPPER_PACKAGES[*]}")
      fi
    else
      RECOMMENDED_COMMANDS+=("install missing prerequisites with your distro package manager: ${APT_PACKAGES[*]}")
    fi
  fi

  RECOMMENDED_COMMANDS+=("./scripts/linux/desktop_doctor.sh --mode fix --install-missing")
  RECOMMENDED_COMMANDS+=("./scripts/linux/desktop_one_click.sh")
}

mode="check"
install_missing="0"
dry_run="0"
summary_json_path=""
print_summary_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    check|fix)
      mode="$1"
      shift
      ;;
    --mode)
      if [[ $# -lt 2 ]]; then
        echo "--mode requires a value: check|fix" >&2
        exit 2
      fi
      mode="$2"
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
    --summary-json)
      if [[ $# -lt 2 ]]; then
        echo "--summary-json requires a path" >&2
        exit 2
      fi
      summary_json_path="$2"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -lt 2 ]]; then
        echo "--print-summary-json requires 0 or 1" >&2
        exit 2
      fi
      print_summary_json="$2"
      shift 2
      ;;
    -h|--help)
      show_usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      show_usage >&2
      exit 2
      ;;
  esac
done

case "$mode" in
  check|fix) ;;
  *)
    echo "unsupported mode: $mode (expected check|fix)" >&2
    show_usage >&2
    exit 2
    ;;
esac

case "$print_summary_json" in
  0|1) ;;
  *)
    echo "invalid --print-summary-json value: $print_summary_json (expected 0|1)" >&2
    exit 2
    ;;
esac

TOOLS=(go node npm rustc cargo git bash)
declare -A TOOL_PATHS=()
MISSING_TOOLS=()
NATIVE_DEPENDENCY_KEYS=(pkg_config gtk3 webkit2gtk libsoup3 javascriptcoregtk)
declare -A NATIVE_DEP_FOUND=()
declare -A NATIVE_DEP_DETAIL=()
MISSING_NATIVE_DEPS=()
APT_PACKAGES=()
DNF_PACKAGES=()
PACMAN_PACKAGES=()
ZYPPER_PACKAGES=()
RECOMMENDED_COMMANDS=()
REMEDIATION_PACKAGES=()

install_attempted="0"
install_completed="0"
install_skipped_reason=""
apt_get_available="0"
dnf_available="0"
pacman_available="0"
zypper_available="0"
package_manager_selected=""
error_message=""
exit_code="0"

if command -v apt-get >/dev/null 2>&1; then
  apt_get_available="1"
fi
if command -v dnf >/dev/null 2>&1; then
  dnf_available="1"
fi
if command -v pacman >/dev/null 2>&1; then
  pacman_available="1"
fi
if command -v zypper >/dev/null 2>&1; then
  zypper_available="1"
fi

log "mode=$mode"
log "scaffold-only, non-production remediation helper for Linux desktop prerequisites"

collect_tool_report
collect_native_dependency_report
build_apt_packages
select_package_manager
build_selected_remediation_packages
build_recommended_commands

log "tool report:"
for tool in "${TOOLS[@]}"; do
  if [[ -n "${TOOL_PATHS[$tool]}" ]]; then
    echo "  - $tool: ${TOOL_PATHS[$tool]}"
  else
    echo "  - $tool: missing"
  fi
done

if [[ "${#MISSING_TOOLS[@]}" -eq 0 ]]; then
  log "all prerequisite tools detected"
else
  log "missing tools: ${MISSING_TOOLS[*]}"
  if [[ "${#APT_PACKAGES[@]}" -gt 0 ]]; then
    log "apt remediation package hints: ${APT_PACKAGES[*]}"
  fi
fi

log "native desktop dependency report:"
for key in "${NATIVE_DEPENDENCY_KEYS[@]}"; do
  if [[ "${NATIVE_DEP_FOUND[$key]}" == "1" ]]; then
    echo "  - $(native_dep_label "$key"): ${NATIVE_DEP_DETAIL[$key]}"
  else
    echo "  - $(native_dep_label "$key"): missing (${NATIVE_DEP_DETAIL[$key]})"
  fi
done

if [[ "${#MISSING_NATIVE_DEPS[@]}" -eq 0 ]]; then
  log "all native Linux desktop prerequisites detected"
else
  log "missing native Linux desktop prerequisites: ${MISSING_NATIVE_DEPS[*]}"
  if [[ "${#APT_PACKAGES[@]}" -gt 0 ]]; then
    log "native remediation package hints are included in recommended commands and apt package hints"
  fi
fi

if [[ "$mode" == "fix" && "$install_missing" == "1" ]]; then
  log "fix mode: selected package manager: ${package_manager_selected:-none}"

  if [[ -z "$package_manager_selected" ]]; then
    install_skipped_reason="no supported package manager available (apt-get/dnf/pacman/zypper)"
    log "fix mode: automatic remediation skipped; no supported package manager detected"
  elif [[ "${#REMEDIATION_PACKAGES[@]}" -eq 0 ]]; then
    install_skipped_reason="nothing to install"
    log "fix mode: no remediation needed for $package_manager_selected"
  else
    install_attempted="1"

    run_prefix=()
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
      run_prefix=()
    elif command -v sudo >/dev/null 2>&1; then
      run_prefix=("sudo")
    else
      install_skipped_reason="requires root or sudo for $package_manager_selected install"
      log "fix mode: remediation requires root privileges or sudo"
      run_prefix=()
    fi

    if [[ -z "$install_skipped_reason" ]]; then
      if [[ "$dry_run" == "1" ]]; then
        case "$package_manager_selected" in
          apt-get)
            log "dry-run: ${run_prefix[*]:+${run_prefix[*]} }apt-get update"
            log "dry-run: ${run_prefix[*]:+${run_prefix[*]} }apt-get install -y ${REMEDIATION_PACKAGES[*]}"
            ;;
          dnf)
            log "dry-run: ${run_prefix[*]:+${run_prefix[*]} }dnf install -y ${REMEDIATION_PACKAGES[*]}"
            ;;
          pacman)
            log "dry-run: ${run_prefix[*]:+${run_prefix[*]} }pacman -Sy --needed ${REMEDIATION_PACKAGES[*]}"
            ;;
          zypper)
            log "dry-run: ${run_prefix[*]:+${run_prefix[*]} }zypper install -y ${REMEDIATION_PACKAGES[*]}"
            ;;
        esac
        log "dry-run: no package-manager commands executed (preview only)"
      else
        case "$package_manager_selected" in
          apt-get)
            log "running remediation (scaffold flow): apt-get update"
            if "${run_prefix[@]}" apt-get update; then
              log "running remediation (scaffold flow): apt-get install -y ${REMEDIATION_PACKAGES[*]}"
              if "${run_prefix[@]}" apt-get install -y "${REMEDIATION_PACKAGES[@]}"; then
                install_completed="1"
                log "apt-get remediation completed"
              else
                error_message="apt-get install failed during remediation"
                exit_code="1"
              fi
            else
              error_message="apt-get update failed during remediation"
              exit_code="1"
            fi
            ;;
          dnf)
            log "running remediation (scaffold flow): dnf install -y ${REMEDIATION_PACKAGES[*]}"
            if "${run_prefix[@]}" dnf install -y "${REMEDIATION_PACKAGES[@]}"; then
              install_completed="1"
              log "dnf remediation completed"
            else
              error_message="dnf install failed during remediation"
              exit_code="1"
            fi
            ;;
          pacman)
            log "running remediation (scaffold flow): pacman -Sy --needed --noconfirm ${REMEDIATION_PACKAGES[*]}"
            if "${run_prefix[@]}" pacman -Sy --needed --noconfirm "${REMEDIATION_PACKAGES[@]}"; then
              install_completed="1"
              log "pacman remediation completed"
            else
              error_message="pacman install failed during remediation"
              exit_code="1"
            fi
            ;;
          zypper)
            log "running remediation (scaffold flow): zypper install -y --non-interactive ${REMEDIATION_PACKAGES[*]}"
            if "${run_prefix[@]}" zypper install -y --non-interactive "${REMEDIATION_PACKAGES[@]}"; then
              install_completed="1"
              log "zypper remediation completed"
            else
              error_message="zypper install failed during remediation"
              exit_code="1"
            fi
            ;;
          *)
            error_message="unsupported package manager selected for remediation"
            exit_code="1"
            ;;
        esac

        if [[ "$install_completed" == "1" ]]; then
          collect_tool_report
          collect_native_dependency_report
          build_apt_packages
          build_selected_remediation_packages
          build_recommended_commands
        fi
      fi
    fi
  fi
elif [[ "$mode" == "fix" ]]; then
  install_skipped_reason="--install-missing not provided"
  log "fix mode selected without --install-missing; remediation skipped"
fi

status="unknown"
if [[ "$exit_code" != "0" ]]; then
  status="error"
elif [[ "${#MISSING_TOOLS[@]}" -eq 0 && "${#MISSING_NATIVE_DEPS[@]}" -eq 0 ]]; then
  if [[ "$mode" == "fix" && "$install_attempted" == "1" ]]; then
    status="fixed"
  else
    status="ok"
  fi
else
  if [[ "$mode" == "fix" && "$install_missing" == "1" && "$dry_run" == "1" && "$install_attempted" == "1" ]]; then
    status="dry-run"
  else
    status="missing"
  fi
fi

generated_at_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

tool_report_json="{"
first_tool="1"
for tool in "${TOOLS[@]}"; do
  if [[ "$first_tool" == "0" ]]; then
    tool_report_json+=","
  fi
  first_tool="0"
  found="0"
  if [[ -n "${TOOL_PATHS[$tool]}" ]]; then
    found="1"
  fi
  tool_report_json+=$'\n'"    \"${tool}\": {\"found\": $(json_bool "$found"), \"path\": \"$(json_escape "${TOOL_PATHS[$tool]}")\"}"
done
tool_report_json+=$'\n'"  }"

native_dependency_report_json="{"
first_native_dep="1"
for key in "${NATIVE_DEPENDENCY_KEYS[@]}"; do
  if [[ "$first_native_dep" == "0" ]]; then
    native_dependency_report_json+=","
  fi
  first_native_dep="0"
  native_dependency_report_json+=$'\n'"    \"${key}\": {\"found\": $(json_bool "${NATIVE_DEP_FOUND[$key]}"), \"detail\": \"$(json_escape "${NATIVE_DEP_DETAIL[$key]}")\"}"
done
native_dependency_report_json+=$'\n'"  }"

missing_tools_json="$(json_array_from_values "${MISSING_TOOLS[@]}")"
missing_native_dependencies_json="$(json_array_from_values "${MISSING_NATIVE_DEPS[@]}")"
apt_packages_json="$(json_array_from_values "${APT_PACKAGES[@]}")"
remediation_packages_json="$(json_array_from_values "${REMEDIATION_PACKAGES[@]}")"
recommended_commands_json="$(json_array_from_values "${RECOMMENDED_COMMANDS[@]}")"

summary_json_payload=$(
  cat <<EOF
{
  "version": 1,
  "generated_at_utc": "$(json_escape "$generated_at_utc")",
  "status": "$(json_escape "$status")",
  "mode": "$(json_escape "$mode")",
  "dry_run": $(json_bool "$dry_run"),
  "install_missing": $(json_bool "$install_missing"),
  "apt_get_available": $(json_bool "$apt_get_available"),
  "install_attempted": $(json_bool "$install_attempted"),
  "install_completed": $(json_bool "$install_completed"),
  "install_skipped_reason": "$(json_escape "$install_skipped_reason")",
  "package_manager_selected": "$(json_escape "$package_manager_selected")",
  "error": "$(json_escape "$error_message")",
  "notes": "Linux desktop doctor is scaffold-only and non-production.",
  "missing_tools": $missing_tools_json,
  "missing_native_dependencies": $missing_native_dependencies_json,
  "apt_packages": $apt_packages_json,
  "remediation_packages": $remediation_packages_json,
  "recommended_commands": $recommended_commands_json,
  "tool_report": $tool_report_json,
  "native_dependency_report": $native_dependency_report_json
}
EOF
)

if [[ -n "$summary_json_path" ]]; then
  write_summary_json_file "$summary_json_path" "$summary_json_payload"
fi

if [[ "$print_summary_json" == "1" ]]; then
  printf '%s\n' "$summary_json_payload"
fi

log "status=$status"
log "recommended remediation commands:"
for cmd in "${RECOMMENDED_COMMANDS[@]}"; do
  echo "  - $cmd"
done
log "next step: run Linux desktop bootstrap/packaged flow after prerequisites are ready"

exit "$exit_code"
