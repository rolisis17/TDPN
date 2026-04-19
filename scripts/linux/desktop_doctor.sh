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
  check  Report prerequisite tool availability (scaffold, non-production).
  fix    Optionally attempt apt-based remediation for missing tools when --install-missing is provided.

Flags:
  --mode check|fix         Explicit mode selector.
  --install-missing        In fix mode, attempt apt-get install for missing dependencies when apt-get exists.
  --dry-run                Print intended remediation actions without executing apt commands.
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
}

build_recommended_commands() {
  RECOMMENDED_COMMANDS=()

  local apt_prefix=""
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    apt_prefix="sudo "
  fi

  if [[ "${#APT_PACKAGES[@]}" -gt 0 ]]; then
    RECOMMENDED_COMMANDS+=("${apt_prefix}apt-get update")
    RECOMMENDED_COMMANDS+=("${apt_prefix}apt-get install -y ${APT_PACKAGES[*]}")
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
APT_PACKAGES=()
RECOMMENDED_COMMANDS=()

install_attempted="0"
install_completed="0"
install_skipped_reason=""
apt_get_available="0"
error_message=""
exit_code="0"

if command -v apt-get >/dev/null 2>&1; then
  apt_get_available="1"
fi

log "mode=$mode"
log "scaffold-only, non-production remediation helper for Linux desktop prerequisites"

collect_tool_report
build_apt_packages
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

if [[ "$mode" == "fix" && "$install_missing" == "1" ]]; then
  if [[ "${#APT_PACKAGES[@]}" -eq 0 ]]; then
    install_skipped_reason="nothing to install"
    log "fix mode: no apt remediation needed"
  elif [[ "$apt_get_available" != "1" ]]; then
    install_skipped_reason="apt-get not available"
    log "fix mode: apt-get not detected; automatic remediation skipped"
  else
    install_attempted="1"

    run_prefix=()
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
      run_prefix=()
    elif command -v sudo >/dev/null 2>&1; then
      run_prefix=("sudo")
    else
      install_skipped_reason="requires root or sudo for apt-get install"
      log "fix mode: remediation requires root privileges or sudo"
      run_prefix=()
    fi

    if [[ -z "$install_skipped_reason" ]]; then
      if [[ "$dry_run" == "1" ]]; then
        log "dry-run: ${run_prefix[*]:+${run_prefix[*]} }apt-get update"
        log "dry-run: ${run_prefix[*]:+${run_prefix[*]} }apt-get install -y ${APT_PACKAGES[*]}"
      else
        log "running apt remediation (scaffold flow): apt-get update"
        if "${run_prefix[@]}" apt-get update; then
          log "running apt remediation (scaffold flow): apt-get install -y ${APT_PACKAGES[*]}"
          if "${run_prefix[@]}" apt-get install -y "${APT_PACKAGES[@]}"; then
            install_completed="1"
            log "apt remediation completed"
            collect_tool_report
            build_apt_packages
            build_recommended_commands
          else
            error_message="apt-get install failed during remediation"
            exit_code="1"
          fi
        else
          error_message="apt-get update failed during remediation"
          exit_code="1"
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
elif [[ "${#MISSING_TOOLS[@]}" -eq 0 ]]; then
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

missing_tools_json="$(json_array_from_values "${MISSING_TOOLS[@]}")"
apt_packages_json="$(json_array_from_values "${APT_PACKAGES[@]}")"
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
  "error": "$(json_escape "$error_message")",
  "notes": "Linux desktop doctor is scaffold-only and non-production.",
  "missing_tools": $missing_tools_json,
  "apt_packages": $apt_packages_json,
  "recommended_commands": $recommended_commands_json,
  "tool_report": $tool_report_json
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
