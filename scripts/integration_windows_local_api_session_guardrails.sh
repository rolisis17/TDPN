#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in grep mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

LOCAL_API_SESSION_PS1="${WINDOWS_LOCAL_API_SESSION_PS1_UNDER_TEST:-$ROOT_DIR/scripts/windows/local_api_session.ps1}"
LOCAL_API_SESSION_CMD="${WINDOWS_LOCAL_API_SESSION_CMD_UNDER_TEST:-$ROOT_DIR/scripts/windows/local_api_session.cmd}"

if [[ ! -f "$LOCAL_API_SESSION_PS1" ]]; then
  echo "windows local api session guardrails failed: missing script: $LOCAL_API_SESSION_PS1"
  exit 1
fi
if [[ ! -f "$LOCAL_API_SESSION_CMD" ]]; then
  echo "windows local api session guardrails failed: missing script: $LOCAL_API_SESSION_CMD"
  exit 1
fi

assert_marker_present() {
  local marker="$1"
  local file_path="$2"
  if ! grep -Fq -- "$marker" "$file_path"; then
    echo "windows local api session guardrails failed: missing marker '$marker' in $file_path"
    exit 1
  fi
}

strip_crlf() {
  local value="$1"
  value="${value//$'\r'/}"
  value="${value//$'\n'/}"
  printf '%s' "$value"
}

extract_banner_field() {
  local log_path="$1"
  local field_name="$2"
  local line
  line="$(grep -F "  $field_name:" "$log_path" | head -n 1 || true)"
  line="$(strip_crlf "$line")"
  if [[ -z "$line" ]]; then
    printf '%s' ""
    return
  fi
  printf '%s' "${line#*${field_name}: }"
}

echo "[windows-local-api-session-guardrails] marker checks: cmd wrapper policy + guardrails"
assert_marker_present "-ExecutionPolicy Bypass" "$LOCAL_API_SESSION_CMD"
assert_marker_present "Unsupported cmd metacharacters" "$LOCAL_API_SESSION_CMD"
assert_marker_present "-File \"%PS1%\"" "$LOCAL_API_SESSION_CMD"

echo "[windows-local-api-session-guardrails] marker checks: powershell script go/runtime guidance"
assert_marker_present "function Resolve-GoExecutable" "$LOCAL_API_SESSION_PS1"
assert_marker_present '[switch]$InstallMissing' "$LOCAL_API_SESSION_PS1"
assert_marker_present "winget install --id GoLang.Go --exact" "$LOCAL_API_SESSION_PS1"
assert_marker_present "Invoke-WingetInstallGo" "$LOCAL_API_SESSION_PS1"
assert_marker_present "Refresh-ProcessPath" "$LOCAL_API_SESSION_PS1"
assert_marker_present '$goArgs = @("run", "./cmd/node")' "$LOCAL_API_SESSION_PS1"
assert_marker_present '$goArgs += @("--local-api")' "$LOCAL_API_SESSION_PS1"
assert_marker_present 'Write-Host "  command: go ' "$LOCAL_API_SESSION_PS1"
assert_marker_present 'Write-Host "  install_missing: $installMissingEnabled"' "$LOCAL_API_SESSION_PS1"

if command -v powershell >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell"
elif command -v pwsh >/dev/null 2>&1; then
  POWERSHELL_BIN="pwsh"
elif command -v powershell.exe >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell.exe"
else
  echo "windows local api session guardrails failed: missing powershell/pwsh/powershell.exe for runtime checks"
  exit 2
fi

POWERSHELL_USES_WINDOWS_PATHS="0"
if [[ "$POWERSHELL_BIN" == *.exe ]]; then
  POWERSHELL_USES_WINDOWS_PATHS="1"
else
  POWERSHELL_IS_WINDOWS_OUTPUT="$("$POWERSHELL_BIN" -NoProfile -Command "if ((\$env:OS -eq 'Windows_NT') -or (\$IsWindows -eq \$true)) { '1' } else { '0' }" 2>/dev/null || true)"
  POWERSHELL_IS_WINDOWS_OUTPUT="${POWERSHELL_IS_WINDOWS_OUTPUT//$'\r'/}"
  POWERSHELL_IS_WINDOWS_OUTPUT="${POWERSHELL_IS_WINDOWS_OUTPUT//$'\n'/}"
  if [[ "$POWERSHELL_IS_WINDOWS_OUTPUT" == "1" ]]; then
    POWERSHELL_USES_WINDOWS_PATHS="1"
  fi
fi

to_powershell_path() {
  local path="$1"
  if [[ "$POWERSHELL_USES_WINDOWS_PATHS" == "1" ]]; then
    if command -v wslpath >/dev/null 2>&1; then
      wslpath -w "$path"
      return
    fi
    if command -v cygpath >/dev/null 2>&1; then
      cygpath -w "$path"
      return
    fi
  fi
  printf '%s' "$path"
}

resolve_windows_git_bash_runner() {
  local result
  result="$("$POWERSHELL_BIN" -NoProfile -Command "\$candidates=@('C:\\Program Files\\Git\\bin\\bash.exe','C:\\Program Files\\Git\\usr\\bin\\bash.exe','C:\\Program Files (x86)\\Git\\bin\\bash.exe','C:\\Program Files (x86)\\Git\\usr\\bin\\bash.exe'); foreach (\$candidate in \$candidates) { if (Test-Path -LiteralPath \$candidate -PathType Leaf) { Write-Output \$candidate; break } }" 2>/dev/null || true)"
  strip_crlf "$result"
}

if command -v cmd >/dev/null 2>&1; then
  CMD_BIN="cmd"
elif command -v cmd.exe >/dev/null 2>&1; then
  CMD_BIN="cmd.exe"
else
  echo "windows local api session guardrails failed: missing cmd/cmd.exe for wrapper runtime check"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

LOCAL_API_SESSION_PS1_PS="$(to_powershell_path "$LOCAL_API_SESSION_PS1")"

run_ps1_dry_run_check() {
  local name="$1"
  local expected_install_missing="$2"
  local mode="$3"
  shift 3
  local log_path="$TMP_DIR/${name}.log"
  local script_path
  local command_runner
  local runner_lc
  if ! "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$LOCAL_API_SESSION_PS1_PS" "$@" >"$log_path" 2>&1; then
    echo "windows local api session guardrails failed: expected local_api_session.ps1 $name to pass"
    cat "$log_path"
    exit 1
  fi
  for marker in \
    "local-api-session (windows-native):" \
    "command: go run ./cmd/node --local-api" \
    "install_missing: $expected_install_missing" \
    "local-api-session dry-run: command not executed"
  do
    if ! grep -Fq -- "$marker" "$log_path"; then
      echo "windows local api session guardrails failed: missing expected ps1 dry-run output marker '$marker' for $name"
      cat "$log_path"
      exit 1
    fi
  done

  script_path="$(extract_banner_field "$log_path" "script_path")"
  command_runner="$(extract_banner_field "$log_path" "command_runner")"

  if [[ -z "$script_path" ]]; then
    echo "windows local api session guardrails failed: missing script_path banner field for $name"
    cat "$log_path"
    exit 1
  fi

  case "$mode" in
    default)
      if [[ "$script_path" == *.ps1 ]]; then
        :
      elif [[ "$script_path" == *.sh ]]; then
        if [[ -z "$command_runner" ]]; then
          echo "windows local api session guardrails failed: .sh default script_path requires command_runner for $name"
          cat "$log_path"
          exit 1
        fi
      else
        echo "windows local api session guardrails failed: default script_path must end with .ps1 or .sh for $name"
        cat "$log_path"
        exit 1
      fi
      ;;
    legacy_sh_runner)
      if [[ "$script_path" != *.sh ]]; then
        echo "windows local api session guardrails failed: legacy mode expected .sh script_path for $name"
        cat "$log_path"
        exit 1
      fi
      if [[ -z "$command_runner" ]]; then
        echo "windows local api session guardrails failed: legacy mode expected non-empty command_runner for $name"
        cat "$log_path"
        exit 1
      fi
      runner_lc="${command_runner,,}"
      if [[ "$runner_lc" != *bash.exe && "$runner_lc" != */bash ]]; then
        echo "windows local api session guardrails failed: legacy mode expected bash runner for $name"
        cat "$log_path"
        exit 1
      fi
      ;;
    *)
      echo "windows local api session guardrails failed: unknown dry-run check mode '$mode'"
      exit 1
      ;;
  esac
}

echo "[windows-local-api-session-guardrails] runtime check: local_api_session.ps1 dry-run"
run_ps1_dry_run_check "ps1_dry_run" "false" "default" -DryRun

echo "[windows-local-api-session-guardrails] runtime check: local_api_session.ps1 dry-run with auto-remediation intent"
run_ps1_dry_run_check "ps1_dry_run_install_missing" "true" "default" -DryRun -InstallMissing

echo "[windows-local-api-session-guardrails] runtime check: local_api_session.ps1 legacy .sh + runner compatibility"
LEGACY_SCRIPT_PATH_PS="$(to_powershell_path "$ROOT_DIR/scripts/easy_node.sh")"
LEGACY_COMMAND_RUNNER="$(resolve_windows_git_bash_runner)"
if [[ -z "$LEGACY_COMMAND_RUNNER" ]]; then
  echo "windows local api session guardrails failed: legacy compatibility check requires Git for Windows bash.exe"
  exit 2
fi
run_ps1_dry_run_check "ps1_dry_run_legacy_sh_runner" "false" "legacy_sh_runner" -DryRun -ScriptPath "$LEGACY_SCRIPT_PATH_PS" -CommandRunner "$LEGACY_COMMAND_RUNNER"

echo "[windows-local-api-session-guardrails] runtime check: cmd wrapper dry-run pass-through"
CMD_DRY_RUN_LOG="$TMP_DIR/cmd_dry_run.log"
if ! "$CMD_BIN" /c "scripts\\windows\\local_api_session.cmd -DryRun" >"$CMD_DRY_RUN_LOG" 2>&1; then
  echo "windows local api session guardrails failed: expected local_api_session.cmd -DryRun to pass"
  cat "$CMD_DRY_RUN_LOG"
  exit 1
fi
for marker in \
  "local-api-session (windows-native):" \
  "command: go run ./cmd/node --local-api"
do
  if ! grep -Fq -- "$marker" "$CMD_DRY_RUN_LOG"; then
    echo "windows local api session guardrails failed: missing expected cmd dry-run output marker '$marker'"
    cat "$CMD_DRY_RUN_LOG"
    exit 1
  fi
done

echo "windows local api session guardrails integration check ok"
