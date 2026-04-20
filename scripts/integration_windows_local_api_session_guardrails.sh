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

echo "[windows-local-api-session-guardrails] marker checks: cmd wrapper policy + guardrails"
assert_marker_present "-ExecutionPolicy Bypass" "$LOCAL_API_SESSION_CMD"
assert_marker_present "Unsupported cmd metacharacters" "$LOCAL_API_SESSION_CMD"
assert_marker_present "-File \"%PS1%\"" "$LOCAL_API_SESSION_CMD"

echo "[windows-local-api-session-guardrails] marker checks: powershell script go/runtime guidance"
assert_marker_present "function Resolve-GoExecutable" "$LOCAL_API_SESSION_PS1"
assert_marker_present "winget install --id GoLang.Go --exact" "$LOCAL_API_SESSION_PS1"
assert_marker_present '$goArgs = @("run", "./cmd/node")' "$LOCAL_API_SESSION_PS1"
assert_marker_present '$goArgs += @("--local-api")' "$LOCAL_API_SESSION_PS1"
assert_marker_present 'Write-Host "  command: go ' "$LOCAL_API_SESSION_PS1"

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

echo "[windows-local-api-session-guardrails] runtime check: local_api_session.ps1 dry-run"
PS1_DRY_RUN_LOG="$TMP_DIR/ps1_dry_run.log"
if ! "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$LOCAL_API_SESSION_PS1_PS" -DryRun >"$PS1_DRY_RUN_LOG" 2>&1; then
  echo "windows local api session guardrails failed: expected local_api_session.ps1 -DryRun to pass"
  cat "$PS1_DRY_RUN_LOG"
  exit 1
fi
for marker in \
  "local-api-session (windows-native):" \
  "command: go run ./cmd/node --local-api"
do
  if ! grep -Fq -- "$marker" "$PS1_DRY_RUN_LOG"; then
    echo "windows local api session guardrails failed: missing expected ps1 dry-run output marker '$marker'"
    cat "$PS1_DRY_RUN_LOG"
    exit 1
  fi
done

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
