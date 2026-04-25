#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in awk sed jq mktemp grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${WINDOWS_DESKTOP_FIRST_RUN_REMEDIATION_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/windows/desktop_first_run_remediation.ps1}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "windows desktop first-run remediation integration failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi

if command -v powershell >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell"
elif command -v pwsh >/dev/null 2>&1; then
  POWERSHELL_BIN="pwsh"
elif command -v powershell.exe >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell.exe"
else
  echo "windows desktop first-run remediation integration failed: missing powershell/pwsh/powershell.exe"
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

extract_json_payload() {
  local input_log="$1"
  local output_json="$2"
  awk '
    BEGIN { emit = 0 }
    /^[[:space:]]*\{/ { emit = 1 }
    emit == 1 { print }
  ' "$input_log" | sed 's/\r$//' >"$output_json"
}

assert_json_query() {
  local json_path="$1"
  local query="$2"
  local context="$3"
  if ! jq -e "$query" "$json_path" >/dev/null; then
    echo "windows desktop first-run remediation integration failed: JSON assertion failed ($context)"
    cat "$json_path"
    exit 1
  fi
}

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

SCRIPT_UNDER_TEST_PS="$(to_powershell_path "$SCRIPT_UNDER_TEST")"

echo "[windows-desktop-first-run-remediation] dry-run default contract"
DRYRUN_DEFAULT_LOG="$TMP_DIR/dryrun_default.log"
DRYRUN_DEFAULT_JSON="$TMP_DIR/dryrun_default.json"
if ! "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" -DryRun -PrintSummaryJson >"$DRYRUN_DEFAULT_LOG" 2>&1; then
  echo "windows desktop first-run remediation integration failed: dry-run default returned non-zero"
  cat "$DRYRUN_DEFAULT_LOG"
  exit 1
fi

extract_json_payload "$DRYRUN_DEFAULT_LOG" "$DRYRUN_DEFAULT_JSON"
if [[ ! -s "$DRYRUN_DEFAULT_JSON" ]]; then
  echo "windows desktop first-run remediation integration failed: unable to extract dry-run default JSON payload"
  cat "$DRYRUN_DEFAULT_LOG"
  exit 1
fi

assert_json_query "$DRYRUN_DEFAULT_JSON" '
  .version == 1
  and (.generated_at_utc | type == "string" and length > 0)
  and (.status == "ok" or .status == "needs_remediation")
  and (.apply.requested == false)
  and (.apply.dry_run_requested == true)
  and (.apply.effective_apply_requested == false)
  and (.apply.applied_actions | type == "array" and length == 0)
  and (.apply.failed_actions | type == "array" and length == 0)
  and (.checks.session_path | type == "object")
  and (.checks.session_path.refresh_attempted == true)
  and (.checks.session_path.refresh_succeeded | type == "boolean")
  and (.checks.session_path.augment_attempted | type == "boolean")
  and (.checks.session_path.path_before_refresh | type == "string")
  and (.checks.session_path.path_after_refresh | type == "string")
  and (.checks.session_path.path_before_augment | type == "string")
  and (.checks.session_path.path_after_augment | type == "string")
  and (.checks.session_path.tool_resolution_pass | type == "string" and length > 0)
  and (.checks.toolchain.npm_path | type == "string")
  and (.checks.npm.resolver_path | type == "string")
  and (.checks.npm.npm_cmd_resolver_path | type == "string")
  and ((.checks.npm.resolver_path | ascii_downcase | endswith("npm.ps1")) | not)
  and (.checks.npm.session_alias_remediation.npm.applied == false)
  and (.checks.npm.session_alias_remediation.npm.attempted == false)
  and (.checks.npm.session_alias_remediation.npx.applied == false)
  and (.checks.npm.session_alias_remediation.npx.attempted == false)
' "dry-run default"

echo "[windows-desktop-first-run-remediation] dry-run+apply contract remains non-destructive"
DRYRUN_APPLY_LOG="$TMP_DIR/dryrun_apply.log"
DRYRUN_APPLY_JSON="$TMP_DIR/dryrun_apply.json"
if ! "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" -DryRun -Apply -PrintSummaryJson >"$DRYRUN_APPLY_LOG" 2>&1; then
  echo "windows desktop first-run remediation integration failed: dry-run+apply returned non-zero"
  cat "$DRYRUN_APPLY_LOG"
  exit 1
fi

extract_json_payload "$DRYRUN_APPLY_LOG" "$DRYRUN_APPLY_JSON"
if [[ ! -s "$DRYRUN_APPLY_JSON" ]]; then
  echo "windows desktop first-run remediation integration failed: unable to extract dry-run+apply JSON payload"
  cat "$DRYRUN_APPLY_LOG"
  exit 1
fi

assert_json_query "$DRYRUN_APPLY_JSON" '
  .version == 1
  and (.status == "ok" or .status == "needs_remediation")
  and (.apply.requested == true)
  and (.apply.dry_run_requested == true)
  and (.apply.effective_apply_requested == false)
  and (.apply.applied_actions | type == "array" and length == 0)
  and (.apply.failed_actions | type == "array" and length == 0)
  and (.checks.npm.resolver_path | type == "string")
  and ((.checks.npm.resolver_path | ascii_downcase | endswith("npm.ps1")) | not)
  and (.checks.npm.session_alias_remediation.npm.applied == false)
  and (.checks.npm.session_alias_remediation.npx.applied == false)
  and (
    .checks.npm.session_alias_remediation.npm.eligible == false
    or (
      .checks.npm.session_alias_remediation.npm.attempted == true
      and .checks.npm.session_alias_remediation.npm.reason == "dry_run"
    )
  )
  and (
    .checks.npm.session_alias_remediation.npx.eligible == false
    or (
      .checks.npm.session_alias_remediation.npx.attempted == true
      and .checks.npm.session_alias_remediation.npx.reason == "dry_run"
    )
  )
' "dry-run+apply"

echo "windows desktop first-run remediation integration check ok"
