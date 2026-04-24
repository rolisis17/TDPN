#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in grep awk sed jq mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${WINDOWS_DESKTOP_FIRST_RUN_REMEDIATION_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/windows/desktop_first_run_remediation.ps1}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "windows desktop first-run remediation guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi

if command -v powershell >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell"
elif command -v pwsh >/dev/null 2>&1; then
  POWERSHELL_BIN="pwsh"
elif command -v powershell.exe >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell.exe"
else
  echo "windows desktop first-run remediation guardrails failed: missing powershell/pwsh/powershell.exe"
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

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

SCRIPT_UNDER_TEST_PS="$(to_powershell_path "$SCRIPT_UNDER_TEST")"

COMPACT_LOG="$TMP_DIR/compact.log"
JSON_LOG="$TMP_DIR/json.log"
JSON_PAYLOAD="$TMP_DIR/summary.json"

echo "[windows-desktop-first-run-remediation-guardrails] compact summary contract"
if ! "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" -Compact >"$COMPACT_LOG" 2>&1; then
  echo "windows desktop first-run remediation guardrails failed: compact run returned non-zero"
  cat "$COMPACT_LOG"
  exit 1
fi

if ! sed 's/\r$//' "$COMPACT_LOG" | grep -Eq '^\[desktop-first-run-remediation\] summary: pass=[0-9]+ fail=[0-9]+ status=(PASS|FAIL)$'; then
  echo "windows desktop first-run remediation guardrails failed: compact summary line format mismatch"
  cat "$COMPACT_LOG"
  exit 1
fi

if sed 's/\r$//' "$COMPACT_LOG" | grep -Fq '[desktop-first-run-remediation] apply:'; then
  echo "windows desktop first-run remediation guardrails failed: default compact run unexpectedly printed apply section"
  cat "$COMPACT_LOG"
  exit 1
fi

echo "[windows-desktop-first-run-remediation-guardrails] JSON summary contract + non-destructive default"
if ! "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" -PrintSummaryJson >"$JSON_LOG" 2>&1; then
  echo "windows desktop first-run remediation guardrails failed: print-summary-json run returned non-zero"
  cat "$JSON_LOG"
  exit 1
fi

awk '
  BEGIN { emit = 0 }
  /^[[:space:]]*\{/ { emit = 1 }
  emit == 1 { print }
' "$JSON_LOG" | sed 's/\r$//' >"$JSON_PAYLOAD"

if [[ ! -s "$JSON_PAYLOAD" ]]; then
  echo "windows desktop first-run remediation guardrails failed: unable to extract JSON payload"
  cat "$JSON_LOG"
  exit 1
fi

if ! jq -e '
  .version == 1
  and (.status == "ok" or .status == "needs_remediation")
  and (.checks.pass_count | type == "number")
  and (.checks.fail_count | type == "number")
  and (.checks.toolchain | type == "object")
  and (.checks.toolchain.npm_available | type == "boolean")
  and (.checks.git_bash | type == "object")
  and (.checks.git_bash.available | type == "boolean")
  and (.checks.git_bash.path | type == "string")
  and (.checks.git_bash.source | type == "string")
  and (.checks.git_bash.checked_candidates | type == "array")
  and (.checks.desktop_assets | type == "object")
  and (.checks.desktop_assets.source_icon | type == "object")
  and (.checks.desktop_assets.source_icon.available | type == "boolean")
  and (.checks.desktop_assets.generated_icon | type == "object")
  and (.checks.desktop_assets.generated_icon.valid | type == "boolean")
  and (.checks.desktop_assets.tauri_bundle_icon | type == "object")
  and (.checks.desktop_assets.tauri_bundle_icon.configured | type == "boolean")
  and (.apply | type == "object")
  and (.apply.requested == false)
  and (.apply.execution_policy_risk_before | type == "boolean")
  and (.apply.execution_policy_effective_before | type == "string")
  and (.apply.execution_policy_effective_after | type == "string")
  and (.apply.applied_actions | type == "array" and length == 0)
  and (.apply.failed_actions | type == "array" and length == 0)
' "$JSON_PAYLOAD" >/dev/null; then
  echo "windows desktop first-run remediation guardrails failed: JSON contract assertion failed"
  cat "$JSON_LOG"
  cat "$JSON_PAYLOAD"
  exit 1
fi

echo "windows desktop first-run remediation guardrails integration check ok"
