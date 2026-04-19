#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq rg sed sort diff awk mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

REQUIRED_FILES=(
  "apps/desktop/README.md"
  "apps/desktop/package.json"
  "apps/desktop/index.html"
  "apps/desktop/src/main.js"
  "apps/desktop/src-tauri/Cargo.toml"
  "apps/desktop/src-tauri/src/main.rs"
  "apps/desktop/src-tauri/src/local_api.rs"
  "apps/desktop/src-tauri/tauri.conf.json"
  "apps/desktop/src-tauri/capabilities/default.json"
)

for path in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "desktop scaffold contract failed: missing required file: $path"
    exit 1
  fi
done
echo "[desktop-scaffold] required files exist"

RELEASE_SCAFFOLD_FILES=(
  "scripts/windows/desktop_release_bundle.ps1"
  "scripts/windows/desktop_release_bundle.cmd"
)
for path in "${RELEASE_SCAFFOLD_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "desktop scaffold contract failed: missing release scaffold script: $path"
    exit 1
  fi
done
echo "[desktop-scaffold] release scaffold scripts exist"

DOCTOR_SCAFFOLD_FILES=(
  "scripts/windows/desktop_doctor.ps1"
  "scripts/windows/desktop_doctor.cmd"
)
for path in "${DOCTOR_SCAFFOLD_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "desktop scaffold contract failed: missing doctor scaffold script: $path"
    exit 1
  fi
done
echo "[desktop-scaffold] doctor scaffold scripts exist"

DOCTOR_POWERSHELL_SCRIPT="scripts/windows/desktop_doctor.ps1"
DOCTOR_CMD_SCRIPT="scripts/windows/desktop_doctor.cmd"

if ! grep -qF 'desktop_native_bootstrap' "$DOCTOR_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected bootstrap launcher reference in $DOCTOR_POWERSHELL_SCRIPT"
  exit 1
fi
if ! grep -qiE 'check|fix' "$DOCTOR_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected check/fix mode marker in $DOCTOR_POWERSHELL_SCRIPT"
  exit 1
fi
if ! grep -qF 'desktop_doctor.ps1' "$DOCTOR_CMD_SCRIPT"; then
  echo "desktop scaffold contract failed: expected PowerShell launcher reference in $DOCTOR_CMD_SCRIPT"
  exit 1
fi
echo "[desktop-scaffold] doctor scaffold script markers are present"

DOCTOR_LINUX_SCRIPT="scripts/linux/desktop_doctor.sh"
if [[ ! -f "$DOCTOR_LINUX_SCRIPT" ]]; then
  echo "desktop scaffold contract failed: missing linux doctor scaffold script: $DOCTOR_LINUX_SCRIPT"
  exit 1
fi
if ! grep -qiE 'check|fix' "$DOCTOR_LINUX_SCRIPT"; then
  echo "desktop scaffold contract failed: expected check/fix mode marker in $DOCTOR_LINUX_SCRIPT"
  exit 1
fi
if ! grep -qF -- '--install-missing' "$DOCTOR_LINUX_SCRIPT"; then
  echo "desktop scaffold contract failed: expected --install-missing marker in $DOCTOR_LINUX_SCRIPT"
  exit 1
fi
if ! grep -qiE 'scaffold|non-production' "$DOCTOR_LINUX_SCRIPT"; then
  echo "desktop scaffold contract failed: expected scaffold/non-production marker in $DOCTOR_LINUX_SCRIPT"
  exit 1
fi
echo "[desktop-scaffold] linux doctor scaffold script markers are present"

PACKAGED_RUN_SCAFFOLD_FILES=(
  "scripts/windows/desktop_packaged_run.ps1"
  "scripts/windows/desktop_packaged_run.cmd"
)
for path in "${PACKAGED_RUN_SCAFFOLD_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "desktop scaffold contract failed: missing packaged-run scaffold script: $path"
    exit 1
  fi
done
echo "[desktop-scaffold] packaged-run scaffold scripts exist"

PACKAGED_RUN_POWERSHELL_SCRIPT="scripts/windows/desktop_packaged_run.ps1"
PACKAGED_RUN_CMD_SCRIPT="scripts/windows/desktop_packaged_run.cmd"

if ! grep -qF 'desktop_native_bootstrap' "$PACKAGED_RUN_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected bootstrap launcher reference in $PACKAGED_RUN_POWERSHELL_SCRIPT"
  exit 1
fi
if ! grep -qiE 'packaged' "$PACKAGED_RUN_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected packaged mode marker in $PACKAGED_RUN_POWERSHELL_SCRIPT"
  exit 1
fi
if ! grep -qF 'desktop_packaged_run.ps1' "$PACKAGED_RUN_CMD_SCRIPT"; then
  echo "desktop scaffold contract failed: expected PowerShell launcher reference in $PACKAGED_RUN_CMD_SCRIPT"
  exit 1
fi
echo "[desktop-scaffold] packaged-run scaffold script markers are present"

LINUX_PACKAGED_RUN_SCRIPT="scripts/linux/desktop_packaged_run.sh"
if [[ ! -f "$LINUX_PACKAGED_RUN_SCRIPT" ]]; then
  echo "desktop scaffold contract failed: missing linux packaged-run scaffold script: $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
if ! grep -qF 'desktop_doctor.sh' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected doctor launcher reference in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
if ! grep -qF 'desktop_native_bootstrap.sh' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected native bootstrap reference in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
if ! grep -qF -- '--desktop-executable-path' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected --desktop-executable-path marker in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
if ! grep -qiE 'scaffold|non-production' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected scaffold/non-production marker in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
echo "[desktop-scaffold] linux packaged-run scaffold script markers are present"

WINDOWS_NATIVE_BOOTSTRAP_FILES=(
  "scripts/windows/desktop_native_bootstrap.ps1"
  "scripts/windows/desktop_native_bootstrap.cmd"
  "scripts/windows/local_api_session.ps1"
)
for path in "${WINDOWS_NATIVE_BOOTSTRAP_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "desktop scaffold contract failed: missing windows-native bootstrap script: $path"
    exit 1
  fi
done
echo "[desktop-scaffold] windows-native bootstrap scripts exist"

WINDOWS_NATIVE_BOOTSTRAP_SCRIPT="scripts/windows/desktop_native_bootstrap.ps1"
if ! grep -qF 'npm.cmd' "$WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected npm.cmd usage in $WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qF 'local_api_session.ps1' "$WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected Windows-native local API session usage in $WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qiE 'SummaryJson|summary[_-]?json' "$WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected summary-json parameter marker in $WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qiE 'PrintSummaryJson|print[_-]?summary[_-]?json' "$WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected print-summary-json parameter marker in $WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qiE 'summary json written|write[-_ ]*summary|Write-[A-Za-z0-9_]*Summary|Summary[[:space:]]+helper' "$WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected summary writing helper marker in $WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi

LINUX_NATIVE_BOOTSTRAP_SCRIPT="scripts/linux/desktop_native_bootstrap.sh"
if [[ ! -f "$LINUX_NATIVE_BOOTSTRAP_SCRIPT" ]]; then
  echo "desktop scaffold contract failed: missing linux native bootstrap script: $LINUX_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qiE 'check|bootstrap|run-api|run-desktop|run-full' "$LINUX_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected mode markers in $LINUX_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qF 'go run ./cmd/node --local-api' "$LINUX_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected local API launcher command in $LINUX_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qiE 'scaffold|non-production' "$LINUX_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected scaffold/non-production marker in $LINUX_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
echo "[desktop-scaffold] linux native bootstrap script markers are present"

README_FILE="apps/desktop/README.md"

ONE_CLICK_LAUNCHER_FILES=(
  "scripts/windows/desktop_one_click.ps1"
  "scripts/windows/desktop_one_click.cmd"
)
ONE_CLICK_LAUNCHER_PRESENT="0"
for path in "${ONE_CLICK_LAUNCHER_FILES[@]}"; do
  if [[ -e "$path" ]]; then
    ONE_CLICK_LAUNCHER_PRESENT="1"
    break
  fi
done

if [[ "$ONE_CLICK_LAUNCHER_PRESENT" == "1" ]]; then
  for path in "${ONE_CLICK_LAUNCHER_FILES[@]}"; do
    if [[ ! -f "$path" ]]; then
      echo "desktop scaffold contract failed: missing one-click launcher script: $path"
      exit 1
    fi
  done

  ONE_CLICK_POWERSHELL_SCRIPT="scripts/windows/desktop_one_click.ps1"
  ONE_CLICK_CMD_SCRIPT="scripts/windows/desktop_one_click.cmd"

  if ! grep -qF 'desktop_native_bootstrap' "$ONE_CLICK_POWERSHELL_SCRIPT"; then
    echo "desktop scaffold contract failed: expected bootstrap launcher reference in $ONE_CLICK_POWERSHELL_SCRIPT"
    exit 1
  fi
  if ! grep -qiE 'run-full|bootstrap' "$ONE_CLICK_POWERSHELL_SCRIPT"; then
    echo "desktop scaffold contract failed: expected launch-mode marker in $ONE_CLICK_POWERSHELL_SCRIPT"
    exit 1
  fi
  if ! grep -qF 'desktop_one_click.ps1' "$ONE_CLICK_CMD_SCRIPT"; then
    echo "desktop scaffold contract failed: expected PowerShell launcher reference in $ONE_CLICK_CMD_SCRIPT"
    exit 1
  fi

  if ! grep -qF 'desktop_one_click.ps1' "$README_FILE"; then
    echo "desktop scaffold contract failed: README must reference the one-click launcher scripts when they exist"
    exit 1
  fi
  echo "[desktop-scaffold] one-click launcher scripts and markers are present"
fi

LINUX_ONE_CLICK_SCRIPT="scripts/linux/desktop_one_click.sh"
if [[ ! -f "$LINUX_ONE_CLICK_SCRIPT" ]]; then
  echo "desktop scaffold contract failed: missing linux one-click launcher script: $LINUX_ONE_CLICK_SCRIPT"
  exit 1
fi
if ! grep -qF 'desktop_native_bootstrap.sh' "$LINUX_ONE_CLICK_SCRIPT"; then
  echo "desktop scaffold contract failed: expected bootstrap launcher reference in $LINUX_ONE_CLICK_SCRIPT"
  exit 1
fi
if ! grep -qiE 'run-full|bootstrap' "$LINUX_ONE_CLICK_SCRIPT"; then
  echo "desktop scaffold contract failed: expected launch-mode marker in $LINUX_ONE_CLICK_SCRIPT"
  exit 1
fi
if ! grep -qF 'scripts/linux/desktop_doctor.sh' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must reference linux desktop doctor script"
  exit 1
fi
if ! grep -qF 'scripts/linux/desktop_packaged_run.sh' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must reference linux packaged-run script"
  exit 1
fi
echo "[desktop-scaffold] linux one-click launcher and README references are present"

LOCAL_API_SESSION_SCRIPT="scripts/windows/local_api_session.ps1"
if ! grep -qF 'windows-native' "$LOCAL_API_SESSION_SCRIPT"; then
  echo "desktop scaffold contract failed: expected Windows-native local API marker in $LOCAL_API_SESSION_SCRIPT"
  exit 1
fi
echo "[desktop-scaffold] bootstrap and local API marker strings present"

DESKTOP_HTML_FILE="apps/desktop/index.html"
JS_FILE="apps/desktop/src/main.js"
if ! grep -qF 'id="tab_client"' "$DESKTOP_HTML_FILE"; then
  echo "desktop scaffold contract failed: missing client tab marker in $DESKTOP_HTML_FILE"
  exit 1
fi
if ! grep -qF 'id="tab_server"' "$DESKTOP_HTML_FILE"; then
  echo "desktop scaffold contract failed: missing server tab marker in $DESKTOP_HTML_FILE"
  exit 1
fi
if ! grep -qF 'id="panel_client"' "$DESKTOP_HTML_FILE"; then
  echo "desktop scaffold contract failed: missing client panel marker in $DESKTOP_HTML_FILE"
  exit 1
fi
if ! grep -qF 'id="panel_server"' "$DESKTOP_HTML_FILE"; then
  echo "desktop scaffold contract failed: missing server panel marker in $DESKTOP_HTML_FILE"
  exit 1
fi
if ! grep -qF 'id="server_lock_hint"' "$DESKTOP_HTML_FILE"; then
  echo "desktop scaffold contract failed: missing server lock hint marker in $DESKTOP_HTML_FILE"
  exit 1
fi

client_hint_marker_present="0"
if grep -qF 'id="client_lock_hint"' "$DESKTOP_HTML_FILE"; then
  client_hint_marker_present="1"
elif grep -qF 'id="desktop_step_client"' "$DESKTOP_HTML_FILE"; then
  client_hint_marker_present="1"
fi
if [[ "$client_hint_marker_present" != "1" ]]; then
  echo "desktop scaffold contract failed: missing client-side lock hint marker (expected client_lock_hint or desktop_step_client) in $DESKTOP_HTML_FILE"
  exit 1
fi
echo "[desktop-scaffold] client/server lock hint elements are present"

if ! grep -qF 'function syncServerRoleLockState()' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing server role lock sync function in $JS_FILE"
  exit 1
fi
if ! grep -qF 'tabServerEl.disabled = !serverTabVisible;' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing server tab disabled handling marker in $JS_FILE"
  exit 1
fi
if ! grep -qF 'tabServerEl.classList.toggle("locked", !serverTabVisible);' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing server tab locked-class marker in $JS_FILE"
  exit 1
fi
if ! grep -qF 'serverLockHintEl.textContent = computeServerLockHintText();' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing server lock hint update marker in $JS_FILE"
  exit 1
fi
if ! grep -qF 'if (!tabServerEl.disabled) {' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing disabled-tab click guard marker in $JS_FILE"
  exit 1
fi
if ! rg -q -- 'tab(Server|Client)El\.disabled[[:space:]]*=' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing tab disabled assignment markers in $JS_FILE"
  exit 1
fi

if grep -qF 'id="client_lock_hint"' "$DESKTOP_HTML_FILE"; then
  if ! rg -q -- 'clientLockHintEl|client_lock_hint' "$JS_FILE"; then
    echo "desktop scaffold contract failed: client lock hint element exists but no client lock hint logic marker found in $JS_FILE"
    exit 1
  fi
else
  if ! grep -qF 'setDesktopStepState(desktopStepClientEl' "$JS_FILE"; then
    echo "desktop scaffold contract failed: missing client onboarding lock-state marker in $JS_FILE"
    exit 1
  fi
fi
echo "[desktop-scaffold] role-lock logic markers are present (client+server hints, disabled-tab handling)"

PARSE_SERVER_READINESS_SNIPPET="$(sed -n '/function parseServerReadiness(/,/^}/p' "$JS_FILE")"
if [[ -z "$PARSE_SERVER_READINESS_SNIPPET" ]]; then
  echo "desktop scaffold contract failed: missing parseServerReadiness function block in $JS_FILE"
  exit 1
fi

assert_parse_readiness_fallback_pair() {
  local field_name="$1"
  local snake_pattern="$2"
  local camel_pattern="$3"

  if ! printf '%s\n' "$PARSE_SERVER_READINESS_SNIPPET" | grep -Eq "$snake_pattern"; then
    echo "desktop scaffold contract failed: parseServerReadiness missing snake_case readiness marker for $field_name in $JS_FILE"
    exit 1
  fi
  if ! printf '%s\n' "$PARSE_SERVER_READINESS_SNIPPET" | grep -Eq "$camel_pattern"; then
    echo "desktop scaffold contract failed: parseServerReadiness missing camelCase readiness marker for $field_name in $JS_FILE"
    exit 1
  fi
}

assert_parse_readiness_fallback_pair \
  "tabVisible" \
  'readiness[[:space:]]*\.[[:space:]]*tab_visible|readiness\[[^]]*tab_visible[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*tabVisible|readiness\[[^]]*tabVisible[^]]*\]'
assert_parse_readiness_fallback_pair \
  "clientTabVisible" \
  'readiness[[:space:]]*\.[[:space:]]*(client_tab_visible|client_tab_enabled)|readiness\[[^]]*(client_tab_visible|client_tab_enabled)[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*(clientTabVisible|clientTabEnabled)|readiness\[[^]]*(clientTabVisible|clientTabEnabled)[^]]*\]'
assert_parse_readiness_fallback_pair \
  "lifecycleActionsUnlocked" \
  'readiness[[:space:]]*\.[[:space:]]*lifecycle_actions_unlocked|readiness\[[^]]*lifecycle_actions_unlocked[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*lifecycleActionsUnlocked|readiness\[[^]]*lifecycleActionsUnlocked[^]]*\]'
assert_parse_readiness_fallback_pair \
  "serviceMutationsConfigured" \
  'readiness[[:space:]]*\.[[:space:]]*service_mutations_configured|readiness\[[^]]*service_mutations_configured[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*serviceMutationsConfigured|readiness\[[^]]*serviceMutationsConfigured[^]]*\]'
assert_parse_readiness_fallback_pair \
  "operatorApplicationStatus" \
  'readiness[[:space:]]*\.[[:space:]]*operator_application_status|readiness\[[^]]*operator_application_status[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*operatorApplicationStatus|readiness\[[^]]*operatorApplicationStatus[^]]*\]'
assert_parse_readiness_fallback_pair \
  "lockReason" \
  'readiness[[:space:]]*\.[[:space:]]*lock_reason|readiness\[[^]]*lock_reason[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*lockReason|readiness\[[^]]*lockReason[^]]*\]'
assert_parse_readiness_fallback_pair \
  "clientLockReason" \
  'readiness[[:space:]]*\.[[:space:]]*(client_lock_reason|client_lock_hint)|readiness\[[^]]*(client_lock_reason|client_lock_hint)[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*(clientLockReason|clientLockHint)|readiness\[[^]]*(clientLockReason|clientLockHint)[^]]*\]'
assert_parse_readiness_fallback_pair \
  "unlockActions" \
  'readiness[[:space:]]*\.[[:space:]]*unlock_actions|readiness\[[^]]*unlock_actions[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*unlockActions|readiness\[[^]]*unlockActions[^]]*\]'
echo "[desktop-scaffold] parseServerReadiness fallback markers are present for snake_case and camelCase readiness fields"

JSON_FILES=(
  "apps/desktop/package.json"
  "apps/desktop/src-tauri/tauri.conf.json"
  "apps/desktop/src-tauri/capabilities/default.json"
)
for path in "${JSON_FILES[@]}"; do
  if ! jq empty "$path" >/dev/null 2>&1; then
    echo "desktop scaffold contract failed: invalid JSON: $path"
    exit 1
  fi
done
echo "[desktop-scaffold] JSON files are valid"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

JS_FILE="apps/desktop/src/main.js"
RUST_FILE="apps/desktop/src-tauri/src/main.rs"

if ! rg -q -- '(invoke\("control_[a-z_]+"|call\("[^"]+",[[:space:]]*"control_[a-z_]+")' "$JS_FILE"; then
  echo "desktop scaffold contract failed: no control_* command calls found in $JS_FILE"
  exit 1
fi

{
  rg -o --no-filename 'invoke\("control_[a-z_]+"' "$JS_FILE" \
    | sed -E 's/invoke\("(control_[a-z_]+)"/\1/' || true
  rg -o --no-filename 'call\("[^"]+",[[:space:]]*"control_[a-z_]+"' "$JS_FILE" \
    | sed -E 's/.*"(control_[a-z_]+)"/\1/' || true
} | sort -u >"$TMP_DIR/js_controls.txt"

if [[ ! -s "$TMP_DIR/js_controls.txt" ]]; then
  echo "desktop scaffold contract failed: no control_* command names could be extracted from $JS_FILE"
  exit 1
fi

rg --no-filename '^(async[[:space:]]+)?fn[[:space:]]+control_[a-z_]+' "$RUST_FILE" \
  | sed -E 's/^(async[[:space:]]+)?fn[[:space:]]+(control_[a-z_]+).*/\2/' \
  | sort -u >"$TMP_DIR/rust_fn_controls.txt"

awk '/generate_handler!\[/,/]/ { print }' "$RUST_FILE" \
  | rg -o --no-filename 'control_[a-z_]+' \
  | sort -u >"$TMP_DIR/rust_handler_controls.txt"

if [[ ! -s "$TMP_DIR/rust_fn_controls.txt" ]]; then
  echo "desktop scaffold contract failed: no Rust control_* bridge functions found in $RUST_FILE"
  exit 1
fi

if [[ ! -s "$TMP_DIR/rust_handler_controls.txt" ]]; then
  echo "desktop scaffold contract failed: no Rust control_* commands found in generate_handler block in $RUST_FILE"
  exit 1
fi

extract_service_lifecycle_controls() {
  local source_file="$1"
  local output_file="$2"
  awk -F'_' '
    BEGIN {
      verbs["install"] = 1
      verbs["uninstall"] = 1
      verbs["start"] = 1
      verbs["stop"] = 1
      verbs["restart"] = 1
      verbs["status"] = 1
      verbs["enable"] = 1
      verbs["disable"] = 1
      verbs["reload"] = 1
    }
    /^control_[a-z0-9_]+$/ {
      has_service_scope = 0
      has_lifecycle_verb = 0
      for (i = 2; i <= NF; i++) {
        if ($i == "service" || $i == "daemon") {
          has_service_scope = 1
        }
        if ($i in verbs) {
          has_lifecycle_verb = 1
        }
      }
      if (has_service_scope && has_lifecycle_verb) {
        print $0
      }
    }
  ' "$source_file" | sort -u >"$output_file"
}

extract_service_lifecycle_controls "$TMP_DIR/js_controls.txt" "$TMP_DIR/js_service_lifecycle_controls.txt"
extract_service_lifecycle_controls "$TMP_DIR/rust_fn_controls.txt" "$TMP_DIR/rust_fn_service_lifecycle_controls.txt"
extract_service_lifecycle_controls "$TMP_DIR/rust_handler_controls.txt" "$TMP_DIR/rust_handler_service_lifecycle_controls.txt"
cat \
  "$TMP_DIR/js_service_lifecycle_controls.txt" \
  "$TMP_DIR/rust_fn_service_lifecycle_controls.txt" \
  "$TMP_DIR/rust_handler_service_lifecycle_controls.txt" \
  | sort -u >"$TMP_DIR/combined_service_lifecycle_controls.txt"

if [[ -s "$TMP_DIR/combined_service_lifecycle_controls.txt" ]]; then
  if ! diff -u "$TMP_DIR/js_service_lifecycle_controls.txt" "$TMP_DIR/rust_fn_service_lifecycle_controls.txt" >/dev/null; then
    echo "desktop scaffold contract failed: JS/Rust service lifecycle control_* command set mismatch"
    echo "--- js service lifecycle controls"
    cat "$TMP_DIR/js_service_lifecycle_controls.txt"
    echo "--- rust function service lifecycle controls"
    cat "$TMP_DIR/rust_fn_service_lifecycle_controls.txt"
    exit 1
  fi

  if ! diff -u "$TMP_DIR/rust_fn_service_lifecycle_controls.txt" "$TMP_DIR/rust_handler_service_lifecycle_controls.txt" >/dev/null; then
    echo "desktop scaffold contract failed: Rust service lifecycle control_* functions are not aligned with generate_handler registration"
    echo "--- rust function service lifecycle controls"
    cat "$TMP_DIR/rust_fn_service_lifecycle_controls.txt"
    echo "--- rust handler service lifecycle controls"
    cat "$TMP_DIR/rust_handler_service_lifecycle_controls.txt"
    exit 1
  fi
  echo "[desktop-scaffold] service lifecycle control_* command names align across JS and Rust bridge"
else
  echo "[desktop-scaffold] service lifecycle control_* commands not present; lifecycle alignment check skipped"
fi

missing_js_rust_fn="$(grep -Fxv -f "$TMP_DIR/rust_fn_controls.txt" "$TMP_DIR/js_controls.txt" || true)"
if [[ -n "$missing_js_rust_fn" ]]; then
  echo "desktop scaffold contract failed: JS invoke control_* command set has entries missing from Rust bridge functions"
  echo "--- js controls missing from rust function controls"
  printf '%s\n' "$missing_js_rust_fn"
  echo "--- rust function controls"
  cat "$TMP_DIR/rust_fn_controls.txt"
  exit 1
fi

missing_js_rust_handler="$(grep -Fxv -f "$TMP_DIR/rust_handler_controls.txt" "$TMP_DIR/js_controls.txt" || true)"
if [[ -n "$missing_js_rust_handler" ]]; then
  echo "desktop scaffold contract failed: JS invoke control_* command set has entries missing from generate_handler registration"
  echo "--- js controls missing from rust handler controls"
  printf '%s\n' "$missing_js_rust_handler"
  echo "--- rust handler controls"
  cat "$TMP_DIR/rust_handler_controls.txt"
  exit 1
fi
echo "[desktop-scaffold] JS-invoked control_* command names are present in Rust bridge and handler registration"

if ! rg -qi -- 'scaffold' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must clearly mention scaffold status"
  exit 1
fi
if ! rg -qi -- 'not production-ready|intentionally lightweight|does not include yet' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must clearly communicate non-production scaffold nature"
  exit 1
fi
if ! rg -qi -- 'update[[:space:]-]*channel' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must mention update channel behavior"
  exit 1
fi
if ! rg -q -- 'TDPN_[A-Z0-9_]*UPDATE[A-Z0-9_]*CHANNEL[A-Z0-9_]*' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must document update channel env knobs (for example TDPN_*UPDATE*CHANNEL*)"
  exit 1
fi
if ! rg -qi -- 'one[^[:alnum:]]+.*window|single[^[:alnum:]]+.*window|single-window|one-window' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must describe the single-window desktop workspace model"
  exit 1
fi
if ! rg -qi -- 'client/server tabs|client and server tabs|client.*server.*tabs|tabs.*client.*server' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must mention client/server tab UX"
  exit 1
fi
if ! rg -qi -- 'non-clickable|disabled[[:space:]]+tab|role-ineligible[[:space:]]+tab' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must describe role-ineligible tab lock behavior"
  exit 1
fi
if ! rg -qi -- 'status reason|lock reason|unlock' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must describe lock-status reason guidance"
  exit 1
fi
echo "[desktop-scaffold] README states scaffold/non-production intent"

echo "desktop scaffold contract integration check ok"
