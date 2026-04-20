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
  "apps/desktop/src-tauri/build.rs"
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

BUILD_RS_FILE="apps/desktop/src-tauri/build.rs"
BUILD_RS_ICON_FALLBACK_MARKERS=(
  'fn placeholder_ico_bytes()'
  'fn ensure_scaffold_icon() -> io::Result<()>'
  'icon_dir.join("icon.ico")'
  'fs::create_dir_all(&icon_dir)?'
  'fs::write(&icon_path, placeholder_ico_bytes())?'
  'generated scaffold placeholder icon'
)
for marker in "${BUILD_RS_ICON_FALLBACK_MARKERS[@]}"; do
  if ! grep -qF -- "$marker" "$BUILD_RS_FILE"; then
    echo "desktop scaffold contract failed: missing build.rs icon fallback marker '$marker' in $BUILD_RS_FILE"
    exit 1
  fi
done
if ! grep -qF -- 'if icon_path.exists() {' "$BUILD_RS_FILE" && \
   ! grep -qF -- 'fs::metadata(&icon_path)' "$BUILD_RS_FILE"; then
  echo "desktop scaffold contract failed: missing build.rs icon-missing detection marker (expected icon_path.exists() or fs::metadata(&icon_path)) in $BUILD_RS_FILE"
  exit 1
fi
if ! grep -qF -- 'io::ErrorKind::NotFound' "$BUILD_RS_FILE" && \
   ! grep -qF -- 'if icon_path.exists() {' "$BUILD_RS_FILE"; then
  echo "desktop scaffold contract failed: missing build.rs icon-not-found handling marker (expected io::ErrorKind::NotFound or icon_path.exists guard) in $BUILD_RS_FILE"
  exit 1
fi
if ! grep -qF -- 'if let Err(err) = ensure_scaffold_icon() {' "$BUILD_RS_FILE"; then
  echo "desktop scaffold contract failed: missing build.rs continue-on-icon-fallback-error guard marker in $BUILD_RS_FILE"
  exit 1
fi
if ! grep -qF -- 'failed to prepare scaffold icon (continuing)' "$BUILD_RS_FILE"; then
  echo "desktop scaffold contract failed: missing build.rs continue-on-error warning marker in $BUILD_RS_FILE"
  exit 1
fi
if ! grep -qF -- 'tauri_build::build()' "$BUILD_RS_FILE"; then
  echo "desktop scaffold contract failed: missing build.rs tauri build continuation marker in $BUILD_RS_FILE"
  exit 1
fi
echo "[desktop-scaffold] build.rs icon fallback markers are present"

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

LINUX_RELEASE_BUNDLE_SCRIPT="scripts/linux/desktop_release_bundle.sh"
if [[ ! -f "$LINUX_RELEASE_BUNDLE_SCRIPT" ]]; then
  echo "desktop scaffold contract failed: missing linux release-bundle scaffold script: $LINUX_RELEASE_BUNDLE_SCRIPT"
  exit 1
fi
if ! grep -qF 'desktop_doctor.sh' "$LINUX_RELEASE_BUNDLE_SCRIPT"; then
  echo "desktop scaffold contract failed: expected desktop doctor launcher reference in $LINUX_RELEASE_BUNDLE_SCRIPT"
  exit 1
fi
if ! grep -qF -- '--install-missing' "$LINUX_RELEASE_BUNDLE_SCRIPT"; then
  echo "desktop scaffold contract failed: expected --install-missing remediation marker in $LINUX_RELEASE_BUNDLE_SCRIPT"
  exit 1
fi
if ! rg -qi -- '--mode([[:space:]]+|=)fix|(^|[[:space:]])fix([[:space:]]|$)' "$LINUX_RELEASE_BUNDLE_SCRIPT"; then
  echo "desktop scaffold contract failed: expected desktop_doctor fix-mode marker in $LINUX_RELEASE_BUNDLE_SCRIPT"
  exit 1
fi
echo "[desktop-scaffold] linux release-bundle remediation markers are present"

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
if ! grep -qF 'GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING' "$PACKAGED_RUN_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected GPM shared auto-install env marker in $PACKAGED_RUN_POWERSHELL_SCRIPT"
  exit 1
fi
if ! grep -qF 'TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING' "$PACKAGED_RUN_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected TDPN shared auto-install legacy env alias marker in $PACKAGED_RUN_POWERSHELL_SCRIPT"
  exit 1
fi
if ! rg -q -- '-NoInstallMissing|\$NoInstallMissing' "$PACKAGED_RUN_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected -NoInstallMissing override marker in $PACKAGED_RUN_POWERSHELL_SCRIPT"
  exit 1
fi
if ! rg -q -- '\$installMissingIntent[[:space:]]*=[[:space:]]*\$true|\$\{GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING:-\$\{TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING:-1\}\}|default[^[:alnum:]]*(enable|enabled|true)[^[:alnum:]]*(install|auto[-_ ]?install)[^[:alnum:]]*missing' "$PACKAGED_RUN_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected default-enabled install-intent marker in $PACKAGED_RUN_POWERSHELL_SCRIPT"
  exit 1
fi
if ! rg -q -- 'if[[:space:]]*\(\$(EffectiveInstallMissing|InstallIntent|InstallMissing|installMissingEffective|installMissingIntent)\)' "$PACKAGED_RUN_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected effective install-intent condition marker in $PACKAGED_RUN_POWERSHELL_SCRIPT"
  exit 1
fi
if ! rg -q -- 'doctorInvokeArgs[[:space:]]*\+=[[:space:]]*@\([^)]*"-InstallMissing"[^)]*\)|doctorInvokeArgs[[:space:]]*\+=[[:space:]]*"-InstallMissing"' "$PACKAGED_RUN_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected doctor -InstallMissing forwarding marker in $PACKAGED_RUN_POWERSHELL_SCRIPT"
  exit 1
fi
if ! rg -q -- 'bootstrapInvokeArgs[[:space:]]*\+=[[:space:]]*"-InstallMissing"|bootstrapInvokeArgs[[:space:]]*\+=[[:space:]]*@\([^)]*"-InstallMissing"[^)]*\)' "$PACKAGED_RUN_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected bootstrap -InstallMissing forwarding marker in $PACKAGED_RUN_POWERSHELL_SCRIPT"
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
if ! grep -qF 'GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected GPM shared auto-install env marker in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
if ! grep -qF 'TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected TDPN shared auto-install legacy env alias marker in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
if ! grep -qF -- '--no-install-missing' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected --no-install-missing override marker in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
if ! rg -q -- '\$\{GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING:-\$\{TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING:-1\}\}|install_missing_effective[[:space:]]*=[[:space:]]*"?1"?|(effective_)?install(_missing|_intent)[[:space:]]*=[[:space:]]*"?1"?|default[^[:alnum:]]*(enable|enabled|true)[^[:alnum:]]*(install|auto[-_ ]?install)[^[:alnum:]]*missing' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected default-enabled install-intent marker in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
if ! rg -q -- 'if[[:space:]]*\[\[[^]]*(effective_install_missing|install_intent|install_missing|auto_install_missing)[^]]*(==|=|-eq)[^]]*("?1"?|true|enabled)[^]]*\]\]|if[[:space:]]*\[\[[^]]*(effective_install_missing|install_intent|install_missing|auto_install_missing)[^]]*\]\]' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected effective install-intent condition marker in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
if ! rg -q -- 'doctor_args\+\=\(--mode[[:space:]]+fix[[:space:]]+--install-missing\)' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected doctor fix-mode install-missing marker in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
if ! rg -q -- 'doctor_args\+\=\(--mode[[:space:]]+check\)' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected doctor check-mode fallback marker in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
if ! rg -q -- 'native_bootstrap_args\+\=\(--install-missing\)' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected native bootstrap --install-missing forwarding marker in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
if ! grep -qiE 'scaffold|non-production' "$LINUX_PACKAGED_RUN_SCRIPT"; then
  echo "desktop scaffold contract failed: expected scaffold/non-production marker in $LINUX_PACKAGED_RUN_SCRIPT"
  exit 1
fi
echo "[desktop-scaffold] linux packaged-run scaffold script markers are present"

LINUX_DEV_SCRIPT="scripts/linux/desktop_dev.sh"
if [[ ! -f "$LINUX_DEV_SCRIPT" ]]; then
  echo "desktop scaffold contract failed: missing linux desktop-dev scaffold script: $LINUX_DEV_SCRIPT"
  exit 1
fi
if ! grep -qF 'GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING' "$LINUX_DEV_SCRIPT"; then
  echo "desktop scaffold contract failed: expected GPM shared auto-install env marker in $LINUX_DEV_SCRIPT"
  exit 1
fi
if ! grep -qF 'TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING' "$LINUX_DEV_SCRIPT"; then
  echo "desktop scaffold contract failed: expected TDPN shared auto-install legacy env alias marker in $LINUX_DEV_SCRIPT"
  exit 1
fi
if ! grep -qF -- '--no-install-missing' "$LINUX_DEV_SCRIPT"; then
  echo "desktop scaffold contract failed: expected --no-install-missing marker in $LINUX_DEV_SCRIPT"
  exit 1
fi
if ! grep -qF 'conflicting install intent: specify only one of --install-missing or --no-install-missing' "$LINUX_DEV_SCRIPT"; then
  echo "desktop scaffold contract failed: expected conflict intent message marker in $LINUX_DEV_SCRIPT"
  exit 1
fi
if ! grep -qF -- '--mode run-desktop' "$LINUX_DEV_SCRIPT"; then
  echo "desktop scaffold contract failed: expected run-desktop launch mode marker in $LINUX_DEV_SCRIPT"
  exit 1
fi
if ! grep -qF -- '--desktop-launch-strategy dev' "$LINUX_DEV_SCRIPT"; then
  echo "desktop scaffold contract failed: expected desktop launch strategy dev marker in $LINUX_DEV_SCRIPT"
  exit 1
fi
echo "[desktop-scaffold] linux desktop-dev script markers are present"

WINDOWS_NATIVE_BOOTSTRAP_FILES=(
  "scripts/windows/desktop_native_bootstrap.ps1"
  "scripts/windows/desktop_native_bootstrap.cmd"
  "scripts/windows/local_api_session.ps1"
  "scripts/windows/local_api_session.cmd"
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
if ! grep -qF 'recommended_commands' "$WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected recommended_commands summary marker in $WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qF 'Get-RecommendedCommands' "$WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected recommended command helper marker in $WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qF 'recommended commands (copy/paste):' "$WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected copy/paste remediation output marker in $WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qF 'desktop_one_click.ps1' "$WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected one-click remediation marker in $WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qF 'Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force' "$WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected execution-policy remediation marker in $WINDOWS_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
DESKTOP_SHELL_FILES=(
  "scripts/windows/desktop_shell.ps1"
  "scripts/windows/desktop_shell.cmd"
)
for path in "${DESKTOP_SHELL_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "desktop scaffold contract failed: missing desktop_shell script: $path"
    exit 1
  fi
done
echo "[desktop-scaffold] desktop_shell scripts exist"

DESKTOP_SHELL_PS1="scripts/windows/desktop_shell.ps1"
DESKTOP_SHELL_CMD="scripts/windows/desktop_shell.cmd"

if ! grep -qF 'function Normalize-NodeToolName' "$DESKTOP_SHELL_PS1"; then
  echo "desktop scaffold contract failed: expected node tool normalization helper in $DESKTOP_SHELL_PS1"
  exit 1
fi
if ! grep -qF "'^(?i)npm(?:\\.(?:cmd|ps1))?$'" "$DESKTOP_SHELL_PS1"; then
  echo "desktop scaffold contract failed: expected npm normalization matcher in $DESKTOP_SHELL_PS1"
  exit 1
fi
if ! grep -qF 'return "npm.cmd"' "$DESKTOP_SHELL_PS1"; then
  echo "desktop scaffold contract failed: expected npm.cmd normalization target in $DESKTOP_SHELL_PS1"
  exit 1
fi
if ! grep -qF "'^(?i)npx(?:\\.(?:cmd|ps1))?$'" "$DESKTOP_SHELL_PS1"; then
  echo "desktop scaffold contract failed: expected npx normalization matcher in $DESKTOP_SHELL_PS1"
  exit 1
fi
if ! grep -qF 'return "npx.cmd"' "$DESKTOP_SHELL_PS1"; then
  echo "desktop scaffold contract failed: expected npx.cmd normalization target in $DESKTOP_SHELL_PS1"
  exit 1
fi
if ! grep -qF 'function Refresh-SessionPath' "$DESKTOP_SHELL_PS1"; then
  echo "desktop scaffold contract failed: expected PATH refresh helper in $DESKTOP_SHELL_PS1"
  exit 1
fi
if ! grep -qF '[Environment]::GetEnvironmentVariable("Path", "Machine")' "$DESKTOP_SHELL_PS1"; then
  echo "desktop scaffold contract failed: expected machine PATH refresh marker in $DESKTOP_SHELL_PS1"
  exit 1
fi
if ! grep -qF '[Environment]::GetEnvironmentVariable("Path", "User")' "$DESKTOP_SHELL_PS1"; then
  echo "desktop scaffold contract failed: expected user PATH refresh marker in $DESKTOP_SHELL_PS1"
  exit 1
fi
if ! rg -q -- '^Refresh-SessionPath$' "$DESKTOP_SHELL_PS1"; then
  echo "desktop scaffold contract failed: expected Refresh-SessionPath invocation marker in $DESKTOP_SHELL_PS1"
  exit 1
fi
if ! grep -qF '$commonToolDirs = @(Get-CommonToolDirectories)' "$DESKTOP_SHELL_PS1"; then
  echo "desktop scaffold contract failed: expected common tool directories marker in $DESKTOP_SHELL_PS1"
  exit 1
fi
if ! grep -qF 'Add-SessionPathSegments -Segments $commonToolDirs' "$DESKTOP_SHELL_PS1"; then
  echo "desktop scaffold contract failed: expected PATH augmentation marker in $DESKTOP_SHELL_PS1"
  exit 1
fi
echo "[desktop-scaffold] desktop_shell.ps1 normalization and PATH refresh markers are present"

if ! grep -qF 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command' "$DESKTOP_SHELL_CMD"; then
  echo "desktop scaffold contract failed: expected cmd wrapper policy-bypass command probe marker in $DESKTOP_SHELL_CMD"
  exit 1
fi
if ! grep -qF '[&|<>^%%!]' "$DESKTOP_SHELL_CMD"; then
  echo "desktop scaffold contract failed: expected cmd metacharacter reject marker in $DESKTOP_SHELL_CMD"
  exit 1
fi
if ! grep -qF 'Unsupported cmd metacharacters in arguments.' "$DESKTOP_SHELL_CMD"; then
  echo "desktop scaffold contract failed: expected cmd metacharacter reject message marker in $DESKTOP_SHELL_CMD"
  exit 1
fi
if ! grep -qF 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*' "$DESKTOP_SHELL_CMD"; then
  echo "desktop scaffold contract failed: expected cmd wrapper policy-bypass file execution marker in $DESKTOP_SHELL_CMD"
  exit 1
fi
echo "[desktop-scaffold] desktop_shell.cmd policy-bypass and metacharacter guard markers are present"

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
if ! grep -qF -- '--summary-json' "$LINUX_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected --summary-json marker in $LINUX_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qF -- '--print-summary-json' "$LINUX_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected --print-summary-json marker in $LINUX_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qF 'recommended_commands' "$LINUX_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected recommended_commands summary marker in $LINUX_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qF 'emit_summary_payload' "$LINUX_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected summary emitter marker in $LINUX_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
if ! grep -qF 'recommended remediation commands' "$LINUX_NATIVE_BOOTSTRAP_SCRIPT"; then
  echo "desktop scaffold contract failed: expected remediation output marker in $LINUX_NATIVE_BOOTSTRAP_SCRIPT"
  exit 1
fi
echo "[desktop-scaffold] linux native bootstrap script markers are present"

README_FILE="apps/desktop/README.md"

if ! rg -q -- 'GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must mention GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE packaged executable override"
  exit 1
fi

if ! rg -q -- 'GPM_DESKTOP_PACKAGED_EXE' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must mention GPM_DESKTOP_PACKAGED_EXE packaged executable override"
  exit 1
fi
if ! rg -q -- 'TDPN_DESKTOP_PACKAGED_EXE' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must mention TDPN_DESKTOP_PACKAGED_EXE compatibility alias override"
  exit 1
fi
if ! awk '
  BEGIN { IGNORECASE = 1 }
  {
    has_global[NR] = ($0 ~ /GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE/)
    has_gpm[NR] = ($0 ~ /GPM_DESKTOP_PACKAGED_EXE/)
    has_primary[NR] = (has_global[NR] || has_gpm[NR])
    has_tdpn[NR] = ($0 ~ /TDPN_DESKTOP_PACKAGED_EXE/)
    has_alias_term[NR] = ($0 ~ /(alias|legacy|compatibility|compat)/)
  }
  END {
    for (i = 1; i <= NR; i++) {
      if (!has_primary[i]) {
        continue
      }
      start = i - 8
      if (start < 1) {
        start = 1
      }
      end = i + 8
      if (end > NR) {
        end = NR
      }
      found_tdpn = 0
      found_alias_term = 0
      found_primary = 0
      for (j = start; j <= end; j++) {
        if (has_primary[j]) {
          found_primary = 1
        }
        if (has_tdpn[j]) {
          found_tdpn = 1
        }
        if (has_alias_term[j]) {
          found_alias_term = 1
        }
      }
      if (found_primary && found_tdpn && found_alias_term) {
        print "ok"
        exit 0
      }
    }
    exit 1
  }
' "$README_FILE" >/dev/null; then
  echo "desktop scaffold contract failed: README must describe GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE or GPM_DESKTOP_PACKAGED_EXE with TDPN_DESKTOP_PACKAGED_EXE legacy compatibility alias context"
  exit 1
fi

if ! awk '
  BEGIN { IGNORECASE = 1 }
  {
    lower = tolower($0)
    has_packaged[NR] = (lower ~ /packaged/)
    has_auto_discovery[NR] = (lower ~ /auto[-[:space:]]*discover(y)?/)
    has_order[NR] = (lower ~ /order/)
    has_env_override[NR] = (lower ~ /env(ironment(al)?)?[[:space:]]*overrides?|override[s]?[[:space:]]*env/)
    has_packaged_env[NR] = ($0 ~ /(GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE|GPM_DESKTOP_PACKAGED_EXE|TDPN_DESKTOP_PACKAGED_EXE)/)
  }
  END {
    for (i = 1; i <= NR; i++) {
      start = i - 8
      if (start < 1) {
        start = 1
      }
      end = i + 8
      if (end > NR) {
        end = NR
      }
      found_packaged = 0
      found_auto_discovery = 0
      found_order = 0
      found_env_override = 0
      found_packaged_env = 0
      for (j = start; j <= end; j++) {
        if (has_packaged[j]) {
          found_packaged = 1
        }
        if (has_auto_discovery[j]) {
          found_auto_discovery = 1
        }
        if (has_order[j]) {
          found_order = 1
        }
        if (has_env_override[j]) {
          found_env_override = 1
        }
        if (has_packaged_env[j]) {
          found_packaged_env = 1
        }
      }
      if (found_packaged && found_auto_discovery && found_order && found_env_override && found_packaged_env) {
        print "ok"
        exit 0
      }
    }
    exit 1
  }
' "$README_FILE" >/dev/null; then
  echo "desktop scaffold contract failed: README must document packaged executable auto-discovery order including env overrides"
  exit 1
fi

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
  if ! grep -qF 'GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING' "$ONE_CLICK_POWERSHELL_SCRIPT"; then
    echo "desktop scaffold contract failed: expected GPM one-click auto-install env marker in $ONE_CLICK_POWERSHELL_SCRIPT"
    exit 1
  fi
  if ! grep -qF 'TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING' "$ONE_CLICK_POWERSHELL_SCRIPT"; then
    echo "desktop scaffold contract failed: expected TDPN one-click auto-install legacy env alias marker in $ONE_CLICK_POWERSHELL_SCRIPT"
    exit 1
  fi
  if ! rg -q -- '-NoInstallMissing|\$NoInstallMissing' "$ONE_CLICK_POWERSHELL_SCRIPT"; then
    echo "desktop scaffold contract failed: expected -NoInstallMissing override marker in $ONE_CLICK_POWERSHELL_SCRIPT"
    exit 1
  fi
  if ! grep -qF '@("-Mode", "fix", "-InstallMissing")' "$ONE_CLICK_POWERSHELL_SCRIPT"; then
    echo "desktop scaffold contract failed: expected doctor fix/install remediation marker in $ONE_CLICK_POWERSHELL_SCRIPT"
    exit 1
  fi
  if ! rg -q -- 'invokeArgs[[:space:]]*\+=[[:space:]]*"-InstallMissing"|invokeArgs[[:space:]]*=[[:space:]]*@\([^)]*"-InstallMissing"[^)]*\)' "$ONE_CLICK_POWERSHELL_SCRIPT"; then
    echo "desktop scaffold contract failed: expected bootstrap -InstallMissing invocation marker in $ONE_CLICK_POWERSHELL_SCRIPT"
    exit 1
  fi
  if ! rg -q -- 'Test-ArgNamePresent[[:space:]]*-Args[[:space:]]*\$BootstrapArgs[[:space:]]*-Name[[:space:]]*"-InstallMissing"|Test-SwitchEnabled[[:space:]]*-Args[[:space:]]*\$BootstrapArgs[[:space:]]*-Name[[:space:]]*"-InstallMissing"' "$ONE_CLICK_POWERSHELL_SCRIPT"; then
    echo "desktop scaffold contract failed: expected one-click default-path InstallMissing decision marker in $ONE_CLICK_POWERSHELL_SCRIPT"
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

WINDOWS_DESKTOP_DEV_LAUNCHER_FILES=(
  "scripts/windows/desktop_dev.ps1"
  "scripts/windows/desktop_dev.cmd"
)
for path in "${WINDOWS_DESKTOP_DEV_LAUNCHER_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "desktop scaffold contract failed: missing windows desktop dev launcher script: $path"
    exit 1
  fi
done

WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT="scripts/windows/desktop_dev.ps1"
WINDOWS_DESKTOP_DEV_CMD_SCRIPT="scripts/windows/desktop_dev.cmd"

if ! grep -qF 'desktop_native_bootstrap.ps1' "$WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected desktop native bootstrap launcher reference in $WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"
  exit 1
fi
if ! grep -qiE 'run-desktop' "$WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected run-desktop mode marker in $WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"
  exit 1
fi
if ! rg -qi -- 'DesktopLaunchStrategy[^[:cntrl:]]*dev|desktop-launch-strategy[^[:cntrl:]]*dev' "$WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected DesktopLaunchStrategy dev marker in $WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"
  exit 1
fi
if ! grep -qF 'GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING' "$WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected GPM one-click auto-install env marker in $WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"
  exit 1
fi
if ! grep -qF 'TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING' "$WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected TDPN one-click auto-install legacy env alias marker in $WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"
  exit 1
fi
if ! rg -q -- '-NoInstallMissing|\$NoInstallMissing' "$WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected -NoInstallMissing override marker in $WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"
  exit 1
fi
if ! grep -qF 'conflicting install intent: specify only one of -InstallMissing or -NoInstallMissing' "$WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"; then
  echo "desktop scaffold contract failed: expected install-intent conflict message marker in $WINDOWS_DESKTOP_DEV_POWERSHELL_SCRIPT"
  exit 1
fi
if ! rg -qi -- 'powershell(\.exe)?' "$WINDOWS_DESKTOP_DEV_CMD_SCRIPT"; then
  echo "desktop scaffold contract failed: expected PowerShell invocation marker in $WINDOWS_DESKTOP_DEV_CMD_SCRIPT"
  exit 1
fi
if ! grep -qF 'desktop_dev.ps1' "$WINDOWS_DESKTOP_DEV_CMD_SCRIPT"; then
  echo "desktop scaffold contract failed: expected desktop_dev.ps1 launcher reference in $WINDOWS_DESKTOP_DEV_CMD_SCRIPT"
  exit 1
fi
if ! grep -qF 'desktop_dev.ps1' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must reference the windows desktop dev launcher script"
  exit 1
fi
echo "[desktop-scaffold] windows desktop dev launcher scripts and markers are present"

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
if ! grep -qF 'GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING' "$LINUX_ONE_CLICK_SCRIPT"; then
  echo "desktop scaffold contract failed: expected GPM one-click auto-install env marker in $LINUX_ONE_CLICK_SCRIPT"
  exit 1
fi
if ! grep -qF 'TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING' "$LINUX_ONE_CLICK_SCRIPT"; then
  echo "desktop scaffold contract failed: expected TDPN one-click auto-install legacy env alias marker in $LINUX_ONE_CLICK_SCRIPT"
  exit 1
fi
if ! grep -qF -- '--no-install-missing' "$LINUX_ONE_CLICK_SCRIPT"; then
  echo "desktop scaffold contract failed: expected --no-install-missing override marker in $LINUX_ONE_CLICK_SCRIPT"
  exit 1
fi
if ! rg -q -- '\$\{GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING:-\$\{TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING:-1\}\}|(INSTALL_MISSING|INSTALL_MISSING_EFFECTIVE|AUTO_INSTALL_MISSING)[[:space:]]*=[[:space:]]*"?1"?|default[^[:alnum:]]*(enable|enabled|true)[^[:alnum:]]*(install|auto[-_ ]?install)[^[:alnum:]]*missing' "$LINUX_ONE_CLICK_SCRIPT"; then
  echo "desktop scaffold contract failed: expected default-enabled auto-install fallback marker in $LINUX_ONE_CLICK_SCRIPT"
  exit 1
fi
if ! rg -q -- 'if[[:space:]].*(INSTALL_MISSING|INSTALL_MISSING_EFFECTIVE|AUTO_INSTALL_MISSING|EFFECTIVE_INSTALL_MISSING).*(==[[:space:]]*"?1"?|true|enabled)' "$LINUX_ONE_CLICK_SCRIPT"; then
  echo "desktop scaffold contract failed: expected effective install-intent condition marker in $LINUX_ONE_CLICK_SCRIPT"
  exit 1
fi
if ! rg -q -- 'bootstrap_args\+\=\(--install-missing\)|run_full_args\+\=\(--install-missing\)' "$LINUX_ONE_CLICK_SCRIPT"; then
  echo "desktop scaffold contract failed: expected bootstrap/run-full --install-missing forwarding marker in $LINUX_ONE_CLICK_SCRIPT"
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
LOCAL_API_SESSION_CMD_SCRIPT="scripts/windows/local_api_session.cmd"

if ! grep -qF 'local-api-session (windows-native):' "$LOCAL_API_SESSION_SCRIPT"; then
  echo "desktop scaffold contract failed: expected windows-native local API session banner marker in $LOCAL_API_SESSION_SCRIPT"
  exit 1
fi
if ! grep -qF 'go run ./cmd/node --local-api' "$LOCAL_API_SESSION_SCRIPT" && \
   {
     ! grep -qF '$goArgs = @("run", "./cmd/node")' "$LOCAL_API_SESSION_SCRIPT" || \
     ! grep -qF '$goArgs += @("--local-api")' "$LOCAL_API_SESSION_SCRIPT";
   }; then
  echo "desktop scaffold contract failed: expected local API go-run command marker in $LOCAL_API_SESSION_SCRIPT"
  exit 1
fi
if ! grep -qF '[switch]$InstallMissing' "$LOCAL_API_SESSION_SCRIPT"; then
  echo "desktop scaffold contract failed: expected InstallMissing parameter marker in $LOCAL_API_SESSION_SCRIPT"
  exit 1
fi
if ! grep -qF 'install_missing:' "$LOCAL_API_SESSION_SCRIPT"; then
  echo "desktop scaffold contract failed: expected install-missing status banner marker in $LOCAL_API_SESSION_SCRIPT"
  exit 1
fi
if ! grep -qF 'winget install --id GoLang.Go --exact' "$LOCAL_API_SESSION_SCRIPT"; then
  echo "desktop scaffold contract failed: expected Go install remediation marker in $LOCAL_API_SESSION_SCRIPT"
  exit 1
fi
if ! grep -qF -- '-ExecutionPolicy Bypass' "$LOCAL_API_SESSION_CMD_SCRIPT"; then
  echo "desktop scaffold contract failed: expected cmd wrapper policy-bypass marker in $LOCAL_API_SESSION_CMD_SCRIPT"
  exit 1
fi
if ! grep -qF 'Unsupported cmd metacharacters' "$LOCAL_API_SESSION_CMD_SCRIPT"; then
  echo "desktop scaffold contract failed: expected cmd metacharacter reject marker in $LOCAL_API_SESSION_CMD_SCRIPT"
  exit 1
fi
echo "[desktop-scaffold] local API session wrappers and markers are present"

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
if ! grep -qF 'id="operator_approval_policy_hint"' "$DESKTOP_HTML_FILE"; then
  echo "desktop scaffold contract failed: missing operator approval policy hint marker in $DESKTOP_HTML_FILE"
  exit 1
fi
if ! grep -qF 'id="legacy_compat_section"' "$DESKTOP_HTML_FILE"; then
  echo "desktop scaffold contract failed: missing legacy compatibility section marker in $DESKTOP_HTML_FILE"
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

OPTIONAL_AUTH_METADATA_HTML_ID_PATTERNS=(
  'id="(auth_)?signature_kind"'
  'id="(auth_)?signature_public_key"'
  'id="(auth_)?signature_public_key_type"'
  'id="(auth_)?signature_source"'
  'id="(auth_)?signature_envelope"'
)
for pattern in "${OPTIONAL_AUTH_METADATA_HTML_ID_PATTERNS[@]}"; do
  if ! grep -Eq "$pattern" "$DESKTOP_HTML_FILE"; then
    echo "desktop scaffold contract failed: missing optional auth metadata input marker ($pattern) in $DESKTOP_HTML_FILE"
    exit 1
  fi
done
if ! grep -Eq 'id="(auth_)?(chain_id|wallet_chain_id)"' "$DESKTOP_HTML_FILE"; then
  echo "desktop scaffold contract failed: missing optional auth chain-id input marker (expected chain_id or wallet_chain_id) in $DESKTOP_HTML_FILE"
  exit 1
fi
if ! grep -Eq 'id="(auth_)?(signed_message|challenge_message)"' "$DESKTOP_HTML_FILE"; then
  echo "desktop scaffold contract failed: missing optional signed-message input marker (expected signed_message or challenge_message) in $DESKTOP_HTML_FILE"
  exit 1
fi
echo "[desktop-scaffold] optional auth metadata input markers are present"

assert_auth_verify_request_marker() {
  local field_label="$1"
  local marker_pattern="$2"
  if ! rg -q -- "$marker_pattern" "$JS_FILE"; then
    echo "desktop scaffold contract failed: missing auth verify request wiring marker for $field_label in $JS_FILE"
    exit 1
  fi
}

assert_auth_verify_request_marker \
  "signature_kind" \
  'request\.[[:space:]]*signature_kind\b|\bsignature_kind\b[[:space:]]*:'
assert_auth_verify_request_marker \
  "signature_public_key" \
  'request\.[[:space:]]*signature_public_key\b|\bsignature_public_key\b[[:space:]]*:'
assert_auth_verify_request_marker \
  "signature_public_key_type" \
  'request\.[[:space:]]*signature_public_key_type\b|\bsignature_public_key_type\b[[:space:]]*:'
assert_auth_verify_request_marker \
  "signature_source" \
  'request\.[[:space:]]*signature_source\b|\bsignature_source\b[[:space:]]*:'
assert_auth_verify_request_marker \
  "chain_id" \
  'request\.[[:space:]]*chain_id\b|\bchain_id\b[[:space:]]*:'
assert_auth_verify_request_marker \
  "signed_message" \
  'request\.[[:space:]]*signed_message\b|\bsigned_message\b[[:space:]]*:'
assert_auth_verify_request_marker \
  "signature_envelope" \
  'request\.[[:space:]]*signature_envelope\b|\bsignature_envelope\b[[:space:]]*:'
if ! rg -q -- 'control_gpm_auth_verify' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing auth verify bridge marker in $JS_FILE"
  exit 1
fi
echo "[desktop-scaffold] auth verify metadata request wiring markers are present"

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
if ! grep -qF 'state.allowLegacyConnectOverride' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing allowLegacyConnectOverride policy-state marker in $JS_FILE"
  exit 1
fi
if ! grep -qF 'function syncCompatAdvancedVisibility()' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing compat advanced visibility policy marker in $JS_FILE"
  exit 1
fi
if ! grep -qF 'compatAdvancedSectionEl.hidden = !visible;' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing compat advanced hide-by-policy marker in $JS_FILE"
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
if ! grep -qF 'function requireClientControlEligibility(actionLabel)' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing client control eligibility guard helper in $JS_FILE"
  exit 1
fi
if ! grep -qF 'function readRuntimeOperatorApprovalPolicyMetadata(runtimeCfg)' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing runtime operator-approval policy parser in $JS_FILE"
  exit 1
fi
if ! grep -qF 'function updateOperatorApprovalPolicyHint()' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing operator approval policy hint updater in $JS_FILE"
  exit 1
fi
if ! grep -qF 'formatOperatorApprovalPolicySourceHint(' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing operator approval policy source hint formatter usage in $JS_FILE"
  exit 1
fi
if ! grep -qF 'state.operatorApprovalRequireSession' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing operator approval strictness state marker in $JS_FILE"
  exit 1
fi
if ! grep -qF 'requireSessionToken("approve an operator")' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing explicit session-token gate for approve operator action in $JS_FILE"
  exit 1
fi
if ! grep -qF 'function requireServerTabEligibility(actionLabel)' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing server tab eligibility guard helper in $JS_FILE"
  exit 1
fi
if ! grep -qF 'function requireServerLifecycleEligibility(actionLabel)' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing server lifecycle eligibility guard helper in $JS_FILE"
  exit 1
fi
if ! grep -qF 'const reason = computeClientLockHintText();' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing client lock hint reason marker in guard helper in $JS_FILE"
  exit 1
fi
if ! grep -qF 'const reason = computeServerLockHintText();' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing server lock hint reason marker in guard helper in $JS_FILE"
  exit 1
fi

assert_handler_guard_marker() {
  local handler_start="$1"
  local guard_marker="$2"
  local label="$3"
  local handler_snippet
  handler_snippet="$(sed -n "/$handler_start/,/^});/p" "$JS_FILE")"
  if [[ -z "$handler_snippet" ]]; then
    echo "desktop scaffold contract failed: missing handler block for $label in $JS_FILE"
    exit 1
  fi
  if ! printf '%s\n' "$handler_snippet" | grep -qF "$guard_marker"; then
    echo "desktop scaffold contract failed: missing handler-level lock guard marker '$guard_marker' for $label in $JS_FILE"
    exit 1
  fi
}

assert_handler_guard_marker \
  'byId("register_client_btn").addEventListener("click", async () => {' \
  'requireClientControlEligibility("Register client profile")' \
  "register_client_btn"
assert_handler_guard_marker \
  'byId("connect_btn").addEventListener("click", async () => {' \
  'requireClientControlEligibility("Connect")' \
  "connect_btn"
assert_handler_guard_marker \
  'byId("service_status_btn").addEventListener("click", async () => {' \
  'requireServerTabEligibility("Check service status")' \
  "service_status_btn"
assert_handler_guard_marker \
  'byId("service_start_btn").addEventListener("click", async () => {' \
  'requireServerLifecycleEligibility("Start service")' \
  "service_start_btn"
assert_handler_guard_marker \
  'byId("service_stop_btn").addEventListener("click", async () => {' \
  'requireServerLifecycleEligibility("Stop service")' \
  "service_stop_btn"
assert_handler_guard_marker \
  'byId("service_restart_btn").addEventListener("click", async () => {' \
  'requireServerLifecycleEligibility("Restart service")' \
  "service_restart_btn"

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

SYNC_SERVER_MUTATION_SNIPPET="$(sed -n '/function syncServerMutationControls(/,/^}/p' "$JS_FILE")"
if [[ -z "$SYNC_SERVER_MUTATION_SNIPPET" ]]; then
  echo "desktop scaffold contract failed: missing syncServerMutationControls function block in $JS_FILE"
  exit 1
fi
if ! printf '%s\n' "$SYNC_SERVER_MUTATION_SNIPPET" | grep -qF 'const serviceMutationsConfigured = state.serverReadiness?.serviceMutationsConfigured !== false;'; then
  echo "desktop scaffold contract failed: missing explicit serviceMutationsConfigured=false lifecycle disable marker in syncServerMutationControls in $JS_FILE"
  exit 1
fi
if ! printf '%s\n' "$SYNC_SERVER_MUTATION_SNIPPET" | grep -qF 'state.serviceMutationsAllowed && serviceMutationsConfigured && isServerMutationRoleEligible();'; then
  echo "desktop scaffold contract failed: missing lifecycle disable gating marker that combines policy, readiness serviceMutationsConfigured, and role eligibility in $JS_FILE"
  exit 1
fi
if ! grep -qF 'serviceStartBtnEl.disabled = !mutationsEnabled;' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing service start disabled marker in $JS_FILE"
  exit 1
fi
if ! grep -qF 'serviceStopBtnEl.disabled = !mutationsEnabled;' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing service stop disabled marker in $JS_FILE"
  exit 1
fi
if ! grep -qF 'serviceRestartBtnEl.disabled = !mutationsEnabled;' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing service restart disabled marker in $JS_FILE"
  exit 1
fi
if ! grep -qF 'else if (readiness.serviceMutationsConfigured === false) {' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing readiness-driven serviceMutationsConfigured=false lock hint branch in $JS_FILE"
  exit 1
fi
echo "[desktop-scaffold] server lifecycle controls include explicit disable semantics for readiness serviceMutationsConfigured=false"

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
assert_parse_readiness_fallback_pair \
  "clientRegistrationStatus" \
  'readiness[[:space:]]*\.[[:space:]]*(client_registration_status|registration_status)|readiness\[[^]]*(client_registration_status|registration_status)[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*(clientRegistrationStatus|registrationStatus)|readiness\[[^]]*(clientRegistrationStatus|registrationStatus)[^]]*\]'
assert_parse_readiness_fallback_pair \
  "registrationTrustStatus" \
  'readiness[[:space:]]*\.[[:space:]]*(registration_trust_status|bootstrap_trust_status|session_bootstrap_trust_status|trust_status)|readiness\[[^]]*(registration_trust_status|bootstrap_trust_status|session_bootstrap_trust_status|trust_status)[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*(registrationTrustStatus|bootstrapTrustStatus|sessionBootstrapTrustStatus|trustStatus)|readiness\[[^]]*(registrationTrustStatus|bootstrapTrustStatus|sessionBootstrapTrustStatus|trustStatus)[^]]*\]'
assert_parse_readiness_fallback_pair \
  "registrationTrustDegraded" \
  'readiness[[:space:]]*\.[[:space:]]*(registration_trust_degraded|bootstrap_trust_degraded|session_bootstrap_trust_degraded|manifest_drift_detected|trust_drift_detected|trust_degraded|bootstrap_trust_revoked|session_bootstrap_revoked)|readiness\[[^]]*(registration_trust_degraded|bootstrap_trust_degraded|session_bootstrap_trust_degraded|manifest_drift_detected|trust_drift_detected|trust_degraded|bootstrap_trust_revoked|session_bootstrap_revoked)[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*(registrationTrustDegraded|bootstrapTrustDegraded|sessionBootstrapTrustDegraded|manifestDriftDetected|trustDriftDetected|trustDegraded|bootstrapTrustRevoked|sessionBootstrapRevoked)|readiness\[[^]]*(registrationTrustDegraded|bootstrapTrustDegraded|sessionBootstrapTrustDegraded|manifestDriftDetected|trustDriftDetected|trustDegraded|bootstrapTrustRevoked|sessionBootstrapRevoked)[^]]*\]'
assert_parse_readiness_fallback_pair \
  "registrationReregisterRequired" \
  'readiness[[:space:]]*\.[[:space:]]*(re_register_required|reregister_required|registration_refresh_required|requires_reregistration)|readiness\[[^]]*(re_register_required|reregister_required|registration_refresh_required|requires_reregistration)[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*(reRegisterRequired|reregisterRequired|registrationRefreshRequired|requiresReregistration)|readiness\[[^]]*(reRegisterRequired|reregisterRequired|registrationRefreshRequired|requiresReregistration)[^]]*\]'
assert_parse_readiness_fallback_pair \
  "registrationTrustReason" \
  'readiness[[:space:]]*\.[[:space:]]*(registration_trust_reason|bootstrap_trust_reason|session_bootstrap_trust_reason|trust_reason|manifest_drift_reason|re_register_reason|registration_lock_reason)|readiness\[[^]]*(registration_trust_reason|bootstrap_trust_reason|session_bootstrap_trust_reason|trust_reason|manifest_drift_reason|re_register_reason|registration_lock_reason)[^]]*\]' \
  'readiness[[:space:]]*\.[[:space:]]*(registrationTrustReason|bootstrapTrustReason|sessionBootstrapTrustReason|trustReason|manifestDriftReason|reRegisterReason|registrationLockReason)|readiness\[[^]]*(registrationTrustReason|bootstrapTrustReason|sessionBootstrapTrustReason|trustReason|manifestDriftReason|reRegisterReason|registrationLockReason)[^]]*\]'
echo "[desktop-scaffold] parseServerReadiness fallback markers are present for snake_case and camelCase readiness fields"

if ! grep -qF 'function setClientRegistrationStateFromPayload(payload, options = {}) {' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing client registration trust-state merge helper in $JS_FILE"
  exit 1
fi
if ! grep -qF 'setClientRegistrationStateFromPayload({ readiness }, { allowFallback: false, preserveWhenUnknown: true });' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing server-readiness trust merge marker in $JS_FILE"
  exit 1
fi
if ! grep -qF 'if (state.clientRegistrationTrustDegraded || state.clientRegistrationReregisterRequired) {' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing client trust-drift lock-hint guard marker in $JS_FILE"
  exit 1
fi
if ! grep -qF 'function clientRegistrationTrustHintText() {' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing client trust-drift hint helper in $JS_FILE"
  exit 1
fi
if ! grep -qF 'Re-register client profile to refresh trusted bootstrap directories before connecting.' "$JS_FILE"; then
  echo "desktop scaffold contract failed: missing re-register guidance marker for trust drift in $JS_FILE"
  exit 1
fi
echo "[desktop-scaffold] client registration trust-drift readiness markers are present"

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

DESKTOP_PACKAGE_JSON="apps/desktop/package.json"
DESKTOP_CARGO_TOML="apps/desktop/src-tauri/Cargo.toml"
DESKTOP_TAURI_CONFIG_JSON="apps/desktop/src-tauri/tauri.conf.json"
EXPECTED_GPM_PACKAGE_NAME="gpm-desktop"
EXPECTED_GPM_IDENTIFIER="com.gpm.desktop"

package_json_name="$(jq -r '.name // empty' "$DESKTOP_PACKAGE_JSON")"
if [[ "$package_json_name" != "$EXPECTED_GPM_PACKAGE_NAME" ]]; then
  echo "desktop scaffold contract failed: desktop package.json name must be GPM-first ($EXPECTED_GPM_PACKAGE_NAME), found '$package_json_name'"
  exit 1
fi

cargo_package_name="$(
  awk -F'=' '
    /^\[package\][[:space:]]*$/ {
      in_package = 1
      next
    }
    /^\[/ {
      if (in_package) {
        exit
      }
    }
    in_package && $1 ~ /^[[:space:]]*name[[:space:]]*$/ {
      value = $2
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      gsub(/^"/, "", value)
      gsub(/"$/, "", value)
      print value
      exit
    }
  ' "$DESKTOP_CARGO_TOML"
)"
if [[ -z "$cargo_package_name" ]]; then
  echo "desktop scaffold contract failed: unable to resolve [package].name from $DESKTOP_CARGO_TOML"
  exit 1
fi
if [[ "$cargo_package_name" != "$package_json_name" ]]; then
  echo "desktop scaffold contract failed: desktop package names must match across package.json ($package_json_name) and Cargo.toml ($cargo_package_name)"
  exit 1
fi
if [[ "$cargo_package_name" != "$EXPECTED_GPM_PACKAGE_NAME" ]]; then
  echo "desktop scaffold contract failed: desktop Cargo package name must be GPM-first ($EXPECTED_GPM_PACKAGE_NAME), found '$cargo_package_name'"
  exit 1
fi

tauri_identifier="$(jq -r '.identifier // empty' "$DESKTOP_TAURI_CONFIG_JSON")"
if [[ "$tauri_identifier" != "$EXPECTED_GPM_IDENTIFIER" ]]; then
  echo "desktop scaffold contract failed: desktop tauri identifier must be GPM-first ($EXPECTED_GPM_IDENTIFIER), found '$tauri_identifier'"
  exit 1
fi
echo "[desktop-scaffold] desktop metadata is GPM-first (name/identifier) while runtime legacy compatibility aliases remain contract-checked elsewhere"

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
if ! rg -q -- 'desktop_shell\.cmd' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must document desktop_shell.cmd execution-policy-safe npm wrapper usage"
  exit 1
fi
if ! rg -qi -- 'execution-policy-safe|policy-safe.*desktop_shell|desktop_shell.*policy-safe' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must explicitly describe desktop_shell as an execution-policy-safe wrapper"
  exit 1
fi
if ! rg -q -- 'desktop_shell\.cmd npm install' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must include desktop_shell npm install usage guidance"
  exit 1
fi
if ! rg -q -- 'desktop_shell\.cmd npm run tauri -- dev' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must include desktop_shell npm run tauri -- dev usage guidance"
  exit 1
fi
if ! rg -qi -- 'scripts\\windows\\local_api_session\.cmd' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must reference scripts\\\\windows\\\\local_api_session.cmd"
  exit 1
fi
if ! rg -qi -- 'powershell[[:space:]]+-NoProfile[[:space:]]+-ExecutionPolicy[[:space:]]+Bypass[[:space:]]+-File[[:space:]]+\.\\scripts\\windows\\local_api_session\.ps1[[:space:]]+-DryRun' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must include local_api_session.ps1 execution-policy bypass dry-run guidance"
  exit 1
fi
if ! rg -qi -- 'npm\.ps1|npm\.cmd|npx\.cmd' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must explain npm.cmd/npx.cmd policy-safe guidance"
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

README_LINUX_RELEASE_SECTION="$(
  sed -n '/^## Linux Release Bundle Scaffold (Non-Production)/,/^## /p' "$README_FILE" \
    | sed '$d'
)"
if [[ -z "$README_LINUX_RELEASE_SECTION" ]]; then
  echo "desktop scaffold contract failed: README missing Linux release bundle section content"
  exit 1
fi
if ! printf '%s\n' "$README_LINUX_RELEASE_SECTION" | rg -q -- 'desktop_doctor\.sh'; then
  echo "desktop scaffold contract failed: README Linux release bundle section must reference desktop_doctor.sh remediation"
  exit 1
fi
if ! printf '%s\n' "$README_LINUX_RELEASE_SECTION" | grep -qF -- '--install-missing'; then
  echo "desktop scaffold contract failed: README Linux release bundle section must mention --install-missing remediation"
  exit 1
fi
if ! printf '%s\n' "$README_LINUX_RELEASE_SECTION" | rg -qi -- '--mode([[:space:]]+|=)fix|(^|[[:space:]])fix([[:space:]]|$)'; then
  echo "desktop scaffold contract failed: README Linux release bundle section must mention desktop_doctor fix mode"
  exit 1
fi
echo "[desktop-scaffold] README states scaffold/non-production intent"

echo "desktop scaffold contract integration check ok"
