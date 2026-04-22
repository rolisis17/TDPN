# Windows Native Script Notes

## One-shot prerequisite setup/remediation

Use `setup_windows_native.ps1` to verify and optionally remediate common Windows-native blockers for desktop and local API workflows.

Check-only, safe default:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\setup_windows_native.ps1 -Workflow both
```

Dry-run remediation preview:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\setup_windows_native.ps1 -Workflow both -InstallMissing -DryRun
```

Unattended remediation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\setup_windows_native.ps1 -Workflow both -InstallMissing -NonInteractive -EnablePolicyBypass
```

What the script does:
- detects and reports current execution policy
- prints the one-command process-scope bypass if the shell is locked down: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`
- refreshes the session `PATH` from machine/user values and common install locations
- resolves Node tooling to `npm.cmd`/`npx.cmd` (never `npm.ps1`/`npx.ps1`) for policy-safe invocation
- routes child script launches through `powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File ...`
- finishes with a verification block for `go version`, `node -v`, `npm -v`, `npx -v`, `rustc -V`, and `cargo -V`

Expected healthy output at the end:
- each tool line says `PASS`
- the summary line says `summary: pass=6 fail=0`

## Troubleshooting (Copy/Paste)

### 1) PowerShell blocks `npm.ps1` (`PSSecurityException`)

Symptoms:
- `npm : File ...\\npm.ps1 cannot be loaded because running scripts is disabled`

Fix in current shell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

Then run Node commands through the wrapper (avoid direct `npm` in locked shells):

```powershell
scripts\windows\desktop_node.cmd npm -v
scripts\windows\desktop_node.cmd npm install
scripts\windows\desktop_node.cmd npm run tauri -- dev
scripts\windows\desktop_node.cmd npx --yes create-vite@latest
```

### 2) `go` / `node` / `npm` / `rustc` / `cargo` not found in PowerShell

Use the bootstrap wrapper to install missing tools (when available) and refresh PATH for this session:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_native_bootstrap.ps1 -Mode bootstrap -InstallMissing -EnablePolicyBypass
```

Verify from wrappers (not manual PATH guessing):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_native_bootstrap.ps1 -Mode check -EnablePolicyBypass
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\local_api_session.ps1 -DryRun
```

### 3) Tauri build fails with missing `icons/icon.ico`

Symptoms:
- `icons/icon.ico not found; required for generating a Windows Resource file during tauri-build`

Use the desktop bootstrap wrapper; it scaffolds a placeholder icon when missing:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_native_bootstrap.ps1 -Mode run-desktop -InstallMissing -EnablePolicyBypass
```

If you only want to regenerate the icon and rerun dev via wrapper:

```powershell
scripts\windows\desktop_node.cmd npm run generate:windows-icon
scripts\windows\desktop_node.cmd npm run tauri -- dev
```

## Wrapper-First Flow

End-to-end desktop + local API with policy-safe defaults:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_one_click.ps1 -InstallMissing -EnablePolicyBypass
```

Local API only:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\local_api_session.ps1
```

Once that local-API prerequisite check is healthy, run the real-host evidence cycle from a repo shell with `./scripts/easy_node.sh profile-default-gate-stability-cycle ...`.
