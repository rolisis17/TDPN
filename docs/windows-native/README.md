# Windows Native First-Run Auto-Remediation Helper

Use the first-run helper to diagnose common Windows-native blockers without changing runtime behavior.

## Diagnose only (safe default)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_first_run_remediation.ps1
```

Compact output:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_first_run_remediation.ps1 -Compact
```

Emit machine-readable summary:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_first_run_remediation.ps1 -PrintSummaryJson
```

Apply only safe local-session remediation (process-scope policy bypass) and then re-check:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_first_run_remediation.ps1 -Apply
```

Fail (exit code `1`) if blockers are found:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_first_run_remediation.ps1 -FailOnIssues
```

## What it checks

- PowerShell execution policy state (`Process`, `CurrentUser`, `LocalMachine`, effective policy)
- Go availability (`go`)
- Node availability (`node`)
- npm availability (`npm`)
- Rust availability (`rustc` + `cargo`)
- Git Bash presence used by `local_api_session.ps1` (`LOCAL_CONTROL_API_GIT_BASH_PATH` + trusted default paths)
- `npm.ps1` resolver risk (including missing sibling `npm.cmd`)
- desktop icon/resource readiness:
  - `apps/desktop/src-tauri/icons/icon.svg` exists
  - `apps/desktop/src-tauri/icons/icon.ico` is present and valid ICO bytes
  - `apps/desktop/src-tauri/tauri.conf.json` contains `bundle.icon` entry `icons/icon.ico`
- concise check summary (`summary: pass=<N> fail=<N> status=PASS|FAIL`)

`-Apply` is intentionally non-destructive: it only attempts `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` in the current shell process.

## Safe one-command remediation hints

Process-scope execution policy bypass for the current shell only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

Install missing toolchains:

```powershell
winget install --id GoLang.Go --exact --accept-package-agreements --accept-source-agreements
winget install --id OpenJS.NodeJS.LTS --exact --accept-package-agreements --accept-source-agreements
winget install --id Rustlang.Rustup --exact --accept-package-agreements --accept-source-agreements
```

Avoid `npm.ps1` resolver issues in locked-down shells:

```powershell
.\scripts\windows\desktop_node.cmd npm -v
```

Desktop icon/resource remediation commands:

```powershell
git checkout -- apps/desktop/src-tauri/icons/icon.svg
.\scripts\windows\desktop_node.cmd npm run generate:windows-icon
powershell -NoProfile -ExecutionPolicy Bypass -Command "$cfg='apps/desktop/src-tauri/tauri.conf.json'; $json=Get-Content -Raw -LiteralPath $cfg | ConvertFrom-Json; if($null -eq $json.bundle){$json | Add-Member -NotePropertyName bundle -NotePropertyValue ([pscustomobject]@{})}; $icons=@(); if($null -ne $json.bundle.icon){$icons=@($json.bundle.icon)}; if($icons -notcontains 'icons/icon.ico'){$json.bundle.icon=@($icons + 'icons/icon.ico')}; $json | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $cfg -Encoding UTF8"
```

Single bootstrap command that applies policy-safe setup and missing-tool install flow:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_native_bootstrap.ps1 -Mode bootstrap -InstallMissing -EnablePolicyBypass
```

One-command Windows installer build path (WSL not required):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_installer.ps1 -Mode build -InstallMissing
```

`-Mode build` behavior:
- runs `desktop_doctor.ps1` preflight first
- auto-attempts remediation when `-InstallMissing` is set
- fails closed on unresolved blockers with copy/paste remediation commands
- builds release bundle artifacts and resolves installer outputs from `apps/desktop/src-tauri/target/release/bundle`

## Existing helper wiring

`desktop_one_click.ps1` now invokes this helper in compact mode as a non-blocking preflight:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_one_click.ps1
```

This preflight prints hints but does not alter core one-click runtime behavior or failure gating.
