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

Fail (exit code `1`) if blockers are found:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_first_run_remediation.ps1 -FailOnIssues
```

## What it checks

- PowerShell execution policy state (`Process`, `CurrentUser`, `LocalMachine`, effective policy)
- Go availability (`go`)
- Node availability (`node`)
- Rust availability (`rustc` + `cargo`)
- `npm.ps1` resolver risk (including missing sibling `npm.cmd`)

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

Single bootstrap command that applies policy-safe setup and missing-tool install flow:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_native_bootstrap.ps1 -Mode bootstrap -InstallMissing -EnablePolicyBypass
```

## Existing helper wiring

`desktop_one_click.ps1` now invokes this helper in compact mode as a non-blocking preflight:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_one_click.ps1
```

This preflight prints hints but does not alter core one-click runtime behavior or failure gating.
