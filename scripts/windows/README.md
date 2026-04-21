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
- routes child script launches through `powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File ...`
- finishes with a verification block for `go version`, `node -v`, `npm -v`, `rustc -V`, and `cargo -V`

Expected healthy output at the end:
- each tool line says `PASS`
- the summary line says `summary: pass=5 fail=0`

## Troubleshooting

### Execution policy blocks `.ps1` files

Run the process-scope bypass once in the current shell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

Expected output:
- the command returns to the prompt without changing machine or user policy
- `Get-ExecutionPolicy -Scope Process` prints `Bypass`

If you want to rerun setup immediately with the bypass baked in:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\setup_windows_native.ps1 -Workflow both -InstallMissing -NonInteractive -EnablePolicyBypass
```

Expected output:
- `execution policy: effective=...`
- `final verification:`
- `summary: pass=5 fail=0` when all tools are installed and reachable

### Go, Node, npm, Rust, or cargo still look missing after install

Run the setup again so it refreshes the current session `PATH` from machine/user entries and the common install directories:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\setup_windows_native.ps1 -Workflow both -InstallMissing -EnablePolicyBypass
```

Then confirm the commands resolve from the current shell:

```powershell
Get-Command go,node,npm,npm.cmd,rustc,cargo | Select-Object Name,Source
```

Expected output:
- `go.exe` from `C:\Program Files\Go\bin\go.exe`
- `node.exe` from `C:\Program Files\nodejs\node.exe`
- `npm.cmd` from `C:\Program Files\nodejs\npm.cmd`
- `rustc.exe` from `C:\Users\<you>\.cargo\bin\rustc.exe`
- `cargo.exe` from `C:\Users\<you>\.cargo\bin\cargo.exe`

### `npm.ps1` is blocked by execution policy

Use the policy-safe wrapper so Node package commands route to `npm.cmd` instead of the PowerShell shim:

```powershell
scripts\windows\desktop_node.cmd npm -v
scripts\windows\desktop_node.cmd npm install
scripts\windows\desktop_node.cmd npm run tauri -- dev
```

Expected output:
- the wrapper runs without a PowerShell execution-policy error
- `npm -v` prints a version number
- install and `tauri -- dev` commands flow through `npm.cmd`

## Follow-on scripts

After setup succeeds, common next steps are:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\local_api_session.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_dev.ps1 -DryRun
```

## Policy-safe npm and npx wrapper

If PowerShell blocks `npm.ps1`, use the Node wrapper below instead of raw `npm`:

```powershell
scripts\windows\desktop_node.cmd npm install
scripts\windows\desktop_node.cmd npm run tauri -- dev
scripts\windows\desktop_node.cmd npx --yes create-vite@latest
```

Notes:
- defaults to `npm` when you omit the tool token:
  - `scripts\windows\desktop_node.cmd install`
- always runs with process-scope `ExecutionPolicy Bypass`
- routes through `desktop_shell` so `npm`/`npx` resolve to `npm.cmd`/`npx.cmd`
