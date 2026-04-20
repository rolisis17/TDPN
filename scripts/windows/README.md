# Windows Native Script Notes

## One-shot prerequisite setup/remediation

Use `setup_windows_native.ps1` to verify and optionally remediate common Windows-native blockers for desktop/local API workflows.

Check-only (safe default):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\setup_windows_native.ps1 -Workflow both
```

Dry-run remediation preview:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\setup_windows_native.ps1 -Workflow both -InstallMissing -DryRun
```

Unattended remediation (no prompts):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\setup_windows_native.ps1 -Workflow both -InstallMissing -NonInteractive -EnablePolicyBypass
```

Workflow options:
- `-Workflow desktop`: prioritize `node`, `npm.cmd`, `rustc`, `cargo`; Git Bash is advisory.
- `-Workflow local-api`: prioritize `go` and Git Bash (`bash.exe` from Git for Windows).
- `-Workflow both` (default): union of both workflows.

Behavior highlights:
- non-destructive by default (`-InstallMissing` is required for installs)
- process-only execution policy bypass (`-EnablePolicyBypass`)
- session PATH refresh from machine/user PATH (+ common tool directories)
- deterministic follow-up commands (`next command:` output)

## Follow-on scripts

After setup succeeds, common next steps are:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\local_api_session.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_dev.ps1 -DryRun
```
