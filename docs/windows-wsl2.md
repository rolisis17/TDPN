# Windows 11 + WSL2 Beta Run Guide

This project can run for beta testing on Windows 11 using WSL2 and Docker Desktop.

## 1) Prerequisites (Windows side)

- Windows 11 with WSL2 enabled.
- A Linux distro installed in WSL (Ubuntu recommended).
- Docker Desktop installed and running.
- Docker Desktop WSL integration enabled for your distro:
  - Docker Desktop -> Settings -> Resources -> WSL Integration.

Optional but recommended:
- Windows Terminal

## 2) One-command bootstrap from PowerShell

From the repository root (PowerShell):

```powershell
./scripts/windows/wsl2_bootstrap.ps1
```

From `cmd.exe` (or double-click):

```cmd
scripts\windows\wsl2_bootstrap.cmd
```

Optional parameters:

```powershell
./scripts/windows/wsl2_bootstrap.ps1 -Distro Ubuntu-22.04
./scripts/windows/wsl2_bootstrap.ps1 -NoAutoInstall
```

What this does:
- enters WSL
- runs `scripts/install_wsl2_mode.sh`
- checks Docker access from WSL
- installs missing Linux dependencies (unless `-NoAutoInstall`)
- builds `bin/privacynode-easy` inside WSL

## 3) Start the simple launcher

From PowerShell:

```powershell
./scripts/windows/wsl2_run_easy.ps1
```

From `cmd.exe`:

```cmd
scripts\windows\wsl2_run_easy.cmd
```

Combined `.cmd` helper:

```cmd
scripts\windows\wsl2_easy.cmd bootstrap
scripts\windows\wsl2_easy.cmd run
```

Or directly in WSL shell:

```bash
./bin/privacynode-easy
```

## 4) Desktop release bundle scaffold (Windows-native, non-production)

This flow is scaffold-only. It is not a production signing/release pipeline.

Update channel env:
- `GPM_DESKTOP_UPDATE_CHANNEL=stable|beta|canary` (default in script: `stable`, legacy alias: `TDPN_DESKTOP_UPDATE_CHANNEL`)

Optional update feed URL env:
- `GPM_DESKTOP_UPDATE_FEED_URL=https://updates.example.invalid/gpm/beta.json` (legacy alias: `TDPN_DESKTOP_UPDATE_FEED_URL`)

Run from repository root in PowerShell:

```powershell
./scripts/windows/desktop_release_bundle.ps1 -Channel beta
```

From `cmd.exe`:

```cmd
scripts\windows\desktop_release_bundle.cmd -Channel beta
```

Optional scaffold signing placeholders:
- `-SigningIdentity`
- `-SigningCertPath`
- `-SigningCertPassword`
- `-SigningCertPassword` is a scaffold placeholder only; do not echo or log this value.

Scaffold guardrails now enforced by script:
- `-UpdateFeedUrl` must be an absolute `http/https` URL.
- non-local update feeds (anything except `localhost`/loopback) must use `https`.
- `-SigningCertPassword` is allowed only when `-SigningCertPath` is provided.
- when `-SigningCertPath` is provided, the certificate file must exist.

Pass extra Tauri build arguments after `--`:

```powershell
./scripts/windows/desktop_release_bundle.ps1 -Channel canary -- --bundles nsis
```

Validate desktop scaffold + release guardrails from WSL:

```bash
bash ./scripts/integration_desktop_scaffold_contract.sh
bash ./scripts/integration_desktop_release_bundle_guardrails.sh
```

Desktop local API hardening reminder:
- `GPM_LOCAL_API_ALLOW_REMOTE=1` (legacy alias: `TDPN_LOCAL_API_ALLOW_REMOTE=1`) with a non-loopback `GPM_LOCAL_API_BASE_URL` (legacy alias: `TDPN_LOCAL_API_BASE_URL`) now requires:
  - `GPM_LOCAL_API_AUTH_BEARER` (legacy alias: `TDPN_LOCAL_API_AUTH_BEARER`) to be set, and
  - `https` in `GPM_LOCAL_API_BASE_URL`.
- Enabling desktop mutation controls (`GPM_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1` or `GPM_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1`, legacy aliases: `TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1` / `TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1`) also requires `GPM_LOCAL_API_AUTH_BEARER`, including loopback-only sessions.
- `GPM_LOCAL_API_AUTH_BEARER` (legacy alias: `TDPN_LOCAL_API_AUTH_BEARER`) must use token68 characters only (`A-Za-z0-9-._~+/=`), no whitespace/control chars.
- Daemon local API (`--local-api`) rejects non-loopback HTTP binds unless `LOCAL_CONTROL_API_ALLOW_INSECURE_REMOTE_HTTP=1` is explicitly set (lab/dev only).

Windows-native local API launcher (no WSL shim):

```powershell
./scripts/windows/local_api_session.ps1
```

Notes:
- This prefers Git for Windows `bash.exe` and rejects `WindowsApps\bash.exe` (WSL shim).
- Use `-CommandRunner` to pin a specific runner path.

Windows-native desktop bootstrap (recommended for client machines):

```powershell
./scripts/windows/desktop_native_bootstrap.ps1 -Mode bootstrap -InstallMissing
./scripts/windows/desktop_native_bootstrap.ps1 -Mode run-full
```

From `cmd.exe`:

```cmd
scripts\windows\desktop_native_bootstrap.cmd -Mode bootstrap -InstallMissing
scripts\windows\desktop_native_bootstrap.cmd -Mode run-full
```

Desktop bootstrap notes:
- use the `.cmd` wrapper if PowerShell policy is locked down; it launches PowerShell with process-scope execution policy bypass (no permanent policy change)
- refreshes PATH for current session
- auto-detects Go/Node/Rust/Git Bash from common install locations before falling back to `winget`
- can install missing Go/Node/Rust/Git Bash dependencies with `winget` when you pass `-InstallMissing`
- uses `npm.cmd` to avoid `npm.ps1` execution policy failures
- modes: `check`, `bootstrap`, `run-api`, `run-desktop`, `run-full`

Desktop doctor remediation flow (`desktop_doctor`):

This remains scaffold-only, non-production setup guidance.

PowerShell (`.ps1`) form:

```powershell
./scripts/windows/desktop_doctor.ps1 -Mode check
./scripts/windows/desktop_doctor.ps1 -Mode fix -InstallMissing -EnablePolicyBypass
```

From `cmd.exe` (`.cmd`) form:

```cmd
scripts\windows\desktop_doctor.cmd -Mode check
scripts\windows\desktop_doctor.cmd -Mode fix -InstallMissing
```

What `desktop_doctor` remediates:
- process-scope execution policy bypass when you pass `-EnablePolicyBypass`
- current-session PATH refresh and common tool path augmentation
- prerequisite detection for Go/Node/npm/Rust/Cargo/Git Bash
- optional prerequisite install via `winget` when `-InstallMissing` is passed
- optional summary artifact output via `-SummaryJson` and `-PrintSummaryJson 1`

Recommended sequence on fresh machines:
1. Run `desktop_doctor` fix/install (`-Mode fix -InstallMissing`).
2. Then run either `desktop_one_click` or `desktop_native_bootstrap -Mode run-full`.

First-run remediation tips:
- run `./scripts/windows/desktop_native_bootstrap.cmd -Mode bootstrap -InstallMissing` on a fresh machine
- if PowerShell policy blocks a direct rerun, use the `.cmd` wrapper or call `./scripts/windows/desktop_native_bootstrap.ps1 -Mode bootstrap -InstallMissing -EnablePolicyBypass`
- if the bootstrap report says `GoLang.Go`, `OpenJS.NodeJS.LTS`, `Rustlang.Rustup`, or `Git.Git` is missing, rerun with `-InstallMissing` or install that winget package manually
- the desktop scaffold auto-creates the icon scaffold when it is missing, so first runs do not need a pre-existing icon asset
- `run-api` needs Go and Git for Windows bash.exe
- `run-desktop` needs Node.js LTS / npm and the Rust toolchain
- `run-full` needs all of the above
- if `winget` is missing, install App Installer first and rerun the bootstrap
- the desktop release bundle scaffold also expects Node.js LTS / npm and Rustup before `tauri build`

One-click desktop launcher for scaffold/client onboarding:

```powershell
./scripts/windows/desktop_one_click.ps1
```

From `cmd.exe`:

```cmd
scripts\windows\desktop_one_click.cmd
```

This wrapper is meant for the common "bootstrap then launch" path on Windows and keeps the same scaffold-only, non-production posture as the rest of the desktop track.

Default remediation behavior for `desktop_one_click` (scaffold/non-production):
- auto-remediation is now enabled by default, equivalent to using `-InstallMissing`, unless explicitly disabled.
- preferred env knob: `GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING`
- legacy compatibility alias: `TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING`
- accepted values:
  - `1` or `true` enables auto-remediation
  - `0` or `false` disables auto-remediation
  - unset defaults to enabled
- explicit switch precedence:
  - `-InstallMissing` explicitly enables remediation
  - `-InstallMissing:$false` explicitly disables remediation, even when env would enable it

Installer-style packaged launcher flow (`desktop_packaged_run`):

This remains scaffold-only, non-production installer-style validation guidance.

PowerShell (`.ps1`) form:

```powershell
./scripts/windows/desktop_packaged_run.ps1 -DryRun
./scripts/windows/desktop_packaged_run.ps1
```

From `cmd.exe` (`.cmd`) form:

```cmd
scripts\windows\desktop_packaged_run.cmd -DryRun
scripts\windows\desktop_packaged_run.cmd
```

What this path does:
- prefers packaged desktop launch for installer-style smoke checks
- still uses local API startup/health checks for desktop launch
- still runs `desktop_doctor` preflight-style environment checks before launch
- packaged executable auto-discovery order: env overrides (`GPM_DESKTOP_PACKAGED_EXE` preferred, then `GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE`, then legacy `TDPN_DESKTOP_PACKAGED_EXE`), installed default paths, then local repo artifacts
- desktop metadata and packaged artifact names are GPM-first (`Global Private Mesh Desktop.exe` / `global-private-mesh-desktop`); TDPN naming remains env-override compatibility only

Env override example (PowerShell):

```powershell
$env:GPM_DESKTOP_PACKAGED_EXE="C:\Program Files\Global Private Mesh\Global Private Mesh Desktop\Global Private Mesh Desktop.exe"; .\scripts\windows\desktop_packaged_run.ps1 -DryRun
# legacy alias still supported:
$env:TDPN_DESKTOP_PACKAGED_EXE="C:\Program Files\Global Private Mesh\Global Private Mesh Desktop\Global Private Mesh Desktop.exe"; .\scripts\windows\desktop_packaged_run.ps1 -DryRun
```

Recommended sequence for installer testing:
1. Build the bundle (`desktop_release_bundle`).
2. Run `desktop_packaged_run` in `-DryRun` first.
3. Run `desktop_packaged_run` for a real launch.

Launch strategy behavior for `desktop_native_bootstrap`:
- `dev` keeps the backward-compatible development flow. Use this when you want the same local development path the bootstrap has always used.
- `auto` prefers a packaged desktop when one is available, then falls back to the dev launch path. Use this when you want one command to work across fresh machines and machines that already have packaged artifacts.
- `packaged` forces the packaged app path. Use this for release-style smoke checks or when you specifically want to validate the packaged launcher path.

Examples:

```powershell
./scripts/windows/desktop_native_bootstrap.ps1 -Mode run-desktop -DesktopLaunchStrategy dev
./scripts/windows/desktop_native_bootstrap.ps1 -Mode run-desktop -DesktopLaunchStrategy auto
./scripts/windows/desktop_native_bootstrap.ps1 -Mode run-desktop -DesktopLaunchStrategy packaged
```

## Linux desktop scaffold parity (doctor + packaged-run, non-production)

Use this when validating Linux desktop first-run behavior with the same scaffold posture as Windows.

Linux doctor (`scripts/linux/desktop_doctor.sh`) usage:

```bash
bash ./scripts/linux/desktop_doctor.sh --mode check
bash ./scripts/linux/desktop_doctor.sh --mode fix --install-missing
```

Modes and first-run guidance:
- `check`: report readiness and missing prerequisites.
- `fix`: apply remediation and optionally install missing prerequisites.
- recommended first run:
1. run `--mode fix --install-missing`
2. run `--mode check`
3. proceed to desktop dev or packaged-run

Linux packaged-run (`scripts/linux/desktop_packaged_run.sh`) usage:

```bash
bash ./scripts/linux/desktop_packaged_run.sh --dry-run
bash ./scripts/linux/desktop_packaged_run.sh
```

Dry-run and override guidance:
- run `--dry-run` first to confirm executable discovery and local API preflight
- executable override env auto-discovery order: `GPM_DESKTOP_PACKAGED_EXE` (preferred), `GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE`, then legacy `TDPN_DESKTOP_PACKAGED_EXE`
- packaged artifact naming remains GPM-first (`global-private-mesh-desktop` and `Global Private Mesh Desktop.AppImage`); TDPN naming is env-override compatibility only
- optional local API tuning: `GPM_LOCAL_API_BASE_URL`, `GPM_LOCAL_API_TIMEOUT_SEC` (legacy aliases: `TDPN_LOCAL_API_BASE_URL`, `TDPN_LOCAL_API_TIMEOUT_SEC`)
- keep manual override usage support/lab-focused while this remains scaffold/non-production

Linux env override example:

```bash
GPM_DESKTOP_PACKAGED_EXE="$HOME/Applications/Global Private Mesh Desktop.AppImage" \
  bash ./scripts/linux/desktop_packaged_run.sh --dry-run
# legacy alias still supported:
TDPN_DESKTOP_PACKAGED_EXE="$HOME/Applications/Global Private Mesh Desktop.AppImage" \
  bash ./scripts/linux/desktop_packaged_run.sh --dry-run
```

Linux native bootstrap and one-click usage:

```bash
bash ./scripts/linux/desktop_native_bootstrap.sh --mode bootstrap --install-missing
bash ./scripts/linux/desktop_native_bootstrap.sh --mode run-full --desktop-launch-strategy auto
bash ./scripts/linux/desktop_one_click.sh --install-missing
```

Linux one-click auto-remediation defaults (scaffold/non-production):
- `desktop_one_click.sh` now enables missing dependency remediation by default, equivalent to `--install-missing`, unless explicitly disabled.
- shared env knobs: `GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING` and legacy alias `TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING`.
- accepted values: `1` / `true` enables, `0` / `false` disables; unset defaults to enabled.
- CLI precedence on Linux:
  - `--install-missing` explicitly enables remediation.
  - `--no-install-missing` explicitly disables remediation, even when env would enable it.

Equivalent `easy_node.sh` wrapper usage on Linux (scaffold/non-production):

```bash
./scripts/easy_node.sh desktop-linux-doctor --mode check
./scripts/easy_node.sh desktop-linux-doctor --mode fix --install-missing
./scripts/easy_node.sh desktop-linux-native-bootstrap --mode bootstrap --install-missing
./scripts/easy_node.sh desktop-linux-native-bootstrap --mode run-full --desktop-launch-strategy auto
./scripts/easy_node.sh desktop-linux-one-click --install-missing
./scripts/easy_node.sh desktop-linux-packaged-run --dry-run
./scripts/easy_node.sh desktop-linux-packaged-run
```

Equivalent `easy_node.sh` wrapper usage on Windows (scaffold/non-production):

```powershell
.\scripts\easy_node.sh desktop-windows-doctor --mode check
.\scripts\easy_node.sh desktop-windows-doctor --mode fix --install-missing
.\scripts\easy_node.sh desktop-windows-native-bootstrap --mode bootstrap --install-missing
.\scripts\easy_node.sh desktop-windows-native-bootstrap --mode run-full --desktop-launch-strategy auto
.\scripts\easy_node.sh desktop-windows-one-click --install-missing
.\scripts\easy_node.sh desktop-windows-packaged-run --dry-run
.\scripts\easy_node.sh desktop-windows-packaged-run
.\scripts\easy_node.sh desktop-windows-release-bundle --bundle-dir .easy-node-logs/windows_release_bundle
.\scripts\easy_node.sh desktop-windows-local-api-session -DryRun
```

The Windows wrapper commands call PowerShell with `-ExecutionPolicy Bypass` automatically for the target `.ps1` scripts.

If your branch does not yet expose these wrapper commands, keep using the direct Linux/Windows script commands above.

Linux native bootstrap mode quick reference:
- `check`: doctor readiness only
- `bootstrap`: doctor check/fix stage only
- `run-api`: local API only (`go run ./cmd/node --local-api`)
- `run-desktop`: desktop only (dev/packaged/auto)
- `run-full`: local API + desktop in one flow

## 5) 3-machine beta test

Use the same flow documented in `docs/easy-3-machine-test.md`.

From WSL on machine C, you can run the automated validator:

```bash
./scripts/easy_node.sh three-machine-validate \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --min-sources 2 \
  --min-operators 2
```

If you are still testing with plain HTTP, keep the validator and targets on a private network only; these examples are not safe to paste onto an exposed host as-is.

Important for WSL/docker client runs:
- do not use `127.0.0.1` / `localhost` for remote machines in `client-test`
- use reachable IP/DNS for machine A/B endpoints

## 6) Troubleshooting

`docker daemon not reachable` in WSL:
- ensure Docker Desktop is running
- ensure distro integration is enabled
- restart WSL:
  - `wsl --shutdown`
  - reopen distro shell

PowerShell script says `wsl.exe not found`:
- install/enable WSL2 first

`The token '&&' is not a valid statement separator in this version`:
- you are likely on Windows PowerShell 5.x
- use the provided wrappers instead of manual `&&` one-liners:
  - `scripts\windows\wsl2_bootstrap.cmd`
  - `scripts\windows\wsl2_run_easy.cmd`
- or run commands on separate lines

`You cannot call a method on a null-valued expression` around `$repoRootWsl`:
- usually means no default distro is configured or `wslpath` failed
- pass distro explicitly, for example:
  - `scripts\windows\wsl2_bootstrap.cmd -Distro Ubuntu-22.04`
  - `scripts\windows\wsl2_run_easy.cmd -Distro Ubuntu-22.04`
- verify distros with `wsl -l -v`

Client cannot reach endpoints:
- verify Windows firewall/cloud security groups
- verify TCP 8081-8084 and UDP 51820-51821 are open on server machines
