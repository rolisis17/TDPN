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
- `TDPN_DESKTOP_UPDATE_CHANNEL=stable|beta|canary` (default in script: `stable`)

Optional update feed URL env:
- `TDPN_DESKTOP_UPDATE_FEED_URL=https://updates.example.invalid/tdpn/beta.json`

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

Scaffold guardrails now enforced by script:
- `-UpdateFeedUrl` must be an absolute `http/https` URL.
- non-local update feeds (anything except `localhost`/loopback) must use `https`.
- `-SigningCertPassword` requires `-SigningCertPath`.
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
- `TDPN_LOCAL_API_ALLOW_REMOTE=1` with a non-loopback `TDPN_LOCAL_API_BASE_URL` now requires:
  - `TDPN_LOCAL_API_AUTH_BEARER` to be set, and
  - `https` in `TDPN_LOCAL_API_BASE_URL`.
- Enabling desktop mutation controls (`TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1` or `TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1`) also requires `TDPN_LOCAL_API_AUTH_BEARER`, including loopback-only sessions.
- `TDPN_LOCAL_API_AUTH_BEARER` must use token68 characters only (`A-Za-z0-9-._~+/=`), no whitespace/control chars.
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
- uses process-scope execution policy bypass (no permanent policy change)
- refreshes PATH for current session
- can install missing Go/Node/Rust/Git Bash dependencies with `winget`
- uses `npm.cmd` to avoid `npm.ps1` execution policy failures
- modes: `check`, `bootstrap`, `run-api`, `run-desktop`, `run-full`

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
