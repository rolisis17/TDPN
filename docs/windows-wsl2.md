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

## 4) 3-machine beta test

Use the same flow documented in `docs/easy-3-machine-test.md`.

Important for WSL/docker client runs:
- do not use `127.0.0.1` / `localhost` for remote machines in `client-test`
- use reachable IP/DNS for machine A/B endpoints

## 5) Troubleshooting

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
