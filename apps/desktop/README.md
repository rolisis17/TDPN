# TDPN Desktop App Track (Tauri Scaffold)

This folder contains a practical scaffold for the Windows-native desktop track.
It is intentionally lightweight and not production-ready yet.

What this scaffold includes:
- Tauri app shell (`src-tauri`)
- minimal desktop UI (`src`)
- Windows release bundle scaffold scripts:
  - `scripts/windows/desktop_release_bundle.ps1`
  - `scripts/windows/desktop_release_bundle.cmd`
- local daemon API bridge commands:
  - `control_connect`
  - `control_disconnect`
  - `control_status`
  - `control_get_diagnostics`
  - `control_set_profile`
  - `control_update`
  - `control_health`
  - `control_config`

What this scaffold does not include yet:
- production-grade installer/signing/update pipeline
- Windows service lifecycle management
- full production-grade auth/session lifecycle (token rotation, signed bootstrap trust, policy rollout)
- telemetry, crash reporting, and production observability

## Local daemon expectation

Run the daemon with local API enabled:

```bash
go run ./cmd/node --local-api
```

Defaults expected by this app:
- local API base URL: `http://127.0.0.1:8095`
- local API timeout: `20s`

Desktop env overrides:
- `TDPN_LOCAL_API_BASE_URL`
- `TDPN_LOCAL_API_TIMEOUT_SEC`
- `TDPN_LOCAL_API_ALLOW_REMOTE=1` (opt-in for non-loopback daemon URLs)
- `TDPN_LOCAL_API_AUTH_BEARER` (required when `TDPN_LOCAL_API_ALLOW_REMOTE=1` targets non-loopback URLs)
- `TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1` (opt-in for desktop `control_update` action)
- `TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1` (opt-in for desktop service start/stop/restart actions)

Remote hardening guardrails:
- non-loopback `TDPN_LOCAL_API_BASE_URL` requires `TDPN_LOCAL_API_ALLOW_REMOTE=1`
- non-loopback `TDPN_LOCAL_API_BASE_URL` with remote opt-in also requires:
  - `TDPN_LOCAL_API_AUTH_BEARER`
  - `https` scheme
- enabling desktop mutation actions (`TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1` or `TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1`) requires `TDPN_LOCAL_API_AUTH_BEARER` even for loopback targets
- `TDPN_LOCAL_API_AUTH_BEARER` must be a single-line token with no whitespace/control characters and only token68 chars (`A-Za-z0-9-._~+/=`); desktop rejects invalid values
- `control_connect` bootstrap URL validation allows `http://` only for literal loopback IPs (`127.0.0.1` / `::1`); `http://localhost:...` is rejected
- desktop response rendering strips unbounded `output`/`raw` fields and redacts secret-like keys (including snake/camel/compact forms such as `accessToken`, `clientSecret`, `refreshToken`, `private_key`, `invite_key`, `api_key`)

Secret handling guidance:
- avoid passing local API auth tokens in command arguments; prefer process-local env vars for the current shell session only
- do not store `TDPN_LOCAL_API_AUTH_BEARER` in shared shell profiles/history on multi-user hosts
- never paste `invite_key` values or bearer tokens into issue trackers, CI logs, or chat transcripts

## Development (once toolchains are installed)

Prerequisites:
- Node.js + npm
- Rust toolchain + Cargo
- Tauri prerequisites for your OS

Run:

```bash
cd apps/desktop
npm install
npm run tauri dev
```

Windows-native local API session (no WSL shim):

```powershell
scripts\windows\local_api_session.cmd
```

Notes:
- This launcher prefers Git for Windows `bash.exe` (not `WindowsApps\bash.exe` / WSL shim).
- Override runner explicitly when needed:
  - `scripts\windows\local_api_session.cmd -CommandRunner "C:\Program Files\Git\bin\bash.exe"`
- `-DryRun` prints the resolved command/runner without starting the daemon.
- If you want to call `.ps1` directly, run with process bypass:
  - `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\local_api_session.ps1 -DryRun`

Windows-native one-command bootstrap and run (recommended for client onboarding):

```powershell
scripts\windows\desktop_native_bootstrap.cmd -Mode bootstrap -InstallMissing
scripts\windows\desktop_native_bootstrap.cmd -Mode run-full
```

From `cmd.exe`:

```cmd
scripts\windows\desktop_native_bootstrap.cmd -Mode bootstrap -InstallMissing
scripts\windows\desktop_native_bootstrap.cmd -Mode run-full
```

What this solves automatically:
- sets process execution policy bypass for this run
- refreshes current session PATH from machine+user PATH
- checks Go/Node/npm/Rust/Cargo/Git Bash
- optionally installs missing dependencies via `winget` (`-InstallMissing`)
- launches local API + desktop dev in one flow (`-Mode run-full`)

Other modes:
- `-Mode check` (diagnostics only)
- `-Mode run-api` (local API only)
- `-Mode run-desktop` (desktop only)

References:
- `docs/local-control-api.md`
- `docs/full-execution-plan-2026-2027.md`

## Windows Release Bundle Scaffold (Non-Production)

Use this only as scaffolding while we build the real signing/release pipeline.
It does not implement production secret handling or production signing.

Update channel env:
- `TDPN_DESKTOP_UPDATE_CHANNEL` = `stable|beta|canary` (default: `stable`)

Optional update feed env:
- `TDPN_DESKTOP_UPDATE_FEED_URL` (example: `https://updates.example.invalid/tdpn/beta.json`)

Run from repository root (PowerShell):

```powershell
./scripts/windows/desktop_release_bundle.ps1 -Channel beta
```

From `cmd.exe`:

```cmd
scripts\windows\desktop_release_bundle.cmd -Channel beta
```

Optional scaffold-only signing placeholders:
- `-SigningIdentity`
- `-SigningCertPath`
- `-SigningCertPassword`

Release scaffold guardrails:
- `-UpdateFeedUrl` must be an absolute `http/https` URL
- non-local update feeds must use `https`
- `-SigningCertPassword` requires `-SigningCertPath`
- `-SigningCertPath` must point to an existing file

Pass extra Tauri build arguments after `--`:

```powershell
./scripts/windows/desktop_release_bundle.ps1 -Channel canary -- --bundles nsis
```

## Contract Checks

Run these from repository root to validate scaffold guardrails without building installers:

```bash
bash ./scripts/integration_desktop_scaffold_contract.sh
bash ./scripts/integration_desktop_release_bundle_guardrails.sh
```
