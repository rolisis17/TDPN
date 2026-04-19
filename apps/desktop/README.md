# Global Private Mesh (GPM) Desktop App Track (Tauri Scaffold)

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
- optional daemon production-hardening mode for connect:
  - `GPM_CONNECT_REQUIRE_SESSION=1` (legacy alias: `TDPN_CONNECT_REQUIRE_SESSION=1`)
  - when enabled, `/v1/connect` rejects manual `bootstrap_directory`/`invite_key` overrides and requires a registered `session_token`
  - default remains legacy-compatible unless explicitly enabled

Desktop env overrides (GPM-first, legacy TDPN alias names preserved for compatibility):
- `GPM_LOCAL_API_BASE_URL` (legacy alias: `TDPN_LOCAL_API_BASE_URL`)
- `GPM_LOCAL_API_TIMEOUT_SEC` (legacy alias: `TDPN_LOCAL_API_TIMEOUT_SEC`)
- `GPM_LOCAL_API_ALLOW_REMOTE=1` (legacy alias: `TDPN_LOCAL_API_ALLOW_REMOTE=1`; opt-in for non-loopback daemon URLs)
- `GPM_LOCAL_API_AUTH_BEARER` (legacy alias: `TDPN_LOCAL_API_AUTH_BEARER`; required when remote mode targets non-loopback URLs)
- `GPM_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1` (legacy alias: `TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1`; opt-in for desktop `control_update` action)
- `GPM_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1` (legacy alias: `TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1`; opt-in for desktop service start/stop/restart actions)
- GPM server lifecycle actions (`POST /v1/gpm/service/start|stop|restart`) require an approved `operator` or `admin` session from `POST /v1/gpm/session`; `client` sessions cannot run server lifecycle mutations.

Remote hardening guardrails:
- non-loopback `TDPN_LOCAL_API_BASE_URL` requires `TDPN_LOCAL_API_ALLOW_REMOTE=1`
- non-loopback `TDPN_LOCAL_API_BASE_URL` with remote opt-in also requires:
  - `TDPN_LOCAL_API_AUTH_BEARER`
  - `https` scheme
- enabling desktop mutation actions (`TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1` or `TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1`) requires `TDPN_LOCAL_API_AUTH_BEARER` even for loopback targets
- `TDPN_LOCAL_API_AUTH_BEARER` must be a single-line token with no whitespace/control characters and only token68 chars (`A-Za-z0-9-._~+/=`); desktop rejects invalid values
- if `GPM_MAIN_DOMAIN` (legacy alias `TDPN_MAIN_DOMAIN`) is set, manifest URLs are trusted only when the host matches the pinned main-domain host; cache fallback checks the cached manifest source URL host too. This hardening is skipped when main domain is unset for dev compatibility, and it complements existing signature verification and expiry checks.
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

Windows PowerShell policy note:
- If `npm` is blocked by execution policy (`npm.ps1 cannot be loaded`), use one of:
  - `scripts\windows\desktop_one_click.cmd`
  - `npm.cmd install` and `npm.cmd run tauri -- dev`
- The `.cmd` launchers already apply process-scope `ExecutionPolicy Bypass` automatically for the run.

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

Desktop doctor remediation flow (`desktop_doctor`):

This remains scaffold-only, non-production setup guidance.

PowerShell (`.ps1`) form:

```powershell
scripts\windows\desktop_doctor.ps1 -Mode check
scripts\windows\desktop_doctor.ps1 -Mode fix -InstallMissing -EnablePolicyBypass
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

One-click desktop launcher for scaffold/client onboarding:

```powershell
scripts\windows\desktop_one_click.ps1
```

From `cmd.exe`:

```cmd
scripts\windows\desktop_one_click.cmd
```

This wrapper keeps the same scaffold-only, non-production posture as the rest of the desktop track and is meant for the common "bootstrap then launch" path.

Installer-style packaged launcher flow (`desktop_packaged_run`):

This path is scaffold-only, non-production installer-style validation guidance.

PowerShell (`.ps1`) form:

```powershell
scripts\windows\desktop_packaged_run.ps1 -DryRun
scripts\windows\desktop_packaged_run.ps1
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
- packaged executable auto-discovery order: env overrides (`GPM_DESKTOP_PACKAGED_EXE`, then `TDPN_DESKTOP_PACKAGED_EXE`), installed default paths, then local repo artifacts

Env override example (PowerShell):

```powershell
$env:GPM_DESKTOP_PACKAGED_EXE="C:\Program Files\GPM\Global Private Mesh Desktop\Global Private Mesh Desktop.exe"; scripts\windows\desktop_packaged_run.ps1 -DryRun
```

Recommended sequence for installer testing:
1. Build the bundle (`desktop_release_bundle`).
2. Run `desktop_packaged_run` in `-DryRun` first.
3. Run `desktop_packaged_run` for a real launch.

Linux doctor remediation flow (`scripts/linux/desktop_doctor.sh`):

This is scaffold-only, non-production setup guidance for Linux parity with the Windows flow.

```bash
bash ./scripts/linux/desktop_doctor.sh --mode check
bash ./scripts/linux/desktop_doctor.sh --mode fix --install-missing
```

Modes:
- `check` prints readiness and missing prerequisites.
- `fix` applies first-run remediation and can install missing dependencies.

Recommended first-run sequence on Linux:
1. Run `desktop_doctor` with `--mode fix --install-missing`.
2. Re-run `desktop_doctor` with `--mode check` and confirm readiness.
3. Start desktop dev (`npm run tauri dev`) or run the packaged launcher flow below.

Linux installer-style packaged launcher flow (`scripts/linux/desktop_packaged_run.sh`):

This is scaffold-only, non-production installer-style validation guidance.

```bash
bash ./scripts/linux/desktop_packaged_run.sh --dry-run
bash ./scripts/linux/desktop_packaged_run.sh
```

Dry-run guidance:
- always run `--dry-run` first to verify executable discovery and local API preflight before real launch.

Executable override and env hints:
- primary packaged executable override: `GPM_DESKTOP_PACKAGED_EXE`
- legacy compatibility alias: `TDPN_DESKTOP_PACKAGED_EXE`
- local API behavior can still be tuned with `GPM_LOCAL_API_BASE_URL` and `GPM_LOCAL_API_TIMEOUT_SEC` (legacy aliases: `TDPN_LOCAL_API_BASE_URL`, `TDPN_LOCAL_API_TIMEOUT_SEC`)
- keep manual executable overrides as support/lab usage in scaffold mode, not production defaults

Linux native bootstrap and one-click launchers:

```bash
bash ./scripts/linux/desktop_native_bootstrap.sh --mode bootstrap --install-missing
bash ./scripts/linux/desktop_native_bootstrap.sh --mode run-full --desktop-launch-strategy auto
bash ./scripts/linux/desktop_one_click.sh --install-missing
```

Equivalent `easy_node.sh` wrapper usage (scaffold/non-production):

```bash
./scripts/easy_node.sh desktop-linux-doctor --mode check
./scripts/easy_node.sh desktop-linux-doctor --mode fix --install-missing
./scripts/easy_node.sh desktop-linux-native-bootstrap --mode bootstrap --install-missing
./scripts/easy_node.sh desktop-linux-native-bootstrap --mode run-full --desktop-launch-strategy auto
./scripts/easy_node.sh desktop-linux-one-click --install-missing
./scripts/easy_node.sh desktop-linux-packaged-run --dry-run
./scripts/easy_node.sh desktop-linux-packaged-run
```

If your branch does not yet expose these wrapper commands, use the direct `scripts/linux/*.sh` commands above.

Linux native bootstrap modes:
- `check` validates prerequisites through doctor.
- `bootstrap` runs doctor readiness/remediation only.
- `run-api` runs `go run ./cmd/node --local-api`.
- `run-desktop` launches desktop only (dev/packaged/auto).
- `run-full` starts local API + desktop in one scaffold flow.

Launch strategy behavior for `desktop_native_bootstrap`:
- `dev` keeps the backward-compatible development flow.
- `auto` prefers packaged artifacts when they exist, then falls back to dev.
- `packaged` forces the packaged app path for release-style smoke checks.

Example commands:

```powershell
scripts\windows\desktop_native_bootstrap.ps1 -Mode run-desktop -DesktopLaunchStrategy dev
scripts\windows\desktop_native_bootstrap.ps1 -Mode run-desktop -DesktopLaunchStrategy auto
scripts\windows\desktop_native_bootstrap.ps1 -Mode run-desktop -DesktopLaunchStrategy packaged
```

References:
- `docs/local-control-api.md`
- `docs/full-execution-plan-2026-2027.md`

## Windows Release Bundle Scaffold (Non-Production)

Use this only as scaffolding while we build the real signing/release pipeline.
It does not implement production secret handling or production signing.

Update channel env:
- `GPM_DESKTOP_UPDATE_CHANNEL` = `stable|beta|canary` (default: `stable`, legacy alias: `TDPN_DESKTOP_UPDATE_CHANNEL`)

Optional update feed env:
- `GPM_DESKTOP_UPDATE_FEED_URL` (legacy alias: `TDPN_DESKTOP_UPDATE_FEED_URL`, example: `https://updates.example.invalid/gpm/beta.json`)

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
