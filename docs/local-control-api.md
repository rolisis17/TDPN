# Local Control API (Desktop/Native App Contract)

This API is served by the node daemon when started with:

```bash
go run ./cmd/node --local-api
```

Easy launcher wrapper (recommended for operator parity with config v1 defaults):

```bash
./scripts/easy_node.sh local-api-session --config-v1-path deploy/config/easy_mode_config_v1.conf
```

Defaults:
- address: `127.0.0.1:8095` (`LOCAL_CONTROL_API_ADDR`)
- script runner: `./scripts/easy_node.sh` (`LOCAL_CONTROL_API_SCRIPT`)
- optional command runner override: `LOCAL_CONTROL_API_RUNNER` (example: `bash` or `powershell`)
- command timeout: `120s` (`LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC`)
- update endpoint disabled by default (`LOCAL_CONTROL_API_ALLOW_UPDATE=1` to enable)
- optional mutation auth token: `LOCAL_CONTROL_API_AUTH_TOKEN`
- unauthenticated loopback mode is disabled by default; explicit developer-only opt-in:
  - `LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK=1`
- non-loopback HTTP binds are blocked by default; explicit dangerous opt-in for lab-only usage:
  - `LOCAL_CONTROL_API_ALLOW_INSECURE_REMOTE_HTTP=1`
- optional service lifecycle command hooks:
  - `LOCAL_CONTROL_API_SERVICE_STATUS_COMMAND`
  - `LOCAL_CONTROL_API_SERVICE_START_COMMAND`
  - `LOCAL_CONTROL_API_SERVICE_STOP_COMMAND`
  - `LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND`
- optional `/v1/connect` hardening mode (production-focused):
  - `GPM_CONNECT_REQUIRE_SESSION=1` (legacy alias: `TDPN_CONNECT_REQUIRE_SESSION=1`)
  - when enabled, `/v1/connect` requires a registered `session_token` and rejects manual `bootstrap_directory` / `invite_key` overrides
  - default remains legacy-compatible unless this flag is explicitly enabled
- main-domain pinning for manifest trust:
  - when `GPM_MAIN_DOMAIN` (legacy alias: `TDPN_MAIN_DOMAIN`) is set, manifest URLs are trusted only when the host matches the pinned main-domain host
  - cache fallback uses the same host check against the cached manifest source URL
  - this complements existing signature verification and expiry checks
  - if the main domain is unset, this hardening is skipped for dev compatibility

Runner behavior:
- Linux/macOS default: execute `LOCAL_CONTROL_API_SCRIPT` directly.
- Windows default:
  - `*.ps1` script path -> `powershell -NoProfile -ExecutionPolicy Bypass -File <script> ...`
  - other script paths -> prefer Git for Windows `bash.exe` (`C:\Program Files\Git\...`) when available, otherwise `bash <script> ...`
- `LOCAL_CONTROL_API_RUNNER` overrides the executable and prefixes the script path as the first argument.
- Optional Windows runner knobs:
  - `LOCAL_CONTROL_API_GIT_BASH_PATH` to pin a Git Bash path.
  - `LOCAL_CONTROL_API_PREFER_GIT_BASH=0` to disable Git Bash auto-preference and use `bash` resolution from `PATH`.

Desktop scaffold defaults (`apps/desktop`):
- base URL: `http://127.0.0.1:8095` (`TDPN_LOCAL_API_BASE_URL`)
- request timeout: `20s` (`TDPN_LOCAL_API_TIMEOUT_SEC`)
- optional bearer auth for daemon API: `TDPN_LOCAL_API_AUTH_BEARER`
- local-only transport enforcement by default, with explicit opt-out:
  - `TDPN_LOCAL_API_ALLOW_REMOTE=1`
  - in local-only mode (`TDPN_LOCAL_API_ALLOW_REMOTE=0`), use a literal loopback IP host (`127.0.0.1` or `::1`), not a hostname.
- desktop mutating action gates are disabled by default (explicit opt-in):
  - `TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1` for `control_update`
  - `TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1` for `control_service_start|stop|restart`
  - when either mutating gate is enabled, `TDPN_LOCAL_API_AUTH_BEARER` is required (including loopback-only desktop sessions)
- desktop bearer token format is strict: token68 charset only (`A-Za-z0-9-._~+/=`), single-line, no whitespace/control characters, max 4096 chars
- renderer CSP is locked down in `apps/desktop/src-tauri/tauri.conf.json`:
  - production: only app resources + Tauri IPC (`ipc:`), no direct remote daemon origin, and no `unsafe-inline` in `style-src`
  - development: adds local HMR (`http://localhost:5173`, `ws://localhost:5173`)

## Endpoints

GPM onboarding/session endpoints (used by desktop and portal flows):
- `POST /v1/gpm/auth/challenge`
- `POST /v1/gpm/auth/verify`
- `POST /v1/gpm/session` (`action=status|refresh|revoke`)
- `POST /v1/gpm/onboarding/client/register`
- `POST /v1/gpm/onboarding/client/status` (returns `registered|not_registered`, `bootstrap_directory`, and persisted `path_profile` when available)
- `POST /v1/gpm/onboarding/operator/apply`
- `POST /v1/gpm/onboarding/operator/status`
- `POST /v1/gpm/onboarding/operator/approve`

## Authentication

Mutating endpoints (`POST /v1/connect`, `POST /v1/disconnect`, `POST /v1/set_profile`, `POST /v1/update`, `POST /v1/service/start`, `POST /v1/service/stop`, `POST /v1/service/restart`) require auth by default.
GPM server lifecycle endpoints (`POST /v1/gpm/service/start`, `POST /v1/gpm/service/stop`, `POST /v1/gpm/service/restart`) also require an approved `operator` or `admin` session issued via `/v1/gpm/session`.

Auth can be bypassed only in explicit developer mode when all of the following are true:
- bind address is loopback-only, and
- `LOCAL_CONTROL_API_AUTH_TOKEN` is not set, and
- `LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK=1`.

For transport hardening, non-loopback binds are rejected unless `LOCAL_CONTROL_API_ALLOW_INSECURE_REMOTE_HTTP=1` is set. Keep this unset in production.

Secret handling guidance:
- avoid passing `LOCAL_CONTROL_API_AUTH_TOKEN` / `TDPN_LOCAL_API_AUTH_BEARER` in CLI args; use process-local env vars instead
- avoid persisting tokens in shared shell profiles/history; prefer short-lived shell/session scope
- never include invite keys or bearer tokens in logs, screenshots, or support tickets

Command-backed read endpoints (`GET /v1/status`, `GET /v1/get_diagnostics`, `GET /v1/service/status`) follow the same auth policy.

Header format:

```http
Authorization: Bearer <LOCAL_CONTROL_API_AUTH_TOKEN>
```

If auth is required and missing/invalid, the API returns `401`.

`GET /v1/health` remains open for liveness checks.

### `GET /v1/health`
- Liveness for desktop app process supervision.

### `GET /v1/status`
- Returns `client-vpn-status --show-json 1`.

### `POST /v1/connect`
Body:

```json
{
  "bootstrap_directory": "https://HOST:8081",
  "invite_key": "inv-...",
  "path_profile": "1hop|2hop|3hop",
  "interface": "wgvpn0",
  "discovery_wait_sec": 20,
  "ready_timeout_sec": 35,
  "run_preflight": true,
  "prod_profile": false,
  "install_route": true
}
```

Notes:
- use `https://` for non-loopback bootstrap hosts.
- loopback-only developer bootstrap may use `http://127.0.0.1:...` or `http://[::1]:...` when explicitly intended.
- `http://localhost:...` is intentionally rejected by desktop validation; use literal loopback IPs to avoid hostname/DNS ambiguity.
- production hardening mode (`GPM_CONNECT_REQUIRE_SESSION=1`, legacy `TDPN_CONNECT_REQUIRE_SESSION=1`) requires `session_token` and rejects manual `bootstrap_directory`/`invite_key` request overrides.
- when hardening mode is not enabled (default), legacy `bootstrap_directory` + `invite_key` behavior remains available.

Behavior:
- runs optional `client-vpn-preflight`
- then runs `client-vpn-up` (background)
- returns status payload

### `POST /v1/disconnect`
- Runs `client-vpn-down --force-iface-cleanup 1`.

### `POST /v1/set_profile`
Body:

```json
{
  "path_profile": "1hop|2hop|3hop"
}
```

Behavior:
- updates `deploy/config/easy_mode_config_v1.conf` through:
  - `config-v1-set-profile --path-profile ...`

### `GET /v1/get_diagnostics`
- Runs `runtime-doctor --show-json 1`.

### `POST /v1/update`
- Runs `self-update --show-status 1` (only when update endpoint is enabled).

### `GET /v1/service/status`
- Returns service lifecycle capability/configuration summary.
- If `LOCAL_CONTROL_API_SERVICE_STATUS_COMMAND` is set, it executes the command and includes command output/rc in the response.

### `POST /v1/service/start`
### `POST /v1/service/stop`
### `POST /v1/service/restart`
- Execute configured lifecycle commands:
  - `LOCAL_CONTROL_API_SERVICE_START_COMMAND`
  - `LOCAL_CONTROL_API_SERVICE_STOP_COMMAND`
  - `LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND`
- If command is unset, returns `501` with configuration guidance.
- On command failure, returns `502` with `rc` and combined output.

## Desktop Command Bridge (Scaffold)

The current desktop scaffold uses a thin Rust bridge that forwards to this API.
Command names exposed to the UI:

- `control_health` -> `GET /v1/health`
- `control_status` -> `GET /v1/status`
- `control_get_diagnostics` -> `GET /v1/get_diagnostics`
- `control_connect` -> `POST /v1/connect`
- `control_disconnect` -> `POST /v1/disconnect`
- `control_set_profile` -> `POST /v1/set_profile`
- `control_update` -> `POST /v1/update`
- `control_service_status` -> `GET /v1/service/status`
- `control_service_start` -> `POST /v1/service/start`
- `control_service_stop` -> `POST /v1/service/stop`
- `control_service_restart` -> `POST /v1/service/restart`
- `control_config` -> local desktop config only (no daemon call)

Scaffold note:
- this bridge is intentionally minimal; daemon actions are token-auth protected by default, with explicit loopback-only developer opt-in for unauthenticated mode.
- desktop payload shaping removes unbounded `output`/`raw` fields and redacts secret-like keys before UI rendering, including common snake/camel/compact forms (for example `accessToken`, `clientSecret`, `refreshToken`, `api_key`).
- additional hardening (service lifecycle, signed updates, telemetry) is tracked for the Windows parity phases.
