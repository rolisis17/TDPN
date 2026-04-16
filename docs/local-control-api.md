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
- optional service lifecycle command hooks:
  - `LOCAL_CONTROL_API_SERVICE_STATUS_COMMAND`
  - `LOCAL_CONTROL_API_SERVICE_START_COMMAND`
  - `LOCAL_CONTROL_API_SERVICE_STOP_COMMAND`
  - `LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND`

Runner behavior:
- Linux/macOS default: execute `LOCAL_CONTROL_API_SCRIPT` directly.
- Windows default:
  - `*.ps1` script path -> `powershell -NoProfile -ExecutionPolicy Bypass -File <script> ...`
  - other script paths -> `bash <script> ...`
- `LOCAL_CONTROL_API_RUNNER` overrides the executable and prefixes the script path as the first argument.

Desktop scaffold defaults (`apps/desktop`):
- base URL: `http://127.0.0.1:8095` (`TDPN_LOCAL_API_BASE_URL`)
- request timeout: `20s` (`TDPN_LOCAL_API_TIMEOUT_SEC`)
- optional bearer auth for daemon API: `TDPN_LOCAL_API_AUTH_BEARER`
- local-only transport enforcement by default, with explicit opt-out:
  - `TDPN_LOCAL_API_ALLOW_REMOTE=1`
- renderer CSP: locked down in `apps/desktop/src-tauri/tauri.conf.json` and allows only Tauri IPC, local dev HMR (`localhost:5173`), and local control API origins (`127.0.0.1:8095` / `localhost:8095`)

## Endpoints

## Authentication

Mutating endpoints (`POST /v1/connect`, `POST /v1/disconnect`, `POST /v1/set_profile`, `POST /v1/update`, `POST /v1/service/start`, `POST /v1/service/stop`, `POST /v1/service/restart`) require auth when either:
- bind address is non-loopback (for example `0.0.0.0:8095`), or
- `LOCAL_CONTROL_API_AUTH_TOKEN` is set (including loopback binds).

Header format:

```http
Authorization: Bearer <LOCAL_CONTROL_API_AUTH_TOKEN>
```

If auth is required and missing/invalid, the API returns `401`.

Read-only endpoints (`/v1/health`, `/v1/status`, `/v1/get_diagnostics`, `/v1/service/status`) remain open by default.

### `GET /v1/health`
- Liveness for desktop app process supervision.

### `GET /v1/status`
- Returns `client-vpn-status --show-json 1`.

### `POST /v1/connect`
Body:

```json
{
  "bootstrap_directory": "http://HOST:8081",
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
- this bridge is intentionally minimal; mutating daemon actions are now protected by loopback-aware/token auth.
- additional hardening (service lifecycle, signed updates, telemetry) is tracked for the Windows parity phases.
