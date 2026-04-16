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

Runner behavior:
- Linux/macOS default: execute `LOCAL_CONTROL_API_SCRIPT` directly.
- Windows default:
  - `*.ps1` script path -> `powershell -NoProfile -ExecutionPolicy Bypass -File <script> ...`
  - other script paths -> `bash <script> ...`
- `LOCAL_CONTROL_API_RUNNER` overrides the executable and prefixes the script path as the first argument.

Desktop scaffold defaults (`apps/desktop`):
- base URL: `http://127.0.0.1:8095` (`TDPN_LOCAL_API_BASE_URL`)
- request timeout: `20s` (`TDPN_LOCAL_API_TIMEOUT_SEC`)

## Endpoints

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
- `control_config` -> local desktop config only (no daemon call)

Scaffold note:
- this bridge is intentionally minimal and unauthenticated beyond localhost scope.
- hardening (authN/authZ, service lifecycle, signed updates, telemetry) is tracked for the Windows parity phases.
