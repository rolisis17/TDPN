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
  - optional desktop/web compatibility-control gate:
    - `GPM_ALLOW_LEGACY_CONNECT_OVERRIDE=1` (legacy alias: `TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE=1`)
    - when disabled (default), UI compatibility controls for manual bootstrap/invite overrides are hidden by policy
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
- `POST /v1/gpm/auth/verify` (uses a pluggable signature verifier hook in the daemon; default verifier enforces baseline proof-shape guardrails while full wallet-extension verification remains a follow-on milestone; request supports optional signature metadata: `signature_kind`, `signature_public_key`, `signature_public_key_type`, `signature_source`, `chain_id`, `signed_message`, `signature_envelope`; when provided, `signed_message` must exactly match the issued challenge message, `signature_kind` must be `sign_arbitrary` or `eip191`, `signature_source` must be `wallet_extension` or `manual`, `signature_public_key_type` must be `secp256k1` or `ed25519`, and `signature_envelope` (string or JSON payload) is normalized and capped at 16384 bytes; omitting metadata preserves existing behavior)
- optional external verifier hook: set `GPM_AUTH_VERIFY_COMMAND` (legacy alias: `TDPN_AUTH_VERIFY_COMMAND`) to run a local command after baseline validation; the command receives context via env vars: `GPM_AUTH_VERIFY_CHALLENGE_ID`, `GPM_AUTH_VERIFY_MESSAGE`, `GPM_AUTH_VERIFY_WALLET_ADDRESS`, `GPM_AUTH_VERIFY_WALLET_PROVIDER`, `GPM_AUTH_VERIFY_SIGNATURE`, `GPM_AUTH_VERIFY_SIGNATURE_KIND`, `GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY`, `GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY_TYPE`, `GPM_AUTH_VERIFY_SIGNATURE_SOURCE`, `GPM_AUTH_VERIFY_CHAIN_ID`, `GPM_AUTH_VERIFY_SIGNED_MESSAGE`, `GPM_AUTH_VERIFY_SIGNATURE_ENVELOPE`
- `POST /v1/gpm/session` (`action=status|refresh|revoke`; `status`/`refresh` reconcile non-admin session role against current operator decision and include additive `session_reconciled` response metadata)
- `POST /v1/gpm/onboarding/client/register`
- `POST /v1/gpm/onboarding/client/status` (returns `registered|not_registered`, `bootstrap_directory`, and persisted `path_profile` when available)
- `POST /v1/gpm/onboarding/server/status` (returns server-tab/lifecycle readiness derived from role, operator approval state, and chain-id sync hints)
- `POST /v1/gpm/onboarding/operator/apply`
- `POST /v1/gpm/onboarding/operator/status`
- `POST /v1/gpm/onboarding/operator/list` (admin-only; supports optional `status` filter (`pending|approved|rejected`), optional `search` substring filter (`wallet_address`, `chain_operator_id`, `server_label`, `status`, `reason`), optional `limit` (default `100`, clamped `1..500`), and optional cursor pagination via `cursor="<updated_at_utc>|<wallet_address>"`; response includes additive pagination metadata `total`, `has_more`, `next_cursor`, and echoed `request` fields)
- `POST /v1/gpm/onboarding/operator/approve` (requires admin authorization: `session_token` with admin role, or legacy `admin_token` fallback when `GPM_APPROVAL_ADMIN_TOKEN` is configured; request body supports optional optimistic concurrency precondition `if_updated_at_utc` (RFC3339); successful responses include additive `decision` (`approved|rejected`) and `decision_auth` (`admin_session|legacy_admin_token`) metadata; matching wallet sessions are promoted on approval and demoted on rejection)
- `GET /v1/gpm/audit/recent` (command-read auth; supports optional `limit` (default `25`, clamped `1..200`), optional `offset` (`>=0`), optional exact case-insensitive `event` filter, optional normalized `wallet_address` filter against `fields.wallet_address`, and optional `order` (`desc|asc`, default `desc`); response includes additive metadata `total`, `count`, `limit`, `offset`, `has_more`, `next_offset`, and echoed `filters`)

## Authentication

Mutating endpoints (`POST /v1/connect`, `POST /v1/disconnect`, `POST /v1/set_profile`, `POST /v1/update`, `POST /v1/service/start`, `POST /v1/service/stop`, `POST /v1/service/restart`) require auth by default.
GPM server lifecycle endpoints (`POST /v1/gpm/service/start`, `POST /v1/gpm/service/stop`, `POST /v1/gpm/service/restart`) also require an approved `operator` or `admin` session issued via `/v1/gpm/session`.
`POST /v1/gpm/onboarding/operator/list` uses command-read auth and requires a valid `admin` `session_token`:
- missing `session_token`: `400` (`session_token is required`)
- missing/expired session token: `404` (`session not found`)
- non-admin session role: `403` (`admin session role is required`)
- invalid cursor format: `400` (`cursor must be in the format <updated_at_utc>|<wallet_address>`)
`POST /v1/gpm/onboarding/operator/approve` also requires admin-level authorization:
- preferred: `session_token` for a valid `admin` session.
- compatibility fallback: `admin_token` matching `GPM_APPROVAL_ADMIN_TOKEN` (or legacy alias) when configured.
- if `GPM_APPROVAL_ADMIN_TOKEN` is unset and no admin session token is provided, approval is rejected.
- decision contract hardening:
  - request body fields:
    - `wallet_address` (required)
    - `approved` (required)
    - `reason` (required when `approved=false`)
    - `if_updated_at_utc` (optional RFC3339 precondition; when present, must match current application `updated_at_utc`)
  - when `approved=false`, `reason` must be non-empty (`400` when missing).
  - when `approved=true`, the existing operator application must have non-empty `chain_operator_id` (`409` when missing).
  - when `if_updated_at_utc` is present but stale/mismatched, response is `409` with `ok=false`, a conflict `error`, `current_updated_at_utc` (latest application timestamp, RFC3339), and `wallet_address`.
  - matching wallet sessions are synchronized with the decision:
    - `approved=true` -> role becomes `operator` and `chain_operator_id` is set from the approved application.
    - `approved=false` -> role becomes `client` and `chain_operator_id` is cleared.

Auth can be bypassed only in explicit developer mode when all of the following are true:
- bind address is loopback-only, and
- `LOCAL_CONTROL_API_AUTH_TOKEN` is not set, and
- `LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK=1`.

For transport hardening, non-loopback binds are rejected unless `LOCAL_CONTROL_API_ALLOW_INSECURE_REMOTE_HTTP=1` is set. Keep this unset in production.

Secret handling guidance:
- avoid passing `LOCAL_CONTROL_API_AUTH_TOKEN` / `TDPN_LOCAL_API_AUTH_BEARER` in CLI args; use process-local env vars instead
- avoid persisting tokens in shared shell profiles/history; prefer short-lived shell/session scope
- never include invite keys or bearer tokens in logs, screenshots, or support tickets

Command-backed read endpoints (`GET /v1/status`, `GET /v1/config`, `GET /v1/get_diagnostics`, `GET /v1/service/status`, `GET /v1/gpm/audit/recent`) follow the same auth policy.

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

### `GET /v1/config`
- Returns non-secret local API policy/config hints for desktop/portal UX.
- Response shape:

```json
{
  "ok": true,
  "config": {
    "connect_require_session": true,
    "allow_legacy_connect_override": false,
    "gpm_main_domain": "https://globalprivatemesh.net",
    "gpm_manifest_url": "https://globalprivatemesh.net/v1/bootstrap/manifest",
    "gpm_manifest_cache_path": ".easy-node-logs/gpm_bootstrap_manifest_cache.json",
    "gpm_manifest_cache_max_age_sec": 86400,
    "command_timeout_sec": 120,
    "allow_update": false,
    "allow_remote": false
  }
}
```

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
- UI compatibility controls for manual `bootstrap_directory`/`invite_key` overrides are policy-gated by `GPM_ALLOW_LEGACY_CONNECT_OVERRIDE` (legacy alias: `TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE`); default is hidden/disabled.
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

### `POST /v1/gpm/onboarding/server/status`
Body (either field may be supplied; at least one is required):

```json
{
  "session_token": "optional-session-token",
  "wallet_address": "optional-wallet-address"
}
```

Resolution and errors:
- uses command-read auth (`requireCommandReadAuth`)
- if `session_token` is provided but missing/expired: `404` with `{"ok":false,"error":"session not found"}`
- if wallet cannot be resolved from request/session: `400` with `wallet_address or session_token is required`

Success payload:
- `ok`: `true`
- `readiness.wallet_address`: resolved wallet address
- `readiness.role`: session role when session is present, otherwise `client`
- `readiness.session_present`: whether a valid session was resolved
- `readiness.operator_application_status`: `not_submitted|pending|approved|rejected`
- `readiness.chain_operator_id`: operator application chain id when present
- `readiness.session_chain_operator_id`: chain id on resolved session when present
- `readiness.tab_visible`: `true` for `operator|admin`, else `false`
- `readiness.client_tab_visible`: `true` when the client tab is eligible/visible for the resolved role/session context
- `readiness.lifecycle_actions_unlocked`: `true` for `admin`, or `operator` with approved application and non-conflicting chain ids
- `readiness.service_mutations_configured`: `true` when all legacy service lifecycle commands are configured (`LOCAL_CONTROL_API_SERVICE_START_COMMAND`, `LOCAL_CONTROL_API_SERVICE_STOP_COMMAND`, `LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND`)
- `readiness.lock_reason`: non-empty reason when lifecycle actions are locked
- `readiness.client_lock_reason`: non-empty reason when the client tab is role-locked
- `readiness.unlock_actions`: guidance steps to unlock lifecycle actions

### `POST /v1/gpm/session`
Body:

```json
{
  "session_token": "required session token",
  "action": "status|refresh|revoke"
}
```

Behavior:
- `action` defaults to `status` when omitted.
- `status` and `refresh` reconcile non-admin sessions against current operator application state before returning:
  - `admin` role remains unchanged.
  - approved operator application for the session wallet -> role becomes `operator` and `chain_operator_id` is aligned with the approved application.
  - missing or non-approved operator application -> role becomes `client` and `chain_operator_id` is cleared.
- `status` and `refresh` responses include additive `session_reconciled`:
  - `true` only when reconciliation changed the stored session role and/or `chain_operator_id` in that request.
  - `false` when no reconciliation change was needed.
- `refresh` rotates `session_token` and extends session TTL.
- `revoke` deletes the session and does not include `session_reconciled`.

### `GET /v1/gpm/audit/recent`
Returns recent GPM local-audit JSONL entries from `GPM_AUDIT_LOG_PATH`.

Query parameters:
- `limit` (optional): default `25`; clamped to `1..200`
- `offset` (optional): default `0`; must be a non-negative integer
- `event` (optional): exact event-name match, case-insensitive
- `wallet_address` (optional): normalized wallet filter matched against `fields.wallet_address`
- `order` (optional): `desc|asc`; defaults to `desc`

Success payload:
- `ok`: `true`
- `entries`: filtered/paginated audit entries
- additive metadata:
  - `total`: total matching entries before pagination
  - `count`: number of entries returned in this page
  - `limit`: applied page size
  - `offset`: applied start offset
  - `has_more`: whether another page exists
  - `next_offset`: next offset to request (`offset + count`)
  - `filters.event`: normalized event filter
  - `filters.wallet_address`: normalized wallet filter
  - `filters.order`: applied ordering (`desc|asc`)

Validation errors:
- invalid `offset`: `400` (`offset must be a non-negative integer`)
- invalid `order`: `400` (`order must be one of: desc, asc`)
- invalid `wallet_address` filter: `400` (`wallet_address filter must be a valid wallet address`)

## Desktop Command Bridge (Scaffold)

The current desktop scaffold uses a thin Rust bridge that forwards to this API.
Command names exposed to the UI:

- `control_health` -> `GET /v1/health`
- `control_status` -> `GET /v1/status`
- `control_runtime_config` -> `GET /v1/config` (best-effort runtime policy hints)
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
