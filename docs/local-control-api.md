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
- optional production policy mode (umbrella defaulting):
  - `GPM_PRODUCTION_MODE=1` (legacy alias: `TDPN_PRODUCTION_MODE=1`)
  - when enabled and explicit per-flag overrides are unset, daemon defaults become:
    - `/v1/connect` session-required (`connect_require_session=true`)
    - manual bootstrap/invite compatibility override locked (`allow_legacy_connect_override=false`)
    - bootstrap manifest transport hardening enabled (`gpm_manifest_require_https=true`)
    - bootstrap manifest signature evidence required (`gpm_manifest_require_signature=true`)
    - auth-verify external verifier command required (`gpm_auth_verify_require_command=true`)
    - auth-verify strict metadata required (`gpm_auth_verify_require_metadata=true`)
    - auth-verify strict wallet-extension-source required (`gpm_auth_verify_require_wallet_extension_source=true`)
  - explicit env overrides still take precedence over production defaults (`GPM_CONNECT_REQUIRE_SESSION`, `GPM_OPERATOR_APPROVAL_REQUIRE_SESSION`, `GPM_ALLOW_LEGACY_CONNECT_OVERRIDE`, `GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS`, `GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE`, `GPM_AUTH_VERIFY_REQUIRE_COMMAND`, `GPM_AUTH_VERIFY_REQUIRE_METADATA`, `GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE`, `GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF`, plus legacy `TDPN_*` aliases)
- optional `/v1/connect` hardening flags (standalone or as explicit overrides):
  - `GPM_CONNECT_REQUIRE_SESSION=1` (legacy alias: `TDPN_CONNECT_REQUIRE_SESSION=1`)
  - when enabled, `/v1/connect` requires a registered `session_token` and rejects manual `bootstrap_directory` / `invite_key` overrides
  - default remains legacy-compatible unless this flag (or production mode defaults) is enabled
  - optional desktop/web compatibility-control gate:
    - `GPM_ALLOW_LEGACY_CONNECT_OVERRIDE=1` (legacy alias: `TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE=1`)
    - when disabled (default), UI compatibility controls for manual bootstrap/invite overrides are hidden by policy
- strict operator-approval auth policy:
  - `GPM_OPERATOR_APPROVAL_REQUIRE_SESSION=1` (legacy alias: `TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION=1`)
  - when enabled, `POST /v1/gpm/onboarding/operator/approve` requires an admin `session_token` and rejects legacy `admin_token` fallback
  - default is `false` for compatibility mode; when `GPM_PRODUCTION_MODE=1` is enabled and this flag is unset, default becomes `true`
- main-domain pinning for manifest trust:
  - when `GPM_MAIN_DOMAIN` (legacy alias: `TDPN_MAIN_DOMAIN`) is set, manifest URLs are trusted only when the host matches the pinned main-domain host
  - cache fallback uses the same host check against the cached manifest source URL
  - this complements existing signature verification and expiry checks
  - if the main domain is unset, this hardening is skipped for dev compatibility
- optional bootstrap manifest transport/signature hardening flags (standalone or as explicit production-default overrides):
  - `GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS=1` (legacy alias: `TDPN_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS=1`) requires HTTPS for bootstrap manifest URLs when the host is non-loopback or when a pinned main domain is configured
  - `GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE=1` (legacy alias: `TDPN_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE=1`) requires verified manifest signature evidence for both remote fetch and cache fallback
  - default for both flags is `false` in compatibility mode, and `true` by default when `GPM_PRODUCTION_MODE=1` is enabled with no explicit override

Runner behavior:
- Linux/macOS default: execute `LOCAL_CONTROL_API_SCRIPT` directly.
- Windows default:
  - `*.ps1` script path -> `powershell -NoProfile -ExecutionPolicy Bypass -File <script> ...`
  - other script paths -> prefer Git for Windows `bash.exe` (`C:\Program Files\Git\...`) when available, otherwise `bash <script> ...`
- `LOCAL_CONTROL_API_RUNNER` overrides the executable and prefixes the script path as the first argument.
- Optional Windows runner knobs:
  - `LOCAL_CONTROL_API_GIT_BASH_PATH` to pin a Git Bash path.
  - `LOCAL_CONTROL_API_PREFER_GIT_BASH=0` to disable Git Bash auto-preference and use `bash` resolution from `PATH`.

Windows local API bridge defaults (`scripts\windows\local_api_session.ps1`):
- default `LOCAL_CONTROL_API_SCRIPT` is `scripts\windows\easy_node_bridge.ps1`.
- bridge default target script is repository `scripts\easy_node.sh` (exported as `/c/.../scripts/easy_node.sh` for Git Bash).
- default run stays WSL-free and rejects `WindowsApps\bash.exe` (WSL shim).
- Git Bash is still required for default `easy_node.sh` execution unless you explicitly provide an alternative `-ScriptPath` and compatible `-CommandRunner`.
- one-shot prerequisite helper: `scripts\windows\setup_windows_native.ps1`
  - check-only: `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\setup_windows_native.ps1 -Workflow local-api`
  - unattended remediation: add `-InstallMissing -NonInteractive` (uses `winget` when available, otherwise prints deterministic fallback commands)
  - process-scope execution-policy opt-in: add `-EnablePolicyBypass`
  - dry-run preview: add `-DryRun`
- `scripts\windows\local_api_session.ps1 -InstallMissing` can auto-install Git for Windows (`Git.Git`), Go (`GoLang.Go`), and jq (`jqlang.jq`) via `winget`.
- compatibility overrides remain supported:
  - runner env override via `LOCAL_CONTROL_API_GIT_BASH_PATH` (with `-AllowRunnerEnvOverride` on the PowerShell bridge)
  - script path override via `-ScriptPath` (or `LOCAL_CONTROL_API_SCRIPT` when launching daemon directly)

Exact Windows examples:

```powershell
scripts\windows\setup_windows_native.ps1 -Workflow local-api -DryRun
scripts\windows\local_api_session.cmd -DryRun
scripts\windows\local_api_session.cmd -ScriptPath "C:\Users\dcella-d\TDPN1\scripts\easy_node.sh" -CommandRunner "C:\Program Files\Git\bin\bash.exe" -DryRun
$env:LOCAL_CONTROL_API_GIT_BASH_PATH="C:\Program Files\Git\bin\bash.exe"; scripts\windows\local_api_session.ps1 -AllowRunnerEnvOverride -DryRun
```

Desktop scaffold defaults (`apps/desktop`):
- base URL: `http://127.0.0.1:8095` (`GPM_LOCAL_API_BASE_URL`, legacy alias: `TDPN_LOCAL_API_BASE_URL`)
- request timeout: `20s` (`GPM_LOCAL_API_TIMEOUT_SEC`, legacy alias: `TDPN_LOCAL_API_TIMEOUT_SEC`)
- optional bearer auth for daemon API: `GPM_LOCAL_API_AUTH_BEARER` (legacy alias: `TDPN_LOCAL_API_AUTH_BEARER`)
- local-only transport enforcement by default, with explicit opt-out:
  - `GPM_LOCAL_API_ALLOW_REMOTE=1` (legacy alias: `TDPN_LOCAL_API_ALLOW_REMOTE=1`)
  - in local-only mode (`GPM_LOCAL_API_ALLOW_REMOTE=0`, legacy alias: `TDPN_LOCAL_API_ALLOW_REMOTE=0`), use a literal loopback IP host (`127.0.0.1` or `::1`), not a hostname.
- desktop mutating action gates are disabled by default (explicit opt-in):
  - `GPM_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1` (legacy alias: `TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1`) for `control_update`
  - `GPM_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1` (legacy alias: `TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1`) for `control_service_start|stop|restart`
  - when either mutating gate is enabled, `GPM_LOCAL_API_AUTH_BEARER` (legacy alias: `TDPN_LOCAL_API_AUTH_BEARER`) is required (including loopback-only desktop sessions)
- desktop and portal both keep `Client`/`Server` workspace tabs in one window; role-ineligible tabs stay visible but disabled with explicit lock guidance (reason + activation path) surfaced next to the tab bar
- desktop bearer token format is strict: token68 charset only (`A-Za-z0-9-._~+/=`), single-line, no whitespace/control characters, max 4096 chars
- renderer CSP is locked down in `apps/desktop/src-tauri/tauri.conf.json`:
  - production: only app resources + Tauri IPC (`ipc:`), no direct remote daemon origin, and no `unsafe-inline` in `style-src`
  - development: adds local HMR (`http://localhost:5173`, `ws://localhost:5173`)

## Endpoints

GPM onboarding/session endpoints (used by desktop and portal flows):
- `POST /v1/gpm/auth/challenge`
- `POST /v1/gpm/auth/verify` (uses a pluggable signature verifier hook in the daemon; default verifier enforces baseline proof-shape guardrails while full wallet-extension verification remains a follow-on milestone; request supports optional signature metadata: `signature_kind`, `signature_public_key`, `signature_public_key_type`, `signature_source`, `chain_id`, `signed_message`, `signature_envelope`; backward-compatible aliases `public_key` -> `signature_public_key` and `public_key_type` -> `signature_public_key_type` are accepted, and canonical keys take precedence when both canonical and alias values are non-empty; when provided, `signed_message` must exactly match the issued challenge message, `signature_kind` must be `sign_arbitrary` or `eip191`, `signature_source` must be `wallet_extension` or `manual`, `signature_public_key_type` must be `secp256k1` or `ed25519`, and `signature_envelope` (string or JSON payload) is normalized and capped at 16384 bytes; if `signature_public_key`, `signature_public_key_type`, and `signed_message` are present, daemon-side cryptographic verification is attempted for supported key types (`ed25519` and `secp256k1`) and invalid supported proofs are rejected; secp256k1 proof decoding accepts compressed/uncompressed keys (33/64/65-byte hex or base64) and raw or DER ECDSA signatures (64-byte `r||s`, 65-byte with recovery id, or ASN.1 DER), verified against `sha256(signed_message)`; omitting crypto-proof metadata preserves existing behavior)
- optional external verifier hook: set `GPM_AUTH_VERIFY_COMMAND` (legacy alias: `TDPN_AUTH_VERIFY_COMMAND`) to run a local command after baseline validation; the command receives context via env vars: `GPM_AUTH_VERIFY_CHALLENGE_ID`, `GPM_AUTH_VERIFY_MESSAGE`, `GPM_AUTH_VERIFY_WALLET_ADDRESS`, `GPM_AUTH_VERIFY_WALLET_PROVIDER`, `GPM_AUTH_VERIFY_SIGNATURE`, `GPM_AUTH_VERIFY_SIGNATURE_KIND`, `GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY`, `GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY_TYPE`, `GPM_AUTH_VERIFY_SIGNATURE_SOURCE`, `GPM_AUTH_VERIFY_CHAIN_ID`, `GPM_AUTH_VERIFY_SIGNED_MESSAGE`, `GPM_AUTH_VERIFY_SIGNATURE_ENVELOPE`
- strict external-verifier policy: set `GPM_AUTH_VERIFY_REQUIRE_COMMAND=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_COMMAND=1`) to require `GPM_AUTH_VERIFY_COMMAND` to be configured; this defaults to `false` in compatibility mode and defaults to `true` when `GPM_PRODUCTION_MODE=1` is enabled with no explicit override; when enabled and the command is unset, `POST /v1/gpm/auth/verify` fails closed with a policy error.
- strict metadata policy: set `GPM_AUTH_VERIFY_REQUIRE_METADATA=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_METADATA=1`) to require `signature_kind`, `signature_source`, and `signed_message`; default is `false` for compatibility unless `GPM_PRODUCTION_MODE=1` is enabled and this flag is unset, and when enabled `POST /v1/gpm/auth/verify` fails closed with a policy error when required metadata is missing.
- strict wallet-extension-source policy: set `GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE=1`) to require explicit `signature_source=wallet_extension`; default is `false` for compatibility unless `GPM_PRODUCTION_MODE=1` is enabled and this flag is unset, and when enabled `POST /v1/gpm/auth/verify` fails closed with a policy error when the source requirement is not met.
- strict cryptographic proof policy: set `GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF=1`) to fail closed unless cryptographic proof metadata is present (`signature_public_key`, `signature_public_key_type`, `signed_message`) and verifiable for a supported type; default is `false` (including production mode unless explicitly enabled). When this policy is disabled, missing or partial crypto-proof metadata does not fail closed and the optional external verifier command can still provide additional validation.
- `GET /v1/gpm/bootstrap/manifest` (command-read auth; returns trusted manifest payload with additive telemetry fields: `trust_status`, `manifest_generated_at_utc`, `manifest_expires_at_utc`, `manifest_expires_in_sec`, `manifest_source_url`, `pinned_main_domain_host`, `signature_required_by_policy`, `https_required_by_policy`, `cache_max_age_sec`, `remote_refresh_interval_sec`; when serving cache after a periodic refresh failure, includes `remote_refresh_warning`)
- `POST /v1/gpm/session` (`action=status|refresh|revoke`; `status`/`refresh` reconcile non-admin session role against current operator decision and include additive `session_reconciled` response metadata)
- `POST /v1/gpm/onboarding/client/register` (persists a session-bound `path_profile`, trusted `bootstrap_directories` from the signed manifest, and preferred `bootstrap_directory`; used as authoritative connect policy for session-token connects)
- `POST /v1/gpm/onboarding/client/status` (returns trust-aware registration state: `registered|not_registered|degraded`, preferred `bootstrap_directory`, trusted `bootstrap_directories`, persisted `path_profile` when available, and additive `status_reason` when registration is no longer trusted or trust revalidation fails)
- `POST /v1/gpm/onboarding/server/status` (returns server-tab/lifecycle readiness derived from role, operator approval state, and strict chain-binding checks)
- `POST /v1/gpm/onboarding/overview` (consolidated onboarding contract for a `session_token`, returning `session + registration + readiness` in one response)
- `POST /v1/gpm/onboarding/operator/apply`
- `POST /v1/gpm/onboarding/operator/status`
- `POST /v1/gpm/onboarding/operator/list` (admin-only; supports optional `status` filter (`pending|approved|rejected`), optional `search` substring filter (`wallet_address`, `chain_operator_id`, `server_label`, `status`, `reason`), optional `limit` (default `100`, clamped `1..500`), and optional cursor pagination via `cursor="<updated_at_utc>|<wallet_address>"`; response includes additive pagination metadata `total`, `has_more`, `next_cursor`, and echoed `request` fields)
- `POST /v1/gpm/onboarding/operator/approve` (requires admin authorization: `session_token` with admin role, or legacy `admin_token` fallback when an approval admin token env is configured; strict mode `GPM_OPERATOR_APPROVAL_REQUIRE_SESSION=1` (legacy alias: `TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION=1`) disables that fallback and fails closed unless an admin `session_token` is provided; primary approval-token env is `GPM_APPROVAL_ADMIN_TOKEN` (legacy aliases: `TDPN_APPROVAL_ADMIN_TOKEN`, `GPM_OPERATOR_APPROVAL_TOKEN`, `TDPN_OPERATOR_APPROVAL_TOKEN`); request body supports optional optimistic concurrency precondition `if_updated_at_utc` (RFC3339); successful responses include additive `decision` (`approved|rejected`) and `decision_auth` (`admin_session|legacy_admin_token`) metadata; matching wallet sessions are promoted on approval and demoted on rejection)
- `GET /v1/gpm/audit/recent` (command-read auth; supports optional `limit` (default `25`, clamped `1..200`), optional `offset` (`>=0`), optional exact case-insensitive `event` filter, optional normalized `wallet_address` filter against `fields.wallet_address`, and optional `order` (`desc|asc`, default `desc`); response includes additive metadata `total`, `count`, `limit`, `offset`, `has_more`, `next_offset`, and echoed `filters`)
- `GET /v1/gpm/gaps/summary` (command-read auth; reads `GPM_GAP_SCAN_SUMMARY_JSON` (legacy alias `TDPN_GAP_SCAN_SUMMARY_JSON`, default `.easy-node-logs/gpm_gap_scan_summary.json`) and returns fail-closed status: `ok` with normalized `in_progress`/`missing_next` items plus convenience `key_gaps`/`next_actions`, or one of `artifact_missing|artifact_unreadable|artifact_malformed` when source evidence is unavailable or invalid)

## Authentication

Mutating endpoints (`POST /v1/connect`, `POST /v1/disconnect`, `POST /v1/set_profile`, `POST /v1/update`, `POST /v1/service/start`, `POST /v1/service/stop`, `POST /v1/service/restart`) require auth by default.
GPM server lifecycle endpoints (`POST /v1/gpm/service/start`, `POST /v1/gpm/service/stop`, `POST /v1/gpm/service/restart`) also require an approved `operator` or `admin` session issued via `/v1/gpm/session`; for `operator` sessions, unlock is strict-bound and requires session/application `chain_operator_id` values to both be present and equal.
`POST /v1/gpm/onboarding/operator/list` uses command-read auth and requires a valid `admin` `session_token`:
- missing `session_token`: `400` (`session_token is required`)
- missing/expired session token: `404` (`session not found`)
- non-admin session role: `403` (`admin session role is required`)
- invalid cursor format: `400` (`cursor must be in the format <updated_at_utc>|<wallet_address>`)
`POST /v1/gpm/onboarding/operator/approve` also requires admin-level authorization:
- preferred: `session_token` for a valid `admin` session.
- compatibility fallback: `admin_token` matching `GPM_APPROVAL_ADMIN_TOKEN` (legacy aliases: `TDPN_APPROVAL_ADMIN_TOKEN`, `GPM_OPERATOR_APPROVAL_TOKEN`, `TDPN_OPERATOR_APPROVAL_TOKEN`) when configured.
- strict policy mode: when `GPM_OPERATOR_APPROVAL_REQUIRE_SESSION=1` (legacy alias: `TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION=1`), legacy `admin_token` fallback is disabled and requests without an admin `session_token` fail closed with a policy error.
- if the approval admin token env is unset and no admin session token is provided, approval is rejected.
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
- avoid passing `LOCAL_CONTROL_API_AUTH_TOKEN` / `GPM_LOCAL_API_AUTH_BEARER` (legacy alias: `TDPN_LOCAL_API_AUTH_BEARER`) in CLI args; use process-local env vars instead
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
- Returns `client-vpn-status --show-json 1` as `status`.
- Also returns additive top-level routing posture telemetry in `routing`:
  - `mode`: `direct | relay_fallback | relay | unknown`
  - `relay_fallback_active`: boolean
  - `direct_preferred`: boolean
  - `detail`: optional routing detail/reason text when available
  - `source`: telemetry source label (`status_payload`)

### `GET /v1/config`
- Returns non-secret local API policy/config hints for desktop/portal UX.
- Response shape:

```json
{
  "ok": true,
  "config": {
    "connect_require_session": true,
    "allow_legacy_connect_override": false,
    "gpm_production_mode": true,
    "gpm_production_mode_source": "GPM_PRODUCTION_MODE",
    "connect_policy_mode": "production",
    "connect_policy_source": "GPM_PRODUCTION_MODE",
    "gpm_operator_approval_require_session": true,
    "gpm_operator_approval_require_session_policy_source": "production-default",
    "gpm_manifest_trust_policy_mode": "production",
    "gpm_manifest_trust_policy_source": "GPM_PRODUCTION_MODE",
    "gpm_manifest_require_https": true,
    "gpm_manifest_require_https_policy_source": "production-default",
    "gpm_manifest_require_signature": true,
    "gpm_manifest_require_signature_policy_source": "production-default",
    "gpm_auth_verify_policy_mode": "production",
    "gpm_auth_verify_policy_source": "GPM_PRODUCTION_MODE",
    "gpm_auth_verify_require_command": true,
    "gpm_auth_verify_require_command_policy_source": "production-default",
    "gpm_auth_verify_require_metadata": false,
    "gpm_auth_verify_require_metadata_policy_source": "production-default",
    "gpm_auth_verify_require_wallet_extension_source": false,
    "gpm_auth_verify_require_wallet_extension_policy_source": "GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE",
    "gpm_auth_verify_require_crypto_proof": false,
    "gpm_auth_verify_require_crypto_proof_policy_source": "default",
    "gpm_auth_verify_command_configured": false,
    "gpm_main_domain": "https://globalprivatemesh.net",
    "gpm_manifest_url": "https://globalprivatemesh.net/v1/bootstrap/manifest",
    "gpm_manifest_cache_path": ".easy-node-logs/gpm_bootstrap_manifest_cache.json",
    "gpm_manifest_cache_max_age_sec": 86400,
    "gpm_manifest_resolve_policy": "cache_first_bounded_remote_refresh",
    "gpm_legacy_env_aliases_active": [
      "TDPN_PRODUCTION_MODE"
    ],
    "gpm_legacy_env_aliases_active_count": 1,
    "gpm_legacy_env_alias_warnings": [
      "TDPN_PRODUCTION_MODE is deprecated; migrate to GPM_PRODUCTION_MODE"
    ],
    "gpm_legacy_env_aliases_warning": "TDPN_PRODUCTION_MODE is deprecated; migrate to GPM_PRODUCTION_MODE",
    "command_timeout_sec": 120,
    "allow_update": false,
    "allow_remote": false
  }
}
```

Policy posture config hints:
- `gpm_production_mode`: additive umbrella production-policy posture boolean derived from runtime production mode resolution.
- `gpm_production_mode_source`: additive source for `gpm_production_mode` selection (`GPM_PRODUCTION_MODE`, `TDPN_PRODUCTION_MODE`, or `default` when unset).
- `connect_policy_mode`: additive connect posture mode (`default|production` in current daemon behavior).
- `connect_policy_source`: additive source for connect posture mode/defaulting (for example `GPM_PRODUCTION_MODE`, `GPM_CONNECT_REQUIRE_SESSION`, `TDPN_CONNECT_REQUIRE_SESSION`, or `default`).
- `gpm_operator_approval_require_session`: whether strict operator-approval auth policy is enabled (`session_token` required for admin moderation decisions, legacy `admin_token` fallback disabled).
- `gpm_operator_approval_require_session_policy_source`: additive source for operator-approval auth strictness (`production-default` when inherited from production mode with no explicit `GPM_OPERATOR_APPROVAL_REQUIRE_SESSION` override).
- `gpm_manifest_trust_policy_mode`: additive manifest-trust posture mode (`default|production`).
- `gpm_manifest_trust_policy_source`: additive source for manifest-trust posture mode/defaulting (for example `GPM_PRODUCTION_MODE` or `default`).
- `gpm_manifest_require_https`: whether manifest URL transport hardening is enabled.
- `gpm_manifest_require_https_policy_source`: additive source for manifest HTTPS strictness (`production-default` when inherited from production mode with no explicit manifest HTTPS env override).
- `gpm_manifest_require_signature`: whether strict manifest signature evidence policy is enabled for both remote fetch and cache fallback.
- `gpm_manifest_require_signature_policy_source`: additive source for manifest signature strictness (`production-default` when inherited from production mode with no explicit signature-policy env override).
- `gpm_manifest_cache_max_age_sec`: manifest cache trust max age in seconds (runtime value derived from `GPM_BOOTSTRAP_MANIFEST_CACHE_MAX_AGE_SEC`, legacy alias `TDPN_BOOTSTRAP_MANIFEST_CACHE_MAX_AGE_SEC`).
- `gpm_manifest_remote_refresh_interval_sec`: bounded periodic remote refresh interval in seconds when a trusted cache entry is still valid (runtime value derived from `GPM_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC`, legacy alias `TDPN_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC`).
- `gpm_manifest_remote_refresh_interval_source`: additive source describing how `gpm_manifest_remote_refresh_interval_sec` was selected (`GPM_*`, `TDPN_*`, or `default`).
- `gpm_manifest_resolve_policy`: additive manifest resolve strategy hint (`cache_first_bounded_remote_refresh` in current daemon behavior).
- `gpm_auth_verify_policy_mode`: additive auth-verify posture mode (`default|production`).
- `gpm_auth_verify_policy_source`: additive source for auth-verify posture mode/defaulting (for example `GPM_PRODUCTION_MODE` or `default`).
- `gpm_auth_verify_require_command`: whether strict external verifier command policy is enabled.
- `gpm_auth_verify_require_command_policy_source`: additive source for verifier-command strictness (`production-default` when inherited from production mode with no explicit verifier-command env override).
- `gpm_auth_verify_require_metadata`: whether strict metadata policy is enabled (`signature_kind`, `signature_source`, and `signed_message` required at verify time).
- `gpm_auth_verify_require_metadata_policy_source`: additive source for metadata strictness (`production-default` when inherited from production mode with no explicit metadata env override).
- `gpm_auth_verify_require_wallet_extension_source`: whether strict wallet-extension-source policy is enabled (`signature_source=wallet_extension` required at verify time).
- `gpm_auth_verify_require_wallet_extension_policy_source`: additive source for wallet-extension-source strictness (`production-default` when inherited from production mode with no explicit wallet-source env override).
- `gpm_auth_verify_require_crypto_proof`: whether strict cryptographic proof policy is enabled (`signature_public_key`, `signature_public_key_type`, and `signed_message` required; supported proof types must verify successfully).
- `gpm_auth_verify_require_crypto_proof_policy_source`: additive source for strict cryptographic proof policy selection (`GPM_*`, `TDPN_*`, or `default`; no production auto-default).
- `gpm_auth_verify_command_configured`: whether `GPM_AUTH_VERIFY_COMMAND` is currently configured.
- `gpm_legacy_env_aliases_active`: additive list of active legacy alias env keys (currently `TDPN_*`) that were actually selected as effective runtime sources.
- `gpm_legacy_env_aliases_active_count`: additive count of `gpm_legacy_env_aliases_active` (convenience telemetry for lightweight clients).
- `gpm_legacy_env_alias_warnings`: additive list of deprecation warnings for active legacy aliases.
- `gpm_legacy_env_aliases_warning`: additive semicolon-joined warning string for simple status banners/log forwarding.

Legacy alias telemetry semantics:
- Active aliases are only aliases that were effective at runtime. If both primary `GPM_*` and legacy `TDPN_*` are set for the same setting, the primary key wins and the legacy alias is shadowed (not reported as active).
- Warning fields describe deprecation/migration guidance for active aliases and are empty when no legacy alias is active.

Backward compatibility notes:
- These mode/source posture keys are additive observability fields; clients must treat them as optional.
- Legacy alias telemetry fields are additive observability only; clients must treat missing fields as "no telemetry provided" and continue normal operation.
- Older daemons may return only legacy booleans (`connect_require_session`, `allow_legacy_connect_override`, and auth-verify strictness booleans); clients should continue functioning by deriving posture from those booleans when mode/source keys are absent.

### `POST /v1/connect`
Body:

```json
{
  "session_token": "optional-session-token",
  "session_bootstrap_directory": "https://HOST:8081",
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
- production hardening can be enabled explicitly (`GPM_CONNECT_REQUIRE_SESSION=1`, legacy `TDPN_CONNECT_REQUIRE_SESSION=1`) or inherited by default from `GPM_PRODUCTION_MODE=1` / `TDPN_PRODUCTION_MODE=1` when connect-specific overrides are unset; in hardening mode, connect requires `session_token` and rejects manual `bootstrap_directory`/`invite_key` request overrides.
- UI compatibility controls for manual `bootstrap_directory`/`invite_key` overrides are policy-gated by `GPM_ALLOW_LEGACY_CONNECT_OVERRIDE` (legacy alias: `TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE`); default is hidden/disabled.
- when hardening mode is not enabled (default), legacy `bootstrap_directory` + `invite_key` behavior remains available.
- when connect resolves credentials from a registered `session_token`, the session-bound `path_profile` from client registration is authoritative.
- `session_bootstrap_directory` is only used for session-based connect flows; it must match one of the session's trusted bootstrap directories after manifest trust revalidation, and if omitted the daemon uses the preferred/fallback trusted directory list automatically.
- `session_bootstrap_directory` must not be combined with manual `bootstrap_directory` / `invite_key` compatibility overrides.
- conflicting request `path_profile`/`policy_profile` values are rejected fail-closed (request is not executed) with conflict semantics in the error message.

Behavior:
- runs optional `client-vpn-preflight`
- then runs `client-vpn-up` (background)
- returns status payload, selected `bootstrap_directory`, and additive routing posture telemetry in top-level `routing`

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

### `POST /v1/gpm/onboarding/client/status`
Body:

```json
{
  "session_token": "required session token"
}
```

Resolution and errors:
- uses command-read auth (`requireCommandReadAuth`)
- missing `session_token`: `400` with `{"ok":false,"error":"session_token is required"}`
- missing/expired session token: `404` with `{"ok":false,"error":"session not found"}`

Success payload:
- `ok`: `true`
- `registration.wallet_address`: session wallet address
- `registration.status`: trust-aware registration status (`registered|not_registered|degraded`)
- `registration.bootstrap_directory`: preferred trusted bootstrap directory (empty when trust drift/hard-failure prevents trusted resolution)
- `registration.bootstrap_directories`: trusted bootstrap candidates (empty when trust drift/hard-failure prevents trusted resolution)
- `registration.path_profile`: persisted session profile when available
- `registration.status_reason`: additive non-empty reason when `registration.status` is not healthy due to trust drift or trust revalidation failure

Trust-aware status behavior:
- `registered`: returned only when session bootstrap registration exists and at least one session bootstrap directory still matches the current trusted manifest set.
- `not_registered` with `status_reason`: returned when registered session bootstrap directories drift from trust (no session directory remains trusted by the current manifest).
- `degraded` with `status_reason`: returned when trust revalidation fails hard (for example manifest trust check/load failure), so the daemon cannot safely confirm trust.

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
- `readiness.lifecycle_actions_unlocked`: `true` for `admin`, or `operator` with approved application where both `readiness.chain_operator_id` and `readiness.session_chain_operator_id` are present and equal (strict chain binding)
- `readiness.chain_binding_status`: additive chain-binding state for operator sessions (`bound|pending_approval|mismatch|not_applicable|unknown`)
- `readiness.chain_binding_ok`: additive boolean convenience flag (`true` only when chain binding is currently healthy/bound)
- `readiness.chain_binding_reason`: additive operator-facing reason when chain binding is not healthy (for example pending approval or chain-id mismatch); preserve this reason in clients and append actionable next steps (refresh session, or re-apply/re-approve when mismatch persists)
- `readiness.service_mutations_configured`: `true` when all legacy service lifecycle commands are configured (`LOCAL_CONTROL_API_SERVICE_START_COMMAND`, `LOCAL_CONTROL_API_SERVICE_STOP_COMMAND`, `LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND`)
- `readiness.lock_reason`: non-empty reason when lifecycle actions are locked
- `readiness.client_lock_reason`: non-empty reason when the client tab is role-locked
- `readiness.unlock_actions`: guidance steps to unlock lifecycle actions
- `readiness.endpoint_posture`: additive endpoint posture snapshot used for server-tab diagnostics (for example, provider/authority and HTTP/HTTPS posture hints)
- `readiness.endpoint_warnings`: additive list of actionable warning strings derived from endpoint posture checks
- endpoint diagnostics are advisory and non-blocking; they do not lock lifecycle actions by themselves
- the web portal Step-3 operator view surfaces `endpoint_posture` and `endpoint_warnings` in the endpoint trust posture banner for operator-facing diagnostics

### `POST /v1/gpm/onboarding/overview`
Body:

```json
{
  "session_token": "required session token"
}
```

Resolution and errors:
- uses command-read auth (`requireCommandReadAuth`)
- missing `session_token`: `400` with `{"ok":false,"error":"session_token is required"}`
- missing/expired session token: `404` with `{"ok":false,"error":"session not found"}`
- unresolved/invalid session wallet identity: `400` with `wallet_address or session_token is required`

Success payload:
- `ok`: `true`
- `session`: same session shape returned by `POST /v1/gpm/session` (`wallet_address`, `wallet_provider`, `role`, `created_at_utc`, `expires_at_utc`, preferred `bootstrap_directory`, trusted `bootstrap_directories`, optional `path_profile`, optional `chain_operator_id`)
- `registration`: same registration shape as `POST /v1/gpm/onboarding/client/status`
- `readiness`: same readiness shape as `POST /v1/gpm/onboarding/server/status`
- `readiness` therefore includes additive chain-binding readiness keys: `chain_binding_status`, `chain_binding_ok`, `chain_binding_reason`
- trust-aware client registration readiness is mirrored via additive `readiness.client_registration_status` and `readiness.client_registration_reason`

Compatibility note:
- `POST /v1/gpm/onboarding/client/status` and `POST /v1/gpm/onboarding/server/status` remain fully supported; `POST /v1/gpm/onboarding/overview` is an additive consolidated contract to reduce round-trips.

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
