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
    - auth-verify strict cryptographic proof required (`gpm_auth_verify_require_crypto_proof=true`)
    - legacy `/v1/service/start|stop|restart` mutations blocked (`allow_legacy_service_mutations=false`)
    - GPM settlement finalization requires a chain-backed settlement adapter (`gpm_settlement_chain_required=true`)
  - explicit env overrides still take precedence over production defaults (`GPM_CONNECT_REQUIRE_SESSION`, `GPM_OPERATOR_APPROVAL_REQUIRE_SESSION`, `GPM_ALLOW_LEGACY_CONNECT_OVERRIDE`, `GPM_ALLOW_LEGACY_SERVICE_MUTATIONS`, `GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS`, `GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE`, `GPM_AUTH_VERIFY_REQUIRE_COMMAND`, `GPM_AUTH_VERIFY_REQUIRE_METADATA`, `GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE`, `GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF`, plus legacy `TDPN_*` aliases)
- GPM settlement adapter wiring:
  - compatibility mode defaults to local memory settlement for developer flows.
  - production mode (`GPM_PRODUCTION_MODE=1`) still boots without a configured adapter for status/config inspection, but Admin Console reward finalization fails closed until `gpm_settlement_chain_backed=true`.
  - set `GPM_SETTLEMENT_COSMOS_ENDPOINT` (legacy alias: `TDPN_SETTLEMENT_COSMOS_ENDPOINT`) to wire the local settlement service through `CosmosAdapter`; `GPM_SETTLEMENT_BACKEND=cosmos` can require Cosmos wiring explicitly (`auto|memory|cosmos`, legacy alias: `TDPN_SETTLEMENT_BACKEND`).
  - optional Cosmos adapter env: `GPM_SETTLEMENT_COSMOS_API_KEY`, `GPM_SETTLEMENT_COSMOS_QUEUE_SIZE`, `GPM_SETTLEMENT_COSMOS_MAX_RETRIES`, `GPM_SETTLEMENT_COSMOS_BASE_BACKOFF_MS`, `GPM_SETTLEMENT_COSMOS_HTTP_TIMEOUT_SEC`, `GPM_SETTLEMENT_COSMOS_ALLOW_INSECURE_HTTP`, `GPM_SETTLEMENT_COSMOS_SUBMIT_MODE`, and signed-tx fields `GPM_SETTLEMENT_COSMOS_SIGNED_TX_BROADCAST_PATH`, `GPM_SETTLEMENT_COSMOS_SIGNED_TX_CHAIN_ID`, `GPM_SETTLEMENT_COSMOS_SIGNED_TX_SIGNER`, `GPM_SETTLEMENT_COSMOS_SIGNED_TX_SECRET`, `GPM_SETTLEMENT_COSMOS_SIGNED_TX_SECRET_FILE`, `GPM_SETTLEMENT_COSMOS_SIGNED_TX_KEY_ID` (all support `TDPN_*` legacy aliases).
  - `/v1/config` reports non-secret settlement posture only; adapter secrets and API keys are never returned.
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
- admin wallet allowlist:
  - `GPM_ADMIN_WALLET_ALLOWLIST=wallet1,wallet2` (legacy alias: `TDPN_ADMIN_WALLET_ALLOWLIST`) is the only way a verified sign-in session can be elevated to `admin`.
  - allowlist membership is necessary but not sufficient: the wallet binding must verify, and admin elevation requires command-backed verification through `GPM_AUTH_VERIFY_COMMAND` or strict command-required policy (`GPM_AUTH_VERIFY_REQUIRE_COMMAND=1`, which is a production default).
  - baseline/local proof-shape validation alone never grants admin role; without command-backed verification, allowlisted wallets remain non-admin.
  - `/v1/config` exposes `gpm_admin_wallet_allowlist_configured`, `gpm_admin_wallet_allowlist_count`, and `gpm_admin_wallet_allowlist_source` for Admin Console readiness checks.
- main-domain pinning for manifest trust:
  - when `GPM_MAIN_DOMAIN` (legacy alias: `TDPN_MAIN_DOMAIN`) is set, manifest URLs are trusted only when the host matches the pinned main-domain host
  - cache fallback uses the same host check against the cached manifest source URL
  - this complements existing signature verification and expiry checks
  - if the main domain is unset, this hardening is skipped for dev compatibility
- optional bootstrap manifest transport/signature hardening flags (standalone or as explicit production-default overrides):
  - `GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS=1` (legacy alias: `TDPN_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS=1`) requires HTTPS for bootstrap manifest URLs when the host is non-loopback or when a pinned main domain is configured
  - `GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE=1` (legacy alias: `TDPN_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE=1`) requires verified manifest signature evidence for both remote fetch and cache fallback
  - default for both flags is `false` in compatibility mode, and `true` by default when `GPM_PRODUCTION_MODE=1` is enabled with no explicit override
  - production manifest fetches use a direct hardened outbound policy and fail closed when the manifest target resolves to private, loopback, link-local, unspecified, or multicast addresses

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
- public desktop app mode is the default and contains zero admin controls:
  - `GPM_DESKTOP_ADMIN_CONSOLE=1` (or `GPM_ADMIN_CONSOLE=1`; legacy alias: `TDPN_DESKTOP_ADMIN_CONSOLE=1`) is required to expose the separate GPM Admin Console surface.
  - release/public app controls are limited to the signed-in user's account, VPN connection, public status/config diagnostics, and optional contribution opt-in/out.
  - server controls, approvals, policy changes, slashing review, settlement review, and payout controls belong to the Admin Console/API surface only.
- daemon admin routes are also disabled by default for the release/public GPM App:
  - set `GPM_LOCAL_API_ADMIN_ROUTES=1` when launching the daemon for the separate Admin Console.
  - legacy `TDPN_LOCAL_API_ADMIN_ROUTES=1` is supported; desktop UI flags such as `GPM_ADMIN_CONSOLE=1`, `GPM_DESKTOP_ADMIN_CONSOLE=1`, and `TDPN_DESKTOP_ADMIN_CONSOLE=1` only expose the separate desktop Admin Console surface and do not enable daemon admin routes.
  - invalid boolean values fail closed and keep the daemon in public-app route mode.
  - `/v1/config` reports `gpm_daemon_surface_mode`, `gpm_admin_routes_enabled`, and `gpm_admin_routes_policy_source` so clients can explain why admin routes are or are not available.
- public desktop and public portal releases hide admin/server controls entirely; Admin Console builds may keep `Client`/`Server` workspace tabs in one window with role-ineligible tabs disabled and explicit lock guidance (reason + activation path) surfaced next to the tab bar
- VPN connect route installation is conservative by default: `/v1/connect` sends `--install-route 0` unless the request explicitly sets `install_route=true`; public client wrappers such as `client-vpn-up` mirror this with `CLIENT_WG_INSTALL_ROUTE=0` by default. In prod profile, `client-vpn-up` now refuses full-tunnel `AllowedIPs` with `install_route=0` unless an operator explicitly sets `--allow-no-route 1`/`GPM_CLIENT_VPN_ALLOW_NO_ROUTE=1` for controlled diagnostics. Full-tunnel/default-route install remains an expert opt-in until endpoint/control-plane bypass routing is fully enforced.
- desktop bearer token format is strict: token68 charset only (`A-Za-z0-9-._~+/=`), single-line, no whitespace/control characters, max 4096 chars
- renderer CSP is locked down in `apps/desktop/src-tauri/tauri.conf.json`:
  - production: only app resources + Tauri IPC (`ipc:`), no direct remote daemon origin, and no `unsafe-inline` in `style-src`
  - development: adds local HMR (`http://localhost:5173`, `ws://localhost:5173`)

## Endpoints

Route surface split:
- Public-app mode is the default daemon surface and registers only user/client-safe routes such as `GET /v1/health`, `GET /v1/status`, `GET /v1/config`, `POST /v1/connect`, `POST /v1/disconnect`, `GET /v1/gpm/bootstrap/manifest`, `POST /v1/gpm/auth/challenge`, `POST /v1/gpm/auth/verify`, `POST /v1/gpm/session`, `POST /v1/gpm/onboarding/client/register`, `POST /v1/gpm/onboarding/client/status`, `POST /v1/gpm/contribution/enable`, `POST /v1/gpm/contribution/disable`, `POST /v1/gpm/settlement/reserve-funds`, and signed-in-user reward reads.
- Admin Console mode additionally registers operator/admin routes such as `POST /v1/set_profile`, `POST /v1/update`, `GET /v1/service/status`, `POST /v1/service/start|stop|restart`, `POST /v1/gpm/service/start|stop|restart`, `GET /v1/gpm/audit/recent`, `GET /v1/gpm/gaps/summary`, `POST /v1/gpm/admin/contributions/list`, `POST /v1/gpm/admin/rewards/review`, `POST /v1/gpm/admin/rewards/hold`, `POST /v1/gpm/admin/rewards/finalize`, `POST /v1/gpm/onboarding/server/status`, and operator apply/list/approve/status routes.
- Admin Console route registration is independent from session authorization: enabling `GPM_LOCAL_API_ADMIN_ROUTES=1` makes the route surface available, while the individual handlers still require bearer/mutation auth plus the documented `operator` or `admin` session checks.

GPM onboarding/session endpoints (used by desktop and portal flows):
- `POST /v1/gpm/auth/challenge`
- `POST /v1/gpm/auth/verify` (uses a pluggable signature verifier hook in the daemon; default verifier enforces baseline proof-shape guardrails; request supports optional signature metadata: `signature_kind`, `signature_public_key`, `signature_public_key_type`, `signature_source`, `chain_id`, `signed_message`, `signature_envelope`; backward-compatible aliases `public_key` -> `signature_public_key` and `public_key_type` -> `signature_public_key_type` are accepted, and canonical keys take precedence when both canonical and alias values are non-empty; when provided, `signed_message` must exactly match the issued challenge message, `signature_kind` must be `sign_arbitrary` or `eip191`, `signature_source` must be `wallet_extension` or `manual`, `signature_public_key_type` must normalize to `secp256k1` or `ed25519` and accepts common Cosmos aliases such as `tendermint/PubKeySecp256k1` and `/cosmos.crypto.secp256k1.PubKey`, and `signature_envelope` (string or JSON payload) is normalized and capped at 16384 bytes; if `signature_public_key`, `signature_public_key_type`, and `signed_message` are present, daemon-side cryptographic verification is attempted for supported key types (`ed25519` and `secp256k1`) and invalid supported proofs are rejected; secp256k1 proof decoding accepts compressed/uncompressed keys (33/64/65-byte hex or base64) and raw or DER ECDSA signatures (64-byte `r||s`, 65-byte with recovery id, or ASN.1 DER), verified against `sha256(signed_message)`; matching secp256k1 proofs also derive a Cosmos-style Bech32 address with the submitted wallet HRP and set `wallet_binding_verified=true` when it matches the submitted wallet address; when strict crypto-proof policy is disabled, omitting crypto-proof metadata preserves existing behavior)
- optional external verifier hook: set `GPM_AUTH_VERIFY_COMMAND` (legacy alias: `TDPN_AUTH_VERIFY_COMMAND`) to run a local command after baseline validation; the command receives context via env vars: `GPM_AUTH_VERIFY_CHALLENGE_ID`, `GPM_AUTH_VERIFY_MESSAGE`, `GPM_AUTH_VERIFY_WALLET_ADDRESS`, `GPM_AUTH_VERIFY_WALLET_PROVIDER`, `GPM_AUTH_VERIFY_SIGNATURE`, `GPM_AUTH_VERIFY_SIGNATURE_KIND`, `GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY`, `GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY_TYPE`, `GPM_AUTH_VERIFY_SIGNATURE_SOURCE`, `GPM_AUTH_VERIFY_CHAIN_ID`, `GPM_AUTH_VERIFY_SIGNED_MESSAGE`, `GPM_AUTH_VERIFY_SIGNATURE_ENVELOPE`
- strict external-verifier policy: set `GPM_AUTH_VERIFY_REQUIRE_COMMAND=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_COMMAND=1`) to require `GPM_AUTH_VERIFY_COMMAND` to be configured; this defaults to `false` in compatibility mode and defaults to `true` when `GPM_PRODUCTION_MODE=1` is enabled with no explicit override; when enabled and the command is unset, `POST /v1/gpm/auth/verify` fails closed with a policy error.
- strict metadata policy: set `GPM_AUTH_VERIFY_REQUIRE_METADATA=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_METADATA=1`) to require `signature_kind`, `signature_source`, and `signed_message`; default is `false` for compatibility unless `GPM_PRODUCTION_MODE=1` is enabled and this flag is unset, and when enabled `POST /v1/gpm/auth/verify` fails closed with a policy error when required metadata is missing.
- strict wallet-extension-source policy: set `GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE=1`) to require explicit `signature_source=wallet_extension`; default is `false` for compatibility unless `GPM_PRODUCTION_MODE=1` is enabled and this flag is unset, and when enabled `POST /v1/gpm/auth/verify` fails closed with a policy error when the source requirement is not met.
- strict cryptographic proof policy: set `GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF=1`) to fail closed unless cryptographic proof metadata is present (`signature_public_key`, `signature_public_key_type`, `signed_message`) and verifiable for a supported type; default is `false` in compatibility mode and `true` when `GPM_PRODUCTION_MODE=1` is enabled with no explicit override. When this policy is disabled, missing or partial crypto-proof metadata does not fail closed and the optional external verifier command can still provide additional validation.
- chain-bound wallet policy: set `GPM_AUTH_VERIFY_EXPECTED_CHAIN_ID` (legacy alias: `TDPN_AUTH_VERIFY_EXPECTED_CHAIN_ID`) to bind issued challenges and minted sessions to one wallet chain ID. `POST /v1/gpm/auth/challenge` accepts optional `chain_id`; when the policy is set, omitted challenge chain IDs are filled from policy, mismatched challenge/verify chain IDs fail closed, and the challenge message includes the chain ID that wallet extensions must sign. Set `GPM_AUTH_VERIFY_EXPECTED_WALLET_HRP` (legacy alias: `TDPN_AUTH_VERIFY_EXPECTED_WALLET_HRP`) to require wallet addresses with a specific Bech32 HRP before challenge/verify can mint a session.
- wallet-bound session semantics: local secp256k1 proof can set `wallet_binding_verified=true` only when the daemon derives a matching Cosmos-style Bech32 wallet address from the submitted public key; local ed25519 proof remains signature-only for Cosmos wallet addresses. Admin sessions still require command-backed verification (`auth_verification_source=command`) plus `GPM_ADMIN_WALLET_ALLOWLIST`, so local secp256k1 binding alone cannot unlock Admin Console access.
- `GET /v1/gpm/bootstrap/manifest` (command-read auth; returns trusted manifest payload with additive telemetry fields: `trust_status`, `manifest_generated_at_utc`, `manifest_expires_at_utc`, `manifest_expires_in_sec`, `manifest_source_url`, `pinned_main_domain_host`, `signature_required_by_policy`, `https_required_by_policy`, `cache_max_age_sec`, `remote_refresh_interval_sec`; when serving cache after a periodic refresh failure, includes `remote_refresh_warning`)
- `POST /v1/gpm/session` (`action=status|refresh|revoke`; `status`/`refresh` reconcile non-admin session role against current operator decision and include additive `session_reconciled` response metadata)
- `POST /v1/gpm/onboarding/client/register` (persists a session-bound `path_profile`, trusted `bootstrap_directories` from the signed manifest, and preferred `bootstrap_directory`; used as authoritative connect policy for session-token connects)
- `POST /v1/gpm/onboarding/client/status` (returns trust-aware registration state: `registered|not_registered|degraded`, preferred `bootstrap_directory`, trusted `bootstrap_directories`, persisted `path_profile` when available, and additive `status_reason` when registration is no longer trusted or trust revalidation fails)
- `POST /v1/gpm/onboarding/server/status` (returns server-tab/lifecycle readiness derived from role, operator approval state, and strict chain-binding checks)
- `POST /v1/gpm/onboarding/overview` (consolidated onboarding contract for a `session_token`, returning `session + registration + readiness` in one response)
- `GET /v1/gpm/contribution/status` (command-read auth; accepts `session_token` query parameter or bearer session token; returns contribution eligibility for the signed-in user's own device only, including `client_tier`, `stake_satisfied`, `prepaid_balance_satisfied`, `can_use_micro_relays`, `can_enable_micro_relay`, `can_enable_micro_exit`, `contribution_lock_reason`, adaptive `contribution_profile`, and pending `current_week_reward`; Tier 1 cannot use/provide micro-relay or micro-exit, Tier 2/3 can when stake, prepaid balance, policy, explicit opt-in, and agent checks pass)
- `POST /v1/gpm/contribution/enable` (mutation auth; body `session_token` + `role=micro-relay|micro-exit`; enables beta contribution only for the signed-in user's own device and persists adaptive caps from the local GPM Agent heuristics)
- `POST /v1/gpm/contribution/disable` (mutation auth; body `session_token`; disables contribution for the signed-in user's own device without changing account tier/stake/prepaid state)
- `POST /v1/gpm/settlement/reserve-funds` (public app settlement surface; mutation auth plus wallet-bound `session_token`; reserves per-session VPN funds for the signed-in wallet only, deriving `subject_id` from the session and rejecting caller-supplied subject control; requires stake and prepaid balance flags; in production fails closed unless chain-backed settlement is configured)
- `GET /v1/gpm/rewards/current-week` (command-read auth; returns pending weekly reward summary for the current Monday 00:00 UTC -> Monday 00:00 UTC epoch)
- `GET /v1/gpm/rewards/history` (command-read auth; returns closed weekly reward history for the signed-in user's own device; payout remains `payout_allowed=false` and `settlement_finalization_state=pending_admin_chain_finalization` until Admin Console review, slashing/abuse checks, and chain settlement complete)
- `POST /v1/gpm/admin/contributions/list` (Admin Console API surface only; command-read auth plus `admin` `session_token`; lists contribution profiles and pending weekly rewards for payout/slashing review; supports optional `wallet_address`, `role=micro-relay|micro-exit`, `status=all|enabled|disabled`, and `limit`)
- `POST /v1/gpm/admin/rewards/review` (Admin Console API surface only; command-read auth plus `admin` `session_token`; reviews one wallet's contribution profile, pending current-week reward, reward history, active holds, and local settlement slash-evidence holds before payout finalization)
- `POST /v1/gpm/admin/rewards/hold` (Admin Console API surface only; mutation auth plus `admin` `session_token`; `action=hold|release` places or releases weekly reward holds before finalization)
- `POST /v1/gpm/admin/rewards/finalize` (Admin Console API surface only; mutation auth plus `admin` `session_token`; finalizes a closed weekly reward after holds and, in production, objective signed or chain-queryable traffic proof evidence checks, then submits/reconciles the settlement reward issue)
- `POST /v1/gpm/onboarding/operator/apply`
- `POST /v1/gpm/onboarding/operator/status`
- `POST /v1/gpm/onboarding/operator/list` (admin-only; supports optional `status` filter (`pending|approved|rejected`), optional `search` substring filter (`wallet_address`, `chain_operator_id`, `server_label`, `status`, `reason`), optional `limit` (default `100`, clamped `1..500`), and optional cursor pagination via `cursor="<updated_at_utc>|<wallet_address>"`; response includes additive pagination metadata `total`, `has_more`, `next_cursor`, and echoed `request` fields)
- `POST /v1/gpm/onboarding/operator/approve` (requires admin authorization: `session_token` with admin role, or legacy `admin_token` fallback when an approval admin token env is configured; strict mode `GPM_OPERATOR_APPROVAL_REQUIRE_SESSION=1` (legacy alias: `TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION=1`) disables that fallback and fails closed unless an admin `session_token` is provided; primary approval-token env is `GPM_APPROVAL_ADMIN_TOKEN` (legacy aliases: `TDPN_APPROVAL_ADMIN_TOKEN`, `GPM_OPERATOR_APPROVAL_TOKEN`, `TDPN_OPERATOR_APPROVAL_TOKEN`); request body supports optional optimistic concurrency precondition `if_updated_at_utc` (RFC3339); successful responses include additive `decision` (`approved|rejected`) and `decision_auth` (`admin_session|legacy_admin_token`) metadata; matching wallet sessions are promoted on approval and demoted on rejection)
- `GET /v1/gpm/audit/recent` (command-read auth; supports optional `limit` (default `25`, clamped `1..200`), optional `offset` (`>=0`), optional exact case-insensitive `event` filter, optional normalized `wallet_address` filter against `fields.wallet_address`, and optional `order` (`desc|asc`, default `desc`); response includes additive metadata `total`, `count`, `limit`, `offset`, `has_more`, `next_offset`, and echoed `filters`)
- `GET /v1/gpm/gaps/summary` (command-read auth; reads `GPM_GAP_SCAN_SUMMARY_JSON` (legacy alias `TDPN_GAP_SCAN_SUMMARY_JSON`, default `.easy-node-logs/gpm_gap_scan_summary.json`) and returns fail-closed status: `ok` with normalized `in_progress`/`missing_next` items plus convenience `key_gaps`/`next_actions`, or one of `artifact_missing|artifact_unreadable|artifact_malformed` when source evidence is unavailable or invalid)

Contribution policy notes:
- `micro-relay` remains available when tier, stake, prepaid, and agent-capacity gates pass.
- `micro-exit` is beta and fail-closed by default. Enable it explicitly with `GPM_MICRO_EXIT_BETA_ALLOWED=1` (legacy alias: `TDPN_MICRO_EXIT_BETA_ALLOWED=1`) only in policy-approved environments.
- Malformed `GPM_MICRO_EXIT_BETA_ALLOWED` or `TDPN_MICRO_EXIT_BETA_ALLOWED` values are treated as disabled so endpoint-exit contribution cannot open from a bad policy value. The old `GPM_MICRO_EXIT_BETA` variable is intentionally ignored and does not enable endpoint-exit contribution.

## Authentication

Mutating endpoints (`POST /v1/connect`, `POST /v1/disconnect`, `POST /v1/set_profile`, `POST /v1/update`, `POST /v1/service/start`, `POST /v1/service/stop`, `POST /v1/service/restart`) require auth by default.
GPM server lifecycle endpoints (`POST /v1/gpm/service/start`, `POST /v1/gpm/service/stop`, `POST /v1/gpm/service/restart`) also require an approved `operator` or `admin` session issued via `/v1/gpm/session`; for `operator` sessions, unlock is strict-bound and requires session/application `chain_operator_id` values to both be present and equal.

Production mutation split:
- In `GPM_PRODUCTION_MODE=1`, legacy `/v1/service/start`, `/v1/service/stop`, and `/v1/service/restart` are blocked by default even when their `LOCAL_CONTROL_API_SERVICE_*_COMMAND` hooks are configured.
- Production operators should use `/v1/gpm/service/start|stop|restart` with wallet-bound `operator`/`admin` sessions.
- `GPM_ALLOW_LEGACY_SERVICE_MUTATIONS=1` (legacy alias: `TDPN_ALLOW_LEGACY_SERVICE_MUTATIONS=1`) is a break-glass support override only; it restores legacy lifecycle mutations for emergency compatibility and `/v1/config` reports `allow_legacy_service_mutations` plus `allow_legacy_service_mutations_policy_source`.
- Invalid break-glass boolean values in production fail closed and keep legacy service mutations disabled.
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

Command-backed read endpoints follow the same auth policy. Public-app reads include `GET /v1/status` and `GET /v1/config`; Admin Console-only reads such as `GET /v1/get_diagnostics`, `GET /v1/service/status`, and `GET /v1/gpm/audit/recent` are present only when admin routes are enabled.

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
    "gpm_daemon_surface_mode": "admin_console",
    "gpm_admin_routes_enabled": true,
    "gpm_admin_routes_policy_source": "GPM_LOCAL_API_ADMIN_ROUTES",
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
    "gpm_auth_verify_require_metadata": true,
    "gpm_auth_verify_require_metadata_policy_source": "production-default",
    "gpm_auth_verify_require_wallet_extension_source": true,
    "gpm_auth_verify_require_wallet_extension_policy_source": "production-default",
    "gpm_auth_verify_require_crypto_proof": true,
    "gpm_auth_verify_require_crypto_proof_policy_source": "production-default",
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
- `gpm_daemon_surface_mode`: additive route-surface posture (`public_app` by default, `admin_console` when daemon admin routes are enabled).
- `gpm_admin_routes_enabled`: whether Admin Console-only daemon routes are registered.
- `gpm_admin_routes_policy_source`: route-gate source (`default`, `GPM_LOCAL_API_ADMIN_ROUTES`, `TDPN_LOCAL_API_ADMIN_ROUTES`, or an `*-invalid-env-fail-closed` source when malformed input kept admin routes disabled).
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
- `gpm_auth_verify_require_crypto_proof_policy_source`: additive source for strict cryptographic proof policy selection (`GPM_*`, `TDPN_*`, `production-default`, or `default`).
- `gpm_auth_verify_command_configured`: whether `GPM_AUTH_VERIFY_COMMAND` is currently configured.
- `gpm_settlement_mode`: additive settlement posture (`compatibility_memory`, `required_unconfigured`, or `chain_backed`).
- `gpm_settlement_backend` / `gpm_settlement_backend_source`: selected local settlement backend and effective source (`default`, `GPM_SETTLEMENT_BACKEND`, `GPM_SETTLEMENT_COSMOS_ENDPOINT`, or legacy aliases).
- `gpm_settlement_chain_required` / `gpm_settlement_chain_required_source`: whether production policy requires chain-backed settlement before Admin Console payout finalization.
- `gpm_settlement_chain_backed`: whether the local settlement service has an active chain adapter.
- `gpm_settlement_adapter_configured`: whether a settlement adapter was configured successfully.
- `gpm_settlement_adapter_config_error`: non-secret adapter configuration error detail; empty when the configured adapter is usable.
- `gpm_settlement_cosmos_endpoint_configured` / `gpm_settlement_cosmos_endpoint_source`: whether a Cosmos endpoint was configured and which env key supplied it; the endpoint value itself is not exposed.
- `gpm_settlement_cosmos_submit_mode`: active Cosmos adapter submit mode (`http` or `signed-tx`).
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
  "install_route": false
}
```

In non-production, set `install_route=true` only for expert/full-tunnel testing where endpoint and control-plane bypass routing has already been validated. In production mode, omitting `install_route` defaults it to `true`; explicitly sending `install_route=false` is rejected before launch so a user cannot appear connected while host traffic is outside the VPN.

Notes:
- use `https://` for non-loopback bootstrap hosts.
- loopback-only developer bootstrap may use `http://127.0.0.1:...` or `http://[::1]:...` when explicitly intended.
- `http://localhost:...` is intentionally rejected by desktop validation; use literal loopback IPs to avoid hostname/DNS ambiguity.
- bootstrap directory URLs are canonicalized before storage and trusted-manifest comparison, including lower-cased scheme/host, default-port elision, and trailing-slash normalization.
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
- In production mode these legacy endpoints return a policy error unless break-glass `GPM_ALLOW_LEGACY_SERVICE_MUTATIONS=1` is explicitly set; use `/v1/gpm/service/*` for normal Admin Console operation.

### `POST /v1/gpm/settlement/reserve-funds`
Body:

```json
{
  "session_token": "required wallet-bound client session token",
  "session_id": "required vpn usage session id",
  "reservation_id": "optional explicit reservation id",
  "amount_micros": 200000,
  "currency": "TDPNC"
}
```

Resolution and errors:
- requires mutation auth and a valid wallet-bound GPM session.
- derives `subject_id` from the session wallet address; caller-supplied subject fields are ignored/rejected by contract and never control the reservation subject.
- requires `stake_satisfied=true` and `prepaid_balance_satisfied=true` on the session before reserving VPN funds.
- Public-app reservations are pinned to the production VPN reservation amount/currency (`200000` micros, `TDPNC`); arbitrary user-supplied reservation amounts are rejected before settlement.
- `session_id` is the idempotency key. Exact replays return the existing reservation with `idempotent_replay=true`; changed subject or reservation id for the same session returns conflict.
- in production mode, reservation fails closed with `503` and `settlement_status.gpm_settlement_mode=required_unconfigured` unless the local settlement service is chain-backed.
- this is a public app settlement surface only; it does not expose admin controls or server-management actions.

Success payload:
- `ok`: `true`
- `reservation`: includes `reservation_id`, `session_id`, wallet-derived `subject_id`, `amount_micros`, `currency`, `created_at_utc`, and settlement `status`
- `idempotent_replay`: whether the request reused an existing exact reservation
- `subject_source`: `wallet_session`
- `settlement_status`: non-secret settlement adapter posture telemetry mirroring the `/v1/config` `gpm_settlement_*` fields
- `public_app_admin_controls`: always `false`

### `POST /v1/gpm/admin/rewards/finalize`
Body:

```json
{
  "session_token": "required admin session token",
  "wallet_address": "required contribution wallet",
  "week_start_utc": "required closed Monday 00:00 UTC week start"
}
```

Resolution and errors:
- requires mutation auth and an `admin` `session_token`; public app sessions and non-admin sessions are rejected.
- `week_start_utc` is required for finalization so admin payout actions cannot silently default to the current open week.
- only closed weekly reward epochs can be finalized. The current open Monday 00:00 UTC -> Monday 00:00 UTC epoch returns conflict with `only closed weekly reward epochs can be finalized`.
- missing contribution state or missing selected weekly reward returns not-found semantics.
- active reward holds block finalization with `weekly reward has active holds and cannot be finalized`; response includes `active_holds`, `active_hold_count`, and `selected_week_reward`.
- chain-bound slash evidence is merged into active holds at review/finalize read time via `slashing_hold_integration=local_settlement_slash_evidence`; these synthetic `slashing_evidence` holds are not cleared by manual hold release and must be resolved through the slashing/settlement review path.
- `traffic_proof_status` must be `trusted`; pending, missing, or untrusted proof returns conflict with `trusted traffic proof is required before weekly reward finalization`. In production, that trusted state must be backed by objective signed or chain-queryable traffic proof evidence, not just env-derived trusted status.
- zero or negative payout amounts are not finalized.
- in production mode, finalization fails closed with `503` and `settlement_status.gpm_settlement_mode=required_unconfigured` unless `gpm_settlement_chain_backed=true` (for example, via `GPM_SETTLEMENT_COSMOS_ENDPOINT`).

Success payload:
- `ok`: `true`
- `admin_api_surface`: `gpm_admin_console`
- `admin_wallet_address`: wallet bound to the admin session
- `wallet_address`, `week_start_utc`
- `selected_week_reward`: finalized reward summary
- `reward_issue`: settlement issue or idempotent replay metadata
- `reconcile_report` and `reconcile_error` when settlement reconciliation was attempted
- `settlement_status`: non-secret settlement adapter posture telemetry mirroring the `/v1/config` `gpm_settlement_*` fields
- `payout_allowed`: mirrors `selected_week_reward.payout_allowed`
- `public_app_admin_controls`: always `false`
- settlement cadence markers: `settlement_frequency=weekly`, `weekly_epoch_start_weekday=monday`, `weekly_epoch_timezone=UTC`

Finalization-state semantics:
- If the selected reward already has `reward_issue_id`, the endpoint is idempotent and returns the existing issue state with `idempotent_replay=true`.
- Confirmed chain settlement maps to `status=finalized_chain_confirmed`, `settlement_finalization_state=chain_confirmed`, and `payout_allowed=true`.
- Deferred or pending settlement submission maps to `status=finalized_pending_chain_submission`, `settlement_finalization_state=pending_chain_submission`, and `payout_allowed=false`.
- Pending chain confirmation maps to `status=finalized_pending_chain_confirmation`, `settlement_finalization_state=pending_chain_confirmation`, and `payout_allowed=false`.
- Failed settlement maps to `status=finalization_failed`, `settlement_finalization_state=chain_failed`, and `payout_allowed=false`.

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
- Admin Console operator views surface `endpoint_posture` and `endpoint_warnings` in the endpoint trust posture banner for operator-facing diagnostics; public portal release mode hides the Step-3 operator/admin lane

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
