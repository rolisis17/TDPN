# Global Private Mesh Web Surface (V1 Scaffold)

This folder provides the first productized web surface for **Global Private Mesh (GPM)**:

- `index.html`: public marketing homepage.
- `portal.html`: authenticated portal scaffold for wallet sign-in (including Keplr/Leap wallet-extension sign + verify), client onboarding, and operator workflow.

## Local Preview

From repo root:

```powershell
cd apps/web
python -m http.server 8088
```

Then open:

- `http://127.0.0.1:8088/index.html`
- `http://127.0.0.1:8088/portal.html`

## Homepage Visual Contract (Premium Surface)

Use this as the change contract for `index.html` (public marketing surface) so refreshes keep the same intent and quality bar.

- Scope: premium styling is intentionally scoped to `.page-home` in `assets/gpm.css`; keep portal UX operational-first and avoid leaking homepage-only polish styles into `portal.html`.
- Narrative sections: preserve the current high-level order and purpose (`Hero` -> onboarding lanes -> flow cues -> product controls/value -> governance -> release direction) so role-based onboarding context stays obvious before deeper policy details.
- Typography direction: keep the humanist/system-forward stack (`"Segoe UI Variable Text"`, `"Aptos"`, `"Segoe UI"`, `"Inter"`, sans-serif), large editorial hero headline with tight tracking, and readable long-form section copy with calmer line-height.
- Visual tokens: preserve the cool trust-focused palette and token usage (`--bg`, `--panel`, `--text`, `--muted`, `--line`, `--brand`, `--brand-strong`) plus lane differentiation (client blue family vs operator green family); new sections should use these tokens before introducing new colors.
- Motion expectations: retain staged reveal behavior (`.reveal`, `.reveal--1..5`, `gpm-reveal-up`) and subtle hover lift for cards/buttons; always keep `prefers-reduced-motion` behavior as a first-class fallback (no forced animation).
- Mobile behavior: preserve responsive intent at `900px` and `640px` breakpoints (stacked top bar, single-column content grids, full-width primary actions, tighter card radii/padding) so copy remains scannable and CTAs remain thumb-friendly.
- Portal coherence: homepage should remain the narrative front door into `portal.html` (client registration and operator review links) while sharing the same product language and trust posture cues; visual treatments can be richer on homepage, but terminology and lane semantics must stay consistent with portal workflows.

## Notes

- The portal calls the new GPM local API endpoints (`/v1/gpm/...`).
- Default API base is `http://127.0.0.1:8095` and can be changed in the portal UI.
- Portal onboarding now includes a persistent `Onboarding state` banner that surfaces `Signed out`, `Session active`, `Operator pending`, `Operator approved`, or `Operator rejected`.
- The onboarding banner includes a single `Next recommended action` hint that follows `challenge -> verify -> register -> operator apply -> await approval`.
- Server/operator lock messaging now includes a direct action path and required conditions when the lane is locked.
- Portal transport auth now uses a dedicated `Local API auth token` UI control for the `Authorization: Bearer ...` header; `session_token` remains in request bodies for GPM session workflows.
- If an endpoint returns `401` and the bearer token field is empty, portal error messaging now explicitly tells operators to set `Local API auth token` and retry.
- `Recent Audit` now includes optional query controls for `limit`, `offset`, `event`, `wallet_address`, and `order`; default values preserve legacy behavior (`limit=25`, descending order, no filters).
- Audit action output/status now includes compact pagination metadata (`returned`, `limit`, `offset`, optional `total`, `next_offset`, `has_more`) alongside returned entries.
- Session lifecycle actions now use `POST /v1/gpm/session` with `action=status|refresh|revoke`.
- Portal now includes a single-window connection console with visible `Client`/`Server` tabs; role-ineligible tabs remain visible but disabled with lock guidance.
- First-run workspace hint now calls a consistent sequence: sign in, run `Session`, then run `Status` before `Connect`, and run `Operator Status` before server lifecycle actions.
- Portal connection console includes `Connect`, `Disconnect`, and `Status` controls backed by `/v1/connect`, `/v1/disconnect`, and `/v1/status`.
- Server tab lifecycle controls (`Start`, `Stop`, `Restart`) call `POST /v1/gpm/service/start|stop|restart` with `session_token`; controls auto-disable with explicit lock hints when readiness reports `lifecycle_actions_unlocked=false` or `service_mutations_configured=false`.
- Server tab lifecycle controls now also fail closed when server readiness is unknown/unloaded (for example after session restore or status fetch failure); operators must run `Check Operator Status` or refresh session/readiness before lifecycle actions can be triggered.
- Connect payload handling is policy-aware: `session_token`/registered-session flow is preferred, and manual `bootstrap_directory`/`invite_key` are sent only when compatibility override is enabled and runtime policy allows it.
- Client onboarding status is available via `POST /v1/gpm/onboarding/client/status` (`registered|not_registered`) and is used by portal step tracking.
- Server readiness is available via `POST /v1/gpm/onboarding/server/status` and now drives portal operator/server lock guidance and onboarding step 3 state (`readiness.tab_visible`, `readiness.lifecycle_actions_unlocked`, `readiness.lock_reason`, `readiness.unlock_actions`) with heuristic fallback when unavailable; operator unlock is strict-bound and requires matching session/application `chain_operator_id`.
- Endpoint posture rendering now accepts readiness object maps (not only strings): `readiness.endpoint_posture.server_mode`, `total_urls`, `http_urls`, `https_urls`, `mixed_scheme`, and `has_remote_http` are summarized in Step-3 guidance, and `readiness.endpoint_warnings` is preserved/merged into operator diagnostics.
- Consolidated onboarding status is available via `POST /v1/gpm/onboarding/overview` and returns `session + registration + readiness` in one call; existing `client/status` and `server/status` endpoints remain supported for backward compatibility.
- Readiness/overview payloads include additive chain-binding fields: `readiness.chain_binding_status`, `readiness.chain_binding_ok`, and `readiness.chain_binding_reason` to surface bound vs pending/mismatch operator chain-binding state while preserving backend reason text and appending actionable guidance (refresh session, re-apply/re-approve if mismatch persists).
- Client-lock readiness fields are carried on the same server-status contract as `readiness.client_tab_visible` and `readiness.client_lock_reason`; portal/contract checks treat legacy `readiness.tab_visible` and `readiness.lock_reason` as compatibility aliases while client registration gating remains fail-closed.
- GPM server lifecycle actions (`POST /v1/gpm/service/start|stop|restart`) are role-gated and require an approved `operator` or `admin` session from `/v1/gpm/session`; `operator` sessions additionally require strict chain binding (`chain_operator_id` present on both session and approved application and matching).
- Operator approval (`POST /v1/gpm/onboarding/operator/approve`) now expects an admin `session_token` by default; legacy `admin_token` fallback remains supported when `GPM_APPROVAL_ADMIN_TOKEN` is configured.
- Strict operator approval policy is surfaced from runtime config (`gpm_operator_approval_require_session`, `gpm_operator_approval_require_session_policy_source`): when enabled, portal disables `admin_token` input, moderation requests require `session_token`, and legacy fallback is fail-closed.
- Operator queue listing is available via `POST /v1/gpm/onboarding/operator/list`; portal includes queue filters (`status/search/limit`) and sends optional `search` and `cursor` when provided.
- Optional production policy mode: set `GPM_PRODUCTION_MODE=1` (legacy alias: `TDPN_PRODUCTION_MODE=1`) to default `/v1/connect` to session-required policy and default auth-verify strictness (`metadata` + `wallet_extension_source` + `crypto_proof`) to required when explicit per-flag overrides are unset.
- Explicit env overrides still win over production defaults for compatibility/testing (`GPM_CONNECT_REQUIRE_SESSION`, `GPM_OPERATOR_APPROVAL_REQUIRE_SESSION`, `GPM_ALLOW_LEGACY_CONNECT_OVERRIDE`, `GPM_AUTH_VERIFY_REQUIRE_METADATA`, `GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE`, plus legacy `TDPN_*` aliases).
- Portal now fetches `GET /v1/config` on startup and displays runtime policy posture from config hints: `connect_policy_mode`, `connect_policy_source`, `gpm_auth_verify_require_metadata`, `gpm_auth_verify_require_metadata_policy_source`, `gpm_auth_verify_require_wallet_extension_source`, `gpm_auth_verify_require_wallet_extension_policy_source`, `gpm_auth_verify_require_crypto_proof`, and `gpm_auth_verify_require_crypto_proof_policy_source`.
- Portal also consumes `gpm_production_mode` telemetry from `GET /v1/config`; when missing, it falls back to connect policy mode/source hints. In production mode, compatibility override controls are hard-locked off and manual `Verify + Create Session` stays disabled with wallet-only guidance (`Sign + Verify (Wallet)`).
- Portal also reads additive `/v1/config` legacy-alias telemetry (including source/env alias keys and mapping hints when present), warns when active `TDPN_*` aliases are detected, and shows migration guidance to matching `GPM_*` env names.
- Backward compatibility is preserved: if newer posture fields are absent, portal safely falls back to legacy `connect_require_session` / `allow_legacy_connect_override` hints and compatible auth-verify defaults.
- When active auth policy requiring wallet-extension source is in effect (`wallet_extension_source`), manual `Verify + Create Session` is disabled/guarded and the portal directs users to `Sign + Verify (Wallet)`; in compatibility mode or config-unavailable fallback, manual verify remains available.
- Client registration now includes a compatibility override toggle (default OFF): manual `bootstrap_directory`/`invite_key` are disabled and not sent unless explicitly enabled; when `connect_require_session=true`, the override is forced OFF/disabled with policy guidance.
- If `/v1/config` is unavailable, portal enters a restricted fail-closed mode for mutating actions (register/connect/operator moderation/service lifecycle) and keeps read-only/session/audit actions available until runtime config is reachable again.
- If `GPM_MAIN_DOMAIN` (legacy alias: `TDPN_MAIN_DOMAIN`) is set, manifest URLs are trusted only when the host matches the pinned main-domain host, including cache fallback source URLs. This hardening is skipped when the main domain is unset for dev compatibility, and it sits alongside existing signature verification and expiry checks.
- Step 2 now includes a `Bootstrap trust status` panel driven by `GET /v1/gpm/bootstrap/manifest`, including source (`remote` or `cache`), signature verify status, and expiry timing with concise trust guidance.
- Bootstrap trust status refresh is integrated into startup/session/register flows and gracefully consumes additive telemetry fields when present (`trust_state`, `trust_reason`, warning arrays, cache age, and policy metadata) without requiring backend contract changes.
- Portal onboarding fields are persisted in browser `localStorage` and restored on reload, excluding sensitive session token material.
- Wallet sign-in support is available now for Keplr/Leap wallet-extension assisted signing in portal (`challenge -> signArbitrary -> verify`); when wallet-assisted context still matches the active `challenge_id` and `signature`, verify also sends optional signature metadata (`signature_kind`, `signature_public_key`, `signature_public_key_type`, `signature_source`, `chain_id`, `signed_message`, `signature_envelope`) and retains manual signature entry fallback for compatibility and troubleshooting. When strict crypto-proof policy is active, those proof fields are the ones the daemon validates, so wallet-assisted sign-in is the safest path.
- Optional strict auth-verify daemon policies: `GPM_AUTH_VERIFY_REQUIRE_METADATA=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_METADATA=1`) and `GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE=1`); both default `false` for compatibility and fail closed at `POST /v1/gpm/auth/verify` when policy requirements are not met.
- Optional strict crypto-proof policy: set `GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF=1`) to require cryptographic proof metadata (`signature_public_key`, `signature_public_key_type`, `signed_message`) at `POST /v1/gpm/auth/verify`; in production mode this defaults to required when unset, and the portal surfaces this next to the other auth-verify posture hints while calling out the wallet-assisted proof path when it is active.
- Portal moderation UI now includes explicit `Approve Operator` and `Reject Operator` actions with a moderation reason input.
- Rejection requires a non-empty `reason`; approval includes `reason` when provided.
- Portal operator listing now includes `List Operators` with queue filters (`status=""` default, `limit=100` default) in addition to `List Pending Operators` (`status=pending`, `limit=25`).
- Portal stores `next_cursor` from list responses and enables `Next Page` to continue listing with the same filters.
- Portal includes a `Load Next Pending` quick action that calls `POST /v1/gpm/onboarding/operator/list` with `status=pending` and `limit=1`, then prefills `wallet_address`, `chain_operator_id`, and `selected application updated at` when an item exists.
- Portal also updates `wallet_address`, `chain_operator_id`, and `selected application updated at` from operator status/list responses when available.
- Approve/reject now send `if_updated_at_utc` when `selected application updated at` is present, adding optimistic stale-decision protection.
- If approve/reject returns `409 Conflict`, portal now surfaces explicit guidance to reload pending queue (`Load Next Pending`) and retry without breaking the moderation flow.
- After approve/reject decisions, portal now forces a session status refresh to reconcile role/readiness state immediately and surfaces backend `session_reconciled` hints in output/status messaging when present.
