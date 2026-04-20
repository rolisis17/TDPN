# Global Private Mesh Web Surface (V1 Scaffold)

This folder provides the first productized web surface for **Global Private Mesh (GPM)**:

- `index.html`: public marketing homepage.
- `portal.html`: authenticated portal scaffold for wallet sign-in, client onboarding, and operator workflow.

## Local Preview

From repo root:

```powershell
cd apps/web
python -m http.server 8088
```

Then open:

- `http://127.0.0.1:8088/index.html`
- `http://127.0.0.1:8088/portal.html`

## Notes

- The portal calls the new GPM local API endpoints (`/v1/gpm/...`).
- Default API base is `http://127.0.0.1:8095` and can be changed in the portal UI.
- `Recent Audit` now includes optional query controls for `limit`, `offset`, `event`, `wallet_address`, and `order`; default values preserve legacy behavior (`limit=25`, descending order, no filters).
- Audit action output/status now includes compact pagination metadata (`returned`, `limit`, `offset`, optional `total`, `next_offset`, `has_more`) alongside returned entries.
- Session lifecycle actions now use `POST /v1/gpm/session` with `action=status|refresh|revoke`.
- Client onboarding status is available via `POST /v1/gpm/onboarding/client/status` (`registered|not_registered`) and is used by portal step tracking.
- Server readiness is available via `POST /v1/gpm/onboarding/server/status` and now drives portal operator/server lock guidance and onboarding step 3 state (`readiness.tab_visible`, `readiness.lifecycle_actions_unlocked`, `readiness.lock_reason`, `readiness.unlock_actions`) with heuristic fallback when unavailable; operator unlock is strict-bound and requires matching session/application `chain_operator_id`.
- Consolidated onboarding status is available via `POST /v1/gpm/onboarding/overview` and returns `session + registration + readiness` in one call; existing `client/status` and `server/status` endpoints remain supported for backward compatibility.
- Readiness/overview payloads include additive chain-binding fields: `readiness.chain_binding_status`, `readiness.chain_binding_ok`, and `readiness.chain_binding_reason` to surface bound vs pending/mismatch operator chain-binding state while preserving backend reason text and appending actionable guidance (refresh session, re-apply/re-approve if mismatch persists).
- Client-lock readiness fields are carried on the same server-status contract as `readiness.client_tab_visible` and `readiness.client_lock_reason`; portal/contract checks treat legacy `readiness.tab_visible` and `readiness.lock_reason` as compatibility aliases while client registration gating remains fail-closed.
- GPM server lifecycle actions (`POST /v1/gpm/service/start|stop|restart`) are role-gated and require an approved `operator` or `admin` session from `/v1/gpm/session`; `operator` sessions additionally require strict chain binding (`chain_operator_id` present on both session and approved application and matching).
- Operator approval (`POST /v1/gpm/onboarding/operator/approve`) now expects an admin `session_token` by default; legacy `admin_token` fallback remains supported when `GPM_APPROVAL_ADMIN_TOKEN` is configured.
- Operator queue listing is available via `POST /v1/gpm/onboarding/operator/list`; portal includes queue filters (`status/search/limit`) and sends optional `search` and `cursor` when provided.
- Optional production hardening for `/v1/connect`: set `GPM_CONNECT_REQUIRE_SESSION=1` (legacy alias: `TDPN_CONNECT_REQUIRE_SESSION=1`) to require registered `session_token` and reject manual `bootstrap_directory`/`invite_key` request overrides; legacy connect behavior remains default unless enabled.
- Portal now fetches `GET /v1/config` on startup and reads `config.connect_require_session` to lock compatibility behavior when required by policy.
- `GET /v1/config` auth-verify policy hints include `gpm_auth_verify_require_command`, `gpm_auth_verify_require_metadata`, and `gpm_auth_verify_require_wallet_extension_source` for runtime visibility in desktop/portal support flows.
- Client registration now includes a compatibility override toggle (default OFF): manual `bootstrap_directory`/`invite_key` are disabled and not sent unless explicitly enabled; when `connect_require_session=true`, the override is forced OFF/disabled with policy guidance.
- If `/v1/config` is unavailable, portal continues without hard failure and keeps compatibility override behavior available.
- If `GPM_MAIN_DOMAIN` (legacy alias: `TDPN_MAIN_DOMAIN`) is set, manifest URLs are trusted only when the host matches the pinned main-domain host, including cache fallback source URLs. This hardening is skipped when the main domain is unset for dev compatibility, and it sits alongside existing signature verification and expiry checks.
- Portal onboarding fields are persisted in browser `localStorage` and restored on reload, excluding sensitive session token material.
- Wallet sign-in supports wallet-extension assisted signing for Keplr/Leap in portal (`challenge -> signArbitrary -> verify`); when wallet-assisted context still matches the active `challenge_id` and `signature`, verify also sends optional signature metadata (`signature_kind`, `signature_public_key`, `signature_public_key_type`, `signature_source`, `chain_id`, `signed_message`, `signature_envelope`) and retains manual signature entry fallback for compatibility and troubleshooting.
- Optional strict auth-verify daemon policies: `GPM_AUTH_VERIFY_REQUIRE_METADATA=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_METADATA=1`) and `GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE=1`); both default `false` for compatibility and fail closed at `POST /v1/gpm/auth/verify` when policy requirements are not met.
- Portal moderation UI now includes explicit `Approve Operator` and `Reject Operator` actions with a moderation reason input.
- Rejection requires a non-empty `reason`; approval includes `reason` when provided.
- Portal operator listing now includes `List Operators` with queue filters (`status=""` default, `limit=100` default) in addition to `List Pending Operators` (`status=pending`, `limit=25`).
- Portal stores `next_cursor` from list responses and enables `Next Page` to continue listing with the same filters.
- Portal includes a `Load Next Pending` quick action that calls `POST /v1/gpm/onboarding/operator/list` with `status=pending` and `limit=1`, then prefills `wallet_address`, `chain_operator_id`, and `selected application updated at` when an item exists.
- Portal also updates `wallet_address`, `chain_operator_id`, and `selected application updated at` from operator status/list responses when available.
- Approve/reject now send `if_updated_at_utc` when `selected application updated at` is present, adding optimistic stale-decision protection.
- If approve/reject returns `409 Conflict`, portal now surfaces explicit guidance to reload pending queue (`Load Next Pending`) and retry without breaking the moderation flow.
- After approve/reject decisions, portal now forces a session status refresh to reconcile role/readiness state immediately and surfaces backend `session_reconciled` hints in output/status messaging when present.
