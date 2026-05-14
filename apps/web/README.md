# Global Private Mesh Access Recovery Web Surface (V1 Scaffold)

This folder provides the first productized public web surface for **Global Private Mesh (GPM)**, now led by the Access Recovery beta:

- `index.html`: public Access Recovery homepage focused on trusted keys, signed recovery packs/invites, browser-local verification, helper bridge paths, and operator evidence.
- `portal.html`: authenticated public client workspace scaffold for wallet sign-in (including Keplr/Leap wallet-extension sign + verify), onboarding, client connection controls, contribution/reward status, and diagnostics. Public release builds do not ship admin, audit, operator moderation, server lifecycle, slashing, settlement, or payout controls; those workflows belong in the separate GPM Admin Console.
- `recovery.html`: local signed access-pack and bridge-invite verifier for the Access Recovery beta path. It can build/import/export a local trusted-organization key store, import single trusted-key handoffs, import/export and summarize a helper registry for active/quarantine checks plus signed abuse-report/rate-limit commitments, verify a signed helper-registry artifact before extracting the raw registry while preserving its organization binding, exchange `GPMREC1` text handoffs including trusted keys and signed helper registries, render/download QR handoffs locally, scan QR images with native QR detection or bundled fallback scanning, then verifies signature, expiry, organization id, trusted-key match, helper status, and helper abuse/rate metadata before listing recovery/helper paths.

## Product Lanes

- Access Recovery: primary beta surface. Signed maps, trusted keys, browser-local verification, helper bridge evidence, and trusted handoff receipts.
- Client Portal: supporting runtime workspace. Wallet, device, connection, and contribution controls are infrastructure reuse, not the product wedge.
- Admin Console: separate operator/governance surface, not shipped in this public web folder.

## Portal Messaging Contract

- `portal.html` must present itself as the client workspace, not as the public beta starting point.
- The first viewport should point users back to `recovery.html` for Access Recovery beta handoffs, signed packs, bridge invites, and browser-local verification.
- Wallet, device registration, connection, contribution, and reward controls are supporting runtime surfaces; avoid hero copy such as `Start here`, `Connect your wallet`, or `Wallet. Device. Connect.` that makes the portal look like the primary product wedge.

## Local Preview

From repo root:

```powershell
cd apps/web
python -m http.server 8088
```

Then open:

- `http://127.0.0.1:8088/index.html`
- `http://127.0.0.1:8088/portal.html`
- `http://127.0.0.1:8088/recovery.html`

When `portal.html` is served from `8088` and the Local API stays on its default `8095`, the browser origin is cross-port. Loopback cross-port requests require the `Local API auth token`; serving the portal from the same Local API origin is the only unauthenticated loopback preview path.

## Homepage Visual Contract (Access Recovery Surface)

Use this as the change contract for `index.html` (public marketing surface) so refreshes keep the same intent and quality bar.

- Scope: premium styling is intentionally scoped to `.page-home` in `assets/gpm.css`; keep portal UX operational-first and avoid leaking homepage-only polish styles into `portal.html`.
- Narrative sections: preserve the current high-level order and purpose (`Hero` -> recovery rationale -> beta mental map -> helper bridge paths -> operator evidence -> recovery posture -> recovery CTA) so the first screen stays about trusted access recovery, not generic network access.
- Beta mental map: keep the public explanation concrete and ordered: trusted key -> signed recovery pack/invite -> browser-local verification -> helper bridge paths -> real helper HTTPS evidence -> trusted verifier receipt -> operator handoff.
- Trusted-key posture: frame helpers as discovery or bridge participants, never authorities. The signed organization key, expiry, organization binding, and trusted-key match decide whether material is usable.
- Helper bridge paths: explain direct recovery packs, helper invites, registry status, quarantine/disabled markers, abuse-report commitments, and rate-limit commitments without exposing privileged moderation or operator actions.
- Operator evidence: describe evidence as narrow verification facts suitable for later review. Do not imply the public homepage is an admin console or that it records unrelated user activity.
- Typography direction: keep the humanist/system-forward stack (`"Segoe UI Variable Text"`, `"Aptos"`, `"Segoe UI"`, `"Inter"`, sans-serif), large editorial hero headline with tight tracking, and readable long-form section copy with calmer line-height.
- Visual tokens: preserve the cool trust-focused palette and token usage (`--bg`, `--panel`, `--text`, `--muted`, `--line`, `--brand`, `--brand-strong`) plus recovery/evidence differentiation; new sections should use these tokens before introducing new colors.
- Motion expectations: retain staged reveal behavior (`.reveal`, `.reveal--1..5`, `gpm-reveal-up`) and subtle hover lift for cards/buttons; always keep `prefers-reduced-motion` behavior as a first-class fallback (no forced animation).
- Mobile behavior: preserve responsive intent at `900px` and `640px` breakpoints (stacked top bar, single-column content grids, full-width primary actions, tighter card radii/padding) so copy remains scannable and CTAs remain thumb-friendly.
- Portal coherence: homepage should primarily drive to `recovery.html` for Access Recovery while keeping `portal.html` available as the authenticated client workspace. Operator/admin governance remains in the separate GPM Admin Console; visual treatments can be richer on homepage, but terminology and lane semantics must stay consistent with the public/admin split.

## Notes

- The portal calls public GPM local API endpoints (`/v1/gpm/...`) for wallet auth, client onboarding, bootstrap trust, contribution, and rewards.
- Default API base is `http://127.0.0.1:8095` and can be changed in the portal UI.
- The public portal exposes only the client workspace. Admin/operator governance, audit review, moderation queues, and server-management actions belong to the separate GPM Admin Console and are not shipped in `apps/web` release files.
- Portal onboarding includes a persistent `Onboarding state` banner and a single `Next recommended action` hint that follows `challenge -> verify -> register -> connect`.
- Portal transport auth uses a dedicated `Local API auth token` UI control for the `Authorization: Bearer ...` header; `session_token` remains in request bodies for GPM session workflows.
- If an endpoint returns `401` and the bearer token field is empty, portal error messaging explicitly tells users to set `Local API auth token` and retry.
- Session lifecycle actions use `POST /v1/gpm/session` with `action=status|refresh|revoke`.
- The connection console includes public `Connect`, `Disconnect`, and `Status` controls backed by `/v1/connect`, `/v1/disconnect`, and `/v1/status`.
- First-run workspace guidance calls a consistent sequence: sign in, run `Session`, then run `Status` before `Connect`.
- Connect payload handling is policy-aware: `session_token`/registered-session flow is preferred, and manual `bootstrap_directory`/`invite_key` are sent only when compatibility override is enabled and runtime policy allows it.
- The install/default-route connect control is an unchecked expert full-tunnel option in non-production. In production mode or when the PROD profile is selected, the portal forces `install_route=true` so users cannot appear connected while host traffic remains outside GPM; non-production manual route installs still require the explicit confirmation dialog.
- Public contribution/reward parity is available in `portal.html`: signed-in users can run contribution status, enable/disable their own `micro-relay` or `micro-exit` contribution role, view current-week reward status, and view closed weekly reward history.
- Public contribution and reward requests use only the current `session_token` in POST bodies (`/v1/gpm/contribution/status`, `/v1/gpm/contribution/enable`, `/v1/gpm/contribution/disable`, `/v1/gpm/rewards/current-week`, `/v1/gpm/rewards/history`); `role` is sent only for enable, and the portal does not send wallet filters or privileged review fields.
- Public contribution/reward UI does not expose admin contribution listing, reward review, reward hold/release, payout, slashing, settlement finalization, or privileged operator routes; finalization remains represented only as read-only `settlement_finalization_state`/`payout_allowed` status from the signed-in user's reward summaries.
- Client onboarding status is available via `POST /v1/gpm/onboarding/client/status` (`registered|not_registered`) and is used by portal step tracking.
- Consolidated onboarding status is available via `POST /v1/gpm/onboarding/overview` and returns `session + registration + readiness + beta_guidance` in one call. The public portal consumes client-facing readiness plus backend-authored `beta_guidance.next_action` when present, with local fallback hints for older daemons.
- Client-lock readiness fields can arrive as `readiness.client_tab_visible` and `readiness.client_lock_reason`; the public portal consumes only those client-facing readiness hints while client registration gating remains fail-closed.
- Backend readiness payloads may include server endpoint posture fields such as `readiness.endpoint_posture.server_mode`, `total_urls`, `http_urls`, `https_urls`, `mixed_scheme`, and `has_remote_http`; the public portal does not render that server-management posture in release mode.
- Optional production policy mode: set `GPM_PRODUCTION_MODE=1` (legacy alias: `TDPN_PRODUCTION_MODE=1`) to enforce `/v1/connect` session-required policy, hard-lock manual bootstrap/invite compatibility controls off, require trusted manifest bootstrap evidence for legacy compatibility paths, require HTTPS/signed bootstrap manifests, and default auth-verify strictness (`metadata` + `wallet_extension_source` + `crypto_proof`) to required when explicit per-flag overrides are unset.
- Explicit env overrides still win only for production-default gates where the backend allows compatibility/testing overrides (`GPM_AUTH_VERIFY_REQUIRE_METADATA`, `GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE`, `GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF`, plus legacy `TDPN_*` aliases). `GPM_CONNECT_REQUIRE_SESSION=0` and `GPM_ALLOW_LEGACY_CONNECT_OVERRIDE=1` do not relax production-enforced connect hardening.
- Portal fetches `GET /v1/config` on startup and displays runtime policy posture from config hints: `connect_policy_mode`, `connect_policy_source`, `gpm_auth_verify_require_metadata`, `gpm_auth_verify_require_metadata_policy_source`, `gpm_auth_verify_require_wallet_extension_source`, `gpm_auth_verify_require_wallet_extension_policy_source`, `gpm_auth_verify_require_crypto_proof`, and `gpm_auth_verify_require_crypto_proof_policy_source`.
- Portal consumes `gpm_production_mode` telemetry from `GET /v1/config`; when missing, it falls back to connect policy mode/source hints. In production mode, compatibility override controls are hard-locked off and manual `Verify + Create Session` stays disabled with wallet-only guidance (`Connect Wallet`).
- Portal reads additive `/v1/config` legacy-alias telemetry (including source/env alias keys and mapping hints when present), warns when active `TDPN_*` aliases are detected, and shows migration guidance to matching `GPM_*` env names.
- Backward compatibility is preserved: if newer posture fields are absent, portal safely falls back to legacy `connect_require_session` / `allow_legacy_connect_override` hints and compatible auth-verify defaults.
- When active auth policy requiring wallet-extension source is in effect (`wallet_extension_source`), manual `Verify + Create Session` is disabled/guarded and the portal directs users to `Connect Wallet`; in compatibility mode or config-unavailable fallback, manual verify remains available.
- Client registration includes a compatibility override toggle (default OFF): manual `bootstrap_directory`/`invite_key` are disabled and not sent unless explicitly enabled; when `connect_require_session=true`, the override is forced OFF/disabled with policy guidance.
- If `/v1/config` is unavailable, portal enters a restricted fail-closed mode for mutating actions such as register/connect and keeps allowed read-only/session actions available until runtime config is reachable again.
- If `GPM_MAIN_DOMAIN` (legacy alias: `TDPN_MAIN_DOMAIN`) is set, manifest URLs are trusted only when the host matches the pinned main-domain host, including cache fallback source URLs.
- Step 2 includes a `Bootstrap trust status` panel driven by `GET /v1/gpm/bootstrap/manifest`, including source (`remote` or `cache`), signature verify status, and expiry timing with concise trust guidance.
- Bootstrap trust status refresh is integrated into startup/session/register flows and gracefully consumes additive telemetry fields when present (`trust_state`, `trust_reason`, warning arrays, cache age, and policy metadata) without requiring backend contract changes.
- Portal onboarding fields are persisted in browser `localStorage` and restored on reload, excluding sensitive session token material.
- Wallet sign-in support is wired for Keplr/Leap wallet-extension assisted signing in the local/beta portal (`Connect Wallet` runs `challenge -> signArbitrary -> verify`); when wallet-assisted context still matches the active `challenge_id` and `signature`, verify also sends optional signature metadata (`signature_kind`, `signature_public_key`, `signature_public_key_type`, `signature_source`, `chain_id`, `signed_message`, `signature_envelope`) and retains manual signature entry fallback under Advanced troubleshooting for compatibility and support.
- Optional strict auth-verify daemon policies: `GPM_AUTH_VERIFY_REQUIRE_METADATA=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_METADATA=1`) and `GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE=1`); both default `false` for compatibility and fail closed at `POST /v1/gpm/auth/verify` when policy requirements are not met.
- Optional strict crypto-proof policy: set `GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF=1` (legacy alias: `TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF=1`) to require cryptographic proof metadata (`signature_public_key`, `signature_public_key_type`, `signed_message`) at `POST /v1/gpm/auth/verify`; in production mode this defaults to required when unset, and the portal surfaces this next to the other auth-verify posture hints while calling out the wallet-assisted proof path when it is active.
- `wallet_binding_verified` is true only when the verifier returns a command-backed or metadata-backed wallet binding that matches the session; local proof-only or metadata-blind custom-verifier sessions remain false and do not unlock entitlement/role surfaces.
