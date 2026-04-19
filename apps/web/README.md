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
- Session lifecycle actions now use `POST /v1/gpm/session` with `action=status|refresh|revoke`.
- Client onboarding status is available via `POST /v1/gpm/onboarding/client/status` (`registered|not_registered`) and is used by portal step tracking.
- Server readiness is available via `POST /v1/gpm/onboarding/server/status` and now drives portal operator/server lock guidance and onboarding step 3 state (`readiness.tab_visible`, `readiness.lifecycle_actions_unlocked`, `readiness.lock_reason`, `readiness.unlock_actions`) with heuristic fallback when unavailable.
- GPM server lifecycle actions (`POST /v1/gpm/service/start|stop|restart`) are role-gated and require an approved `operator` or `admin` session from `/v1/gpm/session`.
- Optional production hardening for `/v1/connect`: set `GPM_CONNECT_REQUIRE_SESSION=1` (legacy alias: `TDPN_CONNECT_REQUIRE_SESSION=1`) to require registered `session_token` and reject manual `bootstrap_directory`/`invite_key` request overrides; legacy connect behavior remains default unless enabled.
- If `GPM_MAIN_DOMAIN` (legacy alias: `TDPN_MAIN_DOMAIN`) is set, manifest URLs are trusted only when the host matches the pinned main-domain host, including cache fallback source URLs. This hardening is skipped when the main domain is unset for dev compatibility, and it sits alongside existing signature verification and expiry checks.
- Portal onboarding fields are persisted in browser `localStorage` and restored on reload; session refresh/revoke keeps stored token/role in sync.
- Wallet verification is currently challenge+signature contract wiring; production wallet extension integration is a follow-on milestone.
