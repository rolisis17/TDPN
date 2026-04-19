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
- GPM server lifecycle actions (`POST /v1/gpm/service/start|stop|restart`) are role-gated and require an approved `operator` or `admin` session from `/v1/gpm/session`.
- Portal onboarding fields are persisted in browser `localStorage` and restored on reload; session refresh/revoke keeps stored token/role in sync.
- Wallet verification is currently challenge+signature contract wiring; production wallet extension integration is a follow-on milestone.
