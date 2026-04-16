# TDPN Desktop App Track (Tauri Scaffold)

This folder contains a practical scaffold for the Windows-native desktop track.
It is intentionally lightweight and not production-ready yet.

What this scaffold includes:
- Tauri app shell (`src-tauri`)
- minimal desktop UI (`src`)
- local daemon API bridge commands:
  - `control_connect`
  - `control_disconnect`
  - `control_status`
  - `control_get_diagnostics`
  - `control_set_profile`
  - `control_update`
  - `control_health`
  - `control_config`

What this scaffold does not include yet:
- installer/signing/update channels
- Windows service lifecycle management
- hardened auth/session model for local API
- telemetry, crash reporting, and production observability

## Local daemon expectation

Run the daemon with local API enabled:

```bash
go run ./cmd/node --local-api
```

Defaults expected by this app:
- local API base URL: `http://127.0.0.1:8095`
- local API timeout: `20s`

Desktop env overrides:
- `TDPN_LOCAL_API_BASE_URL`
- `TDPN_LOCAL_API_TIMEOUT_SEC`

## Development (once toolchains are installed)

Prerequisites:
- Node.js + npm
- Rust toolchain + Cargo
- Tauri prerequisites for your OS

Run:

```bash
cd apps/desktop
npm install
npm run tauri dev
```

References:
- `docs/local-control-api.md`
- `docs/full-execution-plan-2026-2027.md`
