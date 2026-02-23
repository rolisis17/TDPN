# Deployment Guide (Docker + systemd)

## 1) Docker Compose (fastest way)

Files:
- `deploy/Dockerfile`
- `deploy/docker-compose.yml`

Run from repo root:

```bash
cd deploy
docker compose up -d --build directory issuer entry-exit
```

Optional demo client run:

```bash
docker compose --profile demo up client-demo
```

Smoke-test the stack (from repo root):

```bash
./scripts/integration_docker_stack.sh
```

Stop:

```bash
docker compose down
```

Data locations:
- `deploy/data/directory`
- `deploy/data/issuer`
- `deploy/data/entry-exit`

Notes:
- Change `ISSUER_ADMIN_TOKEN` before non-local use.
- `entry-exit` is one process running both roles (`--entry --exit`).

## 2) systemd units

Files:
- `deploy/systemd/privacynode-directory.service`
- `deploy/systemd/privacynode-issuer.service`
- `deploy/systemd/privacynode-entry-exit.service`
- `deploy/systemd/*.env.example`

Install steps (Linux):
1. Install binary to `/usr/local/bin/node`.
2. Create service user and dirs:
   - `sudo useradd --system --home /var/lib/privacynode --shell /usr/sbin/nologin privacynode`
   - `sudo mkdir -p /var/lib/privacynode/data /etc/privacynode`
3. Copy and edit env files:
   - `sudo cp deploy/systemd/common.env.example /etc/privacynode/common.env`
   - `sudo cp deploy/systemd/directory.env.example /etc/privacynode/directory.env`
   - `sudo cp deploy/systemd/issuer.env.example /etc/privacynode/issuer.env`
   - `sudo cp deploy/systemd/entry-exit.env.example /etc/privacynode/entry-exit.env`
4. Copy unit files:
   - `sudo cp deploy/systemd/privacynode-*.service /etc/systemd/system/`
5. Reload and start:
   - `sudo systemctl daemon-reload`
   - `sudo systemctl enable --now privacynode-directory.service`
   - `sudo systemctl enable --now privacynode-issuer.service`
   - `sudo systemctl enable --now privacynode-entry-exit.service`
6. Verify:
   - `systemctl status privacynode-directory.service`
   - `systemctl status privacynode-issuer.service`
   - `systemctl status privacynode-entry-exit.service`

## 3) Recommended pre-production checks

Before exposing anything public:
1. Run `./scripts/ci_local.sh`.
2. Run `./scripts/integration_load_chaos.sh`.
3. Run `./scripts/integration_lifecycle_chaos.sh`.
4. Run `./scripts/integration_directory_auto_key_rotation.sh` if you plan to enable `DIRECTORY_KEY_ROTATE_SEC`.
5. Run `./scripts/integration_sync_status_chaos.sh` and verify `/v1/admin/sync-status` auth + quorum reporting behavior for your topology.
6. Run `./scripts/integration_peer_discovery_backoff.sh` and verify `/v1/admin/peer-status` shows discovered-peer cooldown eligibility and failure metadata under peer instability.
7. Run `./scripts/integration_peer_discovery_require_hint.sh` if you enforce strict discovery hints (`DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1`) and confirm only peers with signed operator+pubkey hints are admitted.
8. Run `./scripts/integration_adjudication_quorum.sh` and verify `/v1/admin/governance-status` reflects your final adjudication policy plus suppressed-vs-published dispute counters and per-relay suppression details.
9. Run `./scripts/integration_adjudication_operator_quorum.sh` and verify operator-quorum suppression behavior for your governance settings.
10. If enabling live WG filtering on entry (`ENTRY_LIVE_WG_MODE=1`), run `./scripts/integration_entry_live_wg_filter.sh`.
11. Set adjudication policy bounds (`DIRECTORY_ADJUDICATION_META_MIN_VOTES`, `DIRECTORY_FINAL_DISPUTE_MIN_VOTES`, `DIRECTORY_FINAL_APPEAL_MIN_VOTES`, `DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS`, `DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO`, `DIRECTORY_DISPUTE_MAX_TTL_SEC`, `DIRECTORY_APPEAL_MAX_TTL_SEC`) to your risk tolerance before enabling federated trust sync.
12. If you disable synthetic client fallback (`CLIENT_DISABLE_SYNTHETIC_FALLBACK=1`), validate your UDP uplink producer path with `./scripts/integration_opaque_udp_only.sh`.
13. Verify issuer key/epoch files and directory key history files persist across restart.
14. If enabling command egress backend, validate firewall rules in a disposable environment first.
