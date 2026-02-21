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
4. Verify issuer key/epoch files persist across restart.
5. If enabling command egress backend, validate firewall rules in a disposable environment first.
