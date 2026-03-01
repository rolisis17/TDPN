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

## 2) Easy installer + launcher (for simple testing)

Files:
- `scripts/install_easy_mode.sh`
- `scripts/easy_node.sh`
- `tools/easy_mode/easy_mode_ui.cpp`

Install launcher:

```bash
./scripts/install_easy_mode.sh
```

Run interactive menu:

```bash
./bin/privacynode-easy
```

Quick non-interactive examples:

```bash
./scripts/easy_node.sh server-up --public-host <PUBLIC_IP_OR_DNS>
./scripts/easy_node.sh client-test \
  --directory-urls http://<SERVER_IP>:8081 \
  --issuer-url http://<SERVER_IP>:8082 \
  --entry-url http://<SERVER_IP>:8083 \
  --exit-url http://<SERVER_IP>:8084

./scripts/easy_node.sh three-machine-validate \
  --directory-a http://<A_SERVER_IP>:8081 \
  --directory-b http://<B_SERVER_IP>:8081 \
  --issuer-url http://<A_SERVER_IP>:8082 \
  --entry-url http://<A_SERVER_IP>:8083 \
  --exit-url http://<A_SERVER_IP>:8084 \
  --min-sources 2 \
  --min-operators 2

./scripts/easy_node.sh machine-a-test --public-host <A_SERVER_IP_OR_DNS>
./scripts/easy_node.sh machine-b-test --peer-directory-a http://<A_SERVER_IP_OR_DNS>:8081 --public-host <B_SERVER_IP_OR_DNS>
./scripts/easy_node.sh machine-c-test \
  --directory-a http://<A_SERVER_IP_OR_DNS>:8081 \
  --directory-b http://<B_SERVER_IP_OR_DNS>:8081 \
  --issuer-url http://<A_SERVER_IP_OR_DNS>:8082 \
  --entry-url http://<A_SERVER_IP_OR_DNS>:8083 \
  --exit-url http://<A_SERVER_IP_OR_DNS>:8084
```

For a full 3-machine flow, see `docs/easy-3-machine-test.md`.

## 3) Windows 11 + WSL2

Files:
- `scripts/install_wsl2_mode.sh` (run in WSL)
- `scripts/windows/wsl2_bootstrap.ps1` (run in PowerShell)
- `scripts/windows/wsl2_run_easy.ps1` (run launcher from PowerShell)
- `scripts/windows/wsl2_bootstrap.cmd` (Windows Command Prompt wrapper)
- `scripts/windows/wsl2_run_easy.cmd` (Windows Command Prompt wrapper)
- `scripts/windows/wsl2_easy.cmd` (combined Command Prompt helper)
- `docs/windows-wsl2.md`

Quick start from PowerShell:

```powershell
./scripts/windows/wsl2_bootstrap.ps1
./scripts/windows/wsl2_run_easy.ps1
```

Or from `cmd.exe`:

```cmd
scripts\windows\wsl2_bootstrap.cmd
scripts\windows\wsl2_run_easy.cmd
```

## 4) systemd units

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

## 5) Recommended pre-production checks

Before exposing anything public:
1. Run `./scripts/beta_preflight.sh` for the default closed-beta validation bundle.
2. Run `./scripts/ci_local.sh`.
3. Run `./scripts/integration_load_chaos.sh`.
4. Run `./scripts/integration_load_chaos_matrix.sh` for broader load-pressure profiles.
5. Run `./scripts/integration_lifecycle_chaos.sh`.
6. Run `./scripts/integration_lifecycle_chaos_matrix.sh` for broader dispute/revocation churn profiles.
7. Run `./scripts/integration_directory_auto_key_rotation.sh` if you plan to enable `DIRECTORY_KEY_ROTATE_SEC`.
8. Run `./scripts/integration_sync_status_chaos.sh` and verify `/v1/admin/sync-status` auth + quorum reporting behavior for your topology.
9. Run `./scripts/integration_directory_operator_churn_scale.sh` to validate multi-operator quorum behavior under transit/seed churn.
10. Run `./scripts/integration_peer_discovery_backoff.sh` and verify `/v1/admin/peer-status` shows discovered-peer cooldown eligibility and failure metadata under peer instability.
11. Run `./scripts/integration_peer_discovery_require_hint.sh` if you enforce strict discovery hints (`DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1`) and confirm only peers with signed operator+pubkey hints are admitted.
12. Run `./scripts/integration_peer_discovery_source_cap.sh` and `./scripts/integration_peer_discovery_operator_cap.sh` if you enforce discovery flood controls (`DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE`, `DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR`).
13. If you enable live WireGuard filtering on exit (`EXIT_LIVE_WG_MODE=1`), run `./scripts/integration_exit_live_wg_mode.sh`.
14. If you enable strict live path on both sides (`CLIENT_LIVE_WG_MODE=1`, `EXIT_LIVE_WG_MODE=1`), run `./scripts/integration_live_wg_full_path.sh`.
15. Run `./scripts/integration_adjudication_quorum.sh` and verify `/v1/admin/governance-status` reflects your final adjudication policy plus suppressed-vs-published dispute counters and per-relay suppression details.
16. Run `./scripts/integration_adjudication_operator_quorum.sh` and verify operator-quorum suppression behavior for your governance settings.
17. Run `./scripts/integration_adjudication_source_quorum.sh` and verify source-class quorum suppression behavior for your governance settings.
18. If enabling live WG filtering on entry (`ENTRY_LIVE_WG_MODE=1`), run `./scripts/integration_entry_live_wg_filter.sh`.
19. Run `./scripts/integration_client_bootstrap_recovery.sh` to validate client retry/backoff recovery when client starts before local control-plane services.
20. Run `./scripts/integration_client_startup_sync.sh` to validate client startup dependency gating (timeout on unavailable issuer/directory, delayed success once control-plane readiness is online).
21. Run `./scripts/integration_exit_startup_sync.sh` to validate exit startup issuer-sync behavior (timeout on unavailable issuer, delayed success once issuer is online).
22. Run `./scripts/integration_client_startup_burst.sh` to validate parallel client bootstrap behavior under jitter/backoff settings.
23. Set adjudication policy bounds (`DIRECTORY_ADJUDICATION_META_MIN_VOTES`, `DIRECTORY_FINAL_DISPUTE_MIN_VOTES`, `DIRECTORY_FINAL_APPEAL_MIN_VOTES`, `DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS`, `DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES`, `DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO`, `DIRECTORY_DISPUTE_MAX_TTL_SEC`, `DIRECTORY_APPEAL_MAX_TTL_SEC`) to your risk tolerance before enabling federated trust sync.
24. Set provider relay admission tiers (`DIRECTORY_PROVIDER_MIN_ENTRY_TIER`, `DIRECTORY_PROVIDER_MIN_EXIT_TIER`) and optional provider concentration cap (`DIRECTORY_PROVIDER_MAX_RELAYS_PER_OPERATOR`) for your rollout stage.
25. Set discovery flood controls (`DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE`, `DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR`) so one source operator cannot introduce unlimited discovered peers and one hinted operator cannot dominate discovery with many endpoints.
26. If you disable synthetic client fallback (`CLIENT_DISABLE_SYNTHETIC_FALLBACK=1`), validate your UDP uplink producer path with `./scripts/integration_opaque_udp_only.sh`.
27. Verify issuer key/epoch files and directory key history files persist across restart.
28. If enabling command egress backend, validate firewall rules in a disposable environment first.
29. If enabling WG kernel proxy bridges (`CLIENT_WG_KERNEL_PROXY=1`, `EXIT_WG_KERNEL_PROXY=1`), keep `EXIT_WG_LISTEN_PORT` distinct from `EXIT_DATA_ADDR`, tune `EXIT_WG_KERNEL_PROXY_MAX_SESSIONS` / `EXIT_WG_KERNEL_PROXY_IDLE_SEC` / `EXIT_SESSION_CLEANUP_SEC`, and validate packet flow in a disposable environment first.
30. For real interface validation on Linux hosts, run `sudo ./scripts/integration_real_wg_privileged.sh` and `sudo ./scripts/integration_real_wg_privileged_matrix.sh` from a disposable test machine before exposing public traffic.
31. For closed beta hardening, run `./scripts/integration_directory_beta_strict.sh` and verify strict governance environment settings are fail-closed when incomplete and healthy when complete.
32. For closed beta hardening, enable `BETA_STRICT_MODE=1` (or role-specific strict toggles) and verify all roles boot with strict settings only.
33. If using DNS seed discovery (`DIRECTORY_PEER_DISCOVERY_DNS_SEEDS`), verify TXT records publish only trusted peer URLs and, in strict hint mode, include signed hint fields (`operator`, `pub_key`) for admitted peers.
34. If using anonymous credentials, run `./scripts/integration_anon_credential.sh` and verify issuer admin controls for `/v1/admin/anon-credential/issue` and `/v1/admin/anon-credential/revoke`, plus credential revocation behavior during token issuance.
35. If using anonymous credentials, run `./scripts/integration_anon_credential_dispute.sh` and verify `/v1/admin/anon-credential/dispute` / `/v1/admin/anon-credential/dispute/clear` temporarily cap and then restore token minting tier for the same credential, and verify `/v1/admin/anon-credential/get` reflects current revoke/dispute state.
36. For cross-host validation before beta rollout, run `./scripts/integration_3machine_beta_validate.sh` from a client machine (machine C) with two server directories (machines A/B) and verify both multi-source bootstrap and federation operator-floor checks pass.
