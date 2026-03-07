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
# authority/admin node (runs directory + issuer + entry + exit)
./scripts/easy_node.sh server-up --mode authority --public-host <PUBLIC_IP_OR_DNS> --beta-profile

# authority/admin node with strict production profile (mTLS + signed admin auth)
./scripts/easy_node.sh server-up --mode authority --public-host <PUBLIC_IP_OR_DNS> --prod-profile 1

# provider node (runs directory + entry + exit, no local issuer admin)
./scripts/easy_node.sh server-up --mode provider \
  --public-host <PROVIDER_IP_OR_DNS> \
  --authority-directory http://<AUTHORITY_IP_OR_DNS>:8081 \
  --authority-issuer http://<AUTHORITY_IP_OR_DNS>:8082 \
  --beta-profile

./scripts/easy_node.sh client-test \
  --directory-urls http://<SERVER_IP>:8081 \
  --issuer-url http://<SERVER_IP>:8082 \
  --entry-url http://<SERVER_IP>:8083 \
  --exit-url http://<SERVER_IP>:8084 \
  --beta-profile 1 \
  --distinct-operators 1

./scripts/easy_node.sh three-machine-validate \
  --directory-a http://<A_SERVER_IP>:8081 \
  --directory-b http://<B_SERVER_IP>:8081 \
  --issuer-url http://<A_SERVER_IP>:8082 \
  --entry-url http://<A_SERVER_IP>:8083 \
  --exit-url http://<A_SERVER_IP>:8084 \
  --min-sources 2 \
  --min-operators 2 \
  --beta-profile 1 \
  --distinct-operators 1

./scripts/easy_node.sh three-machine-soak \
  --directory-a http://<A_SERVER_IP>:8081 \
  --directory-b http://<B_SERVER_IP>:8081 \
  --issuer-url http://<A_SERVER_IP>:8082 \
  --entry-url http://<A_SERVER_IP>:8083 \
  --exit-url http://<A_SERVER_IP>:8084 \
  --rounds 12 \
  --pause-sec 5 \
  --beta-profile 1 \
  --distinct-operators 1

./scripts/easy_node.sh discover-hosts \
  --bootstrap-directory http://<KNOWN_SERVER_IP>:8081 \
  --wait-sec 20 \
  --write-config 1

./scripts/easy_node.sh machine-c-test \
  --bootstrap-directory http://<KNOWN_SERVER_IP>:8081 \
  --discovery-wait-sec 20 \
  --beta-profile 1 \
  --distinct-operators 1

./scripts/easy_node.sh machine-a-test --public-host <A_SERVER_IP_OR_DNS>
./scripts/easy_node.sh machine-b-test --peer-directory-a http://<A_SERVER_IP_OR_DNS>:8081 --public-host <B_SERVER_IP_OR_DNS>
./scripts/easy_node.sh machine-c-test \
  --directory-a http://<A_SERVER_IP_OR_DNS>:8081 \
  --directory-b http://<B_SERVER_IP_OR_DNS>:8081 \
  --issuer-url http://<A_SERVER_IP_OR_DNS>:8082 \
  --entry-url http://<A_SERVER_IP_OR_DNS>:8083 \
  --exit-url http://<A_SERVER_IP_OR_DNS>:8084 \
  --beta-profile 1 \
  --distinct-operators 1
```

Invite-only beta option:
- add `--client-allowlist 1 --allow-anon-cred 0` to `server-up` so only explicitly onboarded client subjects can receive tokens.
- onboard subjects with `./scripts/beta_subject_upsert.sh --issuer-url <ISSUER_URL> --admin-token <TOKEN> --subject <CLIENT_ID> --kind client --tier 1`.
- batch onboarding: `./scripts/beta_subject_batch_upsert.sh --issuer-url <ISSUER_URL> --admin-token <TOKEN> --csv invited_clients.csv`.
- pass `--subject <CLIENT_ID>` to `client-test`/`machine-c-test` for invited users.
- one-command validation+soak bundle from machine C: `./scripts/beta_pilot_runbook.sh ...` (outputs `.tar.gz` report bundle under `.easy-node-logs`).

Prod strict additions:
- bootstrap certs: `./scripts/easy_node.sh bootstrap-mtls --out-dir deploy/tls --public-host <PUBLIC_IP_OR_DNS>`.
- run `server-up --prod-profile 1` to enforce fail-closed strict defaults (`PROD_STRICT_MODE=1`) on top of beta strict.
- authority invite/admin commands auto-switch to signed auth in prod profile; they also support explicit signed credentials (`--admin-key-file`, `--admin-key-id`).
- use `./scripts/easy_node.sh admin-signing-status` and `./scripts/easy_node.sh admin-signing-rotate --restart-issuer 1` for signer maintenance on authority nodes.
- use `./scripts/easy_node.sh prod-preflight --days-min 14` before external beta/production traffic cutover.

For a full 3-machine flow, see `docs/easy-3-machine-test.md`.
For a frozen closed-beta command set, see `docs/beta-playbook.md`.

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
25. If you want stronger anti-capture policy for provider advertisements, enable `DIRECTORY_PROVIDER_SPLIT_ROLES=1` so one provider operator cannot advertise both entry and exit roles simultaneously.
26. If you want server-side anti-collusion enforcement, enable `ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1` and set `ENTRY_OPERATOR_ID` (or `DIRECTORY_OPERATOR_ID`) so entry rejects same-operator entry/exit path-open attempts.
27. Set discovery flood controls (`DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE`, `DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR`) so one source operator cannot introduce unlimited discovered peers and one hinted operator cannot dominate discovery with many endpoints.
28. If you disable synthetic client fallback (`CLIENT_DISABLE_SYNTHETIC_FALLBACK=1`), validate your UDP uplink producer path with `./scripts/integration_opaque_udp_only.sh`.
29. Verify issuer key/epoch files and directory key history files persist across restart.
30. If enabling command egress backend, validate firewall rules in a disposable environment first.
31. If enabling WG kernel proxy bridges (`CLIENT_WG_KERNEL_PROXY=1`, `EXIT_WG_KERNEL_PROXY=1`), keep `EXIT_WG_LISTEN_PORT` distinct from `EXIT_DATA_ADDR`, tune `EXIT_WG_KERNEL_PROXY_MAX_SESSIONS` / `EXIT_WG_KERNEL_PROXY_IDLE_SEC` / `EXIT_SESSION_CLEANUP_SEC`, and validate packet flow in a disposable environment first.
32. For real interface validation on Linux hosts, run `sudo ./scripts/integration_real_wg_privileged.sh` and `sudo ./scripts/integration_real_wg_privileged_matrix.sh` from a disposable test machine before exposing public traffic.
33. For closed beta hardening, run `./scripts/integration_directory_beta_strict.sh` and verify strict governance environment settings are fail-closed when incomplete and healthy when complete.
34. For closed beta hardening, enable `BETA_STRICT_MODE=1` (or role-specific strict toggles) and verify all roles boot with strict settings only (`CLIENT_REQUIRE_DISTINCT_OPERATORS=1`, `ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1`, `EXIT_PEER_REBIND_SEC=0`, `EXIT_STARTUP_SYNC_TIMEOUT_SEC>0`, and other strict prerequisites). If you configure multiple directory URLs in strict mode, enforce quorum floors as well (`DIRECTORY_MIN_SOURCES>=2`, `CLIENT_DIRECTORY_MIN_OPERATORS>=2`, `ENTRY_DIRECTORY_MIN_SOURCES>=2`, `ENTRY_DIRECTORY_MIN_OPERATORS>=2`). If you configure multiple issuer URLs on exit, enforce issuer quorum floors and identity binding (`EXIT_ISSUER_MIN_SOURCES>=2`, `EXIT_ISSUER_MIN_OPERATORS>=2`, `EXIT_ISSUER_REQUIRE_ID=1`).
35. If using DNS seed discovery (`DIRECTORY_PEER_DISCOVERY_DNS_SEEDS`), verify TXT records publish only trusted peer URLs and, in strict hint mode, include signed hint fields (`operator`, `pub_key`) for admitted peers.
36. If using anonymous credentials, keep `ISSUER_ANON_CRED_EXPOSE_ID=0` (default) unless you explicitly need legacy raw-id compatibility.
37. If using anonymous credentials, run `./scripts/integration_anon_credential.sh` and verify issuer admin controls for `/v1/admin/anon-credential/issue` and `/v1/admin/anon-credential/revoke`, plus credential revocation behavior during token issuance.
38. If using anonymous credentials, run `./scripts/integration_anon_credential_dispute.sh` and verify `/v1/admin/anon-credential/dispute` / `/v1/admin/anon-credential/dispute/clear` temporarily cap and then restore token minting tier for the same credential, and verify `/v1/admin/anon-credential/get` reflects current revoke/dispute state.
39. For cross-host validation before beta rollout, run `./scripts/integration_3machine_beta_validate.sh` from a client machine (machine C) with two server directories (machines A/B) and verify both multi-source bootstrap and federation operator-floor checks pass.
40. Run `./scripts/integration_3machine_beta_soak.sh` from machine C for repeated rounds (and optional injected faults) before inviting external beta testers.
41. For stricter cross-host anti-collusion and issuer drift checks, keep `--distinct-operators=1` and `--require-issuer-quorum=1` enabled on 3-machine validate/soak runs (default under `--beta-profile=1`), and require minimum client selection diversity (`--client-min-selection-lines`, `--client-min-entry-operators`, `--client-min-exit-operators`, `--client-require-cross-operator-pair`) so the client actually exercises multi-operator paths.
42. If enforcing anti-collusion (`CLIENT_REQUIRE_DISTINCT_OPERATORS=1` and/or `ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1`), run `./scripts/integration_distinct_operators.sh` and verify same-operator paths are rejected while distinct-operator paths pass.
43. For strict runtime guardrails across roles, run `./scripts/integration_beta_strict_roles.sh` and verify client/entry/exit/issuer fail closed on weak config and entry/issuer boot when strict prerequisites are met.
44. For strict live WireGuard-mode behavior (non-privileged shim path), run `./scripts/integration_live_wg_full_path_strict.sh` and verify strict startup signals plus end-to-end plausible WireGuard packet forwarding/drop behavior.
45. Run `./scripts/integration_beta_fault_matrix.sh` to validate startup-race and sync-loss recovery paths in one pass before external beta tests.
46. Run `./scripts/integration_easy_node_role_guard.sh` to verify provider nodes are blocked from invite/admin actions while authority nodes are allowed past the role gate.
47. Run `./scripts/integration_prod_preflight_tools.sh` to verify easy-node strict prod preflight and authority signer rotate/status flows.
