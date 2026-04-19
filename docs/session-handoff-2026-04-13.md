# Session Handoff (2026-04-13)

## Goal
Transfer work to a faster computer without losing context, then continue toward production-grade real-host validation and signoff.

## Project
- Repo: `trust-tiered decentralized privacy network`
- Main operational script: `scripts/easy_node.sh`
- Current focus: clear `machine_c_vpn_smoke`, then clear `three_machine_prod_signoff`.

## Machine Roles
- Machine A (authority): `100.111.133.33`
- Machine B (authority/provider counterpart depending on step): `100.113.245.61`
- Machine C (client runner): executes smoke/signoff from outside A/B.

## Current Readiness Snapshot
From local `manual-validation-status` output on 2026-04-13:
- `runtime_hygiene`: PASS
- `wg_only_stack_selftest`: PASS
- `three_machine_docker_readiness`: PASS
- `machine_c_vpn_smoke`: FAIL (latest recorded failure artifact from 2026-04-08)
- `three_machine_prod_signoff`: FAIL (latest recorded failure artifact from 2026-04-08)
- `roadmap_stage`: `READY_FOR_MACHINE_C_SMOKE`
- `next_action_check_id`: `machine_c_vpn_smoke`

Important note:
- Some local `2026-04-13` artifacts are integration/fake runs, not authoritative real-host production pass evidence.

## Key Failure Signatures Seen During This Session
1. Exit/entry bootstrap failures on client:
- `path open denied: unknown-exit`

2. Federation trust failures on directories:
- `peer key is not trusted for https://<peer>:8081`

3. Health failures during startup in strict mode:
- `local entry did not become healthy`
- `local exit did not become healthy`

4. Env mismatch/admin token pitfalls:
- Running federation status against the wrong env file (for example using provider env when server is authority)
- Resulting in `401` on admin endpoints.

## Why this happened (short)
- Production strict mode enforces tight trust/quorum behavior.
- If peer directory trust pinning and live peer metadata are not aligned, A/B can serve relays but still fail sync/trust, which then propagates into `unknown-exit` during machine-C bootstrap.

## Work Already Added in Codebase (current branch)
- New real VPN comparison runner:
  - `scripts/client_vpn_profile_compare.sh`
  - command: `client-vpn-profile-compare` wired into `scripts/easy_node.sh`
- Integration coverage added:
  - `scripts/integration_client_vpn_profile_compare.sh`
- CI/beta preflight wiring updated for new integration.
- Docs updated for the new runner.

## Files/State to Transfer to New Computer
At minimum copy:
1. Repo working tree (including current branch and uncommitted changes)
2. `./.easy-node-logs/`
3. `./deploy/tls/`
4. Manual validation state:
   - `~/.local/state/privacynode/manual_validation/`

Optional archive commands from old machine:
```bash
cd "/home/stella/myfirstproject/trust-tiered decentralized privacy network"

tar -czf /tmp/tdpn-repo-state.tgz \
  .easy-node-logs \
  deploy/tls \
  deploy/.env.easy.client \
  deploy/.env.easy.server \
  deploy/.env.easy.provider

tar -czf /tmp/tdpn-manual-validation-state.tgz \
  -C "$HOME/.local/state/privacynode" manual_validation
```

## Clean Next-Step Runbook (after migration)

### Step 1: Verify federation readiness on A and B
Run on each machine in its own repo path and with its active server env (`.env.easy.server` when running authority mode):
```bash
ADMIN_TOKEN="$(grep -m1 '^DIRECTORY_ADMIN_TOKEN=' deploy/.env.easy.server | cut -d= -f2-)"
DIRECTORY_ADMIN_TOKEN="$ADMIN_TOKEN" sudo ./scripts/easy_node.sh server-federation-status \
  --directory-url https://127.0.0.1:8081 \
  --min-peer-source-operators 2 \
  --min-issuer-source-operators 2 \
  --fail-on-not-ready 1 \
  --show-json 1
```

### Step 2: Generate fresh invite on A
```bash
sudo ./scripts/easy_node.sh invite-generate \
  --issuer-url https://127.0.0.1:8082 \
  --count 1 \
  --tier 1 \
  --wait-sec 10
```
Capture returned `inv-...` key.

### Step 3: Machine C smoke (real-host)
```bash
INVITE_KEY="inv-REPLACE_ME"

sudo ./scripts/easy_node.sh client-vpn-down --force-iface-cleanup 1 || true
sudo ./scripts/easy_node.sh client-vpn-trust-reset --all-scoped 1 --trust-scope scoped || true

sudo ./scripts/easy_node.sh client-vpn-smoke \
  --directory-urls https://100.111.133.33:8081,https://100.113.245.61:8081 \
  --issuer-url https://100.111.133.33:8082 \
  --entry-url https://100.111.133.33:8083 \
  --exit-url https://100.111.133.33:8084 \
  --subject "$INVITE_KEY" \
  --path-profile balanced \
  --interface wgvpn0 \
  --prod-profile 1 \
  --mtls-ca-file deploy/tls/ca.crt \
  --mtls-client-cert-file deploy/tls/client.crt \
  --mtls-client-key-file deploy/tls/client.key \
  --pre-real-host-readiness 1 \
  --runtime-fix 1 \
  --trust-reset-on-key-mismatch 1 \
  --trust-reset-scope scoped \
  --print-summary-json 1
```

### Step 4: If smoke passes, run signoff
```bash
sudo ./scripts/easy_node.sh three-machine-prod-signoff \
  --bundle-dir .easy-node-logs/prod_gate_bundle \
  --directory-a https://100.111.133.33:8081 \
  --directory-b https://100.113.245.61:8081 \
  --issuer-url https://100.111.133.33:8082 \
  --entry-url https://100.111.133.33:8083 \
  --exit-url https://100.111.133.33:8084 \
  --pre-real-host-readiness 1 \
  --runtime-fix 1 \
  --print-summary-json 1
```

### Step 5: Refresh readiness
```bash
./scripts/easy_node.sh manual-validation-status --show-json 1
./scripts/easy_node.sh manual-validation-report --print-report 1 --print-summary-json 1
```

## Optional One-Command Wrapper (Machine C)
There is a wrapper that can reduce command noise:
- `./scripts/easy_node.sh prod-pilot-runbook ...`

Use explicit endpoints and mTLS paths when running it. For debugging, direct smoke/signoff commands above are easier to triage.

## Triage Priority If It Fails Again
1. If smoke fails with `unknown-exit`:
- Check A/B federation status immediately.
- Confirm both directories expose both operators in `/v1/relays`.

2. If federation says `peer key is not trusted`:
- Recheck peer trust pin setup and active directory keys on A/B.
- Ensure both nodes are running with consistent strict settings and correct peer URLs.

3. If admin status returns `401`:
- Re-run using correct env file token (`.env.easy.server` in authority mode).

## Artifacts to Share for Fast Debug
When requesting help, always include:
- Smoke: `status`, `stage`, `notes`, `summary_json` path
- Signoff: `status`, `stage`, `notes`, `summary_json` path
- A/B federation output from `server-federation-status --show-json 1`
