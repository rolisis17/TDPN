# Easy Installer + 3-Machine Test

This path is for fast manual testing with minimal setup.

## Current Direction (March 17, 2026)

To keep operations simpler without losing safety:
- favor profile-first usage (`Speed`, `Balanced`, `Private`) in launcher and docs
- keep advanced flags for expert/diagnostics use, not as the primary path
- keep `Balanced` as default
- keep 2-hop as the default privacy baseline
- evaluate true 1-hop as an explicit experimental lower-privacy mode after `Speed` (2-hop) benchmarking
- in quick launcher mode, ask only essential inputs and keep advanced prompts behind an explicit customize step

Identity defaults:
- `server-up` auto-generates unique `operator_id` and `issuer_id` when not provided.
- With peer directories configured, `server-up` now fail-fast checks ID uniqueness against peers by default in beta/prod (`--peer-identity-strict auto`); temporary bypass for diagnostics: `--peer-identity-strict 0`.
- IDs are persisted per machine in `deploy/data/easy_node_identity.conf`.
- Relay IDs and signing key files are derived from those IDs, so machine A/B do not collide by default.
- Optional invite-only mode: `server-up --client-allowlist 1 --allow-anon-cred 0` plus `./scripts/beta_subject_upsert.sh` lets only allowlisted client subjects receive tokens.
- Batch invite-only onboarding: `./scripts/beta_subject_batch_upsert.sh --issuer-url <ISSUER_URL> --admin-token-file <TOKEN_FILE> --csv invited_clients.csv`.
- In invite-only mode, pass `--subject <CLIENT_ID>` to `client-test`/`machine-c-test`.

## 1) Install the easy launcher

From repo root:

```bash
./scripts/install_easy_mode.sh
```

This checks and reports dependencies:
- `docker`
- `docker compose` plugin
- `curl`
- `g++`

Then it builds:
- `bin/privacynode-easy`

## 2) Interactive mode (C++ launcher)

```bash
./bin/privacynode-easy
```

Menu options:
- dependency check
- server stack start/update
- client test against remote server(s)
- server status/logs/down
- built-in 3-machine checklist
- built-in 3-machine validation runner
- built-in closed-beta prod bundle quick profile (strict defaults, minimal prompts)
- built-in closed-beta prod bundle smoke profile (fast sanity run, not sign-off)

## 3) Non-interactive mode (script backend)

All commands below run from repo root.

### Machine A (server)

```bash
./scripts/easy_node.sh server-up \
  --public-host A_PUBLIC_IP_OR_DNS \
  --beta-profile
```

### Machine B (server + federated with A)

```bash
./scripts/easy_node.sh server-up \
  --public-host B_PUBLIC_IP_OR_DNS \
  --peer-directories https://A_PUBLIC_IP_OR_DNS:8081 \
  --beta-profile
```

Optional on Machine A to federate both ways:

```bash
./scripts/easy_node.sh server-up \
  --public-host A_PUBLIC_IP_OR_DNS \
  --peer-directories https://B_PUBLIC_IP_OR_DNS:8081 \
  --beta-profile
```

### Machine C (client)

```bash
./scripts/easy_node.sh client-test \
  --directory-urls https://A_PUBLIC_IP_OR_DNS:8081,https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --min-sources 2 \
  --distinct-operators 1 \
  --beta-profile 1
```

Path profile presets (optional, recommended for repeatable tests):

- Speed (latency-first): `--distinct-operators 1 --distinct-countries 0 --locality-soft-bias 1 --country-bias 1.80 --region-bias 1.35 --region-prefix-bias 1.15`
- Balanced (default): `--distinct-operators 1 --distinct-countries 0 --locality-soft-bias 1 --country-bias 1.50 --region-bias 1.25 --region-prefix-bias 1.10`
- Private (stronger anti-collusion): `--distinct-operators 1 --distinct-countries 1 --locality-soft-bias 0`
- Shortcut: use `--path-profile 1hop|2hop|3hop` (compatibility aliases `speed|balanced|private`, legacy aliases `fast|privacy`) on `client-test`, `three-machine-validate`, `three-machine-soak`, `pilot-runbook`, and `machine-c-test`.
- Experimental 1-hop benchmark mode (non-strict only): `--path-profile 1hop` (or `speed-1hop`) requires `--beta-profile 0 --prod-profile 0` and is available on `client-test` and `client-vpn-up`.

Real client VPN mode (for external testers on Linux):

```bash
sudo ./scripts/easy_node.sh client-vpn-preflight \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081

sudo ./scripts/easy_node.sh client-vpn-up \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
  --subject <INVITE_KEY> \
  --beta-profile 1 \
  --distinct-operators 1

./scripts/easy_node.sh client-vpn-status
sudo ./scripts/easy_node.sh client-vpn-down
# prod profile enables operator-floor checks by default (>=2 global/entry/exit operators).
# for staged or single-operator labs, you can keep checks enabled with:
#   --operator-min-operators 1 --operator-min-entry-operators 1 --operator-min-exit-operators 1
# disable only for diagnostics with: --operator-floor-check 0
# prod profile also enables issuer-quorum checks by default (>=2 distinct issuer IDs with keys).
# for single-issuer lab tests only, append: --issuer-quorum-check 0
```

If you do not have HTTPS on the bootstrap endpoint yet, keep HTTP-only runs private-network only, enable explicit insecure opt-in (`EASY_NODE_ALLOW_INSECURE_REMOTE_HTTP=1`), and do not use them on an exposed public listener.

Automated validation (recommended on machine C):

```bash
./scripts/easy_node.sh three-machine-validate \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --min-sources 2 \
  --min-operators 2 \
  --distinct-operators 1 \
  --beta-profile 1
```

This runs:
- endpoint health checks (`directory`, `issuer`, `entry`, `exit`)
- federation operator-floor check on both directories
- client path bootstrap validation with both directory sources

Role-specific automated checks (recommended before full C run):

Machine A:

```bash
./scripts/easy_node.sh machine-a-test --public-host A_PUBLIC_IP_OR_DNS
```

Machine B:

```bash
./scripts/easy_node.sh machine-b-test \
  --peer-directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --public-host B_PUBLIC_IP_OR_DNS
```

Machine C:

```bash
./scripts/easy_node.sh machine-c-test \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --beta-profile 1 \
  --distinct-operators 1
```

Each command prints (and can store) a test report file to share for debugging.

Success signal:
- output contains `client selected entry=`

Important:
- on machine C, do not use `127.0.0.1` / `localhost` for A/B URLs; use reachable IP/DNS of machine A/B.

One-bootstrap mode (you know only one server IP):

```bash
# discover server hosts from one known directory and update data/easy_mode_hosts.conf
./scripts/easy_node.sh discover-hosts \
  --bootstrap-directory https://KNOWN_SERVER_IP:8081 \
  --wait-sec 20 \
  --write-config 1

# run full machine-C validation from one bootstrap URL
./scripts/easy_node.sh machine-c-test \
  --bootstrap-directory https://KNOWN_SERVER_IP:8081 \
  --discovery-wait-sec 20 \
  --beta-profile 1 \
  --distinct-operators 1
```

Soak test from machine C (optional, recommended before closed beta):

```bash
./scripts/easy_node.sh three-machine-soak \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --rounds 12 \
  --pause-sec 5 \
  --beta-profile 1 \
  --distinct-operators 1
```

Real cross-machine production-profile WG dataplane validation from machine C (Linux root):

```bash
sudo ./scripts/easy_node.sh prod-wg-validate \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --subject client-alice \
  --strict-distinct 1 \
  --skip-control-plane-check 0 \
  --mtls-ca-file deploy/tls/ca.crt \
  --mtls-client-cert-file deploy/tls/client.crt \
  --mtls-client-key-file deploy/tls/client.key
```

Real cross-machine production-profile WG dataplane soak/fault run:

```bash
sudo ./scripts/easy_node.sh prod-wg-soak \
  --rounds 12 \
  --pause-sec 10 \
  --max-consecutive-failures 2 \
  --summary-json .easy-node-logs/prod_wg_soak_summary.json \
  --fault-every 4 \
  --fault-command "ssh user@B 'cd /repo && ./scripts/easy_node.sh server-up --mode provider --prod-profile 1 --beta-profile 1 --public-host B_PUBLIC_IP_OR_DNS'" \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --subject client-alice \
  --strict-distinct 1 \
  --skip-control-plane-check 1 \
  --mtls-ca-file deploy/tls/ca.crt \
  --mtls-client-cert-file deploy/tls/client.crt \
  --mtls-client-key-file deploy/tls/client.key
```

Strict-ingress negative rehearsal (expected strict-ingress failure class):

```bash
sudo ./scripts/easy_node.sh prod-wg-strict-ingress-rehearsal \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084
```

One-command production gate (recommended once A/B are already up):

```bash
sudo ./scripts/easy_node.sh three-machine-prod-gate \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --wg-max-consecutive-failures 2 \
  --wg-validate-summary-json .easy-node-logs/prod_gate_wg_validate_summary.json \
  --wg-soak-summary-json .easy-node-logs/prod_gate_wg_soak_summary.json \
  --gate-summary-json .easy-node-logs/prod_gate_summary.json \
  --strict-distinct 1

# same gate with automatic diagnostics bundle (.tar.gz)
sudo ./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir .easy-node-logs/prod_gate_bundle \
  --signoff-check 1 \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --strict-distinct 1
# note: bundle command runs strict machine-C preflight by default (use --preflight-check 0 only for diagnostics)
# note: bundle integrity verification is fail-close by default (use --bundle-verify-check 0 only for diagnostics)
# note: run report JSON is emitted by default at <bundle-dir>/prod_bundle_run_report.json

# strict artifact signoff check from bundle outputs
./scripts/easy_node.sh prod-gate-check \
  --run-report-json .easy-node-logs/prod_gate_bundle/prod_bundle_run_report.json

# one-command integrity + signoff policy check
./scripts/easy_node.sh prod-gate-signoff \
  --run-report-json .easy-node-logs/prod_gate_bundle/prod_bundle_run_report.json

# integrity verification for bundle artifacts (manifest + tar checksum sidecar)
./scripts/easy_node.sh prod-gate-bundle-verify \
  --bundle-dir .easy-node-logs/prod_gate_bundle

# strict one-command pilot wrapper (same flow with fail-closed defaults)
sudo ./scripts/easy_node.sh prod-pilot-runbook \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
  --subject pilot-client

# sustained pilot cohort (multi-round strict pilots + aggregate policy)
sudo ./scripts/easy_node.sh prod-pilot-cohort-runbook \
  --rounds 5 \
  --pause-sec 60 \
  --trend-min-go-rate-pct 95 \
  --max-alert-severity WARN \
  --bundle-outputs 1 \
  --bundle-fail-close 1 \
  -- \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
  --subject pilot-client

# verify cohort bundle artifacts from generated summary
./scripts/easy_node.sh prod-pilot-cohort-bundle-verify \
  --summary-json .easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary.json

# fail-closed cohort signoff (integrity + policy)
./scripts/easy_node.sh prod-pilot-cohort-signoff \
  --summary-json .easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary.json

# minimal one-command sustained pilot flow
./scripts/easy_node.sh prod-pilot-cohort-quick \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
  --subject pilot-client
# default quick run report: <reports_dir>/prod_pilot_cohort_quick_report.json

# quick run-report fail-closed verification
./scripts/easy_node.sh prod-pilot-cohort-quick-check \
  --run-report-json <reports_dir>/prod_pilot_cohort_quick_report.json

# quick-mode trend across quick run reports
./scripts/easy_node.sh prod-pilot-cohort-quick-trend \
  --reports-dir .easy-node-logs \
  --since-hours 24 \
  --summary-json .easy-node-logs/prod_pilot_quick_trend_24h.json

# quick-mode alert severity from trend metrics
./scripts/easy_node.sh prod-pilot-cohort-quick-alert \
  --trend-summary-json .easy-node-logs/prod_pilot_quick_trend_24h.json \
  --summary-json .easy-node-logs/prod_pilot_quick_alert_24h.json

# quick-mode dashboard artifact (trend + alert + markdown)
./scripts/easy_node.sh prod-pilot-cohort-quick-dashboard \
  --reports-dir .easy-node-logs \
  --dashboard-md .easy-node-logs/prod_pilot_quick_dashboard_24h.md

# one-command quick signoff gate (latest check + trend + alert severity policy)
./scripts/easy_node.sh prod-pilot-cohort-quick-signoff \
  --run-report-json <reports_dir>/prod_pilot_cohort_quick_report.json \
  --reports-dir .easy-node-logs \
  --max-alert-severity WARN

# one-command quick pilot runbook (quick execution + signoff + optional dashboard)
./scripts/easy_node.sh prod-pilot-cohort-quick-runbook \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
  --subject pilot-client \
  --max-alert-severity WARN
```

It runs this sequence:
- strict control-plane validate
- control-plane soak
- real WG validate
- real WG soak

Quick reminder checklist (any time):

```bash
./scripts/easy_node.sh three-machine-reminder
```

Single-command pilot bundle from machine C (validate + soak + snapshots):

```bash
./scripts/beta_pilot_runbook.sh \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --subject client-alice \
  --rounds 10 \
  --pause-sec 5 \
  --beta-profile 1
```

Optional client path diversity tuning on machine C:

```bash
export CLIENT_ENTRY_ROTATION_SEC=15
```

## 4) Ports to open on server machines

- TCP: `8081`, `8082`, `8083`, `8084`
- UDP: `51820`, `51821`

## 5) Useful operations

Server status:

```bash
./scripts/easy_node.sh server-status
```

Server logs:

```bash
./scripts/easy_node.sh server-logs
```

Server stop:

```bash
./scripts/easy_node.sh server-down
```
