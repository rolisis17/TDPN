# Easy Installer + 3-Machine Test

This path is for fast manual testing with minimal setup.

Identity defaults:
- `server-up` auto-generates unique `operator_id` and `issuer_id` when not provided.
- With peer directories configured, `server-up` now fail-fast checks ID uniqueness against peers by default in beta/prod (`--peer-identity-strict auto`); temporary bypass for diagnostics: `--peer-identity-strict 0`.
- IDs are persisted per machine in `deploy/data/easy_node_identity.conf`.
- Relay IDs and signing key files are derived from those IDs, so machine A/B do not collide by default.
- Optional invite-only mode: `server-up --client-allowlist 1 --allow-anon-cred 0` plus `./scripts/beta_subject_upsert.sh` lets only allowlisted client subjects receive tokens.
- Batch invite-only onboarding: `./scripts/beta_subject_batch_upsert.sh --issuer-url <ISSUER_URL> --admin-token <TOKEN> --csv invited_clients.csv`.
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
  --peer-directories http://A_PUBLIC_IP_OR_DNS:8081 \
  --beta-profile
```

Optional on Machine A to federate both ways:

```bash
./scripts/easy_node.sh server-up \
  --public-host A_PUBLIC_IP_OR_DNS \
  --peer-directories http://B_PUBLIC_IP_OR_DNS:8081 \
  --beta-profile
```

### Machine C (client)

```bash
./scripts/easy_node.sh client-test \
  --directory-urls http://A_PUBLIC_IP_OR_DNS:8081,http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084 \
  --min-sources 2 \
  --distinct-operators 1 \
  --beta-profile 1
```

Real client VPN mode (for external testers on Linux):

```bash
sudo ./scripts/easy_node.sh client-vpn-preflight \
  --bootstrap-directory http://A_PUBLIC_IP_OR_DNS:8081

sudo ./scripts/easy_node.sh client-vpn-up \
  --bootstrap-directory http://A_PUBLIC_IP_OR_DNS:8081 \
  --subject <INVITE_KEY> \
  --beta-profile 1 \
  --distinct-operators 1

./scripts/easy_node.sh client-vpn-status
sudo ./scripts/easy_node.sh client-vpn-down
# prod profile enables operator-floor checks by default (>=2 entry and >=2 exit operators).
# for single-operator lab tests only, append: --operator-floor-check 0
# prod profile also enables issuer-quorum checks by default (>=2 distinct issuer IDs with keys).
# for single-issuer lab tests only, append: --issuer-quorum-check 0
```

Automated validation (recommended on machine C):

```bash
./scripts/easy_node.sh three-machine-validate \
  --directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084 \
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
  --peer-directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --public-host B_PUBLIC_IP_OR_DNS
```

Machine C:

```bash
./scripts/easy_node.sh machine-c-test \
  --directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084 \
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
  --bootstrap-directory http://KNOWN_SERVER_IP:8081 \
  --wait-sec 20 \
  --write-config 1

# run full machine-C validation from one bootstrap URL
./scripts/easy_node.sh machine-c-test \
  --bootstrap-directory http://KNOWN_SERVER_IP:8081 \
  --discovery-wait-sec 20 \
  --beta-profile 1 \
  --distinct-operators 1
```

Soak test from machine C (optional, recommended before closed beta):

```bash
./scripts/easy_node.sh three-machine-soak \
  --directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084 \
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

One-command production gate (recommended once A/B are already up):

```bash
sudo ./scripts/easy_node.sh three-machine-prod-gate \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --wg-max-consecutive-failures 2 \
  --wg-soak-summary-json .easy-node-logs/prod_gate_wg_soak_summary.json \
  --gate-summary-json .easy-node-logs/prod_gate_summary.json \
  --strict-distinct 1

# same gate with automatic diagnostics bundle (.tar.gz)
sudo ./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir .easy-node-logs/prod_gate_bundle \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --strict-distinct 1
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
  --directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084 \
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
