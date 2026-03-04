# Closed Beta Playbook

This freezes a practical beta profile that is strict enough for operator separation and federation checks, while staying compatible with the current docker easy-mode flow.

## Scope

- Two server machines:
  - machine A: `directory + issuer + entry + exit`
  - machine B: `directory + issuer + entry + exit`
- One client machine:
  - machine C: validation runner only
- Distinct operator IDs:
  - machine A: `op-a`
  - machine B: `op-b`
- Distinct relay IDs are auto-derived from operator IDs by `easy_node.sh`.

## 1) Machine A

```bash
./scripts/easy_node.sh server-up \
  --public-host A_PUBLIC_IP_OR_DNS \
  --operator-id op-a \
  --peer-directories http://B_PUBLIC_IP_OR_DNS:8081 \
  --client-allowlist 1 \
  --allow-anon-cred 0 \
  --beta-profile 1
```

## 2) Machine B

```bash
./scripts/easy_node.sh server-up \
  --public-host B_PUBLIC_IP_OR_DNS \
  --operator-id op-b \
  --peer-directories http://A_PUBLIC_IP_OR_DNS:8081 \
  --client-allowlist 1 \
  --allow-anon-cred 0 \
  --beta-profile 1
```

## 2.1) Invite-only client onboarding (allowlist)

Run on machine A and machine B issuers:

```bash
./scripts/beta_subject_upsert.sh \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --admin-token "<ISSUER_ADMIN_TOKEN_FROM_SERVER_UP>" \
  --subject client-alice \
  --kind client \
  --tier 1

./scripts/beta_subject_upsert.sh \
  --issuer-url http://B_PUBLIC_IP_OR_DNS:8082 \
  --admin-token "<ISSUER_ADMIN_TOKEN_FROM_SERVER_UP>" \
  --subject client-alice \
  --kind client \
  --tier 1
```

Client-side:

```bash
export CLIENT_SUBJECT=client-alice
```

With `--client-allowlist 1`, unknown or empty subjects are denied token issuance.

Batch onboarding option (CSV):

```bash
cat > invited_clients.csv <<'EOF'
subject,kind,tier,reputation,bond,stake
client-alice,client,1,0,0,0
client-bob,client,1,0,0,0
EOF

./scripts/beta_subject_batch_upsert.sh \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --admin-token "<ISSUER_ADMIN_TOKEN_FROM_SERVER_UP>" \
  --csv invited_clients.csv
```

## 3) Quick role checks

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

## 4) Machine C full validation

```bash
./scripts/easy_node.sh machine-c-test \
  --directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084 \
  --subject client-alice \
  --min-sources 2 \
  --min-operators 2 \
  --beta-profile 1 \
  --distinct-operators 1
```

Expected signal:
- machine C report includes `3-machine beta validation check ok`
- client logs include repeated `client selected entry=... exit=...`

## 5) Soak run (machine C)

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

Optional fault injection:

```bash
./scripts/easy_node.sh three-machine-soak \
  --directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084 \
  --rounds 10 \
  --fault-every 3 \
  --fault-command "ssh user@B_PUBLIC_IP_OR_DNS 'cd /path/to/repo && ./scripts/easy_node.sh server-up --public-host B_PUBLIC_IP_OR_DNS --operator-id op-b --peer-directories http://A_PUBLIC_IP_OR_DNS:8081 --beta-profile 1'" \
  --continue-on-fail 1 \
  --beta-profile 1 \
  --distinct-operators 1
```

## 6) One-command pilot runbook (machine C)

This runs one strict validation pass, then soak rounds, then collects endpoint snapshots into one `.tar.gz` bundle:

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

Optional path diversity tuning on machine C:

```bash
export CLIENT_ENTRY_ROTATION_SEC=15
./scripts/beta_pilot_runbook.sh --bootstrap-directory http://KNOWN_SERVER_IP:8081 --subject client-alice --beta-profile 1
```

## 7) One-bootstrap mode

If machine C only knows one server IP, use bootstrap discovery:

```bash
./scripts/easy_node.sh discover-hosts \
  --bootstrap-directory http://KNOWN_SERVER_IP:8081 \
  --wait-sec 20 \
  --write-config 1

./scripts/easy_node.sh machine-c-test \
  --bootstrap-directory http://KNOWN_SERVER_IP:8081 \
  --discovery-wait-sec 20 \
  --beta-profile 1 \
  --distinct-operators 1
```

## 8) What `--beta-profile` changes in easy mode

- Server:
  - quorum floors for federation and relay voting (`>=2` operator/vote defaults)
  - entry-side anti-collusion guardrail (`ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1`)
  - exit source-lock hardening (`EXIT_PEER_REBIND_SEC=0` in strict runtime)
  - peer discovery anti-concentration caps
  - bounded provider relay concentration, split-role enforcement, and shorter token TTL
- Client:
  - defaults to distinct entry/exit operators unless explicitly overridden
  - defaults to multi-source bootstrap when multiple directories are provided
  - requires at least 2 distinct directory operators in selection flow

Note:
- this beta profile is a safe operational preset for the current workflow.
- full fail-closed runtime `BETA_STRICT_MODE=1` requires additional live-WG and governance prerequisites and should be rolled out separately.
- strict runtime also requires both client and entry anti-collusion toggles (`CLIENT_REQUIRE_DISTINCT_OPERATORS=1`, `ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1`).
- strict runtime with multiple directory URLs also requires multi-source/operator quorum floors (`DIRECTORY_MIN_SOURCES>=2`, `CLIENT_DIRECTORY_MIN_OPERATORS>=2`, `ENTRY_DIRECTORY_MIN_SOURCES>=2`, `ENTRY_DIRECTORY_MIN_OPERATORS>=2`).
- strict runtime with multiple issuer URLs on exit also requires issuer quorum floors and identity binding (`EXIT_ISSUER_MIN_SOURCES>=2`, `EXIT_ISSUER_MIN_OPERATORS>=2`, `EXIT_ISSUER_REQUIRE_ID=1`).
