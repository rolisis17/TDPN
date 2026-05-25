# TDPN Project Deep Dive

Last updated: 2026-05-25

This document is the long-form handoff for the original TDPN project: the Trust-Tiered Decentralized Privacy Network. It explains what the project is, why it was built, how the major pieces fit together, which technologies were used, what was proven in testing, where the work paused, and what would still be needed to finish it as a real beta or production network.

The short version: TDPN is a decentralized privacy network and dVPN-style runtime where the same `node` binary can act as client, entry relay, exit relay, directory, issuer, and WireGuard bridge. It grew into a serious prototype with real control-plane logic, relay selection, signed feeds, invite/token issuance, WireGuard-based data-plane tests, operator evidence tooling, and a blockchain settlement/governance skeleton. It was paused because the product direction changed: a generic dVPN was technically possible, but the market wedge was not strong enough compared with existing free VPNs, commercial VPNs, Tor, Nym, Sentinel, Mysterium, Orchid, HOPR, and other privacy networks.

## Table of Contents

- [Project Identity](#project-identity)
- [Original Product Thesis](#original-product-thesis)
- [What TDPN Tries To Provide](#what-tdpn-tries-to-provide)
- [High-Level User Stories](#high-level-user-stories)
- [Main Runtime Roles](#main-runtime-roles)
- [Control Plane](#control-plane)
- [Data Plane](#data-plane)
- [WireGuard Integration](#wireguard-integration)
- [Identity, Invites, Tokens, and Tiers](#identity-invites-tokens-and-tiers)
- [Relay Selection](#relay-selection)
- [Directory Federation](#directory-federation)
- [Trust, Reputation, Disputes, and Appeals](#trust-reputation-disputes-and-appeals)
- [Blockchain and Settlement Work](#blockchain-and-settlement-work)
- [Operator Tooling](#operator-tooling)
- [Testing Strategy](#testing-strategy)
- [Real Machine Testing Status](#real-machine-testing-status)
- [Important Commands and Evidence Files](#important-commands-and-evidence-files)
- [Security Model](#security-model)
- [What Was Working](#what-was-working)
- [Known Weak Spots](#known-weak-spots)
- [What Is Missing For Beta](#what-is-missing-for-beta)
- [What Is Missing For Production](#what-is-missing-for-production)
- [Why The Project Was Paused](#why-the-project-was-paused)
- [How To Resume TDPN Later](#how-to-resume-tdpn-later)
- [Glossary](#glossary)
- [Primary Source Files](#primary-source-files)

## Project Identity

TDPN stands for Trust-Tiered Decentralized Privacy Network.

The central idea was to build a decentralized network where users could buy or earn access to private routing, while operators could provide relay and exit capacity. The network would not be a single centralized VPN provider. Instead, independent operators would run nodes, publish signed descriptors, receive trust/reputation signals, and eventually be paid or penalized through a blockchain-backed settlement and governance layer.

The original repository name was `TDPN`. Later, the active branch evolved toward "Global Private Mesh" and then "GPM Access Recovery". The old TDPN work is still valuable because it contains the hard network runtime, WireGuard tests, directory federation logic, trust-feed logic, issuer/token logic, and operator automation.

The last pre-GPM pivot checkpoint was tagged:

```text
tdpn-last-before-gpm -> 8c4b6196 Prevent live guard cleanup before backups
```

That tag is useful if someone wants to recover the dVPN direction without the later Access Recovery product pivot.

## Original Product Thesis

The early thesis was:

1. Centralized VPNs are easy to use but require trusting one company.
2. Tor is public, mature, and free, but performance and abuse handling are difficult.
3. Decentralized VPNs exist, but many have weak user trust models, weak reliability proofs, limited UX, or fragile economics.
4. A network with trust tiers, staking, signed evidence, and operator accountability could offer a stronger middle ground.

The design tried to combine:

- VPN-like usability.
- Tor-like distributed routing.
- Nym/HOPR-like thinking around multi-hop privacy.
- Blockchain-style settlement, staking, rewards, and slashing.
- A practical operator workflow that could be tested on real machines.

The project became technically deep very quickly. It was not just a paper plan. It includes a real Go node runtime, CLI scripts, Docker deployment, real WireGuard interface tests, local and multi-machine test gates, signed trust material, and a Cosmos-style blockchain application skeleton.

## What TDPN Tries To Provide

TDPN was designed to provide:

- A client that can connect through the network using an invite or credential.
- Entry relays that accept client traffic and forward it into the network.
- Exit relays that send traffic to the public internet.
- Directory servers that publish signed relay information.
- Token issuers that issue access credentials and role credentials.
- Trust feeds that tell clients and directories which operators are acceptable.
- A route selection layer that can prefer healthy, reputable, geographically suitable, and operator-distinct paths.
- A WireGuard-based local interface so normal applications can send traffic through the network.
- Operator lifecycle tools for startup, testing, incident capture, readiness gates, and production signoff.
- A future settlement layer for payments, staking, slashing, governance, rewards, sponsorship, and validator operations.

The project is not a simple HTTP proxy. It is a layered network prototype with both control-plane and data-plane pieces.

## High-Level User Stories

### Client User

A client user receives or buys an invite key. The client app uses that invite to obtain access from an issuer. It then pulls directory information, verifies signatures, chooses a route, opens a path through an entry and exit, creates or reuses a WireGuard interface, and sends traffic through the selected path.

The desired user experience was:

1. Install app.
2. Enter invite key or account credential.
3. Choose a profile like balanced, low latency, or max privacy.
4. Click connect.
5. The app builds a route using signed directory data and trust policy.
6. The user gets VPN-like network behavior.

### Operator

An operator runs an easy-node script to start directory, issuer, entry, and exit services. In early tests, a single host could run all roles for lab work, while real deployments would separate operators and machines.

The operator flow was:

1. Configure public bind addresses and operator id.
2. Start Docker services.
3. Generate keys and descriptors.
4. Publish directory and control endpoints.
5. Generate invite keys.
6. Run readiness gates.
7. Join federation with other directories.
8. Submit evidence for production readiness.

### Governance / Trust Maintainer

A trust maintainer or governance process could adjust reputation, dispute status, appeals, tier caps, and operator trust signals. That process was expected to become on-chain or at least anchored to signed evidence later.

### Future Sponsor

A sponsor could fund access for users, regions, communities, or apps. This idea later influenced the Access Recovery direction, where the product wedge became helping communities regain access to blocked services.

## Main Runtime Roles

The `node` program was intentionally multi-role. The same binary can be configured through flags or environment variables to run one or more roles.

### Client Role

The client role:

- Fetches directories.
- Verifies signed relay descriptors and feeds.
- Requests or uses access tokens.
- Selects entry and exit relays.
- Opens sessions through the entry and exit.
- Runs WireGuard command-mode integration.
- Optionally uses a kernel proxy to bridge real WireGuard packets into the TDPN opaque session path.
- Maintains status files and logs.

Important concerns in the client role:

- Do not trust unsigned or stale directory data.
- Do not accidentally fall back to unsafe synthetic traffic in real WireGuard mode.
- Do not choose entry and exit relays controlled by the same operator when distinct-operator mode is required.
- Avoid silently routing host traffic unless route installation is explicitly enabled.

### Entry Relay Role

The entry relay:

- Accepts client path-open requests.
- Verifies token proof material.
- Applies anti-abuse controls.
- Forwards opaque traffic toward the exit.
- Enforces session framing rules.
- Can reject malformed WireGuard-shaped payloads in strict live-WG mode.

The entry role is the first TDPN-controlled hop after the client.

### Exit Relay Role

The exit relay:

- Receives session-framed traffic from the entry.
- Enforces tier policy.
- Forwards traffic to the destination or local WireGuard socket.
- Handles WireGuard kernel proxy downlink paths.
- Tracks session lifecycle and metrics.
- Applies revocation checks.

The exit relay is the most legally and operationally sensitive role because it touches the public internet.

### Directory Role

The directory:

- Publishes relay descriptors.
- Signs relay selection feeds.
- Imports relays from peer directories.
- Publishes trust attestations.
- Applies operator quorum and source quorum policy.
- Supports peer membership and peer hints.
- Provides admin observability endpoints.

The directory is part of the network's trust root. Clients rely on directories to discover relays, but they should not blindly trust one directory forever.

### Issuer Role

The issuer:

- Issues client access tokens.
- Issues provider role tokens.
- Handles invite keys.
- Publishes revocation feeds.
- Supports subject profiles, promotions, reputation, bond, disputes, and appeals.
- Signs trust material for directories.

The issuer is responsible for converting an invite or account identity into usable credentials.

### WireGuard I/O Roles

There are internal support roles for WireGuard-side test traffic:

- `wgio bridge`
- `wgio tap listener`
- `wgio injector`

These helped test packet flow before and during real WireGuard interface work.

## Control Plane

The control plane is HTTP-based in the prototype.

Representative endpoints include:

- `/v1/health`
- `/v1/relays`
- `/v1/selection-feed`
- `/v1/trust-attestations`
- `/v1/token`
- `/v1/provider/relay/upsert`
- `/v1/trust/relays`
- `/v1/admin/governance-status`
- `/v1/admin/peer-status`
- `/v1/gossip/relays`
- `/v1/peers`

The control plane handles discovery, health, tokens, trust, relay descriptor exchange, peer discovery, governance status, and admin/operator flows.

Early lab testing used HTTP over Tailscale or loopback. Production was expected to require HTTPS and later mTLS for sensitive operator/admin surfaces. The code and scripts started moving in that direction, but the production cutover was not completed in TDPN before the pivot.

## Data Plane

The data plane is where client traffic moves.

The core shape:

```text
client -> entry relay -> exit relay -> destination
destination -> exit relay -> entry relay -> client
```

The data plane used opaque session framing so relays could route traffic without treating raw UDP payloads as trusted. The project added guardrails to reject non-session-framed raw downlink traffic and malformed live-WireGuard payloads.

Important data-plane features:

- Basic path-open handshake.
- Split token classes for client and provider roles.
- Session expiry propagation.
- Nonce-based replay rejection.
- Opaque bidirectional forwarding.
- Optional persistent opaque sessions.
- Optional path reuse across bootstrap cycles.
- Live-WG framing and plausibility validation.
- WireGuard command backend integration.

The data plane reached the point where real WireGuard privileged tests could pass on Linux/WSL machines, including local matrix tests and multi-machine smoke flows.

## WireGuard Integration

WireGuard was the main VPN-like interface technology.

The project used:

- Linux WireGuard command tools.
- Real kernel interfaces during privileged tests.
- Command-mode WireGuard setup.
- Client and exit key generation.
- Auto-derivation of public keys from private keys.
- Separate client and exit interfaces during tests.
- A client WireGuard kernel proxy.
- An exit WireGuard kernel proxy.
- Strict mode checks around payload shape and downlink source.

Important behavior:

- The client can create an interface like `wgvpn0`.
- The test harness can create temporary interfaces like `wgcrootcheck0` and `wgerootcheck0`.
- The exit can receive WireGuard UDP packets and relay downlink packets back through the entry/client path.
- Route installation is controlled. A full-tunnel `AllowedIPs=0.0.0.0/0,::/0` configuration does not automatically mean host traffic is routed if `install_route=0`.

This distinction mattered during live tests: the interface could be present, a handshake could happen, and the smoke test could pass without taking over the host's default route.

## Identity, Invites, Tokens, and Tiers

TDPN used invite keys and issuer-signed tokens to control access.

### Invite Keys

Operators could generate invite keys with scripts. Invite generation was hardened to refuse insecure remote HTTP admin URLs unless explicitly using loopback or an allowed lab override. This was a recurring real-machine issue because lab machines used Tailscale IPs like `100.113.245.61` and `100.64.244.24`.

The final intended behavior:

- Loopback HTTP is acceptable for local lab admin.
- Remote HTTP should be refused by default.
- HTTPS should be used for remote production admin.
- A lab override can be explicit when needed.

### Token Classes

The project split tokens into:

- `client_access`
- `provider_role`

This prevents a client access token from automatically becoming a provider/admin credential. Provider-role tokens are used for relay upserts and role-related control operations.

### Subject Identity

Tokens include subject identity. The exit and issuer logic can enforce subject tier constraints.

### Tiers

The original project explored tiered access. The exact commercial tiers were still under design, but the code had tier policy ideas like:

- Tier 1 restrictions, including SMTP blocking tests.
- Higher trust or higher bond requirements for provider roles.
- Subject profile promotion and demotion.
- Tier caps during disputes.

Later discussion explored a possible Tier 0 community/free mode where free users would also become micro-relays or micro-exits, but that idea was never implemented. It became a major reason to reconsider the product direction: forcing free users to become exits is a difficult safety, abuse, UX, and adoption problem.

## Relay Selection

Relay selection became one of the strongest parts of TDPN.

Selection considerations included:

- Health.
- Country and region.
- Requested locality.
- Same-region preference.
- Country fallback.
- Region fallback.
- Soft locality bias.
- Reputation weight.
- Exploration floor.
- Exit concentration limits.
- Distinct entry and exit operators.
- Optional distinct entry/exit countries.
- Directory-signed selection feeds.
- Feed vote thresholds.
- Multi-source quorum.

The client could use a path profile such as balanced, which mapped internally to a non-experimental two-hop path. One-hop was considered experimental/non-default because it reduces privacy. Three-hop was discussed as stronger privacy but harder to make reliable in a small test network.

The path selection work is one reason the codebase is still valuable after the pivot. Access Recovery can reuse the idea of signed choices, operator diversity, trust floors, helper scoring, and evidence-based routing, even if the product is not a generic VPN.

## Directory Federation

The directory system was designed to avoid one central list.

Features included:

- Federated directory fetch.
- Relay vote threshold.
- Operator-deduped voting.
- Directory peer sync.
- Pull-based relay import.
- Local re-signing after import.
- Push gossip relay ingestion.
- Periodic fanout.
- Signed peer-membership feeds.
- Seeded dynamic peer discovery.
- Peer hints.
- Optional requirement for signed operator and public key hints.
- Per-source and per-operator admission caps.
- Failure backoff.
- Admin peer-status endpoint.

The trust problem here is subtle. If a client uses only one directory, that directory can shape the network view. If the client uses multiple directories without quorum rules, malicious or stale data can poison route selection. TDPN pushed toward operator-aware quorum controls so one operator could not cheaply appear as many sources.

## Trust, Reputation, Disputes, and Appeals

TDPN's trust system was more advanced than a simple relay list.

It included:

- Issuer trust lifecycle APIs.
- Subject profiles.
- Promotions.
- Reputation.
- Bond/stake signals.
- Disputes.
- Appeals.
- Trust attestation feeds.
- Relay trust feeds.
- Directory ingestion of issuer trust.
- Cross-directory dispute attestation exchange.
- Vote-thresholded trust aggregation.
- Operator-deduped trust voting.
- Independent appeal vote thresholds.
- Outlier-resistant adjudication aggregation.
- Consensus tier caps.
- Median dispute and appeal windows.
- Case id and evidence ref metadata.
- Pair integrity for adjudication metadata.
- Dispute and appeal horizon caps.
- Final adjudication quorum controls.
- Source quorum controls.

The purpose was to make the network accountable without instantly trusting any one party. If an operator misbehaves, the network should be able to publish signed signals that clients and directories can enforce.

The unresolved part was governance reality: who is allowed to publish those signals, how evidence is verified, how slashing is enforced, and how false accusations are handled. The code has building blocks, but a real social/economic governance process would still be required.

## Blockchain and Settlement Work

The repository includes a Cosmos-style blockchain application skeleton under `blockchain/tdpn-chain`.

Major module ideas:

- `vpnbilling`
- `vpngovernance`
- `vpnrewards`
- `vpnslashing`
- `vpnsponsor`
- `vpnvalidator`

The blockchain direction was meant to support:

- Operator registration.
- Staking and bonds.
- Rewards.
- Slashing.
- Sponsorship pools.
- Validator operations.
- Billing records.
- Governance votes.
- Dispute records.
- Appeal records.
- Settlement proofs.

The blockchain work was not ready for mainnet. It needed real network metrics, economic design, validator operations, audit, on-chain/off-chain evidence boundaries, and integration with the runtime.

Important reality: without real beta traffic, many blockchain activation metrics cannot be filled honestly. Placeholder metrics are useful for templates, but mainnet activation should wait for observed data.

## Operator Tooling

The operator tooling is mostly script-driven.

Important script families:

- `scripts/easy_node.sh`
- `scripts/wg_only_stack_selftest_record.sh`
- `scripts/integration_real_wg_privileged.sh`
- `scripts/real_wg_privileged_matrix_record.sh`
- `scripts/client_vpn_smoke.sh`
- `scripts/client_vpn_profile_compare.sh`
- `scripts/three_machine_prod_signoff.sh`
- `scripts/manual_validation_report.sh`
- `scripts/runtime_doctor*`
- `scripts/incident_snapshot*`
- `scripts/roadmap-next-actions*`

The `easy_node.sh` wrapper became the primary operator UX. It grew many commands for:

- Starting local authority mode.
- Generating invites.
- Running client VPN smoke tests.
- Running profile comparisons.
- Running production signoff.
- Running recovery and readiness checks.
- Capturing evidence bundles.
- Refreshing manual validation reports.

The tooling was intentionally pragmatic: use Bash, Docker, Go binaries, JSON summaries, and logs so a non-specialist operator could run commands and send evidence back.

## Testing Strategy

TDPN testing happened at several layers.

### Unit Tests

Go unit tests covered parts of:

- Relay framing.
- Tier policy.
- Governance record validation.
- Validator records.
- Directory selection.
- Trust aggregation.
- WireGuard guards.

### Scripted Local Tests

Local script tests checked:

- Root and non-root readiness.
- WireGuard-only stack behavior.
- Runtime doctor checks.
- No stale interface leftovers.
- Recordable summaries.
- Manual validation reports.

### Docker Tests

Docker Compose was used to run authority-like stacks:

- directory
- issuer
- entry-exit

This made it possible to restart services and test local control-plane behavior quickly.

### Real WireGuard Privileged Tests

These tests needed `sudo` because real WireGuard interfaces require privileged operations.

Important examples:

```bash
sudo ./scripts/wg_only_stack_selftest_record.sh \
  --base-port 19380 \
  --client-iface wgcrootcheck0 \
  --exit-iface wgerootcheck0 \
  --defer-no-root 0 \
  --strict-beta 1 \
  --record-result 1 \
  --manual-validation-report 0 \
  --summary-json ".easy-node-logs/root_wg_only_stack_selftest_${RUN_ID}.json" \
  --print-summary-json 1 \
  --timeout-sec 60
```

```bash
sudo ./scripts/integration_real_wg_privileged.sh
```

```bash
sudo ./scripts/real_wg_privileged_matrix_record.sh \
  --matrix-timeout-sec 240 \
  --record-result 1 \
  --manual-validation-report 0 \
  --matrix-summary-json ".easy-node-logs/root_real_wg_privileged_matrix_${RUN_ID}_matrix.json" \
  --summary-json ".easy-node-logs/root_real_wg_privileged_matrix_${RUN_ID}.json" \
  --print-summary-json 1
```

These tests passed on both Machine A and Machine B after Go/toolchain issues were resolved.

### Real Machine A/B/C Tests

The live lab used:

- Machine A: WSL/Windows host, Tailscale IP `100.113.245.61`, TDPN path `/mnt/c/Users/Stella/Downloads/TDPN`.
- Machine B: Linux host, Tailscale IP `100.64.244.24`, TDPN path `/home/stella/myfirstproject/trust-tiered decentralized privacy network`.
- Machine C / DS: client/test machine, Tailscale IP `100.111.133.33`, path `/mnt/c/Users/dcella-d/TDPN1`.

The real multi-machine smoke used Machine A and B as network servers and Machine C as client.

## Real Machine Testing Status

The most important real result from the old TDPN testing was:

- Machine A real-WG privileged selftest: pass.
- Machine A real-WG integration: pass.
- Machine A real-WG privileged matrix: pass.
- Machine B real-WG privileged selftest: pass after Go/toolchain correction.
- Machine B real-WG integration: pass.
- Machine B real-WG privileged matrix: pass.
- Client VPN smoke across live A/B: pass.
- Profile compare for balanced/2hop across live A/B: 10/10 pass when insecure remote HTTP was explicitly allowed for lab testing.

The live client VPN profile compare produced:

- Profile: `2hop`
- Rounds: 10
- Passes: 10
- Failures: 0
- Pass rate: 100 percent
- Observed country: AU
- Recommended default: 2hop

The earlier failure mode in profile compare was not a network failure. It was a preflight refusal because the command omitted `--allow-insecure-remote-http 1` while using lab HTTP endpoints on Tailscale IPs.

The three-machine production signoff failed at the bundle/gate stage during one run, even though pre-real-host readiness passed. That failure needed follow-up by inspecting the production bundle summaries. It was not enough to say the network was production-ready.

## Important Commands and Evidence Files

Common evidence paths:

```text
.easy-node-logs/
.easy-node-logs/manual_validation_readiness_summary.json
.easy-node-logs/manual_validation_readiness_report.md
.easy-node-logs/*client_vpn_smoke*.json
.easy-node-logs/*client_vpn_profile_compare*.json
.easy-node-logs/*real_wg_privileged_matrix*.json
.easy-node-logs/*wg_only_stack_selftest*.json
.easy-node-logs/*three_machine_prod_signoff*.json
```

Common operator command:

```bash
./scripts/easy_node.sh
```

Common live client smoke shape:

```bash
sudo ./scripts/easy_node.sh client-vpn-smoke \
  --bootstrap-directory http://100.113.245.61:8081 \
  --directory-urls http://100.113.245.61:8081,http://100.64.244.24:8081 \
  --issuer-url http://100.113.245.61:8082 \
  --entry-url http://100.113.245.61:8083 \
  --exit-url http://100.113.245.61:8084 \
  --subject INVITE_KEY \
  --path-profile balanced \
  --allow-insecure-remote-http 1 \
  --operator-floor-check 1 \
  --min-sources 2 \
  --min-operators 2 \
  --issuer-quorum-check 0 \
  --beta-profile 1 \
  --prod-profile 0 \
  --print-summary-json 1
```

Common live profile compare shape:

```bash
sudo ./scripts/easy_node.sh client-vpn-profile-compare \
  --profiles balanced \
  --rounds 10 \
  --pause-sec 10 \
  --min-pass-rate-pct 95 \
  --fail-on-any-fail 1 \
  --bootstrap-directory http://100.113.245.61:8081 \
  --directory-urls http://100.113.245.61:8081,http://100.64.244.24:8081 \
  --issuer-url http://100.113.245.61:8082 \
  --entry-url http://100.113.245.61:8083 \
  --exit-url http://100.113.245.61:8084 \
  --subject INVITE_KEY \
  --min-sources 2 \
  --min-operators 2 \
  --operator-floor-check 1 \
  --issuer-quorum-check 0 \
  --beta-profile 1 \
  --prod-profile 0 \
  --allow-insecure-remote-http 1 \
  --interface wgvpn0 \
  --runtime-fix 1 \
  --trust-reset-on-key-mismatch 1 \
  --public-ip-url https://api.ipify.org \
  --country-url https://ipinfo.io/country \
  --summary-json ".easy-node-logs/live_ab_client_vpn_profile_compare_${RUN_ID}.json" \
  --report-md ".easy-node-logs/live_ab_client_vpn_profile_compare_${RUN_ID}.md" \
  --print-summary-json 1
```

## Security Model

TDPN's security posture was defensive and evidence-driven.

Main guardrails:

- Signed directory descriptors.
- Signed selection feeds.
- Signed trust attestations.
- Issuer-signed tokens.
- Issuer revocation feeds.
- Multi-source directory quorum.
- Operator-deduped voting.
- Distinct operator path selection.
- Replay rejection.
- Session expiry.
- Live-WG packet plausibility checks.
- Strict downlink source framing.
- Runtime doctor checks.
- Incident snapshot bundles.
- Explicit refusal of insecure remote HTTP for admin-sensitive actions unless lab override is supplied.

The project was not audited. It should not be treated as production privacy software without a professional security review.

## What Was Working

By the time TDPN paused, the following were working or materially implemented:

- Multi-role Go node runtime.
- Local Docker authority stack.
- Directory endpoints and signed feeds.
- Issuer invite and token flow.
- Entry/exit path-open flow.
- Opaque bidirectional forwarding.
- Health-aware and trust-aware selection.
- Operator distinctness controls.
- Locality preference controls.
- Trust feed and dispute/appeal data structures.
- Peer directory sync and gossip logic.
- WireGuard command backend.
- Client and exit kernel proxy tests.
- Root privileged WireGuard selftests.
- Real two-machine/three-machine lab smoke flows.
- Profile comparison evidence.
- Manual validation reporting.
- Incident snapshotting.
- Cosmos-style blockchain module skeletons.

This is a strong prototype. It is not a finished commercial network.

## Known Weak Spots

### Product Wedge

The largest issue was not code. It was product strategy.

A generic dVPN must compete with:

- Free VPNs.
- Cheap commercial VPNs.
- Tor.
- Nym.
- Sentinel.
- Mysterium.
- Orchid.
- HOPR.
- Existing proxy and censorship-circumvention tools.

Users who only want "free VPN" have little reason to accept complexity, staking, exit liability, or community relay obligations.

### Exit Liability

Exit nodes are risky. A user running an exit can receive abuse complaints or legal attention for traffic they did not personally create. Any design that asks normal free users to become exits has a major adoption and safety challenge.

### Economics

The economics were not proven:

- Who pays exits?
- How are relays rewarded?
- How much stake is required?
- What behavior is slashable?
- How are false positives avoided?
- Can rewards cover operator costs?
- Can free/low-cost users be funded sustainably?

### Governance

The trust and dispute system had code, but real governance is more than code. It needs:

- Evidence standards.
- Human review process.
- Appeals.
- Anti-capture design.
- Clear authority boundaries.
- Transparent decisions.
- Legal and compliance review.

### Production Transport Security

Lab HTTP over Tailscale worked, but production needs:

- HTTPS everywhere for public endpoints.
- mTLS for sensitive operator/admin paths.
- Real certificates.
- Rotation procedure.
- Trust-store handling.
- Clear dev/lab/prod profiles.

### UX

The scripts are powerful but intimidating. A real beta would need:

- Simple desktop app.
- Clear connect/disconnect.
- Good error messages.
- Safe defaults.
- No accidental exit mode.
- No confusing WireGuard route state.
- Clear warnings for operators.

### Audit Gap

No independent audit had been performed.

## What Is Missing For Beta

A realistic TDPN beta would need:

1. Product narrowing.
2. Decide whether TDPN is a generic dVPN, private mesh, access recovery network, sponsor-funded VPN, or something else.
3. Decide whether exit operation is open, invite-only, staked, insured, or restricted.
4. Finish HTTPS/mTLS transport profile.
5. Replace lab HTTP defaults with production-safe defaults.
6. Build a one-command server installer.
7. Build a client UX that hides most script complexity.
8. Write operator legal/safety guidance.
9. Create a beta abuse response process.
10. Run a small trusted operator cohort.
11. Collect real reliability and performance metrics.
12. Validate path selection under churn.
13. Validate directory federation under stale/malicious peers.
14. Validate revocation propagation.
15. Validate invite expiration and recovery.
16. Decide what logs are kept and what is never logged.
17. Add privacy-preserving telemetry boundaries.
18. Finish beta docs.
19. Add CI coverage for the main gates.
20. Run an external security review before asking strangers to trust it.

## What Is Missing For Production

Production would require all beta items plus:

- Legal review for exit operators.
- Abuse desk workflow.
- Rate limits and abuse throttling.
- Payment settlement.
- Real token economics.
- Slashing rules that cannot be abused.
- Validator operations if using the chain.
- Public status page.
- Monitoring and alerting.
- Backup and disaster recovery.
- Certificate automation.
- Key rotation ceremonies.
- Multi-region relay diversity.
- Long-running soak tests.
- Performance benchmarks.
- Privacy audit.
- Cryptography audit.
- Supply-chain hardening.
- Reproducible builds.
- Signed releases.
- Installer trust chain.
- Governance documentation.
- Incident response drills.

## Why The Project Was Paused

TDPN was paused because the team reconsidered whether a generic dVPN was the right product.

The hard truth:

- The technical work was impressive.
- The network could be made to work in lab conditions.
- But "another dVPN" is not enough by itself.
- Free VPNs and Tor already exist.
- Most users will not run exits for free.
- Staking/slashing adds complexity before the user feels value.
- The unique wedge was not clear enough.

This led to a pivot toward GPM Access Recovery: a more focused product that reuses signed trust, helper routing, operator evidence, and deployment tooling, but solves a clearer problem for blocked or disrupted communities.

## How To Resume TDPN Later

If TDPN is resumed, do not start from scratch.

Recommended restart path:

1. Check out the `tdpn-last-before-gpm` tag for the cleanest pre-pivot network state.
2. Read this document end to end.
3. Read `docs/mvp-status.md`.
4. Read `docs/testing-guide.md`.
5. Read `docs/product-roadmap.md`.
6. Run unit tests.
7. Run local Docker authority tests.
8. Run root WireGuard selftests.
9. Run client VPN smoke locally.
10. Rebuild A/B/C real-machine lab.
11. Run profile compare.
12. Inspect production signoff bundle failure.
13. Decide product wedge before adding features.

Do not begin by adding blockchain features. The network and product must prove real user demand first.

## Glossary

### A/B/C Lab

The three-machine test setup. A and B are server/operator machines. C is the client machine.

### Access Token

A credential from an issuer allowing a client to use the network.

### Directory

A service that publishes relay descriptors, selection feeds, peer information, and trust material.

### Entry Relay

The first relay after the client.

### Exit Relay

The relay that sends traffic to the destination network.

### Issuer

A service that issues invites, access tokens, provider tokens, and revocations.

### Opaque Session

A session-framed forwarding path used so entry and exit relays route traffic in controlled envelopes rather than trusting arbitrary raw payloads.

### Provider Token

A credential allowing a subject/operator to perform provider role actions such as relay upsert.

### Selection Feed

A signed feed used by clients to choose relays.

### Trust Feed

A signed feed describing reputation, stake/bond, disputes, appeals, or relay trust.

### WireGuard Kernel Proxy

The TDPN component that bridges real WireGuard interface traffic into the opaque network path.

## Primary Source Files

Start with:

- `README.md`
- `docs/mvp-status.md`
- `docs/testing-guide.md`
- `docs/product-roadmap.md`
- `docs/protocol.md`
- `docs/deployment.md`
- `docs/manual-validation-backlog.md`
- `docs/easy-3-machine-test.md`
- `docs/cosmos-settlement-runtime.md`
- `docs/blockchain-bootstrap-validator-plan.md`
- `docs/operator-lifecycle-runbook.md`
- `docs/threat-model.md`
- `scripts/easy_node.sh`
- `cmd/node`
- `pkg`
- `internal`
- `services`
- `blockchain/tdpn-chain`

## Final Handoff Note

TDPN should be remembered as a serious network prototype, not a failed experiment. It answered many engineering questions:

- Can one Go runtime run all early node roles? Yes.
- Can signed directories, issuers, and trust feeds be wired together? Yes.
- Can real WireGuard interfaces be tested in this stack? Yes.
- Can multi-machine live smoke flows pass? Yes.
- Can operator evidence be captured repeatably? Mostly yes.

The unanswered question was whether this exact product should exist as a generic dVPN. That is a product and market question, not only an engineering question. If the product wedge becomes clear later, the codebase contains enough working infrastructure to resume from a strong base.
