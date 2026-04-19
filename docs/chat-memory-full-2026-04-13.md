# Full Chat Memory Dump (Reconstructed)

Date written: 2026-04-13  
Author: Codex assistant  
Scope: Detailed memory reconstruction from this chat thread, including technical debugging, commands, errors, architecture/product discussions, and collaboration context.

## Important Note
This is a reconstruction from chat memory, not a byte-for-byte export of the conversation backend.
I included as much detail as possible, including many exact command/output fragments you shared.

## 1. Project + Environment Context
- Project path on Machine C (Linux): `/home/stella/myfirstproject/trust-tiered decentralized privacy network`
- Core workflow script: `./scripts/easy_node.sh`
- Validation/log directory heavily used: `.easy-node-logs/`
- You are orchestrating a 3-machine flow:
- Machine A (authority role often): `100.111.133.33`
- Machine B (provider/authority depending on test): `100.113.245.61`
- Machine C (client/test runner): local Linux machine where you run `client-vpn-*`, manual validation checks, and signoff scripts.

## 2. Early State You Shared
You shared a very large manual validation status output indicating:
- Status JSON corruption warning:
- `manual-validation status file is invalid JSON; falling back to empty checks`
- Runtime hygiene was passing:
- `runtime_hygiene=PASS`
- Blocking checks pending:
- `wg_only_stack_selftest=PENDING`
- `machine_c_vpn_smoke=PENDING`
- `three_machine_prod_signoff=PENDING`
- Optional checks:
- `three_machine_docker_readiness=PENDING`
- `real_wg_privileged_matrix=SKIP` (root required)
- Profile default gate was warning / no-go:
- `profile_default_gate_status=warn`
- `profile_default_gate_decision=NO-GO`
- `recommended_profile=balanced`
- Roadmap stage at that point:
- `roadmap_stage=BLOCKED_LOCAL`
- Next action was explicitly set to WG-only selftest command with sudo.

## 3. Long Troubleshooting Arc (Chronological)

### 3.1 Initial client VPN smoke failures
You reported multiple `client-vpn-smoke` failures with outputs like:
- `status=fail stage=up`
- Later: `status=fail stage=up-retry`
- Notes included key trust reset retry attempts:
- `notes: client-vpn up failed after trust reset retry`
- `trust_reset.reason: directory key is not trusted`
- Multiple artifact bundles were produced each run:
- `...client_vpn_smoke_*_incident_snapshot.tar.gz`
- `...client_vpn_smoke_*_incident_snapshot/incident_report.md`
- and JSON summaries.

### 3.2 Recurrent entry/exit startup failure signature
A major recurring failure signature from Docker logs:
- `local entry did not become healthy at http://127.0.0.1:8083/v1/health`
- repeated crash loop:
- `node stopped: exit wg pubkey init failed: configured EXIT_WG_PUBKEY does not match EXIT_WG_PRIVATE_KEY_PATH`

This error appeared repeatedly on both operator identities over multiple attempts:
- `op-5089f5fb87`
- `op-cf3bf267e2`
- and later other operator IDs in subsequent runs.

### 3.3 Peer identity strict / federation startup blocks
You hit strict startup refusal several times:
- `server-up refused: could not verify operator-id uniqueness against peer directories.`
- Hint printed by script:
- `temporary bypass (diagnostics only): --peer-identity-strict 0`

You also requested that env cleanup be part of cleanup/server-down path so stale settings do not keep breaking startup.

### 3.4 Prod profile constraints confusion
You repeatedly encountered strict prod constraints:
- `server-up --prod-profile requires at least 2 issuer URLs for strict quorum.`
- `current issuer URLs (1): https://...:8082`
- It required at least one peer directory from a distinct authority/issuer operator.

And beta strict constraints:
- `BETA_STRICT_MODE requires ENTRY_DIRECTORY_MIN_SOURCES>=2 when multiple DIRECTORY_URLS are configured`

### 3.5 Exit startup issuer quorum failures
Another recurring signature in prod-profile attempts:
- `local exit did not become healthy at https://127.0.0.1:8084/v1/health`
- `exit startup key fetch failed: issuer source quorum not met: success=1 required=2`
- `exit startup revocation fetch failed: Get "https://100.111.133.33:8082/v1/revocations": dial tcp ... connect: connection refused`
- `node stopped: exit startup issuer sync timeout after 30s`

### 3.6 You asked for step-by-step runbook
You asked explicitly for step-by-step:
- how to bring servers up
- what to test next
- exact order

### 3.7 Mixed progress + hard failures
At one point you got healthy curl checks from local machine against TLS endpoints (example):
- `curl --cacert ... --cert ... --key ... https://100.113.245.61:8082/v1/pubkeys`
- returned JSON with issuer and key epoch.

But overall gating still failed due to quorum/trust/federation conditions.

### 3.8 Successful intermediate wins
You reported very important successes:
- `wg-only-stack-selftest-record: status=pass`
- `client-vpn-smoke: status=pass stage=complete`
- Example subject used in one successful run: `inv-REDACTED`

That successful smoke run showed:
- trust reset auto-retry succeeded (`retry_succeeded=true`)
- `public_ip_result` and `country_result` returned (example: `AU`)
- interface and peer details were printed.

### 3.9 Prod signoff still failing
Even after smoke pass, prod signoff still failed:
- `three-machine-prod-signoff: status=fail stage=bundle`
- with run report status `fail` and bundle artifacts created.

### 3.10 Real WG privileged matrix failure
You also ran:
- `real-wg-privileged-matrix-record --print-summary-json 1`
- Result:
- `status=fail`
- matrix summary + log artifacts were generated.

### 3.11 Provider restart in prod failure
On Machine B provider startup attempt:
- `server-up ... --mode provider ... --prod-profile 1 ...`
- failed with operator uniqueness verification refusal.

### 3.12 Strategic discussion about certs
You asked:
- whether cert generation/use is required every time
- whether client/servers need it
- whether to automate it

### 3.13 Authority prod startup with no peers still blocked
Authority prod startup without enough issuer URLs raised strict quorum requirement.
You called flags confusing and asked for simplification.

### 3.14 Federation diagnostics evidence
You posted detailed `server-federation-wait` and `server-federation-status` JSONs showing:
- peer sync failing while issuer sync passing
- concrete error:
- `peer key is not trusted for https://100.113.245.61:8081`
- and on another side:
- `peer key is not trusted for https://100.111.133.33:8081`
- plus a case of:
- `peer operator quorum not met: operators=1 required=2`

### 3.15 Relay set evidence from both authorities
You confirmed relay visibility with:
- `curl ... /v1/relays | jq -r '.relays[].relay_id'`
- On A:
- `entry-op-ab91835bf0`
- `exit-op-ab91835bf0`
- On B:
- `entry-op-9de9c33b4a`
- `exit-op-9de9c33b4a`

### 3.16 Client preflight eventually passed
You ran preflight successfully in prod mode:
- `client-vpn preflight: OK`
- Directory/issuer/entry/exit all reachable
- operator diversity and issuer diversity passed
- mTLS files existed
- wg interface create/delete check passed

### 3.17 But smoke still failed after preflight
Immediately after preflight success, `client-vpn-smoke` still failed at `stage=up` in one run.
This indicated preflight transport/health checks were not the only issue.

### 3.18 Manual validation and readiness remained NOT_READY
Across many runs:
- `manual_validation_report.readiness_status` stayed `NOT_READY`
- `next_action_check_id` often remained `machine_c_vpn_smoke` or `three_machine_prod_signoff` depending on sequence.

### 3.19 Your explicit frustration and valid concern
You asked why this cannot all be fully tested in docker and why so much real-machine effort was needed.
You highlighted lost time and repeated cycles.

### 3.20 Expanded strategic conversation (non-code)
You moved into high-level strategy discussions:
- virtualizing “real machines” for production-grade test realism
- fundraising and crypto investors online
- how to pitch without fully revealing IP
- payment rail choice (USDT vs high-inflation tokens)
- tokenomics for startup and server/shareholder payout model

### 3.21 Regulatory preference from you
You said:
- you want to do it “crypto way” and not follow specific country law.

### 3.22 Fictional architecture brainstorming
You explored ambitious ideas:
- global privacy mesh
- every client also server (and possibly validator)
- 1 hop to 3 hops selectable by client
- random relay/exit rotation every few minutes
- micro-relays
- lightweight participation model for normal computers (possibly phones later)
- limited client count per participant server
- abuse scanning/attacker detection thought experiments

### 3.23 Safety + abuse resistance thread
You asked:
- how exit owners protect themselves from abuse and legal/operational risk
- which ports to close and how that affects users

You then converged on:
- keeping tiered trust design
- conservative port policy initially
- unlocking additional capabilities through trust system

### 3.24 Roadmap additions you requested
You asked to add:
- micro-relays concept track
- 1-hop/2-hop/3-hop route-profile focus
- `Exit Node Safety Baseline v1`
- `Exit Node Safety Guide`
- plus a guide for clients

### 3.25 You repeatedly instructed execution
You gave many consecutive prompts:
- `Ok, proceed with the next step.`
(repeated many times to continue incremental work)

### 3.26 Chat migration concern
You asked whether this chat context can move to faster computer without losing continuity.
You requested writing context to `.md`.

I created:
- `docs/session-handoff-2026-04-13.md`

### 3.27 Why you did not want migration
You explained:
- previous sessions on new computer made more coding mistakes
- this current long-context collaboration had better reliability
- you preferred preserving this chat continuity.

### 3.28 Performance bottleneck and SSH idea
You proposed:
- keep this chat, but run all work remotely through SSH on A/B/C or a faster dev machine.
- Goal: speed up command/runtime execution while retaining collaboration context.

## 4. Key Failure Signatures Catalog

### 4.1 WireGuard key mismatch (entry/exit)
- `node stopped: exit wg pubkey init failed: configured EXIT_WG_PUBKEY does not match EXIT_WG_PRIVATE_KEY_PATH`

### 4.2 Strict prod issuer quorum gate
- `--prod-profile requires at least 2 issuer URLs for strict quorum`

### 4.3 Beta strict min source guard
- `BETA_STRICT_MODE requires ENTRY_DIRECTORY_MIN_SOURCES>=2 when multiple DIRECTORY_URLS are configured`

### 4.4 Peer identity strict uniqueness gate
- `server-up refused: could not verify operator-id uniqueness against peer directories`

### 4.5 Exit startup issuer sync timeout
- `exit startup key fetch failed: issuer source quorum not met`
- `exit startup revocation fetch failed: ... connect: connection refused`
- `node stopped: exit startup issuer sync timeout after 30s`

### 4.6 Federation trust mismatch
- `peer key is not trusted for https://<peer>:8081`

### 4.7 Federation quorum shortfall
- `peer operator quorum not met: operators=1 required=2`

### 4.8 Auth/token mismatch on diagnostics endpoint
- `server-federation-status failed: peer-status endpoint returned code=401`
(occurred when token source likely mismatched role/env file)

## 5. Important Commands You Ran (Representative)

### 5.1 Cleanup + smoke loop
```bash
sudo ./scripts/easy_node.sh client-vpn-down --force-iface-cleanup 1 || true
sudo ./scripts/easy_node.sh client-vpn-trust-reset --all-scoped 1 --trust-scope scoped || true
sudo ./scripts/easy_node.sh client-vpn-smoke \
  --bootstrap-directory http://100.111.133.33:8081 \
  --subject <invite> \
  --path-profile balanced \
  --interface wgvpn0 \
  --pre-real-host-readiness 1 \
  --runtime-fix 1 \
  --trust-reset-on-key-mismatch 1 \
  --trust-reset-scope scoped \
  --public-ip-url https://api.ipify.org \
  --country-url https://ipinfo.io/country \
  --print-summary-json 1
```

### 5.2 WG-only selftest record
```bash
sudo ./scripts/easy_node.sh wg-only-stack-selftest-record \
  --strict-beta 1 \
  --base-port 19280 \
  --client-iface wgcstack0 \
  --exit-iface wgestack0 \
  --print-summary-json 1
```

### 5.3 Three-machine prod signoff
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

### 5.4 Preflight with prod + mTLS
```bash
sudo ./scripts/easy_node.sh client-vpn-preflight \
  --directory-urls https://100.111.133.33:8081,https://100.113.245.61:8081 \
  --issuer-url https://100.111.133.33:8082 \
  --entry-url https://100.111.133.33:8083 \
  --exit-url https://100.111.133.33:8084 \
  --prod-profile 1 \
  --interface wgvpn0 \
  --mtls-ca-file deploy/tls/ca.crt \
  --mtls-client-cert-file deploy/tls/client.crt \
  --mtls-client-key-file deploy/tls/client.key
```

### 5.5 Relay/operator check
```bash
for h in 100.111.133.33 100.113.245.61; do
  echo "=== $h ==="
  curl -fsS --cacert deploy/tls/ca.crt --cert deploy/tls/client.crt --key deploy/tls/client.key \
    "https://$h:8081/v1/relays" | jq -r '.relays[].relay_id'
done
```

### 5.6 Federation diagnostics
Historical note: this transcript snippet uses `--admin-token` on the CLI; prefer token-file/stdin patterns in live operations to avoid process-list/history leakage.
```bash
ADMIN_TOKEN="$(grep -m1 '^DIRECTORY_ADMIN_TOKEN=' deploy/.env.easy.server | cut -d= -f2-)"
sudo ./scripts/easy_node.sh server-federation-status \
  --directory-url https://127.0.0.1:8081 \
  --admin-token "$ADMIN_TOKEN" \
  --show-json 1
```

## 6. Artifact File Ledger (Major Paths Mentioned)

### 6.1 Manual validation and readiness
- `.easy-node-logs/manual_validation_readiness_summary.json`
- `.easy-node-logs/manual_validation_readiness_report.md`

### 6.2 Selected client smoke artifacts
- `.easy-node-logs/client_vpn_smoke_20260406_174359.json`
- `.easy-node-logs/client_vpn_smoke_20260406_174359.log`
- `.easy-node-logs/client_vpn_smoke_20260406_181614.json`
- `.easy-node-logs/client_vpn_smoke_20260406_181614.log`
- `.easy-node-logs/client_vpn_smoke_20260408_150749.json` (pass run)
- `.easy-node-logs/client_vpn_smoke_20260408_165639.json`
- `.easy-node-logs/client_vpn_smoke_20260408_170933.json`
- `.easy-node-logs/client_vpn_smoke_20260408_171538.json`

### 6.3 Selected selftest/signoff artifacts
- `.easy-node-logs/wg_only_stack_selftest_record_20260408_150648.json`
- `.easy-node-logs/three_machine_prod_signoff_20260408_151143.json`
- `.easy-node-logs/three_machine_prod_signoff_20260408_170255.json`
- `.easy-node-logs/prod_gate_bundle/prod_bundle_run_report.json`
- `.easy-node-logs/prod_gate_bundle/prod_gate_summary.json`

### 6.4 Privileged matrix artifacts
- `.easy-node-logs/real_wg_privileged_matrix_record_20260408_151334.json`
- `.easy-node-logs/real_wg_privileged_matrix_record_20260408_151334_matrix.json`

## 7. Notable JSON/Output Facts from Runs
- Runtime doctor repeatedly reported zero findings in many runs.
- `pre_real_host_readiness.status` often reported `pass` while overall command still failed later stage.
- `manual_validation_report.status` frequently `ok` but `readiness_status` stayed `NOT_READY`.
- `trust_reset` behavior changed by run:
- sometimes skipped
- sometimes attempted due to untrusted directory key
- at least one run succeeded after retry.
- `client-vpn-preflight` reached full green once, proving endpoint reachability and diversity checks can pass simultaneously.
- `client-vpn-smoke` can still fail even after preflight passes, indicating higher-layer/session/path/opening logic differences versus preflight checks.

## 8. Collaboration + Decision Track

### 8.1 You asked for direct progress continuation repeatedly
Your repeated prompt `Ok, proceed with the next step.` indicated you wanted continuous execution over long planning pauses.

### 8.2 You requested safety docs + roadmap integration
You asked to explicitly include:
- exit-node safety baseline
- exit-node safety guide
- client safety guide
- micro-relays track
- 1/2/3 hop route-profile focus

### 8.3 You requested full comparison runner
You asked whether comparison runner was necessary; after explanation you approved full comparison runner.

### 8.4 You requested chat-context preservation
You wanted migration without losing quality/context and asked for `.md` context capture.

### 8.5 You requested performance improvement via remote ops
You suggested SSH from this session to all machines so we keep context and increase throughput.

## 9. Current Repository State Relevant to This Chat (as observed)
These files exist and were part of the evolving roadmap/workstream:
- `docs/session-handoff-2026-04-13.md`
- `docs/easy-3-machine-test.md`
- `docs/exit-node-safety-baseline-v1.md`
- `docs/exit-node-safety-guide.md`
- `docs/client-safety-guide.md`
- `docs/global-privacy-mesh-track.md`
- `scripts/client_vpn_profile_compare.sh`
- `scripts/integration_client_vpn_profile_compare.sh`
- `scripts/integration_session_handoff.sh`
- `scripts/three_machine_prod_signoff.sh`
- `scripts/client_vpn_smoke.sh`
- `scripts/manual_validation_status.sh`

## 10. Why Docker Alone Was Not Enough (core practical reason from this thread)
In this project, docker-based rehearsals and one-host simulations were useful but did not fully cover:
- real cross-host reachability
- real identity/trust transitions between independently bootstrapped hosts
- strict prod-profile quorum behavior across distinct operators/issuers
- mTLS material and cert chain behavior in real endpoint calls
- federation trust/key drift across machines and environments

This mismatch is why you repeatedly saw:
- docker/local checks pass in segments
- while real-host gates still blocked (`peer trust`, quorum, issuer sync, or startup health timeout).

## 11. Concrete Pain Points You Experienced
- High command complexity and flag overload.
- Similar-looking failures with different root causes.
- Time consumed by reruns and waiting windows.
- Unclear when to run authority vs provider mode on B in specific phases.
- Confusion around when prod-profile is valid vs structurally impossible (single issuer URL).
- Friction from stale state and trust files.
- Need to coordinate A/B/C in tight order with minimal human error.

## 12. Your Product + Strategy Questions Captured
You asked to discuss:
- virtualized alternatives to physical multi-machine testing
- crypto-native investor outreach and channels
- idea-protection while pitching
- USDT vs high-inflation token usage for payments and treasury backing
- tokenomics needed to launch and sustain server/shareholder payouts
- whether “client/server/validator all-in-one” could be feasible
- impact on latency/ping and how to make it lightweight
- possibility of dynamic relay/exit rotation
- adding micro-relays
- exit abuse protection and safety baselines

## 13. Architectural Concepts You Floated (Fictional / Exploratory)
- “Global Privacy Mesh” framing
- all participants as both consumers and contributors
- route profile choice by client (1-hop low-latency, 3-hop higher privacy)
- randomized route changes over time
- lightweight participation thresholds
- optional validator role separation from packet forwarding
- trust tiers and capacity controls per participant node

## 14. Operational Safety Direction You Approved
- Keep tier/trust-based restrictions.
- Default to conservative/closed high-abuse surfaces.
- Expand capabilities with trust progression.
- Add explicit operator safety documentation.

## 15. Evidence Snapshots (Verbatim Fragments You Shared)

### 15.1 Example success fragment
```text
wg-only-stack-selftest-record: status=pass
...
client-vpn-smoke: status=pass stage=complete
...
trust_reset:
  attempted: true
  status: ok
  reason: directory key is not trusted
  retry_attempted: true
  retry_succeeded: true
```

### 15.2 Example persistent startup failure fragment
```text
local exit did not become healthy at https://127.0.0.1:8084/v1/health
...
exit startup key fetch failed: issuer source quorum not met: success=1 required=2
exit startup revocation fetch failed: Get "https://100.111.133.33:8082/v1/revocations": dial tcp ... connect: connection refused
node stopped: exit startup issuer sync timeout after 30s
```

### 15.3 Example federation trust failure fragment
```text
peer_sync_ready=0
...
error: "peer key is not trusted for https://100.113.245.61:8081"
```

### 15.4 Example preflight all-green fragment
```text
client-vpn preflight: OK
  [ok] directory reachable
  [ok] issuer reachable
  [ok] entry reachable
  [ok] exit reachable
  operator diversity: all_ops=2 entry_ops=2 exit_ops=2
  issuer diversity: issuer_ops=2
```

### 15.5 Example immediate post-preflight failure fragment
```text
client-vpn-smoke: status=fail stage=up
notes: "client-vpn up failed"
```

## 16. Machine Identity/Role Snapshots You Shared

### 16.1 Machine A sample authority startup identity
- `operator_id: op-ab91835bf0`
- `issuer_id: issuer-8c6c556c8a`
- TLS + prod profile enabled in multiple runs.
- Auto invite generated at least one key in multiple runs.

### 16.2 Machine B sample authority/provider identities
- `operator_id: op-9de9c33b4a`
- `issuer_id: issuer-3b37c168dc`
- Sometimes started as authority for quorum purposes.
- Provider-mode prod startup blocked when only one issuer URL in scope.

### 16.3 Machine C sample role
- Client runner for `client-vpn-preflight`, `client-vpn-smoke`, manual validation gates, and signoff scripts.

## 17. Invite Keys Mentioned in Conversation (examples)
- `inv-REDACTED`
- `inv-REDACTED`
- `inv-REDACTED`
- `inv-REDACTED`
- `inv-REDACTED`

## 18. Why You Asked for Bigger/Faster Computer
- Current computer felt slow for coding iteration.
- You observed much faster performance on another machine.
- But you did not want to lose chat continuity/context quality.
- You asked if we can keep this thread and operate through SSH.

## 19. Assistant Output Previously Created for Migration
- `docs/session-handoff-2026-04-13.md` already existed as compact transfer context.
- This file (`docs/chat-memory-full-2026-04-13.md`) is the expanded version you requested.

## 20. Cautionary Notes Captured from This Experience
- Prod profile in this system is intentionally strict and will block “almost-ready” states.
- Passing health curls and passing preflight are necessary but not always sufficient.
- Federation trust and peer operator quorum must both converge.
- Token/env mismatch between `.env.easy.server` and `.env.easy.provider` can silently derail diagnostics.
- Minor shell mistakes (line continuation/space after `\`) can alter command parsing.

## 21. Shell Formatting Pitfalls Seen
A specific recurring typo risk during multiline commands:
- trailing space after backslash in lines like:
- `--exit-url https://...:8084 \ `
This can break intended continuation and cause subtle argument parsing issues.

## 22. Immediate Technical Priorities That Emerged
- Stabilize prod 2-authority trust sync and peer key trust in both directions.
- Ensure both operators are counted as configured healthy peer sources.
- Keep deterministic startup order and verification gates before client smoke/signoff.
- Maintain clean trust-state resets on client when switching authority/cert material.

## 23. Broader Product Priorities You Asked to Advance
- Route-profile work (1-hop/2-hop/3-hop)
- Micro-relays exploration track
- Safety baseline docs for exits and clients
- Investor and tokenomics strategy planning

## 24. Open Questions You Raised (for future sessions)
- Best way to virtualize multi-machine realism without physical hardware.
- Most credible online channels for crypto-native investors.
- How to pitch enough without giving away core moat.
- Treasury/payments denomination strategy (USDT vs alternatives).
- Practical tokenomics budget planning for launch and payouts.
- Viability of user devices as light relays/validators without unacceptable latency overhead.

## 25. Where We Ended Just Before This File Request
- You asked if we can speed work via SSH to all machines while keeping this chat.
- You then asked for a markdown file containing everything remembered from chat, with as many lines as possible.
- This file is produced as that comprehensive memory artifact.

## 26. Raw Chronology (Compact Date-Labeled Reconstruction)

### 2026-04-06 (major failure-heavy day)
- Manual validation status initially showed invalid JSON fallback.
- Runtime hygiene passed.
- Local gate blocked on WG-only selftest.
- Multiple `client-vpn-smoke` runs failed (up/up-retry).
- Trust reset attempted due to untrusted directory key.
- Repeated `EXIT_WG_PUBKEY` mismatch crashes in entry-exit logs.

### 2026-04-08 (mixed progress day)
- Recurrent prod-profile and federation/issuer quorum issues.
- Several authority/provider restarts and diagnostics.
- `wg-only-stack-selftest-record` passed.
- At least one `client-vpn-smoke` passed completely.
- `three-machine-prod-signoff` still failed (`stage=bundle`).
- `real-wg-privileged-matrix-record` failed.
- Prod mTLS preflight eventually passed but smoke again failed in another run.
- Federation diagnostics exposed `peer key is not trusted` and operator quorum issues.

### 2026-04-13 (strategy + docs + continuity)
- Focus extended to product architecture, investor path, and tokenomics.
- You asked to add/advance micro-relays and multi-hop route profile ideas.
- You asked for persistent next-step execution.
- You asked for context portability and then opted to preserve this chat.
- You asked for SSH-driven acceleration.
- You requested this full memory markdown.

## 27. Additional Detailed Fragments (for completeness)

### 27.1 Manual validation style output pattern repeatedly seen
```text
[manual-validation-status] runtime_hygiene=PASS
[manual-validation-status] wg_only_stack_selftest=PENDING
[manual-validation-status] machine_c_vpn_smoke=PENDING
[manual-validation-status] three_machine_prod_signoff=PENDING
[manual-validation-status] roadmap_stage=BLOCKED_LOCAL
```

### 27.2 Typical signoff failure pattern
```text
three-machine-prod-signoff: status=fail stage=bundle
outputs:
  run_report_status: fail
  run_report_final_rc: 1
  bundle_tar: .../prod_gate_bundle.tar.gz
incident_snapshot.status: ok
manual_validation_report.readiness_status: NOT_READY
```

### 27.3 Typical matrix failure pattern
```text
real-wg-privileged-matrix-record: status=fail
matrix:
  status: fail
  rc: 1
  timeout_sec: 900
```

### 27.4 Typical federation timeout pattern
```text
server-federation-wait: TIMEOUT after 180s
peer_sync_ready=0
issuer_sync_ready=1
peer_health_ready=0 or 1 depending on run
failure_reasons include peer_sync_not_success and peer_sync_quorum_not_met
```

## 28. Human Context (important for collaboration continuity)
- You invested significant time and energy over many iterative attempts.
- You remained persistent and kept testing exact steps.
- You asked direct, practical questions when outputs were contradictory.
- You preferred moving fast once a clear sequence existed.
- You wanted to preserve quality and trust in this collaboration while improving speed.

## 29. Practical Next Session Use of This File
Use this file as:
- onboarding packet for new machine/session
- command + failure signature lookup
- shared source of truth for what has already been tried
- non-code decision log (architecture, safety, product direction)

## 30. Closing
This is the fullest reconstruction I can provide from this chat context in a single `.md` file.
If you want, I can also generate a second companion file that is purely chronological command-by-command with no commentary, optimized for exact rerun automation.
