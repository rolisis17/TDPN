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

## 31. Continuation Memory Update (2026-04-17 through 2026-05-03)

Date updated: 2026-05-03
Reason: user is switching from Codex desktop app back to VS Code Codex because the app has been unstable/frustrating, and needs this file to carry the full project/chat context forward.

### 31.1 New working environment and repo context
- Current local workspace during this continuation: `C:\Users\dcella-d\TDPN1`
- WSL path used for commands from DS: `/mnt/c/Users/dcella-d/TDPN1`
- Main branch used for most active work after merge/branch coordination: `codex/gpm-productization-checkpoint`
- Remote branch: `origin/codex/gpm-productization-checkpoint`
- Product/rebrand target chosen by user: `Global Private Mesh (GPM)`
- Old TDPN names should remain as compatibility aliases where practical, with deprecation hints rather than risky deep internal rename.
- User wants fast work with parallel agents when available, but after many live-test bugs the most important rule is: do not ask the user to retry live commands until the relevant code path has been inspected and local/focused tests have run.

### 31.2 Profile default gate and live evidence arc from 2026-04-17
The user ran live profile default gate commands against two remote hosts:
- Machine A / directory A: `100.113.245.61`
- Machine B / directory B: `100.64.244.24`
- Invite keys were shared in chat, but this file keeps them redacted because they are operational secrets.

Early command pattern:
```bash
./scripts/easy_node.sh profile-default-gate-live \
  --host-a "$A_HOST" \
  --host-b "$B_HOST" \
  --reports-dir .easy-node-logs \
  --campaign-timeout-sec 1200 \
  --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json \
  --print-summary-json 1 \
  --campaign-subject "$INVITE_KEY"
```

Important 2026-04-17 result:
- Endpoint preflight passed.
- Campaign refresh ran for a long time and completed.
- Signoff status was `ok` with `final_rc=0`, but decision was `NO-GO`.
- Recommended profile was `balanced`.
- Support rate example observed: `66.67%`.
- The gate was non-blocking at that stage and still listed as pending in roadmap progress.

Later 2400-second run:
- Campaign ran for about `1324` seconds.
- `status=ok`, `final_rc=0`, but decision stayed `NO-GO`.
- Recommended profile stayed `balanced`.
- Trend source was `vote_fallback`.
- No dominant diagnostic failure signal was detected.

### 31.3 Windows native app/testing arc
The user explicitly wanted the Windows version to be fully native, not WSL/Linux-on-Windows.

Windows script execution problem encountered:
```powershell
.\scripts\windows\local_api_session.ps1 : File ... cannot be loaded because running scripts is disabled on this system.
```

Immediate workaround used:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\windows\local_api_session.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\local_api_session.ps1 -DryRun
```

The dry run showed:
```text
local-api-session (windows-native):
  api_addr: 127.0.0.1:8095
  command_runner: C:\Program Files\Git\bin\bash.exe
  command: go run ./cmd/node --local-api
```

The real run later succeeded and printed:
```text
local control api listening on 127.0.0.1:8095 script=/c/Users/dcella-d/TDPN1/scripts/easy_node.sh runner=C:\Program Files\Git\bin\bash.exe update_enabled=false
```

Missing tools found on Windows:
```powershell
go version
node -v
npm -v
rustc -V
cargo -V
```
Initially Go, Node/npm, rustc, and cargo were not all on PATH. Rustup existed under the user profile and stable MSVC toolchain was selected:
```powershell
& "$env:USERPROFILE\.cargo\bin\rustup.exe" default stable-x86_64-pc-windows-msvc
```

NPM PowerShell shim problem:
```powershell
npm : File C:\Program Files\nodejs\npm.ps1 cannot be loaded because running scripts is disabled on this system.
```
This reinforced the product requirement: installer/first-run tooling must avoid making normal users fight shell policy.

Tauri build problem:
```text
`icons/icon.ico` not found; required for generating a Windows Resource file during tauri-build
```

User request that came from this:
- Build a Windows installer with GUI.
- Build equivalent Linux user-friendly packaging.
- Add automatic problem solving / first-run diagnostics for common Windows policy/tooling/runtime issues.
- Keep the actual project runtime native on Windows, not WSL.

### 31.4 GPM Big-Bang Productization Plan accepted by user
The user accepted a revised plan with these locked decisions:
- Ship one external release rebranded as `Global Private Mesh (GPM)`.
- Keep first trusted entry via the main GPM domain.
- After first entry, use distributed `bootstrap_directory` and peer discovery so clients/servers do not need the main domain every time.
- Replace dual-window risk with one app window and two role lanes/tabs.
- Role-ineligible tab/control should be visible but non-clickable, with a clear reason and unlock path.
- Keep TDPN commands/config keys as aliases for compatibility.
- Auth V1 is chain-native wallet-only: Keplr + Leap.
- Website V1 includes marketing homepage plus authenticated portal.
- Endpoint policy is pinned trusted domain for initial bootstrap and policy/config trust.
- Routing target is hybrid auto: direct mesh preferred, managed relay fallback.
- Client onboarding is self-serve.
- Server onboarding is permissioned and chain-identity bound.
- Rebrand is product-first now; deep internal rename deferred.
- Bootstrap fallback is signed-cache fallback when main domain is temporarily unreachable.

Public interface decisions:
- Add wallet challenge/signature/session endpoints.
- Add client registration/profile bootstrap endpoints.
- Add operator application/approval/chain-binding status endpoints.
- Add signed bootstrap manifest endpoint on main GPM domain.
- Desktop connect contract should use authenticated session plus selected profile/policy.
- Raw endpoint/IP entry removed from production UX.

### 31.5 Admin split and public app constraints
The user clarified strongly:
- The Admin Console is only for the project admin/owner, not for server operators.
- Servers must have no admin powers.
- Server UI/app should only show server status/lifecycle and a few simple actions.
- Public client/server release apps must have zero admin controls, zero approval tools, and zero server-management powers outside the local role.
- Any support/debug settings should be hidden from normal users.
- Public app and website should give users only limited, safe options.

Accepted split:
- Public GPM App: wallet login, account status, stake/prepaid status, connect/disconnect, diagnostics, optional contribution opt-in/out.
- Server view/package: local server state and very simple local lifecycle controls only.
- GPM Admin Console: approvals, policy changes, server/client control from admin side, slashing review, settlement/payout review/finalization.

### 31.6 Contribution, micro-relay, micro-exit, and weekly payouts
The user revised the contribution plan:
- Remove KYC for now.
- Tier 1 cannot use or provide micro-relay/micro-exit.
- Tier 2 and Tier 3 can use micro-relays.
- Tier 2 and Tier 3 can opt into micro-relay or micro-exit beta.
- Micro-exit means a client device can provide public internet exit for other users; this remains beta and should be reviewed later.
- The user expects tier gating plus slashing to remove abusers from the network.
- VPN use should require stake plus prepaid balance before use.
- Micro-relay/micro-exit should require tier eligibility, stake, prepaid balance, policy pass, explicit opt-in, and device checks.
- Background GPM Agent should measure hardware/network and set safe contribution limits automatically.
- Better hardware/network should allow higher safe max clients/bandwidth and better contribution rewards.
- User VPN traffic must be prioritized over contributed traffic.
- Contribution is measured continuously but settled and paid weekly.
- Weekly settlement epoch default: Monday 00:00 UTC to Monday 00:00 UTC.

Important contribution fields discussed:
- `client_tier`
- `stake_satisfied`
- `prepaid_balance_satisfied`
- `can_use_micro_relays`
- `can_enable_micro_relay`
- `can_enable_micro_exit`
- `contribution_lock_reason`
- `contribution_profile`
- capacity score, health score, max forwarded sessions, max bandwidth, uptime/reliability, demotion state.

### 31.7 App and website UX direction
The user reviewed the app/website and gave strong UX direction:
- The app had improved visually, but still had too much happening.
- The website was disliked and described as looking like a generic free accounting site.
- The website should follow the app’s stronger visual language.
- The user wants consumer-grade, high-budget VPN feel.
- Minimal explanatory text.
- Simple words only.
- Basic buttons and commands.
- Button placement should consider psychology: users should feel safe, good, guided, and not overwhelmed.
- Project explanations should be written for clients, not for the developer/admin.
- Avoid internal/admin/support settings on public website.
- The app should start with a small centered wallet-connect modal before opening the full app.
- Wallet connection should be as automated as possible for Cosmos users.
- The website should have personality and premium product feel, possibly informed by strong blockchain/crypto product sites, but not copied.

### 31.8 Community and investor strategy discussions
The user asked how to build a community with zero experience.
Core advice discussed:
- Start with a clear simple story, not technical overload.
- Pick a small initial audience and community home.
- Publish consistent progress and demos.
- Automate repetitive updates where possible.
- Keep community calls-to-action simple.
- Build trust through transparency and proof, not hype alone.

The user also asked how to find investors for a new blockchain/tech project.
Core themes discussed:
- Prepare a credible pitch narrative, demo, roadmap, and evidence.
- Look for crypto-native angels, pre-seed funds, infrastructure/privacy investors, accelerators, hackathons, builder programs, and strategic partners.
- Warm intros are more effective than cold outreach.
- Avoid over-disclosing core moat before trust/NDA/investor quality is established.
- Basic financing can start with smaller angels/grants before larger institutional rounds.
- Investor materials should explain problem, product, traction/evidence, token/economic model, team execution, risk mitigation, and what funds unlock next.

### 31.9 Repeated “next slice” execution and quality-control preference
The user repeatedly asked to:
- Continue through roadmap slices.
- Use as many parallel agents as necessary.
- Add one agent to logic-check everything done.
- Add agents to search for gaps/logic failures in VPN.
- Add agents to search for blockchain logic issues.
- Check the entire project line-by-line for gaps, logic errors, vulnerabilities, and anything wrong.

Important collaboration preference:
- User is comfortable with aggressive parallelism.
- User does not want repeated questions unless truly necessary.
- User wants one independent logic-check/review lane for each meaningful implemented block.
- User values speed, but after live-test frustration, wants best quality and local verification before being asked to run anything.

### 31.10 OpenAI model migration request
The user wrote:
```text
$OPENAI-docs migrate this project to gpt-5.5
```
This triggered the OpenAI docs skill requirement in this environment. If continuing that task, use official OpenAI documentation only and update project model references carefully.

### 31.11 Windows launch/user commands
The user asked how to launch the Windows program.
Relevant command family:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\windows\local_api_session.ps1
```
For desktop dev:
```powershell
cd C:\Users\dcella-d\TDPN1\apps\desktop
npm.cmd install
npm.cmd run tauri -- dev
```
Use `npm.cmd` instead of `npm` in PowerShell if execution policy blocks `npm.ps1`.

### 31.12 Live A/B testing command runbook as of 2026-05-03
The user restarted machines A and B for live evidence.

Machine B command used:
```bash
./scripts/easy_node.sh server-down || true

A_HOST=100.113.245.61
B_HOST=100.64.244.24

./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host "$B_HOST" \
  --operator-id op-b \
  --issuer-id issuer-b \
  --peer-directories "http://$A_HOST:8081" \
  --client-allowlist 0 \
  --allow-anon-cred 1 \
  --beta-profile 1 \
  --peer-identity-strict 0 \
  --federation-wait 0 \
  --show-admin-token 0

./scripts/easy_node.sh server-status
```

Machine A should mirror this with:
```bash
./scripts/easy_node.sh server-down || true

A_HOST=100.113.245.61
B_HOST=100.64.244.24

./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host "$A_HOST" \
  --operator-id op-a \
  --issuer-id issuer-a \
  --peer-directories "http://$B_HOST:8081" \
  --client-allowlist 0 \
  --allow-anon-cred 1 \
  --beta-profile 1 \
  --peer-identity-strict 0 \
  --federation-wait 0 \
  --show-admin-token 0

./scripts/easy_node.sh server-status
```

DS/WSL health check:
```bash
cd /mnt/c/Users/dcella-d/TDPN1

A_HOST=100.113.245.61
B_HOST=100.64.244.24

for host in "$A_HOST" "$B_HOST"; do
  echo "checking $host"
  curl -fsS --connect-timeout 5 "http://$host:8081/v1/pubkeys" >/dev/null && echo "  directory ok"
  curl -fsS --connect-timeout 5 "http://$host:8082/v1/pubkeys" >/dev/null && echo "  issuer ok"
  curl -fsS --connect-timeout 5 "http://$host:8083/v1/health" >/dev/null && echo "  entry ok"
  curl -fsS --connect-timeout 5 "http://$host:8084/v1/health" >/dev/null && echo "  exit ok"
done
```

Profile default gate command:
```bash
cd /mnt/c/Users/dcella-d/TDPN1

A_HOST=100.113.245.61
B_HOST=100.64.244.24
INVITE_KEY='inv-REDACTED'

./scripts/easy_node.sh profile-default-gate-live \
  --host-a "$A_HOST" \
  --host-b "$B_HOST" \
  --allow-remote-http-probe 1 \
  --reports-dir .easy-node-logs \
  --campaign-timeout-sec 2400 \
  --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json \
  --print-summary-json 1 \
  --campaign-subject "$INVITE_KEY"
```

Important: this profile default gate does not require running the blockchain. Blockchain live evidence is separate and should run when testing chain/VPN wiring, validator/reward/slash flows, or settlement.

### 31.13 Live bug chain from May 2026 and fixes made
The live A/B work exposed several code/runtime bugs. These were not user mistakes.

1. Docker build failed because Dockerfile used Go 1.22 while `go.mod` required Go 1.25:
```text
go: go.mod requires go >= 1.25.0 (running go 1.22.12; GOTOOLCHAIN=local)
```
Fix: update server Docker build to Go 1.25.

2. Docker build failed because `go.sum` was missing from build context:
```text
missing go.sum entry for module providing package github.com/redis/go-redis/v9
missing go.sum entry for module providing package golang.org/x/crypto/ripemd160
```
Fix: copy `go.sum` into server Docker build context.

3. Non-prod mTLS default caused missing cert:
```text
directory http tls init: stat MTLS_SERVER_CERT_FILE: lstat /app/tls/node.crt: no such file or directory
```
Fix: default non-prod compose mTLS off unless explicitly enabled.

4. Public bind/admin token guard blocked lab public bind:
```text
public bind with DIRECTORY_ADMIN_TOKEN requires MTLS_ENABLE=1 or DIRECTORY_ALLOW_DANGEROUS_INSECURE_ADMIN_PUBLIC_BIND=1
```
Fix: non-prod lab override path added while preserving production fail-closed behavior.

5. Exit startup issuer sync was blocked by outbound literal host policy:
```text
exit startup key fetch failed: Get "http://127.0.0.1:8082/v1/pubkeys": outbound literal host "127.0.0.1" is blocked by outbound dial policy
node stopped: exit startup issuer sync timeout after 30s
```
Fix: pin non-prod Docker issuer URLs to service names such as `http://issuer:8082` where appropriate.

6. Campaign endpoint preflight used `/v1/ready` but entry/exit exposed `/v1/health`:
```text
endpoint preflight failed for entry (.../v1/ready): curl rc=22: 404
```
Fix: use `/v1/health`.

7. Health probes assumed loopback even when services were published on a Tailscale/LAN IP.
Fix: respect published bind health probes.

8. `profile-default-gate-live --allow-remote-http-probe 1` allowed wrapper probes, but inner client still rejected remote HTTP/private IP control URLs.
Fix: add/forward non-prod lab allowance through the campaign stack and fail-closed in `--prod-profile 1`.

9. Campaign run count mismatch:
- Refreshed campaign defaulted to 3 runs.
- Campaign check required 5 runs.
Fix: signoff path now defaults refreshed campaign runs to check minimum.

10. Profile default gate was blocked by runtime-actuation/M4 evidence gates that belong to dedicated runtime promotion evidence.
Fix: profile default gate defaults those M4/runtime requirements off unless explicitly passed.

11. Compose interpolated `ENTRY_PUZZLE_SECRET` for client-demo even when not relevant.
Fix: non-prod placeholder/build-time env.

12. Machine A entry-exit looped because the exit WG private key on a Windows/NTFS bind mount looked too permissive:
```text
exit wg preflight failed: exit private key path permissions are too broad (expected owner-only)
```
First fix: repair owner-only permissions in exit service.
Second fix: copy key into a private Linux runtime secret under `/tmp` and point `EXIT_WG_PRIVATE_KEY_PATH` at that copy.
Third fix: support Alpine `realpath` without `-m`.

Latest known error before the final fix:
```text
entry-exit-1 | realpath: -m: No such file or directory
```
Root cause: Alpine `realpath` does not support `-m`.

### 31.14 Latest pushed commits relevant to live A/B fixes
Expected latest pushed commit at the time of this memory update:
```text
dc9e8770 Support Alpine realpath in WG key entrypoint
```

Recent pushed fix sequence:
```text
dc9e8770 Support Alpine realpath in WG key entrypoint
4e5d8dce Copy WG key to runtime secret on bind mounts
cf93169c Repair exit WG key permissions at startup
e980db58 Fix live profile gate remote HTTP path
5d9d4188 Use health endpoint for campaign preflight
7efe7c96 Respect published bind health probes
4301ad59 Fix non-prod Docker issuer control URLs
e248c1a5 Pin non-prod issuer URLs for exit
66daee4d Pin authority compose core endpoints
0689ca55 Pass non-prod lab overrides to compose
6dfba05e Allow non-prod public bind lab mode
67241b68 Fix non-prod compose mTLS default
5410cfe3 Copy go.sum into server Docker build
6726af44 Update server Docker build to Go 1.25
```

If the next VS Code Codex session needs to continue live evidence, first ensure both A and B have pulled the latest commit:
```bash
git fetch origin
git checkout codex/gpm-productization-checkpoint
git pull --ff-only origin codex/gpm-productization-checkpoint
git log -1 --oneline
```

Expected branch/commit:
```text
codex/gpm-productization-checkpoint
dc9e8770 Support Alpine realpath in WG key entrypoint
```

### 31.15 Focused tests that were run for latest fixes
Relevant focused checks reported/run during this continuation:
```bash
bash scripts/integration_entrypoint_wg_key_runtime_copy.sh
bash scripts/integration_easy_node_server_up_auto_invite.sh
go test ./pkg/crypto ./pkg/wg ./services/entry ./services/exit ./internal/app
```

Focused shell/integration checks for profile gate and remote HTTP path:
```bash
bash -n scripts/easy_node.sh scripts/profile_compare_local.sh scripts/profile_compare_campaign.sh scripts/profile_compare_campaign_signoff.sh scripts/profile_default_gate_run.sh scripts/integration_easy_node_client_profile_env.sh scripts/integration_profile_compare_local.sh scripts/integration_profile_compare_campaign.sh scripts/integration_profile_compare_campaign_signoff.sh scripts/integration_profile_default_gate_run.sh
bash scripts/integration_profile_compare_local.sh
bash scripts/integration_profile_compare_campaign.sh
bash scripts/integration_profile_compare_campaign_signoff.sh
bash scripts/integration_profile_default_gate_run.sh
bash scripts/integration_easy_node_client_profile_env.sh
go test ./pkg/crypto ./services/entry ./services/exit ./internal/app
```

### 31.16 Current artifacts/logs to inspect
Main live signoff summary:
```text
.easy-node-logs/profile_compare_campaign_signoff_summary.json
```

Campaign summary:
```text
.easy-node-logs/profile_compare_campaign_summary.json
```

Campaign check summary:
```text
.easy-node-logs/profile_compare_campaign_check_summary.json
```

Useful diagnostic fragments from this continuation:
```text
client-test --directory-urls refused insecure remote URL: http://100.113.245.61:8081
entrypoint: copied EXIT_WG_PRIVATE_KEY_PATH to owner-only runtime secret: /tmp/...
exit wg private key permissions repaired to owner-only: /app/data/exit_op-a_wg.key
exit wg preflight failed: exit private key path permissions are too broad
realpath: -m: No such file or directory
```

### 31.17 Best next step after switching to VS Code Codex
1. Revert/ignore any accidental duplicate context edits outside this chat memory file if present.
2. Confirm local branch and status:
```bash
git status --short
git branch --show-current
git log -1 --oneline
```
3. Make sure Machine A and B are on `codex/gpm-productization-checkpoint` at `dc9e8770` or newer.
4. Have the user restart A and B only after code path has been checked locally.
5. From DS/WSL, run the health loop for both hosts.
6. If all four endpoints on both hosts are healthy, run `profile-default-gate-live` with `--allow-remote-http-probe 1`.
7. If profile default gate passes, move to the next live evidence gate.
8. Do not ask the user to run blockchain yet unless testing chain/VPN wiring or settlement/validator functionality.

### 31.18 Longer-term GPM blocks still missing
- Production-grade wallet-first app flow with centered wallet modal before main app.
- Consumer-grade website redesign aligned with app visual language.
- Admin Console separated completely from public app/server app.
- Signed bootstrap manifest and signed-cache fallback.
- Keplr/Leap wallet challenge/signature/session flow.
- Client self-serve registration/profile bootstrap.
- Server/operator permissioned application, approval, and chain-binding flow.
- Production removal of manual endpoint/IP entry.
- Direct mesh preference plus managed relay fallback with user-facing state.
- Stake plus prepaid-balance enforcement before VPN use.
- Tier 2/3 micro-relay and micro-exit eligibility logic.
- Adaptive GPM Agent capacity scoring and automatic relay/exit caps.
- Weekly contribution settlement/payout, holds, voids, disputes, slashing linkage.
- Windows installer, Linux AppImage/DEB/RPM, and first-run auto-remediation.
- Compatibility alias layer for TDPN legacy commands/config keys.

### 31.19 Collaboration memory for future Codex sessions
- User is tired of live-test retry loops and wants fixes verified before being asked to try again.
- User prefers exact commands over menu/flag explanations.
- User wants direct, practical execution, not broad theory.
- User wants the app and website to feel premium, simple, safe, and consumer-friendly.
- User uses strong language when frustrated; treat it as frustration with bugs, not hostility.
- Keep momentum, but be honest about blockers.
- Use parallel agents when available, and always include a logic-check/review lane for risky work.
- When touching git, stage/commit only intentional files and avoid destructive commands.

## 32. Continuation Memory Update (2026-05-04)

### 32.1 Do not forget: provider auto-onboarding is required
The current symmetric `--peer-directories A/B` setup is only a beta/live-test workaround. The intended product shape is:

- Machine A/main authority can start and operate without preconfigured peers.
- Machine B/provider joins by connecting to A.
- B self-registers or gossips relay and issuer metadata to A.
- A learns B dynamically and publishes/syncs the relevant directory/issuer trust state.
- B learns the authority issuer/trust metadata needed to accept A-issued invites.
- Users/operators should not have to manually restart A with B as a peer after B appears.

Future implementation work should replace static manual peer wiring with provider join/self-registration and automatic directory/issuer trust refresh. Do not treat symmetric `--peer-directories` as the final GPM UX.

### 32.2 Current pushed fix and live restart requirement
Latest pushed branch head after this continuation:

```text
2210dab0 Fix beta cross-machine client wiring
```

That patch makes beta/prod `client-test` default to opaque/WireGuard transport and makes beta non-prod server env include peer issuer URLs when peer directories are provided. Both A and B need to pull/restart from this commit or newer before cross-operator live testing.

### 32.3 Current Machine A invite-generate issue
Machine A still hit:

```text
invite admin hint: local loopback issuer is not reachable because ISSUER_PUBLISHED_BIND_ADDR is pinned to 100.113.245.61.
invite-generate refused insecure remote URL: http://100.113.245.61:8082
```

This means A was started with `ISSUER_PUBLISHED_BIND_ADDR` pinned to the Tailscale IP. For non-prod HTTP lab use, bind published ports to `0.0.0.0`, not the specific Tailscale IP, so both remote tests and local loopback admin/invite commands work. The previously pushed auto-bind patch should do this automatically when A has pulled the latest branch and no explicit bind env overrides are present.
