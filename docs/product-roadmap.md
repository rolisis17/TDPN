# Product Roadmap (VPN First)

This roadmap keeps the focus on a production-grade decentralized VPN before adding staking/payment/blockchain layers.

## Decision Log (March 17, 2026)

We agreed to simplify the operator and user experience while keeping strong test coverage:
- move from "many user-facing flags" to a profile-first interface (`Speed`, `Balanced`, `Private`)
- keep advanced flags available behind an explicit expert/diagnostics path, not in the default flow
- keep `Balanced` as default for public guidance
- keep 2-hop as the default architecture for privacy baseline
- add a latency-tuned `Speed` profile first on top of the current 2-hop path
- treat true 1-hop mode as an explicit lower-privacy option and ship it as experimental before any default consideration
- choose long-term defaults based on measured latency/reliability/privacy tradeoff data, not assumptions

Next 5 roadmap execution steps:
1. Freeze a minimal public CLI/UI contract around profiles.
2. Route advanced policy switches into internal defaults and expert mode.
3. Ship and benchmark `Speed` (2-hop latency-tuned).
4. Implement experimental `speed-1hop` with clear safety/privacy labeling.
5. Run comparative pilot metrics and decide default behavior from results.

Strictly necessary vs optional (current project posture):
- strictly necessary for daily operation: start server, connect client, preflight checks, status/down, invite generation on authority, and one repeatable automated signoff path
- optional/expert (keep but do not make default): deep chaos/fault matrices, policy override flags, manual artifact-level campaign checks, and one-off diagnostics toggles
- policy for UI and scripts: if a setting is rarely changed in healthy operation, it should be auto-defaulted and moved behind expert/custom mode

## Phase 1: Stable Linux Beta (Current Priority)

Goal: reliable real-user beta on Linux servers + Linux clients.

Scope:
- strict control-plane and real-WireGuard validation gate (`three-machine-prod-gate`)
- fail-closed diagnostics/signoff bundle path (`three-machine-prod-bundle`, `prod-gate-signoff`)
- invite lifecycle + authority/provider role separation
- anti-collusion pair controls (distinct operators, optional distinct countries)
- locality-aware selection (hard locality + optional soft locality bias)
- federation observability + startup gating (`server-federation-status`, `server-federation-wait`, `server-up --federation-wait 1`)

Exit criteria:
- repeated 3-machine prod-gate runs pass under normal and fault-injected conditions
- clear operator runbook and incident/debug flow
- no high-severity known regressions in CI/beta preflight suite
- peer churn/restarts no longer require manual guesswork: operators can verify and wait for federation readiness with explicit pass/fail outputs

## Phase 2: VPN v1 Production

Goal: operationally safe public rollout for VPN use.

Scope:
- complete production runbooks for upgrade/rollback/key rotation
- alerting + SLO dashboards for directory/entry/exit/issuer health
- hardened abuse controls and adjudication policy defaults
- release hygiene and reproducible artifact verification in every release

Exit criteria:
- production pilot cohort runs for sustained period without critical incidents
- failure classes and recovery SLOs are measured and enforced
- operator onboarding/offboarding process is documented and repeatable

## Phase 3: Cross-Platform Clients (After Linux Beta Stability)

Goal: broaden client adoption while keeping server side stable.

Scope:
- Windows client beta
- macOS client beta
- preserve Linux authority/provider stack as primary operational baseline

Exit criteria:
- same connect/disconnect/status UX contract across Linux/Windows/macOS
- platform-specific diagnostics and support playbooks are in place

## Deferred Track: Staking/Payment/Blockchain

Decision: defer until VPN production flow is stable.

When to start:
- Linux production metrics are stable
- abuse/reputation governance is operating as expected
- protocol interfaces needed by settlement layer are clear and stable

## True 3-Machine Validation Reminder (Before Wider Beta)

Run from machine C (client host), with A and B as independent operators:

1. `sudo ./scripts/easy_node.sh three-machine-prod-gate ... --strict-distinct 1`
2. `sudo ./scripts/easy_node.sh three-machine-prod-bundle ... --signoff-check 1`
3. `./scripts/easy_node.sh prod-gate-signoff --run-report-json <bundle_dir>/prod_bundle_run_report.json`
4. Optional controlled fault rounds (`--control-fault-every/--control-fault-command`, `--wg-fault-every/--wg-fault-command`)

Recommended hardening toggles for client tests:
- `CLIENT_REQUIRE_DISTINCT_OPERATORS=1`
- `CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY=1` (if country metadata quality is good)
- `CLIENT_EXIT_LOCALITY_SOFT_BIAS=1` with tuned locality bias values when you want country preference without hard lock-in.

Deferred manual checks are tracked in:
- `docs/manual-validation-backlog.md`
- `./scripts/easy_node.sh manual-validation-backlog`
- `./scripts/easy_node.sh manual-validation-status --show-json 1`
