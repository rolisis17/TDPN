# Product Roadmap (VPN First)

This roadmap keeps the focus on a production-grade decentralized VPN before adding staking/payment/blockchain layers.

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
