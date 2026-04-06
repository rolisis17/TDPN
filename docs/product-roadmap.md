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

Status update (March 24, 2026):
- `speed-1hop` is now available in `client-test` as an explicit non-strict experimental mode (`--path-profile speed-1hop`), with guardrails that fail closed in strict/beta/prod flows.
- `profile-compare-local` is now available (`./scripts/easy_node.sh profile-compare-local ...`) to run repeatable single-machine profile comparisons with JSON/markdown artifacts and a policy-based default recommendation (never auto-defaulting `speed-1hop`).
- `profile-compare-trend` is now available (`./scripts/easy_node.sh profile-compare-trend ...`) to aggregate multiple local comparison summaries into one reliability/latency trend recommendation (still keeping `speed-1hop` non-default).
- `profile-compare-campaign` is now available (`./scripts/easy_node.sh profile-compare-campaign ...`) to run repeatable multi-run local comparison campaigns and auto-produce a campaign-level trend recommendation bundle.
- `profile-compare-campaign-check` is now available (`./scripts/easy_node.sh profile-compare-campaign-check ...`) to enforce fail-closed policy thresholds on campaign artifacts and output a GO/NO-GO default-profile decision.
- `profile-compare-campaign-signoff` is now available (`./scripts/easy_node.sh profile-compare-campaign-signoff ...`) to run optional campaign refresh + fail-closed check in one command and emit one signoff summary artifact for default-profile handoff decisions.
- `single-machine-prod-readiness` now optionally includes that campaign signoff gate (`--run-profile-compare-campaign-signoff auto|0|1`) so one-host operators can track local default-profile decision readiness alongside runtime/manual-validation gates.
- in `single-machine-prod-readiness`, profile signoff `auto` mode now forces a one-time campaign refresh when campaign artifacts are missing, so local roadmap progress does not stall on absent seed artifacts.
- in `single-machine-prod-readiness`, profile signoff `auto` mode now prefers docker rehearsal endpoints (when available) to run that missing-artifact refresh without root; if docker rehearsal endpoints are unavailable, non-root mode still skips instead of failing the whole sweep.
- manual-validation status/report now also surface a non-blocking profile-default gate snapshot (`profile-compare-campaign-signoff` summary status/decision) so default-profile decision readiness is visible in the same operator handoff.
- manual-validation status/report now classify a `profile-compare-campaign-signoff` campaign-refresh failure as `pending` (not hard-fail) when the refresh is blocked only because local stack bootstrap needs root (`--start-local-stack=1 requires root`), and they emit a sudo-ready next command for that rerun path.
- `single-machine-prod-readiness` now forwards the manual-validation profile-default gate snapshot (`summary.profile_default_gate`, `summary.profile_default_ready`) so one-host sweeps and manual-validation reports show the same default-profile readiness signal.
- `single-machine-prod-readiness` now also forwards its effective `--profile-compare-campaign-signoff-summary-json` path into `manual-validation-report`, so profile-default gate evaluation stays consistent even when operators use non-default artifact paths.
- `single-machine-prod-readiness` now prints `next_action_check_id` and `next_action_command` in stdout, so machine-C/3-machine next steps are explicit without opening JSON artifacts.
- `single-machine-prod-readiness` now optionally runs the dockerized one-host 3-machine rehearsal gate (`--run-three-machine-docker-readiness auto|0|1`) and includes that rehearsal result in its summary JSON/output.
- `single-machine-prod-readiness` now optionally runs Linux root real-WG matrix recording (`--run-real-wg-privileged-matrix auto|0|1`) and classifies that step as an optional non-blocking confidence gate in one-host readiness output.
- easy-node help/forwarding for `manual-validation-status` and `manual-validation-report` now explicitly includes `--profile-compare-signoff-summary-json` and overlay options, with wiring/integration checks to keep that operator contract stable.
- easy launcher advanced menu now includes a dedicated `single-machine-prod-readiness` path (option 75), so one-host production sweeps are available without manual command assembly.
- `vpn-rc-standard-path` is now available as one locked VPN RC operator path (`single-machine-prod-readiness` strict defaults + `roadmap-progress-report` refresh), and easy launcher advanced menu now includes that same flow as option 76.
- profile contract guard is now wired in local gates (`integration_path_profile_contract.sh` in `ci_local` / `beta_preflight`) to keep public profile UX/API naming fixed at `speed|balanced|private` (`speed-1hop` experimental on `client-test` only), while retaining `fast|privacy` as compatibility aliases.
- launcher profile/expert split is now enforced as a contract: simple client flows stay preset-driven, while explicit policy overrides are isolated to advanced option 34 (`Client VPN up (real mode, expert/manual)`), with wiring/runtime coverage to prevent regressions.
- `three-machine-docker-readiness` is now available (`./scripts/easy_node.sh three-machine-docker-readiness ...`) to spin up two independent dockerized operator stacks on one host and run machine-C style validate/soak control-plane rehearsal checks while real multi-host signoff stays pending.
- `three-machine-docker-readiness-record` is now available (`./scripts/easy_node.sh three-machine-docker-readiness-record ...`) to wrap that rehearsal in one recorded manual-validation receipt and keep a durable summary/log artifact.
- `real-wg-privileged-matrix-record` is now available (`sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record ...`) to wrap Linux root real-WG matrix validation into one recorded manual-validation receipt, surfaced as a non-blocking optional gate in the readiness handoff.

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

Bootstrap policy (when this track starts):
- use a small-network manual governance phase first (allow/deny validator candidacy, emergency ban, manual adjudication with audit trail)
- keep validator role server-side only; clients remain non-validating participants
- keep VPN dataplane independent from blockchain liveness (grace mode + deferred settlement path)
- transition to automated validator selection only after operator/diversity/safety thresholds are met

Planned design guide:
- `docs/blockchain-bootstrap-validator-plan.md` (manual bootstrap model, validator eligibility formula skeleton, epoch selection policy, and graduation criteria)

L1 decision gate:
- only start own-L1 build when the explicit 12-week go/no-go metrics gate in `docs/blockchain-bootstrap-validator-plan.md` is fully green
- until then, keep blockchain functions in chain-assisted mode and keep VPN dataplane independent

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
