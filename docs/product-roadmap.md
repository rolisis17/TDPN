# Product Roadmap (VPN First)

This roadmap keeps the focus on a production-grade decentralized VPN while building Cosmos-first payment/governance foundations in parallel.

Canonical source of truth for cross-track sequencing:
- `docs/full-execution-plan-2026-2027.md` is authoritative.
- this roadmap and automation recommendations must remain aligned with that file.

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
- simple launcher defaults are now sourced from a versioned config contract (`deploy/config/easy_mode_config_v1.conf`) with command support in `easy_node.sh` (`config-v1-show`, `config-v1-init`, `config-v1-set-profile`).
- `client-vpn-status` now supports machine-readable output (`--show-json [0|1]`) for desktop/automation integration.
- daemon role `--local-api` is now available with local control endpoints (`connect`, `disconnect`, `status`, `set_profile`, `get_diagnostics`, `update`) to support Windows desktop app integration.
- local API profile defaults are now aligned to config v1 through shared profile contract usage: `/v1/set_profile` persists via `config-v1-set-profile`, and daemon runs started with `--config deploy/config/easy_mode_config_v1.conf` read the same profile defaults as launcher flows.
- `easy_node.sh` now provides a dedicated local API launcher (`local-api-session`) that applies config-v1 defaults for connect behavior and supports explicit override flags for desktop/operator diagnostics.
- chain-agnostic settlement service interfaces are now scaffolded in `pkg/settlement` with an in-memory implementation for early accounting/reconciliation integration.
- `speed-1hop` is now available in `client-test` and `client-vpn-up` as an explicit non-strict experimental mode (`--path-profile speed-1hop`), with guardrails that fail closed in strict/beta/prod flows.
- `profile-compare-local` is now available (`./scripts/easy_node.sh profile-compare-local ...`) to run repeatable single-machine profile comparisons with JSON/markdown artifacts and a policy-based default recommendation (never auto-defaulting `speed-1hop`).
- `profile-compare-trend` is now available (`./scripts/easy_node.sh profile-compare-trend ...`) to aggregate multiple local comparison summaries into one reliability/latency trend recommendation (still keeping `speed-1hop` non-default).
- `client-vpn-profile-compare` is now available (`./scripts/easy_node.sh client-vpn-profile-compare ...`) to run repeatable real host `client-vpn-smoke` rounds across `1hop/2hop/3hop` and emit one default/latency/privacy recommendation bundle while keeping `1hop` experimental non-default.
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
- easy launcher advanced menu now also includes a dedicated Docker profile matrix signoff path (option 77), which wraps `profile-compare-campaign-signoff` in docker campaign mode for one-command refresh + fail-closed default-profile gating.
- coverage status for that wrapper path: docker campaign-signoff behavior is integration-tested (`integration_profile_compare_campaign_signoff.sh`), and launcher signoff forwarding remains contract-tested (`integration_easy_mode_launcher_wiring.sh`, `integration_easy_mode_launcher_runtime.sh`).
- `profile-compare-docker-matrix` is now available in `easy_node.sh` as a docker-first campaign wrapper for `1hop/2hop/3hop` profile comparisons, with one-command summary/report artifact output.
- wrapper dispatch/forwarding coverage for that command is now integration-tested (`integration_profile_compare_docker_matrix.sh`) in `ci_local` and `beta_preflight`.
- `vpn-rc-matrix-path` is now the one-command RC matrix chain path for profile-campaign refresh/check handoff, with gate coverage wired into `ci_local` and `beta_preflight` via `integration_vpn_rc_matrix_path.sh`.
- `vpn-rc-resilience-path` is now the phase-1 resilience chain path in `easy_node.sh`, with gate coverage wired into `ci_local` and `beta_preflight` via `integration_vpn_rc_resilience_path.sh`.
- profile contract guard is now wired in local gates (`integration_path_profile_contract.sh` in `ci_local` / `beta_preflight`) to keep public profile UX/API naming fixed at `1hop|2hop|3hop` with compatibility aliases `speed|balanced|private` (`speed-1hop` explicit experimental alias on non-strict `client-test`/`client-vpn-up`), while retaining `fast|privacy` as legacy compatibility aliases.
- launcher profile/expert split is now enforced as a contract: simple client flows stay preset-driven, while explicit policy overrides are isolated to advanced option 34 (`Client VPN up (real mode, expert/manual)`), with wiring/runtime coverage to prevent regressions.
- simple launcher prompts are now further reduced: main-menu client/server no longer ask inline “expert override” questions, and provider simple mode auto-derives authority directory/issuer URLs from configured peer hosts; advanced overrides remain in Other options.
- simple launcher server path now waits for federation readiness by default (`SIMPLE_SERVER_FEDERATION_WAIT=1` -> `server-session --federation-wait 1`), with diagnostics override via config `SIMPLE_SERVER_FEDERATION_WAIT=0` or expert `server-session --federation-wait 0`.
- `client-vpn-preflight` is now profile-aware for real routing checks: it accepts `--path-profile` directly and auto-enables middle-relay diversity checks for `3hop` (`--middle-relay-check`, `--middle-relay-min-operators`, `--middle-relay-require-distinct`) with staged-lab override knobs.
- launcher runtime wiring now forwards `--path-profile` into preflight paths (simple real-VPN flow and advanced option 31), with integration coverage to keep that contract stable.
- simple-mode prompt budget is now contract-tested in integration gates: launcher wiring/runtime checks enforce the `<=6` prompt budget for client/server simple flows.
- runtime `3hop` behavior is now strict-by-default in client selection: middle relay is required unless explicitly overridden with `CLIENT_REQUIRE_MIDDLE_RELAY=0`, and unit/integration coverage now exercises fail/override/pass middle-relay scenarios.
- path-open contract now carries `middle_relay_id` end-to-end (`client -> entry -> exit`) and includes it in token-proof signing/verification; entry now rejects invalid middle-hop requests early (`middle-relay-equals-exit`, `unknown-middle-relay`, `middle-relay-role-invalid`, operator-collision reasons) with added unit coverage.
- session lifecycle defaults are now explicit and stable in real VPN flows: `client-vpn-up` exports `CLIENT_SESSION_REUSE=1` and `CLIENT_SESSION_REFRESH_LEAD_SEC=20` by default (overrideable), and client runtime defaults to reuse-on when `CLIENT_SESSION_REUSE` is unset while preserving explicit disable (`0`) semantics.
- client session churn guard now includes `CLIENT_SESSION_MIN_REFRESH_SEC` to enforce a minimum refresh interval floor during repeated control-plane retries.
- in `1hop` direct-exit with churn protection on (default), the client applies that minimum refresh floor by default to prevent rapid reopen/close loops; diagnostics override is `CLIENT_SESSION_MIN_REFRESH_SEC=0` or (when churn behavior is needed) `CLIENT_DIRECT_EXIT_ALLOW_SESSION_CHURN=1`.
- `three-machine-docker-readiness` is now available (`./scripts/easy_node.sh three-machine-docker-readiness ...`) to spin up two independent dockerized operator stacks on one host and run machine-C style validate/soak control-plane rehearsal checks while real multi-host signoff stays pending.
- `three-machine-docker-readiness` now also supports an optional peer failover rehearsal (`--run-peer-failover 1`) that temporarily stops and restarts one stack directory and verifies sync-status failure/recovery plus relay serving continuity from the surviving stack.
- `three-machine-docker-profile-matrix` is now the phase-1 resilience profile-matrix rehearsal path (`./scripts/easy_node.sh three-machine-docker-profile-matrix ...`) for one-command `1hop/2hop/3hop` docker comparison runs before real multi-host signoff.
- coverage for that profile-matrix flow is now wired into `ci_local` and `beta_preflight` through `integration_three_machine_docker_profile_matrix.sh`.
- `three-machine-docker-profile-matrix-record` is now available (`./scripts/easy_node.sh three-machine-docker-profile-matrix-record ...`) to wrap that phase-1 resilience matrix rehearsal in one recorded manual-validation receipt with durable summary/log artifacts.
- coverage for that matrix-record flow is now wired into `ci_local` and `beta_preflight` through `integration_three_machine_docker_profile_matrix_record.sh`.
- `ci_phase0.sh` is now the fast Phase-0 product-surface gate runner for launcher wiring/runtime, simple prompt-budget contract (`<=6` prompts), config-v1 contract, and local control API contract; use it for quick contract checks before full `ci_local`/preflight runs.
- `ci_phase1_resilience.sh` is now the focused Phase-1 resilience gate runner for profile-matrix and RC resilience wrappers (`three_machine_docker_profile_matrix`, `profile_compare_docker_matrix`, `three_machine_docker_profile_matrix_record`, `vpn_rc_matrix_path`, `vpn_rc_resilience_path`), with one machine-readable summary artifact at `.easy-node-logs/ci_phase1_resilience_<stamp>/ci_phase1_resilience_summary.json`.
- `integration_session_churn_guard.sh` now adds deterministic client session churn guard coverage (default direct-exit churn suppression vs explicit churn override) so session lifecycle defaults stay stable while retaining an intentional diagnostics override path.
- `single-machine-prod-readiness` now defaults Docker rehearsal to include peer-failover (`--three-machine-docker-readiness-run-peer-failover 1`) so churn recovery is exercised in the standard readiness path (override with `0` when needed for diagnostics).
- `vpn-rc-standard-path` now inherits that same peer-failover default through `single-machine-prod-readiness`; diagnostics can disable failover rehearsal in direct one-host runs with `--three-machine-docker-readiness-run-peer-failover 0` (or low-level `three-machine-docker-readiness --run-peer-failover 0`).
- config-v1 coverage now includes a dedicated integration gate (`integration_easy_node_config_v1.sh`) in `ci_local` and `beta_preflight`, validating `config-v1-init`, `config-v1-show`, `config-v1-set-profile`, and server federation-wait default keys.
- local API coverage now includes dedicated integration gates in `ci_local` and `beta_preflight`:
  - `integration_local_api_config_defaults.sh` validates config-v1 driven local API connect defaults end-to-end.
  - `integration_local_control_api_contract.sh` validates local API endpoint-to-command forwarding contracts.
- desktop scaffold coverage now includes `integration_desktop_scaffold_contract.sh` in `ci_local` and `beta_preflight`, validating file/JSON contract and JS↔Rust `control_*` command alignment.
- `three-machine-docker-readiness-record` is now available (`./scripts/easy_node.sh three-machine-docker-readiness-record ...`) to wrap that rehearsal in one recorded manual-validation receipt and keep a durable summary/log artifact.
- `real-wg-privileged-matrix-record` is now available (`sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record ...`) to wrap Linux root real-WG matrix validation into one recorded manual-validation receipt, surfaced as a non-blocking optional gate in the readiness handoff.
- planning track docs for a future "Global Privacy Mesh" architecture are now added:
  - `docs/global-privacy-mesh-track.md`
  - `docs/exit-node-safety-baseline-v1.md`
  - `docs/exit-node-safety-guide.md`
  - `docs/client-safety-guide.md`
  These establish micro-relay and 1-hop/2-hop/3-hop direction, while keeping current production work on the stable 2-hop path.

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

## Parallel Architecture Track: Global Privacy Mesh (Planning + Incremental Build)

Goal: evolve from fixed 2-hop topology toward an optional micro-relay mesh model,
without regressing current production-grade VPN stability work.

Scope (current):
- define role model for `client`, `micro-relay`, `exit`, and `validator`
- define explicit user-facing hop modes (`1-hop`, `2-hop`, `3-hop`) with clear tradeoff labeling
- define safe rotation policy for relay/exit selection (bounded stickiness + jitter)
- define operator and client safety baselines for broader participation

Guardrails:
- keep blockchain/validator logic out of packet forwarding critical path
- keep 2-hop balanced mode as stable default until comparative metrics justify changes
- keep exit role hardened and specialized; micro-relay rollout should not imply default exit participation

Track docs:
- `docs/global-privacy-mesh-track.md`
- `docs/exit-node-safety-baseline-v1.md`
- `docs/exit-node-safety-guide.md`
- `docs/client-safety-guide.md`

Exit criteria for this track to affect default behavior:
- multi-run comparative evidence for latency/reliability/privacy across hop profiles
- abuse handling quality unchanged or improved under micro-relay participation
- no regression in production-grade VPN RC checks

## Phase 3: Cross-Platform Clients (After Linux Beta Stability)

Goal: broaden client adoption while keeping server side stable.

Scope:
- Windows client beta
- macOS client beta
- preserve Linux authority/provider stack as primary operational baseline

Exit criteria:
- same connect/disconnect/status UX contract across Linux/Windows/macOS
- platform-specific diagnostics and support playbooks are in place

## Parallel Track: Cosmos L1 Settlement and Governance Foundation

Decision:
- build Cosmos-first chain compatibility now (no sidecar chain pivot), while VPN production hardening continues.
- keep VPN dataplane independent from chain liveness and finality at all times.

Current implementation posture:
- app-side settlement bridge remains `pkg/settlement` with graceful deferred writes.
- chain adapter mode is optional and fail-soft (`memory` default, `cosmos` optional).
- sponsor flow is staged through issuer sponsor APIs (`/v1/sponsor/quote|reserve|token|status`) plus payment-proof token issuance.
- `tdpnd` runtime now supports `--state-dir` to switch chain module keepers from in-memory defaults to file-backed stores rooted at one state directory.
- chain scaffold/module ordering now includes `vpnbilling`, `vpnrewards`, `vpnslashing`, `vpnsponsor`, `vpnvalidator`, and `vpngovernance`.
- state-dir persistence now materializes validator/governance module state files (`vpnvalidator.json`, `vpngovernance.json`) alongside existing module stores.
- gRPC runtime registration now includes validator/governance service namespaces (`tdpn.vpnvalidator.v1.{Msg,Query}` and `tdpn.vpngovernance.v1.{Msg,Query}`).
- `scripts/integration_cosmos_grpc_app_roundtrip.sh` now explicitly covers validator/governance Msg+Query roundtrip contracts in addition to billing/sponsor coverage.
- `vpngovernance` now persists append-only governance admin audit actions (`action_id`, `action`, `actor`, `reason`, `evidence_pointer`, `timestamp_unix`) with replay-safe idempotency and conflict-on-divergence handling.
- `vpnvalidator` now includes deterministic epoch selection helpers for bootstrap policy enforcement (hard gates, warmup/cooldown, stable+rotating seats, and operator/ASN/region caps).
- `vpngovernance` gRPC contracts now include audit-action RPC/query surfaces (`RecordAuditAction`, `GovernanceAuditAction`, `ListGovernanceAuditActions`) for bootstrap governance audit trails.
- `vpnvalidator` gRPC contracts now include `PreviewEpochSelection` query for deterministic epoch-selection previews from policy + candidate inputs.
- settlement bridge now exposes module query `GET` endpoints (list + by-id) and module write `POST` endpoints across billing/rewards/sponsor/slashing plus validator/governance routes; bearer auth applies to `POST` only when bridge auth is configured.
- Cosmos CI/local block now includes `scripts/integration_cosmos_tdpnd_state_dir_persistence.sh` to verify state-dir wiring and persistence across reopen.
- phase5 settlement CI now includes these blockchain gate stages and scripts:
  - `settlement_adapter_roundtrip` -> `scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh`
  - `settlement_adapter_signed_tx_roundtrip` -> `scripts/integration_cosmos_adapter_tdpnd_signed_tx_roundtrip.sh`
  - `settlement_shadow_env` -> `scripts/integration_cosmos_settlement_shadow_env.sh`
  - `settlement_shadow_status_surface` -> `scripts/integration_cosmos_settlement_shadow_status_surface.sh`
  - `issuer_sponsor_api_live_smoke` -> `scripts/integration_issuer_sponsor_api_live_smoke.sh` (validates sponsor `quote -> reserve -> token -> status` happy path with no end-user wallet signing)
- phase5 settlement CI/check/run/handoff wrappers now emit canonical summary artifacts under `.easy-node-logs`; these are the helper input contracts for `scripts/phase5_settlement_layer_summary_report.sh`:
  - `phase5_settlement_layer_ci_summary.json`
  - `phase5_settlement_layer_check_summary.json`
  - `phase5_settlement_layer_run_summary.json`
  - `phase5_settlement_layer_handoff_check_summary.json`
  - `phase5_settlement_layer_handoff_run_summary.json`
- phase5 operator summary helper `scripts/phase5_settlement_layer_summary_report.sh` aggregates CI/check/run/handoff summaries into compact operator output plus normalized JSON, with integration contract coverage from `scripts/integration_phase5_settlement_layer_summary_report.sh`.
- phase5 run/handoff wrappers and aggregate report propagate sponsor live-smoke posture for downstream gates/reports via `signals.issuer_sponsor_api_live_smoke_*` and consolidated `signals.issuer_sponsor_api_live_smoke`.
- phase5 summary helper fallback discovery includes timestamped CI and handoff-run summary directories when canonical/default summary files are absent.
- phase6 Cosmos L1 build/testnet CI scaffold now runs via `scripts/ci_phase6_cosmos_l1_build_testnet.sh` with contract checks in `scripts/integration_ci_phase6_cosmos_l1_build_testnet.sh`.
- phase6 build/testnet CI includes `local_testnet_smoke` wired to `scripts/integration_cosmos_local_testnet_smoke.sh` for deterministic local multi-node `tdpnd` lifecycle coverage (`init -> start -> status -> stop -> status`).
- phase6 gRPC runtime smoke now includes validator/governance real-scaffold roundtrip coverage, reflected core-module query-service checks, auth-query parity, and deterministic `PreviewEpochSelection` query checks.
- phase6 gRPC live smoke now validates reflected module-service parity plus live billing/sponsor/validator/governance query dispatch via grpcurl.
- phase6 build/testnet CI now includes `tdpnd_grpc_auth_live_smoke` wired to `scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh` for auth-token gRPC live-smoke coverage across billing/sponsor/validator/governance query RPCs.
- phase6 Cosmos L1 contracts CI gate now runs via `scripts/ci_phase6_cosmos_l1_contracts.sh` with contract checks in `scripts/integration_ci_phase6_cosmos_l1_contracts.sh` for wrapper wiring plus first-failure RC propagation with full-stage accounting (non-short-circuit stage execution), and live-smoke coverage in `scripts/integration_phase6_cosmos_l1_contracts_live_smoke.sh`.
- phase6 Cosmos L1 contracts posture now includes both `cosmos_module_coverage_floor` (`scripts/integration_cosmos_module_coverage_floor.sh`) and `cosmos_keeper_coverage_floor` (`scripts/integration_cosmos_keeper_coverage_floor.sh`) before wrapper handoff/run stages, with six-target floor enforcement across billing/rewards/slashing/sponsor/validator/governance module and keeper packages.
- phase6 Cosmos L1 contracts posture now includes `phase6_cosmos_dual_write_parity` wired to `scripts/integration_cosmos_dual_write_parity.sh` before wrapper handoff/run stages.
- phase6 canonical top-level suite wrapper is `scripts/phase6_cosmos_l1_build_testnet_suite.sh` with contract checks in `scripts/integration_phase6_cosmos_l1_build_testnet_suite.sh`.
- phase6 readiness wrappers are available as `scripts/phase6_cosmos_l1_build_testnet_check.sh` and `scripts/phase6_cosmos_l1_build_testnet_run.sh` (integration-covered).
- phase6 handoff wrappers are available as `scripts/phase6_cosmos_l1_build_testnet_handoff_check.sh` and `scripts/phase6_cosmos_l1_build_testnet_handoff_run.sh` (integration-covered).
- phase6 readiness/handoff checker surfaces include `tdpnd_grpc_auth_live_smoke_ok` in addition to existing `tdpnd_grpc_runtime_smoke_ok` and `tdpnd_grpc_live_smoke_ok` signals.
- phase6 run/handoff-run dry-run relaxation also covers `tdpnd_grpc_auth_live_smoke_ok` by default unless explicitly required by wrapper inputs.
- phase6 operator summary helper `scripts/phase6_cosmos_l1_summary_report.sh` aggregates CI/contracts/suite summary artifacts into compact operator lines plus normalized JSON output, with integration coverage from `scripts/integration_phase6_cosmos_l1_summary_report.sh`.
- phase6 build/testnet/contracts/check/run/handoff/suite wrappers now emit canonical summary artifacts under `.easy-node-logs/phase6_cosmos_l1_*_summary.json` in addition to per-run reports.
- phase6 summary helper fallback discovery now includes CI/contracts/suite timestamped summary directories when canonical/default summary files are absent.
- settlement bridge live process smoke now validates auth enforcement, write acceptance, and billing/rewards/sponsor/slashing/validator/governance GET by-id plus list query behavior in auth-enabled runtime mode.
- easy-node exposes blockchain summary wrappers:
  - `./scripts/easy_node.sh phase5-settlement-layer-summary-report`
  - `./scripts/easy_node.sh phase6-cosmos-l1-summary-report`

Governance posture (hybrid bootstrap):
- objective machine-verifiable events can be enforced on-chain.
- subjective abuse and disputed cases stay policy-governed with human/multisig controls during bootstrap.
- validator role remains server-side only and resource-isolated from VPN forwarding.

Design guides:
- `docs/full-execution-plan-2026-2027.md` (canonical sequencing)
- `docs/blockchain-bootstrap-validator-plan.md` (validator bootstrap and graduation criteria)
- `docs/cosmos-settlement-runtime.md` (issuer/exit runtime wiring, reconcile loops, and Cosmos adapter env contract)
- `blockchain/tdpn-chain/` (Cosmos module workspace scaffold)

L1 gate and safety:
- continue to use the explicit 12-week go/no-go metrics in `docs/blockchain-bootstrap-validator-plan.md`.
- if any gate is missed, keep chain control-plane in assistive mode and preserve VPN grace semantics.

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
