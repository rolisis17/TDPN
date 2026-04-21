# Product Roadmap (VPN First)

This roadmap keeps the focus on a production-grade decentralized VPN while building Cosmos-first payment/governance foundations in parallel.

Canonical source of truth for cross-track sequencing:
- `docs/full-execution-plan-2026-2027.md` is authoritative.
- this roadmap and automation recommendations must remain aligned with that file.

## Decision Log (March 17, 2026)

We agreed to simplify the operator and user experience while keeping strong test coverage:
- move from "many user-facing flags" to a minimal profile-first simple mode (`Speed`, `Balanced`, `Private`)
- keep advanced flags available behind an explicit expert/diagnostics path, not in the default simple flow
- keep `Balanced` as default for public guidance
- keep 2-hop as the default architecture for privacy baseline
- add a latency-tuned `Speed` profile first on top of the current 2-hop path
- treat true 1-hop mode as an explicit lower-privacy option and ship it as experimental before any default consideration
- choose long-term defaults based on measured latency/reliability/privacy tradeoff data, not assumptions

Next 5 roadmap execution steps:
1. Freeze a minimal public CLI/UI contract around profiles.
2. Route advanced policy switches into internal defaults and expert-only help, not the simple path.
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
- simple launcher prompts are now further reduced: main-menu client/server no longer ask inline "expert override" questions, and provider simple mode auto-derives authority directory/issuer URLs from configured peer hosts; advanced overrides remain in Other options.
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
- desktop scaffold coverage now includes `integration_desktop_scaffold_contract.sh` in `ci_local` and `beta_preflight`, validating file/JSON contract and JS-Rust `control_*` command alignment.
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
- policy for UI and scripts: if a setting is rarely changed in healthy operation, it should be auto-defaulted, kept out of simple mode, and labeled as expert/custom

Operator hardening snapshot (April 16, 2026, non-blockchain):
- `pre-real-host-readiness` now supports explicit `--defer-no-root [0|1]` (default `0`, fail-closed by default).
- `client-vpn-smoke` and `three-machine-prod-signoff` now pass their `--defer-no-root` setting through to `pre-real-host-readiness`, so defer behavior is consistent end-to-end.
- `prod-pilot-runbook` now defaults pre-readiness defer to on for non-root operators (`auto` mode), and only continues after a pre-readiness failure when the failure is clearly root-only deferred; all other pre-readiness failures still block the runbook.
- `prod-pilot-cohort-runbook` continues to use the same defer semantics at the top-level readiness gate before rounds begin.
- manual readiness interpretation remains staged: it is expected to see `manual_validation_report.readiness_status=NOT_READY` while machine-C and true 3-machine external gates are still pending.

What this means for operators:
- if you are running as non-root and see a warning about root-only deferred pre-readiness, the pilot/cohort wrapper can proceed for diagnostics collection, but you should not treat that run as final production signoff.
- next command after a root-only deferred warning is:
  - `sudo ./scripts/easy_node.sh pre-real-host-readiness --strict-beta 1 --print-summary-json 1`
- then rerun your pilot wrapper as root for final signoff evidence.

Completed in this slice:
- server preflight/session diagnostics now surface provider/authority endpoint posture and mismatch signals (including HTTPS-vs-HTTP and peer/authority set mismatch) across simple and expert operator paths.

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
- `docs/gpm-productization-status.md`
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
- `scripts/integration_cosmos_grpc_app_roundtrip.sh` now explicitly covers billing/rewards/slashing/sponsor/validator/governance Msg+Query roundtrip contracts, including validator/governance canonical write + mixed-case lookup coverage.
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
  - `settlement_dual_asset_parity` -> `scripts/integration_cosmos_settlement_dual_asset_parity.sh`
  - `issuer_sponsor_api_live_smoke` -> `scripts/integration_issuer_sponsor_api_live_smoke.sh` (validates sponsor `quote -> reserve -> token -> status` happy path with no end-user wallet signing)
  - `issuer_sponsor_vpn_session_live_smoke` -> `scripts/integration_issuer_sponsor_vpn_session_live_smoke.sh` (validates sponsor flow through VPN path open/close with no end-user wallet signing in happy path)
  - `issuer_settlement_status_live_smoke` -> `scripts/integration_issuer_settlement_status_live_smoke.sh` (validates settlement outage recovery in both `http` and `signed-tx` submit modes via `/v1/settlement/status` as `backlog -> ok` after Cosmos endpoint recovery while issuer APIs remain available, with explicit stale-state contract coverage `last_error implies stale=true` and recovery `stale=false`)
  - `issuer_settlement_status_live_smoke` also validates sponsor token issuance/payment-proof happy path remains available during chain outage/backlog and through recovery, with deferred-write fail-soft behavior while settlement status transitions stale/backlog -> recovery.
  - `exit_settlement_status_live_smoke` -> `scripts/integration_exit_settlement_status_live_smoke.sh` (wired through `scripts/integration_cosmos_settlement_acceptance_paths.sh`; validates settlement outage recovery in both `http` and `signed-tx` submit modes via exit `/v1/settlement/status` as `backlog -> ok` after Cosmos endpoint recovery while exit APIs remain available, with explicit stale-state contract coverage `last_error implies stale=true` and recovery `stale=false`)
  - Slash-evidence live-smoke coverage now validates objective `violation_type` allowlist enforcement and required-field rejection in both bridge (`/x/vpnslashing/evidence`, `scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh`) and issuer runtime (`/v1/admin/slash/evidence`, `scripts/integration_issuer_settlement_status_live_smoke.sh`) paths.
  - blockchain fastlane now includes `scripts/integration_slash_violation_type_contract_consistency.sh` as a core contract-check stage, enforcing objective `violation_type` allowlist parity between settlement core and `tdpnd` bridge to prevent contract drift.
  - blockchain fastlane now includes `scripts/integration_cosmos_record_normalization_contract_consistency.sh` as a core contract-check stage (`integration_cosmos_record_normalization_contract_consistency`), enforcing canonical settlement record normalization parity across `vpnbilling`/`vpnrewards`/`vpnslashing`/`vpnsponsor`/`vpnvalidator`/`vpngovernance` between settlement core and Cosmos bridge/runtime surfaces to prevent contract drift.
  - easy-node phase5 live-smoke entrypoints: `./scripts/easy_node.sh issuer-sponsor-api-live-smoke`, `./scripts/easy_node.sh issuer-sponsor-vpn-session-live-smoke`, and `./scripts/easy_node.sh issuer-settlement-status-live-smoke`
  - `issuer_admin_blockchain_handlers_coverage` -> `scripts/integration_issuer_admin_blockchain_handlers_coverage_floor.sh` (validates issuer admin blockchain handler coverage floor for `upsert/promote/reputation/bond/recompute/get-subject/anon issue+revoke/audit/revoke-token`)
- phase5 settlement CI/check/run/handoff wrappers now emit canonical summary artifacts under `.easy-node-logs`; these are the helper input contracts for `scripts/phase5_settlement_layer_summary_report.sh`:
  - `phase5_settlement_layer_ci_summary.json`
  - `phase5_settlement_layer_check_summary.json`
  - `phase5_settlement_layer_run_summary.json`
  - `phase5_settlement_layer_handoff_check_summary.json`
  - `phase5_settlement_layer_handoff_run_summary.json`
- phase5 operator summary helper `scripts/phase5_settlement_layer_summary_report.sh` aggregates CI/check/run/handoff summaries into compact operator output plus normalized JSON, with integration contract coverage from `scripts/integration_phase5_settlement_layer_summary_report.sh`.
- phase5 run/handoff wrappers and aggregate report propagate sponsor live-smoke posture for downstream gates/reports as first-class signals via `signals.issuer_sponsor_api_live_smoke_*` + `signals.issuer_sponsor_vpn_session_live_smoke_*` and consolidated `signals.issuer_sponsor_api_live_smoke` + `signals.issuer_sponsor_vpn_session_live_smoke`.
- `scripts/roadmap_progress_report.sh` summary/report surfacing now also includes `vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status` and `vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_ok`.
- phase5 run/handoff wrappers and aggregate report also propagate settlement-status live-smoke posture via `signals.issuer_settlement_status_live_smoke_*` and consolidated `signals.issuer_settlement_status_live_smoke`.
- phase5 run/handoff wrappers and aggregate report also propagate exit settlement-status live-smoke posture via `signals.exit_settlement_status_live_smoke_*` and consolidated `signals.exit_settlement_status_live_smoke`.
- `scripts/roadmap_progress_report.sh` summary/report surfacing now also includes `vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status` and `vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_ok`.
- phase5 run/handoff wrappers and aggregate report also propagate dual-asset parity posture via `signals.settlement_dual_asset_parity_status`/`signals.settlement_dual_asset_parity_ok`, handoff equivalents, and consolidated `signals.settlement_dual_asset_parity`.
- `scripts/roadmap_progress_report.sh` summary/report surfacing now also includes `vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_status` and `vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok`.
- `scripts/roadmap_progress_report.sh` summary/report surfacing now also includes `vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status` and `vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_ok`.
- `scripts/roadmap_progress_report.sh` summary/report surfacing now also includes `vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status` and `vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok`.
- `scripts/roadmap_progress_report.sh` summary/report surfacing now also includes `vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status` and `vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_ok`.
- `scripts/roadmap_progress_report.sh` summary/report surfacing now also includes `vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status` and `vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok`.
- phase5 summary helper fallback discovery includes timestamped CI and handoff-run summary directories when canonical/default summary files are absent.
- phase5/phase6/phase7 blockchain CI wrappers now all run `integration_blockchain_cosmos_only_guardrail.sh` as fail-closed pre-stage `blockchain_cosmos_only_guardrail` (toggle: `--run-cosmos-only-guardrail`, default enabled), with contract coverage in `scripts/integration_ci_phase5_settlement_layer.sh`, `scripts/integration_ci_phase6_cosmos_l1_build_testnet.sh`, and `scripts/integration_ci_phase7_mainnet_cutover.sh`.
- phase6 Cosmos L1 build/testnet CI scaffold now runs via `scripts/ci_phase6_cosmos_l1_build_testnet.sh` with contract checks in `scripts/integration_ci_phase6_cosmos_l1_build_testnet.sh`, including scaffold/proto/query/module-tx/gRPC stage ordering.
- phase6 build/testnet CI also exposes optional `tdpnd_comet_runtime_smoke` via `--run-tdpnd-comet-runtime-smoke` (`scripts/integration_cosmos_tdpnd_comet_runtime_smoke.sh`) as the Comet runtime-mode smoke path, while keeping VPN dataplane independent from chain liveness.
- phase6 optional `tdpnd_comet_runtime_smoke` now validates mixed Comet+gRPC runtime posture including auth-mode behavior (Comet RPC status, gRPC health-open, reflection/list disabled, and bearer-gated billing query checks), and falls back to deterministic mixed-mode runtime-test coverage for that auth path when `grpcurl` is unavailable.
- phase6 build/testnet CI includes `local_testnet_smoke` wired to `scripts/integration_cosmos_local_testnet_smoke.sh` for deterministic local multi-node `tdpnd` lifecycle coverage (`init -> start -> status -> stop -> status`).
- phase6 build/testnet CI includes `module_tx_surface` wired to `scripts/integration_cosmos_module_tx_surface.sh` for six-module keeper/module transaction-surface coverage.
- phase6 gRPC runtime smoke now includes validator/governance real-scaffold roundtrip coverage, reflected core-module query-service checks, auth-query parity, and deterministic `PreviewEpochSelection` query checks.
- phase6 gRPC live smoke now validates reflected module-service parity plus live billing/rewards/slashing/sponsor/validator/governance query dispatch via grpcurl, including validator/governance canonicalization checks.
- phase6 build/testnet CI now includes `tdpnd_grpc_auth_live_smoke` wired to `scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh` for auth-token gRPC live-smoke coverage across billing/rewards/slashing/sponsor/validator/governance query RPCs, including auth-path canonicalization checks and grpcurl-unavailable fallback runtime coverage.
- phase6 Cosmos L1 contracts CI gate now runs via `scripts/ci_phase6_cosmos_l1_contracts.sh` with contract checks in `scripts/integration_ci_phase6_cosmos_l1_contracts.sh` for wrapper wiring plus first-failure RC propagation with full-stage accounting (non-short-circuit stage execution), and live-smoke coverage in `scripts/integration_phase6_cosmos_l1_contracts_live_smoke.sh`.
- phase6 Cosmos L1 contracts posture now includes `cosmos_module_coverage_floor` (`scripts/integration_cosmos_module_coverage_floor.sh`), `cosmos_keeper_coverage_floor` (`scripts/integration_cosmos_keeper_coverage_floor.sh`), and `cosmos_app_coverage_floor` (`scripts/integration_cosmos_app_coverage_floor.sh`) before wrapper handoff/run stages, with six-target floor enforcement across billing/rewards/slashing/sponsor/validator/governance module and keeper packages plus app coverage-floor enforcement for `./app`.
- phase6 Cosmos L1 contracts posture now includes `phase6_cosmos_dual_write_parity` wired to `scripts/integration_cosmos_dual_write_parity.sh` before wrapper handoff/run stages.
- phase6 canonical top-level suite wrapper is `scripts/phase6_cosmos_l1_build_testnet_suite.sh` with contract checks in `scripts/integration_phase6_cosmos_l1_build_testnet_suite.sh`.
- phase6 readiness wrappers are available as `scripts/phase6_cosmos_l1_build_testnet_check.sh` and `scripts/phase6_cosmos_l1_build_testnet_run.sh` (integration-covered).
- phase6 handoff wrappers are available as `scripts/phase6_cosmos_l1_build_testnet_handoff_check.sh` and `scripts/phase6_cosmos_l1_build_testnet_handoff_run.sh`, with explicit integration contracts `scripts/integration_phase6_cosmos_l1_build_testnet_handoff_check.sh` and `scripts/integration_phase6_cosmos_l1_build_testnet_handoff_run.sh`.
- phase6 readiness/handoff checker surfaces include `module_tx_surface_ok`, `tdpnd_grpc_auth_live_smoke_ok`, and optional `tdpnd_comet_runtime_smoke_ok` in addition to existing `tdpnd_grpc_runtime_smoke_ok` and `tdpnd_grpc_live_smoke_ok` signals, while keeping VPN dataplane independence from chain liveness.
- phase6 run/handoff-run dry-run relaxation also covers `module_tx_surface_ok` and `tdpnd_grpc_auth_live_smoke_ok` by default unless explicitly required by wrapper inputs.
- phase6 runtime smoke coverage now also tracks optional `tdpnd_comet_runtime_smoke` enablement as a dedicated Comet-mode stage, without coupling VPN dataplane forwarding to chain liveness.
- phase6 operator summary helper `scripts/phase6_cosmos_l1_summary_report.sh` aggregates CI/contracts/suite summary artifacts into compact operator lines plus normalized JSON output, with integration coverage from `scripts/integration_phase6_cosmos_l1_summary_report.sh`.
- phase6 build/testnet/contracts/check/run/handoff/suite wrappers now emit canonical summary artifacts under `.easy-node-logs/phase6_cosmos_l1_*_summary.json` in addition to per-run reports.
- phase6 summary helper fallback discovery now includes CI/contracts/suite timestamped summary directories when canonical/default summary files are absent.
- `scripts/roadmap_progress_report.sh` now consumes optional phase6 and phase7 cutover summary artifacts and surfaces `phase6_cosmos_l1_handoff` and `phase7_mainnet_cutover` status/signals under `blockchain_track`, with integration coverage in `scripts/integration_roadmap_progress_report.sh`.
- phase7 mainnet cutover wrappers are available as `scripts/phase7_mainnet_cutover_check.sh` and `scripts/phase7_mainnet_cutover_run.sh`, with integration coverage in `scripts/integration_phase7_mainnet_cutover_check.sh` and `scripts/integration_phase7_mainnet_cutover_run.sh`.
- phase7 mainnet cutover handoff wrappers are available as `scripts/phase7_mainnet_cutover_handoff_check.sh` and `scripts/phase7_mainnet_cutover_handoff_run.sh`, with integration coverage in `scripts/integration_phase7_mainnet_cutover_handoff_check.sh` and `scripts/integration_phase7_mainnet_cutover_handoff_run.sh`; easy-node exposes `./scripts/easy_node.sh phase7-mainnet-cutover-handoff-check` and `./scripts/easy_node.sh phase7-mainnet-cutover-handoff-run`.
- phase7 check/run/handoff-check/handoff-run signal snapshots include `mainnet_activation_gate_go` and `bootstrap_governance_graduation_gate_go` for validator-policy gate visibility.
- `mainnet_activation_gate_go` and `bootstrap_governance_graduation_gate_go` enforcement remain optional by default and are only required when operators explicitly enable `--require-mainnet-activation-gate-go` and/or `--require-bootstrap-governance-graduation-gate-go` in phase7 cutover gates.
- phase7 mainnet cutover CI wrapper is `scripts/ci_phase7_mainnet_cutover.sh`, with contract coverage in `scripts/integration_ci_phase7_mainnet_cutover.sh` for fail-closed stage ordering across check/run/handoff-check/handoff-run and first-failure RC propagation.
- phase7 operator summary helper is `scripts/phase7_mainnet_cutover_summary_report.sh`, with integration coverage in `scripts/integration_phase7_mainnet_cutover_summary_report.sh`, and it aggregates check/run/handoff-check/handoff-run artifacts.
- phase7 summary/report surfacing now includes runtime/readiness signals `module_tx_surface_ok`, `tdpnd_grpc_live_smoke_ok`, `tdpnd_grpc_auth_live_smoke_ok`, `cosmos_module_coverage_floor_ok`, `cosmos_keeper_coverage_floor_ok`, and `cosmos_app_coverage_floor_ok`, gate signals `mainnet_activation_gate_go_ok` and `bootstrap_governance_graduation_gate_go_ok`, and `dual_write_parity_ok` through `scripts/phase7_mainnet_cutover_summary_report.sh` and `scripts/roadmap_progress_report.sh`; optional `tdpnd_comet_runtime_smoke_ok` is preserved when available.
- `scripts/roadmap_progress_report.sh` accepts optional `--blockchain-mainnet-activation-gate-summary-json` and surfaces `blockchain_track.mainnet_activation_gate` with available/status/decision/go/no_go/reasons/source_paths, staying fail-soft when the summary is missing or invalid, and falling back to the Phase-7 propagated `mainnet_activation_gate_go` signal when no dedicated activation-gate summary is available.
- when a dedicated mainnet-activation gate summary is `NO-GO` due to missing/invalid required metrics evidence, `scripts/roadmap_progress_report.sh` now emits deterministic remediation actions under `blockchain_track.mainnet_activation_missing_metrics_action` (generate canonical input via `./scripts/easy_node.sh blockchain-mainnet-activation-metrics-input-template`, generate missing-only input template from the evaluated metrics summary via `./scripts/easy_node.sh blockchain-mainnet-activation-metrics-missing-input-template --metrics-summary-json .easy-node-logs/blockchain_gate_bundle_summary.json ...`, generate the new prefill scaffold with `./scripts/blockchain_mainnet_activation_metrics_prefill.sh` (`blockchain-mainnet-activation-metrics-prefill`) using `--metrics-summary-json .easy-node-logs/blockchain_gate_bundle_summary.json ...` before normalize/rerun/operator-pack/cycle, run missing-evidence checklist via `./scripts/easy_node.sh blockchain-mainnet-activation-metrics-missing-checklist --metrics-summary-json .easy-node-logs/blockchain_gate_bundle_summary.json ...`, generate the full operator artifact pack in one pass via `./scripts/easy_node.sh blockchain-mainnet-activation-operator-pack --metrics-summary-json .easy-node-logs/blockchain_gate_bundle_summary.json ...`, then either run normalize + rerun bundle with `./scripts/easy_node.sh blockchain-mainnet-activation-metrics-input` and `./scripts/easy_node.sh blockchain-gate-bundle --blockchain-mainnet-activation-metrics-input-json ...`, run the one-command cycle with `./scripts/easy_node.sh blockchain-mainnet-activation-gate-cycle --input-json ...`, or use the seeded local bootstrap cycle convenience path `./scripts/easy_node.sh blockchain-mainnet-activation-gate-cycle-seeded --reports-dir ... --summary-json ... --canonical-summary-json ... --refresh-roadmap 1 --print-summary-json 1`) in summary JSON, markdown, and heartbeat logs.
- the same roadmap report now also exposes gate freshness metadata at `blockchain_track.mainnet_activation_gate.summary_generated_at` / `blockchain_track.mainnet_activation_gate.summary_age_sec` / `blockchain_track.mainnet_activation_gate.summary_stale` / `blockchain_track.mainnet_activation_gate.summary_max_age_sec` and `blockchain_track.bootstrap_governance_graduation_gate.summary_generated_at` / `blockchain_track.bootstrap_governance_graduation_gate.summary_age_sec` / `blockchain_track.bootstrap_governance_graduation_gate.summary_stale` / `blockchain_track.bootstrap_governance_graduation_gate.summary_max_age_sec`, and it adds the stale-evidence refresh action `blockchain_mainnet_activation_refresh_evidence` with easy-node wrapper `./scripts/easy_node.sh blockchain-mainnet-activation-real-evidence-run` when stale activation evidence is detected.
- roadmap blockchain actionable runner is `scripts/roadmap_blockchain_actionable_run.sh`; easy-node entrypoint is `./scripts/easy_node.sh roadmap-blockchain-actionable-run`; integration contracts are `scripts/integration_roadmap_blockchain_actionable_run.sh` and `scripts/integration_easy_node_roadmap_blockchain_actionable_run.sh`; it executes blockchain-prefixed roadmap `next_actions` and supports `--recommended-only`, `--max-actions`, `--action-timeout-sec`, and `--parallel`.
- `scripts/roadmap_blockchain_actionable_run.sh --recommended-only 1` is strict: when the recommended action id is missing or not selected, it executes zero actions (no fallback-to-first).
- phase7 cutover wrappers emit canonical summary artifacts consumed by the summary helper, including `phase7_mainnet_cutover_check_summary.json`, `phase7_mainnet_cutover_run_summary.json`, `phase7_mainnet_cutover_handoff_check_summary.json`, and `phase7_mainnet_cutover_handoff_run_summary.json`.
- phase7 cutover CI/check/run/handoff-check/handoff-run wrappers feed canonical `.easy-node-logs` summary artifacts consumed by `scripts/phase7_mainnet_cutover_summary_report.sh`.
- phase7 cutover check/handoff now gate on phase6 contracts coverage-floor signals (`cosmos_module_coverage_floor`, `cosmos_keeper_coverage_floor`, `cosmos_app_coverage_floor`) plus dual-write parity confirmation, surfaced through `scripts/phase7_mainnet_cutover_check.sh`, `scripts/phase7_mainnet_cutover_handoff_check.sh`, and optional `--require-mainnet-activation-gate-go` / `--require-bootstrap-governance-graduation-gate-go` enforcement.
- phase7 mainnet cutover safety posture requires phase6 readiness signals, dual-write parity confirmation, rollback path readiness, and an optional operator approval gate before promotion.
- phase7 handoff wrappers stay fail-closed for cutover readiness and keep optional operator approval semantics unchanged.
- phase7 cutover keeps VPN dataplane independent from chain liveness; chain-side write degradation remains deferred/reconciled and must not block forwarding.
- Mainnet activation gate reporting stays aligned with the `Mainnet Activation Go/No-Go Metrics Gate` in `docs/blockchain-bootstrap-validator-plan.md`: the canonical validator-policy summary can be ingested through `scripts/roadmap_progress_report.sh`, and the default production decision remains NO-GO until the full gate window is met.
- settlement bridge live process smoke (`scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh`) now validates auth enforcement, write acceptance, and billing/rewards/sponsor/slashing/validator/governance GET by-id plus list query behavior in auth-enabled runtime mode, and it now also covers `tdpn.vpnvalidator.v1.Query/PreviewEpochSelection` auth posture and deterministic preview selection through the live gRPC runtime.
- easy-node exposes blockchain summary wrappers:
  - `./scripts/easy_node.sh phase5-settlement-layer-summary-report`
  - `./scripts/easy_node.sh phase6-cosmos-l1-summary-report`
  - `./scripts/easy_node.sh phase7-mainnet-cutover-summary-report`
- easy-node fail-closed blockchain gate wrappers cover phase5 + phase6 + phase7 entrypoints: `./scripts/easy_node.sh ci-phase5-settlement-layer`, `./scripts/easy_node.sh phase5-settlement-layer-check`, `./scripts/easy_node.sh ci-phase6-cosmos-l1-build-testnet`, `./scripts/easy_node.sh ci-phase6-cosmos-l1-contracts`, `./scripts/easy_node.sh ci-phase7-mainnet-cutover`, `./scripts/easy_node.sh phase7-mainnet-cutover-check`, `./scripts/easy_node.sh phase7-mainnet-cutover-run`, `./scripts/easy_node.sh phase7-mainnet-cutover-handoff-check`, and `./scripts/easy_node.sh phase7-mainnet-cutover-handoff-run`.
- integration coverage for those gate-wrapper contracts is `scripts/integration_easy_node_blockchain_gate_wrappers.sh`; it validates phase5 + phase6 + phase7 wrappers, and dataplane independence posture is unchanged.
- parallel blockchain sweep helper is `scripts/ci_blockchain_parallel_sweep.sh`; integration contract is `scripts/integration_ci_blockchain_parallel_sweep.sh`; it runs `cosmos_low_level`, `phase_wrappers`, and `go_tests` lanes concurrently, supports dry-run and per-lane toggles, and emits canonical summary output at `.easy-node-logs/ci_blockchain_parallel_sweep_summary.json` plus per-run lane logs under `.easy-node-logs/ci_blockchain_parallel_sweep_<stamp>/`; the `phase_wrappers` lane contract now also includes activation helper integrations `scripts/integration_blockchain_mainnet_activation_metrics_input.sh`, `scripts/integration_blockchain_mainnet_activation_metrics_input_template.sh`, `scripts/integration_blockchain_mainnet_activation_metrics_missing_input_template.sh`, `scripts/integration_blockchain_mainnet_activation_metrics_missing_checklist.sh`, `scripts/integration_blockchain_mainnet_activation_operator_pack.sh`, `scripts/integration_blockchain_gate_bundle.sh`, and `scripts/integration_blockchain_mainnet_activation_gate_cycle.sh`.
- Cosmos-only drift guardrail is enforced via helper `scripts/blockchain_cosmos_only_guardrail.sh`, integration contract `scripts/integration_blockchain_cosmos_only_guardrail.sh`, and easy-node wrapper `./scripts/easy_node.sh blockchain-cosmos-only-guardrail` with wrapper integration `scripts/integration_easy_node_blockchain_cosmos_only_guardrail.sh`; this guard fails fast on non-Cosmos/sidecar-chain blockchain drift in roadmap and pipeline wiring.
- `blockchain_fastlane` includes core contract-check stage `integration_blockchain_cosmos_only_guardrail` (`scripts/integration_blockchain_cosmos_only_guardrail.sh`).
- `blockchain_gate_bundle` runs a Cosmos-only guardrail pre-stage before activation-metrics + mainnet-activation-gate + bootstrap-governance-graduation-gate stages.
- easy-node blockchain sweep entrypoint is `./scripts/easy_node.sh ci-blockchain-parallel-sweep`, and wrapper coverage is enforced in `scripts/integration_easy_node_blockchain_gate_wrappers.sh`; canonical executable contract remains `scripts/ci_blockchain_parallel_sweep.sh`.
- blockchain fastlane helper is `scripts/blockchain_fastlane.sh`; integration contract is `scripts/integration_blockchain_fastlane.sh`; easy-node entrypoint is `./scripts/easy_node.sh blockchain-fastlane`; easy-node also exposes `./scripts/easy_node.sh blockchain-mainnet-activation-metrics` and `./scripts/easy_node.sh blockchain-mainnet-activation-gate`; integration coverage for those wrappers is `scripts/integration_easy_node_blockchain_gate_wrappers.sh`; it can optionally include the `blockchain_mainnet_activation_metrics` helper stage via `scripts/blockchain_mainnet_activation_metrics.sh` + `scripts/integration_blockchain_mainnet_activation_metrics.sh` before the mainnet activation gate stage (`scripts/blockchain_mainnet_activation_gate.sh` + `scripts/integration_blockchain_mainnet_activation_gate.sh`), and can optionally include the `blockchain_mainnet_activation_operator_pack` helper stage via `scripts/blockchain_mainnet_activation_operator_pack.sh` + `scripts/integration_blockchain_mainnet_activation_operator_pack.sh`; it ingests metrics source artifacts via repeatable `--blockchain-mainnet-activation-metrics-source-json` / CSV env `BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SOURCE_JSONS`, plus optional structured evidence ingestion via `--blockchain-mainnet-activation-metrics-input-json` / `BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_JSON` (normalized by `scripts/blockchain_mainnet_activation_metrics_input.sh` into deterministic reports-dir artifacts before metrics evaluation), and surfaces all metrics-source paths in `inputs.blockchain_mainnet_activation_metrics_source_jsons` + `artifacts.blockchain_mainnet_activation_metrics_source_jsons`; it also supports deterministic gate-summary artifact paths via `--blockchain-mainnet-activation-gate-summary-json` / `BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON`, surfaced as `inputs.blockchain_mainnet_activation_gate_summary_json` and `artifacts.blockchain_mainnet_activation_gate_summary_json`; when operator-pack stage wiring is enabled it also supports deterministic operator-pack summary artifact paths via `--blockchain-mainnet-activation-operator-pack-summary-json` / `BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_SUMMARY_JSON`, surfaced as `inputs.blockchain_mainnet_activation_operator_pack_summary_json` and `artifacts.blockchain_mainnet_activation_operator_pack_summary_json`; gate-summary ingestion stays fail-soft when the summary is missing or invalid while the helper itself remains fail-closed control-plane wiring and preserves dataplane independence.
- default `blockchain_fastlane` activation-gate behavior is prerequisite-aware: when gate wiring is enabled but no metrics input is resolvable, the stage is auto-skipped with reason `missing_metrics_prereq`; when the gate stage runs (explicit request or metrics present), fail-closed semantics remain (`--fail-close 1`).
- fastlane deterministic gate-input wiring now runs `scripts/blockchain_mainnet_activation_metrics_input.sh` whenever `--blockchain-mainnet-activation-metrics-input-json` is provided and either activation gate stage is enabled, even when `blockchain_mainnet_activation_metrics` stage is disabled; gate stages consume the normalized canonical input artifact and surface `blockchain_mainnet_activation_gate_metrics_json` plus `blockchain_mainnet_activation_gate_metrics_source` in summary artifacts.
- easy-node fastlane compatibility hardening now includes `scripts/integration_easy_node_blockchain_fastlane_cohort_quick_check_shim.sh` so stale `cohort_quick_check` dispatch forms remain safe and do not surface `command not found` at blockchain-fastlane completion.
- activation helper/operator-pack contracts now explicitly include `scripts/blockchain_mainnet_activation_metrics_input_template.sh` + `scripts/integration_blockchain_mainnet_activation_metrics_input_template.sh`, `scripts/blockchain_mainnet_activation_metrics_missing_input_template.sh` + `scripts/integration_blockchain_mainnet_activation_metrics_missing_input_template.sh`, `scripts/blockchain_mainnet_activation_metrics_prefill.sh` + `scripts/integration_blockchain_mainnet_activation_metrics_prefill.sh` (`blockchain-mainnet-activation-metrics-prefill`), `scripts/blockchain_mainnet_activation_metrics_missing_checklist.sh` + `scripts/integration_blockchain_mainnet_activation_metrics_missing_checklist.sh`, `scripts/blockchain_mainnet_activation_operator_pack.sh` + `scripts/integration_blockchain_mainnet_activation_operator_pack.sh`, and `scripts/blockchain_mainnet_activation_gate_cycle.sh` + `scripts/integration_blockchain_mainnet_activation_gate_cycle.sh`; the prefill helper sits between missing-input-template generation and normalize/rerun/operator-pack/cycle use. Operator-pack now generates the canonical template (`blockchain-mainnet-activation-metrics-input-template` outputs), generates the missing-input-template (`blockchain-mainnet-activation-metrics-missing-input-template` outputs), and generates the missing-checklist (`blockchain-mainnet-activation-metrics-missing-checklist` outputs) when metrics summary input is available. The gate-cycle helper now auto-runs missing-metrics checklist artifact generation (JSON + markdown) from the evaluated metrics summary by default, with optional disable via `--emit-missing-checklist 0`.
- activation helper print-flag contract is compatibility-preserving: helper scripts accept both `--print-summary-json` and `--print-output-json`, while roadmap-generated missing-metrics action commands now use canonical `--print-summary-json`.
- `scripts/roadmap_progress_report.sh` now also surfaces `blockchain_track.mainnet_activation_gate.summary_generated_at` / `blockchain_track.mainnet_activation_gate.summary_age_sec` / `blockchain_track.mainnet_activation_gate.summary_stale` / `blockchain_track.mainnet_activation_gate.summary_max_age_sec` and `blockchain_track.bootstrap_governance_graduation_gate.summary_generated_at` / `blockchain_track.bootstrap_governance_graduation_gate.summary_age_sec` / `blockchain_track.bootstrap_governance_graduation_gate.summary_stale` / `blockchain_track.bootstrap_governance_graduation_gate.summary_max_age_sec`, plus the stale-evidence refresh action `blockchain_mainnet_activation_refresh_evidence` / `./scripts/easy_node.sh blockchain-mainnet-activation-real-evidence-run` for stale activation evidence on the mainnet activation gate.
- operator guidance for activation evidence collection: start each cycle from a canonical metrics template, fill measured values/evidence links, then run the activation gate cycle helper so normalization + metrics evaluation + gate decision execute as one repeatable pass; missing/invalid evidence remains fail-soft with explicit `NO-GO` reasons, and VPN dataplane forwarding remains independent from chain/gate liveness.
- blockchain gate bundle helper is `scripts/blockchain_gate_bundle.sh`; easy-node entrypoint is `./scripts/easy_node.sh blockchain-gate-bundle`; integration contract is `scripts/integration_blockchain_gate_bundle.sh`; it composes activation-metrics + mainnet-activation-gate + bootstrap-governance-graduation-gate into one contract run, emits canonical bundle summary output, and stays fail-soft for missing/invalid metrics inputs by still generating explicit NO-GO decision visibility (with reasons) instead of suppressing gate-summary artifacts; dataplane independence posture is unchanged.
- `scripts/blockchain_staged_file_groups.sh` is the blockchain-only staged-file-groups helper, with easy-node wrapper `./scripts/easy_node.sh blockchain-staged-file-groups`, integration contract `scripts/integration_blockchain_staged_file_groups.sh`, and dedicated easy-node wrapper contract `scripts/integration_easy_node_blockchain_staged_file_groups.sh`.
- `blockchain_fastlane` summary surfacing now also includes Phase 7 summary/report runtime/readiness signals `module_tx_surface_ok`, `tdpnd_grpc_live_smoke_ok`, and `tdpnd_grpc_auth_live_smoke_ok`; optional `tdpnd_comet_runtime_smoke_ok` is preserved when present.
- `blockchain_fastlane` deterministic Phase 7 summary/report input path contract is `--phase7-mainnet-cutover-summary-report-json` / `BLOCKCHAIN_FASTLANE_PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_JSON`.
- bootstrap governance graduation gate helper is `scripts/blockchain_bootstrap_graduation_gate.sh` (integration: `scripts/integration_blockchain_bootstrap_graduation_gate.sh`); `blockchain_fastlane` can include this stage via `--run-blockchain-bootstrap-governance-graduation-gate` and deterministic summary path `--blockchain-bootstrap-governance-graduation-gate-summary-json` / `BLOCKCHAIN_FASTLANE_BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON`; easy-node exposes `./scripts/easy_node.sh blockchain-bootstrap-governance-graduation-gate` with wrapper coverage in `scripts/integration_easy_node_blockchain_gate_wrappers.sh`; roadmap ingestion contract is optional `scripts/roadmap_progress_report.sh --blockchain-bootstrap-governance-graduation-gate-summary-json` (integration: `scripts/integration_roadmap_progress_report.sh`) and is fail-soft when the summary is missing or invalid, falling back to the Phase-7 propagated `bootstrap_governance_graduation_gate_go` signal when no dedicated bootstrap summary is provided.

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
