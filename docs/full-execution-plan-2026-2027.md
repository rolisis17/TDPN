# TDPN Full Execution Plan (VPN -> Windows Native -> Cosmos L1)

Last updated: 2026-04-16

This is the implementation baseline for the next stages of TDPN.

Canonical status:
- this document is the authoritative source for sequencing across VPN, client-platform, and blockchain tracks.
- roadmap docs and automation recommendations must remain aligned with this plan.

## Priority Lock

1. VPN production hardening
2. Windows native app/parity
3. Payment/L1 rollout

## Phase Map

### Phase 0 (in progress): Product Surface Simplification
- Keep simple launcher flows minimal (profile + required connection fields) and document advanced flags separately.
- Route non-essential switches into expert mode, not the simple path.
- Use one versioned config contract: `deploy/config/easy_mode_config_v1.conf`.
- Add local app-control API foundation for desktop integration (`--local-api` role).

Exit gate:
- simple client/server flows <= 6 prompts each, with expert flags kept out of the default simple flow
- `<=6` prompt-budget contract is now guarded by automated launcher wiring/runtime integration checks.
- core launcher/script integrations remain green

### Phase 1: Route-Profile Completion and Resilience
- Keep `2hop` default.
- Keep `1hop` explicit and non-strict only.
- Extend descriptor model with optional hop-role metadata (`hop_roles`) for future `3hop` routing.
- Improve peer churn handling and session stability.

Exit gate:
- profile compare campaigns stable
- federation recovers from single-peer loss without manual intervention

### Phase 2: Linux Production Candidate
- lock runbooks and reproducible release process
- enforce SLO gates in pilot automation

### Phase 3: Windows Native Client Beta
- desktop-first client (`Tauri` + local daemon)
- daemon control via stable local API:
  - `connect`
  - `disconnect`
  - `status`
  - `set_profile`
  - `get_diagnostics`
  - `update`

### Phase 4: Windows Full Parity
- provider/authority packaging on Windows
- mixed Linux/Windows topology validation

### Phase 5: Chain-Agnostic Settlement Layer
- implement settlement abstraction (`pkg/settlement`)
- keep dataplane independent from settlement liveness

### Phase 6: Cosmos SDK + CometBFT L1 Build/Testnet
- Cosmos-first L1 execution (no sidecar chain pivot), with module scaffold/coverage for `vpnbilling`, `vpnrewards`, `vpnslashing`, `vpnsponsor`, `vpnvalidator`, and `vpngovernance`
- dual-write reconciliation before cutover
- settlement dual-write scaffold uses optional shadow adapter mirroring (best-effort, non-blocking) while primary fail-soft semantics remain canonical.

### Phase 7: Mainnet Cutover
- progressive migration with rollback path to chain-assisted mode
- gate cutover on phase6 readiness signals and explicit dual-write parity confirmation
- require rollback path readiness before promotion; keep an optional operator approval gate for final release decisions
- phase7 check/run/handoff-check/handoff-run signal snapshots include `mainnet_activation_gate_go` for validator-policy gate visibility.
- `mainnet_activation_gate_go` enforcement remains optional by default and is only required when operators explicitly enable the handoff requirement toggle.
- `scripts/phase7_mainnet_cutover_check.sh` + `scripts/integration_phase7_mainnet_cutover_check.sh`
- `scripts/phase7_mainnet_cutover_run.sh` + `scripts/integration_phase7_mainnet_cutover_run.sh`
- `scripts/phase7_mainnet_cutover_handoff_check.sh` + `scripts/integration_phase7_mainnet_cutover_handoff_check.sh`
- `scripts/phase7_mainnet_cutover_handoff_run.sh` + `scripts/integration_phase7_mainnet_cutover_handoff_run.sh`
- `scripts/ci_phase7_mainnet_cutover.sh` + `scripts/integration_ci_phase7_mainnet_cutover.sh`
- `scripts/phase7_mainnet_cutover_summary_report.sh` + `scripts/integration_phase7_mainnet_cutover_summary_report.sh`
- `scripts/roadmap_progress_report.sh` accepts optional `--blockchain-mainnet-activation-gate-summary-json` and surfaces `blockchain_track.mainnet_activation_gate` with available/status/decision/go/no_go/reasons/source_paths, staying fail-soft when the summary is missing or invalid.
- VPN dataplane remains independent from chain liveness during and after cutover.

## Cosmos Execution Update (April 16, 2026)

- `tdpnd` runtime now supports `--state-dir` to enable file-backed module stores without coupling VPN dataplane behavior to chain liveness.
- Chain scaffold/module ordering now includes `vpnbilling`, `vpnrewards`, `vpnslashing`, `vpnsponsor`, `vpnvalidator`, and `vpngovernance`.
- Runtime state-dir persistence now materializes module state files for validator/governance namespaces (`vpnvalidator.json`, `vpngovernance.json`) alongside existing module stores.
- gRPC runtime registration now includes module service namespaces for validator/governance (`tdpn.vpnvalidator.v1.{Msg,Query}` and `tdpn.vpngovernance.v1.{Msg,Query}`) in addition to billing/rewards/slashing/sponsor.
- `scripts/integration_cosmos_grpc_app_roundtrip.sh` now explicitly covers billing/rewards/slashing/sponsor/validator/governance Msg+Query roundtrip contracts.
- `vpngovernance` now persists append-only admin audit actions (`action_id`, `action`, `actor`, `reason`, `evidence_pointer`, `timestamp_unix`) with replay-safe idempotency and conflict-on-divergence behavior.
- `vpnvalidator` now exposes deterministic epoch selection helpers (hard-gate filtering, warmup/cooldown checks, stable-seat then rotating-seat fill, and operator/ASN/region concentration caps).
- `vpngovernance` gRPC contracts now include audit-action RPC/query surfaces (`RecordAuditAction`, `GovernanceAuditAction`, `ListGovernanceAuditActions`) for bootstrap governance audit trails.
- `vpnvalidator` gRPC contracts now include `PreviewEpochSelection` query for deterministic epoch-selection previews from policy + candidate inputs.
- Settlement bridge now includes read/query `GET` endpoints (list + by-id) and write `POST` endpoints across billing/rewards/sponsor/slashing plus validator/governance modules, with bearer auth applied to `POST` only when configured.
- Mainnet activation gate reporting stays aligned with the `Mainnet Activation Go/No-Go Metrics Gate` in `docs/blockchain-bootstrap-validator-plan.md`: the canonical validator-policy summary can be ingested through `scripts/roadmap_progress_report.sh`, and the default production decision remains NO-GO until the full gate window is met.
- CI/local integration now includes `scripts/integration_cosmos_tdpnd_state_dir_persistence.sh` for state-dir wiring and reopen-persistence verification.
- Phase 5 CI now includes the `settlement_adapter_roundtrip` gate backed by `scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh` to verify end-to-end adapter -> `tdpnd` bridge submissions before promotion.
- Phase 5 CI includes `settlement_shadow_env` running `scripts/integration_cosmos_settlement_shadow_env.sh` to validate shadow adapter env wiring and fail-open behavior.
- Phase 5 CI includes `settlement_shadow_status_surface` running `scripts/integration_cosmos_settlement_shadow_status_surface.sh` to validate shadow telemetry/status surfacing in settlement status endpoints.
- Phase 5 CI also includes `settlement_adapter_signed_tx_roundtrip` backed by `scripts/integration_cosmos_adapter_tdpnd_signed_tx_roundtrip.sh` to validate signed-tx adapter relay into `tdpnd` bridge writes before promotion.
- Phase 5 CI also includes `settlement_dual_asset_parity` backed by `scripts/integration_cosmos_settlement_dual_asset_parity.sh` to validate stable/native pricing parity for equivalent session entitlement.
- Phase 5 CI also includes `issuer_sponsor_api_live_smoke` backed by `scripts/integration_issuer_sponsor_api_live_smoke.sh` to validate sponsor API happy path (`quote -> reserve -> token -> status`) with no end-user wallet signing in the happy path.
- Phase 5 CI/check/run/handoff wrappers now emit canonical summary artifacts under `.easy-node-logs`; these are the helper input contracts for `scripts/phase5_settlement_layer_summary_report.sh`:
  - `phase5_settlement_layer_ci_summary.json`
  - `phase5_settlement_layer_check_summary.json`
  - `phase5_settlement_layer_run_summary.json`
  - `phase5_settlement_layer_handoff_check_summary.json`
  - `phase5_settlement_layer_handoff_run_summary.json`
- Phase 5 operator summary helper `scripts/phase5_settlement_layer_summary_report.sh` aggregates CI/check/run/handoff summaries into compact operator output plus normalized JSON, with contract coverage from `scripts/integration_phase5_settlement_layer_summary_report.sh`.
- Phase 5 wrapper summaries now propagate sponsor live-smoke signals end-to-end: run (`signals.issuer_sponsor_api_live_smoke_*`), handoff-run (`handoff.issuer_sponsor_api_live_smoke_*`), and aggregate report (`signals.issuer_sponsor_api_live_smoke`).
- Phase 5 wrapper summaries now also propagate dual-asset parity signals end-to-end: run (`signals.settlement_dual_asset_parity_status`/`signals.settlement_dual_asset_parity_ok`), handoff-run (`handoff.settlement_dual_asset_parity_status`/`handoff.settlement_dual_asset_parity_ok`), and aggregate report (`signals.settlement_dual_asset_parity`).
- Phase 5 summary helper fallback discovery now includes timestamped CI and handoff-run summary directories when canonical/default summary files are absent.
- Easy-node exposes blockchain summary wrappers:
  - `./scripts/easy_node.sh phase5-settlement-layer-summary-report`
  - `./scripts/easy_node.sh phase6-cosmos-l1-summary-report`
  - `./scripts/easy_node.sh phase7-mainnet-cutover-summary-report`
- Phase 6 CI now includes `scripts/ci_phase6_cosmos_l1_build_testnet.sh` with contract coverage from `scripts/integration_ci_phase6_cosmos_l1_build_testnet.sh` for chain scaffold/proto/query/module-tx/gRPC runtime gate ordering and dry-run/first-failure accounting.
- Phase 6 build/testnet CI also exposes optional `tdpnd_comet_runtime_smoke` via `--run-tdpnd-comet-runtime-smoke` (`scripts/integration_cosmos_tdpnd_comet_runtime_smoke.sh`) for the Comet runtime-mode smoke path, while keeping VPN dataplane independent from chain liveness.
- Phase 6 build/testnet CI includes `local_testnet_smoke` wired to `scripts/integration_cosmos_local_testnet_smoke.sh` for deterministic local multi-node `tdpnd` lifecycle coverage (`init -> start -> status -> stop -> status`).
- Phase 6 build/testnet CI includes `module_tx_surface` wired to `scripts/integration_cosmos_module_tx_surface.sh` for six-module keeper/module transaction-surface coverage.
- Phase 6 gRPC runtime smoke now includes validator/governance real-scaffold roundtrip coverage, reflected core-module query-service checks, auth-query parity, and deterministic `PreviewEpochSelection` query checks.
- Phase 6 gRPC live smoke now validates reflected module-service parity plus live billing/rewards/slashing/sponsor/validator/governance query dispatch via grpcurl.
- Phase 6 build/testnet CI now includes `tdpnd_grpc_auth_live_smoke` wired to `scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh` for auth-token gRPC live-smoke coverage across billing/rewards/slashing/sponsor/validator/governance query RPCs.
- Phase 6 contracts CI gate now includes `scripts/ci_phase6_cosmos_l1_contracts.sh` with contract coverage from `scripts/integration_ci_phase6_cosmos_l1_contracts.sh` for wrapper contract wiring and first-failure RC propagation with full-stage accounting (non-short-circuit stage execution), plus live-smoke coverage from `scripts/integration_phase6_cosmos_l1_contracts_live_smoke.sh`.
- Phase 6 contracts CI gate includes both `cosmos_module_coverage_floor` (`scripts/integration_cosmos_module_coverage_floor.sh`) and `cosmos_keeper_coverage_floor` (`scripts/integration_cosmos_keeper_coverage_floor.sh`) before wrapper handoff/run stages, with six-target floor enforcement across billing/rewards/slashing/sponsor/validator/governance module and keeper packages.
- Phase 6 contracts CI gate includes `phase6_cosmos_dual_write_parity` wired to `scripts/integration_cosmos_dual_write_parity.sh` before wrapper handoff/run stages.
- Phase 6 canonical top-level suite wrapper is `scripts/phase6_cosmos_l1_build_testnet_suite.sh` with contract coverage from `scripts/integration_phase6_cosmos_l1_build_testnet_suite.sh`.
- Phase 6 readiness wrappers are available via `scripts/phase6_cosmos_l1_build_testnet_check.sh` and `scripts/phase6_cosmos_l1_build_testnet_run.sh`, each with integration contracts.
- Phase 6 handoff wrappers are available via `scripts/phase6_cosmos_l1_build_testnet_handoff_check.sh` and `scripts/phase6_cosmos_l1_build_testnet_handoff_run.sh`, each with integration contracts.
- Phase 6 readiness/handoff checker surfaces include `module_tx_surface_ok`, `tdpnd_grpc_auth_live_smoke_ok`, and optional `tdpnd_comet_runtime_smoke_ok` in addition to existing `tdpnd_grpc_runtime_smoke_ok` and `tdpnd_grpc_live_smoke_ok` signals, while keeping VPN dataplane independence from chain liveness.
- Phase 6 run/handoff-run dry-run relaxation also covers `module_tx_surface_ok` and `tdpnd_grpc_auth_live_smoke_ok` by default unless explicitly required by wrapper inputs.
- Phase 6 runtime smoke contract now also tracks optional `tdpnd_comet_runtime_smoke` enablement as a dedicated Comet-mode stage, without coupling VPN dataplane forwarding to chain liveness.
- Phase 6 operator summary helper `scripts/phase6_cosmos_l1_summary_report.sh` aggregates CI/contracts/suite summary artifacts into compact operator lines plus normalized JSON output, with contract coverage from `scripts/integration_phase6_cosmos_l1_summary_report.sh`.
- Phase 6 build/testnet/contracts/check/run/handoff/suite wrappers now emit canonical summary artifacts under `.easy-node-logs/phase6_cosmos_l1_*_summary.json` in addition to per-run reports.
- Phase 6 summary helper fallback discovery now includes CI/contracts/suite timestamped summary directories when canonical/default summary files are absent.
- `scripts/roadmap_progress_report.sh` now consumes optional Phase 6 and Phase 7 cutover summary artifacts and surfaces `phase6_cosmos_l1_handoff` and `phase7_mainnet_cutover` status/signals under `blockchain_track`, with integration coverage in `scripts/integration_roadmap_progress_report.sh`.
- Phase 7 mainnet cutover readiness wrappers are `scripts/phase7_mainnet_cutover_check.sh` and `scripts/phase7_mainnet_cutover_run.sh`, with integration coverage from `scripts/integration_phase7_mainnet_cutover_check.sh` and `scripts/integration_phase7_mainnet_cutover_run.sh`.
- Phase 7 mainnet cutover handoff wrappers are `scripts/phase7_mainnet_cutover_handoff_check.sh` and `scripts/phase7_mainnet_cutover_handoff_run.sh`, with integration coverage from `scripts/integration_phase7_mainnet_cutover_handoff_check.sh` and `scripts/integration_phase7_mainnet_cutover_handoff_run.sh`; easy-node exposes `./scripts/easy_node.sh phase7-mainnet-cutover-handoff-check` and `./scripts/easy_node.sh phase7-mainnet-cutover-handoff-run`.
- Easy-node fail-closed blockchain gate wrappers cover phase5 + phase6 + phase7 entrypoints: `./scripts/easy_node.sh ci-phase5-settlement-layer`, `./scripts/easy_node.sh phase5-settlement-layer-check`, `./scripts/easy_node.sh ci-phase6-cosmos-l1-build-testnet`, `./scripts/easy_node.sh ci-phase6-cosmos-l1-contracts`, `./scripts/easy_node.sh ci-phase7-mainnet-cutover`, `./scripts/easy_node.sh phase7-mainnet-cutover-check`, `./scripts/easy_node.sh phase7-mainnet-cutover-run`, `./scripts/easy_node.sh phase7-mainnet-cutover-handoff-check`, and `./scripts/easy_node.sh phase7-mainnet-cutover-handoff-run`.
- Integration coverage for easy-node gate-wrapper dispatch and first-failure propagation is `scripts/integration_easy_node_blockchain_gate_wrappers.sh`; it validates phase5 + phase6 + phase7 wrappers, and VPN dataplane independence is unchanged.
- Blockchain fastlane helper is `scripts/blockchain_fastlane.sh`; integration contract is `scripts/integration_blockchain_fastlane.sh`; easy-node entrypoint is `./scripts/easy_node.sh blockchain-fastlane`; easy-node also exposes `./scripts/easy_node.sh blockchain-mainnet-activation-metrics` and `./scripts/easy_node.sh blockchain-mainnet-activation-gate`; integration coverage for those wrappers is `scripts/integration_easy_node_blockchain_gate_wrappers.sh`; it can optionally include the `blockchain_mainnet_activation_metrics` helper stage via `scripts/blockchain_mainnet_activation_metrics.sh` + `scripts/integration_blockchain_mainnet_activation_metrics.sh` before the mainnet activation gate stage (`scripts/blockchain_mainnet_activation_gate.sh` + `scripts/integration_blockchain_mainnet_activation_gate.sh`), ingesting metrics source artifacts via repeatable `--blockchain-mainnet-activation-metrics-source-json` / CSV env `BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SOURCE_JSONS` and surfacing them in `inputs.blockchain_mainnet_activation_metrics_source_jsons` + `artifacts.blockchain_mainnet_activation_metrics_source_jsons`; it also supports deterministic gate-summary artifact paths via `--blockchain-mainnet-activation-gate-summary-json` / `BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON`, surfaced as `inputs.blockchain_mainnet_activation_gate_summary_json` and `artifacts.blockchain_mainnet_activation_gate_summary_json`; gate-summary ingestion stays fail-soft when the summary is missing or invalid while the helper itself remains fail-closed control-plane wiring and preserves dataplane independence.
- Phase 7 mainnet cutover CI wrapper is `scripts/ci_phase7_mainnet_cutover.sh`, with contract coverage from `scripts/integration_ci_phase7_mainnet_cutover.sh` for fail-closed stage ordering across check/run/handoff-check/handoff-run and first-failure RC propagation.
- Phase 7 operator summary helper is `scripts/phase7_mainnet_cutover_summary_report.sh`, with integration coverage from `scripts/integration_phase7_mainnet_cutover_summary_report.sh`, and it aggregates check/run/handoff-check/handoff-run summary artifacts into canonical operator output.
- Phase 7 operator summary helper preserves optional `tdpnd_comet_runtime_smoke_ok` in the run signal snapshot, so Comet-mode validation can be surfaced when available without making it a hard requirement.
- Phase 7 cutover/handoff signal snapshots include `mainnet_activation_gate_go`; this requirement remains optional by default and is enabled only when operators explicitly require it for handoff readiness.
- Phase 7 cutover wrappers emit canonical summary artifacts consumed by the summary helper, including `phase7_mainnet_cutover_check_summary.json`, `phase7_mainnet_cutover_run_summary.json`, `phase7_mainnet_cutover_handoff_check_summary.json`, and `phase7_mainnet_cutover_handoff_run_summary.json`.
- Phase 7 handoff wrappers are fail-closed readiness gates that preserve the optional operator approval gate before promotion.
- Easy-node exposes Phase 7 summary wrapper `./scripts/easy_node.sh phase7-mainnet-cutover-summary-report`, backed by canonical check/run/handoff-check/handoff-run summary artifacts.
- Phase 7 cutover safety posture requires phase6 readiness signals, dual-write parity confirmation, rollback path readiness, and an optional operator approval gate before promotion.
- Phase 7 cutover keeps VPN dataplane independent from chain liveness; chain-side write outages remain deferred/reconciled and must not block forwarding.
- Settlement confirmation lifecycle posture is canonicalized as `pending` -> `submitted` -> `confirmed` with explicit `failed` records retained for replay/reconciliation.
- Settlement bridge live process smoke (`scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh`) now validates auth enforcement, write acceptance, and billing/rewards/sponsor/slashing/validator/governance GET by-id plus list query behavior in auth-enabled runtime mode, and it now also covers `tdpn.vpnvalidator.v1.Query/PreviewEpochSelection` auth posture and deterministic preview selection through the live gRPC runtime.

## Non-Negotiables

- VPN dataplane must never depend on chain finality/liveness.
- simple UX remains simple; diagnostics depth remains available in expert flows.
- `1hop` is never a silent fallback.
