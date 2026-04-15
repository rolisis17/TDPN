# TDPN Full Execution Plan (VPN -> Windows Native -> Cosmos L1)

Last updated: 2026-04-15

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
- Keep simple launcher flows minimal (profile + required connection fields).
- Route non-essential switches into expert mode.
- Use one versioned config contract: `deploy/config/easy_mode_config_v1.conf`.
- Add local app-control API foundation for desktop integration (`--local-api` role).

Exit gate:
- simple client/server flows <= 6 prompts each
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
- validator eligibility/governance/reward modules
- dual-write reconciliation before cutover
- settlement dual-write scaffold uses optional shadow adapter mirroring (best-effort, non-blocking) while primary fail-soft semantics remain canonical.

### Phase 7: Mainnet Cutover
- progressive migration with rollback path to chain-assisted mode

## Cosmos Execution Update (April 15, 2026)

- `tdpnd` runtime now supports `--state-dir` to enable file-backed module stores without coupling VPN dataplane behavior to chain liveness.
- Settlement bridge now includes read/query `GET` endpoints (list + by-id) across billing/rewards/sponsor/slashing modules in addition to `POST` write paths.
- CI/local integration now includes `scripts/integration_cosmos_tdpnd_state_dir_persistence.sh` for state-dir wiring and reopen-persistence verification.
- Phase 5 CI now includes the `settlement_adapter_roundtrip` gate backed by `scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh` to verify end-to-end adapter -> `tdpnd` bridge submissions before promotion.
- Phase 5 CI includes `settlement_shadow_env` running `scripts/integration_cosmos_settlement_shadow_env.sh` to validate shadow adapter env wiring and fail-open behavior.
- Phase 5 CI includes `settlement_shadow_status_surface` running `scripts/integration_cosmos_settlement_shadow_status_surface.sh` to validate shadow telemetry/status surfacing in settlement status endpoints.
- Phase 5 CI also includes `settlement_adapter_signed_tx_roundtrip` backed by `scripts/integration_cosmos_adapter_tdpnd_signed_tx_roundtrip.sh` to validate signed-tx adapter relay into `tdpnd` bridge writes before promotion.
- Phase 5 CI also includes `issuer_sponsor_api_live_smoke` backed by `scripts/integration_issuer_sponsor_api_live_smoke.sh` to validate sponsor API happy path (`quote -> reserve -> token -> status`) with no end-user wallet signing in the happy path.
- Phase 5 CI/check/run/handoff wrappers now emit canonical summary artifacts under `.easy-node-logs`; these are the helper input contracts for `scripts/phase5_settlement_layer_summary_report.sh`:
  - `phase5_settlement_layer_ci_summary.json`
  - `phase5_settlement_layer_check_summary.json`
  - `phase5_settlement_layer_run_summary.json`
  - `phase5_settlement_layer_handoff_check_summary.json`
  - `phase5_settlement_layer_handoff_run_summary.json`
- Phase 5 operator summary helper `scripts/phase5_settlement_layer_summary_report.sh` aggregates CI/check/run/handoff summaries into compact operator output plus normalized JSON, with contract coverage from `scripts/integration_phase5_settlement_layer_summary_report.sh`.
- Phase 5 wrapper summaries now propagate sponsor live-smoke signals end-to-end: run (`signals.issuer_sponsor_api_live_smoke_*`), handoff-run (`handoff.issuer_sponsor_api_live_smoke_*`), and aggregate report (`signals.issuer_sponsor_api_live_smoke`).
- Phase 5 summary helper fallback discovery now includes timestamped CI and handoff-run summary directories when canonical/default summary files are absent.
- Easy-node exposes blockchain summary wrappers:
  - `./scripts/easy_node.sh phase5-settlement-layer-summary-report`
  - `./scripts/easy_node.sh phase6-cosmos-l1-summary-report`
- Phase 6 CI now includes `scripts/ci_phase6_cosmos_l1_build_testnet.sh` with contract coverage from `scripts/integration_ci_phase6_cosmos_l1_build_testnet.sh` for chain scaffold/proto/query/gRPC runtime gate ordering and dry-run/first-failure accounting.
- Phase 6 build/testnet CI includes `local_testnet_smoke` wired to `scripts/integration_cosmos_local_testnet_smoke.sh` for deterministic local multi-node `tdpnd` lifecycle coverage (`init -> start -> status -> stop -> status`).
- Phase 6 build/testnet CI now includes `tdpnd_grpc_auth_live_smoke` wired to `scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh` for auth-token gRPC live-smoke coverage.
- Phase 6 contracts CI gate now includes `scripts/ci_phase6_cosmos_l1_contracts.sh` with contract coverage from `scripts/integration_ci_phase6_cosmos_l1_contracts.sh` for wrapper contract wiring and fail-fast propagation, plus live-smoke coverage from `scripts/integration_phase6_cosmos_l1_contracts_live_smoke.sh`.
- Phase 6 contracts CI gate includes both `cosmos_module_coverage_floor` (`scripts/integration_cosmos_module_coverage_floor.sh`) and `cosmos_keeper_coverage_floor` (`scripts/integration_cosmos_keeper_coverage_floor.sh`) before wrapper handoff/run stages.
- Phase 6 canonical top-level suite wrapper is `scripts/phase6_cosmos_l1_build_testnet_suite.sh` with contract coverage from `scripts/integration_phase6_cosmos_l1_build_testnet_suite.sh`.
- Phase 6 readiness wrappers are available via `scripts/phase6_cosmos_l1_build_testnet_check.sh` and `scripts/phase6_cosmos_l1_build_testnet_run.sh`, each with integration contracts.
- Phase 6 handoff wrappers are available via `scripts/phase6_cosmos_l1_build_testnet_handoff_check.sh` and `scripts/phase6_cosmos_l1_build_testnet_handoff_run.sh`, each with integration contracts.
- Phase 6 readiness/handoff checker surfaces include `tdpnd_grpc_auth_live_smoke_ok` in addition to existing `tdpnd_grpc_runtime_smoke_ok` and `tdpnd_grpc_live_smoke_ok` signals.
- Phase 6 run/handoff-run dry-run relaxation also covers `tdpnd_grpc_auth_live_smoke_ok` by default unless explicitly required by wrapper inputs.
- Phase 6 operator summary helper `scripts/phase6_cosmos_l1_summary_report.sh` aggregates CI/contracts/suite summary artifacts into compact operator lines plus normalized JSON output, with contract coverage from `scripts/integration_phase6_cosmos_l1_summary_report.sh`.
- Phase 6 build/testnet/contracts/check/run/handoff/suite wrappers now emit canonical summary artifacts under `.easy-node-logs/phase6_cosmos_l1_*_summary.json` in addition to per-run reports.
- Phase 6 summary helper fallback discovery now includes CI/contracts/suite timestamped summary directories when canonical/default summary files are absent.
- Settlement confirmation lifecycle posture is canonicalized as `pending` -> `submitted` -> `confirmed` with explicit `failed` records retained for replay/reconciliation.

## Non-Negotiables

- VPN dataplane must never depend on chain finality/liveness.
- simple UX remains simple; diagnostics depth remains available in expert flows.
- `1hop` is never a silent fallback.
