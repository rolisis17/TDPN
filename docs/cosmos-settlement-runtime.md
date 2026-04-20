# Cosmos Settlement Runtime Wiring

This guide captures the runtime wiring between VPN services and the Cosmos-first settlement control plane.

## Core Principle

- VPN dataplane/session forwarding remains independent from chain liveness.
- Settlement, rewards, sponsor reservations, and slash evidence are fail-soft control-plane operations.
- When chain submissions fail, operations are deferred and reconciled asynchronously.

## Common Settlement Configuration

Use these in issuer/exit service environments:

- `SETTLEMENT_CHAIN_ADAPTER=cosmos`
- `SETTLEMENT_PRICE_PER_MIB_MICROS` (default `1000`)
- `SETTLEMENT_CURRENCY` (default `TDPNC`)
- `SETTLEMENT_NATIVE_CURRENCY` (optional native-token flow)
- `SETTLEMENT_NATIVE_RATE_NUMERATOR` / `SETTLEMENT_NATIVE_RATE_DENOMINATOR`
- `COSMOS_SETTLEMENT_ENDPOINT` (required when adapter=`cosmos`)
- `COSMOS_SETTLEMENT_API_KEY` (optional bearer auth)
- `COSMOS_SETTLEMENT_QUEUE_SIZE` (default `256`)
- `COSMOS_SETTLEMENT_MAX_RETRIES` (default `3`)
- `COSMOS_SETTLEMENT_BASE_BACKOFF_MS` (default `250`)
- `COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS` (default `4000`)
- `COSMOS_SETTLEMENT_SUBMIT_MODE` (`http|signed-tx`, default `http`)
- `COSMOS_SETTLEMENT_SIGNED_TX_BROADCAST_PATH` (default `/cosmos/tx/v1beta1/txs`, signed-tx mode)
- `COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID` (signed-tx mode chain hint)
- `COSMOS_SETTLEMENT_SIGNED_TX_SIGNER` (required in signed-tx mode)
- `COSMOS_SETTLEMENT_SIGNED_TX_SECRET` (inline secret; required unless secret-file is provided)
- `COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE` (optional secret file path; used when inline secret is empty)
- `COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID` (optional signer key id tag embedded in signed-tx payload)
- `COSMOS_SETTLEMENT_SHADOW_ENDPOINT` (optional; enables best-effort shadow dual-write mirror)
- `COSMOS_SETTLEMENT_SHADOW_API_KEY` (optional bearer auth for shadow endpoint)
- `COSMOS_SETTLEMENT_SHADOW_SUBMIT_MODE` (`http|signed-tx`, optional; default follows HTTP mirror behavior)
- `COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_BROADCAST_PATH` (optional signed-tx shadow path override)

`COSMOS_SETTLEMENT_ENDPOINT` may point to a local `tdpnd` settlement HTTP bridge when running chain-integrated settlement control-plane flows.

Signed-tx mode note:
- `COSMOS_SETTLEMENT_SIGNED_TX_SIGNER` is required when `COSMOS_SETTLEMENT_SUBMIT_MODE=signed-tx`.
- Secret resolution order: `COSMOS_SETTLEMENT_SIGNED_TX_SECRET` first; if empty, `COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE` is read and trimmed and must resolve to non-empty content.
- Service behavior remains fail-soft: VPN session setup/forwarding stays available while settlement writes are deferred and reconciled later.

Shadow dual-write note:
- `COSMOS_SETTLEMENT_SHADOW_ENDPOINT` enables optional best-effort shadow submissions for settlement/reward/sponsor/slash writes.
- Shadow submission failures never block primary adapter submission, session setup, or dataplane forwarding.
- Shadow outcomes are surfaced for operator visibility via reconcile metadata (`attempted/submitted/failed` shadow counters plus per-record shadow fields).

## TDPND Settlement HTTP Bridge

- Optional runtime flags:
  - `--settlement-http-listen`
  - `--settlement-http-auth-token`
  - `--settlement-http-auth-principal` (optional identity binding for billing/reward/sponsor/governance caller fields when auth token mode is enabled)
  - `--state-dir` (optional file-backed module stores under one runtime state root)
- Example:
  - `go run ./cmd/tdpnd --settlement-http-listen 127.0.0.1:8080 --state-dir ./.tdpn-chain-state`
- Endpoint/auth contract:
  - `GET /health` (no auth)
  - write (`POST`) endpoints:
    - `POST /x/vpnbilling/settlements`
    - `POST /x/vpnrewards/issues`
    - `POST /x/vpnsponsor/reservations`
      - sponsor reservation payload supports optional `AppID` and `EndUserID`.
      - when omitted, bridge compatibility fallback derives both from `SubjectID`.
    - `POST /x/vpnslashing/evidence`
      - required payload fields on the write path: `EvidenceID`, `SubjectID`, `SessionID`, `ViolationType`, `EvidenceRef`.
      - `ViolationType` must be objective and one of: `double-sign`, `downtime-proof`, `invalid-settlement-proof`, `session-replay-proof`, `sponsor-overdraft-proof`.
      - v1 validation expectation: slash evidence must be machine-verifiable, and `EvidenceRef`/proof reference must use `sha256:<64hex>` or `obj://<path>`.
      - Bridge mapping no longer derives proof references from violation-type fallback; callers must provide canonical proof references.
    - `POST /x/vpnvalidator/eligibilities`
    - `POST /x/vpnvalidator/status-records`
    - `POST /x/vpngovernance/policies`
    - `POST /x/vpngovernance/decisions`
    - `POST /x/vpngovernance/audit-actions`
  - query (`GET`) endpoints:
    - `GET /x/vpnbilling/reservations` and `GET /x/vpnbilling/reservations/{reservation_id}`
    - `GET /x/vpnbilling/settlements` and `GET /x/vpnbilling/settlements/{settlement_id}`
    - `GET /x/vpnrewards/accruals` and `GET /x/vpnrewards/accruals/{accrual_id}`
    - `GET /x/vpnrewards/distributions` and `GET /x/vpnrewards/distributions/{distribution_id}`
    - `GET /x/vpnsponsor/authorizations` and `GET /x/vpnsponsor/authorizations/{authorization_id}`
    - `GET /x/vpnsponsor/delegations` and `GET /x/vpnsponsor/delegations/{reservation_id}`
    - `GET /x/vpnslashing/evidence` and `GET /x/vpnslashing/evidence/{evidence_id}`
    - `GET /x/vpnslashing/penalties` and `GET /x/vpnslashing/penalties/{penalty_id}`
    - `GET /x/vpnvalidator/eligibilities` and `GET /x/vpnvalidator/eligibilities/{validator_id}`
    - `GET /x/vpnvalidator/status-records` and `GET /x/vpnvalidator/status-records/{status_id}`
    - `GET /x/vpngovernance/policies` and `GET /x/vpngovernance/policies/{policy_id}`
    - `GET /x/vpngovernance/decisions` and `GET /x/vpngovernance/decisions/{decision_id}`
    - `GET /x/vpngovernance/audit-actions` and `GET /x/vpngovernance/audit-actions/{action_id}`
  - when `--settlement-http-auth-token` is set, bearer auth is required on all `POST` endpoints (including validator/governance writes) only; `GET` query paths and `GET /health` remain open.
  - optional identity-bound writes:
    - when `--settlement-http-auth-principal` (or `SETTLEMENT_HTTP_AUTH_PRINCIPAL`) is configured with auth token mode, `SubjectID`, `ProviderSubjectID`, `SponsorID`, `Decider`, and `Actor` are bound to that principal (case-insensitive), mismatches return `403`, and omitted fields are auto-filled.
    - `--settlement-http-auth-principal` requires `--settlement-http-auth-token` (or token-file/env equivalent).
  - if you use that mode, bind the bridge to `127.0.0.1` only or another private-only transport and do not expose it on a reachable listener; unauthenticated GETs can leak settlement, validator, and governance state to any caller.
- VPN services can target this bridge with `COSMOS_SETTLEMENT_ENDPOINT=http://127.0.0.1:8080`.
- Bridge responsibilities remain control-plane only; VPN dataplane forwarding does not couple to bridge liveness.

One-command local helper:
- `scripts/cosmos_bridge_local_stack.sh` starts `tdpnd` in bridge mode and prints issuer/exit env wiring.
- Dry-run contract (print only, no process start):
  - `scripts/cosmos_bridge_local_stack.sh --dry-run --settlement-http-listen 127.0.0.1:8080 --grpc-listen 127.0.0.1:9090 --auth-token local-bridge-token --state-dir ./.tdpn-chain-state`
- Live local run:
  - `scripts/cosmos_bridge_local_stack.sh --settlement-http-listen 127.0.0.1:8080 --grpc-listen 127.0.0.1:9090 --state-dir ./.tdpn-chain-state`
  - helper also exports `TDPN_CHAIN_STATE_DIR` when `--state-dir` is set.

## Issuer Runtime Controls

- `ISSUER_SETTLEMENT_RECONCILE_SEC` (default `60`, `0` disables periodic reconcile loop)
- `ISSUER_REQUIRE_PAYMENT_PROOF` (`1` requires payment proof for client-access token issuance)
- `ISSUER_SPONSOR_API_TOKEN` (required for `/v1/sponsor/*` auth)

Issuer control-plane endpoints:

- Sponsor API:
  - `POST /v1/sponsor/quote`
  - `POST /v1/sponsor/reserve`
  - `GET /v1/sponsor/status?reservation_id=...`
  - `POST /v1/sponsor/token`
  - dApp onboarding quickstart: `blockchain-app-sponsorship-quickstart.md`
- Settlement status:
- `GET /v1/settlement/status` (admin auth required, returns reconcile/backlog counters; fail-soft reconcile errors stay `200` with `stale=true` and `last_error`, and recovery returns `stale=false`; `scripts/integration_issuer_settlement_status_live_smoke.sh` validates outage recovery in both `http` and `signed-tx` submit modes (`backlog -> ok` after Cosmos endpoint recovery), with explicit stale-state semantics `last_error implies stale=true` and recovery `stale=false`; the same live-smoke also validates sponsor token issuance/payment-proof happy path availability during outage/backlog and through recovery)
  - Shadow telemetry fields in status payload:
    - `shadow_adapter_configured`
    - `shadow_attempted_operations`
    - `shadow_submitted_operations`
    - `shadow_failed_operations`
- Objective slash evidence intake (admin):
  - `POST /v1/admin/slash/evidence`
  - required payload fields: `EvidenceID`, `SubjectID`, `SessionID`, `ViolationType`, `EvidenceRef`.
  - accepts only objective machine-verifiable evidence in v1; `ViolationType` allowlist: `double-sign`, `downtime-proof`, `invalid-settlement-proof`, `session-replay-proof`, `sponsor-overdraft-proof`; and `EvidenceRef`/proof reference format `sha256:<64hex>` or `obj://<path>`.

## Exit Runtime Controls

- `EXIT_SESSION_RESERVE_MICROS` (default `200000`)
- `EXIT_SETTLEMENT_RECONCILE_SEC` (default `60`, `0` disables periodic reconcile loop)

Exit service records usage, settles sessions, and issues provider rewards while keeping close-path non-blocking if settlement/chain steps fail.
Exit settlement status endpoint:
- `GET /v1/settlement/status` (returns latest backlog snapshot; if reconcile fails response stays `200` with `stale=true` and `last_error`, and recovery returns `stale=false`; `scripts/integration_exit_settlement_status_live_smoke.sh` validates outage recovery in both `http` and `signed-tx` submit modes (`backlog -> ok` after Cosmos endpoint recovery), with explicit stale-state semantics `last_error implies stale=true` and recovery `stale=false`)
- Shadow telemetry fields are also surfaced on exit status snapshots:
  - `shadow_adapter_configured`
  - `shadow_attempted_operations`
  - `shadow_submitted_operations`
  - `shadow_failed_operations`

## Reconciliation Behavior

- Settlement/reward/sponsor/slash operation statuses use `pending|submitted|confirmed|failed`.
- Deferred adapter operations are tracked per idempotency key (`pending` lifecycle).
- Periodic reconcile loops in issuer/exit call settlement `Reconcile(...)`.
- Successful replay marks settlement/reward/sponsor/slash operations `submitted` and clears deferred backlog.
- When adapter query surfaces observe by-id bridge records, reconcile promotes settlement/reward/sponsor/slash operations from `submitted` to `confirmed`.
- This confirmation capability is exposed as optional settlement adapter interface `ChainConfirmationQuerier` (`pkg/settlement/types.go`).
- `failed` remains an explicit reconciliation state for operator visibility, with replay/remediation driven by later reconcile cycles.
- Phase-6 scaffold supports optional shadow adapter mirroring on submission (best-effort only): shadow failures are visible in reconcile metadata and never block primary/session flow.
- Cosmos adapter retry policy:
  - retryable: transport/network errors, HTTP `408`, `425`, `429`, and `5xx`.
  - non-retryable: other HTTP `4xx` validation/auth-style failures (no retry loop).

## CI Acceptance Coverage

- `scripts/integration_cosmos_settlement_acceptance_paths.sh` runs deterministic acceptance coverage for:
  - sponsor happy path (`reserve -> payment authorization -> token issue`),
  - chain-outage fail-soft semantics (deferred adapter writes and non-blocking session close/status across issuer+exit live-smokes: `scripts/integration_issuer_settlement_status_live_smoke.sh` and `scripts/integration_exit_settlement_status_live_smoke.sh`),
  - dual-asset pricing surface (stable-denominated baseline with native-token conversion parity).
- `scripts/blockchain_staged_file_groups.sh` is the blockchain-only staged-file-groups helper, with easy-node wrapper `./scripts/easy_node.sh blockchain-staged-file-groups`, integration contract `scripts/integration_blockchain_staged_file_groups.sh`, and dedicated easy-node wrapper contract `scripts/integration_easy_node_blockchain_staged_file_groups.sh`.
- This check is wired into `scripts/ci_local.sh` under the Cosmos settlement block.
- `scripts/integration_cosmos_tdpnd_state_dir_persistence.sh` validates `tdpnd --state-dir` integration and scaffold persistence/reopen behavior for file-backed module stores.
- This state-dir persistence check is wired into `scripts/ci_local.sh` under the Cosmos runtime block.
- Phase6 Cosmos L1 contracts posture includes `cosmos_module_coverage_floor` (`scripts/integration_cosmos_module_coverage_floor.sh`), `cosmos_keeper_coverage_floor` (`scripts/integration_cosmos_keeper_coverage_floor.sh`), and `cosmos_app_coverage_floor` (`scripts/integration_cosmos_app_coverage_floor.sh`) before wrapper handoff/run stages.
- Phase5 CI treats settlement adapter roundtrip as a first-class stage: `settlement_adapter_roundtrip` runs `scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh`.
- Phase5 CI includes shadow env stage `settlement_shadow_env`: `scripts/integration_cosmos_settlement_shadow_env.sh` validates shadow adapter HTTP wiring, signed-tx shadow wiring, and fail-open behavior.
- Phase5 CI includes shadow status stage `settlement_shadow_status_surface`: `scripts/integration_cosmos_settlement_shadow_status_surface.sh` validates issuer/exit settlement status shadow telemetry surfacing.
- Phase5 CI includes dual-asset parity stage `settlement_dual_asset_parity`: `scripts/integration_cosmos_settlement_dual_asset_parity.sh` validates stable/native payment-path entitlement parity under configured pricing.
- Phase5 CI includes sponsor live-smoke stage `issuer_sponsor_api_live_smoke`: `scripts/integration_issuer_sponsor_api_live_smoke.sh` validates sponsor API happy path (`quote -> reserve -> token -> status`) with no end-user wallet signing in the happy path.
- Phase5 CI includes sponsor VPN-session live-smoke stage `issuer_sponsor_vpn_session_live_smoke`: `scripts/integration_issuer_sponsor_vpn_session_live_smoke.sh` validates sponsor flow through VPN path open/close with no end-user wallet signing in the happy path.
- Phase5 CI includes settlement-status live-smoke scripts `scripts/integration_issuer_settlement_status_live_smoke.sh` and `scripts/integration_exit_settlement_status_live_smoke.sh`, validating outage recovery in both `http` and `signed-tx` submit modes (`backlog -> ok` after Cosmos endpoint recovery) while keeping issuer/exit APIs available, with explicit stale-state contract coverage `last_error implies stale=true` and recovery `stale=false`.
- Phase5 issuer settlement-status live-smoke (`scripts/integration_issuer_settlement_status_live_smoke.sh`) also validates sponsor token issuance/payment-proof happy path remains available during outage/backlog and through recovery under deferred-write fail-soft semantics.
- Phase5 CI includes issuer admin blockchain handler coverage stage `issuer_admin_blockchain_handlers_coverage`: `scripts/integration_issuer_admin_blockchain_handlers_coverage_floor.sh` validates issuer admin blockchain handler coverage floor for `upsert/promote/reputation/bond/recompute/get-subject/anon issue+revoke/audit/revoke-token`.
- Phase5/Phase6/Phase7 blockchain CI wrappers all include fail-closed pre-stage `blockchain_cosmos_only_guardrail` wired to `scripts/integration_blockchain_cosmos_only_guardrail.sh` (toggle `--run-cosmos-only-guardrail`, default enabled) with contract coverage in `scripts/integration_ci_phase5_settlement_layer.sh`, `scripts/integration_ci_phase6_cosmos_l1_build_testnet.sh`, and `scripts/integration_ci_phase7_mainnet_cutover.sh`.
- Missing-metrics prefill helper coverage is now explicit as a blockchain-only operator surface: `scripts/blockchain_mainnet_activation_metrics_prefill.sh` emits the `blockchain-mainnet-activation-metrics-prefill` prefilled metrics scaffold from a gate summary before normalize/rerun/operator-pack/cycle, and its integration contract is `scripts/integration_blockchain_mainnet_activation_metrics_prefill.sh`.
- Roadmap freshness metadata is now surfaced alongside the gate summaries: `scripts/roadmap_progress_report.sh` reports `blockchain_track.mainnet_activation_gate.summary_generated_at` / `blockchain_track.mainnet_activation_gate.summary_age_sec` / `blockchain_track.mainnet_activation_gate.summary_stale` / `blockchain_track.mainnet_activation_gate.summary_max_age_sec` and `blockchain_track.bootstrap_governance_graduation_gate.summary_generated_at` / `blockchain_track.bootstrap_governance_graduation_gate.summary_age_sec` / `blockchain_track.bootstrap_governance_graduation_gate.summary_stale` / `blockchain_track.bootstrap_governance_graduation_gate.summary_max_age_sec`, and when stale activation evidence is detected it exposes `blockchain_mainnet_activation_refresh_evidence` with `./scripts/easy_node.sh blockchain-mainnet-activation-real-evidence-run`.
- `phase5_settlement_layer_run.sh`, `phase5_settlement_layer_handoff_run.sh`, and `phase5_settlement_layer_summary_report.sh` consume sponsor live-smoke signals from CI/check/handoff artifacts and surface normalized sponsor signal fields in wrapper summaries (`signals.issuer_sponsor_api_live_smoke_*`, `signals.issuer_sponsor_vpn_session_live_smoke_*`, and consolidated `signals.issuer_sponsor_api_live_smoke` + `signals.issuer_sponsor_vpn_session_live_smoke`).
- `scripts/roadmap_progress_report.sh` phase5 handoff surfacing treats sponsor VPN-session live smoke as first-class and reports `vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status` plus `vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_ok` alongside other phase5 signals.
- `phase5_settlement_layer_run.sh`, `phase5_settlement_layer_handoff_run.sh`, and `phase5_settlement_layer_summary_report.sh` also consume dual-asset parity signal from CI/check/handoff artifacts and surface normalized parity signal fields in wrapper summaries (`signals.settlement_dual_asset_parity_status`/`signals.settlement_dual_asset_parity_ok`, plus consolidated `signals.settlement_dual_asset_parity`).
- Phase7 cutover CI wrapper is `scripts/ci_phase7_mainnet_cutover.sh`, with contract coverage from `scripts/integration_ci_phase7_mainnet_cutover.sh` for fail-closed cutover stage ordering across check/run/handoff-check/handoff-run and first-failure RC propagation.
- Phase7 cutover handoff wrappers are `scripts/phase7_mainnet_cutover_handoff_check.sh` and `scripts/phase7_mainnet_cutover_handoff_run.sh`, with integration coverage from `scripts/integration_phase7_mainnet_cutover_handoff_check.sh` and `scripts/integration_phase7_mainnet_cutover_handoff_run.sh`; easy-node exposes `./scripts/easy_node.sh phase7-mainnet-cutover-handoff-check` and `./scripts/easy_node.sh phase7-mainnet-cutover-handoff-run`.
- Phase7 summary helper is `scripts/phase7_mainnet_cutover_summary_report.sh`, with integration coverage from `scripts/integration_phase7_mainnet_cutover_summary_report.sh`, aggregates check/run/handoff-check/handoff-run artifacts, and has easy-node wrapper `./scripts/easy_node.sh phase7-mainnet-cutover-summary-report`.
- Phase7 summary/report surfacing now includes runtime/readiness signals `module_tx_surface_ok`, `tdpnd_grpc_live_smoke_ok`, `tdpnd_grpc_auth_live_smoke_ok`, `cosmos_module_coverage_floor_ok`, `cosmos_keeper_coverage_floor_ok`, and `cosmos_app_coverage_floor_ok`, gate signals `mainnet_activation_gate_go_ok` and `bootstrap_governance_graduation_gate_go_ok`, and `dual_write_parity_ok` through `scripts/phase7_mainnet_cutover_summary_report.sh` and `scripts/roadmap_progress_report.sh`; optional `tdpnd_comet_runtime_smoke_ok` is preserved when available.
- Phase7 check/run/handoff-check/handoff-run signal snapshots include `mainnet_activation_gate_go` and `bootstrap_governance_graduation_gate_go`; both requirements remain optional by default and are only required when operators explicitly enable `--require-mainnet-activation-gate-go` and/or `--require-bootstrap-governance-graduation-gate-go` in phase7 cutover gates.
- Phase7 cutover check/handoff now gate on phase6 contracts coverage-floor signals (`cosmos_module_coverage_floor`, `cosmos_keeper_coverage_floor`, `cosmos_app_coverage_floor`) plus dual-write parity confirmation, surfaced through `scripts/phase7_mainnet_cutover_check.sh`, `scripts/phase7_mainnet_cutover_handoff_check.sh`, and optional `--require-mainnet-activation-gate-go` / `--require-bootstrap-governance-graduation-gate-go` enforcement.
- `scripts/roadmap_progress_report.sh` now consumes optional phase6 and phase7 cutover summary artifacts and surfaces `phase6_cosmos_l1_handoff` and `phase7_mainnet_cutover` status/signals under `blockchain_track`, with integration coverage in `scripts/integration_roadmap_progress_report.sh`.
- Easy-node fail-closed blockchain gate wrappers cover phase5 + phase6 + phase7 entrypoints: `./scripts/easy_node.sh ci-phase5-settlement-layer`, `./scripts/easy_node.sh phase5-settlement-layer-check`, `./scripts/easy_node.sh ci-phase6-cosmos-l1-build-testnet`, `./scripts/easy_node.sh ci-phase6-cosmos-l1-contracts`, `./scripts/easy_node.sh ci-phase7-mainnet-cutover`, `./scripts/easy_node.sh phase7-mainnet-cutover-check`, `./scripts/easy_node.sh phase7-mainnet-cutover-run`, `./scripts/easy_node.sh phase7-mainnet-cutover-handoff-check`, and `./scripts/easy_node.sh phase7-mainnet-cutover-handoff-run`.
- Phase7 handoff wrapper posture remains fail-closed with optional operator gate semantics and does not change dataplane independence.
- Integration coverage for these gate-wrapper contracts is `scripts/integration_easy_node_blockchain_gate_wrappers.sh`; it validates phase5 + phase6 + phase7 wrappers, and wrapper posture remains control-plane only while VPN dataplane independence is unchanged.
- Blockchain fastlane helper is `scripts/blockchain_fastlane.sh`; integration contract is `scripts/integration_blockchain_fastlane.sh`; easy-node entrypoint is `./scripts/easy_node.sh blockchain-fastlane`; this remains fail-closed control-plane wiring and preserves dataplane independence.
- Cosmos-only drift guardrail is enforced via helper `scripts/blockchain_cosmos_only_guardrail.sh`, integration contract `scripts/integration_blockchain_cosmos_only_guardrail.sh`, and easy-node wrapper `./scripts/easy_node.sh blockchain-cosmos-only-guardrail` with wrapper integration `scripts/integration_easy_node_blockchain_cosmos_only_guardrail.sh`; this guard fails fast on non-Cosmos/sidecar-chain blockchain drift in roadmap and pipeline wiring.
- `blockchain_fastlane` includes core contract-check stage `integration_blockchain_cosmos_only_guardrail` (`scripts/integration_blockchain_cosmos_only_guardrail.sh`).
- `blockchain_gate_bundle` runs a Cosmos-only guardrail pre-stage before activation-metrics + mainnet-activation-gate + bootstrap-governance-graduation-gate stages.
- Fastlane deterministic gate-input wiring now runs `scripts/blockchain_mainnet_activation_metrics_input.sh` whenever `--blockchain-mainnet-activation-metrics-input-json` is provided and either activation gate stage is enabled, even when `blockchain_mainnet_activation_metrics` stage is disabled; gate stages consume the normalized canonical input artifact and surface `blockchain_mainnet_activation_gate_metrics_json` plus `blockchain_mainnet_activation_gate_metrics_source` in summary artifacts.
- Blockchain fastlane also includes core contract-check stage `integration_cosmos_record_normalization_contract_consistency` via `scripts/integration_cosmos_record_normalization_contract_consistency.sh`, enforcing canonical settlement record normalization parity across `vpnbilling`/`vpnrewards`/`vpnslashing`/`vpnsponsor`/`vpnvalidator`/`vpngovernance` between settlement core and Cosmos bridge/runtime surfaces to prevent contract drift.
- `blockchain_fastlane` summary surfacing now also includes Phase 7 summary/report runtime/readiness signals `module_tx_surface_ok`, `tdpnd_grpc_live_smoke_ok`, and `tdpnd_grpc_auth_live_smoke_ok`; optional `tdpnd_comet_runtime_smoke_ok` is preserved when present.
- `blockchain_fastlane` deterministic Phase 7 summary/report input path contract is `--phase7-mainnet-cutover-summary-report-json` / `BLOCKCHAIN_FASTLANE_PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_JSON`.
- bootstrap governance graduation gate helper is `scripts/blockchain_bootstrap_graduation_gate.sh` (integration: `scripts/integration_blockchain_bootstrap_graduation_gate.sh`); `blockchain_fastlane` can include this stage via `--run-blockchain-bootstrap-governance-graduation-gate` and deterministic summary path `--blockchain-bootstrap-governance-graduation-gate-summary-json` / `BLOCKCHAIN_FASTLANE_BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON`; easy-node exposes `./scripts/easy_node.sh blockchain-bootstrap-governance-graduation-gate` with wrapper coverage in `scripts/integration_easy_node_blockchain_gate_wrappers.sh`; roadmap ingestion contract is optional `scripts/roadmap_progress_report.sh --blockchain-bootstrap-governance-graduation-gate-summary-json` (integration: `scripts/integration_roadmap_progress_report.sh`) and is fail-soft when the summary is missing or invalid, falling back to the Phase-7 propagated `bootstrap_governance_graduation_gate_go` signal when no dedicated bootstrap summary is provided.
- Phase7 cutover summaries remain control-plane only and preserve canonical dataplane independence during chain degradation.

## Chain gRPC Contract

- Chain module boundary expects generated gRPC service surfaces from `blockchain/tdpn-chain/proto/gen/go/tdpn/*/v1/*_grpc.pb.go`.
- Runtime registration contract per module is:
  - `RegisterMsgServer(...)` for tx service handlers.
  - `RegisterQueryServer(...)` for query/read-model handlers.
- Governance/validator bootstrap RPC highlights:
  - `tdpn.vpngovernance.v1.Msg/RecordAuditAction` plus query surfaces `GovernanceAuditAction` and `ListGovernanceAuditActions`.
  - `tdpn.vpnvalidator.v1.Query/PreviewEpochSelection` for deterministic validator-set preview from policy + candidate inputs.
  - `scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh` now exercises `PreviewEpochSelection` with and without `--grpc-auth-token` so the preview endpoint stays bearer-gated in auth mode and remains deterministic when authenticated.
- Optional local serve mode:
  - `go run ./cmd/tdpnd --grpc-listen 127.0.0.1:9090`
  - optional runtime hardening flags:
    - `--grpc-tls-cert`
    - `--grpc-tls-key`
    - `--grpc-auth-token`
  - `tdpnd` exposes gRPC health + reflection and exits gracefully on `SIGINT`/`SIGTERM`.
  - when `--grpc-auth-token` is set:
    - module RPC requests require `authorization: Bearer <token>`,
    - health remains available without auth,
    - reflection is disabled.
- Local module wiring contract:
  - `blockchain/tdpn-chain/go.mod` requires `github.com/tdpn/tdpn-chain/proto/gen/go v0.0.0`.
  - `blockchain/tdpn-chain/go.mod` replaces it with `./proto/gen/go`.
- CI guard: `scripts/integration_cosmos_proto_grpc_surface.sh` compiles generated proto gRPC packages through the chain root module and verifies registration symbols.

### Quick gRPC smoke

- Run registration/compile guard:
  - `./scripts/integration_cosmos_proto_grpc_surface.sh`
  - `./scripts/integration_cosmos_grpc_app_roundtrip.sh` (app-level gRPC roundtrip for billing/rewards/slashing/sponsor/validator/governance Msg+Query contracts, including validator/governance canonical write + mixed-case lookup coverage)
  - `./scripts/integration_cosmos_tdpnd_grpc_runtime_smoke.sh`
  - `./scripts/integration_cosmos_tdpnd_settlement_bridge_smoke.sh`
  - `./scripts/integration_cosmos_tdpnd_state_dir_persistence.sh`
  - `./scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh`
  - `./scripts/integration_cosmos_bridge_local_stack_contract.sh`
  - `./scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh`
  - `./scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh`
  - `./scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh`
- CI/runtime smoke suite split:
  - `integration_cosmos_grpc_app_roundtrip.sh`: targeted `./app` gRPC roundtrip tests for billing/rewards/slashing/sponsor/validator/governance `Msg`/`Query` contracts, including validator/governance canonical write + mixed-case lookup checks.
  - `integration_cosmos_tdpnd_grpc_runtime_smoke.sh`: targeted `cmd/tdpnd` runtime tests, including auth/TLS behavior plus validator/governance real-scaffold roundtrip, reflected core-module query-service checks, and `PreviewEpochSelection` query coverage.
  - `integration_cosmos_tdpnd_settlement_bridge_smoke.sh`: targeted settlement HTTP bridge runtime tests (`/health`, module POST writes, module GET query/list paths, auth checks, and combined gRPC/HTTP serve mode).
  - `integration_cosmos_tdpnd_state_dir_persistence.sh`: targeted state-dir persistence tests (`app` scaffold reopen + `cmd/tdpnd` state-dir runtime wiring/error propagation).
  - `integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh`: live `tdpnd --settlement-http-listen` process smoke (startup, auth enforcement, module POST acceptance, billing/rewards/sponsor/slashing/validator/governance GET by-id/list query coverage, graceful shutdown).
  - `integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh` also validates `tdpn.vpnvalidator.v1.Query/PreviewEpochSelection` auth posture and deterministic seat selection through the live gRPC runtime.
  - `integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh`: live adapter roundtrip from `pkg/settlement` into `tdpnd` bridge endpoints (settlement/reward/sponsor/slash submission paths).
  - `integration_cosmos_tdpnd_comet_runtime_smoke.sh`: mixed Comet+gRPC runtime smoke (`tdpnd` Comet RPC status plus gRPC health-open, reflection/list disabled, and bearer-gated billing query checks), with deterministic mixed-mode runtime-test fallback covering that auth path when `grpcurl` is unavailable.
  - `integration_cosmos_tdpnd_grpc_live_smoke.sh`: live `tdpnd --grpc-listen` process smoke (startup, health/reflection availability, reflected module-service parity, billing/rewards/slashing/sponsor/validator/governance query dispatch, validator/governance canonicalization checks, graceful shutdown).
  - `integration_cosmos_tdpnd_grpc_auth_live_smoke.sh`: live `tdpnd --grpc-auth-token` process smoke (health-open posture plus bearer-token gating for billing/rewards/slashing/sponsor/validator/governance query RPCs, including validator/governance auth-path canonicalization checks).
- Live local smoke:
  - run `tdpnd` with `--grpc-listen` (plus optional TLS/auth flags).
  - health check (`grpcurl`): `grpcurl -d '{"service":""}' 127.0.0.1:9090 grpc.health.v1.Health/Check`.
  - module RPC call (`grpcurl`, token mode): include `-H "authorization: Bearer $TOKEN"` when `--grpc-auth-token` is enabled.
  - reflection list (`grpcurl`): available only when auth token mode is not enabled.
  - fallback when `grpcurl` is unavailable: run `scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh` and `scripts/integration_cosmos_tdpnd_grpc_auth_live_smoke.sh` (auth-live fallback includes auth canonicalization runtime tests).
  - stop with `Ctrl+C` and confirm graceful shutdown.
