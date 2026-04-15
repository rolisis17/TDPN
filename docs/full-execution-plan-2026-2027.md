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

### Phase 7: Mainnet Cutover
- progressive migration with rollback path to chain-assisted mode

## Cosmos Execution Update (April 15, 2026)

- `tdpnd` runtime now supports `--state-dir` to enable file-backed module stores without coupling VPN dataplane behavior to chain liveness.
- Settlement bridge now includes read/query `GET` endpoints (list + by-id) across billing/rewards/sponsor/slashing modules in addition to `POST` write paths.
- CI/local integration now includes `scripts/integration_cosmos_tdpnd_state_dir_persistence.sh` for state-dir wiring and reopen-persistence verification.

## Non-Negotiables

- VPN dataplane must never depend on chain finality/liveness.
- simple UX remains simple; diagnostics depth remains available in expert flows.
- `1hop` is never a silent fallback.
