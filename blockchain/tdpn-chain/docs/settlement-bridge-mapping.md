# Settlement Bridge Mapping (Scaffold)

This scaffold keeps chain responsibilities isolated from VPN dataplane runtime.

## App-side to chain-side mapping
- `pkg/settlement` reservation intents -> `x/vpnbilling` `CreditReservation`.
- `pkg/settlement` usage finalization -> `x/vpnbilling` `SettlementRecord`.
- reward accrual after settlement -> `x/vpnrewards` `RewardAccrual` and `DistributionRecord`.
- objective slash evidence ingestion -> `x/vpnslashing` `SlashEvidence` and `PenaltyDecision`.
  - v1 scope is objective, machine-verifiable evidence only.
  - `evidence_ref`/proof reference must be canonical: `sha256:<value>` or `obj://<path>`.
  - fallback derivation from violation type is removed; callers must submit explicit canonical proof references.
- sponsor API credit delegation -> `x/vpnsponsor` `SponsorAuthorization` and `DelegatedSessionCredit`.
- optional `tdpnd` settlement HTTP bridge routing:
  - write paths (`POST`):
    - `POST /x/vpnbilling/settlements` -> `x/vpnbilling`
    - `POST /x/vpnrewards/issues` -> `x/vpnrewards`
    - `POST /x/vpnsponsor/reservations` -> `x/vpnsponsor`
    - `POST /x/vpnslashing/evidence` -> `x/vpnslashing`
      - validation expectation: reject evidence without canonical `sha256:<value>` or `obj://<path>` proof reference.
  - query paths (`GET`, list + by-id):
    - `GET /x/vpnbilling/reservations[/{reservation_id}]`
    - `GET /x/vpnbilling/settlements[/{settlement_id}]`
    - `GET /x/vpnrewards/accruals[/{accrual_id}]`
    - `GET /x/vpnrewards/distributions[/{distribution_id}]`
    - `GET /x/vpnsponsor/authorizations[/{authorization_id}]`
    - `GET /x/vpnsponsor/delegations[/{reservation_id}]`
    - `GET /x/vpnslashing/evidence[/{evidence_id}]`
    - `GET /x/vpnslashing/penalties[/{penalty_id}]`
  - bridge auth policy: bearer token (when configured) applies to `POST` writes only; `GET` query routes and `GET /health` remain open.

## Reconciliation contract
- Records use `pending|submitted|confirmed|failed` status placeholders via `types/ReconciliationStatus`.
- Reconcile can promote settlement/reward/sponsor/slash records from `submitted` to `confirmed` when adapter query surfaces observe corresponding by-id bridge records.
- Phase-1 app wiring is stateful across all module msg surfaces:
  - `vpnbilling`: reservation create + settlement finalize.
  - `vpnrewards`: accrual create + distribution record.
  - `vpnslashing`: evidence submit + penalty apply.
  - `vpnsponsor`: authorization create + session-credit delegate.
- Query surfaces are available for by-id reads across all modules (reservation/settlement, accrual/distribution, evidence/penalty, authorization/delegation).
- Idempotent replay guarantees are enforced at handler level:
  - identical replays are accepted and flagged as replay,
  - conflicting duplicate payloads are rejected.
- Cross-record reference guards are enforced in keeper flows:
  - distribution requires existing accrual,
  - penalty requires existing evidence,
  - delegated credit requires existing authorization.
- Keepers use in-memory defaults for lightweight/local runs, with file-backed `--state-dir` runtime persistence and a KV-adapter seam for Cosmos SDK integration.
- Cosmos SDK/ABCI wiring can replace keeper storage without changing module responsibility boundaries.
- Proto schemas for Msg/Query surfaces are staged under `proto/tdpn/*/v1`.
- Runtime state persistence option:
  - `tdpnd --state-dir <path>` enables file-backed module stores rooted at one runtime state directory.
  - integration gate: `scripts/integration_cosmos_tdpnd_state_dir_persistence.sh`.
- Phase5 CI includes `settlement_adapter_roundtrip` as a first-class stage running `scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh`.
