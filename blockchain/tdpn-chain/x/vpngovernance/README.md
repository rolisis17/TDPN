# vpngovernance Module

`vpngovernance` stores governance policy and decision records for TDPN chain control surfaces.

Responsibilities:
- Persist governance policies that define validator/governance operating rules.
- Persist governance decisions linked to policies and proposal outcomes.
- Persist append-only governance admin audit actions (`action_id`, `action`, `actor`, `reason`, `evidence_pointer`, `timestamp_unix`) for bootstrap controls.
- Expose deterministic create/query surfaces for control-plane and reconciliation services.

Design notes:
- Keeper supports pluggable storage adapters (in-memory, file JSON, KV).
- Create operations are idempotent by record ID and reject conflicting replays.
- Audit-action writes are append-only by `action_id` with idempotent replay and conflict-on-divergence semantics.
- gRPC/proto surfaces include `RecordAuditAction` plus query paths `GovernanceAuditAction` and `ListGovernanceAuditActions`.
- Query surfaces provide deterministic sorted list output.
