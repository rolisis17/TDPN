# vpngovernance Module

`vpngovernance` stores governance policy and decision records for TDPN chain control surfaces.

Responsibilities:
- Persist governance policies that define validator/governance operating rules.
- Persist governance decisions linked to policies and proposal outcomes.
- Expose deterministic create/query surfaces for control-plane and reconciliation services.

Design notes:
- Keeper supports pluggable storage adapters (in-memory, file JSON, KV).
- Create operations are idempotent by record ID and reject conflicting replays.
- Query surfaces provide deterministic sorted list output.