# vpnvalidator module

`vpnvalidator` provides deterministic validator policy state used by TDPN chain governance and control-plane integrations.

Responsibilities:

- maintain validator eligibility decisions keyed by `validator_id`;
- persist objective validator lifecycle status records (`active`, `jailed`, `suspended`);
- provide idempotent create/upsert semantics for replay-safe ingest;
- expose query surfaces for control plane reconciliation and audits.

Out of scope:

- consensus validator-set updates;
- subjective abuse adjudication workflows.
