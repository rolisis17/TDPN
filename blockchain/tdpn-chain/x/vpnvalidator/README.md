# vpnvalidator module

`vpnvalidator` provides deterministic validator policy state used by TDPN chain governance and control-plane integrations.

Responsibilities:

- maintain validator eligibility decisions keyed by `validator_id`;
- persist objective validator lifecycle status records (`active`, `jailed`, `suspended`);
- provide idempotent create/upsert semantics for replay-safe ingest;
- provide deterministic epoch-selection helpers for bootstrap governance policy (hard gates, warmup/cooldown checks, stable+rotating pools, and concentration caps);
- expose gRPC/proto query path `PreviewEpochSelection` for deterministic validator-set previews from policy + candidate inputs;
- expose query surfaces for control plane reconciliation and audits.

Out of scope:

- consensus validator-set updates;
- subjective abuse adjudication workflows.
