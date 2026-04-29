# Reward Proof Trust Guard

Weekly GPM reward issuance must not rely on a format-only traffic proof reference when the settlement path is chain-backed or otherwise declares that reward proof metadata is required.

Accepted production-grade trust anchor in this package for chain-backed reward issuance is:

- `traffic_proof_ref` using an `obj://...` marker only when a configured `RewardProofVerifier` accepts the `settlement.reward.objective-traffic.v1` trust contract for the exact reward material: reward id, provider subject, session, payout period, amount, currency, issue time, and proof object reference.

Fail-closed behavior:

- A bare `sha256:<64hex>` digest remains format-only for rewards and is rejected when chain-backed reward proof metadata is required.
- An `obj://...` value is treated as a proof locator, not proof by itself. Chain-backed traffic-proof-only rewards fail before payout preparation unless the verifier returns `Verified=true` with a non-empty verifier id.
- Submitted traffic-proof-only rewards are not promoted to `confirmed` during reconciliation unless they already carry verifier metadata or can be verified before finalization.
- A finalized local settlement reference can still be used as an additional session-binding check, but it is not sufficient by itself for chain-backed payout issuance. Rewards must also carry a verified `obj://` traffic proof record.
