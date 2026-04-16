# x/vpnslashing

Scope:
- objective slash evidence submissions
- deterministic penalty execution

Required properties:
- evidence schema must remain machine-verifiable
- strict idempotency by evidence ID
- one penalty per evidence, with deterministic conflicts on second application
- separation from subjective/manual abuse adjudication
