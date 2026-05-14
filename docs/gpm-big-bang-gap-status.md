# GPM Big-Bang Productization Gap Status (Historical Snapshot)

Snapshot date: 2026-04-26

## Scope and source of truth

- This is retained as a historical snapshot of the earlier big-bang sequencing priority: VPN hardening -> Windows parity -> settlement/L1 rollout (`docs/full-execution-plan-2026-2027.md`).
- Current productization source of truth is `docs/gpm-productization-status.md`, with Access Recovery beta evidence and Global Private Mesh (GPM) tooling treated as the active pivot.
- GPM milestone requirements and next-wave ordering remain in `docs/gpm-productization-status.md` and `docs/global-privacy-mesh-track.md`.
- Live implementation signals from `.easy-node-logs/roadmap_progress_summary.json` generated `2026-04-24T15:57:00Z` (top-level `status=warn`).

## Implemented baseline signals

- Blockchain promotion path is currently green in roadmap summary: `phase6_cosmos_l1_handoff.status=pass` and `phase7_mainnet_cutover_summary_report.status=pass`.
- GPM wiring/tooling for M2/M4/M5 is present (cycle/check/evidence-pack/actionable runner helpers), but closure still depends on real-host evidence.

## Open productization gaps (severity-ranked)

### P1-1: M2 default-profile stability evidence closure is blocked
- Requirement: run and archive real-host stability cycles and publish evidence-pack artifacts.
- Signal: `profile_default_gate.status=pending`, `decision=NO-GO`, unresolved placeholder `invite_key`, and missing stability artifacts (`stability_summary_available=false`, `stability_check_summary_available=false`, `cycle_summary_available=false`).
- Next actionable step: populate host/subject placeholders (`A_HOST`, `B_HOST`, `INVITE_KEY` or explicit `--campaign-subject`) then execute `profile-default-gate-stability-cycle` and refresh `profile_default_gate_evidence_pack`.

### P1-2: M4 runtime-actuation promotion remains NO-GO
- Requirement: complete operator-enforcement/runtime scheduler linkage and capture promotion/demotion evidence.
- Signal: `runtime_actuation_promotion.status=fail`, `decision=NO-GO`; reasons include insufficient pass samples, excessive fail samples, and readiness below threshold. Evidence-pack status is also `fail`.
- Next actionable step: run `runtime-actuation-promotion-cycle` until thresholds pass, then rerun `runtime-actuation-promotion-evidence-pack` with fail-closed checks.

### P1-3: M5 multi-VM validation/promotion closure is blocked
- Requirement: execute live multi-VM sweep/stability cycles, reduce outputs, and publish promotion evidence pack.
- Signal: `multi_vm_stability.status=missing` with unresolved VM command source; downstream `multi_vm_stability_promotion.status=fail` and evidence-pack status `fail`.
- Next actionable step: provide a runnable VM command source (`--vm-command` or `--vm-command-file`), execute multi-VM stability cycle/check, then rerun promotion cycle and evidence-pack publish.

### P1-4: Live-chain settlement reservation and reward-proof closure is blocked
- Requirement: Admin Console weekly payouts must be backed by live-chain reservation/write, objective proof-validation, and finalized chain-confirmation evidence before release payout finalization is trusted.
- Signal: local wallet/session-bound reserve-and-connect binding with single-use local connect claims, client -> entry -> exit reservation id/session/subject binding through path-open proofs/assertions, chain-backed billing reservation submit/query support, authenticated bridge POST coverage for `/x/vpnbilling/reservations`, explicit verified reward-proof registry/query plumbing, and bounded trusted-bridge finality controls are now wired locally; live reservation/settlement round-trip evidence, staging round-trip evidence for the reserve-and-connect dataplane path, live objective reward/slashing proof evidence, finalized chain-status reconciliation, and production Admin Console payout/slashing evidence remain blockers.
- Next actionable step: archive API-to-chain reserve-and-connect reservation evidence, run staging reserve-and-connect round trips that exercise the client -> entry -> exit reservation binding, feed verified live proof records through the reward/slashing proof registry, require finalized chain status during reconciliation, rerun live bridge reservation/settlement round-trip smoke tests, and rerun `go test ./pkg/settlement`, `go test ./cmd/tdpnd` from `blockchain/tdpn-chain`, and the Admin Console settlement contract before payout-finalization signoff.

### P2-1: M1 remains validation debt behind M2/M4/M5 closure
- Requirement: complete scheduler/path-selection adoption and end-to-end validation artifacts for micro-relay admission.
- Signal: M1 is explicitly marked as remaining validation debt in next-wave guidance.
- Next actionable step: schedule dedicated validation slice after M2/M4/M5 pass, focused on scheduler adoption and operator/runtime controls evidence.

### P1-5: M3 production middle-hop evidence and admission closure is blocked
- Requirement: strict 3-hop clients must be protected by middle-node deployment/admission policy, exit-side entry-signed path/profile/middle assertions, and durable strict replay-guard storage.
- Signal: local 3-hop runtime validation now proves advertised middle-hop packet forwarding through the local production middle role (`go run ./cmd/node --middle`) with static entry/exit peer allowlisting, but real-host evidence, production deployment/admission policy, and published signoff artifacts remain blockers.
- Next actionable step: run real-host strict 3-hop validation with the local production middle role, publish the evidence pack, formalize middle-node deployment/admission policy, bind exit path-open admission to route assertions, and require durable replay storage for strict production exit deployments.

### P2-2: M3 real-host 3-hop validation remains debt
- Requirement: deterministic repeated real-host 3-hop validation (not only local/docker rehearsal).
- Signal: M3 explicitly remains validation debt in next-wave guidance after local production middle-role and anti-downgrade hardening.
- Next actionable step: run/pack real-host validation artifacts and gate signoff once M2/M4/M5 live-evidence blockers plus M3 deployment/admission, evidence-publication, and replay blockers are cleared.

## Recommended execution order

1. Close M2 real-host default-profile stability evidence and evidence-pack publication.
2. Close M4 runtime-actuation promotion thresholds and evidence-pack publication.
3. Close M5 multi-VM command-source resolution, stability/promotion cycles, and evidence-pack publication.
4. Close M3 real-host middle-role evidence, production deployment/admission policy, route assertion anti-downgrade, and durable strict replay-guard storage.
5. Close live-chain settlement reservation, proof-registry verification, and finalized chain-confirmation validation before any release payout-finalization signoff.
6. Burn down M1 and M3 validation debt with dedicated post-closure verification runs.
