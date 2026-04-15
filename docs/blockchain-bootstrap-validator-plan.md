# Blockchain Bootstrap and Validator Selection Plan

This document captures the active Cosmos-first bootstrap model running in parallel with VPN production hardening.

## Canonical Posture

- Status: active Cosmos-first parallel build track.
- VPN dataplane remains independent from chain liveness.
- Hybrid governance: objective on-chain events + policy-governed subjective cases.
- Validator bootstrap policy is active while decentralization matures.

## Purpose

- Keep VPN dataplane independent from blockchain liveness.
- Define a small-network bootstrap policy that is operationally safe before full decentralization.
- Predefine validator eligibility and epoch selection while chain modules and integration are implemented.

## Scope and Status

- Status: active implementation with phased rollout (`devnet -> testnet -> production gate`).
- In scope: validator onboarding policy, hybrid governance bootstrap, eligibility scoring, epoch selection, and graduation criteria.
- Out of scope for now: final tokenomics constants, full permissionless onboarding, and subjective abuse automation.
- Current module posture:
  - `x/vpngovernance` persists append-only admin audit actions (`action_id`, `action`, `actor`, `reason`, `evidence_pointer`, `timestamp_unix`) with replay-safe idempotency.
  - `x/vpnvalidator` provides deterministic epoch selection helpers for hard gates, warmup/cooldown checks, stable-seat/rotating-seat fill, and concentration caps.

## Phase 0: Hybrid Governance Bootstrap (Small Network)

During early network growth, use hybrid controls.

- Objective, machine-verifiable events are enforced on-chain in v1.
- One governance authority (target: migrate to multisig before public scale).
- Manual allow/deny for validator candidacy.
- Manual emergency ban/disable for abusive or unstable validators.
- Policy-governed approval for dispute outcomes that are not yet fully machine-verifiable.
- Every admin action must produce an append-only audit record (actor, reason, evidence pointer, timestamp, action id).

Policy intent:

- Prefer safety and incident response speed over early full automation.
- Keep manual controls temporary and bounded by graduation criteria.

## Role Separation Policy

- Validator role is server-side only; client devices do not validate.
- VPN forwarding and validator workloads should be resource-isolated.
- Idle VPN servers may become validator candidates, but role changes happen only at epoch boundaries (no real-time flapping).

## Validator Eligibility Policy

A node is eligible only if hard gates pass, then it is ranked by score.

Hard gates (required):

- Minimum stake threshold met.
- Stake age threshold met.
- No active sanctions or unresolved critical incidents.
- Minimum uptime and health window satisfied.
- Resource headroom available (validator workload cannot starve VPN dataplane).

Weighted score (example structure):

`eligibility_score = (w_stake * stake_score) + (w_uptime * uptime_score) + (w_perf * performance_score) + (w_reputation * reputation_score) + (w_diversity * diversity_bonus) - (w_penalty * penalty_score)`

Selection constraints (required):

- Per-operator seat cap.
- Per-ASN/provider concentration cap.
- Regional/country concentration cap.

Notes:

- Reputation-only selection is insufficient; stake cost + age + penalties are mandatory.
- Weight tuning is governance-controlled and versioned.

## Epoch Selection Policy

Baseline:

- Fixed validator set per epoch.
- Candidate refresh only at epoch transition.
- Two pools: stable seats + rotating seats.

Algorithm sketch:

1. Build eligible candidate list from hard gates.
2. Rank by `eligibility_score`.
3. Apply decentralization caps (operator/ASN/region).
4. Fill stable seats first, then rotating seats.
5. Publish epoch set and metadata snapshot.

Stability controls:

- Warm-up requirement: candidate must remain eligible for `K_enter` consecutive epochs before promotion.
- Cooldown requirement: recently removed validator cannot re-enter until `K_cooldown` epochs.
- Hysteresis threshold: avoid churn from minor score oscillations.

## Abuse, Slashing, and Enforcement Baseline

Objective slash events (on-chain in v1):

- Double-sign/equivocation.
- Extended unavailability beyond policy threshold.
- Proven protocol violation with signed evidence.

Subjective abuse handling (policy-governed):

- Manual review with evidence pointer.
- Time-bounded sanctions with explicit appeal state.
- Escalation to slash only after policy quorum.

## VPN Independence Requirement

- VPN session setup and packet forwarding stay off-chain.
- If blockchain control plane is degraded, VPN runs in grace mode with deferred settlement/accounting.
- Blockchain failure must not hard-stop active VPN dataplane.

## Graduation Criteria

Move from bootstrap governance to broader semi-automation only after:

- Sufficient independent operators and geographic/provider diversity.
- Sanctions/slashing workflows produce consistent outcomes with low manual override rate.
- Incident response and audit trail are routinely exercised.
- Chain-layer outages no longer threaten VPN user experience.

## Mainnet Activation Go/No-Go Metrics Gate

Default decision remains **NO-GO** for production activation until every required gate below is met for the full measurement window.

Measurement window:

- 12 consecutive weeks of production VPN operation.

Required gates:

| Category | Metric | Go Threshold |
|---|---|---|
| VPN reliability | Connect/session success SLO | `>=99.5%` successful client session establishment per week |
| VPN reliability | Recovery SLO | `p95` incident recovery (MTTR) `<=30 min` for Sev-1/Sev-2 VPN incidents |
| Demand | Paying users | `>=1,000` paying monthly active clients for 3 consecutive months |
| Demand | Sustained traffic | `>=10,000` successful paid sessions/day (30-day average) |
| Validator supply | Candidate depth | `>=30` validator-eligible servers after hard gates |
| Validator decentralization | Operator concentration | `>=12` independent operators, and no single operator with `>20%` of validator seats |
| Validator decentralization | Infra concentration | no ASN/provider with `>25%` of validator seats |
| Geography diversity | Region/country spread | validators across `>=4` regions and `>=8` countries |
| Governance quality | Manual action quality | `<5%` manual sanctions reversed on appeal (rolling 90 days) |
| Governance quality | Abuse response speed | `p95` time from abuse report to decision `<=24h` |
| Economics | Subsidy sustainability | chain-fee subsidy budget covers `>=12 months` at current demand with no growth assumption |
| Economics | Unit economics | positive contribution margin after server rewards, abuse reserve, and support overhead for 3 consecutive months |

Decision policy:

- Any missed gate => NO-GO (continue staged rollout and governance hardening).
- All gates met => GO for production activation.
- If GO is achieved, run a separate security and readiness review before broad validator expansion.

Evidence artifacts to use for this gate:

- `prod-pilot-cohort` summaries/trend/alert artifacts.
- `roadmap-progress-report` snapshots.
- incident snapshot summaries and appeal outcomes.
- validator candidacy inventory exports (operator/ASN/region distribution).
- finance dashboard snapshots for subsidy runway and contribution margin.

Implementation sequence after GO:

1. Keep VPN dataplane and session control independent from chain liveness during rollout.
2. Run dual-write accounting (settlement ledger + TDPN chain) until reconciliation is stable.
3. Cut over production settlement authority only after dual-write parity and security signoff.
4. Preserve rollback path to grace/deferred settlement mode during initial production rollout.

## Roadmap Integration

- Source roadmap: `docs/product-roadmap.md` (Parallel Track: Cosmos L1 Settlement and Governance Foundation).
- Canonical execution plan: `docs/full-execution-plan-2026-2027.md`.
- Related implementation guide: `docs/mvp-implementation-plan.md`.
