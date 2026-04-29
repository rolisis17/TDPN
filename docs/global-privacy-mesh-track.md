# Global Private Mesh Track (Micro-Relays + Flexible Hops)

Status: active track (phased implementation + validation)

Product naming note:
- external product surface is `Global Private Mesh (GPM)`.
- older `Global Privacy Mesh` wording may remain in internal planning text until the low-risk product-surface rename is complete.

## Why this track exists

The current production path is a stable 2-hop VPN (`client -> entry -> exit`).
This track extends the architecture toward a broader "Global Privacy Mesh" model
without breaking the existing production-hardening work.

Core idea:
- keep packet forwarding fast and lightweight
- keep blockchain/settlement/validator work out of packet fast path
- let most participants run lightweight roles
- let stronger hosts take heavier roles

## Design Principles

1. Capability is universal, obligations are conditional.
   - Any node can be eligible for client, relay, exit, or validator roles.
   - Not every node should run every role at the same time.
2. Data plane and consensus plane stay decoupled.
   - Packet forwarding must not depend on chain finality.
3. Default operation must be safe and cheap.
   - Mobile/low-power systems should remain client-first.
4. Privacy modes must be explicit.
   - 1-hop/2-hop/3-hop are user-visible risk/performance choices.

## Node Role Tiers

- `client-only`
  - default role for all devices
  - minimal CPU/memory/network overhead
- `client-tier-1`
  - can use the standard VPN path when stake and prepaid balance requirements are satisfied
  - cannot use micro-relays and cannot provide micro-relay or micro-exit service
- `client-tier-2`
  - can use micro-relays when stake and prepaid balance requirements are satisfied
  - can opt into micro-relay when policy and local GPM Agent capacity checks pass
  - can opt into micro-exit beta only when the explicit micro-exit policy gate is enabled and local GPM Agent capacity checks pass
- `client-tier-3`
  - same micro-relay/micro-exit eligibility as Tier 2, with higher expected contribution capacity and policy weighting when local measurements support it
- `micro-relay`
  - lightweight middle relay role
  - strict resource caps (CPU, bandwidth, concurrent sessions)
  - no direct internet egress role by default
- `exit-relay`
  - hardened operator role with stricter safety baseline
  - explicit opt-in + stronger abuse controls
- `validator`
  - independent trust/consensus role
  - server-class hardware only
  - must not sit on packet forwarding critical path

## Path Modes (User Facing)

- `speed-1hop` (experimental, lowest latency, lowest privacy)
  - direct client -> exit
- `balanced-2hop` (default)
  - client -> relay -> exit (or entry -> exit in current architecture)
- `private-3hop` (higher latency, stronger privacy)
  - client -> guard/relay -> micro-relay -> exit

Notes:
- Keep entry/guard relatively sticky for bounded windows.
- Rotate middle/exit with jitter to avoid deterministic behavior.
- Avoid "rotate every few minutes always" because that can reduce stability and leak patterns.

## Micro-Relay Resource Model (Target)

Micro-relays are intended for commodity hosts and should enforce hard caps:

- max concurrent forwarded client sessions: small bounded number
- max aggregate egress Mbps: capped by local policy
- CPU guardrails: auto-disable relay mode above threshold
- memory guardrails: bounded buffers only
- uptime quality score: used for scheduling preference

Suggested runtime behavior:
- auto-enable relay only on healthy conditions (power/network/CPU)
- auto-demote to client-only on stress
- recover automatically when healthy again
- prioritize the user's own VPN traffic ahead of contributed relay/exit traffic
- measure bandwidth, latency, jitter, packet loss, CPU, memory, power/battery state, NAT/reachability, and reliability history before setting caps
- settle measured contribution weekly, with Monday 00:00 UTC -> Monday 00:00 UTC as the default accounting epoch

## Trust-Tier Port Access Policy

Default posture remains conservative:

- baseline trusted users get web-safe egress set first
- expanded port access is unlocked by trust tier and risk signals
- high-risk port classes remain blocked by default for new/unknown identities

This policy aligns with:
- `docs/exit-node-safety-baseline-v1.md`
- `docs/exit-node-safety-guide.md`

## Security and Abuse Model

- do not inspect arbitrary client device data
- detect abuse from network behavior and signed identity/session signals
- enforce:
  - per-subject rate limits
  - per-subject connection caps
  - fast revoke and temporary quarantine workflows
  - short-lived credentials + replay protection

## Roadmap Milestones (Track-Specific)

M0. Planning and safety baseline
- publish this track document
- publish operator/client safety guides

M1. Public app/Admin Console split
- public GPM App supports login, stake/prepaid/account state, connect/disconnect, diagnostics, and optional contribution opt-in/out only
- separate GPM Admin Console owns server/client controls, approvals, policy changes, slashing review, settlement review, and payout finalization
- release public app has zero admin tools or admin routes in the visible UX
- Admin Console admin role is wallet-allowlist gated (`GPM_ADMIN_WALLET_ALLOWLIST`) and requires command-backed wallet verification; local baseline proof-shape validation alone cannot mint admin sessions.
- production mode blocks legacy `/v1/service/start|stop|restart` mutations by default; `GPM_ALLOW_LEGACY_SERVICE_MUTATIONS=1` is break-glass only, and normal lifecycle control uses wallet-bound `/v1/gpm/service/*`.

M2. Control-plane schema extension
- descriptor capability flags for `micro_relay` role
- relay eligibility fields for lightweight scheduling
- contribution eligibility fields: `client_tier`, `stake_satisfied`, `prepaid_balance_satisfied`, `can_use_micro_relays`, `can_enable_micro_relay`, `can_enable_micro_exit`, and `contribution_lock_reason`
- contribution profile fields: role, capacity score, health score, max forwarded sessions, max bandwidth, uptime/reliability, demotion state, metering, and pending weekly reward

M3. Route policy extension
- explicit path profile semantics for 1-hop/2-hop/3-hop
- safe rotation windows and jitter policy defaults
- `3hop` is fail-closed for middle-hop policy shape: compatibility env overrides can require stricter middle selection for other profiles, but cannot downgrade `CLIENT_PATH_PROFILE=3hop` into a 2-hop fallback.

M4. Data-plane implementation (incremental)
- introduce optional middle-hop chain support in controlled profiles
- keep backward-compatible 2-hop default path
- local 3-hop runtime validation now seeds an advertised middle relay, forwards packets through the production middle role (`go run ./cmd/node --middle`) with static entry/exit peer allowlisting, and fails closed when strict middle selection is absent; remaining promotion work is deployment/admission policy, real-host evidence, durable replay/signoff evidence, and publication.

M5. Quality and anti-abuse hardening
- micro-relay quality scoring
- adaptive demotion/promotion rules
- trust-tiered port-unlock policy wiring
- local GPM Agent capacity measurement and automatic cap selection
- micro-exit beta descriptors share the micro-relay contribution-quality gate (`reputation`, `uptime`, `capacity`, and `abuse_penalty`) while remaining exit-role-only.
- public-app micro-exit contribution is fail-closed by default; `GPM_MICRO_EXIT_BETA_ALLOWED=1` is required before Tier 2/3 users can opt into endpoint-exit service.

M6. Weekly settlement and payouts
- continuously meter valid relay/exit service
- calculate weekly payout from metered contribution, quality score, uptime, capacity, and role type
- reduce, hold, or void weekly payouts when slashing evidence, abuse flags, invalid traffic, or policy violations exist
- `POST /v1/gpm/admin/rewards/finalize` is the Admin Console-only weekly payout finalizer: it accepts closed weeks only, blocks active holds, requires objective signed or chain-queryable traffic proof evidence in production rather than env-derived trusted status alone, and keeps chain-pending settlement states non-payable until the chain confirms.
- local settlement slash evidence is now read into Admin Console review/finalize as non-releaseable `slashing_evidence` holds (`slashing_hold_integration=local_settlement_slash_evidence`) so weekly payouts fail closed before chain production evidence is captured, including idempotent replay after a reward issue already exists.
- reward replay now conflicts on material drift, objective proof/evidence references are canonicalized before local duplicate checks, and the Cosmos bridge/module boundary rejects proofless reward issues, keys duplicate weekly payout protection to `PayoutPeriodStart`, and unwraps settlement-slash evidence refs before duplicate incident comparison.
- reservation id/session/subject binding is now local across production connect reserve-and-connect and the client -> entry -> exit path-open proof/assertion chain; remaining work is live-chain reservation write/settlement evidence (`ReserveFunds` -> authenticated `/x/vpnbilling/reservations`), staging round-trip evidence for the bound dataplane path, and end-to-end production evidence for Admin Console settlement/slashing/dispute review.

M7. External validation
- repeatable multi-VM scale tests
- compare latency/reliability/privacy outcomes across path profiles
- verify weekly settlement, slashing holds, public-app no-admin boundary, and Admin Console payout review end-to-end

## Explicit Non-Goals (for this track phase)

- no requirement that all users run as exits
- no requirement that all users validate consensus
- no packet forwarding dependence on blockchain finality
- no forced always-on role for low-power devices
- no KYC requirement for this phase
- no admin controls in the release/public GPM App
