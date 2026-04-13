# Global Privacy Mesh Track (Micro-Relays + Flexible Hops)

Status: proposed active track (planning + phased implementation)

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

M1. Control-plane schema extension
- descriptor capability flags for `micro_relay` role
- relay eligibility fields for lightweight scheduling

M2. Route policy extension
- explicit path profile semantics for 1-hop/2-hop/3-hop
- safe rotation windows and jitter policy defaults

M3. Data-plane implementation (incremental)
- introduce optional middle-hop chain support in controlled profiles
- keep backward-compatible 2-hop default path

M4. Quality and anti-abuse hardening
- micro-relay quality scoring
- adaptive demotion/promotion rules
- trust-tiered port-unlock policy wiring

M5. External validation
- repeatable multi-VM scale tests
- compare latency/reliability/privacy outcomes across path profiles

## Explicit Non-Goals (for this track phase)

- no requirement that all users run as exits
- no requirement that all users validate consensus
- no packet forwarding dependence on blockchain finality
- no forced always-on role for low-power devices

