# MVP Implementation Plan

## Objective
Deliver a working 2-hop decentralized privacy path with tiered token policy using one executable that supports all roles.

Current implementation accelerators now in place:
- versioned easy-mode config contract (`deploy/config/easy_mode_config_v1.conf`)
- local daemon control API role (`go run ./cmd/node --local-api`)
- chain-agnostic settlement scaffolding (`pkg/settlement`)

## Phase 1: Foundation (current)
- Monorepo scaffold and unified `node` binary
- Role-based runtime (`--client --entry --exit --directory --issuer`)
- Shared packages for protocol, token crypto, policy
- Protocol and threat docs

## Phase 2: Control Plane
1. Directory service
- Implement `GET /v1/relays` returning signed descriptors
- Add descriptor signature verification in client

2. Issuer service
- Implement `POST /v1/token`
- Tier mapping and short-lived token minting
- Key rotation support

## Phase 3: Two-hop Data Path
1. Entry service
- Outer tunnel endpoint (WireGuard integration)
- `PATH_OPEN` handling and exit forwarding state
- DDoS ingress controls (rate limit + optional puzzles)

2. Exit service
- Inner tunnel endpoint
- Token validation and policy enforcement
- NAT egress + metrics

3. Client role
- Directory fetch + relay selection
- Token acquisition
- Outer + inner tunnel bring-up and keepalive

## Phase 4: Policy & Trust
- Tier-1 default abuse blocks (SMTP/25 + quotas)
- Basic reputation store
- Manual promotion flow (tier1->tier2->tier3)

## Phase 5: Verification
- Integration test for end-to-end path build
- Invariant tests (token expiry, deny ports, tier-1 SMTP block)
- Load test entry under handshake flood conditions

## Parallel Track: Global Privacy Mesh (Planning -> Incremental Build)
- Keep current production path stable (`2-hop`) while designing optional `1-hop/2-hop/3-hop` modes.
- Introduce resource-capped `micro-relay` role for broader participation without forcing all nodes to run exit.
- Keep validator/settlement work out of packet forwarding critical path.
- Reference design and safety docs:
  - `docs/global-privacy-mesh-track.md`
  - `docs/exit-node-safety-baseline-v1.md`
  - `docs/exit-node-safety-guide.md`
  - `docs/client-safety-guide.md`

## C/C++ Acceleration Later
- Keep service boundaries stable and move hot paths first:
  - entry packet forwarder
  - exit accounting/filtering hooks
- Preserve Go control plane for development speed.

## Parallel Phase 6 Foundation: Cosmos-Compatible Settlement/Governance
- Build chain-facing settlement adapters and sponsor payment-proof wiring in parallel with VPN RC hardening.
- Keep validator role server-side only and resource-isolated from VPN dataplane.
- Keep VPN operation independent from blockchain liveness (grace mode + deferred settlement path).
- Run periodic fail-soft settlement reconciliation in issuer/exit services to drain deferred chain submissions during outages/recovery.
- Start with hybrid governance posture: objective machine-verifiable events can be automated, subjective abuse remains policy-governed during bootstrap.
- Include issuer admin objective slash-evidence submission path (`POST /v1/admin/slash/evidence`) for deterministic v1 slashing evidence intake.
- Reference design guides:
  - `docs/full-execution-plan-2026-2027.md` (canonical sequencing)
  - `docs/blockchain-bootstrap-validator-plan.md`
  - `blockchain/tdpn-chain/` module scaffold
- Keep own-L1 cutover gated by the explicit 12-week go/no-go metrics table in `docs/blockchain-bootstrap-validator-plan.md`.
