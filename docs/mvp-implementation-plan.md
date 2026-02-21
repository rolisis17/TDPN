# MVP Implementation Plan

## Objective
Deliver a working 2-hop decentralized privacy path with tiered token policy using one executable that supports all roles.

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

## C/C++ Acceleration Later
- Keep service boundaries stable and move hot paths first:
  - entry packet forwarder
  - exit accounting/filtering hooks
- Preserve Go control plane for development speed.
