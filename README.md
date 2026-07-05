# TDPN

Trust-Tiered Decentralized Privacy Network MVP scaffold. One Go node binary can act as client, entry relay, exit relay, directory, token issuer, WireGuard bridge, tap listener, or test packet injector.

## Why this project exists

TDPN explores a privacy network design where relay access, routing, trust signals, locality, abuse controls, and provider participation are all part of the same system instead of being bolted on later.

## Current capabilities

- Unified node runtime with role flags
- Client, entry, exit, directory, issuer, and WireGuard I/O roles
- Path-open handshake with split token classes
- UDP and opaque-mode relay forwarding
- Directory-driven relay selection and signed feeds
- Health-aware entry/exit selection with locality preferences
- Anti-concentration and anti-collusion guardrails
- Reputation-weighted relay ordering
- Federated directory fetch, peer sync, signed peer membership, and gossip
- Trust attestation, dispute, appeal, adjudication, and governance observability flows
- Entry handshake anti-abuse controls
- Provider relay admission APIs
- Live WireGuard runtime guardrails and kernel-proxy experiments
- CI, security, release, contribution, governance, and support docs

## Tech stack

- Go
- Redis-compatible storage integrations
- WireGuard-oriented packet flow experiments
- GitHub Actions

## Quick start

Run tests:

```bash
go test ./...
```

Run the node:

```bash
go run ./cmd/node
```

Role behavior is configured through flags and environment variables. See the docs in `docs/` for protocol, deployment, and threat-model details.

## Repository structure

```text
apps/        Application experiments
blockchain/  Supporting chain-related work
cmd/         Executables
deploy/      Deployment assets
docs/        Architecture and protocol documentation
internal/    Core implementation packages
pkg/         Reusable packages
scripts/     Automation and checks
```

## Good places to start

- `docs/tdpn-project-deep-dive.md`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `.github/workflows/ci.yml`

## Status

This is an MVP scaffold and research implementation. It is not advertised as production-ready; the value is in the system design, protocol thinking, threat modeling, and breadth of implementation.
