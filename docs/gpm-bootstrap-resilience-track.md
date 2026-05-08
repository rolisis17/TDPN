# GPM Bootstrap Resilience Track

Status: planning track plus first local tooling

Goal:
- let new users find the GPM network even when the main website or first gateway is unavailable
- keep first-contact trust anchored in signed, short-lived bootstrap material
- allow existing insiders to help outsiders discover the network without making one insider a permanent authority

## Why This Track Exists

The first GPM connection is the most fragile moment. A new user may only know one public website, one gateway IP, or one invite code. If that entry point is offline, blocked, stale, or under attack, the user needs another safe way to reach a trusted directory.

Bootstrap resilience is not the same thing as bypass promises. The project should support multiple discovery paths, but every path must converge on the same trust model:
- signed bootstrap manifests
- short expiry windows
- pinned public keys or signed key rotation
- freshness checks
- source diversity when possible
- clear user warnings when trust is degraded

## Current Foundation

The local API already has a signed bootstrap manifest path:
- `GET /v1/gpm/bootstrap/manifest`
- `GPM_BOOTSTRAP_MANIFEST_URL`
- `GPM_BOOTSTRAP_MANIFEST_CACHE_PATH`
- `GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS`
- `GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE`
- `GPM_BOOTSTRAP_MANIFEST_ED25519_PUBLIC_KEY`
- `GPM_BOOTSTRAP_MANIFEST_HMAC_KEY`
- `GPM_MAIN_DOMAIN`

Production mode already tightens manifest transport and signature policy. This track builds on that instead of replacing it.

Related contract docs:
- `docs/local-control-api.md`
- `docs/schemas/gpm-bootstrap-manifest-v1.schema.json`
- `docs/schemas/gpm-bootstrap-bridge-invite-v0.schema.json`

## Bootstrap Source Types

The app should eventually try several source classes in a safe order:

1. Local trusted cache
   - used only while fresh enough
   - must carry the signed payload evidence when signature policy requires it
   - must still match pinned main-domain policy when configured

2. Official signed manifest endpoint
   - preferred normal path
   - HTTPS required in production
   - host pinned by `GPM_MAIN_DOMAIN` where possible

3. Official mirrors
   - static mirrors of the same signed manifest
   - cannot change trust because the signature covers the manifest body
   - useful when the main endpoint is down

4. DNS seed or directory seed hints
   - used to discover candidate directory endpoints
   - not trusted by themselves
   - candidates must still be admitted through signed manifest or directory trust policy

5. Insider bridge invite
   - an existing GPM user helps an outsider reach a signed manifest
   - bridge hints are short-lived and rate limited
   - the insider can help discovery, but cannot mint network trust

6. Offline signed bundle
   - QR/file/text bundle containing manifest body, signature, key id, expiry, and optional bridge hints
   - useful for support, events, or blocked environments
   - same signature and expiry rules apply

## Insider Bridge Invite

The user's idea:
- an insider tells the network that an outsider wants to enter
- the network answers with a safe way to connect
- the outsider may receive a password plus insider relay address or a bridge address

Recommended shape:
- the insider sends an invite-bridge request through the network over 2+ hops
- an authority or approved bridge coordinator issues a signed, short-lived bridge invite
- the outsider receives an invite bundle with:
  - bridge endpoints
  - ticket id
  - expiry
  - nonce/replay guard
  - bootstrap manifest key id
  - optional manifest public key material
  - optional human passphrase for rate limiting
- the outsider uses the bridge only to fetch signed bootstrap material and directory hints
- full network use still requires normal onboarding, wallet/session policy, invite/credit policy, and runtime checks

The passphrase is only a rate-limit or anti-spam gate. It must not be treated as cryptographic trust.

## Bridge Security Rules

Bridge invites should be fail-closed:
- short expiry by default, for example 10 to 30 minutes
- single-use or low-use ticket counters
- bound to an audience such as `bootstrap-manifest-fetch`
- bound to a bridge id and authority key id
- replay-protected with nonce and ticket id
- no permanent trust granted by the bridge
- no data-plane VPN access before normal registration
- bridge cannot override a bad manifest signature
- bridge cannot bypass production HTTPS/signature policy unless the user explicitly enters an emergency/offline recovery flow

Bridge operators should have:
- rate limits per inviter, per IP, per ticket, and per bridge
- abuse reporting and quarantine state
- logs that support abuse response without becoming a raw browsing history
- clear opt-in if a normal user contributes bridge capacity

## Trust Model

The key rule:

An insider can introduce an outsider to the network, but the signed manifest decides what the outsider should trust.

This prevents a malicious or compromised insider from silently redirecting a new user to a fake network. It also keeps support flows simple: the user can paste/import a bridge invite, but the app still checks signatures, expiry, pinned key policy, and source diversity.

## Product UX

The public app should eventually expose:
- normal connect path
- "I have an invite/bridge code" path
- trust status panel showing whether bootstrap came from official endpoint, cache, mirror, bridge, or offline bundle
- plain-language warnings for stale cache, unsigned manifest, or emergency mode

The UI should avoid promising unblockability. Use accurate wording:
- "alternate bootstrap sources"
- "bridge-assisted first connection"
- "signed recovery bundle"
- "network discovery help from an existing user"

## First Engineering Slice

Deliverables:
- publish this track
- add signed manifest schema
- add bridge invite schema
- add local manifest signing/verification CLI
- keep the current local API manifest endpoint compatible with existing manifests

Local tooling:

```bash
go run ./cmd/gpmmanifest gen --private-key-out .easy-node-logs/gpm_manifest_ed25519.key --public-key-out .easy-node-logs/gpm_manifest_ed25519.pub
go run ./cmd/gpmmanifest sign --manifest docs/examples/gpm-bootstrap-manifest.example.json --private-key-file .easy-node-logs/gpm_manifest_ed25519.key
go run ./cmd/gpmmanifest verify --manifest docs/examples/gpm-bootstrap-manifest.example.json --public-key-file .easy-node-logs/gpm_manifest_ed25519.pub --signature <SIGNATURE>
```

## Later Engineering Work

1. Manifest source fallback
   - support ordered official mirrors
   - retain current signed cache behavior
   - record source type in telemetry

2. Bridge invite verifier
   - parse/import bridge invite bundles
   - validate ticket signature, expiry, audience, and manifest key id
   - use bridge only for bootstrap manifest fetch

3. Bridge service
   - expose a minimal bootstrap-fetch relay endpoint
   - rate-limit by ticket and source
   - avoid broad proxy behavior

4. Source diversity
   - require multiple source confirmations for production default when practical
   - keep single signed official source as the phase-1 baseline

5. Operator/admin workflow
   - Admin Console can approve bridge operators, revoke tickets, quarantine bridges, and inspect abuse evidence

## Non-Goals

- no permanent trust from one insider
- no hidden proxy mode that gives full VPN access before onboarding
- no password-only trust
- no claim that the network can always bypass a national block
- no default downgrade from signed production bootstrap to unsigned emergency bootstrap
