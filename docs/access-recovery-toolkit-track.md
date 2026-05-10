# Access Recovery Toolkit Track

Status: pivot track (product direction + first trust primitive)

Product promise:
- help users recover trusted access when a site, app, VPN endpoint, or information source is blocked
- do not compete as "another VPN" first
- do not promise unblockability
- make trust visible, verifiable, and portable

## One-Sentence Version

The app is a trusted emergency address book: it imports or fetches signed recovery maps, verifies who signed them, checks freshness, tests which paths are reachable, then helps the user open the safest working path.

## Why This Is Different From The Previous Direction

The old broad direction tried to become:
- a dVPN
- a mesh
- a credit economy
- a social network
- a blockchain settlement system
- a censorship-resilient access layer

That was too much and did not give normal users a clear reason to choose us.

The new direction starts narrower:
- organizations or communities publish signed access packs
- users import or fetch those packs
- the tool verifies trust and freshness
- the tool shows working access paths
- tunnel integrations come later

This reuses useful work already built:
- signed manifest thinking
- cache/freshness policy
- bootstrap resilience docs
- key generation/signing tooling
- local control API trust posture
- real-world network testing discipline

## Target Users

Early target users are not generic VPN consumers.

Better targets:
- independent media projects
- NGOs and civil-society groups
- privacy educators
- diaspora groups helping blocked communities
- small organizations whose site/app/API may be blocked
- teams that need an emergency access handoff during network disruption

Bad first targets:
- people who only want free streaming VPNs
- people who do not care who operates the access path
- casual users asked to become public exits

## Basic User Story

1. FreeNews runs a website, app API, and several fallback mirrors.
2. FreeNews creates an access pack.
3. The pack lists official links, mirrors, bridge hints, app endpoints, and instructions.
4. FreeNews signs the pack with its private key.
5. Bob's app already trusts FreeNews' public key, or Bob imports it from a trusted source.
6. Bob cannot reach the normal website.
7. Bob imports the access pack by file, QR, text, or bridge invite.
8. The app verifies the signature and expiry.
9. The app shows only trusted, fresh access paths.
10. Bob opens a mirror, starts a helper tunnel, imports a config, or fetches a newer signed pack.

## What The App Does

MVP jobs:

1. Trust store
   - store organization public keys
   - show key id and organization identity
   - warn when a pack is signed by an unknown key

2. Access pack import
   - import JSON file first
   - later support QR/text/deep-link import
   - reject malformed, expired, or badly signed packs

3. Access path listing
   - show official sources
   - show mirrors
   - show bridge hints
   - show external helper configs
   - show safety notes and intended audience

4. Reachability check
   - test candidate URLs without trusting response content
   - record reachable/unreachable/timeout
   - keep this separate from signature trust

5. Launch helpers
   - open verified mirror
   - copy verified URL
   - export/import helper config
   - later call Outline, Tor Browser, Shadowsocks, GPM, or other helpers

## Trust Rule

Delivery does not equal trust.

An access pack can arrive from:
- official site
- mirror
- email
- QR code
- friend
- USB
- bridge invite
- cached copy

But the app trusts it only if:
- signature is valid
- public key is trusted
- key id matches
- pack is not expired
- schema is supported
- safety policy accepts the requested action

## Access Pack v0

Draft schema:
- `docs/schemas/access-recovery-pack-v0.schema.json`
- `docs/schemas/access-recovery-bridge-invite-v0.schema.json`
- `docs/schemas/access-recovery-trust-store-v1.schema.json`
- `docs/schemas/access-recovery-bridge-helper-registry-v1.schema.json`

Example:
- `docs/examples/access-recovery-pack.example.json`
- `docs/examples/access-recovery-bridge-invite.example.json`
- `docs/examples/access-recovery-bridge-helper-registry.example.json`

First CLI:
- `go run ./cmd/gpmrecover demo-bundle --out-dir .easy-node-logs/access-recovery-demo`
- `go run ./cmd/gpmrecover sign --pack docs/examples/access-recovery-pack.example.json --private-key-file .easy-node-logs/recovery.key --out .easy-node-logs/access-pack.signed.json`
- `go run ./cmd/gpmrecover bridge-sign --invite docs/examples/access-recovery-bridge-invite.example.json --private-key-file .easy-node-logs/recovery.key --out .easy-node-logs/bridge-invite.signed.json`
- `go run ./cmd/gpmrecover verify --pack .easy-node-logs/access-pack.signed.json --public-key-file .easy-node-logs/recovery.pub`
- `go run ./cmd/gpmrecover bridge-verify --invite .easy-node-logs/bridge-invite.signed.json --public-key-file .easy-node-logs/recovery.pub --show-paths`
- `go run ./cmd/gpmrecover bridge-policy --invite .easy-node-logs/bridge-invite.signed.json --public-key-file .easy-node-logs/recovery.pub --helper-registry docs/examples/access-recovery-bridge-helper-registry.example.json`
- `go run ./cmd/gpmrecover check --pack .easy-node-logs/access-pack.signed.json --public-key-file .easy-node-logs/recovery.pub --timeout-sec 8`

Demo bundle flow:
- `demo-bundle` creates a self-contained beta demo folder with:
  - `recovery.key` and `recovery.pub`
  - signed and unsigned access-pack JSON
  - signed and unsigned bridge-invite JSON
  - `recovery-trust.json`
  - `bridge-helper-registry.json`
  - `GPMREC1` text handoffs for the pack, bridge invite, trust store, and helper registry
  - QR PNGs for the pack, bridge invite, and helper registry
  - `demo-manifest.json` listing every generated file
- Open `apps/web/recovery.html`, import `recovery-trust.json`, then import either `access-pack.signed.json` or `bridge-invite.signed.json`.
- Alternatively, paste or scan the generated `GPMREC1` text/QR handoffs into the Text Handoff panel.

Local trust-store flow:
- `go run ./cmd/gpmrecover trust-add --trust-store .easy-node-logs/recovery-trust.json --org-id freenews-demo --org-name "FreeNews Demo" --public-key-file .easy-node-logs/recovery.pub --source "demo handoff"`
- `go run ./cmd/gpmrecover trust-list --trust-store .easy-node-logs/recovery-trust.json`
- `go run ./cmd/gpmrecover verify --pack .easy-node-logs/access-pack.signed.json --trust-store .easy-node-logs/recovery-trust.json --show-paths`
- `go run ./cmd/gpmrecover bridge-verify --invite .easy-node-logs/bridge-invite.signed.json --trust-store .easy-node-logs/recovery-trust.json --show-paths`
- `go run ./cmd/gpmrecover bridge-policy --invite .easy-node-logs/bridge-invite.signed.json --trust-store .easy-node-logs/recovery-trust.json --helper-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.json`
- `go run ./cmd/gpmrecover check --pack .easy-node-logs/access-pack.signed.json --trust-store .easy-node-logs/recovery-trust.json --timeout-sec 8`
- `go run ./cmd/gpmrecover trust-remove --trust-store .easy-node-logs/recovery-trust.json --org-id freenews-demo --key-id KEY_ID`

Text handoff flow:
- `go run ./cmd/gpmrecover text-export --kind access-pack --in .easy-node-logs/access-pack.signed.json --out .easy-node-logs/access-pack.txt`
- `go run ./cmd/gpmrecover text-export --kind bridge-invite --in .easy-node-logs/bridge-invite.signed.json --out .easy-node-logs/bridge-invite.txt`
- `go run ./cmd/gpmrecover text-export --kind trust-store --in .easy-node-logs/recovery-trust.json --out .easy-node-logs/recovery-trust.txt`
- `go run ./cmd/gpmrecover text-export --kind bridge-helper-registry --in .easy-node-logs/access-recovery-demo/bridge-helper-registry.json --out .easy-node-logs/bridge-helper-registry.txt`
- `go run ./cmd/gpmrecover text-import --text-file .easy-node-logs/access-pack.txt --expect-kind access-pack --out .easy-node-logs/access-pack.imported.json`
- `go run ./cmd/gpmrecover text-import --text-file .easy-node-logs/bridge-invite.txt --expect-kind bridge-invite --out .easy-node-logs/bridge-invite.imported.json`
- `go run ./cmd/gpmrecover text-import --text-file .easy-node-logs/recovery-trust.txt --expect-kind trust-store --out .easy-node-logs/recovery-trust.imported.json`
- `go run ./cmd/gpmrecover text-import --text-file .easy-node-logs/bridge-helper-registry.txt --expect-kind bridge-helper-registry --out .easy-node-logs/bridge-helper-registry.imported.json`
- `go run ./cmd/gpmrecover qr-png --text-file .easy-node-logs/access-pack.txt --out .easy-node-logs/access-pack.qr.png --size 768`

The text format starts with `GPMREC1.` and carries compact JSON as base64url. It is meant for chat messages, emails, printed handoffs, and QR codes. The CLI can render a text handoff as a PNG, and the browser recovery page can render/download a QR locally from the current text handoff.

Trust-store rules:
- the public key is stored with an organization id/name and derived key id
- a pack or bridge invite must be signed by a trusted key whose organization id matches the artifact
- disabled, expired, unknown, or wrong-organization keys fail closed
- raw `--public-key-file` verification remains available for one-off/operator checks, but beta users should verify through the trust store

Bridge-invite rules:
- bridge invites are helper hints, not new roots of trust
- bridge invites must expire within 14 days of issue time
- `bridge-policy` defaults require at least two helper paths, at least two distinct helper/contact hosts, a helper contact URL, and a manual/external-app fallback path
- `bridge-policy --helper-registry` additionally requires the helper to be active, registered for the invite organization, inside its active window, and not quarantined or disabled
- the helper contact and helper paths are shown only after signature, expiry, org id, and trusted-key checks pass
- the browser gives copy/open actions for the invite id, helper id, helper contact, and verified helper paths
- the helper registry is the first service-level rotation/quarantine control; a public bridge service still needs online rate limits and abuse reporting before launch

`check` keeps trust and reachability separate:
- it verifies the pack before probing anything
- it marks listed entries as trusted because they came from a verified pack
- it reports whether each trusted entry is reachable, unreachable, timed out, or skipped
- it skips paths that require external apps by default
- it skips direct `.onion` probing by default so the tool does not leak onion lookups through normal DNS

First browser surface:
- `apps/web/recovery.html`
- runs local pack, bridge-invite, and trust-store parsing in the browser
- imports an optional helper registry and enforces active/quarantined/disabled helper status before showing bridge paths
- lets a tester add/remove trusted organization public keys without hand-editing JSON
- copies or downloads the current trust store for handoff to another device
- exports/imports `GPMREC1` text handoffs for signed packs, bridge invites, trust stores, helper registries, and single trusted keys
- renders and downloads a local QR PNG from the current `GPMREC1` text handoff
- can scan a QR image into the text handoff field with native `BarcodeDetector` support or the bundled browser scanner fallback
- verifies the Ed25519 signature with Web Crypto when the browser supports it
- lists trusted access/helper paths only after signature, expiry, org id, and trusted-key checks pass
- shows signed helper contact/copy actions for verified bridge invites
- does not run network reachability checks yet because browser cross-origin checks are not reliable enough for the beta trust decision

## MVP Cut

Do first:
- access-pack schema
- bridge-invite schema
- access-pack signing/verification library
- bridge-invite signing/verification library
- CLI sign/verify for packs and bridge invites
- CLI bridge-invite policy gate for helper/contact diversity
- CLI bridge helper registry gate for active/quarantined/disabled helpers
- CLI reachability check that does not confuse reachable with trusted
- local trust-store file
- browser verifier/import screen
- UI trust-key add/remove flow
- text handoff export/import for packs, bridge invites, trust stores, and trusted keys
- QR PNG export in the CLI
- QR rendering/download in the browser
- QR image import in the browser with native scanning or bundled fallback
- helper launch/copy flows for bridge invites
- one-command end-to-end demo bundle
- example pack
- docs explaining how a user visualizes it

Do next:
- bridge service rate limits, abuse reports, and online registry publication

Do later:
- bridge service
- Outline/Shadowsocks/Tor/GPM launch helpers
- organization dashboard
- source-diversity policy
- mobile app

## Non-Goals For MVP

- no VPN tunnel
- no blockchain
- no credits
- no social network
- no hidden proxy
- no public exit role
- no "unblockable" marketing claim
- no automatic execution of downloaded configs

## Success Test

The first useful demo is:

1. Generate an organization key.
2. Sign an access pack.
3. Send the pack through an untrusted channel.
4. Verify it on another machine.
5. Show the trusted recovery paths and expiry.

That proves the foundation before we build any tunnel or app integration.
