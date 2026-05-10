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
- `docs/schemas/access-recovery-bridge-helper-registry-artifact-v1.schema.json`
- `docs/schemas/access-recovery-trusted-key-v1.schema.json`
- `docs/schemas/access-recovery-publication-index-v1.schema.json`

Example:
- `docs/examples/access-recovery-pack.example.json`
- `docs/examples/access-recovery-bridge-invite.example.json`
- `docs/examples/access-recovery-bridge-helper-registry.example.json`
- `docs/examples/access-recovery-trusted-key.example.json`

First CLI:
- `go run ./cmd/gpmrecover demo-bundle --out-dir .easy-node-logs/access-recovery-demo --org-id freenews-demo --org-name "FreeNews Demo" --helper-id helper-demo --helper-name "Demo bridge helper"`
- `bash ./scripts/integration_recovery_browser_smoke.sh`
- `bash ./scripts/integration_access_recovery_demo_contract.sh`
- `bash ./scripts/integration_access_recovery_examples_contract.sh`
- `go run ./cmd/gpmrecover sign --pack docs/examples/access-recovery-pack.example.json --private-key-file .easy-node-logs/recovery.key --out .easy-node-logs/access-pack.signed.json`
- `go run ./cmd/gpmrecover bridge-sign --invite docs/examples/access-recovery-bridge-invite.example.json --private-key-file .easy-node-logs/recovery.key --out .easy-node-logs/bridge-invite.signed.json`
- `go run ./cmd/gpmrecover verify --pack .easy-node-logs/access-pack.signed.json --public-key-file .easy-node-logs/recovery.pub`
- `go run ./cmd/gpmrecover bridge-verify --invite .easy-node-logs/bridge-invite.signed.json --public-key-file .easy-node-logs/recovery.pub --show-paths`
- `go run ./cmd/gpmrecover bridge-policy --invite .easy-node-logs/bridge-invite.signed.json --public-key-file .easy-node-logs/recovery.pub --helper-registry docs/examples/access-recovery-bridge-helper-registry.example.json`
- `go run ./cmd/gpmrecover bridge-policy --invite .easy-node-logs/bridge-invite.signed.json --public-key-file .easy-node-logs/recovery.pub --signed-helper-registry .easy-node-logs/bridge-helper-registry.signed.json`
- `go run ./cmd/gpmrecover bridge-registry-sign --helper-registry docs/examples/access-recovery-bridge-helper-registry.example.json --org-id freenews-demo --org-name "FreeNews Demo" --private-key-file .easy-node-logs/recovery.key --out .easy-node-logs/bridge-helper-registry.signed.json`
- `go run ./cmd/gpmrecover bridge-registry-verify --signed-registry .easy-node-logs/bridge-helper-registry.signed.json --public-key-file .easy-node-logs/recovery.pub --out-registry .easy-node-logs/bridge-helper-registry.verified.json`
- `go run ./cmd/gpmrecover bridge-registry-check --helper-registry docs/examples/access-recovery-bridge-helper-registry.example.json --helper-id helper-perth-1 --org-id freenews-demo --require-active`
- `go run ./cmd/gpmrecover bridge-registry-upsert-helper --helper-registry docs/examples/access-recovery-bridge-helper-registry.example.json --helper-id helper-mirror-1 --org-ids freenews-demo --display-name "Mirror helper" --contact-url https://mirror-helper.example/contact --abuse-report-url https://mirror-helper.example/abuse --rate-limit-policy "beta cap: per-user and per-source limits enforced" --out .easy-node-logs/bridge-helper-registry.updated.json`
- `go run ./cmd/gpmrecover bridge-registry-set-status --helper-registry docs/examples/access-recovery-bridge-helper-registry.example.json --helper-id helper-perth-1 --status quarantined --reason "maintenance window" --out .easy-node-logs/bridge-helper-registry.quarantined.json`
- `go run ./cmd/gpmrecover check --pack .easy-node-logs/access-pack.signed.json --public-key-file .easy-node-logs/recovery.pub --timeout-sec 8`
- `go run ./cmd/gpmrecover fetch-publication --index-url https://freenews.example/.well-known/gpm/recovery-index.json --out-dir .easy-node-logs/access-recovery-fetched`

Demo bundle flow:
- `demo-bundle` creates a self-contained beta demo folder with:
  - `recovery.key` and `recovery.pub`
  - signed and unsigned access-pack JSON
  - signed and unsigned bridge-invite JSON
  - `recovery-trust.json`
  - `bridge-helper-registry.json`
  - `bridge-helper-registry.signed.json`
  - `GPMREC1` text handoffs for the pack, bridge invite, trust store, trusted key, helper registry, and signed helper registry
  - QR PNGs for the pack, bridge invite, trusted key, helper registry, and signed helper registry
  - `public/.well-known/gpm/` static publication copies for `access-pack.json`, `bridge-invite.json`, `bridge-helper-registry.signed.json`, `recovery-trusted-key.json`, and `recovery-index.json`
  - `demo-manifest.json` listing every generated file
- Open `apps/web/recovery.html`, import `recovery-trusted-key.txt`/QR or `recovery-trust.json`, then import either `access-pack.signed.json` or `bridge-invite.signed.json`.
- For bridge invites, import `bridge-helper-registry.signed.json`, paste `bridge-helper-registry.signed.txt`, or scan `bridge-helper-registry.signed.qr.png` into the Helper Registry panel, then click `Verify Signed` to verify/extract the raw helper registry before checking the invite.
- Alternatively, paste or scan the generated `GPMREC1` text/QR handoffs into the Text Handoff panel.

Local trust-store flow:
- `go run ./cmd/gpmrecover trust-add --trust-store .easy-node-logs/recovery-trust.json --org-id freenews-demo --org-name "FreeNews Demo" --public-key-file .easy-node-logs/recovery.pub --source "demo handoff"`
- `go run ./cmd/gpmrecover trust-list --trust-store .easy-node-logs/recovery-trust.json`
- `go run ./cmd/gpmrecover trust-export-key --trust-store .easy-node-logs/recovery-trust.json --org-id freenews-demo --key-id KEY_ID --out .easy-node-logs/recovery-trusted-key.json --text-out .easy-node-logs/recovery-trusted-key.txt`
- `go run ./cmd/gpmrecover verify --pack .easy-node-logs/access-pack.signed.json --trust-store .easy-node-logs/recovery-trust.json --show-paths`
- `go run ./cmd/gpmrecover bridge-verify --invite .easy-node-logs/bridge-invite.signed.json --trust-store .easy-node-logs/recovery-trust.json --show-paths`
- `go run ./cmd/gpmrecover bridge-registry-verify --signed-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.signed.json --trust-store .easy-node-logs/recovery-trust.json --out-registry .easy-node-logs/bridge-helper-registry.verified.json`
- `go run ./cmd/gpmrecover bridge-policy --invite .easy-node-logs/bridge-invite.signed.json --trust-store .easy-node-logs/recovery-trust.json --helper-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.json`
- `go run ./cmd/gpmrecover bridge-policy --invite .easy-node-logs/bridge-invite.signed.json --trust-store .easy-node-logs/recovery-trust.json --signed-helper-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.signed.json`
- `go run ./cmd/gpmrecover bridge-service-config --invite .easy-node-logs/bridge-invite.signed.json --trust-store .easy-node-logs/recovery-trust.json --signed-helper-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.signed.json --out .easy-node-logs/bridge-service-config.json`
- `go run ./cmd/gpmrecover bridge-service-check --config .easy-node-logs/bridge-service-config.json --path-id helper-web`
- `go run ./cmd/gpmrecover bridge-service-code-hash --code-file .easy-node-logs/bridge-code.txt --out .easy-node-logs/bridge-code-hash.json`
- `CONFIG_HASH="$(sha256sum .easy-node-logs/bridge-service-config.json | awk '{print $1}')"`
- `go run ./cmd/gpmrecover bridge-service-serve --config .easy-node-logs/bridge-service-config.json --config-sha256 "$CONFIG_HASH" --addr 127.0.0.1:18980 --rps 2 --abuse-log .easy-node-logs/bridge-abuse.jsonl --access-code-sha256 HASH`
- `go run ./cmd/gpmrecover bridge-service-deploy-pack --out-dir .easy-node-logs/bridge-deploy --public-host bridge.example --config-sha256 "$CONFIG_HASH" --access-code-sha256 HASH`
- `bash ./scripts/integration_access_bridge_service_serve.sh`
- `bash ./scripts/access_bridge_service_smoke.sh --base-url https://bridge.example --path-id helper-web --code CODE --expect-helper-id helper-demo --expect-org-id freenews-demo --summary-json .easy-node-logs/bridge-service-smoke.json`
- `bash ./scripts/access_bridge_deployment_evidence.sh --smoke-summary-json .easy-node-logs/bridge-service-smoke.json --config-json .easy-node-logs/bridge-service-config.json --deploy-pack-dir .easy-node-logs/bridge-deploy --expect-helper-id helper-demo --expect-org-id freenews-demo --summary-json .easy-node-logs/bridge-deployment-evidence.json`
- `bash ./scripts/access_bridge_host_install_check.sh --deploy-pack-dir .easy-node-logs/bridge-deploy --config-json .easy-node-logs/bridge-service-config.json --summary-json .easy-node-logs/bridge-host-install-check.json`
- `go run ./cmd/gpmrecover check --pack .easy-node-logs/access-pack.signed.json --trust-store .easy-node-logs/recovery-trust.json --timeout-sec 8`
- `go run ./cmd/gpmrecover trust-remove --trust-store .easy-node-logs/recovery-trust.json --org-id freenews-demo --key-id KEY_ID`

Text handoff flow:
- `go run ./cmd/gpmrecover text-export --kind access-pack --in .easy-node-logs/access-pack.signed.json --out .easy-node-logs/access-pack.txt`
- `go run ./cmd/gpmrecover text-export --kind bridge-invite --in .easy-node-logs/bridge-invite.signed.json --out .easy-node-logs/bridge-invite.txt`
- `go run ./cmd/gpmrecover text-export --kind trust-store --in .easy-node-logs/recovery-trust.json --out .easy-node-logs/recovery-trust.txt`
- `go run ./cmd/gpmrecover text-export --kind bridge-helper-registry --in .easy-node-logs/access-recovery-demo/bridge-helper-registry.json --out .easy-node-logs/bridge-helper-registry.txt`
- `go run ./cmd/gpmrecover text-export --kind bridge-helper-registry-signed --in .easy-node-logs/access-recovery-demo/bridge-helper-registry.signed.json --out .easy-node-logs/bridge-helper-registry.signed.txt`
- `go run ./cmd/gpmrecover text-import --text-file .easy-node-logs/access-pack.txt --expect-kind access-pack --out .easy-node-logs/access-pack.imported.json`
- `go run ./cmd/gpmrecover text-import --text-file .easy-node-logs/bridge-invite.txt --expect-kind bridge-invite --out .easy-node-logs/bridge-invite.imported.json`
- `go run ./cmd/gpmrecover text-import --text-file .easy-node-logs/recovery-trust.txt --expect-kind trust-store --out .easy-node-logs/recovery-trust.imported.json`
- `go run ./cmd/gpmrecover text-import --text-file .easy-node-logs/bridge-helper-registry.txt --expect-kind bridge-helper-registry --out .easy-node-logs/bridge-helper-registry.imported.json`
- `go run ./cmd/gpmrecover text-import --text-file .easy-node-logs/bridge-helper-registry.signed.txt --expect-kind bridge-helper-registry-signed --out .easy-node-logs/bridge-helper-registry.signed.imported.json`
- `go run ./cmd/gpmrecover qr-png --text-file .easy-node-logs/access-pack.txt --out .easy-node-logs/access-pack.qr.png --size 768`

The text format starts with `GPMREC1.` and carries compact JSON as base64url. It is meant for chat messages, emails, printed handoffs, and QR codes. The CLI can render a text handoff as a PNG, and the browser recovery page can render/download a QR locally from the current text handoff.
`text-export`, `text-import`, and `qr-png` validate that the payload matches its envelope kind, that single trusted-key handoffs are usable rather than disabled, and that signed payloads are not expired and carry a well-formed Ed25519 signature field, so a raw helper registry cannot be mislabeled as a signed helper registry handoff.

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
- `bridge-policy --signed-helper-registry` verifies the registry artifact against the same public key/trust store, requires the registry organization to match the bridge invite organization, then applies the helper registry gate
- `bridge-policy --require-helper-registry` fails if the helper registry was accidentally omitted from a production policy run
- `bridge-registry-sign` and `bridge-registry-verify` publish helper registries as signed short-lived organization artifacts before extracting raw registry JSON for policy checks
- `bridge-registry-check` summarizes active/quarantined/disabled helper counts and can fail closed for a specific active helper/org before publishing or using an invite
- `bridge-registry-upsert-helper` adds or updates helper registry entries with validation and normalized output
- `bridge-registry-set-status` changes helper status with validation and a required reason when quarantining or disabling a helper
- helper policy requires active registry helpers to publish an abuse-report URL and a short rate-limit policy before bridge paths are accepted
- helper registry validation rejects active helpers missing abuse-report/rate-limit metadata or carrying stale quarantine reasons, and rejects quarantined/disabled helpers without a reason
- the helper contact and helper paths are shown only after signature, expiry, org id, and trusted-key checks pass
- the browser gives copy/open actions for the invite id, helper id, helper contact, helper abuse-report URL, and verified helper paths
- the helper registry is the first service-level rotation/quarantine control; a public bridge service still needs live rate-limit and abuse-report enforcement before launch
- `demo-bundle` emits a static `.well-known/gpm` publish folder so operators can test online artifact publication without inventing filenames by hand
- `fetch-publication` downloads the static publication index and same-origin referenced artifacts into a local folder, but marks trust as unverified so signature/trust-store verification remains a separate step
- `bridge-service-config` turns a verified signed invite plus signed helper registry into a fail-closed service config containing the signed invite validity window, helper abuse-report URL, rate-limit policy, active window, registry identity, and verified path hints
- `bridge-service-check` is the first runtime preflight hook: it rejects unsigned/stale service configs, expired invite/helper windows, missing abuse/rate commitments, unknown paths, and manual/external-app paths before a helper bridge serves traffic
- `bridge-service-code-hash` derives an out-of-band access-code hash so helpers do not store plaintext invite codes in their service config
- `bridge-service-serve` wraps that preflight in a minimal HTTP service with `/health`, `/bridge/{path_id}`, required `X-GPM-Bridge-Code` ticket gating for normal deploys, optional config-hash pinning, per-source fixed-window limits, optional signed-path redirects, and `/abuse` JSONL logging
- `bridge-service-serve` emits no-store/no-referrer/nosniff headers so ticket codes and recovery URLs are not cached or leaked through browser referrers
- `bridge-service-deploy-pack` emits a helper-owned env file, shell wrapper, README, hardened systemd unit template, and Caddy/nginx HTTPS reverse-proxy examples for Linux deployment
- `access_bridge_service_smoke.sh` records deployed bridge health, access-code-gated path availability, helper/org/registry identity, security headers, and abuse endpoint acceptance into a JSON summary
- `access_bridge_deployment_evidence.sh` binds smoke output to the staged service config and deploy pack, checks config/deploy file hashes, confirms helper/org/registry identity, and verifies deploy-pack hardening flags plus proxy header overwrite rules
- `access_bridge_host_install_check.sh` records the staged/installed host file checks for env, wrapper, systemd hardening, config hash, access-code gate, loopback bind, and proxy X-Forwarded-For overwrite behavior

Operator bridge install checklist:
- generate a service config only from a verified signed bridge invite plus signed helper registry
- run `bridge-service-check` for each served `path_id` before starting or restarting the service
- derive an access-code hash out of band and deploy only the hash; plaintext access codes stay out of configs, logs, screenshots, and shared evidence
- pass access codes through the `X-GPM-Bridge-Code` header; query-string `?code=` access is disabled by default and should remain off unless a constrained fallback channel truly needs it
- use `bridge-service-deploy-pack` for helper-owned env/wrapper/systemd/proxy templates, pin the staged service config with `--config-sha256`, then bind the service to loopback behind Caddy or nginx HTTPS
- verify helper identity against the signed registry: helper id, contact URL, abuse-report URL, rate-limit policy, active window, and control of the public HTTPS host
- record smoke evidence with `access_bridge_service_smoke.sh` from another machine or network path, then run `access_bridge_deployment_evidence.sh` to capture config/deploy hashes, helper/org/registry identity, proxy header behavior, and hardening checks
- record host install evidence with `access_bridge_host_install_check.sh` before public handoff
- fail closed on helper rotation or quarantine: stop service, mark the helper quarantined/disabled, re-sign the helper registry, redistribute the signed registry, and regenerate configs before resuming
- rotate access codes after suspected exposure; rotate the organization key only if the signing key is suspected compromised

`check` keeps trust and reachability separate:
- it verifies the pack before probing anything
- it marks listed entries as trusted because they came from a verified pack
- it reports whether each trusted entry is reachable, unreachable, timed out, or skipped
- it skips paths that require external apps by default
- it skips direct `.onion` probing by default so the tool does not leak onion lookups through normal DNS

First browser surface:
- `apps/web/recovery.html`
- browser-local bridge-invite verification has a deterministic Node/VM smoke check in `scripts/integration_recovery_browser_smoke.js`
- runs local pack, bridge-invite, and trust-store parsing in the browser
- imports an optional helper registry and enforces active/quarantined/disabled helper status before showing bridge paths
- imports a signed helper registry artifact, verifies it against the local trust store, and extracts the raw registry for bridge-invite policy checks
- preserves signed helper registry provenance after extraction and rejects bridge invites from a different organization
- lets a tester add/remove trusted organization public keys without hand-editing JSON
- validates trusted-key handoffs, imported trust stores, and browser trust-store add/remove writes before persisting them locally, including public-key length, derived key-id matching, duplicate org/key rejection, and disabled single-key handoff rejection
- validates the current browser trust store again during pack, bridge-invite, and signed helper-registry verification so manual JSON edits cannot bypass duplicate-key or malformed-key checks
- copies or downloads the current trust store for handoff to another device
- exports/imports `GPMREC1` text handoffs for signed packs, bridge invites, trust stores, helper registries, signed helper registries, and single trusted keys
- browser pack/bridge text export preserves the original signature field instead of exporting canonical unsigned payloads
- renders and downloads a local QR PNG from the current `GPMREC1` text handoff
- validates text handoff payloads before browser QR rendering/download so a bad pasted handoff is not turned into a QR
- can scan a QR image into the text handoff field with native `BarcodeDetector` support or the bundled browser scanner fallback
- verifies the Ed25519 signature with Web Crypto when the browser supports it
- labels bridge-invite helper policy results as signed-registry or unsigned-registry so beta users can distinguish verified registry snapshots from local/raw testing inputs
- lists trusted access/helper paths only after signature, expiry, org id, and trusted-key checks pass
- shows signed helper contact/copy actions for verified bridge invites
- does not run network reachability checks yet because browser cross-origin checks are not reliable enough for the beta trust decision

Operator runbook:
- `docs/access-recovery-operator-runbook.md`

## MVP Cut

Do first:
- access-pack schema
- bridge-invite schema
- access-pack signing/verification library
- bridge-invite signing/verification library
- CLI sign/verify for packs and bridge invites
- CLI bridge-invite policy gate for helper/contact diversity
- CLI signed helper registry publication/verification artifact
- CLI bridge helper registry gate for active/quarantined/disabled helpers
- CLI bridge helper registry summary/check command for operator review
- CLI bridge helper registry add/update command for helper onboarding
- CLI bridge helper registry status-change command for quarantine/re-enable workflows
- CLI reachability check that does not confuse reachable with trusted
- local trust-store file
- browser verifier/import screen
- UI trust-key add/remove flow
- browser signed helper registry verify/extract flow
- text handoff export/import for packs, bridge invites, trust stores, helper registries, signed helper registries, and trusted keys
- QR PNG export in the CLI
- QR rendering/download in the browser
- QR image import in the browser with native scanning or bundled fallback
- helper launch/copy flows for bridge invites
- one-command end-to-end demo bundle
- example pack
- docs explaining how a user visualizes it

Do next:
- run host install checks plus bridge smoke against a real helper host and record the evidence bundle

Do later:
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
