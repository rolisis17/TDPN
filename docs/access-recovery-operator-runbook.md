# Access Recovery Operator Runbook

This runbook is for the first Access Recovery beta pilot: one organization, a small trusted helper set, signed recovery artifacts, and browser-local verification by users.

The MVP does not require a VPN tunnel, blockchain, credits, staking, public exits, or a native app. Treat every artifact channel as untrusted until the local trust store verifies the organization key and signature.

## Roles

- Organization operator: owns the recovery signing key, publishes signed packs and bridge invites, and decides helper trust.
- Helper operator: provides temporary bridge/contact paths for the organization and can be quarantined without rotating the organization key.
- End user: imports a trust store plus a signed pack or bridge invite into `apps/web/recovery.html`, then follows only verified paths.

## Operator Setup

1. Generate a local demo or pilot bundle:

```sh
go run ./cmd/gpmrecover demo-bundle \
  --out-dir .easy-node-logs/access-recovery-demo \
  --org-id freenews-demo \
  --org-name "FreeNews Demo" \
  --base-url https://freenews.example \
  --helper-id helper-1 \
  --helper-name "Helper 1" \
  --helper-url https://helper.example/freenews/bootstrap \
  --helper-contact mailto:bridge-helper@example.com
```

2. Keep `recovery.key` offline or in a controlled operator machine. Share only:

- `recovery.pub`
- `recovery-trust.json`
- `recovery-trusted-key.json`, `recovery-trusted-key.txt`, or `recovery-trusted-key.qr.png` for first-time trust handoff
- signed packs and bridge invites
- signed helper registries
- `GPMREC1` text/QR handoffs derived from those signed artifacts

3. Verify the bundle before sharing:

```sh
go run ./cmd/gpmrecover verify --pack .easy-node-logs/access-recovery-demo/access-pack.signed.json --trust-store .easy-node-logs/access-recovery-demo/recovery-trust.json --show-paths
go run ./cmd/gpmrecover bridge-policy --invite .easy-node-logs/access-recovery-demo/bridge-invite.signed.json --trust-store .easy-node-logs/access-recovery-demo/recovery-trust.json --signed-helper-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.signed.json --require-helper-registry
```

## Helper Onboarding

1. Add or update a helper entry without hand-editing JSON:

```sh
go run ./cmd/gpmrecover bridge-registry-upsert-helper \
  --helper-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.json \
  --helper-id helper-1 \
  --org-ids freenews-demo \
  --display-name "Helper 1" \
  --contact-url https://helper.example/contact \
  --abuse-report-url https://helper.example/abuse \
  --rate-limit-policy "beta cap: per-user and per-source limits enforced"
```

2. Check the helper before signing the registry:

```sh
go run ./cmd/gpmrecover bridge-registry-check \
  --helper-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.json \
  --helper-id helper-1 \
  --org-id freenews-demo \
  --require-active
```

3. Sign the helper registry as a short-lived organization artifact:

```sh
go run ./cmd/gpmrecover bridge-registry-sign \
  --helper-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.json \
  --org-id freenews-demo \
  --org-name "FreeNews Demo" \
  --private-key-file .easy-node-logs/access-recovery-demo/recovery.key \
  --out .easy-node-logs/access-recovery-demo/bridge-helper-registry.signed.json
```

## User Handoff

Send users only the minimum needed for the situation:

- first-time trust: `recovery-trusted-key.json`, `recovery-trusted-key.txt`, `recovery-trusted-key.qr.png`, or a full `recovery-trust.json` from a known-safe channel
- normal recovery: signed access pack plus trust store
- blocked/bridged recovery: signed bridge invite, signed helper registry, and trust store

For non-demo or rotated trust stores, export a single trusted-key handoff from the trust store:

```sh
go run ./cmd/gpmrecover trust-export-key \
  --trust-store .easy-node-logs/access-recovery-demo/recovery-trust.json \
  --org-id freenews-demo \
  --key-id KEY_ID \
  --out .easy-node-logs/access-recovery-demo/recovery-trusted-key.json \
  --text-out .easy-node-logs/access-recovery-demo/recovery-trusted-key.txt
```

User flow:

1. Open `apps/web/recovery.html`.
2. Import or paste the trust store.
3. Import/paste/scan the signed pack or bridge invite.
4. For bridge invites, import/paste/scan the signed helper registry, then click `Verify Signed`.
5. Click `Verify`.
6. Use only paths shown under `Trusted Paths`.

## Quarantine And Rotation

Quarantine a helper immediately if the contact path is compromised, abusive, stale, or no longer controlled by the expected operator:

```sh
go run ./cmd/gpmrecover bridge-registry-set-status \
  --helper-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.json \
  --helper-id helper-1 \
  --status quarantined \
  --reason "operator requested maintenance window"
```

Then re-sign and redistribute the helper registry. Existing bridge invites whose helper no longer passes registry policy should fail closed when checked with the updated signed registry. Active helpers must keep an abuse-report URL and a short rate-limit policy in the signed registry, so users and operators can see where abuse reports go and what traffic limits the helper claims to enforce.

Rotate the organization key only when the signing key itself is suspected compromised. Helper failures should normally be handled by registry quarantine, not key rotation.

## Expiry Policy

- Bridge invites must be short-lived, currently 14 days maximum.
- Signed helper registries must be short-lived, currently 30 days maximum.
- Single trusted-key handoffs must be usable; disabled or expired single-key handoffs are rejected.
- Full trust stores may retain disabled or expired keys for audit history, but those keys cannot verify artifacts.

## Incident Response

If a user reports an unsafe or broken recovery path:

1. Ask for the signed artifact filename, invite id or pack id, helper id, and visible error text.
2. Run `bridge-policy` with the latest signed helper registry.
3. If the helper is at fault, quarantine it, re-sign the registry, and send the updated signed registry handoff.
4. If the signed pack or invite is stale, generate a fresh signed artifact with a new expiry.
5. If the organization signing key is suspected compromised, stop using every artifact signed by that key, generate a new trust store, and communicate the new key through an out-of-band trusted channel.

## Launch Guardrails

- Never ask users to trust an unsigned pack, unsigned bridge invite, or raw helper registry for a beta recovery decision.
- Never treat reachability as trust. A reachable path can still be unsafe.
- Do not publish public helper onboarding until the signed abuse-report/rate-limit commitments are backed by live service enforcement and helper ownership checks.
- Keep the first pilot small enough that every helper can be manually contacted and removed quickly.
