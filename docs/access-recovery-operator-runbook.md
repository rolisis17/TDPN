# Access Recovery Operator Runbook

This runbook is for the first Access Recovery beta pilot: one organization, a small trusted helper set, signed recovery artifacts, and browser-local verification by users.

The MVP does not require a VPN tunnel, blockchain, credits, staking, public exits, or a native app. Treat every artifact channel as untrusted until the local trust store verifies the organization key and signature.

Command snippets in this runbook assume a Bash-compatible shell on Linux, WSL, or macOS. On native Windows, run them from WSL/Git Bash or translate the shell variables and line continuations before use.

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
  --helper-id helper-demo \
  --helper-name "Demo bridge helper" \
  --helper-url https://helper.example/freenews/bootstrap \
  --helper-contact mailto:bridge-helper@example.com
```

2. Keep `recovery.key` offline or in a controlled operator machine. Share only:

- `recovery.pub`
- `recovery-trust.json`
- `recovery-trusted-key.json`, `recovery-trusted-key.txt`, or `recovery-trusted-key.qr.png` for first-time trust handoff
- signed packs and bridge invites
- signed helper registries
- `public/.well-known/gpm/` when testing static online publication from a site or mirror
- `GPMREC1` text/QR handoffs derived from those signed artifacts

3. Verify the bundle before sharing:

```sh
go run ./cmd/gpmrecover verify --pack .easy-node-logs/access-recovery-demo/access-pack.signed.json --trust-store .easy-node-logs/access-recovery-demo/recovery-trust.json --show-paths
go run ./cmd/gpmrecover bridge-policy --invite .easy-node-logs/access-recovery-demo/bridge-invite.signed.json --trust-store .easy-node-logs/access-recovery-demo/recovery-trust.json --signed-helper-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.signed.json --require-helper-registry
go run ./cmd/gpmrecover bridge-service-config --invite .easy-node-logs/access-recovery-demo/bridge-invite.signed.json --trust-store .easy-node-logs/access-recovery-demo/recovery-trust.json --signed-helper-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.signed.json --out .easy-node-logs/access-recovery-demo/bridge-service-config.json
go run ./cmd/gpmrecover bridge-service-check --config .easy-node-logs/access-recovery-demo/bridge-service-config.json --path-id helper-web
go run ./cmd/gpmrecover bridge-service-code-generate --code-out .easy-node-logs/access-recovery-demo/bridge-code.txt --hash-out .easy-node-logs/access-recovery-demo/bridge-code-hash.json
CONFIG_HASH="$(sha256sum .easy-node-logs/access-recovery-demo/bridge-service-config.json | awk '{print $1}')"
CODE_HASH="$(jq -r '.sha256' .easy-node-logs/access-recovery-demo/bridge-code-hash.json)"
go run ./cmd/gpmrecover bridge-service-serve --config .easy-node-logs/access-recovery-demo/bridge-service-config.json --config-sha256 "$CONFIG_HASH" --addr 127.0.0.1:18980 --rps 2 --abuse-log .easy-node-logs/access-recovery-demo/bridge-abuse.jsonl --access-code-sha256 "$CODE_HASH"
go run ./cmd/gpmrecover bridge-service-deploy-pack --out-dir .easy-node-logs/access-recovery-demo/bridge-deploy --public-host bridge.example --config-sha256 "$CONFIG_HASH" --access-code-sha256 "$CODE_HASH"
```

4. If testing online publication, upload `public/.well-known/gpm/` and fetch it from another machine before verification:

```sh
go run ./cmd/gpmrecover fetch-publication \
  --index-url https://freenews.example/.well-known/gpm/recovery-index.json \
  --out-dir .easy-node-logs/access-recovery-fetched
```

## Bridge Service Install Checklist

Use this checklist before a helper bridge is announced to users. Keep the bridge service on loopback and expose it only through the helper's HTTPS reverse proxy.

1. Build a fail-closed service config from a verified signed invite and signed helper registry:

```sh
go run ./cmd/gpmrecover bridge-service-config \
  --invite .easy-node-logs/access-recovery-demo/bridge-invite.signed.json \
  --trust-store .easy-node-logs/access-recovery-demo/recovery-trust.json \
  --signed-helper-registry .easy-node-logs/access-recovery-demo/bridge-helper-registry.signed.json \
  --out .easy-node-logs/access-recovery-demo/bridge-service-config.json
go run ./cmd/gpmrecover bridge-service-check \
  --config .easy-node-logs/access-recovery-demo/bridge-service-config.json \
  --path-id helper-web
CONFIG_HASH="$(sha256sum .easy-node-logs/access-recovery-demo/bridge-service-config.json | awk '{print $1}')"
```

2. Create a high-entropy access code out of band and deploy only the hash. Do not place the plaintext code in config files, shell history, service units, tickets, screenshots, or smoke summaries:

```sh
go run ./cmd/gpmrecover bridge-service-code-generate \
  --code-out .easy-node-logs/access-recovery-demo/bridge-code.txt \
  --hash-out .easy-node-logs/access-recovery-demo/bridge-code-hash.json
CODE_HASH="$(jq -r '.sha256' .easy-node-logs/access-recovery-demo/bridge-code-hash.json)"
```

3. Generate the helper deploy pack and install only the generated env, wrapper, service unit, and selected HTTPS reverse-proxy example on the helper host:

```sh
go run ./cmd/gpmrecover bridge-service-deploy-pack \
  --out-dir .easy-node-logs/access-recovery-demo/bridge-deploy \
  --public-host bridge.example \
  --config-sha256 "$CONFIG_HASH" \
  --access-code-sha256 "$CODE_HASH"
```

4. Bind the bridge service to loopback, for example `127.0.0.1:18980`, and put Caddy or nginx in front of it with HTTPS enabled. The public endpoint must be `https://bridge.example`, proxying only to the local bridge listener. Keep query-string access codes disabled; pass access codes through `X-GPM-Bridge-Code`.

5. Before sharing the bridge URL or access code, verify helper identity:

- the helper id, display name, contact URL, abuse-report URL, rate-limit policy, and active window match the signed helper registry
- `bridge-policy --signed-helper-registry --require-helper-registry` passes for the invite
- `bridge-service-check` passes for every served `path_id`
- the operator can reach the helper through the registry contact path and confirm they control the HTTPS host

6. Record smoke evidence from a different machine or network path:

```sh
bash ./scripts/access_bridge_service_smoke.sh \
  --base-url https://bridge.example \
  --path-id helper-web \
  --code-file .easy-node-logs/access-recovery-demo/bridge-code.txt \
  --expect-helper-id helper-demo \
  --expect-org-id freenews-demo \
  --summary-json .easy-node-logs/bridge-service-smoke.json

bash ./scripts/access_bridge_deployment_evidence.sh \
  --smoke-summary-json .easy-node-logs/bridge-service-smoke.json \
  --config-json .easy-node-logs/access-recovery-demo/bridge-service-config.json \
  --deploy-pack-dir .easy-node-logs/access-recovery-demo/bridge-deploy \
  --expect-helper-id helper-demo \
  --expect-org-id freenews-demo \
  --summary-json .easy-node-logs/bridge-deployment-evidence.json

bash ./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir .easy-node-logs/access-recovery-demo/bridge-deploy \
  --config-json .easy-node-logs/access-recovery-demo/bridge-service-config.json \
  --summary-json .easy-node-logs/bridge-host-install-check.json

./scripts/easy_node.sh access-bridge-pilot-evidence-bundle \
  --base-url https://bridge.example \
  --path-id helper-web \
  --code-file .easy-node-logs/access-recovery-demo/bridge-code.txt \
  --config-json .easy-node-logs/access-recovery-demo/bridge-service-config.json \
  --deploy-pack-dir .easy-node-logs/access-recovery-demo/bridge-deploy \
  --expect-helper-id helper-demo \
  --expect-org-id freenews-demo \
  --summary-json .easy-node-logs/access-recovery-demo/access-bridge-pilot-evidence-summary.json

./scripts/easy_node.sh access-bridge-pilot-evidence-bundle-verify \
  --summary-json .easy-node-logs/access-recovery-demo/access-bridge-pilot-evidence-summary.json
```

Keep the smoke JSON, deployment-evidence JSON, host-install-check JSON, deployed service config hash, signed invite id, signed registry id, proxy config hashes, `manifest.sha256`, `<bundle>.tar.gz`, `<bundle>.tar.gz.sha256`, and operator timestamp in the incident/evidence folder. Do not include the plaintext access code in evidence shared beyond the helper/operator pair; the bundle skips access-code/private-key-looking deploy-pack files and the verifier rejects manifest tamper, tar checksum mismatch, unsafe tar paths, and tar links.

7. Fail closed on rotation or quarantine:

- if the helper contact, HTTPS host, abuse endpoint, rate-limit commitment, or operator identity cannot be verified, stop the service and quarantine the helper in the registry before issuing new invites
- if a helper is quarantined or disabled, re-sign and redistribute the helper registry; old bridge service configs must be regenerated from the updated signed registry before service resumes
- rotate the access code whenever it may have reached an untrusted channel; keep the same signed invite only if helper identity and expiry are still valid
- rotate the organization signing key only when the signing key is suspected compromised, not for ordinary helper quarantine

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
