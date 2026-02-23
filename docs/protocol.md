# Protocol v0 (MVP)

## Scope
This is a two-hop decentralized privacy path:
1. Client -> Entry (outer tunnel)
2. Entry -> Exit (opaque forwarding for client<->exit inner tunnel)

A single `node` program can run any combination of roles (`client`, `entry`, `exit`, `directory`, `issuer`).

## Security Goal
- Entry must not learn final internet destination.
- Exit must not learn end-user identity.
- No single coordinator for data-plane operation.

## Components
- Directory: publishes signed relay descriptors.
- Issuer: mints short-lived capability tokens.
- Entry: accepts client ingress and forwards opaque inner packets.
- Exit: validates token, enforces tier policy, and provides internet egress.
- Client: builds 2-hop path and drives sessions.

Directory federation note:
- A directory can pull descriptors from peer directories, verify peer signatures, and republish merged descriptors signed by its own key.
- Peer sync can use ETag-based incremental pulls and hop-limited loop resistance (`origin_operator`, `hop_count`).
- Directories can also push signed relay descriptors to peers (`/v1/gossip/relays`) for faster anti-entropy convergence.
- Directories publish a signed peer-membership feed (`/v1/peers`) so seed peers can discover additional operators over time, including optional peer pubkey hints.

## Relay Descriptor
```json
{
  "relay_id": "exit-us-01",
  "role": "exit",
  "operator_id": "op-001",
  "origin_operator": "op-001",
  "hop_count": 0,
  "pub_key": "base64-ed25519",
  "endpoint": "198.51.100.22:51820",
  "control_url": "https://198.51.100.22:8084",
  "country_code": "US",
  "geo_confidence": 0.95,
  "region": "us-east",
  "reputation_score": 0.92,
  "uptime_score": 0.95,
  "capacity_score": 0.80,
  "abuse_penalty": 0.04,
  "bond_score": 0.70,
  "stake_score": 0.60,
  "capabilities": ["wg", "tiered-policy"],
  "valid_until": "2026-02-20T00:00:00Z",
  "signature": "base64-signature"
}
```

## Capability Token (signed)
Claims (JSON payload):
- `iss`: issuer id
- `aud`: `exit` (client access) or `provider` (provider role)
- `sub`: optional client subject identity
- `token_type`: `client_access` or `provider_role`
- `cnf_ed25519`: base64url Ed25519 pubkey used to validate `token_proof`
- `exp`: unix expiry (5-15 min)
- `jti`: unique token id
- `tier`: `1 | 2 | 3`
- `allow_ports`: optional whitelist
- `deny_ports`: optional blacklist
- `bw_kbps`: bandwidth ceiling
- `conn_rate`: new flow rate limit
- `max_conns`: concurrent flow cap
- `exit_scope`: optional allowed exit IDs

Serialization for MVP:
- `base64url(payload) + "." + base64url(ed25519_signature(payload))`

## Control Plane Endpoints
- `GET /v1/relays`
  - Returns signed descriptors from one directory operator.
- `GET /v1/selection-feed`
  - Returns signed time-bounded exit selection score metadata (`reputation_score`, `uptime_score`, `capacity_score`, `abuse_penalty`, `bond_score`, `stake_score`).
- `GET /v1/trust-attestations`
  - Returns signed time-bounded trust attestations (`reputation_score`, `uptime_score`, `capacity_score`, `abuse_penalty`, `bond_score`, `stake_score`, `confidence`).
- `POST /v1/gossip/relays`
  - Peer directory push endpoint for signed descriptor anti-entropy.
- `GET /v1/peers`
  - Signed peer-membership feed for decentralized directory discovery.
- `POST /v1/token`
  - Returns capability token for requester and effective tier.
  - Request includes `token_type` and `pop_pub_key`; response token is bound to that key via `cnf_ed25519`.
- `POST /v1/provider/relay/upsert`
  - Provider-role token gated relay advertisement endpoint for directory ingestion.
  - Requires `aud=provider` + `token_type=provider_role`.
- `GET /v1/admin/sync-status`
  - Directory admin endpoint exposing latest peer/issuer sync quorum outcome (`success_sources`, distinct `source_operators`, quorum state, error).
  - Requires `X-Admin-Token`.
- `GET /v1/admin/governance-status`
  - Directory admin endpoint exposing effective adjudication policy (`meta_min_votes`, final vote thresholds/ratio), upstream dispute/appeal signal counts, upstream operator counts/IDs, suppressed-vs-published adjudication counters, and per-relay suppression details.
  - Requires `X-Admin-Token`.
- `GET /v1/admin/peer-status`
  - Directory admin endpoint exposing configured/discovered peer membership, eligibility, cooldown state, voter/operator counts, and last sync success/failure metadata.
  - Requires `X-Admin-Token`.
- `GET /v1/pubkeys`
  - Returns current and previous issuer pubkeys to support key rollover windows.
- `GET /v1/trust/relays`
  - Returns signed issuer trust attestations derived from subject lifecycle state.
- `POST /v1/admin/subject/upsert`
- `POST /v1/admin/subject/promote`
- `POST /v1/admin/subject/reputation/apply`
- `POST /v1/admin/subject/bond/apply`
- `POST /v1/admin/subject/dispute`
- `POST /v1/admin/subject/dispute/clear`
- `POST /v1/admin/subject/appeal/open`
- `POST /v1/admin/subject/appeal/resolve`
- `POST /v1/admin/subject/recompute-tier`
- `GET /v1/admin/subject/get?subject=<id>`
- `GET /v1/admin/audit`
- `POST /v1/admin/revoke-token`
- `GET /v1/revocations`
- `GET /v1/metrics` (exit counters)

Revocation feed shape:
```json
{
  "issuer": "issuer-local",
  "key_epoch": 7,
  "min_token_epoch": 7,
  "version": 42,
  "generated_at": 1771576000,
  "expires_at": 1771576030,
  "revocations": [{"jti":"123","until":1771576600}],
  "signature": "base64url-ed25519-signature"
}
```

Selection feed shape:
```json
{
  "operator": "op-001",
  "generated_at": 1771576000,
  "expires_at": 1771576030,
  "scores": [
    {
      "relay_id": "exit-us-01",
      "role": "exit",
      "reputation_score": 0.92,
      "uptime_score": 0.95,
      "capacity_score": 0.80,
      "abuse_penalty": 0.04,
      "bond_score": 0.70,
      "stake_score": 0.60
    }
  ],
  "signature": "base64url-ed25519-signature"
}
```

Trust-attestation feed shape:
```json
{
  "operator": "op-001",
  "generated_at": 1771576000,
  "expires_at": 1771576030,
  "attestations": [
    {
      "relay_id": "exit-us-01",
      "role": "exit",
      "operator_id": "op-001",
      "reputation_score": 0.92,
      "uptime_score": 0.95,
      "capacity_score": 0.80,
      "abuse_penalty": 0.04,
      "bond_score": 0.70,
      "stake_score": 0.60,
      "confidence": 0.90,
      "tier_cap": 1,
      "dispute_until": 1771579999,
      "appeal_until": 1771580999,
      "dispute_case_id": "case-dispute-1",
      "dispute_evidence_ref": "evidence://dispute-1",
      "appeal_case_id": "case-appeal-1",
      "appeal_evidence_ref": "evidence://appeal-1"
    }
  ],
  "signature": "base64url-ed25519-signature"
}
```

Directory peer-membership feed shape:
```json
{
  "operator": "op-001",
  "generated_at": 1771576000,
  "expires_at": 1771576045,
  "peers": [
    "https://dir-a.example",
    "https://dir-b.example"
  ],
  "peer_hints": [
    {
      "url": "https://dir-a.example",
      "operator": "op-a",
      "pub_key": "base64url-ed25519-pubkey"
    }
  ],
  "signature": "base64url-ed25519-signature"
}
```

## Directory Trust
- Client verifies descriptor signatures against directory pubkey.
- Client verifies selection feed signatures against directory pubkey.
- Client verifies trust-attestation feed signatures against directory pubkey.
- Strict mode supports trusted key pinning (`DIRECTORY_TRUST_STRICT=1`) with optional TOFU bootstrap.
- Directory signing keys can auto-rotate (`DIRECTORY_KEY_ROTATE_SEC`) with bounded rollover history (`DIRECTORY_KEY_HISTORY`) published at `/v1/pubkeys` to preserve trust continuity.
- Client can query multiple directories (`DIRECTORY_URLS`) and require source quorum (`DIRECTORY_MIN_SOURCES`).
- Client can also require distinct operator quorum (`DIRECTORY_MIN_OPERATORS`, override `CLIENT_DIRECTORY_MIN_OPERATORS`) so one operator cannot satisfy quorum via multiple endpoints.
- Relay descriptors can require multi-source agreement (`DIRECTORY_MIN_RELAY_VOTES`) before selection; votes are deduped by operator identity when available.
- Selection-feed score overrides can require multi-source agreement (`CLIENT_SELECTION_FEED_MIN_VOTES`) before use.
- Trust-feed attestation overrides can require multi-source agreement (`CLIENT_TRUST_FEED_MIN_VOTES`) before use.
- Entry also verifies descriptor signatures/pubkeys during `exit_id` route resolution and can enforce source/operator quorum plus vote thresholds (`ENTRY_DIRECTORY_MIN_SOURCES`, `ENTRY_DIRECTORY_MIN_OPERATORS`, `ENTRY_DIRECTORY_MIN_RELAY_VOTES`).
- Entry binds each active session to the first observed client UDP source by default (source-lock) and drops mismatched sources; optional delayed rebind can be enabled with `ENTRY_CLIENT_REBIND_SEC`.
- Directory peer sync can run with trusted peer key pinning (`DIRECTORY_PEER_TRUST_STRICT`) and optional TOFU bootstrap (`DIRECTORY_PEER_TRUST_TOFU`).
- Directory peer sync can require distinct source operators (`DIRECTORY_PEER_MIN_OPERATORS`, fallback `DIRECTORY_MIN_OPERATORS`) before accepting a sync round.
- Directory peer sync conflict handling can require matching peer descriptor votes (`DIRECTORY_PEER_MIN_VOTES`) per relay key.
- Directory peer sync can require matching peer score votes (`DIRECTORY_PEER_SCORE_MIN_VOTES`), trust-attestation votes (`DIRECTORY_PEER_TRUST_MIN_VOTES`), dispute votes (`DIRECTORY_PEER_DISPUTE_MIN_VOTES`), appeal votes (`DIRECTORY_PEER_APPEAL_MIN_VOTES`), and enforce hop limits (`DIRECTORY_PEER_MAX_HOPS`) to resist sync loops; votes are deduped per source operator.
- Directory records latest peer/issuer sync quorum outcomes for operator accountability (`/v1/admin/sync-status`).
- Directory admin can inspect current adjudication policy, aggregate disputed/appeal publication state, and per-relay suppression details via `/v1/admin/governance-status`.
- Directory peer gossip fanout can be enabled (`DIRECTORY_GOSSIP_SEC`, `DIRECTORY_GOSSIP_FANOUT`) for lower-latency relay propagation.
- Directory can also ingest issuer-signed trust attestations (`DIRECTORY_ISSUER_TRUST_URLS`) and require issuer operator quorum (`DIRECTORY_ISSUER_MIN_OPERATORS`, fallback `DIRECTORY_MIN_OPERATORS`) plus issuer trust/dispute/appeal vote thresholds (`DIRECTORY_ISSUER_TRUST_MIN_VOTES`, `DIRECTORY_ISSUER_DISPUTE_MIN_VOTES`, `DIRECTORY_ISSUER_APPEAL_MIN_VOTES`) before using those signals (votes are deduped per issuer operator).
- For dispute/appeal metadata aggregation, tier-cap uses vote consensus and expiry windows use median time selection to reduce outlier influence.
- For adjudication metadata integrity, `case_id` and `evidence_ref` are selected and published as a voted pair; mismatched cross-source field mixing is rejected.
- Adjudication metadata fields (`case_id`, `evidence_ref`) can require independent vote quorum before publication via `DIRECTORY_ADJUDICATION_META_MIN_VOTES`.
- Final dispute/appeal publication in directory trust feed can additionally require configurable aggregated vote thresholds and ratio quorum (`DIRECTORY_FINAL_DISPUTE_MIN_VOTES`, `DIRECTORY_FINAL_APPEAL_MIN_VOTES`, `DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO`).
- Final dispute/appeal publication can also require distinct operator quorum via `DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS`.
- Final adjudication quorum policy is applied consistently to both published trust attestations and trust-derived selection scoring.
- Dispute/appeal windows are also bounded by configurable max horizons (`DIRECTORY_DISPUTE_MAX_TTL_SEC`, `DIRECTORY_APPEAL_MAX_TTL_SEC`) before publication and scoring, limiting long-window capture attempts.
- Seeded dynamic peer discovery can be enabled with `DIRECTORY_PEER_DISCOVERY`, bounded with `DIRECTORY_PEER_DISCOVERY_MAX` / `DIRECTORY_PEER_DISCOVERY_TTL_SEC`, and gated by distinct source-operator sightings via `DIRECTORY_PEER_DISCOVERY_MIN_VOTES`.
- Optional strict hint gate (`DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1`) requires discovered peers to carry signed `operator` + `pub_key` hints before admission.
- Discovered peers can be temporarily cooled down after repeated sync failures using `DIRECTORY_PEER_DISCOVERY_FAIL_THRESHOLD`, `DIRECTORY_PEER_DISCOVERY_BACKOFF_SEC`, and `DIRECTORY_PEER_DISCOVERY_MAX_BACKOFF_SEC` (exponential backoff for unstable peers).
- Directory admin can inspect discovered-peer eligibility/cooldown state through `/v1/admin/peer-status`.
- When signed peer hints include `pub_key`, directory verifies `/v1/pubkeys` (or legacy `/v1/pubkey`) response matches a hinted key before importing data.

## Session Establishment
1. Client queries one or more directories for entry/exit descriptors.
   - Client selection can prefer healthy entry/exit control endpoints and same-region pairs when available.
   - Optional pair hardening can require distinct entry/exit operators (`CLIENT_REQUIRE_DISTINCT_OPERATORS=1`) to reduce single-operator collusion risk.
   - Optional pair continuity can prefer the most recently successful pair for a bounded window (`CLIENT_STICKY_PAIR_SEC`) to reduce churn.
   - Optional session continuity can reuse an active path across bootstrap cycles (`CLIENT_SESSION_REUSE=1`) and refresh near expiry (`CLIENT_SESSION_REFRESH_LEAD_SEC`) via open-new/close-old handoff.
   - Client may retry `path/open` across alternate ranked entry/exit pairs when a candidate is unavailable.
  - Client can optionally require preferred exit locality (country first, region fallback), minimum `geo_confidence`, and configurable fallback order (`country`, `region`, `region-prefix`, `global`).
   - Client can optionally cap selected exits per operator to reduce concentration.
   - If signed exit score metadata is present (descriptor and/or selection feed), client applies weighted random exit ordering with an exploration floor.
   - If signed trust-attestation metadata is present, client blends bond/stake/reputation signals into ranking using attestation confidence.
2. Client requests short-lived token from issuer.
   - Request includes token class (`token_type`) and a PoP public key (`pop_pub_key`).
   - For path-open tokens use `token_type=client_access`.
   - Issuer token lifetime is configurable (`ISSUER_TOKEN_TTL_SEC`).
3. Client opens control session to selected entry `control_url`.
4. Through outer tunnel, client sends `PATH_OPEN` to entry:

```json
{
  "msg": "PATH_OPEN",
  "exit_id": "exit-us-01",
  "token": "<signed-token>",
  "token_proof": "base64url-ed25519-signature-over-path-open-fields",
  "token_proof_nonce": "client-generated-unique-nonce",
  "client_inner_pub": "base64-key",
  "transport": "wireguard-udp",
  "requested_mtu": 1280,
  "requested_region": "us-east",
  "puzzle_nonce": "optional-nonce",
  "puzzle_digest": "optional-sha256-hex"
}
```

5. Entry resolves `exit_id` from directory descriptors (`control_url` + data `endpoint`) and opens forwarding state keyed by flow/session id.
6. Exit validates token claims, token class, and `token_proof` against `cnf_ed25519`.
   - Optional replay guard mode requires unique `token_proof_nonce` per token lifetime.
   - Then exit replies via entry:

```json
{
  "msg": "PATH_OPEN_ACK",
  "accepted": true,
  "reason": "",
  "session_id": "hex-session-id",
  "entry_data_addr": "127.0.0.1:51820",
  "session_exp": 1771576182,
  "transport": "wireguard-udp",
  "exit_inner_pub": "base64-wg-pub",
  "client_inner_ip": "10.90.0.2/32",
  "exit_inner_ip": "10.90.0.1/32",
  "inner_mtu": 1280,
  "keepalive_sec": 25,
  "session_key_id": "hex-id"
}
```

7. Client starts inner tunnel traffic (client<->exit WireGuard packets) encapsulated through entry.

## Data Packet Frame (current scaffold)
- UDP frame from client to entry:
  - `<session_id> + "\\n" + <json inner packet>`
- Inner packet JSON:

```json
{
  "destination_port": 443,
  "payload": "hello-over-two-hop",
  "nonce": 123456789
}
```

- Entry reads only `session_id` and forwards opaque inner bytes to exit.
- Entry forwards opaque bytes bidirectionally per session (client->exit and exit->client).
- Exit parses inner packet and enforces token tier policy per packet.
- Exit tracks `nonce` per session and drops replayed packets.
- Entry and exit both drop expired sessions using `session_exp`/token expiry.

## Opaque Mode (WireGuard-ready scaffold)
- Set `DATA_PLANE_MODE=opaque` on client and exit.
- `path/open.transport` must be `wireguard-udp` in this mode.
- `client_inner_pub` must be a valid base64 32-byte WireGuard public key.
- UDP frame payload format:
  - `<session_id> + "\\n" + <8-byte big-endian nonce> + <opaque packet bytes>`
- Entry remains fully content-blind and forwards bytes unchanged.
- Exit validates session expiry and nonce replay without inspecting destination ports.
- Exit returns WG peer hints (`exit_inner_pub`, tunnel IPs, MTU) in `PATH_OPEN_ACK`.
- For current scaffold testing, exit can emit downlink-like opaque responses that entry relays back to the client socket.
- Intended for carrying real WireGuard transport packets in next phase.

Implementation note:
- Exit supports `WG_BACKEND=noop` (default) and `WG_BACKEND=command`.
- `command` mode applies peer config using `wg`/`ip` commands on `PATH_OPEN`, explicitly brings the WG interface up, and removes peer on `PATH_CLOSE`.
- In `command` mode, startup preflight validates `wg`/`ip` binaries, configured interface availability, and private key path readability.
- In `command` mode, `EXIT_WG_LISTEN_PORT` must be distinct from `EXIT_DATA_ADDR` port; startup fails on conflicts.
- In `command` mode, exit derives `exit_inner_pub` from `EXIT_WG_PRIVATE_KEY_PATH` when `EXIT_WG_PUBKEY` is unset/invalid.
- In `command` mode, exit fails startup if configured `EXIT_WG_PUBKEY` does not match the private key-derived public key.
- Client supports `CLIENT_WG_BACKEND=noop` (default) and `CLIENT_WG_BACKEND=command`.
- In client command mode, `PATH_OPEN_ACK` hints are used to configure/remove client peer state and bring the client WG interface up.
- Client command mode requires `DATA_PLANE_MODE=opaque` and `CLIENT_INNER_SOURCE=udp`; synthetic payload fallback is disabled.
- In client command mode, client derives `CLIENT_WG_PUBLIC_KEY` from `CLIENT_WG_PRIVATE_KEY_PATH` when unset/invalid.
- In client command mode, client fails startup if configured `CLIENT_WG_PUBLIC_KEY` does not match the private key-derived public key.
- `CLIENT_DISABLE_SYNTHETIC_FALLBACK=1` can enforce UDP-origin opaque uplink traffic even outside command/live mode.
- Client command mode supports configurable `allowed-ips` via `CLIENT_WG_ALLOWED_IPS` and optional route installation via `CLIENT_WG_INSTALL_ROUTE=1`.
- Client can source opaque payloads from local UDP (`CLIENT_INNER_SOURCE=udp`) to mimic real interface output.
- Client can emit received downlink opaque payload bytes to local UDP (`CLIENT_OPAQUE_SINK_ADDR`) to mimic interface input (required in live WG mode).
- Client can keep a path open in persistent opaque bridging mode (`CLIENT_OPAQUE_SESSION_SEC>0`) to continuously relay uplink/downlink packets for a bounded session duration.
- In command/live-style operation (no synthetic fallback), client requires first uplink UDP packet within `CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS` or bootstrap fails fast.
- Exit can forward accepted opaque payload bytes to local UDP sink (`EXIT_OPAQUE_SINK_ADDR`) to mimic interface/input handoff (required in live WG mode).
- Exit can ingest raw downlink opaque payload bytes from UDP source (`EXIT_OPAQUE_SOURCE_ADDR`) and inject them into active sessions toward entry/client.
- Exit can optionally bridge opaque WG payloads into local WG UDP socket I/O with `EXIT_WG_KERNEL_PROXY=1` (command mode), using per-session loopback proxy sockets tied to `EXIT_WG_LISTEN_PORT`.
- Exit source-lock binds each active session to one uplink peer source by default and drops mismatched sources; optional delayed rebind can be enabled with `EXIT_PEER_REBIND_SEC`.
- In live WG mode (`CLIENT_LIVE_WG_MODE=1`, `EXIT_LIVE_WG_MODE=1`), client drops non-plausible WG payloads on uplink before forwarding, client/exit drop non-plausible WG payloads on downlink ingress, exit downlink source packets must be session-framed datagrams, and entry can optionally enforce live WG plausibility checks with `ENTRY_LIVE_WG_MODE=1`.
- Optional `wgio` role in `node` bridges WG-side UDP and relay-side UDP sockets in one process.
- Optional `wgiotap` role in `node` can observe WG-side downlink UDP and report packet stats.
- Optional `wgioinject` role in `node` can generate WG-like/non-WG UDP test packets for uplink simulation.

## Session Close
- Client can release session state early:

```json
{
  "session_id": "hex-session-id"
}
```

- Sent to `POST /v1/path/close` on entry and forwarded to exit.

## Data Plane Rules
- Entry treats inner packets as opaque UDP payload.
- Entry only knows client socket + selected exit endpoint.
- Exit sees entry source + destination internet traffic.
- Exit enforces token-derived constraints before egress.

## Tier Defaults (MVP)
- Tier 1:
  - block destination port 25 (SMTP)
  - low `bw_kbps`
  - strict `conn_rate` and `max_conns`
- Tier 2:
  - wider port/bandwidth limits
- Tier 3:
  - near-full egress with abuse guardrails

Issuer subject lifecycle note:
- Subject profiles can carry temporary dispute controls (`tier_cap`, `dispute_until`).
- Subjects can carry temporary adjudication appeals (`appeal_until`) while disputes are under review.
- Dispute and appeal actions can attach `case_id` / `evidence_ref` metadata, which propagates through issuer and directory trust attestations with vote thresholding.
- While dispute is active, token tier eligibility is capped and issuer/directory trust attestations publish elevated `abuse_penalty` with reduced `confidence`.
- Active appeals can partially relax dispute pressure during token issuance and trust scoring while preserving the dispute signal.
- Subject profiles are typed (`kind=client` or `kind=relay-exit`): relay subjects feed relay trust, while elevated token tiers are only eligible for client subjects.
- Unbound/unknown subjects and relay-kind subjects are pinned to Tier 1 token issuance; `tier>1` tokens require non-empty `sub`.

## Anti-Abuse / DDoS (MVP)
- Entry ingress rate limit per source IP.
- Optional puzzle challenge when entry load crosses threshold.
- Entry can temporarily ban repeated abusers and cap concurrent in-flight path-open handling.
- Token TTL is short; denylist by `jti` for active abuse events.
- Exit periodically consumes issuer revocation feed and denies revoked `jti`.
- Revocation feed includes `generated_at`, `expires_at`, and issuer signature so exits reject stale or tampered feed state.
- Revocation feed includes `version` plus token key-epoch requirements (`key_epoch`, `min_token_epoch`) so exits reject rollbacked feed state and stale-epoch tokens.
- Exit can trust multiple issuers (`ISSUER_URLS`) and multiple revocation feeds (`ISSUER_REVOCATIONS_URLS`).
- When issuer metadata is available from `/v1/pubkeys`, exit rejects tokens whose `iss` does not match the verified signing key's mapped issuer identity.
- Revocation entries are scoped by verified issuer key, so identical `jti` values across issuers do not collide.
- On challenge, `PATH_OPEN_ACK` returns:
  - `accepted=false`
  - `reason=challenge-required`
  - `challenge`, `difficulty`
  client retries with solved `puzzle_nonce` and `puzzle_digest`.

## Future Compatibility
- Replace issuer auth with blind-signed or anonymous credentials.
- Add multi-entry/multi-exit path selection and rotation.
- Expand directory discovery from seeded peer feeds to broader internet-scale membership exchange.
- Add federated selection-feed exchange/gossip across directory operators.
- Add issuer key-epoch rollover and transition policy.

Selection design reference:
- `docs/exit-selection-plan.md`
