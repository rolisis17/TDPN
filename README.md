# Trust-Tiered Decentralized Privacy Network (MVP Scaffold)

This repository starts a decentralized privacy network where one `node` program can run as:
- client
- entry relay
- exit relay (including bring-your-own-exit)
- directory
- token issuer
- wg I/O bridge (UDP handoff role)
- wg I/O tap listener (WG-side downlink observer)
- wg I/O injector (internal test packet source)

## Why this shape
You asked for client and server in one program. The current scaffold is built exactly that way: role flags enable any combination in one process.

## Current status
- [x] Unified node runtime with role flags
- [x] Protocol and threat model docs
- [x] Tier policy package with tier-1 SMTP block test
- [x] HTTP control plane endpoints (`/v1/relays`, `/v1/selection-feed`, `/v1/trust-attestations`, `/v1/token`)
- [x] Basic path-open handshake (`client -> entry -> exit`) with token verification
- [x] UDP session forwarding (`client -> entry -> exit`) with per-packet tier policy enforcement
- [x] Opaque-mode bidirectional relay forwarding (`client -> entry -> exit -> entry -> client`) with session-bound routing
- [x] Directory-driven control routing (`control_url`) for selected entry and exit relays
- [x] Health-aware entry/exit selection with same-region preference and fallback behavior
- [x] Path-open failover across ranked entry/exit candidates
- [x] User-configurable exit locality preference (country first, region fallback)
- [x] Exit selection anti-concentration guardrail (per-operator cap, optional)
- [x] Reputation-weighted exit ordering with exploration floor (optional descriptor metadata)
- [x] Signed directory selection feed (`/v1/selection-feed`) with client verification/consumption
- [x] Signed directory trust-attestation feed (`/v1/trust-attestations`) with bond/stake signals
- [x] Cross-directory dispute attestation exchange (`tier_cap`, `dispute_until`) with vote-thresholded trust aggregation
- [x] Independent appeal vote-threshold controls for peer/issuer trust aggregation (`*_APPEAL_MIN_VOTES`)
- [x] Cross-operator adjudication metadata exchange (`case_id`, `evidence_ref`) in issuer/directory trust signals
- [x] Session hardening: expiry propagation + nonce-based replay rejection on exit
- [x] Descriptor signature verification on client
- [x] Federated directory fetch (multi-source quorum + relay vote threshold)
- [x] Federated directory operator quorum controls (client + entry) with operator-deduped voting
- [x] Directory peer sync (pull-based multi-operator relay import + local re-sign)
- [x] Directory push-gossip relay ingestion (`/v1/gossip/relays`) + periodic fanout scheduler
- [x] Signed directory peer-membership feed (`/v1/peers`) + seeded dynamic peer discovery
- [x] Signed directory peer hints (`peer_hints`) with discovery-time pubkey hint verification
- [x] Entry handshake anti-abuse controls (rate limit + optional challenge puzzle)
- [x] Issuer trust lifecycle APIs (subject profile/promotions/reputation/bond/dispute)
- [x] Issuer appeal lifecycle APIs (open/resolve appeals with trust-feed signaling)
- [x] Token identity hardening (`sub` claim + client-subject tier gating + relay-subject tier-1 pinning)
- [x] Issuer-signed relay trust feed (`/v1/trust/relays`) + directory trust ingestion
- [x] Live-WG runtime guardrails (strict sink requirements + non-WG payload drop on both exit and client downlink)
- [x] Live-WG downlink-source framing hardening (raw downlink packets rejected unless session-framed)
- [x] Exit opaque downlink source ingestion (`EXIT_OPAQUE_SOURCE_ADDR`) for live return-path wiring
- [x] Signed revocation feed (issuer) with periodic verification/enforcement on exit
- [x] Exit multi-issuer trust (verify tokens/revocations across multiple issuers)
- [x] Exit issuer-claim binding against verified issuer-key metadata (anti-spoof hardening)
- [x] Revocation feed version + token key-epoch enforcement on exit
- [x] Automated issuer key-epoch rotation groundwork (epoch state + previous pubkey retention)
- [x] Load/chaos integration automation (`integration_load_chaos.sh`)
- [x] Deployment assets (`deploy/docker-compose.yml`, `deploy/systemd/*.service`)
- [ ] WireGuard-backed two-hop forwarding on live interfaces (production-grade)

## Run
```bash
go run ./cmd/node --directory --issuer
go run ./cmd/node --entry --exit
go run ./cmd/node --client
go run ./cmd/node --wgio
go run ./cmd/node --wgiotap
go run ./cmd/node --wgioinject
./scripts/demo_internal_topology.sh
```

Optional env vars:
- `DIRECTORY_ADDR` (default `127.0.0.1:8081`)
- `ISSUER_ADDR` (default `127.0.0.1:8082`)
- `ENTRY_ADDR` (default `127.0.0.1:8083`)
- `EXIT_ADDR` (default `127.0.0.1:8084`)
- `ENTRY_COUNTRY_CODE` (default `ZZ`; directory descriptor metadata for entry locality)
- `EXIT_COUNTRY_CODE` (default `ZZ`; directory descriptor metadata for exit locality)
- `ENTRY_REGION` (default `local`; directory descriptor metadata for entry region)
- `EXIT_REGION` (default `local`; directory descriptor metadata for exit region)
- `ENTRY_RELAY_ID` (default `entry-local-1`; directory-published entry relay id)
- `EXIT_RELAY_ID` (default `exit-local-1`; directory-published exit relay id)
- `DIRECTORY_OPERATOR_ID` (default `operator-local`; operator metadata fallback for descriptors)
- `ENTRY_OPERATOR_ID` (fallback `DIRECTORY_OPERATOR_ID`; entry descriptor operator id)
- `EXIT_OPERATOR_ID` (fallback `DIRECTORY_OPERATOR_ID`; exit descriptor operator id)
- `EXIT_REPUTATION_SCORE` (default `0`; signed exit descriptor selection score `0..1`)
- `EXIT_UPTIME_SCORE` (default `0`; signed exit descriptor availability score `0..1`)
- `EXIT_CAPACITY_SCORE` (default `0`; signed exit descriptor capacity score `0..1`)
- `EXIT_ABUSE_PENALTY` (default `0`; signed exit descriptor abuse penalty `0..1`)
- `EXIT_BOND_SCORE` (default `0`; signed exit descriptor bond/stake trust signal `0..1`)
- `EXIT_STAKE_SCORE` (default `0`; signed exit descriptor stake trust signal `0..1`)
- `DIRECTORY_URL` (default `http://127.0.0.1:8081`)
- `DIRECTORY_URLS` (comma-separated directory URLs; enables federated source quorum)
- `DIRECTORY_MIN_SOURCES` (default `1`; minimum successful directories required)
- `DIRECTORY_MIN_OPERATORS` (default `1`; minimum distinct directory operators required)
- `DIRECTORY_MIN_RELAY_VOTES` (default `1`; minimum source votes per relay descriptor)
- `DIRECTORY_PUBLIC_URL` (optional public base URL identity used in push-gossip announcements)
- `DIRECTORY_PRIVATE_KEY_FILE` (default `data/directory_ed25519.key`, persistent signing key)
- `DIRECTORY_TRUST_STRICT` (`1` enforces trusted directory key pinning)
- `DIRECTORY_TRUST_TOFU` (`1` default, allow trust-on-first-use when strict and trust file empty)
- `DIRECTORY_TRUSTED_KEYS_FILE` (default `data/trusted_directory_keys.txt`)
- `ENTRY_DIRECTORY_MIN_SOURCES` (fallback `DIRECTORY_MIN_SOURCES`; minimum successful directory sources for entry exit-route resolution)
- `ENTRY_DIRECTORY_MIN_OPERATORS` (fallback `DIRECTORY_MIN_OPERATORS`; minimum distinct directory operators for entry route resolution)
- `ENTRY_DIRECTORY_MIN_RELAY_VOTES` (fallback `DIRECTORY_MIN_RELAY_VOTES`; minimum votes for selected exit route)
- `ENTRY_DIRECTORY_TRUST_STRICT` (fallback `DIRECTORY_TRUST_STRICT`; strict trusted-key mode for entry route discovery)
- `ENTRY_DIRECTORY_TRUST_TOFU` (fallback `DIRECTORY_TRUST_TOFU`; TOFU bootstrap for strict entry trust mode)
- `ENTRY_DIRECTORY_TRUSTED_KEYS_FILE` (fallback `DIRECTORY_TRUSTED_KEYS_FILE`; default `data/entry_trusted_directory_keys.txt`)
- `ISSUER_URL` (default `http://127.0.0.1:8082`)
- `ISSUER_URLS` (comma-separated issuer base URLs; exit verifies tokens against all fetched issuer pubkeys)
- `ISSUER_PRIVATE_KEY_FILE` (default `data/issuer_ed25519.key`, persistent issuer signing key)
- `ISSUER_PREVIOUS_PUBKEYS_FILE` (default `data/issuer_previous_pubkeys.txt`; optional previous issuer pubkeys for rollover exposure at `/v1/pubkeys`)
- `ISSUER_REVOCATION_FEED_TTL_SEC` (default `30`; signed revocation feed max age)
- `ISSUER_TRUST_FEED_TTL_SEC` (default `30`; signed issuer relay-trust feed max age)
- `ISSUER_TRUST_CONFIDENCE` (default `1`; default trust confidence used in `/v1/trust/relays`)
- `ISSUER_TRUST_BOND_MAX` (default `500`; bond normalization ceiling for trust feed score mapping)
- `ISSUER_TRUST_OPERATOR_ID` (optional operator id to stamp into issuer trust attestations)
- `ISSUER_DISPUTE_DEFAULT_TTL_SEC` (default `86400`; fallback active-dispute duration when admin request omits/uses stale `until`)
- `ENTRY_URL` (default `http://127.0.0.1:8083`)
- `EXIT_CONTROL_URL` (default `http://127.0.0.1:8084`)
- `ENTRY_DATA_ADDR` (default `127.0.0.1:51820`)
- `EXIT_DATA_ADDR` (default `127.0.0.1:51821`)
- `DATA_PLANE_MODE` (`json` default, or `opaque`)
- `WG_BACKEND` (`noop` default, `command` for `wg`/`ip` CLI integration; requires `DATA_PLANE_MODE=opaque`)
- `CLIENT_WG_PUBLIC_KEY` (base64 32-byte key; used for `wireguard-udp`, auto-generated if missing)
- `CLIENT_SUBJECT` (optional client identity subject used for token issuance; leave unset for anonymous tier-1 behavior)
- `CLIENT_WG_BACKEND` (`noop` default, `command` for client-side `wg`/`ip` integration; requires `DATA_PLANE_MODE=opaque` and `CLIENT_INNER_SOURCE=udp`)
- `CLIENT_WG_INTERFACE` (default `wg-client0`)
- `CLIENT_WG_PRIVATE_KEY_PATH` (required when `CLIENT_WG_BACKEND=command`)
- `CLIENT_INNER_SOURCE` (`synthetic` default, `udp` to read opaque payloads from local UDP socket)
- `CLIENT_INNER_UDP_ADDR` (default `127.0.0.1:51900`, used when `CLIENT_INNER_SOURCE=udp`)
- `CLIENT_OPAQUE_SINK_ADDR` (optional UDP sink for opaque downlink payload bytes received from entry; required when `CLIENT_LIVE_WG_MODE=1`)
- `CLIENT_OPAQUE_DRAIN_MS` (default `1200`, downlink read window after client sends uplink packets)
- `CLIENT_SELECTION_HEALTHCHECK` (default `1`; enable entry/exit control-plane health probes during relay selection)
- `CLIENT_DIRECTORY_MIN_OPERATORS` (fallback `DIRECTORY_MIN_OPERATORS`; minimum distinct directory operators for client bootstrap quorum)
- `CLIENT_HEALTHCHECK_TIMEOUT_MS` (default `700`; per-relay health probe timeout)
- `CLIENT_HEALTHCHECK_CACHE_SEC` (default `5`; cache TTL for relay health probe results)
- `CLIENT_HEALTHCHECK_DISABLE` (`1` disables health probes and falls back to descriptor ordering)
- `CLIENT_EXIT_COUNTRY` (optional ISO alpha-2 preferred exit country, e.g. `US`, `DE`)
- `CLIENT_EXIT_REGION` (optional preferred exit region fallback, e.g. `us-east`)
- `CLIENT_EXIT_STRICT_LOCALITY` (`1` requires preferred country/region match; otherwise bootstrap fails)
- `CLIENT_MAX_EXITS_PER_OPERATOR` (default `0`; when `>0`, cap selected exits per operator before pair ranking)
- `CLIENT_PATH_OPEN_MAX_ATTEMPTS` (default `4`; max ranked entry/exit pairs tried per bootstrap cycle)
- `CLIENT_MAX_PAIR_CANDIDATES` (default `12`; cap on ranked pair list size before retries)
- `CLIENT_EXIT_EXPLORATION_PCT` (default `10`; percent of ranked exit attempts reserved for exploration)
- `CLIENT_EXIT_SELECTION_SEED` (optional int64; deterministic seed for weighted exit ordering)
- `CLIENT_SELECTION_FEED_DISABLE` (`1` disables signed directory selection-feed fetch/use)
- `CLIENT_SELECTION_FEED_REQUIRE` (`1` requires valid signed selection feed from each successful directory source)
- `CLIENT_SELECTION_FEED_MIN_VOTES` (default `1`; minimum directory feed votes required before side-channel scores override descriptor scores)
- `CLIENT_TRUST_FEED_DISABLE` (`1` disables signed directory trust-feed fetch/use)
- `CLIENT_TRUST_FEED_REQUIRE` (`1` requires valid signed trust feed from each successful directory source)
- `CLIENT_TRUST_FEED_MIN_VOTES` (default `1`; minimum trust-feed votes required before trust attestations are applied)
- `CLIENT_BOOTSTRAP_INTERVAL_SEC` (default `5`; client bootstrap retry interval)
- `EXIT_WG_INTERFACE` (default `wg-exit0`)
- `EXIT_WG_PRIVATE_KEY_PATH` (required when `WG_BACKEND=command`)
- `EXIT_WG_EXIT_IP` (default `10.90.0.1/32`)
- `EXIT_OPAQUE_SINK_ADDR` (optional UDP sink for accepted opaque payload bytes; required when `EXIT_LIVE_WG_MODE=1`)
- `EXIT_OPAQUE_SOURCE_ADDR` (optional UDP listener for downlink payload injection into active opaque sessions; required when `EXIT_LIVE_WG_MODE=1` and packets must be session-framed in live mode)
- `EXIT_OPAQUE_ECHO` (default `1` in noop mode, default `0` in command/live mode; echo accepted payload back toward entry/client as downlink scaffold)
- `WGIO_FROM_WG_ADDR` (default `127.0.0.1:52000`, bridge uplink listen)
- `WGIO_TO_CLIENT_ADDR` (default `127.0.0.1:51900`, bridge uplink target)
- `WGIO_FROM_EXIT_ADDR` (default `127.0.0.1:51910`, bridge downlink listen)
- `WGIO_TO_WG_ADDR` (default `127.0.0.1:52001`, bridge downlink target)
- `WGIOTAP_ADDR` (default `127.0.0.1:52001`, tap listener bind)
- `WGIOINJECT_TARGET_ADDR` (default `127.0.0.1:52000`, injector target)
- `WGIOINJECT_INTERVAL_MS` (default `200`)
- `WGIOINJECT_WG_LIKE_PCT` (default `80`, percentage of WG-like packets)
- `ISSUER_ADMIN_TOKEN` (default `dev-admin-token`)
- `ISSUER_SUBJECTS_FILE` (default `data/issuer_subjects.json`)
- `ISSUER_REVOCATIONS_FILE` (default `data/issuer_revocations.json`)
- `ENTRY_ENDPOINTS` (comma-separated rotating entry endpoints for directory)
- `DIRECTORY_ROTATE_SEC` (default `30`)
- `DIRECTORY_DESCRIPTOR_EPOCH_SEC` (default `10`; descriptor timestamp/signature stabilization window for cacheability)
- `DIRECTORY_DESCRIPTOR_TTL_SEC` (default `1800`; descriptor `valid_until` horizon in seconds)
- `DIRECTORY_PEERS` (comma-separated peer directory base URLs for pull-based sync)
- `DIRECTORY_SYNC_SEC` (default `10`; peer sync interval in seconds)
- `DIRECTORY_GOSSIP_SEC` (default `0`; when `>0`, periodically push signed relays to peers)
- `DIRECTORY_GOSSIP_FANOUT` (default `2`; peers targeted per gossip round)
- `DIRECTORY_PEER_LIST_TTL_SEC` (default `45`; signed `/v1/peers` feed TTL)
- `DIRECTORY_PEER_DISCOVERY` (`1` default; enable seeded dynamic peer discovery from trusted peers)
- `DIRECTORY_PEER_DISCOVERY_MAX` (default `64`; cap discovered peer set size)
- `DIRECTORY_PEER_DISCOVERY_TTL_SEC` (default `900`; expire stale discovered peers)
- `DIRECTORY_PEER_MIN_VOTES` (default `1`; minimum matching peer descriptor votes per relay key during sync conflict resolution)
- `DIRECTORY_PEER_SCORE_MIN_VOTES` (default `1`; minimum peer feed votes required before imported peer selection scores are used)
- `DIRECTORY_PEER_TRUST_MIN_VOTES` (default `1`; minimum peer trust-feed votes required before imported trust attestations are used)
- `DIRECTORY_PEER_DISPUTE_MIN_VOTES` (default `DIRECTORY_PEER_TRUST_MIN_VOTES`; minimum peer dispute votes required before imported dispute metadata is propagated)
- `DIRECTORY_PEER_APPEAL_MIN_VOTES` (default `DIRECTORY_PEER_DISPUTE_MIN_VOTES`; minimum peer appeal votes required before imported appeal metadata is propagated)
- `DIRECTORY_PEER_MAX_HOPS` (default `2`; loop-resistance hop cap for imported peer descriptors)
- `DIRECTORY_PEER_TRUST_STRICT` (`1` enforces trusted key pinning for directory peers)
- `DIRECTORY_PEER_TRUST_TOFU` (`1` default; allow trust-on-first-use for unknown peer keys in strict mode)
- `DIRECTORY_PEER_TRUSTED_KEYS_FILE` (default `data/directory_peer_trusted_keys.txt`)
- `DIRECTORY_ISSUER_TRUST_URLS` (comma-separated issuer URLs for directory trust-attestation ingestion)
- `DIRECTORY_ISSUER_SYNC_SEC` (default `10`; issuer trust sync interval in seconds)
- `DIRECTORY_ISSUER_TRUST_MIN_VOTES` (default `1`; minimum matching issuer votes required for imported issuer trust attestations)
- `DIRECTORY_ISSUER_DISPUTE_MIN_VOTES` (default `DIRECTORY_ISSUER_TRUST_MIN_VOTES`; minimum issuer dispute votes required before imported dispute metadata is propagated)
- `DIRECTORY_ISSUER_APPEAL_MIN_VOTES` (default `DIRECTORY_ISSUER_DISPUTE_MIN_VOTES`; minimum issuer appeal votes required before imported appeal metadata is propagated)
- `DIRECTORY_SELECTION_FEED_TTL_SEC` (default `30`; signed selection feed TTL)
- `DIRECTORY_SELECTION_FEED_EPOCH_SEC` (default `10`; generated_at stabilization window for selection-feed cacheability)
- `DIRECTORY_TRUST_FEED_TTL_SEC` (default `30`; signed trust-attestation feed TTL)
- `DIRECTORY_TRUST_FEED_EPOCH_SEC` (default `10`; generated_at stabilization window for trust-feed cacheability)
- `ENTRY_GEO_CONFIDENCE` (default `1`; descriptor geolocation confidence `0..1` for entry locality metadata)
- `EXIT_GEO_CONFIDENCE` (default `1`; descriptor geolocation confidence `0..1` for exit locality metadata)
- `ENTRY_PUZZLE_ADAPTIVE` (`1` default, adaptive puzzle difficulty under load)
- `ENTRY_BAN_THRESHOLD` (default `3`; temporary source ban strikes after repeated over-limit opens)
- `ENTRY_BAN_SEC` (default `45`; temporary source ban duration)
- `ENTRY_MAX_CONCURRENT_OPENS` (default `128`; max concurrent in-flight path-open handling)
- `CLIENT_LIVE_WG_MODE` (`1` enforces strict live WG requirements: command backend + UDP source + downlink sink)
- `EXIT_LIVE_WG_MODE` (`1` enforces strict live WG requirements: command backend + no echo + opaque sink/source + WG-like payload filtering + session-framed downlink source packets)
- `EXIT_EGRESS_BACKEND` (`noop` default, `command` enables NAT setup)
- `EXIT_EGRESS_CHAIN` (default `PRIVNODE_EGRESS`; dedicated NAT chain name in command mode)
- `EXIT_EGRESS_IFACE` (default `eth0`)
- `EXIT_EGRESS_CIDR` (default `10.90.0.0/24`)
- `EXIT_ACCOUNTING_FILE` (optional JSON metrics/accounting snapshot file)
- `EXIT_ACCOUNTING_FLUSH_SEC` (default `10`; accounting snapshot write interval)
- `EXIT_REVOCATION_REFRESH_SEC` (default `15`)
- `CLIENT_EXIT_MIN_GEO_CONFIDENCE` (default `0`; required minimum `geo_confidence` for country/region matching)
- `CLIENT_EXIT_LOCALITY_FALLBACK_ORDER` (default `country,region,region-prefix,global`; configurable locality fallback policy)
- `ISSUER_REVOCATIONS_URL` (default `$ISSUER_URL/v1/revocations`)
- `ISSUER_REVOCATIONS_URLS` (comma-separated revocation feed URLs; default derived from `ISSUER_URLS`)
- `ISSUER_EPOCHS_FILE` (default `data/issuer_epochs.json`; persistent issuer key-epoch/min-token-epoch state)
- `ISSUER_KEY_ROTATE_SEC` (default `0`; if set `>0`, auto-rotate issuer signing key on interval)
- `ISSUER_KEY_HISTORY` (default `3`; number of previous pubkeys to retain for rollover window)
- `ENTRY_ENDPOINT` (default `127.0.0.1:51820` in descriptors)
- `EXIT_ENDPOINT` (default `127.0.0.1:51821` in descriptors)
- `ENTRY_EXIT_ROUTE_TTL_SEC` (default `30`, entry cache TTL for `exit_id` -> route lookup via directory)

Control API:
- `GET /v1/relays` (directory)
- `GET /v1/selection-feed` (directory)
- `GET /v1/trust-attestations` (directory)
- `POST /v1/gossip/relays` (directory peer push ingestion)
- `GET /v1/peers` (directory signed peer-membership feed + optional peer hints)
- `POST /v1/token` (issuer)
- `GET /v1/pubkeys` (issuer current + previous pubkeys)
- `GET /v1/trust/relays` (issuer signed relay trust feed)
- `POST /v1/path/open` (entry forwards to exit)
- `POST /v1/path/close` (entry forwards close to exit)
- `POST /v1/admin/subject/upsert` (issuer admin)
- `POST /v1/admin/subject/promote` (issuer admin)
- `POST /v1/admin/subject/reputation/apply` (issuer admin)
- `POST /v1/admin/subject/bond/apply` (issuer admin)
- `POST /v1/admin/subject/dispute` (issuer admin)
- `POST /v1/admin/subject/dispute/clear` (issuer admin)
- `POST /v1/admin/subject/appeal/open` (issuer admin)
- `POST /v1/admin/subject/appeal/resolve` (issuer admin)
- `POST /v1/admin/subject/recompute-tier` (issuer admin)
- `GET /v1/admin/subject/get?subject=<id>` (issuer admin)
- `GET /v1/admin/audit` (issuer admin)
- `POST /v1/admin/revoke-token` (issuer admin)
- `GET /v1/revocations` (issuer revocation feed)
- `GET /v1/metrics` (exit packet/byte counters)

Data plane frame:
- client sends UDP: `<session_id>\n<json inner packet>`
- exit enforces policy on `destination_port` (Tier-1 drops `25`)
- inner packet includes `nonce`; replayed nonces in same session are dropped

Opaque mode (`DATA_PLANE_MODE=opaque`):
- client sends UDP: `<session_id>\n<8-byte nonce><opaque payload>`
- entry remains content-blind and forwards bytes unchanged
- exit validates session + nonce replay only, no destination-port inspection
- entry forwards both directions: client->exit and exit->client for each session
- entry resolves `exit_id` from directory descriptors and forwards control/data to that selected exit route
- entry verifies directory descriptor signatures before using exit route data
- entry can require source/operator quorum and route vote thresholds (`ENTRY_DIRECTORY_MIN_SOURCES`, `ENTRY_DIRECTORY_MIN_OPERATORS`, `ENTRY_DIRECTORY_MIN_RELAY_VOTES`)
- client prefers healthy entry/exit control endpoints and favors same-region relay pairs when available
- client retries `path/open` across alternate ranked pairs if earlier attempts fail
- client can prefer exits by country first, then region fallback (`CLIENT_EXIT_COUNTRY`, `CLIENT_EXIT_REGION`)
- client can cap exits per operator to reduce concentration (`CLIENT_MAX_EXITS_PER_OPERATOR`)
- client can use weighted random exit ordering when score metadata is available (descriptor or signed selection feed), with configurable exploration floor (`CLIENT_EXIT_EXPLORATION_PCT`)
- client can require and consume signed trust-attestation feeds (bond/stake/reputation) and blend those signals into exit ranking (`CLIENT_TRUST_FEED_*`)
- client can forward opaque downlink payload bytes to local UDP sink (`CLIENT_OPAQUE_SINK_ADDR`)
- exit validates token claims at `path/open` (`aud=exit`, unexpired `exp`, valid `tier`, non-empty `jti`; `tier>1` requires `sub`)
- `path/open` transport must be `wireguard-udp` and exit returns inner peer hints:
  - `exit_inner_pub`, `client_inner_ip` (allocated per session), `exit_inner_ip`, `inner_mtu`, `keepalive_sec`, `session_key_id`
- if `WG_BACKEND=command`, exit also configures/removes peers via `wg`/`ip` on path open/close
- command backend startup preflight checks `wg`/`ip` binaries, interface presence, and key path readability
- if `CLIENT_WG_BACKEND=command`, client configures/removes peer using exit hints from `path/open`
- command client backend startup preflight checks `wg`/`ip` binaries, interface presence, and key path readability
- if `CLIENT_INNER_SOURCE=udp`, client forwards received UDP packets as opaque payloads instead of synthetic test datagrams
- if `EXIT_OPAQUE_SINK_ADDR` is set, exit emits accepted opaque payload bytes to that UDP address
- if `EXIT_OPAQUE_SOURCE_ADDR` is set, exit accepts raw downlink payload bytes and forwards them into active sessions
- in live WG mode (`CLIENT_LIVE_WG_MODE=1`, `EXIT_LIVE_WG_MODE=1`), sink/source addresses are mandatory, exit drops non-WireGuard-like opaque payloads, and raw downlink source packets must be session-framed
- with `--wgio`, `node` forwards UDP between WG-side and relay-side handoff sockets
- with `--wgiotap`, `node` listens on WG-side downlink socket and logs packet stats
- with `--wgioinject`, `node` generates internal UDP test packets for WG-side uplink

Anti-abuse entry controls:
- `ENTRY_OPEN_RPS` (default `20`) controls per-IP path-open limit per second
- `ENTRY_PUZZLE_DIFFICULTY` (default `0`; set `1..6` to enable challenge puzzle)
- `ENTRY_PUZZLE_SECRET` (default `entry-secret-default`)
- `ENTRY_PUZZLE_ADAPTIVE` (default `1`, increases challenge difficulty with overload)
- `ENTRY_BAN_THRESHOLD` + `ENTRY_BAN_SEC` add temporary source bans after repeated over-limit opens
- `ENTRY_MAX_CONCURRENT_OPENS` adds non-blocking in-flight path-open shielding

CI and tests:
- `./scripts/ci_local.sh` (unit tests + internal topology assertions)
- `.github/workflows/ci.yml` runs the local CI script on push/PR
- `./scripts/load_path_open.sh` (basic entry path-open load script)
- `./scripts/integration_challenge.sh` (entry challenge/anti-abuse integration check)
- `./scripts/integration_revocation.sh` (issuer->exit revocation propagation check)
- `./scripts/integration_federation.sh` (multi-directory quorum/vote integration check)
- `./scripts/integration_operator_quorum.sh` (distinct-directory-operator quorum enforcement check)
- `./scripts/integration_directory_sync.sh` (directory peer sync integration check)
- `./scripts/integration_directory_gossip.sh` (directory push-gossip ingestion integration check)
- `./scripts/integration_peer_discovery.sh` (seeded directory peer discovery + discovered-peer relay import check)
- `./scripts/integration_selection_feed.sh` (signed selection-feed requirement integration check)
- `./scripts/integration_trust_feed.sh` (signed trust-feed requirement + bond/stake signal integration check)
- `./scripts/integration_opaque_source_downlink.sh` (exit opaque source downlink return-path integration check)
- `./scripts/integration_issuer_trust_sync.sh` (directory ingestion of issuer trust attestations check)
- `./scripts/integration_issuer_dispute.sh` (issuer dispute + appeal lifecycle with case/evidence metadata and trust-signal checks)
- `./scripts/integration_lifecycle_chaos.sh` (adversarial dispute/revocation race and stability check; included in deep suite)
- `./scripts/integration_multi_issuer.sh` (exit multi-issuer token/revocation integration check)
- `./scripts/integration_load_chaos.sh` (entry load guardrails + directory peer churn resilience check)
- `./scripts/integration_http_cache.sh` (directory ETag/If-None-Match behavior check)
- `./scripts/integration_key_epoch_rotation.sh` (issuer key rotation + stale-epoch token denial check)
- `./scripts/integration_stress_bootstrap.sh` (multi-client bootstrap stress check)
- `./scripts/deep_test_suite.sh` (race tests + extended integration suite)
- `./scripts/integration_docker_stack.sh` (docker-compose stack smoke test; requires Docker installed)
- `./scripts/pin_directory_key.sh` (pin directory pubkey into trusted key file)
- `docs/testing-guide.md` (simple full test setup + expected results + debug flow)
- `docs/deployment.md` (docker-compose + systemd deployment guide)

## Repository layout
```text
cmd/node                # unified executable
internal/app            # role wiring and lifecycle
services/directory      # relay descriptor service (stub)
services/issuer         # capability token service (stub)
services/entry          # ingress/forwarder role (stub)
services/exit           # egress policy role (stub)
pkg/proto               # protocol structs
pkg/crypto              # token signing/verification
pkg/policy              # tier enforcement logic
docs/                   # protocol, threat model, plan
deploy/                 # docker-compose + systemd deployment assets
```

## Next implementation target
1. Bind `CLIENT_INNER_SOURCE=udp` and exit `EXIT_OPAQUE_SINK_ADDR`/`EXIT_OPAQUE_SOURCE_ADDR` flows to real WireGuard interface I/O end-to-end.
2. Expand issuer-backed trust lifecycle into cross-operator adjudication/dispute governance.
3. Add larger-scale chaos/stress suites and deployment hardening for beta environments.

Project status detail:
- `docs/mvp-status.md`
- `docs/exit-selection-plan.md` (planned country-aware + reputation-weighted exit selection)
- `docs/testing-guide.md` (how to test end-to-end)
