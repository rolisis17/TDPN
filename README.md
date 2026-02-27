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
- [x] Basic path-open handshake (`client -> entry -> exit`) with split token classes (`client_access` / `provider_role`) and PoP-bound token proof verification
- [x] UDP session forwarding (`client -> entry -> exit`) with per-packet tier policy enforcement
- [x] Opaque-mode bidirectional relay forwarding (`client -> entry -> exit -> entry -> client`) with session-bound routing
- [x] Directory-driven control routing (`control_url`) for selected entry and exit relays
- [x] Health-aware entry/exit selection with same-region preference and fallback behavior
- [x] Path-open failover across ranked entry/exit candidates
- [x] User-configurable exit locality preference (country first, region fallback)
- [x] Exit selection anti-concentration guardrail (per-operator cap, optional)
- [x] Optional anti-collusion relay pairing guardrail (require distinct entry/exit operators)
- [x] Reputation-weighted exit ordering with exploration floor (optional descriptor metadata)
- [x] Signed directory selection feed (`/v1/selection-feed`) with client verification/consumption
- [x] Signed directory trust-attestation feed (`/v1/trust-attestations`) with bond/stake signals
- [x] Cross-directory dispute attestation exchange (`tier_cap`, `dispute_until`) with vote-thresholded trust aggregation
- [x] Independent appeal vote-threshold controls for peer/issuer trust aggregation (`*_APPEAL_MIN_VOTES`)
- [x] Outlier-resistant adjudication aggregation (consensus tier-cap + median dispute/appeal windows)
- [x] Cross-operator adjudication metadata exchange (`case_id`, `evidence_ref`) in issuer/directory trust signals
- [x] Adjudication metadata pair integrity (`case_id` + `evidence_ref`) so published metadata always comes from the same voted signal pair
- [x] Adjudication window horizon caps for anti-capture hardening (`DIRECTORY_DISPUTE_MAX_TTL_SEC`, `DIRECTORY_APPEAL_MAX_TTL_SEC`)
- [x] Final trust-feed adjudication quorum controls (`DIRECTORY_FINAL_DISPUTE_MIN_VOTES`, `DIRECTORY_FINAL_APPEAL_MIN_VOTES`, `DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO`)
- [x] Final trust-feed adjudication source quorum control (`DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES`)
- [x] Session hardening: expiry propagation + nonce-based replay rejection on exit
- [x] Descriptor signature verification on client
- [x] Federated directory fetch (multi-source quorum + relay vote threshold)
- [x] Federated directory operator quorum controls (client + entry) with operator-deduped voting
- [x] Directory peer sync (pull-based multi-operator relay import + local re-sign)
- [x] Directory peer/issuer trust aggregation operator quorum controls with operator-deduped trust/dispute/appeal voting
- [x] Directory governance observability endpoint (`/v1/admin/governance-status`) with adjudication policy, upstream dispute/appeal signal + operator counters, suppressed-signal counters, and per-relay suppression detail
- [x] Directory push-gossip relay ingestion (`/v1/gossip/relays`) + periodic fanout scheduler
- [x] Signed directory peer-membership feed (`/v1/peers`) + seeded dynamic peer discovery
- [x] Signed directory peer hints (`peer_hints`) with discovery-time pubkey hint verification
- [x] Optional strict discovered-peer admission policy requiring signed operator+pubkey hints (`DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT`)
- [x] Optional discovered-peer per-source admission cap (`DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE`) to limit how many peers one source operator can add at once
- [x] Directory discovered-peer failure backoff + admin peer status endpoint (`/v1/admin/peer-status`)
- [x] Entry handshake anti-abuse controls (rate limit + optional challenge puzzle)
- [x] Issuer trust lifecycle APIs (subject profile/promotions/reputation/bond/dispute)
- [x] Issuer appeal lifecycle APIs (open/resolve appeals with trust-feed signaling)
- [x] Token identity hardening (`sub` claim + client-subject tier gating + relay-subject tier-1 pinning)
- [x] Provider-role-protected directory relay upsert API (`/v1/provider/relay/upsert`)
- [x] Provider operator relay-admission cap (`DIRECTORY_PROVIDER_MAX_RELAYS_PER_OPERATOR`) to limit per-operator relay concentration in provider upserts
- [x] Issuer-signed relay trust feed (`/v1/trust/relays`) + directory trust ingestion
- [x] Live-WG runtime guardrails (strict sink requirements + non-WG/pattern-invalid payload drop on both exit and client downlink)
- [x] Optional entry live-WG forwarding guardrail (`ENTRY_LIVE_WG_MODE=1`) to drop malformed/non-WG opaque packets before forwarding
- [x] Live-WG downlink-source framing hardening (raw downlink packets rejected unless session-framed)
- [x] Live-WG packet plausibility hardening (type-aware minimum packet lengths for live uplink/downlink acceptance)
- [x] Optional UDP-only opaque source mode (`CLIENT_DISABLE_SYNTHETIC_FALLBACK=1`) to enforce real packet-origin traffic on client uplink
- [x] Optional persistent opaque session loop on client (`CLIENT_OPAQUE_SESSION_SEC`) with enforced initial uplink readiness in command/live-style modes
- [x] Optional active path reuse across bootstrap cycles (`CLIENT_SESSION_REUSE`) with proactive refresh lead and seamless handoff before expiry
- [x] Command WG interface-up hardening (client + exit) with optional client route installation for configured allowed IPs
- [x] Client/exit command backends auto-derive WireGuard public keys from configured private keys when public key envs are unset/invalid
- [x] Optional client command-mode WG kernel proxy (`CLIENT_WG_KERNEL_PROXY=1`) to bridge WG UDP packets directly through session-framed opaque path without external injector/tap process
- [x] Exit command-mode WG kernel proxy option (`EXIT_WG_KERNEL_PROXY=1`) to inject accepted opaque uplink into local WG UDP socket and relay WG downlink back through entry/client
- [x] Exit command-mode listen-port separation (`EXIT_WG_LISTEN_PORT`) with fail-fast conflict detection against `EXIT_DATA_ADDR`
- [x] Exit WG kernel-proxy operational safeguards (session cap, idle cleanup, and proxy lifecycle metrics)
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

Simple installer + menu launcher (for easier testing):

```bash
./scripts/install_easy_mode.sh
./bin/privacynode-easy
```

Windows 11 + WSL2 bootstrap:

```powershell
./scripts/windows/wsl2_bootstrap.ps1
./scripts/windows/wsl2_run_easy.ps1
```

Windows `cmd.exe` wrappers:

```cmd
scripts\windows\wsl2_bootstrap.cmd
scripts\windows\wsl2_run_easy.cmd
scripts\windows\wsl2_easy.cmd bootstrap
scripts\windows\wsl2_easy.cmd run
```

Script-only easy mode:

```bash
./scripts/easy_node.sh server-up --public-host <PUBLIC_IP_OR_DNS>
./scripts/easy_node.sh client-test \
  --directory-urls http://<SERVER_IP>:8081 \
  --issuer-url http://<SERVER_IP>:8082 \
  --entry-url http://<SERVER_IP>:8083 \
  --exit-url http://<SERVER_IP>:8084
```

3-machine test guide:
- `docs/easy-3-machine-test.md`
- `docs/windows-wsl2.md` (Windows 11 + WSL2)

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
- `DIRECTORY_PREVIOUS_PUBKEYS_FILE` (default `data/directory_previous_pubkeys.txt`; retained previous directory signing pubkeys exposed at `/v1/pubkeys`)
- `DIRECTORY_KEY_ROTATE_SEC` (default `0`; when `>0`, auto-rotate directory signing key on interval)
- `DIRECTORY_KEY_HISTORY` (default `3`; number of previous directory pubkeys retained during rotation)
- `DIRECTORY_TRUST_STRICT` (`1` enforces trusted directory key pinning)
- `DIRECTORY_TRUST_TOFU` (`1` default, allow trust-on-first-use when strict and trust file empty)
- `DIRECTORY_TRUSTED_KEYS_FILE` (default `data/trusted_directory_keys.txt`)
- `ENTRY_DIRECTORY_MIN_SOURCES` (fallback `DIRECTORY_MIN_SOURCES`; minimum successful directory sources for entry exit-route resolution)
- `ENTRY_DIRECTORY_MIN_OPERATORS` (fallback `DIRECTORY_MIN_OPERATORS`; minimum distinct directory operators for entry route resolution)
- `ENTRY_DIRECTORY_MIN_RELAY_VOTES` (fallback `DIRECTORY_MIN_RELAY_VOTES`; minimum votes for selected exit route)
- `ENTRY_DIRECTORY_TRUST_STRICT` (fallback `DIRECTORY_TRUST_STRICT`; strict trusted-key mode for entry route discovery)
- `ENTRY_DIRECTORY_TRUST_TOFU` (fallback `DIRECTORY_TRUST_TOFU`; TOFU bootstrap for strict entry trust mode)
- `ENTRY_DIRECTORY_TRUSTED_KEYS_FILE` (fallback `DIRECTORY_TRUSTED_KEYS_FILE`; default `data/entry_trusted_directory_keys.txt`)
- `ENTRY_LIVE_WG_MODE` (`1` enables entry-side live WireGuard plausibility checks for `wireguard-udp` opaque sessions)
- `ISSUER_URL` (default `http://127.0.0.1:8082`)
- `ISSUER_URLS` (comma-separated issuer base URLs; exit verifies tokens against all fetched issuer pubkeys)
- `ISSUER_PRIVATE_KEY_FILE` (default `data/issuer_ed25519.key`, persistent issuer signing key)
- `ISSUER_PREVIOUS_PUBKEYS_FILE` (default `data/issuer_previous_pubkeys.txt`; optional previous issuer pubkeys for rollover exposure at `/v1/pubkeys`)
- `ISSUER_REVOCATION_FEED_TTL_SEC` (default `30`; signed revocation feed max age)
- `ISSUER_TRUST_FEED_TTL_SEC` (default `30`; signed issuer relay-trust feed max age)
- `ISSUER_TRUST_CONFIDENCE` (default `1`; default trust confidence used in `/v1/trust/relays`)
- `ISSUER_TRUST_BOND_MAX` (default `500`; bond normalization ceiling for trust feed score mapping)
- `ISSUER_TRUST_OPERATOR_ID` (optional operator id to stamp into issuer trust attestations)
- `ISSUER_TOKEN_TTL_SEC` (default `600`; issued token lifetime in seconds)
- `ISSUER_DISPUTE_DEFAULT_TTL_SEC` (default `86400`; fallback active-dispute duration when admin request omits/uses stale `until`)
- `ENTRY_URL` (default `http://127.0.0.1:8083`)
- `EXIT_CONTROL_URL` (default `http://127.0.0.1:8084`)
- `ENTRY_DATA_ADDR` (default `127.0.0.1:51820`)
- `EXIT_DATA_ADDR` (default `127.0.0.1:51821`)
- `DATA_PLANE_MODE` (`json` default, or `opaque`)
- `WG_BACKEND` (`noop` default, `command` for `wg`/`ip` CLI integration; requires `DATA_PLANE_MODE=opaque`)
- `CLIENT_WG_PUBLIC_KEY` (base64 32-byte key; in `CLIENT_WG_BACKEND=command`, auto-derived from `CLIENT_WG_PRIVATE_KEY_PATH` if unset/invalid, and startup fails if a configured key mismatches the derived key; otherwise auto-generated if missing)
- `CLIENT_SUBJECT` (optional client identity subject used for token issuance; leave unset for anonymous tier-1 behavior)
- `CLIENT_WG_BACKEND` (`noop` default, `command` for client-side `wg`/`ip` integration; requires `DATA_PLANE_MODE=opaque` and either `CLIENT_INNER_SOURCE=udp` or `CLIENT_WG_KERNEL_PROXY=1`)
- `CLIENT_WG_INTERFACE` (default `wg-client0`)
- `CLIENT_WG_PRIVATE_KEY_PATH` (required when `CLIENT_WG_BACKEND=command`)
- `CLIENT_WG_ALLOWED_IPS` (default `0.0.0.0/0`; peer `allowed-ips` used in client command backend)
- `CLIENT_WG_INSTALL_ROUTE` (`1` installs `ip route replace <allowed_ip> dev <iface>` for each CIDR in `CLIENT_WG_ALLOWED_IPS`)
- `CLIENT_WG_KERNEL_PROXY` (`1` enables client-side kernel proxy bridge between local WG UDP endpoint and entry opaque tunnel in command mode)
- `CLIENT_WG_PROXY_ADDR` (default `127.0.0.1:0`; UDP listen address used as local WG peer endpoint when `CLIENT_WG_KERNEL_PROXY=1`)
- `CLIENT_INNER_SOURCE` (`synthetic` default, `udp` to read opaque payloads from local UDP socket)
- `CLIENT_DISABLE_SYNTHETIC_FALLBACK` (`1` requires UDP-origin opaque uplink traffic and disables synthetic payload fallback)
- `CLIENT_INNER_UDP_ADDR` (default `127.0.0.1:51900`, used when `CLIENT_INNER_SOURCE=udp`)
- `CLIENT_OPAQUE_SINK_ADDR` (optional UDP sink for opaque downlink payload bytes received from entry; required when `CLIENT_LIVE_WG_MODE=1`)
- `CLIENT_OPAQUE_DRAIN_MS` (default `1200`, downlink read window after client sends uplink packets)
- `CLIENT_OPAQUE_SESSION_SEC` (default `0`; when `>0`, keep opaque uplink/downlink bridging active for this session duration before path close)
- `CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS` (default `1500`; max wait for first UDP uplink packet in command/live-style modes before failing bootstrap)
- `CLIENT_SELECTION_HEALTHCHECK` (default `1`; enable entry/exit control-plane health probes during relay selection)
- `CLIENT_DIRECTORY_MIN_OPERATORS` (fallback `DIRECTORY_MIN_OPERATORS`; minimum distinct directory operators for client bootstrap quorum)
- `CLIENT_HEALTHCHECK_TIMEOUT_MS` (default `700`; per-relay health probe timeout)
- `CLIENT_HEALTHCHECK_CACHE_SEC` (default `5`; cache TTL for relay health probe results)
- `CLIENT_HEALTHCHECK_DISABLE` (`1` disables health probes and falls back to descriptor ordering)
- `CLIENT_EXIT_COUNTRY` (optional ISO alpha-2 preferred exit country, e.g. `US`, `DE`)
- `CLIENT_EXIT_REGION` (optional preferred exit region fallback, e.g. `us-east`)
- `CLIENT_EXIT_STRICT_LOCALITY` (`1` requires preferred country/region match; otherwise bootstrap fails)
- `CLIENT_MAX_EXITS_PER_OPERATOR` (default `0`; when `>0`, cap selected exits per operator before pair ranking)
- `CLIENT_REQUIRE_DISTINCT_OPERATORS` (`1` requires entry/exit pair operators to differ and to be present in relay descriptors)
- `CLIENT_STICKY_PAIR_SEC` (default `0`; when `>0`, prefer the most recently successful entry/exit pair for this duration if still available)
- `CLIENT_SESSION_REUSE` (`1` enables active path reuse across bootstrap cycles; client avoids immediate close/reopen when session remains healthy)
- `CLIENT_SESSION_REFRESH_LEAD_SEC` (default `20`; proactive refresh lead window before session expiry when `CLIENT_SESSION_REUSE=1`, with open-new/close-old handoff)
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
- `CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC` (default `CLIENT_BOOTSTRAP_INTERVAL_SEC`; max retry interval used for exponential bootstrap backoff on consecutive failures)
- `CLIENT_BOOTSTRAP_JITTER_PCT` (default `0`; random retry jitter percentage `0..90` applied around computed bootstrap delay to reduce retry synchronization)
- `CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC` (default `0`; optional startup delay before the first bootstrap attempt, useful when client starts before local issuer/directory roles)
- `EXIT_WG_INTERFACE` (default `wg-exit0`)
- `EXIT_WG_PUBKEY` (optional base64 32-byte key; in `WG_BACKEND=command`, auto-derived from `EXIT_WG_PRIVATE_KEY_PATH` if unset/invalid, and startup fails if a configured key mismatches the derived key)
- `EXIT_WG_PRIVATE_KEY_PATH` (required when `WG_BACKEND=command`)
- `EXIT_WG_LISTEN_PORT` (default `51831`; WireGuard UDP listen port in command mode; must differ from `EXIT_DATA_ADDR` port)
- `EXIT_WG_KERNEL_PROXY` (`1` enables exit-side per-session kernel-proxy bridging between accepted opaque packets and local WG UDP socket in command mode)
- `EXIT_WG_KERNEL_PROXY_MAX_SESSIONS` (default `2048`; max concurrent exit WG kernel-proxy session sockets before new proxy allocations are rejected)
- `EXIT_WG_KERNEL_PROXY_IDLE_SEC` (default `120`; idle timeout for automatic closure of inactive exit WG proxy session sockets, `0` disables idle cleanup)
- `EXIT_SESSION_CLEANUP_SEC` (default `30`; cleanup cadence for expired sessions and idle WG proxy sockets)
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
- `DIRECTORY_PEER_DISCOVERY_MIN_VOTES` (default `1`; minimum distinct source-operator sightings required before a discovered peer is admitted to sync set)
- `DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE` (default `0` disabled; when `>0`, cap active discovered-peer votes contributed by one source operator)
- `DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT` (`1` requires discovered peers to include both signed `operator` and `pub_key` hints before admission)
- `DIRECTORY_PEER_DISCOVERY_FAIL_THRESHOLD` (default `3`; consecutive discovered-peer sync failures before temporary cooldown)
- `DIRECTORY_PEER_DISCOVERY_BACKOFF_SEC` (default `60`; initial discovered-peer cooldown duration in seconds)
- `DIRECTORY_PEER_DISCOVERY_MAX_BACKOFF_SEC` (default `900`; max discovered-peer cooldown duration in seconds with exponential backoff)
- `DIRECTORY_PEER_MIN_OPERATORS` (fallback `DIRECTORY_MIN_OPERATORS`; minimum distinct peer directory operators required for each sync round)
- `DIRECTORY_PEER_MIN_VOTES` (default `1`; minimum matching peer descriptor votes per relay key during sync conflict resolution)
- `DIRECTORY_PEER_SCORE_MIN_VOTES` (default `1`; minimum peer feed votes required before imported peer selection scores are used)
- `DIRECTORY_PEER_TRUST_MIN_VOTES` (default `1`; minimum peer trust-feed votes required before imported trust attestations are used)
- `DIRECTORY_PEER_DISPUTE_MIN_VOTES` (default `DIRECTORY_PEER_TRUST_MIN_VOTES`; minimum peer dispute votes required before imported dispute metadata is propagated)
- `DIRECTORY_PEER_APPEAL_MIN_VOTES` (default `DIRECTORY_PEER_DISPUTE_MIN_VOTES`; minimum peer appeal votes required before imported appeal metadata is propagated)
- `DIRECTORY_ADJUDICATION_META_MIN_VOTES` (default `1`; minimum votes required to publish adjudication metadata fields like `dispute_case`, `dispute_evidence_ref`, `appeal_case`, `appeal_evidence_ref`)
- `DIRECTORY_FINAL_DISPUTE_MIN_VOTES` (default `max(DIRECTORY_PEER_DISPUTE_MIN_VOTES, DIRECTORY_ISSUER_DISPUTE_MIN_VOTES)`; minimum final aggregated votes before publishing `tier_cap`/`dispute_until`)
- `DIRECTORY_FINAL_APPEAL_MIN_VOTES` (default `max(DIRECTORY_PEER_APPEAL_MIN_VOTES, DIRECTORY_ISSUER_APPEAL_MIN_VOTES)`; minimum final aggregated votes before publishing `appeal_until`)
- `DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS` (default `1`; minimum distinct operator signals required before final dispute/appeal publication)
- `DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES` (default `1`; minimum distinct adjudication source classes required before final dispute/appeal publication; source classes are descriptor, peer trust, issuer trust)
- `DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO` (default `0.5`; minimum disputed/appeal vote ratio over final aggregated attestations required to publish adjudication signals)
- `DIRECTORY_DISPUTE_MAX_TTL_SEC` (default `604800`; maximum accepted dispute horizon from peer/issuer trust signals before capping)
- `DIRECTORY_APPEAL_MAX_TTL_SEC` (default `604800`; maximum accepted appeal horizon from peer/issuer trust signals before capping)
- `DIRECTORY_PEER_MAX_HOPS` (default `2`; loop-resistance hop cap for imported peer descriptors)
- `DIRECTORY_PEER_TRUST_STRICT` (`1` enforces trusted key pinning for directory peers)
- `DIRECTORY_PEER_TRUST_TOFU` (`1` default; allow trust-on-first-use for unknown peer keys in strict mode)
- `DIRECTORY_PEER_TRUSTED_KEYS_FILE` (default `data/directory_peer_trusted_keys.txt`)
- `DIRECTORY_ISSUER_TRUST_URLS` (comma-separated issuer URLs for directory trust-attestation ingestion)
- `DIRECTORY_PROVIDER_ISSUER_URLS` (comma-separated issuer URLs accepted for provider-role token verification on provider relay upserts; defaults to issuer trust URLs)
- `DIRECTORY_PROVIDER_RELAY_MAX_TTL_SEC` (default `300`; max provider-advertised relay descriptor TTL)
- `DIRECTORY_PROVIDER_MAX_RELAYS_PER_OPERATOR` (default `0` disabled; when `>0`, cap active provider-advertised relays per operator across entry+exit roles)
- `DIRECTORY_ISSUER_SYNC_SEC` (default `10`; issuer trust sync interval in seconds)
- `DIRECTORY_ISSUER_MIN_OPERATORS` (fallback `DIRECTORY_MIN_OPERATORS`; minimum distinct issuer operators required for each issuer sync round)
- `DIRECTORY_ISSUER_TRUST_MIN_VOTES` (default `1`; minimum matching issuer votes required for imported issuer trust attestations)
- `DIRECTORY_ISSUER_DISPUTE_MIN_VOTES` (default `DIRECTORY_ISSUER_TRUST_MIN_VOTES`; minimum issuer dispute votes required before imported dispute metadata is propagated)
- `DIRECTORY_ISSUER_APPEAL_MIN_VOTES` (default `DIRECTORY_ISSUER_DISPUTE_MIN_VOTES`; minimum issuer appeal votes required before imported appeal metadata is propagated)
- `DIRECTORY_PROVIDER_MIN_ENTRY_TIER` (default `1`; minimum `provider_role` token tier required to advertise `entry` relays via `/v1/provider/relay/upsert`)
- `DIRECTORY_PROVIDER_MIN_EXIT_TIER` (default `1`; minimum `provider_role` token tier required to advertise `exit` relays via `/v1/provider/relay/upsert`)
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
- `ENTRY_CLIENT_REBIND_SEC` (default `0`; when `>0`, allow client UDP source rebind after inactivity window to handle NAT changes)
- `CLIENT_LIVE_WG_MODE` (`1` enforces strict live WG requirements: command backend + UDP source + downlink sink)
- `EXIT_LIVE_WG_MODE` (`1` enforces strict live WG requirements: command backend + no echo + opaque sink/source + plausible WireGuard payload filtering + session-framed downlink source packets)
- `EXIT_EGRESS_BACKEND` (`noop` default, `command` enables NAT setup)
- `EXIT_EGRESS_CHAIN` (default `PRIVNODE_EGRESS`; dedicated NAT chain name in command mode)
- `EXIT_EGRESS_IFACE` (default `eth0`)
- `EXIT_EGRESS_CIDR` (default `10.90.0.0/24`)
- `EXIT_ACCOUNTING_FILE` (optional JSON metrics/accounting snapshot file)
- `EXIT_ACCOUNTING_FLUSH_SEC` (default `10`; accounting snapshot write interval)
- `EXIT_REVOCATION_REFRESH_SEC` (default `15`)
- `EXIT_PEER_REBIND_SEC` (default `0`; when `>0`, allow exit session peer source rebind after inactivity window)
- `EXIT_TOKEN_PROOF_REPLAY_GUARD` (`1` enables nonce replay guard for `token_proof_nonce` on path open)
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
- `POST /v1/provider/relay/upsert` (directory provider-role token gated relay advertisement)
- `GET /v1/admin/sync-status` (directory admin sync/quorum status; requires `X-Admin-Token`)
- `GET /v1/admin/governance-status` (directory admin adjudication policy + aggregate and per-relay disputed/appeal signal/operator status; requires `X-Admin-Token`)
- `GET /v1/admin/peer-status` (directory admin discovered-peer eligibility/cooldown/health status; requires `X-Admin-Token`)
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
- exit validates token claims at `path/open` (`aud=exit`, `token_type=client_access`, PoP key `cnf_ed25519`, unexpired `exp`, valid `tier`, non-empty `jti`; `tier>1` requires `sub`)
- exit also verifies `token_proof` signature on each `path/open` request using the token-bound PoP key
- when replay guard is enabled, exit enforces one-time `token_proof_nonce` values per token lifetime
- `path/open` transport must be `wireguard-udp` and exit returns inner peer hints:
  - `exit_inner_pub`, `client_inner_ip` (allocated per session), `exit_inner_ip`, `inner_mtu`, `keepalive_sec`, `session_key_id`
- if `WG_BACKEND=command`, exit also configures/removes peers via `wg`/`ip` on path open/close
- command backend startup preflight checks `wg`/`ip` binaries, interface presence, and key path readability; client/exit derive WG public keys from private keys when `CLIENT_WG_PUBLIC_KEY` / `EXIT_WG_PUBKEY` are unset/invalid and fail fast on configured key mismatch
- exit command mode requires distinct `EXIT_DATA_ADDR` and `EXIT_WG_LISTEN_PORT` UDP ports (fail-fast on conflicts)
- if `CLIENT_WG_BACKEND=command`, client configures/removes peer using exit hints from `path/open`
- command client backend startup preflight checks `wg`/`ip` binaries, interface presence, and key path readability
- if `CLIENT_WG_KERNEL_PROXY=1`, client points WG peer endpoint to `CLIENT_WG_PROXY_ADDR` and bridges WG UDP packets to/from entry via session-framed opaque datagrams
- if `CLIENT_INNER_SOURCE=udp`, client forwards received UDP packets as opaque payloads instead of synthetic test datagrams
- if `CLIENT_DISABLE_SYNTHETIC_FALLBACK=1`, client requires `CLIENT_INNER_SOURCE=udp` (or `CLIENT_WG_KERNEL_PROXY=1`) and fails bootstrap instead of generating synthetic opaque payloads
- if `EXIT_OPAQUE_SINK_ADDR` is set, exit emits accepted opaque payload bytes to that UDP address
- if `EXIT_OPAQUE_SOURCE_ADDR` is set, exit accepts raw downlink payload bytes and forwards them into active sessions
- if `EXIT_WG_KERNEL_PROXY=1`, exit maps accepted opaque WG payloads into local WG UDP (`EXIT_WG_LISTEN_PORT`) and relays WG downlink packets back into session-framed opaque returns
- exit WG kernel proxy supports operational guardrails: `EXIT_WG_KERNEL_PROXY_MAX_SESSIONS` limits per-session proxy fanout, `EXIT_WG_KERNEL_PROXY_IDLE_SEC` reaps stale proxy sockets, and `/v1/metrics` exposes `wg_proxy_*` counters
- exit source-lock binds session uplink to one peer source by default (prevents source hijack); optional delayed rebind can be enabled with `EXIT_PEER_REBIND_SEC`
- in live WG mode (`CLIENT_LIVE_WG_MODE=1`, `EXIT_LIVE_WG_MODE=1`), sink/source addresses are mandatory, client/exit drop opaque payloads that fail WireGuard framing + minimum-length checks (including client uplink filtering before entry forwarding), entry can enforce additional wireguard plausibility checks with `ENTRY_LIVE_WG_MODE=1`, and raw downlink source packets must be session-framed
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
- Entry data-plane source locking binds each session to the first client UDP source (prevents source hijack); optional delayed rebind is available via `ENTRY_CLIENT_REBIND_SEC`

CI and tests:
- `./scripts/ci_local.sh` (unit tests + internal topology assertions)
- `.github/workflows/ci.yml` runs the local CI script on push/PR
- `./scripts/load_path_open.sh` (basic entry path-open load script)
- `./scripts/integration_challenge.sh` (entry challenge/anti-abuse integration check)
- `./scripts/integration_revocation.sh` (issuer->exit revocation propagation check)
- `./scripts/integration_federation.sh` (multi-directory quorum/vote integration check)
- `./scripts/integration_operator_quorum.sh` (distinct-directory-operator quorum enforcement check)
- `./scripts/integration_sync_status_chaos.sh` (directory sync-status failure/recovery observability under peer churn)
- `./scripts/integration_directory_operator_churn_scale.sh` (multi-operator directory churn/quorum resilience check with transit-source loss/recovery)
- `./scripts/integration_directory_sync.sh` (directory peer sync integration check)
- `./scripts/integration_directory_gossip.sh` (directory push-gossip ingestion integration check)
- `./scripts/integration_peer_discovery.sh` (seeded directory peer discovery + discovered-peer relay import check)
- `./scripts/integration_peer_discovery_quorum.sh` (peer discovery admission quorum: single-source blocked, multi-source admitted)
- `./scripts/integration_peer_discovery_backoff.sh` (discovered-peer failure cooldown/backoff + admin peer-status endpoint check)
- `./scripts/integration_peer_discovery_require_hint.sh` (strict discovery hint-gate check: loose mode admits, strict mode blocks peers without signed hints)
- `./scripts/integration_peer_discovery_source_cap.sh` (per-source discovery cap check: one source can only admit capped peers, multiple sources can still admit additional peers)
- `./scripts/integration_selection_feed.sh` (signed selection-feed requirement integration check)
- `./scripts/integration_trust_feed.sh` (signed trust-feed requirement + bond/stake signal integration check)
- `./scripts/integration_opaque_source_downlink.sh` (exit opaque source downlink return-path integration check)
- `./scripts/integration_opaque_udp_only.sh` (client UDP-only opaque input enforcement check with synthetic fallback disabled)
- `./scripts/integration_client_wg_kernel_proxy.sh` (client command-mode WG kernel proxy bridge check with mocked `wg`/`ip` binaries)
- `./scripts/integration_exit_wg_proxy_limit.sh` (exit WG proxy session-cap enforcement: verifies proxy limit drops while traffic is still accepted for at least one active session)
- `./scripts/integration_exit_wg_proxy_idle_cleanup.sh` (exit WG proxy idle-timeout reaping verification via `wg_proxy_idle_closed` + `active_wg_proxy_sessions` metrics)
- `./scripts/integration_entry_live_wg_filter.sh` (entry live-WG opaque forwarding filter check: non-WG dropped, plausible WG forwarded)
- `./scripts/integration_exit_live_wg_mode.sh` (exit live-WG mode check: non-WG opaque payloads dropped while plausible WG-like traffic is accepted and proxied)
- `./scripts/integration_live_wg_full_path.sh` (client+entry+exit live-WG strict path check: client drops non-WG ingress while plausible WG-like traffic traverses full path and activates exit WG proxy metrics)
- `./scripts/integration_client_bootstrap_recovery.sh` (client-first startup recovery check with delayed infrastructure bring-up and retry backoff validation)
- `./scripts/integration_client_startup_burst.sh` (parallel client startup burst with bootstrap jitter/backoff controls and success/traffic assertions)
- `./scripts/integration_issuer_trust_sync.sh` (directory ingestion of issuer trust attestations check)
- `./scripts/integration_issuer_dispute.sh` (issuer dispute + appeal lifecycle with case/evidence metadata and trust-signal checks)
- `./scripts/integration_adjudication_window_caps.sh` (directory dispute/appeal horizon cap enforcement check against far-future issuer signals)
- `./scripts/integration_adjudication_quorum.sh` (directory final adjudication vote/ratio quorum suppression + governance-status signal/operator + per-relay suppression checks)
- `./scripts/integration_adjudication_operator_quorum.sh` (directory final adjudication distinct-operator quorum suppression check)
- `./scripts/integration_adjudication_source_quorum.sh` (directory final adjudication distinct-source quorum suppression check)
- `./scripts/integration_real_wg_privileged.sh` (manual Linux root-only real `wg`/`ip` command-backend integration check; not part of CI)
- `./scripts/integration_real_wg_privileged_matrix.sh` (manual Linux root-only multi-profile wrapper around privileged real-WG integration)
- `./scripts/integration_lifecycle_chaos.sh` (adversarial dispute/revocation race and stability check; included in deep suite)
- `./scripts/integration_multi_issuer.sh` (exit multi-issuer token/revocation integration check)
- `./scripts/integration_load_chaos.sh` (entry load guardrails + directory peer churn resilience check)
- `./scripts/integration_http_cache.sh` (directory ETag/If-None-Match behavior check)
- `./scripts/integration_directory_auto_key_rotation.sh` (directory automatic key rotation + bounded previous-key history enforcement)
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
1. Complete production end-to-end WireGuard interface plumbing (building on `CLIENT_WG_KERNEL_PROXY` / `EXIT_WG_KERNEL_PROXY`) and remove remaining scaffold-only packet paths.
2. Expand issuer-backed trust lifecycle into cross-operator adjudication/dispute governance.
3. Add larger-scale chaos/stress suites and deployment hardening for beta environments.

Project status detail:
- `docs/mvp-status.md`
- `docs/exit-selection-plan.md` (planned country-aware + reputation-weighted exit selection)
- `docs/testing-guide.md` (how to test end-to-end)
