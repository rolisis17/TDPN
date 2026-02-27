# Testing Guide (Simple, End-to-End)

## 1) What you are testing

This prototype is a two-hop privacy path:
- `client -> entry -> exit`
- control services: `directory` + `issuer`

Core behavior under test:
- client can discover relays and build a path
- entry/exit enforce token and tier policy
- descriptor signatures and trust checks work
- revocation and anti-abuse controls work
- federated directory behavior works (fanout + peer sync)
- selection feed scoring and locality selection work
- signed trust-attestation feed (bond/stake signals) works
- issuer dispute lifecycle can cap/restore trust tier eligibility with case/evidence metadata propagation

## 2) Prerequisites

Required:
- Go installed (`go version`)
- `curl`
- `rg` (ripgrep)
- Linux/macOS shell

Optional easy launcher path:
- `./scripts/install_easy_mode.sh`
- `./bin/privacynode-easy`
- `docs/easy-3-machine-test.md`
- `docs/windows-wsl2.md` (Windows 11 + WSL2 path)

Project root:
- run all commands from repository root

## 3) Fastest full check

Run:

```bash
./scripts/ci_local.sh
```

What this does:
1. Runs all Go tests.
2. Runs internal topology smoke test.
3. Runs integration checks:
   - challenge
   - revocation
   - token-proof replay
   - provider api
   - distinct operators
   - federation
   - directory sync
   - selection feed
   - trust feed
   - opaque source
   - session reuse
   - session handoff
   - issuer trust sync
   - issuer dispute
   - multi-issuer
   - load/chaos

Expected result:
- final line: `[ci] ok`

If it fails:
- script prints relevant logs from `/tmp/*`.

## 4) Manual end-to-end run (to understand flow)

Terminal A:

```bash
go run ./cmd/node --directory --issuer
```

Terminal B:

```bash
go run ./cmd/node --entry --exit
```

Terminal C:

```bash
go run ./cmd/node --client
```

What to expect:
- client logs a selected entry/exit pair
- entry logs accepted path open and forwarding
- exit logs accepted packet handling

This is the simplest full path test.

## 5) How to test specific features

Challenge / anti-abuse:

```bash
./scripts/integration_challenge.sh
```

Revocation:

```bash
./scripts/integration_revocation.sh
```

Token proof replay guard:

```bash
./scripts/integration_token_proof_replay.sh
```

Provider API (`provider_role` enforcement):

```bash
./scripts/integration_provider_api.sh
```

Federated directory (multi-source quorum/votes):

```bash
./scripts/integration_federation.sh
```

Directory operator quorum:

```bash
./scripts/integration_operator_quorum.sh
```

Distinct entry/exit operators (anti-collusion pair filter):

```bash
./scripts/integration_distinct_operators.sh
```

Optional stricter anti-capture mode:
- set `DIRECTORY_MIN_OPERATORS=2` (and/or `CLIENT_DIRECTORY_MIN_OPERATORS=2`, `ENTRY_DIRECTORY_MIN_OPERATORS=2`) so one operator cannot satisfy quorum via multiple endpoints.

Directory peer sync (operator-to-operator pull sync):

```bash
./scripts/integration_directory_sync.sh
```

Directory sync-status failure/recovery observability under peer churn:

```bash
./scripts/integration_sync_status_chaos.sh
```

Directory multi-operator churn/quorum resilience:

```bash
./scripts/integration_directory_operator_churn_scale.sh
```

Optional stricter sync conflict policy:
- set `DIRECTORY_PEER_MIN_VOTES=2` (or higher) on syncing directories
- this forces peer descriptor agreement before a relay is imported during conflicts
- set `DIRECTORY_PEER_MIN_OPERATORS=2` (or higher) so one peer operator cannot satisfy sync quorum via multiple endpoints

Selection feed (signed scoring metadata):

```bash
./scripts/integration_selection_feed.sh
```

Trust-attestation feed (signed bond/stake/reputation metadata):

```bash
./scripts/integration_trust_feed.sh
```

Issuer trust ingestion by directory:

```bash
./scripts/integration_issuer_trust_sync.sh
```

Optional stricter issuer anti-capture policy:
- set `DIRECTORY_ISSUER_MIN_OPERATORS=2` (or higher) so one issuer operator cannot satisfy trust sync quorum via multiple URLs

Issuer dispute lifecycle:

```bash
./scripts/integration_issuer_dispute.sh
```

Adjudication horizon cap enforcement:

```bash
./scripts/integration_adjudication_window_caps.sh
```

Final adjudication vote/ratio quorum enforcement:

```bash
./scripts/integration_adjudication_quorum.sh
```

Final adjudication operator-quorum enforcement:

```bash
./scripts/integration_adjudication_operator_quorum.sh
```

Final adjudication source-quorum enforcement:

```bash
./scripts/integration_adjudication_source_quorum.sh
```

Directory push-gossip ingest:

```bash
./scripts/integration_directory_gossip.sh
```

Directory peer discovery (seeded decentralized membership):

```bash
./scripts/integration_peer_discovery.sh
```

Optional stricter discovery anti-capture policy:
- set `DIRECTORY_PEER_DISCOVERY_MIN_VOTES=2` (or higher) so one peer operator cannot unilaterally admit newly discovered peers
- set `DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE` (for example `8`) so one source operator cannot flood discovery with unlimited peer additions
- set `DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1` so newly discovered peers must include signed operator and pubkey hints before admission

Peer discovery quorum behavior (single-source blocked, multi-source admitted):

```bash
./scripts/integration_peer_discovery_quorum.sh
```

Peer discovery failure backoff + admin peer-status observability:

```bash
./scripts/integration_peer_discovery_backoff.sh
```

Peer discovery strict hint-gate behavior (loose mode admits, strict mode blocks peers without signed hints):

```bash
./scripts/integration_peer_discovery_require_hint.sh
```

Peer discovery per-source admission cap behavior:

```bash
./scripts/integration_peer_discovery_source_cap.sh
```

Optional stricter unstable-peer suppression policy:
- lower `DIRECTORY_PEER_DISCOVERY_FAIL_THRESHOLD` (for example `1`) to quarantine flaky discovered peers faster
- increase `DIRECTORY_PEER_DISCOVERY_BACKOFF_SEC` / `DIRECTORY_PEER_DISCOVERY_MAX_BACKOFF_SEC` to keep repeatedly failing discovered peers out of active sync sets longer

Optional stricter adjudication metadata policy:
- set `DIRECTORY_ADJUDICATION_META_MIN_VOTES=2` (or higher) so `case_id` / `evidence_ref` fields require broader agreement than basic dispute/appeal activation
- set `DIRECTORY_DISPUTE_MAX_TTL_SEC` / `DIRECTORY_APPEAL_MAX_TTL_SEC` to bounded windows (for example `86400`) so imported dispute/appeal windows cannot be pushed arbitrarily far into the future by colluding operators
- set `DIRECTORY_FINAL_DISPUTE_MIN_VOTES`, `DIRECTORY_FINAL_APPEAL_MIN_VOTES`, `DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS`, `DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES`, and `DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO` to require stronger final publication quorum for dispute/appeal signals in the directory trust feed

Exit opaque source downlink return path:

```bash
./scripts/integration_opaque_source_downlink.sh
```

Client opaque UDP-only source enforcement (synthetic fallback disabled):

```bash
./scripts/integration_opaque_udp_only.sh
```

Client command-mode WG kernel proxy bridge (mocked `wg`/`ip`):

```bash
./scripts/integration_client_wg_kernel_proxy.sh
```

Exit WG proxy limit enforcement (mocked `wg`/`ip`):

```bash
./scripts/integration_exit_wg_proxy_limit.sh
```

Exit WG proxy idle cleanup metrics (mocked `wg`/`ip`):

```bash
./scripts/integration_exit_wg_proxy_idle_cleanup.sh
```

Real command-backend WireGuard integration (Linux + root required):

```bash
sudo ./scripts/integration_real_wg_privileged.sh
```

Real command-backend WireGuard profile matrix (Linux + root required):

```bash
sudo ./scripts/integration_real_wg_privileged_matrix.sh
```

If this fails immediately:
- ensure WireGuard kernel support exists (`ip link add dev wg-test0 type wireguard` should succeed, then `ip link del wg-test0`)
- install/enable WireGuard tools/module for your distro before retrying

Entry live-WG forwarding filter:

```bash
./scripts/integration_entry_live_wg_filter.sh
```

Exit live-WG mode drop/accept behavior (non-WG dropped, WG-like accepted):

```bash
./scripts/integration_exit_live_wg_mode.sh
```

Full live-WG strict path (client+entry+exit):

```bash
./scripts/integration_live_wg_full_path.sh
```

Client bootstrap delayed-infrastructure recovery:

```bash
./scripts/integration_client_bootstrap_recovery.sh
```

Client parallel startup burst (jitter/backoff behavior under load):

```bash
./scripts/integration_client_startup_burst.sh
```

Persistent opaque-session bridge (delayed downlink timing):

```bash
./scripts/integration_persistent_opaque_session.sh
```

Active session reuse across bootstrap cycles:

```bash
./scripts/integration_session_reuse.sh
```

Active session refresh handoff (open new path, then close old path):

```bash
./scripts/integration_session_handoff.sh
```

Multi-issuer exit trust:

```bash
./scripts/integration_multi_issuer.sh
```

Load + chaos resilience:

```bash
./scripts/integration_load_chaos.sh
```

Adversarial lifecycle chaos (dispute/revocation race):

```bash
./scripts/integration_lifecycle_chaos.sh
```

HTTP cache/anti-entropy behavior:

```bash
./scripts/integration_http_cache.sh
```

Directory automatic key rotation policy:

```bash
./scripts/integration_directory_auto_key_rotation.sh
```

Key epoch rotation enforcement:

```bash
./scripts/integration_key_epoch_rotation.sh
```

Higher-pressure bootstrap stress:

```bash
./scripts/integration_stress_bootstrap.sh
```

All deep checks in one command:

```bash
./scripts/deep_test_suite.sh
```

## 6) What each integration script proves

- `integration_challenge.sh`:
  entry can require a challenge under rate pressure.

- `integration_revocation.sh`:
  previously valid token is denied after issuer revokes it and exit refreshes feed.

- `integration_token_proof_replay.sh`:
  with replay guard enabled, exit denies repeated `token_proof_nonce` reuse for the same token and accepts a fresh nonce.

- `integration_provider_api.sh`:
  directory accepts relay upsert from `provider_role` token, rejects `client_access` token for the same API, enforces role-specific minimum provider tiers for `entry` vs `exit`, and enforces optional per-operator provider relay cap.

- `integration_federation.sh`:
  client can use multiple directories with source/operator quorum and vote thresholds.

- `integration_operator_quorum.sh`:
  client bootstrap fails when quorum is met only by multiple endpoints of one operator, and succeeds when distinct operators are available.

- `integration_distinct_operators.sh`:
  with `CLIENT_REQUIRE_DISTINCT_OPERATORS=1`, client rejects same-operator entry/exit pairs and succeeds once distinct entry/exit operators are published.

- `integration_directory_sync.sh`:
  one directory imports relays from a peer directory and client can use synced relay data.
  With `DIRECTORY_PEER_MIN_VOTES`, conflicting peer variants can be dropped unless enough peers agree.
  With `DIRECTORY_PEER_MIN_OPERATORS`, sync requires distinct peer operators and ignores duplicate votes from one operator.

- `integration_directory_gossip.sh`:
  a directory accepts signed peer push data on `/v1/gossip/relays` and publishes imported relays.

- `integration_peer_discovery.sh`:
  a seed-connected directory learns additional peer URLs from signed `/v1/peers` feed data (including peer hints) and then imports relays from discovered peers.

- `integration_peer_discovery_backoff.sh`:
  a discovered peer that repeatedly fails sync is temporarily excluded by cooldown/backoff policy, and `/v1/admin/peer-status` reflects cooling state (`eligible=false`, `cooling_down=true`) plus failure metadata.

- `integration_peer_discovery_require_hint.sh`:
  `DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1` prevents admission of peers lacking signed `operator`+`pub_key` hints, while loose mode still admits them.

- `integration_peer_discovery_source_cap.sh`:
  `DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE` limits how many discovered peers one source operator can add; additional peers are still admitted when announced by distinct source operators.

- `integration_exit_live_wg_mode.sh`:
  in `EXIT_LIVE_WG_MODE=1`, exit drops non-WireGuard opaque payloads (`dropped_non_wg_live`) while still accepting/proxying plausible WG-like traffic (`accepted_packets`, `wg_proxy_created`).

- `integration_live_wg_full_path.sh`:
  with `CLIENT_LIVE_WG_MODE=1` + `EXIT_LIVE_WG_MODE=1`, client drops non-WireGuard ingress before entry forwarding while plausible WG-like packets still traverse end-to-end and activate exit WG proxy metrics.

- `integration_opaque_source_downlink.sh`:
  exit accepts injected downlink bytes on `EXIT_OPAQUE_SOURCE_ADDR`, forwards them into the active opaque session, and client receives them on sink path (live mode additionally requires session-framed source packets).
  In command mode, optional `EXIT_WG_KERNEL_PROXY=1` can bridge accepted opaque packets into local WG UDP socket I/O on `EXIT_WG_LISTEN_PORT` (must differ from `EXIT_DATA_ADDR` port).
  Optional client command-mode bridge: `CLIENT_WG_KERNEL_PROXY=1` + `CLIENT_WG_PROXY_ADDR` can bind local WG UDP endpoint directly to the opaque session path.

- `integration_persistent_opaque_session.sh`:
  with `CLIENT_OPAQUE_SESSION_SEC>0`, client keeps opaque uplink/downlink bridging active long enough to receive delayed downlink probes that would miss a short drain-only window.

- `integration_session_reuse.sh`:
  with `CLIENT_SESSION_REUSE=1`, client keeps the path active and reuses the same session on subsequent bootstrap cycles instead of immediate close/reopen churn.

- `integration_session_handoff.sh`:
  with short token TTL plus refresh lead, client opens a replacement session first, then closes the old session, preserving continuity across refresh.

- `integration_selection_feed.sh`:
  client can require signed selection feed and still bootstrap successfully.

- `integration_trust_feed.sh`:
  directory publishes signed trust attestations and client can require that feed during bootstrap.

- `integration_issuer_trust_sync.sh`:
  directory ingests issuer-signed trust attestations and merges those signals into published trust/selection outputs.
  With `DIRECTORY_ISSUER_MIN_OPERATORS`, sync requires distinct issuer operators and dedupes duplicate votes from one issuer operator.

- `integration_issuer_dispute.sh`:
  issuer applies a temporary dispute cap, opens/resolves appeal state, and validates trust-feed dispute/appeal signaling including case/evidence metadata.

- `integration_adjudication_window_caps.sh`:
  directory ingests far-future dispute/appeal windows from issuer trust feed and caps them to configured local horizons before publication.

- `integration_adjudication_quorum.sh`:
  directory governance policy can suppress final dispute publication when aggregated vote ratio does not meet `DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO`; `/v1/admin/governance-status` reports the active policy, upstream dispute signal/operator counts, operator-id sets, suppressed-vs-published disputed counters, and per-relay suppression details.

- `integration_adjudication_operator_quorum.sh`:
  directory governance policy can suppress final dispute publication when disputed signals come from fewer than `DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS` distinct operators.

- `integration_adjudication_source_quorum.sh`:
  directory governance policy can suppress final dispute publication when disputed signals come from fewer than `DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES` distinct adjudication source classes.

- `integration_sync_status_chaos.sh`:
  directory admin sync-status endpoint reports failed quorum while peer is down, success with operator attribution after recovery, and failure again after peer loss.

- `integration_directory_operator_churn_scale.sh`:
  validates larger multi-operator topology behavior: relay import across transit operators, quorum drop on one transit loss, quorum recovery after restart, and relay continuity under seed churn.

- `integration_opaque_udp_only.sh`:
  client accepts UDP-origin opaque uplink traffic with synthetic fallback disabled and rejects synthetic-source configuration in strict mode.

- `integration_client_wg_kernel_proxy.sh`:
  client command backend can bind a local WG proxy UDP endpoint (`CLIENT_WG_KERNEL_PROXY=1`) and relay packets through entry/exit using mocked `wg`/`ip` commands in non-privileged test environments.

- `integration_exit_wg_proxy_limit.sh`:
  with `EXIT_WG_KERNEL_PROXY_MAX_SESSIONS=1`, concurrent client sessions trigger `wg_proxy_limit_drops` while one active proxy session still carries accepted traffic.

- `integration_exit_wg_proxy_idle_cleanup.sh`:
  with short `EXIT_WG_KERNEL_PROXY_IDLE_SEC` and `EXIT_SESSION_CLEANUP_SEC`, exit reaps inactive proxy sockets and reports `wg_proxy_idle_closed` with `active_wg_proxy_sessions=0`.

- `integration_real_wg_privileged.sh`:
  Linux root-only manual integration check for real `wg`/`ip` command backends (no mocks), including actual interface bring-up, interface peer wiring checks (`wg show` peers/endpoints/listen-port), and WG-kernel-proxy packet-flow verification.

- `integration_real_wg_privileged_matrix.sh`:
  Linux root-only wrapper that runs privileged real-WG integration across multiple interface/port/startup profiles to catch environment-specific regressions.

- `integration_entry_live_wg_filter.sh`:
  with `ENTRY_LIVE_WG_MODE=1`, entry drops malformed/non-WG opaque packets for `wireguard-udp` sessions while still forwarding plausible WG packets to exit.

- `integration_client_bootstrap_recovery.sh`:
  client starts before directory/issuer/entry/exit are online, records bootstrap failures, then recovers automatically after infrastructure comes up and forwards packets successfully.

- `integration_client_startup_burst.sh`:
  runs many clients in parallel with bootstrap jitter/backoff settings and checks that a healthy majority establish paths without panics while exit traffic counters advance.

- `integration_lifecycle_chaos.sh`:
  races revocation enforcement and dispute apply/clear loops while path-open traffic continues, then checks for expected revoked denials and no crash/panic.

- `integration_multi_issuer.sh`:
  exit accepts token from a secondary issuer and then denies it after that issuer revokes the token.

- `integration_load_chaos.sh`:
  entry anti-abuse controls trigger under handshake load, and directory peer churn does not break client bootstrap after sync.

- `integration_http_cache.sh`:
  directory `ETag` + `If-None-Match` returns `304` when relay/feed payloads are unchanged (incremental sync path).

- `integration_directory_auto_key_rotation.sh`:
  directory auto-rotates signing keys and enforces bounded previous-key history retention.

- `integration_key_epoch_rotation.sh`:
  old token is denied after issuer rotates signing key epoch; freshly issued token remains accepted.

- `integration_stress_bootstrap.sh`:
  many client bootstrap attempts run concurrently and verify no panic/regression while traffic metrics advance.

## 7) Simple architecture mental model

- `directory`:
  publishes signed relay descriptors, selection feed, and trust-attestation feed.

- `issuer`:
  issues short-lived signed capability tokens.

- `entry`:
  opens path and forwards packets to selected exit.

- `exit`:
  validates token/session and enforces policy.

- `client`:
  discovers relays, requests token, opens path, sends traffic.

Data path:
- packet bytes go through entry and exit.
- no single role sees full user identity + destination context together (split trust model).

## 8) Common debug checks

If client does not bootstrap:
1. Confirm ports are free: `8081`, `8082`, `8083`, `8084`.
2. Confirm directory response:
   - `curl -s http://127.0.0.1:8081/v1/relays`
3. Confirm issuer response:
   - `pop=$(go run ./cmd/tokenpop gen)`
   - `pop_pub=$(echo "$pop" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')`
   - `curl -s -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' --data "{\"tier\":1,\"subject\":\"client-debug-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"]}"`
4. Confirm entry health:
   - `curl -s http://127.0.0.1:8083/v1/health`
5. Re-run one integration script to isolate issue.

## 9) Recommended testing order

1. `./scripts/ci_local.sh`
2. Manual 3-terminal run
3. Individual integration scripts (one by one)
4. Change one config parameter at a time and re-test

This order gives fast confidence, then deeper understanding.
