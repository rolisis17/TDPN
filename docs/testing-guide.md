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
   - federation
   - directory sync
   - selection feed
   - trust feed
   - issuer trust sync
   - issuer dispute
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

Federated directory (multi-source quorum/votes):

```bash
./scripts/integration_federation.sh
```

Directory operator quorum:

```bash
./scripts/integration_operator_quorum.sh
```

Optional stricter anti-capture mode:
- set `DIRECTORY_MIN_OPERATORS=2` (and/or `CLIENT_DIRECTORY_MIN_OPERATORS=2`, `ENTRY_DIRECTORY_MIN_OPERATORS=2`) so one operator cannot satisfy quorum via multiple endpoints.

Directory peer sync (operator-to-operator pull sync):

```bash
./scripts/integration_directory_sync.sh
```

Optional stricter sync conflict policy:
- set `DIRECTORY_PEER_MIN_VOTES=2` (or higher) on syncing directories
- this forces peer descriptor agreement before a relay is imported during conflicts

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

Issuer dispute lifecycle:

```bash
./scripts/integration_issuer_dispute.sh
```

Directory push-gossip ingest:

```bash
./scripts/integration_directory_gossip.sh
```

Directory peer discovery (seeded decentralized membership):

```bash
./scripts/integration_peer_discovery.sh
```

Exit opaque source downlink return path:

```bash
./scripts/integration_opaque_source_downlink.sh
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

- `integration_federation.sh`:
  client can use multiple directories with source/operator quorum and vote thresholds.

- `integration_operator_quorum.sh`:
  client bootstrap fails when quorum is met only by multiple endpoints of one operator, and succeeds when distinct operators are available.

- `integration_directory_sync.sh`:
  one directory imports relays from a peer directory and client can use synced relay data.
  With `DIRECTORY_PEER_MIN_VOTES`, conflicting peer variants can be dropped unless enough peers agree.

- `integration_directory_gossip.sh`:
  a directory accepts signed peer push data on `/v1/gossip/relays` and publishes imported relays.

- `integration_peer_discovery.sh`:
  a seed-connected directory learns additional peer URLs from signed `/v1/peers` feed data (including peer hints) and then imports relays from discovered peers.

- `integration_opaque_source_downlink.sh`:
  exit accepts injected downlink bytes on `EXIT_OPAQUE_SOURCE_ADDR`, forwards them into the active opaque session, and client receives them on sink path (live mode additionally requires session-framed source packets).

- `integration_selection_feed.sh`:
  client can require signed selection feed and still bootstrap successfully.

- `integration_trust_feed.sh`:
  directory publishes signed trust attestations and client can require that feed during bootstrap.

- `integration_issuer_trust_sync.sh`:
  directory ingests issuer-signed trust attestations and merges those signals into published trust/selection outputs.

- `integration_issuer_dispute.sh`:
  issuer applies a temporary dispute cap, opens/resolves appeal state, and validates trust-feed dispute/appeal signaling including case/evidence metadata.

- `integration_lifecycle_chaos.sh`:
  races revocation enforcement and dispute apply/clear loops while path-open traffic continues, then checks for expected revoked denials and no crash/panic.

- `integration_multi_issuer.sh`:
  exit accepts token from a secondary issuer and then denies it after that issuer revokes the token.

- `integration_load_chaos.sh`:
  entry anti-abuse controls trigger under handshake load, and directory peer churn does not break client bootstrap after sync.

- `integration_http_cache.sh`:
  directory `ETag` + `If-None-Match` returns `304` when relay/feed payloads are unchanged (incremental sync path).

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
   - `curl -s -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' --data '{"tier":1,"subject":"client-debug-1","exit_scope":["exit-local-1"]}'`
4. Confirm entry health:
   - `curl -s http://127.0.0.1:8083/v1/health`
5. Re-run one integration script to isolate issue.

## 9) Recommended testing order

1. `./scripts/ci_local.sh`
2. Manual 3-terminal run
3. Individual integration scripts (one by one)
4. Change one config parameter at a time and re-test

This order gives fast confidence, then deeper understanding.
