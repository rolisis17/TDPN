# Cosmos Settlement Runtime Wiring

This guide captures the runtime wiring between VPN services and the Cosmos-first settlement control plane.

## Core Principle

- VPN dataplane/session forwarding remains independent from chain liveness.
- Settlement, rewards, sponsor reservations, and slash evidence are fail-soft control-plane operations.
- When chain submissions fail, operations are deferred and reconciled asynchronously.

## Common Settlement Configuration

Use these in issuer/exit service environments:

- `SETTLEMENT_CHAIN_ADAPTER=cosmos`
- `SETTLEMENT_PRICE_PER_MIB_MICROS` (default `1000`)
- `SETTLEMENT_CURRENCY` (default `TDPNC`)
- `SETTLEMENT_NATIVE_CURRENCY` (optional native-token flow)
- `SETTLEMENT_NATIVE_RATE_NUMERATOR` / `SETTLEMENT_NATIVE_RATE_DENOMINATOR`
- `COSMOS_SETTLEMENT_ENDPOINT` (required when adapter=`cosmos`)
- `COSMOS_SETTLEMENT_API_KEY` (optional bearer auth)
- `COSMOS_SETTLEMENT_QUEUE_SIZE` (default `256`)
- `COSMOS_SETTLEMENT_MAX_RETRIES` (default `3`)
- `COSMOS_SETTLEMENT_BASE_BACKOFF_MS` (default `250`)
- `COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS` (default `4000`)
- `COSMOS_SETTLEMENT_SUBMIT_MODE` (`http|signed-tx`, default `http`)
- `COSMOS_SETTLEMENT_SIGNED_TX_BROADCAST_PATH` (default `/cosmos/tx/v1beta1/txs`, signed-tx mode)
- `COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID` (signed-tx mode chain hint)
- `COSMOS_SETTLEMENT_SIGNED_TX_SIGNER` (required in signed-tx mode)
- `COSMOS_SETTLEMENT_SIGNED_TX_SECRET` (inline secret; required unless secret-file is provided)
- `COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE` (optional secret file path; used when inline secret is empty)
- `COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID` (optional signer key id tag embedded in signed-tx payload)

`COSMOS_SETTLEMENT_ENDPOINT` may point to a local `tdpnd` settlement HTTP bridge when running chain-integrated settlement control-plane flows.

Signed-tx mode note:
- `COSMOS_SETTLEMENT_SIGNED_TX_SIGNER` is required when `COSMOS_SETTLEMENT_SUBMIT_MODE=signed-tx`.
- Secret resolution order: `COSMOS_SETTLEMENT_SIGNED_TX_SECRET` first; if empty, `COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE` is read and trimmed and must resolve to non-empty content.
- Service behavior remains fail-soft: VPN session setup/forwarding stays available while settlement writes are deferred and reconciled later.

## TDPND Settlement HTTP Bridge

- Optional runtime flags:
  - `--settlement-http-listen`
  - `--settlement-http-auth-token`
  - `--state-dir` (optional file-backed module stores under one runtime state root)
- Example:
  - `go run ./cmd/tdpnd --settlement-http-listen 127.0.0.1:8080 --state-dir ./.tdpn-chain-state`
- Endpoint/auth contract:
  - `GET /health` (no auth)
  - write (`POST`) endpoints:
    - `POST /x/vpnbilling/settlements`
    - `POST /x/vpnrewards/issues`
    - `POST /x/vpnsponsor/reservations`
    - `POST /x/vpnslashing/evidence`
      - v1 validation expectation: slash evidence must be machine-verifiable, and `evidence_ref`/proof reference must use `sha256:<value>` or `obj://<path>`.
      - Bridge mapping no longer derives proof references from violation-type fallback; callers must provide canonical proof references.
  - query (`GET`) endpoints:
    - `GET /x/vpnbilling/reservations` and `GET /x/vpnbilling/reservations/{reservation_id}`
    - `GET /x/vpnbilling/settlements` and `GET /x/vpnbilling/settlements/{settlement_id}`
    - `GET /x/vpnrewards/accruals` and `GET /x/vpnrewards/accruals/{accrual_id}`
    - `GET /x/vpnrewards/distributions` and `GET /x/vpnrewards/distributions/{distribution_id}`
    - `GET /x/vpnsponsor/authorizations` and `GET /x/vpnsponsor/authorizations/{authorization_id}`
    - `GET /x/vpnsponsor/delegations` and `GET /x/vpnsponsor/delegations/{reservation_id}`
    - `GET /x/vpnslashing/evidence` and `GET /x/vpnslashing/evidence/{evidence_id}`
    - `GET /x/vpnslashing/penalties` and `GET /x/vpnslashing/penalties/{penalty_id}`
  - when `--settlement-http-auth-token` is set, bearer auth is required on `POST` endpoints only; `GET` query paths and `GET /health` remain open.
- VPN services can target this bridge with `COSMOS_SETTLEMENT_ENDPOINT=http://127.0.0.1:8080`.
- Bridge responsibilities remain control-plane only; VPN dataplane forwarding does not couple to bridge liveness.

One-command local helper:
- `scripts/cosmos_bridge_local_stack.sh` starts `tdpnd` in bridge mode and prints issuer/exit env wiring.
- Dry-run contract (print only, no process start):
  - `scripts/cosmos_bridge_local_stack.sh --dry-run --settlement-http-listen 127.0.0.1:8080 --grpc-listen 127.0.0.1:9090 --auth-token local-bridge-token --state-dir ./.tdpn-chain-state`
- Live local run:
  - `scripts/cosmos_bridge_local_stack.sh --settlement-http-listen 127.0.0.1:8080 --grpc-listen 127.0.0.1:9090 --state-dir ./.tdpn-chain-state`
  - helper also exports `TDPN_CHAIN_STATE_DIR` when `--state-dir` is set.

## Issuer Runtime Controls

- `ISSUER_SETTLEMENT_RECONCILE_SEC` (default `60`, `0` disables periodic reconcile loop)
- `ISSUER_REQUIRE_PAYMENT_PROOF` (`1` requires payment proof for client-access token issuance)
- `ISSUER_SPONSOR_API_TOKEN` (required for `/v1/sponsor/*` auth)

Issuer control-plane endpoints:

- Sponsor API:
  - `POST /v1/sponsor/quote`
  - `POST /v1/sponsor/reserve`
  - `GET /v1/sponsor/status?reservation_id=...`
  - `POST /v1/sponsor/token`
- Settlement status:
  - `GET /v1/settlement/status` (admin auth required, returns reconcile/backlog counters; fail-soft degraded `503` payload if reconcile fails)
- Objective slash evidence intake (admin):
  - `POST /v1/admin/slash/evidence`
  - accepts only objective machine-verifiable evidence in v1, with `evidence_ref`/proof reference format `sha256:<value>` or `obj://<path>`.

## Exit Runtime Controls

- `EXIT_SESSION_RESERVE_MICROS` (default `200000`)
- `EXIT_SETTLEMENT_RECONCILE_SEC` (default `60`, `0` disables periodic reconcile loop)

Exit service records usage, settles sessions, and issues provider rewards while keeping close-path non-blocking if settlement/chain steps fail.
Exit settlement status endpoint:
- `GET /v1/settlement/status` (returns latest backlog snapshot; if reconcile fails response stays `200` with `stale=true` and `last_error`)

## Reconciliation Behavior

- Deferred adapter operations are tracked per idempotency key (`pending` lifecycle).
- Periodic reconcile loops in issuer/exit call settlement `Reconcile(...)`.
- Successful replay marks settlement/reward/sponsor/slash operations `submitted` and clears deferred backlog.
- When adapter query surfaces observe by-id bridge records, reconcile promotes settlement/reward/sponsor/slash operations from `submitted` to `confirmed`.
- Failures remain deferred and are retried in future cycles.
- Cosmos adapter retry policy:
  - retryable: transport/network errors, HTTP `408`, `425`, `429`, and `5xx`.
  - non-retryable: other HTTP `4xx` validation/auth-style failures (no retry loop).

## CI Acceptance Coverage

- `scripts/integration_cosmos_settlement_acceptance_paths.sh` runs deterministic acceptance coverage for:
  - sponsor happy path (`reserve -> payment authorization -> token issue`),
  - chain-outage fail-soft semantics (deferred adapter writes and non-blocking session close/status),
  - dual-asset pricing surface (stable-denominated baseline with native-token conversion parity).
- This check is wired into `scripts/ci_local.sh` under the Cosmos settlement block.
- `scripts/integration_cosmos_tdpnd_state_dir_persistence.sh` validates `tdpnd --state-dir` integration and scaffold persistence/reopen behavior for file-backed module stores.
- This state-dir persistence check is wired into `scripts/ci_local.sh` under the Cosmos runtime block.
- Phase5 CI treats settlement adapter roundtrip as a first-class stage: `settlement_adapter_roundtrip` runs `scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh`.

## Chain gRPC Contract

- Chain module boundary expects generated gRPC service surfaces from `blockchain/tdpn-chain/proto/gen/go/tdpn/*/v1/*_grpc.pb.go`.
- Runtime registration contract per module is:
  - `RegisterMsgServer(...)` for tx service handlers.
  - `RegisterQueryServer(...)` for query/read-model handlers.
- Optional local serve mode:
  - `go run ./cmd/tdpnd --grpc-listen 127.0.0.1:9090`
  - optional runtime hardening flags:
    - `--grpc-tls-cert`
    - `--grpc-tls-key`
    - `--grpc-auth-token`
  - `tdpnd` exposes gRPC health + reflection and exits gracefully on `SIGINT`/`SIGTERM`.
  - when `--grpc-auth-token` is set:
    - module RPC requests require `authorization: Bearer <token>`,
    - health remains available without auth,
    - reflection is disabled.
- Local module wiring contract:
  - `blockchain/tdpn-chain/go.mod` requires `github.com/tdpn/tdpn-chain/proto/gen/go v0.0.0`.
  - `blockchain/tdpn-chain/go.mod` replaces it with `./proto/gen/go`.
- CI guard: `scripts/integration_cosmos_proto_grpc_surface.sh` compiles generated proto gRPC packages through the chain root module and verifies registration symbols.

### Quick gRPC smoke

- Run registration/compile guard:
  - `./scripts/integration_cosmos_proto_grpc_surface.sh`
  - `./scripts/integration_cosmos_tdpnd_grpc_runtime_smoke.sh`
  - `./scripts/integration_cosmos_tdpnd_settlement_bridge_smoke.sh`
  - `./scripts/integration_cosmos_tdpnd_state_dir_persistence.sh`
  - `./scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh`
  - `./scripts/integration_cosmos_bridge_local_stack_contract.sh`
  - `./scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh`
  - `./scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh`
- CI/runtime smoke suite split:
  - `integration_cosmos_tdpnd_grpc_runtime_smoke.sh`: targeted `cmd/tdpnd` runtime tests, including auth/TLS behavior.
  - `integration_cosmos_tdpnd_settlement_bridge_smoke.sh`: targeted settlement HTTP bridge runtime tests (`/health`, module POST writes, module GET query/list paths, auth checks, and combined gRPC/HTTP serve mode).
  - `integration_cosmos_tdpnd_state_dir_persistence.sh`: targeted state-dir persistence tests (`app` scaffold reopen + `cmd/tdpnd` state-dir runtime wiring/error propagation).
  - `integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh`: live `tdpnd --settlement-http-listen` process smoke (startup, auth enforcement, module POST acceptance, graceful shutdown).
  - `integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh`: live adapter roundtrip from `pkg/settlement` into `tdpnd` bridge endpoints (settlement/reward/sponsor/slash submission paths).
  - `integration_cosmos_tdpnd_grpc_live_smoke.sh`: live `tdpnd --grpc-listen` process smoke (startup, health/reflection availability, graceful shutdown).
- Live local smoke:
  - run `tdpnd` with `--grpc-listen` (plus optional TLS/auth flags).
  - health check (`grpcurl`): `grpcurl -d '{"service":""}' 127.0.0.1:9090 grpc.health.v1.Health/Check`.
  - module RPC call (`grpcurl`, token mode): include `-H "authorization: Bearer $TOKEN"` when `--grpc-auth-token` is enabled.
  - reflection list (`grpcurl`): available only when auth token mode is not enabled.
  - fallback when `grpcurl` is unavailable: run `scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh`.
  - stop with `Ctrl+C` and confirm graceful shutdown.
