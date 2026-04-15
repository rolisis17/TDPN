# TDPN Chain Workspace (Cosmos + CometBFT)

Status: scaffolding baseline for Cosmos-first rollout.

This workspace defines the initial module boundaries for TDPN's VPN-compatible blockchain layer.

## Canonical constraints
- VPN dataplane must remain independent from chain finality/liveness.
- Chain outages must not hard-stop active VPN sessions.
- Settlement/reward/slash operations are control-plane concerns and may defer/reconcile.

## Initial modules
- `x/vpnbilling`: prepaid balance accounting, sponsor session-credit reservations, settlement finalization.
- `x/vpnrewards`: provider reward accrual/distribution events.
- `x/vpnslashing`: objective slash evidence ingestion and deterministic penalty execution.
- `x/vpnsponsor`: sponsor account controls and credit delegation to end-user sessions.

## Governance posture (hybrid v1)
- Objective machine-verifiable events can be enforced on-chain.
- Subjective abuse decisions remain policy-governed/multisig during bootstrap.

## Integration notes
- Current app-side bridge is `pkg/settlement` with optional Cosmos adapter.
- Issuer sponsor API endpoints map to `quote -> reserve -> token issue -> status` flow.
- Runtime env/operator wiring reference: `docs/cosmos-settlement-runtime.md`.
- Local multi-node operator bootstrap: `docs/local-testnet.md`.
- Local acceptance gate for settlement control-plane behavior: `scripts/integration_cosmos_settlement_acceptance_paths.sh`.

## Scaffold status
- Go scaffold entrypoint: `cmd/tdpnd`.
- Optional local gRPC serve mode:
  - `go run ./cmd/tdpnd --grpc-listen 127.0.0.1:9090 --state-dir ./.tdpn-chain-state`
  - optional runtime hardening flags:
    - `--grpc-tls-cert`
    - `--grpc-tls-key`
    - `--grpc-auth-token`
    - `--state-dir` (optional file-backed module stores under one runtime state root)
  - `tdpnd` handles `SIGINT`/`SIGTERM` with graceful gRPC shutdown.
- Optional settlement HTTP bridge mode:
  - `go run ./cmd/tdpnd --settlement-http-listen 127.0.0.1:8080 --state-dir ./.tdpn-chain-state`
  - optional auth flag:
    - `--settlement-http-auth-token`
  - optional persistence flag:
    - `--state-dir`
  - endpoint/auth contract:
    - `GET /health` (no auth)
    - write (`POST`) endpoints:
      - `POST /x/vpnbilling/settlements`
      - `POST /x/vpnrewards/issues`
      - `POST /x/vpnsponsor/reservations`
      - `POST /x/vpnslashing/evidence`
    - query (`GET`) endpoints:
      - `GET /x/vpnbilling/reservations` and `GET /x/vpnbilling/reservations/{reservation_id}`
      - `GET /x/vpnbilling/settlements` and `GET /x/vpnbilling/settlements/{settlement_id}`
      - `GET /x/vpnrewards/accruals` and `GET /x/vpnrewards/accruals/{accrual_id}`
      - `GET /x/vpnrewards/distributions` and `GET /x/vpnrewards/distributions/{distribution_id}`
      - `GET /x/vpnsponsor/authorizations` and `GET /x/vpnsponsor/authorizations/{authorization_id}`
      - `GET /x/vpnsponsor/delegations` and `GET /x/vpnsponsor/delegations/{reservation_id}`
      - `GET /x/vpnslashing/evidence` and `GET /x/vpnslashing/evidence/{evidence_id}`
      - `GET /x/vpnslashing/penalties` and `GET /x/vpnslashing/penalties/{penalty_id}`
    - bearer auth is required on `POST` endpoints only when `--settlement-http-auth-token` is set; `GET` query routes and `GET /health` remain open.
  - issuer/exit services can point `COSMOS_SETTLEMENT_ENDPOINT` to this bridge.
  - this bridge is control-plane only and does not couple VPN dataplane forwarding to chain/bridge liveness.
  - one-command local helper from repo root:
    - `scripts/cosmos_bridge_local_stack.sh --settlement-http-listen 127.0.0.1:8080 --grpc-listen 127.0.0.1:9090 --state-dir ./.tdpn-chain-state`
    - `scripts/cosmos_bridge_local_stack.sh --dry-run --settlement-http-listen 127.0.0.1:8080 --auth-token local-bridge-token --state-dir ./.tdpn-chain-state`
    - helper prints issuer/exit env exports:
      - `SETTLEMENT_CHAIN_ADAPTER=cosmos`
      - `COSMOS_SETTLEMENT_ENDPOINT=http://...`
      - optional `COSMOS_SETTLEMENT_API_KEY=...`
      - optional `TDPN_CHAIN_STATE_DIR=...`
- Placeholder app wiring: `app/scaffold.go`.
- Phase-1 app wiring exposes module msg servers:
  - `ChainScaffold.BillingMsgServer()` (`CreateReservation`, `FinalizeSettlement`)
  - `ChainScaffold.RewardsMsgServer()` (`CreateAccrual`, `RecordDistribution`)
  - `ChainScaffold.SlashingMsgServer()` (`SubmitEvidence`, `ApplyPenalty`)
  - `ChainScaffold.SponsorMsgServer()` (`CreateAuthorization`, `DelegateCredit`)
- Module stubs: `x/*/{types,keeper,module}`.
- Module query servers are available for get-by-id and list read-model queries under `x/*/module/query_server.go`.
- Protobuf contracts and generated Go/grpc surfaces are available under:
  - `proto/tdpn/*/v1/{types,tx,query}.proto`
  - `proto/gen/go/tdpn/*/v1/*.pb.go`
- Root chain module consumes generated proto module locally:
  - `go.mod` includes `require github.com/tdpn/tdpn-chain/proto/gen/go v0.0.0`
  - `go.mod` includes `replace github.com/tdpn/tdpn-chain/proto/gen/go => ./proto/gen/go`
- gRPC registration/runtime contract for each module is the generated pair:
  - `RegisterMsgServer(...)` from `tx_grpc.pb.go`
  - `RegisterQueryServer(...)` from `query_grpc.pb.go`
- Proto toolchain scaffold:
  - `./scripts/gen_proto.sh --lint-only` (contract validation only)
  - `./scripts/gen_proto.sh` (lint + generate when Buf toolchain is installed)
  - `./scripts/integration_cosmos_proto_grpc_surface.sh` (CI guard for local proto-module wiring + gRPC registration surface)
- Bridge mapping details: `docs/settlement-bridge-mapping.md`.

## gRPC smoke
- Registration expectation: each module exposes generated `Msg` + `Query` services (8 total registrations across billing/rewards/slashing/sponsor).
- Runtime behavior with `tdpnd --grpc-listen`: gRPC health (`grpc.health.v1.Health`) and server reflection are also exposed.
- In `--grpc-auth-token` mode:
  - module RPCs require `authorization: Bearer <token>`,
  - health remains available without auth for liveness,
  - reflection is disabled.
- Fast local check:
  - `./scripts/integration_cosmos_proto_grpc_surface.sh`
  - `./scripts/integration_cosmos_tdpnd_grpc_runtime_smoke.sh`
  - `./scripts/integration_cosmos_tdpnd_settlement_bridge_smoke.sh`
  - `./scripts/integration_cosmos_tdpnd_state_dir_persistence.sh`
  - `./scripts/integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh`
  - `./scripts/integration_cosmos_bridge_local_stack_contract.sh`
  - `./scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh`
  - `./scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh`
- CI/runtime smoke suite coverage:
  - `integration_cosmos_tdpnd_grpc_runtime_smoke.sh`: targeted `cmd/tdpnd` runtime tests, including auth/TLS behavior.
  - `integration_cosmos_tdpnd_settlement_bridge_smoke.sh`: targeted settlement HTTP bridge runtime tests (`/health`, module POST write routes, module GET query/list routes, auth checks, and combined gRPC+HTTP serve mode).
  - `integration_cosmos_tdpnd_state_dir_persistence.sh`: targeted state-dir persistence runtime tests (`app` scaffold reopen + `cmd/tdpnd` state-dir wiring/error checks).
  - `integration_cosmos_tdpnd_settlement_bridge_live_smoke.sh`: live `tdpnd --settlement-http-listen` process smoke (startup, auth enforcement, module POST acceptance, graceful shutdown).
  - `integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh`: live adapter roundtrip from `pkg/settlement` through bridge submission paths.
  - `integration_cosmos_tdpnd_grpc_live_smoke.sh`: live `tdpnd --grpc-listen` process smoke (startup, health/reflection availability, graceful shutdown).
- Optional live smoke:
  - start `tdpnd` with `--grpc-listen` (plus optional TLS/auth flags)
  - health check (`grpcurl`): `grpcurl -d '{"service":""}' 127.0.0.1:9090 grpc.health.v1.Health/Check`
  - module RPC (`grpcurl`, token mode): include `-H "authorization: Bearer $TOKEN"` when `--grpc-auth-token` is enabled
  - reflection list (`grpcurl`): available only when auth token mode is not enabled
  - if `grpcurl` is missing, use `scripts/integration_cosmos_tdpnd_grpc_live_smoke.sh` as the fallback smoke path.
  - stop with `Ctrl+C` and confirm graceful shutdown.

## Phase-1 stateful milestones
- `vpnbilling`: `CreateReservation` and `FinalizeSettlement` execute as stateful operations over keeper storage.
- `vpnrewards`: `CreateAccrual` and `RecordDistribution` execute as stateful operations with accrual-confirmation advancement.
- `vpnslashing`: `SubmitEvidence` and `ApplyPenalty` execute as stateful operations with evidence-confirmation advancement.
- `vpnsponsor`: `CreateAuthorization` and `DelegateSessionCredit` execute as stateful operations with authorization checks.
- Replay safety is idempotent by operation key for each module; identical replays are accepted while conflicting duplicate payloads are rejected.
- Storage remains an in-memory placeholder; Cosmos SDK KV store integration is still pending.
