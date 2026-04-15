# TDPN Chain Protobuf Contracts

This directory contains schema-first protobuf contracts for phase-1 TDPN chain modules.

## Current status

- `proto3` schemas exist for `vpnbilling`, `vpnrewards`, `vpnslashing`, and `vpnsponsor`.
- `Msg` and `Query` services are defined for tx/query surfaces.
- Buf tooling is scaffolded via:
  - `../buf.yaml`
  - `../buf.gen.yaml`
  - `../scripts/gen_proto.sh`

## Layout

- `proto/tdpn/<module>/v1/types.proto`: core record messages
- `proto/tdpn/<module>/v1/tx.proto`: `service Msg` and tx request/response messages
- `proto/tdpn/<module>/v1/query.proto`: `service Query` and get-by-id query messages

## Run lint + codegen

From `blockchain/tdpn-chain`:

```bash
./scripts/gen_proto.sh
```

For environments that only need contract validation:

```bash
./scripts/gen_proto.sh --lint-only
```

The script:

1. Verifies `buf` is installed and in `PATH`.
2. Runs `buf lint`.
3. Runs `buf generate` (unless `--lint-only` is used).
4. Writes generated outputs to `proto/gen/go`.

If `buf` is not installed, the script exits with install instructions:
- [Buf installation docs](https://docs.buf.build/installation)

## Expected outputs

- Generated Go/protobuf artifacts are written under:
  - `proto/gen/go`
- This repo currently checks in generated Go/protobuf outputs used by chain modules,
  gRPC registration, and phase-6 contract/runtime checks.
- When schemas change, regenerate locally with `./scripts/gen_proto.sh` and update
  checked-in generated artifacts under `proto/gen/go`.
