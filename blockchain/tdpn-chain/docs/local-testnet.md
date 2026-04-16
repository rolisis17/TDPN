# Local Multi-Node Testnet (tdpnd)

This guide bootstraps a deterministic local `tdpnd` testnet for operator smoke checks.

## What it creates
- Testnet root: `./.tdpn-testnet`
- Per-node directories: `./.tdpn-testnet/node1`, `node2`, `node3`, ...
- Per-node files:
  - `node.env` (node config)
  - `tdpnd.log` (runtime logs)
  - `tdpnd.pid` (pid tracking)
  - `state/` (per-node `--state-dir`)
- Manifest file: `./.tdpn-testnet/manifest.env`

Ports are deterministic:
- Node `i` gRPC: `base_grpc_port + (i - 1)` (default base `19090`)
- Node `i` settlement HTTP: `base_settlement_port + (i - 1)` (default base `18080`)
- Node `i` Comet P2P (comet mode): `base_grpc_port + node_count + (i - 1)`
- Node `i` Comet RPC (comet mode): `base_settlement_port + node_count + (i - 1)`

Runtime mode is explicit. The default is `scaffold`, which preserves the current behavior. `comet` is available for exercising the newer Comet runtime path.
The local scripts refuse mode mismatches between the manifest, node config, and any explicit `--runtime-mode` override.

## Scripts
- `scripts/testnet_local_init.sh`
- `scripts/testnet_local_start.sh`
- `scripts/testnet_local_status.sh`
- `scripts/testnet_local_stop.sh`

All scripts use shell safety defaults (`set -euo pipefail`) and support `--help`.

## Quick start
From `blockchain/tdpn-chain`:

```bash
# existing scaffold mode (default)
scripts/testnet_local_init.sh --node-count 3
scripts/testnet_local_start.sh
scripts/testnet_local_status.sh
scripts/testnet_local_stop.sh

# comet mode, carried through init/start/status/stop
scripts/testnet_local_init.sh --node-count 3 --runtime-mode comet
scripts/testnet_local_start.sh --runtime-mode comet
scripts/testnet_local_status.sh --runtime-mode comet
scripts/testnet_local_stop.sh --runtime-mode comet
```

## Dry-run contract (no processes started)
```bash
# one real init generates deterministic node metadata under ./.tdpn-testnet
scripts/testnet_local_init.sh --node-count 3

# start/status/stop can then be exercised in dry-run mode
scripts/testnet_local_start.sh --dry-run
scripts/testnet_local_status.sh --dry-run
scripts/testnet_local_stop.sh --dry-run
```

## Useful options
- `testnet_local_init.sh`
  - `--testnet-dir <path>`
  - `--node-count <n>`
  - `--base-grpc-port <port>`
  - `--base-settlement-port <port>`
  - `--host <addr>`
  - `--runtime-mode <scaffold|comet>`
  - `--dry-run`
- `testnet_local_start.sh`
  - `--testnet-dir <path>`
  - `--runtime-mode <scaffold|comet>`
  - `--dry-run`
- `testnet_local_status.sh`
  - `--testnet-dir <path>`
  - `--runtime-mode <scaffold|comet>`
  - `--dry-run`
- `testnet_local_stop.sh`
  - `--testnet-dir <path>`
  - `--runtime-mode <scaffold|comet>`
  - `--wait-seconds <n>`
  - `--dry-run`

## Notes
- `testnet_local_start.sh` launches one `tdpnd` per node with:
  - `--grpc-listen`
  - `--settlement-http-listen`
  - `--state-dir`
- In `scaffold` mode, `node.env` stays lean and omits comet-only settings.
- In `comet` mode, `testnet_local_start.sh` also passes `--comet-home`, `--comet-moniker`, `--comet-p2p-laddr`, and `--comet-rpc-laddr`, and it verifies those values match the deterministic per-node layout before launch.
- `testnet_local_stop.sh` sends `SIGTERM` first, then `SIGKILL` after timeout.
- `testnet_local_status.sh` reports running/stopped nodes and endpoint mapping, and it uses the same comet/scaffold validation rules as start/stop.
- The smoke script can be pointed at one mode or both modes by setting `LOCAL_TESTNET_SMOKE_RUNTIME_MODE=scaffold|comet|both` before running `scripts/integration_cosmos_local_testnet_smoke.sh`.
