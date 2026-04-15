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

## Scripts
- `scripts/testnet_local_init.sh`
- `scripts/testnet_local_start.sh`
- `scripts/testnet_local_status.sh`
- `scripts/testnet_local_stop.sh`

All scripts use shell safety defaults (`set -euo pipefail`) and support `--help`.

## Quick start
From `blockchain/tdpn-chain`:

```bash
scripts/testnet_local_init.sh --node-count 3
scripts/testnet_local_start.sh
scripts/testnet_local_status.sh
scripts/testnet_local_stop.sh
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
  - `--node-count <n>`
  - `--base-grpc-port <port>`
  - `--base-settlement-port <port>`
  - `--host <addr>`
  - `--dry-run`
- `testnet_local_start.sh`
  - `--testnet-dir <path>`
  - `--dry-run`
- `testnet_local_status.sh`
  - `--testnet-dir <path>`
  - `--dry-run`
- `testnet_local_stop.sh`
  - `--testnet-dir <path>`
  - `--wait-seconds <n>`
  - `--dry-run`

## Notes
- `testnet_local_start.sh` launches one `tdpnd` per node with:
  - `--grpc-listen`
  - `--settlement-http-listen`
  - `--state-dir`
- `testnet_local_stop.sh` sends `SIGTERM` first, then `SIGKILL` after timeout.
- `testnet_local_status.sh` reports running/stopped nodes and endpoint mapping.
