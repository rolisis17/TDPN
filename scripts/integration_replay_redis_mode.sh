#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v go >/dev/null 2>&1; then
  echo "missing required command: go"
  exit 2
fi

echo "[replay-redis-mode] exit replay redis tests"
go test ./services/exit -count=1 -run 'Test(NewReadsTokenProofReplayRedisConfig|CheckAndRememberProofNonceRedisModeRejectsCrossInstanceReplay|CheckAndRememberProofNonceRedisModeFailureFailsClosed)$'

echo "[replay-redis-mode] directory provider replay redis tests"
go test ./services/directory -count=1 -run 'Test(NewReadsProviderTokenProofReplayRedisConfig|ProviderTokenProofReplayRedisModeRejectsAcrossInstances|ProviderTokenProofReplayRedisModeFailureFailsClosed)$'

echo "[replay-redis-mode] passed"
