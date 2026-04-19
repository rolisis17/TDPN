#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

timeout 20s go test ./services/issuer -count=1 -run '^(TestHandleSubmitSlashEvidenceRequiresAdmin|TestHandleSubmitSlashEvidenceAcceptsObjectiveEvidence|TestHandleSubmitSlashEvidenceRejectsNonObjectiveViolation)$'

echo "issuer slash evidence integration check ok"
