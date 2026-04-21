#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SERVICE_FILE="services/directory/service.go"
EXIT_SERVICE_FILE="services/exit/service.go"
DEPLOY_DOC="docs/deployment.md"
MVP_DOC="docs/mvp-status.md"
BACKLOG_DOC="docs/manual-validation-backlog.md"

require_file() {
  local file="$1"
  [[ -f "$file" ]] || {
    echo "replay shared-mode guardrail failed: missing file $file"
    exit 1
  }
}

require_marker() {
  local file="$1"
  local marker="$2"
  if ! grep -qF -- "$marker" "$file"; then
    echo "replay shared-mode guardrail failed: missing marker '$marker' in $file"
    exit 1
  fi
}

for file in "$SERVICE_FILE" "$EXIT_SERVICE_FILE" "$DEPLOY_DOC" "$MVP_DOC" "$BACKLOG_DOC"; do
  require_file "$file"
done

# Service wiring markers.
require_marker "$SERVICE_FILE" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE"
require_marker "$SERVICE_FILE" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_LOCK_TIMEOUT_SEC"
require_marker "$SERVICE_FILE" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_ADDR"
require_marker "$SERVICE_FILE" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_DIAL_TIMEOUT_SEC"
require_marker "$SERVICE_FILE" "markProviderTokenProofReplayShared("
require_marker "$SERVICE_FILE" "markProviderTokenProofReplayRedis("
require_marker "$SERVICE_FILE" "providerTokenProofReplayMode() string"
require_marker "$SERVICE_FILE" "provider token proof replay lock failed"
require_marker "$SERVICE_FILE" "shared file mode enabled path=%s lock_timeout_sec=%d"
require_marker "$SERVICE_FILE" "redis mode enabled addr=%s db=%d tls=%t prefix=%q dial_timeout_sec=%d ttl_sec=%d"

require_marker "$EXIT_SERVICE_FILE" "EXIT_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE"
require_marker "$EXIT_SERVICE_FILE" "EXIT_TOKEN_PROOF_REPLAY_LOCK_TIMEOUT_SEC"
require_marker "$EXIT_SERVICE_FILE" "EXIT_TOKEN_PROOF_REPLAY_REDIS_ADDR"
require_marker "$EXIT_SERVICE_FILE" "EXIT_TOKEN_PROOF_REPLAY_REDIS_DIAL_TIMEOUT_SEC"
require_marker "$EXIT_SERVICE_FILE" "checkAndRememberProofNonceShared("
require_marker "$EXIT_SERVICE_FILE" "checkAndRememberProofNonceRedis("
require_marker "$EXIT_SERVICE_FILE" "tokenProofReplayMode() string"
require_marker "$EXIT_SERVICE_FILE" "token proof replay lock failed"
require_marker "$EXIT_SERVICE_FILE" "using shared file-backed store path=%s lock_timeout_sec=%d"
require_marker "$EXIT_SERVICE_FILE" "instance-local persistence only; use shared durable replay storage for multi-instance deployments"
require_marker "$EXIT_SERVICE_FILE" "using redis addr=%s db=%d tls=%t prefix=%s dial_timeout_sec=%d"

# Docs must describe knobs + residual risk posture.
require_marker "$DEPLOY_DOC" "EXIT_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE=1"
require_marker "$DEPLOY_DOC" "EXIT_TOKEN_PROOF_REPLAY_LOCK_TIMEOUT_SEC"
require_marker "$DEPLOY_DOC" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE=1"
require_marker "$DEPLOY_DOC" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_LOCK_TIMEOUT_SEC"
require_marker "$DEPLOY_DOC" "EXIT_TOKEN_PROOF_REPLAY_REDIS_ADDR"
require_marker "$DEPLOY_DOC" "EXIT_TOKEN_PROOF_REPLAY_REDIS_DIAL_TIMEOUT_SEC"
require_marker "$DEPLOY_DOC" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_ADDR"
require_marker "$DEPLOY_DOC" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_DIAL_TIMEOUT_SEC"
require_marker "$DEPLOY_DOC" "Mode precedence and intent:"
require_marker "$DEPLOY_DOC" "Use Redis mode for distributed deployments"

require_marker "$MVP_DOC" "EXIT_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE=1"
require_marker "$MVP_DOC" "EXIT_TOKEN_PROOF_REPLAY_LOCK_TIMEOUT_SEC"
require_marker "$MVP_DOC" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE=1"
require_marker "$MVP_DOC" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_LOCK_TIMEOUT_SEC"
require_marker "$MVP_DOC" "EXIT_TOKEN_PROOF_REPLAY_REDIS_ADDR"
require_marker "$MVP_DOC" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_ADDR"
require_marker "$MVP_DOC" "EXIT_TOKEN_PROOF_REPLAY_REDIS_DIAL_TIMEOUT_SEC"
require_marker "$MVP_DOC" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_DIAL_TIMEOUT_SEC"
require_marker "$MVP_DOC" "mode precedence is"

require_marker "$BACKLOG_DOC" "shared-file mode"
require_marker "$BACKLOG_DOC" "Redis distributed mode is now supported"
require_marker "$BACKLOG_DOC" "default 5s"
require_marker "$BACKLOG_DOC" "EXIT_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE=1"
require_marker "$BACKLOG_DOC" "EXIT_TOKEN_PROOF_REPLAY_LOCK_TIMEOUT_SEC"
require_marker "$BACKLOG_DOC" "EXIT_TOKEN_PROOF_REPLAY_REDIS_ADDR"
require_marker "$BACKLOG_DOC" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_ADDR"
require_marker "$BACKLOG_DOC" "Mode precedence is"

echo "replay shared-mode guardrails passed"
