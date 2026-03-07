#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in go curl rg timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

ENTRY_ADDR="127.0.0.1:18683"
ENTRY_DATA_ADDR="127.0.0.1:61983"
ISSUER_ADDR="127.0.0.1:18682"

CLIENT_FAIL_LOG="/tmp/integration_beta_strict_roles_client_fail.log"
CLIENT_MULTI_DIR_FAIL_LOG="/tmp/integration_beta_strict_roles_client_multi_dir_fail.log"
CLIENT_MULTI_DIR_OP_FAIL_LOG="/tmp/integration_beta_strict_roles_client_multi_dir_operator_fail.log"
ENTRY_FAIL_LOG="/tmp/integration_beta_strict_roles_entry_fail.log"
ENTRY_MULTI_DIR_FAIL_LOG="/tmp/integration_beta_strict_roles_entry_multi_dir_fail.log"
ENTRY_MULTI_DIR_OP_FAIL_LOG="/tmp/integration_beta_strict_roles_entry_multi_dir_operator_fail.log"
EXIT_FAIL_LOG="/tmp/integration_beta_strict_roles_exit_fail.log"
EXIT_REBIND_FAIL_LOG="/tmp/integration_beta_strict_roles_exit_rebind_fail.log"
EXIT_MULTI_ISSUER_FAIL_LOG="/tmp/integration_beta_strict_roles_exit_multi_issuer_fail.log"
EXIT_MULTI_ISSUER_OP_FAIL_LOG="/tmp/integration_beta_strict_roles_exit_multi_issuer_operator_fail.log"
EXIT_MULTI_ISSUER_ID_FAIL_LOG="/tmp/integration_beta_strict_roles_exit_multi_issuer_id_fail.log"
ISSUER_FAIL_LOG="/tmp/integration_beta_strict_roles_issuer_fail.log"
ISSUER_SHORT_TOKEN_FAIL_LOG="/tmp/integration_beta_strict_roles_issuer_short_token_fail.log"
ENTRY_OK_LOG="/tmp/integration_beta_strict_roles_entry_ok.log"
ISSUER_OK_LOG="/tmp/integration_beta_strict_roles_issuer_ok.log"
rm -f "$CLIENT_FAIL_LOG" "$CLIENT_MULTI_DIR_FAIL_LOG" "$CLIENT_MULTI_DIR_OP_FAIL_LOG" "$ENTRY_FAIL_LOG" "$ENTRY_MULTI_DIR_FAIL_LOG" "$ENTRY_MULTI_DIR_OP_FAIL_LOG" "$EXIT_FAIL_LOG" "$EXIT_REBIND_FAIL_LOG" "$EXIT_MULTI_ISSUER_FAIL_LOG" "$EXIT_MULTI_ISSUER_OP_FAIL_LOG" "$EXIT_MULTI_ISSUER_ID_FAIL_LOG" "$ISSUER_FAIL_LOG" "$ISSUER_SHORT_TOKEN_FAIL_LOG" "$ENTRY_OK_LOG" "$ISSUER_OK_LOG"

if CLIENT_BETA_STRICT=1 timeout 12s go run ./cmd/node --client >"$CLIENT_FAIL_LOG" 2>&1; then
  echo "expected strict client startup failure with default client config"
  cat "$CLIENT_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires DATA_PLANE_MODE=opaque" "$CLIENT_FAIL_LOG"; then
  echo "missing expected strict client validation signal"
  cat "$CLIENT_FAIL_LOG"
  exit 1
fi

if CLIENT_BETA_STRICT=1 \
  DIRECTORY_TRUST_STRICT=1 \
  DATA_PLANE_MODE=opaque \
  CLIENT_WG_BACKEND=command \
  CLIENT_WG_PRIVATE_KEY_PATH=/tmp/fake-client.key \
  CLIENT_WG_KERNEL_PROXY=1 \
  CLIENT_WG_PROXY_ADDR=127.0.0.1:0 \
  CLIENT_LIVE_WG_MODE=1 \
  CLIENT_INNER_SOURCE=udp \
  CLIENT_DISABLE_SYNTHETIC_FALLBACK=1 \
  CLIENT_STARTUP_SYNC_TIMEOUT_SEC=8 \
  CLIENT_REQUIRE_DISTINCT_OPERATORS=1 \
  DIRECTORY_URLS=http://127.0.0.1:8081,http://127.0.0.1:8085 \
  DIRECTORY_MIN_SOURCES=1 \
  CLIENT_DIRECTORY_MIN_OPERATORS=2 \
  timeout 12s go run ./cmd/node --client >"$CLIENT_MULTI_DIR_FAIL_LOG" 2>&1; then
  echo "expected strict client startup failure with weak multi-directory source quorum"
  cat "$CLIENT_MULTI_DIR_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires DIRECTORY_MIN_SOURCES>=2 when multiple DIRECTORY_URLS are configured" "$CLIENT_MULTI_DIR_FAIL_LOG"; then
  echo "missing expected strict client multi-directory quorum validation signal"
  cat "$CLIENT_MULTI_DIR_FAIL_LOG"
  exit 1
fi

if CLIENT_BETA_STRICT=1 \
  DIRECTORY_TRUST_STRICT=1 \
  DATA_PLANE_MODE=opaque \
  CLIENT_WG_BACKEND=command \
  CLIENT_WG_PRIVATE_KEY_PATH=/tmp/fake-client.key \
  CLIENT_WG_KERNEL_PROXY=1 \
  CLIENT_WG_PROXY_ADDR=127.0.0.1:0 \
  CLIENT_LIVE_WG_MODE=1 \
  CLIENT_INNER_SOURCE=udp \
  CLIENT_DISABLE_SYNTHETIC_FALLBACK=1 \
  CLIENT_STARTUP_SYNC_TIMEOUT_SEC=8 \
  CLIENT_REQUIRE_DISTINCT_OPERATORS=1 \
  DIRECTORY_URLS=http://127.0.0.1:8081,http://127.0.0.1:8085 \
  DIRECTORY_MIN_SOURCES=2 \
  CLIENT_DIRECTORY_MIN_OPERATORS=1 \
  timeout 12s go run ./cmd/node --client >"$CLIENT_MULTI_DIR_OP_FAIL_LOG" 2>&1; then
  echo "expected strict client startup failure with weak multi-directory operator quorum"
  cat "$CLIENT_MULTI_DIR_OP_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires CLIENT_DIRECTORY_MIN_OPERATORS>=2 when multiple DIRECTORY_URLS are configured" "$CLIENT_MULTI_DIR_OP_FAIL_LOG"; then
  echo "missing expected strict client multi-directory operator validation signal"
  cat "$CLIENT_MULTI_DIR_OP_FAIL_LOG"
  exit 1
fi

if ENTRY_BETA_STRICT=1 timeout 12s go run ./cmd/node --entry >"$ENTRY_FAIL_LOG" 2>&1; then
  echo "expected strict entry startup failure with default entry config"
  cat "$ENTRY_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires ENTRY_LIVE_WG_MODE=1" "$ENTRY_FAIL_LOG"; then
  echo "missing expected strict entry validation signal"
  cat "$ENTRY_FAIL_LOG"
  exit 1
fi

if ENTRY_BETA_STRICT=1 \
  ENTRY_LIVE_WG_MODE=1 \
  ENTRY_DIRECTORY_TRUST_STRICT=1 \
  ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1 \
  ENTRY_PUZZLE_SECRET=integration-entry-secret-0001 \
  ENTRY_OPERATOR_ID=op-entry \
  DIRECTORY_URLS=http://127.0.0.1:8081,http://127.0.0.1:8085 \
  ENTRY_DIRECTORY_MIN_SOURCES=1 \
  ENTRY_DIRECTORY_MIN_OPERATORS=2 \
  timeout 12s go run ./cmd/node --entry >"$ENTRY_MULTI_DIR_FAIL_LOG" 2>&1; then
  echo "expected strict entry startup failure with weak multi-directory source quorum"
  cat "$ENTRY_MULTI_DIR_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires ENTRY_DIRECTORY_MIN_SOURCES>=2 when multiple DIRECTORY_URLS are configured" "$ENTRY_MULTI_DIR_FAIL_LOG"; then
  echo "missing expected strict entry multi-directory quorum validation signal"
  cat "$ENTRY_MULTI_DIR_FAIL_LOG"
  exit 1
fi

if ENTRY_BETA_STRICT=1 \
  ENTRY_LIVE_WG_MODE=1 \
  ENTRY_DIRECTORY_TRUST_STRICT=1 \
  ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1 \
  ENTRY_PUZZLE_SECRET=integration-entry-secret-0001 \
  ENTRY_OPERATOR_ID=op-entry \
  DIRECTORY_URLS=http://127.0.0.1:8081,http://127.0.0.1:8085 \
  ENTRY_DIRECTORY_MIN_SOURCES=2 \
  ENTRY_DIRECTORY_MIN_OPERATORS=1 \
  timeout 12s go run ./cmd/node --entry >"$ENTRY_MULTI_DIR_OP_FAIL_LOG" 2>&1; then
  echo "expected strict entry startup failure with weak multi-directory operator quorum"
  cat "$ENTRY_MULTI_DIR_OP_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires ENTRY_DIRECTORY_MIN_OPERATORS>=2 when multiple DIRECTORY_URLS are configured" "$ENTRY_MULTI_DIR_OP_FAIL_LOG"; then
  echo "missing expected strict entry multi-directory operator validation signal"
  cat "$ENTRY_MULTI_DIR_OP_FAIL_LOG"
  exit 1
fi

if EXIT_BETA_STRICT=1 timeout 12s go run ./cmd/node --exit >"$EXIT_FAIL_LOG" 2>&1; then
  echo "expected strict exit startup failure with default exit config"
  cat "$EXIT_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires DATA_PLANE_MODE=opaque" "$EXIT_FAIL_LOG"; then
  echo "missing expected strict exit validation signal"
  cat "$EXIT_FAIL_LOG"
  exit 1
fi

if EXIT_BETA_STRICT=1 \
  DATA_PLANE_MODE=opaque \
  WG_BACKEND=command \
  EXIT_WG_KERNEL_PROXY=1 \
  EXIT_LIVE_WG_MODE=1 \
  EXIT_OPAQUE_ECHO=0 \
  EXIT_TOKEN_PROOF_REPLAY_GUARD=1 \
  EXIT_WG_PRIVATE_KEY_PATH=/tmp/fake-exit.key \
  EXIT_OPAQUE_SINK_ADDR=127.0.0.1:53011 \
  EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:53012 \
  EXIT_PEER_REBIND_SEC=5 \
  timeout 12s go run ./cmd/node --exit >"$EXIT_REBIND_FAIL_LOG" 2>&1; then
  echo "expected strict exit startup failure with peer rebind enabled"
  cat "$EXIT_REBIND_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires EXIT_PEER_REBIND_SEC=0" "$EXIT_REBIND_FAIL_LOG"; then
  echo "missing expected strict exit peer-rebind validation signal"
  cat "$EXIT_REBIND_FAIL_LOG"
  exit 1
fi

if EXIT_BETA_STRICT=1 \
  DATA_PLANE_MODE=opaque \
  WG_BACKEND=command \
  EXIT_WG_KERNEL_PROXY=1 \
  EXIT_LIVE_WG_MODE=1 \
  EXIT_OPAQUE_ECHO=0 \
  EXIT_TOKEN_PROOF_REPLAY_GUARD=1 \
  EXIT_WG_PRIVATE_KEY_PATH=/tmp/fake-exit.key \
  EXIT_OPAQUE_SINK_ADDR=127.0.0.1:53011 \
  EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:53012 \
  EXIT_PEER_REBIND_SEC=0 \
  EXIT_STARTUP_SYNC_TIMEOUT_SEC=8 \
  ISSUER_URLS=http://127.0.0.1:8082,http://127.0.0.1:8086 \
  EXIT_ISSUER_MIN_SOURCES=1 \
  EXIT_ISSUER_MIN_OPERATORS=2 \
  timeout 12s go run ./cmd/node --exit >"$EXIT_MULTI_ISSUER_FAIL_LOG" 2>&1; then
  echo "expected strict exit startup failure with weak multi-issuer source quorum"
  cat "$EXIT_MULTI_ISSUER_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires EXIT_ISSUER_MIN_SOURCES>=2 when multiple ISSUER_URLS are configured" "$EXIT_MULTI_ISSUER_FAIL_LOG"; then
  echo "missing expected strict exit multi-issuer source validation signal"
  cat "$EXIT_MULTI_ISSUER_FAIL_LOG"
  exit 1
fi

if EXIT_BETA_STRICT=1 \
  DATA_PLANE_MODE=opaque \
  WG_BACKEND=command \
  EXIT_WG_KERNEL_PROXY=1 \
  EXIT_LIVE_WG_MODE=1 \
  EXIT_OPAQUE_ECHO=0 \
  EXIT_TOKEN_PROOF_REPLAY_GUARD=1 \
  EXIT_WG_PRIVATE_KEY_PATH=/tmp/fake-exit.key \
  EXIT_OPAQUE_SINK_ADDR=127.0.0.1:53011 \
  EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:53012 \
  EXIT_PEER_REBIND_SEC=0 \
  EXIT_STARTUP_SYNC_TIMEOUT_SEC=8 \
  ISSUER_URLS=http://127.0.0.1:8082,http://127.0.0.1:8086 \
  EXIT_ISSUER_MIN_SOURCES=2 \
  EXIT_ISSUER_MIN_OPERATORS=1 \
  timeout 12s go run ./cmd/node --exit >"$EXIT_MULTI_ISSUER_OP_FAIL_LOG" 2>&1; then
  echo "expected strict exit startup failure with weak multi-issuer operator quorum"
  cat "$EXIT_MULTI_ISSUER_OP_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires EXIT_ISSUER_MIN_OPERATORS>=2 when multiple ISSUER_URLS are configured" "$EXIT_MULTI_ISSUER_OP_FAIL_LOG"; then
  echo "missing expected strict exit multi-issuer operator validation signal"
  cat "$EXIT_MULTI_ISSUER_OP_FAIL_LOG"
  exit 1
fi

if EXIT_BETA_STRICT=1 \
  DATA_PLANE_MODE=opaque \
  WG_BACKEND=command \
  EXIT_WG_KERNEL_PROXY=1 \
  EXIT_LIVE_WG_MODE=1 \
  EXIT_OPAQUE_ECHO=0 \
  EXIT_TOKEN_PROOF_REPLAY_GUARD=1 \
  EXIT_WG_PRIVATE_KEY_PATH=/tmp/fake-exit.key \
  EXIT_OPAQUE_SINK_ADDR=127.0.0.1:53011 \
  EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:53012 \
  EXIT_PEER_REBIND_SEC=0 \
  EXIT_STARTUP_SYNC_TIMEOUT_SEC=8 \
  ISSUER_URLS=http://127.0.0.1:8082,http://127.0.0.1:8086 \
  EXIT_ISSUER_MIN_SOURCES=2 \
  EXIT_ISSUER_MIN_OPERATORS=2 \
  EXIT_ISSUER_REQUIRE_ID=0 \
  timeout 12s go run ./cmd/node --exit >"$EXIT_MULTI_ISSUER_ID_FAIL_LOG" 2>&1; then
  echo "expected strict exit startup failure with issuer identity requirement disabled"
  cat "$EXIT_MULTI_ISSUER_ID_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires EXIT_ISSUER_REQUIRE_ID=1 when multiple ISSUER_URLS are configured" "$EXIT_MULTI_ISSUER_ID_FAIL_LOG"; then
  echo "missing expected strict exit issuer identity validation signal"
  cat "$EXIT_MULTI_ISSUER_ID_FAIL_LOG"
  exit 1
fi

if ISSUER_BETA_STRICT=1 timeout 12s go run ./cmd/node --issuer >"$ISSUER_FAIL_LOG" 2>&1; then
  echo "expected strict issuer startup failure with default issuer config"
  cat "$ISSUER_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires non-default ISSUER_ADMIN_TOKEN" "$ISSUER_FAIL_LOG"; then
  echo "missing expected strict issuer validation signal"
  cat "$ISSUER_FAIL_LOG"
  exit 1
fi

if ISSUER_BETA_STRICT=1 \
  ISSUER_ADMIN_TOKEN=short-token \
  ISSUER_KEY_ROTATE_SEC=60 \
  ISSUER_TOKEN_TTL_SEC=300 \
  ISSUER_ANON_CRED_EXPOSE_ID=0 \
  timeout 12s go run ./cmd/node --issuer >"$ISSUER_SHORT_TOKEN_FAIL_LOG" 2>&1; then
  echo "expected strict issuer startup failure with short admin token"
  cat "$ISSUER_SHORT_TOKEN_FAIL_LOG"
  exit 1
fi
if ! rg -q "BETA_STRICT_MODE requires ISSUER_ADMIN_TOKEN length>=16" "$ISSUER_SHORT_TOKEN_FAIL_LOG"; then
  echo "missing expected strict issuer token-length validation signal"
  cat "$ISSUER_SHORT_TOKEN_FAIL_LOG"
  exit 1
fi

entry_pid=""
issuer_pid=""
cleanup() {
  kill "${entry_pid:-}" >/dev/null 2>&1 || true
  kill "${issuer_pid:-}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ENTRY_ADDR="$ENTRY_ADDR" \
ENTRY_DATA_ADDR="$ENTRY_DATA_ADDR" \
ENTRY_BETA_STRICT=1 \
ENTRY_LIVE_WG_MODE=1 \
ENTRY_DIRECTORY_TRUST_STRICT=1 \
ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1 \
ENTRY_PUZZLE_SECRET="integration-entry-secret-0001" \
ENTRY_OPERATOR_ID="op-entry" \
timeout 30s go run ./cmd/node --entry >"$ENTRY_OK_LOG" 2>&1 &
entry_pid=$!

entry_ready=0
for _ in $(seq 1 120); do
  if curl -fsS "http://${ENTRY_ADDR}/v1/health" >/dev/null 2>&1; then
    entry_ready=1
    break
  fi
  if ! kill -0 "$entry_pid" >/dev/null 2>&1; then
    echo "strict entry exited unexpectedly"
    cat "$ENTRY_OK_LOG"
    exit 1
  fi
  sleep 0.2
done
if [[ "$entry_ready" -ne 1 ]]; then
  echo "strict entry did not become healthy"
  cat "$ENTRY_OK_LOG"
  exit 1
fi
if ! rg -q "entry route discovery: .*live_wg_mode=true .*distinct_exit_operator=true" "$ENTRY_OK_LOG"; then
  echo "missing expected strict entry startup log signals"
  cat "$ENTRY_OK_LOG"
  exit 1
fi
kill "$entry_pid" >/dev/null 2>&1 || true
entry_pid=""

ISSUER_ADDR="$ISSUER_ADDR" \
ISSUER_BETA_STRICT=1 \
ISSUER_ADMIN_TOKEN="integration-admin-token" \
ISSUER_KEY_ROTATE_SEC=60 \
ISSUER_TOKEN_TTL_SEC=300 \
ISSUER_ANON_CRED_EXPOSE_ID=0 \
timeout 30s go run ./cmd/node --issuer >"$ISSUER_OK_LOG" 2>&1 &
issuer_pid=$!

issuer_ready=0
for _ in $(seq 1 120); do
  if curl -fsS "http://${ISSUER_ADDR}/v1/health" >/dev/null 2>&1; then
    issuer_ready=1
    break
  fi
  if ! kill -0 "$issuer_pid" >/dev/null 2>&1; then
    echo "strict issuer exited unexpectedly"
    cat "$ISSUER_OK_LOG"
    exit 1
  fi
  sleep 0.2
done
if [[ "$issuer_ready" -ne 1 ]]; then
  echo "strict issuer did not become healthy"
  cat "$ISSUER_OK_LOG"
  exit 1
fi
if ! rg -q "issuer listening on ${ISSUER_ADDR}" "$ISSUER_OK_LOG"; then
  echo "missing expected strict issuer startup log signal"
  cat "$ISSUER_OK_LOG"
  exit 1
fi

echo "cross-role beta strict integration check ok"
