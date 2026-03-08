#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash rg awk sed; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
case "$url" in
  *"/v1/relays")
    printf '{"relays":[{"relay_id":"entry-op-a","role":"entry","operator_id":"op-a"},{"relay_id":"exit-op-a","role":"exit","operator_id":"op-a"},{"relay_id":"entry-op-b","role":"entry","operator_id":"op-b"},{"relay_id":"exit-op-b","role":"exit","operator_id":"op-b"}]}\n'
    ;;
  *"issuer-a"*"/v1/pubkeys")
    printf '{"issuer":"issuer-a","pub_keys":["issuer-a-key"]}\n'
    ;;
  *"issuer-b"*"/v1/pubkeys")
    printf '{"issuer":"issuer-b","pub_keys":["issuer-b-key"]}\n'
    ;;
  *"/v1/pubkeys")
    printf '{"issuer":"issuer-main","pub_keys":["issuer-main-key"]}\n'
    ;;
  *"/v1/health"|*"/v1/peers"|*"/v1/metrics")
    printf '{}\n'
    ;;
  *)
    printf '{}\n'
    ;;
esac
EOF_CURL

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  printf 'Docker Compose version vtest\n'
  exit 0
fi
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  printf 'Docker Compose version vtest\n'
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  exit 0
fi
if [[ "${1:-}" == "image" && "${2:-}" == "inspect" ]]; then
  exit 0
fi
if [[ "${1:-}" == "info" ]]; then
  exit 0
fi
exit 0
EOF_DOCKER

cat >"$TMP_BIN/timeout" <<'EOF_TIMEOUT'
#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 2 ]]; then
  exit 2
fi
# Ignore timeout wrappers in wiring tests and run wrapped command directly.
shift
exec "$@"
EOF_TIMEOUT

chmod +x "$TMP_BIN/curl" "$TMP_BIN/docker" "$TMP_BIN/timeout"

FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
VALIDATE_CAPTURE="$TMP_DIR/validate_easy_node_args.log"
cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${VALIDATE_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_EASY
chmod +x "$FAKE_EASY_NODE"

echo "[wiring] validate -> easy_node prod-profile forwarding"
PATH="$TMP_BIN:$PATH" \
VALIDATE_CAPTURE_FILE="$VALIDATE_CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://dir-a:8081 \
  --directory-b http://dir-b:8081 \
  --issuer-url http://issuer-main:8082 \
  --issuer-a-url http://issuer-a:8082 \
  --issuer-b-url http://issuer-b:8082 \
  --entry-url http://entry-main:8083 \
  --exit-url http://exit-main:8084 \
  --min-sources 1 \
  --min-operators 2 \
  --federation-timeout-sec 3 \
  --timeout-sec 5 \
  --client-min-selection-lines 1 \
  --client-min-entry-operators 1 \
  --client-min-exit-operators 1 \
  --client-require-cross-operator-pair 0 \
  --distinct-operators 1 \
  --require-issuer-quorum 1 \
  --beta-profile 0 \
  --prod-profile 1 >/tmp/integration_3machine_prod_profile_wiring_validate.log 2>&1

if ! rg -q -- 'client-test' "$VALIDATE_CAPTURE"; then
  echo "validate wiring failed: client-test command was not invoked"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--prod-profile 1' "$VALIDATE_CAPTURE"; then
  echo "validate wiring failed: --prod-profile 1 was not forwarded to easy_node client-test"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi

FAKE_VALIDATE="$TMP_DIR/fake_validate.sh"
SOAK_CAPTURE="$TMP_DIR/soak_validate_args.log"
cat >"$FAKE_VALIDATE" <<'EOF_FAKE_VALIDATE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SOAK_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_VALIDATE
chmod +x "$FAKE_VALIDATE"

echo "[wiring] soak -> validate prod-profile forwarding"
PATH="$TMP_BIN:$PATH" \
SOAK_CAPTURE_FILE="$SOAK_CAPTURE" \
THREE_MACHINE_VALIDATE_SCRIPT="$FAKE_VALIDATE" \
./scripts/integration_3machine_beta_soak.sh \
  --directory-a http://dir-a:8081 \
  --directory-b http://dir-b:8081 \
  --issuer-url http://issuer-main:8082 \
  --entry-url http://entry-main:8083 \
  --exit-url http://exit-main:8084 \
  --rounds 1 \
  --pause-sec 0 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 1 \
  --timeout-sec 5 \
  --client-min-selection-lines 1 \
  --client-min-entry-operators 1 \
  --client-min-exit-operators 1 \
  --client-require-cross-operator-pair 0 \
  --distinct-operators 1 \
  --require-issuer-quorum 1 \
  --beta-profile 0 \
  --prod-profile 1 >/tmp/integration_3machine_prod_profile_wiring_soak.log 2>&1

if ! rg -q -- '--prod-profile 1' "$SOAK_CAPTURE"; then
  echo "soak wiring failed: --prod-profile 1 was not forwarded to validate script"
  cat "$SOAK_CAPTURE"
  exit 1
fi

FAKE_RUNBOOK_VALIDATE="$TMP_DIR/fake_runbook_validate.sh"
FAKE_RUNBOOK_SOAK="$TMP_DIR/fake_runbook_soak.sh"
RUNBOOK_VALIDATE_CAPTURE="$TMP_DIR/runbook_validate_args.log"
RUNBOOK_SOAK_CAPTURE="$TMP_DIR/runbook_soak_args.log"

cat >"$FAKE_RUNBOOK_VALIDATE" <<'EOF_FAKE_R_VALIDATE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${RUNBOOK_VALIDATE_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_R_VALIDATE

cat >"$FAKE_RUNBOOK_SOAK" <<'EOF_FAKE_R_SOAK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${RUNBOOK_SOAK_CAPTURE_FILE:?}"
report=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-file)
      report="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$report" ]]; then
  printf '[fake-soak] ok\n' >>"$report"
fi
exit 0
EOF_FAKE_R_SOAK

chmod +x "$FAKE_RUNBOOK_VALIDATE" "$FAKE_RUNBOOK_SOAK"

RUNBOOK_BUNDLE="$TMP_DIR/pilot_bundle"
echo "[wiring] runbook -> validate/soak prod-profile forwarding"
PATH="$TMP_BIN:$PATH" \
RUNBOOK_VALIDATE_CAPTURE_FILE="$RUNBOOK_VALIDATE_CAPTURE" \
RUNBOOK_SOAK_CAPTURE_FILE="$RUNBOOK_SOAK_CAPTURE" \
THREE_MACHINE_VALIDATE_SCRIPT="$FAKE_RUNBOOK_VALIDATE" \
THREE_MACHINE_SOAK_SCRIPT="$FAKE_RUNBOOK_SOAK" \
./scripts/beta_pilot_runbook.sh \
  --directory-a http://dir-a:8081 \
  --directory-b http://dir-b:8081 \
  --issuer-url http://issuer-main:8082 \
  --issuer-a-url http://issuer-a:8082 \
  --issuer-b-url http://issuer-b:8082 \
  --entry-url http://entry-main:8083 \
  --exit-url http://exit-main:8084 \
  --rounds 1 \
  --pause-sec 0 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 1 \
  --timeout-sec 5 \
  --client-min-selection-lines 1 \
  --client-min-entry-operators 1 \
  --client-min-exit-operators 1 \
  --client-require-cross-operator-pair 0 \
  --distinct-operators 1 \
  --require-issuer-quorum 1 \
  --beta-profile 0 \
  --prod-profile 1 \
  --bundle-dir "$RUNBOOK_BUNDLE" >/tmp/integration_3machine_prod_profile_wiring_runbook.log 2>&1

if ! rg -q -- '--prod-profile 1' "$RUNBOOK_VALIDATE_CAPTURE"; then
  echo "runbook wiring failed: --prod-profile 1 missing from validate invocation"
  cat "$RUNBOOK_VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--prod-profile 1' "$RUNBOOK_SOAK_CAPTURE"; then
  echo "runbook wiring failed: --prod-profile 1 missing from soak invocation"
  cat "$RUNBOOK_SOAK_CAPTURE"
  exit 1
fi

echo "3-machine prod-profile wiring integration check ok"

