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
  --distinct-countries 1 \
  --locality-soft-bias 0 \
  --country-bias 1.80 \
  --region-bias 1.30 \
  --region-prefix-bias 1.10 \
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
if ! rg -q -- '--distinct-countries 1' "$VALIDATE_CAPTURE"; then
  echo "validate wiring failed: --distinct-countries 1 was not forwarded to easy_node client-test"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--locality-soft-bias 0' "$VALIDATE_CAPTURE"; then
  echo "validate wiring failed: --locality-soft-bias 0 was not forwarded to easy_node client-test"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--country-bias 1.80' "$VALIDATE_CAPTURE"; then
  echo "validate wiring failed: --country-bias 1.80 was not forwarded to easy_node client-test"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--region-bias 1.30' "$VALIDATE_CAPTURE"; then
  echo "validate wiring failed: --region-bias 1.30 was not forwarded to easy_node client-test"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--region-prefix-bias 1.10' "$VALIDATE_CAPTURE"; then
  echo "validate wiring failed: --region-prefix-bias 1.10 was not forwarded to easy_node client-test"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi

VALIDATE_PATH_PROFILE_CAPTURE="$TMP_DIR/validate_easy_node_path_profile_args.log"
echo "[wiring] validate -> easy_node path-profile mapping"
PATH="$TMP_BIN:$PATH" \
VALIDATE_CAPTURE_FILE="$VALIDATE_PATH_PROFILE_CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://dir-a:8081 \
  --directory-b http://dir-b:8081 \
  --issuer-url http://issuer-main:8082 \
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
  --path-profile private \
  --beta-profile 0 \
  --prod-profile 0 >/tmp/integration_3machine_prod_profile_wiring_validate_path_profile.log 2>&1

if ! rg -q -- '--distinct-operators 1' "$VALIDATE_PATH_PROFILE_CAPTURE"; then
  echo "validate path-profile wiring failed: expected --distinct-operators 1 from private profile"
  cat "$VALIDATE_PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--distinct-countries 1' "$VALIDATE_PATH_PROFILE_CAPTURE"; then
  echo "validate path-profile wiring failed: expected --distinct-countries 1 from private profile"
  cat "$VALIDATE_PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--locality-soft-bias 0' "$VALIDATE_PATH_PROFILE_CAPTURE"; then
  echo "validate path-profile wiring failed: expected --locality-soft-bias 0 from private profile"
  cat "$VALIDATE_PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--country-bias 1.60' "$VALIDATE_PATH_PROFILE_CAPTURE"; then
  echo "validate path-profile wiring failed: expected --country-bias 1.60 from private profile"
  cat "$VALIDATE_PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--region-bias 1.25' "$VALIDATE_PATH_PROFILE_CAPTURE"; then
  echo "validate path-profile wiring failed: expected --region-bias 1.25 from private profile"
  cat "$VALIDATE_PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--region-prefix-bias 1.10' "$VALIDATE_PATH_PROFILE_CAPTURE"; then
  echo "validate path-profile wiring failed: expected --region-prefix-bias 1.10 from private profile"
  cat "$VALIDATE_PATH_PROFILE_CAPTURE"
  exit 1
fi

VALIDATE_DEFAULT_PROFILE_CAPTURE="$TMP_DIR/validate_easy_node_default_profile_args.log"
echo "[wiring] validate default balanced profile mapping"
PATH="$TMP_BIN:$PATH" \
VALIDATE_CAPTURE_FILE="$VALIDATE_DEFAULT_PROFILE_CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://dir-a:8081 \
  --directory-b http://dir-b:8081 \
  --issuer-url http://issuer-main:8082 \
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
  --require-issuer-quorum 0 \
  --beta-profile 1 \
  --prod-profile 0 >/tmp/integration_3machine_prod_profile_wiring_validate_default_profile.log 2>&1

if ! rg -q -- '--distinct-operators 1' "$VALIDATE_DEFAULT_PROFILE_CAPTURE"; then
  echo "validate default profile wiring failed: expected balanced distinct-operators 1"
  cat "$VALIDATE_DEFAULT_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--locality-soft-bias 1' "$VALIDATE_DEFAULT_PROFILE_CAPTURE"; then
  echo "validate default profile wiring failed: expected balanced locality-soft-bias 1"
  cat "$VALIDATE_DEFAULT_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--country-bias 1.50' "$VALIDATE_DEFAULT_PROFILE_CAPTURE"; then
  echo "validate default profile wiring failed: expected balanced country-bias 1.50"
  cat "$VALIDATE_DEFAULT_PROFILE_CAPTURE"
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
  --distinct-countries 1 \
  --locality-soft-bias 0 \
  --country-bias 1.80 \
  --region-bias 1.30 \
  --region-prefix-bias 1.10 \
  --require-issuer-quorum 1 \
  --beta-profile 0 \
  --prod-profile 1 >/tmp/integration_3machine_prod_profile_wiring_soak.log 2>&1

if ! rg -q -- '--prod-profile 1' "$SOAK_CAPTURE"; then
  echo "soak wiring failed: --prod-profile 1 was not forwarded to validate script"
  cat "$SOAK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--distinct-countries 1' "$SOAK_CAPTURE"; then
  echo "soak wiring failed: --distinct-countries 1 was not forwarded to validate script"
  cat "$SOAK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--locality-soft-bias 0' "$SOAK_CAPTURE"; then
  echo "soak wiring failed: --locality-soft-bias 0 was not forwarded to validate script"
  cat "$SOAK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--country-bias 1.80' "$SOAK_CAPTURE"; then
  echo "soak wiring failed: --country-bias 1.80 was not forwarded to validate script"
  cat "$SOAK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--region-bias 1.30' "$SOAK_CAPTURE"; then
  echo "soak wiring failed: --region-bias 1.30 was not forwarded to validate script"
  cat "$SOAK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--region-prefix-bias 1.10' "$SOAK_CAPTURE"; then
  echo "soak wiring failed: --region-prefix-bias 1.10 was not forwarded to validate script"
  cat "$SOAK_CAPTURE"
  exit 1
fi

SOAK_PATH_PROFILE_CAPTURE="$TMP_DIR/soak_validate_path_profile_args.log"
echo "[wiring] soak -> validate path-profile mapping"
PATH="$TMP_BIN:$PATH" \
SOAK_CAPTURE_FILE="$SOAK_PATH_PROFILE_CAPTURE" \
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
  --path-profile speed \
  --beta-profile 0 \
  --prod-profile 0 >/tmp/integration_3machine_prod_profile_wiring_soak_path_profile.log 2>&1

if ! rg -q -- '--distinct-operators 1' "$SOAK_PATH_PROFILE_CAPTURE"; then
  echo "soak path-profile wiring failed: expected --distinct-operators 1 from speed profile"
  cat "$SOAK_PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--distinct-countries 0' "$SOAK_PATH_PROFILE_CAPTURE"; then
  echo "soak path-profile wiring failed: expected --distinct-countries 0 from speed profile"
  cat "$SOAK_PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--locality-soft-bias 1' "$SOAK_PATH_PROFILE_CAPTURE"; then
  echo "soak path-profile wiring failed: expected --locality-soft-bias 1 from speed profile"
  cat "$SOAK_PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--country-bias 1.80' "$SOAK_PATH_PROFILE_CAPTURE"; then
  echo "soak path-profile wiring failed: expected --country-bias 1.80 from speed profile"
  cat "$SOAK_PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--region-bias 1.35' "$SOAK_PATH_PROFILE_CAPTURE"; then
  echo "soak path-profile wiring failed: expected --region-bias 1.35 from speed profile"
  cat "$SOAK_PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--region-prefix-bias 1.15' "$SOAK_PATH_PROFILE_CAPTURE"; then
  echo "soak path-profile wiring failed: expected --region-prefix-bias 1.15 from speed profile"
  cat "$SOAK_PATH_PROFILE_CAPTURE"
  exit 1
fi

SOAK_DEFAULT_PROFILE_CAPTURE="$TMP_DIR/soak_validate_default_profile_args.log"
echo "[wiring] soak default balanced profile mapping"
PATH="$TMP_BIN:$PATH" \
SOAK_CAPTURE_FILE="$SOAK_DEFAULT_PROFILE_CAPTURE" \
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
  --require-issuer-quorum 0 \
  --beta-profile 1 \
  --prod-profile 0 >/tmp/integration_3machine_prod_profile_wiring_soak_default_profile.log 2>&1

if ! rg -q -- '--distinct-operators 1' "$SOAK_DEFAULT_PROFILE_CAPTURE"; then
  echo "soak default profile wiring failed: expected balanced distinct-operators 1"
  cat "$SOAK_DEFAULT_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--locality-soft-bias 1' "$SOAK_DEFAULT_PROFILE_CAPTURE"; then
  echo "soak default profile wiring failed: expected balanced locality-soft-bias 1"
  cat "$SOAK_DEFAULT_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--country-bias 1.50' "$SOAK_DEFAULT_PROFILE_CAPTURE"; then
  echo "soak default profile wiring failed: expected balanced country-bias 1.50"
  cat "$SOAK_DEFAULT_PROFILE_CAPTURE"
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
  --distinct-countries 1 \
  --locality-soft-bias 0 \
  --country-bias 1.80 \
  --region-bias 1.30 \
  --region-prefix-bias 1.10 \
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
if ! rg -q -- '--distinct-countries 1' "$RUNBOOK_VALIDATE_CAPTURE"; then
  echo "runbook wiring failed: --distinct-countries 1 missing from validate invocation"
  cat "$RUNBOOK_VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--locality-soft-bias 0' "$RUNBOOK_SOAK_CAPTURE"; then
  echo "runbook wiring failed: --locality-soft-bias 0 missing from soak invocation"
  cat "$RUNBOOK_SOAK_CAPTURE"
  exit 1
fi

RUNBOOK_VALIDATE_PATH_PROFILE_CAPTURE="$TMP_DIR/runbook_validate_path_profile_args.log"
RUNBOOK_SOAK_PATH_PROFILE_CAPTURE="$TMP_DIR/runbook_soak_path_profile_args.log"
RUNBOOK_PATH_PROFILE_BUNDLE="$TMP_DIR/pilot_bundle_path_profile"
echo "[wiring] runbook -> validate/soak path-profile mapping"
PATH="$TMP_BIN:$PATH" \
RUNBOOK_VALIDATE_CAPTURE_FILE="$RUNBOOK_VALIDATE_PATH_PROFILE_CAPTURE" \
RUNBOOK_SOAK_CAPTURE_FILE="$RUNBOOK_SOAK_PATH_PROFILE_CAPTURE" \
THREE_MACHINE_VALIDATE_SCRIPT="$FAKE_RUNBOOK_VALIDATE" \
THREE_MACHINE_SOAK_SCRIPT="$FAKE_RUNBOOK_SOAK" \
./scripts/beta_pilot_runbook.sh \
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
  --path-profile private \
  --beta-profile 0 \
  --prod-profile 0 \
  --bundle-dir "$RUNBOOK_PATH_PROFILE_BUNDLE" >/tmp/integration_3machine_prod_profile_wiring_runbook_path_profile.log 2>&1

if ! rg -q -- '--distinct-countries 1' "$RUNBOOK_VALIDATE_PATH_PROFILE_CAPTURE"; then
  echo "runbook path-profile wiring failed: expected --distinct-countries 1 on validate command"
  cat "$RUNBOOK_VALIDATE_PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--locality-soft-bias 0' "$RUNBOOK_SOAK_PATH_PROFILE_CAPTURE"; then
  echo "runbook path-profile wiring failed: expected --locality-soft-bias 0 on soak command"
  cat "$RUNBOOK_SOAK_PATH_PROFILE_CAPTURE"
  exit 1
fi

RUNBOOK_VALIDATE_DEFAULT_PROFILE_CAPTURE="$TMP_DIR/runbook_validate_default_profile_args.log"
RUNBOOK_SOAK_DEFAULT_PROFILE_CAPTURE="$TMP_DIR/runbook_soak_default_profile_args.log"
RUNBOOK_DEFAULT_PROFILE_BUNDLE="$TMP_DIR/pilot_bundle_default_profile"
echo "[wiring] runbook default balanced profile mapping"
PATH="$TMP_BIN:$PATH" \
RUNBOOK_VALIDATE_CAPTURE_FILE="$RUNBOOK_VALIDATE_DEFAULT_PROFILE_CAPTURE" \
RUNBOOK_SOAK_CAPTURE_FILE="$RUNBOOK_SOAK_DEFAULT_PROFILE_CAPTURE" \
THREE_MACHINE_VALIDATE_SCRIPT="$FAKE_RUNBOOK_VALIDATE" \
THREE_MACHINE_SOAK_SCRIPT="$FAKE_RUNBOOK_SOAK" \
./scripts/beta_pilot_runbook.sh \
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
  --bundle-dir "$RUNBOOK_DEFAULT_PROFILE_BUNDLE" >/tmp/integration_3machine_prod_profile_wiring_runbook_default_profile.log 2>&1

if ! rg -q -- '--distinct-operators 1' "$RUNBOOK_VALIDATE_DEFAULT_PROFILE_CAPTURE"; then
  echo "runbook default profile wiring failed: expected balanced distinct-operators 1 on validate command"
  cat "$RUNBOOK_VALIDATE_DEFAULT_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--locality-soft-bias 1' "$RUNBOOK_SOAK_DEFAULT_PROFILE_CAPTURE"; then
  echo "runbook default profile wiring failed: expected balanced locality-soft-bias 1 on soak command"
  cat "$RUNBOOK_SOAK_DEFAULT_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--country-bias 1.50' "$RUNBOOK_VALIDATE_DEFAULT_PROFILE_CAPTURE"; then
  echo "runbook default profile wiring failed: expected balanced country-bias 1.50 on validate command"
  cat "$RUNBOOK_VALIDATE_DEFAULT_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--country-bias 1.60' "$RUNBOOK_SOAK_PATH_PROFILE_CAPTURE"; then
  echo "runbook path-profile wiring failed: expected --country-bias 1.60 on soak command"
  cat "$RUNBOOK_SOAK_PATH_PROFILE_CAPTURE"
  exit 1
fi

FAKE_GATE="$TMP_DIR/fake_prod_gate.sh"
GATE_CAPTURE="$TMP_DIR/prod_gate_args.log"
cat >"$FAKE_GATE" <<'EOF_FAKE_GATE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${GATE_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_GATE
chmod +x "$FAKE_GATE"

echo "[wiring] easy_node -> prod gate forwarding"
PATH="$TMP_BIN:$PATH" \
GATE_CAPTURE_FILE="$GATE_CAPTURE" \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_GATE" \
./scripts/easy_node.sh three-machine-prod-gate \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --wg-slo-profile strict \
  --control-fault-every 2 \
  --control-fault-command test-control-fault \
  --control-continue-on-fail 1 \
  --wg-fault-every 3 \
  --wg-fault-command test-wg-fault \
  --wg-continue-on-fail 1 \
  --wg-max-round-duration-sec 90 \
  --wg-max-recovery-sec 120 \
  --wg-max-failure-class endpoint_connectivity=2 \
  --wg-disallow-unknown-failure-class 1 \
  --wg-strict-ingress-rehearsal 1 \
  --wg-min-selection-lines 12 \
  --wg-min-entry-operators 2 \
  --wg-min-exit-operators 2 \
  --wg-min-cross-operator-pairs 3 \
  --strict-distinct 1 \
  --wg-max-consecutive-failures 3 \
  --wg-validate-summary-json /tmp/prod_gate_wg_validate_summary.json \
  --wg-soak-summary-json /tmp/prod_gate_wg_soak_summary.json \
  --gate-summary-json /tmp/prod_gate_summary.json \
  --control-soak-rounds 2 \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_gate.log 2>&1

if ! rg -q -- '--strict-distinct 1' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --strict-distinct 1 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--skip-wg 1' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --skip-wg 1 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-max-consecutive-failures 3' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-max-consecutive-failures 3 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-soak-summary-json /tmp/prod_gate_wg_soak_summary.json' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-soak-summary-json missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-validate-summary-json /tmp/prod_gate_wg_validate_summary.json' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-validate-summary-json missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--control-fault-every 2' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --control-fault-every 2 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--control-fault-command test-control-fault' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --control-fault-command missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-fault-every 3' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-fault-every 3 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-fault-command test-wg-fault' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-fault-command missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-slo-profile strict' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-slo-profile strict missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-max-round-duration-sec 90' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-max-round-duration-sec 90 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-max-recovery-sec 120' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-max-recovery-sec 120 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-max-failure-class endpoint_connectivity=2' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-max-failure-class endpoint_connectivity=2 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-disallow-unknown-failure-class 1' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-disallow-unknown-failure-class 1 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-strict-ingress-rehearsal 1' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-strict-ingress-rehearsal 1 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-min-selection-lines 12' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-min-selection-lines 12 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-min-entry-operators 2' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-min-entry-operators 2 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-min-exit-operators 2' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-min-exit-operators 2 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-min-cross-operator-pairs 3' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-min-cross-operator-pairs 3 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--gate-summary-json /tmp/prod_gate_summary.json' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --gate-summary-json missing"
  cat "$GATE_CAPTURE"
  exit 1
fi

echo "[wiring] easy_node reminder command output"
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-reminder | rg -q 'True 3-machine production reminder checklist'; then
  echo "easy_node reminder command missing expected checklist heading"
  exit 1
fi

echo "[wiring] easy_node client-vpn-preflight help dispatch"
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh client-vpn-preflight --help | rg -q 'client-vpn-preflight'; then
  echo "easy_node client-vpn-preflight command help dispatch failed"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh client-vpn-preflight --help | rg -q -- '--operator-floor-check'; then
  echo "easy_node client-vpn-preflight help missing --operator-floor-check"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh client-vpn-preflight --help | rg -q -- '--issuer-quorum-check'; then
  echo "easy_node client-vpn-preflight help missing --issuer-quorum-check"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-wg-soak --help | rg -q -- '--max-consecutive-failures'; then
  echo "easy_node prod-wg-soak help missing --max-consecutive-failures"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-wg-soak --help | rg -q -- '--summary-json'; then
  echo "easy_node prod-wg-soak help missing --summary-json"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-wg-validate --help | rg -q -- '--client-inner-source'; then
  echo "easy_node prod-wg-validate help missing --client-inner-source"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-wg-soak --help | rg -q -- '--strict-ingress-rehearsal'; then
  echo "easy_node prod-wg-soak help missing --strict-ingress-rehearsal"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-prod-gate --help | rg -q -- '--wg-max-round-duration-sec'; then
  echo "easy_node three-machine-prod-gate help missing --wg-max-round-duration-sec"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-prod-gate --help | rg -q -- '--wg-max-failure-class'; then
  echo "easy_node three-machine-prod-gate help missing --wg-max-failure-class"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-prod-gate --help | rg -q -- '--wg-strict-ingress-rehearsal'; then
  echo "easy_node three-machine-prod-gate help missing --wg-strict-ingress-rehearsal"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-prod-gate --help | rg -q -- '--wg-slo-profile'; then
  echo "easy_node three-machine-prod-gate help missing --wg-slo-profile"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-prod-gate --help | rg -q -- '--wg-validate-summary-json'; then
  echo "easy_node three-machine-prod-gate help missing --wg-validate-summary-json"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-prod-gate --help | rg -q -- '--wg-min-selection-lines'; then
  echo "easy_node three-machine-prod-gate help missing --wg-min-selection-lines"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- '--signoff-check'; then
  echo "easy_node usage missing prod bundle signoff options"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- '--preflight-check'; then
  echo "easy_node usage missing prod bundle preflight options"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- '--bundle-verify-check'; then
  echo "easy_node usage missing prod bundle verify options"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- '--run-report-json'; then
  echo "easy_node usage missing prod bundle run-report options"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- '--incident-snapshot-on-fail'; then
  echo "easy_node usage missing prod bundle incident snapshot options"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- 'prod-gate-bundle-verify'; then
  echo "easy_node usage missing prod-gate-bundle-verify command"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-bundle-verify --help | rg -q -- '--bundle-tar'; then
  echo "easy_node prod-gate-bundle-verify help missing --bundle-tar"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-bundle-verify --help | rg -q -- '--run-report-json'; then
  echo "easy_node prod-gate-bundle-verify help missing --run-report-json"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-check --help | rg -q -- '--run-report-json'; then
  echo "easy_node prod-gate-check help missing --run-report-json"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- 'prod-gate-slo-summary'; then
  echo "easy_node usage missing prod-gate-slo-summary command"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-slo-summary --help | rg -q -- '--require-signoff-ok'; then
  echo "easy_node prod-gate-slo-summary help missing --require-signoff-ok"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-slo-summary --help | rg -q -- '--fail-on-no-go'; then
  echo "easy_node prod-gate-slo-summary help missing --fail-on-no-go"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- 'prod-gate-slo-trend'; then
  echo "easy_node usage missing prod-gate-slo-trend command"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-slo-trend --help | rg -q -- '--min-go-rate-pct'; then
  echo "easy_node prod-gate-slo-trend help missing --min-go-rate-pct"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-slo-trend --help | rg -q -- '--fail-on-any-no-go'; then
  echo "easy_node prod-gate-slo-trend help missing --fail-on-any-no-go"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-slo-trend --help | rg -q -- '--since-hours'; then
  echo "easy_node prod-gate-slo-trend help missing --since-hours"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-slo-trend --help | rg -q -- '--summary-json'; then
  echo "easy_node prod-gate-slo-trend help missing --summary-json"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-slo-trend --help | rg -q -- '--print-summary-json'; then
  echo "easy_node prod-gate-slo-trend help missing --print-summary-json"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- 'prod-gate-slo-alert'; then
  echo "easy_node usage missing prod-gate-slo-alert command"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-slo-alert --help | rg -q -- '--trend-summary-json'; then
  echo "easy_node prod-gate-slo-alert help missing --trend-summary-json"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-slo-alert --help | rg -q -- '--fail-on-critical'; then
  echo "easy_node prod-gate-slo-alert help missing --fail-on-critical"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-slo-alert --help | rg -q -- '--summary-json'; then
  echo "easy_node prod-gate-slo-alert help missing --summary-json"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- 'prod-gate-slo-dashboard'; then
  echo "easy_node usage missing prod-gate-slo-dashboard command"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-slo-dashboard --help | rg -q -- '--dashboard-md'; then
  echo "easy_node prod-gate-slo-dashboard help missing --dashboard-md"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-slo-dashboard --help | rg -q -- '--print-dashboard'; then
  echo "easy_node prod-gate-slo-dashboard help missing --print-dashboard"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- 'prod-gate-signoff'; then
  echo "easy_node usage missing prod-gate-signoff command"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- 'prod-pilot-runbook'; then
  echo "easy_node usage missing prod-pilot-runbook command"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-gate-signoff --help | rg -q -- '--show-integrity-details'; then
  echo "easy_node prod-gate-signoff help missing --show-integrity-details"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- 'prod-wg-strict-ingress-rehearsal'; then
  echo "easy_node usage missing prod-wg-strict-ingress-rehearsal command"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help --expert | rg -q -- 'incident-snapshot'; then
  echo "easy_node usage missing incident-snapshot command"
  exit 1
fi

echo "[wiring] easy_node incident-snapshot forwarding"
FAKE_INCIDENT_SNAPSHOT="$TMP_DIR/fake_incident_snapshot.sh"
INCIDENT_SNAPSHOT_CAPTURE="$TMP_DIR/incident_snapshot_args.log"
cat >"$FAKE_INCIDENT_SNAPSHOT" <<'EOF_FAKE_INCIDENT_SNAPSHOT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${INCIDENT_SNAPSHOT_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_INCIDENT_SNAPSHOT
chmod +x "$FAKE_INCIDENT_SNAPSHOT"
PATH="$TMP_BIN:$PATH" \
INCIDENT_SNAPSHOT_CAPTURE_FILE="$INCIDENT_SNAPSHOT_CAPTURE" \
INCIDENT_SNAPSHOT_SCRIPT="$FAKE_INCIDENT_SNAPSHOT" \
./scripts/easy_node.sh incident-snapshot \
  --mode provider \
  --bundle-dir /tmp/incident_bundle \
  --timeout-sec 5 \
  --include-docker-logs 0 >/tmp/integration_3machine_prod_profile_wiring_incident_snapshot.log 2>&1

if ! rg -q -- '--mode provider' "$INCIDENT_SNAPSHOT_CAPTURE"; then
  echo "easy_node incident-snapshot forwarding failed: --mode provider missing"
  cat "$INCIDENT_SNAPSHOT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--include-docker-logs 0' "$INCIDENT_SNAPSHOT_CAPTURE"; then
  echo "easy_node incident-snapshot forwarding failed: --include-docker-logs 0 missing"
  cat "$INCIDENT_SNAPSHOT_CAPTURE"
  exit 1
fi

echo "[wiring] easy_node prod-gate-slo-summary forwarding"
FAKE_SLO_SUMMARY="$TMP_DIR/fake_prod_gate_slo_summary.sh"
SLO_SUMMARY_CAPTURE="$TMP_DIR/prod_gate_slo_summary_args.log"
cat >"$FAKE_SLO_SUMMARY" <<'EOF_FAKE_SLO_SUMMARY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SLO_SUMMARY_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_SLO_SUMMARY
chmod +x "$FAKE_SLO_SUMMARY"
PATH="$TMP_BIN:$PATH" \
SLO_SUMMARY_CAPTURE_FILE="$SLO_SUMMARY_CAPTURE" \
PROD_GATE_SLO_SUMMARY_SCRIPT="$FAKE_SLO_SUMMARY" \
./scripts/easy_node.sh prod-gate-slo-summary \
  --run-report-json /tmp/prod_bundle/prod_bundle_run_report.json \
  --require-preflight-ok 1 \
  --require-signoff-ok 1 \
  --fail-on-no-go 1 >/tmp/integration_3machine_prod_profile_wiring_prod_gate_slo_summary.log 2>&1

if ! rg -q -- '--run-report-json /tmp/prod_bundle/prod_bundle_run_report.json' "$SLO_SUMMARY_CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --run-report-json"
  cat "$SLO_SUMMARY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-preflight-ok 1' "$SLO_SUMMARY_CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --require-preflight-ok 1"
  cat "$SLO_SUMMARY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-signoff-ok 1' "$SLO_SUMMARY_CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --require-signoff-ok 1"
  cat "$SLO_SUMMARY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fail-on-no-go 1' "$SLO_SUMMARY_CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --fail-on-no-go 1"
  cat "$SLO_SUMMARY_CAPTURE"
  exit 1
fi

echo "[wiring] easy_node prod-gate-slo-trend forwarding"
FAKE_SLO_TREND="$TMP_DIR/fake_prod_gate_slo_trend.sh"
SLO_TREND_CAPTURE="$TMP_DIR/prod_gate_slo_trend_args.log"
cat >"$FAKE_SLO_TREND" <<'EOF_FAKE_SLO_TREND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SLO_TREND_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_SLO_TREND
chmod +x "$FAKE_SLO_TREND"
PATH="$TMP_BIN:$PATH" \
SLO_TREND_CAPTURE_FILE="$SLO_TREND_CAPTURE" \
PROD_GATE_SLO_TREND_SCRIPT="$FAKE_SLO_TREND" \
./scripts/easy_node.sh prod-gate-slo-trend \
  --reports-dir /tmp/prod_reports \
  --max-reports 10 \
  --since-hours 24 \
  --summary-json /tmp/prod_slo_trend.json \
  --print-summary-json 1 \
  --min-go-rate-pct 95 \
  --fail-on-any-no-go 1 >/tmp/integration_3machine_prod_profile_wiring_prod_gate_slo_trend.log 2>&1

if ! rg -q -- '--reports-dir /tmp/prod_reports' "$SLO_TREND_CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --reports-dir"
  cat "$SLO_TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-reports 10' "$SLO_TREND_CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --max-reports 10"
  cat "$SLO_TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-go-rate-pct 95' "$SLO_TREND_CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --min-go-rate-pct 95"
  cat "$SLO_TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--since-hours 24' "$SLO_TREND_CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --since-hours 24"
  cat "$SLO_TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json /tmp/prod_slo_trend.json' "$SLO_TREND_CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --summary-json"
  cat "$SLO_TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-summary-json 1' "$SLO_TREND_CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --print-summary-json 1"
  cat "$SLO_TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fail-on-any-no-go 1' "$SLO_TREND_CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --fail-on-any-no-go 1"
  cat "$SLO_TREND_CAPTURE"
  exit 1
fi

echo "[wiring] easy_node prod-gate-slo-alert forwarding"
FAKE_SLO_ALERT="$TMP_DIR/fake_prod_gate_slo_alert.sh"
SLO_ALERT_CAPTURE="$TMP_DIR/prod_gate_slo_alert_args.log"
cat >"$FAKE_SLO_ALERT" <<'EOF_FAKE_SLO_ALERT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SLO_ALERT_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_SLO_ALERT
chmod +x "$FAKE_SLO_ALERT"
PATH="$TMP_BIN:$PATH" \
SLO_ALERT_CAPTURE_FILE="$SLO_ALERT_CAPTURE" \
PROD_GATE_SLO_ALERT_SCRIPT="$FAKE_SLO_ALERT" \
./scripts/easy_node.sh prod-gate-slo-alert \
  --reports-dir /tmp/prod_reports \
  --since-hours 12 \
  --warn-go-rate-pct 99 \
  --critical-go-rate-pct 95 \
  --fail-on-warn 1 \
  --fail-on-critical 1 \
  --summary-json /tmp/prod_slo_alert.json \
  --print-summary-json 1 >/tmp/integration_3machine_prod_profile_wiring_prod_gate_slo_alert.log 2>&1

if ! rg -q -- '--reports-dir /tmp/prod_reports' "$SLO_ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --reports-dir"
  cat "$SLO_ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--since-hours 12' "$SLO_ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --since-hours 12"
  cat "$SLO_ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--warn-go-rate-pct 99' "$SLO_ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --warn-go-rate-pct"
  cat "$SLO_ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--critical-go-rate-pct 95' "$SLO_ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --critical-go-rate-pct"
  cat "$SLO_ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fail-on-warn 1' "$SLO_ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --fail-on-warn 1"
  cat "$SLO_ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fail-on-critical 1' "$SLO_ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --fail-on-critical 1"
  cat "$SLO_ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json /tmp/prod_slo_alert.json' "$SLO_ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --summary-json"
  cat "$SLO_ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-summary-json 1' "$SLO_ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --print-summary-json 1"
  cat "$SLO_ALERT_CAPTURE"
  exit 1
fi

echo "[wiring] easy_node prod-gate-slo-dashboard forwarding"
FAKE_SLO_DASHBOARD="$TMP_DIR/fake_prod_gate_slo_dashboard.sh"
SLO_DASHBOARD_CAPTURE="$TMP_DIR/prod_gate_slo_dashboard_args.log"
cat >"$FAKE_SLO_DASHBOARD" <<'EOF_FAKE_SLO_DASHBOARD'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SLO_DASHBOARD_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_SLO_DASHBOARD
chmod +x "$FAKE_SLO_DASHBOARD"
PATH="$TMP_BIN:$PATH" \
SLO_DASHBOARD_CAPTURE_FILE="$SLO_DASHBOARD_CAPTURE" \
PROD_GATE_SLO_DASHBOARD_SCRIPT="$FAKE_SLO_DASHBOARD" \
./scripts/easy_node.sh prod-gate-slo-dashboard \
  --reports-dir /tmp/prod_reports \
  --since-hours 6 \
  --min-go-rate-pct 97 \
  --warn-go-rate-pct 99 \
  --critical-go-rate-pct 95 \
  --trend-summary-json /tmp/prod_slo_trend.json \
  --alert-summary-json /tmp/prod_slo_alert.json \
  --dashboard-md /tmp/prod_slo_dashboard.md \
  --print-dashboard 1 \
  --print-summary-json 1 >/tmp/integration_3machine_prod_profile_wiring_prod_gate_slo_dashboard.log 2>&1

if ! rg -q -- '--reports-dir /tmp/prod_reports' "$SLO_DASHBOARD_CAPTURE"; then
  echo "easy_node prod-gate-slo-dashboard forwarding failed: missing --reports-dir"
  cat "$SLO_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--since-hours 6' "$SLO_DASHBOARD_CAPTURE"; then
  echo "easy_node prod-gate-slo-dashboard forwarding failed: missing --since-hours 6"
  cat "$SLO_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-go-rate-pct 97' "$SLO_DASHBOARD_CAPTURE"; then
  echo "easy_node prod-gate-slo-dashboard forwarding failed: missing --min-go-rate-pct 97"
  cat "$SLO_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--warn-go-rate-pct 99' "$SLO_DASHBOARD_CAPTURE"; then
  echo "easy_node prod-gate-slo-dashboard forwarding failed: missing --warn-go-rate-pct 99"
  cat "$SLO_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--critical-go-rate-pct 95' "$SLO_DASHBOARD_CAPTURE"; then
  echo "easy_node prod-gate-slo-dashboard forwarding failed: missing --critical-go-rate-pct 95"
  cat "$SLO_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--dashboard-md /tmp/prod_slo_dashboard.md' "$SLO_DASHBOARD_CAPTURE"; then
  echo "easy_node prod-gate-slo-dashboard forwarding failed: missing --dashboard-md"
  cat "$SLO_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-dashboard 1' "$SLO_DASHBOARD_CAPTURE"; then
  echo "easy_node prod-gate-slo-dashboard forwarding failed: missing --print-dashboard 1"
  cat "$SLO_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-summary-json 1' "$SLO_DASHBOARD_CAPTURE"; then
  echo "easy_node prod-gate-slo-dashboard forwarding failed: missing --print-summary-json 1"
  cat "$SLO_DASHBOARD_CAPTURE"
  exit 1
fi

echo "[wiring] easy_node strict-ingress rehearsal preset"
FAKE_EASY_REHEARSAL_SOAK="$TMP_DIR/fake_easy_rehearsal_soak.sh"
EASY_REHEARSAL_CAPTURE="$TMP_DIR/easy_rehearsal_soak_args.log"
cat >"$FAKE_EASY_REHEARSAL_SOAK" <<'EOF_FAKE_EASY_REHEARSAL_SOAK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${EASY_REHEARSAL_CAPTURE_FILE:?}"
report_file=""
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-file)
      report_file="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$report_file" ]]; then
  mkdir -p "$(dirname "$report_file")"
  cat >"$report_file" <<'EOF_REHEARSAL_REPORT'
[3machine-prod-wg-soak] round=1 result=fail rc=1 class=strict_ingress_policy duration_sec=1
[3machine-prod-wg-soak] failure_class strict_ingress_policy=1
EOF_REHEARSAL_REPORT
fi
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_REHEARSAL_SUMMARY'
{
  "status": "fail",
  "rounds_requested": 1,
  "rounds_passed": 0,
  "rounds_failed": 1,
  "failure_classes": {
    "strict_ingress_policy": 1
  }
}
EOF_REHEARSAL_SUMMARY
fi
exit 1
EOF_FAKE_EASY_REHEARSAL_SOAK
chmod +x "$FAKE_EASY_REHEARSAL_SOAK"

EASY_REHEARSAL_LOG="/tmp/integration_3machine_prod_profile_wiring_easy_rehearsal.log"
set +e
PATH="$TMP_BIN:$PATH" \
EASY_REHEARSAL_CAPTURE_FILE="$EASY_REHEARSAL_CAPTURE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_EASY_REHEARSAL_SOAK" \
./scripts/easy_node.sh prod-wg-strict-ingress-rehearsal \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 >"$EASY_REHEARSAL_LOG" 2>&1
easy_rehearsal_rc=$?
set -e
if [[ "$easy_rehearsal_rc" -ne 0 ]]; then
  echo "easy_node strict-ingress rehearsal preset failed"
  cat "$EASY_REHEARSAL_LOG"
  exit 1
fi
if ! rg -q -- '--strict-ingress-rehearsal 1' "$EASY_REHEARSAL_CAPTURE"; then
  echo "easy_node strict-ingress rehearsal preset missing --strict-ingress-rehearsal 1"
  cat "$EASY_REHEARSAL_CAPTURE"
  cat "$EASY_REHEARSAL_LOG"
  exit 1
fi
if ! rg -q -- '--max-failure-class strict_ingress_policy=0' "$EASY_REHEARSAL_CAPTURE"; then
  echo "easy_node strict-ingress rehearsal preset missing strict_ingress_policy budget"
  cat "$EASY_REHEARSAL_CAPTURE"
  cat "$EASY_REHEARSAL_LOG"
  exit 1
fi
if ! rg -q 'prod wg strict-ingress rehearsal check ok' "$EASY_REHEARSAL_LOG"; then
  echo "easy_node strict-ingress rehearsal preset missing success marker"
  cat "$EASY_REHEARSAL_LOG"
  exit 1
fi

FAKE_GATE_VALIDATE="$TMP_DIR/fake_gate_validate.sh"
FAKE_GATE_SOAK="$TMP_DIR/fake_gate_soak.sh"
FAKE_GATE_WG_VALIDATE="$TMP_DIR/fake_gate_wg_validate.sh"
FAKE_GATE_WG_SOAK="$TMP_DIR/fake_gate_wg_soak.sh"
GATE_VALIDATE_CAPTURE="$TMP_DIR/gate_validate_args.log"
GATE_SOAK_CAPTURE="$TMP_DIR/gate_soak_args.log"
GATE_WG_VALIDATE_CAPTURE="$TMP_DIR/gate_wg_validate_args.log"
GATE_WG_SOAK_CAPTURE="$TMP_DIR/gate_wg_soak_args.log"

cat >"$FAKE_GATE_VALIDATE" <<'EOF_FAKE_GATE_VALIDATE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${GATE_VALIDATE_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_GATE_VALIDATE

cat >"$FAKE_GATE_SOAK" <<'EOF_FAKE_GATE_SOAK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${GATE_SOAK_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_GATE_SOAK

cat >"$FAKE_GATE_WG_VALIDATE" <<'EOF_FAKE_GATE_WG_VALIDATE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${GATE_WG_VALIDATE_CAPTURE_FILE:?}"
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_VALIDATE_SUMMARY'
{
  "status": "ok",
  "failed_step": ""
}
EOF_VALIDATE_SUMMARY
fi
exit 0
EOF_FAKE_GATE_WG_VALIDATE

cat >"$FAKE_GATE_WG_SOAK" <<'EOF_FAKE_GATE_WG_SOAK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${GATE_WG_SOAK_CAPTURE_FILE:?}"
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_SUMMARY'
{
  "status": "fail",
  "rounds_requested": 3,
  "rounds_passed": 1,
  "rounds_failed": 2,
  "max_consecutive_failures_seen": 2,
  "max_consecutive_failures_limit": 2,
  "report_file": "/tmp/fake.log",
  "summary_generated_at_utc": "2026-03-09T00:00:00Z",
  "failure_classes": {
    "endpoint_connectivity": 2,
    "timeout": 1
  }
}
EOF_SUMMARY
fi
exit 0
EOF_FAKE_GATE_WG_SOAK

chmod +x "$FAKE_GATE_VALIDATE" "$FAKE_GATE_SOAK" "$FAKE_GATE_WG_VALIDATE" "$FAKE_GATE_WG_SOAK"

echo "[wiring] prod gate script control-step forwarding"
PATH="$TMP_BIN:$PATH" \
GATE_VALIDATE_CAPTURE_FILE="$GATE_VALIDATE_CAPTURE" \
GATE_SOAK_CAPTURE_FILE="$GATE_SOAK_CAPTURE" \
GATE_WG_VALIDATE_CAPTURE_FILE="$GATE_WG_VALIDATE_CAPTURE" \
GATE_WG_SOAK_CAPTURE_FILE="$GATE_WG_SOAK_CAPTURE" \
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_VALIDATE" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_SOAK" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_WG_VALIDATE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_WG_SOAK" \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --control-fault-every 2 \
  --control-fault-command test-control-fault \
  --control-continue-on-fail 1 \
  --control-soak-rounds 2 \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_prod_gate.log 2>&1

if ! rg -q -- '--prod-profile 1' "$GATE_VALIDATE_CAPTURE"; then
  echo "prod gate wiring failed: validate call missing --prod-profile 1"
  cat "$GATE_VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-issuer-quorum 1' "$GATE_VALIDATE_CAPTURE"; then
  echo "prod gate wiring failed: validate call missing --require-issuer-quorum 1"
  cat "$GATE_VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--rounds 2' "$GATE_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: soak call missing --rounds 2"
  cat "$GATE_SOAK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fault-every 2' "$GATE_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: control soak call missing --fault-every 2"
  cat "$GATE_SOAK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fault-command test-control-fault' "$GATE_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: control soak call missing --fault-command test-control-fault"
  cat "$GATE_SOAK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--continue-on-fail 1' "$GATE_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: control soak call missing --continue-on-fail 1"
  cat "$GATE_SOAK_CAPTURE"
  exit 1
fi
if [[ -s "$GATE_WG_VALIDATE_CAPTURE" || -s "$GATE_WG_SOAK_CAPTURE" ]]; then
  echo "prod gate wiring failed: WG scripts should not run when --skip-wg 1"
  cat "$GATE_WG_VALIDATE_CAPTURE" "$GATE_WG_SOAK_CAPTURE"
  exit 1
fi

: >"$GATE_WG_VALIDATE_CAPTURE"
: >"$GATE_WG_SOAK_CAPTURE"

echo "[wiring] prod gate script wg-step summary output"
WG_SUMMARY_FILE="$TMP_DIR/prod_gate_wg_summary.json"
GATE_SUMMARY_FILE="$TMP_DIR/prod_gate_summary.json"
WG_GATE_LOG="/tmp/integration_3machine_prod_profile_wiring_prod_gate_wg.log"
PATH="$TMP_BIN:$PATH" \
GATE_VALIDATE_CAPTURE_FILE="$GATE_VALIDATE_CAPTURE" \
GATE_SOAK_CAPTURE_FILE="$GATE_SOAK_CAPTURE" \
GATE_WG_VALIDATE_CAPTURE_FILE="$GATE_WG_VALIDATE_CAPTURE" \
GATE_WG_SOAK_CAPTURE_FILE="$GATE_WG_SOAK_CAPTURE" \
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_VALIDATE" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_SOAK" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_WG_VALIDATE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_WG_SOAK" \
THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT=1 \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --skip-control-soak 1 \
  --wg-soak-rounds 1 \
  --wg-soak-pause-sec 0 \
  --wg-fault-every 4 \
  --wg-fault-command test-wg-fault \
  --wg-continue-on-fail 1 \
  --wg-max-round-duration-sec 90 \
  --wg-max-recovery-sec 120 \
  --wg-max-failure-class endpoint_connectivity=2 \
  --wg-disallow-unknown-failure-class 1 \
  --wg-strict-ingress-rehearsal 1 \
  --wg-min-selection-lines 6 \
  --wg-min-entry-operators 2 \
  --wg-min-exit-operators 2 \
  --wg-min-cross-operator-pairs 2 \
  --wg-soak-summary-json "$WG_SUMMARY_FILE" \
  --gate-summary-json "$GATE_SUMMARY_FILE" >"$WG_GATE_LOG" 2>&1

if [[ ! -s "$GATE_WG_VALIDATE_CAPTURE" || ! -s "$GATE_WG_SOAK_CAPTURE" ]]; then
  echo "prod gate wiring failed: WG scripts should run when --skip-wg 0"
  cat "$GATE_WG_VALIDATE_CAPTURE" "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--summary-json' "$GATE_WG_VALIDATE_CAPTURE"; then
  echo "prod gate wiring failed: WG validate call missing --summary-json forwarding"
  cat "$GATE_WG_VALIDATE_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--summary-json' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --summary-json forwarding"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--fault-every 4' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --fault-every 4"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--fault-command test-wg-fault' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --fault-command test-wg-fault"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--continue-on-fail 1' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --continue-on-fail 1"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--max-round-duration-sec 90' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --max-round-duration-sec 90"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--max-recovery-sec 120' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --max-recovery-sec 120"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--max-failure-class endpoint_connectivity=2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --max-failure-class endpoint_connectivity=2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--disallow-unknown-failure-class 1' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --disallow-unknown-failure-class 1"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--strict-ingress-rehearsal 1' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --strict-ingress-rehearsal 1"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--min-selection-lines 6' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --min-selection-lines 6"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--min-entry-operators 2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --min-entry-operators 2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--min-exit-operators 2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --min-exit-operators 2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--min-cross-operator-pairs 2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --min-cross-operator-pairs 2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi

echo "[wiring] prod gate script wg slo profile defaults"
: >"$GATE_WG_VALIDATE_CAPTURE"
: >"$GATE_WG_SOAK_CAPTURE"
WG_GATE_LOG_PROFILE="/tmp/integration_3machine_prod_profile_wiring_prod_gate_wg_profile.log"
PATH="$TMP_BIN:$PATH" \
GATE_VALIDATE_CAPTURE_FILE="$GATE_VALIDATE_CAPTURE" \
GATE_SOAK_CAPTURE_FILE="$GATE_SOAK_CAPTURE" \
GATE_WG_VALIDATE_CAPTURE_FILE="$GATE_WG_VALIDATE_CAPTURE" \
GATE_WG_SOAK_CAPTURE_FILE="$GATE_WG_SOAK_CAPTURE" \
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_VALIDATE" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_SOAK" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_WG_VALIDATE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_WG_SOAK" \
THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT=1 \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --skip-control-soak 1 \
  --wg-soak-rounds 1 \
  --wg-soak-pause-sec 0 \
  --wg-slo-profile recommended \
  --wg-soak-summary-json "$WG_SUMMARY_FILE" \
  --gate-summary-json "$GATE_SUMMARY_FILE" >"$WG_GATE_LOG_PROFILE" 2>&1
if ! rg -q -- '--max-round-duration-sec 180' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing --max-round-duration-sec 180"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--max-recovery-sec 240' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing --max-recovery-sec 240"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--max-failure-class endpoint_connectivity=2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing endpoint_connectivity budget"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--max-failure-class timeout=2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing timeout budget"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--max-failure-class wg_dataplane_stall=1' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing wg_dataplane_stall budget"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--max-failure-class strict_ingress_policy=0' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing strict_ingress_policy budget"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--disallow-unknown-failure-class 1' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing disallow-unknown flag"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--min-selection-lines 0' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing --min-selection-lines 0"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--min-entry-operators 0' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing --min-entry-operators 0"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--min-exit-operators 0' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing --min-exit-operators 0"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--min-cross-operator-pairs 0' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing --min-cross-operator-pairs 0"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi

echo "[wiring] prod gate script wg slo strict diversity defaults"
: >"$GATE_WG_VALIDATE_CAPTURE"
: >"$GATE_WG_SOAK_CAPTURE"
WG_GATE_LOG_PROFILE_STRICT="/tmp/integration_3machine_prod_profile_wiring_prod_gate_wg_profile_strict.log"
PATH="$TMP_BIN:$PATH" \
GATE_VALIDATE_CAPTURE_FILE="$GATE_VALIDATE_CAPTURE" \
GATE_SOAK_CAPTURE_FILE="$GATE_SOAK_CAPTURE" \
GATE_WG_VALIDATE_CAPTURE_FILE="$GATE_WG_VALIDATE_CAPTURE" \
GATE_WG_SOAK_CAPTURE_FILE="$GATE_WG_SOAK_CAPTURE" \
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_VALIDATE" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_SOAK" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_WG_VALIDATE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_WG_SOAK" \
THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT=1 \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --skip-control-soak 1 \
  --wg-soak-rounds 1 \
  --wg-soak-pause-sec 0 \
  --wg-slo-profile strict \
  --wg-soak-summary-json "$WG_SUMMARY_FILE" \
  --gate-summary-json "$GATE_SUMMARY_FILE" >"$WG_GATE_LOG_PROFILE_STRICT" 2>&1
if ! rg -q -- '--min-selection-lines 8' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile strict missing --min-selection-lines 8"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE_STRICT"
  exit 1
fi
if ! rg -q -- '--min-entry-operators 2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile strict missing --min-entry-operators 2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE_STRICT"
  exit 1
fi
if ! rg -q -- '--min-exit-operators 2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile strict missing --min-exit-operators 2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE_STRICT"
  exit 1
fi
if ! rg -q -- '--min-cross-operator-pairs 2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile strict missing --min-cross-operator-pairs 2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE_STRICT"
  exit 1
fi
if ! rg -q -- '--max-failure-class strict_ingress_policy=0' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile strict missing strict_ingress_policy budget"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE_STRICT"
  exit 1
fi
if ! rg -q '\[prod-gate\] wg_soak_summary status=fail .* top_failure_class=endpoint_connectivity top_failure_count=2 ' "$WG_GATE_LOG"; then
  echo "prod gate wiring failed: compact WG soak summary output missing/incorrect"
  cat "$WG_GATE_LOG"
  exit 1
fi
if [[ ! -f "$GATE_SUMMARY_FILE" ]]; then
  echo "prod gate wiring failed: gate summary json missing on successful run"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q '"status": "ok"' "$GATE_SUMMARY_FILE"; then
  echo "prod gate wiring failed: gate summary status missing/incorrect on successful run"
  cat "$GATE_SUMMARY_FILE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q '"wg_soak_status": "fail"' "$GATE_SUMMARY_FILE"; then
  echo "prod gate wiring failed: gate summary missing embedded WG status"
  cat "$GATE_SUMMARY_FILE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q '"wg_validate_summary_json": "' "$GATE_SUMMARY_FILE"; then
  echo "prod gate wiring failed: gate summary missing WG validate summary path field"
  cat "$GATE_SUMMARY_FILE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q '"wg_validate_status": "ok"' "$GATE_SUMMARY_FILE"; then
  echo "prod gate wiring failed: gate summary missing WG validate status"
  cat "$GATE_SUMMARY_FILE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q '"prod_wg_soak": "ok"' "$GATE_SUMMARY_FILE"; then
  echo "prod gate wiring failed: gate summary missing per-step status for prod_wg_soak"
  cat "$GATE_SUMMARY_FILE"
  cat "$WG_GATE_LOG"
  exit 1
fi

echo "[wiring] prod gate script summary on failure path"
FAKE_GATE_WG_SOAK_FAIL="$TMP_DIR/fake_gate_wg_soak_fail.sh"
cat >"$FAKE_GATE_WG_SOAK_FAIL" <<'EOF_FAKE_GATE_WG_SOAK_FAIL'
#!/usr/bin/env bash
set -euo pipefail
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_SUMMARY_FAIL'
{
  "status": "fail",
  "rounds_requested": 2,
  "rounds_passed": 0,
  "rounds_failed": 2,
  "max_consecutive_failures_seen": 2,
  "max_consecutive_failures_limit": 2,
  "report_file": "/tmp/fake_fail.log",
  "summary_generated_at_utc": "2026-03-09T00:00:01Z",
  "failure_classes": {
    "timeout": 2
  }
}
EOF_SUMMARY_FAIL
fi
exit 1
EOF_FAKE_GATE_WG_SOAK_FAIL
chmod +x "$FAKE_GATE_WG_SOAK_FAIL"

GATE_SUMMARY_FAIL_FILE="$TMP_DIR/prod_gate_summary_fail.json"
WG_GATE_FAIL_LOG="/tmp/integration_3machine_prod_profile_wiring_prod_gate_wg_fail.log"
set +e
PATH="$TMP_BIN:$PATH" \
GATE_VALIDATE_CAPTURE_FILE="$GATE_VALIDATE_CAPTURE" \
GATE_SOAK_CAPTURE_FILE="$GATE_SOAK_CAPTURE" \
GATE_WG_VALIDATE_CAPTURE_FILE="$GATE_WG_VALIDATE_CAPTURE" \
GATE_WG_SOAK_CAPTURE_FILE="$GATE_WG_SOAK_CAPTURE" \
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_VALIDATE" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_SOAK" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_WG_VALIDATE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_WG_SOAK_FAIL" \
THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT=1 \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --skip-control-soak 1 \
  --wg-soak-rounds 1 \
  --wg-soak-pause-sec 0 \
  --wg-soak-summary-json "$WG_SUMMARY_FILE" \
  --gate-summary-json "$GATE_SUMMARY_FAIL_FILE" >"$WG_GATE_FAIL_LOG" 2>&1
gate_fail_rc=$?
set -e
if [[ "$gate_fail_rc" -eq 0 ]]; then
  echo "prod gate wiring failed: expected non-zero rc on failing WG soak path"
  cat "$WG_GATE_FAIL_LOG"
  exit 1
fi
if [[ ! -f "$GATE_SUMMARY_FAIL_FILE" ]]; then
  echo "prod gate wiring failed: missing gate summary json on failing path"
  cat "$WG_GATE_FAIL_LOG"
  exit 1
fi
if ! rg -q '"status": "fail"' "$GATE_SUMMARY_FAIL_FILE" || ! rg -q '"failed_step": "prod_wg_soak"' "$GATE_SUMMARY_FAIL_FILE"; then
  echo "prod gate wiring failed: failure summary missing status/failed_step"
  cat "$GATE_SUMMARY_FAIL_FILE"
  cat "$WG_GATE_FAIL_LOG"
  exit 1
fi
if ! rg -q '\[prod-gate\] wg_soak_summary status=fail .* top_failure_class=timeout top_failure_count=2 ' "$WG_GATE_FAIL_LOG"; then
  echo "prod gate wiring failed: compact WG summary missing on failing path"
  cat "$WG_GATE_FAIL_LOG"
  exit 1
fi

echo "[wiring] prod gate script strict-ingress summary path"
FAKE_GATE_WG_SOAK_STRICT="$TMP_DIR/fake_gate_wg_soak_strict.sh"
cat >"$FAKE_GATE_WG_SOAK_STRICT" <<'EOF_FAKE_GATE_WG_SOAK_STRICT'
#!/usr/bin/env bash
set -euo pipefail
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_SUMMARY_STRICT'
{
  "status": "fail",
  "rounds_requested": 3,
  "rounds_passed": 0,
  "rounds_failed": 3,
  "max_consecutive_failures_seen": 3,
  "max_consecutive_failures_limit": 3,
  "report_file": "/tmp/fake_strict.log",
  "summary_generated_at_utc": "2026-03-10T00:00:00Z",
  "failure_classes": {
    "strict_ingress_policy": 3,
    "timeout": 1
  }
}
EOF_SUMMARY_STRICT
fi
exit 1
EOF_FAKE_GATE_WG_SOAK_STRICT
chmod +x "$FAKE_GATE_WG_SOAK_STRICT"

GATE_SUMMARY_STRICT_FILE="$TMP_DIR/prod_gate_summary_strict_ingress.json"
WG_GATE_STRICT_LOG="/tmp/integration_3machine_prod_profile_wiring_prod_gate_wg_strict_ingress.log"
set +e
PATH="$TMP_BIN:$PATH" \
GATE_VALIDATE_CAPTURE_FILE="$GATE_VALIDATE_CAPTURE" \
GATE_SOAK_CAPTURE_FILE="$GATE_SOAK_CAPTURE" \
GATE_WG_VALIDATE_CAPTURE_FILE="$GATE_WG_VALIDATE_CAPTURE" \
GATE_WG_SOAK_CAPTURE_FILE="$GATE_WG_SOAK_CAPTURE" \
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_VALIDATE" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_SOAK" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_WG_VALIDATE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_WG_SOAK_STRICT" \
THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT=1 \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --skip-control-soak 1 \
  --wg-soak-rounds 1 \
  --wg-soak-pause-sec 0 \
  --wg-soak-summary-json "$WG_SUMMARY_FILE" \
  --gate-summary-json "$GATE_SUMMARY_STRICT_FILE" >"$WG_GATE_STRICT_LOG" 2>&1
gate_strict_rc=$?
set -e
if [[ "$gate_strict_rc" -eq 0 ]]; then
  echo "prod gate wiring failed: expected non-zero rc on strict-ingress WG soak path"
  cat "$WG_GATE_STRICT_LOG"
  exit 1
fi
if [[ ! -f "$GATE_SUMMARY_STRICT_FILE" ]]; then
  echo "prod gate wiring failed: missing gate summary json on strict-ingress path"
  cat "$WG_GATE_STRICT_LOG"
  exit 1
fi
if ! rg -q '\[prod-gate\] wg_soak_summary status=fail .* top_failure_class=strict_ingress_policy top_failure_count=3 ' "$WG_GATE_STRICT_LOG"; then
  echo "prod gate wiring failed: strict-ingress compact WG summary missing/incorrect"
  cat "$WG_GATE_STRICT_LOG"
  exit 1
fi
if ! rg -q '"wg_soak_top_failure_class": "strict_ingress_policy"' "$GATE_SUMMARY_STRICT_FILE"; then
  echo "prod gate wiring failed: strict-ingress gate summary missing top failure class"
  cat "$GATE_SUMMARY_STRICT_FILE"
  cat "$WG_GATE_STRICT_LOG"
  exit 1
fi
if ! rg -q '"wg_soak_top_failure_count": 3' "$GATE_SUMMARY_STRICT_FILE"; then
  echo "prod gate wiring failed: strict-ingress gate summary missing top failure count"
  cat "$GATE_SUMMARY_STRICT_FILE"
  cat "$WG_GATE_STRICT_LOG"
  exit 1
fi

FAKE_BUNDLE_GATE="$TMP_DIR/fake_bundle_gate.sh"
BUNDLE_CAPTURE="$TMP_DIR/prod_bundle_gate_args.log"
BUNDLE_SOURCE_STEP_LOGS="$TMP_DIR/fake_bundle_step_logs_src"
cat >"$FAKE_BUNDLE_GATE" <<'EOF_FAKE_BUNDLE_GATE'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${BUNDLE_CAPTURE_FILE:?}"

report_file=""
wg_validate_summary=""
wg_summary=""
gate_summary=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-file)
      report_file="${2:-}"
      shift 2
      ;;
    --wg-validate-summary-json)
      wg_validate_summary="${2:-}"
      shift 2
      ;;
    --wg-soak-summary-json)
      wg_summary="${2:-}"
      shift 2
      ;;
    --gate-summary-json)
      gate_summary="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

mkdir -p "${BUNDLE_SOURCE_STEP_LOGS_DIR:?}"
printf 'step log marker\n' >"${BUNDLE_SOURCE_STEP_LOGS_DIR}/marker.log"

if [[ -n "$report_file" ]]; then
  mkdir -p "$(dirname "$report_file")"
  {
    printf '[prod-gate] fake gate running\n'
    printf '[prod-gate] step_logs: %s\n' "${BUNDLE_SOURCE_STEP_LOGS_DIR}"
  } >"$report_file"
fi
if [[ -n "$wg_validate_summary" ]]; then
  mkdir -p "$(dirname "$wg_validate_summary")"
  cat >"$wg_validate_summary" <<'EOF_WG_VALIDATE_SUMMARY'
{
  "status": "ok",
  "failed_step": ""
}
EOF_WG_VALIDATE_SUMMARY
fi
if [[ -n "$wg_summary" ]]; then
  mkdir -p "$(dirname "$wg_summary")"
  cat >"$wg_summary" <<'EOF_WG_SUMMARY'
{
  "status": "ok",
  "rounds_requested": 1,
  "rounds_passed": 1,
  "rounds_failed": 0
}
EOF_WG_SUMMARY
fi
if [[ -n "$gate_summary" ]]; then
  mkdir -p "$(dirname "$gate_summary")"
  cat >"$gate_summary" <<EOF_GATE_SUMMARY
{
  "status": "ok",
  "failed_step": "",
  "step_logs": "${BUNDLE_SOURCE_STEP_LOGS_DIR}"
}
EOF_GATE_SUMMARY
fi

exit "${FAKE_BUNDLE_GATE_RC:-0}"
EOF_FAKE_BUNDLE_GATE
chmod +x "$FAKE_BUNDLE_GATE"

echo "[wiring] prod gate bundle script success path"
BUNDLE_DIR_OK="$TMP_DIR/prod_gate_bundle_ok"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
./scripts/prod_gate_bundle.sh \
  --bundle-dir "$BUNDLE_DIR_OK" \
  --strict-distinct 1 \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_bundle_ok.log 2>&1
bundle_ok_rc=$?
set -e
if [[ "$bundle_ok_rc" -ne 0 ]]; then
  echo "prod gate bundle wiring failed: expected success rc=0"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_ok.log
  exit 1
fi
if [[ ! -f "${BUNDLE_DIR_OK}.tar.gz" ]]; then
  echo "prod gate bundle wiring failed: bundle tarball missing on success"
  ls -la "$TMP_DIR"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_ok.log
  exit 1
fi
if [[ ! -f "${BUNDLE_DIR_OK}.tar.gz.sha256" ]]; then
  echo "prod gate bundle wiring failed: bundle tarball sha256 sidecar missing on success"
  ls -la "$TMP_DIR"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_ok.log
  exit 1
fi
if [[ ! -f "$BUNDLE_DIR_OK/step_logs/marker.log" ]]; then
  echo "prod gate bundle wiring failed: copied step logs missing"
  find "$BUNDLE_DIR_OK" -maxdepth 3 -type f -print || true
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_ok.log
  exit 1
fi
if [[ ! -f "$BUNDLE_DIR_OK/manifest.sha256" ]]; then
  echo "prod gate bundle wiring failed: manifest.sha256 missing in bundle dir"
  find "$BUNDLE_DIR_OK" -maxdepth 2 -type f -print || true
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_ok.log
  exit 1
fi
if ! rg -q '  metadata.txt$' "$BUNDLE_DIR_OK/manifest.sha256"; then
  echo "prod gate bundle wiring failed: manifest missing metadata.txt entry"
  cat "$BUNDLE_DIR_OK/manifest.sha256"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_ok.log
  exit 1
fi
if ! rg -q "  $(basename "${BUNDLE_DIR_OK}.tar.gz")$" "${BUNDLE_DIR_OK}.tar.gz.sha256"; then
  echo "prod gate bundle wiring failed: tarball sha256 sidecar missing bundle filename label"
  cat "${BUNDLE_DIR_OK}.tar.gz.sha256"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_ok.log
  exit 1
fi
if [[ ! -f "$BUNDLE_DIR_OK/prod_wg_validate_summary.json" ]]; then
  echo "prod gate bundle wiring failed: WG validate summary missing in bundle dir"
  find "$BUNDLE_DIR_OK" -maxdepth 2 -type f -print || true
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_ok.log
  exit 1
fi
if ! rg -q -- '--strict-distinct 1' "$BUNDLE_CAPTURE"; then
  echo "prod gate bundle wiring failed: forwarded gate args missing"
  cat "$BUNDLE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-validate-summary-json' "$BUNDLE_CAPTURE"; then
  echo "prod gate bundle wiring failed: missing --wg-validate-summary-json forwarding"
  cat "$BUNDLE_CAPTURE"
  exit 1
fi
if ! rg -q 'gate_rc=0' "$BUNDLE_DIR_OK/metadata.txt"; then
  echo "prod gate bundle wiring failed: metadata missing gate_rc=0"
  cat "$BUNDLE_DIR_OK/metadata.txt"
  exit 1
fi
if ! rg -q 'wg_validate_summary_json=' "$BUNDLE_DIR_OK/metadata.txt"; then
  echo "prod gate bundle wiring failed: metadata missing wg_validate_summary_json entry"
  cat "$BUNDLE_DIR_OK/metadata.txt"
  exit 1
fi
if ! rg -q 'manifest_file=' "$BUNDLE_DIR_OK/metadata.txt"; then
  echo "prod gate bundle wiring failed: metadata missing manifest_file entry"
  cat "$BUNDLE_DIR_OK/metadata.txt"
  exit 1
fi
if ! rg -q 'bundle_tar_sha256_file=' "$BUNDLE_DIR_OK/metadata.txt"; then
  echo "prod gate bundle wiring failed: metadata missing bundle_tar_sha256_file entry"
  cat "$BUNDLE_DIR_OK/metadata.txt"
  exit 1
fi

echo "[wiring] prod gate bundle script failure path"
BUNDLE_DIR_FAIL="$TMP_DIR/prod_gate_bundle_fail"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
FAKE_BUNDLE_GATE_RC=17 \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
./scripts/prod_gate_bundle.sh \
  --bundle-dir "$BUNDLE_DIR_FAIL" \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_bundle_fail.log 2>&1
bundle_fail_rc=$?
set -e
if [[ "$bundle_fail_rc" -ne 17 ]]; then
  echo "prod gate bundle wiring failed: expected rc=17 on failing path (got $bundle_fail_rc)"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_fail.log
  exit 1
fi
if [[ ! -f "${BUNDLE_DIR_FAIL}.tar.gz" ]]; then
  echo "prod gate bundle wiring failed: bundle tarball missing on failure"
  ls -la "$TMP_DIR"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_fail.log
  exit 1
fi
if [[ ! -f "${BUNDLE_DIR_FAIL}.tar.gz.sha256" ]]; then
  echo "prod gate bundle wiring failed: bundle tarball sha256 sidecar missing on failure"
  ls -la "$TMP_DIR"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_fail.log
  exit 1
fi
if [[ ! -f "$BUNDLE_DIR_FAIL/manifest.sha256" ]]; then
  echo "prod gate bundle wiring failed: manifest.sha256 missing on failure"
  find "$BUNDLE_DIR_FAIL" -maxdepth 2 -type f -print || true
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_fail.log
  exit 1
fi
if ! rg -q 'gate_rc=17' "$BUNDLE_DIR_FAIL/metadata.txt"; then
  echo "prod gate bundle wiring failed: metadata missing gate_rc=17"
  cat "$BUNDLE_DIR_FAIL/metadata.txt"
  exit 1
fi

FAKE_BUNDLE_SIGNOFF="$TMP_DIR/fake_bundle_signoff.sh"
SIGNOFF_CAPTURE="$TMP_DIR/prod_bundle_signoff_args.log"
cat >"$FAKE_BUNDLE_SIGNOFF" <<'EOF_FAKE_BUNDLE_SIGNOFF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SIGNOFF_CAPTURE_FILE:?}"
exit "${FAKE_BUNDLE_SIGNOFF_RC:-0}"
EOF_FAKE_BUNDLE_SIGNOFF
chmod +x "$FAKE_BUNDLE_SIGNOFF"

echo "[wiring] prod gate bundle signoff success path"
BUNDLE_DIR_SIGNOFF_OK="$TMP_DIR/prod_gate_bundle_signoff_ok"
: >"$SIGNOFF_CAPTURE"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
FAKE_BUNDLE_SIGNOFF_RC=0 \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
THREE_MACHINE_PROD_GATE_CHECK_SCRIPT="$FAKE_BUNDLE_SIGNOFF" \
./scripts/prod_gate_bundle.sh \
  --bundle-dir "$BUNDLE_DIR_SIGNOFF_OK" \
  --skip-wg 1 \
  --signoff-check 1 \
  --signoff-require-full-sequence 0 \
  --signoff-require-wg-validate-ok 0 \
  --signoff-require-wg-soak-ok 1 \
  --signoff-max-wg-soak-failed-rounds 2 \
  --signoff-show-json 1 >/tmp/integration_3machine_prod_profile_wiring_bundle_signoff_ok.log 2>&1
bundle_signoff_ok_rc=$?
set -e
if [[ "$bundle_signoff_ok_rc" -ne 0 ]]; then
  echo "prod gate bundle wiring failed: expected signoff success rc=0"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_signoff_ok.log
  exit 1
fi
if ! rg -q -- '--gate-summary-json' "$SIGNOFF_CAPTURE"; then
  echo "prod gate bundle signoff wiring failed: missing --gate-summary-json"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-full-sequence 0' "$SIGNOFF_CAPTURE"; then
  echo "prod gate bundle signoff wiring failed: missing --require-full-sequence 0"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-ok 0' "$SIGNOFF_CAPTURE"; then
  echo "prod gate bundle signoff wiring failed: missing --require-wg-validate-ok 0"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-soak-ok 1' "$SIGNOFF_CAPTURE"; then
  echo "prod gate bundle signoff wiring failed: missing --require-wg-soak-ok 1"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-wg-soak-failed-rounds 2' "$SIGNOFF_CAPTURE"; then
  echo "prod gate bundle signoff wiring failed: missing --max-wg-soak-failed-rounds 2"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$SIGNOFF_CAPTURE"; then
  echo "prod gate bundle signoff wiring failed: missing --show-json 1"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q 'signoff_enabled=1' "$BUNDLE_DIR_SIGNOFF_OK/metadata.txt"; then
  echo "prod gate bundle signoff wiring failed: metadata missing signoff_enabled=1"
  cat "$BUNDLE_DIR_SIGNOFF_OK/metadata.txt"
  exit 1
fi
if ! rg -q 'signoff_rc=0' "$BUNDLE_DIR_SIGNOFF_OK/metadata.txt"; then
  echo "prod gate bundle signoff wiring failed: metadata missing signoff_rc=0"
  cat "$BUNDLE_DIR_SIGNOFF_OK/metadata.txt"
  exit 1
fi

echo "[wiring] prod gate bundle signoff fail-close path"
BUNDLE_DIR_SIGNOFF_FAIL="$TMP_DIR/prod_gate_bundle_signoff_fail"
: >"$SIGNOFF_CAPTURE"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
FAKE_BUNDLE_SIGNOFF_RC=19 \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
THREE_MACHINE_PROD_GATE_CHECK_SCRIPT="$FAKE_BUNDLE_SIGNOFF" \
./scripts/prod_gate_bundle.sh \
  --bundle-dir "$BUNDLE_DIR_SIGNOFF_FAIL" \
  --skip-wg 1 \
  --signoff-check 1 >/tmp/integration_3machine_prod_profile_wiring_bundle_signoff_fail.log 2>&1
bundle_signoff_fail_rc=$?
set -e
if [[ "$bundle_signoff_fail_rc" -ne 19 ]]; then
  echo "prod gate bundle wiring failed: expected signoff fail-close rc=19 (got $bundle_signoff_fail_rc)"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_signoff_fail.log
  exit 1
fi
if [[ ! -f "${BUNDLE_DIR_SIGNOFF_FAIL}.tar.gz" ]]; then
  echo "prod gate bundle wiring failed: signoff fail-close should still produce bundle tarball"
  ls -la "$TMP_DIR"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_signoff_fail.log
  exit 1
fi
if ! rg -q 'gate_rc=0' "$BUNDLE_DIR_SIGNOFF_FAIL/metadata.txt"; then
  echo "prod gate bundle signoff wiring failed: metadata missing gate_rc=0 on signoff failure"
  cat "$BUNDLE_DIR_SIGNOFF_FAIL/metadata.txt"
  exit 1
fi
if ! rg -q 'signoff_rc=19' "$BUNDLE_DIR_SIGNOFF_FAIL/metadata.txt"; then
  echo "prod gate bundle signoff wiring failed: metadata missing signoff_rc=19"
  cat "$BUNDLE_DIR_SIGNOFF_FAIL/metadata.txt"
  exit 1
fi

FAKE_BUNDLE_VERIFY="$TMP_DIR/fake_bundle_verify.sh"
BUNDLE_VERIFY_CAPTURE="$TMP_DIR/prod_bundle_verify_args.log"
cat >"$FAKE_BUNDLE_VERIFY" <<'EOF_FAKE_BUNDLE_VERIFY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${BUNDLE_VERIFY_CAPTURE_FILE:?}"
exit "${FAKE_BUNDLE_VERIFY_RC:-0}"
EOF_FAKE_BUNDLE_VERIFY
chmod +x "$FAKE_BUNDLE_VERIFY"

echo "[wiring] easy_node -> prod bundle dispatch"
EASY_BUNDLE_DIR="$TMP_DIR/easy_node_prod_bundle"
: >"$BUNDLE_VERIFY_CAPTURE"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
THREE_MACHINE_PROD_GATE_BUNDLE_VERIFY_SCRIPT="$FAKE_BUNDLE_VERIFY" \
BUNDLE_VERIFY_CAPTURE_FILE="$BUNDLE_VERIFY_CAPTURE" \
FAKE_BUNDLE_VERIFY_RC=0 \
THREE_MACHINE_PROD_BUNDLE_SCRIPT="./scripts/prod_gate_bundle.sh" \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir "$EASY_BUNDLE_DIR" \
  --preflight-check 0 \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_easy_bundle.log 2>&1
easy_bundle_rc=$?
set -e
if [[ "$easy_bundle_rc" -ne 0 ]]; then
  echo "easy_node prod bundle wiring failed: non-zero rc"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle.log
  exit 1
fi
if [[ ! -f "${EASY_BUNDLE_DIR}.tar.gz" ]]; then
  echo "easy_node prod bundle wiring failed: expected tarball missing"
  ls -la "$TMP_DIR"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle.log
  exit 1
fi
if [[ ! -f "$EASY_BUNDLE_DIR/prod_bundle_run_report.json" ]]; then
  echo "easy_node prod bundle wiring failed: missing run report JSON"
  find "$EASY_BUNDLE_DIR" -maxdepth 2 -type f -print || true
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle.log
  exit 1
fi
if ! rg -F -q "\"bundle_dir\": \"$EASY_BUNDLE_DIR\"" "$EASY_BUNDLE_DIR/prod_bundle_run_report.json"; then
  echo "easy_node prod bundle wiring failed: run report missing bundle_dir"
  cat "$EASY_BUNDLE_DIR/prod_bundle_run_report.json"
  exit 1
fi
if ! rg -q '"final_rc":[[:space:]]*0' "$EASY_BUNDLE_DIR/prod_bundle_run_report.json"; then
  echo "easy_node prod bundle wiring failed: run report missing final_rc=0"
  cat "$EASY_BUNDLE_DIR/prod_bundle_run_report.json"
  exit 1
fi
if ! rg -q -- '--bundle-dir' "$BUNDLE_VERIFY_CAPTURE"; then
  echo "easy_node prod bundle wiring failed: verify script missing --bundle-dir forwarding"
  cat "$BUNDLE_VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- "--bundle-tar ${EASY_BUNDLE_DIR}.tar.gz" "$BUNDLE_VERIFY_CAPTURE"; then
  echo "easy_node prod bundle wiring failed: verify script missing --bundle-tar forwarding"
  cat "$BUNDLE_VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--check-tar-sha256 1' "$BUNDLE_VERIFY_CAPTURE"; then
  echo "easy_node prod bundle wiring failed: verify script missing --check-tar-sha256 1"
  cat "$BUNDLE_VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--check-manifest 1' "$BUNDLE_VERIFY_CAPTURE"; then
  echo "easy_node prod bundle wiring failed: verify script missing --check-manifest 1"
  cat "$BUNDLE_VERIFY_CAPTURE"
  exit 1
fi

echo "[wiring] easy_node -> prod bundle verify disabled diagnostics path"
EASY_BUNDLE_NO_VERIFY_DIR="$TMP_DIR/easy_node_prod_bundle_no_verify"
: >"$BUNDLE_VERIFY_CAPTURE"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
THREE_MACHINE_PROD_GATE_BUNDLE_VERIFY_SCRIPT="$FAKE_BUNDLE_VERIFY" \
BUNDLE_VERIFY_CAPTURE_FILE="$BUNDLE_VERIFY_CAPTURE" \
FAKE_BUNDLE_VERIFY_RC=27 \
THREE_MACHINE_PROD_BUNDLE_SCRIPT="./scripts/prod_gate_bundle.sh" \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir "$EASY_BUNDLE_NO_VERIFY_DIR" \
  --preflight-check 0 \
  --bundle-verify-check 0 \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_easy_bundle_no_verify.log 2>&1
easy_bundle_no_verify_rc=$?
set -e
if [[ "$easy_bundle_no_verify_rc" -ne 0 ]]; then
  echo "easy_node prod bundle verify-disable wiring failed: expected rc=0 (got $easy_bundle_no_verify_rc)"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_no_verify.log
  exit 1
fi
if [[ -s "$BUNDLE_VERIFY_CAPTURE" ]]; then
  echo "easy_node prod bundle verify-disable wiring failed: verify script should not run when disabled"
  cat "$BUNDLE_VERIFY_CAPTURE"
  exit 1
fi
if [[ ! -f "$EASY_BUNDLE_NO_VERIFY_DIR/prod_bundle_run_report.json" ]]; then
  echo "easy_node prod bundle verify-disable wiring failed: missing run report JSON"
  find "$EASY_BUNDLE_NO_VERIFY_DIR" -maxdepth 2 -type f -print || true
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_no_verify.log
  exit 1
fi

echo "[wiring] easy_node -> prod bundle verify fail-close path"
EASY_BUNDLE_VERIFY_FAIL_DIR="$TMP_DIR/easy_node_prod_bundle_verify_fail"
: >"$BUNDLE_VERIFY_CAPTURE"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
THREE_MACHINE_PROD_GATE_BUNDLE_VERIFY_SCRIPT="$FAKE_BUNDLE_VERIFY" \
BUNDLE_VERIFY_CAPTURE_FILE="$BUNDLE_VERIFY_CAPTURE" \
FAKE_BUNDLE_VERIFY_RC=29 \
THREE_MACHINE_PROD_BUNDLE_SCRIPT="./scripts/prod_gate_bundle.sh" \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir "$EASY_BUNDLE_VERIFY_FAIL_DIR" \
  --preflight-check 0 \
  --bundle-verify-check 1 \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_easy_bundle_verify_fail.log 2>&1
easy_bundle_verify_fail_rc=$?
set -e
if [[ "$easy_bundle_verify_fail_rc" -ne 29 ]]; then
  echo "easy_node prod bundle verify fail-close wiring failed: expected rc=29 (got $easy_bundle_verify_fail_rc)"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_verify_fail.log
  exit 1
fi
if [[ ! -f "${EASY_BUNDLE_VERIFY_FAIL_DIR}.tar.gz" ]]; then
  echo "easy_node prod bundle verify fail-close wiring failed: expected tarball missing"
  ls -la "$TMP_DIR"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_verify_fail.log
  exit 1
fi
if [[ ! -f "$EASY_BUNDLE_VERIFY_FAIL_DIR/prod_bundle_run_report.json" ]]; then
  echo "easy_node prod bundle verify fail-close wiring failed: missing run report JSON"
  find "$EASY_BUNDLE_VERIFY_FAIL_DIR" -maxdepth 2 -type f -print || true
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_verify_fail.log
  exit 1
fi
if ! rg -q '"final_rc":[[:space:]]*29' "$EASY_BUNDLE_VERIFY_FAIL_DIR/prod_bundle_run_report.json"; then
  echo "easy_node prod bundle verify fail-close wiring failed: run report missing final_rc=29"
  cat "$EASY_BUNDLE_VERIFY_FAIL_DIR/prod_bundle_run_report.json"
  exit 1
fi

FAKE_BUNDLE_BAD_MANIFEST="$TMP_DIR/fake_bundle_bad_manifest.sh"
cat >"$FAKE_BUNDLE_BAD_MANIFEST" <<'EOF_FAKE_BUNDLE_BAD_MANIFEST'
#!/usr/bin/env bash
set -euo pipefail

manifest_mode="${FAKE_BUNDLE_MANIFEST_MODE:-missing}"
bundle_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      bundle_dir="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$bundle_dir" ]]; then
  echo "fake_bundle_bad_manifest: missing --bundle-dir"
  exit 2
fi

mkdir -p "$bundle_dir"
cat >"$bundle_dir/metadata.txt" <<EOF_BAD_MANIFEST_META
gate_rc=0
signoff_enabled=0
signoff_rc=0
bundle_dir=$bundle_dir
EOF_BAD_MANIFEST_META
cat >"$bundle_dir/prod_gate_summary.json" <<'EOF_BAD_MANIFEST_GATE'
{"status":"ok"}
EOF_BAD_MANIFEST_GATE
cat >"$bundle_dir/prod_wg_validate_summary.json" <<'EOF_BAD_MANIFEST_VALIDATE'
{"status":"ok"}
EOF_BAD_MANIFEST_VALIDATE
cat >"$bundle_dir/prod_wg_soak_summary.json" <<'EOF_BAD_MANIFEST_SOAK'
{"status":"ok"}
EOF_BAD_MANIFEST_SOAK

if [[ "$manifest_mode" == "invalid" ]]; then
  printf 'invalidhash  metadata.txt\n' >"$bundle_dir/manifest.sha256"
fi

bundle_tar="${bundle_dir}.tar.gz"
tar -czf "$bundle_tar" -C "$(dirname "$bundle_dir")" "$(basename "$bundle_dir")"
if command -v sha256sum >/dev/null 2>&1; then
  line="$(sha256sum "$bundle_tar")"
else
  line="$(shasum -a 256 "$bundle_tar")"
fi
printf '%s  %s\n' "${line%% *}" "$(basename "$bundle_tar")" >"${bundle_tar}.sha256"
EOF_FAKE_BUNDLE_BAD_MANIFEST
chmod +x "$FAKE_BUNDLE_BAD_MANIFEST"

echo "[wiring] easy_node -> prod bundle manifest missing fail-close path"
EASY_BUNDLE_MANIFEST_MISSING_DIR="$TMP_DIR/easy_node_prod_bundle_manifest_missing"
set +e
PATH="$TMP_BIN:$PATH" \
FAKE_BUNDLE_MANIFEST_MODE=missing \
THREE_MACHINE_PROD_BUNDLE_SCRIPT="$FAKE_BUNDLE_BAD_MANIFEST" \
THREE_MACHINE_PROD_GATE_BUNDLE_VERIFY_SCRIPT="./scripts/prod_gate_bundle_verify.sh" \
./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir "$EASY_BUNDLE_MANIFEST_MISSING_DIR" \
  --preflight-check 0 \
  --bundle-verify-check 1 \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_easy_bundle_manifest_missing.log 2>&1
easy_bundle_manifest_missing_rc=$?
set -e
if [[ "$easy_bundle_manifest_missing_rc" -eq 0 ]]; then
  echo "easy_node prod bundle manifest-missing wiring failed: expected non-zero rc"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_manifest_missing.log
  exit 1
fi
if ! rg -q 'manifest' /tmp/integration_3machine_prod_profile_wiring_easy_bundle_manifest_missing.log; then
  echo "easy_node prod bundle manifest-missing wiring failed: expected manifest error signal"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_manifest_missing.log
  exit 1
fi
if ! rg -q "\"final_rc\":[[:space:]]*$easy_bundle_manifest_missing_rc" "$EASY_BUNDLE_MANIFEST_MISSING_DIR/prod_bundle_run_report.json"; then
  echo "easy_node prod bundle manifest-missing wiring failed: run report missing fail rc"
  cat "$EASY_BUNDLE_MANIFEST_MISSING_DIR/prod_bundle_run_report.json"
  exit 1
fi

echo "[wiring] easy_node -> prod bundle manifest invalid fail-close path"
EASY_BUNDLE_MANIFEST_INVALID_DIR="$TMP_DIR/easy_node_prod_bundle_manifest_invalid"
set +e
PATH="$TMP_BIN:$PATH" \
FAKE_BUNDLE_MANIFEST_MODE=invalid \
THREE_MACHINE_PROD_BUNDLE_SCRIPT="$FAKE_BUNDLE_BAD_MANIFEST" \
THREE_MACHINE_PROD_GATE_BUNDLE_VERIFY_SCRIPT="./scripts/prod_gate_bundle_verify.sh" \
./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir "$EASY_BUNDLE_MANIFEST_INVALID_DIR" \
  --preflight-check 0 \
  --bundle-verify-check 1 \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_easy_bundle_manifest_invalid.log 2>&1
easy_bundle_manifest_invalid_rc=$?
set -e
if [[ "$easy_bundle_manifest_invalid_rc" -eq 0 ]]; then
  echo "easy_node prod bundle manifest-invalid wiring failed: expected non-zero rc"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_manifest_invalid.log
  exit 1
fi
if ! rg -q 'manifest' /tmp/integration_3machine_prod_profile_wiring_easy_bundle_manifest_invalid.log; then
  echo "easy_node prod bundle manifest-invalid wiring failed: expected manifest error signal"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_manifest_invalid.log
  exit 1
fi
if ! rg -q "\"final_rc\":[[:space:]]*$easy_bundle_manifest_invalid_rc" "$EASY_BUNDLE_MANIFEST_INVALID_DIR/prod_bundle_run_report.json"; then
  echo "easy_node prod bundle manifest-invalid wiring failed: run report missing fail rc"
  cat "$EASY_BUNDLE_MANIFEST_INVALID_DIR/prod_bundle_run_report.json"
  exit 1
fi

FAKE_BUNDLE_PREFLIGHT="$TMP_DIR/fake_bundle_preflight.sh"
PREFLIGHT_CAPTURE="$TMP_DIR/prod_bundle_preflight_args.log"
cat >"$FAKE_BUNDLE_PREFLIGHT" <<'EOF_FAKE_BUNDLE_PREFLIGHT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${PREFLIGHT_CAPTURE_FILE:?}"
exit "${FAKE_BUNDLE_PREFLIGHT_RC:-0}"
EOF_FAKE_BUNDLE_PREFLIGHT
chmod +x "$FAKE_BUNDLE_PREFLIGHT"

echo "[wiring] easy_node -> prod bundle preflight forwarding"
EASY_BUNDLE_PREFLIGHT_DIR="$TMP_DIR/easy_node_prod_bundle_preflight"
: >"$PREFLIGHT_CAPTURE"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
PREFLIGHT_CAPTURE_FILE="$PREFLIGHT_CAPTURE" \
FAKE_BUNDLE_PREFLIGHT_RC=0 \
THREE_MACHINE_PROD_BUNDLE_SCRIPT="./scripts/prod_gate_bundle.sh" \
THREE_MACHINE_PROD_BUNDLE_PREFLIGHT_SCRIPT="$FAKE_BUNDLE_PREFLIGHT" \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir "$EASY_BUNDLE_PREFLIGHT_DIR" \
  --preflight-check 1 \
  --preflight-timeout-sec 9 \
  --preflight-require-root 1 \
  --skip-wg 1 \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 >/tmp/integration_3machine_prod_profile_wiring_easy_bundle_preflight.log 2>&1
easy_bundle_preflight_rc=$?
set -e
if [[ "$easy_bundle_preflight_rc" -ne 0 ]]; then
  echo "easy_node prod bundle preflight wiring failed: non-zero rc"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_preflight.log
  exit 1
fi
if ! rg -q -- '--prod-profile 1' "$PREFLIGHT_CAPTURE"; then
  echo "easy_node prod bundle preflight wiring failed: missing --prod-profile 1"
  cat "$PREFLIGHT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--operator-floor-check 1' "$PREFLIGHT_CAPTURE"; then
  echo "easy_node prod bundle preflight wiring failed: missing --operator-floor-check 1"
  cat "$PREFLIGHT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--issuer-quorum-check 1' "$PREFLIGHT_CAPTURE"; then
  echo "easy_node prod bundle preflight wiring failed: missing --issuer-quorum-check 1"
  cat "$PREFLIGHT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--timeout-sec 9' "$PREFLIGHT_CAPTURE"; then
  echo "easy_node prod bundle preflight wiring failed: missing --timeout-sec 9"
  cat "$PREFLIGHT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-root 0' "$PREFLIGHT_CAPTURE"; then
  echo "easy_node prod bundle preflight wiring failed: expected --require-root 0 when --skip-wg 1"
  cat "$PREFLIGHT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--directory-urls https://dir-a:8081,https://dir-b:8081' "$PREFLIGHT_CAPTURE"; then
  echo "easy_node prod bundle preflight wiring failed: missing directory URL merge forwarding"
  cat "$PREFLIGHT_CAPTURE"
  exit 1
fi

echo "[wiring] easy_node -> prod bundle preflight fail-close path"
EASY_BUNDLE_PREFLIGHT_FAIL_DIR="$TMP_DIR/easy_node_prod_bundle_preflight_fail"
: >"$PREFLIGHT_CAPTURE"
: >"$BUNDLE_CAPTURE"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
PREFLIGHT_CAPTURE_FILE="$PREFLIGHT_CAPTURE" \
FAKE_BUNDLE_PREFLIGHT_RC=23 \
THREE_MACHINE_PROD_BUNDLE_SCRIPT="./scripts/prod_gate_bundle.sh" \
THREE_MACHINE_PROD_BUNDLE_PREFLIGHT_SCRIPT="$FAKE_BUNDLE_PREFLIGHT" \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir "$EASY_BUNDLE_PREFLIGHT_FAIL_DIR" \
  --preflight-check 1 \
  --skip-wg 1 \
  --bootstrap-directory https://dir-a:8081 >/tmp/integration_3machine_prod_profile_wiring_easy_bundle_preflight_fail.log 2>&1
easy_bundle_preflight_fail_rc=$?
set -e
if [[ "$easy_bundle_preflight_fail_rc" -ne 23 ]]; then
  echo "easy_node prod bundle preflight wiring failed: expected fail-close rc=23 (got $easy_bundle_preflight_fail_rc)"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_preflight_fail.log
  exit 1
fi
if [[ -f "${EASY_BUNDLE_PREFLIGHT_FAIL_DIR}.tar.gz" ]]; then
  echo "easy_node prod bundle preflight wiring failed: bundle should not run when preflight fails"
  ls -la "$TMP_DIR"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_preflight_fail.log
  exit 1
fi
if [[ -s "$BUNDLE_CAPTURE" ]]; then
  echo "easy_node prod bundle preflight wiring failed: bundle gate script should not run on preflight failure"
  cat "$BUNDLE_CAPTURE"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_preflight_fail.log
  exit 1
fi

echo "[wiring] easy_node -> prod bundle signoff forwarding"
EASY_BUNDLE_SIGNOFF_DIR="$TMP_DIR/easy_node_prod_bundle_signoff"
: >"$SIGNOFF_CAPTURE"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
FAKE_BUNDLE_SIGNOFF_RC=0 \
THREE_MACHINE_PROD_BUNDLE_SCRIPT="./scripts/prod_gate_bundle.sh" \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
THREE_MACHINE_PROD_GATE_CHECK_SCRIPT="$FAKE_BUNDLE_SIGNOFF" \
./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir "$EASY_BUNDLE_SIGNOFF_DIR" \
  --preflight-check 0 \
  --skip-wg 1 \
  --signoff-check 1 \
  --signoff-max-wg-soak-failed-rounds 5 \
  --signoff-show-json 1 >/tmp/integration_3machine_prod_profile_wiring_easy_bundle_signoff.log 2>&1
easy_bundle_signoff_rc=$?
set -e
if [[ "$easy_bundle_signoff_rc" -ne 0 ]]; then
  echo "easy_node prod bundle signoff wiring failed: non-zero rc"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle_signoff.log
  exit 1
fi
if ! rg -q -- '--max-wg-soak-failed-rounds 5' "$SIGNOFF_CAPTURE"; then
  echo "easy_node prod bundle signoff wiring failed: missing signoff max failed rounds forwarding"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$SIGNOFF_CAPTURE"; then
  echo "easy_node prod bundle signoff wiring failed: missing signoff show-json forwarding"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

echo "[wiring] easy_node help includes prod-key-rotation-runbook"
if ! ./scripts/easy_node.sh --help --expert | rg -q -- 'prod-key-rotation-runbook'; then
  echo "easy_node help is missing prod-key-rotation-runbook command"
  exit 1
fi

FAKE_ROTATION_RUNBOOK="$TMP_DIR/fake_rotation_runbook.sh"
ROTATION_CAPTURE="$TMP_DIR/rotation_runbook_capture.log"
cat >"$FAKE_ROTATION_RUNBOOK" <<'EOF_FAKE_ROTATION_RUNBOOK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${ROTATION_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_ROTATION_RUNBOOK
chmod +x "$FAKE_ROTATION_RUNBOOK"

echo "[wiring] easy_node -> prod key-rotation runbook forwarding"
PATH="$TMP_BIN:$PATH" \
ROTATION_CAPTURE_FILE="$ROTATION_CAPTURE" \
PROD_KEY_ROTATION_RUNBOOK_SCRIPT="$FAKE_ROTATION_RUNBOOK" \
./scripts/easy_node.sh prod-key-rotation-runbook \
  --mode provider \
  --preflight-check 0 \
  --key-history 7 >/tmp/integration_3machine_prod_profile_wiring_key_rotation.log 2>&1

if ! rg -q -- '--mode provider' "$ROTATION_CAPTURE"; then
  echo "easy_node prod key-rotation wiring failed: missing --mode forwarding"
  cat "$ROTATION_CAPTURE"
  exit 1
fi
if ! rg -q -- '--preflight-check 0' "$ROTATION_CAPTURE"; then
  echo "easy_node prod key-rotation wiring failed: missing --preflight-check forwarding"
  cat "$ROTATION_CAPTURE"
  exit 1
fi
if ! rg -q -- '--key-history 7' "$ROTATION_CAPTURE"; then
  echo "easy_node prod key-rotation wiring failed: missing --key-history forwarding"
  cat "$ROTATION_CAPTURE"
  exit 1
fi

echo "[wiring] easy_node help includes prod-upgrade-runbook"
if ! ./scripts/easy_node.sh --help --expert | rg -q -- 'prod-upgrade-runbook'; then
  echo "easy_node help is missing prod-upgrade-runbook command"
  exit 1
fi

FAKE_UPGRADE_RUNBOOK="$TMP_DIR/fake_upgrade_runbook.sh"
UPGRADE_CAPTURE="$TMP_DIR/upgrade_runbook_capture.log"
cat >"$FAKE_UPGRADE_RUNBOOK" <<'EOF_FAKE_UPGRADE_RUNBOOK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${UPGRADE_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_UPGRADE_RUNBOOK
chmod +x "$FAKE_UPGRADE_RUNBOOK"

echo "[wiring] easy_node -> prod upgrade runbook forwarding"
PATH="$TMP_BIN:$PATH" \
UPGRADE_CAPTURE_FILE="$UPGRADE_CAPTURE" \
PROD_UPGRADE_RUNBOOK_SCRIPT="$FAKE_UPGRADE_RUNBOOK" \
./scripts/easy_node.sh prod-upgrade-runbook \
  --mode authority \
  --compose-pull 0 \
  --compose-build 1 >/tmp/integration_3machine_prod_profile_wiring_upgrade.log 2>&1

if ! rg -q -- '--mode authority' "$UPGRADE_CAPTURE"; then
  echo "easy_node prod upgrade wiring failed: missing --mode forwarding"
  cat "$UPGRADE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--compose-pull 0' "$UPGRADE_CAPTURE"; then
  echo "easy_node prod upgrade wiring failed: missing --compose-pull forwarding"
  cat "$UPGRADE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--compose-build 1' "$UPGRADE_CAPTURE"; then
  echo "easy_node prod upgrade wiring failed: missing --compose-build forwarding"
  cat "$UPGRADE_CAPTURE"
  exit 1
fi

echo "3-machine prod-profile wiring integration check ok"
