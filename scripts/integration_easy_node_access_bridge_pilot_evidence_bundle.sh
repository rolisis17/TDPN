#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash chmod grep mktemp sed wc; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "easy node access bridge pilot evidence bundle integration failed: missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
FAKE_SCRIPT="$TMP_DIR/fake_access_bridge_pilot_evidence_bundle.sh"
FAKE_VERIFY_SCRIPT="$TMP_DIR/fake_access_bridge_pilot_evidence_bundle_verify.sh"
HELP_OUT="$TMP_DIR/help.txt"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_CAPTURE_FILE:?}"
{
  printf 'access_bridge_pilot_evidence_bundle'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
exit "${FAKE_ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_RC:-0}"
EOF_FAKE
chmod +x "$FAKE_SCRIPT"

cat >"$FAKE_VERIFY_SCRIPT" <<'EOF_FAKE_VERIFY'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_CAPTURE_FILE:?}"
{
  printf 'access_bridge_pilot_evidence_bundle_verify'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
exit "${FAKE_ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_RC:-0}"
EOF_FAKE_VERIFY
chmod +x "$FAKE_VERIFY_SCRIPT"

./scripts/easy_node.sh help >"$HELP_OUT"
if ! grep -Fq -- './scripts/easy_node.sh access-bridge-pilot-evidence-bundle' "$HELP_OUT"; then
  echo "easy_node help missing access-bridge-pilot-evidence-bundle command"
  cat "$HELP_OUT"
  exit 1
fi
if ! grep -Fq -- './scripts/easy_node.sh access-bridge-pilot-evidence-bundle-verify' "$HELP_OUT"; then
  echo "easy_node help missing access-bridge-pilot-evidence-bundle-verify command"
  cat "$HELP_OUT"
  exit 1
fi
if ! ./scripts/easy_node.sh help --expert | grep -Fq -- 'access-bridge-pilot-evidence-bundle wraps deployed bridge smoke'; then
  echo "easy_node expert help missing access bridge pilot evidence bundle note"
  exit 1
fi
if ! ./scripts/easy_node.sh help --expert | grep -Fq -- 'access-bridge-pilot-evidence-bundle-verify validates Access Bridge pilot bundle integrity artifacts'; then
  echo "easy_node expert help missing access bridge pilot evidence bundle verifier note"
  exit 1
fi

: >"$CAPTURE"
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_SCRIPT" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-bridge-pilot-evidence-bundle \
  --base-url https://bridge.example \
  --path-id helper-web \
  --code-file .easy-node-logs/access-recovery-demo/bridge-code.txt \
  --config-json .easy-node-logs/access-recovery-demo/bridge-service-config.json \
  --deploy-pack-dir .easy-node-logs/access-recovery-demo/bridge-deploy \
  --summary-json .easy-node-logs/access-recovery-demo/access-bridge-pilot-evidence-summary.json \
  --print-summary-json 1

if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "1" ]]; then
  echo "expected exactly one forwarded wrapper invocation"
  cat "$CAPTURE"
  exit 1
fi
line="$(sed -n '1p' "$CAPTURE")"
for token in \
  $'\t--base-url\thttps://bridge.example' \
  $'\t--path-id\thelper-web' \
  $'\t--code-file\t.easy-node-logs/access-recovery-demo/bridge-code.txt' \
  $'\t--config-json\t.easy-node-logs/access-recovery-demo/bridge-service-config.json' \
  $'\t--deploy-pack-dir\t.easy-node-logs/access-recovery-demo/bridge-deploy' \
  $'\t--summary-json\t.easy-node-logs/access-recovery-demo/access-bridge-pilot-evidence-summary.json' \
  $'\t--print-summary-json\t1'
do
  if [[ "$line" != *"$token"* ]]; then
    echo "missing forwarded token: $token"
    echo "$line"
    exit 1
  fi
done

: >"$CAPTURE"
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY_SCRIPT" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-bridge-pilot-evidence-bundle-verify \
  --summary-json .easy-node-logs/access-recovery-demo/access-bridge-pilot-evidence-summary.json \
  --bundle-dir .easy-node-logs/access-recovery-demo/pilot-evidence-bundle \
  --bundle-tar .easy-node-logs/access-recovery-demo/pilot-evidence-bundle.tar.gz \
  --provenance-json .easy-node-logs/access-recovery-demo/access-bridge-pilot-evidence.provenance.json \
  --trust-store .easy-node-logs/access-recovery-demo/provenance-trust-store.json \
  --require-trusted-provenance 1 \
  --verification-summary-json .easy-node-logs/access_bridge_pilot_evidence_bundle_verify_summary.json \
  --print-verification-summary-json 1 \
  --show-details 1

if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "1" ]]; then
  echo "expected exactly one forwarded verifier invocation"
  cat "$CAPTURE"
  exit 1
fi
line="$(sed -n '1p' "$CAPTURE")"
for token in \
  $'\t--summary-json\t.easy-node-logs/access-recovery-demo/access-bridge-pilot-evidence-summary.json' \
  $'\t--bundle-dir\t.easy-node-logs/access-recovery-demo/pilot-evidence-bundle' \
  $'\t--bundle-tar\t.easy-node-logs/access-recovery-demo/pilot-evidence-bundle.tar.gz' \
  $'\t--provenance-json\t.easy-node-logs/access-recovery-demo/access-bridge-pilot-evidence.provenance.json' \
  $'\t--trust-store\t.easy-node-logs/access-recovery-demo/provenance-trust-store.json' \
  $'\t--require-trusted-provenance\t1' \
  $'\t--verification-summary-json\t.easy-node-logs/access_bridge_pilot_evidence_bundle_verify_summary.json' \
  $'\t--print-verification-summary-json\t1' \
  $'\t--show-details\t1'
do
  if [[ "$line" != *"$token"* ]]; then
    echo "missing forwarded verifier token: $token"
    echo "$line"
    exit 1
  fi
done

set +e
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$FAKE_SCRIPT" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_CAPTURE_FILE="$CAPTURE" \
FAKE_ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_RC=7 \
./scripts/easy_node.sh access-bridge-pilot-evidence-bundle --sample boom >/dev/null 2>&1
rc=$?
set -e
if [[ "$rc" -ne 7 ]]; then
  echo "expected fake wrapper exit code 7, got $rc"
  exit 1
fi

set +e
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY_SCRIPT" \
ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_CAPTURE_FILE="$CAPTURE" \
FAKE_ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_RC=8 \
./scripts/easy_node.sh access-bridge-pilot-evidence-bundle-verify --sample boom >/dev/null 2>&1
rc=$?
set -e
if [[ "$rc" -ne 8 ]]; then
  echo "expected fake verifier exit code 8, got $rc"
  exit 1
fi

echo "easy node access bridge pilot evidence bundle integration check ok"
