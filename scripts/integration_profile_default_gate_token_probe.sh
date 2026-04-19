#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

CAPTURE_FILE="$TMP_DIR/capture.log"
FAKE_SCRIPT="$TMP_DIR/fake_profile_default_gate_token_probe.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'profile-default-gate-token-probe %s\n' "$*" >>"${PROBE_CAPTURE_FILE:?}"
EOF_FAKE
chmod +x "$FAKE_SCRIPT"

PROBE_CAPTURE_FILE="$CAPTURE_FILE" \
PROFILE_DEFAULT_GATE_TOKEN_PROBE_SCRIPT="$FAKE_SCRIPT" \
./scripts/easy_node.sh profile-default-gate-token-probe \
  --directory-url http://100.113.245.61:8081 \
  --issuer-url http://100.113.245.61:8082 \
  --exit-url http://100.113.245.61:8084 \
  --campaign-subject inv-test \
  --reports-dir .easy-node-logs \
  --print-summary-json 1 \
  --show-json 0

line="$(rg '^profile-default-gate-token-probe ' "$CAPTURE_FILE" | tail -n 1 || true)"
if [[ -z "$line" ]]; then
  echo "missing easy_node forwarding capture for profile-default-gate-token-probe"
  cat "$CAPTURE_FILE"
  exit 1
fi

for expected in \
  '--directory-url http://100.113.245.61:8081' \
  '--issuer-url http://100.113.245.61:8082' \
  '--exit-url http://100.113.245.61:8084' \
  '--campaign-subject inv-test' \
  '--reports-dir .easy-node-logs' \
  '--print-summary-json 1' \
  '--show-json 0'; do
  if ! grep -F -- "$expected" <<<"$line" >/dev/null; then
    echo "easy_node forwarding missing $expected"
    cat "$CAPTURE_FILE"
    exit 1
  fi
done

echo "profile default gate token probe integration ok"
