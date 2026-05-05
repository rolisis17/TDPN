#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

SSH_KEY="$TMP_DIR/fake_ssh_key"
touch "$SSH_KEY"
chmod 600 "$SSH_KEY"

echo "[live-beta-ssh-cycle] client mode without subject fails closed"
set +e
LIVE_BETA_SSH_KEY="$SSH_KEY" \
./scripts/live_beta_ssh_cycle.sh --mode client >"$TMP_DIR/missing_subject.log" 2>&1
rc_missing_subject=$?
set -e
if [[ "$rc_missing_subject" -ne 2 ]]; then
  echo "expected rc=2 when client mode has no subject"
  cat "$TMP_DIR/missing_subject.log"
  exit 1
fi
if ! grep -F -- "client-test failed: pass --subject INVITE, set LIVE_BETA_SUBJECT, or use --generate-subject" "$TMP_DIR/missing_subject.log" >/dev/null; then
  echo "expected missing-subject fail-closed message"
  cat "$TMP_DIR/missing_subject.log"
  exit 1
fi
if grep -F -- "client-test skipped: pass --subject INVITE or set LIVE_BETA_SUBJECT" "$TMP_DIR/missing_subject.log" >/dev/null; then
  echo "unexpected legacy skip message for missing client subject"
  cat "$TMP_DIR/missing_subject.log"
  exit 1
fi

echo "[live-beta-ssh-cycle] explicit client skip remains available"
LIVE_BETA_SSH_KEY="$SSH_KEY" \
LIVE_BETA_SKIP_CLIENT=1 \
./scripts/live_beta_ssh_cycle.sh --mode client >"$TMP_DIR/skip_client.log" 2>&1
if ! grep -F -- "client-test skipped by LIVE_BETA_SKIP_CLIENT=1" "$TMP_DIR/skip_client.log" >/dev/null; then
  echo "expected explicit skip message"
  cat "$TMP_DIR/skip_client.log"
  exit 1
fi

echo "[live-beta-ssh-cycle] topology output redacts endpoint URLs"
FAKE_BIN="$TMP_DIR/fake_bin"
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
cat <<'JSON'
{
  "relays": [
    {
      "relay_id": "entry-a",
      "role": "entry",
      "operator_id": "op-a",
      "control_url": "http://user:pw-secret@control-a:8083?token=control-secret",
      "endpoint": "100.64.0.1:51820",
      "entry_route_assertion_pub_key": "pub"
    }
  ]
}
JSON
EOF_CURL
chmod +x "$FAKE_BIN/curl"
PATH="$FAKE_BIN:$PATH" \
LIVE_BETA_SSH_KEY="$SSH_KEY" \
./scripts/live_beta_ssh_cycle.sh --mode topology >"$TMP_DIR/topology.log" 2>&1
for expected in "A directory relays" "B directory relays" "entry-a" "control-url" "endpoint" "entry-assertion-key"; do
  if ! grep -F -- "$expected" "$TMP_DIR/topology.log" >/dev/null; then
    echo "expected topology output to include: $expected"
    cat "$TMP_DIR/topology.log"
    exit 1
  fi
done
for forbidden in "pw-secret" "token=" "control-a:8083" "100.64.0.1:51820" "http://"; do
  if grep -F -- "$forbidden" "$TMP_DIR/topology.log" >/dev/null; then
    echo "topology output leaked forbidden value: $forbidden"
    cat "$TMP_DIR/topology.log"
    exit 1
  fi
done

echo "live beta ssh cycle integration check ok"
