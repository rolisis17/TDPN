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

FAKE_BIN="$TMP_DIR/fake_bin"
mkdir -p "$FAKE_BIN"

echo "[live-beta-ssh-cycle] ssh command terminates options before destination"
SSH_CAPTURE="$TMP_DIR/ssh_args.log"
cat >"$FAKE_BIN/ssh" <<'EOF_SSH'
#!/usr/bin/env bash
set -euo pipefail
{
  printf 'call\n'
  for arg in "$@"; do
    printf '<%s>\n' "$arg"
  done
} >>"${FAKE_SSH_CAPTURE_FILE:?}"
exit 0
EOF_SSH
chmod +x "$FAKE_BIN/ssh"
PATH="$FAKE_BIN:$PATH" \
FAKE_SSH_CAPTURE_FILE="$SSH_CAPTURE" \
LIVE_BETA_SSH_KEY="$SSH_KEY" \
./scripts/live_beta_ssh_cycle.sh --mode ssh-check >"$TMP_DIR/ssh_check.log" 2>&1
if [[ "$(grep -c '^<-->$' "$SSH_CAPTURE" || true)" -lt 2 ]]; then
  echo "expected ssh invocations to include -- before the destination"
  cat "$SSH_CAPTURE"
  exit 1
fi
if ! awk '
  /^<-->$/ { saw = 1; next }
  saw == 1 {
    if ($0 !~ /^<[^@<>]+@[^<>]+>$/) {
      bad = 1
    }
    saw = 0
  }
  END { exit bad }
' "$SSH_CAPTURE"; then
  echo "expected ssh destination argument immediately after --"
  cat "$SSH_CAPTURE"
  exit 1
fi

echo "[live-beta-ssh-cycle] topology output redacts endpoint URLs"
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

echo "[live-beta-ssh-cycle] auth-negative mode requires issuer allowlist rejection"
cat >"$FAKE_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
out_file=""
write_format=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      out_file="${2:-}"
      shift 2
      ;;
    -w)
      write_format="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$out_file" ]]; then
  printf 'client subject not allowlisted\n' >"$out_file"
fi
if [[ "$write_format" == "%{http_code}" ]]; then
  printf '403'
fi
EOF_CURL
chmod +x "$FAKE_BIN/curl"
PATH="$FAKE_BIN:$PATH" \
LIVE_BETA_SSH_KEY="$SSH_KEY" \
./scripts/live_beta_ssh_cycle.sh --mode auth-negative >"$TMP_DIR/auth_negative.log" 2>&1
if ! grep -F -- "auth-negative ok: unknown client subject was rejected" "$TMP_DIR/auth_negative.log" >/dev/null; then
  echo "expected auth-negative success marker"
  cat "$TMP_DIR/auth_negative.log"
  exit 1
fi

echo "[live-beta-ssh-cycle] auth-negative mode fails if issuer returns a token"
cat >"$FAKE_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
out_file=""
write_format=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      out_file="${2:-}"
      shift 2
      ;;
    -w)
      write_format="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$out_file" ]]; then
  printf '{"token":"bad-open-token"}\n' >"$out_file"
fi
if [[ "$write_format" == "%{http_code}" ]]; then
  printf '200'
fi
EOF_CURL
chmod +x "$FAKE_BIN/curl"
set +e
PATH="$FAKE_BIN:$PATH" \
LIVE_BETA_SSH_KEY="$SSH_KEY" \
./scripts/live_beta_ssh_cycle.sh --mode auth-negative >"$TMP_DIR/auth_negative_open.log" 2>&1
rc_auth_negative_open=$?
set -e
if [[ "$rc_auth_negative_open" -eq 0 ]]; then
  echo "expected auth-negative to fail when issuer accepts unknown subject"
  cat "$TMP_DIR/auth_negative_open.log"
  exit 1
fi
if ! grep -F -- "expected issuer to reject unknown subject with 403, got 200" "$TMP_DIR/auth_negative_open.log" >/dev/null; then
  echo "expected open-issuer failure diagnostic"
  cat "$TMP_DIR/auth_negative_open.log"
  exit 1
fi

echo "live beta ssh cycle integration check ok"
