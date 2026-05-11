#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

FAKE_BIN="$TMP_DIR/bin"
mkdir -p "$FAKE_BIN"

cat >"$FAKE_BIN/tailscale" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  status)
    echo "100.111.133.33 ds user linux -"
    echo "100.113.245.61 win-0h8d1fon0a0 user linux active; direct"
    echo "100.64.244.24 linux user linux active; direct"
    ;;
  ping)
    shift
    if [[ "${1:-}" == --timeout=* ]]; then
      shift
    fi
    echo "pong from ${1:-unknown} via fake"
    ;;
  *)
    echo "unexpected tailscale args: $*" >&2
    exit 2
    ;;
esac
FAKE

cat >"$FAKE_BIN/nc" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
exit 0
FAKE

cat >"$FAKE_BIN/ssh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
cat >/dev/null
target=""
for arg in "$@"; do
  case "$arg" in
    *@*)
      target="$arg"
      ;;
  esac
done
host="${target#*@}"
echo "remote_hostname=fake-${host}"
echo "repo_pwd=/fake/repo/${host}"
echo "git_branch=codex/gpm-productization-checkpoint"
echo "git_head=c47bab82"
echo "git_dirty_count=0"
echo "docker_container_count=3"
echo "docker_container=deploy-directory-1 Up 1 hour"
FAKE

chmod +x "$FAKE_BIN/tailscale" "$FAKE_BIN/nc" "$FAKE_BIN/ssh"

SSH_KEY="$TMP_DIR/test_key"
printf '%s\n' 'fake private key placeholder' >"$SSH_KEY"
SUMMARY_JSON="$TMP_DIR/real_host_ssh_diag_summary.json"
RUN_LOG="$TMP_DIR/run.log"

PATH="$FAKE_BIN:$PATH" ./scripts/real_host_ssh_diag.sh \
  --host-a 100.113.245.61 \
  --host-b 100.64.244.24 \
  --ssh-user stella \
  --ssh-port 2222 \
  --ssh-key "$SSH_KEY" \
  --repo-a /mnt/c/Users/Stella/Downloads/TDPN \
  --repo-b "/home/stella/myfirstproject/trust-tiered decentralized privacy network" \
  --summary-json "$SUMMARY_JSON" \
  --print-summary-json 1 >"$RUN_LOG"

if [[ ! -f "$SUMMARY_JSON" ]]; then
  echo "expected real-host SSH diag summary was not created"
  cat "$RUN_LOG"
  exit 1
fi

if ! jq -e '
  .schema.id == "real_host_ssh_diag_summary"
  and .schema.major == 1
  and .status == "pass"
  and .rc == 0
  and .local.tailscale_available == true
  and (.hosts | length == 2)
  and ([.hosts[].checks.tailscale_ping.status] | all(. == "pass"))
  and ([.hosts[].checks.tcp_ssh_port.status] | all(. == "pass"))
  and ([.hosts[].checks.ssh_key_auth.status] | all(. == "pass"))
  and (.next_actions | length == 0)
' "$SUMMARY_JSON" >/dev/null; then
  echo "real-host SSH diag summary missing expected pass contract"
  cat "$SUMMARY_JSON"
  exit 1
fi

if ! rg -q 'remote_hostname=fake-100.113.245.61' "$SUMMARY_JSON"; then
  echo "expected SSH excerpt for host A"
  cat "$SUMMARY_JSON"
  exit 1
fi

echo "[real-host-ssh-diag] easy_node forwarding"
FAKE_SCRIPT="$TMP_DIR/fake_real_host_ssh_diag.sh"
CAPTURE="$TMP_DIR/easy_node_capture.log"
cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CAPTURE_FILE:?}"
EOF_FAKE
chmod +x "$FAKE_SCRIPT"

CAPTURE_FILE="$CAPTURE" \
REAL_HOST_SSH_DIAG_SCRIPT="$FAKE_SCRIPT" \
./scripts/easy_node.sh real-host-ssh-diag \
  --host-a 100.113.245.61 \
  --host-b 100.64.244.24 \
  --ssh-user stella \
  --ssh-port 2222 \
  --ssh-key "$SSH_KEY" \
  --remote-repo-check 0 \
  --print-summary-json 0 >/tmp/integration_real_host_ssh_diag_easy_node.log 2>&1

for expected in \
  '--host-a 100.113.245.61' \
  '--host-b 100.64.244.24' \
  '--ssh-user stella' \
  '--ssh-port 2222' \
  "--ssh-key $SSH_KEY" \
  '--remote-repo-check 0' \
  '--print-summary-json 0'; do
  if ! grep -F -- "$expected" "$CAPTURE" >/dev/null; then
    echo "easy_node real-host SSH diag forwarding missing: $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

echo "real-host SSH diag integration ok"
