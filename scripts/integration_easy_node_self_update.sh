#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
STATE_FILE="$TMP_DIR/git_state.env"
CAPTURE_FILE="$TMP_DIR/git_calls.log"
FAKE_BIN="$TMP_DIR/bin"
mkdir -p "$FAKE_BIN"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

write_state() {
  local local_sha="$1"
  local remote_sha="$2"
  local branch="$3"
  local dirty="$4"
  cat >"$STATE_FILE" <<EOF_STATE
LOCAL_SHA=$local_sha
REMOTE_SHA=$remote_sha
BRANCH=$branch
DIRTY=$dirty
EOF_STATE
}

write_state \
  "1111111111111111111111111111111111111111" \
  "2222222222222222222222222222222222222222" \
  "main" \
  "0"
: >"$CAPTURE_FILE"

cat >"$FAKE_BIN/git" <<'EOF_FAKE_GIT'
#!/usr/bin/env bash
set -euo pipefail

STATE_FILE="${EASY_NODE_SELF_UPDATE_STATE_FILE:?}"
CAPTURE_FILE="${EASY_NODE_SELF_UPDATE_CAPTURE_FILE:?}"

args=("$@")
if [[ "${args[0]:-}" == "-C" ]]; then
  args=("${args[@]:2}")
fi
printf '%s\n' "${args[*]}" >>"$CAPTURE_FILE"

# shellcheck source=/dev/null
source "$STATE_FILE"

save_state() {
  cat >"$STATE_FILE" <<EOF_STATE
LOCAL_SHA=$LOCAL_SHA
REMOTE_SHA=$REMOTE_SHA
BRANCH=$BRANCH
DIRTY=$DIRTY
EOF_STATE
}

cmd="${args[0]:-}"
case "$cmd" in
  rev-parse)
    sub="${args[1]:-}"
    case "$sub" in
      --is-inside-work-tree)
        echo "true"
        ;;
      HEAD)
        echo "$LOCAL_SHA"
        ;;
      "origin/$BRANCH")
        echo "$REMOTE_SHA"
        ;;
      *)
        exit 1
        ;;
    esac
    ;;
  remote)
    if [[ "${args[1]:-}" == "get-url" && "${args[2]:-}" == "origin" ]]; then
      echo "https://example.invalid/repo.git"
      exit 0
    fi
    exit 1
    ;;
  symbolic-ref)
    echo "$BRANCH"
    ;;
  status)
    if [[ "$DIRTY" == "1" ]]; then
      echo " M scripts/easy_node.sh"
    fi
    ;;
  fetch)
    exit 0
    ;;
  merge-base)
    echo "$LOCAL_SHA"
    ;;
  merge)
    if [[ "${args[1]:-}" == "--ff-only" ]]; then
      LOCAL_SHA="$REMOTE_SHA"
      save_state
      exit 0
    fi
    exit 1
    ;;
  *)
    exit 1
    ;;
esac
EOF_FAKE_GIT
chmod +x "$FAKE_BIN/git"

echo "[self-update] manual fast-forward update applies"
MANUAL_LOG="$TMP_DIR/manual.log"
PATH="$FAKE_BIN:$PATH" \
EASY_NODE_SELF_UPDATE_STATE_FILE="$STATE_FILE" \
EASY_NODE_SELF_UPDATE_CAPTURE_FILE="$CAPTURE_FILE" \
bash ./scripts/easy_node.sh self-update --show-status 1 >"$MANUAL_LOG" 2>&1

if ! rg -q 'self-update: updated' "$MANUAL_LOG"; then
  echo "expected manual self-update to report updated revision"
  cat "$MANUAL_LOG"
  exit 1
fi

# shellcheck source=/dev/null
source "$STATE_FILE"
if [[ "$LOCAL_SHA" != "$REMOTE_SHA" ]]; then
  echo "expected manual self-update to fast-forward local sha to remote sha"
  cat "$STATE_FILE"
  exit 1
fi

echo "[self-update] auto-update triggers one-time reexec on configured command"
write_state \
  "3333333333333333333333333333333333333333" \
  "4444444444444444444444444444444444444444" \
  "main" \
  "0"
: >"$CAPTURE_FILE"
AUTO_LOG="$TMP_DIR/auto.log"
set +e
PATH="$FAKE_BIN:$PATH" \
EASY_NODE_SELF_UPDATE_STATE_FILE="$STATE_FILE" \
EASY_NODE_SELF_UPDATE_CAPTURE_FILE="$CAPTURE_FILE" \
EASY_NODE_AUTO_UPDATE=1 \
EASY_NODE_AUTO_UPDATE_COMMANDS=noop \
bash ./scripts/easy_node.sh noop >"$AUTO_LOG" 2>&1
auto_rc=$?
set -e

if [[ $auto_rc -ne 2 ]]; then
  echo "expected noop command to exit 2 after auto-update reexec path (got rc=$auto_rc)"
  cat "$AUTO_LOG"
  exit 1
fi
if ! rg -q 'auto-update: reloading command with updated code' "$AUTO_LOG"; then
  echo "expected auto-update reexec message"
  cat "$AUTO_LOG"
  exit 1
fi
if [[ "$(rg -c '^fetch ' "$CAPTURE_FILE" || true)" != "1" ]]; then
  echo "expected exactly one fetch call during auto-update reexec path"
  cat "$CAPTURE_FILE"
  exit 1
fi

# shellcheck source=/dev/null
source "$STATE_FILE"
if [[ "$LOCAL_SHA" != "$REMOTE_SHA" ]]; then
  echo "expected auto-update reexec path to fast-forward local sha to remote sha"
  cat "$STATE_FILE"
  exit 1
fi

echo "[self-update] dirty working tree is skipped by default"
write_state \
  "5555555555555555555555555555555555555555" \
  "6666666666666666666666666666666666666666" \
  "main" \
  "1"
: >"$CAPTURE_FILE"
DIRTY_LOG="$TMP_DIR/dirty.log"
PATH="$FAKE_BIN:$PATH" \
EASY_NODE_SELF_UPDATE_STATE_FILE="$STATE_FILE" \
EASY_NODE_SELF_UPDATE_CAPTURE_FILE="$CAPTURE_FILE" \
bash ./scripts/easy_node.sh self-update >"$DIRTY_LOG" 2>&1

if ! rg -q 'self-update skipped: working tree has local tracked changes' "$DIRTY_LOG"; then
  echo "expected dirty working tree skip message"
  cat "$DIRTY_LOG"
  exit 1
fi

# shellcheck source=/dev/null
source "$STATE_FILE"
if [[ "$LOCAL_SHA" == "$REMOTE_SHA" ]]; then
  echo "expected dirty working tree skip path to keep local sha unchanged"
  cat "$STATE_FILE"
  exit 1
fi

echo "easy-node self-update integration check ok"
