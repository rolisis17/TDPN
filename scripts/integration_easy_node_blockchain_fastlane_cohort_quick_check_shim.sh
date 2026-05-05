#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod awk grep sed cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${EASY_NODE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
FAKE_CHECK_SCRIPT="$TMP_DIR/prod_pilot_cohort_quick_check_fake.sh"
cat >"$FAKE_CHECK_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${EASY_NODE_COHORT_QUICK_CHECK_CAPTURE:?}"
{
  printf 'quick-check'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
EOF_FAKE
chmod +x "$FAKE_CHECK_SCRIPT"

# Recreate the historical stale dispatch form observed around blockchain-fastlane
# completion, where prod-pilot-cohort-quick-check dispatched to cohort_quick_check.
STALE_DISPATCH_SCRIPT="$TMP_DIR/easy_node_stale_dispatch.sh"
awk '
BEGIN {
  in_quick_check_case = 0
  replaced = 0
}
{
  if ($0 ~ /^[[:space:]]*prod-pilot-cohort-quick-check\)/) {
    in_quick_check_case = 1
  }
  if (in_quick_check_case == 1 && $0 ~ /prod_pilot_cohort_quick_check "\$@"/ && replaced == 0) {
    sub(/prod_pilot_cohort_quick_check/, "cohort_quick_check")
    replaced = 1
    in_quick_check_case = 0
  }
  print
}
END {
  if (replaced == 0) {
    print "failed to rewrite stale quick-check dispatch in test harness" > "/dev/stderr"
    exit 1
  }
}
' "$SCRIPT_UNDER_TEST" >"$STALE_DISPATCH_SCRIPT"
chmod +x "$STALE_DISPATCH_SCRIPT"

RUN_LOG="$TMP_DIR/stale_dispatch.log"
if ! EASY_NODE_COHORT_QUICK_CHECK_CAPTURE="$CAPTURE" \
     PROD_PILOT_COHORT_QUICK_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
     "$STALE_DISPATCH_SCRIPT" prod-pilot-cohort-quick-check --shim-smoke 1 >"$RUN_LOG" 2>&1; then
  echo "stale quick-check dispatch should succeed via shim"
  cat "$RUN_LOG"
  exit 1
fi

if grep -q 'command not found' "$RUN_LOG"; then
  echo "unexpected command-not-found after shim hardening"
  cat "$RUN_LOG"
  exit 1
fi

line="$(sed -n '1p' "$CAPTURE" || true)"
if [[ "$line" != $'quick-check\t--shim-smoke\t1' ]]; then
  echo "unexpected forwarded args for quick-check shim"
  cat "$CAPTURE"
  exit 1
fi

echo "integration_easy_node_blockchain_fastlane_cohort_quick_check_shim: PASS"
