#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq rg mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/fake_easy_calls.log"
FAKE_COUNTER_DIR="$TMP_DIR/counters"
FAKE_LOG_DIR="$TMP_DIR/client_logs"
mkdir -p "$FAKE_COUNTER_DIR" "$FAKE_LOG_DIR"

FAKE_EASY="$TMP_DIR/fake_easy_node.sh"
cat >"$FAKE_EASY" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${FAKE_CAPTURE_FILE:?}"
cmd="${1:-}"
shift || true

case "$cmd" in
  wg-only-stack-up|wg-only-stack-down)
    echo "fake $cmd ok"
    exit 0
    ;;
  client-test)
    profile=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --path-profile)
          profile="${2:-}"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done

    if [[ -z "$profile" ]]; then
      echo "fake client-test missing --path-profile"
      exit 2
    fi

    counter_file="${FAKE_COUNTER_DIR:?}/${profile}.count"
    count=0
    if [[ -f "$counter_file" ]]; then
      count="$(cat "$counter_file")"
    fi
    count=$((count + 1))
    printf '%s\n' "$count" >"$counter_file"

    client_log="${FAKE_LOG_DIR:?}/client_${profile}_${count}.log"
    direct_forced="false"
    if [[ "$profile" == "speed-1hop" ]]; then
      direct_forced="true"
    fi

    {
      echo "2026/03/24 12:00:00 client role enabled: direct_exit_forced=${direct_forced}"
      if [[ "$profile" == "speed" ]]; then
        echo "2026/03/24 12:00:01 client bootstrap retry failed: transient"
      fi
      if [[ "$profile" == "speed-1hop" ]]; then
        echo "2026/03/24 12:00:02 client direct-exit mode engaged entry=entry-local-1 exit=exit-local-1"
      fi
      echo "2026/03/24 12:00:03 client received wg-session config: key_id=test"
      echo "2026/03/24 12:00:04 client selected entry=entry-local-1 (http://entry) entry_op=op-entry exit=exit-local-1 (http://exit) exit_op=op-exit path_control=http://entry token_exp=1"
    } >"$client_log"

    echo "client selection summary: selections=1 entry_ops=1 exit_ops=1 cross_pairs=1 same_ops=0 missing_ops=0"

    if [[ "$profile" == "private" && "$count" -eq 2 ]]; then
      echo "client test: failed"
      echo "client test log: $client_log"
      exit 1
    fi

    echo "client test: ok"
    echo "client test log: $client_log"
    exit 0
    ;;
  *)
    echo "unexpected fake easy command: $cmd"
    exit 1
    ;;
esac
EOF_FAKE
chmod +x "$FAKE_EASY"

SUMMARY_JSON="$TMP_DIR/profile_compare_summary.json"
REPORT_MD="$TMP_DIR/profile_compare_report.md"
RUN_LOG="$TMP_DIR/profile_compare_run.log"

echo "[profile-compare-local] script behavior"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced,speed,private,speed-1hop \
  --rounds 2 \
  --execution-mode local \
  --directory-urls http://dir-a:8081 \
  --issuer-url http://issuer-a:8082 \
  --entry-url http://entry-a:8083 \
  --exit-url http://exit-a:8084 \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --print-summary-json 1 >"$RUN_LOG"

if ! rg -q 'profile-compare-local: status=warn' "$RUN_LOG"; then
  echo "expected warn status in profile compare output"
  cat "$RUN_LOG"
  exit 1
fi
if [[ ! -f "$SUMMARY_JSON" || ! -f "$REPORT_MD" ]]; then
  echo "expected profile compare artifacts missing"
  ls -la "$TMP_DIR"
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .summary.runs_total == 8
  and .summary.runs_executed == 8
  and .summary.runs_fail == 1
  and .decision.recommended_default_profile == "balanced"
  and ([.profiles[] | select(.profile == "speed-1hop")][0].direct_exit_forced_runs == 2)
' "$SUMMARY_JSON" >/dev/null; then
  echo "summary json missing expected fields"
  cat "$SUMMARY_JSON"
  exit 1
fi
if rg -q '^wg-only-stack-up' "$CAPTURE"; then
  echo "profile compare should not auto-start local stack when explicit endpoints are provided"
  cat "$CAPTURE"
  exit 1
fi

FORWARD_CAPTURE="$TMP_DIR/forward_capture.log"
FAKE_FORWARD="$TMP_DIR/fake_profile_compare_forward.sh"
cat >"$FAKE_FORWARD" <<'EOF_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf 'profile-compare-local %s\n' "$*" >>"${FORWARD_CAPTURE_FILE:?}"
EOF_FORWARD
chmod +x "$FAKE_FORWARD"

: >"$FORWARD_CAPTURE"

echo "[profile-compare-local] easy_node forwarding"
FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
PROFILE_COMPARE_LOCAL_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh profile-compare-local \
  --profiles balanced,speed \
  --rounds 2 \
  --summary-json /tmp/profile_compare_test.json \
  --print-summary-json 1

forward_line="$(rg '^profile-compare-local ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing easy_node forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
for expected in '--profiles balanced,speed' '--rounds 2' '--summary-json /tmp/profile_compare_test.json' '--print-summary-json 1'; do
  if ! grep -F -- "$expected" <<<"$forward_line" >/dev/null; then
    echo "easy_node forwarding missing $expected"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
done

echo "profile compare local integration check ok"
