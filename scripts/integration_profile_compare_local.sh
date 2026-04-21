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
printf 'env container_directory_urls=%s container_issuer_url=%s container_entry_url=%s container_exit_url=%s client_inner_source=%s disable_synthetic_fallback=%s data_plane_mode=%s\n' \
  "${EASY_NODE_CLIENT_TEST_CONTAINER_DIRECTORY_URLS:-}" \
  "${EASY_NODE_CLIENT_TEST_CONTAINER_ISSUER_URL:-}" \
  "${EASY_NODE_CLIENT_TEST_CONTAINER_ENTRY_URL:-}" \
  "${EASY_NODE_CLIENT_TEST_CONTAINER_EXIT_URL:-}" \
  "${CLIENT_INNER_SOURCE:-}" \
  "${CLIENT_DISABLE_SYNTHETIC_FALLBACK:-}" \
  "${DATA_PLANE_MODE:-}" >>"${FAKE_CAPTURE_FILE:?}"
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
    policy_path_profile="2hop"
    case "$profile" in
      private)
        policy_path_profile="3hop"
        ;;
      speed-1hop)
        policy_path_profile="1hop"
        ;;
    esac

    {
      echo "2026/03/24 12:00:00 client role enabled: path_profile=${policy_path_profile} direct_exit_forced=${direct_forced}"
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
  and .summary.selection_policy.sticky_pair_sec == 300
  and .summary.selection_policy.entry_rotation_sec == 180
  and .summary.selection_policy.entry_rotation_jitter_pct == 15
  and .summary.selection_policy.exit_exploration_pct == 10
  and .summary.selection_policy.path_profile == "2hop"
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
remote_env_line="$(rg '^env ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$remote_env_line" ]]; then
  echo "missing remote env capture line"
  cat "$CAPTURE"
  exit 1
fi
for expected in 'client_inner_source=udp' 'disable_synthetic_fallback=1' 'data_plane_mode=opaque'; do
  if ! grep -F -- "$expected" <<<"$remote_env_line" >/dev/null; then
    echo "remote endpoint run missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

PRIVATE_DEFAULT_SUMMARY_JSON="$TMP_DIR/profile_compare_private_default_summary.json"
PRIVATE_DEFAULT_REPORT_MD="$TMP_DIR/profile_compare_private_default_report.md"
PRIVATE_DEFAULT_RUN_LOG="$TMP_DIR/profile_compare_private_default_run.log"

echo "[profile-compare-local] private default selection policy fallback"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles private \
  --rounds 1 \
  --execution-mode local \
  --directory-urls http://dir-private:8081 \
  --issuer-url http://issuer-private:8082 \
  --entry-url http://entry-private:8083 \
  --exit-url http://exit-private:8084 \
  --summary-json "$PRIVATE_DEFAULT_SUMMARY_JSON" \
  --report-md "$PRIVATE_DEFAULT_REPORT_MD" \
  --print-summary-json 0 >"$PRIVATE_DEFAULT_RUN_LOG"

if ! jq -e '
  .status == "pass"
  and .summary.selection_policy.sticky_pair_sec == 420
  and .summary.selection_policy.entry_rotation_sec == 240
  and .summary.selection_policy.entry_rotation_jitter_pct == 10
  and .summary.selection_policy.exit_exploration_pct == 5
  and .summary.selection_policy.path_profile == "3hop"
' "$PRIVATE_DEFAULT_SUMMARY_JSON" >/dev/null; then
  echo "private summary json missing expected selection policy defaults"
  cat "$PRIVATE_DEFAULT_SUMMARY_JSON"
  exit 1
fi

SPEED_1HOP_DEFAULT_SUMMARY_JSON="$TMP_DIR/profile_compare_speed_1hop_default_summary.json"
SPEED_1HOP_DEFAULT_REPORT_MD="$TMP_DIR/profile_compare_speed_1hop_default_report.md"
SPEED_1HOP_DEFAULT_RUN_LOG="$TMP_DIR/profile_compare_speed_1hop_default_run.log"

echo "[profile-compare-local] speed-1hop default selection policy fallback"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles speed-1hop \
  --rounds 1 \
  --execution-mode local \
  --directory-urls http://dir-speed-1hop:8081 \
  --issuer-url http://issuer-speed-1hop:8082 \
  --entry-url http://entry-speed-1hop:8083 \
  --exit-url http://exit-speed-1hop:8084 \
  --summary-json "$SPEED_1HOP_DEFAULT_SUMMARY_JSON" \
  --report-md "$SPEED_1HOP_DEFAULT_REPORT_MD" \
  --print-summary-json 0 >"$SPEED_1HOP_DEFAULT_RUN_LOG"

if ! jq -e '
  .status == "pass"
  and .summary.selection_policy.sticky_pair_sec == 300
  and .summary.selection_policy.entry_rotation_sec == 120
  and .summary.selection_policy.entry_rotation_jitter_pct == 20
  and .summary.selection_policy.exit_exploration_pct == 20
  and .summary.selection_policy.path_profile == "1hop"
' "$SPEED_1HOP_DEFAULT_SUMMARY_JSON" >/dev/null; then
  echo "speed-1hop summary json missing expected selection policy defaults"
  cat "$SPEED_1HOP_DEFAULT_SUMMARY_JSON"
  exit 1
fi

LOOPBACK_SUMMARY_JSON="$TMP_DIR/profile_compare_loopback_summary.json"
LOOPBACK_REPORT_MD="$TMP_DIR/profile_compare_loopback_report.md"
LOOPBACK_RUN_LOG="$TMP_DIR/profile_compare_loopback_run.log"
: >"$CAPTURE"

echo "[profile-compare-local] loopback endpoints keep transport defaults unchanged"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode local \
  --directory-urls http://127.0.0.1:18081 \
  --issuer-url http://127.0.0.1:18082 \
  --entry-url http://127.0.0.1:18083 \
  --exit-url http://127.0.0.1:18084 \
  --summary-json "$LOOPBACK_SUMMARY_JSON" \
  --report-md "$LOOPBACK_REPORT_MD" \
  --print-summary-json 0 >"$LOOPBACK_RUN_LOG"

if ! jq -e '
  .status == "pass"
  and .inputs.explicit_remote_endpoints == false
  and (.summary.transport_mismatch_failures_total | type == "number")
  and (.summary.token_proof_invalid_failures_total | type == "number")
  and (.summary.unknown_exit_failures_total | type == "number")
  and (.summary.directory_trust_failures_total | type == "number")
  and ([.profiles[] | select(.profile == "balanced")][0].avg_transport_mismatch_failures | type == "number")
  and ([.profiles[] | select(.profile == "balanced")][0].avg_token_proof_invalid_failures | type == "number")
  and ([.profiles[] | select(.profile == "balanced")][0].avg_unknown_exit_failures | type == "number")
  and ([.profiles[] | select(.profile == "balanced")][0].avg_directory_trust_failures | type == "number")
  and ([.runs[] | select(.profile == "balanced")][0].transport_mismatch_failures | type == "number")
  and ([.runs[] | select(.profile == "balanced")][0].token_proof_invalid_failures | type == "number")
  and ([.runs[] | select(.profile == "balanced")][0].unknown_exit_failures | type == "number")
  and ([.runs[] | select(.profile == "balanced")][0].directory_trust_failures | type == "number")
' "$LOOPBACK_SUMMARY_JSON" >/dev/null; then
  echo "loopback summary did not preserve explicit_remote_endpoints=false"
  cat "$LOOPBACK_SUMMARY_JSON"
  exit 1
fi
loopback_env_line="$(rg '^env ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$loopback_env_line" ]]; then
  echo "missing loopback env capture line"
  cat "$CAPTURE"
  exit 1
fi
for expected in 'client_inner_source=' 'disable_synthetic_fallback=' 'data_plane_mode='; do
  if ! grep -F -- "$expected" <<<"$loopback_env_line" >/dev/null; then
    echo "loopback run missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done
if grep -F -- 'client_inner_source=udp' <<<"$loopback_env_line" >/dev/null; then
  echo "loopback run unexpectedly forced udp inner source"
  cat "$CAPTURE"
  exit 1
fi
if grep -F -- 'disable_synthetic_fallback=1' <<<"$loopback_env_line" >/dev/null; then
  echo "loopback run unexpectedly forced synthetic fallback disable"
  cat "$CAPTURE"
  exit 1
fi
if grep -F -- 'data_plane_mode=opaque' <<<"$loopback_env_line" >/dev/null; then
  echo "loopback run unexpectedly forced opaque data plane mode"
  cat "$CAPTURE"
  exit 1
fi

OVERRIDE_SUMMARY_JSON="$TMP_DIR/profile_compare_override_summary.json"
OVERRIDE_REPORT_MD="$TMP_DIR/profile_compare_override_report.md"
OVERRIDE_RUN_LOG="$TMP_DIR/profile_compare_override_run.log"
: >"$CAPTURE"

echo "[profile-compare-local] explicit user transport env overrides are preserved"
CLIENT_INNER_SOURCE=tcp \
CLIENT_DISABLE_SYNTHETIC_FALLBACK=0 \
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode local \
  --directory-urls http://dir-b:8081 \
  --issuer-url http://issuer-b:8082 \
  --entry-url http://entry-b:8083 \
  --exit-url http://exit-b:8084 \
  --summary-json "$OVERRIDE_SUMMARY_JSON" \
  --report-md "$OVERRIDE_REPORT_MD" \
  --print-summary-json 0 >"$OVERRIDE_RUN_LOG"

override_env_line="$(rg '^env ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$override_env_line" ]]; then
  echo "missing override env capture line"
  cat "$CAPTURE"
  exit 1
fi
for expected in 'client_inner_source=tcp' 'disable_synthetic_fallback=0' 'data_plane_mode=opaque'; do
  if ! grep -F -- "$expected" <<<"$override_env_line" >/dev/null; then
    echo "override run missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

DOCKER_SUMMARY_JSON="$TMP_DIR/profile_compare_docker_summary.json"
DOCKER_REPORT_MD="$TMP_DIR/profile_compare_docker_report.md"
DOCKER_RUN_LOG="$TMP_DIR/profile_compare_docker_run.log"
: >"$CAPTURE"

echo "[profile-compare-local] docker loopback endpoint rewrite"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode docker \
  --directory-urls http://127.0.0.1:18081,http://localhost:28081 \
  --issuer-url http://127.0.0.1:18082 \
  --entry-url http://localhost:18083 \
  --exit-url http://127.0.0.1:18084 \
  --summary-json "$DOCKER_SUMMARY_JSON" \
  --report-md "$DOCKER_REPORT_MD" \
  --print-summary-json 0 >"$DOCKER_RUN_LOG"

if ! jq -e '
  .status == "pass"
  and .inputs.execution_mode == "docker"
  and .inputs.docker_host_alias == "host.docker.internal"
' "$DOCKER_SUMMARY_JSON" >/dev/null; then
  echo "docker rewrite run summary missing expected fields"
  cat "$DOCKER_RUN_LOG"
  cat "$DOCKER_SUMMARY_JSON"
  exit 1
fi

docker_env_line="$(rg '^env container_directory_urls=' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$docker_env_line" ]]; then
  echo "missing docker env rewrite capture line"
  cat "$CAPTURE"
  exit 1
fi
for expected in \
  'container_directory_urls=http://host.docker.internal:18081,http://host.docker.internal:28081' \
  'container_issuer_url=http://host.docker.internal:18082' \
  'container_entry_url=http://host.docker.internal:18083' \
  'container_exit_url=http://host.docker.internal:18084'
do
  if ! grep -F -- "$expected" <<<"$docker_env_line" >/dev/null; then
    echo "docker env rewrite capture missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

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
