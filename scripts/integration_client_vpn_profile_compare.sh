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
WIN_PATH_DIR=""
cleanup() {
  rm -rf "$TMP_DIR"
  if [[ -n "$WIN_PATH_DIR" && "$WIN_PATH_DIR" == "$ROOT_DIR/.easy-node-logs/"* ]]; then
    rm -rf "$WIN_PATH_DIR"
  fi
}
trap cleanup EXIT

CAPTURE="$TMP_DIR/fake_smoke_capture.log"
COUNTER_DIR="$TMP_DIR/counters"
mkdir -p "$COUNTER_DIR"

FAKE_SMOKE="$TMP_DIR/fake_client_vpn_smoke.sh"
cat >"$FAKE_SMOKE" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${FAKE_CAPTURE_FILE:?}"

profile=""
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --path-profile)
      profile="${2:-}"
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

if [[ -z "$profile" ]]; then
  echo "fake client-vpn-smoke missing --path-profile"
  exit 2
fi
if [[ -z "$summary_json" ]]; then
  echo "fake client-vpn-smoke missing --summary-json"
  exit 2
fi

counter_file="${FAKE_COUNTER_DIR:?}/${profile}.count"
count=0
if [[ -f "$counter_file" ]]; then
  count="$(cat "$counter_file")"
fi
count=$((count + 1))
printf '%s\n' "$count" >"$counter_file"

status="pass"
stage="complete"
notes="ok"
if [[ "$profile" == "3hop" && "$count" -eq 2 ]]; then
  status="fail"
  stage="up"
  notes="simulated failure"
fi

country="US"
if [[ "$profile" == "2hop" ]]; then
  country="DE"
elif [[ "$profile" == "3hop" ]]; then
  country="NL"
fi

trust_attempted="false"
trust_retry_succeeded="false"
if [[ "$profile" == "1hop" && "$count" -eq 1 ]]; then
  trust_attempted="true"
  trust_retry_succeeded="true"
fi

mkdir -p "$(dirname "$summary_json")"
jq -n \
  --arg status "$status" \
  --arg stage "$stage" \
  --arg notes "$notes" \
  --arg ip "198.51.100.$count" \
  --arg country "$country" \
  --arg trust_attempted "$trust_attempted" \
  --arg trust_retry_succeeded "$trust_retry_succeeded" \
  '{
    version: 1,
    status: $status,
    stage: $stage,
    notes: $notes,
    outputs: {
      public_ip_result: $ip,
      country_result: $country
    },
    trust_reset: {
      attempted: ($trust_attempted == "true"),
      retry_succeeded: ($trust_retry_succeeded == "true")
    }
  }' >"$summary_json"

echo "client-vpn-smoke: status=$status stage=$stage"
echo "summary_json: $summary_json"

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 1
EOF_FAKE
chmod +x "$FAKE_SMOKE"

SUMMARY_JSON="$TMP_DIR/client_vpn_profile_compare_summary.json"
REPORT_MD="$TMP_DIR/client_vpn_profile_compare_report.md"
RUN_LOG="$TMP_DIR/client_vpn_profile_compare_run.log"
URL_USER_SECRET="profile-url-user-secret"
URL_PASS_SECRET="profile-url-pass-secret"
URL_USER_ONLY_SECRET="profile-url-user-only-secret"
QUERY_TOKEN_SECRET="profile-query-token-secret"
AUTH_TOKEN_SECRET="profile-auth-token-secret"
ADMIN_TOKEN_SECRET="profile-admin-token-secret"
FRAGMENT_TOKEN_SECRET="profile-fragment-token-secret"

echo "[client-vpn-profile-compare] script behavior"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$COUNTER_DIR" \
CLIENT_VPN_PROFILE_COMPARE_SMOKE_SCRIPT="$FAKE_SMOKE" \
./scripts/client_vpn_profile_compare.sh \
  --profiles 1hop,2hop,3hop \
  --rounds 2 \
  --pause-sec 0 \
  --subject inv-test \
  --directory-urls "https://${URL_USER_ONLY_SECRET}@dir-b:8081/feed?auth_token=${AUTH_TOKEN_SECRET},https://dir-c:8081#access_token=${FRAGMENT_TOKEN_SECRET}" \
  --bootstrap-directory "https://${URL_USER_SECRET}:${URL_PASS_SECRET}@dir-a:8081/bootstrap?token=${QUERY_TOKEN_SECRET}&ok=1" \
  --issuer-url "https://issuer-a:8082?admin_token=${ADMIN_TOKEN_SECRET}" \
  --allow-insecure-remote-http 1 \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --print-summary-json 1 >"$RUN_LOG"

if ! rg -q 'client-vpn-profile-compare: status=warn' "$RUN_LOG"; then
  echo "expected warn status from client-vpn profile compare run"
  cat "$RUN_LOG"
  exit 1
fi
if [[ ! -f "$SUMMARY_JSON" || ! -f "$REPORT_MD" ]]; then
  echo "expected runner artifacts were not created"
  ls -la "$TMP_DIR"
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .summary.runs_total == 6
  and .summary.runs_fail == 1
  and .decision.recommended_default_profile == "2hop"
  and .decision.experimental_non_default_profiles == ["1hop"]
  and .inputs.allow_insecure_remote_http == true
  and ([.profiles[] | select(.profile == "1hop")][0].trust_reset_attempts == 1)
' "$SUMMARY_JSON" >/dev/null; then
  echo "runner summary json missing expected fields"
  cat "$SUMMARY_JSON"
  exit 1
fi
for leaked in "$URL_USER_SECRET" "$URL_PASS_SECRET" "$URL_USER_ONLY_SECRET" "$QUERY_TOKEN_SECRET" "$AUTH_TOKEN_SECRET" "$ADMIN_TOKEN_SECRET" "$FRAGMENT_TOKEN_SECRET" "inv-test"; do
  for artifact in "$SUMMARY_JSON" "$REPORT_MD" "$RUN_LOG"; do
    if grep -F -- "$leaked" "$artifact" >/dev/null; then
      echo "sensitive profile-compare value leaked into artifact: $artifact"
      echo "leaked marker: $leaked"
      cat "$artifact"
      exit 1
    fi
  done
done
if ! jq -e '
  .command as $command
  | ($command | contains("https://\\[redacted\\]@dir-a:8081"))
  and ($command | contains("https://\\[redacted\\]@dir-b:8081"))
  and ($command | contains("token=\\[redacted\\]"))
  and ($command | contains("auth_token=\\[redacted\\]"))
  and ($command | contains("admin_token=\\[redacted\\]"))
  and ($command | contains("access_token=\\[redacted\\]"))
' "$SUMMARY_JSON" >/dev/null; then
  echo "runner summary command did not redact URL credentials/query secrets"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '
  .inputs as $inputs
  | .runs as $runs
  | ($inputs.bootstrap_directory | contains("https://[redacted]@dir-a:8081"))
  and ($inputs.bootstrap_directory | contains("token=[redacted]"))
  and ($inputs.directory_urls | contains("auth_token=[redacted]"))
  and ($inputs.directory_urls | contains("access_token=[redacted]"))
  and ($inputs.directory_urls | contains("https://dir-c:8081"))
  and ($inputs.issuer_url | contains("admin_token=[redacted]"))
  and ([
    $runs[].command
    | contains("https://\\[redacted\\]@dir-a:8081")
      and contains("https://\\[redacted\\]@dir-b:8081")
      and contains("token=\\[redacted\\]")
      and contains("auth_token=\\[redacted\\]")
      and contains("admin_token=\\[redacted\\]")
      and contains("access_token=\\[redacted\\]")
    ] | all)
' "$SUMMARY_JSON" >/dev/null; then
  echo "runner summary inputs/runs did not redact URL credentials/query secrets"
  cat "$SUMMARY_JSON"
  exit 1
fi

if command -v wslpath >/dev/null 2>&1; then
  WIN_PATH_DIR="$ROOT_DIR/.easy-node-logs/client_vpn_profile_compare_windows_path_test_$$"
  WIN_SUMMARY_UNIX="$WIN_PATH_DIR/client_vpn_profile_compare_windows_summary.json"
  WIN_REPORT_UNIX="$WIN_PATH_DIR/client_vpn_profile_compare_windows_report.md"
  WIN_LOG="$TMP_DIR/client_vpn_profile_compare_windows.log"
  mkdir -p "$WIN_PATH_DIR"

  echo "[client-vpn-profile-compare] Windows absolute output paths normalize under WSL"
  FAKE_CAPTURE_FILE="$CAPTURE" \
  FAKE_COUNTER_DIR="$COUNTER_DIR" \
  CLIENT_VPN_PROFILE_COMPARE_SMOKE_SCRIPT="$FAKE_SMOKE" \
  ./scripts/client_vpn_profile_compare.sh \
    --profiles 2hop \
    --rounds 1 \
    --pause-sec 0 \
    --subject inv-test \
    --bootstrap-directory https://dir-a:8081 \
    --summary-json "$(wslpath -w "$WIN_SUMMARY_UNIX")" \
    --report-md "$(wslpath -w "$WIN_REPORT_UNIX")" \
    --print-summary-json 1 >"$WIN_LOG"

  if [[ ! -f "$WIN_SUMMARY_UNIX" || ! -f "$WIN_REPORT_UNIX" ]]; then
    echo "Windows absolute paths were not normalized for client-vpn-profile-compare outputs"
    ls -la "$WIN_PATH_DIR"
    cat "$WIN_LOG"
    exit 1
  fi
  if find "$ROOT_DIR" -maxdepth 1 \( -name 'C*client_vpn_profile_compare_windows_summary.json' -o -name 'C*client_vpn_profile_compare_windows_report.md' \) | rg -q .; then
    echo "client-vpn-profile-compare created repo-local artifacts from Windows absolute paths"
    find "$ROOT_DIR" -maxdepth 1 \( -name 'C*client_vpn_profile_compare_windows_summary.json' -o -name 'C*client_vpn_profile_compare_windows_report.md' \)
    exit 1
  fi
fi

PLACEHOLDER_SUMMARY_JSON="$TMP_DIR/client_vpn_profile_compare_placeholder_summary.json"
PLACEHOLDER_REPORT_MD="$TMP_DIR/client_vpn_profile_compare_placeholder_report.md"
PLACEHOLDER_LOG="$TMP_DIR/client_vpn_profile_compare_placeholder.log"

echo "[client-vpn-profile-compare] command placeholders survive redaction"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$COUNTER_DIR" \
CLIENT_VPN_PROFILE_COMPARE_SMOKE_SCRIPT="$FAKE_SMOKE" \
./scripts/client_vpn_profile_compare.sh \
  --profiles 2hop \
  --rounds 1 \
  --pause-sec 0 \
  --subject INVITE_KEY \
  --anon-cred ANON_CRED \
  --bootstrap-directory https://dir-a:8081 \
  --summary-json "$PLACEHOLDER_SUMMARY_JSON" \
  --report-md "$PLACEHOLDER_REPORT_MD" \
  --print-summary-json 1 >"$PLACEHOLDER_LOG"

if ! jq -e '
  (.command | contains("--subject INVITE_KEY"))
  and (.command | contains("--anon-cred ANON_CRED"))
  and .inputs.subject == "INVITE_KEY"
  and .inputs.anon_cred_present == true
' "$PLACEHOLDER_SUMMARY_JSON" >/dev/null; then
  echo "runner summary command did not preserve safe subject/credential placeholders"
  cat "$PLACEHOLDER_SUMMARY_JSON"
  exit 1
fi
if rg -q -- '--subject \[redacted\]|--anon-cred \[redacted\]' "$PLACEHOLDER_SUMMARY_JSON" "$PLACEHOLDER_REPORT_MD" "$PLACEHOLDER_LOG"; then
  echo "runner artifacts redacted safe placeholders"
  cat "$PLACEHOLDER_SUMMARY_JSON"
  exit 1
fi

for expected in '--path-profile 1hop' '--path-profile 2hop' '--path-profile 3hop' '--allow-insecure-remote-http 1' '--record-result 0' '--manual-validation-report 0' '--incident-snapshot-on-fail 0'; do
  if ! rg -q -- "$expected" "$CAPTURE"; then
    echo "runner did not forward expected smoke arg: $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

SKIP_SUMMARY_JSON="$TMP_DIR/client_vpn_profile_compare_skip_summary.json"
SKIP_REPORT_MD="$TMP_DIR/client_vpn_profile_compare_skip_report.md"

echo "[client-vpn-profile-compare] strict-profile skip policy"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$COUNTER_DIR" \
CLIENT_VPN_PROFILE_COMPARE_SMOKE_SCRIPT="$FAKE_SMOKE" \
./scripts/client_vpn_profile_compare.sh \
  --profiles 1hop,2hop \
  --rounds 1 \
  --pause-sec 0 \
  --subject inv-test \
  --bootstrap-directory https://dir-a:8081 \
  --beta-profile 1 \
  --prod-profile 0 \
  --summary-json "$SKIP_SUMMARY_JSON" \
  --report-md "$SKIP_REPORT_MD" \
  --print-summary-json 0 >/dev/null

if ! jq -e '
  .summary.runs_skipped == 1
  and ([.profiles[] | select(.profile == "1hop")][0].runs_skipped == 1)
' "$SKIP_SUMMARY_JSON" >/dev/null; then
  echo "strict-profile skip policy summary did not match expectations"
  cat "$SKIP_SUMMARY_JSON"
  exit 1
fi

FORWARD_CAPTURE="$TMP_DIR/forward_capture.log"
FAKE_FORWARD="$TMP_DIR/fake_client_vpn_profile_compare_forward.sh"
cat >"$FAKE_FORWARD" <<'EOF_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf 'client-vpn-profile-compare %s\n' "$*" >>"${FORWARD_CAPTURE_FILE:?}"
EOF_FORWARD
chmod +x "$FAKE_FORWARD"

: >"$FORWARD_CAPTURE"

echo "[client-vpn-profile-compare] easy_node forwarding"
FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
CLIENT_VPN_PROFILE_COMPARE_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh client-vpn-profile-compare \
  --profiles 1hop,2hop \
  --rounds 2 \
  --allow-insecure-remote-http 1 \
  --summary-json /tmp/client_vpn_profile_compare_test.json \
  --print-summary-json 1

forward_line="$(rg '^client-vpn-profile-compare ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing easy_node forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
for expected in '--profiles 1hop,2hop' '--rounds 2' '--allow-insecure-remote-http 1' '--summary-json /tmp/client_vpn_profile_compare_test.json' '--print-summary-json 1'; do
  if ! grep -F -- "$expected" <<<"$forward_line" >/dev/null; then
    echo "easy_node forwarding missing: $expected"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
done

echo "client vpn profile compare integration check ok"
