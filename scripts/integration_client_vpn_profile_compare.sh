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

echo "[client-vpn-profile-compare] script behavior"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$COUNTER_DIR" \
CLIENT_VPN_PROFILE_COMPARE_SMOKE_SCRIPT="$FAKE_SMOKE" \
./scripts/client_vpn_profile_compare.sh \
  --profiles 1hop,2hop,3hop \
  --rounds 2 \
  --pause-sec 0 \
  --subject inv-test \
  --bootstrap-directory https://dir-a:8081 \
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
  and ([.profiles[] | select(.profile == "1hop")][0].trust_reset_attempts == 1)
' "$SUMMARY_JSON" >/dev/null; then
  echo "runner summary json missing expected fields"
  cat "$SUMMARY_JSON"
  exit 1
fi

for expected in '--path-profile 1hop' '--path-profile 2hop' '--path-profile 3hop' '--record-result 0' '--manual-validation-report 0' '--incident-snapshot-on-fail 0'; do
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
  --summary-json /tmp/client_vpn_profile_compare_test.json \
  --print-summary-json 1

forward_line="$(rg '^client-vpn-profile-compare ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing easy_node forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
for expected in '--profiles 1hop,2hop' '--rounds 2' '--summary-json /tmp/client_vpn_profile_compare_test.json' '--print-summary-json 1'; do
  if ! grep -F -- "$expected" <<<"$forward_line" >/dev/null; then
    echo "easy_node forwarding missing: $expected"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
done

echo "client vpn profile compare integration check ok"
