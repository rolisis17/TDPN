#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod sed grep cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_DEFAULT_GATE_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_default_gate_run.sh}"
EASY_NODE_SCRIPT_UNDER_TEST="${EASY_NODE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi
if [[ ! -x "$EASY_NODE_SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable easy_node script under test: $EASY_NODE_SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

SIGNOFF_CAPTURE="$TMP_DIR/signoff_capture.tsv"
CURL_URL_CAPTURE="$TMP_DIR/curl_urls.tsv"
WRAPPER_CAPTURE="$TMP_DIR/wrapper_capture.tsv"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local message="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "$message"
    echo "expected to contain: $needle"
    echo "actual: $haystack"
    exit 1
  fi
}

assert_file_contains() {
  local file_path="$1"
  local pattern="$2"
  local message="$3"
  if ! grep -F -- "$pattern" "$file_path" >/dev/null 2>&1; then
    echo "$message"
    cat "$file_path"
    exit 1
  fi
}

cat >"$TMP_BIN/curl" <<'EOF_FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
counter_file="${PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE:?}"
fail_attempts="${PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS:-0}"
url_capture="${PROFILE_DEFAULT_GATE_FAKE_CURL_URL_CAPTURE_FILE:-}"
url="${@: -1}"

count="0"
if [[ -f "$counter_file" ]]; then
  count="$(cat "$counter_file" 2>/dev/null || echo "0")"
fi
if ! [[ "$count" =~ ^[0-9]+$ ]]; then
  count="0"
fi
count="$((count + 1))"
printf '%s' "$count" >"$counter_file"

if [[ -n "$url_capture" ]]; then
  printf '%s\n' "$url" >>"$url_capture"
fi

if (( count <= fail_attempts )); then
  echo "simulated unreachable: $url" >&2
  exit 7
fi
exit 0
EOF_FAKE_CURL
chmod +x "$TMP_BIN/curl"

FAKE_SIGNOFF="$TMP_DIR/fake_profile_compare_campaign_signoff.sh"
cat >"$FAKE_SIGNOFF" <<'EOF_FAKE_SIGNOFF'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${PROFILE_DEFAULT_GATE_CAPTURE_FILE:?}"
{
  printf 'signoff'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"

summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#--summary-json=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_SUMMARY'
{"status":"ok","rc":0}
EOF_SUMMARY
fi

exit "${PROFILE_DEFAULT_GATE_FAKE_SIGNOFF_RC:-0}"
EOF_FAKE_SIGNOFF
chmod +x "$FAKE_SIGNOFF"

FAKE_WRAPPER="$TMP_DIR/fake_profile_default_gate_wrapper.sh"
cat >"$FAKE_WRAPPER" <<'EOF_FAKE_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${PROFILE_DEFAULT_GATE_WRAPPER_CAPTURE_FILE:?}"
{
  printf 'wrapper'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
EOF_FAKE_WRAPPER
chmod +x "$FAKE_WRAPPER"

echo "[profile-default-gate-run] success path waits/retries endpoints and forwards signoff defaults"
: >"$SIGNOFF_CAPTURE"
: >"$CURL_URL_CAPTURE"
SUCCESS_LOG="$TMP_DIR/profile_default_gate_run_success.log"
SUCCESS_COUNTER="$TMP_DIR/curl_counter_success.txt"
SUCCESS_SUMMARY="$TMP_DIR/profile_default_gate_run_success_summary.json"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$SUCCESS_COUNTER" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=2 \
PROFILE_DEFAULT_GATE_FAKE_CURL_URL_CAPTURE_FILE="$CURL_URL_CAPTURE" \
CAMPAIGN_SUBJECT="inv-env-success" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --directory-b "http://dir-b.test:19081" \
  --endpoint-wait-timeout-sec 6 \
  --endpoint-wait-interval-sec 1 \
  --endpoint-connect-timeout-sec 1 \
  --summary-json "$SUCCESS_SUMMARY" \
  --custom-flag "custom value" >"$SUCCESS_LOG" 2>&1
success_rc=$?
set -e
if [[ "$success_rc" -ne 0 ]]; then
  echo "expected success path rc=0, got rc=$success_rc"
  cat "$SUCCESS_LOG"
  exit 1
fi
if [[ ! -f "$SUCCESS_SUMMARY" ]]; then
  echo "expected success summary JSON artifact to be created"
  cat "$SUCCESS_LOG"
  exit 1
fi
success_counter="$(cat "$SUCCESS_COUNTER" 2>/dev/null || echo "0")"
if ! [[ "$success_counter" =~ ^[0-9]+$ ]] || (( success_counter < 3 )); then
  echo "expected endpoint wait retry attempts (counter >= 3), got: $success_counter"
  cat "$SUCCESS_LOG"
  exit 1
fi
assert_file_contains "$SUCCESS_LOG" "wait-retry label=directory_a" "missing directory_a retry status line"
assert_file_contains "$SUCCESS_LOG" "status=ok rc=0 summary_json=$SUCCESS_SUMMARY" "missing success summary status line"

success_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
if [[ -z "$success_line" ]]; then
  echo "missing captured signoff invocation in success path"
  cat "$SUCCESS_LOG"
  exit 1
fi
success_line_sp="${success_line//$'\t'/ }"
assert_contains "$success_line_sp" "--campaign-subject inv-env-success" "missing forwarded subject fallback"
assert_contains "$success_line_sp" "--campaign-directory-urls http://dir-a.test:8081,http://dir-b.test:19081" "missing forwarded directory urls"
assert_contains "$success_line_sp" "--campaign-bootstrap-directory http://dir-a.test:8081" "missing forwarded bootstrap directory"
assert_contains "$success_line_sp" "--refresh-campaign 1" "missing default refresh forwarding"
assert_contains "$success_line_sp" "--campaign-execution-mode docker" "missing docker execution mode default"
assert_contains "$success_line_sp" "--campaign-start-local-stack 0" "missing start-local-stack default"
assert_contains "$success_line_sp" "--fail-on-no-go 0" "missing optional fail-on-no-go default"
assert_contains "$success_line_sp" "--custom-flag custom value" "missing passthrough forwarding"
assert_contains "$success_line_sp" "--summary-json $SUCCESS_SUMMARY" "missing explicit summary-json forwarding"

echo "[profile-default-gate-run] env file subject fallback forwards campaign subject"
: >"$SIGNOFF_CAPTURE"
FILE_FALLBACK_LOG="$TMP_DIR/profile_default_gate_run_file_subject.log"
FILE_FALLBACK_ENV="$TMP_DIR/profile_default_gate_run.env.easy.client"
cat >"$FILE_FALLBACK_ENV" <<'EOF_FILE_FALLBACK_ENV'
CAMPAIGN_SUBJECT=inv-file-campaign-subject
INVITE_KEY=inv-file-invite-key
EOF_FILE_FALLBACK_ENV
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_file_subject.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
PROFILE_DEFAULT_GATE_RUN_ENV_CLIENT_FILE="$FILE_FALLBACK_ENV" \
CAMPAIGN_SUBJECT="" \
INVITE_KEY="" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" >"$FILE_FALLBACK_LOG" 2>&1
file_fallback_rc=$?
set -e
if [[ "$file_fallback_rc" -ne 0 ]]; then
  echo "expected file-fallback path rc=0, got rc=$file_fallback_rc"
  cat "$FILE_FALLBACK_LOG"
  exit 1
fi
file_fallback_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
if [[ -z "$file_fallback_line" ]]; then
  echo "missing captured signoff invocation in file-fallback path"
  cat "$FILE_FALLBACK_LOG"
  exit 1
fi
file_fallback_line_sp="${file_fallback_line//$'\t'/ }"
assert_contains "$file_fallback_line_sp" "--campaign-subject inv-file-campaign-subject" "missing forwarded file-derived campaign subject"
assert_file_contains "$FILE_FALLBACK_LOG" "subject_source=file:CAMPAIGN_SUBJECT" "missing file-derived subject source marker"

echo "[profile-default-gate-run] missing subject fails clearly"
: >"$SIGNOFF_CAPTURE"
MISSING_SUBJECT_LOG="$TMP_DIR/profile_default_gate_run_missing_subject.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_missing_subject.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
PROFILE_DEFAULT_GATE_RUN_ENV_CLIENT_FILE="$TMP_DIR/profile_default_gate_run_no_file_fallback.env" \
CAMPAIGN_SUBJECT="" \
INVITE_KEY="" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" >"$MISSING_SUBJECT_LOG" 2>&1
missing_subject_rc=$?
set -e
if [[ "$missing_subject_rc" -ne 2 ]]; then
  echo "expected missing subject path rc=2, got rc=$missing_subject_rc"
  cat "$MISSING_SUBJECT_LOG"
  exit 1
fi
assert_file_contains "$MISSING_SUBJECT_LOG" "missing invite key subject" "missing clear missing-subject error text"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "missing-subject path should not invoke signoff"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-run] unreachable directory endpoint fails before signoff"
: >"$SIGNOFF_CAPTURE"
UNREACHABLE_LOG="$TMP_DIR/profile_default_gate_run_unreachable.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_unreachable.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=99 \
CAMPAIGN_SUBJECT="inv-env-unreachable" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --endpoint-wait-timeout-sec 2 \
  --endpoint-wait-interval-sec 1 \
  --endpoint-connect-timeout-sec 1 >"$UNREACHABLE_LOG" 2>&1
unreachable_rc=$?
set -e
if [[ "$unreachable_rc" -eq 0 ]]; then
  echo "expected unreachable endpoint path to fail"
  cat "$UNREACHABLE_LOG"
  exit 1
fi
assert_file_contains "$UNREACHABLE_LOG" "unreachable directory endpoint (directory_a)" "missing clear unreachable-endpoint error text"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "unreachable-endpoint path should not invoke signoff"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-run] easy_node wrapper command presence and forwarding"
if ! grep -F -- "profile-default-gate-run" "$EASY_NODE_SCRIPT_UNDER_TEST" >/dev/null 2>&1; then
  echo "missing profile-default-gate-run command text in easy_node wrapper"
  exit 1
fi

: >"$WRAPPER_CAPTURE"
EASY_NODE_FORWARD_LOG="$TMP_DIR/easy_node_profile_default_gate_run_forward.log"
PROFILE_DEFAULT_GATE_WRAPPER_CAPTURE_FILE="$WRAPPER_CAPTURE" \
PROFILE_DEFAULT_GATE_RUN_SCRIPT="$FAKE_WRAPPER" \
bash "$EASY_NODE_SCRIPT_UNDER_TEST" profile-default-gate-run \
  --host-a "wrapper-a.test" \
  --host-b "wrapper-b.test" \
  --subject "inv-wrapper" \
  --summary-json "$TMP_DIR/easy_node_wrapper_summary.json" \
  --omega "9 value" >"$EASY_NODE_FORWARD_LOG" 2>&1

wrapper_line="$(sed -n '1p' "$WRAPPER_CAPTURE" || true)"
if [[ -z "$wrapper_line" ]]; then
  echo "missing easy_node wrapper forwarding capture"
  cat "$EASY_NODE_FORWARD_LOG"
  exit 1
fi
wrapper_line_sp="${wrapper_line//$'\t'/ }"
assert_contains "$wrapper_line_sp" "--host-a wrapper-a.test" "missing forwarded --host-a"
assert_contains "$wrapper_line_sp" "--host-b wrapper-b.test" "missing forwarded --host-b"
assert_contains "$wrapper_line_sp" "--subject inv-wrapper" "missing forwarded --subject"
assert_contains "$wrapper_line_sp" "--summary-json $TMP_DIR/easy_node_wrapper_summary.json" "missing forwarded --summary-json"
assert_contains "$wrapper_line_sp" "--omega 9 value" "missing forwarded passthrough args"

echo "profile default gate run integration ok"
