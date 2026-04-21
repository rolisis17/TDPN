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

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local message="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "$message"
    echo "did not expect to contain: $needle"
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

assert_file_not_contains() {
  local file_path="$1"
  local pattern="$2"
  local message="$3"
  if grep -F -- "$pattern" "$file_path" >/dev/null 2>&1; then
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
  printf '\tenv_CAMPAIGN_SUBJECT=%s' "${CAMPAIGN_SUBJECT-}"
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
  printf '\tenv_CAMPAIGN_SUBJECT=%s' "${CAMPAIGN_SUBJECT-}"
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
  --directory-b "https://dir-b.test:19081" \
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
assert_file_contains "$SUCCESS_LOG" "wait-attempt label=directory_a phase=probe-start" "missing directory_a probe-start progress marker"
assert_file_contains "$SUCCESS_LOG" "wait-next label=directory_a" "missing directory_a next-attempt progress marker"
assert_file_contains "$SUCCESS_LOG" "status=ok rc=0 summary_json=$SUCCESS_SUMMARY" "missing success summary status line"

success_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
if [[ -z "$success_line" ]]; then
  echo "missing captured signoff invocation in success path"
  cat "$SUCCESS_LOG"
  exit 1
fi
success_line_sp="${success_line//$'\t'/ }"
assert_contains "$success_line_sp" "env_CAMPAIGN_SUBJECT=inv-env-success" "missing signoff env CAMPAIGN_SUBJECT marker"
assert_not_contains "$success_line_sp" "--campaign-subject inv-env-success" "unexpected forwarded subject credential arg"
assert_not_contains "$success_line_sp" "--subject inv-env-success" "unexpected forwarded --subject credential arg"
assert_not_contains "$success_line_sp" "--key inv-env-success" "unexpected forwarded --key credential arg"
assert_not_contains "$success_line_sp" "--invite-key inv-env-success" "unexpected forwarded --invite-key credential arg"
assert_contains "$success_line_sp" "--campaign-directory-urls https://dir-a.test:8081,https://dir-b.test:19081" "missing forwarded directory urls"
assert_contains "$success_line_sp" "--campaign-bootstrap-directory https://dir-a.test:8081" "missing forwarded bootstrap directory"
assert_contains "$success_line_sp" "--refresh-campaign 1" "missing default refresh forwarding"
assert_contains "$success_line_sp" "--campaign-execution-mode docker" "missing docker execution mode default"
assert_contains "$success_line_sp" "--campaign-start-local-stack 0" "missing start-local-stack default"
assert_contains "$success_line_sp" "--fail-on-no-go 0" "missing optional fail-on-no-go default"
assert_contains "$success_line_sp" "--campaign-timeout-sec 2400" "missing default campaign timeout forwarding"
assert_contains "$success_line_sp" "--require-selection-policy-present 1" "missing default require-selection-policy-present forwarding"
assert_contains "$success_line_sp" "--require-selection-policy-valid 1" "missing default require-selection-policy-valid forwarding"
assert_contains "$success_line_sp" "--custom-flag custom value" "missing passthrough forwarding"
assert_contains "$success_line_sp" "--summary-json $SUCCESS_SUMMARY" "missing explicit summary-json forwarding"
assert_file_contains "$SUCCESS_LOG" "campaign_timeout_sec=2400" "missing campaign-timeout start marker"
assert_file_contains "$SUCCESS_LOG" "campaign-visibility expected_duration_sec=2400" "missing campaign visibility duration marker"
assert_file_contains "$SUCCESS_LOG" "signoff-startup-hint campaign_timeout_sec=2400" "missing signoff startup hint marker"
assert_file_contains "$SUCCESS_LOG" "progress_reports_dir=$ROOT_DIR/.easy-node-logs" "missing campaign visibility reports-dir marker"
assert_file_contains "$SUCCESS_LOG" "progress_summary_json=$SUCCESS_SUMMARY" "missing campaign visibility summary-json marker"
assert_file_contains "$SUCCESS_LOG" "signoff-heartbeat interval_sec=60" "missing signoff heartbeat marker"
assert_file_contains "$SUCCESS_LOG" "signoff-progress elapsed_sec=0 state=campaign_start_pending" "missing immediate signoff progress marker"
assert_file_contains "$SUCCESS_LOG" "signoff-finish rc=0" "missing signoff completion marker"

echo "[profile-default-gate-run] endpoint-wait-timeout-sec=0 is unbounded (no immediate timeout)"
: >"$SIGNOFF_CAPTURE"
: >"$CURL_URL_CAPTURE"
UNBOUNDED_LOG="$TMP_DIR/profile_default_gate_run_unbounded_timeout.log"
UNBOUNDED_COUNTER="$TMP_DIR/curl_counter_unbounded.txt"
UNBOUNDED_SUMMARY="$TMP_DIR/profile_default_gate_run_unbounded_timeout_summary.json"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$UNBOUNDED_COUNTER" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=2 \
PROFILE_DEFAULT_GATE_FAKE_CURL_URL_CAPTURE_FILE="$CURL_URL_CAPTURE" \
CAMPAIGN_SUBJECT="inv-env-unbounded-timeout" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --endpoint-wait-timeout-sec 0 \
  --endpoint-wait-interval-sec 1 \
  --endpoint-connect-timeout-sec 1 \
  --summary-json "$UNBOUNDED_SUMMARY" >"$UNBOUNDED_LOG" 2>&1
unbounded_rc=$?
set -e
if [[ "$unbounded_rc" -ne 0 ]]; then
  echo "expected unbounded-timeout path rc=0, got rc=$unbounded_rc"
  cat "$UNBOUNDED_LOG"
  exit 1
fi
if [[ ! -f "$UNBOUNDED_SUMMARY" ]]; then
  echo "expected unbounded-timeout summary JSON artifact to be created"
  cat "$UNBOUNDED_LOG"
  exit 1
fi
unbounded_counter="$(cat "$UNBOUNDED_COUNTER" 2>/dev/null || echo "0")"
if ! [[ "$unbounded_counter" =~ ^[0-9]+$ ]] || (( unbounded_counter < 3 )); then
  echo "expected unbounded-timeout path to keep retrying until success (counter >= 3), got: $unbounded_counter"
  cat "$UNBOUNDED_LOG"
  exit 1
fi
assert_file_contains "$UNBOUNDED_LOG" "wait-start label=directory_a" "missing unbounded-timeout wait-start marker"
assert_file_contains "$UNBOUNDED_LOG" "timeout_sec=0" "missing unbounded-timeout timeout marker"
assert_file_contains "$UNBOUNDED_LOG" "remaining_sec=unbounded" "missing unbounded-timeout unbounded remaining marker"
unbounded_signoff_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
if [[ -z "$unbounded_signoff_line" ]]; then
  echo "expected unbounded-timeout path to invoke signoff after retries"
  cat "$UNBOUNDED_LOG"
  exit 1
fi

echo "[profile-default-gate-run] wrapper-level selection-policy opt-out forwards explicit zeros"
: >"$SIGNOFF_CAPTURE"
SELECTION_POLICY_OPT_OUT_LOG="$TMP_DIR/profile_default_gate_run_selection_policy_opt_out.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_selection_policy_opt_out.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="inv-selection-policy-opt-out" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --require-selection-policy-present 0 \
  --require-selection-policy-valid=0 >"$SELECTION_POLICY_OPT_OUT_LOG" 2>&1
selection_policy_opt_out_rc=$?
set -e
if [[ "$selection_policy_opt_out_rc" -ne 0 ]]; then
  echo "expected selection-policy opt-out path rc=0, got rc=$selection_policy_opt_out_rc"
  cat "$SELECTION_POLICY_OPT_OUT_LOG"
  exit 1
fi
selection_policy_opt_out_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
if [[ -z "$selection_policy_opt_out_line" ]]; then
  echo "missing captured signoff invocation in selection-policy opt-out path"
  cat "$SELECTION_POLICY_OPT_OUT_LOG"
  exit 1
fi
selection_policy_opt_out_line_sp="${selection_policy_opt_out_line//$'\t'/ }"
assert_contains "$selection_policy_opt_out_line_sp" "--require-selection-policy-present 0" "missing opt-out require-selection-policy-present forwarding"
assert_contains "$selection_policy_opt_out_line_sp" "--require-selection-policy-valid 0" "missing opt-out require-selection-policy-valid forwarding"
assert_not_contains "$selection_policy_opt_out_line_sp" "--require-selection-policy-present 1" "unexpected default require-selection-policy-present forwarding during opt-out"
assert_not_contains "$selection_policy_opt_out_line_sp" "--require-selection-policy-valid 1" "unexpected default require-selection-policy-valid forwarding during opt-out"

echo "[profile-default-gate-run] CLI heartbeat override supersedes env default"
: >"$SIGNOFF_CAPTURE"
HEARTBEAT_OVERRIDE_LOG="$TMP_DIR/profile_default_gate_run_heartbeat_override.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_heartbeat_override.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
PROFILE_DEFAULT_GATE_RUN_HEARTBEAT_INTERVAL_SEC=99 \
CAMPAIGN_SUBJECT="inv-heartbeat-override" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --heartbeat-interval-sec=7 >"$HEARTBEAT_OVERRIDE_LOG" 2>&1
heartbeat_override_rc=$?
set -e
if [[ "$heartbeat_override_rc" -ne 0 ]]; then
  echo "expected heartbeat override path rc=0, got rc=$heartbeat_override_rc"
  cat "$HEARTBEAT_OVERRIDE_LOG"
  exit 1
fi
assert_file_contains "$HEARTBEAT_OVERRIDE_LOG" "signoff-heartbeat interval_sec=7" "missing explicit CLI heartbeat override marker"

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
assert_contains "$file_fallback_line_sp" "env_CAMPAIGN_SUBJECT=inv-file-campaign-subject" "missing forwarded file-derived campaign subject env marker"
assert_not_contains "$file_fallback_line_sp" "--campaign-subject inv-file-campaign-subject" "unexpected forwarded file-derived campaign subject arg"
assert_file_contains "$FILE_FALLBACK_LOG" "subject_source=file:CAMPAIGN_SUBJECT" "missing file-derived subject source marker"

echo "[profile-default-gate-run] explicit --key alias forwards campaign subject"
: >"$SIGNOFF_CAPTURE"
KEY_ALIAS_LOG="$TMP_DIR/profile_default_gate_run_key_alias.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_key_alias.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="" \
INVITE_KEY="" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --key "inv-key-alias" >"$KEY_ALIAS_LOG" 2>&1
key_alias_rc=$?
set -e
if [[ "$key_alias_rc" -ne 0 ]]; then
  echo "expected explicit --key alias path rc=0, got rc=$key_alias_rc"
  cat "$KEY_ALIAS_LOG"
  exit 1
fi
key_alias_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
if [[ -z "$key_alias_line" ]]; then
  echo "missing captured signoff invocation in --key alias path"
  cat "$KEY_ALIAS_LOG"
  exit 1
fi
key_alias_line_sp="${key_alias_line//$'\t'/ }"
assert_contains "$key_alias_line_sp" "env_CAMPAIGN_SUBJECT=inv-key-alias" "missing forwarded --key alias subject env marker"
assert_not_contains "$key_alias_line_sp" "--campaign-subject inv-key-alias" "unexpected forwarded --key alias subject arg"
assert_not_contains "$key_alias_line_sp" "--key inv-key-alias" "unexpected forwarded --key alias credential arg"
assert_file_contains "$KEY_ALIAS_LOG" "subject_source=explicit:--key" "missing explicit --key subject source marker"

echo "[profile-default-gate-run] explicit --invite-key alias forwards campaign subject"
: >"$SIGNOFF_CAPTURE"
INVITE_KEY_ALIAS_LOG="$TMP_DIR/profile_default_gate_run_invite_key_alias.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_invite_key_alias.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="" \
INVITE_KEY="" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --invite-key "inv-invite-key-alias" >"$INVITE_KEY_ALIAS_LOG" 2>&1
invite_key_alias_rc=$?
set -e
if [[ "$invite_key_alias_rc" -ne 0 ]]; then
  echo "expected explicit --invite-key alias path rc=0, got rc=$invite_key_alias_rc"
  cat "$INVITE_KEY_ALIAS_LOG"
  exit 1
fi
invite_key_alias_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
if [[ -z "$invite_key_alias_line" ]]; then
  echo "missing captured signoff invocation in --invite-key alias path"
  cat "$INVITE_KEY_ALIAS_LOG"
  exit 1
fi
invite_key_alias_line_sp="${invite_key_alias_line//$'\t'/ }"
assert_contains "$invite_key_alias_line_sp" "env_CAMPAIGN_SUBJECT=inv-invite-key-alias" "missing forwarded --invite-key alias subject env marker"
assert_not_contains "$invite_key_alias_line_sp" "--campaign-subject inv-invite-key-alias" "unexpected forwarded --invite-key alias subject arg"
assert_not_contains "$invite_key_alias_line_sp" "--invite-key inv-invite-key-alias" "unexpected forwarded --invite-key alias credential arg"
assert_file_contains "$INVITE_KEY_ALIAS_LOG" "subject_source=explicit:--invite-key" "missing explicit --invite-key subject source marker"

echo "[profile-default-gate-run] equals-form credential flag rejects flag-like value"
: >"$SIGNOFF_CAPTURE"
EQUALS_SUBJECT_VALUE_REJECT_LOG="$TMP_DIR/profile_default_gate_run_equals_subject_value_reject.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_equals_subject_value_reject.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="" \
INVITE_KEY="" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --key=--oops >"$EQUALS_SUBJECT_VALUE_REJECT_LOG" 2>&1
equals_subject_value_reject_rc=$?
set -e
if [[ "$equals_subject_value_reject_rc" -ne 2 ]]; then
  echo "expected equals-form credential value rejection path rc=2, got rc=$equals_subject_value_reject_rc"
  cat "$EQUALS_SUBJECT_VALUE_REJECT_LOG"
  exit 1
fi
assert_file_contains "$EQUALS_SUBJECT_VALUE_REJECT_LOG" "--key requires a value" "missing equals-form --key value rejection text"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "equals-form credential value rejection path should not invoke signoff"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-run] conflicting subject aliases fail clearly"
: >"$SIGNOFF_CAPTURE"
SUBJECT_CONFLICT_LOG="$TMP_DIR/profile_default_gate_run_subject_conflict.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_subject_conflict.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="" \
INVITE_KEY="" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --campaign-subject "inv-campaign-subject" \
  --key "inv-key-mismatch" >"$SUBJECT_CONFLICT_LOG" 2>&1
subject_conflict_rc=$?
set -e
if [[ "$subject_conflict_rc" -ne 2 ]]; then
  echo "expected conflicting subject aliases path rc=2, got rc=$subject_conflict_rc"
  cat "$SUBJECT_CONFLICT_LOG"
  exit 1
fi
assert_file_contains "$SUBJECT_CONFLICT_LOG" "conflicting subject values" "missing conflicting subject alias rejection text"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "conflicting subject aliases path should not invoke signoff"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-run] passthrough --key suppresses duplicate subject injection"
: >"$SIGNOFF_CAPTURE"
PASSTHROUGH_KEY_LOG="$TMP_DIR/profile_default_gate_run_passthrough_key.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_passthrough_key.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="inv-env-no-dup" \
INVITE_KEY="" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  -- --key "inv-passthrough-key" >"$PASSTHROUGH_KEY_LOG" 2>&1
passthrough_key_rc=$?
set -e
if [[ "$passthrough_key_rc" -ne 0 ]]; then
  echo "expected passthrough --key path rc=0, got rc=$passthrough_key_rc"
  cat "$PASSTHROUGH_KEY_LOG"
  exit 1
fi
passthrough_key_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
if [[ -z "$passthrough_key_line" ]]; then
  echo "missing captured signoff invocation in passthrough --key path"
  cat "$PASSTHROUGH_KEY_LOG"
  exit 1
fi
passthrough_key_line_sp="${passthrough_key_line//$'\t'/ }"
assert_contains "$passthrough_key_line_sp" "env_CAMPAIGN_SUBJECT=inv-passthrough-key" "missing passthrough --key subject env forwarding"
assert_not_contains "$passthrough_key_line_sp" "--key inv-passthrough-key" "unexpected passthrough --key credential arg forwarding"
assert_not_contains "$passthrough_key_line_sp" "--campaign-subject inv-env-no-dup" "unexpected duplicate --campaign-subject injection when passthrough --key exists"

echo "[profile-default-gate-run] anon-cred passthrough forwards anon credential without subject args"
: >"$SIGNOFF_CAPTURE"
ANON_CRED_LOG="$TMP_DIR/profile_default_gate_run_anon_cred.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_anon_cred.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="" \
INVITE_KEY="" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  -- --campaign-anon-cred "anon-campaign-token" >"$ANON_CRED_LOG" 2>&1
anon_cred_rc=$?
set -e
if [[ "$anon_cred_rc" -ne 0 ]]; then
  echo "expected anon-cred passthrough path rc=0, got rc=$anon_cred_rc"
  cat "$ANON_CRED_LOG"
  exit 1
fi
anon_cred_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
if [[ -z "$anon_cred_line" ]]; then
  echo "missing captured signoff invocation in anon-cred passthrough path"
  cat "$ANON_CRED_LOG"
  exit 1
fi
anon_cred_line_sp="${anon_cred_line//$'\t'/ }"
assert_contains "$anon_cred_line_sp" "--campaign-anon-cred anon-campaign-token" "missing forwarded --campaign-anon-cred credential"
assert_not_contains "$anon_cred_line_sp" "--campaign-subject" "unexpected subject credential forwarding in anon-cred mode"
assert_not_contains "$anon_cred_line_sp" "--subject" "unexpected --subject forwarding in anon-cred mode"
assert_not_contains "$anon_cred_line_sp" "--key" "unexpected --key forwarding in anon-cred mode"
assert_not_contains "$anon_cred_line_sp" "--invite-key" "unexpected --invite-key forwarding in anon-cred mode"
assert_file_contains "$ANON_CRED_LOG" "subject_source=passthrough:--campaign-anon-cred" "missing anon-cred subject source marker"

echo "[profile-default-gate-run] anon-cred and subject combination fails clearly"
: >"$SIGNOFF_CAPTURE"
ANON_SUBJECT_CONFLICT_LOG="$TMP_DIR/profile_default_gate_run_anon_subject_conflict.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_anon_subject_conflict.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="" \
INVITE_KEY="" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --subject "inv-subject-conflict" \
  -- --anon-cred "anon-conflict-token" >"$ANON_SUBJECT_CONFLICT_LOG" 2>&1
anon_subject_conflict_rc=$?
set -e
if [[ "$anon_subject_conflict_rc" -ne 2 ]]; then
  echo "expected anon-cred+subject conflict path rc=2, got rc=$anon_subject_conflict_rc"
  cat "$ANON_SUBJECT_CONFLICT_LOG"
  exit 1
fi
assert_file_contains "$ANON_SUBJECT_CONFLICT_LOG" "cannot be combined with --campaign-subject/--subject/--key/--invite-key" "missing anon-cred+subject conflict rejection text"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "anon-cred+subject conflict path should not invoke signoff"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-run] malformed campaign anon-cred value fails closed even when anon alias is valid"
: >"$SIGNOFF_CAPTURE"
ANON_MALFORMED_LOG="$TMP_DIR/profile_default_gate_run_anon_malformed.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_anon_malformed.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="" \
INVITE_KEY="" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  -- --campaign-anon-cred --oops --anon-cred "anon-valid-token" >"$ANON_MALFORMED_LOG" 2>&1
anon_malformed_rc=$?
set -e
if [[ "$anon_malformed_rc" -ne 2 ]]; then
  echo "expected malformed campaign anon-cred path rc=2, got rc=$anon_malformed_rc"
  cat "$ANON_MALFORMED_LOG"
  exit 1
fi
assert_file_contains "$ANON_MALFORMED_LOG" "--campaign-anon-cred requires a non-flag value" "missing malformed campaign anon-cred rejection text"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "malformed campaign anon-cred path should not invoke signoff"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-run] passthrough selection-policy flags suppress default injection"
: >"$SIGNOFF_CAPTURE"
PASSTHROUGH_SELECTION_POLICY_LOG="$TMP_DIR/profile_default_gate_run_passthrough_selection_policy.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_passthrough_selection_policy.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="inv-env-passthrough-selection-policy" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  -- --require-selection-policy-present 0 --require-selection-policy-valid=0 >"$PASSTHROUGH_SELECTION_POLICY_LOG" 2>&1
passthrough_selection_policy_rc=$?
set -e
if [[ "$passthrough_selection_policy_rc" -ne 0 ]]; then
  echo "expected passthrough selection-policy path rc=0, got rc=$passthrough_selection_policy_rc"
  cat "$PASSTHROUGH_SELECTION_POLICY_LOG"
  exit 1
fi
passthrough_selection_policy_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
if [[ -z "$passthrough_selection_policy_line" ]]; then
  echo "missing captured signoff invocation in passthrough selection-policy path"
  cat "$PASSTHROUGH_SELECTION_POLICY_LOG"
  exit 1
fi
passthrough_selection_policy_line_sp="${passthrough_selection_policy_line//$'\t'/ }"
assert_contains "$passthrough_selection_policy_line_sp" "--require-selection-policy-present 0" "missing passthrough require-selection-policy-present forwarding"
assert_contains "$passthrough_selection_policy_line_sp" "--require-selection-policy-valid=0" "missing passthrough equals-form require-selection-policy-valid forwarding"
assert_not_contains "$passthrough_selection_policy_line_sp" "--require-selection-policy-present 1" "unexpected default require-selection-policy-present injection with passthrough override"
assert_not_contains "$passthrough_selection_policy_line_sp" "--require-selection-policy-valid 1" "unexpected default require-selection-policy-valid injection with passthrough override"

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
assert_file_contains "$MISSING_SUBJECT_LOG" "failure_kind=missing_invite_subject_precondition" "missing stable missing-subject failure marker"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "missing-subject path should not invoke signoff"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-run] placeholder subject fails fast before endpoint wait"
: >"$SIGNOFF_CAPTURE"
PLACEHOLDER_SUBJECT_LOG="$TMP_DIR/profile_default_gate_run_placeholder_subject.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_placeholder_subject.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="" \
INVITE_KEY="" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --subject "INVITE_KEY" >"$PLACEHOLDER_SUBJECT_LOG" 2>&1
placeholder_subject_rc=$?
set -e
if [[ "$placeholder_subject_rc" -ne 2 ]]; then
  echo "expected placeholder-subject path rc=2, got rc=$placeholder_subject_rc"
  cat "$PLACEHOLDER_SUBJECT_LOG"
  exit 1
fi
assert_file_contains "$PLACEHOLDER_SUBJECT_LOG" "failure_kind=missing_invite_subject_precondition reason=placeholder_subject" "missing placeholder-subject failure marker"
assert_file_contains "$PLACEHOLDER_SUBJECT_LOG" "invite key subject appears to be placeholder text" "missing placeholder-subject rejection text"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "placeholder-subject path should not invoke signoff"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-run] placeholder host fails fast before endpoint wait"
: >"$SIGNOFF_CAPTURE"
PLACEHOLDER_HOST_LOG="$TMP_DIR/profile_default_gate_run_placeholder_host.log"
PLACEHOLDER_HOST_COUNTER="$TMP_DIR/curl_counter_placeholder_host.txt"
rm -f "$PLACEHOLDER_HOST_COUNTER"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$PLACEHOLDER_HOST_COUNTER" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="inv-env-placeholder-host" \
"$SCRIPT_UNDER_TEST" \
  --host-a "A_HOST" \
  --host-b "dir-b.test" >"$PLACEHOLDER_HOST_LOG" 2>&1
placeholder_host_rc=$?
set -e
if [[ "$placeholder_host_rc" -ne 2 ]]; then
  echo "expected placeholder-host path rc=2, got rc=$placeholder_host_rc"
  cat "$PLACEHOLDER_HOST_LOG"
  exit 1
fi
assert_file_contains "$PLACEHOLDER_HOST_LOG" "failure_kind=unreachable_directory_endpoint label=directory_a reason=placeholder_directory_endpoint_input" "missing placeholder-host failure marker"
assert_file_contains "$PLACEHOLDER_HOST_LOG" "directory_a endpoint appears to be placeholder text" "missing placeholder-host rejection text"
assert_file_contains "$PLACEHOLDER_HOST_LOG" "profile-default-gate-live --host-a <host-a> --host-b <host-b> --campaign-subject <invite-key>" "missing placeholder-host operator command hint"
if grep -F -- "wait-start label=directory_a" "$PLACEHOLDER_HOST_LOG" >/dev/null 2>&1; then
  echo "placeholder-host path should fail before endpoint wait-start logging"
  cat "$PLACEHOLDER_HOST_LOG"
  exit 1
fi
if [[ -f "$PLACEHOLDER_HOST_COUNTER" ]]; then
  placeholder_host_attempts="$(cat "$PLACEHOLDER_HOST_COUNTER" 2>/dev/null || echo "0")"
  if ! [[ "$placeholder_host_attempts" =~ ^[0-9]+$ ]]; then
    echo "placeholder-host curl counter must be numeric, got: $placeholder_host_attempts"
    cat "$PLACEHOLDER_HOST_LOG"
    exit 1
  fi
  if (( placeholder_host_attempts > 0 )); then
    echo "placeholder-host path should fail before endpoint curl probes (attempts=$placeholder_host_attempts)"
    cat "$PLACEHOLDER_HOST_LOG"
    exit 1
  fi
fi
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "placeholder-host path should not invoke signoff"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-run] campaign-directory-urls rejects 3-value input"
: >"$SIGNOFF_CAPTURE"
THREE_URLS_LOG="$TMP_DIR/profile_default_gate_run_three_urls.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_three_urls.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="inv-env-three-urls" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --campaign-directory-urls "dir-a.test,dir-b.test,dir-c.test" >"$THREE_URLS_LOG" 2>&1
three_urls_rc=$?
set -e
if [[ "$three_urls_rc" -ne 2 ]]; then
  echo "expected three-value campaign-directory-urls path rc=2, got rc=$three_urls_rc"
  cat "$THREE_URLS_LOG"
  exit 1
fi
assert_file_contains "$THREE_URLS_LOG" "--campaign-directory-urls must include exactly two values (A,B)" "missing clear 3-value campaign-directory-urls rejection text"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "three-value campaign-directory-urls path should not invoke signoff"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-run] remote HTTP probe path fails closed by default"
: >"$SIGNOFF_CAPTURE"
REMOTE_HTTP_PROBE_LOG="$TMP_DIR/profile_default_gate_run_remote_http_probe.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_remote_http_probe.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="inv-env-remote-http-probe" \
"$SCRIPT_UNDER_TEST" \
  --directory-a "http://dir-a.test:8081" \
  --host-b "dir-b.test" >"$REMOTE_HTTP_PROBE_LOG" 2>&1
remote_http_probe_rc=$?
set -e
if [[ "$remote_http_probe_rc" -eq 0 ]]; then
  echo "expected default remote-http probe path to fail closed"
  cat "$REMOTE_HTTP_PROBE_LOG"
  exit 1
fi
assert_file_contains "$REMOTE_HTTP_PROBE_LOG" "wait-reject label=directory_a" "missing remote-http default rejection marker"
assert_file_contains "$REMOTE_HTTP_PROBE_LOG" "error=remote_http_disallowed" "missing remote-http fail-closed error marker"
assert_file_contains "$REMOTE_HTTP_PROBE_LOG" "pass --allow-remote-http-probe 1" "missing remote-http explicit opt-in hint"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "default remote-http probe path should not invoke signoff"
  cat "$REMOTE_HTTP_PROBE_LOG"
  exit 1
fi

echo "[profile-default-gate-run] invalid --allow-remote-http-probe value fails closed"
: >"$SIGNOFF_CAPTURE"
REMOTE_HTTP_PROBE_INVALID_VALUE_LOG="$TMP_DIR/profile_default_gate_run_remote_http_probe_invalid_value.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_remote_http_probe_invalid_value.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="inv-env-remote-http-probe-invalid" \
"$SCRIPT_UNDER_TEST" \
  --directory-a "http://dir-a.test:8081" \
  --host-b "dir-b.test" \
  --allow-remote-http-probe 2 >"$REMOTE_HTTP_PROBE_INVALID_VALUE_LOG" 2>&1
remote_http_probe_invalid_value_rc=$?
set -e
if [[ "$remote_http_probe_invalid_value_rc" -ne 2 ]]; then
  echo "expected invalid --allow-remote-http-probe path rc=2, got rc=$remote_http_probe_invalid_value_rc"
  cat "$REMOTE_HTTP_PROBE_INVALID_VALUE_LOG"
  exit 1
fi
assert_file_contains "$REMOTE_HTTP_PROBE_INVALID_VALUE_LOG" "--allow-remote-http-probe must be 0 or 1" "missing invalid --allow-remote-http-probe value error"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "invalid --allow-remote-http-probe value path should not invoke signoff"
  cat "$REMOTE_HTTP_PROBE_INVALID_VALUE_LOG"
  exit 1
fi

echo "[profile-default-gate-run] remote HTTP probe path proceeds with explicit opt-in"
: >"$SIGNOFF_CAPTURE"
REMOTE_HTTP_PROBE_OPT_IN_LOG="$TMP_DIR/profile_default_gate_run_remote_http_probe_opt_in.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_remote_http_probe_opt_in.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="inv-env-remote-http-probe-opt-in" \
"$SCRIPT_UNDER_TEST" \
  --directory-a "http://dir-a.test:8081" \
  --host-b "dir-b.test" \
  --allow-remote-http-probe 1 >"$REMOTE_HTTP_PROBE_OPT_IN_LOG" 2>&1
remote_http_probe_opt_in_rc=$?
set -e
if [[ "$remote_http_probe_opt_in_rc" -ne 0 ]]; then
  echo "expected remote-http opt-in probe path rc=0, got rc=$remote_http_probe_opt_in_rc"
  cat "$REMOTE_HTTP_PROBE_OPT_IN_LOG"
  exit 1
fi
assert_file_contains "$REMOTE_HTTP_PROBE_OPT_IN_LOG" "wait-pass label=directory_a" "missing remote-http opt-in directory_a wait-pass marker"
assert_file_not_contains "$REMOTE_HTTP_PROBE_OPT_IN_LOG" "error=remote_http_disallowed" "remote-http opt-in path unexpectedly emitted remote_http_disallowed"
remote_http_probe_opt_in_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
if [[ -z "$remote_http_probe_opt_in_line" ]]; then
  echo "remote-http opt-in probe path should invoke signoff"
  cat "$REMOTE_HTTP_PROBE_OPT_IN_LOG"
  exit 1
fi
remote_http_probe_opt_in_line_sp="${remote_http_probe_opt_in_line//$'\t'/ }"
assert_contains "$remote_http_probe_opt_in_line_sp" "--campaign-directory-urls http://dir-a.test:8081,https://dir-b.test:8081" "missing forwarded mixed-scheme campaign-directory-urls in remote-http opt-in path"

echo "[profile-default-gate-run] invalid --allow-insecure-probe value fails closed"
: >"$SIGNOFF_CAPTURE"
INSECURE_PROBE_INVALID_VALUE_LOG="$TMP_DIR/profile_default_gate_run_insecure_probe_invalid_value.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_insecure_probe_invalid_value.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="inv-env-insecure-probe-invalid" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --allow-insecure-probe 2 >"$INSECURE_PROBE_INVALID_VALUE_LOG" 2>&1
insecure_probe_invalid_value_rc=$?
set -e
if [[ "$insecure_probe_invalid_value_rc" -ne 2 ]]; then
  echo "expected invalid --allow-insecure-probe path rc=2, got rc=$insecure_probe_invalid_value_rc"
  cat "$INSECURE_PROBE_INVALID_VALUE_LOG"
  exit 1
fi
assert_file_contains "$INSECURE_PROBE_INVALID_VALUE_LOG" "--allow-insecure-probe must be 0 or 1" "missing invalid --allow-insecure-probe value error"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "invalid --allow-insecure-probe value path should not invoke signoff"
  cat "$INSECURE_PROBE_INVALID_VALUE_LOG"
  exit 1
fi

echo "[profile-default-gate-run] invalid --allow-insecure-probe=<value> fails closed"
: >"$SIGNOFF_CAPTURE"
INSECURE_PROBE_EQUALS_INVALID_VALUE_LOG="$TMP_DIR/profile_default_gate_run_insecure_probe_equals_invalid_value.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_insecure_probe_equals_invalid_value.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="inv-env-insecure-probe-equals-invalid" \
"$SCRIPT_UNDER_TEST" \
  --host-a "dir-a.test" \
  --host-b "dir-b.test" \
  --allow-insecure-probe=2 >"$INSECURE_PROBE_EQUALS_INVALID_VALUE_LOG" 2>&1
insecure_probe_equals_invalid_value_rc=$?
set -e
if [[ "$insecure_probe_equals_invalid_value_rc" -ne 2 ]]; then
  echo "expected invalid --allow-insecure-probe=<value> path rc=2, got rc=$insecure_probe_equals_invalid_value_rc"
  cat "$INSECURE_PROBE_EQUALS_INVALID_VALUE_LOG"
  exit 1
fi
assert_file_contains "$INSECURE_PROBE_EQUALS_INVALID_VALUE_LOG" "--allow-insecure-probe must be 0 or 1" "missing invalid --allow-insecure-probe=<value> error"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "invalid --allow-insecure-probe=<value> path should not invoke signoff"
  cat "$INSECURE_PROBE_EQUALS_INVALID_VALUE_LOG"
  exit 1
fi

echo "[profile-default-gate-run] --allow-insecure-probe=1 is accepted and reaches signoff"
: >"$SIGNOFF_CAPTURE"
INSECURE_PROBE_EQUALS_VALID_LOG="$TMP_DIR/profile_default_gate_run_insecure_probe_equals_valid.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_insecure_probe_equals_valid.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="inv-env-insecure-probe-equals-valid" \
"$SCRIPT_UNDER_TEST" \
  --host-a "localhost" \
  --host-b "127.0.0.1" \
  --allow-insecure-probe=1 >"$INSECURE_PROBE_EQUALS_VALID_LOG" 2>&1
insecure_probe_equals_valid_rc=$?
set -e
if [[ "$insecure_probe_equals_valid_rc" -ne 0 ]]; then
  echo "expected --allow-insecure-probe=1 path rc=0, got rc=$insecure_probe_equals_valid_rc"
  cat "$INSECURE_PROBE_EQUALS_VALID_LOG"
  exit 1
fi
insecure_probe_equals_valid_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
if [[ -z "$insecure_probe_equals_valid_line" ]]; then
  echo "--allow-insecure-probe=1 path should invoke signoff"
  cat "$INSECURE_PROBE_EQUALS_VALID_LOG"
  exit 1
fi

echo "[profile-default-gate-run] malformed endpoint URL with missing host fails closed before signoff"
: >"$SIGNOFF_CAPTURE"
MALFORMED_ENDPOINT_LOG="$TMP_DIR/profile_default_gate_run_malformed_endpoint.log"
set +e
PATH="$TMP_BIN:$PATH" \
PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PROFILE_DEFAULT_GATE_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_DEFAULT_GATE_FAKE_CURL_COUNTER_FILE="$TMP_DIR/curl_counter_malformed_endpoint.txt" \
PROFILE_DEFAULT_GATE_FAKE_CURL_FAIL_ATTEMPTS=0 \
CAMPAIGN_SUBJECT="inv-env-malformed-endpoint" \
"$SCRIPT_UNDER_TEST" \
  --directory-a "http:///missing-host" \
  --host-b "dir-b.test" >"$MALFORMED_ENDPOINT_LOG" 2>&1
malformed_endpoint_rc=$?
set -e
if [[ "$malformed_endpoint_rc" -eq 0 ]]; then
  echo "expected malformed endpoint URL path to fail closed"
  cat "$MALFORMED_ENDPOINT_LOG"
  exit 1
fi
assert_file_contains "$MALFORMED_ENDPOINT_LOG" "error=invalid_endpoint_url_missing_host" "missing malformed endpoint rejection marker"
assert_file_contains "$MALFORMED_ENDPOINT_LOG" "invalid endpoint URL missing host" "missing malformed endpoint failure reason"
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "malformed endpoint path should not invoke signoff"
  cat "$MALFORMED_ENDPOINT_LOG"
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
assert_file_contains "$UNREACHABLE_LOG" "failure_kind=unreachable_directory_endpoint label=directory_a" "missing stable unreachable-endpoint failure marker"
assert_file_contains "$UNREACHABLE_LOG" "hint: verify endpoint path and host reachability" "missing unreachable-endpoint host/path hint"
assert_file_contains "$UNREACHABLE_LOG" "hint: if startup is slow, increase --endpoint-wait-timeout-sec" "missing unreachable-endpoint timeout tuning hint"
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

echo "[profile-default-gate-live] easy_node env wrapper command presence and forwarding"
if ! grep -F -- "profile-default-gate-live" "$EASY_NODE_SCRIPT_UNDER_TEST" >/dev/null 2>&1; then
  echo "missing profile-default-gate-live command text in easy_node wrapper"
  exit 1
fi

: >"$WRAPPER_CAPTURE"
EASY_NODE_LIVE_FORWARD_LOG="$TMP_DIR/easy_node_profile_default_gate_live_forward.log"
PROFILE_DEFAULT_GATE_WRAPPER_CAPTURE_FILE="$WRAPPER_CAPTURE" \
PROFILE_DEFAULT_GATE_RUN_SCRIPT="$FAKE_WRAPPER" \
A_HOST="wrapper-live-a.test" \
B_HOST="wrapper-live-b.test" \
INVITE_KEY="inv-live-wrapper" \
bash "$EASY_NODE_SCRIPT_UNDER_TEST" profile-default-gate-live \
  --reports-dir "$TMP_DIR/live_reports" \
  --campaign-timeout-sec 777 \
  --summary-json "$TMP_DIR/easy_node_live_wrapper_summary.json" \
  --omega "10 value" >"$EASY_NODE_LIVE_FORWARD_LOG" 2>&1

live_wrapper_line="$(sed -n '1p' "$WRAPPER_CAPTURE" || true)"
if [[ -z "$live_wrapper_line" ]]; then
  echo "missing easy_node live wrapper forwarding capture"
  cat "$EASY_NODE_LIVE_FORWARD_LOG"
  exit 1
fi
live_wrapper_line_sp="${live_wrapper_line//$'\t'/ }"
assert_contains "$live_wrapper_line_sp" "--directory-a http://wrapper-live-a.test:8081" "missing live forwarded --directory-a"
assert_contains "$live_wrapper_line_sp" "--directory-b http://wrapper-live-b.test:8081" "missing live forwarded --directory-b"
assert_contains "$live_wrapper_line_sp" "--allow-remote-http-probe 1" "missing live forwarded --allow-remote-http-probe opt-in"
assert_contains "$live_wrapper_line_sp" "--campaign-bootstrap-directory http://wrapper-live-a.test:8081" "missing live forwarded --campaign-bootstrap-directory"
assert_contains "$live_wrapper_line_sp" "--campaign-issuer-url http://wrapper-live-a.test:8082" "missing live forwarded --campaign-issuer-url"
assert_contains "$live_wrapper_line_sp" "--campaign-entry-url http://wrapper-live-a.test:8083" "missing live forwarded --campaign-entry-url"
assert_contains "$live_wrapper_line_sp" "--campaign-exit-url http://wrapper-live-a.test:8084" "missing live forwarded --campaign-exit-url"
assert_contains "$live_wrapper_line_sp" "env_CAMPAIGN_SUBJECT=inv-live-wrapper" "missing live forwarded env CAMPAIGN_SUBJECT"
assert_not_contains "$live_wrapper_line_sp" "--campaign-subject" "unexpected live forwarded --campaign-subject credential arg"
assert_not_contains "$live_wrapper_line_sp" "--subject" "unexpected live forwarded --subject credential arg"
assert_not_contains "$live_wrapper_line_sp" "--key" "unexpected live forwarded --key credential arg"
assert_not_contains "$live_wrapper_line_sp" "--invite-key" "unexpected live forwarded --invite-key credential arg"
assert_contains "$live_wrapper_line_sp" "--reports-dir $TMP_DIR/live_reports" "missing live forwarded --reports-dir"
assert_contains "$live_wrapper_line_sp" "--campaign-timeout-sec 777" "missing live forwarded --campaign-timeout-sec"
assert_contains "$live_wrapper_line_sp" "--summary-json $TMP_DIR/easy_node_live_wrapper_summary.json" "missing live forwarded --summary-json"
assert_contains "$live_wrapper_line_sp" "--print-summary-json 1" "missing live forwarded --print-summary-json"
assert_contains "$live_wrapper_line_sp" "--omega 10 value" "missing live forwarded passthrough args"

echo "[profile-default-gate-live] invalid --allow-remote-http-probe value fails closed"
: >"$WRAPPER_CAPTURE"
EASY_NODE_LIVE_INVALID_ALLOW_REMOTE_HTTP_PROBE_LOG="$TMP_DIR/easy_node_profile_default_gate_live_invalid_allow_remote_http_probe.log"
set +e
PROFILE_DEFAULT_GATE_WRAPPER_CAPTURE_FILE="$WRAPPER_CAPTURE" \
PROFILE_DEFAULT_GATE_RUN_SCRIPT="$FAKE_WRAPPER" \
bash "$EASY_NODE_SCRIPT_UNDER_TEST" profile-default-gate-live \
  --host-a "wrapper-live-a.test" \
  --host-b "wrapper-live-b.test" \
  --campaign-subject "inv-live-invalid-allow-remote-http-probe" \
  --allow-remote-http-probe 2 \
  --reports-dir "$TMP_DIR/live_reports_invalid_allow_remote_http_probe" \
  --campaign-timeout-sec 777 \
  --summary-json "$TMP_DIR/easy_node_live_wrapper_invalid_allow_remote_http_probe_summary.json" >"$EASY_NODE_LIVE_INVALID_ALLOW_REMOTE_HTTP_PROBE_LOG" 2>&1
live_invalid_allow_remote_http_probe_rc=$?
set -e
if [[ "$live_invalid_allow_remote_http_probe_rc" -ne 2 ]]; then
  echo "expected profile-default-gate-live invalid --allow-remote-http-probe path rc=2, got rc=$live_invalid_allow_remote_http_probe_rc"
  cat "$EASY_NODE_LIVE_INVALID_ALLOW_REMOTE_HTTP_PROBE_LOG"
  exit 1
fi
assert_file_contains "$EASY_NODE_LIVE_INVALID_ALLOW_REMOTE_HTTP_PROBE_LOG" "profile-default-gate-live requires --allow-remote-http-probe 0|1" "missing live invalid --allow-remote-http-probe value error"
if [[ -s "$WRAPPER_CAPTURE" ]]; then
  echo "profile-default-gate-live invalid --allow-remote-http-probe path should not invoke wrapper"
  cat "$WRAPPER_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-live] equals-form args parse and forward correctly"
: >"$WRAPPER_CAPTURE"
EASY_NODE_LIVE_EQUALS_FORWARD_LOG="$TMP_DIR/easy_node_profile_default_gate_live_equals_forward.log"
PROFILE_DEFAULT_GATE_WRAPPER_CAPTURE_FILE="$WRAPPER_CAPTURE" \
PROFILE_DEFAULT_GATE_RUN_SCRIPT="$FAKE_WRAPPER" \
bash "$EASY_NODE_SCRIPT_UNDER_TEST" profile-default-gate-live \
  --host-a=wrapper-live-eq-a.test \
  --host-b=wrapper-live-eq-b.test \
  --key=inv-live-equals-wrapper \
  --reports-dir="$TMP_DIR/live_reports_equals" \
  --campaign-timeout-sec=778 \
  --heartbeat-interval-sec=9 \
  --summary-json="$TMP_DIR/easy_node_live_wrapper_equals_summary.json" \
  --print-summary-json=0 >"$EASY_NODE_LIVE_EQUALS_FORWARD_LOG" 2>&1

live_equals_wrapper_line="$(sed -n '1p' "$WRAPPER_CAPTURE" || true)"
if [[ -z "$live_equals_wrapper_line" ]]; then
  echo "missing easy_node live equals-form wrapper forwarding capture"
  cat "$EASY_NODE_LIVE_EQUALS_FORWARD_LOG"
  exit 1
fi
live_equals_wrapper_line_sp="${live_equals_wrapper_line//$'\t'/ }"
assert_contains "$live_equals_wrapper_line_sp" "--directory-a http://wrapper-live-eq-a.test:8081" "missing equals live forwarded --directory-a"
assert_contains "$live_equals_wrapper_line_sp" "--directory-b http://wrapper-live-eq-b.test:8081" "missing equals live forwarded --directory-b"
assert_contains "$live_equals_wrapper_line_sp" "--allow-remote-http-probe 1" "missing equals live forwarded --allow-remote-http-probe opt-in"
assert_contains "$live_equals_wrapper_line_sp" "env_CAMPAIGN_SUBJECT=inv-live-equals-wrapper" "missing equals live forwarded env CAMPAIGN_SUBJECT"
assert_not_contains "$live_equals_wrapper_line_sp" "--campaign-subject" "unexpected equals live forwarded --campaign-subject credential arg"
assert_not_contains "$live_equals_wrapper_line_sp" "--subject" "unexpected equals live forwarded --subject credential arg"
assert_not_contains "$live_equals_wrapper_line_sp" "--key" "unexpected equals live forwarded --key credential arg"
assert_not_contains "$live_equals_wrapper_line_sp" "--invite-key" "unexpected equals live forwarded --invite-key credential arg"
assert_contains "$live_equals_wrapper_line_sp" "--reports-dir $TMP_DIR/live_reports_equals" "missing equals live forwarded --reports-dir"
assert_contains "$live_equals_wrapper_line_sp" "--campaign-timeout-sec 778" "missing equals live forwarded --campaign-timeout-sec"
assert_contains "$live_equals_wrapper_line_sp" "--heartbeat-interval-sec 9" "missing equals live forwarded --heartbeat-interval-sec"
assert_contains "$live_equals_wrapper_line_sp" "--summary-json $TMP_DIR/easy_node_live_wrapper_equals_summary.json" "missing equals live forwarded --summary-json"
assert_contains "$live_equals_wrapper_line_sp" "--print-summary-json 0" "missing equals live forwarded --print-summary-json"

echo "[profile-default-gate-live] explicit directory URL overrides are forwarded as-is with env subject forwarding"
: >"$WRAPPER_CAPTURE"
EASY_NODE_LIVE_DIRECTORY_URL_OVERRIDE_LOG="$TMP_DIR/easy_node_profile_default_gate_live_directory_url_override.log"
PROFILE_DEFAULT_GATE_WRAPPER_CAPTURE_FILE="$WRAPPER_CAPTURE" \
PROFILE_DEFAULT_GATE_RUN_SCRIPT="$FAKE_WRAPPER" \
bash "$EASY_NODE_SCRIPT_UNDER_TEST" profile-default-gate-live \
  --directory-a-url "https://user:pw@dir-a-override.example:18443/custom/path?token=abc#frag" \
  --directory-b-url "https://dir-b-override.example:19443/alt/path?apikey=xyz" \
  --campaign-subject "inv-live-directory-url-override" \
  --reports-dir "$TMP_DIR/live_reports_directory_url_override" \
  --campaign-timeout-sec 781 \
  --summary-json "$TMP_DIR/easy_node_live_wrapper_directory_url_override_summary.json" >"$EASY_NODE_LIVE_DIRECTORY_URL_OVERRIDE_LOG" 2>&1

live_directory_url_override_line="$(sed -n '1p' "$WRAPPER_CAPTURE" || true)"
if [[ -z "$live_directory_url_override_line" ]]; then
  echo "missing easy_node live directory-url override wrapper forwarding capture"
  cat "$EASY_NODE_LIVE_DIRECTORY_URL_OVERRIDE_LOG"
  exit 1
fi
live_directory_url_override_line_sp="${live_directory_url_override_line//$'\t'/ }"
assert_contains "$live_directory_url_override_line_sp" "env_CAMPAIGN_SUBJECT=inv-live-directory-url-override" "missing directory-url override env CAMPAIGN_SUBJECT forwarding"
assert_contains "$live_directory_url_override_line_sp" "--directory-a https://user:pw@dir-a-override.example:18443/custom/path?token=abc#frag" "missing directory-url override forwarded --directory-a"
assert_contains "$live_directory_url_override_line_sp" "--directory-b https://dir-b-override.example:19443/alt/path?apikey=xyz" "missing directory-url override forwarded --directory-b"
assert_contains "$live_directory_url_override_line_sp" "--allow-remote-http-probe 0" "missing directory-url override forwarded --allow-remote-http-probe fail-closed default"
assert_contains "$live_directory_url_override_line_sp" "--campaign-bootstrap-directory https://user:pw@dir-a-override.example:18443/custom/path?token=abc#frag" "missing directory-url override forwarded --campaign-bootstrap-directory"
assert_not_contains "$live_directory_url_override_line_sp" "--campaign-subject" "unexpected directory-url override forwarded --campaign-subject credential arg"
assert_not_contains "$live_directory_url_override_line_sp" "--subject" "unexpected directory-url override forwarded --subject credential arg"
assert_not_contains "$live_directory_url_override_line_sp" "--key" "unexpected directory-url override forwarded --key credential arg"
assert_not_contains "$live_directory_url_override_line_sp" "--invite-key" "unexpected directory-url override forwarded --invite-key credential arg"
assert_file_not_contains "$EASY_NODE_LIVE_DIRECTORY_URL_OVERRIDE_LOG" "user:pw@" "directory-url override log should redact URL userinfo"
assert_file_not_contains "$EASY_NODE_LIVE_DIRECTORY_URL_OVERRIDE_LOG" "token=abc" "directory-url override log should redact URL query token"
assert_file_not_contains "$EASY_NODE_LIVE_DIRECTORY_URL_OVERRIDE_LOG" "apikey=xyz" "directory-url override log should redact URL query api key"
assert_file_contains "$EASY_NODE_LIVE_DIRECTORY_URL_OVERRIDE_LOG" "resolved_directory_a_url: https://dir-a-override.example:18443/custom/path" "directory-url override log missing sanitized resolved directory_a URL"
assert_file_contains "$EASY_NODE_LIVE_DIRECTORY_URL_OVERRIDE_LOG" "resolved_directory_b_url: https://dir-b-override.example:19443/alt/path" "directory-url override log missing sanitized resolved directory_b URL"

echo "[profile-default-gate-live] host scheme/path/port values normalize to safe endpoint hosts"
: >"$WRAPPER_CAPTURE"
EASY_NODE_LIVE_HOST_NORM_LOG="$TMP_DIR/easy_node_profile_default_gate_live_host_norm.log"
PROFILE_DEFAULT_GATE_WRAPPER_CAPTURE_FILE="$WRAPPER_CAPTURE" \
PROFILE_DEFAULT_GATE_RUN_SCRIPT="$FAKE_WRAPPER" \
bash "$EASY_NODE_SCRIPT_UNDER_TEST" profile-default-gate-live \
  --host-a "https://wrapper-live-norm-a.test:19081/bootstrap/v1" \
  --host-b "wrapper-live-norm-b.test:29081/ignored/path" \
  --campaign-subject "inv-live-host-norm" \
  --reports-dir "$TMP_DIR/live_reports_host_norm" \
  --campaign-timeout-sec 779 \
  --summary-json "$TMP_DIR/easy_node_live_wrapper_host_norm_summary.json" >"$EASY_NODE_LIVE_HOST_NORM_LOG" 2>&1

live_host_norm_line="$(sed -n '1p' "$WRAPPER_CAPTURE" || true)"
if [[ -z "$live_host_norm_line" ]]; then
  echo "missing easy_node live host normalization wrapper forwarding capture"
  cat "$EASY_NODE_LIVE_HOST_NORM_LOG"
  exit 1
fi
live_host_norm_line_sp="${live_host_norm_line//$'\t'/ }"
assert_contains "$live_host_norm_line_sp" "--directory-a http://wrapper-live-norm-a.test:8081" "missing host-normalized live forwarded --directory-a"
assert_contains "$live_host_norm_line_sp" "--directory-b http://wrapper-live-norm-b.test:8081" "missing host-normalized live forwarded --directory-b"
assert_contains "$live_host_norm_line_sp" "--allow-remote-http-probe 1" "missing host-normalized live forwarded --allow-remote-http-probe opt-in"
assert_contains "$live_host_norm_line_sp" "--campaign-bootstrap-directory http://wrapper-live-norm-a.test:8081" "missing host-normalized live forwarded --campaign-bootstrap-directory"
assert_contains "$live_host_norm_line_sp" "--campaign-issuer-url http://wrapper-live-norm-a.test:8082" "missing host-normalized live forwarded --campaign-issuer-url"
assert_contains "$live_host_norm_line_sp" "--campaign-entry-url http://wrapper-live-norm-a.test:8083" "missing host-normalized live forwarded --campaign-entry-url"
assert_contains "$live_host_norm_line_sp" "--campaign-exit-url http://wrapper-live-norm-a.test:8084" "missing host-normalized live forwarded --campaign-exit-url"
assert_contains "$live_host_norm_line_sp" "env_CAMPAIGN_SUBJECT=inv-live-host-norm" "missing host-normalized live forwarded env CAMPAIGN_SUBJECT"
assert_not_contains "$live_host_norm_line_sp" "--campaign-subject" "unexpected host-normalized live forwarded --campaign-subject credential arg"
assert_not_contains "$live_host_norm_line_sp" "--subject" "unexpected host-normalized live forwarded --subject credential arg"
assert_not_contains "$live_host_norm_line_sp" "--key" "unexpected host-normalized live forwarded --key credential arg"
assert_not_contains "$live_host_norm_line_sp" "--invite-key" "unexpected host-normalized live forwarded --invite-key credential arg"

echo "[profile-default-gate-live] loopback HTTP endpoints do not auto-enable remote-http probe opt-in"
: >"$WRAPPER_CAPTURE"
EASY_NODE_LIVE_LOOPBACK_HTTP_LOG="$TMP_DIR/easy_node_profile_default_gate_live_loopback_http.log"
PROFILE_DEFAULT_GATE_WRAPPER_CAPTURE_FILE="$WRAPPER_CAPTURE" \
PROFILE_DEFAULT_GATE_RUN_SCRIPT="$FAKE_WRAPPER" \
bash "$EASY_NODE_SCRIPT_UNDER_TEST" profile-default-gate-live \
  --host-a "127.0.0.1" \
  --host-b "localhost" \
  --campaign-subject "inv-live-loopback-http" \
  --reports-dir "$TMP_DIR/live_reports_loopback_http" \
  --campaign-timeout-sec 779 \
  --summary-json "$TMP_DIR/easy_node_live_wrapper_loopback_http_summary.json" >"$EASY_NODE_LIVE_LOOPBACK_HTTP_LOG" 2>&1

live_loopback_http_line="$(sed -n '1p' "$WRAPPER_CAPTURE" || true)"
if [[ -z "$live_loopback_http_line" ]]; then
  echo "missing easy_node live loopback-http wrapper forwarding capture"
  cat "$EASY_NODE_LIVE_LOOPBACK_HTTP_LOG"
  exit 1
fi
live_loopback_http_line_sp="${live_loopback_http_line//$'\t'/ }"
assert_contains "$live_loopback_http_line_sp" "--directory-a http://127.0.0.1:8081" "missing loopback-http live forwarded --directory-a"
assert_contains "$live_loopback_http_line_sp" "--directory-b http://localhost:8081" "missing loopback-http live forwarded --directory-b"
assert_contains "$live_loopback_http_line_sp" "--allow-remote-http-probe 0" "missing loopback-http live forwarded --allow-remote-http-probe fail-closed default"

echo "[profile-default-gate-live] IPv6 host literals preserve address and safely drop explicit ports"
: >"$WRAPPER_CAPTURE"
EASY_NODE_LIVE_IPV6_NORM_LOG="$TMP_DIR/easy_node_profile_default_gate_live_ipv6_norm.log"
PROFILE_DEFAULT_GATE_WRAPPER_CAPTURE_FILE="$WRAPPER_CAPTURE" \
PROFILE_DEFAULT_GATE_RUN_SCRIPT="$FAKE_WRAPPER" \
bash "$EASY_NODE_SCRIPT_UNDER_TEST" profile-default-gate-live \
  --host-a "https://[2001:db8::10]:19081/bootstrap/v1" \
  --host-b "2001:db8::20" \
  --campaign-subject "inv-live-ipv6-norm" \
  --reports-dir "$TMP_DIR/live_reports_ipv6_norm" \
  --campaign-timeout-sec 780 \
  --summary-json "$TMP_DIR/easy_node_live_wrapper_ipv6_norm_summary.json" >"$EASY_NODE_LIVE_IPV6_NORM_LOG" 2>&1

live_ipv6_norm_line="$(sed -n '1p' "$WRAPPER_CAPTURE" || true)"
if [[ -z "$live_ipv6_norm_line" ]]; then
  echo "missing easy_node live IPv6 normalization wrapper forwarding capture"
  cat "$EASY_NODE_LIVE_IPV6_NORM_LOG"
  exit 1
fi
live_ipv6_norm_line_sp="${live_ipv6_norm_line//$'\t'/ }"
assert_contains "$live_ipv6_norm_line_sp" "--directory-a http://[2001:db8::10]:8081" "missing IPv6-normalized live forwarded --directory-a"
assert_contains "$live_ipv6_norm_line_sp" "--directory-b http://[2001:db8::20]:8081" "missing IPv6-normalized live forwarded --directory-b"
assert_contains "$live_ipv6_norm_line_sp" "--campaign-bootstrap-directory http://[2001:db8::10]:8081" "missing IPv6-normalized live forwarded --campaign-bootstrap-directory"
assert_contains "$live_ipv6_norm_line_sp" "--campaign-issuer-url http://[2001:db8::10]:8082" "missing IPv6-normalized live forwarded --campaign-issuer-url"
assert_contains "$live_ipv6_norm_line_sp" "--campaign-entry-url http://[2001:db8::10]:8083" "missing IPv6-normalized live forwarded --campaign-entry-url"
assert_contains "$live_ipv6_norm_line_sp" "--campaign-exit-url http://[2001:db8::10]:8084" "missing IPv6-normalized live forwarded --campaign-exit-url"
assert_contains "$live_ipv6_norm_line_sp" "env_CAMPAIGN_SUBJECT=inv-live-ipv6-norm" "missing IPv6-normalized live forwarded env CAMPAIGN_SUBJECT"
assert_not_contains "$live_ipv6_norm_line_sp" "--campaign-subject" "unexpected IPv6-normalized live forwarded --campaign-subject credential arg"
assert_not_contains "$live_ipv6_norm_line_sp" "--subject" "unexpected IPv6-normalized live forwarded --subject credential arg"
assert_not_contains "$live_ipv6_norm_line_sp" "--key" "unexpected IPv6-normalized live forwarded --key credential arg"
assert_not_contains "$live_ipv6_norm_line_sp" "--invite-key" "unexpected IPv6-normalized live forwarded --invite-key credential arg"

echo "[profile-default-gate-live] missing env/subject fails clearly"
: >"$WRAPPER_CAPTURE"
LIVE_MISSING_LOG="$TMP_DIR/easy_node_profile_default_gate_live_missing.log"
set +e
PROFILE_DEFAULT_GATE_WRAPPER_CAPTURE_FILE="$WRAPPER_CAPTURE" \
PROFILE_DEFAULT_GATE_RUN_SCRIPT="$FAKE_WRAPPER" \
A_HOST="" \
B_HOST="" \
INVITE_KEY="" \
bash "$EASY_NODE_SCRIPT_UNDER_TEST" profile-default-gate-live >"$LIVE_MISSING_LOG" 2>&1
live_missing_rc=$?
set -e
if [[ "$live_missing_rc" -ne 2 ]]; then
  echo "expected profile-default-gate-live missing-env path rc=2, got rc=$live_missing_rc"
  cat "$LIVE_MISSING_LOG"
  exit 1
fi
assert_file_contains "$LIVE_MISSING_LOG" "requires host A (set --host-a or A_HOST" "missing profile-default-gate-live missing-host-A error"
if [[ -s "$WRAPPER_CAPTURE" ]]; then
  echo "profile-default-gate-live missing-env path should not invoke wrapper"
  cat "$WRAPPER_CAPTURE"
  exit 1
fi

echo "profile default gate run integration ok"
