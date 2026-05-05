#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod grep sed cat wc; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${GPM_ENDPOINT_POSTURE_REMEDIATE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/gpm_endpoint_posture_remediate.sh}"
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

assert_file_contains() {
  local file_path="$1"
  local expected="$2"
  local message="$3"
  if ! grep -F -- "$expected" "$file_path" >/dev/null 2>&1; then
    echo "$message"
    cat "$file_path"
    exit 1
  fi
}

assert_help_includes_command_token() {
  local help_output="$1"
  local command_token="$2"

  if ! grep -Fq -- "$command_token" <<<"$help_output"; then
    echo "help output missing command token: $command_token"
    printf '%s\n' "$help_output"
    exit 1
  fi
}

assert_single_invocation() {
  local capture_file="$1"
  local count

  count="$(wc -l <"$capture_file")"
  count="${count//[[:space:]]/}"
  if [[ "$count" != "1" ]]; then
    echo "expected exactly one wrapper invocation, got $count"
    cat "$capture_file"
    exit 1
  fi
}

assert_forwarded_args() {
  local capture_file="$1"
  local expected_env_file="$2"
  local expected_summary_json="$3"
  local line
  local -a fields=()

  line="$(sed -n '1p' "$capture_file" || true)"
  if [[ -z "$line" ]]; then
    echo "missing forwarded invocation payload"
    cat "$capture_file"
    exit 1
  fi

  IFS=$'\t' read -r -a fields <<<"$line"
  if [[ "${fields[0]:-}" != "gpm_endpoint_posture_remediate" ]]; then
    echo "forwarded marker mismatch"
    echo "$line"
    exit 1
  fi

  if [[ "${#fields[@]}" -ne 11 ]]; then
    echo "unexpected forwarded arg count: expected 11 got ${#fields[@]}"
    echo "$line"
    exit 1
  fi

  if [[ "${fields[1]:-}" != "--mode" || "${fields[2]:-}" != "report" ]]; then
    echo "forwarded mode args mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "${fields[3]:-}" != "--env-file" || "${fields[4]:-}" != "$expected_env_file" ]]; then
    echo "forwarded env-file args mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "${fields[5]:-}" != "--summary-json" || "${fields[6]:-}" != "$expected_summary_json" ]]; then
    echo "forwarded summary-json args mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "${fields[7]:-}" != "--signoff-arg" || "${fields[8]:-}" != "--subject" ]]; then
    echo "forwarded first signoff-arg mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "${fields[9]:-}" != "--signoff-arg" || "${fields[10]:-}" != "inv-wrapper" ]]; then
    echo "forwarded second signoff-arg mismatch"
    echo "$line"
    exit 1
  fi
}

echo "[gpm-endpoint-posture-remediate] report mode markers"
REPORT_ENV_FILE="$TMP_DIR/report.env.easy.client"
REPORT_SUMMARY_JSON="$TMP_DIR/missing_signoff_summary.json"
REPORT_LOG="$TMP_DIR/report.log"

set +e
A_HOST="" \
B_HOST="" \
CAMPAIGN_SUBJECT="" \
INVITE_KEY="" \
bash "$SCRIPT_UNDER_TEST" \
  --mode report \
  --env-file "$REPORT_ENV_FILE" \
  --summary-json "$REPORT_SUMMARY_JSON" \
  --minimum-campaign-timeout-sec 900 \
  --signoff-arg --subject \
  --signoff-arg inv-legacy \
  --signoff-arg --campaign-timeout-sec \
  --signoff-arg 120 >"$REPORT_LOG" 2>&1
report_rc=$?
set -e
if [[ "$report_rc" -ne 0 ]]; then
  echo "expected report mode rc=0, got rc=$report_rc"
  cat "$REPORT_LOG"
  exit 1
fi

for expected in \
  '[gpm-endpoint-posture-remediate] finding id=missing_a_host_env' \
  '[gpm-endpoint-posture-remediate] finding id=missing_b_host_env' \
  '[gpm-endpoint-posture-remediate] finding id=missing_invite_subject_env' \
  '[gpm-endpoint-posture-remediate] finding id=deprecated_subject_alias' \
  '[gpm-endpoint-posture-remediate] finding id=campaign_timeout_too_low' \
  '[gpm-endpoint-posture-remediate] finding id=summary_artifact_missing' \
  $'[gpm-endpoint-posture-remediate]\tremediation_cmd\tdeprecated_subject_alias\t./scripts/easy_node.sh profile-default-gate-live --host-a "${A_HOST}" --host-b "${B_HOST}" --campaign-subject "${INVITE_KEY}"' \
  '[gpm-endpoint-posture-remediate] status=ok mode=report findings=6 applied=0'; do
  assert_file_contains "$REPORT_LOG" "$expected" "missing expected report marker: $expected"
done

echo "[gpm-endpoint-posture-remediate] apply mode env upsert idempotency"
APPLY_ENV_FILE="$TMP_DIR/apply.env.easy.client"
APPLY_SUMMARY_JSON="$TMP_DIR/apply_signoff_summary.json"
APPLY_REMEDIATION_SCRIPT="$TMP_DIR/gpm_posture_apply.sh"
APPLY_LOG="$TMP_DIR/apply.log"

cat >"$APPLY_ENV_FILE" <<'EOF_APPLY_ENV'
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_TIMEOUT_SEC=120
EOF_APPLY_ENV

set +e
bash "$SCRIPT_UNDER_TEST" \
  --mode apply \
  --env-file "$APPLY_ENV_FILE" \
  --summary-json "$APPLY_SUMMARY_JSON" \
  --remediation-script "$APPLY_REMEDIATION_SCRIPT" \
  --minimum-campaign-timeout-sec 900 \
  --set-a-host 100.64.0.11 \
  --set-b-host 100.64.0.12 \
  --set-campaign-subject inv-apply-123 >"$APPLY_LOG" 2>&1
apply_rc=$?
set -e
if [[ "$apply_rc" -ne 0 ]]; then
  echo "expected apply mode rc=0, got rc=$apply_rc"
  cat "$APPLY_LOG"
  exit 1
fi

for expected in \
  '[gpm-endpoint-posture-remediate] apply_env_upsert key=A_HOST' \
  '[gpm-endpoint-posture-remediate] apply_env_upsert key=B_HOST' \
  '[gpm-endpoint-posture-remediate] apply_env_upsert key=CAMPAIGN_SUBJECT' \
  '[gpm-endpoint-posture-remediate] apply_env_upsert key=INVITE_KEY' \
  '[gpm-endpoint-posture-remediate] apply_env_upsert key=PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_TIMEOUT_SEC' \
  '[gpm-endpoint-posture-remediate] apply_written_remediation_script path=' \
  '[gpm-endpoint-posture-remediate] status=ok mode=apply findings=5 applied=5'; do
  assert_file_contains "$APPLY_LOG" "$expected" "missing expected apply marker: $expected"
done

assert_file_contains "$APPLY_ENV_FILE" 'A_HOST=100.64.0.11' "missing A_HOST upsert"
assert_file_contains "$APPLY_ENV_FILE" 'B_HOST=100.64.0.12' "missing B_HOST upsert"
assert_file_contains "$APPLY_ENV_FILE" 'CAMPAIGN_SUBJECT=inv-apply-123' "missing CAMPAIGN_SUBJECT upsert"
assert_file_contains "$APPLY_ENV_FILE" 'INVITE_KEY=inv-apply-123' "missing INVITE_KEY upsert"
assert_file_contains "$APPLY_ENV_FILE" 'PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_TIMEOUT_SEC=900' "missing timeout upsert"

for key in A_HOST B_HOST CAMPAIGN_SUBJECT INVITE_KEY PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_TIMEOUT_SEC; do
  key_count="$(grep -c "^${key}=" "$APPLY_ENV_FILE" || true)"
  if [[ "$key_count" != "1" ]]; then
    echo "expected exactly one ${key}= entry after apply idempotent upsert (got $key_count)"
    cat "$APPLY_ENV_FILE"
    exit 1
  fi
done

if [[ ! -x "$APPLY_REMEDIATION_SCRIPT" ]]; then
  echo "expected apply remediation script to be executable: $APPLY_REMEDIATION_SCRIPT"
  ls -la "$TMP_DIR"
  exit 1
fi
assert_file_contains "$APPLY_REMEDIATION_SCRIPT" '# Generated by gpm_endpoint_posture_remediate.sh' "missing remediation script header"
assert_file_contains "$APPLY_REMEDIATION_SCRIPT" './scripts/easy_node.sh profile-compare-campaign-signoff --refresh-campaign 1' "missing remediation script refresh command"

echo "[gpm-endpoint-posture-remediate] easy_node wrapper command contract"
HELP_OUTPUT="$(bash "$EASY_NODE_SCRIPT_UNDER_TEST" --help)"
assert_help_includes_command_token "$HELP_OUTPUT" "gpm-endpoint-posture-remediate"

CAPTURE_FILE="$TMP_DIR/easy_node_capture.tsv"
FAKE_WRAPPER="$TMP_DIR/fake_gpm_endpoint_posture_remediate.sh"
cat >"$FAKE_WRAPPER" <<'EOF_FAKE_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${GPM_ENDPOINT_POSTURE_CAPTURE_FILE:?}"
{
  printf 'gpm_endpoint_posture_remediate'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
EOF_FAKE_WRAPPER
chmod +x "$FAKE_WRAPPER"

: >"$CAPTURE_FILE"
(
  cd "$TMP_DIR"
  GPM_ENDPOINT_POSTURE_REMEDIATE_SCRIPT="$FAKE_WRAPPER" \
  GPM_ENDPOINT_POSTURE_CAPTURE_FILE="$CAPTURE_FILE" \
  bash "$EASY_NODE_SCRIPT_UNDER_TEST" gpm-endpoint-posture-remediate \
    --mode report \
    --env-file fixture.env \
    --summary-json fixture-summary.json \
    --signoff-arg --subject \
    --signoff-arg inv-wrapper >/dev/null 2>&1
)

assert_single_invocation "$CAPTURE_FILE"
assert_forwarded_args "$CAPTURE_FILE" "fixture.env" "fixture-summary.json"

echo "gpm endpoint posture remediate integration ok"
