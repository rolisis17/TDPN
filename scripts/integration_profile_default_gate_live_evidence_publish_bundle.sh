#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_PUBLISH_BUNDLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_default_gate_live_evidence_publish_bundle.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

assert_jq() {
  local file="$1"
  local query="$2"
  if ! jq -e "$query" "$file" >/dev/null 2>&1; then
    echo "assertion failed: $query"
    echo "file: $file"
    cat "$file"
    exit 1
  fi
}

CAPTURE_FILE="$TMP_DIR/capture.tsv"
FAKE_LIVE="$TMP_DIR/fake_live.sh"
FAKE_STABILITY="$TMP_DIR/fake_stability_cycle.sh"
FAKE_PUBLISH="$TMP_DIR/fake_evidence_pack.sh"

cat >"$FAKE_LIVE" <<'EOF_FAKE_LIVE'
#!/usr/bin/env bash
set -euo pipefail
scenario="${FAKE_BUNDLE_LIVE_SCENARIO:-pass}"
capture_file="${FAKE_BUNDLE_CAPTURE_FILE:-}"
summary_json=""
subject=""
host_a=""
host_b=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    --campaign-subject|--subject)
      subject="${2:-}"
      shift 2
      ;;
    --campaign-subject=*|--subject=*)
      subject="${1#*=}"
      shift
      ;;
    --host-a)
      host_a="${2:-}"
      shift 2
      ;;
    --host-a=*)
      host_a="${1#*=}"
      shift
      ;;
    --host-b)
      host_b="${2:-}"
      shift 2
      ;;
    --host-b=*)
      host_b="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -z "$summary_json" ]]; then
  echo "fake live: missing --summary-json" >&2
  exit 2
fi
if [[ -n "$capture_file" ]]; then
  printf 'live\tscenario=%s\thost_a=%s\thost_b=%s\tsubject=%s\tsummary_json=%s\n' \
    "$scenario" "$host_a" "$host_b" "$subject" "$summary_json" >>"$capture_file"
fi
echo "fake-live subject=$subject host_a=$host_a host_b=$host_b"
if [[ "$scenario" == "fail" ]]; then
  exit "${FAKE_BUNDLE_LIVE_FAIL_RC:-31}"
fi
mkdir -p "$(dirname "$summary_json")"
jq -n '{
  version: 1,
  schema: { id: "profile_compare_campaign_signoff_summary" },
  status: "ok",
  rc: 0,
  decision: { decision: "GO", go: true, no_go: false }
}' >"$summary_json"
exit 0
EOF_FAKE_LIVE
chmod +x "$FAKE_LIVE"

cat >"$FAKE_STABILITY" <<'EOF_FAKE_STABILITY'
#!/usr/bin/env bash
set -euo pipefail
scenario="${FAKE_BUNDLE_STABILITY_SCENARIO:-pass}"
capture_file="${FAKE_BUNDLE_CAPTURE_FILE:-}"
summary_json=""
subject=""
host_a=""
host_b=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    --campaign-subject|--subject)
      subject="${2:-}"
      shift 2
      ;;
    --campaign-subject=*|--subject=*)
      subject="${1#*=}"
      shift
      ;;
    --host-a)
      host_a="${2:-}"
      shift 2
      ;;
    --host-a=*)
      host_a="${1#*=}"
      shift
      ;;
    --host-b)
      host_b="${2:-}"
      shift 2
      ;;
    --host-b=*)
      host_b="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -z "$summary_json" ]]; then
  echo "fake stability: missing --summary-json" >&2
  exit 2
fi
if [[ -n "$capture_file" ]]; then
  printf 'stability\tscenario=%s\thost_a=%s\thost_b=%s\tsubject=%s\tsummary_json=%s\n' \
    "$scenario" "$host_a" "$host_b" "$subject" "$summary_json" >>"$capture_file"
fi
echo "fake-stability subject=$subject host_a=$host_a host_b=$host_b"
if [[ "$scenario" == "fail" ]]; then
  exit "${FAKE_BUNDLE_STABILITY_FAIL_RC:-41}"
fi
if [[ "$scenario" == "reuse_no_write" ]]; then
  # Intentionally avoid writing summary_json to simulate stale summary reuse.
  exit 0
fi
mkdir -p "$(dirname "$summary_json")"
jq -n '{
  version: 1,
  schema: { id: "profile_default_gate_stability_cycle_summary" },
  status: "pass",
  rc: 0,
  decision: "GO"
}' >"$summary_json"
exit 0
EOF_FAKE_STABILITY
chmod +x "$FAKE_STABILITY"

cat >"$FAKE_PUBLISH" <<'EOF_FAKE_PUBLISH'
#!/usr/bin/env bash
set -euo pipefail
scenario="${FAKE_BUNDLE_PUBLISH_SCENARIO:-pass}"
capture_file="${FAKE_BUNDLE_CAPTURE_FILE:-}"
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -z "$summary_json" ]]; then
  echo "fake publish: missing --summary-json" >&2
  exit 2
fi
if [[ -n "$capture_file" ]]; then
  printf 'publish\tscenario=%s\tsummary_json=%s\n' "$scenario" "$summary_json" >>"$capture_file"
fi
echo "fake-publish summary_json=$summary_json"
if [[ "$scenario" == "fail" ]]; then
  exit "${FAKE_BUNDLE_PUBLISH_FAIL_RC:-53}"
fi
mkdir -p "$(dirname "$summary_json")"
jq -n '{
  version: 1,
  schema: { id: "profile_default_gate_stability_evidence_pack_summary" },
  status: "ok",
  rc: 0,
  decision: "GO"
}' >"$summary_json"
exit 0
EOF_FAKE_PUBLISH
chmod +x "$FAKE_PUBLISH"

echo "[profile-default-gate-live-evidence-publish-bundle] pass path"
PASS_DIR="$TMP_DIR/pass"
mkdir -p "$PASS_DIR"
PASS_SUMMARY="$PASS_DIR/bundle_summary.json"
PASS_REPORT="$PASS_DIR/bundle_report.md"
PASS_SECRET="inv-super-secret-001"
set +e
PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_LIVE_SCRIPT="$FAKE_LIVE" \
PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_STABILITY_CYCLE_SCRIPT="$FAKE_STABILITY" \
PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_EVIDENCE_PACK_SCRIPT="$FAKE_PUBLISH" \
FAKE_BUNDLE_CAPTURE_FILE="$CAPTURE_FILE" \
FAKE_BUNDLE_LIVE_SCENARIO="pass" \
FAKE_BUNDLE_STABILITY_SCENARIO="pass" \
FAKE_BUNDLE_PUBLISH_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "100.64.0.10" \
  --host-b "100.64.0.11" \
  --campaign-subject "$PASS_SECRET" \
  --reports-dir "$PASS_DIR" \
  --summary-json "$PASS_SUMMARY" \
  --report-md "$PASS_REPORT" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_live_evidence_publish_bundle_pass.log 2>&1
PASS_RC=$?
set -e

if [[ "$PASS_RC" -ne 0 ]]; then
  echo "expected pass path rc=0, got rc=$PASS_RC"
  cat /tmp/integration_profile_default_gate_live_evidence_publish_bundle_pass.log
  exit 1
fi

assert_jq "$PASS_SUMMARY" '
  .schema.id == "profile_default_gate_live_evidence_publish_bundle_summary"
  and .status == "ok"
  and .rc == 0
  and .inputs.subject_source == "explicit:--campaign-subject"
  and .inputs.subject_configured == true
  and .failure_stage == null
  and .failure_substep == null
  and .preflight.ok == true
  and .stages.live_gate.attempted == true
  and .stages.live_gate.status == "pass"
  and .stages.stability_cycle.attempted == true
  and .stages.stability_cycle.status == "pass"
  and .stages.evidence_pack_publish.attempted == true
  and .stages.evidence_pack_publish.status == "pass"
'

PASS_LIVE_LOG="$(jq -r '.stages.live_gate.log' "$PASS_SUMMARY")"
PASS_STABILITY_LOG="$(jq -r '.stages.stability_cycle.log' "$PASS_SUMMARY")"
if grep -F -- "$PASS_SECRET" "$PASS_LIVE_LOG" >/dev/null 2>&1; then
  echo "secret leaked in live stage log"
  cat "$PASS_LIVE_LOG"
  exit 1
fi
if grep -F -- "$PASS_SECRET" "$PASS_STABILITY_LOG" >/dev/null 2>&1; then
  echo "secret leaked in stability stage log"
  cat "$PASS_STABILITY_LOG"
  exit 1
fi
if ! grep -F -- "[redacted]" "$PASS_LIVE_LOG" >/dev/null 2>&1; then
  echo "expected redacted token in live stage log"
  cat "$PASS_LIVE_LOG"
  exit 1
fi
if ! grep -F -- "[redacted]" "$PASS_STABILITY_LOG" >/dev/null 2>&1; then
  echo "expected redacted token in stability stage log"
  cat "$PASS_STABILITY_LOG"
  exit 1
fi

echo "[profile-default-gate-live-evidence-publish-bundle] missing-subject fail-closed path"
MISS_DIR="$TMP_DIR/missing_subject"
mkdir -p "$MISS_DIR"
MISS_SUMMARY="$MISS_DIR/bundle_summary.json"
set +e
PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_LIVE_SCRIPT="$FAKE_LIVE" \
PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_STABILITY_CYCLE_SCRIPT="$FAKE_STABILITY" \
PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_EVIDENCE_PACK_SCRIPT="$FAKE_PUBLISH" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "100.64.0.20" \
  --host-b "100.64.0.21" \
  --reports-dir "$MISS_DIR" \
  --summary-json "$MISS_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_live_evidence_publish_bundle_missing.log 2>&1
MISS_RC=$?
set -e

if [[ "$MISS_RC" -eq 0 ]]; then
  echo "expected missing-subject path to fail"
  cat /tmp/integration_profile_default_gate_live_evidence_publish_bundle_missing.log
  exit 1
fi
if [[ "$MISS_RC" -ne 2 ]]; then
  echo "expected missing-subject rc=2, got rc=$MISS_RC"
  cat /tmp/integration_profile_default_gate_live_evidence_publish_bundle_missing.log
  exit 1
fi

assert_jq "$MISS_SUMMARY" '
  .status == "fail"
  and .rc == 2
  and .inputs.subject_source == null
  and .inputs.subject_configured == false
  and .failure_stage == "preflight"
  and .failure_substep == "preflight_validation_failed"
  and .preflight.ok == false
  and (.preflight.errors | map(contains("--campaign-subject/--subject is required")) | any)
  and .stages.live_gate.attempted == false
  and .stages.stability_cycle.attempted == false
  and .stages.evidence_pack_publish.attempted == false
  and .next_action.command_has_unresolved_placeholders == false
'
assert_jq "$MISS_SUMMARY" '
  (.next_action.reason // "") | contains("--campaign-subject/--subject is required")
'
assert_jq "$MISS_SUMMARY" '
  (.next_action.command // "") | contains("profile_default_gate_live_evidence_publish_bundle.sh")
'
assert_jq "$MISS_SUMMARY" '
  ((.next_action.command // "") | contains("INVITE_KEY")) | not
'
assert_jq "$MISS_SUMMARY" '
  ((.next_action.command // "") | contains("CAMPAIGN_SUBJECT")) | not
'

echo "[profile-default-gate-live-evidence-publish-bundle] stage-failure propagation path"
FAIL_DIR="$TMP_DIR/stage_failure"
mkdir -p "$FAIL_DIR"
FAIL_SUMMARY="$FAIL_DIR/bundle_summary.json"
set +e
PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_LIVE_SCRIPT="$FAKE_LIVE" \
PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_STABILITY_CYCLE_SCRIPT="$FAKE_STABILITY" \
PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_EVIDENCE_PACK_SCRIPT="$FAKE_PUBLISH" \
FAKE_BUNDLE_CAPTURE_FILE="$CAPTURE_FILE" \
FAKE_BUNDLE_LIVE_SCENARIO="pass" \
FAKE_BUNDLE_STABILITY_SCENARIO="fail" \
FAKE_BUNDLE_STABILITY_FAIL_RC="41" \
FAKE_BUNDLE_PUBLISH_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "100.64.0.30" \
  --host-b "100.64.0.31" \
  --campaign-subject "inv-secret-fail-stage" \
  --reports-dir "$FAIL_DIR" \
  --summary-json "$FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_live_evidence_publish_bundle_stagefail.log 2>&1
FAIL_RC=$?
set -e

if [[ "$FAIL_RC" -ne 41 ]]; then
  echo "expected stage-failure rc=41, got rc=$FAIL_RC"
  cat /tmp/integration_profile_default_gate_live_evidence_publish_bundle_stagefail.log
  exit 1
fi

assert_jq "$FAIL_SUMMARY" '
  .status == "fail"
  and .failure_stage == "stability_cycle"
  and .failure_substep == "stability_cycle_stage_failed"
  and .stages.live_gate.attempted == true
  and .stages.live_gate.status == "pass"
  and .stages.stability_cycle.attempted == true
  and .stages.stability_cycle.status == "fail"
  and .stages.stability_cycle.rc == 41
  and .stages.evidence_pack_publish.attempted == false
  and .stages.evidence_pack_publish.status == "skip"
'
assert_jq "$FAIL_SUMMARY" '
  (.next_action.reason // "") | contains("stability cycle stage failed")
'

echo "[profile-default-gate-live-evidence-publish-bundle] stale summary reuse fail-closed path"
STALE_DIR="$TMP_DIR/stale_summary_reuse"
mkdir -p "$STALE_DIR"
STALE_SUMMARY="$STALE_DIR/bundle_summary.json"
STALE_CYCLE_SUMMARY="$STALE_DIR/profile_default_gate_stability_cycle_summary.json"
cat >"$STALE_CYCLE_SUMMARY" <<'EOF_STALE_SUMMARY'
{
  "version": 1,
  "schema": { "id": "profile_default_gate_stability_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO"
}
EOF_STALE_SUMMARY
set +e
PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_LIVE_SCRIPT="$FAKE_LIVE" \
PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_STABILITY_CYCLE_SCRIPT="$FAKE_STABILITY" \
PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_EVIDENCE_PACK_SCRIPT="$FAKE_PUBLISH" \
FAKE_BUNDLE_CAPTURE_FILE="$CAPTURE_FILE" \
FAKE_BUNDLE_LIVE_SCENARIO="pass" \
FAKE_BUNDLE_STABILITY_SCENARIO="reuse_no_write" \
FAKE_BUNDLE_PUBLISH_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "100.64.0.40" \
  --host-b "100.64.0.41" \
  --campaign-subject "inv-secret-stale" \
  --reports-dir "$STALE_DIR" \
  --stability-cycle-summary-json "$STALE_CYCLE_SUMMARY" \
  --summary-json "$STALE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_live_evidence_publish_bundle_stale.log 2>&1
STALE_RC=$?
set -e

if [[ "$STALE_RC" -ne 66 ]]; then
  echo "expected stale summary reuse rc=66, got rc=$STALE_RC"
  cat /tmp/integration_profile_default_gate_live_evidence_publish_bundle_stale.log
  exit 1
fi
assert_jq "$STALE_SUMMARY" '
  .status == "fail"
  and .failure_stage == "stability_cycle"
  and .failure_substep == "stability_cycle_stage_failed"
  and .stages.stability_cycle.attempted == true
  and .stages.stability_cycle.status == "fail"
  and .stages.stability_cycle.rc == 66
  and .stages.stability_cycle.summary_valid_after_run == true
  and .stages.stability_cycle.summary_fresh_after_run == false
  and .stages.evidence_pack_publish.attempted == false
  and .stages.evidence_pack_publish.status == "skip"
'

echo "integration_profile_default_gate_live_evidence_publish_bundle: PASS"
