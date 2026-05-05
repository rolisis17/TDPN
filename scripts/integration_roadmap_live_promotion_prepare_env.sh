#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${ROADMAP_LIVE_PROMOTION_PREPARE_ENV_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/roadmap_live_promotion_prepare_env.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

mkdir -p "$ROOT_DIR/.easy-node-logs"
TMP_DIR="$(mktemp -d "$ROOT_DIR/.easy-node-logs/integration_roadmap_live_promotion_prepare_env_XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "$msg"
    echo "missing token: $needle"
    exit 1
  fi
}

echo "[roadmap-live-promotion-prepare-env] help contract"
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--roadmap-summary-json PATH" >/dev/null; then
  echo "help output missing --roadmap-summary-json PATH"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--summary-json PATH" >/dev/null; then
  echo "help output missing --summary-json PATH"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--host-a HOST" >/dev/null; then
  echo "help output missing --host-a HOST"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--host-b HOST" >/dev/null; then
  echo "help output missing --host-b HOST"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--campaign-subject ID" >/dev/null; then
  echo "help output missing --campaign-subject ID"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--vm-command-source PATH" >/dev/null; then
  echo "help output missing --vm-command-source PATH"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--require-summary [0|1]" >/dev/null; then
  echo "help output missing --require-summary [0|1]"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--print-shell [0|1]" >/dev/null; then
  echo "help output missing --print-shell [0|1]"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--print-summary-json [0|1]" >/dev/null; then
  echo "help output missing --print-summary-json [0|1]"
  exit 1
fi

echo "[roadmap-live-promotion-prepare-env] success path from roadmap summary commands"
ROADMAP_SUCCESS="$TMP_DIR/roadmap_success.json"
cat >"$ROADMAP_SUCCESS" <<'JSON_SUCCESS'
{
  "status": "warn",
  "rc": 0,
  "vpn_track": {
    "profile_default_gate": {
      "status": "pending",
      "next_command": "./scripts/easy_node.sh profile-default-gate-live --host-a 100.113.245.61 --host-b 100.64.244.24 --campaign-subject subj-live-123 --print-summary-json 1"
    },
    "runtime_actuation_promotion": {
      "status": "fail"
    },
    "multi_vm_stability": {
      "status": "missing",
      "next_command": "./scripts/easy_node.sh profile-compare-multi-vm-stability-cycle --vm-command-source /tmp/vm_specs.json --print-summary-json 1"
    },
    "multi_vm_stability_promotion": {
      "status": "fail"
    }
  },
  "next_actions": [
    {
      "id": "profile_default_gate",
      "command": "./scripts/easy_node.sh profile-default-gate-live --host-a 100.113.245.61 --host-b 100.64.244.24 --campaign-subject subj-live-123 --print-summary-json 1"
    },
    {
      "id": "profile_compare_multi_vm_stability",
      "command": "./scripts/easy_node.sh profile-compare-multi-vm-stability-cycle --vm-command-source /tmp/vm_specs.json --print-summary-json 1"
    }
  ]
}
JSON_SUCCESS

SUMMARY_SUCCESS="$TMP_DIR/summary_success.json"
OUTPUT_SUCCESS="$(
  bash "$SCRIPT_UNDER_TEST" \
    --roadmap-summary-json "$ROADMAP_SUCCESS" \
    --summary-json "$SUMMARY_SUCCESS" \
    --print-summary-json 0 \
    --print-shell 1
)"

assert_contains "$OUTPUT_SUCCESS" "export ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_HOST_A=100.113.245.61" "expected host-a export command"
assert_contains "$OUTPUT_SUCCESS" "export ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_HOST_B=100.64.244.24" "expected host-b export command"
assert_contains "$OUTPUT_SUCCESS" "export ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_CAMPAIGN_SUBJECT=subj-live-123" "expected campaign-subject export command"
assert_contains "$OUTPUT_SUCCESS" "export ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_VM_COMMAND_SOURCE=/tmp/vm_specs.json" "expected vm-command-source export command"

if ! jq -e '
  .schema.id == "roadmap_live_promotion_prepare_env_summary"
  and .status == "pass"
  and .rc == 0
  and .unresolved.count == 0
  and .runtime.host_a.configured == true
  and .runtime.host_b.configured == true
  and .runtime.campaign_subject.configured == true
  and .runtime.vm_command_source.configured == true
  and .exports.count >= 8
' "$SUMMARY_SUCCESS" >/dev/null; then
  echo "success summary contract assertion failed"
  cat "$SUMMARY_SUCCESS"
  exit 1
fi

echo "[roadmap-live-promotion-prepare-env] fail-closed unresolved placeholders"
ROADMAP_UNRESOLVED="$TMP_DIR/roadmap_unresolved.json"
cat >"$ROADMAP_UNRESOLVED" <<'JSON_UNRESOLVED'
{
  "status": "warn",
  "rc": 0,
  "vpn_track": {
    "profile_default_gate": {
      "status": "pending",
      "next_command": "./scripts/easy_node.sh profile-default-gate-live --host-a HOST_A --host-b B_HOST --campaign-subject INVITE_KEY --print-summary-json 1"
    },
    "runtime_actuation_promotion": {
      "status": "fail"
    },
    "multi_vm_stability": {
      "status": "missing",
      "next_command": null
    },
    "multi_vm_stability_promotion": {
      "status": "fail"
    }
  },
  "next_actions": [
    {
      "id": "profile_default_gate",
      "command": "./scripts/easy_node.sh profile-default-gate-live --host-a HOST_A --host-b B_HOST --campaign-subject INVITE_KEY --print-summary-json 1"
    }
  ]
}
JSON_UNRESOLVED

SUMMARY_UNRESOLVED="$TMP_DIR/summary_unresolved.json"
set +e
OUTPUT_UNRESOLVED="$(
  bash "$SCRIPT_UNDER_TEST" \
    --roadmap-summary-json "$ROADMAP_UNRESOLVED" \
    --summary-json "$SUMMARY_UNRESOLVED" \
    --print-summary-json 0 \
    --print-shell 1 \
    2>"$TMP_DIR/unresolved_stderr.log"
)"
UNRESOLVED_RC=$?
set -e

if [[ $UNRESOLVED_RC -eq 0 ]]; then
  echo "expected unresolved run to fail"
  exit 1
fi
if [[ "$OUTPUT_UNRESOLVED" == *"export ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_HOST_A="* ]]; then
  echo "unresolved run should not emit export commands"
  echo "$OUTPUT_UNRESOLVED"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .unresolved.count == 4
  and (.unresolved.keys | index("host_a")) != null
  and (.unresolved.keys | index("host_b")) != null
  and (.unresolved.keys | index("campaign_subject")) != null
  and (.unresolved.keys | index("vm_command_source")) != null
' "$SUMMARY_UNRESOLVED" >/dev/null; then
  echo "unresolved summary contract assertion failed"
  cat "$SUMMARY_UNRESOLVED"
  exit 1
fi

echo "[roadmap-live-promotion-prepare-env] env fallback overrides placeholder summary values"
SUMMARY_ENV_FALLBACK="$TMP_DIR/summary_env_fallback.json"
OUTPUT_ENV_FALLBACK="$(
  A_HOST="198.18.0.10" \
  B_HOST="198.18.0.11" \
  CAMPAIGN_SUBJECT="subject-env-777" \
  VM_COMMAND_SOURCE="/tmp/env_vm_commands.json" \
  bash "$SCRIPT_UNDER_TEST" \
    --roadmap-summary-json "$ROADMAP_UNRESOLVED" \
    --summary-json "$SUMMARY_ENV_FALLBACK" \
    --print-summary-json 0 \
    --print-shell 1
)"

assert_contains "$OUTPUT_ENV_FALLBACK" "export ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_HOST_A=198.18.0.10" "expected env host-a export command"
assert_contains "$OUTPUT_ENV_FALLBACK" "export ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_HOST_B=198.18.0.11" "expected env host-b export command"
assert_contains "$OUTPUT_ENV_FALLBACK" "export ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_CAMPAIGN_SUBJECT=subject-env-777" "expected env campaign-subject export command"
assert_contains "$OUTPUT_ENV_FALLBACK" "export ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_VM_COMMAND_SOURCE=/tmp/env_vm_commands.json" "expected env vm command source export command"

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .runtime.host_a.source == "env:A_HOST"
  and .runtime.host_b.source == "env:B_HOST"
  and .runtime.campaign_subject.source == "env:CAMPAIGN_SUBJECT"
  and .runtime.vm_command_source.source == "env:VM_COMMAND_SOURCE"
  and .runtime.campaign_subject.value == "[redacted]"
' "$SUMMARY_ENV_FALLBACK" >/dev/null; then
  echo "env fallback summary contract assertion failed"
  cat "$SUMMARY_ENV_FALLBACK"
  exit 1
fi

echo "[roadmap-live-promotion-prepare-env] print-summary-json emits machine-readable summary"
SUMMARY_PRINT_ONLY="$TMP_DIR/summary_print_only.json"
OUTPUT_PRINT_ONLY="$(
  bash "$SCRIPT_UNDER_TEST" \
    --roadmap-summary-json "$ROADMAP_SUCCESS" \
    --summary-json "$SUMMARY_PRINT_ONLY" \
    --print-shell 0 \
    --print-summary-json 1
)"
assert_contains "$OUTPUT_PRINT_ONLY" "\"schema\"" "expected summary JSON output when --print-summary-json=1"
if printf '%s\n' "$OUTPUT_PRINT_ONLY" | grep -E '^export [A-Z_]+=.*$' >/dev/null; then
  echo "print-summary-json only run should not emit export lines when --print-shell=0"
  exit 1
fi

echo "[roadmap-live-promotion-prepare-env] all assertions passed"
