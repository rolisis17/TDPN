#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod grep tail cat; do
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

CAPTURE_SWEEP="$TMP_DIR/capture_sweep.tsv"
CAPTURE_REDUCER="$TMP_DIR/capture_reducer.tsv"
CAPTURE_CYCLE="$TMP_DIR/capture_cycle.tsv"
CAPTURE_STABILITY_RUN="$TMP_DIR/capture_stability_run.tsv"
CAPTURE_STABILITY_CHECK="$TMP_DIR/capture_stability_check.tsv"
CAPTURE_STABILITY_CYCLE="$TMP_DIR/capture_stability_cycle.tsv"
HELP_OUT="$TMP_DIR/help.txt"
STDOUT_OUT="$TMP_DIR/stdout.txt"
STDERR_OUT="$TMP_DIR/stderr.txt"
FAKE_SWEEP="$TMP_DIR/fake_profile_compare_multi_vm_sweep.sh"
FAKE_REDUCER="$TMP_DIR/fake_profile_compare_multi_vm_reducer.sh"
FAKE_CYCLE="$TMP_DIR/fake_profile_compare_multi_vm_cycle.sh"
FAKE_STABILITY_RUN="$TMP_DIR/fake_profile_compare_multi_vm_stability_run.sh"
FAKE_STABILITY_CHECK="$TMP_DIR/fake_profile_compare_multi_vm_stability_check.sh"
FAKE_STABILITY_CYCLE="$TMP_DIR/fake_profile_compare_multi_vm_stability_cycle.sh"

cat >"$FAKE_SWEEP" <<'EOF_FAKE_SWEEP'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${PROFILE_COMPARE_MULTI_VM_SWEEP_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake profile compare multi-vm sweep: $*"
exit "${FAKE_PROFILE_COMPARE_MULTI_VM_SWEEP_RC:-0}"
EOF_FAKE_SWEEP
chmod +x "$FAKE_SWEEP"

cat >"$FAKE_REDUCER" <<'EOF_FAKE_REDUCER'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${PROFILE_COMPARE_MULTI_VM_REDUCER_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake profile compare multi-vm reducer: $*"
exit "${FAKE_PROFILE_COMPARE_MULTI_VM_REDUCER_RC:-0}"
EOF_FAKE_REDUCER
chmod +x "$FAKE_REDUCER"

cat >"$FAKE_CYCLE" <<'EOF_FAKE_CYCLE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${PROFILE_COMPARE_MULTI_VM_CYCLE_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake profile compare multi-vm cycle: $*"
exit "${FAKE_PROFILE_COMPARE_MULTI_VM_CYCLE_RC:-0}"
EOF_FAKE_CYCLE
chmod +x "$FAKE_CYCLE"

cat >"$FAKE_STABILITY_RUN" <<'EOF_FAKE_STABILITY_RUN'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake profile compare multi-vm stability run: $*"
exit "${FAKE_PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_RC:-0}"
EOF_FAKE_STABILITY_RUN
chmod +x "$FAKE_STABILITY_RUN"

cat >"$FAKE_STABILITY_CHECK" <<'EOF_FAKE_STABILITY_CHECK'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake profile compare multi-vm stability check: $*"
exit "${FAKE_PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_RC:-0}"
EOF_FAKE_STABILITY_CHECK
chmod +x "$FAKE_STABILITY_CHECK"

cat >"$FAKE_STABILITY_CYCLE" <<'EOF_FAKE_STABILITY_CYCLE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${PROFILE_COMPARE_MULTI_VM_STABILITY_CYCLE_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake profile compare multi-vm stability cycle: $*"
exit "${FAKE_PROFILE_COMPARE_MULTI_VM_STABILITY_CYCLE_RC:-0}"
EOF_FAKE_STABILITY_CYCLE
chmod +x "$FAKE_STABILITY_CYCLE"

assert_token() {
  local line="$1"
  local token="$2"
  local message="$3"
  if [[ "$line" != *"$token"* ]]; then
    echo "$message"
    echo "line: $line"
    exit 1
  fi
}

echo "[easy-node-profile-compare-multi-vm] help contract"
bash "$SCRIPT_UNDER_TEST" help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh profile-compare-multi-vm-sweep [profile_compare_multi_vm_sweep args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing profile-compare-multi-vm-sweep command contract"
  cat "$HELP_OUT"
  exit 1
fi
if ! grep -F -- './scripts/easy_node.sh profile-compare-multi-vm-reducer [profile_compare_multi_vm_reducer args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing profile-compare-multi-vm-reducer command contract"
  cat "$HELP_OUT"
  exit 1
fi
if ! grep -F -- './scripts/easy_node.sh profile-compare-multi-vm-cycle [profile_compare_multi_vm_cycle args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing profile-compare-multi-vm-cycle command contract"
  cat "$HELP_OUT"
  exit 1
fi
if ! grep -F -- './scripts/easy_node.sh profile-compare-multi-vm-stability-run [profile_compare_multi_vm_stability_run args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing profile-compare-multi-vm-stability-run command contract"
  cat "$HELP_OUT"
  exit 1
fi
if ! grep -F -- './scripts/easy_node.sh profile-compare-multi-vm-stability-check [profile_compare_multi_vm_stability_check args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing profile-compare-multi-vm-stability-check command contract"
  cat "$HELP_OUT"
  exit 1
fi
if ! grep -F -- './scripts/easy_node.sh profile-compare-multi-vm-stability-cycle [profile_compare_multi_vm_stability_cycle args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing profile-compare-multi-vm-stability-cycle command contract"
  cat "$HELP_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm] sweep forwarding contract"
: >"$CAPTURE_SWEEP"
PROFILE_COMPARE_MULTI_VM_SWEEP_SCRIPT="$FAKE_SWEEP" \
PROFILE_COMPARE_MULTI_VM_SWEEP_CAPTURE_FILE="$CAPTURE_SWEEP" \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-sweep \
  --reports-dir .easy-node-logs/multi_vm_sweep_contract \
  --profiles 1hop,2hop,3hop \
  --runs 3 \
  --sample-arg sample-value >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE_SWEEP" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded sweep invocation capture line"
  exit 1
fi
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/multi_vm_sweep_contract' "missing sweep --reports-dir forwarding"
assert_token "$line" $'\t--profiles\t1hop,2hop,3hop' "missing sweep --profiles forwarding"
assert_token "$line" $'\t--runs\t3' "missing sweep --runs forwarding"
assert_token "$line" $'\t--sample-arg\tsample-value' "missing sweep passthrough arg forwarding"
if ! grep -F -- 'fake profile compare multi-vm sweep:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake sweep script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm] reducer forwarding contract"
: >"$CAPTURE_REDUCER"
PROFILE_COMPARE_MULTI_VM_REDUCER_SCRIPT="$FAKE_REDUCER" \
PROFILE_COMPARE_MULTI_VM_REDUCER_CAPTURE_FILE="$CAPTURE_REDUCER" \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-reducer \
  --input-glob '.easy-node-logs/profile_compare_multi_vm_sweep_*.json' \
  --summary-json .easy-node-logs/profile_compare_multi_vm_reducer_contract_summary.json \
  --report-md .easy-node-logs/profile_compare_multi_vm_reducer_contract_report.md \
  --sample-arg sample-value >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE_REDUCER" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded reducer invocation capture line"
  exit 1
fi
assert_token "$line" $'\t--input-glob\t.easy-node-logs/profile_compare_multi_vm_sweep_*.json' "missing reducer --input-glob forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/profile_compare_multi_vm_reducer_contract_summary.json' "missing reducer --summary-json forwarding"
assert_token "$line" $'\t--report-md\t.easy-node-logs/profile_compare_multi_vm_reducer_contract_report.md' "missing reducer --report-md forwarding"
assert_token "$line" $'\t--sample-arg\tsample-value' "missing reducer passthrough arg forwarding"
if ! grep -F -- 'fake profile compare multi-vm reducer:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake reducer script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm] reducer exit code contract"
set +e
PROFILE_COMPARE_MULTI_VM_REDUCER_SCRIPT="$FAKE_REDUCER" \
PROFILE_COMPARE_MULTI_VM_REDUCER_CAPTURE_FILE="$CAPTURE_REDUCER" \
FAKE_PROFILE_COMPARE_MULTI_VM_REDUCER_RC=9 \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-reducer --sample-arg boom >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 9 ]]; then
  echo "expected easy_node reducer wrapper to return fake script exit code 9, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake profile compare multi-vm reducer: --sample-arg boom' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded reducer output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm] cycle forwarding contract"
: >"$CAPTURE_CYCLE"
PROFILE_COMPARE_MULTI_VM_CYCLE_SCRIPT="$FAKE_CYCLE" \
PROFILE_COMPARE_MULTI_VM_CYCLE_CAPTURE_FILE="$CAPTURE_CYCLE" \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-cycle \
  --reports-dir .easy-node-logs/profile_compare_multi_vm_cycle_contract \
  --summary-json .easy-node-logs/profile_compare_multi_vm_cycle_contract_summary.json \
  --report-md .easy-node-logs/profile_compare_multi_vm_cycle_contract_report.md \
  --sample-arg sample-value >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE_CYCLE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded cycle invocation capture line"
  exit 1
fi
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/profile_compare_multi_vm_cycle_contract' "missing cycle --reports-dir forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/profile_compare_multi_vm_cycle_contract_summary.json' "missing cycle --summary-json forwarding"
assert_token "$line" $'\t--report-md\t.easy-node-logs/profile_compare_multi_vm_cycle_contract_report.md' "missing cycle --report-md forwarding"
assert_token "$line" $'\t--sample-arg\tsample-value' "missing cycle passthrough arg forwarding"
if ! grep -F -- 'fake profile compare multi-vm cycle:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake cycle script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm] cycle exit code contract"
set +e
PROFILE_COMPARE_MULTI_VM_CYCLE_SCRIPT="$FAKE_CYCLE" \
PROFILE_COMPARE_MULTI_VM_CYCLE_CAPTURE_FILE="$CAPTURE_CYCLE" \
FAKE_PROFILE_COMPARE_MULTI_VM_CYCLE_RC=7 \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-cycle --sample-arg boom >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 7 ]]; then
  echo "expected easy_node cycle wrapper to return fake script exit code 7, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake profile compare multi-vm cycle: --sample-arg boom' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded cycle output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm] stability-run forwarding contract"
: >"$CAPTURE_STABILITY_RUN"
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SCRIPT="$FAKE_STABILITY_RUN" \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CAPTURE_FILE="$CAPTURE_STABILITY_RUN" \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-stability-run \
  --runs 4 \
  --reports-dir .easy-node-logs/profile_compare_multi_vm_stability_run_contract \
  --summary-json .easy-node-logs/profile_compare_multi_vm_stability_run_contract_summary.json \
  --sample-arg sample-value >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE_STABILITY_RUN" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded stability-run invocation capture line"
  exit 1
fi
assert_token "$line" $'\t--runs\t4' "missing stability-run --runs forwarding"
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/profile_compare_multi_vm_stability_run_contract' "missing stability-run --reports-dir forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/profile_compare_multi_vm_stability_run_contract_summary.json' "missing stability-run --summary-json forwarding"
assert_token "$line" $'\t--sample-arg\tsample-value' "missing stability-run passthrough arg forwarding"
if ! grep -F -- 'fake profile compare multi-vm stability run:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake stability-run script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm] stability-run exit code contract"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SCRIPT="$FAKE_STABILITY_RUN" \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CAPTURE_FILE="$CAPTURE_STABILITY_RUN" \
FAKE_PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_RC=5 \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-stability-run --sample-arg boom >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 5 ]]; then
  echo "expected easy_node stability-run wrapper to return fake script exit code 5, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake profile compare multi-vm stability run: --sample-arg boom' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded stability-run output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm] stability-check forwarding contract"
: >"$CAPTURE_STABILITY_CHECK"
PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SCRIPT="$FAKE_STABILITY_CHECK" \
PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_CAPTURE_FILE="$CAPTURE_STABILITY_CHECK" \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-stability-check \
  --stability-summary-json .easy-node-logs/profile_compare_multi_vm_stability_run_contract_summary.json \
  --require-stability-ok 1 \
  --summary-json .easy-node-logs/profile_compare_multi_vm_stability_check_contract_summary.json \
  --sample-arg sample-value >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE_STABILITY_CHECK" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded stability-check invocation capture line"
  exit 1
fi
assert_token "$line" $'\t--stability-summary-json\t.easy-node-logs/profile_compare_multi_vm_stability_run_contract_summary.json' "missing stability-check --stability-summary-json forwarding"
assert_token "$line" $'\t--require-stability-ok\t1' "missing stability-check --require-stability-ok forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/profile_compare_multi_vm_stability_check_contract_summary.json' "missing stability-check --summary-json forwarding"
assert_token "$line" $'\t--sample-arg\tsample-value' "missing stability-check passthrough arg forwarding"
if ! grep -F -- 'fake profile compare multi-vm stability check:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake stability-check script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm] stability-check exit code contract"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SCRIPT="$FAKE_STABILITY_CHECK" \
PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_CAPTURE_FILE="$CAPTURE_STABILITY_CHECK" \
FAKE_PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_RC=6 \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-stability-check --sample-arg boom >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 6 ]]; then
  echo "expected easy_node stability-check wrapper to return fake script exit code 6, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake profile compare multi-vm stability check: --sample-arg boom' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded stability-check output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm] stability-cycle forwarding contract"
: >"$CAPTURE_STABILITY_CYCLE"
PROFILE_COMPARE_MULTI_VM_STABILITY_CYCLE_SCRIPT="$FAKE_STABILITY_CYCLE" \
PROFILE_COMPARE_MULTI_VM_STABILITY_CYCLE_CAPTURE_FILE="$CAPTURE_STABILITY_CYCLE" \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-stability-cycle \
  --runs 4 \
  --reports-dir .easy-node-logs/profile_compare_multi_vm_stability_cycle_contract \
  --stability-summary-json .easy-node-logs/profile_compare_multi_vm_stability_cycle_contract_stability_summary.json \
  --stability-check-summary-json .easy-node-logs/profile_compare_multi_vm_stability_cycle_contract_stability_check_summary.json \
  --summary-json .easy-node-logs/profile_compare_multi_vm_stability_cycle_contract_summary.json \
  --sample-arg sample-value >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE_STABILITY_CYCLE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded stability-cycle invocation capture line"
  exit 1
fi
assert_token "$line" $'\t--runs\t4' "missing stability-cycle --runs forwarding"
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/profile_compare_multi_vm_stability_cycle_contract' "missing stability-cycle --reports-dir forwarding"
assert_token "$line" $'\t--stability-summary-json\t.easy-node-logs/profile_compare_multi_vm_stability_cycle_contract_stability_summary.json' "missing stability-cycle --stability-summary-json forwarding"
assert_token "$line" $'\t--stability-check-summary-json\t.easy-node-logs/profile_compare_multi_vm_stability_cycle_contract_stability_check_summary.json' "missing stability-cycle --stability-check-summary-json forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/profile_compare_multi_vm_stability_cycle_contract_summary.json' "missing stability-cycle --summary-json forwarding"
assert_token "$line" $'\t--sample-arg\tsample-value' "missing stability-cycle passthrough arg forwarding"
if ! grep -F -- 'fake profile compare multi-vm stability cycle:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake stability-cycle script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm] stability-cycle exit code contract"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_CYCLE_SCRIPT="$FAKE_STABILITY_CYCLE" \
PROFILE_COMPARE_MULTI_VM_STABILITY_CYCLE_CAPTURE_FILE="$CAPTURE_STABILITY_CYCLE" \
FAKE_PROFILE_COMPARE_MULTI_VM_STABILITY_CYCLE_RC=8 \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-stability-cycle --sample-arg boom >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 8 ]]; then
  echo "expected easy_node stability-cycle wrapper to return fake script exit code 8, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake profile compare multi-vm stability cycle: --sample-arg boom' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded stability-cycle output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "easy node profile-compare-multi-vm wrappers integration check ok"
