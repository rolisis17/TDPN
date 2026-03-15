#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in rg g++; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_ROOT="$TMP_DIR/fake_root"
BIN="$TMP_DIR/easy_mode_ui"
CAPTURE="$TMP_DIR/easy_node_calls.log"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TMP_ROOT/scripts" "$TMP_ROOT/data"

cat >"$TMP_ROOT/scripts/easy_node.sh" <<'EOF_FAKE_EASY'
#!/usr/bin/env bash
set -euo pipefail
subcommand="${1:-}"
if [[ $# -gt 0 ]]; then
  shift
fi
printf '%s\n' "${subcommand}${*:+ }$*" >>"${EASY_MODE_RUNTIME_CAPTURE_FILE:?}"

resolve_repo_path() {
  local path="${1:-}"
  if [[ -z "$path" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "${PRIVACYNODE_ROOT:?}/$path"
  fi
}

if [[ "$subcommand" == "manual-validation-report" ]]; then
  summary_json=""
  report_md=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --summary-json)
        summary_json="$(resolve_repo_path "${2:-}")"
        shift 2
        ;;
      --report-md)
        report_md="$(resolve_repo_path "${2:-}")"
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done

  mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
  cat >"$summary_json" <<EOF_SUMMARY
{
  "report": {
    "readiness_status": "NOT_READY",
    "summary_json": "$summary_json",
    "report_md": "$report_md"
  },
  "summary": {
    "pre_machine_c_gate": {
      "ready": false,
      "blockers": ["runtime_hygiene"],
      "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --runtime-fix 1"
    },
    "next_action_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --runtime-fix 1",
    "latest_failed_incident": {
      "summary_json": {"path": "/tmp/fake-incident/incident_summary.json"},
      "report_md": {"path": "/tmp/fake-incident/incident_report.md"},
      "readiness_report_summary_attachment": {"bundle_path": "attachments/02_manual_validation_readiness_summary.json"},
      "readiness_report_md_attachment": {"bundle_path": "attachments/03_manual_validation_readiness_report.md"}
    }
  }
}
EOF_SUMMARY
  printf '# fake readiness report\n' >"$report_md"
fi
if [[ "$subcommand" == "pre-real-host-readiness" ]]; then
  summary_json=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --summary-json)
        summary_json="$(resolve_repo_path "${2:-}")"
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done
  if [[ -z "$summary_json" ]]; then
    summary_json="$(resolve_repo_path ".easy-node-logs/pre_real_host_readiness_summary.json")"
  fi
  mkdir -p "$(dirname "$summary_json")" "$(dirname "$(resolve_repo_path ".easy-node-logs/manual_validation_readiness_summary.json")")"
  cat >"$(resolve_repo_path ".easy-node-logs/manual_validation_readiness_summary.json")" <<EOF_READY
{
  "report": {
    "readiness_status": "NOT_READY",
    "summary_json": "$(resolve_repo_path ".easy-node-logs/manual_validation_readiness_summary.json")",
    "report_md": "$(resolve_repo_path ".easy-node-logs/manual_validation_readiness_report.md")"
  },
  "summary": {
    "pre_machine_c_gate": {
      "ready": true,
      "blockers": [],
      "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --runtime-fix 1"
    },
    "next_action_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --runtime-fix 1",
    "latest_failed_incident": {
      "summary_json": {"path": "/tmp/fake-incident/incident_summary.json"},
      "report_md": {"path": "/tmp/fake-incident/incident_report.md"},
      "readiness_report_summary_attachment": {"bundle_path": "attachments/02_manual_validation_readiness_summary.json"},
      "readiness_report_md_attachment": {"bundle_path": "attachments/03_manual_validation_readiness_report.md"}
    }
  }
}
EOF_READY
  printf '# fake readiness report\n' >"$(resolve_repo_path ".easy-node-logs/manual_validation_readiness_report.md")"
  cat >"$summary_json" <<EOF_PRE
{
  "status": "pass",
  "stage": "complete",
  "machine_c_smoke_gate": {
    "ready": true
  }
}
EOF_PRE
fi
exit 0
EOF_FAKE_EASY
chmod +x "$TMP_ROOT/scripts/easy_node.sh"

cat >"$TMP_ROOT/data/easy_mode_hosts.conf" <<'EOF_HOSTS'
MACHINE_A_HOST=198.51.100.10
MACHINE_B_HOST=203.0.113.20
EOF_HOSTS

echo "[easy-mode-runtime] compile launcher"
g++ -std=c++17 -O2 -o "$BIN" tools/easy_mode/easy_mode_ui.cpp

run_ui() {
  local input_file="$1"
  local out_file="$2"
  EASY_MODE_RUNTIME_CAPTURE_FILE="$CAPTURE" \
  PRIVACYNODE_ROOT="$TMP_ROOT" \
  "$BIN" <"$input_file" >"$out_file" 2>&1
}

assert_line_has() {
  local line="$1"
  local pattern="$2"
  local message="$3"
  if ! printf '%s\n' "$line" | rg -q -- "$pattern"; then
    echo "$message"
    printf 'line: %s\n' "$line"
    exit 1
  fi
}

echo "[easy-mode-runtime] main menu option 1 (simple client) runtime command forwarding"
INPUT1="$TMP_DIR/input1.txt"
{
  printf '1\n'   # main menu: simple client
  printf '\n'    # bootstrap URL (default from hosts)
  printf 'inv-runtime-smoke\n'
  printf '\n'    # discovery wait
  printf '\n'    # prod profile (default no)
  printf '\n'    # path profile (default balanced)
  printf 'n\n'   # real VPN mode? no -> client-test path
  printf '\n'    # timeout sec
  printf '0\n'   # exit main menu
} >"$INPUT1"
run_ui "$INPUT1" "$TMP_DIR/run1.log"

line1="$(rg '^client-test ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line1" ]]; then
  echo "runtime wiring failed: option 1 did not invoke client-test in simple mode"
  cat "$TMP_DIR/run1.log"
  exit 1
fi
assert_line_has "$line1" '--bootstrap-directory http://198\.51\.100\.10:8081' \
  "runtime wiring failed: option 1 missing default bootstrap directory"
assert_line_has "$line1" '--subject inv-runtime-smoke' \
  "runtime wiring failed: option 1 missing invite subject"
assert_line_has "$line1" '--timeout-sec 45' \
  "runtime wiring failed: option 1 missing default timeout-sec"
assert_line_has "$line1" '--beta-profile 1' \
  "runtime wiring failed: option 1 missing --beta-profile 1"
assert_line_has "$line1" '--prod-profile 0' \
  "runtime wiring failed: option 1 missing --prod-profile 0 default"
assert_line_has "$line1" '--distinct-operators 1' \
  "runtime wiring failed: option 1 missing balanced path distinct-operators flag"
assert_line_has "$line1" '--locality-soft-bias 1' \
  "runtime wiring failed: option 1 missing balanced path locality-soft-bias flag"
assert_line_has "$line1" '--country-bias 1\.50' \
  "runtime wiring failed: option 1 missing balanced path country-bias default"

: >"$CAPTURE"

echo "[easy-mode-runtime] main menu option 2 (simple server/provider) runtime command forwarding"
INPUT2="$TMP_DIR/input2.txt"
{
  printf '2\n'   # main menu: simple server
  printf '\n'    # public host (default hosts.a)
  printf '\n'    # authority mode? default no (provider)
  printf '.\n'   # peer host (use shown default hosts.b)
  printf '\n'    # prod profile (default no)
  printf '\n'    # run preflight (default yes)
  printf '\n'    # peer identity strict mode
  printf '\n'    # preflight timeout
  printf '\n'    # authority directory URL default from peer host
  printf '\n'    # authority issuer URL default from peer host
  printf '\n'    # preflight minimum peer operators default
  printf '\n'    # save/update hosts (default no)
  printf '0\n'   # exit main menu
} >"$INPUT2"
run_ui "$INPUT2" "$TMP_DIR/run2.log"

line2_preflight="$(rg '^server-preflight ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line2_preflight" ]]; then
  echo "runtime wiring failed: option 2 did not invoke server-preflight"
  cat "$TMP_DIR/run2.log"
  exit 1
fi
assert_line_has "$line2_preflight" '--mode provider' \
  "runtime wiring failed: option 2 preflight missing --mode provider"
assert_line_has "$line2_preflight" '--public-host 198\.51\.100\.10' \
  "runtime wiring failed: option 2 preflight missing default public host"
assert_line_has "$line2_preflight" '--peer-directories http://203\.0\.113\.20:8081' \
  "runtime wiring failed: option 2 preflight missing derived peer directories"
assert_line_has "$line2_preflight" '--authority-directory http://203\.0\.113\.20:8081' \
  "runtime wiring failed: option 2 preflight missing derived authority directory"
assert_line_has "$line2_preflight" '--authority-issuer http://203\.0\.113\.20:8082' \
  "runtime wiring failed: option 2 preflight missing derived authority issuer"
assert_line_has "$line2_preflight" '--min-peer-operators 1' \
  "runtime wiring failed: option 2 preflight missing default min-peer-operators"
assert_line_has "$line2_preflight" '--prod-profile 0' \
  "runtime wiring failed: option 2 preflight missing --prod-profile 0 default"

line2_serverup="$(rg '^server-up ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line2_serverup" ]]; then
  echo "runtime wiring failed: option 2 did not invoke server-up"
  cat "$TMP_DIR/run2.log"
  exit 1
fi
assert_line_has "$line2_serverup" '--mode provider' \
  "runtime wiring failed: option 2 server-up missing --mode provider"
assert_line_has "$line2_serverup" '--public-host 198\.51\.100\.10' \
  "runtime wiring failed: option 2 server-up missing default public host"
assert_line_has "$line2_serverup" '--peer-directories http://203\.0\.113\.20:8081' \
  "runtime wiring failed: option 2 server-up missing derived peer directories"
assert_line_has "$line2_serverup" '--authority-directory http://203\.0\.113\.20:8081' \
  "runtime wiring failed: option 2 server-up missing derived authority directory"
assert_line_has "$line2_serverup" '--authority-issuer http://203\.0\.113\.20:8082' \
  "runtime wiring failed: option 2 server-up missing derived authority issuer"
assert_line_has "$line2_serverup" '--beta-profile 1' \
  "runtime wiring failed: option 2 server-up missing --beta-profile 1"
assert_line_has "$line2_serverup" '--prod-profile 0' \
  "runtime wiring failed: option 2 server-up missing --prod-profile 0 default"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 36 (closed-beta strict bundle) runtime command forwarding"
INPUT36="$TMP_DIR/input36.txt"
{
  printf '3\n'   # main menu: advanced
  printf '36\n'  # strict closed-beta bundle
  printf '\n'    # auto-discover (default yes)
  printf '\n'    # bootstrap directory URL (default hosts.a)
  printf '\n'    # subject optional
  printf '\n'    # bundle dir
  printf '\n'    # report optional
  printf 'n\n'   # run with sudo? no
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT36"
run_ui "$INPUT36" "$TMP_DIR/run36.log"

line36="$(rg '^three-machine-prod-bundle ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line36" ]]; then
  echo "runtime wiring failed: option 36 did not invoke three-machine-prod-bundle"
  cat "$TMP_DIR/run36.log"
  exit 1
fi
assert_line_has "$line36" '--preflight-check 1' \
  "runtime wiring failed: option 36 missing --preflight-check 1"
assert_line_has "$line36" '--bundle-verify-check 1' \
  "runtime wiring failed: option 36 missing --bundle-verify-check 1"
assert_line_has "$line36" '--signoff-check 1' \
  "runtime wiring failed: option 36 missing --signoff-check 1"
assert_line_has "$line36" '--signoff-require-wg-validate-udp-source 1' \
  "runtime wiring failed: option 36 missing --signoff-require-wg-validate-udp-source 1"
assert_line_has "$line36" '--signoff-require-wg-validate-strict-distinct 1' \
  "runtime wiring failed: option 36 missing --signoff-require-wg-validate-strict-distinct 1"
assert_line_has "$line36" '--signoff-require-wg-soak-diversity-pass 1' \
  "runtime wiring failed: option 36 missing --signoff-require-wg-soak-diversity-pass 1"
assert_line_has "$line36" '--signoff-min-wg-soak-selection-lines 12' \
  "runtime wiring failed: option 36 missing --signoff-min-wg-soak-selection-lines 12"
assert_line_has "$line36" '--signoff-min-wg-soak-entry-operators 2' \
  "runtime wiring failed: option 36 missing --signoff-min-wg-soak-entry-operators 2"
assert_line_has "$line36" '--signoff-min-wg-soak-exit-operators 2' \
  "runtime wiring failed: option 36 missing --signoff-min-wg-soak-exit-operators 2"
assert_line_has "$line36" '--signoff-min-wg-soak-cross-operator-pairs 3' \
  "runtime wiring failed: option 36 missing --signoff-min-wg-soak-cross-operator-pairs 3"
assert_line_has "$line36" '--wg-slo-profile strict' \
  "runtime wiring failed: option 36 missing strict wg slo profile"
assert_line_has "$line36" '--bundle-dir \.easy-node-logs/prod_gate_bundle_quick' \
  "runtime wiring failed: option 36 missing default strict bundle dir"
assert_line_has "$line36" '--run-report-json \.easy-node-logs/prod_gate_bundle_quick/prod_bundle_run_report\.json' \
  "runtime wiring failed: option 36 missing default strict run-report path"
assert_line_has "$line36" '--bootstrap-directory http://198\.51\.100\.10:8081' \
  "runtime wiring failed: option 36 missing default bootstrap directory"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 37 (closed-beta smoke bundle) runtime command forwarding"
INPUT37="$TMP_DIR/input37.txt"
{
  printf '3\n'   # main menu: advanced
  printf '37\n'  # smoke closed-beta bundle
  printf '\n'    # auto-discover (default yes)
  printf '\n'    # bootstrap directory URL (default hosts.a)
  printf '\n'    # subject optional
  printf '\n'    # bundle dir
  printf '\n'    # report optional
  printf 'n\n'   # run with sudo? no
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT37"
run_ui "$INPUT37" "$TMP_DIR/run37.log"

line37="$(rg '^three-machine-prod-bundle ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line37" ]]; then
  echo "runtime wiring failed: option 37 did not invoke three-machine-prod-bundle"
  cat "$TMP_DIR/run37.log"
  exit 1
fi
assert_line_has "$line37" '--preflight-check 0' \
  "runtime wiring failed: option 37 missing --preflight-check 0"
assert_line_has "$line37" '--bundle-verify-check 1' \
  "runtime wiring failed: option 37 missing --bundle-verify-check 1"
assert_line_has "$line37" '--signoff-check 0' \
  "runtime wiring failed: option 37 missing --signoff-check 0"
assert_line_has "$line37" '--wg-slo-profile recommended' \
  "runtime wiring failed: option 37 missing recommended wg slo profile"
assert_line_has "$line37" '--bundle-dir \.easy-node-logs/prod_gate_bundle_smoke' \
  "runtime wiring failed: option 37 missing default smoke bundle dir"
assert_line_has "$line37" '--run-report-json \.easy-node-logs/prod_gate_bundle_smoke/prod_bundle_run_report\.json' \
  "runtime wiring failed: option 37 missing default smoke run-report path"
assert_line_has "$line37" '--bootstrap-directory http://198\.51\.100\.10:8081' \
  "runtime wiring failed: option 37 missing default bootstrap directory"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 38 (prod gate signoff) runtime command forwarding"
INPUT38="$TMP_DIR/input38.txt"
{
  printf '3\n'   # main menu: advanced
  printf '38\n'  # verify/signoff
  printf '\n'    # bundle dir override optional
  printf '\n'    # bundle tar optional
  printf '\n'    # run report json path default
  printf '\n'    # verify integrity? default yes
  printf '\n'    # show integrity details? default no
  printf '\n'    # gate summary optional
  printf '\n'    # require full sequence? default yes
  printf '\n'    # require wg validate? default yes
  printf '\n'    # require wg soak? default yes
  printf '\n'    # max wg soak failed rounds default 0
  printf '\n'    # require run-report stages default no
  printf '\n'    # require incident snapshot on fail default no
  printf '\n'    # require incident snapshot artifacts default no
  printf '\n'    # show summary json? default no
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT38"
run_ui "$INPUT38" "$TMP_DIR/run38.log"

line38="$(rg '^prod-gate-signoff ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line38" ]]; then
  echo "runtime wiring failed: option 38 did not invoke prod-gate-signoff"
  cat "$TMP_DIR/run38.log"
  exit 1
fi
assert_line_has "$line38" '--check-tar-sha256 1' \
  "runtime wiring failed: option 38 missing --check-tar-sha256 1"
assert_line_has "$line38" '--check-manifest 1' \
  "runtime wiring failed: option 38 missing --check-manifest 1"
assert_line_has "$line38" '--require-full-sequence 1' \
  "runtime wiring failed: option 38 missing --require-full-sequence 1"
assert_line_has "$line38" '--require-wg-validate-ok 1' \
  "runtime wiring failed: option 38 missing --require-wg-validate-ok 1"
assert_line_has "$line38" '--require-wg-soak-ok 1' \
  "runtime wiring failed: option 38 missing --require-wg-soak-ok 1"
assert_line_has "$line38" '--require-preflight-ok 0' \
  "runtime wiring failed: option 38 missing --require-preflight-ok 0 default"
assert_line_has "$line38" '--require-bundle-ok 0' \
  "runtime wiring failed: option 38 missing --require-bundle-ok 0 default"
assert_line_has "$line38" '--require-integrity-ok 0' \
  "runtime wiring failed: option 38 missing --require-integrity-ok 0 default"
assert_line_has "$line38" '--require-signoff-ok 0' \
  "runtime wiring failed: option 38 missing --require-signoff-ok 0 default"
assert_line_has "$line38" '--require-incident-snapshot-on-fail 0' \
  "runtime wiring failed: option 38 missing --require-incident-snapshot-on-fail 0 default"
assert_line_has "$line38" '--require-incident-snapshot-artifacts 0' \
  "runtime wiring failed: option 38 missing --require-incident-snapshot-artifacts 0 default"
assert_line_has "$line38" '--require-wg-validate-udp-source 1' \
  "runtime wiring failed: option 38 missing --require-wg-validate-udp-source 1"
assert_line_has "$line38" '--require-wg-validate-strict-distinct 1' \
  "runtime wiring failed: option 38 missing --require-wg-validate-strict-distinct 1"
assert_line_has "$line38" '--require-wg-soak-diversity-pass 1' \
  "runtime wiring failed: option 38 missing --require-wg-soak-diversity-pass 1"
assert_line_has "$line38" '--min-wg-soak-selection-lines 12' \
  "runtime wiring failed: option 38 missing --min-wg-soak-selection-lines 12"
assert_line_has "$line38" '--min-wg-soak-entry-operators 2' \
  "runtime wiring failed: option 38 missing --min-wg-soak-entry-operators 2"
assert_line_has "$line38" '--min-wg-soak-exit-operators 2' \
  "runtime wiring failed: option 38 missing --min-wg-soak-exit-operators 2"
assert_line_has "$line38" '--min-wg-soak-cross-operator-pairs 2' \
  "runtime wiring failed: option 38 missing --min-wg-soak-cross-operator-pairs 2"
assert_line_has "$line38" '--run-report-json \.easy-node-logs/prod_gate_bundle_quick/prod_bundle_run_report\.json' \
  "runtime wiring failed: option 38 missing default run-report path"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 39 (prod pilot runbook) runtime command forwarding"
INPUT39="$TMP_DIR/input39.txt"
{
  printf '3\n'   # main menu: advanced
  printf '39\n'  # prod pilot runbook
  printf '\n'    # auto-discover (default yes)
  printf '\n'    # bootstrap directory URL (default hosts.a)
  printf '\n'    # subject optional
  printf '\n'    # bundle dir
  printf '\n'    # report optional
  printf 'y\n'   # run pre-real-host readiness first? yes
  printf 'n\n'   # run with sudo? no
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT39"
run_ui "$INPUT39" "$TMP_DIR/run39.log"

line39="$(rg '^prod-pilot-runbook ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line39" ]]; then
  echo "runtime wiring failed: option 39 did not invoke prod-pilot-runbook"
  cat "$TMP_DIR/run39.log"
  exit 1
fi
assert_line_has "$line39" '--bootstrap-directory http://198\.51\.100\.10:8081' \
  "runtime wiring failed: option 39 missing default bootstrap directory"
assert_line_has "$line39" '--bundle-dir \.easy-node-logs/prod_pilot_bundle' \
  "runtime wiring failed: option 39 missing default pilot bundle dir"
assert_line_has "$line39" '--run-report-json \.easy-node-logs/prod_pilot_bundle/prod_bundle_run_report\.json' \
  "runtime wiring failed: option 39 missing default pilot run-report path"
assert_line_has "$line39" '--run-report-print 1' \
  "runtime wiring failed: option 39 missing --run-report-print 1"
assert_line_has "$line39" '--pre-real-host-readiness 1' \
  "runtime wiring failed: option 39 missing --pre-real-host-readiness 1"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 40 (incident snapshot) runtime command forwarding"
INPUT40="$TMP_DIR/input40.txt"
{
  printf '3\n'   # main menu: advanced
  printf '40\n'  # incident snapshot
  printf '\n'    # mode default auto
  printf '\n'    # bundle directory default
  printf '\n'    # compose project default
  printf '\n'    # include docker logs default yes
  printf '\n'    # docker log lines default
  printf '\n'    # timeout sec default
  printf '\n'    # override endpoints manually? default no
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT40"
run_ui "$INPUT40" "$TMP_DIR/run40.log"

line40="$(rg '^incident-snapshot ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line40" ]]; then
  echo "runtime wiring failed: option 40 did not invoke incident-snapshot"
  cat "$TMP_DIR/run40.log"
  exit 1
fi
assert_line_has "$line40" '--mode auto' \
  "runtime wiring failed: option 40 missing default --mode auto"
assert_line_has "$line40" '--bundle-dir \.easy-node-logs/incident_snapshot' \
  "runtime wiring failed: option 40 missing default bundle dir"
assert_line_has "$line40" '--compose-project deploy' \
  "runtime wiring failed: option 40 missing default compose project"
assert_line_has "$line40" '--include-docker-logs 1' \
  "runtime wiring failed: option 40 missing --include-docker-logs 1 default"
assert_line_has "$line40" '--docker-log-lines 200' \
  "runtime wiring failed: option 40 missing default docker-log-lines"
assert_line_has "$line40" '--timeout-sec 8' \
  "runtime wiring failed: option 40 missing default timeout-sec"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 41 (prod gate slo summary) runtime command forwarding"
INPUT41="$TMP_DIR/input41.txt"
{
  printf '3\n'   # main menu: advanced
  printf '41\n'  # prod gate slo summary
  printf '\n'    # bundle dir override optional
  printf '\n'    # run report json path default
  printf '\n'    # gate summary json optional
  printf '\n'    # wg validate summary json optional
  printf '\n'    # wg soak summary json optional
  printf '\n'    # require full sequence default yes
  printf '\n'    # require wg validate default yes
  printf '\n'    # require wg soak default yes
  printf '\n'    # max wg soak failed rounds default 0
  printf '\n'    # require run report stages default no
  printf '\n'    # fail on no-go default no
  printf '\n'    # show json default no
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT41"
run_ui "$INPUT41" "$TMP_DIR/run41.log"

line41="$(rg '^prod-gate-slo-summary ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line41" ]]; then
  echo "runtime wiring failed: option 41 did not invoke prod-gate-slo-summary"
  cat "$TMP_DIR/run41.log"
  exit 1
fi
assert_line_has "$line41" '--require-full-sequence 1' \
  "runtime wiring failed: option 41 missing --require-full-sequence 1 default"
assert_line_has "$line41" '--require-wg-validate-ok 1' \
  "runtime wiring failed: option 41 missing --require-wg-validate-ok 1 default"
assert_line_has "$line41" '--require-wg-soak-ok 1' \
  "runtime wiring failed: option 41 missing --require-wg-soak-ok 1 default"
assert_line_has "$line41" '--require-wg-validate-udp-source 1' \
  "runtime wiring failed: option 41 missing --require-wg-validate-udp-source 1 default"
assert_line_has "$line41" '--require-wg-validate-strict-distinct 1' \
  "runtime wiring failed: option 41 missing --require-wg-validate-strict-distinct 1 default"
assert_line_has "$line41" '--require-wg-soak-diversity-pass 1' \
  "runtime wiring failed: option 41 missing --require-wg-soak-diversity-pass 1 default"
assert_line_has "$line41" '--min-wg-soak-selection-lines 8' \
  "runtime wiring failed: option 41 missing --min-wg-soak-selection-lines 8 default"
assert_line_has "$line41" '--min-wg-soak-entry-operators 2' \
  "runtime wiring failed: option 41 missing --min-wg-soak-entry-operators 2 default"
assert_line_has "$line41" '--min-wg-soak-exit-operators 2' \
  "runtime wiring failed: option 41 missing --min-wg-soak-exit-operators 2 default"
assert_line_has "$line41" '--min-wg-soak-cross-operator-pairs 1' \
  "runtime wiring failed: option 41 missing --min-wg-soak-cross-operator-pairs 1 default"
assert_line_has "$line41" '--max-wg-soak-failed-rounds 0' \
  "runtime wiring failed: option 41 missing default max-wg-soak-failed-rounds"
assert_line_has "$line41" '--require-preflight-ok 0' \
  "runtime wiring failed: option 41 missing default require-preflight-ok 0"
assert_line_has "$line41" '--require-bundle-ok 0' \
  "runtime wiring failed: option 41 missing default require-bundle-ok 0"
assert_line_has "$line41" '--require-integrity-ok 0' \
  "runtime wiring failed: option 41 missing default require-integrity-ok 0"
assert_line_has "$line41" '--require-signoff-ok 0' \
  "runtime wiring failed: option 41 missing default require-signoff-ok 0"
assert_line_has "$line41" '--require-incident-snapshot-on-fail 0' \
  "runtime wiring failed: option 41 missing default require-incident-snapshot-on-fail 0"
assert_line_has "$line41" '--require-incident-snapshot-artifacts 0' \
  "runtime wiring failed: option 41 missing default require-incident-snapshot-artifacts 0"
assert_line_has "$line41" '--fail-on-no-go 0' \
  "runtime wiring failed: option 41 missing default fail-on-no-go 0"
assert_line_has "$line41" '--show-json 0' \
  "runtime wiring failed: option 41 missing default show-json 0"
assert_line_has "$line41" '--run-report-json \.easy-node-logs/prod_gate_bundle/prod_bundle_run_report\.json' \
  "runtime wiring failed: option 41 missing default run-report path"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 42 (prod gate slo trend) runtime command forwarding"
INPUT42="$TMP_DIR/input42.txt"
{
  printf '3\n'   # main menu: advanced
  printf '42\n'  # prod gate slo trend
  printf '\n'    # reports dir default
  printf '\n'    # max reports default
  printf '\n'    # since hours default
  printf '\n'    # require full sequence default yes
  printf '\n'    # require wg validate default yes
  printf '\n'    # require wg soak default yes
  printf '\n'    # max wg soak failed rounds default 0
  printf '\n'    # require run report stages default no
  printf '\n'    # fail on any no-go default no
  printf '\n'    # min go rate pct default 0
  printf '\n'    # show details default yes
  printf '\n'    # show top reasons default 5
  printf '\n'    # summary json optional
  printf '\n'    # print summary json default no
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT42"
run_ui "$INPUT42" "$TMP_DIR/run42.log"

line42="$(rg '^prod-gate-slo-trend ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line42" ]]; then
  echo "runtime wiring failed: option 42 did not invoke prod-gate-slo-trend"
  cat "$TMP_DIR/run42.log"
  exit 1
fi
assert_line_has "$line42" '--reports-dir \.easy-node-logs' \
  "runtime wiring failed: option 42 missing default reports dir"
assert_line_has "$line42" '--max-reports 25' \
  "runtime wiring failed: option 42 missing default max-reports"
assert_line_has "$line42" '--since-hours 0' \
  "runtime wiring failed: option 42 missing default since-hours"
assert_line_has "$line42" '--require-full-sequence 1' \
  "runtime wiring failed: option 42 missing --require-full-sequence 1 default"
assert_line_has "$line42" '--require-wg-validate-ok 1' \
  "runtime wiring failed: option 42 missing --require-wg-validate-ok 1 default"
assert_line_has "$line42" '--require-wg-soak-ok 1' \
  "runtime wiring failed: option 42 missing --require-wg-soak-ok 1 default"
assert_line_has "$line42" '--require-wg-validate-udp-source 1' \
  "runtime wiring failed: option 42 missing --require-wg-validate-udp-source 1 default"
assert_line_has "$line42" '--require-wg-validate-strict-distinct 1' \
  "runtime wiring failed: option 42 missing --require-wg-validate-strict-distinct 1 default"
assert_line_has "$line42" '--require-wg-soak-diversity-pass 1' \
  "runtime wiring failed: option 42 missing --require-wg-soak-diversity-pass 1 default"
assert_line_has "$line42" '--min-wg-soak-selection-lines 8' \
  "runtime wiring failed: option 42 missing --min-wg-soak-selection-lines 8 default"
assert_line_has "$line42" '--min-wg-soak-entry-operators 2' \
  "runtime wiring failed: option 42 missing --min-wg-soak-entry-operators 2 default"
assert_line_has "$line42" '--min-wg-soak-exit-operators 2' \
  "runtime wiring failed: option 42 missing --min-wg-soak-exit-operators 2 default"
assert_line_has "$line42" '--min-wg-soak-cross-operator-pairs 1' \
  "runtime wiring failed: option 42 missing --min-wg-soak-cross-operator-pairs 1 default"
assert_line_has "$line42" '--max-wg-soak-failed-rounds 0' \
  "runtime wiring failed: option 42 missing default max-wg-soak-failed-rounds"
assert_line_has "$line42" '--require-incident-snapshot-on-fail 0' \
  "runtime wiring failed: option 42 missing default require-incident-snapshot-on-fail 0"
assert_line_has "$line42" '--require-incident-snapshot-artifacts 0' \
  "runtime wiring failed: option 42 missing default require-incident-snapshot-artifacts 0"
assert_line_has "$line42" '--fail-on-any-no-go 0' \
  "runtime wiring failed: option 42 missing default fail-on-any-no-go 0"
assert_line_has "$line42" '--min-go-rate-pct 0' \
  "runtime wiring failed: option 42 missing default min-go-rate-pct"
assert_line_has "$line42" '--show-details 1' \
  "runtime wiring failed: option 42 missing default show-details 1"
assert_line_has "$line42" '--show-top-reasons 5' \
  "runtime wiring failed: option 42 missing default show-top-reasons 5"
assert_line_has "$line42" '--print-summary-json 0' \
  "runtime wiring failed: option 42 missing default print-summary-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 43 (prod gate slo alert) runtime command forwarding"
INPUT43="$TMP_DIR/input43.txt"
{
  printf '3\n'   # main menu: advanced
  printf '43\n'  # prod gate slo alert
  printf '\n'    # use trend summary json? default no
  printf '\n'    # reports dir default
  printf '\n'    # max reports default
  printf '\n'    # since hours default
  printf '\n'    # warn go rate pct default
  printf '\n'    # critical go rate pct default
  printf '\n'    # warn no-go count default
  printf '\n'    # critical no-go count default
  printf '\n'    # warn eval errors default
  printf '\n'    # critical eval errors default
  printf '\n'    # fail on warn default no
  printf '\n'    # fail on critical default no
  printf '\n'    # show top reasons default
  printf '\n'    # summary json optional
  printf '\n'    # print summary json default no
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT43"
run_ui "$INPUT43" "$TMP_DIR/run43.log"

line43="$(rg '^prod-gate-slo-alert ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line43" ]]; then
  echo "runtime wiring failed: option 43 did not invoke prod-gate-slo-alert"
  cat "$TMP_DIR/run43.log"
  exit 1
fi
assert_line_has "$line43" '--reports-dir \.easy-node-logs' \
  "runtime wiring failed: option 43 missing default reports dir"
assert_line_has "$line43" '--max-reports 25' \
  "runtime wiring failed: option 43 missing default max-reports"
assert_line_has "$line43" '--since-hours 24' \
  "runtime wiring failed: option 43 missing default since-hours"
assert_line_has "$line43" '--require-wg-validate-udp-source 1' \
  "runtime wiring failed: option 43 missing --require-wg-validate-udp-source 1 default"
assert_line_has "$line43" '--require-wg-validate-strict-distinct 1' \
  "runtime wiring failed: option 43 missing --require-wg-validate-strict-distinct 1 default"
assert_line_has "$line43" '--require-wg-soak-diversity-pass 1' \
  "runtime wiring failed: option 43 missing --require-wg-soak-diversity-pass 1 default"
assert_line_has "$line43" '--min-wg-soak-selection-lines 8' \
  "runtime wiring failed: option 43 missing --min-wg-soak-selection-lines 8 default"
assert_line_has "$line43" '--min-wg-soak-entry-operators 2' \
  "runtime wiring failed: option 43 missing --min-wg-soak-entry-operators 2 default"
assert_line_has "$line43" '--min-wg-soak-exit-operators 2' \
  "runtime wiring failed: option 43 missing --min-wg-soak-exit-operators 2 default"
assert_line_has "$line43" '--min-wg-soak-cross-operator-pairs 1' \
  "runtime wiring failed: option 43 missing --min-wg-soak-cross-operator-pairs 1 default"
assert_line_has "$line43" '--warn-go-rate-pct 98' \
  "runtime wiring failed: option 43 missing default warn-go-rate-pct"
assert_line_has "$line43" '--critical-go-rate-pct 90' \
  "runtime wiring failed: option 43 missing default critical-go-rate-pct"
assert_line_has "$line43" '--warn-no-go-count 1' \
  "runtime wiring failed: option 43 missing default warn-no-go-count"
assert_line_has "$line43" '--critical-no-go-count 2' \
  "runtime wiring failed: option 43 missing default critical-no-go-count"
assert_line_has "$line43" '--warn-eval-errors 1' \
  "runtime wiring failed: option 43 missing default warn-eval-errors"
assert_line_has "$line43" '--critical-eval-errors 2' \
  "runtime wiring failed: option 43 missing default critical-eval-errors"
assert_line_has "$line43" '--fail-on-warn 0' \
  "runtime wiring failed: option 43 missing default fail-on-warn 0"
assert_line_has "$line43" '--fail-on-critical 0' \
  "runtime wiring failed: option 43 missing default fail-on-critical 0"
assert_line_has "$line43" '--show-top-reasons 5' \
  "runtime wiring failed: option 43 missing default show-top-reasons 5"
assert_line_has "$line43" '--print-summary-json 0' \
  "runtime wiring failed: option 43 missing default print-summary-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 44 (prod gate slo dashboard) runtime command forwarding"
INPUT44="$TMP_DIR/input44.txt"
{
  printf '3\n'   # main menu: advanced
  printf '44\n'  # prod gate slo dashboard
  printf '\n'    # reports dir default
  printf '\n'    # max reports default
  printf '\n'    # since hours default
  printf '\n'    # require full sequence default yes
  printf '\n'    # require wg validate default yes
  printf '\n'    # require wg soak default yes
  printf '\n'    # max wg soak failed rounds default 0
  printf '\n'    # require run report stages default no
  printf '\n'    # fail on any no-go default no
  printf '\n'    # min go rate pct default 95
  printf '\n'    # show top reasons default 5
  printf '\n'    # warn go rate pct default 98
  printf '\n'    # critical go rate pct default 90
  printf '\n'    # warn no-go count default 1
  printf '\n'    # critical no-go count default 2
  printf '\n'    # warn eval errors default 1
  printf '\n'    # critical eval errors default 2
  printf '\n'    # fail on warn default no
  printf '\n'    # fail on critical default no
  printf '\n'    # trend summary json default
  printf '\n'    # alert summary json default
  printf '\n'    # dashboard markdown default
  printf '\n'    # print dashboard default yes
  printf '\n'    # print summary json default no
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT44"
run_ui "$INPUT44" "$TMP_DIR/run44.log"

line44="$(rg '^prod-gate-slo-dashboard ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line44" ]]; then
  echo "runtime wiring failed: option 44 did not invoke prod-gate-slo-dashboard"
  cat "$TMP_DIR/run44.log"
  exit 1
fi
assert_line_has "$line44" '--reports-dir \.easy-node-logs' \
  "runtime wiring failed: option 44 missing default reports dir"
assert_line_has "$line44" '--max-reports 25' \
  "runtime wiring failed: option 44 missing default max-reports"
assert_line_has "$line44" '--since-hours 24' \
  "runtime wiring failed: option 44 missing default since-hours"
assert_line_has "$line44" '--require-full-sequence 1' \
  "runtime wiring failed: option 44 missing --require-full-sequence 1 default"
assert_line_has "$line44" '--require-wg-validate-ok 1' \
  "runtime wiring failed: option 44 missing --require-wg-validate-ok 1 default"
assert_line_has "$line44" '--require-wg-soak-ok 1' \
  "runtime wiring failed: option 44 missing --require-wg-soak-ok 1 default"
assert_line_has "$line44" '--require-wg-validate-udp-source 1' \
  "runtime wiring failed: option 44 missing --require-wg-validate-udp-source 1 default"
assert_line_has "$line44" '--require-wg-validate-strict-distinct 1' \
  "runtime wiring failed: option 44 missing --require-wg-validate-strict-distinct 1 default"
assert_line_has "$line44" '--require-wg-soak-diversity-pass 1' \
  "runtime wiring failed: option 44 missing --require-wg-soak-diversity-pass 1 default"
assert_line_has "$line44" '--min-wg-soak-selection-lines 8' \
  "runtime wiring failed: option 44 missing --min-wg-soak-selection-lines 8 default"
assert_line_has "$line44" '--min-wg-soak-entry-operators 2' \
  "runtime wiring failed: option 44 missing --min-wg-soak-entry-operators 2 default"
assert_line_has "$line44" '--min-wg-soak-exit-operators 2' \
  "runtime wiring failed: option 44 missing --min-wg-soak-exit-operators 2 default"
assert_line_has "$line44" '--min-wg-soak-cross-operator-pairs 1' \
  "runtime wiring failed: option 44 missing --min-wg-soak-cross-operator-pairs 1 default"
assert_line_has "$line44" '--max-wg-soak-failed-rounds 0' \
  "runtime wiring failed: option 44 missing default max-wg-soak-failed-rounds"
assert_line_has "$line44" '--require-incident-snapshot-on-fail 0' \
  "runtime wiring failed: option 44 missing default require-incident-snapshot-on-fail 0"
assert_line_has "$line44" '--require-incident-snapshot-artifacts 0' \
  "runtime wiring failed: option 44 missing default require-incident-snapshot-artifacts 0"
assert_line_has "$line44" '--fail-on-any-no-go 0' \
  "runtime wiring failed: option 44 missing default fail-on-any-no-go 0"
assert_line_has "$line44" '--min-go-rate-pct 95' \
  "runtime wiring failed: option 44 missing default min-go-rate-pct"
assert_line_has "$line44" '--show-top-reasons 5' \
  "runtime wiring failed: option 44 missing default show-top-reasons 5"
assert_line_has "$line44" '--warn-go-rate-pct 98' \
  "runtime wiring failed: option 44 missing default warn-go-rate-pct"
assert_line_has "$line44" '--critical-go-rate-pct 90' \
  "runtime wiring failed: option 44 missing default critical-go-rate-pct"
assert_line_has "$line44" '--warn-no-go-count 1' \
  "runtime wiring failed: option 44 missing default warn-no-go-count"
assert_line_has "$line44" '--critical-no-go-count 2' \
  "runtime wiring failed: option 44 missing default critical-no-go-count"
assert_line_has "$line44" '--warn-eval-errors 1' \
  "runtime wiring failed: option 44 missing default warn-eval-errors"
assert_line_has "$line44" '--critical-eval-errors 2' \
  "runtime wiring failed: option 44 missing default critical-eval-errors"
assert_line_has "$line44" '--fail-on-warn 0' \
  "runtime wiring failed: option 44 missing default fail-on-warn 0"
assert_line_has "$line44" '--fail-on-critical 0' \
  "runtime wiring failed: option 44 missing default fail-on-critical 0"
assert_line_has "$line44" '--trend-summary-json \.easy-node-logs/prod_slo_trend_24h\.json' \
  "runtime wiring failed: option 44 missing default trend-summary-json path"
assert_line_has "$line44" '--alert-summary-json \.easy-node-logs/prod_slo_alert_24h\.json' \
  "runtime wiring failed: option 44 missing default alert-summary-json path"
assert_line_has "$line44" '--dashboard-md \.easy-node-logs/prod_slo_dashboard_24h\.md' \
  "runtime wiring failed: option 44 missing default dashboard-md path"
assert_line_has "$line44" '--print-dashboard 1' \
  "runtime wiring failed: option 44 missing default print-dashboard 1"
assert_line_has "$line44" '--print-summary-json 0' \
  "runtime wiring failed: option 44 missing default print-summary-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 45 (prod key-rotation runbook) runtime command forwarding"
INPUT45="$TMP_DIR/input45.txt"
{
  printf '3\n'   # main menu: advanced
  printf '45\n'  # prod key-rotation runbook
  for _ in $(seq 1 24); do
    printf '\n'  # accept defaults
  done
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT45"
run_ui "$INPUT45" "$TMP_DIR/run45.log"

line45="$(rg '^prod-key-rotation-runbook ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line45" ]]; then
  echo "runtime wiring failed: option 45 did not invoke prod-key-rotation-runbook"
  cat "$TMP_DIR/run45.log"
  exit 1
fi
assert_line_has "$line45" '--mode auto' \
  "runtime wiring failed: option 45 missing default --mode auto"
assert_line_has "$line45" '--backup-dir \.easy-node-logs/prod_key_rotation_manual' \
  "runtime wiring failed: option 45 missing default backup dir"
assert_line_has "$line45" '--preflight-check 1' \
  "runtime wiring failed: option 45 missing default --preflight-check 1"
assert_line_has "$line45" '--preflight-live 0' \
  "runtime wiring failed: option 45 missing default --preflight-live 0"
assert_line_has "$line45" '--preflight-timeout-sec 12' \
  "runtime wiring failed: option 45 missing default --preflight-timeout-sec 12"
assert_line_has "$line45" '--rotate-server-secrets 1' \
  "runtime wiring failed: option 45 missing default --rotate-server-secrets 1"
assert_line_has "$line45" '--rotate-admin-signing 1' \
  "runtime wiring failed: option 45 missing default --rotate-admin-signing 1"
assert_line_has "$line45" '--key-history 3' \
  "runtime wiring failed: option 45 missing default --key-history 3"
assert_line_has "$line45" '--restart 1' \
  "runtime wiring failed: option 45 missing default --restart 1"
assert_line_has "$line45" '--restart-issuer 1' \
  "runtime wiring failed: option 45 missing default --restart-issuer 1"
assert_line_has "$line45" '--rollback-on-fail 1' \
  "runtime wiring failed: option 45 missing default --rollback-on-fail 1"
assert_line_has "$line45" '--restart-after-rollback 1' \
  "runtime wiring failed: option 45 missing default --restart-after-rollback 1"
assert_line_has "$line45" '--print-summary-json 0' \
  "runtime wiring failed: option 45 missing default --print-summary-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 46 (prod upgrade runbook) runtime command forwarding"
INPUT46="$TMP_DIR/input46.txt"
{
  printf '3\n'   # main menu: advanced
  printf '46\n'  # prod upgrade runbook
  for _ in $(seq 1 20); do
    printf '\n'  # accept defaults
  done
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT46"
run_ui "$INPUT46" "$TMP_DIR/run46.log"

line46="$(rg '^prod-upgrade-runbook ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line46" ]]; then
  echo "runtime wiring failed: option 46 did not invoke prod-upgrade-runbook"
  cat "$TMP_DIR/run46.log"
  exit 1
fi
assert_line_has "$line46" '--mode auto' \
  "runtime wiring failed: option 46 missing default --mode auto"
assert_line_has "$line46" '--backup-dir \.easy-node-logs/prod_upgrade_manual' \
  "runtime wiring failed: option 46 missing default backup dir"
assert_line_has "$line46" '--preflight-check 1' \
  "runtime wiring failed: option 46 missing default --preflight-check 1"
assert_line_has "$line46" '--preflight-live 0' \
  "runtime wiring failed: option 46 missing default --preflight-live 0"
assert_line_has "$line46" '--preflight-timeout-sec 12' \
  "runtime wiring failed: option 46 missing default --preflight-timeout-sec 12"
assert_line_has "$line46" '--compose-pull 1' \
  "runtime wiring failed: option 46 missing default --compose-pull 1"
assert_line_has "$line46" '--compose-build 0' \
  "runtime wiring failed: option 46 missing default --compose-build 0"
assert_line_has "$line46" '--restart 1' \
  "runtime wiring failed: option 46 missing default --restart 1"
assert_line_has "$line46" '--rollback-on-fail 1' \
  "runtime wiring failed: option 46 missing default --rollback-on-fail 1"
assert_line_has "$line46" '--restart-after-rollback 1' \
  "runtime wiring failed: option 46 missing default --restart-after-rollback 1"
assert_line_has "$line46" '--print-summary-json 0' \
  "runtime wiring failed: option 46 missing default --print-summary-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 47 (prod operator lifecycle runbook) runtime command forwarding"
INPUT47="$TMP_DIR/input47.txt"
{
  printf '3\n'   # main menu: advanced
  printf '47\n'  # prod operator lifecycle runbook
  for _ in $(seq 1 26); do
    printf '\n'  # accept defaults
  done
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT47"
run_ui "$INPUT47" "$TMP_DIR/run47.log"

line47="$(rg '^prod-operator-lifecycle-runbook ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line47" ]]; then
  echo "runtime wiring failed: option 47 did not invoke prod-operator-lifecycle-runbook"
  cat "$TMP_DIR/run47.log"
  exit 1
fi
assert_line_has "$line47" '--action onboard' \
  "runtime wiring failed: option 47 missing default --action onboard"
assert_line_has "$line47" '--mode auto' \
  "runtime wiring failed: option 47 missing default --mode auto"
assert_line_has "$line47" '--preflight-check 1' \
  "runtime wiring failed: option 47 missing default --preflight-check 1"
assert_line_has "$line47" '--preflight-timeout-sec 30' \
  "runtime wiring failed: option 47 missing default --preflight-timeout-sec 30"
assert_line_has "$line47" '--health-check 1' \
  "runtime wiring failed: option 47 missing default --health-check 1"
assert_line_has "$line47" '--health-timeout-sec 60' \
  "runtime wiring failed: option 47 missing default --health-timeout-sec 60"
assert_line_has "$line47" '--verify-relays 1' \
  "runtime wiring failed: option 47 missing default --verify-relays 1"
assert_line_has "$line47" '--verify-absent 1' \
  "runtime wiring failed: option 47 missing default --verify-absent 1"
assert_line_has "$line47" '--verify-relay-timeout-sec 90' \
  "runtime wiring failed: option 47 missing default --verify-relay-timeout-sec 90"
assert_line_has "$line47" '--verify-relay-min-count 2' \
  "runtime wiring failed: option 47 missing default --verify-relay-min-count 2"
assert_line_has "$line47" '--print-summary-json 0' \
  "runtime wiring failed: option 47 missing default --print-summary-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 48 (prod pilot cohort runbook) runtime command forwarding"
INPUT48="$TMP_DIR/input48.txt"
{
  printf '3\n'   # main menu: advanced
  printf '48\n'  # prod pilot cohort runbook
  for _ in $(seq 1 23); do
    printf '\n'  # accept defaults
  done
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT48"
run_ui "$INPUT48" "$TMP_DIR/run48.log"

line48="$(rg '^prod-pilot-cohort-runbook ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line48" ]]; then
  echo "runtime wiring failed: option 48 did not invoke prod-pilot-cohort-runbook"
  cat "$TMP_DIR/run48.log"
  exit 1
fi
assert_line_has "$line48" '--rounds 5' \
  "runtime wiring failed: option 48 missing default --rounds 5"
assert_line_has "$line48" '--pause-sec 60' \
  "runtime wiring failed: option 48 missing default --pause-sec 60"
assert_line_has "$line48" '--continue-on-fail 0' \
  "runtime wiring failed: option 48 missing default --continue-on-fail 0"
assert_line_has "$line48" '--require-all-rounds-ok 1' \
  "runtime wiring failed: option 48 missing default --require-all-rounds-ok 1"
assert_line_has "$line48" '--trend-min-go-rate-pct 95' \
  "runtime wiring failed: option 48 missing default --trend-min-go-rate-pct 95"
assert_line_has "$line48" '--trend-require-wg-validate-udp-source 1' \
  "runtime wiring failed: option 48 missing strict trend --trend-require-wg-validate-udp-source 1"
assert_line_has "$line48" '--trend-require-wg-validate-strict-distinct 1' \
  "runtime wiring failed: option 48 missing strict trend --trend-require-wg-validate-strict-distinct 1"
assert_line_has "$line48" '--trend-require-wg-soak-diversity-pass 1' \
  "runtime wiring failed: option 48 missing strict trend --trend-require-wg-soak-diversity-pass 1"
assert_line_has "$line48" '--trend-min-wg-soak-selection-lines 12' \
  "runtime wiring failed: option 48 missing strict trend --trend-min-wg-soak-selection-lines 12"
assert_line_has "$line48" '--trend-min-wg-soak-entry-operators 2' \
  "runtime wiring failed: option 48 missing strict trend --trend-min-wg-soak-entry-operators 2"
assert_line_has "$line48" '--trend-min-wg-soak-exit-operators 2' \
  "runtime wiring failed: option 48 missing strict trend --trend-min-wg-soak-exit-operators 2"
assert_line_has "$line48" '--trend-min-wg-soak-cross-operator-pairs 2' \
  "runtime wiring failed: option 48 missing strict trend --trend-min-wg-soak-cross-operator-pairs 2"
assert_line_has "$line48" '--max-alert-severity WARN' \
  "runtime wiring failed: option 48 missing default --max-alert-severity WARN"
assert_line_has "$line48" '--bundle-outputs 1' \
  "runtime wiring failed: option 48 missing default --bundle-outputs 1"
assert_line_has "$line48" '--bundle-fail-close 1' \
  "runtime wiring failed: option 48 missing default --bundle-fail-close 1"
assert_line_has "$line48" '--pre-real-host-readiness 1' \
  "runtime wiring failed: option 48 missing default --pre-real-host-readiness 1"
assert_line_has "$line48" '--print-summary-json 0' \
  "runtime wiring failed: option 48 missing default --print-summary-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 49 (prod pilot cohort bundle verify) runtime command forwarding"
INPUT49="$TMP_DIR/input49.txt"
{
  printf '3\n'   # main menu: advanced
  printf '49\n'  # prod pilot cohort bundle verify
  for _ in $(seq 1 16); do
    printf '\n'  # accept defaults
  done
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT49"
run_ui "$INPUT49" "$TMP_DIR/run49.log"

line49="$(rg '^prod-pilot-cohort-bundle-verify ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line49" ]]; then
  echo "runtime wiring failed: option 49 did not invoke prod-pilot-cohort-bundle-verify"
  cat "$TMP_DIR/run49.log"
  exit 1
fi
assert_line_has "$line49" '--summary-json \.easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary\.json' \
  "runtime wiring failed: option 49 missing default summary-json path"
assert_line_has "$line49" '--check-tar-sha256 1' \
  "runtime wiring failed: option 49 missing default --check-tar-sha256 1"
assert_line_has "$line49" '--check-manifest 1' \
  "runtime wiring failed: option 49 missing default --check-manifest 1"
assert_line_has "$line49" '--show-details 0' \
  "runtime wiring failed: option 49 missing default --show-details 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 50 (prod pilot cohort signoff) runtime command forwarding"
INPUT50="$TMP_DIR/input50.txt"
{
  printf '3\n'   # main menu: advanced
  printf '50\n'  # prod pilot cohort signoff
  for _ in $(seq 1 24); do
    printf '\n'  # accept defaults
  done
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT50"
run_ui "$INPUT50" "$TMP_DIR/run50.log"

line50="$(rg '^prod-pilot-cohort-signoff ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line50" ]]; then
  echo "runtime wiring failed: option 50 did not invoke prod-pilot-cohort-signoff"
  cat "$TMP_DIR/run50.log"
  exit 1
fi
assert_line_has "$line50" '--summary-json \.easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary\.json' \
  "runtime wiring failed: option 50 missing default summary-json path"
assert_line_has "$line50" '--check-tar-sha256 1' \
  "runtime wiring failed: option 50 missing default --check-tar-sha256 1"
assert_line_has "$line50" '--check-manifest 1' \
  "runtime wiring failed: option 50 missing default --check-manifest 1"
assert_line_has "$line50" '--show-integrity-details 0' \
  "runtime wiring failed: option 50 missing default --show-integrity-details 0"
assert_line_has "$line50" '--require-status-ok 1' \
  "runtime wiring failed: option 50 missing default --require-status-ok 1"
assert_line_has "$line50" '--require-all-rounds-ok 1' \
  "runtime wiring failed: option 50 missing default --require-all-rounds-ok 1"
assert_line_has "$line50" '--max-round-failures 0' \
  "runtime wiring failed: option 50 missing default --max-round-failures 0"
assert_line_has "$line50" '--require-trend-go 1' \
  "runtime wiring failed: option 50 missing default --require-trend-go 1"
assert_line_has "$line50" '--require-trend-artifact-policy-match 1' \
  "runtime wiring failed: option 50 missing strict trend --require-trend-artifact-policy-match 1"
assert_line_has "$line50" '--require-trend-wg-validate-udp-source 1' \
  "runtime wiring failed: option 50 missing strict trend --require-trend-wg-validate-udp-source 1"
assert_line_has "$line50" '--require-trend-wg-validate-strict-distinct 1' \
  "runtime wiring failed: option 50 missing strict trend --require-trend-wg-validate-strict-distinct 1"
assert_line_has "$line50" '--require-trend-wg-soak-diversity-pass 1' \
  "runtime wiring failed: option 50 missing strict trend --require-trend-wg-soak-diversity-pass 1"
assert_line_has "$line50" '--min-trend-wg-soak-selection-lines 12' \
  "runtime wiring failed: option 50 missing strict trend --min-trend-wg-soak-selection-lines 12"
assert_line_has "$line50" '--min-trend-wg-soak-entry-operators 2' \
  "runtime wiring failed: option 50 missing strict trend --min-trend-wg-soak-entry-operators 2"
assert_line_has "$line50" '--min-trend-wg-soak-exit-operators 2' \
  "runtime wiring failed: option 50 missing strict trend --min-trend-wg-soak-exit-operators 2"
assert_line_has "$line50" '--min-trend-wg-soak-cross-operator-pairs 2' \
  "runtime wiring failed: option 50 missing strict trend --min-trend-wg-soak-cross-operator-pairs 2"
assert_line_has "$line50" '--min-go-rate-pct 95' \
  "runtime wiring failed: option 50 missing default --min-go-rate-pct 95"
assert_line_has "$line50" '--max-alert-severity WARN' \
  "runtime wiring failed: option 50 missing default --max-alert-severity WARN"
assert_line_has "$line50" '--require-bundle-created 1' \
  "runtime wiring failed: option 50 missing default --require-bundle-created 1"
assert_line_has "$line50" '--require-bundle-manifest 1' \
  "runtime wiring failed: option 50 missing default --require-bundle-manifest 1"
assert_line_has "$line50" '--show-json 0' \
  "runtime wiring failed: option 50 missing default --show-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 51 (prod pilot cohort full flow) runtime command forwarding"
INPUT51="$TMP_DIR/input51.txt"
{
  printf '3\n'   # main menu: advanced
  printf '51\n'  # prod pilot cohort full flow
  for _ in $(seq 1 25); do
    printf '\n'  # accept defaults
  done
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT51"
run_ui "$INPUT51" "$TMP_DIR/run51.log"

line51_runbook="$(rg '^prod-pilot-cohort-runbook ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line51_runbook" ]]; then
  echo "runtime wiring failed: option 51 did not invoke prod-pilot-cohort-runbook stage"
  cat "$TMP_DIR/run51.log"
  exit 1
fi
assert_line_has "$line51_runbook" '--rounds 5' \
  "runtime wiring failed: option 51 runbook missing default --rounds 5"
assert_line_has "$line51_runbook" '--pause-sec 60' \
  "runtime wiring failed: option 51 runbook missing default --pause-sec 60"
assert_line_has "$line51_runbook" '--continue-on-fail 0' \
  "runtime wiring failed: option 51 runbook missing default --continue-on-fail 0"
assert_line_has "$line51_runbook" '--require-all-rounds-ok 1' \
  "runtime wiring failed: option 51 runbook missing default --require-all-rounds-ok 1"
assert_line_has "$line51_runbook" '--trend-min-go-rate-pct 95' \
  "runtime wiring failed: option 51 runbook missing default --trend-min-go-rate-pct 95"
assert_line_has "$line51_runbook" '--trend-require-wg-validate-udp-source 1' \
  "runtime wiring failed: option 51 runbook missing strict trend --trend-require-wg-validate-udp-source 1"
assert_line_has "$line51_runbook" '--trend-require-wg-validate-strict-distinct 1' \
  "runtime wiring failed: option 51 runbook missing strict trend --trend-require-wg-validate-strict-distinct 1"
assert_line_has "$line51_runbook" '--trend-require-wg-soak-diversity-pass 1' \
  "runtime wiring failed: option 51 runbook missing strict trend --trend-require-wg-soak-diversity-pass 1"
assert_line_has "$line51_runbook" '--trend-min-wg-soak-selection-lines 12' \
  "runtime wiring failed: option 51 runbook missing strict trend --trend-min-wg-soak-selection-lines 12"
assert_line_has "$line51_runbook" '--trend-min-wg-soak-entry-operators 2' \
  "runtime wiring failed: option 51 runbook missing strict trend --trend-min-wg-soak-entry-operators 2"
assert_line_has "$line51_runbook" '--trend-min-wg-soak-exit-operators 2' \
  "runtime wiring failed: option 51 runbook missing strict trend --trend-min-wg-soak-exit-operators 2"
assert_line_has "$line51_runbook" '--trend-min-wg-soak-cross-operator-pairs 2' \
  "runtime wiring failed: option 51 runbook missing strict trend --trend-min-wg-soak-cross-operator-pairs 2"
assert_line_has "$line51_runbook" '--max-alert-severity WARN' \
  "runtime wiring failed: option 51 runbook missing default --max-alert-severity WARN"
assert_line_has "$line51_runbook" '--bundle-outputs 1' \
  "runtime wiring failed: option 51 runbook missing default --bundle-outputs 1"
assert_line_has "$line51_runbook" '--bundle-fail-close 1' \
  "runtime wiring failed: option 51 runbook missing default --bundle-fail-close 1"
assert_line_has "$line51_runbook" '--pre-real-host-readiness 1' \
  "runtime wiring failed: option 51 runbook missing default --pre-real-host-readiness 1"
assert_line_has "$line51_runbook" '--reports-dir \.easy-node-logs/prod_pilot_cohort' \
  "runtime wiring failed: option 51 runbook missing default reports-dir"
assert_line_has "$line51_runbook" '--summary-json \.easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary\.json' \
  "runtime wiring failed: option 51 runbook missing default summary-json"
assert_line_has "$line51_runbook" '--print-summary-json 0' \
  "runtime wiring failed: option 51 runbook missing default --print-summary-json 0"

line51_signoff="$(rg '^prod-pilot-cohort-signoff ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line51_signoff" ]]; then
  echo "runtime wiring failed: option 51 did not invoke prod-pilot-cohort-signoff stage"
  cat "$TMP_DIR/run51.log"
  exit 1
fi
assert_line_has "$line51_signoff" '--summary-json \.easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary\.json' \
  "runtime wiring failed: option 51 signoff missing default summary-json"
assert_line_has "$line51_signoff" '--reports-dir \.easy-node-logs/prod_pilot_cohort' \
  "runtime wiring failed: option 51 signoff missing default reports-dir"
assert_line_has "$line51_signoff" '--check-tar-sha256 1' \
  "runtime wiring failed: option 51 signoff missing default --check-tar-sha256 1"
assert_line_has "$line51_signoff" '--check-manifest 1' \
  "runtime wiring failed: option 51 signoff missing default --check-manifest 1"
assert_line_has "$line51_signoff" '--show-integrity-details 0' \
  "runtime wiring failed: option 51 signoff missing default --show-integrity-details 0"
assert_line_has "$line51_signoff" '--require-status-ok 1' \
  "runtime wiring failed: option 51 signoff missing default --require-status-ok 1"
assert_line_has "$line51_signoff" '--require-all-rounds-ok 1' \
  "runtime wiring failed: option 51 signoff missing default --require-all-rounds-ok 1"
assert_line_has "$line51_signoff" '--max-round-failures 0' \
  "runtime wiring failed: option 51 signoff missing default --max-round-failures 0"
assert_line_has "$line51_signoff" '--require-trend-go 1' \
  "runtime wiring failed: option 51 signoff missing default --require-trend-go 1"
assert_line_has "$line51_signoff" '--require-trend-artifact-policy-match 1' \
  "runtime wiring failed: option 51 signoff missing strict trend --require-trend-artifact-policy-match 1"
assert_line_has "$line51_signoff" '--require-trend-wg-validate-udp-source 1' \
  "runtime wiring failed: option 51 signoff missing strict trend --require-trend-wg-validate-udp-source 1"
assert_line_has "$line51_signoff" '--require-trend-wg-validate-strict-distinct 1' \
  "runtime wiring failed: option 51 signoff missing strict trend --require-trend-wg-validate-strict-distinct 1"
assert_line_has "$line51_signoff" '--require-trend-wg-soak-diversity-pass 1' \
  "runtime wiring failed: option 51 signoff missing strict trend --require-trend-wg-soak-diversity-pass 1"
assert_line_has "$line51_signoff" '--min-trend-wg-soak-selection-lines 12' \
  "runtime wiring failed: option 51 signoff missing strict trend --min-trend-wg-soak-selection-lines 12"
assert_line_has "$line51_signoff" '--min-trend-wg-soak-entry-operators 2' \
  "runtime wiring failed: option 51 signoff missing strict trend --min-trend-wg-soak-entry-operators 2"
assert_line_has "$line51_signoff" '--min-trend-wg-soak-exit-operators 2' \
  "runtime wiring failed: option 51 signoff missing strict trend --min-trend-wg-soak-exit-operators 2"
assert_line_has "$line51_signoff" '--min-trend-wg-soak-cross-operator-pairs 2' \
  "runtime wiring failed: option 51 signoff missing strict trend --min-trend-wg-soak-cross-operator-pairs 2"
assert_line_has "$line51_signoff" '--min-go-rate-pct 95' \
  "runtime wiring failed: option 51 signoff missing default --min-go-rate-pct 95"
assert_line_has "$line51_signoff" '--max-alert-severity WARN' \
  "runtime wiring failed: option 51 signoff missing default --max-alert-severity WARN"
assert_line_has "$line51_signoff" '--require-bundle-created 1' \
  "runtime wiring failed: option 51 signoff missing default --require-bundle-created 1"
assert_line_has "$line51_signoff" '--require-bundle-manifest 1' \
  "runtime wiring failed: option 51 signoff missing default --require-bundle-manifest 1"
assert_line_has "$line51_signoff" '--show-json 0' \
  "runtime wiring failed: option 51 signoff missing default --show-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 52 (prod pilot cohort quick mode) runtime command forwarding"
INPUT52="$TMP_DIR/input52.txt"
{
  printf '3\n'   # main menu: advanced
  printf '52\n'  # prod pilot cohort quick
  for _ in $(seq 1 21); do
    printf '\n'  # accept defaults
  done
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT52"
run_ui "$INPUT52" "$TMP_DIR/run52.log"

line52="$(rg '^prod-pilot-cohort-quick ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line52" ]]; then
  echo "runtime wiring failed: option 52 did not invoke prod-pilot-cohort-quick"
  cat "$TMP_DIR/run52.log"
  exit 1
fi
assert_line_has "$line52" '--bootstrap-directory http://198\.51\.100\.10:8081' \
  "runtime wiring failed: option 52 missing default bootstrap directory"
assert_line_has "$line52" '--subject pilot-client' \
  "runtime wiring failed: option 52 missing default subject"
assert_line_has "$line52" '--rounds 5' \
  "runtime wiring failed: option 52 missing default --rounds 5"
assert_line_has "$line52" '--pause-sec 60' \
  "runtime wiring failed: option 52 missing default --pause-sec 60"
assert_line_has "$line52" '--continue-on-fail 0' \
  "runtime wiring failed: option 52 missing default --continue-on-fail 0"
assert_line_has "$line52" '--require-all-rounds-ok 1' \
  "runtime wiring failed: option 52 missing default --require-all-rounds-ok 1"
assert_line_has "$line52" '--max-round-failures 0' \
  "runtime wiring failed: option 52 missing default --max-round-failures 0"
assert_line_has "$line52" '--trend-min-go-rate-pct 95' \
  "runtime wiring failed: option 52 missing default --trend-min-go-rate-pct 95"
assert_line_has "$line52" '--max-alert-severity WARN' \
  "runtime wiring failed: option 52 missing default --max-alert-severity WARN"
assert_line_has "$line52" '--bundle-outputs 1' \
  "runtime wiring failed: option 52 missing default --bundle-outputs 1"
assert_line_has "$line52" '--bundle-fail-close 1' \
  "runtime wiring failed: option 52 missing default --bundle-fail-close 1"
assert_line_has "$line52" '--pre-real-host-readiness 1' \
  "runtime wiring failed: option 52 missing default --pre-real-host-readiness 1"
assert_line_has "$line52" '--signoff-require-trend-artifact-policy-match 1' \
  "runtime wiring failed: option 52 missing strict signoff --signoff-require-trend-artifact-policy-match 1"
assert_line_has "$line52" '--signoff-require-trend-wg-validate-udp-source 1' \
  "runtime wiring failed: option 52 missing strict signoff --signoff-require-trend-wg-validate-udp-source 1"
assert_line_has "$line52" '--signoff-require-trend-wg-validate-strict-distinct 1' \
  "runtime wiring failed: option 52 missing strict signoff --signoff-require-trend-wg-validate-strict-distinct 1"
assert_line_has "$line52" '--signoff-require-trend-wg-soak-diversity-pass 1' \
  "runtime wiring failed: option 52 missing strict signoff --signoff-require-trend-wg-soak-diversity-pass 1"
assert_line_has "$line52" '--signoff-min-trend-wg-soak-selection-lines 12' \
  "runtime wiring failed: option 52 missing strict signoff --signoff-min-trend-wg-soak-selection-lines 12"
assert_line_has "$line52" '--signoff-min-trend-wg-soak-entry-operators 2' \
  "runtime wiring failed: option 52 missing strict signoff --signoff-min-trend-wg-soak-entry-operators 2"
assert_line_has "$line52" '--signoff-min-trend-wg-soak-exit-operators 2' \
  "runtime wiring failed: option 52 missing strict signoff --signoff-min-trend-wg-soak-exit-operators 2"
assert_line_has "$line52" '--signoff-min-trend-wg-soak-cross-operator-pairs 2' \
  "runtime wiring failed: option 52 missing strict signoff --signoff-min-trend-wg-soak-cross-operator-pairs 2"
assert_line_has "$line52" '--signoff-require-incident-snapshot-on-fail 1' \
  "runtime wiring failed: option 52 missing strict signoff --signoff-require-incident-snapshot-on-fail 1"
assert_line_has "$line52" '--signoff-require-incident-snapshot-artifacts 1' \
  "runtime wiring failed: option 52 missing strict signoff --signoff-require-incident-snapshot-artifacts 1"
assert_line_has "$line52" '--print-run-report 0' \
  "runtime wiring failed: option 52 missing default --print-run-report 0"
assert_line_has "$line52" '--show-json 0' \
  "runtime wiring failed: option 52 missing default --show-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 53 (prod pilot cohort quick-check) runtime command forwarding"
INPUT53="$TMP_DIR/input53.txt"
{
  printf '3\n'   # main menu: advanced
  printf '53\n'  # prod pilot cohort quick-check
  for _ in $(seq 1 14); do
    printf '\n'  # accept defaults
  done
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT53"
run_ui "$INPUT53" "$TMP_DIR/run53.log"

line53="$(rg '^prod-pilot-cohort-quick-check ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line53" ]]; then
  echo "runtime wiring failed: option 53 did not invoke prod-pilot-cohort-quick-check"
  cat "$TMP_DIR/run53.log"
  exit 1
fi
assert_line_has "$line53" '--run-report-json \.easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_quick_report\.json' \
  "runtime wiring failed: option 53 missing default run-report-json path"
assert_line_has "$line53" '--require-status-ok 1' \
  "runtime wiring failed: option 53 missing default --require-status-ok 1"
assert_line_has "$line53" '--require-runbook-ok 1' \
  "runtime wiring failed: option 53 missing default --require-runbook-ok 1"
assert_line_has "$line53" '--require-signoff-attempted 1' \
  "runtime wiring failed: option 53 missing default --require-signoff-attempted 1"
assert_line_has "$line53" '--require-signoff-ok 1' \
  "runtime wiring failed: option 53 missing default --require-signoff-ok 1"
assert_line_has "$line53" '--require-cohort-signoff-policy 1' \
  "runtime wiring failed: option 53 missing default --require-cohort-signoff-policy 1"
assert_line_has "$line53" '--require-summary-json 1' \
  "runtime wiring failed: option 53 missing default --require-summary-json 1"
assert_line_has "$line53" '--require-summary-status-ok 1' \
  "runtime wiring failed: option 53 missing default --require-summary-status-ok 1"
assert_line_has "$line53" '--max-duration-sec 0' \
  "runtime wiring failed: option 53 missing default --max-duration-sec 0"
assert_line_has "$line53" '--show-json 0' \
  "runtime wiring failed: option 53 missing default --show-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 54 (prod pilot cohort quick-trend) runtime command forwarding"
INPUT54="$TMP_DIR/input54.txt"
{
  printf '3\n'   # main menu: advanced
  printf '54\n'  # prod pilot cohort quick-trend
  for _ in $(seq 1 21); do
    printf '\n'  # accept defaults
  done
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT54"
run_ui "$INPUT54" "$TMP_DIR/run54.log"

line54="$(rg '^prod-pilot-cohort-quick-trend ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line54" ]]; then
  echo "runtime wiring failed: option 54 did not invoke prod-pilot-cohort-quick-trend"
  cat "$TMP_DIR/run54.log"
  exit 1
fi
assert_line_has "$line54" '--reports-dir \.easy-node-logs' \
  "runtime wiring failed: option 54 missing default reports-dir"
assert_line_has "$line54" '--max-reports 25' \
  "runtime wiring failed: option 54 missing default --max-reports 25"
assert_line_has "$line54" '--since-hours 24' \
  "runtime wiring failed: option 54 missing default --since-hours 24"
assert_line_has "$line54" '--require-status-ok 1' \
  "runtime wiring failed: option 54 missing default --require-status-ok 1"
assert_line_has "$line54" '--require-runbook-ok 1' \
  "runtime wiring failed: option 54 missing default --require-runbook-ok 1"
assert_line_has "$line54" '--require-signoff-attempted 1' \
  "runtime wiring failed: option 54 missing default --require-signoff-attempted 1"
assert_line_has "$line54" '--require-signoff-ok 1' \
  "runtime wiring failed: option 54 missing default --require-signoff-ok 1"
assert_line_has "$line54" '--require-cohort-signoff-policy 1' \
  "runtime wiring failed: option 54 missing default --require-cohort-signoff-policy 1"
assert_line_has "$line54" '--require-summary-json 1' \
  "runtime wiring failed: option 54 missing default --require-summary-json 1"
assert_line_has "$line54" '--require-summary-status-ok 1' \
  "runtime wiring failed: option 54 missing default --require-summary-status-ok 1"
assert_line_has "$line54" '--max-duration-sec 0' \
  "runtime wiring failed: option 54 missing default --max-duration-sec 0"
assert_line_has "$line54" '--fail-on-any-no-go 0' \
  "runtime wiring failed: option 54 missing default --fail-on-any-no-go 0"
assert_line_has "$line54" '--min-go-rate-pct 0' \
  "runtime wiring failed: option 54 missing default --min-go-rate-pct 0"
assert_line_has "$line54" '--show-details 1' \
  "runtime wiring failed: option 54 missing default --show-details 1"
assert_line_has "$line54" '--show-top-reasons 5' \
  "runtime wiring failed: option 54 missing default --show-top-reasons 5"
assert_line_has "$line54" '--print-summary-json 0' \
  "runtime wiring failed: option 54 missing default --print-summary-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 55 (prod pilot cohort quick-alert) runtime command forwarding"
INPUT55="$TMP_DIR/input55.txt"
{
  printf '3\n'   # main menu: advanced
  printf '55\n'  # prod pilot cohort quick-alert
  for _ in $(seq 1 23); do
    printf '\n'  # accept defaults
  done
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT55"
run_ui "$INPUT55" "$TMP_DIR/run55.log"

line55="$(rg '^prod-pilot-cohort-quick-alert ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line55" ]]; then
  echo "runtime wiring failed: option 55 did not invoke prod-pilot-cohort-quick-alert"
  cat "$TMP_DIR/run55.log"
  exit 1
fi
assert_line_has "$line55" '--reports-dir \.easy-node-logs' \
  "runtime wiring failed: option 55 missing default reports-dir"
assert_line_has "$line55" '--max-reports 25' \
  "runtime wiring failed: option 55 missing default --max-reports 25"
assert_line_has "$line55" '--since-hours 24' \
  "runtime wiring failed: option 55 missing default --since-hours 24"
assert_line_has "$line55" '--require-status-ok 1' \
  "runtime wiring failed: option 55 missing default --require-status-ok 1"
assert_line_has "$line55" '--require-runbook-ok 1' \
  "runtime wiring failed: option 55 missing default --require-runbook-ok 1"
assert_line_has "$line55" '--require-signoff-attempted 1' \
  "runtime wiring failed: option 55 missing default --require-signoff-attempted 1"
assert_line_has "$line55" '--require-signoff-ok 1' \
  "runtime wiring failed: option 55 missing default --require-signoff-ok 1"
assert_line_has "$line55" '--require-cohort-signoff-policy 1' \
  "runtime wiring failed: option 55 missing default --require-cohort-signoff-policy 1"
assert_line_has "$line55" '--require-summary-json 1' \
  "runtime wiring failed: option 55 missing default --require-summary-json 1"
assert_line_has "$line55" '--require-summary-status-ok 1' \
  "runtime wiring failed: option 55 missing default --require-summary-status-ok 1"
assert_line_has "$line55" '--max-duration-sec 0' \
  "runtime wiring failed: option 55 missing default --max-duration-sec 0"
assert_line_has "$line55" '--warn-go-rate-pct 98' \
  "runtime wiring failed: option 55 missing default --warn-go-rate-pct 98"
assert_line_has "$line55" '--critical-go-rate-pct 90' \
  "runtime wiring failed: option 55 missing default --critical-go-rate-pct 90"
assert_line_has "$line55" '--warn-no-go-count 1' \
  "runtime wiring failed: option 55 missing default --warn-no-go-count 1"
assert_line_has "$line55" '--critical-no-go-count 2' \
  "runtime wiring failed: option 55 missing default --critical-no-go-count 2"
assert_line_has "$line55" '--warn-eval-errors 1' \
  "runtime wiring failed: option 55 missing default --warn-eval-errors 1"
assert_line_has "$line55" '--critical-eval-errors 2' \
  "runtime wiring failed: option 55 missing default --critical-eval-errors 2"
assert_line_has "$line55" '--fail-on-warn 0' \
  "runtime wiring failed: option 55 missing default --fail-on-warn 0"
assert_line_has "$line55" '--fail-on-critical 0' \
  "runtime wiring failed: option 55 missing default --fail-on-critical 0"
assert_line_has "$line55" '--show-top-reasons 5' \
  "runtime wiring failed: option 55 missing default --show-top-reasons 5"
assert_line_has "$line55" '--print-summary-json 0' \
  "runtime wiring failed: option 55 missing default --print-summary-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] advanced option 56 (prod pilot cohort quick-dashboard) runtime command forwarding"
INPUT56="$TMP_DIR/input56.txt"
{
  printf '3\n'   # main menu: advanced
  printf '56\n'  # prod pilot cohort quick-dashboard
  for _ in $(seq 1 27); do
    printf '\n'  # accept defaults
  done
  printf '0\n'   # back from advanced menu
  printf '0\n'   # exit main menu
} >"$INPUT56"
run_ui "$INPUT56" "$TMP_DIR/run56.log"

line56="$(rg '^prod-pilot-cohort-quick-dashboard ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line56" ]]; then
  echo "runtime wiring failed: option 56 did not invoke prod-pilot-cohort-quick-dashboard"
  cat "$TMP_DIR/run56.log"
  exit 1
fi
assert_line_has "$line56" '--reports-dir \.easy-node-logs' \
  "runtime wiring failed: option 56 missing default reports-dir"
assert_line_has "$line56" '--max-reports 25' \
  "runtime wiring failed: option 56 missing default --max-reports 25"
assert_line_has "$line56" '--since-hours 24' \
  "runtime wiring failed: option 56 missing default --since-hours 24"
assert_line_has "$line56" '--require-status-ok 1' \
  "runtime wiring failed: option 56 missing default --require-status-ok 1"
assert_line_has "$line56" '--require-runbook-ok 1' \
  "runtime wiring failed: option 56 missing default --require-runbook-ok 1"
assert_line_has "$line56" '--require-signoff-attempted 1' \
  "runtime wiring failed: option 56 missing default --require-signoff-attempted 1"
assert_line_has "$line56" '--require-signoff-ok 1' \
  "runtime wiring failed: option 56 missing default --require-signoff-ok 1"
assert_line_has "$line56" '--require-cohort-signoff-policy 1' \
  "runtime wiring failed: option 56 missing default --require-cohort-signoff-policy 1"
assert_line_has "$line56" '--require-summary-json 1' \
  "runtime wiring failed: option 56 missing default --require-summary-json 1"
assert_line_has "$line56" '--require-summary-status-ok 1' \
  "runtime wiring failed: option 56 missing default --require-summary-status-ok 1"
assert_line_has "$line56" '--max-duration-sec 0' \
  "runtime wiring failed: option 56 missing default --max-duration-sec 0"
assert_line_has "$line56" '--fail-on-any-no-go 0' \
  "runtime wiring failed: option 56 missing default --fail-on-any-no-go 0"
assert_line_has "$line56" '--min-go-rate-pct 95' \
  "runtime wiring failed: option 56 missing default --min-go-rate-pct 95"
assert_line_has "$line56" '--show-top-reasons 5' \
  "runtime wiring failed: option 56 missing default --show-top-reasons 5"
assert_line_has "$line56" '--warn-go-rate-pct 98' \
  "runtime wiring failed: option 56 missing default --warn-go-rate-pct 98"
assert_line_has "$line56" '--critical-go-rate-pct 90' \
  "runtime wiring failed: option 56 missing default --critical-go-rate-pct 90"
assert_line_has "$line56" '--warn-no-go-count 1' \
  "runtime wiring failed: option 56 missing default --warn-no-go-count 1"
assert_line_has "$line56" '--critical-no-go-count 2' \
  "runtime wiring failed: option 56 missing default --critical-no-go-count 2"
assert_line_has "$line56" '--warn-eval-errors 1' \
  "runtime wiring failed: option 56 missing default --warn-eval-errors 1"
assert_line_has "$line56" '--critical-eval-errors 2' \
  "runtime wiring failed: option 56 missing default --critical-eval-errors 2"
assert_line_has "$line56" '--fail-on-warn 0' \
  "runtime wiring failed: option 56 missing default --fail-on-warn 0"
assert_line_has "$line56" '--fail-on-critical 0' \
  "runtime wiring failed: option 56 missing default --fail-on-critical 0"
assert_line_has "$line56" '--trend-summary-json \.easy-node-logs/prod_pilot_quick_trend_24h\.json' \
  "runtime wiring failed: option 56 missing default trend-summary-json path"
assert_line_has "$line56" '--alert-summary-json \.easy-node-logs/prod_pilot_quick_alert_24h\.json' \
  "runtime wiring failed: option 56 missing default alert-summary-json path"
assert_line_has "$line56" '--dashboard-md \.easy-node-logs/prod_pilot_quick_dashboard_24h\.md' \
  "runtime wiring failed: option 56 missing default dashboard-md path"
assert_line_has "$line56" '--print-dashboard 1' \
  "runtime wiring failed: option 56 missing default --print-dashboard 1"
assert_line_has "$line56" '--print-summary-json 0' \
  "runtime wiring failed: option 56 missing default --print-summary-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] option 57 runtime command forwarding"
INPUT57="$TMP_DIR/input57.txt"
{
  printf '3\n'
  printf '57\n'
  for _ in $(seq 1 40); do
    printf '\n'
  done
  printf '0\n'
  printf '0\n'
} >"$INPUT57"
run_ui "$INPUT57" "$TMP_DIR/run57.log"

line57="$(rg 'prod-pilot-cohort-quick-signoff' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line57" ]]; then
  echo "runtime wiring failed: option 57 did not invoke prod-pilot-cohort-quick-signoff"
  cat "$TMP_DIR/run57.log"
  exit 1
fi
assert_line_has "$line57" '--check-latest 1' "runtime wiring failed: option 57 missing --check-latest 1"
assert_line_has "$line57" '--check-trend 1' "runtime wiring failed: option 57 missing --check-trend 1"
assert_line_has "$line57" '--check-alert 1' "runtime wiring failed: option 57 missing --check-alert 1"
assert_line_has "$line57" '--max-alert-severity WARN' "runtime wiring failed: option 57 missing --max-alert-severity WARN"
assert_line_has "$line57" '--require-cohort-signoff-policy 1' "runtime wiring failed: option 57 missing --require-cohort-signoff-policy 1"
assert_line_has "$line57" '--require-trend-artifact-policy-match 1' "runtime wiring failed: option 57 missing strict --require-trend-artifact-policy-match 1"
assert_line_has "$line57" '--require-trend-wg-validate-udp-source 1' "runtime wiring failed: option 57 missing strict --require-trend-wg-validate-udp-source 1"
assert_line_has "$line57" '--require-trend-wg-validate-strict-distinct 1' "runtime wiring failed: option 57 missing strict --require-trend-wg-validate-strict-distinct 1"
assert_line_has "$line57" '--require-trend-wg-soak-diversity-pass 1' "runtime wiring failed: option 57 missing strict --require-trend-wg-soak-diversity-pass 1"
assert_line_has "$line57" '--min-trend-wg-soak-selection-lines 12' "runtime wiring failed: option 57 missing strict --min-trend-wg-soak-selection-lines 12"
assert_line_has "$line57" '--min-trend-wg-soak-entry-operators 2' "runtime wiring failed: option 57 missing strict --min-trend-wg-soak-entry-operators 2"
assert_line_has "$line57" '--min-trend-wg-soak-exit-operators 2' "runtime wiring failed: option 57 missing strict --min-trend-wg-soak-exit-operators 2"
assert_line_has "$line57" '--min-trend-wg-soak-cross-operator-pairs 2' "runtime wiring failed: option 57 missing strict --min-trend-wg-soak-cross-operator-pairs 2"
assert_line_has "$line57" '--require-bundle-created 1' "runtime wiring failed: option 57 missing strict --require-bundle-created 1"
assert_line_has "$line57" '--require-bundle-manifest 1' "runtime wiring failed: option 57 missing strict --require-bundle-manifest 1"
assert_line_has "$line57" '--run-report-json \.easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_quick_report\.json' \
  "runtime wiring failed: option 57 missing default --run-report-json path"
assert_line_has "$line57" '--trend-summary-json \.easy-node-logs/prod_pilot_quick_signoff_trend\.json' \
  "runtime wiring failed: option 57 missing default --trend-summary-json path"
assert_line_has "$line57" '--alert-summary-json \.easy-node-logs/prod_pilot_quick_signoff_alert\.json' \
  "runtime wiring failed: option 57 missing default --alert-summary-json path"
assert_line_has "$line57" '--signoff-json \.easy-node-logs/prod_pilot_quick_signoff\.json' \
  "runtime wiring failed: option 57 missing default --signoff-json path"

: >"$CAPTURE"

echo "[easy-mode-runtime] option 58 runtime command forwarding"
INPUT58="$TMP_DIR/input58.txt"
{
  printf '3\n'
  printf '58\n'
  for _ in $(seq 1 41); do
    printf '\n'
  done
  printf '0\n'
  printf '0\n'
} >"$INPUT58"
run_ui "$INPUT58" "$TMP_DIR/run58.log"

line58="$(rg 'prod-pilot-cohort-quick-runbook' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line58" ]]; then
  echo "runtime wiring failed: option 58 did not invoke prod-pilot-cohort-quick-runbook"
  cat "$TMP_DIR/run58.log"
  exit 1
fi
assert_line_has "$line58" '--bootstrap-directory http://198\.51\.100\.10:8081' \
  "runtime wiring failed: option 58 missing default --bootstrap-directory from hosts config"
assert_line_has "$line58" '--subject pilot-client' "runtime wiring failed: option 58 missing default subject"
assert_line_has "$line58" '--rounds 5' "runtime wiring failed: option 58 missing default rounds"
assert_line_has "$line58" '--pause-sec 60' "runtime wiring failed: option 58 missing default pause-sec"
assert_line_has "$line58" '--max-round-failures 0' "runtime wiring failed: option 58 missing default max-round-failures"
assert_line_has "$line58" '--max-alert-severity WARN' "runtime wiring failed: option 58 missing default max-alert-severity"
assert_line_has "$line58" '--bundle-outputs 1' "runtime wiring failed: option 58 missing default bundle-outputs"
assert_line_has "$line58" '--bundle-fail-close 1' "runtime wiring failed: option 58 missing default bundle-fail-close"
assert_line_has "$line58" '--pre-real-host-readiness 1' "runtime wiring failed: option 58 missing default pre-real-host-readiness"
assert_line_has "$line58" '--dashboard-enable 1' "runtime wiring failed: option 58 missing --dashboard-enable 1"
assert_line_has "$line58" '--dashboard-fail-close 0' "runtime wiring failed: option 58 missing --dashboard-fail-close 0"
assert_line_has "$line58" '--dashboard-print 1' "runtime wiring failed: option 58 missing --dashboard-print 1"
assert_line_has "$line58" '--dashboard-print-summary-json 0' "runtime wiring failed: option 58 missing --dashboard-print-summary-json 0"
assert_line_has "$line58" '--signoff-max-reports 25' "runtime wiring failed: option 58 missing default signoff max reports"
assert_line_has "$line58" '--signoff-since-hours 24' "runtime wiring failed: option 58 missing default signoff since-hours"
assert_line_has "$line58" '--signoff-min-go-rate-pct 95' "runtime wiring failed: option 58 missing default signoff min go rate"
assert_line_has "$line58" '--signoff-require-cohort-signoff-policy 1' "runtime wiring failed: option 58 missing default signoff cohort policy requirement"
assert_line_has "$line58" '--signoff-require-trend-artifact-policy-match 1' "runtime wiring failed: option 58 missing strict signoff --signoff-require-trend-artifact-policy-match 1"
assert_line_has "$line58" '--signoff-require-trend-wg-validate-udp-source 1' "runtime wiring failed: option 58 missing strict signoff --signoff-require-trend-wg-validate-udp-source 1"
assert_line_has "$line58" '--signoff-require-trend-wg-validate-strict-distinct 1' "runtime wiring failed: option 58 missing strict signoff --signoff-require-trend-wg-validate-strict-distinct 1"
assert_line_has "$line58" '--signoff-require-trend-wg-soak-diversity-pass 1' "runtime wiring failed: option 58 missing strict signoff --signoff-require-trend-wg-soak-diversity-pass 1"
assert_line_has "$line58" '--signoff-min-trend-wg-soak-selection-lines 12' "runtime wiring failed: option 58 missing strict signoff --signoff-min-trend-wg-soak-selection-lines 12"
assert_line_has "$line58" '--signoff-min-trend-wg-soak-entry-operators 2' "runtime wiring failed: option 58 missing strict signoff --signoff-min-trend-wg-soak-entry-operators 2"
assert_line_has "$line58" '--signoff-min-trend-wg-soak-exit-operators 2' "runtime wiring failed: option 58 missing strict signoff --signoff-min-trend-wg-soak-exit-operators 2"
assert_line_has "$line58" '--signoff-min-trend-wg-soak-cross-operator-pairs 2' "runtime wiring failed: option 58 missing strict signoff --signoff-min-trend-wg-soak-cross-operator-pairs 2"
assert_line_has "$line58" '--signoff-require-incident-snapshot-on-fail 1' "runtime wiring failed: option 58 missing strict signoff --signoff-require-incident-snapshot-on-fail 1"
assert_line_has "$line58" '--signoff-require-incident-snapshot-artifacts 1' "runtime wiring failed: option 58 missing strict signoff --signoff-require-incident-snapshot-artifacts 1"

: >"$CAPTURE"

echo "[easy-mode-runtime] option 59 runtime command forwarding"
INPUT59="$TMP_DIR/input59.txt"
{
  printf '3\n'
  printf '59\n'
  for _ in $(seq 1 6); do
    printf '\n'
  done
  printf '0\n'
  printf '0\n'
} >"$INPUT59"
run_ui "$INPUT59" "$TMP_DIR/run59.log"

line59="$(rg 'prod-pilot-cohort-campaign' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line59" ]]; then
  echo "runtime wiring failed: option 59 did not invoke prod-pilot-cohort-campaign"
  cat "$TMP_DIR/run59.log"
  exit 1
fi
assert_line_has "$line59" '--bootstrap-directory http://198\.51\.100\.10:8081' \
  "runtime wiring failed: option 59 missing default bootstrap directory"
assert_line_has "$line59" '--subject pilot-client' \
  "runtime wiring failed: option 59 missing default subject"
assert_line_has "$line59" '--pre-real-host-readiness 1' \
  "runtime wiring failed: option 59 missing default --pre-real-host-readiness 1"
assert_line_has "$line59" '--show-json 0' \
  "runtime wiring failed: option 59 missing default --show-json 0"

: >"$CAPTURE"

echo "[easy-mode-runtime] option 60 runtime command forwarding"
INPUT60="$TMP_DIR/input60.txt"
{
  printf '3\n'
  printf '60\n'
  for _ in $(seq 1 5); do
    printf '\n'
  done
  printf '0\n'
  printf '0\n'
} >"$INPUT60"
run_ui "$INPUT60" "$TMP_DIR/run60.log"

line60="$(rg '^runtime-doctor ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line60" ]]; then
  echo "runtime wiring failed: option 60 did not invoke runtime-doctor"
  cat "$TMP_DIR/run60.log"
  exit 1
fi
assert_line_has "$line60" '--base-port 19280' \
  "runtime wiring failed: option 60 missing default --base-port"
assert_line_has "$line60" '--client-iface wgcstack0' \
  "runtime wiring failed: option 60 missing default --client-iface"
assert_line_has "$line60" '--exit-iface wgestack0' \
  "runtime wiring failed: option 60 missing default --exit-iface"
assert_line_has "$line60" '--vpn-iface wgvpn0' \
  "runtime wiring failed: option 60 missing default --vpn-iface"
assert_line_has "$line60" '--show-json 1' \
  "runtime wiring failed: option 60 missing default --show-json 1"

: >"$CAPTURE"

echo "[easy-mode-runtime] option 61 runtime command forwarding"
INPUT61="$TMP_DIR/input61.txt"
{
  printf '3\n'
  printf '61\n'
  printf '0\n'
  printf '0\n'
} >"$INPUT61"
run_ui "$INPUT61" "$TMP_DIR/run61.log"

line61="$(rg '^manual-validation-backlog$' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line61" ]]; then
  echo "runtime wiring failed: option 61 did not invoke manual-validation-backlog"
  cat "$TMP_DIR/run61.log"
  exit 1
fi

echo "[easy-mode-runtime] option 62 runtime command forwarding"
INPUT62="$TMP_DIR/input62.txt"
{
  printf '3\n'
  printf '62\n'
  for _ in $(seq 1 6); do
    printf '\n'
  done
  printf 'n\n'
  printf '0\n'
  printf '0\n'
} >"$INPUT62"
run_ui "$INPUT62" "$TMP_DIR/run62.log"

line62="$(rg '^runtime-fix ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line62" ]]; then
  echo "runtime wiring failed: option 62 did not invoke runtime-fix"
  cat "$TMP_DIR/run62.log"
  exit 1
fi
assert_line_has "$line62" '--base-port 19280' \
  "runtime wiring failed: option 62 missing default --base-port"
assert_line_has "$line62" '--client-iface wgcstack0' \
  "runtime wiring failed: option 62 missing default --client-iface"
assert_line_has "$line62" '--exit-iface wgestack0' \
  "runtime wiring failed: option 62 missing default --exit-iface"
assert_line_has "$line62" '--vpn-iface wgvpn0' \
  "runtime wiring failed: option 62 missing default --vpn-iface"
assert_line_has "$line62" '--prune-wg-only-dir 0' \
  "runtime wiring failed: option 62 missing default --prune-wg-only-dir 0"
assert_line_has "$line62" '--show-json 1' \
  "runtime wiring failed: option 62 missing default --show-json 1"

: >"$CAPTURE"

echo "[easy-mode-runtime] option 63 runtime command forwarding"
INPUT63="$TMP_DIR/input63.txt"
{
  printf '3\n'
  printf '63\n'
  for _ in $(seq 1 5); do
    printf '\n'
  done
  printf '0\n'
  printf '0\n'
} >"$INPUT63"
run_ui "$INPUT63" "$TMP_DIR/run63.log"

line63="$(rg '^manual-validation-status ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line63" ]]; then
  echo "runtime wiring failed: option 63 did not invoke manual-validation-status"
  cat "$TMP_DIR/run63.log"
  exit 1
fi
assert_line_has "$line63" '--base-port 19280' \
  "runtime wiring failed: option 63 missing default --base-port"
assert_line_has "$line63" '--client-iface wgcstack0' \
  "runtime wiring failed: option 63 missing default --client-iface"
assert_line_has "$line63" '--exit-iface wgestack0' \
  "runtime wiring failed: option 63 missing default --exit-iface"
assert_line_has "$line63" '--vpn-iface wgvpn0' \
  "runtime wiring failed: option 63 missing default --vpn-iface"
assert_line_has "$line63" '--show-json 1' \
  "runtime wiring failed: option 63 missing default --show-json 1"

: >"$CAPTURE"

echo "[easy-mode-runtime] option 64 runtime command forwarding"
INPUT64="$TMP_DIR/input64.txt"
{
  printf '3\n'
  printf '64\n'
  printf '\n'    # bootstrap directory default
  printf 'inv-runtime-smoke\n'
  printf 'wgvpn7\n'
  printf 'https://api.ipify.org\n'
  printf 'https://ipinfo.io/country\n'
  printf '\n'    # pre-real-host readiness default yes
  printf '\n'    # runtime doctor default yes
  printf '\n'    # runtime fix default no
  printf 'y\n'   # print summary json
  printf 'n\n'   # no sudo in integration
  printf '0\n'
  printf '0\n'
} >"$INPUT64"
run_ui "$INPUT64" "$TMP_DIR/run64.log"

line64="$(rg '^client-vpn-smoke ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line64" ]]; then
  echo "runtime wiring failed: option 64 did not invoke client-vpn-smoke"
  cat "$TMP_DIR/run64.log"
  exit 1
fi
assert_line_has "$line64" '--bootstrap-directory http://198\.51\.100\.10:8081' \
  "runtime wiring failed: option 64 missing default bootstrap directory"
assert_line_has "$line64" '--subject inv-runtime-smoke' \
  "runtime wiring failed: option 64 missing subject"
assert_line_has "$line64" '--beta-profile 1' \
  "runtime wiring failed: option 64 missing --beta-profile 1"
assert_line_has "$line64" '--path-profile balanced' \
  "runtime wiring failed: option 64 missing default path profile"
assert_line_has "$line64" '--distinct-operators 1' \
  "runtime wiring failed: option 64 missing distinct-operators default"
assert_line_has "$line64" '--interface wgvpn7' \
  "runtime wiring failed: option 64 missing interface override"
assert_line_has "$line64" '--pre-real-host-readiness 1' \
  "runtime wiring failed: option 64 missing pre-real-host-readiness default"
assert_line_has "$line64" '--runtime-doctor 1' \
  "runtime wiring failed: option 64 missing runtime-doctor default"
assert_line_has "$line64" '--runtime-fix 0' \
  "runtime wiring failed: option 64 missing runtime-fix default"
assert_line_has "$line64" '--public-ip-url https://api\.ipify\.org' \
  "runtime wiring failed: option 64 missing public IP URL"
assert_line_has "$line64" '--country-url https://ipinfo\.io/country' \
  "runtime wiring failed: option 64 missing country URL"
assert_line_has "$line64" '--print-summary-json 1' \
  "runtime wiring failed: option 64 missing print-summary-json 1"

: >"$CAPTURE"

echo "[easy-mode-runtime] option 65 runtime command forwarding"
INPUT65="$TMP_DIR/input65.txt"
{
  printf '3\n'
  printf '65\n'
  printf '\n'    # directory A default
  printf '\n'    # directory B default
  printf '\n'    # issuer URL default
  printf '\n'    # entry URL default
  printf '\n'    # exit URL default
  printf '.easy-node-logs/prod_gate_bundle_test\n'
  printf '\n'    # pre-real-host readiness default yes
  printf '\n'    # runtime doctor default yes
  printf '\n'    # runtime fix default no
  printf 'y\n'   # print summary json
  printf 'n\n'   # no sudo in integration
  printf '0\n'
  printf '0\n'
} >"$INPUT65"
run_ui "$INPUT65" "$TMP_DIR/run65.log"

line65="$(rg '^three-machine-prod-signoff ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line65" ]]; then
  echo "runtime wiring failed: option 65 did not invoke three-machine-prod-signoff"
  cat "$TMP_DIR/run65.log"
  exit 1
fi
assert_line_has "$line65" '--directory-a https://198\.51\.100\.10:8081' \
  "runtime wiring failed: option 65 missing default directory A"
assert_line_has "$line65" '--directory-b https://203\.0\.113\.20:8081' \
  "runtime wiring failed: option 65 missing default directory B"
assert_line_has "$line65" '--issuer-url https://198\.51\.100\.10:8082' \
  "runtime wiring failed: option 65 missing default issuer URL"
assert_line_has "$line65" '--entry-url https://198\.51\.100\.10:8083' \
  "runtime wiring failed: option 65 missing default entry URL"
assert_line_has "$line65" '--exit-url https://203\.0\.113\.20:8084' \
  "runtime wiring failed: option 65 missing default exit URL"
assert_line_has "$line65" '--bundle-dir \.easy-node-logs/prod_gate_bundle_test' \
  "runtime wiring failed: option 65 missing bundle dir override"
assert_line_has "$line65" '--pre-real-host-readiness 1' \
  "runtime wiring failed: option 65 missing pre-real-host-readiness default"
assert_line_has "$line65" '--runtime-doctor 1' \
  "runtime wiring failed: option 65 missing runtime-doctor default"
assert_line_has "$line65" '--runtime-fix 0' \
  "runtime wiring failed: option 65 missing runtime-fix default"
assert_line_has "$line65" '--print-summary-json 1' \
  "runtime wiring failed: option 65 missing print-summary-json 1"

: >"$CAPTURE"

echo "[easy-mode-runtime] option 66 runtime command forwarding"
INPUT66="$TMP_DIR/input66.txt"
{
  printf '3\n'
  printf '66\n'
  printf '\n'    # base port default
  printf '\n'    # client iface default
  printf '\n'    # exit iface default
  printf '\n'    # vpn iface default
  printf '.easy-node-logs/manual_validation_readiness_summary_test.json\n'
  printf '.easy-node-logs/manual_validation_readiness_report_test.md\n'
  printf '\n'    # print report default yes
  printf 'y\n'   # print summary json
  printf 'y\n'   # fail on not ready
  printf '0\n'
  printf '0\n'
} >"$INPUT66"
run_ui "$INPUT66" "$TMP_DIR/run66.log"

line66="$(rg '^manual-validation-report ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line66" ]]; then
  echo "runtime wiring failed: option 66 did not invoke manual-validation-report"
  cat "$TMP_DIR/run66.log"
  exit 1
fi
assert_line_has "$line66" '--base-port 19280' \
  "runtime wiring failed: option 66 missing default --base-port"
assert_line_has "$line66" '--client-iface wgcstack0' \
  "runtime wiring failed: option 66 missing default --client-iface"
assert_line_has "$line66" '--exit-iface wgestack0' \
  "runtime wiring failed: option 66 missing default --exit-iface"
assert_line_has "$line66" '--vpn-iface wgvpn0' \
  "runtime wiring failed: option 66 missing default --vpn-iface"
assert_line_has "$line66" '--summary-json \.easy-node-logs/manual_validation_readiness_summary_test\.json' \
  "runtime wiring failed: option 66 missing summary-json override"
assert_line_has "$line66" '--report-md \.easy-node-logs/manual_validation_readiness_report_test\.md' \
  "runtime wiring failed: option 66 missing report-md override"
assert_line_has "$line66" '--print-report 1' \
  "runtime wiring failed: option 66 missing default print-report"
assert_line_has "$line66" '--print-summary-json 1' \
  "runtime wiring failed: option 66 missing print-summary-json 1"
assert_line_has "$line66" '--fail-on-not-ready 1' \
  "runtime wiring failed: option 66 missing fail-on-not-ready 1"
if ! rg -q '^launcher readiness summary$' "$TMP_DIR/run66.log"; then
  echo "runtime wiring failed: option 66 missing launcher readiness summary heading"
  cat "$TMP_DIR/run66.log"
  exit 1
fi
if ! rg -q '^  readiness_status=NOT_READY$' "$TMP_DIR/run66.log"; then
  echo "runtime wiring failed: option 66 missing launcher readiness status"
  cat "$TMP_DIR/run66.log"
  exit 1
fi
if ! rg -q '^  machine_c_smoke_ready=false$' "$TMP_DIR/run66.log"; then
  echo "runtime wiring failed: option 66 missing machine_c_smoke_ready line"
  cat "$TMP_DIR/run66.log"
  exit 1
fi
if ! rg -q '^  machine_c_smoke_blockers=runtime_hygiene$' "$TMP_DIR/run66.log"; then
  echo "runtime wiring failed: option 66 missing machine_c_smoke_blockers line"
  cat "$TMP_DIR/run66.log"
  exit 1
fi
if ! rg -q '^  machine_c_smoke_next_command=sudo ./scripts/easy_node.sh client-vpn-smoke --runtime-fix 1$' "$TMP_DIR/run66.log"; then
  echo "runtime wiring failed: option 66 missing machine_c_smoke_next_command line"
  cat "$TMP_DIR/run66.log"
  exit 1
fi
if ! rg -q '^  next_action_command=sudo ./scripts/easy_node.sh client-vpn-smoke --runtime-fix 1$' "$TMP_DIR/run66.log"; then
  echo "runtime wiring failed: option 66 missing launcher next action command"
  cat "$TMP_DIR/run66.log"
  exit 1
fi
if ! rg -q '^  latest_failed_incident_summary_json=/tmp/fake-incident/incident_summary.json$' "$TMP_DIR/run66.log"; then
  echo "runtime wiring failed: option 66 missing latest failed incident summary path"
  cat "$TMP_DIR/run66.log"
  exit 1
fi
if ! rg -q '^  latest_failed_incident_report_md=/tmp/fake-incident/incident_report.md$' "$TMP_DIR/run66.log"; then
  echo "runtime wiring failed: option 66 missing latest failed incident report path"
  cat "$TMP_DIR/run66.log"
  exit 1
fi
if ! rg -q '^  latest_failed_incident_readiness_report_summary_attachment=attachments/02_manual_validation_readiness_summary.json$' "$TMP_DIR/run66.log"; then
  echo "runtime wiring failed: option 66 missing readiness summary attachment path"
  cat "$TMP_DIR/run66.log"
  exit 1
fi
if ! rg -q '^  latest_failed_incident_readiness_report_md_attachment=attachments/03_manual_validation_readiness_report.md$' "$TMP_DIR/run66.log"; then
  echo "runtime wiring failed: option 66 missing readiness report attachment path"
  cat "$TMP_DIR/run66.log"
  exit 1
fi

: >"$CAPTURE"

echo "[easy-mode-runtime] option 67 runtime command forwarding"
INPUT67="$TMP_DIR/input67.txt"
{
  printf '3\n'
  printf '67\n'
  printf '\n'    # base port default
  printf '\n'    # client iface default
  printf '\n'    # exit iface default
  printf 'n\n'   # strict beta disabled
  printf 'y\n'   # print summary json
  printf 'n\n'   # no sudo in integration
  printf '0\n'
  printf '0\n'
} >"$INPUT67"
run_ui "$INPUT67" "$TMP_DIR/run67.log"

line67="$(rg '^wg-only-stack-selftest-record ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line67" ]]; then
  echo "runtime wiring failed: option 67 did not invoke wg-only-stack-selftest-record"
  cat "$TMP_DIR/run67.log"
  exit 1
fi
assert_line_has "$line67" '--base-port 19280' \
  "runtime wiring failed: option 67 missing default --base-port"
assert_line_has "$line67" '--client-iface wgcstack0' \
  "runtime wiring failed: option 67 missing default --client-iface"
assert_line_has "$line67" '--exit-iface wgestack0' \
  "runtime wiring failed: option 67 missing default --exit-iface"
assert_line_has "$line67" '--strict-beta 0' \
  "runtime wiring failed: option 67 missing strict-beta override"
assert_line_has "$line67" '--print-summary-json 1' \
  "runtime wiring failed: option 67 missing print-summary-json 1"

: >"$CAPTURE"

echo "[easy-mode-runtime] option 68 runtime command forwarding"
INPUT68="$TMP_DIR/input68.txt"
{
  printf '3\n'
  printf '68\n'
  printf '\n'    # base port default
  printf 'wgcpre0\n'
  printf 'wgepre0\n'
  printf 'wgvpnpre0\n'
  printf '\n'    # prune default yes
  printf 'n\n'   # strict beta disabled
  printf 'y\n'   # print summary json
  printf 'n\n'   # no sudo in integration
  printf '0\n'
  printf '0\n'
} >"$INPUT68"
run_ui "$INPUT68" "$TMP_DIR/run68.log"

line68="$(rg '^pre-real-host-readiness ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line68" ]]; then
  echo "runtime wiring failed: option 68 did not invoke pre-real-host-readiness"
  cat "$TMP_DIR/run68.log"
  exit 1
fi
assert_line_has "$line68" '--base-port 19280' \
  "runtime wiring failed: option 68 missing default --base-port"
assert_line_has "$line68" '--client-iface wgcpre0' \
  "runtime wiring failed: option 68 missing client iface override"
assert_line_has "$line68" '--exit-iface wgepre0' \
  "runtime wiring failed: option 68 missing exit iface override"
assert_line_has "$line68" '--vpn-iface wgvpnpre0' \
  "runtime wiring failed: option 68 missing vpn iface override"
assert_line_has "$line68" '--runtime-fix-prune-wg-only-dir 1' \
  "runtime wiring failed: option 68 missing prune flag default"
assert_line_has "$line68" '--strict-beta 0' \
  "runtime wiring failed: option 68 missing strict-beta override"
assert_line_has "$line68" '--print-summary-json 1' \
  "runtime wiring failed: option 68 missing print-summary-json 1"

echo "easy-mode launcher runtime integration check ok"
