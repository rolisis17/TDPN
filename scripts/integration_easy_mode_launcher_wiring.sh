#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CPP_UI="tools/easy_mode/easy_mode_ui.cpp"
EASY_NODE="scripts/easy_node.sh"

for cmd in rg mktemp cat chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

if [[ ! -f "$CPP_UI" ]]; then
  echo "missing launcher source: $CPP_UI"
  exit 1
fi
if [[ ! -x "$EASY_NODE" ]]; then
  echo "missing easy_node helper: $EASY_NODE"
  exit 1
fi

if grep -Eq 'std::system\(|popen\(' "$CPP_UI"; then
  echo "launcher portability failed: easy_mode_ui.cpp still depends on std::system/popen and will break on systems without /bin/sh"
  exit 1
fi

check_cpp() {
  local pattern="$1"
  local message="$2"
  if ! rg -q -- "$pattern" "$CPP_UI"; then
    echo "$message"
    exit 1
  fi
}

check_cpp_absent() {
  local pattern="$1"
  local message="$2"
  if rg -q -- "$pattern" "$CPP_UI"; then
    echo "$message"
    exit 1
  fi
}

last_forward_line_for_label() {
  local capture_file="$1"
  local label="$2"
  local line=""
  while IFS= read -r candidate; do
    line="$candidate"
  done < <(rg "^${label}(	|$)" "$capture_file" || true)
  printf '%s\n' "$line"
}

assert_forward_line_has_token() {
  local line="$1"
  local token="$2"
  local message="$3"
  if [[ "$line" != *"$token"* ]]; then
    echo "$message"
    printf 'forward line: %s\n' "$line"
    exit 1
  fi
}

echo "[easy-mode-wiring] main menu simplicity contract"
check_cpp 'Main menu:' "launcher wiring failed: main menu heading missing"
check_cpp '1\) Connect as CLIENT \(simple\)' "launcher wiring failed: simple CLIENT entry missing"
check_cpp '2\) Connect as SERVER \(simple, provider default\)' "launcher wiring failed: simple SERVER entry missing"
check_cpp '3\) Other options \(expert/tests\)' "launcher wiring failed: advanced options entry missing"

echo "[easy-mode-wiring] simple wrapper wiring"
check_cpp 'simple-client-test' "launcher wiring failed: simple client dry-run wrapper wiring missing"
check_cpp 'simple-client-vpn-preflight' "launcher wiring failed: simple client preflight wrapper wiring missing"
check_cpp 'simple-client-vpn-session' "launcher wiring failed: simple client session wrapper wiring missing"
check_cpp 'simple-server-preflight' "launcher wiring failed: simple server preflight wrapper wiring missing"
check_cpp 'simple-server-session' "launcher wiring failed: simple server session wrapper wiring missing"
check_cpp_absent 'Need expert client overrides now\?' "launcher wiring failed: simple client still exposes inline expert override prompt"
check_cpp_absent 'Need expert server overrides now\?' "launcher wiring failed: simple server still exposes inline expert override prompt"

echo "[easy-mode-wiring] advanced options presence"
check_cpp '36\) Closed-beta PROD bundle \(strict preflight \+ integrity verify \+ signoff \+ run report \+ auto incident snapshot on fail\)' \
  "launcher wiring failed: option 36 menu label missing"
check_cpp '37\) Closed-beta PROD bundle \(smoke \+ integrity verify \+ run report \+ auto incident snapshot on fail\)' \
  "launcher wiring failed: option 37 menu label missing"
check_cpp '38\) Verify PROD bundle integrity \+ gate artifacts' \
  "launcher wiring failed: option 38 menu label missing"
check_cpp '39\) PROD pilot runbook \(strict one-command defaults\)' \
  "launcher wiring failed: option 39 menu label missing"
check_cpp '40\) Capture incident snapshot bundle \(debug/triage\)' \
  "launcher wiring failed: option 40 menu label missing"
check_cpp '41\) PROD gate SLO decision summary \(GO/NO-GO\)' \
  "launcher wiring failed: option 41 menu label missing"
check_cpp '42\) PROD gate SLO trend \(multi-run GO/NO-GO rate\)' \
  "launcher wiring failed: option 42 menu label missing"
check_cpp '43\) PROD gate SLO alert severity \(OK/WARN/CRITICAL\)' \
  "launcher wiring failed: option 43 menu label missing"
check_cpp '44\) PROD SLO dashboard artifact \(trend \+ alert \+ markdown\)' \
  "launcher wiring failed: option 44 menu label missing"
check_cpp '45\) PROD key-rotation runbook \(backup \+ preflight \+ rollback\)' \
  "launcher wiring failed: option 45 menu label missing"
check_cpp '46\) PROD upgrade runbook \(pull/build/restart \+ rollback\)' \
  "launcher wiring failed: option 46 menu label missing"
check_cpp '47\) PROD operator lifecycle runbook \(onboard/offboard\)' \
  "launcher wiring failed: option 47 menu label missing"
check_cpp '48\) PROD pilot cohort runbook \(multi-round sustained pilot\)' \
  "launcher wiring failed: option 48 menu label missing"
check_cpp '49\) PROD pilot cohort bundle verify' \
  "launcher wiring failed: option 49 menu label missing"
check_cpp '50\) PROD pilot cohort signoff \(integrity \+ policy\)' \
  "launcher wiring failed: option 50 menu label missing"
check_cpp '51\) PROD pilot cohort full flow \(runbook \+ signoff\)' \
  "launcher wiring failed: option 51 menu label missing"
check_cpp '52\) PROD pilot cohort quick mode \(minimal prompts\)' \
  "launcher wiring failed: option 52 menu label missing"
check_cpp '53\) PROD pilot cohort quick-check \(verify quick run report\)' \
  "launcher wiring failed: option 53 menu label missing"
check_cpp '54\) PROD pilot cohort quick-trend \(multi-run GO/NO-GO\)' \
  "launcher wiring failed: option 54 menu label missing"
check_cpp '55\) PROD pilot cohort quick-alert \(OK/WARN/CRITICAL\)' \
  "launcher wiring failed: option 55 menu label missing"
check_cpp '56\) PROD pilot cohort quick-dashboard \(trend \+ alert \+ markdown\)' \
  "launcher wiring failed: option 56 menu label missing"
check_cpp '57\) PROD pilot cohort quick-signoff \(check \+ trend \+ alert gate\)' \
  "launcher wiring failed: option 57 menu label missing"
check_cpp '58\) PROD pilot cohort quick-runbook \(quick \+ signoff \+ dashboard\)' \
  "launcher wiring failed: option 58 menu label missing"
check_cpp '59\) PROD pilot cohort campaign \(strict low-prompt preset\)' \
  "launcher wiring failed: option 59 menu label missing"
check_cpp '60\) Runtime doctor \(stale ports/interfaces/state preflight\)' \
  "launcher wiring failed: option 60 menu label missing"
check_cpp '61\) Show manual validation backlog reminder' \
  "launcher wiring failed: option 61 menu label missing"
check_cpp '62\) Runtime fix \(safe cleanup from doctor findings\)' \
  "launcher wiring failed: option 62 menu label missing"
check_cpp '63\) Manual validation status \(live readiness \+ recorded receipts\)' \
  "launcher wiring failed: option 63 menu label missing"
check_cpp '64\) Client VPN smoke \(preflight \+ up \+ status \+ optional egress check \+ receipt\)' \
  "launcher wiring failed: option 64 menu label missing"
check_cpp '65\) True 3-machine PROD signoff \(bundle \+ receipt\)' \
  "launcher wiring failed: option 65 menu label missing"
check_cpp '66\) Manual validation report \(markdown \+ JSON readiness handoff\)' \
  "launcher wiring failed: option 66 menu label missing"
check_cpp '67\) WG-only selftest \+ readiness receipt' \
  "launcher wiring failed: option 67 menu label missing"
check_cpp '68\) Pre-real-host readiness sweep \(runtime fix \+ WG-only \+ report\)' \
  "launcher wiring failed: option 68 menu label missing"
check_cpp '69\) Server federation status \(peer \+ sync health\)' \
  "launcher wiring failed: option 69 menu label missing"
check_cpp '70\) Server federation wait gate \(block until ready\)' \
  "launcher wiring failed: option 70 menu label missing"
check_cpp '71\) PROD campaign summary regenerate \(saved artifacts -> handoff report\)' \
  "launcher wiring failed: option 71 menu label missing"
check_cpp '72\) PROD campaign check \(fail-closed artifact/policy gate\)' \
  "launcher wiring failed: option 72 menu label missing"
check_cpp '73\) PROD campaign signoff \(optional summary refresh \+ check\)' \
  "launcher wiring failed: option 73 menu label missing"
check_cpp '74\) Runtime fix \+ readiness receipt \(recorded cleanup\)' \
  "launcher wiring failed: option 74 menu label missing"
check_cpp '75\) Single-machine PROD readiness sweep \(all local gates \+ next action\)' \
  "launcher wiring failed: option 75 menu label missing"
check_cpp '76\) VPN RC standard path \(single-machine sweep \+ roadmap report\)' \
  "launcher wiring failed: option 76 menu label missing"
check_cpp '78\) VPN RC matrix chain path \(campaign refresh/check handoff\)' \
  "launcher wiring failed: option 78 menu label missing"
check_cpp '79\) 3-machine Docker profile matrix \(resilience defaults\)' \
  "launcher wiring failed: option 79 menu label missing"
check_cpp '80\) VPN RC resilience path \(resilience defaults \+ integration coverage\)' \
  "launcher wiring failed: option 80 menu label missing"
check_cpp '81\) 3-machine Docker profile matrix record wrapper \(coverage defaults\)' \
  "launcher wiring failed: option 81 menu label missing"
check_cpp '82\) Phase-0 CI gate \(surface simplification fast gate\)' \
  "launcher wiring failed: option 82 menu label missing"
check_cpp '83\) Phase-1 resilience CI gate' \
  "launcher wiring failed: option 83 menu label missing"
check_cpp '84\) Phase-1 resilience handoff check' \
  "launcher wiring failed: option 84 menu label missing"
check_cpp '85\) Phase-1 resilience handoff run \(refresh \+ check\)' \
  "launcher wiring failed: option 85 menu label missing"
check_cpp '86\) Phase-2 Linux prod-candidate CI gate' \
  "launcher wiring failed: option 86 menu label missing"
check_cpp '87\) Phase-2 Linux prod-candidate check' \
  "launcher wiring failed: option 87 menu label missing"
check_cpp '88\) Phase-2 Linux prod-candidate run \(refresh \+ check\)' \
  "launcher wiring failed: option 88 menu label missing"
check_cpp '89\) Phase-2 Linux prod-candidate signoff \(run \+ roadmap report\)' \
  "launcher wiring failed: option 89 menu label missing"
check_cpp '90\) Phase-2 Linux prod-candidate handoff check' \
  "launcher wiring failed: option 90 menu label missing"
check_cpp '91\) Phase-2 Linux prod-candidate handoff run \(signoff \+ check\)' \
  "launcher wiring failed: option 91 menu label missing"
check_cpp '92\) Phase-3 Windows client beta CI gate' \
  "launcher wiring failed: option 92 menu label missing"
check_cpp '93\) Phase-3 Windows client beta check' \
  "launcher wiring failed: option 93 menu label missing"
check_cpp '94\) Phase-3 Windows client beta run \(refresh \+ check\)' \
  "launcher wiring failed: option 94 menu label missing"
check_cpp '95\) Phase-3 Windows client beta handoff check' \
  "launcher wiring failed: option 95 menu label missing"
check_cpp '96\) Phase-3 Windows client beta handoff run \(run \+ check\)' \
  "launcher wiring failed: option 96 menu label missing"
check_cpp '97\) Phase-4 Windows full parity CI gate' \
  "launcher wiring failed: option 97 menu label missing"
check_cpp '98\) Phase-4 Windows full parity check' \
  "launcher wiring failed: option 98 menu label missing"
check_cpp '99\) Phase-4 Windows full parity run \(refresh \+ check\)' \
  "launcher wiring failed: option 99 menu label missing"
check_cpp '100\) Phase-4 Windows full parity handoff check' \
  "launcher wiring failed: option 100 menu label missing"
check_cpp '101\) Phase-4 Windows full parity handoff run \(run \+ check\)' \
  "launcher wiring failed: option 101 menu label missing"
check_cpp '102\) Phase-5 settlement layer CI gate' \
  "launcher wiring failed: option 102 menu label missing"
check_cpp '103\) Phase-5 settlement layer check' \
  "launcher wiring failed: option 103 menu label missing"
check_cpp '104\) Phase-5 settlement layer run \(refresh \+ check\)' \
  "launcher wiring failed: option 104 menu label missing"
check_cpp '105\) Phase-5 settlement layer handoff check' \
  "launcher wiring failed: option 105 menu label missing"
check_cpp '106\) Phase-5 settlement layer handoff run \(run \+ check\)' \
  "launcher wiring failed: option 106 menu label missing"
check_cpp '107\) VPN non-blockchain fastlane \(runtime\+phase1-4 handoff\+roadmap\)' \
  "launcher wiring failed: option 107 menu label missing"
check_cpp '34\) Client VPN up \(real mode, expert/manual\)' \
  "launcher wiring failed: option 34 expert/manual label missing"

echo "[easy-mode-wiring] option 34 command wiring"
check_cpp 'if \(choice == "34"\)' "launcher wiring failed: option 34 handler missing"
check_cpp 'Use anonymous credential token instead of invite subject\?' \
  "launcher wiring failed: option 34 anon credential prompt missing"
check_cpp 'Run client-vpn-preflight first\?' \
  "launcher wiring failed: option 34 preflight prompt missing"
check_cpp 'Run client-vpn-up with sudo\?' \
  "launcher wiring failed: option 34 sudo prompt missing"
check_cpp 'client-vpn-up' "launcher wiring failed: option 34 command missing"

echo "[easy-mode-wiring] options 36/37/38/39/40/41/42/43/44/45/46/47/48/49/50/51/52/53/54/55/56 command wiring"
check_cpp 'if \(choice == "36"\)' "launcher wiring failed: option 36 handler missing"
check_cpp 'if \(choice == "37"\)' "launcher wiring failed: option 37 handler missing"
check_cpp 'if \(choice == "38"\)' "launcher wiring failed: option 38 handler missing"
check_cpp 'if \(choice == "39"\)' "launcher wiring failed: option 39 handler missing"
check_cpp 'if \(choice == "40"\)' "launcher wiring failed: option 40 handler missing"
check_cpp 'if \(choice == "41"\)' "launcher wiring failed: option 41 handler missing"
check_cpp 'if \(choice == "42"\)' "launcher wiring failed: option 42 handler missing"
check_cpp 'if \(choice == "43"\)' "launcher wiring failed: option 43 handler missing"
check_cpp 'if \(choice == "44"\)' "launcher wiring failed: option 44 handler missing"
check_cpp 'if \(choice == "45"\)' "launcher wiring failed: option 45 handler missing"
check_cpp 'if \(choice == "46"\)' "launcher wiring failed: option 46 handler missing"
check_cpp 'if \(choice == "47"\)' "launcher wiring failed: option 47 handler missing"
check_cpp 'if \(choice == "48"\)' "launcher wiring failed: option 48 handler missing"
check_cpp 'if \(choice == "49"\)' "launcher wiring failed: option 49 handler missing"
check_cpp 'if \(choice == "50"\)' "launcher wiring failed: option 50 handler missing"
check_cpp 'if \(choice == "51"\)' "launcher wiring failed: option 51 handler missing"
check_cpp 'if \(choice == "52"\)' "launcher wiring failed: option 52 handler missing"
check_cpp 'if \(choice == "53"\)' "launcher wiring failed: option 53 handler missing"
check_cpp 'if \(choice == "54"\)' "launcher wiring failed: option 54 handler missing"
check_cpp 'if \(choice == "55"\)' "launcher wiring failed: option 55 handler missing"
check_cpp 'if \(choice == "56"\)' "launcher wiring failed: option 56 handler missing"
check_cpp 'three-machine-prod-bundle' "launcher wiring failed: options 36/37 command missing"
check_cpp 'prod-gate-signoff' "launcher wiring failed: option 38 command missing"
check_cpp 'prod-pilot-runbook' "launcher wiring failed: option 39 command missing"
check_cpp 'Run pre-real-host readiness first\?' "launcher wiring failed: option 39 pre-real-host readiness prompt missing"
check_cpp 'Path profile for machine C test \(1=1-hop Speed, 2=2-hop Balanced, 3=3-hop Private\)' \
  "launcher wiring failed: machine C test path profile prompt missing"
check_cpp 'Path profile for machine C soak \(1=1-hop Speed, 2=2-hop Balanced, 3=3-hop Private\)' \
  "launcher wiring failed: machine C soak path profile prompt missing"
check_cpp 'appendPathProfilePreset\(cmd, pathProfile\);' \
  "launcher wiring failed: profile-first forwarding helper is not used in launcher command builders"
check_cpp 'incident-snapshot' "launcher wiring failed: option 40 command missing"
check_cpp 'prod-gate-slo-summary' "launcher wiring failed: option 41 command missing"
check_cpp 'prod-gate-slo-trend' "launcher wiring failed: option 42 command missing"
check_cpp 'prod-gate-slo-alert' "launcher wiring failed: option 43 command missing"
check_cpp 'prod-gate-slo-dashboard' "launcher wiring failed: option 44 command missing"
check_cpp 'prod-key-rotation-runbook' "launcher wiring failed: option 45 command missing"
check_cpp 'prod-upgrade-runbook' "launcher wiring failed: option 46 command missing"
check_cpp 'prod-operator-lifecycle-runbook' "launcher wiring failed: option 47 command missing"
check_cpp 'prod-pilot-cohort-runbook' "launcher wiring failed: option 48/51 command missing"
check_cpp 'prod-pilot-cohort-bundle-verify' "launcher wiring failed: option 49 command missing"
check_cpp 'prod-pilot-cohort-signoff' "launcher wiring failed: option 50/51 command missing"
check_cpp 'prod-pilot-cohort-quick' "launcher wiring failed: option 52 command missing"
check_cpp 'prod-pilot-cohort-quick-check' "launcher wiring failed: option 53 command missing"
check_cpp 'prod-pilot-cohort-quick-trend' "launcher wiring failed: option 54 command missing"
check_cpp 'prod-pilot-cohort-quick-alert' "launcher wiring failed: option 55 command missing"
check_cpp 'prod-pilot-cohort-quick-dashboard' "launcher wiring failed: option 56 command missing"
check_cpp '--max-round-failures ' "launcher wiring failed: option 50/51/52 max-round-failures forwarding missing"
check_cpp '--preflight-check 1' "launcher wiring failed: option 36 strict preflight flag missing"
check_cpp '--preflight-check 0' "launcher wiring failed: option 37 smoke preflight flag missing"
check_cpp '--signoff-check 1' "launcher wiring failed: option 36 signoff-check flag missing"
check_cpp '--signoff-check 0' "launcher wiring failed: option 37 signoff-check flag missing"
check_cpp '--mode ' "launcher wiring failed: option 40 mode forwarding missing"
check_cpp '--include-docker-logs ' "launcher wiring failed: option 40 include-docker-logs forwarding missing"
check_cpp '--docker-log-lines ' "launcher wiring failed: option 40 docker-log-lines forwarding missing"
check_cpp '--require-preflight-ok ' "launcher wiring failed: option 38/41/42/44 require-preflight-ok forwarding missing"
check_cpp '--require-bundle-ok ' "launcher wiring failed: option 38/41/42/44 require-bundle-ok forwarding missing"
check_cpp '--require-integrity-ok ' "launcher wiring failed: option 38/41/42/44 require-integrity-ok forwarding missing"
check_cpp '--require-signoff-ok ' "launcher wiring failed: option 38/41/42/44 require-signoff-ok forwarding missing"
check_cpp '--require-incident-snapshot-on-fail ' "launcher wiring failed: option 38/41/42/44 require-incident-snapshot-on-fail forwarding missing"
check_cpp '--require-incident-snapshot-artifacts ' "launcher wiring failed: option 38/41/42/44 require-incident-snapshot-artifacts forwarding missing"
check_cpp '--fail-on-no-go ' "launcher wiring failed: option 41 fail-on-no-go forwarding missing"
check_cpp '--fail-on-any-no-go ' "launcher wiring failed: option 42 fail-on-any-no-go forwarding missing"
check_cpp '--min-go-rate-pct ' "launcher wiring failed: option 42/44 min-go-rate forwarding missing"
check_cpp '--fail-on-warn ' "launcher wiring failed: option 43/44 fail-on-warn forwarding missing"
check_cpp '--fail-on-critical ' "launcher wiring failed: option 43/44 fail-on-critical forwarding missing"
check_cpp '--dashboard-md ' "launcher wiring failed: option 44 dashboard markdown forwarding missing"
check_cpp '--print-dashboard ' "launcher wiring failed: option 44 print-dashboard forwarding missing"
check_cpp '--rotate-server-secrets ' "launcher wiring failed: option 45 rotate-server-secrets forwarding missing"
check_cpp '--rotate-admin-signing ' "launcher wiring failed: option 45 rotate-admin-signing forwarding missing"
check_cpp '--key-history ' "launcher wiring failed: option 45 key-history forwarding missing"
check_cpp '--compose-pull ' "launcher wiring failed: option 46 compose-pull forwarding missing"
check_cpp '--compose-build ' "launcher wiring failed: option 46 compose-build forwarding missing"
check_cpp '--verify-relays ' "launcher wiring failed: option 47 verify-relays forwarding missing"
check_cpp '--verify-absent ' "launcher wiring failed: option 47 verify-absent forwarding missing"
check_cpp '--verify-relay-min-count ' "launcher wiring failed: option 47 verify-relay-min-count forwarding missing"
check_cpp '--federation-check ' "launcher wiring failed: option 47 federation-check forwarding missing"
check_cpp '--federation-ready-timeout-sec ' "launcher wiring failed: option 47 federation-ready-timeout-sec forwarding missing"
check_cpp '--federation-poll-sec ' "launcher wiring failed: option 47 federation-poll-sec forwarding missing"
check_cpp '--federation-timeout-sec ' "launcher wiring failed: option 47 federation-timeout-sec forwarding missing"
check_cpp '--federation-status-file ' "launcher wiring failed: option 47 federation-status-file forwarding missing"
check_cpp 'Enable onboard invite bootstrap \(authority only\)\?' "launcher wiring failed: option 47 onboard invite prompt missing"
check_cpp '--onboard-invite ' "launcher wiring failed: option 47 onboard-invite forwarding missing"
check_cpp '--onboard-invite-count ' "launcher wiring failed: option 47 onboard-invite-count forwarding missing"
check_cpp '--onboard-invite-tier ' "launcher wiring failed: option 47 onboard-invite-tier forwarding missing"
check_cpp '--onboard-invite-wait-sec ' "launcher wiring failed: option 47 onboard-invite-wait-sec forwarding missing"
check_cpp '--onboard-invite-fail-open ' "launcher wiring failed: option 47 onboard-invite-fail-open forwarding missing"
check_cpp '--onboard-invite-file ' "launcher wiring failed: option 47 onboard-invite-file forwarding missing"
check_cpp 'Auto-rollback onboard runs if they fail after startup\?' "launcher wiring failed: option 47 rollback-on-fail prompt missing"
check_cpp '--rollback-on-fail ' "launcher wiring failed: option 47 rollback-on-fail forwarding missing"
check_cpp '--rollback-verify-absent ' "launcher wiring failed: option 47 rollback-verify-absent forwarding missing"
check_cpp '--rollback-verify-timeout-sec ' "launcher wiring failed: option 47 rollback-verify-timeout-sec forwarding missing"
check_cpp 'Capture incident snapshot automatically on lifecycle failure\?' "launcher wiring failed: option 47 incident-snapshot prompt missing"
check_cpp '--incident-snapshot-on-fail ' "launcher wiring failed: option 47 incident-snapshot-on-fail forwarding missing"
check_cpp '--incident-bundle-dir ' "launcher wiring failed: option 47 incident-bundle-dir forwarding missing"
check_cpp '--incident-timeout-sec ' "launcher wiring failed: option 47 incident-timeout-sec forwarding missing"
check_cpp '--incident-include-docker-logs ' "launcher wiring failed: option 47 incident-include-docker-logs forwarding missing"
check_cpp '--incident-docker-log-lines ' "launcher wiring failed: option 47 incident-docker-log-lines forwarding missing"
check_cpp 'Capture runtime-doctor diagnostics on lifecycle failure\?' "launcher wiring failed: option 47 runtime-doctor prompt missing"
check_cpp '--runtime-doctor-on-fail ' "launcher wiring failed: option 47 runtime-doctor-on-fail forwarding missing"
check_cpp '--runtime-doctor-base-port ' "launcher wiring failed: option 47 runtime-doctor-base-port forwarding missing"
check_cpp '--runtime-doctor-client-iface ' "launcher wiring failed: option 47 runtime-doctor-client-iface forwarding missing"
check_cpp '--runtime-doctor-exit-iface ' "launcher wiring failed: option 47 runtime-doctor-exit-iface forwarding missing"
check_cpp '--runtime-doctor-vpn-iface ' "launcher wiring failed: option 47 runtime-doctor-vpn-iface forwarding missing"
check_cpp 'Lifecycle report markdown path \(optional\)' "launcher wiring failed: option 47 report markdown prompt missing"
check_cpp '--report-md ' "launcher wiring failed: option 47 report markdown forwarding missing"
check_cpp '--bundle-outputs ' "launcher wiring failed: option 48/51 bundle-outputs forwarding missing"
check_cpp '--bundle-fail-close ' "launcher wiring failed: option 48/51 bundle-fail-close forwarding missing"
check_cpp 'Run pre-real-host readiness once before the cohort\?' "launcher wiring failed: option 48/51 pre-real-host readiness prompt missing"
check_cpp '--pre-real-host-readiness ' "launcher wiring failed: option 48/51 pre-real-host readiness forwarding missing"
check_cpp '--check-tar-sha256 ' "launcher wiring failed: option 49/50/51 signoff integrity forwarding missing"
check_cpp '--check-manifest ' "launcher wiring failed: option 49/50/51 signoff manifest forwarding missing"
check_cpp '--max-alert-severity ' "launcher wiring failed: option 48/50/51/52 max-alert-severity forwarding missing"
check_cpp '--run-report-json ' "launcher wiring failed: option 52/53/57/58 run-report-json forwarding missing"
check_cpp 'Run pre-real-host readiness once before the cohort\?' "launcher wiring failed: option 52/58 pre-real-host readiness prompt missing"
check_cpp '--signoff-incident-snapshot-min-attachment-count 1' "launcher wiring failed: option 52/58 strict signoff incident attachment minimum forwarding missing"
check_cpp '--signoff-incident-snapshot-max-skipped-count 0' "launcher wiring failed: option 52/58 strict signoff incident skipped-attachment cap forwarding missing"
check_cpp '--incident-snapshot-min-attachment-count 1' "launcher wiring failed: option 56/57 strict incident attachment minimum forwarding missing"
check_cpp '--incident-snapshot-max-skipped-count 0' "launcher wiring failed: option 56/57 strict incident skipped-attachment cap forwarding missing"
check_cpp '--require-signoff-attempted ' "launcher wiring failed: option 53/54/55/56 signoff-attempted forwarding missing"
check_cpp '--require-cohort-signoff-policy ' "launcher wiring failed: quick SLO flows require-cohort-signoff-policy forwarding missing"
check_cpp '--require-summary-status-ok ' "launcher wiring failed: option 53/54/55/56 summary-status forwarding missing"
check_cpp '--max-duration-sec ' "launcher wiring failed: option 53/54/55/56 max-duration forwarding missing"
check_cpp '--show-top-reasons ' "launcher wiring failed: option 54/55/56 show-top-reasons forwarding missing"

echo "[easy-mode-wiring] option 57 command wiring"
check_cpp 'if \(choice == "57"\)' "launcher wiring failed: option 57 handler missing"
check_cpp 'prod-pilot-cohort-quick-signoff' "launcher wiring failed: option 57 command missing"
check_cpp '--max-alert-severity ' "launcher wiring failed: option 57 max-alert-severity forwarding missing"
check_cpp '--require-trend-artifact-policy-match 1' "launcher wiring failed: option 57 strict trend artifact policy forwarding missing"
check_cpp '--min-trend-wg-soak-selection-lines 12' "launcher wiring failed: option 57 strict trend soak selection-lines forwarding missing"
check_cpp '--require-bundle-created 1' "launcher wiring failed: option 57 strict bundle-created policy forwarding missing"
check_cpp '--incident-snapshot-min-attachment-count 1' "launcher wiring failed: option 57 strict incident attachment minimum forwarding missing"
check_cpp '--incident-snapshot-max-skipped-count 0' "launcher wiring failed: option 57 strict incident skipped-attachment cap forwarding missing"
check_cpp '--trend-summary-json ' "launcher wiring failed: option 57 trend summary forwarding missing"
check_cpp '--alert-summary-json ' "launcher wiring failed: option 57 alert summary forwarding missing"
check_cpp '--signoff-json ' "launcher wiring failed: option 57 signoff json forwarding missing"

echo "[easy-mode-wiring] option 58 command wiring"
check_cpp 'if \(choice == "58"\)' "launcher wiring failed: option 58 handler missing"
check_cpp 'prod-pilot-cohort-quick-runbook' "launcher wiring failed: option 58 command missing"
check_cpp '--dashboard-enable ' "launcher wiring failed: option 58 dashboard-enable forwarding missing"
check_cpp '--dashboard-fail-close ' "launcher wiring failed: option 58 dashboard-fail-close forwarding missing"
check_cpp '--dashboard-print-summary-json ' "launcher wiring failed: option 58 dashboard-print-summary-json forwarding missing"
check_cpp '--signoff-max-reports ' "launcher wiring failed: option 58 signoff-max-reports forwarding missing"
check_cpp '--signoff-since-hours ' "launcher wiring failed: option 58 signoff-since-hours forwarding missing"
check_cpp '--signoff-min-go-rate-pct ' "launcher wiring failed: option 58 signoff-min-go-rate-pct forwarding missing"
check_cpp '--signoff-require-cohort-signoff-policy ' "launcher wiring failed: option 58 signoff-require-cohort-signoff-policy forwarding missing"
check_cpp '--signoff-incident-snapshot-min-attachment-count 1' "launcher wiring failed: option 58 strict incident attachment minimum forwarding missing"
check_cpp '--signoff-incident-snapshot-max-skipped-count 0' "launcher wiring failed: option 58 strict incident skipped-attachment cap forwarding missing"
check_cpp '--max-round-failures ' "launcher wiring failed: option 58 max-round-failures forwarding missing"
check_cpp '--bundle-outputs ' "launcher wiring failed: option 58 bundle-outputs forwarding missing"
check_cpp '--bundle-fail-close ' "launcher wiring failed: option 58 bundle-fail-close forwarding missing"
check_cpp '--pre-real-host-readiness ' "launcher wiring failed: option 52/58/59 pre-real-host readiness forwarding missing"

echo "[easy-mode-wiring] option 59 command wiring"
check_cpp 'if \(choice == "59"\)' "launcher wiring failed: option 59 handler missing"
check_cpp 'prod-pilot-cohort-campaign' "launcher wiring failed: option 59 command missing"
check_cpp 'Run pre-real-host readiness once before the campaign\?' "launcher wiring failed: option 59 pre-real-host readiness prompt missing"
check_cpp 'Run inline campaign-signoff policy gate\? \(Y/n\)' "launcher wiring failed: option 59 campaign-signoff-check prompt missing"
check_cpp 'Fail campaign when inline campaign-signoff fails\? \(Y/n\)' "launcher wiring failed: option 59 campaign-signoff-required prompt missing"
check_cpp 'Refresh campaign summary during inline campaign-signoff\? \(y/N\)' "launcher wiring failed: option 59 campaign-signoff-refresh-summary prompt missing"
check_cpp 'Inline campaign-signoff summary stage: fail on NO-GO\? \(Y/n\)' "launcher wiring failed: option 59 campaign-signoff-summary-fail-on-no-go prompt missing"
check_cpp 'Campaign signoff summary JSON path \(optional\)' "launcher wiring failed: option 59 campaign-signoff-summary-json prompt missing"
check_cpp 'Print inline campaign-signoff summary JSON payload\? \(y/N\)' "launcher wiring failed: option 59 campaign-signoff-print-summary-json prompt missing"
check_cpp 'Extra campaign args \(optional\)' "launcher wiring failed: option 59 prompt text missing"
check_cpp '--campaign-signoff-check ' "launcher wiring failed: option 59 campaign-signoff-check forwarding missing"
check_cpp '--campaign-signoff-required ' "launcher wiring failed: option 59 campaign-signoff-required forwarding missing"
check_cpp '--campaign-signoff-refresh-summary ' "launcher wiring failed: option 59 campaign-signoff-refresh-summary forwarding missing"
check_cpp '--campaign-signoff-summary-fail-on-no-go ' "launcher wiring failed: option 59 campaign-signoff-summary-fail-on-no-go forwarding missing"
check_cpp '--campaign-signoff-print-summary-json ' "launcher wiring failed: option 59 campaign-signoff-print-summary-json forwarding missing"
check_cpp '--campaign-signoff-summary-json ' "launcher wiring failed: option 59 campaign-signoff-summary-json forwarding missing"
check_cpp '--show-json ' "launcher wiring failed: option 59 show-json forwarding missing"

echo "[easy-mode-wiring] options 60/61 command wiring"
check_cpp 'if \(choice == "60"\)' "launcher wiring failed: option 60 handler missing"
check_cpp 'runtime-doctor' "launcher wiring failed: option 60 command missing"
check_cpp 'WG-only base port' "launcher wiring failed: option 60 base port prompt missing"
check_cpp '--client-iface ' "launcher wiring failed: option 60 client-iface forwarding missing"
check_cpp '--exit-iface ' "launcher wiring failed: option 60 exit-iface forwarding missing"
check_cpp '--vpn-iface ' "launcher wiring failed: option 60 vpn-iface forwarding missing"
check_cpp 'if \(choice == "61"\)' "launcher wiring failed: option 61 handler missing"
check_cpp 'manual-validation-backlog' "launcher wiring failed: option 61 command missing"

echo "[easy-mode-wiring] option 62 command wiring"
check_cpp 'if \(choice == "62"\)' "launcher wiring failed: option 62 handler missing"
check_cpp 'runtime-fix' "launcher wiring failed: option 62 command missing"
check_cpp 'Prune wg-only runtime dir after cleanup\?' "launcher wiring failed: option 62 prune prompt missing"
check_cpp '--prune-wg-only-dir ' "launcher wiring failed: option 62 prune flag forwarding missing"

echo "[easy-mode-wiring] option 63 command wiring"
check_cpp 'if \(choice == "63"\)' "launcher wiring failed: option 63 handler missing"
check_cpp 'manual-validation-status' "launcher wiring failed: option 63 command missing"
check_cpp 'Profile default signoff summary JSON \(optional\)' "launcher wiring failed: option 63 profile signoff summary prompt missing"
check_cpp '--profile-compare-signoff-summary-json ' "launcher wiring failed: option 63 profile signoff summary forwarding missing"
check_cpp 'Show JSON summary payload\?' "launcher wiring failed: option 63 JSON prompt missing"

echo "[easy-mode-wiring] option 64 command wiring"
check_cpp 'if \(choice == "64"\)' "launcher wiring failed: option 64 handler missing"
check_cpp 'client-vpn-smoke' "launcher wiring failed: option 64 command missing"
check_cpp 'Public IP check URL' "launcher wiring failed: option 64 public IP prompt missing"
check_cpp 'Country check URL' "launcher wiring failed: option 64 country prompt missing"
check_cpp 'Run pre-real-host readiness first\?' "launcher wiring failed: option 64 pre-real-host readiness prompt missing"
check_cpp '--path-profile balanced' "launcher wiring failed: option 64 balanced path default missing"

echo "[easy-mode-wiring] option 65 command wiring"
check_cpp 'if \(choice == "65"\)' "launcher wiring failed: option 65 handler missing"
check_cpp 'three-machine-prod-signoff' "launcher wiring failed: option 65 command missing"
check_cpp 'Directory A URL' "launcher wiring failed: option 65 directory A prompt missing"
check_cpp 'Directory B URL' "launcher wiring failed: option 65 directory B prompt missing"
check_cpp 'Bundle dir' "launcher wiring failed: option 65 bundle dir prompt missing"
check_cpp 'Run pre-real-host readiness first\?' "launcher wiring failed: option 65 pre-real-host readiness prompt missing"

echo "[easy-mode-wiring] option 66 command wiring"
check_cpp 'if \(choice == "66"\)' "launcher wiring failed: option 66 handler missing"
check_cpp 'manual-validation-report' "launcher wiring failed: option 66 command missing"
check_cpp 'Profile default signoff summary JSON \(optional\)' "launcher wiring failed: option 66 profile signoff summary prompt missing"
check_cpp '--profile-compare-signoff-summary-json ' "launcher wiring failed: option 66 profile signoff summary forwarding missing"
check_cpp 'Summary JSON path' "launcher wiring failed: option 66 summary JSON prompt missing"
check_cpp 'Report markdown path' "launcher wiring failed: option 66 report markdown prompt missing"
check_cpp 'Fail if readiness is not complete\?' "launcher wiring failed: option 66 fail-close prompt missing"

echo "[easy-mode-wiring] option 67 command wiring"
check_cpp 'if \(choice == "67"\)' "launcher wiring failed: option 67 handler missing"
check_cpp 'wg-only-stack-selftest-record' "launcher wiring failed: option 67 command missing"
check_cpp 'Use strict beta profile\?' "launcher wiring failed: option 67 strict beta prompt missing"
check_cpp 'Run with sudo\? \(Y/n\)' "launcher wiring failed: option 67 sudo prompt missing"

echo "[easy-mode-wiring] option 68 command wiring"
check_cpp 'if \(choice == "68"\)' "launcher wiring failed: option 68 handler missing"
check_cpp 'pre-real-host-readiness' "launcher wiring failed: option 68 command missing"
check_cpp 'Prune wg-only runtime dir during cleanup\?' "launcher wiring failed: option 68 prune prompt missing"
check_cpp 'Client VPN iface' "launcher wiring failed: option 68 vpn iface prompt missing"

echo "[easy-mode-wiring] options 69/70 command wiring"
check_cpp 'if \(choice == "69"\)' "launcher wiring failed: option 69 handler missing"
check_cpp 'server-federation-status' "launcher wiring failed: option 69 command missing"
check_cpp 'Directory URL override \(optional\)' "launcher wiring failed: option 69 directory URL prompt missing"
check_cpp 'Request timeout sec' "launcher wiring failed: option 69 timeout prompt missing"
check_cpp 'Use strict federation policy preset\?' "launcher wiring failed: option 69/70 strict federation preset prompt missing"
check_cpp 'Summary JSON path \(optional\)' "launcher wiring failed: option 69/70 summary JSON prompt missing"
check_cpp '--require-configured-healthy ' "launcher wiring failed: option 69/70 require-configured-healthy forwarding missing"
check_cpp '--max-cooling-retry-sec ' "launcher wiring failed: option 69/70 max-cooling-retry-sec forwarding missing"
check_cpp '--max-peer-sync-age-sec ' "launcher wiring failed: option 69/70 max-peer-sync-age-sec forwarding missing"
check_cpp '--max-issuer-sync-age-sec ' "launcher wiring failed: option 69/70 max-issuer-sync-age-sec forwarding missing"
check_cpp '--min-peer-success-sources ' "launcher wiring failed: option 69/70 min-peer-success-sources forwarding missing"
check_cpp '--min-issuer-success-sources ' "launcher wiring failed: option 69/70 min-issuer-success-sources forwarding missing"

echo "[easy-mode-wiring] option 74 command wiring"
check_cpp 'if \(choice == "74"\)' "launcher wiring failed: option 74 handler missing"
check_cpp 'runtime-fix-record' "launcher wiring failed: option 74 command missing"
check_cpp 'Prune wg-only runtime dir after cleanup\?' "launcher wiring failed: option 74 prune prompt missing"
check_cpp 'Run with sudo\? \(Y/n\)' "launcher wiring failed: option 74 sudo prompt missing"

echo "[easy-mode-wiring] option 75 command wiring"
check_cpp 'if \(choice == "75"\)' "launcher wiring failed: option 75 handler missing"
check_cpp 'single-machine-prod-readiness' "launcher wiring failed: option 75 command missing"
check_cpp 'Profile campaign signoff mode \(auto/1/0\)' "launcher wiring failed: option 75 profile-signoff mode prompt missing"
check_cpp 'Force profile campaign refresh if signoff runs\?' "launcher wiring failed: option 75 refresh prompt missing"
check_cpp '--run-profile-compare-campaign-signoff ' "launcher wiring failed: option 75 signoff mode forwarding missing"
check_cpp '--profile-compare-campaign-signoff-refresh-campaign ' "launcher wiring failed: option 75 refresh forwarding missing"
check_cpp '--print-summary-json ' "launcher wiring failed: option 75 print-summary-json forwarding missing"
check_cpp 'Run with sudo\? \(Y/n\)' "launcher wiring failed: option 75 sudo prompt missing"
echo "[easy-mode-wiring] option 76 command wiring"
check_cpp 'if \(choice == "76"\)' "launcher wiring failed: option 76 handler missing"
check_cpp 'vpn-rc-standard-path' "launcher wiring failed: option 76 command missing"
check_cpp 'Force profile campaign refresh if signoff runs\?' "launcher wiring failed: option 76 refresh prompt missing"
check_cpp 'Print roadmap markdown report in terminal\?' "launcher wiring failed: option 76 print-report prompt missing"
check_cpp 'readLine\("Force profile campaign refresh if signoff runs\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 76 refresh prompt default missing"
check_cpp 'readLine\("Print roadmap markdown report in terminal\? \(Y/n\)", "y"\)' \
  "launcher wiring failed: option 76 print-report prompt default missing"
check_cpp 'readLine\("Print summary JSON\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 76 print-summary-json prompt default missing"
check_cpp 'readLine\("Run with sudo\? \(Y/n\)", "y"\)' \
  "launcher wiring failed: option 76 sudo prompt default missing"
check_cpp '--run-profile-compare-campaign-signoff auto' "launcher wiring failed: option 76 signoff mode forwarding missing"
check_cpp '--run-profile-compare-campaign-signoff auto"' "launcher wiring failed: option 76 signoff mode forwarding literal missing"
check_cpp '--profile-compare-campaign-signoff-refresh-campaign " << \(profileSignoffRefreshCampaign \? "1" : "0"\)' \
  "launcher wiring failed: option 76 refresh forwarding expression missing"
check_cpp '--print-report " << \(printReport \? "1" : "0"\)' \
  "launcher wiring failed: option 76 print-report forwarding expression missing"
check_cpp '--print-summary-json " << \(printSummaryJson \? "1" : "0"\)' \
  "launcher wiring failed: option 76 print-summary-json forwarding expression missing"
check_cpp '--profile-compare-campaign-signoff-refresh-campaign ' "launcher wiring failed: option 76 refresh forwarding missing"
check_cpp '--print-report ' "launcher wiring failed: option 76 print-report forwarding missing"
check_cpp '--print-summary-json ' "launcher wiring failed: option 76 print-summary-json forwarding missing"
check_cpp 'Run with sudo\? \(Y/n\)' "launcher wiring failed: option 76 sudo prompt missing"
echo "[easy-mode-wiring] option 77 command wiring"
check_cpp 'if \(choice == "77"\)' "launcher wiring failed: option 77 handler missing"
check_cpp 'profile-compare-campaign-signoff' "launcher wiring failed: option 77 command missing"
check_cpp '77\) Docker profile matrix signoff \(campaign refresh \+ fail-closed gate\)' \
  "launcher wiring failed: option 77 numbered menu label missing"
check_cpp 'Docker profile matrix signoff' "launcher wiring failed: option 77 menu label missing"
check_cpp 'Campaign bootstrap directory URL' "launcher wiring failed: option 77 bootstrap prompt missing"
check_cpp 'Campaign discovery wait sec' "launcher wiring failed: option 77 discovery wait prompt missing"
check_cpp 'Refresh campaign before signoff gate\?' "launcher wiring failed: option 77 refresh prompt missing"
check_cpp 'Fail if signoff decision is NO-GO\?' "launcher wiring failed: option 77 fail-on-no-go prompt missing"
check_cpp 'Signoff summary JSON path \(optional\)' "launcher wiring failed: option 77 summary-json prompt missing"
check_cpp 'Print signoff summary JSON payload\?' "launcher wiring failed: option 77 print-summary prompt missing"
check_cpp 'Show signoff check JSON payload\?' "launcher wiring failed: option 77 show-json prompt missing"
check_cpp 'readLine\("Reports dir", "\.easy-node-logs/profile_compare_campaign_docker"\)' \
  "launcher wiring failed: option 77 reports-dir prompt default missing"
check_cpp 'readLine\("Campaign discovery wait sec", "20"\)' \
  "launcher wiring failed: option 77 discovery wait prompt default missing"
check_cpp 'readLine\("Refresh campaign before signoff gate\? \(Y/n\)", "y"\)' \
  "launcher wiring failed: option 77 refresh prompt default missing"
check_cpp 'readLine\("Fail if signoff decision is NO-GO\? \(Y/n\)", "y"\)' \
  "launcher wiring failed: option 77 fail-on-no-go prompt default missing"
check_cpp 'readLine\("Print signoff summary JSON payload\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 77 print-summary prompt default missing"
check_cpp 'readLine\("Show signoff check JSON payload\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 77 show-json prompt default missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 77 sudo prompt default missing"
check_cpp '--campaign-execution-mode docker' "launcher wiring failed: option 77 missing fixed --campaign-execution-mode docker"
check_cpp '--campaign-start-local-stack 0' "launcher wiring failed: option 77 missing fixed --campaign-start-local-stack 0"
check_cpp '--refresh-campaign ' "launcher wiring failed: option 77 refresh forwarding missing"
check_cpp '--fail-on-no-go ' "launcher wiring failed: option 77 fail-on-no-go forwarding missing"
check_cpp '--campaign-bootstrap-directory ' "launcher wiring failed: option 77 bootstrap forwarding missing"
check_cpp '--campaign-discovery-wait-sec ' "launcher wiring failed: option 77 discovery wait forwarding missing"
check_cpp '--subject \$\{CAMPAIGN_SUBJECT:-\$\{INVITE_KEY:-INVITE_KEY\}\}' \
  "launcher wiring failed: option 77 subject placeholder forwarding missing"
check_cpp '--refresh-campaign " << \(refreshCampaign \? "1" : "0"\)' \
  "launcher wiring failed: option 77 refresh forwarding expression missing"
check_cpp '--fail-on-no-go " << \(failOnNoGo \? "1" : "0"\)' \
  "launcher wiring failed: option 77 fail-on-no-go forwarding expression missing"
check_cpp '--print-summary-json " << \(printSummaryJson \? "1" : "0"\)' \
  "launcher wiring failed: option 77 print-summary forwarding expression missing"
check_cpp '--show-json " << \(showJson \? "1" : "0"\)' \
  "launcher wiring failed: option 77 show-json forwarding expression missing"
check_cpp '--summary-json ' "launcher wiring failed: option 77 summary-json forwarding missing"
check_cpp '--print-summary-json ' "launcher wiring failed: option 77 print-summary forwarding missing"
check_cpp '--show-json ' "launcher wiring failed: option 77 show-json forwarding missing"

echo "[easy-mode-wiring] option 78 command wiring"
check_cpp 'if \(choice == "78"\)' "launcher wiring failed: option 78 handler missing"
check_cpp '78\) VPN RC matrix chain path \(campaign refresh/check handoff\)' \
  "launcher wiring failed: option 78 numbered menu label missing"
check_cpp 'VPN RC matrix chain path' "launcher wiring failed: option 78 menu label missing"
check_cpp 'vpn-rc-matrix-path' "launcher wiring failed: option 78 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 78 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 78 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 78 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " vpn-rc-matrix-path"' \
  "launcher wiring failed: option 78 command assembly missing"
check_cpp '--campaign-execution-mode docker' \
  "launcher wiring failed: option 78 fixed --campaign-execution-mode docker missing"
check_cpp '--signoff-refresh-campaign 0' \
  "launcher wiring failed: option 78 fixed --signoff-refresh-campaign 0 missing"
check_cpp '--signoff-fail-on-no-go 1' \
  "launcher wiring failed: option 78 fixed --signoff-fail-on-no-go 1 missing"
check_cpp '--roadmap-refresh-manual-validation 1' \
  "launcher wiring failed: option 78 fixed --roadmap-refresh-manual-validation 1 missing"
check_cpp '--roadmap-refresh-single-machine-readiness 0' \
  "launcher wiring failed: option 78 fixed --roadmap-refresh-single-machine-readiness 0 missing"
check_cpp '--print-report 1' \
  "launcher wiring failed: option 78 fixed --print-report 1 missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 78 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 78 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 78 sudo forwarding missing"

echo "[easy-mode-wiring] option 79 command wiring"
check_cpp 'if \(choice == "79"\)' "launcher wiring failed: option 79 handler missing"
check_cpp '79\) 3-machine Docker profile matrix \(resilience defaults\)' \
  "launcher wiring failed: option 79 numbered menu label missing"
check_cpp '3-machine Docker profile matrix' "launcher wiring failed: option 79 menu label missing"
check_cpp 'three-machine-docker-profile-matrix' "launcher wiring failed: option 79 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 79 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 79 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 79 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " three-machine-docker-profile-matrix"' \
  "launcher wiring failed: option 79 command assembly missing"
check_cpp '--run-peer-failover 1' \
  "launcher wiring failed: option 79 fixed --run-peer-failover 1 missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 79 fixed --print-summary-json 1 missing"
check_cpp '--docker-host-alias ' \
  "launcher wiring failed: option 79 docker host forwarding missing"
check_cpp '--bootstrap-directory ' \
  "launcher wiring failed: option 79 bootstrap forwarding missing"
check_cpp 'endpointFromHost\(hosts\.aHost, 8081\)' \
  "launcher wiring failed: option 79 host-derived bootstrap default missing"
check_cpp '"host\.docker\.internal"' \
  "launcher wiring failed: option 79 fallback docker host alias default missing"
check_cpp '"http://127\.0\.0\.1:18081"' \
  "launcher wiring failed: option 79 fallback bootstrap default missing"

echo "[easy-mode-wiring] option 80 command wiring"
check_cpp 'if \(choice == "80"\)' "launcher wiring failed: option 80 handler missing"
check_cpp '80\) VPN RC resilience path \(resilience defaults \+ integration coverage\)' \
  "launcher wiring failed: option 80 numbered menu label missing"
check_cpp 'VPN RC resilience path' "launcher wiring failed: option 80 menu label missing"
check_cpp 'vpn-rc-resilience-path' "launcher wiring failed: option 80 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 80 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 80 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 80 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " vpn-rc-resilience-path"' \
  "launcher wiring failed: option 80 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 80 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 80 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 80 sudo forwarding missing"

echo "[easy-mode-wiring] option 81 command wiring"
check_cpp 'if \(choice == "81"\)' "launcher wiring failed: option 81 handler missing"
check_cpp '81\) 3-machine Docker profile matrix record wrapper \(coverage defaults\)' \
  "launcher wiring failed: option 81 numbered menu label missing"
check_cpp '3-machine Docker profile matrix record wrapper' "launcher wiring failed: option 81 menu label missing"
check_cpp 'three-machine-docker-profile-matrix-record' "launcher wiring failed: option 81 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 81 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 81 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 81 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " three-machine-docker-profile-matrix-record"' \
  "launcher wiring failed: option 81 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 81 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 81 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 81 sudo forwarding missing"

echo "[easy-mode-wiring] option 82 command wiring"
check_cpp 'if \(choice == "82"\)' "launcher wiring failed: option 82 handler missing"
check_cpp '82\) Phase-0 CI gate \(surface simplification fast gate\)' \
  "launcher wiring failed: option 82 numbered menu label missing"
check_cpp 'Phase-0 CI gate' "launcher wiring failed: option 82 menu label missing"
check_cpp 'ci-phase0' "launcher wiring failed: option 82 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 82 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 82 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 82 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " ci-phase0"' \
  "launcher wiring failed: option 82 command assembly missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 82 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 82 sudo forwarding missing"

echo "[easy-mode-wiring] option 83 command wiring"
check_cpp 'if \(choice == "83"\)' "launcher wiring failed: option 83 handler missing"
check_cpp '83\) Phase-1 resilience CI gate' \
  "launcher wiring failed: option 83 numbered menu label missing"
check_cpp 'Phase-1 resilience CI gate' "launcher wiring failed: option 83 menu label missing"
check_cpp 'ci-phase1-resilience' "launcher wiring failed: option 83 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 83 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 83 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 83 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " ci-phase1-resilience"' \
  "launcher wiring failed: option 83 command assembly missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 83 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 83 sudo forwarding missing"

echo "[easy-mode-wiring] option 84 command wiring"
check_cpp 'if \(choice == "84"\)' "launcher wiring failed: option 84 handler missing"
check_cpp '84\) Phase-1 resilience handoff check' \
  "launcher wiring failed: option 84 numbered menu label missing"
check_cpp 'Phase-1 resilience handoff check' "launcher wiring failed: option 84 menu label missing"
check_cpp 'phase1-resilience-handoff-check' "launcher wiring failed: option 84 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 84 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 84 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 84 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase1-resilience-handoff-check"' \
  "launcher wiring failed: option 84 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 84 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 84 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 84 sudo forwarding missing"

echo "[easy-mode-wiring] option 85 command wiring"
check_cpp 'if \(choice == "85"\)' "launcher wiring failed: option 85 handler missing"
check_cpp '85\) Phase-1 resilience handoff run \(refresh \+ check\)' \
  "launcher wiring failed: option 85 numbered menu label missing"
check_cpp 'Phase-1 resilience handoff run \(refresh \+ check\)' "launcher wiring failed: option 85 menu label missing"
check_cpp 'phase1-resilience-handoff-run' "launcher wiring failed: option 85 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 85 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 85 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 85 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase1-resilience-handoff-run"' \
  "launcher wiring failed: option 85 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 85 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 85 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 85 sudo forwarding missing"

echo "[easy-mode-wiring] option 86 command wiring"
check_cpp 'if \(choice == "86"\)' "launcher wiring failed: option 86 handler missing"
check_cpp '86\) Phase-2 Linux prod-candidate CI gate' \
  "launcher wiring failed: option 86 numbered menu label missing"
check_cpp 'Phase-2 Linux prod-candidate CI gate' "launcher wiring failed: option 86 menu label missing"
check_cpp 'ci-phase2-linux-prod-candidate' "launcher wiring failed: option 86 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 86 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 86 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 86 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " ci-phase2-linux-prod-candidate"' \
  "launcher wiring failed: option 86 command assembly missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 86 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 86 sudo forwarding missing"

echo "[easy-mode-wiring] option 87 command wiring"
check_cpp 'if \(choice == "87"\)' "launcher wiring failed: option 87 handler missing"
check_cpp '87\) Phase-2 Linux prod-candidate check' \
  "launcher wiring failed: option 87 numbered menu label missing"
check_cpp 'Phase-2 Linux prod-candidate check' "launcher wiring failed: option 87 menu label missing"
check_cpp 'phase2-linux-prod-candidate-check' "launcher wiring failed: option 87 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 87 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 87 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 87 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase2-linux-prod-candidate-check"' \
  "launcher wiring failed: option 87 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 87 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 87 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 87 sudo forwarding missing"

echo "[easy-mode-wiring] option 88 command wiring"
check_cpp 'if \(choice == "88"\)' "launcher wiring failed: option 88 handler missing"
check_cpp '88\) Phase-2 Linux prod-candidate run \(refresh \+ check\)' \
  "launcher wiring failed: option 88 numbered menu label missing"
check_cpp 'Phase-2 Linux prod-candidate run \(refresh \+ check\)' "launcher wiring failed: option 88 menu label missing"
check_cpp 'phase2-linux-prod-candidate-run' "launcher wiring failed: option 88 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 88 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 88 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 88 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase2-linux-prod-candidate-run"' \
  "launcher wiring failed: option 88 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 88 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 88 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 88 sudo forwarding missing"

echo "[easy-mode-wiring] option 89 command wiring"
check_cpp 'if \(choice == "89"\)' "launcher wiring failed: option 89 handler missing"
check_cpp '89\) Phase-2 Linux prod-candidate signoff \(run \+ roadmap report\)' \
  "launcher wiring failed: option 89 numbered menu label missing"
check_cpp 'Phase-2 Linux prod-candidate signoff \(run \+ roadmap report\)' \
  "launcher wiring failed: option 89 menu label missing"
check_cpp 'phase2-linux-prod-candidate-signoff' "launcher wiring failed: option 89 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 89 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 89 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 89 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase2-linux-prod-candidate-signoff"' \
  "launcher wiring failed: option 89 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 89 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 89 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 89 sudo forwarding missing"

echo "[easy-mode-wiring] option 90 command wiring"
check_cpp 'if \(choice == "90"\)' "launcher wiring failed: option 90 handler missing"
check_cpp '90\) Phase-2 Linux prod-candidate handoff check' \
  "launcher wiring failed: option 90 numbered menu label missing"
check_cpp 'Phase-2 Linux prod-candidate handoff check' \
  "launcher wiring failed: option 90 menu label missing"
check_cpp 'phase2-linux-prod-candidate-handoff-check' \
  "launcher wiring failed: option 90 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 90 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 90 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 90 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase2-linux-prod-candidate-handoff-check"' \
  "launcher wiring failed: option 90 command assembly missing"
check_cpp '--show-json 1' \
  "launcher wiring failed: option 90 fixed --show-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 90 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 90 sudo forwarding missing"

echo "[easy-mode-wiring] option 91 command wiring"
check_cpp 'if \(choice == "91"\)' "launcher wiring failed: option 91 handler missing"
check_cpp '91\) Phase-2 Linux prod-candidate handoff run \(signoff \+ check\)' \
  "launcher wiring failed: option 91 numbered menu label missing"
check_cpp 'Phase-2 Linux prod-candidate handoff run \(signoff \+ check\)' \
  "launcher wiring failed: option 91 menu label missing"
check_cpp 'phase2-linux-prod-candidate-handoff-run' \
  "launcher wiring failed: option 91 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 91 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 91 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 91 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase2-linux-prod-candidate-handoff-run"' \
  "launcher wiring failed: option 91 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 91 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 91 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 91 sudo forwarding missing"

echo "[easy-mode-wiring] option 92 command wiring"
check_cpp 'if \(choice == "92"\)' "launcher wiring failed: option 92 handler missing"
check_cpp '92\) Phase-3 Windows client beta CI gate' \
  "launcher wiring failed: option 92 numbered menu label missing"
check_cpp 'Phase-3 Windows client beta CI gate' \
  "launcher wiring failed: option 92 menu label missing"
check_cpp 'ci-phase3-windows-client-beta' \
  "launcher wiring failed: option 92 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 92 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 92 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 92 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " ci-phase3-windows-client-beta"' \
  "launcher wiring failed: option 92 command assembly missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 92 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 92 sudo forwarding missing"

echo "[easy-mode-wiring] option 93 command wiring"
check_cpp 'if \(choice == "93"\)' "launcher wiring failed: option 93 handler missing"
check_cpp '93\) Phase-3 Windows client beta check' \
  "launcher wiring failed: option 93 numbered menu label missing"
check_cpp 'Phase-3 Windows client beta check' \
  "launcher wiring failed: option 93 menu label missing"
check_cpp 'phase3-windows-client-beta-check' \
  "launcher wiring failed: option 93 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 93 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 93 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 93 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase3-windows-client-beta-check"' \
  "launcher wiring failed: option 93 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 93 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 93 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 93 sudo forwarding missing"

echo "[easy-mode-wiring] option 94 command wiring"
check_cpp 'if \(choice == "94"\)' "launcher wiring failed: option 94 handler missing"
check_cpp '94\) Phase-3 Windows client beta run \(refresh \+ check\)' \
  "launcher wiring failed: option 94 numbered menu label missing"
check_cpp 'Phase-3 Windows client beta run \(refresh \+ check\)' \
  "launcher wiring failed: option 94 menu label missing"
check_cpp 'phase3-windows-client-beta-run' \
  "launcher wiring failed: option 94 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 94 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 94 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 94 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase3-windows-client-beta-run"' \
  "launcher wiring failed: option 94 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 94 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 94 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 94 sudo forwarding missing"

echo "[easy-mode-wiring] option 95 command wiring"
check_cpp 'if \(choice == "95"\)' "launcher wiring failed: option 95 handler missing"
check_cpp '95\) Phase-3 Windows client beta handoff check' \
  "launcher wiring failed: option 95 numbered menu label missing"
check_cpp 'Phase-3 Windows client beta handoff check' \
  "launcher wiring failed: option 95 menu label missing"
check_cpp 'phase3-windows-client-beta-handoff-check' \
  "launcher wiring failed: option 95 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 95 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 95 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 95 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase3-windows-client-beta-handoff-check"' \
  "launcher wiring failed: option 95 command assembly missing"
check_cpp '--show-json 1' \
  "launcher wiring failed: option 95 fixed --show-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 95 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 95 sudo forwarding missing"

echo "[easy-mode-wiring] option 96 command wiring"
check_cpp 'if \(choice == "96"\)' "launcher wiring failed: option 96 handler missing"
check_cpp '96\) Phase-3 Windows client beta handoff run \(run \+ check\)' \
  "launcher wiring failed: option 96 numbered menu label missing"
check_cpp 'Phase-3 Windows client beta handoff run \(run \+ check\)' \
  "launcher wiring failed: option 96 menu label missing"
check_cpp 'phase3-windows-client-beta-handoff-run' \
  "launcher wiring failed: option 96 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 96 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 96 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 96 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase3-windows-client-beta-handoff-run"' \
  "launcher wiring failed: option 96 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 96 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 96 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 96 sudo forwarding missing"

echo "[easy-mode-wiring] option 97 command wiring"
check_cpp 'if \(choice == "97"\)' "launcher wiring failed: option 97 handler missing"
check_cpp '97\) Phase-4 Windows full parity CI gate' \
  "launcher wiring failed: option 97 numbered menu label missing"
check_cpp 'Phase-4 Windows full parity CI gate' \
  "launcher wiring failed: option 97 menu label missing"
check_cpp 'ci-phase4-windows-full-parity' \
  "launcher wiring failed: option 97 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 97 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 97 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 97 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " ci-phase4-windows-full-parity"' \
  "launcher wiring failed: option 97 command assembly missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 97 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 97 sudo forwarding missing"

echo "[easy-mode-wiring] option 98 command wiring"
check_cpp 'if \(choice == "98"\)' "launcher wiring failed: option 98 handler missing"
check_cpp '98\) Phase-4 Windows full parity check' \
  "launcher wiring failed: option 98 numbered menu label missing"
check_cpp 'Phase-4 Windows full parity check' \
  "launcher wiring failed: option 98 menu label missing"
check_cpp 'phase4-windows-full-parity-check' \
  "launcher wiring failed: option 98 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 98 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 98 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 98 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase4-windows-full-parity-check"' \
  "launcher wiring failed: option 98 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 98 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 98 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 98 sudo forwarding missing"

echo "[easy-mode-wiring] option 99 command wiring"
check_cpp 'if \(choice == "99"\)' "launcher wiring failed: option 99 handler missing"
check_cpp '99\) Phase-4 Windows full parity run \(refresh \+ check\)' \
  "launcher wiring failed: option 99 numbered menu label missing"
check_cpp 'Phase-4 Windows full parity run \(refresh \+ check\)' \
  "launcher wiring failed: option 99 menu label missing"
check_cpp 'phase4-windows-full-parity-run' \
  "launcher wiring failed: option 99 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 99 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 99 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 99 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase4-windows-full-parity-run"' \
  "launcher wiring failed: option 99 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 99 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 99 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 99 sudo forwarding missing"

echo "[easy-mode-wiring] option 100 command wiring"
check_cpp 'if \(choice == "100"\)' "launcher wiring failed: option 100 handler missing"
check_cpp '100\) Phase-4 Windows full parity handoff check' \
  "launcher wiring failed: option 100 numbered menu label missing"
check_cpp 'Phase-4 Windows full parity handoff check' \
  "launcher wiring failed: option 100 menu label missing"
check_cpp 'phase4-windows-full-parity-handoff-check' \
  "launcher wiring failed: option 100 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 100 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 100 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 100 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase4-windows-full-parity-handoff-check"' \
  "launcher wiring failed: option 100 command assembly missing"
check_cpp '--show-json 1' \
  "launcher wiring failed: option 100 fixed --show-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 100 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 100 sudo forwarding missing"

echo "[easy-mode-wiring] option 101 command wiring"
check_cpp 'if \(choice == "101"\)' "launcher wiring failed: option 101 handler missing"
check_cpp '101\) Phase-4 Windows full parity handoff run \(run \+ check\)' \
  "launcher wiring failed: option 101 numbered menu label missing"
check_cpp 'Phase-4 Windows full parity handoff run \(run \+ check\)' \
  "launcher wiring failed: option 101 menu label missing"
check_cpp 'phase4-windows-full-parity-handoff-run' \
  "launcher wiring failed: option 101 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 101 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 101 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 101 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase4-windows-full-parity-handoff-run"' \
  "launcher wiring failed: option 101 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 101 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 101 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 101 sudo forwarding missing"

echo "[easy-mode-wiring] option 102 command wiring"
check_cpp 'if \(choice == "102"\)' "launcher wiring failed: option 102 handler missing"
check_cpp '102\) Phase-5 settlement layer CI gate' \
  "launcher wiring failed: option 102 numbered menu label missing"
check_cpp 'Phase-5 settlement layer CI gate' \
  "launcher wiring failed: option 102 menu label missing"
check_cpp 'ci-phase5-settlement-layer' \
  "launcher wiring failed: option 102 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 102 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 102 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 102 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " ci-phase5-settlement-layer"' \
  "launcher wiring failed: option 102 command assembly missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 102 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 102 sudo forwarding missing"

echo "[easy-mode-wiring] option 103 command wiring"
check_cpp 'if \(choice == "103"\)' "launcher wiring failed: option 103 handler missing"
check_cpp '103\) Phase-5 settlement layer check' \
  "launcher wiring failed: option 103 numbered menu label missing"
check_cpp 'Phase-5 settlement layer check' \
  "launcher wiring failed: option 103 menu label missing"
check_cpp 'phase5-settlement-layer-check' \
  "launcher wiring failed: option 103 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 103 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 103 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 103 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase5-settlement-layer-check"' \
  "launcher wiring failed: option 103 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 103 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 103 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 103 sudo forwarding missing"

echo "[easy-mode-wiring] option 104 command wiring"
check_cpp 'if \(choice == "104"\)' "launcher wiring failed: option 104 handler missing"
check_cpp '104\) Phase-5 settlement layer run \(refresh \+ check\)' \
  "launcher wiring failed: option 104 numbered menu label missing"
check_cpp 'Phase-5 settlement layer run \(refresh \+ check\)' \
  "launcher wiring failed: option 104 menu label missing"
check_cpp 'phase5-settlement-layer-run' \
  "launcher wiring failed: option 104 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 104 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 104 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 104 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase5-settlement-layer-run"' \
  "launcher wiring failed: option 104 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 104 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 104 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 104 sudo forwarding missing"

echo "[easy-mode-wiring] option 105 command wiring"
check_cpp 'if \(choice == "105"\)' "launcher wiring failed: option 105 handler missing"
check_cpp '105\) Phase-5 settlement layer handoff check' \
  "launcher wiring failed: option 105 numbered menu label missing"
check_cpp 'Phase-5 settlement layer handoff check' \
  "launcher wiring failed: option 105 menu label missing"
check_cpp 'phase5-settlement-layer-handoff-check' \
  "launcher wiring failed: option 105 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 105 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 105 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 105 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase5-settlement-layer-handoff-check"' \
  "launcher wiring failed: option 105 command assembly missing"
check_cpp '--show-json 1' \
  "launcher wiring failed: option 105 fixed --show-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 105 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 105 sudo forwarding missing"

echo "[easy-mode-wiring] option 106 command wiring"
check_cpp 'if \(choice == "106"\)' "launcher wiring failed: option 106 handler missing"
check_cpp '106\) Phase-5 settlement layer handoff run \(run \+ check\)' \
  "launcher wiring failed: option 106 numbered menu label missing"
check_cpp 'Phase-5 settlement layer handoff run \(run \+ check\)' \
  "launcher wiring failed: option 106 menu label missing"
check_cpp 'phase5-settlement-layer-handoff-run' \
  "launcher wiring failed: option 106 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 106 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 106 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 106 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " phase5-settlement-layer-handoff-run"' \
  "launcher wiring failed: option 106 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 106 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 106 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 106 sudo forwarding missing"

echo "[easy-mode-wiring] option 107 command wiring"
check_cpp 'if \(choice == "107"\)' "launcher wiring failed: option 107 handler missing"
check_cpp '107\) VPN non-blockchain fastlane \(runtime\+phase1-4 handoff\+roadmap\)' \
  "launcher wiring failed: option 107 numbered menu label missing"
check_cpp 'VPN non-blockchain fastlane \(runtime\+phase1-4 handoff\+roadmap\)' \
  "launcher wiring failed: option 107 menu label missing"
check_cpp 'vpn-non-blockchain-fastlane' \
  "launcher wiring failed: option 107 command keyword missing"
check_cpp 'Run with sudo\? \(y/N\)' "launcher wiring failed: option 107 sudo prompt missing"
check_cpp 'readLine\("Run with sudo\? \(y/N\)", "n"\)' \
  "launcher wiring failed: option 107 sudo prompt default missing"
check_cpp 'bool runWithSudo = parseYesNo\(readLine\("Run with sudo\? \(y/N\)", "n"\), false\);' \
  "launcher wiring failed: option 107 sudo parse wiring missing"
check_cpp 'cmd << shellEscape\(script\) << " vpn-non-blockchain-fastlane"' \
  "launcher wiring failed: option 107 command assembly missing"
check_cpp '--print-summary-json 1' \
  "launcher wiring failed: option 107 fixed --print-summary-json 1 missing"
check_cpp 'if \(runWithSudo\)' "launcher wiring failed: option 107 sudo branch missing"
check_cpp 'cmd << "sudo ";' "launcher wiring failed: option 107 sudo forwarding missing"

check_cpp '--min-peer-source-operators ' "launcher wiring failed: option 69/70 min-peer-source-operators forwarding missing"
check_cpp '--min-issuer-source-operators ' "launcher wiring failed: option 69/70 min-issuer-source-operators forwarding missing"
check_cpp '--summary-json ' "launcher wiring failed: option 69/70 summary-json forwarding missing"
check_cpp '--print-summary-json ' "launcher wiring failed: option 69/70 print-summary-json forwarding missing"
check_cpp '--fail-on-not-ready ' "launcher wiring failed: option 69 fail-on-not-ready forwarding missing"
check_cpp 'if \(choice == "70"\)' "launcher wiring failed: option 70 handler missing"
check_cpp 'server-federation-wait' "launcher wiring failed: option 70 command missing"
check_cpp 'Ready timeout sec' "launcher wiring failed: option 70 ready timeout prompt missing"
check_cpp 'Poll interval sec' "launcher wiring failed: option 70 poll interval prompt missing"

echo "[easy-mode-wiring] options 71/72/73 command wiring"
check_cpp 'if \(choice == "71"\)' "launcher wiring failed: option 71 handler missing"
check_cpp 'prod-pilot-cohort-campaign-summary' "launcher wiring failed: option 71 command missing"
check_cpp 'Campaign summary JSON path' "launcher wiring failed: option 71 summary JSON prompt missing"
check_cpp 'Fail when campaign decision is NO-GO\?' "launcher wiring failed: option 71 fail-on-no-go prompt missing"
check_cpp 'if \(choice == "72"\)' "launcher wiring failed: option 72 handler missing"
check_cpp 'prod-pilot-cohort-campaign-check' "launcher wiring failed: option 72 command missing"
check_cpp 'Require runbook summary JSON artifact present/valid\?' "launcher wiring failed: option 72 runbook summary prompt missing"
check_cpp 'Require quick run-report JSON artifact present/valid\?' "launcher wiring failed: option 72 quick run-report prompt missing"
check_cpp 'Require campaign summary decision=GO\?' "launcher wiring failed: option 72 GO policy prompt missing"
check_cpp 'Require campaign signoff stage\+summary evidence \(strict\)\?' "launcher wiring failed: option 72 campaign signoff evidence prompt missing"
check_cpp 'Check summary JSON path \(optional\)' "launcher wiring failed: option 72 summary-json prompt missing"
check_cpp 'Print check summary JSON payload\?' "launcher wiring failed: option 72 print-summary-json prompt missing"
check_cpp '--require-runbook-summary-json ' "launcher wiring failed: option 72 runbook summary forwarding missing"
check_cpp '--require-quick-run-report-json ' "launcher wiring failed: option 72 quick run-report forwarding missing"
check_cpp '--require-summary-policy-match ' "launcher wiring failed: option 72 summary policy forwarding missing"
check_cpp '--require-incident-policy-clean ' "launcher wiring failed: option 72 incident policy forwarding missing"
check_cpp '--require-campaign-signoff-enabled ' "launcher wiring failed: option 72 campaign signoff enabled forwarding missing"
check_cpp '--require-campaign-signoff-required ' "launcher wiring failed: option 72 campaign signoff required forwarding missing"
check_cpp '--require-campaign-signoff-attempted ' "launcher wiring failed: option 72 campaign signoff attempted forwarding missing"
check_cpp '--require-campaign-signoff-ok ' "launcher wiring failed: option 72 campaign signoff rc forwarding missing"
check_cpp '--require-campaign-signoff-summary-json ' "launcher wiring failed: option 72 campaign signoff summary forwarding missing"
check_cpp '--require-campaign-signoff-summary-json-valid ' "launcher wiring failed: option 72 campaign signoff summary valid forwarding missing"
check_cpp '--require-campaign-signoff-summary-status-ok ' "launcher wiring failed: option 72 campaign signoff summary status forwarding missing"
check_cpp '--require-campaign-signoff-summary-final-rc-zero ' "launcher wiring failed: option 72 campaign signoff summary final_rc forwarding missing"
check_cpp '--summary-json ' "launcher wiring failed: option 72 summary-json forwarding missing"
check_cpp '--print-summary-json ' "launcher wiring failed: option 72 print-summary-json forwarding missing"
check_cpp 'if \(choice == "73"\)' "launcher wiring failed: option 73 handler missing"
check_cpp 'prod-pilot-cohort-campaign-signoff' "launcher wiring failed: option 73 command missing"
check_cpp 'Refresh campaign summary before check\?' "launcher wiring failed: option 73 refresh prompt missing"
check_cpp 'Campaign signoff stage summary JSON path \(optional\)' "launcher wiring failed: option 73 campaign signoff stage summary prompt missing"
check_cpp 'Require existing campaign signoff stage\+summary evidence\?' "launcher wiring failed: option 73 campaign signoff evidence prompt missing"
check_cpp 'Signoff summary JSON path \(optional\)' "launcher wiring failed: option 73 summary-json prompt missing"
check_cpp 'Print signoff summary JSON payload\?' "launcher wiring failed: option 73 print-summary-json prompt missing"
check_cpp '--summary-fail-on-no-go ' "launcher wiring failed: option 73 summary fail-on-no-go forwarding missing"
check_cpp '--require-runbook-summary-json ' "launcher wiring failed: option 73 runbook summary forwarding missing"
check_cpp '--require-quick-run-report-json ' "launcher wiring failed: option 73 quick run-report forwarding missing"
check_cpp '--require-summary-policy-match ' "launcher wiring failed: option 73 summary policy forwarding missing"
check_cpp '--require-incident-policy-clean ' "launcher wiring failed: option 73 incident policy forwarding missing"
check_cpp '--campaign-signoff-summary-json ' "launcher wiring failed: option 73 campaign signoff stage summary forwarding missing"
check_cpp '--require-campaign-signoff-enabled ' "launcher wiring failed: option 73 campaign signoff enabled forwarding missing"
check_cpp '--require-campaign-signoff-required ' "launcher wiring failed: option 73 campaign signoff required forwarding missing"
check_cpp '--require-campaign-signoff-attempted ' "launcher wiring failed: option 73 campaign signoff attempted forwarding missing"
check_cpp '--require-campaign-signoff-ok ' "launcher wiring failed: option 73 campaign signoff rc forwarding missing"
check_cpp '--require-campaign-signoff-summary-json ' "launcher wiring failed: option 73 campaign signoff summary forwarding missing"
check_cpp '--require-campaign-signoff-summary-json-valid ' "launcher wiring failed: option 73 campaign signoff summary valid forwarding missing"
check_cpp '--require-campaign-signoff-summary-status-ok ' "launcher wiring failed: option 73 campaign signoff summary status forwarding missing"
check_cpp '--require-campaign-signoff-summary-final-rc-zero ' "launcher wiring failed: option 73 campaign signoff summary final_rc forwarding missing"
check_cpp '--summary-json ' "launcher wiring failed: option 73 summary-json forwarding missing"
check_cpp '--print-summary-json ' "launcher wiring failed: option 73 print-summary-json forwarding missing"

echo "[easy-mode-wiring] easy_node help exposure"
if ! "$EASY_NODE" --help --expert | rg -q 'simple-client-test'; then
  echo "launcher wiring failed: easy_node help missing simple-client-test"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'simple-client-vpn-preflight'; then
  echo "launcher wiring failed: easy_node help missing simple-client-vpn-preflight"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'simple-client-vpn-session'; then
  echo "launcher wiring failed: easy_node help missing simple-client-vpn-session"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'simple-server-preflight'; then
  echo "launcher wiring failed: easy_node help missing simple-server-preflight"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'simple-server-session'; then
  echo "launcher wiring failed: easy_node help missing simple-server-session"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-pilot-cohort-quick-signoff'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-quick-signoff"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-pilot-cohort-quick-runbook'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-quick-runbook"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-pilot-cohort-campaign'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-campaign"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-pilot-cohort-campaign-check'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-campaign-check"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-pilot-cohort-campaign-signoff'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-campaign-signoff"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'runtime-doctor'; then
  echo "launcher wiring failed: easy_node help missing runtime-doctor"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'manual-validation-backlog'; then
  echo "launcher wiring failed: easy_node help missing manual-validation-backlog"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'manual-validation-status'; then
  echo "launcher wiring failed: easy_node help missing manual-validation-status"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q -- 'manual-validation-status .*--profile-compare-signoff-summary-json'; then
  echo "launcher wiring failed: easy_node help missing manual-validation-status --profile-compare-signoff-summary-json"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q -- 'manual-validation-status .*--overlay-check-id'; then
  echo "launcher wiring failed: easy_node help missing manual-validation-status --overlay-check-id"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'manual-validation-report'; then
  echo "launcher wiring failed: easy_node help missing manual-validation-report"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q -- 'manual-validation-report .*--profile-compare-signoff-summary-json'; then
  echo "launcher wiring failed: easy_node help missing manual-validation-report --profile-compare-signoff-summary-json"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q -- 'manual-validation-report .*--overlay-check-id'; then
  echo "launcher wiring failed: easy_node help missing manual-validation-report --overlay-check-id"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'wg-only-stack-selftest-record'; then
  echo "launcher wiring failed: easy_node help missing wg-only-stack-selftest-record"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'pre-real-host-readiness'; then
  echo "launcher wiring failed: easy_node help missing pre-real-host-readiness"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'server-federation-status'; then
  echo "launcher wiring failed: easy_node help missing server-federation-status"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'server-federation-wait'; then
  echo "launcher wiring failed: easy_node help missing server-federation-wait"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'manual-validation-record'; then
  echo "launcher wiring failed: easy_node help missing manual-validation-record"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'client-vpn-smoke'; then
  echo "launcher wiring failed: easy_node help missing client-vpn-smoke"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'three-machine-prod-signoff'; then
  echo "launcher wiring failed: easy_node help missing three-machine-prod-signoff"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'runtime-fix'; then
  echo "launcher wiring failed: easy_node help missing runtime-fix"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'incident-snapshot'; then
  echo "launcher wiring failed: easy_node help missing incident-snapshot"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-gate-slo-dashboard'; then
  echo "launcher wiring failed: easy_node help missing prod-gate-slo-dashboard"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-key-rotation-runbook'; then
  echo "launcher wiring failed: easy_node help missing prod-key-rotation-runbook"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-upgrade-runbook'; then
  echo "launcher wiring failed: easy_node help missing prod-upgrade-runbook"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-operator-lifecycle-runbook'; then
  echo "launcher wiring failed: easy_node help missing prod-operator-lifecycle-runbook"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-pilot-cohort-runbook'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-runbook"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-pilot-cohort-bundle-verify'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-bundle-verify"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-pilot-cohort-signoff'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-signoff"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'prod-pilot-cohort-quick-dashboard'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-quick-dashboard"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'vpn-rc-standard-path'; then
  echo "launcher wiring failed: easy_node help missing vpn-rc-standard-path"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'vpn-rc-matrix-path'; then
  echo "launcher wiring failed: easy_node help missing vpn-rc-matrix-path"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'ci-phase0'; then
  echo "launcher wiring failed: easy_node help missing ci-phase0"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'ci-phase1-resilience'; then
  echo "launcher wiring failed: easy_node help missing ci-phase1-resilience"
  exit 1
fi
if ! "$EASY_NODE" vpn-rc-resilience-path --help | rg -q -- '--docker-profile-matrix-timeout-sec'; then
  echo "launcher wiring failed: vpn-rc-resilience-path help missing --docker-profile-matrix-timeout-sec"
  exit 1
fi
if ! "$EASY_NODE" vpn-rc-resilience-path --help | rg -q -- '--rc-matrix-path-timeout-sec'; then
  echo "launcher wiring failed: vpn-rc-resilience-path help missing --rc-matrix-path-timeout-sec"
  exit 1
fi
if ! "$EASY_NODE" ci-phase1-resilience --help | rg -q -- '--vpn-rc-resilience-path-timeout-sec'; then
  echo "launcher wiring failed: ci-phase1-resilience help missing --vpn-rc-resilience-path-timeout-sec"
  exit 1
fi
if ! "$EASY_NODE" ci-phase1-resilience --help | rg -q -- '--session-churn-guard-timeout-sec'; then
  echo "launcher wiring failed: ci-phase1-resilience help missing --session-churn-guard-timeout-sec"
  exit 1
fi
if ! "$EASY_NODE" vpn-non-blockchain-fastlane --help | rg -q -- '--parallel'; then
  echo "launcher wiring failed: vpn-non-blockchain-fastlane help missing --parallel"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'phase1-resilience-handoff-check'; then
  echo "launcher wiring failed: easy_node help missing phase1-resilience-handoff-check"
  exit 1
fi
if ! "$EASY_NODE" --help --expert | rg -q 'phase1-resilience-handoff-run'; then
  echo "launcher wiring failed: easy_node help missing phase1-resilience-handoff-run"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-signoff --help | rg -q -- '--max-alert-severity'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-signoff help missing --max-alert-severity"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-signoff --help | rg -q -- '--require-trend-artifact-policy-match'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-signoff help missing --require-trend-artifact-policy-match"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-check --help | rg -q -- '--require-bundle-created'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-check help missing --require-bundle-created"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-runbook --help | rg -q -- '--dashboard-fail-close'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-runbook help missing --dashboard-fail-close"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-runbook --help | rg -q -- '--signoff-require-cohort-signoff-policy'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-runbook help missing --signoff-require-cohort-signoff-policy"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-runbook --help | rg -q -- '--signoff-require-trend-artifact-policy-match'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-runbook help missing --signoff-require-trend-artifact-policy-match"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-runbook --help | rg -q -- '--signoff-incident-snapshot-min-attachment-count'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-runbook help missing --signoff-incident-snapshot-min-attachment-count"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-runbook --help | rg -q -- '--signoff-incident-snapshot-max-skipped-count'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-runbook help missing --signoff-incident-snapshot-max-skipped-count"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-runbook --help | rg -q -- '--max-round-failures'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-runbook help missing --max-round-failures"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-runbook --help | rg -q -- '--bundle-outputs'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-runbook help missing --bundle-outputs"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-runbook --help | rg -q -- '--pre-real-host-readiness'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-runbook help missing --pre-real-host-readiness"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign --help | rg -q -- 'prod-pilot-cohort-quick-runbook'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign help missing quick-runbook reference"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign --help | rg -q -- '--pre-real-host-readiness'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign help missing --pre-real-host-readiness"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign --help | rg -q -- '--campaign-require-incident-snapshot-on-fail'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign help missing --campaign-require-incident-snapshot-on-fail"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign --help | rg -q -- '--campaign-incident-snapshot-max-skipped-count'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign help missing --campaign-incident-snapshot-max-skipped-count"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign --help | rg -q -- '--campaign-run-report-json'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign help missing --campaign-run-report-json"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign --help | rg -q -- '--campaign-run-report-required'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign help missing --campaign-run-report-required"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign --help | rg -q -- '--campaign-run-report-json-required'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign help missing --campaign-run-report-json-required"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign --help | rg -q -- '--campaign-signoff-check'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign help missing --campaign-signoff-check"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign --help | rg -q -- '--campaign-signoff-required'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign help missing --campaign-signoff-required"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign --help | rg -q -- '--campaign-signoff-summary-json'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign help missing --campaign-signoff-summary-json"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign --help | rg -q -- '--campaign-signoff-summary-fail-on-no-go'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign help missing --campaign-signoff-summary-fail-on-no-go"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-summary --help | rg -q -- '--require-incident-snapshot-on-fail'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-summary help missing --require-incident-snapshot-on-fail"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-summary --help | rg -q -- '--incident-snapshot-max-skipped-count'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-summary help missing --incident-snapshot-max-skipped-count"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-summary --help | rg -q -- '--fail-on-no-go'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-summary help missing --fail-on-no-go"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--campaign-run-report-json'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --campaign-run-report-json"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--campaign-signoff-summary-json'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --campaign-signoff-summary-json"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--require-summary-policy-match'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --require-summary-policy-match"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--require-campaign-signoff-attempted'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --require-campaign-signoff-attempted"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--require-campaign-signoff-enabled'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --require-campaign-signoff-enabled"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--require-campaign-signoff-required'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --require-campaign-signoff-required"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--require-campaign-signoff-summary-json-valid'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --require-campaign-signoff-summary-json-valid"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--require-campaign-signoff-summary-status-ok'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --require-campaign-signoff-summary-status-ok"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--require-campaign-signoff-summary-final-rc-zero'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --require-campaign-signoff-summary-final-rc-zero"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--require-campaign-summary-fail-close'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --require-campaign-summary-fail-close"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--require-campaign-signoff-check'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --require-campaign-signoff-check"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--require-campaign-run-report-required'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --require-campaign-run-report-required"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--require-campaign-run-report-json-required'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --require-campaign-run-report-json-required"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-check --help | rg -q -- '--require-artifact-path-match'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-check help missing --require-artifact-path-match"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--refresh-summary'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --refresh-summary"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--summary-fail-on-no-go'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --summary-fail-on-no-go"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--campaign-signoff-summary-json'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --campaign-signoff-summary-json"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--require-campaign-signoff-attempted'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --require-campaign-signoff-attempted"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--require-campaign-signoff-enabled'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --require-campaign-signoff-enabled"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--require-campaign-signoff-required'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --require-campaign-signoff-required"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--require-campaign-signoff-summary-json-valid'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --require-campaign-signoff-summary-json-valid"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--require-campaign-signoff-summary-status-ok'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --require-campaign-signoff-summary-status-ok"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--require-campaign-signoff-summary-final-rc-zero'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --require-campaign-signoff-summary-final-rc-zero"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--require-campaign-summary-fail-close'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --require-campaign-summary-fail-close"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--require-campaign-signoff-check'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --require-campaign-signoff-check"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--require-campaign-run-report-required'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --require-campaign-run-report-required"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--require-campaign-run-report-json-required'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --require-campaign-run-report-json-required"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-campaign-signoff --help | rg -q -- '--require-artifact-path-match'; then
  echo "launcher wiring failed: prod-pilot-cohort-campaign-signoff help missing --require-artifact-path-match"
  exit 1
fi
if ! "$EASY_NODE" incident-snapshot --help | rg -q -- '--include-docker-logs'; then
  echo "launcher wiring failed: incident-snapshot help missing --include-docker-logs"
  exit 1
fi
if ! "$EASY_NODE" prod-gate-slo-dashboard --help | rg -q -- '--dashboard-md'; then
  echo "launcher wiring failed: prod-gate-slo-dashboard help missing --dashboard-md"
  exit 1
fi
if ! "$EASY_NODE" prod-key-rotation-runbook --help | rg -q -- '--key-history'; then
  echo "launcher wiring failed: prod-key-rotation-runbook help missing --key-history"
  exit 1
fi
if ! "$EASY_NODE" prod-upgrade-runbook --help | rg -q -- '--compose-pull'; then
  echo "launcher wiring failed: prod-upgrade-runbook help missing --compose-pull"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--verify-relays'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --verify-relays"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--federation-check'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --federation-check"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--federation-status-file'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --federation-status-file"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--federation-status-summary-json'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --federation-status-summary-json"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--onboard-invite'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --onboard-invite"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--onboard-invite-file'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --onboard-invite-file"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--rollback-on-fail'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --rollback-on-fail"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--rollback-verify-timeout-sec'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --rollback-verify-timeout-sec"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--incident-snapshot-on-fail'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --incident-snapshot-on-fail"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--incident-docker-log-lines'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --incident-docker-log-lines"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--incident-attach-min-count'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --incident-attach-min-count"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--incident-attachment-manifest-min-count'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --incident-attachment-manifest-min-count"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--runtime-doctor-on-fail'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --runtime-doctor-on-fail"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--runtime-doctor-base-port'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --runtime-doctor-base-port"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--runtime-doctor-client-iface'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --runtime-doctor-client-iface"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--runtime-doctor-exit-iface'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --runtime-doctor-exit-iface"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--runtime-doctor-vpn-iface'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --runtime-doctor-vpn-iface"
  exit 1
fi
if ! "$EASY_NODE" prod-operator-lifecycle-runbook --help | rg -q -- '--report-md'; then
  echo "launcher wiring failed: prod-operator-lifecycle-runbook help missing --report-md"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-runbook --help | rg -q -- '--bundle-fail-close'; then
  echo "launcher wiring failed: prod-pilot-cohort-runbook help missing --bundle-fail-close"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-runbook --help | rg -q -- '--pre-real-host-readiness'; then
  echo "launcher wiring failed: prod-pilot-cohort-runbook help missing --pre-real-host-readiness"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-bundle-verify --help | rg -q -- '--check-manifest'; then
  echo "launcher wiring failed: prod-pilot-cohort-bundle-verify help missing --check-manifest"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-signoff --help | rg -q -- '--max-alert-severity'; then
  echo "launcher wiring failed: prod-pilot-cohort-signoff help missing --max-alert-severity"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick --help | rg -q -- '--run-report-json'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick help missing --run-report-json"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick --help | rg -q -- '--signoff-require-trend-artifact-policy-match'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick help missing --signoff-require-trend-artifact-policy-match"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick --help | rg -q -- '--max-round-failures'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick help missing --max-round-failures"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick --help | rg -q -- '--signoff-require-incident-snapshot-artifacts'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick help missing --signoff-require-incident-snapshot-artifacts"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick --help | rg -q -- '--signoff-incident-snapshot-min-attachment-count'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick help missing --signoff-incident-snapshot-min-attachment-count"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick --help | rg -q -- '--signoff-incident-snapshot-max-skipped-count'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick help missing --signoff-incident-snapshot-max-skipped-count"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick --help | rg -q -- '--pre-real-host-readiness'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick help missing --pre-real-host-readiness"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-check --help | rg -q -- '--require-signoff-attempted'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-check help missing --require-signoff-attempted"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-trend --help | rg -q -- '--min-go-rate-pct'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-trend help missing --min-go-rate-pct"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-alert --help | rg -q -- '--warn-go-rate-pct'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-alert help missing --warn-go-rate-pct"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-dashboard --help | rg -q -- '--dashboard-md'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-dashboard help missing --dashboard-md"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-dashboard --help | rg -q -- '--incident-snapshot-min-attachment-count'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-dashboard help missing --incident-snapshot-min-attachment-count"
  exit 1
fi
if ! "$EASY_NODE" prod-pilot-cohort-quick-dashboard --help | rg -q -- '--incident-snapshot-max-skipped-count'; then
  echo "launcher wiring failed: prod-pilot-cohort-quick-dashboard help missing --incident-snapshot-max-skipped-count"
  exit 1
fi

echo "[easy-mode-wiring] easy_node wrapper forwarding contracts"
FORWARD_TMP_DIR="$(mktemp -d)"
cleanup_forward_tmp() {
  rm -rf "$FORWARD_TMP_DIR"
}
trap cleanup_forward_tmp EXIT

FORWARD_CAPTURE="$FORWARD_TMP_DIR/easy_node_forwarding.tsv"
FAKE_FORWARD_SCRIPT="$FORWARD_TMP_DIR/fake_forward.sh"
cat >"$FAKE_FORWARD_SCRIPT" <<'EOF_FAKE_FORWARD'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${EASY_NODE_FORWARD_CAPTURE_FILE:?}"
label="${EASY_NODE_FORWARD_LABEL:?}"

{
  printf '%s' "$label"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
EOF_FAKE_FORWARD
chmod +x "$FAKE_FORWARD_SCRIPT"
: >"$FORWARD_CAPTURE"

if ! EASY_NODE_FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
  EASY_NODE_FORWARD_LABEL="vpn_rc_resilience_path" \
  VPN_RC_RESILIENCE_PATH_SCRIPT="$FAKE_FORWARD_SCRIPT" \
  "$EASY_NODE" vpn-rc-resilience-path \
  --docker-profile-matrix-timeout-sec 61 \
  --rc-matrix-path-timeout-sec 62 \
  --print-summary-json 0 >/dev/null 2>&1; then
  echo "launcher wiring failed: vpn-rc-resilience-path forwarding invocation failed"
  exit 1
fi

vpn_rc_forward_line="$(last_forward_line_for_label "$FORWARD_CAPTURE" "vpn_rc_resilience_path")"
if [[ -z "$vpn_rc_forward_line" ]]; then
  echo "launcher wiring failed: missing vpn-rc-resilience-path forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
assert_forward_line_has_token "$vpn_rc_forward_line" $'\t--docker-profile-matrix-timeout-sec\t61' \
  "launcher wiring failed: vpn-rc-resilience-path forwarding missing --docker-profile-matrix-timeout-sec 61"
assert_forward_line_has_token "$vpn_rc_forward_line" $'\t--rc-matrix-path-timeout-sec\t62' \
  "launcher wiring failed: vpn-rc-resilience-path forwarding missing --rc-matrix-path-timeout-sec 62"

if ! EASY_NODE_FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
  EASY_NODE_FORWARD_LABEL="ci_phase1_resilience" \
  CI_PHASE1_RESILIENCE_SCRIPT="$FAKE_FORWARD_SCRIPT" \
  "$EASY_NODE" ci-phase1-resilience \
  --vpn-rc-resilience-path-timeout-sec 71 \
  --session-churn-guard-timeout-sec 72 \
  --print-summary-json 0 >/dev/null 2>&1; then
  echo "launcher wiring failed: ci-phase1-resilience forwarding invocation failed"
  exit 1
fi

ci_phase1_forward_line="$(last_forward_line_for_label "$FORWARD_CAPTURE" "ci_phase1_resilience")"
if [[ -z "$ci_phase1_forward_line" ]]; then
  echo "launcher wiring failed: missing ci-phase1-resilience forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
assert_forward_line_has_token "$ci_phase1_forward_line" $'\t--vpn-rc-resilience-path-timeout-sec\t71' \
  "launcher wiring failed: ci-phase1-resilience forwarding missing --vpn-rc-resilience-path-timeout-sec 71"
assert_forward_line_has_token "$ci_phase1_forward_line" $'\t--session-churn-guard-timeout-sec\t72' \
  "launcher wiring failed: ci-phase1-resilience forwarding missing --session-churn-guard-timeout-sec 72"

if ! EASY_NODE_FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
  EASY_NODE_FORWARD_LABEL="vpn_non_blockchain_fastlane" \
  VPN_NON_BLOCKCHAIN_FASTLANE_SCRIPT="$FAKE_FORWARD_SCRIPT" \
  "$EASY_NODE" vpn-non-blockchain-fastlane \
  --parallel 0 \
  --print-summary-json 0 >/dev/null 2>&1; then
  echo "launcher wiring failed: vpn-non-blockchain-fastlane forwarding invocation failed"
  exit 1
fi

fastlane_forward_line="$(last_forward_line_for_label "$FORWARD_CAPTURE" "vpn_non_blockchain_fastlane")"
if [[ -z "$fastlane_forward_line" ]]; then
  echo "launcher wiring failed: missing vpn-non-blockchain-fastlane forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
assert_forward_line_has_token "$fastlane_forward_line" $'\t--parallel\t0' \
  "launcher wiring failed: vpn-non-blockchain-fastlane forwarding missing --parallel 0"

echo "easy-mode launcher wiring integration check ok"
