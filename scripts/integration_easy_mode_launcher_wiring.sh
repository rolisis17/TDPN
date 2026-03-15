#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CPP_UI="tools/easy_mode/easy_mode_ui.cpp"
EASY_NODE="scripts/easy_node.sh"

for cmd in rg; do
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

echo "[easy-mode-wiring] main menu simplicity contract"
check_cpp 'Main menu:' "launcher wiring failed: main menu heading missing"
check_cpp '1\) Connect as CLIENT \(simple\)' "launcher wiring failed: simple CLIENT entry missing"
check_cpp '2\) Connect as SERVER \(simple, provider default\)' "launcher wiring failed: simple SERVER entry missing"
check_cpp '3\) Other options \(tests/config\)' "launcher wiring failed: advanced options entry missing"

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
check_cpp '--bundle-outputs ' "launcher wiring failed: option 48/51 bundle-outputs forwarding missing"
check_cpp '--bundle-fail-close ' "launcher wiring failed: option 48/51 bundle-fail-close forwarding missing"
check_cpp 'Run pre-real-host readiness once before the cohort\?' "launcher wiring failed: option 48/51 pre-real-host readiness prompt missing"
check_cpp '--pre-real-host-readiness ' "launcher wiring failed: option 48/51 pre-real-host readiness forwarding missing"
check_cpp '--check-tar-sha256 ' "launcher wiring failed: option 49/50/51 signoff integrity forwarding missing"
check_cpp '--check-manifest ' "launcher wiring failed: option 49/50/51 signoff manifest forwarding missing"
check_cpp '--max-alert-severity ' "launcher wiring failed: option 48/50/51/52 max-alert-severity forwarding missing"
check_cpp '--run-report-json ' "launcher wiring failed: option 52/53/57/58 run-report-json forwarding missing"
check_cpp 'Run pre-real-host readiness once before the cohort\?' "launcher wiring failed: option 52/58 pre-real-host readiness prompt missing"
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
check_cpp '--max-round-failures ' "launcher wiring failed: option 58 max-round-failures forwarding missing"
check_cpp '--bundle-outputs ' "launcher wiring failed: option 58 bundle-outputs forwarding missing"
check_cpp '--bundle-fail-close ' "launcher wiring failed: option 58 bundle-fail-close forwarding missing"
check_cpp '--pre-real-host-readiness ' "launcher wiring failed: option 52/58/59 pre-real-host readiness forwarding missing"

echo "[easy-mode-wiring] option 59 command wiring"
check_cpp 'if \(choice == "59"\)' "launcher wiring failed: option 59 handler missing"
check_cpp 'prod-pilot-cohort-campaign' "launcher wiring failed: option 59 command missing"
check_cpp 'Run pre-real-host readiness once before the campaign\?' "launcher wiring failed: option 59 pre-real-host readiness prompt missing"
check_cpp 'Extra campaign args \(optional\)' "launcher wiring failed: option 59 prompt text missing"
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
check_cpp 'Show JSON summary payload\?' "launcher wiring failed: option 63 JSON prompt missing"

echo "[easy-mode-wiring] option 64 command wiring"
check_cpp 'if \(choice == "64"\)' "launcher wiring failed: option 64 handler missing"
check_cpp 'client-vpn-smoke' "launcher wiring failed: option 64 command missing"
check_cpp 'Public IP check URL' "launcher wiring failed: option 64 public IP prompt missing"
check_cpp 'Country check URL' "launcher wiring failed: option 64 country prompt missing"
check_cpp 'Run pre-real-host readiness first\?' "launcher wiring failed: option 64 pre-real-host readiness prompt missing"
check_cpp '--path-profile balanced' "launcher wiring failed: option 64 balanced path default missing"
check_cpp '--distinct-operators 1' "launcher wiring failed: option 64 distinct-operators default missing"

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

echo "[easy-mode-wiring] easy_node help exposure"
if ! "$EASY_NODE" --help | rg -q 'prod-pilot-cohort-quick-signoff'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-quick-signoff"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'prod-pilot-cohort-quick-runbook'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-quick-runbook"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'prod-pilot-cohort-campaign'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-campaign"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'runtime-doctor'; then
  echo "launcher wiring failed: easy_node help missing runtime-doctor"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'manual-validation-backlog'; then
  echo "launcher wiring failed: easy_node help missing manual-validation-backlog"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'manual-validation-status'; then
  echo "launcher wiring failed: easy_node help missing manual-validation-status"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'manual-validation-report'; then
  echo "launcher wiring failed: easy_node help missing manual-validation-report"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'wg-only-stack-selftest-record'; then
  echo "launcher wiring failed: easy_node help missing wg-only-stack-selftest-record"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'pre-real-host-readiness'; then
  echo "launcher wiring failed: easy_node help missing pre-real-host-readiness"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'manual-validation-record'; then
  echo "launcher wiring failed: easy_node help missing manual-validation-record"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'client-vpn-smoke'; then
  echo "launcher wiring failed: easy_node help missing client-vpn-smoke"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'three-machine-prod-signoff'; then
  echo "launcher wiring failed: easy_node help missing three-machine-prod-signoff"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'runtime-fix'; then
  echo "launcher wiring failed: easy_node help missing runtime-fix"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'incident-snapshot'; then
  echo "launcher wiring failed: easy_node help missing incident-snapshot"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'prod-gate-slo-dashboard'; then
  echo "launcher wiring failed: easy_node help missing prod-gate-slo-dashboard"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'prod-key-rotation-runbook'; then
  echo "launcher wiring failed: easy_node help missing prod-key-rotation-runbook"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'prod-upgrade-runbook'; then
  echo "launcher wiring failed: easy_node help missing prod-upgrade-runbook"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'prod-operator-lifecycle-runbook'; then
  echo "launcher wiring failed: easy_node help missing prod-operator-lifecycle-runbook"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'prod-pilot-cohort-runbook'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-runbook"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'prod-pilot-cohort-bundle-verify'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-bundle-verify"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'prod-pilot-cohort-signoff'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-signoff"
  exit 1
fi
if ! "$EASY_NODE" --help | rg -q 'prod-pilot-cohort-quick-dashboard'; then
  echo "launcher wiring failed: easy_node help missing prod-pilot-cohort-quick-dashboard"
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

echo "easy-mode launcher wiring integration check ok"
