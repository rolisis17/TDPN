# Testing Guide (Simple, End-to-End)

## 1) What you are testing

This prototype is a two-hop privacy path:
- `client -> entry -> exit`
- control services: `directory` + `issuer`

Core behavior under test:
- client can discover relays and build a path
- entry/exit enforce token and tier policy
- descriptor signatures and trust checks work
- revocation and anti-abuse controls work
- federated directory behavior works (fanout + peer sync)
- selection feed scoring and locality selection work
- signed trust-attestation feed (bond/stake signals) works
- issuer dispute lifecycle can cap/restore trust tier eligibility with case/evidence metadata propagation

## 2) Prerequisites

Required:
- Go installed (`go version`)
- `curl`
- `rg` (ripgrep)
- `jq`
- `openssl`
- Linux/macOS shell

Optional easy launcher path:
- `./scripts/install_easy_mode.sh`
- `./bin/privacynode-easy`
- `docs/easy-3-machine-test.md`
- `docs/windows-wsl2.md` (Windows 11 + WSL2 path)

Project root:
- run all commands from repository root

## 3) Fastest full check

Run:

```bash
./scripts/ci_local.sh
```

What this does:
1. Runs all Go tests.
2. Runs internal topology smoke test.
3. Runs integration checks:
   - challenge
   - revocation
   - token-proof replay
   - provider api
   - distinct operators
   - federation
   - directory sync
   - selection feed
   - trust feed
   - opaque source
   - session reuse
   - session handoff
   - issuer trust sync
   - issuer dispute
   - multi-issuer
   - load/chaos

Expected result:
- final line: `[ci] ok`

If it fails:
- script prints relevant logs from `/tmp/*`.

## 4) Manual end-to-end run (to understand flow)

Terminal A:

```bash
go run ./cmd/node --directory --issuer
```

Terminal B:

```bash
go run ./cmd/node --entry --exit
```

Terminal C:

```bash
go run ./cmd/node --client
```

What to expect:
- client logs a selected entry/exit pair
- entry logs accepted path open and forwarding
- exit logs accepted packet handling

This is the simplest full path test.

3-machine external beta validation (machine C runner):

```bash
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084 \
  --min-sources 2 \
  --min-operators 2 \
  --beta-profile 1 \
  --distinct-operators 1
```

Path profile presets for client routing tests:

- Fast: `--distinct-operators 1 --distinct-countries 0 --locality-soft-bias 1 --country-bias 1.80 --region-bias 1.35 --region-prefix-bias 1.15`
- Balanced: `--distinct-operators 1 --distinct-countries 0 --locality-soft-bias 1 --country-bias 1.50 --region-bias 1.25 --region-prefix-bias 1.10`
- Privacy: `--distinct-operators 1 --distinct-countries 1 --locality-soft-bias 0`
- Shortcut: use `--path-profile fast|balanced|privacy` on validate/soak/runbook wrappers; explicit flags still override preset values.

Real client VPN smoke test (machine C / tester host, Linux root):

```bash
sudo ./scripts/easy_node.sh client-vpn-preflight \
  --bootstrap-directory http://A_PUBLIC_IP_OR_DNS:8081

sudo ./scripts/easy_node.sh client-vpn-up \
  --bootstrap-directory http://A_PUBLIC_IP_OR_DNS:8081 \
  --subject <INVITE_KEY> \
  --beta-profile 1 \
  --distinct-operators 1

./scripts/easy_node.sh client-vpn-status
sudo ./scripts/easy_node.sh client-vpn-down
# prod profile enables operator-floor checks by default (>=2 global/entry/exit operators).
# for staged or single-operator labs, you can keep checks enabled with:
#   --operator-min-operators 1 --operator-min-entry-operators 1 --operator-min-exit-operators 1
# disable only for diagnostics with: --operator-floor-check 0
# prod profile also enables issuer-quorum checks by default (>=2 distinct issuer IDs with keys).
# for single-issuer lab tests only, append: --issuer-quorum-check 0
```

Server federation readiness checks (machine A/B host):

```bash
# one-shot federation health snapshot (peer failures + sync quorum)
./scripts/easy_node.sh server-federation-status

# optional: one-shot strict policy check (no polling loop) + summary artifact
./scripts/easy_node.sh server-federation-status \
  --require-configured-healthy 1 \
  --max-cooling-retry-sec 120 \
  --max-peer-sync-age-sec 120 \
  --max-issuer-sync-age-sec 120 \
  --min-peer-success-sources 2 \
  --min-issuer-success-sources 2 \
  --min-peer-source-operators 2 \
  --min-issuer-source-operators 2 \
  --fail-on-not-ready 1 \
  --summary-json .easy-node-logs/federation_status_summary.json \
  --print-summary-json 1

# block until local directory is federation-ready (or fail on timeout)
./scripts/easy_node.sh server-federation-wait \
  --ready-timeout-sec 90 \
  --poll-sec 5

# optional: capture machine-readable wait summary artifact
./scripts/easy_node.sh server-federation-wait \
  --ready-timeout-sec 90 \
  --poll-sec 5 \
  --summary-json .easy-node-logs/federation_wait_summary.json \
  --print-summary-json 1

# optional strict gates:
# - require every configured peer to be healthy (no fallback to discovered peers)
# - fail fast if cooling peers have long retry windows
./scripts/easy_node.sh server-federation-wait \
  --ready-timeout-sec 90 \
  --poll-sec 5 \
  --require-configured-healthy 1 \
  --max-cooling-retry-sec 120 \
  --max-peer-sync-age-sec 120 \
  --max-issuer-sync-age-sec 120 \
  --min-peer-success-sources 2 \
  --min-issuer-success-sources 2 \
  --min-peer-source-operators 2 \
  --min-issuer-source-operators 2

# optional: gate server startup directly
./scripts/easy_node.sh server-up \
  --bootstrap-directory http://A_PUBLIC_IP_OR_DNS:8081 \
  --federation-wait 1 \
  --federation-require-configured-healthy 1 \
  --federation-max-cooling-retry-sec 120 \
  --federation-max-peer-sync-age-sec 120 \
  --federation-max-issuer-sync-age-sec 120 \
  --federation-min-peer-success-sources 2 \
  --federation-min-issuer-success-sources 2 \
  --federation-min-peer-source-operators 2 \
  --federation-min-issuer-source-operators 2
```

Notes:
- `server-federation-wait` is useful after restarting one operator in a multi-peer setup; it waits for peer-sync and issuer-sync quorum plus healthy/eligible peer availability.
- `server-federation-status` now surfaces per-peer cooldown retry windows (`retry_after_sec`) and sync-source operator details so operators can see both retry timing and current source diversity.
- `server-federation-status` can also enforce the same strict policy thresholds in one shot (`--fail-on-not-ready 1`) and produce a machine-readable summary artifact (`--summary-json`) that now includes explicit readiness failure reasons (`readiness.failure_reasons`).
- `server-federation-wait` now also supports explicit fail-close outage policy (`--require-configured-healthy`, `--max-cooling-retry-sec`, `--max-peer-sync-age-sec`, `--max-issuer-sync-age-sec`, `--min-peer-success-sources`, `--min-issuer-success-sources`, `--min-peer-source-operators`, `--min-issuer-source-operators`) for stricter production readiness gates.
- `server-federation-wait` can now emit machine-readable readiness artifacts (`--summary-json`) including explicit failure reasons (`readiness.failure_reasons`) and final state (`ready|timeout|cooling_retry_exceeded|...`).
- if a peer is permanently offline, remove it from `DIRECTORY_PEERS` (or keep discovery enabled with eligible peers) to avoid repeated degraded-status loops.
- `prod-operator-lifecycle-runbook` enables federation readiness gating by default during onboard (`--federation-check 1`) and now captures federation wait log + wait/status summary artifacts (`--federation-wait-file`, `--federation-wait-summary-json`, `--federation-status-file`, `--federation-status-summary-json`) with normalized readiness fields in lifecycle summary/report handoffs (`federation.wait_*`, `federation.status_ready*`).
- lifecycle onboarding can now fail-close when wait summary capture is missing/invalid (`--federation-wait-summary-required 1`), producing failure step `federation_wait_summary`.
- lifecycle onboarding can now also fail-close when status summary capture is missing/invalid (`--federation-status-summary-required 1`), producing failure step `federation_status_summary`.
- lifecycle onboarding can now also fail-close when federation wait/status output artifacts are missing/empty (`--federation-wait-file-required 1`, `--federation-status-file-required 1`), producing failure steps `federation_wait_file` and `federation_status_file`.
- `server-up --federation-wait 1` can now pass through federation-wait summary artifact controls (`--federation-wait-summary-json`, `--federation-wait-print-summary-json`) for startup-gate automation/handoff.
- authority `server-up` can now auto-generate invite keys during startup (`--auto-invite 1` with optional count/tier/wait tuning) to reduce manual onboarding steps.
- authority `prod-operator-lifecycle-runbook` can also bootstrap invite keys after onboarding (`--onboard-invite 1`), with artifact/metadata reported in `invite_bootstrap.*` summary fields.
- `prod-operator-lifecycle-runbook` can now auto-rollback failed onboard runs (`--rollback-on-fail 1`) and optionally verify relay disappearance after rollback (`--rollback-verify-absent 1`), with rollback diagnostics in `rollback.*` summary fields.
- failed lifecycle runs can now auto-capture runtime-doctor diagnostics (`--runtime-doctor-on-fail 1`) with captured artifact metadata in `runtime_doctor.*` summary fields.
- failed lifecycle runs can now auto-capture incident bundles (`--incident-snapshot-on-fail 1`) with optional docker-log controls and attached lifecycle artifacts; lifecycle summary now also surfaces normalized incident handoff pointers (`incident_summary.json`, `incident_report.md`, bundle tar/sha, and attachment manifest paths) via `incident_snapshot.*`.
- lifecycle failed-run diagnostics now also support strict output-artifact completeness policies: runtime-doctor output can require non-empty capture (`--runtime-doctor-file-required 1`), incident handoff can require non-empty summary/report and tar+sha artifacts (`--incident-summary-required 1`, `--incident-bundle-required 1`), and attachment evidence can enforce manifest/no-skips/floor-count policy (`--incident-attachment-manifest-required 1`, `--incident-attachment-no-skips-required 1`, `--incident-attach-min-count N`, `--incident-attachment-manifest-min-count N`) with explicit lifecycle state reporting when requirements are unmet.
- lifecycle runs now also emit a human-readable markdown handoff by default (override with `--report-md`), with the artifact path recorded in summary JSON as `report_md`.

3-machine soak/fault validation (machine C runner):

```bash
./scripts/integration_3machine_beta_soak.sh \
  --directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084 \
  --rounds 12 \
  --pause-sec 5 \
  --beta-profile 1 \
  --distinct-operators 1

# one-bootstrap mode (auto-discovery)
./scripts/integration_machine_c_client_check.sh \
  --bootstrap-directory http://KNOWN_SERVER_IP:8081 \
  --discovery-wait-sec 20 \
  --beta-profile 1 \
  --distinct-operators 1
```

Production-grade 3-machine gate (strict control + real WG from machine C, Linux root):

```bash
sudo ./scripts/easy_node.sh three-machine-prod-gate \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --wg-max-consecutive-failures 2 \
  --wg-validate-summary-json .easy-node-logs/prod_gate_wg_validate_summary.json \
  --wg-soak-summary-json .easy-node-logs/prod_gate_wg_soak_summary.json \
  --gate-summary-json .easy-node-logs/prod_gate_summary.json \
  --strict-distinct 1

# same gate flow + automatic diagnostics bundle archive
sudo ./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir .easy-node-logs/prod_gate_bundle \
  --signoff-check 1 \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --strict-distinct 1
# note: bundle command runs strict machine-C preflight by default (use --preflight-check 0 only for diagnostics)
# note: bundle integrity verification is fail-close by default (use --bundle-verify-check 0 only for diagnostics)
# note: run report JSON is emitted by default at <bundle-dir>/prod_bundle_run_report.json

# strict artifact signoff check from bundle outputs
./scripts/easy_node.sh prod-gate-check \
  --run-report-json .easy-node-logs/prod_gate_bundle/prod_bundle_run_report.json

# single-run GO/NO-GO SLO summary
./scripts/easy_node.sh prod-gate-slo-summary \
  --run-report-json .easy-node-logs/prod_gate_bundle/prod_bundle_run_report.json \
  --fail-on-no-go 1

# multi-run SLO trend summary (recent run reports)
./scripts/easy_node.sh prod-gate-slo-trend \
  --reports-dir .easy-node-logs \
  --max-reports 25 \
  --show-details 1 \
  --show-top-reasons 5

# optional fail-close trend gate
./scripts/easy_node.sh prod-gate-slo-trend \
  --reports-dir .easy-node-logs \
  --fail-on-any-no-go 1 \
  --min-go-rate-pct 95

# optional time-windowed machine-readable trend output (last 24h)
./scripts/easy_node.sh prod-gate-slo-trend \
  --reports-dir .easy-node-logs \
  --since-hours 24 \
  --summary-json .easy-node-logs/prod_slo_trend_24h.json \
  --print-summary-json 1

# optional: classify trend into alert severity (OK/WARN/CRITICAL)
./scripts/easy_node.sh prod-gate-slo-alert \
  --trend-summary-json .easy-node-logs/prod_slo_trend_24h.json \
  --warn-go-rate-pct 98 \
  --critical-go-rate-pct 90 \
  --warn-no-go-count 1 \
  --critical-no-go-count 2 \
  --summary-json .easy-node-logs/prod_slo_alert_24h.json \
  --print-summary-json 1

# optional fail-close on alert levels
./scripts/easy_node.sh prod-gate-slo-alert \
  --reports-dir .easy-node-logs \
  --since-hours 24 \
  --fail-on-warn 1 \
  --fail-on-critical 1

# optional: generate one operator dashboard artifact (trend + alert + markdown)
./scripts/easy_node.sh prod-gate-slo-dashboard \
  --reports-dir .easy-node-logs \
  --since-hours 24 \
  --dashboard-md .easy-node-logs/prod_slo_dashboard_24h.md \
  --print-dashboard 1

# one-command integrity + signoff policy check
./scripts/easy_node.sh prod-gate-signoff \
  --run-report-json .easy-node-logs/prod_gate_bundle/prod_bundle_run_report.json

# integrity verification for bundle artifacts (manifest + tar checksum sidecar)
./scripts/easy_node.sh prod-gate-bundle-verify \
  --bundle-dir .easy-node-logs/prod_gate_bundle

# one-command strict production pilot wrapper (fail-closed defaults)
sudo ./scripts/easy_node.sh prod-pilot-runbook \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
  --subject pilot-client
# note: runbook auto-generates trend/alert/dashboard artifacts by default

# sustained production pilot cohort (multi-round + aggregated trend/alert policy)
sudo ./scripts/easy_node.sh prod-pilot-cohort-runbook \
  --rounds 5 \
  --pause-sec 60 \
  --trend-min-go-rate-pct 95 \
  --max-alert-severity WARN \
  --bundle-outputs 1 \
  --bundle-fail-close 1 \
  -- \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
  --subject pilot-client

# verify sustained-pilot cohort bundle artifacts from summary
./scripts/easy_node.sh prod-pilot-cohort-bundle-verify \
  --summary-json .easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary.json

# fail-closed sustained-pilot cohort signoff (integrity + policy)
./scripts/easy_node.sh prod-pilot-cohort-signoff \
  --summary-json .easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary.json

# minimal one-command sustained-pilot flow (cohort runbook + signoff)
./scripts/easy_node.sh prod-pilot-cohort-quick \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
  --subject pilot-client
# default quick run report: <reports_dir>/prod_pilot_cohort_quick_report.json

# quick run-report fail-closed verification
# output now also points to incident_summary.json / incident_report.md when
# failed-round incident artifacts are available in the linked cohort summary
./scripts/easy_node.sh prod-pilot-cohort-quick-check \
  --run-report-json <reports_dir>/prod_pilot_cohort_quick_report.json
# output now also prints the upstream pre_real_host_readiness_summary_json path when present

# quick-mode trend across quick run reports
# trend summary JSON now also carries latest failed incident handoff paths when available
./scripts/easy_node.sh prod-pilot-cohort-quick-trend \
  --reports-dir .easy-node-logs \
  --since-hours 24 \
  --summary-json .easy-node-logs/prod_pilot_quick_trend_24h.json

# quick-mode alert severity from trend metrics
./scripts/easy_node.sh prod-pilot-cohort-quick-alert \
  --trend-summary-json .easy-node-logs/prod_pilot_quick_trend_24h.json \
  --summary-json .easy-node-logs/prod_pilot_quick_alert_24h.json

# quick-mode dashboard artifact (trend + alert + markdown)
# dashboard markdown now also renders incident handoff paths when present
./scripts/easy_node.sh prod-pilot-cohort-quick-dashboard \
  --reports-dir .easy-node-logs \
  --dashboard-md .easy-node-logs/prod_pilot_quick_dashboard_24h.md

# one-command quick signoff gate (latest check + trend + alert severity policy)
# signoff_json now also carries incident handoff paths and the upstream
# pre_real_host_readiness_summary_json path when available
./scripts/easy_node.sh prod-pilot-cohort-quick-signoff \
  --run-report-json <reports_dir>/prod_pilot_cohort_quick_report.json \
  --reports-dir .easy-node-logs \
  --max-alert-severity WARN

# one-command quick pilot runbook (quick execution + signoff + optional dashboard)
./scripts/easy_node.sh prod-pilot-cohort-quick-runbook \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
  --subject pilot-client \
  --max-alert-severity WARN \
  --max-round-failures 0 \
  --bundle-outputs 1 \
  --bundle-fail-close 1

# low-prompt sustained pilot campaign wrapper (recommended for real machine-C operator runs)
./scripts/easy_node.sh prod-pilot-cohort-campaign \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
  --subject pilot-client
# default campaign handoff artifacts:
#   <reports_dir>/prod_pilot_campaign_summary.json
#   <reports_dir>/prod_pilot_campaign_summary.md
#   <reports_dir>/prod_pilot_campaign_run_report.json
#   <reports_dir>/prod_pilot_campaign_signoff_summary.json
# inline campaign signoff is enabled by default:
#   --campaign-signoff-check 1
#   --campaign-signoff-required 1
# optional strict wrapper-artifact policy controls:
#   --campaign-run-report-required [0|1]
#   --campaign-run-report-json-required [0|1]

# regenerate one concise campaign handoff report from saved artifacts
./scripts/easy_node.sh prod-pilot-cohort-campaign-summary \
  --reports-dir <reports_dir> \
  --fail-on-no-go 1
# this summary now also points to failed-round incident snapshot summary/report artifacts
# and preserves the upstream pre_real_host_readiness_summary.json pointer when present

# fail-closed campaign artifact + policy validation gate
./scripts/easy_node.sh prod-pilot-cohort-campaign-check \
  --reports-dir <reports_dir> \
  --require-status-ok 1 \
  --require-runbook-summary-json 1 \
  --require-quick-run-report-json 1 \
  --require-campaign-summary-go 1 \
  --require-campaign-signoff-enabled 1 \
  --require-campaign-signoff-required 1 \
  --require-campaign-signoff-attempted 1 \
  --require-campaign-signoff-ok 1 \
  --require-campaign-signoff-summary-json-valid 1 \
  --require-campaign-signoff-summary-status-ok 1 \
  --require-campaign-signoff-summary-final-rc-zero 1 \
  --require-campaign-summary-fail-close 1 \
  --require-campaign-signoff-check 1 \
  --require-campaign-run-report-required 1 \
  --require-campaign-run-report-json-required 1 \
  --require-artifact-path-match 1 \
  --summary-json <reports_dir>/prod_pilot_campaign_check_summary.json
# optional: --print-summary-json 1

# one-command campaign signoff gate (optional summary refresh + fail-closed check)
./scripts/easy_node.sh prod-pilot-cohort-campaign-signoff \
  --reports-dir <reports_dir> \
  --refresh-summary 1 \
  --summary-fail-on-no-go 1 \
  --campaign-signoff-summary-json <reports_dir>/prod_pilot_campaign_signoff_summary.json \
  --require-runbook-summary-json 1 \
  --require-quick-run-report-json 1 \
  --require-campaign-signoff-enabled 1 \
  --require-campaign-signoff-required 1 \
  --require-campaign-signoff-attempted 1 \
  --require-campaign-signoff-ok 1 \
  --require-campaign-signoff-summary-json-valid 1 \
  --require-campaign-signoff-summary-status-ok 1 \
  --require-campaign-signoff-summary-final-rc-zero 1 \
  --require-campaign-summary-fail-close 1 \
  --require-campaign-signoff-check 1 \
  --require-campaign-run-report-required 1 \
  --require-campaign-run-report-json-required 1 \
  --require-artifact-path-match 1 \
  --summary-json <reports_dir>/prod_pilot_campaign_signoff_check_summary.json
# optional: --print-summary-json 1

# production key/signing rotation maintenance runbook
./scripts/easy_node.sh prod-key-rotation-runbook \
  --mode auto \
  --preflight-check 1 \
  --rollback-on-fail 1

# production upgrade maintenance runbook
./scripts/easy_node.sh prod-upgrade-runbook \
  --mode auto \
  --preflight-check 1 \
  --compose-pull 1 \
  --compose-build 0 \
  --restart 1 \
  --rollback-on-fail 1

# quick checklist reminder output
./scripts/easy_node.sh three-machine-reminder
```

Controlled strict-ingress rehearsal (expected strict-ingress failure class):

```bash
sudo ./scripts/easy_node.sh prod-wg-strict-ingress-rehearsal \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084
```

Machine-role quick checks (run on each host before full 3-machine run):

```bash
# machine A
./scripts/easy_node.sh machine-a-test --public-host A_PUBLIC_IP_OR_DNS

# machine B
./scripts/easy_node.sh machine-b-test --peer-directory-a http://A_PUBLIC_IP_OR_DNS:8081 --public-host B_PUBLIC_IP_OR_DNS

# machine C
./scripts/easy_node.sh machine-c-test \
  --directory-a http://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b http://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url http://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url http://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url http://A_PUBLIC_IP_OR_DNS:8084
```

## 5) How to test specific features

Challenge / anti-abuse:

```bash
./scripts/integration_challenge.sh
```

Revocation:

```bash
./scripts/integration_revocation.sh
```

Token proof replay guard:

```bash
./scripts/integration_token_proof_replay.sh
```

Provider API (`provider_role` enforcement):

```bash
./scripts/integration_provider_api.sh
```

Federated directory (multi-source quorum/votes):

```bash
./scripts/integration_federation.sh
```

Directory operator quorum:

```bash
./scripts/integration_operator_quorum.sh
```

Distinct entry/exit operators (anti-collusion pair filter):

```bash
./scripts/integration_distinct_operators.sh
```

Optional stricter anti-capture mode:
- set `DIRECTORY_MIN_OPERATORS=2` (and/or `CLIENT_DIRECTORY_MIN_OPERATORS=2`, `ENTRY_DIRECTORY_MIN_OPERATORS=2`) so one operator cannot satisfy quorum via multiple endpoints.

Directory peer sync (operator-to-operator pull sync):

```bash
./scripts/integration_directory_sync.sh
```

Directory sync-status failure/recovery observability under peer churn:

```bash
./scripts/integration_sync_status_chaos.sh
```

Directory beta strict-mode guardrail behavior:

```bash
./scripts/integration_directory_beta_strict.sh
```

In strict mode, discovery anti-capture caps are fail-closed:
- `DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE>0`
- `DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR>0`

Directory multi-operator churn/quorum resilience:

```bash
./scripts/integration_directory_operator_churn_scale.sh
```

Optional stricter sync conflict policy:
- set `DIRECTORY_PEER_MIN_VOTES=2` (or higher) on syncing directories
- this forces peer descriptor agreement before a relay is imported during conflicts
- set `DIRECTORY_PEER_MIN_OPERATORS=2` (or higher) so one peer operator cannot satisfy sync quorum via multiple endpoints

Selection feed (signed scoring metadata):

```bash
./scripts/integration_selection_feed.sh
```

Trust-attestation feed (signed bond/stake/reputation metadata):

```bash
./scripts/integration_trust_feed.sh
```

Issuer trust ingestion by directory:

```bash
./scripts/integration_issuer_trust_sync.sh
```

Optional stricter issuer anti-capture policy:
- set `DIRECTORY_ISSUER_MIN_OPERATORS=2` (or higher) so one issuer operator cannot satisfy trust sync quorum via multiple URLs

Issuer dispute lifecycle:

```bash
./scripts/integration_issuer_dispute.sh
```

Adjudication horizon cap enforcement:

```bash
./scripts/integration_adjudication_window_caps.sh
```

Final adjudication vote/ratio quorum enforcement:

```bash
./scripts/integration_adjudication_quorum.sh
```

Final adjudication operator-quorum enforcement:

```bash
./scripts/integration_adjudication_operator_quorum.sh
```

Final adjudication source-quorum enforcement:

```bash
./scripts/integration_adjudication_source_quorum.sh
```

Directory push-gossip ingest:

```bash
./scripts/integration_directory_gossip.sh
```

Directory peer discovery (seeded decentralized membership):

```bash
./scripts/integration_peer_discovery.sh
```

Optional stricter discovery anti-capture policy:
- set `DIRECTORY_PEER_DISCOVERY_MIN_VOTES=2` (or higher) so one peer operator cannot unilaterally admit newly discovered peers
- set `DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE` (for example `8`) so one source operator cannot flood discovery with unlimited peer additions
- set `DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR` (for example `4`) so one hinted operator cannot dominate discovery with many endpoints
- set `DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1` so newly discovered peers must include signed operator and pubkey hints before admission
- for DNS seed mode, publish TXT records as `url=https://dir.example;operator=<id>;pub_key=<base64url-ed25519-pubkey>` when strict hint admission is enabled

Peer discovery quorum behavior (single-source blocked, multi-source admitted):

```bash
./scripts/integration_peer_discovery_quorum.sh
```

Peer discovery failure backoff + admin peer-status observability:

```bash
./scripts/integration_peer_discovery_backoff.sh
```

Peer discovery strict hint-gate behavior (loose mode admits, strict mode blocks peers without signed hints):

```bash
./scripts/integration_peer_discovery_require_hint.sh
```

Peer discovery per-source admission cap behavior:

```bash
./scripts/integration_peer_discovery_source_cap.sh
```

Peer discovery per-operator admission cap behavior:

```bash
./scripts/integration_peer_discovery_operator_cap.sh
```

Optional stricter unstable-peer suppression policy:
- lower `DIRECTORY_PEER_DISCOVERY_FAIL_THRESHOLD` (for example `1`) to quarantine flaky discovered peers faster
- increase `DIRECTORY_PEER_DISCOVERY_BACKOFF_SEC` / `DIRECTORY_PEER_DISCOVERY_MAX_BACKOFF_SEC` to keep repeatedly failing discovered peers out of active sync sets longer

Optional stricter adjudication metadata policy:
- set `DIRECTORY_ADJUDICATION_META_MIN_VOTES=2` (or higher) so `case_id` / `evidence_ref` fields require broader agreement than basic dispute/appeal activation
- set `DIRECTORY_DISPUTE_MAX_TTL_SEC` / `DIRECTORY_APPEAL_MAX_TTL_SEC` to bounded windows (for example `86400`) so imported dispute/appeal windows cannot be pushed arbitrarily far into the future by colluding operators
- set `DIRECTORY_FINAL_DISPUTE_MIN_VOTES`, `DIRECTORY_FINAL_APPEAL_MIN_VOTES`, `DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS`, `DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES`, and `DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO` to require stronger final publication quorum for dispute/appeal signals in the directory trust feed

Exit opaque source downlink return path:

```bash
./scripts/integration_opaque_source_downlink.sh
```

Client opaque UDP-only source enforcement (synthetic fallback disabled):

```bash
./scripts/integration_opaque_udp_only.sh
```

Client command-mode WG kernel proxy bridge (mocked `wg`/`ip`):

```bash
./scripts/integration_client_wg_kernel_proxy.sh
```

Exit WG proxy limit enforcement (mocked `wg`/`ip`):

```bash
./scripts/integration_exit_wg_proxy_limit.sh
```

Exit WG proxy idle cleanup metrics (mocked `wg`/`ip`):

```bash
./scripts/integration_exit_wg_proxy_idle_cleanup.sh
```

Real command-backend WireGuard integration (Linux + root required):

```bash
sudo ./scripts/integration_real_wg_privileged.sh
```

Real command-backend WireGuard profile matrix (Linux + root required):

```bash
sudo ./scripts/integration_real_wg_privileged_matrix.sh
```

WG-only stack lifecycle selftest (stack up + client validation + cleanup, Linux + root required):

```bash
sudo ./scripts/integration_wg_only_stack_selftest.sh
```

Stop-all cleanup validation for WG-only stack resources (Linux + root required):

```bash
sudo ./scripts/integration_stop_all_wg_only_cleanup.sh
```

If this fails immediately:
- ensure WireGuard kernel support exists (`ip link add dev wg-test0 type wireguard` should succeed, then `ip link del wg-test0`)
- install/enable WireGuard tools/module for your distro before retrying

Entry live-WG forwarding filter:

```bash
./scripts/integration_entry_live_wg_filter.sh
```

Exit live-WG mode drop/accept behavior (non-WG dropped, WG-like accepted):

```bash
./scripts/integration_exit_live_wg_mode.sh
```

Full live-WG strict path (client+entry+exit):

```bash
./scripts/integration_live_wg_full_path.sh
```

Client bootstrap delayed-infrastructure recovery:

```bash
./scripts/integration_client_bootstrap_recovery.sh
```

Client bootstrap recovery matrix:

```bash
./scripts/integration_client_bootstrap_recovery_matrix.sh
```

Startup sync gating profile (within the matrix):
- `startup_sync_gate` uses `CLIENT_STARTUP_SYNC_TIMEOUT_SEC` so client waits for control-plane readiness and avoids initial bootstrap failures while infrastructure is still starting.

Client startup sync gate (timeout + delayed-success recovery):

```bash
./scripts/integration_client_startup_sync.sh
```

Exit startup issuer-sync gate (timeout + delayed-success recovery):

```bash
./scripts/integration_exit_startup_sync.sh
```

Client parallel startup burst (jitter/backoff behavior under load):

```bash
./scripts/integration_client_startup_burst.sh
```

Anonymous credential end-to-end issue/revoke flow:

```bash
./scripts/integration_anon_credential.sh
```

Anonymous credential dispute tier-cap flow:

```bash
./scripts/integration_anon_credential_dispute.sh
```

Persistent opaque-session bridge (delayed downlink timing):

```bash
./scripts/integration_persistent_opaque_session.sh
```

Active session reuse across bootstrap cycles:

```bash
./scripts/integration_session_reuse.sh
```

Active session refresh handoff (open new path, then close old path):

```bash
./scripts/integration_session_handoff.sh
```

Multi-issuer exit trust:

```bash
./scripts/integration_multi_issuer.sh
```

Load + chaos resilience:

```bash
./scripts/integration_load_chaos.sh
```

Load + chaos profile matrix:

```bash
./scripts/integration_load_chaos_matrix.sh
```

Adversarial lifecycle chaos (dispute/revocation race):

```bash
./scripts/integration_lifecycle_chaos.sh
```

Adversarial lifecycle chaos matrix (multi-profile):

```bash
./scripts/integration_lifecycle_chaos_matrix.sh
```

Closed-beta preflight bundle:

```bash
./scripts/beta_preflight.sh
```

Easy-node secret rotation flow:

```bash
./scripts/integration_rotate_server_secrets.sh
```

HTTP cache/anti-entropy behavior:

```bash
./scripts/integration_http_cache.sh
```

Directory automatic key rotation policy:

```bash
./scripts/integration_directory_auto_key_rotation.sh
```

Key epoch rotation enforcement:

```bash
./scripts/integration_key_epoch_rotation.sh
```

Higher-pressure bootstrap stress:

```bash
./scripts/integration_stress_bootstrap.sh
```

All deep checks in one command:

```bash
./scripts/deep_test_suite.sh
```

## 6) What each integration script proves

- `integration_challenge.sh`:
  entry can require a challenge under rate pressure.

- `integration_revocation.sh`:
  previously valid token is denied after issuer revokes it and exit refreshes feed.

- `integration_token_proof_replay.sh`:
  with replay guard enabled, exit denies repeated `token_proof_nonce` reuse for the same token and accepts a fresh nonce.

- `integration_provider_api.sh`:
  directory accepts relay upsert from `provider_role` token, rejects `client_access` token for the same API, enforces role-specific minimum provider tiers for `entry` vs `exit`, and enforces optional per-operator provider relay cap.

- `integration_federation.sh`:
  client can use multiple directories with source/operator quorum and vote thresholds.

- `integration_operator_quorum.sh`:
  client bootstrap fails when quorum is met only by multiple endpoints of one operator, and succeeds when distinct operators are available.

- `integration_distinct_operators.sh`:
  with `CLIENT_REQUIRE_DISTINCT_OPERATORS=1`, client rejects same-operator entry/exit pairs and succeeds once distinct entry/exit operators are published.

- `integration_directory_sync.sh`:
  one directory imports relays from a peer directory and client can use synced relay data.
  With `DIRECTORY_PEER_MIN_VOTES`, conflicting peer variants can be dropped unless enough peers agree.
  With `DIRECTORY_PEER_MIN_OPERATORS`, sync requires distinct peer operators and ignores duplicate votes from one operator.

- `integration_directory_gossip.sh`:
  a directory accepts signed peer push data on `/v1/gossip/relays` and publishes imported relays.

- `integration_peer_discovery.sh`:
  a seed-connected directory learns additional peer URLs from signed `/v1/peers` feed data (including peer hints) and then imports relays from discovered peers.

- `integration_peer_discovery_backoff.sh`:
  a discovered peer that repeatedly fails sync is temporarily excluded by cooldown/backoff policy, and `/v1/admin/peer-status` reflects cooling state (`eligible=false`, `cooling_down=true`) plus failure metadata.

- `integration_peer_discovery_require_hint.sh`:
  `DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1` prevents admission of peers lacking signed `operator`+`pub_key` hints, while loose mode still admits them.

- `integration_peer_discovery_source_cap.sh`:
  `DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE` limits how many discovered peers one source operator can add; additional peers are still admitted when announced by distinct source operators.

- `integration_peer_discovery_operator_cap.sh`:
  `DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR` limits how many discovered peers sharing the same hinted operator id can be admitted at once, while still allowing peers from other operators.

- `integration_exit_live_wg_mode.sh`:
  in `EXIT_LIVE_WG_MODE=1`, exit drops non-WireGuard opaque payloads (`dropped_non_wg_live`) while still accepting/proxying plausible WG-like traffic (`accepted_packets`, `wg_proxy_created`).

- `integration_live_wg_full_path.sh`:
  with `CLIENT_LIVE_WG_MODE=1` + `EXIT_LIVE_WG_MODE=1`, client drops non-WireGuard ingress before entry forwarding while plausible WG-like packets still traverse end-to-end and activate exit WG proxy metrics.

- `integration_opaque_source_downlink.sh`:
  exit accepts injected downlink bytes on `EXIT_OPAQUE_SOURCE_ADDR`, forwards them into the active opaque session, and client receives them on sink path (live mode additionally requires session-framed source packets).
  In command mode, optional `EXIT_WG_KERNEL_PROXY=1` can bridge accepted opaque packets into local WG UDP socket I/O on `EXIT_WG_LISTEN_PORT` (must differ from `EXIT_DATA_ADDR` port).
  Optional client command-mode bridge: `CLIENT_WG_KERNEL_PROXY=1` + `CLIENT_WG_PROXY_ADDR` can bind local WG UDP endpoint directly to the opaque session path.

- `integration_persistent_opaque_session.sh`:
  with `CLIENT_OPAQUE_SESSION_SEC>0`, client keeps opaque uplink/downlink bridging active long enough to receive delayed downlink probes that would miss a short drain-only window.

- `integration_session_reuse.sh`:
  with `CLIENT_SESSION_REUSE=1`, client keeps the path active and reuses the same session on subsequent bootstrap cycles instead of immediate close/reopen churn.

- `integration_session_handoff.sh`:
  with short token TTL plus refresh lead, client opens a replacement session first, then closes the old session, preserving continuity across refresh.

- `integration_selection_feed.sh`:
  client can require signed selection feed and still bootstrap successfully.

- `integration_trust_feed.sh`:
  directory publishes signed trust attestations and client can require that feed during bootstrap.

- `integration_issuer_trust_sync.sh`:
  directory ingests issuer-signed trust attestations and merges those signals into published trust/selection outputs.
  With `DIRECTORY_ISSUER_MIN_OPERATORS`, sync requires distinct issuer operators and dedupes duplicate votes from one issuer operator.

- `integration_issuer_dispute.sh`:
  issuer applies a temporary dispute cap, opens/resolves appeal state, and validates trust-feed dispute/appeal signaling including case/evidence metadata.

- `integration_adjudication_window_caps.sh`:
  directory ingests far-future dispute/appeal windows from issuer trust feed and caps them to configured local horizons before publication.

- `integration_adjudication_quorum.sh`:
  directory governance policy can suppress final dispute publication when aggregated vote ratio does not meet `DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO`; `/v1/admin/governance-status` reports the active policy, upstream dispute signal/operator counts, operator-id sets, suppressed-vs-published disputed counters, and per-relay suppression details.

- `integration_adjudication_operator_quorum.sh`:
  directory governance policy can suppress final dispute publication when disputed signals come from fewer than `DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS` distinct operators.

- `integration_adjudication_source_quorum.sh`:
  directory governance policy can suppress final dispute publication when disputed signals come from fewer than `DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES` distinct adjudication source classes.

- `integration_sync_status_chaos.sh`:
  directory admin sync-status endpoint reports failed quorum while peer is down, success with operator attribution after recovery, and failure again after peer loss.

- `integration_directory_beta_strict.sh`:
  directory strict-mode config guardrails fail closed with missing prerequisites, and startup succeeds once strict governance requirements are supplied.

- `integration_directory_operator_churn_scale.sh`:
  validates larger multi-operator topology behavior: relay import across transit operators, quorum drop on one transit loss, quorum recovery after restart, and relay continuity under seed churn.

- `integration_opaque_udp_only.sh`:
  client accepts UDP-origin opaque uplink traffic with synthetic fallback disabled and rejects synthetic-source configuration in strict mode.

- `integration_client_wg_kernel_proxy.sh`:
  client command backend can bind a local WG proxy UDP endpoint (`CLIENT_WG_KERNEL_PROXY=1`) and relay packets through entry/exit using mocked `wg`/`ip` commands in non-privileged test environments.

- `integration_exit_wg_proxy_limit.sh`:
  with `EXIT_WG_KERNEL_PROXY_MAX_SESSIONS=1`, concurrent client sessions trigger `wg_proxy_limit_drops` while one active proxy session still carries accepted traffic.

- `integration_exit_wg_proxy_idle_cleanup.sh`:
  with short `EXIT_WG_KERNEL_PROXY_IDLE_SEC` and `EXIT_SESSION_CLEANUP_SEC`, exit reaps inactive proxy sockets and reports `wg_proxy_idle_closed` with `active_wg_proxy_sessions=0`.

- `integration_real_wg_privileged.sh`:
  Linux root-only manual integration check for real `wg`/`ip` command backends (no mocks), including actual interface bring-up, interface peer wiring checks (`wg show` peers/endpoints/listen-port), and WG-kernel-proxy packet-flow verification.

- `integration_real_wg_privileged_matrix.sh`:
  Linux root-only wrapper that runs privileged real-WG integration across multiple interface/port/startup profiles to catch environment-specific regressions.

- `integration_entry_live_wg_filter.sh`:
  with `ENTRY_LIVE_WG_MODE=1`, entry drops malformed/non-WG opaque packets for `wireguard-udp` sessions while still forwarding plausible WG packets to exit.

- `integration_client_bootstrap_recovery.sh`:
  client starts before directory/issuer/entry/exit are online, records bootstrap failures, then recovers automatically after infrastructure comes up and forwards packets successfully.

- `integration_client_bootstrap_recovery_matrix.sh`:
  runs startup recovery across multiple delay/backoff/jitter profiles (including startup-sync gating) to catch race-induced flakiness in bootstrap behavior.

- `integration_client_startup_sync.sh`:
  client with `CLIENT_STARTUP_SYNC_TIMEOUT_SEC` fails closed when issuer/directory are unavailable, then succeeds once control-plane readiness is restored.

- `integration_exit_startup_sync.sh`:
  exit with `EXIT_STARTUP_SYNC_TIMEOUT_SEC` fails closed when issuer endpoints are unavailable, then succeeds when issuer comes online before timeout.

- `integration_client_startup_burst.sh`:
  runs many clients in parallel with bootstrap jitter/backoff settings and checks that a healthy majority establish paths without panics while exit traffic counters advance.

- `integration_anon_credential.sh`:
  issuer issues an anonymous credential, client-access token minting with `anon_cred` succeeds, path-open succeeds, then credential revocation blocks further token minting.

- `integration_anon_credential_dispute.sh`:
  issuer applies a temporary anonymous-credential dispute cap, verifies admin status via `/v1/admin/anon-credential/get`, token minting from `anon_cred` is tier-capped during the dispute window, and clearing the dispute restores baseline credential tier.

- `integration_lifecycle_chaos.sh`:
  races revocation enforcement and dispute apply/clear loops while path-open traffic continues, then checks for expected revoked denials and no crash/panic.

- `integration_lifecycle_chaos_matrix.sh`:
  runs lifecycle chaos validation across multiple churn profiles (open/dispute/reissue cadence) to catch timing-sensitive regressions.

- `integration_multi_issuer.sh`:
  exit accepts token from a secondary issuer and then denies it after that issuer revokes the token.

- `integration_load_chaos.sh`:
  entry anti-abuse controls trigger under handshake load, custom-port descriptor control URLs remain correct (`ENTRY_URL`/`EXIT_CONTROL_URL`), and directory peer churn does not break client bootstrap after sync.

- `integration_load_chaos_matrix.sh`:
  runs load/chaos validation across multiple pressure profiles (RPS/puzzle/ban thresholds and concurrent opens) to surface tuning-sensitive regressions.

- `integration_3machine_beta_validate.sh`:
  from machine C, verifies A/B endpoint health, federation operator-floor on both directories, then runs client bootstrap against both directory sources for real cross-host setup validation.

- `integration_http_cache.sh`:
  directory `ETag` + `If-None-Match` returns `304` when relay/feed payloads are unchanged (incremental sync path).

- `integration_directory_auto_key_rotation.sh`:
  directory auto-rotates signing keys and enforces bounded previous-key history retention.

- `integration_key_epoch_rotation.sh`:
  old token is denied after issuer rotates signing key epoch; freshly issued token remains accepted.

- `integration_stress_bootstrap.sh`:
  many client bootstrap attempts run concurrently and verify no panic/regression while traffic metrics advance.

## 7) Simple architecture mental model

- `directory`:
  publishes signed relay descriptors, selection feed, and trust-attestation feed.

- `issuer`:
  issues short-lived signed capability tokens.

- `entry`:
  opens path and forwards packets to selected exit.

- `exit`:
  validates token/session and enforces policy.

- `client`:
  discovers relays, requests token, opens path, sends traffic.

Data path:
- packet bytes go through entry and exit.
- no single role sees full user identity + destination context together (split trust model).

## 8) Common debug checks

If client does not bootstrap:
1. Confirm ports are free: `8081`, `8082`, `8083`, `8084`.
2. Confirm directory response:
   - `curl -s http://127.0.0.1:8081/v1/relays`
3. Confirm issuer response:
   - `pop=$(go run ./cmd/tokenpop gen)`
   - `pop_pub=$(echo "$pop" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')`
   - `curl -s -X POST http://127.0.0.1:8082/v1/token -H 'Content-Type: application/json' --data "{\"tier\":1,\"subject\":\"client-debug-1\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"]}"`
4. Confirm entry health:
   - `curl -s http://127.0.0.1:8083/v1/health`
5. Re-run one integration script to isolate issue.

## 9) Recommended testing order

1. `./scripts/ci_local.sh`
2. Manual 3-terminal run
3. Individual integration scripts (one by one)
4. Change one config parameter at a time and re-test

This order gives fast confidence, then deeper understanding.
