# Deployment Guide (Docker + systemd)

## 1) Docker Compose (fastest way)

Files:
- `deploy/Dockerfile`
- `deploy/docker-compose.yml`

Run from repo root:

```bash
cd deploy
docker compose up -d --build directory issuer entry-exit
```

Optional demo client run:

```bash
docker compose --profile demo up client-demo
```

Smoke-test the stack (from repo root):

```bash
./scripts/integration_docker_stack.sh
```

Stop:

```bash
docker compose down
```

Data locations:
- `deploy/data/directory`
- `deploy/data/issuer`
- `deploy/data/entry-exit`

Notes:
- In easy-mode `server-up`, issuer/directory/puzzle secrets are auto-generated; if you override manually, avoid defaults and keep them private.
- `entry-exit` is one process running both roles (`--entry --exit`).

## 2) Easy installer + launcher (for simple testing)

Current direction (March 17, 2026):
- use profile-first operation (`Speed`, `Balanced`, `Private`) as the primary UX
- keep advanced flags for expert diagnostics and CI policy enforcement
- keep `Balanced` as the default recommendation for most operators
- keep default path architecture at 2-hop
- introduce true 1-hop only as an explicit experimental lower-privacy option
- keep quick launcher flows low-prompt by default, with one explicit "customize advanced options" branch when needed

Files:
- `scripts/install_easy_mode.sh`
- `scripts/easy_node.sh`
- `tools/easy_mode/easy_mode_ui.cpp`

Install launcher:

```bash
./scripts/install_easy_mode.sh
```

Optional: auto-update from GitHub before server/client start (friend-machine friendly):

```bash
# one-time setup in shell profile (example: ~/.bashrc)
export EASY_NODE_AUTO_UPDATE=1
export EASY_NODE_AUTO_UPDATE_REMOTE=origin
export EASY_NODE_AUTO_UPDATE_BRANCH=main
# safe default: skip auto-update when tracked local changes exist
export EASY_NODE_AUTO_UPDATE_ALLOW_DIRTY=0
```

Manual one-shot update is also available:

```bash
./scripts/easy_node.sh self-update
```

Run interactive menu:

```bash
./bin/privacynode-easy
```

Quick non-interactive examples:

```bash
# optional preflight before server-up (peer reachability + identity/quorum readiness)
./scripts/easy_node.sh server-preflight \
  --mode provider \
  --authority-directory https://<AUTHORITY_IP_OR_DNS>:8081 \
  --authority-issuer https://<AUTHORITY_IP_OR_DNS>:8082 \
  --peer-directories https://<AUTHORITY_IP_OR_DNS>:8081 \
  --beta-profile 1

# authority/admin node (runs directory + issuer + entry + exit)
# auto-generate one invite key on startup for immediate client onboarding
./scripts/easy_node.sh server-up --mode authority --public-host <PUBLIC_IP_OR_DNS> --beta-profile --auto-invite 1

# authority/admin node with strict production profile (mTLS + signed admin auth)
./scripts/easy_node.sh server-up --mode authority --public-host <PUBLIC_IP_OR_DNS> --peer-directories https://<PEER_DIRECTORY_IP_OR_DNS>:8081 --prod-profile 1

# provider node (runs directory + entry + exit, no local issuer admin)
./scripts/easy_node.sh server-up --mode provider \
  --public-host <PROVIDER_IP_OR_DNS> \
  --authority-directory https://<AUTHORITY_IP_OR_DNS>:8081 \
  --authority-issuer https://<AUTHORITY_IP_OR_DNS>:8082 \
  --beta-profile

./scripts/easy_node.sh client-test \
  --directory-urls https://<SERVER_IP>:8081 \
  --issuer-url https://<SERVER_IP>:8082 \
  --entry-url https://<SERVER_IP>:8083 \
  --exit-url https://<SERVER_IP>:8084 \
  --path-profile balanced

# local profile comparison (single-machine decision support)
./scripts/easy_node.sh profile-compare-local \
  --profiles balanced,speed,private,speed-1hop \
  --rounds 3 \
  --start-local-stack auto \
  --summary-json .easy-node-logs/profile_compare_local.json \
  --report-md .easy-node-logs/profile_compare_local.md \
  --print-summary-json 1

# aggregate trend recommendation from multiple profile-compare-local runs
./scripts/easy_node.sh profile-compare-trend \
  --reports-dir .easy-node-logs \
  --max-reports 20 \
  --min-profile-runs 3 \
  --min-profile-pass-rate-pct 95 \
  --balanced-latency-margin-pct 15 \
  --summary-json .easy-node-logs/profile_compare_trend.json \
  --report-md .easy-node-logs/profile_compare_trend.md \
  --print-summary-json 1

# repeatable campaign run (multiple local comparisons + trend aggregation)
./scripts/easy_node.sh profile-compare-campaign \
  --campaign-runs 5 \
  --profiles balanced,speed,private,speed-1hop \
  --rounds 3 \
  --start-local-stack auto \
  --trend-min-profile-runs 3 \
  --trend-min-profile-pass-rate-pct 95 \
  --trend-balanced-latency-margin-pct 15 \
  --summary-json .easy-node-logs/profile_compare_campaign_summary.json \
  --report-md .easy-node-logs/profile_compare_campaign_report.md \
  --print-summary-json 1

# fail-closed decision check for campaign recommendation readiness
./scripts/easy_node.sh profile-compare-campaign-check \
  --campaign-summary-json .easy-node-logs/profile_compare_campaign_summary.json \
  --require-min-runs-total 5 \
  --require-max-runs-fail 0 \
  --require-max-runs-warn 0 \
  --require-recommendation-support-rate-pct 70 \
  --allow-recommended-profiles balanced,speed,private \
  --disallow-experimental-default 1 \
  --show-json 1

# one-command campaign signoff (optional campaign refresh + fail-closed gate)
./scripts/easy_node.sh profile-compare-campaign-signoff \
  --reports-dir .easy-node-logs \
  --refresh-campaign 1 \
  --fail-on-no-go 1 \
  --require-min-runs-total 5 \
  --allow-recommended-profiles balanced,speed,private \
  --disallow-experimental-default 1 \
  --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json \
  --print-summary-json 1

# real client VPN session (Linux + sudo)
sudo ./scripts/easy_node.sh client-vpn-preflight \
  --bootstrap-directory https://<SERVER_IP>:8081
sudo ./scripts/easy_node.sh client-vpn-up \
  --bootstrap-directory https://<SERVER_IP>:8081 \
  --subject <INVITE_KEY> \
  --path-profile balanced
./scripts/easy_node.sh client-vpn-status
sudo ./scripts/easy_node.sh client-vpn-down
# prod profile enables operator-floor checks by default (>=2 global/entry/exit operators).
# for staged or single-operator labs, you can keep checks enabled with:
#   --operator-min-operators 1 --operator-min-entry-operators 1 --operator-min-exit-operators 1
# disable only for diagnostics with: --operator-floor-check 0
# prod profile also enables issuer-quorum checks by default (>=2 distinct issuer IDs with keys).
# for single-issuer lab tests only, append: --issuer-quorum-check 0

./scripts/easy_node.sh three-machine-validate \
  --directory-a https://<A_SERVER_IP>:8081 \
  --directory-b https://<B_SERVER_IP>:8081 \
  --issuer-url https://<A_SERVER_IP>:8082 \
  --entry-url https://<A_SERVER_IP>:8083 \
  --exit-url https://<A_SERVER_IP>:8084 \
  --min-sources 2 \
  --min-operators 2 \
  --path-profile balanced

./scripts/easy_node.sh three-machine-soak \
  --directory-a https://<A_SERVER_IP>:8081 \
  --directory-b https://<B_SERVER_IP>:8081 \
  --issuer-url https://<A_SERVER_IP>:8082 \
  --entry-url https://<A_SERVER_IP>:8083 \
  --exit-url https://<A_SERVER_IP>:8084 \
  --rounds 12 \
  --pause-sec 5 \
  --path-profile balanced

./scripts/easy_node.sh discover-hosts \
  --bootstrap-directory https://<KNOWN_SERVER_IP>:8081 \
  --wait-sec 20 \
  --write-config 1

./scripts/easy_node.sh machine-c-test \
  --bootstrap-directory https://<KNOWN_SERVER_IP>:8081 \
  --discovery-wait-sec 20 \
  --path-profile balanced

./scripts/easy_node.sh machine-a-test --public-host <A_SERVER_IP_OR_DNS>
./scripts/easy_node.sh machine-b-test --peer-directory-a https://<A_SERVER_IP_OR_DNS>:8081 --public-host <B_SERVER_IP_OR_DNS>
./scripts/easy_node.sh machine-c-test \
  --directory-a https://<A_SERVER_IP_OR_DNS>:8081 \
  --directory-b https://<B_SERVER_IP_OR_DNS>:8081 \
  --issuer-url https://<A_SERVER_IP_OR_DNS>:8082 \
  --entry-url https://<A_SERVER_IP_OR_DNS>:8083 \
  --exit-url https://<A_SERVER_IP_OR_DNS>:8084 \
  --path-profile balanced

# host real-WireGuard preflight and local validation (Linux + sudo required)
./scripts/easy_node.sh wg-only-check
sudo ./scripts/easy_node.sh wg-only-local-test --matrix 1
sudo ./scripts/easy_node.sh wg-only-stack-up --strict-beta 1   # strict live-WG client/entry/exit roles
./scripts/easy_node.sh wg-only-stack-status
sudo ./scripts/easy_node.sh wg-only-stack-down --force-iface-cleanup 1
sudo ./scripts/easy_node.sh wg-only-stack-selftest --strict-beta 1   # stack-up + live-WG validation + cleanup
sudo ./scripts/easy_node.sh wg-only-stack-selftest-record --strict-beta 1 --print-summary-json 1

# full local cleanup (docker + wg-only stack); run with sudo for interface cleanup
sudo ./scripts/easy_node.sh stop-all --with-wg-only 1 --force-iface-cleanup 1

# deferred real-host validation checklist
./scripts/easy_node.sh manual-validation-backlog
./scripts/easy_node.sh manual-validation-status --show-json 1
./scripts/easy_node.sh manual-validation-report --print-report 1 --print-summary-json 1
./scripts/easy_node.sh runtime-doctor --show-json 1
sudo ./scripts/easy_node.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1
sudo ./scripts/easy_node.sh pre-real-host-readiness --strict-beta 1 --print-summary-json 1
sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory https://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country
sudo ./scripts/easy_node.sh three-machine-prod-signoff --bundle-dir .easy-node-logs/prod_gate_bundle --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084 --pre-real-host-readiness 1 --runtime-fix 1 --print-summary-json 1

Both wrappers now persist runtime hygiene evidence alongside the summary output:
- `*_runtime_doctor_before.log`
- `*_runtime_doctor_before.json`
- `*_runtime_fix.log` / `*_runtime_fix.json` when auto-fix runs
- `*_runtime_doctor_after.log` / `*_runtime_doctor_after.json` when a post-fix doctor rerun happens

They also now refresh the shared manual-validation readiness handoff automatically:
- `.easy-node-logs/manual_validation_readiness_summary.json`
- `.easy-node-logs/manual_validation_readiness_report.md`

That refresh now happens before the final manual-validation receipt is written, so the saved receipt artifacts can point at the updated readiness handoff too.

If `client-vpn-smoke` fails, it now also auto-captures a client incident bundle, attaches the saved runtime-doctor/runtime-fix evidence into that bundle, refreshes the shared manual-validation readiness report, and attaches those refreshed readiness-report artifacts back into the same failed incident bundle for faster triage. `manual-validation-report` now surfaces those refreshed readiness-report attachment paths directly, so the latest failed handoff points at the actual bundled files instead of only the attachment manifest. The Linux root WG-only rerun now also has a recorded wrapper via `wg-only-stack-selftest-record`, `runtime-fix` now refreshes the shared readiness report on its own by default, `runtime-fix-record` packages that cleanup into one recorded runtime-hygiene receipt, and `pre-real-host-readiness` now chains `runtime-fix-record` + `wg-only-stack-selftest-record` + readiness refresh into one operator command before the real machine-C smoke step.

# rotate local server secret material (directory/puzzle, plus issuer token on authority nodes)
./scripts/easy_node.sh rotate-server-secrets --restart 1

# production-safe rotation runbook (backup + preflight + rollback)
./scripts/easy_node.sh prod-key-rotation-runbook --mode auto --preflight-check 1 --rollback-on-fail 1

# production-safe upgrade runbook (compose pull/build/restart + rollback)
./scripts/easy_node.sh prod-upgrade-runbook --mode auto --preflight-check 1 --compose-pull 1 --compose-build 0 --restart 1 --rollback-on-fail 1

# production-safe operator lifecycle runbook (repeatable onboarding/offboarding)
./scripts/easy_node.sh prod-operator-lifecycle-runbook --action onboard --mode provider --public-host <PUBLIC_IP_OR_DNS> --authority-directory https://<AUTHORITY_DIR_IP_OR_DNS>:8081 --authority-issuer https://<AUTHORITY_DIR_IP_OR_DNS>:8082 --prod-profile 1 --rollback-on-fail 1 --rollback-verify-absent 1 --runtime-doctor-on-fail 1 --incident-snapshot-on-fail 1 --federation-require-configured-healthy 1 --federation-max-cooling-retry-sec 120 --federation-max-peer-sync-age-sec 120 --federation-max-issuer-sync-age-sec 120 --federation-min-peer-success-sources 2 --federation-min-issuer-success-sources 2 --federation-min-peer-source-operators 2 --federation-min-issuer-source-operators 2
./scripts/easy_node.sh prod-operator-lifecycle-runbook --action onboard --mode authority --public-host <AUTHORITY_PUBLIC_IP_OR_DNS> --prod-profile 1 --onboard-invite 1 --onboard-invite-count 1 --onboard-invite-tier 1 --rollback-on-fail 1 --rollback-verify-absent 1 --runtime-doctor-on-fail 1 --incident-snapshot-on-fail 1
./scripts/easy_node.sh prod-operator-lifecycle-runbook --action offboard --operator-id <OPERATOR_ID> --directory-url https://<AUTHORITY_DIR_IP_OR_DNS>:8081

# sustained production pilot cohort (multi-round runbook + trend/alert rollup)
# note: this now runs pre-real-host-readiness once before the cohort by default
./scripts/easy_node.sh prod-pilot-cohort-runbook --rounds 5 --pause-sec 60 --trend-min-go-rate-pct 95 --max-alert-severity WARN --bundle-outputs 1 --bundle-fail-close 1 -- --bootstrap-directory https://<A_SERVER_IP_OR_DNS>:8081 --subject pilot-client

# verify cohort bundle integrity artifacts
./scripts/easy_node.sh prod-pilot-cohort-bundle-verify --summary-json .easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary.json

# fail-closed cohort signoff (integrity + policy)
./scripts/easy_node.sh prod-pilot-cohort-signoff --summary-json .easy-node-logs/prod_pilot_cohort/prod_pilot_cohort_summary.json

# minimal one-command sustained cohort flow (runbook + signoff)
./scripts/easy_node.sh prod-pilot-cohort-quick --bootstrap-directory https://<A_SERVER_IP_OR_DNS>:8081 --subject pilot-client
# default quick run report: <reports_dir>/prod_pilot_cohort_quick_report.json

# verify quick run-report policy fail-closed
# output now also points directly to incident_summary.json / incident_report.md
# when failed-round incident artifacts are available
./scripts/easy_node.sh prod-pilot-cohort-quick-check --run-report-json <reports_dir>/prod_pilot_cohort_quick_report.json

# quick-mode trend across quick run reports
# trend summary JSON now also carries latest failed incident handoff paths when available
./scripts/easy_node.sh prod-pilot-cohort-quick-trend --reports-dir .easy-node-logs --since-hours 24 --summary-json .easy-node-logs/prod_pilot_quick_trend_24h.json

# quick-mode alert severity from trend metrics
./scripts/easy_node.sh prod-pilot-cohort-quick-alert --trend-summary-json .easy-node-logs/prod_pilot_quick_trend_24h.json --summary-json .easy-node-logs/prod_pilot_quick_alert_24h.json

# quick-mode dashboard (trend + alert + markdown)
# dashboard markdown now also renders incident handoff paths when present
./scripts/easy_node.sh prod-pilot-cohort-quick-dashboard --reports-dir .easy-node-logs --dashboard-md .easy-node-logs/prod_pilot_quick_dashboard_24h.md

# one-command quick signoff (latest check + trend + alert severity gate)
# signoff_json now also carries incident handoff paths when present
./scripts/easy_node.sh prod-pilot-cohort-quick-signoff --run-report-json <reports_dir>/prod_pilot_cohort_quick_report.json --reports-dir .easy-node-logs --max-alert-severity WARN

# one-command quick pilot runbook (quick execution + signoff + optional dashboard)
# note: this now also exposes the same one-time pre-real-host readiness gate
#       before the quick wrapper delegates into the sustained cohort flow
./scripts/easy_node.sh prod-pilot-cohort-quick-runbook --bootstrap-directory https://<A_SERVER_IP_OR_DNS>:8081 --subject pilot-client --max-alert-severity WARN
```

Invite-only beta option:
- add `--client-allowlist 1 --allow-anon-cred 0` to `server-up` so only explicitly onboarded client subjects can receive tokens.
- onboard subjects with `./scripts/beta_subject_upsert.sh --issuer-url <ISSUER_URL> --admin-token-file <TOKEN_FILE> --subject <CLIENT_ID> --kind client --tier 1`.
- batch onboarding: `./scripts/beta_subject_batch_upsert.sh --issuer-url <ISSUER_URL> --admin-token-file <TOKEN_FILE> --csv invited_clients.csv`.
- pass `--subject <CLIENT_ID>` to `client-test`/`machine-c-test` for invited users.
- one-command validation+soak bundle from machine C: `./scripts/beta_pilot_runbook.sh ...` (outputs `.tar.gz` report bundle under `.easy-node-logs`).

Prod strict additions:
- bootstrap certs: `./scripts/easy_node.sh bootstrap-mtls --out-dir deploy/tls --public-host <PUBLIC_IP_OR_DNS>`.
- run `server-up --prod-profile 1` to enforce fail-closed strict defaults (`PROD_STRICT_MODE=1`) on top of beta strict.
- prod profile now also enforces hardened abuse/adjudication defaults (entry open-rate/ban/inflight bounds, peer+final dispute/appeal floors, final operator/source quorum floors, and stricter ratio/TTL caps) for safer public operation.
- prod profile requires at least one peer directory from a distinct authority/issuer operator so strict issuer quorum has at least two issuer URLs.
- when peers are configured, `server-up` now fail-fast verifies local `operator_id`/`issuer_id` uniqueness against peer feeds by default in beta/prod (`--peer-identity-strict auto` -> strict); use `--peer-identity-strict 0` only as a temporary diagnostics bypass.
- `server-federation-status` now includes per-peer cooldown retry windows (`retry_after_sec`), a `cooling_retry_max_sec` summary, and sync-source operator details (`source_operator_count`, `peer_sync_source_operators`, `issuer_sync_source_operators`) to make intermittent peer outage behavior and diversity posture easier to reason about during operations; it can also enforce strict one-shot policy checks via `--fail-on-not-ready 1` and emit a machine-readable summary via `--summary-json`.
- `server-federation-wait` can now enforce strict federation readiness policy (`--require-configured-healthy`, `--max-cooling-retry-sec`, `--max-peer-sync-age-sec`, `--max-issuer-sync-age-sec`, `--min-peer-success-sources`, `--min-issuer-success-sources`, `--min-peer-source-operators`, `--min-issuer-source-operators`) and emit machine-readable wait summaries (`--summary-json`, `--print-summary-json`) with explicit failure reasons. `server-up --federation-wait 1` can pass the same policy gates via `--federation-require-configured-healthy`, `--federation-max-cooling-retry-sec`, `--federation-max-peer-sync-age-sec`, `--federation-max-issuer-sync-age-sec`, `--federation-min-peer-success-sources`, `--federation-min-issuer-success-sources`, `--federation-min-peer-source-operators`, and `--federation-min-issuer-source-operators`, plus wait-summary forwarding via `--federation-wait-summary-json` and `--federation-wait-print-summary-json`.
- authority mode can auto-generate invite keys at startup (`--auto-invite 1`, optional `--auto-invite-count`, `--auto-invite-tier`, `--auto-invite-wait-sec`); `--auto-invite-fail-open 1` keeps startup non-blocking if invite generation fails.
- prod profile auto-wires WG command-backend runtime defaults (`WG_BACKEND=command`, live WG filters, exit WG kernel proxy, and issuer quorum URL feeds) and sets entry-exit compose runtime privileges (`ENTRY_EXIT_USER=0:0`, `ENTRY_EXIT_PRIVILEGED=true`).
- authority invite/admin commands auto-switch to signed auth in prod profile; they also support explicit signed credentials (`--admin-key-file`, `--admin-key-id`).
- run `./scripts/security_secret_guard.sh` before packaging/release to fail fast on tracked invite-key/private-key leakage in `docs/` and `deploy/`.
- use `./scripts/easy_node.sh admin-signing-status` and `./scripts/easy_node.sh admin-signing-rotate --restart-issuer 1 --key-history 3` for signer maintenance on authority nodes.
- use `./scripts/easy_node.sh prod-preflight --days-min 14 --check-live 1 --timeout-sec 12` before external beta/production traffic cutover; live mode now verifies endpoint reachability, governance policy floors (`/v1/admin/governance-status`), peer-status payload validity, optional strict federation health thresholds (`--live-require-configured-healthy`, `--live-max-cooling-retry-sec`), optional sync freshness thresholds (`--live-max-peer-sync-age-sec`, `--live-max-issuer-sync-age-sec`), and optional sync source-diversity floors (`--live-min-peer-success-sources`, `--live-min-issuer-success-sources`, `--live-min-peer-source-operators`, `--live-min-issuer-source-operators`).
- use `./scripts/easy_node.sh prod-key-rotation-runbook ...` for operator-safe maintenance windows (automatic backup + optional pre/post preflight + rollback-on-failure summary JSON).
- use `./scripts/easy_node.sh prod-upgrade-runbook ...` for operator-safe upgrade windows (automatic backup + optional pre/post preflight + compose pull/build/restart + rollback-on-failure summary JSON).
- use `./scripts/easy_node.sh prod-operator-lifecycle-runbook ...` for repeatable onboarding/offboarding with optional preflight, health checks, federation readiness gating, relay visibility checks, optional authority onboarding invite bootstrap (`--onboard-invite`), optional fail-close onboard rollback (`--rollback-on-fail`, `--rollback-verify-absent`), optional failed-run runtime-doctor capture (`--runtime-doctor-on-fail`), and optional failed-run incident capture (`--incident-snapshot-on-fail`), with both machine-readable summary JSON and a human-readable lifecycle report markdown artifact (`--report-md`), plus normalized runtime + incident handoff pointers in lifecycle summary JSON (`runtime_doctor.*`, `incident_snapshot.*`). For stricter multi-peer federation policy during onboard readiness, tune `--federation-require-configured-healthy`, `--federation-max-cooling-retry-sec`, `--federation-max-peer-sync-age-sec`, `--federation-max-issuer-sync-age-sec`, `--federation-min-peer-success-sources`, and `--federation-min-issuer-success-sources`, plus `--federation-min-peer-source-operators` and `--federation-min-issuer-source-operators`; set `--federation-status-fail-on-not-ready 1` if post-start federation status capture should fail-close on the same strict policy. Lifecycle runs now persist federation wait log + wait/status summary artifacts (`--federation-wait-file`, `--federation-wait-summary-json`, `--federation-status-file`, `--federation-status-summary-json`), can optionally fail-close on missing/empty wait/status output artifacts (`--federation-wait-file-required 1`, `--federation-status-file-required 1`) and missing wait/status summaries (`--federation-wait-summary-required 1`, `--federation-status-summary-required 1`), can enforce non-empty runtime-doctor and incident handoff artifacts on failed runs (`--runtime-doctor-file-required 1`, `--incident-summary-required 1`, `--incident-bundle-required 1`), can enforce stricter incident attachment evidence policy (`--incident-attachment-manifest-required 1`, `--incident-attachment-no-skips-required 1`, `--incident-attach-min-count N`, `--incident-attachment-manifest-min-count N`), and surface normalized wait/status readiness and failure-reason fields in summary JSON/report handoffs (`federation.wait_*`, `federation.status_ready*`).
- use `./scripts/easy_node.sh prod-pilot-cohort-runbook ...` for sustained pilot cohorts (multiple strict pilot rounds + aggregated trend/alert + cohort summary JSON), with alert-severity fail-close policy (`--max-alert-severity`, default `WARN`), optional fail-closed cohort bundle artifact generation (`--bundle-outputs`, `--bundle-fail-close`), and a one-time top-level `pre-real-host-readiness` gate before the cohort starts by default (`--pre-real-host-readiness 0` disables that wrapper gate for diagnostics-only runs).
- use `./scripts/easy_node.sh prod-pilot-cohort-bundle-verify ...` to fail-close validate cohort artifact integrity (tar checksum + manifest schema + round structure).
- use `./scripts/easy_node.sh prod-pilot-cohort-check ...` to enforce cohort policy gates from the generated summary JSON (round failure budget, trend GO-rate/decision, alert severity threshold, bundle presence).
- use `./scripts/easy_node.sh prod-pilot-cohort-signoff ...` for one-command fail-closed cohort signoff (bundle verify + cohort policy check).
- use `./scripts/easy_node.sh prod-pilot-cohort-quick ...` for minimal-prompt operator flow that runs cohort execution and signoff together, now with the same one-time top-level `pre-real-host-readiness` gate exposed directly on the quick wrapper.
- `prod-pilot-cohort-quick` writes a quick run report JSON by default (`<reports_dir>/prod_pilot_cohort_quick_report.json`) and supports `--run-report-json` override.
- use `./scripts/easy_node.sh prod-pilot-cohort-quick-check ...` to enforce quick run-report policy (status, runbook/signoff RCs, summary presence/status, optional duration threshold); it now also prints the upstream `pre_real_host_readiness_summary_json` path when present in the quick run report.
- use `./scripts/easy_node.sh prod-pilot-cohort-quick-trend ...` to aggregate quick run-report GO/NO-GO trend with optional fail-close thresholds, including latest failed incident attachment pointers plus the upstream `pre_real_host_readiness_summary_json` pointer when available.
- use `./scripts/easy_node.sh prod-pilot-cohort-quick-alert ...` to classify trend metrics into severity (`OK/WARN/CRITICAL`) with optional fail-close exits, while preserving incident handoff attachment pointers and the upstream `pre_real_host_readiness_summary_json` pointer in alert JSON/output.
- use `./scripts/easy_node.sh prod-pilot-cohort-quick-dashboard ...` to generate one operator dashboard (trend JSON + alert JSON + markdown), including incident handoff paths, attachment manifests, and the upstream `pre_real_host_readiness_summary_json` pointer when present in the linked quick trend summary.
- use `./scripts/easy_node.sh prod-pilot-cohort-quick-signoff ...` to run quick-check + trend + alert in one fail-closed decision command; it now also preserves the upstream `pre_real_host_readiness_summary_json` path in signoff JSON/output when present.
- use `./scripts/easy_node.sh prod-pilot-cohort-quick-runbook ...` for one-command quick execution + signoff + optional dashboard with a runbook summary artifact, and the same one-time top-level `pre-real-host-readiness` gate exposed directly on the quick runbook wrapper.
- use `./scripts/easy_node.sh prod-pilot-cohort-campaign ...` for low-prompt sustained operator campaigns with the same top-level `pre-real-host-readiness` gate exposed directly on the campaign wrapper; it now writes both a machine-readable campaign run report (`<reports_dir>/prod_pilot_campaign_run_report.json`) and an inline campaign-signoff summary (`<reports_dir>/prod_pilot_campaign_signoff_summary.json`) by default, supports fail-close report completeness policy controls (`--campaign-run-report-required`, `--campaign-run-report-json-required`), and can disable inline signoff only for diagnostics (`--campaign-signoff-check 0`).
- `./scripts/easy_node.sh prod-pilot-cohort-campaign-summary ...` now also preserves the upstream `pre_real_host_readiness_summary_json` pointer from quick-runbook artifacts in its JSON/markdown handoff, alongside the normalized incident source pointers.
- use `./scripts/easy_node.sh prod-pilot-cohort-campaign-check ...` to fail-close validate campaign run-report + summary artifacts, including upstream `runbook_summary_json` / `quick_run_report_json` completeness and JSON validity, campaign-signoff stage configuration/RC requirements (`--require-campaign-signoff-enabled`, `--require-campaign-signoff-required`, `--require-campaign-signoff-attempted`, `--require-campaign-signoff-ok`), campaign-signoff summary integrity (`--require-campaign-signoff-summary-json-valid`, `--require-campaign-signoff-summary-status-ok`, `--require-campaign-signoff-summary-final-rc-zero`), wrapper fail-close config floors (`--require-campaign-summary-fail-close`, `--require-campaign-signoff-check`, `--require-campaign-run-report-required`, `--require-campaign-run-report-json-required`), and cross-artifact path consistency (`--require-artifact-path-match`) before signoff; optionally emit a machine-readable check artifact (`--summary-json`, `--print-summary-json`).
- use `./scripts/easy_node.sh prod-pilot-cohort-campaign-signoff ...` for one-command operator signoff that can optionally refresh campaign-summary and then run campaign-check fail-closed, including upstream runbook/quick artifact policy checks, wrapper fail-close config-floor checks, and optional campaign-signoff evidence policy pass-through (`--campaign-signoff-summary-json`, `--require-campaign-signoff-*`); keep `--campaign-signoff-summary-json` (input stage evidence) and `--summary-json` (output signoff/check result) on distinct paths to preserve both artifacts.

For a full 3-machine flow, see `docs/easy-3-machine-test.md`.
For a frozen closed-beta command set, see `docs/beta-playbook.md`.
For repeatable operator onboarding/offboarding, see `docs/operator-lifecycle-runbook.md`.

## 3) Windows 11 + WSL2

Files:
- `scripts/install_wsl2_mode.sh` (run in WSL)
- `scripts/windows/wsl2_bootstrap.ps1` (run in PowerShell)
- `scripts/windows/wsl2_run_easy.ps1` (run launcher from PowerShell)
- `scripts/windows/wsl2_bootstrap.cmd` (Windows Command Prompt wrapper)
- `scripts/windows/wsl2_run_easy.cmd` (Windows Command Prompt wrapper)
- `scripts/windows/wsl2_easy.cmd` (combined Command Prompt helper)
- `docs/windows-wsl2.md`

Quick start from PowerShell:

```powershell
./scripts/windows/wsl2_bootstrap.ps1
./scripts/windows/wsl2_run_easy.ps1
```

Or from `cmd.exe`:

```cmd
scripts\windows\wsl2_bootstrap.cmd
scripts\windows\wsl2_run_easy.cmd
```

## 4) systemd units

Files:
- `deploy/systemd/privacynode-directory.service`
- `deploy/systemd/privacynode-issuer.service`
- `deploy/systemd/privacynode-entry-exit.service`
- `deploy/systemd/*.env.example`

Install steps (Linux):
1. Install binary to `/usr/local/bin/node`.
2. Create service user and dirs:
   - `sudo useradd --system --home /var/lib/privacynode --shell /usr/sbin/nologin privacynode`
   - `sudo mkdir -p /var/lib/privacynode/data /etc/privacynode`
3. Copy and edit env files:
   - `sudo cp deploy/systemd/common.env.example /etc/privacynode/common.env`
   - `sudo cp deploy/systemd/directory.env.example /etc/privacynode/directory.env`
   - `sudo cp deploy/systemd/issuer.env.example /etc/privacynode/issuer.env`
   - `sudo cp deploy/systemd/entry-exit.env.example /etc/privacynode/entry-exit.env`
4. Copy unit files:
   - `sudo cp deploy/systemd/privacynode-*.service /etc/systemd/system/`
5. Reload and start:
   - `sudo systemctl daemon-reload`
   - `sudo systemctl enable --now privacynode-directory.service`
   - `sudo systemctl enable --now privacynode-issuer.service`
   - `sudo systemctl enable --now privacynode-entry-exit.service`
6. Verify:
   - `systemctl status privacynode-directory.service`
   - `systemctl status privacynode-issuer.service`
   - `systemctl status privacynode-entry-exit.service`

## 5) Recommended pre-production checks

Before exposing anything public:
1. Run `./scripts/beta_preflight.sh` for the default closed-beta validation bundle.
2. Run `./scripts/ci_local.sh`.
3. Run `./scripts/integration_load_chaos.sh`.
4. Run `./scripts/integration_load_chaos_matrix.sh` for broader load-pressure profiles.
5. Run `./scripts/integration_lifecycle_chaos.sh`.
6. Run `./scripts/integration_lifecycle_chaos_matrix.sh` for broader dispute/revocation churn profiles.
7. Run `./scripts/integration_directory_auto_key_rotation.sh` if you plan to enable `DIRECTORY_KEY_ROTATE_SEC`.
8. Run `./scripts/integration_sync_status_chaos.sh` and verify `/v1/admin/sync-status` auth + quorum reporting behavior for your topology.
9. Run `./scripts/integration_directory_operator_churn_scale.sh` to validate multi-operator quorum behavior under transit/seed churn.
10. Run `./scripts/integration_peer_discovery_backoff.sh` and verify `/v1/admin/peer-status` shows discovered-peer cooldown eligibility and failure metadata under peer instability.
11. Run `./scripts/integration_peer_discovery_require_hint.sh` if you enforce strict discovery hints (`DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1`) and confirm only peers with signed operator+pubkey hints are admitted.
12. Run `./scripts/integration_peer_discovery_source_cap.sh` and `./scripts/integration_peer_discovery_operator_cap.sh` if you enforce discovery flood controls (`DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE`, `DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR`).
13. If you enable live WireGuard filtering on exit (`EXIT_LIVE_WG_MODE=1`), run `./scripts/integration_exit_live_wg_mode.sh`.
14. If you enable strict live path on both sides (`CLIENT_LIVE_WG_MODE=1`, `EXIT_LIVE_WG_MODE=1`), run `./scripts/integration_live_wg_full_path.sh`.
15. Run `./scripts/integration_adjudication_quorum.sh` and verify `/v1/admin/governance-status` reflects your final adjudication policy plus suppressed-vs-published dispute counters and per-relay suppression details.
16. Run `./scripts/integration_adjudication_operator_quorum.sh` and verify operator-quorum suppression behavior for your governance settings.
17. Run `./scripts/integration_adjudication_source_quorum.sh` and verify source-class quorum suppression behavior for your governance settings.
18. If enabling live WG filtering on entry (`ENTRY_LIVE_WG_MODE=1`), run `./scripts/integration_entry_live_wg_filter.sh`.
19. Run `./scripts/integration_client_bootstrap_recovery.sh` to validate client retry/backoff recovery when client starts before local control-plane services.
20. Run `./scripts/integration_client_startup_sync.sh` to validate client startup dependency gating (timeout on unavailable issuer/directory, delayed success once control-plane readiness is online).
21. Run `./scripts/integration_exit_startup_sync.sh` to validate exit startup issuer-sync behavior (timeout on unavailable issuer, delayed success once issuer is online).
22. Run `./scripts/integration_client_startup_burst.sh` to validate parallel client bootstrap behavior under jitter/backoff settings.
23. Set adjudication policy bounds (`DIRECTORY_ADJUDICATION_META_MIN_VOTES`, `DIRECTORY_FINAL_DISPUTE_MIN_VOTES`, `DIRECTORY_FINAL_APPEAL_MIN_VOTES`, `DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS`, `DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES`, `DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO`, `DIRECTORY_DISPUTE_MAX_TTL_SEC`, `DIRECTORY_APPEAL_MAX_TTL_SEC`) to your risk tolerance before enabling federated trust sync.
24. Set provider relay admission tiers (`DIRECTORY_PROVIDER_MIN_ENTRY_TIER`, `DIRECTORY_PROVIDER_MIN_EXIT_TIER`) and optional provider concentration cap (`DIRECTORY_PROVIDER_MAX_RELAYS_PER_OPERATOR`) for your rollout stage.
25. If you want stronger anti-capture policy for provider advertisements, enable `DIRECTORY_PROVIDER_SPLIT_ROLES=1` so one provider operator cannot advertise both entry and exit roles simultaneously.
26. If you want server-side anti-collusion enforcement, enable `ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1` and set `ENTRY_OPERATOR_ID` (or `DIRECTORY_OPERATOR_ID`) so entry rejects same-operator entry/exit path-open attempts.
27. Set discovery flood controls (`DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE`, `DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR`) so one source operator cannot introduce unlimited discovered peers and one hinted operator cannot dominate discovery with many endpoints.
28. If you disable synthetic client fallback (`CLIENT_DISABLE_SYNTHETIC_FALLBACK=1`), validate your UDP uplink producer path with `./scripts/integration_opaque_udp_only.sh`.
29. Verify issuer key/epoch files and directory key history files persist across restart.
30. If enabling command egress backend, validate firewall rules in a disposable environment first.
31. If enabling WG kernel proxy bridges (`CLIENT_WG_KERNEL_PROXY=1`, `EXIT_WG_KERNEL_PROXY=1`), keep `EXIT_WG_LISTEN_PORT` distinct from `EXIT_DATA_ADDR`, tune `EXIT_WG_KERNEL_PROXY_MAX_SESSIONS` / `EXIT_WG_KERNEL_PROXY_IDLE_SEC` / `EXIT_SESSION_CLEANUP_SEC`, and validate packet flow in a disposable environment first.
32. For real interface validation on Linux hosts, run `sudo ./scripts/integration_real_wg_privileged.sh` and `sudo ./scripts/integration_real_wg_privileged_matrix.sh` from a disposable test machine before exposing public traffic.
33. For closed beta hardening, run `./scripts/integration_directory_beta_strict.sh` and verify strict governance environment settings are fail-closed when incomplete and healthy when complete.
34. For closed beta hardening, enable `BETA_STRICT_MODE=1` (or role-specific strict toggles) and verify all roles boot with strict settings only (`CLIENT_REQUIRE_DISTINCT_OPERATORS=1`, `ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1`, `EXIT_PEER_REBIND_SEC=0`, `EXIT_STARTUP_SYNC_TIMEOUT_SEC>0`, and other strict prerequisites). If you configure multiple directory URLs in strict mode, enforce quorum floors as well (`DIRECTORY_MIN_SOURCES>=2`, `CLIENT_DIRECTORY_MIN_OPERATORS>=2`, `ENTRY_DIRECTORY_MIN_SOURCES>=2`, `ENTRY_DIRECTORY_MIN_OPERATORS>=2`). If you configure multiple issuer URLs on exit, enforce issuer quorum floors and identity binding (`EXIT_ISSUER_MIN_SOURCES>=2`, `EXIT_ISSUER_MIN_OPERATORS>=2`, `EXIT_ISSUER_REQUIRE_ID=1`).
35. If using DNS seed discovery (`DIRECTORY_PEER_DISCOVERY_DNS_SEEDS`), verify TXT records publish only trusted peer URLs and, in strict hint mode, include signed hint fields (`operator`, `pub_key`) for admitted peers.
36. If using anonymous credentials, keep `ISSUER_ANON_CRED_EXPOSE_ID=0` (default) unless you explicitly need legacy raw-id compatibility.
37. If using anonymous credentials, run `./scripts/integration_anon_credential.sh` and verify issuer admin controls for `/v1/admin/anon-credential/issue` and `/v1/admin/anon-credential/revoke`, plus credential revocation behavior during token issuance.
38. If using anonymous credentials, run `./scripts/integration_anon_credential_dispute.sh` and verify `/v1/admin/anon-credential/dispute` / `/v1/admin/anon-credential/dispute/clear` temporarily cap and then restore token minting tier for the same credential, and verify `/v1/admin/anon-credential/get` reflects current revoke/dispute state.
39. For cross-host validation before beta rollout, run `./scripts/integration_3machine_beta_validate.sh` from a client machine (machine C) with two server directories (machines A/B) and verify both multi-source bootstrap and federation operator-floor checks pass.
40. Run `./scripts/integration_3machine_beta_soak.sh` from machine C for repeated rounds (and optional injected faults) before inviting external beta testers.
41. For stricter cross-host anti-collusion and issuer drift checks, keep `--distinct-operators=1` and `--require-issuer-quorum=1` enabled on 3-machine validate/soak runs (default under `--beta-profile=1`), and require minimum client selection diversity (`--client-min-selection-lines`, `--client-min-entry-operators`, `--client-min-exit-operators`, `--client-require-cross-operator-pair`) so the client actually exercises multi-operator paths.
42. For production-grade cross-machine sign-off, run `sudo ./scripts/easy_node.sh three-machine-prod-gate ...` from machine C (Linux root) to execute strict control validate/soak plus real-WG validate/soak in one sequence (`--wg-max-consecutive-failures` controls sustained WG soak failure threshold, default `2`; `--wg-slo-profile recommended` applies default production soak SLO/failure budgets; `--wg-slo-profile strict` additionally applies cross-round diversity floors by default; `--wg-max-round-duration-sec` and `--wg-max-recovery-sec` enforce WG soak latency/recovery SLOs; `--wg-max-failure-class CLASS=N` plus `--wg-disallow-unknown-failure-class=1` enforce per-failure-class budgets; `--wg-strict-ingress-rehearsal=1` injects a controlled strict-client-ingress failure path for rehearsals; `--wg-min-selection-lines`, `--wg-min-entry-operators`, `--wg-min-exit-operators`, and `--wg-min-cross-operator-pairs` enforce real-WG selection diversity across rounds; `--control-fault-every`/`--control-fault-command` inject controlled disruptions during control-plane soak; `--wg-fault-every`/`--wg-fault-command` inject disruptions during real-WG soak; `--wg-validate-summary-json` writes a machine-readable WG validate result artifact; `--wg-soak-summary-json` writes a machine-readable WG soak result artifact; `--gate-summary-json` writes the overall gate result with per-step statuses/failure metadata). Use `sudo ./scripts/easy_node.sh three-machine-prod-bundle ... --signoff-check 1` when you also want an always-generated diagnostics bundle tarball and fail-close artifact signoff in the same run; this path now runs strict machine-C preflight by default (disable only for diagnostics with `--preflight-check 0`), fail-close bundle integrity verification by default (disable only for diagnostics with `--bundle-verify-check 0`), auto-captures an incident snapshot on failed runs by default (disable only for diagnostics with `--incident-snapshot-on-fail 0`), optionally accepts repeatable `--incident-snapshot-attach-artifact PATH` evidence files, and writes a one-command run report JSON by default at `<bundle_dir>/prod_bundle_run_report.json` (override with `--run-report-json`). If you want the same strict flow packaged as a recorded manual-validation step, use `sudo ./scripts/easy_node.sh three-machine-prod-signoff ... --pre-real-host-readiness 1 --runtime-fix 1 --print-summary-json 1`; it wraps `three-machine-prod-bundle`, can run the pre-real-host/runtime hygiene gates first, keeps the same diagnostics artifacts, automatically attaches runtime-doctor/runtime-fix evidence into failed incident snapshots, refreshes the shared manual-validation readiness report, attaches those refreshed readiness-report artifacts back into the failed incident snapshot bundle, emits a compact summary JSON, and records the final pass/fail receipt automatically. For the same flow with opinionated strict defaults, use `sudo ./scripts/easy_node.sh prod-pilot-runbook ...` (you can still append explicit overrides); this wrapper now gates on `pre-real-host-readiness` by default and auto-generates trend/alert/dashboard artifacts at the end of each run. You can run `./scripts/easy_node.sh prod-gate-check --run-report-json <bundle_dir>/prod_bundle_run_report.json` for signoff policy checks, `./scripts/easy_node.sh prod-gate-bundle-verify --run-report-json <bundle_dir>/prod_bundle_run_report.json` for integrity checks, `./scripts/easy_node.sh prod-gate-signoff --run-report-json <bundle_dir>/prod_bundle_run_report.json` to run both checks fail-closed in one command, `./scripts/easy_node.sh prod-gate-slo-summary --run-report-json <bundle_dir>/prod_bundle_run_report.json --fail-on-no-go 1` for single-run GO/NO-GO summary, `./scripts/easy_node.sh prod-gate-slo-trend --reports-dir .easy-node-logs --max-reports 25 --min-go-rate-pct 95 --fail-on-any-no-go 1 --since-hours 24 --summary-json .easy-node-logs/prod_slo_trend_24h.json` for time-windowed multi-run trend gating, `./scripts/easy_node.sh prod-gate-slo-alert --trend-summary-json .easy-node-logs/prod_slo_trend_24h.json --warn-go-rate-pct 98 --critical-go-rate-pct 90 --summary-json .easy-node-logs/prod_slo_alert_24h.json` to classify operator alert severity (OK/WARN/CRITICAL) with optional fail-close exits, or `./scripts/easy_node.sh prod-gate-slo-dashboard --reports-dir .easy-node-logs --since-hours 24 --dashboard-md .easy-node-logs/prod_slo_dashboard_24h.md` to emit a single operator dashboard artifact (markdown + JSON).
43. If enforcing anti-collusion (`CLIENT_REQUIRE_DISTINCT_OPERATORS=1` and/or `ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1`), run `./scripts/integration_distinct_operators.sh` and verify same-operator paths are rejected while distinct-operator paths pass.
44. If you also want jurisdiction separation during pairing, set `CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY=1` on clients and ensure relay descriptors publish accurate `country_code`.
45. If you want locality preference without hard filtering, set `CLIENT_EXIT_LOCALITY_SOFT_BIAS=1` and tune `CLIENT_EXIT_COUNTRY_BIAS`, `CLIENT_EXIT_REGION_BIAS`, and `CLIENT_EXIT_REGION_PREFIX_BIAS`.
46. For strict runtime guardrails across roles, run `./scripts/integration_beta_strict_roles.sh` and verify client/entry/exit/issuer fail closed on weak config and entry/issuer boot when strict prerequisites are met.
47. Run `./scripts/integration_wg_only_mode.sh` to verify wireguard-only fail-closed guardrails (`WG_ONLY_MODE`) reject scaffold/non-WG dataplane configuration before runtime.
48. For strict live WireGuard-mode behavior (non-privileged shim path), run `./scripts/integration_live_wg_full_path_strict.sh` and verify strict startup signals plus end-to-end plausible WireGuard packet forwarding/drop behavior.
49. Run `./scripts/integration_beta_fault_matrix.sh` to validate startup-race and sync-loss recovery paths in one pass before external beta tests.
50. Run `./scripts/integration_easy_node_role_guard.sh` to verify provider nodes are blocked from invite/admin actions while authority nodes are allowed past the role gate.
51. Run `./scripts/integration_easy_node_invite_auth_policy.sh` to verify invite/admin commands fail fast when authority token auth is disabled (`ISSUER_ADMIN_ALLOW_TOKEN=0`) and require signed admin credentials.
52. Run `./scripts/integration_prod_preflight_tools.sh` to verify easy-node strict prod preflight and authority signer rotate/status flows.
53. Run `./scripts/easy_node.sh incident-snapshot --mode auto` on each machine after any failed prod-gate/prod-bundle run to capture a shareable incident bundle (endpoint probes + docker/system snapshots) for triage and regression tracking. This now also writes `incident_summary.json` and `incident_report.md` into the bundle directory, and you can include extra evidence files with repeatable `--attach-artifact PATH`; if you need to rebuild the summary/report later, run `./scripts/easy_node.sh incident-snapshot-summary --bundle-dir <incident_bundle_dir>`. Higher-level operator summaries (`prod-gate-check`, `prod-gate-slo-summary`, `prod-pilot-cohort-check`, `prod-pilot-cohort-campaign-summary`) now also surface the attachment manifest/skipped paths when present.
