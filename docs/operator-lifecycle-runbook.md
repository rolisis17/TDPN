# Operator Lifecycle Runbook

This runbook documents repeatable onboarding/offboarding for provider/authority operators using:

`./scripts/easy_node.sh prod-operator-lifecycle-runbook`

It is designed for production-style operations with machine-readable summaries.

## 1) Onboard a provider operator

```bash
./scripts/easy_node.sh prod-operator-lifecycle-runbook \
  --action onboard \
  --mode provider \
  --public-host <PROVIDER_PUBLIC_IP_OR_DNS> \
  --authority-directory https://<AUTHORITY_IP_OR_DNS>:8081 \
  --authority-issuer https://<AUTHORITY_IP_OR_DNS>:8082 \
  --peer-directories https://<PEER_DIRECTORY_1>:8081,https://<PEER_DIRECTORY_2>:8081 \
  --peer-identity-strict 1 \
  --min-peer-operators 2 \
  --prod-profile 1 \
  --preflight-check 1 \
  --health-check 1 \
  --verify-relays 1 \
  --verify-relay-min-count 2
```

What it does:
- runs `server-preflight` (optional, enabled by default)
- runs `server-up`
- checks directory/entry/exit health (and issuer health in authority mode)
- waits for federation readiness when peers are configured (`server-federation-wait`)
- captures federation status JSON/log artifact (`server-federation-status`)
- optionally bootstraps invite keys for authority onboarding (`invite-generate`)
- verifies relay visibility in directory feed for the operator id
- can auto-rollback failed onboard runs by stopping stack and verifying relay absence
- can auto-capture runtime-doctor diagnostics on failed runs for faster root-cause triage
- can auto-capture an incident snapshot bundle on failed runs for operator handoff
- writes summary JSON to `.easy-node-logs/...`

## 2) Onboard an authority operator

```bash
./scripts/easy_node.sh prod-operator-lifecycle-runbook \
  --action onboard \
  --mode authority \
  --public-host <AUTHORITY_PUBLIC_IP_OR_DNS> \
  --peer-directories https://<PEER_DIRECTORY_1>:8081,https://<PEER_DIRECTORY_2>:8081 \
  --peer-identity-strict 1 \
  --min-peer-operators 2 \
  --prod-profile 1 \
  --preflight-check 1 \
  --health-check 1 \
  --verify-relays 1 \
  --onboard-invite 1 \
  --onboard-invite-count 1 \
  --onboard-invite-tier 1
```

## 3) Offboard an operator cleanly

```bash
./scripts/easy_node.sh prod-operator-lifecycle-runbook \
  --action offboard \
  --operator-id <OPERATOR_ID> \
  --directory-url https://<AUTHORITY_OR_TRUSTED_DIRECTORY>:8081 \
  --verify-absent 1
```

What it does:
- runs `server-down`
- waits until operator relays disappear from directory feed
- writes summary JSON with pass/fail and failure step

## 4) Useful flags

- `--summary-json <path>`: explicit summary artifact path.
- `--report-md <path>`: explicit human-readable lifecycle report path.
- `--print-summary-json 1`: print summary payload to stdout.
- `--verify-relay-timeout-sec <N>`: wait budget for relay publication/removal.
- `--verify-relay-min-count <N>`: minimum relays required for onboard verification.
- `--health-timeout-sec <N>`: per-endpoint readiness timeout.
- `--preflight-timeout-sec <N>`: preflight timeout.
- `--federation-check [0|1]`: enable/disable onboard federation readiness gate (default `1`).
- `--federation-ready-timeout-sec <N>`: total wait budget for readiness gate.
- `--federation-poll-sec <N>`: poll interval for readiness checks.
- `--federation-timeout-sec <N>`: timeout per federation admin request.
- `--federation-require-configured-healthy [0|1]`: require every configured peer to be healthy for federation readiness.
- `--federation-max-cooling-retry-sec <N>`: fail if any cooling peer reports a retry window above this threshold.
- `--federation-max-peer-sync-age-sec <N>` / `--federation-max-issuer-sync-age-sec <N>`: max allowed sync staleness ages.
- `--federation-min-peer-success-sources <N>` / `--federation-min-issuer-success-sources <N>`: minimum sync success-source floors.
- `--federation-min-peer-source-operators <N>` / `--federation-min-issuer-source-operators <N>`: minimum distinct source-operator floors from sync status.
- `--federation-status-fail-on-not-ready [0|1]`: fail lifecycle run when post-start `server-federation-status` does not meet configured policy thresholds.
- `--federation-status-file <path>`: explicit artifact path for captured federation status output.
- `--onboard-invite [0|1]`: enable authority onboarding invite bootstrap.
- `--onboard-invite-count <N>`: invite keys to generate when bootstrap is enabled.
- `--onboard-invite-tier 1|2|3`: default invite tier for generated keys.
- `--onboard-invite-wait-sec <N>`: issuer readiness wait budget before invite generation.
- `--onboard-invite-fail-open [0|1]`: continue onboarding when invite generation fails.
- `--onboard-invite-file <path>`: output artifact for generated keys (or failure diagnostics).
- `--rollback-on-fail [0|1]`: when onboard fails after startup, run `server-down` automatically.
- `--rollback-verify-absent [0|1]`: after rollback, verify operator relays disappear from directory feed.
- `--rollback-verify-timeout-sec <N>`: wait budget for rollback relay-absence verification.
- `--incident-snapshot-on-fail [0|1]`: capture incident bundle automatically when lifecycle run fails.
- `--incident-bundle-dir <path>`: explicit incident bundle output directory.
- `--incident-timeout-sec <N>`: timeout budget for incident snapshot collection.
- `--incident-include-docker-logs [0|1]` / `--incident-docker-log-lines <N>`: incident docker log capture controls.
- `--incident-attach-artifact <path>`: attach extra evidence files (repeatable).
- `--runtime-doctor-on-fail [0|1]`: capture runtime-doctor output automatically when lifecycle run fails.
- `--runtime-doctor-base-port <N>`: base port passed to runtime-doctor capture.
- `--runtime-doctor-client-iface <iface>` / `--runtime-doctor-exit-iface <iface>` / `--runtime-doctor-vpn-iface <iface>`: interface names used by runtime-doctor.
- `--runtime-doctor-file <path>`: explicit runtime-doctor output artifact path.

## 5) Summary JSON fields

Main fields in output summary:
- `status`: `ok` or `fail`
- `action`: `onboard` or `offboard`
- `mode`: resolved mode (`authority` or `provider`)
- `completed_steps`: successful steps list
- `failure_step` and `failure_rc`: first failed stage
- `relay_policy.observed_count`: latest operator relay count seen
- `directory_url` and `operator_id`: verification target context
- `report_md`: human-readable lifecycle report artifact path
- `checks.federation_enabled`: whether federation gating/status capture was enabled
- `checks.onboard_invite_enabled`: whether authority invite bootstrap was enabled
- `federation.wait_state`: `disabled`, `not_run`, `ready`, `failed`, or `skipped_no_peers`
- `federation.require_configured_healthy`, `federation.max_cooling_retry_sec`, `federation.max_peer_sync_age_sec`, `federation.max_issuer_sync_age_sec`, `federation.min_peer_success_sources`, `federation.min_issuer_success_sources`, `federation.min_peer_source_operators`, `federation.min_issuer_source_operators`, `federation.status_fail_on_not_ready`: effective strict federation policy thresholds used for this run
- `federation.peer_count`: effective configured peer count used for gate decision
- `federation.status_file` and `federation.status_capture_rc`: captured federation diagnostics artifact metadata
- `invite_bootstrap.state`: `disabled`, `not_run`, `generated`, `failed`, or skip state
- `invite_bootstrap.generated_count`, `invite_bootstrap.file`, `invite_bootstrap.rc`: invite artifact/result metadata
- `rollback.state`: `not_triggered`, `completed`, `skipped_server_not_started`, or rollback failure state
- `rollback.performed`, `rollback.server_down_rc`: rollback execution status
- `rollback.absent_verify_state`, `rollback.absent_observed_count`: relay-absence verification status after rollback
- `runtime_doctor.state`: `disabled`, `not_run`, `skipped_status_ok`, `captured`, or `failed`
- `runtime_doctor.rc`, `runtime_doctor.file`: runtime-doctor capture result and artifact path
- `runtime_doctor.base_port`, `runtime_doctor.client_iface`, `runtime_doctor.exit_iface`, `runtime_doctor.vpn_iface`: effective runtime-doctor capture settings
- `incident_snapshot.state`: `disabled`, `not_run`, `skipped_status_ok`, `captured`, or `failed`
- `incident_snapshot.bundle_dir`, `incident_snapshot.rc`: incident capture result + artifact location
- `incident_snapshot.attach_count`, `incident_snapshot.attach_artifacts_csv`: attached evidence metadata
- `incident_snapshot.summary_json`, `incident_snapshot.report_md`, `incident_snapshot.bundle_tar`, `incident_snapshot.bundle_tar_sha256_file`: normalized handoff artifact pointers
- `incident_snapshot.attachment_manifest`, `incident_snapshot.attachment_skipped`: attachment manifest paths
- `incident_snapshot.attachment_manifest_count`, `incident_snapshot.attachment_skipped_count`, `incident_snapshot.artifact_state`: attachment counts and completeness status (`complete|partial|missing|unknown`)

## 6) Troubleshooting

- `failure_step=server_preflight`:
  - peer/issuer reachability, identity floor, or strict peer-identity checks failed.
- `failure_step=server_up`:
  - stack start failed (`docker compose`/env/runtime issue).
- `failure_step=health_check`:
  - local services did not expose expected endpoints in timeout.
- `failure_step=federation_wait`:
  - federation readiness quorum did not converge in time; inspect `server-federation-status` output and peer/issuer sync health.
- `failure_step=federation_status`:
  - post-start diagnostics capture failed; verify directory admin token/env and inspect `federation.status_file`.
- `failure_step=onboard_invite`:
  - invite bootstrap failed in fail-close mode; inspect `invite_bootstrap.file` diagnostics and issuer admin auth mode.
- `failure_step=relay_verify`:
  - relay feed did not show required operator relay count in timeout.
- `failure_step=relay_absent_verify`:
  - operator relays still present after offboard in timeout.
- `rollback.state=server_down_failed`:
  - onboarding failed and rollback `server-down` also failed; inspect docker/env/runtime health before retry.
- `rollback.state=verify_absent_failed`:
  - rollback stopped stack but directory still reports operator relays inside timeout; inspect directory sync lag and relay TTL behavior.
- `runtime_doctor.state=failed`:
  - lifecycle failed but runtime-doctor artifact capture did not persist; run `easy_node.sh runtime-doctor --show-json 1` manually and attach output to incident handoff.
- `incident_snapshot.state=failed`:
  - lifecycle failure occurred but incident bundle capture also failed; run `easy_node.sh incident-snapshot --mode <authority|provider>` manually and attach runbook artifacts.

Note:
- if no peers are configured (`DIRECTORY_PEERS` empty and no `--peer-directories/--bootstrap-directory`), federation wait is skipped and summary reports `federation.wait_state=skipped_no_peers`.
- invite bootstrap is authority-onboard only; provider/offboard runs report a skip state when `--onboard-invite=1`.
