# Manual Validation Backlog

This file tracks the real-host checks that still need to be rerun manually while we continue hardening the automated path.

Live status:

```bash
./scripts/easy_node.sh manual-validation-status --show-json 1
./scripts/easy_node.sh manual-validation-report --print-report 1 --print-summary-json 1
./scripts/easy_node.sh roadmap-progress-report --refresh-manual-validation 1 --print-report 1 --print-summary-json 1
./scripts/easy_node.sh single-machine-prod-readiness --print-summary-json 1
./scripts/easy_node.sh vpn-rc-standard-path --print-report 1 --print-summary-json 1
# optional: include local profile-default decision signoff in that one-host sweep
./scripts/easy_node.sh single-machine-prod-readiness \
  --run-profile-compare-campaign-signoff 1 \
  --profile-compare-campaign-signoff-refresh-campaign 1 \
  --print-summary-json 1
```

That status view now also surfaces the latest failed incident handoff from recorded real-host smoke/signoff runs when one is available, so we can jump straight to the right bundle/report paths. The report wrapper turns that same state into one shareable markdown + JSON readiness handoff artifact, and the `client-vpn-smoke` / `three-machine-prod-signoff` wrappers now refresh that shared report automatically before they write the final receipt, so the saved receipt artifacts include the updated readiness report and failed incident bundles now pick up the refreshed readiness-report artifacts too. The readiness report now points directly at those bundled readiness-report attachments when they exist, so we can open the right files without manually browsing the attachment manifest first.

When `single-machine-prod-readiness` runs with `--run-profile-compare-campaign-signoff auto`, it now forces one campaign refresh pass automatically if the campaign summary artifact is missing, preferring docker rehearsal endpoints when available so the local profile-default signoff step can bootstrap without root.

`manual-validation-status` and `manual-validation-report` also expose a staged progress signal for single-machine work:
- `roadmap_stage=BLOCKED_LOCAL`: local runtime + WG-only gates are not clean yet.
- `roadmap_stage=READY_FOR_MACHINE_C_SMOKE`: local gates are clean; next external step is machine-C smoke.
- `roadmap_stage=READY_FOR_3_MACHINE_PROD_SIGNOFF`: machine-C smoke is done; next external step is true 3-machine signoff.
- `roadmap_stage=PRODUCTION_SIGNOFF_COMPLETE`: all tracked manual checks passed.
`roadmap-progress-report` now adds a VPN RC-done phase signal plus the explicit list of pending real-host checks so the remaining external-only tail is visible at a glance.

Manual readiness interpretation (operator quick guide):
- `pre_real_host_readiness.status=pass` with `manual_validation_report.readiness_status=NOT_READY` is expected while external gates are still pending (`machine_c_vpn_smoke`, `three_machine_prod_signoff`).
- `client-vpn-smoke` or `three-machine-prod-signoff` with `status=skip`, `defer_no_root=true`, `deferred_no_root=true`, and `stage=pre-real-host-readiness` means root-only defer was applied; treat as deferred, not complete.
- same commands with `status=fail` and `deferred_no_root=false` mean a real blocker (not root-only); fail-closed behavior is working as intended.
- `prod-pilot-runbook` / `prod-pilot-cohort-runbook` may continue after root-only deferred pre-readiness to collect pilot evidence, but final signoff still requires privileged reruns.
- next command after any root-only deferred warning:
  - `sudo ./scripts/easy_node.sh pre-real-host-readiness --strict-beta 1 --print-summary-json 1`

They also surface an optional one-host docker rehearsal snapshot (`docker_rehearsal_status`, `docker_rehearsal_ready`, `docker_rehearsal_command`) so we can track that confidence pass without changing real-host signoff requirements.
They now also surface an optional Linux root real-WG privileged matrix snapshot (`real_wg_privileged_status`, `real_wg_privileged_ready`, `real_wg_privileged_command`) so one-host dataplane confidence can be tracked alongside the docker rehearsal gate without changing machine-C / true 3-machine blockers.

They also surface a non-blocking profile-default gate snapshot from `profile-compare-campaign-signoff` (status/decision/recommended profile + next command) so default-profile decision progress is visible in the same readiness handoff.
That profile-default gate now reports `pending` when `decision=NO-GO` is driven by insufficient campaign evidence (for example low/incomplete campaign runs or local refresh blocked by root requirements), so one-host readiness stays focused on true blockers.
`warn` is reserved for advisory `NO-GO` outcomes with sufficient campaign evidence.
`single-machine-prod-readiness` now mirrors that same profile-default gate snapshot in its summary JSON (`summary.profile_default_gate`, `summary.profile_default_ready`) so the one-host sweep and manual-validation report stay consistent.
It now also prints the same profile-default gate fields in stdout (`profile_default_gate_status`, `profile_default_gate_available`, `profile_default_gate_next_command`) so operators can see the rerun path immediately without opening JSON artifacts.
When docker rehearsal artifacts are available, `profile_default_gate_next_command` now prefers a deterministic no-sudo refresh command (docker execution mode + explicit directory/issuer/entry/exit overrides), and also exposes `profile_default_gate_next_command_sudo` as explicit fallback.
The same gate snapshot now includes artifact pointers for fast triage (`campaign_check_summary_json_resolved`, `docker_rehearsal_matrix_summary_json`, `docker_rehearsal_profile_summary_json`) plus source hints (`next_command_source`, `docker_rehearsal_hint_available`, `docker_rehearsal_hint_source`).
Operator next steps:
- if `profile_default_gate_status=pending`: rerun `./scripts/easy_node.sh profile-compare-campaign-signoff --refresh-campaign 1 --print-summary-json 1` (or use docker campaign mode / launcher option 77 when non-root).
- if `profile_default_gate_status=warn`: keep the current default profile and continue machine-C + true 3-machine signoff; treat profile-default tuning as follow-up.
`single-machine-prod-readiness` now also prints `next_action_check_id` and `next_action_command` directly in stdout so the next roadmap step is visible immediately in terminal output.
It can now also include the one-host dockerized 3-machine rehearsal in that same sweep (`--run-three-machine-docker-readiness auto|0|1`) and surfaces the rehearsal status in summary JSON/stdout.
It can now also include an optional Linux root real-WG matrix receipt refresh in that same sweep (`--run-real-wg-privileged-matrix auto|0|1`), and treats that matrix step as a non-blocking confidence gate in one-host readiness output.
When `single-machine-prod-readiness` is pointed at a custom profile signoff summary path (`--profile-compare-campaign-signoff-summary-json`), it now forwards that exact path into `manual-validation-report` too, preventing mismatched profile-default gate reads across the two commands.
`easy_node.sh --help` now exposes that same profile-signoff summary override plus overlay controls for both `manual-validation-status` and `manual-validation-report`, and forwarding coverage verifies those flags pass through unchanged.
The easy launcher now exposes a dedicated advanced option for `single-machine-prod-readiness` (option 75), so this one-host production sweep can be run from the menu without rebuilding the command by hand.
The easy launcher also exposes `vpn-rc-standard-path` (option 76) for the locked one-command RC path (single-machine sweep + roadmap report handoff).

When the next blocker is a remediable runtime hygiene warning, `manual-validation-status` / `manual-validation-report` now point at `sudo ./scripts/easy_node.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1` as the immediate next action instead of sending you back through another doctor-only pass first. That recorded cleanup run wraps `runtime-fix`, refreshes the shared readiness report, and leaves behind a durable runtime-hygiene receipt in one step.

Preferred pre-machine-C sweep:

```bash
sudo ./scripts/easy_node.sh pre-real-host-readiness --strict-beta 1 --print-summary-json 1
```

Optional one-host docker rehearsal before real machine-C reruns:

```bash
./scripts/easy_node.sh three-machine-docker-readiness \
  --path-profile balanced \
  --soak-rounds 6 \
  --soak-pause-sec 3 \
  --print-summary-json 1
```

This rehearsal is a control-plane confidence pass only. It does not replace the
tracked real machine-C smoke or true multi-host production signoff checks below.

Preferred recorded wrapper:

```bash
./scripts/easy_node.sh three-machine-docker-readiness-record \
  --path-profile balanced \
  --soak-rounds 6 \
  --soak-pause-sec 3 \
  --print-summary-json 1
```

Optional Linux root real-WG matrix confidence run:

```bash
sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1
```

Record a completed manual check manually if you are not using one of the recorded wrappers:

```bash
./scripts/easy_node.sh manual-validation-record \
  --check-id wg_only_stack_selftest \
  --status pass \
  --notes "Linux root host rerun passed" \
  --artifact .easy-node-logs/easy_node_wg_only_stack_YYYYMMDD_HHMMSS.log
```

Preferred recorded wrapper:

```bash
sudo ./scripts/easy_node.sh wg-only-stack-selftest-record --strict-beta 1 --print-summary-json 1
```

## Current Pending Checks

### 0. Pre-machine-C readiness sweep before the next real-host rerun

Goal:
- clean stale runtime leftovers
- rerun the Linux root WG-only proof
- refresh the shared readiness report in one command

Command:

```bash
sudo ./scripts/easy_node.sh pre-real-host-readiness \
  --strict-beta 1 \
  --base-port 19280 \
  --client-iface wgcstack0 \
  --exit-iface wgestack0 \
  --vpn-iface wgvpn0 \
  --print-summary-json 1
```

### 1. WG-only stack selftest rerun on a Linux root host

Reason:
- fallback drill if the combined readiness sweep blocks at WG-only validation

Commands:

```bash
sudo ./scripts/easy_node.sh wg-only-stack-down \
  --force-iface-cleanup 1 \
  --base-port 19280 \
  --client-iface wgcstack0 \
  --exit-iface wgestack0

sudo rm -rf deploy/data/wg_only

sudo ./scripts/easy_node.sh wg-only-stack-selftest-record \
  --strict-beta 1 \
  --base-port 19280 \
  --client-iface wgcstack0 \
  --exit-iface wgestack0 \
  --print-summary-json 1
```

If it fails, collect:

```bash
tail -n 120 .easy-node-logs/wg_only_stack_selftest_record_*.log
```

### 2. Real machine-C VPN smoke test

Goal:
- validate host WireGuard bring-up from an external client machine
- confirm session establishment and exit-IP change

Suggested flow:

```bash
sudo ./scripts/easy_node.sh client-vpn-smoke \
  --bootstrap-directory https://A_HOST:8081 \
  --subject INVITE_KEY \
  --path-profile balanced \
  --interface wgvpn0 \
  --pre-real-host-readiness 1 \
  --runtime-fix 1 \
  --public-ip-url https://api.ipify.org \
  --country-url https://ipinfo.io/country \
  --print-summary-json 1
```

If this smoke run fails, keep the generated summary JSON and incident snapshot bundle together. The wrapper now records both automatically, attaches the runtime-doctor/runtime-fix evidence into the failed-run incident bundle, refreshes the shared readiness report, and attaches those refreshed readiness-report artifacts back into that failed incident bundle too.

### 3. True 3-machine production signoff run

Goal:
- run strict control-plane plus real-WG production validation from machine C
- produce bundle and signoff artifacts for operator review
- record the outcome automatically into manual-validation status

Suggested flow:

```bash
./scripts/easy_node.sh three-machine-reminder

sudo ./scripts/easy_node.sh three-machine-prod-signoff \
  --bundle-dir .easy-node-logs/prod_gate_bundle \
  --directory-a https://A_HOST:8081 \
  --directory-b https://B_HOST:8081 \
  --issuer-url https://A_HOST:8082 \
  --entry-url https://A_HOST:8083 \
  --exit-url https://A_HOST:8084 \
  --pre-real-host-readiness 1 \
  --runtime-fix 1 \
  --print-summary-json 1
```

## Quick Access

The CLI prints the same reminder with:

```bash
./scripts/easy_node.sh manual-validation-backlog
./scripts/easy_node.sh manual-validation-status --show-json 1
```

## Security Re-scan Notes (2026-04-18, independent verifier pass)

Potential remaining hardening items from a read-only grep/ripgrep + manual line-by-line sweep (Go/shell/Rust/JS/docs), prioritized by impact:

1. **P1 (resolved 2026-04-21): client outbound dial policy `localhost` mixed-resolution hardening**
   - References:
     - `internal/app/client.go:4094`
     - `internal/app/client.go:4127`
     - `internal/app/client.go:4142`
   - Status:
     - Default mode now fail-closes `localhost` unless all resolved answers are loopback.
     - Explicit dangerous/private-DNS override still intentionally bypasses that localhost safeguard.
   - Validation:
     - `internal/app/outbound_dial_policy_test.go` covers mixed-answer rejection in default mode and all-loopback acceptance.

2. **P2 (open): replay guards now support distributed Redis, but HA rollout is still configuration-sensitive**
   - References:
     - `services/exit/service.go:341`
     - `services/exit/service.go:597`
     - `services/exit/service.go:1900`
     - `services/directory/service.go:377`
     - `services/directory/service.go:549`
     - `services/directory/service.go:3307`
   - Why it matters:
      - Restart durability is present (file-backed stores), but active/active deployments can still accept cross-instance replays if they stay in instance-local file mode.
      - Shared-file mode is an opt-in mitigation for same-volume replicas, but it still depends on shared filesystem lock semantics.
      - Redis distributed mode is now supported, but production safety still depends on explicit Redis durability/availability hardening.
   - Suggested fix:
      - Use Redis replay mode for multi-instance deployments, with keys keyed by `(token_id, nonce)` and TTL enforcement.
      - Keep local file/cache mode for single-instance or same-volume labs only.
      - Treat shared-file mode as an interim same-volume option, not the long-term HA endpoint.
   - Progress update (2026-04-21):
      - Exit and directory startup logs now explicitly surface replay-store mode and loaded replay-entry counts, including clear warnings when replay persistence is instance-local.
      - Exit replay guard now supports opt-in shared-file mode via `EXIT_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE=1` plus lock timeout control `EXIT_TOKEN_PROOF_REPLAY_LOCK_TIMEOUT_SEC` (default 5s).
      - Directory provider replay guard now supports opt-in shared-file mode via `DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE=1` plus lock timeout control `DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_LOCK_TIMEOUT_SEC` (default 5s).
      - Exit replay guard now supports Redis mode via `EXIT_TOKEN_PROOF_REPLAY_REDIS_ADDR` (+ `EXIT_TOKEN_PROOF_REPLAY_REDIS_PASSWORD`, `EXIT_TOKEN_PROOF_REPLAY_REDIS_DB`, `EXIT_TOKEN_PROOF_REPLAY_REDIS_TLS`, `EXIT_TOKEN_PROOF_REPLAY_REDIS_PREFIX`, `EXIT_TOKEN_PROOF_REPLAY_REDIS_DIAL_TIMEOUT_SEC`).
      - Directory provider replay guard now supports Redis mode via `DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_ADDR` (+ `DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_PASSWORD`, `DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_DB`, `DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_TLS`, `DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_PREFIX`, `DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_DIAL_TIMEOUT_SEC`).
      - Mode precedence is `redis` > `shared-file` > `file` > `in-memory`.
   - Suggested tests:
      - Replay the same proof across two concurrently running instances (distinct local stores) and assert second submission is rejected.
      - Replay the same proof across two instances sharing one Redis backend and assert second submission is rejected.

3. **P2 (resolved 2026-04-21): integration scripts no longer leak raw PoP private-key JSON on parse failures**
   - References:
     - `scripts/integration_lifecycle_chaos.sh:109`
     - `scripts/integration_multi_issuer.sh:40`
     - `scripts/integration_revocation.sh:23`
   - Status:
     - The scripts now use redacted tokenpop error helpers and keypair parsing helpers that never print raw tokenpop payloads.
   - Validation:
     - Script syntax checks pass for all three updated integration scripts.

4. **P2 (resolved 2026-04-21): privileged `entry-exit` compose runtime is override-gated**
   - References:
     - `deploy/docker-compose.yml`
     - `scripts/easy_node.sh`
   - Status:
     - Base compose path is documented as non-privileged by default.
     - Privileged `entry-exit` runtime is documented as requiring a dedicated override compose file.
     - `easy_node.sh` is documented as auto-including that privileged override path when `ENTRY_EXIT_PRIVILEGED=true`.
   - Validation:
     - Deployment/README/MVP docs now consistently describe the same override-gated privilege model.

5. **P3 (resolved 2026-04-21): client-side trusted-key/subject loaders use bounded regular-file reads**
   - References:
     - `internal/app/directory_trust.go:98`
     - `internal/app/client.go:176`
   - Status:
     - `loadTrustedKeys` and `loadClientSubject` now use `readAppFileBounded`, which enforces regular-file checks, symlink rejection, `lstat/open/samefile` anti-race checks, and max-byte limits.
   - Validation:
     - `internal/app/file_io_test.go` covers bounded read, oversize rejection, symlink rejection, and non-regular file rejection.

6. **P1 (resolved in current branch): sensitive local IDE runtime artifacts removed from repo**
   - References:
     - `User/globalStorage/storage.json:5`
     - `User/globalStorage/storage.json:14`
     - `User/globalStorage/github.copilot-chat/copilotCli/copilot:3`
     - `User/globalStorage/github.copilot-chat/debugCommand/copilot-debug:3`
     - `User/globalStorage/state.vscdb` (binary SQLite)
   - Status:
     - `git ls-files User/globalStorage` now returns no tracked files.
     - `.gitignore` includes guardrails to prevent reintroduction.
   - Remaining follow-up:
     - If this data was pushed/shared previously, rotate any potentially exposed credentials/tokens and assess remote history cleanup.

7. **P3 (verified resolved): bounded service file reads enforce regular-file + anti-symlink/TOCTOU checks**
   - References:
     - `services/entry/service.go:1881`
     - `services/directory/service.go:5887`
     - `services/issuer/service.go:3577`
   - Status:
     - `readFileBounded` in `directory`, `entry`, and `issuer` now validates path/file type and same-file consistency while keeping bounded reads.

8. **P1 (verified resolved): entry service map growth bounded (memory DoS hardening)**
   - References:
     - `services/entry/service.go:89`
     - `services/entry/service.go:96`
     - `services/entry/service.go:107`
     - `services/entry/service.go:553`
     - `services/entry/service.go:601`
     - `services/entry/service.go:690`
   - Status:
     - Capacity bounds + pruning + fail-closed behavior are present and covered by focused tests.

9. **P2 (verified resolved): default admin token fallback is no longer implicit**
   - References:
     - `services/directory/service.go:154`
     - `services/directory/service.go:421`
     - `services/issuer/service.go:132`
     - `services/issuer/service.go:158`
   - Status:
     - `directory`/`issuer` no longer auto-populate `dev-admin-token` by default.
     - Legacy fallback requires explicit dangerous opt-in env vars.

10. **P3 (verified resolved): integration fan-out no longer uses `xargs ... sh -c` in flagged scripts**
    - References:
      - `scripts/integration_client_startup_burst.sh:130`
      - `scripts/integration_load_chaos.sh:219`
    - Status:
      - Flagged scripts now use function/background-job fan-out.
      - `rg 'xargs.*sh -c|xargs.*bash -c'` returns no matches.
