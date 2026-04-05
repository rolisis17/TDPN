# Manual Validation Backlog

This file tracks the real-host checks that still need to be rerun manually while we continue hardening the automated path.

Live status:

```bash
./scripts/easy_node.sh manual-validation-status --show-json 1
./scripts/easy_node.sh manual-validation-report --print-report 1 --print-summary-json 1
./scripts/easy_node.sh roadmap-progress-report --refresh-manual-validation 1 --print-report 1 --print-summary-json 1
./scripts/easy_node.sh single-machine-prod-readiness --print-summary-json 1
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

They also surface an optional one-host docker rehearsal snapshot (`docker_rehearsal_status`, `docker_rehearsal_ready`, `docker_rehearsal_command`) so we can track that confidence pass without changing real-host signoff requirements.
They now also surface an optional Linux root real-WG privileged matrix snapshot (`real_wg_privileged_status`, `real_wg_privileged_ready`, `real_wg_privileged_command`) so one-host dataplane confidence can be tracked alongside the docker rehearsal gate without changing machine-C / true 3-machine blockers.

They also surface a non-blocking profile-default gate snapshot from `profile-compare-campaign-signoff` (status/decision/recommended profile + next command) so default-profile decision progress is visible in the same readiness handoff.
When a profile-compare campaign refresh cannot run because local stack bootstrap needs root (`--start-local-stack=1 requires root`) and no docker rehearsal endpoints are available, that profile-default gate now reports `pending` with a sudo-ready rerun command instead of a hard `fail`, so single-machine readiness signaling stays focused on true blockers.
`single-machine-prod-readiness` now mirrors that same profile-default gate snapshot in its summary JSON (`summary.profile_default_gate`, `summary.profile_default_ready`) so the one-host sweep and manual-validation report stay consistent.
It now also prints the same profile-default gate fields in stdout (`profile_default_gate_status`, `profile_default_gate_available`, `profile_default_gate_next_command`) so operators can see the rerun path immediately without opening JSON artifacts.
`single-machine-prod-readiness` now also prints `next_action_check_id` and `next_action_command` directly in stdout so the next roadmap step is visible immediately in terminal output.
It can now also include the one-host dockerized 3-machine rehearsal in that same sweep (`--run-three-machine-docker-readiness auto|0|1`) and surfaces the rehearsal status in summary JSON/stdout.
It can now also include an optional Linux root real-WG matrix receipt refresh in that same sweep (`--run-real-wg-privileged-matrix auto|0|1`), and treats that matrix step as a non-blocking confidence gate in one-host readiness output.
When `single-machine-prod-readiness` is pointed at a custom profile signoff summary path (`--profile-compare-campaign-signoff-summary-json`), it now forwards that exact path into `manual-validation-report` too, preventing mismatched profile-default gate reads across the two commands.
`easy_node.sh --help` now exposes that same profile-signoff summary override plus overlay controls for both `manual-validation-status` and `manual-validation-report`, and forwarding coverage verifies those flags pass through unchanged.
The easy launcher now exposes a dedicated advanced option for `single-machine-prod-readiness` (option 75), so this one-host production sweep can be run from the menu without rebuilding the command by hand.

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
  --bootstrap-directory http://A_HOST:8081 \
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
