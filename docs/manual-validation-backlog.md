# Manual Validation Backlog

This file tracks the real-host checks that still need to be rerun manually while we continue hardening the automated path.

Live status:

```bash
./scripts/easy_node.sh manual-validation-status --show-json 1
./scripts/easy_node.sh manual-validation-report --print-report 1 --print-summary-json 1
```

That status view now also surfaces the latest failed incident handoff from recorded real-host smoke/signoff runs when one is available, so we can jump straight to the right bundle/report paths. The report wrapper turns that same state into one shareable markdown + JSON readiness handoff artifact, and the `client-vpn-smoke` / `three-machine-prod-signoff` wrappers now refresh that shared report automatically before they write the final receipt, so the saved receipt artifacts include the updated readiness report and failed incident bundles now pick up the refreshed readiness-report artifacts too. The readiness report now points directly at those bundled readiness-report attachments when they exist, so we can open the right files without manually browsing the attachment manifest first.

Preferred pre-machine-C sweep:

```bash
sudo ./scripts/easy_node.sh pre-real-host-readiness --strict-beta 1 --print-summary-json 1
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
  --beta-profile 1 \
  --interface wgvpn0 \
  --distinct-operators 1 \
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
  --runtime-fix 1 \
  --print-summary-json 1
```

## Quick Access

The CLI prints the same reminder with:

```bash
./scripts/easy_node.sh manual-validation-backlog
./scripts/easy_node.sh manual-validation-status --show-json 1
```
