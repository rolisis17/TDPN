# Production Pilot Cohort Runbook

Use this runbook to execute sustained pilot rounds and produce one cohort-level decision artifact.

Command:

```bash
./scripts/easy_node.sh prod-pilot-cohort-runbook [flags] -- [prod-pilot-runbook args...]
```

## Recommended baseline

```bash
./scripts/easy_node.sh prod-pilot-cohort-runbook \
  --rounds 5 \
  --pause-sec 60 \
  --trend-min-go-rate-pct 95 \
  --max-alert-severity WARN \
  --bundle-outputs 1 \
  --bundle-fail-close 1 \
  --print-summary-json 1 \
  -- \
  --bootstrap-directory https://<A_HOST>:8081 \
  --subject pilot-client
```

## What it does

1. Runs `prod-pilot-runbook` repeatedly for `--rounds`.
2. Stores each round in `reports_dir/round_<N>/` with:
   - round log
   - `prod_bundle_run_report.json`
3. Builds cohort SLO outputs:
   - trend summary (`prod_pilot_cohort_trend.json`)
   - alert summary (`prod_pilot_cohort_alert.json`)
4. Writes final cohort summary JSON:
   - `prod_pilot_cohort_summary.json`
5. Optionally writes a shareable cohort bundle:
   - tarball (`reports_dir.tar.gz` by default)
   - checksum sidecar (`.sha256`)
   - manifest JSON (`prod_pilot_cohort_bundle_manifest.json`)

## Pre-Readiness Defer Semantics (Operator Practical)

Top-level pre-readiness runs once before cohort rounds by default.

Non-root default:
- wrapper auto-enables pre-readiness defer mode for root-required checks.
- if pre-readiness fails only because WG-only proof is root-required/deferred, cohort continues with a warning so you can still gather bundle evidence.

Fail-closed rule:
- if pre-readiness fails for any non-root-independent reason (runtime hygiene, malformed outputs, unrelated blockers), cohort stops immediately.

What to run next after a root-only deferred warning:

```bash
sudo ./scripts/easy_node.sh pre-real-host-readiness --strict-beta 1 --print-summary-json 1
sudo ./scripts/easy_node.sh prod-pilot-cohort-runbook --rounds 5 --pause-sec 60 -- --bootstrap-directory https://<A_HOST>:8081 --subject pilot-client
```

Diagnostics-only override:
- skip pre-readiness gate entirely with `--pre-real-host-readiness 0` (not for final signoff posture).

Then verify artifacts:

```bash
./scripts/easy_node.sh prod-pilot-cohort-bundle-verify \
  --summary-json <reports_dir>/prod_pilot_cohort_summary.json
```

Then run fail-closed signoff:

```bash
./scripts/easy_node.sh prod-pilot-cohort-signoff \
  --summary-json <reports_dir>/prod_pilot_cohort_summary.json
```

Minimal one-command operator path:

```bash
./scripts/easy_node.sh prod-pilot-cohort-quick \
  --bootstrap-directory https://<A_HOST>:8081 \
  --subject pilot-client
```

Quick-mode artifact:
- run report JSON defaults to `<reports_dir>/prod_pilot_cohort_quick_report.json` (override with `--run-report-json`).
- validate quick run-report policy with:
  - `./scripts/easy_node.sh prod-pilot-cohort-quick-check --run-report-json <reports_dir>/prod_pilot_cohort_quick_report.json`
  - output now also prints the upstream `pre_real_host_readiness_summary_json` path when present, plus direct incident handoff paths when failed-round incident artifacts are available
- aggregate quick trend with:
  - `./scripts/easy_node.sh prod-pilot-cohort-quick-trend --reports-dir <reports_dir> --summary-json <reports_dir>/prod_pilot_quick_trend.json`
  - trend summary JSON now also carries latest failed incident handoff paths plus the upstream `pre_real_host_readiness_summary_json` pointer when available
- classify quick alert severity with:
  - `./scripts/easy_node.sh prod-pilot-cohort-quick-alert --trend-summary-json <reports_dir>/prod_pilot_quick_trend.json --summary-json <reports_dir>/prod_pilot_quick_alert.json`
  - alert JSON/output now also carries that same readiness pointer when the latest failed incident handoff exists
- generate quick dashboard artifacts with:
  - `./scripts/easy_node.sh prod-pilot-cohort-quick-dashboard --reports-dir <reports_dir> --dashboard-md <reports_dir>/prod_pilot_quick_dashboard.md`
  - dashboard markdown now also renders incident handoff paths plus the same readiness pointer when present
- run one-command quick signoff gate with:
  - `./scripts/easy_node.sh prod-pilot-cohort-quick-signoff --run-report-json <reports_dir>/prod_pilot_cohort_quick_report.json --reports-dir <reports_dir> --max-alert-severity WARN`
  - generated signoff JSON now also carries incident handoff artifact paths and the upstream `pre_real_host_readiness_summary_json` path when present
- run one-command quick pilot runbook (quick + signoff + optional dashboard) with:
  - `./scripts/easy_node.sh prod-pilot-cohort-quick-runbook --bootstrap-directory https://<A_HOST>:8081 --subject pilot-client --max-alert-severity WARN --max-round-failures 0 --bundle-outputs 1 --bundle-fail-close 1`
  - generated runbook summary now also preserves incident handoff artifact paths from quick signoff when available
- run low-prompt sustained campaign wrapper (campaign defaults + handoff summary artifacts) with:
  - `./scripts/easy_node.sh prod-pilot-cohort-campaign --bootstrap-directory https://<A_HOST>:8081 --subject pilot-client`
- regenerate one concise campaign handoff report later from saved artifacts with:
  - `./scripts/easy_node.sh prod-pilot-cohort-campaign-summary --reports-dir <reports_dir> --fail-on-no-go 1`
  - this handoff summary now also surfaces failed-round `incident_summary.json` / `incident_report.md` paths when incident bundles were captured, plus the upstream `pre_real_host_readiness_summary.json` pointer from quick-runbook artifacts when available

Campaign wrapper outputs:
- `<reports_dir>/prod_pilot_campaign_summary.json`
- `<reports_dir>/prod_pilot_campaign_summary.md`
- `<reports_dir>/prod_pilot_campaign_run_report.json`
- `<reports_dir>/prod_pilot_campaign_signoff_summary.json`
- `<reports_dir>/pre_real_host_readiness_summary.json`

By default, campaign now also runs inline campaign signoff (`campaign-signoff-check=1`) after summary generation.
- keep strict fail-close behavior: default `--campaign-signoff-required 1`
- disable only for diagnostics: `--campaign-signoff-check 0`
- post-run artifact gate can enforce signoff completeness with `prod-pilot-cohort-campaign-check --require-campaign-signoff-attempted 1 --require-campaign-signoff-ok 1 --require-campaign-signoff-summary-json-valid 1`

## Key policy flags

- `--require-all-rounds-ok`:
  - `1` means any failed pilot round marks the cohort as failed.
- `--continue-on-fail`:
  - `0` stops at first failed round.
  - `1` continues all rounds and evaluates aggregate results.
- `--trend-min-go-rate-pct`:
  - minimum accepted GO-rate for trend evaluation.
- `--max-alert-severity`:
  - accepted maximum alert severity (`OK|WARN|CRITICAL`).
  - default is `WARN`, which fail-closes on `CRITICAL`.
- `--bundle-outputs`:
  - `1` (default) creates cohort tar/checksum/manifest artifacts.
- `--bundle-fail-close`:
  - `1` (default) fails cohort if bundle generation/checksum fails.
- `--bundle-tar`, `--bundle-sha256-file`, `--bundle-manifest-json`:
  - override artifact output paths.

## Main outputs

- Cohort summary JSON includes:
  - `status`, `failure_step`, `final_rc`
  - `rounds.requested/attempted/passed/failed`
- `artifacts.run_reports` list
- `artifacts.bundle_tar`, `artifacts.bundle_sha256_file`, `artifacts.bundle_manifest_json`
- trend and alert result fields
- per-round result entries (`round_results`)
- bundle result block (`bundle.*`)

Bundle verifier behavior:
- validates tar checksum sidecar
- validates manifest schema (`generated_at`, artifact pointers, run reports, round results)
- validates round structure (`round_*` directories, round logs, non-empty `run_reports.list`)

Cohort check/signoff behavior:
- validates cohort `status` and round-failure policy
- validates trend decision/GO-rate thresholds
- validates alert severity threshold
- validates required bundle presence (`bundle.created`, manifest artifact)

## Failure-step meanings

- `pilot_rounds`: one or more pilot rounds failed under round policy.
- `slo_trend`: trend script failed or trend gate failed.
- `slo_alert`: alert script failed.
- `alert_severity_policy`: alert severity exceeded `--max-alert-severity`.
- `alert_severity_parse`: alert summary had unknown severity value.
- `bundle_outputs`: bundle artifact generation failed under fail-close mode.
