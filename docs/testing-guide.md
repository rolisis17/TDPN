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

Desktop native prerequisites (scaffold/beta desktop flows):
- Windows desktop native (`desktop-doctor` / `desktop-native-bootstrap`):
  - Go + Node.js/npm + Rust (rustup MSVC toolchain) + Git (with Git Bash).
  - Visual Studio Build Tools (C++), Windows 10/11 SDK, and Microsoft Edge WebView2 Runtime.
- Linux desktop native (`desktop-doctor` / `desktop-native-bootstrap`):
  - Go + Node.js/npm + Rust + Git.
  - `pkg-config` plus GTK/WebKit development libraries required by Tauri/WebView (`libgtk-3-dev`, `libwebkit2gtk-4.1-dev`, or distro equivalents).
- Start with `./scripts/easy_node.sh desktop-doctor --platform windows|linux`, then run `./scripts/easy_node.sh desktop-native-bootstrap --platform windows|linux`.
- `desktop-doctor` / `desktop-native-bootstrap` now surface proactive prerequisite checks and remediation hints (including `recommended_commands` in summary JSON output).
- Compatibility note: desktop helper scripts remain scaffold/non-production compatibility tooling and are not a production-readiness claim.

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
   - easy-node config v1 contract (`integration_easy_node_config_v1.sh`)
   - local API config defaults contract (`integration_local_api_config_defaults.sh`)
   - local control API forwarding contract (`integration_local_control_api_contract.sh`)
   - local control API GPM bootstrap trust contract (`integration_local_control_api_gpm_manifest_trust.sh`)
   - desktop scaffold contract (`integration_desktop_scaffold_contract.sh`)
   - web portal scaffold contract (`integration_web_portal_contract.sh`, including bootstrap trust panel + telemetry render markers)
   - web home contract (`integration_web_home_contract.sh`, validating stable homepage HTML/CSS markers in `apps/web/index.html` + `apps/web/assets/gpm.css`)
   - windows desktop native bootstrap guardrails (`integration_windows_desktop_native_bootstrap_guardrails.sh`)
   - windows desktop installer guardrails (`integration_windows_desktop_installer_guardrails.sh`)
   - linux desktop installer guardrails (`integration_linux_desktop_installer_guardrails.sh`)

Expected result:
- final line: `[ci] ok`

If it fails:
- script prints relevant logs from `/tmp/*`.

Windows desktop native bootstrap guardrails:

```bash
./scripts/integration_windows_desktop_native_bootstrap_guardrails.sh
./scripts/easy_node.sh desktop-windows-native-bootstrap-guardrails
```

Desktop installer guardrails:

```bash
./scripts/integration_windows_desktop_installer_guardrails.sh
./scripts/integration_linux_desktop_installer_guardrails.sh
./scripts/easy_node.sh desktop-windows-installer-guardrails
./scripts/easy_node.sh desktop-linux-installer-guardrails
```

Desktop launcher wrappers:

```bash
./scripts/easy_node.sh desktop-doctor [--platform auto|linux|windows] [...]
./scripts/easy_node.sh desktop-native-bootstrap [--platform auto|linux|windows] [...]
./scripts/easy_node.sh desktop-one-click [--platform auto|linux|windows] [...]
./scripts/easy_node.sh desktop-install-launch [--platform auto|linux|windows] [desktop_installer args...]
./scripts/easy_node.sh desktop-packaged-run [--platform auto|linux|windows] [...]
./scripts/easy_node.sh desktop-local-api-session [--platform auto|linux|windows] [...]
```

`desktop-install-launch` defaults:
- auto-adds build-if-missing unless explicitly overridden.
- applies launch-after-install defaults when installer scripts expose launch flags.

- `--platform auto` is the default and routes to the current host platform.
- Use `--platform linux` or `--platform windows` for an explicit path.
- `EASY_NODE_DESKTOP_PLATFORM` overrides host detection for deterministic automation.
- `desktop-doctor` and `desktop-native-bootstrap` now emit proactive prerequisite checks plus copy/paste remediation hints.
- Existing platform-specific desktop commands remain available and documented below.

## 3a) Phase 0/1 targeted gates

`ci_phase0` (fast Phase-0 product-surface gate):

```bash
./scripts/ci_phase0.sh
```

- Purpose: fail-fast contract check for launcher wiring/runtime, simple prompt budget (`<=6` prompts), config-v1, and local control API forwarding.
- When to run: before full `ci_local.sh` when editing launcher/simple-mode flow, prompt flow, or config-v1/local API surface.
- Expected artifacts: console step lines (`[ci-phase0] ...`); no aggregate summary file.
- Exit meaning: `0` with final `[ci-phase0] ok` on full pass; non-zero on first failing step (`2` for invalid args/missing executable step script).

`ci_phase1_resilience` (focused Phase-1 resilience wrapper gate):

```bash
./scripts/ci_phase1_resilience.sh
```

- Purpose: run profile-matrix/RC-resilience wrapper chain checks (`three_machine_docker_profile_matrix`, `profile_compare_docker_matrix`, `three_machine_docker_profile_matrix_record`, `vpn_rc_matrix_path`, `vpn_rc_resilience_path`) with deterministic stage accounting.
- Additional stages:
  - `session_churn_guard` (`integration_session_churn_guard.sh`) is enabled by default.
  - `three_hop_runtime_integration` (`integration_client_3hop_runtime.sh`) is optional (`--run-3hop-runtime-integration 1`).
- When to run: after changes to phase-1 resilience wrappers, profile-matrix orchestration, or RC chain wiring; use `--dry-run 1` for contract-only verification.
- Expected artifacts: report tree under `.easy-node-logs/ci_phase1_resilience_<stamp>/`, including `ci_phase1_resilience_summary.json` plus per-stage summary/report artifacts.
- Exit meaning: `0` when all enabled stages pass; non-zero when any enabled stage fails (summary `status=fail` and per-stage `status/rc` fields identify failure).

`ci_phase1_resilience` resume mode (retry interrupted long runs):

- Command shape: `./scripts/ci_phase1_resilience.sh --resume 1 --reports-dir <same-dir>`.
- Resume reuses prior passing summary artifacts for wrapper stages:
  - `three_machine_docker_profile_matrix`
  - `profile_compare_docker_matrix`
  - `three_machine_docker_profile_matrix_record`
  - `vpn_rc_matrix_path`
  - `vpn_rc_resilience_path`
- Resume does not auto-reuse runtime-only stages; `session_churn_guard` and optional `three_hop_runtime_integration` run normally when enabled.
- Dry-run note: `--dry-run 1` keeps contract-only behavior; no stage commands are executed.
- Best practice: point `--reports-dir` to the exact directory from the previous interrupted attempt.

Retry example:

```bash
./scripts/ci_phase1_resilience.sh --resume 1 --reports-dir .easy-node-logs/ci_phase1_resilience_20260416_203000
```

`integration_ci_phase1_resilience` (Phase-1 gate contract check):

```bash
./scripts/integration_ci_phase1_resilience.sh
```

- Purpose: verify `ci_phase1_resilience.sh` contract behavior (stage ordering, dry-run forwarding, runtime-stage skip policy, toggle wiring, and first-failure `rc` propagation).
- When to run: after editing `ci_phase1_resilience.sh` stage wiring, defaults, or toggle/env forwarding in higher-level CI wrappers.
- Expected artifacts: temporary summary JSON and log captures under a harness-owned temp directory.
- Exit meaning: `0` when all contract assertions pass; non-zero on any contract regression (`2` for missing required commands/executable under test).

`vpn-rc-resilience-path` (Phase-1 resilience handoff run command):

```bash
./scripts/easy_node.sh vpn-rc-resilience-path
```

- Purpose: execute the Phase-1 resilience run chain and emit handoff booleans (`profile_matrix_stable`, `peer_loss_recovery_ok`, `session_churn_guard_ok`) in one summary.
- When to run: after profile-matrix/resilience wrapper changes and before publishing roadmap progress handoff artifacts.
- Expected artifacts: `.easy-node-logs/vpn_rc_resilience_path_<stamp>/vpn_rc_resilience_path_summary.json` (plus stage-level reports under the same run directory).
- Exit meaning: `0` when all enabled resilience stages pass; non-zero when any stage fails (summary `status=fail` + `rc` fields).

`integration_vpn_rc_resilience_path` (Phase-1 resilience handoff check):

```bash
./scripts/integration_vpn_rc_resilience_path.sh
```

- Purpose: validate `vpn-rc-resilience-path` summary contract fields, including explicit resilience handoff booleans and stable fail/pass status behavior.
- When to run: after modifying `vpn_rc_resilience_path.sh` output schema/derivation logic.
- Expected artifacts: harness temp summary/log files for pass/fail contract scenarios.
- Exit meaning: `0` when contract checks pass; non-zero on any schema/status/rc mismatch.

`integration_roadmap_progress_resilience_handoff` (handoff ingestion check):

```bash
./scripts/integration_roadmap_progress_resilience_handoff.sh
```

- Purpose: ensure roadmap progress reporting ingests and surfaces resilience handoff fields from `vpn_rc_resilience_path_summary.json`.
- Also validates Phase-1 handoff ingestion (`--phase1-resilience-handoff-summary-json`) and the non-blockchain actionable gate list contract (`vpn_track.non_blockchain_actionable_no_sudo_or_github`) for checks that do not require sudo or GitHub.
- When to run: after editing `roadmap_progress_report.sh` resilience-source detection or output mapping.
- Expected artifacts: harness temp summaries validating ingestion and fallback behavior.
- Exit meaning: `0` when ingestion contract checks pass; non-zero on mapping/regression failures.

`integration_roadmap_progress_phase2_handoff` (Phase-2 handoff ingestion check):

```bash
./scripts/integration_roadmap_progress_phase2_handoff.sh
```

- Purpose: ensure roadmap progress reporting ingests and surfaces the Phase-2 Linux production-candidate handoff in the `vpn_track` block of the generated JSON/markdown report.
- When to run: after editing Phase-2 handoff wiring or `roadmap_progress_report.sh` output mapping.
- Expected artifacts: harness temp summaries validating the Phase-2 handoff contract and report placement.
- Exit meaning: `0` when contract checks pass; non-zero on any schema/status/mapping regression.

`integration_roadmap_progress_phase3_handoff` (Phase-3 handoff ingestion check):

```bash
./scripts/integration_roadmap_progress_phase3_handoff.sh
```

- Purpose: ensure roadmap progress reporting ingests and surfaces the Phase-3 Windows client-beta handoff in the `vpn_track` block of the generated JSON/markdown report.
- When to run: after editing Phase-3 handoff wiring or `roadmap_progress_report.sh` output mapping.
- Expected artifacts: harness temp summaries validating direct, nested, fallback, and missing-input ingestion paths.
- Exit meaning: `0` when contract checks pass; non-zero on any schema/status/mapping regression.

`integration_roadmap_progress_phase4_handoff` (Phase-4 handoff ingestion check):

```bash
./scripts/integration_roadmap_progress_phase4_handoff.sh
```

- Purpose: ensure roadmap progress reporting ingests and surfaces the Phase-4 Windows full-parity handoff in the `vpn_track` block of the generated JSON/markdown report.
- When to run: after editing Phase-4 handoff wiring or `roadmap_progress_report.sh` output mapping.
- Expected artifacts: harness temp summaries validating direct, nested, fallback, and missing-input ingestion paths.
- Exit meaning: `0` when contract checks pass; non-zero on any schema/status/mapping regression.

`integration_roadmap_progress_phase5_handoff` (Phase-5 handoff ingestion check):

```bash
./scripts/integration_roadmap_progress_phase5_handoff.sh
```

- Purpose: ensure roadmap progress reporting ingests and surfaces the Phase-5 settlement-layer handoff in the `vpn_track` block of the generated JSON/markdown report.
- When to run: after editing Phase-5 handoff wiring or `roadmap_progress_report.sh` output mapping.
- Expected artifacts: harness temp summaries validating direct, nested, fallback, and missing-input ingestion paths.
- Exit meaning: `0` when contract checks pass; non-zero on any schema/status/mapping regression.

`roadmap_non_blockchain_actionable_run` (no-sudo actionable gate runner):

```bash
./scripts/roadmap_non_blockchain_actionable_run.sh --recommended-only 1 --print-summary-json 1
```

- Purpose: resolve `vpn_track.non_blockchain_actionable_no_sudo_or_github` from `roadmap_progress_report`, then execute selected actions in one wrapper run.
- Recommended use: `--recommended-only 1` for one fast next action, or run without it to execute all currently listed no-sudo/no-GitHub actions.
- Clean launcher/wiring invocation path (same behavior through easy-node command routing):
```bash
./scripts/easy_node.sh roadmap-non-blockchain-actionable-run --recommended-only 1 --print-summary-json 1
```
- Optional limit: `--max-actions N` to cap how many actions run in one pass.
- Optional parallel execution: `--parallel 1` to run selected no-sudo actions concurrently and reduce wall-clock time.
- Optional per-action timeout: `--action-timeout-sec N` (or env `ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ACTION_TIMEOUT_SEC`), where `0` keeps current unlimited behavior.
- Timeout semantics: timed-out actions are marked `status=fail` with `timed_out=true`, `failure_kind=timed_out`, and `timeout_sec=N`; the runner continues remaining actions, and wrapper exit code still follows the first failing action (`124` for timeout).
- Expected artifacts: one wrapper summary JSON and per-action logs under `.easy-node-logs/roadmap_non_blockchain_actionable_run_<stamp>/`.
- Exit meaning: `0` when selected actions pass; non-zero with first failing action `rc`.

Fast refresh: Phase-1 handoff summary (no heavy CI rerun):

```bash
latest_vpn_rc="$(find .easy-node-logs -type f -name vpn_rc_resilience_path_summary.json -print 2>/dev/null | sort | tail -n 1)"
./scripts/easy_node.sh phase1-resilience-handoff-run \
  --run-ci-phase1-resilience 0 \
  --run-phase1-resilience-handoff-check 1 \
  --handoff-vpn-rc-resilience-summary-json "$latest_vpn_rc" \
  --print-summary-json 1
```

- Purpose: emit a fresh `phase1_resilience_handoff_run` summary from an existing `vpn_rc_resilience_path` artifact without re-running Docker/profile-matrix stages.
- Note: if `latest_vpn_rc` is empty, run `./scripts/easy_node.sh vpn-rc-resilience-path` first.

`integration_session_churn_guard` (session lifecycle churn guard integration):

```bash
./scripts/integration_session_churn_guard.sh
```

- Purpose: verify default direct-exit churn guard behavior (forced reuse/min-refresh floor) and explicit override path (`CLIENT_DIRECT_EXIT_ALLOW_SESSION_CHURN=1`) in one deterministic run.
- When to run: after edits to client session reuse/refresh logic, direct-exit defaults, or guard env wiring.
- Expected artifacts: `/tmp/integration_session_churn_guard_guarded.log` and `/tmp/integration_session_churn_guard_churn.log`; terminal summary line with guarded/churn selection and reuse counts.
- Exit meaning: `0` when guard and override assertions both hold; non-zero on mismatch/failure (`2` for missing required commands).

### Phase 2 targeted gates (Linux production candidate)

Status:
- `ci_phase2_linux_prod_candidate.sh` is the focused Phase-2 gate runner, with signoff and roadmap handoff integration checks included in the expanded gate set.
- `integration_ci_phase2_linux_prod_candidate.sh` validates the Phase-2 gate contract.
- `phase2_linux_prod_candidate_check.sh` validates the Phase-2 handoff/check artifact contract.
- `phase2_linux_prod_candidate_run.sh` runs the Phase-2 gate + handoff check in one command.
- `integration_phase2_linux_prod_candidate_check.sh` validates checker behavior/contract.
- `integration_phase2_linux_prod_candidate_run.sh` validates wrapper behavior/contract.
- `phase2_linux_prod_candidate_handoff_check.sh` validates the Phase-2 handoff/check artifact contract.
- `phase2_linux_prod_candidate_handoff_run.sh` runs the Phase-2 handoff check in one command; use `--resume 1 --reports-dir <same-run-dir>` to reuse passing signoff/handoff summaries on retry.
- `integration_phase2_linux_prod_candidate_handoff_check.sh` validates checker behavior/contract.
- `integration_phase2_linux_prod_candidate_handoff_run.sh` validates wrapper behavior/contract.
- `integration_phase2_linux_prod_candidate_signoff.sh` validates the Phase-2 signoff wrapper contract.
- `integration_roadmap_progress_phase2_handoff.sh` validates roadmap progress ingestion of the Phase-2 handoff.

Usage:

```bash
./scripts/ci_phase2_linux_prod_candidate.sh
./scripts/integration_ci_phase2_linux_prod_candidate.sh
./scripts/phase2_linux_prod_candidate_check.sh
./scripts/phase2_linux_prod_candidate_run.sh
./scripts/integration_phase2_linux_prod_candidate_check.sh
./scripts/integration_phase2_linux_prod_candidate_run.sh
./scripts/phase2_linux_prod_candidate_handoff_check.sh
./scripts/phase2_linux_prod_candidate_handoff_run.sh
./scripts/integration_phase2_linux_prod_candidate_handoff_check.sh
./scripts/integration_phase2_linux_prod_candidate_handoff_run.sh
./scripts/integration_phase2_linux_prod_candidate_signoff.sh
./scripts/integration_roadmap_progress_phase2_handoff.sh
```

`phase2_linux_prod_candidate_handoff` (Phase-2 handoff check/run wrapper):

```bash
./scripts/easy_node.sh phase2-linux-prod-candidate-handoff-check
./scripts/easy_node.sh phase2-linux-prod-candidate-handoff-run
```

- Purpose: run the Phase-2 Linux production-candidate handoff check or run wrapper and verify the matching contract in one place.
- When to run: after changing Phase-2 handoff wiring, wrapper behavior, or operator-facing `easy_node.sh` command forwarding.
- Expected artifacts: wrapper summary/log artifacts under the run directory.
- Exit meaning: `0` when the wrapper and integration check pass; non-zero on any contract or run failure.

`phase2_linux_prod_candidate_signoff` (Phase-2 signoff wrapper):

```bash
./scripts/easy_node.sh phase2-linux-prod-candidate-signoff
./scripts/integration_phase2_linux_prod_candidate_signoff.sh
```

- Purpose: run the Phase-2 Linux production-candidate signoff wrapper and check its contract in one place.
- When to run: after changing Phase-2 wrapper wiring or signoff handoff behavior.
- Expected artifacts: wrapper summary/log artifacts under the run directory.
- Exit meaning: `0` when the wrapper and integration check pass; non-zero on any contract or run failure.

### Phase 3 targeted gates (Windows client beta)

Status:
- `ci_phase3_windows_client_beta.sh` is the focused Phase-3 gate runner for desktop/control API/config and launcher contract checks.
- `integration_ci_phase3_windows_client_beta.sh` validates the Phase-3 gate contract.
- `phase3_windows_client_beta_check.sh` validates the Phase-3 readiness/check artifact contract.
  - Includes the Windows-native bootstrap guardrails required-default policy/signal gate: `require_windows_native_bootstrap_guardrails_ok` must align with `windows_native_bootstrap_guardrails_ok` on stage `windows_native_bootstrap_guardrails`.
- `phase3_windows_client_beta_run.sh` runs the Phase-3 gate + check in one command.
- `integration_windows_desktop_native_bootstrap_guardrails.sh` validates Windows-native bootstrap dry-run modes, invalid-mode failure behavior, summary-json write, and print-summary-json output contract.
- `integration_phase3_windows_client_beta_check.sh` validates checker behavior/contract.
- `integration_phase3_windows_client_beta_run.sh` validates wrapper behavior/contract.
- `phase3_windows_client_beta_handoff_check.sh` validates the Phase-3 handoff/check artifact contract.
- `phase3_windows_client_beta_handoff_run.sh` runs the Phase-3 handoff check in one command; use `--resume 1 --reports-dir <same-run-dir>` to reuse passing run/handoff summaries on retry.
- `integration_phase3_windows_client_beta_handoff_check.sh` validates handoff checker behavior/contract.
- `integration_phase3_windows_client_beta_handoff_run.sh` validates handoff wrapper behavior/contract.
- `integration_roadmap_progress_phase3_handoff.sh` validates roadmap progress ingestion of the Phase-3 handoff.

Usage:

```bash
./scripts/ci_phase3_windows_client_beta.sh
./scripts/integration_ci_phase3_windows_client_beta.sh
./scripts/integration_windows_desktop_native_bootstrap_guardrails.sh
./scripts/phase3_windows_client_beta_check.sh
./scripts/phase3_windows_client_beta_run.sh
./scripts/integration_phase3_windows_client_beta_check.sh
./scripts/integration_phase3_windows_client_beta_run.sh
./scripts/phase3_windows_client_beta_handoff_check.sh
./scripts/phase3_windows_client_beta_handoff_run.sh
./scripts/integration_phase3_windows_client_beta_handoff_check.sh
./scripts/integration_phase3_windows_client_beta_handoff_run.sh
./scripts/integration_roadmap_progress_phase3_handoff.sh
./scripts/easy_node.sh ci-phase3-windows-client-beta
./scripts/easy_node.sh phase3-windows-client-beta-check
./scripts/easy_node.sh phase3-windows-client-beta-run
./scripts/easy_node.sh phase3-windows-client-beta-handoff-check
./scripts/easy_node.sh phase3-windows-client-beta-handoff-run
```

### Phase 4 targeted gates (Windows full parity)

Status:
- `ci_phase4_windows_full_parity.sh` is the focused Phase-4 gate runner for cross-platform Windows full-parity contract checks.
- `integration_ci_phase4_windows_full_parity.sh` validates the Phase-4 gate contract.
- `phase4_windows_full_parity_check.sh` validates the Phase-4 readiness/check artifact contract.
- `phase4_windows_full_parity_run.sh` runs the Phase-4 gate + check in one command.
- `integration_phase4_windows_full_parity_check.sh` validates checker behavior/contract.
- `integration_phase4_windows_full_parity_run.sh` validates wrapper behavior/contract.
- `phase4_windows_full_parity_handoff_check.sh` validates the Phase-4 handoff/check artifact contract.
- `phase4_windows_full_parity_handoff_run.sh` runs the Phase-4 handoff check in one command; use `--resume 1 --reports-dir <same-run-dir>` to reuse passing run/handoff summaries on retry.
- `integration_phase4_windows_full_parity_handoff_check.sh` validates handoff checker behavior/contract.
- `integration_phase4_windows_full_parity_handoff_run.sh` validates handoff wrapper behavior/contract.
- `integration_roadmap_progress_phase4_handoff.sh` validates roadmap progress ingestion of the Phase-4 handoff, including the explicit `windows_native_bootstrap_guardrails_ok_source` label when present and the stage-based compatibility fallback when the newer direct signal is absent.
- Phase-4 wrapper integration also exercises the bootstrap-guardrail passthrough knobs used by the phase-3-style desktop bootstrap flow:
  - `--check-require-windows-native-bootstrap-guardrails-ok`
  - `--handoff-require-windows-native-bootstrap-guardrails-ok`

Usage:

```bash
./scripts/ci_phase4_windows_full_parity.sh
./scripts/integration_ci_phase4_windows_full_parity.sh
./scripts/phase4_windows_full_parity_check.sh
./scripts/phase4_windows_full_parity_run.sh
./scripts/integration_phase4_windows_full_parity_check.sh
./scripts/integration_phase4_windows_full_parity_run.sh
./scripts/phase4_windows_full_parity_handoff_check.sh
./scripts/phase4_windows_full_parity_handoff_run.sh
./scripts/integration_phase4_windows_full_parity_handoff_check.sh
./scripts/integration_phase4_windows_full_parity_handoff_run.sh
./scripts/integration_roadmap_progress_phase4_handoff.sh
./scripts/easy_node.sh ci-phase4-windows-full-parity
./scripts/easy_node.sh phase4-windows-full-parity-check
./scripts/easy_node.sh phase4-windows-full-parity-run
./scripts/easy_node.sh phase4-windows-full-parity-handoff-check
./scripts/easy_node.sh phase4-windows-full-parity-handoff-run
```

### Phase 5 targeted gates (Settlement layer)

Status:
- `ci_phase5_settlement_layer.sh` is the focused Phase-5 gate runner for settlement-layer readiness and contract checks.
- `integration_ci_phase5_settlement_layer.sh` validates the Phase-5 gate contract.
- canonical Phase-5 CI settlement blockchain stages include `settlement_adapter_roundtrip`, `settlement_adapter_signed_tx_roundtrip`, `settlement_shadow_env`, `settlement_shadow_status_surface`, `settlement_dual_asset_parity`, and `issuer_sponsor_api_live_smoke` (wired to `scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh`, `scripts/integration_cosmos_adapter_tdpnd_signed_tx_roundtrip.sh`, `scripts/integration_cosmos_settlement_shadow_env.sh`, `scripts/integration_cosmos_settlement_shadow_status_surface.sh`, `scripts/integration_cosmos_settlement_dual_asset_parity.sh`, and `scripts/integration_issuer_sponsor_api_live_smoke.sh`).
- canonical Phase-5 CI settlement blockchain stages also include `issuer_admin_blockchain_handlers_coverage` wired to `scripts/integration_issuer_admin_blockchain_handlers_coverage_floor.sh`, validating issuer admin blockchain handler coverage floor for `upsert/promote/reputation/bond/recompute/get-subject/anon issue+revoke/audit/revoke-token`.
- canonical Phase-6 Cosmos L1 contracts posture includes `cosmos_module_coverage_floor`, `cosmos_keeper_coverage_floor`, and `cosmos_app_coverage_floor` (wired to `scripts/integration_cosmos_module_coverage_floor.sh`, `scripts/integration_cosmos_keeper_coverage_floor.sh`, and `scripts/integration_cosmos_app_coverage_floor.sh`) before wrapper handoff/run stages.
- `phase5_settlement_layer_check.sh` validates the Phase-5 readiness/check artifact contract.
- `phase5_settlement_layer_run.sh` runs the Phase-5 gate + check in one command.
- `integration_phase5_settlement_layer_check.sh` validates checker behavior/contract.
- `integration_phase5_settlement_layer_run.sh` validates wrapper behavior/contract.
- `phase5_settlement_layer_handoff_check.sh` validates the Phase-5 handoff/check artifact contract.
- `phase5_settlement_layer_handoff_run.sh` runs the Phase-5 handoff check in one command.
- `integration_phase5_settlement_layer_handoff_check.sh` validates handoff checker behavior/contract.
- `integration_phase5_settlement_layer_handoff_run.sh` validates handoff wrapper behavior/contract.
- `integration_roadmap_progress_phase5_handoff.sh` validates roadmap progress ingestion of the Phase-5 handoff.
- `./scripts/easy_node.sh vpn-non-blockchain-fastlane --print-summary-json 1` is a non-blockchain acceleration wrapper (runtime + Phase-1..4 handoff + roadmap path) and explicitly excludes blockchain/Phase-5 settlement checks; Phase-1/2/3/4 handoff-run stages default to `--resume 1` unless explicitly overridden.

Usage:

```bash
./scripts/ci_phase5_settlement_layer.sh
./scripts/integration_ci_phase5_settlement_layer.sh
./scripts/phase5_settlement_layer_check.sh
./scripts/phase5_settlement_layer_run.sh
./scripts/integration_phase5_settlement_layer_check.sh
./scripts/integration_phase5_settlement_layer_run.sh
./scripts/phase5_settlement_layer_handoff_check.sh
./scripts/phase5_settlement_layer_handoff_run.sh
./scripts/integration_phase5_settlement_layer_handoff_check.sh
./scripts/integration_phase5_settlement_layer_handoff_run.sh
./scripts/integration_roadmap_progress_phase5_handoff.sh
./scripts/easy_node.sh ci-phase5-settlement-layer
./scripts/easy_node.sh phase5-settlement-layer-check
./scripts/easy_node.sh phase5-settlement-layer-run
./scripts/easy_node.sh phase5-settlement-layer-handoff-check
./scripts/easy_node.sh phase5-settlement-layer-handoff-run
```

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
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --min-sources 2 \
  --min-operators 2 \
  --path-profile balanced
```

Single-host docker 3-machine rehearsal (A/B stacks + machine-C style runner):

```bash
./scripts/easy_node.sh three-machine-docker-readiness \
  --path-profile balanced \
  --soak-rounds 6 \
  --soak-pause-sec 3 \
  --print-summary-json 1
```

Three-machine docker profile matrix rehearsal (phase-1 resilience matrix path):

```bash
./scripts/easy_node.sh three-machine-docker-profile-matrix \
  --profiles 1hop,2hop,3hop \
  --rounds 3 \
  --print-summary-json 1
```

Three-machine docker profile matrix recorded rehearsal (phase-1 resilience receipt path):

```bash
./scripts/easy_node.sh three-machine-docker-profile-matrix-record \
  --profiles 1hop,2hop,3hop \
  --rounds 3 \
  --print-summary-json 1
```

3-hop runtime integration (local deterministic, no docker):

```bash
./scripts/integration_client_3hop_runtime.sh
```

Notes:
- This runs the machine-C control-plane validate/soak flow against two local
  dockerized operator stacks (`A` + `B`) for fast iteration.
- It is not a replacement for final true multi-host production signoff.
- In `three-machine-docker-profile-matrix`, `1hop` is auto-run with `--beta-profile 0 --prod-profile 0`; strict/beta/prod client-test paths intentionally reject `1hop`.
- `single-machine-prod-readiness` and `vpn-rc-standard-path` now run this docker rehearsal with peer failover enabled by default.
- Diagnostic override knobs: `single-machine-prod-readiness --three-machine-docker-readiness-run-peer-failover 0` or low-level `three-machine-docker-readiness --run-peer-failover 0`.
- Docker profile matrix wrapper is now exposed in launcher advanced option 77 and maps to `profile-compare-campaign-signoff --campaign-execution-mode docker --campaign-start-local-stack 0`.
- Coverage status for that wrapper: docker campaign-signoff contract is exercised by `integration_profile_compare_campaign_signoff.sh`, and launcher signoff forwarding remains guarded by `integration_easy_mode_launcher_wiring.sh` plus `integration_easy_mode_launcher_runtime.sh`.
- `easy_node.sh profile-compare-docker-matrix` now provides a direct docker-first campaign wrapper for `1hop/2hop/3hop`, with pass-through overrides and deterministic summary/report artifact output.
- dispatch/forwarding contract for `profile-compare-docker-matrix` is exercised by `integration_profile_compare_docker_matrix.sh` (now in both `ci_local.sh` and `beta_preflight.sh`).
- one-command RC matrix chain path is now exposed as `easy_node.sh vpn-rc-matrix-path` for refresh/check handoff in one run.
- contract coverage for `vpn-rc-matrix-path` is exercised by `integration_vpn_rc_matrix_path.sh` in both `ci_local.sh` and `beta_preflight.sh`.
- one-command RC resilience chain path is now exposed as `easy_node.sh vpn-rc-resilience-path` for phase-1 resilience handoff in one run.
- contract coverage for `vpn-rc-resilience-path` is exercised by `integration_vpn_rc_resilience_path.sh` in both `ci_local.sh` and `beta_preflight.sh`.
- three-machine docker profile matrix flow (`easy_node.sh three-machine-docker-profile-matrix`) is now guarded in both local gates by `integration_three_machine_docker_profile_matrix.sh`.
- three-machine docker profile matrix record flow (`easy_node.sh three-machine-docker-profile-matrix-record`) is now guarded in both local gates by `integration_three_machine_docker_profile_matrix_record.sh`.

Phase-1 RC resilience path example:

```bash
./scripts/easy_node.sh vpn-rc-resilience-path
```

Path profile presets for client routing tests:

- Speed: `--distinct-operators 1 --distinct-countries 0 --locality-soft-bias 1 --country-bias 1.80 --region-bias 1.35 --region-prefix-bias 1.15`
- Balanced: `--distinct-operators 1 --distinct-countries 0 --locality-soft-bias 1 --country-bias 1.50 --region-bias 1.25 --region-prefix-bias 1.10`
- Private: `--distinct-operators 1 --distinct-countries 1 --locality-soft-bias 0`
- Shortcut: use `--path-profile 1hop|2hop|3hop` (compatibility aliases `speed|balanced|private`, legacy `fast|privacy` still work) on validate/soak/runbook wrappers; explicit flags still override preset values.
- Experimental 1-hop benchmark mode (non-strict only): `--path-profile 1hop` (or `speed-1hop`) enables direct-exit mode in `client-test` and `client-vpn-up` when `--beta-profile 0 --prod-profile 0`, and is intentionally blocked in strict/prod flows.
- Session churn guard env: `CLIENT_SESSION_MIN_REFRESH_SEC` sets a minimum refresh interval to avoid rapid session reopen/close loops during unstable control-plane periods.
- Direct-exit default behavior: with churn protection on, `1hop` uses that minimum refresh guard by default; diagnostics override with `CLIENT_SESSION_MIN_REFRESH_SEC=0` or `CLIENT_DIRECT_EXIT_ALLOW_SESSION_CHURN=1` when churn reproduction is intentional.
- Local control API profile operations stay on the same config-v1 contract (`/v1/set_profile` -> `config-v1-set-profile`); start daemon roles with `--config deploy/config/easy_mode_config_v1.conf` to keep runtime profile defaults aligned with launcher defaults.
- Config-v1 also supports optional auto-update defaults for simple flows (`SIMPLE_AUTO_UPDATE`, `SIMPLE_AUTO_UPDATE_REMOTE`, `SIMPLE_AUTO_UPDATE_BRANCH`, `SIMPLE_AUTO_UPDATE_ALLOW_DIRTY`, `SIMPLE_AUTO_UPDATE_SHOW_STATUS`, `SIMPLE_AUTO_UPDATE_COMMANDS`), and `easy_node.sh` now applies those values before command dispatch unless explicit `EASY_NODE_AUTO_UPDATE*` env overrides are already set.
- New coverage this round: `integration_easy_node_config_v1.sh` now gates `config-v1-init/show/set-profile` behavior plus required server federation and auto-update default keys, and `integration_easy_node_self_update.sh` now includes a config-v1-driven auto-update reexec contract check (both run in `ci_local.sh` and `beta_preflight.sh`).
- Planned future track: optional micro-relay-based 3-hop mode is tracked in `docs/global-privacy-mesh-track.md` and is not part of the current production validation baseline yet.

Single-machine profile comparison (decision support for default profile):

```bash
./scripts/easy_node.sh profile-compare-local \
  --profiles balanced,speed,private,speed-1hop \
  --rounds 3 \
  --start-local-stack auto \
  --summary-json .easy-node-logs/profile_compare_local.json \
  --report-md .easy-node-logs/profile_compare_local.md \
  --print-summary-json 1
```

Aggregate profile decision trend across multiple local comparison runs:

```bash
./scripts/easy_node.sh profile-compare-trend \
  --reports-dir .easy-node-logs \
  --max-reports 20 \
  --min-profile-runs 3 \
  --min-profile-pass-rate-pct 95 \
  --balanced-latency-margin-pct 15 \
  --summary-json .easy-node-logs/profile_compare_trend.json \
  --report-md .easy-node-logs/profile_compare_trend.md \
  --print-summary-json 1
```

Real VPN profile comparison (host WireGuard mode, route-profile decision support):

```bash
sudo ./scripts/easy_node.sh client-vpn-profile-compare \
  --profiles 1hop,2hop,3hop \
  --rounds 3 \
  --pause-sec 1 \
  --min-pass-rate-pct 95 \
  --directory-urls https://A_HOST:8081,https://B_HOST:8081 \
  --issuer-url https://A_HOST:8082 \
  --entry-url https://A_HOST:8083 \
  --exit-url https://A_HOST:8084 \
  --subject INVITE_KEY \
  --interface wgvpn0 \
  --beta-profile 0 \
  --prod-profile 0 \
  --public-ip-url https://api.ipify.org \
  --country-url https://ipinfo.io/country \
  --summary-json .easy-node-logs/client_vpn_profile_compare.json \
  --report-md .easy-node-logs/client_vpn_profile_compare.md \
  --print-summary-json 1
```

Notes:
- `1hop` is experimental and non-default by policy; strict/prod runs skip or fail-close for `1hop` as designed.
- This runner forces smoke runs to be non-recording (`--record-result 0 --manual-validation-report 0`) so benchmark loops do not overwrite manual-validation state.

Run a repeatable campaign (multiple local comparisons + auto trend aggregation):

```bash
./scripts/easy_node.sh profile-compare-campaign \
  --campaign-runs 5 \
  --campaign-pause-sec 1 \
  --profiles balanced,speed,private,speed-1hop \
  --rounds 3 \
  --start-local-stack auto \
  --trend-min-profile-runs 3 \
  --trend-min-profile-pass-rate-pct 95 \
  --trend-balanced-latency-margin-pct 15 \
  --summary-json .easy-node-logs/profile_compare_campaign_summary.json \
  --report-md .easy-node-logs/profile_compare_campaign_report.md \
  --print-summary-json 1
```

Fail-closed campaign decision gate (GO/NO-GO for default-profile readiness):

```bash
./scripts/easy_node.sh profile-compare-campaign-check \
  --campaign-summary-json .easy-node-logs/profile_compare_campaign_summary.json \
  --require-min-runs-total 5 \
  --require-max-runs-fail 0 \
  --require-max-runs-warn 0 \
  --require-recommendation-support-rate-pct 70 \
  --allow-recommended-profiles balanced,speed,private \
  --disallow-experimental-default 1 \
  --show-json 1
```

One-command campaign signoff (optional refresh + fail-closed check artifact):

```bash
./scripts/easy_node.sh profile-compare-campaign-signoff \
  --reports-dir .easy-node-logs \
  --refresh-campaign 1 \
  --fail-on-no-go 1 \
  --require-min-runs-total 5 \
  --allow-recommended-profiles balanced,speed,private \
  --disallow-experimental-default 1 \
  --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json \
  --print-summary-json 1
```

No-sudo deterministic fallback (when docker rehearsal endpoints are known):

```bash
./scripts/easy_node.sh profile-compare-campaign-signoff \
  --reports-dir .easy-node-logs \
  --refresh-campaign 1 \
  --fail-on-no-go 0 \
  --campaign-execution-mode docker \
  --campaign-start-local-stack 0 \
  --campaign-directory-urls http://127.0.0.1:18081,http://127.0.0.1:28081 \
  --campaign-issuer-url http://127.0.0.1:18082 \
  --campaign-entry-url http://127.0.0.1:18083 \
  --campaign-exit-url http://127.0.0.1:18084 \
  --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json \
  --print-summary-json 1
```

`manual-validation-status`, `manual-validation-report`, and `roadmap-progress-report` now surface this as the profile-default gate primary command when derivable, and also print an explicit `sudo` fallback command.

Endpoint posture auto-remediation (report/apply wrappers for common gate misconfig classes):

```bash
# report-only (default): emits findings + remediation commands
./scripts/easy_node.sh gpm-endpoint-posture-remediate \
  --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json \
  --signoff-arg --subject \
  --signoff-arg <INVITE_KEY> \
  --signoff-arg --campaign-timeout-sec \
  --signoff-arg 300

# apply mode: idempotent env upserts + executable remediation script output
./scripts/easy_node.sh gpm-endpoint-posture-remediate \
  --mode apply \
  --env-file deploy/.env.easy.client \
  --set-a-host <A_HOST> \
  --set-b-host <B_HOST> \
  --set-campaign-subject <INVITE_KEY> \
  --remediation-script .easy-node-logs/gpm_endpoint_posture_remediation.sh
```

This helper focuses on deterministic fixes/hints for missing live-run env wiring (`A_HOST`/`B_HOST`/invite subject), deprecated subject aliases (`--subject|--key|--invite-key`), low campaign timeout posture, and stale/missing campaign signoff summary artifacts.

Real client VPN smoke test (machine C / tester host, Linux root):

```bash
sudo ./scripts/easy_node.sh client-vpn-preflight \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081

sudo ./scripts/easy_node.sh client-vpn-up \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
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
```

No-sudo local automation (explicit defer mode, default strict behavior unchanged):

```bash
./scripts/easy_node.sh wg-only-stack-selftest-record \
  --defer-no-root 1 \
  --strict-beta 1 \
  --print-summary-json 1

./scripts/easy_node.sh client-vpn-smoke \
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
  --subject <INVITE_KEY> \
  --runtime-fix 1 \
  --defer-no-root 1 \
  --print-summary-json 1
```

- When `--defer-no-root 1` is used on a non-root host, root-required failures are recorded as `skip` with explicit notes, so no-sudo automation can continue without pretending the check passed.
- Default behavior remains strict/fail-closed when `--defer-no-root` is not enabled.

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
  --bootstrap-directory https://A_PUBLIC_IP_OR_DNS:8081 \
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
- simple launcher server mode (main menu `2`) now starts `server-session` with federation wait on by default (`SIMPLE_SERVER_FEDERATION_WAIT=1`, `--federation-wait 1`).
- diagnostics override: set `SIMPLE_SERVER_FEDERATION_WAIT=0` in config, or run expert startup with `server-session --federation-wait 0`.
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
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084 \
  --rounds 12 \
  --pause-sec 5 \
  --path-profile balanced

# one-bootstrap mode (auto-discovery)
./scripts/integration_machine_c_client_check.sh \
  --bootstrap-directory https://KNOWN_SERVER_IP:8081 \
  --discovery-wait-sec 20 \
  --path-profile balanced
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
# trend summary JSON now also carries latest failed incident handoff paths plus
# the upstream pre_real_host_readiness_summary_json pointer when available
./scripts/easy_node.sh prod-pilot-cohort-quick-trend \
  --reports-dir .easy-node-logs \
  --since-hours 24 \
  --summary-json .easy-node-logs/prod_pilot_quick_trend_24h.json

# quick-mode alert severity from trend metrics
# alert JSON/output now also preserves that same readiness pointer when present
./scripts/easy_node.sh prod-pilot-cohort-quick-alert \
  --trend-summary-json .easy-node-logs/prod_pilot_quick_trend_24h.json \
  --summary-json .easy-node-logs/prod_pilot_quick_alert_24h.json

# quick-mode dashboard artifact (trend + alert + markdown)
# dashboard markdown now also renders incident handoff paths plus the same
# readiness pointer when present
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
./scripts/easy_node.sh machine-b-test --peer-directory-a https://A_PUBLIC_IP_OR_DNS:8081 --public-host B_PUBLIC_IP_OR_DNS

# machine C
./scripts/easy_node.sh machine-c-test \
  --directory-a https://A_PUBLIC_IP_OR_DNS:8081 \
  --directory-b https://B_PUBLIC_IP_OR_DNS:8081 \
  --issuer-url https://A_PUBLIC_IP_OR_DNS:8082 \
  --entry-url https://A_PUBLIC_IP_OR_DNS:8083 \
  --exit-url https://A_PUBLIC_IP_OR_DNS:8084
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
