# GPM Productization Status Tracker

Last updated: 2026-04-21

Scope:
- Global Privacy Mesh track only.
- Status labels below are based on repository evidence, not intent.

Compatibility note:
- TDPN path aliases are retained.
- Public route/profile naming stays `1hop|2hop|3hop`, with compatibility aliases `speed|balanced|private` and legacy `fast|privacy`; `speed-1hop` remains the explicit experimental alias.

## Completed

- M0 planning and safety baseline is in repo: `docs/global-privacy-mesh-track.md`, `docs/client-safety-guide.md`, `docs/exit-node-safety-baseline-v1.md`, and `docs/exit-node-safety-guide.md`. Acceptance criterion: the role model, safety posture, and non-goals are documented for operators and clients.
- Public path-profile contract and alias retention are implemented across scripts: `scripts/easy_node.sh`, `scripts/beta_pilot_runbook.sh`, `scripts/client_vpn_smoke.sh`, `scripts/client_vpn_profile_compare.sh`, `scripts/profile_compare_local.sh`, `scripts/profile_compare_trend.sh`, `scripts/profile_compare_campaign.sh`, `scripts/profile_compare_docker_matrix.sh`, and `scripts/three_machine_docker_profile_matrix.sh`. Acceptance criterion: profile input normalizes consistently and `1hop` never silently becomes the default.
- Validation and decision-support harnesses exist for profile comparison: `scripts/profile_compare_local.sh`, `scripts/profile_compare_trend.sh`, `scripts/profile_compare_campaign.sh`, `scripts/profile_compare_campaign_check.sh`, `scripts/profile_compare_campaign_signoff.sh`, `scripts/client_vpn_profile_compare.sh`, `scripts/three_machine_docker_profile_matrix.sh`, `scripts/three_machine_docker_profile_matrix_record.sh`, `scripts/three_machine_docker_readiness.sh`, and `scripts/single_machine_prod_readiness.sh`. Acceptance criterion: the repo can emit JSON and markdown summary artifacts for repeated comparisons and readiness checks.
- Local control API and desktop integration scaffolding are present: `docs/local-control-api.md`, `scripts/easy_node.sh` (`local-api-session`), `scripts/windows/local_api_session.ps1`, `scripts/integration_local_api_config_defaults.sh`, `scripts/integration_local_control_api_contract.sh`, and `scripts/integration_desktop_scaffold_contract.sh`. Acceptance criterion: `connect`, `disconnect`, `status`, `set_profile`, `get_diagnostics`, and `update` flow through one shared profile contract.

## In-Progress

- M1 dedicated micro-relay role runtime admission is partially implemented at minimum viable level: provider descriptor role + entry admission are in scope, with post-merge evidence expected in `services/directory/service.go`, `services/directory/provider_api_test.go`, `services/entry/service.go`, and `services/entry/path_open_test.go`. Acceptance criterion: micro-relay nodes can be advertised and admitted through entry path-open flows without changing exit or validator behavior. Remaining work: scheduler/path-selection adoption, operator/runtime controls, and end-to-end validation artifacts.
- M2 selection-policy artifact evidence is partially implemented: `scripts/profile_compare_local.sh` now emits `.summary.selection_policy` with `sticky_pair_sec`, `entry_rotation_sec`, `entry_rotation_jitter_pct`, `exit_exploration_pct`, and `path_profile` from effective client runtime knobs/logs. Acceptance criterion: profile-compare summary artifacts expose machine-readable policy evidence without manual log scraping. Remaining work: propagate the same evidence shape into trend/campaign reducers and wire policy-aware signoff checks.
- M3 route-policy and 3-hop validation are partially wired: `scripts/integration_client_3hop_runtime.sh`, `scripts/ci_phase1_resilience.sh`, `scripts/ci_local.sh`, `scripts/beta_preflight.sh`, `scripts/three_machine_docker_profile_matrix.sh`, and `scripts/three_machine_docker_readiness.sh` exercise 3-hop and resilience paths, but the repo still describes true multi-host production signoff as pending in `docs/testing-guide.md`. Acceptance criterion: 3-hop can be validated repeatedly with deterministic artifacts in real-host conditions, not just local or docker rehearsal.
- Default-profile evidence gathering is in place but still under decision support rather than promotion: `scripts/profile_compare_local.sh`, `scripts/profile_compare_trend.sh`, `scripts/profile_compare_campaign.sh`, and `scripts/profile_compare_campaign_check.sh` can recommend `balanced`, but the docs still frame the result as comparative support rather than a finalized architecture shift. Acceptance criterion: repeated campaigns converge on a documented default decision with no manual interpretation.

## Missing / Next

- M2 bounded stickiness, jitter, and rotation enforcement are still design targets in `docs/global-privacy-mesh-track.md` even though summary artifact evidence now exists in `scripts/profile_compare_local.sh` (`.summary.selection_policy`). Acceptance criterion: path selection can enforce explicit rotation windows without destabilizing sessions or leaking deterministic patterns. Next slice: implement runtime policy controls in client/router selection and add pass/fail gates that evaluate the emitted policy evidence.
- M4 micro-relay quality scoring, adaptive demotion/promotion, and trust-tiered port unlocks are still described only in `docs/global-privacy-mesh-track.md`. Acceptance criterion: relay health and abuse signals can change role eligibility automatically. Next slice: add scoring inputs and demotion outputs to the existing compare/report harnesses.
- M5 external validation at multi-VM scale is still missing as a dedicated track artifact; current automation is local, docker, or one-host multi-machine (`scripts/three_machine_docker_*`, `scripts/profile_compare_*`). Acceptance criterion: repeatable multi-VM runs compare latency, reliability, and privacy across `1hop`, `2hop`, and `3hop` with stable artifact output. Next slice: add a multi-VM sweep wrapper and a reducer that reuses the existing campaign JSON schema.
