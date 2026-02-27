# MVP Status Snapshot

## Completed
- Unified single-binary runtime with multi-role support (`client`, `entry`, `exit`, `directory`, `issuer`, `wgio`, `wgiotap`, `wgioinject`).
- Control plane: relay directory, token issuer, path open/close.
- Two-hop session forwarding (`client -> entry -> exit`) with split trust semantics.
- Opaque-mode bidirectional forwarding scaffold (`client -> entry -> exit -> entry -> client`) for WG-like tunnel traffic simulation.
- Directory-driven relay control routing using signed descriptors (`control_url` + `endpoint`) for selected entry/exit.
- Health-aware client relay selection (control-plane probes + same-region preference + deterministic fallback).
- Client path-open failover across ranked relay pairs (bounded retry attempts).
- Client-configurable exit locality preference (country-first with region fallback).
- Descriptor operator metadata + optional client per-operator exit cap for anti-concentration.
- Optional client pair hardening to require distinct entry/exit operators (anti-collusion guardrail).
- Optional client sticky pair continuity window (`CLIENT_STICKY_PAIR_SEC`) to prefer the last successful entry/exit pair when still eligible.
- Optional client active-session reuse (`CLIENT_SESSION_REUSE`) with proactive refresh lead (`CLIENT_SESSION_REFRESH_LEAD_SEC`) and seamless open-new/close-old handoff.
- Client bootstrap resilience controls with optional startup delay, exponential retry backoff, and configurable jitter (`CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC`, `CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC`, `CLIENT_BOOTSTRAP_JITTER_PCT`).
- Reputation-weighted exit ordering with exploration floor (when signed score metadata is present).
- Signed directory selection feed endpoint with client-side signature/expiry verification and optional feed vote thresholding.
- Signed directory trust-attestation feed (`/v1/trust-attestations`) with bond/stake signals and client-side signature/expiry verification.
- Entry-side cryptographic route discovery: directory pubkey fetch + descriptor signature verification + configurable source quorum/vote thresholds.
- Tier policy enforcement in JSON mode (Tier-1 SMTP/25 deny).
- Session hardening: short expiry + nonce replay rejection.
- Opaque mode for WireGuard-ready forwarding (`wireguard-udp` transport contract).
- WG session metadata exchange (`exit_inner_pub`, IPs, MTU, keepalive, session key id).
- Pluggable WG backends on both client/exit (`noop` + `command`).
- Command WG configuration hardening: explicit client/exit interface-up and optional client route installation for configured allowed IPs.
- Client/exit command backends auto-derive WireGuard public keys from configured private keys when `CLIENT_WG_PUBLIC_KEY` / `EXIT_WG_PUBKEY` are unset/invalid, with fail-fast mismatch detection against configured keys.
- Command-backend runtime preflight (`wg`/`ip`, interface, key path) and strict no-synthetic fallback in command/live modes.
- Linux root-only real WG privileged integration script now validates actual interface peer wiring (`wg show` peers/endpoints/listen-port) in addition to packet-path metrics/log checks.
- Linux root-only real WG profile-matrix wrapper (`integration_real_wg_privileged_matrix.sh`) exercises privileged validation across multiple interface/port/startup profiles.
- Client command-mode optional per-session WG kernel proxy bridge (`CLIENT_WG_KERNEL_PROXY`, `CLIENT_WG_PROXY_ADDR`) for local WG UDP endpoint integration.
- Exit command-mode port/bridge hardening: explicit `EXIT_WG_LISTEN_PORT` separation from `EXIT_DATA_ADDR` plus optional per-session WG kernel proxy bridging (`EXIT_WG_KERNEL_PROXY`).
- Exit WG kernel-proxy safeguards: configurable per-node proxy session cap + idle proxy reaping (`EXIT_WG_KERNEL_PROXY_MAX_SESSIONS`, `EXIT_WG_KERNEL_PROXY_IDLE_SEC`) with lifecycle counters in `/v1/metrics`.
- Exit session/proxy cleanup cadence control (`EXIT_SESSION_CLEANUP_SEC`) for deterministic idle-reap behavior and testability.
- Client optional UDP-only opaque uplink enforcement (`CLIENT_DISABLE_SYNTHETIC_FALLBACK`) for real packet-origin traffic in non-command scaffolds.
- Live-WG guardrails: required downlink/uplink sink wiring in live mode and non-WireGuard payload drop on exit live path.
- Live-WG downlink source hardening: raw downlink source packets must be session-framed in live mode.
- Live-WG packet plausibility hardening: live mode requires valid WireGuard framing plus type-aware minimum packet lengths on client/exit paths.
- Live-WG uplink hardening: client drops non-plausible WireGuard payloads at ingress before entry forwarding in live mode.
- Live-WG strict full-path integration coverage: non-root command-backend test validates client+entry+exit live-mode behavior (`integration_live_wg_full_path.sh`) while preserving plausible WG-like end-to-end forwarding.
- Optional entry live-WG forwarding hardening (`ENTRY_LIVE_WG_MODE`): entry drops malformed/non-plausible opaque payloads for `wireguard-udp` sessions before forwarding.
- Exit session source-lock hardening on data plane (drop mismatched peer source by default, optional delayed rebind).
- Client persistent opaque-session bridging mode (`CLIENT_OPAQUE_SESSION_SEC`) with initial uplink readiness gating for command/live-style operation.
- Exit opaque downlink source ingestion (`EXIT_OPAQUE_SOURCE_ADDR`) with session-bound return forwarding and metrics.
- Internal test topology tools: UDP bridge, tap observer, and injector.
- Entry open-path anti-abuse controls (per-IP RPS + optional puzzle challenge).
- Entry session source-lock hardening on data plane (drop mismatched client source by default, optional delayed rebind).
- Adaptive puzzle difficulty and rotating directory entry endpoint descriptors.
- Advanced entry anti-DDoS controls: temporary source bans and concurrent path-open shielding.
- Issuer trust lifecycle admin APIs (subject profile upsert/get/promote + effective tiering).
- Issuer configurable token lifetime (`ISSUER_TOKEN_TTL_SEC`) for short-lived path/session tuning.
- Issuer dispute lifecycle admin APIs (apply/clear temporary tier caps with audit trail).
- Issuer appeal lifecycle admin APIs (open/resolve appeal windows with temporary dispute-pressure relaxation).
- Issuer adjudication metadata lifecycle (`case_id` / `evidence_ref`) for dispute/appeal workflows and trust-feed signaling.
- Token subject hardening: `sub` claim issuance, client-vs-relay subject typing, and relay/unknown subject Tier-1 token pinning.
- Token class hardening: split `client_access` vs `provider_role` capability tokens plus PoP-bound path-open proofs (`token_proof` verified against token `cnf_ed25519`).
- Optional PoP replay guard on exit (`EXIT_TOKEN_PROOF_REPLAY_GUARD=1`): one-time `token_proof_nonce` enforcement per token lifetime.
- Provider-role directory API: token-gated provider relay advertisement (`/v1/provider/relay/upsert`) with issuer pubkey verification and bounded relay TTL.
- Provider relay role-tier policy controls (`DIRECTORY_PROVIDER_MIN_ENTRY_TIER`, `DIRECTORY_PROVIDER_MIN_EXIT_TIER`) to gate advertised entry/exit roles by provider token tier.
- Provider relay concentration hardening: optional per-operator relay cap for provider upserts (`DIRECTORY_PROVIDER_MAX_RELAYS_PER_OPERATOR`).
- Persisted issuer subject profile store on disk.
- Persisted issuer signing key on disk (`ISSUER_PRIVATE_KEY_FILE`).
- Issuer epoch persistence + optional automatic signing-key rotation (`ISSUER_EPOCHS_FILE`, `ISSUER_KEY_ROTATE_SEC`, `ISSUER_KEY_HISTORY`).
- Client-side directory descriptor signature verification with trusted-key pinning/TOFU support.
- Federated directory client fetch with source quorum and relay vote threshold filtering.
- Federated directory operator quorum controls (client/entry) with operator-deduped relay voting.
- Directory federation anti-capture hardening: peer/issuer operator quorum controls (`DIRECTORY_PEER_MIN_OPERATORS`, `DIRECTORY_ISSUER_MIN_OPERATORS`) plus operator-deduped trust/dispute/appeal vote counting.
- Directory peer sync (pull-based) with signature verification, optional peer key pinning/TOFU trust, quorum-style conflict resolution (`DIRECTORY_PEER_MIN_VOTES`), and local re-signing for published descriptors.
- Directory peer sync anti-entropy hardening: ETag incremental pulls, per-peer cache reuse, hop-limited loop resistance (`origin_operator`/`hop_count`), and peer score vote thresholds (`DIRECTORY_PEER_SCORE_MIN_VOTES`).
- Directory admin sync observability endpoint (`/v1/admin/sync-status`) with per-run quorum outcome and distinct-source operator tracking.
- Multi-operator directory churn-scale integration coverage (`integration_directory_operator_churn_scale.sh`) validates quorum drop/recovery under transit and seed churn.
- Directory peer push-gossip relay ingestion (`/v1/gossip/relays`) with signature verification and periodic fanout scheduler (`DIRECTORY_GOSSIP_SEC`, `DIRECTORY_GOSSIP_FANOUT`).
- Signed directory peer-membership feed (`/v1/peers`) with seeded dynamic peer discovery (`DIRECTORY_PEER_DISCOVERY*`).
- Directory peer discovery quorum hardening: discovered peers can require multiple distinct source-operator sightings before sync admission (`DIRECTORY_PEER_DISCOVERY_MIN_VOTES`).
- Directory peer discovery source-flood hardening: optional per-source admission cap limits active discovered-peer votes contributed by one operator (`DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE`).
- Directory peer discovery hint-admission hardening: optional requirement that discovered peers include signed operator + pubkey hints before sync admission (`DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT`).
- Directory discovered-peer health hardening: repeated discovered-peer sync failures trigger cooldown/backoff suppression (`DIRECTORY_PEER_DISCOVERY_FAIL_THRESHOLD`, `DIRECTORY_PEER_DISCOVERY_BACKOFF_SEC`, `DIRECTORY_PEER_DISCOVERY_MAX_BACKOFF_SEC`).
- Directory admin peer membership observability endpoint (`/v1/admin/peer-status`) exposing configured/discovered eligibility, cooldown, and per-peer failure metadata.
- Signed directory peer-hint metadata (`peer_hints`) with discovery-time peer pubkey hint pinning.
- Directory peer sync trust aggregation: signed peer trust-attestation ingestion with vote thresholding (`DIRECTORY_PEER_TRUST_MIN_VOTES`) and operator-deduped voting.
- Directory peer dispute aggregation: vote-thresholded dispute metadata propagation (`DIRECTORY_PEER_DISPUTE_MIN_VOTES`) with operator-deduped voting.
- Directory peer appeal aggregation: independent vote-thresholded appeal metadata propagation (`DIRECTORY_PEER_APPEAL_MIN_VOTES`) with operator-deduped voting.
- Directory issuer trust aggregation: signed issuer trust-attestation ingestion with vote thresholding (`DIRECTORY_ISSUER_TRUST_URLS`, `DIRECTORY_ISSUER_TRUST_MIN_VOTES`) and operator-deduped voting.
- Directory issuer dispute aggregation: vote-thresholded dispute metadata propagation (`DIRECTORY_ISSUER_DISPUTE_MIN_VOTES`) with operator-deduped voting.
- Directory issuer appeal aggregation: independent vote-thresholded appeal metadata propagation (`DIRECTORY_ISSUER_APPEAL_MIN_VOTES`) with operator-deduped voting.
- Outlier-resistant adjudication aggregation: dispute tier caps use consensus voting and dispute/appeal windows use median time selection.
- Adjudication metadata quorum controls: `case_id` / `evidence_ref` publication can be gated independently with `DIRECTORY_ADJUDICATION_META_MIN_VOTES`.
- Adjudication metadata pair-integrity hardening: published `case_id` and `evidence_ref` are selected from the same voted source pair (no cross-source field mixing).
- Final adjudication publication quorum controls: aggregated dispute/appeal signals can require final vote and ratio thresholds (`DIRECTORY_FINAL_DISPUTE_MIN_VOTES`, `DIRECTORY_FINAL_APPEAL_MIN_VOTES`, `DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO`).
- Final adjudication operator quorum controls: aggregated dispute/appeal publication can require distinct operator count (`DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS`).
- Final adjudication source quorum controls: aggregated dispute/appeal publication can require distinct source classes (`DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES`).
- Final adjudication policy consistency hardening: final quorum/operator thresholds now gate both trust-attestation publication and trust-derived selection scoring.
- Adjudication window horizon caps: dispute/appeal windows are bounded before aggregation/publication (`DIRECTORY_DISPUTE_MAX_TTL_SEC`, `DIRECTORY_APPEAL_MAX_TTL_SEC`).
- Directory trust aggregation appeal propagation (`appeal_until`) with vote-thresholded blending into published attestations.
- Directory admin governance observability endpoint (`/v1/admin/governance-status`) exposing effective adjudication policy, upstream dispute/appeal signal+operator counts/ids, suppressed-vs-published adjudication counters, and per-relay suppression details.
- Token revocation feed (`/v1/revocations`) with exit-side periodic enforcement.
- Signed/epoch-style revocation feed (`generated_at`/`expires_at` + signature) with exit-side verification.
- Exit multi-issuer token verification and revocation feed enforcement (`ISSUER_URLS`, `ISSUER_REVOCATIONS_URLS`).
- Exit path-open token claim validation hardening (`aud`, `exp`, `tier`, `jti`, and `sub` requirement for `tier>1`).
- Exit issuer-claim binding: token `iss` must match verified issuer-key metadata when available, and key-epoch gating uses mapped issuer identity.
- Revocation rollback/key-epoch hardening: monotonic feed version + issuer `key_epoch` / `min_token_epoch` enforcement on exit.
- Issuer key rollover groundwork: persistent key file plus `/v1/pubkeys` exposure of current+previous pubkeys.
- Directory signer rollover policy: persistent key file, bounded previous-key history (`DIRECTORY_KEY_HISTORY`), and optional automatic key rotation (`DIRECTORY_KEY_ROTATE_SEC`).
- Advanced exit locality policy: geo-confidence-gated country/region matching with configurable fallback order.
- Production-hardened exit command egress scaffolding: dedicated NAT chain setup/cleanup and accounting snapshot export.
- Local/CI automation scripts (`scripts/ci_local.sh`, challenge/revocation/token-proof-replay/provider-api/federation/operator-quorum/sync-status-chaos/directory-operator-churn-scale/peer-discovery-source-cap/distinct-operators/directory-sync/directory-gossip/selection-feed/trust-feed/opaque-source/opaque-udp-only/client-wg-kernel-proxy/exit-wg-proxy-limit/exit-wg-proxy-idle-cleanup/entry-live-wg-filter/exit-live-wg-mode/live-wg-full-path/client-bootstrap-recovery/persistent-opaque-session/session-reuse/session-handoff/issuer-trust-sync/issuer-dispute/adjudication-window-caps/adjudication-quorum/adjudication-operator-quorum/adjudication-source-quorum/multi-issuer/load-chaos integrations, GitHub Actions workflow).
- Extended deep test suite (`integration_http_cache`, `integration_directory_auto_key_rotation`, `integration_key_epoch_rotation`, `integration_directory_gossip`, `integration_operator_quorum`, `integration_sync_status_chaos`, `integration_directory_operator_churn_scale`, `integration_distinct_operators`, `integration_peer_discovery`, `integration_peer_discovery_quorum`, `integration_peer_discovery_backoff`, `integration_peer_discovery_require_hint`, `integration_peer_discovery_source_cap`, `integration_opaque_source_downlink`, `integration_opaque_udp_only`, `integration_client_wg_kernel_proxy`, `integration_exit_wg_proxy_limit`, `integration_exit_wg_proxy_idle_cleanup`, `integration_entry_live_wg_filter`, `integration_exit_live_wg_mode`, `integration_live_wg_full_path`, `integration_client_bootstrap_recovery`, `integration_client_startup_burst`, `integration_persistent_opaque_session`, `integration_session_reuse`, `integration_session_handoff`, `integration_trust_feed`, `integration_issuer_trust_sync`, `integration_issuer_dispute`, `integration_adjudication_window_caps`, `integration_adjudication_quorum`, `integration_adjudication_operator_quorum`, `integration_adjudication_source_quorum`, `integration_lifecycle_chaos`, `integration_stress_bootstrap`, `deep_test_suite`).
- Operational deployment assets (Docker Compose + systemd service units/env templates).

## In Progress / Partial
- Real WG interface packet plumbing is scaffolded; bidirectional opaque relay through entry/client/exit is in place (including exit downlink source path and optional client/exit command-mode WG UDP kernel-proxy bridges), and Linux root-only manual validation is available via `scripts/integration_real_wg_privileged.sh` and `scripts/integration_real_wg_privileged_matrix.sh`; production end-to-end cryptographic WG interface integration remains pending.
- Federated reputation/trust exchange includes directory peer score aggregation, peer trust-attestation exchange, issuer trust/dispute ingestion, appeal propagation, case/evidence metadata exchange, and client/entry/directory operator quorum controls; governance and anti-capture policy are still partial.
- Directory anti-entropy includes pull sync + ETag + push-gossip fanout + signed seeded peer discovery; broader internet-scale membership/discovery remains partial.

## Not Started / Remaining
- Full production WireGuard interface plumbing (live encrypted payload I/O only).
- Full federated identity/bond/stake/reputation lifecycle with robust cross-operator adjudication governance and anti-capture controls.
- Privacy-preserving credentials (blind-signed/revocable anonymous credentials) integrated into tier upgrades and dispute workflows.
- Broad decentralized directory peer discovery/membership management (beyond static peer lists).

## Suggested Next Milestones
1. Real WireGuard packet path: bind client/exit command backends to live interfaces and replace synthetic payload generation with interface I/O only.
2. Multi-operator directory trust governance: signer key rotation policy, quorum rules, and operator accountability.
3. Cross-operator adjudication: formalize appeal voting, evidence exchange, and anti-capture safeguards.
4. Attach issuer-backed trust attestations to privacy-preserving identity primitives (revocable anonymous credentials).
5. Expand stress/chaos coverage toward beta-scale traffic patterns and fault domains.
