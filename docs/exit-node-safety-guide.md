# Exit Node Safety Guide

Practical operator guide aligned with `docs/exit-node-safety-baseline-v1.md`.

## Before You Enable Exit Mode

1. Run exit on dedicated infrastructure.
2. Keep software and OS patched before opening traffic.
3. Enable monitoring and alerting first, not after incidents.
4. Start from conservative default egress policy.

## Safe Rollout Sequence

1. Stage mode
- bring up node with strict limits and low traffic
- validate health checks and log pipeline

2. Limited exposure mode
- allow a small trusted cohort
- verify abuse controls, revocation, and incident snapshots

3. General availability mode
- expand only after multiple clean validation windows

## Default Safety Posture

- conservative egress allow-list
- high-abuse destination ports blocked for low-trust sessions
- strict per-subject rate limits
- short token/session lifetimes
- replay protection and fast revocation

## Abuse Handling Workflow

When abuse is detected:

1. Contain
- temporarily throttle or isolate affected subject/session/operator segment

2. Verify
- inspect signed identity/session metadata and event history

3. Act
- revoke/deny/quarantine according to severity

4. Record
- keep incident summary and artifact bundle for review

5. Improve
- update policy thresholds and detection rules

## Do and Do Not

Do:
- prefer automation for containment
- keep evidence reproducible and minimal
- track false positives and tune thresholds

Do not:
- run exit on personal daily-use devices
- allow unlimited high-risk ports by default
- keep long, unnecessary user-linked metadata

## Relationship to Global Privacy Mesh Track

In the Global Privacy Mesh model:

- many participants can run `micro-relay` safely
- only hardened operators should run `exit` role by default
- trust-tier policy can gradually expand capabilities while preserving safety

Reference:
- `docs/global-privacy-mesh-track.md`

