# Client Safety Guide

This guide helps users operate the client safely with clear privacy/performance tradeoffs.

## Choose the Right Path Mode

- `speed-1hop`: lowest latency, lowest privacy
- `balanced-2hop`: default recommended mode
- `private-3hop`: strongest privacy posture with higher latency

Use mode based on task sensitivity, not only speed.

## Trust and Bootstrap Hygiene

1. Use trusted directory endpoints.
2. Keep trust pin files scoped and rotate deliberately.
3. Avoid bypassing strict trust checks in normal operation.
4. Treat trust-reset as a controlled recovery action, not a routine step.

## Session and Identity Safety

1. Use short-lived access credentials.
2. Do not reuse sensitive identities across different anonymity contexts.
3. Rotate sessions periodically according to profile policy.
4. Keep software updated to receive security fixes.

## Network Safety Basics

1. Prefer secure bootstrap/control URLs where supported.
2. Validate that traffic is flowing through expected interface/profile.
3. Fail closed when critical trust/quorum checks fail.

## Device Safety Basics

1. Keep OS patches current.
2. Avoid running unknown software while routing sensitive traffic.
3. Use separate profiles/devices for high-risk workflows where possible.

## In a Global Privacy Mesh Context

- most users should remain client-first by default
- optional `micro-relay` mode should be resource-capped and opt-in
- exit and validator roles should remain specialized/hardened

Reference:
- `docs/global-privacy-mesh-track.md`
- `docs/exit-node-safety-baseline-v1.md`

