# Exit Node Safety Baseline v1

Status: baseline policy for operator safety hardening

## Purpose

This baseline defines the minimum controls required before operating an exit node
in production-like environments.

Goals:
- reduce abuse and complaint volume
- protect operator infrastructure
- preserve user privacy while maintaining incident response capability

## Baseline Requirements

1. Role separation
- do not run exit on personal workstation
- run exit on dedicated host/VM only
- separate control-plane and admin credentials from daily-use accounts

2. Network exposure
- deny all inbound by default except required service ports
- disable unnecessary host services
- isolate management plane from public data plane where possible

3. Conservative egress defaults
- default allow-list for common web traffic first
- block known high-abuse destination ports by default for low-trust sessions
- expand allowed ports only via trust-tier policy

4. Session and rate controls
- per-subject/session connection caps
- per-subject/session request-rate caps
- burst controls and cooldowns

5. Fast identity/session containment
- short-lived tokens/credentials
- replay protection enabled
- rapid revoke and deny-list propagation path

6. Observability and evidence
- structured logs for control events and abuse signals
- metrics and alerts for spikes, failures, and suspicious patterns
- minimal metadata retention window only as long as needed for operations

7. Incident response readiness
- documented runbook for abuse and outages
- on-call path and triage severity classes
- reproducible incident bundles and postmortem records

## High-Abuse Port Classes (Default Block)

These classes are frequently abused and should remain blocked for default/low-trust sessions:

- SMTP classes (`25`, `465`, `587`)
- legacy remote admin and file-sharing classes (`23`, `139`, `445`)
- common amplification/reflection surfaces when misused

Port policy should be explicit and versioned. Any change must be auditable.

## Trust-Tier Port Expansion Policy

Recommended policy shape:

- Tier 1 (new/unknown)
  - strict allow-list
  - strongest rate limits
- Tier 2 (established/healthy)
  - expanded allow-list with bounded risk controls
- Tier 3 (high-trust/operator-reviewed)
  - broader access with continuous abuse scoring

Promotion/demotion signals:
- uptime quality
- abuse event rate
- successful challenge/verification history
- dispute and appeal outcomes

## Operator Hardening Checklist

Pre-launch:
- host patched and hardened
- firewall policy reviewed and tested
- monitoring/alerting live
- backup and key-rotation plan tested

Daily:
- review alert dashboard
- inspect abuse queue and top talkers
- verify token revocation path health

Incident:
- contain (rate-limit/quarantine/revoke)
- preserve evidence bundle
- recover service with post-incident guardrails

## Out-of-Scope for v1

- country-specific legal process automation
- advanced ML abuse classification
- autonomous global blackhole propagation

