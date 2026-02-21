# Threat Model (MVP)

## Assets
- User source identity
- Destination metadata and traffic patterns
- Token signing keys
- Relay reputation and availability

## Trust Assumptions
- Entry and exit are non-colluding in baseline privacy model.
- Issuer keys are uncompromised.
- Client endpoint can authenticate descriptor signatures.

## Adversaries
- Malicious exit operator
- Malicious entry operator
- External network observer
- Sybil relay operator
- Token thief/replay attacker

## Non-goals (MVP)
- Full traffic analysis resistance against global passive adversary
- Perfect anonymity against entry-exit collusion

## Key Risks and Mitigations
1. Entry learns destination
- Risk: If entry can parse payload, privacy breaks.
- Mitigation: Inner tunnel packets remain opaque at entry.

2. Exit learns user identity
- Risk: direct client-to-exit exposure leaks IP.
- Mitigation: client talks to exit only through entry in default mode.

3. Token replay
- Risk: captured token reused by attacker.
- Mitigation: short token expiry, optional `exit_scope`, `jti` denylist.

4. Sybil relay flooding
- Risk: attacker controls many listed relays.
- Mitigation: signed descriptors from multiple operators, basic reputation/stake.

5. DDoS on entry
- Risk: path setup exhaustion.
- Mitigation: per-IP rate limits, optional challenge puzzles, temporary source bans, in-flight open shielding, horizontal entry scale.

6. Abuse from new users
- Risk: spam/scanning via egress.
- Mitigation: tier-1 default restrictions, quotas, progressive trust promotion.

7. Revocation rollback / stale key usage
- Risk: attacker replays stale revocation state or stale-epoch token.
- Mitigation: signed feed versioning + key-epoch minimum enforcement on exit.

8. Directory sync loop amplification
- Risk: peer directories repeatedly re-import and rebroadcast stale descriptors.
- Mitigation: origin/hop metadata with max-hop enforcement and incremental sync with ETag cache reuse.

## Security Invariants to Test
- Entry cannot derive destination from packet contents.
- Exit cannot map token to client identity directly.
- Tier-1 blocks SMTP/25 consistently.
- Expired tokens are denied.
