# Governance

## Roles
### Maintainers
- Merge/revert PRs
- Cut releases
- Handle security and incident decisions
- Own roadmap prioritization

### Contributors
- Propose/implement changes via issues and PRs
- Provide tests and docs for changes

## Decision Model
1. Small changes: maintainer review + merge.
2. Cross-component or security-sensitive changes: design discussion in issue/PR before merge.
3. Emergency security fixes: maintainers may fast-track with follow-up documentation.

## Change Control for High-Risk Areas
The following require strict review:
- Authentication/authorization
- Token/credential validation
- Peer trust/quorum rules
- WireGuard/data-plane behavior
- Admin/security tooling

## Release Policy
- `main` is integration-focused and may move quickly.
- Tagged releases are the recommended deployment points.
- Security fixes may be prioritized over feature work.
