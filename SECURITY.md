# Security Policy

## Scope
This policy covers:
- `cmd/`, `internal/`, `pkg/`, and `services/`
- `scripts/` and deployment tooling
- `tools/easy_mode/` launcher
- Protocol and control-plane logic documented in `docs/`

## Supported Security Status
The project is currently in beta.

| Branch | Status |
|---|---|
| `main` | Security fixes accepted |
| Other branches | Best effort only |

## Reporting a Vulnerability
Do not open public issues for vulnerabilities.

Use one of:
1. GitHub Security Advisory: repository `Security` -> `Report a vulnerability`
2. Private maintainer contact (if provided in repo settings)

Include:
- Affected component/path
- Reproduction steps
- Impact assessment
- Logs or traces with secrets/tokens removed
- Suggested mitigation (if known)

## Disclosure Process
Targets (best effort):
1. Acknowledge report within 72 hours
2. Initial triage within 7 days
3. Critical fix or mitigation plan within 30 days

We prefer coordinated disclosure. Please do not publish exploit details before a fix or mitigation is available.

## Safe Harbor
Good-faith security research is welcome. Avoid:
- Privacy violations
- Service disruption
- Accessing non-public user data
