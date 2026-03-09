# Contributing Guide

Thanks for contributing.

## Before You Start
1. Open an issue describing the bug/feature and proposed approach.
2. Wait for maintainer confirmation on large changes.
3. Keep changes scoped and testable.

## Development Setup
Minimum tools:
- Go 1.22+
- Docker + Docker Compose
- `jq`, `rg`, `curl`, `timeout`

Useful commands:
```bash
./scripts/easy_node.sh check
go test ./...
./scripts/ci_local.sh
./scripts/beta_preflight.sh
```

## Branch and PR Rules
1. Create a feature branch from `main`.
2. Add or update tests for behavior changes.
3. Update docs when changing behavior or flags.
4. Open a PR with:
   - What changed
   - Why it changed
   - How it was tested
   - Risk/rollback notes (if operational)

## Commit Guidelines
Use clear, scoped commit messages, for example:
- `easy-node: add server preflight for peer identity checks`
- `docs: add production gate bundle usage`

## Security and Privacy Requirements
Never commit:
- Private keys
- Admin tokens
- Real credentials
- User traffic logs or PII

If you accidentally committed secrets:
1. Rotate them immediately
2. Remove from history
3. Notify maintainers via security channel

## Testing Expectations
For core behavior changes, run at least:
```bash
go test ./...
./scripts/ci_local.sh
```

For easy-node/runtime changes, also run:
```bash
./scripts/beta_preflight.sh
```

## Code Style
- Keep changes minimal and focused.
- Prefer explicit, fail-closed behavior for security-sensitive paths.
- Avoid introducing hidden behavior or magic defaults without docs.
